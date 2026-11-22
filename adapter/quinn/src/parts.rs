//! The parts every carrier over QUIC streams shares, whether it runs on
//! quinn's streams directly or on a layer over them (WebTransport): the
//! streams as a pipe's halves and as lanes, the queue of the pipes the
//! peer opened, and the connection's datagrams as the pipes' datagram
//! channels. An adapter provides how its streams are opened and accepted
//! ([`SendPart`], [`RecvPart`], [`DatagramConn`]) and its close codes.
//!
//! Stability: this module is plumbing for adapter authors, tied to
//! [`zmux::adapter`]. It changes whenever that interface does, without
//! the guarantees of the carrier API; an adapter built on it pins the
//! exact `zmux-quinn` version it was built against.

use std::any::Any;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{Notify, oneshot};
use zmux::PipeIo;
use zmux::adapter::{
    ChannelDemux, ChannelReceiver, ChannelRegistration, ChunkWrite, DRAIN_LIMIT, DatagramChannel,
    Lane,
};

/// What a carrier's streams keep alive: the state of their connection,
/// whose drop closes it.
pub type Keep = Arc<dyn Any + Send + Sync>;

/// A QUIC stream's sending part as the adapter's layer has it.
pub trait SendPart: Unpin + Send + 'static {
    /// Takes bytes from the front of `chunks` without copying, as
    /// [`ChunkWrite::poll_write_chunks`]: a call that returns `Pending`
    /// took nothing and registered the waker.
    fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>>;

    /// Flushes, as `AsyncWrite::poll_flush`.
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Ends the stream gracefully (FIN).
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Resets the stream with `ZMUX_CARRIER_FAILED`.
    fn reset(&mut self);

    /// Resolves once the peer acknowledged all of the stream, stopped it,
    /// or the connection ended; holds nothing of the stream.
    fn stopped(&self) -> impl Future<Output = ()> + Send + 'static;
}

/// A QUIC stream's receiving part as the adapter's layer has it.
pub trait RecvPart: Unpin + Send + 'static {
    /// Reads, as `AsyncRead::poll_read`.
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>;

    /// Stops the stream with `ZMUX_CARRIER_FAILED`.
    fn stop(&mut self);
}

type Stopped = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A stream's sending part as a carrier's: ended gracefully by
/// `poll_shutdown` (FIN), reset with `ZMUX_CARRIER_FAILED` when dropped
/// otherwise. A sender registered by [`pipe`] or [`lane`] keeps the connection until the peer
/// acknowledged all of it, within [`DRAIN_LIMIT`]: QUIC closes a
/// connection whose last handle is dropped, and discards the data still in
/// flight, so a carrier's last records (a `CONNECTION_CLOSE`) would be lost
/// with it. A pipe's does so as the pipe's drain ([`pipe`]), a lane's
/// as the lane's drain.
pub struct QuicSend<S: SendPart> {
    stream: S,
    finished: bool,
    keep: Option<Keep>,
    /// The pipe's drain, which takes the wait once the stream finished.
    drain: Option<oneshot::Sender<Stopped>>,
}

impl<S: SendPart> QuicSend<S> {
    /// `stream`, wrapped as soon as it is opened or accepted: dropped from
    /// now on, it is reset unless it ended gracefully.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            finished: false,
            keep: None,
            drain: None,
        }
    }

    /// Both a pipe and each of its lanes register this wait with the driver.
    fn drain(&mut self, keep: Keep) -> impl Future<Output = ()> + Send + 'static + use<S> {
        let (drain, stopped) = oneshot::channel::<Stopped>();
        self.keep = Some(keep.clone());
        self.drain = Some(drain);
        async move {
            if let Ok(stopped) = stopped.await {
                stopped.await;
            }
            drop(keep);
        }
    }

    /// The stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// The stream, mutably.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl<S: SendPart> std::fmt::Debug for QuicSend<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicSend")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

/// Owned buffers go to the stream as they are: payloads without copying.
impl<S: SendPart> ChunkWrite for QuicSend<S> {
    fn poll_write_chunks(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        self.stream.poll_write_chunks(cx, chunks)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = self.stream.poll_finish(cx);
        // Only a finish that succeeded is the graceful end; a failed one
        // leaves the stream to be reset when dropped.
        if matches!(r, Poll::Ready(Ok(()))) {
            self.finished = true;
        }
        r
    }
}

impl<S: SendPart> Drop for QuicSend<S> {
    fn drop(&mut self) {
        if !self.finished {
            // quinn ends a dropped stream gracefully: a failure is a reset.
            self.stream.reset();
            return;
        }
        if let Some(drain) = self.drain.take() {
            let _ = drain.send(Box::pin(self.stream.stopped()));
        }
    }
}

/// A stream's receiving part as a carrier's: stopped with
/// `ZMUX_CARRIER_FAILED` when dropped (a no-op after its end).
pub struct QuicRecv<R: RecvPart> {
    stream: R,
    keep: Option<Keep>,
}

impl<R: RecvPart> QuicRecv<R> {
    /// `stream`, wrapped as soon as it is opened or accepted.
    pub fn new(stream: R) -> Self {
        Self { stream, keep: None }
    }

    /// The stream.
    pub fn get_ref(&self) -> &R {
        &self.stream
    }

    /// The stream, mutably.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.stream
    }
}

impl<R: RecvPart> std::fmt::Debug for QuicRecv<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicRecv").finish_non_exhaustive()
    }
}

impl<R: RecvPart> Drop for QuicRecv<R> {
    fn drop(&mut self) {
        self.stream.stop();
    }
}

impl<R: RecvPart> AsyncRead for QuicRecv<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.stream.poll_read(cx, buf)
    }
}

/// The pipe carrier of a bidirectional stream: both halves keep `keep`
/// (the connection's state) while they live, and once the session is done
/// with a pipe whose sending half ended gracefully, its drain keeps it
/// until the peer acknowledged the stream, within [`DRAIN_LIMIT`]
/// ([`PipeIo::with_drain`]).
pub fn pipe<S: SendPart, R: RecvPart>(
    mut send: QuicSend<S>,
    mut recv: QuicRecv<R>,
    keep: Keep,
) -> PipeIo {
    recv.keep = Some(keep.clone());
    let drain = send.drain(keep);
    PipeIo::from_chunk_halves(recv, send).with_drain(drain, DRAIN_LIMIT)
}

/// A lane on the unidirectional stream `send`, which keeps `keep` while it
/// lives and, once finished, until the peer acknowledged it, within
/// [`DRAIN_LIMIT`].
pub fn lane<S: SendPart>(send: S, keep: Keep) -> Lane {
    let mut send = QuicSend::new(send);
    let drain = send.drain(keep);
    Lane::from_chunks(send).with_drain(drain, DRAIN_LIMIT)
}

/// The pipes the peer opened that nobody took yet, on a carrier without a
/// listener, until the connection closes.
pub struct AcceptQueue<T> {
    st: Mutex<(VecDeque<T>, bool)>,
    notify: Notify,
}

impl<T> Default for AcceptQueue<T> {
    fn default() -> Self {
        Self {
            st: Mutex::new((VecDeque::new(), false)),
            notify: Notify::new(),
        }
    }
}

impl<T> std::fmt::Debug for AcceptQueue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptQueue").finish_non_exhaustive()
    }
}

impl<T> AcceptQueue<T> {
    fn lock(&self) -> std::sync::MutexGuard<'_, (VecDeque<T>, bool)> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `pipe`, the peer's.
    pub fn push(&self, pipe: T) {
        self.lock().0.push_back(pipe);
        self.notify.notify_waiters();
    }

    /// The connection closed: no pipe comes any more, and those queued are
    /// dropped (outside the lock).
    pub fn close(&self) {
        let pipes = {
            let mut st = self.lock();
            st.1 = true;
            std::mem::take(&mut st.0)
        };
        self.notify.notify_waiters();
        drop(pipes);
    }

    /// The next pipe; `None` once the connection is closed and none is
    /// left. Cancel safe.
    pub async fn pop(&self) -> Option<T> {
        loop {
            let mut notified = pin!(self.notify.notified());
            notified.as_mut().enable();
            {
                let mut st = self.lock();
                if let Some(p) = st.0.pop_front() {
                    return Some(p);
                }
                if st.1 {
                    return None;
                }
            }
            notified.await;
        }
    }
}

/// A stream the peer opened, as the adapter's layer has it.
pub enum Accepted<S, R> {
    /// A bidirectional stream: a pipe.
    Bi(S, R),
    /// A unidirectional stream: a lane.
    Uni(R),
}

/// A connection whose streams the peer opens, as the adapter's layer has
/// them.
pub trait StreamConn: Send + Sync + 'static {
    /// Its streams' sending part.
    type Send: SendPart;
    /// Its streams' receiving part.
    type Recv: RecvPart;

    /// The next stream the peer opened, bidirectional or not; `None` once
    /// the connection is closed.
    fn accept(&self) -> impl Future<Output = Option<Accepted<Self::Send, Self::Recv>>> + Send;
}

/// A carrier's state as [`accept_loop`] needs it: how a bidirectional
/// stream becomes a pipe, the connection's identity and carrier kind, and
/// the queue of the pipes nobody took.
pub trait CarrierState<S: SendPart, R: RecvPart>: Send + Sync + 'static {
    /// The pipe carrier of a stream the peer opened.
    fn pipe(self: &Arc<Self>, send: QuicSend<S>, recv: QuicRecv<R>) -> PipeIo;
    /// The connection's identity.
    fn conn_id(&self) -> zmux::adapter::CarrierConnId;
    /// The carrier kind of its lanes.
    fn kind(&self) -> zmux::CarrierKind;
    /// The pipes the peer opened that nobody took (without a listener).
    fn accepted(&self) -> &AcceptQueue<(QuicSend<S>, QuicRecv<R>)>;
}

/// Hands every stream the peer opens on `conn` to zmux until the
/// connection closes or the carrier (`state`) is gone: a pipe to
/// `listener` with `hint()`, or to the queue without one; a lane to
/// `listener`, or to its session's lane without one. Each stream is wrapped
/// at once, so that one dropped from here on is reset or stopped, never
/// ended gracefully.
pub async fn accept_loop<C, I>(
    conn: C,
    state: std::sync::Weak<I>,
    listener: Option<zmux::Listener>,
    hint: impl Fn() -> zmux::PipeHint,
) where
    C: StreamConn,
    I: CarrierState<C::Send, C::Recv>,
{
    let handle = |l: &zmux::Listener, io: PipeIo| {
        let (l, hint) = (l.clone(), hint());
        tokio::spawn(async move { l.handle_pipe(io, hint).await });
    };
    while let Some(stream) = conn.accept().await {
        let stream = match stream {
            Accepted::Bi(send, recv) => Accepted::Bi(QuicSend::new(send), QuicRecv::new(recv)),
            Accepted::Uni(recv) => Accepted::Uni(QuicRecv::new(recv)),
        };
        let Some(state) = state.upgrade() else {
            break;
        };
        match (stream, &listener) {
            (Accepted::Bi(send, recv), Some(l)) => handle(l, state.pipe(send, recv)),
            (Accepted::Bi(send, recv), None) => state.accepted().push((send, recv)),
            (Accepted::Uni(recv), l) => {
                let io = PipeIo::reader(recv)
                    .with_carrier(state.kind())
                    .with_carrier_conn(state.conn_id());
                match l {
                    Some(l) => handle(l, io),
                    None => {
                        tokio::spawn(zmux::adapter::handle_lane(io));
                    }
                }
            }
        }
    }
    if let Some(state) = state.upgrade() {
        state.accepted().close();
    }
}

/// A connection's datagrams as the adapter's layer has them.
pub trait DatagramConn: Send + Sync + 'static {
    /// The largest datagram the connection sends now, 0 when it sends none.
    fn max_datagram_size(&self) -> usize;

    /// Sends `datagram`, waiting for room.
    fn send_datagram(&self, datagram: Bytes) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Hands every datagram the connection receives to `demux` until it
    /// closes.
    fn deliver(&self, demux: ChannelDemux) -> impl Future<Output = ()> + Send + 'static;
}

/// The datagrams of a connection as the datagram channels of its stream
/// pipes: each starts with a varint that names the pipe, its QUIC stream
/// ID (or the Quarter Stream ID of an HTTP/3 request, which makes it an
/// HTTP Datagram). One receive loop routes the connection's datagrams to
/// its pipes, which may belong to several sessions; it starts with the
/// first pipe that receives and stops when this state is gone. Its
/// datagrams belong to zmux.
pub struct Datagrams<C: DatagramConn> {
    conn: C,
    demux: ChannelDemux,
    receiving: OnceLock<tokio::task::AbortHandle>,
}

impl<C: DatagramConn> std::fmt::Debug for Datagrams<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Datagrams")
            .field("demux", &self.demux)
            .finish_non_exhaustive()
    }
}

impl<C: DatagramConn> Drop for Datagrams<C> {
    fn drop(&mut self) {
        if let Some(t) = self.receiving.get() {
            t.abort();
        }
    }
}

impl<C: DatagramConn> Datagrams<C> {
    /// The datagrams of `conn`. Make one per connection: its receive loop
    /// takes every datagram of the connection.
    pub fn with(conn: C) -> Arc<Self> {
        Arc::new(Self {
            conn,
            demux: ChannelDemux::new(),
            receiving: OnceLock::new(),
        })
    }

    /// The connection.
    pub fn conn(&self) -> &C {
        &self.conn
    }

    /// The datagram channel of the pipe whose datagrams start with `id`
    /// (its QUIC stream ID): a [`DatagramChannel`] for
    /// [`PipeIo::with_datagram_channel`].
    pub fn channel(self: &Arc<Self>, id: u64) -> Arc<QuicChannel<C>> {
        self.channel_when(id, None)
    }

    /// [`Datagrams::channel`] that takes datagrams only while `usable`
    /// says so (for example once the peer's HTTP/3 SETTINGS enabled HTTP
    /// Datagrams); it must be cheap and must not wait.
    pub fn channel_when(
        self: &Arc<Self>,
        id: u64,
        usable: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    ) -> Arc<QuicChannel<C>> {
        Arc::new(QuicChannel {
            datagrams: self.clone(),
            id: std::sync::atomic::AtomicU64::new(id),
            usable,
        })
    }

    /// The datagrams received that named no pipe attached to a session (an
    /// unknown, not yet attached or closed one), or whose ID was truncated.
    pub fn dropped(&self) -> u64 {
        self.demux.dropped()
    }

    /// Starts the receive loop, inside a tokio runtime.
    fn receive(&self) {
        self.receiving
            .get_or_init(|| tokio::spawn(self.conn.deliver(self.demux.clone())).abort_handle());
    }
}

/// The datagram channel of one pipe of a connection
/// ([`Datagrams::channel`]).
pub struct QuicChannel<C: DatagramConn> {
    datagrams: Arc<Datagrams<C>>,
    id: std::sync::atomic::AtomicU64,
    usable: Option<Box<dyn Fn() -> bool + Send + Sync>>,
}

impl<C: DatagramConn> std::fmt::Debug for QuicChannel<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicChannel")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl<C: DatagramConn> QuicChannel<C> {
    fn id(&self) -> u64 {
        self.id.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The pipe moved to the stream `id`: its datagrams start with it from
    /// now on, both ways.
    pub fn rekey(&self, id: u64) {
        let old = self.id.swap(id, std::sync::atomic::Ordering::Relaxed);
        self.datagrams.demux.rekey(old, id);
    }
}

impl<C: DatagramConn> DatagramChannel for QuicChannel<C> {
    fn channel_id(&self) -> Option<u64> {
        Some(self.id())
    }

    fn max_datagram_size(&self) -> usize {
        if self.usable.as_ref().is_some_and(|u| !u()) {
            return 0;
        }
        self.datagrams.conn.max_datagram_size()
    }

    fn send(&self, datagram: Bytes) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(self.datagrams.conn.send_datagram(datagram))
    }

    fn receive(&self, receiver: ChannelReceiver) -> ChannelRegistration {
        let r = self.datagrams.demux.register(self.id(), receiver);
        self.datagrams.receive();
        r
    }
}
