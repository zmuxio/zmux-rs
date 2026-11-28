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
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, oneshot, watch};
use zmux::adapter::{
    AdmitIo, Admitted, ChannelDemux, ChannelReceiver, ChannelRegistration, ChunkWrite, DRAIN_LIMIT,
    DatagramChannel, DatagramChannelPrefix, Entry, Lane,
};
use zmux::{CarrierInfo, Listener, PipeHint, PipeIo};

/// The connection state a carrier's streams keep alive.
pub type Keep = Arc<dyn Any + Send + Sync>;

/// A QUIC stream's sending part as the adapter's layer has it.
pub trait SendPart: Unpin + Send + 'static {
    /// Writes borrowed bytes during admission fallback.
    fn poll_write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>>;

    /// Takes bytes from the front of `chunks` without copying, as
    /// [`ChunkWrite::poll_write_chunks`]: a call that returns `Pending`
    /// took nothing and registered the waker.
    fn poll_send_bytes(
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
    staged: Vec<Bytes>,
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
            staged: Vec::new(),
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
        chunks: &mut [zmux::Chunk],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.staged.is_empty() {
            this.staged
                .extend(chunks.iter().cloned().map(zmux::Chunk::into_bytes));
        }
        let result = std::task::ready!(this.stream.poll_send_bytes(cx, &mut this.staged));
        this.staged.clear();
        let taken = result?;
        let mut remaining = taken;
        for chunk in chunks {
            let n = remaining.min(chunk.len());
            bytes::Buf::advance(chunk, n);
            remaining -= n;
            if remaining == 0 {
                break;
            }
        }
        Poll::Ready(Ok(taken))
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

impl<S: SendPart> AsyncWrite for QuicSend<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream.poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ChunkWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ChunkWrite::poll_shutdown(self, cx)
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

/// A connection with independently accepted pipe and lane streams.
pub trait StreamConn: Send + Sync + 'static {
    /// Its streams' sending part.
    type Send: SendPart;
    /// Its streams' receiving part.
    type Recv: RecvPart;

    /// The default hint for a newly received stream without an admitted source.
    fn hints(&self, listener: Option<&Listener>) -> impl Fn() -> PipeHint + Send + Sync;

    /// Accepts one pipe stream. Cancel safe.
    fn accept_bi(&self) -> impl Future<Output = Option<(Self::Send, Self::Recv)>> + Send;

    /// Accepts one lane stream. Cancel safe.
    fn accept_uni(&self) -> impl Future<Output = Option<Self::Recv>> + Send;
}

/// A carrier's state as the receivers need it: how a bidirectional
/// stream becomes a pipe, the connection's identity and carrier kind, and
/// the queue of the pipes nobody took.
pub trait CarrierState<S: SendPart, R: RecvPart>: Send + Sync + 'static {
    /// The pipe carrier of a stream the peer opened.
    fn pipe(self: &Arc<Self>, send: QuicSend<S>, recv: QuicRecv<R>) -> PipeIo;
    /// The connection's identity.
    fn conn_id(&self) -> zmux::adapter::CarrierConnId;
    /// The carrier's close responsibility.
    fn close(&self) -> &ConnectionClose;
    /// The carrier kind of its lanes.
    fn kind(&self) -> zmux::CarrierKind;
    /// The pipes the peer opened that nobody took (without a listener).
    fn accepted(&self) -> &AcceptQueue<(QuicSend<S>, QuicRecv<R>)>;
}

/// Starts receivers for a carrier whose caller owns its lifetime.
pub fn start_receivers<C, I>(conn: C, state: &Arc<I>, listener: Option<Listener>)
where
    C: StreamConn,
    I: CarrierState<C::Send, C::Recv>,
{
    state.close().claim();
    let state = Arc::downgrade(state);
    tokio::spawn(async move {
        let hint = conn.hints(listener.as_ref());
        tokio::join!(
            accept_pipes(
                &conn,
                &state,
                listener.as_ref(),
                &hint,
                None,
                admission_end(listener.as_ref())
            ),
            accept_lanes(
                &conn,
                &state,
                listener.as_ref(),
                &hint,
                std::future::pending()
            ),
        );
    });
}

async fn admission_end(listener: Option<&Listener>) {
    match listener {
        Some(listener) => listener.adapter().closed().await,
        None => std::future::pending().await,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stop {
    Running,
    Admission,
    All,
}

/// Controls pipe setup and lane reception for an adopted connection.
/// Dropping it stops setup; transferred pipes retain lane reception.
pub struct ConnectionService {
    stop: watch::Sender<Stop>,
    admission: watch::Receiver<()>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ConnectionService {
    /// Starts an adapter's admission and delivery task.
    pub fn start<F>(run: impl FnOnce(Delivery) -> F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let (stop, stopped) = watch::channel(Stop::Running);
        let (admission_done, admission) = watch::channel(());
        let task = tokio::spawn(run(Delivery {
            stopped,
            admission_done,
        }));
        Self {
            stop,
            admission,
            task: Some(task),
        }
    }

    /// Stops new pipe admission and cancels pending setup.
    pub fn stop_admission(&self) {
        self.stop_at(Stop::Admission);
    }

    /// Stops both receivers, leaving transferred pipes with their owners.
    pub fn stop(&self) {
        self.stop_at(Stop::All);
    }

    fn stop_at(&self, target: Stop) {
        self.stop.send_if_modified(|stop| {
            if *stop >= target {
                return false;
            }
            *stop = target;
            true
        });
    }

    /// Waits until the admission receiver and its pending setups have stopped.
    pub async fn admission_stopped(&self) {
        let _ = self.admission.clone().changed().await;
    }

    /// Waits until both receivers have finished.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the connection service task failed.
    pub async fn wait(&mut self) -> io::Result<()> {
        if let Some(task) = &mut self.task {
            let result = task.await.map_err(io::Error::other);
            self.task = None;
            result?;
        }
        Ok(())
    }
}

impl Drop for ConnectionService {
    fn drop(&mut self) {
        self.stop_admission();
    }
}

async fn stopping(mut state: watch::Receiver<Stop>, target: Stop) {
    if state.wait_for(|state| *state >= target).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Owns pending setup and the carrier until pipe admission stops.
pub struct Delivery {
    stopped: watch::Receiver<Stop>,
    admission_done: watch::Sender<()>,
}

/// Stages the carrier made from the first stream, until the listener accepts it.
pub struct FirstStream<C, I> {
    staged: oneshot::Sender<(C, Arc<I>)>,
}

impl<C, I> FirstStream<C, I>
where
    C: StreamConn,
    I: CarrierState<C::Send, C::Recv>,
{
    /// Gives the first stream to admission. The transport adds its fallback
    /// connection metadata and creates carrier state on conversion.
    pub fn prepare(
        self,
        send: C::Send,
        recv: C::Recv,
        make: impl FnOnce() -> (C, Arc<I>) + Send + 'static,
    ) -> AdmitIo {
        let streams = tokio::io::join(QuicRecv::new(recv), QuicSend::new(send));
        AdmitIo::stream(streams, move |streams| {
            let (recv, send) = streams.into_inner();
            let (conn, state) = make();
            let pipe = state.pipe(send, recv);
            let _ = self.staged.send((conn, state));
            pipe
        })
    }
}

impl Delivery {
    /// Runs first-stream admission and starts delivery only after it succeeds.
    /// If fallback is running when admission is cancelled, its return guard
    /// or the detached host retains close responsibility.
    pub async fn admit<C, I, F>(
        self,
        listener: Listener,
        mut entry: Entry,
        first: impl FnOnce(FirstStream<C, I>) -> F,
        close_unclaimed: impl FnOnce(),
    ) where
        C: StreamConn,
        I: CarrierState<C::Send, C::Recv>,
        F: Future<Output = io::Result<(CarrierInfo, AdmitIo)>>,
    {
        let (staged, mut state) = oneshot::channel();
        let mut stream_open = false;
        let first = async {
            let io = first(FirstStream { staged }).await?;
            stream_open = true;
            Ok(io)
        };
        let Some(accepted) = zmux::adapter::while_open(
            stopping(self.stopped.clone(), Stop::Admission),
            entry.admit_first_with_info(first),
        )
        .await
        else {
            // Before the first stream exists, nobody else can own the close.
            // Once it enters admission, a running fallback may already have it.
            if !stream_open {
                entry.end_unclaimed_connection(close_unclaimed);
            }
            return;
        };
        let (Some(pipe), Ok((conn, state))) = (accepted, state.try_recv()) else {
            entry.end_unclaimed_connection(close_unclaimed);
            return;
        };
        let admitted = entry.admitted();
        let first = (pipe, PipeHint::from_entry(entry));
        self.serve(conn, state, listener, admitted, Some(first))
            .await;
    }

    /// Delivers subsequent streams after a first-stream or head handoff.
    pub async fn serve<C, I>(
        self,
        conn: C,
        state: Arc<I>,
        listener: Listener,
        admitted: Option<Admitted>,
        first: Option<(PipeIo, PipeHint)>,
    ) where
        C: StreamConn,
        I: CarrierState<C::Send, C::Recv>,
    {
        state.close().claim();
        let weak = Arc::downgrade(&state);
        let default_hint = conn.hints(Some(&listener));
        let hint = || match &admitted {
            Some(admitted) => PipeHint::from_admitted(admitted.clone()),
            None => default_hint(),
        };
        let stop = async {
            tokio::select! {
                () = stopping(self.stopped.clone(), Stop::Admission) => {},
                () = admission_end(Some(&listener)) => {},
            }
        };
        let pipes = async {
            accept_pipes(&conn, &weak, Some(&listener), &hint, first, stop).await;
            drop(state);
            drop(self.admission_done);
        };
        tokio::join!(
            pipes,
            accept_lanes(
                &conn,
                &weak,
                Some(&listener),
                &hint,
                stopping(self.stopped.clone(), Stop::All)
            ),
        );
    }
}

/// Accepts pipes and owns all untransferred setup futures until admission stops.
async fn accept_pipes<C, I>(
    conn: &C,
    state: &std::sync::Weak<I>,
    listener: Option<&zmux::Listener>,
    hint: &(impl Fn() -> zmux::PipeHint + Sync),
    first: Option<(PipeIo, zmux::PipeHint)>,
    stop: impl Future<Output = ()>,
) where
    C: StreamConn,
    I: CarrierState<C::Send, C::Recv>,
{
    let mut setups = tokio::task::JoinSet::new();
    let mut stop = pin!(stop);
    if let (Some((pipe, hint)), Some(listener)) = (first, listener) {
        let listener = listener.clone();
        setups.spawn(async move { listener.handle_pipe(pipe, hint).await });
    }
    loop {
        tokio::select! {
            biased;
            () = &mut stop => break,
            joined = setups.join_next(), if !setups.is_empty() => { drop(joined); }
            stream = conn.accept_bi() => {
                let Some((send, recv)) = stream else { break };
                let (send, recv) = (QuicSend::new(send), QuicRecv::new(recv));
                let Some(state) = state.upgrade() else { break };
                if let Some(listener) = listener {
                    let (listener, pipe, hint) = (listener.clone(), state.pipe(send, recv), hint());
                    setups.spawn(async move { listener.handle_pipe(pipe, hint).await });
                } else {
                    state.accepted().push((send, recv));
                }
            }
        }
    }
    setups.shutdown().await;
    if let Some(state) = state.upgrade() {
        state.accepted().close();
    }
}

/// Accepts lane streams independently of pipe admission. QUIC stream credit
/// bounds the number of reads awaiting a lane header on this connection.
pub(crate) async fn accept_lanes<C, I>(
    conn: &C,
    state: &std::sync::Weak<I>,
    listener: Option<&zmux::Listener>,
    hint: &(impl Fn() -> zmux::PipeHint + Sync),
    stop: impl Future<Output = ()>,
) where
    C: StreamConn,
    I: CarrierState<C::Send, C::Recv>,
{
    let mut setups = tokio::task::JoinSet::new();
    let mut stop = pin!(stop);
    loop {
        tokio::select! {
            biased;
            () = &mut stop => break,
            joined = setups.join_next(), if !setups.is_empty() => { drop(joined); }
            stream = conn.accept_uni() => {
                let Some(recv) = stream else { break };
                let recv = QuicRecv::new(recv);
                let Some(state) = state.upgrade() else { break };
                let io = PipeIo::reader(recv)
                    .with_carrier_transport(state.kind(), state.conn_id());
                if let Some(listener) = listener {
                    let (listener, hint) = (listener.clone(), hint());
                    setups.spawn(async move { listener.handle_pipe(io, hint).await });
                } else {
                    setups.spawn(zmux::adapter::handle_lane(io));
                }
            }
        }
    }
    setups.shutdown().await;
}

/// The transport close responsibility and the last pipe's close code.
#[derive(Default)]
pub struct ConnectionClose {
    owned: std::sync::atomic::AtomicBool,
    code: std::sync::atomic::AtomicU64,
}

impl ConnectionClose {
    /// Claims the connection once admission transferred it to zmux.
    fn claim(&self) {
        self.owned.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Remembers the application code of the last pipe to finish.
    pub fn set_code(&self, code: u64) {
        self.code.store(code, std::sync::atomic::Ordering::Relaxed);
    }

    /// Closes the transport with the last recorded code if zmux owns it.
    pub fn close(&self, close: impl FnOnce(u64)) {
        if self.owned.load(std::sync::atomic::Ordering::Relaxed) {
            close(self.code.load(std::sync::atomic::Ordering::Relaxed));
        }
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
    capacity: OnceLock<usize>,
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
            capacity: OnceLock::new(),
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
        self.channel_with_routing(id, None)
    }

    /// The HTTP Datagrams of a request. The Quarter Stream ID is carrier
    /// framing. The channel is available when the peer negotiated HTTP Datagrams.
    pub fn http_datagram_channel(
        self: &Arc<Self>,
        quarter_stream_id: u64,
        enabled: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> Arc<QuicChannel<C>> {
        self.channel_with_routing(quarter_stream_id, Some(enabled))
    }

    fn channel_with_routing(
        self: &Arc<Self>,
        id: u64,
        http_enabled: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    ) -> Arc<QuicChannel<C>> {
        Arc::new(QuicChannel {
            datagrams: self.clone(),
            id: std::sync::atomic::AtomicU64::new(id),
            http_enabled,
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
    http_enabled: Option<Box<dyn Fn() -> bool + Send + Sync>>,
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
    fn channel_prefix(&self) -> DatagramChannelPrefix {
        if self.http_enabled.is_some() {
            DatagramChannelPrefix::Carrier(self.id())
        } else {
            DatagramChannelPrefix::Pipe(self.id())
        }
    }

    fn datagram_capacity(&self) -> (usize, usize) {
        if self.http_enabled.as_ref().is_some_and(|u| !u()) {
            return (0, 0);
        }
        let room = self.datagrams.conn.max_datagram_size();
        // The carrier exposes the minimum of its MTU and the peer's limit.
        // Declare the first usable size as this connection's service capacity.
        let capacity = if room > 0 {
            *self.datagrams.capacity.get_or_init(|| room)
        } else {
            self.datagrams.capacity.get().copied().unwrap_or(0)
        };
        (capacity, room.min(capacity))
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
