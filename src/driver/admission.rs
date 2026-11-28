//! The driver side of carrier admission ([`crate::Admission`]): reading a
//! carrier's prefix or first message, discarding what a stalled carrier
//! sends, giving the prefix back in front of a byte stream ([`Prefixed`]),
//! the carrier an adapter hands to the admission ([`AdmitIo`]), the one
//! fallback of a listener ([`Fallback`]) and what it takes over
//! ([`Takeover`]), and the PROXY protocol header of a trusted intermediary
//! ([`proxied_source`]). The listener applies the admission itself
//! ([`Entry::admit`](crate::adapter::Entry::admit)).

use std::any::Any;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::deadline::timeout;
use super::tokio::PipeIo;
use crate::ClockDomain;
use crate::proto::admission::{AdmittedValue, CarrierInfo};
use crate::proto::record::Framing;

/// Reads on until `prefix` holds `need` bytes, the carrier ends, or
/// `deadline` passes; returns it and whether the deadline passed.
pub(crate) async fn read_more<R>(
    mut prefix: Vec<u8>,
    need: usize,
    r: &mut R,
    clock: &ClockDomain,
    deadline: Option<Instant>,
) -> (Vec<u8>, bool)
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut got = prefix.len();
    prefix.resize(need.max(got), 0);
    let fill = async {
        while got < prefix.len() {
            match r.read(&mut prefix[got..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
    };
    let late = timeout(clock, deadline, fill).await.is_none();
    prefix.truncate(got);
    (prefix, late)
}

/// What reading a message-framed carrier's first message gave.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FirstMessage {
    /// The message, whole.
    Message(Vec<u8>),
    /// Longer than the bound, with the entire message if it was retained.
    TooLarge(Option<Vec<u8>>),
    /// No message to decide on: the carrier ended or failed, or sent an
    /// empty or a non-binary message.
    Failed,
    /// None arrived by the deadline.
    Late,
}

/// Reads the first message of a message-framed carrier, every read of
/// which is one message (a [`message_too_large`](crate::adapter::message_too_large)
/// error for one longer than the read's room), at most `max` bytes, by
/// `deadline`.
pub(crate) async fn read_message<R>(
    r: &mut R,
    max: usize,
    clock: &ClockDomain,
    deadline: Option<Instant>,
) -> FirstMessage
where
    R: AsyncRead + Unpin + ?Sized,
{
    // One byte more than the bound: a longer message is told apart from
    // one of the bound's length either way.
    let mut buf = vec![0u8; max.saturating_add(1)];
    let read = timeout(clock, deadline, r.read(&mut buf)).await;
    match read {
        None => FirstMessage::Late,
        Some(Ok(n)) if n > max => {
            buf.truncate(n);
            FirstMessage::TooLarge(Some(buf))
        }
        Some(Ok(0)) => FirstMessage::Failed,
        Some(Ok(n)) => {
            buf.truncate(n);
            FirstMessage::Message(buf)
        }
        Some(Err(e)) if super::is_message_too_large(&e) => FirstMessage::TooLarge(None),
        Some(Err(_)) => FirstMessage::Failed,
    }
}

/// Reads and discards what arrives on `r`, `chunk` bytes at a time (a
/// message at a time on a message-framed carrier, `records`, one too long
/// for the chunk dropped by the reader), until it ends or fails.
pub(crate) async fn discard<R>(r: &mut R, chunk: usize, records: bool)
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = vec![0u8; chunk.max(1)];
    loop {
        match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if records && super::is_message_too_large(&e) => {}
            Err(_) => break,
        }
    }
}

/// The source of a TCP connection that arrived from `peer`, which `trusted`
/// may say is an intermediary that reports its client with a PROXY protocol
/// header: from a trusted address with the PROXY protocol configured, the
/// header is read (exactly, nothing after it) and the client it reports is
/// returned, or `peer` for the intermediary's own connections (`LOCAL`,
/// `UNKNOWN`); a missing or invalid header is an error, and the caller
/// closes the connection. From any other address nothing is read and the
/// source is `peer`. Bound the call (the listener's handshake timeout, an
/// admission's peek timeout).
///
/// # Errors
///
/// From a trusted intermediary: [`io::ErrorKind::InvalidData`] for a header
/// that is not a valid PROXY protocol header, or the read's error (an early
/// end is [`io::ErrorKind::UnexpectedEof`]).
pub async fn proxied_source<S>(
    io: &mut S,
    peer: SocketAddr,
    trusted: &crate::proto::trusted::TrustedProxies,
) -> io::Result<SocketAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    use crate::proto::trusted::{ProxyHeader, parse_proxy_header};
    if !trusted.proxy_protocol() || !trusted.trusts(peer.ip()) {
        return Ok(peer);
    }
    let mut buf = Vec::with_capacity(crate::proto::trusted::PROXY_V1_MAX);
    loop {
        match parse_proxy_header(&buf) {
            ProxyHeader::Complete { source, .. } => return Ok(source.unwrap_or(peer)),
            ProxyHeader::Invalid => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no valid PROXY protocol header from a trusted intermediary",
                ));
            }
            ProxyHeader::Incomplete(need) => {
                let have = buf.len();
                buf.resize(need, 0);
                io.read_exact(&mut buf[have..]).await?;
            }
        }
    }
}

/// A byte stream with bytes read from it before given back in front: reads
/// return the prefix first, then the stream's own bytes, read into the
/// caller's buffer without a further copy. Writes and shutdown go to the
/// stream.
#[derive(Debug)]
pub struct Prefixed<T> {
    prefix: Vec<u8>,
    pos: usize,
    inner: T,
}

impl<T> Prefixed<T> {
    /// `inner` with `prefix` in front.
    pub fn new(inner: T, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// The stream.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// The stream, mutably, once the prefix is read: `None` while some of
    /// it remains, since reading the stream directly would skip it. The
    /// stream and the unread prefix together: [`Prefixed::into_parts`].
    pub fn get_mut(&mut self) -> Option<&mut T> {
        (self.pos == self.prefix.len()).then_some(&mut self.inner)
    }

    /// The prefix bytes not read yet.
    pub fn prefix(&self) -> &[u8] {
        &self.prefix[self.pos..]
    }

    /// The stream and the prefix bytes not read yet.
    pub fn into_parts(mut self) -> (T, Vec<u8>) {
        self.prefix.drain(..self.pos);
        (self.inner, self.prefix)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let rest = &this.prefix[this.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// The byte stream of a carrier taken over by a fallback
/// ([`Takeover::into_stream`]): the connection itself (a TCP or TLS
/// stream, a QUIC stream's two halves joined). It is [`Any`], so that the
/// host reaches the connection's own type and its capabilities (a TLS
/// stream's connection state): [`Takeover::stream`] before taking it,
/// `(&**prefixed.get_ref() as &dyn Any).downcast_ref::<T>()` after.
pub trait TakeoverStream: AsyncRead + AsyncWrite + Send + Unpin + Any {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + Any> TakeoverStream for T {}

/// A host's value of the connection under a carrier, for the fallback of
/// its adapter's kind (a QUIC connection): see the adapter.
pub type ConnectionValue = Arc<dyn Any + Send + Sync>;

/// The carrier an adapter hands to the listener's admission
/// ([`Entry::admit`](crate::adapter::Entry::admit)): a [`PipeIo`], or a byte
/// stream with how to make it one, which a [`Takeover`] then also gives as
/// the stream itself ([`Takeover::into_stream`]).
pub struct AdmitIo {
    io: Box<dyn Subject>,
    connection: Option<ConnectionValue>,
    on_return: Option<OnReturn>,
    pub(crate) stall_until: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

/// What an adapter closes of a carrier beside its parts once the
/// fallback's future returned it ([`AdmitIo::with_on_return`]).
type OnReturn = Box<dyn FnOnce() + Send>;

impl std::fmt::Debug for AdmitIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmitIo")
            .field("framing", &self.io.framing())
            .finish_non_exhaustive()
    }
}

impl From<PipeIo> for AdmitIo {
    fn from(pipe: PipeIo) -> Self {
        Self::pipe(pipe)
    }
}

impl AdmitIo {
    /// A carrier made into a [`PipeIo`]: what the admission reads is read
    /// from its receiving half (one message per read on a message-framed
    /// carrier, [`PipeIo::records`]), after the bytes it was given back
    /// with ([`PipeIo::with_prefix`]).
    #[must_use]
    pub fn pipe(pipe: PipeIo) -> Self {
        Self {
            io: Box::new(pipe),
            connection: None,
            on_return: None,
            stall_until: None,
        }
    }

    /// A byte stream on one connection (a TCP or TLS stream): read
    /// directly, made a [`PipeIo`] by `carrier` once accepted (and by a
    /// takeover's [`Takeover::into_pipe`], so that it has every capability
    /// `carrier` gives it), and given to a fallback as it is
    /// ([`Takeover::into_stream`]).
    pub fn stream<C>(conn: C, carrier: impl FnOnce(C) -> PipeIo + Send + 'static) -> Self
    where
        C: TakeoverStream,
    {
        Self {
            io: Box::new(StreamIo {
                conn,
                carrier: Box::new(carrier),
            }),
            connection: None,
            on_return: None,
            stall_until: None,
        }
    }

    /// With the connection under the carrier, which a fallback finds in the
    /// takeover ([`Takeover::connection`]).
    #[must_use]
    pub fn with_connection(mut self, connection: ConnectionValue) -> Self {
        self.connection = Some(connection);
        self
    }

    /// With what the adapter closes of the carrier beside its parts (a
    /// QUIC connection, a WebTransport session, an HTTP request) once a
    /// fallback took it over and its future completed, or panicked,
    /// without [`Takeover::detach`]. It runs once, on the fallback's own
    /// task, whether or not the task that admitted the carrier still
    /// waits for it (a cancelled request, a dropped connection), and also
    /// when the runtime shuts down under the future. Not run when the
    /// carrier goes to no fallback.
    #[must_use]
    pub fn with_on_return(mut self, close: impl FnOnce() + Send + 'static) -> Self {
        self.on_return = Some(Box::new(close));
        self
    }

    /// Keeps an upgraded session stalled until it closes or the stall ends.
    #[doc(hidden)]
    #[must_use]
    pub fn with_stall_until(mut self, closed: impl Future<Output = ()> + Send + 'static) -> Self {
        self.stall_until = Some(Box::pin(closed));
        self
    }

    pub(crate) fn attachment(&mut self) -> Option<&Arc<super::attachment::Attachment>> {
        self.io.attachment()
    }

    pub(crate) fn framing(&self) -> Framing {
        self.io.framing()
    }

    pub(crate) fn reader(&mut self) -> Option<&mut (dyn AsyncRead + Unpin + Send)> {
        self.io.reader()
    }

    /// The bytes given back with the carrier, taken.
    pub(crate) fn given_back(&mut self) -> Vec<u8> {
        self.io.given_back()
    }

    /// The accepted carrier, `rest` in front.
    pub(crate) fn into_pipe(self, rest: Vec<u8>) -> PipeIo {
        self.io.into_pipe(rest)
    }

    /// Ends the carrier's sending half gracefully.
    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.io.poll_shutdown(cx)).await
    }

    /// The carrier taken over, `replay` in front, with the value of the
    /// verdict that handed it over.
    pub(crate) fn into_takeover(
        self,
        info: CarrierInfo,
        replay: Vec<u8>,
        value: Option<AdmittedValue>,
    ) -> Takeover {
        Takeover(Box::new(TakeoverParts {
            info,
            replay,
            value,
            io: self.io.into_takeover(),
            connection: self.connection,
            on_return: self.on_return,
            state: Arc::new(TakeoverState::default()),
        }))
    }
}

/// The carrier under admission, of either kind.
trait Subject: Send {
    fn attachment(&mut self) -> Option<&Arc<super::attachment::Attachment>> {
        None
    }
    fn framing(&self) -> Framing;
    fn reader(&mut self) -> Option<&mut (dyn AsyncRead + Unpin + Send)>;
    fn given_back(&mut self) -> Vec<u8>;
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn into_pipe(self: Box<Self>, rest: Vec<u8>) -> PipeIo;
    fn into_takeover(self: Box<Self>) -> TakeoverIo;
}

impl Subject for PipeIo {
    fn attachment(&mut self) -> Option<&Arc<super::attachment::Attachment>> {
        Some(PipeIo::attachment(self))
    }

    fn framing(&self) -> Framing {
        self.framing
    }

    fn reader(&mut self) -> Option<&mut (dyn AsyncRead + Unpin + Send)> {
        self.reader
            .as_mut()
            .map(|r| r as &mut (dyn AsyncRead + Unpin + Send))
    }

    fn given_back(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.prefix)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.writer.as_mut() {
            Some(w) => w.poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn into_pipe(self: Box<Self>, rest: Vec<u8>) -> PipeIo {
        // What it was given back with is in `rest`, if not skipped.
        let mut p = *self;
        p.prefix = rest;
        p
    }

    fn into_takeover(self: Box<Self>) -> TakeoverIo {
        TakeoverIo::Pipe(self)
    }
}

/// How a byte stream becomes its [`PipeIo`], type-erased.
type MakePipe = Box<dyn FnOnce(Box<dyn TakeoverStream>) -> PipeIo + Send>;

struct StreamIo<C> {
    conn: C,
    carrier: Box<dyn FnOnce(C) -> PipeIo + Send>,
}

impl<C: TakeoverStream> Subject for StreamIo<C> {
    fn framing(&self) -> Framing {
        Framing::ByteStream
    }

    fn reader(&mut self) -> Option<&mut (dyn AsyncRead + Unpin + Send)> {
        Some(&mut self.conn)
    }

    fn given_back(&mut self) -> Vec<u8> {
        Vec::new()
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }

    fn into_pipe(self: Box<Self>, rest: Vec<u8>) -> PipeIo {
        let Self { conn, carrier } = *self;
        carrier(conn).with_prefix(rest)
    }

    fn into_takeover(self: Box<Self>) -> TakeoverIo {
        let Self { conn, carrier } = *self;
        let make: MakePipe = Box::new(move |s: Box<dyn TakeoverStream>| {
            let s: Box<dyn Any> = s;
            match s.downcast::<C>() {
                Ok(c) => carrier(*c),
                // The stream is the one it was made with.
                Err(_) => unreachable!("a takeover's stream of another type"),
            }
        });
        TakeoverIo::Stream(Box::new(conn), make)
    }
}

enum TakeoverIo {
    Pipe(Box<PipeIo>),
    Stream(Box<dyn TakeoverStream>, MakePipe),
}

/// Whose a taken-over carrier is: the fallback's for its future, then the
/// adapter's to close (returned), unless the host detached it first.
#[derive(Debug, Default)]
pub(crate) struct TakeoverState(AtomicU8);

const HELD: u8 = 0;
const DETACHED: u8 = 1;
const RETURNED: u8 = 2;

impl TakeoverState {
    /// The fallback's future completed: whether the host detached the
    /// carrier (else it is returned, and a later detach fails).
    pub(crate) fn finish(&self) -> bool {
        match self
            .0
            .compare_exchange(HELD, RETURNED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => false,
            Err(s) => s == DETACHED,
        }
    }

    fn is_detached(&self) -> bool {
        self.0.load(Ordering::Acquire) == DETACHED
    }

    fn detach(&self) -> Result<(), TakeoverReturned> {
        match self
            .0
            .compare_exchange(HELD, DETACHED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(DETACHED) => Ok(()),
            Err(_) => Err(TakeoverReturned),
        }
    }
}

/// [`Takeover::detach`] after the fallback's future completed: what the
/// adapter held of the carrier is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TakeoverReturned;

impl std::fmt::Display for TakeoverReturned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the fallback's future completed before the takeover was detached")
    }
}

impl std::error::Error for TakeoverReturned {}

/// A carrier the listener's admission hands to the host
/// ([`crate::ListenerConfig::fallback`]): on
/// [`AdmissionVerdict::Fallback`](crate::AdmissionVerdict::Fallback), or on a
/// prefix that [`Admission::with_fallback_on_peek_timeout`](crate::Admission::with_fallback_on_peek_timeout)
/// gave up on, whatever entry took it (a TCP or TLS stream, a WebSocket
/// after a deferred decision, a QUIC connection's or a WebTransport
/// session's first stream, an HTTP request carrier decided on its body, a
/// [`PipeIo`] given to [`Listener::handle_pipe`](crate::Listener::handle_pipe)).
/// What was read of it is replayed: the bytes of a byte stream, the first
/// message of a message-framed carrier (always a whole, non-empty binary
/// message: a carrier whose first read fails is closed without a
/// decision).
///
/// # Ownership
///
/// The carrier's parts are owned values: whoever holds a part closes it,
/// once, by shutting it down or dropping it (the host, or the library when
/// the fallback's future drops what it did not take). A part closes on its
/// own: the sending half shut down, the receiving one read on to its end.
///
/// The fallback's future is the call: it runs on a task of its own, from
/// the admission to its completion, at every entry point. Nothing the entry
/// does (the listener's close, the setup bound of
/// [`Listener::serve_connections`](crate::Listener::serve_connections), a
/// cancelled HTTP request) cancels it. When it completes, the adapter
/// closes what it holds of the carrier beside its parts (the QUIC
/// connection of a stream, the WebTransport session, the HTTP request of a
/// request carrier, whose response is then reset if not ended), unless the
/// host called [`Takeover::detach`] in the future: all of it is then the
/// host's, to serve on any task after the future completed and to close
/// once done.
pub struct Takeover(Box<TakeoverParts>);

struct TakeoverParts {
    info: CarrierInfo,
    replay: Vec<u8>,
    value: Option<AdmittedValue>,
    io: TakeoverIo,
    connection: Option<ConnectionValue>,
    /// Taken by [`Fallback::serve`], never the host's.
    on_return: Option<OnReturn>,
    state: Arc<TakeoverState>,
}

impl std::fmt::Debug for Takeover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Takeover")
            .field("info", &self.0.info)
            .field("replayed", &self.0.replay.len())
            .field("stream", &self.has_stream())
            .field("value", &self.0.value.is_some())
            .finish_non_exhaustive()
    }
}

impl Takeover {
    /// The carrier's metadata, as the decision saw it.
    #[must_use]
    pub fn info(&self) -> &CarrierInfo {
        &self.0.info
    }

    /// The carrier's framing: [`Framing::Records`] for a message-framed
    /// carrier, whose replay is its first message.
    #[must_use]
    pub fn framing(&self) -> Framing {
        self.0.info.framing
    }

    /// What the admission read, replayed in front of either view.
    #[must_use]
    pub fn replayed(&self) -> &[u8] {
        &self.0.replay
    }

    /// The host's value of the verdict that handed the carrier over
    /// ([`AdmissionVerdict::with_value`](crate::AdmissionVerdict::with_value)
    /// on [`AdmissionVerdict::Fallback`](crate::AdmissionVerdict::Fallback)):
    /// its routing of the carrier to a service of its own; `None` without
    /// one, and after a peek timeout.
    #[must_use]
    pub fn value(&self) -> Option<&AdmittedValue> {
        self.0.value.as_ref()
    }

    /// The connection under the carrier, as its adapter gives it (a
    /// `quinn::Connection`): downcast it, or use the adapter's accessor.
    #[must_use]
    pub fn connection(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.0.connection.as_deref()
    }

    /// Whether the carrier is a byte stream on one connection
    /// ([`Takeover::into_stream`] gives it).
    #[must_use]
    pub fn has_stream(&self) -> bool {
        matches!(self.0.io, TakeoverIo::Stream(..))
    }

    /// The byte stream of a carrier on one connection as its own type `T`
    /// (a TLS stream, for its connection state), before it is taken.
    #[must_use]
    pub fn stream<T: Any>(&self) -> Option<&T> {
        match &self.0.io {
            TakeoverIo::Stream(s, _) => (&**s as &dyn Any).downcast_ref::<T>(),
            TakeoverIo::Pipe(_) => None,
        }
    }

    /// Makes the carrier the host's for good: the adapter does not close
    /// what it holds of it when the fallback's future completes (see
    /// [`Takeover`]), so that the host may hand the carrier, or what it
    /// made of it, to another task and complete. The host then closes all
    /// of it once done: dropping or shutting down its parts, and the
    /// adapter's connection, if it took it ([`Takeover::connection`]). A
    /// second call is `Ok`.
    ///
    /// # Errors
    ///
    /// [`TakeoverReturned`] once the future completed without it (the host
    /// moved the takeover out of the future): what the adapter held is
    /// closed then.
    pub fn detach(&self) -> Result<(), TakeoverReturned> {
        self.0.state.detach()
    }

    /// Whether [`Takeover::detach`] made the carrier the host's.
    #[must_use]
    pub fn is_detached(&self) -> bool {
        self.0.state.is_detached()
    }

    /// The carrier as a pipe, what was read replayed first: on a
    /// message-framed carrier the first message is the first message read
    /// again. It is the carrier an acceptance would have handed on, with
    /// every capability of it (TLS state, exporter, Bound contract, failure
    /// reporting, carrier connection, lanes, abort, close code, unsent and
    /// retransmission counts, ...): the [`PipeIo`] is the one place a
    /// carrier's capabilities are kept, and a takeover moves it as a whole.
    /// Read and write it by units with [`PipeIo::read_handshake`] and
    /// [`PipeIo::write_handshake`] (a message each on a message-framed
    /// carrier, see also [`Takeover::into_messages`]), or as a stream with
    /// [`PipeIo::into_stream`]; both read the replay first.
    #[must_use]
    pub fn into_pipe(self) -> PipeIo {
        let TakeoverParts { io, replay, .. } = *self.0;
        match io {
            TakeoverIo::Pipe(p) => p.with_prefix(replay),
            TakeoverIo::Stream(s, make) => make(s).with_prefix(replay),
        }
    }

    /// The carrier as the byte stream it is on one connection, with the
    /// same replay in front ([`Prefixed`]): once it is read, reads go to
    /// the connection itself, which [`Prefixed::get_mut`] gives only then
    /// (no direct read skips the replay; [`Prefixed::into_parts`] hands
    /// the connection and what remains of the replay together). The
    /// capabilities are the stream's own, through its type
    /// ([`TakeoverStream`]). `Err(self)` when the carrier is not one
    /// ([`Takeover::has_stream`]): use [`Takeover::into_pipe`].
    ///
    /// # Errors
    ///
    /// The takeover, unchanged, for a carrier that is no single stream.
    pub fn into_stream(self) -> Result<Prefixed<Box<dyn TakeoverStream>>, Self> {
        let parts = *self.0;
        match parts.io {
            TakeoverIo::Stream(s, _) => Ok(Prefixed::new(s, parts.replay)),
            io @ TakeoverIo::Pipe(_) => Err(Self(Box::new(TakeoverParts { io, ..parts }))),
        }
    }

    /// The halves of a message-framed carrier ([`Framing::Records`], such
    /// as a WebSocket), read and written by whole messages, the first one
    /// read again first. `Err(self)` for a byte stream.
    ///
    /// # Errors
    ///
    /// The takeover, unchanged, for a carrier that is not message-framed.
    pub fn into_messages(self) -> Result<Messages, Self> {
        if self.framing() != Framing::Records {
            return Err(self);
        }
        Ok(Messages {
            io: self.into_pipe(),
            buf: Vec::new(),
        })
    }
}

/// A taken-over message-framed carrier ([`Takeover::into_messages`]): each
/// read a whole message, each write one, the replayed first message
/// first. The [`PipeIo`] under it keeps the carrier's capabilities.
#[derive(Debug)]
pub struct Messages {
    io: PipeIo,
    /// The read buffer, reused across reads.
    buf: Vec<u8>,
}

impl Messages {
    /// The next message, of at most `max` bytes (a longer one is an
    /// error, its message discarded: the replayed first message too);
    /// `None` at the carrier's end.
    ///
    /// # Errors
    ///
    /// The carrier's read error, one for a message over `max`, or
    /// [`io::ErrorKind::UnexpectedEof`] without a receiving half.
    pub async fn read_message(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        let p = &mut self.io;
        read_unit(&mut p.prefix, p.reader.as_mut(), &mut self.buf, max).await
    }

    /// Writes `message` as one message.
    ///
    /// # Errors
    ///
    /// The carrier's write error, or [`io::ErrorKind::BrokenPipe`] without
    /// a sending half.
    pub async fn write_message(&mut self, message: &[u8]) -> io::Result<()> {
        super::sealed::write_unit(&mut self.io, message).await
    }

    /// Ends the sending half gracefully; the receiving half reads on.
    ///
    /// # Errors
    ///
    /// The carrier's error.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| match self.io.writer.as_mut() {
            Some(w) => w.poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        })
        .await
    }

    /// The carrier, with its capabilities.
    #[must_use]
    pub fn get_ref(&self) -> &PipeIo {
        &self.io
    }

    /// The carrier as a pipe, what remains of the replay in front.
    #[must_use]
    pub fn into_inner(self) -> PipeIo {
        self.io
    }

    /// The two halves, owned, to read and write from two tasks at once:
    /// the reader gets the receiving half and what remains of the replayed
    /// first message, the writer the sending half and the carrier's other
    /// capabilities ([`MessageWriter::get_ref`]). Each half closes its own
    /// part once, when dropped.
    #[must_use]
    pub fn split(self) -> (MessageReader, MessageWriter) {
        let mut io = self.io;
        let reader = MessageReader {
            reader: io.reader.take(),
            replay: std::mem::take(&mut io.prefix),
            buf: self.buf,
        };
        (reader, MessageWriter(io))
    }
}

/// The receiving half of a split [`Messages`] ([`Messages::split`]).
pub struct MessageReader {
    reader: Option<super::tokio::Reader>,
    replay: Vec<u8>,
    buf: Vec<u8>,
}

impl std::fmt::Debug for MessageReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageReader")
            .field("replayed", &self.replay.len())
            .finish_non_exhaustive()
    }
}

impl MessageReader {
    /// The next message, as [`Messages::read_message`] reads it.
    ///
    /// # Errors
    ///
    /// As [`Messages::read_message`].
    pub async fn read_message(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        read_unit(&mut self.replay, self.reader.as_mut(), &mut self.buf, max).await
    }
}

/// The sending half of a split [`Messages`] ([`Messages::split`]), with
/// the carrier's capabilities.
#[derive(Debug)]
pub struct MessageWriter(PipeIo);

impl MessageWriter {
    /// Writes `message` as one message.
    ///
    /// # Errors
    ///
    /// As [`Messages::write_message`].
    pub async fn write_message(&mut self, message: &[u8]) -> io::Result<()> {
        super::sealed::write_unit(&mut self.0, message).await
    }

    /// Ends the sending half gracefully.
    ///
    /// # Errors
    ///
    /// The carrier's error.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| match self.0.writer.as_mut() {
            Some(w) => w.poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        })
        .await
    }

    /// The carrier, with its capabilities (its receiving half is the
    /// reader's).
    #[must_use]
    pub fn get_ref(&self) -> &PipeIo {
        &self.0
    }
}

/// One message of at most `max` bytes: the replayed one first, then the
/// carrier's, read into `buf` (reused, grown to the largest `max`) and
/// copied out at its own length.
async fn read_unit<R: AsyncRead + Unpin + ?Sized>(
    replay: &mut Vec<u8>,
    reader: Option<&mut R>,
    buf: &mut Vec<u8>,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    if !replay.is_empty() {
        let first = std::mem::take(replay);
        if first.len() > max {
            return Err(crate::adapter::message_too_large());
        }
        return Ok(Some(first));
    }
    let r = reader.ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let room = max.max(1);
    if buf.len() < room {
        buf.resize(room, 0);
    }
    let mut rb = ReadBuf::new(&mut buf[..room]);
    std::future::poll_fn(|cx| Pin::new(&mut *r).poll_read(cx, &mut rb)).await?;
    let n = rb.filled().len();
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(buf[..n].to_vec()))
}

type FallbackFn =
    dyn Fn(Takeover) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> + Send + Sync;

/// The listener's fallback ([`crate::ListenerConfig::fallback`]): a
/// handler given every carrier the admission hands back, as a
/// [`Takeover`]. Its future runs on a task of its own (see
/// [`Takeover`]). A handler that panics closes that carrier, not the
/// process: a peer reaches it with any bytes that are not zmux's. Cheap
/// to clone.
#[derive(Clone)]
pub struct Fallback(Arc<FallbackFn>);

impl std::fmt::Debug for Fallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fallback(..)")
    }
}

/// How a fallback's future ended.
#[derive(Debug)]
pub(crate) struct Served {
    /// The handler failed or its task ended without a successful return.
    pub(crate) error: Option<io::Error>,
    /// The host detached the carrier.
    pub(crate) detached: bool,
}

impl Fallback {
    /// The handler `f`.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(Takeover) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self::try_new(move |t| {
            let future = f(t);
            async move {
                future.await;
                Ok(())
            }
        })
    }

    /// A fallible callback. An error ends setup with `HandleError::SetupFailed`.
    pub fn try_new<F, Fut>(f: F) -> Self
    where
        F: Fn(Takeover) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<()>> + Send + 'static,
    {
        Self(Arc::new(move |t| Box::pin(f(t))))
    }

    /// Serves `takeover` to its end, on a task of its own: the caller's
    /// cancellation does not end it, and the end of the future (completed,
    /// panicked, or dropped by the runtime's shutdown) is acted on there:
    /// the takeover returned unless detached, and the adapter's
    /// [`AdmitIo::with_on_return`] run then.
    pub(crate) async fn serve(
        &self,
        mut takeover: Takeover,
        dispatched: impl FnOnce() + Send + 'static,
    ) -> Served {
        let state = takeover.0.state.clone();
        let end = Returned {
            state: state.clone(),
            on_return: takeover.0.on_return.take(),
        };
        let handler = self.0.clone();
        let task = tokio::spawn(async move {
            let mut end = end;
            dispatched();
            let result = crate::proto::decision::host_result(|| handler(takeover)).await;
            let cleaned = end.finish();
            let outcome = result.map_err(|payload| {
                let msg = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("fallback panicked");
                io::Error::other(msg.to_owned())
            })?;
            outcome?;
            if cleaned {
                Ok(())
            } else {
                Err(io::Error::other("fallback return hook panicked"))
            }
        });
        let error = match task.await {
            Ok(result) => result.err(),
            Err(e) => Some(io::Error::other(e)),
        };
        Served {
            error,
            detached: state.is_detached(),
        }
    }
}

/// The end of a fallback's future, however it ends: dropped with its
/// task.
struct Returned {
    state: Arc<TakeoverState>,
    on_return: Option<OnReturn>,
}

impl Returned {
    fn finish(&mut self) -> bool {
        if !self.state.finish()
            && let Some(close) = self.on_return.take()
        {
            return crate::proto::decision::host(close).is_some();
        }
        true
    }
}

impl Drop for Returned {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn prefixed_replays_then_reads_through() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"world").await.unwrap();
        drop(a);
        let mut p = Prefixed::new(b, b"hello ".to_vec());
        let mut out = String::new();
        p.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }

    #[tokio::test(start_paused = true)]
    async fn prefix_is_bounded() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(b"0123456789").await.unwrap();
        let clock = ClockDomain::default();
        let deadline = clock.now().checked_add(Duration::from_secs(5));
        let (p, late) = read_more(Vec::new(), 4, &mut b, &clock, deadline).await;
        assert_eq!((&p[..], late), (&b"0123"[..], false));
        let mut rest = [0u8; 6];
        b.read_exact(&mut rest).await.unwrap();
        let deadline = clock.now().checked_add(Duration::from_millis(20));
        let (p, late) = read_more(Vec::new(), 4, &mut b, &clock, deadline).await;
        assert!(p.is_empty() && late, "timed out with nothing read");
    }

    /// A reader of messages: one per read, too long ones refused whole.
    struct Messages(std::collections::VecDeque<io::Result<Vec<u8>>>);

    impl AsyncRead for Messages {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.0.pop_front() {
                None => Poll::Pending,
                Some(Err(e)) => Poll::Ready(Err(e)),
                Some(Ok(m)) if m.len() > buf.remaining() => {
                    Poll::Ready(Err(crate::adapter::message_too_large()))
                }
                Some(Ok(m)) => {
                    buf.put_slice(&m);
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn first_message_is_bounded() {
        let clock = ClockDomain::default();
        let at = || clock.now().checked_add(Duration::from_secs(1));
        let msgs = |m: Vec<io::Result<Vec<u8>>>| Messages(m.into());
        let mut r = msgs(vec![Ok(vec![1; 8])]);
        assert_eq!(
            read_message(&mut r, 8, &clock, at()).await,
            FirstMessage::Message(vec![1; 8])
        );
        // One byte over, whether the reader has the room or not.
        let mut r = msgs(vec![Ok(vec![1; 9])]);
        assert_eq!(
            read_message(&mut r, 8, &clock, at()).await,
            FirstMessage::TooLarge(Some(vec![1; 9]))
        );
        let mut r = msgs(vec![Ok(vec![1; 10])]);
        assert_eq!(
            read_message(&mut r, 8, &clock, at()).await,
            FirstMessage::TooLarge(None)
        );
        // Ended, failed, an empty message: nothing to decide on.
        let mut r = tokio::io::empty();
        assert_eq!(
            read_message(&mut r, 8, &clock, at()).await,
            FirstMessage::Failed
        );
        let mut r = msgs(vec![Err(io::ErrorKind::InvalidData.into())]);
        assert_eq!(
            read_message(&mut r, 8, &clock, at()).await,
            FirstMessage::Failed
        );
        let mut r = msgs(vec![Err(crate::adapter::empty_message())]);
        assert_eq!(
            read_message(&mut r, 8, &clock, at()).await,
            FirstMessage::Failed
        );
        let mut r = msgs(vec![]);
        assert_eq!(
            read_message(&mut r, 8, &clock, at()).await,
            FirstMessage::Late
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stall_discards_long_messages() {
        let mut r = Messages(
            vec![
                Ok(vec![1; 100]),
                Ok(vec![2; 3]),
                Ok(vec![3; 1000]),
                Err(io::ErrorKind::BrokenPipe.into()),
            ]
            .into(),
        );
        discard(&mut r, 16, true).await;
        assert!(r.0.is_empty(), "read on past the long ones to the error");
        // A byte stream's error ends it.
        let mut r = Messages(vec![Err(crate::adapter::message_too_large()), Ok(vec![1])].into());
        discard(&mut r, 16, false).await;
        assert_eq!(r.0.len(), 1);
    }

    /// A carrier with every capability a host can declare.
    fn capable(io: PipeIo) -> PipeIo {
        let conn = Arc::new(());
        io.with_abort(|| {})
            .with_exporter(|_, _, out| {
                out.fill(7);
                true
            })
            .with_protocol("p")
            .with_carrier(crate::CarrierKind::Streaming)
            .with_variant("v")
            .with_terminated_tls(|| Some(crate::TlsState::new(Some(b"h2".to_vec()), None)))
            .with_unsent(|| Some(1))
            .with_establish_receipts([
                Some(crate::shaping::EstablishReceipt {
                    at: std::time::Instant::now(),
                    baseline: 20,
                    allowance: 3,
                    extra: 3,
                    delay: Duration::ZERO,
                }),
                None,
            ])
            .with_write_overhead(4)
            .with_max_record(16_384)
            .unwrap()
            .with_carrier_secure()
            .with_secure_first_pipe(crate::proto::seal::RecordMode::Bound)
            .with_admitted(Arc::new(5u8))
            .with_low_water()
            .with_partial_reads()
            .with_carrier_conn(super::super::lanes::CarrierConnId::new(&conn))
            .with_lanes(true)
            .with_connection_memory(6)
            .with_taken(|| {})
            .with_close_code(|_| {})
            .with_drain(async {}, Duration::from_secs(1))
            .with_reports_failure(true)
    }

    /// Every capability of a carrier reaches the host through a takeover,
    /// of either kind of carrier: the [`PipeIo`] is the one place they are
    /// kept, and the takeover moves it whole. The destructuring has no
    /// rest pattern: a new field fails to compile here until it is
    /// classified.
    fn assert_forwarded(p: PipeIo, replay: &[u8]) {
        let PipeIo {
            reader,
            writer,
            framing,
            abort,
            exporter,
            // Set with early data only; part of the moved carrier.
            exporter_ready: _,
            protocol,
            carrier,
            variant,
            tls,
            prefix,
            // A TCP socket's: part of the moved carrier.
            socket: _,
            unsent,
            establish_receipts,
            write_overhead,
            max_record,
            secure,
            // A paired split carrier's, which is never taken over.
            split: _,
            first_mode,
            admission_evidence,
            low_water,
            partial_reads,
            // A stream carrier's outer session: part of the moved carrier.
            outer: _,
            lanes,
            conn_memory,
            // Carrier early data: part of the moved carrier.
            early: _,
            taken,
            // A split bootstrap's, which is never taken over.
            split_bootstrap: _,
            attachment: _,
            close_code,
            drain,
            reports_failure,
            ..
        } = p;
        assert!(reader.is_some() && writer.is_some());
        assert_eq!(framing, Framing::ByteStream);
        assert!(abort.is_some() && exporter.is_some() && tls.is_some());
        assert_eq!(protocol.as_deref(), Some("p"));
        assert_eq!(carrier, Some(crate::CarrierKind::Streaming));
        assert_eq!(variant.as_deref(), Some("v"));
        assert_eq!(prefix, replay);
        assert!(unsent.is_some());
        assert_eq!(
            (establish_receipts[0].unwrap().extra, write_overhead),
            (3, 4)
        );
        assert_eq!(max_record, Some(16_384));
        assert!(secure && low_water && partial_reads && reports_failure);
        assert_eq!(first_mode, Some(crate::proto::seal::RecordMode::Bound));
        let evidence = admission_evidence.unwrap();
        assert!(evidence.value.is_some() && evidence.bound_prefix.is_none());
        let lanes = lanes.expect("lane capabilities");
        assert!(lanes.conn.is_some() && lanes.on == Some(true));
        assert_eq!(conn_memory, 6);
        assert!(taken.is_some() && close_code.is_some() && drain.is_some());
    }

    #[tokio::test]
    async fn a_takeover_forwards_every_capability() {
        let info = CarrierInfo::new();
        // A carrier given as a pipe.
        let (a, _b) = tokio::io::duplex(64);
        let io = AdmitIo::pipe(capable(PipeIo::new(a)));
        let t = io.into_takeover(info.clone(), b"replay".to_vec(), None);
        assert_forwarded(t.into_pipe(), b"replay");
        // A byte stream, made a pipe as an acceptance would.
        let (a, _b) = tokio::io::duplex(64);
        let io = AdmitIo::stream(a, |s| capable(PipeIo::new(s)));
        let t = io.into_takeover(info, b"replay".to_vec(), None);
        assert!(t.stream::<tokio::io::DuplexStream>().is_some());
        assert_forwarded(t.into_pipe(), b"replay");
    }

    /// A message-framed carrier taken over, `first` replayed.
    fn messages(first: &[u8]) -> (super::Messages, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(1024);
        let info = CarrierInfo::new().with_framing(Framing::Records);
        let t = AdmitIo::pipe(PipeIo::new(a).records()).into_takeover(info, first.to_vec(), None);
        (t.into_messages().expect("message-framed"), b)
    }

    #[tokio::test]
    async fn the_replayed_message_is_bounded_too() {
        let (mut m, _b) = messages(b"0123456789");
        let e = m.read_message(4).await.unwrap_err();
        assert_eq!(e.kind(), crate::adapter::message_too_large().kind());
        let (mut m, _b) = messages(b"0123");
        assert_eq!(m.read_message(4).await.unwrap(), Some(b"0123".to_vec()));
    }

    #[tokio::test]
    async fn message_reads_reuse_one_buffer() {
        let (mut m, mut b) = messages(b"x");
        m.read_message(16).await.unwrap();
        for msg in [&b"ab"[..], b"cde"] {
            b.write_all(msg).await.unwrap();
            assert_eq!(m.read_message(64).await.unwrap().as_deref(), Some(msg));
        }
        assert_eq!(m.buf.len(), 64, "grown once, to the largest bound");
        let p = m.buf.as_ptr();
        b.write_all(b"f").await.unwrap();
        m.read_message(8).await.unwrap();
        assert_eq!(m.buf.as_ptr(), p, "not reallocated");
    }

    /// The halves of a split carrier work from two tasks: a read pending
    /// on one does not hold up writes on the other.
    #[tokio::test]
    async fn split_messages_are_full_duplex() {
        let (m, b) = messages(b"first");
        let (mut r, mut w) = m.split();
        assert_eq!(r.read_message(16).await.unwrap(), Some(b"first".to_vec()));
        let reading = tokio::spawn(async move { (r.read_message(16).await, r) });
        tokio::task::yield_now().await;
        assert!(!reading.is_finished(), "the read waits for a message");
        let (mut br, mut bw) = tokio::io::split(b);
        for msg in [&b"one"[..], b"two"] {
            w.write_message(msg).await.unwrap();
            let mut got = vec![0; msg.len()];
            br.read_exact(&mut got).await.unwrap();
            assert_eq!(got, msg);
        }
        assert!(!reading.is_finished());
        bw.write_all(b"back").await.unwrap();
        let (got, r) = reading.await.unwrap();
        assert_eq!(got.unwrap(), Some(b"back".to_vec()));
        // Each half ends its own part.
        w.shutdown().await.unwrap();
        let mut end = Vec::new();
        br.read_to_end(&mut end).await.unwrap();
        assert_eq!(end, b"");
        drop(r);
    }

    #[tokio::test]
    async fn prefixed_gives_the_stream_only_after_the_replay() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"!").await.unwrap();
        let mut p = Prefixed::new(b, b"ab".to_vec());
        assert!(p.get_mut().is_none(), "the replay is unread");
        let mut one = [0u8; 1];
        p.read_exact(&mut one).await.unwrap();
        assert!(p.get_mut().is_none(), "one byte of it remains");
        p.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"b");
        let inner = p.get_mut().expect("the replay is read");
        inner.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"!");
    }

    /// The fallback's future ends on its own task even when the admitting
    /// future is dropped: the takeover is returned (a later detach fails)
    /// and the adapter's close runs.
    #[tokio::test]
    async fn a_dropped_admission_still_returns_the_takeover() {
        use std::sync::atomic::AtomicBool;
        let (go_tx, go) = tokio::sync::oneshot::channel::<()>();
        let (held_tx, held) = tokio::sync::oneshot::channel::<Takeover>();
        let go = std::sync::Mutex::new(Some((go, held_tx)));
        let f = Fallback::new(move |t: Takeover| {
            let (go, held_tx) = go.lock().unwrap().take().unwrap();
            async move {
                let _ = go.await;
                // The host keeps the takeover past its future.
                let _ = held_tx.send(t);
            }
        });
        let closed = Arc::new(AtomicBool::new(false));
        let c = closed.clone();
        let (a, _b) = tokio::io::duplex(64);
        let t = AdmitIo::pipe(PipeIo::new(a))
            .with_on_return(move || c.store(true, Ordering::SeqCst))
            .into_takeover(CarrierInfo::new(), Vec::new(), None);
        let mut serving = Box::pin(f.serve(t, || {}));
        assert!(futures_poll_once(serving.as_mut()).await.is_none());
        drop(serving);
        assert!(!closed.load(Ordering::SeqCst), "held while the future runs");
        go_tx.send(()).unwrap();
        let t = held.await.unwrap();
        // The future completed: returned, closed.
        tokio::task::yield_now().await;
        assert!(closed.load(Ordering::SeqCst), "the adapter's close ran");
        assert_eq!(t.detach(), Err(TakeoverReturned));
    }

    /// A panicking fallback is reported, the carrier closed.
    #[tokio::test]
    async fn a_panicking_fallback_closes_the_carrier() {
        use std::sync::atomic::AtomicBool;
        let f = Fallback::new(|_t: Takeover| async move { panic!("host bug") });
        let closed = Arc::new(AtomicBool::new(false));
        let c = closed.clone();
        let (a, _b) = tokio::io::duplex(64);
        let t = AdmitIo::pipe(PipeIo::new(a))
            .with_on_return(move || c.store(true, Ordering::SeqCst))
            .into_takeover(CarrierInfo::new(), Vec::new(), None);
        let served = f.serve(t, || {}).await;
        assert!(served.error.is_some() && !served.detached);
        assert!(closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    // HS-07
    async fn a_panicking_return_hook_fails_fallback_once() {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called = count.clone();
        let (a, _) = tokio::io::duplex(64);
        let takeover = AdmitIo::pipe(PipeIo::new(a))
            .with_on_return(move || {
                called.fetch_add(1, Ordering::SeqCst);
                panic!("adapter close");
            })
            .into_takeover(CarrierInfo::new(), Vec::new(), None);
        assert!(
            Fallback::new(|_| async {})
                .serve(takeover, || {})
                .await
                .error
                .is_some()
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// A detached takeover leaves the close to the host.
    #[tokio::test]
    async fn a_detached_takeover_is_not_closed() {
        use std::sync::atomic::AtomicBool;
        let f = Fallback::new(|t: Takeover| async move { t.detach().unwrap() });
        let closed = Arc::new(AtomicBool::new(false));
        let c = closed.clone();
        let (a, _b) = tokio::io::duplex(64);
        let t = AdmitIo::pipe(PipeIo::new(a))
            .with_on_return(move || c.store(true, Ordering::SeqCst))
            .into_takeover(CarrierInfo::new(), Vec::new(), None);
        let served = f.serve(t, || {}).await;
        assert!(served.detached && served.error.is_none());
        assert!(!closed.load(Ordering::SeqCst));
    }

    /// Polls `f` once.
    async fn futures_poll_once<F: Future + Unpin>(mut f: F) -> Option<F::Output> {
        std::future::poll_fn(|cx| match Pin::new(&mut f).poll(cx) {
            Poll::Ready(v) => Poll::Ready(Some(v)),
            Poll::Pending => Poll::Ready(None),
        })
        .await
    }
}
