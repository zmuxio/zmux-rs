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
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use super::tokio::PipeIo;
use crate::proto::admission::CarrierInfo;
use crate::proto::record::Framing;

/// Reads on until `prefix` holds `need` bytes, the carrier ends, or
/// `deadline` passes; returns it and whether the deadline passed.
pub(crate) async fn read_more<R>(
    mut prefix: Vec<u8>,
    need: usize,
    r: &mut R,
    deadline: Instant,
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
    let late = tokio::time::timeout_at(deadline, fill).await.is_err();
    prefix.truncate(got);
    (prefix, late)
}

/// What reading a message-framed carrier's first message gave.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FirstMessage {
    /// The message, whole.
    Message(Vec<u8>),
    /// Longer than the bound.
    TooLarge,
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
pub(crate) async fn read_message<R>(r: &mut R, max: usize, deadline: Instant) -> FirstMessage
where
    R: AsyncRead + Unpin + ?Sized,
{
    // One byte more than the bound: a longer message is told apart from
    // one of the bound's length either way.
    let mut buf = vec![0u8; max.saturating_add(1)];
    let read = tokio::time::timeout_at(deadline, r.read(&mut buf)).await;
    match read {
        Err(_) => FirstMessage::Late,
        Ok(Ok(n)) if n > max => FirstMessage::TooLarge,
        Ok(Ok(0)) => FirstMessage::Failed,
        Ok(Ok(n)) => {
            buf.truncate(n);
            FirstMessage::Message(buf)
        }
        Ok(Err(e)) if super::is_message_too_large(&e) => FirstMessage::TooLarge,
        Ok(Err(_)) => FirstMessage::Failed,
    }
}

/// Reads and discards what arrives on `r`, `chunk` bytes at a time (a
/// message at a time on a message-framed carrier, `records`, one too long
/// for the chunk dropped by the reader), until it ends, fails, or
/// `duration` has passed.
pub(crate) async fn discard<R>(r: &mut R, chunk: usize, duration: Duration, records: bool)
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = vec![0u8; chunk.max(1)];
    let discard = async {
        loop {
            match r.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if records && super::is_message_too_large(&e) => {}
                Err(_) => break,
            }
        }
    };
    let _ = tokio::time::timeout(duration, discard).await;
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

    /// The stream, mutably: reading it directly skips what remains of the
    /// prefix.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
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
/// stream, a QUIC stream's two halves joined).
pub trait TakeoverStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> TakeoverStream for T {}

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
}

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
        }
    }

    /// A byte stream on one connection (a TCP or TLS stream): read
    /// directly, made a [`PipeIo`] by `carrier` once accepted, and given to
    /// a fallback as it is ([`Takeover::into_stream`]).
    pub fn stream<C>(conn: C, carrier: impl FnOnce(C) -> PipeIo + Send + 'static) -> Self
    where
        C: TakeoverStream + 'static,
    {
        Self {
            io: Box::new(StreamIo {
                conn,
                carrier: Box::new(carrier),
            }),
            connection: None,
        }
    }

    /// With the connection under the carrier, which a fallback finds in the
    /// takeover ([`Takeover::connection`]).
    #[must_use]
    pub fn with_connection(mut self, connection: ConnectionValue) -> Self {
        self.connection = Some(connection);
        self
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

    /// The carrier taken over, `replay` in front.
    pub(crate) fn into_takeover(self, info: CarrierInfo, replay: Vec<u8>) -> Takeover {
        Takeover(Box::new(TakeoverParts {
            info,
            replay,
            io: self.io.into_takeover(),
            connection: self.connection,
        }))
    }
}

/// The carrier under admission, of either kind.
trait Subject: Send {
    fn framing(&self) -> Framing;
    fn reader(&mut self) -> Option<&mut (dyn AsyncRead + Unpin + Send)>;
    fn given_back(&mut self) -> Vec<u8>;
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn into_pipe(self: Box<Self>, rest: Vec<u8>) -> PipeIo;
    fn into_takeover(self: Box<Self>) -> TakeoverIo;
}

impl Subject for PipeIo {
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

struct StreamIo<C> {
    conn: C,
    carrier: Box<dyn FnOnce(C) -> PipeIo + Send>,
}

impl<C: TakeoverStream + 'static> Subject for StreamIo<C> {
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
        TakeoverIo::Stream(Box::new(self.conn))
    }
}

enum TakeoverIo {
    Pipe(Box<PipeIo>),
    Stream(Box<dyn TakeoverStream>),
}

/// A carrier the listener's admission hands to the host
/// ([`crate::ListenerConfig::fallback`]): on
/// [`AdmissionVerdict::Fallback`](crate::AdmissionVerdict::Fallback), or on a
/// prefix that [`Admission::with_fallback_on_peek_timeout`](crate::Admission::with_fallback_on_peek_timeout)
/// gave up on, whatever entry took it (a TCP or TLS stream, a WebSocket
/// after a deferred decision, a QUIC connection's or a WebTransport
/// session's first stream, a [`PipeIo`] given to
/// [`Listener::handle_pipe`](crate::Listener::handle_pipe)). What was read
/// of it is replayed: the bytes of a byte stream, the first message of a
/// message-framed carrier (always a whole binary message: a carrier whose
/// first read fails is closed without a decision).
///
/// The carrier is the fallback's for its future: everything of it that
/// the future owns is dropped, and so closed, when it completes, and the
/// adapter closes what it holds of the carrier then (a QUIC connection, a
/// WebTransport session). A host that serves the carrier does so inside
/// the future.
pub struct Takeover(Box<TakeoverParts>);

struct TakeoverParts {
    info: CarrierInfo,
    replay: Vec<u8>,
    io: TakeoverIo,
    connection: Option<ConnectionValue>,
}

impl std::fmt::Debug for Takeover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Takeover")
            .field("info", &self.0.info)
            .field("replayed", &self.0.replay.len())
            .field("stream", &self.has_stream())
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
        matches!(self.0.io, TakeoverIo::Stream(_))
    }

    /// The carrier as a pipe, what was read replayed first: on a
    /// message-framed carrier the first message is the first message read
    /// again. Read and write it by units with [`PipeIo::read_handshake`]
    /// and [`PipeIo::write_handshake`] (a message each on a message-framed
    /// carrier).
    #[must_use]
    pub fn into_pipe(self) -> PipeIo {
        let TakeoverParts { io, replay, .. } = *self.0;
        match io {
            TakeoverIo::Pipe(p) => p.with_prefix(replay),
            TakeoverIo::Stream(s) => PipeIo::new(s).with_prefix(replay),
        }
    }

    /// The carrier as the byte stream it is on one connection, with the
    /// same replay in front ([`Prefixed`]): once it is read, reads go to
    /// the connection itself. `Err(self)` when the carrier is not one
    /// ([`Takeover::has_stream`]): use [`Takeover::into_pipe`].
    ///
    /// # Errors
    ///
    /// The takeover, unchanged, for a carrier that is no single stream.
    pub fn into_stream(self) -> Result<Prefixed<Box<dyn TakeoverStream>>, Self> {
        let parts = *self.0;
        match parts.io {
            TakeoverIo::Stream(s) => Ok(Prefixed::new(s, parts.replay)),
            io @ TakeoverIo::Pipe(_) => Err(Self(Box::new(TakeoverParts { io, ..parts }))),
        }
    }
}

type FallbackFn = dyn Fn(Takeover) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync;

/// The listener's fallback ([`crate::ListenerConfig::fallback`]): a
/// handler given every carrier the admission hands back, as a
/// [`Takeover`]. A handler that panics closes that carrier, not the
/// process: a peer reaches it with any bytes that are not zmux's. Cheap
/// to clone.
#[derive(Clone)]
pub struct Fallback(Arc<FallbackFn>);

impl std::fmt::Debug for Fallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fallback(..)")
    }
}

impl Fallback {
    /// The handler `f`.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(Takeover) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self(Arc::new(move |t| Box::pin(f(t))))
    }

    /// Serves `takeover` to its end: `false` when the handler panicked.
    pub(crate) async fn serve(&self, takeover: Takeover) -> bool {
        let handler = &self.0;
        let fut = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(takeover)));
        let Ok(fut) = fut else {
            return false;
        };
        crate::proto::Decision::Later(fut).settle().await.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let deadline = Instant::now() + Duration::from_secs(5);
        let (p, late) = read_more(Vec::new(), 4, &mut b, deadline).await;
        assert_eq!((&p[..], late), (&b"0123"[..], false));
        let mut rest = [0u8; 6];
        b.read_exact(&mut rest).await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(20);
        let (p, late) = read_more(Vec::new(), 4, &mut b, deadline).await;
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
        let at = || Instant::now() + Duration::from_secs(1);
        let msgs = |m: Vec<io::Result<Vec<u8>>>| Messages(m.into());
        let mut r = msgs(vec![Ok(vec![1; 8])]);
        assert_eq!(
            read_message(&mut r, 8, at()).await,
            FirstMessage::Message(vec![1; 8])
        );
        // One byte over, whether the reader has the room or not.
        let mut r = msgs(vec![Ok(vec![1; 9])]);
        assert_eq!(read_message(&mut r, 8, at()).await, FirstMessage::TooLarge);
        let mut r = msgs(vec![Ok(vec![1; 10])]);
        assert_eq!(read_message(&mut r, 8, at()).await, FirstMessage::TooLarge);
        // Ended, failed, an empty message: nothing to decide on.
        let mut r = tokio::io::empty();
        assert_eq!(read_message(&mut r, 8, at()).await, FirstMessage::Failed);
        let mut r = msgs(vec![Err(io::ErrorKind::InvalidData.into())]);
        assert_eq!(read_message(&mut r, 8, at()).await, FirstMessage::Failed);
        let mut r = msgs(vec![Err(crate::adapter::empty_message())]);
        assert_eq!(read_message(&mut r, 8, at()).await, FirstMessage::Failed);
        let mut r = msgs(vec![]);
        assert_eq!(read_message(&mut r, 8, at()).await, FirstMessage::Late);
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
        let started = Instant::now();
        discard(&mut r, 16, Duration::from_secs(5), true).await;
        assert!(r.0.is_empty(), "read on past the long ones to the error");
        assert_eq!(started, Instant::now());
        // A byte stream's error ends it.
        let mut r = Messages(vec![Err(crate::adapter::message_too_large()), Ok(vec![1])].into());
        discard(&mut r, 16, Duration::from_secs(5), false).await;
        assert_eq!(r.0.len(), 1);
    }
}
