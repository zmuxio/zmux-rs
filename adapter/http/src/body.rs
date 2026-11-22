//! HTTP bodies as the halves of a pipe: a body read as bytes
//! ([`BodyReader`]), and a body fed by a writer ([`body`]), with one write's
//! buffers in flight between them.

use std::error::Error as StdError;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes};
use http_body::{Body, Frame};
use tokio::io::{AsyncRead, ReadBuf};
use zmux::adapter::{ChunkBuf, ChunkWrite};

/// How a fed body ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    /// Finished: the body ends cleanly.
    Finish,
    /// Aborted: the body fails, so that the peer sees a failure.
    Abort,
}

#[derive(Default)]
struct Slot {
    /// The buffers of the last write, not yet taken by the body.
    chunks: ChunkBuf,
    end: Option<End>,
    /// Why writes fail after an abort with a cause ([`Abort::fail`]).
    failure: Option<io::ErrorKind>,
    /// The body was dropped (its exchange is gone).
    gone: bool,
    /// A split request waiting for its shared setup.
    on_drop: Option<tokio::sync::oneshot::Sender<()>>,
    /// A request body whose response is still awaited: once the body is
    /// gone, writes wait for the response to tell why ([`Abort::await_response`]).
    awaiting: bool,
    writer: Option<Waker>,
    reader: Option<Waker>,
    /// A request body that a redirect may repeat: the bytes written while
    /// the response is pending ([`Abort::keep_replay`]), until the bound.
    replay: Option<ChunkBuf>,
    /// More than [`REPLAY_MAX`] written while the response was pending: a
    /// redirect cannot repeat the body.
    over: bool,
    /// The request body that is live: a redirect's repeat replaces the
    /// one before ([`Abort::repeat`]).
    generation: u64,
}

/// The bytes of a request body written before its response that are kept
/// for a repeat at a redirect's URL. Past it the body goes on unkept and a
/// later redirect is refused: a redirecting front answers before reading
/// the body, a server once it has read the preface, well within it.
pub(crate) const REPLAY_MAX: usize = 64 << 10;

#[derive(Default)]
struct Shared(Mutex<Slot>);

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Slot> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the body (the first end stays) and wakes it.
    fn end(&self, end: End) {
        // Both sides: a writer parked on a full chunk fails at once.
        let (reader, writer) = {
            let mut s = self.lock();
            s.end.get_or_insert(end);
            (s.reader.take(), s.writer.take())
        };
        for w in [reader, writer].into_iter().flatten() {
            w.wake();
        }
    }
}

/// A body fed by a [`BodyWriter`], and its abort.
pub(crate) fn body() -> (BodyWriter, PipeBody, Abort) {
    let shared = Arc::new(Shared::default());
    (
        BodyWriter(shared.clone()),
        PipeBody(Inner::Fed(shared.clone(), 0)),
        Abort(shared),
    )
}

/// Fails a fed body: the request or response it is ends with an error
/// (an HTTP/2 stream reset, an HTTP/1.1 connection closed mid-body).
#[derive(Clone)]
pub(crate) struct Abort(Arc<Shared>);

impl Abort {
    /// Cancels this request's setup wait when HTTP drops its response.
    pub(crate) fn dropped(&self) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut s = self.0.lock();
        if !s.gone {
            s.on_drop = Some(tx);
        }
        rx
    }

    pub(crate) fn run(self) {
        self.0.end(End::Abort);
    }

    /// Fails the body as [`Abort::run`] does; the writer's writes then fail
    /// with `kind` (a refused request is a refused carrier).
    pub(crate) fn fail(self, kind: io::ErrorKind) {
        {
            let mut s = self.0.lock();
            s.failure.get_or_insert(kind);
            s.replay = None;
        }
        self.0.end(End::Abort);
    }

    /// Writes that find the body gone wait until the response decided
    /// ([`Abort::answered`], [`Abort::fail`]): an exchange that drops the
    /// request body on a refusal fails the writes as refused, not as a
    /// broken pipe, whichever comes first.
    pub(crate) fn await_response(&self) {
        self.0.lock().awaiting = true;
    }

    /// Keeps what is written until the response decides, for a repeat at
    /// a redirect's URL ([`Abort::repeat`]).
    pub(crate) fn keep_replay(&self) {
        self.0.lock().replay = Some(ChunkBuf::new());
    }

    /// A new body for the request repeated at a redirect's URL: `prefix`
    /// (the credential presented anew), then every byte written so far,
    /// then what is written next. The body before it ends with an error.
    /// `None` when more than [`REPLAY_MAX`] bytes were written.
    pub(crate) fn repeat(&self, prefix: Option<Bytes>) -> Option<PipeBody> {
        let mut s = self.0.lock();
        let replay = s.replay.clone().filter(|_| !s.over)?;
        s.generation += 1;
        let mut chunks = ChunkBuf::new();
        if let Some(p) = prefix {
            chunks.push(p);
        }
        let mut written: Vec<Bytes> = Vec::new();
        let mut replay = replay;
        while Buf::has_remaining(&replay) {
            let n = Buf::chunk(&replay).len();
            written.push(Buf::copy_to_bytes(&mut replay, n));
        }
        chunks.take_from(&mut written);
        s.chunks = chunks;
        s.gone = false;
        Some(PipeBody(Inner::Fed(self.0.clone(), s.generation)))
    }

    /// Whether a redirect can repeat the body ([`Abort::repeat`]).
    pub(crate) fn replayable(&self) -> bool {
        let s = self.0.lock();
        s.replay.is_some() && !s.over
    }

    /// The response was answered: a body gone from now on is a broken pipe.
    pub(crate) fn answered(&self) {
        let writer = {
            let mut s = self.0.lock();
            s.replay = None;
            s.awaiting = false;
            s.writer.take()
        };
        if let Some(w) = writer {
            w.wake();
        }
    }

    /// Ends the body cleanly, unless it already ended.
    pub(crate) fn finish(&self) {
        self.0.end(End::Finish);
    }
}

/// The sending half of a pipe: each write hands its buffers to the body
/// without copying them, as one data frame, once the exchange took the
/// previous one. Shutting it down ends the body cleanly;
/// dropping it without that is a failure (zmux always shuts a sending half
/// down before it drops it gracefully).
pub(crate) struct BodyWriter(Arc<Shared>);

impl BodyWriter {
    /// Puts `data` in front of the body, before any write: the body's
    /// first data frame.
    pub(crate) fn preload(&self, data: Bytes) {
        self.0.lock().chunks.take_from(&mut [data]);
    }
}

impl ChunkWrite for BodyWriter {
    fn poll_write_chunks(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        let waker = {
            let mut s = self.0.lock();
            if s.gone && s.end.is_none() && s.awaiting {
                s.writer = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if s.gone || s.end.is_some() {
                let kind = s.failure.unwrap_or(io::ErrorKind::BrokenPipe);
                return Poll::Ready(Err(kind.into()));
            }
            if !s.chunks.is_empty() {
                s.writer = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let s = &mut *s;
            if let Some(replay) = &mut s.replay {
                let n: usize = chunks.iter().map(Bytes::len).sum();
                if replay.len() + n > REPLAY_MAX {
                    s.replay = None;
                    s.over = true;
                } else {
                    for c in chunks.iter() {
                        replay.push(c.clone());
                    }
                }
            }
            let n = s.chunks.take_from(chunks);
            if n == 0 {
                return Poll::Ready(Ok(0));
            }
            (s.reader.take(), n)
        };
        if let Some(w) = waker.0 {
            w.wake();
        }
        Poll::Ready(Ok(waker.1))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.end(End::Finish);
        Poll::Ready(Ok(()))
    }
}

impl Drop for BodyWriter {
    fn drop(&mut self) {
        // After a shutdown the clean end stays (the first end wins).
        self.0.end(End::Abort);
    }
}

/// A request or response body of the adapter: one that a pipe's sending
/// half feeds (the body of [`crate::handle_request`]'s responses), its
/// data, then its clean end, or an error when zmux aborts the pipe; a
/// body of a known length (an exchange carrier's request or response,
/// sent with a `Content-Length`, or [`PipeBody::full`]); or any other body
/// ([`PipeBody::new`]), for the responses of a fallback handler.
pub struct PipeBody(Inner);

type BoxedBody = Pin<Box<dyn Body<Data = Bytes, Error = Box<dyn StdError + Send + Sync>> + Send>>;

enum Inner {
    /// Fed by a writer: its generation ([`Abort::repeat`]).
    Fed(Arc<Shared>, u64),
    /// A header and the data it precedes, one frame, without copying
    /// either.
    Fixed(Option<ChunkBuf>),
    Boxed(BoxedBody),
    Head(Box<(PipeBody, zmux::adapter::ResponseHead)>),
}

impl PipeBody {
    pub(crate) fn with_head(self, sent: zmux::adapter::ResponseHead) -> Self {
        Self(Inner::Head(Box::new((self, sent))))
    }

    /// Moves the receipt into a separately scheduled header write. A host
    /// that cancels that write asynchronously keeps it until the write exits.
    pub fn take_response_head(&mut self) -> Option<zmux::adapter::ResponseHead> {
        if !matches!(&self.0, Inner::Head(_)) {
            return None;
        }
        let Inner::Head(head) = std::mem::replace(&mut self.0, Inner::Fixed(None)) else {
            unreachable!()
        };
        let (body, sent) = *head;
        *self = body;
        Some(sent)
    }

    /// Confirms that the server successfully flushed this response's headers.
    /// A custom HTTP server calls this after its header write and flush and
    /// before driving the response body. The built-in serve functions do this
    /// internally. Dropping the response before confirmation withdraws takeover.
    pub fn response_head_flushed(&mut self) {
        if let Some(sent) = self.take_response_head() {
            sent.flushed();
        }
    }

    /// A body without data.
    #[must_use]
    pub fn empty() -> Self {
        Self(Inner::Fixed(None))
    }

    /// A body of `data`, of known length.
    pub fn full(data: impl Into<Bytes>) -> Self {
        Self::fixed([data.into()])
    }

    /// `body` as it is: its frames, its end and its errors.
    pub fn new<B>(body: B) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        struct MapErr<B>(Pin<Box<B>>);
        impl<B> Body for MapErr<B>
        where
            B: Body<Data = Bytes>,
            B::Error: Into<Box<dyn StdError + Send + Sync>>,
        {
            type Data = Bytes;
            type Error = Box<dyn StdError + Send + Sync>;
            fn poll_frame(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
                self.get_mut()
                    .0
                    .as_mut()
                    .poll_frame(cx)
                    .map(|f| f.map(|r| r.map_err(Into::into)))
            }
            fn is_end_stream(&self) -> bool {
                self.0.is_end_stream()
            }
            fn size_hint(&self) -> http_body::SizeHint {
                self.0.size_hint()
            }
        }
        Self(Inner::Boxed(Box::pin(MapErr(Box::pin(body)))))
    }

    /// A body of `parts` one after the other, of known length.
    pub(crate) fn fixed<const N: usize>(parts: [Bytes; N]) -> Self {
        let mut b = ChunkBuf::new();
        for p in parts {
            b.push(p);
        }
        Self(Inner::Fixed((!b.is_empty()).then_some(b)))
    }
}

impl std::fmt::Debug for PipeBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PipeBody")
    }
}

impl Body for PipeBody {
    type Data = ChunkBuf;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<ChunkBuf>, io::Error>>> {
        let (shared, generation) = match &mut self.get_mut().0 {
            Inner::Head(head) => return Pin::new(&mut head.0).poll_frame(cx),
            Inner::Fed(shared, g) => (shared, *g),
            Inner::Fixed(chunks) => return Poll::Ready(chunks.take().map(|c| Ok(Frame::data(c)))),
            Inner::Boxed(b) => {
                return b.as_mut().poll_frame(cx).map(|f| {
                    f.map(|r| {
                        r.map(|f| {
                            f.map_data(|d| {
                                let mut c = ChunkBuf::new();
                                c.push(d);
                                c
                            })
                        })
                        .map_err(io::Error::other)
                    })
                });
            }
        };
        let (r, waker) = {
            let mut s = shared.lock();
            if s.generation != generation {
                // A redirect's repeat replaced this request.
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "request redirected",
                ))));
            }
            if s.chunks.is_empty() {
                match s.end {
                    Some(End::Finish) => (Poll::Ready(None), None),
                    Some(End::Abort) => (
                        Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "pipe aborted",
                        )))),
                        None,
                    ),
                    None => {
                        s.reader = Some(cx.waker().clone());
                        (Poll::Pending, None)
                    }
                }
            } else {
                let c = std::mem::take(&mut s.chunks);
                (Poll::Ready(Some(Ok(Frame::data(c)))), s.writer.take())
            }
        };
        if let Some(w) = waker {
            w.wake();
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            Inner::Head(_) => false,
            Inner::Fed(s, _) => {
                let s = s.lock();
                s.chunks.is_empty() && s.end == Some(End::Finish)
            }
            Inner::Fixed(chunks) => chunks.is_none(),
            Inner::Boxed(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.0 {
            Inner::Head(head) => head.0.size_hint(),
            Inner::Fed(..) => http_body::SizeHint::default(),
            Inner::Fixed(chunks) => {
                http_body::SizeHint::with_exact(chunks.as_ref().map_or(0, |c| c.len() as u64))
            }
            Inner::Boxed(b) => b.size_hint(),
        }
    }
}

impl Drop for PipeBody {
    fn drop(&mut self) {
        if let Inner::Fed(shared, generation) = &self.0 {
            let (waker, on_drop) = {
                let mut s = shared.lock();
                if s.generation != *generation {
                    return;
                }
                s.gone = true;
                (s.writer.take(), s.on_drop.take())
            };
            drop(on_drop);
            if let Some(w) = waker {
                w.wake();
            }
        }
    }
}

/// The receiving half of a pipe: a body's data frames as bytes; its end
/// is the end of the stream, its error (a reset, a connection cut
/// mid-body) an error of the read.
pub(crate) struct BodyReader<B> {
    body: B,
    chunk: Bytes,
    trailers: Option<Box<http::HeaderMap>>,
    ended: bool,
}

impl<B> BodyReader<B> {
    pub(crate) fn new(body: B) -> Self {
        Self {
            body,
            chunk: Bytes::new(),
            trailers: None,
            ended: false,
        }
    }

    /// Return every frame consumed by byte-stream admission to the HTTP host.
    pub(crate) fn replay(self, prefix: Bytes) -> ReplayBody<B> {
        ReplayBody::new([prefix, self.chunk], Some(self.body)).with_trailers(self.trailers)
    }
}

/// A request body with bytes read from it before given back in front:
/// [`crate::Unhandled::Fallback`]'s requests. Its first frames are those
/// bytes (as they were read, without a further copy), then the body's own
/// frames, its trailers and its end.
pub struct ReplayBody<B> {
    front: [Bytes; 2],
    rest: Option<B>,
    trailers: Option<Box<http::HeaderMap>>,
    stop: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl<B> ReplayBody<B> {
    /// `front` then `rest`.
    pub(crate) fn new(front: [Bytes; 2], rest: Option<B>) -> Self {
        Self {
            front,
            rest,
            trailers: None,
            stop: None,
        }
    }

    pub(crate) fn with_trailers(mut self, trailers: Option<Box<http::HeaderMap>>) -> Self {
        self.trailers = trailers;
        self
    }

    pub(crate) fn stop_with(&mut self, listener: zmux::Listener) {
        if self.stop.is_none() {
            self.stop = Some(Box::pin(async move { listener.adapter().closed().await }));
        }
    }

    /// The bytes given back in front not read yet, and the rest of the
    /// body (`None` when it is not available: the listener read it).
    pub fn into_parts(self) -> (Bytes, Option<B>) {
        let [a, b] = self.front;
        let front = if b.is_empty() {
            a
        } else if a.is_empty() {
            b
        } else {
            let mut v = Vec::with_capacity(a.len() + b.len());
            v.extend_from_slice(&a);
            v.extend_from_slice(&b);
            v.into()
        };
        (front, self.rest)
    }
}

impl<B> std::fmt::Debug for ReplayBody<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayBody")
            .field("front", &(self.front[0].len() + self.front[1].len()))
            .field("rest", &self.rest.is_some())
            .field("trailers", &self.trailers.is_some())
            .field("stop", &self.stop.is_some())
            .finish()
    }
}

impl<B> Body for ReplayBody<B>
where
    B: Body + Unpin,
    B::Data: Buf,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        if this
            .stop
            .as_mut()
            .is_some_and(|stop| stop.as_mut().poll(cx).is_ready())
        {
            this.front = Default::default();
            this.trailers = None;
            this.rest = None;
            this.stop = None;
            return Poll::Ready(None);
        }
        for b in &mut this.front {
            if !b.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(std::mem::take(b)))));
            }
        }
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(*trailers))));
        }
        match &mut this.rest {
            Some(rest) => Pin::new(rest)
                .poll_frame(cx)
                .map(|f| f.map(|r| r.map(|f| f.map_data(|mut d| d.copy_to_bytes(d.remaining()))))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.front.iter().all(Bytes::is_empty)
            && self.trailers.is_none()
            && self.rest.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let front = (self.front[0].len() + self.front[1].len()) as u64;
        let rest = self
            .rest
            .as_ref()
            .map_or_else(|| http_body::SizeHint::with_exact(0), Body::size_hint);
        let mut h = http_body::SizeHint::new();
        h.set_lower(rest.lower() + front);
        if let Some(u) = rest.upper() {
            h.set_upper(u + front);
        }
        h
    }
}

impl<B> AsyncRead for BodyReader<B>
where
    B: Body + Unpin,
    B::Data: Buf,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.chunk.is_empty() {
                let n = self.chunk.len().min(buf.remaining());
                buf.put_slice(&self.chunk[..n]);
                self.chunk.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.ended {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.ended = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
                }
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(mut data) => self.chunk = data.copy_to_bytes(data.remaining()),
                    Err(frame) => {
                        self.trailers = frame.into_trailers().ok().map(Box::new);
                        self.ended = true;
                    }
                },
            }
        }
    }
}

/// Before handoff the HTTP reader and setup can both observe a reset. Keep
/// DATA pulled by the observer in order, bounded by the setup replay budget
/// plus the one frame currently returned by the HTTP implementation.
pub(crate) struct SetupBody<B> {
    reader: BodyReader<B>,
    ahead: ChunkBuf,
    failure: Option<io::Error>,
}

impl<B> SetupBody<B> {
    pub(crate) fn new(reader: BodyReader<B>) -> Self {
        Self {
            reader,
            ahead: ChunkBuf::new(),
            failure: None,
        }
    }
}

impl<B> SetupBody<B>
where
    B: Body + Unpin,
    B::Data: Buf,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        while !self.reader.ended && self.ahead.len() < REPLAY_MAX {
            // An empty destination leaves the current frame intact.
            let result = Pin::new(&mut self.reader).poll_read(cx, &mut ReadBuf::new(&mut []));
            match result {
                Poll::Ready(Ok(())) => self.ahead.push(std::mem::take(&mut self.reader.chunk)),
                Poll::Ready(Err(error)) => {
                    self.failure = Some(error);
                    return Poll::Ready(());
                }
                Poll::Pending => break,
            }
        }
        Poll::Pending
    }
}

impl<B> AsyncRead for SetupBody<B>
where
    B: Body + Unpin,
    B::Data: Buf,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.ahead.is_empty() {
            if let Some(error) = self.failure.take() {
                return Poll::Ready(Err(error));
            }
            return Pin::new(&mut self.reader).poll_read(cx, buf);
        }
        let n = self.ahead.chunk().len().min(buf.remaining());
        buf.put_slice(&self.ahead.chunk()[..n]);
        self.ahead.advance(n);
        Poll::Ready(Ok(()))
    }
}

pub(crate) async fn request_gone<B>(
    probe: zmux::adapter::ReadProbe<SetupBody<B>>,
    response: impl Future,
    transport: Option<std::sync::Weak<zmux_rustls::TcpReset>>,
) where
    B: Body + Unpin,
    B::Data: Buf,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let reset = std::future::poll_fn(|cx| {
        probe
            .poll(cx, SetupBody::poll_reset)
            .unwrap_or(Poll::Pending)
    });
    let failed = async {
        match transport {
            Some(connection) => {
                if let Some(tcp) = connection.upgrade() {
                    tcp.failed().await;
                }
            }
            None => std::future::pending().await,
        }
    };
    tokio::select! { biased; _ = response => {}, () = failed => {}, () = reset => {} }
}

/// The whole of `body`, at most `limit` bytes: one data frame is taken as
/// it is, several are joined. A body beyond the limit is `Ok(Err(start))`,
/// with its first bytes (up to the limit); one that fails is an error.
pub(crate) async fn collect<B>(body: B, limit: usize) -> io::Result<Result<Bytes, Bytes>>
where
    B: Body + Unpin,
    B::Data: Buf,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let mut body = body;
    let mut first = Bytes::new();
    let mut rest: Option<bytes::BytesMut> = None;
    let mut have = 0usize;
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?;
        let Ok(mut data) = frame.into_data() else {
            continue;
        };
        let mut data = data.copy_to_bytes(data.remaining());
        let over = data.len() > limit - have;
        if over {
            data.truncate(limit - have);
        }
        have += data.len();
        if let Some(r) = &mut rest {
            r.extend_from_slice(&data);
        } else if first.is_empty() {
            first = data;
        } else if !data.is_empty() {
            // Sized by what arrived, never by what the peer declares.
            let mut r = bytes::BytesMut::with_capacity(have);
            r.extend_from_slice(&std::mem::take(&mut first));
            r.extend_from_slice(&data);
            rest = Some(r);
        }
        if over {
            return Ok(Err(rest.map_or(first, bytes::BytesMut::freeze)));
        }
    }
    Ok(Ok(rest.map_or(first, bytes::BytesMut::freeze)))
}

/// Bytes read from a body: one data frame as it is, several joined in a
/// buffer that grows with what arrives, never with a length the peer
/// declares.
#[derive(Default)]
pub(crate) struct Gathered {
    first: Bytes,
    pub(crate) trailers: Option<Box<http::HeaderMap>>,
    joined: Option<bytes::BytesMut>,
}

impl Gathered {
    /// The bytes gathered.
    pub(crate) fn as_slice(&self) -> &[u8] {
        match &self.joined {
            Some(j) => j,
            None => &self.first,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn push(&mut self, data: Bytes) {
        match &mut self.joined {
            Some(j) => j.extend_from_slice(&data),
            None if self.first.is_empty() => self.first = data,
            None => {
                let mut j = bytes::BytesMut::with_capacity(self.first.len() + data.len());
                j.extend_from_slice(&self.first);
                j.extend_from_slice(&data);
                self.first = Bytes::new();
                self.joined = Some(j);
            }
        }
    }

    /// The bytes gathered, without a copy.
    pub(crate) fn freeze(self) -> Bytes {
        self.joined.map_or(self.first, bytes::BytesMut::freeze)
    }
}

/// Reads `body` into `read` until it holds at least `len` bytes, or until
/// `deadline`, without reading beyond the frame that completes them.
/// Whether it does; a body that ends, fails or passes the deadline first
/// leaves what was read. A trailers frame read on the way ends the reading
/// and is retained for HTTP fallback.
pub(crate) async fn read_to<B>(
    body: &mut B,
    read: &mut Gathered,
    len: usize,
    deadline: Option<tokio::time::Instant>,
) -> bool
where
    B: Body + Unpin,
    B::Data: Buf,
{
    while read.len() < len {
        let next = std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx));
        let Some(Some(Ok(frame))) =
            zmux::adapter::while_open(zmux::adapter::wait_deadline(deadline), next).await
        else {
            return false;
        };
        let mut data = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => {
                read.trailers = frame.into_trailers().ok().map(Box::new);
                return false;
            }
        };
        let data = data.copy_to_bytes(data.remaining());
        if !data.is_empty() {
            read.push(data);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Wake;

    struct Flag(AtomicBool);
    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// An abort wakes a writer parked on buffers the body never takes.
    #[test]
    fn abort_wakes_a_parked_writer() {
        let (mut writer, _body, abort) = body();
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let mut bufs = [Bytes::from_static(b"one")];
        assert!(matches!(
            Pin::new(&mut writer).poll_write_chunks(&mut cx, &mut bufs),
            Poll::Ready(Ok(3))
        ));
        assert!(bufs[0].is_empty());
        let mut bufs = [Bytes::from_static(b"two")];
        assert!(
            Pin::new(&mut writer)
                .poll_write_chunks(&mut cx, &mut bufs)
                .is_pending()
        );
        assert_eq!(&bufs[0][..], b"two");
        abort.run();
        assert!(flag.0.load(Ordering::SeqCst));
        assert!(matches!(
            Pin::new(&mut writer).poll_write_chunks(&mut cx, &mut bufs),
            Poll::Ready(Err(_))
        ));
    }

    /// A write's buffers are one data frame of the body, shared, and the
    /// writer goes on once the body took it.
    #[test]
    fn a_write_is_one_frame_without_copying() {
        use bytes::Buf;
        let (mut writer, mut body, _abort) = body();
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let payload = Bytes::from(vec![7u8; 5000]);
        let mut bufs = [Bytes::from_static(b"hd"), payload.clone()];
        assert!(matches!(
            Pin::new(&mut writer).poll_write_chunks(&mut cx, &mut bufs),
            Poll::Ready(Ok(5002))
        ));
        let mut next = [Bytes::from_static(b"x")];
        assert!(
            Pin::new(&mut writer)
                .poll_write_chunks(&mut cx, &mut next)
                .is_pending()
        );
        let Poll::Ready(Some(Ok(f))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("no frame");
        };
        let mut data = f.into_data().unwrap();
        assert_eq!(data.remaining(), 5002);
        assert_eq!(data.chunk(), b"hd");
        data.advance(2);
        assert_eq!(data.chunk().as_ptr(), payload.as_ptr());
        assert!(flag.0.load(Ordering::SeqCst));
    }

    /// A body of the given data frames.
    struct Frames(std::collections::VecDeque<Bytes>);
    impl Body for Frames {
        type Data = Bytes;
        type Error = io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
            Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
        }
    }

    fn frames(sizes: &[usize]) -> Frames {
        let mut n = 0u8;
        Frames(
            sizes
                .iter()
                .map(|&len| {
                    n = n.wrapping_add(1);
                    Bytes::from(vec![n; len])
                })
                .collect(),
        )
    }

    /// The limit applies to the bytes of all frames, each counted once.
    #[tokio::test]
    async fn collect_counts_each_frame_once() {
        let whole = |sizes: &[usize]| sizes.iter().sum::<usize>();
        for sizes in [&[10][..], &[4, 3, 3], &[1, 1, 1, 1, 6], &[0, 5, 0, 5]] {
            let got = collect(frames(sizes), 10).await.unwrap().unwrap();
            assert_eq!(got.len(), whole(sizes));
            let expect: Vec<u8> = frames(sizes).0.into_iter().flatten().collect();
            assert_eq!(&got[..], &expect[..]);
        }
        let start = collect(frames(&[4, 4, 4]), 10).await.unwrap().unwrap_err();
        assert_eq!(start.len(), 10);
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;

    fn write(w: &mut BodyWriter, data: &[u8]) {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut chunks = [Bytes::copy_from_slice(data)];
        let r = Pin::new(w).poll_write_chunks(&mut cx, &mut chunks);
        assert!(matches!(r, Poll::Ready(Ok(n)) if n == data.len()));
    }

    /// Takes what the body holds, as the exchange would.
    fn drain(b: &mut PipeBody) -> Vec<u8> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match Pin::new(b).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(f))) => {
                let mut d = f.into_data().ok().unwrap();
                d.copy_to_bytes(d.remaining()).to_vec()
            }
            _ => Vec::new(),
        }
    }

    #[test]
    fn a_repeat_sends_a_fresh_prefix_then_every_byte_written() {
        let (mut w, mut body, abort) = body();
        abort.keep_replay();
        w.preload(Bytes::from_static(b"old prefix"));
        assert_eq!(drain(&mut body), b"old prefix");
        write(&mut w, b"abc");
        assert_eq!(drain(&mut body), b"abc");
        write(&mut w, b"def");
        let mut again = abort.repeat(Some(Bytes::from_static(b"P"))).unwrap();
        // The replaced body fails and leaves the shared state alone.
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(_)))
        ));
        drop(body);
        assert_eq!(drain(&mut again), b"Pabcdef");
        write(&mut w, b"g");
        assert_eq!(drain(&mut again), b"g");
    }

    #[test]
    fn past_the_bound_no_repeat() {
        let (mut w, mut body, abort) = body();
        abort.keep_replay();
        let big = vec![7u8; REPLAY_MAX];
        write(&mut w, &big);
        assert!(abort.replayable());
        drain(&mut body);
        write(&mut w, b"x");
        assert!(!abort.replayable());
        assert!(abort.repeat(None).is_none());
    }
}
