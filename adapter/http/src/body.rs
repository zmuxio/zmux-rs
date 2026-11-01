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
use zmux::carrier::{ChunkBuf, ChunkWrite};

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
    /// A request body whose response is still awaited: once the body is
    /// gone, writes wait for the response to tell why ([`Abort::await_response`]).
    awaiting: bool,
    writer: Option<Waker>,
    reader: Option<Waker>,
}

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
        PipeBody(Inner::Fed(shared.clone())),
        Abort(shared),
    )
}

/// Fails a fed body: the request or response it is ends with an error
/// (an HTTP/2 stream reset, an HTTP/1.1 connection closed mid-body).
#[derive(Clone)]
pub(crate) struct Abort(Arc<Shared>);

impl Abort {
    pub(crate) fn run(self) {
        self.0.end(End::Abort);
    }

    /// Fails the body as [`Abort::run`] does; the writer's writes then fail
    /// with `kind` (a refused request is a refused carrier).
    pub(crate) fn fail(self, kind: io::ErrorKind) {
        self.0.lock().failure.get_or_insert(kind);
        self.0.end(End::Abort);
    }

    /// Writes that find the body gone wait until the response decided
    /// ([`Abort::answered`], [`Abort::fail`]): an exchange that drops the
    /// request body on a refusal fails the writes as refused, not as a
    /// broken pipe, whichever comes first.
    pub(crate) fn await_response(&self) {
        self.0.lock().awaiting = true;
    }

    /// The response was answered: a body gone from now on is a broken pipe.
    pub(crate) fn answered(&self) {
        let writer = {
            let mut s = self.0.lock();
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
    Fed(Arc<Shared>),
    /// A header and the data it precedes, one frame, without copying
    /// either.
    Fixed(Option<ChunkBuf>),
    Boxed(BoxedBody),
}

impl PipeBody {
    /// A body without data.
    pub fn empty() -> Self {
        Self(Inner::Fixed(None))
    }

    /// A body of `data`, of known length.
    pub fn full(data: impl Into<Bytes>) -> Self {
        Self::fixed(data.into(), Bytes::new())
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

    /// A body of `head` then `tail`, of known length.
    pub(crate) fn fixed(head: Bytes, tail: Bytes) -> Self {
        let mut b = ChunkBuf::new();
        b.push(head);
        b.push(tail);
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
        let shared = match &mut self.get_mut().0 {
            Inner::Fed(shared) => shared,
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
            if !s.chunks.is_empty() {
                let c = std::mem::take(&mut s.chunks);
                (Poll::Ready(Some(Ok(Frame::data(c)))), s.writer.take())
            } else {
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
            }
        };
        if let Some(w) = waker {
            w.wake();
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            Inner::Fed(s) => {
                let s = s.lock();
                s.chunks.is_empty() && s.end == Some(End::Finish)
            }
            Inner::Fixed(chunks) => chunks.is_none(),
            Inner::Boxed(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.0 {
            Inner::Fed(_) => http_body::SizeHint::default(),
            Inner::Fixed(chunks) => {
                http_body::SizeHint::with_exact(chunks.as_ref().map_or(0, |c| c.len() as u64))
            }
            Inner::Boxed(b) => b.size_hint(),
        }
    }
}

impl Drop for PipeBody {
    fn drop(&mut self) {
        if let Inner::Fed(shared) = &self.0 {
            let waker = {
                let mut s = shared.lock();
                s.gone = true;
                s.writer.take()
            };
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
    ended: bool,
}

impl<B> BodyReader<B> {
    pub(crate) fn new(body: B) -> Self {
        Self {
            body,
            chunk: Bytes::new(),
            ended: false,
        }
    }

    /// Whether the body ended (cleanly) and every byte was read.
    pub(crate) fn ended(&self) -> bool {
        self.ended && self.chunk.is_empty()
    }

    /// The body and the part of its last frame not read yet.
    pub(crate) fn into_parts(self) -> (B, Bytes) {
        (self.body, self.chunk)
    }
}

/// A request body with bytes read from it before given back in front:
/// [`crate::Unhandled::Fallback`]'s requests. Its first frames are those
/// bytes (as they were read, without a further copy), then the body's own
/// frames, its trailers and its end.
pub struct ReplayBody<B> {
    front: [Bytes; 2],
    rest: Option<B>,
}

impl<B> ReplayBody<B> {
    /// `front` then `rest`.
    pub(crate) fn new(front: [Bytes; 2], rest: Option<B>) -> Self {
        Self { front, rest }
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
        for b in &mut this.front {
            if !b.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(std::mem::take(b)))));
            }
        }
        match &mut this.rest {
            Some(rest) => Pin::new(rest)
                .poll_frame(cx)
                .map(|f| f.map(|r| r.map(|f| f.map_data(|mut d| d.copy_to_bytes(d.remaining()))))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.front.iter().all(Bytes::is_empty) && self.rest.as_ref().is_none_or(Body::is_end_stream)
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
                Poll::Ready(Some(Ok(frame))) => {
                    // Trailers carry nothing of the pipe.
                    if let Ok(mut data) = frame.into_data() {
                        // Shared when the frame is one buffer.
                        self.chunk = data.copy_to_bytes(data.remaining());
                    }
                }
            }
        }
    }
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
            // Room for what the body says is left.
            let left = usize::try_from(body.size_hint().upper().unwrap_or(0)).unwrap_or(limit);
            let mut r = bytes::BytesMut::with_capacity(have.saturating_add(left).min(limit));
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

/// Reads the first `len` bytes of `body` until `deadline`, without reading
/// beyond the frame that completes them. Returns the bytes read (one data
/// frame is taken as it is, several are joined) and whether they are `len`
/// bytes; a body that ends, fails or passes the deadline first gives what
/// was read. A trailers frame read on the way ends the reading and is lost.
pub(crate) async fn read_len<B>(
    body: &mut B,
    len: usize,
    deadline: tokio::time::Instant,
) -> (Bytes, bool)
where
    B: Body + Unpin,
    B::Data: Buf,
{
    let mut first = Bytes::new();
    let mut joined: Option<bytes::BytesMut> = None;
    let mut have = 0;
    while have < len {
        let next = std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx));
        let Ok(Some(Ok(frame))) = tokio::time::timeout_at(deadline, next).await else {
            break;
        };
        let Ok(mut data) = frame.into_data() else {
            break;
        };
        let data = data.copy_to_bytes(data.remaining());
        if data.is_empty() {
            continue;
        }
        have += data.len();
        match &mut joined {
            Some(j) => j.extend_from_slice(&data),
            None if first.is_empty() => first = data,
            None => {
                let mut j = bytes::BytesMut::with_capacity(len.max(have));
                j.extend_from_slice(&first);
                j.extend_from_slice(&data);
                joined = Some(j);
            }
        }
    }
    let read = joined.map_or(first, bytes::BytesMut::freeze);
    let complete = read.len() == len;
    (read, complete)
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
