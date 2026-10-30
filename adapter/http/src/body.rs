//! HTTP bodies as the halves of a pipe: a body read as bytes
//! ([`BodyReader`]), and a body fed by a writer ([`body`]), with one chunk
//! in flight between them.

use std::error::Error as StdError;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes};
use http_body::{Body, Frame};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
    /// The chunk handed over and not yet taken by the body.
    chunk: Option<Bytes>,
    end: Option<End>,
    /// The body was dropped (its exchange is gone).
    gone: bool,
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
pub(crate) struct Abort(Arc<Shared>);

impl Abort {
    pub(crate) fn run(self) {
        self.0.end(End::Abort);
    }
}

/// The sending half of a pipe: each write hands one chunk to the body,
/// which waits until the exchange took the previous one. Shutting it down
/// ends the body cleanly; dropping it without that is a failure (zmux
/// always shuts a sending half down before it drops it gracefully).
pub(crate) struct BodyWriter(Arc<Shared>);

impl AsyncWrite for BodyWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_vectored(cx, &[io::IoSlice::new(buf)])
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.end(End::Finish);
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let waker = {
            let mut s = self.0.lock();
            if s.gone || s.end.is_some() {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if s.chunk.is_some() {
                s.writer = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n: usize = bufs.iter().map(|b| b.len()).sum();
            if n == 0 {
                return Poll::Ready(Ok(0));
            }
            let mut chunk = Vec::with_capacity(n);
            for b in bufs {
                chunk.extend_from_slice(b);
            }
            s.chunk = Some(Bytes::from(chunk));
            s.reader.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        Poll::Ready(Ok(bufs.iter().map(|b| b.len()).sum()))
    }

    fn is_write_vectored(&self) -> bool {
        true
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
/// data, then its clean end, or an error when zmux aborts the pipe; or a
/// body of a known length (an exchange carrier's request or response,
/// sent with a `Content-Length`).
pub struct PipeBody(Inner);

enum Inner {
    Fed(Arc<Shared>),
    /// Up to two chunks, sent in order: a header and the data it precedes,
    /// without copying either.
    Fixed([Option<Bytes>; 2]),
}

impl PipeBody {
    /// A body without data.
    pub fn empty() -> Self {
        Self(Inner::Fixed([None, None]))
    }

    /// A body of `head` then `tail`, of known length.
    pub(crate) fn fixed(head: Bytes, tail: Bytes) -> Self {
        let keep = |b: Bytes| (!b.is_empty()).then_some(b);
        Self(Inner::Fixed([keep(head), keep(tail)]))
    }
}

impl std::fmt::Debug for PipeBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PipeBody")
    }
}

impl Body for PipeBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let shared = match &mut self.get_mut().0 {
            Inner::Fed(shared) => shared,
            Inner::Fixed(chunks) => {
                return Poll::Ready(
                    chunks
                        .iter_mut()
                        .find_map(Option::take)
                        .map(|c| Ok(Frame::data(c))),
                );
            }
        };
        let (r, waker) = {
            let mut s = shared.lock();
            if let Some(c) = s.chunk.take() {
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
                s.chunk.is_none() && s.end == Some(End::Finish)
            }
            Inner::Fixed(chunks) => chunks.iter().all(Option::is_none),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.0 {
            Inner::Fed(_) => http_body::SizeHint::default(),
            Inner::Fixed(chunks) => http_body::SizeHint::with_exact(
                chunks.iter().flatten().map(|c| c.len() as u64).sum(),
            ),
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
}

impl<B> BodyReader<B> {
    pub(crate) fn new(body: B) -> Self {
        Self {
            body,
            chunk: Bytes::new(),
        }
    }
}

impl<B> AsyncRead for BodyReader<B>
where
    B: Body<Data = Bytes> + Unpin,
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
            match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    // Trailers carry nothing of the pipe.
                    if let Ok(data) = frame.into_data() {
                        self.chunk = data;
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
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let mut body = body;
    let mut first = Bytes::new();
    let mut rest: Option<bytes::BytesMut> = None;
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?;
        let Ok(mut data) = frame.into_data() else {
            continue;
        };
        let have = first.len() + rest.as_ref().map_or(0, |r| r.len());
        let over = have + data.len() > limit;
        if over {
            data.truncate(limit - have);
        }
        if let Some(r) = &mut rest {
            r.extend_from_slice(&data);
        } else if first.is_empty() {
            first = data;
        } else if !data.is_empty() {
            // Room for what the body says is left.
            let left = usize::try_from(body.size_hint().upper().unwrap_or(0)).unwrap_or(limit);
            let mut r =
                bytes::BytesMut::with_capacity((have + data.len()).saturating_add(left).min(limit));
            r.extend_from_slice(&first);
            r.extend_from_slice(&data);
            rest = Some(r);
        }
        if over {
            return Ok(Err(rest.map_or(first, bytes::BytesMut::freeze)));
        }
    }
    Ok(Ok(rest.map_or(first, bytes::BytesMut::freeze)))
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

    /// An abort wakes a writer parked on a chunk the body never takes.
    #[test]
    fn abort_wakes_a_parked_writer() {
        let (mut writer, _body, abort) = body();
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let bufs = [io::IoSlice::new(b"one")];
        assert!(matches!(
            Pin::new(&mut writer).poll_write_vectored(&mut cx, &bufs),
            Poll::Ready(Ok(3))
        ));
        assert!(
            Pin::new(&mut writer)
                .poll_write_vectored(&mut cx, &bufs)
                .is_pending()
        );
        abort.run();
        assert!(flag.0.load(Ordering::SeqCst));
        assert!(matches!(
            Pin::new(&mut writer).poll_write_vectored(&mut cx, &bufs),
            Poll::Ready(Err(_))
        ));
    }
}
