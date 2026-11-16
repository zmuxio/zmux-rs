//! The carrier contract every adapter's carriers keep, as a suite each
//! adapter runs on a pair of its connected carriers (feature `test-hooks`):
//! the [`ChunkWrite`](super::tokio::ChunkWrite) rule that a write left
//! `Pending` is retried with the same chunks or dropped, at each point a
//! write may wait; a carrier dropped without its graceful end (after its
//! abort, as zmux fails a pipe) is a failure at the peer, never a clean
//! end; a peer that went away fails the writes and ends the reads instead
//! of leaving them waiting; and a graceful end completes, and arrives as a
//! clean end, while the peer never ends its own half.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tokio::{PipeIo, Reader, Writer};

/// How long a step that must happen may take.
const STEP: Duration = Duration::from_secs(10);
/// The bytes of one write call.
const CHUNK: usize = 16 << 10;
/// The most a write that never waits may send before a case gives up on
/// meeting a `Pending`: the carrier's windows and buffers are larger.
const MAX_UNREAD: usize = 64 << 20;
/// How many points at which a write waited the cancel case tries, each on
/// a new pair.
const PENDING_POINTS: usize = 3;

/// The halves of one carrier.
struct Halves {
    reader: Reader,
    prefix: Vec<u8>,
    writer: Writer,
    abort: Option<Box<dyn FnOnce() + Send>>,
}

impl Halves {
    fn of(mut io: PipeIo, name: &str) -> Self {
        Self {
            reader: io
                .reader
                .take()
                .unwrap_or_else(|| panic!("{name}: no reader")),
            prefix: std::mem::take(&mut io.prefix),
            writer: io
                .writer
                .take()
                .unwrap_or_else(|| panic!("{name}: no writer")),
            abort: io.abort.take(),
        }
    }

    /// Fails the carrier as zmux fails a pipe: its abort, then its halves
    /// dropped.
    fn fail(mut self) {
        if let Some(abort) = self.abort.take() {
            abort();
        }
    }
}

/// One write call of what is left of `chunk`: its bytes taken, as a
/// [`ChunkWrite`](super::tokio::ChunkWrite) or an `AsyncWrite` takes them.
fn poll_write(w: &mut Writer, cx: &mut Context<'_>, chunk: &mut Bytes) -> Poll<io::Result<usize>> {
    match w {
        Writer::Chunks(w) => w
            .as_mut()
            .poll_write_chunks(cx, std::slice::from_mut(chunk)),
        Writer::Io(w) => poll_slice(w.as_mut(), cx, chunk),
        Writer::Sealed(w) => poll_slice(w.as_mut(), cx, chunk),
        Writer::Stream(_) => panic!("a stream carrier is not an adapter's"),
    }
}

fn poll_slice(
    w: Pin<&mut (impl AsyncWrite + ?Sized)>,
    cx: &mut Context<'_>,
    chunk: &mut Bytes,
) -> Poll<io::Result<usize>> {
    let r = w.poll_write(cx, chunk);
    if let Poll::Ready(Ok(n)) = r {
        let _ = chunk.split_to(n);
    }
    r
}

/// The byte at `at` of the data the cases send.
#[allow(clippy::cast_possible_truncation, reason = "the pattern wraps at 251")]
fn pattern(at: usize) -> u8 {
    (at % 251) as u8
}

fn chunk_at(at: usize) -> Bytes {
    (at..at + CHUNK).map(pattern).collect::<Vec<_>>().into()
}

/// Writes `chunk` to its end, retrying each `Pending` with the same chunk;
/// `Err` or `Ok(0)` ends it with the error.
async fn write_all(w: &mut Writer, mut chunk: Bytes) -> io::Result<()> {
    while !chunk.is_empty() {
        let n = poll_fn(|cx| poll_write(w, cx, &mut chunk)).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
    }
    Ok(())
}

/// Reads until the end; the bytes read and how it ended (`Ok` for a clean
/// end), checking them against the pattern.
async fn read_to_end(h: &mut Halves, name: &str) -> (usize, io::Result<()>) {
    let mut at = 0;
    for &b in &h.prefix {
        assert_eq!(b, pattern(at), "{name}: byte {at} differs");
        at += 1;
    }
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let mut rb = ReadBuf::new(&mut buf);
        match poll_fn(|cx| Pin::new(&mut h.reader).poll_read(cx, &mut rb)).await {
            Ok(()) if rb.filled().is_empty() => return (at, Ok(())),
            Ok(()) => {
                for &b in rb.filled() {
                    assert_eq!(b, pattern(at), "{name}: byte {at} differs");
                    at += 1;
                }
            }
            Err(e) => return (at, Err(e)),
        }
    }
}

/// Both futures, polled in turn.
async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (std::pin::pin!(a), std::pin::pin!(b));
    let (mut ra, mut rb) = (None, None);
    poll_fn(|cx| {
        if ra.is_none()
            && let Poll::Ready(r) = a.as_mut().poll(cx)
        {
            ra = Some(r);
        }
        if rb.is_none()
            && let Poll::Ready(r) = b.as_mut().poll(cx)
        {
            rb = Some(r);
        }
        if ra.is_some() && rb.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    (ra.expect("ready"), rb.expect("ready"))
}

async fn step<T>(name: &str, what: &str, f: impl Future<Output = T>) -> T {
    tokio::time::timeout(STEP, f)
        .await
        .unwrap_or_else(|_| panic!("{name}: {what} took longer than {STEP:?}"))
}

/// The byte at `at` of the data the suite sends: a carrier that must
/// carry data before its peer sees it (a QUIC stream) opens with the first
/// bytes of this pattern ([`run`]).
#[must_use]
pub fn pattern_byte(at: usize) -> u8 {
    pattern(at)
}

/// Runs the suite on carriers from `pair`, which connects a new pair each
/// time: the first opened by this end, the second its peer's, and how many
/// bytes of the pattern ([`pattern_byte`]) the first already sent to open
/// it. Panics with the case that failed.
pub async fn run<F, Fut>(name: &str, mut pair: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = (PipeIo, PipeIo, usize)>,
{
    for forward in [true, false] {
        let (x, y, opened) = pair().await;
        let (from, to) = if forward {
            ((x, opened), y)
        } else {
            ((y, 0), x)
        };
        retried_writes_arrive_whole(name, from, to).await;
    }
    for point in 1..=PENDING_POINTS {
        let (x, y, opened) = pair().await;
        dropped_at_a_pending_write_fails_the_peer(name, (x, opened), y, point).await;
    }
    let (x, y, opened) = pair().await;
    a_dropped_carrier_is_no_clean_end(name, (x, opened), y).await;
    let (x, y, opened) = pair().await;
    a_gone_peer_fails_the_writes(name, (x, opened), y).await;
    let (x, y, opened) = pair().await;
    a_graceful_end_does_not_wait_for_the_peer(name, (x, opened), y).await;
}

/// Every `Pending` write retried with the same chunk: all bytes arrive, in
/// order, and the graceful end is a clean end at the peer.
async fn retried_writes_arrive_whole(name: &str, (from, sent): (PipeIo, usize), to: PipeIo) {
    let name = &format!("{name}: retried writes");
    let mut from = Halves::of(from, name);
    let mut to = Halves::of(to, name);
    let total = 4 << 20;
    let writing = async {
        let mut at = sent;
        while at < total {
            write_all(&mut from.writer, chunk_at(at))
                .await
                .unwrap_or_else(|e| panic!("{name}: write failed: {e}"));
            at += CHUNK;
        }
        poll_fn(|cx| from.writer.poll_shutdown(cx))
            .await
            .unwrap_or_else(|e| panic!("{name}: graceful end failed: {e}"));
        at
    };
    let (written, (read, end)) = step(name, "the transfer", async {
        join(writing, read_to_end(&mut to, name)).await
    })
    .await;
    end.unwrap_or_else(|e| panic!("{name}: no clean end: {e}"));
    assert_eq!(read, written, "{name}: bytes lost");
}

/// Writes without the peer reading until the `point`-th write that waited,
/// then fails the carrier: the peer reads a prefix of what was sent, then a
/// failure. A carrier must make a write wait before [`MAX_UNREAD`] bytes
/// are unread.
async fn dropped_at_a_pending_write_fails_the_peer(
    name: &str,
    (from, sent): (PipeIo, usize),
    to: PipeIo,
    point: usize,
) {
    let name = &format!("{name}: dropped at pending write {point}");
    let mut from = Halves::of(from, name);
    let mut to = Halves::of(to, name);
    let mut at = sent;
    let mut pending = 0;
    let mut chunk = chunk_at(at);
    let mut waker_cx = Context::from_waker(std::task::Waker::noop());
    while pending < point {
        assert!(at <= MAX_UNREAD, "{name}: no write waited for the peer");
        match poll_write(&mut from.writer, &mut waker_cx, &mut chunk) {
            Poll::Pending => {
                pending += 1;
                // Polled again with the same chunk: the write goes on where
                // it waited.
                tokio::task::yield_now().await;
            }
            Poll::Ready(Ok(0) | Err(_)) => panic!("{name}: the write failed"),
            Poll::Ready(Ok(_)) => {
                if chunk.is_empty() {
                    at += CHUNK;
                    chunk = chunk_at(at);
                }
            }
        }
    }
    from.fail();
    let (_, end) = step(name, "the peer's end", read_to_end(&mut to, name)).await;
    assert!(
        end.is_err(),
        "{name}: a carrier dropped while a write waited ended cleanly"
    );
}

/// A carrier dropped without its graceful end: the peer reads what was
/// sent, then a failure, never a clean end.
async fn a_dropped_carrier_is_no_clean_end(name: &str, (from, at): (PipeIo, usize), to: PipeIo) {
    let name = &format!("{name}: dropped carrier");
    let mut from = Halves::of(from, name);
    let mut to = Halves::of(to, name);
    step(name, "a write", write_all(&mut from.writer, chunk_at(at)))
        .await
        .unwrap_or_else(|e| panic!("{name}: write failed: {e}"));
    let _ = step(name, "a flush", poll_fn(|cx| from.writer.poll_flush(cx))).await;
    from.fail();
    let (read, end) = step(name, "the peer's end", read_to_end(&mut to, name)).await;
    assert!(
        end.is_err(),
        "{name}: a dropped carrier ended cleanly after {read} bytes"
    );
}

/// The peer's carrier dropped: this end's writes fail, and its reads end,
/// instead of waiting.
async fn a_gone_peer_fails_the_writes(name: &str, (from, sent): (PipeIo, usize), to: PipeIo) {
    let name = &format!("{name}: gone peer");
    let mut from = Halves::of(from, name);
    Halves::of(to, name).fail();
    step(name, "a failed write", async {
        let mut at = sent;
        while write_all(&mut from.writer, chunk_at(at)).await.is_ok() {
            at += CHUNK;
            // Written data is flushed so that the failure surfaces.
            if poll_fn(|cx| from.writer.poll_flush(cx)).await.is_err() {
                break;
            }
        }
    })
    .await;
    let mut buf = [0u8; 64];
    step(name, "the reads' end", async {
        loop {
            let mut rb = ReadBuf::new(&mut buf);
            match poll_fn(|cx| Pin::new(&mut from.reader).poll_read(cx, &mut rb)).await {
                Ok(()) if !rb.filled().is_empty() => {}
                _ => break,
            }
        }
    })
    .await;
}

/// A graceful end completes while the peer never ends its own half: the
/// peer reads a clean end, and this end's reads do not fail.
async fn a_graceful_end_does_not_wait_for_the_peer(
    name: &str,
    (from, at): (PipeIo, usize),
    to: PipeIo,
) {
    let name = &format!("{name}: graceful end, peer never ends");
    let mut from = Halves::of(from, name);
    let mut to = Halves::of(to, name);
    step(name, "a write", write_all(&mut from.writer, chunk_at(at)))
        .await
        .unwrap_or_else(|e| panic!("{name}: write failed: {e}"));
    step(
        name,
        "the graceful end",
        poll_fn(|cx| from.writer.poll_shutdown(cx)),
    )
    .await
    .unwrap_or_else(|e| panic!("{name}: graceful end failed: {e}"));
    let (read, end) = step(name, "the peer's end", read_to_end(&mut to, name)).await;
    end.unwrap_or_else(|e| panic!("{name}: no clean end: {e}"));
    assert_eq!(read, at + CHUNK, "{name}: bytes lost");
    let mut buf = [0u8; 64];
    let mut rb = ReadBuf::new(&mut buf);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    if let Poll::Ready(Err(e)) = Pin::new(&mut from.reader).poll_read(&mut cx, &mut rb) {
        panic!("{name}: the reads failed while the peer's half is open: {e}");
    }
    drop(to);
}
