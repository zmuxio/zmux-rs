//! Streams as pipes: a bidirectional stream of an
//! outer session as the carrier of a pipe pair of a nested session, mapped
//! as EXTENSIONS.md Section 10.2 specifies.
//!
//! | Pipe | Outer stream |
//! |---|---|
//! | write | write within the send capacity: not writable while the stream lacks credit or room |
//! | graceful end of the sending half | finish (FIN) |
//! | any other end of the sending half (an abort, the nested session's end) | reset with ZMUX_CARRIER_FAILED (RESET_STREAM_AT keeping the preamble on the opener's part) |
//! | close of the receiving half before its end | stop with ZMUX_CARRIER_FAILED |
//! | FIN received | graceful end of the inbound pipe |
//! | reset received, STOP_SENDING received, the outer session's end | a read or write error: failure of the pipe |
//!
//! The halves pass the nested session's records as owned buffers: the
//! session task reads the outer stream in chunks, which the nested core
//! parses where they lie (keeping only a record split across two chunks),
//! and writes its batches' referenced payloads as shared chunks. They declare
//! no carrier capability (no unsent count, no
//! low-water mark, no RTT): the nested session paces the pipe with its
//! carrier queue limiter, and the outer stream's
//! own send buffer is never reported as the carrier's unsent bytes.
//!
//! A pipe never runs over its own session (EXTENSIONS.md Section 10.2): a
//! table of the process records the sessions whose streams carry pipes of
//! other sessions, and a carrier is refused when its outer session runs,
//! directly or through other sessions of the process, over the session it
//! is for.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Poll};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::Bytes;

use super::handle::Shared;
use super::tokio::{RecvStream, SendStream, Tokio};
use crate::proto::session::{PieceCursor, PipeError, StreamError, TransmitBuf};
use crate::proto::{ApplicationErrorCode, VarInt};

/// ZMUX_CARRIER_FAILED as a code.
fn carrier_failed() -> VarInt {
    VarInt::from_u64(ApplicationErrorCode::ZMUX_CARRIER_FAILED.0).unwrap_or(VarInt::ZERO)
}

/// The receiving half of a stream carrier.
pub(crate) struct StreamReader {
    recv: RecvStream,
    /// The stream's end was read (a FIN, a reset or the session's end).
    ended: bool,
}

impl StreamReader {
    pub(crate) fn new(recv: RecvStream) -> Self {
        Self { recv, ended: false }
    }

    /// One chunk of at most `max` bytes, without copying; `None` at the
    /// FIN.
    pub(crate) fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max: usize,
    ) -> Poll<io::Result<Option<Bytes>>> {
        let r = std::task::ready!(self.recv.poll_read_chunk(cx.waker(), max.max(1)));
        self.ended |= !matches!(r, Ok(Some(_)));
        Poll::Ready(r.map_err(io::Error::from))
    }
}

impl AsyncRead for StreamReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let dst = buf.initialize_unfilled();
        if dst.is_empty() {
            return Poll::Ready(Ok(()));
        }
        match std::task::ready!(this.recv.poll_read_buf(cx.waker(), dst)) {
            Ok(Some(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Ok(None) => {
                this.ended = true;
                Poll::Ready(Ok(()))
            }
            Err(e) => {
                this.ended = true;
                Poll::Ready(Err(e.into()))
            }
        }
    }
}

impl Drop for StreamReader {
    /// Closed before its end: stop with ZMUX_CARRIER_FAILED.
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.recv.stop_shared(carrier_failed());
        }
    }
}

/// The sending half of a stream carrier.
pub(crate) struct StreamWriter {
    send: SendStream,
    /// The half was shut down gracefully (FIN).
    finished: bool,
}

impl StreamWriter {
    pub(crate) fn new(send: SendStream) -> Self {
        Self {
            send,
            finished: false,
        }
    }

    /// Registers the task as the stream's writer while the pipe has nothing
    /// to write, so that a STOP_SENDING or the end of the stream's session
    /// wakes it; fails at once with what ended the stream.
    pub(crate) fn watch(&self, cx: &Context<'_>) -> io::Result<()> {
        self.send.watch(cx.waker()).map_err(io::Error::from)
    }

    /// One write call of a batch (see [`SendStream::poll_write_batch`](crate::SendStream#method.poll_write_batch)).
    pub(crate) fn poll_write_batch(
        &mut self,
        cx: &mut Context<'_>,
        out: &TransmitBuf,
        cursor: &mut PieceCursor,
        from: usize,
        limit: usize,
    ) -> Poll<io::Result<usize>> {
        self.send
            .poll_write_batch(cx.waker(), out, cursor, from, limit)
            .map_err(io::Error::from)
    }
}

impl AsyncWrite for StreamWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.send
            .poll_write_capped(cx.waker(), buf)
            .map_err(io::Error::from)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// The graceful end: FIN.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Poll::Ready(match this.send.finish_shared() {
            Ok(()) | Err(StreamError::ClosedLocally) => {
                this.finished = true;
                Ok(())
            }
            Err(e) => Err(e.into()),
        })
    }
}

impl Drop for StreamWriter {
    /// Any end but the graceful one is an abort: reset with
    /// ZMUX_CARRIER_FAILED (on the opener's part RESET_STREAM_AT keeping the
    /// preamble, EXTENSIONS.md Section 4.5).
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.send.reset_shared(carrier_failed());
        }
    }
}

/// The nesting table of the process (MULTIPATH.md Section 5.4 step 7): one edge
/// per pipe carried by a stream,
/// from the session the pipe belongs to (`inner`) to the session whose
/// stream carries it (`outer`). A leaf lock: no other lock is taken while
/// it is held, so a loop check and the recording of the edge it allows are
/// one atomic step.
struct Edge {
    inner: Weak<Shared<Tokio>>,
    pipe: u64,
    outer: Weak<Shared<Tokio>>,
}

static NESTING: Mutex<Vec<Edge>> = Mutex::new(Vec::new());

/// Edges in [`NESTING`], changed under its lock: a pipe or session of a
/// process that carries no pipe over a stream skips the lock.
static EDGES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn nesting() -> std::sync::MutexGuard<'static, Vec<Edge>> {
    NESTING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether the session at `outer` runs over the one at `target`: is it,
/// or has a pipe carried by a stream of a session that runs over `target`.
fn runs_over_in(edges: &[Edge], outer: *const Shared<Tokio>, target: *const Shared<Tokio>) -> bool {
    let mut stack = vec![outer];
    let mut seen: Vec<*const Shared<Tokio>> = Vec::new();
    while let Some(at) = stack.pop() {
        if std::ptr::eq(at, target) {
            return true;
        }
        if seen.contains(&at) {
            continue;
        }
        seen.push(at);
        stack.extend(
            edges
                .iter()
                .filter(|e| std::ptr::eq(e.inner.as_ptr(), at) && e.outer.strong_count() > 0)
                .map(|e| e.outer.as_ptr()),
        );
    }
    false
}

/// Whether `outer` runs over `target` (a check ahead of a join; the
/// binding check is [`claim_carrier`]).
pub(crate) fn runs_over(outer: &Arc<Shared<Tokio>>, target: &Shared<Tokio>) -> bool {
    runs_over_in(&nesting(), Arc::as_ptr(outer), target)
}

/// Records that pipe `pipe` of `session` is carried by a stream of
/// `outer`, unless `outer` runs over `session`: the check and the record
/// are one step under the table's lock.
pub(crate) fn claim_carrier(
    session: &Arc<Shared<Tokio>>,
    pipe: u64,
    outer: Option<Weak<Shared<Tokio>>>,
) -> Result<(), PipeError> {
    let Some(outer) = outer else {
        return Ok(());
    };
    let mut edges = nesting();
    // Edges of ended sessions go when met.
    edges.retain(|e| e.inner.strong_count() > 0 && e.outer.strong_count() > 0);
    EDGES.store(edges.len(), std::sync::atomic::Ordering::Release);
    if outer.strong_count() > 0 && runs_over_in(&edges, outer.as_ptr(), Arc::as_ptr(session)) {
        return Err(PipeError::CarrierLoop);
    }
    edges.push(Edge {
        inner: Arc::downgrade(session),
        pipe,
        outer,
    });
    EDGES.store(edges.len(), std::sync::atomic::Ordering::Release);
    Ok(())
}

/// Pipe `pipe` of `session` is gone (or, with `None`, every pipe of an
/// ended session): its edges leave the table.
pub(crate) fn release_carriers(session: &Shared<Tokio>, pipe: Option<u64>) {
    // An edge of this session was recorded before its pipe or the session
    // could end, by the thread that ends it or one it synchronised with.
    if EDGES.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return;
    }
    let at: *const Shared<Tokio> = session;
    let mut edges = nesting();
    edges.retain(|e| !(std::ptr::eq(e.inner.as_ptr(), at) && pipe.is_none_or(|p| p == e.pipe)));
    EDGES.store(edges.len(), std::sync::atomic::Ordering::Release);
}
