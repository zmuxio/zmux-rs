//! Splicing two bidirectional streams into each other: how a relay connects an
//! inbound stream to an outbound one, whether
//! the streams carry application data or a nested session's pipe
//! (EXTENSIONS.md Section 10).
//!
//! Each direction, from a receiving part `r` to a sending part `w`, waits
//! for `w`'s send capacity with `min` = m = min(chunk, the bytes readable
//! on `r`, 16 KiB) ([`crate::SendStream::poll_send_capacity`]: woken once
//! per chunk, not on every credit change, and never stalled by a peer
//! window smaller than m); asks the
//! direction's limiter, if any, for `ready(min(m, capacity), min(capacity,
//! chunk))`; takes at most that from `r` as a chunk and hands it to `w`
//! without copying; and charges the limiter with what `w` took. Every wait
//! also watches both parts, so that an end or an error never waits behind
//! capacity: the waits register the task with `r` (data, FIN, reset, the
//! session's end) and with `w` (STOP_SENDING, the session's end) at once.
//!
//! At most one chunk per direction is held, between the read and the
//! moment `w` takes it; the backlog stays in `r`'s receive buffer, where
//! the stream's window bounds it. Nothing runs outside the caller's task
//! and no lock is held across a wait: dropping the future ends both streams
//! with code 0, releases the chunks and leaves nothing behind. A direction
//! that keeps finding data yields after 1 MiB (or 256 steps) in one poll,
//! so that it holds neither the other direction nor the executor.

use std::fmt;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::Bytes;

use super::handle::Upstream;
use crate::proto::limit::Limiter;
use crate::proto::session::StreamError;
use crate::proto::{ApplicationErrorCode, VarInt};
use crate::{RecvStream, SendStream};

/// The most a direction waits to take at once before it forwards less.
const STEP: usize = 16 * 1024;

/// The default chunk.
const CHUNK: usize = 64 * 1024;

/// The most a direction forwards in one poll before it yields to the
/// other direction and the executor's other tasks.
const POLL_BYTES: u64 = 1024 * 1024;

/// The most steps a direction takes in one poll before it yields.
const POLL_STEPS: u32 = 256;

fn code(c: ApplicationErrorCode) -> VarInt {
    VarInt::from_u64(c.0).unwrap_or(VarInt::ZERO)
}

/// How a splice runs.
#[derive(Clone)]
#[non_exhaustive]
pub struct SpliceOptions {
    /// The most bytes taken from a receiving part and held at once
    /// (default 64 KiB; at least 1).
    pub chunk: usize,
    /// Limits what is forwarded from `a` to `b`, stream and datagram bytes
    /// together.
    pub a_to_b: Option<Arc<dyn Limiter>>,
    /// Limits what is forwarded from `b` to `a`.
    pub b_to_a: Option<Arc<dyn Limiter>>,
}

impl Default for SpliceOptions {
    fn default() -> Self {
        Self {
            chunk: CHUNK,
            a_to_b: None,
            b_to_a: None,
        }
    }
}

impl fmt::Debug for SpliceOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpliceOptions")
            .field("chunk", &self.chunk)
            .field("a_to_b", &self.a_to_b.is_some())
            .field("b_to_a", &self.b_to_a.is_some())
            .finish()
    }
}

/// How one direction of a splice ended; codes travel unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpliceEnd {
    /// The upstream part ended with a FIN, which was forwarded after its
    /// data.
    Finished,
    /// The upstream part was reset with this code; the downstream part
    /// was reset with it, after the bytes below the upstream Reliable Size.
    Reset(VarInt),
    /// The downstream part was stopped with this code; the upstream part
    /// was stopped with it. A downstream stream refused after the peer's
    /// GOAWAY counts as stopped with ZMUX_REJECTED.
    Stopped(VarInt),
    /// The upstream session ended: the downstream part was reset with
    /// ZMUX_CARRIER_FAILED.
    UpstreamLost,
    /// The downstream session ended: the upstream part was stopped with
    /// ZMUX_CARRIER_FAILED.
    DownstreamLost,
}

/// What one direction forwarded (Result).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Forwarded {
    /// Stream bytes forwarded: read from the upstream part and taken by the
    /// downstream part.
    pub bytes: u64,
    /// Payload bytes of the stream datagrams forwarded. With `bytes`,
    /// exactly what the direction's limiter was charged.
    pub datagram_bytes: u64,
    /// Stream datagrams not forwarded: refused by the limiter or by the
    /// downstream session.
    pub datagrams_dropped: u64,
    /// How the direction ended.
    pub end: SpliceEnd,
}

/// The result of a splice: each direction's counts and end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Spliced {
    /// From `a` to `b`.
    pub a_to_b: Forwarded,
    /// From `b` to `a`.
    pub b_to_a: Forwarded,
}

/// Why a splice was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpliceError {
    /// A direction would forward a stream into itself.
    SameStream,
}

impl fmt::Display for SpliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameStream => f.write_str("a stream cannot be spliced into itself"),
        }
    }
}

impl std::error::Error for SpliceError {}

/// Forwards two bidirectional streams, usually of two different sessions,
/// into each other: what arrives on `a` is sent on
/// `b` and what arrives on `b` on `a`, until both directions have ended,
/// each independently, as half-closes do. Each stream is given as its
/// sending and receiving part.
///
/// The application opens the outbound stream with the inbound stream's
/// preamble ([`RecvStream::preamble`](crate::RecvStream#method.preamble), [`Session::open_bi_with`](crate::Session#method.open_bi_with)),
/// adjusted as its conventions say (PIPE_CARRIER and the application TLVs
/// come with it). Ends and errors propagate per direction, codes
/// unchanged:
///
/// | Event | Action |
/// |---|---|
/// | FIN read upstream | finish downstream after the data before it |
/// | upstream reset (code c, Reliable Size s) | the bytes below s are forwarded without waiting for capacity, made reliable downstream, and the downstream part reset with c; towards a peer without RESET_STREAM_AT, once they were passed to its carrier |
/// | downstream stopped with c | stop upstream with c |
/// | either session ends | reset and stop the other side's stream with ZMUX_CARRIER_FAILED |
/// | the future is dropped | reset and stop both streams with code 0 |
///
/// Stream datagrams (EXTENSIONS.md Section 6.3) are forwarded to the other
/// stream with their context, without waiting and without a queue of the
/// helper's own: the direction's limiter allows the whole payload or the
/// datagram is dropped, then the other session's datagram limiter and send
/// queue take it.
///
/// Each direction holds at most one chunk ([`SpliceOptions::chunk`], and
/// never more than the downstream capacity); the backlog stays in the
/// upstream receive buffer, bounded by its window, and flow control
/// carries the backpressure upstream. There is no timeout and no byte
/// limit: the streams' and sessions' own failure detection ends a splice
/// whose other side is gone. The helper runs in the caller's task, starts
/// none, and on every exit path ends both streams as the table says.
///
/// Refuses ([`SpliceError::SameStream`]) a direction from a stream into
/// itself; the streams are then released (code 0).
pub async fn splice(
    a: (SendStream, RecvStream),
    b: (SendStream, RecvStream),
    opts: SpliceOptions,
) -> Result<Spliced, SpliceError> {
    let (a_send, a_recv) = a;
    let (b_send, b_recv) = b;
    if b_send.same_stream(&a_recv) || a_send.same_stream(&b_recv) {
        return Err(SpliceError::SameStream);
    }
    let chunk = opts.chunk.max(1);
    let mut ab = Direction::new(&a_recv, &b_send, opts.a_to_b.as_deref(), chunk);
    let mut ba = Direction::new(&b_recv, &a_send, opts.b_to_a.as_deref(), chunk);
    let mut ab_datagrams = Datagrams::default();
    let mut ba_datagrams = Datagrams::default();
    let (ab_end, ba_end) = {
        let mut dg_ab = pin!(forward_datagrams(
            &a_recv,
            &b_send,
            opts.a_to_b.as_deref(),
            &mut ab_datagrams
        ));
        let mut dg_ba = pin!(forward_datagrams(
            &b_recv,
            &a_send,
            opts.b_to_a.as_deref(),
            &mut ba_datagrams
        ));
        let (mut dg_ab_done, mut dg_ba_done) = (false, false);
        let (mut ab_end, mut ba_end) = (None, None);
        poll_fn(|cx| {
            if ab_end.is_none()
                && let Poll::Ready(end) = ab.poll(cx)
            {
                ab_end = Some(end);
            }
            if ba_end.is_none()
                && let Poll::Ready(end) = ba.poll(cx)
            {
                ba_end = Some(end);
            }
            if !dg_ab_done {
                dg_ab_done = dg_ab.as_mut().poll(cx).is_ready();
            }
            if !dg_ba_done {
                dg_ba_done = dg_ba.as_mut().poll(cx).is_ready();
            }
            match (ab_end, ba_end) {
                (Some(x), Some(y)) => Poll::Ready((x, y)),
                _ => Poll::Pending,
            }
        })
        .await
    };
    Ok(Spliced {
        a_to_b: ab_datagrams.result(ab.bytes, ab_end),
        b_to_a: ba_datagrams.result(ba.bytes, ba_end),
    })
}

/// A limiter's allowance now for `len` bytes (a panic allows nothing).
fn allowance(limiter: &dyn Limiter, len: usize) -> usize {
    catch_unwind(AssertUnwindSafe(|| limiter.try_ready(len))).unwrap_or(0)
}

/// Polls a limiter for `min..=max` bytes (a panic allows nothing).
fn poll_allowance(limiter: &dyn Limiter, waker: &Waker, min: usize, max: usize) -> Poll<usize> {
    catch_unwind(AssertUnwindSafe(|| {
        limiter.poll_ready(&mut Context::from_waker(waker), min, max)
    }))
    .unwrap_or(Poll::Ready(0))
}

/// Charges a limiter (a panic is ignored).
fn charge(limiter: Option<&dyn Limiter>, n: usize) {
    if let Some(l) = limiter
        && n > 0
    {
        let _ = catch_unwind(AssertUnwindSafe(|| l.charge(n)));
    }
}

/// The datagrams of one direction.
#[derive(Default)]
struct Datagrams {
    bytes: u64,
    dropped: u64,
}

impl Datagrams {
    fn result(&self, bytes: u64, end: SpliceEnd) -> Forwarded {
        Forwarded {
            bytes,
            datagram_bytes: self.bytes,
            datagrams_dropped: self.dropped,
            end,
        }
    }
}

/// Forwards the stream datagrams of `r` to `w` until `r` can carry no more
/// (or the splice ends and drops this).
async fn forward_datagrams(
    r: &RecvStream,
    w: &SendStream,
    limiter: Option<&dyn Limiter>,
    count: &mut Datagrams,
) {
    while let Ok((context, data)) = r.read_datagram().await {
        let len = data.len();
        if let Some(l) = limiter
            && len > 0
            && allowance(l, len) < len
        {
            count.dropped += 1;
            continue;
        }
        match w.send_datagram(context, data) {
            Ok(()) => {
                charge(limiter, len);
                count.bytes += len as u64;
            }
            Err(_) => count.dropped += 1,
        }
    }
}

/// Where a direction is.
#[derive(Debug, Clone, Copy)]
enum Phase {
    /// Forwarding.
    Run,
    /// The upstream part was reset with `code`: the bytes below
    /// `reliable` (application bytes) are forwarded as `w`'s credit
    /// allows, then `w` is reset with them reliable.
    Reliable {
        code: VarInt,
        reliable: u64,
    },
    /// Towards a peer without RESET_STREAM_AT: the reset waits until the
    /// forwarded bytes were passed to the carrier.
    Flush {
        code: VarInt,
    },
    Done(SpliceEnd),
}

/// One direction of a splice, from `r` to `w`.
struct Direction<'a> {
    r: &'a RecvStream,
    w: &'a SendStream,
    limiter: Option<&'a dyn Limiter>,
    chunk: usize,
    /// A chunk read from `r` that `w` has not taken whole.
    held: Option<Bytes>,
    /// Bytes `w` took.
    bytes: u64,
    phase: Phase,
}

impl<'a> Direction<'a> {
    fn new(
        r: &'a RecvStream,
        w: &'a SendStream,
        limiter: Option<&'a dyn Limiter>,
        chunk: usize,
    ) -> Self {
        Self {
            r,
            w,
            limiter,
            chunk,
            held: None,
            bytes: 0,
            phase: Phase::Run,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<SpliceEnd> {
        let waker = cx.waker();
        let start = self.bytes;
        let mut steps = 0u32;
        loop {
            let step = match self.phase {
                Phase::Run => self.run(waker),
                Phase::Reliable { code, reliable } => self.reliable(waker, code, reliable),
                Phase::Flush { code } => self.flush(waker, code),
                Phase::Done(end) => {
                    // Whatever was read and not forwarded is released now.
                    self.held = None;
                    return Poll::Ready(end);
                }
            };
            if step.is_pending() {
                return Poll::Pending;
            }
            steps += 1;
            if steps >= POLL_STEPS || self.bytes - start >= POLL_BYTES {
                // A fast direction does not hold the task: it yields and
                // continues on the next poll.
                waker.wake_by_ref();
                return Poll::Pending;
            }
        }
    }

    /// Forwarding: one step; `Ready` when the phase changed or progress
    /// was made.
    fn run(&mut self, waker: &Waker) -> Poll<()> {
        if self.held.is_some() {
            // The chunk in hand first; meanwhile `r` is watched for its
            // reset, which is acted on as soon as it arrived.
            if self.watch_upstream(waker) {
                return Poll::Ready(());
            }
            return self.write_held(waker);
        }
        // One critical section: a reset, acted on before the data below
        // its Reliable Size was read, or what is readable; `r` stays
        // registered while the step waits on `w`.
        let readable = match self.r.poll_upstream(waker) {
            Poll::Ready(Ok(Upstream::Reset(code, reliable))) => {
                self.on_reset(code, reliable);
                return Poll::Ready(());
            }
            Poll::Ready(Ok(Upstream::Readable(0))) => {
                self.forward_fin(waker);
                return Poll::Ready(());
            }
            Poll::Ready(Ok(Upstream::Readable(n))) => n,
            Poll::Ready(Err(e)) => {
                self.upstream_failed(e);
                return Poll::Ready(());
            }
            Poll::Pending => {
                // Nothing to read: `w` is watched for its end.
                return self.watch_downstream(waker);
            }
        };
        let m = self.chunk.min(readable).min(STEP);
        let capacity = match self.w.poll_capacity_with(waker, m as u64) {
            Poll::Ready(Ok(c)) => usize::try_from(c).unwrap_or(usize::MAX),
            Poll::Ready(Err(e)) => {
                self.downstream_failed(e);
                return Poll::Ready(());
            }
            Poll::Pending => return Poll::Pending,
        };
        let max = capacity.min(self.chunk);
        let allowed = match self.limiter {
            None => max,
            Some(l) => match poll_allowance(l, waker, m.min(capacity), max) {
                Poll::Ready(a) if a > 0 => a.min(max),
                // An allowance of 0 breaks the contract (a limiter waits
                // instead), as does a panic: taken as a wait that only the
                // streams' events end, never as a reason to spin.
                _ => return self.watch_downstream(waker),
            },
        };
        match self.r.poll_take_chunk(waker, allowed) {
            Poll::Ready(Ok(Some(chunk))) => {
                self.held = Some(chunk);
                // Handed to `w` at once: `r` stays registered for its
                // next event while `w` takes the chunk.
                self.write_held(waker)
            }
            // The end, seen again by the next step.
            Poll::Ready(Ok(None)) => Poll::Ready(()),
            Poll::Ready(Err(e)) => {
                self.upstream_failed(e);
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Hands the chunk in hand to `w`; `Pending` (the writer registered)
    /// while `w` takes nothing.
    fn write_held(&mut self, waker: &Waker) -> Poll<()> {
        let Some(held) = &mut self.held else {
            return Poll::Ready(());
        };
        match self.w.poll_write_part(waker, held) {
            Poll::Ready(Ok(n)) => {
                if held.is_empty() {
                    self.held = None;
                }
                self.took(n);
            }
            Poll::Ready(Err(e)) => self.downstream_failed(e),
            Poll::Pending => return Poll::Pending,
        }
        Poll::Ready(())
    }

    /// Waits on `r` (registered by the caller) while `w` is watched for
    /// its end: `Ready` when `w` ended (the phase changed).
    fn watch_downstream(&mut self, waker: &Waker) -> Poll<()> {
        match self.w.watch(waker) {
            Ok(()) => Poll::Pending,
            Err(e) => {
                self.downstream_failed(e);
                Poll::Ready(())
            }
        }
    }

    /// Watches `r` for its reset or its session's end while the direction
    /// waits on something else; `true` when it ended (the phase changed).
    fn watch_upstream(&mut self, waker: &Waker) -> bool {
        match self.r.watch(waker) {
            Ok(None) => false,
            Ok(Some((code, reliable))) => {
                self.on_reset(code, reliable);
                true
            }
            Err(e) => {
                self.upstream_failed(e);
                true
            }
        }
    }

    /// `w` took `n` bytes: count and charge them.
    fn took(&mut self, n: usize) {
        self.bytes += n as u64;
        charge(self.limiter, n);
    }

    /// The FIN was read: consume it and finish `w`.
    fn forward_fin(&mut self, waker: &Waker) {
        // Reads the end (nothing is left before it).
        let _ = self.r.poll_read_chunk(waker, 1);
        match self.w.finish_shared() {
            Ok(()) | Err(StreamError::ClosedLocally) => {
                self.phase = Phase::Done(SpliceEnd::Finished)
            }
            Err(e) => self.downstream_failed(e),
        }
    }

    /// `r` was reset with `code` and Reliable Size `reliable` (in
    /// application bytes).
    fn on_reset(&mut self, code: VarInt, reliable: u64) {
        self.phase = Phase::Reliable { code, reliable };
    }

    /// Forwards the bytes below the Reliable Size as `w`'s credit allows
    /// (EXTENSIONS.md Section 10.5: a relay forwards data only within the
    /// next hop's credit), then marks the reliable boundary after them and
    /// resets `w`; with nothing left to forward, at once. The wait for
    /// credit ends early only when `w` ends.
    fn reliable(&mut self, waker: &Waker, code: VarInt, reliable: u64) -> Poll<()> {
        if self.bytes < reliable {
            let need = usize::try_from(reliable - self.bytes).unwrap_or(usize::MAX);
            if let Some(held) = &mut self.held {
                // Only the part below the Reliable Size is owed.
                if held.len() > need {
                    held.truncate(need);
                }
                return self.write_held(waker);
            }
            let m = self.chunk.min(need).min(STEP);
            let capacity = match self.w.poll_capacity_with(waker, m as u64) {
                Poll::Ready(Ok(c)) => usize::try_from(c).unwrap_or(usize::MAX),
                Poll::Ready(Err(e)) => {
                    self.downstream_failed(e);
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            };
            match self
                .r
                .poll_read_chunk(waker, capacity.min(self.chunk).min(need))
            {
                Poll::Ready(Ok(Some(chunk))) => {
                    self.held = Some(chunk);
                    return self.write_held(waker);
                }
                // The reset took effect: everything below it was read, or
                // the session ended before it arrived.
                Poll::Ready(Ok(None) | Err(StreamError::Reset { .. } | StreamError::Rejected)) => {}
                Poll::Ready(Err(e)) => {
                    self.upstream_failed(e);
                    return Poll::Ready(());
                }
                Poll::Pending => return self.watch_downstream(waker),
            }
        }
        // The chunk in hand beyond the Reliable Size is not forwarded.
        self.held = None;
        if reliable > 0 {
            // The bytes forwarded stay reliable downstream, in `w`'s
            // offsets (its preamble included): everything below the
            // upstream Reliable Size, and possibly more. Towards a peer
            // without RESET_STREAM_AT, they are passed to the carrier
            // before the RESET_STREAM.
            let _ = self.w.set_reliable_boundary_shared();
            if !self.w.peer_accepts_reset_stream_at() {
                self.phase = Phase::Flush { code };
                return Poll::Ready(());
            }
        }
        self.reset_downstream(code);
        Poll::Ready(())
    }

    /// Without RESET_STREAM_AT: the reset once the forwarded bytes were
    /// passed to the carrier.
    fn flush(&mut self, waker: &Waker, code: VarInt) -> Poll<()> {
        match self.w.poll_sent(waker) {
            Poll::Ready(Ok(())) => self.reset_downstream(code),
            Poll::Ready(Err(e)) => self.downstream_failed(e),
            Poll::Pending => return Poll::Pending,
        }
        Poll::Ready(())
    }

    fn reset_downstream(&mut self, code: VarInt) {
        let _ = self.w.reset_shared(code);
        self.phase = Phase::Done(SpliceEnd::Reset(code));
    }

    /// `r` ended other than by a FIN or a reset seen as such.
    fn upstream_failed(&mut self, e: StreamError) {
        let (c, end) = match e {
            StreamError::Reset { code, .. } => (code, SpliceEnd::Reset(code)),
            // ZMUX_REJECTED, or a stream refused after the peer's GOAWAY.
            StreamError::Rejected | StreamError::GoingAway => {
                let c = code(ApplicationErrorCode::ZMUX_REJECTED);
                (c, SpliceEnd::Reset(c))
            }
            _ => (
                code(ApplicationErrorCode::ZMUX_CARRIER_FAILED),
                SpliceEnd::UpstreamLost,
            ),
        };
        let _ = self.w.reset_shared(c);
        self.phase = Phase::Done(end);
    }

    /// `w` ended: stopped by its peer, refused, or its session ended.
    fn downstream_failed(&mut self, e: StreamError) {
        let (c, end) = match e {
            StreamError::Stopped(c) => (c, SpliceEnd::Stopped(c)),
            StreamError::Rejected | StreamError::GoingAway => {
                let c = code(ApplicationErrorCode::ZMUX_REJECTED);
                (c, SpliceEnd::Stopped(c))
            }
            _ => (
                code(ApplicationErrorCode::ZMUX_CARRIER_FAILED),
                SpliceEnd::DownstreamLost,
            ),
        };
        let _ = self.r.stop_shared(c);
        self.phase = Phase::Done(end);
    }
}
