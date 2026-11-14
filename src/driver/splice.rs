//! Splicing two bidirectional streams into each other: how a relay connects an
//! inbound stream to an outbound one, whether the streams carry application
//! data or a nested session's pipe.
//!
//! Each direction, from a receiving part `r` to a sending part `w`, waits
//! for `w`'s send capacity with `min` = m = min(chunk, the bytes readable
//! on `r`, 16 KiB) ([`SendStream::poll_send_capacity`]: woken once
//! per chunk, not on every credit change, and never stalled by a peer
//! window smaller than m); asks the
//! direction's limiter, if any, for `ready(min(m, capacity), min(capacity,
//! chunk))`; takes at most that from `r` as a chunk and hands it to `w`
//! without copying; and charges the limiter with what `w` took. Every wait
//! also watches both parts, so that an end or an error never waits behind
//! capacity: the waits register the task with `r` (data, FIN, reset, the
//! session's end) and with `w` (`STOP_SENDING`, the session's end) at once.
//!
//! At most one chunk per direction is held, between the read and the
//! moment `w` takes it; the backlog stays in `r`'s receive buffer, where
//! the stream's window bounds it. Nothing runs outside the caller's task
//! and no lock is held across a wait: dropping the future ends both streams
//! with code 0, releases the chunks and leaves nothing behind. A direction
//! that keeps finding data yields after 1 MiB (or 256 steps) in one poll,
//! so that it holds neither the other direction nor the executor.

use std::collections::VecDeque;
use std::fmt;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;

use super::handle::Upstream;
use crate::helpers::capsule::{self, MAX_HEADER, Scanner};
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
    /// Ends the splice with a chosen code when aborted ([`SpliceAbort`]).
    pub abort: Option<SpliceAbort>,
}

impl Default for SpliceOptions {
    fn default() -> Self {
        Self {
            chunk: CHUNK,
            a_to_b: None,
            b_to_a: None,
            abort: None,
        }
    }
}

impl fmt::Debug for SpliceOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpliceOptions")
            .field("chunk", &self.chunk)
            .field("a_to_b", &self.a_to_b.is_some())
            .field("b_to_a", &self.b_to_a.is_some())
            .field("abort", &self.abort)
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
    /// GOAWAY counts as stopped with `ZMUX_REJECTED`.
    Stopped(VarInt),
    /// The upstream session ended: the downstream part was reset with
    /// `ZMUX_CARRIER_FAILED`.
    UpstreamLost,
    /// The downstream session ended: the upstream part was stopped with
    /// `ZMUX_CARRIER_FAILED`.
    DownstreamLost,
    /// The splice was aborted with this code ([`SpliceAbort::abort`]): the
    /// downstream part was reset and the upstream part stopped with it.
    Cancelled(VarInt),
}

/// Aborts splices with a chosen application error code: what dropping the
/// splice's future does, but with that code, and with a result.
///
/// Created with [`SpliceAbort::new`] and given to one or more splices in
/// [`SpliceOptions::abort`]; clones share the handle. The first
/// [`abort`](Self::abort) decides the code; later calls change nothing. A
/// splice given an aborted handle, at its start or later, resets both
/// downstream sending parts and stops both upstream receiving parts with
/// the code, in each direction still running, discards what it holds and
/// completes with [`SpliceEnd::Cancelled`] for those directions (one that
/// had already ended keeps its end). Dropping the future instead still
/// resets the streams with `ZMUX_CANCELLED` and stops them with code 0,
/// and gives no result.
#[derive(Clone, Default)]
pub struct SpliceAbort(Arc<Mutex<AbortState>>);

#[derive(Default)]
struct AbortState {
    code: Option<VarInt>,
    next: u64,
    wakers: Vec<(u64, Waker)>,
}

impl SpliceAbort {
    /// A handle not aborted yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Aborts every splice given this handle with `code` (any code, 0
    /// included); idempotent, the first code stays.
    pub fn abort(&self, code: VarInt) {
        let wakers = {
            let mut st = lock_abort(&self.0);
            if st.code.is_some() {
                return;
            }
            st.code = Some(code);
            std::mem::take(&mut st.wakers)
        };
        for (_, w) in wakers {
            w.wake();
        }
    }

    /// The code of the abort, once aborted.
    #[must_use]
    pub fn code(&self) -> Option<VarInt> {
        lock_abort(&self.0).code
    }

    /// The code once aborted; otherwise registers the waker of the splice
    /// `slot` (assigned on its first call).
    fn poll(&self, slot: &mut Option<u64>, waker: &Waker) -> Option<VarInt> {
        let mut st = lock_abort(&self.0);
        if st.code.is_some() {
            return st.code;
        }
        let id = *slot.get_or_insert_with(|| {
            st.next += 1;
            st.next
        });
        match st.wakers.iter_mut().find(|(i, _)| *i == id) {
            Some((_, w)) => w.clone_from(waker),
            None => st.wakers.push((id, waker.clone())),
        }
        None
    }

    fn forget(&self, slot: Option<u64>) {
        if let Some(id) = slot {
            lock_abort(&self.0).wakers.retain(|(i, _)| *i != id);
        }
    }
}

impl fmt::Debug for SpliceAbort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SpliceAbort").field(&self.code()).finish()
    }
}

fn lock_abort(m: &Mutex<AbortState>) -> MutexGuard<'_, AbortState> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Removes a splice's waker from its abort handle when the splice ends or
/// is dropped.
struct AbortSlot<'a>(Option<&'a SpliceAbort>, Option<u64>);

impl Drop for AbortSlot<'_> {
    fn drop(&mut self) {
        if let Some(a) = self.0 {
            a.forget(self.1);
        }
    }
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
    /// Stream datagrams not forwarded, for any cause: at least
    /// `datagrams_too_large + datagrams_limited`, and also those the
    /// downstream stream or session could no longer carry.
    pub datagrams_dropped: u64,
    /// Stream datagrams not forwarded because they did not fit a datagram
    /// of the downstream stream (its largest payload, or no datagrams on
    /// the downstream session). A packet relay ([`splice_packets`]) drops
    /// one only when its capsule queue is full, or when the direction
    /// ended (the upstream's FIN or reset included) before the capsule
    /// was written whole.
    pub datagrams_too_large: u64,
    /// Stream datagrams not forwarded because the direction's limiter or
    /// the downstream session's datagram limiter refused them.
    pub datagrams_limited: u64,
    /// Stream datagrams a packet relay forwarded as DATAGRAM capsules on
    /// the downstream stream because they did not fit a datagram there,
    /// counted once written whole; counted in `datagram_bytes` too.
    /// Always 0 for [`splice`].
    pub datagrams_as_capsules: u64,
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
/// preamble ([`RecvStream::preamble`](RecvStream#method.preamble), [`Session::open_bi_with`](crate::Session#method.open_bi_with)),
/// adjusted as its conventions say (`PIPE_CARRIER` and the application TLVs
/// come with it). Ends and errors propagate per direction, codes
/// unchanged:
///
/// | Event | Action |
/// |---|---|
/// | FIN read upstream | finish downstream after the data before it |
/// | upstream reset (code c, Reliable Size s) | the bytes below s are forwarded without waiting for capacity, made reliable downstream, and the downstream part reset with c; towards a peer without `RESET_STREAM_AT`, once they were passed to its carrier |
/// | downstream stopped with c | stop upstream with c |
/// | either session ends | reset and stop the other side's stream with `ZMUX_CARRIER_FAILED` |
/// | the future is dropped | reset both streams with `ZMUX_CANCELLED` and stop them with code 0 |
/// | [`SpliceOptions::abort`] aborted with c | reset both streams and stop them with c; the result reports [`SpliceEnd::Cancelled`] |
///
/// Stream datagrams are forwarded to the other stream with their context,
/// without waiting and without a queue of the helper's own: the
/// direction's limiter allows the whole payload or the datagram is
/// dropped, then the other session's datagram limiter and send queue take
/// it.
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
///
/// # Errors
///
/// [`SpliceError::SameStream`], as above; how each direction ended is in
/// the [`Spliced`] result, not an error.
pub async fn splice(
    a: (SendStream, RecvStream),
    b: (SendStream, RecvStream),
    opts: SpliceOptions,
) -> Result<Spliced, SpliceError> {
    splice_with(a, b, opts, false).await
}

/// [`splice`] for two packet streams (EXTENSIONS.md Section 12): the
/// relay of [`PacketStream`](crate::helpers::PacketStream)s. Ends,
/// limiters and results are those of [`splice`]; what differs is how
/// packets cross:
///
/// - the stream bytes are passed through in chunks, as [`splice`] passes
///   them, while only the capsule headers are parsed, to know where each
///   capsule ends; capsules of any type, unknown ones included, pass
///   unchanged, and a capsule above a receiver's bound is the receiver's
///   to refuse;
/// - a stream datagram goes on as a datagram when it fits the downstream
///   stream's datagrams, and otherwise (too large there, or no datagrams
///   on the downstream session) as a DATAGRAM capsule with the same
///   Context ID and payload, inserted at the next capsule boundary of the
///   downstream bytes ([`Forwarded::datagrams_as_capsules`]). Those
///   waiting for a boundary are bounded (the larger of the chunk and one
///   largest datagram); beyond it they are dropped as too large. The
///   direction's limiter must allow the payload when it is queued and is
///   charged once the capsule was written whole; one the direction never
///   wrote (it ended first) is dropped as too large and not charged.
///
/// A capsule is never turned into a datagram: what was sent reliably stays
/// reliable.
///
/// # Errors
///
/// As [`splice`].
pub async fn splice_packets(
    a: (SendStream, RecvStream),
    b: (SendStream, RecvStream),
    opts: SpliceOptions,
) -> Result<Spliced, SpliceError> {
    splice_with(a, b, opts, true).await
}

async fn splice_with(
    a: (SendStream, RecvStream),
    b: (SendStream, RecvStream),
    opts: SpliceOptions,
    packets: bool,
) -> Result<Spliced, SpliceError> {
    let (a_send, a_recv) = a;
    let (b_send, b_recv) = b;
    if b_send.same_stream(&a_recv) || a_send.same_stream(&b_recv) {
        return Err(SpliceError::SameStream);
    }
    let chunk = opts.chunk.max(1);
    // The DATAGRAM capsules waiting for a boundary of each direction (a
    // packet relay's only).
    let bound = chunk.max(MAX_HEADER + MAX_DATAGRAM);
    let (ab_inserts, ba_inserts) = (Mutex::default(), Mutex::default());
    let (ab_convert, ba_convert) = if packets {
        (Some(&ab_inserts), Some(&ba_inserts))
    } else {
        (None, None)
    };
    let mut ab = Direction::new(&a_recv, &b_send, opts.a_to_b.as_deref(), chunk, ab_convert);
    let mut ba = Direction::new(&b_recv, &a_send, opts.b_to_a.as_deref(), chunk, ba_convert);
    let mut ab_datagrams = Datagrams::default();
    let mut ba_datagrams = Datagrams::default();
    let (ab_end, ba_end) = {
        let mut dg_ab = pin!(forward_datagrams(
            &a_recv,
            &b_send,
            opts.a_to_b.as_deref(),
            &mut ab_datagrams,
            ab_convert.map(|q| (q, bound)),
        ));
        let mut dg_ba = pin!(forward_datagrams(
            &b_recv,
            &a_send,
            opts.b_to_a.as_deref(),
            &mut ba_datagrams,
            ba_convert.map(|q| (q, bound)),
        ));
        let (mut dg_ab_done, mut dg_ba_done) = (false, false);
        let (mut ab_end, mut ba_end) = (None, None);
        let mut slot = AbortSlot(opts.abort.as_ref(), None);
        poll_fn(|cx| {
            if let Some(a) = slot.0
                && let Some(c) = a.poll(&mut slot.1, cx.waker())
            {
                for (d, end) in [(&mut ab, &mut ab_end), (&mut ba, &mut ba_end)] {
                    if end.is_none() {
                        d.abort(c);
                        *end = Some(SpliceEnd::Cancelled(c));
                    }
                }
            }
            // Datagrams first: a capsule they queued is written by the
            // direction in the same poll.
            if !dg_ab_done {
                dg_ab_done = dg_ab.as_mut().poll(cx).is_ready();
            }
            if !dg_ba_done {
                dg_ba_done = dg_ba.as_mut().poll(cx).is_ready();
            }
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
            match (ab_end, ba_end) {
                (Some(x), Some(y)) => Poll::Ready((x, y)),
                _ => Poll::Pending,
            }
        })
        .await
    };
    Ok(Spliced {
        a_to_b: ab_datagrams.result(ab.bytes, ab_end, &lock(&ab_inserts)),
        b_to_a: ba_datagrams.result(ba.bytes, ba_end, &lock(&ba_inserts)),
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

/// The largest datagram payload a session carries.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the largest record size is 65535, inside usize"
)]
const MAX_DATAGRAM: usize = crate::proto::params::ZMUX_MAX_RECORD_SIZE as usize;

/// The datagrams of one direction.
#[derive(Default)]
struct Datagrams {
    bytes: u64,
    dropped: u64,
    too_large: u64,
    limited: u64,
}

impl Datagrams {
    /// With what the direction wrote of the capsules queued in `inserts`.
    fn result(&self, bytes: u64, end: SpliceEnd, inserts: &Inserts) -> Forwarded {
        Forwarded {
            bytes,
            datagram_bytes: self.bytes + inserts.sent_bytes,
            datagrams_dropped: self.dropped + inserts.unsent,
            datagrams_too_large: self.too_large + inserts.unsent,
            datagrams_limited: self.limited,
            datagrams_as_capsules: inserts.sent,
            end,
        }
    }

    fn forwarded(&mut self, limiter: Option<&dyn Limiter>, len: usize) {
        charge(limiter, len);
        self.bytes += len as u64;
    }
}

/// DATAGRAM capsules of a packet relay's direction waiting for a capsule
/// boundary of the downstream bytes: each a header and a payload.
#[derive(Default)]
struct Inserts {
    queue: VecDeque<(Bytes, Bytes)>,
    bytes: usize,
    /// The direction ended, or its upstream did (a FIN or a reset):
    /// nothing more is queued.
    closed: bool,
    /// Capsules written whole, and their payload bytes (charged to the
    /// direction's limiter as they were written).
    sent: u64,
    sent_bytes: u64,
    /// Capsules queued and never written whole.
    unsent: u64,
}

impl Inserts {
    /// Queues a capsule unless the direction ended or `bound` bytes wait.
    fn push(&mut self, context: u64, payload: Bytes, bound: usize) -> bool {
        let mut h = [0; MAX_HEADER];
        let n = capsule::datagram_header(context, payload.len(), &mut h);
        let size = n + payload.len();
        if self.closed || (!self.queue.is_empty() && self.bytes + size > bound) {
            return false;
        }
        self.bytes += size;
        self.queue
            .push_back((Bytes::copy_from_slice(&h[..n]), payload));
        true
    }
}

fn lock(m: &Mutex<Inserts>) -> MutexGuard<'_, Inserts> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Forwards the stream datagrams of `r` to `w` until `r` can carry no more
/// (or the splice ends and drops this); with `convert`, one that does not
/// fit a datagram of `w` is queued as a DATAGRAM capsule.
async fn forward_datagrams(
    r: &RecvStream,
    w: &SendStream,
    limiter: Option<&dyn Limiter>,
    count: &mut Datagrams,
    convert: Option<(&Mutex<Inserts>, usize)>,
) {
    while let Ok(crate::StreamDatagram {
        context,
        payload: data,
    }) = r.read_datagram().await
    {
        let len = data.len();
        if let Some(l) = limiter
            && len > 0
            && allowance(l, len) < len
        {
            count.dropped += 1;
            count.limited += 1;
            continue;
        }
        match w.try_send_datagram(context, data.clone()) {
            Ok(true) => count.forwarded(limiter, len),
            Ok(false) => {
                count.dropped += 1;
                count.limited += 1;
            }
            Err(crate::DatagramError::TooLarge { .. } | crate::DatagramError::NotNegotiated) => {
                match convert {
                    // Counted, and charged, once the direction wrote it.
                    Some((q, bound)) if lock(q).push(context, data, bound) => {}
                    _ => {
                        count.dropped += 1;
                        count.too_large += 1;
                    }
                }
            }
            Err(_) => count.dropped += 1,
        }
    }
}

/// A packet relay's view of a direction's downstream bytes.
struct Framing<'a> {
    scan: Scanner,
    inserts: &'a Mutex<Inserts>,
    /// Bytes read from `r` past the boundary where a capsule waits.
    unscanned: Option<Bytes>,
    /// The payload of the capsule being inserted, after its header.
    tail: Option<Bytes>,
    /// The payload length of the capsule being inserted.
    insert_len: usize,
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
    /// Towards a peer without `RESET_STREAM_AT`: the reset waits until the
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
    /// `held` is part of an inserted capsule, not of `r`'s bytes.
    held_insert: bool,
    framing: Option<Framing<'a>>,
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
        inserts: Option<&'a Mutex<Inserts>>,
    ) -> Self {
        Self {
            r,
            w,
            limiter,
            chunk,
            held: None,
            held_insert: false,
            framing: inserts.map(|inserts| Framing {
                scan: Scanner::default(),
                inserts,
                unscanned: None,
                tail: None,
                insert_len: 0,
            }),
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
                    if let Some(f) = self.framing.take() {
                        let mut q = lock(f.inserts);
                        q.closed = true;
                        // A capsule cut short was not delivered either.
                        let cut = u64::from(self.held_insert || f.tail.is_some());
                        q.unsent += q.queue.len() as u64 + cut;
                        q.queue.clear();
                    }
                    self.held_insert = false;
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
        if self.load_framed() {
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
                self.upstream_failed(&e);
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
                self.downstream_failed(&e);
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
                self.hold(chunk);
                // Handed to `w` at once: `r` stays registered for its
                // next event while `w` takes the chunk.
                self.write_held(waker)
            }
            // The end, seen again by the next step.
            Poll::Ready(Ok(None)) => Poll::Ready(()),
            Poll::Ready(Err(e)) => {
                self.upstream_failed(&e);
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Takes a chunk read from `r` in hand: with framing, up to the first
    /// capsule boundary while a capsule waits for one.
    fn hold(&mut self, mut chunk: Bytes) {
        self.held_insert = false;
        if let Some(f) = &mut self.framing {
            let waiting = !lock(f.inserts).queue.is_empty();
            let n = f.scan.scan(&chunk, waiting);
            if n < chunk.len() {
                f.unscanned = Some(chunk.split_off(n));
            }
        }
        self.held = Some(chunk);
    }

    /// With framing and nothing in hand: takes the next thing to write in
    /// hand (the rest of an inserted capsule, a capsule waiting for the
    /// boundary reached, the bytes read past it); whether there was one.
    fn load_framed(&mut self) -> bool {
        let Some(f) = &mut self.framing else {
            return false;
        };
        if let Some(tail) = f.tail.take() {
            self.held = Some(tail);
            self.held_insert = true;
            return true;
        }
        if f.scan.at_boundary() {
            let mut q = lock(f.inserts);
            if let Some((header, payload)) = q.queue.pop_front() {
                q.bytes -= header.len() + payload.len();
                drop(q);
                f.insert_len = payload.len();
                f.tail = (!payload.is_empty()).then_some(payload);
                self.held = Some(header);
                self.held_insert = true;
                return true;
            }
        }
        if let Some(rest) = f.unscanned.take() {
            self.hold(rest);
            return true;
        }
        false
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
                if !self.held_insert {
                    self.took(n);
                } else if self.held.is_none() {
                    self.held_insert = false;
                    if let Some(f) = &self.framing
                        && f.tail.is_none()
                    {
                        // The inserted capsule was written whole.
                        charge(self.limiter, f.insert_len);
                        let mut q = lock(f.inserts);
                        q.sent += 1;
                        q.sent_bytes += f.insert_len as u64;
                    }
                }
            }
            Poll::Ready(Err(e)) => self.downstream_failed(&e),
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
                self.downstream_failed(&e);
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
                self.upstream_failed(&e);
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
        self.close_inserts();
        // Reads the end (nothing is left before it).
        let _ = self.r.poll_read_chunk(waker, 1);
        match self.w.finish_shared() {
            Ok(()) | Err(StreamError::ClosedLocally) => {
                self.phase = Phase::Done(SpliceEnd::Finished);
            }
            Err(e) => self.downstream_failed(&e),
        }
    }

    /// `r` was reset with `code` and Reliable Size `reliable` (in
    /// application bytes).
    fn on_reset(&mut self, code: VarInt, reliable: u64) {
        self.close_inserts();
        self.phase = Phase::Reliable { code, reliable };
    }

    /// No more capsules are queued: they would never be written.
    fn close_inserts(&mut self) {
        if let Some(f) = &self.framing {
            lock(f.inserts).closed = true;
        }
    }

    /// Forwards the bytes below the Reliable Size as `w`'s credit allows
    /// (a relay forwards data only within the next hop's credit), then
    /// marks the reliable boundary after them and resets `w`; with nothing
    /// left to forward, at once. The wait for credit ends early only when
    /// `w` ends.
    fn reliable(&mut self, waker: &Waker, code: VarInt, reliable: u64) -> Poll<()> {
        // An inserted capsule is completed, so that the bytes delivered stay
        // whole capsules; none is started.
        if self.held.is_some() && self.held_insert {
            return self.write_held(waker);
        }
        if let Some(f) = &mut self.framing {
            if let Some(tail) = f.tail.take() {
                self.held = Some(tail);
                self.held_insert = true;
                return self.write_held(waker);
            }
            if self.held.is_none() {
                self.held = f.unscanned.take();
            }
        }
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
                    self.downstream_failed(&e);
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
                    self.upstream_failed(&e);
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

    /// Without `RESET_STREAM_AT`: the reset once the forwarded bytes were
    /// passed to the carrier.
    fn flush(&mut self, waker: &Waker, code: VarInt) -> Poll<()> {
        match self.w.poll_sent(waker) {
            Poll::Ready(Ok(())) => self.reset_downstream(code),
            Poll::Ready(Err(e)) => self.downstream_failed(&e),
            Poll::Pending => return Poll::Pending,
        }
        Poll::Ready(())
    }

    fn reset_downstream(&mut self, code: VarInt) {
        let _ = self.w.reset_shared(code);
        self.phase = Phase::Done(SpliceEnd::Reset(code));
    }

    /// The splice was aborted with `code`: both parts end with it, and
    /// what the direction holds is released.
    fn abort(&mut self, code: VarInt) {
        let _ = self.w.reset_shared(code);
        let _ = self.r.stop_shared(code);
        self.close_inserts();
        self.phase = Phase::Done(SpliceEnd::Cancelled(code));
        let _ = self.poll(&mut Context::from_waker(Waker::noop()));
    }

    /// `r` ended other than by a FIN or a reset seen as such.
    fn upstream_failed(&mut self, e: &StreamError) {
        let (c, end) = match *e {
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
    fn downstream_failed(&mut self, e: &StreamError) {
        let (c, end) = match *e {
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
