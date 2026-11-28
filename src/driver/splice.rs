//! Splicing two bidirectional streams into each other: how a relay connects an
//! inbound stream to an outbound one, whether the streams carry application
//! data or a nested session's pipe.
//!
//! Each direction, from a receiving part `r` to a sending part `w`, waits
//! for `w`'s send capacity with `min` = m = min(chunk, the bytes readable
//! on `r`, 16 KiB) ([`SendStream::poll_send_capacity`]: woken once
//! per chunk, not on every credit change, and never stalled by a peer
//! window smaller than m); with a limiter for the direction, waits until
//! `r` is readable without consuming anything and then asks it for
//! `acquire(1, k)`, k = min(the bytes readable, capacity, chunk); takes at
//! most the grant from `r` as a chunk and hands it to `w` without copying;
//! and refunds the limiter what it granted and was not forwarded. A
//! limiter that fails ends the direction ([`SpliceEnd::LimiterFailed`]).
//! Every wait
//! also watches both parts, so that an end or an error never waits behind
//! capacity: the waits register the task with `r` (data, FIN, reset, the
//! session's end) and with `w` (`STOP_SENDING`, the session's end) at once.
//!
//! The static byte splice holds at most one chunk per direction, between the read and the
//! moment `w` takes it; the backlog stays in `r`'s receive buffer, where
//! the stream's window bounds it. Nothing runs outside the caller's task
//! and no lock is held across a wait: dropping the future ends both streams
//! with code 0, releases the chunks and leaves nothing behind. A direction
//! that keeps finding data yields after 1 MiB (or 256 steps) in one poll,
//! so that it holds neither the other direction nor the executor.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use crate::helpers::SpliceHandoffs;
use crate::proto::limit::Permit;
use crate::proto::session::splice_handoff::Prepayment;

use super::handle::{Upstream, WaitSlot};
use crate::proto::limit::Limiter;
use crate::proto::session::StreamError;
use crate::proto::{ApplicationErrorCode, VarInt};
use crate::{RecvStream, SendStream};

mod control;
mod hooks;
mod mirror;
mod permit;
mod relay;

pub use control::{
    SpliceCommandError, SpliceControl, SpliceController, SpliceDisposition, SpliceDropReason,
    SpliceEvent, SpliceEventSink, SpliceInjection, SpliceInjectionStatus, SplicePause,
    SpliceReceipt,
};
pub use hooks::{
    SpliceBudget, SpliceDecision, SpliceEditor, SpliceHook, SpliceHooks, SpliceKind, SpliceLimits,
    SpliceMeta, SplicePayloads, SpliceRoute, SpliceSignal, SpliceUnit, SpliceWait,
};
pub use mirror::{SpliceMirror, SpliceMirrorMode, SpliceMirrorReceiver, SpliceSample};
pub use relay::{controlled_splice, controlled_splice_packets};

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
    /// Local outgoing datagram settings on the A to B hop.
    pub a_to_b_datagrams: crate::DatagramSendOptions,
    /// Local outgoing datagram settings on the B to A hop.
    pub b_to_a_datagrams: crate::DatagramSendOptions,
    /// Ends the splice with a chosen code when aborted ([`SpliceAbort`]).
    pub abort: Option<SpliceAbort>,
    /// Maximum payload size of a datagram or DATAGRAM capsule.
    pub max_packet_payload: usize,
    /// Maximum Value size of an opaque reliable capsule.
    pub max_opaque_value: usize,
}

impl Default for SpliceOptions {
    fn default() -> Self {
        Self {
            chunk: CHUNK,
            a_to_b: None,
            b_to_a: None,
            a_to_b_datagrams: crate::DatagramSendOptions::default(),
            b_to_a_datagrams: crate::DatagramSendOptions::default(),
            abort: None,
            max_packet_payload: crate::helpers::DEFAULT_MAX_PACKET,
            max_opaque_value: crate::helpers::DEFAULT_MAX_PACKET,
        }
    }
}

impl fmt::Debug for SpliceOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpliceOptions")
            .field("chunk", &self.chunk)
            .field("a_to_b", &self.a_to_b.is_some())
            .field("b_to_a", &self.b_to_a.is_some())
            .field("a_to_b_datagrams", &self.a_to_b_datagrams)
            .field("b_to_a_datagrams", &self.b_to_a_datagrams)
            .field("abort", &self.abort)
            .field("max_packet_payload", &self.max_packet_payload)
            .field("max_opaque_value", &self.max_opaque_value)
            .finish()
    }
}

/// Options for a splice with an attachable direction controller.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ControlledSpliceOptions {
    /// Forwarding and capsule bounds shared with the static entry.
    pub forwarding: SpliceOptions,
    /// Initial chain from the first stream to the second.
    pub a_to_b_hooks: SpliceHooks,
    /// Initial chain from the second stream to the first.
    pub b_to_a_hooks: SpliceHooks,
    /// Budgets for queued output, transformation and control.
    pub limits: SpliceLimits,
    /// Application label for the A to B route.
    pub a_to_b_label: Arc<str>,
    /// Application label for the B to A route.
    pub b_to_a_label: Arc<str>,
    /// Optional diagnostics for A to B inputs.
    pub a_to_b_mirror: Option<SpliceMirror>,
    /// Optional diagnostics for B to A inputs.
    pub b_to_a_mirror: Option<SpliceMirror>,
    /// Optional observer for the ordered events of each direction.
    pub events: Option<SpliceEventSink>,
}

impl SpliceOptions {
    fn resolve(
        &self,
        packets: bool,
        limits: SpliceLimits,
    ) -> Result<hooks::ResolvedLimits, SpliceError> {
        use crate::helpers::capsule::MAX_WIRE_HEADER;

        let invalid = SpliceError::InvalidOptions;
        let max_value = crate::util::usize_sat(crate::VarInt::MAX.into_inner());
        if self.chunk == 0
            || self.max_packet_payload == 0
            || self.max_opaque_value == 0
            || self.max_packet_payload > max_value.saturating_sub(8)
            || self.max_opaque_value > max_value
        {
            return Err(invalid);
        }
        let unit = if packets {
            self.max_packet_payload
                .checked_add(MAX_WIRE_HEADER)
                .zip(self.max_opaque_value.checked_add(16))
                .map(|(datagram, opaque)| datagram.max(opaque))
                .ok_or(invalid)?
        } else {
            self.chunk.max(self.max_packet_payload)
        };
        let limits = limits.resolve(unit).ok_or(invalid)?;
        let burst = u64::try_from(limits.group_bytes).map_err(|_| invalid)?;
        for limiter in [&self.a_to_b, &self.b_to_a].into_iter().flatten() {
            let declared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                limiter.max_burst_bytes()
            }));
            if !matches!(declared, Ok(Some(max)) if max >= burst) {
                return Err(invalid);
            }
        }
        Ok(limits)
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
    /// The direction's limiter failed (its error, a panic or a grant
    /// outside its contract): the downstream part was reset and the
    /// upstream part stopped with `ZMUX_CANCELLED`.
    LimiterFailed,
    /// A hook deliberately reset this direction with an application code.
    HookReset(VarInt),
    /// A hook panicked, failed or violated the output budget.
    HookFailed,
    /// A malformed capsule ended the direction.
    PacketError,
    /// A reliable unit expired before it could be released.
    WaitTimeout,
}

impl SpliceEnd {
    /// The stable end reason used in comparable observations.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Finished => "finished",
            Self::Reset(_) => "reset",
            Self::Stopped(_) => "stopped",
            Self::UpstreamLost => "upstream_lost",
            Self::DownstreamLost => "downstream_lost",
            Self::Cancelled(_) => "cancelled",
            Self::LimiterFailed => "limiter_failed",
            Self::HookReset(_) => "hook_reset",
            Self::HookFailed => "hook_failed",
            Self::PacketError => "packet_error",
            Self::WaitTimeout => "wait_timeout",
        }
    }

    /// Application code carried by this end, if present.
    #[must_use]
    pub const fn application_code(self) -> Option<VarInt> {
        match self {
            Self::Reset(code)
            | Self::Stopped(code)
            | Self::Cancelled(code)
            | Self::HookReset(code) => Some(code),
            _ => None,
        }
    }
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
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SpliceDirection {
    /// Stream bytes forwarded: read from the upstream part and taken by the
    /// downstream part.
    pub bytes: u64,
    /// Payload bytes of the stream datagrams forwarded.
    pub datagram_bytes: u64,
    /// Stream datagrams a packet relay forwarded as DATAGRAM capsules on
    /// the downstream stream because they did not fit a datagram there,
    /// counted once written whole; counted in `datagram_bytes` too.
    /// Always 0 for [`splice`].
    pub datagrams_as_capsules: u64,
    /// Inputs admitted on the transformation/control path.
    pub input_units: u64,
    /// Input payload bytes admitted on the transformation/control path.
    pub input_bytes: u64,
    /// Complete outputs admitted to the target.
    pub enqueued_items: u64,
    /// Chain steps that replaced an input group.
    pub replacements: u64,
    /// Pre-publication datagram drops by reason.
    pub drops: SpliceDrops,
    /// Samples the diagnostic consumer's queue could not accept.
    pub mirror_misses: u64,
    /// Total time spent waiting on hook readiness, in microseconds.
    pub wait_us: u64,
    /// Complete capsules accepted by the target stream.
    pub capsule_count: u64,
    /// Bytes accepted into the target, including capsule headers.
    pub accepted_bytes: u64,
    /// Live target settlement when tracking is active for this direction.
    pub handoffs: Option<SpliceHandoffs>,
    /// Bytes actually copied while transferring payloads.
    pub payload_copy_bytes: u64,
    /// Bytes written into new capsule headers.
    pub encode_bytes: u64,
    /// Bytes copied to independent mirror storage.
    pub mirror_copy_bytes: u64,
    /// Bytes refunded before transfer to the target.
    pub pre_admission_refunded_bytes: u64,
    /// How the direction ended.
    pub end: SpliceEnd,
    /// The local group bound failed, if it caused the direction to end.
    pub cause: Option<SpliceBudget>,
}

/// Counts of discarded datagram groups by their pre-publication reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpliceDrops {
    /// Discarded by a hook.
    pub dropped_hook: u64,
    /// Reached a deadline.
    pub dropped_expired: u64,
    /// A bounded queue had no room.
    pub dropped_queue_full: u64,
    /// A limiter refused the exact grant.
    pub dropped_limiter: u64,
    /// Temporary unavailability.
    pub dropped_blocked: u64,
    /// Size was unrepresentable.
    pub dropped_too_large: u64,
    /// No permitted representation was structurally available.
    pub dropped_no_path: u64,
    /// The target exhausted its sequence space.
    pub dropped_sequence_exhausted: u64,
    /// The owning flow closed.
    pub dropped_flow_closed: u64,
    /// The core delay controller discarded the datagram.
    pub dropped_codel: u64,
}

impl SpliceDrops {
    fn count(&mut self, reason: SpliceDropReason) {
        let counter = match reason {
            SpliceDropReason::Hook => &mut self.dropped_hook,
            SpliceDropReason::Expired => &mut self.dropped_expired,
            SpliceDropReason::QueueFull => &mut self.dropped_queue_full,
            SpliceDropReason::Limiter => &mut self.dropped_limiter,
            SpliceDropReason::Blocked => &mut self.dropped_blocked,
            SpliceDropReason::TooLarge => &mut self.dropped_too_large,
            SpliceDropReason::NoPath => &mut self.dropped_no_path,
            SpliceDropReason::SequenceExhausted => &mut self.dropped_sequence_exhausted,
            SpliceDropReason::FlowClosed => &mut self.dropped_flow_closed,
            SpliceDropReason::Codel => &mut self.dropped_codel,
        };
        *counter += 1;
    }

    /// All discarded datagram groups.
    #[must_use]
    pub fn total(self) -> u64 {
        self.dropped_hook
            + self.dropped_expired
            + self.dropped_queue_full
            + self.dropped_limiter
            + self.dropped_blocked
            + self.dropped_too_large
            + self.dropped_no_path
            + self.dropped_sequence_exhausted
            + self.dropped_flow_closed
            + self.dropped_codel
    }
}

/// The result of a splice: each direction's counts and end.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SpliceResult {
    /// From `a` to `b`.
    pub a_to_b: SpliceDirection,
    /// From `b` to `a`.
    pub b_to_a: SpliceDirection,
}

/// Why a splice was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpliceError {
    /// A direction would forward a stream into itself.
    SameStream,
    /// The chunk, hook lists or budgets are invalid for this splice mode.
    InvalidOptions,
}

impl fmt::Display for SpliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameStream => f.write_str("a stream cannot be spliced into itself"),
            Self::InvalidOptions => f.write_str("invalid_parameter"),
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
/// Use [`controlled_splice`] to install a transformation chain or control
/// admissions at runtime.
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
/// | the direction's limiter fails | reset downstream and stop upstream with `ZMUX_CANCELLED`; the result reports [`SpliceEnd::LimiterFailed`] |
///
/// Stream datagrams are forwarded to the other stream with their context,
/// without waiting and without a queue of the helper's own: the
/// direction's limiter grants the whole payload (`try_acquire(n, n)`) or
/// the datagram is dropped, then the other session's datagram limiter and send queue take
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
/// A direction forwards a stream to itself, or the supplied options are invalid.
pub async fn splice(
    a: (SendStream, RecvStream),
    b: (SendStream, RecvStream),
    opts: SpliceOptions,
) -> Result<SpliceResult, SpliceError> {
    relay::validate_halves(&a, &b)?;
    opts.resolve(false, SpliceLimits::default())?;
    splice_transparent(a, b, opts).await
}

/// [`splice`] for two packet streams (EXTENSIONS.md Section 12): the
/// relay of [`PacketStream`](crate::helpers::PacketStream)s. Ends,
/// limiters and results are those of [`splice`]; what differs is how
/// packets cross:
///
/// Capsules preserve their boundaries, including unknown types. Stream
/// datagrams may be converted to DATAGRAM capsules at a reliable boundary
/// when the next hop does not support their datagram representation.
///
/// A limiter reserves exactly the encoded size of each reliable capsule.
/// Datagram admission uses a nonblocking exact reservation. A capsule
/// received reliably remains reliable.
///
/// # Errors
///
/// As [`splice`].
pub async fn splice_packets(
    a: (SendStream, RecvStream),
    b: (SendStream, RecvStream),
    opts: SpliceOptions,
) -> Result<SpliceResult, SpliceError> {
    relay::run_static(a, b, opts).await
}

async fn splice_transparent(
    (a_send, a_recv): (SendStream, RecvStream),
    (b_send, b_recv): (SendStream, RecvStream),
    opts: SpliceOptions,
) -> Result<SpliceResult, SpliceError> {
    let ab_handoffs = opts.a_to_b.as_ref().map(|_| SpliceHandoffs::default());
    let ba_handoffs = opts.b_to_a.as_ref().map(|_| SpliceHandoffs::default());
    let mut ab = Direction::new(
        &a_recv,
        &b_send,
        opts.a_to_b.as_ref(),
        ab_handoffs.as_ref(),
        opts.chunk,
    );
    let mut ba = Direction::new(
        &b_recv,
        &a_send,
        opts.b_to_a.as_ref(),
        ba_handoffs.as_ref(),
        opts.chunk,
    );
    let mut ab_datagrams = Datagrams::default();
    let mut ba_datagrams = Datagrams::default();
    let (ab_end, ba_end) = {
        let mut dg_ab = pin!(forward_datagrams(
            &a_recv,
            &b_send,
            opts.a_to_b.as_ref().zip(ab_handoffs.as_ref()),
            opts.a_to_b_datagrams,
            opts.max_packet_payload,
            &mut ab_datagrams,
        ));
        let mut dg_ba = pin!(forward_datagrams(
            &b_recv,
            &a_send,
            opts.b_to_a.as_ref().zip(ba_handoffs.as_ref()),
            opts.b_to_a_datagrams,
            opts.max_packet_payload,
            &mut ba_datagrams,
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
            // The directions and their datagram readers share this task.
            for (done, dg) in [
                (&mut dg_ab_done, dg_ab.as_mut()),
                (&mut dg_ba_done, dg_ba.as_mut()),
            ] {
                if !*done && dg.poll(cx).is_ready() {
                    *done = true;
                }
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
    Ok(SpliceResult {
        a_to_b: ab_datagrams.result(ab.bytes, ab_end, ab_handoffs.clone()),
        b_to_a: ba_datagrams.result(ba.bytes, ba_end, ba_handoffs.clone()),
    })
}

/// The datagrams of one direction.
#[derive(Default)]
struct Datagrams {
    bytes: u64,
    drops: SpliceDrops,
}

impl Datagrams {
    /// With what the direction wrote of the capsules queued in `inserts`.
    fn result(
        &self,
        bytes: u64,
        end: SpliceEnd,
        handoffs: Option<SpliceHandoffs>,
    ) -> SpliceDirection {
        SpliceDirection {
            bytes,
            datagram_bytes: self.bytes,
            // Only those dropped for their size: a capsule that could not be
            // written for another reason is only dropped.
            datagrams_as_capsules: 0,
            input_units: 0,
            input_bytes: 0,
            enqueued_items: 0,
            replacements: 0,
            drops: self.drops,
            mirror_misses: 0,
            wait_us: 0,
            capsule_count: 0,
            accepted_bytes: bytes + self.bytes,
            handoffs,
            end,
            cause: None,
            payload_copy_bytes: 0,
            encode_bytes: 0,
            mirror_copy_bytes: 0,
            pre_admission_refunded_bytes: 0,
        }
    }
}

/// Forward stream datagrams on a transparent byte splice.
async fn forward_datagrams(
    r: &RecvStream,
    w: &SendStream,
    prepaid: Option<(&Arc<dyn Limiter>, &SpliceHandoffs)>,
    options: crate::DatagramSendOptions,
    max_packet_payload: usize,
    count: &mut Datagrams,
) {
    while let Ok(crate::StreamDatagram { context, payload }) = r.read_datagram().await {
        if payload.len() > max_packet_payload {
            count.drops.count(SpliceDropReason::TooLarge);
            continue;
        }
        let len = payload.len() as u64;
        let result = if let Some((limiter, handoffs)) = prepaid {
            forward_prepaid_datagram(w, limiter, handoffs, context, &payload, options)
        } else {
            w.send_datagram_with(context, payload, options)
        };
        match result {
            Ok(()) => count.bytes += len,
            Err(error) => count.drops.count(SpliceDropReason::from_datagram(&error)),
        }
    }
}

fn forward_prepaid_datagram(
    w: &SendStream,
    limiter: &Arc<dyn Limiter>,
    handoffs: &SpliceHandoffs,
    context: u64,
    payload: &bytes::Bytes,
    options: crate::DatagramSendOptions,
) -> Result<(), crate::DatagramError> {
    let options = w.resolve_splice_datagram_options(options, w.packet_clock().now())?;
    let len = payload.len() as u64;
    let mut grant = Permit::try_acquire(&**limiter, len, len);
    let refused = crate::DatagramError::Dropped(crate::DatagramDrop::Limiter);
    if len != 0 && grant.is_none() {
        return Err(refused);
    }
    let mut allowance = w.datagram_allowance(payload.len());
    if !allowance.allowed() {
        return Err(refused);
    }
    let mut payment = Prepayment::new(
        handoffs,
        grant
            .as_mut()
            .map(|grant| (limiter, grant.prepaid_remaining())),
    );
    w.commit_datagram_group(
        context,
        std::slice::from_ref(payload),
        options,
        crate::helpers::SendPolicy::DatagramOnly,
        Some(&mut payment),
    )?;
    allowance.commit();
    Ok(())
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
    /// This direction's waits on `r` and `w`.
    r_wait: WaitSlot<'a, super::tokio::Tokio>,
    w_wait: WaitSlot<'a, super::tokio::Tokio>,
    limiter: Option<&'a Arc<dyn Limiter>>,
    handoffs: Option<&'a SpliceHandoffs>,
    chunk: usize,
    /// A chunk read from `r` that `w` has not taken whole.
    held: Option<crate::Chunk>,
    pending_grant: Option<Permit<'a>>,
    /// Bytes `w` took.
    bytes: u64,
    phase: Phase,
}

impl<'a> Direction<'a> {
    fn new(
        r: &'a RecvStream,
        w: &'a SendStream,
        limiter: Option<&'a Arc<dyn Limiter>>,
        handoffs: Option<&'a SpliceHandoffs>,
        chunk: usize,
    ) -> Self {
        Self {
            r,
            w,
            r_wait: r.wait_slot(),
            w_wait: w.wait_slot(),
            limiter,
            handoffs,
            chunk,
            held: None,
            pending_grant: None,
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
                    self.held = None;
                    self.pending_grant = None;
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
        let readable = match self.r.poll_upstream(waker, &mut self.r_wait.ticket) {
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
        let capacity = match self.poll_write_capacity(waker, m) {
            Poll::Ready(Some(capacity)) => capacity,
            Poll::Ready(None) => return Poll::Ready(()),
            Poll::Pending => return Poll::Pending,
        };
        let max = capacity.min(self.chunk).min(readable);
        let permit = if let Some(limiter) = self.limiter {
            match Permit::poll_acquire(&**limiter, &mut Context::from_waker(waker), 1, max as u64) {
                Poll::Ready(Ok(p)) => Some(p),
                Poll::Ready(Err(_)) => {
                    self.limiter_failed();
                    return Poll::Ready(());
                }
                Poll::Pending => return self.watch_downstream(waker),
            }
        } else {
            None
        };
        let allowed = permit
            .as_ref()
            .map_or(max, |p| usize::try_from(p.len()).unwrap_or(usize::MAX));
        let taken = self
            .r
            .poll_take_chunk(waker, &mut self.r_wait.ticket, allowed);
        match taken {
            Poll::Ready(Ok(Some(chunk))) => {
                self.held = Some(chunk);
                self.pending_grant = permit;
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

    /// Hands the chunk in hand to `w`; `Pending` (the writer registered)
    /// while `w` takes nothing.
    fn write_held(&mut self, waker: &Waker) -> Poll<()> {
        let Some(held) = &mut self.held else {
            return Poll::Ready(());
        };
        let mut payment = self.handoffs.map(|handoffs| {
            let grant = self
                .limiter
                .zip(self.pending_grant.as_mut())
                .map(|(origin, grant)| (origin, grant.prepaid_remaining()));
            Prepayment::new(handoffs, grant)
        });
        let output = self.w.poll_write_part_before(
            waker,
            &mut self.w_wait.ticket,
            held,
            None,
            payment.as_mut(),
        );
        match output {
            Poll::Ready(Ok(n)) => {
                self.bytes += n.expect("write without a deadline") as u64;
                if held.is_empty() {
                    self.held = None;
                    self.pending_grant = None;
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
        match self.w.watch(waker, &mut self.w_wait.ticket) {
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
        match self.r.watch(waker, &mut self.r_wait.ticket) {
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

    /// The FIN was read: consume it and finish `w`.
    fn forward_fin(&mut self, waker: &Waker) {
        // Reads the end (nothing is left before it).
        let _ = self.r.poll_read_chunk(waker, &mut self.r_wait.ticket, 1);
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
        self.phase = Phase::Reliable { code, reliable };
    }

    /// Forwards the bytes below the Reliable Size as `w`'s credit allows
    /// (a relay forwards data only within the next hop's credit), then
    /// marks the reliable boundary after them and resets `w`; with nothing
    /// left to forward, at once. The wait for credit ends early only when
    /// `w` ends.
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
            let capacity = match self.poll_write_capacity(waker, m) {
                Poll::Ready(Some(capacity)) => capacity,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            };
            match self.r.poll_read_chunk(
                waker,
                &mut self.r_wait.ticket,
                capacity.min(self.chunk).min(need),
            ) {
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
        self.pending_grant = None;
        if reliable > 0 {
            // The bytes forwarded stay reliable downstream, in `w`'s
            // offsets (its preamble included): everything below the
            // upstream Reliable Size, and possibly more. Towards a peer
            // without RESET_STREAM_AT, they are passed to the carrier
            // before the RESET_STREAM.
            let _ = self.w.set_reliable_boundary_shared(None);
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
        match self.w.poll_sent(waker, &mut self.w_wait.ticket, None) {
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
        self.phase = Phase::Done(SpliceEnd::Cancelled(code));
        let _ = self.poll(&mut Context::from_waker(Waker::noop()));
    }

    /// The limiter failed: the direction ends as if cancelled, both parts
    /// reset and stopped with `ZMUX_CANCELLED`.
    fn limiter_failed(&mut self) {
        let c = code(ApplicationErrorCode::ZMUX_CANCELLED);
        let _ = self.w.reset_shared(c);
        let _ = self.r.stop_shared(c);
        self.phase = Phase::Done(SpliceEnd::LimiterFailed);
    }

    /// `r` ended other than by a FIN or a reset seen as such.
    fn upstream_failed(&mut self, e: &StreamError) {
        let (end, c) = upstream_end(e);
        let _ = self.w.reset_shared(c);
        self.phase = Phase::Done(end);
    }

    /// `w` ended: stopped by its peer, refused, or its session ended.
    fn poll_write_capacity(&mut self, waker: &Waker, min: usize) -> Poll<Option<usize>> {
        match self
            .w
            .poll_capacity_with(waker, &mut self.w_wait.ticket, min as u64)
        {
            Poll::Ready(Ok(room)) => Poll::Ready(Some(crate::util::usize_sat(room))),
            Poll::Ready(Err(error)) => {
                self.downstream_failed(&error);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn downstream_failed(&mut self, e: &StreamError) {
        let (end, c) = downstream_end(e);
        let _ = self.r.stop_shared(c);
        self.phase = Phase::Done(end);
    }
}

fn upstream_end(e: &StreamError) -> (SpliceEnd, VarInt) {
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
    (end, c)
}

fn downstream_end(e: &StreamError) -> (SpliceEnd, VarInt) {
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
    (end, c)
}
