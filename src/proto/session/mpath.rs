//! Multipath (MULTIPATH.md): pipe identifiers and the replay window,
//! joining, removal, failure detection and retirement. Acknowledgements and
//! reinjection are in `ack.rs`, scheduling in `sched.rs`, resume in
//! `resume.rs`.

use std::time::{Duration, Instant};

use bytes::Bytes;

use super::pipes::{
    Attachment, InPipe, InState, OutPipe, OutState, PipeHalf, PipeState, PrioritySource,
};
use super::{
    CloseFrame, CoreEvent, LaneId, PipeEnd, PipeFailure, PipeId, SessionCore, SessionError, State,
    StreamKey,
};
use crate::proto::codec::Writer;
use crate::proto::frame::{JoinDirection, PipeJoin};
use crate::proto::keys::{self, SessionKeys};
use crate::proto::params::{Locator, Role, TransportParameters};
use crate::proto::record::Framing;
use crate::proto::{Error, TransportErrorCode as T, VarInt};

/// The idle-pipe probe interval of attachments without an outbound
/// direction at the peer, and the default of `probe_interval`
/// (MULTIPATH.md Section 7.1).
pub(super) const PROBE_INTERVAL: Duration = Duration::from_secs(15);
/// The busy window: a session that sent or received a traffic frame within
/// it, or was established within it, probes its backup pipes every
/// `standby_probe` (MULTIPATH.md Section 7.1).
pub(super) const BUSY_WINDOW: Duration = Duration::from_secs(15);
/// The acknowledgement redundancy interval (MULTIPATH.md Section 6.5).
pub(super) const ACK_COPY_INTERVAL: Duration = Duration::from_millis(50);

/// One write call on an outbound pipe, as the driver reports it with
/// [`SessionCore::pipe_write`]: whatever the
/// driver's style, the core learns of a pipe's write progress from these
/// reports only. A driver that writes with blocking calls reports each call
/// when it starts and when it returns; one that writes when its carrier is
/// writable reports its calls when they return, refused when the carrier
/// took less than it was offered (it is not writable then).
///
/// ```
/// use std::time::Instant;
/// use zmux::proto::session::PipeWrite;
///
/// let start = Instant::now();
/// // A blocking call of 16 KiB: in progress, then returned.
/// let call = PipeWrite::started(start, 16 * 1024);
/// assert_eq!(call.end, None);
/// let done = PipeWrite::returned(start, Instant::now(), 16 * 1024, 0, false);
/// assert!(!done.refused);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PipeWrite {
    /// When the call started.
    pub start: Instant,
    /// When it returned; `None` while it is in progress.
    pub end: Option<Instant>,
    /// The bytes the carrier took; while the call is in progress, the bytes
    /// it was handed.
    pub bytes: u64,
    /// U: what the carrier still holds unsent when the call returned (its
    /// unsent count; for a non-blocking carrier with a low-water mark, up
    /// to that mark plus what the call added; 0 for a blocking adapter,
    /// whose call returns once the bytes are handed on, MULTIPATH.md
    /// Section 7.1).
    pub unsent: u64,
    /// The carrier refused bytes: it takes more only once it drains.
    pub refused: bool,
}

impl PipeWrite {
    /// A call handed `bytes` at `start` and has not returned.
    pub fn started(start: Instant, bytes: u64) -> Self {
        Self {
            start,
            end: None,
            bytes,
            unsent: 0,
            refused: false,
        }
    }

    /// A call that ran from `start` to `end`: the carrier took `bytes`,
    /// held `unsent` unsent then, and `refused` the rest.
    pub fn returned(start: Instant, end: Instant, bytes: u64, unsent: u64, refused: bool) -> Self {
        Self {
            start,
            end: Some(end),
            bytes,
            unsent,
            refused,
        }
    }
}

/// Whether multipath is in use, and why not (MULTIPATH.md Section 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Multipath {
    /// This endpoint did not offer it (`max_pipes` 1 and no resume), or the
    /// session is not established yet.
    #[default]
    Off,
    /// In use: pipes can be added and resumption works when configured.
    InUse,
    /// The peer did not offer it (a plain QMux peer, or a zmux peer
    /// configured without multipath).
    PeerDeclined,
    /// Both endpoints offered it, but no secret source of `pipe_auth`
    /// matched (for example one offers only a PSK and the other only the
    /// TLS exporter, or the bootstrap carrier has no exporter).
    JoinSecurityUnavailable,
}

/// Per-pipe options: fields for each direction, and
/// chained setters, of which [`PipeOptions::with_priority`] and
/// [`PipeOptions::with_standby`] set both directions at once.
///
/// ```
/// use zmux::PipeOptions;
///
/// // A relay pipe as the fallback: used only while the preferred pipes are
/// // saturated or have failed, and the peer is asked to do the same.
/// let relay = PipeOptions::new().with_priority(10).with_label("relay");
/// assert_eq!((relay.send_priority, relay.receive_priority), (Some(10), 10));
/// assert_eq!(relay.weight, 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PipeOptions {
    /// Fate group; 0 means independent (MULTIPATH.md Section 2.2).
    pub fate_group: u64,
    /// The tier of the local outbound direction, lower preferred; `None`
    /// follows the peer's request, else
    /// 0.
    pub send_priority: Option<u64>,
    /// The tier requested for the peer's outbound direction, sent as
    /// PIPE_STATUS with the join when not 0.
    pub receive_priority: u64,
    /// The local outbound direction takes data only on failover; `None`
    /// follows the peer's request, else available.
    pub send_standby: Option<bool>,
    /// Asks the peer to use its outbound direction only on failover, with
    /// PIPE_STATUS sent with the join.
    pub receive_standby: bool,
    /// The outbound direction's share for `spread-round-robin` and factor
    /// for `spread-rate-weighted`.
    pub weight: u64,
    /// The base of the pipe's probation; `None` for the session default,
    /// zero disables probation.
    pub probation: Option<Duration>,
    /// The floor of T_suspect for this pipe (at least 50 ms); the session
    /// default when `None`.
    pub suspect_floor: Option<Duration>,
    /// Replaces the stall limit of the last usable pipe (at least 1 s).
    pub dead_timeout: Option<Duration>,
    /// The application's name for the pipe, reported by its statistics
    /// (local, never sent).
    pub label: Option<std::sync::Arc<str>>,
}

impl PipeOptions {
    /// The defaults: tier 0 both ways, available, weight 1.
    pub fn new() -> Self {
        Self::default()
    }

    /// The tier of both directions: this endpoint's outbound direction,
    /// and the one requested of the peer for its outbound direction.
    #[must_use]
    pub fn with_priority(mut self, priority: u64) -> Self {
        self.send_priority = Some(priority);
        self.receive_priority = priority;
        self
    }

    /// Standby (data only on failover) for both directions, as
    /// [`PipeOptions::with_priority`].
    #[must_use]
    pub fn with_standby(mut self, standby: bool) -> Self {
        self.send_standby = Some(standby);
        self.receive_standby = standby;
        self
    }

    /// The tier of this endpoint's outbound direction only.
    #[must_use]
    pub fn with_send_priority(mut self, priority: u64) -> Self {
        self.send_priority = Some(priority);
        self
    }

    /// The tier requested of the peer for its outbound direction only.
    #[must_use]
    pub fn with_receive_priority(mut self, priority: u64) -> Self {
        self.receive_priority = priority;
        self
    }

    /// Standby for this endpoint's outbound direction only.
    #[must_use]
    pub fn with_send_standby(mut self, standby: bool) -> Self {
        self.send_standby = Some(standby);
        self
    }

    /// Standby requested of the peer for its outbound direction only.
    #[must_use]
    pub fn with_receive_standby(mut self, standby: bool) -> Self {
        self.receive_standby = standby;
        self
    }

    /// The outbound direction's weight.
    #[must_use]
    pub fn with_weight(mut self, weight: u64) -> Self {
        self.weight = weight;
        self
    }

    /// The probation base (zero disables probation).
    #[must_use]
    pub fn with_probation(mut self, probation: Duration) -> Self {
        self.probation = Some(probation);
        self
    }

    /// The fate group: a pipe that replaces a failed one on the same path
    /// reuses its group (MULTIPATH.md Section 2.2).
    #[must_use]
    pub fn with_fate_group(mut self, group: u64) -> Self {
        self.fate_group = group;
        self
    }

    /// The floor of T_suspect (at least 50 ms).
    #[must_use]
    pub fn with_suspect_floor(mut self, floor: Duration) -> Self {
        self.suspect_floor = Some(floor);
        self
    }

    /// The dead timeout (at least 1 s).
    #[must_use]
    pub fn with_dead_timeout(mut self, timeout: Duration) -> Self {
        self.dead_timeout = Some(timeout);
        self
    }

    /// The application's name for the pipe.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<std::sync::Arc<str>>) -> Self {
        self.label = Some(label.into());
        self
    }
}

impl Default for PipeOptions {
    fn default() -> Self {
        Self {
            fate_group: 0,
            send_priority: None,
            receive_priority: 0,
            send_standby: None,
            receive_standby: false,
            weight: 1,
            probation: None,
            suspect_floor: None,
            dead_timeout: None,
            label: None,
        }
    }
}

/// A pipe's quality and settings: a snapshot taken
/// under the core lock. Estimates change as samples arrive; the other
/// fields are exact counts or settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PipeStats {
    /// The pipe ID.
    pub pipe: PipeId,
    /// Whether the local endpoint joined it.
    pub local: bool,
    /// The fate group.
    pub fate_group: u64,
    /// The inbound pipe's state, if the attachment has one.
    pub inbound: Option<PipeState>,
    /// The outbound pipe's state, if the attachment has one.
    pub outbound: Option<PipeState>,
    /// How long the attachment has existed.
    pub attached_for: Duration,
    /// How often the outbound pipe became suspect.
    pub suspect_count: u64,
    /// Whether the attachment failed (0 or 1).
    pub failure_count: u64,
    /// Why it failed, once it did.
    pub failure: Option<PipeFailure>,
    /// The label the application gave it ([`PipeOptions::label`]).
    pub label: Option<std::sync::Arc<str>>,
    /// The effective priority of the outbound direction (lower preferred).
    pub send_priority: u64,
    /// Where it comes from.
    pub send_priority_source: PrioritySource,
    /// The effective standby flag of the outbound direction.
    pub standby: bool,
    /// Where it comes from.
    pub standby_source: PrioritySource,
    /// The priority requested of the peer for its outbound direction.
    pub receive_priority: u64,
    /// Whether the peer is asked to use its direction only on failover.
    pub receive_standby: bool,
    /// The sequence number of the last request sent.
    pub request_seq: u64,
    /// The peer's latest request for the outbound direction.
    pub peer_request: Option<PipeRequest>,
    /// The outbound direction's weight.
    pub weight: u64,
    /// The end of the outbound pipe's probation;
    /// `None` outside probation, or for a configured base so large that it
    /// never ends.
    pub probation_until: Option<Instant>,
    /// In probation.
    pub in_probation: bool,
    /// Awaiting revalidation.
    pub revalidating: bool,
    /// Eligible under tier gating now.
    pub eligible: bool,
    /// Where `smoothed_rtt` and `rttvar` come from;
    /// `None` before the first sample.
    pub rtt_source: Option<RttSource>,
    /// Smoothed RTT of the outbound pipe (estimate); `None` before the
    /// first sample, not the 333 ms default.
    pub smoothed_rtt: Option<Duration>,
    /// Minimum RTT (estimate, SPEC.md Section 8.3 rule 6): the carrier's
    /// minimum when it reports one, otherwise the 300 s minimum of the
    /// samples; `None` before the first.
    pub min_rtt: Option<Duration>,
    /// RTT variation (estimate), when the source measures one.
    pub rttvar: Option<Duration>,
    /// The one-way delay (estimate); needs
    /// acknowledgements.
    pub one_way_delay: Option<Duration>,
    /// Delivery rate R_p in bytes per second (estimate); needs
    /// acknowledgements (absent with a plain QMux peer).
    pub delivery_rate: Option<u64>,
    /// Bytes committed to the outbound pipe and not yet transmitted.
    pub queued_bytes: u64,
    /// queued_bytes / R_p (estimate); needs acknowledgements.
    pub queue_delay: Option<Duration>,
    /// The outbound pipe's carrier takes bytes now.
    pub writable: bool,
    /// The outbound pipe's tier is saturated.
    pub saturated: bool,
    /// Bytes sent and not acknowledged; needs acknowledgements.
    pub bytes_in_flight: Option<u64>,
    /// Bytes sent (the outbound position).
    pub bytes_sent: u64,
    /// Bytes received (the inbound position).
    pub bytes_received: u64,
    /// Bytes acknowledged (the acknowledged outbound position); needs
    /// acknowledgements.
    pub bytes_acked: Option<u64>,
    /// Records sent and received.
    pub records_sent: u64,
    /// Records received.
    pub records_received: u64,
    /// Stream bytes re-sent elsewhere after this pipe failed or became
    /// suspect.
    pub bytes_reinjected: u64,
    /// Duplicate stream bytes received on the inbound pipe.
    pub bytes_duplicate_received: u64,
    /// Opportunistic copies sent on the outbound pipe (MULTIPATH.md
    /// Section 7.5.1).
    pub bytes_opportunistic: u64,
    /// Redundant copies sent on the outbound pipe.
    pub bytes_redundant: u64,
    /// PIPE_PING frames sent, and answered by an acknowledgement.
    pub pings_sent: u64,
    /// PIPE_PING frames answered.
    pub pings_answered: u64,
    /// Since the outbound pipe's acknowledged position last advanced.
    pub since_last_ack: Option<Duration>,
    /// Since the inbound pipe last completed a record.
    pub since_last_receive: Option<Duration>,
    /// The lanes of the outbound and of the inbound direction, lane 0
    /// included (MULTIPATH.md Section 2.5).
    pub lanes_out: u64,
    /// See `lanes_out`.
    pub lanes_in: u64,
    /// Lanes of the outbound direction refused (MULTIPATH.md Section 5.8).
    pub lanes_refused: u64,
    /// The positions of each lane, for a pipe with lanes (empty without:
    /// lane 0 is then the pipe, `bytes_sent`, `bytes_acked` and
    /// `bytes_received`).
    pub lanes: Vec<LaneStats>,
}

/// The positions of one lane of a pipe, in each
/// direction that has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaneStats {
    /// The lane.
    pub lane: super::Lane,
    /// Bytes written on the outbound lane, its first record included.
    pub position_sent: Option<u64>,
    /// The position the peer acknowledged on it.
    pub position_acked: Option<u64>,
    /// The position of the inbound lane.
    pub position_received: Option<u64>,
}

/// Where a pipe's RTT estimates come from: the first
/// available of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RttSource {
    /// PIPE_ACK samples: multipath sessions,
    /// and single-pipe sessions between zmux endpoints (pipe
    /// acknowledgement, MULTIPATH.md Section 3.5).
    Ack,
    /// The carrier's own estimate (`TCP_INFO`), for adapters that report
    /// it.
    Kernel,
    /// QX_PING requests and responses, with the credit-loop samples of
    /// SPEC.md Section 8.3 rule 6: every session, plain QMux peers
    /// included.
    Ping,
}

/// A PIPE_STATUS request (MULTIPATH.md Section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PipeRequest {
    /// The requested priority.
    pub priority: u64,
    /// Standby requested.
    pub standby: bool,
}

/// A pipe's RTT estimates as [`PipeStats`] reports them.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct RttView {
    pub(super) source: Option<RttSource>,
    pub(super) srtt: Option<Duration>,
    pub(super) rttvar: Option<Duration>,
    pub(super) min: Option<Duration>,
    pub(super) latest: Option<Duration>,
}

/// The carrier of a join a listener offered.
#[derive(Debug, Clone, Copy)]
struct JoinCarrier {
    inbound: Option<Framing>,
    outbound: Option<Framing>,
    /// The carrier's first record starts with the PIPE_JOIN.
    inband: bool,
    /// The carrier runs over this session (refused).
    looped: bool,
}

/// What became of a join a listener offered (MULTIPATH.md Section 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinVerdict {
    /// The session is not established yet: hold the carrier and offer the
    /// join again after establishment (or close it at the handshake
    /// timeout).
    Wait,
    /// Close the carrier without writing anything: unknown, replayed, or
    /// the session cannot take joins.
    Reject,
    /// The token did not verify: close the carrier. Reported as
    /// [`CoreEvent::JoinAuthFailed`].
    AuthFailed,
    /// Authenticated but refused (direction, a carrier that runs over the
    /// session, or resources): close the carrier; the session answers with
    /// PIPE_ABANDON.
    Refused,
    /// Authenticated and fatal for the session (parity or credit): close
    /// the carrier; the session is closing.
    Fatal,
    /// Attached. Feed the carrier's bytes (including the record that
    /// carried an in-band PIPE_JOIN) to the session under this pipe ID.
    Accepted(PipeId),
}

/// A local join not sent yet ([`OutState::Deferred`]).
#[derive(Debug)]
pub(crate) struct Deferred {
    id: u64,
    direction: JoinDirection,
    oob: bool,
    /// The new carrier's exporter for a carrier-bound token (empty: none).
    binding: Vec<u8>,
}

/// Session-wide multipath state: the identifiers, keys and joins of this
/// module, and the parts the other modules of the path layer keep, each
/// behind its own operations.
#[derive(Debug)]
pub(crate) struct Mp {
    /// Why the last pipe that failed did (SessionError::PipesLost and
    /// ResumeTimeout report it).
    pub(super) last_failure: Option<PipeFailure>,
    keys: SessionKeys,
    peer_locator: Locator,
    local_locator: Locator,
    resume: bool,
    /// The peer's `zmux_max_ack_delay` (bounds our RTT adjustment).
    peer_mad: Duration,
    /// The local role's parity bit.
    parity: u64,
    /// Our next pipe ID.
    next_id: u64,
    /// The replay window over the peer's pipe IDs (MULTIPATH.md Section
    /// 4.3).
    replay: ReplayWindow,
    /// Our joins refused with ZMUX_PIPE_RESOURCE_LIMIT in a row, and until
    /// when the next join waits (MULTIPATH.md Section 5.7 step 1).
    refusals: u32,
    join_backoff: Option<Instant>,
    /// Our joins not sent yet, oldest first, and whether they are being
    /// released.
    deferred: Vec<Deferred>,
    releasing: bool,
    seq: u64,
    pings: super::pipes::RateLimiter<8>,
    /// Retained, unacknowledged stream bytes.
    retained: u64,
    /// The running aggregates of the scheduled stream directions, brought
    /// up to date on read (`SessionCore::ledger`).
    ledger: std::cell::RefCell<super::ledger::Ledger>,
    /// When detection by acknowledgement resumed (an inbound pipe exists
    /// again, MULTIPATH.md Section 7.1), and whether one is live.
    detect_from: Instant,
    inbound_live: bool,
    /// The last interval without a live inbound pipe (start, end once one
    /// is live again): bytes sent in it give no samples.
    no_inbound: Option<(Instant, Option<Instant>)>,
    /// The session is busy until this time: the last traffic frame, or
    /// establishment, plus the busy window (MULTIPATH.md Section 7.1).
    busy_until: Instant,
    /// The phase of the idle-pipe probes, a fraction of the probe interval
    /// drawn once per session: sessions established together do not probe
    /// in lockstep.
    probe_phase: f64,
    /// PIPE_ACK generation (`ack.rs`).
    acks: super::ack::AckState,
    /// What the batch being written logs (`output.rs`).
    batch: super::output::BatchLog,
    /// Custom-policy decisions (`sched.rs`).
    picks: super::sched::Picks,
    /// The `affinity` bindings' re-evaluation (`sched.rs`).
    affinity: super::sched::Affinity,
    /// The pipe views, tier waits and probation histories (`tier.rs`).
    tiers: super::tier::Tiers,
    /// Stream directions held back by stream credit (`opp.rs`).
    blocked: super::opp::CreditBlocked,
    /// The SUSPENDED state (`resume.rs`).
    suspension: super::resume::Suspension,
}

/// The replay window over the pipe IDs of the peer's parity (MULTIPATH.md
/// Section 4.3), counted in pipe numbers of that parity (ID >> 1): h, the
/// highest verified join, and the bits set within [h - W, h + W]. For a
/// responder peer without a verified join the window is its first W IDs.
#[derive(Debug)]
pub(crate) struct ReplayWindow {
    high: Option<u64>,
    width: u64,
    /// The bits from pipe number `64 x base` on, one word per 64 numbers,
    /// covering the window (2W + 1 bits at most, allocated once).
    base: u64,
    bits: Vec<u64>,
}

impl ReplayWindow {
    /// `bootstrap`: the peer is the initiator, whose attachment 0 (the
    /// bootstrap pair) sets h = 0 and its bit.
    pub(crate) fn new(width: u64, bootstrap: bool) -> Self {
        let width = width.max(1);
        let words = usize::try_from(width.saturating_mul(2) / 64 + 2).unwrap_or(usize::MAX);
        let mut w = Self {
            high: None,
            width,
            base: 0,
            bits: Vec::with_capacity(words),
        };
        if bootstrap {
            w.raise(0);
            w.set(0);
        }
        w
    }

    /// The lowest pipe number in the window; below it IDs are stale.
    pub(crate) fn low(&self) -> u64 {
        self.high.map_or(0, |h| h.saturating_sub(self.width))
    }

    /// The highest pipe number in the window.
    fn top(&self) -> u64 {
        self.high
            .map_or(self.width - 1, |h| h.saturating_add(self.width))
    }

    /// Within the window.
    pub(crate) fn within(&self, n: u64) -> bool {
        (self.low()..=self.top()).contains(&n)
    }

    /// The word and bit of a pipe number at or above the base.
    fn place(&self, n: u64) -> (usize, u64) {
        ((n / 64 - self.base) as usize, 1 << (n % 64))
    }

    /// Without attachment state, an ID whose bit is set or that is stale
    /// is retired.
    pub(crate) fn retired(&self, n: u64) -> bool {
        if n < self.low() {
            return true;
        }
        let (i, bit) = self.place(n);
        self.bits.get(i).is_some_and(|w| w & bit != 0)
    }

    /// Sets a bit (a no-op outside the window: a stale ID is retired
    /// anyway).
    pub(crate) fn set(&mut self, n: u64) {
        if !self.within(n) {
            return;
        }
        let (i, bit) = self.place(n);
        if self.bits.len() <= i {
            self.bits.resize(i + 1, 0);
        }
        self.bits[i] |= bit;
    }

    /// A verified join raises h; bits below the window are dropped.
    pub(crate) fn raise(&mut self, n: u64) {
        if self.high.is_some_and(|h| h >= n) {
            return;
        }
        self.high = Some(n);
        let base = self.low() / 64;
        let gone = usize::try_from(base - self.base).unwrap_or(usize::MAX);
        self.bits.drain(..gone.min(self.bits.len()));
        self.base = base;
    }
}

impl Mp {
    /// Heap bytes the multipath state holds besides the attachments.
    pub(crate) fn heap_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.batch.heap_bytes() + self.acks.heap_bytes()
    }

    /// The session is closing: no more pipe-layer state changes matter.
    pub(crate) fn closing(&mut self, _now: Instant) {
        self.acks.closing();
        self.suspension.closing();
    }

    pub(crate) fn is_local(&self, id: u64) -> bool {
        id & 1 == self.parity
    }

    /// Resume is in use.
    #[inline]
    pub(crate) fn resume(&self) -> bool {
        self.resume
    }

    /// The peer's `zmux_max_ack_delay`.
    #[inline]
    pub(crate) fn peer_mad(&self) -> Duration {
        self.peer_mad
    }

    // ---- retained stream data --------------------------

    /// Retained, unacknowledged stream bytes.
    #[inline]
    pub(crate) fn retained(&self) -> u64 {
        self.retained
    }

    /// `n` more stream bytes are retained.
    #[inline]
    pub(crate) fn retain(&mut self, n: u64) {
        self.retained += n;
    }

    /// `n` retained stream bytes are released.
    #[inline]
    pub(crate) fn release(&mut self, n: u64) {
        self.retained = self.retained.saturating_sub(n);
    }

    /// A direction's retained bytes went from `before` to `after`.
    #[inline]
    pub(crate) fn retained_changed(&mut self, before: u64, after: u64) {
        self.retained = (self.retained + after).saturating_sub(before);
    }

    // ---- the PIPE_PING limit (MULTIPATH.md Section 6.4) -----------------------------

    /// PIPE_PING frames the limit lets go at `now`.
    #[inline]
    pub(crate) fn ping_slots(&self, now: Instant) -> usize {
        self.pings.available(now)
    }

    /// A PIPE_PING was written at `now`.
    pub(crate) fn ping_sent(&mut self, now: Instant) {
        self.pings.record(now);
    }

    // ---- inbound pipes and acknowledgement detection (MULTIPATH.md 7.1) ----------

    /// The last interval without a live inbound pipe: its start, and its
    /// end once one is live again.
    #[inline]
    pub(crate) fn no_inbound(&self) -> Option<(Instant, Option<Instant>)> {
        self.no_inbound
    }

    /// An inbound pipe is live (`true`) or none is: detection by
    /// acknowledgement resumes, with t_ref reset, or the interval without
    /// one starts.
    fn inbound(&mut self, live: bool, now: Instant) {
        if live && !self.inbound_live {
            self.detect_from = now;
            if let Some((_, end)) = &mut self.no_inbound {
                *end = Some(now);
            }
        } else if !live && self.inbound_live {
            self.no_inbound = Some((now, None));
        }
        self.inbound_live = live;
    }

    /// The session resumed: detection by acknowledgement starts over.
    pub(crate) fn resumed(&mut self, now: Instant) {
        self.inbound_live = true;
        self.detect_from = now;
    }

    // ---- the parts of the other modules --------------------------------------------

    /// The running aggregates of the scheduled stream directions.
    #[inline]
    pub(crate) fn ledger(&self) -> &std::cell::RefCell<super::ledger::Ledger> {
        &self.ledger
    }

    #[inline]
    pub(crate) fn acks(&self) -> &super::ack::AckState {
        &self.acks
    }

    #[inline]
    pub(crate) fn acks_mut(&mut self) -> &mut super::ack::AckState {
        &mut self.acks
    }

    #[inline]
    pub(crate) fn batch(&self) -> &super::output::BatchLog {
        &self.batch
    }

    #[inline]
    pub(crate) fn batch_mut(&mut self) -> &mut super::output::BatchLog {
        &mut self.batch
    }

    #[inline]
    pub(crate) fn picks(&self) -> &super::sched::Picks {
        &self.picks
    }

    #[inline]
    pub(crate) fn picks_mut(&mut self) -> &mut super::sched::Picks {
        &mut self.picks
    }

    #[inline]
    pub(crate) fn affinity(&self) -> &super::sched::Affinity {
        &self.affinity
    }

    #[inline]
    pub(crate) fn affinity_mut(&mut self) -> &mut super::sched::Affinity {
        &mut self.affinity
    }

    #[inline]
    pub(crate) fn tiers(&self) -> &super::tier::Tiers {
        &self.tiers
    }

    #[inline]
    pub(crate) fn tiers_mut(&mut self) -> &mut super::tier::Tiers {
        &mut self.tiers
    }

    #[inline]
    pub(crate) fn blocked(&self) -> &super::opp::CreditBlocked {
        &self.blocked
    }

    #[inline]
    pub(crate) fn blocked_mut(&mut self) -> &mut super::opp::CreditBlocked {
        &mut self.blocked
    }

    #[inline]
    pub(crate) fn suspension(&self) -> &super::resume::Suspension {
        &self.suspension
    }

    #[inline]
    pub(crate) fn suspension_mut(&mut self) -> &mut super::resume::Suspension {
        &mut self.suspension
    }
}

impl SessionCore {
    // ---- setup ------------------------------------------------------------------

    /// Multipath is in use: derive the keys and limits (MULTIPATH.md
    /// Sections 3 and 10).
    pub(super) fn mp_setup(
        &mut self,
        local: &TransportParameters,
        peer: &TransportParameters,
        now: Instant,
    ) {
        let (Some(l), Some(p)) = (local.zmux_multipath, peer.zmux_multipath) else {
            return;
        };
        let Some(source) = keys::select_secret_source(l.secret_flags, p.secret_flags) else {
            return;
        };
        let initiator = self.role == Role::Initiator;
        let (i_nonce, r_nonce) = if initiator {
            (l.session_nonce, p.session_nonce)
        } else {
            (p.session_nonce, l.session_nonce)
        };
        let exporter: &[u8] = if source.exporter {
            self.exporter.as_deref().unwrap_or_default()
        } else {
            &[]
        };
        let psk: &[u8] = if source.psk {
            self.config.pipe_auth.psk.as_deref().unwrap_or_default()
        } else {
            &[]
        };
        let secret = keys::session_secret(&i_nonce, &r_nonce, exporter, psk);
        let keys = SessionKeys::derive(&secret);
        let resume = self.features.resume;
        let grace = [local.zmux_resume, peer.zmux_resume]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(0);
        let local_mad = Duration::from_millis(self.local_tp().max_ack_delay());
        let threshold = self.local_tp().ack_threshold();
        let mp = Mp {
            last_failure: None,
            keys,
            peer_locator: p.locator,
            local_locator: l.locator,
            resume,
            peer_mad: Duration::from_millis(
                peer.zmux_max_ack_delay
                    .unwrap_or(crate::proto::params::DEFAULT_MAX_ACK_DELAY_MS),
            ),
            parity: u64::from(!initiator),
            next_id: if initiator { 2 } else { 1 },
            // The bootstrap pair is the initiator's attachment 0.
            replay: ReplayWindow::new(self.replay_width(), !initiator),
            refusals: 0,
            join_backoff: None,
            deferred: Vec::new(),
            releasing: false,
            seq: 1,
            pings: super::pipes::RateLimiter::default(),
            retained: 0,
            ledger: std::cell::RefCell::default(),
            detect_from: now,
            inbound_live: true,
            no_inbound: None,
            acks: super::ack::AckState::new(local_mad, threshold),
            batch: super::output::BatchLog::default(),
            picks: super::sched::Picks::default(),
            affinity: super::sched::Affinity::default(),
            tiers: super::tier::Tiers::default(),
            blocked: super::opp::CreditBlocked::default(),
            suspension: super::resume::Suspension::new(Duration::from_millis(grace)),
            busy_until: now + BUSY_WINDOW,
            probe_phase: self
                .config
                .hooks
                .probe_phase
                // A pinned phase outside [0, 1] (or NaN) is clamped.
                .map(|p| if p >= 0.0 { p.min(1.0) } else { 0.0 })
                .unwrap_or_else(|| (super::random_u64() >> 11) as f64 / (1u64 << 53) as f64),
        };
        self.mp = Some(Box::new(mp));
        // Every stream counts in the ledger from now on.
        self.streams.track();
        if let Some(a) = self.atts.first_mut()
            && a.id() == 0
        {
            a.start_multipath(
                initiator,
                self.config.suspect_floor,
                self.config.dead_timeout,
                now,
            );
        }
        // Positions count the bootstrap records sent so far; they were sent
        // before multipath was in use, so they elicit no stall (detection
        // starts at establishment, STATE_MACHINE.md Section 3.1).
    }

    pub(super) fn mp(&self) -> &Mp {
        self.mp.as_deref().expect("multipath in use")
    }

    pub(super) fn mp_mut(&mut self) -> &mut Mp {
        self.mp.as_deref_mut().expect("multipath in use")
    }

    /// Sets the locator of the multipath parameter this endpoint sends
    /// (MULTIPATH.md Section 4.4) in place of the configured one: a
    /// listener gives each of its sessions its own. Only before the
    /// parameters were sent; `Err` for a locator above 16 bytes.
    pub fn set_locator(&mut self, locator: &[u8]) -> Result<(), &'static str> {
        let l = Locator::new(locator).ok_or("locator above 16 bytes")?;
        if let Some(mp) = self.local.multipath.as_mut()
            && self.state == State::Establishing
        {
            mp.locator = l;
        }
        Ok(())
    }

    /// Whether multipath is in use.
    pub fn is_multipath(&self) -> bool {
        self.mp.is_some()
    }

    /// Whether multipath is in use, and why not.
    pub fn multipath(&self) -> Multipath {
        let Some(peer) = &self.peer_tp else {
            return Multipath::Off;
        };
        if self.local_tp().multipath.is_none() {
            Multipath::Off
        } else if peer.multipath.is_none() {
            Multipath::PeerDeclined
        } else if self.mp.is_some() {
            Multipath::InUse
        } else {
            Multipath::JoinSecurityUnavailable
        }
    }

    /// Sets the TLS exporter value of the bootstrap carrier(s) for
    /// `PipeAuth::tls` (MULTIPATH.md Section 10.2): of the TLS 1.3
    /// handshake that carries pipe 0 and terminates at the peer (its TLS
    /// connection, or the QUIC connection whose stream it is), taken once
    /// the handshake completed. Call before the parameters are sent: a
    /// session without one does not offer E (a stream of a multiplexed
    /// session never has one, MULTIPATH.md Section 10.5).
    pub fn set_bootstrap_exporter(&mut self, value: &[u8]) {
        self.exporter = Some(value.to_vec());
    }

    /// E names a secret source this endpoint can provide (MULTIPATH.md
    /// Section 3.1): without the bootstrap exporter it is not offered, so
    /// that no session secret is ever derived from the public nonces
    /// alone. With no other source left, multipath is not in use.
    pub(super) fn offer_exporter_only_with_one(&mut self) {
        if self.exporter.is_none()
            && let Some(mp) = self.local.multipath.as_mut()
        {
            mp.secret_flags &= !crate::proto::keys::secret_flags::EXPORTER;
        }
    }

    /// The Session Locator the peer must put in PIPE_JOIN to reach this
    /// session (empty when it accepts no joins).
    pub fn local_locator(&self) -> &[u8] {
        self.local
            .multipath
            .as_ref()
            .map_or(&[], |m| m.locator.as_bytes())
    }

    // ---- pipe IDs (MULTIPATH.md Section 4) ---------------------------------------

    /// W of the replay window: the setting, else max(64, 2 x (max_pipes +
    /// H)), never below max_pipes + H.
    fn replay_width(&self) -> u64 {
        let held = self.cap() as u64;
        self.config
            .replay_window
            .unwrap_or_else(|| 64.max(held.saturating_mul(2)))
            .max(held)
    }

    /// Whether an ID names a retired attachment: our own parity, taken and
    /// without state; the peer's, without attachment state and with its
    /// bit set or stale (Section 4.3).
    pub(super) fn is_retired(&self, id: u64) -> bool {
        if self.att(id).is_some_and(|a| !a.unattached()) {
            return false;
        }
        let mp = self.mp();
        if mp.is_local(id) {
            self.local_id_taken(id)
        } else {
            mp.replay.retired(id >> 1) || self.att(id).is_some()
        }
    }

    /// Whether a pipe ID of the local parity was taken by a local join
    /// (MULTIPATH.md Section 4.1); the bootstrap pair is the initiator's
    /// attachment 0. A frame naming one that was not is a
    /// PROTOCOL_VIOLATION (Section 4.3).
    pub(super) fn local_id_taken(&self, id: u64) -> bool {
        let mp = self.mp();
        // A deferred join's ID is not taken until its PIPE_JOIN goes
        // (Section 5.7 step 1): the peer cannot know it.
        (id < mp.next_id || (id == 0 && mp.parity == 0))
            && !self.att(id).is_some_and(Attachment::deferred)
    }

    /// Records a peer-parity ID as used: its bit is set, and a verified
    /// join raises h (Section 4.3). When the window slides, used IDs that
    /// fall below it lose their pending PIPE_ABANDON.
    fn use_peer_id(&mut self, id: u64, verified_join: bool) {
        let mp = self.mp_mut();
        if verified_join {
            mp.replay.raise(id >> 1);
        }
        mp.replay.set(id >> 1);
        let low = mp.replay.low();
        self.atts.forget_unattached_below(low);
        self.views_changed();
    }

    /// The cap of unretired attachments per joiner: max_pipes + H
    /// (MULTIPATH.md Section 5.4 step 9).
    pub(super) fn cap(&self) -> usize {
        let held = u64::from(self.config.max_pipes.max(1))
            .saturating_add(u64::from(self.config.pipe_headroom));
        usize::try_from(held).unwrap_or(usize::MAX)
    }

    /// Unretired attachments joined by the peer (or by us).
    fn unretired(&self, local: bool) -> usize {
        self.atts
            .iter()
            .filter(|a| a.joiner_local() == local && !a.unattached() && !a.deferred())
            .count()
    }

    /// Makes room for a join under the cap of unretired attachments
    /// (MULTIPATH.md Section 5.4 step 9). Outside suspension there is room
    /// only below the cap. While SUSPENDED, a join that provides a
    /// direction the endpoint lacks displaces one attachment of the same
    /// joiner: the oldest failed one whose own PIPE_ABANDON is
    /// unacknowledged, else the live one with the oldest last progress,
    /// failed without PIPE_ABANDON; either is retired locally at once.
    fn room_for_join(&mut self, local: bool, inbound: bool, outbound: bool, now: Instant) -> bool {
        let cap = if local {
            self.cap()
        } else {
            // The trace runner's cap for the peer's attachments.
            self.config.hooks.pipe_cap.unwrap_or_else(|| self.cap())
        };
        if self.unretired(local) < cap {
            return true;
        }
        if self.state != State::Suspended {
            return false;
        }
        // `inbound`/`outbound` are the directions the join gives us.
        let lacks_in = !self.atts.any_in_live();
        let lacks_out = !self.atts.any_out_live();
        if !(inbound && lacks_in || outbound && lacks_out) {
            return false;
        }
        let failed = self
            .atts
            .iter()
            .enumerate()
            .filter(|(_, a)| {
                a.joiner_local() == local && !a.unattached() && a.failed() && !a.abandon_acked()
            })
            .min_by_key(|(_, a)| a.seq())
            .map(|(i, _)| i);
        let pick = failed.or_else(|| {
            self.atts
                .iter()
                .enumerate()
                .filter(|(_, a)| {
                    a.joiner_local() == local && !a.unattached() && !a.failed() && !a.deferred()
                })
                .min_by_key(|(_, a)| a.last_progress())
                .map(|(i, _)| i)
        });
        let Some(i) = pick else {
            return false;
        };
        if !self.atts.at(i).failed() {
            let id = self.atts.at(i).id();
            self.fail_attachment(id, PipeFailure::Aborted, now);
            let Some(i) = self.att_index(id) else {
                return true;
            };
            // Retired at once: no PIPE_ABANDON.
            self.atts.at_mut(i).drop_abandon();
            self.retire_at_index(i, now);
        } else {
            self.retire_at_index(i, now);
        }
        self.unretired(local) < cap
    }

    // ---- joining (joiner side, MULTIPATH.md Section 5.7) ------------------------

    /// The framing of a reserved pipe's carrier, set when it is attached
    /// (an out-of-band join, before the pipe read or wrote a byte).
    pub fn set_reserved_framing(
        &mut self,
        id: PipeId,
        inbound: Option<Framing>,
        outbound: Option<Framing>,
        now: Instant,
    ) {
        let max = self.local_tp().max_record_size();
        if let (Some(f), Some(p)) = (inbound, self.inp_mut(id.0)) {
            p.set_framing(f, max, now);
        }
        if let (Some(f), Some(p)) = (outbound, self.out_mut(id.0)) {
            p.set_framing(f);
        }
    }

    /// Adds a pipe that the local endpoint joins. `inbound`/`outbound` name
    /// the carrier's halves: the outbound pipe is joined in band unless
    /// `oob`, in which case (and always for an inbound-only carrier) the
    /// frame is handed to the adapter as [`CoreEvent::OobJoin`]. Each call takes
    /// a fresh pipe ID. While the endpoint has max_pipes + H unretired
    /// attachments of its own, or after a refusal until the backoff of
    /// Section 5.7 step 1 has elapsed, the join is deferred
    /// ([`SessionCore::join_deferred`]) and goes once allowed; fails when the
    /// peer accepts no joins.
    #[allow(clippy::too_many_arguments)]
    pub fn add_pipe(
        &mut self,
        inbound: Option<Framing>,
        outbound: Option<Framing>,
        opts: &PipeOptions,
        oob: bool,
        carrier_binding: Option<&[u8]>,
        now: Instant,
    ) -> Result<PipeId, super::PipeError> {
        use super::PipeError;
        self.tick(now);
        if let Some(e) = self.lost() {
            return Err(PipeError::SessionLost(e));
        }
        if self.state == State::Establishing {
            return Err(PipeError::NotEstablished);
        }
        if self.mp.is_none() {
            return Err(PipeError::NotNegotiated);
        }
        if self.mp().peer_locator.as_bytes().is_empty() {
            // The peer accepts no joins (MULTIPATH.md Section 3.1).
            return Err(PipeError::NotNegotiated);
        }
        let direction = match (inbound.is_some(), outbound.is_some()) {
            (true, true) => JoinDirection::Bidi,
            (false, true) => JoinDirection::Up,
            (true, false) => JoinDirection::Down,
            (false, false) => return Err(PipeError::UnknownPipe),
        };
        let id = {
            let mp = self.mp_mut();
            let id = mp.next_id;
            mp.next_id += 2;
            id
        };
        let seq = self.next_att_seq();
        let mut att = Attachment::new(id, true, opts.fate_group, seq);
        att.set_label(opts.label.clone());
        let max = self.local_tp().max_record_size();
        let floor = opts.suspect_floor.unwrap_or(self.config.suspect_floor);
        let dead = opts.dead_timeout.or(self.config.dead_timeout);
        let rtt = self.initial_rtt(id);
        if let Some(framing) = inbound {
            att = att.with_inp(InPipe::new(framing, max, InState::Deferred, now));
        }
        if let Some(framing) = outbound {
            att = att.with_out(
                OutPipe::new(framing, OutState::Deferred, rtt, now).with_mp(floor, dead, now),
            );
        }
        let pos = self.insert_attachment(att);
        self.init_tier(pos, opts);
        self.stats.pipes_added += 1;
        self.mp_mut().deferred.push(Deferred {
            id,
            direction,
            oob: oob || outbound.is_none(),
            binding: carrier_binding.map(<[u8]>::to_vec).unwrap_or_default(),
        });
        for half in [PipeHalf::Inbound, PipeHalf::Outbound] {
            self.pipe_event(id, half);
        }
        self.release_deferred_joins(now);
        Ok(PipeId(id))
    }

    /// Whether a join made now would go at once rather than be deferred:
    /// no refusal backoff runs and the cap of unretired attachments has
    /// room (while suspended, a join that brings a missing direction makes
    /// room). Helpers that dial carriers ask this first, so that a carrier
    /// is never held idle (MULTIPATH.md Sections 5.4 step 9 and 5.7 step 1).
    pub fn join_ready(&self, now: Instant) -> bool {
        let Some(mp) = self.mp.as_deref() else {
            return false;
        };
        mp.deferred.is_empty()
            && mp.join_backoff.is_none_or(|t| now >= t)
            && (self.unretired(true) < self.cap() || self.state == State::Suspended)
    }

    /// Whether this endpoint has room for a join of its own now: one
    /// added would join at once ([`SessionCore::join_ready`]), and its live
    /// attachments stay within `max_pipes`, the attachments it aims for.
    /// A rejoin of a duplicate session's route is skipped otherwise.
    pub fn join_wanted(&self, now: Instant) -> bool {
        let live = self
            .atts
            .iter()
            .filter(|a| !a.unattached() && !a.failed())
            .count();
        self.join_ready(now) && live < self.config.max_pipes as usize
    }

    /// Whether a local join waits to be sent (the cap of unretired
    /// attachments or the refusal backoff); it is sent, with this ID, once
    /// allowed.
    pub fn join_deferred(&self, pipe: PipeId) -> bool {
        self.att(pipe.0).is_some_and(Attachment::deferred)
    }

    /// Sends the deferred joins that are allowed now, oldest first
    /// (MULTIPATH.md Sections 5.4 step 9 and 5.7 step 1).
    pub(super) fn release_deferred_joins(&mut self, now: Instant) {
        if self.state >= State::Closing || self.mp().releasing {
            return;
        }
        // Making room may retire attachments, which comes back here.
        self.mp_mut().releasing = true;
        self.release_deferred(now);
        self.mp_mut().releasing = false;
    }

    fn release_deferred(&mut self, now: Instant) {
        while let Some(&Deferred { id, .. }) = self.mp().deferred.first() {
            if self.mp().join_backoff.is_some_and(|t| now < t) {
                return;
            }
            self.mp_mut().join_backoff = None;
            let (inbound, outbound) = self
                .att(id)
                .map_or((false, false), |a| (a.inp().is_some(), a.out().is_some()));
            if !self.room_for_join(true, inbound, outbound, now) {
                return;
            }
            let d = self.mp_mut().deferred.remove(0);
            if let Some(o) = self.out_mut(id) {
                o.release_join();
            }
            if let Some(p) = self.inp_mut(id) {
                p.release_join();
            }
            self.send_join(id, d.direction, d.oob, Some(&d.binding), now);
            for half in [PipeHalf::Inbound, PipeHalf::Outbound] {
                self.pipe_event(id, half);
            }
        }
    }

    /// Drops a deferred join: the peer never learned its ID, so nothing is
    /// abandoned; its carrier halves are closed.
    pub(super) fn drop_deferred(&mut self, i: usize) {
        let a = self.atts.remove(i);
        self.views_changed();
        let id = a.id();
        self.recv_lane_gone(id);
        self.mp_mut().deferred.retain(|d| d.id != id);
        for (half, present) in [
            (PipeHalf::Inbound, a.inp().is_some()),
            (PipeHalf::Outbound, a.out().is_some()),
        ] {
            if present {
                self.push_event(CoreEvent::ClosePipe {
                    pipe: PipeId(id),
                    half,
                    abort: true,
                });
                self.push_event(CoreEvent::PipeState {
                    pipe: PipeId(id),
                    half,
                    state: PipeState::Retired,
                });
            }
        }
    }

    /// Builds and hands off the PIPE_JOIN of a local attachment. It carries
    /// the initial request for the peer's outbound direction (Section 5.1);
    /// for direction up there is none.
    fn send_join(
        &mut self,
        id: u64,
        direction: JoinDirection,
        oob: bool,
        binding: Option<&[u8]>,
        now: Instant,
    ) {
        let initiator = self.role == Role::Initiator;
        let mp = self.mp();
        let key = if initiator {
            mp.keys.join_initiator
        } else {
            mp.keys.join_responder
        };
        let locator = mp.peer_locator;
        let (fate_group, standby, priority) = self.att(id).map_or((0, false, 0), |a| {
            if direction == JoinDirection::Up {
                (a.fate_group(), false, 0)
            } else {
                (
                    a.fate_group(),
                    a.tier().receive_standby(),
                    a.tier().receive_priority(),
                )
            }
        });
        let frame = PipeJoin {
            locator: locator.as_bytes(),
            pipe_id: id,
            direction,
            carrier_bound: binding.is_some_and(|b| !b.is_empty()),
            fate_group,
            standby,
            priority,
            token: [0; 16],
        };
        let mut buf = [0u8; 64];
        let len = frame.encoded_len();
        {
            let mut w = Writer::new(&mut buf[..len]);
            let _ = frame.write(&mut w);
        }
        keys::sign_join(&key, &mut buf[..len], binding.unwrap_or_default());
        // The first record carries a complete snapshot (step 2), after the
        // PIPE_JOIN when it goes in band.
        let inband = (!oob).then_some((buf, len as u8));
        if let Some(o) = self.out_mut(id) {
            o.start_join(inband, now);
        }
        if let Some(i) = self.inp_mut(id) {
            i.restart(now);
        }
        if oob {
            self.push_event(CoreEvent::OobJoin {
                pipe: PipeId(id),
                frame: Bytes::copy_from_slice(&buf[..len]),
            });
        }
    }

    fn next_att_seq(&mut self) -> u64 {
        let mp = self.mp_mut();
        mp.seq += 1;
        mp.seq
    }

    /// One of our joins was confirmed (Section 5.7 step 4): the refusal
    /// backoff resets, and a request for the peer's direction changed while
    /// JOINING goes out with its latest value.
    pub(super) fn join_confirmed(&mut self, id: u64) {
        let mp = self.mp_mut();
        let before = std::mem::take(&mut mp.refusals);
        mp.join_backoff = None;
        if let Some(a) = self.att_mut(id) {
            a.join_confirmed(before);
        }
    }

    /// One of our joins was refused with ZMUX_PIPE_RESOURCE_LIMIT: the next
    /// waits 1 s, doubled per consecutive refusal, at most 60 s (Section 5.7
    /// step 1).
    fn join_refused(&mut self, now: Instant) {
        self.stats.join_refusals += 1;
        let mp = self.mp_mut();
        mp.refusals = mp.refusals.saturating_add(1);
        let wait = Duration::from_secs(1)
            .saturating_mul(1 << (mp.refusals - 1).min(6))
            .min(Duration::from_secs(60));
        mp.join_backoff = Some(now + wait);
    }

    // ---- joining (acceptor side, MULTIPATH.md Section 5.4) -----------------------

    /// Offers a join that a listener received: `frame` is the PIPE_JOIN
    /// (Type through Join Token, exactly as received), `carrier_binding` the
    /// new carrier's TLS exporter when it has one. `inbound`/`outbound` give
    /// the halves the carrier provides and their framing. With `inband`,
    /// the carrier's first record starts with this frame and is fed to
    /// [`SessionCore::receive`] like the rest.
    #[allow(clippy::too_many_arguments)]
    pub fn offer_join(
        &mut self,
        frame: &[u8],
        carrier_binding: &[u8],
        inbound: Option<Framing>,
        outbound: Option<Framing>,
        inband: bool,
        now: Instant,
    ) -> JoinVerdict {
        let carrier = JoinCarrier {
            inbound,
            outbound,
            inband,
            looped: false,
        };
        self.join_offered(frame, carrier_binding, carrier, now)
    }

    /// Offers a join whose carrier is a stream of a session that runs,
    /// directly or through other sessions of the process, over a pipe of
    /// this one (EXTENSIONS.md Section 10.2): the join
    /// is checked like any other and, authenticated, refused at MULTIPATH.md
    /// Section 5.4 step 7 with PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT), so
    /// that a joiner that cannot see the loop backs off (Section 5.7)
    /// instead of rejoining at once. Never [`JoinVerdict::Accepted`]: close
    /// the carrier.
    pub fn refuse_looped_join(
        &mut self,
        frame: &[u8],
        carrier_binding: &[u8],
        inbound: Option<Framing>,
        outbound: Option<Framing>,
        now: Instant,
    ) -> JoinVerdict {
        let carrier = JoinCarrier {
            inbound,
            outbound,
            inband: false,
            looped: true,
        };
        self.join_offered(frame, carrier_binding, carrier, now)
    }

    fn join_offered(
        &mut self,
        frame: &[u8],
        carrier_binding: &[u8],
        carrier: JoinCarrier,
        now: Instant,
    ) -> JoinVerdict {
        let JoinCarrier {
            inbound,
            outbound,
            inband,
            looped,
        } = carrier;
        self.tick(now);
        match self.state {
            State::Establishing => return JoinVerdict::Wait,
            State::Closing | State::Closed => return JoinVerdict::Reject,
            _ => {}
        }
        if self.mp.is_none() {
            return JoinVerdict::Reject;
        }
        let Ok((join, len)) = PipeJoin::decode(frame) else {
            return JoinVerdict::Reject;
        };
        if len != frame.len() || join.locator != self.mp().local_locator.as_bytes() {
            return JoinVerdict::Reject;
        }
        // Step 5: the join key of the peer's role, never inferred from the
        // pipe ID.
        let peer_initiator = self.role != Role::Initiator;
        let key = if peer_initiator {
            self.mp().keys.join_initiator
        } else {
            self.mp().keys.join_responder
        };
        let binding: &[u8] = if join.carrier_bound {
            carrier_binding
        } else {
            &[]
        };
        if (join.carrier_bound && carrier_binding.is_empty())
            || !keys::verify_join(&key, frame, binding)
        {
            self.stats.join_auth_failures += 1;
            self.push_event(CoreEvent::JoinAuthFailed {
                carrier_bound: join.carrier_bound,
            });
            return JoinVerdict::AuthFailed;
        }
        let id = join.pipe_id;
        // Step 6: replay. The ID has attachment state, its bit is set, or
        // it is stale.
        if !self.mp().is_local(id) && (self.att_index(id).is_some() || self.is_retired(id)) {
            self.stats.join_replays += 1;
            return JoinVerdict::Reject;
        }
        // Step 7: violations are the peer's from here on.
        if self.mp().is_local(id) {
            self.protocol_error(
                Error::protocol_violation(0x1a24_de36, "PIPE_JOIN with the acceptor's parity"),
                now,
            );
            return JoinVerdict::Fatal;
        }
        let (want_in, want_out) = match join.direction {
            JoinDirection::Up => (true, false),
            JoinDirection::Down => (false, true),
            JoinDirection::Bidi => (true, true),
        };
        if (want_in && inbound.is_none()) || (want_out && outbound.is_none()) {
            self.refuse_join(id, T::ZMUX_PIPE_FAILED.0);
            return JoinVerdict::Refused;
        }
        // A carrier running over this session (a local condition, not a
        // violation), or step 9: the cap of unretired attachments.
        if looped || !self.room_for_join(false, want_in, want_out, now) {
            self.refuse_join(id, T::ZMUX_PIPE_RESOURCE_LIMIT.0);
            return JoinVerdict::Refused;
        }
        // Step 8: attach.
        self.use_peer_id(id, true);
        let seq = self.next_att_seq();
        let mut att = Attachment::accepted(id, join.fate_group, seq);
        let max = self.local_tp().max_record_size();
        if want_in && let Some(framing) = inbound {
            att = att
                .with_inp(InPipe::new(framing, max, InState::Open, now).with_inband_join(inband));
        }
        if want_out && let Some(framing) = outbound {
            let rtt = self.initial_rtt(id);
            // The first record carries a complete snapshot and PIPE_PING
            // (step 8).
            let o = OutPipe::new(framing, OutState::Active, rtt, now)
                .with_mp(self.config.suspect_floor, self.config.dead_timeout, now)
                .accepted(now);
            att = att.with_out(o);
            // The joiner's initial request for our outbound direction
            // (Section 5.1), sequence number 0.
            att.tier_mut().join_request(join.standby, join.priority);
        }
        self.insert_attachment(att);
        self.stats.pipes_added += 1;
        if want_out && outbound.is_some() {
            // An accepted attachment is ACTIVE at once, in probation.
            self.start_probation(id, now);
        }
        for half in [PipeHalf::Inbound, PipeHalf::Outbound] {
            self.pipe_event(id, half);
        }
        if self.state == State::Suspended {
            self.check_resume(now);
        }
        JoinVerdict::Accepted(PipeId(id))
    }

    /// Records a refused join (MULTIPATH.md Section 5.4 step 7): never
    /// attached, it leaves its bit and a PIPE_ABANDON, kept while the ID is
    /// in the replay window and until the PIPE_ABANDON is acknowledged.
    fn refuse_join(&mut self, id: u64, code: u64) {
        self.use_peer_id(id, true);
        self.add_unattached(id, code, None);
    }

    /// Inserts `att` in identifier order; returns its index. The list grows
    /// by one: attachments come rarely and are bounded by `max_pipes`, and a
    /// quiet session holds no room for more.
    fn insert_attachment(&mut self, att: Attachment) -> usize {
        let pos = self.atts.insert(att);
        self.views_changed();
        pos
    }

    /// A peer-parity ID used without attachment state, with our
    /// PIPE_ABANDON for it pending.
    fn add_unattached(&mut self, id: u64, code: u64, received: Option<u64>) {
        let seq = self.next_att_seq();
        self.insert_attachment(Attachment::unattached_id(id, seq, code, received));
    }

    // ---- removal (MULTIPATH.md Section 8) ---------------------------------------

    /// Removes a pipe: gracefully (drain, PIPE_ABANDON(NO_ERROR)) or
    /// abruptly (failure, reinjection, PIPE_ABANDON(ZMUX_PIPE_FAILED)).
    pub fn remove_pipe(
        &mut self,
        pipe: PipeId,
        graceful: bool,
        now: Instant,
    ) -> Result<(), super::PipeError> {
        self.tick(now);
        if self.mp.is_none() {
            return Err(super::PipeError::NotNegotiated);
        }
        let Some(a) = self.att(pipe.0) else {
            return Err(super::PipeError::UnknownPipe);
        };
        if a.failed() || a.unattached() {
            return Ok(());
        }
        if a.deferred() {
            if let Some(i) = self.att_index(pipe.0) {
                self.drop_deferred(i);
            }
            return Ok(());
        }
        if graceful {
            self.drain_attachment(pipe.0, now);
            // As the last frame of the drained pipe itself.
            self.att_mut(pipe.0).expect("present").abandon_gracefully();
        } else {
            self.fail_attachment(pipe.0, PipeFailure::Aborted, now);
        }
        self.after_pipe_change(now);
        Ok(())
    }

    /// Removes `pipe` abruptly for a local resource limit or a carrier loop
    /// found after it was attached (MULTIPATH.md Sections 5.4 step 7 and
    /// 8.3): it fails with PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT), which
    /// makes the joiner back off, and affects no other attachment of its
    /// fate group.
    pub fn abandon_pipe_for_limit(&mut self, pipe: PipeId, now: Instant) {
        self.tick(now);
        let Some(a) = self.att_mut(pipe.0) else {
            return;
        };
        if a.failed() || a.unattached() {
            return;
        }
        a.abandon(T::ZMUX_PIPE_RESOURCE_LIMIT.0);
        self.fail_attachment(pipe.0, PipeFailure::Aborted, now);
        self.after_pipe_change(now);
    }

    /// Starts draining an attachment's outbound pipe.
    fn drain_attachment(&mut self, id: u64, now: Instant) {
        if !self.out_mut(id).is_some_and(|o| o.start_drain(now)) {
            return;
        }
        self.unsettle(id);
        self.pipe_event(id, PipeHalf::Outbound);
    }

    /// Fails an attachment (MULTIPATH.md Section 7.2): reinjection, carriers
    /// closed, PIPE_ABANDON(ZMUX_PIPE_FAILED) unless one was sent.
    pub(super) fn fail_attachment(&mut self, id: u64, cause: PipeFailure, now: Instant) {
        let Some(i) = self.att_index(id) else {
            return;
        };
        if self.atts.at(i).deferred() {
            self.drop_deferred(i);
            return;
        }
        // Decided before the failure sets a failure code.
        let draining = self.atts.at(i).outside_fate();
        if !self.atts.at_mut(i).fail() {
            return;
        }
        self.atts.at_mut(i).set_failure(cause);
        self.mp_mut().last_failure = Some(cause);
        self.stats.pipe_failures += 1;
        self.probation_failed(i, now);
        let a = self.atts.at_mut(i);
        let (local, group) = a.fate();
        a.abandon(T::ZMUX_PIPE_FAILED.0);
        if a.out().is_some_and(|o| o.state() != OutState::Failed) {
            self.reinject(id, now);
            let report = self.atts.at_mut(i).out_mut().expect("present").fail();
            self.unsettle(id);
            self.pipe_event(id, PipeHalf::Outbound);
            if report {
                self.push_event(CoreEvent::ClosePipe {
                    pipe: PipeId(id),
                    half: PipeHalf::Outbound,
                    abort: true,
                });
            }
        }
        if let Some(report) = self.atts.at_mut(i).inp_mut().and_then(InPipe::fail) {
            self.mp_mut().acks_mut().owe_now();
            self.pipe_event(id, PipeHalf::Inbound);
            if report {
                self.push_event(CoreEvent::ClosePipe {
                    pipe: PipeId(id),
                    half: PipeHalf::Inbound,
                    abort: true,
                });
            }
        }
        // The fate group (MULTIPATH.md Section 7.1), unless the attachment
        // was being removed gracefully or abandoned for a resource limit.
        if group != 0 && !draining {
            let others: Vec<u64> = self
                .atts
                .iter()
                .filter(|a| a.id() != id && a.fate() == (local, group))
                .map(Attachment::id)
                .collect();
            for o in others {
                let Some(out) = self.out_ref(o) else {
                    continue;
                };
                if !matches!(out.state(), OutState::Active | OutState::Joining) {
                    continue;
                }
                if out.oldest_unacked_watched().is_some() {
                    self.suspect(o, now);
                } else if let Some(out) = self.out_mut(o) {
                    out.want_ping(now);
                }
            }
        }
        // The failure may complete the conditions of retirement (Section
        // 8.4).
        self.try_retire(now);
    }

    /// An outbound pipe becomes suspect (MULTIPATH.md Section 7.2).
    pub(super) fn suspect(&mut self, id: u64, now: Instant) {
        if !self.out_mut(id).is_some_and(|o| o.suspect(now)) {
            return;
        }
        self.unsettle(id);
        self.probation_suspect(id, now);
        let primary = self.mp().acks().primary() == Some(id);
        self.pipe_event(id, PipeHalf::Outbound);
        self.reinject(id, now);
        self.check_standby_takeover();
        if primary {
            // A copy of the snapshot goes out at once (Section 6.5).
            self.mp_mut().acks_mut().copy_now(now);
        }
    }

    /// The pipe's acknowledged position advanced: a suspect pipe whose
    /// carrier accepts bytes recovers; a joining one is confirmed.
    pub(super) fn ack_progress(&mut self, id: u64, now: Instant) {
        let Some(joined) = self.out_mut(id).and_then(OutPipe::ack_progress) else {
            return;
        };
        // A joined pipe is in probation, and so is one back from SUSPECT.
        if joined {
            self.join_confirmed(id);
            self.start_probation(id, now);
            self.release_deferred_joins(now);
        } else {
            self.probation_recovered(id, now);
        }
        self.pipe_event(id, PipeHalf::Outbound);
        self.check_standby_takeover();
    }

    /// Retires attachments whose exchange is complete (MULTIPATH.md
    /// Section 8.4).
    pub(super) fn try_retire(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.atts.len() {
            let a = self.atts.at(i);
            if a.id() == 0 && self.mp.is_none() {
                i += 1;
                continue;
            }
            let ends_done = a.ends_done();
            let own = a.own_abandon_done();
            if own && a.unattached() {
                // Only a bit in the replay window remains (Section 4.3).
                let id = self.atts.remove(i).id();
                self.views_changed();
                self.recv_lane_gone(id);
                continue;
            }
            let unilateral = a.retire_at().is_some_and(|t| now >= t);
            if own && unilateral && a.abandon_received().is_none() {
                // The peer never answered: close whatever is still open and
                // retire anyway (MULTIPATH.md Section 8.4).
                self.retire_at_index(i, now);
                continue;
            }
            if own && ends_done && a.abandon_received().is_some() {
                self.retire_at_index(i, now);
                continue;
            }
            i += 1;
        }
        if self.mp.as_deref().is_some_and(|m| !m.deferred.is_empty()) {
            self.release_deferred_joins(now);
        }
    }

    fn retire_at_index(&mut self, i: usize, now: Instant) {
        // Retired information must have been reinjected or acknowledged
        // (Section 8.4): a unilateral retirement of a pipe still draining
        // reinjects what it holds.
        let a = self.atts.at(i);
        if a.out().is_some_and(|o| o.state().is_live()) {
            let id = a.id();
            self.reinject(id, now);
        }
        let a = self.atts.remove(i);
        self.views_changed();
        let id = a.id();
        self.recv_lane_gone(id);
        let peer = !a.joiner_local();
        if let Some(o) = a.out().filter(|o| o.close_unreported()) {
            self.push_event(CoreEvent::ClosePipe {
                pipe: PipeId(id),
                half: PipeHalf::Outbound,
                abort: o.state() != OutState::Closed,
            });
        }
        if a.inp().is_some_and(InPipe::close_unreported) {
            self.push_event(CoreEvent::ClosePipe {
                pipe: PipeId(id),
                half: PipeHalf::Inbound,
                abort: false,
            });
        }
        for (half, present) in [
            (PipeHalf::Inbound, a.inp().is_some()),
            (PipeHalf::Outbound, a.out().is_some()),
        ] {
            if present {
                self.push_event(CoreEvent::PipeState {
                    pipe: PipeId(id),
                    half,
                    state: PipeState::Retired,
                });
            }
        }
        if !peer && a.joined() && !a.limit_abandoned() {
            // An attachment the peer had attached is gone: a join waiting
            // after a refusal may go now (Section 5.7 step 1).
            self.mp_mut().join_backoff = None;
        }

        let _ = now;
    }

    // ---- received pipe frames ---------------------------------------------------

    /// PIPE_ABANDON (MULTIPATH.md Section 8.1).
    pub(super) fn on_pipe_abandon(
        &mut self,
        id: u64,
        code: u64,
        now: Instant,
    ) -> Result<(), Error> {
        let ty = 0x23b3_5b74;
        if self.mp().is_local(id) && !self.local_id_taken(id) {
            return Err(
                Error::protocol_violation(ty, "PIPE_ABANDON for an untaken local pipe ID")
                    .detail(crate::proto::DetailKey::Pipe, id),
            );
        }
        let Some(i) = self
            .att_index(id)
            .filter(|&i| !self.atts.at(i).unattached())
        else {
            // No attachment state: a peer ID within the replay window whose
            // bit is not set is marked used and answered; anything else is
            // ignored, and the peer retires unilaterally.
            let mp = self.mp();
            let n = id >> 1;
            if !mp.is_local(id) && mp.replay.within(n) && !mp.replay.retired(n) {
                self.use_peer_id(id, false);
                let answer = if code == 0 { 0 } else { T::ZMUX_PIPE_FAILED.0 };
                self.add_unattached(id, answer, Some(code));
            }
            return Ok(());
        };
        let a = self.atts.at_mut(i);
        if !a.abandon_arrived(code) {
            // A copy: answered once already (Section 8.4).
            return Ok(());
        }
        // A refusal or an abandonment for a resource limit of one of our
        // attachments starts the join backoff (Section 5.7 step 1).
        let refused =
            a.joiner_local() && code == T::ZMUX_PIPE_RESOURCE_LIMIT.0 && !a.own_limit_abandon();
        let joined = a.joined();
        let before = a.refusals_at_join();
        // The failure may retire the attachment at once (Section 8.4).
        if code == 0 {
            self.drain_attachment(id, now);
            if let Some(a) = self.att_mut(id) {
                a.abandon(0);
            }
        } else {
            self.fail_attachment(
                id,
                PipeFailure::Abandoned(VarInt::from_u64(code).unwrap_or(VarInt::MAX)),
                now,
            );
            if let Some(a) = self.att_mut(id) {
                a.abandon(T::ZMUX_PIPE_FAILED.0);
            }
        }
        if refused {
            if joined {
                // Its join did not count as a success: the refusals before
                // it continue.
                let mp = self.mp_mut();
                mp.refusals = mp.refusals.max(before);
            }
            self.join_refused(now);
        }
        self.exchange_progress(id, now);
        self.after_pipe_change(now);
        Ok(())
    }

    // ---- pipe ends -------------------------------------------------------------

    /// An inbound pipe ended in a multipath session (MULTIPATH.md Section
    /// 7.3). `clean`: a graceful end at a record boundary.
    pub(super) fn mp_inbound_ended(&mut self, id: u64, end: PipeEnd, clean: bool, now: Instant) {
        let closing = self.state >= State::Closing;
        // Expected after the peer's PIPE_ABANDON, and during a graceful
        // removal this endpoint started: the peer may shut its side down
        // once it has our PIPE_ABANDON, before its own reaches us over
        // another pipe (MULTIPATH.md Section 7.3).
        let expected = clean && (closing || self.att(id).is_some_and(Attachment::end_expected));
        if closing || expected {
            if let Some(p) = self.inp_mut(id) {
                // Its carrier ended: nothing to close.
                p.end_gracefully();
            }
            if !closing {
                self.mp_mut().acks_mut().owe_now();
                self.pipe_event(id, PipeHalf::Inbound);
                self.try_retire(now);
                self.after_pipe_change(now);
            } else {
                self.maybe_closed(now);
            }
            return;
        }
        // An unexpected end: the attachment fails (a pipe pair as a unit).
        if let Some(p) = self.inp_mut(id) {
            p.carrier_ended();
        }
        self.fail_attachment(id, end.failure(), now);
        self.after_pipe_change(now);
    }

    /// A write to an outbound pipe failed (multipath): the attachment fails.
    pub(super) fn mp_outbound_failed(&mut self, id: u64, cause: PipeFailure, now: Instant) {
        if let Some(o) = self.out_mut(id) {
            o.abort_reported();
        }
        self.fail_attachment(id, cause, now);
        self.after_pipe_change(now);
    }

    /// The exchange of PIPE_ABANDON frames progressed for an attachment:
    /// start the inbound linger, close a drained pipe, retire.
    pub(super) fn exchange_progress(&mut self, id: u64, now: Instant) {
        let linger = self.linger_timeout();
        let Some(a) = self.att_mut(id) else {
            return;
        };
        if a.exchange_complete()
            && let Some(p) = a.inp_mut()
        {
            p.start_linger(now + linger);
        }
        self.check_drained(id, now);
        self.try_retire(now);
    }

    /// A DRAINING pipe whose exchange is complete and whose stream data is
    /// acknowledged closes (MULTIPATH.md Section 8.2 step 3).
    pub(super) fn check_drained(&mut self, id: u64, now: Instant) {
        let Some(a) = self.att(id) else {
            return;
        };
        let Some(o) = a.out() else {
            return;
        };
        if o.state() != OutState::Draining || !a.exchange_complete() || o.stream_unacked() {
            return;
        }
        // Control information still unacknowledged goes elsewhere; the log
        // stays, so that a late acknowledgement still counts (our own
        // PIPE_ABANDON may be on this pipe).
        self.reinject(id, now);
        self.out_mut(id).expect("present").close_drained();
        self.pipe_event(id, PipeHalf::Outbound);
        self.try_retire(now);
        // It may have been the last outbound pipe (Section 8.5).
        self.after_pipe_change(now);
    }

    /// After pipes changed: the last pipe in a direction (MULTIPATH.md
    /// Section 8.5), suspension and resumption.
    pub(super) fn after_pipe_change(&mut self, now: Instant) {
        if self.state >= State::Closing || self.mp.is_none() {
            return;
        }
        self.check_standby_takeover();
        let live_out = self.atts.any_out_live();
        let live_in = self.atts.any_in_live();
        // Acknowledgement detection resumes with an inbound pipe, with t_ref
        // reset (MULTIPATH.md Section 7.1).
        self.mp_mut().inbound(live_in, now);
        if live_out && live_in {
            if self.state == State::Suspended {
                self.check_resume(now);
            }
            return;
        }
        if self.mp().resume {
            self.suspend(now);
            return;
        }
        // Without resume the session ends (MULTIPATH.md Section 8.5).
        let last = self.mp().last_failure;
        self.set_error(SessionError::PipesLost { last });
        if live_out {
            self.enter_closing(
                Some(CloseFrame::Transport {
                    code: T::NO_VIABLE_PATH.0,
                    frame_type: 0,
                    reason: Bytes::new(),
                }),
                now,
            );
        } else {
            self.closed_now();
        }
    }

    // ---- states and events -----------------------------------------------------

    /// Reports a pipe's current state.
    pub(super) fn pipe_event(&mut self, id: u64, half: PipeHalf) {
        let Some(a) = self.att(id) else {
            return;
        };
        let state = match half {
            PipeHalf::Inbound => a.inp().map(|p| p.state().public()),
            PipeHalf::Outbound => a.out().map(OutPipe::public_state),
        };
        if let Some(state) = state {
            self.push_event(CoreEvent::PipeState {
                pipe: PipeId(id),
                half,
                state,
            });
        }
    }

    /// A pipe's state (STATE_MACHINE.md Section 3), `Retired` for a retired
    /// attachment, `None` for one never seen.
    pub fn pipe_state(&self, pipe: PipeId, half: PipeHalf) -> Option<PipeState> {
        match self.att(pipe.0).filter(|a| !a.unattached()) {
            Some(a) => match half {
                PipeHalf::Inbound => a.inp().map(|p| p.state().public()),
                PipeHalf::Outbound => a.out().map(OutPipe::public_state),
            },
            None if self.mp.is_some() && self.is_retired(pipe.0) => Some(PipeState::Retired),
            None => None,
        }
    }

    /// The attachments and their pipes, with their quality.
    pub fn pipes(&self) -> Vec<PipeStats> {
        let gate = self.mp.as_ref().and_then(|_| self.gate());
        self.atts
            .iter()
            .filter(|a| !a.unattached())
            .map(|a| self.info_of(a, gate))
            .collect()
    }

    /// The IDs of the attachments [`SessionCore::pipes`] reports, in order.
    pub fn pipe_ids(&self) -> Vec<PipeId> {
        self.atts
            .iter()
            .filter(|a| !a.unattached())
            .map(|a| PipeId(a.id()))
            .collect()
    }

    /// Why the attachment failed, once it did.
    pub fn pipe_failure(&self, pipe: PipeId) -> Option<PipeFailure> {
        self.att(pipe.0)?.failure()
    }

    /// Whether the attachment is known and not retired.
    pub fn has_pipe(&self, pipe: PipeId) -> bool {
        self.att(pipe.0).is_some_and(|a| !a.unattached())
    }

    /// Whether the join of `pipe` completed: `Ok` once it was confirmed
    /// (the outbound pipe ACTIVE, or an inbound-only pipe open), the error
    /// once it failed, the attachment is gone or the session ended; `None`
    /// while it is pending.
    pub fn pipe_joined(&self, pipe: PipeId) -> Option<Result<(), super::PipeError>> {
        use super::PipeError;
        if let Some(e) = self.lost() {
            return Some(Err(PipeError::SessionLost(e)));
        }
        let Some(a) = self.att(pipe.0).filter(|a| !a.unattached()) else {
            return Some(Err(PipeError::UnknownPipe));
        };
        if a.failed() {
            return Some(Err(PipeError::Failed(
                a.failure().unwrap_or(PipeFailure::Aborted),
            )));
        }
        if pipe.0 == 0 {
            // The bootstrap pair joins with establishment.
            return self.is_established().then_some(Ok(()));
        }
        match (a.out(), a.inp()) {
            (Some(o), _) if o.confirmed() => Some(Ok(())),
            (Some(o), _) => (!o.is_live()).then(|| Err(PipeError::Failed(PipeFailure::Aborted))),
            (None, Some(i)) => (i.state() != InState::Joining).then_some(Ok(())),
            (None, None) => Some(Err(PipeError::UnknownPipe)),
        }
    }

    /// Whether the pipe ended: `Ok` once none of its halves is live any
    /// more (closed or ended) or the session no longer knows it,
    /// [`PipeError::Failed`](super::PipeError::Failed) when it failed,
    /// [`PipeError::SessionLost`](super::PipeError::SessionLost) when the
    /// session ended while a half was live; `None` while a half is live.
    /// A pipe that failed and was retired since reads as `Ok`.
    pub fn pipe_closed(&self, pipe: PipeId) -> Option<Result<(), super::PipeError>> {
        use super::PipeError;
        let Some(a) = self.att(pipe.0).filter(|a| !a.unattached()) else {
            return Some(Ok(()));
        };
        if a.failed() {
            return Some(Err(PipeError::Failed(
                a.failure().unwrap_or(PipeFailure::Aborted),
            )));
        }
        let out_live = a
            .out()
            .is_some_and(|o| !matches!(o.state(), OutState::Failed | OutState::Closed));
        let in_live = a.inp().is_some_and(|i| i.state() != InState::Ended);
        if !out_live && !in_live {
            return Some(Ok(()));
        }
        self.lost().map(|e| Err(PipeError::SessionLost(e)))
    }

    /// One attachment's quality, `None` when unknown.
    pub fn pipe_info(&self, pipe: PipeId) -> Option<PipeStats> {
        let a = self.att(pipe.0).filter(|a| !a.unattached())?;
        Some(self.info_of(a, self.mp.as_ref().and_then(|_| self.gate())))
    }

    /// The RTT estimates of an attachment's outbound pipe and their source:
    /// source, smoothed RTT, variation, minimum and
    /// latest sample, all `None` before the first sample.
    pub(super) fn rtt_of(&self, o: Option<&OutPipe>) -> RttView {
        let none = RttView::default();
        if self.mp.is_some() {
            let Some(o) = o else {
                return none;
            };
            let min = o.min_rtt();
            let est = o.est();
            return if est.sampled {
                RttView {
                    source: Some(RttSource::Ack),
                    srtt: Some(est.srtt),
                    rttvar: Some(est.rttvar),
                    min,
                    latest: est.latest,
                }
            } else if let Some(r) = o.carrier_rtt() {
                RttView {
                    source: Some(RttSource::Kernel),
                    srtt: Some(r),
                    min,
                    ..none
                }
            } else {
                none
            };
        }
        // A single pipe: its acknowledgements, the carrier, or the
        // session's QX_PING and credit-loop samples.
        let min = self.carrier_rtt.or(self.loop_min.get());
        if let Some(est) = o
            .map(OutPipe::est)
            .filter(|e| self.pipe_ack.is_some() && e.sampled)
        {
            RttView {
                source: Some(RttSource::Ack),
                srtt: Some(est.srtt),
                rttvar: Some(est.rttvar),
                min,
                latest: est.latest,
            }
        } else if let Some(r) = self.carrier_rtt {
            RttView {
                source: Some(RttSource::Kernel),
                srtt: Some(r),
                min,
                ..none
            }
        } else if let Some(r) = self.srtt.or(self.loop_min.get()) {
            RttView {
                source: Some(RttSource::Ping),
                srtt: Some(r),
                rttvar: self.ping_rttvar(),
                min,
                latest: self.ping_latest(),
            }
        } else {
            none
        }
    }

    fn info_of(&self, a: &Attachment, gate: Option<super::tier::Gate>) -> PipeStats {
        let now = self.now;
        let o = a.out();
        let i = a.inp();
        let q = o.and_then(OutPipe::quality).unwrap_or_default();
        let single = self.mp.is_none();
        // Rates, positions acknowledged and one-way delays need
        // acknowledgements.
        let acked = o.filter(|_| !single || self.pipe_ack.is_some());
        let rtt = self.rtt_of(o);
        let since = |t: Instant| now.saturating_duration_since(t);
        let tier = a.tier();
        let (send_priority, send_priority_source) = tier.send_priority();
        let created = [q.joined_at, i.map(InPipe::opened_at)]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(now);
        PipeStats {
            pipe: PipeId(a.id()),
            local: a.joiner_local(),
            fate_group: a.fate_group(),
            inbound: i.map(|p| p.state().public()),
            outbound: o.map(OutPipe::public_state),
            attached_for: since(created),
            suspect_count: q.suspect_count,
            failure_count: u64::from(a.failed()),
            failure: a.failure(),
            label: a.label().cloned(),
            send_priority,
            send_priority_source,
            standby: a.standby(),
            standby_source: tier.standby().1,
            receive_priority: tier.receive_priority(),
            receive_standby: tier.receive_standby(),
            request_seq: tier.seq(),
            peer_request: tier
                .peer_request()
                .map(|(standby, priority)| PipeRequest { priority, standby }),
            weight: tier.weight(),
            probation_until: self.probation_end(a),
            in_probation: q.in_probation,
            revalidating: q.revalidating,
            // A single pipe carries everything while the session lives.
            eligible: if single {
                o.is_some_and(OutPipe::is_live)
            } else {
                gate.is_some_and(|g| g.admits(a))
            },
            rtt_source: rtt.source,
            smoothed_rtt: rtt.srtt,
            min_rtt: rtt.min,
            rttvar: rtt.rttvar,
            one_way_delay: acked.filter(|o| o.est().sampled).map(|o| self.owd(o)),
            delivery_rate: acked.map(|o| o.est().rate),
            queued_bytes: o.map_or(0, OutPipe::carrier_unsent),
            queue_delay: acked.map(OutPipe::queue_delay),
            writable: o.is_some_and(OutPipe::writable),
            saturated: !single && o.is_some() && self.tier_saturated(a),
            bytes_in_flight: acked.map(OutPipe::in_flight),
            bytes_sent: o.map_or(0, OutPipe::bytes_written),
            bytes_received: i.map_or(0, InPipe::bytes_received),
            bytes_acked: acked.map(OutPipe::acked),
            records_sent: o.map_or(0, OutPipe::records),
            records_received: i.map_or(0, InPipe::records),
            bytes_reinjected: q.bytes_reinjected,
            bytes_duplicate_received: i.map_or(0, InPipe::dup_bytes),
            bytes_opportunistic: q.bytes_opportunistic,
            bytes_redundant: q.bytes_redundant,
            pings_sent: q.pings_sent,
            pings_answered: q.pings_answered,
            since_last_ack: acked.map(|o| since(o.last_advance())),
            since_last_receive: i
                .filter(|p| p.records() > 0)
                .map(|p| since(p.last_record())),
            lanes_out: o.map_or(0, OutPipe::lane_count),
            lanes_in: i.map_or(0, InPipe::lane_count),
            lanes_refused: o.and_then(OutPipe::lanes).map_or(0, |l| l.refused()),
            lanes: super::lanes::lane_infos(o, i),
        }
    }

    /// A write call's progress on an outbound pipe: the one report of both
    /// driver styles, from which the
    /// pipe's write-stall clock runs (MULTIPATH.md Section 7.1) and the
    /// bottleneck that marks its rate samples comes. The scheduler uses only
    /// pipes whose carrier did not refuse
    /// bytes; a pipe whose call runs longer than its size takes at its
    /// rate, or whose carrier refuses bytes while bytes wait for it, is
    /// suspected.
    pub fn pipe_write(&mut self, at: impl Into<LaneId>, write: PipeWrite, now: Instant) {
        let at = at.into();
        let pipe = at.pipe;
        if at.lane.0 != 0 {
            self.lane_write(pipe.0, at.lane.0, &write, now);
            return;
        }
        if self.mp.is_none() {
            // Outside multipath only rate samples depend on it, and only
            // with pipe acknowledgement: no scan of the scheduled streams
            // otherwise.
            let has_data = self.pipe_ack.is_some() && self.data_waiting();
            if let Some(o) = self.out_mut(pipe.0) {
                o.write_progress(&write, has_data, false, now);
            }
            return;
        }
        self.tick(now);
        let has_data = self.has_ready_stream_data();
        let waits = write.refused && write.end.is_some() && self.bytes_wait_for(pipe.0);
        if let Some(o) = self.out_mut(pipe.0) {
            o.write_progress(&write, has_data, waits, now);
        }
    }

    /// Declares whether the pipe's carrier has a low-water mark
    /// (TCP_NOTSENT_LOWAT, [`SessionCore::notsent_lowat`]), an optional carrier
    /// capability: the carrier queue limiter does not
    /// pace it. When it stops taking bytes it may
    /// still hold up to the mark plus the last write, which the driver
    /// reports as U ([`SessionCore::pipe_write`], MULTIPATH.md Section 7.1);
    /// carriers that report their unsent bytes ([`SessionCore::set_pipe_unsent`])
    /// are judged by that count instead. Drivers declare it before the
    /// pipe's first write.
    pub fn set_pipe_low_water(&mut self, pipe: PipeId, on: bool) {
        let now = self.now;
        if let Some(o) = self.out_mut(pipe.0)
            && o.set_low_water(on)
        {
            o.unpace(now);
            self.quality_sample(pipe.0, now);
        }
    }

    /// The carrier's unsent bytes (for example `tcpi_notsent_bytes`), when
    /// the adapter can report them: reporting them
    /// declares the capability, and the carrier queue limiter no longer
    /// paces the pipe.
    pub fn set_pipe_unsent(&mut self, at: impl Into<LaneId>, bytes: u64, now: Instant) {
        let at = at.into();
        let pipe = at.pipe.0;
        self.tick(now);
        if let Some(o) = self.out_mut(pipe)
            && o.set_lane_unsent(at.lane.0, bytes, now)
        {
            o.unpace(now);
            self.quality_sample(pipe, now);
        }
    }

    // ---- failure detection (MULTIPATH.md Section 7.1) ----------------------------

    /// T_suspect, T_fail and D of an outbound pipe.
    pub(super) fn limits(&self, o: &OutPipe) -> (Duration, Duration, Duration) {
        let mad = self.mp().peer_mad;
        let base = o.est().pto(mad) + o.queue_term();
        let t_suspect = o.detection().0.max(base * 2);
        let t_fail = Duration::from_secs(2).max(base * 8);
        let dead = self
            .idle_timeout()
            .map_or(Duration::from_secs(15), |t| t / 2);
        (t_suspect, t_fail, t_fail.max(dead))
    }

    /// The reference time of a write stall, if the pipe has one.
    fn write_stall_from(&self, id: u64, o: &OutPipe) -> Option<Instant> {
        o.write_stall_from(|| self.bytes_wait_for(id).then_some(self.now))
    }

    /// Whether bytes wait for an unwritable pipe (MULTIPATH.md Section
    /// 7.1): stream data within its flow-control limits is bound to it, or
    /// the endpoint has stream data within its limits or reinjection (whose
    /// bytes were charged to session credit when first sent) to send and
    /// it is the only live outbound pipe that may carry them: the only one neither suspect nor penalized, standby pipes and
    /// lower tiers included. Another such pipe counts whether or not its
    /// carrier takes bytes at the moment: two pipes that a bulk sender
    /// keeps full do not wait for each other, and a pipe whose path went
    /// dark is found by its ack stall; a suspect or penalized pipe is
    /// never waited for on account of that data.
    pub(super) fn bytes_wait_for(&self, id: u64) -> bool {
        if self.data_bound_to(id) {
            return true;
        }
        if !self.out_ref(id).is_some_and(OutPipe::may_carry) {
            return false;
        }
        let others = self
            .atts
            .iter()
            .any(|a| a.id() != id && a.out().is_some_and(OutPipe::may_carry));
        if others {
            return false;
        }
        self.has_ready_stream_data() || self.ledger().is_some_and(|l| l.any_lost())
    }

    /// Whether stream data that can be sent is bound to pipe `id`
    /// (`affinity`).
    fn data_bound_to(&self, id: u64) -> bool {
        if self.streams.send_flow().used >= self.streams.send_flow().max {
            return false;
        }
        self.streams.queue().keys().any(|k| {
            self.streams.send(k).is_some_and(|s| {
                s.mp()
                    .bound
                    .is_some_and(|b| b.pipe == id && b.move_to.is_none())
                    && (!s.buf.is_empty() || s.preamble_left > 0)
                    && s.offset < s.max_data
            })
        })
    }

    /// Records since when bytes wait for unwritable pipes (called before
    /// the clock moves).
    pub(super) fn refresh_waiting(&mut self) {
        if self.mp.is_none() {
            return;
        }
        let now = self.now;
        for i in 0..self.atts.len() {
            let a = self.atts.at(i);
            let id = a.id();
            if a.out().is_some_and(OutPipe::refusing_unclocked)
                && self.bytes_wait_for(id)
                && let Some(o) = self.atts.at_mut(i).out_mut()
            {
                o.refused_since(now);
            }
        }
    }

    /// The stall reference of a pipe: the earlier of its ack and write
    /// stalls (ack stalls only while an inbound pipe is live).
    fn stall_from(&self, id: u64, o: &OutPipe, inbound_live: bool) -> Option<Instant> {
        let ack = if inbound_live {
            o.ack_stall_from(self.mp().detect_from)
        } else {
            None
        };
        match (ack, self.write_stall_from(id, o)) {
            (Some(a), Some(w)) => Some(a.min(w)),
            (a, w) => a.or(w),
        }
    }

    /// Whether another outbound pipe than `id` is ACTIVE.
    fn other_active(&self, id: u64) -> bool {
        self.atts.iter().any(|a| {
            a.id() != id
                && a.out()
                    .is_some_and(|o| o.state() == OutState::Active && !o.out_closed())
        })
    }

    /// The deadline at which a pipe's state changes next, and the change.
    fn pipe_deadline(&self, a: &Attachment, inbound_live: bool, now: Instant) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        // A deadline beyond the clock's range never comes.
        let mut at = |t: Option<Instant>| {
            if let Some(t) = t {
                next = Some(next.map_or(t, |n: Instant| n.min(t)));
            }
        };
        if let Some(o) = a.out().filter(|o| o.is_live()) {
            let (t_suspect, t_fail, d) = self.limits(o);
            if !o.confirmed() {
                at(o.joined_at().checked_add(self.config.handshake_timeout));
            }
            if let Some(from) = self.stall_from(a.id(), o, inbound_live) {
                match o.state() {
                    OutState::Joining | OutState::Active => at(from.checked_add(t_suspect)),
                    OutState::Suspect if o.confirmed() => {
                        let (fail, dead) = self.fail_limits(a.id(), o, t_suspect, t_fail, d);
                        if let Some(f) = fail {
                            at(from.checked_add(f));
                        }
                        at(from.checked_add(dead));
                    }
                    OutState::Draining if !o.suspect_mark() => at(from.checked_add(t_suspect)),
                    _ => {}
                }
            }
            if let Some(since) = o.drain_since() {
                at(since.checked_add(t_fail));
            }
            // Probes of idle pipes; an owed PIPE_PING waits only for the
            // rate limit (writing it is the transmit path's business).
            if o.ping_wanted().is_none() {
                if o.state() != OutState::Draining {
                    at(self.probe_due(a, o, now));
                }
            } else if let Some(slot) = self
                .mp()
                .pings
                .next_slot(now)
                .max(self.requests.next_slot(now))
                .filter(|&t| t > now)
            {
                at(Some(slot));
            }
            // Probation: its end changes the tier gate, and its probes.
            // The end of the reinjection hold lets reinjected data go.
            at(o.reinject_hold_after(now));
            // A due end or probe fires at once: nothing else ends a
            // probation.
            at(self.probation_deadline(a, now));
        }
        if let Some(p) = a.inp() {
            at(p.linger_until().filter(|_| p.is_live()));
            if p.state() == InState::Joining {
                at(p.opened_at().checked_add(self.config.handshake_timeout));
            }
            if let Some(limit) = self.silence_limit(a) {
                at(p.last_progress().checked_add(limit));
            }
        }
        at(a.retire_at());
        next
    }

    /// When the outbound pipe `o` of `a` is due for a PIPE_PING
    /// (MULTIPATH.md Section 7.1), measured from its last ack-eliciting
    /// byte or from when it became ACTIVE; `None` when it is never probed
    /// for idleness.
    ///
    /// The probe interval is the 15 s constant for an attachment without an
    /// outbound direction at the peer (its inbound silence rule relies on
    /// it) and `probe_interval` otherwise (zero: none). While the session
    /// is busy, a standby pipe and a pipe of a less-preferred tier than the
    /// most-preferred usable one are probed every `standby_probe` when that
    /// is shorter. The first probe after the pipe becomes usable, and after
    /// a quiet session becomes busy, comes earlier by the session's phase; a
    /// deadline beyond the clock's range
    /// never comes.
    fn probe_due(&self, a: &Attachment, o: &OutPipe, now: Instant) -> Option<Instant> {
        let last = o.last_eliciting();
        let idle = if a.inp().is_none() {
            Some(PROBE_INTERVAL)
        } else {
            Some(self.config.probe_interval).filter(|d| !d.is_zero())
        };
        let backup = self.config.standby_probe;
        if !backup.is_zero()
            && idle.is_none_or(|i| backup < i)
            && now < self.mp().busy_until
            && self.is_backup(a)
        {
            return last.checked_add(backup);
        }
        let idle = idle?;
        let phase = if o.phase_pending() {
            Duration::try_from_secs_f64(idle.as_secs_f64() * self.mp().probe_phase)
                .unwrap_or_default()
        } else {
            Duration::ZERO
        };
        last.checked_add(idle.saturating_sub(phase))
    }

    /// A standby pipe, or a pipe of a less-preferred tier than the
    /// most-preferred tier with a usable pipe.
    fn is_backup(&self, a: &Attachment) -> bool {
        a.standby()
            || self
                .views()
                .tiers()
                .first()
                .is_some_and(|t| a.send_tier() > t.priority)
    }

    /// A traffic frame (STREAM, RESET_STREAM, RESET_STREAM_AT,
    /// STOP_SENDING or DATAGRAM) was sent or received: the session is busy
    /// for the busy window. A quiet session that becomes busy probes at
    /// once each backup pipe without an ack-eliciting byte for
    /// `standby_probe` (MULTIPATH.md Section 7.1), and the next idle probe
    /// of every pipe takes the session's phase again.
    pub(super) fn note_traffic(&mut self, now: Instant) {
        let Some(mp) = self.mp.as_deref_mut() else {
            return;
        };
        let quiet = now >= mp.busy_until;
        mp.busy_until = now + BUSY_WINDOW;
        if !quiet {
            return;
        }
        for o in self.atts.outs_mut() {
            o.rephase();
        }
        let backup = self.config.standby_probe;
        if backup.is_zero() {
            return;
        }
        for i in 0..self.atts.len() {
            let a = self.atts.at(i);
            let due = a.out().is_some_and(|o| {
                o.is_live()
                    && o.state() != OutState::Draining
                    && o.ping_wanted().is_none()
                    && o.last_eliciting()
                        .checked_add(backup)
                        .is_some_and(|t| now >= t)
            });
            if due
                && self.is_backup(a)
                && let Some(o) = self.atts.at_mut(i).out_mut()
            {
                o.probe(now);
            }
        }
    }

    /// The T_fail and D limits that apply to a suspect pipe: T_fail only
    /// with another ACTIVE pipe or with resume; the last usable pipe uses
    /// max(T_suspect, DeadTimeout) when set.
    fn fail_limits(
        &self,
        id: u64,
        o: &OutPipe,
        t_suspect: Duration,
        t_fail: Duration,
        d: Duration,
    ) -> (Option<Duration>, Duration) {
        let other = self.other_active(id);
        if !other && let Some(dt) = o.detection().1 {
            let limit = t_suspect.max(dt);
            return (None, limit);
        }
        if other || self.mp().resume {
            (Some(t_fail), d)
        } else {
            (None, d)
        }
    }

    /// The inbound silence limit L_in of an attachment's inbound pipe, when
    /// the rule applies (MULTIPATH.md Section 7.3).
    fn silence_limit(&self, a: &Attachment) -> Option<Duration> {
        let p = a.inp()?;
        if p.state() != InState::Open || a.out().is_some() {
            return None;
        }
        let n_in = self.atts.iter().filter(|x| x.in_live()).count() as u32;
        let srtt_max = self
            .atts
            .outs()
            .filter(|o| o.is_live())
            .map(|o| o.est().srtt)
            .max()
            .unwrap_or(super::pipes::INITIAL_RTT);
        let slack = Duration::from_secs(2)
            .max(srtt_max * 2)
            .max(p.gap().saturating_sub(PROBE_INTERVAL));
        let l_in = PROBE_INTERVAL + Duration::from_millis(125) * n_in + slack;
        if n_in <= 1 {
            // The last live inbound pipe gets the last-usable-pipe patience.
            let pto = self
                .atts
                .outs()
                .filter(|o| o.is_live())
                .map(|o| o.est().pto(self.mp().peer_mad))
                .max()
                .unwrap_or_else(|| {
                    super::pipes::INITIAL_RTT + super::pipes::INITIAL_RTT * 2 + self.mp().peer_mad
                });
            let t_suspect = self.config.suspect_floor.max(pto * 2);
            let t_fail = Duration::from_secs(2).max(pto * 8);
            let dead = self
                .idle_timeout()
                .map_or(Duration::from_secs(15), |t| t / 2);
            let stall = if let Some(dt) = self.config.dead_timeout {
                t_suspect.max(dt)
            } else if self.mp().resume {
                t_fail
            } else {
                t_fail.max(dead)
            };
            return Some(l_in.max(stall));
        }
        Some(l_in)
    }

    /// The next multipath deadline.
    pub(super) fn mp_deadline(&self) -> Option<Instant> {
        let mp = self.mp.as_deref()?;
        if self.state >= State::Closing {
            return None;
        }
        let now = self.now;
        let inbound_live = self.atts.any_in_live();
        let mut next = [
            mp.acks().copy_due().filter(|&t| t > now),
            mp.suspension().deadline(),
            mp.join_backoff.filter(|_| !mp.deferred.is_empty()),
            self.ack_timer(),
            self.opp_deadline(),
            self.tier_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        for a in &self.atts {
            if let Some(t) = self.pipe_deadline(a, inbound_live, now) {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        next
    }

    /// Fires the multipath timers due at `now`.
    pub(super) fn mp_timeout(&mut self, now: Instant) {
        if self.state >= State::Closing {
            return;
        }
        if self.resume_timeout_fired(now) {
            return;
        }
        // Attachments are sorted by identifier; checking one may retire it.
        let mut next = self.atts.first().map(Attachment::id);
        while let Some(id) = next {
            if self.state >= State::Closing {
                return;
            }
            self.check_pipe(id, now);
            next = self.atts.next_after(id);
        }
        self.probation_timers(now);
        self.refresh_tiers();
        self.try_retire(now);
        self.release_deferred_joins(now);
    }

    /// Applies the time-driven transitions of one attachment.
    fn check_pipe(&mut self, id: u64, now: Instant) {
        let inbound_live = self.atts.any_in_live();
        let Some(a) = self.att(id) else {
            return;
        };
        // Outbound.
        if let Some(o) = a.out().filter(|o| o.is_live()) {
            let (t_suspect, t_fail, d) = self.limits(o);
            if !o.confirmed()
                && o.joined_at()
                    .checked_add(self.config.handshake_timeout)
                    .is_some_and(|t| now >= t)
            {
                self.fail_attachment(id, PipeFailure::JoinTimedOut, now);
                self.after_pipe_change(now);
                return;
            }
            if let Some(from) = self.stall_from(id, o, inbound_live) {
                let stalled = now.saturating_duration_since(from);
                match o.state() {
                    OutState::Joining | OutState::Active if stalled >= t_suspect => {
                        self.suspect(id, now);
                    }
                    OutState::Suspect if o.confirmed() => {
                        let (fail, dead) = self.fail_limits(id, o, t_suspect, t_fail, d);
                        if fail.is_some_and(|f| stalled >= f) || stalled >= dead {
                            self.fail_attachment(id, PipeFailure::Stalled, now);
                            self.after_pipe_change(now);
                            return;
                        }
                    }
                    OutState::Draining if !o.suspect_mark() && stalled >= t_suspect => {
                        self.suspect(id, now);
                    }
                    _ => {}
                }
            }
            let Some(o) = self.out_ref(id) else {
                return;
            };
            if let Some(since) = o.drain_since()
                && o.state() == OutState::Draining
                && since.checked_add(t_fail).is_some_and(|t| now >= t)
            {
                // The drain did not complete (Section 8.2 step 3).
                self.fail_attachment(id, PipeFailure::Stalled, now);
                self.after_pipe_change(now);
                return;
            }
            // Idle-pipe probes.
            let a = self.att(id).expect("present");
            let o = a.out().expect("present");
            if o.state() != OutState::Draining
                && o.ping_wanted().is_none()
                && self.probe_due(a, o, now).is_some_and(|due| now >= due)
            {
                self.out_mut(id).expect("present").probe(now);
            }
        }
        // Inbound.
        let Some(a) = self.att(id) else {
            return;
        };
        if let Some(p) = a.inp() {
            if p.is_live() && p.linger_until().is_some_and(|t| now >= t) {
                // Linger after the exchange ends the pipe gracefully.
                let report = self.inp_mut(id).expect("present").end_gracefully();
                self.pipe_event(id, PipeHalf::Inbound);
                if report {
                    self.push_event(CoreEvent::ClosePipe {
                        pipe: PipeId(id),
                        half: PipeHalf::Inbound,
                        abort: false,
                    });
                }
                self.try_retire(now);
                self.after_pipe_change(now);
                return;
            }
            if p.state() == InState::Joining
                && p.opened_at()
                    .checked_add(self.config.handshake_timeout)
                    .is_some_and(|t| now >= t)
            {
                self.fail_attachment(id, PipeFailure::JoinTimedOut, now);
                self.after_pipe_change(now);
                return;
            }
            if let Some(limit) = self.silence_limit(a)
                && p.last_progress()
                    .checked_add(limit)
                    .is_some_and(|t| now >= t)
            {
                self.fail_attachment(id, PipeFailure::Stalled, now);
                self.after_pipe_change(now);
            }
        }
    }

    /// Whether stream data is ready to send and not placed on a pipe
    /// (the bottleneck signal).
    pub(super) fn has_ready_stream_data(&self) -> bool {
        self.streams.data_waiting()
    }
}

/// A credit frame owed again on a second pipe (MULTIPATH.md Section 6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreditCopy {
    /// MAX_DATA.
    Session,
    /// MAX_STREAMS of a direction index.
    Streams(usize),
    /// MAX_STREAM_DATA of a stream.
    Stream(StreamKey),
}
