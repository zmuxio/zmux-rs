//! Directional service and stability, committed by the protocol owner.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::pipes::{InPipe, InState, OutPipe, OutState, PipeHalf};
use super::{CarrierConnId, CoreEvent, Directions, PipeFailure, PipeId, SessionCore, State};

/// A physical failure reported by the carrier that owns a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CarrierFailureReport {
    /// Identity the carrier registered when it joined the session.
    pub connection: CarrierConnId,
    /// Monotonically increasing failure round of that connection.
    pub round: NonZeroU64,
    /// The underlying I/O error classification.
    pub kind: std::io::ErrorKind,
    /// Any authoritative minimum delay before retrying this carrier.
    pub retry_after: Option<Duration>,
}

impl CarrierFailureReport {
    /// Reports a failure with the carrier's connection identity and round.
    #[must_use]
    pub const fn new(
        connection: CarrierConnId,
        round: NonZeroU64,
        kind: std::io::ErrorKind,
    ) -> Self {
        Self {
            connection,
            round,
            kind,
            retry_after: None,
        }
    }
}

/// Physical failure evidence committed by the session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CarrierFailureEvent {
    /// The verified report.
    pub report: CarrierFailureReport,
    /// The local commit time.
    pub at: Instant,
    /// Earliest permitted retry on this clock.
    pub retry_at: Option<Instant>,
}

/// Directions that host topology temporarily makes unsuitable for local service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectionExclusion {
    /// Exclude the local outbound direction.
    pub send: bool,
    /// Exclude the local inbound direction.
    pub receive: bool,
}

const OBSERVATION_GRACE: Duration = Duration::from_secs(10);

/// Continuous healthy time required before an observed pipe can replace service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StabilityPolicy {
    /// Required hold after attachment or the latest recovery. The default is five seconds.
    pub hold_for: Duration,
}

impl Default for StabilityPolicy {
    fn default() -> Self {
        Self {
            hold_for: Duration::from_secs(5),
        }
    }
}

/// Service phase of one local direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipeHealthState {
    /// The attachment has no such direction.
    #[default]
    Absent,
    /// The peer has not attached this direction.
    Joining,
    /// Evidence is incomplete, or a deliberate hold is in progress.
    Unknown,
    /// Current-round progress was observed.
    Usable,
    /// Effective service fault or topology exclusion.
    Unavailable,
    /// This direction is being retired gracefully.
    Draining,
    /// This direction ended.
    Ended,
}

/// Why a direction is in its current service phase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipeHealthReason {
    /// No direction is present.
    #[default]
    None,
    /// The peer has not attached the pipe.
    AwaitAttachment,
    /// Observing the initial attachment.
    ObserveJoin,
    /// The initial observation grace elapsed without service evidence.
    /// The direction's health remains unknown.
    Idle,
    /// Multipath probation is in progress.
    Probation,
    /// Revalidation was requested locally.
    Revalidate,
    /// Acknowledgements stopped advancing.
    AckStall,
    /// The writer stopped advancing.
    WriteStall,
    /// The inbound silence bound elapsed.
    InboundSilence,
    /// A carrier error or unexpected EOF ended the direction.
    CarrierError,
    /// The carrier ended when more protocol input was required.
    UnexpectedEof,
    /// The Join deadline elapsed.
    JoinTimeout,
    /// Current-round progress was observed.
    Progress,
    /// A graceful drain was requested.
    PlannedDrain,
    /// The session is closing.
    SessionClosing,
    /// A policy or caller canceled the attachment.
    Canceled,
    /// The host excluded the direction due to topology.
    TopologyExcluded,
}

impl PipeHealthReason {
    /// Whether this reason carries evidence of a carrier fault.
    #[must_use]
    pub fn is_fault(self) -> bool {
        matches!(
            self,
            Self::AckStall
                | Self::WriteStall
                | Self::InboundSilence
                | Self::CarrierError
                | Self::UnexpectedEof
                | Self::JoinTimeout
        )
    }
}

/// The current round's evidence for continuing service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipeProofKind {
    /// A probe acknowledged in the current round.
    ProbeRoundTrip,
    /// A validated record arrived on an independent receiving half.
    VerifiedRecord,
}

/// A committed snapshot of one local direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectionHealth {
    /// Service phase.
    pub state: PipeHealthState,
    /// Cause or current suppression.
    pub reason: PipeHealthReason,
    /// Monotonic time at which this phase or its evidence changed.
    pub since: Option<Instant>,
    /// The direction can carry data. Actual writes also require scheduling eligibility.
    pub can_carry: bool,
    /// Generation and continuous service start at this transition.
    pub evidence: Option<DirectionEvidence>,
    /// Evidence recorded for this direction in the current round.
    pub proof_kind: Option<PipeProofKind>,
    /// This direction completed the current stability hold and supplied its evidence.
    pub settled: bool,
}

impl DirectionHealth {
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn recovered(self) -> bool {
        self.state == PipeHealthState::Absent
            || self.can_carry
            || (self.state == PipeHealthState::Unknown
                && self.reason == PipeHealthReason::Probation)
    }
}

/// Both directions of an attachment, at one protocol state commit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipeHealth {
    /// Last directional transition in the session's sequence space.
    pub seq: u64,
    /// Local sending direction.
    pub send: DirectionHealth,
    /// Local receiving direction.
    pub receive: DirectionHealth,
    /// The peer's attachment was confirmed locally.
    pub peer_attached: bool,
    /// Local Join or Establish success time.
    pub joined_at: Option<Instant>,
    /// Local time at which peer attachment was first confirmed.
    pub attached_at: Option<Instant>,
    /// Evidence generation of the local sending direction.
    pub send_evidence: Option<DirectionEvidence>,
    /// Evidence generation of the local receiving direction.
    pub receive_evidence: Option<DirectionEvidence>,
    /// The outbound half passes its local liveness and stability gates.
    pub eligible_for_new_data: bool,
    /// Time since that handshake completed.
    pub since_join: Duration,
    /// Original failure classification, where available.
    pub failure: Option<PipeFailure>,
}

/// The current directional generation and the start of continuous service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectionEvidence {
    /// Sequence of the core commit that began the generation.
    pub generation: u64,
    /// Monotonic start of the current service interval.
    pub since: Instant,
}

impl PipeHealth {
    /// Whether all present directions completed the current stability hold.
    #[must_use]
    pub fn settled(self) -> bool {
        self.peer_attached
            && [self.send, self.receive]
                .into_iter()
                .all(|direction| direction.state == PipeHealthState::Absent || direction.settled)
    }

    /// Whether all present directions can currently serve the member.
    #[must_use]
    pub fn can_carry(self) -> bool {
        self.peer_attached
            && [self.send, self.receive]
                .into_iter()
                .all(|direction| direction.state == PipeHealthState::Absent || direction.can_carry)
    }

    /// Whether a direction of this member is draining or ended.
    #[must_use]
    pub fn ending(self) -> bool {
        [self.send, self.receive].into_iter().any(|direction| {
            matches!(
                direction.state,
                PipeHealthState::Draining | PipeHealthState::Ended
            )
        })
    }
}

/// A directional health transition committed by the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeHealthChange {
    /// Session-wide transition sequence.
    pub seq: u64,
    /// Attachment whose direction changed.
    pub pipe: PipeId,
    /// Local direction that changed.
    pub half: PipeHalf,
    /// Direction before this commit.
    pub before: DirectionHealth,
    /// Direction after this commit.
    pub after: DirectionHealth,
    /// Stable cause of the transition.
    pub reason: PipeHealthReason,
    /// Monotonic commit time.
    pub at: Instant,
    /// Time since local Join or Establish success.
    pub since_join: Duration,
    /// Original pipe failure classification, where available.
    pub failure: Option<PipeFailure>,
    /// Physical evidence provided by the adapter for this fault edge.
    pub physical_failure: Option<Arc<CarrierFailureEvent>>,
}

#[derive(Debug, Default)]
pub(super) struct PhysicalFailures(pub(super) std::collections::HashMap<CarrierConnId, NonZeroU64>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Round {
    since: Instant,
    generation: u64,
    /// Each ping consumes bytes in the 62-bit protocol position space. The
    /// remaining high bits hold the proof and whether a probe was requested.
    ping_and_flags: u64,
}

impl Round {
    const COUNT: u64 = (1 << 62) - 1;
    const REQUESTED: u64 = 1 << 62;
    const PROVED: u64 = 1 << 63;

    fn new(since: Instant, generation: u64, pings: u64) -> Self {
        Self {
            since,
            generation,
            ping_and_flags: pings.min(Self::COUNT),
        }
    }

    fn previous_pings(self) -> u64 {
        self.ping_and_flags & Self::COUNT
    }

    fn proved(self) -> bool {
        self.ping_and_flags & Self::PROVED != 0
    }

    fn proof(self, has_out: bool) -> Option<PipeProofKind> {
        self.proved().then_some(if has_out {
            PipeProofKind::ProbeRoundTrip
        } else {
            PipeProofKind::VerifiedRecord
        })
    }

    fn request(&mut self) -> bool {
        if self.ping_and_flags & (Self::REQUESTED | Self::PROVED) != 0 {
            return false;
        }
        self.ping_and_flags |= Self::REQUESTED;
        true
    }

    fn mark_proved(&mut self) {
        self.ping_and_flags |= Self::PROVED;
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Snapshot {
    seq: u64,
    send: DirectionHealth,
    receive: DirectionHealth,
    joined_at: Option<Instant>,
    attached_after_join: Option<NonZeroU64>,
}

#[derive(Debug, Default)]
pub(super) struct HealthTracker {
    snapshot: Snapshot,
    round: Option<Round>,
    // Paired directions normally share the same generation and proof.
    // Allocate independent state only when their evidence diverges.
    receive_override: Option<Box<Round>>,
    receive_absent: bool,
    receive_flags: u8,
    pub(super) fault: Option<PipeHealthReason>,
    pub(super) exclusion: DirectionExclusion,
    hold_back: bool,
}

impl HealthTracker {
    pub(super) const fn new() -> Self {
        Self {
            snapshot: Snapshot {
                seq: 0,
                send: DirectionHealth {
                    state: PipeHealthState::Absent,
                    reason: PipeHealthReason::None,
                    since: None,
                    can_carry: false,
                    proof_kind: None,
                    evidence: None,
                    settled: false,
                },
                receive: DirectionHealth {
                    state: PipeHealthState::Absent,
                    reason: PipeHealthReason::None,
                    since: None,
                    can_carry: false,
                    proof_kind: None,
                    evidence: None,
                    settled: false,
                },
                joined_at: None,
                attached_after_join: None,
            },
            round: None,
            receive_override: None,
            receive_absent: true,
            receive_flags: 0,
            fault: None,
            exclusion: DirectionExclusion {
                send: false,
                receive: false,
            },
            hold_back: false,
        }
    }

    pub(super) fn outbound_held(&self) -> bool {
        self.hold_back && !self.snapshot.send.settled
    }

    fn rounds(&self, send: bool, receive: bool) -> [Option<Round>; 2] {
        let receive_round = if receive && !self.receive_absent {
            self.receive_override.as_deref().copied().or_else(|| {
                let mut round = self.round?;
                round.ping_and_flags =
                    round.previous_pings() | (u64::from(self.receive_flags) << 62);
                Some(round)
            })
        } else {
            None
        };
        [self.round.filter(|_| send), receive_round]
    }

    fn save_rounds(
        &mut self,
        [send_round, receive_round]: [Option<Round>; 2],
        send: bool,
        receive: bool,
    ) {
        let primary = if send { send_round } else { receive_round };
        self.round = primary;
        self.receive_absent = !receive || receive_round.is_none();
        self.receive_flags = receive_round.map_or(0, |round| (round.ping_and_flags >> 62) as u8);
        let independent = receive_round.filter(|receive| {
            primary.is_none_or(|send| {
                send.since != receive.since
                    || send.generation != receive.generation
                    || send.previous_pings() != receive.previous_pings()
            })
        });
        match (independent, self.receive_override.as_mut()) {
            (Some(round), Some(storage)) => **storage = round,
            (Some(round), None) => self.receive_override = Some(Box::new(round)),
            (None, _) => self.receive_override = None,
        }
    }

    pub(super) fn deadline(&self, hold: Duration) -> Option<Instant> {
        let dirs = [self.snapshot.send, self.snapshot.receive];
        let rounds = self.rounds(
            dirs[0].state != PipeHealthState::Absent,
            dirs[1].state != PipeHealthState::Absent,
        );
        dirs.into_iter()
            .zip(rounds)
            .filter_map(|(dir, round)| {
                if dir.reason == PipeHealthReason::ObserveJoin {
                    self.snapshot.joined_at?.checked_add(OBSERVATION_GRACE)
                } else if dir.can_carry && !dir.settled {
                    round
                        .filter(|round| round.proved())?
                        .since
                        .checked_add(hold)
                } else {
                    None
                }
            })
            .min()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttachmentPhase {
    Closing,
    Draining,
    Joining,
    Revalidating,
    Observing,
}

#[derive(Clone, Copy)]
enum Evidence {
    Initial,
    Idle,
    Current(PipeProofKind),
    Settled(PipeProofKind),
}

#[derive(Clone, Copy)]
enum DirectionPhase {
    Absent,
    Ended,
    Excluded,
    Suspect,
    Probation,
    Open,
}

struct DirectionInputs {
    round: Option<DirectionEvidence>,
    attachment: AttachmentPhase,
    evidence: Evidence,
    failure: Option<PipeFailure>,
    fault: Option<PipeHealthReason>,
}

pub(super) fn covered_directions(health: PipeHealth) -> (Directions, Directions) {
    let covers = |d: DirectionHealth| {
        health.peer_attached
            && matches!(d.state, PipeHealthState::Usable | PipeHealthState::Unknown)
    };
    let send = covers(health.send);
    let receive = covers(health.receive);
    (
        Directions::from_halves(send, receive),
        Directions::from_halves(
            send && health.send.settled,
            receive && health.receive.settled,
        ),
    )
}

impl DirectionInputs {
    fn project(
        &self,
        before: DirectionHealth,
        direction: DirectionPhase,
        can_carry: bool,
        now: Instant,
    ) -> DirectionHealth {
        use PipeHealthReason as R;
        use PipeHealthState as S;
        if matches!(direction, DirectionPhase::Absent) {
            return DirectionHealth::default();
        }
        let (state, reason) = match (self.attachment, direction) {
            (AttachmentPhase::Closing, _) => (S::Ended, R::SessionClosing),
            (_, DirectionPhase::Ended) => {
                let reason = match self.failure {
                    Some(PipeFailure::JoinTimedOut | PipeFailure::CallerDeadline) => R::JoinTimeout,
                    Some(PipeFailure::Aborted | PipeFailure::JoinRefused) => R::Canceled,
                    Some(PipeFailure::Carrier(std::io::ErrorKind::UnexpectedEof)) => {
                        R::UnexpectedEof
                    }
                    Some(PipeFailure::Stalled) => self.fault.unwrap_or(R::InboundSilence),
                    None if self.attachment == AttachmentPhase::Draining => R::PlannedDrain,
                    Some(_) | None => R::CarrierError,
                };
                (S::Ended, reason)
            }
            (AttachmentPhase::Draining, _) => (S::Draining, R::PlannedDrain),
            (AttachmentPhase::Joining, _) => (S::Joining, R::AwaitAttachment),
            (_, DirectionPhase::Suspect) => (S::Unavailable, self.fault.unwrap_or(R::AckStall)),
            (_, DirectionPhase::Excluded) => (S::Unavailable, R::TopologyExcluded),
            (AttachmentPhase::Revalidating, _) => (S::Unknown, R::Revalidate),
            (_, DirectionPhase::Probation) => (S::Unknown, R::Probation),
            _ => match self.evidence {
                Evidence::Initial => (S::Unknown, R::ObserveJoin),
                Evidence::Idle => (S::Unknown, R::Idle),
                Evidence::Current(_) | Evidence::Settled(_) => (S::Usable, R::Progress),
            },
        };
        let can_carry = can_carry
            && matches!(state, S::Unknown | S::Usable)
            && self.attachment != AttachmentPhase::Revalidating;
        let mut after = DirectionHealth {
            state,
            reason,
            since: before.since,
            evidence: self.round,
            can_carry,
            proof_kind: match self.evidence {
                Evidence::Current(kind) | Evidence::Settled(kind) if can_carry => Some(kind),
                _ => None,
            },
            settled: matches!(self.evidence, Evidence::Settled(_)) && can_carry,
        };
        if before != after {
            after.since = Some(now);
        }
        after
    }
}

impl SessionCore {
    pub(crate) fn service_directions(&self, except: &[PipeId]) -> (bool, bool) {
        let (covered, _) = self.coverage_except(except);
        (
            covered.contains(Directions::SEND),
            covered.contains(Directions::RECEIVE),
        )
    }

    pub(super) fn coverage_except(&self, except: &[PipeId]) -> (Directions, Directions) {
        let mut covered = Directions::NONE;
        let mut stable = Directions::NONE;
        for a in &self.atts {
            let id = PipeId(a.id());
            if except.contains(&id) {
                continue;
            }
            let Some(h) = self.pipe_health(id) else {
                continue;
            };
            let (att_covered, att_stable) = covered_directions(h);
            covered = covered.union(att_covered);
            stable = stable.union(att_stable);
            if stable == Directions::BOTH {
                break;
            }
        }
        (covered, stable)
    }

    /// The committed directional health of an existing attachment.
    #[must_use]
    pub fn pipe_health(&self, id: PipeId) -> Option<PipeHealth> {
        let a = self.att(id.0).filter(|a| !a.unattached())?;
        if let Some(health) = a.health().filter(|_| self.mp.is_some()) {
            let h = health.snapshot;
            let [send, receive] = health.rounds(a.out().is_some(), a.inp().is_some());
            let evidence = |round: Round| DirectionEvidence {
                since: round.since,
                generation: round.generation,
            };
            return Some(PipeHealth {
                seq: h.seq,
                send: h.send,
                receive: h.receive,
                joined_at: h.joined_at,
                attached_at: h.attached_after_join.and_then(|delta| {
                    h.joined_at?
                        .checked_add(Duration::from_nanos(delta.get() - 1))
                }),
                send_evidence: send.map(evidence),
                receive_evidence: receive.map(evidence),
                eligible_for_new_data: h.send.can_carry
                    && !health.outbound_held()
                    && a.out().is_some_and(|o| o.usable(false)),
                failure: a.failure(),
                peer_attached: h.joined_at.is_some() && a.peer_attached(),
                since_join: h
                    .joined_at
                    .map_or(Duration::ZERO, |at| self.now.saturating_duration_since(at)),
            });
        }
        let plain = |ended| {
            let (state, reason) = if self.state >= State::Closing {
                (PipeHealthState::Ended, PipeHealthReason::SessionClosing)
            } else if ended {
                (PipeHealthState::Ended, PipeHealthReason::CarrierError)
            } else if self.is_established() {
                (PipeHealthState::Usable, PipeHealthReason::Progress)
            } else {
                (PipeHealthState::Joining, PipeHealthReason::AwaitAttachment)
            };
            DirectionHealth {
                state,
                reason,
                since: None,
                can_carry: state == PipeHealthState::Usable,
                proof_kind: None,
                evidence: None,
                settled: state == PipeHealthState::Usable,
            }
        };
        Some(PipeHealth {
            peer_attached: self.is_established(),
            send: a
                .out()
                .map_or_else(DirectionHealth::default, |o| plain(!o.is_live())),
            receive: a.inp().map_or_else(DirectionHealth::default, |i| {
                plain(i.state() == InState::Ended)
            }),
            failure: a.failure(),
            ..PipeHealth::default()
        })
    }

    /// Temporarily removes the named directions from local service and coverage.
    pub fn set_pipe_topology_exclusion(
        &mut self,
        id: PipeId,
        exclusion: DirectionExclusion,
        now: Instant,
    ) {
        self.tick(now);
        if self.mp.is_none() {
            return;
        }
        let Some(health) = self
            .att_mut(id.0)
            .and_then(super::pipes::Attachment::health_mut)
        else {
            return;
        };
        if health.exclusion == exclusion {
            return;
        }
        let exclude_out = exclusion.send && !health.exclusion.send;
        let restores_service = (health.exclusion.send && !exclusion.send)
            || (health.exclusion.receive && !exclusion.receive);
        health.exclusion = exclusion;
        if exclude_out {
            self.reinject(id.0, now);
        }
        self.sync_pipe_health(id.0);
        if restores_service {
            self.observe_pipe_stability(id, now);
        }
        self.views_changed();
        self.check_standby_takeover();
    }

    /// Hold a replacement behind stable service while gathering its evidence.
    pub fn stage_pipe_stability(&mut self, id: PipeId, now: Instant) {
        if let Some(health) = self
            .att_mut(id.0)
            .and_then(super::pipes::Attachment::health_mut)
            && !health.hold_back
        {
            health.hold_back = true;
            self.views_changed();
            self.check_standby_takeover();
        }
        self.observe_pipe_stability(id, now);
    }

    /// Requests current-round probe evidence for a proposed replacement.
    /// Existing protocol probe pacing and retransmission handle the request.
    pub fn observe_pipe_stability(&mut self, id: PipeId, now: Instant) {
        self.tick(now);
        self.sync_pipe_health(id.0);
        let Some(a) = self.att_mut(id.0) else { return };
        let (send, receive) = (a.out().is_some(), a.inp().is_some());
        if !send {
            return;
        }
        let Some(health) = a.health_mut() else { return };
        let mut rounds = health.rounds(send, receive);
        let mut request = false;
        for round in rounds.iter_mut().flatten() {
            request |= round.request();
        }
        if request {
            health.save_rounds(rounds, send, receive);
            if let Some(out) = a.out_mut() {
                out.want_ping(now);
            }
        }
    }

    pub(super) fn sync_all_pipe_health(&mut self) {
        if self.mp.is_some() {
            for i in 0..self.atts.len() {
                self.sync_pipe_health(self.atts.at(i).id());
            }
        }
    }

    pub(super) fn health_timeouts(&mut self) {
        if self.mp.is_some() {
            for i in 0..self.atts.len() {
                let a = self.atts.at(i);
                if a.health()
                    .and_then(|h| h.deadline(self.config.stability.hold_for))
                    .is_some_and(|due| due <= self.now)
                {
                    self.sync_pipe_health(a.id());
                }
            }
        }
    }

    pub(super) fn health_proof(&mut self, id: u64, half: PipeHalf, acked_ping: Option<u64>) {
        let now = self.now;
        let matched_return = self.rx == id;
        let Some(a) = self.att_mut(id) else { return };
        let (send, receive) = (a.out().is_some(), a.inp().is_some());
        let Some(health) = a.health_mut() else { return };
        let mut rounds = health.rounds(send, receive);
        let mut changed = false;
        for (i, round) in rounds.iter_mut().enumerate() {
            let Some(round) = round.as_mut().filter(|r| !r.proved()) else {
                continue;
            };
            match half {
                PipeHalf::Inbound if i == 1 && !send => {
                    round.mark_proved();
                    round.since = now;
                    changed = true;
                }
                PipeHalf::Outbound
                    if (i == 0 || matched_return)
                        && acked_ping.is_some_and(|ping| ping > round.previous_pings()) =>
                {
                    round.mark_proved();
                    changed = true;
                }
                _ => {}
            }
        }
        if changed {
            health.save_rounds(rounds, send, receive);
            self.sync_pipe_health(id);
        }
    }

    pub(super) fn sync_pipe_health(&mut self, id: u64) {
        let Some(i) = self.att_index(id).filter(|_| self.mp.is_some()) else {
            return;
        };
        let physical_failure = self
            .applying_carrier_failure()
            .filter(|event| self.atts.at(i).physical_connection() == Some(&event.report.connection))
            .cloned();
        let generation = self.mp().health_seq.saturating_add(1);
        let a = self.atts.at_mut(i);
        if a.unattached() {
            return;
        }
        let now = self.now;
        let closing = self.state >= State::Closing || self.error.is_some();
        let joined = a.joined() || id == 0;
        let attached = joined && a.peer_attached();
        let failure = a.failure();
        let draining = a.draining();
        let out = a.out().map(OutPipe::state);
        let recv = a.inp().map(InPipe::state);
        let probation = a.out().is_some_and(OutPipe::in_probation);
        let revalidating = a.out().is_some_and(OutPipe::revalidating);
        let pings = a.out().map_or(0, OutPipe::pings_sent);
        // A blocked-flow penalty changes scheduling eligibility. The
        // direction still provides service in its current health generation.
        let out_can_carry = a.out().is_some_and(OutPipe::takes_new_data) && !probation;
        let Some(h) = a.health_mut() else { return };
        let before = h.snapshot;
        let was_held = h.outbound_held();
        if joined && h.snapshot.joined_at.is_none() {
            h.snapshot.joined_at = Some(now);
        }
        if attached
            && h.snapshot.attached_after_join.is_none()
            && let Some(joined) = h.snapshot.joined_at
        {
            let ns =
                u64::try_from(now.saturating_duration_since(joined).as_nanos()).unwrap_or(u64::MAX);
            h.snapshot.attached_after_join = NonZeroU64::new(ns.saturating_add(1));
        }
        let active = attached && !closing && !draining && failure.is_none();
        let healthy = [
            active && !revalidating && !h.exclusion.send && out == Some(OutState::Active),
            active && !h.exclusion.receive && recv == Some(InState::Open),
        ];
        let mut rounds = h.rounds(out.is_some(), recv.is_some());
        let new_send_round = healthy[0] && rounds[0].is_none();
        for (round, ready) in rounds.iter_mut().zip(healthy) {
            if ready {
                round.get_or_insert_with(|| Round::new(now, generation, pings));
            } else {
                *round = None;
            }
        }
        if before.send.can_carry && (!healthy[0] || revalidating) {
            h.hold_back = true;
        }
        let mut needs_ping = false;
        if h.hold_back && healthy[0] {
            for round in rounds.iter_mut().flatten() {
                needs_ping |= round.request();
            }
        }
        h.save_rounds(rounds, out.is_some(), recv.is_some());
        let since_join = h
            .snapshot
            .joined_at
            .map_or(Duration::ZERO, |at| now.saturating_duration_since(at));
        let phase = if closing {
            AttachmentPhase::Closing
        } else if draining {
            AttachmentPhase::Draining
        } else if !attached {
            AttachmentPhase::Joining
        } else {
            AttachmentPhase::Observing
        };
        let inputs = |round: Option<Round>, revalidating| {
            let evidence = match round
                .and_then(|round| Some((round.since, round.proof(out.is_some())?)))
            {
                Some((since, proof))
                    if now.saturating_duration_since(since) >= self.config.stability.hold_for =>
                {
                    Evidence::Settled(proof)
                }
                Some((_, proof)) => Evidence::Current(proof),
                None if since_join < OBSERVATION_GRACE => Evidence::Initial,
                None => Evidence::Idle,
            };
            DirectionInputs {
                round: round.map(|r| DirectionEvidence {
                    generation: r.generation,
                    since: r.since,
                }),
                attachment: if revalidating && phase == AttachmentPhase::Observing {
                    AttachmentPhase::Revalidating
                } else {
                    phase
                },
                evidence,
                failure,
                fault: h.fault,
            }
        };
        let out_phase = match out {
            None => DirectionPhase::Absent,
            Some(OutState::Closed | OutState::Failed) => DirectionPhase::Ended,
            Some(_) if failure.is_some() => DirectionPhase::Ended,
            Some(OutState::Suspect) => DirectionPhase::Suspect,
            Some(_) if h.exclusion.send => DirectionPhase::Excluded,
            Some(_) if probation => DirectionPhase::Probation,
            Some(_) => DirectionPhase::Open,
        };
        let in_phase = match recv {
            None => DirectionPhase::Absent,
            Some(InState::Ended) => DirectionPhase::Ended,
            Some(_) if failure.is_some() => DirectionPhase::Ended,
            Some(_) if h.exclusion.receive => DirectionPhase::Excluded,
            Some(_) => DirectionPhase::Open,
        };
        h.snapshot.send =
            inputs(rounds[0], revalidating).project(before.send, out_phase, out_can_carry, now);
        h.snapshot.receive = inputs(rounds[1], false).project(
            before.receive,
            in_phase,
            recv == Some(InState::Open),
            now,
        );
        let mut next = h.snapshot;
        let released_hold = was_held != h.outbound_held();
        if let Some(out) = a.out_mut() {
            if new_send_round {
                out.reset_delivery_proof();
            }
            if needs_ping {
                out.want_ping(now);
            }
        }
        for (half, before, after) in [
            (PipeHalf::Outbound, before.send, next.send),
            (PipeHalf::Inbound, before.receive, next.receive),
        ] {
            if before == after {
                continue;
            }
            self.mp_mut().health_seq += 1;
            next.seq = self.mp().health_seq;
            self.push_event(CoreEvent::PipeHealthChanged(Box::new(PipeHealthChange {
                seq: next.seq,
                pipe: PipeId(id),
                half,
                before,
                after,
                reason: after.reason,
                at: now,
                since_join,
                failure,
                physical_failure: after
                    .reason
                    .is_fault()
                    .then(|| physical_failure.clone())
                    .flatten(),
            })));
        }
        if let Some(h) = self.atts.at_mut(i).health_mut() {
            h.snapshot = next;
        }
        if released_hold {
            self.views_changed();
            if self.state < State::Closing && self.error.is_none() {
                self.check_standby_takeover();
            }
        }
    }
}
