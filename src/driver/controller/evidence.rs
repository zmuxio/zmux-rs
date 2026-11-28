use std::borrow::Borrow;
use std::time::{Duration, Instant};

use super::{ChangeError, ControllerSnapshot, MemberId, MemberSnapshot, PipeId, SessionTarget};
use crate::driver::handle::{Driver, State};
use crate::{CapacitySnapshot, CarrierConnId, PipeHalf, PipeStats, SessionId};

/// A source measurement used to authorize a replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityMeasurement {
    /// Directional health advisory alone.
    Health,
    /// Current outgoing protocol RTT.
    CurrentRtt,
    /// Same-source protocol baseline.
    BaselineRtt,
    /// Outgoing ACK-delivery interval.
    Delivery,
    /// An outgoing physical interval on this connection and counter epoch.
    Loss(CarrierConnId, u64),
}

/// An immutable reference to evidence from a controller snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityInput {
    session: SessionId,
    binding: u64,
    revision: u64,
    policy: (u64, u64),
    pub(super) member: MemberId,
    pipe: PipeId,
    direction: PipeHalf,
    generation: u64,
    measurement: QualityMeasurement,
    version: u64,
    sampled_at: Instant,
    valid_until: Option<Instant>,
}

impl ControllerSnapshot {
    /// Captures the identity and original expiry of currently projected evidence.
    #[must_use]
    pub fn quality_input(
        &self,
        pipe: PipeId,
        direction: PipeHalf,
        measurement: impl Borrow<QualityMeasurement>,
    ) -> Option<QualityInput> {
        let measurement = measurement.borrow();
        self.evidence
            .iter()
            .find(|input| {
                input.pipe == pipe
                    && input.direction == direction
                    && &input.measurement == measurement
            })
            .cloned()
    }
}

pub(super) fn capture(
    session: SessionId,
    (binding, revision): (u64, u64),
    capacity: CapacitySnapshot,
    members: &[MemberSnapshot],
    paths: &[PipeStats],
) -> std::sync::Arc<[QualityInput]> {
    let mut inputs = Vec::new();
    for member in members {
        for pipe in &member.pipes {
            let Some(path) = paths.iter().find(|p| p.pipe == *pipe) else {
                continue;
            };
            for (direction, evidence) in [
                (PipeHalf::Outbound, path.health.send.evidence),
                (PipeHalf::Inbound, path.health.receive.evidence),
            ] {
                let Some(evidence) = evidence else { continue };
                let mut add = |measurement, version, sampled_at, valid_until| {
                    inputs.push(QualityInput {
                        session,
                        binding,
                        revision,
                        policy: policy_stamp(capacity),
                        member: member.id,
                        pipe: *pipe,
                        direction,
                        generation: evidence.generation,
                        measurement,
                        version,
                        sampled_at,
                        valid_until,
                    });
                };
                add(QualityMeasurement::Health, 0, evidence.since, None);
                if direction == PipeHalf::Outbound {
                    let loss = path.carrier_loss.as_ref().map(|loss| {
                        QualityMeasurement::Loss(loss.connection.clone(), loss.generation)
                    });
                    for measurement in [
                        QualityMeasurement::CurrentRtt,
                        QualityMeasurement::BaselineRtt,
                        QualityMeasurement::Delivery,
                    ]
                    .into_iter()
                    .chain(loss)
                    {
                        if let Some((at, valid_for, version)) = measurement.sample(path)
                            && let Some(until) = at.checked_add(valid_for)
                        {
                            add(measurement, version, at, Some(until));
                        }
                    }
                }
            }
        }
    }
    inputs.into()
}

impl QualityMeasurement {
    fn sample(&self, path: &PipeStats) -> Option<(Instant, Duration, u64)> {
        match self {
            Self::Health => None,
            Self::CurrentRtt => path.protocol_rtt.map(|(at, _, age)| (at, age, 0)),
            Self::BaselineRtt => path.protocol_min_rtt.map(|(at, _, age)| (at, age, 0)),
            Self::Delivery => path
                .ack_delivery
                .map(|s| (s.end, s.valid_for, path.delivery_version)),
            Self::Loss(connection, generation) => path
                .carrier_loss
                .as_ref()
                .filter(|loss| &loss.connection == connection && loss.generation == *generation)
                .map(|loss| {
                    (
                        loss.at,
                        super::super::carrier_stats::LOSS_VALIDITY,
                        loss.version,
                    )
                }),
        }
    }
}

fn policy_stamp(capacity: CapacitySnapshot) -> (u64, u64) {
    (capacity.policy_revision, capacity.auth_generation)
}

impl QualityInput {
    /// Original observation time, or the start of the referenced health evidence.
    #[must_use]
    pub const fn sampled_at(&self) -> Instant {
        self.sampled_at
    }

    /// Exclusive end of validity, if referencing a timed measurement.
    #[must_use]
    pub const fn valid_until(&self) -> Option<Instant> {
        self.valid_until
    }

    pub(super) fn valid(
        &self,
        session: SessionId,
        capacity: CapacitySnapshot,
        members: &[MemberSnapshot],
        paths: &[PipeStats],
        now: Instant,
    ) -> bool {
        if self.session != session
            || self.policy != policy_stamp(capacity)
            || now < self.sampled_at
            || self.valid_until.is_some_and(|until| now >= until)
            || !members
                .iter()
                .any(|m| m.id == self.member && m.pipes.contains(&self.pipe))
        {
            return false;
        }
        let Some(path) = paths.iter().find(|p| p.pipe == self.pipe) else {
            return false;
        };
        let direction = match self.direction {
            PipeHalf::Outbound => path.health.send,
            PipeHalf::Inbound => path.health.receive,
        };
        direction
            .evidence
            .is_some_and(|e| e.generation == self.generation)
            && (self.measurement == QualityMeasurement::Health
                || self
                    .measurement
                    .sample(path)
                    .is_some_and(|(_, _, version)| version == self.version))
    }
}

impl SessionTarget {
    pub(super) fn accepts_evidence<D: Driver>(
        &self,
        state: &State<D>,
        binding: u64,
        revision: u64,
    ) -> bool {
        self.replace
            .iter()
            .flat_map(|intent| &intent.evidence)
            .all(|input| input.binding == binding && input.revision == revision)
            && self.check_evidence(state, None).is_ok()
    }

    pub(super) fn check_evidence<D: Driver>(
        &self,
        state: &State<D>,
        drain: Option<&[MemberId]>,
    ) -> Result<(), ChangeError> {
        let mut inputs = self
            .replace
            .iter()
            .flat_map(|intent| &intent.evidence)
            .filter(|input| drain.is_none_or(|members| members.contains(&input.member)));
        if inputs.clone().next().is_none() {
            return Ok(());
        }
        let members = state.core.members();
        let paths = state.control_paths();
        let now = state.now();
        let capacity = state.capacity();
        if inputs.all(|input| input.valid(state.session_id(), capacity, &members, &paths, now)) {
            Ok(())
        } else {
            Err(ChangeError::StaleDecision)
        }
    }
}
