//! Local capacity and authorization policy under the session owner.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use super::{AuthorizeJoin, InvalidConfig, SessionCore, SessionError, State};

/// Local scheduling preferences for one member direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPreference {
    /// Smaller tiers serve first.
    pub tier: u64,
    /// Reserved for fallback until needed.
    pub standby: bool,
    /// Relative weight. Zero is a deliberate setting.
    pub weight: u64,
}

impl Default for PathPreference {
    fn default() -> Self {
        Self {
            tier: 0,
            standby: false,
            weight: 1,
        }
    }
}

/// Host-assigned identity of a candidate within a controller domain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateId(pub Arc<str>);

impl From<&str> for CandidateId {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

/// Stable, session-local identity of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberId(pub u64);

/// A member projected from the session owner's attachment state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberSnapshot {
    /// Stable identity.
    pub id: MemberId,
    /// Explicitly registered candidate, when known.
    pub candidate: Option<CandidateId>,
    /// Directions the original member promised.
    pub expected: Directions,
    /// Currently indexed attachment identifiers.
    pub pipes: Vec<super::PipeId>,
    /// Current directions of service.
    pub covered: Directions,
    /// Directions with current evidence that have completed their hold.
    pub stable: Directions,
    /// Every promised attachment is confirmed and provides its directions.
    pub complete: bool,
}

#[derive(Debug, Clone)]
pub(super) struct MemberBinding {
    pub(super) id: MemberId,
    pub(super) candidate: Option<CandidateId>,
    pub(super) expected: Directions,
    pub(super) attachments: usize,
}

/// Local directions of service, which can be combined.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Directions(u8);

impl Directions {
    /// Neither direction.
    pub const NONE: Self = Self(0);
    /// The local send direction.
    pub const SEND: Self = Self(1);
    /// The local receive direction.
    pub const RECEIVE: Self = Self(2);
    /// Both local directions.
    pub const BOTH: Self = Self(3);

    /// Whether all the requested directions are present.
    #[must_use]
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }

    /// Combines the directions from two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the directions absent from this set.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub(super) const fn from_halves(send: bool, receive: bool) -> Self {
        Self((send as u8) | (receive as u8) << 1)
    }
}

/// A view of one session's local limits and occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CapacitySnapshot {
    /// Observation watermark for change notification.
    pub observed: u64,
    /// Local protocol slots reserved by work that has not submitted a Join.
    pub reserved_attachments: usize,
    /// Revision of the policy in force.
    pub policy_revision: u64,
    /// Generation of the authorization policy in force.
    pub auth_generation: u64,
    /// The current configured limits.
    pub limits: CapacityLimits,
    /// Fixed initial envelope for protocol attachments.
    pub protocol_envelope: usize,
    /// Effective carrier quota, including its resolved default.
    pub local_carrier_limit: usize,
    /// Unretired attachments initiated by the local endpoint.
    pub local_attachments: usize,
    /// Unretired attachments initiated by the peer.
    pub peer_attachments: usize,
    /// Peer Joins awaiting protocol confirmation.
    pub pending_peer_joins: usize,
    /// Earliest retry required by the peer's recent Join resource refusals.
    pub peer_retry_at: Option<Instant>,
    /// Host authorization calls still in progress.
    pub authorizing_peer_joins: usize,
    /// Carriers with outstanding local I/O or teardown.
    pub local_carriers: usize,
    /// The directions required by an established session.
    pub required: Directions,
    /// Directions currently covered by a confirmed attachment.
    pub covered: Directions,
    /// Covered directions which have settled.
    pub stable: Directions,
}

/// Local limits for protocol attachments and carrier work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CapacityLimits {
    /// Steady-state local attachments. The default is one.
    pub steady_attachments: u32,
    /// Additional protocol attachment slots for Join. The default is eight.
    pub join_headroom: u32,
    /// Outstanding physical carriers. The default is twice the initial envelope.
    pub local_carriers: Option<NonZeroUsize>,
    /// The separate limits on authorizing and unconfirmed peer Joins.
    /// Each phase defaults to four.
    pub pending_peer_joins: NonZeroUsize,
    /// Maximum recovery admissions ahead of an eligible ordinary request.
    pub recovery_burst: NonZeroUsize,
}

impl Default for CapacityLimits {
    fn default() -> Self {
        Self {
            steady_attachments: 1,
            join_headroom: 8,
            local_carriers: None,
            pending_peer_joins: NonZeroUsize::new(4).expect("positive default"),
            recovery_burst: NonZeroUsize::new(4).expect("positive default"),
        }
    }
}

impl CapacityLimits {
    pub(super) fn validate(self) -> Result<(), InvalidConfig> {
        if self.steady_attachments == 0 {
            return Err(InvalidConfig::new("steady_attachments", "zero"));
        }
        let envelope = u64::from(self.steady_attachments) + u64::from(self.join_headroom);
        if usize::try_from(envelope * 2).is_err() {
            return Err(InvalidConfig::new(
                "CapacityLimits",
                "attachment envelope exceeds the resource index range",
            ));
        }
        Ok(())
    }

    pub(super) fn envelope(self) -> usize {
        self.steady_attachments as usize + self.join_headroom as usize
    }

    /// The replay width derived once from the initial attachment envelope.
    pub(super) fn replay_width(self) -> u64 {
        (2 * (u64::from(self.steady_attachments) + u64::from(self.join_headroom))).max(64)
    }
}

/// A versioned session capacity and Join authorization policy.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SessionPolicy {
    /// Policy revision. An update must increase this value.
    pub revision: u64,
    /// Authorization generation. Increase it to publish new authorization rules.
    pub auth_generation: u64,
    /// Authorization of authenticated incoming Joins. The default allows them.
    pub authorize_join: Option<AuthorizeJoin>,
    /// Known routes for incoming Joins. When set, every requested half
    /// must carry a route verified by the local carrier adapter and present
    /// in this set. An empty set refuses all incoming Joins.
    pub join_source_routes: Option<Arc<BTreeSet<Arc<str>>>>,
    /// Directions unavailable for named local candidates.
    pub candidate_exclusions:
        Option<Arc<std::collections::BTreeMap<CandidateId, super::DirectionExclusion>>>,
    /// Local capacity limits.
    pub limits: CapacityLimits,
}

impl SessionPolicy {
    /// The initial policy with the given steady-state attachment limit.
    #[must_use]
    pub fn with_steady_attachments(steady_attachments: u32) -> Self {
        let mut policy = Self::default();
        policy.limits.steady_attachments = steady_attachments;
        policy
    }

    pub(crate) fn permits_join_sources(
        &self,
        sources: Option<&super::CarrierHalfSources>,
        (inbound, outbound): (bool, bool),
    ) -> bool {
        self.join_source_routes.as_ref().is_none_or(|routes| {
            sources.is_some_and(|sources| {
                let allowed = |route: &Option<Arc<str>>| {
                    route.as_ref().is_some_and(|route| routes.contains(route))
                };
                (!inbound || allowed(&sources.receive.route))
                    && (!outbound || allowed(&sources.send.route))
            })
        })
    }

    /// Whether current topology permits a candidate to provide these directions.
    #[must_use]
    pub fn allows_candidate(&self, candidate: &CandidateId, directions: Directions) -> bool {
        let excluded = self.exclusion(candidate);
        !(excluded.send && directions.contains(Directions::SEND)
            || excluded.receive && directions.contains(Directions::RECEIVE))
    }

    pub(super) fn exclusion(&self, candidate: &CandidateId) -> super::DirectionExclusion {
        self.candidate_exclusions
            .as_ref()
            .and_then(|rules| rules.get(candidate))
            .copied()
            .unwrap_or_default()
    }
}

/// Why a session policy update could not be committed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionPolicyError {
    /// The session has closed.
    Closed(SessionError),
    /// The revision failed to increase or the authorization generation regressed.
    Conflict {
        /// Current revision.
        revision: u64,
        /// Current authorization generation.
        auth_generation: u64,
    },
    /// The limits are invalid or exceed the fixed protocol envelope.
    Capacity(InvalidConfig),
}

impl std::fmt::Display for SessionPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(error) => error.fmt(f),
            Self::Capacity(error) => error.fmt(f),
            Self::Conflict {
                revision,
                auth_generation,
            } => {
                write!(
                    f,
                    "session policy conflict at revision {revision}, authorization generation {auth_generation}"
                )
            }
        }
    }
}

impl std::error::Error for SessionPolicyError {}

impl SessionCore {
    /// Resolves any currently indexed attachment to its member.
    #[must_use]
    pub fn member_for_pipe(&self, pipe: super::PipeId) -> Option<MemberId> {
        let attachment = self.att(pipe.0).filter(|a| !a.unattached())?;
        Some(
            self.member_binding(pipe)
                .map_or_else(|| MemberId(attachment.seq() + 1), |binding| binding.id),
        )
    }

    /// Lists the current members in session-local identifier order.
    #[must_use]
    pub fn members(&self) -> Vec<MemberSnapshot> {
        use super::health::covered_directions;
        use std::collections::BTreeMap;

        let mut members = BTreeMap::new();
        for attachment in self.atts.iter().filter(|a| !a.unattached()) {
            let pipe = super::PipeId(attachment.id());
            let binding = self.member_binding(pipe);
            let directions =
                Directions::from_halves(attachment.out().is_some(), attachment.inp().is_some());
            let id = binding.map_or_else(|| MemberId(attachment.seq() + 1), |b| b.id);
            let (member, promised_count) = members.entry(id).or_insert_with(|| {
                let mut member = MemberSnapshot {
                    id,
                    candidate: None,
                    pipes: Vec::new(),
                    expected: directions,
                    covered: Directions::NONE,
                    stable: Directions::NONE,
                    complete: true,
                };
                if let Some(binding) = binding {
                    member.candidate.clone_from(&binding.candidate);
                    member.expected = binding.expected;
                }
                (member, binding.map_or(1, |b| b.attachments))
            });
            let (covered, stable) = self
                .pipe_health(pipe)
                .map_or((Directions::NONE, Directions::NONE), covered_directions);
            member.pipes.push(pipe);
            member.covered = member.covered.union(covered);
            member.stable = member.stable.union(stable);
            member.complete &= covered.contains(directions) && *promised_count > 0;
        }
        members
            .into_values()
            .map(|(mut member, count)| {
                member.complete &= member.pipes.len() == count;
                member
            })
            .collect()
    }

    /// Projects capacity under the protocol owner. Driver resource counts
    /// are supplied by the driver when publishing its public snapshot.
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn capacity_snapshot(
        &self,
        authorizing_peer_joins: usize,
        local_carriers: usize,
    ) -> CapacitySnapshot {
        let policy = self.session_policy();
        let (covered, stable) = self.coverage_except(&[]);
        CapacitySnapshot {
            observed: 0,
            reserved_attachments: 0,
            policy_revision: policy.revision,
            auth_generation: policy.auth_generation,
            limits: policy.limits,
            protocol_envelope: self.config.initial_capacity().envelope(),
            local_carrier_limit: self.local_carrier_limit(),
            local_attachments: self.unretired(true),
            peer_attachments: self.unretired(false),
            pending_peer_joins: self.pending_peer_joins(),
            peer_retry_at: self.peer_join_retry(),
            authorizing_peer_joins,
            local_carriers,
            required: Directions::BOTH,
            covered,
            stable,
        }
    }

    /// The policy currently in force.
    pub fn session_policy(&self) -> &SessionPolicy {
        &self.config.session_policy
    }

    /// Installs a newer policy atomically. The protocol envelope and replay
    /// history survive local limit changes.
    ///
    /// # Errors
    ///
    /// Returns an error if the session has closed, the revisions conflict, or
    /// the local capacity exceeds the initial protocol envelope.
    pub fn set_session_policy(
        &mut self,
        mut policy: SessionPolicy,
        now: Instant,
    ) -> Result<(), SessionPolicyError> {
        self.tick(now);
        let now = self.now;
        if let Some(error) = self.error() {
            return Err(SessionPolicyError::Closed(error.clone()));
        }
        let current = self.session_policy();
        if policy.revision <= current.revision || policy.auth_generation < current.auth_generation {
            return Err(SessionPolicyError::Conflict {
                revision: current.revision,
                auth_generation: current.auth_generation,
            });
        }
        policy
            .limits
            .validate()
            .map_err(SessionPolicyError::Capacity)?;
        let initial_capacity = self.config.initial_capacity();
        if policy.limits.envelope() > initial_capacity.envelope() {
            return Err(SessionPolicyError::Capacity(InvalidConfig::new(
                "CapacityLimits",
                "above the initial protocol envelope",
            )));
        }
        let auth_changed = policy.auth_generation != current.auth_generation;
        let source_changed = policy.join_source_routes != current.join_source_routes;
        let topology_changed = policy.candidate_exclusions != current.candidate_exclusions;
        if !auth_changed {
            policy.authorize_join.clone_from(&current.authorize_join);
        }
        let config = Arc::make_mut(&mut self.config);
        config
            .initial_capacity
            .get_or_insert_with(|| Box::new(initial_capacity));
        config.session_policy = policy;
        if self.mp.is_some() && self.state < State::Closing {
            if auth_changed || source_changed {
                self.revoke_peer_attachments(auth_changed, now);
            }
            if topology_changed {
                for member in self.members() {
                    if let Some(candidate) = member.candidate {
                        let exclusion = self.session_policy().exclusion(&candidate);
                        for pipe in member.pipes {
                            self.set_pipe_topology_exclusion(pipe, exclusion, now);
                        }
                    }
                }
            }
            self.release_deferred_joins(now);
        }
        Ok(())
    }

    /// Effective local carrier budget. Its automatic default is pinned to
    /// the initial protocol envelope.
    pub fn local_carrier_limit(&self) -> usize {
        self.session_policy().limits.local_carriers.map_or_else(
            || 2 * self.config.initial_capacity().envelope(),
            NonZeroUsize::get,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::session::{Config, Role};

    #[test]
    fn limits_keep_the_initial_protocol_envelope_and_carrier_default() {
        let now = Instant::now();
        let mut config = Config::multipath(crate::PipeAuth::psk([1; 32]));
        config.session_policy.limits.steady_attachments = 32;
        let mut core = SessionCore::new(config, Role::Client, None, now).unwrap();
        let initial = core.session_policy().limits;
        assert_eq!(initial.envelope(), 40);
        assert_eq!(initial.replay_width(), 80);
        assert_eq!(initial.join_headroom, 8);
        assert_eq!(initial.pending_peer_joins.get(), 4);
        assert_eq!(core.local_carrier_limit(), 80);
        let mut limit = core.session_policy().clone();
        limit.revision = 1;
        limit.limits.steady_attachments = 1;
        limit.limits.join_headroom = 0;
        core.set_session_policy(limit, now).unwrap();
        assert_eq!(core.cap(), 1);
        assert_eq!(core.config().initial_capacity(), initial);
        assert_eq!(core.local_carrier_limit(), 80);
        let mut next = core.session_policy().clone();
        next.revision = 2;
        next.limits = initial;
        next.limits.join_headroom += 1;
        assert!(matches!(
            core.set_session_policy(next.clone(), now),
            Err(SessionPolicyError::Capacity(_))
        ));
        assert_eq!(core.session_policy().revision, 1);
        next.limits = initial;
        core.set_session_policy(next, now).unwrap();
        assert_eq!(core.cap(), 40);
        assert_eq!(core.session_policy().revision, 2);
    }
}
