//! Declarative convergence over the session's member and capacity owner.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use tokio::sync::watch;

pub(super) mod domain;
mod evidence;
use domain::{Demand, Domain, Owner};
pub use evidence::{QualityInput, QualityMeasurement};

use super::capacity_change::{
    Attempt, AttemptCause, AttemptReason, CapacityChangeFor, ChangeAdmissionFor, ChangeError,
    ChangeRequest, MemberSpec, RecoveryAdmission,
};
use super::choice::{
    BootstrapError, Candidate, ChoiceSource, FeedbackSource, MemberFaults, score_order,
};
use super::handle::{Driver, Session, SessionApi, State};
use super::handle::{WeakSession, capacity_changed};
use crate::{
    CandidateId, CapacitySnapshot, CarrierCache, CarrierCacheConfig, ClockDomain, Config,
    Directions, InvalidConfig, MemberId, MemberSnapshot, Multipath, PathPreference, PipeId,
    RetryAdmission,
};

/// Candidate permitted to satisfy a quota.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCandidate {
    /// Registered candidate.
    pub id: CandidateId,
    /// Optional outbound preference.
    pub send: Option<PathPreference>,
    /// Optional local inbound preference.
    pub receive: Option<PathPreference>,
}

/// Number and kind of complete members required by one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberQuota {
    /// Identifier unique inside the group.
    pub id: String,
    /// Number of complete members. Zero explicitly requests none.
    pub count: usize,
    /// Directions each matching member must serve.
    pub directions: Directions,
    /// Registered candidates eligible to fill this quota.
    pub candidates: Vec<TargetCandidate>,
}

/// Replacement thresholds for members of a group.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Replace when this member age is reached.
    pub max_age: Option<Duration>,
    /// Replace after handing this many bytes to the carrier.
    pub send_bytes: Option<u64>,
    /// Replace after receiving this many bytes.
    pub receive_bytes: Option<u64>,
}

/// A named pool that reconciles one logical member at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupTarget {
    /// Unique group identity for the session.
    pub id: String,
    /// Required members.
    pub quotas: Vec<MemberQuota>,
    /// Optional replacement thresholds.
    pub rotation: RotationPolicy,
}

/// Explicit make-before-break replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceIntent {
    /// Stable identity across target revisions.
    pub id: String,
    /// Members to replace.
    pub members: Vec<MemberId>,
    /// Minimum epoch of replacement Joins.
    pub min_epoch: u64,
    /// Observations relied on by a quality-driven replacement.
    pub evidence: Vec<QualityInput>,
}

/// One version of a session's desired membership.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionTarget {
    /// Strictly increasing revision. Equal revisions are idempotent for identical content.
    pub revision: u64,
    /// Desired membership.
    pub groups: Vec<GroupTarget>,
    /// Explicit retirement and replacement requests.
    pub replace: Vec<ReplaceIntent>,
}

impl SessionTarget {
    fn requires_members(&self) -> bool {
        !self.groups.is_empty() || !self.replace.is_empty()
    }

    fn renews_replacement(&self, next: &Self) -> bool {
        self.groups == next.groups
            && !self.replace.is_empty()
            && self.replace.len() == next.replace.len()
            && self.replace.iter().zip(&next.replace).all(|(old, new)| {
                old.id == new.id && old.members == new.members && old.min_epoch == new.min_epoch
            })
    }

    fn validate<D: Driver>(&self, controller: &Controller<D>) -> Result<(), ControllerError> {
        let mut group_ids = HashSet::new();
        for group in &self.groups {
            if group.id.is_empty()
                || !group_ids.insert(&group.id)
                || group
                    .rotation
                    .max_age
                    .is_some_and(|d| d.is_zero() || controller.clock.now().checked_add(d).is_none())
                || group.rotation.send_bytes == Some(0)
                || group.rotation.receive_bytes == Some(0)
            {
                return Err(ControllerError::Invalid("invalid group"));
            }
            let mut quota_ids = HashSet::new();
            for quota in &group.quotas {
                if quota.id.is_empty()
                    || !quota_ids.insert(&quota.id)
                    || quota.directions == Directions::NONE
                    || (quota.count != 0 && quota.candidates.is_empty())
                {
                    return Err(ControllerError::Invalid("invalid quota"));
                }
                let mut candidate_ids = HashSet::new();
                for path in &quota.candidates {
                    let Some(&index) = controller.by_id.get(&path.id) else {
                        return Err(ControllerError::Invalid("unknown candidate"));
                    };
                    if !candidate_ids.insert(&path.id)
                        || !controller
                            .member_spec(index)
                            .expected()
                            .contains(quota.directions)
                    {
                        return Err(ControllerError::Invalid("invalid quota candidate layout"));
                    }
                }
            }
        }
        let mut intents = HashSet::new();
        let mut members = HashSet::new();
        for intent in &self.replace {
            if intent
                .evidence
                .iter()
                .any(|input| !intent.members.contains(&input.member))
                || intent.id.is_empty()
                || !intents.insert(&intent.id)
                || intent.members.iter().any(|id| !members.insert(id))
            {
                return Err(ControllerError::Invalid("invalid replacement"));
            }
        }
        Ok(())
    }
}

/// Policy for ranking eligible carriers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChoicePolicy {
    /// Rank by configured priority and registration order.
    #[default]
    Static,
    /// Use the shared decayed score within a tier.
    D160,
}

/// Bounds actual controller work shared by all sessions in a domain.
#[derive(Debug, Clone)]
pub struct ControllerLimits {
    /// Number of openers that may be running together.
    pub concurrent_openers: NonZeroUsize,
    /// Maximum number of pending owners, including standalone opens.
    pub pending_owners: NonZeroUsize,
    /// Maximum number of attachments reserved for controller cleanup.
    pub cleanup_attachments: NonZeroUsize,
    /// Maximum duration of a pending attempt and its reservation.
    pub attempt_timeout: Duration,
}

impl Default for ControllerLimits {
    fn default() -> Self {
        Self {
            concurrent_openers: NonZeroUsize::new(4).unwrap(),
            pending_owners: NonZeroUsize::new(64).unwrap(),
            cleanup_attachments: NonZeroUsize::new(8).unwrap(),
            attempt_timeout: Duration::from_secs(10),
        }
    }
}

/// Domain, candidates and sharing configuration of a controller.
#[derive(Debug, Clone)]
pub struct ControllerOptions<D: Driver> {
    /// Process-local name of the isolated controller.
    pub domain: String,
    /// Candidates in deterministic registration order.
    pub candidates: Vec<Candidate<D>>,
    /// Candidate ranking policy.
    pub choice: ChoicePolicy,
    /// Minimum ratio of candidate to incumbent reliability for an automatic upgrade.
    pub upgrade_ratio: f64,
    /// Domain and attempt bounds.
    pub limits: ControllerLimits,
    /// Session and cache time domain.
    pub clock_domain: ClockDomain,
    /// Optional preconfigured shared cache.
    pub cache: Option<CarrierCache>,
    /// Earliest host start by candidate, in the controller clock domain.
    pub dial_after: BTreeMap<CandidateId, Instant>,
}

impl<D: Driver> ControllerOptions<D> {
    /// Defaults for a new isolated controller domain.
    #[must_use]
    pub fn new(domain: impl Into<String>, candidates: Vec<Candidate<D>>) -> Self {
        Self {
            domain: domain.into(),
            candidates,
            choice: ChoicePolicy::default(),
            upgrade_ratio: 1.25,
            limits: ControllerLimits::default(),
            clock_domain: ClockDomain::default(),
            cache: None,
            dial_after: BTreeMap::new(),
        }
    }
}

/// A controller operation failed before it could take effect.
#[derive(Debug)]
#[non_exhaustive]
pub enum ControllerError {
    /// Invalid registration, bounds or target.
    Invalid(&'static str),
    /// Session transport configuration is invalid.
    Config(InvalidConfig),
    /// Bootstrap candidates failed.
    Bootstrap(BootstrapError),
    /// Bootstrap could not start before the host's earliest candidate time.
    DialAfter(Instant),
    /// This process already has a controller for that domain.
    DomainInUse,
    /// The domain cannot accept another pending owner.
    QueueFull,
    /// Session, controller and cache must use the same clock domain.
    ClockDomainMismatch,
    /// Multipath capability is required for a maintained target.
    NotNegotiated,
    /// The session already has a controller binding.
    AlreadyManaged,
    /// The expected handle is no longer the current binding.
    StaleBinding,
    /// A relied-on quality observation is no longer valid.
    StaleDecision,
    /// The current target is newer or has different content.
    Conflict {
        /// Installed revision.
        revision: u64,
    },
    /// The controller or session has closed.
    Closed,
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session controller: {self:?}")
    }
}

impl std::error::Error for ControllerError {}

/// Reason the current target cannot advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControllerBlock {
    /// A quality-driven replacement requires fresh observations.
    StaleDecision,
    /// The host or protocol has no room for more attachments.
    Capacity,
    /// The domain has no available opener slot.
    Execution,
    /// The domain has insufficient attachment cleanup capacity.
    Cleanup,
    /// The domain cannot accept another pending owner.
    QueueFull,
    /// The controller no longer accepts work.
    OwnerClosed,
    /// No candidate can supply the required member.
    NoEligibleCandidate,
    /// The current topology disallows the requested directions.
    Unauthorized,
    /// Candidate admission is waiting for a cache event or retry.
    Retry,
    /// The host requires a later start for the candidate.
    DialAfter,
    /// No time remains for an attempt.
    Deadline,
    /// A replacement is waiting for stability.
    Stability,
    /// A proposed retirement would remove required coverage.
    Coverage,
    /// A replacement is waiting for the minimum epoch.
    Epoch,
}

impl ControllerBlock {
    fn from_owner(error: &ControllerError) -> Self {
        match error {
            ControllerError::Closed => Self::OwnerClosed,
            _ => Self::QueueFull,
        }
    }
}

/// One unresolved quota in the currently observed target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaDeficit {
    /// Group identity.
    pub group: String,
    /// Quota identity.
    pub quota: String,
    /// Count of missing complete members.
    pub missing: usize,
}

/// Latest progress from the controller.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ControllerSnapshot {
    evidence: Arc<[QualityInput]>,
    /// Session-local identity of the binding.
    pub generation: u64,
    /// Generation replaced by this binding, when installed by takeover.
    pub predecessor: Option<u64>,
    /// Installed target revision.
    pub revision: u64,
    /// Core capacity and coverage.
    pub capacity: CapacitySnapshot,
    /// Core member table.
    pub members: Vec<MemberSnapshot>,
    /// Per-attachment health and quality at the same owner observation as the member table.
    pub paths: Vec<crate::PipeStats>,
    /// Deficits in deterministic group and quota order.
    pub deficits: Vec<QuotaDeficit>,
    /// Openers in this binding.
    pub attempts: Vec<crate::AttemptId>,
    /// The most recent terminal attempt observed by the controller.
    pub last_attempt: Option<crate::AttemptResult>,
    /// Current blocked reason, if any.
    pub blocked: Option<ControllerBlock>,
    /// Earliest time-based eligibility change.
    pub next_retry: Option<Instant>,
    /// Actual opener calls retaining a shared host work slot.
    pub host_calls_in_flight: usize,
    /// Attachments retaining cleanup permits from this binding.
    pub cleanup_in_flight: usize,
    /// Opener work slots charged to the domain.
    pub domain_openers: usize,
    /// Cleanup permits charged to the domain.
    pub domain_cleanup: usize,
}

static DOMAINS: std::sync::LazyLock<Mutex<BTreeMap<String, Weak<Domain>>>> =
    std::sync::LazyLock::new(Mutex::default);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Default)]
pub(super) struct DialSchedule(Arc<Mutex<BTreeMap<CandidateId, Instant>>>);

impl DialSchedule {
    pub(super) fn from_options(options: BTreeMap<CandidateId, Instant>) -> Self {
        Self(Arc::new(Mutex::new(options)))
    }

    fn independent(&self) -> Self {
        Self::from_options(lock(&self.0).clone())
    }

    pub(super) fn blocked(&self, candidate: &CandidateId, now: Instant) -> Option<Instant> {
        lock(&self.0)
            .get(candidate)
            .copied()
            .filter(|&deadline| now < deadline)
    }

    pub(super) fn gate(&self, candidate: &CandidateId) -> DialGate {
        DialGate {
            schedule: self.clone(),
            candidate: candidate.clone(),
            recovery_cutoff: None,
        }
    }

    pub(super) fn set(&self, candidate: CandidateId, at: Option<Instant>) {
        let mut times = lock(&self.0);
        if let Some(at) = at {
            times.insert(candidate, at);
        } else {
            times.remove(&candidate);
        }
    }
}

#[derive(Clone)]
pub(super) struct DialGate {
    schedule: DialSchedule,
    candidate: CandidateId,
    recovery_cutoff: Option<Instant>,
}

impl DialGate {
    pub(super) fn blocked(&self, now: Instant) -> Option<Instant> {
        self.schedule.blocked(&self.candidate, now)
    }

    /// The latest recovery start that still leaves a full attempt before a
    /// suspended session's grace expires. It caps the shared cadence wait.
    pub(super) const fn recovery_cutoff(&self) -> Option<Instant> {
        self.recovery_cutoff
    }

    const fn with_recovery_cutoff(mut self, cutoff: Option<Instant>) -> Self {
        self.recovery_cutoff = cutoff;
        self
    }
}

#[derive(Debug, Clone)]
/// A domain controller that can establish and manage multiple sessions.
pub struct SessionController<D: Driver>(Arc<Controller<D>>);

struct Controller<D: Driver> {
    by_id: BTreeMap<CandidateId, usize>,
    candidates: Vec<Candidate<D>>,
    source: Arc<ChoiceSource<D>>,
    dial_after: DialSchedule,
    domain: Arc<Domain>,
    clock: ClockDomain,
    cache: CarrierCache,
    choice: ChoicePolicy,
    upgrade_ratio: f64,
    timeout: Duration,
    closed: watch::Sender<bool>,
    bindings: watch::Sender<usize>,
    registration: Mutex<()>,
}

impl<D: Driver> fmt::Debug for Controller<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Controller")
            .field("candidates", &self.by_id)
            .finish_non_exhaustive()
    }
}

impl<D: Driver> SessionController<D> {
    /// Creates a controller and binds its candidates and cache to the domain.
    ///
    /// # Errors
    ///
    /// Rejects duplicate identities, conflicting domain bindings and invalid options.
    pub fn new(options: ControllerOptions<D>) -> Result<Self, ControllerError> {
        if !options.upgrade_ratio.is_finite() || options.upgrade_ratio <= 1.0 {
            return Err(ControllerError::Invalid("invalid upgrade ratio"));
        }
        if options.domain.is_empty()
            || options.limits.attempt_timeout.is_zero()
            || options.limits.attempt_timeout > crate::proto::session::MAX_JOIN_DEADLINE
            || options
                .clock_domain
                .now()
                .checked_add(options.limits.attempt_timeout)
                .is_none()
        {
            return Err(ControllerError::Invalid("invalid domain or limits"));
        }
        let mut by_id = BTreeMap::new();
        for (index, candidate) in options.candidates.iter().enumerate() {
            let id = candidate
                .id
                .as_ref()
                .ok_or(ControllerError::Invalid("missing candidate id"))?;
            let key = candidate
                .cache_key
                .as_ref()
                .ok_or(ControllerError::Invalid("missing cache key"))?;
            if id.0.is_empty()
                || key.is_empty()
                || by_id.insert(id.clone(), index).is_some()
                || candidate.layout.is_empty()
                || candidate.layout.len() > options.limits.cleanup_attachments.get()
                || candidate
                    .layout
                    .iter()
                    .any(|a| a.directions == Directions::NONE || a.options.validate().is_err())
            {
                return Err(ControllerError::Invalid("invalid candidate registration"));
            }
        }
        if options.dial_after.keys().any(|id| !by_id.contains_key(id)) {
            return Err(ControllerError::Invalid("unknown DialAfter candidate"));
        }
        let cache = match options.cache {
            Some(cache) if *cache.clock_domain() != options.clock_domain => {
                return Err(ControllerError::ClockDomainMismatch);
            }
            Some(cache) => cache,
            None => {
                let mut config = CarrierCacheConfig::default();
                config.clock_domain.clone_from(&options.clock_domain);
                if options.choice == ChoicePolicy::Static {
                    config.backoff = crate::Backoff::default();
                }
                CarrierCache::new(config).map_err(ControllerError::Config)?
            }
        };
        let mut domains = lock(&DOMAINS);
        domains.retain(|_, current| current.strong_count() != 0);
        if domains
            .get(&options.domain)
            .and_then(Weak::upgrade)
            .is_some_and(|domain| !domain.released())
        {
            return Err(ControllerError::DomainInUse);
        }
        let dial_after = DialSchedule::from_options(options.dial_after);
        let domain = Domain::new(options.limits.clone());
        let source = Arc::new(ChoiceSource::new(
            options.candidates.clone(),
            options.choice == ChoicePolicy::D160,
            cache.clone(),
            options.limits.attempt_timeout,
            dial_after.clone(),
        ));
        let controller = Arc::new(Controller {
            by_id,
            candidates: options.candidates,
            source,
            dial_after,
            domain,
            clock: options.clock_domain,
            cache,
            choice: options.choice,
            upgrade_ratio: options.upgrade_ratio,
            timeout: options.limits.attempt_timeout,
            closed: watch::Sender::new(false),
            bindings: watch::Sender::new(0),
            registration: Mutex::new(()),
        });
        domains.insert(options.domain, Arc::downgrade(&controller.domain));
        Ok(Self(controller))
    }

    /// Establishes a session and applies its initial target.
    ///
    /// # Errors
    ///
    /// Returns a registration, bootstrap or capability error.
    pub(super) async fn open_async(
        &self,
        mut config: Config,
        target: SessionTarget,
    ) -> Result<(Session<D>, Option<SessionControl<D>>), ControllerError> {
        target.validate(&self.0)?;
        if config.clock_domain != ClockDomain::default() && config.clock_domain != self.0.clock {
            return Err(ControllerError::ClockDomainMismatch);
        }
        config.clock_domain.clone_from(&self.0.clock);
        config.validate().map_err(ControllerError::Config)?;
        config.early_data = crate::EarlyData::default();
        let config = Arc::new(config);
        let owner = self.0.domain.owner();
        owner.enqueue()?;
        let mut trials = Vec::new();
        let mut closed = self.0.closed.subscribe();
        let established = tokio::select! {
            biased;
            _ = closed.wait_for(|&closed| closed) => return Err(ControllerError::Closed),
            result = self.0.source.race_bootstrap(&config, &owner, &mut trials) => result,
        };
        let Some((index, session, sequence)) = established else {
            if trials.is_empty()
                && let Some(next) = self.0.source.next_dial_after()
            {
                return Err(ControllerError::DialAfter(next));
            }
            return Err(ControllerError::Bootstrap(BootstrapError {
                results: trials,
            }));
        };
        let candidate = &self.0.candidates[index];
        session.assign_bootstrap(self.0.id(index).clone(), sequence);
        session.report_carrier(
            &trials,
            Some((candidate.kind(), candidate.variant().cloned())),
        );
        if session.multipath() != Multipath::InUse {
            if target.requires_members() {
                session.abort_op(crate::VarInt::from_u32(0), b"");
                return Err(ControllerError::NotNegotiated);
            }
            return Ok((session, None));
        }
        match self.bind(&session, target, Some(owner), None, Some(self.0.id(index))) {
            Ok(control) => Ok((session, Some(control))),
            Err(error) => {
                session.abort_op(crate::VarInt::from_u32(0), b"");
                Err(error)
            }
        }
    }

    /// Attaches a controller to an established multipath session.
    ///
    /// # Errors
    ///
    /// Rejects sessions already managed or in a different clock domain.
    pub fn manage(
        &self,
        session: &Session<D>,
        target: SessionTarget,
    ) -> Result<SessionControl<D>, ControllerError> {
        self.manage_with_bootstrap(session, target, None)
    }

    /// Attaches a controller and optionally attributes the confirmed first pipe.
    ///
    /// # Errors
    ///
    /// Rejects incompatible bootstrap attribution, targets or bindings.
    pub fn manage_with_bootstrap(
        &self,
        session: &Session<D>,
        target: SessionTarget,
        bootstrap: Option<&crate::CandidateId>,
    ) -> Result<SessionControl<D>, ControllerError> {
        if session.multipath() != Multipath::InUse {
            return Err(ControllerError::NotNegotiated);
        }
        self.bind(session, target, None, None, bootstrap)
    }

    /// Replaces the exact current binding on its existing session.
    ///
    /// # Errors
    ///
    /// Returns a stale binding error if the expected handle has already been replaced or released.
    pub fn take_over(
        &self,
        previous: &SessionControl<D>,
        target: SessionTarget,
    ) -> Result<SessionControl<D>, ControllerError> {
        self.take_over_with_bootstrap(previous, target, None)
    }

    /// Atomically takes over and optionally attributes the confirmed first pipe.
    ///
    /// # Errors
    ///
    /// Rejects stale bindings and incompatible bootstrap attribution or targets.
    pub fn take_over_with_bootstrap(
        &self,
        previous: &SessionControl<D>,
        target: SessionTarget,
        bootstrap: Option<&crate::CandidateId>,
    ) -> Result<SessionControl<D>, ControllerError> {
        let _install = lock(&previous.0.install);
        let session = previous
            .0
            .session
            .upgrade()
            .ok_or(ControllerError::StaleBinding)?;
        self.bind(&session, target, None, Some(&previous.0), bootstrap)
    }

    fn bind(
        &self,
        session: &Session<D>,
        target: SessionTarget,
        owner: Option<Owner>,
        previous: Option<&Binding<D>>,
        bootstrap: Option<&crate::CandidateId>,
    ) -> Result<SessionControl<D>, ControllerError> {
        target.validate(&self.0)?;
        if session.clock_domain() != self.0.clock {
            return Err(ControllerError::ClockDomainMismatch);
        }
        let _registration = lock(&self.0.registration);
        if *self.0.closed.borrow() {
            return Err(ControllerError::Closed);
        }
        let owner = if let Some(owner) = owner {
            owner
        } else {
            let owner = self.0.domain.owner();
            owner.enqueue()?;
            owner
        };
        let (generation, capacity, members, paths) = session.command(|state| {
            if state.core.error().is_some() {
                return Err(ControllerError::Closed);
            }
            let capacity = state.capacity();
            let mut members = state.core.members();
            if target
                .replace
                .iter()
                .any(|intent| !intent.evidence.is_empty())
            {
                return Err(ControllerError::StaleDecision);
            }
            let changes = &mut state.control.get_or_insert_default().changes;
            if let Some(old) = previous {
                if changes.controller.map(|stamp| stamp.0) != Some(old.generation) {
                    return Err(ControllerError::StaleBinding);
                }
                if Arc::ptr_eq(&old.controller, &self.0) {
                    return Err(ControllerError::Invalid("cannot take over own binding"));
                }
            } else if changes.controller.is_some() {
                return Err(ControllerError::AlreadyManaged);
            }
            let pool = state.control.as_ref().expect("prepared control");
            for member in &members {
                if let Some(index) = member
                    .candidate
                    .as_ref()
                    .and_then(|id| self.0.by_id.get(id))
                    && pool
                        .origins
                        .get(&member.id)
                        .is_some_and(|old| old != &self.0.origin(*index))
                {
                    return Err(ControllerError::Invalid("live candidate identity changed"));
                }
            }
            self.0.check_envelope(&target, capacity)?;
            let changes = &mut state.control.as_mut().expect("prepared control").changes;
            let generation = changes
                .generation
                .checked_add(1)
                .ok_or(ControllerError::Invalid("binding generation exhausted"))?;
            if let Some(id) = bootstrap {
                let (index, candidate) = self
                    .0
                    .by_id
                    .get(id)
                    .map(|&index| (index, &self.0.candidates[index]))
                    .ok_or(ControllerError::Invalid(
                        "bootstrap candidate is unregistered",
                    ))?;
                let member = members
                    .iter_mut()
                    .find(|member| member.pipes.contains(&crate::PipeId(0)))
                    .ok_or(ControllerError::Invalid("bootstrap member unavailable"))?;
                let matches = member.complete
                    && member.pipes.len() == 1
                    && member.expected == Directions::BOTH
                    && member.candidate.as_ref().is_none_or(|old| old == id)
                    && candidate.can_bootstrap()
                    && state.core.pipes().iter().any(|pipe| {
                        pipe.pipe == crate::PipeId(0)
                            && pipe.carrier == Some(candidate.kind())
                            && pipe.variant.as_ref() == candidate.variant()
                    });
                if !matches {
                    return Err(ControllerError::Invalid("incompatible bootstrap candidate"));
                }
                state.core.assign_member(
                    crate::PipeId(0),
                    member.id,
                    Some(id.clone()),
                    member.expected,
                    1,
                );
                member.candidate = Some(id.clone());
                state
                    .control
                    .as_mut()
                    .unwrap()
                    .origins
                    .insert(member.id, self.0.origin(index));
            }
            let changes = &mut state.control.as_mut().expect("prepared control").changes;
            changes.generation = generation;
            changes.controller = Some((generation, target.revision));
            let mut demand = self.0.recovery_demand(owner.starts.clone());
            demand.refresh(capacity, state.core.session_policy());
            if let Some(old) = previous
                && old.controller.cache.shares_history(&self.0.cache)
            {
                let prior = old.target.borrow();
                let same_target = prior.groups == target.groups && prior.replace == target.replace;
                old.owner
                    .starts
                    .transfer(&owner.starts, &demand.held, same_target);
            }
            state.control.as_mut().expect("installed control").demand = Some(demand);
            let outage = super::cache::OutageLog::new(self.0.cache.clone());
            let next = ControllerFeedback {
                sources: self
                    .0
                    .by_id
                    .iter()
                    .map(|(id, &index)| {
                        (
                            id.clone(),
                            self.0.source.feedback(index).with_outage(&outage),
                        )
                    })
                    .collect(),
                members: BTreeMap::new(),
                outage,
            };
            state.transfer_controller_feedback(Some(next));
            if let Some(old) = previous {
                old.revoke();
                super::capacity_change::invalidate_batches(
                    state,
                    target.revision,
                    true,
                    state.now(),
                );
            }
            state.enroll_confirmed_members(None);
            state.app_event(crate::SessionEvent::TargetChanged {
                generation,
                revision: target.revision,
                initial: true,
                predecessor: previous.map(|old| old.generation),
            });
            state.notify_capacity_change();
            Ok((generation, capacity, members, state.control_paths()))
        })?;
        self.0.bindings.send_modify(|count| *count += 1);
        let predecessor = previous.map(|old| old.generation);
        let (domain_openers, domain_cleanup) = self.0.domain.usage();
        let (host_calls_in_flight, cleanup_in_flight) = owner.usage();
        let snapshot = ControllerSnapshot {
            evidence: evidence::capture(
                SessionApi::id(session),
                (generation, target.revision),
                capacity,
                &members,
                &paths,
            ),
            generation,
            predecessor,
            revision: target.revision,
            capacity,
            members,
            paths,
            deficits: Vec::new(),
            attempts: Vec::new(),
            last_attempt: None,
            blocked: None,
            next_retry: None,
            host_calls_in_flight,
            cleanup_in_flight,
            domain_openers,
            domain_cleanup,
        };
        let state = Arc::new(Binding {
            generation,
            predecessor,
            controller: self.0.clone(),
            owner,
            session: session.downgrade(),
            target: watch::Sender::new(target),
            dial_after: self.0.dial_after.independent(),
            stop: watch::Sender::new(false),
            done: watch::Sender::new(false),
            snapshot: watch::Sender::new(snapshot),
            install: Mutex::new(()),
            #[cfg(test)]
            passes: std::sync::atomic::AtomicU64::new(0),
        });
        D::spawn_join(session.shared(), reconcile(state.clone()));
        Ok(SessionControl(state))
    }

    /// Stops this controller and all of its bindings.
    pub fn close(&self) {
        let _registration = lock(&self.0.registration);
        self.0.closed.send_replace(true);
        self.0.domain.close();
    }

    /// Waits until the controller has been closed.
    pub async fn done(&self) {
        let _ = self.0.closed.subscribe().wait_for(|&closed| closed).await;
        let _ = self
            .0
            .bindings
            .subscribe()
            .wait_for(|&count| count == 0)
            .await;
        let mut changed = self.0.domain.subscribe();
        while !self.0.domain.idle() {
            let _ = changed.changed().await;
        }
    }
}

#[cfg(feature = "tokio")]
impl SessionController<super::tokio::Tokio> {
    /// Establishes and manages an asynchronous session.
    ///
    /// # Errors
    ///
    /// Returns the target, admission or transport error.
    pub async fn open(
        &self,
        config: Config,
        target: SessionTarget,
    ) -> Result<(super::tokio::Session, Option<crate::SessionControl>), ControllerError> {
        self.open_async(config, target).await
    }
}

struct Binding<D: Driver> {
    generation: u64,
    predecessor: Option<u64>,
    controller: Arc<Controller<D>>,
    owner: Owner,
    session: WeakSession<D>,
    target: watch::Sender<SessionTarget>,
    dial_after: DialSchedule,
    stop: watch::Sender<bool>,
    done: watch::Sender<bool>,
    snapshot: watch::Sender<ControllerSnapshot>,
    install: Mutex<()>,
    /// Passes of the reconcile loop, for tests that bound its wakeups.
    #[cfg(test)]
    passes: std::sync::atomic::AtomicU64,
}

/// The optional controller binding of an established session.
#[derive(Clone)]
pub struct SessionControl<D: Driver>(Arc<Binding<D>>);

impl<D: Driver> fmt::Debug for SessionControl<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionControl")
            .field("revision", &self.0.target.borrow().revision)
            .finish_non_exhaustive()
    }
}

impl<D: Driver> SessionControl<D> {
    /// Installs one coherent new target revision.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or conflicting targets or a stopped binding.
    pub fn set_target(&self, target: SessionTarget) -> Result<(), ControllerError> {
        let _install = lock(&self.0.install);
        target.validate(&self.0.controller)?;
        if *self.0.stop.borrow() {
            return Err(ControllerError::StaleBinding);
        }
        if *self.0.controller.closed.borrow() {
            return Err(ControllerError::Closed);
        }
        let current = self.0.target.borrow();
        if *current == target {
            return Ok(());
        }
        let revision = current.revision;
        if target.revision <= revision {
            return Err(ControllerError::Conflict { revision });
        }
        let renews_replacement = current.renews_replacement(&target);
        drop(current);
        let session = self.0.session.upgrade().ok_or(ControllerError::Closed)?;
        session.command(|state| {
            if !state.controller_current((self.0.generation, revision)) {
                return Err(ControllerError::StaleBinding);
            }
            self.0
                .controller
                .check_envelope(&target, state.capacity())?;
            if !target.accepts_evidence(state, self.0.generation, revision) {
                self.0.suppress_stale(&target, &state.core.members());
                return Err(ControllerError::StaleDecision);
            }
            self.0.owner.enqueue()?;
            state
                .control
                .as_mut()
                .expect("installed control")
                .changes
                .controller = Some((self.0.generation, target.revision));
            if renews_replacement {
                super::capacity_change::renew_confirmed_replacement(
                    state,
                    self.0.generation,
                    revision,
                    target.revision,
                );
            }
            super::capacity_change::invalidate_batches(
                state,
                target.revision,
                true,
                self.0.controller.clock.now(),
            );
            state.app_event(crate::SessionEvent::TargetChanged {
                generation: self.0.generation,
                revision: target.revision,
                initial: false,
                predecessor: None,
            });
            self.0.owner.starts.finish_ordinary();
            self.0.target.send_replace(target);
            state.notify_capacity_change();
            Ok(())
        })
    }

    /// Updates this session's earliest start for a candidate. `None` clears the restriction.
    ///
    /// # Errors
    ///
    /// Returns an error for a stopped binding or an unregistered candidate.
    pub fn set_dial_after(
        &self,
        candidate: CandidateId,
        at: Option<Instant>,
    ) -> Result<(), ControllerError> {
        if !self.0.controller.by_id.contains_key(&candidate) {
            return Err(ControllerError::Invalid("unknown DialAfter candidate"));
        }
        let session = self.0.session.upgrade().ok_or(ControllerError::Closed)?;
        session.command(|state| {
            if !state.controller_current((self.0.generation, self.0.target.borrow().revision)) {
                return Err(ControllerError::StaleBinding);
            }
            if *self.0.controller.closed.borrow() || state.core.error().is_some() {
                return Err(ControllerError::Closed);
            }
            self.0.dial_after.set(candidate, at);
            state.notify_capacity_change();
            Ok(())
        })
    }

    /// Reads the last committed controller plan and its core observation.
    #[must_use]
    pub fn snapshot(&self) -> ControllerSnapshot {
        let mut snapshot = self.0.snapshot.borrow().clone();
        (snapshot.host_calls_in_flight, snapshot.cleanup_in_flight) = self.0.owner.usage();
        (snapshot.domain_openers, snapshot.domain_cleanup) = self.0.controller.domain.usage();
        snapshot
    }

    /// Subscribes to the latest snapshot. Slow observers can resume from a snapshot.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ControllerSnapshot> {
        self.0.snapshot.subscribe()
    }

    /// Releases this binding and preserves the session's confirmed coverage.
    ///
    /// # Errors
    ///
    /// Returns a stale binding error if a different binding won the comparison.
    pub fn release(&self) -> Result<(), ControllerError> {
        let _install = lock(&self.0.install);
        let session = self
            .0
            .session
            .upgrade()
            .ok_or(ControllerError::StaleBinding)?;
        session.command(|state| {
            let changes = &mut state.control.get_or_insert_default().changes;
            if changes.controller.map(|stamp| stamp.0) != Some(self.0.generation) {
                return Err(ControllerError::StaleBinding);
            }
            changes.controller = None;
            state.control.as_mut().expect("installed control").demand = None;
            state.transfer_controller_feedback(None);
            self.0.revoke();
            super::capacity_change::invalidate_batches(state, 0, true, state.now());
            state.core.set_member_rotation(&[]);
            state.notify_capacity_change();
            Ok(())
        })
    }

    /// Resolves when the controller binding has stopped.
    pub async fn done(&self) {
        let _ = self.0.done.subscribe().wait_for(|&done| done).await;
    }
}

pub(super) struct RecoveryDemand {
    cache: CarrierCache,
    keys: Vec<(CandidateId, Directions, super::cache::Key)>,
    held: BTreeSet<super::cache::Key>,
    stamp: Option<(Directions, u64)>,
    starts: domain::StartOpportunities,
}

impl RecoveryDemand {
    pub(super) fn refresh(&mut self, capacity: CapacitySnapshot, policy: &crate::SessionPolicy) {
        let need = capacity.required.difference(capacity.covered);
        let stamp = (need, policy.revision);
        if self.stamp.replace(stamp) == Some(stamp) {
            return;
        }
        let wanted: BTreeSet<_> = self
            .keys
            .iter()
            .filter(|(id, dirs, _)| overlaps(*dirs, need) && policy.allows_candidate(id, *dirs))
            .map(|(_, _, key)| key.clone())
            .collect();
        for key in wanted.difference(&self.held) {
            self.cache.recovery_demand(key, true);
        }
        for key in self.held.difference(&wanted) {
            self.cache.recovery_demand(key, false);
        }
        self.starts.retain_recovery(&wanted);
        self.held = wanted;
    }
}

impl Drop for RecoveryDemand {
    fn drop(&mut self) {
        for key in &self.held {
            self.cache.recovery_demand(key, false);
        }
    }
}

#[derive(Default)]
struct CandidateSelection {
    dial: Option<usize>,
    retry: Option<(Instant, ControllerBlock)>,
    suppressed: Vec<BlockedStart>,
}

struct BlockedStart {
    index: usize,
    reason: RetryAdmission,
}

impl<D: Driver> Controller<D> {
    fn check_envelope(
        &self,
        target: &SessionTarget,
        capacity: CapacitySnapshot,
    ) -> Result<(), ControllerError> {
        let mut remaining = capacity.protocol_envelope;
        for quota in target.groups.iter().flat_map(|group| &group.quotas) {
            let slots = quota
                .candidates
                .iter()
                .map(|p| self.candidates[self.by_id[&p.id]].layout.len())
                .min()
                .unwrap_or(0);
            remaining = quota
                .count
                .checked_mul(slots)
                .and_then(|n| remaining.checked_sub(n))
                .ok_or(ControllerError::Invalid("quota exceeds protocol envelope"))?;
        }
        Ok(())
    }

    fn recovery_demand(&self, starts: domain::StartOpportunities) -> RecoveryDemand {
        RecoveryDemand {
            cache: self.cache.clone(),
            keys: self
                .candidates
                .iter()
                .enumerate()
                .map(|(i, candidate)| {
                    (
                        self.id(i).clone(),
                        self.member_spec(i).expected(),
                        super::cache::candidate_key(self.key(i), candidate),
                    )
                })
                .collect(),
            held: BTreeSet::new(),
            stamp: None,
            starts,
        }
    }

    fn id(&self, index: usize) -> &CandidateId {
        self.candidates[index].id.as_ref().expect("registered id")
    }

    fn key(&self, index: usize) -> &str {
        self.candidates[index]
            .cache_key
            .as_deref()
            .expect("registered key")
    }

    fn member_spec(&self, index: usize) -> MemberSpec {
        MemberSpec {
            candidate: Some(self.id(index).clone()),
            attachments: self.candidates[index].layout.clone(),
        }
    }

    fn priority(&self, index: usize, preferred: Option<PathPreference>) -> PathPreference {
        let candidate = &self.candidates[index];
        preferred.unwrap_or(PathPreference {
            tier: candidate.tier,
            standby: candidate.standby,
            weight: 1,
        })
    }

    fn score(&self, index: usize, at: Instant) -> super::cache::CarrierRank {
        let candidate = &self.candidates[index];
        self.cache.rank_at(
            self.key(index),
            candidate.kind(),
            candidate.variant().map_or("", |v| v.as_ref()),
            at,
        )
    }

    fn choose(
        &self,
        schedule: &DialSchedule,
        session: &Session<D>,
        eligible: &[TargetCandidate],
        need: Directions,
        recovery: bool,
        at: Instant,
    ) -> CandidateSelection {
        let mut best = None;
        let mut selection = CandidateSelection::default();
        let policy = session.session_policy();
        let cutoff = recovery
            .then(|| recovery_cutoff(session, self.timeout))
            .flatten();
        for path in eligible {
            let index = self.by_id[&path.id];
            let candidate = &self.candidates[index];
            let expected = self.member_spec(index).expected();
            let covers_need = if recovery {
                expected.difference(need) != expected
            } else {
                expected.contains(need)
            };
            if !covers_need {
                continue;
            }
            let gate = schedule.blocked(self.id(index), at);
            let key_retry =
                self.cache
                    .next_candidate_retry(self.key(index), candidate, recovery, cutoff);
            let recovery_due = !recovery
                || self
                    .cache
                    .recovery_due(self.key(index), candidate, at, cutoff);
            if !policy.allows_candidate(self.id(index), expected) {
                if recovery_due {
                    selection.suppressed.push(BlockedStart {
                        index,
                        reason: RetryAdmission::Unauthorized,
                    });
                }
                continue;
            }
            if let Some(after) = gate {
                if recovery_due {
                    selection.suppressed.push(BlockedStart {
                        index,
                        reason: RetryAdmission::DialAfter,
                    });
                }
                note_retry(
                    &mut selection.retry,
                    key_retry.map_or(after, |due| due.max(after)),
                    ControllerBlock::DialAfter,
                );
                continue;
            }
            let preference = self.priority(
                index,
                if need == Directions::RECEIVE {
                    path.receive
                } else {
                    path.send
                },
            );
            let admission =
                self.cache
                    .candidate_admission(self.key(index), candidate, recovery, cutoff);
            let cooling = match admission {
                Ok(cooling) => cooling,
                Err(reason) => {
                    if let Some(next) = key_retry {
                        note_retry(&mut selection.retry, next, ControllerBlock::Retry);
                    }
                    if recovery_due {
                        selection.suppressed.push(BlockedStart { index, reason });
                    }
                    continue;
                }
            };
            let stage = if preference.standby {
                2
            } else {
                u8::from(cooling)
            };
            let score = self.score(index, at);
            let bucket = if recovery || self.choice == ChoicePolicy::D160 {
                score_order(score.score)
            } else {
                0
            };
            let cool = score.retry_at.filter(|_| recovery && stage == 1);
            let rank = (
                stage,
                preference.tier,
                cool,
                std::cmp::Reverse(bucket),
                index,
            );
            if best.is_none_or(|previous| rank < previous) {
                best = Some(rank);
            }
        }
        selection.dial = best.map(|rank| rank.4);
        selection
    }

    fn upgrade(
        &self,
        schedule: &DialSchedule,
        session: &Session<D>,
        member: &MemberSnapshot,
        quota: &MemberQuota,
        at: Instant,
    ) -> CandidateSelection {
        if self.choice != ChoicePolicy::D160 || !member.stable.contains(member.expected) {
            return CandidateSelection::default();
        }
        let Some(&current) = member.candidate.as_ref().and_then(|id| self.by_id.get(id)) else {
            return CandidateSelection::default();
        };
        let floor = self.score(current, at).reliability * self.upgrade_ratio;
        let alternatives: Vec<_> = quota
            .candidates
            .iter()
            .filter(|path| {
                let index = self.by_id[&path.id];
                let score = self.score(index, at);
                let preference = self.priority(index, path.send);
                index != current
                    && !preference.standby
                    && score.attempts >= 3
                    && score.reliability >= floor
            })
            .cloned()
            .collect();
        self.choose(
            schedule,
            session,
            &alternatives,
            quota.directions,
            false,
            at,
        )
    }
}

fn note_retry(wait: &mut Option<(Instant, ControllerBlock)>, at: Instant, reason: ControllerBlock) {
    if wait.is_none_or(|(due, _)| at < due) {
        *wait = Some((at, reason));
    }
}

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

struct QuotaMatching<'a> {
    quotas: Vec<(&'a GroupTarget, &'a MemberQuota)>,
    members: Vec<Option<usize>>,
    quota_slots: Vec<usize>,
}

impl<'a> QuotaMatching<'a> {
    fn match_target<D: Driver>(
        controller: &Controller<D>,
        target: &'a SessionTarget,
        members: &[MemberSnapshot],
        excluded: &BTreeSet<MemberId>,
    ) -> Self {
        let mut quotas: Vec<_> = target
            .groups
            .iter()
            .flat_map(|group| group.quotas.iter().map(move |quota| (group, quota)))
            .collect();
        quotas.sort_unstable_by_key(|(grp, quota)| (&grp.id, &quota.id));
        let slots: Vec<_> = quotas
            .iter()
            .enumerate()
            .flat_map(|(i, (_, quota))| {
                std::iter::repeat_n(i, quota.count.min(members.len().saturating_add(1)))
            })
            .collect();
        let mut order: Vec<_> = members
            .iter()
            .enumerate()
            .filter_map(|(i, member)| {
                let candidate = member
                    .candidate
                    .as_ref()
                    .and_then(|id| controller.by_id.get(id))?;
                (member.complete && !excluded.contains(&member.id))
                    .then_some((*candidate, member.id, i))
            })
            .collect();
        order.sort_unstable();
        let edges: Vec<Vec<usize>> = slots
            .iter()
            .map(|&quota| {
                let rule = quotas[quota].1;
                order
                    .iter()
                    .filter_map(|&(_, _, index)| {
                        let member = &members[index];
                        (member.covered.contains(rule.directions)
                            && rule
                                .candidates
                                .iter()
                                .any(|path| Some(&path.id) == member.candidate.as_ref()))
                        .then_some(index)
                    })
                    .collect()
            })
            .collect();
        let mut assigned = vec![None; members.len()];
        for slot in 0..edges.len() {
            augment(slot, 0, &edges, &mut assigned);
        }
        // Freeze slots in order. A preferred member can displace a later
        // match only if the remaining graph can still attain the same count.
        for (slot, candidates) in edges.iter().enumerate() {
            for &candidate in candidates {
                let previous = assigned[candidate];
                if previous.is_some_and(|old| old < slot) {
                    continue;
                }
                if previous == Some(slot) {
                    break;
                }
                let current = assigned.iter().position(|&owner| owner == Some(slot));
                assigned[candidate] = Some(slot);
                if let Some(member) = current {
                    assigned[member] = None;
                }
                let requires_repair = previous.is_some() && current.is_some();
                let repaired = !requires_repair
                    || (slot + 1..edges.len()).any(|later| {
                        !assigned.contains(&Some(later))
                            && augment(later, slot + 1, &edges, &mut assigned)
                    });
                if repaired {
                    break;
                }
                assigned[candidate] = previous;
                if let Some(member) = current {
                    assigned[member] = Some(slot);
                }
            }
        }
        let mut result = vec![None; slots.len()];
        for (member, slot) in assigned.into_iter().enumerate() {
            if let Some(slot) = slot {
                result[slot] = Some(member);
            }
        }
        Self {
            quotas,
            members: result,
            quota_slots: slots,
        }
    }

    fn deficits(&self) -> Vec<QuotaDeficit> {
        let mut completed = vec![0; self.quotas.len()];
        for (&quota, assigned) in self.quota_slots.iter().zip(&self.members) {
            completed[quota] += usize::from(assigned.is_some());
        }
        self.quotas
            .iter()
            .zip(completed)
            .filter_map(|((group, quota), count)| {
                let missing = quota.count - count;
                (missing != 0).then(|| QuotaDeficit {
                    group: group.id.clone(),
                    quota: quota.id.clone(),
                    missing,
                })
            })
            .collect()
    }
}

fn augment(
    slot: usize,
    first_unfixed: usize,
    edges: &[Vec<usize>],
    assigned: &mut [Option<usize>],
) -> bool {
    let mut seen = vec![false; assigned.len()];
    let mut stack = vec![(slot, 0)];
    let mut path = Vec::new();
    while let Some((slot, next)) = stack.last_mut() {
        let Some(&member) = edges[*slot].get(*next) else {
            stack.pop();
            path.pop();
            continue;
        };
        *next += 1;
        let previous = assigned[member];
        if seen[member] || previous.is_some_and(|old| old < first_unfixed) {
            continue;
        }
        seen[member] = true;
        if let Some(occupied) = previous {
            path.push((member, *slot));
            stack.push((occupied, 0));
        } else {
            assigned[member] = Some(*slot);
            for (member, destination) in path {
                assigned[member] = Some(destination);
            }
            return true;
        }
    }
    false
}

pub(super) const CONTROLLER_STAGGER: Duration = Duration::from_millis(250);

struct Plan {
    deficit: Vec<QuotaDeficit>,
    pool: Option<String>,
    dial: Option<(usize, AttemptCause)>,
    needed: Directions,
    drain: Vec<MemberId>,
    epoch: u64,
    next: Option<Instant>,
    blocked: Option<ControllerBlock>,
    suppressed: Vec<BlockedStart>,
}

impl Plan {
    fn consider(&mut self, selection: CandidateSelection) -> Option<usize> {
        if selection.dial.is_none()
            && selection
                .suppressed
                .iter()
                .any(|s| s.reason == RetryAdmission::AlreadyInFlight)
        {
            self.blocked = Some(ControllerBlock::Execution);
        }
        self.suppressed.extend(selection.suppressed);
        if let Some((at, reason)) = selection.retry
            && self.next.is_none_or(|next| at <= next)
        {
            self.next = Some(at);
            self.blocked = Some(reason);
        }
        selection.dial
    }

    fn count_due_starts<D: Driver>(
        &self,
        binding: &Binding<D>,
        session: &Session<D>,
        revision: u64,
    ) {
        if self.dial.is_some() {
            return;
        }
        session.command(|state| {
            if state.controller_current((binding.generation, revision)) {
                for start in &self.suppressed {
                    binding.controller.source.suppress_due(
                        &binding.owner,
                        start.index,
                        self.needed != Directions::NONE,
                        start.reason,
                    );
                }
            }
        });
    }

    fn new<D: Driver>(
        binding: &Binding<D>,
        session: &Session<D>,
        target: &SessionTarget,
        members: &[MemberSnapshot],
        stats: &[crate::PipeStats],
        (capacity, at, need): (CapacitySnapshot, Instant, Directions),
        (launched, last_pool): (&BTreeSet<usize>, Option<&str>),
    ) -> Self {
        let controller = &binding.controller;
        let schedule = &binding.dial_after;
        let mut excluded = BTreeSet::new();
        let mut epoch = 0;
        let mut stale = false;
        for intent in &target.replace {
            if !intent
                .evidence
                .iter()
                .all(|input| input.valid(SessionApi::id(session), capacity, members, stats, at))
            {
                stale = true;
                session.command(|state| {
                    if state.controller_current((binding.generation, target.revision)) {
                        binding.suppress_stale(target, members);
                    }
                });
                continue;
            }
            for &member in &intent.members {
                if members
                    .iter()
                    .any(|m| m.id == member && m.covered != Directions::NONE)
                {
                    excluded.insert(member);
                    epoch = epoch.max(intent.min_epoch);
                }
            }
        }
        let slots = QuotaMatching::match_target(controller, target, members, &excluded);
        let mut next = capacity.peer_retry_at.filter(|&retry| retry > at);
        let rotation: Vec<_> = slots
            .quota_slots
            .iter()
            .zip(&slots.members)
            .filter_map(|(&quota, &member)| {
                let rule = slots.quotas[quota].0.rotation;
                let id = members[member?].id;
                (rule.send_bytes.is_some() || rule.receive_bytes.is_some()).then_some((
                    id,
                    rule.send_bytes,
                    rule.receive_bytes,
                ))
            })
            .collect();
        session.command(|state| {
            if !state.controller_current((binding.generation, target.revision)) {
                return;
            }
            state.core.set_member_rotation(&rotation);
            for (&quota, &member) in slots.quota_slots.iter().zip(&slots.members) {
                if let Some(index) = member {
                    let rotation = slots.quotas[quota].0.rotation;
                    let member = &members[index];
                    let age = stats
                        .iter()
                        .filter(|s| member.pipes.contains(&s.pipe))
                        .map(|s| s.attached_for)
                        .max()
                        .unwrap_or_default();
                    if state.core.member_rotation_due(member.id)
                        || rotation.max_age.is_some_and(|limit| age >= limit)
                    {
                        excluded.insert(member.id);
                    } else if let Some(age_limit) = rotation.max_age {
                        next = earliest(next, at.checked_add(age_limit.saturating_sub(age)));
                    }
                }
            }
        });
        let slots = QuotaMatching::match_target(controller, target, members, &excluded);
        let mut plan = Self {
            deficit: slots.deficits(),
            pool: None,
            dial: None,
            needed: need,
            drain: Vec::new(),
            epoch,
            next,
            blocked: stale.then_some(ControllerBlock::StaleDecision),
            suppressed: Vec::new(),
        };
        let need = plan.needed;
        for (&quota, member) in slots.quota_slots.iter().zip(&slots.members) {
            if let Some(index) = *member {
                let member = &members[index];
                let rule = slots.quotas[quota].1;
                let Some(path) = rule
                    .candidates
                    .iter()
                    .find(|path| Some(&path.id) == member.candidate.as_ref())
                else {
                    continue;
                };
                let candidate = controller.by_id[&path.id];
                let send = controller.priority(candidate, path.send);
                let receive = controller.priority(candidate, path.receive);
                session.install_member_preferences(
                    (binding.generation, target.revision),
                    &member.pipes,
                    send,
                    receive,
                );
            }
        }
        if need != Directions::NONE {
            let all: Vec<_> = controller
                .by_id
                .iter()
                .filter(|(_, index)| !launched.contains(index))
                .map(|(id, _)| TargetCandidate {
                    id: id.clone(),
                    send: None,
                    receive: None,
                })
                .collect();
            if let Some(index) =
                plan.consider(controller.choose(schedule, session, &all, need, true, at))
            {
                let expected = controller.member_spec(index).expected();
                plan.dial = Some((index, AttemptCause::Recovery));
                plan.blocked = None;
                plan.needed = need.difference(need.difference(expected));
                plan.epoch = 0;
                return plan;
            }
            plan.blocked.get_or_insert(if plan.next.is_some() {
                ControllerBlock::Retry
            } else {
                ControllerBlock::NoEligibleCandidate
            });
            return plan;
        }
        if target.groups.is_empty() && target.replace.is_empty() {
            return plan;
        }
        let matched: BTreeSet<_> = slots.members.iter().flatten().copied().collect();
        let mut drain: Vec<_> = members
            .iter()
            .enumerate()
            .filter(|(index, member)| {
                !matched.contains(index)
                    && member.covered != Directions::NONE
                    && (excluded.contains(&member.id)
                        || !target.groups.is_empty()
                            && member
                                .candidate
                                .as_ref()
                                .is_some_and(|id| controller.by_id.contains_key(id)))
            })
            .map(|(_, member)| member.id)
            .collect();
        drain.sort_unstable();
        let count = slots.quota_slots.len();
        let pivot = last_pool.map_or(0, |last| {
            slots
                .quota_slots
                .partition_point(|&quota| slots.quotas[quota].0.id.as_str() <= last)
        });
        let order = (pivot..count).chain(0..pivot);
        for i in order.clone() {
            if slots.members[i].is_some() {
                continue;
            }
            let (group, rule) = slots.quotas[slots.quota_slots[i]];
            if let Some(index) = plan.consider(controller.choose(
                schedule,
                session,
                &rule.candidates,
                rule.directions,
                false,
                at,
            )) {
                plan.dial = Some((index, AttemptCause::Target));
                plan.pool = Some(group.id.clone());
                break;
            }
        }
        if plan.dial.is_none() && !plan.deficit.is_empty() {
            plan.blocked.get_or_insert(if plan.next.is_some() {
                ControllerBlock::Retry
            } else {
                ControllerBlock::NoEligibleCandidate
            });
            return plan;
        }
        if plan.dial.is_none() && drain.is_empty() {
            for i in order {
                if let Some(index) = slots.members[i] {
                    let (group, quota) = slots.quotas[slots.quota_slots[i]];
                    if let Some(candidate) = plan.consider(controller.upgrade(
                        schedule,
                        session,
                        &members[index],
                        quota,
                        at,
                    )) {
                        plan.dial = Some((candidate, AttemptCause::Target));
                        plan.pool = Some(group.id.clone());
                        drain.push(members[index].id);
                        break;
                    }
                }
            }
        }
        drain.truncate(1);
        if plan.dial.is_some() {
            plan.blocked = None;
        }
        plan.drain = drain;
        plan
    }
}

struct Batch<D: Driver> {
    change: CapacityChangeFor<D>,
    dial: Option<InProgress>,
}

struct InProgress {
    attempt: Attempt,
    index: usize,
    slot: usize,
}

struct Recovery<D: Driver> {
    change: Option<CapacityChangeFor<D>>,
    running: Vec<InProgress>,
    retry_round: bool,
    launched: BTreeSet<usize>,
    stagger: Option<Instant>,
    awaiting_start: Option<Attempt>,
}

/// Required service still missing after adopting the confirmed alternatives.
struct RecoveryNeed(Directions);

impl RecoveryNeed {
    fn includes(&self, provided: Directions) -> bool {
        overlaps(self.0, provided)
    }

    fn confirmed(&mut self, covered: Directions) {
        self.0 = self.0.difference(covered);
    }
}

impl<D: Driver> Default for Recovery<D> {
    fn default() -> Self {
        Self {
            change: None,
            running: Vec::new(),
            retry_round: false,
            launched: BTreeSet::new(),
            stagger: None,
            awaiting_start: None,
        }
    }
}

impl<D: Driver> Recovery<D> {
    fn round_ended(&self, need: Directions, plan: &Plan) -> bool {
        need != Directions::NONE
            && self.running.is_empty()
            && plan.dial.is_none()
            && !self.launched.is_empty()
    }

    fn observe(
        &mut self,
        capacity: CapacitySnapshot,
        members: &[MemberSnapshot],
        last_attempt: &mut Option<crate::AttemptResult>,
    ) -> Directions {
        if let Some(attempt) = &self.awaiting_start {
            let snapshot = attempt.snapshot();
            if let Some(started) = snapshot.started {
                self.stagger = started.checked_add(CONTROLLER_STAGGER);
                self.awaiting_start = None;
            } else if snapshot.result.is_some() {
                self.awaiting_start = None;
            }
        }
        let Some(change) = &self.change else {
            return capacity.required.difference(capacity.covered);
        };
        let mut need = RecoveryNeed(
            members
                .iter()
                .filter(|member| {
                    !self
                        .running
                        .iter()
                        .any(|dial| dial.attempt.member() == member.id)
                })
                .fold(capacity.required, |need, member| {
                    need.difference(member.covered)
                }),
        );
        self.running.sort_by_cached_key(|dial| {
            let at = dial.attempt.finished_at();
            (at.is_none(), at)
        });
        let mut failed = false;
        self.running.retain_mut(|dial| {
            if let Some(result) = dial.attempt.snapshot().result {
                let wanted = if result.reason == AttemptReason::Confirmed {
                    need.0
                } else {
                    Directions::NONE
                };
                need.confirmed(change.finish_recovery(dial.slot, wanted));
                if result.reason == AttemptReason::DialAfter {
                    self.launched.remove(&dial.index);
                }
                // Every failure drew a recovery retry; the next round waits for it.
                self.retry_round |= result.reason.is_failure();
                failed |= result.reason != AttemptReason::Confirmed;
                *last_attempt = Some(result);
                false
            } else if need.includes(dial.attempt.snapshot().need) {
                true
            } else {
                change.finish_recovery(dial.slot, Directions::NONE);
                if self
                    .awaiting_start
                    .as_ref()
                    .is_some_and(|attempt| attempt.member() == dial.attempt.member())
                {
                    self.awaiting_start = None;
                }
                false
            }
        });
        let covered_by_running = self.running.iter().fold(Directions::NONE, |covered, dial| {
            covered.union(dial.attempt.snapshot().need)
        });
        if failed && !covered_by_running.contains(need.0) {
            self.stagger = None;
        }
        if need.0 == Directions::NONE {
            *self = Self::default();
        } else if self.running.is_empty() && !change.recovery_active() {
            self.change = None;
            self.stagger = None;
        }
        need.0
    }

    fn start(&mut self, change: Option<CapacityChangeFor<D>>, dial: InProgress) {
        if let Some(change) = change {
            debug_assert!(self.change.is_none());
            self.change = Some(change);
        }
        self.launched.insert(dial.index);
        self.awaiting_start = Some(dial.attempt.clone());
        self.running.push(dial);
    }
}

/// The latest recovery start that leaves a full attempt before the session's
/// resume grace expires, while it is suspended.
fn recovery_cutoff<D: Driver>(session: &Session<D>, attempt_timeout: Duration) -> Option<Instant> {
    grace_cutoff(
        session.shared().lock().core.recovery_grace_deadline(),
        attempt_timeout,
    )
}

/// Without a known grace deadline there is no cap.
fn grace_cutoff(grace: Option<Instant>, attempt_timeout: Duration) -> Option<Instant> {
    grace.and_then(|grace| grace.checked_sub(attempt_timeout))
}

fn overlaps(first: Directions, second: Directions) -> bool {
    first.difference(second) != first
}

impl<D: Driver> Binding<D> {
    /// Counts a reconcile pass for tests that bound the loop's wakeups.
    #[cfg(test)]
    fn count_pass(&self) {
        self.passes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(not(test))]
    const fn count_pass(&self) {
        let _ = self;
    }

    fn suppress_stale(&self, target: &SessionTarget, members: &[MemberSnapshot]) {
        for input in target.replace.iter().flat_map(|intent| &intent.evidence) {
            if let Some(index) = members
                .iter()
                .find(|m| m.id == input.member)
                .and_then(|m| m.candidate.as_ref())
                .and_then(|id| self.controller.by_id.get(id))
            {
                self.controller.source.suppress_due(
                    &self.owner,
                    *index,
                    false,
                    RetryAdmission::Stale,
                );
            }
        }
    }

    fn detach(&self) {
        let _install = lock(&self.install);
        if let Some(session) = self.session.upgrade() {
            session.command(|state| {
                if let Some(pool) = &mut state.control
                    && pool.changes.controller.map(|stamp| stamp.0) == Some(self.generation)
                {
                    pool.changes.controller = None;
                    pool.demand = None;
                    state.transfer_controller_feedback(None);
                    super::capacity_change::invalidate_batches(state, 0, true, state.now());
                    state.core.set_member_rotation(&[]);
                    state.notify_capacity_change();
                }
            });
        }
        self.revoke();
    }

    fn revoke(&self) {
        self.stop.send_replace(true);
        self.owner.withdraw();
    }

    fn update_pending(
        &self,
        revision: u64,
        plan: &mut Plan,
        active: bool,
        need: Directions,
    ) -> bool {
        let _install = lock(&self.install);
        if *self.stop.borrow() || self.target.borrow().revision != revision {
            return false;
        }
        match plan.blocked {
            Some(
                ControllerBlock::Execution | ControllerBlock::Cleanup | ControllerBlock::QueueFull,
            ) => {}
            // Work in progress waits for its commit, not for domain permits:
            // withdraw the demand a renewed target queued so arbitration
            // does not keep waking this binding.
            Some(
                ControllerBlock::Stability
                | ControllerBlock::Coverage
                | ControllerBlock::StaleDecision,
            ) if active => {
                self.owner.withdraw();
            }
            None if active
                || (plan.dial.is_none()
                    && plan.drain.is_empty()
                    && plan.deficit.is_empty()
                    && need == Directions::NONE) =>
            {
                self.owner.withdraw();
            }
            _ => {
                if !active
                    && (need != Directions::NONE
                        || !plan.deficit.is_empty()
                        || !plan.drain.is_empty())
                    && matches!(self.owner.enqueue(), Err(ControllerError::QueueFull))
                {
                    plan.blocked = Some(ControllerBlock::QueueFull);
                } else {
                    self.owner.blocked();
                }
            }
        }
        true
    }

    fn publish_snapshot(
        &self,
        session: &Session<D>,
        revision: u64,
        observed: SessionObservation,
        plan: Plan,
        attempts: Vec<crate::AttemptId>,
        last_attempt: Option<crate::AttemptResult>,
    ) {
        let (domain_openers, domain_cleanup) = self.controller.domain.usage();
        let (host_calls_in_flight, cleanup_in_flight) = self.owner.usage();
        let SessionObservation {
            capacity,
            members,
            paths,
        } = observed;
        self.snapshot.send_replace(ControllerSnapshot {
            evidence: evidence::capture(
                SessionApi::id(session),
                (self.generation, revision),
                capacity,
                &members,
                &paths,
            ),
            generation: self.generation,
            predecessor: self.predecessor,
            revision,
            capacity,
            members,
            paths,
            deficits: plan.deficit,
            attempts,
            last_attempt,
            blocked: plan.blocked,
            next_retry: plan.next,
            host_calls_in_flight,
            cleanup_in_flight,
            domain_openers,
            domain_cleanup,
        });
    }
}

struct SessionObservation {
    capacity: CapacitySnapshot,
    members: Vec<MemberSnapshot>,
    paths: Vec<crate::PipeStats>,
}

struct BindingCount<'a>(&'a watch::Sender<usize>);

impl Drop for BindingCount<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count -= 1);
    }
}

async fn reconcile<D: Driver>(binding: Arc<Binding<D>>) {
    let _bound = BindingCount(&binding.controller.bindings);
    let live = super::resources::Live::new(super::resources::Kind::Maintainer);
    let controller = &binding.controller;
    let mut domain_changes = controller.domain.subscribe();
    let mut target_changes = binding.target.subscribe();
    let mut cache = controller.cache.subscribe();
    let mut stopped = binding.stop.subscribe();
    let mut closed = controller.closed.subscribe();
    let Some(shared) = binding.session.shared() else {
        binding.revoke();
        binding.done.send_replace(true);
        return;
    };
    let mut carrier_release = shared.lock().observe_carrier_release();
    drop(shared);
    let mut in_progress: Option<Batch<D>> = None;
    let mut recovery = Recovery::default();
    let mut admission = None;
    let mut current_revision = None;
    let mut last_attempt = None;
    let mut last_pool: Option<String> = None;
    loop {
        binding.count_pass();
        if *stopped.borrow() || *closed.borrow() {
            break;
        }
        let Some(session) = binding.session.upgrade() else {
            break;
        };
        if session.close_reason().is_some() {
            break;
        }
        let target = target_changes.borrow_and_update().clone();
        let at = controller.clock.now();
        let observed = {
            let state = session.shared().lock();
            SessionObservation {
                capacity: state.capacity(),
                members: state.core.members(),
                paths: state.control_paths(),
            }
        };
        let capacity = observed.capacity;
        if current_revision != Some((target.revision, capacity.policy_revision)) {
            if in_progress.as_ref().is_some_and(|work| {
                !work.change.is_current(
                    (binding.generation, target.revision),
                    capacity.policy_revision,
                )
            }) {
                in_progress = None;
            }
            recovery = Recovery::default();
            admission = None;
            current_revision = Some((target.revision, capacity.policy_revision));
        }
        let need = recovery.observe(capacity, &observed.members, &mut last_attempt);
        if session.shared().lock().capacity().observed != capacity.observed {
            continue;
        }
        let feedback = session.command(|state| {
            if state.controller_current((binding.generation, target.revision)) {
                state.observe_controller_feedback()
            } else {
                None
            }
        });
        let mut plan = Plan::new(
            &binding,
            &session,
            &target,
            &observed.members,
            &observed.paths,
            (capacity, at, need),
            (&recovery.launched, last_pool.as_deref()),
        );
        let round_ended = recovery.round_ended(need, &plan);
        let parked = round_ended && !recovery.retry_round && plan.suppressed.is_empty();
        if round_ended && recovery.retry_round {
            recovery = Recovery::default();
            plan = Plan::new(
                &binding,
                &session,
                &target,
                &observed.members,
                &observed.paths,
                (capacity, at, need),
                (&recovery.launched, last_pool.as_deref()),
            );
        }
        plan.next = earliest(plan.next, feedback);
        let mut attempts: Vec<_> = recovery
            .running
            .iter()
            .map(|dial| dial.attempt.snapshot().id)
            .filter(|id| id.0 != 0)
            .collect();
        if need != Directions::NONE {
            // A direction can become eligible while an ordinary rotation is pending.
            in_progress = None;
            if let Some(due) = recovery.stagger.filter(|&due| due > at) {
                plan.next = earliest(plan.next, Some(due));
            } else if recovery.awaiting_start.is_none() {
                plan.count_due_starts(&binding, &session, target.revision);
                if plan.dial.is_some() {
                    match apply_plan(
                        &binding,
                        &session,
                        &target,
                        capacity,
                        &plan,
                        (&mut admission, Some(&mut recovery)),
                    ) {
                        Ok(_) => {}
                        Err(block) => plan.blocked = Some(block),
                    }
                }
            }
        } else if let Some(job) = in_progress.as_mut() {
            let ready = if let Some(dial) = job.dial.as_mut() {
                if let Some(result) = dial.attempt.snapshot().result {
                    let confirmed = result.reason == AttemptReason::Confirmed;
                    last_attempt = Some(result);
                    if !confirmed {
                        in_progress = None;
                        continue;
                    }
                    true
                } else {
                    let id = dial.attempt.snapshot().id;
                    if id.0 != 0 {
                        attempts.push(id);
                    }
                    false
                }
            } else {
                true
            };
            if ready {
                if let Err(
                    block @ (ControllerBlock::Stability
                    | ControllerBlock::Coverage
                    | ControllerBlock::Cleanup
                    | ControllerBlock::QueueFull
                    | ControllerBlock::StaleDecision),
                ) = commit_change(&binding, &target, &job.change)
                {
                    plan.blocked = Some(block);
                } else {
                    in_progress = None;
                    continue;
                }
            }
        } else {
            let epoch_ready = plan.epoch <= session.epoch().unwrap_or(0);
            if epoch_ready {
                plan.count_due_starts(&binding, &session, target.revision);
            }
            if (plan.dial.is_some() || !plan.drain.is_empty()) && plan.blocked.is_none() {
                if epoch_ready {
                    match apply_plan(
                        &binding,
                        &session,
                        &target,
                        capacity,
                        &plan,
                        (&mut admission, None),
                    ) {
                        Ok(job) => {
                            if plan.pool.is_some() {
                                last_pool = plan.pool.take();
                            }
                            in_progress = job;
                            continue;
                        }
                        Err(block) => plan.blocked = Some(block),
                    }
                } else {
                    session.command(|state| {
                        state.advance_controller_epoch(
                            (binding.generation, target.revision),
                            capacity.policy_revision,
                        );
                    });
                    plan.blocked = Some(ControllerBlock::Epoch);
                }
            }
        }
        if plan.blocked == Some(ControllerBlock::DialAfter)
            && let Some((index, _)) = plan.dial
        {
            let after = binding
                .dial_after
                .blocked(controller.id(index), controller.clock.now());
            plan.next = earliest(plan.next, after);
        }
        if plan.dial.is_none() {
            admission = None;
        }
        let active = in_progress.is_some() || !recovery.running.is_empty();
        if !active && plan.dial.is_none() && plan.suppressed.is_empty() && plan.deficit.is_empty() {
            binding.owner.starts.finish_ordinary();
        }
        if !binding.update_pending(target.revision, &mut plan, active, need) {
            continue;
        }
        // For pending commits the core publishes the wakeup when stability,
        // epoch or protocol occupancy changes. Cache and budget wakeups can
        // come from work on a different session in this controller domain.
        let ready_at = plan.next;
        binding.publish_snapshot(
            &session,
            target.revision,
            observed,
            plan,
            attempts,
            last_attempt.clone(),
        );
        let shared = session.shared().clone();
        drop(session);
        if parked {
            cache.borrow_and_update();
            domain_changes.borrow_and_update();
            carrier_release.borrow_and_update();
        }
        tokio::select! {
            biased;
            _ = stopped.wait_for(|&stopped| stopped) => break,
            _ = closed.wait_for(|&closed| closed) => break,
            _ = target_changes.changed() => {}
            _ = capacity_changed(&shared, capacity.observed) => {}
            _ = carrier_release.changed() => {}
            _ = cache.changed() => {}
            () = async {
                if let Some(at) = ready_at {
                    super::deadline::sleep::<D>(&controller.clock, Some(at)).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
            _ = domain_changes.changed() => {}
        }
        if parked {
            recovery.retry_round = true;
        }
    }
    drop(in_progress);
    drop(recovery);
    drop(admission);
    binding.detach();
    drop(live);
    binding.done.send_replace(true);
}

fn apply_plan<D: Driver>(
    binding: &Binding<D>,
    session: &Session<D>,
    target: &SessionTarget,
    capacity: CapacitySnapshot,
    plan: &Plan,
    (admission, recovery): (&mut Option<ChangeAdmissionFor<D>>, Option<&mut Recovery<D>>),
) -> Result<Option<Batch<D>>, ControllerBlock> {
    let _install = lock(&binding.install);
    if *binding.stop.borrow() || binding.target.borrow().revision != target.revision {
        return Err(ControllerBlock::Capacity);
    }
    let controller = &binding.controller;
    let owner = &binding.owner;
    owner
        .enqueue()
        .map_err(|error| ControllerBlock::from_owner(&error))?;
    let mut request = ChangeRequest::new(capacity, controller.timeout);
    request.drain.clone_from(&plan.drain);
    request.min_epoch = plan.epoch;
    let Some((index, cause)) = plan.dial else {
        let change = session
            .begin_target_change(request, Some((binding.generation, target.revision)))
            .map_err(|error| blocked(&error))?;
        return Ok(Some(Batch { change, dial: None }));
    };
    let count_block = |error: ChangeError| {
        let reason = match error {
            ChangeError::Coverage => RetryAdmission::Coverage,
            ChangeError::Unauthorized => RetryAdmission::Unauthorized,
            ChangeError::Deadline => RetryAdmission::Deadline,
            ChangeError::Capacity | ChangeError::Busy(_) => RetryAdmission::Capacity,
            _ => RetryAdmission::Stale,
        };
        controller
            .source
            .suppress_due(owner, index, cause == AttemptCause::Recovery, reason);
        blocked(&error)
    };
    let cutoff = (cause == AttemptCause::Recovery)
        .then(|| recovery_cutoff(session, controller.timeout))
        .flatten();
    let gate = binding
        .dial_after
        .gate(controller.id(index))
        .with_recovery_cutoff(cutoff);
    request.add.push(controller.member_spec(index));
    if admission
        .as_ref()
        .is_none_or(|waiting| !waiting.matches(&request, (binding.generation, target.revision)))
    {
        *admission = Some(
            session
                .queue_target_change(request, Some((binding.generation, target.revision)))
                .map_err(count_block)?,
        );
    }
    let candidate = &controller.candidates[index];
    let mut granted = None;
    let mut domain_block = None;
    let mode = recovery
        .as_ref()
        .map_or(RecoveryAdmission::Ordinary, |recovery| {
            recovery.change.as_ref().map_or(
                RecoveryAdmission::Begin,
                CapacityChangeFor::continue_recovery,
            )
        });
    let next = admission
        .as_mut()
        .expect("queued change")
        .try_admit_with(mode, || {
            match controller.source.grant_attempt(
                owner,
                index,
                candidate.layout.len(),
                cause == AttemptCause::Recovery,
                false,
                &gate,
            ) {
                Ok(grant) => {
                    granted = Some(grant);
                    Ok(())
                }
                Err(reason) => {
                    domain_block = Some(reason);
                    Err(ChangeError::Capacity)
                }
            }
        });
    if !matches!(next, Err(ChangeError::Capacity | ChangeError::Busy(_))) {
        *admission = None;
    }
    if matches!(next, Err(ChangeError::Deadline)) {
        owner.withdraw();
    }
    let (change, slot) = next.map_err(|error| {
        if matches!(error, ChangeError::Cancelled | ChangeError::Deadline)
            && let Some(recovery) = recovery.as_ref()
            && recovery.running.is_empty()
        {
            // An expired transaction is replaced after its last attempt settles.
            owner.blocked();
        }
        domain_block.unwrap_or_else(|| count_block(error))
    })?;
    let batch = change
        .as_ref()
        .or_else(|| recovery.as_ref().and_then(|race| race.change.as_ref()))
        .expect("admitted batch");
    let (grant, permit) = granted.expect("admitted controller change");
    controller.cache.prime(controller.key(index), candidate);
    let attempt = batch
        .start_member_with(
            slot,
            candidate.opener(),
            cause,
            (cause == AttemptCause::Recovery).then_some(plan.needed),
            Some(super::capacity_change::ManagedAttempt::new(
                permit,
                grant,
                controller.origin(index),
            )),
        )
        .map_err(|error| {
            if recovery.is_some() {
                batch.finish_recovery(slot, Directions::NONE);
            }
            count_block(error)
        })?;
    let dial = InProgress {
        attempt,
        index,
        slot,
    };
    if let Some(recovery) = recovery {
        recovery.start(change, dial);
        Ok(None)
    } else {
        Ok(Some(Batch {
            change: change.expect("new batch"),
            dial: Some(dial),
        }))
    }
}

fn commit_change<D: Driver>(
    binding: &Binding<D>,
    target: &SessionTarget,
    change: &CapacityChangeFor<D>,
) -> Result<(), ControllerBlock> {
    let _install = lock(&binding.install);
    if *binding.stop.borrow() || binding.target.borrow().revision != target.revision {
        return Err(ControllerBlock::Capacity);
    }
    let owner = &binding.owner;
    let mut cleanup = None;
    let mut domain_block = None;
    let retiring = change
        .commit_controlled(
            |state, drain| target.check_evidence(state, Some(drain)),
            |pipes| {
                if pipes.is_empty() {
                    owner.withdraw();
                    return Ok(());
                }
                match owner.grant(
                    Demand {
                        opener: false,
                        cleanup: pipes.len(),
                    },
                    false,
                ) {
                    Ok(grant) => {
                        cleanup = Some(grant.cleanup);
                        Ok(())
                    }
                    Err(reason) => {
                        domain_block = Some(reason);
                        Err(ChangeError::Capacity)
                    }
                }
            },
        )
        .map_err(|error| domain_block.unwrap_or_else(|| blocked(&error)))?;
    if let Some(mut cleanup) = cleanup {
        for (outcome, permit) in retiring
            .into_iter()
            .zip(std::iter::from_fn(|| cleanup.split()))
        {
            D::spawn_controller(async move {
                let _permit = permit;
                outcome.released.wait().await;
            });
        }
    }
    Ok(())
}

fn blocked(error: &ChangeError) -> ControllerBlock {
    match error {
        ChangeError::Deadline => ControllerBlock::Deadline,
        ChangeError::Coverage => ControllerBlock::Coverage,
        ChangeError::Unauthorized => ControllerBlock::Unauthorized,
        ChangeError::StaleDecision => ControllerBlock::StaleDecision,
        ChangeError::Unstable => ControllerBlock::Stability,
        ChangeError::Epoch => ControllerBlock::Epoch,
        _ => ControllerBlock::Capacity,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct MemberOrigin {
    key: super::cache::Key,
    target: Option<String>,
    layout: Vec<Directions>,
}

pub(super) struct ControllerFeedback {
    pub(super) sources: BTreeMap<CandidateId, FeedbackSource>,
    pub(super) members: BTreeMap<MemberId, Arc<MemberFaults>>,
    pub(super) outage: super::cache::OutageLog,
}

impl<D: Driver> Controller<D> {
    fn origin(&self, index: usize) -> MemberOrigin {
        let candidate = &self.candidates[index];
        MemberOrigin {
            key: super::cache::candidate_key(self.key(index), candidate),
            target: candidate.target().map(|target| target.base().to_owned()),
            layout: candidate
                .layout
                .iter()
                .map(|part| part.directions)
                .collect(),
        }
    }
}

impl<D: Driver> State<D> {
    /// The binding's outage journal, after recording the current coverage.
    pub(super) fn outage_log(&self) -> Option<super::cache::OutageLog> {
        let log = self.control.as_ref()?.feedback.as_ref()?.outage.clone();
        log.observe(self.connected());
        Some(log)
    }

    fn connected(&self) -> bool {
        let (send, receive) = self.core.service_directions(&[]);
        send || receive
    }

    /// Coverage changes reach the binding through dispatch. A pipe that
    /// carries again ends an outage as a success.
    pub(super) fn observe_outage(&self) {
        if let Some(feedback) = self
            .control
            .as_ref()
            .and_then(|pool| pool.feedback.as_ref())
        {
            feedback.outage.observe(self.connected());
        }
    }

    pub(super) fn transfer_controller_feedback(&mut self, mut next: Option<ControllerFeedback>) {
        let at = self.now();
        let Some(pool) = self.control.as_mut() else {
            return;
        };
        if let Some(old) = pool.feedback.take() {
            if let Some(next) = &next {
                next.outage.adopt(&old.outage);
            }
            let paths = self.control_paths();
            let members = self.core.members();
            for (id, observer) in old.members {
                let member = members.iter().find(|member| member.id == id);
                if let Some(member) = member {
                    let metrics: Vec<_> = paths
                        .iter()
                        .filter(|pipe| member.pipes.contains(&pipe.pipe))
                        .collect();
                    observer.observe_performance(&metrics);
                }
                if let Some(next) = &mut next
                    && let Some(member) = member
                {
                    let source = member
                        .candidate
                        .as_ref()
                        .and_then(|id| next.sources.get(id));
                    observer.transfer(source.cloned(), at);
                    next.members.insert(id, observer);
                } else {
                    observer.transfer(None, at);
                }
            }
        }
        self.control.as_mut().expect("installed control").feedback = next;
    }

    pub(super) fn enroll_confirmed_members(&mut self, pipe: Option<PipeId>) {
        let Some(mut feedback) = self.control.as_mut().and_then(|pool| pool.feedback.take()) else {
            return;
        };
        let at = self.now();
        for member in self.core.members() {
            if !member.complete
                || pipe.is_some_and(|id| !member.pipes.contains(&id))
                || feedback.members.contains_key(&member.id)
            {
                continue;
            }
            let Some(source) = member
                .candidate
                .as_ref()
                .and_then(|id| feedback.sources.get(id))
            else {
                continue;
            };
            let metrics: Vec<_> = member
                .pipes
                .iter()
                .filter_map(|&id| self.core.pipe_info(id))
                .collect();
            let attached = metrics
                .iter()
                .filter_map(|s| s.health.attached_at)
                .max()
                .unwrap_or(at);
            let observer = MemberFaults::new(source.clone(), attached, &metrics);
            let capacity: Arc<dyn crate::proto::session::CapacityObserver> = observer.clone();
            for &pipe in &member.pipes {
                self.pipe_end(pipe).watch_faults(&observer);
                self.core
                    .watch_capacity(pipe, Arc::downgrade(&capacity), at);
                self.core.observe_pipe_stability(pipe, at);
            }
            observer.observe_performance(&metrics.iter().collect::<Vec<_>>());
            feedback.members.insert(member.id, observer);
        }
        self.control.as_mut().expect("installed control").feedback = Some(feedback);
    }

    pub(super) fn observe_controller_feedback(&mut self) -> Option<Instant> {
        let feedback = self.control.as_ref()?.feedback.as_ref()?;
        let members = self.core.members();
        let paths = self.control_paths();
        let at = self.now();
        feedback.members.iter().fold(None, |next, (id, observer)| {
            if let Some(member) = members.iter().find(|member| member.id == *id) {
                let stats: Vec<_> = paths
                    .iter()
                    .filter(|pipe| member.pipes.contains(&pipe.pipe))
                    .collect();
                observer.observe_performance(&stats);
            }
            earliest(next, observer.observe_time(at))
        })
    }

    pub(super) fn prune_controller_members(&mut self) {
        if let Some(pool) = &mut self.control
            && (!pool.origins.is_empty()
                || pool
                    .feedback
                    .as_ref()
                    .is_some_and(|f| !f.members.is_empty()))
        {
            let members = self.core.members();
            let live = |id: &MemberId| members.iter().any(|member| member.id == *id);
            pool.origins.retain(|id, _| live(id));
            if let Some(feedback) = &mut pool.feedback {
                let at = self.core.config().clock_domain.now();
                feedback.members.retain(|id, observer| {
                    let present = live(id);
                    if !present {
                        observer.transfer(None, at);
                    }
                    present
                });
            }
        }
    }
}

impl<D: Driver> Session<D> {
    /// Updates the local receive service preference of an attachment.
    /// The preference is evaluated by this endpoint's driver.
    ///
    /// # Errors
    ///
    /// Returns an error if multipath is unavailable or the pipe has no inbound direction.
    pub fn set_local_receive_preference(
        &self,
        pipe: PipeId,
        preference: Option<crate::PathPreference>,
    ) -> Result<(), crate::PipeError> {
        self.command(|state| {
            if state.core.set_local_receive_preference(pipe, preference)? {
                D::wake_driver(state);
            }
            Ok(())
        })
    }

    /// The local receive preference, when explicitly configured.
    #[must_use]
    pub fn local_receive_preference(&self, pipe: PipeId) -> Option<crate::PathPreference> {
        self.shared().lock().core.local_receive_preference(pipe)
    }

    fn install_member_preferences(
        &self,
        stamp: (u64, u64),
        pipes: &[PipeId],
        send: PathPreference,
        receive: PathPreference,
    ) {
        self.command(|state| {
            if state.control.as_ref().and_then(|c| c.changes.controller) != Some(stamp) {
                return;
            }
            let mut changed = false;
            for &pipe in pipes {
                changed |= state.core.set_local_path_preference(pipe, send, receive);
            }
            if changed {
                D::wake_driver(state);
            }
        });
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::{Directions, RecoveryNeed};

    #[test]
    fn send_confirmation_keeps_the_duplex_alternative() {
        let mut need = RecoveryNeed(Directions::BOTH);
        assert!(need.includes(Directions::SEND));
        assert!(need.includes(Directions::BOTH));

        need.confirmed(Directions::SEND);
        assert_eq!(need.0, Directions::RECEIVE);
        assert!(need.includes(Directions::BOTH));
        assert!(!need.includes(Directions::SEND));

        need.confirmed(Directions::BOTH);
        assert_eq!(need.0, Directions::NONE);
        assert!(!need.includes(Directions::BOTH));
    }
}

#[cfg(all(test, feature = "tokio"))]
pub(super) mod owner_tests {
    use super::*;

    pub(in crate::driver) async fn session() -> (crate::Session, crate::Session, crate::Listener) {
        let mut cfg = Config {
            pipe_auth: crate::PipeAuth::psk([42; 32]).with_end_to_end(),
            resume_timeout: Some(Duration::from_secs(120)),
            max_idle_timeout: None,
            ..Config::default()
        };
        cfg.session_policy.limits.steady_attachments = 6;
        let listener = crate::Listener::new(cfg.clone(), crate::ListenerConfig::default()).unwrap();
        let (a, b) = tokio::io::duplex(64 * 1024);
        let peer = listener.clone();
        tokio::spawn(async move {
            let _ = peer
                .handle_pipe(crate::PipeIo::new(b), crate::PipeHint::default())
                .await;
        });
        let client = crate::Session::connect(
            crate::PipeIo::new(a).with_carrier(crate::CarrierKind::Streaming),
            cfg,
        )
        .await
        .unwrap();
        let peer = listener.accept().await.unwrap();
        (client, peer, listener)
    }

    #[tokio::test(start_paused = true)]
    async fn stale_controller_plans_cannot_advance_epoch() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (session, _peer, _listener) = session().await;
            let first =
                SessionController::new(ControllerOptions::new("epoch-fence-first", Vec::new()))
                    .unwrap();
            let old = first.manage(&session, SessionTarget::default()).unwrap();
            let generation = old.snapshot().generation;
            let cap = session.capacity();
            let before = session.epoch();
            old.set_target(SessionTarget {
                revision: 1,
                ..Default::default()
            })
            .unwrap();
            assert!(!session.command(|state| {
                state.advance_controller_epoch((generation, 0), cap.policy_revision)
            }));
            let next =
                SessionController::new(ControllerOptions::new("epoch-fence-next", Vec::new()))
                    .unwrap();
            let next = next
                .take_over(
                    &old,
                    SessionTarget {
                        revision: 1,
                        ..Default::default()
                    },
                )
                .unwrap();
            assert!(!session.command(|state| {
                state.advance_controller_epoch((generation, 1), cap.policy_revision)
            }));
            assert_eq!(session.epoch(), before);
            assert!(session.command(|state| {
                state.advance_controller_epoch((next.snapshot().generation, 1), cap.policy_revision)
            }));
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_session_before_reconcile_withdraws_its_recovery_demand() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (session, _peer, _listener) = session().await;
            let candidate = crate::Candidate::new(crate::CarrierKind::Streaming, || async {
                unreachable!("the caller drops the session before the worker is polled")
            })
            .with_identity("demand", "demand");
            let cache = CarrierCache::default();
            let mut opts =
                ControllerOptions::new("demand-before-reconcile", vec![candidate.clone()]);
            opts.cache = Some(cache.clone());
            let ctl = SessionController::new(opts).unwrap();
            session.pipe(PipeId(0)).unwrap().abort().unwrap();
            let old = ctl.manage(&session, SessionTarget::default()).unwrap();
            let permit = cache.begin("demand", &candidate, true, None).unwrap();
            let start = permit.start_handle();
            start.start().unwrap();
            let at = cache.clock_domain().now();
            assert!(
                permit
                    .commit_cadence(AttemptReason::DialFailed, true, at, Some(1.0), None)
                    .is_ok()
            );
            assert!(
                cache
                    .retry_metrics("demand", crate::CarrierKind::Streaming, "")
                    .recovery_retry_at
                    .is_some()
            );
            super::super::capacity_change::OpenerAdmission::host_returned(&start);
            drop(permit);
            drop(session);
            old.done().await;
            assert_eq!(
                cache
                    .retry_metrics("demand", crate::CarrierKind::Streaming, "")
                    .recovery_retry_at,
                None
            );
        })
        .await
        .unwrap();
    }

    #[test]
    fn no_grace_deadline_means_no_recovery_cap() {
        let at = crate::ClockDomain::default().now();
        assert_eq!(grace_cutoff(None, Duration::from_secs(10)), None);
        assert_eq!(
            grace_cutoff(Some(at + Duration::from_secs(30)), Duration::from_secs(10)),
            Some(at + Duration::from_secs(20))
        );
    }

    fn host_opener_bug() -> std::io::Result<crate::PipeIo> {
        panic!("host opener bug")
    }

    /// A host opener failure (here a panic, reported as `hook_failed`) is no
    /// evidence against the carrier. The next attempt must still follow the
    /// recovery cadence instead of waiting for an unrelated change.
    #[tokio::test(start_paused = true)]
    async fn unattributed_recovery_failure_schedules_the_next_attempt() {
        tokio::time::timeout(Duration::from_secs(100), async {
            let (session, _peer, _listener) = session().await;
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let candidate = crate::Candidate::new(crate::CarrierKind::Streaming, {
                let calls = calls.clone();
                move || {
                    calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    async move { host_opener_bug() }
                }
            })
            .with_identity("hook", "hook");
            let mut config = crate::CarrierCacheConfig::default();
            config.recovery_sample = || 1.0;
            let cache = CarrierCache::new(config).unwrap();
            let mut opts = ControllerOptions::new("unattributed-recovery", vec![candidate]);
            opts.cache = Some(cache.clone());
            let ctl = SessionController::new(opts).unwrap();
            session.pipe(PipeId(0)).unwrap().abort().unwrap();
            let handle = ctl.manage(&session, SessionTarget::default()).unwrap();
            // Cadence 1 s, 2 s, 4 s: four starts within 8 s.
            tokio::time::sleep(Duration::from_secs(8)).await;
            let calls = calls.load(std::sync::atomic::Ordering::Relaxed);
            let metrics = cache.retry_metrics("hook", crate::CarrierKind::Streaming, "");
            assert!(calls >= 4, "starts {calls}, {metrics:?}");
            let score = cache.score("hook", crate::CarrierKind::Streaming, "");
            assert_eq!(
                score.cooldown_level, 0,
                "an unattributed failure is not charged"
            );
            // The failed candidates leave no member behind.
            let members = session.members();
            assert!(
                members
                    .iter()
                    .all(|member| member.candidate.as_ref().is_none_or(|id| &*id.0 != "hook")),
                "{members:?}"
            );
            handle.release().unwrap();
        })
        .await
        .unwrap();
    }

    /// A clock that never advances: a confirmed replacement stays unsettled.
    struct Frozen(Instant);

    impl crate::MonotonicClock for Frozen {
        fn now(&self) -> Instant {
            self.0
        }

        fn sleep_until(
            &self,
            _: Instant,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    /// Renewing a replacement's evidence while its batch waits for Settle
    /// keeps the batch under the new revision. The binding must withdraw the
    /// demand that `set_target` queued and park, not keep waking.
    #[tokio::test]
    async fn renewed_replacement_waits_for_settle_without_spinning() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let clock = ClockDomain::with_source(Frozen(Instant::now()));
            let mut cfg = Config {
                pipe_auth: crate::PipeAuth::psk([42; 32]).with_end_to_end(),
                resume_timeout: Some(Duration::from_secs(120)),
                max_idle_timeout: None,
                clock_domain: clock.clone(),
                ..Config::default()
            };
            cfg.session_policy.limits.steady_attachments = 6;
            let listener =
                crate::Listener::new(cfg.clone(), crate::ListenerConfig::default()).unwrap();
            let (a, b) = tokio::io::duplex(64 * 1024);
            let peer = listener.clone();
            tokio::spawn(async move {
                let _ = peer
                    .handle_pipe(crate::PipeIo::new(b), crate::PipeHint::default())
                    .await;
            });
            let session = crate::Session::connect(
                crate::PipeIo::new(a).with_carrier(crate::CarrierKind::Streaming),
                cfg,
            )
            .await
            .unwrap();
            let _peer = listener.accept().await.unwrap();
            let joins = listener.clone();
            let candidate = crate::Candidate::new(crate::CarrierKind::Streaming, move || {
                let (near, far) = tokio::io::duplex(64 * 1024);
                let joins = joins.clone();
                tokio::spawn(async move {
                    let _ = joins
                        .handle_pipe(crate::PipeIo::new(far), crate::PipeHint::default())
                        .await;
                });
                async move { Ok(crate::PipeIo::new(near)) }
            })
            .with_identity("next", "next");
            let mut cache_config = crate::CarrierCacheConfig::default();
            cache_config.clock_domain = clock.clone();
            let mut opts = ControllerOptions::new("renewed-replacement", vec![candidate]);
            opts.clock_domain = clock.clone();
            opts.cache = Some(CarrierCache::new(cache_config).unwrap());
            let ctl = SessionController::new(opts).unwrap();
            let base = session.members()[0].id;
            let target = |revision| SessionTarget {
                revision,
                groups: vec![GroupTarget {
                    id: "main".into(),
                    quotas: vec![MemberQuota {
                        id: "member".into(),
                        count: 1,
                        directions: Directions::BOTH,
                        candidates: vec![TargetCandidate {
                            id: "next".into(),
                            send: None,
                            receive: None,
                        }],
                    }],
                    rotation: RotationPolicy::default(),
                }],
                replace: vec![ReplaceIntent {
                    id: "replace".into(),
                    members: vec![base],
                    min_epoch: 0,
                    evidence: Vec::new(),
                }],
            };
            let handle = ctl.manage(&session, target(1)).unwrap();
            let mut view = handle.subscribe();
            view.wait_for(|s| s.blocked == Some(ControllerBlock::Stability))
                .await
                .unwrap();
            for revision in 2..6 {
                handle.set_target(target(revision)).unwrap();
                view.wait_for(|s| {
                    s.revision == revision && s.blocked == Some(ControllerBlock::Stability)
                })
                .await
                .unwrap();
                for _ in 0..64 {
                    tokio::task::yield_now().await;
                }
                let before = handle.0.passes.load(std::sync::atomic::Ordering::Relaxed);
                for _ in 0..256 {
                    tokio::task::yield_now().await;
                }
                let after = handle.0.passes.load(std::sync::atomic::Ordering::Relaxed);
                assert!(
                    after - before <= 2,
                    "revision {revision}: {} passes while parked",
                    after - before
                );
                assert!(
                    !handle.0.owner.is_pending(),
                    "revision {revision}: demand left queued"
                );
            }
            handle.release().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn confirmed_member_feedback_exists_before_the_worker_runs() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (session, _peer, _listener) = session().await;
            let candidate = crate::Candidate::new(crate::CarrierKind::Streaming, || async {
                unreachable!("no opener before the first fault")
            })
            .with_identity("member", "member");
            let cache = CarrierCache::default();
            let mut options = ControllerOptions::new("feedback-at-confirmation", vec![candidate]);
            options.cache = Some(cache.clone());
            let controller = SessionController::new(options).unwrap();
            let handle = controller
                .manage_with_bootstrap(&session, SessionTarget::default(), Some(&"member".into()))
                .unwrap();
            session.command(|state| {
                let pipe = PipeId(0);
                let before = state.core.pipe_health(pipe).unwrap().send;
                let reason = crate::PipeHealthReason::CarrierError;
                state
                    .pipe_end(pipe)
                    .report_health(&crate::PipeHealthChange {
                        seq: 1,
                        pipe,
                        half: crate::PipeHalf::Outbound,
                        before,
                        after: crate::DirectionHealth {
                            reason,
                            state: crate::PipeHealthState::Ended,
                            ..before
                        },
                        reason,
                        at: state.now(),
                        since_join: Duration::ZERO,
                        failure: None,
                        physical_failure: None,
                    });
            });
            assert_eq!(
                cache
                    .retry_metrics("member", crate::CarrierKind::Streaming, "")
                    .faults,
                1
            );
            handle.release().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn quality_references_keep_the_original_expiry_and_withdrawal_version() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (session, _peer, _listener) = session().await;
            let controller = SessionController::new(ControllerOptions::new(
                "quality-reference-fence",
                Vec::new(),
            ))
            .unwrap();
            let handle = controller
                .manage(&session, SessionTarget::default())
                .unwrap();
            let capacity = session.capacity();
            let mut view = handle.snapshot();
            let at = session.command(|state| state.now());
            let mut paths = session.command(|state| state.control_paths());
            let path = &mut paths[0];
            path.ack_delivery = Some(crate::AckDelivery {
                start: at.checked_sub(Duration::from_millis(10)).unwrap(),
                end: at,
                delivered: 100,
                bytes_per_second: 10_000,
                load: crate::DeliveryLoad::Backlogged,
                valid_for: Duration::from_secs(2),
            });
            view.evidence = evidence::capture(
                session.id(),
                (view.generation, view.revision),
                capacity,
                &view.members,
                &paths,
            );
            let original = view
                .quality_input(
                    PipeId(0),
                    crate::PipeHalf::Outbound,
                    QualityMeasurement::Delivery,
                )
                .unwrap();
            let newer = at + Duration::from_secs(1);
            paths[0].ack_delivery.as_mut().unwrap().end = newer;
            assert!(original.valid(session.id(), capacity, &view.members, &paths, newer));
            view.paths[0].ack_delivery = paths[0].ack_delivery.map(|mut sample| {
                sample.valid_for = Duration::from_secs(60);
                sample
            });
            let reread = view
                .quality_input(
                    PipeId(0),
                    crate::PipeHalf::Outbound,
                    QualityMeasurement::Delivery,
                )
                .unwrap();
            assert_eq!(original, reread);
            assert!(!original.valid(
                session.id(),
                capacity,
                &view.members,
                &paths,
                at + Duration::from_secs(2)
            ));
            paths[0].delivery_version += 1;
            assert!(!original.valid(session.id(), capacity, &view.members, &paths, newer));
        })
        .await
        .unwrap();
    }
}
