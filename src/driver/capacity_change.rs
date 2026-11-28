//! Explicit, session-owned reservations and independently observable Join attempts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use super::attachment::CarrierReservation;
use super::handle::{Driver, State, WeakSession, session_ended_wait};
use super::handle::{Pipe, Session};
use crate::proto::session::JoinDeadline;
use crate::{
    AccountingTicket, CandidateId, Directions, MemberId, PipeDirection, PipeError, PipeFailure,
    PipeId, PipeOptions, SessionError,
};

/// A locally suppressed attempt for a candidate key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RetryAdmission {
    /// Another attempt has this key's only in-flight token.
    AlreadyInFlight,
    /// The shared missing-direction retry opportunity has not arrived.
    RecoveryWait,
    /// The ordinary scoring cooldown is active.
    Cooling,
    /// An authoritative carrier retry delay has not elapsed.
    RetryAfter,
    /// The host's candidate schedule prohibits this start.
    DialAfter,
    /// Current direction demand does not authorize this work.
    Coverage,
    /// Authorization or topology excludes this candidate.
    Unauthorized,
    /// Opener or Join capacity is exhausted.
    Capacity,
    /// The operation deadline has elapsed.
    Deadline,
    /// The reservation was cancelled, superseded, or already started.
    Stale,
}

impl fmt::Display for RetryAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyInFlight => "a candidate attempt is already in flight",
            Self::RecoveryWait => "waiting for recovery cadence",
            Self::Cooling => "the candidate is cooling",
            Self::RetryAfter => "the carrier requires a later retry",
            Self::DialAfter => "the host requires a later start",
            Self::Coverage => "the candidate no longer supplies needed coverage",
            Self::Unauthorized => "the candidate is excluded by authorization or topology",
            Self::Capacity => "opener or Join capacity is exhausted",
            Self::Deadline => "the operation deadline elapsed",
            Self::Stale => "the attempt reservation is no longer current",
        })
    }
}

impl std::error::Error for RetryAdmission {}

/// Key gate for a controller-owned opener. Manual and private attempts need no gate.
pub(super) trait OpenerAdmission: Send + Sync {
    fn start(&self) -> Result<(), RetryAdmission>;
    fn suppress(&self, reason: RetryAdmission);
    fn host_returned(&self);
    fn replied(&self, at: Instant);
}

pub(super) struct OpenerLifetime<'a>(pub(super) &'a dyn OpenerAdmission);

impl Drop for OpenerLifetime<'_> {
    fn drop(&mut self) {
        self.0.host_returned();
    }
}

/// One attachment in a member's intended layout.
#[derive(Debug, Clone, PartialEq)]
pub struct AttachmentSpec {
    /// Local directions served once the Join confirms.
    pub directions: Directions,
    /// Record, scheduling and liveness settings.
    pub options: PipeOptions,
}

impl AttachmentSpec {
    /// Declares the local direction independently of carrier I/O requirements.
    #[must_use]
    pub fn new(directions: Directions, options: PipeOptions) -> Self {
        Self {
            directions,
            options,
        }
    }

    fn join_options(&self) -> PipeOptions {
        let mut options = self.options.clone();
        options.direction = match self.directions {
            Directions::SEND => PipeDirection::Out,
            Directions::RECEIVE => PipeDirection::In,
            _ => PipeDirection::Bidi,
        };
        options
    }
}

/// One explicit member to open and hand over.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberSpec {
    /// Host candidate identity, if known.
    pub candidate: Option<CandidateId>,
    /// Exact number and directions of carriers the opener will hand over.
    pub attachments: Vec<AttachmentSpec>,
}

impl MemberSpec {
    pub(super) fn expected(&self) -> Directions {
        self.attachments
            .iter()
            .fold(Directions::NONE, |set, a| set.union(a.directions))
    }
}

/// A batch of additions and planned retirements.
#[derive(Debug, Clone, PartialEq)]
pub struct ChangeRequest {
    /// Policy revision observed when planning this batch.
    pub policy_revision: u64,
    /// Capacity watermark from the observation used to plan the batch.
    pub observed: u64,
    /// Time allowed to make the change. Zero uses the session Join timeout.
    pub timeout: Duration,
    /// New members to prepare.
    pub add: Vec<MemberSpec>,
    /// Whole existing members to retire at commit.
    pub drain: Vec<MemberId>,
    /// Minimum epoch of new Joins, if required.
    pub min_epoch: u64,
}

impl ChangeRequest {
    /// Prepares a request based on an atomic capacity observation.
    #[must_use]
    pub fn new(capacity: crate::CapacitySnapshot, timeout: Duration) -> Self {
        Self {
            policy_revision: capacity.policy_revision,
            observed: capacity.observed,
            timeout,
            add: Vec::new(),
            drain: Vec::new(),
            min_epoch: 0,
        }
    }
}

/// A stable session-local identifier allocated when an opener starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptId(pub u64);

/// Why a carrier is being opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptCause {
    /// Establish the session.
    Initial,
    /// Explicit capacity change.
    Manual,
    /// Cover a missing direction.
    Recovery,
    /// Satisfy or replace a target quota.
    Target,
}

/// Handshake to perform on the resources handed over by the opener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenStage {
    /// Start a session with one bidirectional carrier.
    Bootstrap,
    /// Add the declared layout to an existing session.
    Join,
}

/// The request actually granted to a carrier opener.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OpenRequest {
    /// Identity of this actual opener call.
    pub attempt: AttemptId,
    /// Why the resources are needed.
    pub cause: AttemptCause,
    /// Directions requested by this attempt.
    pub need: Directions,
    /// First handshake or Join.
    pub stage: OpenStage,
    /// Exact layout of the required carriers.
    pub layout: Vec<AttachmentSpec>,
    /// Monotonic setup deadline.
    pub deadline: Instant,
}

/// The resources already opened, including a possible partially failed open.
///
/// All returned carriers transfer to the attempt and are released by its executor.
#[derive(Debug)]
pub struct OpenedCarriersFor<C> {
    /// Carriers in the layout order.
    pub carriers: Vec<C>,
    /// Error completing the layout, if any.
    pub error: Option<io::Error>,
}

impl<C> OpenedCarriersFor<C> {
    /// Hands over a complete layout.
    #[must_use]
    pub fn ready(carriers: Vec<C>) -> Self {
        Self {
            carriers,
            error: None,
        }
    }
}

impl<C> From<io::Result<Vec<C>>> for OpenedCarriersFor<C> {
    fn from(result: io::Result<Vec<C>>) -> Self {
        match result {
            Ok(carriers) => Self::ready(carriers),
            Err(error) => Self {
                carriers: Vec::new(),
                error: Some(error),
            },
        }
    }
}

type OpenFuture<C> = Pin<Box<dyn Future<Output = OpenedCarriersFor<C>> + Send>>;
type OpenFn<C> = dyn Fn(OpenRequest) -> OpenFuture<C> + Send + Sync;

/// Opens the actual carriers and hands them to the session executor.
pub struct CarrierOpenerFor<C>(Arc<OpenFn<C>>);

impl<C> Clone for CarrierOpenerFor<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<C: Send + 'static> CarrierOpenerFor<C> {
    /// Wraps an asynchronous opener.
    pub fn new<F, Fut, O>(open: F) -> Self
    where
        F: Fn(OpenRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = O> + Send + 'static,
        O: Into<OpenedCarriersFor<C>> + 'static,
    {
        Self(Arc::new(move |request| {
            let result = open(request);
            Box::pin(async move { result.await.into() })
        }))
    }

    /// Hands over carriers already owned by the caller on the first invocation.
    #[must_use]
    pub fn prepared(carriers: Vec<C>) -> Self {
        let carriers = super::sync::Mutex::new(Some(carriers));
        Self::new(move |_| {
            let carriers = super::sync::lock(&carriers)
                .take()
                .ok_or_else(|| io::Error::other("prepared carriers already handed over"));
            std::future::ready(carriers)
        })
    }

    pub(super) async fn open(&self, request: OpenRequest) -> OpenedCarriersFor<C> {
        (self.0)(request).await
    }
}

impl<C> fmt::Debug for CarrierOpenerFor<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CarrierOpener").finish_non_exhaustive()
    }
}

/// A terminal attempt's stable classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttemptReason {
    /// The opener returned a carrier error.
    DialFailed,
    /// The opener panicked or returned an invalid layout.
    HookFailed,
    /// The host cancelled the attempt.
    Cancelled,
    /// The policy or target changed before handoff.
    NoLongerNeeded,
    /// The host moved the permitted start after this reservation.
    DialAfter,
    /// The session closed.
    SessionClosed,
    /// The monotonic deadline elapsed.
    Deadline,
    /// An authenticated Join Reply refused the attachment.
    JoinRefused,
    /// The attachment failed before confirmation. This includes the peer
    /// closing the carrier without a Reply after denying Join authorization.
    ConfirmationFailed,
    /// All attachments confirmed.
    Confirmed,
}

/// A terminal, immutable attempt result.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AttemptResult {
    /// Attempt identity. Zero while admitted work is waiting for its opener to start.
    pub id: AttemptId,
    /// Originating controller generation, when managed.
    pub generation: Option<u64>,
    /// Session-local identity of the reserved capacity batch.
    pub batch: u64,
    /// Stable terminal reason.
    pub reason: AttemptReason,
    /// Original Join failure, when available.
    pub error: Option<PipeError>,
    /// Opener error, when available.
    pub open_error: Option<Arc<io::Error>>,
    /// Complete or retained degraded member.
    pub member: Option<MemberId>,
    /// Assigned attachment IDs in submission order.
    pub pipes: Vec<PipeId>,
    /// Accounting tickets of carriers taken into the session.
    pub tickets: Vec<AccountingTicket>,
}

impl AttemptReason {
    /// Whether the attempt itself failed to deliver. Recovery pacing advances
    /// on every such failure; attribution decides only the candidate charge.
    pub(crate) const fn is_failure(self) -> bool {
        match self {
            Self::DialFailed
            | Self::HookFailed
            | Self::Deadline
            | Self::JoinRefused
            | Self::ConfirmationFailed => true,
            Self::Cancelled
            | Self::NoLongerNeeded
            | Self::DialAfter
            | Self::SessionClosed
            | Self::Confirmed => false,
        }
    }
}

impl AttemptResult {
    pub(crate) fn candidate_failed(&self) -> bool {
        Self::attributed(self.reason, self.error.as_ref())
    }

    fn attributed(reason: AttemptReason, error: Option<&PipeError>) -> bool {
        reason == AttemptReason::DialFailed
            || matches!(
                reason,
                AttemptReason::ConfirmationFailed
                    | AttemptReason::Deadline
                    | AttemptReason::JoinRefused
            ) && matches!(
                error,
                Some(
                    crate::PipeError::Io(_)
                        | crate::PipeError::Failed(
                            crate::PipeFailure::Carrier(_) | crate::PipeFailure::Stalled
                        )
                )
            )
    }
}

/// Attempt progress. A stalled observer can read the latest snapshot.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AttemptSnapshot {
    /// Attempt identity. Zero while admitted work is waiting for its opener to start.
    pub id: AttemptId,
    /// Originating controller generation, when managed.
    pub generation: Option<u64>,
    /// Session-local identity of the reserved capacity batch.
    pub batch: u64,
    /// Reason for opening the carriers.
    pub cause: AttemptCause,
    /// Requested directions.
    pub need: Directions,
    /// Candidate assigned by the host.
    pub candidate: Option<CandidateId>,
    /// Member identity allocated at attempt admission.
    pub member: MemberId,
    /// Assigned attachment IDs in layout order.
    pub pipes: Vec<PipeId>,
    /// Attachments whose authenticated Reply was observed.
    pub replied: Vec<PipeId>,
    /// Attachments confirmed by the peer.
    pub confirmed: Vec<PipeId>,
    /// Monotonic time when host execution starts.
    pub started: Option<Instant>,
    /// Monotonic terminal time, once known.
    pub ended: Option<Instant>,
    /// Immutable terminal result, once available.
    pub result: Option<AttemptResult>,
}

/// An attempt observation handle. Dropping this handle only stops observation.
#[derive(Clone)]
pub struct Attempt {
    cancel: Arc<dyn Fn() + Send + Sync>,
    progress: watch::Receiver<AttemptSnapshot>,
}

impl fmt::Debug for Attempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attempt")
            .field("id", &self.progress.borrow().id)
            .finish_non_exhaustive()
    }
}

impl Attempt {
    pub(super) fn member(&self) -> MemberId {
        self.progress.borrow().member
    }

    pub(super) fn finished_at(&self) -> Option<Instant> {
        self.progress.borrow().ended
    }

    /// Reads the latest progress.
    #[must_use]
    pub fn snapshot(&self) -> AttemptSnapshot {
        self.progress.borrow().clone()
    }

    /// Waits for an immutable result. Dropping this future cancels the wait.
    pub async fn wait(&self) -> AttemptResult {
        let mut progress = self.progress.clone();
        if let Ok(snapshot) = progress.wait_for(|p| p.result.is_some()).await
            && let Some(result) = &snapshot.result
        {
            return result.clone();
        }
        let abandoned = progress.borrow();
        AttemptResult {
            id: abandoned.id,
            generation: abandoned.generation,
            batch: abandoned.batch,
            reason: AttemptReason::SessionClosed,
            error: None,
            open_error: None,
            member: None,
            pipes: abandoned.pipes.clone(),
            tickets: Vec::new(),
        }
    }

    /// Requests cancellation of unconfirmed work.
    pub fn cancel(&self) {
        let pending = self.progress.borrow().result.is_none();
        if pending {
            (self.cancel)();
        }
    }
}

/// Why a capacity batch could not advance.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ChangeError {
    /// The session has closed.
    Closed(SessionError),
    /// The peer did not negotiate multipath.
    NotNegotiated,
    /// The submitted policy or controller revision is stale.
    Stale,
    /// A measurement used to authorize retirement expired or was withdrawn.
    StaleDecision,
    /// The absolute deadline has arrived.
    Deadline,
    /// Protocol or physical capacity is occupied.
    Capacity,
    /// Current topology excludes one of the requested candidate directions.
    Unauthorized,
    /// The index is already claimed, or the request is invalid.
    Invalid,
    /// The named member is no longer indexed.
    UnknownMember(MemberId),
    /// Another transaction already intends to remove a member of this batch.
    Busy(MemberId),
    /// The new members have not confirmed.
    Unconfirmed,
    /// The new members have not completed their stability hold.
    Unstable,
    /// Removing the requested members would lose a required direction.
    Coverage,
    /// The requested minimum epoch is not active.
    Epoch,
    /// The transaction is no longer active.
    Cancelled,
    /// The protocol refused the requested drain.
    Drain(PipeError),
}

impl fmt::Display for ChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "capacity change: {self:?}")
    }
}

impl std::error::Error for ChangeError {}

impl From<PipeError> for ChangeError {
    fn from(error: PipeError) -> Self {
        match error {
            PipeError::NoDirectionCoverage => Self::Coverage,
            _ => Self::Drain(error),
        }
    }
}

#[derive(Default)]
pub(super) struct Changes {
    sequence: u64,
    attempts: u64,
    reserved: usize,
    batches: BTreeMap<u64, Batch>,
    waiting: BTreeMap<u64, Queued>,
    recovery_streak: usize,
    pub(super) generation: u64,
    pub(super) controller: Option<(u64, u64)>,
}

struct Queued {
    request: ChangeRequest,
    revision: Option<(u64, u64)>,
    deadline: Option<Instant>,
    total: usize,
}

impl Queued {
    fn repairs(&self, missing: Directions) -> bool {
        self.request.add.iter().any(|member| {
            let directions = member.expected();
            directions.difference(missing) != directions
        })
    }

    fn ready<D: Driver>(
        &self,
        state: &State<D>,
        capacity: crate::CapacitySnapshot,
        at: Instant,
    ) -> bool {
        if self.deadline.is_some_and(|deadline| at >= deadline)
            || self.request.policy_revision != capacity.policy_revision
            || self.request.min_epoch > state.core.epoch().unwrap_or(0)
            || self.revision.is_some_and(|revision| {
                state
                    .control
                    .as_ref()
                    .and_then(|control| control.changes.controller)
                    != Some(revision)
            })
        {
            return false;
        }
        if !self.request.drain.is_empty() {
            let members = state.core.members();
            let batches = state
                .control
                .as_ref()
                .map(|control| &control.changes.batches);
            if self.request.drain.iter().any(|id| {
                !members.iter().any(|m| m.id == *id)
                    || batches.is_some_and(|batches| {
                        batches.values().any(|b| b.request.drain.contains(id))
                    })
            }) {
                return false;
            }
        }
        self.total
            <= join_room(
                state,
                capacity,
                self.repairs(capacity.required.difference(capacity.covered))
                    || !self.request.drain.is_empty(),
                at,
            )
    }
}

fn join_room<D: Driver>(
    state: &State<D>,
    snapshot: crate::CapacitySnapshot,
    replacement: bool,
    at: Instant,
) -> usize {
    let protocol = if replacement {
        state.core.replacement_join_room(at)
    } else {
        state.core.join_room(at)
    };
    let unopened = state
        .control
        .as_ref()
        .map_or(0, |control| control.changes.unopened_carriers());
    let carriers = snapshot
        .local_carrier_limit
        .saturating_sub(snapshot.local_carriers);
    protocol
        .saturating_sub(state.reserved_joins())
        .min(carriers.saturating_sub(unopened))
}

fn layout_size(request: &ChangeRequest) -> Result<usize, ChangeError> {
    let drains: BTreeSet<_> = request.drain.iter().collect();
    if drains.len() != request.drain.len() {
        return Err(ChangeError::Invalid);
    }
    request
        .add
        .iter()
        .try_fold(0usize, |total, member| {
            if member.attachments.is_empty()
                || member
                    .attachments
                    .iter()
                    .any(|a| a.directions == Directions::NONE || a.options.validate().is_err())
            {
                return None;
            }
            total.checked_add(member.attachments.len())
        })
        .ok_or(ChangeError::Invalid)
}

impl Changes {
    pub(super) fn current(&self, stamp: (u64, u64)) -> bool {
        self.controller == Some(stamp)
    }

    fn next_sequence(&mut self) -> Result<u64, ChangeError> {
        self.sequence = self.sequence.checked_add(1).ok_or(ChangeError::Invalid)?;
        Ok(self.sequence)
    }

    fn select<D: Driver>(
        &self,
        state: &State<D>,
        capacity: crate::CapacitySnapshot,
        at: Instant,
    ) -> (Option<u64>, Option<u64>) {
        let missing = capacity.required.difference(capacity.covered);
        let (mut recovery, mut ordinary) = (None, None);
        for (&id, queued) in &self.waiting {
            if queued.ready(state, capacity, at) {
                let first = if queued.repairs(missing) {
                    &mut recovery
                } else {
                    &mut ordinary
                };
                first.get_or_insert(id);
                if recovery.is_some() && ordinary.is_some() {
                    break;
                }
            }
        }
        (recovery, ordinary)
    }

    pub(super) fn seed_attempts(&mut self, attempts: u64) {
        self.attempts = self.attempts.max(attempts);
    }

    pub(super) fn reserved(&self) -> usize {
        self.reserved
    }

    fn unopened_carriers(&self) -> usize {
        self.batches
            .values()
            .map(|batch| {
                batch
                    .work
                    .values()
                    .filter(|work| work.id.is_none())
                    .map(|work| work.remaining)
                    .sum::<usize>()
            })
            .sum()
    }

    fn remove(&mut self, id: u64) -> Option<Batch> {
        let batch = self.batches.remove(&id)?;
        self.reserved -= batch
            .work
            .values()
            .map(|work| work.remaining)
            .sum::<usize>();
        batch.finished.send_replace(true);
        Some(batch)
    }
}

struct Batch {
    request: ChangeRequest,
    revision: Option<(u64, u64)>,
    deadline: watch::Sender<Instant>,
    recovery: bool,
    next_slot: usize,
    // Ordinary slots each name a reserved member. Recovery slots are attempts
    // within the one logical member transaction, sharing the batch's lifetime.
    work: BTreeMap<usize, AttemptWork>,
    finished: watch::Sender<bool>,
}

impl Batch {
    fn deadline(&self) -> Instant {
        *self.deadline.borrow()
    }

    fn check<D: Driver>(&self, state: &State<D>, at: Instant) -> Result<(), ChangeError> {
        check_request(state, &self.request, self.revision, self.deadline(), at)
    }
}

fn check_request<D: Driver>(
    state: &State<D>,
    request: &ChangeRequest,
    revision: Option<(u64, u64)>,
    deadline: Instant,
    at: Instant,
) -> Result<(), ChangeError> {
    let core = &state.core;
    if let Some(error) = core.error() {
        return Err(ChangeError::Closed(error.clone()));
    }
    if at >= deadline {
        return Err(ChangeError::Deadline);
    }
    if core.session_policy().revision != request.policy_revision
        || revision.is_some_and(|rev| {
            state
                .control
                .as_ref()
                .is_none_or(|p| !p.changes.current(rev))
        })
    {
        return Err(ChangeError::Stale);
    }
    if request.min_epoch > core.epoch().unwrap_or(0) {
        return Err(ChangeError::Epoch);
    }
    Ok(())
}

struct AttemptWork {
    spec: MemberSpec,
    remaining: usize,
    stop: watch::Sender<bool>,
    id: Option<MemberId>,
    confirmed: bool,
    cancelled: bool,
    need: Option<Directions>,
    pipes: Vec<PipeId>,
    attempt: Option<AttemptSettlement>,
}

struct AttemptSettlement {
    progress: watch::Sender<AttemptSnapshot>,
    feedback: Option<ManagedAttempt>,
    carriers: Option<CarrierReservation>,
}

pub(super) struct ManagedAttempt {
    pub(super) permit: super::cache::AttemptPermit,
    grant: Option<super::controller::domain::Grant>,
    cleanup: Vec<super::controller::domain::CleanupObserver>,
    pub(super) origin: super::controller::MemberOrigin,
}

impl ManagedAttempt {
    pub(super) fn new(
        permit: super::cache::AttemptPermit,
        grant: super::controller::domain::Grant,
        origin: super::controller::MemberOrigin,
    ) -> Self {
        Self {
            permit,
            grant: Some(grant),
            cleanup: Vec::new(),
            origin,
        }
    }
}

impl AttemptWork {
    fn new(spec: MemberSpec) -> Self {
        let remaining = spec.attachments.len();
        Self {
            spec,
            remaining,
            stop: watch::channel(false).0,
            id: None,
            confirmed: false,
            cancelled: false,
            need: None,
            pipes: Vec::new(),
            attempt: None,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Submission {
    batch: u64,
    index: usize,
}

impl Submission {
    pub(super) fn check<D: Driver>(self, state: &State<D>, at: Instant) -> Result<(), PipeError> {
        let changes = state
            .control
            .as_ref()
            .map(|p| &p.changes)
            .ok_or(PipeError::Deferred)?;
        let batch = changes
            .batches
            .get(&self.batch)
            .ok_or(PipeError::Deferred)?;
        batch.check(state, at).map_err(|error| match error {
            ChangeError::Deadline => PipeError::Failed(PipeFailure::CallerDeadline),
            ChangeError::Closed(error) => PipeError::SessionLost(error),
            _ => PipeError::Deferred,
        })?;
        let member = batch.work.get(&self.index).ok_or(PipeError::Deferred)?;
        if member.cancelled {
            return Err(PipeError::CallerCancelled(None));
        }
        let spec = &member.spec;
        if spec.candidate.as_ref().is_some_and(|candidate| {
            !state
                .core
                .session_policy()
                .allows_candidate(candidate, spec.expected())
        }) {
            return Err(PipeError::Deferred);
        }
        if member.pipes.is_empty()
            && member.need.is_some_and(|need| {
                let capacity = state.capacity();
                let missing = capacity.required.difference(capacity.covered);
                need.difference(missing) == need
            })
        {
            return Err(PipeError::Deferred);
        }
        if member.remaining == 0 {
            return Err(PipeError::InvalidArgument);
        }
        Ok(())
    }

    fn start_opener<D: Driver>(
        self,
        state: &mut State<D>,
        request: &mut OpenRequest,
        mut opener: CarrierOpenerFor<D::Carrier>,
        status: OpenerStatus<'_>,
        admission: Option<&dyn OpenerAdmission>,
    ) -> Result<(CarrierOpenerFor<D::Carrier>, CarrierReservation), AttemptReason> {
        // Logical completion and the opener's start arbitrate under the same owner lock.
        let OpenerStatus {
            cancelled,
            batch_finished,
            progress,
        } = status;
        let terminal = progress
            .borrow()
            .result
            .as_ref()
            .map(|result| result.reason);
        if let Some(reason) = terminal.or_else(|| {
            if *cancelled.borrow() {
                Some(AttemptReason::Cancelled)
            } else {
                batch_finished
                    .borrow()
                    .then_some(AttemptReason::NoLongerNeeded)
            }
        }) {
            return Err(reason);
        }
        if state.now() >= request.deadline {
            if let Some(permit) = admission {
                permit.suppress(crate::RetryAdmission::Deadline);
            }
            return Err(AttemptReason::Deadline);
        }
        let at = state.now();
        self.check(state, at).map_err(|error| {
            let reason = join_failure(&error);
            if let Some(permit) = admission {
                let stale_binding = state.control.as_ref().is_none_or(|ctl| {
                    ctl.changes.batches.get(&self.batch).is_none_or(|batch| {
                        batch.revision.is_some() && batch.revision != ctl.changes.controller
                    })
                });
                let blocked = match reason {
                    AttemptReason::NoLongerNeeded if stale_binding => crate::RetryAdmission::Stale,
                    AttemptReason::Deadline => crate::RetryAdmission::Deadline,
                    AttemptReason::NoLongerNeeded
                        if request.cause == AttemptCause::Recovery && {
                            let capacity = state.capacity();
                            let missing = capacity.required.difference(capacity.covered);
                            request.need.difference(missing) == request.need
                        } =>
                    {
                        crate::RetryAdmission::Coverage
                    }
                    AttemptReason::NoLongerNeeded => crate::RetryAdmission::Unauthorized,
                    _ => crate::RetryAdmission::Stale,
                };
                permit.suppress(blocked);
            }
            reason
        })?;
        if let Some(permit) = admission
            && state
                .capacity()
                .peer_retry_at
                .is_some_and(|retry| at < retry)
        {
            permit.suppress(crate::RetryAdmission::RetryAfter);
            return Err(AttemptReason::NoLongerNeeded);
        }
        let changes = &mut state.control.as_mut().expect("admitted attempt").changes;
        let id = changes
            .attempts
            .checked_add(1)
            .ok_or(AttemptReason::HookFailed)?;
        if let Some(permit) = admission {
            permit.start().map_err(|reason| match reason {
                crate::RetryAdmission::DialAfter => AttemptReason::DialAfter,
                _ => AttemptReason::NoLongerNeeded,
            })?;
        }
        let work = changes
            .batches
            .get_mut(&self.batch)
            .and_then(|batch| batch.work.get_mut(&self.index))
            .and_then(|work| work.attempt.as_mut())
            .expect("admitted attempt");
        let carriers = work.carriers.take().expect("reserved carriers");
        if let Some(feedback) = &mut work.feedback {
            let grant = feedback.grant.take().expect("reserved controller grant");
            (opener, feedback.cleanup) = grant.reserve_opener::<D>(opener);
        }
        changes.attempts = id;
        request.attempt = AttemptId(id);
        progress.send_modify(|snapshot| {
            snapshot.id = request.attempt;
            snapshot.started = Some(at);
        });
        let generation = progress.borrow().generation;
        if let Some(generation) = generation {
            state.app_event(crate::SessionEvent::AttemptStarted {
                generation,
                batch: self.batch,
                attempt: request.attempt,
            });
        }
        state.notify_capacity_change();
        Ok((opener, carriers))
    }

    fn cancel<D: Driver>(self, state: &mut State<D>) {
        let at = state.now();
        let Some(batch) = state
            .control
            .as_mut()
            .and_then(|control| control.changes.batches.get_mut(&self.batch))
        else {
            return;
        };
        let deadline = batch.deadline();
        let Some(work) = batch.work.get_mut(&self.index) else {
            return;
        };
        if work.confirmed || work.cancelled || at >= deadline {
            return;
        }
        let pipes: Vec<_> = work
            .pipes
            .iter()
            .copied()
            .filter(|&pipe| {
                !state
                    .core
                    .pipe_health(pipe)
                    .is_some_and(|health| health.peer_attached)
            })
            .collect();
        if pipes.is_empty() && work.remaining == 0 {
            return;
        }
        work.cancelled = true;
        work.stop.send_replace(true);
        self.settle(state, AttemptReason::Cancelled, None, None, None, at);
    }

    fn settle<D: Driver>(
        self,
        state: &mut State<D>,
        proposed: AttemptReason,
        mut error: Option<PipeError>,
        mut open_error: Option<Arc<io::Error>>,
        sample: Option<f64>,
        at: Instant,
    ) -> Option<super::cache::AttemptStart> {
        state.refresh_controller_demand();
        let outage = state.outage_log();
        let changes = &mut state.control.as_mut()?.changes;
        let stamp = changes.controller;
        let batch = changes.batches.get_mut(&self.batch)?;
        let deadline = batch.deadline();
        let replacement = !batch.request.drain.is_empty();
        let binding_changed = batch.revision.is_some() && batch.revision != stamp
            || batch.request.policy_revision != state.core.session_policy().revision;
        let work = batch.work.get_mut(&self.index)?;
        let attempt = work.attempt.as_ref()?;
        let reason = if binding_changed || work.cancelled {
            error = None;
            open_error = None;
            AttemptReason::Cancelled
        } else if state.core.error().is_some() {
            error = None;
            open_error = None;
            AttemptReason::SessionClosed
        } else if at >= deadline && proposed == AttemptReason::Confirmed {
            AttemptReason::Deadline
        } else {
            proposed
        };
        if let Some(feedback) = &attempt.feedback
            && let Err(start) = feedback.permit.commit_cadence(
                reason,
                reason.is_failure(),
                at,
                sample,
                outage.as_ref(),
            )
        {
            return Some(start);
        }
        let AttemptSettlement {
            progress,
            feedback,
            carriers,
        } = work.attempt.take().expect("checked attempt");
        drop(carriers);
        changes.reserved -= std::mem::take(&mut work.remaining);
        let confirmed = reason == AttemptReason::Confirmed;
        work.confirmed = confirmed;
        let pipes = work.pipes.clone();
        let outcomes: Vec<_> = pipes.iter().map(|&pipe| state.pipe_end(pipe)).collect();
        if confirmed && replacement {
            for &id in &pipes {
                state.core.observe_pipe_stability(id, at);
            }
        }
        if reason == AttemptReason::Deadline {
            for &id in &pipes {
                state.core.expire_join(id.get(), at);
            }
        }
        let retained = confirmed || !discard_additions(state, &pipes, at);
        let snapshot = progress.borrow();
        let result = AttemptResult {
            id: snapshot.id,
            generation: snapshot.generation,
            batch: snapshot.batch,
            reason,
            error,
            open_error,
            member: retained.then_some(snapshot.member),
            pipes,
            tickets: outcomes
                .iter()
                .filter_map(AccountingTicket::from_outcome)
                .collect(),
        };
        drop(snapshot);
        if let Some(feedback) = feedback {
            feedback.permit.settle(&result, at, outage.as_ref());
            if confirmed && let Some(outage) = &outage {
                outage.connected();
            }
            if confirmed {
                for slot in feedback.cleanup {
                    super::controller::domain::confirm(&slot);
                }
            }
        }
        if let Some(generation) = result.generation {
            state.app_event(crate::SessionEvent::AttemptFinished {
                generation,
                batch: self.batch,
                attempt: result.id,
                reason,
            });
        }
        progress.send_modify(|snapshot| {
            snapshot.ended = Some(at);
            snapshot.result = Some(result);
        });
        state.notify_capacity_change();
        None
    }

    pub(super) fn record<D: Driver>(self, state: &mut State<D>, pipe: PipeId, at: Instant) {
        let changes = &mut state.control.as_mut().expect("reserved submission").changes;
        let batch = changes
            .batches
            .get_mut(&self.batch)
            .expect("reserved batch");
        let member = batch.work.get_mut(&self.index).expect("reserved work");
        let spec = &member.spec;
        member.pipes.push(pipe);
        state.core.assign_member(
            pipe,
            member.id.expect("started member"),
            spec.candidate.clone(),
            spec.expected(),
            spec.attachments.len(),
        );
        if !batch.request.drain.is_empty() {
            state.core.stage_pipe_stability(pipe, at);
        }
        member.remaining -= 1;
        let member_id = member.id.expect("started member");
        let feedback = member
            .attempt
            .as_ref()
            .and_then(|attempt| attempt.feedback.as_ref())
            .map(|feedback| (feedback.origin.clone(), feedback.permit.start_handle()));
        changes.reserved -= 1;
        if let Some((origin, start)) = feedback {
            state
                .control
                .as_mut()
                .expect("installed control")
                .origins
                .entry(member_id)
                .or_insert(origin);
            state.pipe_end(pipe).watch_reply(Arc::new(start));
        }
    }
}

/// Report of an atomic capacity commit.
#[derive(Debug, Clone)]
pub struct ChangeResult {
    /// Members that started draining.
    pub draining: Vec<MemberId>,
    /// Capacity after the commit.
    pub capacity: crate::CapacitySnapshot,
}

/// A pending capacity reservation. Dropping it cancels uncommitted work.
#[derive(Debug)]
pub struct CapacityChangeFor<D: Driver> {
    session: WeakSession<D>,
    id: u64,
}

#[derive(Clone, Copy)]
enum Admission {
    Immediate,
    Queued(u64, RecoveryAdmission),
}

#[derive(Clone, Copy)]
pub(super) enum RecoveryAdmission {
    Ordinary,
    Begin,
    Continue(u64),
}

impl Admission {
    fn ticket(self) -> Option<u64> {
        match self {
            Self::Immediate => None,
            Self::Queued(ticket, _) => Some(ticket),
        }
    }
}

impl<D: Driver> Session<D> {
    pub(super) fn single_member_change(
        &self,
        options: PipeOptions,
        deadline: Option<Instant>,
        retiring: Option<MemberId>,
    ) -> Result<CapacityChangeFor<D>, ChangeError> {
        let directions = match options.direction {
            PipeDirection::In => Directions::RECEIVE,
            PipeDirection::Out => Directions::SEND,
            PipeDirection::Bidi => Directions::BOTH,
        };
        let (capacity, deadline) = self.command(|state| {
            (
                state.capacity(),
                deadline.or_else(|| state.now().checked_add(state.core.config().join_wait())),
            )
        });
        let deadline = deadline.ok_or(ChangeError::Invalid)?;
        let mut request = ChangeRequest::new(capacity, Duration::ZERO);
        request.add.push(MemberSpec {
            candidate: None,
            attachments: vec![AttachmentSpec::new(directions, options)],
        });
        request.drain.extend(retiring);
        let total = layout_size(&request)?;
        self.admit(
            request,
            None,
            total,
            Some(deadline),
            Admission::Immediate,
            || Ok(()),
        )
        .map(|(change, _)| change.expect("new change"))
    }

    pub(super) fn launch_recovery(&self, opener: CarrierOpenerFor<D::Carrier>) -> bool {
        let Ok(change) = self.single_member_change(PipeOptions::new(), None, None) else {
            return false;
        };
        let Ok(attempt) = change.start_member_with(0, opener, AttemptCause::Recovery, None, None)
        else {
            return false;
        };
        D::spawn_join(self.shared(), async move {
            if attempt.wait().await.reason == AttemptReason::Confirmed {
                let _ = change.commit();
            }
        });
        true
    }

    /// Waits for a newer capacity observation without losing intervening commits.
    pub(super) async fn capacity_changed_op(&self, observed: u64) -> crate::CapacitySnapshot {
        let mut released = self.shared().lock().observe_carrier_release();
        tokio::select! {
            snapshot = super::handle::capacity_changed(self.shared(), observed) => snapshot,
            _ = released.changed() => self.capacity(),
        }
    }

    /// Reserves capacity for an exact layout and a set of whole member retirements.
    ///
    /// # Errors
    ///
    /// Returns why admission failed and the session can be observed again.
    pub fn begin_change(
        &self,
        request: ChangeRequest,
    ) -> Result<CapacityChangeFor<D>, ChangeError> {
        self.begin_target_change(request, None)
    }

    pub(super) fn begin_target_change(
        &self,
        request: ChangeRequest,
        revision: Option<(u64, u64)>,
    ) -> Result<CapacityChangeFor<D>, ChangeError> {
        let total = layout_size(&request)?;
        let start = self.command(|state| state.now());
        let timeout = self.change_timeout(request.timeout)?;
        let deadline = start.checked_add(timeout).ok_or(ChangeError::Invalid)?;
        self.admit(
            request,
            revision,
            total,
            Some(deadline),
            Admission::Immediate,
            || Ok(()),
        )
        .map(|(change, _)| change.expect("new change"))
    }

    fn change_timeout(&self, timeout: Duration) -> Result<Duration, ChangeError> {
        if timeout > crate::proto::session::MAX_JOIN_DEADLINE {
            return Err(ChangeError::Invalid);
        }
        if timeout.is_zero() {
            return Ok(self.shared().lock().core.config().join_wait());
        }
        Ok(timeout)
    }

    /// Queues a change for capacity admission. Dropping the receipt withdraws its place.
    ///
    /// # Errors
    ///
    /// Rejects an invalid layout or deadline.
    pub fn queue_change(
        &self,
        request: ChangeRequest,
    ) -> Result<ChangeAdmissionFor<D>, ChangeError> {
        self.queue_target_change(request, None)
    }

    pub(super) fn queue_target_change(
        &self,
        request: ChangeRequest,
        revision: Option<(u64, u64)>,
    ) -> Result<ChangeAdmissionFor<D>, ChangeError> {
        let total = layout_size(&request)?;
        let timeout = self.change_timeout(request.timeout)?;
        let deadline = if revision.is_some() {
            None
        } else {
            Some(
                self.command(|state| state.now())
                    .checked_add(timeout)
                    .ok_or(ChangeError::Invalid)?,
            )
        };
        let (id, request) = self.command(|state| {
            let changes = &mut state.control.get_or_insert_default().changes;
            let id = changes.next_sequence()?;
            changes.waiting.insert(
                id,
                Queued {
                    request: request.clone(),
                    revision,
                    deadline,
                    total,
                },
            );
            state.notify_capacity_change();
            Ok::<_, ChangeError>((id, request))
        })?;
        Ok(ChangeAdmissionFor {
            session: self.downgrade(),
            id,
            request,
            revision,
            deadline,
            total,
        })
    }

    fn admit(
        &self,
        mut request: ChangeRequest,
        revision: Option<(u64, u64)>,
        total: usize,
        deadline: Option<Instant>,
        admission: Admission,
        grant: impl FnOnce() -> Result<(), ChangeError>,
    ) -> Result<(Option<CapacityChangeFor<D>>, usize), ChangeError> {
        let ticket = admission.ticket();
        let (new_batch, slot) = self.command(|state| {
            let start = state.now();
            if !state.core.is_multipath() {
                return Err(ChangeError::NotNegotiated);
            }
            let snapshot = state.capacity();
            if request.observed > snapshot.observed {
                return Err(ChangeError::Invalid);
            }
            let policy = state.core.session_policy();
            if request.add.iter().any(|member| {
                member
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| !policy.allows_candidate(candidate, member.expected()))
            }) {
                return Err(ChangeError::Unauthorized);
            }
            let missing = snapshot.required.difference(snapshot.covered);
            let repairs = request.add.iter().any(|member| {
                let directions = member.expected();
                directions.difference(missing) != directions
            });
            let replacement = !request.drain.is_empty() || repairs;
            let batches = state.control.as_ref().map(|p| &p.changes.batches);
            let present: BTreeSet<_> = state.core.members().into_iter().map(|m| m.id).collect();
            for member in &request.drain {
                if !present.contains(member) {
                    return Err(ChangeError::UnknownMember(*member));
                }
                if batches.is_some_and(|b| b.values().any(|p| p.request.drain.contains(member))) {
                    return Err(ChangeError::Busy(*member));
                }
            }
            let recovery = match admission {
                Admission::Queued(_, mode) => mode,
                Admission::Immediate => RecoveryAdmission::Ordinary,
            };
            let continuation = if let RecoveryAdmission::Continue(id) = recovery {
                let batch = batches
                    .and_then(|batches| batches.get(&id))
                    .filter(|batch| batch.recovery)
                    .ok_or(ChangeError::Cancelled)?;
                batch.check(state, start)?;
                Some((id, batch.next_slot, batch.deadline()))
            } else {
                None
            };
            if !matches!(recovery, RecoveryAdmission::Ordinary) {
                if request.add.len() != 1 || !request.drain.is_empty() {
                    return Err(ChangeError::Invalid);
                }
                if !repairs {
                    return Err(ChangeError::Coverage);
                }
            }
            let cutoff = if let Some((_, _, cutoff)) = continuation {
                Some(cutoff)
            } else if revision.is_some() && total != 0 {
                deadline
                    .into_iter()
                    .chain(start.checked_add(request.timeout))
                    .chain(state.core.attempt_grace_cutoff(start))
                    .min()
            } else {
                deadline.or_else(|| start.checked_add(request.timeout))
            }
            .ok_or(ChangeError::Deadline)?;
            check_request(state, &request, revision, cutoff, start)?;
            if total > join_room(state, snapshot, replacement, start) {
                return Err(ChangeError::Capacity);
            }
            let mut ordinary_ready = false;
            if total != 0
                && let Some(changes) = state.control.as_ref().map(|control| &control.changes)
            {
                let (recovery, ordinary) = changes.select(state, snapshot, start);
                ordinary_ready = ordinary.is_some();
                let ordinary_turn = changes.recovery_streak >= snapshot.limits.recovery_burst.get();
                let next = if ordinary_turn {
                    ordinary.or(recovery)
                } else {
                    recovery.or_else(|| (!repairs).then_some(ordinary).flatten())
                };
                if next.is_some_and(|next| Some(next) != ticket) {
                    return Err(ChangeError::Capacity);
                }
            }
            grant()?;
            let changes = &mut state.control.get_or_insert_default().changes;
            if let Some(ticket) = ticket {
                changes.waiting.remove(&ticket);
            }
            if total != 0 {
                if repairs && ordinary_ready {
                    changes.recovery_streak = changes.recovery_streak.saturating_add(1);
                } else {
                    changes.recovery_streak = 0;
                }
            }
            changes.reserved += total;
            let reserved = if let Some((id, slot, _)) = continuation {
                let batch = changes
                    .batches
                    .get_mut(&id)
                    .expect("checked recovery batch");
                batch.next_slot += 1;
                batch.work.insert(
                    slot,
                    AttemptWork::new(request.add.pop().expect("one layout")),
                );
                (None, slot)
            } else {
                let id = changes.next_sequence()?;
                let work: BTreeMap<_, _> = std::mem::take(&mut request.add)
                    .into_iter()
                    .map(AttemptWork::new)
                    .enumerate()
                    .collect();
                let (deadline, expires) = watch::channel(cutoff);
                let (finished, ended) = watch::channel(false);
                let batch = Batch {
                    request,
                    revision,
                    deadline,
                    recovery: matches!(recovery, RecoveryAdmission::Begin),
                    next_slot: work.len(),
                    work,
                    finished,
                };
                changes.batches.insert(id, batch);
                if let Some((generation, revision)) = revision {
                    state.app_event(crate::SessionEvent::BatchReserved {
                        generation,
                        revision,
                        batch: id,
                    });
                }
                (Some((id, expires, ended)), 0)
            };
            state.notify_capacity_change();
            Ok(reserved)
        })?;
        let Some((id, expires, mut ended)) = new_batch else {
            return Ok((None, slot));
        };
        let session = self.downgrade();
        let weak = self.downgrade();
        let clock = self.clock_domain();
        D::spawn_join(self.shared(), async move {
            tokio::select! {
                _ = ended.wait_for(|done| *done) => {}
                () = wait_for_deadline::<D>(&clock, expires) => {
                    if let Some(session) = weak.upgrade() {
                        cancel_batch(&session, id);
                    }
                }
            }
        });
        Ok((Some(CapacityChangeFor { session, id }), 0))
    }
}

/// A queued request for session-owned capacity.
#[derive(Debug)]
pub struct ChangeAdmissionFor<D: Driver> {
    session: WeakSession<D>,
    id: u64,
    request: ChangeRequest,
    revision: Option<(u64, u64)>,
    deadline: Option<Instant>,
    total: usize,
}

impl<D: Driver> ChangeAdmissionFor<D> {
    /// Tries to turn this request into a reserved capacity transaction.
    ///
    /// # Errors
    ///
    /// Returns capacity if the request still has to wait, or its terminal refusal.
    pub fn try_admit(&mut self) -> Result<CapacityChangeFor<D>, ChangeError> {
        self.try_admit_with(RecoveryAdmission::Ordinary, || Ok(()))
            .map(|(change, _)| change.expect("new change"))
    }

    pub(super) fn try_admit_with(
        &mut self,
        recovery: RecoveryAdmission,
        grant: impl FnOnce() -> Result<(), ChangeError>,
    ) -> Result<(Option<CapacityChangeFor<D>>, usize), ChangeError> {
        let session = self.session.upgrade().ok_or(ChangeError::Cancelled)?;
        if self.id == 0 {
            return Err(ChangeError::Cancelled);
        }
        let result = session.admit(
            self.request.clone(),
            self.revision,
            self.total,
            self.deadline,
            Admission::Queued(self.id, recovery),
            grant,
        );
        match &result {
            Ok(_) => self.id = 0,
            Err(ChangeError::Capacity | ChangeError::Busy(_)) => {}
            Err(_) => self.withdraw(&session),
        }
        result
    }

    pub(super) fn matches(&self, request: &ChangeRequest, revision: (u64, u64)) -> bool {
        self.revision == Some(revision)
            && self.request.policy_revision == request.policy_revision
            && self.request.min_epoch == request.min_epoch
            && self.request.add == request.add
            && self.request.drain == request.drain
    }

    /// Waits for admission, withdrawing this request when dropped.
    ///
    /// # Errors
    ///
    /// Returns the admission error when the request expires or loses eligibility.
    pub async fn wait(mut self) -> Result<CapacityChangeFor<D>, ChangeError> {
        let session = self.session.upgrade().ok_or(ChangeError::Cancelled)?;
        let clock = session.clock_domain();
        let shared = session.shared().clone();
        let mut released = shared.lock().observe_carrier_release();
        drop(session);
        loop {
            let observed = shared.lock().capacity().observed;
            match self.try_admit() {
                Err(ChangeError::Capacity | ChangeError::Busy(_)) => {}
                result => return result,
            }
            tokio::select! {
                _ = super::handle::capacity_changed(&shared, observed) => {}
                _ = released.changed() => {}
                () = super::deadline::sleep::<D>(&clock, self.deadline) => return Err(ChangeError::Deadline),
            }
        }
    }

    fn withdraw(&mut self, session: &Session<D>) {
        let id = std::mem::take(&mut self.id);
        session.command(|state| {
            if state
                .control
                .as_mut()
                .and_then(|control| control.changes.waiting.remove(&id))
                .is_some()
            {
                state.notify_capacity_change();
            }
        });
    }
}

impl<D: Driver> Drop for ChangeAdmissionFor<D> {
    fn drop(&mut self) {
        if self.id != 0
            && let Some(session) = self.session.upgrade()
        {
            self.withdraw(&session);
        }
    }
}

#[cfg(feature = "tokio")]
/// A queued asynchronous capacity request.
pub type ChangeAdmission = ChangeAdmissionFor<super::tokio::Tokio>;

impl<D: Driver> CapacityChangeFor<D> {
    /// Starts an opener for one reserved member and returns its attempt handle.
    ///
    /// # Errors
    ///
    /// A stale, expired or already claimed reservation cannot invoke the opener.
    pub fn start_member(
        &self,
        index: usize,
        opener: CarrierOpenerFor<D::Carrier>,
    ) -> Result<Attempt, ChangeError> {
        self.start_member_with(index, opener, AttemptCause::Manual, None, None)
    }

    pub(super) fn start_member_with(
        &self,
        index: usize,
        opener: CarrierOpenerFor<D::Carrier>,
        cause: AttemptCause,
        need: Option<Directions>,
        feedback: Option<ManagedAttempt>,
    ) -> Result<Attempt, ChangeError> {
        let session = self.session.upgrade().ok_or(ChangeError::Cancelled)?;
        let start = session.command(|state| state.now());
        let submission = Submission {
            batch: self.id,
            index,
        };
        let admission = feedback
            .as_ref()
            .map(|feedback| feedback.permit.start_handle());
        let (request, progress, observe, batch_finished, deadline_at, cancelled) = session
            .command(|state| {
                let changes = &state
                    .control
                    .as_ref()
                    .ok_or(ChangeError::Cancelled)?
                    .changes;
                let batch = changes
                    .batches
                    .get(&self.id)
                    .ok_or(ChangeError::Cancelled)?;
                batch.check(state, start)?;
                let member = batch.work.get(&index).ok_or(ChangeError::Invalid)?;
                if member.id.is_some() {
                    return Err(ChangeError::Invalid);
                }
                let carriers = member.remaining;
                let reservation = state
                    .reserve_carriers(carriers)
                    .ok_or(ChangeError::Capacity)?;
                let state_member = state.core.allocate_member();
                let changes = &mut state.control.as_mut().unwrap().changes;
                let batch = changes.batches.get_mut(&self.id).unwrap();
                let deadline = batch.deadline();
                let work = batch.work.get_mut(&index).expect("checked work");
                work.id = Some(state_member);
                work.need = need;
                let spec = &work.spec;
                let request = OpenRequest {
                    attempt: AttemptId(0),
                    cause,
                    need: need.unwrap_or_else(|| spec.expected()),
                    stage: OpenStage::Join,
                    layout: spec.attachments.clone(),
                    deadline,
                };
                let (progress, observe) = watch::channel(AttemptSnapshot {
                    id: request.attempt,
                    generation: batch.revision.map(|stamp| stamp.0),
                    batch: self.id,
                    cause,
                    need: request.need,
                    candidate: spec.candidate.clone(),
                    member: state_member,
                    pipes: Vec::new(),
                    replied: Vec::new(),
                    confirmed: Vec::new(),
                    started: None,
                    ended: None,
                    result: None,
                });
                work.attempt = Some(AttemptSettlement {
                    progress: progress.clone(),
                    feedback,
                    carriers: Some(reservation),
                });
                Ok((
                    request,
                    progress,
                    observe,
                    batch.finished.subscribe(),
                    batch.deadline.subscribe(),
                    work.stop.subscribe(),
                ))
            })?;
        let weak = session.downgrade();
        D::spawn_join(
            session.shared(),
            run_attempt(
                weak,
                submission,
                request,
                opener,
                admission,
                cancelled,
                batch_finished,
                deadline_at,
                progress,
            ),
        );
        let owner = session.downgrade();
        let cancel = Arc::new(move || {
            if let Some(shared) = owner.shared() {
                shared.command(|state| submission.cancel(state));
            }
        });
        Ok(Attempt {
            cancel,
            progress: observe,
        })
    }

    /// Commits a complete batch, rechecking epoch, stability and coverage together.
    ///
    /// # Errors
    ///
    /// The batch remains pending after a stability or coverage error.
    pub fn commit(&self) -> Result<ChangeResult, ChangeError> {
        self.commit_inner(
            |_, _| Ok(()),
            None::<fn(&[PipeId]) -> Result<(), ChangeError>>,
        )
        .map(|(result, _)| result)
    }

    pub(super) fn commit_controlled(
        &self,
        validate: impl FnOnce(&State<D>, &[MemberId]) -> Result<(), ChangeError>,
        reserve: impl FnOnce(&[PipeId]) -> Result<(), ChangeError>,
    ) -> Result<Vec<Arc<super::attachment::PipeOutcome>>, ChangeError> {
        self.commit_inner(validate, Some(reserve))
            .map(|(_, outcomes)| outcomes)
    }

    fn commit_inner(
        &self,
        validate: impl FnOnce(&State<D>, &[MemberId]) -> Result<(), ChangeError>,
        reserve: Option<impl FnOnce(&[PipeId]) -> Result<(), ChangeError>>,
    ) -> Result<(ChangeResult, Vec<Arc<super::attachment::PipeOutcome>>), ChangeError> {
        let session = self.session.upgrade().ok_or(ChangeError::Cancelled)?;
        session.command(|state| {
            let now = state.now();
            state.core.tick(now);
            let changes = &state
                .control
                .as_ref()
                .ok_or(ChangeError::Cancelled)?
                .changes;
            let batch = changes
                .batches
                .get(&self.id)
                .ok_or(ChangeError::Cancelled)?;
            batch.check(state, now)?;
            if !batch.request.drain.is_empty() {
                validate(state, &batch.request.drain)?;
            }
            let members = state.core.members();
            if batch.recovery {
                return Err(ChangeError::Invalid);
            }
            for work in batch.work.values() {
                let member = members.iter().find(|m| Some(m.id) == work.id);
                if !work.confirmed || member.is_none_or(|m| !m.complete) {
                    return Err(ChangeError::Unconfirmed);
                }
                if !batch.request.drain.is_empty()
                    && member.is_some_and(|m| !m.stable.contains(m.expected))
                {
                    return Err(ChangeError::Unstable);
                }
            }
            let mut pipes = Vec::new();
            for &id in &batch.request.drain {
                let member = members
                    .iter()
                    .find(|m| m.id == id)
                    .ok_or(ChangeError::UnknownMember(id))?;
                pipes.extend_from_slice(&member.pipes);
            }
            let mut retiring = Vec::new();
            if !pipes.is_empty() {
                state.core.drain_attachments(&pipes, now, |active| {
                    if let Some(reserve) = reserve {
                        reserve(active)?;
                        retiring.extend_from_slice(active);
                    }
                    Ok::<_, ChangeError>(())
                })?;
            }
            let outcomes = retiring.into_iter().map(|id| state.pipe_end(id)).collect();
            let batch = state
                .control
                .as_mut()
                .and_then(|pool| pool.changes.remove(self.id))
                .ok_or(ChangeError::Cancelled)?;
            if let Some((generation, _)) = batch.revision {
                for &member in &batch.request.drain {
                    state.app_event(crate::SessionEvent::DrainCommitted {
                        generation,
                        batch: self.id,
                        member,
                    });
                }
            }
            state.notify_capacity_change();
            Ok((
                ChangeResult {
                    draining: batch.request.drain,
                    capacity: state.capacity(),
                },
                outcomes,
            ))
        })
    }

    pub(super) fn continue_recovery(&self) -> RecoveryAdmission {
        RecoveryAdmission::Continue(self.id)
    }

    pub(super) fn is_current(&self, stamp: (u64, u64), policy: u64) -> bool {
        self.session.shared().is_some_and(|session| {
            let state = session.lock();
            state.controller_current(stamp)
                && state
                    .control
                    .as_ref()
                    .and_then(|pool| pool.changes.batches.get(&self.id))
                    .is_some_and(|batch| {
                        batch.revision == Some(stamp) && batch.request.policy_revision == policy
                    })
        })
    }

    pub(super) fn recovery_active(&self) -> bool {
        let Some(session) = self.session.upgrade() else {
            return false;
        };
        let state = session.shared().lock();
        state
            .control
            .as_ref()
            .and_then(|control| control.changes.batches.get(&self.id))
            .is_some_and(|batch| batch.check(&state, state.now()).is_ok())
    }

    pub(super) fn finish_recovery(&self, slot: usize, need: Directions) -> Directions {
        let Some(session) = self.session.upgrade() else {
            return Directions::NONE;
        };
        session.command(|state| {
            let now = state.now();
            let Some(changes) = state.control.as_ref().map(|control| &control.changes) else {
                return Directions::NONE;
            };
            let Some(batch) = changes.batches.get(&self.id).filter(|batch| batch.recovery) else {
                return Directions::NONE;
            };
            let Some(work) = batch.work.get(&slot) else {
                return Directions::NONE;
            };
            let covered =
                if work.confirmed && need != Directions::NONE && batch.check(state, now).is_ok() {
                    state
                        .core
                        .members()
                        .into_iter()
                        .find(|member| {
                            Some(member.id) == work.id
                                && member.complete
                                && member.covered.difference(need) != member.covered
                        })
                        .map_or(Directions::NONE, |member| member.covered)
                } else {
                    Directions::NONE
                };
            if covered == Directions::NONE {
                Submission {
                    batch: self.id,
                    index: slot,
                }
                .settle(
                    state,
                    AttemptReason::NoLongerNeeded,
                    None,
                    None,
                    None,
                    now,
                );
            }
            let changes = &mut state.control.as_mut().expect("checked control").changes;
            let work = changes
                .batches
                .get_mut(&self.id)
                .expect("checked batch")
                .work
                .remove(&slot)
                .expect("checked work");
            changes.reserved -= work.remaining;
            if covered == Directions::NONE {
                work.stop.send_replace(true);
                discard_additions(state, &work.pipes, now);
            }
            state.notify_capacity_change();
            covered
        })
    }

    /// Cancels work that has not crossed the drain commit point.
    pub fn cancel(&self) {
        if let Some(session) = self.session.upgrade() {
            cancel_batch(&session, self.id);
        }
    }
}

impl<D: Driver> Drop for CapacityChangeFor<D> {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn discard_additions<D: Driver>(state: &mut State<D>, pipes: &[PipeId], at: Instant) -> bool {
    for &pipe in pipes {
        if state
            .core
            .pipe_health(pipe)
            .is_some_and(|health| !health.peer_attached)
        {
            let _ = state.core.remove_pipe(pipe, false, at);
        }
    }
    let current = state.core.service_directions(&[]);
    let after = state.core.service_directions(pipes);
    if (current.0 && !after.0) || (current.1 && !after.1) {
        return false;
    }
    for pipe in pipes {
        let _ = state.core.remove_pipe(*pipe, false, at);
    }
    true
}

pub(super) fn renew_confirmed_replacement<D: Driver>(
    state: &mut State<D>,
    generation: u64,
    previous: u64,
    next: u64,
) {
    if let Some(pool) = &mut state.control {
        for batch in pool.changes.batches.values_mut() {
            if batch.revision == Some((generation, previous))
                && !batch.request.drain.is_empty()
                && !batch.work.is_empty()
                && batch.work.values().all(|work| work.confirmed)
            {
                batch.revision = Some((generation, next));
            }
        }
    }
}

pub(super) fn invalidate_batches<D: Driver>(
    state: &mut State<D>,
    revision: u64,
    target_only: bool,
    at: Instant,
) {
    if let Some(control) = &mut state.control {
        let stamp = control.changes.controller;
        control.changes.waiting.retain(|_, queued| {
            if target_only {
                queued.revision.is_none() || queued.revision == stamp
            } else {
                queued.request.policy_revision == revision
            }
        });
        let obsolete: Vec<_> = control
            .changes
            .batches
            .iter()
            .filter_map(|(&id, batch)| {
                let obsolete = if target_only {
                    batch.revision.is_some() && batch.revision != control.changes.controller
                } else {
                    batch.request.policy_revision != revision
                };
                obsolete.then_some(id)
            })
            .collect();
        for id in obsolete {
            rollback_batch(state, id, AttemptReason::Cancelled, at);
        }
    }
}

pub(super) fn tighten_suspended_attempts<D: Driver>(state: &mut State<D>) {
    let now = state.now();
    let Some(cutoff) = state.core.attempt_grace_cutoff(now) else {
        return;
    };
    if let Some(control) = &mut state.control {
        for batch in control.changes.batches.values_mut() {
            if batch.revision.is_some() && !batch.work.is_empty() && cutoff < batch.deadline() {
                batch.deadline.send_replace(cutoff);
            }
        }
    }
}

async fn wait_for_deadline<D: Driver>(
    clock: &crate::ClockDomain,
    mut deadline: watch::Receiver<Instant>,
) {
    loop {
        let at = *deadline.borrow_and_update();
        tokio::select! {
            biased;
            () = super::deadline::sleep::<D>(clock, Some(at)) => return,
            result = deadline.changed() => {
                if result.is_err() {
                    super::deadline::sleep::<D>(clock, Some(at)).await;
                    return;
                }
            }
        }
    }
}

fn rollback_batch<D: Driver>(state: &mut State<D>, id: u64, reason: AttemptReason, at: Instant) {
    let Some(batch) = state
        .control
        .as_ref()
        .and_then(|p| p.changes.batches.get(&id))
    else {
        return;
    };
    let slots: Vec<_> = batch.work.keys().copied().collect();
    for index in slots {
        Submission { batch: id, index }.settle(state, reason, None, None, None, at);
    }
    if let Some(batch) = state.control.as_mut().and_then(|p| p.changes.remove(id)) {
        let deadline = batch.deadline();
        let pipes: Vec<_> = batch.work.into_values().flat_map(|m| m.pipes).collect();
        if at >= deadline && reason != AttemptReason::Cancelled {
            for &pipe in &pipes {
                state.core.expire_join(pipe.get(), at);
            }
        }
        discard_additions(state, &pipes, at);
        if let Some((generation, _)) = batch.revision {
            state.app_event(crate::SessionEvent::BatchRolledBack {
                generation,
                batch: id,
            });
        }
        state.notify_capacity_change();
    }
}

pub(super) fn close_batches<D: Driver>(state: &mut State<D>) {
    let Some(changes) = state.control.as_ref().map(|pool| &pool.changes) else {
        return;
    };
    let batches: Vec<_> = changes.batches.keys().copied().collect();
    let at = state.now();
    for id in batches {
        rollback_batch(state, id, AttemptReason::SessionClosed, at);
    }
}

fn cancel_batch<D: Driver>(session: &Session<D>, id: u64) {
    session.command(|state| {
        let at = state.now();
        let reason = if state
            .control
            .as_ref()
            .and_then(|p| p.changes.batches.get(&id))
            .is_some_and(|batch| at >= batch.deadline())
        {
            AttemptReason::Deadline
        } else {
            AttemptReason::NoLongerNeeded
        };
        rollback_batch(state, id, reason, at);
    });
}

#[derive(Clone, Copy)]
struct OpenerStatus<'a> {
    cancelled: &'a watch::Receiver<bool>,
    batch_finished: &'a watch::Receiver<bool>,
    progress: &'a watch::Sender<AttemptSnapshot>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "one task owns each admitted attempt"
)]
async fn run_attempt<D: Driver>(
    weak: WeakSession<D>,
    submission: Submission,
    mut request: OpenRequest,
    opener: CarrierOpenerFor<D::Carrier>,
    admission: Option<super::cache::AttemptStart>,
    mut cancelled: watch::Receiver<bool>,
    mut batch_finished: watch::Receiver<bool>,
    deadline_at: watch::Receiver<Instant>,
    progress: watch::Sender<AttemptSnapshot>,
) {
    let mut pipes = Vec::new();
    let mut error = None;
    let mut open_error = None;
    let Some(shared) = weak.shared() else {
        return;
    };
    let clock = shared.lock().core.config().clock_domain.clone();
    let reason = 'attempt: {
        let mut expires = std::pin::pin!(wait_for_deadline::<D>(&clock, deadline_at.clone()));
        let host_deadline = deadline_at.clone();
        let layout = request.layout.clone();
        let owner = shared.clone();
        let stopped = cancelled.clone();
        let batch_ended = batch_finished.clone();
        let host_progress = progress.clone();
        let (handoff, host) = tokio::sync::oneshot::channel();
        D::spawn_join(&shared, async move {
            let run = async move {
                let admission = admission
                    .as_ref()
                    .map(|start| start as &dyn OpenerAdmission);
                let _host = admission.map(OpenerLifetime);
                let (opener, reservation) = owner.command(|state| {
                    request.deadline = *host_deadline.borrow();
                    submission.start_opener(
                        state,
                        &mut request,
                        opener,
                        OpenerStatus {
                            cancelled: &stopped,
                            batch_finished: &batch_ended,
                            progress: &host_progress,
                        },
                        admission,
                    )
                })?;
                let open = catch_callback(async move { opener.open(request).await })
                    .await
                    .map_err(|_| AttemptReason::HookFailed)?;
                Ok((open, reservation))
            };
            let _ = handoff.send(run.await);
        });
        let open = tokio::select! {
            biased;
            () = expires.as_mut() => break 'attempt AttemptReason::Deadline,
            () = session_ended_wait(&shared) => break 'attempt AttemptReason::SessionClosed,
            Ok(_) = cancelled.wait_for(|&stop| stop) => break 'attempt AttemptReason::Cancelled,
            _ = batch_finished.wait_for(|&stop| stop) => break 'attempt AttemptReason::NoLongerNeeded,
            open = host => open,
        };
        let (
            OpenedCarriersFor {
                carriers,
                error: failure,
            },
            mut reservation,
        ) = match open {
            Ok(Ok(handoff)) => handoff,
            Ok(Err(reason)) => break 'attempt reason,
            Err(_) => break 'attempt AttemptReason::HookFailed,
        };
        if let Some(failure) = failure {
            open_error = Some(Arc::new(failure));
            break 'attempt AttemptReason::DialFailed;
        }
        if carriers.len() != layout.len() {
            break 'attempt AttemptReason::HookFailed;
        }
        for (carrier, spec) in carriers.into_iter().zip(layout) {
            tokio::select! {
                biased;
                () = expires.as_mut() => break 'attempt AttemptReason::Deadline,
                () = session_ended_wait(&shared) => break 'attempt AttemptReason::SessionClosed,
                Ok(_) = cancelled.wait_for(|&stop| stop) => break 'attempt AttemptReason::Cancelled,
                _ = batch_finished.wait_for(|&stop| stop) => break 'attempt AttemptReason::NoLongerNeeded,
                () = D::resolve_join_exporter(&carrier) => {}
            }
            let Some(session) = weak.upgrade() else {
                break 'attempt AttemptReason::SessionClosed;
            };
            let options = spec.join_options();
            let deadline = *deadline_at.borrow();
            let join = session.start_join_inner(
                carrier,
                &options,
                Some(JoinDeadline::Caller(deadline)),
                Some((&submission, &mut reservation)),
            );
            match join {
                Ok(pipe) => {
                    let attachment = pipe.into_attempt_attachment();
                    progress.send_modify(|p| p.pipes.push(attachment.0));
                    pipes.push(attachment);
                }
                Err(failure) => {
                    let reason = join_failure(&failure);
                    error = Some(failure);
                    break 'attempt reason;
                }
            }
        }
        loop {
            let observed = shared.lock().capacity().observed;
            let (replied, confirmed, failed) = Pipe::attempt_progress(&shared, &pipes);
            progress.send_if_modified(|snapshot| {
                let mut changed = false;
                for (seen, fresh) in [
                    (&mut snapshot.replied, replied),
                    (&mut snapshot.confirmed, confirmed),
                ] {
                    for pipe in fresh {
                        if !seen.contains(&pipe) {
                            seen.push(pipe);
                            changed = true;
                        }
                    }
                }
                changed
            });
            if *cancelled.borrow() {
                break 'attempt AttemptReason::Cancelled;
            }
            if let Some(failure) = failed {
                let reason = join_failure(&failure);
                error = Some(failure);
                break 'attempt reason;
            }
            if progress.borrow().confirmed.len() == pipes.len() {
                break 'attempt AttemptReason::Confirmed;
            }
            tokio::select! {
                biased;
                () = expires.as_mut() => break 'attempt AttemptReason::Deadline,
                _ = super::handle::capacity_changed(&shared, observed) => {}
                () = session_ended_wait(&shared) => break 'attempt AttemptReason::SessionClosed,
                Ok(_) = cancelled.wait_for(|&stop| stop) => break 'attempt AttemptReason::Cancelled,
                _ = batch_finished.wait_for(|&stop| stop) => break 'attempt AttemptReason::NoLongerNeeded,
            }
        }
    };
    let pending = shared.command(|state| {
        submission.settle(
            state,
            reason,
            error.clone(),
            open_error.clone(),
            None,
            state.now(),
        )
    });
    if let Some(start) = pending {
        let sample = tokio::select! {
            biased;
            () = wait_for_deadline::<D>(&clock, deadline_at) => {
                shared.command(|state| {
                    submission.settle(state, AttemptReason::Deadline, None, None, None, state.now());
                });
                return;
            }
            _ = cancelled.wait_for(|&stop| stop) => return,
            _ = batch_finished.wait_for(|&stop| stop) => return,
            sample = D::join_callback(move || crate::Decision::Now(start.sample())) => {
                sample.and_then(|decision| match decision {
                    crate::Decision::Now(sample) => Some(sample),
                    crate::Decision::Later(_) => None,
                })
            }
        };
        shared.command(|state| {
            let (reason, error, open_error) = if sample.is_some() {
                (reason, error, open_error)
            } else {
                (AttemptReason::HookFailed, None, None)
            };
            // A failed sampler still schedules the next recovery: it draws
            // the full nominal wait.
            let sample = sample.or(Some(1.0));
            submission.settle(state, reason, error, open_error, sample, state.now());
        });
    }
}

pub(super) async fn catch_callback<F: Future>(future: F) -> std::thread::Result<F::Output> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Ok(std::task::Poll::Ready(value)) => std::task::Poll::Ready(Ok(value)),
            Err(error) => std::task::Poll::Ready(Err(error)),
        }
    })
    .await
}

fn join_failure(error: &PipeError) -> AttemptReason {
    match error {
        PipeError::SessionLost(_) => AttemptReason::SessionClosed,
        PipeError::Failed(PipeFailure::JoinTimedOut | PipeFailure::CallerDeadline) => {
            AttemptReason::Deadline
        }
        PipeError::Failed(PipeFailure::JoinRefused) => AttemptReason::JoinRefused,
        PipeError::Deferred => AttemptReason::NoLongerNeeded,
        PipeError::CallerCancelled(_) => AttemptReason::Cancelled,
        _ => AttemptReason::ConfirmationFailed,
    }
}

#[cfg(feature = "tokio")]
/// An asynchronous session capacity transaction.
pub type CapacityChange = CapacityChangeFor<super::tokio::Tokio>;
#[cfg(feature = "tokio")]
/// An opener of asynchronous carriers.
pub type CarrierOpener = CarrierOpenerFor<super::tokio::PipeIo>;
#[cfg(feature = "tokio")]
/// Asynchronous carriers returned by an opener.
pub type OpenedCarriers = OpenedCarriersFor<super::tokio::PipeIo>;

#[cfg(all(test, feature = "tokio"))]
#[tokio::test(start_paused = true)]
async fn a_stale_confirmation_cannot_settle_after_handoff() {
    use super::controller::owner_tests::session;

    tokio::time::timeout(Duration::from_secs(2), async {
        let (session, _peer, _listener) = session().await;
        let ctl = crate::SessionController::new(crate::ControllerOptions::new(
            "confirmation-fence",
            Vec::new(),
        ))
        .unwrap();
        let old = ctl
            .manage(&session, crate::SessionTarget::default())
            .unwrap();
        let generation = old.snapshot().generation;
        let local_carriers = session.capacity().local_carriers;
        let mut request = ChangeRequest::new(session.capacity(), Duration::from_secs(1));
        request.add.push(MemberSpec {
            candidate: None,
            attachments: vec![AttachmentSpec::new(
                Directions::BOTH,
                PipeOptions::default(),
            )],
        });
        let change = session
            .begin_target_change(request, Some((generation, 0)))
            .unwrap();
        let attempt = change
            .start_member(
                0,
                CarrierOpenerFor::new(|_| async {
                    Ok::<_, io::Error>(Vec::<crate::PipeIo>::new())
                }),
            )
            .unwrap();
        let successor = crate::SessionController::new(crate::ControllerOptions::new(
            "confirmation-next",
            Vec::new(),
        ))
        .unwrap();
        let _next = successor
            .take_over(&old, crate::SessionTarget::default())
            .unwrap();
        session.command(|state| {
            let submission = Submission {
                batch: change.id,
                index: 0,
            };
            assert!(
                submission
                    .settle(
                        state,
                        AttemptReason::Confirmed,
                        None,
                        None,
                        None,
                        state.now()
                    )
                    .is_none()
            );
        });
        let result = attempt.wait().await;
        assert_eq!(result.generation, Some(generation));
        assert_eq!(result.batch, change.id);
        assert_eq!(result.reason, AttemptReason::Cancelled);
        assert_eq!(session.capacity().local_carriers, local_carriers);
        assert_eq!(session.capacity().reserved_attachments, 0);
    })
    .await
    .unwrap();
}
