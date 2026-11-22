//! Keeping pipes up (non-normative): a helper above the
//! session that uses only its public API ([`Session::add_pipe`](Session#method.add_pipe),
//! [`Session::pipes`](Session#method.pipes), [`Pipe::stats`](Pipe#method.stats), [`Pipe::close`](Pipe#method.close)) and
//! the pool's `dial`; it changes nothing on the wire and keeps no state in
//! the session.
//!
//! One maintainer task per pool keeps `count` usable members, each a pipe
//! dialled by the pool or a group of pipes it joins itself (an uplink and
//! a downlink of a split carrier), redials failed ones with exponential
//! backoff and jitter, measured from the start of the previous attempt,
//! and rotates them make-before-break: when a usable member has carried
//! `max_bytes` in either direction, is `max_age` old (each reduced by a
//! random fraction of up to `jitter`), or has a pipe whose
//! `PipeStats::replace_by` passed (a carrier of an older session epoch), a
//! replacement is joined with the
//! same options, and the old member is closed gracefully once the
//! replacement is usable (every pipe ACTIVE and out of probation, or a
//! downlink OPEN, and attached by the peer, `Pipe::attached`). A member
//! one of whose pipes fails is closed and
//! redialled whole. A failed dial or a replacement that fails keeps the
//! old member and retries with backoff.
//! Nothing rotates while the session lacks a usable outbound or a live
//! inbound pipe or is suspended, and redials never wait for rotations.
//! A pool dialed by a carrier choice ([`PipePool::choice`]) picks each member's
//! carrier kind through the carrier cache and upgrades members to a
//! preferred kind by the same make-before-break replacement, the
//! replacement settling before the old member is closed; it is also the
//! only upgrade logic of a session dialed with an auto choice.
//!
//! It looks at the pipes' statistics at once when a pipe changes state or
//! the session is suspended or resumed, and at least every [`POLL`]; the
//! application keeps the session's pipe events. Dials run on the
//! maintainer task, outside every lock; they go on while the session is
//! suspended (each is a rejoin) and stop when it ends.
//!
//! An optional [`PoolPolicy`] is asked at each of these looks for a
//! [`PoolDecision`]: the number of members to keep (members above it
//! close gracefully), the wait before the next dial (in place of the
//! backoff's), members to replace now, the liveness settings of the pipes
//! dialled after it and how soon to look again. The maintainer applies it
//! within what it does anyway (dial, add, replace make before break,
//! close); without a policy nothing changes.

use crate::Backoff;
use crate::backoff::{random_fraction, reduce};
use crate::util::{f64_of, u64_sat};
use std::cmp::Reverse;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Poll, Waker};
use std::time::Duration;

use tokio::time::Instant;

use crate::driver::choice::ChoiceSource;
use crate::driver::handle::{self, WeakSession, dead, usable};
use crate::driver::resources::{Kind, Live};
use crate::driver::tokio::Tokio;
use crate::proto::session::{
    InboundState, Inherit, InvalidConfig, OutboundState, PipeError, PipeId, PipeLiveness,
    PipeOptions, PipeStats, State,
};
use crate::{
    CarrierChoice, CarrierChoicePolicy, ConnectError, Dial, DialRequest, Pipe, PipeIo, Session,
};
use atomic_waker::AtomicWaker;

use super::{POLL, policy_exec};

/// The shortest [`PoolDecision::recheck`] a pool honours: a shorter one
/// is lengthened to this, so that a policy cannot make it spin.
pub const MIN_RECHECK: Duration = Duration::from_millis(10);

/// Members to keep up over one path; see [`maintain_pipes`]. A member is
/// a pipe on a carrier that [`PipePool::new`]'s dial opens (its
/// [`DialRequest`] is `Bidi`), or the group of pipes that
/// [`PipePool::join`]'s function joins, such as the downlink and uplink of
/// a split carrier ([`PipeIo::paired_join`]).
///
/// ```no_run
/// # async fn example(session: zmux::Session) {
/// use std::time::Duration;
/// use zmux::PipeOptions;
/// use zmux::helpers::{PipePool, Rotation, maintain_pipes};
///
/// let pool = PipePool::new(2, |_req| async {
///     Ok(zmux::PipeIo::from_tcp(tokio::net::TcpStream::connect("10.0.0.2:4433").await?))
/// })
/// .with_options(PipeOptions::new().with_send_priority(10).with_receive_priority(10).with_label("relay"))
/// .with_rotate(Rotation::new().with_max_age(Duration::from_secs(600)));
/// let _keep = maintain_pipes(&session, pool).expect("valid pool");
/// # }
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct PipePool {
    /// How a member is made.
    source: Source,
    /// Usable members to keep.
    pub count: usize,
    /// The options of every pipe of the pool.
    pub options: PipeOptions,
    /// Rotation; none by default.
    pub rotate: Option<Rotation>,
    /// Redial backoff.
    pub backoff: Backoff,
    /// The policy consulted at each look; see [`PipePool::with_policy`].
    policy: Option<Policy>,
    /// Told of each rejected decision; see
    /// [`PipePool::with_decision_rejected`].
    decision_rejected: Option<RejectFn>,
}

/// A pool's policy: the public synchronous one, or the adapter-level
/// asynchronous one ([`AsyncPoolPolicy`]).
#[derive(Clone)]
enum Policy {
    Sync(SyncPolicy),
    Async(Arc<dyn AsyncPoolPolicy>),
}

/// A synchronous policy, and the gate that lets one look at it run at a
/// time: pools that share the policy (clones of a pool) wait for the gate
/// on their own task, so that a `decide` that does not return holds one
/// thread of the policy executor, however many pools wait for the policy.
#[derive(Clone)]
struct SyncPolicy {
    policy: Arc<Mutex<dyn PoolPolicy>>,
    gate: Arc<tokio::sync::Semaphore>,
}

impl SyncPolicy {
    fn new(policy: impl PoolPolicy + 'static) -> Self {
        Self {
            policy: Arc::new(Mutex::new(policy)),
            gate: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
}

type RejectFn = Arc<dyn Fn(&(dyn std::error::Error + 'static)) + Send + Sync>;

type JoinFuture = Pin<Box<dyn Future<Output = io::Result<Vec<Pipe>>> + Send>>;
type JoinFn = Arc<dyn Fn(Session, PipeOptions) -> JoinFuture + Send + Sync>;

/// How a pool makes a member.
#[derive(Clone)]
enum Source {
    /// A carrier the pool adds as one pipe.
    Dial(Dial),
    /// Pipes the function joins itself.
    Join(JoinFn),
    /// Pipes joined over a carrier kind a carrier choice chooses.
    Choice(Arc<ChoiceSource>),
}

impl PipePool {
    /// A pool of `count` pipes dialled by `dial`, with default options, no
    /// rotation and the default backoff.
    pub fn new<F, Fut>(count: usize, dial: F) -> Self
    where
        F: Fn(DialRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<PipeIo>> + Send + 'static,
    {
        Self::with_dial(count, Dial::new(dial))
    }

    /// A pool of `count` pipes dialled by `dial`.
    #[must_use]
    pub fn with_dial(count: usize, dial: Dial) -> Self {
        Self::of(count, Source::Dial(dial))
    }

    /// A pool of `count` members, each the pipes that `join` joins to the
    /// session with the options given (for example over [`PipeIo::paired_join`]
    /// or an adapter's split join): a member is usable while all of its
    /// pipes are, counts once against `count`, and is redialled, rotated
    /// (make before break) and retired as a whole. `join` returns the
    /// pipes once they are joined; an error, or no pipe, is a failed dial.
    pub fn join<F, Fut>(count: usize, join: F) -> Self
    where
        F: Fn(Session, PipeOptions) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<Vec<Pipe>>> + Send + 'static,
    {
        Self::of(
            count,
            Source::Join(Arc::new(move |s, o| Box::pin(join(s, o)))),
        )
    }

    /// A pool of one member dialed over the carrier kinds of `choice`, under `policy` (its
    /// [`no_join`](CarrierChoicePolicy::no_join) does not apply); set
    /// [`count`](Self::count) for more. Stable first, then upgrade: a
    /// member is dialed over the most robust kind available (a kind the
    /// policy's cache holds as usable, else the exchange carrier, else the
    /// last), skipping the kinds the cache holds as failed unless all are;
    /// a split candidate joins as a downlink and an uplink, one member. A
    /// member of a kind that a preferred kind not backing off could replace
    /// is rotated to it, make before break, one such upgrade at a time and
    /// only with room within `max_pipes`; the replacement takes over once
    /// it has stayed usable for [`CarrierChoicePolicy::settle`], and the old member
    /// is then closed gracefully. A kind whose join fails, whose
    /// replacement ends before it settled, or whose member (or session)
    /// fails within [`CarrierChoicePolicy::drop_window`] of being joined is recorded
    /// as failed; a joined or settled one as usable. Each try is reported as
    /// a [`SessionEvent::CarrierCandidate`](crate::SessionEvent::CarrierCandidate),
    /// and a member joined over a kind other than the session's carrier as
    /// a [`SessionEvent::CarrierChosen`](crate::SessionEvent::CarrierChosen).
    /// [`CarrierChoice::explicit`] dials its one kind, without the cache. Several
    /// pools may share a cache. A choice without candidates or with two of
    /// one kind, or a policy with a negative or non-finite timer factor, is
    /// [`ConnectError::InvalidConfig`].
    ///
    /// # Errors
    ///
    /// [`ConnectError::InvalidConfig`] for an invalid choice or policy, as
    /// above.
    pub fn choice(
        choice: &CarrierChoice,
        policy: &CarrierChoicePolicy,
    ) -> Result<Self, ConnectError> {
        let src = ChoiceSource::new(choice, policy).map_err(ConnectError::InvalidConfig)?;
        Ok(Self::of(1, Source::Choice(Arc::new(src))))
    }

    fn of(count: usize, source: Source) -> Self {
        Self {
            source,
            count,
            options: PipeOptions::default(),
            rotate: None,
            backoff: Backoff::default(),
            policy: None,
            decision_rejected: None,
        }
    }

    /// With the options of every pipe of the pool.
    #[must_use]
    pub fn with_options(mut self, options: PipeOptions) -> Self {
        self.options = options;
        self
    }

    /// With rotation.
    #[must_use]
    pub fn with_rotate(mut self, rotate: Rotation) -> Self {
        self.rotate = Some(rotate);
        self
    }

    /// With this redial backoff.
    #[must_use]
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// With a policy that the maintainer consults each time it looks at
    /// its members (see [`PoolPolicy`]). Clones of the pool share the
    /// policy and its state.
    #[must_use]
    pub fn with_policy(mut self, policy: impl PoolPolicy + 'static) -> Self {
        self.policy = Some(Policy::Sync(SyncPolicy::new(policy)));
        self
    }

    /// With an asynchronous policy, answered on the maintainer's task
    /// instead of a thread of the policy executor: for an adapter whose
    /// answer comes from an event loop (a language binding), which would
    /// otherwise occupy a thread to wait for it. Replaces any
    /// [`with_policy`](Self::with_policy). Not part of the stable API.
    #[doc(hidden)]
    #[must_use]
    pub fn with_async_policy(mut self, policy: Arc<dyn AsyncPoolPolicy>) -> Self {
        self.policy = Some(Policy::Async(policy));
        self
    }

    /// With a function handed the error of each rejected decision of the
    /// policy (one that panicked, see [`PoolPolicy`]); it runs on the
    /// maintainer task and must return promptly. Without one, the error is
    /// logged through the session's logger.
    #[must_use]
    pub fn with_decision_rejected(
        mut self,
        f: impl Fn(&(dyn std::error::Error + 'static)) + Send + Sync + 'static,
    ) -> Self {
        self.decision_rejected = Some(Arc::new(f));
        self
    }
}

impl fmt::Debug for PipePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipePool")
            .field(
                "source",
                &match self.source {
                    Source::Dial(_) => "dial",
                    Source::Join(_) => "join",
                    Source::Choice(_) => "choice",
                },
            )
            .field("count", &self.count)
            .field("options", &self.options)
            .field("rotate", &self.rotate)
            .field("backoff", &self.backoff)
            .field("policy", &self.policy.is_some())
            .field("decision_rejected", &self.decision_rejected.is_some())
            .finish_non_exhaustive()
    }
}

/// When the members of a pool are replaced (make before break).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[non_exhaustive]
pub struct Rotation {
    /// Bytes carried in either direction (a group's pipes summed).
    pub max_bytes: Option<u64>,
    /// Age of the member. For a carrier with a hard lifetime, set it
    /// below that by the expected probation and a few round trips.
    pub max_age: Option<Duration>,
    /// Each limit is reduced by a random fraction of up to this (0 to 1),
    /// so that members opened together do not rotate together.
    pub jitter: f64,
}

impl Rotation {
    /// No limit and no jitter: set the limits with the builders.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// With a limit on the bytes carried in either direction.
    #[must_use]
    pub fn with_max_bytes(mut self, bytes: u64) -> Self {
        self.max_bytes = Some(bytes);
        self
    }

    /// With a limit on the member's age.
    #[must_use]
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = Some(age);
        self
    }

    /// With this jitter (0 to 1).
    #[must_use]
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter;
        self
    }
}

/// Decides, at each look of the maintainer, how many members the pool
/// keeps, when it dials next and which members it replaces.
///
/// [`decide`](Self::decide) runs, on one of a few threads of the crate's own
/// that serve no other work (no runtime worker, not the runtime's blocking
/// pool) and while the pool holds no lock, each time the maintainer looks at its
/// members: at once when a pipe of the session changes state or the
/// session is suspended or resumed, after each dial attempt ends, no later
/// than the [`recheck`](PoolDecision::recheck) of the last decision, and
/// every 100 ms, the maintenance interval. A pool asks one look at a time:
/// what happens while it is being decided merges into the one look after it.
/// It may block (nothing bounds it with a timeout: one that does not return
/// holds the looks of its own pool, and a thread of the policy executor,
/// of which there are four for the whole process: when all four are held
/// the looks of other pools wait for one to come free; the runtime's own
/// threads and every other task are not affected) and must not call into
/// the session. `out` starts as
/// [`PoolDecision::default()`], in which every field keeps the pool's own
/// behaviour. A policy that returns an error (so that
/// `out.set_recheck(d)?` rejects an invalid value), or panics, has its
/// decision rejected as a whole: the pool applies the default decision for
/// that look, hands the error to [`PipePool::with_decision_rejected`]'s
/// function or, without one, logs it at warning level through the
/// session's logger, and goes on.
pub trait PoolPolicy: Send {
    /// Fills `out` from the state of the pool in `view`.
    ///
    /// # Errors
    ///
    /// Any error rejects the look: the default decision applies.
    fn decide(&mut self, view: &PoolView<'_>, out: &mut PoolDecision) -> Result<(), PolicyError>;
}

/// A pool policy answered asynchronously, for an adapter (a language
/// binding) whose answer comes from an event loop. The maintainer polls the
/// returned future on its own task, so a pending answer occupies no thread
/// and no slot of the policy executor; it holds no lock of the pool.
/// Not part of the stable API.
///
/// One look is asked at a time per pool (a future that does not complete
/// holds the looks of its own pool and nothing else); the policy is shared
/// by the pools that use it, so it keeps its own state behind its own
/// synchronisation. A panic when the future is created or polled rejects
/// the look, as for [`PoolPolicy`]; dropping the future (the pool stops)
/// cancels the look.
#[doc(hidden)]
pub trait AsyncPoolPolicy: Send + Sync {
    /// The decision for the pool in `view`; an error rejects the look.
    fn decide(&self, view: OwnedPoolView) -> PolicyFuture;
}

/// The future of [`AsyncPoolPolicy::decide`].
#[doc(hidden)]
pub type PolicyFuture = Pin<Box<dyn Future<Output = Result<PoolDecision, PolicyError>> + Send>>;

/// A [`PoolView`] that owns its members, for [`AsyncPoolPolicy`].
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct OwnedPoolView {
    /// [`PoolView::members`].
    pub members: Vec<PoolMember>,
    /// [`PoolView::failures`].
    pub failures: u32,
    /// [`PoolView::since_last_dial`].
    pub since_last_dial: Option<Duration>,
    /// [`PoolView::dialing`].
    pub dialing: usize,
}

impl OwnedPoolView {
    /// The borrowed view of it.
    #[must_use]
    pub fn view(&self) -> PoolView<'_> {
        PoolView {
            members: &self.members,
            failures: self.failures,
            since_last_dial: self.since_last_dial,
            dialing: self.dialing,
        }
    }
}

/// The error with which a [`PoolPolicy`] rejects a look.
pub type PolicyError = Box<dyn std::error::Error + Send + Sync>;

impl<F> PoolPolicy for F
where
    F: FnMut(&PoolView<'_>, &mut PoolDecision) -> Result<(), PolicyError> + Send,
{
    fn decide(&mut self, view: &PoolView<'_>, out: &mut PoolDecision) -> Result<(), PolicyError> {
        self(view, out)
    }
}

/// The state of a pool that a [`PoolPolicy`] sees. Durations, not points
/// in time: a policy reads no clock of its own, and is tested with plain
/// values. A policy's tests build one from [`PoolView::default()`] and set
/// its fields.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct PoolView<'a> {
    /// The pool's members; a replacement being joined is not one until it
    /// replaces its member.
    pub members: &'a [PoolMember],
    /// Consecutive failed dial attempts of the pool (redials and
    /// replacements alike), 0 once a dial gives a usable member.
    pub failures: u32,
    /// The time since the start of the pool's last dial attempt; `None`
    /// before the first.
    pub since_last_dial: Option<Duration>,
    /// The dial attempts in progress that would add a member (redials and
    /// first dials; replacements are not counted).
    pub dialing: usize,
}

/// A member of the pool in a [`PoolView`]: a dialled pipe, or the group of
/// pipes a join function joined. A policy's tests build one from
/// [`PoolMember::default()`] and set its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolMember {
    /// The ID of its first pipe, which identifies the member (pipe 0
    /// included).
    pub pipe: PipeId,
    /// The time since its oldest pipe was attached.
    pub age: Duration,
    /// The least time since a traffic frame on any of its pipes (since
    /// attachment for a pipe without traffic).
    pub idle: Duration,
    /// The number of its pipes: 1 for a dialled pipe, the group's size for
    /// a joined member.
    pub pipes: usize,
    /// Bytes sent over its pipes.
    pub bytes_sent: u64,
    /// Bytes received over its pipes.
    pub bytes_received: u64,
    /// Every pipe serves its direction (an outbound pipe ACTIVE and out of
    /// probation, a downlink OPEN) and the peer attached it
    /// (`Pipe::attached`).
    pub usable: bool,
    /// A replacement of it is being dialled or joined.
    pub replacing: bool,
}

impl Default for PoolMember {
    /// Pipe 0, zero durations and counts, not usable, not being replaced.
    fn default() -> Self {
        Self {
            pipe: PipeId(0),
            age: Duration::ZERO,
            idle: Duration::ZERO,
            pipes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            usable: false,
            replacing: false,
        }
    }
}

/// What a [`PoolPolicy`] decides, written with its setters; each field left
/// unset keeps the pool's own behaviour, so the default decision changes
/// nothing. No layer corrects a value into range: the setters refuse what
/// is out of range.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PoolDecision {
    count: Option<NonZeroUsize>,
    dial_after: Option<Duration>,
    retire_pipes: Vec<PipeId>,
    recheck: Option<Duration>,
    liveness: Option<PipeLiveness>,
}

impl PoolDecision {
    /// Keeps `count` members instead of [`PipePool::count`]. Above it,
    /// with members and [`dialing`](PoolView::dialing) counted together,
    /// the pool shrinks one step at a time: dials that would add a member
    /// are cancelled first, the most recently started first; then members
    /// close gracefully, those in [`retire_pipes`](Self::set_retire_pipes)
    /// first, then the longest idle, ties broken by the fewest pipes, then
    /// the least age, then the highest pipe ID. A closed member's
    /// replacement is cancelled or closed with it.
    pub fn set_count(&mut self, count: NonZeroUsize) {
        self.count = Some(count);
    }

    /// The count set, if any.
    #[must_use]
    pub fn count(&self) -> Option<NonZeroUsize> {
        self.count
    }

    /// Waits `after` from the start of the last dial attempt (the start of
    /// the pool before the first) to the next dial, redial or replacement,
    /// in place of the backoff's wait and its jitter; its effect is bounded
    /// by the backoff's [`max`](Backoff::max). Zero dials at once.
    pub fn set_dial_after(&mut self, after: Duration) {
        self.dial_after = Some(after);
    }

    /// The dial wait set, if any.
    #[must_use]
    pub fn dial_after(&self) -> Option<Duration> {
        self.dial_after
    }

    /// Replaces these members now, make before break, by the ID of their
    /// first pipe ([`PoolMember::pipe`]); a member that is not usable or
    /// already being replaced is skipped.
    pub fn set_retire_pipes(&mut self, pipes: impl IntoIterator<Item = PipeId>) {
        self.retire_pipes.clear();
        self.retire_pipes.extend(pipes);
    }

    /// The members to replace.
    #[must_use]
    pub fn retire_pipes(&self) -> &[PipeId] {
        &self.retire_pipes
    }

    /// Looks again no later than `recheck` after this decision, even when
    /// nothing happens; its effect is bounded below by [`MIN_RECHECK`] so
    /// that a policy cannot make the pool spin, and not bounded above.
    ///
    /// # Errors
    ///
    /// [`InvalidConfig`] for zero; nothing changes.
    pub fn set_recheck(&mut self, recheck: Duration) -> Result<(), InvalidConfig> {
        if recheck.is_zero() {
            return Err(InvalidConfig::new(
                "PoolDecision::recheck",
                "zero: leave it unset for no extra look",
            ));
        }
        self.recheck = Some(recheck);
        Ok(())
    }

    /// The recheck set, if any.
    #[must_use]
    pub fn recheck(&self) -> Option<Duration> {
        self.recheck
    }

    /// Sets the liveness settings of the pipes the pool dials after this
    /// decision: each field set here replaces the one of
    /// [`PipePool::options`]' [`liveness`](PipeOptions::liveness), and a
    /// field left to inherit keeps it (else the session's); pipes already
    /// added keep theirs.
    ///
    /// # Errors
    ///
    /// [`InvalidConfig`] for settings out of range, as for the pipe
    /// option; nothing changes.
    pub fn set_liveness(&mut self, liveness: PipeLiveness) -> Result<(), InvalidConfig> {
        liveness.validate()?;
        self.liveness = Some(liveness);
        Ok(())
    }

    /// The liveness settings set, if any.
    #[must_use]
    pub fn liveness(&self) -> Option<PipeLiveness> {
        self.liveness
    }
}

/// The error handed to [`PipePool::with_decision_rejected`]'s function
/// for a policy that panicked (one that returned an error hands that).
#[derive(Debug)]
struct PolicyPanicked(String);

impl fmt::Display for PolicyPanicked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the pool policy panicked: {}", self.0)
    }
}

impl std::error::Error for PolicyPanicked {}

/// The error handed to [`PipePool::with_decision_rejected`]'s function
/// for a look that no thread of the policy executor answered: the process
/// is ending.
#[derive(Debug)]
struct PolicyUnavailable;

impl fmt::Display for PolicyUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the pool policy was not asked: the policy executor ended")
    }
}

impl std::error::Error for PolicyUnavailable {}

impl PolicyPanicked {
    fn of(payload: &(dyn std::any::Any + Send)) -> Self {
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        Self(msg)
    }
}

/// Stops a maintainer when dropped or on [`MaintainHandle::stop`]; it also
/// ends when the session closes. The maintainer holds a handle of the
/// session until then.
#[derive(Debug)]
#[must_use = "dropping the handle stops the maintainer"]
pub struct MaintainHandle {
    stop: Arc<Stop>,
}

impl MaintainHandle {
    /// Stops the maintainer: dials in flight are cancelled; the pipes it
    /// added stay in the session.
    pub fn stop(&self) {
        self.stop.stop();
    }

    /// Whether the maintainer has ended.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.stop.finished.load(Ordering::SeqCst)
    }
}

impl Drop for MaintainHandle {
    fn drop(&mut self) {
        self.stop.stop();
    }
}

/// The stop signal of a maintainer (a leaf lock: no other lock is taken
/// under it, and the wake-up comes after it).
#[derive(Default)]
struct Stop {
    stopped: AtomicBool,
    finished: AtomicBool,
    waker: AtomicWaker,
}

impl fmt::Debug for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stop")
            .field("stopped", &self.stopped)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Stop {
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.waker.wake();
    }

    fn is_stopped(&self, waker: &Waker) -> bool {
        if self.stopped.load(Ordering::SeqCst) {
            return true;
        }
        self.waker.register(waker);
        // A stop between the check and the registration found no waker.
        self.stopped.load(Ordering::SeqCst)
    }
}

/// Keeps the pool's members of `session` up: `count` usable members
/// (one pool per path; several pools may run on one session), redialled
/// with exponential backoff when they fail and rotated by `pool.rotate`,
/// make before break. Dropping the handle or [`MaintainHandle::stop`] ends
/// it (a replacement still being rotated in is closed; the members' pipes
/// stay), as does the end of the session. Needs a multipath session and a
/// tokio runtime.
///
/// # Errors
///
/// [`ConnectError::InvalidConfig`] for a backoff whose initial delay is
/// zero or above its max, or whose jitter is outside \[0, 1); a
/// [`ConnectError::Io`] of kind `Unsupported` outside a tokio runtime.
pub fn maintain_pipes(session: &Session, pool: PipePool) -> Result<MaintainHandle, ConnectError> {
    pool.backoff
        .validate()
        .map_err(ConnectError::InvalidConfig)?;
    let stop = Arc::new(Stop::default());
    if !Maintainer::spawn(
        Link::Strong(session.clone()),
        pool,
        Vec::new(),
        stop.clone(),
    ) {
        return Err(ConnectError::Io(Arc::new(io::Error::new(
            io::ErrorKind::Unsupported,
            "maintain_pipes outside a tokio runtime",
        ))));
    }
    Ok(MaintainHandle { stop })
}

/// The redial of a session with [`Config::redial`](crate::Config#structfield.redial):
/// one member, first `pipe0`, replaced by the hook's carrier when it fails,
/// with the configuration's backoff. It holds no handle of the session
/// between its looks and ends with it.
pub(crate) fn maintain_redial(session: &Session, dial: Dial, backoff: Backoff, pipe0: Pipe) {
    let mut first = Member::new(vec![pipe0], None);
    first.was_usable = true;
    let pool = PipePool::with_dial(1, dial).with_backoff(backoff);
    // Called on the runtime the session runs on.
    let _ = Maintainer::spawn(
        Link::Weak(session.downgrade()),
        pool,
        vec![first],
        Arc::default(),
    );
}

/// The pool of a session dialed by [`crate::dial_choice`]: one member over
/// `src`, first `pipe0`, of kind `kind`, chosen at `chosen`. It holds no
/// handle of the session between its looks and ends with it.
pub(crate) fn maintain_choice(
    session: &Session,
    src: Arc<ChoiceSource>,
    kind: usize,
    pipe0: Pipe,
    chosen: std::time::Instant,
) {
    let mut first = Member::new(vec![pipe0], Some(kind));
    first.joined = chosen;
    first.was_usable = true;
    let pool = PipePool::of(1, Source::Choice(src));
    // Called on the runtime the session runs on.
    let _ = Maintainer::spawn(
        Link::Weak(session.downgrade()),
        pool,
        vec![first],
        Arc::default(),
    );
}

/// How the maintainer reaches its session.
enum Link {
    /// A handle, held until the maintainer ends.
    Strong(Session),
    /// A reference upgraded at each look only.
    Weak(WeakSession<Tokio>),
}

impl Link {
    fn get(&self) -> Option<Session> {
        match self {
            Self::Strong(s) => Some(s.clone()),
            Self::Weak(w) => w.upgrade(),
        }
    }
}

/// Why a dial was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Redial,
    /// The replacement of this member.
    Rotate(PipeId),
}

/// A member of the pool: one pipe, or a group joined together.
struct Member {
    pipes: Vec<Pipe>,
    /// Rotation limits (jittered).
    max_bytes: Option<u64>,
    max_age: Option<Instant>,
    /// It replaces this member once usable.
    replaces: Option<PipeId>,
    /// A replacement is being joined for it.
    replaced: bool,
    /// It was usable once.
    was_usable: bool,
    /// With a carrier choice: the candidate it was joined over, and when (for the
    /// cache's drop window).
    kind: Option<usize>,
    joined: std::time::Instant,
    /// A replacement that upgrades to a preferred kind.
    upgrade: bool,
    /// Since when a replacement has been usable without a break.
    usable_since: Option<Instant>,
}

impl Member {
    fn new(pipes: Vec<Pipe>, kind: Option<usize>) -> Self {
        Self {
            pipes,
            max_bytes: None,
            max_age: None,
            replaces: None,
            replaced: false,
            was_usable: false,
            kind,
            joined: std::time::Instant::now(),
            upgrade: false,
            usable_since: None,
        }
    }

    fn id(&self) -> PipeId {
        self.pipes[0].id()
    }

    fn close(&self) {
        for p in &self.pipes {
            let _ = p.close();
        }
    }
}

/// What a dial under way yields.
enum Made {
    Carrier(io::Result<Box<PipeIo>>),
    Joined(io::Result<Vec<Pipe>>),
}

type MadeFuture = Pin<Box<dyn Future<Output = Made> + Send>>;

/// A dial under way and why.
struct Dialing {
    purpose: Purpose,
    /// With a carrier choice: the candidate dialed, and whether it is an upgrade.
    kind: Option<usize>,
    upgrade: bool,
    future: MadeFuture,
}

struct Maintainer {
    link: Link,
    pool: PipePool,
    stop: Arc<Stop>,
    members: Vec<Member>,
    dials: Vec<Dialing>,
    redial_failures: u32,
    /// The backoff of the next redial, from the last dial's start: drawn
    /// (with its jitter) once, when a dial starts or its outcome is known,
    /// not at every look.
    redial_wait: Duration,
    rotate_failures: u32,
    /// The backoff of the next replacement, from the last dial's start.
    rotate_delay: Duration,
    /// Consecutive failed dial attempts, redials and replacements alike
    /// ([`PoolView::failures`]).
    failures: u32,
    /// Usable members to keep: the policy's, else the pool's.
    count: usize,
    /// The policy's wait before the next dial; `None`: the backoff's.
    dial_after: Option<Duration>,
    /// The policy's idle-probe interval and jitter for pipes added now.
    liveness: Option<PipeLiveness>,
    /// When the last dial started.
    last_dial_at: Option<Instant>,
    /// When the maintainer started: waits count from it before the first
    /// dial.
    started: Instant,
    /// When the policy asked to be consulted again; `None`: no need.
    recheck_at: Option<Instant>,
    /// The session's pipe changes as of the last look.
    seen: u64,
    /// The pool counted as a redial source while it runs (`ResumeUnattended`),
    /// from its spawn.
    source: Option<handle::RedialSource<Tokio>>,
}

/// What woke the maintainer.
enum Wake {
    Stop,
    Dial(Box<Dialing>, Box<Made>),
    Tick,
}

impl Maintainer {
    /// Starts the maintainer on the current runtime; `false` outside one.
    fn spawn(link: Link, pool: PipePool, members: Vec<Member>, stop: Arc<Stop>) -> bool {
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        let now = Instant::now();
        let task = Self {
            link,
            pool,
            stop,
            members,
            dials: Vec::new(),
            redial_failures: 0,
            redial_wait: Duration::ZERO,
            rotate_failures: 0,
            rotate_delay: Duration::ZERO,
            failures: 0,
            count: 0,
            dial_after: None,
            liveness: None,
            last_dial_at: None,
            started: now,
            recheck_at: None,
            seen: 0,
            source: None,
        };
        let mut task = task;
        task.source = task
            .link
            .get()
            .map(|s| handle::RedialSource::new(s.shared()));
        rt.spawn(task.run());
        true
    }

    /// The pool's carrier choice, if it dials by one.
    fn choice(&self) -> Option<&Arc<ChoiceSource>> {
        match &self.pool.source {
            Source::Choice(m) => Some(m),
            _ => None,
        }
    }

    async fn run(mut self) {
        let _live = Live::new(Kind::Maintainer);
        let source = self.source.take();
        let mut shared = None;
        loop {
            // A weak link holds the session only during a look.
            let Some(session) = self.link.get() else {
                break;
            };
            if session.close_reason().is_some() {
                break;
            }
            let now = Instant::now();
            // Changes from here on wake the next wait.
            self.seen = session.pipe_changes();
            self.observe(&session, now);
            let infos = self.infos();
            if !self.consult(&session, &infos, now).await {
                shared = Some(session.shared().clone());
                break;
            }
            self.rotate(&session, &infos, now);
            self.start_dials(&session, now);
            let next = self.next_check(now);
            let sh = session.shared().clone();
            drop(session);
            let wake = {
                let sleep = tokio::time::sleep_until(next);
                let mut sleep = pin!(sleep);
                let mut closed = pin!(handle::closed_wait(&sh));
                let mut changed = pin!(handle::pipes_changed_wait(&sh, self.seen));
                poll_fn(|cx| {
                    if self.stop.is_stopped(cx.waker()) || closed.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Wake::Stop);
                    }
                    if changed.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Wake::Tick);
                    }
                    for i in 0..self.dials.len() {
                        if let Poll::Ready(r) = self.dials[i].future.as_mut().poll(cx) {
                            return Poll::Ready(Wake::Dial(
                                Box::new(self.dials.remove(i)),
                                Box::new(r),
                            ));
                        }
                    }
                    sleep.as_mut().poll(cx).map(|()| Wake::Tick)
                })
                .await
            };
            match wake {
                Wake::Stop => {
                    shared = Some(sh);
                    break;
                }
                Wake::Dial(dialing, r) => {
                    self.dialled(&Session::after_dial(sh), &dialing, *r);
                }
                Wake::Tick => {}
            }
        }
        // Dials in flight are cancelled here; a carrier one already
        // returned was handed to the session or dropped (closed).
        self.dials.clear();
        // A replacement still being rotated in is the pool's own: it goes
        // when the pool stops; the members' pipes stay.
        for m in self.members.iter().filter(|m| m.replaces.is_some()) {
            m.close();
        }
        // With a carrier choice, a session that failed counts against the kinds of
        // the members joined less than the drop window ago.
        if let (Some(src), Some(sh)) = (self.choice(), shared)
            && crate::driver::choice::session_failed(&sh)
        {
            for m in &self.members {
                if let Some(k) = m.kind {
                    src.dropped(k, m.joined);
                }
            }
        }
        drop(source);
        self.stop.finished.store(true, Ordering::SeqCst);
    }

    /// Each member's pipe statistics (`None` for a pipe gone).
    fn infos(&self) -> Vec<Vec<Option<PipeStats>>> {
        self.members
            .iter()
            .map(|m| m.pipes.iter().map(Pipe::pipe_signals).collect())
            .collect()
    }

    /// When to look again.
    fn next_check(&self, now: Instant) -> Instant {
        let mut next = now + POLL;
        if let Some(t) = self.recheck_at {
            next = next.min(t);
        }
        if self.wants_redial()
            && let Some(t) = self.dial_time(self.redial_delay()).filter(|&t| t > now)
        {
            next = next.min(t);
        }
        next
    }

    /// Asks the policy, if any, and applies its decision; `false` when the
    /// pool stopped or the session closed while it was being decided.
    async fn consult(
        &mut self,
        session: &Session,
        infos: &[Vec<Option<PipeStats>>],
        now: Instant,
    ) -> bool {
        self.count = self.pool.count;
        self.dial_after = None;
        self.liveness = None;
        self.recheck_at = None;
        let Some(policy) = self.pool.policy.clone() else {
            return true;
        };
        let members: Vec<PoolMember> = self
            .members
            .iter()
            .zip(infos)
            // A replacement is not a member until it replaces its member.
            .filter(|(m, _)| m.replaces.is_none())
            .filter_map(|(m, i)| {
                let pipes: Option<Vec<&PipeStats>> = i.iter().map(Option::as_ref).collect();
                let pipes = pipes?;
                let age = pipes
                    .iter()
                    .map(|p| p.attached_for)
                    .max()
                    .unwrap_or_default();
                let idle = pipes
                    .iter()
                    .map(|p| p.since_last_traffic.unwrap_or(p.attached_for))
                    .min()
                    .unwrap_or_default();
                Some(PoolMember {
                    pipe: m.id(),
                    age,
                    idle,
                    pipes: pipes.len(),
                    bytes_sent: pipes.iter().map(|p| p.bytes_sent).sum(),
                    bytes_received: pipes.iter().map(|p| p.bytes_received).sum(),
                    usable: m.pipes.iter().zip(&pipes).all(|(p, i)| usable(p, i)),
                    replacing: m.replaced,
                })
            })
            .collect();
        let (failures, since_last_dial, dialing) = (
            self.failures,
            self.last_dial_at.map(|t| now.saturating_duration_since(t)),
            self.adding_dials().count(),
        );
        // `decide` may block: a synchronous policy runs on a thread of the
        // policy executor (no runtime worker, not the blocking pool),
        // holding no lock of the pool (the policy's own mutex only
        // serializes the pools that share it); an asynchronous one is
        // polled here. The wait ends with the pool. A policy that panics is
        // a rejected decision: the maintainer goes on with the default
        // one, and ends (and cleans up) as it would otherwise.
        let owned = OwnedPoolView {
            members: members.clone(),
            failures,
            since_last_dial,
            dialing,
        };
        let sh = session.shared().clone();
        let asked = {
            let mut ask = pin!(ask_policy(policy, owned));
            let mut closed = pin!(handle::closed_wait(&sh));
            poll_fn(|cx| {
                if self.stop.is_stopped(cx.waker()) || closed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                ask.as_mut().poll(cx).map(Some)
            })
            .await
        };
        let Some((decided, d)) = asked else {
            return false;
        };
        if let Err(e) = decided {
            let e: &(dyn std::error::Error + 'static) = &*e;
            if let Some(f) = &self.pool.decision_rejected {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(e)));
            } else {
                session.log_warn(format!("zmux: pool decision rejected: {e}"));
            }
            return true;
        }
        if let Some(c) = d.count {
            self.count = c.get();
        }
        self.dial_after = d.dial_after;
        self.liveness = d.liveness;
        self.recheck_at = d.recheck.and_then(|r| now.checked_add(r.max(MIN_RECHECK)));
        for &id in &d.retire_pipes {
            if let Some((m, _)) = self.members.iter_mut().zip(infos).find(|(m, i)| {
                m.id() == id
                    && m.replaces.is_none()
                    && !m.replaced
                    && m.pipes
                        .iter()
                        .zip(i.iter())
                        .all(|(p, i)| i.as_ref().is_some_and(|i| usable(p, i)))
            }) {
                // Due now: replaced as by a limit, make before break.
                m.max_age = Some(now);
            }
        }
        self.shrink(&members, &d.retire_pipes);
        true
    }

    /// Closes what is above the count (the policy's shrinking order): dials that
    /// would add a member first, the most recently started first; then
    /// members, those the policy retires first, then the longest idle,
    /// ties broken by the fewest pipes, the least age and the highest pipe
    /// ID. A closed member's replacement goes with it.
    fn shrink(&mut self, view: &[PoolMember], retire: &[PipeId]) {
        while self.slots() > self.count {
            let step = shrink_step(
                self.adding_dials().count(),
                view,
                self.members
                    .iter()
                    .filter(|m| self.fills_slot(m))
                    .map(Member::id),
                retire,
            );
            let victim = match step {
                Some(Shrink::CancelDial) => {
                    if let Some(i) = self.adding_dials().last() {
                        // Dropping the future cancels the dial; `remove` keeps
                        // the others in the order they started.
                        drop(self.dials.remove(i));
                    }
                    continue;
                }
                Some(Shrink::Close(victim)) => victim,
                None => return,
            };
            let Some(i) = self.members.iter().position(|m| m.id() == victim) else {
                return;
            };
            self.members.swap_remove(i).close();
            self.dials.retain(|d| d.purpose != Purpose::Rotate(victim));
            while let Some(j) = self.members.iter().position(|m| m.replaces == Some(victim)) {
                self.members.swap_remove(j).close();
            }
        }
    }

    /// The start of the last dial, or of the maintainer before the first:
    /// every wait counts from it.
    fn since(&self) -> Instant {
        self.last_dial_at.unwrap_or(self.started)
    }

    /// The backoff of the next redial, as drawn.
    fn redial_delay(&self) -> Duration {
        self.redial_wait
    }

    /// The backoff after the last dial, whether it succeeded or failed:
    /// the initial delay after a success or a first failure, doubling with
    /// each further one; drawn once.
    fn backoff_wait(&self, failures: u32) -> Duration {
        self.pool.backoff.delay(failures.max(1))
    }

    /// Sets the consecutive redial failures; a change redraws the wait.
    fn set_redial_failures(&mut self, failures: u32) {
        if failures != self.redial_failures {
            self.redial_failures = failures;
            self.redial_wait = self.backoff_wait(failures);
        }
    }

    /// When a dial waiting `delay` from the last dial's start may start:
    /// the policy's wait in place of the backoff's, at most the backoff's
    /// max; `None`: never.
    fn dial_time(&self, delay: Duration) -> Option<Instant> {
        let delay = self
            .dial_after
            .map_or(delay, |d| d.min(self.pool.backoff.max));
        self.since().checked_add(delay)
    }

    fn may_dial(&self, delay: Duration, now: Instant) -> bool {
        self.dial_time(delay).is_some_and(|t| now >= t)
    }

    /// The members and dials that fill the pool's count: a replacement, or
    /// a rotation dial, whose old member is gone takes its place (it joins
    /// as an ordinary member), so that the failure of the old one does not
    /// also start a redial that would leave one member too many.
    fn slots(&self) -> usize {
        self.members.iter().filter(|m| self.fills_slot(m)).count() + self.adding_dials().count()
    }

    /// Whether a member fills a slot of the count: all but a replacement
    /// whose old member is still there (the old one holds the slot).
    fn fills_slot(&self, m: &Member) -> bool {
        m.replaces
            .is_none_or(|old| !self.members.iter().any(|o| o.id() == old))
    }

    /// The indices, in start order, of the dials that would add a member:
    /// redials, and a rotation dial whose old member is gone (it takes its
    /// place, [`slots`](Self::slots)).
    fn adding_dials(&self) -> impl DoubleEndedIterator<Item = usize> + '_ {
        let present = |old: PipeId| self.members.iter().any(|o| o.id() == old);
        self.dials
            .iter()
            .enumerate()
            .filter(move |(_, d)| match d.purpose {
                Purpose::Redial => true,
                Purpose::Rotate(old) => !present(old),
            })
            .map(|(i, _)| i)
    }

    fn wants_redial(&self) -> bool {
        self.slots() < self.count
    }

    /// Looks at the pool's members: failures, usable replacements (with a
    /// choice, once they stayed usable for the settle time).
    fn observe(&mut self, session: &Session, now: Instant) {
        let infos = self.infos();
        let settle = self.choice().map(|m| m.settle());
        let mut gone = Vec::new();
        let mut close = Vec::new();
        let mut settled = Vec::new();
        let (mut usable_now, mut rotated) = (false, false);
        for (m, info) in self.members.iter_mut().zip(&infos) {
            if info.iter().any(|i| dead(i.as_ref())) {
                gone.push(m.id());
                continue;
            }
            if !m
                .pipes
                .iter()
                .zip(info)
                .all(|(p, i)| i.as_ref().is_some_and(|i| usable(p, i)))
            {
                m.usable_since = None;
                continue;
            }
            if !m.was_usable {
                // A dial gave a usable member.
                self.failures = 0;
            }
            m.was_usable = true;
            usable_now = true;
            let since = *m.usable_since.get_or_insert(now);
            if m.replaces.is_some() && settle.is_none_or(|s| now.duration_since(since) >= s) {
                // Make before break: the replacement is usable (and
                // settled).
                close.extend(m.replaces.take());
                settled.extend(m.kind);
                rotated = true;
            }
        }
        if usable_now {
            self.set_redial_failures(0);
        }
        if rotated {
            self.rotate_failures = 0;
            self.rotate_delay = self.backoff_wait(0);
        }
        let mode = self.choice().cloned();
        let ending = session.close_reason().is_some();
        for id in gone {
            let Some(i) = self.members.iter().position(|m| m.id() == id) else {
                continue;
            };
            let m = self.members.swap_remove(i);
            // The rest of a member goes with its failed pipe.
            m.close();
            if let Some(old) = m.replaces {
                // The replacement failed: the old member stays, and the
                // kind counts as failed.
                if let Some(o) = self.members.iter_mut().find(|o| o.id() == old) {
                    o.replaced = false;
                }
                if let (Some(src), Some(k)) = (&mode, m.kind) {
                    src.record(k, false);
                }
                self.failures = self.failures.saturating_add(1);
                self.rotate_failed();
                continue;
            }
            if let (Some(src), Some(k), false) = (&mode, m.kind, ending) {
                src.dropped(k, m.joined);
            }
            if let Some(r) = self.members.iter_mut().find(|r| r.replaces == Some(id)) {
                // The old member went first: its replacement takes the
                // slot.
                r.replaces = None;
                settled.extend(r.kind);
            } else if !m.was_usable {
                self.failures = self.failures.saturating_add(1);
                self.set_redial_failures(self.redial_failures.saturating_add(1));
            }
        }
        for id in close {
            if let Some(i) = self.members.iter().position(|m| m.id() == id) {
                self.members.swap_remove(i).close();
            }
        }
        if let Some(src) = &mode {
            for k in settled {
                src.established(session, k);
            }
        }
    }

    /// Dials replacements of the usable members that reached a limit and,
    /// with a carrier choice, one of a member a preferred kind could replace.
    fn rotate(&mut self, session: &Session, infos: &[Vec<Option<PipeStats>>], now: Instant) {
        let mode = self.choice().cloned();
        let mut upgrading = self.dials.iter().any(|d| d.upgrade)
            || self
                .members
                .iter()
                .any(|m| m.upgrade && m.replaces.is_some());
        let mut due: Vec<(PipeId, Option<usize>, bool)> = Vec::new();
        for (m, i) in self.members.iter().zip(infos) {
            let Some(i): Option<Vec<&PipeStats>> = i.iter().map(Option::as_ref).collect() else {
                continue;
            };
            if m.replaced
                || m.replaces.is_some()
                || !m.pipes.iter().zip(&i).all(|(p, i)| usable(p, i))
            {
                continue;
            }
            let sent: u64 = i.iter().map(|p| p.bytes_sent).sum();
            let received: u64 = i.iter().map(|p| p.bytes_received).sum();
            // A carrier of an older session epoch is replaced as its epoch policy says.
            let stale = i
                .iter()
                .any(|p| p.replace_by.is_some_and(|t| now.into_std() >= t));
            let limit = stale
                || m.max_age.is_some_and(|t| now >= t)
                || m.max_bytes.is_some_and(|b| sent >= b || received >= b);
            let better = match (&mode, m.kind) {
                (Some(src), Some(k)) if !upgrading => src.better(k),
                _ => None,
            };
            if let Some(b) = better {
                upgrading = true;
                due.push((m.id(), Some(b), true));
            } else if limit {
                due.push((m.id(), mode.as_ref().map(|src| src.pick()), false));
            }
        }
        if due.is_empty()
            || !Self::session_whole(session)
            || !session.adapter().join_ready()
            || !self.may_dial(self.rotate_delay, now)
        {
            return;
        }
        for (id, kind, upgrade) in due {
            // An upgrade needs room within max_pipes for the replacement.
            if upgrade && !session.join_wanted() {
                continue;
            }
            let Some(m) = self.members.iter_mut().find(|m| m.id() == id) else {
                continue;
            };
            m.replaced = true;
            self.dial(session, Purpose::Rotate(id), kind, upgrade);
        }
    }

    /// Whether the session has a usable outbound and a live inbound pipe
    /// and is not suspended: only then may members rotate.
    fn session_whole(session: &Session) -> bool {
        if session.state() == State::Suspended {
            return false;
        }
        let pipes = session.pipe_signals();
        pipes
            .iter()
            .any(|p| p.outbound == Some(OutboundState::Active) && !p.in_probation)
            && pipes.iter().any(|p| p.inbound == Some(InboundState::Open))
    }

    fn start_dials(&mut self, session: &Session, now: Instant) {
        if !session.is_multipath() {
            // Nothing to maintain.
            self.stop.stop();
            return;
        }
        let room = session.adapter().join_room();
        if !self.wants_redial() || room == 0 || !self.may_dial(self.redial_delay(), now) {
            // A carrier dialled now would wait idle for its join: look again
            // at the next poll.
            return;
        }
        // No more at once than the session can take: a count above
        // `max_pipes` does not open carriers that would only be refused.
        let want = self.count.saturating_sub(self.slots()).min(room);
        for _ in 0..want {
            let kind = self.choice().map(|m| m.pick());
            self.dial(session, Purpose::Redial, kind, false);
        }
    }

    /// Starts a dial or join.
    fn dial(&mut self, session: &Session, purpose: Purpose, kind: Option<usize>, upgrade: bool) {
        self.last_dial_at = Some(Instant::now());
        // A wait counts from this start, whatever comes of it.
        self.redial_wait = self.backoff_wait(self.redial_failures);
        let future: MadeFuture = match &self.pool.source {
            Source::Dial(d) => {
                let f = d.boxed(DialRequest::bidi());
                Box::pin(async move { Made::Carrier(f.await.map(Box::new)) })
            }
            Source::Join(j) => {
                let f = j(session.clone(), self.options());
                Box::pin(async move { Made::Joined(f.await) })
            }
            Source::Choice(m) => {
                let f = m.join(session.clone(), kind.unwrap_or(0), self.options());
                Box::pin(async move { Made::Joined(f.await) })
            }
        };
        self.dials.push(Dialing {
            purpose,
            kind,
            upgrade,
            future,
        });
    }

    /// The options of a pipe added now: the pool's, with the policy's
    /// idle-probe settings, and `return_on_reply` set: a replacement
    /// closes its old pipe only once the peer attached it (the member's own
    /// judgement), and a redial must not wait for a `PIPE_ACK` that only the
    /// direction it restores could carry.
    fn options(&self) -> PipeOptions {
        let mut o = self.pool.options.clone();
        o.return_on_reply = true;
        if let Some(l) = self.liveness {
            fn own<T>(d: Inherit<T>, p: Inherit<T>) -> Inherit<T> {
                match d {
                    Inherit::Session => p,
                    d @ Inherit::Set(_) => d,
                }
            }
            let p = match o.liveness {
                crate::Change::Set(p) => p,
                crate::Change::Keep | crate::Change::Clear => PipeLiveness::default(),
            };
            o.liveness = crate::Change::Set(PipeLiveness {
                suspect_floor: own(l.suspect_floor, p.suspect_floor),
                dead_timeout: own(l.dead_timeout, p.dead_timeout),
                probe_interval: own(l.probe_interval, p.probe_interval),
                probe_jitter: own(l.probe_jitter, p.probe_jitter),
            });
        }
        o
    }

    /// A dial or join failed: backoff from its start, and nothing more to
    /// do on a session that cannot take pipes.
    fn dial_failed(&mut self, purpose: Purpose, e: Option<&PipeError>) {
        self.failures = self.failures.saturating_add(1);
        if matches!(
            e,
            Some(PipeError::NotNegotiated | PipeError::SessionLost(_))
        ) {
            // Nothing to maintain.
            self.stop.stop();
        }
        match purpose {
            Purpose::Redial => {
                self.set_redial_failures(self.redial_failures.saturating_add(1));
            }
            Purpose::Rotate(old) => {
                if let Some(o) = self.members.iter_mut().find(|o| o.id() == old) {
                    o.replaced = false;
                }
                self.rotate_failed();
            }
        }
    }

    fn rotate_failed(&mut self) {
        self.rotate_failures = self.rotate_failures.saturating_add(1);
        self.rotate_delay = self.backoff_wait(self.rotate_failures);
    }

    /// A dial finished: the carrier joins the session, or the joined pipes
    /// are a member.
    fn dialled(&mut self, session: &Session, dialing: &Dialing, made: Made) {
        let now = Instant::now();
        let purpose = dialing.purpose;
        let pipes = match made {
            Made::Carrier(Ok(io)) => {
                // The member waits for the Reply and the attachment itself.
                session.begin_add_pipe(*io, self.options()).map(|p| vec![p])
            }
            Made::Joined(Ok(pipes)) if !pipes.is_empty() => Ok(pipes),
            Made::Joined(Ok(_)) => Err(PipeError::InvalidArgument),
            Made::Carrier(Err(e)) | Made::Joined(Err(e)) => Err(PipeError::Io(Arc::new(e))),
        };
        let pipes = match pipes {
            Ok(p) => p,
            Err(e) => {
                self.dial_failed(purpose, Some(&e));
                return;
            }
        };
        let replaces = match purpose {
            Purpose::Redial => None,
            Purpose::Rotate(old) => self.members.iter().any(|o| o.id() == old).then_some(old),
        };
        let mut m = Member::new(pipes, dialing.kind);
        m.replaces = replaces;
        m.upgrade = dialing.upgrade;
        set_limits(&mut m, self.pool.rotate.as_ref(), now);
        if replaces.is_none()
            && let (Some(src), Some(k)) = (self.choice(), m.kind)
        {
            src.established(session, k);
        }
        self.members.push(m);
    }
}

/// One look at the policy: the answer, or the reason the look is rejected,
/// with what the policy filled in (the default decision for a rejection).
async fn ask_policy(
    policy: Policy,
    view: OwnedPoolView,
) -> (Result<(), PolicyError>, PoolDecision) {
    let rejected = |e: PolicyError| (Err(e), PoolDecision::default());
    match policy {
        Policy::Sync(SyncPolicy { policy, gate }) => {
            // One look at a policy at a time, in the order they were
            // asked, before any thread is taken. The permit goes with the
            // job: it is released when the policy returned (or the job was
            // dropped unrun), not when this look is given up.
            let Ok(permit) = gate.acquire_owned().await else {
                return rejected(Box::new(PolicyUnavailable));
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            let job = move || {
                let _permit = permit;
                // The pool stopped while the look waited for a thread.
                if tx.is_closed() {
                    return;
                }
                let mut d = PoolDecision::default();
                let decided = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    policy
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .decide(&view.view(), &mut d)
                }))
                .unwrap_or_else(|payload| {
                    Err(Box::new(PolicyPanicked::of(&*payload)) as PolicyError)
                });
                let _ = tx.send((decided, d));
            };
            if let Err(e) = policy_exec::shared().submit(job) {
                return rejected(Box::new(e));
            }
            // No answer: the look's job was dropped, the process is ending.
            rx.await
                .unwrap_or_else(|_| rejected(Box::new(PolicyUnavailable)))
        }
        Policy::Async(policy) => {
            let made =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| policy.decide(view)));
            let mut fut = match made {
                Ok(f) => f,
                Err(p) => return rejected(Box::new(PolicyPanicked::of(&*p))),
            };
            let answer = poll_fn(|cx| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    fut.as_mut().poll(cx)
                })) {
                    Ok(p) => p.map(Ok),
                    Err(p) => Poll::Ready(Err(p)),
                }
            })
            .await;
            match answer {
                Ok(Ok(d)) => (Ok(()), d),
                Ok(Err(e)) => rejected(e),
                Err(p) => rejected(Box::new(PolicyPanicked::of(&*p))),
            }
        }
    }
}

/// The member's rotation limits, each reduced by its own random fraction.
fn set_limits(m: &mut Member, rotate: Option<&Rotation>, now: Instant) {
    let Some(r) = rotate else { return };
    let keep = |jitter: f64| 1.0 - jitter.clamp(0.0, 1.0) * random_fraction();
    m.max_bytes = r.max_bytes.map(|b| u64_sat(f64_of(b) * keep(r.jitter)));
    // An age beyond the clock's range never comes.
    m.max_age = r.max_age.and_then(|a| now.checked_add(reduce(a, r.jitter)));
}

/// One step of shrinking a pool above its count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shrink {
    /// Cancel the most recently started dial that would add a member.
    CancelDial,
    /// Close this member (and its replacement).
    Close(PipeId),
}

/// The next step of shrinking (the pool's shrink order): a dial
/// that would add a member first; else the member the policy retires, then
/// the longest idle, ties broken by the fewest pipes, the least age and the
/// highest pipe ID. `members` are the pool's members that are not
/// replacements; `view` is the look the policy decided on.
fn shrink_step(
    adding_dials: usize,
    view: &[PoolMember],
    members: impl Iterator<Item = PipeId>,
    retire: &[PipeId],
) -> Option<Shrink> {
    if adding_dials > 0 {
        return Some(Shrink::CancelDial);
    }
    let rank = |id: PipeId| {
        let v = view.iter().find(|v| v.pipe == id);
        (
            retire.contains(&id),
            v.map(|v| v.idle),
            v.map(|v| Reverse(v.pipes)),
            v.map(|v| Reverse(v.age)),
            id,
        )
    };
    members.max_by_key(|&id| rank(id)).map(Shrink::Close)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Listener, ListenerConfig, PipeAuth};
    use std::sync::atomic::AtomicUsize;

    fn config() -> Config {
        Config {
            max_pipes: 4,
            pipe_auth: PipeAuth::psk(*b"maintain-psk----0123456789abcdef").with_end_to_end(),
            ..Config::default()
        }
    }

    /// The shrink order every implementation shares (`testdata/pool-shrink/vectors.json`), driven through the maintainer's
    /// own step function.
    #[test]
    fn shrink_order_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/pool-shrink/vectors.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let num = |x: &serde_json::Value| x.as_u64().unwrap();
        let list =
            |x: &serde_json::Value| -> Vec<u64> { x.as_array().unwrap().iter().map(num).collect() };
        for case in v["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let view: Vec<PoolMember> = case["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| PoolMember {
                    pipe: PipeId::new(num(&m["key"])),
                    idle: Duration::from_secs(num(&m["idle"])),
                    pipes: usize::try_from(num(&m["pipes"])).unwrap(),
                    age: Duration::from_secs(num(&m["age"])),
                    ..PoolMember::default()
                })
                .collect();
            let retire: Vec<PipeId> = list(&case["decision"]["retire"])
                .into_iter()
                .map(PipeId::new)
                .collect();
            let count = usize::try_from(num(&case["decision"]["count"])).unwrap();
            let mut dialing = usize::try_from(num(&case["dialing"])).unwrap();
            let mut members: Vec<PipeId> = view.iter().map(|m| m.pipe).collect();
            let (mut cancelled, mut closed) = (Vec::new(), Vec::new());
            while members.len() + dialing > count {
                match shrink_step(dialing, &view, members.iter().copied(), &retire).unwrap() {
                    Shrink::CancelDial => {
                        dialing -= 1;
                        cancelled.push(dialing as u64);
                    }
                    Shrink::Close(id) => {
                        members.retain(|m| *m != id);
                        closed.push(id.get());
                    }
                }
            }
            assert_eq!(
                cancelled,
                list(&case["expect"]["cancel_dials"]),
                "{name}: dials"
            );
            assert_eq!(closed, list(&case["expect"]["close"]), "{name}: members");
        }
    }

    /// The jitter of a redial's wait is drawn once per dial and once per
    /// outcome, never at a look: with the policy looking every 10 ms and
    /// waits of at least 30 ms, a draw at each look would add three or more
    /// per dial. Paused time on one thread: the count is exact.
    #[tokio::test(start_paused = true)]
    #[allow(
        clippy::many_single_char_names,
        reason = "test: the two ends, the listener's clone and a counter's"
    )]
    async fn redial_jitter_is_drawn_once() {
        let listener = Listener::new(config(), ListenerConfig::default())
            .expect("valid listener configuration");
        let (a, b) = tokio::io::duplex(64 * 1024);
        let l = listener.clone();
        tokio::spawn(async move {
            let hint = crate::PipeHint::from_peer(([127, 0, 0, 1], 0).into());
            let _ = l.handle_pipe(PipeIo::new(b), hint).await;
        });
        let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
        let _server = listener.accept().await.unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let d = dials.clone();
        let pool = PipePool::new(1, move |_| {
            d.fetch_add(1, Ordering::SeqCst);
            async { Err(io::Error::other("refused")) }
        })
        .with_backoff({
            let mut b = Backoff::new(Duration::from_millis(300), Duration::from_millis(300));
            b.jitter = 0.9;
            b
        })
        .with_policy(|_: &PoolView<'_>, d: &mut PoolDecision| {
            d.set_recheck(Duration::from_millis(10)).unwrap();
            Ok(())
        });
        let before = crate::backoff::DRAWS.with(std::cell::Cell::get);
        let handle = maintain_pipes(&client, pool).expect("valid pool");
        while dials.load(Ordering::SeqCst) < 16 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.stop();
        let draws = crate::backoff::DRAWS.with(std::cell::Cell::get) - before;
        let n = dials.load(Ordering::SeqCst) as u64;
        // One at each dial's start, one at its failure.
        assert!(draws <= 2 * n, "{draws} draws for {n} dials");
        client.close().await;
    }

    /// A `decide` that does not return holds one thread of the policy
    /// executor however many pools share the policy: with more waiting pools
    /// than the executor has threads, a pool of another policy still gets
    /// its answer.
    #[tokio::test]
    async fn a_hung_shared_policy_holds_one_executor_thread() {
        let (release, hold) = std::sync::mpsc::channel::<()>();
        let hung = SyncPolicy::new(move |_: &PoolView<'_>, _: &mut PoolDecision| {
            // Returns once the sender is dropped.
            let _ = hold.recv();
            Ok(())
        });
        let waiting: Vec<_> = (0..2 * policy_exec::THREADS)
            .map(|_| {
                let p = hung.clone();
                tokio::spawn(ask_policy(Policy::Sync(p), OwnedPoolView::default()))
            })
            .collect();
        // Every look has asked, in turn, before the other policy's.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let quick = SyncPolicy::new(|_: &PoolView<'_>, d: &mut PoolDecision| {
            d.set_recheck(Duration::from_secs(1))?;
            Ok(())
        });
        let (answer, d) = tokio::time::timeout(
            Duration::from_secs(10),
            ask_policy(Policy::Sync(quick), OwnedPoolView::default()),
        )
        .await
        .expect("the other policy's look waits behind the hung one");
        assert!(answer.is_ok());
        assert_eq!(d.recheck(), Some(Duration::from_secs(1)));
        drop(release);
        for w in waiting {
            assert!(w.await.unwrap().0.is_ok());
        }
    }
}
