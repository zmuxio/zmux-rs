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
//! A pool dialed by a mode ([`PipePool::mode`]) picks each member's
//! carrier kind through the carrier cache and upgrades members to a
//! preferred kind by the same make-before-break replacement, the
//! replacement settling before the old member is closed; it is also the
//! only upgrade logic of a session dialed in auto mode.
//!
//! It looks at the pipes' statistics at once when a pipe changes state or
//! the session is suspended or resumed, and at least every [`POLL`]; the
//! application keeps the session's pipe events. Dials run on the
//! maintainer task, outside every lock; they go on while the session is
//! suspended (each is a rejoin) and stop when it ends.
//!
//! An optional [`PoolPolicy`] is asked at each of these looks for a
//! [`PoolDecision`]: the number of members to keep, the time of the next
//! dial (in place of the backoff's), the times at which given members are
//! replaced, the idle-probe settings of the pipes added after it and
//! the time by which to ask again (looks come sooner, not later, for it). The
//! maintainer applies it within what it does anyway (dial, add, replace
//! make before break, close) and bounds it; without a policy nothing
//! changes.

use super::backoff::{Backoff, random_fraction, reduce};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Poll, Waker};
use std::time::Duration;

use tokio::time::Instant;

use crate::driver::handle::{self, WeakSession, dead, usable};
use crate::driver::mode::ModeSource;
use crate::driver::resources::{Kind, Live};
use crate::driver::tokio::Tokio;
use crate::proto::session::{
    InboundState, OutboundState, Period, PipeError, PipeId, PipeOptions, PipeStats, State,
};
use crate::{ConnectError, Dial, DialRequest, Mode, ModePolicy, Pipe, PipeIo, Session};
use atomic_waker::AtomicWaker;

use super::POLL;

/// The shortest [`PoolDecision::recheck`] a pool honours: a shorter one
/// is lengthened to this, so that a policy cannot make it spin.
pub const RECHECK_FLOOR: Duration = Duration::from_millis(10);

/// Members to keep up over one path; see [`maintain_pipes`]. A member is
/// a pipe on a carrier that [`PipePool::new`]'s dial opens (its
/// [`DialRequest`] is `Bidi`), or the group of pipes that
/// [`PipePool::join`]'s function joins, such as the downlink and uplink of
/// a split carrier ([`crate::PipeIo::paired_join`]).
///
/// ```no_run
/// # async fn example(session: zmux::Session) {
/// use std::time::Duration;
/// use zmux::PipeOptions;
/// use zmux::helpers::{PipePool, RotatePolicy, maintain_pipes};
///
/// let pool = PipePool::new(2, |_req| async {
///     Ok(zmux::PipeIo::tcp(tokio::net::TcpStream::connect("10.0.0.2:4433").await?))
/// })
/// .with_options(PipeOptions::new().with_priority(10).with_label("relay"))
/// .with_rotate(RotatePolicy::new().with_max_age(Duration::from_secs(600)));
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
    pub rotate: Option<RotatePolicy>,
    /// Redial backoff.
    pub backoff: Backoff,
    /// The policy consulted at each look; see [`PipePool::with_policy`].
    policy: Option<Arc<Mutex<dyn PoolPolicy>>>,
    /// Told of each rejected decision; see
    /// [`PipePool::with_decision_rejected`].
    decision_rejected: Option<RejectFn>,
}

type RejectFn = Arc<dyn Fn(&str) + Send + Sync>;

type JoinFuture = Pin<Box<dyn Future<Output = io::Result<Vec<Pipe>>> + Send>>;
type JoinFn = Arc<dyn Fn(Session, PipeOptions) -> JoinFuture + Send + Sync>;

/// How a pool makes a member.
#[derive(Clone)]
enum Source {
    /// A carrier the pool adds as one pipe.
    Dial(Dial),
    /// Pipes the function joins itself.
    Join(JoinFn),
    /// Pipes joined over a carrier kind a mode chooses.
    Mode(Arc<ModeSource>),
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
    /// session with the options given (for example over [`crate::PipeIo::paired_join`]
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

    /// A pool of one member dialed over the carrier kinds of `mode`, under `policy` (its
    /// [`no_join`](ModePolicy::no_join) does not apply); set
    /// [`count`](Self::count) for more. Stable first, then upgrade: a
    /// member is dialed over the most robust kind available (a kind the
    /// policy's cache holds as usable, else the exchange carrier, else the
    /// last), skipping the kinds the cache holds as failed unless all are;
    /// a split candidate joins as a downlink and an uplink, one member. A
    /// member of a kind that a preferred kind not backing off could replace
    /// is rotated to it, make before break, one such upgrade at a time and
    /// only with room within `max_pipes`; the replacement takes over once
    /// it has stayed usable for [`ModePolicy::settle`], and the old member
    /// is then closed gracefully. A kind whose join fails, whose
    /// replacement ends before it settled, or whose member (or session)
    /// fails within [`ModePolicy::drop_window`] of being joined is recorded
    /// as failed; a joined or settled one as usable. Each try is reported as
    /// a [`SessionEvent::CarrierCandidate`](crate::SessionEvent::CarrierCandidate),
    /// and a member joined over a kind other than the session's carrier as
    /// a [`SessionEvent::CarrierChosen`](crate::SessionEvent::CarrierChosen).
    /// [`Mode::explicit`] dials its one kind, without the cache. Several
    /// pools may share a cache. A mode without candidates or with two of
    /// one kind, or a policy with a negative or non-finite timer factor, is
    /// [`ConnectError::InvalidConfig`].
    pub fn mode(mode: &Mode, policy: &ModePolicy) -> Result<Self, ConnectError> {
        let src = ModeSource::new(mode, policy).map_err(ConnectError::InvalidConfig)?;
        Ok(Self::of(1, Source::Mode(Arc::new(src))))
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
    pub fn with_rotate(mut self, rotate: RotatePolicy) -> Self {
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
        self.policy = Some(Arc::new(Mutex::new(policy)));
        self
    }

    /// With a function told the reason of each decision of the policy
    /// that was [rejected](PoolDecision::reject); it runs on the
    /// maintainer task and must return promptly. Without one, rejected
    /// decisions are only kept from taking effect.
    #[must_use]
    pub fn with_decision_rejected(mut self, f: impl Fn(&str) + Send + Sync + 'static) -> Self {
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
                    Source::Mode(_) => "mode",
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
pub struct RotatePolicy {
    /// Bytes carried in either direction (a group's pipes summed).
    pub max_bytes: Option<u64>,
    /// Age of the member. For a carrier with a hard lifetime, set it
    /// below that by the expected probation and a few round trips.
    pub max_age: Option<Duration>,
    /// Each limit is reduced by a random fraction of up to this (0 to 1),
    /// so that members opened together do not rotate together.
    pub jitter: f64,
}

impl RotatePolicy {
    /// No limit and no jitter: set the limits with the builders.
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
/// keeps, when it may dial next and when given members are replaced.
///
/// [`decide`](Self::decide) runs on the maintainer task each time it looks
/// at its members (at once after a pipe of the session changed state or
/// the session was suspended or resumed, after 100 ms at the latest, after
/// each finished dial, and by the [`recheck`](PoolDecision::recheck) of
/// its last decision); it must return promptly and must not call into the
/// session. It starts from a default [`PoolDecision`], in which every
/// field keeps the pool's own behaviour.
pub trait PoolPolicy: Send {
    /// Fills `out` from the state of the pool in `view`.
    fn decide(&mut self, view: &PoolView<'_>, out: &mut PoolDecision);
}

impl<F> PoolPolicy for F
where
    F: FnMut(&PoolView<'_>, &mut PoolDecision) + Send,
{
    fn decide(&mut self, view: &PoolView<'_>, out: &mut PoolDecision) {
        self(view, out);
    }
}

/// The state of a pool that a [`PoolPolicy`] sees.
#[derive(Debug)]
#[non_exhaustive]
pub struct PoolView<'a> {
    /// The time of the look.
    pub now: std::time::Instant,
    /// The pool's members, replacements included.
    pub members: &'a [PoolMember],
    /// Consecutive failed redials (reset when a member becomes usable).
    pub redial_failures: u32,
    /// Consecutive failed replacements.
    pub rotate_failures: u32,
    /// When the pool last started a dial; `None` before the first.
    pub last_dial_at: Option<std::time::Instant>,
    /// When the pool started: dial waits count from it before the first
    /// dial.
    pub started: std::time::Instant,
    /// The session's state.
    pub session_state: crate::SessionState,
}

/// A member of the pool in a [`PoolView`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PoolMember {
    /// The member's identifier: the ID of its first pipe.
    pub id: PipeId,
    /// The statistics of its pipes (one for a dialled member).
    pub pipes: Vec<PipeStats>,
    /// Every pipe serves its direction (an outbound pipe ACTIVE and out
    /// of probation, a downlink OPEN) and the peer attached it
    /// (`Pipe::attached`).
    pub usable: bool,
    /// It is the replacement of this member, until it becomes usable.
    pub replaces: Option<PipeId>,
    /// A replacement of it is being joined.
    pub replaced: bool,
}

impl PoolMember {
    /// Bytes sent over its pipes.
    pub fn bytes_sent(&self) -> u64 {
        self.pipes.iter().map(|p| p.bytes_sent).sum()
    }

    /// Bytes received over its pipes.
    pub fn bytes_received(&self) -> u64 {
        self.pipes.iter().map(|p| p.bytes_received).sum()
    }

    /// The least time since a traffic frame on any of its pipes.
    pub fn since_last_traffic(&self) -> Option<Duration> {
        self.pipes.iter().filter_map(|p| p.since_last_traffic).min()
    }

    /// How long its oldest pipe has been attached.
    pub fn age(&self) -> Duration {
        self.pipes
            .iter()
            .map(|p| p.attached_for)
            .max()
            .unwrap_or_default()
    }
}

/// What a [`PoolPolicy`] decides; each field left at its default keeps the
/// pool's own behaviour. The maintainer bounds the values.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct PoolDecision {
    /// Usable members to keep instead of [`PipePool::count`]; at least 1.
    /// A lower count closes no member: members above it are not
    /// redialled when they fail.
    pub count: Option<usize>,
    /// The next dial, redial or replacement starts then, in place of the
    /// backoff's delay (and its jitter); it is held for at most the
    /// backoff's [`max`](Backoff::max) after the start of the last dial
    /// (or the maintainer's start).
    pub next_dial_at: Option<std::time::Instant>,
    /// Members of the pool to replace, make before break, from the given
    /// time on (a past time: at once). A member's replacement time only
    /// moves earlier; members that are not usable, or already being
    /// replaced, are skipped.
    pub rotate: Vec<(PipeId, std::time::Instant)>,
    /// Ask the policy again within this, even if nothing happens in the
    /// pool (`None`: no such need; the pool's own looks go on). It is
    /// lengthened to [`RECHECK_FLOOR`] at least and is not capped.
    pub recheck: Option<Duration>,
    probe_interval: Option<Period>,
    probe_jitter: Option<f64>,
    rejected: Option<String>,
}

impl PoolDecision {
    /// Rejects the decision as a whole for `reason`: the pool keeps its
    /// own behaviour, as for a default decision, and tells the pool's
    /// [`with_decision_rejected`](PipePool::with_decision_rejected)
    /// function. For a policy that cannot keep its decision within bounds
    /// (the setters' errors are for a policy that can).
    pub fn reject(&mut self, reason: impl Into<String>) {
        self.rejected = Some(reason.into());
    }

    /// The reason the decision was rejected, if it was.
    pub fn rejected(&self) -> Option<&str> {
        self.rejected.as_deref()
    }

    /// Sets the idle-probe interval of the pipes the pool adds after this
    /// decision, in place of [`PipePool::options`]'
    /// [`probe_interval`](PipeOptions::probe_interval); pipes already added
    /// keep theirs. [`Period::Off`] turns their idle probes off; a period
    /// below 1 s is [`PipeError::InvalidOptions`], as for the pipe option.
    pub fn set_probe_interval(&mut self, interval: impl Into<Period>) -> Result<(), PipeError> {
        let interval = interval.into();
        if !interval.off_or_seconds() {
            return Err(PipeError::InvalidOptions);
        }
        self.probe_interval = Some(interval);
        Ok(())
    }

    /// Likewise their idle-probe jitter; outside \[0, 1) is
    /// [`PipeError::InvalidOptions`].
    pub fn set_probe_jitter(&mut self, jitter: f64) -> Result<(), PipeError> {
        if !(0.0..1.0).contains(&jitter) {
            return Err(PipeError::InvalidOptions);
        }
        self.probe_jitter = Some(jitter);
        Ok(())
    }

    /// The idle-probe interval set, if any.
    pub fn probe_interval(&self) -> Option<Period> {
        self.probe_interval
    }

    /// The idle-probe jitter set, if any.
    pub fn probe_jitter(&self) -> Option<f64> {
        self.probe_jitter
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
/// tokio runtime (it panics outside one).
///
/// # Errors
///
/// [`ConnectError::InvalidConfig`] for a backoff whose initial delay is
/// zero or above its max, or whose jitter is outside \[0, 1\].
pub fn maintain_pipes(session: &Session, pool: PipePool) -> Result<MaintainHandle, ConnectError> {
    pool.backoff
        .validate()
        .map_err(ConnectError::InvalidConfig)?;
    let stop = Arc::new(Stop::default());
    Maintainer::spawn(
        Link::Strong(session.clone()),
        pool,
        Vec::new(),
        stop.clone(),
    );
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
    Maintainer::spawn(
        Link::Weak(session.downgrade()),
        pool,
        vec![first],
        Arc::default(),
    );
}

/// The pool of a session dialed by [`crate::dial_mode`]: one member over
/// `src`, first `pipe0`, of kind `kind`, chosen at `chosen`. It holds no
/// handle of the session between its looks and ends with it.
pub(crate) fn maintain_mode(
    session: &Session,
    src: Arc<ModeSource>,
    kind: usize,
    pipe0: Pipe,
    chosen: std::time::Instant,
) {
    let mut first = Member::new(vec![pipe0], Some(kind));
    first.joined = chosen;
    first.was_usable = true;
    let pool = PipePool::of(1, Source::Mode(src));
    Maintainer::spawn(
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
    /// With a mode: the candidate it was joined over, and when (for the
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
    /// With a mode: the candidate dialed, and whether it is an upgrade.
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
    /// Usable members to keep: the policy's, else the pool's.
    count: usize,
    /// The policy's next dial; `None`: the backoff's.
    dial_gate: Option<Instant>,
    /// The policy's idle-probe interval and jitter for pipes added now.
    probe: (Option<Period>, Option<f64>),
    /// When the last dial started.
    last_dial_at: Option<Instant>,
    /// When the maintainer started: waits count from it before the first
    /// dial.
    started: Instant,
    /// When the policy asked to be consulted again; `None`: no need.
    recheck_at: Option<Instant>,
    /// The session's pipe changes as of the last look.
    seen: u64,
    /// The pool counted as a redial source while it runs (ResumeUnattended),
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
    fn spawn(link: Link, pool: PipePool, members: Vec<Member>, stop: Arc<Stop>) {
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
            count: 0,
            dial_gate: None,
            probe: (None, None),
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
        tokio::spawn(task.run());
    }

    /// The pool's mode, if it dials by one.
    fn mode(&self) -> Option<&Arc<ModeSource>> {
        match &self.pool.source {
            Source::Mode(m) => Some(m),
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
            self.consult(&session, &infos, now);
            self.rotate(&session, &infos, now);
            self.start_dials(&session, now);
            let next = self.next_check(now);
            let sh = session.shared().clone();
            drop(session);
            let wake = {
                let sleep = tokio::time::sleep_until(next);
                let mut sleep = std::pin::pin!(sleep);
                let mut closed = std::pin::pin!(handle::closed_wait(&sh));
                let mut changed = std::pin::pin!(handle::pipes_changed_wait(&sh, self.seen));
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
                                Box::new(self.dials.swap_remove(i)),
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
                    if let Some(session) = self.link.get() {
                        self.dialled(&session, *dialing, *r);
                    }
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
        // With a mode, a session that failed counts against the kinds of
        // the members joined less than the drop window ago.
        if let (Some(src), Some(sh)) = (self.mode(), shared)
            && crate::driver::mode::session_failed(&sh)
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
            .map(|m| m.pipes.iter().map(Pipe::stats).collect())
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

    /// Asks the policy, if any, and applies its decision within bounds.
    fn consult(&mut self, session: &Session, infos: &[Vec<Option<PipeStats>>], now: Instant) {
        self.count = self.pool.count;
        self.dial_gate = None;
        self.probe = (None, None);
        self.recheck_at = None;
        let Some(policy) = self.pool.policy.clone() else {
            return;
        };
        let members: Vec<PoolMember> = self
            .members
            .iter()
            .zip(infos)
            .filter_map(|(m, i)| {
                let pipes: Option<Vec<PipeStats>> = i.iter().cloned().collect();
                let pipes = pipes?;
                Some(PoolMember {
                    id: m.id(),
                    usable: m.pipes.iter().zip(&pipes).all(|(p, i)| usable(p, i)),
                    pipes,
                    replaces: m.replaces,
                    replaced: m.replaced,
                })
            })
            .collect();
        let view = PoolView {
            now: now.into_std(),
            members: &members,
            redial_failures: self.redial_failures,
            rotate_failures: self.rotate_failures,
            last_dial_at: self.last_dial_at.map(Instant::into_std),
            started: self.started.into_std(),
            session_state: session.state(),
        };
        let mut d = PoolDecision::default();
        policy
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .decide(&view, &mut d);
        if let Some(reason) = d.rejected.take() {
            if let Some(f) = &self.pool.decision_rejected {
                f(&reason);
            }
            d = PoolDecision::default();
        }
        if let Some(c) = d.count {
            self.count = c.max(1);
        }
        self.dial_gate = d.next_dial_at.map(Instant::from_std);
        self.probe = (d.probe_interval, d.probe_jitter);
        self.recheck_at = d
            .recheck
            .and_then(|r| now.checked_add(r.max(RECHECK_FLOOR)));
        for (id, at) in d.rotate {
            let at = Instant::from_std(at);
            if let Some(m) = self
                .members
                .iter_mut()
                .find(|m| m.id() == id && m.replaces.is_none() && !m.replaced)
            {
                m.max_age = Some(m.max_age.map_or(at, |t| t.min(at)));
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
    /// the policy's time in place of the backoff's, held for at most the
    /// backoff's max after the last dial's start; `None`: never.
    fn dial_time(&self, delay: Duration) -> Option<Instant> {
        let since = self.since();
        let Some(g) = self.dial_gate else {
            return since.checked_add(delay);
        };
        let cap = since.checked_add(self.pool.backoff.max);
        Some(cap.map_or(g, |c| c.min(g)))
    }

    fn may_dial(&self, delay: Duration, now: Instant) -> bool {
        self.dial_time(delay).is_some_and(|t| now >= t)
    }

    /// Members and redials that fill the pool's slots (a replacement
    /// shares its old member's slot).
    fn slots(&self) -> usize {
        self.members.iter().filter(|m| m.replaces.is_none()).count()
            + self
                .dials
                .iter()
                .filter(|d| d.purpose == Purpose::Redial)
                .count()
    }

    fn wants_redial(&self) -> bool {
        self.slots() < self.count
    }

    /// Looks at the pool's members: failures, usable replacements (with a
    /// mode, once they stayed usable for the settle time).
    fn observe(&mut self, session: &Session, now: Instant) {
        let infos = self.infos();
        let settle = self.mode().map(|m| m.settle());
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
        let mode = self.mode().cloned();
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
    /// with a mode, one of a member a preferred kind could replace.
    fn rotate(&mut self, session: &Session, infos: &[Vec<Option<PipeStats>>], now: Instant) {
        let mode = self.mode().cloned();
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
            || !self.session_whole(session)
            || !session.join_ready()
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
    fn session_whole(&self, session: &Session) -> bool {
        if session.state() == State::Suspended {
            return false;
        }
        let pipes = session.pipe_stats();
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
        if !self.wants_redial() || !session.join_ready() || !self.may_dial(self.redial_delay(), now)
        {
            // A carrier dialled now would wait idle for its join: look again
            // at the next poll.
            return;
        }
        for _ in self.slots()..self.count {
            let kind = self.mode().map(|m| m.pick());
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
            Source::Mode(m) => {
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
    /// idle-probe settings, and `no_wait_attached` set: a replacement
    /// closes its old pipe only once the peer attached it (the member's own
    /// judgement), and a redial must not wait for a PIPE_ACK that only the
    /// direction it restores could carry.
    fn options(&self) -> PipeOptions {
        let mut o = self.pool.options.clone();
        o.no_wait_attached = true;
        let (interval, jitter) = self.probe;
        o.probe_interval = interval.or(o.probe_interval);
        o.probe_jitter = jitter.or(o.probe_jitter);
        o
    }

    /// A dial or join failed: backoff from its start, and nothing more to
    /// do on a session that cannot take pipes.
    fn dial_failed(&mut self, purpose: Purpose, e: Option<&PipeError>) {
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
    fn dialled(&mut self, session: &Session, dialing: Dialing, made: Made) {
        let now = Instant::now();
        let purpose = dialing.purpose;
        let pipes = match made {
            Made::Carrier(Ok(io)) => {
                // The member waits for the Reply and the attachment itself.
                session.begin_add_pipe(*io, self.options()).map(|p| vec![p])
            }
            Made::Carrier(Err(e)) => Err(PipeError::Io(e.kind())),
            Made::Joined(Ok(pipes)) if !pipes.is_empty() => Ok(pipes),
            Made::Joined(Ok(_)) => Err(PipeError::InvalidArgument),
            Made::Joined(Err(e)) => Err(PipeError::Io(e.kind())),
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
            && let (Some(src), Some(k)) = (self.mode(), m.kind)
        {
            src.established(session, k);
        }
        self.members.push(m);
    }
}

/// The member's rotation limits, each reduced by its own random fraction.
fn set_limits(m: &mut Member, rotate: Option<&RotatePolicy>, now: Instant) {
    let Some(r) = rotate else { return };
    let keep = |jitter: f64| 1.0 - jitter.clamp(0.0, 1.0) * random_fraction();
    m.max_bytes = r.max_bytes.map(|b| (b as f64 * keep(r.jitter)) as u64);
    // An age beyond the clock's range never comes.
    m.max_age = r.max_age.and_then(|a| now.checked_add(reduce(a, r.jitter)));
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

    /// The jitter of a redial's wait is drawn once per dial and once per
    /// outcome, never at a look: with the policy looking every 10 ms and
    /// waits of at least 30 ms, a draw at each look would add three or more
    /// per dial. Paused time on one thread: the count is exact.
    #[tokio::test(start_paused = true)]
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
        .with_backoff(
            Backoff::new(Duration::from_millis(300), Duration::from_millis(300)).with_jitter(0.9),
        )
        .with_policy(|_: &PoolView<'_>, d: &mut PoolDecision| {
            d.recheck = Some(Duration::from_millis(10));
        });
        let before = super::super::backoff::DRAWS.with(std::cell::Cell::get);
        let handle = maintain_pipes(&client, pool).expect("valid pool");
        while dials.load(Ordering::SeqCst) < 16 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.stop();
        let draws = super::super::backoff::DRAWS.with(std::cell::Cell::get) - before;
        let n = dials.load(Ordering::SeqCst) as u64;
        // One at each dial's start, one at its failure.
        assert!(draws <= 2 * n, "{draws} draws for {n} dials");
        client.close(0u32.into(), b"").await;
    }
}
