//! Keeping pipes up (non-normative): a helper above the
//! session that uses only its public API ([`Session::add_pipe`](Session#method.add_pipe),
//! [`Session::pipes`](Session#method.pipes), [`Pipe::stats`](Pipe#method.stats), [`Pipe::close`](Pipe#method.close)) and
//! the pool's `dial`; it changes nothing on the wire and keeps no state in
//! the session.
//!
//! One maintainer task per pool keeps `count` usable pipes dialled by the
//! pool, redials failed ones with exponential backoff and jitter, and
//! rotates them make-before-break: when a usable pipe has carried
//! `max_bytes` in either direction or is `max_age` old (each reduced by a
//! random fraction of up to `jitter`), a replacement is dialled and added
//! with the same options, and the old pipe is closed gracefully once the
//! replacement is usable (ACTIVE and out of probation). A failed dial or a
//! replacement that fails keeps the old pipe and retries with backoff.
//! Nothing rotates while the session lacks a usable outbound or a live
//! inbound pipe or is suspended, and redials never wait for rotations.
//!
//! It watches the pipes by polling their statistics (at most every
//! [`POLL`]), so the application keeps the session's pipe events. Dials run
//! on the maintainer task, outside every lock.

use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Poll, Waker};
use std::time::Duration;

use tokio::time::Instant;

use crate::driver::resources::{Kind, Live};
use crate::proto::session::{PipeError, PipeId, PipeOptions, PipeState, PipeStats, State};
use crate::{Dial, DialRequest, Pipe, PipeDirection, PipeIo, PipeReservation, Session};
use atomic_waker::AtomicWaker;

/// How often the maintainer looks at its pipes, at most.
pub(crate) const POLL: Duration = Duration::from_millis(100);

/// Pipes to keep up over one path; see
/// [`maintain_pipes`]. Its dial gets a [`DialRequest`]: `Bidi`, `Out` for
/// an uplink or the replacement of an outbound-only pipe, `In` for a
/// downlink of a split pool.
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
/// .with_rotate(RotatePolicy {
///     max_age: Some(Duration::from_secs(600)),
///     ..RotatePolicy::default()
/// });
/// let _keep = maintain_pipes(&session, pool);
/// # }
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct PipePool {
    /// Dials a carrier.
    pub dial: Dial,
    /// Usable pipes to keep.
    pub count: usize,
    /// The options of every pipe of the pool.
    pub options: PipeOptions,
    /// Rotation; none by default.
    pub rotate: Option<RotatePolicy>,
    /// Redial backoff.
    pub backoff: BackoffPolicy,
    /// The pool's carriers are one-way (an uplink and a downlink, for
    /// example an HTTP POST body and a GET response through a CDN): it keeps
    /// `count` uplinks and `count` downlinks, and dials the two directions
    /// in parallel, so that a lost direction, which comes with a lost peer
    /// direction, is rejoined without waiting (RESUME.md Section 4.3). A
    /// downlink joins out of band: its dial gets the join header.
    pub split: bool,
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
        Self {
            dial,
            count,
            options: PipeOptions::default(),
            rotate: None,
            backoff: BackoffPolicy::default(),
            split: false,
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
    pub fn with_backoff(mut self, backoff: BackoffPolicy) -> Self {
        self.backoff = backoff;
        self
    }

    /// One-way carriers: `count` uplinks and `count` downlinks (see
    /// [`PipePool::split`]).
    #[must_use]
    pub fn with_split(mut self, split: bool) -> Self {
        self.split = split;
        self
    }
}

impl fmt::Debug for PipePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipePool")
            .field("count", &self.count)
            .field("options", &self.options)
            .field("rotate", &self.rotate)
            .field("backoff", &self.backoff)
            .field("split", &self.split)
            .finish_non_exhaustive()
    }
}

/// When the pipes of a pool are replaced (make before break).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RotatePolicy {
    /// Bytes carried in either direction.
    pub max_bytes: Option<u64>,
    /// Age of the attachment. For a carrier with a hard lifetime, set it
    /// below that by the expected probation and a few round trips.
    pub max_age: Option<Duration>,
    /// Each limit is reduced by a random fraction of up to this (0 to 1),
    /// so that pipes opened together do not rotate together.
    pub jitter: f64,
}

/// Exponential backoff of failed dials and joins.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BackoffPolicy {
    /// The first delay.
    pub initial: Duration,
    /// The largest delay.
    pub max: Duration,
    /// Each delay is reduced by a random fraction of up to this (0 to 1).
    pub jitter: f64,
}

impl Default for BackoffPolicy {
    /// From 1 s to at most 60 s, with 20 % jitter.
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            jitter: 0.2,
        }
    }
}

impl BackoffPolicy {
    /// The delay after `failures` consecutive failures (none before the
    /// first).
    fn delay(&self, failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let exp = self
            .initial
            .saturating_mul(1u32.checked_shl(failures - 1).unwrap_or(u32::MAX))
            .min(self.max);
        reduce(exp, self.jitter)
    }
}

/// `d` reduced by a random fraction of up to `jitter`.
fn reduce(d: Duration, jitter: f64) -> Duration {
    let f = 1.0 - jitter.clamp(0.0, 1.0) * random_fraction();
    // Saturating: near the largest duration the product rounds above it.
    Duration::try_from_secs_f64(d.as_secs_f64() * f).map_or(d, |r| r.min(d))
}

/// A uniform value in [0, 1).
fn random_fraction() -> f64 {
    let r = getrandom::u64().unwrap_or(0) >> 11;
    r as f64 / (1u64 << 53) as f64
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

/// Keeps the pool's pipes of `session` up: `count`
/// usable pipes dialled by `pool.dial` (one pool per path; several pools
/// may run on one session), redialled with exponential backoff when they
/// fail and rotated by `pool.rotate`, make before break. Dropping the
/// handle or [`MaintainHandle::stop`] ends it, as does the end of the
/// session. Needs a multipath session and a tokio runtime (it panics
/// outside one).
pub fn maintain_pipes(session: &Session, pool: PipePool) -> MaintainHandle {
    let stop = Arc::new(Stop::default());
    let task = Maintainer {
        session: session.clone(),
        pool,
        stop: stop.clone(),
        members: Vec::new(),
        dials: Vec::new(),
        redial_failures: 0,
        rotate_failures: 0,
        redial_at: Some(Instant::now()),
        rotate_at: Some(Instant::now()),
    };
    tokio::spawn(task.run());
    MaintainHandle { stop }
}

/// Why a dial was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Redial,
    /// The replacement of this pipe.
    Rotate(PipeId),
}

/// A pipe of the pool.
struct Member {
    pipe: Pipe,
    direction: PipeDirection,
    /// Rotation limits (jittered).
    max_bytes: Option<u64>,
    max_age: Option<Instant>,
    /// It replaces this pipe once usable.
    replaces: Option<PipeId>,
    /// A replacement is being dialled or joined for it.
    replaced: bool,
    /// It was usable once.
    was_usable: bool,
}

type DialFuture = Pin<Box<dyn Future<Output = io::Result<PipeIo>> + Send>>;

/// A dial under way: why, for which direction, and the reservation of a
/// downlink's out-of-band join.
struct Dialing {
    purpose: Purpose,
    direction: PipeDirection,
    future: DialFuture,
    reservation: Option<PipeReservation>,
}

struct Maintainer {
    session: Session,
    pool: PipePool,
    stop: Arc<Stop>,
    members: Vec<Member>,
    dials: Vec<Dialing>,
    redial_failures: u32,
    rotate_failures: u32,
    /// The next redial and rotation may start then; `None`: never (a
    /// backoff beyond the clock's range).
    redial_at: Option<Instant>,
    rotate_at: Option<Instant>,
}

/// What woke the maintainer.
enum Wake {
    Stop,
    Dial(Box<Dialing>, io::Result<PipeIo>),
    Tick,
}

/// A pipe of the pool serves its direction: an outbound one is ACTIVE and
/// out of probation, an inbound-only one (a downlink) is OPEN.
fn usable(info: &PipeStats, direction: PipeDirection) -> bool {
    match direction {
        PipeDirection::In => info.inbound == Some(PipeState::Open),
        PipeDirection::Out | PipeDirection::Bidi => {
            info.outbound == Some(PipeState::Active) && !info.in_probation
        }
    }
}

/// A pipe of the pool no longer serves its direction.
fn dead(info: Option<&PipeStats>, direction: PipeDirection) -> bool {
    info.is_none_or(|i| match direction {
        PipeDirection::In => matches!(
            i.inbound,
            Some(PipeState::Ended | PipeState::Retired) | None
        ),
        PipeDirection::Out | PipeDirection::Bidi => matches!(
            i.outbound,
            Some(PipeState::Failed | PipeState::Closed | PipeState::Draining | PipeState::Retired)
                | None
        ),
    })
}

impl Maintainer {
    async fn run(mut self) {
        let _live = Live::new(Kind::Maintainer);
        loop {
            if self.session.close_reason().is_some() {
                break;
            }
            let now = Instant::now();
            self.observe(now);
            self.start_dials(now);
            let next = self.next_check(now);
            let sleep = tokio::time::sleep_until(next);
            let mut sleep = std::pin::pin!(sleep);
            let session = self.session.clone();
            let mut closed = std::pin::pin!(session.closed());
            let wake = poll_fn(|cx| {
                if self.stop.is_stopped(cx.waker()) || closed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Wake::Stop);
                }
                for i in 0..self.dials.len() {
                    if let Poll::Ready(r) = self.dials[i].future.as_mut().poll(cx) {
                        return Poll::Ready(Wake::Dial(Box::new(self.dials.swap_remove(i)), r));
                    }
                }
                sleep.as_mut().poll(cx).map(|()| Wake::Tick)
            })
            .await;
            match wake {
                Wake::Stop => break,
                Wake::Dial(dialing, r) => self.dialled(*dialing, r),
                Wake::Tick => {}
            }
        }
        // Dials in flight are cancelled here; a carrier one already
        // returned was handed to the session or dropped (closed).
        self.dials.clear();
        self.stop.finished.store(true, Ordering::SeqCst);
    }

    /// When to look again.
    fn next_check(&self, now: Instant) -> Instant {
        let mut next = now + POLL;
        if self.wants_redial()
            && let Some(t) = self.redial_at.filter(|&t| t > now)
        {
            next = next.min(t);
        }
        next
    }

    fn wants_redial(&self) -> bool {
        self.directions()
            .iter()
            .any(|&d| self.slots(d) < self.pool.count)
    }

    /// The directions the pool keeps pipes of.
    fn directions(&self) -> &'static [PipeDirection] {
        if self.pool.split {
            &[PipeDirection::Out, PipeDirection::In]
        } else {
            &[PipeDirection::Bidi]
        }
    }

    /// Pipes and redials of a direction that fill the pool's slots (a
    /// replacement shares its old pipe's slot).
    fn slots(&self, direction: PipeDirection) -> usize {
        self.members
            .iter()
            .filter(|m| m.replaces.is_none() && m.direction == direction)
            .count()
            + self
                .dials
                .iter()
                .filter(|d| d.purpose == Purpose::Redial && d.direction == direction)
                .count()
    }

    /// Looks at the pool's pipes: failures, usable replacements, limits.
    fn observe(&mut self, now: Instant) {
        let infos: Vec<Option<PipeStats>> = self.members.iter().map(|m| m.pipe.stats()).collect();
        let mut gone = Vec::new();
        let mut close = Vec::new();
        for (m, info) in self.members.iter_mut().zip(&infos) {
            if dead(info.as_ref(), m.direction) {
                gone.push(m.pipe.id());
                continue;
            }
            let Some(info) = info else { continue };
            if usable(info, m.direction) {
                m.was_usable = true;
                self.redial_failures = 0;
                if let Some(old) = m.replaces.take() {
                    // Make before break: the replacement is usable.
                    close.push(old);
                    self.rotate_failures = 0;
                }
            }
        }
        for id in gone {
            let Some(i) = self.members.iter().position(|m| m.pipe.id() == id) else {
                continue;
            };
            let m = self.members.swap_remove(i);
            if let Some(old) = m.replaces {
                // The replacement failed: the old pipe stays.
                if let Some(o) = self.members.iter_mut().find(|o| o.pipe.id() == old) {
                    o.replaced = false;
                }
                self.rotate_failed(now);
            } else if let Some(r) = self.members.iter_mut().find(|r| r.replaces == Some(id)) {
                // The old pipe went first: its replacement takes the slot.
                r.replaces = None;
            } else if !m.was_usable {
                self.redial_failed(now);
            }
        }
        for id in close {
            if let Some(i) = self.members.iter().position(|m| m.pipe.id() == id) {
                let _ = self.members.swap_remove(i).pipe.close();
            }
        }
        self.rotate(&infos, now);
    }

    /// Dials replacements of the usable pipes that reached a limit.
    fn rotate(&mut self, infos: &[Option<PipeStats>], now: Instant) {
        if self.pool.rotate.is_none() || self.rotate_at.is_none_or(|t| now < t) {
            return;
        }
        let due: Vec<PipeId> = self
            .members
            .iter()
            .zip(infos)
            .filter(|(m, i)| {
                let Some(i) = i else { return false };
                !m.replaced
                    && m.replaces.is_none()
                    && usable(i, m.direction)
                    && (m.max_age.is_some_and(|t| now >= t)
                        || m.max_bytes
                            .is_some_and(|b| i.bytes_sent >= b || i.bytes_received >= b))
            })
            .map(|(m, _)| m.pipe.id())
            .collect();
        if due.is_empty() || !self.session_whole() || !self.session.join_ready() {
            return;
        }
        for id in due {
            let Some(m) = self.members.iter_mut().find(|m| m.pipe.id() == id) else {
                continue;
            };
            m.replaced = true;
            let direction = m.direction;
            if !self.dial(Purpose::Rotate(id), direction) {
                break;
            }
        }
    }

    /// Whether the session has a usable outbound and a live inbound pipe
    /// and is not suspended: only then may pipes rotate.
    fn session_whole(&self) -> bool {
        if self.session.state() == State::Suspended {
            return false;
        }
        let pipes = self.session.pipe_stats();
        pipes.iter().any(|p| usable(p, PipeDirection::Out))
            && pipes.iter().any(|p| usable(p, PipeDirection::In))
    }

    fn start_dials(&mut self, now: Instant) {
        if !self.session.is_multipath() {
            // Nothing to maintain.
            self.stop.stop();
            return;
        }
        if self.redial_at.is_none_or(|t| now < t)
            || (self.wants_redial() && !self.session.join_ready())
        {
            // A carrier dialled now would wait idle for its join: look again
            // at the next poll.
            return;
        }
        // Split carriers: both directions are dialled at once.
        for &d in self.directions() {
            for _ in self.slots(d)..self.pool.count {
                if !self.dial(Purpose::Redial, d) {
                    // One failure, one backoff step.
                    return;
                }
            }
        }
    }

    /// Starts a dial; a downlink reserves its out-of-band join first, whose
    /// header the dial carries.
    fn dial(&mut self, purpose: Purpose, direction: PipeDirection) -> bool {
        let reservation = match direction {
            PipeDirection::In => {
                match self
                    .session
                    .reserve_pipe(direction, self.pool.options.clone())
                {
                    Ok(r) => Some(r),
                    Err(e) => {
                        self.dial_failed(purpose, &e);
                        return false;
                    }
                }
            }
            PipeDirection::Out | PipeDirection::Bidi => None,
        };
        let request = DialRequest {
            direction,
            join_header: reservation.as_ref().map(PipeReservation::header),
        };
        self.dials.push(Dialing {
            purpose,
            direction,
            future: self.pool.dial.boxed(request),
            reservation,
        });
        true
    }

    /// A dial or join failed: backoff, and nothing more to do on a session
    /// that cannot take pipes.
    fn dial_failed(&mut self, purpose: Purpose, e: &PipeError) {
        let now = Instant::now();
        if matches!(e, PipeError::NotNegotiated | PipeError::SessionLost(_)) {
            // Nothing to maintain.
            self.stop.stop();
        }
        match purpose {
            Purpose::Redial => self.redial_failed(now),
            Purpose::Rotate(old) => {
                if let Some(o) = self.members.iter_mut().find(|o| o.pipe.id() == old) {
                    o.replaced = false;
                }
                self.rotate_failed(now);
            }
        }
    }

    fn redial_failed(&mut self, now: Instant) {
        self.redial_failures = self.redial_failures.saturating_add(1);
        self.redial_at = now.checked_add(self.pool.backoff.delay(self.redial_failures));
    }

    fn rotate_failed(&mut self, now: Instant) {
        self.rotate_failures = self.rotate_failures.saturating_add(1);
        self.rotate_at = now.checked_add(self.pool.backoff.delay(self.rotate_failures));
    }

    /// A dial finished: the carrier joins the session.
    fn dialled(&mut self, dialing: Dialing, r: io::Result<PipeIo>) {
        let now = Instant::now();
        let Dialing {
            purpose,
            direction,
            reservation,
            ..
        } = dialing;
        // A carrier the session refuses is dropped, which closes it; a
        // failed dial cancels a reservation.
        let added = match (r, reservation) {
            (Ok(io), Some(r)) => r.attach(io),
            (Ok(io), None) => self.session.add_pipe(io, self.pool.options.clone()),
            (Err(e), r) => {
                if let Some(r) = r {
                    r.cancel();
                }
                Err(PipeError::Io(e.kind()))
            }
        };
        let pipe = match added {
            Ok(p) => p,
            Err(e) => {
                self.dial_failed(purpose, &e);
                return;
            }
        };
        let replaces = match purpose {
            Purpose::Redial => None,
            Purpose::Rotate(old) => self
                .members
                .iter()
                .any(|o| o.pipe.id() == old)
                .then_some(old),
        };
        let mut m = Member {
            pipe,
            direction,
            max_bytes: None,
            max_age: None,
            replaces,
            replaced: false,
            was_usable: false,
        };
        set_limits(&mut m, self.pool.rotate.as_ref(), now);
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

    /// Durations have no maximum: the largest one
    /// reduces and backs off without overflowing, and never comes.
    #[test]
    fn the_largest_durations_saturate() {
        assert!(reduce(Duration::MAX, 0.0) <= Duration::MAX);
        assert!(reduce(Duration::MAX, 0.5) <= Duration::MAX);
        let b = BackoffPolicy {
            initial: Duration::MAX,
            max: Duration::MAX,
            jitter: 0.0,
        };
        assert!(Instant::now().checked_add(b.delay(40)).is_none());
    }

    #[test]
    fn backoff_doubles_up_to_the_max() {
        let b = BackoffPolicy {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(1),
            jitter: 0.0,
        };
        let d: Vec<_> = (0..7).map(|n| b.delay(n).as_millis()).collect();
        assert_eq!(d, [0, 100, 200, 400, 800, 1000, 1000]);
        assert_eq!(b.delay(u32::MAX), Duration::from_secs(1));
        let j = BackoffPolicy { jitter: 0.5, ..b };
        for _ in 0..100 {
            let d = j.delay(2);
            assert!(d <= Duration::from_millis(200) && d >= Duration::from_millis(100));
        }
    }
}
