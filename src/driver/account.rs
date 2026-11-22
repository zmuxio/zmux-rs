//! A listener's memory budget and suspended-session limit, kept up to date
//! by its sessions as their charges change: a session reports its charge
//! from its own task's rounds, at most every [`CHARGE_INTERVAL`], and takes
//! its allowance and the budget's pressure in the same step, so a quiet
//! session costs the listener nothing and no task visits every session.
//!
//! The account is a leaf: its atomics, and one lock that is never held
//! while any other is taken (the suspended sessions it closes are closed
//! after the session's own lock is released).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
#[cfg(feature = "tokio")]
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::proto::listener::{MemoryBudget, MemoryPressure, OnMemoryPressure};
use crate::proto::session::SessionCore as Core;

/// How often an active session reports its charge (the listener's old
/// visiting period, as an upper bound).
const CHARGE_INTERVAL: Duration = Duration::from_millis(100);

/// [`Account::budget`]'s encoding of no budget.
const UNLIMITED: u64 = u64::MAX;

/// The reader of a listener's live `max_suspended`.
type MaxSuspended = Box<dyn Fn() -> Option<usize> + Send + Sync>;

/// Suspended sessions a session's report picked for closing, and whether
/// the suspended limit is to be applied, both done once the session's lock
/// is released ([`Evictions::take`]).
pub(crate) struct Evictions<S> {
    close: Vec<Arc<S>>,
    trim: Option<Arc<Account<S>>>,
}

impl<S> Evictions<S> {
    pub(crate) fn new() -> Self {
        Self {
            close: Vec::new(),
            trim: None,
        }
    }

    #[cfg(feature = "blocking")]
    pub(crate) fn is_empty(&self) -> bool {
        self.close.is_empty() && self.trim.is_none()
    }

    /// The sessions to close: those picked, and the longest-suspended ones
    /// beyond the listener's limit. Called without the session's lock.
    pub(crate) fn take(&mut self) -> Vec<Arc<S>> {
        let mut close = std::mem::take(&mut self.close);
        if let Some(a) = self.trim.take() {
            close.extend(a.trim());
        }
        close
    }
}

/// The listener's side.
pub(crate) struct Account<S> {
    /// The listener's live `memory_budget`, read without a lock by every
    /// session's report ([`UNLIMITED`]: none): the enforcement value of the
    /// core's limits, written with them under the listener's lock
    /// ([`Account::set_budget`]).
    budget: AtomicU64,
    /// Reads the listener's live `max_suspended` from its core (`None`
    /// once the listener is gone); it takes the listener's lock, so it is
    /// called with no session lock held ([`Evictions::take`]).
    max_suspended: OnceLock<MaxSuspended>,
    /// The sessions' charges, summed.
    used: AtomicU64,
    /// Sessions that grew since their last allowance (at least one share).
    growing: AtomicU64,
    /// Above the budget (with its hysteresis).
    pressure: AtomicBool,
    /// The hook's mailbox, with a hook.
    signal: Option<Arc<PressureSignal>>,
    state: Mutex<State<S>>,
}

/// The latest pressure change for the hook's context, and how it is woken.
/// The context reads the latest only: changes it has not seen coalesce,
/// the last state winning.
struct PressureSignal {
    /// The latest change, and the account is gone.
    latest: Mutex<(Option<MemoryPressure>, bool)>,
    /// Wakes a hook thread.
    changed: Condvar,
    /// Wakes a hook task.
    waker: Mutex<Option<std::task::Waker>>,
}

impl PressureSignal {
    fn wake(&self) {
        self.changed.notify_all();
        if let Some(w) = self
            .waker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            w.wake();
        }
    }

    /// The next change, if any; `Err` once the account is gone.
    #[cfg(feature = "tokio")]
    fn take(&self) -> Result<Option<MemoryPressure>, ()> {
        let mut l = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        match l.0.take() {
            Some(p) => Ok(Some(p)),
            None if l.1 => Err(()),
            None => Ok(None),
        }
    }
}

/// Where the hook runs: a task of the tokio runtime current at the
/// listener's creation, or a thread of its own (the std driver).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HookContext {
    #[cfg(feature = "tokio")]
    Task,
    #[cfg(feature = "blocking")]
    Thread,
}

/// Tells `hook` a change, in order, unless it cancels the last one.
fn tell(hook: &OnMemoryPressure, last: &mut bool, p: MemoryPressure) {
    // Changes that cancelled out before the context ran are not reported.
    if *last == p.active {
        return;
    }
    *last = p.active;
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook.0.as_ref()(p)));
}

/// The listener's hook task: calls `on_memory_pressure` for each change,
/// in order, until the account is gone.
#[cfg(feature = "tokio")]
async fn run_pressure_task(signal: Arc<PressureSignal>, hook: OnMemoryPressure) {
    let mut last = false;
    loop {
        let next = std::future::poll_fn(|cx| {
            *signal.waker.lock().unwrap_or_else(PoisonError::into_inner) = Some(cx.waker().clone());
            match signal.take() {
                Ok(Some(p)) => Poll::Ready(Some(p)),
                Ok(None) => Poll::Pending,
                Err(()) => Poll::Ready(None),
            }
        })
        .await;
        let Some(p) = next else {
            return;
        };
        tell(&hook, &mut last, p);
    }
}

/// The listener's hook thread (the std driver), as the task.
#[cfg(feature = "blocking")]
fn run_pressure_thread(signal: &PressureSignal, hook: &OnMemoryPressure) {
    let mut last = false;
    loop {
        let p = {
            let mut l = signal.latest.lock().unwrap_or_else(PoisonError::into_inner);
            loop {
                if let Some(p) = l.0.take() {
                    break p;
                }
                if l.1 {
                    return;
                }
                l = signal
                    .changed
                    .wait(l)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        };
        tell(hook, &mut last, p);
    }
}

impl<S> Drop for Account<S> {
    fn drop(&mut self) {
        if let Some(s) = &self.signal {
            s.latest.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
            s.wake();
        }
    }
}

struct State<S> {
    budget: MemoryBudget,
    /// Suspended sessions, by when they were suspended (a session that
    /// resumed or ended is dropped when met).
    suspended: Vec<(Instant, Weak<S>)>,
}

impl<S> Account<S> {
    /// An account; with a hook, its context is started: a task on the
    /// current tokio runtime (`None` outside one) or a thread (`None` when
    /// it cannot be started).
    pub(crate) fn new(
        budget_bytes: Option<u64>,
        hook: Option<OnMemoryPressure>,
        context: HookContext,
    ) -> Option<Arc<Self>> {
        let signal = match hook {
            None => None,
            Some(hook) => {
                let signal = Arc::new(PressureSignal {
                    latest: Mutex::new((None, false)),
                    changed: Condvar::new(),
                    waker: Mutex::new(None),
                });
                match context {
                    #[cfg(feature = "tokio")]
                    HookContext::Task => {
                        let rt = tokio::runtime::Handle::try_current().ok()?;
                        rt.spawn(run_pressure_task(signal.clone(), hook));
                    }
                    #[cfg(feature = "blocking")]
                    HookContext::Thread => {
                        let s = signal.clone();
                        std::thread::Builder::new()
                            .name("zmux-pressure".into())
                            .spawn(move || run_pressure_thread(&s, &hook))
                            .ok()?;
                    }
                }
                Some(signal)
            }
        };
        Some(Arc::new(Self {
            budget: AtomicU64::new(budget_bytes.unwrap_or(UNLIMITED)),
            max_suspended: OnceLock::new(),
            used: AtomicU64::new(0),
            growing: AtomicU64::new(0),
            pressure: AtomicBool::new(false),
            signal,
            state: Mutex::new(State {
                budget: MemoryBudget::new(),
                suspended: Vec::new(),
            }),
        }))
    }

    /// The sessions are above the budget: new sessions are refused, and
    /// only joins that resume a session pass.
    pub(crate) fn pressure(&self) -> bool {
        self.pressure.load(Ordering::Acquire)
    }

    /// Binds the reader of the listener's live `max_suspended`, once.
    pub(crate) fn bind_max_suspended(&self, read: MaxSuspended) {
        let _ = self.max_suspended.set(read);
    }

    /// The longest-suspended sessions beyond `max`, for the caller to
    /// close without any lock held.
    pub(crate) fn trim_to(&self, max: usize) -> Vec<Arc<S>> {
        let mut close = Vec::new();
        AccountLink::enforce(&mut self.lock(), max, false, &mut close);
        close
    }

    /// [`Account::trim_to`] the listener's live `max_suspended`: takes the
    /// listener's lock, then this one.
    fn trim(&self) -> Vec<Arc<S>> {
        match self.max_suspended.get().and_then(|read| read()) {
            Some(max) => self.trim_to(max),
            None => Vec::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State<S>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A session's charge went from `old` to `new`: the sum, and the
    /// pressure, follow.
    pub(crate) fn charge(&self, new: u64, old: u64) {
        if new == old {
            return;
        }
        if new > old {
            self.used.fetch_add(new - old, Ordering::AcqRel);
        } else {
            self.used.fetch_sub(old - new, Ordering::AcqRel);
        }
        if self.budget().is_none() && !self.pressure() {
            return;
        }
        // The sum and the budget read under the lock: the last update
        // decides.
        let st = self.lock();
        self.update(st);
    }

    /// The budget in effect (`None`: unlimited).
    fn budget(&self) -> Option<u64> {
        Some(self.budget.load(Ordering::Acquire)).filter(|&b| b != UNLIMITED)
    }

    /// Follows the sum and the budget with the pressure, telling the hook
    /// of a change; the guard is released before the hook is woken.
    fn update(&self, mut st: std::sync::MutexGuard<'_, State<S>>) -> Option<bool> {
        let used = self.used.load(Ordering::Acquire);
        let budget = self.budget();
        let on = st.budget.update(used, budget)?;
        self.pressure.store(on, Ordering::Release);
        // Stored under the lock, so that the last change is the latest;
        // the hook's task is woken after it.
        if let Some(s) = &self.signal {
            s.latest.lock().unwrap_or_else(PoisonError::into_inner).0 = Some(MemoryPressure {
                used,
                budget: budget.unwrap_or(0),
                active: on,
            });
            drop(st);
            s.wake();
        }
        Some(on)
    }

    /// A new `memory_budget`, applied at once as if the sum crossed it:
    /// pressure that starts closes every suspended session (returned, for
    /// the caller to close without any lock held).
    pub(crate) fn set_budget(&self, budget: Option<u64>) -> Vec<Arc<S>> {
        let st = self.lock();
        self.budget
            .store(budget.unwrap_or(UNLIMITED), Ordering::Release);
        let mut close = Vec::new();
        if self.update(st) == Some(true) {
            AccountLink::enforce(&mut self.lock(), usize::MAX, true, &mut close);
        }
        close
    }
}

/// A session's link to its listener's account, under the session's lock.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent state of the link, not one state machine"
)]
pub(crate) struct AccountLink<S> {
    _registration: Option<super::setup::SessionRegistration<S>>,
    account: Arc<Account<S>>,
    /// What this session last added to the sum.
    charge: u64,
    growing: bool,
    suspended: bool,
    /// The pressure last handed to the core.
    pressure: bool,
    /// The last report.
    at: Option<Instant>,
    /// A round skipped a report within [`CHARGE_INTERVAL`] of the last:
    /// one is due then ([`AccountLink::due`]), so that a session that went
    /// quiet does not leave its charge behind.
    dirty: bool,
}

impl<S> AccountLink<S> {
    pub(super) fn new(
        account: Arc<Account<S>>,
        registration: Option<super::setup::SessionRegistration<S>>,
    ) -> Self {
        Self {
            _registration: registration,
            account,
            charge: 0,
            growing: false,
            suspended: false,
            pressure: false,
            at: None,
            dirty: false,
        }
    }

    /// When a report skipped by the interval is due: a deadline of the
    /// session task.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.at
            .filter(|_| self.dirty)
            .and_then(|t| t.checked_add(CHARGE_INTERVAL))
    }

    /// Reports the session's charge, at most every [`CHARGE_INTERVAL`]
    /// (`force`: now, for a suspension), and hands the core its allowance
    /// and the budget's pressure. Suspended sessions beyond the limit (all
    /// of them under pressure) go to `out`, to be closed once this
    /// session's lock is released.
    pub(crate) fn report(
        &mut self,
        core: &mut Core,
        me: &Arc<S>,
        now: Instant,
        out: &mut Evictions<S>,
    ) {
        let suspended = core.suspended_since();
        let force = suspended.is_some() != self.suspended;
        if !force
            && self
                .at
                .is_some_and(|t| now.saturating_duration_since(t) < CHARGE_INTERVAL)
        {
            self.dirty = true;
            return;
        }
        self.at = Some(now);
        self.dirty = false;
        let a = &self.account;
        let charge = core.held_bytes() + core.memory_usage() as u64 + core.window_growth();
        a.charge(charge, self.charge);
        self.charge = charge;
        let grew = core.grew_since_allowance();
        if grew != self.growing {
            if grew {
                a.growing.fetch_add(1, Ordering::AcqRel);
            } else {
                a.growing.fetch_sub(1, Ordering::AcqRel);
            }
            self.growing = grew;
        }
        // What is left is shared between the sessions that grew, so that
        // sessions growing at once do not each take all of it; the
        // listener's budget replaces the session's own, unlimited too.
        let used = a.used.load(Ordering::Acquire);
        let growing = a.growing.load(Ordering::Acquire).max(1);
        core.set_memory_allowance(a.budget().map(|b| b.saturating_sub(used) / growing));
        let pressure = a.pressure();
        let pressure_on = pressure && !self.pressure;
        if pressure != self.pressure {
            core.set_memory_pressure(pressure);
            self.pressure = pressure;
        }
        let started = suspended.filter(|_| !self.suspended);
        let resumed = suspended.is_none() && self.suspended;
        self.suspended = suspended.is_some();
        // The suspended list changes only with a suspension, a resumption
        // or the pressure turning on: other reports leave it alone.
        if started.is_none() && !resumed && !pressure_on {
            return;
        }
        let mut st = a.lock();
        let mine = |w: &Weak<S>| std::ptr::eq(w.as_ptr(), Arc::as_ptr(me));
        if resumed {
            st.suspended.retain(|(_, w)| !mine(w));
        }
        if let Some(t) = started {
            // Kept in suspension order.
            let i = st.suspended.partition_point(|&(u, _)| u <= t);
            st.suspended.insert(i, (t, Arc::downgrade(me)));
        }
        if pressure_on {
            Self::enforce(&mut st, usize::MAX, true, &mut out.close);
        } else if started.is_some() {
            // The limit is the listener's, read without this session's lock.
            out.trim = Some(a.clone());
        }
    }

    /// Drops the sessions that ended and picks the oldest suspended ones
    /// beyond the limit (all of them under pressure) for closing. A
    /// session that resumed left the list at its own report.
    fn enforce(st: &mut State<S>, max: usize, pressure: bool, close: &mut Vec<Arc<S>>) {
        st.suspended.retain(|(_, w)| w.strong_count() > 0);
        let excess = if pressure {
            st.suspended.len()
        } else {
            st.suspended.len().saturating_sub(max)
        };
        for (_, w) in st.suspended.drain(..excess) {
            if let Some(s) = w.upgrade() {
                close.push(s);
            }
        }
    }

    /// The session ended: its charge leaves the sum.
    pub(crate) fn leave(&mut self) {
        let a = &self.account;
        a.charge(0, std::mem::take(&mut self.charge));
        if std::mem::take(&mut self.growing) {
            a.growing.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl<S> Drop for AccountLink<S> {
    fn drop(&mut self) {
        self.leave();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::session::{Config, Role};

    /// A report the interval holds back is due at the end of the interval,
    /// so that a session that goes quiet still reports its last charge.
    #[cfg(feature = "tokio")]
    #[test]
    fn a_report_held_back_by_the_interval_is_due_after_it() {
        let t0 = Instant::now();
        let mut core = Core::new(Config::default(), Role::Client, None, t0).unwrap();
        let account = Account::<()>::new(Some(1 << 20), None, HookContext::Task).expect("no hook");
        let me = Arc::new(());
        let mut link = AccountLink::new(account.clone(), None);
        let mut close = Evictions::new();
        link.report(&mut core, &me, t0, &mut close);
        assert!(link.due().is_none());
        let used = account.used.load(Ordering::Acquire);
        assert!(used > 0);
        link.report(&mut core, &me, t0 + Duration::from_millis(10), &mut close);
        assert_eq!(link.due(), Some(t0 + CHARGE_INTERVAL));
        link.report(&mut core, &me, t0 + CHARGE_INTERVAL, &mut close);
        assert!(link.due().is_none());
        drop(link);
        assert_eq!(account.used.load(Ordering::Acquire), 0, "the charge left");
        assert!(close.is_empty());
    }

    /// A lowered `max_suspended` gives the longest-suspended sessions
    /// beyond it back for closing.
    #[cfg(feature = "tokio")]
    #[test]
    fn a_lowered_max_suspended_trims_the_oldest() {
        let account = Account::<u8>::new(None, None, HookContext::Task).expect("no hook");
        let t0 = Instant::now();
        let s: Vec<_> = (0..3u8).map(Arc::new).collect();
        account.lock().suspended = s
            .iter()
            .enumerate()
            .map(|(i, x)| (t0 + Duration::from_secs(i as u64), Arc::downgrade(x)))
            .collect();
        assert_eq!(account.trim_to(1), vec![s[0].clone(), s[1].clone()]);
        assert_eq!(account.lock().suspended.len(), 1);
    }
}
