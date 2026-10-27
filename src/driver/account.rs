//! A listener's memory budget and suspended-session limit (RESUME.md Section
//! 9), kept up to date by its sessions as their
//! charges change: a session reports
//! its charge from its own task's rounds, at most every [`CHARGE_INTERVAL`],
//! and takes its allowance and the budget's pressure in the same step, so a
//! quiet session costs the listener nothing and no task visits every
//! session.
//!
//! The account is a leaf: its atomics, and one lock that is never held
//! while any other is taken (the suspended sessions it closes are closed
//! after the session's own lock is released).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::Poll;
use std::time::{Duration, Instant};

use atomic_waker::AtomicWaker;

use crate::proto::listener::{MemoryBudget, MemoryPressure, OnMemoryPressure};
use crate::proto::session::SessionCore as Core;

/// How often an active session reports its charge (the listener's old
/// visiting period, as an upper bound).
const CHARGE_INTERVAL: Duration = Duration::from_millis(100);

/// The listener's side.
pub(crate) struct Account<S> {
    /// The memory budget in bytes (0: unlimited).
    budget_bytes: u64,
    max_suspended: usize,
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

/// The latest pressure change for the hook's task, and its waker. The
/// task reads the latest only: changes it has not seen coalesce, the last
/// state winning.
struct PressureSignal {
    latest: Mutex<Option<MemoryPressure>>,
    waker: AtomicWaker,
    closed: AtomicBool,
}

/// The listener's hook context: calls `on_memory_pressure` for each change,
/// in order, until the account is gone.
async fn run_pressure_hook(signal: Arc<PressureSignal>, hook: OnMemoryPressure) {
    // No pressure to begin with.
    let mut last = false;
    loop {
        let next = std::future::poll_fn(|cx| {
            signal.waker.register(cx.waker());
            if let Some(p) = signal
                .latest
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                return Poll::Ready(Some(p));
            }
            if signal.closed.load(Ordering::Acquire) {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await;
        let Some(p) = next else {
            return;
        };
        // Changes that cancelled out before the task ran are not reported.
        if last == p.active {
            continue;
        }
        last = p.active;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook.0.as_ref()(p)));
    }
}

impl<S> Drop for Account<S> {
    fn drop(&mut self) {
        if let Some(s) = &self.signal {
            s.closed.store(true, Ordering::Release);
            s.waker.wake();
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
    /// An account; with a hook, its task is started (inside a tokio
    /// runtime).
    pub(crate) fn new(
        budget_bytes: u64,
        max_suspended: usize,
        hook: Option<OnMemoryPressure>,
    ) -> Arc<Self> {
        let signal = hook.map(|hook| {
            let signal = Arc::new(PressureSignal {
                latest: Mutex::new(None),
                waker: AtomicWaker::new(),
                closed: AtomicBool::new(false),
            });
            tokio::spawn(run_pressure_hook(signal.clone(), hook));
            signal
        });
        Arc::new(Self {
            budget_bytes,
            max_suspended,
            used: AtomicU64::new(0),
            growing: AtomicU64::new(0),
            pressure: AtomicBool::new(false),
            signal,
            state: Mutex::new(State {
                budget: MemoryBudget::new(budget_bytes),
                suspended: Vec::new(),
            }),
        })
    }

    /// The sessions are above the budget: new sessions are refused, and
    /// only joins that resume a session pass.
    pub(crate) fn pressure(&self) -> bool {
        self.pressure.load(Ordering::Acquire)
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
        if self.budget_bytes == 0 {
            return;
        }
        // The sum read under the lock: the last update decides.
        let mut st = self.lock();
        let used = self.used.load(Ordering::Acquire);
        let Some(on) = st.budget.update(used) else {
            return;
        };
        self.pressure.store(on, Ordering::Release);
        // Stored under the lock, so that the last change is the latest;
        // the hook's task is woken after it.
        let Some(s) = &self.signal else {
            return;
        };
        *s.latest.lock().unwrap_or_else(PoisonError::into_inner) = Some(MemoryPressure {
            used,
            budget: self.budget_bytes,
            active: on,
        });
        drop(st);
        s.waker.wake();
    }
}

/// A session's link to its listener's account, under the session's lock.
pub(crate) struct AccountLink<S> {
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
    pub(crate) fn new(account: Arc<Account<S>>) -> Self {
        Self {
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
    /// of them under pressure) go to `close`, to be closed once this
    /// session's lock is released.
    pub(crate) fn report(
        &mut self,
        core: &mut Core,
        me: &Arc<S>,
        now: Instant,
        close: &mut Vec<Arc<S>>,
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
        if a.budget_bytes > 0 {
            // What is left is shared between the sessions that grew, so
            // that sessions growing at once do not each take all of it.
            let used = a.used.load(Ordering::Acquire);
            let growing = a.growing.load(Ordering::Acquire).max(1);
            core.set_memory_allowance(Some(a.budget_bytes.saturating_sub(used) / growing));
        }
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
        if started.is_some() || pressure_on {
            Self::enforce(&mut st, a.max_suspended, pressure, close);
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
    use crate::proto::session::{Config, RoleConfig};

    /// A report the interval holds back is due at the end of the interval,
    /// so that a session that goes quiet still reports its last charge.
    #[test]
    fn a_report_held_back_by_the_interval_is_due_after_it() {
        let t0 = Instant::now();
        let mut core = Core::new(Config::default(), RoleConfig::Initiator, None, t0).unwrap();
        let account = Account::<()>::new(1 << 20, 4, None);
        let me = Arc::new(());
        let mut link = AccountLink::new(account.clone());
        let mut close = Vec::new();
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
}
