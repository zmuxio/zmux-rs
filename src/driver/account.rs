//! Listener memory and suspended-session accounting. Carrier and session
//! grants commit on one live ledger. Session rounds observe only pressure
//! and suspension changes.
//!
//! The ledger and the suspended list are separate leaf locks. Accounts
//! return sessions to close after the session or listener lock is released.

use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
#[cfg(feature = "tokio")]
use std::task::Poll;
use std::time::Instant;

use crate::proto::listener::{MemoryPressure, OnMemoryPressure};
use crate::proto::memory::{Ledger, Snapshot};
use crate::proto::session::SessionCore as Core;

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
    /// Shared by session and carrier grants.
    pub(crate) ledger: Arc<Ledger>,
    /// Reads the live suspended-session limit without a session lock.
    max_suspended: OnceLock<MaxSuspended>,
    /// The hook's mailbox, with a hook.
    signal: Option<Arc<PressureSignal>>,
    state: Mutex<State<S>>,
}

/// The latest pressure change for the hook's context, and how it is woken.
/// The context reads the latest only: changes it has not seen coalesce,
/// the last state winning.
struct PressureSignal {
    /// The latest change, and the account is gone.
    latest: Mutex<(Option<MemoryPressure>, bool, u64)>,
    /// Wakes a hook thread.
    changed: Condvar,
    /// Wakes a hook task.
    waker: Mutex<Option<std::task::Waker>>,
}

impl PressureSignal {
    fn publish(&self, snapshot: Snapshot) {
        let mut latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        if latest.1 || snapshot.generation <= latest.2 {
            return;
        }
        latest.0 = Some(MemoryPressure {
            used: snapshot.used,
            budget: snapshot.limit.unwrap_or(0),
            active: snapshot.pressure,
        });
        latest.2 = snapshot.generation;
        drop(latest);
        self.wake();
    }

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
    /// Suspended sessions, by when they were suspended (a session that
    /// resumed or ended is dropped when met).
    suspended: Vec<(Instant, Weak<S>)>,
}

impl<S> Account<S> {
    /// An account; with a hook, its context is started: a task on the
    /// current tokio runtime (`None` outside one) or a thread (`None` when
    /// it cannot be started).
    pub(crate) fn new(
        limits: crate::proto::listener::ListenerLimits,
        ingress: u64,
        hook: Option<OnMemoryPressure>,
        context: HookContext,
    ) -> Option<Arc<Self>> {
        let signal = match hook {
            None => None,
            Some(hook) => {
                let signal = Arc::new(PressureSignal {
                    latest: Mutex::new((None, false, 0)),
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
        let notify = signal.as_ref().map(|signal| {
            let signal = Arc::downgrade(signal);
            Box::new(move |snapshot| {
                if let Some(signal) = signal.upgrade() {
                    signal.publish(snapshot);
                }
            }) as Box<dyn Fn(Snapshot) + Send + Sync>
        });
        Some(Arc::new(Self {
            ledger: Ledger::for_listener(
                limits.memory_budget,
                notify,
                ingress,
                limits.session_receive_growth_limit,
            ),
            max_suspended: OnceLock::new(),
            signal,
            state: Mutex::new(State {
                suspended: Vec::new(),
            }),
        }))
    }

    /// Under pressure, new sessions are refused and only joins that resume
    /// a session pass.
    pub(crate) fn pressure(&self) -> bool {
        self.ledger.pressure()
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

    pub(super) fn evict_under_pressure(&self) -> Vec<Arc<S>> {
        let mut close = Vec::new();
        if self.pressure() {
            AccountLink::enforce(&mut self.lock(), usize::MAX, true, &mut close);
        }
        close
    }

    pub(crate) fn set_memory_limits(
        &self,
        limits: crate::proto::listener::ListenerLimits,
    ) -> Result<Vec<Arc<S>>, crate::InvalidConfig> {
        if !self.ledger.set_limits(
            limits.memory_budget,
            Some(limits.session_receive_growth_limit),
        ) {
            return Err(crate::InvalidConfig::new(
                "memory_budget",
                "below outstanding memory reservations",
            ));
        }
        Ok(self.evict_under_pressure())
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
    suspended: bool,
    /// The pressure last handed to the core.
    pressure: bool,
}

impl<S> AccountLink<S> {
    pub(super) fn new(
        account: Arc<Account<S>>,
        registration: Option<super::setup::SessionRegistration<S>>,
    ) -> Self {
        Self {
            _registration: registration,
            account,
            suspended: false,
            pressure: false,
        }
    }

    /// Reconciles suspension and pressure without measuring session buffers.
    pub(crate) fn report(&mut self, core: &mut Core, me: &Arc<S>, out: &mut Evictions<S>) {
        let suspended = core.suspended_since();
        let a = &self.account;
        let pressure = a.ledger.pressure();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    /// A lowered `max_suspended` gives the longest-suspended sessions
    /// beyond it back for closing.
    #[cfg(feature = "tokio")]
    #[test]
    fn a_lowered_max_suspended_trims_the_oldest() {
        let limits = crate::proto::listener::ListenerLimits {
            memory_budget: None,
            ..crate::proto::listener::ListenerLimits::default()
        };
        let account = Account::<u8>::new(limits, 0, None, HookContext::Task).expect("no hook");
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
