//! Short waits with the operating system's timer precision. tokio's timer
//! counts in milliseconds and fires at the first tick at or after a
//! deadline, so a wait it serves ends up to a millisecond or more late:
//! shaping delays and pacing of a few hundred microseconds would come out
//! systematically long. Deadlines a little ahead are served by one thread
//! of the process instead, which sleeps on a condition variable until the
//! earliest of them (nanosecond timeouts) and wakes their tasks.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Deadlines up to this far ahead are served here; later ones by tokio's
/// timer, whose lateness is small next to them.
pub(crate) const HORIZON: Duration = Duration::from_millis(50);

struct Timers {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    waits: BTreeMap<(Instant, u64), Waker>,
    next: u64,
}

fn timers() -> &'static Timers {
    static TIMERS: OnceLock<&'static Timers> = OnceLock::new();
    TIMERS.get_or_init(|| {
        let t: &'static Timers = Box::leak(Box::new(Timers {
            state: Mutex::default(),
            changed: Condvar::new(),
        }));
        // Without the thread, waits are tokio's ([`available`]).
        let started = std::thread::Builder::new()
            .name("zmux-timer".into())
            .spawn(move || run(t))
            .is_ok();
        RUNNING.store(started, Ordering::Release);
        t
    })
}

static RUNNING: AtomicBool = AtomicBool::new(false);

/// Whether short waits are served here: the timer thread runs (it starts
/// with the first call), and tokio's clock is the system's. A paused tokio
/// clock (the simulations of `test-util`) stands still or jumps ahead of
/// the system's, and only tokio's timer advances it, so its waits stay
/// tokio's.
pub(crate) fn available() -> bool {
    let virtual_now = tokio::time::Instant::now().into_std();
    let real_now = Instant::now();
    if virtual_now > real_now || real_now - virtual_now > Duration::from_micros(100) {
        return false;
    }
    timers();
    RUNNING.load(Ordering::Acquire)
}

fn run(t: &'static Timers) {
    let mut st = t.state.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        let now = Instant::now();
        let mut due = Vec::new();
        while let Some(entry) = st.waits.first_entry() {
            if entry.key().0 > now {
                break;
            }
            due.push(entry.remove());
        }
        if !due.is_empty() {
            drop(st);
            for w in due {
                w.wake();
            }
            st = t.state.lock().unwrap_or_else(PoisonError::into_inner);
            continue;
        }
        st = match st.waits.keys().next().map(|k| k.0) {
            Some(d) => {
                t.changed
                    .wait_timeout(st, d.saturating_duration_since(now))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
            None => t.changed.wait(st).unwrap_or_else(PoisonError::into_inner),
        };
    }
}

/// A wait until `deadline` served by the timer thread.
pub(crate) struct Sleep {
    deadline: Instant,
    key: Option<(Instant, u64)>,
}

impl Sleep {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            key: None,
        }
    }

    fn leave(&mut self) {
        if let Some(k) = self.key.take() {
            let t = timers();
            t.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .waits
                .remove(&k);
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if Instant::now() >= this.deadline {
            this.leave();
            return Poll::Ready(());
        }
        let t = timers();
        let mut st = t.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(w) = this.key.as_ref().and_then(|k| st.waits.get_mut(k)) {
            if !w.will_wake(cx.waker()) {
                w.clone_from(cx.waker());
            }
            return Poll::Pending;
        }
        // Not registered, or woken and taken out: (re-)register.
        let id = st.next;
        st.next += 1;
        let key = (this.deadline, id);
        let earliest = st.waits.keys().next().is_none_or(|k| key < *k);
        st.waits.insert(key, cx.waker().clone());
        this.key = Some(key);
        drop(st);
        if earliest {
            t.changed.notify_one();
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        self.leave();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::task::Wake;

    /// Reports when, and on which thread, it was woken.
    struct Probe {
        i: usize,
        tx: Mutex<mpsc::Sender<(usize, Instant, Option<String>)>>,
    }

    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            let name = std::thread::current().name().map(str::to_owned);
            let tx = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = tx.send((self.i, Instant::now(), name));
        }
    }

    // How late a wait ends is the operating system's scheduling of the
    // timer thread, which a loaded host stretches without bound: the
    // assertions are what this module decides. Each wait is woken by the
    // timer thread itself (not by a millisecond timer), never before its
    // deadline, once, and in the order of the deadlines.
    #[test]
    fn waits_are_woken_by_the_timer_thread_in_deadline_order() {
        let n = 50;
        let start = Instant::now() + Duration::from_millis(100);
        // Registered out of order: deadlines 37 µs apart, interleaved.
        let order: Vec<usize> = (0..n).map(|k| (k * 17) % n).collect();
        let (tx, rx) = mpsc::channel();
        let mut sleeps = Vec::new();
        let mut expected = Vec::new();
        for &i in &order {
            let deadline = start + Duration::from_micros(37 * i as u64);
            let mut s = Box::pin(Sleep::new(deadline));
            let waker = Waker::from(Arc::new(Probe {
                i,
                tx: Mutex::new(tx.clone()),
            }));
            let mut cx = Context::from_waker(&waker);
            if s.as_mut().poll(&mut cx).is_ready() {
                // Registration took longer than the lead (a loaded host).
                assert!(Instant::now() >= deadline);
                continue;
            }
            expected.push(i);
            sleeps.push(s);
        }
        drop(tx);
        let mut woken = Vec::new();
        expected.sort_unstable();
        for _ in 0..expected.len() {
            let (i, at, thread) = rx
                .recv_timeout(Duration::from_secs(60))
                .expect("a wait was not woken");
            assert_eq!(thread.as_deref(), Some("zmux-timer"));
            let deadline = start + Duration::from_micros(37 * i as u64);
            assert!(at >= deadline, "wait {i} woken before its deadline");
            woken.push(i);
        }
        assert_eq!(woken, expected);
        // Every wait is over now, and was woken once.
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        for s in &mut sleeps {
            assert!(s.as_mut().poll(&mut cx).is_ready());
        }
        drop(sleeps);
        assert!(rx.recv_timeout(Duration::from_millis(10)).is_err());
    }
}
