//! The executor of synchronous pool policies: a small, fixed set of threads
//! of its own, shared by every pool of the process and started on first use.
//!
//! A [`PoolPolicy`](super::PoolPolicy) may block, and nothing bounds it with
//! a timeout. It therefore never runs on a thread that other work shares
//! (the runtime's workers, its blocking pool): a policy that does not return
//! would take one of those away from every other user. Here it takes one of
//! at most [`THREADS`] threads that serve nothing else. A pool asks one
//! look at a time (single flight), so the queue holds at most one job per
//! pool; with every thread busy a pool's look waits its turn, and what
//! happens in the meantime merges into the one look that follows. A policy
//! that never returns thus keeps its own pool's looks, and, with
//! [`THREADS`] of them, those of the pools queued behind them; it keeps
//! nothing else.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

/// The most threads the executor runs at once.
pub(super) const THREADS: usize = 4;

/// How long an idle thread waits for a job before it ends.
const IDLE: Duration = Duration::from_secs(5);

type Job = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct State {
    queue: VecDeque<Job>,
    /// Threads running (busy or waiting).
    threads: usize,
    /// Threads waiting for a job.
    idle: usize,
}

pub(super) struct Executor {
    max: usize,
    state: Mutex<State>,
    ready: Condvar,
}

/// The executor of the process.
pub(super) fn shared() -> &'static Executor {
    static SHARED: OnceLock<Executor> = OnceLock::new();
    SHARED.get_or_init(|| Executor::new(THREADS))
}

impl Executor {
    pub(super) const fn new(max: usize) -> Self {
        Self {
            max,
            state: Mutex::new(State {
                queue: VecDeque::new(),
                threads: 0,
                idle: 0,
            }),
            ready: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `job`; it runs on a thread of the executor, which is started
    /// when none is free and the limit allows.
    ///
    /// # Errors
    ///
    /// The error that starting the first thread gave: with no thread the
    /// job would never run.
    pub(super) fn submit(
        &'static self,
        job: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<()> {
        let mut st = self.lock();
        st.queue.push_back(Box::new(job));
        // A waiting thread takes it, unless the jobs queued before it
        // already have every waiting thread's name on them.
        if st.idle >= st.queue.len() {
            drop(st);
            self.ready.notify_one();
            return Ok(());
        }
        if st.threads >= self.max {
            return Ok(());
        }
        st.threads += 1;
        drop(st);
        let spawned = std::thread::Builder::new()
            .name("zmux-pool-policy".into())
            .spawn(move || self.work());
        if let Err(e) = spawned {
            let mut st = self.lock();
            st.threads -= 1;
            // Another thread will find the job; with none, it never runs.
            if st.threads == 0 {
                st.queue.pop_back();
                return Err(e);
            }
        }
        Ok(())
    }

    fn work(&self) {
        let mut st = self.lock();
        loop {
            if let Some(job) = st.queue.pop_front() {
                drop(st);
                // A job catches what the policy panics with; this only keeps
                // the thread whatever else goes wrong.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                st = self.lock();
                continue;
            }
            st.idle += 1;
            let (guard, timeout) = self
                .ready
                .wait_timeout(st, IDLE)
                .unwrap_or_else(PoisonError::into_inner);
            st = guard;
            st.idle -= 1;
            if timeout.timed_out() && st.queue.is_empty() {
                st.threads -= 1;
                return;
            }
        }
    }

    #[cfg(test)]
    pub(super) fn threads(&self) -> usize {
        self.lock().threads
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::mpsc;

    fn leak(max: usize) -> &'static Executor {
        Box::leak(Box::new(Executor::new(max)))
    }

    /// With every thread held by a job that does not return, the next job
    /// waits, and runs once a thread is free; no more threads than the
    /// limit are started.
    #[test]
    fn saturated_executor_delays_without_growing() {
        let ex = leak(2);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let (started_tx, started_rx) = mpsc::channel();
        for _ in 0..2 {
            let (r, s) = (release_rx.clone(), started_tx.clone());
            ex.submit(move || {
                s.send(()).unwrap();
                let _ = r.lock().unwrap().recv();
            })
            .unwrap();
        }
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        ex.submit(move || done_tx.send(()).unwrap()).unwrap();
        assert_eq!(ex.threads(), 2);
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        release_tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        release_tx.send(()).unwrap();
    }

    /// A job that panics does not end its thread.
    #[test]
    fn panicking_job_keeps_the_thread() {
        let ex = leak(1);
        ex.submit(|| panic!("policy")).unwrap();
        let (tx, rx) = mpsc::channel();
        ex.submit(move || tx.send(()).unwrap()).unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(ex.threads(), 1);
    }
}
