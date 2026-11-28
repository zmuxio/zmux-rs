//! The session timers of the std driver, on one thread of the process.
//!
//! Each blocking session has a timer task: when it runs it fires the core's
//! timers, reports to the listener's account, starts the hook thread and,
//! after the session closed, ends the carriers; it says when it wants to run
//! next. One thread runs the tasks of every session in the order of their
//! deadlines, so a session costs no thread for its timers. A task does what
//! the session's lock allows and never waits for anything: it must not
//! block, since it holds the thread that every other session's timers
//! share.
//!
//! A task's waker (the one it registers in its session's state) makes it run
//! as soon as possible; a wake-up that comes while the task runs makes it
//! run again after, so none is lost.

use std::collections::BTreeMap;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::{Wake, Waker};
use std::time::Instant;

use super::context::DriverThread;

/// What a task asks for after it ran.
pub(crate) enum Next {
    /// Run again at this time (or earlier, when woken).
    At(Instant),
    /// Run again only when woken.
    Idle,
    /// Never again.
    Done,
}

type Run = Box<dyn FnMut(&Waker) -> Next + Send>;

/// A timer task.
pub(crate) struct Task {
    run: Mutex<Run>,
    state: Mutex<TaskState>,
}

#[derive(Default)]
struct TaskState {
    /// Its place in the queue.
    key: Option<(Instant, u64)>,
    running: bool,
    /// Woken while running.
    again: bool,
    done: bool,
}

#[derive(Default)]
struct Queue {
    entries: BTreeMap<(Instant, u64), Arc<Task>>,
    next: u64,
}

struct Timers {
    queue: Mutex<Queue>,
    changed: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn timers() -> io::Result<&'static Timers> {
    static TIMERS: OnceLock<io::Result<&'static Timers>> = OnceLock::new();
    TIMERS
        .get_or_init(|| {
            let t: &'static Timers = Box::leak(Box::new(Timers {
                queue: Mutex::default(),
                changed: Condvar::new(),
            }));
            std::thread::Builder::new()
                .name("zmux-session-timer".into())
                .spawn(move || serve(t))
                .map(|_| t)
        })
        .as_ref()
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
        .copied()
}

impl Timers {
    /// Puts `task` in the queue at `at`, in place of its entry.
    fn place(&self, q: &mut Queue, task: &Arc<Task>, st: &mut TaskState, at: Instant) {
        if let Some(k) = st.key.take() {
            q.entries.remove(&k);
        }
        let key = (at, q.next);
        q.next += 1;
        let earliest = q.entries.keys().next().is_none_or(|k| key < *k);
        q.entries.insert(key, task.clone());
        st.key = Some(key);
        if earliest {
            self.changed.notify_one();
        }
    }
}

/// Starts a task: it runs at once, then as it asks. It gets its own waker,
/// to register wherever it is to be woken from.
///
/// # Errors
///
/// The timer thread could not be started.
pub(crate) fn spawn(run: impl FnMut(&Waker) -> Next + Send + 'static) -> io::Result<()> {
    let t = timers()?;
    let task = Arc::new(Task {
        run: Mutex::new(Box::new(run)),
        state: Mutex::default(),
    });
    let mut q = lock(&t.queue);
    let mut st = lock(&task.state);
    t.place(&mut q, &task, &mut st, Instant::now());
    Ok(())
}

impl Wake for Task {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // A task exists only after the thread started.
        let Ok(t) = timers() else { return };
        let mut q = lock(&t.queue);
        let mut st = lock(&self.state);
        if st.done {
            return;
        }
        if st.running {
            st.again = true;
        } else {
            t.place(&mut q, self, &mut st, Instant::now());
        }
    }
}

fn serve(t: &'static Timers) {
    let _driver = DriverThread::enter_process_wide();
    let mut q = lock(&t.queue);
    loop {
        let now = Instant::now();
        let Some(entry) = q.entries.first_entry().filter(|e| e.key().0 <= now) else {
            q = match q.entries.keys().next().map(|k| k.0) {
                Some(at) => {
                    t.changed
                        .wait_timeout(q, at.saturating_duration_since(now))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => t.changed.wait(q).unwrap_or_else(PoisonError::into_inner),
            };
            continue;
        };
        let task = entry.remove();
        {
            let mut st = lock(&task.state);
            st.key = None;
            st.running = true;
            st.again = false;
        }
        drop(q);
        let me = Waker::from(task.clone());
        // A panic of a task ends that task, not the thread that every
        // session's timers share.
        let next = catch_unwind(AssertUnwindSafe(|| {
            let mut run = lock(&task.run);
            run(&me)
        }))
        .unwrap_or(Next::Done);
        drop(me);
        q = lock(&t.queue);
        let mut st = lock(&task.state);
        st.running = false;
        if matches!(next, Next::Done) {
            st.done = true;
            // What the task holds goes now.
            drop(st);
            drop(q);
            *lock(&task.run) = Box::new(|_| Next::Done);
            q = lock(&t.queue);
        } else if st.again {
            t.place(&mut q, &task, &mut st, Instant::now());
        } else if let Next::At(at) = next {
            t.place(&mut q, &task, &mut st, at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Every task of every session runs on the one thread; a task runs at
    /// its time, not before, and a task that is woken runs at once.
    #[test]
    fn tasks_run_on_one_thread_in_their_time() {
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        for i in 0..8u32 {
            let tx = tx.clone();
            let at = start + Duration::from_millis(20 * u64::from(8 - i));
            let mut ran = false;
            spawn(move |_| {
                if !ran {
                    ran = true;
                    return Next::At(at);
                }
                tx.send((i, Instant::now() >= at, std::thread::current().id()))
                    .unwrap();
                Next::Done
            })
            .unwrap();
        }
        let got: Vec<_> = (0..8)
            .map(|_| rx.recv_timeout(Duration::from_secs(10)).unwrap())
            .collect();
        // In the order of their deadlines.
        assert_eq!(
            got.iter().map(|g| g.0).collect::<Vec<_>>(),
            [7, 6, 5, 4, 3, 2, 1, 0]
        );
        assert!(got.iter().all(|g| g.1));
        assert!(got.iter().all(|g| g.2 == got[0].2));
    }

    /// An idle task runs when woken; a wake-up while it runs runs it again.
    #[test]
    fn a_wake_up_is_never_lost() {
        let (tx, rx) = mpsc::channel();
        let (wtx, wrx) = mpsc::channel::<Waker>();
        let (ready, second_run_finished) = mpsc::channel();
        let mut ready = Some(ready);
        let mut runs = 0u32;
        spawn(move |me| {
            runs += 1;
            match runs {
                1 => {
                    wtx.send(me.clone()).unwrap();
                    // Woken while it runs: it runs again.
                    me.wake_by_ref();
                    Next::Idle
                }
                2 => {
                    let ready = ready.take().unwrap();
                    // The timer thread processes this after it records this task as idle.
                    spawn(move |_| {
                        ready.send(()).unwrap();
                        Next::Done
                    })
                    .unwrap();
                    Next::Idle
                }
                _ => {
                    tx.send(runs).unwrap();
                    Next::Done
                }
            }
        })
        .unwrap();
        let waker = wrx.recv_timeout(Duration::from_secs(30)).unwrap();
        second_run_finished
            .recv_timeout(Duration::from_secs(30))
            .unwrap();
        assert!(rx.try_recv().is_err());
        waker.wake();
        assert_eq!(rx.recv_timeout(Duration::from_secs(30)).unwrap(), 3);
    }

    /// A task that panics ends alone.
    #[test]
    fn a_panicking_task_does_not_end_the_thread() {
        spawn(|_| panic!("task")).unwrap();
        let (tx, rx) = mpsc::channel();
        spawn(move |_| {
            tx.send(()).unwrap();
            Next::Done
        })
        .unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
    }
}
