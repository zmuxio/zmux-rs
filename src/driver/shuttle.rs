//! Shuttle models of the std driver's thread protocol: randomized and PCT
//! schedules of application, reader, writer and timer threads around the
//! production units ([`Locked`], [`WakeList`], [`Waiters`], [`Wait`],
//! [`Open`], [`WaitList`], the thread waker and `park`). Shuttle fails a
//! schedule that deadlocks (a lost wake-up leaves every thread parked) or
//! panics.
//!
//! The threads repeat the std driver's steps (`blocking.rs`): a waiting
//! call runs the shared wait future (`handle.rs`) on its thread, parking
//! between polls, like `blocking::run`; the writer thread registers in its
//! list under the core lock, unlocks and parks; whoever changes the state
//! decides the wake-ups under the lock and delivers them after it. The core
//! is a small fake.
//!
//! ```text
//! RUSTFLAGS="--cfg shuttle" CARGO_TARGET_DIR=target/shuttle \
//!     cargo test --lib --release --features blocking shuttle
//! ```
//!
//! Shuttle does not model time: a call's timeout is modelled as an event (a
//! thread that marks the wait expired and unparks it). The shared timer
//! thread (`session_timer.rs`) is modelled by [`Scheduler`], which repeats
//! its steps over logical time: a clock thread advances the time and wakes
//! the scheduler thread, as the expiry of its timed wait does.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, PoisonError};
use std::task::{Context, Poll, Wake, Waker};

use shuttle::sync::Condvar;
use shuttle::sync::atomic::{AtomicBool, Ordering};
use shuttle::thread;

use super::sync::{Mutex, lock as lock_slot, park, thread_waker};
use super::wait::{Attempt, List, Open, Wait, WaitList, Waiters, Waiting};
use super::wake::{Defer, Locked, WakeList};

/// Schedules per model.
const ITERATIONS: usize = 20_000;

/// The fake session: per-stream data, stream credit, output for the
/// writer, and the end.
#[derive(Default)]
struct Inner {
    data: [VecDeque<u8>; 3],
    credit: usize,
    opened: Vec<usize>,
    output: usize,
    written: usize,
    closed: bool,
    waiters: Waiters<usize>,
    writers: WaitList,
    writers_alive: usize,
    timer: Option<Waker>,
    wakes: WakeList,
}

impl Defer for Inner {
    type After = WakeList;

    fn take_after(&mut self) -> Option<WakeList> {
        (!self.wakes.is_empty()).then(|| std::mem::take(&mut self.wakes))
    }
}

impl Waiting for Inner {
    type Key = usize;

    fn waits(&mut self) -> (&mut Waiters<usize>, &mut WakeList) {
        (&mut self.waiters, &mut self.wakes)
    }
}

type Session = Arc<Mutex<Inner>>;

fn lock(s: &Session) -> Locked<'_, Inner> {
    Locked::lock(s)
}

impl Inner {
    /// `State::after_command` with `Blocking::kick`: the writers wake when
    /// there is output or the end, the timer at the end (after the lock).
    fn kick(&mut self) {
        if self.output > 0 || self.closed {
            self.writers.wake_all(&mut self.wakes);
        }
        if self.closed
            && let Some(w) = self.timer.take()
        {
            self.wakes.push(w);
        }
    }

    /// The core's `Closed` event: every wait resolves.
    fn close(&mut self) {
        self.closed = true;
        self.waiters.close(&mut self.wakes);
        self.kick();
    }
}

/// A wait's timeout, modelled as an event: the call gives up once it is
/// set, and setting it unparks the waiting thread.
#[derive(Default)]
struct Expiry {
    expired: AtomicBool,
    thread: Mutex<Option<Waker>>,
}

impl Expiry {
    fn expire(&self) {
        self.expired.store(true, Ordering::SeqCst);
        let w = lock_slot(&self.thread).take();
        if let Some(w) = w {
            w.wake();
        }
    }
}

/// `blocking::run`: polls `fut` on this thread, parking between polls,
/// until it completes or `expiry` fires; the future is dropped before this
/// returns (a wait that gave up leaves its list).
fn run<F: Future>(fut: F, expiry: &Expiry) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let waker = thread_waker();
    *lock_slot(&expiry.thread) = Some(waker.clone());
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            return Some(r);
        }
        if expiry.expired.load(Ordering::SeqCst) {
            return None;
        }
        park(None);
    }
}

/// A blocking read of `stream` (`RecvStream::poll_read_cmd`): its bytes, or
/// `None` at the end.
fn read(s: &Session, stream: usize) -> Option<u8> {
    let read = Wait::new(&**s, List::Readable(stream), |inner: &mut Inner| {
        if let Some(b) = inner.data[stream].pop_front() {
            return Some(Some(b));
        }
        inner.closed.then_some(None)
    });
    run(read, &Expiry::default()).flatten()
}

/// A blocking `closing()` (`Session::closing_op`).
fn closed(s: &Session) {
    let wait = Wait::new(&**s, List::State, |i: &mut Inner| i.closed.then_some(()));
    run(wait, &Expiry::default());
}

/// `Session::open_bi`: FIFO openers, each with a timeout that may expire.
fn open(s: &Session, id: usize, expiry: &Expiry) -> Option<Result<(), ()>> {
    let open = Open::new(
        &**s,
        0,
        move |i: &mut Inner| {
            if i.closed {
                Attempt::Failed(())
            } else if i.credit > 0 {
                i.credit -= 1;
                i.opened.push(id);
                Attempt::Opened(())
            } else {
                Attempt::Blocked
            }
        },
        |_: &mut Inner, _| {},
    );
    run(open, expiry)
}

/// `writer_thread`: waits for output or the end, writes outside the lock.
fn writer(s: &Session) {
    let me = thread_waker();
    let mut ticket = None;
    loop {
        let mut inner = lock(s);
        let batch = loop {
            if inner.closed {
                break None;
            }
            if inner.output > 0 {
                break Some(std::mem::take(&mut inner.output));
            }
            inner.writers.register(&mut ticket, &me);
            drop(inner);
            park(None);
            inner = lock(s);
        };
        if let Some(t) = ticket.take() {
            inner.writers.remove(t);
        }
        drop(inner);
        let Some(n) = batch else {
            break;
        };
        // The write call, without the lock.
        thread::yield_now();
        let mut inner = lock(s);
        inner.written += n;
        inner.kick();
    }
    let mut inner = lock(s);
    inner.writers_alive -= 1;
    if let Some(w) = inner.timer.take() {
        inner.wakes.push(w);
    }
}

/// A one-shot event a thread can wait for.
#[derive(Default)]
struct Latch {
    set: Mutex<bool>,
    cv: Condvar,
}

impl Latch {
    fn set(&self) {
        *lock_slot(&self.set) = true;
        self.cv.notify_all();
    }

    fn wait(&self) {
        let mut set = lock_slot(&self.set);
        while !*set {
            set = self.cv.wait(set).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// `session_timer::Next`, over logical time.
enum Next {
    At(u64),
    Idle,
    Done,
    /// The task panicked: the real thread catches the unwinding and ends
    /// the task (shuttle fails a test at any panic, so it is modelled by
    /// the outcome).
    Panicked,
}

type Run = Box<dyn FnMut(&Waker) -> Next + Send>;

/// `session_timer::Task`: its body and its place in the scheduler.
struct SchedTask {
    run: Mutex<Run>,
    state: Mutex<TaskState>,
    sched: Arc<Scheduler>,
}

#[derive(Default)]
struct TaskState {
    key: Option<(u64, u64)>,
    running: bool,
    again: bool,
    done: bool,
}

#[derive(Default)]
struct Queue {
    entries: BTreeMap<(u64, u64), Arc<SchedTask>>,
    next: u64,
    /// The logical time.
    now: u64,
    /// The end of the model: the thread leaves once it is set.
    stop: bool,
}

/// `session_timer::Timers`: one thread runs the tasks in the order of
/// their deadlines. The steps are those of `session_timer.rs`; the time is
/// the queue's `now`, advanced by [`Scheduler::tick`], whose notification
/// stands for the expiry of the real thread's timed wait.
#[derive(Default)]
struct Scheduler {
    queue: Mutex<Queue>,
    changed: Condvar,
}

impl Scheduler {
    fn place(&self, q: &mut Queue, task: &Arc<SchedTask>, st: &mut TaskState, at: u64) {
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

    /// `session_timer::spawn`: the task runs at once.
    fn spawn(self: &Arc<Self>, run: impl FnMut(&Waker) -> Next + Send + 'static) {
        let task = Arc::new(SchedTask {
            run: Mutex::new(Box::new(run)),
            state: Mutex::default(),
            sched: self.clone(),
        });
        let mut q = lock_slot(&self.queue);
        let mut st = lock_slot(&task.state);
        let now = q.now;
        self.place(&mut q, &task, &mut st, now);
    }

    fn now(&self) -> u64 {
        lock_slot(&self.queue).now
    }

    /// The clock: time advances to `to` and the thread looks at the queue.
    fn tick(&self, to: u64) {
        lock_slot(&self.queue).now = to;
        self.changed.notify_one();
    }

    fn stop(&self) {
        lock_slot(&self.queue).stop = true;
        self.changed.notify_one();
    }

    /// `session_timer::serve`.
    fn serve(&self) {
        let mut q = lock_slot(&self.queue);
        loop {
            let now = q.now;
            let Some(entry) = q.entries.first_entry().filter(|e| e.key().0 <= now) else {
                if q.stop {
                    return;
                }
                q = self.changed.wait(q).unwrap_or_else(PoisonError::into_inner);
                continue;
            };
            let task = entry.remove();
            {
                let mut st = lock_slot(&task.state);
                st.key = None;
                st.running = true;
                st.again = false;
            }
            drop(q);
            let me = Waker::from(task.clone());
            let next = (lock_slot(&task.run))(&me);
            drop(me);
            q = lock_slot(&self.queue);
            let mut st = lock_slot(&task.state);
            st.running = false;
            if matches!(next, Next::Done | Next::Panicked) {
                st.done = true;
                drop(st);
                drop(q);
                *lock_slot(&task.run) = Box::new(|_| Next::Done);
                q = lock_slot(&self.queue);
            } else if st.again {
                let now = q.now;
                self.place(&mut q, &task, &mut st, now);
            } else if let Next::At(at) = next {
                self.place(&mut q, &task, &mut st, at);
            }
        }
    }
}

impl Wake for SchedTask {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let t = &self.sched;
        let mut q = lock_slot(&t.queue);
        let mut st = lock_slot(&self.state);
        if st.done {
            return;
        }
        if st.running {
            st.again = true;
        } else {
            let now = q.now;
            t.place(&mut q, self, &mut st, now);
        }
    }
}

/// The scheduler thread and the clock (time 1..=`TICKS`), started by the
/// model; `finish` ends them.
struct Timers {
    sched: Arc<Scheduler>,
    threads: Vec<thread::JoinHandle<()>>,
}

/// The last logical time.
const TICKS: u64 = 4;

impl Timers {
    /// The scheduler thread only; tasks spawned before [`Timers::start_clock`]
    /// are placed at time 0.
    fn new() -> Self {
        let sched = Arc::new(Scheduler::default());
        let s = sched.clone();
        Self {
            sched,
            threads: vec![thread::spawn(move || s.serve())],
        }
    }

    fn start_clock(&mut self) {
        let s = self.sched.clone();
        self.threads.push(thread::spawn(move || {
            for t in 1..=TICKS {
                s.tick(t);
            }
        }));
    }

    fn finish(self) {
        self.sched.stop();
        for t in self.threads {
            t.join().unwrap();
        }
    }
}

/// How long the session task waits for the writers after the close.
const FINAL_WRITE: u64 = 2;

/// `blocking::timer_task` after the close: the task re-runs, as the core's
/// timers ask, until the session is closed; then it waits until no writer is
/// left or the time ran out, and ends. It registers its waker under the
/// session lock, like the real task.
fn timer_task(
    sched: Arc<Scheduler>,
    s: Session,
    ended: Arc<Latch>,
) -> impl FnMut(&Waker) -> Next + Send + 'static {
    let mut draining: Option<u64> = None;
    move |me| {
        let now = sched.now();
        let mut inner = lock(&s);
        let deadline = match draining {
            Some(d) => d,
            None if inner.closed => *draining.insert(now + FINAL_WRITE),
            None => {
                // The core's timers.
                inner.timer = Some(me.clone());
                return Next::At(now + 2);
            }
        };
        if inner.writers_alive == 0 || now >= deadline {
            inner.timer = None;
            drop(inner);
            ended.set();
            return Next::Done;
        }
        inner.timer = Some(me.clone());
        Next::At(deadline)
    }
}

fn session() -> Session {
    Arc::new(Mutex::new(Inner {
        writers_alive: 1,
        ..Inner::default()
    }))
}

/// Readers of three streams, a reader thread delivering data, an
/// application producing output for the writer thread, a thread waiting
/// for the end, and a close at a random point: every read returns (data in
/// order, then the end), the writer and the session's timer task end, and no wait is left
/// registered.
fn readers_writer_and_close() {
    let s = session();
    let readers: Vec<_> = (0..3)
        .map(|k| {
            let s = s.clone();
            thread::spawn(move || {
                let mut got = Vec::new();
                while let Some(b) = read(&s, k) {
                    got.push(b);
                }
                got
            })
        })
        .collect();
    let end = {
        let s = s.clone();
        thread::spawn(move || closed(&s))
    };
    let w = {
        let s = s.clone();
        thread::spawn(move || writer(&s))
    };
    let mut timers = Timers::new();
    let ended = Arc::new(Latch::default());
    timers
        .sched
        .spawn(timer_task(timers.sched.clone(), s.clone(), ended.clone()));
    timers.start_clock();
    let delivered = {
        let s = s.clone();
        thread::spawn(move || {
            for b in 0..3u8 {
                for k in 0..3 {
                    let mut inner = lock(&s);
                    if inner.closed {
                        return;
                    }
                    inner.data[k].push_back(b);
                    inner.output += 1;
                    let Inner { waiters, wakes, .. } = &mut *inner;
                    waiters.readable(k, wakes);
                    inner.kick();
                }
            }
        })
    };
    {
        let s = s.clone();
        thread::spawn(move || lock(&s).close());
    }
    for r in readers {
        let got = r.join().unwrap();
        assert!(
            got.iter().enumerate().all(|(i, &b)| usize::from(b) == i),
            "{got:?}"
        );
    }
    end.join().unwrap();
    delivered.join().unwrap();
    w.join().unwrap();
    ended.wait();
    timers.finish();
    assert!(lock(&s).waiters.is_idle(), "a wait stayed registered");
}

/// Openers waiting for credit, one whose timeout expires, credit granted
/// one at a time, then a close: openers are served in arrival order, the
/// expired one passes its turn, the rest fail at the close, and no opener
/// stays queued.
fn openers_credit_and_expiry() {
    let s = session();
    let expiries: Vec<_> = (0..3).map(|_| Arc::new(Expiry::default())).collect();
    let openers: Vec<_> = (0..3)
        .map(|id| {
            let s = s.clone();
            let e = expiries[id].clone();
            thread::spawn(move || open(&s, id, &e))
        })
        .collect();
    let granter = {
        let s = s.clone();
        thread::spawn(move || {
            for _ in 0..2 {
                let mut inner = lock(&s);
                inner.credit += 1;
                let Inner { waiters, wakes, .. } = &mut *inner;
                waiters.open[0].credit(wakes);
            }
        })
    };
    {
        let e = expiries[1].clone();
        thread::spawn(move || e.expire());
    }
    granter.join().unwrap();
    {
        let s = s.clone();
        thread::spawn(move || lock(&s).close());
    }
    let results: Vec<_> = openers.into_iter().map(|o| o.join().unwrap()).collect();
    let inner = lock(&s);
    // At most the two credits, never to an opener after it gave up.
    assert!(inner.opened.len() <= 2);
    for (id, r) in results.iter().enumerate() {
        assert_eq!(
            *r == Some(Ok(())),
            inner.opened.contains(&id),
            "opener {id}: {r:?}"
        );
    }
    assert!(inner.waiters.is_idle(), "an opener stayed queued");
}

/// The shared scheduler alone: tasks of two deadlines run in the order of
/// their deadlines and never before them; a wake-up that comes while a task
/// runs makes it run again; an idle task runs when woken from another
/// thread; a task that panics ends alone (the model: `Next::Panicked`); a task that is done ignores a
/// late wake-up. A lost wake-up leaves a wait for a task that never runs
/// again, which shuttle reports as a deadlock.
fn timer_scheduler() {
    let mut timers = Timers::new();
    let sched = timers.sched.clone();
    let order = Arc::new(Mutex::new(Vec::new()));
    let ordered = [Arc::new(Latch::default()), Arc::new(Latch::default())];
    for (id, at) in [(0u8, 2u64), (1, 1)] {
        let (sched, order, ordered) = (
            sched.clone(),
            order.clone(),
            ordered[usize::from(id)].clone(),
        );
        let mut ran = false;
        timers.sched.spawn(move |_| {
            if !ran {
                ran = true;
                return Next::At(at);
            }
            assert!(sched.now() >= at, "task {id} ran before its time");
            lock_slot(&order).push(id);
            ordered.set();
            Next::Done
        });
    }
    timers.sched.spawn(|_| Next::Panicked);
    let again = Arc::new(Latch::default());
    let (wtx, waker) = (
        Arc::new(Mutex::new(None::<Waker>)),
        Arc::new(Latch::default()),
    );
    {
        let (again, wtx, waker) = (again.clone(), wtx.clone(), waker.clone());
        let mut runs = 0u32;
        timers.sched.spawn(move |me| {
            runs += 1;
            match runs {
                1 => {
                    *lock_slot(&wtx) = Some(me.clone());
                    waker.set();
                    // Woken while it runs: it runs again.
                    me.wake_by_ref();
                    Next::Idle
                }
                2 => {
                    again.set();
                    Next::Idle
                }
                _ => Next::Done,
            }
        });
    }
    timers.start_clock();
    // The third run is the wake-up from here; the second the one during the
    // first run.
    waker.wait();
    again.wait();
    let w = lock_slot(&wtx).take().unwrap();
    w.wake_by_ref();
    // The task is done after the next run, or idle until then; a wake-up of
    // a task that is done does nothing.
    w.wake();
    for o in &ordered {
        o.wait();
    }
    timers.finish();
    assert_eq!(*lock_slot(&order), [1, 0]);
}

#[test]
fn shuttle_readers_writer_and_close() {
    shuttle::check_random(readers_writer_and_close, ITERATIONS);
    shuttle::check_pct(readers_writer_and_close, ITERATIONS, 3);
}

#[test]
fn shuttle_openers_credit_and_expiry() {
    shuttle::check_random(openers_credit_and_expiry, ITERATIONS);
    shuttle::check_pct(openers_credit_and_expiry, ITERATIONS, 3);
}

#[test]
fn shuttle_timer_scheduler() {
    shuttle::check_random(timer_scheduler, ITERATIONS);
    shuttle::check_pct(timer_scheduler, ITERATIONS, 3);
}
