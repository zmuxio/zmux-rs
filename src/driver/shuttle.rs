//! Shuttle models of the std driver's thread protocol (CONFORMANCE.md):
//! randomized and PCT schedules of application,
//! reader, writer and timer threads around the production units
//! ([`Locked`], [`WakeList`], [`Waiters`], [`Wait`], [`Open`], [`WaitList`],
//! the thread waker and `park`). Shuttle fails a schedule that deadlocks (a
//! lost wake-up leaves every thread parked) or panics.
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
//! thread that marks the wait expired and unparks it).

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

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
    let read = poll_fn(|cx| {
        let mut inner = lock(s);
        inner.waiters.remove_reader(stream);
        if let Some(b) = inner.data[stream].pop_front() {
            return Poll::Ready(Some(b));
        }
        if inner.closed {
            return Poll::Ready(None);
        }
        inner.waiters.register_reader(stream, cx.waker());
        Poll::Pending
    });
    run(read, &Expiry::default()).flatten()
}

/// A blocking `closed()` (`Session::closed_op`).
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
        |_: &mut Inner| {},
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

/// `timer_thread` after the close: waits until no writer is left.
fn timer(s: &Session) {
    let me = thread_waker();
    loop {
        let mut inner = lock(s);
        if inner.closed && inner.writers_alive == 0 {
            return;
        }
        inner.timer = Some(me.clone());
        drop(inner);
        park(None);
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
/// order, then the end), the writer and the timer end, and no wait is left
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
    let t = {
        let s = s.clone();
        thread::spawn(move || timer(&s))
    };
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
            got.iter().enumerate().all(|(i, &b)| b == i as u8),
            "{got:?}"
        );
    }
    end.join().unwrap();
    delivered.join().unwrap();
    w.join().unwrap();
    t.join().unwrap();
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
