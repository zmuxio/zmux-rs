//! Loom models of the drivers' synchronization units: every interleaving
//! (up to the preemption bound) of the session task, application tasks and
//! carriers is explored, and loom fails a model that deadlocks (a lost
//! wake-up leaves a thread parked forever) or panics.
//!
//! Run with (a separate target directory: `--cfg loom` rebuilds every
//! dependency):
//!
//! ```text
//! LOOM_MAX_PREEMPTIONS=2 RUSTFLAGS="--cfg loom" CARGO_TARGET_DIR=target/loom \
//!     cargo test --lib --release loom
//! ```
//!
//! A few seconds with a bound of 2.
//!
//! The units are the production code ([`ReadPath`], [`WritePath`],
//! [`Locked`], [`WakeList`], [`Waiters`], [`Wait`], [`Open`],
//! [`super::wait::OpenQueue`], [`PipeDone`]); carriers and the core are small
//! fakes, and the session task and application tasks repeat the drivers'
//! steps around the units. Every waker a model registers checks that it is
//! never woken by a thread holding a core lock, and so does every
//! [`WakeList`].
//!
//! | model | checks |
//! |---|---|
//! | `loom_deferred_wakes_*` | a wake-up decided under the lock is delivered after it, never lost |
//! | `loom_read_through_*` | the pipe's read wake-up with the session task and two readers, a cancelled reader, or one that unwinds out of the carrier; the session's end during a read-through; the task skips the side while a reader holds it |
//! | `loom_write_through_*` | the write-through hand-over: no lost batch, no deadlock, one or two writers; the task skips the side while a writer holds it |
//! | `loom_close_*` | close against pending reads, accepts, opens and `stopped`, and a cancelled wait |
//! | `loom_*opener*`, `loom_try_open_*` | FIFO openers: order, a cancelled opener passing its turn, no overtaking |
//! | `loom_pipe_done` | a pipe's end against a wait and a cancelled wait |

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc as StdArc;
use std::task::{Context, Poll, Wake, Waker};

use loom::future::block_on;
use loom::sync::Arc;
use loom::thread;

use super::sync::{Mutex, lock};
use super::through::{Carrier, Outbox, Polled, ReadPath, WritePath};
use super::wait::{Attempt, List, Open, PipeDone, Wait, Waiters, Waiting, open_now};
use super::wake::{Defer, Locked, WakeList, lock_held};

/// A waker that asserts, when woken, that the waking thread holds no core
/// lock.
struct Checked(Waker);

impl Wake for Checked {
    fn wake(self: StdArc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &StdArc<Self>) {
        assert!(!lock_held(), "woken under a core lock");
        self.0.wake_by_ref();
    }
}

fn checked(cx: &Context<'_>) -> Waker {
    Waker::from(StdArc::new(Checked(cx.waker().clone())))
}

/// Polls `f` once with a waker nobody wakes, as a future that is then
/// dropped (cancelled).
fn poll_once<F: Future + Unpin>(f: &mut F) -> Poll<F::Output> {
    Pin::new(f).poll(&mut Context::from_waker(Waker::noop()))
}

fn take_wakes(wakes: &mut WakeList) -> Option<WakeList> {
    (!wakes.is_empty()).then(|| std::mem::take(wakes))
}

// ---- (b) the deferred-wake guard ----------------------------------------------------

#[derive(Default)]
struct Flags {
    set: u8,
    waiter: Option<Waker>,
    wakes: WakeList,
}

impl Defer for Flags {
    type After = WakeList;

    fn take_after(&mut self) -> Option<WakeList> {
        take_wakes(&mut self.wakes)
    }
}

/// Two critical sections each decide a wake-up of a waiter that registers
/// under the same lock: the waiter sees both (no wake-up decided before the
/// unlock is lost), and no wake-up runs under the lock.
#[test]
fn loom_deferred_wakes_are_delivered_after_unlock() {
    loom::model(|| {
        let m = Arc::new(Mutex::new(Flags::default()));
        let notifiers: Vec<_> = (0..2)
            .map(|i| {
                let m = m.clone();
                thread::spawn(move || {
                    let mut f = Locked::lock(&m);
                    f.set |= 1 << i;
                    if let Some(w) = f.waiter.take() {
                        f.wakes.push(w);
                    }
                })
            })
            .collect();
        block_on(poll_fn(|cx| {
            let mut f = Locked::lock(&m);
            if f.set == 3 {
                return Poll::Ready(());
            }
            f.waiter = Some(checked(cx));
            Poll::Pending
        }));
        for n in notifiers {
            n.join().unwrap();
        }
    });
}

// ---- (a) read-through and the pipe's read wake-up ----------------------------------

/// A carrier's readable half: messages, each for one stream, and the waker
/// of the last poll that found none, woken by the sender after it unlocked
/// (like a reactor).
#[derive(Default)]
struct Wire {
    state: Mutex<WireState>,
}

#[derive(Default)]
struct WireState {
    queue: VecDeque<usize>,
    waker: Option<Waker>,
}

impl Wire {
    fn send(&self, stream: usize) {
        let w = {
            let mut s = lock(&self.state);
            s.queue.push_back(stream);
            s.waker.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

struct WireReader(Arc<Wire>);

loom::thread_local! {
    /// The carrier panics at the next read of this thread.
    static PANICS: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

impl Carrier for WireReader {
    type Outcome = usize;

    fn poll_read(&mut self, cx: &mut Context<'_>, _max: usize) -> Poll<usize> {
        if PANICS.with(|p| p.replace(false)) {
            panic!("the carrier panics");
        }
        let mut s = lock(&self.0.state);
        match s.queue.pop_front() {
            Some(m) => Poll::Ready(m),
            None => {
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn outcome_bytes(_: &usize) -> usize {
        // Eight messages fill a read-through.
        super::through::READ_THROUGH_BYTES / 8
    }

    fn is_open(&self) -> bool {
        true
    }
}

/// The core of the read models: messages delivered per stream and read by
/// the application, the readers' and the session task's wakers.
#[derive(Default)]
struct ReadCore {
    delivered: [usize; 2],
    consumed: [usize; 2],
    readers: [Option<Waker>; 2],
    task: Option<Waker>,
    repoll: bool,
    /// The model's end: the session task stops.
    done: bool,
    /// The session ended: reads resolve (`Event::Closed`).
    closed: bool,
    /// The main thread, waiting until every message reached the core.
    watcher: Option<Waker>,
    wakes: WakeList,
}

impl Defer for ReadCore {
    type After = WakeList;

    fn take_after(&mut self) -> Option<WakeList> {
        take_wakes(&mut self.wakes)
    }
}

/// Hands a message to the core (`ReadSide::apply` and `dispatch`).
fn deliver(_: &mut WireReader, stream: usize, core: &mut ReadCore) {
    core.delivered[stream] += 1;
    if let Some(w) = core.readers[stream].take() {
        core.wakes.push(w);
    }
    if let Some(w) = core.watcher.take() {
        core.wakes.push(w);
    }
}

/// Waits until `total` messages reached the core, whoever read them (a
/// message left in the carrier with nobody to read it is a lost
/// readiness: the model deadlocks), then stops the session task.
fn all_delivered(core: &Mutex<ReadCore>, total: usize) {
    block_on(poll_fn(|cx| {
        let mut c = Locked::lock(core);
        if c.delivered.iter().sum::<usize>() < total {
            c.watcher = Some(checked(cx));
            return Poll::Pending;
        }
        c.done = true;
        if let Some(w) = c.task.take() {
            c.wakes.push(w);
        }
        Poll::Ready(())
    }));
}

/// `Inner::repoll_task`.
fn repoll_read(core: &mut ReadCore) {
    core.repoll = true;
    if let Some(w) = core.task.take() {
        core.wakes.push(w);
    }
}

/// The session task's read loop (`Task::poll`): read the carrier until it
/// has nothing, skipping it while an application reads through, then check
/// `repoll` and a skipped side under the core lock (H1) and register. Ends
/// when told so.
fn read_task<'a>(
    path: &'a ReadPath<WireReader>,
    core: &'a Mutex<ReadCore>,
) -> impl Future<Output = ()> + 'a {
    let mut skipped = false;
    poll_fn(move |cx| {
        let waker = checked(cx);
        loop {
            let polled = path.poll_task(core, &waker, deliver);
            skipped |= polled == Polled::Busy;
            let mut c = Locked::lock(core);
            if c.done {
                return Poll::Ready(());
            }
            if polled == Polled::Read || std::mem::take(&mut c.repoll) {
                continue;
            }
            if std::mem::take(&mut skipped) && path.recheck_before_wait(false) {
                continue;
            }
            c.task = Some(waker);
            return Poll::Pending;
        }
    })
}

/// An application read of one message of `stream` (`poll_read_cmd`).
fn read_message<'a>(
    path: &'a ReadPath<WireReader>,
    core: &'a Mutex<ReadCore>,
    stream: usize,
) -> impl Future<Output = ()> + Unpin + 'a {
    poll_fn(move |cx| {
        let waker = checked(cx);
        let mut c = Locked::lock(core);
        c.readers[stream] = None;
        let mut through = true;
        loop {
            if c.consumed[stream] < c.delivered[stream] {
                c.consumed[stream] += 1;
                return Poll::Ready(());
            }
            if c.closed {
                return Poll::Ready(());
            }
            if through {
                through = false;
                let (again, unlocked) =
                    path.read_through(core, c, &waker, deliver, repoll_read, |c| c.task.clone());
                c = again;
                if unlocked {
                    continue;
                }
            }
            c.readers[stream] = Some(waker);
            return Poll::Pending;
        }
    })
}

/// The session task and two application reads on one pipe: whatever the
/// carrier delivers reaches the core, and both reads complete.
#[test]
fn loom_read_through_two_readers() {
    loom::model(|| {
        let wire = Arc::new(Wire::default());
        let path = Arc::new(ReadPath::new(WireReader(wire.clone())));
        let core = Arc::new(Mutex::new(ReadCore::default()));
        let task = {
            let (path, core) = (path.clone(), core.clone());
            thread::spawn(move || block_on(read_task(&path, &core)))
        };
        let readers: Vec<_> = (0..2)
            .map(|s| {
                let (path, core) = (path.clone(), core.clone());
                thread::spawn(move || block_on(read_message(&path, &core, s)))
            })
            .collect();
        wire.send(0);
        wire.send(1);
        for r in readers {
            r.join().unwrap();
        }
        all_delivered(&core, 2);
        task.join().unwrap();
    });
}

/// An application read that reads through is cancelled (it is never
/// polled again): the carrier's readiness still reaches the session task,
/// and the other read completes.
#[test]
fn loom_read_through_cancelled_reader() {
    loom::model(|| {
        let wire = Arc::new(Wire::default());
        let path = Arc::new(ReadPath::new(WireReader(wire.clone())));
        let core = Arc::new(Mutex::new(ReadCore::default()));
        let task = {
            let (path, core) = (path.clone(), core.clone());
            thread::spawn(move || block_on(read_task(&path, &core)))
        };
        let reader = {
            let (path, core) = (path.clone(), core.clone());
            thread::spawn(move || block_on(read_message(&path, &core, 0)))
        };
        let sender = {
            let wire = wire.clone();
            thread::spawn(move || {
                wire.send(1);
                wire.send(0);
            })
        };
        let mut cancelled = read_message(&path, &core, 1);
        let _ = poll_once(&mut cancelled);
        drop(cancelled);
        sender.join().unwrap();
        reader.join().unwrap();
        all_delivered(&core, 2);
        task.join().unwrap();
    });
}

/// The session ends while an application read reads through, the core
/// unlocked: the end woke no reader of the stream yet, so the read looks
/// again before it registers, and resolves.
#[test]
fn loom_read_through_sees_the_end() {
    loom::model(|| {
        let wire = Arc::new(Wire::default());
        let path = Arc::new(ReadPath::new(WireReader(wire)));
        let core = Arc::new(Mutex::new(ReadCore::default()));
        let closer = {
            let core = core.clone();
            thread::spawn(move || {
                let mut c = Locked::lock(&core);
                let c = &mut *c;
                c.closed = true;
                c.wakes
                    .extend(c.readers.iter_mut().filter_map(Option::take));
            })
        };
        block_on(read_message(&path, &core, 0));
        closer.join().unwrap();
    });
}

/// An application read unwinds out of the carrier's code while it holds
/// the side: the hand-over guard still clears the mark, asks the session
/// task to poll again and releases the side, so a task that skipped the
/// side reads the message.
#[test]
fn loom_read_through_reader_panics() {
    loom::model(|| {
        let wire = Arc::new(Wire::default());
        let path = Arc::new(ReadPath::new(WireReader(wire.clone())));
        let core = Arc::new(Mutex::new(ReadCore::default()));
        let task = {
            let (path, core) = (path.clone(), core.clone());
            thread::spawn(move || block_on(read_task(&path, &core)))
        };
        let reader = {
            let (path, core) = (path.clone(), core.clone());
            thread::spawn(move || {
                PANICS.with(|p| p.set(true));
                // Either the carrier panics in this read, or the task read
                // the message first and this read takes it.
                let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    block_on(read_message(&path, &core, 0))
                }));
                PANICS.with(|p| p.set(false));
                drop(read);
            })
        };
        wire.send(0);
        reader.join().unwrap();
        all_delivered(&core, 1);
        task.join().unwrap();
    });
}

// ---- (c) write-through ---------------------------------------------------------------

/// A carrier's writable half with room for one unit: a write that finds it
/// full registers the writer's waker, or none for a write without a waker
/// (which replaces an earlier one, like a socket polled with a no-op waker).
#[derive(Default)]
struct Sink {
    state: Mutex<SinkState>,
}

struct SinkState {
    room: usize,
    written: usize,
    consumed: usize,
    writer: Option<Waker>,
    reader: Option<Waker>,
}

impl Default for SinkState {
    fn default() -> Self {
        Self {
            room: 1,
            written: 0,
            consumed: 0,
            writer: None,
            reader: None,
        }
    }
}

impl Sink {
    /// Writes up to `n` units; returns how many.
    fn write(&self, n: usize, waker: Option<&Waker>) -> usize {
        let (k, reader) = {
            let mut s = lock(&self.state);
            let k = n.min(s.room);
            s.room -= k;
            s.written += k;
            if k < n {
                s.writer = waker.cloned();
            }
            (k, if k > 0 { s.reader.take() } else { None })
        };
        if let Some(r) = reader {
            r.wake();
        }
        k
    }

    /// The peer reads until it got `total` units.
    fn consume(&self, total: usize) -> impl Future<Output = ()> + '_ {
        poll_fn(move |cx| {
            let (done, writer) = {
                let mut s = lock(&self.state);
                let got = s.written - s.consumed;
                s.consumed = s.written;
                s.room += got;
                if s.consumed < total {
                    s.reader = Some(checked(cx));
                }
                (
                    s.consumed == total,
                    if got > 0 { s.writer.take() } else { None },
                )
            };
            if let Some(w) = writer {
                w.wake();
            }
            if done { Poll::Ready(()) } else { Poll::Pending }
        })
    }
}

/// A pipe's write side: the batch left to write.
struct Out {
    sink: Arc<Sink>,
    batch: usize,
    blocked: bool,
}

impl Outbox for Out {
    fn idle(&self) -> bool {
        self.batch == 0 && !self.blocked
    }

    fn write_now(&mut self, budget: usize) -> usize {
        let n = self.sink.write(self.batch.min(budget), None);
        self.batch -= n;
        n
    }

    fn call_limit(&self) -> usize {
        // Units of the model: a few batches.
        8
    }

    fn has_work(&self) -> bool {
        self.batch > 0
    }
}

#[derive(Default)]
struct WriteCore {
    /// Output the core has not handed to the pipe yet.
    outbox: usize,
    task: Option<Waker>,
    repoll: bool,
    done: bool,
    wakes: WakeList,
}

impl Defer for WriteCore {
    type After = WakeList;

    fn take_after(&mut self) -> Option<WakeList> {
        take_wakes(&mut self.wakes)
    }
}

impl WriteCore {
    fn wake_task(&mut self) {
        if let Some(w) = self.task.take() {
            self.wakes.push(w);
        }
    }
}

/// `take_batch`.
fn take_batch(out: &mut Out, core: &mut WriteCore) -> bool {
    if out.batch > 0 || core.outbox == 0 {
        return false;
    }
    out.batch = core.outbox;
    core.outbox = 0;
    true
}

/// `State::repoll_task`: the hand-over of the write-through.
fn repoll_write(core: &mut WriteCore) {
    core.repoll = true;
    core.wake_task();
}

/// An application write of `n` units (`finish_write`, `after_command`).
fn app_write(path: &WritePath<Out>, core: &Mutex<WriteCore>, n: usize) {
    let mut c = Locked::lock(core);
    c.outbox += n;
    let mut c = path.write_through(core, c, take_batch, repoll_write);
    if c.outbox > 0 {
        c.wake_task();
    }
}

/// The session task's write loop (`PipeTask::poll_write` and the checks of
/// `Task::poll` before it waits): a side an application writes through is
/// skipped, and checked again under the core lock (W3, H1). Ends when told
/// so.
fn write_task<'a>(
    path: &'a WritePath<Out>,
    core: &'a Mutex<WriteCore>,
) -> impl Future<Output = ()> + 'a {
    let mut skipped = false;
    poll_fn(move |cx| {
        let waker = checked(cx);
        loop {
            let mut progress = false;
            match path.try_side() {
                None => skipped = true,
                Some(mut w) => {
                    if w.batch == 0 {
                        let mut c = Locked::lock(core);
                        progress = take_batch(&mut w, &mut c);
                    }
                    if w.batch > 0 {
                        let k = w.sink.write(w.batch, Some(&waker));
                        w.batch -= k;
                        progress |= k > 0;
                        w.blocked = w.batch > 0;
                    }
                }
            }
            let mut c = Locked::lock(core);
            if c.done {
                return Poll::Ready(());
            }
            if progress
                || std::mem::take(&mut c.repoll)
                || path.take_before_wait(&mut *c, std::mem::take(&mut skipped), false, take_batch)
            {
                continue;
            }
            c.task = Some(waker);
            return Poll::Pending;
        }
    })
}

/// Application writes on a thread of their own (`app`, units each, in
/// order) and on the main thread (`main`), which then reads the carrier
/// until everything arrived; the carrier has room for one unit until the
/// peer reads.
fn write_model(app: &'static [usize], main: &[usize]) {
    let sink = Arc::new(Sink::default());
    let path = Arc::new(WritePath::new(Out {
        sink: sink.clone(),
        batch: 0,
        blocked: false,
    }));
    let core = Arc::new(Mutex::new(WriteCore::default()));
    let task = {
        let (path, core) = (path.clone(), core.clone());
        thread::spawn(move || block_on(write_task(&path, &core)))
    };
    let writer = {
        let (path, core) = (path.clone(), core.clone());
        thread::spawn(move || {
            for &n in app {
                app_write(&path, &core, n);
            }
        })
    };
    for &n in main {
        app_write(&path, &core, n);
    }
    block_on(sink.consume(app.iter().chain(main).sum()));
    writer.join().unwrap();
    {
        let mut c = Locked::lock(&core);
        c.done = true;
        c.wake_task();
    }
    task.join().unwrap();
}

/// An application writing through and the session task: every unit is
/// written, whatever the carrier takes at once (no lost batch, no
/// deadlock).
#[test]
fn loom_write_through_hand_off() {
    loom::model(|| write_model(&[2], &[]));
}

/// Two application writes racing for the write side with the session task:
/// the second finds the side busy or the carrier full, and its unit reaches
/// the carrier through the session task.
#[test]
fn loom_write_through_two_writers() {
    loom::model(|| write_model(&[1], &[1]));
}

/// The session task writes the rest of a batch the carrier could not take,
/// and an application command without output tries the side at the moment
/// the carrier's readiness wakes the task: the task skips the busy side and
/// polls it again before it waits (H1), so the readiness it consumed is not
/// lost.
#[test]
fn loom_write_through_task_skips_a_busy_side() {
    loom::model(|| write_model(&[2, 0], &[]));
}

// ---- (d) close racing with waiters --------------------------------------------------

/// The core of the close and open models.
#[derive(Default)]
struct FakeCore {
    closed: bool,
    credit: usize,
    /// An open was blocked since the last credit.
    waiting: bool,
}

impl FakeCore {
    /// Opening in the core (`core::SessionCore::open`).
    fn open(&mut self) -> Attempt<(), ()> {
        if self.closed {
            Attempt::Failed(())
        } else if self.credit > 0 {
            self.credit -= 1;
            Attempt::Opened(())
        } else {
            self.waiting = true;
            Attempt::Blocked
        }
    }
}

#[derive(Default)]
struct Sess {
    core: FakeCore,
    waiters: Waiters<u32>,
    wakes: WakeList,
}

impl Defer for Sess {
    type After = WakeList;

    fn take_after(&mut self) -> Option<WakeList> {
        take_wakes(&mut self.wakes)
    }
}

impl Waiting for Sess {
    type Key = u32;

    fn waits(&mut self) -> (&mut Waiters<u32>, &mut WakeList) {
        (&mut self.waiters, &mut self.wakes)
    }
}

impl Sess {
    /// `Event::Closed`.
    fn close(&mut self) {
        self.core.closed = true;
        self.waiters.close(&mut self.wakes);
    }

    /// `Event::StreamsAvailable` (emitted only to a blocked opener).
    fn grant(&mut self) {
        self.core.credit += 1;
        if std::mem::take(&mut self.core.waiting) {
            self.waiters.open[0].credit(&mut self.wakes);
        }
    }
}

/// A stream read (`poll_read_cmd` without reading through): resolves at the
/// end of the session.
fn read_until_closed(m: &Mutex<Sess>, key: u32) -> impl Future<Output = ()> + Unpin + '_ {
    poll_fn(move |cx| {
        let mut s = Locked::lock(m);
        s.waiters.remove_reader(key);
        if s.core.closed {
            return Poll::Ready(());
        }
        s.waiters.register_reader(key, &checked(cx));
        Poll::Pending
    })
}

fn until_closed(s: &mut Sess) -> Option<()> {
    s.core.closed.then_some(())
}

fn open(m: &Mutex<Sess>) -> impl Future<Output = Result<(), ()>> + Unpin + '_ {
    Open::new(m, 0, |s: &mut Sess| s.core.open(), |_: &mut Sess| {})
}

/// Checks the waiters left nothing registered.
fn assert_idle(m: &Mutex<Sess>) {
    assert!(lock(m).waiters.is_idle(), "a wait stayed registered");
}

/// A stream read and an accept race with the close: both resolve.
#[test]
fn loom_close_resolves_read_and_accept() {
    loom::model(|| {
        let m = Arc::new(Mutex::new(Sess::default()));
        let reader = {
            let m = m.clone();
            thread::spawn(move || block_on(read_until_closed(&m, 1)))
        };
        let accept = {
            let m = m.clone();
            thread::spawn(move || block_on(Wait::new(&*m, List::Accept(0), until_closed)))
        };
        Locked::lock(&m).close();
        reader.join().unwrap();
        accept.join().unwrap();
        assert_idle(&m);
    });
}

/// A blocked opener and a `stopped` wait resolve on close, while another
/// wait is cancelled at the same time: nothing stays registered.
#[test]
fn loom_close_resolves_open_and_stopped_with_a_cancelled_wait() {
    loom::model(|| {
        let m = Arc::new(Mutex::new(Sess::default()));
        let opener = {
            let m = m.clone();
            thread::spawn(move || assert_eq!(block_on(open(&m)), Err(())))
        };
        let stopped = {
            let m = m.clone();
            thread::spawn(move || block_on(Wait::new(&*m, List::Stopped(1), until_closed)))
        };
        let closer = {
            let m = m.clone();
            thread::spawn(move || Locked::lock(&m).close())
        };
        let mut cancelled = Wait::new(&*m, List::State, until_closed);
        let _ = poll_once(&mut cancelled);
        drop(cancelled);
        closer.join().unwrap();
        opener.join().unwrap();
        stopped.join().unwrap();
        assert_idle(&m);
    });
}

// ---- (e) FIFO openers -----------------------------------------------------------------

/// The first waiting opener is cancelled while credit for one stream
/// arrives: the second opener gets it (the turn passes on).
#[test]
fn loom_cancelled_opener_passes_its_turn() {
    loom::model(|| {
        let m = Arc::new(Mutex::new(Sess::default()));
        // The first opener queues before the second exists.
        let mut first = open(&m);
        assert!(poll_once(&mut first).is_pending());
        let second = {
            let m = m.clone();
            thread::spawn(move || assert_eq!(block_on(open(&m)), Ok(())))
        };
        let credit = {
            let m = m.clone();
            thread::spawn(move || Locked::lock(&m).grant())
        };
        drop(first);
        credit.join().unwrap();
        second.join().unwrap();
        let s = lock(&m);
        assert_eq!(s.waiters.open[0].len(), 0);
        assert_eq!(s.core.credit, 0);
    });
}

/// An opener that does not wait never takes credit a waiting opener is
/// queued for.
#[test]
fn loom_try_open_does_not_overtake() {
    loom::model(|| {
        let m = Arc::new(Mutex::new(Sess::default()));
        let mut waiting = open(&m);
        assert!(poll_once(&mut waiting).is_pending());
        let credit = {
            let m = m.clone();
            thread::spawn(move || Locked::lock(&m).grant())
        };
        let eager = {
            let m = m.clone();
            thread::spawn(move || {
                let mut s = Locked::lock(&m);
                let s = &mut *s;
                open_now(&s.waiters.open[0], || s.core.open())
            })
        };
        assert_eq!(block_on(&mut waiting), Ok(()));
        assert!(
            eager.join().unwrap().is_none(),
            "try_open overtook a waiter"
        );
        credit.join().unwrap();
    });
}

/// Credit for one stream and two queued openers: exactly the first opens;
/// the second keeps waiting until close, which fails it.
#[test]
fn loom_openers_are_served_in_order() {
    loom::model(|| {
        let m = Arc::new(Mutex::new(Sess::default()));
        let mut first = open(&m);
        assert!(poll_once(&mut first).is_pending());
        let mut second = open(&m);
        assert!(poll_once(&mut second).is_pending());
        let credit = {
            let m = m.clone();
            thread::spawn(move || Locked::lock(&m).grant())
        };
        assert_eq!(block_on(&mut first), Ok(()));
        credit.join().unwrap();
        let closer = {
            let m = m.clone();
            thread::spawn(move || Locked::lock(&m).close())
        };
        assert_eq!(block_on(&mut second), Err(()));
        closer.join().unwrap();
        assert_idle(&m);
    });
}

// ---- (f) PipeDone ---------------------------------------------------------------------

/// The pipe ends while one wait waits and another is cancelled: the first
/// resolves and nothing stays registered.
#[test]
fn loom_pipe_done() {
    loom::model(|| {
        let done = Arc::new(PipeDone::default());
        let waiter = {
            let done = done.clone();
            thread::spawn(move || block_on(done.wait()))
        };
        let finisher = {
            let done = done.clone();
            thread::spawn(move || {
                let mut wakes = WakeList::default();
                done.finish_into(&mut wakes);
            })
        };
        let mut cancelled = done.wait();
        let _ = poll_once(&mut cancelled);
        drop(cancelled);
        finisher.join().unwrap();
        waiter.join().unwrap();
        assert_eq!(done.waiting(), 0);
    });
}
