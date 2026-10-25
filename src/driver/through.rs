//! A pipe's read and write sides, shared by the session task and the
//! application's fast paths: write-through on every pipe, read-through in
//! a multipath session (see `Driver::read_through` of the tokio driver).
//!
//! # Locks
//!
//! Three locks per pipe and session: the core lock `C` (the session state,
//! [`Locked`]), and the pipe's read side `R` and write side `W` (the carrier
//! halves with their buffers). The order is `R → C` and `W → C`: whoever
//! holds a side may wait for the core lock. A holder of the core lock only
//! ever *tries* a side, and never waits for one. So no cycle exists, and no
//! I/O happens under the core lock: a side is used for I/O only after the
//! core lock was released.
//!
//! The session task `T` never waits for a side either: an application that
//! reads or writes through may hold one for a while (up to
//! [`READ_THROUGH_BYTES`] read, or one bounded write call's worth written),
//! and `T` waiting for it would stall every other stream's reads
//! and writes on the pipe meanwhile (the latency of small messages under
//! bulk transfer). `T` only tries a side and skips it when it is busy; the
//! holder serves what arrives meanwhile (it reads on, and writes the output
//! other commands produced) and hands over when it releases the side (the
//! `contended` flag below).
//!
//! # Hand-over of a busy side
//!
//! - H1: before it waits, `T` checks under `C` every side it skipped this
//!   round: a free one it polls again (its holder may have consumed a
//!   wake-up of `T`, or left readiness behind); a busy one it marks
//!   `contended` with what it needs: `WATCH` for a skipped read (a wake-up
//!   only if the carrier's readiness may have been consumed meanwhile),
//!   `RUN` for a close it deferred (a wake-up in any case).
//! - H2: an application that is done with a side takes `C` while it still
//!   holds the side (the order `R → C`, `W → C`), takes `contended` and
//!   asks `T` to poll again (`repoll`, which wakes `T`) when the mark asks
//!   for it, and releases the side before it releases `C`.
//!
//! Either `T`'s check under `C` comes first, while the side is still held:
//! then the holder's critical section comes later and sees the mark; or the
//! holder's comes first: then the side is free when `T` checks, and `T`
//! polls it again. Nothing the holder left is lost, and `T` never waits for
//! the holder.

//! # Read-through
//!
//! An application read of a multipath session that finds nothing reads the
//! carriers itself instead of waiting for `T` to read them and wake it. The carrier is always polled with the pipe's own waker
//! ([`ReadWake`]), which wakes two slots: slot 0 holds `T`, slot 1 the newest
//! application read that read through.
//!
//! - R1: whoever polls the carrier holds `R` and polls with the pipe's waker.
//! - R2: `T` *tries* `R`; when it gets the side, it registers in slot 0 and
//!   polls ([`ReadPath::poll_task`]). A busy side is skipped, and H1
//!   applies: the holder registers `T` in slot 0 at H2 when `T` waits.
//! - R3: an application read holds `C`, *tries* `R`, releases `C`, registers
//!   in slot 1, then polls ([`ReadPath::read_through`]). It re-takes `C` to
//!   hand what it read to the core, and at the end, before it releases `R`
//!   (H2), so that it registers in its stream's waiters before `T` can read
//!   the carrier again. A carrier found empty by the last poll, with no
//!   wake-up since (`readable`: cleared before every poll, set by every
//!   wake-up and after a poll that read), is not read: the read only
//!   registers in slot 1.
//! - R4: an application read stops once its reads returned
//!   [`READ_THROUGH_BYTES`], leaving the carrier possibly readable with no waker
//!   armed: it asks `T` to read on (`repoll`, set under `C`, which `T`
//!   checks under `C` before it waits). Whenever it releases `R`, H2
//!   applies: for a `WATCH` mark, it wakes `T` if the pipe's waker fired
//!   since its last poll (`fired`, cleared before each poll it makes);
//!   otherwise its last poll armed the waker, which wakes `T` in slot 0.
//!
//! Invariants:
//!
//! - No lost readiness. `T` registers in slot 0 before every attempt, and
//!   slot 0 is emptied only by a wake-up of `T`, which also sets `fired`.
//!   When `T` skipped the side, the holder ends by R4 (it wakes `T`), by a
//!   poll that armed the pipe's waker while `T` waits in slot 0 (`fired`
//!   unset: the next readiness wakes `T`), or by H2 when the waker fired
//!   since (it wakes `T`); a wake-up of `T` consumed while the side was
//!   held is recovered by H1 (the free side is polled again) or H2.
//! - Several readers on one pipe. An application read registers in its
//!   stream's waiters under `C` before it returns `Pending`, so `T` wakes it
//!   when it reads data for its stream. Slot 1 is only a shortcut and never
//!   needed for progress: overwriting it with another reader loses nothing.
//! - Readiness is never routed to slot 1 alone: the pipe would then depend on
//!   an application task being polled (a dropped or starved read would stall
//!   every stream; an earlier design lost wake-ups with two readers this
//!   way). Waking both costs, at worst, a needless wake-up of `T`.
//! - No application code under `C`: a reader that ended is dropped only
//!   after the core lock was released ([`Carrier::release`]).
//!
//! # Write-through
//!
//! An application command that produced output writes it itself when the
//! write side is idle, without waking `T`.
//!
//! - W1: `T` *tries* `W` holding no other lock, then may take `C`; a busy
//!   side is skipped, and H1 applies.
//! - W2: an application command holds `C` and *tries* `W`; when the side is
//!   idle and the core wants to write, it takes a batch under both, releases
//!   `C`, writes without a waker until the batch is done or the carrier is
//!   full, and takes `C` again. While the carrier took everything, it takes
//!   and writes the core's next batch the same way (output other commands
//!   produced meanwhile, which would otherwise wait for `T`), up to the
//!   bytes of one write call ([`Outbox::call_limit`]), so that the
//!   session's reads never wait longer than one bounded write. Then, if
//!   anything is left (the rest
//!   of a batch, a flush, a shutdown) or `T` deferred a close of the side
//!   (H2), it sets `repoll` and wakes `T`, and releases `W`
//!   ([`WritePath::write_through`]); output left at the limit wakes `T` as
//!   any command's output does.
//! - W3: before it waits, `T` checks under `C`: `repoll`, then the write side
//!   ([`WritePath::take_before_wait`]): a busy side belongs to an application
//!   writing through, which writes the core's output and hands over what it
//!   leaves by W2; a free one gets a new batch if the core has output, and
//!   is polled again if `T` skipped it this round (H1).
//!
//! No batch is lost: what an application leaves is announced under `C`. If
//! `T` checked before, it registered its waker in the same critical section
//! and the announcement wakes it; otherwise `T` sees `repoll`. The carrier
//! never holds a waker of an application write: it is written only while
//! nobody waits for it to become writable (an idle side), and when it is
//! full the side is handed to `T`, which polls it with its own waker.
//!
//! The loom models in `loom.rs` check both protocols: the session task with
//! two readers (and with a reader cancelled after it registered in slot 1),
//! the hand-over with one and with two writers, and the session task
//! skipping a busy side on both paths; each fails without H1, without H2's
//! wake-up for a `WATCH` mark, or with `T` registering in slot 0 only after
//! it got the side.

use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use super::sync::{
    AtomicBool, AtomicU8, AtomicWaker, Mutex, Ordering, TryMutex, TryMutexGuard, try_lock_side,
};
use super::wake::{Defer, Locked};

/// Bytes an application read-through reads before it leaves a carrier
/// that keeps delivering to the session task (R4).
pub(crate) const READ_THROUGH_BYTES: usize = 128 * 1024;

/// What the session task needs from the holder of a side it skipped
/// (`contended`, H1 and H2): nothing,
const NONE: u8 = 0;
/// a wake-up when the carrier's readiness may have been consumed while it
/// skipped the read side,
const WATCH: u8 = 1;
/// or a wake-up in any case (a close it deferred).
const RUN: u8 = 2;

/// Slot of the session task.
const TASK: usize = 0;
/// Slot of the newest application read that reads through.
const READER: usize = 1;

/// The waker a pipe's carrier is read with: it wakes the session task and
/// the newest application read that reads through. It owns no carrier (a
/// carrier may drop its last waker inside its own I/O).
pub(crate) struct ReadWake {
    slots: [AtomicWaker; 2],
    /// Woken since the reader that holds the side last polled (set before
    /// the slots are emptied).
    fired: AtomicBool,
    /// Unset while the last poll of the carrier, by anyone, found nothing
    /// and armed the waker and nothing arrived since: a read-through has
    /// nothing to read then (it only registers in slot 1). Cleared before
    /// each poll, set by each wake-up and after each poll that read.
    readable: AtomicBool,
}

impl ReadWake {
    fn register(&self, slot: usize, waker: &Waker) {
        self.slots[slot].register(waker);
    }
}

impl Wake for ReadWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.readable.store(true, Ordering::SeqCst);
        self.fired.store(true, Ordering::SeqCst);
        for s in &self.slots {
            s.wake();
        }
    }
}

/// A side an application holds, with the hand-over it owes (H2). When the
/// holder unwinds out of the carrier's code (`io`: the core lock is not
/// held then), the guard still hands over: it takes the core lock, clears
/// the mark, asks the session task to poll again, and releases the side
/// before the core lock, so that a task that skipped the side is never left
/// waiting.
struct Held<'a, 'c, T, C: Defer, F: FnOnce(&mut C)> {
    side: Option<TryMutexGuard<'a, T>>,
    core: &'c Mutex<C>,
    contended: &'a AtomicU8,
    repoll: Option<F>,
    io: bool,
}

impl<T, C: Defer, F: FnOnce(&mut C)> Held<'_, '_, T, C, F> {
    fn side(&mut self) -> &mut T {
        self.side.as_mut().expect("held until handed over")
    }
}

impl<T, C: Defer, F: FnOnce(&mut C)> Drop for Held<'_, '_, T, C, F> {
    fn drop(&mut self) {
        if !self.io {
            // Unwinding out of the core's own code: the session is broken,
            // and its lock may be held by this thread.
            return;
        }
        let (Some(side), Some(repoll)) = (self.side.take(), self.repoll.take()) else {
            return;
        };
        let mut c = Locked::lock(self.core);
        self.contended.store(NONE, Ordering::Relaxed);
        repoll(&mut c);
        drop(side);
        drop(c);
    }
}

/// A carrier's readable half with its buffer.
pub(crate) trait Carrier {
    /// What one read produced.
    type Outcome;

    /// Reads once, at most `max` bytes.
    fn poll_read(&mut self, cx: &mut Context<'_>, max: usize) -> Poll<Self::Outcome>;

    /// The bytes an outcome carries.
    fn outcome_bytes(outcome: &Self::Outcome) -> usize;

    /// The half can still be read.
    fn is_open(&self) -> bool;

    /// Drops what ended in the last outcome (called without the core
    /// lock).
    fn release(&mut self) {}
}

/// What the session task's read of a pipe did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Polled {
    /// The carrier produced an outcome, handed to the core.
    Read,
    /// Nothing to read now (the pipe's waker is armed), or the side is
    /// closed.
    Idle,
    /// An application holds the side: skipped (H1 applies).
    Busy,
}

/// A pipe's read side (see the module documentation).
pub(crate) struct ReadPath<S> {
    side: TryMutex<S>,
    /// The side is closed (mirrors `!is_open()`).
    closed: AtomicBool,
    /// What the session task, which found the side busy before it waited,
    /// needs from the holder (H1): [`NONE`], [`WATCH`] or [`RUN`]; read and
    /// written under the core lock only.
    contended: AtomicU8,
    wake: Arc<ReadWake>,
    /// The waker the carrier is polled with, from `wake`.
    waker: Waker,
}

impl<S: Carrier> ReadPath<S> {
    pub(crate) fn new(side: S) -> Self {
        let wake = Arc::new(ReadWake {
            slots: [AtomicWaker::new(), AtomicWaker::new()],
            fired: AtomicBool::new(false),
            readable: AtomicBool::new(true),
        });
        Self {
            closed: AtomicBool::new(!side.is_open()),
            contended: AtomicU8::new(NONE),
            side: TryMutex::new(side),
            waker: Waker::from(wake.clone()),
            wake,
        }
    }

    /// The side is closed.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Tries the side outside the read path (the session task, to close it
    /// or free its buffer); `None` while an application reads through.
    pub(crate) fn try_side(&self) -> Option<TryMutexGuard<'_, S>> {
        try_lock_side(&self.side)
    }

    /// Closes the side with `close`, unless it is busy (`false`: the
    /// session task tries again after the holder handed over).
    pub(crate) fn try_close(&self, close: impl FnOnce(&mut S)) -> bool {
        let Some(mut side) = try_lock_side(&self.side) else {
            return false;
        };
        close(&mut side);
        self.closed.store(!side.is_open(), Ordering::Release);
        true
    }

    /// The session task reads the carrier once (R2): `apply` hands the
    /// outcome to the core. It registers in slot 0 once it has the side,
    /// before it polls; a busy side it skips, and the holder registers it
    /// at H2 if it waits.
    pub(crate) fn poll_task<C: Defer>(
        &self,
        core: &Mutex<C>,
        task: &Waker,
        apply: impl FnOnce(&mut S, S::Outcome, &mut C),
    ) -> Polled {
        if self.is_closed() {
            return Polled::Idle;
        }
        let Some(mut side) = try_lock_side(&self.side) else {
            return Polled::Busy;
        };
        if !side.is_open() {
            return Polled::Idle;
        }
        self.wake.register(TASK, task);
        self.wake.readable.store(false, Ordering::SeqCst);
        let Poll::Ready(outcome) =
            side.poll_read(&mut Context::from_waker(&self.waker), usize::MAX)
        else {
            return Polled::Idle;
        };
        // The carrier may hold more.
        self.wake.readable.store(true, Ordering::SeqCst);
        self.apply(&mut *side, core, outcome, apply);
        Polled::Read
    }

    /// The session task skipped the side this round and is about to wait,
    /// with the core locked (H1): `true` when the side is free now (poll it
    /// again); otherwise the holder is asked to wake it when the carrier's
    /// readiness may have been consumed meanwhile, or in any case with
    /// `run` (a close the task deferred).
    pub(crate) fn recheck_before_wait(&self, run: bool) -> bool {
        if try_lock_side(&self.side).is_some() {
            return true;
        }
        self.contended
            .fetch_max(if run { RUN } else { WATCH }, Ordering::Relaxed);
        false
    }

    /// Hands an outcome to the core under its lock; a carrier that ended is
    /// dropped after the lock (its drop is the application's code).
    fn apply<C: Defer>(
        &self,
        side: &mut S,
        core: &Mutex<C>,
        outcome: S::Outcome,
        apply: impl FnOnce(&mut S, S::Outcome, &mut C),
    ) {
        let mut c = Locked::lock(core);
        apply(side, outcome, &mut c);
        drop(c);
        side.release();
        self.closed.store(!side.is_open(), Ordering::Release);
    }

    /// An application read that found nothing reads the carrier through
    /// (R3, R4): `locked` is the core it holds; `apply` hands an outcome to
    /// the core, `repoll` asks the session task to read on. Returns the core,
    /// locked again, and whether it was unlocked meanwhile: then anything
    /// may have changed (the session task read, the session ended), and the
    /// caller looks again before it waits. Reads nothing, and keeps the
    /// core locked, when the side is busy (the session task or another
    /// reader has it) or closed.
    pub(crate) fn read_through<'a, C: Defer>(
        &self,
        core: &'a Mutex<C>,
        locked: Locked<'a, C>,
        reader: &Waker,
        mut apply: impl FnMut(&mut S, S::Outcome, &mut C),
        repoll: impl FnOnce(&mut C),
        task: impl FnOnce(&C) -> Option<Waker>,
    ) -> (Locked<'a, C>, bool) {
        if self.is_closed() {
            return (locked, false);
        }
        if !self.wake.readable.load(Ordering::SeqCst) {
            // Nothing arrived since the carrier was found empty: the next
            // arrival wakes this read too. (Leaving it to the session task,
            // which wakes the read when the data is for it, halved the
            // wake-ups but lengthened the loop that acknowledgements and
            // credit take through the reads: a quarter less multipath
            // throughput on Linux, while macOS gained.)
            self.wake.register(READER, reader);
            return (locked, false);
        }
        // Never waiting for the side under the core lock.
        let Some(side) = try_lock_side(&self.side) else {
            return (locked, false);
        };
        let mut held = Held {
            side: Some(side),
            core,
            contended: &self.contended,
            repoll: Some(repoll),
            io: false,
        };
        drop(locked);
        self.wake.register(READER, reader);
        // Whether the carrier may hold more with no waker armed (R4).
        let mut more = true;
        let mut bytes = 0;
        while bytes < READ_THROUGH_BYTES {
            let side = held.side();
            if !side.is_open() {
                more = false;
                break;
            }
            // A wake-up from here on means the readiness armed by this
            // poll was consumed.
            self.wake.fired.store(false, Ordering::SeqCst);
            self.wake.readable.store(false, Ordering::SeqCst);
            let left = READ_THROUGH_BYTES - bytes;
            held.io = true;
            let side = held.side();
            let polled = side.poll_read(&mut Context::from_waker(&self.waker), left);
            held.io = false;
            let Poll::Ready(outcome) = polled else {
                // The pipe's waker is armed: readiness reaches the task.
                more = false;
                break;
            };
            self.wake.readable.store(true, Ordering::SeqCst);
            bytes += S::outcome_bytes(&outcome);
            self.apply(held.side(), core, outcome, &mut apply);
        }
        // The hand-over below is the normal one.
        let side = held.side.take().expect("held");
        let repoll = held.repoll.take().expect("held");
        drop(held);
        // The side is released under the core lock (H2), and the core is
        // kept until the caller registered its read: nothing the session
        // task reads afterwards can slip past it. A task that skipped the
        // side waits in slot 0 for the readiness this read armed, unless it
        // fired already.
        let mut c = Locked::lock(core);
        // The mark is taken whatever this read leaves, so that it never
        // outlives the hand-over it asked for.
        let mark = self.contended.swap(NONE, Ordering::Relaxed);
        let wanted = more
            || match mark {
                NONE => false,
                WATCH => match task(&c) {
                    // The task waits: it waits in slot 0 for the readiness
                    // this read armed, unless that fired already.
                    Some(t) => {
                        self.wake.register(TASK, &t);
                        self.wake.fired.load(Ordering::SeqCst)
                    }
                    // The task runs, and polls the free side again.
                    None => false,
                },
                _ => true,
            };
        if wanted {
            repoll(&mut c);
        }
        drop(side);
        (c, true)
    }
}

/// A carrier's writable half with the batch being written.
pub(crate) trait Outbox {
    /// Nothing is being written and nobody waits for the carrier: a new
    /// batch may be taken and written through.
    fn idle(&self) -> bool;

    /// Writes the batch without a waker until it is done, the carrier is
    /// full (or failed: what is left is the session task's) or `budget`
    /// bytes are written; returns the bytes written.
    fn write_now(&mut self, budget: usize) -> usize;

    /// The most bytes one write call (and one write-through) hands the
    /// carrier.
    fn call_limit(&self) -> usize;

    /// A batch, a flush or a shutdown is left for the session task.
    fn has_work(&self) -> bool;
}

/// A pipe's write side (see the module documentation).
pub(crate) struct WritePath<W> {
    side: TryMutex<W>,
    /// The session task deferred a close of the side while it was busy
    /// (H1: [`RUN`]); read and written under the core lock only.
    contended: AtomicU8,
}

impl<W: Outbox> WritePath<W> {
    pub(crate) fn new(side: W) -> Self {
        Self {
            side: TryMutex::new(side),
            contended: AtomicU8::new(NONE),
        }
    }

    /// Tries the side (the session task, W1, or any holder of the core
    /// lock); `None` while an application writes through.
    pub(crate) fn try_side(&self) -> Option<TryMutexGuard<'_, W>> {
        try_lock_side(&self.side)
    }

    /// An application command that may have produced output writes it
    /// through (W2): `take` takes a batch from the core into the side
    /// (whether it did), `hand_over` asks the session task to take over.
    /// While the carrier takes everything, the next batch the core has
    /// meanwhile (other streams' output) is written too, up to the bytes of
    /// one write call in all. Returns the core, locked.
    pub(crate) fn write_through<'a, C: Defer>(
        &self,
        core: &'a Mutex<C>,
        mut locked: Locked<'a, C>,
        mut take: impl FnMut(&mut W, &mut C) -> bool,
        hand_over: impl FnOnce(&mut C),
    ) -> Locked<'a, C> {
        let Some(mut side) = try_lock_side(&self.side) else {
            return locked;
        };
        if !side.idle() || !take(&mut side, &mut locked) {
            drop(side);
            return locked;
        }
        let mut budget = side.call_limit();
        let mut held = Held {
            side: Some(side),
            core,
            contended: &self.contended,
            repoll: Some(hand_over),
            io: false,
        };
        loop {
            // No I/O under the core lock.
            drop(locked);
            held.io = true;
            let side = held.side();
            budget = budget.saturating_sub(side.write_now(budget));
            let left = side.has_work();
            held.io = false;
            locked = Locked::lock(core);
            if !left && budget > 0 && take(held.side(), &mut locked) {
                continue;
            }
            // Output left at the limit wakes the session task with the
            // command's other work; the side is released under the core
            // lock (H2).
            let side = held.side.take().expect("held");
            let hand_over = held.repoll.take().expect("held");
            if self.contended.swap(NONE, Ordering::Relaxed) == RUN || left {
                hand_over(&mut locked);
            }
            drop(side);
            return locked;
        }
    }

    /// The session task before it waits, with the core locked (W3, H1):
    /// takes a new batch with `take` when the side is free; returns whether
    /// the task has work. A side the task `skipped` this round that is free
    /// now is polled again (its holder may have consumed a wake-up of the
    /// task). A busy side belongs to an application writing through, which
    /// writes the core's output and hands over what it leaves; with `run`
    /// (a close the task deferred) it is asked to wake the task in any case.
    pub(crate) fn take_before_wait<C>(
        &self,
        core: &mut C,
        skipped: bool,
        run: bool,
        take: impl FnOnce(&mut W, &mut C) -> bool,
    ) -> bool {
        match try_lock_side(&self.side) {
            Some(mut side) => take(&mut side, core) || skipped || run,
            None => {
                if run {
                    self.contended.store(RUN, Ordering::Relaxed);
                }
                false
            }
        }
    }
}
