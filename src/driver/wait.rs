//! Waiting tasks and threads: lists that a cancelled wait leaves, the FIFO
//! queue of openers waiting for stream credit, and the end of a pipe.
//!
//! A wait registers its waker under the lock that guards its condition and
//! receives a [`Ticket`]. Whoever changes the condition moves the wakers into
//! the lock's [`WakeList`] (woken after unlocking, see [`super::wake`]). A
//! wait that ends before it is woken, because its future was dropped or its
//! thread timed out, removes its ticket, so that no list grows with waits
//! nobody completes.

// The waiter registry, its futures and `PipeDone` are the tokio driver's;
// the std driver uses the lists and the openers' queue.
#![cfg_attr(not(feature = "tokio"), allow(dead_code, unused_imports))]

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering as StdOrdering};
use std::task::{Context, Poll, Waker};

use super::sync::{Mutex, lock};
use super::wake::{Defer, Locked, WakeList};

/// A registration in a [`WaitList`]. Tickets increase in issue order across
/// the process, so a ticket never names another wait, even in another list,
/// and every list is sorted by ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Ticket(u64);

impl Ticket {
    fn next() -> Self {
        // Not a synchronization point: lists are ordered by the lock that
        // guards them, and fetch_add values follow that order.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Ticket(NEXT.fetch_add(1, StdOrdering::Relaxed))
    }
}

/// Waits for one condition, in arrival order.
#[derive(Default)]
pub(crate) struct WaitList {
    waiters: VecDeque<(Ticket, Waker)>,
}

impl WaitList {
    pub(crate) fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }

    /// Waits registered (for the leak tests).
    #[cfg(feature = "test-hooks")]
    pub(crate) fn len(&self) -> usize {
        self.waiters.len()
    }

    fn find(&self, ticket: Ticket) -> Option<usize> {
        self.waiters.binary_search_by_key(&ticket, |&(t, _)| t).ok()
    }

    /// Registers the wait holding `ticket` with `waker`, or refreshes its
    /// waker while it is still registered.
    pub(crate) fn register(&mut self, ticket: &mut Option<Ticket>, waker: &Waker) {
        if let Some(i) = ticket.and_then(|t| self.find(t)) {
            self.waiters[i].1.clone_from(waker);
            return;
        }
        let t = Ticket::next();
        self.waiters.push_back((t, waker.clone()));
        *ticket = Some(t);
    }

    /// Removes a wait; returns whether it was the first.
    pub(crate) fn remove(&mut self, ticket: Ticket) -> bool {
        match self.find(ticket) {
            Some(i) => {
                self.waiters.remove(i);
                i == 0
            }
            None => false,
        }
    }

    /// The first wait.
    pub(crate) fn first(&self) -> Option<Ticket> {
        self.waiters.front().map(|&(t, _)| t)
    }

    /// Wakes every wait; they leave the list.
    pub(crate) fn wake_all(&mut self, wakes: &mut WakeList) {
        wakes.extend(self.waiters.drain(..).map(|(_, w)| w));
    }

    /// Wakes every wait; they stay in the list.
    fn wake_all_staying(&self, wakes: &mut WakeList) {
        wakes.extend(self.waiters.iter().map(|(_, w)| w.clone()));
    }

    /// Wakes the first wait; it stays first.
    fn wake_first(&self, wakes: &mut WakeList) {
        if let Some((_, w)) = self.waiters.front() {
            wakes.push(w.clone());
        }
    }
}

/// What opening a stream did.
pub(crate) enum Attempt<K, E> {
    Opened(K),
    /// No stream credit.
    Blocked,
    Failed(E),
}

/// Openers waiting for stream credit of one type, served first come, first
/// served.
///
/// Only the first waiter tries to open; the others wait their turn. The
/// turn passes on whenever the first waiter leaves: it opened a stream
/// (there may be credit left), it failed, or it was cancelled (it may have
/// been woken for credit it will not use). An opener that does not wait
/// does not overtake waiters ([`OpenQueue::may_try`]). Once opening fails
/// for good (GOAWAY, shutdown, close), every waiter tries at once and fails.
///
/// A waiting opener checks its turn, opens in the core if it is its turn,
/// then settles the attempt: [`OpenQueue::turn`], [`OpenQueue::settle`].
#[derive(Default)]
pub(crate) struct OpenQueue {
    list: WaitList,
    failing: bool,
}

impl OpenQueue {
    /// Whether the opener holding `ticket` (`None` before it queued) may
    /// try to open now.
    pub(crate) fn turn(&self, ticket: Option<Ticket>) -> bool {
        self.failing
            || match ticket {
                None => self.list.is_empty(),
                Some(t) => self.list.first() == Some(t),
            }
    }

    /// Settles a waiting opener's poll: `attempt` is what opening did, or
    /// `None` when it was not its turn. A blocked opener queues (or keeps
    /// its place); one that is done leaves the queue.
    pub(crate) fn settle<K, E>(
        &mut self,
        ticket: &mut Option<Ticket>,
        attempt: Option<Attempt<K, E>>,
        waker: &Waker,
        wakes: &mut WakeList,
    ) -> Poll<Result<K, E>> {
        let r = match attempt {
            Some(Attempt::Opened(k)) => Ok(k),
            Some(Attempt::Failed(e)) => Err(e),
            Some(Attempt::Blocked) | None => {
                self.list.register(ticket, waker);
                return Poll::Pending;
            }
        };
        if let Some(t) = ticket.take() {
            self.leave(t, wakes);
        }
        Poll::Ready(r)
    }

    /// Whether an opener that does not wait may try: not while others wait
    /// for credit.
    pub(crate) fn may_try(&self) -> bool {
        self.failing || self.list.is_empty()
    }

    /// A waiter leaves (cancelled, or done): when it was first, the next one
    /// gets its turn.
    pub(crate) fn leave(&mut self, ticket: Ticket, wakes: &mut WakeList) {
        if self.list.remove(ticket) {
            self.list.wake_first(wakes);
        }
    }

    /// Stream credit arrived: the first waiter tries.
    pub(crate) fn credit(&self, wakes: &mut WakeList) {
        self.list.wake_first(wakes);
    }

    /// Opening fails from now on: every waiter tries (and fails).
    pub(crate) fn fail_all(&mut self, wakes: &mut WakeList) {
        self.failing = true;
        self.list.wake_all_staying(wakes);
    }

    /// Waiters queued.
    #[cfg(any(test, loom))]
    pub(crate) fn len(&self) -> usize {
        self.list.waiters.len()
    }
}

/// An opener that does not wait: what opening did, unless it would
/// overtake waiting openers (`None`: no credit now).
pub(crate) fn open_now<K, E>(
    queue: &OpenQueue,
    open: impl FnOnce() -> Attempt<K, E>,
) -> Option<Result<K, E>> {
    if !queue.may_try() {
        return None;
    }
    match open() {
        Attempt::Opened(k) => Some(Ok(k)),
        Attempt::Failed(e) => Some(Err(e)),
        Attempt::Blocked => None,
    }
}

/// Which list a [`Wait`] waits in.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum List<K> {
    Accept(usize),
    DatagramRecv,
    DatagramSend,
    State,
    /// `next_event` calls.
    Events,
    /// Pipe state changes (`Pipe::joined`).
    Pipes,
    /// `ping` calls (a QX_PING response arrived).
    Ping,
    /// The session's hook task (a hook's input arrived).
    Hook,
    Stopped(K),
    StreamDatagrams(K),
}

/// The blocked operations of a session, woken by the core's events. A
/// stream has at most one read and one write waiting (they take the handle
/// by `&mut`): its newest waker is kept, and dropping the handle removes it.
/// Every other wait may be shared, waits in a list in arrival order and
/// leaves it when it ends unresolved ([`Wait`]); openers wait their turn
/// ([`OpenQueue`]). Lists exist from their first wait on: a session nobody
/// waits on holds none.
pub(crate) struct Waiters<K> {
    readers: HashMap<K, Waker>,
    writers: HashMap<K, Waker>,
    /// The lists of a stream ([`List::Stopped`], [`List::StreamDatagrams`]),
    /// kept until its handle is gone.
    streams: HashMap<List<K>, WaitList>,
    /// The session's other lists.
    session: Vec<(List<K>, WaitList)>,
    pub(crate) open: [OpenQueue; 2],
}

impl<K> Default for Waiters<K> {
    fn default() -> Self {
        Self {
            readers: HashMap::new(),
            writers: HashMap::new(),
            streams: HashMap::new(),
            session: Vec::new(),
            open: Default::default(),
        }
    }
}

/// Keeps the newest waker of a stream's read or write.
fn register_one<K: Eq + Hash>(map: &mut HashMap<K, Waker>, key: K, waker: &Waker) {
    match map.get_mut(&key) {
        Some(w) => w.clone_from(waker),
        None => {
            map.insert(key, waker.clone());
        }
    }
}

impl<K: Copy + Eq + Hash> Waiters<K> {
    /// `list`, created if it does not exist yet.
    fn list(&mut self, list: List<K>) -> &mut WaitList {
        if matches!(list, List::Stopped(_) | List::StreamDatagrams(_)) {
            return self.streams.entry(list).or_default();
        }
        let i = match self.session.iter().position(|(l, _)| *l == list) {
            Some(i) => i,
            None => {
                self.session.push((list, WaitList::default()));
                self.session.len() - 1
            }
        };
        &mut self.session[i].1
    }

    /// `list`, if it exists.
    fn existing(&mut self, list: List<K>) -> Option<&mut WaitList> {
        if matches!(list, List::Stopped(_) | List::StreamDatagrams(_)) {
            return self.streams.get_mut(&list);
        }
        self.session
            .iter_mut()
            .find(|(l, _)| *l == list)
            .map(|(_, w)| w)
    }

    /// Every list.
    fn lists(&mut self) -> impl Iterator<Item = &mut WaitList> {
        self.streams
            .values_mut()
            .chain(self.session.iter_mut().map(|(_, w)| w))
    }

    /// Registers (or refreshes) the wait holding `ticket` in `list`.
    pub(crate) fn register(&mut self, list: List<K>, ticket: &mut Option<Ticket>, waker: &Waker) {
        self.list(list).register(ticket, waker);
    }

    /// A wait leaves `list`.
    pub(crate) fn remove(&mut self, list: List<K>, ticket: Ticket) {
        if let Some(l) = self.existing(list) {
            l.remove(ticket);
        }
    }

    /// A stream's read waits.
    pub(crate) fn register_reader(&mut self, key: K, waker: &Waker) {
        register_one(&mut self.readers, key, waker);
    }

    /// A stream's read polls again (or ended).
    pub(crate) fn remove_reader(&mut self, key: K) {
        self.readers.remove(&key);
    }

    /// A stream's write waits.
    pub(crate) fn register_writer(&mut self, key: K, waker: &Waker) {
        register_one(&mut self.writers, key, waker);
    }

    /// A stream's write no longer waits (it was cancelled).
    pub(crate) fn remove_writer(&mut self, key: K) {
        self.writers.remove(&key);
    }

    /// The receiving handle of a stream is gone.
    pub(crate) fn forget_recv(&mut self, key: K) {
        self.readers.remove(&key);
        self.streams.remove(&List::StreamDatagrams(key));
    }

    /// The sending handle of a stream is gone.
    pub(crate) fn forget_send(&mut self, key: K) {
        self.writers.remove(&key);
        self.streams.remove(&List::Stopped(key));
    }

    pub(crate) fn readable(&mut self, key: K, wakes: &mut WakeList) {
        if let Some(w) = self.readers.remove(&key) {
            wakes.push(w);
        }
    }

    pub(crate) fn writable(&mut self, key: K, wakes: &mut WakeList) {
        if let Some(w) = self.writers.remove(&key) {
            wakes.push(w);
        }
        // The list stays for the next wait until the handle is dropped.
        self.wake_list(List::Stopped(key), wakes);
    }

    pub(crate) fn stream_datagram(&mut self, key: K, wakes: &mut WakeList) {
        self.wake_list(List::StreamDatagrams(key), wakes);
    }

    pub(crate) fn wake_list(&mut self, list: List<K>, wakes: &mut WakeList) {
        if let Some(l) = self.existing(list) {
            l.wake_all(wakes);
        }
    }

    /// No stream opens from now on: waiting openers fail.
    pub(crate) fn fail_opens(&mut self, wakes: &mut WakeList) {
        for q in &mut self.open {
            q.fail_all(wakes);
        }
    }

    /// The session ended: every wait resolves.
    pub(crate) fn close(&mut self, wakes: &mut WakeList) {
        wakes.extend(self.readers.drain().map(|(_, w)| w));
        wakes.extend(self.writers.drain().map(|(_, w)| w));
        for l in self.lists() {
            l.wake_all(wakes);
        }
        self.fail_opens(wakes);
    }

    /// Entries held (registered waits, and per-stream lists even when
    /// empty), for the leak tests ([`super::resources::Tables`]).
    #[cfg(feature = "test-hooks")]
    pub(crate) fn entries(&self) -> usize {
        self.readers.len()
            + self.writers.len()
            + self
                .streams
                .values()
                .map(|l| l.waiters.len().max(1))
                .sum::<usize>()
            + self
                .session
                .iter()
                .filter(|(l, _)| *l != List::Hook)
                .map(|(_, w)| w.waiters.len())
                .sum::<usize>()
            + self
                .open
                .iter()
                .map(|q| q.list.waiters.len())
                .sum::<usize>()
    }

    /// Nothing is registered (openers aside, which leave by themselves).
    #[cfg(any(test, loom))]
    pub(crate) fn is_idle(&self) -> bool {
        self.readers.is_empty()
            && self.writers.is_empty()
            && self.streams.values().all(WaitList::is_empty)
            && self.session.iter().all(|(_, w)| w.is_empty())
            && self.open.iter().all(|q| q.list.is_empty())
    }
}

/// Session state with [`Waiters`].
pub(crate) trait Waiting: Defer {
    type Key: Copy + Eq + Hash + Unpin;

    /// The waits, and the wake-ups for after the lock.
    fn waits(&mut self) -> (&mut Waiters<Self::Key>, &mut WakeList);
}

/// A wait on the session: `step` runs under the core lock until it returns
/// a result; meanwhile the task waits in `list`. Dropped while waiting, it
/// leaves the list.
pub(crate) struct Wait<'a, T: Waiting, F> {
    mutex: &'a Mutex<T>,
    list: List<T::Key>,
    ticket: Option<Ticket>,
    step: F,
}

impl<'a, T: Waiting, F> Wait<'a, T, F> {
    pub(crate) fn new(mutex: &'a Mutex<T>, list: List<T::Key>, step: F) -> Self {
        Self {
            mutex,
            list,
            ticket: None,
            step,
        }
    }
}

impl<T: Waiting, R, F: FnMut(&mut T) -> Option<R> + Unpin> Future for Wait<'_, T, F> {
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        let this = self.get_mut();
        let mut state = Locked::lock(this.mutex);
        let r = (this.step)(&mut *state);
        let (waiters, _) = state.waits();
        match r {
            Some(r) => {
                if let Some(t) = this.ticket.take() {
                    waiters.remove(this.list, t);
                }
                Poll::Ready(r)
            }
            None => {
                // Under the lock that checked the condition: whoever changes
                // it next sees this wait.
                waiters.register(this.list, &mut this.ticket, cx.waker());
                Poll::Pending
            }
        }
    }
}

impl<T: Waiting, F> Drop for Wait<'_, T, F> {
    fn drop(&mut self) {
        if let Some(t) = self.ticket.take() {
            Locked::lock(self.mutex).waits().0.remove(self.list, t);
        }
    }
}

/// Opening a stream of type `dir` (0 bidirectional, 1 unidirectional),
/// waiting for stream credit in arrival order: `open` opens in the core,
/// `after` ends the command (a blocked open may owe the peer a
/// STREAMS_BLOCKED). Dropped while waiting, it leaves the queue and passes
/// its turn on.
pub(crate) struct Open<'a, T: Waiting, F, A> {
    mutex: &'a Mutex<T>,
    dir: usize,
    ticket: Option<Ticket>,
    open: F,
    after: A,
}

impl<'a, T: Waiting, F, A> Open<'a, T, F, A> {
    pub(crate) fn new(mutex: &'a Mutex<T>, dir: usize, open: F, after: A) -> Self {
        Self {
            mutex,
            dir,
            ticket: None,
            open,
            after,
        }
    }
}

impl<T, K, E, F, A> Future for Open<'_, T, F, A>
where
    T: Waiting,
    F: FnMut(&mut T) -> Attempt<K, E> + Unpin,
    A: FnMut(&mut T) + Unpin,
{
    type Output = Result<K, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<K, E>> {
        let this = self.get_mut();
        let mut state = Locked::lock(this.mutex);
        let turn = state.waits().0.open[this.dir].turn(this.ticket);
        let attempt = turn.then(|| (this.open)(&mut *state));
        let (waiters, wakes) = state.waits();
        let r = waiters.open[this.dir].settle(&mut this.ticket, attempt, cx.waker(), wakes);
        (this.after)(&mut *state);
        r
    }
}

impl<T: Waiting, F, A> Drop for Open<'_, T, F, A> {
    fn drop(&mut self) {
        if let Some(t) = self.ticket.take() {
            let mut state = Locked::lock(self.mutex);
            let (waiters, wakes) = state.waits();
            waiters.open[self.dir].leave(t, wakes);
        }
    }
}

/// Resolves when a pipe was closed (a listener's `handle_pipe` lives as long
/// as its pipe).
#[derive(Default)]
pub(crate) struct PipeDone {
    state: Mutex<DoneState>,
}

#[derive(Default)]
struct DoneState {
    done: bool,
    waiters: WaitList,
}

impl PipeDone {
    /// Marks the pipe closed; the waits are woken with `wakes` (after the
    /// caller's lock).
    pub(crate) fn finish_into(&self, wakes: &mut WakeList) {
        let mut s = lock(&self.state);
        s.done = true;
        s.waiters.wake_all(wakes);
    }

    /// Whether the pipe was closed; else registers the wait holding
    /// `ticket`.
    pub(crate) fn poll_done(&self, ticket: &mut Option<Ticket>, cx: &Context<'_>) -> Poll<()> {
        let mut s = lock(&self.state);
        if s.done {
            if let Some(t) = ticket.take() {
                s.waiters.remove(t);
            }
            return Poll::Ready(());
        }
        s.waiters.register(ticket, cx.waker());
        Poll::Pending
    }

    /// A wait ends unresolved (its future was dropped).
    pub(crate) fn cancel(&self, ticket: Ticket) {
        lock(&self.state).waiters.remove(ticket);
    }

    /// Waits registered.
    #[cfg(any(test, loom))]
    pub(crate) fn waiting(&self) -> usize {
        lock(&self.state).waiters.waiters.len()
    }

    /// Resolves when the pipe was closed.
    pub(crate) fn wait(&self) -> DoneWait<'_> {
        DoneWait {
            done: self,
            ticket: None,
        }
    }
}

/// The future of [`PipeDone::wait`]; dropped early, it leaves the list.
pub(crate) struct DoneWait<'a> {
    done: &'a PipeDone,
    ticket: Option<Ticket>,
}

impl Future for DoneWait<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        this.done.poll_done(&mut this.ticket, cx)
    }
}

impl Drop for DoneWait<'_> {
    fn drop(&mut self) {
        if let Some(t) = self.ticket.take() {
            self.done.cancel(t);
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    use super::*;

    /// A waker that counts its wake-ups.
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn counter() -> (Arc<Count>, Waker) {
        let c = Arc::new(Count(AtomicUsize::new(0)));
        (c.clone(), Waker::from(c))
    }

    fn woken(c: &Count) -> usize {
        c.0.load(Ordering::Relaxed)
    }

    #[test]
    fn a_wait_list_keeps_arrival_order_and_lets_waits_leave() {
        let (a, wa) = counter();
        let (b, wb) = counter();
        let mut list = WaitList::default();
        let (mut ta, mut tb) = (None, None);
        list.register(&mut ta, &wa);
        list.register(&mut tb, &wb);
        // Registering again keeps the place.
        list.register(&mut ta, &wa);
        assert_eq!(list.first(), ta);
        assert!(list.remove(ta.unwrap()));
        assert!(!list.remove(ta.unwrap()), "a ticket leaves once");
        let mut wakes = WakeList::default();
        list.wake_all(&mut wakes);
        drop(wakes);
        assert_eq!((woken(&a), woken(&b)), (0, 1));
        assert!(list.is_empty());
        // A stale ticket registers anew, at the end.
        list.register(&mut tb, &wb);
        assert!(tb.is_some() && !list.is_empty());
    }

    fn try_open(
        q: &mut OpenQueue,
        t: &mut Option<Ticket>,
        w: &Waker,
        credit: &mut u32,
    ) -> Poll<Result<u32, ()>> {
        let mut wakes = WakeList::default();
        let attempt = q.turn(*t).then(|| {
            if *credit > 0 {
                *credit -= 1;
                Attempt::Opened(*credit)
            } else {
                Attempt::Blocked
            }
        });
        q.settle(t, attempt, w, &mut wakes)
    }

    #[test]
    fn openers_are_served_in_order_and_a_cancelled_one_passes_its_turn() {
        let mut q = OpenQueue::default();
        let mut credit = 0;
        let (a, wa) = counter();
        let (b, wb) = counter();
        let (c, wc) = counter();
        let (mut ta, mut tb, mut tc) = (None, None, None);
        assert!(try_open(&mut q, &mut ta, &wa, &mut credit).is_pending());
        assert!(try_open(&mut q, &mut tb, &wb, &mut credit).is_pending());
        assert!(try_open(&mut q, &mut tc, &wc, &mut credit).is_pending());
        assert_eq!(q.len(), 3);
        // Credit for one: only the first is woken.
        credit = 1;
        let mut wakes = WakeList::default();
        q.credit(&mut wakes);
        drop(wakes);
        assert_eq!((woken(&a), woken(&b), woken(&c)), (1, 0, 0));
        // Not its turn: the second does not take it.
        assert!(try_open(&mut q, &mut tb, &wb, &mut credit).is_pending());
        assert_eq!(credit, 1);
        // The first is cancelled: the second gets the turn.
        let mut wakes = WakeList::default();
        q.leave(ta.take().unwrap(), &mut wakes);
        drop(wakes);
        assert_eq!(woken(&b), 1);
        assert_eq!(
            try_open(&mut q, &mut tb, &wb, &mut credit),
            Poll::Ready(Ok(0))
        );
        // Leaving first passes the turn on: the third tries (no credit).
        assert_eq!(woken(&c), 1);
        assert!(try_open(&mut q, &mut tc, &wc, &mut credit).is_pending());
        // A non-waiting opener does not overtake.
        credit = 1;
        assert!(open_now(&q, || -> Attempt<(), ()> { panic!("overtook") }).is_none());
        assert_eq!(
            try_open(&mut q, &mut tc, &wc, &mut credit),
            Poll::Ready(Ok(0))
        );
        assert_eq!(q.len(), 0);
        assert!(q.may_try());
    }

    #[test]
    fn failing_opens_wake_every_waiter() {
        let mut q = OpenQueue::default();
        let (a, wa) = counter();
        let (b, wb) = counter();
        let (mut ta, mut tb) = (None, None);
        let mut wakes = WakeList::default();
        assert!(
            q.settle::<(), ()>(&mut ta, Some(Attempt::Blocked), &wa, &mut wakes)
                .is_pending()
        );
        assert!(
            q.settle::<(), ()>(&mut tb, None, &wb, &mut wakes)
                .is_pending()
        );
        q.fail_all(&mut wakes);
        drop(wakes);
        assert_eq!((woken(&a), woken(&b)), (1, 1));
        // Everyone's turn; each fails and leaves.
        let mut wakes = WakeList::default();
        assert!(q.turn(tb));
        assert_eq!(
            q.settle::<(), ()>(&mut tb, Some(Attempt::Failed(())), &wb, &mut wakes),
            Poll::Ready(Err(()))
        );
        assert_eq!(
            q.settle::<(), ()>(&mut ta, Some(Attempt::Failed(())), &wa, &mut wakes),
            Poll::Ready(Err(()))
        );
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn closing_wakes_every_wait() {
        let mut w = Waiters::<u32>::default();
        let (c, waker) = counter();
        w.register_reader(1, &waker);
        w.register_writer(1, &waker);
        let (mut t1, mut t2, mut t3) = (None, None, None);
        w.register(List::Accept(0), &mut t1, &waker);
        w.register(List::Stopped(1), &mut t2, &waker);
        w.register(List::State, &mut t3, &waker);
        let mut to = None;
        let mut wakes = WakeList::default();
        assert!(
            w.open[0]
                .settle::<(), ()>(&mut to, Some(Attempt::Blocked), &waker, &mut wakes)
                .is_pending()
        );
        w.close(&mut wakes);
        drop(wakes);
        assert_eq!(woken(&c), 6);
        // The opener leaves when it fails; the rest left already.
        assert!(!w.is_idle());
        w.open[0].leave(to.unwrap(), &mut WakeList::default());
        assert!(w.is_idle());
    }

    #[test]
    fn a_cancelled_done_wait_leaves() {
        let done = PipeDone::default();
        let (c, waker) = counter();
        let cx = Context::from_waker(&waker);
        let mut t = None;
        assert!(done.poll_done(&mut t, &cx).is_pending());
        assert_eq!(done.waiting(), 1);
        done.cancel(t.take().unwrap());
        assert_eq!(done.waiting(), 0);
        assert!(done.poll_done(&mut t, &cx).is_pending());
        let mut wakes = WakeList::default();
        done.finish_into(&mut wakes);
        assert_eq!(woken(&c), 0, "woken only after the caller's lock");
        drop(wakes);
        assert_eq!(woken(&c), 1);
        assert!(done.poll_done(&mut t, &cx).is_ready());
    }
}
