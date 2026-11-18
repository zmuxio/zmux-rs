//! The observing hooks as a subscription: what the logger, the tracer and
//! `on_memory_pressure` are told, queued for the host to read when it wants
//! ([`crate::Config::events`], [`crate::ListenerConfig::events`]) instead of
//! a callback on the thread that produced it. Pushing never blocks and
//! never waits for the host.
//!
//! The trace records of a session have a backlog of their own, fixed at
//! 256 events per session: an event that finds it full is
//! dropped and counted, and the count is read as a
//! [`TraceRecord::Dropped`] of that session where the dropped events would
//! have stood (before the next event accepted, or before the end,
//! whichever comes first). A session's `Established`, its `Dropped` counts
//! and its `Closed` take no room from the backlog and are never dropped; the
//! session's `Closed` is its last record. The log lines and the memory
//! pressure reports share the capacity the subscription was made with:
//! past it the newly arriving one is dropped and counted, and the count is
//! read as [`HostEvent::Overflowed`] before the next one queued after them
//! (or, when none follows, once the queue is read empty); it is never
//! reported through a trace record.
//!
//! This is the one queue of the observing hooks: the tracer callback of a
//! session is a reader of such a queue too (its hook context calls the
//! tracer for what it reads), so there is no second queue and no second
//! count between an event and its observer.
//!
//! Each `events` call makes a subscription of its own, beside the hooks set
//! before (which keep being called): two subscriptions each read every
//! event. The clones of one [`HostEvents`] read one queue, each event once.
//! A subscription ends when the reader closes it ([`HostEvents::close`]),
//! when every clone of the reader is dropped (which closes it), or when
//! everything that writes to it is gone: the configuration it was made on,
//! its clones, and the sessions or listener made with them.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use super::listener::MemoryPressure;
use super::session::{LogLevel, SessionId, TraceRecord};

/// What a [`HostEvents`] subscription reads.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostEvent {
    /// A message of the logger.
    Log {
        /// The session that logged it; `None` for a listener's line.
        session: Option<SessionId>,
        /// Its level.
        level: LogLevel,
        /// The message.
        message: String,
    },
    /// What the tracer is told of a session.
    Trace {
        /// The session.
        session: SessionId,
        /// The record.
        record: TraceRecord,
    },
    /// A listener's memory pressure started or ended.
    MemoryPressure(MemoryPressure),
    /// The subscription's queue was full of log lines and memory pressure
    /// reports: this many that arrived were dropped, after the ones read
    /// before this and before the next one. Trace records are not among
    /// them: a session's lost events are counted in its own
    /// [`TraceRecord::Dropped`].
    Overflowed(u64),
}

/// The log lines a session has queued unread, at most; fixed.
#[cfg(any(feature = "tokio", feature = "blocking", test))]
pub(crate) const LOG_BACKLOG: usize = 256;

/// The events a session's trace backlog holds, at most; fixed.
#[cfg(any(feature = "tokio", feature = "blocking", test))]
pub(crate) const TRACE_BACKLOG: usize = 256;

/// What the queue holds of one session's trace records.
#[derive(Default)]
struct Backlog {
    /// Events queued and not read: those count against the backlog.
    queued: usize,
    /// Log lines queued and not read.
    logs: usize,
    /// Events dropped since the last `Dropped` record was queued.
    dropped: u64,
}

struct Queue {
    items: VecDeque<HostEvent>,
    /// Log lines and memory pressure reports queued, and the most there
    /// may be.
    others: usize,
    capacity: usize,
    /// Of those, dropped since the last `Overflowed` was queued.
    dropped: u64,
    /// The trace backlogs, by session; an entry lasts while it holds
    /// something.
    sessions: HashMap<SessionId, Backlog>,
    senders: usize,
    /// The clones of the reading end.
    readers: usize,
    /// Closed by the reader, or every reader dropped.
    closed: bool,
    /// The readers waiting, by key; each leaves when its future ends.
    waiters: Vec<(u64, Waker)>,
    next_key: u64,
}

impl Queue {
    fn ended(&self) -> bool {
        self.closed || self.senders == 0
    }
}

struct Chan(Mutex<Queue>);

impl Chan {
    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The reading end of a subscription; cheap to clone, the clones read the
/// same queue (each event once). Dropping the last clone closes it.
pub struct HostEvents(Arc<Chan>);

/// The writing end of a subscription, held by the hooks it replaces.
pub(crate) struct Sender(Arc<Chan>);

impl HostEvents {
    /// A subscription holding `capacity` log lines and memory pressure
    /// reports (at least 1), whatever the trace backlogs hold, and its
    /// writing end.
    pub(crate) fn channel(capacity: usize) -> (Self, Sender) {
        let chan = Arc::new(Chan(Mutex::new(Queue {
            items: VecDeque::new(),
            others: 0,
            capacity: capacity.max(1),
            dropped: 0,
            sessions: HashMap::new(),
            senders: 1,
            readers: 1,
            closed: false,
            waiters: Vec::new(),
            next_key: 0,
        })));
        (Self(chan.clone()), Sender(chan))
    }

    /// The next event, once one is queued; `None` once the subscription
    /// ended (closed, or everything that writes to it gone) and the queue
    /// is empty. Cancel-safe: a future dropped unfinished took nothing and
    /// leaves nothing behind.
    pub fn next(&self) -> impl Future<Output = Option<HostEvent>> + Send + '_ {
        Next {
            chan: &self.0,
            key: None,
        }
    }

    /// The next event if one is queued, without waiting.
    #[must_use]
    pub fn try_next(&self) -> Option<HostEvent> {
        self.0.lock().pop()
    }

    /// Ends the subscription for every clone: what is queued is discarded,
    /// nothing more is queued, and [`HostEvents::next`] returns `None`. The
    /// hooks stay set on the configuration and do nothing.
    pub fn close(&self) {
        let waiters = close(&mut self.0.lock());
        for (_, w) in waiters {
            w.wake();
        }
    }

    /// Whether the subscription ended: closed, or everything that writes
    /// to it gone.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.0.lock().ended()
    }
}

impl Clone for HostEvents {
    fn clone(&self) -> Self {
        self.0.lock().readers += 1;
        Self(self.0.clone())
    }
}

impl Drop for HostEvents {
    /// The last reader gone, nothing more is queued: writers stop paying
    /// for events nobody reads. No reader is left to wake.
    fn drop(&mut self) {
        let mut q = self.0.lock();
        q.readers -= 1;
        if q.readers == 0 {
            close(&mut q);
        }
    }
}

/// Closes the queue; returns the readers to wake.
fn close(q: &mut Queue) -> Vec<(u64, Waker)> {
    q.closed = true;
    q.items.clear();
    q.others = 0;
    q.dropped = 0;
    q.sessions.clear();
    std::mem::take(&mut q.waiters)
}

/// [`HostEvents::next`].
struct Next<'a> {
    chan: &'a Chan,
    key: Option<u64>,
}

impl Future for Next<'_> {
    type Output = Option<HostEvent>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut q = this.chan.lock();
        let ready = match q.pop() {
            Some(e) => Some(Some(e)),
            None if q.ended() => Some(None),
            None => None,
        };
        if let Some(r) = ready {
            if let Some(k) = this.key.take() {
                q.waiters.retain(|w| w.0 != k);
            }
            return Poll::Ready(r);
        }
        let key = this.key;
        if let Some(w) = key.and_then(|k| q.waiters.iter_mut().find(|w| w.0 == k)) {
            w.1.clone_from(cx.waker());
        } else {
            let k = q.next_key;
            q.next_key += 1;
            q.waiters.push((k, cx.waker().clone()));
            this.key = Some(k);
        }
        Poll::Pending
    }
}

impl Drop for Next<'_> {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            self.chan.lock().waiters.retain(|w| w.0 != k);
        }
    }
}

impl fmt::Debug for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sender(..)")
    }
}

impl fmt::Debug for HostEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let q = self.0.lock();
        f.debug_struct("HostEvents")
            .field("queued", &q.items.len())
            .field("dropped", &q.dropped)
            .field("closed", &q.ended())
            .finish_non_exhaustive()
    }
}

impl Sender {
    /// Queues a log line or a memory pressure report, dropping it (and
    /// counting it) when the queue is full of them; nothing once the
    /// subscription is closed.
    pub(crate) fn push(&self, event: HostEvent) {
        let waiters = {
            let mut q = self.0.lock();
            if q.closed {
                return;
            }
            if q.others >= q.capacity {
                q.dropped += 1;
                return;
            }
            if q.dropped > 0 {
                let n = std::mem::take(&mut q.dropped);
                q.items.push_back(HostEvent::Overflowed(n));
                q.others += 1;
            }
            q.items.push_back(event);
            q.others += 1;
            std::mem::take(&mut q.waiters)
        };
        // Woken readers register again if they find nothing.
        for (_, w) in waiters {
            w.wake();
        }
    }

    /// Queues a log line of `session`; `false` when the session already has
    /// 256 lines queued unread and this one is dropped (the caller counts it
    /// in `log_lines_dropped`).
    #[cfg(any(feature = "tokio", feature = "blocking", test))]
    pub(crate) fn push_log(
        &self,
        session: SessionId,
        level: LogLevel,
        message: &str,
        wake: &mut dyn FnMut(Waker),
    ) -> bool {
        let waiters = {
            let mut q = self.0.lock();
            if q.closed {
                return true;
            }
            let backlog = q.sessions.entry(session).or_default();
            if backlog.logs >= LOG_BACKLOG {
                return false;
            }
            backlog.logs += 1;
            q.items.push_back(HostEvent::Log {
                session: Some(session),
                level,
                message: message.to_owned(),
            });
            std::mem::take(&mut q.waiters)
        };
        for (_, w) in waiters {
            wake(w);
        }
        true
    }

    /// Queues `record` of `session`, and nothing once the subscription is
    /// closed. An event past the session's backlog is dropped and counted,
    /// the count queued as a `Dropped` before the next event the backlog
    /// accepts or before `Closed`. The readers to wake go to `wake`, for a
    /// caller that holds a lock until it may wake them.
    #[cfg(any(feature = "tokio", feature = "blocking", test))]
    pub(crate) fn push_trace(
        &self,
        session: SessionId,
        record: &TraceRecord,
        wake: &mut dyn FnMut(Waker),
    ) {
        let waiters = {
            let mut q = self.0.lock();
            if q.closed {
                return;
            }
            let lost = if matches!(record, TraceRecord::Event(_)) {
                let backlog = q.sessions.entry(session).or_default();
                if backlog.queued >= TRACE_BACKLOG {
                    backlog.dropped += 1;
                    return;
                }
                backlog.queued += 1;
                std::mem::take(&mut backlog.dropped)
            } else if let Some(backlog) = q.sessions.get_mut(&session) {
                let lost = std::mem::take(&mut backlog.dropped);
                if backlog.queued == 0 && backlog.logs == 0 {
                    q.sessions.remove(&session);
                }
                lost
            } else {
                0
            };
            if lost > 0 {
                q.items.push_back(HostEvent::Trace {
                    session,
                    record: TraceRecord::Dropped(lost),
                });
            }
            q.items.push_back(HostEvent::Trace {
                session,
                record: record.clone(),
            });
            std::mem::take(&mut q.waiters)
        };
        for (_, w) in waiters {
            wake(w);
        }
    }
}

impl Queue {
    /// Takes one item of `session`'s backlog off its count, and the entry
    /// once it holds nothing.
    fn release(&mut self, session: SessionId, take: impl FnOnce(&mut Backlog)) {
        if let Some(b) = self.sessions.get_mut(&session) {
            take(b);
            if b.queued == 0 && b.logs == 0 && b.dropped == 0 {
                self.sessions.remove(&session);
            }
        }
    }

    /// The next item; what was dropped after the last queued one, once all
    /// is read.
    fn pop(&mut self) -> Option<HostEvent> {
        let Some(item) = self.items.pop_front() else {
            return (self.dropped > 0)
                .then(|| HostEvent::Overflowed(std::mem::take(&mut self.dropped)));
        };
        match &item {
            HostEvent::Trace {
                session,
                record: TraceRecord::Event(_),
            } => self.release(*session, |b| b.queued -= 1),
            HostEvent::Log {
                session: Some(session),
                ..
            } => self.release(*session, |b| b.logs -= 1),
            HostEvent::Trace { .. } => {}
            _ => self.others -= 1,
        }
        Some(item)
    }
}

impl Clone for Sender {
    fn clone(&self) -> Self {
        self.0.lock().senders += 1;
        Self(self.0.clone())
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        let waiters = {
            let mut q = self.0.lock();
            q.senders -= 1;
            if q.senders > 0 {
                return;
            }
            std::mem::take(&mut q.waiters)
        };
        for (_, w) in waiters {
            w.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(i: u8) -> HostEvent {
        HostEvent::Log {
            session: None,
            level: LogLevel::Info,
            message: i.to_string(),
        }
    }

    #[test]
    fn overflow_drops_the_new_and_counts() {
        let (events, tx) = HostEvents::channel(2);
        for i in 0..4u8 {
            tx.push(log(i));
        }
        assert_eq!(events.try_next(), Some(log(0)));
        assert_eq!(events.try_next(), Some(log(1)));
        // What was dropped follows what was queued.
        assert_eq!(events.try_next(), Some(HostEvent::Overflowed(2)));
        assert_eq!(events.try_next(), None);
        let tx2 = tx.clone();
        drop(tx);
        assert!(!events.is_closed());
        drop(tx2);
        assert!(events.is_closed());
        let mut next = std::pin::pin!(events.next());
        let cx = &mut Context::from_waker(Waker::noop());
        assert_eq!(next.as_mut().poll(cx), Poll::Ready(None));
    }

    #[test]
    fn the_count_stands_before_the_next_queued_event() {
        let (events, tx) = HostEvents::channel(1);
        tx.push(log(0));
        tx.push(log(1));
        tx.push(log(2));
        assert_eq!(events.try_next(), Some(log(0)));
        tx.push(log(3));
        assert_eq!(events.try_next(), Some(HostEvent::Overflowed(2)));
        assert_eq!(events.try_next(), Some(log(3)));
        assert_eq!(events.try_next(), None);
    }

    fn push_trace(tx: &Sender, session: SessionId, record: &TraceRecord) {
        tx.push_trace(session, record, &mut |_| {});
    }

    fn event(i: u64) -> TraceRecord {
        TraceRecord::Event(crate::SessionEvent::CarrierChosen(
            crate::CarrierKind::Quic,
            Some(i.to_string().into()),
        ))
    }

    fn read(events: &HostEvents) -> Vec<(SessionId, TraceRecord)> {
        std::iter::from_fn(|| events.try_next())
            .map(|e| match e {
                HostEvent::Trace { session, record } => (session, record),
                other => panic!("not a trace: {other:?}"),
            })
            .collect()
    }

    /// A session's backlog is 256 events whatever the capacity; its
    /// `Established`, `Dropped` and `Closed` take no room, the count stands
    /// where the dropped events stood (before the end here) and the end is
    /// last.
    #[test]
    fn a_full_backlog_drops_the_new_events_and_counts() {
        let (events, tx) = HostEvents::channel(1);
        let s = SessionId::next();
        push_trace(&tx, s, &TraceRecord::Established);
        for i in 0..TRACE_BACKLOG as u64 + 10 {
            push_trace(&tx, s, &event(i));
        }
        push_trace(
            &tx,
            s,
            &TraceRecord::Closed(crate::SessionError::HandshakeTimeout),
        );
        let got = read(&events);
        assert_eq!(got.len(), TRACE_BACKLOG + 3);
        assert_eq!(got[0].1, TraceRecord::Established);
        assert_eq!(got[TRACE_BACKLOG].1.clone(), event(255));
        assert_eq!(got[TRACE_BACKLOG + 1].1, TraceRecord::Dropped(10));
        assert!(matches!(got[TRACE_BACKLOG + 2].1, TraceRecord::Closed(_)));
        assert!(got.iter().all(|(id, _)| *id == s));
        assert!(events.0.lock().sessions.is_empty());
    }

    /// The count is queued before the next event the backlog accepts, and
    /// reading frees room: nothing queued is replaced by what arrives.
    #[test]
    fn the_count_stands_before_the_next_accepted_event() {
        let (events, tx) = HostEvents::channel(1);
        let s = SessionId::next();
        push_trace(&tx, s, &TraceRecord::Established);
        for i in 0..TRACE_BACKLOG as u64 + 3 {
            push_trace(&tx, s, &event(i));
        }
        // Read the start and the first two events: room for two.
        for _ in 0..3 {
            assert!(events.try_next().is_some());
        }
        push_trace(&tx, s, &event(7));
        push_trace(&tx, s, &event(8));
        push_trace(&tx, s, &event(9));
        let got: Vec<_> = read(&events).into_iter().map(|(_, r)| r).collect();
        let tail = &got[got.len() - 5..];
        assert_eq!(tail[0], event(254));
        assert_eq!(tail[1], event(255));
        assert_eq!(tail[2], TraceRecord::Dropped(3));
        assert_eq!(tail[3], event(7));
        assert_eq!(tail[4], event(8));
        // The third was dropped again and is counted for the next.
        push_trace(
            &tx,
            s,
            &TraceRecord::Closed(crate::SessionError::HandshakeTimeout),
        );
        let got: Vec<_> = read(&events).into_iter().map(|(_, r)| r).collect();
        assert_eq!(got[0], TraceRecord::Dropped(1));
        assert!(matches!(got[1], TraceRecord::Closed(_)));
    }

    /// Backlogs are per session: one session's full backlog costs another
    /// nothing, and the counts go to their own session.
    #[test]
    fn backlogs_are_per_session() {
        let (events, tx) = HostEvents::channel(1);
        let (a, b) = (SessionId::next(), SessionId::next());
        for i in 0..TRACE_BACKLOG as u64 + 2 {
            push_trace(&tx, a, &event(i));
        }
        push_trace(&tx, b, &event(1));
        push_trace(
            &tx,
            a,
            &TraceRecord::Closed(crate::SessionError::HandshakeTimeout),
        );
        push_trace(
            &tx,
            b,
            &TraceRecord::Closed(crate::SessionError::HandshakeTimeout),
        );
        let got = read(&events);
        assert!(got.contains(&(a, TraceRecord::Dropped(2))));
        assert!(got.contains(&(b, event(1))));
        assert!(
            !got.iter()
                .any(|(s, r)| *s == b && matches!(r, TraceRecord::Dropped(_)))
        );
        assert!(events.0.lock().sessions.is_empty());
    }

    /// A session's log lines have a backlog of 256 of their own: the next
    /// is refused, reading frees room, and the entry goes with the last.
    #[test]
    fn a_sessions_log_backlog_refuses_the_line_past_256() {
        let (events, tx) = HostEvents::channel(1);
        let (a, b) = (SessionId::next(), SessionId::next());
        let line = |s, tx: &Sender| tx.push_log(s, LogLevel::Info, "x", &mut |_| {});
        for _ in 0..LOG_BACKLOG {
            assert!(line(a, &tx));
        }
        assert!(!line(a, &tx));
        assert!(line(b, &tx));
        assert!(events.try_next().is_some());
        assert!(line(a, &tx));
        while events.try_next().is_some() {}
        assert!(events.0.lock().sessions.is_empty());
    }

    /// Log lines of a listener and traces do not take each other's room.
    #[test]
    fn logs_and_traces_have_their_own_room() {
        let (events, tx) = HostEvents::channel(1);
        let s = SessionId::next();
        tx.push(log(0));
        tx.push(log(1));
        for i in 0..4 {
            push_trace(&tx, s, &event(i));
        }
        let mut seen = Vec::new();
        while let Some(e) = events.try_next() {
            seen.push(e);
        }
        assert_eq!(seen.len(), 6);
        assert_eq!(seen[0], log(0));
        assert!(matches!(seen[1], HostEvent::Trace { .. }));
        assert_eq!(seen[5], HostEvent::Overflowed(1));
    }

    #[test]
    fn close_ends_the_subscription_and_cancelled_reads_leave_no_waker() {
        let (events, tx) = HostEvents::channel(4);
        let cx = &mut Context::from_waker(Waker::noop());
        for _ in 0..100 {
            let mut next = std::pin::pin!(events.next());
            assert!(next.as_mut().poll(cx).is_pending());
        }
        assert!(events.0.lock().waiters.is_empty());
        let mut next = std::pin::pin!(events.next());
        assert!(next.as_mut().poll(cx).is_pending());
        events.close();
        assert_eq!(next.as_mut().poll(cx), Poll::Ready(None));
        tx.push(HostEvent::Overflowed(1));
        assert_eq!(events.try_next(), None);
        assert!(events.is_closed());
    }

    #[test]
    fn dropping_every_reader_closes_and_stops_building_events() {
        let (events, tx) = HostEvents::channel(4);
        let other = events.clone();
        drop(events);
        tx.push(HostEvent::Overflowed(1));
        assert_eq!(other.try_next(), Some(HostEvent::Overflowed(1)));
        drop(other);
        push_trace(&tx, SessionId::next(), &event(1));
        let q = tx.0.lock();
        assert!(q.closed && q.items.is_empty() && q.sessions.is_empty());
    }
}
