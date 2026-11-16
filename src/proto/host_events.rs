//! The observing hooks as a subscription: what the logger, the tracer and
//! `on_memory_pressure` are told, queued for the host to read when it wants
//! ([`crate::Config::events`], [`crate::ListenerConfig::events`]) instead of
//! a callback on the thread that produced it. The queue is bounded: past
//! its capacity the oldest event is dropped and counted, and the count is
//! read as [`HostEvent::Overflowed`] before the events that follow it. Pushing
//! never blocks and never waits for the host.
//!
//! Each `events` call makes a subscription of its own, beside the hooks set
//! before (which keep being called): two subscriptions each read every
//! event. The clones of one [`HostEvents`] read one queue, each event once.
//! A subscription ends when the reader closes it ([`HostEvents::close`]),
//! when every clone of the reader is dropped (which closes it), or when
//! everything that writes to it is gone: the configuration it was made on,
//! its clones, and the sessions or listener made with them.

use std::collections::VecDeque;
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
        /// Its level.
        level: LogLevel,
        /// The message.
        message: String,
    },
    /// What the tracer is told of a session.
    Trace {
        /// The session.
        session: SessionId,
        /// The record ([`TraceRecord::Dropped`]: the session's own tracer
        /// backlog overflowed).
        record: TraceRecord,
    },
    /// A listener's memory pressure started or ended.
    MemoryPressure(MemoryPressure),
    /// The subscription's queue overflowed: this many events were dropped
    /// before the next one (the events a dropped [`TraceRecord::Dropped`]
    /// counted included). Not to be confused with
    /// [`TraceRecord::Dropped`], a session's own tracer backlog.
    Overflowed(u64),
}

struct Queue {
    items: VecDeque<HostEvent>,
    capacity: usize,
    dropped: u64,
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
    /// A subscription of `capacity` events (at least 1) and its writing end.
    pub(crate) fn channel(capacity: usize) -> (Self, Sender) {
        let chan = Arc::new(Chan(Mutex::new(Queue {
            items: VecDeque::new(),
            capacity: capacity.max(1),
            dropped: 0,
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
        take(&mut self.0.lock())
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
    q.dropped = 0;
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
        let ready = match take(&mut q) {
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

fn take(q: &mut Queue) -> Option<HostEvent> {
    if q.dropped > 0 {
        return Some(HostEvent::Overflowed(std::mem::take(&mut q.dropped)));
    }
    q.items.pop_front()
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
    /// Queues `event`, dropping the oldest when the queue is full; nothing
    /// once the subscription is closed.
    pub(crate) fn push(&self, event: HostEvent) {
        self.push_with(|| event);
    }

    /// [`Sender::push`] of the event `make` builds, called only while the
    /// subscription is open.
    pub(crate) fn push_with(&self, make: impl FnOnce() -> HostEvent) {
        let waiters = {
            let mut q = self.0.lock();
            if q.closed {
                return;
            }
            let event = make();
            if q.items.len() >= q.capacity {
                // A dropped count stands for the events it counted.
                q.dropped += match q.items.pop_front() {
                    Some(
                        HostEvent::Overflowed(n)
                        | HostEvent::Trace {
                            record: TraceRecord::Dropped(n),
                            ..
                        },
                    ) => n,
                    _ => 1,
                };
            }
            q.items.push_back(event);
            std::mem::take(&mut q.waiters)
        };
        // Woken readers register again if they find nothing.
        for (_, w) in waiters {
            w.wake();
        }
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

/// The tracer of a subscription, and the one set before it (still called).
pub(crate) struct TraceSink {
    pub(crate) tx: Sender,
    pub(crate) before: Option<Arc<dyn super::session::Tracer>>,
}

impl super::session::Tracer for TraceSink {
    fn trace(&self, session: SessionId, record: &TraceRecord) {
        if let Some(t) = &self.before {
            t.trace(session, record);
        }
        self.tx.push_with(|| HostEvent::Trace {
            session,
            record: record.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_drops_the_oldest_and_counts() {
        let (events, tx) = HostEvents::channel(2);
        for i in 0..4u8 {
            tx.push(HostEvent::Log {
                level: LogLevel::Info,
                message: i.to_string(),
            });
        }
        assert_eq!(events.try_next(), Some(HostEvent::Overflowed(2)));
        assert!(
            matches!(events.try_next(), Some(HostEvent::Log { message, .. }) if message == "2")
        );
        assert!(
            matches!(events.try_next(), Some(HostEvent::Log { message, .. }) if message == "3")
        );
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
    fn a_dropped_count_pushed_out_is_kept_in_the_count() {
        let (events, tx) = HostEvents::channel(1);
        tx.push(HostEvent::Trace {
            session: SessionId::next(),
            record: TraceRecord::Dropped(5),
        });
        tx.push(HostEvent::MemoryPressure(MemoryPressure {
            used: 0,
            budget: 0,
            active: false,
        }));
        assert_eq!(events.try_next(), Some(HostEvent::Overflowed(5)));
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
        let mut built = false;
        tx.push_with(|| {
            built = true;
            HostEvent::Overflowed(1)
        });
        assert!(!built, "nothing is built for a subscription nobody reads");
        let q = tx.0.lock();
        assert!(q.closed && q.items.is_empty());
    }
}
