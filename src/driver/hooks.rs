//! Application hooks whose answers the core needs, run outside every lock:
//!
//! - a custom scheduling policy is asked on the session task or a writer
//!   thread (`PickRequest`, filled and answered under the lock, run without
//!   it);
//! - `allow_connection_window_increase` runs on a hook task or thread of
//!   the session, started when the first proposal appears and fed through
//!   the one-slot mailbox [`WindowHook`], never through a queue that may
//!   drop it. A panic counts as a refusal;
//! - the `tracer` runs on the same hook context, started with the session,
//!   fed through the [`TraceQueue`], the one queue of the host events: the
//!   session's backlog holds 256 events, past it the new event is dropped
//!   and counted, the session's start, the counts and its end never are.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use super::wake::WakeList;
#[cfg(test)]
use crate::proto::host_events::TRACE_BACKLOG;
use crate::proto::host_events::{HostEvent, HostEvents, Sender};
use crate::proto::session::{
    Config, LogLevel, Logger, SessionCore as Core, SessionId, TraceRecord, Tracer, WindowIncrease,
};

/// Where a session's trace records go: the queues of the observers of the
/// session. One queue implementation serves all of them
/// ([`HostEvents`]): the session's backlog holds 256 events, past it the
/// newly arriving event is dropped and counted, where it would have stood
/// (the session's `Established`, the counts and its `Closed` take no room
/// and are never dropped). An observer is either a subscription
/// ([`Config::events`]), whose queue the host reads when it wants, or the
/// tracer callback of the configuration, whose queue the session's hook
/// context reads and calls the tracer with. A record is queued once for
/// each, with its own count of what it dropped.
pub(crate) struct TraceQueue {
    pub(crate) session: SessionId,
    /// The tracer callback and the queue it consumes.
    callback: Option<(Arc<dyn Tracer>, Sender, HostEvents)>,
    /// The subscriptions of the configuration.
    subscriptions: Vec<Sender>,
    /// The end was queued: the last record.
    closed: bool,
}

impl TraceQueue {
    /// The queues of a session of `config`; `None` when nothing observes it.
    pub(crate) fn new(config: &Config, session: SessionId) -> Option<Self> {
        if config.tracer.is_none() && config.subscriptions.is_empty() {
            return None;
        }
        Some(Self {
            session,
            callback: config.tracer.clone().map(|t| {
                let (reader, tx) = HostEvents::channel(1);
                (t, tx, reader)
            }),
            subscriptions: config.subscriptions.clone(),
            closed: false,
        })
    }

    /// The tracer callback, if any.
    pub(crate) fn tracer(&self) -> Option<Arc<dyn Tracer>> {
        self.callback.as_ref().map(|c| c.0.clone())
    }

    /// Queues a record for every observer, nothing once the end was
    /// queued. Under the session's lock: the wake-ups of the readers go to
    /// `wakes`. Returns whether the tracer callback has something to read.
    pub(crate) fn push(&mut self, item: &TraceRecord, wakes: &mut WakeList) -> bool {
        if self.closed {
            return false;
        }
        self.closed = matches!(item, TraceRecord::Closed(_));
        for tx in &self.subscriptions {
            tx.push_trace(self.session, item, &mut |w| wakes.push(w));
        }
        match &self.callback {
            Some((_, tx, _)) => {
                tx.push_trace(self.session, item, &mut |w| wakes.push(w));
                true
            }
            None => false,
        }
    }

    /// What the observers are told when `pipe` is retired: one
    /// `PipesRetired` per pipe, counting its end, `failed` as the core
    /// reports it (observers read nothing, so every end counts).
    pub(crate) fn retired(pipe: crate::PipeId, failed: bool) -> crate::SessionEvent {
        crate::SessionEvent::PipesRetired {
            retired: 1,
            failed: u64::from(failed),
            closed: u64::from(!failed),
            last: vec![pipe],
        }
    }

    /// The next record of the tracer callback's queue. One at a time, so
    /// that what the tracer has not been told yet is what the backlog
    /// holds, never more.
    pub(crate) fn take(&mut self) -> Option<TraceRecord> {
        let (_, _, reader) = self.callback.as_ref()?;
        match reader.try_next()? {
            HostEvent::Trace { record, .. } => Some(record),
            _ => None,
        }
    }

    /// The end was queued and, after a [`take`](Self::take) that found
    /// nothing, everything was taken.
    pub(crate) fn finished(&self) -> bool {
        self.callback.is_none() || self.closed
    }

    /// The hook context could not be started: the tracer is not called.
    #[cfg(feature = "blocking")]
    pub(crate) fn drop_callback(&mut self) {
        self.callback = None;
    }

    /// Whether a tracer callback consumes the queue.
    pub(crate) fn has_callback(&self) -> bool {
        self.callback.is_some()
    }
}

/// Tells the tracer `item` of `session`, outside every lock; a panic is
/// ignored.
pub(crate) fn trace(
    tracer: &Arc<dyn Tracer>,
    session: SessionId,
    item: &TraceRecord,
    logger: Option<&Logger>,
) {
    let r = catch_unwind(AssertUnwindSafe(|| tracer.trace(session, item)));
    if let (Err(_), Some(l)) = (r, logger) {
        l.log(
            LogLevel::Error,
            "zmux: the tracer panicked; the panic was contained",
        );
    }
}

/// What the hook context runs: the predicate and the tracer of the
/// session, either of them.
#[derive(Clone)]
pub(crate) struct HookStart {
    pub(crate) predicate: Option<WindowIncrease>,
    pub(crate) tracer: Option<Arc<dyn Tracer>>,
    pub(crate) logger: Option<Logger>,
}

/// The mailbox of a session's `allow_connection_window_increase`: at most
/// one proposal, since the core keeps at most one outstanding.
#[derive(Debug)]
pub(crate) struct WindowHook {
    predicate: Option<WindowIncrease>,
    /// The proposal for the hook context: generation and increase.
    proposal: Option<(u64, u64)>,
    /// The hook context was started (or is being started).
    started: bool,
}

impl WindowHook {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            predicate: config.allow_connection_window_increase.clone(),
            proposal: None,
            started: false,
        }
    }

    /// Under the lock, on the core's `WindowIncrease` event: moves the
    /// proposal into the mailbox. Returns whether the hook context must be
    /// started for it (once per session).
    pub(crate) fn offer(&mut self, core: &mut Core) -> bool {
        if self.predicate.is_none() {
            return false;
        }
        if let Some(p) = core.take_window_increase() {
            self.proposal = Some(p);
        }
        self.proposal.is_some() && !std::mem::replace(&mut self.started, true)
    }

    /// The predicate.
    pub(crate) fn predicate(&self) -> Option<WindowIncrease> {
        self.predicate.clone()
    }

    /// The hook context was started for another hook (the tracer).
    pub(crate) fn mark_started(&mut self) {
        self.started = true;
    }

    /// Whether a proposal waits for the hook context.
    pub(crate) fn pending(&self) -> bool {
        self.proposal.is_some()
    }

    /// The proposal for the hook context, once.
    pub(crate) fn take(&mut self) -> Option<(u64, u64)> {
        self.proposal.take()
    }

    /// The hook context could not be started: the proposal is refused, so
    /// that the core proposes again at its next growth decision.
    #[cfg(feature = "blocking")]
    pub(crate) fn not_started(&mut self, core: &mut Core) {
        self.started = false;
        if let Some((generation, _)) = self.proposal.take() {
            core.answer_window_increase(generation, false);
        }
    }
}

/// Asks the predicate (with no zmux lock held); a panic is a refusal.
pub(crate) async fn ask(predicate: &WindowIncrease, delta: u64, logger: Option<&Logger>) -> bool {
    predicate
        .allows(delta)
        .settle()
        .await
        .flatten()
        .unwrap_or_else(|| {
            if let Some(l) = logger {
                l.log(
                    LogLevel::Error,
                    "zmux: allow_connection_window_increase panicked; counted as a refusal",
                );
            }
            false
        })
}

/// A host decision, awaited until `deadline` (`None`: unbounded) or until
/// `stop` (its caller ended: the listener closed, the carrier was evicted,
/// the session ended), whichever comes first; `None` when it panicked,
/// missed the deadline or was stopped, the future dropped unfinished. An
/// answer given now never touches the timer or `stop`.
#[cfg(feature = "tokio")]
pub(crate) async fn settle_by<T>(
    decision: crate::proto::Decision<T>,
    deadline: Option<std::time::Instant>,
    stop: impl Future<Output = ()>,
) -> Option<T> {
    match decision {
        crate::proto::Decision::Now(v) => Some(v),
        later @ crate::proto::Decision::Later(_) => {
            let settled = first(stop, later.settle());
            match deadline {
                Some(at) => tokio::time::timeout_at(at.into(), settled)
                    .await
                    .ok()
                    .flatten()
                    .flatten(),
                None => settled.await.flatten(),
            }
        }
    }
}

/// [`settle_by`] on a thread of the std driver: the thread parks while it
/// waits.
#[cfg(feature = "blocking")]
pub(crate) fn settle_blocking<T>(
    decision: crate::proto::Decision<T>,
    deadline: Option<std::time::Instant>,
    stop: impl Future<Output = ()>,
) -> Option<T> {
    match decision {
        crate::proto::Decision::Now(v) => Some(v),
        later @ crate::proto::Decision::Later(_) => {
            super::blocking::run(first(stop, later.settle()), deadline)
                .flatten()
                .flatten()
        }
    }
}

/// `f`'s output, or `None` once `stop` is ready first.
pub(crate) async fn first<T>(
    stop: impl Future<Output = ()>,
    f: impl Future<Output = T>,
) -> Option<T> {
    let (mut stop, mut f) = (std::pin::pin!(stop), std::pin::pin!(f));
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(cx) {
            return std::task::Poll::Ready(Some(v));
        }
        stop.as_mut().poll(cx).map(|()| None)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionEvent;
    use crate::proto::session::SessionError;

    struct Nobody;
    impl Tracer for Nobody {
        fn trace(&self, _: SessionId, _: &TraceRecord) {}
    }

    /// The tracer callback reads one queue with the session's backlog of
    /// 256 events: past it the new event is dropped and counted before the
    /// end; the start, the count and the end take no room.
    #[test]
    fn the_tracer_callback_reads_the_one_bounded_queue() {
        let mut config = Config {
            tracer: Some(Arc::new(Nobody)),
            ..Config::default()
        };
        let events = config.events();
        let mut q = TraceQueue::new(&config, SessionId::next()).expect("observed");
        let mut wakes = WakeList::default();
        assert!(q.push(&TraceRecord::Established, &mut wakes));
        for _ in 0..TRACE_BACKLOG + 10 {
            q.push(
                &TraceRecord::Event(SessionEvent::SessionResumed),
                &mut wakes,
            );
        }
        q.push(
            &TraceRecord::Closed(SessionError::HandshakeTimeout),
            &mut wakes,
        );
        // Nothing follows the end.
        assert!(!q.push(&TraceRecord::Established, &mut wakes));
        let got: Vec<_> = std::iter::from_fn(|| q.take()).collect();
        assert_eq!(got.first(), Some(&TraceRecord::Established));
        assert!(matches!(got.last(), Some(TraceRecord::Closed(_))));
        // The start, 256 events, the 10 dropped counted before the end, the end.
        assert_eq!(got.len(), TRACE_BACKLOG + 3);
        assert_eq!(got[TRACE_BACKLOG + 1], TraceRecord::Dropped(10));
        assert!(q.finished());
        // The subscription, with its own queue and count, saw the start and
        // the end too.
        let mut seen = Vec::new();
        while let Some(e) = events.try_next() {
            seen.push(e);
        }
        assert!(matches!(
            seen.first(),
            Some(HostEvent::Trace {
                record: TraceRecord::Established,
                ..
            })
        ));
        assert!(matches!(
            seen.last(),
            Some(HostEvent::Trace {
                record: TraceRecord::Closed(_),
                ..
            })
        ));
    }
}
