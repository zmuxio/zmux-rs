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
//!   fed through the bounded [`TraceQueue`]: past [`TRACE_BACKLOG`] events
//!   are dropped and counted, the session's end never is.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use crate::proto::session::{
    Config, LogLevel, Logger, SessionCore as Core, SessionId, TraceRecord, Tracer, WindowIncrease,
};

/// Events a tracer may have unread before more are dropped.
pub(crate) const TRACE_BACKLOG: usize = 256;

/// The bounded queue of a session's tracer, and the tracer.
pub(crate) struct TraceQueue {
    pub(crate) tracer: Arc<dyn Tracer>,
    pub(crate) session: SessionId,
    items: VecDeque<TraceRecord>,
    dropped: u64,
    /// The end was queued: the last item.
    closed: bool,
}

impl TraceQueue {
    pub(crate) fn new(tracer: Arc<dyn Tracer>, session: SessionId) -> Self {
        Self {
            tracer,
            session,
            items: VecDeque::new(),
            dropped: 0,
            closed: false,
        }
    }

    /// Queues a record; past the backlog an event is dropped and counted,
    /// and the end is always queued.
    pub(crate) fn push(&mut self, item: TraceRecord) {
        if self.closed {
            return;
        }
        let end = matches!(item, TraceRecord::Closed(_));
        if self.items.len() >= TRACE_BACKLOG && !end {
            self.dropped += 1;
            return;
        }
        if self.dropped > 0 {
            self.items
                .push_back(TraceRecord::Dropped(std::mem::take(&mut self.dropped)));
        }
        self.closed = end;
        self.items.push_back(item);
    }

    /// The records queued, all of them.
    pub(crate) fn take(&mut self) -> Option<VecDeque<TraceRecord>> {
        (!self.items.is_empty()).then(|| std::mem::take(&mut self.items))
    }

    /// Everything was taken, the end included.
    pub(crate) fn finished(&self) -> bool {
        self.closed && self.items.is_empty()
    }
}

/// Tells the tracer `items` of `session`, outside every lock; a panic is
/// ignored.
pub(crate) fn trace(
    tracer: &Arc<dyn Tracer>,
    session: SessionId,
    items: VecDeque<TraceRecord>,
    logger: Option<&Logger>,
) {
    for item in items {
        let r = catch_unwind(AssertUnwindSafe(|| tracer.trace(session, &item)));
        if let (Err(_), Some(l)) = (r, logger) {
            l.log(
                LogLevel::Error,
                "zmux: the tracer panicked; the panic was contained",
            );
        }
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
    stop: impl std::future::Future<Output = ()>,
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
    stop: impl std::future::Future<Output = ()>,
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
    stop: impl std::future::Future<Output = ()>,
    f: impl std::future::Future<Output = T>,
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
