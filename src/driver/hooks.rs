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
    Config, SessionCore as Core, SessionError, SessionEvent, Tracer, WindowIncrease,
};

/// Events a tracer may have unread before more are dropped.
pub(crate) const TRACE_BACKLOG: usize = 256;

/// What the tracer is told, in order.
#[derive(Debug)]
pub(crate) enum Trace {
    Established,
    Event(SessionEvent),
    /// Events dropped since the last item.
    Dropped(u64),
    Closed(SessionError),
}

/// The bounded queue of a session's tracer, and the tracer.
pub(crate) struct TraceQueue {
    pub(crate) tracer: Arc<dyn Tracer>,
    items: VecDeque<Trace>,
    dropped: u64,
    /// The end was queued: the last item.
    closed: bool,
}

impl TraceQueue {
    pub(crate) fn new(tracer: Arc<dyn Tracer>) -> Self {
        Self {
            tracer,
            items: VecDeque::new(),
            dropped: 0,
            closed: false,
        }
    }

    /// Queues an item; past the backlog an event is dropped and counted,
    /// and the end is always queued.
    pub(crate) fn push(&mut self, item: Trace) {
        if self.closed {
            return;
        }
        let end = matches!(item, Trace::Closed(_));
        if self.items.len() >= TRACE_BACKLOG && !end {
            self.dropped += 1;
            return;
        }
        if self.dropped > 0 {
            self.items
                .push_back(Trace::Dropped(std::mem::take(&mut self.dropped)));
        }
        self.closed = end;
        self.items.push_back(item);
    }

    /// The items queued, all of them.
    pub(crate) fn take(&mut self) -> Option<VecDeque<Trace>> {
        (!self.items.is_empty()).then(|| std::mem::take(&mut self.items))
    }

    /// Everything was taken, the end included.
    pub(crate) fn finished(&self) -> bool {
        self.closed && self.items.is_empty()
    }
}

/// Tells the tracer `items`, outside every lock; a panic is ignored.
pub(crate) fn trace(tracer: &Arc<dyn Tracer>, items: VecDeque<Trace>) {
    for item in items {
        let _ = catch_unwind(AssertUnwindSafe(|| match &item {
            Trace::Established => tracer.established(),
            Trace::Event(e) => tracer.event(e),
            Trace::Dropped(n) => tracer.dropped(*n),
            Trace::Closed(e) => tracer.closed(e),
        }));
    }
}

/// What the hook context runs: the predicate and the tracer of the
/// session, either of them.
#[derive(Clone)]
pub(crate) struct HookStart {
    pub(crate) predicate: Option<WindowIncrease>,
    pub(crate) tracer: Option<Arc<dyn Tracer>>,
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
    #[cfg_attr(not(feature = "blocking"), allow(dead_code))]
    pub(crate) fn not_started(&mut self, core: &mut Core) {
        self.started = false;
        if let Some((generation, _)) = self.proposal.take() {
            core.answer_window_increase(generation, false);
        }
    }
}

/// Asks the predicate (with no zmux lock held); a panic is a refusal.
pub(crate) fn ask(predicate: &WindowIncrease, delta: u64) -> bool {
    catch_unwind(AssertUnwindSafe(|| (predicate.0)(delta))).unwrap_or(false)
}
