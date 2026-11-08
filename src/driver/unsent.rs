//! The carrier's unsent count: an optional query of the sending half of
//! each lane, which the drivers call without the core lock and hand to
//! the core under it. The core's Q_p is the bytes of the write calls in
//! progress plus this count.

use std::time::Instant;

use std::time::Duration;

use crate::proto::session::{LaneId, PipeId, SessionCore as Core};

use super::tcp::PROBE_INTERVAL;

/// The query: bytes a write call took that the carrier has not transmitted
/// yet, `None` while it has no count.
pub(crate) type Unsent = Box<dyn Fn() -> Option<u64> + Send + Sync>;

/// A lane's unsent query, called at most every [`PROBE_INTERVAL`] in two
/// steps: [`UnsentQuery::query`] without the core lock, and
/// [`UnsentQuery::feed`] under it.
pub(crate) struct UnsentQuery {
    query: Unsent,
    /// When the next query is due.
    next: Instant,
    /// The last count, for [`UnsentQuery::feed`].
    count: Option<u64>,
}

impl UnsentQuery {
    /// The first query is due at once.
    pub(crate) fn new(query: Unsent, now: Instant) -> Self {
        Self {
            query,
            next: now,
            count: None,
        }
    }

    /// Step 1, without any lock: queries the carrier when due; whether it
    /// did.
    pub(crate) fn query(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now + PROBE_INTERVAL;
        self.count = (self.query)();
        true
    }

    /// Step 2, under the core lock: a count goes to the core in a
    /// multipath session (outside one nothing reads it).
    pub(crate) fn feed(&mut self, core: &mut Core, at: LaneId, now: Instant) {
        if let Some(n) = self.count.take()
            && core.is_multipath()
        {
            core.set_pipe_unsent(at, n, now);
        }
    }

    /// When the next query is due.
    #[cfg(feature = "tokio")]
    pub(crate) fn next_query(&self) -> Instant {
        self.next
    }
}

impl std::fmt::Debug for UnsentQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsentQuery")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

/// How often a pipe's retransmission count is queried, at most.
pub(crate) const RETRANSMITTED_INTERVAL: Duration = Duration::from_secs(1);

/// A pipe's retransmission-count query, on its sending half, in the same
/// two steps as [`UnsentQuery`], at most every
/// [`RETRANSMITTED_INTERVAL`].
pub(crate) struct RetransmittedQuery {
    query: Unsent,
    next: Instant,
    count: Option<u64>,
}

impl RetransmittedQuery {
    /// The first query is due at once.
    pub(crate) fn new(query: Unsent, now: Instant) -> Self {
        Self {
            query,
            next: now,
            count: None,
        }
    }

    /// Step 1, without any lock: queries the carrier when due; whether it
    /// did.
    pub(crate) fn query(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now + RETRANSMITTED_INTERVAL;
        self.count = (self.query)();
        true
    }

    /// Step 2, under the core lock: a count goes to the core.
    pub(crate) fn feed(&mut self, core: &mut Core, pipe: PipeId, now: Instant) {
        if let Some(n) = self.count.take() {
            core.set_pipe_retransmitted(pipe, n, now);
        }
    }
}

impl std::fmt::Debug for RetransmittedQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetransmittedQuery")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}
