//! The event queue of a session: bounded by construction, however many pipes a
//! session goes through.
//!
//! - Events are coalesced per pipe and per kind: a pipe direction keeps its
//!   latest state event, a pipe its `PipeAdded`, latest priority change and quality report, a
//!   tier its latest saturation, the session its latest GOAWAY, suspension
//!   and capacity state, and failed join authentications are counted. Each
//!   holds one slot, queued where its first unread event was.
//! - A terminal event (`PipeFailed`, `PipeClosed`) is never replaced or
//!   dropped.
//! - Only pipes that are not retired hold slots: when a pipe is retired,
//!   its unread events leave the queue and fold into one session-level
//!   [`SessionEvent::PipesRetired`] (pipes retired, unread failures and ends, the
//!   last few IDs). It is queued at the first retirement after the
//!   previous one was read, and every later retirement updates it.
//! - A slot limit derived from `max_pipes` guards against more live pipes
//!   than the core allows: past it non-terminal events are dropped and
//!   counted in the summary unread or, when none is queued, the next one;
//!   terminal states and the summary are never dropped.
//!
//! The queue therefore holds at most the session's unretired pipes (at most
//! `max_pipes` + H per joiner) plus a constant, and no terminal outcome is
//! lost.

use std::collections::{HashMap, VecDeque};

use super::Event as SessionEvent;
use crate::proto::session::{Config, PipeHalf, PipeId};

/// The retired pipe IDs a summary names, at most.
pub(crate) const SUMMARY_IDS: usize = 4;

/// What a queued slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    /// A pipe's `PipeAdded`.
    Added(u64),
    /// The latest state event of one direction of a pipe.
    State(u64, PipeHalf),
    /// The latest priority change of a pipe's outbound direction.
    Priority(u64),
    /// The latest quality report of a pipe's outbound direction.
    Quality(u64),
    /// The latest saturation of a tier.
    Tier(u64),
    GoAway,
    /// The latest of `SessionSuspended` and `SessionResumed`.
    Suspension,
    /// `ResumeUnattended`.
    Unattended,
    /// The latest of `CapacityBelow` and `CapacityRestored`.
    Capacity,
    /// Failed join authentications, counted.
    JoinAuth,
    /// The latest try of a carrier kind, as the session or as a pipe.
    Candidate(crate::CarrierKind, bool),
    /// The latest choice of carrier kind.
    Chosen,
    /// The latest committed epoch.
    EpochCommitted,
    /// The latest deleted epoch.
    EpochDeleted,
    Summary,
}

/// The session-level summary of retired pipes and dropped events.
#[derive(Debug, Default)]
struct Summary {
    retired: u64,
    failed: u64,
    closed: u64,
    /// Counted also while no summary is queued: the next one reports them.
    dropped: u64,
    last: Vec<u64>,
    /// The summary is queued (a pipe was retired since the last was read).
    queued: bool,
}

/// The bounded, coalescing pipe-event queue of a session.
#[derive(Debug)]
pub(crate) struct EventQueue {
    /// Slots in delivery order; each key at most once.
    order: VecDeque<Key>,
    /// The events of the queued slots (all keys but `Summary`).
    slots: HashMap<Key, SessionEvent>,
    summary: Summary,
    /// Slots for pipes and tiers, at most.
    limit: usize,
}

impl EventQueue {
    /// A queue for a session with `config`.
    pub(crate) fn new(config: &Config) -> Self {
        // Unretired attachments per joiner: max_pipes + H; two joiners and
        // the bootstrap attachment; per attachment two directions, a
        // priority and a quality report.
        let per_joiner =
            u64::from(config.max_pipes).saturating_add(u64::from(config.pipe_headroom));
        let pipes = per_joiner.saturating_mul(2).saturating_add(1);
        let limit = usize::try_from(pipes.saturating_mul(4)).unwrap_or(usize::MAX);
        Self::with_limit(limit)
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            order: VecDeque::new(),
            slots: HashMap::new(),
            summary: Summary::default(),
            limit,
        }
    }

    /// Unread slots (the summary included).
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }

    /// Queues an event, coalescing it with an unread one of its kind.
    pub(crate) fn push(&mut self, event: SessionEvent) {
        let key = match &event {
            SessionEvent::PipeAdded { pipe, .. } => Key::Added(pipe.0),
            SessionEvent::PipeJoined { pipe, .. }
            | SessionEvent::PipeSuspect { pipe, .. }
            | SessionEvent::PipeRecovered { pipe, .. }
            | SessionEvent::PipeFailed { pipe, .. } => Key::State(pipe.0, PipeHalf::Outbound),
            SessionEvent::PipeClosed { pipe, half, .. } => Key::State(pipe.0, *half),
            SessionEvent::PipePriorityChanged { pipe, .. } => Key::Priority(pipe.0),
            SessionEvent::PipeQualityChanged { pipe, .. } => Key::Quality(pipe.0),
            SessionEvent::TierSaturation { priority, .. } => Key::Tier(*priority),
            SessionEvent::GoAwayReceived(_) => Key::GoAway,
            SessionEvent::SessionSuspended | SessionEvent::SessionResumed => Key::Suspension,
            SessionEvent::ResumeUnattended => Key::Unattended,
            SessionEvent::CapacityBelow { .. } | SessionEvent::CapacityRestored { .. } => {
                Key::Capacity
            }
            SessionEvent::JoinAuthFailed { .. } => Key::JoinAuth,
            SessionEvent::CarrierCandidate { kind, joined, .. } => Key::Candidate(*kind, *joined),
            SessionEvent::CarrierChosen(..) => Key::Chosen,
            SessionEvent::EpochCommitted { .. } => Key::EpochCommitted,
            SessionEvent::EpochDeleted { .. } => Key::EpochDeleted,
            // Made by the queue only.
            SessionEvent::PipesRetired { .. } => return,
        };
        if let Some(old) = self.slots.get_mut(&key) {
            match (old, event) {
                (
                    SessionEvent::JoinAuthFailed { count, .. },
                    SessionEvent::JoinAuthFailed { .. },
                ) => {
                    *count = count.saturating_add(1);
                }
                // A terminal state stays.
                (old, _) if old.is_terminal() => {}
                (old, event) => *old = event,
            }
            return;
        }
        let limited = matches!(
            key,
            Key::Added(_) | Key::State(..) | Key::Priority(_) | Key::Quality(_) | Key::Tier(_)
        );
        let terminal = event.is_terminal();
        if limited && !terminal && self.slots.len() >= self.limit {
            // More live pipes than the core allows: nothing is lost
            // silently, and a terminal state is kept.
            self.summary.dropped = self.summary.dropped.saturating_add(1);
            return;
        }
        self.slots.insert(key, event);
        self.order.push_back(key);
    }

    /// A pipe was retired: its unread events leave the queue; its unread
    /// terminal states and its retirement go to the summary.
    pub(crate) fn retire(&mut self, pipe: u64) {
        let mut failed = 0;
        let mut closed = 0;
        let mut gone = false;
        for key in [
            Key::Added(pipe),
            Key::State(pipe, PipeHalf::Inbound),
            Key::State(pipe, PipeHalf::Outbound),
            Key::Priority(pipe),
            Key::Quality(pipe),
        ] {
            match self.slots.remove(&key) {
                Some(SessionEvent::PipeFailed { .. }) => failed += 1,
                Some(e) if e.is_terminal() => closed += 1,
                Some(_) => {}
                None => continue,
            }
            gone = true;
        }
        if gone {
            self.order
                .retain(|k| !matches!(k, Key::Added(p) | Key::State(p, _) | Key::Priority(p) | Key::Quality(p) if *p == pipe));
        }
        let s = &mut self.summary;
        if !s.queued {
            s.queued = true;
            self.order.push_back(Key::Summary);
        }
        s.retired = s.retired.saturating_add(1);
        // A pipe one of whose unread directions failed counts as failed,
        // else as closed when one ended unread.
        if failed > 0 {
            s.failed += 1;
        } else if closed > 0 {
            s.closed += 1;
        }
        if s.last.len() == SUMMARY_IDS {
            s.last.remove(0);
        }
        s.last.push(pipe);
    }

    /// The next event, oldest slot first.
    pub(crate) fn pop(&mut self) -> Option<SessionEvent> {
        let key = self.order.pop_front()?;
        if key == Key::Summary {
            let s = std::mem::take(&mut self.summary);
            debug_assert!(s.retired >= 1);
            return Some(SessionEvent::PipesRetired {
                retired: s.retired,
                failed: s.failed,
                closed: s.closed,
                dropped: s.dropped,
                last: s.last.into_iter().map(PipeId).collect(),
            });
        }
        self.slots.remove(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn added(pipe: u64) -> SessionEvent {
        SessionEvent::PipeAdded {
            pipe: PipeId(pipe),
            carrier: None,
        }
    }

    fn joined(pipe: u64) -> SessionEvent {
        SessionEvent::PipeJoined {
            pipe: PipeId(pipe),
            carrier: None,
        }
    }

    fn failed(pipe: u64) -> SessionEvent {
        SessionEvent::PipeFailed {
            pipe: PipeId(pipe),
            failure: None,
            carrier: None,
        }
    }

    fn closed(pipe: u64, half: PipeHalf) -> SessionEvent {
        SessionEvent::PipeClosed {
            pipe: PipeId(pipe),
            half,
            carrier: None,
        }
    }

    fn drain(q: &mut EventQueue) -> Vec<SessionEvent> {
        std::iter::from_fn(|| q.pop()).collect()
    }

    #[test]
    fn latest_state_wins_and_terminal_stays() {
        let mut q = EventQueue::with_limit(100);
        q.push(added(2));
        q.push(added(4));
        q.push(joined(2));
        q.push(failed(2));
        q.push(joined(2));
        assert_eq!(drain(&mut q), [added(2), added(4), failed(2)]);
    }

    #[test]
    fn retirement_folds_into_one_summary() {
        let mut q = EventQueue::with_limit(100);
        for pipe in 0..10u64 {
            let p = pipe * 2 + 1;
            q.push(added(p));
            q.push(joined(p));
            if pipe % 2 == 0 {
                q.push(failed(p));
            } else {
                q.push(closed(p, PipeHalf::Inbound));
            }
            q.retire(p);
        }
        assert_eq!(q.len(), 1);
        assert_eq!(
            drain(&mut q),
            [SessionEvent::PipesRetired {
                retired: 10,
                failed: 5,
                closed: 5,
                dropped: 0,
                last: vec![PipeId(13), PipeId(15), PipeId(17), PipeId(19)],
            }]
        );
        // A retirement after the summary was read starts a new one.
        q.retire(21);
        assert_eq!(
            drain(&mut q),
            [SessionEvent::PipesRetired {
                retired: 1,
                failed: 0,
                closed: 0,
                dropped: 0,
                last: vec![PipeId(21)],
            }]
        );
    }

    #[test]
    fn session_events_coalesce() {
        let mut q = EventQueue::with_limit(100);
        q.push(SessionEvent::JoinAuthFailed {
            reason: "auth",
            count: 1,
        });
        q.push(SessionEvent::SessionSuspended);
        q.push(SessionEvent::JoinAuthFailed {
            reason: "auth",
            count: 1,
        });
        q.push(SessionEvent::SessionResumed);
        for saturated in [true, false, true] {
            q.push(SessionEvent::TierSaturation {
                priority: 1,
                saturated,
            });
        }
        assert_eq!(
            drain(&mut q),
            [
                SessionEvent::JoinAuthFailed {
                    reason: "auth",
                    count: 2,
                },
                SessionEvent::SessionResumed,
                SessionEvent::TierSaturation {
                    priority: 1,
                    saturated: true,
                },
            ]
        );
    }

    /// Quality reports coalesce per pipe, the latest values winning, and
    /// leave with the pipe; the capacity state keeps its latest crossing.
    #[test]
    fn quality_events_coalesce_and_leave_with_their_pipe() {
        let quality = |pipe, ms| SessionEvent::PipeQualityChanged {
            pipe: PipeId(pipe),
            smoothed_rtt: Some(std::time::Duration::from_millis(ms)),
            delivery_rate: None,
        };
        let mut q = EventQueue::with_limit(100);
        q.push(quality(2, 10));
        q.push(SessionEvent::CapacityBelow { rate: 1 });
        q.push(quality(4, 10));
        q.push(quality(2, 30));
        q.push(SessionEvent::CapacityRestored { rate: 9 });
        q.retire(4);
        assert_eq!(
            drain(&mut q),
            [
                quality(2, 30),
                SessionEvent::CapacityRestored { rate: 9 },
                SessionEvent::PipesRetired {
                    retired: 1,
                    failed: 0,
                    closed: 0,
                    dropped: 0,
                    last: vec![PipeId(4)],
                },
            ]
        );
    }

    /// Past the limit terminal states are still queued and other events
    /// are dropped; the drops are counted in the next summary, which only
    /// a retirement queues (never with `retired` 0), or in the one unread.
    #[test]
    fn past_the_limit_terminal_states_stay_and_others_count() {
        let mut q = EventQueue::with_limit(2);
        q.push(joined(1));
        q.push(joined(3));
        q.push(joined(5));
        q.push(failed(7));
        q.push(closed(9, PipeHalf::Outbound));
        // An existing slot still coalesces.
        q.push(failed(1));
        assert_eq!(q.len(), 4);
        assert_eq!(
            drain(&mut q),
            [
                failed(1),
                joined(3),
                failed(7),
                closed(9, PipeHalf::Outbound),
            ]
        );
        q.retire(7);
        q.push(added(11));
        q.push(added(13));
        // Dropped while the summary is unread: counted in it.
        q.push(added(15));
        assert_eq!(
            drain(&mut q),
            [
                SessionEvent::PipesRetired {
                    retired: 1,
                    failed: 0,
                    closed: 0,
                    dropped: 2,
                    last: vec![PipeId(7)],
                },
                added(11),
                added(13),
            ]
        );
    }

    /// Retirement counts a pipe's unread terminal states by direction: a
    /// FAILED direction makes it failed, else an ended one closed; its
    /// unread non-terminal events leave uncounted, and read ones count
    /// nowhere.
    #[test]
    fn retirement_counts_unread_outcomes_by_direction() {
        let mut q = EventQueue::with_limit(100);
        q.push(failed(7));
        let _ = drain(&mut q);
        // Inbound ENDED and outbound FAILED: failed.
        q.push(closed(1, PipeHalf::Inbound));
        q.push(failed(1));
        // Outbound CLOSED alone: closed.
        q.push(closed(3, PipeHalf::Outbound));
        // Non-terminal only: neither.
        q.push(joined(5));
        for p in [1, 3, 5, 7] {
            q.retire(p);
        }
        assert_eq!(
            drain(&mut q),
            [SessionEvent::PipesRetired {
                retired: 4,
                failed: 1,
                closed: 1,
                dropped: 0,
                last: vec![PipeId(1), PipeId(3), PipeId(5), PipeId(7)],
            }]
        );
    }

    #[test]
    fn churn_stays_bounded() {
        let mut q = EventQueue::new(&Config::default());
        let mut most = 0;
        for i in 0..100_000u64 {
            let p = 2 * i + 1;
            q.push(added(p));
            q.push(joined(p));
            q.push(failed(p));
            q.push(closed(p, PipeHalf::Inbound));
            // `PipeAdded`, two directions of the pipe and the summary.
            most = most.max(q.len());
            q.retire(p);
        }
        assert_eq!(most, 4);
        assert_eq!(q.len(), 1);
        assert!(q.slots.capacity() < 64, "{}", q.slots.capacity());
    }
}
