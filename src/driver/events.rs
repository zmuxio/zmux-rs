//! The event queue of a session: bounded by construction, however many pipes a
//! session goes through.
//!
//! - Events are coalesced per pipe and per kind: a pipe direction keeps its
//!   latest state, a pipe its latest priority change and quality report, a
//!   tier its latest saturation, the session its latest GOAWAY, suspension
//!   and capacity state, and failed join authentications are counted. Each
//!   holds one slot, queued where its first unread event was.
//! - A terminal state (outbound FAILED or CLOSED, inbound ENDED) is never
//!   replaced or dropped.
//! - Only pipes that are not retired hold slots: when a pipe is retired,
//!   its unread events leave the queue and fold into one session-level
//!   [`SessionEvent::PipesRetired`] (pipes retired, unread failures and ends, the
//!   last few IDs), which every retirement updates.
//! - A slot limit derived from `max_pipes` guards against more live pipes
//!   than the core allows: past it a terminal state folds into the summary
//!   and other events are dropped and counted in it.
//!
//! The queue therefore holds at most the session's unretired pipes (at most
//! `max_pipes` + H per joiner, MULTIPATH.md Section 5.4) plus a constant,
//! and no terminal outcome is lost.

use std::collections::{HashMap, VecDeque};

use super::Event as SessionEvent;
use crate::proto::session::{Config, PipeHalf, PipeId, PipeState};

/// The retired pipe IDs a summary names, at most.
pub(crate) const SUMMARY_IDS: usize = 4;

/// What a queued slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    /// The latest state of one direction of a pipe.
    State(u64, PipeHalf),
    /// The latest priority change of a pipe's outbound direction.
    Priority(u64),
    /// The latest quality report of a pipe's outbound direction.
    Quality(u64),
    /// The latest saturation of a tier.
    Tier(u64),
    GoAway,
    /// The latest of `Suspended` and `Resumed`.
    Suspension,
    /// The latest of `CapacityBelow` and `CapacityRestored`.
    Capacity,
    /// Failed join authentications, counted.
    JoinAuth(bool),
    JoinSecurity,
    Summary,
}

/// The session-level summary of retired pipes and dropped events.
#[derive(Debug, Default)]
struct Summary {
    retired: u64,
    failed: u64,
    closed: u64,
    dropped: u64,
    last: Vec<u64>,
}

impl Summary {
    fn is_empty(&self) -> bool {
        self.retired == 0 && self.failed == 0 && self.closed == 0 && self.dropped == 0
    }
}

/// The bounded, coalescing pipe-event queue of a session.
#[derive(Debug)]
pub(crate) struct EventQueue {
    /// Slots in delivery order; each key at most once.
    order: VecDeque<Key>,
    /// The events of the queued slots (all keys but `Summary`).
    slots: HashMap<Key, SessionEvent>,
    summary: Summary,
    /// The pipe whose retirement was folded last (a retired attachment
    /// reports each of its directions).
    last_retired: Option<u64>,
    /// Slots for pipes and tiers, at most.
    limit: usize,
}

/// Whether a pipe state is terminal for its direction.
fn terminal(state: PipeState) -> bool {
    matches!(
        state,
        PipeState::Failed | PipeState::Closed | PipeState::Ended
    )
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
            last_retired: None,
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
            SessionEvent::PipeState { pipe, state, .. } if *state == PipeState::Retired => {
                self.retire(pipe.0);
                return;
            }
            SessionEvent::PipeState { pipe, half, .. } => Key::State(pipe.0, *half),
            SessionEvent::PipePriorityChanged { pipe, .. } => Key::Priority(pipe.0),
            SessionEvent::PipeQualityChanged { pipe, .. } => Key::Quality(pipe.0),
            SessionEvent::TierSaturation { priority, .. } => Key::Tier(*priority),
            SessionEvent::GoAway(_) => Key::GoAway,
            SessionEvent::Suspended | SessionEvent::Resumed => Key::Suspension,
            SessionEvent::CapacityBelow { .. } | SessionEvent::CapacityRestored { .. } => {
                Key::Capacity
            }
            SessionEvent::JoinAuthFailed { carrier_bound, .. } => Key::JoinAuth(*carrier_bound),
            SessionEvent::JoinSecurityUnavailable => Key::JoinSecurity,
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
                (SessionEvent::PipeState { state, .. }, _) if terminal(*state) => {}
                (old, event) => *old = event,
            }
            return;
        }
        let limited = matches!(
            key,
            Key::State(..) | Key::Priority(_) | Key::Quality(_) | Key::Tier(_)
        );
        if limited && self.slots.len() >= self.limit {
            // More live pipes than the core allows: nothing is lost
            // silently.
            match event {
                SessionEvent::PipeState {
                    state: PipeState::Failed,
                    ..
                } => {
                    self.fold(|s| s.failed += 1);
                }
                SessionEvent::PipeState { state, .. } if terminal(state) => {
                    self.fold(|s| s.closed += 1);
                }
                _ => self.fold(|s| s.dropped += 1),
            }
            return;
        }
        self.slots.insert(key, event);
        self.order.push_back(key);
    }

    /// Updates the summary, queueing it when it was not.
    fn fold(&mut self, f: impl FnOnce(&mut Summary)) {
        if self.summary.is_empty() {
            self.order.push_back(Key::Summary);
        }
        f(&mut self.summary);
    }

    /// A pipe was retired: its unread events leave the queue; its unread
    /// terminal states and its retirement go to the summary.
    fn retire(&mut self, pipe: u64) {
        if self.last_retired == Some(pipe) {
            return;
        }
        self.last_retired = Some(pipe);
        let mut failed = 0;
        let mut closed = 0;
        let mut gone = false;
        for key in [
            Key::State(pipe, PipeHalf::Inbound),
            Key::State(pipe, PipeHalf::Outbound),
            Key::Priority(pipe),
            Key::Quality(pipe),
        ] {
            match self.slots.remove(&key) {
                Some(SessionEvent::PipeState {
                    state: PipeState::Failed,
                    ..
                }) => failed += 1,
                Some(SessionEvent::PipeState { state, .. }) if terminal(state) => closed += 1,
                Some(_) => {}
                None => continue,
            }
            gone = true;
        }
        if gone {
            self.order
                .retain(|k| !matches!(k, Key::State(p, _) | Key::Priority(p) | Key::Quality(p) if *p == pipe));
        }
        self.fold(|s| {
            s.retired += 1;
            // A pipe whose direction failed counts as failed, else as
            // closed when one ended.
            if failed > 0 {
                s.failed += 1;
            } else if closed > 0 {
                s.closed += 1;
            }
            if s.last.len() == SUMMARY_IDS {
                s.last.remove(0);
            }
            s.last.push(pipe);
        });
    }

    /// The next event, oldest slot first.
    pub(crate) fn pop(&mut self) -> Option<SessionEvent> {
        let key = self.order.pop_front()?;
        if key == Key::Summary {
            let s = std::mem::take(&mut self.summary);
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

    fn state(pipe: u64, half: PipeHalf, state: PipeState) -> SessionEvent {
        SessionEvent::PipeState {
            pipe: PipeId(pipe),
            half,
            state,
            failure: None,
        }
    }

    fn drain(q: &mut EventQueue) -> Vec<SessionEvent> {
        std::iter::from_fn(|| q.pop()).collect()
    }

    #[test]
    fn latest_state_wins_and_terminal_stays() {
        let mut q = EventQueue::with_limit(100);
        q.push(state(2, PipeHalf::Outbound, PipeState::Joining));
        q.push(state(4, PipeHalf::Outbound, PipeState::Joining));
        q.push(state(2, PipeHalf::Outbound, PipeState::Active));
        q.push(state(2, PipeHalf::Outbound, PipeState::Failed));
        q.push(state(2, PipeHalf::Outbound, PipeState::Active));
        assert_eq!(
            drain(&mut q),
            [
                state(2, PipeHalf::Outbound, PipeState::Failed),
                state(4, PipeHalf::Outbound, PipeState::Joining),
            ]
        );
    }

    #[test]
    fn retirement_folds_into_one_summary() {
        let mut q = EventQueue::with_limit(100);
        for pipe in 0..10u64 {
            let p = pipe * 2 + 1;
            q.push(state(p, PipeHalf::Outbound, PipeState::Joining));
            q.push(state(p, PipeHalf::Inbound, PipeState::Open));
            if pipe % 2 == 0 {
                q.push(state(p, PipeHalf::Outbound, PipeState::Failed));
            } else {
                q.push(state(p, PipeHalf::Inbound, PipeState::Ended));
            }
            q.push(state(p, PipeHalf::Outbound, PipeState::Retired));
            q.push(state(p, PipeHalf::Inbound, PipeState::Retired));
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
        q.push(state(21, PipeHalf::Outbound, PipeState::Retired));
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
            carrier_bound: false,
            count: 1,
        });
        q.push(SessionEvent::Suspended);
        q.push(SessionEvent::JoinAuthFailed {
            carrier_bound: false,
            count: 1,
        });
        q.push(SessionEvent::Resumed);
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
                    carrier_bound: false,
                    count: 2,
                },
                SessionEvent::Resumed,
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
        q.push(state(4, PipeHalf::Outbound, PipeState::Retired));
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

    #[test]
    fn past_the_limit_terminal_outcomes_fold_and_others_count() {
        let mut q = EventQueue::with_limit(2);
        q.push(state(1, PipeHalf::Outbound, PipeState::Joining));
        q.push(state(3, PipeHalf::Outbound, PipeState::Joining));
        q.push(state(5, PipeHalf::Outbound, PipeState::Joining));
        q.push(state(7, PipeHalf::Outbound, PipeState::Failed));
        q.push(state(9, PipeHalf::Outbound, PipeState::Closed));
        // An existing slot still coalesces.
        q.push(state(1, PipeHalf::Outbound, PipeState::Failed));
        assert_eq!(q.len(), 3);
        assert_eq!(
            drain(&mut q),
            [
                state(1, PipeHalf::Outbound, PipeState::Failed),
                state(3, PipeHalf::Outbound, PipeState::Joining),
                SessionEvent::PipesRetired {
                    retired: 0,
                    failed: 1,
                    closed: 1,
                    dropped: 1,
                    last: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn churn_stays_bounded() {
        let mut q = EventQueue::new(&Config::default());
        let mut most = 0;
        for i in 0..100_000u64 {
            let p = 2 * i + 1;
            q.push(state(p, PipeHalf::Outbound, PipeState::Joining));
            q.push(state(p, PipeHalf::Inbound, PipeState::Open));
            q.push(state(p, PipeHalf::Outbound, PipeState::Failed));
            q.push(state(p, PipeHalf::Inbound, PipeState::Ended));
            // Two directions of the pipe and the summary.
            most = most.max(q.len());
            q.push(state(p, PipeHalf::Outbound, PipeState::Retired));
            q.push(state(p, PipeHalf::Inbound, PipeState::Retired));
        }
        assert_eq!(most, 3);
        assert_eq!(q.len(), 1);
        assert!(q.slots.capacity() < 64, "{}", q.slots.capacity());
    }
}
