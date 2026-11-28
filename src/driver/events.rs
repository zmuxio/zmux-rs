//! The event queue of a session: keyed, never dropping, bounded by what the
//! session holds.
//!
//! - Every event has a key (the event key table): its kind, and for a pipe
//!   event the pipe (and the direction where one kind covers both), for a
//!   tier its priority, for a failed join its reason, for a carrier
//!   candidate its kind and variant. The queue holds at most one unread
//!   event per key. An event whose key has one unread updates it as its
//!   kind says (the latest replaces, `JoinAuthFailed` counts, a terminal or
//!   once-only event stays) and moves it to the tail, so events are read in
//!   the order of their keys' latest occurrences. A `SessionResumed` removes
//!   an unread `ResumeUnattended`.
//! - The keys are those of the pipes the session
//!   holds (a constant number each), its tiers, its carrier candidates and
//!   a fixed set of session keys, so the queue is bounded by what bounds
//!   those (attachment capacity, Join admission caps, memory budget), with
//!   no limit or overflow count of its own.
//! - When a pipe is retired its keys leave the queue. Health subscribers keep
//!   the direction changes for a bounded number of recently retired pipes.
//!   The one
//!   session-level summary [`SessionEvent::PipesRetired`] (pipes retired,
//!   failures and ends the application did not read, the last few IDs),
//!   itself a key that moves to the tail at each retirement, counts the
//!   pipe in `failed` (the core's failure flag) or else `closed`, unless the
//!   application had read a `PipeFailed` or `PipeClosed` of the pipe: an
//!   unread terminal state includes one never queued.
//! - Once the session is closed ([`EventQueue::freeze`]) nothing more
//!   enters; what is queued is still read.
//!
//! The queue is a map from key to a node of one doubly linked list over a
//! slab: update, move to the tail, removal and pop are O(1).

use std::collections::HashMap;
use std::sync::Arc;

use super::Event as SessionEvent;
use crate::CarrierKind;
use crate::proto::session::{PipeHalf, PipeId};

/// The retired pipe IDs a summary names, at most.
pub(crate) const SUMMARY_IDS: usize = 4;

/// What a queued event is keyed by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Controller(u8),
    Added(u64),
    Joined(u64),
    Suspect(u64),
    Recovered(u64),
    Failed(u64),
    Closed(u64, PipeHalf),
    Priority(u64),
    Quality(u64),
    Health(u64, PipeHalf),
    Tier(u64),
    JoinAuth(&'static str),
    CapacityBelow,
    CapacityRestored,
    EpochCommitted,
    EpochDeleted,
    DatagramPath,
    Shaping(crate::shaping::EventKind),
    Retired,
    Candidate(CarrierKind, Option<Arc<str>>),
    Chosen,
    Suspended,
    Resumed,
    Unattended,
    GoAway,
}

impl Key {
    /// The keys of one pipe, which leave the queue at its retirement.
    fn of_pipe(pipe: u64) -> [Self; 9] {
        [
            Self::Added(pipe),
            Self::Joined(pipe),
            Self::Suspect(pipe),
            Self::Recovered(pipe),
            Self::Failed(pipe),
            Self::Closed(pipe, PipeHalf::Inbound),
            Self::Closed(pipe, PipeHalf::Outbound),
            Self::Priority(pipe),
            Self::Quality(pipe),
        ]
    }

    /// The key of `event`; `None` for the summary, which only the queue
    /// makes.
    fn of(event: &SessionEvent) -> Option<Self> {
        Some(match event {
            SessionEvent::TargetChanged { .. }
            | SessionEvent::BatchReserved { .. }
            | SessionEvent::BatchRolledBack { .. }
            | SessionEvent::DrainCommitted { .. }
            | SessionEvent::AttemptStarted { .. }
            | SessionEvent::AttemptFinished { .. } => Self::Controller(0),
            SessionEvent::PipeHealthChanged(change) => Self::Health(change.pipe.0, change.half),
            SessionEvent::PipeAdded { pipe, .. } => Self::Added(pipe.0),
            SessionEvent::PipeJoined { pipe, .. } => Self::Joined(pipe.0),
            SessionEvent::PipeSuspect { pipe, .. } => Self::Suspect(pipe.0),
            SessionEvent::PipeRecovered { pipe, .. } => Self::Recovered(pipe.0),
            // Only an outbound direction fails.
            SessionEvent::PipeFailed { pipe, .. } => Self::Failed(pipe.0),
            SessionEvent::PipeClosed { pipe, half, .. } => Self::Closed(pipe.0, *half),
            SessionEvent::PipePriorityChanged { pipe, .. } => Self::Priority(pipe.0),
            SessionEvent::PipeQualityChanged { pipe, .. } => Self::Quality(pipe.0),
            SessionEvent::TierSaturation { priority, .. } => Self::Tier(*priority),
            SessionEvent::JoinAuthFailed { reason, .. } => Self::JoinAuth(reason),
            SessionEvent::CapacityBelow { .. } => Self::CapacityBelow,
            SessionEvent::CapacityRestored { .. } => Self::CapacityRestored,
            SessionEvent::EpochCommitted { .. } => Self::EpochCommitted,
            SessionEvent::EpochDeleted { .. } => Self::EpochDeleted,
            SessionEvent::DatagramPathChanged { .. } => Self::DatagramPath,
            SessionEvent::Shaping(event) => Self::Shaping(event.kind),
            SessionEvent::CarrierCandidate { kind, variant, .. } => {
                Self::Candidate(*kind, variant.clone())
            }
            SessionEvent::CarrierChosen(..) => Self::Chosen,
            SessionEvent::SessionSuspended => Self::Suspended,
            SessionEvent::SessionResumed => Self::Resumed,
            SessionEvent::ResumeUnattended => Self::Unattended,
            SessionEvent::GoAwayReceived(_) => Self::GoAway,
            SessionEvent::PipesRetired { .. } => return None,
        })
    }
}

/// Updates the unread `old` of a key with `new`, the event that occurred.
fn merge(old: &mut SessionEvent, new: SessionEvent) {
    match (old, new) {
        (
            SessionEvent::JoinAuthFailed { count, .. },
            SessionEvent::JoinAuthFailed { count: n, .. },
        ) => {
            *count = count.saturating_add(n);
        }
        // Each occurs once per pipe (direction): the unread one stays.
        (
            SessionEvent::PipeAdded { .. }
            | SessionEvent::PipeJoined { .. }
            | SessionEvent::PipeFailed { .. }
            | SessionEvent::PipeClosed { .. },
            _,
        ) => {}
        (old, new) => *old = new,
    }
}

#[derive(Default, Debug)]
struct RecentHealth {
    pipes: [Option<u64>; SUMMARY_IDS],
    next: usize,
}

impl RecentHealth {
    fn retired(&mut self, pipe: u64) -> Option<u64> {
        let expired = self.pipes[self.next].replace(pipe);
        self.next = (self.next + 1) % SUMMARY_IDS;
        expired
    }
}

const NIL: usize = usize::MAX;

/// A node of the list: a queued event, or a free slot.
#[derive(Debug)]
struct Node {
    entry: Option<(Key, SessionEvent)>,
    prev: usize,
    next: usize,
}

/// The keyed, never dropping pipe-event queue of a session.
#[derive(Debug)]
pub(crate) struct EventQueue {
    /// The node of each queued key.
    index: HashMap<Key, usize>,
    nodes: Vec<Node>,
    /// Free slots of `nodes`.
    free: Vec<usize>,
    head: usize,
    tail: usize,
    /// The session is closed: nothing more is queued.
    frozen: bool,
    controller_next: u8,
    health_observed: Option<Box<RecentHealth>>,
    /// The pipes of which the application read a terminal event
    /// (`PipeFailed` or `PipeClosed`), until they are retired.
    read_terminal: std::collections::HashSet<u64>,
}

impl EventQueue {
    pub(crate) fn new() -> Self {
        Self {
            index: HashMap::new(),
            nodes: Vec::new(),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
            frozen: false,
            controller_next: 0,
            health_observed: None,
            read_terminal: std::collections::HashSet::new(),
        }
    }

    /// Unread events.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }

    /// From now on nothing enters the queue; what is queued is still read.
    pub(crate) fn freeze(&mut self) {
        self.frozen = true;
    }

    pub(super) fn observe_health(&mut self) {
        self.health_observed.get_or_insert_default();
    }

    /// Queues an event: updates the unread one of its key and moves it to
    /// the tail, or appends it.
    pub(crate) fn push(&mut self, event: SessionEvent) {
        if self.frozen
            || (self.health_observed.is_none()
                && matches!(event, SessionEvent::PipeHealthChanged(_)))
        {
            return;
        }
        let Some(mut key) = Key::of(&event) else {
            debug_assert!(false, "the summary is made by the queue");
            return;
        };
        if let Key::Controller(slot) = &mut key {
            *slot = self.controller_next;
            self.controller_next = self.controller_next.wrapping_add(1);
        }
        if matches!(event, SessionEvent::SessionResumed) {
            // Stale once the session resumed.
            self.remove(&Key::Unattended);
        }
        if let Some(&i) = self.index.get(&key) {
            if let Some((_, old)) = self.nodes[i].entry.as_mut() {
                merge(old, event);
            }
            self.unlink(i);
            self.link_tail(i);
        } else {
            self.insert(key, event);
        }
    }

    /// A pipe was retired, its own end a failure (`failed`) or not: its
    /// unread events leave the queue; unless the application read a
    /// terminal event of it, the summary counts it as failed or closed.
    pub(crate) fn retire(&mut self, pipe: u64, failed: bool) {
        if self.frozen {
            return;
        }
        self.fold_retired(pipe, failed);
    }

    fn fold_retired(&mut self, pipe: u64, failed: bool) {
        for key in Key::of_pipe(pipe) {
            self.remove(&key);
        }
        if let Some(expired) = self
            .health_observed
            .as_mut()
            .and_then(|health| health.retired(pipe))
        {
            for half in [PipeHalf::Inbound, PipeHalf::Outbound] {
                self.remove(&Key::Health(expired, half));
            }
        }
        let read = self.read_terminal.remove(&pipe);
        let (f, c) = (u64::from(failed && !read), u64::from(!failed && !read));
        if let Some(&i) = self.index.get(&Key::Retired) {
            if let Some((
                _,
                SessionEvent::PipesRetired {
                    retired,
                    failed,
                    closed,
                    last,
                },
            )) = self.nodes[i].entry.as_mut()
            {
                *retired = retired.saturating_add(1);
                *failed += f;
                *closed += c;
                if last.len() == SUMMARY_IDS {
                    last.remove(0);
                }
                last.push(PipeId(pipe));
            }
            self.unlink(i);
            self.link_tail(i);
        } else {
            self.insert(
                Key::Retired,
                SessionEvent::PipesRetired {
                    retired: 1,
                    failed: f,
                    closed: c,
                    last: vec![PipeId(pipe)],
                },
            );
        }
    }

    /// The next event, the one whose key occurred longest ago.
    pub(crate) fn pop(&mut self) -> Option<SessionEvent> {
        let i = self.head;
        if i == NIL {
            return None;
        }
        let key = self.nodes[i].entry.as_ref()?.0.clone();
        self.index.remove(&key);
        if let Key::Failed(pipe) | Key::Closed(pipe, _) = key {
            self.read_terminal.insert(pipe);
        }
        self.release(i)
    }

    fn remove(&mut self, key: &Key) -> Option<SessionEvent> {
        let i = self.index.remove(key)?;
        self.release(i)
    }

    /// Unlinks node `i` and frees it, returning its event.
    fn release(&mut self, i: usize) -> Option<SessionEvent> {
        self.unlink(i);
        let node = &mut self.nodes[i];
        node.prev = NIL;
        node.next = NIL;
        let entry = node.entry.take();
        self.free.push(i);
        entry.map(|(_, e)| e)
    }

    fn insert(&mut self, key: Key, event: SessionEvent) {
        let node = Node {
            entry: Some((key.clone(), event)),
            prev: NIL,
            next: NIL,
        };
        let i = if let Some(i) = self.free.pop() {
            self.nodes[i] = node;
            i
        } else {
            self.nodes.push(node);
            self.nodes.len() - 1
        };
        self.index.insert(key, i);
        self.link_tail(i);
    }

    fn link_tail(&mut self, i: usize) {
        self.nodes[i].prev = self.tail;
        self.nodes[i].next = NIL;
        if self.tail == NIL {
            self.head = i;
        } else {
            let t = self.tail;
            self.nodes[t].next = i;
        }
        self.tail = i;
    }

    fn unlink(&mut self, i: usize) {
        let (prev, next) = (self.nodes[i].prev, self.nodes[i].next);
        if prev == NIL {
            if self.head != i {
                // Not linked.
                return;
            }
            self.head = next;
        } else {
            self.nodes[prev].next = next;
        }
        if next == NIL {
            self.tail = prev;
        } else {
            self.nodes[next].prev = prev;
        }
        self.nodes[i].prev = NIL;
        self.nodes[i].next = NIL;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CandidateOutcome::{Failed, TimedOut, Usable};
    use crate::proto::session::PrioritySource;

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

    fn suspect(pipe: u64) -> SessionEvent {
        SessionEvent::PipeSuspect {
            pipe: PipeId(pipe),
            carrier: None,
        }
    }

    fn recovered(pipe: u64) -> SessionEvent {
        SessionEvent::PipeRecovered {
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

    fn auth(reason: &'static str) -> SessionEvent {
        SessionEvent::JoinAuthFailed { reason, count: 1 }
    }

    fn quality(pipe: u64, ms: u64) -> SessionEvent {
        SessionEvent::PipeQualityChanged {
            pipe: PipeId(pipe),
            smoothed_rtt: Some(std::time::Duration::from_millis(ms)),
            delivery_rate: None,
        }
    }

    fn tier(priority: u64, saturated: bool) -> SessionEvent {
        SessionEvent::TierSaturation {
            priority,
            saturated,
        }
    }

    fn retired(retired: u64, failed: u64, closed: u64, last: &[u64]) -> SessionEvent {
        SessionEvent::PipesRetired {
            retired,
            failed,
            closed,
            last: last.iter().map(|&p| PipeId(p)).collect(),
        }
    }

    fn goaway(max: u64) -> crate::GoAway {
        crate::GoAway {
            max_bidi: max,
            max_uni: max,
            code: 7,
        }
    }

    fn drain(q: &mut EventQueue) -> Vec<SessionEvent> {
        std::iter::from_fn(|| q.pop()).collect()
    }

    /// An event of a key with an unread one updates it and moves it to the
    /// tail: the order read is that of the keys' latest occurrences.
    #[test]
    fn update_moves_the_key_to_the_tail() {
        let mut q = EventQueue::new();
        q.push(SessionEvent::SessionSuspended);
        q.push(added(2));
        q.push(SessionEvent::SessionResumed);
        assert_eq!(
            drain(&mut q),
            [
                SessionEvent::SessionSuspended,
                added(2),
                SessionEvent::SessionResumed
            ]
        );
        q.push(quality(2, 10));
        q.push(tier(1, true));
        q.push(quality(4, 10));
        q.push(quality(2, 30));
        q.push(tier(1, false));
        assert_eq!(
            drain(&mut q),
            [quality(4, 10), quality(2, 30), tier(1, false)]
        );
    }

    /// The event key table, kind by kind.
    #[test]
    fn the_key_table() {
        let mut q = EventQueue::new();
        // Once per pipe: the unread one stays.
        q.push(joined(2));
        q.push(SessionEvent::PipeJoined {
            pipe: PipeId(2),
            carrier: Some(CarrierKind::Quic),
        });
        // Suspect and recovered are keys of their own, the latest of each.
        q.push(suspect(2));
        q.push(recovered(2));
        q.push(suspect(2));
        // Terminal states per direction.
        q.push(failed(2));
        q.push(SessionEvent::PipeFailed {
            pipe: PipeId(2),
            failure: Some(crate::PipeFailure::Stalled),
            carrier: None,
        });
        q.push(closed(2, PipeHalf::Inbound));
        q.push(closed(2, PipeHalf::Outbound));
        q.push(closed(2, PipeHalf::Inbound));
        // Priorities and tiers.
        let prio = |p, standby| SessionEvent::PipePriorityChanged {
            pipe: PipeId(p),
            send_priority: 1,
            standby,
            weight: 1,
            source: PrioritySource::Local,
        };
        q.push(prio(2, false));
        q.push(prio(2, true));
        q.push(tier(1, true));
        q.push(tier(2, true));
        q.push(tier(1, false));
        // Capacity: below and restored are keys of their own.
        q.push(SessionEvent::CapacityBelow { rate: 1 });
        q.push(SessionEvent::CapacityRestored { rate: 5 });
        q.push(SessionEvent::CapacityBelow { rate: 2 });
        // Epochs: the latest of each.
        for epoch in 1..4 {
            q.push(SessionEvent::EpochCommitted { epoch });
        }
        q.push(SessionEvent::EpochDeleted { epoch: 1 });
        q.push(SessionEvent::EpochDeleted { epoch: 2 });
        // Carriers: per kind and variant.
        let cand = |kind, variant: Option<&str>, outcome| SessionEvent::CarrierCandidate {
            kind,
            variant: variant.map(Arc::from),
            outcome,
            joined: false,
        };
        q.push(cand(CarrierKind::Quic, None, TimedOut));
        q.push(cand(CarrierKind::Quic, Some("a"), TimedOut));
        q.push(cand(CarrierKind::Quic, None, Usable));
        q.push(cand(CarrierKind::WebSocket, None, Failed));
        q.push(SessionEvent::CarrierChosen(CarrierKind::Quic, None));
        q.push(SessionEvent::CarrierChosen(CarrierKind::WebSocket, None));
        // GOAWAY: the latest.
        for max in [8, 4] {
            q.push(SessionEvent::GoAwayReceived(goaway(max)));
        }
        // Each key where its latest occurrence stood.
        assert_eq!(
            drain(&mut q),
            [
                joined(2),
                recovered(2),
                suspect(2),
                failed(2),
                closed(2, PipeHalf::Outbound),
                closed(2, PipeHalf::Inbound),
                prio(2, true),
                tier(2, true),
                tier(1, false),
                SessionEvent::CapacityRestored { rate: 5 },
                SessionEvent::CapacityBelow { rate: 2 },
                SessionEvent::EpochCommitted { epoch: 3 },
                SessionEvent::EpochDeleted { epoch: 2 },
                cand(CarrierKind::Quic, Some("a"), TimedOut),
                cand(CarrierKind::Quic, None, Usable),
                cand(CarrierKind::WebSocket, None, Failed),
                SessionEvent::CarrierChosen(CarrierKind::WebSocket, None),
                SessionEvent::GoAwayReceived(goaway(4)),
            ]
        );
    }

    /// Failed joins are counted per reason, at the tail.
    #[test]
    fn failed_joins_count_per_reason() {
        let mut q = EventQueue::new();
        q.push(auth("auth"));
        q.push(SessionEvent::SessionSuspended);
        q.push(auth("kex"));
        q.push(auth("auth"));
        q.push(auth("auth"));
        assert_eq!(
            drain(&mut q),
            [
                SessionEvent::SessionSuspended,
                auth("kex"),
                SessionEvent::JoinAuthFailed {
                    reason: "auth",
                    count: 3
                },
            ]
        );
    }

    /// A resume removes the unread `ResumeUnattended`; a read one is not
    /// missed, and a later one queues again.
    #[test]
    fn resume_removes_resume_unattended() {
        let mut q = EventQueue::new();
        q.push(SessionEvent::SessionSuspended);
        q.push(SessionEvent::ResumeUnattended);
        q.push(SessionEvent::SessionResumed);
        assert_eq!(
            drain(&mut q),
            [SessionEvent::SessionSuspended, SessionEvent::SessionResumed]
        );
        q.push(SessionEvent::SessionSuspended);
        q.push(SessionEvent::ResumeUnattended);
        assert_eq!(q.pop(), Some(SessionEvent::SessionSuspended));
        q.push(SessionEvent::SessionResumed);
        assert_eq!(q.pop(), Some(SessionEvent::SessionResumed));
        assert_eq!(q.pop(), None);
        q.push(SessionEvent::ResumeUnattended);
        assert_eq!(q.pop(), Some(SessionEvent::ResumeUnattended));
    }

    #[test]
    fn retirement_folds_into_one_summary() {
        let mut q = EventQueue::new();
        for pipe in 0..10u64 {
            let p = pipe * 2 + 1;
            q.push(added(p));
            q.push(joined(p));
            if pipe % 2 == 0 {
                q.push(failed(p));
            } else {
                q.push(closed(p, PipeHalf::Inbound));
            }
            q.retire(p, pipe % 2 == 0);
        }
        assert_eq!(q.len(), 1);
        assert_eq!(drain(&mut q), [retired(10, 5, 5, &[13, 15, 17, 19])]);
        // A retirement after the summary was read starts a new one.
        q.retire(21, false);
        assert_eq!(drain(&mut q), [retired(1, 0, 1, &[21])]);
    }

    /// The summary is a key: it moves to the tail at each retirement.
    #[test]
    fn the_summary_moves_to_the_tail() {
        let mut q = EventQueue::new();
        q.push(joined(2));
        q.retire(2, false);
        q.push(SessionEvent::SessionSuspended);
        q.retire(4, true);
        assert_eq!(
            drain(&mut q),
            [SessionEvent::SessionSuspended, retired(2, 1, 1, &[2, 4])]
        );
    }

    /// Quality reports leave with their pipe; the capacity state keeps
    /// its latest crossing.
    #[test]
    fn a_pipes_keys_leave_with_it() {
        let mut q = EventQueue::new();
        q.push(quality(2, 10));
        q.push(SessionEvent::CapacityBelow { rate: 1 });
        q.push(quality(4, 10));
        q.push(quality(2, 30));
        q.push(SessionEvent::CapacityRestored { rate: 9 });
        q.retire(4, false);
        assert_eq!(
            drain(&mut q),
            [
                SessionEvent::CapacityBelow { rate: 1 },
                quality(2, 30),
                SessionEvent::CapacityRestored { rate: 9 },
                retired(1, 0, 1, &[4]),
            ]
        );
    }

    /// A retired pipe counts by the core's failure flag, failed or else
    /// closed, unless the application read a terminal event of it: one never
    /// queued counts, one unread counts whatever remains unread, one read
    /// (of either direction) counts nowhere.
    #[test]
    fn retirement_counts_unread_outcomes_by_the_pipes_end() {
        let mut q = EventQueue::new();
        // Read terminal states: neither, whatever the flag.
        q.push(failed(1));
        q.push(closed(3, PipeHalf::Outbound));
        q.push(closed(5, PipeHalf::Inbound));
        let _ = drain(&mut q);
        // Outbound FAILED read, the inbound end still unread: neither.
        q.push(failed(7));
        q.push(closed(7, PipeHalf::Inbound));
        assert_eq!(q.pop(), Some(failed(7)));
        for (p, flag) in [(1, true), (3, false), (5, false), (7, true)] {
            q.retire(p, flag);
        }
        assert_eq!(drain(&mut q), [retired(4, 0, 0, &[1, 3, 5, 7])]);
        // Unread, or never queued: counted by the flag, not by the event
        // that remains unread.
        q.push(closed(9, PipeHalf::Inbound));
        q.push(failed(11));
        q.push(joined(13));
        q.push(closed(15, PipeHalf::Inbound));
        for (p, flag) in [(9, true), (11, false), (13, true), (15, false), (17, false)] {
            q.retire(p, flag);
        }
        assert_eq!(drain(&mut q), [retired(5, 2, 3, &[11, 13, 15, 17])]);
    }

    /// Nothing enters a frozen queue (retirements included); what is
    /// queued is still read.
    #[test]
    fn a_frozen_queue_takes_nothing() {
        let mut q = EventQueue::new();
        q.push(joined(2));
        q.freeze();
        q.push(joined(4));
        q.push(SessionEvent::SessionResumed);
        q.retire(2, false);
        assert_eq!(q.len(), 1);
        assert_eq!(drain(&mut q), [joined(2)]);
        q.retire(6, false);
        assert_eq!(q.pop(), None);
    }

    /// A peer that fails joins by the thousand, beside the events of the
    /// session: they never displace one and the queue stays one slot per
    /// reason.
    #[test]
    fn failed_joins_never_displace_other_events() {
        let mut q = EventQueue::new();
        q.push(added(2));
        q.push(joined(2));
        q.push(SessionEvent::SessionSuspended);
        for i in 0..100_000u32 {
            q.push(auth(if i % 3 == 0 { "kex" } else { "auth" }));
        }
        assert_eq!(q.len(), 5);
        let got = drain(&mut q);
        assert_eq!(
            &got[..3],
            [added(2), joined(2), SessionEvent::SessionSuspended]
        );
        assert_eq!(
            got[3..],
            [
                // The last failure, number 99 999, was a `kex`.
                SessionEvent::JoinAuthFailed {
                    reason: "auth",
                    count: 66_666
                },
                SessionEvent::JoinAuthFailed {
                    reason: "kex",
                    count: 33_334
                },
            ]
        );
    }

    #[test]
    fn churn_stays_bounded() {
        let mut q = EventQueue::new();
        let mut most = 0;
        for i in 0..100_000u64 {
            let p = 2 * i + 1;
            q.push(added(p));
            q.push(joined(p));
            q.push(failed(p));
            q.push(closed(p, PipeHalf::Inbound));
            // Four keys of the pipe and the summary.
            most = most.max(q.len());
            q.retire(p, true);
        }
        assert_eq!(most, 5);
        assert_eq!(q.len(), 1);
        assert!(q.nodes.capacity() < 64, "{}", q.nodes.capacity());
        assert!(q.index.capacity() < 64, "{}", q.index.capacity());
    }
}
