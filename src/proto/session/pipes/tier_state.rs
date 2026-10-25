//! An attachment's tier settings (MULTIPATH.md Section 9): the local
//! settings of its outbound direction, the request for the peer's, the
//! peer's request, and the PIPE_STATUS frames owed.

use std::collections::VecDeque;
use std::time::Duration;

use super::PrioritySource;

/// An attachment's tier settings (MULTIPATH.md Section 9).
#[derive(Debug, Clone)]
pub(crate) struct TierState {
    /// Local settings of the outbound direction; `None` follows the peer's
    /// request, else the default.
    send_priority: Option<u64>,
    send_standby: Option<bool>,
    /// The request for the peer's outbound direction.
    receive_priority: u64,
    receive_standby: bool,
    /// A standby takeover is announced: the request says "available" until
    /// a non-standby pipe is usable again (MULTIPATH.md Section 9).
    takeover: bool,
    /// The peer's latest request (standby, priority) and its sequence.
    peer: Option<(bool, u64)>,
    peer_seq: u64,
    /// The last PIPE_STATUS sequence number assigned, and the requests
    /// owed: each change is one frame with the next number, and a lost
    /// frame is sent again only if it is the latest.
    seq: u64,
    owed: VecDeque<(u64, bool, u64)>,
    /// The outbound direction's weight (local).
    weight: u64,
    /// The base of the outbound direction's probation; `None` for the
    /// session default.
    probation: Option<Duration>,
}

impl Default for TierState {
    fn default() -> Self {
        Self::new()
    }
}

impl TierState {
    /// Unsent requests kept: a newer request supersedes older ones, so
    /// the oldest are dropped first (each frame states the whole request).
    const OWED: usize = 8;

    pub(super) const fn new() -> Self {
        Self {
            send_priority: None,
            send_standby: None,
            receive_priority: 0,
            receive_standby: false,
            takeover: false,
            peer: None,
            peer_seq: 0,
            seq: 0,
            owed: VecDeque::new(),
            weight: 1,
            probation: None,
        }
    }

    /// Heap bytes held.
    pub(super) fn heap_bytes(&self) -> usize {
        self.owed.capacity() * std::mem::size_of::<(u64, bool, u64)>()
    }

    // ---- reading -------------------------------------------------------------------

    /// The effective priority of the outbound direction and its source.
    #[inline]
    pub(crate) fn send_priority(&self) -> (u64, PrioritySource) {
        match (self.send_priority, self.peer) {
            (Some(p), _) => (p, PrioritySource::Local),
            (None, Some((_, p))) => (p, PrioritySource::Peer),
            (None, None) => (0, PrioritySource::Default),
        }
    }

    /// The effective standby flag of the outbound direction and its
    /// source.
    #[inline]
    pub(crate) fn standby(&self) -> (bool, PrioritySource) {
        match (self.send_standby, self.peer) {
            (Some(s), _) => (s, PrioritySource::Local),
            (None, Some((s, _))) => (s, PrioritySource::Peer),
            (None, None) => (false, PrioritySource::Default),
        }
    }

    /// The priority requested for the peer's outbound direction.
    #[inline]
    pub(crate) fn receive_priority(&self) -> u64 {
        self.receive_priority
    }

    /// Whether the peer is asked to use its outbound direction only on
    /// failover (the configured request, whatever a takeover announces).
    #[inline]
    pub(crate) fn receive_standby(&self) -> bool {
        self.receive_standby
    }

    /// A standby takeover is announced.
    #[inline]
    pub(crate) fn takeover(&self) -> bool {
        self.takeover
    }

    /// The peer's latest request: standby and priority.
    pub(crate) fn peer_request(&self) -> Option<(bool, u64)> {
        self.peer
    }

    /// The last PIPE_STATUS sequence number assigned.
    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    /// The outbound direction's weight.
    #[inline]
    pub(crate) fn weight(&self) -> u64 {
        self.weight
    }

    /// The outbound direction's probation base; `None` for the session
    /// default.
    #[inline]
    pub(crate) fn probation(&self) -> Option<Duration> {
        self.probation
    }

    /// The oldest PIPE_STATUS owed: sequence, standby, priority.
    #[inline]
    pub(crate) fn owed(&self) -> Option<(u64, bool, u64)> {
        self.owed.front().copied()
    }

    /// A PIPE_STATUS is owed.
    #[inline]
    pub(crate) fn status_owed(&self) -> bool {
        !self.owed.is_empty()
    }

    // ---- changing -------------------------------------------------------------------

    /// The settings of a new attachment's options (MULTIPATH.md Section
    /// 9); the initial request travels in the PIPE_JOIN (Section 5.1).
    pub(crate) fn configure(
        &mut self,
        send_priority: Option<u64>,
        send_standby: Option<bool>,
        receive_priority: u64,
        receive_standby: bool,
        weight: u64,
        probation: Option<Duration>,
    ) {
        self.send_priority = send_priority;
        self.send_standby = send_standby;
        self.receive_priority = receive_priority;
        self.receive_standby = receive_standby;
        self.weight = weight;
        self.probation = probation;
    }

    /// The local priority of the outbound direction; `None` follows the
    /// peer's request.
    pub(crate) fn set_send_priority(&mut self, priority: Option<u64>) {
        self.send_priority = priority;
    }

    /// The local standby flag of the outbound direction; `None` follows
    /// the peer's request.
    pub(crate) fn set_send_standby(&mut self, standby: Option<bool>) {
        self.send_standby = standby;
    }

    /// The request for the peer's outbound direction: its standby flag
    /// and priority, each when given.
    pub(crate) fn set_receive(&mut self, standby: Option<bool>, priority: Option<u64>) {
        if let Some(s) = standby {
            self.receive_standby = s;
        }
        if let Some(p) = priority {
            self.receive_priority = p;
        }
    }

    pub(crate) fn set_weight(&mut self, weight: u64) {
        self.weight = weight;
    }

    pub(crate) fn set_probation(&mut self, probation: Option<Duration>) {
        self.probation = probation;
    }

    /// The joiner's initial request for our outbound direction, carried
    /// by its PIPE_JOIN with sequence number 0 (MULTIPATH.md Section 5.1).
    pub(crate) fn join_request(&mut self, standby: bool, priority: u64) {
        self.peer = Some((standby, priority));
    }

    /// Whether a PIPE_STATUS with sequence number `seq` is newer than the
    /// last one taken.
    pub(crate) fn newer(&self, seq: u64) -> bool {
        seq > self.peer_seq
    }

    /// The peer's PIPE_STATUS request with sequence number `seq`.
    pub(crate) fn peer_status(&mut self, seq: u64, standby: bool, priority: u64) {
        self.peer_seq = seq;
        self.peer = Some((standby, priority));
    }

    /// Announces or ends a standby takeover.
    pub(crate) fn set_takeover(&mut self, takeover: bool) {
        self.takeover = takeover;
    }

    /// The standby flag the request carries now: the configured one,
    /// except during a takeover.
    fn requested_standby(&self) -> bool {
        self.receive_standby && !self.takeover
    }

    /// The current request as a new PIPE_STATUS with the next sequence
    /// number.
    pub(crate) fn request(&mut self) {
        self.seq += 1;
        if self.owed.len() >= Self::OWED {
            self.owed.pop_front();
        }
        self.owed
            .push_back((self.seq, self.requested_standby(), self.receive_priority));
    }

    /// The latest request again, after its frame was lost.
    pub(crate) fn request_again(&mut self, seq: u64) {
        if seq == self.seq && !self.owed.iter().any(|e| e.0 == seq) {
            self.owed
                .push_back((seq, self.requested_standby(), self.receive_priority));
        }
    }

    /// Only the latest request owed stays (a join was confirmed).
    pub(super) fn keep_latest_request(&mut self) {
        while self.owed.len() > 1 {
            self.owed.pop_front();
        }
    }

    /// The oldest PIPE_STATUS owed was written.
    pub(crate) fn status_written(&mut self) {
        self.owed.pop_front();
    }
}
