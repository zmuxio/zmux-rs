//! Outcome counters at the session datagram owner.

use super::DatagramRoute;

/// Original datagrams dropped locally, grouped by cause.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramDrops {
    /// The required native representation was unavailable.
    pub no_native_path: u64,
    /// A queue's packet or byte budget refused or evicted the datagram.
    pub queue_overflow: u64,
    /// The application datagram limiter refused it.
    pub limiter: u64,
    /// CoDel dropped a head that spent too long in the queue.
    pub codel: u64,
    /// Its deadline elapsed or the estimated delivery could not meet it.
    pub deadline: u64,
    /// The send sequence space ran out.
    pub sequence_exhausted: u64,
    /// The owning Flow closed before dispatch.
    pub closed_flow: u64,
    /// The negotiated size limit no longer fits the queued datagram.
    pub size: u64,
    /// The carrier returned an error for an attempted handoff.
    pub carrier_rejected: u64,
    /// The channel closed before the handoff.
    pub carrier_cancelled: u64,
}

/// The reason an original datagram was dropped locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatagramDrop {
    /// The required native representation was unavailable.
    NoNativePath,
    /// The configured packet or byte allowance was exhausted.
    QueueOverflow,
    /// The application limiter refused the datagram.
    Limiter,
    /// The send queue dropped an item whose delay stayed above its target.
    Codel,
    /// The datagram could no longer meet its deadline.
    Deadline,
    /// No sequence remains in this direction.
    SequenceExhausted,
    /// The owning Flow closed before dispatch.
    ClosedFlow,
    /// The encoded datagram no longer fits the negotiated protocol bound.
    Size,
    /// The carrier rejected handoff.
    CarrierRejected,
    /// The channel closed before handoff.
    CarrierCancelled,
}

impl DatagramDrops {
    const EMPTY: Self = Self {
        no_native_path: 0,
        queue_overflow: 0,
        limiter: 0,
        codel: 0,
        deadline: 0,
        sequence_exhausted: 0,
        closed_flow: 0,
        size: 0,
        carrier_rejected: 0,
        carrier_cancelled: 0,
    };

    pub(super) fn count(&mut self, reason: DatagramDrop, count: u64) {
        let counter = match reason {
            DatagramDrop::NoNativePath => &mut self.no_native_path,
            DatagramDrop::QueueOverflow => &mut self.queue_overflow,
            DatagramDrop::Limiter => &mut self.limiter,
            DatagramDrop::Codel => &mut self.codel,
            DatagramDrop::Deadline => &mut self.deadline,
            DatagramDrop::SequenceExhausted => &mut self.sequence_exhausted,
            DatagramDrop::ClosedFlow => &mut self.closed_flow,
            DatagramDrop::Size => &mut self.size,
            DatagramDrop::CarrierRejected => &mut self.carrier_rejected,
            DatagramDrop::CarrierCancelled => &mut self.carrier_cancelled,
        };
        *counter += count;
    }

    pub(in crate::proto::session) fn without_limiter(self) -> u64 {
        self.no_native_path
            + self.queue_overflow
            + self.codel
            + self.deadline
            + self.sequence_exhausted
            + self.closed_flow
            + self.size
            + self.carrier_rejected
            + self.carrier_cancelled
    }
}

/// Replicas that could not be sent. These do not count as original datagram drops.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramReplicaDegradation {
    /// The byte budget or pending-replica queue could not take another copy.
    pub budget: u64,
    /// There was no suitable additional pipe.
    pub no_eligible_pipe: u64,
    /// Required independence could not be proved.
    pub fate: u64,
    /// The stream OPEN was still unconfirmed.
    pub open_fence: u64,
    /// Candidate paths could not carry the copy's encoded size.
    pub size: u64,
    /// A copy expired or could not be delivered by its deadline.
    pub deadline: u64,
    /// The carrier returned an error for an attempted handoff.
    pub carrier_rejected: u64,
    /// The channel closed before the handoff.
    pub carrier_cancelled: u64,
}

// Order reflects how far a candidate made it through placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::proto::session) enum ReplicaDegradation {
    NoEligiblePipe,
    Fate,
    Size,
    Deadline,
    OpenFence,
    Budget,
    CarrierRejected,
    CarrierCancelled,
}

impl DatagramReplicaDegradation {
    const EMPTY: Self = Self {
        budget: 0,
        no_eligible_pipe: 0,
        fate: 0,
        open_fence: 0,
        size: 0,
        deadline: 0,
        carrier_rejected: 0,
        carrier_cancelled: 0,
    };

    pub(in crate::proto::session) fn count(&mut self, reason: ReplicaDegradation, count: u64) {
        let counter = match reason {
            ReplicaDegradation::Budget => &mut self.budget,
            ReplicaDegradation::NoEligiblePipe => &mut self.no_eligible_pipe,
            ReplicaDegradation::Fate => &mut self.fate,
            ReplicaDegradation::OpenFence => &mut self.open_fence,
            ReplicaDegradation::Size => &mut self.size,
            ReplicaDegradation::Deadline => &mut self.deadline,
            ReplicaDegradation::CarrierRejected => &mut self.carrier_rejected,
            ReplicaDegradation::CarrierCancelled => &mut self.carrier_cancelled,
        };
        *counter += count;
    }
}

/// Local dispatch and acceptance counts for one outgoing representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramDispatchStats {
    /// Original dispatch attempts.
    pub originals: u64,
    /// Payload bytes in those original attempts.
    pub original_bytes: u64,
    /// Attempts accepted at the record or native handoff.
    pub originals_accepted: u64,
    /// Payload bytes accepted at original handoff.
    pub original_bytes_accepted: u64,
    /// Attempts the native carrier refused, cancelled or let expire.
    pub originals_failed: u64,
    /// Replica dispatch attempts.
    pub replicas: u64,
    /// Payload bytes in those replica attempts.
    pub replica_bytes: u64,
    /// Replicas accepted at the record or native handoff.
    pub replicas_accepted: u64,
    /// Payload bytes accepted at replica handoff.
    pub replica_bytes_accepted: u64,
    /// Attempts the native carrier refused, cancelled or let expire.
    pub replicas_failed: u64,
}

impl DatagramDispatchStats {
    const EMPTY: Self = Self {
        originals: 0,
        original_bytes: 0,
        originals_accepted: 0,
        original_bytes_accepted: 0,
        originals_failed: 0,
        replicas: 0,
        replica_bytes: 0,
        replicas_accepted: 0,
        replica_bytes_accepted: 0,
        replicas_failed: 0,
    };

    fn dispatch(&mut self, replica: bool, bytes: u64, accepted: bool) {
        if replica {
            self.replicas += 1;
            self.replica_bytes += bytes;
        } else {
            self.originals += 1;
            self.original_bytes += bytes;
        }
        if accepted {
            self.finish(replica, true, bytes);
        }
    }

    pub(in crate::proto::session) fn finish(&mut self, replica: bool, accepted: bool, bytes: u64) {
        match (replica, accepted) {
            (true, true) => {
                self.replicas_accepted += 1;
                self.replica_bytes_accepted += bytes;
            }
            (true, false) => self.replicas_failed += 1,
            (false, true) => {
                self.originals_accepted += 1;
                self.original_bytes_accepted += bytes;
            }
            (false, false) => self.originals_failed += 1,
        }
    }
}

/// Datagram outcomes in a session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramStats {
    /// Inbound datagrams already received on this or another path.
    pub duplicates_dropped: u64,
    /// Inbound datagrams older than the sequence window.
    pub stale_dropped: u64,
    /// Outgoing original drops.
    pub drops: DatagramDrops,
    /// Outgoing replicas abandoned, with the original accounted separately.
    pub replica_degradation: DatagramReplicaDegradation,
    /// Outgoing record dispatches.
    pub record: DatagramDispatchStats,
    /// Outgoing native dispatches.
    pub native: DatagramDispatchStats,
}

impl DatagramStats {
    pub(in crate::proto::session) const EMPTY: Self = Self {
        duplicates_dropped: 0,
        stale_dropped: 0,
        drops: DatagramDrops::EMPTY,
        replica_degradation: DatagramReplicaDegradation::EMPTY,
        record: DatagramDispatchStats::EMPTY,
        native: DatagramDispatchStats::EMPTY,
    };

    pub(super) fn dispatch(&mut self, route: DatagramRoute, replica: bool, bytes: u64) {
        match route {
            DatagramRoute::Record(_) => self.record.dispatch(replica, bytes, true),
            DatagramRoute::Native(_) => self.native.dispatch(replica, bytes, false),
        }
    }
}
