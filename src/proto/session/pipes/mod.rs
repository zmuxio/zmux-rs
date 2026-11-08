//! The path layer's per-pipe state: attachments with their inbound and
//! outbound pipes, states, positions and the per-pipe logs of what was
//! sent; the estimates are in `estimator.rs`.
//!
//! The state of each type is private to its module: the session reads it
//! through accessors and changes it through the operations here, which keep
//! a pipe's invariants (its state machine, its positions and logs, the
//! PIPE_ABANDON exchange of its attachment, its probation and tier
//! settings) with the state they belong to.

mod att;
mod inp;
mod lanes;
mod out;
mod probation;
mod rate;
mod tier_state;

pub(crate) use super::estimator::{AckSample, Batch, Estimator, INITIAL_RTT, RttSample};
use super::stream::StreamKey;

pub(crate) use att::Attachment;
pub(crate) use inp::{Classified, InPipe, LaneEnd};
pub(crate) use lanes::{LaneState, OutLanes};
pub(crate) use out::{BatchStart, Channel, Detection, OutPipe, QueuedCopy, splitmix};
pub(crate) use probation::History;
pub(crate) use rate::{RateLimiter, TokenBucket};
pub(crate) use tier_state::TierState;

/// One direction of an attachment, seen from the local endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipeHalf {
    /// The pipe the local endpoint reads.
    Inbound,
    /// The pipe the local endpoint writes.
    Outbound,
}

/// The state of an outbound pipe direction (a retired attachment has no
/// state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundState {
    /// The join is not confirmed yet.
    Joining,
    /// In use.
    Active,
    /// No acknowledgement or write progress for T_suspect.
    Suspect,
    /// Removed gracefully, draining.
    Draining,
    /// Failed.
    Failed,
    /// Drained and shut down.
    Closed,
}

impl OutboundState {
    /// Whether the direction reached its end ([`Self::Failed`] or
    /// [`Self::Closed`]).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Closed)
    }
}

/// The state of an inbound pipe direction (a retired attachment has no
/// state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboundState {
    /// The join is not confirmed yet.
    Joining,
    /// Receiving.
    Open,
    /// Ended.
    Ended,
}

impl InboundState {
    /// Whether the direction reached its end ([`Self::Ended`]).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ended)
    }
}

/// The state of one direction of an attachment, as a state change reports
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectionState {
    /// The outbound direction's state.
    Outbound(OutboundState),
    /// The inbound direction's state.
    Inbound(InboundState),
}

impl DirectionState {
    /// Which direction.
    #[must_use]
    pub const fn half(self) -> PipeHalf {
        match self {
            Self::Outbound(_) => PipeHalf::Outbound,
            Self::Inbound(_) => PipeHalf::Inbound,
        }
    }

    /// Whether the direction reached its end.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        match self {
            Self::Outbound(s) => s.is_terminal(),
            Self::Inbound(s) => s.is_terminal(),
        }
    }
}

/// Outbound pipe states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutState {
    /// A local join that may not be sent yet (the cap of unretired
    /// attachments, or the refusal backoff): its carrier stays silent,
    /// nothing names its ID, and it has no timers. Reported as joining.
    Deferred,
    Joining,
    Active,
    Suspect,
    Draining,
    Failed,
    Closed,
}

impl OutState {
    pub(crate) fn is_live(self) -> bool {
        matches!(
            self,
            Self::Joining | Self::Active | Self::Suspect | Self::Draining
        )
    }

    pub(crate) fn public(self) -> OutboundState {
        match self {
            Self::Deferred | Self::Joining => OutboundState::Joining,
            Self::Active => OutboundState::Active,
            Self::Suspect => OutboundState::Suspect,
            Self::Draining => OutboundState::Draining,
            Self::Failed => OutboundState::Failed,
            Self::Closed => OutboundState::Closed,
        }
    }
}

/// Inbound pipe states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InState {
    /// See [`OutState::Deferred`].
    Deferred,
    Joining,
    Open,
    Ended,
}

impl InState {
    pub(crate) fn public(self) -> InboundState {
        match self {
            Self::Deferred | Self::Joining => InboundState::Joining,
            Self::Open => InboundState::Open,
            Self::Ended => InboundState::Ended,
        }
    }
}

/// A frame whose information is re-sent when its pipe fails, or
/// whose acknowledgement matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SentFrame {
    Stream {
        key: StreamKey,
        off: u64,
        len: u64,
        fin: bool,
    },
    Reset {
        key: StreamKey,
    },
    StopSending {
        key: StreamKey,
    },
    MaxData,
    MaxStreamData {
        key: StreamKey,
    },
    MaxStreams {
        dir: usize,
    },
    DataBlocked,
    StreamDataBlocked {
        key: StreamKey,
    },
    StreamsBlocked {
        dir: usize,
    },
    GoAway,
    PriorityUpdate {
        key: StreamKey,
        seq: u64,
    },
    PipeStatus {
        pipe: u64,
        seq: u64,
    },
    PipeAbandon {
        pipe: u64,
    },
    /// This end's SESSION_EPOCH answer: once acknowledged, this end switches epoch.
    EpochAnswer {
        epoch: u64,
    },
    /// A QX_PING request: it stops being outstanding when its pipe
    /// fails.
    Ping {
        seq: u64,
    },
}

/// The state of a revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Revalidation {
    /// Its PIPE_PING waits for the PIPE_PING limit.
    PingOwed,
    /// Its PIPE_PING was sent: it ends when the acknowledged position
    /// reaches this.
    Until(u64),
}

/// Where an effective setting comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrioritySource {
    /// Set locally.
    Local,
    /// The peer's PIPE_STATUS request.
    Peer,
    /// Neither: the default (priority 0, available).
    Default,
}

/// The attachments of a session in identifier order: outside multipath
/// only the bootstrap pair (pipe 0).
///
/// Loops that may retire attachments while they run walk them by
/// position ([`Attachments::at`]); everything else finds them by ID.
#[derive(Debug, Default)]
pub(crate) struct Attachments {
    list: Vec<Attachment>,
}

impl Attachments {
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.list.len()
    }

    /// The position of attachment `id`.
    #[inline]
    pub(crate) fn index_of(&self, id: u64) -> Option<usize> {
        if self.list.len() == 1 {
            return (self.list[0].id() == id).then_some(0);
        }
        self.list.binary_search_by_key(&id, Attachment::id).ok()
    }

    #[inline]
    pub(crate) fn get(&self, id: u64) -> Option<&Attachment> {
        self.index_of(id).map(|i| &self.list[i])
    }

    #[inline]
    pub(crate) fn get_mut(&mut self, id: u64) -> Option<&mut Attachment> {
        self.index_of(id).map(|i| &mut self.list[i])
    }

    /// The attachment at position `i`.
    #[inline]
    pub(crate) fn at(&self, i: usize) -> &Attachment {
        &self.list[i]
    }

    #[inline]
    pub(crate) fn at_mut(&mut self, i: usize) -> &mut Attachment {
        &mut self.list[i]
    }

    #[inline]
    pub(crate) fn iter_mut(&mut self) -> std::slice::IterMut<'_, Attachment> {
        self.list.iter_mut()
    }

    pub(crate) fn iter(&self) -> std::slice::Iter<'_, Attachment> {
        self.list.iter()
    }

    /// The outbound pipes.
    pub(crate) fn outs(&self) -> impl Iterator<Item = &OutPipe> {
        self.list.iter().filter_map(Attachment::out)
    }

    pub(crate) fn outs_mut(&mut self) -> impl Iterator<Item = &mut OutPipe> {
        self.list.iter_mut().filter_map(Attachment::out_mut)
    }

    pub(crate) fn inps_mut(&mut self) -> impl Iterator<Item = &mut InPipe> {
        self.list.iter_mut().filter_map(Attachment::inp_mut)
    }

    /// The first attachment: the bootstrap pair while it exists.
    #[inline]
    pub(crate) fn first(&self) -> Option<&Attachment> {
        self.list.first()
    }

    #[inline]
    pub(crate) fn first_mut(&mut self) -> Option<&mut Attachment> {
        self.list.first_mut()
    }

    /// The ID of the first attachment after `id`.
    pub(crate) fn next_after(&self, id: u64) -> Option<u64> {
        let i = self.list.partition_point(|a| a.id() <= id);
        self.list.get(i).map(Attachment::id)
    }

    /// Inserts `att` in identifier order; returns its position. The list
    /// grows by one: attachments come rarely and are bounded by
    /// `max_pipes`, and a quiet session holds no room for more.
    pub(crate) fn insert(&mut self, att: Attachment) -> usize {
        let pos = self.list.partition_point(|a| a.id() < att.id());
        self.list.reserve_exact(1);
        self.list.insert(pos, att);
        pos
    }

    pub(crate) fn remove(&mut self, i: usize) -> Attachment {
        self.list.remove(i)
    }

    /// Drops the unattached IDs of the peer that fell below the replay
    /// window, whose lowest pipe number is `low`.
    pub(crate) fn forget_unattached_below(&mut self, low: u64) {
        self.list
            .retain(|a| !(a.unattached() && (a.id() >> 1) < low));
    }

    /// Whether an attachment has a live inbound pipe.
    pub(crate) fn any_in_live(&self) -> bool {
        self.list.iter().any(Attachment::in_live)
    }

    /// Whether an attachment has a live outbound pipe.
    pub(crate) fn any_out_live(&self) -> bool {
        self.list.iter().any(Attachment::out_live)
    }

    /// Heap bytes held by the list and the attachments.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.list.capacity() * size_of::<Attachment>()
            + self.list.iter().map(Attachment::heap_bytes).sum::<usize>()
    }
}

impl<'a> IntoIterator for &'a Attachments {
    type Item = &'a Attachment;
    type IntoIter = std::slice::Iter<'a, Attachment>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_states_are_typed_per_direction() {
        // A deferred join reports joining in both directions.
        assert_eq!(OutState::Deferred.public(), OutboundState::Joining);
        assert_eq!(InState::Deferred.public(), InboundState::Joining);
        let out = DirectionState::Outbound(OutState::Failed.public());
        assert_eq!(out.half(), PipeHalf::Outbound);
        assert!(out.is_terminal());
        assert!(OutboundState::Closed.is_terminal());
        assert!(!OutboundState::Draining.is_terminal());
        let inb = DirectionState::Inbound(InState::Ended.public());
        assert_eq!(inb.half(), PipeHalf::Inbound);
        assert!(inb.is_terminal());
        assert!(!InboundState::Open.is_terminal());
    }
}
