//! The path layer's per-pipe state (MULTIPATH.md Sections 2, 5 to 9):
//! attachments with their inbound and outbound pipes, states, positions and
//! the per-pipe logs of what was sent; the estimates are in `estimator.rs`.
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
pub(crate) use inp::{Classified, FrameIn, InPipe, LaneEnd};
pub(crate) use lanes::{LaneState, OutLanes};
pub(crate) use out::{BatchStart, OutPipe, QueuedCopy};
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

/// Pipe states (STATE_MACHINE.md Section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipeState {
    /// Outbound or inbound: the join is not confirmed yet.
    Joining,
    /// Outbound: in use.
    Active,
    /// Outbound: no acknowledgement or write progress for T_suspect.
    Suspect,
    /// Outbound: removed gracefully, draining.
    Draining,
    /// Outbound: failed.
    Failed,
    /// Outbound: drained and shut down.
    Closed,
    /// Inbound: receiving.
    Open,
    /// Inbound: ended.
    Ended,
    /// Either: the attachment is retired and its state freed.
    Retired,
}

/// Outbound pipe states (STATE_MACHINE.md Section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutState {
    /// A local join that may not be sent yet (the cap of unretired
    /// attachments, or the refusal backoff, MULTIPATH.md Sections 5.4 step
    /// 9 and 5.7 step 1): its carrier stays silent, nothing names its ID,
    /// and it has no timers. Reported as joining.
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

    pub(crate) fn public(self) -> PipeState {
        match self {
            Self::Deferred | Self::Joining => PipeState::Joining,
            Self::Active => PipeState::Active,
            Self::Suspect => PipeState::Suspect,
            Self::Draining => PipeState::Draining,
            Self::Failed => PipeState::Failed,
            Self::Closed => PipeState::Closed,
        }
    }
}

/// Inbound pipe states (STATE_MACHINE.md Section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InState {
    /// See [`OutState::Deferred`].
    Deferred,
    Joining,
    Open,
    Ended,
}

impl InState {
    pub(crate) fn public(self) -> PipeState {
        match self {
            Self::Deferred | Self::Joining => PipeState::Joining,
            Self::Open => PipeState::Open,
            Self::Ended => PipeState::Ended,
        }
    }
}

/// A frame whose information is re-sent when its pipe fails
/// (MULTIPATH.md Section 7.4), or whose acknowledgement matters.
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
    /// A QX_PING request: it stops being outstanding when its pipe fails
    /// (SPEC.md Section 4.5).
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

/// Where an effective setting comes from (MULTIPATH.md Section 9).
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
    /// window, whose lowest pipe number is `low` (MULTIPATH.md Section
    /// 4.3).
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
