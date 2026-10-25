//! The scheduler's types: the
//! policies, the custom policy's interface and the per-direction state the
//! scheduler keeps. Lower layers (streams, configuration) name them without
//! depending on the scheduler itself.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::pipes::PipeState;
use super::{PipeId, StreamKey};

/// A scheduling policy.
#[derive(Clone, Default)]
pub enum Policy {
    /// Each stream direction is bound to one pipe (the session default).
    #[default]
    Affinity,
    /// Every chunk to the pipe with the earliest estimated arrival, with
    /// ECF/BLEST admission of slower pipes (the default spreading policy).
    SpreadEta,
    /// Every chunk to the next pipe of a smooth weighted round-robin by the
    /// pipes' weights.
    SpreadRoundRobin,
    /// The same round-robin by weight times measured delivery rate.
    SpreadRateWeighted,
    /// One active pipe per direction; the others carry no data.
    SessionAffinity,
    /// An application policy.
    Custom(Arc<dyn Pick>),
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Affinity => "Affinity",
            Self::SpreadEta => "SpreadEta",
            Self::SpreadRoundRobin => "SpreadRoundRobin",
            Self::SpreadRateWeighted => "SpreadRateWeighted",
            Self::SessionAffinity => "SessionAffinity",
            Self::Custom(_) => "Custom",
        })
    }
}

impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b),
            _ => std::mem::discriminant(self) == std::mem::discriminant(other),
        }
    }
}

/// An application scheduling policy. It never runs under a zmux lock: the
/// core hands the driver a value-only view of the stream directions waiting
/// for a decision ([`SessionCore::take_pick`](super::SessionCore::take_pick)), the driver calls the policy
/// outside every lock and gives the answers back
/// ([`SessionCore::answer_pick`](super::SessionCore::answer_pick)), which are applied if the view's generation is
/// still current; otherwise, and for an invalid answer or a panic, the chunk
/// takes the `affinity` choice and the miss is counted. The policy must not
/// block: the drivers call it on the
/// thread or task that drives the session, where a blocking zmux call fails
/// at once.
///
/// A pipe answer is sticky: the direction keeps using the pipe for its
/// chunks until the answer's bytes are used (0: until it is invalidated, by
/// a change of the pipe set, a pipe's state or eligibility, or a pipe's
/// ability to carry data). A [`PickAnswer::Wait`] holds only until the
/// core's next input; the direction is then asked again.
///
/// The built-in policies choose only among the eligible pipes of tier
/// gating; a custom policy sees every pipe that
/// may carry new data, with the gate's view in [`PipeSnapshot::eligible`],
/// and may override the gate.
///
/// # Example
///
/// Urgent streams on the lowest-delay pipe whatever its tier, everything
/// else on the eligible pipe with the most room, 256 KiB at a time:
///
/// ```
/// use std::sync::Arc;
/// use zmux::proto::session::{Config, FrameInfo, Pick, PickAnswer, PipeSnapshot, Policy};
///
/// struct UrgentFirst;
///
/// impl Pick for UrgentFirst {
///     fn pick(&self, reqs: &[FrameInfo], pipes: &[PipeSnapshot], out: &mut [PickAnswer]) {
///         let usable = || pipes.iter().enumerate().filter(|(_, p)| p.writable);
///         for (frame, answer) in reqs.iter().zip(out) {
///             let choice = if frame.urgency <= 2 {
///                 usable().min_by_key(|(_, p)| p.srtt)
///             } else {
///                 usable().filter(|(_, p)| p.eligible).min_by_key(|(_, p)| p.unsent)
///             };
///             if let Some((index, _)) = choice {
///                 *answer = PickAnswer::Pipe { index, bytes: 256 * 1024 };
///             }
///         }
///     }
/// }
///
/// let mut config = Config::default();
/// config.scheduler = Policy::Custom(Arc::new(UrgentFirst));
/// ```
pub trait Pick: Send + Sync + 'static {
    /// One answer per request, in `out` (preset to [`PickAnswer::Wait`]).
    /// An index out of range falls back to `affinity`.
    fn pick(&self, reqs: &[FrameInfo], pipes: &[PipeSnapshot], out: &mut [PickAnswer]);
}

/// A policy's answer for one stream direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PickAnswer {
    /// The pipe at `index` of the snapshots, for `bytes` of the direction's
    /// data (0: until the answer is invalidated).
    Pipe {
        /// Index into the pipe snapshots.
        index: usize,
        /// The bytes the answer covers; 0 for "until invalidated".
        bytes: u64,
    },
    /// Hold the direction until the core's next input.
    #[default]
    Wait,
}

/// The custom scheduling decisions for the driver to make outside the
/// lock: fill it with
/// [`SessionCore::take_pick`](super::SessionCore::take_pick), call [`PickRequest::run`] with no zmux lock
/// held, then hand it to [`SessionCore::answer_pick`](super::SessionCore::answer_pick). Reuse one request: its
/// buffers are kept.
#[derive(Default)]
pub struct PickRequest {
    /// The generation the view belongs to.
    pub generation: u64,
    /// The stream directions waiting for a decision.
    pub frames: Vec<FrameInfo>,
    /// The pipes that may carry new stream data.
    pub pipes: Vec<PipeSnapshot>,
    /// The answers, one per frame.
    pub answers: Vec<PickAnswer>,
    /// The policy to ask.
    pub policy: Option<Arc<dyn Pick>>,
    /// The stream directions of `frames`.
    pub(super) keys: Vec<StreamKey>,
    /// The policy panicked: every answer is a miss.
    pub(super) panicked: bool,
}

impl fmt::Debug for PickRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PickRequest")
            .field("generation", &self.generation)
            .field("frames", &self.frames)
            .field("pipes", &self.pipes)
            .field("answers", &self.answers)
            .finish_non_exhaustive()
    }
}

impl PickRequest {
    /// Asks the policy, catching a panic (which makes every answer a
    /// miss). Call it with no zmux lock held.
    pub fn run(&mut self) {
        self.answers.clear();
        self.answers.resize(self.frames.len(), PickAnswer::Wait);
        let Some(policy) = &self.policy else {
            self.panicked = true;
            return;
        };
        let (frames, pipes, answers) = (&self.frames, &self.pipes, &mut self.answers);
        self.panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            policy.pick(frames, pipes, answers);
        }))
        .is_err();
    }
}

/// The answer a stream direction holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Picked {
    /// Sticky: `left` bytes (`None`: until invalidated).
    Pipe {
        pipe: u64,
        generation: u64,
        left: Option<u64>,
    },
    /// Until the next input.
    Wait { generation: u64, epoch: u64 },
    /// The `affinity` choice for one chunk (a miss).
    Affinity,
}

/// A stream direction waiting for a custom decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrameInfo {
    /// The stream.
    pub stream: Option<u64>,
    /// Its urgency (0 most urgent).
    pub urgency: u8,
    /// Bytes of stream data ready to place.
    pub len: u64,
    /// The pipe the stream's previous chunk went to.
    pub last_pipe: Option<PipeId>,
    /// The most-preferred usable tier; the
    /// eligible pipes are marked in the snapshots.
    pub eligible_tier: Option<u64>,
}

/// A read-only view of an outbound pipe for a custom policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PipeSnapshot {
    /// The pipe.
    pub pipe: PipeId,
    /// Its state.
    pub state: PipeState,
    /// Smoothed RTT.
    pub srtt: Duration,
    /// RTT variation.
    pub rttvar: Duration,
    /// Delivery rate in bytes per second.
    pub rate: u64,
    /// Bytes the carrier has not transmitted yet.
    pub unsent: u64,
    /// Unacknowledged bytes.
    pub in_flight: u64,
    /// The carrier takes bytes now.
    pub writable: bool,
    /// The effective priority (lower preferred) and standby flag.
    pub priority: u64,
    /// Standby: used only on failover.
    pub standby: bool,
    /// The pipe's tier is saturated.
    pub saturated: bool,
    /// In probation.
    pub probation: bool,
    /// Eligible under tier gating: the built-in policies choose only
    /// among these.
    pub eligible: bool,
    /// The weight.
    pub weight: u64,
}

/// The pipe an `affinity` stream direction is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) pipe: u64,
    /// Made before every usable pipe had an RTT sample.
    pub(crate) provisional: bool,
    /// The usable-pipe generation the binding was made in: a binding made
    /// before a pipe that is usable now became usable is re-evaluated like
    /// a provisional one.
    pub(crate) epoch: u64,
    /// A move decided when the provisional binding was re-evaluated: no
    /// new data until the data on `pipe` is acknowledged (the idle point
    /// the sender creates), then the direction binds here.
    pub(crate) move_to: Option<u64>,
}
