//! Events the core reports to its driver.

use bytes::Bytes;

use crate::proto::frame::Dir;
use crate::proto::params::{Features, Role};

use super::pipes::{PipeHalf, PipeState, PrioritySource};
use super::stream::StreamKey;
use super::{LaneId, PipeId, SessionError};

/// An event for the driver or the application.
///
/// Stream events are edge-triggered and coalesced per stream: a stream has
/// at most one pending event of each kind.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreEvent {
    /// The peer's parameters were processed; roles and features are fixed.
    Established {
        /// The local role.
        role: Role,
        /// The features in use.
        features: Features,
        /// The application protocol negotiated with `protocols` (SPEC.md
        /// Section 13.3), when both endpoints offered one.
        protocol: Option<Box<str>>,
    },
    /// A peer stream of this type can be accepted.
    StreamOpened(Dir),
    /// A session window increase waits for
    /// `allow_connection_window_increase`: take it with
    /// [`super::SessionCore::take_window_increase`], run the predicate outside
    /// every lock and answer with [`super::SessionCore::answer_window_increase`].
    WindowIncrease,
    /// A stream has data, an end, or an error to read.
    StreamReadable(StreamKey),
    /// A stream accepts more data, or its sending part ended.
    StreamWritable(StreamKey),
    /// A stream received a datagram (datagram flows).
    StreamDatagram(StreamKey),
    /// Opening a stream of this type may succeed now.
    StreamsAvailable(Dir),
    /// A session datagram was received.
    DatagramReceived,
    /// The datagram send queue has room again.
    DatagramsUnblocked,
    /// Received datagrams were dropped from full queues since the last
    /// event of this kind.
    DatagramsDropped {
        /// Number of datagrams dropped.
        count: u64,
    },
    /// The peer lowered a GOAWAY watermark.
    GoAway {
        /// Bidirectional watermark.
        max_bidi: u64,
        /// Unidirectional watermark.
        max_uni: u64,
        /// The peer's application error code.
        code: u64,
    },
    /// A pipe changed state (STATE_MACHINE.md Section 3).
    PipeState {
        /// The attachment.
        pipe: PipeId,
        /// Which of its pipes.
        half: PipeHalf,
        /// The new state.
        state: PipeState,
    },
    /// The effective priority, standby flag or weight of a pipe's outbound
    /// direction changed (MULTIPATH.md Section 9).
    PipePriorityChanged {
        /// The attachment.
        pipe: PipeId,
        /// The effective priority (lower preferred).
        send_priority: u64,
        /// The effective standby flag.
        standby: bool,
        /// The weight.
        weight: u64,
        /// Where the priority comes from.
        source: PrioritySource,
    },
    /// A tier of the local outbound direction entered or left saturation; at
    /// most one event per tier per second,
    /// the latest state winning.
    TierSaturation {
        /// The tier's priority.
        priority: u64,
        /// Saturated now.
        saturated: bool,
    },
    /// An outbound pipe's estimates left its quality band
    /// ([`super::SessionCore::set_quality_band`]): the
    /// band now centres on these values. At most one per pipe per
    /// `min_interval`, the latest values winning.
    PipeQualityChanged {
        /// The attachment.
        pipe: PipeId,
        /// The smoothed RTT; `None` before the first sample.
        smoothed_rtt: Option<std::time::Duration>,
        /// The delivery rate R_p in bytes per second; `None` before it was
        /// measured, or without pipe acknowledgement.
        delivery_rate: Option<u64>,
    },
    /// The outbound capacity, the sum of the delivery rates of the usable
    /// non-standby outbound pipes, fell below the floor
    /// ([`super::SessionCore::set_capacity_floor`]).
    CapacityBelow {
        /// The capacity in bytes per second.
        rate: u64,
    },
    /// The outbound capacity rose to the floor times its ratio again.
    CapacityRestored {
        /// The capacity in bytes per second.
        rate: u64,
    },
    /// Hand this PIPE_JOIN to the pipe's adapter for out-of-band delivery
    /// (MULTIPATH.md Section 5.3), for example in the `Zmux-Pipe-Join`
    /// header.
    OobJoin {
        /// The new attachment.
        pipe: PipeId,
        /// The frame, Type through Join Token.
        frame: Bytes,
    },
    /// A join's token did not verify (MULTIPATH.md Section 5.4 step 5).
    JoinAuthFailed {
        /// The token was carrier-bound.
        carrier_bound: bool,
    },
    /// Close a pipe's carrier half, every lane of it: after a failure
    /// (`abort`), or at the end of a drain or linger. An outbound pipe that
    /// drains gracefully is shut down through [`super::Transmit::Shutdown`]
    /// instead.
    ClosePipe {
        /// The attachment.
        pipe: PipeId,
        /// Which of its pipes.
        half: PipeHalf,
        /// Abortively (the pipe failed).
        abort: bool,
    },
    /// Open a lane of an outbound pipe (MULTIPATH.md Section 5.8): a new
    /// stream of the carrier connection of the pipe's lane 0, attached
    /// with [`super::SessionCore::lane_opened`] once the carrier's stream
    /// credit allows; a stream that cannot be opened is reported with
    /// [`super::SessionCore::write_failed`].
    OpenLane(LaneId),
    /// Reset an outbound lane that was not confirmed in time (MULTIPATH.md
    /// Section 5.8): it is refused, which is no failure of its pipe.
    ResetLane(LaneId),
    /// The session entered SUSPENDED (RESUME.md Section 4).
    Suspended,
    /// The session left SUSPENDED.
    Resumed,
    /// A QX_PING request was answered with this RTT sample
    /// ([`super::SessionCore::ping_rtt`]).
    PingAnswered {
        /// The round-trip time measured.
        rtt: std::time::Duration,
    },
    /// Multipath was offered by both endpoints but no secret source
    /// matched: "join security unavailable" (MULTIPATH.md Section 3.3).
    JoinSecurityUnavailable,
    /// The session ended. Carriers are closed once `poll_transmit` reports
    /// it and the session is [`super::State::Closed`].
    Closed(SessionError),
}
