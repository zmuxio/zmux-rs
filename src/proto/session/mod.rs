//! The sans-IO session core.
//!
//! A [`SessionCore`] is a state machine without I/O and without a clock: every
//! input carries `now`, and every output is pulled by the driver.
//!
//! | Input | Method |
//! |---|---|
//! | bytes read from a pipe (a lane of it) | [`SessionCore::receive`], [`SessionCore::receive_in_place`], [`SessionCore::receive_message`] |
//! | pipe events | [`SessionCore::attach_pipe`], [`SessionCore::pipe_ended`], [`SessionCore::pipe_write`] |
//! | lanes | [`SessionCore::set_pipe_lanes`], [`SessionCore::lane_opened`], [`SessionCore::accept_lane`] |
//! | application commands | the stream, datagram and session methods |
//! | timers | [`SessionCore::handle_timeout`] |
//!
//! | Output | Method |
//! |---|---|
//! | bytes for a pipe or a lane of it (late binding) | [`SessionCore::poll_transmit`], [`SessionCore::wants_write`] |
//! | events (lanes to open: [`CoreEvent::OpenLane`]) | [`SessionCore::poll_event`] |
//! | the next deadline | [`SessionCore::poll_timeout`] |
//!
//! After any input or command the driver drains [`SessionCore::poll_event`],
//! calls [`SessionCore::poll_transmit`] for every writable pipe that
//! [`SessionCore::wants_write`] and writes each batch completely, and re-arms
//! its timer to [`SessionCore::poll_timeout`].
//!
//! Pipes are attachments with up to one inbound and one outbound pipe each. Outside multipath there
//! is exactly one, the bootstrap pair (pipe 0); in a multipath session pipes join and leave,
//! and every input and output names its pipe. A pipe whose carrier is a
//! stream of a multi-stream connection may have lanes, further streams of
//! that connection: the I/O calls then name the
//! lane ([`LaneId`]; a [`PipeId`] is the pipe's lane 0), and everything
//! else sees one pipe.

mod api;
mod app_event;
mod channel;
mod config;
mod credit;
mod early;
mod error;
mod estimator;
mod event;
mod filter;
mod input;
mod lanes;
mod limiter;
mod output;
mod pacing;
mod path;
use path::{ack, epoch, join, ledger, mpath, opp, redundancy, resume, sched, tier};
pub use tier::PipeUpdate;
mod pipe_ack;
mod pipes;
mod policy;
mod preamble;
mod quality;
mod ranges;
mod reasm;
mod recv_buf;
mod rtt;
mod shape;
mod shape_account;
pub mod shaping;
mod share;
mod stream;
mod streams;
mod tp;
mod transmit;
mod tuner;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::proto::frame::Dir;
use crate::proto::ident::Classifier;
use crate::proto::meter::{Count, Meter};
pub use crate::proto::params::Role;
use crate::proto::params::{Features, TransportParameters};
use crate::proto::record::Framing;
use crate::proto::{ApplicationErrorCode, Error, TransportErrorCode, VarInt};

pub use crate::proto::seal::RecordMode;
pub use api::{SendCapacity, SendOutcomeKind};
pub use app_event::{
    CandidateOutcome, CandidateResult, CarrierKind, GoAway, SessionEvent, Support, Tracer,
};
pub(crate) use config::Period;
#[cfg(feature = "test-hooks")]
pub use config::TestHooks;
pub use config::{AllowRecordMode, AuthorizeJoin, RecordPolicy, RecordPolicyInput};
pub use config::{
    Cap, Change, Config, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_JOIN_TIMEOUT,
    DEFAULT_KEEP_ALIVE_PERIOD, DEFAULT_LATENCY_BUDGET, DEFAULT_MAX_BACKOFF, DEFAULT_MEMORY_BUDGET,
    DEFAULT_MIN_BACKOFF, DEFAULT_OVERFLOW_DELAY, DEFAULT_PROBE_INTERVAL, DEFAULT_PROBE_JITTER,
    DEFAULT_SEND_BUFFER_MAX, DEFAULT_STANDBY_PROBE, DEFAULT_SUSPECT_FLOOR, EarlyData, Inherit,
    Liveness, LogFn, LogLevel, Logger, MAX_STREAM_CREDIT, PipeAuth, Redundancy,
    SESSION_WINDOW_FLOOR, STREAM_WINDOW_FLOOR, UniCredit, WindowIncrease,
};
pub use early::EarlyDataState;
pub use epoch::{
    DEFAULT_EPOCH_JOINS, DEFAULT_EPOCH_PERIOD, EPOCH_RETENTION, EpochPolicy, MAX_JOIN_DEADLINE,
};
pub(crate) use error::ON_DRIVER_THREAD;
pub use error::{
    DatagramError, InvalidConfig, JoinMissing, OpenError, PipeError, PipeFailure, SessionError,
    StreamError,
};
pub use event::CoreEvent;
pub use join::{
    ClaimedHello, ConfirmedJoin, JOIN_READ_BOUND, JoinFinished, JoinRecords, JoinStep, OpenedHello,
    PeerCarrier, PeerJoin,
};
pub use lanes::LaneAccept;
pub use mpath::{
    LaneStats, Multipath, PipeDirection, PipeLiveness, PipeOptions, PipeStats, PipeWrite, RttSource,
};
pub use pipes::{DirectionState, InboundState, OutboundState, PipeHalf, PrioritySource};
pub use policy::{FrameInfo, Pick, PickAnswer, PickRequest, PipeSnapshot, Policy};
pub use preamble::Preamble;
pub use quality::{CapacityFloor, QualityBand};
pub use recv_buf::Backing;
pub(crate) use rtt::WRITE_CALL_MIN;
pub use stream::StreamKey;
pub(crate) use transmit::DEFAULT_BATCH;
pub use transmit::{Piece, PieceCursor, TransmitBuf};

use pipes::{Attachment, Attachments, InPipe, InState, OutPipe, OutState};
use streams::Streams;

/// Identifies a pipe attachment. Pipe 0 is the
/// bootstrap pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PipeId(pub(crate) u64);

impl std::fmt::Display for PipeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl PipeId {
    /// The pipe with ID `id` (pipe 0 is the bootstrap pair).
    #[inline]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The ID's value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Lane `lane` of the pipe's directions.
    #[inline]
    pub const fn lane(self, lane: u64) -> LaneId {
        LaneId {
            pipe: self,
            lane: Lane(lane),
        }
    }
}

/// The number of a lane of a pipe direction:
/// lane 0 is the carrier the pipe started on; lanes 1, 2, ... are further
/// streams of the same carrier connection, each a record stream of its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lane(pub(crate) u64);

impl Lane {
    /// Lane 0: the pipe's own carrier.
    pub const ZERO: Self = Self(0);

    /// Lane `n` of a pipe.
    #[inline]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// The lane's number.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A lane of a pipe: what each carrier stream the driver reads or writes
/// is. A pipe without lanes is its lane 0, which a [`PipeId`] converts to,
/// so the driver of a carrier without lanes names pipes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneId {
    /// The pipe.
    pub pipe: PipeId,
    /// The lane of it.
    pub lane: Lane,
}

impl From<PipeId> for LaneId {
    #[inline]
    fn from(pipe: PipeId) -> Self {
        pipe.lane(0)
    }
}

/// The application protocol of the `application_protocols` exchange: the
/// accepting side's most preferred name that both listed (RFC 7301 order,
/// as the `qmux` crate selects it).
fn select_protocol(ours: &[String], theirs: &[Vec<u8>], server: bool) -> Option<Box<str>> {
    let listed = |name: &[u8], list: &[String]| list.iter().any(|o| o.as_bytes() == name);
    if server {
        ours.iter()
            .find(|o| theirs.iter().any(|t| t == o.as_bytes()))
            .map(|o| o.as_str().into())
    } else {
        theirs
            .iter()
            .find(|t| listed(t, ours))
            .and_then(|t| std::str::from_utf8(t).ok())
            .map(Into::into)
    }
}

/// How an inbound pipe ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeEnd {
    /// End of stream (TCP FIN, TLS close_notify, end of a body).
    Eof,
    /// A carrier error or reset, of this kind.
    Error(std::io::ErrorKind),
}

impl PipeEnd {
    /// The pipe failure an unexpected end of this kind is.
    pub(crate) fn failure(self) -> PipeFailure {
        PipeFailure::Carrier(match self {
            Self::Eof => std::io::ErrorKind::UnexpectedEof,
            Self::Error(kind) => kind,
        })
    }
}

/// What the driver does after writing a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transmit {
    /// The batch holds bytes; write them and poll again when writable.
    Data,
    /// Nothing to send now.
    Idle,
    /// Write the batch, then shut down the write side gracefully. Nothing
    /// more will be sent on this pipe.
    Shutdown,
}

/// Session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    /// Own parameters sent, the peer's not processed yet.
    Establishing,
    /// Normal operation.
    Active,
    /// GOAWAY sent or received.
    Draining,
    /// Resume in use and no live pipe in a direction.
    Suspended,
    /// Closing: writes shut down, reading until the peer ends or the linger
    /// timeout.
    Closing,
    /// All done; close the carriers.
    Closed,
}

/// Session statistics: transport bytes and other counts, a snapshot taken under
/// the core lock. `bytes_sent` and
/// `bytes_received` count every byte of the records passed to or received
/// from the carriers (Size fields, frames of every kind, copies and
/// acknowledgements), and nothing a carrier adds. The application bytes
/// are the session's [`Meter`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionStats {
    /// The carrier kind a carrier mode chose, the
    /// latest after a switch; `None` for a session not dialed in a mode.
    pub carrier: Option<CarrierKind>,
    /// The tries of the mode's candidates, in order (the latest 64).
    pub carrier_candidates: Vec<CandidateResult>,
    /// Bytes passed to the carrier.
    pub bytes_sent: u64,
    /// Bytes received from the carrier.
    pub bytes_received: u64,
    /// Records sent.
    pub records_sent: u64,
    /// Records received.
    pub records_received: u64,
    /// Payload bytes the application wrote to the session's streams: the
    /// session [`Meter`]'s counter, not a second count.
    pub bytes_written: u64,
    /// Payload bytes returned to the application from the session's
    /// streams (the [`Meter`]'s).
    pub bytes_read: u64,
    /// Payload bytes of session and stream datagrams handed to a carrier
    /// (the [`Meter`]'s).
    pub datagram_bytes_sent: u64,
    /// Payload bytes of session and stream datagrams returned to the
    /// application (the [`Meter`]'s).
    pub datagram_bytes_received: u64,
    /// Streams opened locally.
    pub streams_opened_local: u64,
    /// Streams opened by the peer.
    pub streams_opened_remote: u64,
    /// Streams currently held.
    pub streams_active: u64,
    /// Datagrams sent.
    pub datagrams_sent: u64,
    /// Datagrams received.
    pub datagrams_received: u64,
    /// Datagrams dropped from the send queue.
    pub datagrams_dropped_send: u64,
    /// Received datagrams dropped from full queues or for closed streams.
    pub datagrams_dropped_recv: u64,
    /// Datagrams dropped by a datagram limiter, sent or received.
    pub datagrams_dropped_limit: u64,
    /// The datagrams of `datagrams_sent` that went on a carrier's datagram
    /// channel rather than in a record.
    pub datagrams_sent_channel: u64,
    /// The datagrams of `datagrams_received` that arrived on a carrier's
    /// datagram channel.
    pub datagrams_received_channel: u64,
    /// Current no-effect budget in tokens.
    pub no_effect_budget: u64,
    /// Smoothed RTT, when sampled: pipe 0's outside multipath (its
    /// acknowledgements, the carrier's estimate, or QX_PING and credit-loop
    /// samples), the primary pipe's in a multipath
    /// session.
    pub smoothed_rtt: Option<Duration>,
    /// Minimum RTT, when sampled (outside multipath, the minimum auto-tuning
    /// uses).
    pub min_rtt: Option<Duration>,
    /// The latest RTT sample.
    pub latest_rtt: Option<Duration>,
    /// RTT variation, when the source measures one.
    pub mean_deviation: Option<Duration>,
    /// Stream bytes sent again after a pipe failed or became suspect, or
    /// opportunistically.
    pub bytes_reinjected: u64,
    /// Stream bytes sent again opportunistically, and the penalties that
    /// came with it.
    pub bytes_opportunistic: u64,
    /// Stream bytes sent as redundant copies.
    pub bytes_redundant: u64,
    /// Pipes penalized for slowing down.
    pub penalties: u64,
    /// Stream bytes received that had been received already (multipath).
    pub bytes_duplicate_received: u64,
    /// Reinjection episodes (a pipe's information reinjected).
    pub reinjections: u64,
    /// Opens that waited for stream credit.
    pub stream_credit_waits: u64,
    /// Written stream bytes not yet sent.
    pub send_buffered: u64,
    /// Received stream bytes not yet read.
    pub recv_buffered: u64,
    /// Sent stream bytes not yet acknowledged (multipath), each counted
    /// once: what the retransmit budget bounds.
    pub retained: u64,
    /// Outbound pipes that are ACTIVE.
    pub pipes_active: u64,
    /// Attachments added (joined either way), the bootstrap pair included.
    pub pipes_added: u64,
    /// Attachments that failed.
    pub pipe_failures: u64,
    /// Hellos that did not verify.
    pub join_auth_failures: u64,
    /// Peer joins held while join pending, per offer.
    pub join_pending: u64,
    /// Frames of a first batch or of return frames dropped in error.
    pub join_batch_dropped: u64,
    /// Own consecutive failed joins, reset by a Proven join.
    pub join_failures: u64,
    /// Joins closed as replays or too late.
    pub join_replays: u64,
    /// Our joins refused by a decision in the Reply, or abandoned with
    /// ZMUX_PIPE_RESOURCE_LIMIT.
    pub join_refusals: u64,
    /// Times the session entered SUSPENDED.
    pub suspensions: u64,
    /// Custom scheduler answers that fell back to `affinity` (stale,
    /// invalid, or a panic).
    pub scheduler_fallbacks: u64,
    /// Custom scheduler answers applied.
    pub scheduler_answers: u64,
    /// 1 when [`EarlyData::hold_first_flight`] was released by the handshake
    /// timeout rather than [`SessionCore::release_first_flight`].
    pub first_flight_timeouts: u64,
    /// Time spent suspended.
    pub suspended_time: Duration,
}

/// Stream statistics, in payload bytes (the preamble
/// excluded): the application bytes as the stream's
/// [`Meter`] counts them, and the transport counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamStats {
    /// Bytes the application wrote (accepted by its write calls).
    pub bytes_written: u64,
    /// Bytes put into STREAM frames, each copy (reinjection, redundancy,
    /// opportunistic) again.
    pub bytes_sent: u64,
    /// Distinct bytes acknowledged: passed to the carrier on a single
    /// pipe, covered by PIPE_ACK in a multipath session.
    pub bytes_acknowledged: u64,
    /// Distinct application bytes received, read or not; never
    /// decreases. None count before a peer stream's preamble, and once
    /// the application stopped reading, every byte below the highest
    /// offset received counts.
    pub bytes_received: u64,
    /// Bytes returned to the application; bytes discarded unread never
    /// count.
    pub bytes_read: u64,
    /// The stream's datagrams handed to a carrier.
    pub datagrams_sent: u64,
    /// The stream's datagrams received (queued for the application).
    pub datagrams_received: u64,
    /// The stream's datagrams dropped from its full queue.
    pub datagrams_dropped_recv: u64,
    /// Payload bytes of the stream's datagrams handed to a carrier.
    pub datagram_bytes_sent: u64,
    /// Payload bytes of the stream's datagrams returned to the
    /// application.
    pub datagram_bytes_received: u64,
    /// Written-but-unreleased bytes (unsent; unacknowledged in multipath).
    pub send_buffered: u64,
    /// Received bytes not yet read.
    pub recv_buffered: u64,
    /// The current (auto-tuned) receive window.
    pub recv_window: u64,
    /// The pipe the sending direction is bound to (`affinity`).
    pub pipe_id: Option<PipeId>,
}

/// QX_PING state.
#[derive(Debug, Default)]
struct PingState {
    /// Next request sequence number.
    next_seq: u64,
    /// Outstanding request: sequence and send time.
    outstanding: Option<(u64, Instant)>,
    /// A request to send (sequence assigned at emission).
    request_pending: bool,
    /// Largest request sequence received.
    peer_request: Option<u64>,
    /// Response to send.
    response_pending: Option<u64>,
    /// Largest response sequence received (NE-8).
    peer_response: Option<u64>,
    /// Largest request sent.
    largest_sent: Option<u64>,
    /// Requests answered with an RTT sample, the latest sample and the
    /// variation of the samples (RFC 6298 smoothing).
    answered: u64,
    latest: Option<Duration>,
    rttvar: Option<Duration>,
    /// The largest ticket a [`SessionCore::ping`] handed out: while it is not
    /// answered, a request that stops being outstanding without its
    /// response is sent again, so that the caller's wait ends.
    wanted: u64,
}

/// GOAWAY state.
#[derive(Debug, Default)]
struct GoAwayState {
    /// Shutdown requested with this application code.
    shutdown: Option<u64>,
    /// The reason phrase of the final CONNECTION_CLOSE.
    reason: Bytes,
    /// GOAWAY frame to send: watermarks and code.
    pending: Option<(u64, u64, u64)>,
    /// Watermarks last sent.
    sent: Option<(u64, u64)>,
    /// Sequence of the fence request; phase 2 follows its response.
    fence: Option<u64>,
    /// The fence request still has to be sent.
    fence_pending: bool,
    /// Phase 2 done (or skipped).
    final_sent: bool,
    /// The fence completed: phase 2 follows at this time, one SRTT later
    /// in a multipath session or with lanes toward this endpoint.
    phase_two_at: Option<Instant>,
    /// GOAWAY lost with a pipe: the current watermarks again.
    resend: Option<(u64, u64)>,
}

/// The GOAWAY state of a session that never had one.
static NO_GOAWAY: GoAwayState = GoAwayState {
    shutdown: None,
    reason: Bytes::new(),
    pending: None,
    sent: None,
    fence: None,
    fence_pending: false,
    final_sent: false,
    phase_two_at: None,
    resend: None,
};

impl SessionCore {
    fn goaway(&self) -> &GoAwayState {
        self.goaway.as_deref().unwrap_or(&NO_GOAWAY)
    }

    fn goaway_mut(&mut self) -> &mut GoAwayState {
        self.goaway.get_or_insert_with(Box::default)
    }

    /// A GOAWAY was sent or is about to be.
    fn goaway_announced(&self) -> bool {
        let g = self.goaway();
        g.sent.is_some() || g.pending.is_some()
    }
}

/// Datagram state.
#[derive(Debug, Default)]
pub(super) struct DatagramState {
    /// Outgoing datagrams: flow prefix (stream ID and context) and payload.
    send: VecDeque<(Option<(u64, u64)>, Bytes)>,
    /// Datagrams sent before establishment: the stream
    /// (`None` for the session) and context, and the payload. Sent, or
    /// dropped and counted, once the peer's parameters arrive.
    early: VecDeque<(Option<(StreamKey, u64)>, Bytes)>,
    /// Received session datagrams.
    recv: VecDeque<Bytes>,
    /// Bytes held in the session queue and, with an entry cost each, for
    /// streams not opened yet (`waiting`): what
    /// [`Config::datagram_receive_bytes`] bounds.
    recv_bytes: usize,
    /// Bytes held in every stream's queue together, each bounded by its own
    /// limits: for the memory accounting only.
    stream_bytes: usize,
    /// Received datagrams held for the receive limiter, which the driver
    /// asks outside the lock.
    held: VecDeque<ReceivedDatagram>,
    /// Bytes of the datagrams waiting for the limiter: `held`, and those
    /// the driver took and has not handed back yet. With `recv_bytes` they
    /// stay within the session's datagram bytes.
    held_bytes: usize,
    /// Received datagrams of peer streams within the limit that have not
    /// been opened yet, in arrival order, until the stream opens or their deadline. Their bytes,
    /// with an entry cost each, are in `recv_bytes`.
    waiting: VecDeque<WaitingDatagram>,
    /// [`SessionCore::channel_generation`].
    channel_gen: u64,
}

/// A received datagram held for a peer stream not opened yet.
#[derive(Debug)]
struct WaitingDatagram {
    stream_id: u64,
    context: u64,
    data: Bytes,
    /// Dropped at this time: one smoothed RTT after its arrival, or the
    /// deadline of the one held before it when that is later.
    until: Instant,
    /// It arrived on a carrier's datagram channel.
    channel: bool,
}

/// What a datagram held for a stream not opened yet counts in the
/// session's datagram bytes besides its payload: its entry, so that the
/// byte limit bounds the number of tiny ones too.
const WAITING_COST: usize = 64;

/// How long an application close waits for the carriers to take
/// CONNECTION_CLOSE before the session ends locally.
pub(crate) const CLOSE_HANDOFF_LIMIT: Duration = Duration::from_secs(1);

impl WaitingDatagram {
    fn cost(&self) -> usize {
        self.data.len() + WAITING_COST
    }
}

impl DatagramState {
    /// Heap bytes held: the state, its queues and the datagrams queued.
    fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + self.send.capacity() * size_of::<(Option<(u64, u64)>, Bytes)>()
            + self.early.capacity() * size_of::<(Option<(StreamKey, u64)>, Bytes)>()
            + self.recv.capacity() * size_of::<Bytes>()
            + self.held.capacity() * size_of::<ReceivedDatagram>()
            + self.waiting.capacity() * size_of::<WaitingDatagram>()
            + self.send.iter().map(|(_, b)| b.len()).sum::<usize>()
            + self.early.iter().map(|(_, b)| b.len()).sum::<usize>()
            + self.recv_bytes
            + self.stream_bytes
            + self.held_bytes
    }
}

/// The datagram state of a session that never had one.
static NO_DGRAM: DatagramState = DatagramState {
    send: VecDeque::new(),
    early: VecDeque::new(),
    recv: VecDeque::new(),
    recv_bytes: 0,
    stream_bytes: 0,
    held: VecDeque::new(),
    held_bytes: 0,
    waiting: VecDeque::new(),
    channel_gen: 0,
};

impl SessionCore {
    fn dgram(&self) -> &DatagramState {
        self.dgram.as_deref().unwrap_or(&NO_DGRAM)
    }

    fn dgram_mut(&mut self) -> &mut DatagramState {
        self.dgram.get_or_insert_with(Box::default)
    }
}

/// A received datagram held for the receive limiter
/// ([`Config::datagram_limiter`]): the core never calls a limiter, which is
/// application code. The driver takes the held
/// datagrams with [`SessionCore::take_received_datagrams`] after the input
/// that carried them, asks the limiter for each outside the lock, records
/// its verdict with [`ReceivedDatagram::set_allowed`], and gives them back
/// with [`SessionCore::admit_datagrams`].
#[derive(Debug)]
pub struct ReceivedDatagram {
    /// The stream and context, `None` for the session.
    stream: Option<(StreamKey, u64)>,
    data: Bytes,
    allowed: bool,
}

impl ReceivedDatagram {
    /// The payload bytes, what the limiter is asked for.
    pub fn payload_len(&self) -> usize {
        self.data.len()
    }

    /// Records the limiter's verdict; a datagram not allowed (the
    /// default) is dropped and counted (`datagrams_dropped_limit`).
    pub fn set_allowed(&mut self, allowed: bool) {
        self.allowed = allowed;
    }
}

/// The no-effect budget, in thousandths of a token.
#[derive(Debug)]
struct NoEffectBudget {
    milli: i64,
    last: Option<Instant>,
}

const BUDGET_CAPACITY: i64 = 4096 * 1000;
/// 32 tokens per second is 32 thousandths per millisecond.
const BUDGET_REFILL_PER_MS: i64 = 32;

impl NoEffectBudget {
    fn new() -> Self {
        Self {
            milli: BUDGET_CAPACITY,
            last: None,
        }
    }

    fn refill(&mut self, now: Instant) {
        if let Some(last) = self.last {
            let ms = now.saturating_duration_since(last).as_millis();
            let ms = i64::try_from(ms).unwrap_or(i64::MAX / BUDGET_REFILL_PER_MS);
            if ms > 0 {
                self.milli = (self.milli + ms * BUDGET_REFILL_PER_MS).min(BUDGET_CAPACITY);
                self.last = Some(last + Duration::from_millis(ms as u64));
            }
        } else {
            self.last = Some(now);
        }
    }

    /// Charges one frame; `false` when the budget is exhausted.
    pub(super) fn charge(&mut self) -> bool {
        self.milli -= 1000;
        self.milli >= 0
    }

    fn tokens(&self) -> u64 {
        (self.milli.max(0) / 1000) as u64
    }
}

/// The streams whose received data references the driver's read buffers,
/// and the buffer each inbound lane reads into.
#[derive(Debug, Default)]
struct RecvRefs {
    /// The read buffer each lane received its last bytes in, and its size:
    /// the driver still reads into it, so it is alive anyway. A lane's
    /// buffers before its current one are retired: the driver never reads
    /// into them again.
    current: Vec<(LaneId, Backing)>,
    /// The streams whose received data references read buffers.
    holders: Vec<StreamKey>,
    /// Scratch of the bound: each buffer referenced, its size and the
    /// bytes referenced in it.
    tally: Vec<(u64, usize, usize)>,
    /// Since the bound was last checked: at most this many bytes of
    /// retired buffers are referenced (each retirement adds its buffer),
    /// and at least this many bytes are referenced in all (each byte that
    /// arrives referenced adds one, each consumed or dropped takes one off,
    /// referenced or not). The bound is checked again only once these
    /// could break it.
    retired_at_most: usize,
    referenced_at_least: usize,
}

impl RecvRefs {
    /// `n` more bytes of received data reference read buffers.
    fn referenced(&mut self, n: usize) {
        self.referenced_at_least = self.referenced_at_least.saturating_add(n);
    }

    /// `n` bytes of received data were consumed or dropped; whether the
    /// bound may be broken now (it is checked again).
    fn consumed(&mut self, n: u64) -> bool {
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        self.referenced_at_least = self.referenced_at_least.saturating_sub(n);
        self.retired_at_most > 2 * self.referenced_at_least
    }
}

/// What a close must still put on the wire.
#[derive(Debug, Clone)]
enum CloseFrame {
    /// CONNECTION_CLOSE type 0x1c.
    Transport {
        code: u64,
        frame_type: u64,
        reason: Bytes,
    },
    /// CONNECTION_CLOSE type 0x1d.
    Application { code: u64, reason: Bytes },
}

/// The sans-IO state machine of one session.
///
/// The session never performs I/O and never reads a clock: the driver
/// feeds it the bytes each pipe delivers ([`SessionCore::receive`]), asks it
/// for the bytes to write when a pipe can take them
/// ([`SessionCore::poll_transmit`], which is where the scheduler decides),
/// fires its timers ([`SessionCore::poll_timeout`], [`SessionCore::handle_timeout`])
/// and drains its events ([`SessionCore::poll_event`]). The drivers of this
/// crate do that for tokio and for threads; other runtimes and language
/// bindings drive it the same way.
///
/// # Example
///
/// Two endpoints over one in-memory pipe, driven by hand:
///
/// ```
/// use std::time::Instant;
/// use zmux::proto::frame::Dir;
/// use zmux::proto::record::Framing;
/// use zmux::proto::session::{Config, PipeId, Role, SessionCore, TransmitBuf};
///
/// /// Moves what `from` has to write on pipe 0 to `to`.
/// fn pump(from: &mut SessionCore, to: &mut SessionCore, buf: &mut TransmitBuf, now: Instant) {
///     while from.wants_write(PipeId::new(0)) {
///         from.poll_transmit(PipeId::new(0), now, buf);
///         let mut bytes = Vec::new();
///         buf.copy_to_vec(&mut bytes);
///         if bytes.is_empty() {
///             break;
///         }
///         to.receive(PipeId::new(0), &bytes, now);
///     }
/// }
///
/// let now = Instant::now();
/// let mut client = SessionCore::new(Config::default(), Role::Client, None, now)?;
/// let mut server = SessionCore::new(Config::default(), Role::Server, None, now)?;
/// client.attach_pipe(PipeId::new(0), Framing::ByteStream, now);
/// server.attach_pipe(PipeId::new(0), Framing::ByteStream, now);
///
/// // Streams may be opened and written before establishment: the data
/// // goes out with the handshake.
/// let stream = client.open(Dir::Bidi)?;
/// client.write(stream, b"hello")?;
/// client.finish(stream)?;
///
/// let mut buf = TransmitBuf::default();
/// for _ in 0..4 {
///     pump(&mut client, &mut server, &mut buf, now);
///     pump(&mut server, &mut client, &mut buf, now);
/// }
/// let peer = server.accept(Dir::Bidi)?.expect("the client's stream");
/// let mut data = [0u8; 16];
/// let (n, fin) = server.read(peer, &mut data)?.expect("data");
/// assert_eq!(&data[..n], b"hello");
/// assert!(fin);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct SessionCore {
    /// Shared by the sessions of a listener; `set_scheduler` copies it.
    config: Arc<Config>,
    /// The transport role of pipe 0 (`None` on a symmetric carrier).
    transport_role: Option<Role>,
    /// The local role: the transport role (or a placeholder) until
    /// establishment, then the negotiated one.
    role: Role,
    state: State,
    /// The values of the transport parameters this endpoint sends, which
    /// [`SessionCore::local_parameters`] builds again from the configuration.
    /// The session's own part of the local transport parameters, the rest
    /// being the shared configuration's ([`SessionCore::local_tp`]).
    local: tp::LocalTp,
    grease: (u64, Vec<u8>),
    /// The values of the peer's transport parameters, once processed.
    peer_tp: Option<tp::TpValues>,
    /// Early data under the zmux floor, until the peer's parameters are
    /// processed.
    early: Option<Box<early::EarlyState>>,
    features: Features,
    /// Attachments in pipe ID order: pipe 0 alone outside multipath.
    atts: Attachments,
    /// Multipath state, once multipath is in use.
    mp: Option<Box<mpath::Mp>>,
    /// Pipe acknowledgement state, while it is in use.
    pipe_ack: Option<pipe_ack::PipeAckState>,
    /// The inbound pipe whose records are being processed.
    rx: u64,
    /// The index of the lane of `rx` whose records are being processed
    /// (0: lane 0).
    rx_lane: usize,
    /// The datagram being processed arrived on a carrier's datagram
    /// channel.
    rx_channel: bool,
    /// The read buffer the bytes being processed came in, when the driver
    /// handed it over ([`SessionCore::receive_shared`]), and the streams whose
    /// received data references read buffers.
    rx_src: Option<(Bytes, Backing)>,
    recv_refs: RecvRefs,
    /// The outbound pipe whose batch is being built.
    tx: u64,
    /// The lane of `tx` the batch is for, and whether `tx` has lanes.
    tx_lane: u64,
    tx_lanes: bool,
    /// New stream bytes in the current batch.
    batch_stream_bytes: u64,
    /// The last input or output of latency-sensitive frames, anything but
    /// acknowledgements and credit.
    exchange_at: Option<Instant>,
    /// While a batch takes stream data: the bytes of stream data,
    /// reinjection and copies the carrier queue limiter still lets it take;
    /// `None` when the pipe is not paced.
    pace_left: Option<u64>,

    /// Present once the host announced an exporter on the bootstrap carrier:
    /// its value, passed by the host, which goes when the peer's parameters
    /// are processed, or at the close.
    exporter: Option<Box<Option<Vec<u8>>>>,
    /// The record mode of a first pipe on the secure carrier; `None` is Unmanaged.
    first_pipe_mode: Option<crate::proto::seal::RecordMode>,
    /// The host declared pipe 0 end to end.
    declared: bool,
    /// The length of the instance identifier at the start of the local Locators.
    locator_instance: usize,
    ping: PingState,
    /// Boxed with the first GOAWAY step: a session that never shuts down
    /// gracefully holds none.
    goaway: Option<Box<GoAwayState>>,
    /// Boxed with the first datagram: a session without any holds none.
    dgram: Option<Box<DatagramState>>,
    /// Quality bands and the capacity floor, boxed
    /// once the application sets one: a session without holds none.
    quality: Option<Box<quality::Quality>>,
    budget: NoEffectBudget,
    events: VecDeque<CoreEvent>,
    /// Boxed: an open session has neither.
    error: Option<Box<SessionError>>,
    close: Option<Box<CloseFrame>>,
    /// Whether the GREASE TLV was used in a preamble already.
    grease_tlv_used: bool,
    srtt: Option<Duration>,
    /// The carrier's RTT estimate, from the driver.
    carrier_rtt: Option<Duration>,
    /// The credit-loop minimum RTT over 300 s, QX_PING samples included.
    loop_min: filter::MinFilter,
    /// Memory the session's carriers hold for it, charged by their
    /// adapters without a listener (a QUIC connection's receive window).
    carrier_memory: u64,
    /// What a listener's memory budget has left for the session to grow
    /// by, and what the session held when it said so
    /// ([`SessionCore::set_memory_allowance`]); `None`: the session's own
    /// `memory_budget` applies.
    memory_allowance: Option<(Option<u64>, u64)>,
    /// `allow_connection_window_increase` proposals.
    window_increase: credit::IncreaseState,
    /// The rate bytes are handed to the carrier (single pipe).
    send_rate: filter::IntervalRate,
    /// The limit of probe requests (at most
    /// 16 QX_PING requests and PIPE_PING frames in any one second).
    requests: pipes::TokenBucket<16>,
    /// When auto-tuning last asked for a QX_PING sample.
    last_rtt_probe: Option<Instant>,
    /// The latest time an input carried; commands without a clock (stream
    /// operations) act at this time.
    now: Instant,
    handshake_deadline: Option<Instant>,
    /// Pipe 0 writes nothing yet ([`EarlyData::hold_first_flight`]) until
    /// the release or this time; `Some(None)`: no timeout. Boxed: rarely
    /// used, and every session holds the field.
    first_held: Option<Box<Option<Instant>>>,
    idle_deadline: Option<Instant>,
    keep_alive_deadline: Option<Instant>,
    /// The last activity (`restart_idle`), which the keep-alive wait counts
    /// from.
    last_activity: Instant,
    /// A keep-alive was sent for that activity: at most one is.
    keep_alive_sent: bool,
    /// The generator of the keep-alive waits' draws.
    keep_alive_rng: u64,
    linger_deadline: Option<Instant>,
    /// When an application close stops waiting for the carriers to take
    /// CONNECTION_CLOSE ([`SessionCore::close_handed_off`]).
    handoff_deadline: Option<Instant>,
    /// The hand-off limit passed: a close no longer waits for the
    /// carriers ([`SessionCore::close_returned`]).
    handoff_expired: bool,
    /// A graceful close sends what the streams wrote before its
    /// CONNECTION_CLOSE: its code and reason while it does.
    close_flush: Option<Box<(VarInt, Bytes)>>,
    /// An abort was called: a close returns at once.
    close_aborted: bool,
    stats: SessionStats,
    /// The linger deadline was extended once because the close was not
    /// written yet.
    linger_extended: bool,
    /// The peer's CONNECTION_CLOSE was processed: what arrived before it
    /// stays readable while the session is closing.
    peer_close_processed: bool,
    /// After the peer's close: the streams the application holds (opened or
    /// accepted) whose received data is not read yet; CLOSED waits for 0 or
    /// the linger deadline.
    peer_close_unread: usize,
    /// The linger was restarted when the carriers took CONNECTION_CLOSE.
    pub(in crate::proto::session) linger_from_delivery: bool,
    /// The application byte counters.
    meter: Arc<Meter>,
    /// The stream layer: the streams, their flow control and scheduling
    /// queues (`streams/`).
    streams: Streams,
    /// Shaping, once a shaper is set (`shape.rs`).
    shape: Option<Box<shape::Shaping>>,
    /// Stream events for the shapers while a batch holds their state.
    shape_pending: Option<Vec<(shaping::EventKind, u64)>>,
    /// What Joins counted of their handshake plans.
    join_shaping: JoinShaping,
    /// Time 0 of the session clock shapers see.
    started: Instant,
    /// The shaping configuration's budget of this session.
    shape_budget: shaping::Budget,
    /// The bytes this endpoint sent of its own: no padding, injections or copies.
    earn_bytes: u64,
    /// Bytes earned on a discarded first flight, not earned twice.
    earn_skip: u64,
    /// Padding, injections and copies of the batch just closed.
    batch_not_earned: u64,
}

const BIDI: usize = 0;
const UNI: usize = 1;

const fn di(dir: Dir) -> usize {
    match dir {
        Dir::Bidi => BIDI,
        Dir::Uni => UNI,
    }
}

const fn dir_of_index(i: usize) -> Dir {
    if i == BIDI { Dir::Bidi } else { Dir::Uni }
}

use crate::util::random_u64;

/// A Lane Key chosen uniformly at random.
fn random_key() -> [u8; 16] {
    let mut k = [0u8; 16];
    if getrandom::fill(&mut k).is_err() {
        k[..8].copy_from_slice(&random_u64().to_le_bytes());
        k[8..].copy_from_slice(&random_u64().to_le_bytes());
    }
    k
}

impl SessionCore {
    /// A session before any pipe is attached. `role` is the session-creation
    /// role: [`Role::Client`] and
    /// [`Role::Server`] are transport roles; [`Role::Auto`]
    /// sends `zmux_role` auto. `transport_role` is who dialled pipe 0 when
    /// the carrier tells (it overrides the transport role implied by
    /// `role`); a symmetric carrier passes `None`, and the roles are then
    /// resolved from `zmux_role` alone.
    pub fn new(
        config: impl Into<Arc<Config>>,
        role: Role,
        transport_role: Option<Role>,
        now: Instant,
    ) -> Result<Self, crate::InvalidConfig> {
        let config: Arc<Config> = config.into();
        let keep_alive_rng = config
            .hooks
            .probe_seed
            .map_or_else(random_u64, |s| s ^ 0x6b65_6570_616c_6976);
        config.validate()?;
        let role_nonce =
            (role == Role::Auto).then(|| config.hooks.role_nonce.unwrap_or_else(random_u64));
        let session_nonce = config.hooks.session_nonce.unwrap_or_else(|| {
            let mut n = [0u8; 16];
            n[..8].copy_from_slice(&random_u64().to_le_bytes());
            n[8..].copy_from_slice(&random_u64().to_le_bytes());
            n
        });
        let lane_key = config.hooks.lane_key.unwrap_or_else(random_key);
        let local_tp = config.transport_parameters(role_nonce, session_nonce, lane_key);
        local_tp.validate().map_err(|_| {
            crate::InvalidConfig::new("Config", "gives transport parameters that are not valid")
        })?;
        let local = tp::LocalTp::of(&local_tp);
        let grease = config.grease_parameter(random_u64());
        let transport_role = transport_role.or(match role {
            Role::Client => Some(Role::Client),
            Role::Server => Some(Role::Server),
            Role::Auto => None,
        });
        let window = local_tp.initial_max_data.unwrap_or(0);
        let stream_limits = [
            local_tp.initial_max_streams_bidi.unwrap_or(0),
            local_tp.initial_max_streams_uni.unwrap_or(0),
        ];
        // Unidirectional credit grows on the first accept unless the
        // application configured it (or the test parameters set more).
        let staged_uni = config.max_incoming_uni_streams == config::UniCredit::Staged
            && stream_limits[UNI] < config::STAGED_UNI_STREAMS.1;
        let streams = Streams::new(config.send_buffer, stream_limits, staged_uni, window);
        let ping_start = config.hooks.ping_seq_start.unwrap_or(0);
        let srtt = config.hooks.rtt;
        let hold = config.early_data.hold_first_flight;
        if hold
            && (role != Role::Client
                || !config.early_data.zmux_peer && !config.early_data.carrier_early_data)
        {
            return Err(crate::InvalidConfig::new(
                "early_data",
                "hold_first_flight without client early data",
            ));
        }
        let start_timeout = now.checked_add(config.handshake_wait());
        let mut session = Self {
            early: None,
            // With the first flight held it runs from the release.
            handshake_deadline: start_timeout.filter(|_| !hold),
            first_held: hold.then(|| Box::new(start_timeout)),
            config,
            transport_role,
            role: transport_role.unwrap_or(Role::Client),
            state: State::Establishing,
            local,
            grease,
            peer_tp: None,
            features: Features::default(),
            atts: Attachments::default(),
            mp: None,
            pipe_ack: None,
            rx: 0,
            rx_lane: 0,
            rx_channel: false,
            rx_src: None,
            recv_refs: RecvRefs::default(),
            tx: 0,
            tx_lane: 0,
            tx_lanes: false,
            batch_stream_bytes: 0,
            exchange_at: None,
            pace_left: None,

            exporter: None,
            first_pipe_mode: None,
            declared: false,
            locator_instance: 0,
            ping: PingState {
                next_seq: ping_start,
                ..PingState::default()
            },
            goaway: None,
            dgram: None,
            quality: None,
            budget: NoEffectBudget::new(),
            events: VecDeque::new(),
            error: None,
            close: None,
            grease_tlv_used: false,
            srtt,
            carrier_rtt: None,
            loop_min: filter::MinFilter::default(),
            memory_allowance: None,
            carrier_memory: 0,
            window_increase: credit::IncreaseState::default(),
            send_rate: filter::IntervalRate::default(),
            requests: pipes::TokenBucket::default(),
            last_rtt_probe: None,
            now,
            idle_deadline: None,
            keep_alive_deadline: None,
            last_activity: now,
            keep_alive_sent: false,
            keep_alive_rng,
            linger_deadline: None,
            handoff_deadline: None,
            handoff_expired: false,
            close_flush: None,
            close_aborted: false,
            stats: SessionStats::default(),
            linger_extended: false,
            peer_close_processed: false,
            peer_close_unread: 0,
            linger_from_delivery: false,
            meter: Arc::new(Meter::new()),
            streams,
            shape: None,
            shape_pending: None,
            join_shaping: JoinShaping::default(),
            started: now,
            shape_budget: shaping::Budget::default(),
            earn_bytes: 0,
            earn_skip: 0,
            batch_not_earned: 0,
        };
        session.early_setup(transport_role);
        if let Some(b) = &session.config.shaping_budget {
            session.shape_budget = b.ask();
        }
        if let Some(f) = session.config.shaper.clone() {
            session.install_shaper(Some(f));
        }
        Ok(session)
    }

    /// Moves the session clock forward (inputs may carry the same time).
    /// A driver also calls it before a statistics snapshot, so that the
    /// durations since an event are current.
    pub(crate) fn tick(&mut self, now: Instant) {
        if now > self.now {
            self.now = now;
        }
    }

    /// The session state.
    pub fn state(&self) -> State {
        self.state
    }

    /// The local role: the transport role until establishment, then the
    /// negotiated one.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The features in use (empty before establishment).
    pub fn features(&self) -> Features {
        self.features
    }

    /// The local transport parameter values in use: the shared
    /// configuration's, with the session's own.
    fn local_tp(&self) -> tp::TpValues {
        tp::TpValues::local(&self.config, &self.local)
    }

    /// The transport parameters this endpoint sends (or sent), built from
    /// the configuration and the session's nonces, Lane Key and locator.
    pub fn local_parameters(&self) -> TransportParameters {
        let l = &self.local;
        let nonce = l
            .multipath
            .as_ref()
            .map(|m| m.session_nonce)
            .unwrap_or_default();
        let mut tp = self
            .config
            .transport_parameters(l.role_nonce, nonce, l.lane_key);
        tp.zmux_multipath.clone_from(&l.multipath);
        tp.zmux_carrier_datagrams |= l.carrier_datagrams && tp.max_datagram_frame_size.is_some();
        tp
    }

    /// The `zmux_role` nonces, this endpoint's
    /// first, when both endpoints sent `auto`.
    pub fn role_nonces(&self) -> Option<(u64, u64)> {
        Some((
            self.local_tp().role_nonce?,
            self.peer_tp.as_ref()?.role_nonce?,
        ))
    }

    /// Whether the peer is a plain QMux peer.
    pub fn is_plain_qmux_peer(&self) -> bool {
        self.peer_tp.as_ref().is_some_and(|t| t.plain_qmux)
    }

    /// DATAGRAM support: (announced locally, announced by the peer), the
    /// peer's once its parameters were processed.
    pub fn datagram_support(&self) -> (bool, bool) {
        let peer = self
            .peer_tp
            .as_ref()
            .is_some_and(|t| t.max_datagram_frame_size() > 0);
        (self.config.enable_datagrams, peer)
    }

    /// RESET_STREAM_AT support: (local, the peer's once its parameters
    /// were processed).
    pub fn reset_stream_at_support(&self) -> (bool, bool) {
        (
            self.local_tp().reset_stream_at,
            self.peer_accepts_reset_stream_at(),
        )
    }

    /// Whether the peer accepts RESET_STREAM_AT (its `reset_stream_at`
    /// transport parameter), once its parameters were processed.
    pub fn peer_accepts_reset_stream_at(&self) -> bool {
        self.peer_tp.as_ref().is_some_and(|t| t.reset_stream_at)
    }

    /// The session's configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The error that ended the session, once it is closing.
    pub fn error(&self) -> Option<&SessionError> {
        self.error.as_deref()
    }

    /// Whether the session is established and not closing (SUSPENDED
    /// included).
    pub fn is_established(&self) -> bool {
        matches!(
            self.state,
            State::Active | State::Draining | State::Suspended
        )
    }

    /// The smoothed RTT, when sampled (QX_PING) or configured.
    pub fn rtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// The variation of the QX_PING samples.
    pub(super) fn ping_rttvar(&self) -> Option<Duration> {
        self.ping.rttvar
    }

    /// The latest QX_PING sample.
    pub(super) fn ping_latest(&self) -> Option<Duration> {
        self.ping.latest
    }

    /// The initial smoothed RTT of a pipe: a test hook, or 333 ms.
    fn initial_rtt(&self, pipe: u64) -> Duration {
        let h = &self.config.hooks;
        h.pipe_rtt
            .iter()
            .find(|(p, _)| *p == pipe)
            .map(|(_, d)| *d)
            .or(h.rtt)
            .unwrap_or(pipes::INITIAL_RTT)
    }

    /// Sets or clears memory pressure, as a listener's memory budget
    /// decides. Under
    /// pressure new peer streams are rejected with ZMUX_REJECTED without
    /// receive buffers (MAX_STREAMS keeps flowing as they are discarded),
    /// session credit is released only as data is consumed, and windows
    /// stop growing.
    pub fn set_memory_pressure(&mut self, on: bool) {
        if !self.streams.set_memory_pressure(on) {
            return;
        }
        if !on {
            // Held bytes are released at once below the cap.
            self.credit_consumed(0);
        }
    }

    /// Whether memory pressure is set.
    pub fn memory_pressure(&self) -> bool {
        self.streams.memory_pressure()
    }

    /// A snapshot of a stream's statistics; `None` once
    /// the core no longer holds the stream.
    pub fn stream_stats(&self, key: StreamKey) -> Option<StreamStats> {
        let s = self.streams.get(key)?;
        let mp = self.retains();
        let d = s.datagram_counts();
        let mut st = StreamStats {
            datagrams_sent: d.sent,
            datagrams_received: d.received,
            datagrams_dropped_recv: d.dropped_recv,
            datagram_bytes_sent: d.bytes_sent,
            datagram_bytes_received: d.bytes_received,
            ..StreamStats::default()
        };
        if let Some(send) = &s.send {
            let first = send.offset.saturating_sub(send.base);
            st.bytes_written = send.written;
            st.bytes_sent = first + send.mp().resent;
            st.bytes_acknowledged = if mp {
                let m = send.mp();
                let floor = m.buf_floor.max(send.base);
                floor - send.base + m.acked.covered(floor, u64::MAX)
            } else {
                first
            };
            st.send_buffered = send.held(mp);
            st.pipe_id = send.mp().bound.map(|b| PipeId(b.pipe));
        }
        if let Some(r) = &s.recv {
            // Application bytes: none before a peer stream's preamble.
            st.bytes_received = match r.preamble_size {
                Some(base) => r.arrived_from(base),
                None if self.features.preamble && !s.local => 0,
                None => r.arrived_from(0),
            };
            st.bytes_read = r.app_read;
            st.recv_buffered = r.buf.len() as u64;
            st.recv_window = r.window;
        }
        Some(st)
    }

    /// The session's application byte counters: a
    /// handle any thread may read without the session.
    pub fn meter(&self) -> &Arc<Meter> {
        &self.meter
    }

    /// The application byte counters of a stream,
    /// created on the first call; `None` once the core no longer holds the
    /// stream. The meter counts from the stream's start whenever it is
    /// first asked for, and keeps counting until the stream is discarded.
    pub fn stream_meter(&mut self, key: StreamKey) -> Option<Arc<Meter>> {
        let s = self.streams.get_mut(key)?;
        let m = s.meter.get_or_insert_with(|| {
            let m = Meter::new();
            let written = s.send.as_ref().map_or(0, |x| x.written);
            let read = s.recv.as_ref().map_or(0, |r| r.app_read);
            let d = s.datagrams.as_ref().map(|d| d.counts).unwrap_or_default();
            m.add(Count::Written, written);
            m.add(Count::Read, read);
            m.add(Count::DatagramSent, d.bytes_sent);
            m.add(Count::DatagramReceived, d.bytes_received);
            Arc::new(m)
        });
        Some(m.clone())
    }

    /// The slot that receives a stream's statistics as they are when the
    /// stream is discarded, created on the first call; `None` once the core
    /// no longer holds the stream. A handle that outlives the stream reads
    /// its final statistics there.
    pub fn stream_final_stats(
        &mut self,
        key: StreamKey,
    ) -> Option<Arc<std::sync::OnceLock<StreamStats>>> {
        let s = self.streams.get_mut(key)?;
        Some(s.final_stats.get_or_insert_with(Default::default).clone())
    }

    /// Heap bytes of received stream data held for the application, with
    /// the bookkeeping of out-of-order data.
    #[doc(hidden)]
    pub fn received_data_memory(&self) -> usize {
        self.streams
            .keys()
            .filter_map(|k| self.streams.get(k)?.recv.as_ref())
            .map(stream::RecvPart::memory)
            .sum()
    }

    // ---- pipes ---------------------------------------------------------

    /// Attaches the bootstrap carrier (pipe 0, both directions). Its
    /// outbound side starts with QX_TRANSPORT_PARAMETERS on the first
    /// `poll_transmit`.
    pub fn attach_pipe(&mut self, pipe: PipeId, framing: Framing, now: Instant) {
        if pipe != PipeId(0) {
            return;
        }
        self.attach_bootstrap(Some(framing), Some(framing), now);
    }

    /// Attaches the halves of the bootstrap pair that a carrier provides:
    /// both for a bidirectional carrier, one at a time for a split
    /// bootstrap whose two carriers a pairing token joined.
    pub fn attach_bootstrap(
        &mut self,
        inbound: Option<Framing>,
        outbound: Option<Framing>,
        now: Instant,
    ) {
        self.tick(now);
        let max = self.local_tp().max_record_size();
        let rtt = self.initial_rtt(0);
        let detection = self.detection(0, None);
        if self.atts.first().is_none_or(|a| a.id() != 0) {
            let joiner = self.transport_role != Some(Role::Server);
            // Room for this one alone: a single-pipe session has no other.
            self.atts.insert(Attachment::bootstrap(joiner));
            self.views_changed();
            self.stats.pipes_added += 1;
        }
        let mp = self.per_pipe();
        let a = self.atts.at_mut(0);
        if let Some(framing) = inbound {
            a.attach_inp(|| {
                InPipe::new(framing, max, InState::Open, now)
                    .with_classifier(Classifier::bootstrap(max))
            });
        }
        if let Some(framing) = outbound {
            a.attach_out(|| {
                let o = OutPipe::new(framing, OutState::Active, rtt, now);
                let o = if mp { o.with_mp(detection, now) } else { o };
                o.with_parameters_first()
            });
        }
    }

    /// Index of an attachment.
    #[inline]
    pub(crate) fn att_index(&self, id: u64) -> Option<usize> {
        self.atts.index_of(id)
    }

    #[inline]
    pub(crate) fn att(&self, id: u64) -> Option<&Attachment> {
        self.atts.get(id)
    }

    #[inline]
    pub(crate) fn att_mut(&mut self, id: u64) -> Option<&mut Attachment> {
        self.atts.get_mut(id)
    }

    #[inline]
    pub(crate) fn inp_mut(&mut self, id: u64) -> Option<&mut InPipe> {
        self.att_mut(id).and_then(Attachment::inp_mut)
    }

    #[inline]
    pub(crate) fn out_mut(&mut self, id: u64) -> Option<&mut OutPipe> {
        self.att_mut(id).and_then(Attachment::out_mut)
    }

    #[inline]
    pub(crate) fn out_ref(&self, id: u64) -> Option<&OutPipe> {
        self.att(id).and_then(Attachment::out)
    }

    /// The inbound side of a pipe ended, or of one of its lanes. Complete
    /// records already received were processed; an end inside a record is
    /// a pipe failure. A pipe with lanes ends gracefully once every lane
    /// did at a record boundary; a lane that ends before its second record is no event of it.
    pub fn pipe_ended(&mut self, at: impl Into<LaneId>, end: PipeEnd, now: Instant) {
        let at = at.into();
        self.tick(now);
        self.pick_input();
        let pipe = at.pipe.0;
        let Some(p) = self.inp_mut(pipe) else {
            return;
        };
        if p.state() == InState::Ended {
            return;
        }
        let Some(li) = p.lane_index(at.lane.0) else {
            return;
        };
        if li > 0 {
            self.inbound_lane_ended(pipe, li, end, now);
        } else {
            let clean = end == PipeEnd::Eof && p.at_clean_end();
            if clean && p.lane_count() > 1 && !p.zero_ended_cleanly() {
                // The other lanes are still open: the pipe ends with them.
                return;
            }
            self.inbound_ended(pipe, end, clean, now);
        }
        self.recv_lane_gone(pipe);
    }

    /// The single pipe's inbound side ended ([`Self::inbound_ended`]).
    pub(super) fn single_inbound_ended(
        &mut self,
        pipe: u64,
        end: PipeEnd,
        clean: bool,
        now: Instant,
    ) {
        let Some(p) = self.inp_mut(pipe) else {
            return;
        };
        if p.state() == InState::Ended {
            return;
        }
        p.end();
        match self.state {
            State::Closed => {}
            State::Closing => {
                if matches!(end, PipeEnd::Error(_))
                    && let Some(o) = self.out_mut(pipe)
                {
                    o.carrier_closed();
                    self.views_changed();
                }
                self.maybe_closed(now);
            }
            _ if clean && self.state != State::Establishing && !self.acknowledged() => {
                // The peer's idle close; with
                // acknowledgement a graceful end without CONNECTION_CLOSE is
                // a carrier failure, below.
                self.set_error(SessionError::IdleTimeout { remote: true });
                self.enter_closing(None, now);
                self.maybe_closed(now);
            }
            _ => {
                // A carrier failure, or an end inside a record: close without frames.
                self.set_error(SessionError::PipesLost {
                    last: Some(end.failure()),
                });
                self.closed_now();
            }
        }
    }

    /// A write to the pipe failed with an error of `kind`, or to one of
    /// its lanes: the carrier is gone. A lane that is not confirmed is
    /// refused instead, and its pipe goes on.
    pub fn write_failed(&mut self, at: impl Into<LaneId>, kind: std::io::ErrorKind, now: Instant) {
        let at = at.into();
        self.tick(now);
        if at.lane.0 != 0 {
            self.outbound_lane_failed(at.pipe.0, at.lane.0, kind, now);
            return;
        }
        self.outbound_failed(at.pipe.0, PipeFailure::Carrier(kind), now);
    }

    // ---- events and timers ---------------------------------------------

    /// The next event.
    pub fn poll_event(&mut self) -> Option<CoreEvent> {
        let e = self.events.pop_front()?;
        match &e {
            CoreEvent::StreamReadable(k) => {
                if let Some(s) = self.streams.get_mut(*k) {
                    s.notified_readable = false;
                }
            }
            CoreEvent::StreamWritable(k) => {
                if let Some(s) = self.streams.get_mut(*k) {
                    s.notified_writable = false;
                }
            }
            _ => {}
        }
        Some(e)
    }

    /// The earliest deadline at which [`SessionCore::handle_timeout`] must run.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.state == State::Closed {
            return None;
        }
        let ping = self
            .ping
            .outstanding
            .and_then(|(_, at)| at.checked_add(self.ping_timeout()))
            .or_else(|| {
                // An owed request waits for the rate limit.
                self.ping
                    .request_pending
                    .then(|| self.requests.next_slot(self.now))
                    .flatten()
                    .filter(|&t| t > self.now)
            });
        let mp = self.path_deadline();
        [
            self.handshake_deadline,
            self.first_held.as_deref().copied().flatten(),
            self.idle_deadline,
            self.keep_alive_deadline,
            self.linger_deadline,
            self.handoff_deadline,
            self.lanes_deadline(),
            ping,
            mp,
            self.goaway().phase_two_at,
            self.pacing_deadline(),
            self.quality_deadline(),
            self.shape_deadline(),
            self.waiting_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Fires every timer due at `now`.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.fire_timers(now);
        if self.shape.is_some() && self.state != State::Closed {
            self.shape_timeout(now);
        }
        // Last: the quality reports read the estimates and pipe views as
        // the other timers left them.
        self.quality_timeout(now);
    }

    fn fire_timers(&mut self, now: Instant) {
        // Bytes that waited for unwritable pipes since the last input.
        self.refresh_waiting();
        self.tick(now);
        self.pick_input();
        self.pacing_timeout(now);
        if self.state == State::Closed {
            return;
        }
        self.expire_waiting(now);
        if self.close_wait_deadline().is_some_and(|d| now >= d) {
            // The close waited for the other lanes long enough.
            self.end_close_wait();
        }
        if self.handoff_deadline.is_some_and(|d| now >= d) {
            self.handoff_deadline = None;
            self.handoff_expired = true;
            if let Some(f) = self.close_flush.take() {
                // The flush took the whole bound: what is left is
                // discarded, and CONNECTION_CLOSE goes out in the background
                // within one more limit, as an abort's.
                self.close_with(f.0, &f.1, now);
                self.handoff_deadline = Some(now + self.handoff_limit());
                return;
            }
            if !self.close_handed_off() {
                if self.peer_close_unread > 0 {
                    // The application still reads what arrived before the
                    // peer's close: the linger deadline bounds it.
                    self.linger_deadline
                        .get_or_insert(now + self.linger_timeout());
                    return;
                }
                // A carrier did not take CONNECTION_CLOSE in time: the
                // session ends locally, every carrier closed.
                self.closed_now();
                return;
            }
        }
        if self.linger_deadline.is_some_and(|d| now >= d) {
            // The linger runs from the delivery of CONNECTION_CLOSE: while
            // a carrier is still taking it, the hand-off limit bounds the
            // wait, and the delivery starts the linger
            // ([`Self::pipe_written`]).
            if let Some(h) = self.handoff_deadline.filter(|_| !self.close_handed_off()) {
                self.linger_deadline = Some(h);
                return;
            }
            // The deadline may come from a stale clock (a command without a
            // time ended the session): give the close one linger period
            // from now to be written.
            let unwritten = self.atts.outs().any(OutPipe::unwritten);
            if unwritten && !self.linger_extended {
                self.linger_extended = true;
                self.linger_deadline = Some(now + self.linger_timeout());
                return;
            }
            self.linger_deadline = None;
            self.closed_now();
            return;
        }
        if self.goaway().phase_two_at.is_some_and(|t| now >= t) {
            self.goaway_mut().phase_two_at = None;
            self.goaway_phase_two(now);
        }
        if self
            .first_held
            .as_deref()
            .copied()
            .flatten()
            .is_some_and(|d| now >= d)
            && self.release_first_flight(now)
        {
            self.stats.first_flight_timeouts += 1;
        }
        if self.handshake_deadline.is_some_and(|d| now >= d) {
            self.handshake_deadline = None;
            if self.state == State::Establishing {
                self.set_error(SessionError::HandshakeTimeout);
                self.closed_now();
                return;
            }
        }
        if self.idle_deadline.is_some_and(|d| now >= d) {
            self.idle_deadline = None;
            if self.is_established() {
                self.set_error(SessionError::IdleTimeout { remote: false });
                // Toward a plain QMux peer: shut down without frames; in a
                // session with acknowledgement CONNECTION_CLOSE
                // (ZMUX_IDLE_TIMEOUT) on every live outbound pipe.
                let frame = self.acknowledged().then(|| CloseFrame::Transport {
                    code: TransportErrorCode::ZMUX_IDLE_TIMEOUT.0,
                    frame_type: 0,
                    reason: Bytes::new(),
                });
                self.enter_closing(frame, now);
                return;
            }
        }
        if let Some((_, at)) = self.ping.outstanding
            && at
                .checked_add(self.ping_timeout())
                .is_some_and(|t| now >= t)
        {
            // The request stops being outstanding.
            self.ping_lost();
            if self.goaway().fence.is_some() {
                self.goaway_mut().fence = None;
                self.goaway_mut().fence_pending = true;
                self.ping.request_pending = true;
            }
        }
        if self.keep_alive_deadline.is_some_and(|d| now >= d) {
            if self.is_established() && self.ping.outstanding.is_none() {
                // At most one QX_PING after each activity: the next activity, such as its answer,
                // restarts the timer; an unanswered one lets the idle timeout run.
                self.keep_alive_deadline = None;
                self.keep_alive_sent = true;
                self.ping.request_pending = true;
            } else {
                // A request is outstanding already: it probes in place of
                // this one.
                self.keep_alive_deadline = self.keep_alive_wait().and_then(|p| now.checked_add(p));
            }
        }
        self.lanes_timeouts(now);
        self.path_timeout(now);
    }

    /// The outstanding request stopped being outstanding without its
    /// response (its timeout, or the loss of its pipe): a late response
    /// matches nothing, so an application ping still waiting asks again,
    /// as a GOAWAY fence does.
    pub(super) fn ping_lost(&mut self) {
        self.ping.outstanding = None;
        if self.ping.wanted > self.ping.answered {
            self.ping.request_pending = true;
        }
    }

    fn ping_timeout(&self) -> Duration {
        (self.rtt_or_default() * 3).max(Duration::from_secs(1))
    }

    fn linger_timeout(&self) -> Duration {
        if let Some(t) = self.config.hooks.linger_timeout {
            return t;
        }
        (self.rtt_or_default() * 3)
            .max(Duration::from_millis(250))
            .min(Duration::from_secs(2))
    }

    fn push_event(&mut self, e: CoreEvent) {
        if let CoreEvent::PipeRetired { pipe, .. } = e {
            self.quality_retired(pipe.0);
        }
        if matches!(
            e,
            CoreEvent::PipeState { .. }
                | CoreEvent::PipeRetired { .. }
                | CoreEvent::PipePriorityChanged { .. }
        ) {
            // A custom decision made before no longer applies.
            self.advance_pick_generation();
        }
        self.events.push_back(e);
    }

    fn notify_readable(&mut self, key: StreamKey) {
        if let Some(s) = self.streams.get_mut(key)
            && !s.notified_readable
        {
            s.notified_readable = true;
            self.events.push_back(CoreEvent::StreamReadable(key));
        }
    }

    fn notify_writable(&mut self, key: StreamKey) {
        // Whatever changed the part may change its fair-share standing.
        self.sync_holder(key);
        self.streams.notify_writable(key, &mut self.events);
    }

    // ---- closing -------------------------------------------------------

    /// Records the session error if none is set yet (the first cause
    /// wins).
    fn set_error(&mut self, e: SessionError) {
        if self.error.is_none() {
            self.events.push_back(CoreEvent::Closed(e.clone()));
            self.error = Some(Box::new(e));
        }
    }

    /// Closes the session because of a violation the local endpoint found.
    /// Closes the session with a transport INTERNAL_ERROR: after a panic
    /// under its lock in a driver, or when it cannot go on. It does nothing
    /// once the session is closing.
    pub fn fail_internal(&mut self, reason: &'static str, now: Instant) {
        self.protocol_error(
            Error::new(TransportErrorCode::INTERNAL_ERROR, 0, reason),
            now,
        );
    }

    /// Counts an open that waited for stream credit
    /// ([`SessionStats::stream_credit_waits`]); the driver calls it once per open.
    pub fn count_credit_wait(&mut self) {
        self.stats.stream_credit_waits += 1;
    }

    /// Closes a session the listener does not take: CONNECTION_REFUSED,
    /// after the session's own parameters, so that the peer reads why. It does
    /// nothing once the session is closing.
    pub fn refuse(&mut self, reason: &'static str, now: Instant) {
        self.protocol_error(
            Error::new(TransportErrorCode::CONNECTION_REFUSED, 0, reason),
            now,
        );
    }

    fn protocol_error(&mut self, e: Error, now: Instant) {
        if self.state >= State::Closing {
            return;
        }
        self.set_error(if e.code() == TransportErrorCode::ZMUX_RESUME_FAILED {
            SessionError::ResumeFailed {
                reason: Bytes::from_static(e.reason().as_bytes()),
                remote: false,
            }
        } else {
            SessionError::TransportClosed {
                code: e.code(),
                frame_type: e.frame_type(),
                reason: Bytes::from_static(e.reason().as_bytes()),
                details: e.details().collect(),
                remote: false,
            }
        });
        // The reason with its diagnostic line.
        let reason = if e.details().next().is_none() {
            Bytes::from_static(e.reason().as_bytes())
        } else {
            Bytes::from(e.reason_phrase())
        };
        self.enter_closing(
            Some(CloseFrame::Transport {
                code: e.code().0,
                frame_type: e.frame_type(),
                reason,
            }),
            now,
        );
    }

    /// Enters CLOSING: the close frame (if any) is sent, then the write side
    /// is shut down, then the endpoint lingers.
    fn enter_closing(&mut self, frame: Option<CloseFrame>, now: Instant) {
        if self.state >= State::Closing {
            return;
        }
        self.state = State::Closing;
        self.wipe_exporter();
        self.close = frame.map(Box::new);
        self.handshake_deadline = None;
        self.idle_deadline = None;
        self.keep_alive_deadline = None;
        self.ping.outstanding = None;
        self.linger_deadline = Some(now + self.linger_timeout());
        self.start_close_wait(now + self.linger_timeout());
        // Deferred joins never went: their carriers are closed now.
        while let Some(i) = self.atts.iter().position(Attachment::deferred) {
            self.drop_deferred(i);
        }
        for o in self.atts.outs_mut() {
            o.shut_down();
        }
        self.views_changed();
        if let Some(mp) = &mut self.mp {
            mp.closing(now);
        }
        self.wake_all_streams();
        self.maybe_closed(now);
    }

    /// CLOSING ends when the write side is shut down and the inbound side
    /// ended (or at the linger deadline).
    fn maybe_closed(&mut self, now: Instant) {
        let _ = now;
        if self.state != State::Closing {
            return;
        }
        // Protocol rule: a single pipe's inbound side ends with its
        // outbound one; a multipath pipe's are apart.
        let single = !self.is_multipath();
        let done = self.atts.iter().all(|a| {
            let out_closed = a.out().is_some_and(OutPipe::out_closed);
            let in_done =
                a.inp().is_none_or(|p| p.state() == InState::Ended) || (single && out_closed);
            let out_done = a.out().is_none_or(OutPipe::write_done);
            in_done && out_done
        });
        if !done {
            return;
        }
        if self.peer_close_unread > 0 {
            // The application still reads what arrived before the peer's
            // close: CLOSED once it has, or at the linger deadline.
            if self.linger_deadline.is_none() {
                self.linger_deadline = Some(self.now + self.linger_timeout());
            }
            return;
        }
        self.closed_now();
    }

    /// The peer's CONNECTION_CLOSE was processed: counts the streams the
    /// application holds (opened or accepted) with received data unread,
    /// which stays readable until read, or until the linger deadline ends
    /// the session as for every close. Nothing arrives after it, so the
    /// count only falls ([`Self::unread_drained`]).
    pub(super) fn peer_close_received(&mut self) {
        self.peer_close_processed = true;
        self.peer_close_unread = self
            .streams
            .keys()
            .filter(|&k| self.holds_unread(k))
            .count();
    }

    /// Whether `key` counts in [`Self::peer_close_unread`]: the application
    /// holds it and it has received data unread.
    pub(super) fn holds_unread(&self, key: StreamKey) -> bool {
        self.streams.get(key).is_some_and(|s| {
            matches!(s.offer, stream::Offer::Local | stream::Offer::Accepted)
                && s.recv
                    .as_ref()
                    .is_some_and(|r| !r.buf.is_empty() && r.cold().stopped.is_none())
        })
    }

    /// A counted stream's unread data was read or discarded after the peer's
    /// close: the session may be CLOSED now.
    pub(super) fn unread_drained(&mut self) {
        if self.peer_close_unread > 0 {
            self.peer_close_unread -= 1;
            self.maybe_closed(self.now);
        }
    }

    /// Whether the session is closing for the peer's CONNECTION_CLOSE, while
    /// what arrived before it stays readable.
    pub(super) fn draining_peer_close(&self) -> bool {
        self.state == State::Closing && self.peer_close_processed
    }

    /// CLOSED: release everything.
    fn closed_now(&mut self) {
        if self.state == State::Closed {
            return;
        }
        if self.error.is_none() {
            self.set_error(SessionError::PipesLost { last: None });
        }
        self.state = State::Closed;
        self.wipe_exporter();
        self.handshake_deadline = None;
        self.idle_deadline = None;
        self.keep_alive_deadline = None;
        self.linger_deadline = None;
        self.ping.outstanding = None;
        for o in self.atts.outs_mut() {
            o.session_closed();
        }
        self.views_changed();
        if let Some(mp) = &mut self.mp {
            mp.closing(self.now);
        }
        self.wake_all_streams();
    }

    fn wake_all_streams(&mut self) {
        let keys: Vec<StreamKey> = self.streams.keys().collect();
        for k in keys {
            self.notify_readable(k);
            self.notify_writable(k);
        }
        for d in 0..2 {
            if self.streams.take_waiting(d) {
                self.events
                    .push_back(CoreEvent::StreamsAvailable(dir_of_index(d)));
            }
        }
    }

    /// Abandons a session that is not established yet, as its handshake
    /// timeout does: it is closed without
    /// CONNECTION_CLOSE, its carrier closed. Nothing happens to an
    /// established session.
    pub fn abandon(&mut self, now: Instant) {
        self.tick(now);
        if self.state == State::Establishing {
            self.set_error(SessionError::HandshakeTimeout);
            self.closed_now();
        }
    }

    /// Closes the session gracefully with an application CONNECTION_CLOSE:
    /// the stream data written and not yet sent goes out first, as far as
    /// flow control and the carriers allow within the hand-off limit (data
    /// waiting for the peer's credit waits for it), then CONNECTION_CLOSE. The
    /// whole close, the flush included, is bounded by the hand-off limit
    /// (1 s) from this call: what has not left by then is discarded and the
    /// close goes on in the background as an abort's
    /// ([`SessionCore::close_returned`]). The first close or abort decides
    /// what is sent; a later call sends nothing more.
    pub fn close(&mut self, code: VarInt, reason: &[u8], now: Instant) {
        self.tick(now);
        if self.close_flush.is_some() {
            return;
        }
        if self.state >= State::Closing {
            // Closing already (a shutdown's close, which has no hand-off
            // limit, or a protocol error's): this call is still bounded.
            if self.state == State::Closing
                && self.handoff_deadline.is_none()
                && !self.handoff_expired
            {
                self.handoff_deadline = Some(now.max(self.now) + self.handoff_limit());
            }
            return;
        }
        self.handoff_deadline = Some(now.max(self.now) + self.handoff_limit());
        self.close_flush = Some(Box::new((
            code,
            Bytes::copy_from_slice(clip_reason(reason)),
        )));
        self.check_close_flush(now);
    }

    /// Ends the session at once with an application CONNECTION_CLOSE: data
    /// not yet sent is discarded, and CONNECTION_CLOSE is handed to the
    /// carriers in the background, bounded by the hand-off limit (1 s), then
    /// their write sides are shut and their input drained until the peer
    /// ends it or the linger timeout passes. An abort during a graceful
    /// close's flush ends the flush: the close's CONNECTION_CLOSE goes out
    /// at once. A session already closing keeps its close.
    pub fn abort(&mut self, code: VarInt, reason: &[u8], now: Instant) {
        self.tick(now);
        // A close returns at once after an abort that came first or ended its
        // flush; one already handing over CONNECTION_CLOSE keeps its wait.
        if self.state < State::Closing {
            self.close_aborted = true;
        }
        if let Some(f) = self.close_flush.take() {
            self.close_with(f.0, &f.1, now);
            return;
        }
        if self.state <= State::Closing && self.handoff_deadline.is_none() && !self.handoff_expired
        {
            self.handoff_deadline = Some(now.max(self.now) + self.handoff_limit());
        }
        self.close_with(code, reason, now);
    }

    /// Ends the flush of a graceful close once every stream has sent what
    /// it was given ([`Self::close_flushed`]); the hand-off limit ends it
    /// otherwise.
    pub(super) fn check_close_flush(&mut self, now: Instant) {
        if self.close_flush.is_none() || !self.close_flushed() {
            return;
        }
        if let Some(f) = self.close_flush.take() {
            self.close_with(f.0, &f.1, now);
        }
    }

    /// Whether every stream has sent what it was given: its buffer is
    /// empty or it was reset, or no outbound pipe can carry anything. Data
    /// that waits for the peer's credit (flow control, a stream ID) holds
    /// the flush, which the hand-off limit bounds: a peer that reads gets
    /// it ahead of CONNECTION_CLOSE.
    fn close_flushed(&self) -> bool {
        if !self.atts.outs().any(OutPipe::is_live) {
            return true;
        }
        self.streams.keys().all(|k| {
            let Some(send) = self.streams.send(k) else {
                return true;
            };
            send.outcome == Some(stream::SendOutcome::Reset)
                || send.buf.is_empty() && send.preamble_left == 0
        })
    }

    /// The application CONNECTION_CLOSE of a close or of a completed
    /// shutdown (which has no hand-off limit).
    fn close_with(&mut self, code: VarInt, reason: &[u8], now: Instant) {
        if self.state >= State::Closing {
            return;
        }
        let reason = Bytes::copy_from_slice(clip_reason(reason));
        self.set_error(SessionError::ApplicationClosed {
            code,
            reason: reason.clone(),
            remote: false,
        });
        self.enter_closing(
            Some(CloseFrame::Application {
                code: code.into_inner(),
                reason,
            }),
            now,
        );
    }

    /// The hand-off limit of an application close.
    fn handoff_limit(&self) -> Duration {
        self.config
            .hooks
            .close_handoff_limit
            .unwrap_or(CLOSE_HANDOFF_LIMIT)
    }

    /// Whether a close no longer waits for the carriers: CONNECTION_CLOSE was taken whole by the
    /// carrier of every outbound pipe that wrote it and is not closed, and no live pipe
    /// that can still carry it lacks it; also once CLOSED, and for a close
    /// without CONNECTION_CLOSE. False before the session is closing. The
    /// driver tells the bytes the carriers took
    /// ([`SessionCore::pipe_written`]).
    pub fn close_handed_off(&self) -> bool {
        match self.state {
            State::Closed => true,
            State::Closing => {
                self.close.is_none() || self.atts.outs().all(OutPipe::close_handed_off)
            }
            _ => false,
        }
    }

    /// Whether a close or abort no longer holds its caller: CONNECTION_CLOSE
    /// was handed to every carrier that can take it, the hand-off limit
    /// passed, an abort was called, or the session is CLOSED. The
    /// half-close and the drain then go on in the background until the
    /// session is CLOSED.
    pub fn close_returned(&self) -> bool {
        self.state == State::Closed
            || self.close_aborted
            || self.handoff_expired
            || self.close_flush.is_none() && self.close_handed_off()
    }

    /// The session error as seen by stream operations.
    fn lost(&self) -> Option<SessionError> {
        if self.state >= State::Closing {
            Some(
                self.error
                    .as_deref()
                    .cloned()
                    .unwrap_or(SessionError::PipesLost { last: None }),
            )
        } else {
            None
        }
    }

    // ---- establishment -------------------------------------------------

    /// Processes the peer's transport parameters.
    fn on_peer_parameters(&mut self, tp: TransportParameters, now: Instant) -> Result<(), Error> {
        // The parameters this endpoint sends (or sent) offer E only with
        // the bootstrap exporter.
        self.offer_exporter_only_with_one();
        let local = self.local_parameters();
        let role =
            crate::proto::params::resolve_role(local.zmux_role, tp.zmux_role, self.transport_role)?;
        self.role = role;
        self.features = Features::negotiate(&local, &tp);
        self.keep_to_remember(&tp);
        if !self.early_outcome(&tp, now)? {
            return Ok(());
        }
        let protocol = match (&self.config.protocols, &tp.application_protocols) {
            (Some(ours), Some(theirs)) => select_protocol(ours, theirs, self.role == Role::Server),
            _ => None,
        };
        // Send-side limits come from the peer's parameters.
        self.streams.peer_limits(
            tp.initial_max_data.unwrap_or(0),
            [
                tp.initial_max_streams_bidi.unwrap_or(0),
                tp.initial_max_streams_uni.unwrap_or(0),
            ],
        );
        self.peer_tp = Some(tp::TpValues::of(&tp));
        self.state = State::Active;
        self.handshake_deadline = None;
        self.pipe_ack_setup();
        if self.features.multipath {
            self.mp_setup(&local, &tp, now);
        }
        self.drop_unselected_secret();
        if let Some(idle) = self.idle_timeout() {
            self.idle_deadline = now.checked_add(idle);
        }
        self.last_activity = now;
        self.keep_alive_deadline = self.keep_alive_wait().and_then(|p| now.checked_add(p));
        self.push_event(CoreEvent::Established {
            role,
            features: self.features,
            protocol,
        });
        // Streams opened before establishment may send now.
        for d in 0..2 {
            let ld = self.streams.local_dir(d);
            if ld.reserved < ld.peer_max {
                self.events
                    .push_back(CoreEvent::StreamsAvailable(dir_of_index(d)));
            }
        }
        let pending: Vec<StreamKey> = self.streams.keys().collect();
        for k in pending {
            self.after_establish(k);
        }
        // The peer's credit is known: waiting parts may send.
        self.wake_capacity_waiters();
        self.release_early_datagrams();
        // A shutdown requested before establishment starts now.
        if let Some(code) = self.goaway().shutdown {
            self.start_drain(code);
            self.check_shutdown_done(now);
        }
        Ok(())
    }

    /// The effective idle timeout, once established.
    fn idle_timeout(&self) -> Option<Duration> {
        let peer = self.peer_tp.as_ref()?.max_idle_timeout;
        [self.local_tp().max_idle_timeout, peer]
            .into_iter()
            .filter(|&v| v > 0)
            .min()
            .map(Duration::from_millis)
    }

    /// Activity: a record completely received or passed to the carrier
    /// restarts the idle timer, and the keep-alive timer counts the same
    /// activity.
    fn restart_idle(&mut self, now: Instant) {
        // Not while suspended: the grace timer replaces the idle timer.
        if !matches!(self.state, State::Active | State::Draining) {
            return;
        }
        if let Some(t) = self.idle_timeout() {
            self.idle_deadline = now.checked_add(t);
        }
        self.last_activity = now;
        self.keep_alive_sent = false;
        if let Some(wait) = self.keep_alive_wait() {
            self.keep_alive_deadline = now.checked_add(wait);
        }
    }

    /// The next keep-alive wait, drawn when the timer restarts: the period k, capped at half the
    /// effective idle timeout, reduced by a uniform fraction of up to the probe jitter
    /// j, from \[k (1 - j), k\]; `None` with keep-alive off.
    fn keep_alive_wait(&mut self) -> Option<Duration> {
        let mut k = self.config.keep_alive()?;
        if let Some(idle) = self.idle_timeout() {
            k = k.min(idle / 2);
        }
        let j = self.config.liveness.probe_jitter;
        if j <= 0.0 {
            return Some(k);
        }
        let u = (pipes::splitmix(&mut self.keep_alive_rng) >> 11) as f64 / (1u64 << 53) as f64;
        Some(Duration::try_from_secs_f64(k.as_secs_f64() * (1.0 - j * u)).unwrap_or(k))
    }

    // ---- shutdown --------------------------------------------------------

    /// Graceful close: the two-phase GOAWAY when it is in use, then an
    /// application CONNECTION_CLOSE once no stream remains.
    pub fn shutdown(&mut self, code: VarInt, reason: &[u8], now: Instant) {
        self.tick(now);
        if self.state >= State::Closing || self.goaway().shutdown.is_some() {
            return;
        }
        let code = code.into_inner();
        self.goaway_mut().shutdown = Some(code);
        self.goaway_mut().reason = Bytes::copy_from_slice(clip_reason(reason));
        if self.is_established() {
            self.start_drain(code);
        }
        self.check_shutdown_done(now);
    }

    /// Enters DRAINING for a shutdown; with GOAWAY in use, phase 1: the
    /// limits currently granted, then the fence.
    fn start_drain(&mut self, code: u64) {
        if self.state == State::Suspended {
            // Draining after resumption.
            self.drain_after_suspension();
        } else {
            self.state = State::Draining;
        }
        if self.features.goaway {
            let bidi = self.streams.remote_dir(BIDI).limit_sent;
            let uni = self.streams.remote_dir(UNI).limit_sent;
            self.goaway_mut().pending = Some((bidi, uni, code));
            self.goaway_mut().fence_pending = true;
            self.ping.request_pending = true;
        }
    }

    /// After a shutdown, closes once no stream remains.
    fn check_shutdown_done(&mut self, now: Instant) {
        if let Some(code) = self.goaway().shutdown
            && self.state < State::Closing
            && self.streams.len() == 0
            && (self.goaway().final_sent || !self.features.goaway || !self.is_established())
        {
            let reason = std::mem::take(&mut self.goaway_mut().reason);
            self.close_with(VarInt::from_u64(code).unwrap_or(VarInt::ZERO), &reason, now);
        }
    }

    /// Phase 2 of GOAWAY, after the fence completed.
    fn goaway_phase_two(&mut self, now: Instant) {
        let Some(code) = self.goaway().shutdown else {
            return;
        };
        self.goaway_mut().fence = None;
        let (b1, u1) = self.goaway().sent.unwrap_or((
            self.streams.remote_dir(BIDI).limit_sent,
            self.streams.remote_dir(UNI).limit_sent,
        ));
        let b2 = self.streams.remote_dir(BIDI).offered.min(b1);
        let u2 = self.streams.remote_dir(UNI).offered.min(u1);
        self.goaway_mut().final_sent = true;
        if let Some(f) = &self.config.hooks.goaway_final {
            f.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if b2 < b1 || u2 < u1 {
            self.goaway_mut().pending = Some((b2, u2, code));
            self.streams.set_goaway_watermark(BIDI, b2);
            self.streams.set_goaway_watermark(UNI, u2);
            self.reject_above_watermarks(now);
        }
        self.check_shutdown_done(now);
    }

    /// Rejects every peer stream at or above the GOAWAY watermark that was
    /// not offered.
    fn reject_above_watermarks(&mut self, now: Instant) {
        let keys: Vec<StreamKey> = self.streams.keys().collect();
        for k in keys {
            let Some(s) = self.streams.get(k) else {
                continue;
            };
            if s.local || s.offer != stream::Offer::Pending {
                continue;
            }
            let Some(id) = s.id else { continue };
            let d = di(s.dir);
            if self
                .streams
                .remote_dir(d)
                .goaway_sent
                .is_some_and(|w| stream::index(id) >= w)
            {
                self.stack_reject(k, now);
            }
        }
    }

    /// Terminates a peer stream with ZMUX_REJECTED on both parts; it is
    /// never offered and needs no release.
    fn stack_reject(&mut self, key: StreamKey, now: Instant) {
        let code = ApplicationErrorCode::ZMUX_REJECTED.0;
        if let Some(s) = self.streams.get_mut(key) {
            s.offer = stream::Offer::Rejected;
            s.released = true;
        }
        self.local_stop(key, code);
        self.local_reset(key, code);
        self.try_discard(key);
        let _ = now;
    }
}

/// Converts an application code into a [`VarInt`], saturating (codes from
/// the wire are always in range).
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap_or(VarInt::MAX)
}

/// Transport error helper.
fn violation(code: TransportErrorCode, frame_type: u64, reason: &'static str) -> Error {
    Error::new(code, frame_type, reason)
}

/// A Reason Phrase of at most 1024 bytes, cut before
/// a UTF-8 continuation byte so that text is not split inside a character.
fn clip_reason(reason: &[u8]) -> &[u8] {
    const MAX: usize = 1024;
    if reason.len() <= MAX {
        return reason;
    }
    let mut end = MAX;
    while end > MAX - 3 && reason[end] & 0xc0 == 0x80 {
        end -= 1;
    }
    &reason[..end]
}

/// What Joins counted of their handshake plans.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct JoinShaping {
    unplanned: u64,
    faults: u64,
}
