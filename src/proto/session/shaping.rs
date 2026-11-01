//! [`Shaper`] customizes record sizes and timing.
//!
//! A [`Factory`] installed on a session
//! ([`SessionCore::set_shaper`](super::SessionCore::set_shaper)) gives each
//! outbound pipe its own [`Shaper`]; the session calls it on the thread that
//! drives it and applies its answers within the protocol's limits and the
//! session's [`Limits`].

use std::fmt;
use std::ops::BitOr;
use std::time::{Duration, Instant};

use super::{CarrierKind, PipeId};

/// Customizes record sizes and timing. The session calls its methods one at
/// a time, under its own lock; they must not block or call methods of the
/// session. A panic ends shaping of the pipe and is counted in
/// [`Stats::faults`].
pub trait Shaper: Send {
    /// Called once, when the instance is installed.
    fn capabilities(&self) -> Caps;

    /// Called before each outgoing record of the pipe ([`Caps::PLAN`]);
    /// `plan` starts at its default.
    fn plan(&mut self, view: &RecordView, plan: &mut RecordPlan) {
        let _ = (view, plan);
    }

    /// Receives a notification; `reply` starts at its default. Unknown
    /// kinds should be ignored.
    fn on_event(&mut self, event: &Event, reply: &mut Reply) {
        let _ = (event, reply);
    }
}

/// The outbound pipe a [`Factory`] makes a [`Shaper`] for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ShapedPipe {
    /// The pipe ID.
    pub id: PipeId,
    /// The pipe's carrier kind (`PipeIo::with_carrier`, set by the
    /// adapters); `None` for a carrier of no listed kind, such as raw TCP
    /// or TLS.
    pub carrier: Option<CarrierKind>,
    /// The fixed number of bytes the layers below zmux add to each write
    /// call on the pipe's carrier (`PipeIo::with_write_overhead`; 0:
    /// none), passed through unchanged. zmux itself does not use it.
    pub write_overhead: u16,
}

impl ShapedPipe {
    /// Pipe `id` on a carrier of kind `carrier`, without write overhead.
    pub const fn new(id: PipeId, carrier: Option<CarrierKind>) -> Self {
        Self {
            id,
            carrier,
            write_overhead: 0,
        }
    }

    /// With the carrier's write overhead ([`ShapedPipe::write_overhead`]).
    #[must_use]
    pub const fn with_write_overhead(mut self, bytes: u16) -> Self {
        self.write_overhead = bytes;
        self
    }
}

/// Makes the [`Shaper`] of an outbound pipe; `None`: the pipe is not
/// shaped. It is called when the pipe's first record is made after the
/// factory was installed, and may be called from several sessions at once.
pub trait Factory: Send + Sync {
    /// The instance for `pipe`.
    fn shaper(&self, pipe: &ShapedPipe) -> Option<Box<dyn Shaper>>;
}

impl<F> Factory for F
where
    F: Fn(&ShapedPipe) -> Option<Box<dyn Shaper>> + Send + Sync,
{
    fn shaper(&self, pipe: &ShapedPipe) -> Option<Box<dyn Shaper>> {
        self(pipe)
    }
}

/// A set of capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Caps(u32);

impl Caps {
    /// None.
    pub const NONE: Self = Self(0);
    /// [`Shaper::plan`] is called.
    pub const PLAN: Self = Self(1);
    /// [`EventKind::RecordIn`] is delivered.
    pub const RECORD_IN: Self = Self(2);
    /// [`EventKind::StreamOpen`] and [`EventKind::StreamEnd`] are delivered.
    pub const STREAMS: Self = Self(4);

    /// Whether every capability of `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for Caps {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The next outgoing record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordView {
    /// The pipe.
    pub pipe: PipeId,
    /// The lane of the pipe (0: the pipe's own carrier).
    pub lane: u64,
    /// Records of the pipe planned before this one.
    pub seq: u64,
    /// The largest frames length, bytes.
    pub limit: usize,
    /// The record is the first of a write call on the carrier: every
    /// record on a carrier with message framing, the first record of each
    /// batch on a byte stream.
    pub write_start: bool,
    /// The session clock.
    pub now: Instant,
}

impl RecordView {
    /// A view with the given values.
    #[must_use]
    pub const fn new(pipe: PipeId, lane: u64, seq: u64, limit: usize, now: Instant) -> Self {
        Self {
            pipe,
            lane,
            seq,
            limit,
            write_start: false,
            now,
        }
    }

    /// With [`RecordView::write_start`].
    #[must_use]
    pub const fn with_write_start(mut self, write_start: bool) -> Self {
        self.write_start = write_start;
        self
    }
}

/// The decision for one record. Values beyond the limits are reduced to
/// them.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct RecordPlan {
    /// The largest frames length, bytes; 0: [`RecordView::limit`]. A
    /// frame that does not fit starts a record of its own.
    pub max_len: usize,
    /// Frames length padded up to, bytes; 0: none.
    pub pad_to: usize,
    /// Frames length rounded up to a multiple, bytes, after `pad_to`; 0:
    /// none.
    pub pad_multiple: usize,
    /// PADDING bytes appended after `pad_to` and `pad_multiple`; 0: none.
    pub pad: usize,
    /// The record ends its carrier write.
    pub flush: bool,
    /// Stream data of the pipe waits this long from the record on; zero:
    /// none.
    pub delay: Duration,
    /// Shaping of the pipe ends after the record.
    pub stop: bool,
    /// Applied as an event reply when the plan is made.
    pub reply: Reply,
}

/// What an [`Event`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventKind {
    /// The instance was installed.
    Start,
    /// The instance was replaced; no further calls.
    Replaced,
    /// A record arrived on the pipe ([`Caps::RECORD_IN`]).
    RecordIn,
    /// A record of PADDING only was sent, or PADDING was added to a record
    /// for an [`Inject`].
    Injected,
    /// A timer fired.
    Timer,
    /// Shaping of the pipe ended; no further calls.
    Stopped,
    /// The pipe's outbound direction failed; no further calls.
    PipeFailed,
    /// A stream got its identifier ([`Caps::STREAMS`]).
    StreamOpen,
    /// A stream's state was discarded ([`Caps::STREAMS`]).
    StreamEnd,
}

/// A notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Event {
    /// What happened.
    pub kind: EventKind,
    /// The pipe.
    pub pipe: PipeId,
    /// The lane ([`EventKind::RecordIn`]).
    pub lane: u64,
    /// The session clock.
    pub now: Instant,
    /// Frames length, bytes ([`EventKind::RecordIn`], [`EventKind::Injected`]).
    pub len: usize,
    /// The record holds PADDING only ([`EventKind::RecordIn`]).
    pub padding_only: bool,
    /// The timer slot, 0 or 1 ([`EventKind::Timer`]).
    pub timer: usize,
    /// The stream ID ([`EventKind::StreamOpen`], [`EventKind::StreamEnd`]).
    pub stream: u64,
}

impl Event {
    /// An event of `kind` with zero values elsewhere.
    #[must_use]
    pub const fn new(kind: EventKind, pipe: PipeId, now: Instant) -> Self {
        Self {
            kind,
            pipe,
            lane: 0,
            now,
            len: 0,
            padding_only: false,
            timer: 0,
            stream: 0,
        }
    }

    /// With `lane`.
    #[must_use]
    pub const fn with_lane(mut self, lane: u64) -> Self {
        self.lane = lane;
        self
    }

    /// With `len` and `padding_only`.
    #[must_use]
    pub const fn with_len(mut self, len: usize, padding_only: bool) -> Self {
        self.len = len;
        self.padding_only = padding_only;
        self
    }

    /// With timer slot `timer`.
    #[must_use]
    pub const fn with_timer(mut self, timer: usize) -> Self {
        self.timer = timer;
        self
    }

    /// With stream ID `stream`.
    #[must_use]
    pub const fn with_stream(mut self, stream: u64) -> Self {
        self.stream = stream;
        self
    }
}

/// The answer to an [`Event`]. `None` fields and the default change
/// nothing.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Reply {
    /// Replaces the pending injection.
    pub inject: Option<Inject>,
    /// Replaces the gate.
    pub gate: Option<Gate>,
    /// Arms or cancels the two timer slots.
    pub timers: [Option<Timer>; 2],
    /// [`PipeSnapshot::shaping_weight`](super::PipeSnapshot::shaping_weight)
    /// of the pipe; a value that is not positive and finite is ignored.
    pub weight: Option<f64>,
    /// Shaping of the pipe ends.
    pub stop: bool,
}

impl Reply {
    pub(crate) fn is_empty(&self) -> bool {
        self.inject.is_none()
            && self.gate.is_none()
            && self.timers == [None, None]
            && self.weight.is_none()
            && !self.stop
    }
}

/// A record of PADDING only on lane 0 of the pipe; one is pending at most.
/// When a record with other frames is being built as it falls due, its
/// bytes are added to that record as PADDING instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Inject {
    /// `len` frames bytes, `after` from now.
    Send {
        /// From now.
        after: Duration,
        /// Frames length, bytes; at least 1.
        len: usize,
    },
    /// Cancels the pending one.
    Cancel,
}

/// Bounds the stream data of the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Gate {
    /// Stream data waits this long from now; zero: none.
    pub pause: Duration,
    /// Bytes per second; 0: no limit.
    pub rate: u64,
    /// Bytes; 0: the record limit.
    pub burst: u64,
}

impl Gate {
    /// A gate of `pause`, `rate` and `burst`.
    #[must_use]
    pub const fn new(pause: Duration, rate: u64, burst: u64) -> Self {
        Self { pause, rate, burst }
    }
}

/// Arms or cancels a timer slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Timer {
    /// Fires once, this long from now.
    After(Duration),
    /// Cancels the slot.
    Cancel,
}

/// The smallest [`RecordPlan`] `max_len` honoured (64 bytes: a STREAM
/// frame header and some data); a smaller nonzero one is raised to it and
/// counted in [`Stats::clamped`].
pub const MIN_MAX_LEN: usize = 64;

/// The PADDING a session may add under a set
/// [`Limits::max_padding_ratio`] whatever the ratio (16382 bytes, one
/// record of the default `max_record_size`), so that the first padding and
/// injections of a session are not cut by the ratio;
/// [`Limits::max_padding_bytes`] still applies. Without a ratio limit it
/// does not apply.
pub const STARTUP_ALLOWANCE: u64 = crate::proto::params::DEFAULT_MAX_RECORD_SIZE;

/// Upper bounds over a session. Each field is `None` by default, no
/// limit; a set one bounds as it is, zero allowing none. A session whose
/// limits are not [valid](Self::validate) is not created.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct Limits {
    /// PADDING bytes added.
    pub max_padding_bytes: Option<u64>,
    /// PADDING bytes added over the other bytes sent, in \[0, 1\]: at
    /// most max(ratio x the other bytes sent, [`STARTUP_ALLOWANCE`]).
    pub max_padding_ratio: Option<f64>,
    /// Records of PADDING only.
    pub max_injected: Option<u64>,
    /// Sum of pauses and delays.
    pub max_pause_total: Option<Duration>,
    /// One pause or delay.
    pub max_delay: Option<Duration>,
}

impl Limits {
    /// Whether the limits are valid: a set `max_padding_ratio` a number in
    /// \[0, 1\] (the other fields cannot be negative).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .max_padding_ratio
            .is_some_and(|r| !(0.0..=1.0).contains(&r))
        {
            return Err("shaping_limits max_padding_ratio outside [0, 1]");
        }
        Ok(())
    }
}

/// Counters over a session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// PADDING bytes added.
    pub padding_bytes: u64,
    /// Records of PADDING only sent.
    pub injected: u64,
    /// Injections not sent.
    pub inject_dropped: u64,
    /// Decisions reduced to limits.
    pub clamped: u64,
    /// Pauses and delays applied.
    pub pause_total: Duration,
    /// Calls that panicked.
    pub faults: u64,
}

impl fmt::Debug for dyn Factory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Factory")
    }
}

impl fmt::Debug for dyn Shaper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Shaper")
    }
}
