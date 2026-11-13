//! [`Shaper`] customizes record sizes and timing.
//!
//! A [`Factory`] installed on a session
//! ([`SessionCore::set_shaper`](super::SessionCore::set_shaper)) gives each
//! outbound pipe its own [`Shaper`]; the session calls it on the thread that
//! drives it and applies its answers within the protocol's limits and the
//! session's [`Limits`]. A [`HandshakeShaper`] plans the handshake messages a
//! side writes, outside every lock.
//!
//! Every length of a plan is the length of one unit on the carrier; the core
//! converts it. Times are microseconds of the session clock, which starts at 0.

use std::fmt;
use std::ops::BitOr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

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

    /// Receives a notification; `effects` starts at its default. Unknown
    /// kinds should be ignored.
    fn on_event(&mut self, event: &Event, effects: &mut Effects) {
        let _ = (event, effects);
    }
}

/// The outbound pipe a [`Factory`] makes a [`Shaper`] for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// The host's label of the transform the carrier runs
    /// (`PipeIo::with_variant`), so that a factory can choose by it.
    pub variant: Option<Arc<str>>,
}

impl ShapedPipe {
    /// Pipe `id` on a carrier of kind `carrier`, without write overhead.
    pub const fn new(id: PipeId, carrier: Option<CarrierKind>) -> Self {
        Self {
            id,
            carrier,
            write_overhead: 0,
            variant: None,
        }
    }

    /// With the carrier's variant ([`ShapedPipe::variant`]).
    #[must_use]
    pub fn with_variant(mut self, variant: Option<Arc<str>>) -> Self {
        self.variant = variant;
        self
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
    /// [`RecordView::meters`] and [`Event::meters`] are filled.
    pub const BUDGET: Self = Self(8);

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
    /// The session clock, microseconds.
    pub now: u64,
    /// The session's readings ([`Caps::BUDGET`]).
    pub meters: Meters,
}

impl RecordView {
    /// A view with the given values.
    #[must_use]
    pub const fn new(pipe: PipeId, lane: u64, seq: u64, limit: usize, now: u64) -> Self {
        Self {
            pipe,
            lane,
            seq,
            limit,
            write_start: false,
            now,
            meters: Meters::new(0, 0, 0, 0),
        }
    }

    /// With [`RecordView::meters`].
    #[must_use]
    pub const fn with_meters(mut self, meters: Meters) -> Self {
        self.meters = meters;
        self
    }

    /// With [`RecordView::write_start`].
    #[must_use]
    pub const fn with_write_start(mut self, write_start: bool) -> Self {
        self.write_start = write_start;
        self
    }
}

/// The size and timing of one unit written to a carrier: a handshake message
/// or a record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnitPlan {
    /// Wire length padded up to, bytes; 0: none.
    pub pad_to: usize,
    /// Wire length rounded up to a multiple, after `pad_to`; 0: none.
    pub pad_multiple: usize,
    /// Bytes added after both; 0: none.
    pub pad: usize,
    /// Wait before the write.
    pub delay: Duration,
}

impl UnitPlan {
    /// The plan of the given lengths and no delay.
    #[must_use]
    pub const fn new(pad_to: usize, pad_multiple: usize, pad: usize) -> Self {
        Self {
            pad_to,
            pad_multiple,
            pad,
            delay: Duration::ZERO,
        }
    }

    /// With `delay`.
    #[must_use]
    pub const fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// The wire length a unit of `n` bytes grows to.
    #[must_use]
    pub const fn pad_for(&self, n: usize) -> usize {
        pad_for(n, self.pad_to, self.pad_multiple, self.pad)
    }

    /// Applies `limits`: `no_padding` clears the lengths, `no_pause` the delay, and the
    /// bound on one wait bounds it.
    pub fn apply_limits(&mut self, limits: &Limits) {
        if limits.no_padding {
            self.pad_to = 0;
            self.pad_multiple = 0;
            self.pad = 0;
        }
        if limits.no_pause {
            self.delay = Duration::ZERO;
        }
        if let Some(m) = limits.max_delay {
            self.delay = self.delay.min(m);
        }
    }
}

/// A hook's lengths are unbounded here: the result saturates at the largest length a signed
/// gap can hold, and the room of the message bounds what is sent.
const fn pad_for(n: usize, pad_to: usize, multiple: usize, pad: usize) -> usize {
    let mut t = if n > pad_to { n } else { pad_to };
    if multiple > 0 && t % multiple != 0 {
        t = t.saturating_add(multiple - t % multiple);
    }
    let t = t.saturating_add(pad);
    if t > isize::MAX as usize {
        isize::MAX as usize
    } else {
        t
    }
}

/// What a [`HandshakeShaper`] is told of a message. It is not told a size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HandshakeView {
    /// The kind of carrier; `None` for one of no listed kind.
    pub kind: Option<CarrierKind>,
    /// The handshake: `establish` or `join`.
    pub handshake: &'static str,
    /// The message: `hello`, `reply`, `finish`, `hello_early` or `confirm`.
    pub message: &'static str,
}

impl HandshakeView {
    /// The view of a message.
    #[must_use]
    pub const fn new(
        kind: Option<CarrierKind>,
        handshake: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            kind,
            handshake,
            message,
        }
    }
}

/// Is asked for the plan of each handshake message a side writes; `None` is no
/// plan. It is called outside every lock, may be called concurrently and must
/// not block. A panic is no plan, and the handshake goes on.
#[derive(Clone)]
pub struct HandshakeShaper(pub Arc<HandshakeShaperFn>);

/// The callable behind a [`HandshakeShaper`].
pub type HandshakeShaperFn = dyn Fn(&HandshakeView) -> Option<UnitPlan> + Send + Sync;

impl HandshakeShaper {
    /// The shaper of `f`.
    pub fn new(f: impl Fn(&HandshakeView) -> Option<UnitPlan> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }
}

impl fmt::Debug for HandshakeShaper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HandshakeShaper")
    }
}

/// What a [`HandshakeShaper`] answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanAnswer {
    /// A plan, with the limits applied.
    Plan(UnitPlan),
    /// No plan for this message.
    Unplanned,
    /// The call panicked.
    Fault,
}

/// Asks `shaper` about a message and applies `limits` to the plan.
#[must_use]
pub fn ask_handshake(
    shaper: &HandshakeShaper,
    view: &HandshakeView,
    limits: &Limits,
) -> PlanAnswer {
    match catch_unwind(AssertUnwindSafe(|| (shaper.0)(view))) {
        Ok(Some(mut plan)) => {
            plan.apply_limits(limits);
            PlanAnswer::Plan(plan)
        }
        Ok(None) => PlanAnswer::Unplanned,
        Err(_) => PlanAnswer::Fault,
    }
}

/// The length of a shortest variable-length integer.
#[must_use]
pub const fn varint_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// The length of a padding item of `v` bytes of value.
#[must_use]
pub const fn item_size(v: usize) -> usize {
    1 + varint_len(v as u64) + v
}

/// The largest value length whose item fits in `room`; `None` when none does.
#[must_use]
pub const fn fit_item(room: usize) -> Option<usize> {
    if room < 2 {
        return None;
    }
    let mut v = room - 2;
    while v > 0 && item_size(v) > room {
        v -= 1;
    }
    Some(v)
}

/// The padding item that grows a message by `gap` bytes within `room` bytes: its
/// value length, the smallest whose item reaches `gap`, or the largest that fits.
/// `None` is no item.
#[must_use]
pub const fn pad_item(gap: isize, room: usize) -> Option<usize> {
    if gap <= 0 {
        return None;
    }
    let gap = gap as usize;
    let mut v = gap.saturating_sub(2);
    while v > 0 && item_size(v - 1) >= gap {
        v -= 1;
    }
    while item_size(v) < gap {
        v += 1;
    }
    if item_size(v) > room {
        return fit_item(room);
    }
    Some(v)
}

/// The zero bytes that grow a confirmation by `gap` within `room` bytes.
#[must_use]
pub const fn pad_fill(gap: isize, room: usize) -> usize {
    if gap <= 0 {
        return 0;
    }
    if gap as usize > room {
        room
    } else {
        gap as usize
    }
}

/// The wire length of a record of `frames` bytes: its size field where the framing
/// has one, and the write overhead where the record starts a write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordWire {
    /// The record has a size field: a byte stream, not Sealed.
    pub size_field: bool,
    /// The write overhead counted on this record.
    pub overhead: usize,
}

impl RecordWire {
    /// The wire length of `frames` bytes.
    #[must_use]
    pub const fn wire(&self, frames: usize) -> usize {
        let size = if self.size_field {
            varint_len(frames as u64)
        } else {
            0
        };
        size + frames + self.overhead
    }

    /// The smallest frames length that reaches wire length `target`, so that a
    /// length no record can have is taken to the next one that it can.
    #[must_use]
    pub const fn frames_of(&self, target: usize) -> usize {
        if target <= self.overhead {
            return 0;
        }
        let x = target - self.overhead;
        if !self.size_field {
            return x;
        }
        let mut f = x.saturating_sub(8);
        while f + varint_len(f as u64) < x {
            f += 1;
        }
        f
    }

    /// The largest frames length whose wire length is at most `target`.
    #[must_use]
    pub const fn frames_within(&self, target: usize) -> usize {
        if target <= self.overhead {
            return 0;
        }
        let x = target - self.overhead;
        if !self.size_field {
            return x;
        }
        let mut f = x.saturating_sub(1);
        while f > 0 && f + varint_len(f as u64) > x {
            f -= 1;
        }
        f
    }

    /// The largest frames length `plan` allows; 0: no bound. The bool says a
    /// length below [`MIN_MAX_LEN`] was raised, with the `pad_to` it came with.
    pub fn frames_max(&self, plan: &mut RecordPlan) -> (usize, bool) {
        if plan.max_len == 0 {
            return (0, false);
        }
        let f = self.frames_of(plan.max_len);
        if f >= MIN_MAX_LEN {
            return (f, false);
        }
        if plan.pad_to == plan.max_len {
            plan.pad_to = self.wire(MIN_MAX_LEN);
        }
        (MIN_MAX_LEN, true)
    }

    /// The frames length of a record of `data` frames bytes under `plan`.
    #[must_use]
    pub const fn frames(&self, data: usize, plan: &RecordPlan) -> usize {
        let n = self.wire(data);
        let t = pad_for(n, plan.pad_to, plan.pad_multiple, plan.pad);
        if t <= n {
            return data;
        }
        let f = self.frames_of(t);
        if f > data { f } else { data }
    }
}

/// The wire length without padding of an Establish Hello: `profile`, a Handle of the
/// given length if it has one, the length field on a byte stream, Noise bytes and the
/// carrier's write overhead.
#[must_use]
pub const fn establish_hello_len(
    profile: u64,
    handle: bool,
    stream: bool,
    noise: usize,
    overhead: usize,
) -> usize {
    let wire_profile = if profile <= 7 {
        1
    } else {
        1 + varint_len(profile)
    };
    // The Handle is 16 bytes, present exactly when the Profile has one.
    let handle = if handle { 16 } else { 0 };
    wire_profile + 1 + handle + message_len(stream, noise, overhead)
}

/// The wire length without padding of a message that is its body: an Establish Reply or
/// Finish, or a Confirm, whose body is the tag.
#[must_use]
pub const fn message_len(stream: bool, body: usize, overhead: usize) -> usize {
    (if stream { 2 } else { 0 }) + body + overhead
}

/// The wire length without padding of a Join Hello.
#[must_use]
pub const fn join_hello_len(
    suite: u64,
    locator: usize,
    r: usize,
    stream: bool,
    ciphertext: usize,
    overhead: usize,
) -> usize {
    1 + varint_len(suite) + 2 + locator + r + message_len(stream, ciphertext, overhead)
}

/// The wire length without padding of a Join Reply.
#[must_use]
pub const fn join_reply_len(r: usize, stream: bool, ciphertext: usize, overhead: usize) -> usize {
    1 + r + message_len(stream, ciphertext, overhead)
}

/// The limit of a Hello's first batch: `early` is the configured one, `base` the
/// Hello's wire length without its frames and padding. With a length to pad to, the
/// batch stays within it.
#[must_use]
pub const fn first_batch_limit(early: usize, pad_to: usize, base: usize) -> usize {
    if pad_to == 0 {
        return early;
    }
    if pad_to < base {
        return 0;
    }
    match fit_item(pad_to - base) {
        Some(v) if v < early => v,
        Some(_) => early,
        None => 0,
    }
}

/// What a Reply may hold before Confirmed, where the carrier's bytes received bound
/// it (Sealed, Bound): three times `received`, frames before padding. `base` is the
/// Reply's wire length without its frames and padding, and `want` the frames wanted.
/// Returns the frames' limit and the room left for padding.
#[must_use]
pub const fn reply_room(received: usize, base: usize, want: usize) -> (usize, usize) {
    let room = (3 * received).saturating_sub(base);
    let limit = match fit_item(room) {
        Some(v) if v < want => v,
        Some(_) => want,
        None => 0,
    };
    let used = if limit > 0 { item_size(limit) } else { 0 };
    (limit, room.saturating_sub(used))
}

/// The decision for one record. Lengths are wire lengths; the core converts them,
/// and values beyond the limits are reduced to them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordPlan {
    /// The largest record, bytes; 0: [`RecordView::limit`]. A frame that does
    /// not fit starts a record of its own.
    pub max_len: usize,
    /// Wire length padded up to, bytes; 0: none.
    pub pad_to: usize,
    /// Wire length rounded up to a multiple, after `pad_to`; 0: none.
    pub pad_multiple: usize,
    /// Bytes added after `pad_to` and `pad_multiple`; 0: none.
    pub pad: usize,
    /// The record ends its carrier write.
    pub flush: bool,
    /// Stream data of the pipe waits this long from the record on; zero:
    /// none.
    pub delay: Duration,
    /// Shaping of the pipe ends after the record.
    pub stop: bool,
    /// Applied when the plan is made.
    pub effects: Effects,
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
    /// for an [`Injection`].
    Injected,
    /// The core gave up the pending [`Injection`]: the account, a limit, the protocol or
    /// the peer. An answer that keeps it is tried again one granularity later.
    InjectDropped,
    /// The wake time ([`Effects::wake`]) came.
    Wake,
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
    /// The session clock, microseconds.
    pub now: u64,
    /// Frames length, bytes ([`EventKind::RecordIn`], [`EventKind::Injected`]).
    pub len: usize,
    /// The record holds PADDING only ([`EventKind::RecordIn`]).
    pub padding_only: bool,
    /// The stream ID ([`EventKind::StreamOpen`], [`EventKind::StreamEnd`]).
    pub stream: u64,
    /// The session's readings ([`Caps::BUDGET`]).
    pub meters: Meters,
}

impl Event {
    /// An event of `kind` with zero values elsewhere.
    #[must_use]
    pub const fn new(kind: EventKind, pipe: PipeId, now: u64) -> Self {
        Self {
            kind,
            pipe,
            lane: 0,
            now,
            len: 0,
            padding_only: false,
            stream: 0,
            meters: Meters::new(0, 0, 0, 0),
        }
    }

    /// With [`Event::meters`].
    #[must_use]
    pub const fn with_meters(mut self, meters: Meters) -> Self {
        self.meters = meters;
        self
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

    /// With stream ID `stream`.
    #[must_use]
    pub const fn with_stream(mut self, stream: u64) -> Self {
        self.stream = stream;
        self
    }
}

/// What changed with an entrance of a [`Shaper`]. A field that is `None` changes
/// nothing: the core keeps one injection, one wake time, one gate and one weight
/// per pipe. An injection or a wake time that has come stays until a later
/// answer changes it, so an answer to [`EventKind::Injected`],
/// [`EventKind::InjectDropped`] and [`EventKind::Wake`] says what follows it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Effects {
    /// The pending injection, or none.
    pub inject: Option<Option<Injection>>,
    /// When to send [`EventKind::Wake`], or never.
    pub wake: Option<Option<u64>>,
    /// The gate.
    pub gate: Option<Gate>,
    /// [`PipeSnapshot::shaping_weight`](super::PipeSnapshot::shaping_weight)
    /// of the pipe; 0 changes nothing.
    pub weight: Option<u32>,
    /// Shaping of the pipe ends.
    pub stop: bool,
}

impl Effects {
    pub(crate) fn is_empty(&self) -> bool {
        self.inject.is_none()
            && self.wake.is_none()
            && self.gate.is_none()
            && self.weight.is_none()
            && !self.stop
    }
}

/// A record of PADDING only on lane 0 of the pipe. When a record with other
/// frames is being built as it falls due, its bytes are added to that record as
/// PADDING instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Injection {
    /// When, on the session clock.
    pub at: u64,
    /// Wire length, bytes.
    pub len: usize,
}

impl Injection {
    /// `len` bytes at `at`.
    #[must_use]
    pub const fn new(at: u64, len: usize) -> Self {
        Self { at, len }
    }
}

/// Bounds the stream data of the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Gate {
    /// Stream data waits until then, on the session clock.
    pub pause_until: u64,
    /// Bytes per second; 0: no limit.
    pub rate: u64,
    /// Bytes; 0: the record limit.
    pub burst: u64,
}

impl Gate {
    /// A gate of `pause_until`, `rate` and `burst`.
    #[must_use]
    pub const fn new(pause_until: u64, rate: u64, burst: u64) -> Self {
        Self {
            pause_until,
            rate,
            burst,
        }
    }
}

/// The smallest [`RecordPlan`] `max_len` honoured (64 bytes: a STREAM
/// frame header and some data); a smaller nonzero one is raised to it and
/// counted in [`Stats::clamped`].
pub const MIN_MAX_LEN: usize = 64;

/// The default of [`Limits::max_delay`], the bound on one wait.
pub const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(1);

/// The largest [`Account::initial`].
pub const MAX_ACCOUNT_INITIAL: u64 = 1 << 53;

/// The largest [`Account::per_mb`] and [`Account::per_sec`], and the largest rate of a [`Gate`].
pub const MAX_ACCOUNT_RATE: u64 = 1 << 43;

/// An allowance for injections, in bytes on the carrier. All fields zero: not set.
/// Padding that goes with a record is never refused and does not draw on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Account {
    /// Available from the start.
    pub initial: u64,
    /// Added per 10^6 bytes this endpoint sends of its own.
    pub per_mb: u64,
    /// Added per second.
    pub per_sec: u64,
}

impl Account {
    /// An account of the given values.
    #[must_use]
    pub const fn new(initial: u64, per_mb: u64, per_sec: u64) -> Self {
        Self {
            initial,
            per_mb,
            per_sec,
        }
    }

    /// Whether every field is zero.
    #[must_use]
    pub const fn is_unset(&self) -> bool {
        self.initial == 0 && self.per_mb == 0 && self.per_sec == 0
    }

    const fn clamped(self) -> Self {
        Self {
            initial: if self.initial > MAX_ACCOUNT_INITIAL {
                MAX_ACCOUNT_INITIAL
            } else {
                self.initial
            },
            per_mb: if self.per_mb > MAX_ACCOUNT_RATE {
                MAX_ACCOUNT_RATE
            } else {
                self.per_mb
            },
            per_sec: if self.per_sec > MAX_ACCOUNT_RATE {
                MAX_ACCOUNT_RATE
            } else {
                self.per_sec
            },
        }
    }
}

/// Local bounds over a session, set by the application and never sent. A configuration
/// cannot widen them. A session whose limits are not [valid](Self::validate) is not created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// What injections may spend.
    pub wire: Account,
    /// The bound on one wait, and so on the lowest rate of a gate (default
    /// [`DEFAULT_MAX_DELAY`]; `None`: no bound). A bound is above zero.
    pub max_delay: Option<Duration>,
    /// No padding at all, on handshakes and injections too.
    pub no_padding: bool,
    /// No pause or delay.
    pub no_pause: bool,
    /// No injection.
    pub no_injection: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            wire: Account::default(),
            max_delay: Some(DEFAULT_MAX_DELAY),
            no_padding: false,
            no_pause: false,
            no_injection: false,
        }
    }
}

impl Limits {
    /// Whether the limits are valid: the account's fields within their maximums and a
    /// set `max_delay` above zero.
    pub fn validate(&self) -> Result<(), crate::InvalidConfig> {
        let a = self.wire;
        if a.initial > MAX_ACCOUNT_INITIAL
            || a.per_mb > MAX_ACCOUNT_RATE
            || a.per_sec > MAX_ACCOUNT_RATE
        {
            return Err(crate::InvalidConfig::new(
                "shaping_limits",
                "a wire account field above its maximum",
            ));
        }
        if self.max_delay == Some(Duration::ZERO) {
            return Err(crate::InvalidConfig::new(
                "shaping_limits",
                "max_delay of zero",
            ));
        }
        Ok(())
    }

    /// These limits in force under `budget`: the account field by field the smaller where
    /// both are set, the smaller bound on one wait, and either side's switch. Two set
    /// accounts whose smaller fields are all zero allow no injection.
    #[must_use]
    pub fn under(mut self, budget: &Budget) -> Self {
        let b = budget.wire.clamped();
        if self.wire.is_unset() {
            self.wire = b;
        } else if !b.is_unset() {
            self.wire = Account {
                initial: self.wire.initial.min(b.initial),
                per_mb: self.wire.per_mb.min(b.per_mb),
                per_sec: self.wire.per_sec.min(b.per_sec),
            };
            self.no_injection |= self.wire.is_unset();
        }
        self.no_injection |= budget.no_injection;
        self.max_delay = match (self.max_delay, budget.max_delay.filter(|d| !d.is_zero())) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        };
        self
    }
}

/// What a shaping configuration allows for a session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Budget {
    /// What injections may spend.
    pub wire: Account,
    /// The configuration's bound on one wait; `None`: none.
    pub max_delay: Option<Duration>,
    /// The configuration allows no injection.
    pub no_injection: bool,
}

impl Budget {
    /// A budget of the given values.
    #[must_use]
    pub const fn new(wire: Account, max_delay: Option<Duration>, no_injection: bool) -> Self {
        Self {
            wire,
            max_delay,
            no_injection,
        }
    }
}

/// Gives the budget of a session: called once per session, outside every lock; it may be
/// called concurrently. A panic is no budget.
#[derive(Clone)]
pub struct ShapingBudget(pub Arc<dyn Fn() -> Budget + Send + Sync>);

impl ShapingBudget {
    /// The source of `f`.
    pub fn new(f: impl Fn() -> Budget + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// One session's budget.
    #[must_use]
    pub fn ask(&self) -> Budget {
        catch_unwind(AssertUnwindSafe(|| (self.0)())).unwrap_or_default()
    }
}

impl fmt::Debug for ShapingBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShapingBudget")
    }
}

/// A session's readings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Meters {
    /// What the account allows injections now; `u64::MAX` when it is not set.
    pub wire_left: u64,
    /// Reserved; `u64::MAX`.
    pub stall_left: u64,
    /// All wire bytes shaping added.
    pub wire_spent: u64,
    /// The waits applied, microseconds.
    pub stall_spent: u64,
    /// The bytes this endpoint sent of its own: no padding, injections or copies.
    pub sent_bytes: u64,
}

impl Meters {
    /// Readings of the given values, `stall_spent` 0.
    #[must_use]
    pub const fn new(wire_left: u64, stall_left: u64, wire_spent: u64, sent_bytes: u64) -> Self {
        Self {
            wire_left,
            stall_left,
            wire_spent,
            stall_spent: 0,
            sent_bytes,
        }
    }
}

/// `s` bytes in parts per million of `e`; `u64::MAX` when `e` is 0. From 2^44 on both lose
/// their low 20 bits.
#[must_use]
pub const fn wire_ppm(mut s: u64, mut e: u64) -> u64 {
    if s >= 1 << 44 || e >= 1 << 44 {
        s >>= 20;
        e >>= 20;
    }
    if e == 0 {
        return u64::MAX;
    }
    s * 1_000_000 / e
}

/// The rate in force for `rate` under a bound of `max_delay` microseconds on one wait
/// (`None`: no bound, so no lower rate), and whether it was raised. Rate 0 is no gate.
#[must_use]
pub const fn rate_floor(rate: u64, max_delay: Option<u64>) -> (u64, bool) {
    let Some(md) = max_delay else {
        return (rate, false);
    };
    if rate == 0 {
        return (0, false);
    }
    let md = if md == 0 { 1 } else { md };
    let floor = (MIN_MAX_LEN as u64 * 1_000_000).div_ceil(md);
    if rate < floor {
        (floor, true)
    } else {
        (rate, false)
    }
}

/// The burst in force for `burst` with records up to `record_max`, and whether it was raised:
/// 0 is the record limit, at least [`MIN_MAX_LEN`], not counted; a smaller burst is raised.
#[must_use]
pub const fn burst_floor(burst: u64, record_max: u64) -> (u64, bool) {
    let least = MIN_MAX_LEN as u64;
    if burst == 0 {
        return (
            if record_max > least {
                record_max
            } else {
                least
            },
            false,
        );
    }
    if burst < least {
        return (least, true);
    }
    (if burst > 1 << 53 { 1 << 53 } else { burst }, false)
}

/// Counters over a session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Wire bytes added: padding, splits, handshakes, injections.
    pub wire_spent: u64,
    /// Waits applied.
    pub stall_spent: Duration,
    /// Decisions reduced by a structural limit, the bound on one wait or a switch.
    pub clamped: u64,
    /// Records of PADDING only sent.
    pub injected: u64,
    /// Injections not sent.
    pub inject_dropped: u64,
    /// Calls that panicked, of a handshake shaper on a Join too.
    pub faults: u64,
    /// Messages of a Join a handshake shaper had no plan for.
    pub handshake_unplanned: u64,
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
