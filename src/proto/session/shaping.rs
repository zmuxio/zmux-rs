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

    /// The longest certified wait for a compiled rate gate, including an
    /// indivisible STREAM preamble of up to `preamble` bytes.
    fn required_gate_wait(&self, preamble: u64) -> Duration {
        let _ = preamble;
        Duration::ZERO
    }

    /// Called before each outgoing record of the pipe ([`Caps::PLAN`]);
    /// `plan` starts at its default.
    fn plan(&mut self, view: &RecordView, plan: &mut RecordPlan) {
        let _ = (view, plan);
    }

    /// Plans the selected native datagram ([`Caps::DATAGRAM_PLAN`]).
    fn plan_datagram(&mut self, view: &DatagramView, plan: &mut DatagramPlan) {
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
    #[must_use]
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

    /// The longest certified wait for a compiled rate gate, including an
    /// indivisible STREAM preamble of up to `preamble` bytes.
    fn required_gate_wait(&self, preamble: u64) -> Duration {
        let _ = preamble;
        Duration::ZERO
    }
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
    /// [`EventKind::Outbound`] is delivered for new application data.
    pub const OUTBOUND: Self = Self(2);
    /// [`EventKind::StreamOpen`] and [`EventKind::StreamEnd`] are delivered.
    pub const STREAMS: Self = Self(4);
    /// [`RecordView::meters`] and [`Event::meters`] are filled.
    pub const BUDGET: Self = Self(8);
    /// [`Shaper::plan_datagram`] is called.
    pub const DATAGRAM_PLAN: Self = Self(16);
    /// Also deliver control-only [`EventKind::Outbound`] with [`Self::OUTBOUND`].
    pub const INCLUDE_CONTROL: Self = Self(32);

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

    /// One handshake's structural allowance after choosing its absolute target.
    #[must_use]
    pub fn handshake_room(&self, baseline: usize, physical_room: usize) -> usize {
        let basis = if self.pad_to == 0 { baseline } else { 0 };
        self.pad_for(basis)
            .saturating_sub(baseline)
            .min(physical_room)
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
        self.delay = self.delay.min(limits.max_added_delay());
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
    match catch_unwind(AssertUnwindSafe(|| shaper.0(view))) {
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
    let gap = gap.cast_unsigned();
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
    if gap.cast_unsigned() > room {
        room
    } else {
        gap.cast_unsigned()
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
    establish_hello_header_len(profile, handle) + message_len(stream, noise, overhead)
}

/// The header of an Establish Hello before its Noise message: `profile`
/// (one byte up to 7, else an escape and its varint), the mode byte, and a
/// 16-byte Handle when the Profile has one. The one definition of that
/// length; the secure carrier's codec builds the bytes.
#[must_use]
pub const fn establish_hello_header_len(profile: u64, handle: bool) -> usize {
    let wire_profile = if profile <= 7 {
        1
    } else {
        1 + varint_len(profile)
    };
    let handle = if handle { 16 } else { 0 };
    wire_profile + 1 + handle
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

/// The native datagram selected by this pipe's writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramView {
    /// The pipe.
    pub pipe: PipeId,
    /// Session time in microseconds.
    pub now: u64,
    /// Unpadded encoded bytes, including the channel's pipe ID when present.
    pub len: usize,
    /// Structural channel capacity.
    pub capacity: usize,
    /// Current channel room.
    pub room: usize,
    /// Whether the negotiated format and local limits allow padding.
    pub padding: bool,
    /// This is a replica of a previously dispatched original.
    pub replica: bool,
    /// The session's readings ([`Caps::BUDGET`]).
    pub meters: Meters,
}

impl DatagramView {
    /// A view with these sizes and time on the owner's clock.
    #[must_use]
    pub const fn new(pipe: PipeId, now: u64, len: usize, capacity: usize, room: usize) -> Self {
        Self {
            pipe,
            now,
            len,
            capacity,
            room,
            padding: false,
            replica: false,
            meters: Meters::new(0, 0, 0, 0),
        }
    }
}

/// A native datagram's optional changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramPlan {
    /// Padding and delay for this datagram.
    pub unit: UnitPlan,
    /// Changes to the local policy state.
    pub effects: Effects,
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
    /// The carrier accepted a complete qualifying outbound unit.
    Outbound,
    /// Cover was irreversibly committed with this layout.
    InjectionAccepted,
    /// A cover request was rejected before commit.
    InjectionRejected,
    /// The carrier returned the result of a committed cover dispatch.
    InjectionCarrierCompleted,
    /// A scheduled wake became due.
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

/// The representation of an outbound unit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnitKind {
    /// A reliable record.
    #[default]
    Record,
    /// An unreliable datagram on a carrier channel.
    NativeDatagram,
}

/// A reason an optional shaping decision was limited or a carrier did not accept it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeReason {
    /// The carrier or negotiated format lacks the optional capability.
    UnsupportedCapability,
    /// The profile or local delay cap shortened a plan.
    PolicyDeadline,
    /// The application deadline elapsed.
    ApplicationExpired,
    /// The policy instance was replaced before dispatch.
    StaleGeneration,
    /// The pending unit was cancelled.
    Cancelled,
    /// No structural room.
    ClippedRoom,
    /// Policy or peer disallows this operation.
    Disabled,
    /// The available cover balance is too small.
    InsufficientCoverCredit,
    /// The profile's byte ceiling would be exceeded.
    OverheadLimit,
    /// The protocol's no-effect limit was reached.
    RateLimit,
    /// The carrier accepted no bytes.
    CarrierRejected,
    /// The carrier accepted only a prefix.
    PartialProgress,
}

impl RuntimeReason {
    /// Number of defined reasons in the meters.
    pub const COUNT: usize = Self::PartialProgress as usize + 1;
}

/// A notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Event {
    /// What happened.
    pub kind: EventKind,
    /// The pipe.
    pub pipe: PipeId,
    /// The lane, zero for a native datagram.
    pub lane: u64,
    /// The session clock, microseconds.
    pub now: u64,
    /// Encoded unit length or actual cover bytes.
    pub len: usize,
    /// The representation of an outbound unit.
    pub unit: UnitKind,
    /// This unit contains original application data.
    pub data: bool,
    /// This unit contains eligible control frames.
    pub control: bool,
    /// The cover request identifier, for injection results.
    pub request_id: u64,
    /// Wire overhead charged to the cover request when accepted.
    pub wire_cost: usize,
    /// Reason for a refusal or incomplete write.
    pub reason: Option<RuntimeReason>,
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
            unit: UnitKind::Record,
            data: false,
            control: false,
            request_id: 0,
            wire_cost: 0,
            reason: None,
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

    /// With a length in bytes.
    #[must_use]
    pub const fn with_len(mut self, len: usize) -> Self {
        self.len = len;
        self
    }

    /// With stream ID `stream`.
    #[must_use]
    pub const fn with_stream(mut self, stream: u64) -> Self {
        self.stream = stream;
        self
    }
}

/// Changes to the pipe's bounded policy slots. A field of `None` keeps its
/// previous value. The core consumes a cover request or wake once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Effects {
    /// The pending injection, or none.
    pub inject: Option<Option<Injection>>,
    /// When to send [`EventKind::Timer`], or never.
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
    /// Identifies this request in acceptance and completion events.
    pub id: u64,
    /// When, on the session clock.
    pub at: u64,
    /// Requested PADDING bytes.
    pub pad_bytes: usize,
}

impl Injection {
    /// Requests `pad_bytes` at `at` with the supplied nonzero identifier.
    #[must_use]
    pub const fn new(id: u64, at: u64, pad_bytes: usize) -> Self {
        Self { id, at, pad_bytes }
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

/// The largest [`Account::initial`].
pub const MAX_ACCOUNT_INITIAL: u64 = 1 << 53;

/// The largest [`Account::per_mb`] and [`Account::per_sec`], and the largest rate of a [`Gate`].
pub const MAX_ACCOUNT_RATE: u64 = 1 << 43;

/// An allowance for injections, in bytes on the carrier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Account {
    /// Maximum balance. Zero disables the account.
    pub ceiling: u64,
    /// Balance the first time a positive ceiling is configured.
    pub initial: u64,
    /// Added per million carrier-confirmed own bytes.
    pub per_mb: u64,
    /// Added per second.
    pub per_sec: u64,
}

impl Account {
    /// An account of the given values.
    #[must_use]
    pub const fn new(ceiling: u64, initial: u64, per_mb: u64, per_sec: u64) -> Self {
        Self {
            ceiling,
            initial,
            per_mb,
            per_sec,
        }
    }

    fn validate(self) -> Result<(), crate::InvalidConfig> {
        if self.ceiling > MAX_ACCOUNT_INITIAL
            || self.initial > self.ceiling
            || self.per_mb > MAX_ACCOUNT_RATE
            || self.per_sec > MAX_ACCOUNT_RATE
        {
            return Err(crate::InvalidConfig::new(
                "shaping wire account",
                "invalid ceiling, initial, or refill rate",
            ));
        }
        Ok(())
    }

    fn under(self, other: Self) -> Self {
        Self::new(
            self.ceiling.min(other.ceiling),
            self.initial.min(other.initial),
            self.per_mb.min(other.per_mb),
            self.per_sec.min(other.per_sec),
        )
    }
}

/// Hard deployment limits at the zmux handoff boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProfileLimits {
    /// Number of one-second buckets in the sliding window.
    pub window_seconds: u32,
    /// Extra bytes per million proved baseline bytes.
    pub extra_bytes_ppm: u32,
    /// Absolute allowance per direction and window.
    pub floor_bytes: u64,
    /// Maximum additional local wait of a unit.
    pub max_added_delay: Duration,
}

impl ProfileLimits {
    /// The default hard limits of an enabled policy.
    pub const LIGHTWEIGHT: Self = Self::new(10, 50_000, 540, Duration::from_micros(2000));

    /// Hard limits of the given values.
    #[must_use]
    pub const fn new(
        window_seconds: u32,
        extra_bytes_ppm: u32,
        floor_bytes: u64,
        max_added_delay: Duration,
    ) -> Self {
        Self {
            window_seconds,
            extra_bytes_ppm,
            floor_bytes,
            max_added_delay,
        }
    }

    fn validate(self) -> Result<(), crate::InvalidConfig> {
        if self.window_seconds == 0
            || self.extra_bytes_ppm > 1_000_000
            || self.floor_bytes > MAX_ACCOUNT_INITIAL
            || self.max_added_delay > Duration::from_secs(1_000_000_000)
            || !self.max_added_delay.subsec_nanos().is_multiple_of(1000)
        {
            return Err(crate::InvalidConfig::new(
                "shaping profile",
                "invalid window, ratio, floor or delay",
            ));
        }
        Ok(())
    }

    /// Extra bytes allowed for the proved baseline in this window.
    #[must_use]
    pub fn allowance(self, baseline: u64) -> u64 {
        let ratio = u128::from(baseline) * u128::from(self.extra_bytes_ppm) / 1_000_000;
        self.floor_bytes
            .max(u64::try_from(ratio).unwrap_or(u64::MAX))
    }
}

/// Local session bounds. The peer never receives them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// A cap on a policy's cover grant.
    pub wire: Option<Account>,
    /// A local profile cap, or the policy profile on effective limits.
    pub profile: Option<ProfileLimits>,
    pub(super) local_profile: Option<ProfileLimits>,
    /// Disable all padding.
    pub no_padding: bool,
    /// Disable shaping delays.
    pub no_pause: bool,
    /// Disable cover injection.
    pub no_injection: bool,
}

impl Limits {
    /// Checks all configured bounds before they take effect.
    pub fn validate(&self) -> Result<(), crate::InvalidConfig> {
        Budget {
            wire: self.wire,
            profile: self.profile,
            ..Budget::default()
        }
        .validate()
    }

    /// Effective profile windows, with the policy first.
    pub fn profiles(&self) -> impl Iterator<Item = ProfileLimits> + use<> {
        [self.profile, self.local_profile].into_iter().flatten()
    }

    /// Effective per-unit delay limit.
    #[must_use]
    pub fn max_added_delay(&self) -> Duration {
        if self.no_pause {
            return Duration::ZERO;
        }
        self.profiles()
            .map(|p| p.max_added_delay)
            .min()
            .unwrap_or(ProfileLimits::LIGHTWEIGHT.max_added_delay)
    }

    /// Applies the enabled policy and the independent local cap.
    #[must_use]
    pub fn under(mut self, budget: &Budget) -> Self {
        self.wire = budget
            .wire
            .map(|grant| self.wire.map_or(grant, |cap| grant.under(cap)));
        self.local_profile = self.profile;
        self.profile = Some(budget.profile.unwrap_or(ProfileLimits::LIGHTWEIGHT));
        self.no_injection |= budget.no_injection;
        self
    }
}

/// What an enabled shaping configuration allows for a session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Budget {
    /// Cover grant, if configured.
    pub wire: Option<Account>,
    /// Hard deployment limits. Absent selects Lightweight.
    pub profile: Option<ProfileLimits>,
    /// Disable cover injection.
    pub no_injection: bool,
}

impl Budget {
    /// A budget of the given values.
    #[must_use]
    pub const fn new(
        wire: Option<Account>,
        profile: Option<ProfileLimits>,
        no_injection: bool,
    ) -> Self {
        Self {
            wire,
            profile,
            no_injection,
        }
    }

    /// Checks all configured bounds before they take effect.
    pub fn validate(&self) -> Result<(), crate::InvalidConfig> {
        if let Some(account) = self.wire {
            account.validate()?;
        }
        if let Some(profile) = self.profile {
            profile.validate()?;
        }
        Ok(())
    }
}

/// One completed outbound Establish unit at the handoff boundary.
#[derive(Debug, Clone, Copy)]
pub struct EstablishReceipt {
    /// Dispatch instant on the carrier's clock.
    pub at: std::time::Instant,
    /// Encoded unpadded bytes accepted.
    pub baseline: u64,
    /// Structural allowance for this unit alone.
    pub allowance: u64,
    /// Encoded padding bytes accepted.
    pub extra: u64,
    /// Shaping-induced wait before dispatch.
    pub delay: Duration,
}

/// The initiator writes at most two Establish messages.
pub type EstablishReceipts = [Option<EstablishReceipt>; 2];

/// An immutable outbound Join layout and its settlement identity.
#[derive(Debug)]
pub struct JoinUnit {
    bytes: Vec<u8>,
    pub(super) dispatch: Option<JoinDispatch>,
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(super) handoffs: Vec<super::splice_handoff::HandoffSpan>,
}

#[derive(Debug)]
pub(super) struct JoinDispatch {
    pub(super) at: u64,
    pub(super) extra_at: usize,
    pub(super) extra: usize,
}

impl JoinUnit {
    pub(super) fn new(bytes: Vec<u8>, dispatch: JoinDispatch) -> Self {
        Self {
            bytes,
            dispatch: Some(dispatch),
            #[cfg(all(feature = "tokio", not(loom)))]
            handoffs: Vec::new(),
        }
    }

    /// The immutable encoded unit to hand to the carrier.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::ops::Deref for JoinUnit {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}

/// The byte costs observed at the default handoff boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CostPrecision {
    /// Confirmed progress can be attributed to the final layout.
    #[default]
    Exact,
    /// A live window contains unidentified terminal progress.
    Unavailable,
}

/// The boundary used to price baseline and shaped output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ObservationBoundary {
    /// Encoded zmux units at the adapter handoff.
    #[default]
    ZmuxHandoff,
}

/// Meter readings for one effective admission window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowStats {
    pub profile: ProfileLimits,
    pub baseline_bytes: u64,
    pub allowance_bytes: u64,
    pub consumed_bytes: u64,
    pub reserved_bytes: u64,
    pub history_complete: bool,
}

/// Send-direction ledger readings at the observation boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LedgerStats {
    pub boundary: ObservationBoundary,
    pub precision: CostPrecision,
    pub policy: Option<WindowStats>,
    pub local: Option<WindowStats>,
    pub measured_bytes: u64,
    pub baseline_bytes: u64,
}

/// Gives the budget of a session: called once per session, outside every lock; it may be
/// called concurrently. A panic rejects the installation.
#[derive(Clone)]
pub struct ShapingBudget(pub Arc<dyn Fn() -> Budget + Send + Sync>);

impl ShapingBudget {
    /// The source of `f`.
    pub fn new(f: impl Fn() -> Budget + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Resolves one session's budget.
    ///
    /// # Errors
    ///
    /// The source panicked while sampling the policy.
    pub fn ask(&self) -> Result<Budget, crate::InvalidConfig> {
        catch_unwind(AssertUnwindSafe(|| self.0()))
            .map_err(|_| crate::InvalidConfig::new("shaping budget", "budget source panicked"))
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
    /// What the account allows injections now.
    pub wire_left: u64,
    /// Reserved; `u64::MAX`.
    pub stall_left: u64,
    /// All wire bytes shaping added.
    pub wire_spent: u64,
    /// The waits applied, microseconds.
    pub stall_spent: u64,
    /// The bytes this endpoint sent of its own: no padding, injections or copies.
    pub earned_bytes: u64,
}

impl Meters {
    /// Readings of the given values, `stall_spent` 0.
    #[must_use]
    pub const fn new(wire_left: u64, stall_left: u64, wire_spent: u64, earned_bytes: u64) -> Self {
        Self {
            wire_left,
            stall_left,
            wire_spent,
            stall_spent: 0,
            earned_bytes,
        }
    }
}

/// Cover account debits as parts per million of confirmed own bytes.
#[must_use]
pub fn wire_ppm(spent: u64, earned: u64) -> u64 {
    if spent == 0 {
        return 0;
    }
    if earned == 0 {
        return u64::MAX;
    }
    let ratio = u128::from(spent) * 1_000_000 / u128::from(earned);
    u64::try_from(ratio).unwrap_or(u64::MAX)
}

/// Worst required recovery after draining the bucket or an indivisible prefix.
#[must_use]
pub fn gate_wait(rate: u64, burst: u64, preamble: u64) -> Duration {
    if rate == 0 {
        return Duration::ZERO;
    }
    let quantum = (MIN_MAX_LEN as u64).max(burst.min(rate / 1000));
    let micros = (u128::from(quantum.max(preamble)) * 1_000_000).div_ceil(u128::from(rate));
    Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
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
    /// Current session policy generation.
    pub generation: u64,
    /// Cumulative cover account debits.
    pub wire_spent: u64,
    /// Waits applied.
    pub stall_spent: Duration,
    /// Longest additional local wait applied.
    pub max_added_delay: Duration,
    /// Decisions reduced by a structural limit, the bound on one wait or a switch.
    pub clamped: u64,
    /// PADDING bytes committed as cover, merged and independent.
    pub injection_accepted_bytes: u64,
    /// Committed cover PADDING bytes confirmed by the carrier.
    pub injection_sent_bytes: u64,
    /// Cover requests committed.
    pub injection_accepted_requests: u64,
    /// Cover requests rejected before commit.
    pub injection_rejected: u64,
    /// Causes of cover rejection.
    pub injection_rejected_by_reason: [u64; RuntimeReason::COUNT],
    /// Observed clipping and failure reasons.
    pub runtime_reasons: [u64; RuntimeReason::COUNT],
    /// The direction's ongoing overhead.
    pub ledger: LedgerStats,
    /// Structural handshake padding proved accepted.
    pub handshake_measured_bytes: u64,
    /// Structural handshake padding awaiting a terminal result.
    pub handshake_reserved_bytes: u64,
    /// Structural handshake padding of unknown terminal progress.
    pub handshake_unresolved_bytes: u64,
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
