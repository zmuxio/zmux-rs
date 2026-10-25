//! Typed model of the conformance assets: frame objects (TRACES.md Section
//! 6), profiles (Section 3) and trace files (Sections 4 and 5).
//!
//! Every struct rejects unknown fields so that a change of the trace format
//! fails loudly here instead of being ignored by the runner. The trace runner
//! of the sans-IO core reads the fields that only these tests parse today.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer};

/// A lowercase hex byte string.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Hex(pub Vec<u8>);

impl fmt::Debug for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::support::to_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        crate::support::from_hex(&s)
            .map(Hex)
            .ok_or_else(|| de::Error::custom(format!("invalid hex {s:?}")))
    }
}

/// An integer field of a `peer_send` frame, possibly a `$sent` placeholder
/// (Section 6.1).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Int {
    /// A literal value.
    Value(u64),
    /// Bytes sent on a pipe so far, plus an offset.
    Sent(SentPlaceholder),
}

/// `{"$sent": pipe, "lane": l, "plus": n}` (TRACES.md Section 6.1).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SentPlaceholder {
    #[serde(rename = "$sent")]
    pub pipe: u64,
    #[serde(default)]
    pub lane: u64,
    #[serde(default)]
    pub plus: u64,
}

/// A transport parameter ID: a registry name or a number.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ParamId {
    Name(String),
    Number(u64),
}

/// The value of a transport parameter in its registry format.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ParamValue {
    Int(u64),
    Role(RoleValue),
    Multipath(MultipathValue),
    Lanes(LanesValue),
}

/// `{"max_lanes": n, "lane_key": hex}` (TRACES.md Section 3).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LanesValue {
    pub max_lanes: u64,
    pub lane_key: Hex,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleValue {
    pub role: RoleName,
    pub nonce: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoleName {
    Initiator,
    Responder,
    Auto,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MultipathValue {
    pub flags: u8,
    pub nonce: Hex,
    pub locator: Hex,
}

/// One entry of a QX_TRANSPORT_PARAMETERS `params` list.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    pub id: ParamId,
    /// The value; `null` (or absent) for empty parameters.
    #[serde(default)]
    pub value: Option<ParamValue>,
    /// Raw value bytes, for unknown and GREASE parameters.
    pub raw: Option<Hex>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JoinDirectionName {
    Up,
    Down,
    Bidi,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PipeStatusName {
    Available,
    Standby,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AckEntrySpec {
    pub pipe: u64,
    pub lane: u64,
    pub position: Int,
    pub delay: u64,
}

fn yes() -> bool {
    true
}

/// A concrete frame object (TRACES.md Section 6), as the wire corpus, the
/// wire examples and `peer_send` steps use it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum FrameSpec {
    Padding {
        count: usize,
    },
    Stream {
        id: u64,
        off: u64,
        data: Hex,
        fin: bool,
        has_off: Option<bool>,
        has_len: Option<bool>,
    },
    ResetStream {
        id: u64,
        code: u64,
        final_size: u64,
    },
    ResetStreamAt {
        id: u64,
        code: u64,
        final_size: u64,
        reliable_size: u64,
    },
    StopSending {
        id: u64,
        code: u64,
    },
    MaxData {
        max: u64,
    },
    MaxStreamData {
        id: u64,
        max: u64,
    },
    MaxStreams {
        bidi: bool,
        max: u64,
    },
    DataBlocked {
        limit: u64,
    },
    StreamDataBlocked {
        id: u64,
        limit: u64,
    },
    StreamsBlocked {
        bidi: bool,
        limit: u64,
    },
    ConnectionClose {
        app: bool,
        code: u64,
        frame_type: Option<u64>,
        #[serde(default)]
        reason: Hex,
    },
    Datagram {
        data: Hex,
        #[serde(default = "yes")]
        has_len: bool,
    },
    QxTransportParameters {
        params: Vec<ParamSpec>,
    },
    QxPing {
        response: bool,
        seq: u64,
    },
    Goaway {
        max_bidi: u64,
        max_uni: u64,
        code: u64,
    },
    PriorityUpdate {
        id: u64,
        seq: u64,
        urgency: u8,
        incremental: bool,
    },
    PipeJoin {
        locator: Hex,
        pipe: u64,
        direction: JoinDirectionName,
        carrier_bound: bool,
        standby: bool,
        fate_group: u64,
        priority: u64,
        token: Hex,
    },
    PipeAck {
        entries: Vec<AckEntrySpec>,
    },
    PipeLane {
        lane_key: Hex,
        pipe: u64,
        lane: u64,
    },
    PipePing,
    PipeAbandon {
        pipe: u64,
        code: u64,
    },
    PipeStatus {
        pipe: u64,
        seq: u64,
        status: PipeStatusName,
        priority: u64,
    },
    Raw {
        bytes: Hex,
    },
    Repeat {
        count: usize,
        frame: Box<FrameSpec>,
    },
}

impl FrameSpec {
    /// Whether the frame (or a frame it repeats) is RAW bytes.
    pub fn has_raw(&self) -> bool {
        match self {
            Self::Raw { .. } => true,
            Self::Repeat { frame, .. } => frame.has_raw(),
            _ => false,
        }
    }

    /// Whether the frame contains a `$sent` placeholder.
    pub fn has_placeholder(&self) -> bool {
        match self {
            Self::PipeAck { entries } => entries.iter().any(|e| matches!(e.position, Int::Sent(_))),
            Self::Repeat { frame, .. } => frame.has_placeholder(),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Profiles

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub tp: BTreeMap<String, Option<ParamValue>>,
    pub config: Config,
    pub test: TestHooks,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub keep_alive_period: Option<u64>,
    pub handshake_timeout: Option<u64>,
    pub enable_datagrams: Option<bool>,
    pub role: Option<RoleName>,
    pub max_pipes: Option<u32>,
    pub scheduler: Option<String>,
    pub pipe_auth: Option<PipeAuth>,
    pub resume_timeout: Option<u64>,
    /// Absent: not set by this entry; `null`: unset (staged credit).
    #[serde(default, deserialize_with = "present")]
    pub max_incoming_uni_streams: Option<Option<u64>>,
    pub suspect_floor: Option<u64>,
    pub dead_timeout: Option<u64>,
    /// Absent: the profile's; `null`: the formula; 0 disables probation.
    #[serde(default, deserialize_with = "present")]
    pub probation: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub overflow_delay: Option<Option<u64>>,
    /// `urgent` or `off`.
    pub redundancy: Option<String>,
    /// Milliseconds; 0 is the 15 s probe interval.
    pub standby_probe: Option<u64>,
    /// The `early_data` configuration.
    pub early_data: Option<EarlyData>,
}

/// The `early_data` knob: absent fields are false.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EarlyData {
    #[serde(default)]
    pub zmux_peer: bool,
    #[serde(default)]
    pub replayable: bool,
}

/// Distinguishes a field that is present with `null` (`Some(None)`) from an
/// absent one (`None`, through `default`).
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipeAuth {
    pub psk: Option<Hex>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestHooks {
    pub grease_tp: Option<GreaseParam>,
    pub grease_tlv: Option<GreaseTlv>,
    pub session_nonce: Option<Hex>,
    pub role_nonce: Option<u64>,
    pub ping_seq_start: Option<u64>,
    pub rtt_ms: Option<u64>,
    pub pipe_rtt_ms: Option<BTreeMap<String, u64>>,
    pub pipe_cap: Option<u64>,
    pub lane_key: Option<Hex>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GreaseParam {
    pub id: u64,
    pub value: Hex,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GreaseTlv {
    #[serde(rename = "type")]
    pub ty: u64,
    pub value: Hex,
}

// ---------------------------------------------------------------------------
// Traces

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub kind: HeaderKind,
    pub id: String,
    pub title: String,
    pub profile: String,
    pub local_role: TransportRole,
    pub overrides: Overrides,
    pub refs: Vec<String>,
    pub findings: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeaderKind {
    Trace,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    #[serde(default)]
    pub tp: BTreeMap<String, Option<ParamValue>>,
    #[serde(default)]
    pub config: Config,
    #[serde(default)]
    pub test: TestHooks,
}

/// One trace file: its header and steps.
#[derive(Debug, Clone)]
pub struct Trace {
    pub header: Header,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone)]
pub struct Step {
    pub number: u32,
    pub op: Op,
    /// The step as written, for comparisons with decoded frames.
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    In,
    Out,
    Bidi,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    Bootstrap,
    Listener,
    /// A new stream that the peer opened on connection `conn` (TRACES.md
    /// Section 5.1.1).
    Lane,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FramingName {
    Bytes,
    Records,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DownHow {
    Eof,
    Error,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClosedHow {
    Graceful,
    Abort,
    Any,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    Exact,
    Contains,
    Unordered,
    First,
}

/// A pipe ID or `"*"` for every outbound pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeSelector {
    Id(u64),
    All,
}

impl<'de> Deserialize<'de> for PipeSelector {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Id(u64),
            Star(String),
        }
        match Raw::deserialize(d)? {
            Raw::Id(id) => Ok(Self::Id(id)),
            Raw::Star(s) if s == "*" => Ok(Self::All),
            Raw::Star(s) => Err(de::Error::custom(format!("bad pipe selector {s:?}"))),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    PipeUp {
        pipe: Option<u64>,
        carrier: Option<String>,
        dir: Direction,
        via: Option<Via>,
        conn: Option<String>,
        oob_join: Option<Hex>,
        carrier_binding: Option<Hex>,
        pairing: Option<Hex>,
        framing: Option<FramingName>,
        source: Option<String>,
    },
    PipeDown {
        pipe: Option<u64>,
        carrier: Option<String>,
        lane: Option<u64>,
        dir: Direction,
        how: DownHow,
    },
    SetWritable {
        pipe: u64,
        writable: bool,
    },
    PeerSend {
        pipe: Option<u64>,
        carrier: Option<String>,
        records: Option<Vec<Vec<FrameSpec>>>,
        hex: Option<Hex>,
        messages: Option<Vec<Vec<FrameSpec>>>,
        messages_hex: Option<Vec<Hex>>,
        chunks: Option<Vec<usize>>,
        #[serde(default)]
        invalid: bool,
    },
    #[serde(skip)]
    Api(ApiStep),
    ExpectFrames {
        pipe: PipeSelector,
        lane: Option<u64>,
        frames: Vec<FramePattern>,
        #[serde(rename = "match")]
        mode: MatchMode,
        #[serde(default)]
        one_credit_per_record: bool,
    },
    ExpectNoFrames {
        pipe: PipeSelector,
        lane: Option<u64>,
        types: Option<Vec<String>>,
    },
    ExpectClose {
        error: CloseSpec,
        wire: Option<bool>,
    },
    ExpectOpen,
    ExpectState {
        session: Option<SessionState>,
        pipe: Option<u64>,
        dir: Option<Direction>,
        state: Option<StatePattern>,
    },
    ExpectEvent {
        event: EventName,
        fields: EventFields,
    },
    ExpectNoEvent {
        event: EventName,
    },
    ExpectPipeClosed {
        pipe: u64,
        lane: Option<u64>,
        dir: Direction,
        how: ClosedHow,
    },
    ExpectRejectCarrier {
        carrier: String,
    },
    Advance {
        ms: u64,
    },
    Note {
        text: String,
    },
}

/// An `api` step (Section 5.3).
#[derive(Debug, Clone)]
pub struct ApiStep {
    pub call: Call,
    pub bind: Option<String>,
    pub expect: Option<ApiExpect>,
}

/// A stream handle name bound by an earlier step, or a stream ID.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StreamRef {
    Id(u64),
    Handle(String),
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrioritySpec {
    pub urgency: u8,
    pub incremental: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Fill {
    pub len: usize,
    pub byte: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "call",
    content = "args",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Call {
    OpenBidi(OpenArgs),
    OpenUni(OpenArgs),
    AcceptBidi(NoArgs),
    AcceptUni(NoArgs),
    Write(WriteArgs),
    StreamId(StreamArgs),
    SetReliableBoundary(StreamArgs),
    Finish(StreamArgs),
    Reset(CodeArgs),
    Stop(CodeArgs),
    Read(ReadArgs),
    Release(StreamArgs),
    Reject(StreamArgs),
    SetPriority(PriorityArgs),
    SetPeerPriority(PriorityArgs),
    SendDatagram(SendDatagramArgs),
    RecvDatagram(RecvDatagramArgs),
    Ping(NoArgs),
    Shutdown(ShutdownArgs),
    Close(CloseArgs),
    AddPipe(AddPipeArgs),
    RemovePipe(RemovePipeArgs),
    SetPipeStatus(PipeStatusArgs),
    SetScheduler(SchedulerArgs),
    SetRedundant(RedundantArgs),
    RevalidatePipes(RevalidateArgs),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenArgs {
    pub open_info: Option<Hex>,
    pub priority: Option<PrioritySpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteArgs {
    pub stream: StreamRef,
    pub data: Option<Hex>,
    pub fill: Option<Fill>,
    #[serde(default)]
    pub fin: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamArgs {
    pub stream: StreamRef,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeArgs {
    pub stream: StreamRef,
    pub code: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    pub stream: StreamRef,
    pub max: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityArgs {
    pub stream: StreamRef,
    pub urgency: u8,
    pub incremental: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendDatagramArgs {
    pub data: Hex,
    pub stream: Option<StreamRef>,
    pub context: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecvDatagramArgs {
    pub stream: Option<StreamRef>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownArgs {
    pub code: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseArgs {
    pub code: u64,
    pub reason: Hex,
    pub app: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddPipeArgs {
    pub pipe: u64,
    pub dir: Direction,
    pub fate_group: u64,
    #[serde(default)]
    pub oob: bool,
    #[serde(default)]
    pub carrier_bound: bool,
    pub send_priority: Option<u64>,
    pub receive_priority: Option<u64>,
    pub send_standby: Option<bool>,
    pub receive_standby: Option<bool>,
    /// Both directions (older fixtures).
    pub standby: Option<bool>,
    pub weight: Option<u64>,
    pub probation: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovePipeArgs {
    pub pipe: u64,
    pub graceful: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipeStatusArgs {
    pub pipe: u64,
    /// Absent: unchanged; `null`: cleared (back to the peer's request).
    #[serde(default, deserialize_with = "present")]
    pub send_priority: Option<Option<u64>>,
    pub receive_priority: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    pub send_standby: Option<Option<bool>>,
    pub receive_standby: Option<bool>,
    /// Both directions (older fixtures).
    pub standby: Option<bool>,
    pub weight: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerArgs {
    pub policy: String,
    pub stream: Option<StreamRef>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedundantArgs {
    pub stream: StreamRef,
    pub redundant: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidateArgs {
    pub pipe: Option<u64>,
}

/// The expected result of an API call (Section 5.5); absent fields match
/// anything.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiExpect {
    pub ok: Option<bool>,
    pub pending: Option<bool>,
    pub stream: Option<u64>,
    pub open_info: Option<Hex>,
    pub priority: Option<PrioritySpec>,
    pub pipe_carrier: Option<bool>,
    /// The application TLVs in the order received (EXTENSIONS.md 4.4).
    pub app_tlvs: Option<Vec<AppTlvSpec>>,
    pub accepted: Option<u64>,
    pub data: Option<Hex>,
    pub fin: Option<bool>,
    pub context: Option<u64>,
    pub error: Option<ErrorSpec>,
}

/// One application TLV of an accept result.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppTlvSpec {
    #[serde(rename = "type")]
    pub ty: u64,
    pub value: Hex,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    StreamReset,
    StreamStopped,
    StreamRejected,
    ClosedLocally,
    GoingAway,
    TooLarge,
    Unsupported,
    Session,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSpace {
    Transport,
    Application,
    Local,
}

/// An error code: a number, or a registry or local-reason name.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CodeRef {
    Value(u64),
    Name(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorSpec {
    pub kind: ErrorKind,
    pub space: Option<ErrorSpace>,
    pub code: Option<CodeRef>,
    pub remote: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseSpec {
    pub space: ErrorSpace,
    pub code: CodeRef,
    pub remote: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Establishing,
    Active,
    Draining,
    Suspended,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PipeState {
    Joining,
    Active,
    Suspect,
    Draining,
    Failed,
    Closed,
    Retired,
    Open,
    Ended,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StatePattern {
    One(PipeState),
    OneOf(OneOf<PipeState>),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OneOf<T> {
    pub oneof: Vec<T>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventName {
    Established,
    OobJoin,
    GoawayReceived,
    PipeState,
    JoinAuthFailed,
    Suspended,
    Resumed,
    DatagramDropped,
    Closed,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Role,
    Goaway,
    Preamble,
    Priority,
    DatagramFlows,
    Multipath,
    PipeAck,
    Resume,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailure {
    Mac,
    MacCarrierBound,
}

/// The fields of an expected event (Section 5.7); absent fields match
/// anything.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventFields {
    pub role: Option<TransportRole>,
    pub features: Option<Vec<Feature>>,
    pub pipe: Option<u64>,
    pub frame: Option<Hex>,
    pub max_bidi: Option<u64>,
    pub max_uni: Option<u64>,
    pub code: Option<u64>,
    pub dir: Option<Direction>,
    pub state: Option<StatePattern>,
    pub reason: Option<AuthFailure>,
    pub count: Option<u64>,
    pub error: Option<CloseSpec>,
}

/// The `type` of a frame pattern: a name, `{"oneof": [...]}` or `"*"`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TypePattern {
    Name(String),
    OneOf(OneOf<String>),
}

/// A field pattern (Section 5.6).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ValuePattern {
    /// An exact integer.
    Int(u64),
    /// An exact boolean.
    Bool(bool),
    /// `"*"`, an exact hex byte string, or a name (`"up"`, `"backup"`).
    Text(String),
    /// `{"min": a, "max": b}`.
    Range(Range),
    /// `{"len": n}` for byte fields.
    Len(LenPattern),
    /// `{"prefix": hex}` for byte fields.
    Prefix(PrefixPattern),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub min: Option<u64>,
    pub max: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LenPattern {
    pub len: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrefixPattern {
    pub prefix: Hex,
}

/// A PIPE_ACK entry pattern.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntryPattern {
    pub pipe: Option<ValuePattern>,
    pub lane: Option<ValuePattern>,
    pub position: Option<ValuePattern>,
    pub delay: Option<ValuePattern>,
}

/// A frame pattern of `expect_frames` (Section 5.6).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FramePattern {
    #[serde(rename = "type")]
    pub ty: TypePattern,
    pub count: Option<ValuePattern>,
    pub id: Option<ValuePattern>,
    pub off: Option<ValuePattern>,
    pub data: Option<ValuePattern>,
    pub fin: Option<ValuePattern>,
    pub has_off: Option<ValuePattern>,
    pub has_len: Option<ValuePattern>,
    pub code: Option<ValuePattern>,
    pub final_size: Option<ValuePattern>,
    pub reliable_size: Option<ValuePattern>,
    pub max: Option<ValuePattern>,
    pub bidi: Option<ValuePattern>,
    pub limit: Option<ValuePattern>,
    pub app: Option<ValuePattern>,
    pub frame_type: Option<ValuePattern>,
    pub reason: Option<ValuePattern>,
    pub response: Option<ValuePattern>,
    pub seq: Option<ValuePattern>,
    pub max_bidi: Option<ValuePattern>,
    pub max_uni: Option<ValuePattern>,
    pub urgency: Option<ValuePattern>,
    pub incremental: Option<ValuePattern>,
    pub locator: Option<ValuePattern>,
    pub pipe: Option<ValuePattern>,
    pub direction: Option<ValuePattern>,
    pub carrier_bound: Option<ValuePattern>,
    pub standby: Option<ValuePattern>,
    pub fate_group: Option<ValuePattern>,
    pub token: Option<ValuePattern>,
    pub lane_key: Option<ValuePattern>,
    pub lane: Option<ValuePattern>,
    pub entries: Option<Vec<EntryPattern>>,
    pub status: Option<ValuePattern>,
    pub priority: Option<ValuePattern>,
    pub params_include: Option<BTreeMap<String, ParamPattern>>,
    pub params_exclude: Option<Vec<String>>,
    pub grease: Option<bool>,
}

/// An expected parameter value in `params_include`: `"*"`, `null` for an
/// empty parameter, or a value.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ParamPattern {
    Any(String),
    Value(Option<ParamValue>),
}

/// Parses a trace file.
pub fn parse_trace(text: &str) -> Result<Trace, String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next().ok_or("empty trace")?;
    let header: Header = serde_json::from_str(first).map_err(|e| format!("header: {e}"))?;
    let mut steps = Vec::new();
    for (i, line) in lines.enumerate() {
        let mut v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 2))?;
        let raw = v.clone();
        let obj = v
            .as_object_mut()
            .ok_or_else(|| format!("line {}: not an object", i + 2))?;
        let number = obj
            .remove("step")
            .and_then(|s| s.as_u64())
            .and_then(|s| u32::try_from(s).ok())
            .ok_or_else(|| format!("line {}: missing step number", i + 2))?;
        let op = if obj.get("op").and_then(|o| o.as_str()) == Some("api") {
            obj.remove("op");
            let bind = match obj.remove("bind") {
                Some(b) => {
                    Some(serde_json::from_value(b).map_err(|e| format!("step {number}: {e}"))?)
                }
                None => None,
            };
            let expect = match obj.remove("expect") {
                Some(e) => {
                    Some(serde_json::from_value(e).map_err(|e| format!("step {number}: {e}"))?)
                }
                None => None,
            };
            let call: Call =
                serde_json::from_value(v).map_err(|e| format!("step {number}: {e}"))?;
            Op::Api(ApiStep { call, bind, expect })
        } else {
            serde_json::from_value(v).map_err(|e| format!("step {number}: {e}"))?
        };
        steps.push(Step { number, op, raw });
    }
    Ok(Trace { header, steps })
}
