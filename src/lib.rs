//! Rust implementation of the ZMux v1 stream multiplexing protocol.
//!
//! The crate exposes public codec helpers for the normative wire format, a
//! synchronous native session/stream runtime built on split `Read` / `Write`
//! halves, and explicit `Async*` traits for runtime-neutral adapters.

#![forbid(unsafe_code)]

mod api;
mod async_api;
mod config;
mod conformance;
mod error;
mod event;
mod frame;
mod io_adapters;
mod open_send;
mod payload;
mod preface;
mod protocol;
mod session;
mod settings;
mod stream_id;
mod tlv;
mod varint;

pub use api::{
    box_session, closed_session, join_streams, BoxDuplexStream, BoxRecvStream, BoxSendStream,
    BoxSession, ClosedSession, DuplexInfoSide, DuplexStream, DuplexStreamHandle,
    PausedNativeHalf as PausedHalf, PausedNativeRecvHalf as PausedRecvHalf,
    PausedNativeSendHalf as PausedSendHalf, RecvStreamHandle, SendStreamHandle, Session,
    StreamHandle,
};
pub use async_api::{
    box_async_session, closed_async_session, join_async_streams, AsyncBoxFuture, AsyncDuplexStream,
    AsyncDuplexStreamHandle, AsyncRecvStreamHandle, AsyncSendStreamHandle, AsyncSession,
    AsyncStreamHandle, BoxAsyncDuplexStream, BoxAsyncRecvStream, BoxAsyncSendStream,
    BoxAsyncSession, ClosedAsyncSession, PausedAsyncHalf, PausedAsyncRecvHalf, PausedAsyncSendHalf,
};
pub use config::{
    Config, OpenOptions, DEFAULT_PING_PADDING_MAX_BYTES, DEFAULT_PING_PADDING_MIN_BYTES,
    DEFAULT_PREFACE_PADDING_MAX_BYTES, DEFAULT_PREFACE_PADDING_MIN_BYTES,
};
pub use conformance::{
    core_module_target_claims, core_module_target_implementation_profiles,
    core_module_target_suites, known_claims, known_conformance_suites,
    known_implementation_profiles, reference_profile_claim_gate, Claim, ConformanceSuite,
    ImplementationProfile, ParseConformanceError,
};
pub use error::{
    Error, ErrorCode, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource, Result,
    TerminationKind,
};
pub use event::{Event, EventHandler, EventType, StreamEventInfo};
pub use frame::{
    parse_frame, read_frame, Frame, FrameType, FrameView, Limits, FRAME_FLAG_FIN,
    FRAME_FLAG_OPEN_METADATA,
};
pub use io_adapters::AsyncIo;
pub use open_send::{OpenRequest, OpenSend, WritePayload};
pub use payload::{
    build_code_payload, build_go_away_payload, build_open_metadata_prefix,
    build_open_metadata_prefix_into, build_priority_update_payload,
    build_priority_update_payload_into, parse_data_payload, parse_data_payload_view,
    parse_error_payload, parse_go_away_payload, parse_priority_update_payload,
    parse_stream_metadata_bytes_view, parse_stream_metadata_tlvs, DataPayload, DataPayloadView,
    GoAwayPayload, MetadataUpdate, StreamMetadata, StreamMetadataView,
};
pub use preface::{
    negotiate_prefaces, parse_preface, parse_preface_prefix, read_preface, resolve_roles,
    Negotiated, Preface,
};
pub use protocol::{
    capabilities_can_carry_group_in_update, capabilities_can_carry_group_on_open,
    capabilities_can_carry_open_info, capabilities_can_carry_priority_in_update,
    capabilities_can_carry_priority_on_open, capabilities_have_peer_visible_group_semantics,
    capabilities_have_peer_visible_priority_semantics, capabilities_support_open_metadata,
    capabilities_support_priority_update, has_capability, Role, CAPABILITY_OPEN_METADATA,
    CAPABILITY_PRIORITY_HINTS, CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS,
    DEFAULT_CAPABILITIES, DIAG_DEBUG_TEXT, DIAG_OFFENDING_FRAME_TYPE, DIAG_OFFENDING_STREAM_ID,
    DIAG_RETRY_AFTER_MILLIS, EXT_PRIORITY_UPDATE, MAGIC, MAX_PREFACE_SETTINGS_BYTES,
    METADATA_OPEN_INFO, METADATA_STREAM_GROUP, METADATA_STREAM_PRIORITY, PREFACE_VERSION,
    PROTO_VERSION, SETTING_INITIAL_MAX_DATA, SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED,
    SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED, SETTING_INITIAL_MAX_STREAM_DATA_UNI,
    SETTING_MAX_CONTROL_PAYLOAD_BYTES, SETTING_MAX_EXTENSION_PAYLOAD_BYTES,
    SETTING_MAX_FRAME_PAYLOAD, SETTING_MAX_INCOMING_STREAMS_BIDI, SETTING_MAX_INCOMING_STREAMS_UNI,
    SETTING_PING_PADDING_KEY, SETTING_PREFACE_PADDING, SETTING_SCHEDULER_HINTS,
};
pub use session::{
    duplex_io, try_duplex_io, AbuseStats, AcceptBacklogStats, ActiveStreamStats, Conn,
    DiagnosticStats, DuplexConnection, DuplexIo, DuplexTransport, DuplexTransportControl,
    FlushStats, HiddenStateStats, LivenessStats, MemoryStats, PeerCloseError, PeerGoAwayError,
    PressureStats, ProgressStats, ProvisionalStats, ReasonStats, RecvStream, RetentionStats,
    SendStream, SessionState, SessionStats, Stream, TelemetryStats, WriterQueueStats,
};
pub use settings::{
    default_settings, marshal_settings_tlv, parse_settings_tlv, SchedulerHint, Settings,
};
pub use tlv::{append_tlv, parse_tlvs, parse_tlvs_view, visit_tlvs, Tlv, TlvView};
pub use varint::{
    append_varint, encode_varint, encode_varint_to_slice, parse_varint, read_varint, varint_len,
    MAX_VARINT62, MAX_VARINT_LEN,
};
