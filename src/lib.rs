//! Rust implementation of the ZMux v1 stream multiplexing protocol.
//!
//! The crate exposes public codec helpers for the normative wire format and a
//! synchronous session/stream runtime built on split `Read` / `Write` halves.

#![forbid(unsafe_code)]

mod api;
mod async_api;
mod config;
mod conformance;
mod error;
mod event;
mod frame;
mod io_adapters;
mod payload;
mod preface;
mod protocol;
mod session;
mod settings;
mod stream_id;
mod tlv;
mod varint;

pub use api::{
    boxed_closed_native_session, closed_native_session,
    join_optional_streams as join_optional_native_streams, join_streams as join_native_streams,
    BoxRecvStream as BoxNativeRecvStream, BoxSendStream as BoxNativeSendStream,
    BoxSession as BoxNativeSession, BoxStream as BoxNativeStream, ClosedNativeSession,
    DuplexInfoSide, DuplexStream as NativeDuplexStream, PausedNativeHalf, PausedNativeRecvHalf,
    PausedNativeSendHalf, RecvStreamApi as NativeRecvStreamApi,
    SendStreamApi as NativeSendStreamApi, Session as NativeSession, StreamApi as NativeStreamApi,
    StreamInfo as NativeStreamInfo,
};
pub use async_api::{
    box_async_session, box_async_session as box_session, boxed_closed_session,
    boxed_closed_session as boxed_closed_async_session, closed_session,
    closed_session as closed_async_session, join_async_streams, join_async_streams as join_streams,
    join_optional_streams, join_optional_streams as join_optional_async_streams, AsyncBoxFuture,
    AsyncBoxFuture as BoxFuture, AsyncDuplexStream, AsyncDuplexStream as DuplexStream,
    AsyncRecvStreamApi, AsyncRecvStreamApi as RecvStreamApi, AsyncSendStreamApi,
    AsyncSendStreamApi as SendStreamApi, AsyncSession, AsyncSession as Session, AsyncStreamApi,
    AsyncStreamApi as StreamApi, AsyncStreamInfo, AsyncStreamInfo as StreamInfo,
    BoxAsyncRecvStream, BoxAsyncRecvStream as BoxRecvStream, BoxAsyncSendStream,
    BoxAsyncSendStream as BoxSendStream, BoxAsyncSession, BoxAsyncSession as BoxSession,
    BoxAsyncStream, BoxAsyncStream as BoxStream, BoxedAsyncSession,
    BoxedAsyncSession as BoxedSession, ClosedSession, ClosedSession as ClosedAsyncSession,
    PausedAsyncHalf, PausedAsyncRecvHalf, PausedAsyncSendHalf,
};
pub use config::{
    configure_default_config, default_config, reset_default_config, Config, OpenOptions,
    DEFAULT_PING_PADDING_MAX_BYTES, DEFAULT_PING_PADDING_MIN_BYTES,
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
pub use io_adapters::{async_io, AsyncIo};
pub use payload::{
    build_code_payload, build_goaway_payload, build_open_metadata_prefix,
    build_priority_update_payload, parse_data_payload, parse_data_payload_view,
    parse_error_payload, parse_goaway_payload, parse_priority_update_payload,
    parse_stream_metadata_bytes_view, parse_stream_metadata_tlvs, DataPayload, DataPayloadView,
    GoAwayPayload, MetadataUpdate, StreamMetadata, StreamMetadataView,
};
pub use preface::{
    negotiate_prefaces, parse_preface, parse_preface_prefix, read_preface, resolve_roles,
    Negotiated, Preface,
};
pub use protocol::{
    capabilities_can_carry_group_in_update, capabilities_can_carry_group_on_open,
    capabilities_can_carry_group_update, capabilities_can_carry_open_info,
    capabilities_can_carry_priority_in_update, capabilities_can_carry_priority_on_open,
    capabilities_can_carry_priority_update, capabilities_have_peer_visible_group_semantics,
    capabilities_have_peer_visible_priority_semantics, capabilities_support_open_metadata,
    capabilities_support_priority_update, has_capability, Role, CAPABILITY_MULTILINK_BASIC,
    CAPABILITY_MULTILINK_BASIC_RETIRED, CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS, DIAG_DEBUG_TEXT,
    DIAG_OFFENDING_FRAME_TYPE, DIAG_OFFENDING_STREAM_ID, DIAG_RETRY_AFTER_MILLIS,
    EXT_ML_ATTACH_ACK_RETIRED, EXT_ML_ATTACH_RETIRED, EXT_ML_DRAIN_ACK_RETIRED,
    EXT_ML_DRAIN_REQ_RETIRED, EXT_ML_READY_RETIRED, EXT_PRIORITY_UPDATE, MAGIC,
    MAX_PREFACE_SETTINGS_BYTES, METADATA_OPEN_INFO, METADATA_STREAM_GROUP,
    METADATA_STREAM_PRIORITY, PREFACE_VERSION, PROTO_VERSION, SETTING_IDLE_TIMEOUT_MILLIS,
    SETTING_INITIAL_MAX_DATA, SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED,
    SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED, SETTING_INITIAL_MAX_STREAM_DATA_UNI,
    SETTING_KEEPALIVE_HINT_MILLIS, SETTING_MAX_CONTROL_PAYLOAD_BYTES,
    SETTING_MAX_EXTENSION_PAYLOAD_BYTES, SETTING_MAX_FRAME_PAYLOAD,
    SETTING_MAX_INCOMING_STREAMS_BIDI, SETTING_MAX_INCOMING_STREAMS_UNI, SETTING_PING_PADDING_KEY,
    SETTING_PREFACE_PADDING, SETTING_SCHEDULER_HINTS,
};
pub use session::{
    AbuseStats, AcceptBacklogStats, ActiveStreamStats, Conn, DiagnosticStats, DuplexTransport,
    DuplexTransportControl, FlushStats, HiddenStateStats, LivenessStats, MemoryStats,
    PeerCloseError, PeerGoAwayError, PressureStats, ProgressStats, ProvisionalStats, ReasonStats,
    RecvStream, RetentionStats, SendStream, SessionState, SessionStats, Stream, TelemetryStats,
    WriterQueueStats,
};
pub use settings::{
    default_settings, marshal_settings_tlv, parse_settings_tlv, SchedulerHint, Settings,
};
pub use stream_id::{
    expected_next_peer_stream_id, first_local_stream_id, first_peer_stream_id,
    initial_receive_window, initial_send_window, local_open_refused_by_goaway,
    max_stream_id_for_class, peer_open_refused_by_goaway, projected_local_open_id, stream_is_bidi,
    stream_is_local, stream_kind_for_local, stream_opener, validate_local_open_id,
    validate_stream_id_for_role,
};
pub use tlv::{append_tlv, parse_tlvs, parse_tlvs_view, visit_tlvs, Tlv, TlvView};
pub use varint::{
    append_varint, encode_varint, encode_varint_to_slice, parse_varint, read_varint, varint_len,
    MAX_VARINT62, MAX_VARINT_LEN,
};

/// Create a native ZMux session over split blocking `Read` / `Write` halves.
pub fn new<R, W>(reader: R, writer: W, config: Config) -> Result<Conn>
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    Conn::new(reader, writer, config)
}

/// Create an initiator/client native ZMux session over split blocking halves.
pub fn client<R, W>(reader: R, writer: W, config: Config) -> Result<Conn>
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    Conn::client(reader, writer, config)
}

/// Create a responder/server native ZMux session over split blocking halves.
pub fn server<R, W>(reader: R, writer: W, config: Config) -> Result<Conn>
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    Conn::server(reader, writer, config)
}

/// Create a native ZMux session over a blocking TCP stream.
pub fn new_tcp(stream: std::net::TcpStream, config: Config) -> Result<Conn> {
    Conn::new_tcp(stream, config)
}

/// Create a native ZMux session over a custom duplex transport wrapper.
pub fn new_transport<R, W>(transport: DuplexTransport<R, W>, config: Config) -> Result<Conn>
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    Conn::new_transport(transport, config)
}

/// Create an initiator/client native ZMux session over a blocking TCP stream.
pub fn client_tcp(stream: std::net::TcpStream, config: Config) -> Result<Conn> {
    Conn::client_tcp(stream, config)
}

/// Create an initiator/client native ZMux session over a custom duplex transport wrapper.
pub fn client_transport<R, W>(transport: DuplexTransport<R, W>, config: Config) -> Result<Conn>
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    Conn::client_transport(transport, config)
}

/// Create a responder/server native ZMux session over a blocking TCP stream.
pub fn server_tcp(stream: std::net::TcpStream, config: Config) -> Result<Conn> {
    Conn::server_tcp(stream, config)
}

/// Create a responder/server native ZMux session over a custom duplex transport wrapper.
pub fn server_transport<R, W>(transport: DuplexTransport<R, W>, config: Config) -> Result<Conn>
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    Conn::server_transport(transport, config)
}

/// Erase a native blocking session behind the native session trait object.
pub fn box_native_session<S>(session: S) -> BoxNativeSession
where
    S: NativeSession + 'static,
{
    Box::new(session)
}
