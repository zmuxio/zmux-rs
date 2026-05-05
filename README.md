# zmux

Rust implementation of the ZMux v1 single-link stream multiplexing protocol.

The workspace publishes two crates:

- `zmux`: native blocking ZMux sessions, stable session/stream traits, wire codec helpers, and conformance helpers.
- `zmux-quinn`: optional async adapter for applications that already use `quinn`.

`zmux` does not depend on Tokio, Quinn, rustls, or any QUIC stack.

## Installation

```toml
[dependencies]
zmux = "VERSION"
```

Optional core features:

```toml
[dependencies]
zmux = { version = "VERSION", features = ["tokio-io", "futures-io"] }
```

For QUIC support, add the adapter crate:

```toml
[dependencies]
zmux = "VERSION"
zmux-quinn = "VERSION"
quinn = "QUINN_VERSION"
```

Adapter usage is documented in [`adapter/quinn/README.md`](adapter/quinn/README.md).

## Start A Session

Use `zmux::new_tcp(...)` when both peers can use auto role negotiation on an already established TCP connection.

```rust
use std::net::TcpStream;
use zmux::Config;

fn main() -> zmux::Result<()> {
    let socket = TcpStream::connect("127.0.0.1:9000")?;
    let session = zmux::new_tcp(socket, Config::default())?;

    let stream = session.open_stream()?;
    stream.write_final(b"hello")?;

    let mut reply = [0u8; 1024];
    let _n = stream.read(&mut reply)?;

    session.close()?;
    Ok(())
}
```

Constructor choice:

- `new(...)`, `new_tcp(...)`, `new_transport(...)`: auto role negotiation.
- `client(...)`, `client_tcp(...)`, `client_transport(...)`: fixed initiator/client role.
- `server(...)`, `server_tcp(...)`, `server_transport(...)`: fixed responder/server role.
- `Conn::new*`, `Conn::client*`, and `Conn::server*`: native session constructors with the same transport choices.

Use the stable trait surfaces when application code should not depend on `Conn` directly:

- `NativeSession`, `NativeStreamApi`, `NativeSendStreamApi`, `NativeRecvStreamApi`: blocking native API.
- `Session` / `AsyncSession`, `StreamApi` / `AsyncStreamApi`, `SendStreamApi` / `AsyncSendStreamApi`, `RecvStreamApi` / `AsyncRecvStreamApi`: async API used by adapters and async integration code.

## Streams

Bidirectional streams can both read and write:

```rust
let stream = session.open_stream()?;
stream.write(b"request")?;
stream.close_write()?;

let mut response = Vec::new();
let mut buf = [0u8; 4096];
loop {
    let n = stream.read(&mut buf)?;
    if n == 0 {
        break;
    }
    response.extend_from_slice(&buf[..n]);
}
```

Unidirectional streams split send and receive sides:

```rust
let send = session.open_uni_stream()?;
send.write_final(b"event")?;

let recv = session.accept_uni_stream()?;
let mut buf = [0u8; 4096];
let _n = recv.read(&mut buf)?;
```

Open a stream and send the first payload in one call:

```rust
let (stream, _n) = session.open_and_send(b"hello")?;
let (send, _n) = session.open_uni_and_send(b"event")?;
```

`open_and_send(...)` leaves a bidirectional stream open. `open_uni_and_send(...)` writes the final payload for a unidirectional send stream.

## Metadata And Priority

Enable negotiated capabilities before using open metadata, priority hints, stream groups, or priority updates:

```rust
use zmux::{
    Config, MetadataUpdate, OpenOptions, CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS,
};

let capabilities = CAPABILITY_OPEN_METADATA
    | CAPABILITY_PRIORITY_HINTS
    | CAPABILITY_STREAM_GROUPS
    | CAPABILITY_PRIORITY_UPDATE;

let config = Config::default().with_capabilities(capabilities);
let options = OpenOptions::open_info("rpc")
    .with_initial_priority(7)
    .with_initial_group(2);

let stream = session.open_stream_with_options(options)?;
stream.update_metadata(MetadataUpdate::priority(3))?;
stream.write_final(b"hello")?;
```

The peer reads opener metadata through `stream.open_info()` or `stream.metadata()`.

## Custom Transports

Wrap split blocking halves directly:

```rust
let session = zmux::new(reader, writer, Config::default())?;
```

Use `DuplexTransport` when the transport can expose addresses, timeouts, or a close hook:

```rust
let transport = zmux::DuplexTransport::new(reader, writer)
    .with_addresses(local_addr, peer_addr)
    .with_close_fn(close_transport);

let session = zmux::new_transport(transport, Config::default())?;
```

Join existing stream halves when an API expects a duplex object:

```rust
let duplex = zmux::join_native_streams(recv_half, send_half);
let optional = zmux::join_optional_native_streams(Some(recv_half), Some(send_half));
```

Async equivalents are `join_streams(...)`, `join_async_streams(...)`, and `join_optional_streams(...)`.

## Closing And Errors

```rust
stream.close_write()?;                // graceful local send-half close
stream.close_read()?;                 // local read cancellation
stream.close_with_error(0x100, "bye")?;

session.close()?;                     // graceful session close
session.close_with_error(0x100, "bye")?;
session.wait()?;
```

Use `Error` helpers instead of matching error text:

```rust
match stream.write(payload) {
    Ok(_) => {}
    Err(err) if err.is_session_closed() => {}
    Err(err) if err.is_timeout() => {}
    Err(err) => return Err(err),
}
```

Common helpers include `is_session_closed()`, `is_read_closed()`, `is_write_closed()`, `is_timeout()`, `is_interrupted()`, `is_open_limited()`, `is_open_expired()`, `is_open_info_unavailable()`, `is_priority_update_unavailable()`, and `is_adapter_unsupported()`.

## Configuration

```rust
let config = Config::default()
    .with_capabilities(capabilities)
    .with_event_handler(|event| {
        let _ = event;
    });
```

`Settings` controls negotiated stream windows, incoming stream limits, frame payload limits, idle timeout hints, keepalive hints, scheduler hints, and padding keys.

`configure_default_config(...)` updates the process-wide default template during startup. `reset_default_config()` restores built-in defaults.

## Public API Surface

Root constructors and wrappers:

- `new`, `client`, `server`
- `new_tcp`, `client_tcp`, `server_tcp`
- `new_transport`, `client_transport`, `server_transport`
- `box_native_session`, `box_session`, `box_async_session`
- `closed_native_session`, `closed_session`, `closed_async_session`
- `boxed_closed_native_session`, `boxed_closed_session`, `boxed_closed_async_session`
- `join_native_streams`, `join_optional_native_streams`
- `join_streams`, `join_async_streams`, `join_optional_streams`, `join_optional_async_streams`

Configuration and settings:

- `Config`, `OpenOptions`, `Settings`, `SchedulerHint`
- `default_config`, `configure_default_config`, `reset_default_config`
- `default_settings`, `marshal_settings_tlv`, `parse_settings_tlv`
- `DEFAULT_PREFACE_PADDING_MIN_BYTES`, `DEFAULT_PREFACE_PADDING_MAX_BYTES`
- `DEFAULT_PING_PADDING_MIN_BYTES`, `DEFAULT_PING_PADDING_MAX_BYTES`
- `Config` methods: `builtin_default`, `configure_default`, `reset_default`, `initiator`, `responder`, `with_role`, `with_capabilities`, `enable_capabilities`, `with_settings`, `with_event_handler`, `normalized`, `local_preface`
- `OpenOptions` methods: `new`, `priority`, `group`, `open_info`, `open_info_bytes`, `with_initial_priority`, `try_with_initial_priority`, `with_initial_group`, `try_with_initial_group`, `with_open_info`, `with_open_info_bytes`, `is_empty`, `validate`
- `Settings` methods: `limits`, `validate`, `encoded_tlv_len`, `append_tlv_to`
- `SchedulerHint` methods: `from_code`, `from_u64`, `as_u64`, `as_str`

Native session and stream types:

- `Conn`, `Stream`, `SendStream`, `RecvStream`
- `NativeSession`, `NativeStreamApi`, `NativeSendStreamApi`, `NativeRecvStreamApi`, `NativeStreamInfo`
- `BoxNativeSession`, `BoxNativeStream`, `BoxNativeSendStream`, `BoxNativeRecvStream`
- `ClosedNativeSession`
- `NativeDuplexStream`, `DuplexInfoSide`, `PausedNativeHalf`, `PausedNativeRecvHalf`, `PausedNativeSendHalf`
- joined native stream methods: `new`, `from_parts`, `empty`, `with_info_side`, `info_side`, `recv`, `send`, `into_parts`, `pause_read`, `pause_read_timeout`, `pause_write`, `pause_write_timeout`, `replace_recv`, `replace_send`, `detach_recv`, `detach_send`, `read_stream_id`, `write_stream_id`
- paused native half methods: `current`, `current_mut`, `take`, `set`, `replace`, `resume`

Async session and stream types:

- `Session`, `AsyncSession`
- `StreamApi`, `AsyncStreamApi`, `SendStreamApi`, `AsyncSendStreamApi`, `RecvStreamApi`, `AsyncRecvStreamApi`, `StreamInfo`, `AsyncStreamInfo`
- `BoxSession`, `BoxedSession`, `BoxStream`, `BoxSendStream`, `BoxRecvStream`
- `BoxAsyncSession`, `BoxedAsyncSession`, `BoxAsyncStream`, `BoxAsyncSendStream`, `BoxAsyncRecvStream`
- `ClosedSession`, `ClosedAsyncSession`
- `DuplexStream`, `AsyncDuplexStream`, `AsyncBoxFuture`, `BoxFuture`
- `PausedAsyncHalf`, `PausedAsyncRecvHalf`, `PausedAsyncSendHalf`
- `async_io`, `AsyncIo`
- `BoxedAsyncSession` methods: `new`, `inner`, `into_inner`
- joined async stream methods: `new`, `from_parts`, `empty`, `with_info_side`, `info_side`, `recv`, `send`, `into_parts`, `pause_read`, `pause_read_timeout`, `pause_write`, `pause_write_timeout`, `replace_recv`, `replace_send`, `detach_recv`, `detach_send`, `read_stream_id`, `write_stream_id`
- paused async half methods: `current`, `take`, `set`, `set_arc`, `replace`, `resume`

Session methods:

- open/accept: `accept_stream`, `accept_stream_timeout`, `accept_uni_stream`, `accept_uni_stream_timeout`, `open_stream`, `open_stream_timeout`, `open_uni_stream`, `open_uni_stream_timeout`, `open_stream_with_options`, `open_stream_with_options_timeout`, `open_uni_stream_with_options`, `open_uni_stream_with_options_timeout`
- open and write: `open_and_send`, `open_and_send_timeout`, `open_and_send_with_options`, `open_and_send_with_options_timeout`, `open_and_send_vectored`, `open_and_send_vectored_timeout`, `open_and_send_vectored_with_options`, `open_and_send_vectored_with_options_timeout`, `open_uni_and_send`, `open_uni_and_send_timeout`, `open_uni_and_send_with_options`, `open_uni_and_send_with_options_timeout`, `open_uni_and_send_vectored`, `open_uni_and_send_vectored_timeout`, `open_uni_and_send_vectored_with_options`, `open_uni_and_send_vectored_with_options_timeout`
- lifecycle: `close`, `close_with_error`, `wait`, `wait_timeout`, `wait_close_error`, `wait_close_error_timeout`, `closed`, `close_error`, `state`, `stats`
- native controls: `ping`, `ping_timeout`, `goaway`, `goaway_with_error`, `peer_goaway_error`, `peer_close_error`, `local_preface`, `peer_preface`, `negotiated`
- addresses: `local_addr`, `peer_addr`, `remote_addr`

Stream methods:

- identity/info: `stream_id`, `close_identity`, `opened_locally`, `bidirectional`, `open_info`, `copy_open_info_to`, `open_info_len`, `has_open_info`, `metadata`, `local_addr`, `peer_addr`, `remote_addr`
- read side: `read`, `read_vectored`, `read_timeout`, `read_vectored_timeout`, `read_exact_timeout`, `read_closed`, `set_read_deadline`, `set_read_timeout`, `clear_read_deadline`, `close_read`, `cancel_read`
- write side: `write`, `write_timeout`, `write_vectored`, `writev`, `write_vectored_timeout`, `writev_timeout`, `write_final`, `write_final_timeout`, `write_vectored_final`, `writev_final`, `write_vectored_final_timeout`, `writev_final_timeout`, `write_closed`, `set_write_deadline`, `set_write_timeout`, `clear_write_deadline`, `update_metadata`, `close_write`, `cancel_write`
- async read/write helpers: `read_exact`, `read_to_end`, `read_to_end_limited`, `write_all`
- combined stream helpers: `set_deadline`, `set_timeout`, `clear_deadline`, `close`, `close_with_error`
- `SendStream` exposes write-side methods. `RecvStream` exposes read-side methods. `Stream` exposes both.

Wire codec and protocol helpers:

- `Role`, `Preface`, `Negotiated`
- `Role` methods: `from_u8`, `as_u8`, `as_str`
- `Preface` methods: `has_capability`, `supports_open_metadata`, `supports_priority_update`, `can_carry_open_info`, `can_carry_priority_on_open`, `can_carry_group_on_open`, `can_carry_priority_in_update`, `can_carry_group_in_update`, `has_peer_visible_priority_semantics`, `has_peer_visible_group_semantics`, `marshal`, `marshal_with_settings_padding`, `parse`
- `Negotiated` methods: `has_capability`, `supports_open_metadata`, `supports_priority_update`, `can_carry_open_info`, `can_carry_priority_on_open`, `can_carry_group_on_open`, `can_carry_priority_in_update`, `can_carry_group_in_update`, `has_peer_visible_priority_semantics`, `has_peer_visible_group_semantics`
- `parse_preface`, `parse_preface_prefix`, `read_preface`, `negotiate_prefaces`, `resolve_roles`
- `Frame`, `FrameView`, `FrameType`, `Limits`, `FRAME_FLAG_FIN`, `FRAME_FLAG_OPEN_METADATA`
- `FrameType` methods: `from_code`, `from_u8`, `as_u8`, `as_str`
- `Limits` methods: `normalized`, `inbound_payload_limit`
- `Frame` methods: `new`, `with_flags`, `code`, `as_view`, `marshal`, `encoded_len`, `append_to`, `parse`, `validate`
- `FrameView` methods: `code`, `to_owned_frame`, `try_to_owned_frame`, `parse`, `validate`
- `parse_frame`, `read_frame`
- `append_varint`, `encode_varint`, `encode_varint_to_slice`, `parse_varint`, `read_varint`, `varint_len`, `MAX_VARINT62`, `MAX_VARINT_LEN`
- `Tlv`, `TlvView`, `append_tlv`, `parse_tlvs`, `parse_tlvs_view`, `visit_tlvs`
- `Tlv` methods: `new`, `as_view`, `is_empty`, `validate`, `encoded_len`, `append_to`
- `TlvView` methods: `is_empty`, `validate`, `encoded_len`, `append_to`, `to_tlv`
- `DataPayload`, `DataPayloadView`, `GoAwayPayload`, `MetadataUpdate`, `StreamMetadata`, `StreamMetadataView`
- `StreamMetadata` methods: `as_view`, `open_info`, `has_open_info`, `is_empty`
- `StreamMetadataView` methods: `open_info`, `has_open_info`, `is_empty`, `to_owned_metadata`, `try_to_owned_metadata`
- `MetadataUpdate` methods: `new`, `priority`, `group`, `with_priority`, `try_with_priority`, `with_group`, `try_with_group`, `is_empty`, `validate`
- `build_code_payload`, `build_goaway_payload`, `build_open_metadata_prefix`, `build_priority_update_payload`
- `parse_data_payload`, `parse_data_payload_view`, `parse_error_payload`, `parse_goaway_payload`, `parse_priority_update_payload`, `parse_stream_metadata_tlvs`, `parse_stream_metadata_bytes_view`

Protocol constants and capability helpers:

- `MAGIC`, `PREFACE_VERSION`, `PROTO_VERSION`, `MAX_PREFACE_SETTINGS_BYTES`
- `CAPABILITY_OPEN_METADATA`, `CAPABILITY_PRIORITY_HINTS`, `CAPABILITY_PRIORITY_UPDATE`, `CAPABILITY_STREAM_GROUPS`, `CAPABILITY_MULTILINK_BASIC`, `CAPABILITY_MULTILINK_BASIC_RETIRED`
- `EXT_PRIORITY_UPDATE`, `EXT_ML_READY_RETIRED`, `EXT_ML_ATTACH_RETIRED`, `EXT_ML_ATTACH_ACK_RETIRED`, `EXT_ML_DRAIN_REQ_RETIRED`, `EXT_ML_DRAIN_ACK_RETIRED`
- `METADATA_STREAM_PRIORITY`, `METADATA_STREAM_GROUP`, `METADATA_OPEN_INFO`
- `DIAG_DEBUG_TEXT`, `DIAG_RETRY_AFTER_MILLIS`, `DIAG_OFFENDING_STREAM_ID`, `DIAG_OFFENDING_FRAME_TYPE`
- `SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED`, `SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED`, `SETTING_INITIAL_MAX_STREAM_DATA_UNI`, `SETTING_INITIAL_MAX_DATA`, `SETTING_MAX_INCOMING_STREAMS_BIDI`, `SETTING_MAX_INCOMING_STREAMS_UNI`, `SETTING_MAX_FRAME_PAYLOAD`, `SETTING_IDLE_TIMEOUT_MILLIS`, `SETTING_KEEPALIVE_HINT_MILLIS`, `SETTING_MAX_CONTROL_PAYLOAD_BYTES`, `SETTING_MAX_EXTENSION_PAYLOAD_BYTES`, `SETTING_SCHEDULER_HINTS`, `SETTING_PING_PADDING_KEY`, `SETTING_PREFACE_PADDING`
- `has_capability`, `capabilities_support_open_metadata`, `capabilities_support_priority_update`
- `capabilities_can_carry_open_info`, `capabilities_can_carry_priority_on_open`, `capabilities_can_carry_group_on_open`, `capabilities_can_carry_priority_update`, `capabilities_can_carry_priority_in_update`, `capabilities_can_carry_group_update`, `capabilities_can_carry_group_in_update`
- `capabilities_have_peer_visible_priority_semantics`, `capabilities_have_peer_visible_group_semantics`

Stream ID helpers:

- `expected_next_peer_stream_id`, `first_local_stream_id`, `first_peer_stream_id`
- `initial_receive_window`, `initial_send_window`
- `local_open_refused_by_goaway`, `peer_open_refused_by_goaway`
- `max_stream_id_for_class`, `projected_local_open_id`
- `stream_is_bidi`, `stream_is_local`, `stream_kind_for_local`, `stream_opener`
- `validate_local_open_id`, `validate_stream_id_for_role`

Errors, events, diagnostics, and conformance:

- `Error`, `Result`, `ErrorCode`, `ErrorScope`, `ErrorOperation`, `ErrorSource`, `ErrorDirection`, `TerminationKind`
- enum helpers: `ErrorCode::from_code`, `ErrorCode::from_u64`, `ErrorCode::as_u64`, `ErrorCode::as_str`, `ErrorCode::name`; `ErrorScope::as_str`; `ErrorOperation::as_str`; `ErrorSource::as_str`; `ErrorDirection::as_str`; `TerminationKind::as_str`
- `Error` constructors: `new`, `local`, `protocol`, `frame_size`, `unsupported_version`, `role_conflict`, `flow_control`, `stream_state`, `stream_closed`, `read_closed`, `write_closed`, `session_closed`, `application`, `try_application`, `io`, `timeout`, `graceful_close_timeout`
- `Error` accessors: `code`, `application_code`, `numeric_code`, `reason`, `message`, `source_io_error_kind`, `scope`, `operation`, `source`, `direction`, `termination_kind`, `io_error_kind`
- `Error` classification helpers: `is_error_code`, `is_application_code`, `is_session_closed`, `is_timeout`, `is_interrupted`, `is_stream_not_readable`, `is_stream_not_writable`, `is_read_closed`, `is_write_closed`, `is_open_limited`, `is_open_expired`, `is_open_info_unavailable`, `is_open_metadata_too_large`, `is_adapter_unsupported`, `is_priority_update_unavailable`, `is_priority_update_too_large`, `is_empty_metadata_update`, `is_keepalive_timeout`, `is_graceful_close_timeout`
- `Error` context helpers: `with_scope`, `with_operation`, `with_source`, `with_direction`, `with_termination_kind`, `with_session_context`, `with_stream_context`
- `Event`, `EventType`, `EventHandler`, `StreamEventInfo`
- event helpers: `EventType::as_str`, `StreamEventInfo::open_info`, `StreamEventInfo::open_info_len`, `StreamEventInfo::has_open_info`
- `SessionState`, `SessionStats`, `PeerCloseError`, `PeerGoAwayError`
- `AbuseStats`, `AcceptBacklogStats`, `ActiveStreamStats`, `DiagnosticStats`, `FlushStats`, `HiddenStateStats`, `LivenessStats`, `MemoryStats`, `PressureStats`, `ProgressStats`, `ProvisionalStats`, `ReasonStats`, `RetentionStats`, `TelemetryStats`, `WriterQueueStats`
- `DuplexTransport`, `DuplexTransportControl`
- `DuplexTransport` methods: `new`, `with_local_addr`, `with_peer_addr`, `with_addresses`, `with_control`, `with_close_fn`, `local_addr`, `peer_addr`, `remote_addr`, `set_read_timeout`, `set_write_timeout`, `close`, `reader`, `reader_mut`, `writer`, `writer_mut`, `into_parts`
- `Claim`, `ConformanceSuite`, `ImplementationProfile`, `ParseConformanceError`
- conformance methods: `Claim::as_str`, `Claim::acceptance_checklist`, `Claim::required_conformance_suites`, `ImplementationProfile::as_str`, `ImplementationProfile::claims`, `ImplementationProfile::acceptance_checklist`, `ImplementationProfile::required_conformance_suites`, `ImplementationProfile::release_certification_gate`, `ConformanceSuite::as_str`
- `known_claims`, `known_conformance_suites`, `known_implementation_profiles`, `core_module_target_claims`, `core_module_target_suites`, `core_module_target_implementation_profiles`, `reference_profile_claim_gate`

## Semantics

- Successful write calls mean the local implementation accepted and flushed the write to its backend. They are not peer application acknowledgements.
- Buffers passed to write/open-and-send methods are not retained after the call returns.
- `close_write()` finishes only the local send half.
- `close_read()` cancels local interest in inbound bytes.
- Open metadata is sent only when negotiated; required but unavailable metadata fails instead of being silently discarded.
