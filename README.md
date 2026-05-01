# zmux

Rust implementation of the ZMux v1 single-connection multiplexing protocol.

`zmux` is the synchronous native runtime crate.
`zmux-quinn` is an optional async adapter crate and is documented in `adapter/quinn/README.md`.

## Install

```toml
[dependencies]
zmux = "<version>"
```

If you need the QUIC adapter:

```toml
[dependencies]
zmux-quinn = "<same version as zmux>"
```

## Quick Start (synchronous, blocking)

```rust
use std::net::TcpStream;
use zmux::{client_tcp, Config};

let socket = TcpStream::connect("127.0.0.1:9000") ?;
let conn = client_tcp(socket, Config::default ()) ?;

let mut stream = conn.open_stream() ?;
stream.write_all(b"hello") ?;
stream.close_write() ?;

let mut peer = conn.accept_stream() ?;
let mut buf = [0u8; 64];
let n = peer.read( & mut buf) ?;
let _ = peer.close();
```

```rust
use std::net::TcpStream;
use zmux::{new_tcp, Config, OpenOptions};

let socket = TcpStream::connect("127.0.0.1:9000") ?;
let options = OpenOptions::open_info_bytes(b"route:v1")
.with_initial_priority(7)
.with_initial_group(3);
let conn = new_tcp(socket, Config::default ()) ?;
let (_stream, n) = conn.open_and_send_with_options(options, b"payload") ?;
```

## Public API (all exported items)

### Root constructors and wrappers

- `new`, `client`, `server`
- `new_tcp`, `client_tcp`, `server_tcp`
- `new_transport`, `client_transport`, `server_transport`
- `box_session`, `box_native_session`
- `boxed_closed_session`, `boxed_closed_native_session`
- `closed_session`, `closed_native_session`
- `join_streams`, `join_native_streams`
- `join_optional_streams`, `join_optional_native_streams`

### Configuration and conformance

- `Config`
- `OpenOptions`
- `default_config`, `configure_default_config`, `reset_default_config`
- `DEFAULT_PING_PADDING_MAX_BYTES`, `DEFAULT_PING_PADDING_MIN_BYTES`
- `DEFAULT_PREFACE_PADDING_MAX_BYTES`, `DEFAULT_PREFACE_PADDING_MIN_BYTES`
- `Settings`, `SchedulerHint`
- `default_settings`, `marshal_settings_tlv`, `parse_settings_tlv`
- `Claim`, `ConformanceSuite`, `ImplementationProfile`, `ParseConformanceError`
- `core_module_target_claims`, `core_module_target_implementation_profiles`
- `core_module_target_suites`, `known_claims`
- `known_implementation_profiles`, `known_conformance_suites`
- `reference_profile_claim_gate`

### Protocol + wire helpers

- `Role`, `Negotiated`, `Preface`
- `negotiate_prefaces`, `parse_preface`, `parse_preface_prefix`, `read_preface`, `resolve_roles`
- `Frame`, `FrameType`, `FrameView`, `Limits`
- `FRAME_FLAG_FIN`, `FRAME_FLAG_OPEN_METADATA`
- `parse_frame`, `read_frame`
- `append_varint`, `encode_varint`, `encode_varint_to_slice`, `parse_varint`, `read_varint`, `varint_len`
- `MAX_VARINT62`, `MAX_VARINT_LEN`
- `append_tlv`, `parse_tlvs`, `parse_tlvs_view`, `visit_tlvs`, `Tlv`, `TlvView`
- `build_code_payload`, `build_goaway_payload`, `parse_data_payload`
- `parse_data_payload_view`, `parse_error_payload`, `parse_goaway_payload`
- `parse_priority_update_payload`, `build_priority_update_payload`, `build_open_metadata_prefix`
- `parse_stream_metadata_tlvs`, `parse_stream_metadata_bytes_view`
- `StreamMetadata`, `StreamMetadataView`, `MetadataUpdate`, `DataPayload`, `DataPayloadView`
- `GoAwayPayload`
- capability helpers:
    - `has_capability`, `Role`, `CAPABILITY_*`, `EXT_*`, `METADATA_*`
    - `SETTING_*`

### Stream ID helpers

- `expected_next_peer_stream_id`, `first_local_stream_id`, `first_peer_stream_id`
- `initial_receive_window`, `initial_send_window`
- `max_stream_id_for_class`, `stream_is_bidi`, `stream_is_local`
- `local_open_refused_by_goaway`, `peer_open_refused_by_goaway`
- `projected_local_open_id`, `stream_opener`, `validate_local_open_id`
- `validate_stream_id_for_role`, `stream_kind_for_local`

### Session and stream types

- `Conn`
- `Stream`, `SendStream`, `RecvStream`
- `DuplexTransport`, `DuplexTransportControl`
- `DuplexInfoSide`, `DuplexStream`, `NativeDuplexStream`
- `NativeSession`, `StreamApi`, `SendStreamApi`, `RecvStreamApi`, `StreamInfo`
- `SessionState`, `SessionStats`, `AbuseStats`, `AcceptBacklogStats`, `ActiveStreamStats`,
  `DiagnosticStats`, `FlushStats`, `HiddenStateStats`, `LivenessStats`, `MemoryStats`,
  `PressureStats`, `ProgressStats`, `ProvisionalStats`, `ReasonStats`, `RetentionStats`,
  `TelemetryStats`, `WriterQueueStats`
- Boxed/native trait-object types:
    - `BoxSession`, `BoxStream`, `BoxSendStream`, `BoxRecvStream`
    - `BoxNativeSession`, `BoxNativeStream`, `BoxNativeSendStream`, `BoxNativeRecvStream`
    - `ClosedSession`, `ClosedNativeSession`

### Async API aliases and wrappers

- `Session` (`AsyncSession`)
- `StreamApi`, `SendStreamApi`, `RecvStreamApi`, `StreamInfo`
- `AsyncStreamApi`, `AsyncSendStreamApi`, `AsyncRecvStreamApi`
- `AsyncDuplexStream`, `AsyncSession`
- `join_streams`, `join_optional_streams`
- `DuplexStream` (async), `BoxFuture`, `AsyncBoxFuture`
- `join_native_streams` and `join_optional_native_streams` for native handles
- `boxed_closed_session`, `boxed_closed_native_session`, `box_session`, `box_native_session`
- `async_io`, `AsyncIo`

### `Conn` methods

- `new`, `client`, `server`, `new_tcp`, `client_tcp`, `server_tcp`
- `new_transport`, `client_transport`, `server_transport`
- `local_addr`, `peer_addr`, `remote_addr`
- Stream open/accept:
    - `open_stream`, `open_stream_timeout`
    - `open_uni_stream`, `open_uni_stream_timeout`
    - `open_stream_with_options`, `open_stream_with_options_timeout`
    - `open_uni_stream_with_options`, `open_uni_stream_with_options_timeout`
    - `open_and_send`, `open_and_send_timeout`
    - `open_and_send_with_options`, `open_and_send_with_options_timeout`
    - `open_and_send_vectored`, `open_and_send_vectored_timeout`
    - `open_and_send_vectored_with_options`, `open_and_send_vectored_with_options_timeout`
    - `open_uni_and_send`, `open_uni_and_send_timeout`
    - `open_uni_and_send_with_options`, `open_uni_and_send_with_options_timeout`
    - `open_uni_and_send_vectored`, `open_uni_and_send_vectored_timeout`
    - `open_uni_and_send_vectored_with_options`, `open_uni_and_send_vectored_with_options_timeout`
    - `accept_stream`, `accept_stream_timeout`
    - `accept_uni_stream`, `accept_uni_stream_timeout`
- lifecycle / control:
    - `ping`, `ping_timeout`
    - `goaway`, `goaway_with_error`
    - `close`, `close_with_error`
    - `wait`, `wait_timeout`
    - `closed`
    - `close_error`, `state`, `stats`
    - `peer_close_error`, `peer_goaway_error`
    - `local_preface`, `peer_preface`, `negotiated`

### `Stream` methods

- identity: `stream_id`, `close_identity`, `opened_locally`, `bidirectional`
- state: `read_closed`, `write_closed`
- open metadata:
    - `open_info`, `open_info_len`, `has_open_info`, `copy_open_info_to`
    - `metadata`, `update_metadata`
- address: `local_addr`, `peer_addr`, `remote_addr`
- read ops: `read`, `read_vectored`, `read_timeout`, `read_vectored_timeout`, `read_exact_timeout`
- read state: `set_read_deadline`, `set_read_timeout`, `set_deadline`, `clear_read_deadline`, `clear_deadline`
- write ops: `write`, `write_timeout`, `write_vectored`, `writev`, `write_vectored_timeout`, `writev_timeout`
- final writes: `write_final`, `write_vectored_final`, `writev_final`
- final timeout variants: `write_final_timeout`, `write_vectored_final_timeout`, `writev_final_timeout`
- close ops: `close_read`, `cancel_read`, `close_write`, `cancel_write`, `close`, `close_with_error`

### `SendStream` methods

- same identity/open metadata/address set as `Stream`
- write-only operations:
    - `write`, `write_timeout`, `write_vectored`, `writev`, `write_vectored_timeout`, `writev_timeout`
    - `write_final`, `write_vectored_final`, `writev_final`
    - `write_final_timeout`, `write_vectored_final_timeout`, `writev_final_timeout`
- metadata: `metadata`, `update_metadata`
- deadlines/timeouts: `set_write_deadline`, `set_write_timeout`, `set_deadline`, `clear_write_deadline`,
  `clear_deadline`
- close ops: `close_write`, `cancel_write`, `close`, `close_with_error`

### `RecvStream` methods

- same identity/open metadata/address set as `Stream`
- read-only operations:
    - `read`, `read_vectored`, `read_timeout`, `read_vectored_timeout`, `read_exact_timeout`
- deadlines/timeouts: `set_read_deadline`, `set_read_timeout`, `set_deadline`, `clear_read_deadline`, `clear_deadline`
- close ops: `close_read`, `cancel_read`, `close`, `close_with_error`

### Async equivalents

All async operations in `zmux` mirror the synchronous API through trait aliases and async futures:

- `AsyncSession` methods:
    - `accept_stream*`, `accept_uni_stream*`, `open_stream*`, `open_uni_stream*`,
      `open_stream_with_options*`, `open_uni_stream_with_options*`
    - `open_and_send*`, `open_and_send_vectored*`, `open_and_send_with_options*`
    - `open_and_send_vectored_with_options*`
    - `open_uni_and_send*`, `open_uni_and_send_vectored*`, `open_uni_and_send_with_options*`
    - `open_uni_and_send_vectored_with_options*`
    - `close`, `close_with_error`, `wait`, `wait_timeout`, `closed`, `close_error`, `state`, `stats`
- async stream methods are the same set as sync versions, returning boxed futures:
    - `read/read_timeout`, `read_vectored/read_vectored_timeout`, `read_exact/read_exact_timeout`
    - `write/write_timeout`, `write_vectored/write_vectored_timeout`
    - `write_final/write_final_timeout`, `write_vectored_final`, `write_vectored_final_timeout`
    - `close_read`, `close_write`, `cancel_read`, `cancel_write`, `close`, `close_with_error`

### Errors and events

- `Error`, `Result`, `ErrorCode`, `ErrorDirection`, `ErrorOperation`, `ErrorScope`, `ErrorSource`
- `Error::` helper constructors and terminal/error kind enums from API (`TerminationKind`)
- `Event`, `EventType`, `StreamEventInfo`, `EventHandler`
- telemetry: `AbuseStats`, `AcceptBacklogStats`, `ActiveStreamStats`, `DiagnosticStats`,
  `FlushStats`, `HiddenStateStats`, `LivenessStats`, `MemoryStats`, `PressureStats`,
  `ProgressStats`, `ProvisionalStats`, `ReasonStats`, `RetentionStats`,
  `TelemetryStats`, `WriterQueueStats`

## Note

There is no `docs/` folder needed for normal use of this repo.
