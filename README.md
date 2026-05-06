# zmux

Rust implementation of the ZMux v1 single-link stream multiplexing protocol.

The workspace publishes two crates:

- `zmux`: native blocking ZMux sessions, runtime-neutral async traits, stable stream/session trait objects, wire codec helpers, and conformance helpers.
- `zmux-quinn`: optional async `quinn` adapter that implements the same async session/stream traits.

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

Use `zmux::Conn::new(...)` when both peers can use auto role negotiation on an already established reliable connection.

```rust
use std::net::TcpStream;

fn main() -> zmux::Result<()> {
    let socket = TcpStream::connect("127.0.0.1:9000")?;
    let session = zmux::Conn::new(socket)?;

    let stream = session.open_stream()?;
    stream.write_final(b"hello")?;

    let mut reply = [0u8; 1024];
    let _n = stream.read(&mut reply)?;

    session.close()?;
    Ok(())
}
```

Constructor choice:

- `Conn::new(transport)`: auto role negotiation with the default config.
- `Conn::client(transport)`: fixed initiator/client role with the default config.
- `Conn::server(transport)`: fixed responder/server role with the default config.
- `Conn::with_config(transport, config)`, `Conn::client_with_config(...)`, and `Conn::server_with_config(...)`: same constructors with an explicit `Config`.

`transport` is any `DuplexConnection`. Built-in implementations cover `TcpStream`, `(reader, writer)` pairs, boxed `DuplexConnection` values, and `DuplexTransport`. It is not limited to TCP: TLS streams, pipes, in-memory links, and custom reliable byte streams are supported when they can expose independent read/write handles and a real full-connection close operation.

Use the stable trait surfaces when application code should not depend on one concrete session type:

- `Conn` plus `Session`, `DuplexStreamHandle`, `SendStreamHandle`, `RecvStreamHandle`, `StreamHandle`: blocking API. Prefer concrete `Conn` when you own the transport; use the traits when type erasure or generic code is useful.
- `AsyncSession`, `AsyncDuplexStreamHandle`, `AsyncSendStreamHandle`, `AsyncRecvStreamHandle`, `AsyncStreamHandle`: runtime-neutral async API shared by native ZMux and adapters.

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
let (stream, _n) = session.open_and_send(b"\x01hello")?;
let (send, _n) = session.open_uni_and_send(b"\x02event")?;

let buf = vec![0x01, 0x02, 0x03];
let (stream, _n) = session.open_and_send(&buf)?;
```

`open_and_send(...)` opens a bidirectional stream and writes the whole first payload before returning; the stream remains open. `open_uni_and_send(...)` writes the final payload and closes the send side.

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

let config = Config::default().capabilities(capabilities);
let options = OpenOptions::new()
    .open_info(b"\x01\x00\x00\x2a")
    .priority(7)
    .group(2);

let stream = session.open_stream_with(options)?;
stream.update_metadata(MetadataUpdate::new().priority(3))?;
stream.write_final(b"hello")?;
```

Open info is opaque binary metadata. Pass a byte slice such as `&[u8]` / `&buf`, or pass an owned `Vec<u8>` to move it into the options without another caller-side copy. ZMux stores its own copy for borrowed metadata and owns the bytes once the stream is opened. Concrete sessions accept `OpenOptions` directly for open calls; trait-object and generic `Session` / `AsyncSession` code uses `OpenRequest` when timeout must travel with the options. The peer reads opener metadata through `stream.open_info()` or `stream.metadata()`. Use `append_open_info_to(&mut Vec<u8>)` to append the bytes into a reusable buffer without allocating a fresh `Vec`.

Stream payloads are binary bytes, not text. Reads follow the standard Rust I/O
shape: `read(&mut [u8])` fills caller-owned memory, while async callers can use
`read_to_end(&mut Vec<u8>)` / `read_to_end_limited(...)` when they want an owned
result buffer. Writes keep the TCP-style partial-write entry point as
`write(&[u8])`; because partial writes must leave the caller owning any unwritten
bytes, owned buffers are accepted by complete-consumption APIs instead:
`write_all(Vec<u8>)`, `write_final(Vec<u8>)`, and `open_uni_and_send(Vec<u8>)`.
For erased or generic send handles, pass `WritePayload::from(vec)` to
`SendStreamHandle::write_all(...)`, `SendStreamHandle::write_final(...)`, or
their async `AsyncSendStreamHandle` equivalents when ownership should travel
through the trait object.

Borrowed payloads are copied into native queued frames when ZMux must own data
past the call boundary. Owned payloads move into the operation and let native
ZMux avoid that queue copy when a whole frame can use the buffer directly; if
open metadata or fragmentation requires a combined frame payload, only that
fragment is copied.

## Custom Transports

Wrap split blocking halves directly:

```rust
let session = zmux::Conn::new((reader, writer))?;
```

Rust does not have a standard-library equivalent of Go's `net.Conn`: `Read` and
`Write` describe byte operations, but not splitting, timeouts, addresses, or
full-resource close. ZMux defines `DuplexConnection` for that boundary. The
native API accepts any `DuplexConnection`; built-in implementations cover
`TcpStream`, split `Read` / `Write` halves, boxed `DuplexConnection` values,
and `DuplexTransport`.

For TLS or other reliable byte streams, prefer the transport's own split API
and pass those halves to ZMux:

```rust
let session = zmux::Conn::client((tls_read_half, tls_write_half))?;
```

When a stream type exposes cloneable handles instead of split halves, build a
transport from the clone operation:

```rust
let transport = zmux::DuplexTransport::try_clone_with(tls_stream, |stream| {
    stream.try_clone()
})?;
let session = zmux::Conn::client(transport)?;
```

Use `DuplexTransport::from_cloneable(...)` when `Clone` itself creates an
independent read/write handle. If the underlying object must still be closed as
one resource, attach that close operation with `DuplexTransport::with_close_fn(...)`.
Avoid hiding one blocking duplex object behind a single `Mutex`: a blocking read
can hold the lock and prevent writes or close progress.

Custom connection types can implement `DuplexConnection` directly:

```rust
struct MyTlsConnection {
    // user-owned TLS stream state
}

impl zmux::DuplexConnection for MyTlsConnection {
    type Reader = MyTlsReadHalf;
    type Writer = MyTlsWriteHalf;

    fn into_transport(self) -> zmux::Result<zmux::DuplexTransport<Self::Reader, Self::Writer>> {
        let (reader, writer, close_handle) = self.into_split_with_close_handle()?;
        Ok(zmux::DuplexTransport::new(reader, writer)
            .with_close_fn(move || close_handle.close()))
    }
}

let session = zmux::Conn::client(my_tls_connection)?;
```

`Conn::close`, `Conn::close_with_error`, establishment failure, and runtime
shutdown call the transport close hook when one is present. Passing only split
halves drops/closes those halves according to their own types; attach
`with_close_fn(...)` or implement `DuplexConnection` when the original
underlying connection needs an explicit whole-resource shutdown.

Use `DuplexTransport` when the transport can expose addresses, timeouts, or a close hook:

```rust
let transport = zmux::DuplexTransport::new(reader, writer)
    .with_local_addr(local_addr)
    .with_peer_addr(peer_addr)
    .with_close_fn(close_transport);

let session = zmux::Conn::new(transport)?;
```

When addresses are discovered as optional values, use `with_addresses(local_addr, peer_addr)`.

Join existing stream halves when an API expects a duplex object:

```rust
let duplex = zmux::join_streams(recv_half, send_half);
let optional = zmux::DuplexStream::from_parts(Some(recv_half), Some(send_half));
```

Joined zmux stream halves are also `DuplexConnection` values when both halves
are present, so they can back another zmux session over an already established
outer reliable stream or pair of directional halves:

```rust
let transport = zmux::join_streams(recv_from_peer, send_to_peer);
let nested = zmux::Conn::client(transport)?;
```

Async equivalent is `join_async_streams(...)`; use `AsyncDuplexStream::from_parts(...)` when one side is optional. Closing a joined duplex stream closes both original halves, and skips the second close only when both halves report the same close identity.

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
    .capabilities(capabilities)
    .event_handler(|event| {
        let _ = event;
    });
```

`Settings` controls negotiated stream windows, incoming stream limits, frame payload limits, idle timeout hints, keepalive hints, scheduler hints, and padding keys.

`Config::default()` and `default_config()` return a copy of the process-wide
default template. Use `configure_default_config(...)` during startup when every
new session should inherit the same changes. Constructors without a `Config`
argument use that template; use `Conn::with_config(...)` or `Conn::*_with_config(...)`
when one session needs an explicit override:

```rust
zmux::configure_default_config(|config| {
    config.capabilities |= CAPABILITY_OPEN_METADATA;
    config.keepalive_interval = std::time::Duration::from_secs(30);
});
```

`reset_default_config()` restores the built-in template. Existing sessions keep
the config they were created with.

## Public API Surface

Root wrappers:

- `box_async_session`
- `closed_session`, `closed_async_session`
- `join_streams`
- `join_async_streams`

Configuration and open requests:

- `Config`, `OpenOptions`, `OpenRequest`, `OpenSend`, `WritePayload`, `Settings`, `SchedulerHint`
- `default_config`, `configure_default_config`, `reset_default_config`
- `default_settings`, `marshal_settings_tlv`, `parse_settings_tlv`
- `DEFAULT_PREFACE_PADDING_MIN_BYTES`, `DEFAULT_PREFACE_PADDING_MAX_BYTES`
- `DEFAULT_PING_PADDING_MIN_BYTES`, `DEFAULT_PING_PADDING_MAX_BYTES`
- `Config` methods: `initiator`, `responder`, `role`, `capabilities`, `enable_capabilities`, `settings`, `event_handler`, `normalized`, `local_preface`
- `OpenOptions` methods: `new`, `priority`, `group`, `open_info`, `initial_priority`, `initial_group`, `open_info_bytes`, `open_info_len`, `has_open_info`, `is_empty`, `validate`, `into_parts`
- `OpenRequest` methods: `new`, `options`, `timeout`, `open_options`, `timeout_duration`, `into_parts`
- `OpenSend` methods: `new`, `vectored`, `options`, `timeout`, `open_options`, `payload`, `timeout_duration`, `into_parts`
- `WritePayload` methods: `bytes`, `vectored`, `checked_len`, `is_empty`
- `Settings` methods: `limits`, `validate`, `encoded_tlv_len`, `append_tlv_to`
- `SchedulerHint` methods: `from_u64`, `as_u64`, `as_str`

Blocking session and stream types:

- `Conn`, `Stream`, `SendStream`, `RecvStream`
- `Session`, `DuplexStreamHandle`, `SendStreamHandle`, `RecvStreamHandle`, `StreamHandle`
- `BoxSession`, `BoxDuplexStream`, `BoxSendStream`, `BoxRecvStream`
- `ClosedSession`
- `DuplexStream`, `DuplexInfoSide`, `PausedHalf`, `PausedRecvHalf`, `PausedSendHalf`
- joined native stream methods: `new`, `from_parts`, `empty`, `with_info_side`, `info_side`, `recv`, `send`, `into_parts`, `pause_read`, `pause_read_timeout`, `pause_write`, `pause_write_timeout`, `replace_recv`, `replace_send`, `detach_recv`, `detach_send`, `read_stream_id`, `write_stream_id`
- paused native half methods: `current`, `current_mut`, `take`, `set`, `replace`, `resume`

Async session and stream types:

- `AsyncSession`
- `AsyncDuplexStreamHandle`, `AsyncSendStreamHandle`, `AsyncRecvStreamHandle`, `AsyncStreamHandle`
- `BoxAsyncSession`, `BoxAsyncDuplexStream`, `BoxAsyncSendStream`, `BoxAsyncRecvStream`
- `ClosedAsyncSession`
- `AsyncDuplexStream`, `AsyncBoxFuture`
- `PausedAsyncHalf`, `PausedAsyncRecvHalf`, `PausedAsyncSendHalf`
- `AsyncIo`
- `AsyncIo` methods: `new`, `from_arc`, `get_ref`, `as_arc`, `into_inner`, `read_chunk_size`, `set_read_chunk_size`, `write_chunk_size`, `set_write_chunk_size`
- joined async stream methods: `new`, `from_parts`, `empty`, `with_info_side`, `info_side`, `recv`, `send`, `into_parts`, `pause_read`, `pause_read_timeout`, `pause_write`, `pause_write_timeout`, `replace_recv`, `replace_send`, `detach_recv`, `detach_send`, `read_stream_id`, `write_stream_id`
- paused async half methods: `current`, `take`, `set`, `set_arc`, `replace`, `resume`

Session methods:

- open/accept: `accept_stream`, `accept_stream_timeout`, `accept_uni_stream`, `accept_uni_stream_timeout`, `open_stream`, `open_uni_stream`, `open_stream_with`, `open_uni_stream_with`; concrete sessions accept `OpenOptions` directly, use `OpenRequest::new`, `OpenRequest::options`, and `OpenRequest::timeout` when open metadata and timeout must be carried through trait-object or generic APIs
- open and write: `open_and_send`, `open_uni_and_send`; concrete sessions accept byte buffers such as `&[u8]`, `&Vec<u8>`, and `Vec<u8>` directly, use `OpenSend::new`, `OpenSend::vectored`, `OpenSend::options`, and `OpenSend::timeout` when payload shape, open metadata, or timeout must be carried through trait-object or generic APIs
- lifecycle: `close`, `close_with_error`, `wait`, `wait_timeout`, `is_closed`, `close_error`, `state`, `stats`
- session controls: `ping`, `ping_timeout`, `go_away`, `go_away_with_error`, `peer_go_away_error`, `peer_close_error`, `local_preface`, `peer_preface`, `negotiated`
- addresses: `local_addr`, `peer_addr`

Stream methods:

- identity/info: `stream_id`, `is_opened_locally`, `is_bidirectional`, `open_info`, `append_open_info_to`, `open_info_len`, `has_open_info`, `metadata`, `local_addr`, `peer_addr`; open info is opaque bytes, not text, and `append_open_info_to` appends to the caller's buffer
- read side: `read`, `read_vectored`, `read_timeout`, `read_vectored_timeout`, `read_exact_timeout`, `is_read_closed`, `set_read_deadline`, `set_read_timeout`, `close_read`, `cancel_read`
- write side: `write`, `write_timeout`, `write_all`, `write_all_timeout`, `write_vectored`, `write_vectored_timeout`, `write_final`, `write_final_timeout`, `write_vectored_final`, `write_vectored_final_timeout`, `is_write_closed`, `set_write_deadline`, `set_write_timeout`, `update_metadata`, `close_write`, `cancel_write`
- async read/write helpers: `read_exact`, `read_to_end`, `read_to_end_limited`
- combined stream helpers: `set_deadline`, `set_timeout`, `close`, `close_with_error`
- `SendStream` exposes write-side methods. `RecvStream` exposes read-side methods. `Stream` exposes both.

Wire codec and protocol helpers:

- `Role`, `Preface`, `Negotiated`
- `Role` methods: `from_u8`, `as_u8`, `as_str`
- `Preface` methods: `has_capability`, `supports_open_metadata`, `supports_priority_update`, `can_carry_open_info`, `can_carry_priority_on_open`, `can_carry_group_on_open`, `can_carry_priority_in_update`, `can_carry_group_in_update`, `has_peer_visible_priority_semantics`, `has_peer_visible_group_semantics`, `marshal`, `marshal_with_settings_padding`, `parse`
- `Negotiated` methods: `has_capability`, `supports_open_metadata`, `supports_priority_update`, `can_carry_open_info`, `can_carry_priority_on_open`, `can_carry_group_on_open`, `can_carry_priority_in_update`, `can_carry_group_in_update`, `has_peer_visible_priority_semantics`, `has_peer_visible_group_semantics`
- `parse_preface`, `parse_preface_prefix`, `read_preface`, `negotiate_prefaces`, `resolve_roles`
- `Frame`, `FrameView`, `FrameType`, `Limits`, `FRAME_FLAG_FIN`, `FRAME_FLAG_OPEN_METADATA`
- `FrameType` methods: `from_u8`, `as_u8`, `as_str`
- `Limits` methods: `normalized`, `inbound_payload_limit`
- `Frame` methods: `new`, `with_flags`, `code`, `as_view`, `marshal`, `encoded_len`, `append_to`, `parse`, `validate`
- `FrameView` methods: `code`, `try_to_owned`, `parse`, `validate`
- `parse_frame`, `read_frame`
- `append_varint`, `encode_varint`, `encode_varint_to_slice`, `parse_varint`, `read_varint`, `varint_len`, `MAX_VARINT62`, `MAX_VARINT_LEN`
- `Tlv`, `TlvView`, `append_tlv`, `parse_tlvs`, `parse_tlvs_view`, `visit_tlvs`
- `Tlv` methods: `new`, `as_view`, `is_empty`, `validate`, `encoded_len`, `append_to`
- `TlvView` methods: `is_empty`, `validate`, `encoded_len`, `append_to`, `try_to_owned`
- `DataPayload`, `DataPayloadView`, `GoAwayPayload`, `MetadataUpdate`, `StreamMetadata`, `StreamMetadataView`
- `StreamMetadata` methods: `as_view`, `open_info`, `open_info_len`, `has_open_info`, `is_empty`
- `StreamMetadataView` methods: `open_info`, `open_info_len`, `has_open_info`, `is_empty`, `try_to_owned`
- `MetadataUpdate` methods: `new`, `priority`, `group`, `is_empty`, `validate`
- `build_code_payload`, `build_go_away_payload`, `build_open_metadata_prefix`, `build_priority_update_payload`
- `parse_data_payload`, `parse_data_payload_view`, `parse_error_payload`, `parse_go_away_payload`, `parse_priority_update_payload`, `parse_stream_metadata_tlvs`, `parse_stream_metadata_bytes_view`

Protocol constants and capability helpers:

- `MAGIC`, `PREFACE_VERSION`, `PROTO_VERSION`, `MAX_PREFACE_SETTINGS_BYTES`
- `CAPABILITY_OPEN_METADATA`, `CAPABILITY_PRIORITY_HINTS`, `CAPABILITY_PRIORITY_UPDATE`, `CAPABILITY_STREAM_GROUPS`, `CAPABILITY_MULTILINK_BASIC`, `CAPABILITY_MULTILINK_BASIC_RETIRED`
- `EXT_PRIORITY_UPDATE`, `EXT_ML_READY_RETIRED`, `EXT_ML_ATTACH_RETIRED`, `EXT_ML_ATTACH_ACK_RETIRED`, `EXT_ML_DRAIN_REQ_RETIRED`, `EXT_ML_DRAIN_ACK_RETIRED`
- `METADATA_STREAM_PRIORITY`, `METADATA_STREAM_GROUP`, `METADATA_OPEN_INFO`
- `DIAG_DEBUG_TEXT`, `DIAG_RETRY_AFTER_MILLIS`, `DIAG_OFFENDING_STREAM_ID`, `DIAG_OFFENDING_FRAME_TYPE`
- `SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED`, `SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED`, `SETTING_INITIAL_MAX_STREAM_DATA_UNI`, `SETTING_INITIAL_MAX_DATA`, `SETTING_MAX_INCOMING_STREAMS_BIDI`, `SETTING_MAX_INCOMING_STREAMS_UNI`, `SETTING_MAX_FRAME_PAYLOAD`, `SETTING_IDLE_TIMEOUT_MILLIS`, `SETTING_KEEPALIVE_HINT_MILLIS`, `SETTING_MAX_CONTROL_PAYLOAD_BYTES`, `SETTING_MAX_EXTENSION_PAYLOAD_BYTES`, `SETTING_SCHEDULER_HINTS`, `SETTING_PING_PADDING_KEY`, `SETTING_PREFACE_PADDING`
- `has_capability`, `capabilities_support_open_metadata`, `capabilities_support_priority_update`
- `capabilities_can_carry_open_info`, `capabilities_can_carry_priority_on_open`, `capabilities_can_carry_group_on_open`, `capabilities_can_carry_priority_in_update`, `capabilities_can_carry_group_in_update`
- `capabilities_have_peer_visible_priority_semantics`, `capabilities_have_peer_visible_group_semantics`

Errors, events, diagnostics, and conformance:

- `Error`, `Result`, `ErrorCode`, `ErrorScope`, `ErrorOperation`, `ErrorSource`, `ErrorDirection`, `TerminationKind`
- enum helpers: `ErrorCode::from_u64`, `ErrorCode::as_u64`, `ErrorCode::as_str`; `ErrorScope::as_str`; `ErrorOperation::as_str`; `ErrorSource::as_str`; `ErrorDirection::as_str`; `TerminationKind::as_str`
- `Error` constructors: `new`, `local`, `protocol`, `frame_size`, `unsupported_version`, `role_conflict`, `flow_control`, `stream_state`, `stream_closed`, `read_closed`, `write_closed`, `session_closed`, `application`, `try_application`, `io`, `timeout`, `graceful_close_timeout`
- `Error` accessors: `code`, `application_code`, `numeric_code`, `reason`, `message`, `source_io_error_kind`, `scope`, `operation`, `source`, `direction`, `termination_kind`, `io_error_kind`
- `Error` classification helpers: `is_error_code`, `is_application_code`, `is_session_closed`, `is_timeout`, `is_interrupted`, `is_stream_not_readable`, `is_stream_not_writable`, `is_read_closed`, `is_write_closed`, `is_open_limited`, `is_open_expired`, `is_open_info_unavailable`, `is_open_metadata_too_large`, `is_adapter_unsupported`, `is_priority_update_unavailable`, `is_priority_update_too_large`, `is_empty_metadata_update`, `is_keepalive_timeout`, `is_graceful_close_timeout`
- `Error` context helpers: `with_scope`, `with_operation`, `with_source`, `with_direction`, `with_termination_kind`, `with_session_context`, `with_stream_context`
- `Event`, `EventType`, `EventHandler`, `StreamEventInfo`
- event helpers: `EventType::as_str`, `StreamEventInfo::open_info`, `StreamEventInfo::open_info_len`, `StreamEventInfo::has_open_info`
- `SessionState`, `SessionStats`, `PeerCloseError`, `PeerGoAwayError`
- `AbuseStats`, `AcceptBacklogStats`, `ActiveStreamStats`, `DiagnosticStats`, `FlushStats`, `HiddenStateStats`, `LivenessStats`, `MemoryStats`, `PressureStats`, `ProgressStats`, `ProvisionalStats`, `ReasonStats`, `RetentionStats`, `TelemetryStats`, `WriterQueueStats`
- `DuplexConnection`, `DuplexTransport`, `DuplexTransportControl`
- `DuplexTransport` methods: `new`, `from_cloneable`, `try_clone_with`, `with_local_addr`, `with_peer_addr`, `with_addresses`, `with_control`, `with_close_fn`, `local_addr`, `peer_addr`, `set_read_timeout`, `set_write_timeout`, `close`, `reader`, `reader_mut`, `writer`, `writer_mut`, `into_parts`
- `Claim`, `ConformanceSuite`, `ImplementationProfile`, `ParseConformanceError`
- conformance methods: `Claim::as_str`, `Claim::acceptance_checklist`, `Claim::required_conformance_suites`, `ImplementationProfile::as_str`, `ImplementationProfile::claims`, `ImplementationProfile::acceptance_checklist`, `ImplementationProfile::required_conformance_suites`, `ImplementationProfile::release_certification_gate`, `ConformanceSuite::as_str`
- `known_claims`, `known_conformance_suites`, `known_implementation_profiles`, `core_module_target_claims`, `core_module_target_suites`, `core_module_target_implementation_profiles`, `reference_profile_claim_gate`

## Semantics

- Successful native ZMux complete-write calls wait for the local writer path to flush the framed data to its backend. Adapter writes wait for the adapter's backend future. Neither form is a peer application acknowledgement.
- Borrowed buffers passed to write/open-and-send methods are not retained after the call returns. Owned buffers are consumed by the operation.
- `close_write()` finishes only the local send half.
- `close_read()` cancels local interest in inbound bytes.
- Open metadata is sent only when negotiated; required but unavailable metadata fails instead of being silently discarded.

## Unified async interface

Use `zmux::AsyncSession` and `zmux::BoxAsyncSession` when upper layers need one storage path for native zmux sessions and adapter-backed sessions. Native `zmux::Conn` implements the trait directly, and adapters such as `zmux_quinn::QuinnSession` implement the same async trait.

```rust
let native: zmux::BoxAsyncSession = zmux::box_async_session(native_conn);
let quic: zmux::BoxAsyncSession = zmux::box_async_session(quinn_session);

let sessions: Vec<zmux::BoxAsyncSession> = vec![native, quic];
```

Use `zmux::AsyncDuplexStreamHandle`, `zmux::AsyncSendStreamHandle`, and `zmux::AsyncRecvStreamHandle` for heterogeneous async stream storage. Blocking/native code can use the short `Session`, `DuplexStreamHandle`, `SendStreamHandle`, and `RecvStreamHandle` names.
