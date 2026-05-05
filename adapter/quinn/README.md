# zmux-quinn

`zmux-quinn` wraps an established `quinn::Connection` behind the async `zmux::Session` API.

It is an adapter over QUIC streams. It does not create QUIC connections and it does not expose native ZMux wire-session controls such as `ping`, `goaway`, prefaces, or negotiated native settings.

## Installation

```toml
[dependencies]
zmux = "VERSION"
zmux-quinn = "VERSION"
quinn = "QUINN_VERSION"
tokio = "TOKIO_VERSION"
```

Enable the Quinn runtime and TLS features your application needs. The adapter itself keeps Quinn default features disabled.

## Usage

```rust
use std::time::Duration;
use zmux::Session;
use zmux_quinn::{wrap_session_with_options, SessionOptions};

async fn run(conn: quinn::Connection) -> zmux::Result<()> {
    let options = SessionOptions::new()
        .with_accepted_prelude_read_timeout(Duration::from_secs(2))
        .with_accepted_prelude_max_concurrent(16);

    let session = wrap_session_with_options(conn, options);
    let stream = session.open_stream().await?;
    stream.write_final(b"hello").await?;
    session.close();
    Ok(())
}
```

Use `wrap_session(...)` when default adapter options are enough.

## Options

```rust
use zmux_quinn::SessionOptions;

let options = SessionOptions::new()
    .with_accepted_prelude_read_timeout(timeout)
    .with_accepted_prelude_max_concurrent(max_concurrent)
    .with_addresses(local_addr, peer_addr);
```

`accepted_prelude_read_timeout`:

- default: `DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT`
- `without_accepted_prelude_read_timeout()`: disables the adapter-managed read timeout
- accepted QUIC streams whose adapter prelude never arrives in time are discarded instead of blocking later ready streams

`accepted_prelude_max_concurrent`:

- default: `default_accepted_prelude_max_concurrent()`
- capped by `MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- controls how many accepted QUIC streams may parse adapter preludes concurrently

## Stable API Coverage

`QuinnSession` implements the async `zmux::Session` surface:

- open/accept: `accept_stream`, `accept_stream_timeout`, `accept_uni_stream`, `accept_uni_stream_timeout`, `open_stream`, `open_stream_timeout`, `open_uni_stream`, `open_uni_stream_timeout`, `open_stream_with_options`, `open_stream_with_options_timeout`, `open_uni_stream_with_options`, `open_uni_stream_with_options_timeout`
- open and write: `open_and_send`, `open_and_send_timeout`, `open_and_send_with_options`, `open_and_send_with_options_timeout`, `open_and_send_vectored`, `open_and_send_vectored_timeout`, `open_and_send_vectored_with_options`, `open_and_send_vectored_with_options_timeout`, `open_uni_and_send`, `open_uni_and_send_timeout`, `open_uni_and_send_with_options`, `open_uni_and_send_with_options_timeout`, `open_uni_and_send_vectored`, `open_uni_and_send_vectored_timeout`, `open_uni_and_send_vectored_with_options`, `open_uni_and_send_vectored_with_options_timeout`
- lifecycle: `close`, `close_with_error`, `wait`, `wait_timeout`, `closed`, `close_error`, `state`, `stats`
- addresses: `local_addr`, `peer_addr`, `remote_addr`

Wrapped streams expose `zmux::StreamApi`, `zmux::SendStreamApi`, and `zmux::RecvStreamApi` methods:

- identity/info: `stream_id`, `opened_locally`, `bidirectional`, `open_info`, `copy_open_info_to`, `open_info_len`, `has_open_info`, `metadata`, `local_addr`, `peer_addr`, `remote_addr`
- read: `read`, `read_timeout`, `read_exact`, `read_exact_timeout`, `read_vectored`, `readv`, `read_vectored_timeout`, `readv_timeout`, `read_closed`, `set_read_deadline`, `set_read_timeout`, `close_read`, `cancel_read`
- write: `write`, `write_all`, `write_timeout`, `write_vectored`, `writev`, `write_vectored_timeout`, `writev_timeout`, `write_final`, `write_final_timeout`, `write_vectored_final`, `writev_final`, `write_vectored_final_timeout`, `writev_final_timeout`, `write_chunks_final`, `write_closed`, `set_write_deadline`, `set_write_timeout`, `update_metadata`, `close_write`, `cancel_write`
- combined helpers: `set_deadline`, `set_timeout`, `close`, `close_with_error`

`QuinnStream` exposes both read and write methods. `QuinnSendStream` exposes write methods. `QuinnRecvStream` exposes read methods.

## Mapping

- `open_stream(...)` and `accept_stream(...)` map to QUIC bidirectional streams.
- `open_uni_stream(...)` and `accept_uni_stream(...)` map to QUIC unidirectional streams.
- Open-time ZMux metadata is carried in an adapter prelude: `varint(metadata_len)` followed by stream metadata TLVs.
- `OpenOptions` supports open info, initial priority, and initial group.
- `open_info()` and `metadata()` expose decoded opener metadata on accepted streams.
- `update_metadata(...)` works only before the local stream prelude is emitted. Later updates fail with `PriorityUpdateUnavailable`.
- `close_read()` maps to QUIC read-side cancellation with `ErrorCode::Cancelled`.
- `cancel_read(code)` maps to QUIC read-side cancellation with that code.
- `close_write()` maps to QUIC send-side graceful close.
- `cancel_write(code)` maps to QUIC send-side reset with that code.
- `close_with_error(code, reason)` is best-effort at stream scope.
- QUIC application error codes are 32-bit. Codes outside the Quinn varint range fail with `AdapterUnsupported`.

## Errors

- QUIC connection application closes are normalized to `zmux::Error::application(...)`.
- QUIC stream reset/cancel codes are surfaced as application errors where Quinn exposes the numeric code.
- QUIC stream-limit failures are normalized to `OpenLimited`.
- QUIC transport or connection closure is normalized into the stable `zmux::Error` surface.

Use `zmux::Error` helpers such as `is_application_code(...)`, `is_open_limited()`, `is_adapter_unsupported()`, `is_priority_update_unavailable()`, `is_session_closed()`, `is_read_closed()`, `is_write_closed()`, and `is_timeout()` instead of depending on Quinn error variants.

## Public API Surface

Top-level entry points:

- `wrap_session`
- `wrap_session_with_options`
- `wrap_session_with_addresses`
- `target_claims`
- `target_implementation_profiles`
- `target_suites`

Options and prelude helpers:

- `SessionOptions`
- `SessionOptions::new`
- `SessionOptions::with_accepted_prelude_read_timeout`
- `SessionOptions::without_accepted_prelude_read_timeout`
- `SessionOptions::with_accepted_prelude_max_concurrent`
- `SessionOptions::with_local_addr`
- `SessionOptions::with_peer_addr`
- `SessionOptions::with_addresses`
- `build_stream_prelude`
- `read_stream_prelude`
- `AcceptedStreamMetadata`
- `AcceptedStreamMetadata::metadata`
- `AcceptedStreamMetadata::is_metadata_valid`
- `AcceptedStreamMetadata::open_info`
- `AcceptedStreamMetadata::has_open_info`
- `default_accepted_prelude_max_concurrent`
- `set_default_accepted_prelude_max_concurrent`

Types:

- `QuinnSession`
- `QuinnStream`
- `QuinnSendStream`
- `QuinnRecvStream`

`QuinnSession` methods:

- construction: `new`, `with_options`
- addresses: `local_addr`, `peer_addr`, `remote_addr`
- open/accept: `accept_stream`, `accept_stream_timeout`, `accept_uni_stream`, `accept_uni_stream_timeout`, `open_stream`, `open_stream_timeout`, `open_uni_stream`, `open_uni_stream_timeout`, `open_stream_with_options`, `open_stream_with_options_timeout`, `open_uni_stream_with_options`, `open_uni_stream_with_options_timeout`
- open and write: `open_and_send`, `open_and_send_timeout`, `open_and_send_with_options`, `open_and_send_with_options_timeout`, `open_and_send_vectored`, `open_and_send_vectored_timeout`, `open_and_send_vectored_with_options`, `open_and_send_vectored_with_options_timeout`, `open_uni_and_send`, `open_uni_and_send_timeout`, `open_uni_and_send_with_options`, `open_uni_and_send_with_options_timeout`, `open_uni_and_send_vectored`, `open_uni_and_send_vectored_timeout`, `open_uni_and_send_vectored_with_options`, `open_uni_and_send_vectored_with_options_timeout`
- lifecycle: `close`, `close_with_error`, `wait`, `wait_timeout`, `closed`, `close_error`, `state`, `stats`

`QuinnStream` methods:

- identity/info: `stream_id`, `opened_locally`, `bidirectional`, `read_closed`, `write_closed`, `metadata`, `open_info`, `copy_open_info_to`, `open_info_len`, `has_open_info`, `local_addr`, `peer_addr`, `remote_addr`
- deadlines: `set_read_deadline`, `set_write_deadline`, `set_deadline`, `set_read_timeout`, `set_write_timeout`, `set_timeout`
- metadata: `update_metadata`
- read: `read`, `read_timeout`, `read_exact`, `read_exact_timeout`, `read_vectored`, `readv`, `read_vectored_timeout`, `readv_timeout`, `close_read`, `cancel_read`
- write: `write`, `write_all`, `write_timeout`, `write_vectored`, `writev`, `write_vectored_timeout`, `writev_timeout`, `write_final`, `write_final_timeout`, `write_vectored_final`, `writev_final`, `write_vectored_final_timeout`, `writev_final_timeout`, `write_chunks_final`, `close_write`, `cancel_write`
- close/error: `close`, `close_with_error`

`QuinnSendStream` methods:

- identity/info: `stream_id`, `opened_locally`, `bidirectional`, `write_closed`, `metadata`, `open_info`, `copy_open_info_to`, `open_info_len`, `has_open_info`, `local_addr`, `peer_addr`, `remote_addr`
- deadlines: `set_write_deadline`, `set_deadline`, `set_write_timeout`, `set_timeout`
- metadata: `update_metadata`
- write: `write`, `write_all`, `write_timeout`, `write_vectored`, `writev`, `write_vectored_timeout`, `writev_timeout`, `write_final`, `write_final_timeout`, `write_vectored_final`, `writev_final`, `write_vectored_final_timeout`, `writev_final_timeout`, `write_chunks_final`, `close_write`, `cancel_write`
- close/error: `close`, `close_with_error`

`QuinnRecvStream` methods:

- identity/info: `stream_id`, `opened_locally`, `bidirectional`, `read_closed`, `metadata`, `open_info`, `copy_open_info_to`, `open_info_len`, `has_open_info`, `local_addr`, `peer_addr`, `remote_addr`
- deadlines: `set_read_deadline`, `set_deadline`, `set_read_timeout`, `set_timeout`
- read: `read`, `read_timeout`, `read_exact`, `read_exact_timeout`, `read_vectored`, `readv`, `read_vectored_timeout`, `readv_timeout`, `close_read`, `cancel_read`
- close/error: `close_with_error`

Constants:

- `STREAM_PRELUDE_MAX_PAYLOAD`
- `QUINN_WRITEV_COALESCE_MAX_BYTES`
- `OPEN_METADATA_CAPABILITIES`
- `DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT`
- `DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- `MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- `ACCEPTED_PRELUDE_RESULT_QUEUE_CAP`

Adapter-specific stream helper:

- `write_chunks_final`

## Reduced Behavior

- No native ZMux session helpers such as `ping`, `goaway`, `peer_goaway_error`, `peer_close_error`, `local_preface`, `peer_preface`, or `negotiated`.
- No post-open native advisory frames such as native `PRIORITY_UPDATE`.
- No QUIC datagram, packet acknowledgement, RTT, or loss-state API.
- `stats()` reports adapter-visible counters. It cannot expose native ZMux runtime internals that do not exist in QUIC.

## Conformance

`target_claims()`, `target_implementation_profiles()`, and `target_suites()` provide adapter conformance metadata for tests that exercise the stable ZMux session contract over Quinn.
