# zmux-quinn

`zmux-quinn` wraps an established `quinn::Connection` behind the async `zmux::AsyncSession` API.

It is an adapter over QUIC streams. It does not create QUIC connections and it cannot implement native ZMux wire-session controls such as `ping`, `go_away`, prefaces, or negotiated native settings; those methods are exposed through the shared `zmux::AsyncSession` trait and return adapter-unsupported errors or empty snapshots.

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
use zmux::AsyncSession;
use zmux_quinn::{QuinnSession, SessionOptions};

async fn run(conn: quinn::Connection) -> zmux::Result<()> {
    let options = SessionOptions::new()
        .with_accepted_prelude_read_timeout(Duration::from_secs(2))
        .with_accepted_prelude_max_concurrent(16);

    let session = QuinnSession::with_options(conn, options);
    let stream = session.open_stream().await?;
    stream.write_final(b"hello").await?;
    session.close().await?;
    Ok(())
}
```

Use `QuinnSession::new(conn)` when default adapter options are enough.

## Options

```rust
use zmux_quinn::SessionOptions;

let options = SessionOptions::new()
    .with_accepted_prelude_read_timeout(timeout)
    .with_accepted_prelude_max_concurrent(max_concurrent)
    .with_local_addr(local_addr)
    .with_peer_addr(peer_addr);

let _disabled = SessionOptions::new().disable_accepted_prelude_read_timeout();
```

`accepted_prelude_read_timeout`:

- default: `AcceptedPreludeReadTimeout::Default`, which resolves to `DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT`
- explicit timeout: `AcceptedPreludeReadTimeout::Timeout(duration)` or `with_accepted_prelude_read_timeout(duration)`
- disabled: `AcceptedPreludeReadTimeout::Disabled`
- `disable_accepted_prelude_read_timeout()`: disables the adapter-managed read timeout
- accepted QUIC streams whose adapter prelude never arrives in time are discarded instead of blocking later ready streams

`accepted_prelude_max_concurrent`:

- default: `default_accepted_prelude_max_concurrent()`, initially `DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- capped by `MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- `set_default_accepted_prelude_max_concurrent(max)` changes the process-wide default used when a session does not override this option; pass `0` to restore the built-in default
- controls how many accepted QUIC streams may parse adapter preludes concurrently

## Stable API Coverage

`QuinnSession` implements the async `zmux::AsyncSession` surface:

- open/accept: `accept_stream`, `accept_stream_timeout`, `accept_uni_stream`, `accept_uni_stream_timeout`, `open_stream`, `open_uni_stream`, `open_stream_with`, `open_uni_stream_with`; concrete `QuinnSession` accepts `zmux::OpenOptions` directly, use `zmux::OpenRequest::new`, `OpenRequest::with_options`, and `OpenRequest::with_timeout` when open metadata and timeout must be carried through trait/object-safe APIs
- open and write: `open_and_send`, `open_uni_and_send`; concrete `QuinnSession` accepts byte buffers such as `&[u8]`, `&Vec<u8>`, and `Vec<u8>` directly, use `zmux::OpenSend::new`, `zmux::OpenSend::vectored`, `OpenSend::with_options`, and `OpenSend::with_timeout` when payload shape, open metadata, or timeout must be carried through trait/object-safe APIs
- lifecycle: `close`, `close_with_error`, `wait`, `wait_timeout`, `is_closed`, `close_error`, `state`, `stats`
- addresses: `local_addr`, `peer_addr`

Wrapped streams expose `zmux::AsyncStreamApi`, `zmux::AsyncSendStreamApi`, and `zmux::AsyncRecvStreamApi` methods:

- identity/info: `stream_id`, `is_opened_locally`, `is_bidirectional`, `open_info`, `append_open_info_to`, `open_info_len`, `has_open_info`, `metadata`, `local_addr`, `peer_addr`
- read: `read`, `read_timeout`, `read_exact`, `read_exact_timeout`, `read_vectored`, `read_vectored_timeout`, `is_read_closed`, `set_read_deadline`, `set_read_timeout`, `close_read`, `cancel_read`
- write: `write`, `write_all`, `write_all_timeout`, `write_timeout`, `write_vectored`, `write_vectored_timeout`, `write_final`, `write_final_timeout`, `write_vectored_final`, `write_vectored_final_timeout`, `write_chunks_final`, `is_write_closed`, `set_write_deadline`, `set_write_timeout`, `update_metadata`, `close_write`, `cancel_write`
- combined helpers: `set_deadline`, `set_timeout`, `close`, `close_with_error`

`QuinnStream` exposes both read and write methods. `QuinnSendStream` exposes write methods. `QuinnRecvStream` exposes read methods.

Payloads are binary bytes. `write(&[u8])` keeps the normal QUIC/TCP partial-write
shape, so it borrows caller memory. Complete-consumption calls such as
`write_all(Vec<u8>)`, `write_final(Vec<u8>)`, and `open_uni_and_send(Vec<u8>)` can
move owned buffers into the async operation and avoid an extra adapter-level
copy. Bidirectional `open_and_send(...)` intentionally performs one stream write
and returns the number of bytes Quinn accepted, so flow control may make it
consume only part of a larger payload. Quinn still owns its transport buffering
and completion semantics.
When using `zmux::AsyncSendStreamApi` through generics or trait objects, call
`write_all(WritePayload::from(vec))` or `write_final(WritePayload::from(vec))`
to preserve owned-buffer intent.

## Mapping

- `open_stream(...)` and `accept_stream(...)` map to QUIC bidirectional streams.
- `open_uni_stream(...)` and `accept_uni_stream(...)` map to QUIC unidirectional streams.
- Open-time ZMux metadata is carried in an adapter prelude: `varint(metadata_len)` followed by stream metadata TLVs.
- `OpenOptions` supports opaque binary open info, initial priority, and initial group.
- `open_info()` and `metadata()` expose decoded opener metadata as bytes on accepted streams; `append_open_info_to(...)` appends those bytes into a reusable buffer.
- `update_metadata(...)` works only before the local stream prelude is emitted. Later updates fail with `PriorityUpdateUnavailable`.
- `close_read()` maps to QUIC read-side cancellation with `ErrorCode::Cancelled`.
- `cancel_read(code)` maps to QUIC read-side cancellation with that code.
- `close_write()` maps to QUIC send-side graceful close.
- `cancel_write(code)` maps to QUIC send-side reset with that code.
- `close_with_error(code, reason)` is best-effort at stream scope.
- QUIC application error codes use Quinn varints. Codes outside the Quinn varint range fail with `AdapterUnsupported`.

## Errors

- QUIC connection application closes are normalized to `zmux::Error::application(...)`.
- QUIC stream reset/cancel codes are surfaced as application errors where Quinn exposes the numeric code.
- QUIC stream-limit failures are normalized to `OpenLimited`.
- QUIC transport or connection closure is normalized into the stable `zmux::Error` surface.

Use `zmux::Error` helpers such as `is_application_code(...)`, `is_open_limited()`, `is_adapter_unsupported()`, `is_priority_update_unavailable()`, `is_session_closed()`, `is_read_closed()`, `is_write_closed()`, and `is_timeout()` instead of depending on Quinn error variants.

## Public API Surface

Top-level entry points:

- `target_claims`
- `target_implementation_profiles`
- `target_suites`
- `default_accepted_prelude_max_concurrent`
- `set_default_accepted_prelude_max_concurrent`

Options and prelude helpers:

- `AcceptedPreludeReadTimeout`
- `SessionOptions`
- `SessionOptions::new`
- `SessionOptions::with_accepted_prelude_read_timeout`
- `SessionOptions::disable_accepted_prelude_read_timeout`
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

Types:

- `QuinnSession`
- `QuinnSession::new`
- `QuinnSession::with_options`
- `QuinnStream`
- `QuinnSendStream`
- `QuinnRecvStream`

`QuinnSession` methods:

- construction: `new`, `with_options`
- addresses: `local_addr`, `peer_addr`
- open/accept: `accept_stream`, `accept_stream_timeout`, `accept_uni_stream`, `accept_uni_stream_timeout`, `open_stream`, `open_uni_stream`, `open_stream_with`, `open_uni_stream_with`; concrete `QuinnSession` accepts `zmux::OpenOptions` directly, use `zmux::OpenRequest::new`, `OpenRequest::with_options`, and `OpenRequest::with_timeout`
- open and write: `open_and_send`, `open_uni_and_send`; concrete `QuinnSession` accepts byte buffers such as `&[u8]`, `&Vec<u8>`, and `Vec<u8>` directly, use `zmux::OpenSend::new`, `zmux::OpenSend::vectored`, `OpenSend::with_options`, and `OpenSend::with_timeout`
- lifecycle: `close`, `close_with_error`, `wait`, `wait_timeout`, `is_closed`, `close_error`, `state`, `stats`

`QuinnStream` methods:

- identity/info: `stream_id`, `is_opened_locally`, `is_bidirectional`, `is_read_closed`, `is_write_closed`, `metadata`, `open_info`, `append_open_info_to`, `open_info_len`, `has_open_info`, `local_addr`, `peer_addr`
- deadlines: `set_read_deadline`, `set_write_deadline`, `set_deadline`, `set_read_timeout`, `set_write_timeout`, `set_timeout`
- metadata: `update_metadata`
- read: `read`, `read_timeout`, `read_exact`, `read_exact_timeout`, `read_vectored`, `read_vectored_timeout`, `close_read`, `cancel_read`
- write: `write`, `write_all`, `write_all_timeout`, `write_timeout`, `write_vectored`, `write_vectored_timeout`, `write_final`, `write_final_timeout`, `write_vectored_final`, `write_vectored_final_timeout`, `write_chunks_final`, `close_write`, `cancel_write`
- close/error: `close`, `close_with_error`

`QuinnSendStream` methods:

- identity/info: `stream_id`, `is_opened_locally`, `is_bidirectional`, `is_write_closed`, `metadata`, `open_info`, `append_open_info_to`, `open_info_len`, `has_open_info`, `local_addr`, `peer_addr`
- deadlines: `set_write_deadline`, `set_deadline`, `set_write_timeout`, `set_timeout`
- metadata: `update_metadata`
- write: `write`, `write_all`, `write_all_timeout`, `write_timeout`, `write_vectored`, `write_vectored_timeout`, `write_final`, `write_final_timeout`, `write_vectored_final`, `write_vectored_final_timeout`, `write_chunks_final`, `close_write`, `cancel_write`
- close/error: `close`, `close_with_error`

`QuinnRecvStream` methods:

- identity/info: `stream_id`, `is_opened_locally`, `is_bidirectional`, `is_read_closed`, `metadata`, `open_info`, `append_open_info_to`, `open_info_len`, `has_open_info`, `local_addr`, `peer_addr`
- deadlines: `set_read_deadline`, `set_deadline`, `set_read_timeout`, `set_timeout`
- read: `read`, `read_timeout`, `read_exact`, `read_exact_timeout`, `read_vectored`, `read_vectored_timeout`, `close_read`, `cancel_read`
- close/error: `close`, `close_with_error`

Constants:

- `STREAM_PRELUDE_MAX_PAYLOAD`
- `QUINN_WRITE_VECTORED_COALESCE_MAX_BYTES`
- `OPEN_METADATA_CAPABILITIES`
- `DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT`
- `DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- `MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- `ACCEPTED_PRELUDE_RESULT_QUEUE_CAP`

Adapter-specific stream helper:

- `write_chunks_final`

## Reduced Behavior

- Native ZMux-only session controls such as `ping`, `go_away`, `local_preface`, `peer_preface`, and `negotiated` are present on `zmux::AsyncSession`, but this adapter reports them as unsupported or empty because QUIC owns that layer.
- No post-open native advisory frames such as native `PRIORITY_UPDATE`.
- No QUIC datagram, packet acknowledgement, RTT, or loss-state API.
- `stats()` reports adapter-visible counters. It cannot expose native ZMux runtime internals that do not exist in QUIC.

## Conformance

`target_claims()`, `target_implementation_profiles()`, and `target_suites()` provide adapter conformance metadata for tests that exercise the stable ZMux session contract over Quinn.

## Unified async interface with native zmux

`QuinnSession` implements `zmux::AsyncSession`, so it can be stored with native `zmux::Conn` behind the same boxed trait object:

```rust
let native: zmux::BoxAsyncSession = zmux::box_async_session(native_conn);
let quic: zmux::BoxAsyncSession = zmux::box_async_session(quinn_session);

let sessions: Vec<zmux::BoxAsyncSession> = vec![native, quic];
```

The stream side follows the same rule: use `zmux::AsyncStreamApi`, `zmux::AsyncSendStreamApi`, and `zmux::AsyncRecvStreamApi` for adapter/native async code that must share storage. QUIC cannot represent native zmux ping, go-away, or preface negotiation state exactly; those control methods are still present on the common trait and return adapter-unsupported errors or empty snapshots instead of requiring a separate API.
