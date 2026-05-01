# zmux-quinn

Async adapter that exposes a `quinn::Connection` as ZMux sessions and streams.
The API here is designed to follow the same usage patterns as `zmux` async API.

## Install

```toml
[dependencies]
zmux = "<version>"
zmux-quinn = "<same version as zmux>"
quinn = "<version>"
```

## Quick Start

```rust
use zmux_quinn::wrap_session;

let session = wrap_session(quinn_connection);
let stream = session.open_stream().await?;
stream.write_final(b"hello").await?;
```

## Public API

### Top-level entry points

- `wrap_session(conn: quinn::Connection) -> QuinnSession`
- `wrap_session_with_options(conn, opts: SessionOptions) -> QuinnSession`
- `wrap_session_with_addresses(conn, local_addr: Option<SocketAddr>, peer_addr: Option<SocketAddr>) -> QuinnSession`
- `target_claims() -> &'static [zmux::Claim]`
- `target_implementation_profiles() -> &'static [zmux::ImplementationProfile]`
- `target_suites() -> &'static [zmux::ConformanceSuite]`

### Constants

- `STREAM_PRELUDE_MAX_PAYLOAD`
- `QUINN_WRITEV_COALESCE_MAX_BYTES`
- `OPEN_METADATA_CAPABILITIES`
- `DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT`
- `DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- `MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT`
- `ACCEPTED_PRELUDE_RESULT_QUEUE_CAP`

### Prelude helpers

- `build_stream_prelude(opts: &OpenOptions) -> Result<Vec<u8>>`
- `read_stream_prelude<R: Read>(reader: &mut R) -> Result<AcceptedStreamMetadata>`
- `default_accepted_prelude_max_concurrent() -> usize`
- `set_default_accepted_prelude_max_concurrent(max: usize)`

### `SessionOptions`

- `new()`
- `with_accepted_prelude_read_timeout`
- `without_accepted_prelude_read_timeout`
- `with_accepted_prelude_max_concurrent`
- `with_local_addr`
- `with_peer_addr`
- `with_addresses`

### `AcceptedStreamMetadata`

- `metadata() -> &StreamMetadata`
- `is_metadata_valid() -> bool`
- `open_info() -> &[u8]`
- `has_open_info() -> bool`

### `QuinnSession` (implements `zmux::Session`)

- `new`, `with_options`
- `local_addr`, `peer_addr`, `remote_addr`
- stream lifecycle:
  - `open_stream`, `open_stream_timeout`
  - `open_stream_with_options`, `open_stream_with_options_timeout`
  - `open_uni_stream`, `open_uni_stream_timeout`
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
- control and lifecycle:
  - `close`, `close_with_error`
  - `closed`
  - `close_error`, `state`, `stats`

### `QuinnStream` (implements `zmux::{StreamApi, SendStreamApi, RecvStreamApi}`)

- identity/info: `stream_id`, `opened_locally`, `bidirectional`, `open_info_len`, `has_open_info`
- metadata: `open_info`, `copy_open_info_to`, `metadata`, `update_metadata`
- addresses: `local_addr`, `peer_addr`, `remote_addr`
- read:
  - `read`, `read_timeout`
  - `read_vectored`, `readv`, `read_vectored_timeout`, `readv_timeout`
  - `read_closed`
  - `set_read_deadline`, `set_deadline`, `set_read_timeout`, `set_timeout`
  - `close_read`, `cancel_read`
- write:
  - `write`, `write_timeout`, `write_all`
  - `write_vectored`, `writev`, `write_vectored_timeout`, `writev_timeout`
  - `write_final`, `write_final_timeout`
  - `write_vectored_final`, `writev_final`, `write_vectored_final_timeout`, `writev_final_timeout`
  - `write_chunks_final`
  - `write_closed`
  - `set_write_deadline`, `set_timeout`, `set_write_timeout`
  - `close_write`, `cancel_write`
- close:
  - `close`, `close_with_error`

### `QuinnSendStream` (implements `zmux::SendStreamApi`)

- identity/info: `stream_id`, `opened_locally`, `bidirectional`, `open_info_len`, `has_open_info`
- metadata: `open_info`, `copy_open_info_to`, `metadata`, `update_metadata`
- addresses: `local_addr`, `peer_addr`, `remote_addr`
- write:
  - `write`, `write_timeout`, `write_all`
  - `write_vectored`, `writev`, `write_vectored_timeout`, `writev_timeout`
  - `write_final`, `write_final_timeout`
  - `write_vectored_final`, `writev_final`
  - `write_vectored_final_timeout`, `writev_final_timeout`
  - `write_chunks_final`
- state/deadline:
  - `write_closed`
  - `set_write_deadline`, `set_deadline`, `set_write_timeout`, `set_timeout`
- close:
  - `close_write`, `cancel_write`, `close`, `close_with_error`

### `QuinnRecvStream` (implements `zmux::RecvStreamApi`)

- identity/info: `stream_id`, `opened_locally`, `bidirectional`, `open_info_len`, `has_open_info`
- metadata: `open_info`, `copy_open_info_to`, `metadata`
- addresses: `local_addr`, `peer_addr`, `remote_addr`
- read:
  - `read`, `read_timeout`, `read_exact`, `read_exact_timeout`
  - `read_vectored`, `readv`, `read_vectored_timeout`, `readv_timeout`
- state/deadline:
  - `read_closed`
  - `set_read_deadline`, `set_deadline`, `set_read_timeout`, `set_timeout`
- close:
  - `close_read`, `cancel_read`, `close`, `close_with_error`

## Notes

- This adapter is async-only.
- Use `zmux` async utilities (`zmux::async_io`, `AsyncSession`, `AsyncStreamApi`) for integration with Tokio/Futures.
- Metadata fields can only be updated before prelude bytes are sent.
