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

`transport` is any `DuplexConnection`. Built-in implementations cover `TcpStream`, `duplex_io(...)` wrappers for cloneable full-duplex I/O, `(reader, writer)` pairs, boxed `DuplexConnection` values, native bidirectional `Stream`s, joined stream halves, and `DuplexTransport`. It is not limited to TCP: TLS streams, pipes, in-memory links, and custom reliable byte streams are supported when they can expose independent read/write handles. Attach a close hook when dropping those handles is not enough to close the whole underlying resource.

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
let stream = session.open_and_send(b"\x01hello")?;
let send = session.open_uni_and_send(b"\x02event")?;

let buf = vec![0x01, 0x02, 0x03];
let stream = session.open_and_send(&buf)?;
```

`open_and_send(...)` opens a bidirectional stream and writes the whole first payload before returning; the stream remains open. `open_uni_and_send(...)` writes the final payload and closes the send side. If the stream opens but the payload write fails, ZMux best-effort closes the opened stream before returning the error.

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

ZMux accepts native transports through `DuplexConnection`. A transport must be a
reliable byte stream that can provide independent blocking read and write paths.
Built-in implementations cover `TcpStream`, `duplex_io(...)` wrappers for
cloneable full-duplex I/O, split `Read` / `Write` halves, boxed
`DuplexConnection` values, native bidirectional `Stream`s, joined stream halves,
and `DuplexTransport`.

For normal full-duplex connections, pass the connection object directly when it
already implements `DuplexConnection`:

```rust
let session = zmux::Conn::client(tcp_stream)?;
```

For TLS or other reliable byte streams that can create an independent cloned
handle, wrap the full-duplex object with `duplex_io(...)`:

```rust
let session = zmux::Conn::client(zmux::duplex_io(tls_stream))?;
```

When the type exposes a `try_clone`-style API instead of `Clone`, build the
transport from that operation:

```rust
let transport = zmux::try_duplex_io(tls_stream, |stream| stream.try_clone())?;
let session = zmux::Conn::client(transport)?;
```

If the original object needs an explicit full-resource shutdown, attach that
operation with `DuplexTransport::with_close_fn(...)` after building a transport
or from a custom `DuplexConnection` implementation.
`with_close_fn(...)` preserves any timeout control installed earlier with
`with_control(...)` and replaces only the transport close action.

Use split halves only when the transport naturally provides independent read and
write sides:

```rust
let session = zmux::Conn::client((tls_read_half, tls_write_half))?;
```

Use `DuplexTransport` when the transport can expose addresses, timeouts, or a
close hook:

```rust
let transport = zmux::DuplexTransport::new(reader, writer)
    .with_local_addr(local_addr)
    .with_peer_addr(peer_addr)
    .with_close_fn(close_transport);

let session = zmux::Conn::new(transport)?;
```

When addresses are discovered as optional values, use
`with_addresses(local_addr, peer_addr)`. `DuplexTransportControl` hooks default
to no-ops, so a custom control can provide only read/write timeout integration
and leave full close to `with_close_fn(...)`.

Avoid hiding one blocking duplex object behind a single `Mutex`: a blocking read
can hold the lock and prevent writes or close progress.

`Conn::close`, `Conn::close_with_error`, establishment failure, and runtime
shutdown call the transport close hook when one is present. Passing only split
halves drops/closes those halves according to their own types; attach
`with_close_fn(...)` or implement `DuplexConnection` when the original
underlying connection needs an explicit whole-resource shutdown.

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

Join existing stream halves when an API expects a duplex object. `join_streams`
is for already-separated directions, including ordinary `Read` / `Write` halves,
two unidirectional connections, or unidirectional ZMux streams; it is not the
normal wrapper for one full-duplex connection object:

```rust
let duplex = zmux::join_streams(recv_half, send_half);
let optional = zmux::DuplexStream::from_parts(Some(recv_half), Some(send_half));
```

Joined halves are also `DuplexConnection` values when both halves are present
and the read side implements `Read` while the write side implements `Write`, so
they can back another zmux session over an already established outer reliable
stream or pair of directional halves. When the supplied halves also implement
ZMux stream handle traits, the joined value exposes the stable ZMux stream
traits too:

```rust
let nested = zmux::Conn::client(outer_bidi_stream)?;

let paired = zmux::join_streams(recv_from_peer, send_to_peer);
let nested_from_halves = zmux::Conn::client(paired)?;
```

Calling the ZMux stream-handle close methods on joined ZMux halves closes both
original halves and skips the second close when both halves report the same
close identity. When a joined value is used as a `Conn` transport, ZMux closes
known native ZMux stream halves with their own close methods; other generic
`Read` / `Write` halves are detached and dropped. Attach an explicit
`with_close_fn(...)` if another original resource needs a protocol-level
shutdown.

Async equivalent is `join_async_streams(...)`; use
`AsyncDuplexStream::from_parts(...)` when one side is optional.

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

`Config::default()` returns a copy of the process-wide default template. Use
`Config::configure_default(...)` during startup when every new session should
inherit the same changes. Constructors without a `Config` argument use that
template; use `Conn::with_config(...)` or `Conn::*_with_config(...)` when one
session needs an explicit override:

```rust
zmux::Config::configure_default(|config| {
    config.capabilities |= CAPABILITY_OPEN_METADATA;
    config.keepalive_interval = std::time::Duration::from_secs(30);
});
```

`Config::reset_default()` restores the built-in template. Existing sessions keep
the config they were created with.

## API Overview

Use concrete types when you own the transport and want the full API:

- `Conn`, `Stream`, `SendStream`, and `RecvStream` for native blocking sessions.
- `QuinnSession`, `QuinnStream`, `QuinnSendStream`, and `QuinnRecvStream` when using the Quinn adapter.

Use trait objects when an upper layer should not care which concrete session or
stream implementation is underneath:

- Blocking: `Session`, `StreamHandle`, `DuplexStreamHandle`, `SendStreamHandle`, `RecvStreamHandle`, and `BoxSession`.
- Async: `AsyncSession`, `AsyncStreamHandle`, `AsyncDuplexStreamHandle`, `AsyncSendStreamHandle`, `AsyncRecvStreamHandle`, and `BoxAsyncSession`.

Use request/value helpers only when the simple call needs extra data:

- `OpenOptions` for open metadata, initial priority, and initial group.
- `OpenRequest` when open options and timeout must travel together through a trait object.
- `OpenSend` when an initial payload, open options, and timeout must travel together.
- `WritePayload` when an owned or vectored payload must travel through a trait object.

Transport helpers are intentionally small:

- `duplex_io(io)` for cloneable full-duplex reliable byte streams.
- `try_duplex_io(io, clone)` for streams with a `try_clone`-style operation.
- `(reader, writer)` or `DuplexTransport::new(reader, writer)` for already split halves.
- `join_streams(recv, send)` and `join_async_streams(recv, send)` for already separated directions.

## Semantics

- Successful native ZMux complete-write calls wait for the local writer path to flush the framed data to its backend. Adapter writes wait for the adapter's backend future. Neither form is a peer application acknowledgement.
- Borrowed buffers passed to write/open-and-send methods are not retained after the call returns. Owned buffers are consumed by the operation.
- `close_write()` finishes only the local send half.
- `close_read()` cancels local interest in inbound bytes.
- Open metadata is sent only when negotiated; required but unavailable metadata fails instead of being silently discarded.
