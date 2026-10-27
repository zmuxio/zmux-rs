# zmux

[![CI](https://github.com/zmuxio/zmux-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/zmuxio/zmux-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/zmux.svg)](https://crates.io/crates/zmux)
[![docs.rs](https://img.shields.io/docsrs/zmux)](https://docs.rs/zmux)
[![MSRV](https://img.shields.io/crates/msrv/zmux)](Cargo.toml)
[![License](https://img.shields.io/crates/l/zmux.svg)](LICENSE)

[![zmux-rustls](https://img.shields.io/crates/v/zmux-rustls.svg?label=zmux-rustls)](https://crates.io/crates/zmux-rustls)
[![zmux-quinn](https://img.shields.io/crates/v/zmux-quinn.svg?label=zmux-quinn)](https://crates.io/crates/zmux-quinn)
[![zmux-websocket](https://img.shields.io/crates/v/zmux-websocket.svg?label=zmux-websocket)](https://crates.io/crates/zmux-websocket)
[![zmux-http](https://img.shields.io/crates/v/zmux-http.svg?label=zmux-http)](https://crates.io/crates/zmux-http)
[![zmux-h3](https://img.shields.io/crates/v/zmux-h3.svg?label=zmux-h3)](https://crates.io/crates/zmux-h3)
[![zmux-webtransport](https://img.shields.io/crates/v/zmux-webtransport.svg?label=zmux-webtransport)](https://crates.io/crates/zmux-webtransport)

Rust implementation of zmux: multiplexed, flow-controlled streams and
datagrams over one or many reliable byte pipes.

zmux is wire-compatible with QMux (draft-ietf-quic-qmux-02): QUIC version 1
frames in size-prefixed records over TCP, TLS, WebSocket or any other
reliable carrier. With a plain QMux peer a session is a plain single-pipe
QMux session. Between zmux endpoints, transport parameters negotiate
multipath (many unidirectional pipes, per-frame spreading, failover with
reinjection), resumption after every pipe is lost, and the base extensions:
roles, GOAWAY, stream preambles, priorities and datagram flows.

## Usage

```rust
let tcp = tokio::net::TcpStream::connect("127.0.0.1:4433").await?;
let session = zmux::Session::connect(zmux::PipeIo::tcp(tcp), zmux::Config::default()).await?;
let (mut send, mut recv) = session.open_bi().await?;
send.write_all(b"hello").await?;
send.finish()?;
let reply = recv.read_to_end(1 << 20).await?;
```

The accepting side calls `Session::accept`, then `accept_bi` / `accept_uni`.
Streams implement `AsyncRead` / `AsyncWrite`; dropping a stream that was not
finished resets it (and stops reading) with code 0. A bidirectional stream
can itself carry a pipe of another session (`Session::open_pipe_stream`,
`PipeIo::from_stream`): a nested session whose pipes cross relays.

Errors are one type per kind of operation, the same for both drivers and
the sans-IO core: `SessionError` (why a session ended), `StreamError` (every
stream operation), `OpenError`, `DatagramError`, `PipeError`, and
`ConnectError`, `ReadExactError`, `ReadToEndError` for the compound calls.
Each tells whether the operation may be retried (`is_retryable`) and
converts into `std::io::Error`.

## Memory and allocators

zmux gives memory back as load goes away: idle pipes return their read and
write buffers after a second, a process-wide pool keeps a bounded number of
read buffers, and closed streams and sessions free their state. Whether the
freed memory also leaves the process is up to the global allocator, which
the crate never sets: the choice belongs to the application.

After a burst of many sessions and large transfers on several runtime
threads, the live heap returns to its quiet level, but the resident set
usually stays near its peak: glibc's malloc keeps freed pages in its
per-thread arenas, and jemalloc and mimalloc keep theirs for reuse unless
they are told to purge them while the process is quiet. Under sustained
churn the resident set stays bounded with glibc's malloc and with
jemalloc; mimalloc's kept growing in a long churn on many threads unless
it purges freed pages at once (`MIMALLOC_PURGE_DELAY=0`). Applications
that serve such bursts and want the memory back between them can use
jemalloc as the global allocator with background purging
(`background_thread:true` in its configuration, through `MALLOC_CONF` or
the allocator crate's options), which returns most of it within seconds of
the burst. With glibc, `MALLOC_ARENA_MAX` lowers the plateau but does not
return it. Measure with the application's own load: the `soak` scenario of
`benches/session.rs` runs a bounded churn and prints the live heap next to
the resident set, under any allocator given by `LD_PRELOAD`.

## Layout

| Part | Content | Feature |
|---|---|---|
| `zmux::proto` | the sans-IO layer: wire format (`varint`, `frame`, `record`, `params`, `ident`, `payload`, `keys`, `oob`, `error`) and the session state machine `proto::session` | always |
| crate root | `Session`, `SendStream`, `RecvStream`, `PipeIo`, `Listener`: one tokio task per session | `tokio` (default) |
| `zmux::blocking` | the same handles for threads: the calls that wait block instead of returning a future; streams implement `std::io::Read` / `Write` | `blocking` |
| `zmux::helpers` | helpers above the public API: `maintain_pipes` (keeping pipes up), `splice` (relaying a stream into another), `resolve_duplicate` (two sessions between the same endpoints) | `tokio`; `resolve_duplicate` either driver |
| `zmux::carrier` | items for carrier authors: connection identities, lane handling, memory charges | `tokio` |

The session core has no I/O and no clock: drivers feed it bytes, timer
events and application commands, and pull records, events and deadlines
from it.

The carrier crates of the workspace turn connections into pipes, each with
`dial` (a pipe), `connect` (a session) and `serve` (into a `Listener`):

| Crate | Carrier | Lanes |
|---|---|---|
| `zmux-rustls` (`adapter/rustls`) | TLS 1.3 over TCP (tokio-rustls), with the exporter for carrier-bound joins | no |
| `zmux-quinn` (`adapter/quinn`) | QUIC (quinn): pipes on streams of a connection | further streams |
| `zmux-websocket` (`adapter/websocket`) | WebSocket (tokio-tungstenite), `ws` and `wss` | no |
| `zmux-http` (`adapter/http`) | HTTP/1.1 and HTTP/2 exchanges (hyper), over TCP or TLS | HTTP/2, off by default |
| `zmux-h3` (`adapter/h3`) | HTTP/3 requests (h3 over quinn) | further requests |
| `zmux-webtransport` (`adapter/webtransport`) | WebTransport sessions (web-transport-quinn) | further streams |

The crate documentation compares them and describes multipath, resumption,
relays and nesting.

## Minimum Rust version

Rust 1.95, edition 2024.

## Development

```sh
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo bench --bench codec
cargo bench --bench session
```

Interoperability tests against the `qmux` crate over TCP live in a separate
crate, so that its dependencies are fetched only when they run:

```sh
cargo test --manifest-path interop/qmux/Cargo.toml
```

The heap of an idle connection of each carrier (TCP, TLS 1.3, QUIC) next
to that of a zmux session over it is measured by another separate crate:

```sh
cargo run --release --manifest-path interop/carrier-mem/Cargo.toml
```

`testdata/spec` holds the conformance assets of the zmux specification:
the codepoint registry, the wire corpus, the wire examples and the
executable traces. Refresh them from a specification checkout with:

```sh
ZMUX_SPEC_DIR=../zmux-spec tools/sync-spec-fixtures.sh
```

## License

Apache-2.0.
