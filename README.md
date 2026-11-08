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
[![zmux-shaping](https://img.shields.io/crates/v/zmux-shaping.svg?label=zmux-shaping)](https://crates.io/crates/zmux-shaping)

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

```rust
use std::error::Error as _;
use zmux::SessionError;

match session.closed().await {
    SessionError::ApplicationClosed { code, remote: true, .. } => println!("peer closed: {code}"),
    SessionError::ApplicationClosed { .. } => println!("closed here"),
    // Resume ran out of time, or every pipe was lost without resume: the
    // last pipe's failure is the source, for example a refused rejoin.
    e @ (SessionError::ResumeTimeout { .. } | SessionError::PipesLost { .. }) => {
        println!("{e}; last pipe: {:?}", e.source());
    }
    SessionError::ResumeFailed { .. } => println!("resume diverged; data in flight is lost"),
    e => println!("{e}"),
}
```

## Multipath

A session can run on several pipes at once (`Config::max_pipes` above 1).
Joins need a secret source, given in `Config::pipe_auth`: a pre-shared key
(`PipeAuth::psk`, or `PipeAuth::deferred_psk` given later with
`set_join_secret`), the TLS exporter of the first pipe (`PipeAuth::exporter`),
or a first pipe on the secure carrier (`zmux-seal`), for which `pipe_auth`
stays unset. Multipath or resume without a source is a configuration error
before any byte. A first pipe that is not on the secure carrier gives join
keys only once the host states that it proved the pipe end to end:
`with_end_to_end` in the configuration, or `declare_end_to_end` later.

```rust
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeIo, PipeOptions, Session};

let auth = PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end();
let config = Config::multipath(auth);
// Server: a Listener routes joins to their session.
let listener = Listener::new(config.clone(), ListenerConfig::default())?;
// Client: a second TCP connection becomes a second pipe.
let session = Session::connect(PipeIo::tcp(first), config).await?;
let pipe = session.add_pipe(PipeIo::tcp(second), PipeOptions::default()).await?;
```

`add_pipe` waits at most `Config::join_timeout` (10 s) for the peer to
attach the pipe; it fails with `PipeError::JoinRefused` when the peer
refused the join. `helpers::maintain_pipes` keeps a pool of pipes up per
path, redialling with backoff.

## Resume

With `Config::resume_timeout` set, a session whose pipes are all lost is
suspended for that long instead of ending, and resumes when a pipe joins
again. Something has to dial: the `redial` hook (a session on one pipe at a
time), a pipe pool, or the application's own `add_pipe`. A suspension with
none of them is reported as `SessionEvent::ResumeUnattended` and logged.

```rust
use std::time::Duration;
use zmux::{Config, Dial, PipeAuth, PipeIo, Session};

let mut config = Config::default();
config.pipe_auth = PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end();
config.resume_timeout = Some(Duration::from_secs(60));
// Replaces the lost pipe, with backoff from 1 s doubling up to 60 s.
config.redial = Some(Dial::new(|_req| async {
    Ok(PipeIo::tcp(tokio::net::TcpStream::connect("192.0.2.1:4433").await?))
}));
config.logger = Some(zmux::Logger::new(|level, msg| eprintln!("{level:?}: {msg}")));
let session = Session::connect(PipeIo::tcp(first), config).await?;
```

The server side needs a `Listener` with `resume_timeout` set as well.

## Closing

`session.close(code, reason).await` sends CONNECTION_CLOSE at once and
returns once it has been handed to the carriers (for a socket, in the
kernel's send buffer), after 1 s at the latest; a process may exit then.
Dropping the last handle closes with code 0 without waiting.
`session.closed().await` waits for the session's whole end and returns
why it ended.

## Servers, carrier choice and shaping

- **Admission.** `ListenerConfig::admission` (an `Admission`) decides on
  every carrier of a `Listener`, whatever adapter took it, before anything
  is sent on it: from its first bytes and its metadata (`CarrierInfo`) it
  accepts the carrier, hands it to the fallback of its kind with the bytes
  read replayed (`ListenerConfig::fallback`), stalls it, or closes it
  (`Verdict`). `PrefixAuth` is a ready-made credential check, bound to the
  TLS connection where the carrier has an exporter; a client presents it
  as a `Credential`. `TrustedProxies` names the intermediaries whose report
  of the client address (PROXY protocol, a forwarding header field) is
  believed.
- **Choosing a carrier.** `dial_mode` takes a `Mode`: `Mode::explicit` uses
  one `Candidate`, `Mode::auto` tries several in order of preference and,
  with `Config::max_pipes` above 1, moves the session to preferred kinds by
  joining them as further pipes. A `CarrierCache` in the `ModePolicy`
  remembers which kinds worked per server and network; `snapshot` and
  `restore` carry it across restarts.
- **Shaping.** `zmux::shaping` holds the hooks for record sizes and timing
  (`Config::shaper`, `Session::set_shaper`, `shaping::Limits`); the
  `zmux-shaping` crate offers a factory for them.

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
| `zmux-rustls` (`adapter/rustls`) | TLS 1.3 over TCP (tokio-rustls), with the exporter for Bound joins | no |
| `zmux-quinn` (`adapter/quinn`) | QUIC (quinn): pipes on streams of a connection | further streams |
| `zmux-websocket` (`adapter/websocket`) | WebSocket (tokio-tungstenite), `ws` and `wss` | no |
| `zmux-http` (`adapter/http`) | HTTP/1.1 and HTTP/2 exchanges (hyper), over TCP or TLS | HTTP/2, off by default |
| `zmux-h3` (`adapter/h3`) | HTTP/3 requests (h3 over quinn) | further requests |
| `zmux-webtransport` (`adapter/webtransport`) | WebTransport sessions (web-transport-quinn) | further streams |

`zmux-http` also serves every HTTP carrier kind on one request target:
streamed bidirectional requests, split uplink and downlink requests, and
the exchange carrier of bounded requests for paths that buffer whole
bodies.

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
executable traces, copied unchanged from the specification.

## License

Apache-2.0.
