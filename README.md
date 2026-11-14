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

```rust,no_run
async fn hello() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let tcp = tokio::net::TcpStream::connect("127.0.0.1:4433").await?;
    let session = zmux::Session::connect(zmux::PipeIo::from_tcp(tcp), zmux::Config::default()).await?;
    let (mut send, mut recv) = session.open_bi().await?;
    send.write_all(b"hello").await?;
    send.finish()?;
    let reply = recv.read_to_end(1 << 20).await?;
    session.close().await;
    Ok(reply)
}
```

The accepting side calls `Session::accept`, then `accept_bi` / `accept_uni`.
Streams implement `AsyncRead` / `AsyncWrite`; dropping a stream that was not
finished resets it with `ZMUX_CANCELLED` (and stops reading with code 0). A bidirectional stream
can itself carry a pipe of another session (`Session::open_pipe_stream`,
`PipeIo::from_stream`): a nested session whose pipes cross relays.

Errors are one type per kind of operation: `SessionError` (why a session
ended), `StreamError` (every stream operation), `OpenError`,
`DatagramError`, `PipeError`, and `ConnectError`, `ReadExactError`,
`ReadToEndError` for the compound calls; a setting that cannot work is an
`InvalidConfig`, which names the setting. The std driver (`zmux::blocking`)
wraps the same types in a `WaitError` for the calls that wait: `Failed`
with the error the tokio driver's future returns, `TimedOut` when the
call's bound (`x_timeout(d)`, a stream's read or write timeout) expired,
and `OnDriverThread` when it was refused on a thread that drives sessions.
Each tells whether the operation may be retried (`is_retryable`) and
converts into `std::io::Error`; a session's end is never
`ErrorKind::TimedOut`, also when an idle, handshake or resume timeout
ended it. The session-ended variant is `SessionLost` everywhere.

```rust,no_run
use std::error::Error as _;
use zmux::SessionError;

async fn report(session: &zmux::Session) {
    match session.closing().await {
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

```rust,no_run
use tokio::net::TcpStream;
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeIo, PipeOptions, Session};

async fn two_pipes(first: TcpStream, second: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let auth = PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end();
    let config = Config::multipath(auth);
    // Server: a Listener routes joins to their session.
    let _listener = Listener::new(config.clone(), ListenerConfig::default())?;
    // Client: a second TCP connection becomes a second pipe.
    let session = Session::connect(PipeIo::from_tcp(first), config).await?;
    let pipe = session.add_pipe(PipeIo::from_tcp(second), PipeOptions::default()).await?;
    // Make it a fallback for both directions.
    pipe.update(&zmux::PipeUpdate {
        send_priority: zmux::Change::Set(10),
        receive_priority: zmux::Change::Set(10),
        ..Default::default()
    })?;
    Ok(())
}
```

`add_pipe` waits at most `Config::join_timeout` (10 s) for the peer to
attach the pipe; it fails with `PipeError::Failed(PipeFailure::JoinRefused)`
when the peer refused the join. `helpers::maintain_pipes` keeps a pool of pipes up per
path, redialling with backoff.

## Resume

With `Config::resume_timeout` set, a session whose pipes are all lost is
suspended for that long instead of ending, and resumes when a pipe joins
again. Something has to dial: the `redial` hook (a session on one pipe at a
time), a pipe pool, or the application's own `add_pipe`. A suspension with
none of them is reported as `SessionEvent::ResumeUnattended` and logged.

```rust,no_run
use std::time::Duration;
use zmux::{Config, PipeAuth, PipeIo, Redial, Session};

async fn resumable(first: tokio::net::TcpStream) -> Result<Session, zmux::ConnectError> {
    let mut config = Config::default();
    config.pipe_auth = PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end();
    config.resume_timeout = Some(Duration::from_secs(60));
    // Replaces the lost pipe, with `config.redial_backoff` (from 1 s
    // doubling up to 60 s).
    config.redial = Some(Redial::new(|_req| async {
        Ok(PipeIo::from_tcp(tokio::net::TcpStream::connect("192.0.2.1:4433").await?))
    }));
    config.logger = Some(zmux::Logger::new(|level, msg| eprintln!("{level:?}: {msg}")));
    Session::connect(PipeIo::from_tcp(first), config).await
}
```

The server side needs a `Listener` with `resume_timeout` set as well.

## Closing

`session.close_with_error(code, reason).await` closes gracefully with an
application error code: what the streams have written and not yet sent
goes out first, as far as flow control and the carriers allow within the
bound, then CONNECTION_CLOSE with the code is handed to the carriers, and
the call returns, after 1 s at the latest for the whole call; a process
may exit then. The peer reads what was written before the code, and sees
`SessionError::ApplicationClosed` with that code and reason.
`session.close().await` is the same close with code 0 and no reason. The
carriers' write sides are then shut and their input read until the peer
ends it or the linger timeout passes, in the background.
`session.abort(code, reason)` ends the session at once with an
application error code, discarding what was not sent, and returns at
once; an abort during a close's flush ends the flush. The first close or
abort decides the code and reason; both are idempotent. Dropping the last
handle starts `close` without waiting. A peer that receives a close can
still read what arrived on its open streams until it has read it, within
the linger timeout.

`session.closing().await` returns why the session ended as soon as it is
closing, and `session.closed().await` once it has ended entirely: every
pipe's input ended (the peer read the close and ended its side) or the
linger timeout passed, and the session's task released its carriers. A
wait that returns before the linger timeout confirms the peer read the
close; "delivered or given up after `d`" is
`tokio::time::timeout(d, session.closed())`, which changes nothing in the
session. Over QUIC, the adapter closes the QUIC connection only after
that, with the same application error code.

## Servers, carrier choice and shaping

- **Admission.** `ListenerConfig::admission` (an `Admission`) decides on
  every carrier of a `Listener`, whatever adapter took it, before anything
  is sent on it: from its first bytes and its metadata (`CarrierInfo`) it
  accepts the carrier, hands it to the fallback of its kind with the bytes
  read replayed (`ListenerConfig::fallback`), stalls it, or closes it
  (`AdmissionVerdict`). `PrefixAuth` is a ready-made credential check, bound to the
  TLS connection where the carrier has an exporter; a client presents it
  as a `CarrierCredential`. `TrustedProxies` names the intermediaries whose report
  of the client address (PROXY protocol, a forwarding header field) is
  believed.
- **Carriers before a session.** Every carrier holds a slot of its source
  (`ListenerConfig::max_pending_per_source`, default 8, at least 2) and one of the
  listener (`ListenerConfig::max_pending`, default 1024, `None` for
  unlimited) from the moment it is taken, through its handshake,
  admission, transform, pairing and classification, and through a stall,
  until it enters a session or is closed. A source is counted by its
  prefix, `ListenerConfig::source_prefix_v4` (default 32, 1 to 32) and
  `source_prefix_v6` (default 64, 1 to 128), for the slots, the stalls and
  the stall duration alike. A source without a free slot has
  its carrier closed at once (`refused`). With every listener slot taken, a
  new carrier closes the carrier stalled longest to take its slot, or is
  closed at once (`rejected`) when none is stalled. Stalls hold at most
  half of the listener's slots and one fewer than a source's; a Stall
  beyond them is closed at once (`stall_overflow`).
- **Choosing a carrier.** `dial_choice` takes a `CarrierChoice`: `CarrierChoice::explicit` uses
  one `Candidate`, `CarrierChoice::auto` tries several in order of preference and,
  with `Config::max_pipes` above 1, moves the session to preferred kinds by
  joining them as further pipes. A `CarrierCache` in the `CarrierChoicePolicy`
  remembers which kinds worked per server and network; `snapshot` and
  `restore` carry it across restarts.
- **Shaping.** `zmux::shaping` holds the hooks for record sizes and timing
  (`Config::shaper`, `Session::set_shaper`, `Pipe::set_shaper`,
  `shaping::Limits`); the
  `zmux-shaping` crate offers a factory for them.

## Memory and allocators

What a peer can make a session hold is bounded per kind: received
datagrams by `Config::datagram_receive_bytes` (the session queue, 1 MiB) and,
per stream, by `datagram_stream_queue` (32) and `datagram_stream_bytes`
(512 KiB, `None` for no byte bound); peer streams by
`max_incoming_streams`, whose range ends at `zmux::MAX_STREAM_CREDIT`
(2^60, as many as the protocol can count).

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
| `zmux::proto` (hidden) | the sans-IO layer: wire format and the session state machine, which the drivers, carrier crates and bindings build on; no stable API, and the crate root re-exports what applications use | always |
| crate root | `Session`, `SendStream`, `RecvStream`, `PipeIo`, `Listener`: one tokio task per session | `tokio` (default) |
| `zmux::blocking` | the same handles for threads: the calls that wait block instead of returning a future; streams implement `std::io::Read` / `Write` | `blocking` |
| `zmux::helpers` | helpers above the public API: `maintain_pipes` (keeping pipes up), `splice` (relaying a stream into another), `resolve_duplicate` (two sessions between the same endpoints) | `tokio`; `resolve_duplicate` either driver |
| `zmux::sched` | the scheduler: `Scheduler` and the custom policy's interface (`Pick`) | always |
| `zmux::shaping` | traffic shaping: shapers, definitions and budgets | always |
| `zmux::adapter` | what carrier adapters and own accept loops use: `Listener::adapter()` and `Session::adapter()` views, carrier admission at an entrance, connection identities, lanes, datagram channels, memory charges | `tokio` |

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
