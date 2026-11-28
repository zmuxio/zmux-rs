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

A session can run on several pipes at once when
`config.session_policy.limits.steady_attachments` is above 1.
Use `Session::capacity` to inspect protocol occupancy, carrier occupancy, and
direction coverage. Commit a newer policy with `Session::set_session_policy`.
Increase its authorization generation when changing Join authorization.
Joins need a secret source, given in `Config::pipe_auth`: a pre-shared key
(`PipeAuth::psk`, or `PipeAuth::deferred_psk` given later with
`set_join_secret`), the TLS exporter of the first pipe (`PipeAuth::exporter`),
or a first pipe on the secure carrier (`zmux-seal`), for which `pipe_auth`
stays unset. Multipath or resume without a source is a configuration error
before any byte. A first pipe that is not on the secure carrier gives join
keys only once the host states that it proved the pipe end to end:
`with_end_to_end` in the configuration, or `declare_end_to_end` later.

```rust,no_run
use std::time::Duration;
use tokio::net::TcpStream;
use zmux::{AttachmentSpec, AttemptReason, CarrierOpener, ChangeRequest, Config, Directions,
    Listener, ListenerConfig, MemberSpec, PathPreference, PipeAuth, PipeIo, PipeOptions, Session};

async fn two_pipes(first: TcpStream, second: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let auth = PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end();
    let config = Config::multipath(auth);
    // Server: a Listener routes joins to their session.
    let _listener = Listener::new(config.clone(), ListenerConfig::default())?;
    // Client: a second TCP connection becomes a second pipe.
    let session = Session::connect(PipeIo::from_tcp(first), config).await?;
    let mut request = ChangeRequest::new(session.capacity(), Duration::from_secs(10));
    request.add.push(MemberSpec {
        candidate: None,
        attachments: vec![AttachmentSpec::new(Directions::BOTH,
            PipeOptions::default().with_send_priority(10))],
    });
    let change = session.begin_change(request)?;
    let opener = CarrierOpener::prepared(vec![PipeIo::from_tcp(second)]);
    let result = change.start_member(0, opener)?.wait().await;
    if result.reason != AttemptReason::Confirmed {
        return Err(format!("Join ended with {:?}", result.reason).into());
    }
    change.commit()?;
    session.set_local_receive_preference(result.pipes[0], Some(PathPreference {
        tier: 10,
        ..PathPreference::default()
    }))?;
    Ok(())
}
```

`Session::begin_change` reserves a member's exact carrier layout.
`CapacityChange::start_member` returns an `Attempt` that can be inspected
or cancelled independently of a wait. A `SessionController` uses the
same capacity transaction to manage a declarative target.

A pipe whose acknowledgements stall turns suspect, traffic moves away from
it, and it fails after `Liveness::dead_timeout` (a `DeadTimeout`: `Auto`,
derived from the RTT and the idle timeout; `After(d)`, at least 1 s, any
larger value safe). `DeadTimeout::Off` turns stall-based failure off: a
stalled pipe still turns suspect, is avoided, has its data reinjected and
is probed, but only its carrier's error or end, its drain deadline or its
removal fail it. It is off by default on a carrier that reports its own
failure (`PipeIo::with_reports_failure`), such as a stream of an outer
session (`PipeIo::from_stream`, `Session::open_pipe_stream`), whose outer
session ends it when its path fails; a pipe's own
`PipeLiveness::dead_timeout` (`Inherit::Set`, `Set(DeadTimeout::Auto)`
included) overrides both.

## Resume

With `Config::resume_timeout` set, a session whose pipes are all lost is
suspended for that long and resumes when a pipe joins again. A
`SessionController` opens carriers to recover missing directions. Its domain
defaults to 64 pending owners, 4 concurrent carrier openers and 8 attachment
cleanup reservations. Set `ControllerOptions::limits` to change these bounds.
Applications may also submit explicit capacity changes. A suspension
without an active recovery source is reported as
`SessionEvent::ResumeUnattended`.

```rust,no_run
use std::time::Duration;
use zmux::{Candidate, Config, ControllerError, ControllerOptions, PipeAuth, Session,
    SessionControl, SessionController, SessionTarget};

async fn resumable(candidate: Candidate) -> Result<(Session, Option<SessionControl>), ControllerError> {
    let mut config = Config::default();
    config.pipe_auth = PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end();
    config.resume_timeout = Some(Duration::from_secs(60));
    let candidate = candidate.with_identity("primary", "primary");
    let controller = SessionController::new(ControllerOptions::new("application", vec![candidate]))?;
    controller.open(config, SessionTarget::default()).await
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

## Servers and carrier choice

- **Carrier handoff.** Calling `Listener::handle_pipe` moves the carrier into
  setup, even if the future is dropped before its first poll. Await it to
  learn when a session reaches the accept queue, a join or lane attaches,
  or the listener takes responsibility for rejection or completes fallback.
  A fallback that returns normally completes setup successfully, including when it
  leaves the carrier undetached. A callback failure returns a setup error.
  A stalled carrier and an authenticated refusal keep their admission slots
  while the listener finishes the stall or flushes the refusal reply.
  The session drives attached I/O and its bounded close flush after setup
  returns or serving stops. Rust's direct `handle_lane` returns when the lane
  is routed. Use `Pipe::closed` to wait for the carrier, lanes and attachment
  workers to finish, or `Session::closed` to wait for session termination.
- **Admission.** `ListenerConfig::admission` (an `Admission`) decides on
  every carrier of a `Listener`, whatever adapter took it, before anything
  is sent on it: from its first bytes or first message and its metadata
  (`CarrierInfo`) it accepts the carrier, hands it to the listener's one
  fallback with what was read replayed (`ListenerConfig::fallback`, a
  `Fallback` given a `Takeover`), stalls it, or closes it
  (`AdmissionVerdict`). An HTTP upgrade (WebSocket, WebTransport) is decided
  on its request head, which may defer the decision to the carrier's first
  message or bytes (`AdmissionVerdict::Defer`). On HTTP, Fallback serves the request through the
  adapter's HTTP handler with its prefix replayed. Takeover writes the accepted
  response head or completes the upgrade, then hands the carrier to the byte-stream
  target. The built-in HTTP server confirms the flush. Hosts driving the HTTP
  transport themselves call `PipeBody::response_head_flushed` after the head
  has flushed. Admission totals and variant statistics increment `takeover` when
  the carrier reaches the host. Without that target the stall outcome counts.
  `More { need }` reads a longer stream prefix up to `max_peek` using the
  original peek deadline. Label a decision with `labelled` to group its
  verdict in `Listener::variant_stats()`. With `with_fallback_on_peek_timeout(true)`,
  an incomplete stream prefix is replayed to the byte-stream target or
  stalled when none is configured. HTTP request bodies, message-framed
  carriers and late decision callbacks still close on timeout. Quinn sends
  its first bidirectional stream to `ListenerConfig::fallback` from either
  serving entry point.
- **Join progress.** Use the `Attempt` returned by a capacity change to
  inspect the verified Replies, confirmed attachments and terminal result.
  A local pipe abort is included in `PipeError::is_gone()`.
- **Draining a listener.** `drain(reason)` refuses subsequent bootstrap handshakes
  with transport `CONNECTION_REFUSED` and the reason bytes. A later drain
  sets a new reason. `undrain()` resumes accepting new sessions. Joins,
  resumptions and lanes remain available. Graceful shutdown drains permanently.

- **Takeover.** The fallback's future runs on a task of its own and owns
  the carrier until it completes: what it did not take is dropped then,
  and the adapter closes what it holds of the carrier (a QUIC connection,
  a WebTransport session, an HTTP request). `Takeover::detach` makes all
  of it the host's, to serve on another task afterwards and to close once
  done. `AdmissionVerdict::fallback().with_value(..)` routes the carrier
  (`Takeover::value`); `Takeover::into_pipe` keeps every capability of the
  carrier, `into_stream` gives the connection itself (`Takeover::stream`
  to look at its type), `into_messages` the whole messages of a WebSocket.

```rust,no_run
use zmux::{Fallback, Takeover};

let fallback = Fallback::new(|t: Takeover| async move {
    // Keep the carrier past this future: served on a task of the host's.
    if t.detach().is_ok() {
        let pipe = t.into_pipe();
        tokio::spawn(async move {
            let _stream = pipe.into_stream(); // replay first, then the carrier
        });
    }
});
# let _ = fallback;
```
  Use `PrefixAuth` to present a 64-byte ticket at a protected entry and
  `Admission::prefix_auth` to redeem it with a shared `PrefixStore`. The
  bound form uses the completed TLS 1.3 or QUIC connection's exporter and
  makes the bootstrap ticket ID available through
  `Session::bound_prefix_principal` after session acceptance. Head-stage
  tickets require an encrypted connection. Configure a PSK and a separate
  envelope-only listener for exchange at a ticket-protected HTTP endpoint.

  Share one `MemoryPrefixStore` across the entry points of an admission
  domain. Use a durable store if the domain's tickets survive a restart.
  An in-memory authority's ID capacity is a process-lifetime quota. Expired,
  spent and revoked IDs continue to occupy it.
  A single-use ticket may have been consumed without admitting the carrier.
  When a commit receipt is missing, the verifier queries the original
  operation with an independent one-second deadline. Issue a fresh ticket
  ID when the single-use ticket must be replaced.

  `TrustedProxies` configures the intermediaries trusted for client
  addresses reported through PROXY protocol or forwarding fields.
- **Carriers before a session.** `ListenerConfig::limits` holds the bounds
  that `Listener::set_limits` changes while the listener runs
  (`Listener::limits` reads them). Every carrier holds a slot of its source
  (`ListenerLimits::max_pending_per_source`, default 8, at least 2) and one of the
  listener (`ListenerLimits::max_pending`, default 1024, `None` for
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
- **Managing carriers.** Register candidates with an identity and cache key
  using `Candidate::with_identity`, then construct a `SessionController`.
  `open` establishes the first carrier and `manage` binds an existing
  multipath session. Submit `SessionTarget` revisions to grow or replace
  members. The controller protects direction coverage and shares retry
  admission across its sessions. `CarrierCache::export` and `import`
  persist v2 history across restarts.

## Memory and allocators

What a peer can make a session hold is bounded per kind: received
datagrams by `Config::datagram_receive_bytes` (the session queue, 1 MiB) and,
per stream, by `datagram_stream_queue` (32) and `datagram_stream_bytes`
(512 KiB, `None` for no byte bound); peer streams by
`max_incoming_streams`, whose range ends at `zmux::MAX_STREAM_CREDIT`
(2^60, as many as the protocol can count).

Every datagram queue, the send queue included, also bounds how long its
datagrams wait (`Config::datagram_queue_delay`, 20 ms; `None`: off): once
the datagrams leaving a queue have waited longer for 100 ms, CoDel drops
some as they leave, counted, so a slow reader gets fresh datagrams instead
of stale ones. `Session::path_datagram_size` (and
`SendStream::path_datagram_size`) is the largest payload that leaves as one
carrier datagram, a QUIC DATAGRAM as path MTU discovery sizes it, instead
of in a record; `SessionEvent::DatagramPathChanged` reports changes. A
packet forwarder uses it as its MTU.

zmux gives memory back as load goes away: idle pipes return their read and
write buffers after a second. The process-wide receive pool keeps up to
8 MiB of idle backing capacity. Closed streams and sessions free their state.
Whether the freed memory also leaves the process is up to the global allocator, which
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
| `zmux::helpers` | helpers above the public API: `splice` (relaying a stream into another), `resolve_duplicate` (two sessions between the same endpoints) | `tokio`; `resolve_duplicate` either driver |
| `zmux::sched` | the scheduler: `Scheduler` and the custom policy's interface (`Pick`) | always |
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
| `zmux-webtransport` (`adapter/webtransport`) | WebTransport sessions (Quinn, HTTP/3) | further streams |

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
