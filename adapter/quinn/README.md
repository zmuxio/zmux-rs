# zmux-quinn

QUIC connections as [zmux](../../README.md) carriers over `quinn`.

A `QuicCarrier` takes a whole established `quinn::Connection`. A pipe is one
bidirectional stream of it (`open_pipe`, `accept_pipe`); the pipe's lanes
are further unidirectional streams that zmux opens as it needs them, so that
a loss on one lane does not hold back the streams on the others. The carrier
runs the connection's accept loop and hands every stream the peer opens to
zmux: to a `zmux::Listener` when one is given, else lanes to
`zmux::carrier::handle_lane` and pipes to `accept_pipe`. The connection's streams
and datagrams belong to zmux; its statistics, path and close stay the
application's (`connection()`).

The carrier wires:

- the connection's TLS 1.3 exporter, for `PipeAuth::exporter()` and for
  carrier-bound joins (none when the handshake was not complete, as with
  0-RTT);
- flow control for lanes: the peer may open `Options::lanes` lanes at once,
  and the connection's receive window covers that many stream windows and a
  pipe's own; with a listener the window is charged to its memory budget;
- QUIC datagrams as the datagram channel of its pipes: a session with
  datagrams enabled sends each datagram that fits one there instead of in a
  record when the peer negotiated it, so that a lost packet loses that
  datagram rather than delaying the ones after it; `Options::transport_config`
  enables them;
- failure signalling: a stream zmux drops without ending it is reset (or
  stopped) with `ZMUX_CARRIER_FAILED`.

```rust,no_run
# async fn example(conn: quinn::Connection) -> Result<(), Box<dyn std::error::Error>> {
use zmux_quinn::{Options, QuicCarrier};

let quic = QuicCarrier::new(conn, Options::default());
let mut config = zmux::Config::default();
config.pipe_auth = zmux::PipeAuth::exporter();
let session = zmux::Session::connect(quic.open_pipe().await?, config).await?;
# Ok(())
# }
```

`client_config` and `server_config` keep the rustls configurations' ALPN
identifiers as they are: configure them explicitly (zmux's are
`zmux::alpn_protocols(&[])`). `server_config` refuses early data unless the
options enable 0-RTT.

`serve` admits every connection by the listener's admission
(`ListenerConfig::admission`, a `zmux::Admission` such as
`Admission::prefix_auth`) when it has one: each connection takes its source
slot before the QUIC handshake, and the decision is taken on the first bytes
of the connection's first bidirectional stream, within the peek timeout from
the end of the handshake. Only once that
stream is accepted does it become the connection's first pipe, the rest of
its prefix in front, and do the connection's other streams reach the
listener. A connection that is not accepted goes to an optional
`QuicFallback` handler with that stream, every byte read replayed;
without one it is closed (after a stall, or at once). Admitted connections
never take 0-RTT data: the server configuration must refuse early data. A
client presents a `zmux::Credential` (such as `zmux::PrefixAuth`) with
`Options::with_credential`: `dial` and `connect` write its prefix on the
first stream once the handshake completed, and send no 0-RTT data; or it
writes the prefix itself with `QuicCarrier::open_pipe_with_prefix`.

The adapter enables no crypto provider of quinn's: the application's endpoint
configuration chooses it.
