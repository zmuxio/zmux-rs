# zmux-quinn

QUIC connections as [zmux](../../README.md) carriers over `quinn`.

A `Carrier` uses an established `quinn::Connection`. A pipe is one
bidirectional stream of it (`open_pipe`, `accept_pipe`); the pipe's lanes
are further unidirectional streams that zmux opens as it needs them, so that
a loss on one lane does not hold back the streams on the others. The carrier
made with `Carrier::new` runs the connection's accept loop and hands every
stream the peer opens to zmux: to a `zmux::Listener` when one is given, else lanes to
`zmux::adapter::handle_lane` and pipes to `accept_pipe`. The carrier owns the
connection: its streams and datagrams belong to zmux, and once no carrier
clone and no pipe made from it is left the connection is closed. Keep the
`Carrier` for as long as the connection is to stay open; its statistics and
path stay readable through `connection()`.

Use `Carrier::borrow(&connection, &options).await?` for an established
client connection whose lifetime the host manages. Open pipes on it with
`open_pipe`. The live bindings share the lane receiver and datagram router.
The host receives peer-opened bidirectional streams and closes the connection.
For an established connection, pass the receive window used by the host's
QUIC transport configuration with `LaneWindows::with_established_receive_window`.

The carrier wires:

- the connection's TLS 1.3 exporter, for `PipeAuth::exporter()` and for
  Bound joins (none when the handshake was not complete, as with
  0-RTT);
- flow control for lanes: the peer may open `LaneWindows::lanes` lanes at once,
  and the connection's receive window covers that many stream windows and a
  pipe's own; with a listener the window is charged to its memory budget;
- QUIC datagrams as the datagram channel of its pipes: a session with
  datagrams enabled sends each datagram that fits one there instead of in a
  record when the peer negotiated it, so that a lost packet loses that
  datagram rather than delaying the ones after it; `Options::transport_config`
  enables them;
- failure signalling: a stream zmux drops without ending it is reset (or
  stopped) with `ZMUX_CARRIER_FAILED`, never ended with a FIN.

`candidate(endpoint, addr, server_name, &options)` is a `zmux::Candidate` for
carrier modes.

```rust,no_run
# async fn example(conn: quinn::Connection, receive_window: u64) -> Result<(), Box<dyn std::error::Error>> {
use zmux_quinn::{Carrier, LaneWindows, Options};

let windows = LaneWindows::new().with_established_receive_window(receive_window);
let quic = Carrier::new(conn, &Options::new().with_windows(windows))?;
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
listener. Both `serve` and `serve_connection` dispatch a first-stream
`Fallback` or `Takeover` to the listener's byte-stream target (`ListenerConfig::fallback`, a `zmux::Takeover` of the stream with
every byte read replayed; `takeover_connection` gives its connection), and
the connection is closed once the fallback completed; without one it is
stalled with its stream. An explicit `Close` ends it immediately. Ticket
admission rejects presentations carried in 0-RTT bytes. A 1-RTT stream on
the same connection can present a ticket. Apply
`zmux_quinn::track_server_early_data` to a custom Quinn server configuration
before using it for ticket admission. It is included in
`zmux_quinn::server_config`. Without tracking, `adopt_connection` and
`serve_connection` return `InvalidInput` for ticket-protected listeners. A
client presents a `zmux::CarrierCredential` (such as `zmux::PrefixAuth`) with
`Options::with_carrier_credential`: `dial` and `connect` write its prefix on the
first stream once the handshake completed, and send no 0-RTT data; or it
writes the prefix itself with `Carrier::open_pipe_with_prefix`.

The adapter enables no crypto provider of quinn's: the application's endpoint
configuration chooses it.
