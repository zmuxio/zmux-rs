# zmux-quinn

QUIC connections as [zmux](../../README.md) carriers over `quinn`.

A `QuicCarrier` takes a whole established `quinn::Connection`. A pipe is one
bidirectional stream of it (`open_pipe`, `accept_pipe`); the pipe's lanes
are further unidirectional streams that zmux opens as it needs them, so that
a loss on one lane does not hold back the streams on the others. The carrier
runs the connection's accept loop and hands every stream the peer opens to
zmux: to a `zmux::Listener` when one is given, else lanes to
`zmux::carrier::handle_lane` and pipes to `accept_pipe`. The connection's streams
belong to zmux; its datagrams, statistics, path and close stay the
application's (`connection()`).

The carrier wires:

- the connection's TLS 1.3 exporter, for `PipeAuth::tls()` and for
  carrier-bound joins (none when the handshake was not complete, as with
  0-RTT);
- flow control for lanes: the peer may open `Options::lanes` lanes at once,
  and the connection's receive window covers that many stream windows and a
  pipe's own; with a listener the window is charged to its memory budget;
- failure signalling: a stream zmux drops without ending it is reset (or
  stopped) with `ZMUX_CARRIER_FAILED`.

```rust,no_run
# async fn example(conn: quinn::Connection) -> Result<(), Box<dyn std::error::Error>> {
use zmux_quinn::{Options, QuicCarrier};

let quic = QuicCarrier::new(conn, None, Options::default());
let mut config = zmux::Config::default();
config.pipe_auth = zmux::PipeAuth::tls();
let session = zmux::Session::connect(quic.open_pipe().await?, config).await?;
# Ok(())
# }
```

The adapter enables no crypto provider of quinn's: the application's endpoint
configuration chooses it.
