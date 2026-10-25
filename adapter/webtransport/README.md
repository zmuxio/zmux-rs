# zmux-webtransport

WebTransport sessions as [zmux](../../README.md) carriers over
`web-transport-quinn`.

A `WebTransportCarrier` takes a whole established WebTransport session. A
pipe is one bidirectional stream of it (`open_pipe`, `accept_pipe`); the
pipe's lanes are unidirectional streams that zmux opens as it needs them, in
both directions, so that a loss on one lane does not hold back the others.
The carrier runs the session's accept loop and hands every stream the peer
opens to zmux: to a `zmux::Listener` when one is given, else lanes to
`zmux::carrier::handle_lane` and pipes to `accept_pipe`. Because WebTransport runs
over HTTP/3, the carrier reaches servers through HTTP/3 front ends that
forward WebTransport.

`connect(&client, url, &options, config)` establishes a zmux session over a
new WebTransport session; `serve(listener, server, options)` accepts
WebTransport sessions and hands their streams to a listener.

The carrier wires:

- the TLS 1.3 exporter of the QUIC connection under the session, for
  `PipeAuth::tls()` and carrier-bound joins (behind a front end that
  terminates TLS, use a PSK);
- flow control for lanes: the peer may open `Options::lanes` lanes at once,
  and the connection's receive window covers that many stream windows and a
  pipe's own, charged to the listener's memory budget, or to the zmux
  session's own without a listener; `Options::transport_config` gives the
  endpoints the matching transport parameters;
- failure signalling: a stream zmux drops without ending it is reset (or
  stopped) with `ZMUX_CARRIER_FAILED`, and a session that ends under a pipe
  is a failure of the pipe.

```rust,no_run
# async fn example(client: web_transport_quinn::Client) -> Result<(), Box<dyn std::error::Error>> {
let url: zmux_webtransport::Url = "https://example.com/zmux".parse()?;
let mut config = zmux::Config::default();
config.pipe_auth = zmux::PipeAuth::tls();
let options = zmux_webtransport::Options::default();
let session = zmux_webtransport::connect(&client, url, &options, config).await?;
# drop(session);
# Ok(())
# }
```

The endpoints use the HTTP/3 ALPN identifier `h3`. The crypto provider is
ring by default (feature `ring`), or aws-lc-rs (feature `aws-lc-rs`).
