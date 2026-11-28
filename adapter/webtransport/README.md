# zmux-webtransport

WebTransport sessions as [zmux](../../README.md) carriers over Quinn and HTTP/3.

A `Carrier` takes a whole established WebTransport session. A
pipe is one bidirectional stream of it (`open_pipe`, `accept_pipe`); the
pipe's lanes are unidirectional streams that zmux opens as it needs them, in
both directions, so that a loss on one lane does not hold back the others.
The carrier runs the session's accept loop and hands every stream the peer
opens to zmux: to a `zmux::Listener` when one is given, else lanes to
`zmux::adapter::handle_lane` and pipes to `accept_pipe`. Because WebTransport runs
over HTTP/3, the carrier reaches servers through HTTP/3 front ends that
forward WebTransport.

`connect(&client, url, &options, config)` establishes a zmux session over a
new WebTransport session; `serve(listener, endpoint, options)` accepts
WebTransport sessions on a QUIC endpoint, within the listener's setup
limits, and hands their streams to a listener. With the listener's
admission (`ListenerConfig::admission`), each session request is decided on before it is
answered (`admit`, without a prefix): accepted requests get 200, those it
refuses get 404, or are stalled or closed without a response. The head may
defer the decision to the session's first bidirectional stream
(`AdmissionVerdict::Defer`): the session is answered, nothing else of it
reaches the listener before, and a first stream not accepted goes to the
listener's fallback (`ListenerConfig::fallback`, a `zmux::Takeover`;
`takeover_session` gives the session), which is closed once the fallback
completed. A client's `zmux::CarrierCredential`
(`Options::with_carrier_credential`) travels in a request header field, such as a
`zmux::PrefixAuth` ticket in `Zmux-Prefix-Auth`. Apply `zmux_quinn::track_server_early_data`
to the server's Quinn configuration before using ticket admission.
The client's `dial` presents an encrypted bearer ticket. For a bound ticket,
`dial_over` makes the session on the application's QUIC connection and
uses its exporter. `candidate(client, url, &options)` is a `zmux::Candidate` for
carrier modes.

For an established QUIC connection or WebTransport session, pass the host
transport's configured receive window with `LaneWindows::with_established_receive_window`.

The carrier wires:

- the TLS 1.3 exporter of the QUIC connection under the session, for
  `PipeAuth::exporter()` and Bound joins, declared secure with a Binding of the
  connection, not the stream (behind a front end that
  terminates TLS, use a PSK);
- flow control for lanes: the peer may open `LaneWindows::lanes` lanes at once,
  and the connection's receive window covers that many stream windows and a
  pipe's own, charged to the listener's memory budget, or to the zmux
  session's own without a listener; `Options::transport_config` gives the
  endpoints the matching transport parameters;
- failure signalling: a stream zmux drops without ending it is reset (or
  stopped) with `ZMUX_CARRIER_FAILED`, and a session that ends under a pipe
  is a failure of the pipe.

Each QUIC connection carries one WebTransport session. The adapter sends the
[draft-16](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-16.html)
`webtransport-h3` token and `SETTINGS_WT_ENABLED`, with HTTP/3 DATAGRAM and
the server's Extended CONNECT setting. Both roles also advertise and recognize
the four historical WT settings. The server accepts the legacy
`webtransport` token and validates any Origin against the target authority. A client accepts any final 2xx and exposes other final
statuses as `zmux_webtransport::ConnectRejected`.

The WT stream header carries the full CONNECT stream ID. Native datagrams
use its Quarter Stream ID under [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297).
The adapter handles peer CLOSE and DRAIN. DRAIN leaves existing streams
and datagrams active while notifying the application to finish gracefully. Unknown extensions and
unused flow control capsules are ignored. QUIC enforces stream and connection
credit. The adapter omits WT initial credit settings and flow-control capsules. HTTP routing, WT application
subprotocol negotiation and additional response headers are outside the
carrier API.

Quinn uses ordinary `RESET_STREAM` and `STOP_SENDING` with mapped WebTransport
application error codes. Clients that require `RESET_STREAM_AT` can reject
the connection during negotiation.

```rust,no_run
# async fn example(client: zmux_webtransport::Client) -> Result<(), Box<dyn std::error::Error>> {
let url: zmux_webtransport::Url = "https://example.com/zmux".parse()?;
let mut config = zmux::Config::default();
config.pipe_auth = zmux::PipeAuth::exporter();
let options = zmux_webtransport::Options::default();
let session = zmux_webtransport::connect(&client, url, &options, config).await?;
# drop(session);
# Ok(())
# }
```

The endpoints use the HTTP/3 ALPN identifier `h3`. The crypto provider is
ring by default (feature `rustls-ring`), or aws-lc-rs (feature
`rustls-aws-lc-rs`).
