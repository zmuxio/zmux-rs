# zmux-websocket

WebSocket pipe carriers for [zmux](../../README.md) over `tokio-tungstenite`.

Every binary message carries one record's Frames field (message framing),
so intermediaries that re-chunk the byte stream cannot break records. The
subprotocol is the ALPN identifier (`qmux-02` by default, `qmux-01`
accepted).

- `connect(url, options, config)` / `dial(request, options)`: a session, or
  a carrier for a further pipe, over a new WebSocket;
- `serve(listener, tcp, options)`: WebSocket upgrades on a TCP
  listener, handed to a `zmux::Listener`; `serve_tls` the same over TLS
  (`wss://`). Behind intermediaries the listener trusts, the source is the
  client a PROXY protocol header or a forwarding header field reports;
  `accept(io, info, listener,
  options)` upgrades one connection, plain or TLS, or refuses it, `info`
  giving the connection's metadata (address, TLS exporter);
- `Options` (`Options::new()` for the defaults): the subprotocols, `qmux-02[.<application>]` or an
  application's own identifier, and a client's `zmux::CarrierCredential`, presented
  in a request header field (a `zmux::PrefixAuth` token in
  `Zmux-Prefix-Auth`, bound to the TLS connection with `dial_tls`);
- `pipe(ws, protocol)`: any established WebSocket stream;
- `candidate(connect, url, options)` and `candidate_tls(url, tls, options)`:
  `zmux::Candidate`s for carrier modes, over a connection of the
  application's or over TLS by rustls.

A request head ends with an empty line after CRLF or bare LF line endings,
as HTTP/1.1 parsers accept.

Only a request that is a valid upgrade, offers an accepted subprotocol and
passes the listener's admission (`ListenerConfig::admission`, decided on
the upgrade request head) is upgraded. Every other request is refused before
anything is written: `serve` hands it to the listener's fallback
(`ListenerConfig::fallback`, a `zmux::Fallback`) with the bytes read replayed, or answers
`404 Not Found` without one.

A Close frame is the graceful end of a pipe; a connection that ends
without one is a failure. Over plain TCP a failed pipe is aborted without a
Close frame. For `wss://`, `dial_tls` and `connect_tls` take the
application's `tokio_rustls::TlsConnector`; `dial_over` upgrades an
established TLS stream. With the `wss` feature (off by default), `dial` and
`connect` also take `wss://` URLs, trusting the Mozilla roots of
`webpki-roots` with rustls's ring provider; `tls_connector` makes a connector
of other roots.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let session = zmux_websocket::connect("ws://example.com/zmux", &Default::default(), zmux::Config::default()).await?;
# drop(session);
# Ok(())
# }
```
