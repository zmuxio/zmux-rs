# zmux-websocket

WebSocket pipe carriers for [zmux](../../README.md) over `tokio-tungstenite`.

Every binary message carries one record's Frames field (message framing),
so intermediaries that re-chunk the byte stream cannot break records. The
subprotocol is the ALPN identifier (`qmux-02` by default, `qmux-01`
accepted), and the `Zmux-Pipe-Join` request header carries an out-of-band
join to a listener.

- `connect(url, options, config)` / `dial(request, options)`: a session, or
  a carrier for a further pipe, over a new WebSocket;
- `serve(listener, tcp, options)`: WebSocket upgrades on a TCP listener,
  handed to a `zmux::Listener`; `accept(io, peer, options)` upgrades one
  connection, plain or TLS;
- `Options`: the subprotocols, `qmux-02[.<application>]` or an
  application's own identifier;
- `pipe(ws, protocol)`: any established WebSocket stream.

A Close frame is the graceful end of a pipe; a connection that ends
without one is a failure. Over plain TCP a failed pipe is aborted without a
Close frame. No TLS is chosen here: enable a TLS feature of
`tokio-tungstenite` for `wss://`, or upgrade an established TLS stream.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let session = zmux_websocket::connect("ws://example.com/zmux", zmux::Config::default()).await?;
# drop(session);
# Ok(())
# }
```
