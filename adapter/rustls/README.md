# zmux-rustls

TLS 1.3 pipe carriers for [zmux](../../README.md) over `tokio-rustls`.

`zmux_rustls::pipe(stream)` turns an established TLS stream, client or
server, into a `zmux::PipeIo`; `zmux_rustls::tcp(stream)` does the same for
TLS over TCP and adds the socket's capabilities. The carrier has:

- the TLS 1.3 exporter for both labels zmux uses: the session secret of a
  bootstrap carrier with `PipeAuth::tls()`, and the binding of carrier-bound
  joins, so that a join token copied to another connection does not verify.
  TLS 1.2 connections and connections still in their handshake (early data)
  have none, and their joins are not carrier-bound;
- partial reads declared (tokio-rustls hands over one record per read), so
  that zmux reads again before it decides that no input is pending;
- the negotiated ALPN identifier as the session's protocol;
- over TCP: the socket's minimum RTT, unsent bytes and low-water mark, and an
  abort that shuts the socket down without TLS close_notify, so that the peer
  sees a failed pipe rather than a graceful end.

The adapter chooses no crypto provider, protocol version or buffer size: the
application's rustls configuration does.

```rust,no_run
# async fn example(
#     tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
# ) -> Result<(), Box<dyn std::error::Error>> {
let mut config = zmux::Config::default();
config.pipe_auth = zmux::PipeAuth::tls();
let session = zmux::Session::connect(zmux_rustls::tcp(tls), config).await?;
# Ok(())
# }
```
