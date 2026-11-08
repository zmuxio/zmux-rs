# zmux-rustls

TLS 1.3 pipe carriers for [zmux](../../README.md) over `tokio-rustls`.

`zmux_rustls::pipe(stream)` turns an established TLS stream, client or
server, into a `zmux::PipeIo`; `zmux_rustls::over_tcp(stream)` does the same for
TLS over TCP and adds the socket's capabilities. The carrier has:

- the TLS 1.3 exporter for both labels zmux uses: the session secret of a
  bootstrap carrier with `PipeAuth::exporter()`, and the binding of Bound
  joins, so that a Hello copied to another connection does not verify.
  TLS 1.2 connections and connections still in their handshake (early data)
  have none, and their joins are not Bound;
- partial reads declared (tokio-rustls hands over one record per read), so
  that zmux reads again before it decides that no input is pending;
- the negotiated ALPN identifier as the session's protocol;
- over TCP: the socket's minimum RTT, unsent bytes and low-water mark, and an
  abort that shuts the socket down without TLS close_notify, so that the peer
  sees a failed pipe rather than a graceful end.

The adapter chooses no crypto provider, protocol version, buffer size or ALPN
identifier: the application's rustls configuration does
(`zmux::alpn_protocols(&[])` gives zmux's identifiers).

`zmux_rustls::serve` applies the listener's admission
(`ListenerConfig::admission`, a `zmux::Admission`): each connection takes its
source slot before the handshake; after it, the connection's first bytes and
its metadata (source and peer, ALPN identifier, server name, TLS exporter)
decide whether it reaches the listener, the listener's fallback connection
handler (`ListenerConfig::fallback`) with the bytes read replayed, or
neither. Nothing is written above TLS before acceptance, and
TLS early data is refused. `zmux_rustls::dial` with a `zmux::Credential`,
such as `zmux::PrefixAuth`, writes its prefix as a client's first bytes.

```rust,no_run
# async fn example(
#     tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
# ) -> Result<(), Box<dyn std::error::Error>> {
let mut config = zmux::Config::default();
config.pipe_auth = zmux::PipeAuth::exporter();
let session = zmux::Session::connect(zmux_rustls::over_tcp(tls), config).await?;
# Ok(())
# }
```
