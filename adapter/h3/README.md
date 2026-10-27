# zmux-h3

HTTP/3 request streams as [zmux](../../README.md) carriers over `h3` and
`quinn`.

A pipe is one HTTP/3 request: the request body carries the client's
outbound direction and the response body its inbound direction (the
server's the other way round). HTTP/3 reaches servers through front ends,
proxies and load balancers that forward HTTP/3 requests.

- `H3Client` drives an HTTP/3 connection: `open_pipe` makes a pipe on a new
  request, and the pipe's lanes are further requests on the same
  connection, opened by zmux as it needs them. Only the client opens lanes:
  an HTTP/3 server cannot open requests, so lanes in both directions need
  WebTransport.
- `serve(listener, endpoint, options)` (or `serve_connection` for one
  connection) answers every request with 200 and hands it to a
  `zmux::Listener` as a carrier of its connection, which tells new
  sessions, joins and client lanes apart.
- `connect(&endpoint, addr, uri, &options, config)` establishes a session
  over a new connection.

The carriers wire the TLS 1.3 exporter of the QUIC connection (for
`PipeAuth::tls()` and carrier-bound joins; behind a front end that
terminates TLS, use a PSK), a connection receive window sized for the lanes
and charged to the memory budget, and failure signalling: a sent body dropped
without its end is reset with `ZMUX_CARRIER_FAILED`; dropping a received
body cancels it with the transport's STOP_SENDING(0). A request or
connection that fails under a pipe is a failure of the pipe. At most one
body write is in flight at a time.

```rust,no_run
# async fn example(endpoint: quinn::Endpoint) -> Result<(), Box<dyn std::error::Error>> {
let uri: http::Uri = "https://example.com/zmux".parse()?;
let addr = "192.0.2.1:443".parse()?;
let options = zmux_h3::Options::default();
let session =
    zmux_h3::connect(&endpoint, addr, uri, &options, zmux::Config::default()).await?;
# drop(session);
# Ok(())
# }
```

The endpoints use the HTTP/3 ALPN identifier `h3` (`zmux_h3::ALPN`) and the
transport parameters of `Options::transport_config`.
