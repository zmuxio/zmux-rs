# zmux-http

HTTP/1.1 and HTTP/2 exchanges as [zmux](../../README.md) pipes over `hyper`.

A pipe is one HTTP exchange with its two bodies paired: the request body
carries the client's outbound direction, the response body its inbound
one. The server answers at once with a streaming response, so both bodies
flow at the same time. A clean end of a body is the graceful end of its
direction; a failed pipe ends its body with an error (an HTTP/2 stream
reset, an HTTP/1.1 connection closed mid-body), and a cut exchange is a
read error at the other end, never a clean end.

- HTTP/1.1: one pipe per connection (`dial_http1`, `connect_http1`).
- HTTP/2: one connection carries many pipes (`Http2Connection`), which
  report the connection as their carrier connection. Lanes on further
  requests of the connection are off by default, since the streams of an
  HTTP/2 connection share one ordered TCP byte stream; `Options::lanes`
  turns them on (client side).
- Server: `serve` accepts TCP connections, speaks HTTP/1.1 and HTTP/2
  (prior knowledge) and hands every POST to `Options::path` (default
  `/zmux`) to a `zmux::Listener`; `handle_request` does the same for one
  request inside an HTTP server of the application's own.

An out-of-band join travels in the `Zmux-Pipe-Join` request header. TLS is
the caller's concern: the adapter speaks HTTP over the connections it is
given.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use zmux::{Config, Listener, ListenerConfig};
use zmux_http::Options;

let listener = Listener::new(Config::default(), ListenerConfig::default());
let tcp = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));

let session = zmux_http::connect_http1("127.0.0.1:8080", &Options::default(), Config::default()).await?;
# drop(session);
# Ok(())
# }
```
