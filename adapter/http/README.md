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

## Exchange carrier

Where a long-lived exchange does not survive the path (intermediaries
that buffer whole bodies, HTTP/1.0 hops without chunked coding, limits on
request duration, caches, lost or repeated requests), the exchange
carrier builds one byte-stream carrier out of a sequence of bounded POST
requests, each with a `Content-Length`. The client numbers its bytes in
UP pieces and keeps DOWN requests outstanding, which the server answers
with numbered pieces of its bytes; requests are repeated until they have
a result, and a MAC binds every response to the request it answers, so a
cached or rewritten response is never taken.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use zmux::{Config, Listener, ListenerConfig};
use zmux_http::{ExchangeOptions, ExchangeServer, Options};

let options = ExchangeOptions::default().with_psk(*b"a shared secret");

// Server: POSTs under /zmux/exchange are exchange requests.
let listener = Listener::new(Config::default(), ListenerConfig::default());
let exchange = ExchangeServer::new(&listener, options.clone());
let tcp = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default().with_exchange(exchange)));

// Client: the carrier exists at once; zmux's first record rides the
// first UP request.
let session = zmux_http::connect_exchange("127.0.0.1:8080", &options, Config::default()).await?;
# drop(session);
# Ok(())
# }
```

- `dial_exchange_with` makes the connections with a closure of the
  caller's (TLS); `dial_exchange_split` sends UP and DOWN requests to
  different endpoints and paths (`ExchangeOptions::down_path`), which must
  reach the same server process. `ExchangeServer::handle` answers one
  request inside an HTTP server of the application's own.
- The request path is a template: `{instance}` is a random token of the
  carrier, `{nonce}` a fresh value in every request; a path without
  `{nonce}` carries it in the query parameter `n`, so a cache keyed on the
  target never matches.
- `ExchangeOptions` documents the local parameters and their defaults:
  outstanding requests, piece sizes and body limits (1 MiB), hold time
  (20 s, below every intermediary's response timeout), coalescing delay,
  window, request timeout, carrier deadline, backoff, idle timeout. The
  bytes a server carrier holds count against the listener's memory budget.
- Both ends must agree on the PSK and on the body encoding (binary, or
  base64 for paths that only pass text).

**Trust.** The PSK authenticates requests and responses; it does not
encrypt them. A TLS-terminating proxy or CDN on the path reads and could
record everything the carrier carries; zmux's own guarantees assume TLS
that terminates at the zmux endpoint.

The `exchange_interop` example is a client or server for checks against
another implementation (see its documentation for the environment
variables).
