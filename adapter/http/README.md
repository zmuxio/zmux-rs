# zmux-http

HTTP/1.1 and HTTP/2 carriers of [zmux](../../README.md) pipes over `hyper`.

- **Bidirectional**: one `POST` whose request body carries the client's
  outbound direction and whose response body its inbound one, streamed at
  the same time (`dial_http1`, `Http2Connection::open_pipe`).
- **Uplink** `POST` and **downlink** `GET`: one-way carriers
  (`dial_http1_carrier_over`, `Http2Connection::open_carrier` with a
  `zmux::DialRequest`). A downlink joins a session out of band with the
  `Zmux-Pipe-Join` header of a `zmux::PipeReservation`; the two together
  form a split bootstrap, paired by a random token in `Zmux-Pipe-Pair`
  (`dial_http1_split`, `connect_http1_split`,
  `Http2Connection::open_split`), for paths that pass a streamed request
  body and a streamed response body but not both on one request. The
  pairing token is a bearer secret until the session is established: run
  a split bootstrap over TLS to the server or to an intermediary trusted
  with the carriers' contents.
- **Exchange**: bounded `POST` requests with a `Content-Length`, for paths
  that buffer whole bodies (below).

The server classifies every request by its head alone (`classify`): an
upgrade, a `GET` with `Zmux-Pipe-Pair` or `Zmux-Pipe-Join` (downlink), a
`POST` with `Zmux-Pipe-Pair` (uplink), a `POST` with a `Content-Length`
(exchange), a `POST` without one (bidirectional, or an uplink with
`Zmux-Pipe-Join`), and everything else for the host's handler. All kinds
can therefore share one request target (`Options::path`, default
`/zmux`). Nothing is answered before a carrier is accepted: with an
admission (the listener's `ListenerConfig::admission`, which every carrier
kind goes through, the exchange's new carriers included), when it accepts, on
the first bytes of the request body or, for a request without a body such
as a downlink `GET`, on the request head (a credential in a header field);
without, when the listener first writes on the carrier or has taken it.
Responses that carry a downlink are sent with `Cache-Control: no-store` and
`X-Accel-Buffering: no`, and no carrier body has a `Content-Length`, so that
reverse proxies forward them as they are written. A carrier request that an
intermediary forwarded from TLS early data (`Early-Data: 1`) is answered
`425 Too Early`. A clean end of a body is the graceful end of its
direction; a failed pipe ends its body with an error (an HTTP/2 stream
reset, an HTTP/1.1 connection closed mid-body), and a cut request is a read
error at the other end, never a clean end.

- HTTP/1.1: one carrier per connection.
- HTTP/2: one connection carries many carriers (`Http2Connection`), which
  report the connection as their carrier connection. Lanes on further
  requests of the connection are off by default, since the streams of an
  HTTP/2 connection share one ordered TCP byte stream; `Options::lanes`
  turns them on (client side). `Http2Connection::dial` and `http1_dial`
  give a `zmux::Dial` for pools, rejoins and out-of-band joins.
- Server: `serve` accepts TCP connections, speaks HTTP/1.1 and HTTP/2
  (prior knowledge, as a reverse proxy that speaks HTTP/2 to its origin
  without TLS does) and hands every carrier on `Options::path` to a
  `zmux::Listener`; `handle_request` does the same for one request inside
  an HTTP server of the application's own, and gives back a request that
  carries no pipe (`Unhandled::Fallback`, its body bytes read for the
  decision replayed in front of the rest) or one to end without a response
  (`Unhandled::Abort`: an admission's stall, once over, or close). Requests
  that carry no pipe go to `Options::fallback`, an HTTP handler, or are
  answered with 404.
- Behind a reverse proxy or CDN: TLS ends at the intermediary, so prefix
  tokens are unbound. A carrier's source, for the listener's per-source
  limits and the admission, is the client that an intermediary the
  listener trusts reports (`zmux::ListenerConfig::trusted_proxies`): in a
  PROXY protocol header (`serve`) or a forwarding header field such as
  `X-Forwarded-For` (`request_source`). Keep the session's keep-alive
  period and probe interval below the shortest idle limit on the path.
- Split carriers: `join_http1_split_with` (or `Http2Connection::join_split`)
  joins a downlink and an uplink as two further pipes of a session; a split
  bootstrap's carrier makes pipe pair 0 only, and `Session::add_pipe`
  refuses it. A `zmux::helpers::PipePool::join` keeps such pairs up.
- Client: `Options::credential` presents a `zmux::Credential`, such as an
  unbound `zmux::PrefixAuth` token: its prefix first on every request body
  that carries a pipe or a lane, its header form on a downlink `GET`.

TLS is the caller's concern: the adapter speaks HTTP over the connections
it is given.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use zmux::{Config, Listener, ListenerConfig};
use zmux_http::Options;

let listener = Listener::new(Config::default(), ListenerConfig::default());
let tcp = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));

let session = zmux_http::connect_http1("127.0.0.1:8080", &Options::default(), Config::default()).await?;
// The same server takes a split bootstrap on the same target.
let split = zmux_http::connect_http1_split("127.0.0.1:8080", &Options::default(), Config::default()).await?;
# drop((session, split));
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

// Server: POSTs with a Content-Length under /zmux/exchange are exchange
// requests (with_path("/zmux") shares the carriers' target).
let listener = Listener::new(Config::default(), ListenerConfig::default());
let exchange = ExchangeServer::new(&listener, options.clone())?;
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
  request inside an HTTP server of the application's own, or gives it
  back, its body bytes replayed, when it is not authenticated.
- A server authenticates a request when its MAC verifies, its Time is
  within `ExchangeOptions::time_window` (60 s) of the server's clock and
  its (Carrier ID, Nonce) pair is new; at most
  `ExchangeOptions::max_recorded` (262144) pairs are recorded. Every other
  request, and every request `serve` does not take, goes to
  `Options::fallback` (status 404 without one).
- The request path is a template: `{instance}` is a random token of the
  carrier, `{nonce}` a fresh value in every request; a path without
  `{nonce}` carries it in the query parameter `n`, so a cache keyed on the
  target never matches.
- `ExchangeOptions` documents the local parameters and their defaults:
  outstanding requests, piece sizes (`default_piece_size`: every body
  stays within 1,000,000 bytes after the encoding, below the common 1 MiB
  request body limit of reverse proxies; 999,938 bytes in binary, 749,938
  in base64) and acceptance limits (1 MiB or the piece size), hold time
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
