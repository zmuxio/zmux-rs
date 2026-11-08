//! HTTP carriers of zmux pipes over hyper: HTTP/1.1
//! and HTTP/2 requests whose bodies carry a pipe's directions, and the
//! exchange carrier, which builds one pipe out of many bounded requests.
//!
//! - **Bidirectional**: one `POST` whose request body is the uplink and
//!   whose response body is the downlink, streamed at the same time
//!   ([`dial_http1`], [`Http2Connection::open_pipe`]).
//! - **Uplink**: a `POST` whose request body is the uplink, and
//!   **Downlink**: a `GET` whose response body is the downlink
//!   ([`dial_http1_carrier_over`], [`Http2Connection::open_carrier`]):
//!   the two carriers of a split bootstrap or join paired by `Zmux-Pipe-Pair`
//!   ([`dial_http1_split`], [`Http2Connection::open_split`]) for paths
//!   that do not pass a bidirectional request.
//! - **Exchange** ([`dial_exchange`], [`ExchangeServer`]): bounded `POST`
//!   requests with a `Content-Length`, for paths that buffer whole bodies.
//!
//! The server classifies each request by its head alone ([`classify`]), so
//! that every kind can share one request target, and answers nothing before
//! the carrier is accepted: with a [`ListenerConfig::admission`](zmux::ListenerConfig::admission), when its
//! decision is `Accept` (on the first bytes of the request body, or on the
//! request head for a request without a body); without, when the listener
//! first writes on the carrier or has taken it. Responses that carry a
//! downlink are sent with `Cache-Control: no-store` and `X-Accel-Buffering:
//! no`, and no body has a `Content-Length`, so that reverse proxies forward
//! them as they are written. A carrier request that an intermediary
//! forwarded from TLS early data (`Early-Data: 1`) is answered `425 (Too
//! Early)`. Requests that carry no pipe go to [`Options::fallback`], or are
//! answered with 404 ([`handle_request`] says which). A body that ends
//! cleanly is the graceful end of its direction; a failed pipe ends its
//! body with an error (an HTTP/2 stream reset, an HTTP/1.1 connection
//! closed mid-body), and a request that is cut is a read error at the other
//! end, never a clean end.
//!
//! - HTTP/1.1: one carrier per connection ([`dial_http1`],
//!   [`connect_http1`]; a split bootstrap uses two).
//! - HTTP/2: one connection carries many carriers ([`Http2Connection`]),
//!   which report the connection as their carrier connection, so that the
//!   listener knows they share it. Lanes (further requests of the same
//!   connection carrying a pipe's records) are off by default: the streams
//!   of an HTTP/2 connection share one ordered TCP byte stream, so lanes
//!   recover nothing from a loss;
//!   [`Options::lanes`] turns them on. Only the client opens lanes (a
//!   server cannot open requests).
//! - The server: [`serve`] accepts TCP connections and serves both
//!   protocols (HTTP/2 with prior knowledge, as a reverse proxy that speaks
//!   HTTP/2 to its origin without TLS does), handing every carrier on
//!   [`Options::path`] to a [`Listener`](zmux::Listener); [`serve_with`] sets each
//!   connection up first (TLS), [`serve_connection`] serves one
//!   established connection, and [`handle_request`] hands over one request
//!   inside an existing HTTP server, giving back the requests that carry
//!   no pipe ([`Unhandled`]).
//! - Behind a reverse proxy or CDN, a carrier's source is the client that
//!   an intermediary the listener trusts reports
//!   ([`zmux::ListenerConfig::trusted_proxies`]): in a PROXY protocol
//!   header ([`serve`]) or a forwarding header field
//!   ([`request_source`]).
//!
//! TLS is the caller's: the `*_over`/[`Http2Connection::handshake`] entry
//! points and [`serve_with`] speak HTTP over any established connection.
//! The adapter sees only a byte stream, so its carriers have no exporter
//! and are not declared secure ([`zmux::PipeIo::with_carrier_secure`]),
//! even over TLS: no Bound join and no session exporter. A carrier whose
//! TLS the adapter itself establishes and can read the exporter of (the
//! WebSocket adapter's `wss://`, HTTP/3, WebTransport) declares both.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use zmux::{Config, Listener, ListenerConfig};
//! use zmux_http::Options;
//!
//! // Server.
//! let listener = Listener::new(Config::default(), ListenerConfig::default()).expect("valid listener configuration");
//! let tcp = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
//! tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));
//!
//! // Client: one session over an HTTP/2 connection.
//! let session = zmux_http::connect_http2("127.0.0.1:8080", &Options::default(), Config::default()).await?;
//! let server_side = listener.accept().await;
//! # drop((session, server_side));
//! # Ok(())
//! # }
//! ```

mod body;
mod classify;
mod client;
mod endpoint;
mod exchange;
mod server;

use std::sync::Arc;
use std::time::Duration;

use zmux::Credential;

pub use body::{PipeBody, ReplayBody};
pub use classify::{RequestClass, classify, classify_head, forwarded_early_data};
pub use client::{
    Http2Connection, connect_http1, connect_http1_split, connect_http2, dial_http1,
    dial_http1_carrier_over, dial_http1_over, dial_http1_split, dial_http1_split_with,
    exchange_candidate, http1_dial, join_http1_split_with, split_candidate, streaming_candidate,
};
pub use endpoint::Endpoint;
pub use exchange::{
    Backoff, BodyEncoding, ExchangeEndpoint, ExchangeOptions, ExchangeServer, connect_exchange,
    default_piece_size, dial_exchange, dial_exchange_split, dial_exchange_with,
};
pub use server::{
    FallbackRequest, HttpFallback, Unhandled, handle_request, request_source, route_request, serve,
    serve_connection, serve_connection_with, serve_proxied, serve_proxied_with, serve_with,
    too_early,
};

/// The adapter's options.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// The request target of the carriers (default `/zmux`): a client's
    /// requests go to it, and a server takes carriers only on it.
    pub path: String,
    /// HTTP/2 client: open lanes on further requests of the connection
    /// (default off; see the crate documentation).
    pub lanes: bool,
    /// Client: the limit on establishing a carrier, from the connection's
    /// HTTP handshake to the response head (default 10 s); a carrier not
    /// answered within it fails with `TimedOut`.
    pub timeout: Duration,
    /// Server: the exchange carrier's server, which answers the exchange
    /// requests whose path starts with the fixed part of its
    /// [`ExchangeOptions::path`] (none by default). Its carriers go to the
    /// listener it was made with.
    pub exchange: Option<ExchangeServer>,
    /// Server: the HTTP handler of the requests that carry no pipe: those
    /// to other paths, those the listener's admission hands to the
    /// fallback, and those
    /// the listener does not take (none by default: such requests are
    /// answered with 404).
    pub fallback: Option<HttpFallback>,
    /// Client: the credential presented for a server's admission
    /// ([`zmux::ListenerConfig::admission`], none by default): its prefix
    /// ([`Credential::prefix`]) is written first on each request body that
    /// carries a pipe or a lane, and a downlink `GET`, which has no body,
    /// carries its header form ([`Credential::header`]). The adapter does
    /// not see the TLS layer of its connections (they are the caller's
    /// byte streams): the credential is given no exporter, so a bound one
    /// fails each request.
    pub credential: Option<Arc<dyn Credential>>,
    /// Client: the connections carry TLS, so the carriers' URL is
    /// `https://` (default `false`, `http://`): the scheme redirects are
    /// checked against and HTTP/2 requests name.
    pub https: bool,
    /// Client: the redirects a carrier request follows (default
    /// [`zmux::redirect::DEFAULT_MAX_REDIRECTS`]; 0 follows none). One is
    /// followed only within the origin, since the connection's endpoint is
    /// the caller's: the same scheme, host and port, as
    /// [`zmux::redirect::check`] allows (a `POST` only for 307 and 308). The
    /// request is repeated on a new connection that the carrier's `connect`
    /// makes (an HTTP/2 connection's further request), with the credential
    /// presented anew and every uplink byte written before the response,
    /// up to 64 KiB; past that a later redirect is refused. A carrier over
    /// one connection the caller gave (`*_over`) follows none. A refused
    /// redirect fails the carrier with a [`zmux::redirect::RedirectError`].
    pub max_redirects: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            path: "/zmux".into(),
            lanes: false,
            timeout: Duration::from_secs(10),
            exchange: None,
            fallback: None,
            credential: None,
            https: false,
            max_redirects: zmux::redirect::DEFAULT_MAX_REDIRECTS,
        }
    }
}

impl Options {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// With this request target.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// With HTTP/2 lanes on or off.
    #[must_use]
    pub fn with_lanes(mut self, on: bool) -> Self {
        self.lanes = on;
        self
    }

    /// With this limit on establishing a carrier.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Serves the exchange carrier's requests with `server`.
    #[must_use]
    pub fn with_exchange(mut self, server: ExchangeServer) -> Self {
        self.exchange = Some(server);
        self
    }

    /// Serves the requests that carry no pipe with `fallback`.
    #[must_use]
    pub fn with_fallback(mut self, fallback: HttpFallback) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// With the carriers' URL `https://` ([`Options::https`]).
    #[must_use]
    pub fn with_https(mut self, on: bool) -> Self {
        self.https = on;
        self
    }

    /// With this bound on the redirects followed ([`Options::max_redirects`]).
    #[must_use]
    pub fn with_max_redirects(mut self, redirects: usize) -> Self {
        self.max_redirects = redirects;
        self
    }

    /// Presents `credential` on each carrier.
    #[must_use]
    pub fn with_credential(mut self, credential: Arc<dyn Credential>) -> Self {
        self.credential = Some(credential);
        self
    }
}
