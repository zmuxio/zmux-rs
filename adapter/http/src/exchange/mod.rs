//! The exchange carrier: one bidirectional byte-stream carrier made of a
//! sequence of bounded HTTP POST exchanges, for paths where a long-lived
//! exchange does not work (intermediaries that buffer whole bodies, HTTP/1.0
//! hops, request duration limits, caches, lost or repeated requests).
//!
//! The client numbers the bytes it sends in pieces, one per UP request, and
//! keeps DOWN requests outstanding that the server answers with numbered
//! pieces of its bytes; requests are repeated until they have a result, a
//! MAC binds every response to the request it answers, and both ends put
//! the pieces back in order. zmux runs on top as on any byte-stream
//! carrier.
//!
//! The client is [`dial_exchange`] (or [`dial_exchange_with`] over
//! connections of the caller's, such as TLS): it returns the carrier at
//! once, without a round trip. The server is an [`ExchangeServer`], served
//! by [`serve`](crate::serve) and the other serve functions through
//! [`Options::with_exchange`](crate::Options::with_exchange), or called by
//! an HTTP server of the application's own ([`ExchangeServer::handle`]).
//!
//! The carrier authenticates its requests and responses with an optional
//! pre-shared key but does not encrypt them: an intermediary that
//! terminates TLS reads the carrier.

mod client;
mod record;
mod server;
mod wire;

use std::io;

use std::time::Duration;
use zmux::Cap;
pub use zmux::helpers::Backoff;

pub use client::{
    ExchangeEndpoint, connect_exchange, dial_exchange, dial_exchange_split, dial_exchange_with,
};
pub use server::ExchangeServer;

/// How the binary request and response bodies travel in HTTP bodies; both
/// ends must agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BodyEncoding {
    /// As they are (the default).
    #[default]
    Binary,
    /// Base64 with padding (RFC 4648 Section 4), for paths that only pass
    /// text.
    Base64,
}

/// The default piece size of both directions for `encoding`: the largest
/// that keeps every request and response body, with the request's
/// authentication header and Data MAC, at most 1,000,000 bytes after the encoding (999,918 bytes in
/// binary, 749,918 in base64), below the request body limit of 1 MiB that
/// reverse proxies commonly apply.
pub const fn default_piece_size(encoding: BodyEncoding) -> usize {
    const BODY: usize = 1_000_000;
    match encoding {
        BodyEncoding::Binary => BODY - wire::REQUEST_OVERHEAD,
        BodyEncoding::Base64 => BODY / 4 * 3 - wire::REQUEST_OVERHEAD,
    }
}

/// The default acceptance limit of a piece: 1 MiB, or the piece size if
/// larger.
const MIN_PIECE_LIMIT: usize = 1 << 20;

/// The exchange carrier's options (both ends; each uses its own). The two
/// ends must agree on [`psk`](Self::psk) and [`encoding`](Self::encoding);
/// everything else is local. A carrier is authenticated unless
/// [`unauthenticated`](Self::unauthenticated) says otherwise: without a
/// PSK and without that choice, [`dial_exchange`](dial_exchange)
/// and the other dials, and [`ExchangeServer::new`](ExchangeServer::new),
/// fail.
#[derive(Clone)]
#[non_exhaustive]
pub struct ExchangeOptions {
    /// The pre-shared key that authenticates requests and responses (none
    /// by default, which must be set unless
    /// [`unauthenticated`](Self::unauthenticated) is).
    pub psk: Vec<u8>,
    /// Client: the credential whose prefix ([`zmux::CarrierCredential::prefix`],
    /// given no metadata) the uplink starts with, for a server's admission
    /// ([`zmux::ListenerConfig::admission`]; none by default).
    pub carrier_credential: Option<std::sync::Arc<dyn zmux::CarrierCredential>>,
    /// Runs without a PSK, explicitly (false by default): the MACs then
    /// only bind responses to requests, and the carrier ID is a bearer
    /// secret. On the wire it is the empty PSK. Set with a PSK, it is an
    /// error.
    pub unauthenticated: bool,
    /// The body encoding (default binary).
    pub encoding: BodyEncoding,
    /// Client: the request path. `{instance}` is replaced by a random
    /// token of the carrier (the same in all its requests, for example for
    /// routing) and `{nonce}` by a fresh random value in every request, so
    /// that no cache keyed on the target ever matches; a path without
    /// `{nonce}` gets it in the query parameter [`query`](Self::query)
    /// (default `/zmux/exchange`). Server: requests to a path that starts with its
    /// part before the first placeholder or `?` are exchanges.
    pub path: String,
    /// Client: the path of DOWN requests, a template like
    /// [`path`](Self::path) ([`Cap::Auto`], the default: `path`).
    pub down_path: Cap<String>,
    /// Client: the query parameter that carries the fresh value when the
    /// path has no `{nonce}` (default `n`).
    pub query: String,

    /// Client: DOWN requests kept outstanding (default 2, at least 1).
    pub down_requests: usize,
    /// Client: UP requests outstanding at most (default 2, at least 1).
    pub up_requests: usize,
    /// Client: the largest UP piece ([`Cap::Auto`], the default:
    /// [`default_piece_size`] of the encoding;
    /// [`up_piece_size`](Self::up_piece_size)).
    pub up_piece: Cap<usize>,
    /// Client: the largest DOWN piece accepted ([`Cap::Auto`], the default:
    /// the larger of 1 MiB and the DOWN piece size); a larger response fails
    /// the carrier. At least the server's [`down_piece`](Self::down_piece).
    pub max_down_piece: Cap<usize>,
    /// Client: the delays between repetitions of a request that had no
    /// result (default from 20 ms to at most 2 s, each between half and
    /// all of its value).
    pub backoff: Backoff,
    /// Client: one attempt of a request, from connecting to its whole
    /// response, has no result after this (default 25 s). It must exceed
    /// the server's hold time and the path's round trip.
    pub request_timeout: Duration,
    /// Client: a request that has had no result for this long fails the
    /// carrier (default 30 s).
    pub deadline: Duration,
    /// Client: the connections carry TLS, so the requests' URL is
    /// `https://` (default `false`, `http://`): the scheme redirects are
    /// checked against.
    pub https: bool,
    /// Client: the redirects one request follows (default
    /// [`zmux::redirect::DEFAULT_MAX_REDIRECTS`]; 0 follows none), each
    /// only within the origin of its endpoint, since the connections are
    /// the caller's: another path or query of the same scheme, host and
    /// port, as [`zmux::redirect::check`] allows (a `POST`, so 307 and 308
    /// only). The request is repeated with its body unchanged, on a
    /// connection of the endpoint; the next request starts at its
    /// configured path again. A refused redirect fails the carrier.
    pub max_redirects: usize,

    /// Server: a held DOWN request is answered within this (default 20 s);
    /// below every intermediary's response timeout on the path.
    pub hold: Duration,
    /// Server: a DOWN piece is closed this long after its first byte
    /// (default 2 ms).
    pub coalesce: Duration,
    /// Server: the largest DOWN piece ([`Cap::Auto`], the default:
    /// [`default_piece_size`] of the encoding); also the bytes zmux may
    /// write ahead of the pieces.
    pub down_piece: Cap<usize>,
    /// Server: DOWN pieces assigned beyond the client's acknowledgement at
    /// most (default 32).
    pub down_window: u64,
    /// Server: the largest UP piece accepted ([`Cap::Auto`], the default:
    /// the larger of 1 MiB and the UP piece size); a request with a larger
    /// one is not authenticated. At least the client's
    /// [`up_piece`](Self::up_piece).
    pub max_up_piece: Cap<usize>,
    /// Server: uplink bytes held for zmux, and out of order, each at most
    /// (default 4 MiB); a piece beyond it is answered BUSY. Each piece held
    /// out of order also counts a fixed 64 bytes, which bounds how many are
    /// held.
    pub up_store: usize,
    /// Server: a carrier without a request for this long has failed
    /// (default 60 s); above the hold time.
    pub idle_timeout: Duration,
    /// Server: a carrier that ended is remembered this long, to answer
    /// GONE to late requests (default 60 s).
    pub gone_memory: Duration,
    /// Server: carriers at once at most, and carriers remembered as
    /// ended (none by default: the listener's memory budget bounds what
    /// carriers hold); a request that would create one beyond it is
    /// answered BUSY.
    pub max_carriers: Option<usize>,
    /// Server: the time window W (default 60 s, whole seconds): a request
    /// whose Time differs from the server's clock by more than this, the
    /// difference taken modulo 2^32 as a signed 32-bit value, is not
    /// authenticated. A window of 2^31 s or more takes every Time.
    pub time_window: Duration,
    /// Server: the (Carrier ID, Nonce) pairs recorded at most (default
    /// 262144). A pair stays recorded while its request's Time is within
    /// the window, and up to one window longer; a request that finds the
    /// record full is not authenticated.
    pub max_recorded: usize,
}

impl std::fmt::Debug for ExchangeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeOptions")
            .field("psk", &if self.psk.is_empty() { "none" } else { "set" })
            .field("carrier_credential", &self.carrier_credential.is_some())
            .field("unauthenticated", &self.unauthenticated)
            .field("encoding", &self.encoding)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("https", &self.https)
            .field("max_redirects", &self.max_redirects)
            .finish_non_exhaustive()
    }
}

impl Default for ExchangeOptions {
    fn default() -> Self {
        Self {
            psk: Vec::new(),
            carrier_credential: None,
            unauthenticated: false,
            encoding: BodyEncoding::Binary,
            path: "/zmux/exchange".into(),
            down_path: Cap::Auto,
            query: "n".into(),
            down_requests: 2,
            up_requests: 2,
            up_piece: Cap::Auto,
            max_down_piece: Cap::Auto,
            backoff: Backoff::new(Duration::from_millis(20), Duration::from_secs(2))
                .with_jitter(0.5),
            request_timeout: Duration::from_secs(25),
            deadline: Duration::from_secs(30),
            https: false,
            max_redirects: zmux::redirect::DEFAULT_MAX_REDIRECTS,
            hold: Duration::from_secs(20),
            coalesce: Duration::from_millis(2),
            down_piece: Cap::Auto,
            down_window: 32,
            max_up_piece: Cap::Auto,
            up_store: 4 << 20,
            idle_timeout: Duration::from_secs(60),
            gone_memory: Duration::from_secs(60),
            max_carriers: None,
            time_window: Duration::from_secs(60),
            max_recorded: 1 << 18,
        }
    }
}

impl ExchangeOptions {
    /// Client: starts the uplink with the prefix of `credential`.
    #[must_use]
    pub fn with_carrier_credential(
        mut self,
        credential: std::sync::Arc<dyn zmux::CarrierCredential>,
    ) -> Self {
        self.carrier_credential = Some(credential);
        self
    }

    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The UP piece size in use.
    pub fn up_piece_size(&self) -> usize {
        match self.up_piece {
            Cap::Auto => default_piece_size(self.encoding),
            Cap::Fixed(n) => n,
        }
        .clamp(1, wire::MAX_DATA)
    }

    /// The DOWN piece size in use.
    pub fn down_piece_size(&self) -> usize {
        match self.down_piece {
            Cap::Auto => default_piece_size(self.encoding),
            Cap::Fixed(n) => n,
        }
        .max(1)
    }

    /// The largest UP piece a server accepts.
    pub fn max_up_piece_size(&self) -> usize {
        match self.max_up_piece {
            Cap::Auto => MIN_PIECE_LIMIT.max(self.up_piece_size()),
            Cap::Fixed(n) => n,
        }
        .min(wire::MAX_DATA)
    }

    /// The largest DOWN piece a client accepts.
    pub fn max_down_piece_size(&self) -> usize {
        match self.max_down_piece {
            Cap::Auto => MIN_PIECE_LIMIT.max(self.down_piece_size()),
            Cap::Fixed(n) => n,
        }
    }

    /// With this pre-shared key.
    #[must_use]
    pub fn with_psk(mut self, psk: impl Into<Vec<u8>>) -> Self {
        self.psk = psk.into();
        self
    }

    /// Without authentication ([`unauthenticated`](Self::unauthenticated)).
    #[must_use]
    pub fn with_unauthenticated(mut self) -> Self {
        self.unauthenticated = true;
        self
    }

    /// The PSK the MACs are keyed with (empty when unauthenticated), or an
    /// error ([`io::ErrorKind::InvalidInput`]) when the options neither set
    /// one nor explicitly run without one, or do both.
    pub(crate) fn mac_psk(&self) -> io::Result<&[u8]> {
        match (self.psk.is_empty(), self.unauthenticated) {
            (false, false) | (true, true) => Ok(&self.psk),
            (true, false) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exchange carrier without a PSK: set one, or choose unauthenticated",
            )),
            (false, true) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exchange carrier both with a PSK and unauthenticated",
            )),
        }
    }

    /// With this time window ([`time_window`](Self::time_window)).
    #[must_use]
    pub fn with_time_window(mut self, window: Duration) -> Self {
        self.time_window = window;
        self
    }

    /// With this bound on recorded pairs
    /// ([`max_recorded`](Self::max_recorded)).
    #[must_use]
    pub fn with_max_recorded(mut self, max: usize) -> Self {
        self.max_recorded = max;
        self
    }

    /// With this body encoding.
    #[must_use]
    pub fn with_encoding(mut self, encoding: BodyEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// With the requests' URL `https://` ([`https`](Self::https)).
    #[must_use]
    pub fn with_https(mut self, on: bool) -> Self {
        self.https = on;
        self
    }

    /// With this bound on the redirects one request follows
    /// ([`max_redirects`](Self::max_redirects)).
    #[must_use]
    pub fn with_max_redirects(mut self, redirects: usize) -> Self {
        self.max_redirects = redirects;
        self
    }

    /// With this request path template.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// With this path template for DOWN requests.
    #[must_use]
    pub fn with_down_path(mut self, path: impl Into<String>) -> Self {
        self.down_path = Cap::Fixed(path.into());
        self
    }

    /// With this cache-busting query parameter name.
    #[must_use]
    pub fn with_query(mut self, name: impl Into<String>) -> Self {
        self.query = name.into();
        self
    }

    /// The path template of DOWN requests.
    fn down_path(&self) -> &str {
        match &self.down_path {
            Cap::Auto => &self.path,
            Cap::Fixed(p) => p,
        }
    }

    /// The fixed starts of the path templates (UP and DOWN), before the
    /// first placeholder or `?`.
    pub(crate) fn path_prefixes<'a>(&'a self) -> [&'a str; 2] {
        let fixed = |p: &'a str| &p[..p.find(['{', '?']).unwrap_or(p.len())];
        [fixed(&self.path), fixed(self.down_path())]
    }

    /// The request target of one request: the path with `instance` and
    /// `nonce` in its placeholders, or `nonce` in the query parameter.
    pub(crate) fn target(&self, down: bool, instance: &str, nonce: &str) -> String {
        let path = if down { self.down_path() } else { &self.path };
        let mut t = path.replace("{instance}", instance);
        if t.contains("{nonce}") {
            t = t.replace("{nonce}", nonce);
        } else {
            t.push(if t.contains('?') { '&' } else { '?' });
            t.push_str(&self.query);
            t.push('=');
            t.push_str(nonce);
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let o = ExchangeOptions::default();
        assert_eq!(o.target(false, "i", "ab"), "/zmux/exchange?n=ab");
        assert_eq!(o.path_prefixes(), ["/zmux/exchange"; 2]);
        let o = ExchangeOptions::default().with_path("/x/{instance}/{nonce}");
        assert_eq!(o.target(false, "i1", "ab"), "/x/i1/ab");
        assert_eq!(o.path_prefixes()[0], "/x/");
        let o = ExchangeOptions::default()
            .with_path("/x?a=1")
            .with_query("r");
        assert_eq!(o.target(false, "i", "ab"), "/x?a=1&r=ab");
        assert_eq!(o.path_prefixes()[0], "/x");
        let o = o.with_down_path("/d/{nonce}");
        assert_eq!(o.target(true, "i", "ab"), "/d/ab");
        assert_eq!(o.target(false, "i", "ab"), "/x?a=1&r=ab");
        assert_eq!(o.path_prefixes(), ["/x", "/d/"]);
    }

    #[test]
    fn default_bodies_fit_common_proxy_limits() {
        for e in [BodyEncoding::Binary, BodyEncoding::Base64] {
            let piece = default_piece_size(e);
            let request = wire::encoded_len(e, wire::REQUEST_OVERHEAD + piece);
            let response = wire::encoded_len(e, wire::RESPONSE_HEAD + piece);
            assert!(request <= 1_000_000 && response <= 1_000_000, "{e:?}");
            // The largest such piece.
            assert!(wire::encoded_len(e, wire::REQUEST_OVERHEAD + piece + 1) > 1_000_000);
        }
        assert_eq!(default_piece_size(BodyEncoding::Binary), 999_918);
        assert_eq!(default_piece_size(BodyEncoding::Base64), 749_918);
    }

    #[test]
    fn backoff_doubles_with_jitter() {
        let b = ExchangeOptions::default().backoff;
        for (attempt, base) in [(1, 20), (2, 40), (3, 80), (10, 2000), (40, 2000)] {
            let base = Duration::from_millis(base);
            for _ in 0..20 {
                let d = b.delay(attempt);
                assert!(d >= base / 2 && d <= base, "{attempt} {d:?}");
            }
        }
    }
}
