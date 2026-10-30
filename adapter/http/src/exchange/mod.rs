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
mod server;
mod wire;

use std::time::Duration;

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

/// The delays between repetitions of a request that had no result:
/// doubling from `initial` up to `max`, each drawn at random between half
/// and all of its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The first delay (default 20 ms).
    pub initial: Duration,
    /// The longest delay (default 2 s).
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(20),
            max: Duration::from_secs(2),
        }
    }
}

impl Backoff {
    /// The delay before repetition `attempt` (1 for the first), with
    /// `random` the jitter source.
    pub(crate) fn delay(&self, attempt: u32, random: u64) -> Duration {
        let base = self
            .initial
            .saturating_mul(1u32 << attempt.saturating_sub(1).min(20))
            .min(self.max);
        // Between half and all of it.
        let half = base / 2;
        let nanos = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
        half + Duration::from_nanos(if nanos == 0 { 0 } else { random % nanos })
    }
}

/// The exchange carrier's options (both ends; each uses its own). The two
/// ends must agree on [`psk`](Self::psk) and [`encoding`](Self::encoding);
/// everything else is local.
#[derive(Clone)]
#[non_exhaustive]
pub struct ExchangeOptions {
    /// The pre-shared key that authenticates requests and responses (empty
    /// by default: the MACs then only bind responses to requests).
    pub psk: Vec<u8>,
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
    /// [`path`](Self::path) (default: `path`).
    pub down_path: Option<String>,
    /// Client: the query parameter that carries the fresh value when the
    /// path has no `{nonce}` (default `n`).
    pub query: String,

    /// Client: DOWN requests kept outstanding (default 2, at least 1).
    pub down_requests: usize,
    /// Client: UP requests outstanding at most (default 2, at least 1).
    pub up_requests: usize,
    /// Client: the largest UP piece (default 1 MiB).
    pub up_piece: usize,
    /// Client: the largest DOWN piece accepted (default 1 MiB); a larger
    /// response fails the carrier. At least the server's
    /// [`down_piece`](Self::down_piece).
    pub max_down_piece: usize,
    /// Client: the delays between repetitions.
    pub backoff: Backoff,
    /// Client: one attempt of a request, from connecting to its whole
    /// response, has no result after this (default 25 s). It must exceed
    /// the server's hold time and the path's round trip.
    pub request_timeout: Duration,
    /// Client: a request that has had no result for this long fails the
    /// carrier (default 30 s).
    pub deadline: Duration,

    /// Server: a held DOWN request is answered within this (default 20 s);
    /// below every intermediary's response timeout on the path.
    pub hold: Duration,
    /// Server: a DOWN piece is closed this long after its first byte
    /// (default 2 ms).
    pub coalesce: Duration,
    /// Server: the largest DOWN piece (default 1 MiB); also the bytes zmux
    /// may write ahead of the pieces.
    pub down_piece: usize,
    /// Server: DOWN pieces assigned beyond the client's acknowledgement at
    /// most (default 32).
    pub down_window: u64,
    /// Server: the largest UP piece accepted (default 1 MiB); a larger one
    /// is answered GONE. At least the client's [`up_piece`](Self::up_piece).
    pub max_up_piece: usize,
    /// Server: uplink bytes held for zmux, and out of order, each at most
    /// (default 4 MiB); a piece beyond it is answered BUSY.
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
}

impl std::fmt::Debug for ExchangeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeOptions")
            .field("psk", &if self.psk.is_empty() { "none" } else { "set" })
            .field("encoding", &self.encoding)
            .field("path", &self.path)
            .field("query", &self.query)
            .finish_non_exhaustive()
    }
}

impl Default for ExchangeOptions {
    fn default() -> Self {
        Self {
            psk: Vec::new(),
            encoding: BodyEncoding::Binary,
            path: "/zmux/exchange".into(),
            down_path: None,
            query: "n".into(),
            down_requests: 2,
            up_requests: 2,
            up_piece: 1 << 20,
            max_down_piece: 1 << 20,
            backoff: Backoff::default(),
            request_timeout: Duration::from_secs(25),
            deadline: Duration::from_secs(30),
            hold: Duration::from_secs(20),
            coalesce: Duration::from_millis(2),
            down_piece: 1 << 20,
            down_window: 32,
            max_up_piece: 1 << 20,
            up_store: 4 << 20,
            idle_timeout: Duration::from_secs(60),
            gone_memory: Duration::from_secs(60),
            max_carriers: None,
        }
    }
}

impl ExchangeOptions {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// With this pre-shared key.
    #[must_use]
    pub fn with_psk(mut self, psk: impl Into<Vec<u8>>) -> Self {
        self.psk = psk.into();
        self
    }

    /// With this body encoding.
    #[must_use]
    pub fn with_encoding(mut self, encoding: BodyEncoding) -> Self {
        self.encoding = encoding;
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
        self.down_path = Some(path.into());
        self
    }

    /// With this cache-busting query parameter name.
    #[must_use]
    pub fn with_query(mut self, name: impl Into<String>) -> Self {
        self.query = name.into();
        self
    }

    /// The fixed starts of the path templates (UP and DOWN), before the
    /// first placeholder or `?`.
    pub(crate) fn path_prefixes<'a>(&'a self) -> [&'a str; 2] {
        let fixed = |p: &'a str| &p[..p.find(['{', '?']).unwrap_or(p.len())];
        [
            fixed(&self.path),
            fixed(self.down_path.as_deref().unwrap_or(&self.path)),
        ]
    }

    /// The request target of one request: the path with `instance` and
    /// `nonce` in its placeholders, or `nonce` in the query parameter.
    pub(crate) fn target(&self, down: bool, instance: &str, nonce: &str) -> String {
        let path = match &self.down_path {
            Some(p) if down => p,
            _ => &self.path,
        };
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
    fn backoff_doubles_with_jitter() {
        let b = Backoff::default();
        for (attempt, base) in [(1, 20), (2, 40), (3, 80), (10, 2000), (40, 2000)] {
            let base = Duration::from_millis(base);
            for r in [0, 1, u64::MAX / 3, u64::MAX] {
                let d = b.delay(attempt, r);
                assert!(d >= base / 2 && d <= base, "{attempt} {d:?}");
            }
        }
    }
}
