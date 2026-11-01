//! Carrier admission: the configuration a listener applies to every new
//! carrier ([`Admission`], [`crate::ListenerConfig::admission`]), the
//! metadata of a carrier ([`CarrierInfo`]), the decision taken on it
//! ([`Decide`], [`Verdict`]), and what a client presents to it
//! ([`Credential`]).

use std::any::Any;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::prefix_auth::{PREFIX_TOKEN_LEN, PrefixAuthVerifier};

/// The future of a decision ([`Decide::decide`]).
pub type DecideFuture<'a> = Pin<Box<dyn Future<Output = Verdict> + Send + 'a>>;

/// The decision on a carrier from its metadata and its prefix: called
/// once per carrier, outside the listener's locks, concurrently for
/// different carriers. The decision may take time (a lookup): it is bound
/// by what remains of the peek timeout, and is cancelled (its future
/// dropped) when that ends or when the listener stops taking carriers; the
/// carrier is then closed. `prefix` is valid only during the call.
///
/// A synchronous function `Fn(&CarrierInfo, &[u8]) -> Verdict` is a
/// `Decide`; implement the trait for one that waits.
pub trait Decide: Send + Sync + 'static {
    /// The decision on the carrier `info` describes, whose first bytes are
    /// `prefix`.
    fn decide<'a>(&'a self, info: &'a CarrierInfo<'a>, prefix: &'a [u8]) -> DecideFuture<'a>;
}

impl<F> Decide for F
where
    F: Fn(&CarrierInfo<'_>, &[u8]) -> Verdict + Send + Sync + 'static,
{
    fn decide<'a>(&'a self, info: &'a CarrierInfo<'a>, prefix: &'a [u8]) -> DecideFuture<'a> {
        Box::pin(std::future::ready(self(info, prefix)))
    }
}

/// The bounds a peek timeout that is not configured is drawn from.
pub const PEEK_TIMEOUT_DRAWN: (Duration, Duration) =
    (Duration::from_secs(5), Duration::from_secs(30));
/// The bounds the upper end of a stall interval that is not configured is
/// drawn from; its lower end is drawn from a quarter to three quarters of
/// it.
pub const STALL_MAX_DRAWN: (Duration, Duration) =
    (Duration::from_secs(30), Duration::from_secs(120));

/// The admission of a listener's new carriers
/// ([`crate::ListenerConfig::admission`]): how many bytes are read before
/// the decision ([`Admission::peek`]), how long reading them and deciding
/// may take from the end of the carrier's outer handshake
/// ([`Admission::peek_timeout`]), the interval stall durations are in
/// ([`Admission::stall_interval`]), and the decision itself ([`Decide`]).
/// Every entry of the listener applies it, in the same order: the
/// carrier's source slot, its outer handshake (TLS, an HTTP upgrade,
/// QUIC), the admission, then its first record. Nothing is written on a
/// carrier before it is accepted. Cheap to clone; the clones share the
/// drawn values.
#[derive(Clone)]
pub struct Admission {
    peek: usize,
    peek_timeout: Duration,
    stall: (Duration, Duration),
    discard_buffer: usize,
    decide: Arc<dyn Decide>,
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission")
            .field("peek", &self.peek)
            .field("peek_timeout", &self.peek_timeout)
            .field("stall", &self.stall)
            .field("discard_buffer", &self.discard_buffer)
            .finish_non_exhaustive()
    }
}

impl Admission {
    /// An admission that reads up to `peek` bytes (0: none) and then calls
    /// `decide` with the carrier's metadata and the bytes read (fewer when
    /// the carrier ends or the peek timeout passes first): a synchronous
    /// decision ([`Admission::with_decider`] takes one that waits).
    pub fn new(
        peek: usize,
        decide: impl Fn(&CarrierInfo<'_>, &[u8]) -> Verdict + Send + Sync + 'static,
    ) -> Self {
        Self::with_decider(peek, decide)
    }

    /// An admission that reads up to `peek` bytes (0: none) and then asks
    /// `decide` with the carrier's metadata and the bytes read (fewer when
    /// the carrier ends or the peek timeout passes first).
    ///
    /// The peek timeout is drawn here, once, uniformly from
    /// [`PEEK_TIMEOUT_DRAWN`], and the stall interval's upper end from
    /// [`STALL_MAX_DRAWN`] and its lower end from a quarter to three
    /// quarters of it, from the system's secure random source;
    /// [`Admission::with_peek_timeout`] and
    /// [`Admission::with_stall_interval`] set them instead.
    pub fn with_decider(peek: usize, decide: impl Decide) -> Self {
        let peek_timeout = draw(PEEK_TIMEOUT_DRAWN.0, PEEK_TIMEOUT_DRAWN.1);
        let max = draw(STALL_MAX_DRAWN.0, STALL_MAX_DRAWN.1);
        let min = draw(max / 4, max * 3 / 4);
        Self {
            peek,
            peek_timeout,
            stall: (min, max),
            discard_buffer: 512,
            decide: Arc::new(decide),
        }
    }

    /// An admission by prefix authentication tokens:
    /// [`PREFIX_TOKEN_LEN`] bytes read (none on a carrier decided on its
    /// HTTP request head, whose token is in a request header field),
    /// decided by [`PrefixAuthVerifier::decide`].
    pub fn prefix_auth(verifier: Arc<PrefixAuthVerifier>) -> Self {
        Self::new(PREFIX_TOKEN_LEN, move |info, prefix| {
            verifier.decide(info, prefix)
        })
    }

    /// With this peek timeout: the limit on reading the prefix and
    /// deciding, from the end of the carrier's outer handshake.
    #[must_use]
    pub fn with_peek_timeout(mut self, timeout: Duration) -> Self {
        self.peek_timeout = timeout;
        self
    }

    /// With this stall interval: a stall lasts a duration in `[min, max]`
    /// (`max` when `min` is above it) that the listener derives from the
    /// carrier's source.
    #[must_use]
    pub fn with_stall_interval(mut self, min: Duration, max: Duration) -> Self {
        self.stall = (min.min(max), max);
        self
    }

    /// With this read size for the bytes a stall discards (default 512,
    /// at least 1).
    #[must_use]
    pub fn with_discard_buffer(mut self, bytes: usize) -> Self {
        self.discard_buffer = bytes.max(1);
        self
    }

    /// The number of bytes read before the decision.
    pub fn peek(&self) -> usize {
        self.peek
    }

    /// The peek timeout.
    pub fn peek_timeout(&self) -> Duration {
        self.peek_timeout
    }

    /// The stall interval, `(min, max)`.
    pub fn stall_interval(&self) -> (Duration, Duration) {
        self.stall
    }

    /// The read size of a stall's discarding.
    pub(crate) fn discard_buffer(&self) -> usize {
        self.discard_buffer
    }

    /// The decider.
    pub(crate) fn decider(&self) -> &dyn Decide {
        &*self.decide
    }
}

/// Uniform in `[lo, hi]` from the system's secure random source.
fn draw(lo: Duration, hi: Duration) -> Duration {
    if hi <= lo {
        return hi;
    }
    let span = (hi - lo).as_nanos() + 1;
    let r = u128::from(crate::util::random_u64()) % span;
    lo + Duration::from_nanos(u64::try_from(r).unwrap_or(u64::MAX))
}

/// A host's value attached to a carrier by the admission that accepted
/// it ([`Verdict::Accept`]): opaque to zmux, which neither inspects,
/// compares nor drops it early. The transform of a listener sees it
/// ([`crate::PipeHint::admitted`]), the session it bootstraps keeps it
/// (`Session::admitted`, the uplink's for a split bootstrap) and each pipe
/// the value of the carrier that joined it (`Pipe::admitted`); a further
/// stream of an admitted QUIC connection carries the connection's. A join
/// is never refused for a value that differs from its session's: a host
/// that wants that checks in its transform, or closes the pipe.
pub type AdmittedValue = Arc<dyn Any + Send + Sync>;

/// The decision on a carrier under admission.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// The first `skip` bytes of the prefix are removed; the rest of the
    /// prefix, then the rest of the carrier, go to the listener. A `skip`
    /// beyond the prefix is [`Verdict::Close`]. `value` is the host's
    /// value for the carrier ([`AdmittedValue`]).
    Accept {
        /// Prefix bytes removed.
        skip: usize,
        /// The host's value for the carrier.
        value: Option<AdmittedValue>,
    },
    /// The carrier, every prefix byte read replayed in front of the rest,
    /// goes to the adapter's fallback target; without one, a stream
    /// carrier is stalled and an HTTP request receives the not-found
    /// response of its server.
    Fallback,
    /// Nothing is sent; what arrives is read and discarded, and the carrier
    /// is closed gracefully (a byte stream's write side first) when the
    /// peer ends it or when a duration drawn from the configured stall
    /// interval has passed. An HTTP request is ended then without a
    /// response.
    Stall,
    /// The carrier is closed at once.
    Close,
}

/// Values compare by identity.
impl PartialEq for Verdict {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Accept { skip: a, value: x }, Self::Accept { skip: b, value: y }) => {
                a == b
                    && match (x, y) {
                        (None, None) => true,
                        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
                        _ => false,
                    }
            }
            (Self::Fallback, Self::Fallback)
            | (Self::Stall, Self::Stall)
            | (Self::Close, Self::Close) => true,
            _ => false,
        }
    }
}

impl Eq for Verdict {}

impl Verdict {
    /// [`Verdict::Accept`] removing `skip` prefix bytes, without a value.
    pub const fn accept(skip: usize) -> Self {
        Self::Accept { skip, value: None }
    }

    /// With the host's value for an accepted carrier; other verdicts carry
    /// none and are returned as they are.
    #[must_use]
    pub fn with_value(self, value: AdmittedValue) -> Self {
        match self {
            Self::Accept { skip, .. } => Self::Accept {
                skip,
                value: Some(value),
            },
            v => v,
        }
    }

    /// The verdict with `Accept` bounded by a prefix of `len` bytes: a
    /// `skip` beyond it is [`Verdict::Close`].
    #[must_use]
    pub fn bounded(self, len: usize) -> Self {
        match self {
            Self::Accept { skip, .. } if skip > len => Self::Close,
            v => v,
        }
    }
}

/// A TLS exporter (RFC 8446 Section 7.5): fills `out` with the value for
/// `label` and `context`, or returns `false`.
type ExportFn<'a> = dyn Fn(&[u8], &[u8], &mut [u8]) -> bool + Send + Sync + 'a;

/// The request header fields of an HTTP carrier: calls `each(name, value)`
/// for every field, in order.
type HeadersFn<'a> = dyn Fn(&mut dyn FnMut(&str, &[u8])) + Send + Sync + 'a;

/// The metadata of a carrier, read-only, as far as its adapter has it: a
/// server's admission decides with it, and a
/// client's [`Credential`] is given it. Fields that do not apply are
/// `None`.
#[derive(Default)]
#[non_exhaustive]
pub struct CarrierInfo<'a> {
    /// The carrier's source: the client a trusted intermediary reports
    /// ([`crate::TrustedProxies::source`], a reported port of 0 when it
    /// reported none), the source a host gave the listener
    /// ([`crate::PipeHint::source`]), or otherwise the peer. The one
    /// source of the carrier: its per-source limits and stall duration go
    /// by it too.
    pub source: Option<SocketAddr>,
    /// The directly connected peer: the TCP or QUIC peer, or the remote
    /// address of an HTTP request's connection.
    pub peer: Option<SocketAddr>,
    /// The application protocol the TLS or QUIC handshake negotiated.
    pub alpn: Option<&'a [u8]>,
    /// The server name the client sent in its TLS or QUIC handshake.
    pub server_name: Option<&'a str>,
    /// The request head of an HTTP carrier, as the adapter's own type (the
    /// HTTP adapters give `http::request::Parts`): downcast it. Its
    /// header fields are also given independently of the type
    /// ([`CarrierInfo::for_each_header`]).
    pub request: Option<&'a (dyn Any + Send + Sync)>,
    /// Whether the carrier is decided on its HTTP request head, without a
    /// prefix: an HTTP upgrade (WebSocket,
    /// WebTransport), or an HTTP request carrier whose request has no
    /// body. A token travels in a request header field.
    pub head: bool,
    headers: Option<Box<HeadersFn<'a>>>,
    exporter: Option<Box<ExportFn<'a>>>,
}

impl std::fmt::Debug for CarrierInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarrierInfo")
            .field("source", &self.source)
            .field("peer", &self.peer)
            .field("alpn", &self.alpn)
            .field("server_name", &self.server_name)
            .field("request", &self.request.is_some())
            .field("head", &self.head)
            .field("headers", &self.headers.is_some())
            .field("exporter", &self.exporter.is_some())
            .finish()
    }
}

impl<'a> CarrierInfo<'a> {
    /// No metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// With the carrier's source ([`CarrierInfo::source`]).
    #[must_use]
    pub fn with_source(mut self, source: SocketAddr) -> Self {
        self.source = Some(source);
        self
    }

    /// With the directly connected peer ([`CarrierInfo::peer`]).
    #[must_use]
    pub fn with_peer(mut self, peer: SocketAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// With the negotiated application protocol.
    #[must_use]
    pub fn with_alpn(mut self, alpn: Option<&'a [u8]>) -> Self {
        self.alpn = alpn;
        self
    }

    /// With the client's server name.
    #[must_use]
    pub fn with_server_name(mut self, name: Option<&'a str>) -> Self {
        self.server_name = name;
        self
    }

    /// With an HTTP carrier's request head.
    #[must_use]
    pub fn with_request(mut self, request: &'a (dyn Any + Send + Sync)) -> Self {
        self.request = Some(request);
        self
    }

    /// As a carrier decided on its HTTP request head
    /// ([`CarrierInfo::head`]).
    #[must_use]
    pub fn with_head(mut self) -> Self {
        self.head = true;
        self
    }

    /// With an HTTP carrier's request header fields: `fields()` gives
    /// every field as `(name, value)`, in order, the name in lower case.
    #[must_use]
    pub fn with_headers<I>(mut self, fields: impl Fn() -> I + Send + Sync + 'a) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a [u8])>,
    {
        self.headers = Some(Box::new(move |each| {
            for (name, value) in fields() {
                each(name, value);
            }
        }));
        self
    }

    /// Calls `each(name, value)` for every request header field of an HTTP
    /// carrier, in order, the name in lower case; for no field on other
    /// carriers.
    pub fn for_each_header(&self, mut each: impl FnMut(&str, &[u8])) {
        if let Some(headers) = &self.headers {
            headers(&mut each);
        }
    }

    /// With the exporter of the carrier's completed TLS or QUIC handshake:
    /// `export(label, context, out)` fills `out` or returns `false`.
    #[must_use]
    pub fn with_exporter(
        mut self,
        export: impl Fn(&[u8], &[u8], &mut [u8]) -> bool + Send + Sync + 'a,
    ) -> Self {
        self.exporter = Some(Box::new(export));
        self
    }

    /// Whether the carrier has an exporter.
    pub fn has_exporter(&self) -> bool {
        self.exporter.is_some()
    }

    /// `len` bytes of the exporter for `label` and `context`; `None` without
    /// an exporter or when it fails.
    pub fn export(&self, label: &[u8], context: &[u8], len: usize) -> Option<Vec<u8>> {
        let export = self.exporter.as_ref()?;
        let mut out = vec![0u8; len];
        export(label, context, &mut out).then_some(out)
    }
}

/// What a client presents to a server's admission on a new carrier: the
/// counterpart of the server's decision. An adapter asks for it once per
/// carrier, after the carrier's TLS or QUIC handshake completed and before
/// any zmux record, with the metadata it has of the carrier, the exporter
/// of that handshake among them where the adapter holds the TLS layer (for
/// a credential bound to it). An error fails the dial.
/// [`crate::PrefixAuth`] is one.
pub trait Credential: Send + Sync + std::fmt::Debug {
    /// The bytes a byte-stream carrier, an HTTP request body carrier or a
    /// QUIC carrier's first stream starts with.
    fn prefix(&self, info: &CarrierInfo<'_>) -> io::Result<Vec<u8>>;

    /// The request header field, `(name, value)`, of a carrier decided on
    /// its HTTP request head: an HTTP upgrade (WebSocket, WebTransport), or
    /// an HTTP request without a body.
    fn header(&self, info: &CarrierInfo<'_>) -> io::Result<(String, String)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drawn_bounds() {
        for _ in 0..64 {
            let a = Admission::new(0, |_, _| Verdict::Close);
            assert!((PEEK_TIMEOUT_DRAWN.0..=PEEK_TIMEOUT_DRAWN.1).contains(&a.peek_timeout()));
            let (min, max) = a.stall_interval();
            assert!((STALL_MAX_DRAWN.0..=STALL_MAX_DRAWN.1).contains(&max));
            assert!(min >= max / 4 && min <= max * 3 / 4);
        }
        let a = Admission::new(0, |_, _| Verdict::Close)
            .with_stall_interval(Duration::from_secs(3), Duration::from_secs(1));
        assert_eq!(
            a.stall_interval(),
            (Duration::from_secs(1), Duration::from_secs(1))
        );
    }

    #[test]
    fn accept_beyond_prefix_is_close() {
        assert_eq!(Verdict::accept(3).bounded(3), Verdict::accept(3));
        assert_eq!(Verdict::accept(4).bounded(3), Verdict::Close);
        assert_eq!(Verdict::Stall.bounded(0), Verdict::Stall);
    }

    #[test]
    fn exporter_is_optional() {
        let info = CarrierInfo::new();
        assert!(info.export(b"l", b"", 32).is_none());
        let info = CarrierInfo::new().with_exporter(|l, _, out| {
            out.fill(l.len() as u8);
            true
        });
        assert_eq!(info.export(b"abc", b"", 2), Some(vec![3, 3]));
    }

    #[test]
    fn headers_are_visited_in_order() {
        let fields = [("a", &b"1"[..]), ("b", b"2"), ("a", b"3")];
        let info = CarrierInfo::new().with_headers(|| fields);
        let mut seen = Vec::new();
        info.for_each_header(|n, v| seen.push((n.to_owned(), v.to_vec())));
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[2], ("a".to_owned(), b"3".to_vec()));
        CarrierInfo::new().for_each_header(|_, _| panic!("no fields"));
    }
}
