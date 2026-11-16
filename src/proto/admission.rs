//! Carrier admission: the configuration a listener applies to every new
//! carrier ([`Admission`], [`crate::ListenerConfig::admission`]), the
//! metadata of a carrier ([`CarrierInfo`]), the decision taken on it
//! ([`Decide`], [`AdmissionVerdict`]), and what a client presents to it
//! ([`CarrierCredential`]).

use std::any::Any;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::exporter::CarrierExporter;
use super::prefix_auth::{PREFIX_TOKEN_LEN, PrefixAuthVerifier};

/// The decision on a carrier from its metadata and its prefix: called
/// once per carrier, outside the listener's locks, concurrently for
/// different carriers. A decision that takes time (a lookup) answers
/// [`Decision::Later`](crate::Decision::Later): it is bound by what remains
/// of the peek timeout, and is cancelled (its future dropped) when that ends
/// or when the listener stops taking carriers; the carrier is then closed.
/// A later answer clones what it keeps of `info` (cheap: shared fields) and
/// of `prefix`.
///
/// A synchronous function `Fn(&CarrierInfo, &[u8]) -> AdmissionVerdict` is a
/// `Decide`; implement the trait for one that waits.
pub trait Decide: Send + Sync + 'static {
    /// The decision on the carrier `info` describes, whose first bytes are
    /// `prefix`.
    fn decide(
        &self,
        info: &CarrierInfo,
        prefix: &[u8],
    ) -> crate::proto::Decision<AdmissionDecision>;
}

impl<F, D> Decide for F
where
    F: Fn(&CarrierInfo, &[u8]) -> D + Send + Sync + 'static,
    D: Into<AdmissionDecision>,
{
    fn decide(
        &self,
        info: &CarrierInfo,
        prefix: &[u8],
    ) -> crate::proto::Decision<AdmissionDecision> {
        crate::proto::Decision::Now(self(info, prefix).into())
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
    max_peek: usize,
    peek_timeout: Duration,
    stall: (Duration, Duration),
    discard_buffer: usize,
    fallback_on_peek_timeout: bool,
    decide: Arc<dyn Decide>,
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission")
            .field("peek", &self.peek)
            .field("max_peek", &self.max_peek)
            .field("peek_timeout", &self.peek_timeout)
            .field("stall", &self.stall)
            .field("discard_buffer", &self.discard_buffer)
            .field("fallback_on_peek_timeout", &self.fallback_on_peek_timeout)
            .finish_non_exhaustive()
    }
}

impl Admission {
    /// An admission that reads up to `peek` bytes (0: none) and then calls
    /// `decide` with the carrier's metadata and the bytes read (fewer when
    /// the carrier ends; one whose prefix does not arrive within the peek
    /// timeout is closed, or see
    /// [`Admission::with_fallback_on_peek_timeout`]): a synchronous
    /// decision ([`Admission::with_decider`] takes one that waits).
    pub fn new<D: Into<AdmissionDecision>>(
        peek: usize,
        decide: impl Fn(&CarrierInfo, &[u8]) -> D + Send + Sync + 'static,
    ) -> Self {
        Self::with_decider(peek, decide)
    }

    /// An admission that reads up to `peek` bytes (0: none) and then asks
    /// `decide` with the carrier's metadata and the bytes read (fewer when
    /// the carrier ends; one whose prefix does not arrive within the peek
    /// timeout is closed, or see
    /// [`Admission::with_fallback_on_peek_timeout`]).
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
            max_peek: 0,
            peek_timeout,
            stall: (min, max),
            discard_buffer: 512,
            fallback_on_peek_timeout: false,
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
    /// deciding, from the end of the carrier's outer handshake. Zero keeps
    /// the drawn one.
    #[must_use]
    pub fn with_peek_timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.peek_timeout = timeout;
        }
        self
    }

    /// The largest prefix a decision may ask for with [`AdmissionVerdict::More`].
    /// 0, the default: the peek length, so that [`AdmissionVerdict::More`] is not
    /// valid.
    #[must_use]
    pub fn with_max_peek(mut self, bytes: usize) -> Self {
        self.max_peek = bytes;
        self
    }

    /// With this stall interval: a stall lasts a duration in `[min, max]`
    /// (`max` when `min` is above it) that the listener derives from the
    /// carrier's source. A `max` of zero keeps the drawn interval.
    #[must_use]
    pub fn with_stall_interval(mut self, min: Duration, max: Duration) -> Self {
        if !max.is_zero() {
            self.stall = (min.min(max), max);
        }
        self
    }

    /// With this read size for the bytes a stall discards (default 512,
    /// at least 1).
    #[must_use]
    pub fn with_discard_buffer(mut self, bytes: usize) -> Self {
        self.discard_buffer = bytes.max(1);
        self
    }

    /// Takes a byte-stream carrier whose prefix has not arrived when the
    /// peek timeout ends, in the first read or in a [`AdmissionVerdict::More`]
    /// round, to [`AdmissionVerdict::Fallback`] with every byte read replayed,
    /// instead of closing it (default off). Without a fallback target it
    /// is stalled, as for any fallback. It is counted in both
    /// `peek_timed_out` and `fallback`. A carrier read without a reader
    /// (message-framed), an HTTP request carrier and a decision that does
    /// not return in time are closed either way.
    #[must_use]
    pub fn with_fallback_on_peek_timeout(mut self, on: bool) -> Self {
        self.fallback_on_peek_timeout = on;
        self
    }

    /// Whether a late prefix goes to the fallback
    /// ([`Admission::with_fallback_on_peek_timeout`]).
    #[must_use]
    pub fn fallback_on_peek_timeout(&self) -> bool {
        self.fallback_on_peek_timeout
    }

    /// The number of bytes read before the decision.
    #[must_use]
    pub fn peek(&self) -> usize {
        self.peek
    }

    /// The largest prefix: [`Admission::with_max_peek`], at least the peek
    /// length.
    #[must_use]
    pub fn max_peek(&self) -> usize {
        self.max_peek.max(self.peek)
    }

    /// The peek timeout.
    #[must_use]
    pub fn peek_timeout(&self) -> Duration {
        self.peek_timeout
    }

    /// The stall interval, `(min, max)`.
    #[must_use]
    pub fn stall_interval(&self) -> (Duration, Duration) {
        self.stall
    }

    /// The read size of a stall's discarding.
    #[must_use]
    pub fn discard_buffer(&self) -> usize {
        self.discard_buffer
    }

    /// The decider, for a driver that applies the admission.
    #[must_use]
    pub fn decider(&self) -> &dyn Decide {
        &*self.decide
    }
}

/// A listener's maximum stall duration without an admission: drawn from
/// [`STALL_MAX_DRAWN`], as an admission's is.
#[cfg(all(not(loom), any(feature = "tokio", feature = "blocking")))]
pub(crate) fn draw_stall_max() -> Duration {
    draw(STALL_MAX_DRAWN.0, STALL_MAX_DRAWN.1)
}

/// Uniform in `[lo, hi]` from the system's secure random source.
fn draw(lo: Duration, hi: Duration) -> Duration {
    if hi <= lo {
        return hi;
    }
    let span = hi.saturating_sub(lo).as_nanos().saturating_add(1);
    let r = u128::from(crate::util::random_u64()) % span;
    lo.saturating_add(Duration::from_nanos(u64::try_from(r).unwrap_or(u64::MAX)))
        .min(hi)
}

/// A host's value attached to a carrier by the admission that accepted
/// it ([`AdmissionVerdict::Accept`]): opaque to zmux, which neither inspects,
/// compares nor drops it early. The transform of a listener sees it
#[cfg_attr(
    feature = "tokio",
    doc = " ([`crate::PipeHint::admitted`]), the session it bootstraps keeps it"
)]
#[cfg_attr(
    not(feature = "tokio"),
    doc = " (`PipeHint::admitted`), the session it bootstraps keeps it"
)]
/// (`Session::admitted`, the uplink's for a split bootstrap) and each pipe
/// the value of the carrier that joined it (`Pipe::admitted`); a further
/// stream of an admitted QUIC connection carries the connection's. A join
/// is never refused for a value that differs from its session's: a host
/// that wants that checks in its transform, or closes the pipe.
pub type AdmittedValue = Arc<dyn Any + Send + Sync>;

/// The decision on a carrier under admission.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AdmissionVerdict {
    /// The first `skip` bytes of the prefix are removed; the rest of the
    /// prefix, then the rest of the carrier, go to the listener. A `skip`
    /// beyond the prefix is [`AdmissionVerdict::Close`]. `value` is the host's
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
    /// Read until the prefix holds `need` bytes in all (or the carrier
    /// ends, or the peek timeout passes, all rounds sharing it), then decide
    /// again with the longer prefix. `need` must exceed the prefix and not
    /// exceed [`Admission::max_peek`], and the carrier must be a byte
    #[cfg_attr(
        feature = "tokio",
        doc = " stream read by [`crate::adapter::Entry::admit`] or"
    )]
    #[cfg_attr(
        not(feature = "tokio"),
        doc = " stream read by `adapter::Entry::admit` or"
    )]
    #[cfg_attr(
        feature = "tokio",
        doc = " [`crate::adapter::Entry::decide_reading`]; otherwise it counts as"
    )]
    #[cfg_attr(
        not(feature = "tokio"),
        doc = " `adapter::Entry::decide_reading`; otherwise it counts as"
    )]
    /// [`AdmissionVerdict::Close`], as it does when the carrier ended short.
    More {
        /// The total prefix length wanted.
        need: usize,
    },
}

/// A decision on a carrier: its [`AdmissionVerdict`] and the host's label of the kind
/// of carrier. A label counts the verdict per label
#[cfg_attr(
    feature = "tokio",
    doc = " ([`crate::AdmissionVariants::variants`]); on an accepted carrier it becomes"
)]
#[cfg_attr(
    not(feature = "tokio"),
    doc = " (`AdmissionVariants::variants`); on an accepted carrier it becomes"
)]
/// the carrier's variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDecision {
    /// What to do.
    pub verdict: AdmissionVerdict,
    /// The carrier's label; `None` for none.
    pub variant: Option<Arc<str>>,
}

impl From<AdmissionVerdict> for AdmissionDecision {
    fn from(verdict: AdmissionVerdict) -> Self {
        Self {
            verdict,
            variant: None,
        }
    }
}

/// Values compare by identity.
impl PartialEq for AdmissionVerdict {
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
            (Self::More { need: a }, Self::More { need: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for AdmissionVerdict {}

impl AdmissionVerdict {
    /// [`AdmissionVerdict::Accept`] removing `skip` prefix bytes, without a value.
    #[must_use]
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

    /// An [`AdmissionDecision`] of this verdict labelled `variant`.
    #[must_use]
    pub fn labelled(self, variant: impl Into<Arc<str>>) -> AdmissionDecision {
        AdmissionDecision {
            verdict: self,
            variant: Some(variant.into()),
        }
    }

    /// The verdict with `Accept` bounded by a prefix of `len` bytes: a
    /// `skip` beyond it is [`AdmissionVerdict::Close`].
    #[must_use]
    pub fn bounded(self, len: usize) -> Self {
        match self {
            Self::Accept { skip, .. } if skip > len => Self::Close,
            v => v,
        }
    }
}

/// The request header fields of an HTTP carrier: calls `each(name, value)`
/// for every field, in order.
/// Visits the header fields of a request head `R`: `(request, each)`.
pub type VisitFields<R> = fn(&R, &mut dyn FnMut(&str, &[u8]));

type HeadersFn = dyn Fn(&mut dyn FnMut(&str, &[u8])) + Send + Sync;

/// The metadata of a carrier, as far as its adapter has it: a server's
/// admission decides with it, and a client's [`CarrierCredential`] is given
/// it. Fields that do not apply are `None`. Owned and cheap to clone (its
/// fields are shared), so that a decision that answers later keeps it.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct CarrierInfo {
    /// The carrier's source: the client a trusted intermediary reports
    /// ([`crate::TrustedProxies::source`], a reported port of 0 when it
    /// reported none), the source a host gave the listener
    #[cfg_attr(
        feature = "tokio",
        doc = " ([`crate::PipeHint::source`]), or otherwise the peer. The one"
    )]
    #[cfg_attr(
        not(feature = "tokio"),
        doc = " (`PipeHint::source`), or otherwise the peer. The one"
    )]
    /// source of the carrier: its per-source limits and stall duration go
    /// by it too.
    pub source: Option<SocketAddr>,
    /// The directly connected peer: the TCP or QUIC peer, or the remote
    /// address of an HTTP request's connection.
    pub peer: Option<SocketAddr>,
    /// The application protocol the TLS or QUIC handshake negotiated.
    pub alpn: Option<Arc<[u8]>>,
    /// The server name the client sent in its TLS or QUIC handshake.
    pub server_name: Option<Arc<str>>,
    /// The request head of an HTTP carrier, as the adapter's own type (the
    /// HTTP adapters give `http::request::Parts`): downcast it. Its
    /// header fields are also given independently of the type
    /// ([`CarrierInfo::for_each_header`]).
    pub request: Option<Arc<dyn Any + Send + Sync>>,
    /// Whether the carrier is decided on its HTTP request head, without a
    /// prefix: an HTTP upgrade (WebSocket,
    /// WebTransport), or an HTTP request carrier whose request has no
    /// body. A token travels in a request header field.
    pub head: bool,
    headers: Option<Arc<HeadersFn>>,
    exporter: Option<CarrierExporter>,
}

impl std::fmt::Debug for CarrierInfo {
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

impl CarrierInfo {
    /// No metadata.
    #[must_use]
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
    pub fn with_alpn(mut self, alpn: Option<&[u8]>) -> Self {
        self.alpn = alpn.map(Arc::from);
        self
    }

    /// With the client's server name.
    #[must_use]
    pub fn with_server_name(mut self, name: Option<&str>) -> Self {
        self.server_name = name.map(Arc::from);
        self
    }

    /// With an HTTP carrier's request head.
    #[must_use]
    pub fn with_request(mut self, request: Arc<dyn Any + Send + Sync>) -> Self {
        self.request = Some(request);
        self
    }

    /// With an HTTP carrier's request head `request` ([`Self::request`])
    /// and its header fields, which `fields(request, each)` visits
    /// ([`Self::with_headers`]); one shared value for both.
    #[must_use]
    pub fn with_request_head<R: Any + Send + Sync>(
        self,
        request: Arc<R>,
        fields: VisitFields<R>,
    ) -> Self {
        let r = request.clone();
        self.with_request(request)
            .with_headers(move |each| fields(&r, each))
    }

    /// As a carrier decided on its HTTP request head
    /// ([`CarrierInfo::head`]).
    #[must_use]
    pub fn with_head(mut self) -> Self {
        self.head = true;
        self
    }

    /// With an HTTP carrier's request header fields: `fields(each)` calls
    /// `each(name, value)` for every field, in order, the name in lower
    /// case.
    #[must_use]
    pub fn with_headers(
        mut self,
        fields: impl Fn(&mut dyn FnMut(&str, &[u8])) + Send + Sync + 'static,
    ) -> Self {
        self.headers = Some(Arc::new(fields));
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

    /// With the exporter of the carrier's completed TLS or QUIC handshake.
    #[must_use]
    pub fn with_exporter(mut self, exporter: CarrierExporter) -> Self {
        self.exporter = Some(exporter);
        self
    }

    /// The carrier's exporter.
    #[must_use]
    pub fn exporter(&self) -> Option<&CarrierExporter> {
        self.exporter.as_ref()
    }

    /// Whether the carrier has an exporter.
    #[must_use]
    pub fn has_exporter(&self) -> bool {
        self.exporter.is_some()
    }

    /// `len` bytes of the exporter for `label` and `context`; `None` without
    /// an exporter, when it fails, or for an exporter whose values come
    /// later that has not given this one yet ([`Self::export_async`]).
    #[must_use]
    pub fn export(&self, label: &str, context: &[u8], len: usize) -> Option<Vec<u8>> {
        self.exporter.as_ref()?.export(label, context, len)
    }

    /// [`Self::export`], waiting for an exporter whose values come later.
    pub fn export_async(
        &self,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send + 'static {
        let fut = self
            .exporter
            .as_ref()
            .map(|e| e.export_async(label, context, len));
        async move { fut?.await }
    }
}

/// What a client presents to a server's admission on a new carrier: the
/// counterpart of the server's decision. An adapter asks for it once per
/// carrier, after the carrier's TLS or QUIC handshake completed and before
/// any zmux record, with the metadata it has of the carrier, the exporter
/// of that handshake among them where the adapter holds the TLS layer (for
/// a credential bound to it). An error fails the dial.
/// [`crate::PrefixAuth`] is one.
pub trait CarrierCredential: Send + Sync + std::fmt::Debug {
    /// The bytes a byte-stream carrier, an HTTP request body carrier or a
    /// QUIC carrier's first stream starts with.
    fn prefix(&self, info: &CarrierInfo) -> io::Result<Vec<u8>>;

    /// The request header field, `(name, value)`, of a carrier decided on
    /// its HTTP request head: an HTTP upgrade (WebSocket, WebTransport), or
    /// an HTTP request without a body.
    fn header(&self, info: &CarrierInfo) -> io::Result<(String, String)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drawn_bounds() {
        for _ in 0..64 {
            let a = Admission::new(0, |_, _| AdmissionVerdict::Close);
            assert!((PEEK_TIMEOUT_DRAWN.0..=PEEK_TIMEOUT_DRAWN.1).contains(&a.peek_timeout()));
            let (min, max) = a.stall_interval();
            assert!((STALL_MAX_DRAWN.0..=STALL_MAX_DRAWN.1).contains(&max));
            assert!(min >= max / 4 && min <= max * 3 / 4);
        }
        let a = Admission::new(0, |_, _| AdmissionVerdict::Close)
            .with_stall_interval(Duration::from_secs(3), Duration::from_secs(1));
        assert_eq!(
            a.stall_interval(),
            (Duration::from_secs(1), Duration::from_secs(1))
        );
    }

    #[test]
    fn accept_beyond_prefix_is_close() {
        assert_eq!(
            AdmissionVerdict::accept(3).bounded(3),
            AdmissionVerdict::accept(3)
        );
        assert_eq!(
            AdmissionVerdict::accept(4).bounded(3),
            AdmissionVerdict::Close
        );
        assert_eq!(AdmissionVerdict::Stall.bounded(0), AdmissionVerdict::Stall);
    }

    #[test]
    fn exporter_is_optional() {
        let info = CarrierInfo::new();
        assert!(info.export("l", b"", 32).is_none());
        let info = CarrierInfo::new().with_exporter(CarrierExporter::new(|l, _, out| {
            out.fill(u8::try_from(l.len()).unwrap());
            true
        }));
        assert_eq!(info.export("abc", b"", 2), Some(vec![3, 3]));
    }

    #[test]
    fn headers_are_visited_in_order() {
        let fields = [("a", &b"1"[..]), ("b", b"2"), ("a", b"3")];
        let info = CarrierInfo::new().with_headers(move |each| {
            for (n, v) in fields {
                each(n, v);
            }
        });
        let mut seen = Vec::new();
        info.for_each_header(|n, v| seen.push((n.to_owned(), v.to_vec())));
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[2], ("a".to_owned(), b"3".to_vec()));
        CarrierInfo::new().for_each_header(|_, _| panic!("no fields"));
    }
}
