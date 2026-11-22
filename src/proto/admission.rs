//! Carrier admission: the configuration a listener applies to every new
//! carrier ([`Admission`], [`crate::ListenerConfig::admission`]), the
//! metadata of a carrier ([`CarrierInfo`]), the decision taken on it
//! ([`Decide`], [`AdmissionVerdict`]), and what a client presents to it
//! ([`CarrierCredential`]). The rules that turn a decision into the next
//! step (`step`) are here, apart from any I/O; the listener drivers read
//! the prefix and act on the outcome.

use std::any::Any;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::exporter::CarrierExporter;
use super::prefix_auth::{PREFIX_TOKEN_LEN, PrefixAuthVerifier};
use super::record::Framing;

/// The decision on a carrier from its metadata and its prefix: called
/// once per carrier, once more after each [`AdmissionVerdict::More`] and
/// once more after an [`AdmissionVerdict::Defer`], outside the listener's
/// locks, concurrently for different carriers. Each call gets its own
/// `info` (cheap: its fields are shared), the same metadata on every call
/// of one carrier but for its stage and framing. A decision that takes
/// time (a lookup) answers [`Decision::Later`](crate::Decision::Later): it
/// is bound by what remains of the peek timeout, and is cancelled (its
/// future dropped) when that ends or when the listener stops taking
/// carriers; the carrier is then closed, as it is when the decision
/// panics. A later answer keeps `info` and clones what it keeps of
/// `prefix`.
///
/// A synchronous function `Fn(CarrierInfo, &[u8]) -> AdmissionVerdict` is a
/// `Decide`; implement the trait for one that waits.
pub trait Decide: Send + Sync + 'static {
    /// The decision on the carrier `info` describes, whose first bytes (or
    /// first message) are `prefix`.
    fn decide(&self, info: CarrierInfo, prefix: &[u8])
    -> crate::proto::Decision<AdmissionDecision>;

    /// Decides within a listener setup. A decider that dispatches to an
    /// independent runtime can register its work before dispatch and move
    /// the returned guard to its actual completion callback. That work
    /// continues to occupy admission capacity while processing cancellation.
    fn decide_with_worker(
        &self,
        info: CarrierInfo,
        prefix: &[u8],
        _worker: &mut dyn FnMut() -> Box<dyn Send + Sync>,
    ) -> crate::proto::Decision<AdmissionDecision> {
        self.decide(info, prefix)
    }
}

impl<F, D> Decide for F
where
    F: Fn(CarrierInfo, &[u8]) -> D + Send + Sync + 'static,
    D: Into<AdmissionDecision>,
{
    fn decide(
        &self,
        info: CarrierInfo,
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
/// ([`crate::ListenerConfig::admission`]): how many bytes of a byte stream
/// are read before the decision ([`Admission::peek`]) and how many it may
/// ask for ([`Admission::with_max_peek`]), the largest first message of a
/// message-framed carrier ([`Admission::with_max_message`]), how long
/// reading and deciding may take from the end of the carrier's outer
/// handshake ([`Admission::peek_timeout`]), the interval stall durations
/// are in ([`Admission::stall_interval`]), and the decision itself
/// ([`Decide`]). Every entry of the listener applies it, in the same order:
/// the carrier's source slot, its outer handshake (TLS, an HTTP upgrade,
/// QUIC), the admission, then its first record. An HTTP request carrier
/// and an HTTP upgrade are decided on their request head
/// ([`AdmissionStage::Head`]); an upgrade's head may defer the decision to
/// the carrier ([`AdmissionVerdict::Defer`]). Nothing is written on a
/// carrier before it is accepted. Cheap to clone; the clones share the
/// drawn values.
#[derive(Clone)]
pub struct Admission {
    peek: usize,
    max_peek: usize,
    max_message: usize,
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
            .field("max_message", &self.max_message)
            .field("peek_timeout", &self.peek_timeout)
            .field("stall", &self.stall)
            .field("discard_buffer", &self.discard_buffer)
            .field("fallback_on_peek_timeout", &self.fallback_on_peek_timeout)
            .finish_non_exhaustive()
    }
}

/// The largest first message an admission reads by default, and the bound
/// of [`Admission::with_max_message`]: the largest record (the most a zmux
/// first record can be).
#[allow(
    clippy::cast_possible_truncation,
    reason = "65535 fits every usize zmux builds for"
)]
pub const MAX_ADMISSION_MESSAGE: usize = super::params::ZMUX_MAX_RECORD_SIZE as usize;

impl Admission {
    /// An admission that reads up to `peek` bytes of a byte stream (0:
    /// none) and then calls `decide` with the carrier's metadata and the
    /// bytes read (fewer when the carrier ends; one whose prefix does not
    /// arrive within the peek timeout is closed, or see
    /// [`Admission::with_fallback_on_peek_timeout`]): a synchronous
    /// decision ([`Admission::with_decider`] takes one that waits). On a
    /// message-framed carrier a `peek` above 0, and a decision an upgrade's
    /// head deferred with any `peek`, reads the carrier's first message
    /// instead ([`Admission::with_max_message`]).
    pub fn new<D: Into<AdmissionDecision>>(
        peek: usize,
        decide: impl Fn(CarrierInfo, &[u8]) -> D + Send + Sync + 'static,
    ) -> Self {
        Self::with_decider(peek, decide)
    }

    /// [`Admission::new`] with a decision that may wait.
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
            max_message: 0,
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
            verifier.decide(&info, prefix)
        })
    }

    /// With this peek timeout: the limit on reading the prefix and
    /// deciding, every [`AdmissionVerdict::More`] round and a deferred
    /// decision included, from the end of the carrier's outer handshake.
    /// Zero keeps the drawn one.
    #[must_use]
    pub fn with_peek_timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.peek_timeout = timeout;
        }
        self
    }

    /// The largest prefix of a byte stream a decision may ask for with
    /// [`AdmissionVerdict::More`]. 0, the default: the peek length, so that
    /// [`AdmissionVerdict::More`] is [`AdmissionVerdict::Close`]. It bounds
    /// byte streams only: a first message is bounded by
    /// [`Admission::with_max_message`].
    #[must_use]
    pub fn with_max_peek(mut self, bytes: usize) -> Self {
        self.max_peek = bytes;
        self
    }

    /// The largest first message of a message-framed carrier (a WebSocket)
    /// that the decision reads: a longer one is closed without a decision
    /// (`AdmissionStats::too_large`). 0, the default:
    /// [`MAX_ADMISSION_MESSAGE`], the largest record; a host that decides on
    /// messages of its own sets the largest it accepts. Above
    /// [`MAX_ADMISSION_MESSAGE`] the listener's configuration is invalid.
    #[must_use]
    pub fn with_max_message(mut self, bytes: usize) -> Self {
        self.max_message = bytes;
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
    /// instead of closing it (default off). Without a fallback
    /// (`ListenerConfig::fallback`) it is stalled, as for any
    /// fallback. Admission counts the outcome of that fallback path. A
    /// message-framed carrier, an HTTP request, a carrier deferred from an
    /// upgrade, or a decision that runs past the deadline closes either way.
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

    /// The number of bytes of a byte stream read before the decision.
    #[must_use]
    pub fn peek(&self) -> usize {
        self.peek
    }

    /// The largest prefix of a byte stream: [`Admission::with_max_peek`], at
    /// least the peek length.
    #[must_use]
    pub fn max_peek(&self) -> usize {
        self.max_peek.max(self.peek)
    }

    /// The largest first message: [`Admission::with_max_message`], or
    /// [`MAX_ADMISSION_MESSAGE`] for 0.
    #[must_use]
    pub fn max_message(&self) -> usize {
        if self.max_message == 0 {
            MAX_ADMISSION_MESSAGE
        } else {
            self.max_message
        }
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

    /// Checks the bounds: [`Admission::with_max_message`] at most
    /// [`MAX_ADMISSION_MESSAGE`].
    pub(crate) fn validate(&self) -> Result<(), crate::InvalidConfig> {
        if self.max_message > MAX_ADMISSION_MESSAGE {
            return Err(crate::InvalidConfig::new(
                "Admission::max_message",
                "above MAX_ADMISSION_MESSAGE",
            ));
        }
        Ok(())
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
    /// beyond the prefix is [`AdmissionVerdict::Close`], and so is one that
    /// would split a first message (neither 0 nor the whole message).
    /// `value` is the host's value for the carrier ([`AdmittedValue`]).
    Accept {
        /// Prefix bytes removed.
        skip: usize,
        /// The host's value for the carrier.
        value: Option<AdmittedValue>,
    },
    /// The carrier, with every byte or the first message read replayed,
    /// goes to the listener's fallback
    #[cfg_attr(
        feature = "tokio",
        doc = " ([`crate::ListenerConfig::fallback`], a [`crate::Takeover`]); without"
    )]
    #[cfg_attr(
        not(feature = "tokio"),
        doc = " (`ListenerConfig::fallback`, a `Takeover`); without"
    )]
    /// one it is stalled. An HTTP request that is itself the carrier
    /// (decided on its head or body, an upgrade refused on its head) is a
    /// request rather than a carrier to take over: its adapter's HTTP
    /// fallback serves it (without one: a not-found response). The carrier
    /// of an upgrade decided after an [`AdmissionVerdict::Defer`] is a
    /// carrier: it goes to the listener's fallback. `value` is the host's value for the
    /// takeover (`Takeover::value`), routing it to the host's service; it
    /// does not reach an adapter's HTTP fallback.
    Fallback {
        /// The host's value for the carrier's takeover.
        value: Option<AdmittedValue>,
    },
    /// Serve the carrier itself through the listener's byte-stream target,
    /// after the accepted response or upgrade. Without a target, stall.
    Takeover {
        /// Host value delivered with the carrier.
        value: Option<AdmittedValue>,
    },
    /// Nothing is sent; what arrives is read and discarded, and the carrier
    /// is closed gracefully (a byte stream's write side first) when the
    /// peer ends it or when a duration drawn from the configured stall
    /// interval has passed. An HTTP request is ended then without a
    /// response.
    Stall,
    /// The carrier is closed at once.
    Close,
    /// Read the byte stream on until the prefix holds `need` bytes in all
    /// (or the carrier ends, or the peek timeout passes, all rounds sharing
    /// it), then decide again with the longer prefix. `need` must exceed
    /// the prefix and not exceed [`Admission::max_peek`]; anything else,
    /// a carrier that ended short of an earlier `need`, a message-framed
    /// carrier and a request head make it [`AdmissionVerdict::Close`].
    More {
        /// The total prefix length wanted.
        need: usize,
    },
    /// On the head of an HTTP upgrade ([`CarrierInfo::upgrade`],
    /// [`AdmissionStage::Head`]): complete the upgrade and decide again on
    /// the carrier, with the same metadata at [`AdmissionStage::Carrier`]
    /// and the carrier's first message, or its first [`Admission::peek`]
    /// bytes (the first stream of a WebTransport session). The peek timeout
    /// runs on from the head's decision, and the carrier keeps its slots
    /// throughout. On any other decision it is [`AdmissionVerdict::Close`].
    Defer,
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
                a == b && same(x.as_ref(), y.as_ref())
            }
            (Self::Fallback { value: x }, Self::Fallback { value: y })
            | (Self::Takeover { value: x }, Self::Takeover { value: y }) => {
                same(x.as_ref(), y.as_ref())
            }
            (Self::Stall, Self::Stall)
            | (Self::Close, Self::Close)
            | (Self::Defer, Self::Defer) => true,
            (Self::More { need: a }, Self::More { need: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for AdmissionVerdict {}

/// Whether two optional values are the same one.
fn same(x: Option<&AdmittedValue>, y: Option<&AdmittedValue>) -> bool {
    match (x, y) {
        (None, None) => true,
        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
        _ => false,
    }
}

impl AdmissionVerdict {
    /// [`AdmissionVerdict::Accept`] removing `skip` prefix bytes, without a value.
    #[must_use]
    pub const fn accept(skip: usize) -> Self {
        Self::Accept { skip, value: None }
    }

    /// Take over the carrier with its prefetched input.
    #[must_use]
    pub const fn takeover() -> Self {
        Self::Takeover { value: None }
    }

    /// [`AdmissionVerdict::Fallback`] without a value.
    #[must_use]
    pub const fn fallback() -> Self {
        Self::Fallback { value: None }
    }

    /// With the host's value for an accepted carrier or a takeover
    /// ([`AdmissionVerdict::Accept`], [`AdmissionVerdict::Fallback`], [`AdmissionVerdict::Takeover`]); other
    /// verdicts carry none and are returned as they are.
    #[must_use]
    pub fn with_value(self, value: AdmittedValue) -> Self {
        match self {
            Self::Accept { skip, .. } => Self::Accept {
                skip,
                value: Some(value),
            },
            Self::Takeover { .. } => Self::Takeover { value: Some(value) },
            Self::Fallback { .. } => Self::Fallback { value: Some(value) },
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
}

/// What of a carrier a decision is taken on ([`CarrierInfo::stage`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AdmissionStage {
    /// The carrier's start: the prefix is its first bytes
    /// ([`Admission::peek`], [`AdmissionVerdict::More`]) or its first
    /// message ([`CarrierInfo::framing`]).
    #[default]
    Carrier,
    /// An HTTP request's head, before any body byte is read or the upgrade
    /// is answered: an HTTP upgrade (WebSocket, WebTransport;
    /// [`CarrierInfo::upgrade`]), or an HTTP request carrier without a
    /// body. There is no prefix, and a credential travels in a request
    /// header field.
    Head,
}

/// Where a decision is taken, for [`step`]: what the rules of the
/// verdicts depend on.
#[cfg(any(test, all(feature = "tokio", not(loom))))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Round {
    /// The stage of the decision.
    pub stage: AdmissionStage,
    /// The carrier's framing at [`AdmissionStage::Carrier`].
    pub framing: Framing,
    /// An HTTP upgrade's head, which may defer.
    pub upgrade: bool,
    /// The length of the prefix decided on.
    pub len: usize,
    /// More of the byte stream can be read.
    pub can_read: bool,
    /// The carrier ended short of an earlier [`AdmissionVerdict::More`].
    pub short: bool,
    /// [`Admission::max_peek`].
    pub max_peek: usize,
}

/// What a decision leads to ([`step`]).
#[cfg(any(test, all(feature = "tokio", not(loom))))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// The outcome: [`AdmissionVerdict::Accept`] with a `skip` within the
    /// prefix, [`AdmissionVerdict::Fallback`], [`AdmissionVerdict::Stall`]
    /// or [`AdmissionVerdict::Close`].
    Final(AdmissionVerdict),
    /// Read the byte stream on to this many bytes and decide again.
    Read(usize),
    /// Complete the upgrade and decide again on the carrier.
    Defer,
}

/// The step a decision leads to at `round`, the one place of the rules of
/// [`AdmissionVerdict::More`], [`AdmissionVerdict::Defer`] and an
/// [`AdmissionVerdict::Accept`]'s `skip`; every misuse is
/// [`AdmissionVerdict::Close`].
#[cfg(any(test, all(feature = "tokio", not(loom))))]
pub(crate) fn step(verdict: AdmissionVerdict, round: &Round) -> Step {
    let head = round.stage == AdmissionStage::Head;
    let records = !head && round.framing == Framing::Records;
    match verdict {
        AdmissionVerdict::Defer if head && round.upgrade => Step::Defer,
        AdmissionVerdict::More { need }
            if !head
                && !records
                && round.can_read
                && !round.short
                && need > round.len
                && need <= round.max_peek =>
        {
            Step::Read(need)
        }
        AdmissionVerdict::Defer | AdmissionVerdict::More { .. } => {
            Step::Final(AdmissionVerdict::Close)
        }
        AdmissionVerdict::Accept { skip, .. }
            if skip > round.len || records && skip != 0 && skip != round.len =>
        {
            Step::Final(AdmissionVerdict::Close)
        }
        v => Step::Final(v),
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
    /// What of the carrier the decision is taken on: its HTTP request head
    /// ([`AdmissionStage::Head`], without a prefix: an HTTP upgrade, or an
    /// HTTP request carrier whose request has no body; a token travels in
    /// a request header field) or its start ([`AdmissionStage::Carrier`],
    /// the default).
    pub stage: AdmissionStage,
    /// The carrier's framing at [`AdmissionStage::Carrier`]: the prefix is
    /// the start of a byte stream, or the carrier's first message with
    /// [`Framing::Records`]; as
    #[cfg_attr(
        feature = "tokio",
        doc = " [`crate::adapter::classify_first_bytes`] takes it. [`Framing::ByteStream`]"
    )]
    #[cfg_attr(
        not(feature = "tokio"),
        doc = " `classify_first_bytes` takes it. [`Framing::ByteStream`]"
    )]
    /// on a head.
    pub framing: Framing,
    /// The carrier of an HTTP upgrade (WebSocket, WebTransport), on its
    /// head and on the decision an [`AdmissionVerdict::Defer`] on that head
    /// takes on the carrier.
    pub upgrade: bool,
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
            .field("stage", &self.stage)
            .field("framing", &self.framing)
            .field("upgrade", &self.upgrade)
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

    /// At this stage ([`CarrierInfo::stage`]).
    #[must_use]
    pub fn with_stage(mut self, stage: AdmissionStage) -> Self {
        self.stage = stage;
        self
    }

    /// With the carrier's framing ([`CarrierInfo::framing`]).
    #[must_use]
    pub fn with_framing(mut self, framing: Framing) -> Self {
        self.framing = framing;
        self
    }

    /// As the carrier of an HTTP upgrade ([`CarrierInfo::upgrade`]).
    #[must_use]
    pub fn with_upgrade(mut self) -> Self {
        self.upgrade = true;
        self
    }

    /// Whether the decision is taken on an HTTP request head
    /// ([`AdmissionStage::Head`]).
    #[must_use]
    pub fn is_head(&self) -> bool {
        self.stage == AdmissionStage::Head
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
    /// its HTTP request head ([`AdmissionStage::Head`]): an HTTP upgrade
    /// (WebSocket, WebTransport), or an HTTP request without a body.
    fn header(&self, info: &CarrierInfo) -> io::Result<(String, String)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drawn_bounds() {
        for _ in 0..64 {
            let a = Admission::new(0, |_, _: &[u8]| AdmissionVerdict::Close);
            assert!((PEEK_TIMEOUT_DRAWN.0..=PEEK_TIMEOUT_DRAWN.1).contains(&a.peek_timeout()));
            let (min, max) = a.stall_interval();
            assert!((STALL_MAX_DRAWN.0..=STALL_MAX_DRAWN.1).contains(&max));
            assert!(min >= max / 4 && min <= max * 3 / 4);
        }
        let a = Admission::new(0, |_, _: &[u8]| AdmissionVerdict::Close)
            .with_stall_interval(Duration::from_secs(3), Duration::from_secs(1));
        assert_eq!(
            a.stall_interval(),
            (Duration::from_secs(1), Duration::from_secs(1))
        );
    }

    fn round(stage: AdmissionStage, framing: Framing, len: usize) -> Round {
        Round {
            stage,
            framing,
            upgrade: false,
            len,
            can_read: true,
            short: false,
            max_peek: 16,
        }
    }

    #[test]
    fn accept_beyond_prefix_is_close() {
        let r = round(AdmissionStage::Carrier, Framing::ByteStream, 3);
        let close = Step::Final(AdmissionVerdict::Close);
        assert_eq!(
            step(AdmissionVerdict::accept(3), &r),
            Step::Final(AdmissionVerdict::accept(3))
        );
        assert_eq!(step(AdmissionVerdict::accept(4), &r), close);
        assert_eq!(
            step(AdmissionVerdict::Stall, &r),
            Step::Final(AdmissionVerdict::Stall)
        );
        // A message is replayed whole or not at all.
        let m = round(AdmissionStage::Carrier, Framing::Records, 3);
        assert_eq!(
            step(AdmissionVerdict::accept(0), &m),
            Step::Final(AdmissionVerdict::accept(0))
        );
        assert_eq!(
            step(AdmissionVerdict::accept(3), &m),
            Step::Final(AdmissionVerdict::accept(3))
        );
        assert_eq!(step(AdmissionVerdict::accept(1), &m), close);
    }

    #[test]
    fn more_reads_a_byte_stream_only() {
        let close = Step::Final(AdmissionVerdict::Close);
        let more = |need| AdmissionVerdict::More { need };
        let r = round(AdmissionStage::Carrier, Framing::ByteStream, 4);
        assert_eq!(step(more(8), &r), Step::Read(8));
        assert_eq!(step(more(16), &r), Step::Read(16));
        // Not beyond max_peek, not at or below the prefix.
        assert_eq!(step(more(17), &r), close);
        assert_eq!(step(more(4), &r), close);
        // Nothing more to read: ended short, or no reader.
        assert_eq!(step(more(8), &Round { short: true, ..r }), close);
        assert_eq!(
            step(
                more(8),
                &Round {
                    can_read: false,
                    ..r
                }
            ),
            close
        );
        // A message carrier, a head (an upgrade's included).
        let m = round(AdmissionStage::Carrier, Framing::Records, 4);
        assert_eq!(step(more(8), &m), close);
        let h = Round {
            upgrade: true,
            ..round(AdmissionStage::Head, Framing::ByteStream, 0)
        };
        assert_eq!(step(more(8), &h), close);
    }

    #[test]
    fn defer_only_on_an_upgrade_head() {
        let close = Step::Final(AdmissionVerdict::Close);
        let head = round(AdmissionStage::Head, Framing::ByteStream, 0);
        let upgrade = Round {
            upgrade: true,
            ..head
        };
        assert_eq!(step(AdmissionVerdict::Defer, &upgrade), Step::Defer);
        // A request head, and the carrier of an upgrade, cannot defer.
        assert_eq!(step(AdmissionVerdict::Defer, &head), close);
        let carrier = Round {
            stage: AdmissionStage::Carrier,
            ..upgrade
        };
        assert_eq!(step(AdmissionVerdict::Defer, &carrier), close);
        let m = round(AdmissionStage::Carrier, Framing::Records, 3);
        assert_eq!(step(AdmissionVerdict::Defer, &m), close);
    }

    #[test]
    fn max_message_default_and_bound() {
        let a = Admission::new(0, |_, _: &[u8]| AdmissionVerdict::Close);
        assert_eq!(a.max_message(), MAX_ADMISSION_MESSAGE);
        assert!(a.validate().is_ok());
        let a = a.with_max_message(100);
        assert_eq!(a.max_message(), 100);
        let a = a.with_max_message(MAX_ADMISSION_MESSAGE);
        assert!(a.validate().is_ok());
        let a = a.with_max_message(MAX_ADMISSION_MESSAGE + 1);
        assert!(a.validate().is_err());
        // max_peek bounds byte streams only.
        let a = Admission::new(4, |_, _: &[u8]| AdmissionVerdict::Close).with_max_peek(2);
        assert_eq!(a.max_peek(), 4);
        assert_eq!(a.max_message(), MAX_ADMISSION_MESSAGE);
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
