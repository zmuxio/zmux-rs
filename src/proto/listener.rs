//! A sans-IO listener: it classifies new carriers by their first bytes, cuts Join
//! Hellos, pairs split carriers, and bounds the carriers that are not authenticated
//! yet. It never touches session state: the driver looks up the session by locator and
//! offers the Hello to it ([`crate::proto::session::SessionCore::open_hello`]).

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use crate::proto::frame::{LANE_KEY_LEN, PipeLane};
use crate::proto::ident::{Classifier, FirstRecord, Verdict};
use crate::proto::oob::PAIRING_TOKEN_LEN;
use crate::proto::record::Framing;
use crate::proto::seal::Error as SealError;
use crate::proto::seal::join::JoinHello;
use crate::proto::session::Budget;
use crate::proto::varint;

/// A change of a listener's memory pressure: it
/// started (the sessions' charges reached the budget) or ended (they fell
/// below three quarters of it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryPressure {
    /// The sum of the sessions' charges, in bytes, when it changed.
    pub used: u64,
    /// The budget.
    pub budget: u64,
    /// Pressure started (`true`) or ended.
    pub active: bool,
}

/// The hook `on_memory_pressure`: called outside every
/// lock on the listener's own serial context, never on an I/O path, when
/// pressure starts and when it ends; free to close sessions. A panic is
/// ignored.
#[derive(Clone)]
pub struct OnMemoryPressure(pub std::sync::Arc<dyn Fn(MemoryPressure) + Send + Sync>);

impl std::fmt::Debug for OnMemoryPressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnMemoryPressure(..)")
    }
}

/// Listener limits.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ListenerConfig {
    /// Carriers being classified or verified at once (default 64); a new
    /// carrier evicts the oldest when full.
    pub max_pending: usize,
    /// Pending carriers per source (default 8).
    pub max_pending_per_source: usize,
    /// Unconfirmed carriers per session: joins that passed authentication and wait for the
    /// joiner's confirmation (default 4). A new authenticated Hello beyond it evicts the one
    /// Unconfirmed longest and is never refused for lack of room.
    pub max_pending_per_session: usize,
    /// The first record or Hello must arrive within this (default 2 s).
    pub first_record_timeout: Duration,
    /// A pending carrier is closed after this (default 10 s).
    pub handshake_timeout: Duration,
    /// The listener's own `max_record_size` (default 65535).
    pub max_record_size: u64,
    /// Whether carriers may start new sessions.
    pub accept_sessions: bool,
    /// Suspended sessions held at once (default 1024).
    pub max_suspended: usize,
    /// Bytes the sessions may hold together (default 1 GiB;
    /// [`Budget::Unlimited`] lifts the limit).
    pub memory_budget: Budget,
    /// Called when memory pressure starts and ends (unset by default).
    pub on_memory_pressure: Option<OnMemoryPressure>,
    /// Bytes at the start of every session locator, for load-balancer
    /// stickiness; random bytes fill the rest of the 16-byte locator. At
    /// most [`MAX_INSTANCE_ID_LEN`] bytes (empty by default).
    pub instance_id: Vec<u8>,
    /// The intermediaries whose report of a carrier's client address the
    /// listener's adapters take as the carrier's source: the PROXY
    /// protocol on TCP connections, a forwarding header field on HTTP
    /// carriers (none by default).
    pub trusted_proxies: super::trusted::TrustedProxies,
    /// The admission of every new carrier, at every entry of the listener
    /// (its byte-stream, HTTP, WebSocket, WebTransport and QUIC adapters,
    /// and [`crate::Listener::handle_pipe`] for joins and resumptions as
    /// for new sessions): read its prefix, decide, act on the decision
    /// (none by default: every carrier is accepted).
    pub admission: Option<super::admission::Admission>,
    /// Where byte-stream carriers (TCP, TLS, Unix) that the admission
    /// decided on with [`crate::Verdict::Fallback`] go, every byte read
    /// replayed in front; without one they are stalled. HTTP and QUIC
    /// carriers have the fallback of their adapter's options. It never
    /// decides whether the admission runs.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub fallback: Option<crate::driver::admission::Fallback>,
    /// The inbound transform every carrier passes through after its
    /// admission and before its first record is read (none by default):
    /// [`crate::InboundTransform`].
    #[cfg(all(feature = "tokio", not(loom)))]
    pub inbound_transform: Option<crate::driver::transform::InboundTransform>,
    /// Decides the response to an unauthenticated carrier: an unknown Locator, a failed
    /// Hello, an Establish a transform refused. Unset is
    /// [`RejectAction::default_for`]: an Establish refused before
    /// authentication is stalled, a Join closed. No verdict sends anything.
    pub on_reject: Option<OnReject>,
    /// Chooses the [`Config`](crate::Config) of each new session (not of a
    /// join); unset, the listener's.
    pub session_config: Option<SessionConfigFn>,
    /// The listener's logger (unset: nothing is logged): failures of its
    /// host callbacks that it contains. Its sessions log through their own
    /// [`Config::logger`](crate::Config#structfield.logger).
    pub logger: Option<crate::proto::session::Logger>,
}

/// What [`ListenerConfig::on_reject`] knows of a refused carrier.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RejectInfo {
    /// The Profile, 2 for a Join; `None` when the first bytes named none.
    pub profile: Option<u64>,
    /// The record mode the carrier asked for, when it named one.
    pub mode: Option<crate::proto::seal::Mode>,
    /// The reason: a secure-carrier error class, or `unknown_locator`.
    pub reason: &'static str,
    /// The carrier's source.
    pub source: Option<std::net::SocketAddr>,
}

impl RejectInfo {
    /// A refusal for `reason`.
    pub fn new(
        profile: Option<u64>,
        mode: Option<crate::proto::seal::Mode>,
        reason: &'static str,
        source: Option<std::net::SocketAddr>,
    ) -> Self {
        Self {
            profile,
            mode,
            reason,
            source,
        }
    }
}

/// The error of a transform that refused a carrier before authentication: it goes to
/// [`ListenerConfig::on_reject`], inside an `io::Error`, and nothing is ever sent for it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RejectError {
    /// The Profile, when the first bytes named one.
    pub profile: Option<u64>,
    /// The record mode, when they named one.
    pub mode: Option<crate::proto::seal::Mode>,
    /// The reason: `profile_disabled`, `unknown_handle`, `auth`,
    /// `binding_unavailable`, `record_mode`, `early_data`, `gate_error`, or another error
    /// class of the secure carrier. Every reason gets the same response: no byte, and the
    /// reject policy's way of ending.
    pub reason: &'static str,
    /// The underlying error, such as a gate's ([`std::error::Error::source`]).
    pub err: Option<std::sync::Arc<dyn std::error::Error + Send + Sync>>,
}

impl RejectError {
    /// A refusal for `reason`.
    pub fn new(
        profile: Option<u64>,
        mode: Option<crate::proto::seal::Mode>,
        reason: &'static str,
    ) -> Self {
        Self {
            profile,
            mode,
            reason,
            err: None,
        }
    }

    /// With the underlying error.
    #[must_use]
    pub fn with_source(mut self, err: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.err = Some(std::sync::Arc::new(err));
        self
    }
}

impl std::fmt::Display for RejectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "carrier refused: {}", self.reason)
    }
}

impl std::error::Error for RejectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.err
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// A [`RejectError`] with the refused carrier handed back, inside an `io::Error`: the
/// listener keeps the carrier open while it stalls it ([`RejectAction::Stall`]), since a
/// carrier the transform dropped is closed at once. `P` is the driver's carrier type.
pub struct Refused<P> {
    /// The refusal.
    pub error: RejectError,
    carrier: std::sync::Mutex<Option<P>>,
}

impl<P: Send + 'static> Refused<P> {
    /// The refusal of `carrier`, as an `io::Error`.
    pub fn error(error: RejectError, carrier: P) -> std::io::Error {
        std::io::Error::other(Self {
            error,
            carrier: std::sync::Mutex::new(Some(carrier)),
        })
    }

    /// The carrier, once.
    pub fn take_carrier(&self) -> Option<P> {
        self.carrier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

impl<P> std::fmt::Debug for Refused<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Refused")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<P> std::fmt::Display for Refused<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl<P> std::error::Error for Refused<P> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.error)
    }
}

/// The answer of [`ListenerConfig::on_reject`]. Without one, an Establish
/// refused before authentication is stalled, and a Join and every other
/// refusal closed ([`RejectAction::default_for`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectAction {
    /// Close the carrier.
    Close,
    /// Keep the carrier without a byte, holding its source slot: a Join
    /// until the join timeout, an Establish until the handshake timeout
    /// and never beyond the listener's maximum stall duration. A source
    /// that holds its maximum of stalled carriers has it closed at once
    /// (`stall_overflow`).
    Stall,
}

impl RejectAction {
    /// The answer without [`ListenerConfig::on_reject`]: `Stall` for an
    /// Establish (a Profile other than 2), `Close` for a Join and for a
    /// refusal that named no Profile.
    pub fn default_for(info: &RejectInfo) -> Self {
        match info.profile {
            Some(p) if p != 2 => Self::Stall,
            _ => Self::Close,
        }
    }
}

/// The function of [`ListenerConfig::on_reject`].
#[derive(Clone)]
pub struct OnReject(pub std::sync::Arc<dyn Fn(&RejectInfo) -> RejectAction + Send + Sync>);

impl OnReject {
    /// What the policy chooses for `info`; one that panics closes the carrier.
    #[cfg(all(not(loom), any(feature = "tokio", feature = "blocking")))]
    pub(crate) fn ask(
        &self,
        info: &RejectInfo,
        logger: Option<&crate::proto::session::Logger>,
    ) -> RejectAction {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.0)(info))).unwrap_or_else(
            |_| {
                if let Some(l) = logger {
                    l.log(
                        crate::proto::session::LogLevel::Error,
                        "zmux: on_reject panicked; the carrier is closed",
                    );
                }
                RejectAction::Close
            },
        )
    }
}

impl std::fmt::Debug for OnReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnReject(..)")
    }
}

/// What [`ListenerConfig::session_config`] knows of a carrier that starts a
/// session.
#[derive(Debug)]
#[non_exhaustive]
pub struct SessionCarrier<'a> {
    /// The carrier's source, as the admission saw it.
    pub source: Option<std::net::SocketAddr>,
    /// The directly connected peer.
    pub peer: Option<std::net::SocketAddr>,
    /// The TLS or QUIC handshake this process terminated for the carrier.
    pub tls: Option<&'a crate::proto::exporter::TlsState>,
    /// The value of the admission that accepted the carrier.
    pub admitted: Option<&'a crate::proto::admission::AdmittedValue>,
}

/// The function of [`ListenerConfig::session_config`].
///
/// It runs once for every carrier that starts a new session, outside every
/// lock, and returns the session's configuration, such as an exporter where
/// TLS ends here and a deferred key where it ends at an intermediary, or
/// per-session shaping limits; `Ok(None)` selects the listener's. Joins to
/// the session verify with its own configuration. Settings of the listener
/// as a whole stay the listener's: its memory budget and the bounds at the
/// carrier level use the listener's configuration. A configuration invalid
/// for a server session, an error and a panic close the carrier without a
/// byte, counted as rejected.
#[derive(Clone)]
pub struct SessionConfigFn(pub std::sync::Arc<SessionConfigDyn>);

/// The callable behind a [`SessionConfigFn`].
pub type SessionConfigDyn =
    dyn Fn(&SessionCarrier<'_>) -> Result<Option<crate::Config>, String> + Send + Sync;

impl SessionConfigFn {
    /// Wraps `f`.
    pub fn new(
        f: impl Fn(&SessionCarrier<'_>) -> Result<Option<crate::Config>, String> + Send + Sync + 'static,
    ) -> Self {
        Self(std::sync::Arc::new(f))
    }

    /// Runs the function for `carrier`: `Ok(None)` selects the listener's
    /// configuration; an error, a panic or a configuration invalid for a
    /// session is logged to the listener's `logger` and returns `Err`.
    #[cfg(all(not(loom), any(feature = "tokio", feature = "blocking")))]
    pub(crate) fn choose(
        &self,
        carrier: &SessionCarrier<'_>,
        logger: Option<&crate::proto::session::Logger>,
    ) -> Result<Option<crate::Config>, ()> {
        let why = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.0)(carrier)))
        {
            Ok(Ok(None)) => return Ok(None),
            Ok(Ok(Some(c))) => match c.validate() {
                Ok(()) => return Ok(Some(c)),
                Err(e) => format!("returned an invalid configuration ({e})"),
            },
            Ok(Err(e)) => format!("failed: {e}"),
            Err(_) => "panicked; the panic was contained".to_string(),
        };
        if let Some(l) = logger {
            l.log(
                crate::proto::session::LogLevel::Warn,
                &format!("zmux: session_config {why}; the carrier is closed"),
            );
        }
        Err(())
    }
}

impl std::fmt::Debug for SessionConfigFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionConfigFn(..)")
    }
}

/// The longest Hello a listener holds on a byte stream: its limit, independent of
/// `max_record_size`.
pub const MAX_HELLO: usize = 2 + 8 + 1 + 1 + 255 + 64 + 2 + 65_535;

/// The longest [`ListenerConfig::instance_id`], so that at least 8 random
/// bytes remain in the 16-byte session locator.
pub const MAX_INSTANCE_ID_LEN: usize = 8;

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            max_pending: 64,
            max_pending_per_source: 8,
            max_pending_per_session: 4,
            first_record_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(10),
            max_record_size: 65535,
            accept_sessions: true,
            max_suspended: 1024,
            memory_budget: Budget::Bytes(super::session::DEFAULT_MEMORY_BUDGET),
            on_memory_pressure: None,
            instance_id: Vec::new(),
            trusted_proxies: super::trusted::TrustedProxies::new(),
            admission: None,
            #[cfg(all(feature = "tokio", not(loom)))]
            fallback: None,
            #[cfg(all(feature = "tokio", not(loom)))]
            inbound_transform: None,
            on_reject: None,
            session_config: None,
            logger: None,
        }
    }
}

/// A carrier the listener tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CarrierId(pub u64);

/// The result of opening a carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// Tracked; `evicted` is the oldest pending carrier that made room and
    /// must be closed.
    Accepted {
        /// The new carrier.
        id: CarrierId,
        /// A carrier to close.
        evicted: Option<CarrierId>,
    },
    /// The source has too many pending carriers: close it.
    Refused,
}

/// What a carrier turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// More bytes are needed.
    NeedMore,
    /// Close the carrier without writing anything.
    Reject,
    /// A new session: create it and feed it `first`, the bytes so far.
    NewSession {
        /// The bytes received so far.
        first: Vec<u8>,
    },
    /// A lane: route it by `lane_key` over the sessions (comparing in
    /// constant time), check that the pipe's lane 0 is on the stream's
    /// connection, and offer it to the session
    /// ([`crate::proto::session::SessionCore::accept_lane`]); once it is
    /// accepted, feed `bytes`, the stream's bytes so far, to that lane.
    Lane {
        /// The Lane Key it carries.
        lane_key: [u8; LANE_KEY_LEN],
        /// The pipe it names.
        pipe: u64,
        /// Its lane number.
        lane: u64,
        /// The stream's bytes so far.
        bytes: Vec<u8>,
    },
    /// A Join whose Hello does not parse: an unauthenticated rejection, given the
    /// listener's reject policy (closed or stalled, nothing written) like an unknown
    /// Locator. The carrier stays pending until [`ListenerCore::done`].
    BadHello {
        /// The class of the parse failure.
        reason: &'static str,
    },
    /// A Join: find the session whose locator is `locator` and offer it `hello`
    /// ([`JoinHello::parse`]).
    Join {
        /// The Session Locator.
        locator: Vec<u8>,
        /// The whole Hello.
        hello: Vec<u8>,
    },
}

/// The result of pairing a split-bootstrap carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paired {
    /// The first carrier with this token: wait for the other.
    Waiting,
    /// Both carriers are here.
    Complete(CarrierId),
    /// A third carrier with the token, or the same direction twice: close.
    Reject,
}

#[derive(Debug)]
struct Pending {
    id: CarrierId,
    source: u64,
    opened: Instant,
    framing: Framing,
    classifier: Classifier,
    buf: Vec<u8>,
    /// The first record or Hello arrived.
    first: bool,
    /// The session's locator once a verified Hello made it Unconfirmed, with the order in
    /// which carriers became Unconfirmed.
    unconfirmed: Option<(Vec<u8>, u64)>,
    /// A new stream of a connection that already carries a pipe of the
    /// endpoint: not an unauthenticated carrier (the connection's stream
    /// credit bounds them), so outside the source and pending limits, and
    /// only the first-record timeout applies.
    stream: bool,
}

/// A sans-IO listener.
#[derive(Debug)]
pub struct ListenerCore {
    config: ListenerConfig,
    next: u64,
    /// Pending carriers, oldest first.
    pending: VecDeque<Pending>,
    /// Split-bootstrap pairing: token -> (carrier, inbound half?, opened).
    pairs: HashMap<[u8; PAIRING_TOKEN_LEN], (CarrierId, bool, Instant, bool)>,
    /// Source slots held per source ([`ListenerCore::hold`]).
    held: HashMap<u64, usize>,
    /// Stalled carriers by source, a subset of `held`
    /// ([`ListenerCore::stall`]).
    stalled: HashMap<u64, usize>,
    /// The order of the next carrier to become Unconfirmed.
    unconfirmed_seq: u64,
}

/// A source key from a remote address, aggregated to /64 for IPv6; an
/// IPv4-mapped address (a dual-stack socket's IPv4 client) counts as
/// its IPv4 address: the key
/// [`ListenerCore::hold`] and [`ListenerCore::stall`] take.
pub fn source_key(addr: std::net::IpAddr) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match addr.to_canonical() {
        std::net::IpAddr::V4(a) => a.octets().hash(&mut h),
        std::net::IpAddr::V6(a) => a.octets()[..8].hash(&mut h),
    }
    h.finish()
}

/// A source key from an opaque name.
pub fn source_name(name: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    h.finish()
}

impl ListenerCore {
    /// A listener with these limits.
    pub fn new(config: ListenerConfig) -> Self {
        Self {
            config,
            next: 1,
            pending: VecDeque::new(),
            pairs: HashMap::new(),
            held: HashMap::new(),
            stalled: HashMap::new(),
            unconfirmed_seq: 0,
        }
    }

    /// The limits.
    pub fn config(&self) -> &ListenerConfig {
        &self.config
    }

    /// Carriers pending.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// A new stream that the peer opened on a connection that carries lane
    /// 0 of an open inbound pipe of the endpoint, within the streams such
    /// pipes let wait for their first record unlimited (which the caller
    /// counts): its first record may begin a lane, which takes no slot;
    /// one that turns out a join or a new session takes a slot then
    /// ([`ListenerCore::admit`]).
    pub fn open_stream(&mut self, framing: Framing, now: Instant) -> CarrierId {
        let id = CarrierId(self.next);
        self.next += 1;
        self.pending.push_back(Pending {
            id,
            source: 0,
            opened: now,
            framing,
            classifier: Classifier::new(
                self.config.max_record_size,
                self.config.accept_sessions,
                true,
            )
            .with_lanes(),
            buf: Vec::new(),
            first: false,
            unconfirmed: None,
            stream: true,
        });
        id
    }

    /// A new carrier from `source`.
    pub fn open(&mut self, source: u64, framing: Framing, now: Instant) -> Opened {
        let evicted = match self.make_slot(source) {
            Ok(evicted) => evicted,
            Err(()) => return Opened::Refused,
        };
        self.push(source, framing, now, evicted)
    }

    /// A new carrier from `source` that holds a source slot
    /// ([`ListenerCore::hold`]): the slot becomes its pending slot, so the
    /// source's limit does not refuse it; the oldest pending carrier is
    /// evicted when all pending slots are taken.
    pub fn open_held(&mut self, source: u64, framing: Framing, now: Instant) -> Opened {
        self.release(source);
        let carriers = self.pending.iter().filter(|p| !p.stream).count();
        let evicted = if carriers >= self.config.max_pending
            && let Some(i) = self.pending.iter().position(|p| !p.stream)
        {
            self.pending.remove(i).map(|p| p.id)
        } else {
            None
        };
        self.push(source, framing, now, evicted)
    }

    fn push(
        &mut self,
        source: u64,
        framing: Framing,
        now: Instant,
        evicted: Option<CarrierId>,
    ) -> Opened {
        let id = CarrierId(self.next);
        self.next += 1;
        self.pending.push_back(Pending {
            id,
            source,
            opened: now,
            framing,
            classifier: Classifier::new(
                self.config.max_record_size,
                self.config.accept_sessions,
                true,
            ),
            buf: Vec::new(),
            first: false,
            unconfirmed: None,
            stream: false,
        });
        Opened::Accepted { id, evicted }
    }

    /// A slot for a carrier from `source`: refused when the source has
    /// its share, else the oldest pending carrier evicted when all are
    /// taken.
    fn make_slot(&mut self, source: u64) -> Result<Option<CarrierId>, ()> {
        if self.per_source(source) >= self.config.max_pending_per_source {
            return Err(());
        }
        let carriers = || self.pending.iter().filter(|p| !p.stream);
        if carriers().count() >= self.config.max_pending
            && let Some(i) = self.pending.iter().position(|p| !p.stream)
        {
            return Ok(self.pending.remove(i).map(|p| p.id));
        }
        Ok(None)
    }

    /// The carriers that count against the per-source limit of `source`:
    /// its pending carriers and its held source slots.
    fn per_source(&self, source: u64) -> usize {
        let pending = self
            .pending
            .iter()
            .filter(|p| !p.stream && p.source == source)
            .count();
        pending + self.held.get(&source).copied().unwrap_or(0)
    }

    /// A source slot for a carrier from `source` that entered the
    /// listener and is not pending yet (in its outer handshake, under
    /// admission, or stalled): it counts against the source's limit of
    /// pending carriers until [`ListenerCore::release`] or
    /// [`ListenerCore::open_held`], without a pending slot (it is neither
    /// evicted nor timed out). `false` when the source has its share:
    /// close the carrier.
    pub fn hold(&mut self, source: u64) -> bool {
        if self.per_source(source) >= self.config.max_pending_per_source {
            return false;
        }
        *self.held.entry(source).or_default() += 1;
        true
    }

    /// A slot [`ListenerCore::hold`] counted is given back.
    pub fn release(&mut self, source: u64) {
        if let Some(n) = self.held.get_mut(&source) {
            *n -= 1;
            if *n == 0 {
                self.held.remove(&source);
            }
        }
    }

    /// A carrier from `source` holding a source slot starts to stall:
    /// `false` when the source already has `max_pending_per_source - 1`
    /// stalled carriers, so that it always keeps a slot for a new attempt;
    /// close the carrier at once. Until [`ListenerCore::unstall`].
    pub fn stall(&mut self, source: u64) -> bool {
        let n = self.stalled.entry(source).or_default();
        if *n + 1 >= self.config.max_pending_per_source {
            if *n == 0 {
                self.stalled.remove(&source);
            }
            return false;
        }
        *n += 1;
        true
    }

    /// The carriers of `source` counted against its pending limit now.
    #[cfg(test)]
    pub(crate) fn pending_of(&self, source: u64) -> usize {
        self.per_source(source)
    }

    /// The carriers of `source` stalled now.
    #[cfg(test)]
    pub(crate) fn stalled(&self, source: u64) -> usize {
        self.stalled.get(&source).copied().unwrap_or(0)
    }

    /// A stall [`ListenerCore::stall`] counted ended.
    pub fn unstall(&mut self, source: u64) {
        if let Some(n) = self.stalled.get_mut(&source) {
            *n -= 1;
            if *n == 0 {
                self.stalled.remove(&source);
            }
        }
    }

    /// A stream opened by [`ListenerCore::open_stream`] turned out a join or a
    /// new session: it takes a slot from `source` now, like any carrier.
    /// `Refused`: close it.
    pub fn admit(&mut self, id: CarrierId, source: u64) -> Opened {
        if self.find(id).is_none() {
            return Opened::Refused;
        }
        let evicted = match self.make_slot(source) {
            Ok(evicted) => evicted,
            Err(()) => return Opened::Refused,
        };
        if let Some(i) = self.find(id) {
            let p = &mut self.pending[i];
            p.stream = false;
            p.source = source;
        }
        Opened::Accepted { id, evicted }
    }

    fn find(&mut self, id: CarrierId) -> Option<usize> {
        self.pending.iter().position(|p| p.id == id)
    }

    /// Bytes from a byte-stream carrier.
    pub fn data(&mut self, id: CarrierId, bytes: &[u8], now: Instant) -> Classified {
        let _ = now;
        let max_hold = (self.config.max_record_size as usize + 8).max(MAX_HELLO);
        let Some(i) = self.find(id) else {
            return Classified::Reject;
        };
        let p = &mut self.pending[i];
        let start = p.buf.len();
        p.buf.extend_from_slice(bytes);
        let verdict = if p.classifier.verdict() == Verdict::NeedMore {
            p.classifier.push(&p.buf[start..])
        } else {
            p.classifier.verdict()
        };
        match verdict {
            Verdict::NeedMore => {
                if p.buf.len() > max_hold {
                    self.done(id);
                    return Classified::Reject;
                }
                Classified::NeedMore
            }
            Verdict::Reject { .. } => {
                self.done(id);
                Classified::Reject
            }
            Verdict::Accept(FirstRecord::Session) => {
                let first = std::mem::take(&mut self.pending[i].buf);
                self.done(id);
                Classified::NewSession { first }
            }
            Verdict::Accept(FirstRecord::Lane) => {
                let c = lane_record(&mut p.buf);
                if c != Classified::NeedMore {
                    self.done(id);
                }
                c
            }
            Verdict::Accept(FirstRecord::Join) => match JoinHello::parse(p.framing, &p.buf) {
                Err(SealError::Incomplete { .. }) if p.buf.len() <= MAX_HELLO => {
                    Classified::NeedMore
                }
                Ok(h) => {
                    let locator = h.locator().to_vec();
                    p.first = true;
                    Classified::Join {
                        locator,
                        hello: std::mem::take(&mut p.buf),
                    }
                }
                Err(_) => Classified::BadHello {
                    reason: "malformed",
                },
            },
        }
    }

    /// One message from a message-framed carrier.
    pub fn message(&mut self, id: CarrierId, message: &[u8], now: Instant) -> Classified {
        let _ = now;
        let Some(i) = self.find(id) else {
            return Classified::Reject;
        };
        let p = &mut self.pending[i];
        if p.first {
            // Later messages before the join is decided.
            if p.buf.len() + message.len() > self.config.max_record_size as usize * 2 {
                self.done(id);
                return Classified::Reject;
            }
            p.buf.extend_from_slice(message);
            return Classified::NeedMore;
        }
        match p.classifier.message(message) {
            Verdict::Accept(FirstRecord::Session) => {
                let first = message.to_vec();
                self.done(id);
                Classified::NewSession { first }
            }
            Verdict::Accept(FirstRecord::Lane) => {
                self.done(id);
                lane_message(message)
            }
            Verdict::Accept(FirstRecord::Join) => match JoinHello::parse(p.framing, message) {
                Ok(h) => {
                    let locator = h.locator().to_vec();
                    p.first = true;
                    Classified::Join {
                        locator,
                        hello: message.to_vec(),
                    }
                }
                Err(_) => Classified::BadHello {
                    reason: "malformed",
                },
            },
            _ => {
                self.done(id);
                Classified::Reject
            }
        }
    }

    /// A verified Hello of the session named `locator` is Unconfirmed: beyond the session's
    /// limit, the carrier that became Unconfirmed first, never this one, is evicted rather
    /// than the new Hello refused. Returns the carrier to close.
    pub fn unconfirmed(&mut self, id: CarrierId, locator: &[u8]) -> Option<CarrierId> {
        let i = self.find(id)?;
        let seq = self.unconfirmed_seq;
        self.unconfirmed_seq += 1;
        self.pending[i].unconfirmed = Some((locator.to_vec(), seq));
        let of = |p: &Pending| {
            p.unconfirmed
                .as_ref()
                .filter(|(l, _)| l.as_slice() == locator)
                .map(|&(_, seq)| seq)
        };
        if self.pending.iter().filter_map(of).count() <= self.config.max_pending_per_session {
            return None;
        }
        let (i, _) = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, p)| p.id != id)
            .filter_map(|(i, p)| of(p).map(|seq| (i, seq)))
            .min_by_key(|&(_, seq)| seq)?;
        self.pending.remove(i).map(|p| p.id)
    }

    /// The carrier left the listener (attached, rejected or closed).
    pub fn done(&mut self, id: CarrierId) {
        if let Some(i) = self.find(id) {
            self.pending.remove(i);
        }
    }

    /// The bytes held for a carrier that waits for its session.
    pub fn held_bytes(&self, id: CarrierId) -> &[u8] {
        self.pending
            .iter()
            .find(|p| p.id == id)
            .map_or(&[], |p| &p.buf)
    }

    /// The framing of a pending carrier.
    pub fn framing(&self, id: CarrierId) -> Option<Framing> {
        self.pending.iter().find(|p| p.id == id).map(|p| p.framing)
    }

    /// What an inbound transform made of the carrier's framing, before its first record.
    pub fn set_framing(&mut self, id: CarrierId, framing: Framing) {
        if let Some(i) = self.find(id) {
            self.pending[i].framing = framing;
        }
    }

    /// Pairs a split-bootstrap carrier by its token; `inbound` is the half the carrier gives the
    /// local endpoint.
    pub fn pair(
        &mut self,
        token: [u8; PAIRING_TOKEN_LEN],
        id: CarrierId,
        inbound: bool,
        now: Instant,
    ) -> Paired {
        // Entries older than the handshake timeout are gone: their halves
        // gave up.
        let limit = self.config.handshake_timeout;
        self.pairs
            .retain(|_, v| now.saturating_duration_since(v.2) < limit);
        match self.pairs.get_mut(&token) {
            None => {
                if self.pairs.len() >= self.config.max_pending {
                    // Drop the oldest entry: the table stays bounded.
                    if let Some(old) = self.pairs.iter().min_by_key(|(_, v)| v.2).map(|(k, _)| *k) {
                        self.pairs.remove(&old);
                    }
                }
                self.pairs.insert(token, (id, inbound, now, false));
                Paired::Waiting
            }
            Some(entry) if !entry.3 && entry.1 != inbound => {
                entry.3 = true;
                Paired::Complete(entry.0)
            }
            Some(_) => Paired::Reject,
        }
    }

    /// Forgets the pairing of `token` the half `id` began: the half gave up, so the token
    /// starts a new pairing.
    pub fn unpair(&mut self, token: &[u8; PAIRING_TOKEN_LEN], id: CarrierId) {
        if self.pairs.get(token).is_some_and(|v| v.0 == id) {
            self.pairs.remove(token);
        }
    }

    /// The next timeout.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.pending
            .iter()
            .filter_map(|p| {
                // A deadline beyond the clock's range never comes.
                p.opened.checked_add(if p.first {
                    self.config.handshake_timeout
                } else {
                    self.config.first_record_timeout
                })
            })
            .min()
    }

    /// Carriers whose first-record or handshake timeout expired: close
    /// them.
    pub fn expired(&mut self, now: Instant) -> Vec<CarrierId> {
        let first_timeout = self.config.first_record_timeout;
        let handshake = self.config.handshake_timeout;
        let mut out = Vec::new();
        self.pending.retain(|p| {
            let limit = if p.first { handshake } else { first_timeout };
            if p.opened.checked_add(limit).is_some_and(|t| now >= t) {
                out.push(p.id);
                false
            } else {
                true
            }
        });
        let pairs_limit = handshake;
        self.pairs
            .retain(|_, v| now.saturating_duration_since(v.2) < pairs_limit);
        out
    }
}

/// The PIPE_LANE that begins the first record held in `buf` (byte-stream
/// framing), once it decodes: the lane, with the bytes (taken), or a
/// rejection when the record holds no valid PIPE_LANE first.
fn lane_record(buf: &mut Vec<u8>) -> Classified {
    let Some((size, width)) = varint::decode(buf) else {
        return Classified::NeedMore;
    };
    let body = &buf[width..];
    let have = body.len().min(usize::try_from(size).unwrap_or(usize::MAX));
    match PipeLane::decode(&body[..have]) {
        Ok((f, _)) => Classified::Lane {
            lane_key: f.lane_key,
            pipe: f.pipe_id,
            lane: f.lane,
            bytes: std::mem::take(buf),
        },
        Err(_) if (have as u64) < size => Classified::NeedMore,
        Err(_) => Classified::Reject,
    }
}

/// The PIPE_LANE that begins the first message of a message-framed
/// stream.
fn lane_message(message: &[u8]) -> Classified {
    match PipeLane::decode(message) {
        Ok((f, _)) => Classified::Lane {
            lane_key: f.lane_key,
            pipe: f.pipe_id,
            lane: f.lane,
            bytes: message.to_vec(),
        },
        Err(_) => Classified::Reject,
    }
}

/// The first record of a new stream of a connection that already carries a
/// pipe of the endpoint, checked for a lane without a listener: an
/// endpoint whose adapter hands such streams to its sessions directly
/// classifies them the same way. It decides within the first record; only
/// a lane is accepted.
#[derive(Debug, Clone)]
pub struct LaneProbe {
    classifier: Classifier,
    framing: Framing,
    buf: Vec<u8>,
}

impl LaneProbe {
    /// A probe for a stream with `framing`; `max_record_size` is the
    /// receiver's own limit.
    pub const fn new(max_record_size: u64, framing: Framing) -> Self {
        Self {
            classifier: Classifier::new(max_record_size, false, false).with_lanes(),
            framing,
            buf: Vec::new(),
        }
    }

    /// Bytes of a byte-stream carrier: [`Classified::NeedMore`],
    /// [`Classified::Reject`] or [`Classified::Lane`].
    pub fn data(&mut self, bytes: &[u8]) -> Classified {
        if self.framing == Framing::Records {
            return self.message(bytes);
        }
        let start = self.buf.len();
        self.buf.extend_from_slice(bytes);
        let verdict = match self.classifier.verdict() {
            Verdict::NeedMore => self.classifier.push(&self.buf[start..]),
            v => v,
        };
        match verdict {
            Verdict::NeedMore => Classified::NeedMore,
            Verdict::Accept(FirstRecord::Lane) => lane_record(&mut self.buf),
            _ => Classified::Reject,
        }
    }

    /// The first message of a message-framed carrier.
    pub fn message(&mut self, message: &[u8]) -> Classified {
        match self.classifier.message(message) {
            Verdict::Accept(FirstRecord::Lane) => lane_message(message),
            _ => Classified::Reject,
        }
    }
}

/// The memory budget of a listener's sessions: above
/// the budget sessions behave as if at their buffer cap; normal operation
/// resumes below three quarters of it.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryBudget {
    budget: Option<u64>,
    pressure: bool,
}

impl MemoryBudget {
    /// A budget of `bytes`; `None` is unlimited.
    pub fn new(bytes: Option<u64>) -> Self {
        Self {
            budget: bytes,
            pressure: false,
        }
    }

    /// Updates with the bytes the sessions hold; returns the new pressure
    /// state when it changed.
    pub fn update(&mut self, used: u64) -> Option<bool> {
        let budget = self.budget?;
        let next = if self.pressure {
            used >= budget / 4 * 3
        } else {
            used > budget
        };
        (next != self.pressure).then(|| {
            self.pressure = next;
            next
        })
    }

    /// Whether the sessions are above the budget.
    pub fn pressure(&self) -> bool {
        self.pressure
    }
}

/// What the listener's admission ([`crate::ListenerConfig::admission`])
/// decided ([`ListenerStats::admission`]): counts since the listener was
/// made, each carrier that took a source slot counted once its outcome is
/// known, all 0 without an admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmissionStats {
    /// Decided with [`crate::Verdict::Accept`]; each then counts once more as a
    /// pipe input in the other fields of [`ListenerStats`].
    pub accepted: u64,
    /// Decided with [`crate::Verdict::Fallback`] (stalled without a fallback
    /// target, still counted here).
    pub fallback: u64,
    /// Decided with [`crate::Verdict::Stall`], counted when the stall starts.
    pub stalled: u64,
    /// Decided with [`crate::Verdict::Close`], an `Accept` beyond the prefix, a
    /// decision that panicked, or one cancelled because the listener
    /// closed.
    pub closed: u64,
    /// Decided with [`crate::Verdict::Stall`] when the listener could not stall
    /// it: its source already stalled `max_pending_per_source - 1`
    /// carriers ([`ListenerConfig::max_pending_per_source`]), or the
    /// listener closed meanwhile. Closed at once.
    pub stall_overflow: u64,
    /// The decision did not come before the end of the peek timeout.
    pub peek_timed_out: u64,
    /// The outer handshake (TLS, an HTTP upgrade, QUIC) failed or timed
    /// out: never decided on. Not counted in
    /// [`ListenerStats::setup_failures`].
    pub handshake_failed: u64,
}

/// What happened to the pipe inputs handed to a listener
/// ([`crate::Listener::stats`]): counts since it was made.
///
/// The unit is the pipe input: a carrier, a lane, or the two carriers of a
/// split pipe once paired (a half never paired is an input of its own).
/// Every input whose outcome is known is counted once, in one of
/// `sessions`, `joins`, `rejected`, `refused` and `timed_out`;
/// `setup_failures` counts connections that never became an input, and
/// `admission` what the listener's admission decided on carriers before
/// they became inputs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListenerStats {
    /// Sessions started: bootstraps offered to [`crate::Listener::accept`], a
    /// split bootstrap once.
    pub sessions: u64,
    /// Joins accepted into existing sessions, and lanes accepted into
    /// their pipes.
    pub joins: u64,
    /// Connections never made a pipe input: a failed TLS handshake or its
    /// timeout (also the handshake a join sent in early data waits for), a
    /// failed HTTP or WebSocket upgrade, or the setup limit
    /// ([`crate::Listener::count_setup_failure`]). With an admission, a carrier's
    /// failed outer handshake counts in [`AdmissionStats::handshake_failed`]
    /// instead.
    pub setup_failures: u64,
    /// Inputs closed without a distinguishable reason: unknown,
    /// unauthenticated or replayed joins, lanes that name no pipe, or not
    /// zmux at all ([`HandleError::Rejected`]). An admission's decisions
    /// count in [`ListenerStats::admission`] only.
    pub rejected: u64,
    /// Inputs refused at a limit: of the listener, of its source (a
    /// carrier refused its source slot, before any handshake), of the
    /// session (a join closed with ZMUX_PIPE_RESOURCE_LIMIT), new sessions
    /// during [`crate::Listener::shutdown`], or anything after [`crate::Listener::close`]
    /// ([`HandleError::Refused`]).
    pub refused: u64,
    /// Inputs without a first record, or join, in time, and split halves
    /// whose other half did not arrive in time ([`HandleError::TimedOut`]).
    pub timed_out: u64,
    /// What the listener's admission decided.
    pub admission: AdmissionStats,
}

/// Why a carrier was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandleError {
    /// Closed without a distinguishable reason: unknown, unauthenticated
    /// or replayed, a lane that names no pipe, or not zmux at all.
    Rejected,
    /// At a limit: of the listener for this source, of the session (a
    /// join closed with ZMUX_PIPE_RESOURCE_LIMIT), or the listener closed.
    Refused,
    /// No first record (or join) in time, or a split half whose other half
    /// did not arrive in time.
    TimedOut,
    /// The carrier's setup did not complete: the handshake that a join
    /// sent in carrier early data waits for failed or timed out. Counted
    /// as a setup failure ([`ListenerStats::setup_failures`]) only.
    SetupFailed,
    /// The listener's admission did not accept the carrier: it was
    /// closed, stalled or handed to a fallback. Counted in
    /// [`ListenerStats::admission`] only.
    NotAdmitted,
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rejected => "carrier rejected",
            Self::Refused => "carrier refused",
            Self::SetupFailed => "carrier setup failed",
            Self::TimedOut => "carrier timed out",
            Self::NotAdmitted => "carrier not admitted",
        })
    }
}

impl std::error::Error for HandleError {}

/// A 16-byte session locator: `prefix`, then random bytes.
#[cfg(all(not(loom), any(feature = "tokio", feature = "blocking")))]
pub(crate) fn random_locator(prefix: &[u8]) -> Vec<u8> {
    let mut l = vec![0u8; 16];
    l[..prefix.len()].copy_from_slice(prefix);
    let rest = &mut l[prefix.len()..];
    if getrandom::fill(rest).is_err() {
        use std::hash::BuildHasher;
        let s = std::collections::hash_map::RandomState::new();
        for (i, c) in rest.chunks_mut(8).enumerate() {
            let t = s.hash_one((0x006c_6f63_6174_6f72_u64, i));
            c.copy_from_slice(&t.to_le_bytes()[..c.len()]);
        }
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_source_and_first_record_limits() {
        let mut l = ListenerCore::new(ListenerConfig::default());
        let now = Instant::now();
        let a = source_name("a");
        for _ in 0..8 {
            assert!(matches!(
                l.open(a, Framing::ByteStream, now),
                Opened::Accepted { .. }
            ));
        }
        assert_eq!(l.open(a, Framing::ByteStream, now), Opened::Refused);
        assert!(matches!(
            l.open(source_name("b"), Framing::ByteStream, now),
            Opened::Accepted { .. }
        ));
        assert!(l.expired(now + Duration::from_millis(1999)).is_empty());
        assert_eq!(l.expired(now + Duration::from_secs(2)).len(), 9);
    }

    #[test]
    fn held_slots_count_per_source() {
        let mut l = ListenerCore::new(ListenerConfig {
            max_pending_per_source: 2,
            ..ListenerConfig::default()
        });
        let now = Instant::now();
        let (a, b) = (source_name("a"), source_name("b"));
        assert!(l.hold(a));
        assert!(matches!(
            l.open(a, Framing::ByteStream, now),
            Opened::Accepted { .. }
        ));
        assert!(!l.hold(a));
        assert_eq!(l.open(a, Framing::ByteStream, now), Opened::Refused);
        assert!(l.hold(b));
        // A held slot takes no pending slot and does not expire.
        assert_eq!(l.pending(), 1);
        assert_eq!(l.expired(now + Duration::from_secs(60)).len(), 1);
        l.release(a);
        assert!(l.hold(a) && l.hold(a));
        assert!(!l.hold(a));
        // A held slot becomes the pending slot: the source's limit does not
        // refuse it.
        assert!(matches!(
            l.open_held(b, Framing::ByteStream, now),
            Opened::Accepted { .. }
        ));
        // The first expired above.
        assert_eq!(l.pending(), 1);
    }

    /// Beyond the session's limit the carrier Unconfirmed longest goes, by when it became
    /// Unconfirmed and not by when it arrived, and never the Hello that went over it.
    #[test]
    fn the_longest_unconfirmed_is_evicted() {
        let mut l = ListenerCore::new(ListenerConfig::default());
        let now = Instant::now();
        let ids: Vec<_> = (0..6)
            .map(|n| match l.open(n, Framing::ByteStream, now) {
                Opened::Accepted { id, .. } => id,
                Opened::Refused => panic!("refused"),
            })
            .collect();
        // The first to arrive is the slowest to be verified.
        for &id in &ids[1..5] {
            assert_eq!(l.unconfirmed(id, b"s"), None);
        }
        assert_eq!(l.unconfirmed(ids[0], b"s"), Some(ids[1]));
        // Another session's Unconfirmed carriers are not counted.
        assert_eq!(l.unconfirmed(ids[5], b"t"), None);
        assert_eq!(l.pending(), 5);
    }

    #[test]
    fn source_keys() {
        let ip = |s: &str| source_key(s.parse().unwrap());
        assert_eq!(ip("2001:db8:1:2::1"), ip("2001:db8:1:2:ffff::9"));
        assert_ne!(ip("2001:db8:1:2::1"), ip("2001:db8:1:3::1"));
        assert_eq!(ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
        assert_ne!(ip("::ffff:192.0.2.1"), ip("::ffff:192.0.2.2"));
    }

    #[test]
    fn garbage_is_rejected() {
        let mut l = ListenerCore::new(ListenerConfig::default());
        let now = Instant::now();
        let Opened::Accepted { id, .. } = l.open(1, Framing::ByteStream, now) else {
            panic!()
        };
        assert_eq!(l.data(id, b"GET / HTTP/1.1\r\n", now), Classified::Reject);
    }

    #[test]
    fn memory_budget_hysteresis() {
        let mut m = MemoryBudget::new(Some(1000));
        assert_eq!(m.update(900), None);
        assert_eq!(m.update(1001), Some(true));
        assert_eq!(m.update(800), None);
        assert_eq!(m.update(700), Some(false));
    }
}
