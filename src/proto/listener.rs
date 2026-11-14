//! A sans-IO listener: it classifies new carriers by their first bytes, cuts Join
//! Hellos, pairs split carriers, and bounds the carriers that are not authenticated
//! yet. It never touches session state: the driver looks up the session by locator and
//! offers the Hello to it ([`crate::proto::session::SessionCore::open_hello`]).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use crate::proto::frame::{LANE_KEY_LEN, PipeLane};
use crate::proto::ident::{Classifier, FirstRecord, Verdict};
use crate::proto::oob::PAIRING_TOKEN_LEN;
use crate::proto::record::Framing;
use crate::proto::seal::Error as SealError;
use crate::proto::seal::join::JoinHello;
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
// Called by the tokio listener only.
#[cfg_attr(not(all(feature = "tokio", not(loom))), allow(dead_code))]
#[derive(Clone)]
pub struct OnMemoryPressure(pub(crate) std::sync::Arc<dyn Fn(MemoryPressure) + Send + Sync>);

impl OnMemoryPressure {
    /// The hook calling `f`.
    pub fn new(f: impl Fn(MemoryPressure) + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(f))
    }
}

impl std::fmt::Debug for OnMemoryPressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnMemoryPressure(..)")
    }
}

/// Listener limits.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ListenerConfig {
    /// The listener's bound on carriers before they belong to a session
    /// (default [`DEFAULT_MAX_PENDING`]; `None` is unlimited): a carrier
    /// holds one of these slots with its source slot, from the moment it
    /// is taken, through its outer handshake, admission, inbound
    /// transform, a split half's wait for its pair, classification,
    /// verification and a new session's transport parameters, and through
    /// a stall, until it enters a session or is closed. A new carrier that
    /// finds every slot taken closes the oldest stalled carrier to take
    /// its slot, or is closed at once (counted as rejected) when none is
    /// stalled. Stalled carriers hold at most half of the slots (rounded
    /// down, so that with one slot no carrier stalls: a Stall then closes
    /// it at once, as `stall_overflow`).
    pub max_pending: Option<usize>,
    /// Carriers before a session per source (default 8; a source counted
    /// by its prefix, [`ListenerConfig::source_prefix_v4`] and
    /// [`ListenerConfig::source_prefix_v6`]), held as
    /// [`ListenerConfig::max_pending`] says. A source stalls at most one
    /// fewer, so that it always keeps a slot for a new attempt. At least 2,
    /// since a split bootstrap holds two slots and an exchange carrier's
    /// further requests compete with the request that created it.
    pub max_pending_per_source: usize,
    /// The prefix an IPv4 source is counted by: its first this many bits
    /// (default 32, the address on its own; 1 to 32, another value being
    /// the configuration error). An IPv4-mapped IPv6 address counts as
    /// IPv4, and ports are ignored. This one aggregation serves everything
    /// the listener keeps per source, and nothing else: the per-source
    /// bound, the count of a source's stalled carriers, the stall duration
    /// and so the limit on failed join verifications, which hold source
    /// slots. A shorter prefix groups more clients into one share, which
    /// tightens the bound against one network and also lets its clients
    /// crowd each other out; the defaults suit public listeners.
    pub source_prefix_v4: u8,
    /// The prefix an IPv6 source is counted by: its first this many bits
    /// (default 64; 1 to 128, another value being the configuration
    /// error), as [`ListenerConfig::source_prefix_v4`] says.
    pub source_prefix_v6: u8,
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
    /// Bytes the sessions may hold together (default 1 GiB; `None` is
    /// unlimited).
    pub memory_budget: Option<u64>,
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
    /// decided on with [`crate::AdmissionVerdict::Fallback`] go, every byte read
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
    pub record_mode: Option<crate::proto::seal::RecordMode>,
    /// The reason: a secure-carrier error class, or `unknown_locator`.
    pub reason: &'static str,
    /// The carrier's source.
    pub source: Option<std::net::SocketAddr>,
}

impl RejectInfo {
    /// A refusal for `reason`.
    pub fn new(
        profile: Option<u64>,
        record_mode: Option<crate::proto::seal::RecordMode>,
        reason: &'static str,
        source: Option<std::net::SocketAddr>,
    ) -> Self {
        Self {
            profile,
            record_mode,
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
    pub record_mode: Option<crate::proto::seal::RecordMode>,
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
        record_mode: Option<crate::proto::seal::RecordMode>,
        reason: &'static str,
    ) -> Self {
        Self {
            profile,
            record_mode,
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
// Called by the drivers' listeners only.
#[cfg_attr(
    any(loom, not(any(feature = "tokio", feature = "blocking"))),
    allow(dead_code)
)]
#[derive(Clone)]
pub struct OnReject(pub(crate) std::sync::Arc<dyn Fn(&RejectInfo) -> RejectAction + Send + Sync>);

impl OnReject {
    /// The policy calling `f`.
    pub fn new(f: impl Fn(&RejectInfo) -> RejectAction + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(f))
    }

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

/// The default of [`ListenerConfig::max_pending`].
pub const DEFAULT_MAX_PENDING: usize = 1024;

/// The longest [`ListenerConfig::instance_id`], so that at least 8 random
/// bytes remain in the 16-byte session locator.
pub const MAX_INSTANCE_ID_LEN: usize = 8;

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            max_pending: Some(DEFAULT_MAX_PENDING),
            max_pending_per_source: 8,
            source_prefix_v4: 32,
            source_prefix_v6: 64,
            max_pending_per_session: 4,
            first_record_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(10),
            max_record_size: 65535,
            accept_sessions: true,
            max_suspended: 1024,
            memory_budget: Some(super::session::DEFAULT_MEMORY_BUDGET),
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

/// The source slot and listener slot one carrier holds
/// ([`ListenerCore::enter`]) until [`ListenerCore::release`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot(pub u64);

/// The result of [`ListenerCore::enter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entered {
    /// The carrier holds `slot`; `evicted` is the stalled carrier whose
    /// slot it took, to be closed now (its slot is already free).
    Taken {
        /// The new carrier's slot.
        slot: Slot,
        /// The stalled carrier to close.
        evicted: Option<Slot>,
    },
    /// The source holds its share: close the carrier at once (refused).
    SourceFull,
    /// Every slot of the listener is taken and none is stalled: close
    /// the carrier at once (rejected).
    Full,
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
    /// The slot it gives back when it leaves the listener, if the core
    /// holds it for the carrier ([`ListenerCore::open`]).
    slot: Option<Slot>,
    opened: Instant,
    framing: Framing,
    classifier: Classifier,
    buf: Vec<u8>,
    /// The first record or Hello arrived.
    first: bool,
    /// The session's locator once a verified Hello made it Unconfirmed, with the order in
    /// which carriers became Unconfirmed.
    unconfirmed: Option<(Vec<u8>, u64)>,
}

/// A held slot: its source, and its place among the stalls while stalled.
#[derive(Debug)]
struct SlotState {
    source: u64,
    stall: Option<u64>,
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
    /// The slots held ([`ListenerCore::enter`]).
    slots: HashMap<Slot, SlotState>,
    /// Slots held per source.
    by_source: HashMap<u64, usize>,
    /// Stalled slots per source ([`ListenerCore::stall`]).
    stalled_by: HashMap<u64, usize>,
    /// The stalled slots by the order their stall began, oldest first.
    stalls: BTreeMap<u64, Slot>,
    /// The order of the next stall.
    stall_seq: u64,
    /// The next slot.
    next_slot: u64,
    /// The order of the next carrier to become Unconfirmed.
    unconfirmed_seq: u64,
}

impl ListenerConfig {
    /// Checks the limits as creating a listener does: the error
    /// `Listener::new` would fail with, naming the field.
    pub fn validate(&self) -> Result<(), crate::InvalidConfig> {
        let e = crate::InvalidConfig::new;
        if self.instance_id.len() > MAX_INSTANCE_ID_LEN {
            return Err(e(
                "ListenerConfig::instance_id",
                "longer than MAX_INSTANCE_ID_LEN",
            ));
        }
        if self.max_pending == Some(0) || self.max_pending_per_session == 0 {
            return Err(e(
                "ListenerConfig::max_pending",
                "max_pending and max_pending_per_session must be at least 1",
            ));
        }
        if self.max_pending_per_source < 2 {
            return Err(e(
                "ListenerConfig::max_pending_per_source",
                "at least 2: a split bootstrap holds two slots",
            ));
        }
        if !(1..=32).contains(&self.source_prefix_v4) {
            return Err(e("ListenerConfig::source_prefix_v4", "outside 1..=32"));
        }
        if !(1..=128).contains(&self.source_prefix_v6) {
            return Err(e("ListenerConfig::source_prefix_v6", "outside 1..=128"));
        }
        Ok(())
    }

    /// The key the listener counts `addr` under, the one aggregation of
    /// every per-source limit ([`ListenerConfig::source_prefix_v4`]): its
    /// prefix, an IPv4-mapped IPv6 address (a dual-stack socket's IPv4
    /// client) as its IPv4 address. The key [`ListenerCore::enter`] takes.
    #[cfg(any(test, all(any(feature = "tokio", feature = "blocking"), not(loom))))]
    pub(crate) fn source_key(&self, addr: std::net::IpAddr) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        match addr.to_canonical() {
            std::net::IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.source_prefix_v4.min(32)));
                (4u8, u32::from(a) & mask.unwrap_or(0)).hash(&mut h);
            }
            std::net::IpAddr::V6(a) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.source_prefix_v6.min(128)));
                (6u8, u128::from(a) & mask.unwrap_or(0)).hash(&mut h);
            }
        }
        h.finish()
    }
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
            slots: HashMap::new(),
            by_source: HashMap::new(),
            stalled_by: HashMap::new(),
            stalls: BTreeMap::new(),
            stall_seq: 0,
            next_slot: 1,
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
    /// ([`ListenerCore::enter`]).
    pub fn open_stream(&mut self, framing: Framing, now: Instant) -> CarrierId {
        self.push(None, framing, now, true)
    }

    /// A carrier to classify, holding `slot` ([`ListenerCore::enter`]):
    /// given here, the slot is released when the carrier leaves the
    /// listener ([`ListenerCore::done`], its timeout, an eviction);
    /// without one, its holder releases it.
    pub fn open(&mut self, slot: Option<Slot>, framing: Framing, now: Instant) -> CarrierId {
        self.push(slot, framing, now, false)
    }

    fn push(
        &mut self,
        slot: Option<Slot>,
        framing: Framing,
        now: Instant,
        stream: bool,
    ) -> CarrierId {
        let id = CarrierId(self.next);
        self.next += 1;
        let classifier = Classifier::new(
            self.config.max_record_size,
            self.config.accept_sessions,
            true,
        );
        self.pending.push_back(Pending {
            id,
            slot,
            opened: now,
            framing,
            classifier: if stream {
                classifier.with_lanes()
            } else {
                classifier
            },
            buf: Vec::new(),
            first: false,
            unconfirmed: None,
        });
        id
    }

    /// A source slot and a listener slot for a new carrier from `source`,
    /// taken before anything else is done with it and held until
    /// [`ListenerCore::release`]. With every listener slot taken, the
    /// oldest stalled carrier gives its slot up ([`Entered::Taken`]'s
    /// `evicted`, to be closed now), or the carrier is refused
    /// ([`Entered::Full`]) when none is stalled.
    pub fn enter(&mut self, source: u64) -> Entered {
        if self.held_by(source) >= self.config.max_pending_per_source {
            return Entered::SourceFull;
        }
        let mut evicted = None;
        if self
            .config
            .max_pending
            .is_some_and(|max| self.slots.len() >= max)
        {
            let Some((_, &oldest)) = self.stalls.first_key_value() else {
                return Entered::Full;
            };
            self.release(oldest);
            evicted = Some(oldest);
        }
        let slot = Slot(self.next_slot);
        self.next_slot += 1;
        self.slots.insert(
            slot,
            SlotState {
                source,
                stall: None,
            },
        );
        *self.by_source.entry(source).or_default() += 1;
        Entered::Taken { slot, evicted }
    }

    fn held_by(&self, source: u64) -> usize {
        self.by_source.get(&source).copied().unwrap_or(0)
    }

    /// Gives `slot` back, ending its stall. A slot released already, or
    /// evicted, is ignored.
    pub fn release(&mut self, slot: Slot) {
        self.unstall(slot);
        if let Some(s) = self.slots.remove(&slot) {
            decrement(&mut self.by_source, s.source);
        }
    }

    /// Moves `slot` to `source`, the client a trusted intermediary
    /// reported: `false` when that source holds its share, or the slot is
    /// stalled and that source holds its share of stalls
    /// ([`ListenerCore::stall`]), and the slot stays where it was.
    pub fn move_slot(&mut self, slot: Slot, source: u64) -> bool {
        let Some((from, stalled)) = self.slots.get(&slot).map(|s| (s.source, s.stall.is_some()))
        else {
            return false;
        };
        if from == source {
            return true;
        }
        if self.held_by(source) >= self.config.max_pending_per_source
            || stalled
                && self.stalled_by.get(&source).copied().unwrap_or(0) + 1
                    >= self.config.max_pending_per_source
        {
            return false;
        }
        decrement(&mut self.by_source, from);
        *self.by_source.entry(source).or_default() += 1;
        if let Some(s) = self.slots.get_mut(&slot) {
            s.source = source;
            if s.stall.is_some() {
                decrement(&mut self.stalled_by, from);
                *self.stalled_by.entry(source).or_default() += 1;
            }
        }
        true
    }

    /// The carrier holding `slot` starts to stall: `false` when its source
    /// already has `max_pending_per_source - 1` stalled carriers (so that
    /// it always keeps a slot for a new attempt), the listener's stalled
    /// carriers hold half of `max_pending` (rounded down), or the slot is
    /// not held; the carrier is then closed at once (`stall_overflow`).
    /// Until [`ListenerCore::unstall`] or [`ListenerCore::release`]; a new
    /// carrier may evict it meanwhile ([`ListenerCore::enter`]).
    pub fn stall(&mut self, slot: Slot) -> bool {
        let Some(s) = self.slots.get(&slot) else {
            return false;
        };
        if s.stall.is_some() {
            return true;
        }
        let source = s.source;
        let per = self.stalled_by.get(&source).copied().unwrap_or(0);
        if per + 1 >= self.config.max_pending_per_source
            || self
                .config
                .max_pending
                .is_some_and(|max| self.stalls.len() >= max / 2)
        {
            return false;
        }
        let seq = self.stall_seq;
        self.stall_seq += 1;
        self.stalls.insert(seq, slot);
        *self.stalled_by.entry(source).or_default() += 1;
        if let Some(s) = self.slots.get_mut(&slot) {
            s.stall = Some(seq);
        }
        true
    }

    /// The stall of `slot` ended: `true` when the slot is still held,
    /// `false` when it was evicted or released meanwhile.
    pub fn unstall(&mut self, slot: Slot) -> bool {
        let Some(s) = self.slots.get_mut(&slot) else {
            return false;
        };
        if let Some(seq) = s.stall.take() {
            let source = s.source;
            self.stalls.remove(&seq);
            decrement(&mut self.stalled_by, source);
        }
        true
    }

    /// The slots held now: the listener's, and `source`'s.
    pub fn held(&self, source: u64) -> (usize, usize) {
        (self.slots.len(), self.held_by(source))
    }

    /// The carriers stalled now: the listener's, and `source`'s.
    pub fn stalled(&self, source: u64) -> (usize, usize) {
        (
            self.stalls.len(),
            self.stalled_by.get(&source).copied().unwrap_or(0),
        )
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
        self.remove(i)
    }

    /// The carrier left the listener (attached, rejected or closed); a
    /// slot it was opened with is released.
    pub fn done(&mut self, id: CarrierId) {
        if let Some(i) = self.find(id) {
            self.remove(i);
        }
    }

    fn remove(&mut self, i: usize) -> Option<CarrierId> {
        let p = self.pending.remove(i)?;
        if let Some(slot) = p.slot {
            self.release(slot);
        }
        Some(p.id)
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
            // The halves waiting hold slots, which bound the table.
            None => {
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
        let mut i = 0;
        while i < self.pending.len() {
            let p = &self.pending[i];
            let limit = if p.first { handshake } else { first_timeout };
            if p.opened.checked_add(limit).is_some_and(|t| now >= t) {
                out.extend(self.remove(i));
            } else {
                i += 1;
            }
        }
        let pairs_limit = handshake;
        self.pairs
            .retain(|_, v| now.saturating_duration_since(v.2) < pairs_limit);
        out
    }
}

/// Takes one from `source`'s count, forgetting it at 0.
fn decrement(counts: &mut HashMap<u64, usize>, source: u64) {
    if let Some(n) = counts.get_mut(&source) {
        *n -= 1;
        if *n == 0 {
            counts.remove(&source);
        }
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
    /// Decided with [`crate::AdmissionVerdict::Accept`]; each then counts once more as a
    /// pipe input in the other fields of [`ListenerStats`].
    pub accepted: u64,
    /// Decided with [`crate::AdmissionVerdict::Fallback`] (stalled without a fallback
    /// target, still counted here), or taken to the fallback by a peek
    /// timeout ([`crate::Admission::with_fallback_on_peek_timeout`], also
    /// counted in `peek_timed_out`).
    pub fallback: u64,
    /// Decided with [`crate::AdmissionVerdict::Stall`], counted when the stall starts.
    pub stalled: u64,
    /// Decided with [`crate::AdmissionVerdict::Close`], an `Accept` beyond the prefix, a
    /// decision that panicked, or one cancelled because the listener
    /// closed.
    pub closed: u64,
    /// A Stall, decided by the admission or by [`ListenerConfig::on_reject`], that the
    /// listener could not carry out: its source already stalled
    /// `max_pending_per_source - 1` carriers
    /// ([`ListenerConfig::max_pending_per_source`]), the listener's stalls held half of
    /// [`ListenerConfig::max_pending`], or the listener closed meanwhile. Closed at once.
    pub stall_overflow: u64,
    /// The prefix or the decision did not come before the end of the peek
    /// timeout.
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
    /// ([`ListenerAdapter::count_setup_failure`](crate::adapter::ListenerAdapter::count_setup_failure)). With an admission, a carrier's
    /// failed outer handshake counts in [`AdmissionStats::handshake_failed`]
    /// instead.
    pub setup_failures: u64,
    /// Inputs closed without a distinguishable reason: unknown,
    /// unauthenticated or replayed joins, lanes that name no pipe, or not
    /// zmux at all ([`HandleError::Rejected`]); and new carriers closed at once
    /// because every slot of [`ListenerConfig::max_pending`] was taken and none
    /// was stalled. An admission's decisions count in [`ListenerStats::admission`]
    /// only, and a stalled carrier closed to make room is not counted again.
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

    fn taken(e: Entered) -> (Slot, Option<Slot>) {
        match e {
            Entered::Taken { slot, evicted } => (slot, evicted),
            other => panic!("not taken: {other:?}"),
        }
    }

    #[test]
    fn per_source_and_first_record_limits() {
        let mut l = ListenerCore::new(ListenerConfig::default());
        let now = Instant::now();
        let a = source_name("a");
        for _ in 0..8 {
            let (slot, _) = taken(l.enter(a));
            l.open(Some(slot), Framing::ByteStream, now);
        }
        assert_eq!(l.enter(a), Entered::SourceFull);
        let (slot, _) = taken(l.enter(source_name("b")));
        l.open(Some(slot), Framing::ByteStream, now);
        assert!(l.expired(now + Duration::from_millis(1999)).is_empty());
        assert_eq!(l.expired(now + Duration::from_secs(2)).len(), 9);
        // The carriers' slots went with them.
        assert_eq!(l.held(a), (0, 0));
    }

    #[test]
    fn slots_are_held_until_released() {
        let mut l = ListenerCore::new(ListenerConfig {
            max_pending_per_source: 2,
            ..ListenerConfig::default()
        });
        let now = Instant::now();
        let (a, b) = (source_name("a"), source_name("b"));
        let (s1, _) = taken(l.enter(a));
        let (s2, _) = taken(l.enter(a));
        assert_eq!(l.enter(a), Entered::SourceFull);
        // A slot its holder keeps does not expire with the classification.
        l.open(None, Framing::ByteStream, now);
        assert_eq!(l.expired(now + Duration::from_secs(60)).len(), 1);
        assert_eq!(l.held(a), (2, 2));
        l.release(s1);
        l.release(s1);
        assert_eq!(l.held(a), (1, 1));
        // Moved to another source, it frees its share of the first.
        assert!(l.move_slot(s2, b));
        assert_eq!(l.held(a), (1, 0));
        taken(l.enter(a));
        taken(l.enter(a));
        assert!(!l.move_slot(s2, a), "a holds its share");
    }

    /// A stalled slot moves only to a source with room for one more stall.
    #[test]
    fn a_stalled_slot_moves_within_the_stall_share() {
        let mut l = ListenerCore::new(ListenerConfig {
            max_pending: None,
            max_pending_per_source: 3,
            ..ListenerConfig::default()
        });
        let (a, b) = (source_name("a"), source_name("b"));
        let (b1, _) = taken(l.enter(b));
        let (b2, _) = taken(l.enter(b));
        assert!(l.stall(b1) && l.stall(b2));
        let (a1, _) = taken(l.enter(a));
        let (a2, _) = taken(l.enter(a));
        assert!(l.stall(a1));
        // b holds two stalls, its share: a third would be one too many.
        assert!(!l.move_slot(a1, b));
        assert_eq!(l.stalled(b), (3, 2));
        assert_eq!(l.stalled(a), (3, 1));
        // A slot that does not stall still moves.
        assert!(l.move_slot(a2, b));
        l.release(b1);
        assert!(l.move_slot(a1, b));
        assert_eq!(l.stalled(b), (2, 2));
    }

    /// The listener's bound: a stall holds at most half of it; a new carrier with every
    /// slot taken evicts the oldest stall, and is refused when none is stalled.
    #[test]
    fn the_global_bound_evicts_the_oldest_stall() {
        let mut l = ListenerCore::new(ListenerConfig {
            max_pending: Some(4),
            ..ListenerConfig::default()
        });
        let slots: Vec<_> = (0..4).map(|n| taken(l.enter(n)).0).collect();
        assert_eq!(l.enter(9), Entered::Full);
        assert!(l.stall(slots[1]) && l.stall(slots[0]));
        assert!(!l.stall(slots[2]), "stalls hold at most half");
        assert_eq!(l.stalled(0), (2, 1));
        let (_, evicted) = taken(l.enter(9));
        assert_eq!(evicted, Some(slots[1]), "the stall that began first");
        assert!(!l.unstall(slots[1]), "evicted: its slot is gone");
        assert_eq!(l.stalled(0), (1, 1));
        let (_, evicted) = taken(l.enter(9));
        assert_eq!(evicted, Some(slots[0]));
        assert_eq!(l.enter(9), Entered::Full);
        assert_eq!(l.held(9), (4, 2));
    }

    /// With one slot, half of it rounded down is none: no carrier stalls,
    /// so a carrier holding the slot is never one to evict, and a new one
    /// finds the listener full.
    #[test]
    fn one_slot_stalls_nothing() {
        let mut l = ListenerCore::new(ListenerConfig {
            max_pending: Some(1),
            ..ListenerConfig::default()
        });
        let (slot, _) = taken(l.enter(0));
        assert!(!l.stall(slot), "half of one slot, rounded down, is none");
        assert_eq!(l.enter(1), Entered::Full);
        l.release(slot);
        let (_, evicted) = taken(l.enter(1));
        assert_eq!(evicted, None);
    }

    /// A source stalls at most `max_pending_per_source - 1` carriers; unlimited, the
    /// listener never refuses for its own bound.
    #[test]
    fn a_source_keeps_a_slot_and_unlimited_never_fills() {
        let mut l = ListenerCore::new(ListenerConfig {
            max_pending: None,
            max_pending_per_source: 3,
            ..ListenerConfig::default()
        });
        let a: Vec<_> = (0..3).map(|_| taken(l.enter(1)).0).collect();
        assert!(l.stall(a[0]) && l.stall(a[1]));
        assert!(!l.stall(a[2]));
        assert!(l.unstall(a[0]));
        assert!(l.stall(a[2]));
        for n in 0..10_000 {
            taken(l.enter(100 + n));
        }
    }

    /// Beyond the session's limit the carrier Unconfirmed longest goes, by when it became
    /// Unconfirmed and not by when it arrived, and never the Hello that went over it.
    #[test]
    fn the_longest_unconfirmed_is_evicted() {
        let mut l = ListenerCore::new(ListenerConfig::default());
        let now = Instant::now();
        let ids: Vec<_> = (0..6)
            .map(|n| {
                let (slot, _) = taken(l.enter(n));
                l.open(Some(slot), Framing::ByteStream, now)
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
        let c = ListenerConfig::default();
        let ip = |s: &str| c.source_key(s.parse().unwrap());
        assert_eq!(ip("2001:db8:1:2::1"), ip("2001:db8:1:2:ffff::9"));
        assert_ne!(ip("2001:db8:1:2::1"), ip("2001:db8:1:3::1"));
        assert_eq!(ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
        assert_ne!(ip("::ffff:192.0.2.1"), ip("::ffff:192.0.2.2"));
        // Shorter prefixes: one /24, one /56.
        let mut c = ListenerConfig {
            source_prefix_v4: 24,
            source_prefix_v6: 56,
            ..ListenerConfig::default()
        };
        let ip = |s: &str| c.source_key(s.parse().unwrap());
        assert_eq!(ip("192.0.2.1"), ip("192.0.2.200"));
        assert_eq!(ip("::ffff:192.0.2.1"), ip("192.0.2.9"));
        assert_ne!(ip("192.0.2.1"), ip("192.0.3.1"));
        assert_eq!(ip("2001:db8:0:a1::1"), ip("2001:db8:0:a2::1"));
        assert_ne!(ip("2001:db8:0:a1::1"), ip("2001:db8:0:1a1::1"));
        // The extremes: one address, every address of a family.
        c.source_prefix_v4 = 1;
        c.source_prefix_v6 = 128;
        let ip = |s: &str| c.source_key(s.parse().unwrap());
        assert_eq!(ip("1.0.0.0"), ip("127.255.0.1"));
        assert_ne!(ip("1.0.0.0"), ip("128.0.0.1"));
        assert_ne!(ip("2001:db8::1"), ip("2001:db8::2"));
        // Families never share.
        assert_ne!(ip("0.0.0.0"), ip("::"));
    }

    #[test]
    fn source_prefixes_are_checked() {
        let with = |v4: u8, v6: u8| {
            ListenerConfig {
                source_prefix_v4: v4,
                source_prefix_v6: v6,
                ..ListenerConfig::default()
            }
            .validate()
        };
        assert!(with(32, 64).is_ok() && with(1, 1).is_ok() && with(32, 128).is_ok());
        for (v4, v6) in [(0, 64), (33, 64), (32, 0), (32, 129)] {
            assert!(with(v4, v6).is_err(), "{v4} {v6}");
        }
    }

    #[test]
    fn garbage_is_rejected() {
        let mut l = ListenerCore::new(ListenerConfig::default());
        let now = Instant::now();
        let id = l.open(None, Framing::ByteStream, now);
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
