//! The tokio listener: new carriers start sessions or join existing
//! ones after verification, with the pending-join and rate limits and
//! the memory budget and suspended-session limits.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::Instant;

use super::account::{Account, AccountLink};
use super::admission::{AdmitIo, Fallback, FirstMessage, discard, read_message, read_more};
use super::handle::{self, Shared, WeakSession};
use super::resources::{Kind, Live};
use super::sealed::{read_unit, seal_carrier, until, write_unit};
use super::stream_pipe::{claim_carrier, runs_over};
use super::tokio::{PipeIo, Session, Tokio, now};
use super::transform::InboundTransform;
use super::wait::{PipeDone, Ticket, WaitList};
use super::wake::WakeList;
use crate::proto::VarInt;
use crate::proto::admission::{
    Admission, AdmissionStage, AdmissionVerdict, AdmittedValue, CarrierInfo, Round, Step, step,
};
use crate::proto::exporter::CarrierExporter;
use crate::proto::listener::{
    CarrierId, Classified, Entered, ListenerConfig, ListenerCore as Core, Paired, Slot,
};
use crate::proto::listener::{RejectAction, RejectInfo, SessionConfigFn};
use crate::proto::oob::PAIRING_TOKEN_LEN;
use crate::proto::record::Framing;
use crate::proto::session::{Config, PipeId, Role};
use crate::util::{HmacSha256, random_u64};

/// What a carrier came with besides its bytes.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct PipeHint {
    /// The carrier's source, for the per-source limits and the stall
    /// duration: the client a trusted intermediary reported, or one the
    /// host resolved itself; the same value as [`CarrierInfo::source`].
    /// Unset, the listener takes the peer.
    pub source: Option<SocketAddr>,
    /// The directly connected peer ([`CarrierInfo::peer`]).
    pub peer: Option<SocketAddr>,
    /// The pairing token of a split bootstrap's carrier (for example the
    /// decoded `Zmux-Pipe-Pair` header): the carrier is one half of pipe
    /// pair 0, an uplink when it has only an inbound half, a downlink
    /// when it has only an outbound one. A token that is not
    /// [`PAIRING_TOKEN_LEN`] bytes is rejected.
    ///
    /// A half waits for its partner in a slot of the listener, until the
    /// other half arrives or the handshake timeout ends: 1024 per
    /// listener and 8 per source by default
    /// ([`crate::ListenerConfig::max_pending`],
    /// [`crate::ListenerConfig::max_pending_per_source`]), a source
    /// counted by its prefix ([`crate::ListenerConfig::source_prefix_v4`]).
    /// Without an admission
    /// ([`crate::ListenerConfig::admission`]), a few sources can keep
    /// those slots full and delay other clients' split bootstraps: serve a
    /// split bootstrap that the open Internet reaches with an admission,
    /// such as prefix authentication.
    pub pair: Option<Vec<u8>>,
    /// The carrier's entry, once an adapter made it enter the listener.
    entry: Option<Entry>,
    /// The admitted connection the carrier is a further stream of.
    connection: Option<Admitted>,
    /// The admission's value, set by the listener.
    value: Option<AdmittedValue>,
}

impl PipeHint {
    /// A hint with the directly connected peer, which is also the source.
    #[must_use]
    pub fn from_peer(peer: SocketAddr) -> Self {
        Self {
            peer: Some(peer),
            ..Self::default()
        }
    }

    /// The hint of a carrier that entered the listener ([`ListenerAdapter::enter`])
    /// and was admitted there ([`Entry::admit`]): its source and peer are
    /// the entry's, which [`Listener::handle_pipe`] goes on with.
    #[must_use]
    pub fn from_entry(entry: Entry) -> Self {
        Self {
            source: Some(entry.source),
            peer: Some(entry.peer),
            entry: Some(entry),
            ..Self::default()
        }
    }

    /// The hint of a further carrier (a stream) of a connection whose
    /// admission accepted it ([`Entry::admitted`]): it takes its own
    /// source slot in [`Listener::handle_pipe`], and is admitted already.
    #[must_use]
    pub fn from_admitted(admitted: Admitted) -> Self {
        Self {
            source: Some(admitted.source),
            peer: Some(admitted.peer),
            value: admitted.value.clone(),
            connection: Some(admitted),
            ..Self::default()
        }
    }

    /// The value of the admission that accepted the carrier
    /// ([`AdmissionVerdict::Accept`]): set by the listener before its inbound
    /// transform runs ([`InboundTransform`]); `None` without an
    /// admission or a value.
    #[must_use]
    pub fn admitted(&self) -> Option<&AdmittedValue> {
        self.value.as_ref()
    }

    /// With the carrier's source ([`PipeHint::source`]).
    #[must_use]
    pub fn with_source(mut self, source: SocketAddr) -> Self {
        self.source = Some(source);
        self
    }

    /// Takes the pairing token from a `Zmux-Pipe-Pair` header value; a
    /// value that does not decode is kept as an invalid token, so that the
    /// carrier is rejected rather than taken as a bidirectional one.
    #[must_use]
    pub fn with_pair_header(mut self, value: &str) -> Self {
        self.pair = Some(crate::proto::oob::decode_vec(value.as_bytes()).unwrap_or_default());
        self
    }
}

/// The counts of [`Listener::stats`].
#[derive(Default)]
struct Counts {
    sessions: AtomicU64,
    joins: AtomicU64,
    setup_failures: AtomicU64,
    rejected: AtomicU64,
    refused: AtomicU64,
    timed_out: AtomicU64,
    admission: AdmissionCounts,
}

#[derive(Default)]
struct AdmissionCounts {
    accepted: AtomicU64,
    fallback: AtomicU64,
    stalled: AtomicU64,
    closed: AtomicU64,
    stall_overflow: AtomicU64,
    too_large: AtomicU64,
    peek_timed_out: AtomicU64,
    handshake_failed: AtomicU64,
    variants: Mutex<AdmissionVariants>,
}

/// The outcome of a carrier's admission, counted once
/// ([`AdmissionStats`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Accepted,
    Fallback,
    Stalled,
    StallOverflow,
    Closed,
    TooLarge,
    PeekTimedOut,
    HandshakeFailed,
}

impl AdmissionCounts {
    /// Counts an outcome, and the verdict of a labelled decision.
    fn count(&self, outcome: Outcome, variant: Option<&Arc<str>>) {
        let total = match outcome {
            Outcome::Accepted => &self.accepted,
            Outcome::Fallback => &self.fallback,
            Outcome::Stalled => &self.stalled,
            Outcome::StallOverflow => &self.stall_overflow,
            Outcome::Closed => &self.closed,
            Outcome::TooLarge => &self.too_large,
            Outcome::PeekTimedOut => &self.peek_timed_out,
            Outcome::HandshakeFailed => &self.handshake_failed,
        };
        total.fetch_add(1, Relaxed);
        match outcome {
            Outcome::Accepted => self.count_variant(variant, |v| v.accepted += 1),
            Outcome::Fallback => self.count_variant(variant, |v| v.fallback += 1),
            Outcome::Stalled => self.count_variant(variant, |v| v.stalled += 1),
            Outcome::Closed => self.count_variant(variant, |v| v.closed += 1),
            _ => {}
        }
    }

    fn count_variant(&self, variant: Option<&Arc<str>>, bump: impl FnOnce(&mut VariantStats)) {
        if let Some(v) = variant {
            let mut m = self.variants.lock().unwrap_or_else(PoisonError::into_inner);
            let m = &mut *m;
            if let Some(s) = m.variants.get_mut(v) {
                bump(s);
            } else if m.variants.len() < MAX_ADMISSION_VARIANTS {
                bump(m.variants.entry(v.clone()).or_default());
            } else {
                bump(&mut m.overflow);
            }
        }
    }
}

/// The admission's verdicts on the carriers it labelled
/// ([`crate::AdmissionDecision::variant`]), per label; they count in the totals of
/// [`AdmissionStats`] as well.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VariantStats {
    /// Accepted.
    pub accepted: u64,
    /// To the fallback target.
    pub fallback: u64,
    /// Stalled.
    pub stalled: u64,
    /// Closed at once.
    pub closed: u64,
}

/// How many distinct [`crate::AdmissionDecision::variant`] labels a listener counts
/// apart; further ones share [`AdmissionVariants::overflow`]. Labels are
/// meant to be a few constants of the host, never derived from the peer's
/// bytes.
pub const MAX_ADMISSION_VARIANTS: usize = 64;

/// The admission's verdicts per label ([`Listener::variant_stats`]), a copy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmissionVariants {
    /// Per label, at most [`MAX_ADMISSION_VARIANTS`] of them.
    pub variants: HashMap<Arc<str>, VariantStats>,
    /// The labels past that bound together.
    pub overflow: VariantStats,
}

pub(crate) use crate::proto::listener::HandleError;
pub use crate::proto::listener::{AdmissionStats, ListenerStats};

struct State_ {
    core: Core,
    accept: VecDeque<Session>,
    accept_waiters: WaitList,
    /// Carriers waiting for their first record, woken by [`Listener::close`]
    /// and by an eviction.
    close_waiters: WaitList,
    /// Unconfirmed carriers evicted for a new one, until each saw it and
    /// closed.
    evicted: Vec<CarrierId>,
    /// The slots of stalled carriers evicted for a new carrier, until each
    /// saw it and closed.
    evicted_slots: Vec<Slot>,
    /// The halves of split bootstraps waiting for their other half, by
    /// pairing token; the core decides the pairing.
    pairs: HashMap<[u8; PAIRING_TOKEN_LEN], PairSlot>,
    /// Every session the listener started, until it ended: what
    /// [`Listener::shutdown`] closes.
    live: Vec<Weak<Shared<Tokio>>>,
    /// The size of `live` after its last pruning.
    live_pruned: usize,
    /// [`Listener::shutdown`] began: no new session, joins go on.
    draining: bool,
    closed: bool,
}

/// A split bootstrap's first half, waiting under its token: the second
/// half is put here, with the latch it waits on until the session ends.
/// The second half of a pair: its carrier, what it resolves, and a split join's locator and
/// Hello when it is the uplink.
///
/// Dropped with its slot, the latch releases the second half.
type PairPartner = (PipeIo, FinishOnDrop);

struct PairSlot {
    waiter: CarrierId,
    partner: Option<PairPartner>,
}

impl State_ {
    /// Ends the pending carrier the core evicted for a new one: it is woken
    /// to close. The wake-ups go to `wakes`, woken after the lock.
    fn evict(&mut self, evicted: Option<CarrierId>, wakes: &mut WakeList) {
        if let Some(e) = evicted {
            self.evicted.push(e);
            self.close_waiters.wake_all(wakes);
        }
    }

    /// Ends the stalled carrier whose slot a new carrier took: it is woken
    /// to close. The wake-ups go to `wakes`, woken after the lock.
    fn evict_slot(&mut self, evicted: Option<Slot>, wakes: &mut WakeList) {
        if let Some(e) = evicted {
            self.evicted_slots.push(e);
            self.close_waiters.wake_all(wakes);
        }
    }
}

struct ListenShared {
    /// What happened to the carriers handed to the listener.
    counts: Counts,
    state: Mutex<State_>,
    /// The sessions by Locator.
    locators: handle::LocatorTable<Shared<Tokio>>,
    /// The memory budget and suspended-session limit, which the sessions
    /// keep up to date (`super::account`).
    account: Arc<Account<Shared<Tokio>>>,
    config: Arc<Config>,
    /// The prefix of every session locator.
    instance_id: Vec<u8>,
    /// The key of stall durations ([`Listener::stall_slot`]), drawn when
    /// the listener is made.
    stall_key: HmacSha256,
    /// [`ListenerConfig::trusted_proxies`], read without the lock.
    trusted: crate::proto::trusted::TrustedProxies,
    /// [`ListenerConfig::admission`].
    admission: Option<Admission>,
    /// [`ListenerConfig::fallback`].
    fallback: Option<Fallback>,
    /// [`ListenerConfig::inbound_transform`].
    transform: Option<InboundTransform>,
    /// [`ListenerConfig::on_reject`].
    on_reject: Option<crate::proto::listener::OnReject>,
    /// The longest stall of a refused Establish: the admission's, or drawn.
    stall_max: Duration,
    /// [`ListenerConfig::logger`].
    logger: Option<crate::Logger>,
    _live: Live,
}

impl ListenShared {
    fn lock(&self) -> MutexGuard<'_, State_> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A carrier that entered a listener ([`ListenerAdapter::enter`]): it holds a
/// source slot ([`ListenerConfig::max_pending_per_source`]) and a slot of
/// the listener ([`ListenerConfig::max_pending`]) from before its outer
/// handshake, through its admission and, handed to
/// [`Listener::handle_pipe`] with [`PipeHint::from_entry`], until it enters
/// a session; or until it goes to the listener's fallback, is released
/// ([`Entry::release`]) or dropped. Dropped before its admission
/// ([`Entry::admit`], [`Entry::admit_first`], [`Entry::decide_request`],
/// [`Entry::decide_upgrade`]), its outer handshake counts as failed;
/// dropped while an upgrade's head deferred its decision, the decision
/// that never came counts as timed out once the peek timeout passed, and
/// as closed before.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts of the carrier's admission"
)]
pub struct Entry {
    shared: Arc<ListenShared>,
    key: u64,
    /// Its slots; `None` once a new carrier evicted it while it stalled,
    /// or once it went to the fallback.
    slot: Option<Slot>,
    source: SocketAddr,
    peer: SocketAddr,
    admitted: bool,
    handshaken: bool,
    /// The carrier counts as stalled
    /// ([`ListenerCore::stall`](crate::proto::listener::ListenerCore::stall)).
    stalling: bool,
    /// The end of the peek timeout, from the end of the outer handshake.
    deadline: Option<Instant>,
    /// The metadata of the decision an upgrade's head deferred to its
    /// carrier ([`AdmissionVerdict::Defer`]), at the carrier's stage.
    deferred: Option<CarrierInfo>,
    /// The value the admission accepted it with.
    value: Option<AdmittedValue>,
    /// The label the admission gave it.
    variant: Option<Arc<str>>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("source", &self.source)
            .field("peer", &self.peer)
            .field("admitted", &self.admitted)
            .field("deferred", &self.deferred.is_some())
            .finish_non_exhaustive()
    }
}

/// The setups [`Listener::serve_connections`] runs, oldest first.
#[derive(Default)]
struct SetupTasks(VecDeque<tokio::task::AbortHandle>);

impl SetupTasks {
    /// Makes room for one more setup within `most`: the finished ones are
    /// forgotten and, at the bound, the oldest running one is ended.
    fn make_room(&mut self, most: Option<usize>) {
        let Some(most) = most else {
            return;
        };
        self.0.retain(|h| !h.is_finished());
        while self.0.len() >= most.max(1) {
            if let Some(oldest) = self.0.pop_front() {
                oldest.abort();
            }
        }
    }

    fn push(&mut self, task: tokio::task::AbortHandle) {
        self.0.push_back(task);
    }
}

/// What the listener's admission decided on an HTTP request taken as a
/// carrier ([`Entry::decide_request`], [`Entry::decide_upgrade`]). A
/// request is taken over as a request, by its adapter's HTTP fallback, not
/// by the listener's ([`ListenerConfig::fallback`]).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Admit {
    /// Accepted: the prefix bytes of the body after those the decision
    /// removed, to be given back in front of the carrier
    /// ([`PipeIo::with_prefix`]; none on a head), handed to
    /// [`Listener::handle_pipe`] with [`PipeHint::from_entry`].
    Accept(Vec<u8>),
    /// An upgrade's head deferred the decision to its carrier: complete the
    /// upgrade and admit the carrier with [`Entry::admit_first`].
    Defer,
    /// To the adapter's HTTP fallback, every byte of the body read
    /// replayed in front (none on a head).
    Fallback(Vec<u8>),
    /// Stall it ([`Entry::stall`]), then end it without a response.
    Stall,
    /// End it at once.
    Close,
}

/// What a bounded read of a prefix gave.
enum Read {
    /// The bytes, and whether the carrier ended short of the length asked.
    Got(Vec<u8>, bool),
    /// The peek timeout passed first: the bytes read so far.
    Late(Vec<u8>),
    /// The listener stopped taking carriers.
    Closed,
}

/// Why a decision gave no verdict.
enum NoDecision {
    /// Not within the peek timeout.
    Late,
    /// It panicked, or the listener stopped taking carriers.
    Closed,
}

/// What a carrier's prefix is to the listener's sessions
/// ([`ListenerAdapter::join_prefix`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JoinPrefix {
    /// A Join Hello whose Locator names a current session.
    Known,
    /// A Join Hello whose Locator names no current session.
    Unknown,
    /// Not a Join Hello, or a malformed one (a suite this build does not
    /// have, reserved mode bits, an empty Locator).
    NotJoin,
    /// The prefix ends inside the Hello's head: its total length.
    Need(usize),
}

/// The source of a carrier that its connection's admission accepted, for
/// the further carriers of that connection (the streams of a QUIC
/// connection): [`PipeHint::from_admitted`].
#[derive(Debug, Clone)]
pub struct Admitted {
    source: SocketAddr,
    peer: SocketAddr,
    value: Option<AdmittedValue>,
}

impl Entry {
    /// The carrier's source.
    #[must_use]
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// The directly connected peer.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Whether the admission accepted it (or the listener has none).
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        self.admitted
    }

    /// The admitted source of this carrier's connection, once its
    /// admission accepted it.
    #[must_use]
    pub fn admitted(&self) -> Option<Admitted> {
        self.admitted.then(|| Admitted {
            source: self.source,
            peer: self.peer,
            value: self.value.clone(),
        })
    }

    /// Applies the listener's admission to a carrier once its outer
    /// handshake completed (or right away for one without), and acts on
    /// the decision: the accepted carrier, the bytes read given back in
    /// front, to be handed to [`Listener::handle_pipe`] with
    /// [`PipeHint::from_entry`]; `None` when it was not accepted, once it
    /// was handed to the listener's fallback
    /// ([`ListenerConfig::fallback`], a [`Takeover`](crate::Takeover); a
    /// stall without one) and the fallback completed, stalled, or closed.
    ///
    /// The prefix is read within the peek timeout and until the listener
    /// closes: up to [`Admission::peek`] bytes of a byte stream (more on
    /// [`AdmissionVerdict::More`]), or a message-framed carrier's first
    /// message, whole, at most [`Admission::max_message`] bytes (with a
    /// peek above 0, or after an upgrade's head deferred the decision). A
    /// longer message is closed without a decision
    /// ([`AdmissionStats::too_large`]), and so is a carrier whose first
    /// message does not come (it ends, fails, or sends an empty or a
    /// non-binary message), counted as closed, as is one the listener's
    /// close interrupts. `info` is the carrier's metadata (its source and
    /// peer are the entry's, its stage [`AdmissionStage::Carrier`] and its
    /// framing the carrier's), unless an upgrade's head deferred the
    /// decision ([`Entry::decide_upgrade`]): the head's is used then. Once
    /// the carrier is accepted, or without an admission, it is returned at
    /// once.
    pub async fn admit(&mut self, info: CarrierInfo, io: impl Into<AdmitIo>) -> Option<PipeIo> {
        let mut io = io.into();
        let deferred = self.deferred.take();
        let deadline = self.start();
        let (adm, deadline) = match (self.shared.admission.clone(), deadline) {
            (Some(adm), Some(deadline)) if !self.admitted => (adm, deadline),
            _ => {
                self.admitted = true;
                let given = io.given_back();
                return Some(io.into_pipe(given));
            }
        };
        let framing = io.framing();
        let records = framing == Framing::Records;
        let mut info = match &deferred {
            Some(head) => head.clone(),
            None => self.carrier_info(info, AdmissionStage::Carrier),
        };
        info.framing = framing;
        let c = &self.shared.counts.admission;
        let mut prefix = io.given_back();
        if records && (adm.peek() > 0 || deferred.is_some()) {
            if prefix.is_empty() {
                let Some(r) = io.reader() else {
                    c.count(Outcome::Closed, None);
                    return None;
                };
                let listener = self.listener();
                let read = read_message(r, adm.max_message(), deadline);
                match until(listener.adapter().closed(), read).await {
                    Some(FirstMessage::Message(m)) => prefix = m,
                    Some(FirstMessage::TooLarge) => {
                        c.count(Outcome::TooLarge, None);
                        return None;
                    }
                    Some(FirstMessage::Late) => {
                        c.count(Outcome::PeekTimedOut, None);
                        return None;
                    }
                    Some(FirstMessage::Failed) | None => {
                        c.count(Outcome::Closed, None);
                        return None;
                    }
                }
            } else if prefix.len() > adm.max_message() {
                c.count(Outcome::TooLarge, None);
                return None;
            }
        } else if !records
            && prefix.len() < adm.peek()
            && let Some(r) = io.reader()
        {
            match self.read_bounded(prefix, adm.peek(), r, deadline).await {
                Read::Got(p, _) => prefix = p,
                Read::Late(p) => {
                    if let Admit::Fallback(p) = self.late_outcome(p, false, None) {
                        self.fall_back(info, p, io).await;
                    }
                    return None;
                }
                Read::Closed => {
                    self.shared.counts.admission.count(Outcome::Closed, None);
                    return None;
                }
            }
        }
        let reader = if records { None } else { io.reader() };
        match self.decide_on(&info, prefix, reader, false).await {
            Admit::Accept(rest) => Some(io.into_pipe(rest)),
            Admit::Fallback(replay) => {
                self.fall_back(info, replay, io).await;
                None
            }
            Admit::Stall => {
                self.stall_io(io).await;
                None
            }
            Admit::Close | Admit::Defer => None,
        }
    }

    /// [`Entry::admit`] for an adapter whose first carrier comes after the
    /// carrier's head decision or its outer handshake: `first` completes an
    /// HTTP upgrade or waits for the carrier (the first stream of a QUIC
    /// connection or a WebTransport session) and yields it.
    ///
    /// Unless the head was accepted already (or there is no admission),
    /// `first` runs within the peek timeout, counted from the head's
    /// decision ([`AdmissionVerdict::Defer`]) or from the end of the outer
    /// handshake (now, when nothing started it), and until the listener
    /// closes: a carrier that does not come in time counts as timed out
    /// ([`AdmissionStats::peek_timed_out`]), one the close interrupted as
    /// closed and one `first` fails as a failed handshake, without a
    /// decision; the carrier then passes the admission as with
    /// [`Entry::admit`], `info` its metadata unless the head deferred the
    /// decision. When the head was accepted, `first` runs until the
    /// listener closes and its carrier is returned as it comes; a failure
    /// then counts as a setup failure. On `None` the adapter closes what it
    /// upgraded.
    pub async fn admit_first<F>(&mut self, info: CarrierInfo, first: F) -> Option<PipeIo>
    where
        F: Future<Output = std::io::Result<AdmitIo>>,
    {
        let listener = self.listener();
        if self.admitted || self.shared.admission.is_none() {
            if let Some(Ok(io)) = until(listener.adapter().closed(), first).await {
                return self.admit(info, io).await;
            }
            self.handshaken = true;
            self.shared.counts.setup_failures.fetch_add(1, Relaxed);
            return None;
        }
        let deadline = self.start()?;
        let came = until(
            listener.adapter().closed(),
            tokio::time::timeout_at(deadline, first),
        )
        .await;
        let outcome = match came {
            Some(Ok(Ok(io))) => return self.admit(info, io).await,
            Some(Ok(Err(_))) => Outcome::HandshakeFailed,
            Some(Err(_)) => Outcome::PeekTimedOut,
            None => Outcome::Closed,
        };
        // Counted here: the deferral, if any, ends without its decision.
        self.deferred = None;
        self.shared.counts.admission.count(outcome, None);
        None
    }

    /// The listener's decision on an HTTP request whose body (or nothing
    /// after its head) is the carrier, before anything is answered: up to
    /// [`Admission::peek`] bytes of `body` are read within the peek
    /// timeout and until the listener closes (more on
    /// [`AdmissionVerdict::More`]), and the decision is taken on them with
    /// `info` (the request head among it; its source and peer the entry's).
    /// A request without a body (`None`, or one that ends before its first
    /// byte) is decided on its head ([`AdmissionStage::Head`]). A late
    /// prefix ends the request ([`Admit::Close`]), whatever
    /// [`Admission::with_fallback_on_peek_timeout`] says. Without an
    /// admission it accepts at once.
    pub async fn decide_request<R>(&mut self, info: CarrierInfo, body: Option<&mut R>) -> Admit
    where
        R: AsyncRead + Unpin + Send,
    {
        let deadline = self.start();
        let (Some(adm), Some(deadline)) = (self.shared.admission.clone(), deadline) else {
            self.admitted = true;
            return Admit::Accept(Vec::new());
        };
        let mut info = self.carrier_info(info, AdmissionStage::Carrier);
        let mut prefix = Vec::new();
        let mut reader: Option<&mut (dyn AsyncRead + Unpin + Send)> = None;
        match body {
            None => info.stage = AdmissionStage::Head,
            Some(r) if adm.peek() > 0 => {
                match self
                    .read_bounded(Vec::new(), adm.peek(), &mut *r, deadline)
                    .await
                {
                    Read::Got(p, ended) if p.is_empty() && ended => {
                        info.stage = AdmissionStage::Head;
                    }
                    Read::Got(p, _) => {
                        prefix = p;
                        reader = Some(r);
                    }
                    Read::Late(p) => return self.late_outcome(p, true, None),
                    Read::Closed => {
                        self.shared.counts.admission.count(Outcome::Closed, None);
                        return Admit::Close;
                    }
                }
            }
            Some(r) => reader = Some(r),
        }
        self.decide_on(&info, prefix, reader, true).await
    }

    /// The listener's decision on the head of an HTTP upgrade (WebSocket,
    /// WebTransport), before anything is answered: `info` carries the
    /// request head (its source and peer the entry's; its stage
    /// [`AdmissionStage::Head`] and [`CarrierInfo::upgrade`] are set here).
    /// [`Admit::Defer`] defers the decision to the carrier: complete the
    /// upgrade and admit the carrier with [`Entry::admit_first`], which
    /// decides again with the same metadata at
    /// [`AdmissionStage::Carrier`]; the peek timeout runs on meanwhile.
    /// Without an admission it accepts at once.
    pub async fn decide_upgrade(&mut self, info: CarrierInfo) -> Admit {
        let info = self.carrier_info(info, AdmissionStage::Head).with_upgrade();
        let admit = self
            .decide_on(&info, Vec::new(), None::<&mut tokio::io::Empty>, true)
            .await;
        if admit == Admit::Defer {
            self.deferred = Some(info.with_stage(AdmissionStage::Carrier));
        }
        admit
    }

    /// The entry's listener, for its close.
    fn listener(&self) -> Listener {
        Listener {
            shared: self.shared.clone(),
        }
    }

    /// `info` with the entry's source and peer, at `stage`, a byte stream.
    fn carrier_info(&self, info: CarrierInfo, stage: AdmissionStage) -> CarrierInfo {
        info.with_source(self.source)
            .with_peer(self.peer)
            .with_stage(stage)
            .with_framing(Framing::ByteStream)
    }

    /// The deadline of the admission, started at the first call: the end
    /// of the outer handshake. A timeout beyond the clock's range never ends.
    fn start(&mut self) -> Option<Instant> {
        self.handshaken = true;
        let adm = self.shared.admission.as_ref()?;
        Some(*self.deadline.get_or_insert_with(|| {
            let now = Instant::now();
            now.checked_add(adm.peek_timeout())
                .unwrap_or_else(|| now + Duration::from_hours(262_800))
        }))
    }

    /// Reads `prefix` on to `need` bytes from `r`, by `deadline` and
    /// until the listener closes.
    async fn read_bounded<R>(
        &self,
        prefix: Vec<u8>,
        need: usize,
        r: &mut R,
        deadline: Instant,
    ) -> Read
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let listener = self.listener();
        let read = read_more(prefix, need, r, deadline);
        match until(listener.adapter().closed(), read).await {
            None => Read::Closed,
            Some((p, true)) => Read::Late(p),
            Some((p, false)) => {
                let ended = p.len() < need;
                Read::Got(p, ended)
            }
        }
    }

    /// The outcome of a prefix that did not arrive within the peek
    /// timeout: counted in `peek_timed_out`, then closed, or taken to the
    /// fallback with `prefix` replayed when the admission says so
    /// ([`Admission::with_fallback_on_peek_timeout`]; counted in
    /// `fallback` as well, under `variant`), except an HTTP request carrier
    /// (`request`), which is always closed.
    fn late_outcome(&self, prefix: Vec<u8>, request: bool, variant: Option<&Arc<str>>) -> Admit {
        let c = &self.shared.counts.admission;
        c.count(Outcome::PeekTimedOut, None);
        let fallback = self
            .shared
            .admission
            .as_ref()
            .is_some_and(Admission::fallback_on_peek_timeout);
        if fallback && !request {
            c.count(Outcome::Fallback, variant);
            return Admit::Fallback(prefix);
        }
        Admit::Close
    }

    /// The decision on `prefix` at `info`'s stage, again on a longer one
    /// read from `reader` (a byte stream) after each
    /// [`AdmissionVerdict::More`], within the peek timeout and until the
    /// listener closes, counted once it is final ([`Admit::Defer`] is not:
    /// the decision then is the carrier's). `request`: an HTTP request,
    /// which a late prefix closes.
    async fn decide_on<R>(
        &mut self,
        info: &CarrierInfo,
        mut prefix: Vec<u8>,
        mut reader: Option<&mut R>,
        request: bool,
    ) -> Admit
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let deadline = self.start();
        let (Some(adm), Some(deadline)) = (self.shared.admission.clone(), deadline) else {
            self.admitted = true;
            return Admit::Accept(prefix);
        };
        let shared = self.shared.clone();
        let c = &shared.counts.admission;
        // An exporter whose values come later is resolved first, within the
        // peek deadline and the listener's life: a decision reads its values
        // synchronously ([`CarrierInfo::export`]).
        if let Some(e) = info.exporter().filter(|e| !e.is_resolved()) {
            let resolve = tokio::time::timeout_at(deadline, e.resolve());
            match until(self.listener().adapter().closed(), resolve).await {
                Some(Ok(())) => {}
                Some(Err(_)) => {
                    let records = info.framing == Framing::Records;
                    return self.late_outcome(prefix, request || records, None);
                }
                None => {
                    c.count(Outcome::Closed, None);
                    return Admit::Close;
                }
            }
        }
        let mut short = false;
        loop {
            let decision = match self
                .call_decide(&adm, info.clone(), &prefix, deadline)
                .await
            {
                Ok(d) => d,
                Err(NoDecision::Late) => {
                    c.count(Outcome::PeekTimedOut, None);
                    return Admit::Close;
                }
                Err(NoDecision::Closed) => {
                    c.count(Outcome::Closed, None);
                    return Admit::Close;
                }
            };
            let crate::AdmissionDecision { verdict, variant } = decision;
            let round = Round {
                stage: info.stage,
                framing: info.framing,
                upgrade: info.upgrade,
                len: prefix.len(),
                can_read: reader.is_some(),
                short,
                max_peek: adm.max_peek(),
            };
            match step(verdict, &round) {
                Step::Defer => return Admit::Defer,
                Step::Read(need) => {
                    let Some(r) = reader.as_deref_mut() else {
                        unreachable!("a read without a reader");
                    };
                    match self.read_bounded(prefix, need, r, deadline).await {
                        Read::Got(p, ended) => (prefix, short) = (p, ended),
                        Read::Late(p) => return self.late_outcome(p, request, variant.as_ref()),
                        Read::Closed => {
                            c.count(Outcome::Closed, variant.as_ref());
                            return Admit::Close;
                        }
                    }
                }
                Step::Final(v) => return self.finish(v, variant, prefix),
            }
        }
    }

    /// One call of the decision, within the peek timeout and until the
    /// listener closes.
    async fn call_decide(
        &self,
        adm: &Admission,
        info: CarrierInfo,
        prefix: &[u8],
        deadline: Instant,
    ) -> Result<crate::AdmissionDecision, NoDecision> {
        // A synchronous decision panics in the call itself.
        let decide = crate::Decision::catch(|| adm.decider().decide(info, prefix));
        let later = match decide {
            None => return Err(NoDecision::Closed),
            Some(crate::Decision::Now(d)) => return Ok(d),
            Some(later @ crate::Decision::Later(_)) => later,
        };
        let listener = self.listener();
        let timed = tokio::time::timeout_at(deadline, later.settle());
        match until(listener.adapter().closed(), timed).await {
            Some(Ok(Some(d))) => Ok(d),
            Some(Err(_)) => Err(NoDecision::Late),
            // Panicked, or cancelled with the listener.
            Some(Ok(None)) | None => Err(NoDecision::Closed),
        }
    }

    /// Counts a final verdict and keeps an acceptance's value and label.
    fn finish(
        &mut self,
        verdict: AdmissionVerdict,
        variant: Option<Arc<str>>,
        mut prefix: Vec<u8>,
    ) -> Admit {
        let shared = self.shared.clone();
        let c = &shared.counts.admission;
        match verdict {
            AdmissionVerdict::Accept { skip, value } => {
                c.count(Outcome::Accepted, variant.as_ref());
                self.admitted = true;
                self.value = value;
                self.variant = variant;
                prefix.drain(..skip);
                Admit::Accept(prefix)
            }
            AdmissionVerdict::Fallback => {
                c.count(Outcome::Fallback, variant.as_ref());
                Admit::Fallback(prefix)
            }
            AdmissionVerdict::Stall if self.start_stall() => {
                c.count(Outcome::Stalled, variant.as_ref());
                Admit::Stall
            }
            AdmissionVerdict::Stall => {
                c.count(Outcome::StallOverflow, None);
                Admit::Close
            }
            _ => {
                c.count(Outcome::Closed, variant.as_ref());
                Admit::Close
            }
        }
    }

    /// Hands `io`, `replay` in front, to the listener's fallback, its slots
    /// given back first, until the fallback completes; without a fallback
    /// it is stalled (not counted as a stall: the decision was a fallback).
    async fn fall_back(&mut self, info: CarrierInfo, replay: Vec<u8>, io: AdmitIo) {
        if self.shared.fallback.is_none() {
            self.stall_io(io).await;
            return;
        }
        if let Some(slot) = self.slot.take() {
            self.shared.lock().core.release(slot);
        }
        self.listener().adapter().take_over(info, io, replay).await;
    }

    /// Stalls `io` ([`Entry::stall`]), then ends its sending half
    /// gracefully, within [`DRAIN_LIMIT`](super::tokio::DRAIN_LIMIT).
    async fn stall_io(&mut self, mut io: AdmitIo) {
        let records = io.framing() == Framing::Records;
        self.stall_reading(io.reader(), records).await;
        let _ = tokio::time::timeout(super::tokio::DRAIN_LIMIT, io.shutdown()).await;
    }

    /// Counts the carrier as stalled: `false` when the listener closed,
    /// the source has `max_pending_per_source - 1` stalled carriers, or
    /// the listener's stalled carriers hold half of `max_pending`.
    fn start_stall(&mut self) -> bool {
        if !self.stalling {
            let mut st = self.shared.lock();
            self.stalling = !st.closed && self.slot.is_some_and(|s| st.core.stall(s));
        }
        self.stalling
    }

    /// Stops counting the carrier as stalled; its slot is gone when a new
    /// carrier evicted it meanwhile.
    fn end_stall(&mut self) {
        if std::mem::take(&mut self.stalling)
            && let Some(slot) = self.slot
        {
            let mut st = self.shared.lock();
            if !st.core.unstall(slot) {
                self.slot = None;
            }
            st.evicted_slots.retain(|&e| e != slot);
        }
    }

    /// Resolves once the listener closes or a new carrier evicts this
    /// stalled one.
    fn closed_or_evicted(&self) -> impl Future<Output = ()> + '_ {
        let mut closing = Closing {
            shared: &self.shared,
            id: None,
            slot: self.slot,
            ticket: None,
        };
        std::future::poll_fn(move |cx| Pin::new(&mut closing).poll(cx))
    }

    /// Gives the slots back without counting anything: for a carrier that
    /// will not be one after all (an HTTP request that turned out to
    /// belong to a carrier already set up), read as far as it goes.
    pub fn release(mut self) {
        self.handshaken = true;
        self.deferred = None;
    }

    /// Stalls a carrier the admission did not accept ([`Admit::Stall`] of
    /// an HTTP request): reads and discards what arrives on `reader` (or
    /// only waits, without one) until it ends, fails, the listener
    /// closes, or a duration in the admission's stall interval has passed,
    /// a function of the source alone for the listener's lifetime (a keyed
    /// MAC of the source, aggregated to its prefix as for every per-source
    /// limit, [`ListenerConfig::source_prefix_v4`]), or a new
    /// carrier that found every slot of the listener taken evicts it. The
    /// slots stay held meanwhile, until the entry is dropped. The caller
    /// then ends the carrier and drops the entry. [`Entry::admit`] stalls
    /// the carriers it decides on itself.
    ///
    /// A source stalls at most `max_pending_per_source - 1` carriers at
    /// once ([`ListenerConfig::max_pending_per_source`]), and the listener
    /// at most half of [`ListenerConfig::max_pending`]: beyond them, a
    /// [`AdmissionVerdict::Stall`] is [`Admit::Close`] (counted in
    /// [`AdmissionStats::stall_overflow`]).
    pub async fn stall<R>(&mut self, reader: Option<&mut R>)
    where
        R: AsyncRead + Unpin + Send,
    {
        self.stall_reading(
            reader.map(|r| r as &mut (dyn AsyncRead + Unpin + Send)),
            false,
        )
        .await;
    }

    /// [`Entry::stall`] of a byte stream or of a message-framed carrier
    /// (`records`), which discards message by message.
    async fn stall_reading(
        &mut self,
        reader: Option<&mut (dyn AsyncRead + Unpin + Send)>,
        records: bool,
    ) {
        let Some(adm) = self.shared.admission.clone() else {
            return;
        };
        if !self.start_stall() {
            return;
        }
        let (min, max) = adm.stall_interval();
        let mac = self.shared.stall_key.mac(&[&self.key.to_be_bytes()]);
        let mut v = [0u8; 16];
        v.copy_from_slice(&mac[..16]);
        let span = max.saturating_sub(min).as_nanos() + 1;
        let off = u64::try_from(u128::from_be_bytes(v) % span).unwrap_or(u64::MAX);
        let duration = min.saturating_add(Duration::from_nanos(off));
        let wait = async {
            match reader {
                Some(r) => discard(r, adm.discard_buffer(), duration, records).await,
                None => tokio::time::sleep(duration).await,
            }
        };
        let _ = until(self.closed_or_evicted(), wait).await;
        self.end_stall();
    }

    /// Moves the slot to `source`, the client a trusted intermediary
    /// reported in the request the carrier's outer handshake read (a
    /// WebSocket upgrade's forwarding header field): `false` when that
    /// source has its share, and the carrier is closed at once (counted
    /// as refused).
    pub fn set_source(&mut self, source: SocketAddr) -> bool {
        let (key, moved) = {
            let mut st = self.shared.lock();
            let key = st.core.config().source_key(source.ip());
            let moved = key == self.key || self.slot.is_some_and(|s| st.core.move_slot(s, key));
            (key, moved)
        };
        if key != self.key {
            if !moved {
                self.shared.counts.refused.fetch_add(1, Relaxed);
                // Refused, not a failed handshake.
                self.handshaken = true;
                return false;
            }
            self.key = key;
        }
        self.source = source;
        true
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        let c = &self.shared.counts;
        if !self.handshaken {
            if self.shared.admission.is_some() {
                &c.admission.handshake_failed
            } else {
                &c.setup_failures
            }
            .fetch_add(1, Relaxed);
        }
        if self.deferred.take().is_some() {
            // A deferred decision that never came: its carrier did not
            // arrive in time, or ended first.
            let late = self.deadline.is_some_and(|d| Instant::now() >= d);
            let outcome = if late {
                Outcome::PeekTimedOut
            } else {
                Outcome::Closed
            };
            c.admission.count(outcome, None);
        }
        self.end_stall();
        if let Some(slot) = self.slot.take() {
            self.shared.lock().core.release(slot);
        }
    }
}

/// The address of a carrier the host gave without one.
const NO_ADDR: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// A listener: hand it every new carrier. It starts a
/// session for a carrier that opens one and routes a carrier that joins an
/// existing session to it, after verifying its Hello.
///
/// # Example
///
/// A multipath server and a client with two TCP pipes on one machine:
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions, Session};
///
/// let mut config = Config::default();
/// config.max_pipes = 8;
/// config.pipe_auth = PipeAuth::psk(b"a pre-shared key, 16 bytes or more".to_vec()).with_end_to_end();
///
/// let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
/// let addr = tcp.local_addr()?;
/// let listener = Listener::new(config.clone(), ListenerConfig::default()).expect("valid listener configuration");
/// let l = listener.clone();
/// tokio::spawn(async move {
///     while let Ok((carrier, peer)) = tcp.accept().await {
///         let l = l.clone();
///         tokio::spawn(async move {
///             let _ = l.handle_pipe(PipeIo::from_tcp(carrier), PipeHint::from_peer(peer)).await;
///         });
///     }
/// });
/// tokio::spawn(async move {
///     while let Some(session) = listener.accept().await {
///         tokio::spawn(async move {
///             while let Ok((mut send, mut recv)) = session.accept_bi().await {
///                 let data = recv.read_to_end(1 << 20).await.unwrap_or_default();
///                 let _ = send.write_all(&data).await;
///                 let _ = send.finish();
///             }
///         });
///     }
/// });
///
/// let first = tokio::net::TcpStream::connect(addr).await?;
/// let session = Session::connect(PipeIo::from_tcp(first), config).await?;
/// let second = tokio::net::TcpStream::connect(addr).await?;
/// let pipe = session.add_pipe(PipeIo::from_tcp(second), PipeOptions::default()).await?;
/// // The second path is the fallback: it carries data only while the
/// // first one is saturated or has failed, and the server is asked to do
/// // the same on its side.
/// pipe.update(&zmux::PipeUpdate {
///     send_priority: zmux::Change::Set(10),
///     receive_priority: zmux::Change::Set(10),
///     ..Default::default()
/// })?;
///
/// let (mut send, mut recv) = session.open_bi().await?;
/// send.write_all(b"over two pipes").await?;
/// send.finish()?;
/// assert_eq!(recv.read_to_end(1 << 20).await?, b"over two pipes");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Listener {
    shared: Arc<ListenShared>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Listener")
    }
}

/// A pipe a join attached whose carrier task does not run yet: forgotten
/// (it fails) when dropped armed, so that a handler that ends early, also
/// by its future being dropped, leaves no pipe without a carrier.
struct AttachedPipe<'a> {
    session: &'a Arc<Shared<Tokio>>,
    pipe: Option<PipeId>,
}

impl AttachedPipe<'_> {
    /// Abandons the pipe for a limit (`ZMUX_PIPE_RESOURCE_LIMIT`).
    fn abandon(&mut self) {
        if let Some(p) = self.pipe.take() {
            self.session.drop_pipe(p);
        }
    }
}

impl Drop for AttachedPipe<'_> {
    fn drop(&mut self) {
        if let Some(p) = self.pipe.take() {
            self.session.forget_pipe(p);
        }
    }
}

impl Listener {
    /// The listener's operations for carrier adapters and own accept
    /// loops: carrier slots, admission, join lookups, memory charges and
    /// setup-failure counts ([`ListenerAdapter`]).
    #[must_use]
    pub fn adapter(&self) -> ListenerAdapter<'_> {
        ListenerAdapter { listener: self }
    }
}

/// The operations of a [`Listener`] that only carrier adapters and own
/// accept loops use ([`Listener::adapter`]): an application that serves
/// through the listener's `serve` entries or a carrier crate needs none of
/// them.
#[derive(Debug, Clone, Copy)]
pub struct ListenerAdapter<'a> {
    listener: &'a Listener,
}

impl<'a> ListenerAdapter<'a> {
    /// The first step of every carrier at every entry of the listener,
    /// before its outer handshake: a source slot (`source`, or `peer` when
    /// unset; counted by its prefix, [`ListenerConfig::source_prefix_v4`])
    /// and a slot of the
    /// listener, held by the returned [`Entry`]. With every slot of the
    /// listener taken, the carrier stalled longest is closed to make room.
    /// `None`: close the carrier at once, without a handshake; counted as
    /// refused when the source has its share or the listener is closed,
    /// as rejected when every slot is taken and none is stalled. Then the
    /// outer handshake, [`Entry::admit`], and [`Listener::handle_pipe`].
    #[must_use]
    pub fn enter(&self, peer: SocketAddr, source: Option<SocketAddr>) -> Option<Entry> {
        self.listener
            .enter_uncounted(peer, source)
            .map_err(|e| self.listener.count(e))
            .ok()
    }

    /// The listener's admission ([`ListenerConfig::admission`]).
    #[must_use]
    pub fn admission(&self) -> Option<&'a Admission> {
        self.listener.shared.admission.as_ref()
    }

    /// Whether the listener has a fallback ([`ListenerConfig::fallback`]).
    #[must_use]
    pub fn has_fallback(&self) -> bool {
        self.listener.shared.fallback.is_some()
    }

    /// Hands a connection that never became a carrier to the listener's
    /// fallback ([`ListenerConfig::fallback`]), `replay` (what the adapter
    /// read of it) in front: for an adapter's own refusals, such as a
    /// request on a WebSocket server that is no upgrade. Resolves once the
    /// fallback completed (at once without one, the connection dropped).
    /// Counted nowhere: the adapter counts the refusal. The carriers the
    /// admission hands back reach the fallback through [`Entry::admit`].
    pub async fn take_over(&self, info: CarrierInfo, io: AdmitIo, replay: Vec<u8>) {
        let Some(f) = self.listener.shared.fallback.clone() else {
            return;
        };
        let info = info.with_framing(io.framing());
        if !f.serve(io.into_takeover(info, replay)).await
            && let Some(l) = &self.listener.shared.logger
        {
            l.log(
                crate::LogLevel::Error,
                "zmux: the listener's fallback panicked; its carrier is closed",
            );
        }
    }

    /// For use in an admission's decision: whether `prefix`, a byte-stream
    /// carrier's first bytes, begins a Join Hello (first byte `02`) whose
    /// Locator names a session of the listener at this moment. While the
    /// prefix is shorter than the Hello's clear head (through the nonce,
    /// at most 291 bytes for the suites defined) the answer is
    /// [`JoinPrefix::Need`], to ask for with [`AdmissionVerdict::More`]
    /// ([`Admission::with_max_peek`] must allow it). On a
    /// message-framed carrier the prefix is the whole message, and `Need`
    /// means it is too short. Advisory: the join still authenticates, and
    /// one whose session ended meanwhile is an unknown Locator.
    #[must_use]
    pub fn join_prefix(&self, prefix: &[u8]) -> JoinPrefix {
        use crate::proto::seal::{Error, join::JoinHello};
        match JoinHello::head_locator(prefix) {
            Ok(l) if self.listener.shared.locators.get(l).is_some() => JoinPrefix::Known,
            Ok(_) => JoinPrefix::Unknown,
            Err(Error::Incomplete { need }) => JoinPrefix::Need(need),
            Err(_) => JoinPrefix::NotJoin,
        }
    }

    /// The intermediaries the listener trusts to report a carrier's client
    /// ([`ListenerConfig::trusted_proxies`]): its adapters take a carrier's
    /// source from them.
    #[must_use]
    pub fn trusted_proxies(&self) -> &'a crate::proto::trusted::TrustedProxies {
        &self.listener.shared.trusted
    }

    /// Whether the listener is closed ([`Listener::close`]): an adapter
    /// tells with it why [`ListenerAdapter::enter`] gave no place.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.listener.shared.lock().closed
    }

    /// Resolves once the listener is closed ([`Listener::close`]): for
    /// accept loops of carriers, which end with it. Cancel-safe.
    pub async fn closed(self) {
        Closing {
            shared: &self.listener.shared,
            id: None,
            slot: None,
            ticket: None,
        }
        .await;
    }

    /// A guard for a connection's setup that holds no [`Entry`] (the TLS
    /// handshake of an HTTP connection, whose requests enter the listener
    /// one by one): dropped before [`SetupGuard::done`], it counts a setup
    /// failure ([`ListenerStats::setup_failures`]).
    #[must_use]
    pub fn setup_guard(&self) -> SetupGuard {
        SetupGuard(Some(self.listener.shared.clone()))
    }

    /// Counts `bytes` that a carrier holds for the listener's sessions in
    /// its memory budget for as long as the charge
    /// lives: for example the receive window of a QUIC connection whose
    /// streams carry their pipes and lanes.
    #[must_use]
    pub fn charge_memory(&self, bytes: u64) -> MemoryCharge {
        self.listener.shared.account.charge(bytes, 0);
        MemoryCharge {
            account: self.listener.shared.account.clone(),
            bytes,
        }
    }

    /// Counts a connection that an accept loop could not make a pipe input
    /// of: a failed TLS handshake or its timeout (the handshake a join sent
    /// in early data waits for included), a failed HTTP or WebSocket
    /// upgrade, or the setup limit. For carrier adapters' own accept loops
    /// ([`ListenerStats::setup_failures`]); such a connection is counted
    /// nowhere else.
    pub fn count_setup_failure(&self) {
        self.listener
            .shared
            .counts
            .setup_failures
            .fetch_add(1, Relaxed);
    }
}

impl Listener {
    /// A listener that starts sessions with `config` and applies `limits`.
    /// Must be created inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// [`ConnectError::InvalidConfig`](crate::ConnectError::InvalidConfig) when `config` is not valid, or
    /// `limits.instance_id` is longer than [`MAX_INSTANCE_ID_LEN`](crate::MAX_INSTANCE_ID_LEN). The
    /// secret source of each session is checked as its first carrier
    /// arrives, since its first pipe may be a secure carrier.
    pub fn new(
        config: impl Into<Arc<Config>>,
        limits: ListenerConfig,
    ) -> Result<Self, crate::ConnectError> {
        limits
            .validate()
            .map_err(crate::ConnectError::InvalidConfig)?;
        let config = config.into();
        config
            .validate()
            .map_err(crate::ConnectError::InvalidConfig)?;
        let stall_max = limits
            .admission
            .as_ref()
            .map_or_else(crate::proto::admission::draw_stall_max, |a| {
                a.stall_interval().1
            });
        let instance_id = limits.instance_id.clone();
        let trusted = limits.trusted_proxies.clone();
        let admission = limits.admission.clone();
        let fallback = limits.fallback.clone();
        let transform = limits.inbound_transform.clone();
        let on_reject = limits.on_reject.clone();
        let logger = limits.logger.clone();
        let account = Account::new(
            limits.memory_budget,
            limits.max_suspended,
            limits.on_memory_pressure.clone(),
            super::account::HookContext::Task,
        )
        .ok_or_else(|| {
            crate::ConnectError::InvalidConfig(crate::InvalidConfig::new(
                "ListenerConfig::on_memory_pressure",
                "its hook runs on a tokio runtime: create the listener inside one",
            ))
        })?;
        let mut stall_key = [0u8; 32];
        for c in stall_key.as_chunks_mut::<8>().0 {
            *c = random_u64().to_le_bytes();
        }
        let shared = Arc::new(ListenShared {
            locators: handle::LocatorTable::default(),
            counts: Counts::default(),
            account,
            state: Mutex::new(State_ {
                core: Core::new(limits),
                accept: VecDeque::new(),
                accept_waiters: WaitList::default(),
                close_waiters: WaitList::default(),
                evicted: Vec::new(),
                evicted_slots: Vec::new(),
                pairs: HashMap::new(),
                live: Vec::new(),
                live_pruned: 0,
                draining: false,
                closed: false,
            }),
            config,
            instance_id,
            stall_key: HmacSha256::new(&stall_key),
            trusted,
            admission,
            fallback,
            transform,
            on_reject,
            stall_max,
            logger,
            _live: Live::new(Kind::Listener),
        });
        Ok(Self { shared })
    }

    /// The response to a refused carrier `id` (none: one not yet
    /// registered): the policy's, or the default. A later answer is bounded
    /// by the handshake timeout from now, the listener's close and the
    /// carrier's eviction; one that panics, misses them or is stopped closes
    /// the carrier.
    async fn reject_response(&self, info: &RejectInfo, id: Option<CarrierId>) -> RejectAction {
        let Some(f) = &self.shared.on_reject else {
            return RejectAction::default_for(info);
        };
        let deadline = self.handshake_deadline();
        if let Some(a) = super::hooks::settle_by(f.ask(info), deadline, self.closed_or_evicted(id))
            .await
            .flatten()
        {
            a
        } else {
            if let Some(l) = &self.shared.logger {
                l.log(
                    crate::LogLevel::Error,
                    "zmux: on_reject panicked or missed the handshake deadline; the carrier is closed",
                );
            }
            RejectAction::Close
        }
    }

    /// The handshake timeout from now; `None` when it does not end.
    fn handshake_deadline(&self) -> Option<std::time::Instant> {
        let timeout = self.shared.lock().core.config().handshake_timeout;
        now().checked_add(timeout)
    }

    /// Stalls a refused carrier, which keeps its slots meanwhile, until
    /// `wait` ends, the listener closes or a new carrier evicts it; closed
    /// at once (counted as `stall_overflow`) when it holds no slot, its
    /// source holds its maximum of stalls or the listener's stalls hold
    /// half of its slots.
    async fn stall_refused(&self, entry: Option<&mut Entry>, wait: impl Future<Output = ()>) {
        let Some(entry) = entry.and_then(|e| e.start_stall().then_some(e)) else {
            self.shared
                .counts
                .admission
                .stall_overflow
                .fetch_add(1, Relaxed);
            return;
        };
        let _ = until(entry.closed_or_evicted(), wait).await;
        entry.end_stall();
    }

    /// Counts a carrier the listener did not use.
    fn count(&self, e: HandleError) {
        let c = &self.shared.counts;
        match e {
            HandleError::Rejected => &c.rejected,
            HandleError::Refused => &c.refused,
            HandleError::TimedOut => &c.timed_out,
            HandleError::SetupFailed => &c.setup_failures,
            // Counted by the admission.
            HandleError::NotAdmitted => return,
        }
        .fetch_add(1, Relaxed);
    }

    fn enter_uncounted(
        &self,
        peer: SocketAddr,
        source: Option<SocketAddr>,
    ) -> Result<Entry, HandleError> {
        let source = source.unwrap_or(peer);
        // The evicted carrier is woken after the lock.
        let mut wakes = WakeList::default();
        let (key, slot) = {
            let mut st = self.shared.lock();
            let key = st.core.config().source_key(source.ip());
            if st.closed {
                return Err(HandleError::Refused);
            }
            match st.core.enter(key) {
                Entered::Taken { slot, evicted } => {
                    st.evict_slot(evicted, &mut wakes);
                    (key, slot)
                }
                Entered::SourceFull => return Err(HandleError::Refused),
                Entered::Full => return Err(HandleError::Rejected),
            }
        };
        drop(wakes);
        Ok(Entry {
            shared: self.shared.clone(),
            key,
            slot: Some(slot),
            stalling: false,
            variant: None,
            source,
            peer,
            admitted: false,
            handshaken: false,
            deadline: None,
            deferred: None,
            value: None,
        })
    }

    /// The next session a carrier started, once established. `None` after
    /// [`Listener::close`] or once [`Listener::shutdown`] began.
    /// Cancel-safe.
    pub async fn accept(&self) -> Option<Session> {
        Accept {
            shared: &self.shared,
            ticket: None,
        }
        .await
    }

    /// Closes at once: `accept` returns `None`; every new carrier is
    /// refused, joins and resumptions included, carriers still in their
    /// handshake, admission or waiting for their first record are given
    /// up, the serve loops end, and sessions established but not accepted
    /// are closed (with code 0). Sessions accepted go on.
    pub fn close(&self) {
        let mut wakes = WakeList::default();
        let mut st = self.shared.lock();
        st.closed = true;
        st.accept_waiters.wake_all(&mut wakes);
        st.close_waiters.wake_all(&mut wakes);
        // Nobody accepts these any more: queued, each would keep itself,
        // its carrier task and this listener alive for as long as its
        // peer.
        let unaccepted = std::mem::take(&mut st.accept);
        for _ in 0..unaccepted.len() {
            st.core.release_unaccepted();
        }
        // Woken and dropped (each takes its session's lock) after the
        // listener's lock.
        drop(st);
        drop(unaccepted);
    }

    /// Closes gracefully: `accept` returns `None` and new sessions are
    /// refused at once, while the listener goes on taking the joins and
    /// resumptions of its live sessions, through every entry; it shuts
    /// every session down with `code` and `reason`
    /// ([`Session::shutdown`](Session#method.shutdown)), and once they all ended it closes
    /// ([`Listener::close`]). Cancelled (the future dropped, for example by
    /// `tokio::time::timeout` at a deadline), it closes the listener and
    /// the sessions left at once.
    pub async fn shutdown(&self, code: VarInt, reason: &[u8]) {
        // Closes the listener however the shutdown ends.
        struct CloseOnDrop<'a>(&'a Listener);
        impl Drop for CloseOnDrop<'_> {
            fn drop(&mut self) {
                self.0.close();
            }
        }

        let (sessions, unaccepted) = {
            let mut wakes = WakeList::default();
            let mut st = self.shared.lock();
            st.draining = true;
            st.accept_waiters.wake_all(&mut wakes);
            let unaccepted = std::mem::take(&mut st.accept);
            for _ in 0..unaccepted.len() {
                st.core.release_unaccepted();
            }
            let live: Vec<_> = st
                .live
                .iter()
                .filter_map(|w| WeakSession::from_weak(w.clone()).upgrade())
                .collect();
            (live, unaccepted)
        };
        drop(unaccepted);
        let _close = CloseOnDrop(self);
        // Dropped, the set aborts the shutdowns, which close their sessions
        // at once.
        let mut set = tokio::task::JoinSet::new();
        for s in sessions {
            let reason = reason.to_vec();
            set.spawn(async move {
                let _ = s.shutdown(code, &reason).await;
            });
        }
        while set.join_next().await.is_some() {}
    }

    /// The session configuration of the sessions it starts.
    #[must_use]
    pub fn config(&self) -> &Arc<Config> {
        &self.shared.config
    }

    /// The listener's limits.
    #[must_use]
    pub fn limits(&self) -> ListenerConfig {
        self.shared.lock().core.config().clone()
    }

    /// Serves a TCP listener until [`Listener::close`]: every connection
    /// it accepts becomes a carrier ([`PipeIo::from_tcp`]), its source the
    /// peer or the client a trusted intermediary reports in a PROXY
    /// protocol header ([`ListenerConfig::trusted_proxies`],
    /// [`crate::adapter::proxied_source`]), admitted by the listener's admission
    /// and handed to [`Listener::handle_pipe`], as
    /// [`Listener::serve_streams`] says. Run it in a task of its own:
    ///
    /// ```no_run
    /// # async fn example() -> std::io::Result<()> {
    /// use zmux::{Config, Listener, ListenerConfig, PipeAuth};
    ///
    /// let config = Config::multipath(PipeAuth::psk(*b"a pre-shared key of 32 bytes...."));
    /// let listener = Listener::new(config, ListenerConfig::default()).expect("valid listener configuration");
    /// let tcp = tokio::net::TcpListener::bind("0.0.0.0:4433").await?;
    /// tokio::spawn(listener.clone().serve(tcp));
    /// while let Some(session) = listener.accept().await {
    ///     // ...
    /// #   drop(session);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn serve(self, tcp: tokio::net::TcpListener) {
        self.serve_streams(
            || tcp.accept(),
            |stream| std::future::ready(Ok(stream)),
            |_: &tokio::net::TcpStream| CarrierInfo::new(),
            PipeIo::from_tcp,
        )
        .await;
    }

    /// Serves any listening byte-stream socket until [`Listener::close`]:
    /// `accept` yields a connection and its peer's address. Each
    /// connection, in a task of its own: a connection from an intermediary
    /// the listener trusts to send the PROXY protocol has its header read
    /// first ([`crate::adapter::proxied_source`]), and the client it reports is the
    /// source; the connection enters the listener ([`ListenerAdapter::enter`]:
    /// refused at once when its source has its share); `setup` (a TLS
    /// handshake) runs within the listener's handshake timeout; the
    /// listener's admission reads the prefix and decides with the metadata
    /// `info` gives (the source and peer filled in); an accepted
    /// connection becomes a carrier by `carrier`, handed to
    /// [`Listener::handle_pipe`] with the rest of the prefix in front
    /// ([`PipeIo::with_prefix`]); one decided on with Fallback goes to
    /// [`ListenerConfig::fallback`], every byte read replayed, or is
    /// stalled without one. Each connection holds its slots of the
    /// listener ([`ListenerAdapter::enter`]) from before its setup. Nothing is written on a connection before it is accepted.
    pub async fn serve_streams<T, A, AF, S, SF, C, I, P>(
        self,
        mut accept: A,
        setup: S,
        info: I,
        carrier: P,
    ) where
        A: FnMut() -> AF,
        AF: Future<Output = std::io::Result<(T, SocketAddr)>>,
        T: AsyncRead + Unpin + Send + 'static,
        S: Fn(T) -> SF + Send + Sync + 'static,
        SF: Future<Output = std::io::Result<C>> + Send + 'static,
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        I: Fn(&C) -> CarrierInfo + Send + Sync + 'static,
        P: Fn(C) -> PipeIo + Send + Sync + 'static,
    {
        let trusted = Arc::new(self.shared.trusted.clone());
        let setup = Arc::new(setup);
        let (info, carrier) = (Arc::new(info), Arc::new(carrier));
        let l = self.clone();
        self.serve_connections(
            || {
                let next = accept();
                async move { Some(next.await) }
            },
            move |(mut conn, peer): (T, SocketAddr)| {
                let (trusted, setup, l) = (trusted.clone(), setup.clone(), l.clone());
                async move {
                    let Ok(source) =
                        super::admission::proxied_source(&mut conn, peer, &trusted).await
                    else {
                        l.adapter().count_setup_failure();
                        return Err(());
                    };
                    let entry = l.adapter().enter(peer, Some(source)).ok_or(())?;
                    // A failed handshake counts with the entry dropped.
                    let conn = setup(conn).await.map_err(drop)?;
                    Ok((conn, entry))
                }
            },
            move |l, (conn, mut entry): (C, Entry)| {
                let (info, carrier) = (info.clone(), carrier.clone());
                async move {
                    let meta = info(&conn);
                    let io = AdmitIo::stream(conn, move |c| carrier(c));
                    if let Some(io) = entry.admit(meta, io).await {
                        let _ = l.handle_pipe(io, PipeHint::from_entry(entry)).await;
                    }
                }
            },
        )
        .await;
    }

    /// The listener's one accept loop, for carriers of every kind: until
    /// [`Listener::close`], or until `accept` yields `None` (its source
    /// ended), each connection `accept` yields is set up by `setup` in a
    /// task of its own (entering the listener, a TLS or QUIC handshake, a
    /// WebSocket upgrade), within the listener's `handshake_timeout`, and
    /// then served by `serve` for as long as it needs (handing its
    /// carriers to [`Listener::handle_pipe`], for example). A setup that
    /// enters the listener ([`ListenerAdapter::enter`]) holds its slots from
    /// then on; whatever a setup does before it enters, or when it never
    /// does (a connection whose carriers enter one by one), at most
    /// `max_pending` of the listener's limits are in setup at once: a new
    /// connection beyond them ends the oldest setup, so that slow
    /// handshakes can neither pile up nor lock new clients out. A setup counts its own
    /// failures: an [`Entry`] dropped before its admission counts its
    /// handshake as failed, and a setup without one calls
    /// [`ListenerAdapter::count_setup_failure`] (or holds a
    /// [`ListenerAdapter::setup_guard`]); one ended by its timeout or for a
    /// newer one, or still running when the listener is closed, is dropped.
    /// Serving goes on after the close: it carries the sessions already
    /// accepted. Accept errors (a connection reset before it was accepted,
    /// no file descriptors left) are retried after a pause of up to
    /// 100 ms.
    ///
    /// The loop holds a handle of the listener until it ends.
    pub async fn serve_connections<T, A, AF, S, SF, C, E, H, HF>(
        self,
        mut accept: A,
        setup: S,
        serve: H,
    ) where
        A: FnMut() -> AF,
        AF: Future<Output = Option<std::io::Result<T>>>,
        S: Fn(T) -> SF,
        SF: Future<Output = Result<C, E>> + Send + 'static,
        C: Send + 'static,
        H: Fn(Listener, C) -> HF + Send + Sync + 'static,
        HF: Future<Output = ()> + Send + 'static,
    {
        let limits = self.limits();
        let (limit, most) = (limits.handshake_timeout, limits.max_pending);
        let serve = Arc::new(serve);
        // The setup tasks, oldest first; each spawns its serving apart, so
        // that aborting it ends only the setup.
        let mut setups = SetupTasks::default();
        while let Some(Some(accepted)) = self.accept_or_close(accept()).await {
            let conn = match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    accept_failed(&e).await;
                    continue;
                }
            };
            setups.make_room(most);
            let (l, made, serve) = (self.clone(), setup(conn), serve.clone());
            let task = tokio::spawn(async move {
                let made = l.accept_or_close(tokio::time::timeout(limit, made)).await;
                if let Some(Ok(Ok(c))) = made {
                    tokio::spawn(async move { serve(l, c).await });
                }
            });
            setups.push(task.abort_handle());
        }
    }

    /// `accept`'s result, or `None` once the listener is closed.
    async fn accept_or_close<T>(&self, accept: impl Future<Output = T>) -> Option<T> {
        let mut accept = std::pin::pin!(accept);
        let mut closed = std::pin::pin!(self.adapter().closed());
        std::future::poll_fn(|cx| {
            if closed.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            accept.as_mut().poll(cx).map(Some)
        })
        .await
    }

    /// Handles a new carrier: a new session (returned by
    /// [`Listener::accept`]) or a join of an existing one. A carrier that
    /// did not enter the listener through an adapter
    /// ([`PipeHint::from_entry`]) enters here: it takes a source slot (its
    /// hint's source, or peer), and the listener's admission reads its
    /// prefix and decides ([`Entry::admit`]); a carrier not accepted is
    /// stalled or closed ([`HandleError::NotAdmitted`]). Resolves when the
    /// carrier is done, so that an HTTP handler stays alive with its pipe.
    /// A join over a stream of a session that runs over the session it
    /// joins ([`PipeIo::from_stream`]) is refused: the carrier is closed
    /// and the session sends `PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT)`.
    ///
    /// The first poll decides whether the listener takes the carrier at
    /// all, before any I/O or wait: a closed listener's carrier resolves
    /// `Err(HandleError::Refused)` on it, and so does one that came with its
    /// entry ([`PipeHint::from_entry`]) when the listener has no place for
    /// it. A caller that must answer at once (an HTTP exchange) may poll
    /// once with a no-op waker to learn that.
    ///
    /// # Errors
    ///
    /// The [`HandleError`] that says why the carrier was not used.
    pub fn handle_pipe(
        &self,
        pipe: PipeIo,
        hint: PipeHint,
    ) -> impl Future<Output = Result<(), HandleError>> + Send + '_ {
        // The setup's state (admission, transform, first record), the
        // carrier and its hint included, is boxed now and freed once it is
        // done: what waits for the pipe's end is small, as it is kept for
        // the pipe's lifetime.
        let setup = Box::pin(self.handle(pipe, hint));
        async move {
            let r = match setup.await {
                Ok(end) => {
                    end.wait().await;
                    Ok(())
                }
                Err(e) => Err(e),
            };
            if let Err(e) = r {
                self.count(e);
            }
            r
        }
    }

    /// The admission's verdicts on the carriers it labelled, per label.
    pub fn variant_stats(&self) -> AdmissionVariants {
        self.shared
            .counts
            .admission
            .variants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What happened to the carriers handed to the listener, and to the
    /// connections its `serve` loops set up: counts since it was made, for
    /// monitoring (a server whose certificate is wrong sees only setup
    /// failures).
    #[must_use]
    pub fn stats(&self) -> ListenerStats {
        let c = &self.shared.counts;
        ListenerStats {
            sessions: c.sessions.load(Relaxed),
            joins: c.joins.load(Relaxed),
            setup_failures: c.setup_failures.load(Relaxed),
            rejected: c.rejected.load(Relaxed),
            refused: c.refused.load(Relaxed),
            timed_out: c.timed_out.load(Relaxed),
            admission: {
                let a = &c.admission;
                AdmissionStats {
                    accepted: a.accepted.load(Relaxed),
                    fallback: a.fallback.load(Relaxed),
                    stalled: a.stalled.load(Relaxed),
                    closed: a.closed.load(Relaxed),
                    stall_overflow: a.stall_overflow.load(Relaxed),
                    too_large: a.too_large.load(Relaxed),
                    peek_timed_out: a.peek_timed_out.load(Relaxed),
                    handshake_failed: a.handshake_failed.load(Relaxed),
                }
            },
        }
    }

    /// The carrier's entry: the adapter's, or one taken now, with the
    /// listener's admission applied to the carrier ([`Entry::admit`]).
    async fn entered(
        &self,
        pipe: PipeIo,
        hint: &mut PipeHint,
    ) -> Result<(PipeIo, Entry), HandleError> {
        let mut entry = if let Some(e) = hint.entry.take() {
            e
        } else {
            let peer = hint.peer.or(hint.source).unwrap_or(NO_ADDR);
            let mut e = self.enter_uncounted(peer, hint.source)?;
            // No outer handshake here.
            e.handshaken = true;
            e.admitted = hint.connection.is_some();
            e
        };
        if entry.admitted {
            return Ok((pipe, entry));
        }
        match entry.admit(CarrierInfo::new(), pipe).await {
            Some(pipe) => Ok((pipe, entry)),
            None => Err(HandleError::NotAdmitted),
        }
    }

    /// Sets up a carrier: what its pipe's end is waited for with, if it
    /// became a pipe.
    async fn handle(&self, mut pipe: PipeIo, mut hint: PipeHint) -> Result<PipeEnd, HandleError> {
        let shared = &self.shared;
        // Decided on the first poll (see `handle_pipe`).
        if shared.lock().closed {
            return Err(HandleError::Refused);
        }
        // A stream that may be a lane of a pipe on its connection waits
        // for its first record outside the limits: its connection was
        // admitted, and it takes a slot once it turns out a join or a
        // new session.
        let mut exempt = pipe.conn().and_then(super::lanes::Exempt::new);
        let mut entry = if exempt.is_some() {
            // Its adapter's entry, if any, is given back: it waits outside
            // the slots.
            hint.entry = None;
            None
        } else {
            let (admitted, entry) = self.entered(pipe, &mut hint).await?;
            pipe = admitted;
            Some(entry)
        };
        // The admission's value goes with the carrier, whatever the caller
        // set: to the transform, the session and the pipe.
        let value = entry
            .as_ref()
            .and_then(|e| e.value.clone())
            .or_else(|| hint.connection.as_ref().and_then(|a| a.value.clone()));
        hint.value.clone_from(&value);
        pipe.admitted = value.map(Box::new);
        if let Some(v) = entry.as_mut().and_then(|e| e.variant.take())
            && pipe.variant.is_none()
        {
            pipe.variant = Some(v);
        }
        // A half is not transformed: a handshake needs both directions.
        if let Some(token) = hint.pair.take() {
            return self.handle_paired(pipe, hint, entry.take(), &token).await;
        }
        if let Some(t) = shared.transform.clone() {
            pipe = self.transform(&t, pipe, &hint, entry.as_mut()).await?;
        }
        pipe.resolve_exporter(self.handshake_deadline()).await;
        let now = now();
        let (limits, id) = {
            let mut st = shared.lock();
            if st.closed {
                return Err(HandleError::Refused);
            }
            let limits = st.core.config().clone();
            let id = if entry.is_some() {
                st.core.open(None, pipe.framing, now)
            } else {
                st.core.open_stream(pipe.framing, now)
            };
            (limits, id)
        };
        // Leaves the pending carriers and gives its slots back however this
        // ends, a dropped handler included.
        let mut pending = Pending {
            shared,
            id,
            done: false,
            slot: entry,
        };
        let classified = {
            let first = tokio::time::timeout(
                limits.first_record_timeout,
                Self::first_record(shared, id, &mut pipe),
            );
            let mut first = std::pin::pin!(first);
            let mut closing = Closing {
                shared,
                id: Some(id),
                slot: None,
                ticket: None,
            };
            // The first record, its timeout, or the listener's close.
            let r = std::future::poll_fn(|cx| {
                if let Poll::Ready(r) = first.as_mut().poll(cx) {
                    return Poll::Ready(Some(r));
                }
                Pin::new(&mut closing).poll(cx).map(|()| None)
            })
            .await;
            match r {
                Some(Ok(c)) => c,
                Some(Err(_)) => return Err(HandleError::TimedOut),
                None => return Err(HandleError::Refused),
            }
        };
        if !matches!(classified, Classified::Reject)
            && let Some(taken) = pipe.taken.take()
        {
            taken();
        }
        // Its first record is in: a lane goes on without a slot; a join or
        // a new session takes one now, like any carrier.
        if exempt.take().is_some()
            && matches!(
                classified,
                Classified::NewSession { .. } | Classified::Join { .. }
            )
        {
            let peer = hint.peer.or(hint.source).unwrap_or(NO_ADDR);
            match self.enter_uncounted(peer, hint.source) {
                Ok(mut e) => {
                    e.handshaken = true;
                    e.admitted = true;
                    pending.slot = Some(e);
                }
                Err(err) => {
                    // Known to be a join or a session now: the reject policy, though
                    // without a slot it cannot be stalled.
                    let profile = matches!(classified, Classified::Join { .. }).then_some(2);
                    let info =
                        RejectInfo::new(profile, None, "pending_limit", hint.source.or(hint.peer));
                    self.refuse(&info, None, None).await;
                    return Err(err);
                }
            }
        }
        match classified {
            Classified::NewSession { first } => {
                let slot = pending.slot.take();
                pending.done();
                pipe.prefix = first;
                self.start_session(pipe, (hint.source, hint.peer), slot)
                    .await
            }
            Classified::Lane {
                lane_key,
                pipe: id,
                lane,
                bytes,
            } => {
                pending.done();
                super::lanes::route(pipe, &lane_key, PipeId(id).lane(lane), bytes)?;
                shared.counts.joins.fetch_add(1, Relaxed);
                Ok(PipeEnd::default())
            }
            Classified::BadHello { reason } => {
                self.rejected(&mut pending, reason, None, hint.source.or(hint.peer))
                    .await
            }
            Classified::Join { locator, hello } => {
                self.join(
                    &mut pending,
                    &locator,
                    &hello,
                    pipe,
                    &limits,
                    hint.source.or(hint.peer),
                )
                .await
            }
            // First bytes that are no carrier this listener knows (step 2).
            _ => {
                let info = RejectInfo::new(None, None, "malformed", hint.source.or(hint.peer));
                self.refuse(&info, None, pending.slot.as_mut()).await;
                Err(HandleError::Rejected)
            }
        }
    }

    /// Applies the inbound transform to `pipe`, within the handshake
    /// timeout and until the listener closes: a result of another kind, an
    /// error or the bound is a setup failure, and the carrier is dropped.
    /// A refusal goes to the reject policy, a stall keeping `entry`'s slots.
    async fn transform(
        &self,
        t: &InboundTransform,
        mut pipe: PipeIo,
        hint: &PipeHint,
        entry: Option<&mut Entry>,
    ) -> Result<PipeIo, HandleError> {
        // The transform reads the carrier: it is the listener's now, never
        // handed on with bytes replayed.
        if let Some(taken) = pipe.taken.take() {
            taken();
        }
        let kind = (
            pipe.reader.is_some(),
            pipe.writer.is_some(),
            pipe.framing,
            pipe.split_bootstrap,
        );
        let (carrier, value) = (pipe.carrier, pipe.admitted.take());
        let source = hint.source.or(hint.peer);
        let timeout = self.shared.lock().core.config().handshake_timeout;
        let timed = tokio::time::timeout(timeout, t.call(pipe, hint));
        let mut timed = std::pin::pin!(timed);
        let mut closed = std::pin::pin!(self.adapter().closed());
        let r = std::future::poll_fn(|cx| {
            if closed.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            timed.as_mut().poll(cx).map(Some)
        })
        .await;
        let mut io = match r {
            Some(Ok(Ok(io))) => io,
            None => return Err(HandleError::Refused),
            Some(Ok(Err(e))) => {
                let inner = e.get_ref();
                let refused =
                    inner.and_then(|e| e.downcast_ref::<crate::proto::listener::Refused<PipeIo>>());
                // The carrier handed back stays open while it is stalled.
                let (r, _held) = match refused {
                    Some(r) => (Some(&r.error), r.take_carrier()),
                    None => (
                        inner.and_then(|e| e.downcast_ref::<crate::proto::listener::RejectError>()),
                        None,
                    ),
                };
                if let Some(r) = r {
                    let info = RejectInfo::new(r.profile, r.record_mode, r.reason, source);
                    self.refuse(&info, None, entry).await;
                    return Err(HandleError::Rejected);
                }
                return Err(HandleError::SetupFailed);
            }
            Some(Err(_)) => return Err(HandleError::SetupFailed),
        };
        // An Establish makes a message carrier of a Sealed one; every other kind stays.
        let same = (
            io.reader.is_some(),
            io.writer.is_some(),
            if io.first_mode.is_some() {
                kind.2
            } else {
                io.framing
            },
            io.split_bootstrap,
        ) == kind;
        if !same {
            return Err(HandleError::SetupFailed);
        }
        io.carrier = carrier;
        if io.admitted.is_none() {
            io.admitted = value;
        }
        Ok(io)
    }

    /// A half of a split carrier: it holds its slots like any carrier until the pair is
    /// complete (so the listener's limits bound the unpaired halves, per source too), and
    /// the first half keeps them as the carrier. The first half
    /// waits for the other, with the same token and the opposite direction, within the
    /// handshake timeout from its arrival. Nothing is read before the pair is complete. The
    /// first half then runs the inbound transform on the two, reads the first record within
    /// the first-record timeout, and starts a session or a Join; the second resolves when
    /// that ends.
    async fn handle_paired(
        &self,
        pipe: PipeIo,
        hint: PipeHint,
        mut entry: Option<Entry>,
        token: &[u8],
    ) -> Result<PipeEnd, HandleError> {
        let shared = &self.shared;
        let Ok(token) = <[u8; PAIRING_TOKEN_LEN]>::try_from(token) else {
            return Err(HandleError::Rejected);
        };
        let uplink = pipe.reader.is_some();
        if uplink == pipe.writer.is_some() {
            return Err(HandleError::Rejected);
        }
        let arrived = now();
        // A half on a connection that carries a pipe has no slot yet: it takes one now.
        let entry = if let Some(e) = entry.take() {
            e
        } else {
            let peer = hint.peer.or(hint.source).unwrap_or(NO_ADDR);
            let mut e = self.enter_uncounted(peer, hint.source)?;
            e.handshaken = true;
            e.admitted = true;
            e
        };
        let mut wakes = WakeList::default();
        let (limits, id) = {
            let mut st = shared.lock();
            if st.closed {
                return Err(HandleError::Refused);
            }
            let limits = st.core.config().clone();
            (limits, st.core.open(None, pipe.framing, arrived))
        };
        let mut pending = Pending {
            shared,
            id,
            done: false,
            slot: Some(entry),
        };
        let mut pipe = Some(pipe);
        let second = {
            let mut st = shared.lock();
            if st.closed {
                return Err(HandleError::Refused);
            }
            match st.core.pair(token, id, uplink, now()) {
                Paired::Waiting => {
                    // A half the core forgot (the table is bounded) may still wait here:
                    // it times out, not being this slot's waiter.
                    let replaced = st.pairs.insert(
                        token,
                        PairSlot {
                            waiter: id,
                            partner: None,
                        },
                    );
                    drop(st);
                    drop(replaced);
                    None
                }
                Paired::Complete(_) => {
                    let Some(slot) = st.pairs.get_mut(&token).filter(|s| s.partner.is_none())
                    else {
                        return Err(HandleError::Rejected);
                    };
                    let done = Arc::new(PipeDone::default());
                    let halves = (pipe.take().expect("kept"), FinishOnDrop(done.clone()));
                    slot.partner = Some(halves);
                    st.close_waiters.wake_all(&mut wakes);
                    Some(done)
                }
                Paired::Reject => return Err(HandleError::Rejected),
            }
        };
        if let Some(done) = second {
            drop(std::mem::take(&mut wakes));
            pending.done();
            return Ok(PipeEnd::of(done));
        }
        let pipe = pipe.expect("kept");
        // From here this half owns the token: however it ends before its partner is taken,
        // the pairing goes from both tables and a second half in the slot is released.
        let mut owner = PairOwner {
            shared,
            token,
            id,
            armed: true,
        };
        // Always bounded: a timeout past the clock's range waits as long as
        // the clock goes, never without a deadline (the wait also ends with
        // the listener's close and the half's eviction).
        let deadline = arrived
            .checked_add(limits.handshake_timeout)
            .unwrap_or_else(|| arrived + Duration::from_hours(262_800));
        let partner = PairWait {
            shared,
            token,
            id,
            ticket: None,
        };
        let partner = tokio::time::timeout_at(deadline.into(), partner)
            .await
            .ok()
            .flatten();
        let Some((other, finish)) = partner else {
            return Err(HandleError::TimedOut);
        };
        owner.armed = false;
        drop(owner);
        // The second half resolves when the session ends, however it ends:
        // its release goes with what this half waits for.
        let (up, down) = if uplink { (pipe, other) } else { (other, pipe) };
        let mut io = PipeIo::paired(up, down);
        if let Some(taken) = io.taken.take() {
            taken();
        }
        let mut hint = hint;
        hint.value = io.admitted.as_deref().cloned();
        if let Some(t) = shared.transform.clone() {
            io = self.transform(&t, io, &hint, pending.slot.as_mut()).await?;
        }
        // The record is read from what the transform returned.
        shared.lock().core.set_framing(id, io.framing);
        let classified = {
            let first = tokio::time::timeout(
                limits.first_record_timeout,
                Self::first_record(shared, id, &mut io),
            );
            let mut first = std::pin::pin!(first);
            let mut closing = Closing {
                shared,
                id: Some(id),
                slot: None,
                ticket: None,
            };
            std::future::poll_fn(|cx| {
                if let Poll::Ready(r) = first.as_mut().poll(cx) {
                    return Poll::Ready(Some(r));
                }
                Pin::new(&mut closing).poll(cx).map(|()| None)
            })
            .await
        };
        match classified {
            Some(Ok(Classified::NewSession { first })) => {
                io.prefix = first;
                let slot = pending.slot.take();
                pending.done();
                let mut end = self
                    .start_session(io, (hint.source, hint.peer), slot)
                    .await?;
                end.partner = Some(finish);
                Ok(end)
            }
            Some(Ok(Classified::Join { locator, hello })) => {
                let mut end = self
                    .join(
                        &mut pending,
                        &locator,
                        &hello,
                        io,
                        &limits,
                        hint.source.or(hint.peer),
                    )
                    .await?;
                end.partner = Some(finish);
                Ok(end)
            }
            Some(Ok(_)) => Err(HandleError::Rejected),
            Some(Err(_)) => Err(HandleError::TimedOut),
            None => Err(HandleError::Refused),
        }
    }

    /// Reads until the listener classified the carrier.
    async fn first_record(shared: &ListenShared, id: CarrierId, pipe: &mut PipeIo) -> Classified {
        let Some(reader) = pipe.reader.as_mut() else {
            return Classified::Reject;
        };
        // Bytes an adapter read first (an admission's prefix).
        if !pipe.prefix.is_empty() {
            let prefix = std::mem::take(&mut pipe.prefix);
            let mut st = shared.lock();
            let r = if pipe.framing == Framing::Records {
                st.core.message(id, &prefix, now())
            } else {
                st.core.data(id, &prefix, now())
            };
            if r != Classified::NeedMore {
                return r;
            }
        }
        // A message arrives whole, so its room is the largest record's.
        let room = if pipe.framing == Framing::Records {
            crate::util::usize_sat(crate::proto::params::ZMUX_MAX_RECORD_SIZE) + 1
        } else {
            16 * 1024
        };
        let mut buf = vec![0u8; room];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                // An empty first message is below the size of any first
                // record.
                Ok(_) | Err(_) => return Classified::Reject,
            };
            let mut st = shared.lock();
            let r = if pipe.framing == Framing::Records {
                st.core.message(id, &buf[..n], now())
            } else {
                st.core.data(id, &buf[..n], now())
            };
            if r != Classified::NeedMore {
                return r;
            }
        }
    }

    /// What the listener's `session_config` is told of a new session's carrier.
    fn session_carrier(
        pipe: &PipeIo,
        (source, peer): (Option<SocketAddr>, Option<SocketAddr>),
    ) -> crate::SessionCarrier {
        crate::SessionCarrier {
            source: source.or(peer),
            peer,
            tls: pipe.terminated_tls(),
            admitted: pipe.admitted.as_deref().cloned(),
        }
    }

    /// The configuration of a new session on the carrier `carrier` describes.
    async fn session_config(
        &self,
        carrier: crate::SessionCarrier,
    ) -> Result<Arc<Config>, HandleError> {
        let chosen = self.shared.lock().core.config().session_config.clone();
        let Some(f) = chosen else {
            return Ok(self.shared.config.clone());
        };
        let deadline = self.handshake_deadline();
        let answer =
            super::hooks::settle_by(f.ask(&carrier), deadline, self.closed_or_evicted(None))
                .await
                .flatten();
        match SessionConfigFn::chosen(answer, self.shared.logger.as_ref()) {
            Ok(None) => Ok(self.shared.config.clone()),
            Ok(Some(c)) => Ok(Arc::new(c)),
            Err(()) => Err(HandleError::Rejected),
        }
    }

    /// A new session on its bootstrap carrier, which keeps `_slot` until the
    /// transport parameters are exchanged.
    async fn start_session(
        &self,
        pipe: PipeIo,
        addrs: (Option<SocketAddr>, Option<SocketAddr>),
        _slot: Option<Entry>,
    ) -> Result<PipeEnd, HandleError> {
        let config = self
            .session_config(Self::session_carrier(&pipe, addrs))
            .await?;
        // Each session of the listener has its own locator unless one is
        // configured.
        let own = (config.offers_multipath() && config.own_locator().is_empty())
            .then(|| crate::proto::listener::random_locator(&self.shared.instance_id));
        let shared = Shared::create(
            pipe,
            config,
            Role::Server,
            Some(Role::Server),
            own.as_deref(),
            |shared| self.register_session(shared),
        )
        .map_err(|_| HandleError::Rejected)?;
        let mut place = Unaccepted(&self.shared, false);
        let refusal = {
            let pressure = self.shared.account.pressure();
            let mut st = self.shared.lock();
            let closing = st.closed || st.draining;
            let r = st.core.admit_session(closing, pressure).err();
            place.1 = r.is_none();
            r
        };
        if let Some(reason) = refusal {
            // Refused after its own parameters, so that the peer reads why,
            // within the handshake timeout.
            let limit = self.shared.lock().core.config().handshake_timeout;
            let _ = tokio::time::timeout(limit, shared.refuse(reason)).await;
            return Err(HandleError::Refused);
        }
        let done = shared.lock_pipe_done(0);
        // Bounded by the handshake timeout and the listener's close: a peer
        // that never completes the parameters holds no place for good.
        let limit = self.shared.lock().core.config().handshake_timeout;
        let closing = Closing {
            shared: &self.shared,
            id: None,
            slot: None,
            ticket: None,
        };
        let mut closing = std::pin::pin!(closing);
        let mut establishing = std::pin::pin!(tokio::time::timeout(limit, shared.established()));
        let established = std::future::poll_fn(|cx| {
            if closing.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(HandleError::Refused));
            }
            establishing
                .as_mut()
                .poll(cx)
                .map(|r| r.map_err(|_| HandleError::TimedOut))
        })
        .await?;
        match established {
            Ok(s) => {
                let mut wakes = WakeList::default();
                let mut st = self.shared.lock();
                if st.closed || st.draining {
                    // Closed meanwhile: nobody accepts it; dropped (and so
                    // closed) after the listener's lock.
                    drop(st);
                    drop(s);
                    return Err(HandleError::Refused);
                }
                st.accept.push_back(s);
                // The queued session holds the place until it is taken.
                place.1 = false;
                self.shared.counts.sessions.fetch_add(1, Relaxed);
                st.accept_waiters.wake_all(&mut wakes);
                // Woken after the listener's lock.
                drop(st);
            }
            Err(_) => return Err(HandleError::Rejected),
        }
        Ok(PipeEnd {
            done,
            partner: None,
        })
    }

    // Called synchronously by Shared::create before any bootstrap I/O.
    fn register_session(&self, shared: &Arc<Shared<Tokio>>) {
        let locator = shared.lock().core.local_locator().to_vec();
        shared.lock().io.account = Some(Box::new(AccountLink::new(self.shared.account.clone())));
        {
            // The Locators an epoch adds and deletes follow in the table.
            let listener = Arc::downgrade(&self.shared);
            let session = Arc::downgrade(shared);
            let mut held = vec![locator.clone()];
            let mut s = shared.lock();
            s.core.set_locator_instance(self.shared.instance_id.len());
            s.locator_hook = Some(Box::new(move |now: &[Vec<u8>]| {
                let Some(l) = listener.upgrade() else {
                    return;
                };
                l.locators.replace(&held, now, &session);
                held = now.to_vec();
            }));
        }
        {
            let mut st = self.shared.lock();
            st.live.push(Arc::downgrade(shared));
            if st.live.len() > 2 * st.live_pruned.max(16) {
                st.live.retain(|w| w.strong_count() > 0);
                st.live_pruned = st.live.len();
            }
        }
        if !locator.is_empty() {
            // Ended sessions leave the table once it doubled since the last pruning:
            // amortized constant work per session.
            self.shared.locators.insert(locator, Arc::downgrade(shared));
        }
    }

    /// Processes a Hello from its Locator lookup to Confirmed and, once
    /// Confirmed, hands the session the carrier.
    #[allow(clippy::too_many_arguments)]
    async fn join(
        &self,
        pending: &mut Pending<'_>,
        locator: &[u8],
        hello: &[u8],
        mut pipe: PipeIo,
        _limits: &ListenerConfig,
        source: Option<SocketAddr>,
    ) -> Result<PipeEnd, HandleError> {
        use super::accept::{AcceptStep, JoinAccept, JoinCarrier};
        let session = self.shared.locators.get(locator);
        // A stream carrier of a session that runs over this one is refused once the join is
        // authenticated, so that a joiner that cannot see the loop backs off.
        let looped = session.as_ref().is_some_and(|session| {
            pipe.outer
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|outer| runs_over(&outer, session))
        });
        // A Bound Hello needs a Binding of this carrier: it declares the contract, is not
        // split and has an exporter. A stream of a multiplexed session has none here: the
        // connection below it would vouch for streams the multiplexer's other carriers
        // open.
        let binding = (pipe.secure && !pipe.split)
            .then(|| {
                pipe.exporter
                    .as_ref()
                    .and_then(CarrierExporter::pipe_binding)
            })
            .flatten();
        let carrier = JoinCarrier {
            framing: pipe.framing,
            binding,
            has_exporter: pipe.exporter.is_some(),
            secure: pipe.secure,
            admitted: pipe.admitted.as_deref().cloned(),
            inbound: pipe.reader.is_some(),
            outbound: pipe.writer.is_some(),
            looped,
            overhead: pipe.write_overhead,
            max_record: pipe.max_record,
            kind: pipe.carrier,
        };
        let mut acc = JoinAccept::new(session, self.shared.config.join_timeout, hello, carrier);
        let deadline = acc.deadline();
        let bounded = |d: Option<std::time::Instant>| d.map(Instant::from_std);
        // A Hello that arrived as carrier early data could be a replay: it is
        // offered only once the carrier's handshake completed, within the join's
        // deadline; one that does not complete is a setup failure. Bound never takes it.
        if acc.session().is_some()
            && let Some(done) = pipe.take_early_in()
        {
            let mode = JoinAccept::<Tokio>::parse_mode(pipe.framing, hello);
            if mode == Some(crate::proto::seal::RecordMode::Bound) {
                return self.rejected(pending, "early_data", mode, source).await;
            }
            if !within(bounded(deadline), done).await {
                return Err(HandleError::SetupFailed);
            }
        }
        let mut step = self.join_open(pending, &mut acc, None);
        let reply = loop {
            step = match step {
                AcceptStep::Reject(reason, mode) => {
                    return self.rejected(pending, reason, mode, source).await;
                }
                AcceptStep::End(e) => return Err(e),
                AcceptStep::WaitKeys => {
                    let session = acc.session().expect("named").clone();
                    let keys = handle::join_keys_wait(&session);
                    let waited = until(self.closed_or_evicted(Some(pending.id)), keys);
                    let waited = match bounded(deadline) {
                        Some(d) => tokio::time::timeout_at(d, waited).await.ok(),
                        None => Some(waited.await),
                    };
                    match waited {
                        Some(Some(ready)) => self.join_open(pending, &mut acc, Some(ready)),
                        Some(None) => AcceptStep::End(HandleError::Refused),
                        None => AcceptStep::End(HandleError::TimedOut),
                    }
                }
                AcceptStep::Ask(d) => {
                    let session = acc.session().expect("named").clone();
                    let ended = self.join_stopped(pending.id, &session);
                    let ok = super::hooks::settle_by(d, deadline, ended).await == Some(true);
                    acc.allowed(ok)
                }
                AcceptStep::Delay(delay) => {
                    let session = acc.session().expect("named").clone();
                    let wait = until(
                        self.join_stopped(pending.id, &session),
                        tokio::time::sleep(delay),
                    );
                    match bounded(deadline) {
                        Some(d) => match tokio::time::timeout_at(d, wait).await {
                            Ok(w) => acc.delayed(w.is_some()),
                            Err(_) => AcceptStep::End(HandleError::TimedOut),
                        },
                        None => acc.delayed(wait.await.is_some()),
                    }
                }
                AcceptStep::Refuse(reply) => {
                    let session = acc.session().expect("named").clone();
                    let refuse = async {
                        if write_unit(&mut pipe, &reply).await.is_ok() {
                            pipe.end_unused(true, false).await;
                        }
                    };
                    let refuse = until(self.join_stopped(pending.id, &session), refuse);
                    match bounded(deadline) {
                        Some(d) => {
                            let _ = tokio::time::timeout_at(d, refuse).await;
                        }
                        None => {
                            let _ = refuse.await;
                        }
                    }
                    return Err(HandleError::Refused);
                }
                AcceptStep::Reply(reply) => break reply,
            };
        };
        let session = acc.session().expect("named").clone();
        {
            // A new authenticated Hello is never refused for lack of room: with the
            // session at its bound of Unconfirmed carriers, the oldest of them is closed
            // first, as a failed join (MULTIPATH.md 5.4 step 7); below it nothing is.
            let mut wakes = WakeList::default();
            let mut st = self.shared.lock();
            let evicted = st.core.unconfirmed(pending.id, locator);
            st.evict(evicted, &mut wakes);
        }
        let confirm = async {
            write_unit(&mut pipe, &reply).await?;
            // The acceptor's records wait for Confirmed.
            let mut input = Vec::new();
            loop {
                match acc.confirm(&mut input) {
                    Ok(true) => return Ok::<_, std::io::Error>(input),
                    Ok(false) => {}
                    Err(()) => return Err(std::io::ErrorKind::InvalidData.into()),
                }
                if read_unit(&mut pipe, &mut input).await? == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
            }
        };
        // An Unconfirmed carrier ends with its session and with the listener.
        let confirm = until(self.join_stopped(pending.id, &session), confirm);
        let confirmed = match bounded(deadline) {
            Some(d) => match tokio::time::timeout_at(d, confirm).await {
                Ok(c) => c,
                Err(_) => return Err(HandleError::TimedOut),
            },
            None => confirm.await,
        };
        let rest = match confirmed {
            Some(Ok(rest)) => rest,
            Some(Err(_)) => return Err(HandleError::Rejected),
            // Nothing the peer did: no authentication failure.
            None => return Err(HandleError::Refused),
        };
        let super::accept::Attached {
            pipe: attached,
            records,
            want_in,
            want_out,
        } = acc.attach()?;
        // Until its carrier task runs, the attached pipe is given up with
        // this handler however it ends: by an error below, or by the
        // handler's future being dropped at an await.
        let mut guard = AttachedPipe {
            session: &session,
            pipe: Some(attached),
        };
        // A pipe of its session now, no longer pending.
        pending.done();
        pipe.prefix = rest;
        pipe.resolve_lanes();
        if let Some((s, o)) = records {
            pipe = seal_carrier(pipe, s, o);
        }
        if let Some(m) = pipe.max_record {
            // Fits: checked against the join's mode before it was confirmed.
            if session
                .set_pipe_limits(attached, m, pipe.write_overhead)
                .is_err()
            {
                guard.abandon();
                return Err(HandleError::Refused);
            }
        }
        // The unused halves end within the join's deadline: a buffering layer
        // whose peer does not read holds no handler past it.
        if !within(bounded(deadline), pipe.end_unused(want_in, want_out)).await {
            guard.abandon();
            return Err(HandleError::TimedOut);
        }
        if claim_carrier(&session, attached.0, pipe.outer.take()).is_err() {
            // A loop formed since the check above, through another session:
            // ZMUX_PIPE_RESOURCE_LIMIT.
            guard.abandon();
            return Err(HandleError::Refused);
        }
        // A session closing meanwhile takes no new pipe (the guard forgets it).
        let Ok(done) = session.attach_task(attached.0, pipe) else {
            return Err(HandleError::Refused);
        };
        guard.pipe = None;
        drop(guard);
        // Counted once attached.
        self.shared.counts.joins.fetch_add(1, Relaxed);
        drop(session);
        Ok(PipeEnd::of(done))
    }

    /// Opens the Hello unless the listener closed or evicted the carrier
    /// meanwhile; `ready` is the answer of a key wait, if one came first.
    fn join_open(
        &self,
        pending: &Pending<'_>,
        acc: &mut super::accept::JoinAccept<Tokio>,
        ready: Option<bool>,
    ) -> super::accept::AcceptStep {
        // The listener's lock is never taken under a session's.
        let closed = {
            let st = self.shared.lock();
            // Evicted for a newer carrier while it waits: closed like one
            // waiting for its first record.
            st.closed || st.evicted.contains(&pending.id)
        };
        if closed {
            return super::accept::AcceptStep::End(HandleError::Refused);
        }
        let pressure = self.shared.account.pressure();
        match ready {
            None => acc.start(pressure),
            Some(r) => acc.keys_ready(r, pressure),
        }
    }

    /// Ready once a Hello's handshake has nothing left to wait for: its session ended, the
    /// listener closed or the carrier was evicted.
    async fn join_stopped(&self, id: CarrierId, session: &Shared<Tokio>) {
        let ended = handle::session_ended_wait(session);
        let _ = until(self.closed_or_evicted(Some(id)), ended).await;
    }

    /// Ready once the listener closes or the carrier `id` (if any) was
    /// evicted.
    fn closed_or_evicted(&self, id: Option<CarrierId>) -> impl Future<Output = ()> + '_ {
        let mut closing = Closing {
            shared: &self.shared,
            id,
            slot: None,
            ticket: None,
        };
        std::future::poll_fn(move |cx| Pin::new(&mut closing).poll(cx))
    }

    /// The reject policy of an unauthenticated join: closed, or stalled without a byte for
    /// the listener's join timeout from the refusal, keeping its slot. The response and the
    /// way of ending are the same whether or not the Locator names a session.
    async fn rejected(
        &self,
        pending: &mut Pending<'_>,
        reason: &'static str,
        mode: Option<crate::proto::seal::RecordMode>,
        source: Option<SocketAddr>,
    ) -> Result<PipeEnd, HandleError> {
        let info = RejectInfo::new(Some(2), mode, reason, source);
        let id = pending.id;
        self.refuse(&info, Some(id), pending.slot.as_mut()).await;
        Err(HandleError::Rejected)
    }

    /// The reject policy for `info`: closed, or stalled without a byte, a Join (Profile 2)
    /// for the listener's join timeout from now and any other carrier for the handshake
    /// timeout, at most the listener's maximum stall; the stall keeps `entry`'s slots (none:
    /// closed as `stall_overflow`). A pending carrier `id` also ends its stall when evicted
    /// as Unconfirmed.
    async fn refuse(&self, info: &RejectInfo, id: Option<CarrierId>, entry: Option<&mut Entry>) {
        if self.reject_response(info, id).await != RejectAction::Stall {
            return;
        }
        let limit = if info.profile == Some(2) {
            self.shared.config.join_timeout
        } else {
            let handshake = self.shared.lock().core.config().handshake_timeout;
            handshake.min(self.shared.stall_max)
        };
        let deadline = now().checked_add(limit);
        let stall = async {
            match deadline {
                Some(d) => tokio::time::sleep_until(d.into()).await,
                None => std::future::pending().await,
            }
        };
        let wait = async {
            match id {
                Some(id) => {
                    let _ = until(self.closed_or_evicted(Some(id)), stall).await;
                }
                None => stall.await,
            }
        };
        self.stall_refused(entry, wait).await;
    }
}

/// Whether `fut` completed before `deadline` (none: it is awaited without
/// one).
async fn within(deadline: Option<Instant>, fut: impl Future<Output = ()>) -> bool {
    if let Some(d) = deadline {
        tokio::time::timeout_at(d, fut).await.is_ok()
    } else {
        fut.await;
        true
    }
}

/// Memory counted in a listener's budget on behalf of its sessions
/// ([`ListenerAdapter::charge_memory`]) until dropped.
pub struct MemoryCharge {
    account: Arc<Account<Shared<Tokio>>>,
    bytes: u64,
}

impl std::fmt::Debug for MemoryCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCharge")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for MemoryCharge {
    fn drop(&mut self) {
        self.account.charge(0, self.bytes);
    }
}

/// A carrier among the listener's pending carriers, until it is classified, joined or given
/// up, with the entry that holds its slots.
struct Pending<'a> {
    shared: &'a ListenShared,
    id: CarrierId,
    done: bool,
    slot: Option<Entry>,
}

impl Pending<'_> {
    /// Leaves the pending carriers and gives the slots back (after the lock).
    fn done(&mut self) {
        if !std::mem::replace(&mut self.done, true) {
            let mut st = self.shared.lock();
            st.core.done(self.id);
            // An eviction it did not see (it ended first) is forgotten.
            let id = self.id;
            st.evicted.retain(|&e| e != id);
        }
        self.slot = None;
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.done();
    }
}

/// A new session's place among the unaccepted
/// ([`ListenerCore::reserve_unaccepted`]), released when dropped while held.
struct Unaccepted<'a>(&'a ListenShared, bool);

impl Drop for Unaccepted<'_> {
    fn drop(&mut self) {
        if self.1 {
            self.0.lock().core.release_unaccepted();
        }
    }
}

/// [`Listener::accept`]; dropped while waiting, it leaves the waiters.
struct Accept<'a> {
    shared: &'a ListenShared,
    ticket: Option<Ticket>,
}

impl Future for Accept<'_> {
    type Output = Option<Session>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Session>> {
        let this = self.get_mut();
        let mut st = this.shared.lock();
        let ready = match st.accept.pop_front() {
            Some(s) => {
                st.core.release_unaccepted();
                Some(Some(s))
            }
            None => (st.closed || st.draining).then_some(None),
        };
        if let Some(r) = ready {
            if let Some(t) = this.ticket.take() {
                st.accept_waiters.remove(t);
            }
            return Poll::Ready(r);
        }
        st.accept_waiters.register(&mut this.ticket, cx.waker());
        Poll::Pending
    }
}

impl Drop for Accept<'_> {
    fn drop(&mut self) {
        if let Some(t) = self.ticket.take() {
            self.shared.lock().accept_waiters.remove(t);
        }
    }
}

/// Resolves once the listener is closed; dropped while waiting, it leaves
/// the waiters.
struct Closing<'a> {
    shared: &'a ListenShared,
    /// The carrier, which an eviction ends too.
    id: Option<CarrierId>,
    /// The slots of a stalled carrier, which an eviction ends too.
    slot: Option<Slot>,
    ticket: Option<Ticket>,
}

impl Future for Closing<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let mut st = this.shared.lock();
        let evicted = this
            .id
            .and_then(|id| st.evicted.iter().position(|&e| e == id));
        if let Some(i) = evicted {
            st.evicted.swap_remove(i);
        }
        // Seen by the stall's end, which then gives up the slot.
        let slot_gone = this.slot.is_some_and(|s| st.evicted_slots.contains(&s));
        if st.closed || evicted.is_some() || slot_gone {
            if let Some(t) = this.ticket.take() {
                st.close_waiters.remove(t);
            }
            return Poll::Ready(());
        }
        st.close_waiters.register(&mut this.ticket, cx.waker());
        Poll::Pending
    }
}

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        if let Some(t) = self.ticket.take() {
            self.shared.lock().close_waiters.remove(t);
        }
    }
}

/// The second half of a split bootstrap, put under the first's token;
/// `None` once the listener is closed or the first half was evicted.
struct PairWait<'a> {
    shared: &'a ListenShared,
    token: [u8; PAIRING_TOKEN_LEN],
    id: CarrierId,
    ticket: Option<Ticket>,
}

impl Future for PairWait<'_> {
    type Output = Option<PairPartner>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut st = this.shared.lock();
        let id = this.id;
        let partner = st
            .pairs
            .get_mut(&this.token)
            .filter(|s| s.waiter == id)
            .and_then(|s| s.partner.take());
        let ended = partner.is_none() && {
            let evicted = st.evicted.iter().position(|&e| e == id);
            if let Some(i) = evicted {
                st.evicted.swap_remove(i);
            }
            st.closed || evicted.is_some()
        };
        if partner.is_some() || ended {
            if partner.is_some() {
                st.pairs.remove(&this.token);
            }
            if let Some(t) = this.ticket.take() {
                st.close_waiters.remove(t);
            }
            return Poll::Ready(partner);
        }
        st.close_waiters.register(&mut this.ticket, cx.waker());
        Poll::Pending
    }
}

impl Drop for PairWait<'_> {
    fn drop(&mut self) {
        if let Some(t) = self.ticket.take() {
            self.shared.lock().close_waiters.remove(t);
        }
    }
}

/// The first half of a split bootstrap while it waits: dropped armed (a timeout, a close,
/// its handler cancelled), it takes the pairing out of both tables. A partner in the slot
/// ends after the lock.
struct PairOwner<'a> {
    shared: &'a ListenShared,
    token: [u8; PAIRING_TOKEN_LEN],
    id: CarrierId,
    armed: bool,
}

impl Drop for PairOwner<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let slot = {
            let mut st = self.shared.lock();
            st.core.unpair(&self.token, self.id);
            let id = self.id;
            if st.pairs.get(&self.token).is_some_and(|s| s.waiter == id) {
                st.pairs.remove(&self.token)
            } else {
                None
            }
        };
        drop(slot);
    }
}

/// Finishes a latch when dropped.
struct FinishOnDrop(Arc<PipeDone>);

/// What a set-up carrier's handler waits for: its pipe's end, and the
/// second half of a split bootstrap to release then.
#[derive(Default)]
struct PipeEnd {
    done: Option<Arc<PipeDone>>,
    partner: Option<FinishOnDrop>,
}

impl PipeEnd {
    fn of(done: Arc<PipeDone>) -> Self {
        Self {
            done: Some(done),
            partner: None,
        }
    }

    /// Resolves when the pipe ended; the partner half is released after.
    async fn wait(self) {
        if let Some(d) = &self.done {
            d.wait().await;
        }
    }
}

impl Drop for FinishOnDrop {
    fn drop(&mut self) {
        let mut wakes = WakeList::default();
        self.0.finish_into(&mut wakes);
    }
}

/// A connection's setup without an [`Entry`] ([`ListenerAdapter::setup_guard`]).
pub struct SetupGuard(Option<Arc<ListenShared>>);

impl std::fmt::Debug for SetupGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetupGuard")
    }
}

impl SetupGuard {
    /// The setup completed: nothing is counted.
    pub fn done(mut self) {
        self.0 = None;
    }
}

impl Drop for SetupGuard {
    fn drop(&mut self) {
        if let Some(s) = self.0.take() {
            s.counts.setup_failures.fetch_add(1, Relaxed);
        }
    }
}

/// After a failed accept: a connection that went away before it was
/// accepted is no reason to wait; anything else (no file descriptors or
/// memory left) is retried after 100 ms, so that an accept loop does not
/// spin.
async fn accept_failed(e: &std::io::Error) {
    if super::accept_backs_off(e) {
        tokio::time::sleep(super::ACCEPT_BACKOFF).await;
    }
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    use std::io;
    use std::sync::mpsc;
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    struct FirstWrite {
        io: DuplexStream,
        listener: Listener,
        observed: Option<mpsc::Sender<bool>>,
    }
    impl AsyncRead for FirstWrite {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            dst: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, dst)
        }
    }
    impl AsyncWrite for FirstWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            src: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(observed) = self.observed.take() {
                let routed = self.listener.shared.locators.any();
                let ready = routed.is_some_and(|shared| shared.lock().io.account.is_some());
                let _ = observed.send(ready);
            }
            Pin::new(&mut self.io).poll_write(cx, src)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registration_and_accounting_precede_bootstrap_io() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let config = Config {
                max_pipes: 4,
                pipe_auth: crate::PipeAuth::psk(vec![7; 32]),
                ..Config::default()
            };
            let config = Arc::new(config);
            let listener = Listener::new(config.clone(), ListenerConfig::default())
                .expect("valid listener configuration");
            let (a, b) = tokio::io::duplex(65536);
            let client = tokio::spawn(Session::connect(PipeIo::new(a), config.clone()));
            let (observed, seen) = mpsc::channel();
            let carrier = FirstWrite {
                io: b,
                listener: listener.clone(),
                observed: Some(observed),
            };
            let shared = Shared::create(
                PipeIo::new(carrier),
                config,
                Role::Server,
                Some(Role::Server),
                Some(&[9; 16]),
                |shared| {
                    // Give another runtime worker a chance to expose any
                    // mistakenly started driver before registration.
                    assert!(
                        matches!(
                            seen.recv_timeout(Duration::from_millis(100)),
                            Err(mpsc::RecvTimeoutError::Timeout)
                        ),
                        "bootstrap I/O started before the registration callback"
                    );
                    listener.register_session(shared);
                },
            )
            .expect("create session");
            assert!(
                seen.recv_timeout(Duration::from_secs(1))
                    .expect("first bootstrap write"),
                "bootstrap write lacked a live locator route or memory account"
            );
            let server = shared.established().await.expect("server established");
            let client = client
                .await
                .expect("client task")
                .expect("client established");
            server.abort(VarInt::ZERO, b"done");
            server.closing().await;
            client.closing().await;
            listener.close();
        })
        .await
        .expect("registration test deadline");
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;
    use crate::proto::TransportErrorCode;

    /// A draining listener refuses a new session with `CONNECTION_REFUSED`
    /// after its own parameters, so that the peer reads why, as the Go listener.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_draining_listener_refuses_with_connection_refused() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = Listener::new(Config::default(), ListenerConfig::default())
                .expect("valid listener configuration");
            listener.shared.lock().draining = true;
            let (a, b) = tokio::io::duplex(65536);
            let client = tokio::spawn(Session::connect(PipeIo::new(a), Config::default()));
            let l = listener.clone();
            let handled = l.handle_pipe(PipeIo::new(b), PipeHint::default()).await;
            assert_eq!(handled, Err(HandleError::Refused));
            // The client may see the parameters establish the session first.
            let error = match client.await.expect("client task") {
                Ok(s) => s.closing().await,
                Err(crate::ConnectError::SessionLost(e)) => e,
                Err(e) => panic!("not refused: {e:?}"),
            };
            match error {
                crate::SessionError::TransportClosed {
                    code, remote: true, ..
                } => assert_eq!(code, TransportErrorCode::CONNECTION_REFUSED),
                other => panic!("not refused: {other:?}"),
            }
            assert_eq!(listener.stats().refused, 1);
        })
        .await
        .expect("timed out");
    }
}

#[cfg(test)]
mod setup_bound_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct Live(Arc<AtomicUsize>);
    impl Drop for Live {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Relaxed);
        }
    }

    /// Setups that never enter the listener (a handshake before it, or
    /// carriers entering one by one) stay within `max_pending`: a new
    /// connection beyond it ends the oldest setup.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn setups_without_an_entry_stay_within_max_pending() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let limits = ListenerConfig {
                max_pending: Some(3),
                ..ListenerConfig::default()
            };
            let listener =
                Listener::new(Config::default(), limits).expect("valid listener configuration");
            let live = Arc::new(AtomicUsize::new(0));
            let (most, accepted) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            let (l, live2, most2, acc2) = (
                listener.clone(),
                live.clone(),
                most.clone(),
                accepted.clone(),
            );
            let serving = tokio::spawn(l.serve_connections(
                move || {
                    let acc = acc2.clone();
                    async move {
                        if acc.fetch_add(1, Relaxed) == 20 {
                            std::future::pending::<()>().await;
                        }
                        tokio::task::yield_now().await;
                        Some(Ok(()))
                    }
                },
                move |()| {
                    let n = live2.fetch_add(1, Relaxed) + 1;
                    most2.fetch_max(n, Relaxed);
                    let guard = Live(live2.clone());
                    async move {
                        let _guard = guard;
                        std::future::pending::<Result<(), ()>>().await
                    }
                },
                |_l, ()| async {},
            ));
            while accepted.load(Relaxed) <= 20 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                live.load(Relaxed) <= 3,
                "{} setups running",
                live.load(Relaxed)
            );
            listener.close();
            serving.await.expect("serve loop");
        })
        .await
        .expect("setup bound test deadline");
    }
}
