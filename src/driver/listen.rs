//! The tokio listener: new carriers start sessions or join existing
//! ones after verification, with the pending-join and rate limits and
//! the memory budget and suspended-session limits.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

use super::account::{Account, AccountLink};
use super::admission::{AdmitIo, Fallback, FirstMessage, discard, read_message, read_more};
use super::deadline::{earlier, sleep, timeout};
use super::handle::{self, Shared};
use super::resources::{Kind, Live};
use super::sealed::{read_unit, seal_carrier, until};
use super::setup::{Authority, CommitError, ListenerLock, Owner, Setup, SlotTable, Transfer};
use super::stream_pipe::{claim_carrier, runs_over};
use super::tokio::{PipeIo, Session, Tokio};
use super::transform::InboundTransform;
use super::wait::{Ticket, WaitList};
use super::wake::WakeList;
use crate::proto::VarInt;
use crate::proto::admission::{
    Admission, AdmissionStage, AdmissionVerdict, AdmittedValue, CarrierInfo, Round, Step, step,
};
use crate::proto::exporter::CarrierExporter;
use crate::proto::listener::{
    CarrierId, Classified, Entered, ListenerConfig, ListenerCore as Core, ListenerLimits, Paired,
    Slot,
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
    /// ([`crate::ListenerLimits::max_pending`],
    /// [`crate::ListenerLimits::max_pending_per_source`]), a source
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
    clock: crate::ClockDomain,
    transform_deadline: Option<Instant>,
}

/// A foreign event loop's synchronous cancellation of an ordinary carrier setup.
#[derive(Debug)]
#[doc(hidden)]
pub struct SetupCancellation(Arc<super::setup::Handoff>);

impl SetupCancellation {
    /// Returns true only when this call withdrew the pending setup.
    #[must_use]
    pub fn cancel(&self) -> bool {
        self.0.withdraw()
    }
}

/// A header writer's ownership of an admission. Move this receipt into the
/// operation that actually writes and flushes the accepted response. Drop it
/// after a failed write finishes, including any asynchronous cancellation.
pub struct ResponseHead {
    sent: oneshot::Sender<()>,
    _worker: Box<dyn Send + Sync>,
}

impl std::fmt::Debug for ResponseHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseHead")
            .field("cancelled", &self.sent.is_closed())
            .finish_non_exhaustive()
    }
}

impl ResponseHead {
    /// Reports the completed successful flush to the pending takeover.
    pub fn flushed(self) {
        let _ = self.sent.send(());
    }

    /// Wait for setup to end. A foreign writer observes this signal on its
    /// own executor and keeps this guard until its actual completion.
    pub async fn cancelled(&mut self) {
        self.sent.closed().await;
    }
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

    /// The listener's clock during its inbound transform.
    #[must_use]
    pub fn clock_domain(&self) -> &crate::ClockDomain {
        &self.clock
    }

    /// Absolute deadline for the inbound transform.
    #[must_use]
    pub const fn transform_deadline(&self) -> Option<Instant> {
        self.transform_deadline
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
    common: super::setup::ListenerCounts,
    admission: AdmissionCounts,
    #[cfg(feature = "test-hooks")]
    revision: tokio::sync::watch::Sender<()>,
}

impl Counts {
    fn commit(&self, counter: fn(&super::setup::ListenerCounts) -> &AtomicU64) {
        counter(&self.common).fetch_add(1, Relaxed);
        #[cfg(feature = "test-hooks")]
        self.notify();
    }

    fn admit(&self, outcome: Outcome, variant: Option<&Arc<str>>) {
        self.admission.count(outcome, variant);
        #[cfg(feature = "test-hooks")]
        self.notify();
    }

    #[cfg(feature = "test-hooks")]
    fn notify(&self) {
        let _ = self.revision.send(());
    }
}

#[derive(Default)]
struct AdmissionCounts {
    accepted: AtomicU64,
    fallback: AtomicU64,
    takeover: AtomicU64,
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
    Takeover,
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
            Outcome::Takeover => &self.takeover,
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
            Outcome::Takeover => self.count_variant(variant, |v| v.takeover += 1),
            Outcome::Stalled | Outcome::StallOverflow => {
                self.count_variant(variant, |v| v.stalled += 1);
            }
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
    /// Carriers handed to the byte-stream target by Takeover, counted at dispatch.
    pub takeover: u64,
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
    live: super::setup::Sessions<Tokio>,
    /// [`Listener::shutdown`] began: no new session, joins go on.
    closed: bool,
}

/// One request waiting for its complementary half.
struct PairSlot {
    id: CarrierId,
    setup: Setup<Entry, PipeIo>,
    hint: PipeHint,
    result: oneshot::Sender<Result<(), HandleError>>,
}

impl State_ {
    /// Ends the pending carrier the core evicted for a new one: it is woken
    /// to close. The wake-ups go to `wakes`, woken after the lock.
    fn evict(&mut self, evicted: Vec<CarrierId>, wakes: &mut WakeList) {
        let before = self.evicted.len();
        self.evicted
            .extend(evicted.into_iter().filter(|&id| self.core.done(id)));
        if self.evicted.len() != before {
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

pub(super) struct ListenShared {
    /// What happened to the carriers handed to the listener.
    counts: Counts,
    state: Mutex<State_>,
    /// The sessions by Locator.
    locators: Arc<handle::LocatorTable<Shared<Tokio>>>,
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
    fn lock(&self) -> ListenerLock<'_, State_> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .into()
    }
}

impl SlotTable for ListenShared {
    fn deregister(&self, id: CarrierId) {
        let mut st = self.lock();
        st.core.done(id);
        st.evicted.retain(|&evicted| evicted != id);
    }

    fn release(&self, slot: Slot) {
        let mut st = self.lock();
        st.core.release(slot);
        st.evicted_slots.retain(|&e| e != slot);
    }

    fn commit(
        &self,
        id: Option<CarrierId>,
        slot: Option<Slot>,
        remove: bool,
        willing: impl FnOnce() -> bool,
    ) -> Result<(), CommitError> {
        let mut st = self.lock();
        let evicted = slot.is_some_and(|slot| !st.core.holds_slot(slot))
            || id.is_some_and(|id| st.evicted.contains(&id));
        if let Some(id) = super::setup::check_handoff(st.closed, evicted, remove, id, willing)? {
            st.core.done(id);
        }
        Ok(())
    }
}

/// A carrier that entered a listener ([`ListenerAdapter::enter`]): it holds a
/// source slot ([`ListenerLimits::max_pending_per_source`]) and a slot of
/// the listener ([`ListenerLimits::max_pending`]) from before its outer
/// handshake, through its admission and, handed to
/// [`Listener::handle_pipe`] with [`PipeHint::from_entry`], until it enters
/// a session; or until it goes to the listener's fallback, is released
/// ([`Entry::release`]) or dropped. Dropped before its admission
/// ([`Entry::admit`], [`Entry::admit_first`], [`Entry::decide_request`],
/// [`Entry::decide_upgrade`]), its outer handshake counts as failed, or
/// as closed if setup was withdrawn or the listener stopped;
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
    setup: Authority<ListenShared>,
    setup_deadline: Option<Instant>,
    source: SocketAddr,
    peer: SocketAddr,
    admitted: bool,
    handshaken: bool,
    admission_settled: bool,
    /// The end of the peek timeout, from the end of the outer handshake.
    deadline: Option<PeekDeadline>,
    /// The metadata of the decision an upgrade's head deferred to its
    /// carrier ([`AdmissionVerdict::Defer`]), at the carrier's stage.
    deferred: Option<CarrierInfo>,
    /// Opaque host value and any principal verified by bound presentation.
    admission_evidence: Option<Box<super::tokio::AdmissionEvidence>>,
    /// The label the admission gave it.
    variant: Option<Arc<str>>,
    /// The metadata (set once a request carrier is to be taken over,
    /// [`Admit::TakeOver`]) and the value of a fallback verdict.
    fallback: Option<(Option<CarrierInfo>, Option<AdmittedValue>)>,
    /// Receipt from the committed fallback and its return guard.
    fallback_end: Option<FallbackEnd>,
}

struct PeekDeadline(Option<Instant>);

enum FallbackEnd {
    Returned,
    Detached,
}

/// A stream setup may return as soon as the listener owns its stall. An
/// outer adapter that still owns a connection waits for that same task
/// before closing it.
enum AdmissionEnd {
    Failed(HandleError),
    Stalled(tokio::task::JoinHandle<()>),
}

impl From<HandleError> for AdmissionEnd {
    fn from(error: HandleError) -> Self {
        Self::Failed(error)
    }
}

impl From<AdmissionEnd> for HandleError {
    fn from(end: AdmissionEnd) -> Self {
        match end {
            AdmissionEnd::Failed(error) => error,
            AdmissionEnd::Stalled(_) => Self::NotAdmitted,
        }
    }
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
/// request sent to fallback is handled by its adapter. A takeover delivers
/// its carrier to the byte-stream target ([`ListenerConfig::fallback`]).
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
    /// An explicit carrier takeover by the listener's byte-stream target:
    /// answer it as an accepted carrier (the response head), make its
    /// carrier (request body in, response body out for a bidirectional
    /// one) and hand it, these bytes replayed in front of the body, to
    /// [`Entry::take_over`]. Without a listener's fallback the verdict is
    /// [`Admit::Stall`].
    TakeOver(Vec<u8>),
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
    issuer: Weak<ListenShared>,
    source: SocketAddr,
    peer: SocketAddr,
    value: Option<AdmittedValue>,
}

impl Owner for Entry {
    type Table = ListenShared;
    fn authority(&mut self) -> &mut Authority<ListenShared> {
        &mut self.setup
    }
}

/// Marks requests whose server records the final HTTP fallback route.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct TrackRequestFallback;

/// Admission awaiting either an HTTP fallback dispatch or a not-found response.
#[doc(hidden)]
#[derive(Clone)]
pub struct RequestFallback(Arc<RequestFallbackCount>);

impl std::fmt::Debug for RequestFallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestFallback").finish_non_exhaustive()
    }
}

struct RequestFallbackCount {
    shared: Arc<ListenShared>,
    variant: Option<Arc<str>>,
    settled: AtomicBool,
}

impl RequestFallbackCount {
    fn count(&self, outcome: Outcome) {
        if !self.settled.swap(true, Relaxed) {
            self.shared
                .counts
                .admission
                .count(outcome, self.variant.as_ref());
        }
    }
}

impl Drop for RequestFallbackCount {
    fn drop(&mut self) {
        self.count(Outcome::Closed);
    }
}

impl RequestFallback {
    /// Records the host dispatch or the server's targetless response.
    pub fn complete(self, has_target: bool) {
        self.0.count(if has_target {
            Outcome::Fallback
        } else {
            Outcome::Stalled
        });
    }
}

impl Entry {
    fn new(shared: Arc<ListenShared>, source: SocketAddr, peer: SocketAddr) -> Self {
        let limit = shared.lock().core.config().handshake_timeout;
        Self {
            setup_deadline: super::handshake_deadline(shared.config.clock_domain.now(), limit),
            setup: Authority::listener(&shared),
            shared,
            key: 0,
            variant: None,
            source,
            peer,
            admitted: false,
            handshaken: true,
            admission_settled: false,
            deadline: None,
            deferred: None,
            admission_evidence: None,
            fallback: None,
            fallback_end: None,
        }
    }

    /// Registers the host writer before dispatching an accepted response head.
    #[doc(hidden)]
    pub fn response_head(&mut self) -> (ResponseHead, oneshot::Receiver<()>) {
        let (sent, wait) = oneshot::channel();
        (
            ResponseHead {
                sent,
                _worker: self.setup.admission_worker(),
            },
            wait,
        )
    }

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
            issuer: Arc::downgrade(&self.shared),
            source: self.source,
            peer: self.peer,
            value: self
                .admission_evidence
                .as_deref()
                .and_then(|evidence| evidence.value.clone()),
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
    /// longer message is closed without a decision, counted in
    /// [`AdmissionStats::too_large`] after an upgrade defers and in
    /// [`AdmissionStats::closed`] otherwise. So is a carrier whose first
    /// message does not come (it ends, fails, or sends an empty or a
    /// non-binary message), counted as closed, as is one the listener's
    /// close interrupts. `info` is the carrier's metadata (its source and
    /// peer are the entry's, its stage [`AdmissionStage::Carrier`] and its
    /// framing the carrier's), unless an upgrade's head deferred the
    /// decision ([`Entry::decide_upgrade`]): the head's is used then. Once
    /// the carrier is accepted, or without an admission, it is returned at
    /// once.
    pub async fn admit(&mut self, info: CarrierInfo, io: impl Into<AdmitIo>) -> Option<PipeIo> {
        match self.admission_result(info, io.into()).await {
            Ok(pipe) => pipe,
            Err(AdmissionEnd::Stalled(task)) => {
                let _ = task.await;
                None
            }
            Err(AdmissionEnd::Failed(_)) => None,
        }
    }

    // Some continues zmux setup; None means the fallback successfully served it.
    async fn admission_result(
        &mut self,
        info: CarrierInfo,
        mut io: AdmitIo,
    ) -> Result<Option<PipeIo>, AdmissionEnd> {
        if let Some(attachment) = io.attachment() {
            self.setup.bind(attachment);
        }
        if let Some((Some(metadata), _)) = &self.fallback {
            let metadata = metadata.clone();
            let prefix = io.given_back();
            return self
                .fall_back(metadata, prefix, io, Outcome::Takeover)
                .await
                .map(|()| None);
        }
        let deferred = self.deferred.take();
        let (adm, deadline) = match self.start() {
            Some((adm, deadline)) if !self.admitted => (adm, deadline),
            _ => {
                self.admitted = true;
                let given = io.given_back();
                return self
                    .make_pipe(io, given)
                    .map(Some)
                    .ok_or(AdmissionEnd::Failed(HandleError::SetupFailed));
            }
        };
        // Reading and deciding can hold large host and carrier state.
        // A listener without admission never allocates that setup future.
        Box::pin(self.admit_carrier(info, io, deferred, adm, deadline)).await
    }

    async fn admit_carrier(
        &mut self,
        info: CarrierInfo,
        mut io: AdmitIo,
        deferred: Option<CarrierInfo>,
        adm: Admission,
        deadline: Option<Instant>,
    ) -> Result<Option<PipeIo>, AdmissionEnd> {
        let framing = io.framing();
        let records = framing == Framing::Records;
        let mut info = match &deferred {
            Some(head) => head.clone(),
            None => self.carrier_info(info, AdmissionStage::Carrier),
        };
        info.framing = framing;
        let mut prefix = io.given_back();
        if records && (adm.peek() > 0 || deferred.is_some()) {
            let oversized = if deferred.is_some() {
                Outcome::TooLarge
            } else {
                Outcome::Closed
            };
            let ticket = adm.ticket_verifier().map(|(_, reject)| reject);
            let fallback_or_stall =
                ticket.is_some_and(|reject| reject != crate::PrefixRejection::Close);
            if prefix.is_empty() {
                let Some(r) = io.reader() else {
                    self.settle_admission(Outcome::Closed, None);
                    return Err(HandleError::NotAdmitted.into());
                };
                let listener = self.listener();
                let read = read_message(
                    r,
                    if fallback_or_stall {
                        crate::MAX_ADMISSION_MESSAGE
                    } else {
                        adm.max_message()
                    },
                    &self.shared.config.clock_domain,
                    deadline,
                );
                match until(listener.adapter().closed(), read).await {
                    Some(FirstMessage::Message(m) | FirstMessage::TooLarge(Some(m))) => prefix = m,
                    Some(FirstMessage::TooLarge(None)) => {
                        if let Some(reject) = ticket {
                            if self.reject_without_handoff(reject, oversized) == Admit::Stall {
                                return Err(self.stall_io(io, false));
                            }
                        } else {
                            self.settle_admission(oversized, None);
                        }
                        return Err(HandleError::NotAdmitted.into());
                    }
                    Some(FirstMessage::Late) => {
                        let route = self.ticket_rejection(&info, &adm, prefix, false, true);
                        return self.finish_carrier(route, info, io).await;
                    }
                    Some(FirstMessage::Failed) | None => {
                        self.settle_admission(Outcome::Closed, None);
                        return Err(HandleError::NotAdmitted.into());
                    }
                }
            }
            if prefix.len() > adm.max_message() {
                if let Some(reject) = ticket {
                    let route = self.finish(reject.verdict(), None, &info, prefix, false);
                    return self.finish_carrier(route, info, io).await;
                }
                self.settle_admission(oversized, None);
                return Err(HandleError::NotAdmitted.into());
            }
        } else if !records
            && prefix.len() < adm.peek()
            && let Some(r) = io.reader()
        {
            match self.read_bounded(prefix, adm.peek(), r, deadline).await {
                Read::Got(p, _) => prefix = p,
                Read::Late(p) => {
                    let verdict = self.ticket_rejection(&info, &adm, p, false, deferred.is_some());
                    return self.finish_carrier(verdict, info, io).await;
                }
                Read::Closed => {
                    self.settle_admission(Outcome::Closed, None);
                    return Err(HandleError::NotAdmitted.into());
                }
            }
        }
        let reader = if records { None } else { io.reader() };
        let verdict = self.decide_on(&info, prefix, reader, false).await;
        self.finish_carrier(verdict, info, io).await
    }

    async fn finish_carrier(
        &mut self,
        verdict: Admit,
        info: CarrierInfo,
        io: AdmitIo,
    ) -> Result<Option<PipeIo>, AdmissionEnd> {
        let takeover = matches!(verdict, Admit::TakeOver(_));
        match verdict {
            Admit::Accept(rest) => self
                .make_pipe(io, rest)
                .map(Some)
                .ok_or(AdmissionEnd::Failed(HandleError::SetupFailed)),
            Admit::Fallback(replay) | Admit::TakeOver(replay) => {
                let outcome = if takeover {
                    Outcome::Takeover
                } else {
                    Outcome::Fallback
                };
                self.fall_back(info, replay, io, outcome)
                    .await
                    .map(|()| None)
            }
            Admit::Stall => Err(self.stall_io(io, true)),
            Admit::Close | Admit::Defer => Err(HandleError::NotAdmitted.into()),
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
    /// closes. If the first carrier does not arrive in time, ticket admission
    /// stalls for Stall or Fallback and closes for Close. Without a ticket
    /// policy this counts as timed out ([`AdmissionStats::peek_timed_out`]).
    /// An intervening listener close or outer handshake failure ends the
    /// attempt. An available carrier passes the admission as with
    /// [`Entry::admit`], `info` its metadata unless the head deferred the
    /// decision. When the head was accepted, `first` runs until the
    /// listener closes and its carrier is returned as it comes; a failure
    /// then counts as a setup failure. On `None` the adapter closes what it
    /// upgraded.
    pub async fn admit_first<F>(&mut self, info: CarrierInfo, first: F) -> Option<PipeIo>
    where
        F: Future<Output = std::io::Result<AdmitIo>>,
    {
        self.admit_first_with_info(async { Ok((info, first.await?)) })
            .await
    }

    /// First-carrier admission when its metadata becomes available with the I/O.
    #[doc(hidden)]
    pub async fn admit_first_with_info<F>(&mut self, first: F) -> Option<PipeIo>
    where
        F: Future<Output = std::io::Result<(CarrierInfo, AdmitIo)>>,
    {
        let use_peek = !self.admitted && self.shared.admission.is_some();
        let deadline = if use_peek {
            let (_, peek) = self.start()?;
            earlier(self.setup_deadline, peek)
        } else {
            self.setup_deadline
        };
        let result = {
            let listener = self.listener();
            let mut first = std::pin::pin!(first);
            let first = until(
                sleep::<Tokio>(&self.shared.config.clock_domain, deadline),
                first.as_mut(),
            );
            until(listener.adapter().closed(), first).await
        };
        let ticket = self
            .shared
            .admission
            .as_ref()
            .and_then(Admission::ticket_verifier)
            .map(|(_, reject)| reject);
        let outcome = match result {
            Some(Some(Ok((info, io)))) => {
                if !use_peek || !self.elapsed(deadline) || ticket.is_some() {
                    return self.admit(info, io).await;
                }
                Outcome::PeekTimedOut
            }
            Some(_) if use_peek && ticket.is_none() && self.elapsed(deadline) => {
                Outcome::PeekTimedOut
            }
            _ if !use_peek => {
                self.handshaken = true;
                self.shared.counts.commit(|counts| &counts.setup_failures);
                return None;
            }
            Some(Some(Err(_))) => Outcome::HandshakeFailed,
            Some(None) => Outcome::PeekTimedOut,
            None => Outcome::Closed,
        };
        // Counted here: the deferral, if any, ends without its decision.
        self.deferred = None;
        self.fallback.take();
        if matches!(outcome, Outcome::PeekTimedOut)
            && let Some(reject) = ticket
        {
            if self.reject_without_handoff(reject, outcome) == Admit::Stall {
                self.stall_local(()).await;
            }
        } else {
            self.settle_current_admission(outcome);
        }
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
    /// ticket on a protected entry uses the entry's refusal policy. For
    /// other admissions a late prefix closes the request. Without an
    /// admission it accepts at once. On `Admit::Fallback`, record the
    /// dispatch or not-found response with [`Entry::complete_request_fallback`].
    pub async fn decide_request<R>(&mut self, info: CarrierInfo, body: Option<&mut R>) -> Admit
    where
        R: AsyncRead + Unpin + Send,
    {
        let Some((adm, deadline)) = self.start() else {
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
                    Read::Late(p) => return self.ticket_rejection(&info, &adm, p, true, true),
                    Read::Closed => {
                        self.settle_admission(Outcome::Closed, None);
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

    /// One outer handshake operation before carrier handoff. A stopped listener
    /// or expired handshake drops the operation while the entry still owns its slot.
    #[doc(hidden)]
    pub async fn setup_step<F: Future>(&self, work: F) -> Option<F::Output> {
        let l = self.listener();
        super::setup::while_open(
            l.adapter().closed(),
            super::setup::while_open(
                sleep::<Tokio>(&self.shared.config.clock_domain, self.setup_deadline),
                work,
            ),
        )
        .await
        .flatten()
    }

    /// Waits for a takeover response head to be written before committing the handoff.
    #[doc(hidden)]
    pub async fn takeover_head(&mut self, written: impl Future<Output = bool>) -> bool {
        let deadline = earlier(
            self.deadline.as_ref().and_then(|peek| peek.0),
            self.setup_deadline,
        );
        let listener = self.listener();
        let write = super::setup::while_open(
            sleep::<Tokio>(&self.shared.config.clock_domain, deadline),
            written,
        );
        let outcome = match super::setup::while_open(listener.adapter().closed(), write).await {
            Some(Some(true)) => return true,
            Some(Some(false)) => Outcome::HandshakeFailed,
            Some(None) => Outcome::PeekTimedOut,
            None => Outcome::Closed,
        };
        self.settle_current_admission(outcome);
        false
    }

    /// Completes an upgrade within the deadline of its pending admission.
    #[doc(hidden)]
    pub async fn upgrade_step<F, T>(&mut self, work: F) -> Option<std::io::Result<T>>
    where
        F: Future<Output = std::io::Result<T>>,
    {
        if self.admitted || self.shared.admission.is_none() {
            return self.setup_step(work).await;
        }
        let (_, peek) = self.start()?;
        let deadline = earlier(self.setup_deadline, peek);
        let listener = self.listener();
        let response = super::setup::while_open(
            sleep::<Tokio>(&self.shared.config.clock_domain, deadline),
            work,
        );
        let outcome = match until(listener.adapter().closed(), response).await {
            Some(Some(value)) => {
                if value.is_err() {
                    self.settle_admission(Outcome::HandshakeFailed, None);
                }
                return Some(value);
            }
            Some(None) => Outcome::PeekTimedOut,
            None => Outcome::Closed,
        };
        self.deferred = None;
        self.fallback.take();
        self.settle_current_admission(outcome);
        None
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
    fn start(&mut self) -> Option<(Admission, Option<Instant>)> {
        self.handshaken = true;
        let adm = self.shared.admission.clone()?;
        let deadline = self.deadline.get_or_insert_with(|| {
            PeekDeadline(
                self.shared
                    .config
                    .clock_domain
                    .now()
                    .checked_add(adm.peek_timeout()),
            )
        });
        Some((adm, deadline.0))
    }

    fn elapsed(&self, deadline: Option<Instant>) -> bool {
        deadline.is_some_and(|at| self.shared.config.clock_domain.now() >= at)
    }

    /// Reads `prefix` on to `need` bytes from `r`, by `deadline` and
    /// until the listener closes.
    async fn read_bounded<R>(
        &self,
        prefix: Vec<u8>,
        need: usize,
        r: &mut R,
        deadline: Option<Instant>,
    ) -> Read
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let listener = self.listener();
        let read = read_more(prefix, need, r, &self.shared.config.clock_domain, deadline);
        match until(listener.adapter().closed(), read).await {
            None => Read::Closed,
            Some((p, true)) => Read::Late(p),
            Some((p, false)) => {
                let ended = p.len() < need;
                Read::Got(p, ended)
            }
        }
    }

    fn settle_admission(&mut self, outcome: Outcome, variant: Option<&Arc<str>>) {
        if !std::mem::replace(&mut self.admission_settled, true) {
            self.shared.counts.admit(outcome, variant);
        }
    }

    fn settle_current_admission(&mut self, outcome: Outcome) {
        let variant = self.variant.take();
        self.settle_admission(outcome, variant.as_ref());
    }

    /// A prefix timeout can route an ordinary byte stream to fallback.
    fn late_outcome(
        &mut self,
        prefix: Vec<u8>,
        suppress: bool,
        variant: Option<Arc<str>>,
    ) -> Admit {
        let fallback = self
            .shared
            .admission
            .as_ref()
            .is_some_and(Admission::fallback_on_peek_timeout);
        if fallback && !suppress {
            if self.shared.fallback.is_none() {
                return self.reserve_stall(variant.as_ref());
            }
            self.variant = variant;
            return Admit::Fallback(prefix);
        }
        self.settle_admission(Outcome::PeekTimedOut, None);
        Admit::Close
    }

    fn ticket_rejection(
        &mut self,
        info: &CarrierInfo,
        admission: &Admission,
        prefix: Vec<u8>,
        request: bool,
        suppress_legacy_fallback: bool,
    ) -> Admit {
        if let Some((_, reject)) = admission.ticket_verifier() {
            self.finish(reject.verdict(), None, info, prefix, request)
        } else {
            self.late_outcome(prefix, suppress_legacy_fallback, None)
        }
    }

    /// A live carrier without a replayable admission input can only stall or close.
    fn reject_without_handoff(&mut self, reject: crate::PrefixRejection, closed: Outcome) -> Admit {
        if reject == crate::PrefixRejection::Close {
            self.settle_admission(closed, None);
            Admit::Close
        } else {
            self.reserve_stall(None)
        }
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
        let Some((adm, deadline)) = self.start() else {
            self.admitted = true;
            return Admit::Accept(prefix);
        };
        let suppress_timeout_fallback = request || info.upgrade;
        if let Some((_, reject)) = adm.ticket_verifier()
            && info.is_early_data()
        {
            return self.finish(reject.verdict(), None, info, prefix, request);
        }
        if info.is_head() && info.upgrade && adm.defers_ticket_upgrade() {
            return Admit::Defer;
        }
        // An exporter whose values come later is resolved first, within the
        // peek deadline and the listener's life: a decision reads its values
        // synchronously ([`CarrierInfo::export`]).
        if let Some(e) = info.exporter().filter(|e| !e.is_resolved()) {
            let resolve = timeout(&self.shared.config.clock_domain, deadline, e.resolve());
            match until(self.listener().adapter().closed(), resolve).await {
                Some(Some(())) => {}
                Some(None) => {
                    let records = info.framing == Framing::Records;
                    return self.ticket_rejection(
                        info,
                        &adm,
                        prefix,
                        request,
                        suppress_timeout_fallback || records,
                    );
                }
                None => {
                    self.settle_admission(Outcome::Closed, None);
                    return Admit::Close;
                }
            }
        }
        if let Some((verifier, reject)) = adm.ticket_verifier() {
            let clock = self.shared.config.clock_domain.clone();
            let attempt = crate::PrefixDeadline::new(clock.clone(), deadline);
            let listener = self.listener();
            let worker = self.setup.admission_worker();
            let work = crate::proto::decision::host_future(|| {
                verifier.redeem(info, &prefix, attempt, worker)
            });
            let result = until(listener.adapter().closed(), timeout(&clock, deadline, work)).await;
            let verdict = match result {
                Some(Some(Some(Some((skip, principal))))) if !self.elapsed(deadline) => {
                    if let Some(id) = principal {
                        self.admission_evidence
                            .get_or_insert_with(Box::default)
                            .bound_prefix = Some(id);
                    }
                    AdmissionVerdict::accept(skip)
                }
                Some(_) => reject.verdict(),
                None => {
                    self.settle_admission(Outcome::Closed, None);
                    return Admit::Close;
                }
            };
            return self.finish(verdict, None, info, prefix, request);
        }
        let mut short = false;
        loop {
            let decision = match self
                .call_decide(&adm, info.clone(), &prefix, deadline)
                .await
            {
                Ok(d) => d,
                Err(NoDecision::Late) => {
                    self.settle_admission(Outcome::PeekTimedOut, None);
                    return Admit::Close;
                }
                Err(NoDecision::Closed) => {
                    self.settle_admission(Outcome::Closed, None);
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
                        Read::Late(p) => {
                            return self.late_outcome(p, suppress_timeout_fallback, variant);
                        }
                        Read::Closed => {
                            self.settle_admission(Outcome::Closed, variant.as_ref());
                            return Admit::Close;
                        }
                    }
                }
                Step::Final(v) => {
                    return self.finish(v, variant, info, prefix, request);
                }
            }
        }
    }

    /// One call of the decision, within the peek timeout and until the
    /// listener closes.
    async fn call_decide(
        &mut self,
        adm: &Admission,
        info: CarrierInfo,
        prefix: &[u8],
        deadline: Option<Instant>,
    ) -> Result<crate::AdmissionDecision, NoDecision> {
        // A synchronous decision panics in the call itself.
        let decide = crate::Decision::catch(|| {
            adm.decider()
                .expect("host admission decider")
                .decide_with_worker(info, prefix, &mut || self.setup.admission_worker())
        });
        let later = match decide {
            None => return Err(NoDecision::Closed),
            Some(crate::Decision::Now(d)) => {
                return if self.elapsed(deadline) {
                    Err(NoDecision::Late)
                } else {
                    Ok(d)
                };
            }
            Some(later @ crate::Decision::Later(_)) => later,
        };
        let listener = self.listener();
        let timed = timeout(&self.shared.config.clock_domain, deadline, later.settle());
        match until(listener.adapter().closed(), timed).await {
            Some(Some(Some(_))) if self.elapsed(deadline) => Err(NoDecision::Late),
            Some(Some(Some(d))) => Ok(d),
            Some(None) => Err(NoDecision::Late),
            // Panicked, or cancelled with the listener.
            Some(Some(None)) | None => Err(NoDecision::Closed),
        }
    }

    /// Counts a final verdict and keeps an acceptance's value and label.
    fn finish(
        &mut self,
        verdict: AdmissionVerdict,
        variant: Option<Arc<str>>,
        info: &CarrierInfo,
        mut prefix: Vec<u8>,
        request: bool,
    ) -> Admit {
        match verdict {
            AdmissionVerdict::Accept { skip, value } => {
                self.settle_admission(Outcome::Accepted, variant.as_ref());
                self.admitted = true;
                if value.is_some() {
                    self.admission_evidence
                        .get_or_insert_with(Box::default)
                        .value = value;
                }
                self.variant = variant;
                prefix.drain(..skip);
                Admit::Accept(prefix)
            }
            AdmissionVerdict::Fallback { value } => {
                if request
                    && Setup::new(&mut self.setup, ())
                        .claim(Transfer::Fallback)
                        .is_err()
                {
                    return Admit::Close;
                }
                if !request && self.shared.fallback.is_none() {
                    return self.reserve_stall(variant.as_ref());
                }
                self.variant = variant;
                self.fallback = Some((None, value));
                Admit::Fallback(prefix)
            }
            AdmissionVerdict::Takeover { value } => {
                if self.shared.fallback.is_none() {
                    return self.reserve_stall(variant.as_ref());
                }
                self.variant = variant;
                self.fallback = Some((Some(info.clone()), value));
                Admit::TakeOver(prefix)
            }
            AdmissionVerdict::Stall => self.reserve_stall(variant.as_ref()),
            _ => {
                self.settle_admission(Outcome::Closed, variant.as_ref());
                Admit::Close
            }
        }
    }

    fn reserve_stall(&mut self, variant: Option<&Arc<str>>) -> Admit {
        if self.start_stall() {
            self.settle_admission(Outcome::Stalled, variant);
            Admit::Stall
        } else {
            self.settle_admission(Outcome::StallOverflow, variant);
            Admit::Close
        }
    }

    /// Transfers responsibility for recording the HTTP fallback outcome.
    #[doc(hidden)]
    pub fn request_fallback(&mut self) -> Option<RequestFallback> {
        if self.admission_settled || !matches!(self.fallback, Some((None, _))) {
            return None;
        }
        self.admission_settled = true;
        Some(RequestFallback(Arc::new(RequestFallbackCount {
            shared: self.shared.clone(),
            variant: self.variant.take(),
            settled: AtomicBool::new(false),
        })))
    }

    /// Records an HTTP fallback on dispatch or when the adapter answers 404.
    #[doc(hidden)]
    pub fn complete_request_fallback(&mut self, has_target: bool) {
        if let Some(outcome) = self.request_fallback() {
            outcome.complete(has_target);
        }
    }

    fn make_pipe(&mut self, io: AdmitIo, rest: Vec<u8>) -> Option<PipeIo> {
        self.host(|| io.into_pipe(rest))
    }

    /// Runs the adapter's setup callback and settles a panic at this admission.
    #[doc(hidden)]
    pub fn host<T>(&mut self, call: impl FnOnce() -> T) -> Option<T> {
        let value = crate::proto::decision::host(call);
        if value.is_none() && self.setup.host_failed().is_ok() {
            if self.shared.admission.is_some() && !self.admission_settled && !self.admitted {
                let outcome = if self.handshaken {
                    Outcome::Closed
                } else {
                    Outcome::HandshakeFailed
                };
                self.settle_current_admission(outcome);
            } else {
                self.listener().adapter().count_setup_failure();
            }
            self.handshaken = true;
        }
        value
    }

    /// Hands `io`, `replay` in front, to the listener's fallback, its slots
    /// given back first, until the fallback completes.
    async fn fall_back(
        &mut self,
        info: CarrierInfo,
        replay: Vec<u8>,
        io: AdmitIo,
        outcome: Outcome,
    ) -> Result<(), AdmissionEnd> {
        let listener = self.listener();
        let io = Setup::new(&mut self.setup, io);
        let committed = || {
            let (_, value) = self.fallback.take().unwrap_or_default();
            self.admission_settled = true;
            let shared = self.shared.clone();
            let variant = self.variant.take();
            let dispatched = move || shared.counts.admit(outcome, variant.as_ref());
            (value, dispatched)
        };
        let served = listener
            .adapter()
            .hand_over(info, io, replay, committed)
            .await?;
        self.fallback_end = Some(if served.detached {
            FallbackEnd::Detached
        } else {
            FallbackEnd::Returned
        });
        match served.error {
            Some(error) => Err(HandleError::Fallback(crate::proto::listener::FallbackError(
                Arc::new(error),
            ))
            .into()),
            None => Ok(()),
        }
    }

    /// Hands a request carrier the admission gave to the listener's
    /// fallback ([`Admit::TakeOver`]) over: `io`, its carrier, `replay` in
    /// front, its slots given back first, until the fallback's future
    /// completed. The adapter answered the request as an accepted
    /// carrier's before, and closes what it holds of the request after,
    /// unless the host detached it ([`Entry::is_detached`]). Nothing
    /// happens on an entry the admission did not hand over so.
    pub async fn take_over(&mut self, io: impl Into<AdmitIo>, replay: Vec<u8>) {
        let Some((Some(info), _)) = &self.fallback else {
            return;
        };
        let info = info.clone();
        let _ = self
            .fall_back(info, replay, io.into(), Outcome::Takeover)
            .await;
    }

    /// Whether the host detached the carrier the listener's fallback took
    /// over ([`Takeover::detach`](crate::Takeover::detach)): its adapter
    /// then leaves what it holds of it (a QUIC connection, a WebTransport
    /// session, an HTTP request) to the host, instead of closing it.
    #[must_use]
    pub fn is_detached(&self) -> bool {
        matches!(self.fallback_end, Some(FallbackEnd::Detached))
    }

    /// Consumes a shared connection's failed entry. Once fallback took the
    /// connection, its return guard or the detached host owns the close.
    #[doc(hidden)]
    pub fn end_unclaimed_connection(mut self, close: impl FnOnce()) {
        if self.fallback_end.is_none() {
            self.host(close);
        }
    }

    /// Stalls `io` ([`Entry::stall`]), then ends its sending half
    /// gracefully, within [`DRAIN_LIMIT`](super::tokio::DRAIN_LIMIT).
    fn stall_io(&mut self, io: AdmitIo, discard_input: bool) -> AdmissionEnd {
        if self.start_stall()
            && let Some(mut stall) = self.setup.stalled(io)
        {
            let shared = self.shared.clone();
            let key = self.key;
            AdmissionEnd::Stalled(tokio::spawn(async move {
                let records = stall.carrier_mut().framing() == Framing::Records;
                let slot = stall.slot();
                if let Some(closed) = stall.carrier_mut().stall_until.take() {
                    super::setup::while_open(
                        closed,
                        Self::stall_reading(&shared, key, slot, None, false),
                    )
                    .await;
                } else {
                    let reader = if discard_input {
                        stall.carrier_mut().reader()
                    } else {
                        None
                    };
                    Self::stall_reading(&shared, key, slot, reader, records).await;
                }
                let _ =
                    tokio::time::timeout(super::tokio::DRAIN_LIMIT, stall.carrier_mut().shutdown())
                        .await;
                drop(stall);
            }))
        } else {
            AdmissionEnd::Failed(HandleError::NotAdmitted)
        }
    }

    /// Counts the carrier as stalled: `false` when the listener closed,
    /// the source has `max_pending_per_source - 1` stalled carriers, or
    /// the listener's stalled carriers hold half of `max_pending`.
    fn start_stall(&mut self) -> bool {
        if self.setup.stalling() {
            return true;
        }
        let admitted = {
            let mut st = self.shared.lock();
            !st.closed && self.setup.slot().is_some_and(|s| st.core.stall(s))
        };
        admitted && self.setup.stall().is_ok()
    }

    fn stall_end(shared: &ListenShared, slot: Slot) -> Closing<'_> {
        Closing {
            shared,
            id: None,
            slot: Some(slot),
            ticket: None,
        }
    }

    /// Commits an admitted shared connection before its stream accept loop starts.
    #[doc(hidden)]
    pub fn hand_off_connection(mut self) -> Result<(), HandleError> {
        Setup::new(&mut self.setup, ()).publish(|()| Ok(()))
    }

    /// Gives the slots back without counting anything: for a carrier that
    /// will not be one after all (an HTTP request that turned out to
    /// belong to a carrier already set up), read as far as it goes.
    pub fn release(mut self) {
        self.handshaken = true;
        self.deferred = None;
        self.admission_settled = true;
        let _ = self.setup.give_back();
    }

    /// Stalls a request owned by the calling executor, including borrowed bodies.
    #[doc(hidden)]
    pub async fn stall_local<C>(&mut self, carrier: C) {
        if self.start_stall()
            && let Some(stall) = self.setup.stalled(carrier)
        {
            Self::stall_reading(&self.shared, self.key, stall.slot(), None, false).await;
            drop(stall);
        }
    }

    /// Hands an adapter-owned request to listener stall cleanup. Dropping its
    /// observer ends that request; the task releases its slot after the reader.
    #[doc(hidden)]
    pub fn stall_request<R, F, W>(
        &mut self,
        reader: Option<R>,
        finish: F,
    ) -> impl Future<Output = ()> + use<R, F, W>
    where
        R: AsyncRead + Unpin + Send + 'static,
        F: FnOnce(Option<R>) -> W + Send + 'static,
        W: Future<Output = ()> + Send,
    {
        let (mut result, observe) = oneshot::channel();
        if self.start_stall()
            && let Some(mut stall) = self.setup.stalled(reader)
        {
            let shared = self.shared.clone();
            let key = self.key;
            tokio::spawn(async move {
                let slot = stall.slot();
                let reader = stall
                    .carrier_mut()
                    .as_mut()
                    .map(|r| r as &mut (dyn AsyncRead + Unpin + Send));
                super::setup::while_open(
                    result.closed(),
                    Self::stall_reading(&shared, key, slot, reader, false),
                )
                .await;
                let end = stall.carrier_mut().take();
                let _ = tokio::time::timeout(
                    super::tokio::DRAIN_LIMIT,
                    crate::proto::decision::host_future(|| finish(end)),
                )
                .await;
                drop(stall);
                let _ = result.send(());
            });
        }
        async move {
            let _ = observe.await;
        }
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
    /// once ([`ListenerLimits::max_pending_per_source`]), and the listener
    /// at most half of [`ListenerLimits::max_pending`]: beyond them, a
    /// [`AdmissionVerdict::Stall`] is [`Admit::Close`] (counted in
    /// [`AdmissionStats::stall_overflow`]).
    pub async fn stall<R>(&mut self, reader: Option<&mut R>)
    where
        R: AsyncRead + Unpin + Send,
    {
        if !self.start_stall() {
            return;
        }
        let Some(slot) = self.setup.slot() else {
            return;
        };
        Self::stall_reading(
            &self.shared,
            self.key,
            slot,
            reader.map(|r| r as &mut (dyn AsyncRead + Unpin + Send)),
            false,
        )
        .await;
    }

    /// [`Entry::stall`] of a byte stream or of a message-framed carrier
    /// (`records`), which discards message by message.
    async fn stall_reading(
        shared: &ListenShared,
        key: u64,
        slot: Slot,
        reader: Option<&mut (dyn AsyncRead + Unpin + Send)>,
        records: bool,
    ) {
        let Some(adm) = shared.admission.clone() else {
            return;
        };
        let (min, max) = adm.stall_interval();
        let mac = shared.stall_key.mac(&[&key.to_be_bytes()]);
        let mut v = [0u8; 16];
        v.copy_from_slice(&mac[..16]);
        let span = max.saturating_sub(min).as_nanos() + 1;
        let off = u64::try_from(u128::from_be_bytes(v) % span).unwrap_or(u64::MAX);
        let duration = min.saturating_add(Duration::from_nanos(off));
        let clock = &shared.config.clock_domain;
        let deadline = clock.now().checked_add(duration);
        let wait = async {
            if let Some(r) = reader {
                discard(r, adm.discard_buffer(), records).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let _ = until(
            Self::stall_end(shared, slot),
            timeout(clock, deadline, wait),
        )
        .await;
        shared.lock().core.unstall(slot);
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
            let moved =
                key == self.key || self.setup.slot().is_some_and(|s| st.core.move_slot(s, key));
            (key, moved)
        };
        if key != self.key {
            if !moved {
                self.shared.counts.commit(|counts| &counts.refused);
                // Refused before admission.
                self.handshaken = true;
                self.admission_settled = true;
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
        if self.shared.admission.is_none() {
            if !self.handshaken {
                c.commit(|counts| &counts.setup_failures);
            }
        } else if !self.admission_settled {
            let outcome = if !self.handshaken {
                if self.setup.checkpoint().is_ok() {
                    Outcome::HandshakeFailed
                } else {
                    Outcome::Closed
                }
            } else if self
                .deadline
                .as_ref()
                .is_some_and(|peek| self.elapsed(earlier(peek.0, self.setup_deadline)))
            {
                Outcome::PeekTimedOut
            } else if self.deadline.is_some() {
                Outcome::Closed
            } else {
                return;
            };
            self.settle_current_admission(outcome);
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
/// config.session_policy.limits.steady_attachments = 8;
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
/// let mut req = zmux::ChangeRequest::new(session.capacity(), zmux::DEFAULT_JOIN_TIMEOUT);
/// req.add.push(zmux::MemberSpec {
///     candidate: None,
///     attachments: vec![zmux::AttachmentSpec::new(zmux::Directions::BOTH, PipeOptions::default())],
/// });
/// let change = session.begin_change(req)?;
/// let attempt = change.start_member(0, zmux::CarrierOpener::prepared(vec![PipeIo::from_tcp(second)]))?;
/// let result = attempt.wait().await;
/// change.commit()?;
/// let pipe = session.pipe(result.pipes[0]).expect("confirmed pipe");
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
            .map_err(|e| self.listener.count(&e))
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
    /// `true` when the host detached the carrier
    /// ([`Takeover::detach`](crate::Takeover::detach)): the adapter leaves
    /// what it holds of the connection to the host then.
    pub async fn take_over(&self, info: CarrierInfo, io: AdmitIo, replay: Vec<u8>) -> bool {
        self.take_over_request(info, io, replay, None).await
    }

    /// Dispatches an HTTP fallback, recording it when the host callback starts.
    #[doc(hidden)]
    pub async fn take_over_request(
        &self,
        info: CarrierInfo,
        io: AdmitIo,
        replay: Vec<u8>,
        outcome: Option<RequestFallback>,
    ) -> bool {
        self.hand_over(
            info,
            Setup::new(Authority::listener(&self.listener.shared), io),
            replay,
            || {
                (None, move || {
                    if let Some(outcome) = outcome {
                        outcome.complete(true);
                    }
                })
            },
        )
        .await
        .is_ok_and(|s| s.detached)
    }

    async fn hand_over<O: Owner, D: FnOnce() + Send + 'static>(
        &self,
        info: CarrierInfo,
        setup: Setup<O, AdmitIo>,
        replay: Vec<u8>,
        committed: impl FnOnce() -> (Option<AdmittedValue>, D),
    ) -> Result<super::admission::Served, HandleError> {
        let Some(f) = self.listener.shared.fallback.clone() else {
            return Err(HandleError::NotAdmitted);
        };
        let io = setup.claim(Transfer::Fallback)?;
        let (value, dispatched) = committed();
        let info = info.with_framing(io.framing());
        let served = f
            .serve(io.into_takeover(info, replay, value), dispatched)
            .await;
        if served.error.is_some()
            && let Some(l) = &self.listener.shared.logger
        {
            l.log(
                crate::LogLevel::Error,
                "zmux: the listener's fallback failed",
            );
        }
        Ok(served)
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

    /// [`ListenerConfig::handshake_timeout`], fixed for the listener's life.
    #[must_use]
    pub fn handshake_timeout(&self) -> Duration {
        self.listener.shared.lock().core.config().handshake_timeout
    }

    /// The listener's clock for admission and protocol setup.
    #[must_use]
    pub fn clock_domain(&self) -> &'a crate::ClockDomain {
        &self.listener.shared.config.clock_domain
    }

    /// Whether the listener is closed ([`Listener::close`]): an adapter
    /// tells with it why [`ListenerAdapter::enter`] gave no place.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.listener.shared.lock().closed
    }

    /// Ordinary carrier setup driven by a foreign event loop. Calling
    /// `cancel` synchronously competes for the same handoff as the listener.
    /// Dropping the returned future interrupts any outstanding I/O.
    #[doc(hidden)]
    pub fn cancellable_setup(
        &self,
        pipe: PipeIo,
        peer: SocketAddr,
        source: Option<SocketAddr>,
    ) -> (
        SetupCancellation,
        impl Future<Output = Result<(), HandleError>> + Send + use<>,
    ) {
        let gate = Arc::<super::setup::Handoff>::default();
        let cancel = SetupCancellation(gate.clone());
        let mut hint = PipeHint::from_peer(peer);
        hint.source = source;
        let listener = self.listener.clone();
        (cancel, async move {
            let result = listener.incoming(pipe, hint, Some(gate.clone())).await;
            // A setup error before handoff is also final before foreign delivery.
            gate.commit();
            result
        })
    }

    /// Drives one request carrier until its setup completes or the request disappears.
    /// Internal entry point for the HTTP-family adapters.
    #[doc(hidden)]
    pub async fn setup_until(
        &self,
        io: PipeIo,
        hint: PipeHint,
        gone: impl Future,
    ) -> Option<Result<(), HandleError>> {
        super::setup::while_open(gone, self.listener.handle_pipe(io, hint)).await
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

    /// Reserves a carrier's in-flight memory on the listener's ledger.
    /// Keep the returned grant until the corresponding buffers are gone.
    ///
    /// # Errors
    ///
    /// The listener's budget has insufficient room.
    pub fn reserve_memory(&self, bytes: u64) -> io::Result<MemoryCharge> {
        let account = &self.listener.shared.account;
        let reservation = account.ledger.reserve(bytes);
        for session in account.evict_under_pressure() {
            session.close_suspended();
        }
        reservation
            .map(MemoryCharge)
            .ok_or_else(|| io::Error::other("listener memory budget exhausted"))
    }

    /// Counts a connection that an accept loop could not make a pipe input
    /// of: a failed TLS handshake or its timeout (the handshake a join sent
    /// in early data waits for included), a failed HTTP or WebSocket
    /// upgrade, or the setup limit. For carrier adapters' own accept loops
    /// ([`ListenerStats::setup_failures`]); such a connection is counted
    /// nowhere else.
    pub fn count_setup_failure(&self) {
        let c = &self.listener.shared.counts;
        c.commit(|counts| &counts.setup_failures);
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
            limits.limits,
            crate::proto::session::minimum_listener_admission(&config),
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
            locators: Arc::default(),
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
                live: super::setup::Sessions::default(),
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
        let weak = Arc::downgrade(&shared);
        shared.account.bind_max_suspended(Box::new(move || {
            let s = weak.upgrade()?;
            let max = s.lock().core.config().limits.max_suspended;
            Some(max)
        }));
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
        if let Some(a) = super::hooks::settle_by(
            f.ask(info),
            &self.shared.config.clock_domain,
            deadline,
            self.closed_or_evicted(id),
        )
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

    /// The handshake deadline, if representable.
    fn handshake_deadline(&self) -> Option<Instant> {
        let timeout = self.shared.lock().core.config().handshake_timeout;
        self.shared.config.clock_domain.now().checked_add(timeout)
    }

    /// Counts a carrier the listener did not use.
    fn count(&self, e: &HandleError) {
        let c = &self.shared.counts;
        match e {
            HandleError::Rejected => c.commit(|counts| &counts.rejected),
            HandleError::Refused => c.commit(|counts| &counts.refused),
            HandleError::TimedOut => c.commit(|counts| &counts.timed_out),
            HandleError::SetupFailed => c.commit(|counts| &counts.setup_failures),
            // Counted by the admission.
            HandleError::NotAdmitted | HandleError::Fallback(_) => {}
        }
    }

    fn enter_uncounted(
        &self,
        peer: SocketAddr,
        source: Option<SocketAddr>,
    ) -> Result<Entry, HandleError> {
        let source = source.unwrap_or(peer);
        let mut entry = Entry::new(self.shared.clone(), source, peer);
        self.reserve(&mut entry)?;
        entry.handshaken = false;
        Ok(entry)
    }

    fn reserve(&self, entry: &mut Entry) -> Result<(), HandleError> {
        let source = entry.source;
        // The evicted carrier is woken after the lock.
        let mut wakes = WakeList::default();
        entry.key = entry.setup.reserve(&self.shared, || {
            let mut st = self.shared.lock();
            let key = st.core.config().source_key(source.ip());
            if st.closed {
                return Err(HandleError::Refused);
            }
            match st.core.enter(key) {
                Entered::Taken { slot, evicted } => {
                    st.evict_slot(evicted, &mut wakes);
                    Ok((slot, key))
                }
                Entered::SourceFull => Err(HandleError::Refused),
                Entered::Full => Err(HandleError::Rejected),
            }
        })?;
        drop(wakes);
        Ok(())
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
        let establishing = st.live.establishing();
        drop(st);
        for s in establishing {
            s.close_unaccepted();
        }
        for session in unaccepted {
            session.shared().close_unaccepted();
        }
    }

    /// Refuses subsequent bootstrap carriers after their handshake with
    /// `CONNECTION_REFUSED` and these reason bytes. Joins and lanes stay open.
    /// Repeating the call replaces the reason until graceful shutdown begins.
    pub fn drain(&self, reason: &[u8]) {
        self.shared.lock().core.drain(reason);
    }

    /// Resumes accepting new sessions. Has no effect after graceful shutdown begins.
    pub fn undrain(&self) {
        self.shared.lock().core.undrain();
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

        let (sessions, unaccepted, establishing) = {
            let mut wakes = WakeList::default();
            let mut st = self.shared.lock();
            st.core.begin_shutdown(reason);
            st.accept_waiters.wake_all(&mut wakes);
            let unaccepted = std::mem::take(&mut st.accept);
            for _ in 0..unaccepted.len() {
                st.core.release_unaccepted();
            }
            let live = st.live.accepted();
            let establishing = st.live.establishing();
            (live, unaccepted, establishing)
        };
        for s in establishing {
            s.close_unaccepted();
        }
        for session in unaccepted {
            session.shared().close_unaccepted();
        }
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

    /// The limits in effect ([`Listener::set_limits`]).
    #[must_use]
    pub fn limits(&self) -> ListenerLimits {
        self.shared.lock().core.config().limits
    }

    /// Replaces the listener's limits; invalid ones change nothing. New
    /// carriers and the next decisions on held ones use them at once:
    /// lowered pending bounds refuse or displace new carriers until the
    /// count is below them but close no carrier already held. A lowered `max_suspended` closes the longest-suspended sessions beyond
    /// it (`ZMUX_RESUME_TIMEOUT`), a changed `first_record_timeout`
    /// applies to carriers that arrive after the call, and a changed
    /// `memory_budget` immediately applies to new reservations.
    ///
    /// # Errors
    ///
    /// A limit failed [`ListenerLimits::validate`] or the memory budget
    /// is below the outstanding charges.
    pub fn set_limits(&self, limits: ListenerLimits) -> Result<(), crate::InvalidConfig> {
        // Trimmed under the listener's lock (then the account's), so that
        // no suspension slips past the new limit; closed after it.
        let over = {
            let mut st = self.shared.lock();
            super::setup::update_listener_limits(&mut st.core, &self.shared.account, limits)?
        };
        for s in over {
            s.close_suspended();
        }
        Ok(())
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
        let limit = self.shared.lock().core.config().handshake_timeout;
        let serve = Arc::new(serve);
        // The setup tasks, oldest first; each spawns its serving apart, so
        // that aborting it ends only the setup.
        let mut setups = SetupTasks::default();
        while let Some(accepted) = self
            .accept_or_close(crate::proto::decision::host_future(&mut accept))
            .await
        {
            let Some(accepted) = accepted else {
                self.adapter().count_setup_failure();
                break;
            };
            let Some(conn) = accepted else { break };
            let conn = match conn {
                Ok(conn) => conn,
                Err(e) => {
                    accept_failed(&e).await;
                    continue;
                }
            };
            setups.make_room(self.limits().max_pending);
            let Some(made) = crate::proto::decision::host(|| setup(conn)) else {
                continue;
            };
            let (l, serve) = (self.clone(), serve.clone());
            let task = tokio::spawn(async move {
                let work = crate::proto::decision::host_future(|| made);
                let clock = &l.shared.config.clock_domain;
                let deadline = clock.now().checked_add(limit);
                if let Some(Some(Some(Ok(c)))) =
                    l.accept_or_close(timeout(clock, deadline, work)).await
                {
                    tokio::spawn(async move {
                        crate::proto::decision::host_future(|| serve(l, c)).await;
                    });
                }
            });
            setups.push(task.abort_handle());
        }
    }

    /// `accept`'s result, or `None` once the listener is closed.
    async fn accept_or_close<T>(&self, accept: impl Future<Output = T>) -> Option<T> {
        super::setup::while_open(self.adapter().closed(), accept).await
    }

    /// Handles a new carrier: a new session (returned by
    /// [`Listener::accept`]) or a join of an existing one. A carrier that
    /// did not enter the listener through an adapter
    /// ([`PipeHint::from_entry`]) enters here: it takes a source slot (its
    /// hint's source, or peer), and the listener's admission reads its
    /// prefix and decides ([`Entry::admit`]); a carrier not accepted is
    /// stalled or closed ([`HandleError::NotAdmitted`]). Takes ownership on entry.
    /// Resolves when a bootstrap is queued, a join or lane is attached, or
    /// admission and any synchronous fallback have finished. Normal fallback return
    /// is success, including without detach. A failed fallback reports its cause in
    /// [`HandleError::Fallback`]. Dropping the
    /// future cancels pending setup. An attached carrier belongs to its session.
    /// A join over a stream of a session that runs over the session it
    /// joins ([`PipeIo::from_stream`]) is refused: the carrier is closed
    /// and the session sends `PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT)`.
    ///
    /// The first poll checks listener admission before any I/O or wait.
    /// A closed listener's carrier resolves
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
        self.incoming(pipe, hint, None)
    }

    fn incoming(
        &self,
        mut pipe: PipeIo,
        mut hint: PipeHint,
        withdrawal: Option<Arc<super::setup::Handoff>>,
    ) -> impl Future<Output = Result<(), HandleError>> + Send + '_ {
        let mut entry = hint.entry.take().unwrap_or_else(|| {
            let peer = hint.peer.or(hint.source).unwrap_or(NO_ADDR);
            Entry::new(self.shared.clone(), hint.source.unwrap_or(peer), peer)
        });
        if let Some(gate) = withdrawal {
            entry.setup.observe_withdrawal(gate);
        }
        entry.setup.bind(pipe.attachment());
        let setup = Box::pin(self.handle(Setup::new(entry, pipe), hint));
        async move {
            let r = setup.await;
            if let Err(e) = &r {
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

    #[cfg(feature = "test-hooks")]
    pub(crate) fn revisions(&self) -> tokio::sync::watch::Receiver<()> {
        self.shared.counts.revision.subscribe()
    }

    /// What happened to the carriers handed to the listener, and to the
    /// connections its `serve` loops set up: counts since it was made, for
    /// monitoring (a server whose certificate is wrong sees only setup
    /// failures).
    #[must_use]
    pub fn stats(&self) -> ListenerStats {
        let c = &self.shared.counts;
        c.common.snapshot({
            let a = &c.admission;
            AdmissionStats {
                accepted: a.accepted.load(Relaxed),
                fallback: a.fallback.load(Relaxed),
                takeover: a.takeover.load(Relaxed),
                stalled: a.stalled.load(Relaxed),
                closed: a.closed.load(Relaxed),
                stall_overflow: a.stall_overflow.load(Relaxed),
                too_large: a.too_large.load(Relaxed),
                peek_timed_out: a.peek_timed_out.load(Relaxed),
                handshake_failed: a.handshake_failed.load(Relaxed),
            }
        })
    }

    /// Owns the carrier during setup and transfers it at handoff.
    async fn handle(
        &self,
        mut incoming: Setup<Entry, PipeIo>,
        mut hint: PipeHint,
    ) -> Result<(), HandleError> {
        let (entry, pipe) = incoming.parts();
        let shared = &self.shared;
        // Decided on the first poll (see `handle_pipe`).
        if !Arc::ptr_eq(shared, &entry.shared)
            || hint
                .connection
                .as_ref()
                .is_some_and(|a| !a.issuer.ptr_eq(&Arc::downgrade(shared)))
            || shared.lock().closed
        {
            return Err(HandleError::Refused);
        }
        // A stream that may be a lane of a pipe on its connection waits
        // for its first record outside the limits: its connection was
        // admitted, and it takes a slot once it turns out a join or a
        // new session.
        let exempt = pipe.conn().and_then(super::lanes::Exempt::new);
        if exempt.is_some() {
            entry.setup.exempt()?;
            entry.admitted = true;
            entry.handshaken = true;
        } else {
            if entry.setup.slot().is_none() {
                self.reserve(entry)?;
                entry.admitted = hint.connection.is_some();
            }
            if !entry.admitted {
                let admitted = incoming
                    .prepare(async |entry, pipe| {
                        entry
                            .admission_result(CarrierInfo::new(), pipe.into())
                            .await
                            .map_err(HandleError::from)
                    })
                    .await?;
                let Some(accepted) = admitted.transpose() else {
                    return Ok(());
                };
                incoming = accepted;
            }
        }
        let (entry, pipe) = incoming.parts();
        let mut evidence = entry.admission_evidence.take();
        if evidence.is_none()
            && let Some(value) = hint.connection.as_ref().and_then(|a| a.value.clone())
        {
            evidence = Some(Box::new(super::tokio::AdmissionEvidence {
                value: Some(value),
                bound_prefix: None,
            }));
        }
        hint.value = evidence
            .as_deref()
            .and_then(|evidence| evidence.value.clone());
        hint.clock.clone_from(&shared.config.clock_domain);
        pipe.admission_evidence = evidence;
        if let Some(v) = entry.variant.take()
            && pipe.variant.is_none()
        {
            pipe.variant = Some(v);
        }
        // A half is not transformed: a handshake needs both directions.
        if let Some(token) = hint.pair.take() {
            return self.handle_paired(incoming, hint, &token).await;
        }
        let mut incoming = incoming
            .prepare(async |entry, pipe| self.prepare(pipe, &mut hint, entry).await)
            .await?;
        let (_, pipe) = incoming.parts();
        let now = shared.config.clock_domain.now();
        let (limits, id) = {
            let mut st = shared.lock();
            if st.closed {
                return Err(HandleError::Refused);
            }
            let limits = st.core.config().clone();
            let id = if exempt.is_none() {
                st.core.open(None, pipe.framing, now)
            } else {
                st.core.open_stream(pipe.framing, now)
            };
            (limits, id)
        };
        // Leaves the pending carriers and gives its slots back however this
        // ends, a dropped handler included.
        let incoming = incoming.register(|entry| Pending::new(shared, id, entry));
        Box::pin(self.classify(incoming, hint, Origin::Single(exempt), &limits)).await
    }

    async fn prepare(
        &self,
        mut pipe: PipeIo,
        hint: &mut PipeHint,
        entry: &mut Entry,
    ) -> Result<PipeIo, HandleError> {
        if let Some(t) = self.shared.transform.clone() {
            let lease = pipe.attachment().clone();
            pipe = self.transform(&t, pipe, hint, entry).await?;
            pipe.adopt_attachment(lease);
        }
        if self
            .accept_or_close(timeout(
                &self.shared.config.clock_domain,
                self.handshake_deadline(),
                pipe.resolve_exporter(),
            ))
            .await
            .is_none()
        {
            entry.setup.stop()?;
            return Err(HandleError::Refused);
        }
        Ok(pipe)
    }

    async fn classify(
        &self,
        mut setup: Setup<Pending, PipeIo>,
        hint: PipeHint,
        origin: Origin,
        limits: &ListenerConfig,
    ) -> Result<(), HandleError> {
        let (pending, pipe) = setup.parts();
        let shared = &self.shared;
        let clock = &shared.config.clock_domain;
        let classified = until(
            self.closed_or_evicted(Some(pending.registration.id)),
            timeout(
                clock,
                clock.now().checked_add(limits.limits.first_record_timeout),
                Self::first_record(shared, pending.registration.id, pipe),
            ),
        )
        .await
        .ok_or(HandleError::Refused)?
        .ok_or(HandleError::TimedOut)?;
        let exempt = match origin {
            Origin::Single(exempt) => exempt,
            Origin::Pair => match classified {
                Classified::NewSession { .. } | Classified::Join { .. } => None,
                Classified::Reject
                | Classified::BadHello { .. }
                | Classified::Lane { .. }
                | Classified::NeedMore => return Err(HandleError::Rejected),
            },
        };
        if !matches!(classified, Classified::Reject)
            && let Some(taken) = pipe.taken.take()
        {
            crate::proto::decision::host(taken).ok_or(HandleError::SetupFailed)?;
        }
        // Its first record is in: a lane goes on without a slot; a join or
        // a new session takes one now, like any carrier.
        let was_exempt = exempt.is_some();
        drop(exempt);
        if was_exempt
            && matches!(
                classified,
                Classified::NewSession { .. } | Classified::Join { .. }
            )
        {
            match self.reserve(&mut pending.entry) {
                Ok(()) => {}
                Err(err) => {
                    // Known to be a join or a session now: the reject policy, though
                    // without a slot it cannot be stalled.
                    let profile = matches!(classified, Classified::Join { .. }).then_some(2);
                    let info =
                        RejectInfo::new(profile, None, "pending_limit", hint.source.or(hint.peer));
                    self.refuse(&info, None, None, None).await;
                    return Err(err);
                }
            }
        }
        match classified {
            Classified::NewSession { first } => {
                pipe.prefix = first;
                self.start_session(setup, (hint.source, hint.peer)).await
            }
            Classified::Lane {
                lane_key,
                pipe: id,
                lane,
                bytes,
            } => {
                super::lanes::route(setup, shared, &lane_key, PipeId(id).lane(lane), bytes)?;
                shared.counts.commit(|counts| &counts.joins);
                Ok(())
            }
            Classified::BadHello { reason } => {
                self.rejected(
                    setup,
                    RejectInfo::new(Some(2), None, reason, hint.source.or(hint.peer)),
                )
                .await
            }
            Classified::Join { locator, hello } => {
                Box::pin(self.join(setup, &locator, &hello, hint.source.or(hint.peer))).await
            }
            // First bytes that are no carrier this listener knows (step 2).
            _ => {
                let info = RejectInfo::new(None, None, "malformed", hint.source.or(hint.peer));
                self.rejected(setup, info).await
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
        hint: &mut PipeHint,
        entry: &mut Entry,
    ) -> Result<PipeIo, HandleError> {
        // The transform reads the carrier: it is the listener's now, never
        // handed on with bytes replayed.
        if let Some(taken) = pipe.taken.take() {
            crate::proto::decision::host(taken).ok_or(HandleError::SetupFailed)?;
        }
        let kind = (
            pipe.reader.is_some(),
            pipe.writer.is_some(),
            pipe.framing,
            pipe.split_bootstrap,
        );
        let carrier = pipe.carrier;
        let original_evidence = pipe.admission_evidence.take();
        let sources = pipe.record_sources();
        let source = hint.source.or(hint.peer);
        hint.transform_deadline = self.handshake_deadline();
        let timed = timeout(
            &self.shared.config.clock_domain,
            hint.transform_deadline,
            crate::proto::decision::host_future(|| t.call(pipe, hint)),
        );
        let r = self.accept_or_close(timed).await;
        let mut io = match r {
            Some(Some(Some(Ok(io)))) => io,
            Some(Some(None)) => {
                entry.setup.host_failed()?;
                return Err(HandleError::SetupFailed);
            }
            None => return Err(HandleError::Refused),
            Some(Some(Some(Err(e)))) => {
                let inner = e.get_ref();
                let refused =
                    inner.and_then(|e| e.downcast_ref::<crate::proto::listener::Refused<PipeIo>>());
                // The carrier handed back stays open while it is stalled.
                let (r, held) = match refused {
                    Some(r) => (Some(&r.error), r.take_carrier()),
                    None => (
                        inner.and_then(|e| e.downcast_ref::<crate::proto::listener::RejectError>()),
                        None,
                    ),
                };
                if let Some(r) = r {
                    let info = RejectInfo::from_error(r.clone(), source);
                    self.refuse(&info, None, Some(entry), held).await;
                    return Err(HandleError::Rejected);
                }
                return Err(HandleError::SetupFailed);
            }
            Some(None) => return Err(HandleError::SetupFailed),
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
        io.accounting_sources = Some(Box::new(sources));
        if let Some(evidence) = &mut io.admission_evidence {
            let original = original_evidence
                .map(|evidence| *evidence)
                .unwrap_or_default();
            evidence.bound_prefix = original.bound_prefix;
            if evidence.value.is_none() {
                evidence.value = original.value;
            }
        } else {
            io.admission_evidence = original_evidence;
        }
        Ok(io)
    }

    /// A half of a split carrier: it holds its slots like any carrier until the pair is
    /// complete (so the listener's limits bound the unpaired halves, per source too), and
    /// the first half keeps its slot through combined setup. It
    /// waits for the other, with the same token and the opposite direction, within the
    /// handshake timeout from its arrival. Nothing is read before the pair is complete. The
    /// combined setup owns both halves and reports the same result to both callers.
    async fn handle_paired(
        &self,
        mut setup: Setup<Entry, PipeIo>,
        hint: PipeHint,
        token: &[u8],
    ) -> Result<(), HandleError> {
        let (entry, pipe) = setup.parts();
        let shared = &self.shared;
        let Ok(token) = <[u8; PAIRING_TOKEN_LEN]>::try_from(token) else {
            return Err(HandleError::Rejected);
        };
        let uplink = pipe.reader.is_some();
        if uplink == pipe.writer.is_some() {
            return Err(HandleError::Rejected);
        }
        let clock = &shared.config.clock_domain;
        let arrived = clock.now();
        // A half on a connection that carries a pipe has no slot yet: it takes one now.
        if entry.setup.slot().is_none() {
            self.reserve(entry)?;
        }
        let _withdraw = Withdraw(entry.setup.withdrawal());
        let (result, mut answer) = oneshot::channel();
        let (limits, id, pair) = {
            let mut st = shared.lock();
            if st.closed {
                return Err(HandleError::Refused);
            }
            let limits = st.core.config().clone();
            let id = st.core.open(None, pipe.framing, arrived);
            let mut slot = PairSlot {
                id,
                setup,
                hint,
                result,
            };
            let pair = match st.core.pair(token, id, uplink, arrived) {
                Paired::Reject => {
                    st.core.done(id);
                    drop(st);
                    return Err(HandleError::Rejected);
                }
                Paired::Waiting => {
                    slot.setup.parts().1.attachment().hold(PairLease {
                        shared: Arc::downgrade(shared),
                        token,
                        id,
                    });
                    if let Some(old) = st.pairs.insert(token, slot) {
                        st.core.done(old.id);
                        drop(st);
                        drop(old);
                    }
                    None
                }
                Paired::Complete(_) => {
                    st.core.done(id);
                    Some((st.pairs.remove(&token).expect("waiting half"), slot))
                }
            };
            (limits, id, pair)
        };
        if let Some((mut first, mut second)) = pair {
            let principal = |pipe: &PipeIo| {
                pipe.admission_evidence
                    .as_ref()
                    .and_then(|evidence| evidence.bound_prefix)
            };
            if principal(first.setup.parts().1) != principal(second.setup.parts().1) {
                let _ = first.result.send(Err(HandleError::Rejected));
                return Err(HandleError::Rejected);
            }
            let l = self.clone();
            let lease = first.setup.parts().1.attachment().clone();
            let setup = first
                .setup
                .pair(
                    second.setup,
                    |first, second| {
                        let (up, down) = if uplink {
                            (second, first)
                        } else {
                            (first, second)
                        };
                        let mut pipe = PipeIo::paired(up, down);
                        pipe.adopt_attachment(lease.clone());
                        pipe
                    },
                    &lease,
                )?
                .register(|entry| Pending::new(shared, first.id, entry));
            let mut first_result = first.result;
            let mut second_result = second.result;
            tokio::spawn(async move {
                let r = {
                    let withdrawn = async {
                        first_result.closed().await;
                        second_result.closed().await;
                    };
                    let setup = Box::pin(l.setup_pair(setup, first.hint, &limits));
                    super::setup::while_open(
                        l.adapter().closed(),
                        super::setup::while_open(withdrawn, setup),
                    )
                    .await
                    .flatten()
                    .unwrap_or(Err(HandleError::Refused))
                };
                let _ = first_result.send(r.clone());
                let _ = second_result.send(r);
            });
        } else {
            let mut waiting = WaitingPair { shared, token, id };
            let wait = timeout(
                clock,
                arrived.checked_add(limits.handshake_timeout),
                &mut answer,
            );
            let error = match until(self.adapter().closed(), wait).await {
                Some(Some(result)) => return result.unwrap_or(Err(HandleError::TimedOut)),
                Some(None) => HandleError::TimedOut,
                None => HandleError::Refused,
            };
            // If the partner already took the slot, the combined setup owns
            // the deadline and the result, including a concurrent close.
            if waiting.withdraw() {
                return Err(error);
            }
        }
        answer.await.unwrap_or(Err(HandleError::Refused))
    }

    async fn setup_pair(
        &self,
        mut setup: Setup<Pending, PipeIo>,
        mut hint: PipeHint,
        limits: &ListenerConfig,
    ) -> Result<(), HandleError> {
        let (_, io) = setup.parts();
        if let Some(taken) = io.taken.take() {
            crate::proto::decision::host(taken).ok_or(HandleError::SetupFailed)?;
        }
        hint.value = io.admitted_value().cloned();
        let mut setup = setup
            .prepare(async |pending, io| self.prepare(io, &mut hint, &mut pending.entry).await)
            .await?;
        let (pending, io) = setup.parts();
        // The record is read from what the transform returned.
        self.shared
            .lock()
            .core
            .set_framing(pending.registration.id, io.framing);
        Box::pin(self.classify(setup, hint, Origin::Pair, limits)).await
    }

    /// Reads until the listener classified the carrier.
    async fn first_record(shared: &ListenShared, id: CarrierId, pipe: &mut PipeIo) -> Classified {
        super::lanes::first_record(pipe, |framing, bytes| {
            let now = shared.config.clock_domain.now();
            let mut st = shared.lock();
            if framing == Framing::Records {
                st.core.message(id, bytes, now)
            } else {
                st.core.data(id, bytes, now)
            }
        })
        .await
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
            admitted: pipe.admitted_value().cloned(),
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
        let answer = super::hooks::settle_by(
            f.ask(&carrier),
            &self.shared.config.clock_domain,
            deadline,
            self.closed_or_evicted(None),
        )
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
        setup: Setup<Pending, PipeIo>,
        addrs: (Option<SocketAddr>, Option<SocketAddr>),
    ) -> Result<(), HandleError> {
        let admission = {
            let mut st = self.shared.lock();
            let closed = st.closed;
            st.core
                .bootstrap_admission(closed, self.shared.account.pressure())
        };
        let mut place = super::setup::QueuePlace::new(
            || self.shared.lock().core.release_unaccepted(),
            admission.is_ok(),
        );
        let setup = setup
            .prepare(async |_, pipe| {
                let config = self
                    .session_config(Self::session_carrier(&pipe, addrs))
                    .await?;
                // Each session of the listener has its own locator unless one is
                // configured.
                let own = (config.offers_multipath() && config.own_locator().is_empty())
                    .then(|| crate::proto::listener::random_locator(&self.shared.instance_id));
                let mut pipe = Some(pipe);
                let shared = Shared::create(
                    &mut pipe,
                    config,
                    Role::Server,
                    Some(Role::Server),
                    own.as_deref(),
                    Some(self.shared.account.ledger.clone()),
                    |shared| Some(self.register_session(shared, admission.is_ok())),
                );
                let shared = match shared {
                    Ok(shared) => shared,
                    Err(crate::ConnectError::MemoryBudget) => {
                        for session in self.shared.account.evict_under_pressure() {
                            session.close_suspended();
                        }
                        let mut carrier = pipe.take().expect("refused bootstrap carrier");
                        let mut bytes = [0; 128];
                        let record = super::setup::bootstrap_refusal_record(
                            carrier.handshake_framing(),
                            &mut bytes,
                        );
                        let deadline = self.handshake_deadline();
                        let _ = timeout(
                            &self.shared.config.clock_domain,
                            deadline,
                            carrier.write_handshake(record),
                        )
                        .await;
                        return Err(HandleError::Refused);
                    }
                    Err(_) => return Err(HandleError::Rejected),
                };
                if let Err(crate::proto::listener::BootstrapRefusal::Capacity(reason)) = admission {
                    shared.refuse(reason.into());
                    return Err(HandleError::Refused);
                }
                // Bounded by the handshake timeout and the listener's close: a peer
                // that never completes the parameters holds no place for good.
                let closing = Closing {
                    shared: &self.shared,
                    id: None,
                    slot: None,
                    ticket: None,
                };
                let established = super::setup::while_open(
                    closing,
                    timeout(
                        &self.shared.config.clock_domain,
                        self.handshake_deadline(),
                        shared.established(),
                    ),
                )
                .await
                .ok_or(HandleError::Refused)?
                .ok_or(HandleError::TimedOut)?;
                let session = established.map_err(|_| HandleError::Rejected)?;
                if let Err(reason) = admission {
                    session.shared().refuse(reason.reason());
                    return Err(HandleError::Refused);
                }
                Ok(session)
            })
            .await?;
        setup.publish(|s| {
            let mut wakes = WakeList::default();
            let mut st = self.shared.lock();
            if st.closed || st.core.shutting_down() {
                // Closed meanwhile: nobody accepts it; dropped (and so
                // closed) after the listener's lock.
                drop(st);
                s.shared().close_unaccepted();
                return Err(HandleError::Refused);
            }
            st.live.queue(s.shared().id)?;
            st.accept.push_back(s);
            // The queued session holds the place until it is taken.
            place.queued();
            self.shared.counts.commit(|counts| &counts.sessions);
            st.accept_waiters.wake_all(&mut wakes);
            drop(st);
            Ok(())
        })
    }

    // Called synchronously by Shared::create before any bootstrap I/O.
    fn register_session(&self, shared: &Arc<Shared<Tokio>>, admitted: bool) -> Weak<ListenShared> {
        let registration = self.shared.lock().live.start(shared);
        shared.lock().io.account = Some(Box::new(AccountLink::new(
            self.shared.account.clone(),
            Some(registration),
        )));
        if admitted {
            self.shared
                .locators
                .advertise(shared, self.shared.instance_id.len());
        }
        Arc::downgrade(&self.shared)
    }

    /// Processes a Hello from its Locator lookup to Confirmed and, once
    /// Confirmed, hands the session the carrier.
    #[allow(clippy::too_many_arguments)]
    async fn join(
        &self,
        mut setup: Setup<Pending, PipeIo>,
        locator: &[u8],
        hello: &[u8],
        source: Option<SocketAddr>,
    ) -> Result<(), HandleError> {
        use super::accept::{AcceptStep, JoinAccept, JoinCarrier};
        let (pending, pipe) = setup.parts();
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
            attachment: pipe.attachment().clone(),
            sources: pipe.record_sources(),
            framing: pipe.framing,
            binding,
            has_exporter: pipe.exporter.is_some(),
            secure: pipe.secure,
            reports_failure: pipe.reports_failure,
            admitted: pipe.admitted_value().cloned(),
            inbound: pipe.reader.is_some(),
            outbound: pipe.writer.is_some(),
            looped,
            overhead: pipe.write_overhead,
            max_record: pipe.max_record,
            kind: pipe.carrier,
        };
        let mut acc = JoinAccept::new(
            session,
            &self.shared.config,
            hello,
            carrier,
            pending.registration.id,
        );
        let deadline = acc.deadline();
        let clock = acc.clock_domain().clone();
        let mut timer = std::pin::pin!(sleep::<Tokio>(&clock, deadline));

        // Early data could be replayed. Wait for the carrier's handshake
        // before opening the Hello. Bound never accepts early data.
        if let Some(session) = acc.session()
            && let Some(done) = pipe.take_early_in()
        {
            let mode = JoinAccept::<Tokio>::parse_mode(pipe.framing, hello);
            if mode == Some(crate::proto::seal::RecordMode::Bound) {
                return self
                    .rejected(setup, RejectInfo::new(Some(2), mode, "early_data", source))
                    .await;
            }
            let early = until(self.join_stopped(pending.registration.id, session), done);
            match until(timer.as_mut(), early).await {
                Some(Some(())) => {}
                Some(None) => return Err(HandleError::Refused),
                None => return Err(HandleError::SetupFailed),
            }
        }
        let open = async {
            let mut step = self.join_open(pending, &mut acc, None);
            loop {
                step = match step {
                    AcceptStep::WaitKeys => {
                        let session = acc.session().expect("named");
                        let keys = handle::join_keys_wait(session);
                        match until(self.closed_or_evicted(Some(pending.registration.id)), keys)
                            .await
                        {
                            Some(ready) => self.join_open(pending, &mut acc, Some(ready)),
                            None => {
                                return AcceptStep::End(
                                    acc.stopped(pending.entry.setup.checkpoint()),
                                );
                            }
                        }
                    }
                    AcceptStep::Ask(check, decision) => {
                        let session = acc.session().expect("named");
                        let ended = self.join_stopped(pending.registration.id, session);
                        match super::hooks::settle_by(decision, &clock, None, ended).await {
                            Some(ok) => {
                                if ok
                                    && matches!(check, super::accept::Check::Mode)
                                    && let Err(error) = pipe.reserve_carrier_memory(session)
                                {
                                    return AcceptStep::End(acc.failed(error.into()));
                                }
                                acc.allowed(check, ok)
                            }
                            None => {
                                return AcceptStep::End(
                                    acc.stopped(pending.entry.setup.checkpoint()),
                                );
                            }
                        }
                    }
                    AcceptStep::Delay(delay) => {
                        let session = acc.session().expect("named");
                        let ended = self.join_stopped(pending.registration.id, session);
                        let delay = sleep::<Tokio>(&clock, clock.now().checked_add(delay));
                        if until(ended, delay).await.is_none() {
                            return AcceptStep::End(acc.stopped(pending.entry.setup.checkpoint()));
                        }
                        acc.delayed(true)
                    }
                    finished => return finished,
                };
            }
        };
        let (reply, evicted) = match until(timer.as_mut(), open).await {
            None => return Err(HandleError::TimedOut),
            Some(AcceptStep::End(e)) => return Err(e),
            Some(AcceptStep::Reject(reason, mode)) => {
                return self
                    .rejected(setup, RejectInfo::new(Some(2), mode, reason, source))
                    .await;
            }
            Some(AcceptStep::Refuse(reply)) => {
                let write =
                    super::accept::JoinWrite::new(acc.session().expect("named").clone(), reply);
                let pipe = setup
                    .claim(Transfer::Reply)
                    .map_err(|e| acc.commit_failed(e))?;
                let clock = clock.clone();
                super::tokio::spawn_drain(
                    async move {
                        let mut pipe = pipe;
                        let work = async {
                            if super::sealed::write_join_unit(&mut pipe, write)
                                .await
                                .is_ok()
                            {
                                pipe.end_unused(true, false).await;
                            }
                        };
                        let _ = until(sleep::<Tokio>(&clock, deadline), work).await;
                    },
                    super::tokio::DRAIN_LIMIT,
                );
                return Err(HandleError::Refused);
            }
            Some(AcceptStep::Reply { bytes, evicted }) => (bytes, evicted),
            Some(AcceptStep::WaitKeys | AcceptStep::Ask(..) | AcceptStep::Delay(_)) => {
                unreachable!("join still opening")
            }
        };
        let session = acc.session().expect("named").clone();
        {
            let mut wakes = WakeList::default();
            let mut st = self.shared.lock();
            st.evict(evicted, &mut wakes);
        }
        let write = super::accept::JoinWrite::new(session.clone(), reply);
        let confirm = async {
            super::sealed::write_join_unit(pipe, write).await?;
            // The acceptor's records wait for Confirmed.
            let mut input = Vec::new();
            loop {
                match acc.confirm(&mut input) {
                    Ok(true) => return Ok::<_, std::io::Error>(input),
                    Ok(false) => {}
                    Err(()) => return Err(std::io::ErrorKind::InvalidData.into()),
                }
                if read_unit(pipe, &mut input).await? == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
            }
        };
        // An Unconfirmed carrier ends with its session and with the listener.
        let confirm = until(
            self.join_stopped(pending.registration.id, &session),
            confirm,
        );
        let confirmed = until(timer.as_mut(), confirm)
            .await
            .ok_or(HandleError::TimedOut)?;
        let rest = match confirmed {
            Some(Ok(rest)) => rest,
            Some(Err(e)) => return Err(acc.carrier_failed(e.kind())),
            // Nothing the peer did: no authentication failure.
            None => return Err(acc.stopped(pending.entry.setup.checkpoint())),
        };
        if acc.sends_on_pipe() {
            pipe.register_carrier_stats();
        }
        setup
            .publication()
            .map_err(|e| acc.commit_failed(e))?
            .finish(|mut pipe| {
                let super::accept::Attached {
                    mut install,
                    records,
                    want_in,
                    want_out,
                } = acc.attach()?;
                let attached = install.id();
                // A pipe of its session now, no longer taking a source slot.
                pipe.prefix = rest;
                pipe.resolve_lanes();
                let mut pipe = match records {
                    Some((s, o)) => seal_carrier(pipe, s, o),
                    None => pipe,
                };
                if let Some(m) = pipe.max_record {
                    // Fits: checked against the join's mode before it was confirmed.
                    if session
                        .set_pipe_limits(attached, m, pipe.write_overhead)
                        .is_err()
                    {
                        return Err(install.resource_limit());
                    }
                }
                pipe.release_unused(want_in, want_out);
                if claim_carrier(&session, attached.0, pipe.outer.take()).is_err() {
                    // A loop formed since the check above, through another session:
                    // ZMUX_PIPE_RESOURCE_LIMIT.
                    return Err(install.resource_limit());
                }
                // A session closing meanwhile takes no new pipe (the guard forgets it).
                session
                    .attach_task(attached.0, pipe)
                    .map_err(|e| acc.failed(e.into()))?;
                install.installed().map_err(|e| acc.failed(e.into()))
            })?;
        // Counted once attached.
        self.shared.counts.commit(|counts| &counts.joins);
        drop(session);
        Ok(())
    }

    /// Opens the Hello unless the listener closed or evicted the carrier
    /// meanwhile; `ready` is the answer of a key wait, if one came first.
    fn join_open(
        &self,
        pending: &Pending,
        acc: &mut super::accept::JoinAccept<Tokio>,
        ready: Option<bool>,
    ) -> super::accept::AcceptStep {
        // The listener's lock is never taken under a session's.
        let closed = {
            let st = self.shared.lock();
            // Evicted for a newer carrier while it waits: closed like one
            // waiting for its first record.
            st.closed || st.evicted.contains(&pending.registration.id)
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
    fn rejected(
        &self,
        setup: Setup<Pending, PipeIo>,
        info: RejectInfo,
    ) -> impl Future<Output = Result<(), HandleError>> + '_ {
        // Rejection can hold a large admission state across a host callback.
        // Keep it out of every successful carrier setup's future.
        Box::pin(async move {
            setup
                .prepare(async |pending, pipe| {
                    self.refuse(
                        &info,
                        Some(pending.registration.id),
                        Some(&mut pending.entry),
                        Some(pipe),
                    )
                    .await;
                    Ok(())
                })
                .await?;
            Err(HandleError::Rejected)
        })
    }

    /// The reject policy for `info`: closed, or stalled without a byte, a Join (Profile 2)
    /// for the listener's join timeout from now and any other carrier for the handshake
    /// timeout, at most the listener's maximum stall. The stall requires and
    /// keeps the entry's slots. An Unconfirmed carrier's stall ends if it is evicted.
    async fn refuse(
        &self,
        info: &RejectInfo,
        id: Option<CarrierId>,
        entry: Option<&mut Entry>,
        pipe: Option<PipeIo>,
    ) {
        if self.reject_response(info, id).await != RejectAction::Stall {
            return;
        }
        let limit = if info.profile == Some(2) {
            self.shared.config.join_timeout
        } else {
            let handshake = self.shared.lock().core.config().handshake_timeout;
            handshake.min(self.shared.stall_max)
        };
        let Some(stall) = entry.and_then(|entry| {
            entry
                .start_stall()
                .then(|| entry.setup.stalled(pipe))
                .flatten()
        }) else {
            return;
        };
        let shared = self.shared.clone();
        let end = shared.config.clock_domain.now().checked_add(limit);
        tokio::spawn(async move {
            let _ = until(
                Entry::stall_end(&shared, stall.slot()),
                sleep::<Tokio>(&shared.config.clock_domain, end),
            )
            .await;
            drop(stall);
        });
    }
}

/// A carrier's memory reservation on its listener.
pub struct MemoryCharge(crate::proto::memory::Reservation);

impl MemoryCharge {
    /// Changes the reservation before using more capacity. A refusal
    /// preserves the existing grant.
    ///
    /// # Errors
    ///
    /// The listener's budget has insufficient room for the increase.
    pub fn resize(&mut self, bytes: u64) -> io::Result<()> {
        if self.0.resize(bytes) {
            Ok(())
        } else {
            Err(io::Error::other("listener memory budget exhausted"))
        }
    }
}

impl std::fmt::Debug for MemoryCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCharge")
            .field("bytes", &self.0.bytes())
            .finish_non_exhaustive()
    }
}

enum Origin {
    Single(Option<super::lanes::Exempt>),
    Pair,
}

/// A carrier among the listener's pending carriers, until it is classified, joined or given
/// up, with the entry that holds its slots.
struct Pending {
    registration: super::setup::Registration<ListenShared>,
    entry: Entry,
}

impl Owner for Pending {
    type Table = ListenShared;
    fn authority(&mut self) -> &mut Authority<ListenShared> {
        &mut self.entry.setup
    }
}

impl Pending {
    fn new(shared: &Arc<ListenShared>, id: CarrierId, mut entry: Entry) -> Self {
        entry.setup.register(id);
        Self {
            registration: super::setup::Registration {
                table: shared.clone(),
                id,
            },
            entry,
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
                st.live.accept(s.shared().id);
                st.core.release_unaccepted();
                Some(Some(s))
            }
            None => (st.closed || st.core.shutting_down()).then_some(None),
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

/// Withdraws an unmatched half synchronously when its caller drops the future.
struct Withdraw(Arc<super::setup::Handoff>);
impl Drop for Withdraw {
    fn drop(&mut self) {
        self.0.withdraw();
    }
}

struct WaitingPair<'a> {
    shared: &'a ListenShared,
    token: [u8; PAIRING_TOKEN_LEN],
    id: CarrierId,
}

impl WaitingPair<'_> {
    fn withdraw(&mut self) -> bool {
        let mut st = self.shared.lock();
        if st.pairs.get(&self.token).is_some_and(|s| s.id == self.id) {
            st.core.withdraw_pair(&self.token, self.id);
            st.core.done(self.id);
            let slot = st.pairs.remove(&self.token);
            drop(st);
            drop(slot);
            return true;
        }
        false
    }
}

impl Drop for WaitingPair<'_> {
    fn drop(&mut self) {
        self.withdraw();
    }
}

/// Shared by a split attachment and work that can outlive its carrier.
pub(crate) struct PairLease {
    shared: Weak<ListenShared>,
    token: [u8; PAIRING_TOKEN_LEN],
    id: CarrierId,
}

impl Drop for PairLease {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            let mut st = shared.lock();
            st.core.unpair(&self.token, self.id);
            st.core.done(self.id);
        }
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
            s.counts.commit(|counts| &counts.setup_failures);
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

    #[tokio::test]
    async fn listener_enforces_the_exact_initial_credit_cutoff_on_the_wire() {
        use crate::proto::{TransportErrorCode, session::SessionError};

        let config = Config::default();
        let cutoff = crate::proto::session::minimum_listener_admission(&config);
        for budget in [cutoff - 1, cutoff] {
            let mut options = ListenerConfig::default();
            options.limits.memory_budget = Some(budget);
            let listener = Listener::new(config.clone(), options).unwrap();
            let (a, b) = tokio::io::duplex(65_536);
            let (connect, setup) = tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(
                    Session::connect(PipeIo::new(a), config.clone()),
                    listener.handle_pipe(PipeIo::new(b), PipeHint::default())
                )
            })
            .await
            .expect("bootstrap watchdog");
            if budget == cutoff {
                assert!(setup.is_ok());
                assert!(connect.is_ok());
                assert_eq!(listener.shared.account.ledger.snapshot().used, cutoff);
            } else {
                assert_eq!(setup, Err(HandleError::Refused));
                let error = match connect {
                    Err(crate::ConnectError::SessionLost(error)) => error,
                    Ok(session) => tokio::time::timeout(Duration::from_secs(30), session.closing())
                        .await
                        .expect("refusal watchdog"),
                    Err(other) => panic!("unexpected connect error: {other}"),
                };
                assert!(
                    matches!(
                        error,
                        SessionError::TransportClosed {
                            code: TransportErrorCode::CONNECTION_REFUSED,
                            remote: true,
                            ..
                        }
                    ),
                    "{error:?}"
                );
                assert_eq!(listener.shared.account.ledger.snapshot().used, 0);
            }
            listener.close();
        }
    }

    #[tokio::test]
    async fn ended_session_leaves_the_registry_while_handles_are_retained() {
        let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
        let (a, b) = tokio::io::duplex(65536);
        let (client, setup) = tokio::join!(
            Session::connect(PipeIo::new(a), Config::default()),
            listener.handle_pipe(PipeIo::new(b), PipeHint::default())
        );
        setup.unwrap();
        let client = client.unwrap();
        let server = listener.accept().await.unwrap();
        assert_eq!(listener.shared.lock().live.accepted().len(), 1);
        client.close().await;
        server.closed().await;
        assert!(listener.shared.lock().live.accepted().is_empty());
    }

    #[tokio::test]
    async fn client_connect_order_can_differ_from_listener_accept_order() {
        use std::future::poll_fn;
        use std::pin::pin;

        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
            let (client, server) = tokio::io::duplex(65536);
            let mut first_setup = pin!(listener.handle_pipe(
                PipeIo::new(server).with_protocol("first"),
                PipeHint::default(),
            ));
            let mut first_client = pin!(Session::connect(PipeIo::new(client), Config::default()));
            let first_client = poll_fn(|cx| {
                // Once the server driver can do the handshake, hold its setup
                // future so it cannot publish the session to the accept queue.
                if listener.shared.lock().live.establishing().is_empty() {
                    assert!(first_setup.as_mut().poll(cx).is_pending());
                }
                first_client.as_mut().poll(cx)
            })
            .await
            .unwrap();
            assert_eq!(listener.stats().sessions, 0);

            let (client, server) = tokio::io::duplex(65536);
            let (second_client, second_setup) = tokio::join!(
                Session::connect(PipeIo::new(client), Config::default()),
                listener.handle_pipe(
                    PipeIo::new(server).with_protocol("second"),
                    PipeHint::default()
                ),
            );
            let _second_client = second_client.unwrap();
            second_setup.unwrap();
            first_setup.await.unwrap();

            let second_server = listener.accept().await.unwrap();
            let first_server = listener.accept().await.unwrap();
            assert_eq!(second_server.protocol().as_deref(), Some("second"));
            assert_eq!(first_server.protocol().as_deref(), Some("first"));

            let mut send = first_client.open_uni().await.unwrap();
            send.write_chunk(crate::Chunk::from_static(b"first"))
                .await
                .unwrap();
            send.finish().unwrap();
            let mut recv = first_server.accept_uni().await.unwrap();
            assert_eq!(recv.read_to_end(5).await.unwrap(), b"first");
            let mut mismatched = pin!(second_server.accept_uni());
            assert!(poll_fn(|cx| Poll::Ready(mismatched.as_mut().poll(cx).is_pending())).await);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registration_and_accounting_precede_bootstrap_io() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let config = Config {
                session_policy: crate::SessionPolicy::with_steady_attachments(4),
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
                &mut Some(PipeIo::new(carrier)),
                config,
                Role::Server,
                Some(Role::Server),
                Some(&[9; 16]),
                Some(listener.shared.account.ledger.clone()),
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
                    Some(listener.register_session(shared, true))
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

    #[tokio::test]
    async fn rejected_pipe_stalls_do_not_add_admission_outcomes() {
        let limits = ListenerConfig {
            admission: Some(Admission::new(0, |_, _| AdmissionVerdict::accept(0))),
            on_reject: Some(crate::OnReject::new(|_| RejectAction::Stall)),
            ..ListenerConfig::default()
        };
        let listener = Listener::new(Config::default(), limits).unwrap();
        listener
            .refuse(
                &RejectInfo::new(Some(2), None, "pending_limit", None),
                None,
                None,
                None,
            )
            .await;
        assert_eq!(listener.stats().admission, AdmissionStats::default());
    }

    /// A draining listener refuses a new session with `CONNECTION_REFUSED`
    /// after its own parameters, so that the peer reads why, as the Go listener.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_draining_listener_refuses_with_connection_refused() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = Listener::new(Config::default(), ListenerConfig::default())
                .expect("valid listener configuration");
            listener.drain(b"maintenance");
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

    #[tokio::test(start_paused = true)]
    async fn takeover_head_settles_once() {
        for (case, expected) in [
            (0, (1, 0, 0, 0)),
            (1, (0, 1, 0, 0)),
            (2, (0, 0, 1, 0)),
            (3, (0, 0, 0, 1)),
        ] {
            let config = ListenerConfig {
                admission: Some(Admission::new(0, |_, _| AdmissionVerdict::takeover())),
                fallback: Some(Fallback::new(|_| async {})),
                ..ListenerConfig::default()
            };
            let listener = Listener::new(Config::default(), config).unwrap();
            let mut entry = listener.adapter().enter(NO_ADDR, None).unwrap();
            assert!(matches!(
                entry
                    .decide_request(CarrierInfo::new(), None::<&mut tokio::io::Empty>)
                    .await,
                Admit::TakeOver(_)
            ));
            let written = match case {
                0 => entry.takeover_head(std::future::ready(true)).await,
                1 => entry.takeover_head(std::future::ready(false)).await,
                2 => entry.takeover_head(std::future::pending()).await,
                _ => {
                    listener.close();
                    entry.takeover_head(std::future::pending()).await
                }
            };
            if written {
                let (io, _) = tokio::io::duplex(64);
                entry.take_over(PipeIo::new(io), Vec::new()).await;
            }
            drop(entry);
            let stats = listener.stats().admission;
            assert_eq!(
                (
                    stats.takeover,
                    stats.handshake_failed,
                    stats.peek_timed_out,
                    stats.closed
                ),
                expected
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn overflowing_handshake_deadline_waits_until_listener_close() {
        let config = ListenerConfig {
            handshake_timeout: Duration::MAX,
            ..ListenerConfig::default()
        };
        let listener = Listener::new(Config::default(), config).unwrap();
        let entry = listener.adapter().enter(NO_ADDR, None).unwrap();
        let mut step = std::pin::pin!(entry.setup_step(std::future::pending::<()>()));
        assert!(std::future::poll_fn(|cx| Poll::Ready(step.as_mut().poll(cx).is_pending())).await);
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(std::future::poll_fn(|cx| Poll::Ready(step.as_mut().poll(cx).is_pending())).await);
        listener.close();
        assert_eq!(step.await, None);
    }

    struct Live {
        count: Arc<AtomicUsize>,
        dropped: tokio::sync::mpsc::UnboundedSender<()>,
    }

    impl Drop for Live {
        fn drop(&mut self) {
            self.count.fetch_sub(1, Relaxed);
            let _ = self.dropped.send(());
        }
    }

    /// Setups that never enter the listener (a handshake before it, or
    /// carriers entering one by one) stay within `max_pending`: a new
    /// connection beyond it ends the oldest setup.
    #[tokio::test]
    async fn setups_without_an_entry_stay_within_max_pending() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let limits = ListenerConfig {
                handshake_timeout: Duration::MAX,
                limits: ListenerLimits {
                    max_pending: Some(3),
                    ..ListenerLimits::default()
                },
                ..ListenerConfig::default()
            };
            let listener =
                Listener::new(Config::default(), limits).expect("valid listener configuration");
            let live = Arc::new(AtomicUsize::new(0));
            let count = live.clone();
            let (dropped, mut releases) = tokio::sync::mpsc::unbounded_channel();
            let mut accepted = 0;
            let serving = tokio::spawn(listener.clone().serve_connections(
                move || {
                    accepted += 1;
                    let next = accepted <= 20;
                    async move {
                        if next {
                            Some(Ok(()))
                        } else {
                            std::future::pending().await
                        }
                    }
                },
                move |()| {
                    count.fetch_add(1, Relaxed);
                    let guard = Live {
                        count: count.clone(),
                        dropped: dropped.clone(),
                    };
                    async move {
                        let _guard = guard;
                        std::future::pending::<Result<(), ()>>().await
                    }
                },
                |_l, ()| async {},
            ));
            for _ in 0..17 {
                releases.recv().await.unwrap();
            }
            assert_eq!(live.load(Relaxed), 3);
            listener.close();
            serving.await.expect("serve loop");
            for _ in 0..3 {
                releases.recv().await.unwrap();
            }
            assert_eq!(live.load(Relaxed), 0);
        })
        .await
        .expect("setup bound test watchdog");
    }
}
