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
use super::admission::{
    CatchUnwind, Fallback, FallbackStream, Prefixed, discard, read_more, read_prefix,
};
use super::handle::{self, Shared, WeakSession};
use super::resources::{Kind, Live};
use super::sealed::{read_unit, seal_carrier, until, write_unit};
use super::stream_pipe::{claim_carrier, runs_over};
use super::tokio::{PipeIo, Session, Tokio, now};
use super::transform::InboundTransform;
use super::wait::{PipeDone, Ticket, WaitList};
use super::wake::WakeList;
use crate::proto::VarInt;
use crate::proto::admission::{Admission, AdmissionVerdict, AdmittedValue, CarrierInfo};
use crate::proto::listener::{
    CarrierId, Classified, Entered, ListenerConfig, ListenerCore as Core, Paired, Slot,
};
use crate::proto::listener::{RejectAction, RejectInfo};
use crate::proto::oob::PAIRING_TOKEN_LEN;
use crate::proto::record::Framing;
use crate::proto::seal::join::JoinHello;
use crate::proto::session::{
    ClaimedHello, Config, ConfirmedJoin, OpenedHello, PeerCarrier, RecordPolicyInput, Role,
};
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
    pub fn from_peer(peer: SocketAddr) -> Self {
        Self {
            peer: Some(peer),
            ..Self::default()
        }
    }

    /// The hint of a carrier that entered the listener ([`ListenerAdapter::enter`](crate::adapter::ListenerAdapter::enter))
    /// and was admitted there ([`Entry::admit`]): its source and peer are
    /// the entry's, which [`Listener::handle_pipe`] goes on with.
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
    peek_timed_out: AtomicU64,
    handshake_failed: AtomicU64,
    variants: Mutex<AdmissionVariants>,
}

impl AdmissionCounts {
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
/// ([`crate::Decision::variant`]), per label; they count in the totals of
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

/// How many distinct [`crate::Decision::variant`] labels a listener counts
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

/// A carrier that entered a listener ([`ListenerAdapter::enter`](crate::adapter::ListenerAdapter::enter)): it holds a
/// source slot ([`ListenerConfig::max_pending_per_source`]) and a slot of
/// the listener ([`ListenerConfig::max_pending`]) from before its outer
/// handshake, through its admission and, handed to
/// [`Listener::handle_pipe`] with [`PipeHint::from_entry`], until it enters
/// a session; or until it goes to a fallback target, is released
/// ([`Entry::release`]) or dropped. Dropped before its admission
/// ([`Entry::admit`]), its outer handshake counts as failed.
pub struct Entry {
    shared: Arc<ListenShared>,
    key: u64,
    /// Its slots; `None` once a new carrier evicted it while it stalled.
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
    /// The prefix did not arrive within the peek timeout.
    late: bool,
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

/// What the listener's admission decided on an entered carrier
/// ([`Entry::admit`]).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Admit {
    /// Accepted: the prefix bytes after those the decision removed, to be
    /// given back in front of the carrier ([`PipeIo::with_prefix`]) handed
    /// to [`Listener::handle_pipe`] with [`PipeHint::from_entry`].
    Accept(Vec<u8>),
    /// To the fallback target of the carrier's kind, every prefix byte read
    /// replayed in front; without a target, stall it ([`Entry::stall`]).
    Fallback(Vec<u8>),
    /// Stall it ([`Entry::stall`]), then close it.
    Stall,
    /// Close it at once.
    Close,
}

/// What one decision on a prefix led to.
enum Round {
    Done(Admit),
    /// Another decision once the prefix has this many bytes.
    Read(usize),
}

/// What a carrier's prefix is to the listener's sessions
/// ([`ListenerAdapter::join_prefix`](crate::adapter::ListenerAdapter::join_prefix)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// The directly connected peer.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Whether the admission accepted it (or the listener has none).
    pub fn is_admitted(&self) -> bool {
        self.admitted
    }

    /// The admitted source of this carrier's connection, once
    /// [`Entry::admit`] accepted it.
    pub fn admitted(&self) -> Option<Admitted> {
        self.admitted.then(|| Admitted {
            source: self.source,
            peer: self.peer,
            value: self.value.clone(),
        })
    }

    /// Applies the listener's admission once the carrier's outer handshake
    /// completed: [`Entry::read_prefix`] from `reader` (none without one,
    /// for a carrier decided on its request head), then
    /// [`Entry::decide_reading`] with `info`.
    pub async fn admit<R>(&mut self, info: CarrierInfo<'_>, reader: Option<&mut R>) -> Admit
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        match reader {
            Some(r) => {
                let prefix = self.read_prefix(r).await;
                self.decide_reading(info, prefix, r).await
            }
            None => self.decide(info, Vec::new()).await,
        }
    }

    /// Once the carrier's outer handshake completed: starts the peek
    /// timeout, and reads up to the admission's prefix length from
    /// `reader` within it (nothing without an admission).
    pub async fn read_prefix<R>(&mut self, reader: &mut R) -> Vec<u8>
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let deadline = self.start();
        match (&self.shared.admission, deadline) {
            (Some(adm), Some(d)) if adm.peek() > 0 => {
                let (prefix, late) = read_prefix(adm.peek(), reader, d).await;
                self.late = late;
                prefix
            }
            _ => Vec::new(),
        }
    }

    /// The deadline of the admission, started at the first call: the end
    /// of the outer handshake. A timeout beyond the clock's range never ends.
    fn start(&mut self) -> Option<Instant> {
        self.handshaken = true;
        let adm = self.shared.admission.as_ref()?;
        Some(*self.deadline.get_or_insert_with(|| {
            let now = Instant::now();
            now.checked_add(adm.peek_timeout())
                .unwrap_or_else(|| now + Duration::from_secs(86_400 * 365 * 30))
        }))
    }

    /// The listener's decision on the carrier, from `info` (whose source
    /// and peer are the entry's) and `prefix` (read by
    /// [`Entry::read_prefix`]), within what remains of the peek timeout;
    /// cancelled when the listener closes. Without an admission it accepts
    /// at once. Counted in [`ListenerStats::admission`]. With no reader to
    /// read more from, [`AdmissionVerdict::More`] closes the carrier.
    pub async fn decide(&mut self, info: CarrierInfo<'_>, prefix: Vec<u8>) -> Admit {
        self.decide_rounds(info, prefix, None::<&mut tokio::io::Empty>)
            .await
    }

    /// [`Entry::decide`] of a byte-stream carrier: [`AdmissionVerdict::More`] reads
    /// on from `reader` and decides again.
    pub async fn decide_reading<R>(
        &mut self,
        info: CarrierInfo<'_>,
        prefix: Vec<u8>,
        reader: &mut R,
    ) -> Admit
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        self.decide_rounds(info, prefix, Some(reader)).await
    }

    /// One decision or more, reading on from `reader` for [`AdmissionVerdict::More`].
    async fn decide_rounds<R>(
        &mut self,
        info: CarrierInfo<'_>,
        mut prefix: Vec<u8>,
        mut reader: Option<&mut R>,
    ) -> Admit
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let info = info.with_source(self.source).with_peer(self.peer);
        // The carrier ended short of what was asked for.
        let mut short = false;
        loop {
            let can_read = reader.is_some();
            match self.decide_round(&info, &mut prefix, can_read, short).await {
                Round::Done(admit) => return admit,
                Round::Read(need) => {
                    let Some(r) = reader.as_deref_mut() else {
                        return Admit::Close;
                    };
                    short = self.read_round(&mut prefix, need, r).await;
                }
            }
        }
    }

    /// [`Entry::decide_reading`] when the metadata borrows the carrier the
    /// reads come from: `info` is taken again for each decision.
    async fn decide_carrier<C, I>(&mut self, conn: &mut C, info: &I, mut prefix: Vec<u8>) -> Admit
    where
        C: AsyncRead + Unpin + Send,
        I: for<'a> Fn(&'a C) -> CarrierInfo<'a>,
    {
        let mut short = false;
        loop {
            let round = {
                let info = info(&*conn).with_source(self.source).with_peer(self.peer);
                self.decide_round(&info, &mut prefix, true, short).await
            };
            match round {
                Round::Done(admit) => return admit,
                Round::Read(need) => short = self.read_round(&mut prefix, need, conn).await,
            }
        }
    }

    /// Reads `prefix` on to `need` bytes within the peek timeout: whether
    /// the carrier ended short of it. Past the timeout the entry is late,
    /// which the next round decides.
    async fn read_round<R>(&mut self, prefix: &mut Vec<u8>, need: usize, reader: &mut R) -> bool
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let Some(deadline) = self.start() else {
            return false;
        };
        let have = std::mem::take(prefix);
        let (more, late) = read_more(have, need, reader, deadline).await;
        self.late = late;
        let short = more.len() < need;
        *prefix = more;
        short
    }

    /// The outcome of a prefix that did not arrive within the peek
    /// timeout: counted in `peek_timed_out`, then closed, or taken to the
    /// fallback with `prefix` replayed when the admission says so
    /// ([`crate::Admission::with_fallback_on_peek_timeout`]; counted in
    /// `fallback` as well), except an HTTP request carrier (`request`),
    /// which is always closed.
    fn late_outcome(
        &mut self,
        adm: &crate::Admission,
        prefix: &mut Vec<u8>,
        request: bool,
    ) -> Admit {
        let c = &self.shared.counts.admission;
        c.peek_timed_out.fetch_add(1, Relaxed);
        if adm.fallback_on_peek_timeout() && !request {
            c.fallback.fetch_add(1, Relaxed);
            return Admit::Fallback(std::mem::take(prefix));
        }
        Admit::Close
    }

    /// One decision on `prefix`, with `info`'s source and peer filled in:
    /// its outcome, or how far to read for another when `can_read` and the
    /// carrier did not end `short`.
    async fn decide_round(
        &mut self,
        info: &CarrierInfo<'_>,
        prefix: &mut Vec<u8>,
        can_read: bool,
        short: bool,
    ) -> Round {
        let Some(deadline) = self.start() else {
            self.admitted = true;
            return Round::Done(Admit::Accept(std::mem::take(prefix)));
        };
        let Some(adm) = self.shared.admission.clone() else {
            return Round::Done(Admit::Close);
        };
        if self.late {
            return Round::Done(self.late_outcome(&adm, prefix, info.request.is_some()));
        }
        let shared = self.shared.clone();
        let c = &shared.counts.admission;
        let listener = Listener {
            shared: self.shared.clone(),
        };
        let decided = {
            // A synchronous decision panics in the call itself.
            let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                adm.decider().decide(info, prefix)
            }));
            let Ok(decide) = call else {
                c.closed.fetch_add(1, Relaxed);
                return Round::Done(Admit::Close);
            };
            let decide = CatchUnwind(decide);
            let timed = tokio::time::timeout_at(deadline, decide);
            let mut timed = std::pin::pin!(timed);
            let mut closed = std::pin::pin!(listener.adapter().closed());
            std::future::poll_fn(|cx| {
                if closed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                timed.as_mut().poll(cx).map(Some)
            })
            .await
        };
        let decision = match decided {
            Some(Ok(Some(d))) => d,
            Some(Err(_)) => {
                c.peek_timed_out.fetch_add(1, Relaxed);
                return Round::Done(Admit::Close);
            }
            // Panicked, or cancelled with the listener.
            Some(Ok(None)) | None => AdmissionVerdict::Close.into(),
        };
        let crate::Decision { verdict, variant } = decision;
        let verdict = match verdict.bounded(prefix.len()) {
            AdmissionVerdict::More { need } => {
                if can_read && !short && need > prefix.len() && need <= adm.max_peek() {
                    return Round::Read(need);
                }
                AdmissionVerdict::Close
            }
            v => v,
        };
        Round::Done(match verdict {
            AdmissionVerdict::Accept { skip, value } => {
                c.accepted.fetch_add(1, Relaxed);
                c.count_variant(variant.as_ref(), |v| v.accepted += 1);
                self.admitted = true;
                self.value = value;
                self.variant = variant;
                prefix.drain(..skip);
                Admit::Accept(std::mem::take(prefix))
            }
            AdmissionVerdict::Fallback => {
                c.fallback.fetch_add(1, Relaxed);
                c.count_variant(variant.as_ref(), |v| v.fallback += 1);
                Admit::Fallback(std::mem::take(prefix))
            }
            AdmissionVerdict::Stall if self.start_stall() => {
                c.stalled.fetch_add(1, Relaxed);
                c.count_variant(variant.as_ref(), |v| v.stalled += 1);
                Admit::Stall
            }
            AdmissionVerdict::Stall => {
                c.stall_overflow.fetch_add(1, Relaxed);
                Admit::Close
            }
            AdmissionVerdict::Close | AdmissionVerdict::More { .. } => {
                c.closed.fetch_add(1, Relaxed);
                c.count_variant(variant.as_ref(), |v| v.closed += 1);
                Admit::Close
            }
        })
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
    }

    /// Stalls the carrier: reads and discards what arrives on `reader`
    /// (or only waits, without one) until it ends, fails, the listener
    /// closes, or a duration in the admission's stall interval has passed,
    /// a function of the source alone for the listener's lifetime (a keyed
    /// MAC of the source, aggregated to its prefix as for every per-source
    /// limit, [`ListenerConfig::source_prefix_v4`]), or a new
    /// carrier that found every slot of the listener taken evicts it. The
    /// slots stay held meanwhile, until the entry is dropped. The caller
    /// then closes the carrier gracefully and drops the entry.
    ///
    /// A source stalls at most `max_pending_per_source - 1` carriers at
    /// once ([`ListenerConfig::max_pending_per_source`]), and the listener
    /// at most half of [`ListenerConfig::max_pending`]: beyond them, a
    /// [`AdmissionVerdict::Stall`] is [`Admit::Close`] (counted in
    /// [`AdmissionStats::stall_overflow`]) and a stall after
    /// [`Admit::Fallback`] returns at once.
    pub async fn stall<R>(&mut self, reader: Option<&mut R>)
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
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
                Some(r) => discard(r, adm.discard_buffer(), duration).await,
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
        if !self.handshaken {
            let c = &self.shared.counts;
            if self.shared.admission.is_some() {
                &c.admission.handshake_failed
            } else {
                &c.setup_failures
            }
            .fetch_add(1, Relaxed);
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

impl Listener {
    /// The listener's operations for carrier adapters and own accept
    /// loops: carrier slots, admission, join lookups, memory charges and
    /// setup-failure counts ([`ListenerAdapter`]).
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
    pub fn enter(&self, peer: SocketAddr, source: Option<SocketAddr>) -> Option<Entry> {
        self.listener
            .enter_uncounted(peer, source)
            .map_err(|e| self.listener.count(e))
            .ok()
    }

    /// The listener's admission ([`ListenerConfig::admission`]).
    pub fn admission(&self) -> Option<&'a Admission> {
        self.listener.shared.admission.as_ref()
    }

    /// For use in an admission's decision: whether `prefix`, a byte-stream
    /// carrier's first bytes, begins a Join Hello (first byte `02`) whose
    /// Locator names a session of the listener at this moment. While the
    /// prefix is shorter than the Hello's clear head (through the nonce,
    /// at most 291 bytes for the suites defined) the answer is
    /// [`JoinPrefix::Need`], to ask for with [`crate::AdmissionVerdict::More`]
    /// ([`crate::Admission::with_max_peek`] must allow it). On a
    /// message-framed carrier the prefix is the whole message, and `Need`
    /// means it is too short. Advisory: the join still authenticates, and
    /// one whose session ended meanwhile is an unknown Locator.
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
    pub fn trusted_proxies(&self) -> &'a crate::proto::trusted::TrustedProxies {
        &self.listener.shared.trusted
    }

    /// Whether the listener is closed ([`Listener::close`]): an adapter
    /// tells with it why [`ListenerAdapter::enter`](crate::adapter::ListenerAdapter::enter) gave no place.
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
    pub fn setup_guard(&self) -> SetupGuard {
        SetupGuard(Some(self.listener.shared.clone()))
    }

    /// Counts `bytes` that a carrier holds for the listener's sessions in
    /// its memory budget for as long as the charge
    /// lives: for example the receive window of a QUIC connection whose
    /// streams carry their pipes and lanes.
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
        );
        let mut stall_key = [0u8; 32];
        for c in stall_key.as_chunks_mut::<8>().0 {
            *c = random_u64().to_le_bytes();
        }
        let shared = Arc::new(ListenShared {
            locators: Default::default(),
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

    /// The response to a refused carrier: the policy's, or the default.
    fn reject_response(&self, info: &RejectInfo) -> RejectAction {
        self.shared.on_reject.as_ref().map_or_else(
            || RejectAction::default_for(info),
            |f| f.ask(info, self.shared.logger.as_ref()),
        )
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
            late: false,
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
        let (sessions, unaccepted) = {
            let mut wakes = WakeList::default();
            let mut st = self.shared.lock();
            st.draining = true;
            st.accept_waiters.wake_all(&mut wakes);
            let unaccepted = std::mem::take(&mut st.accept);
            let live: Vec<_> = st
                .live
                .iter()
                .filter_map(|w| WeakSession::from_weak(w.clone()).upgrade())
                .collect();
            (live, unaccepted)
        };
        drop(unaccepted);
        struct CloseOnDrop<'a>(&'a Listener);
        impl Drop for CloseOnDrop<'_> {
            fn drop(&mut self) {
                self.0.close();
            }
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
    pub fn config(&self) -> &Arc<Config> {
        &self.shared.config
    }

    /// The listener's limits.
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
    /// source; the connection enters the listener ([`ListenerAdapter::enter`](crate::adapter::ListenerAdapter::enter):
    /// refused at once when its source has its share); `setup` (a TLS
    /// handshake) runs within the listener's handshake timeout; the
    /// listener's admission reads the prefix and decides with the metadata
    /// `info` gives (the source and peer filled in); an accepted
    /// connection becomes a carrier by `carrier`, handed to
    /// [`Listener::handle_pipe`] with the rest of the prefix in front
    /// ([`PipeIo::with_prefix`]); one decided on with Fallback goes to
    /// [`ListenerConfig::fallback`], every byte read replayed, or is
    /// stalled without one. Each connection holds its slots of the
    /// listener ([`ListenerAdapter::enter`](crate::adapter::ListenerAdapter::enter)) from before its setup. Nothing is written on a connection before it is accepted.
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
        I: for<'a> Fn(&'a C) -> CarrierInfo<'a> + Send + Sync + 'static,
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
            move |l, (mut conn, mut entry): (C, Entry)| {
                let (info, carrier) = (info.clone(), carrier.clone());
                async move {
                    let prefix = entry.read_prefix(&mut conn).await;
                    match entry.decide_carrier(&mut conn, &*info, prefix).await {
                        Admit::Accept(rest) => {
                            let io = carrier(conn).with_prefix(rest);
                            let _ = l.handle_pipe(io, PipeHint::from_entry(entry)).await;
                        }
                        Admit::Fallback(prefix) => match l.shared.fallback.clone() {
                            Some(f) => {
                                let source = entry.source();
                                drop(entry);
                                let conn: Box<dyn FallbackStream> = Box::new(conn);
                                f.serve(Prefixed::new(conn, prefix), source).await;
                            }
                            None => stall_stream(entry, conn).await,
                        },
                        Admit::Stall => stall_stream(entry, conn).await,
                        Admit::Close => {}
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
    /// enters the listener ([`ListenerAdapter::enter`](crate::adapter::ListenerAdapter::enter)) holds its slots from
    /// then on; whatever a setup does before it enters, or when it never
    /// does (a connection whose carriers enter one by one), at most
    /// `max_pending` of the listener's limits are in setup at once: a new
    /// connection beyond them ends the oldest setup, so that slow
    /// handshakes can neither pile up nor lock new clients out. A setup counts its own
    /// failures: an [`Entry`] dropped before its admission counts its
    /// handshake as failed, and a setup without one calls
    /// [`ListenerAdapter::count_setup_failure`](crate::adapter::ListenerAdapter::count_setup_failure) (or holds a
    /// [`ListenerAdapter::setup_guard`](crate::adapter::ListenerAdapter::setup_guard)); one ended by its timeout or for a
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
    /// and the session sends PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT).
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
                    peek_timed_out: a.peek_timed_out.load(Relaxed),
                    handshake_failed: a.handshake_failed.load(Relaxed),
                }
            },
        }
    }

    /// The carrier's entry: the adapter's, or one taken now, with the
    /// listener's admission applied to the carrier's own bytes.
    async fn entered(&self, pipe: &mut PipeIo, hint: &mut PipeHint) -> Result<Entry, HandleError> {
        let mut entry = match hint.entry.take() {
            Some(e) => e,
            None => {
                let peer = hint.peer.or(hint.source).unwrap_or(NO_ADDR);
                let mut e = self.enter_uncounted(peer, hint.source)?;
                // No outer handshake here.
                e.handshaken = true;
                e.admitted = hint.connection.is_some();
                e
            }
        };
        if entry.admitted {
            return Ok(entry);
        }
        // Bytes come apart into records on a message carrier: its prefix is
        // its first message's start.
        let mut reader = pipe.reader.take();
        let admit = entry.admit(CarrierInfo::new(), reader.as_mut()).await;
        let r = match admit {
            Admit::Accept(rest) => {
                pipe.reader = reader;
                let mut rest = rest;
                rest.extend_from_slice(&pipe.prefix);
                pipe.prefix = rest;
                return Ok(entry);
            }
            // A carrier handed over directly has no fallback target.
            Admit::Fallback(_) | Admit::Stall => {
                entry.stall(reader.as_mut()).await;
                Err(HandleError::NotAdmitted)
            }
            Admit::Close => Err(HandleError::NotAdmitted),
        };
        pipe.reader = reader;
        r
    }

    /// Sets up a carrier: what its pipe's end is waited for with, if it
    /// became a pipe.
    async fn handle(&self, mut pipe: PipeIo, mut hint: PipeHint) -> Result<PipeEnd, HandleError> {
        let shared = &self.shared;
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
            Some(self.entered(&mut pipe, &mut hint).await?)
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
                super::lanes::route(
                    pipe,
                    &lane_key,
                    crate::proto::session::PipeId(id).lane(lane),
                    bytes,
                )?;
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
        let entry = match entry.take() {
            Some(e) => e,
            None => {
                let peer = hint.peer.or(hint.source).unwrap_or(NO_ADDR);
                let mut e = self.enter_uncounted(peer, hint.source)?;
                e.handshaken = true;
                e.admitted = true;
                e
            }
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
        let deadline = arrived.checked_add(limits.handshake_timeout);
        let partner = PairWait {
            shared,
            token,
            id,
            ticket: None,
        };
        let partner = match deadline {
            Some(d) => tokio::time::timeout_at(d.into(), partner)
                .await
                .ok()
                .flatten(),
            None => partner.await,
        };
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
            crate::proto::params::ZMUX_MAX_RECORD_SIZE as usize + 1
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

    /// The configuration of a new session on `pipe`.
    fn session_config(
        &self,
        pipe: &PipeIo,
        (source, peer): (Option<SocketAddr>, Option<SocketAddr>),
    ) -> Result<Arc<Config>, HandleError> {
        let chosen = self.shared.lock().core.config().session_config.clone();
        let Some(f) = chosen else {
            return Ok(self.shared.config.clone());
        };
        let tls = pipe.terminated_tls();
        let carrier = crate::SessionCarrier {
            source: source.or(peer),
            peer,
            tls: tls.as_ref(),
            admitted: pipe.admitted.as_deref(),
        };
        match f.choose(&carrier, self.shared.logger.as_ref()) {
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
        let config = self.session_config(&pipe, addrs)?;
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
        let refusal = if self.shared.account.pressure() {
            Some("memory budget")
        } else {
            let st = self.shared.lock();
            (st.closed || st.draining).then_some("draining")
        };
        if let Some(reason) = refusal {
            // Refused after its own parameters, so that the peer reads why.
            shared.refuse(reason).await;
            return Err(HandleError::Refused);
        }
        let done = shared.lock_pipe_done(0);
        match shared.established().await {
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
        let session = self.shared.locators.get(locator);
        // The joined session's join timeout bounds the handshake, or the listener's session
        // configuration's for an unknown Locator. A refusal's stall does not use it.
        let join_timeout = session
            .as_ref()
            .map_or(self.shared.config.join_timeout, |s| {
                s.lock().core.config().join_timeout
            });
        let deadline = now().checked_add(join_timeout);
        let Ok(parsed) = JoinHello::parse(pipe.framing, hello) else {
            return self.rejected(pending, "malformed", None, source).await;
        };
        let mode = Some(parsed.mode());
        let Some(session) = session else {
            return self
                .rejected(pending, "unknown_locator", mode, source)
                .await;
        };
        // A stream carrier of a session that runs over this one is refused once the join is
        // authenticated, so that a joiner that cannot see the loop backs off.
        let looped = pipe
            .outer
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|outer| runs_over(&outer, &session));
        // A Hello that arrived as carrier early data could be a replay: it is
        // offered only once the carrier's handshake completed, within the handshake
        // timeout; one that does not complete is a setup failure. Bound never takes it.
        if let Some(done) = pipe.take_early_in() {
            if parsed.mode() == crate::proto::seal::RecordMode::Bound {
                return self.rejected(pending, "early_data", mode, source).await;
            }
            let completed = match deadline {
                Some(d) => tokio::time::timeout_at(d.into(), done).await.is_ok(),
                None => {
                    done.await;
                    true
                }
            };
            if !completed {
                return Err(HandleError::SetupFailed);
            }
        }
        // A Hello in Bound needs a Binding of this carrier: it declares the contract, is
        // not split and has an exporter. A stream of a multiplexed session has none
        // here: the connection below it would vouch for streams the multiplexer's other
        // carriers open.
        let binding = if parsed.mode() == crate::proto::seal::RecordMode::Bound {
            let binding = (pipe.secure && !pipe.split)
                .then(|| pipe.exporter.as_ref().and_then(|e| e.pipe_binding()))
                .flatten();
            let Some(binding) = binding else {
                session.hello_without_binding();
                return self.rejected(pending, "auth", mode, source).await;
            };
            binding
        } else {
            Vec::new()
        };
        let mut join = loop {
            // The listener's lock is never taken under a session's.
            let closed = {
                let st = self.shared.lock();
                // Evicted for a newer carrier while it waits: closed
                // like one waiting for its first record.
                st.closed || st.evicted.contains(&pending.id)
            };
            let pressure = self.shared.account.pressure();
            if closed {
                return Err(HandleError::Refused);
            }
            // Only joins that let a session resume pass the budget; the others are declined
            // by the reject policy, like an unknown Locator.
            let Some(opened) =
                session.open_hello(&parsed, &binding, |suspended| suspended || !pressure)
            else {
                return self
                    .rejected(pending, "memory_pressure", mode, source)
                    .await;
            };
            match opened {
                OpenedHello::Verified(j) => break j,
                OpenedHello::AuthFailed => {
                    return self.rejected(pending, "auth", mode, source).await;
                }
                OpenedHello::UnknownSuite => {
                    return self.rejected(pending, "unknown_suite", mode, source).await;
                }
                OpenedHello::UnknownLocator => {
                    return self
                        .rejected(pending, "unknown_locator", mode, source)
                        .await;
                }
                OpenedHello::Close | OpenedHello::Fatal => return Err(HandleError::Rejected),
                // Offered again only when the session is ready, so that each carrier
                // counts once in `join_pending`.
                OpenedHello::Hold | OpenedHello::KeyWait => {
                    let keys = handle::join_keys_wait(&session);
                    let mut keys = std::pin::pin!(keys);
                    let mut closing = Closing {
                        slot: None,
                        shared: &self.shared,
                        id: Some(pending.id),
                        ticket: None,
                    };
                    let waited = std::pin::pin!(async {
                        std::future::poll_fn(|cx| {
                            if let Poll::Ready(ready) = keys.as_mut().poll(cx) {
                                return Poll::Ready(Ok(ready));
                            }
                            Pin::new(&mut closing).poll(cx).map(|()| Err(()))
                        })
                        .await
                    });
                    let waited = match deadline {
                        Some(d) => tokio::time::timeout_at(d.into(), waited).await.ok(),
                        None => Some(waited.await),
                    };
                    match waited {
                        Some(Ok(true)) => {}
                        Some(Err(()) | Ok(false)) => return Err(HandleError::Refused),
                        None => return Err(HandleError::TimedOut),
                    }
                }
            }
        };
        // Step 7: a Mode or authorization that local policy refuses leaves the Pipe ID's
        // bit clear and is counted.
        let info = RecordPolicyInput {
            has_exporter: pipe.exporter.is_some(),
            secure: pipe.secure,
            ..RecordPolicyInput::default()
        };
        let admitted = pipe.admitted.as_deref().cloned();
        if !session.join_allowed(&info, &join, admitted.as_ref()) {
            return Err(HandleError::Rejected);
        }
        let carrier = PeerCarrier {
            inbound: pipe.reader.is_some().then_some(pipe.framing),
            outbound: pipe.writer.is_some().then_some(pipe.framing),
            looped,
            overhead: pipe.write_overhead,
            received: hello.len(),
        };
        let plan = session.join_plan(pipe.carrier, "reply");
        if !plan.delay.is_zero() {
            let wait = until(
                self.join_stopped(pending.id, &session),
                tokio::time::sleep(plan.delay),
            );
            let waited = match deadline {
                Some(d) => match tokio::time::timeout_at(d.into(), wait).await {
                    Ok(w) => w,
                    Err(_) => return Err(HandleError::TimedOut),
                },
                None => wait.await,
            };
            if waited.is_none() {
                return Err(HandleError::Refused);
            }
        }
        let reply = match session.claim_hello(&mut join, carrier, &plan) {
            ClaimedHello::Accept(reply) => reply,
            ClaimedHello::Refuse(reply) => {
                // The Reply ends with a graceful end of the writing half: closing the half
                // abruptly could discard it on the way, and the joiner would not see the
                // refusal.
                let refuse = async {
                    if write_unit(&mut pipe, &reply).await.is_ok() {
                        pipe.end_unused(true, false).await;
                    }
                };
                let refuse = until(self.join_stopped(pending.id, &session), refuse);
                match deadline {
                    Some(d) => {
                        let _ = tokio::time::timeout_at(d.into(), refuse).await;
                    }
                    None => {
                        let _ = refuse.await;
                    }
                }
                return Err(HandleError::Refused);
            }
            ClaimedHello::Close => return Err(HandleError::Rejected),
        };
        {
            // A new authenticated Hello may evict the session's oldest Unconfirmed one
            // and is not refused for lack of room.
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
                match join.read_confirm(&input) {
                    Ok(Some(n)) => {
                        input.drain(..n);
                        return Ok::<_, std::io::Error>(input);
                    }
                    Ok(None) => {}
                    Err(_) => return Err(std::io::ErrorKind::InvalidData.into()),
                }
                if pipe.framing == Framing::Records {
                    input.clear();
                }
                if read_unit(&mut pipe, &mut input).await? == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
            }
        };
        // An Unconfirmed carrier ends with its session and with the listener.
        let confirm = until(self.join_stopped(pending.id, &session), confirm);
        let confirmed = match deadline {
            Some(d) => match tokio::time::timeout_at(d.into(), confirm).await {
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
        let meta = (
            pipe.carrier,
            pipe.write_overhead,
            pipe.admitted.as_deref().cloned(),
        );
        let (want_in, want_out) = (join.pipe().direction != 1, join.pipe().direction != 0);
        let (attached, records) = match session.confirm_join(*join, carrier, meta) {
            ConfirmedJoin::Attached { pipe, records } => (pipe, records),
            ConfirmedJoin::Refused | ConfirmedJoin::Close => return Err(HandleError::Refused),
        };
        // A pipe of its session now, no longer pending.
        pending.done();
        pipe.prefix = rest;
        pipe.resolve_lanes();
        if let Some((s, o)) = records {
            pipe = seal_carrier(pipe, s, o);
        }
        if let Some(m) = pipe.max_record {
            session.set_pipe_limits(attached, m, pipe.write_overhead);
        }
        pipe.end_unused(want_in, want_out).await;
        if claim_carrier(&session, attached.0, pipe.outer.take()).is_err() {
            // A loop formed since the check above, through another session:
            // ZMUX_PIPE_RESOURCE_LIMIT.
            session.drop_pipe(attached);
            return Err(HandleError::Refused);
        }
        // A session closing meanwhile takes no new pipe.
        let Ok(done) = session.attach_task(attached.0, pipe) else {
            session.forget_pipe(attached);
            return Err(HandleError::Refused);
        };
        // Counted once attached.
        self.shared.counts.joins.fetch_add(1, Relaxed);
        drop(session);
        Ok(PipeEnd::of(done))
    }

    /// Ready once a Hello's handshake has nothing left to wait for: its session ended, the
    /// listener closed or the carrier was evicted.
    async fn join_stopped(&self, id: CarrierId, session: &Shared<Tokio>) {
        let ended = handle::session_ended_wait(session);
        let _ = until(self.closed_or_evicted(id), ended).await;
    }

    /// Ready once the listener closes or the carrier was evicted.
    fn closed_or_evicted(&self, id: CarrierId) -> impl Future<Output = ()> + '_ {
        let mut closing = Closing {
            shared: &self.shared,
            id: Some(id),
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
        if self.reject_response(info) != RejectAction::Stall {
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
                    let _ = until(self.closed_or_evicted(id), stall).await;
                }
                None => stall.await,
            }
        };
        self.stall_refused(entry, wait).await;
    }
}

/// Memory counted in a listener's budget on behalf of its sessions
/// ([`ListenerAdapter::charge_memory`](crate::adapter::ListenerAdapter::charge_memory)) until dropped.
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
            Some(s) => Some(Some(s)),
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

/// A connection's setup without an [`Entry`] ([`ListenerAdapter::setup_guard`](crate::adapter::ListenerAdapter::setup_guard)).
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

/// Stalls a byte-stream connection that was not admitted, then shuts its
/// write side down; the source slot is given back once it is closed.
async fn stall_stream<C: AsyncRead + AsyncWrite + Unpin + Send>(mut entry: Entry, mut conn: C) {
    use tokio::io::AsyncWriteExt;
    entry.stall(Some(&mut conn)).await;
    let _ = conn.shutdown().await;
    drop(conn);
    drop(entry);
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

    /// A draining listener refuses a new session with CONNECTION_REFUSED
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
