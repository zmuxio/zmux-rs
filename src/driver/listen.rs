//! The tokio listener: new carriers start sessions or
//! join existing ones after verification, with the limits of MULTIPATH.md
//! Section 5.6 and the memory budget and suspended-session limits of
//! RESUME.md Section 9.

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
use super::admission::{CatchUnwind, Fallback, FallbackStream, Prefixed, discard, read_prefix};
use super::handle::{Shared, WeakSession};
use super::resources::{Kind, Live};
use super::stream_pipe::{claim_carrier, runs_over};
use super::tokio::{JoinOffer, PipeIo, Session, Tokio, now};
use super::transform::InboundTransform;
use super::wait::{PipeDone, Ticket, WaitList};
use super::wake::WakeList;
use crate::proto::VarInt;
use crate::proto::admission::{Admission, AdmittedValue, CarrierInfo, Verdict};
use crate::proto::listener::{
    CarrierId, Classified, ListenerConfig, ListenerCore as Core, MAX_INSTANCE_ID_LEN, Opened,
    Paired, source_key,
};
use crate::proto::oob::PAIRING_TOKEN_LEN;
use crate::proto::params::Role;
use crate::proto::record::Framing;
use crate::proto::session::{Config, JoinVerdict, RoleConfig};
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
    /// An out-of-band PIPE_JOIN (for example the decoded `Zmux-Pipe-Join`
    /// header).
    pub join: Option<Vec<u8>>,
    /// The pairing token of a split bootstrap's carrier (SPEC.md Section
    /// 6.1.1; for example the decoded `Zmux-Pipe-Pair` header): the
    /// carrier is one half of pipe pair 0, an uplink when it has only an
    /// inbound half, a downlink when it has only an outbound one. A token
    /// that is not [`PAIRING_TOKEN_LEN`] bytes is rejected.
    ///
    /// A half waits for its partner in a pending slot of the listener,
    /// until the other half arrives or the handshake timeout ends: 64 per
    /// listener and 8 per source by default
    /// ([`crate::ListenerConfig::max_pending`],
    /// [`crate::ListenerConfig::max_pending_per_source`]), an IPv6 source
    /// counted by its /64. Without an admission
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

    /// The hint of a carrier that entered the listener ([`Listener::enter`])
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
    /// ([`Verdict::Accept`]): set by the listener before its inbound
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

    /// Takes the out-of-band join from a `Zmux-Pipe-Join` header value.
    #[must_use]
    pub fn with_join_header(mut self, value: &str) -> Self {
        self.join = crate::proto::oob::decode_vec(value.as_bytes()).ok();
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
}

/// What the listener's admission ([`crate::ListenerConfig::admission`])
/// decided ([`ListenerStats::admission`]): counts since the listener was
/// made, each carrier that took a source slot counted once its outcome is
/// known, all 0 without an admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmissionStats {
    /// Decided with [`Verdict::Accept`]; each then counts once more as a
    /// pipe input in the other fields of [`ListenerStats`].
    pub accepted: u64,
    /// Decided with [`Verdict::Fallback`] (stalled without a fallback
    /// target, still counted here).
    pub fallback: u64,
    /// Decided with [`Verdict::Stall`], counted when the stall starts.
    pub stalled: u64,
    /// Decided with [`Verdict::Close`], an `Accept` beyond the prefix, a
    /// decision that panicked, or one cancelled because the listener
    /// closed.
    pub closed: u64,
    /// Decided with [`Verdict::Stall`] when the listener could not stall
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
/// ([`Listener::stats`], API.md Section 7.2): counts since it was made.
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
    /// Sessions started: bootstraps offered to [`Listener::accept`], a
    /// split bootstrap once.
    pub sessions: u64,
    /// Joins accepted into existing sessions, and lanes accepted into
    /// their pipes.
    pub joins: u64,
    /// Connections never made a pipe input: a failed TLS handshake or its
    /// timeout (also the handshake a join sent in early data waits for), a
    /// failed HTTP or WebSocket upgrade, or the setup limit
    /// ([`Listener::count_setup_failure`]). With an admission, a carrier's
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
    /// during [`Listener::shutdown`], or anything after [`Listener::close`]
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
    /// or replayed (MULTIPATH.md Section 5.4), a lane that names no pipe,
    /// or not zmux at all.
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

struct State_ {
    core: Core,
    sessions: HashMap<Vec<u8>, Weak<Shared<Tokio>>>,
    /// The size of `sessions` after its last pruning of ended sessions.
    pruned: usize,
    accept: VecDeque<Session>,
    accept_waiters: WaitList,
    /// Carriers waiting for their first record, woken by [`Listener::close`]
    /// and by an eviction.
    close_waiters: WaitList,
    /// Pending carriers evicted for a new one (MULTIPATH.md Section 5.6),
    /// until each saw it and closed.
    evicted: Vec<CarrierId>,
    /// The halves of split bootstraps waiting for their other half, by
    /// pairing token (SPEC.md Section 6.1.1); the core decides the pairing.
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
struct PairSlot {
    waiter: CarrierId,
    partner: Option<(PipeIo, Arc<PipeDone>)>,
}

impl State_ {
    /// Ends the pending carrier the core evicted for a new one: it is woken
    /// to close (MULTIPATH.md Section 5.6).
    /// The wake-ups go to `wakes`, woken after the lock.
    fn evict(&mut self, evicted: Option<CarrierId>, wakes: &mut WakeList) {
        if let Some(e) = evicted {
            self.evicted.push(e);
            self.close_waiters.wake_all(wakes);
        }
    }
}

struct ListenShared {
    /// What happened to the carriers handed to the listener.
    counts: Counts,
    state: Mutex<State_>,
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
    /// [`ListenerConfig::answer_unknown_joins`].
    answer_unknown: bool,
    _live: Live,
}

impl ListenShared {
    fn lock(&self) -> MutexGuard<'_, State_> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A carrier that entered a listener ([`Listener::enter`]): it holds a
/// place under its source's limit of pending carriers
/// ([`ListenerConfig::max_pending_per_source`]) from before its outer
/// handshake until it becomes a pending input of the listener
/// ([`Listener::handle_pipe`] with [`PipeHint::from_entry`]), goes to a
/// fallback target, or is dropped. Dropped before its admission
/// ([`Entry::admit`]), its outer handshake counts as failed.
pub struct Entry {
    shared: Arc<ListenShared>,
    key: u64,
    held: bool,
    source: SocketAddr,
    peer: SocketAddr,
    admitted: bool,
    handshaken: bool,
    /// The carrier counts as stalled under its source's limit of stalled
    /// carriers ([`ListenerCore::stall`](crate::proto::listener::ListenerCore::stall)).
    stalling: bool,
    /// The end of the peek timeout, from the end of the outer handshake.
    deadline: Option<Instant>,
    /// The value the admission accepted it with.
    value: Option<AdmittedValue>,
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
    /// for a carrier decided on its request head), then [`Entry::decide`]
    /// with `info`.
    pub async fn admit<R>(&mut self, info: CarrierInfo<'_>, reader: Option<&mut R>) -> Admit
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let prefix = match reader {
            Some(r) => self.read_prefix(r).await,
            None => Vec::new(),
        };
        self.decide(info, prefix).await
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
            (Some(adm), Some(d)) if adm.peek() > 0 => read_prefix(adm.peek(), reader, d).await.0,
            _ => Vec::new(),
        }
    }

    /// The deadline of the admission, started at the first call: the end
    /// of the outer handshake.
    fn start(&mut self) -> Option<Instant> {
        self.handshaken = true;
        let adm = self.shared.admission.as_ref()?;
        Some(
            *self
                .deadline
                .get_or_insert_with(|| Instant::now() + adm.peek_timeout()),
        )
    }

    /// The listener's decision on the carrier, from `info` (whose source
    /// and peer are the entry's) and `prefix` (read by
    /// [`Entry::read_prefix`]), within what remains of the peek timeout;
    /// cancelled when the listener closes. Without an admission it accepts
    /// at once. Counted in [`ListenerStats::admission`].
    pub async fn decide(&mut self, info: CarrierInfo<'_>, mut prefix: Vec<u8>) -> Admit {
        let Some(deadline) = self.start() else {
            self.admitted = true;
            return Admit::Accept(prefix);
        };
        let Some(adm) = self.shared.admission.clone() else {
            return Admit::Close;
        };
        let shared = self.shared.clone();
        let c = &shared.counts.admission;
        let info = info.with_source(self.source).with_peer(self.peer);
        let listener = Listener {
            shared: self.shared.clone(),
        };
        let decided = {
            // A synchronous decision panics in the call itself.
            let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                adm.decider().decide(&info, &prefix)
            }));
            let Ok(decide) = call else {
                c.closed.fetch_add(1, Relaxed);
                return Admit::Close;
            };
            let decide = CatchUnwind(decide);
            let timed = tokio::time::timeout_at(deadline, decide);
            let mut timed = std::pin::pin!(timed);
            let mut closed = std::pin::pin!(listener.closed());
            std::future::poll_fn(|cx| {
                if closed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                timed.as_mut().poll(cx).map(Some)
            })
            .await
        };
        let verdict = match decided {
            Some(Ok(Some(v))) => v.bounded(prefix.len()),
            Some(Err(_)) => {
                c.peek_timed_out.fetch_add(1, Relaxed);
                return Admit::Close;
            }
            // Panicked, or cancelled with the listener.
            Some(Ok(None)) | None => Verdict::Close,
        };
        match verdict {
            Verdict::Accept { skip, value } => {
                c.accepted.fetch_add(1, Relaxed);
                self.admitted = true;
                self.value = value;
                prefix.drain(..skip);
                Admit::Accept(prefix)
            }
            Verdict::Fallback => {
                c.fallback.fetch_add(1, Relaxed);
                Admit::Fallback(prefix)
            }
            Verdict::Stall if self.start_stall() => {
                c.stalled.fetch_add(1, Relaxed);
                Admit::Stall
            }
            Verdict::Stall => {
                c.stall_overflow.fetch_add(1, Relaxed);
                Admit::Close
            }
            Verdict::Close => {
                c.closed.fetch_add(1, Relaxed);
                Admit::Close
            }
        }
    }

    /// Counts the carrier as stalled: `false` when the listener closed or
    /// the source has `max_pending_per_source - 1` stalled carriers.
    fn start_stall(&mut self) -> bool {
        if !self.stalling {
            let mut st = self.shared.lock();
            self.stalling = !st.closed && st.core.stall(self.key);
        }
        self.stalling
    }

    /// Stops counting the carrier as stalled.
    fn end_stall(&mut self) {
        if std::mem::take(&mut self.stalling) {
            self.shared.lock().core.unstall(self.key);
        }
    }

    /// Stalls the carrier: reads and discards what arrives on `reader`
    /// (or only waits, without one) until it ends, fails, the listener
    /// closes, or a duration in the admission's stall interval has passed,
    /// a function of the source alone for the listener's lifetime (a keyed
    /// MAC of the source, an IPv6 address aggregated to its /64). The
    /// source slot stays held meanwhile, until the entry is dropped. The
    /// caller then closes the carrier gracefully and drops the entry.
    ///
    /// A source stalls at most `max_pending_per_source - 1` carriers at
    /// once ([`ListenerConfig::max_pending_per_source`]): beyond them, a
    /// [`Verdict::Stall`] is [`Admit::Close`] (counted in
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
        let duration = min + Duration::from_nanos(off);
        let listener = Listener {
            shared: self.shared.clone(),
        };
        let wait = async {
            match reader {
                Some(r) => discard(r, adm.discard_buffer(), duration).await,
                None => tokio::time::sleep(duration).await,
            }
        };
        let mut wait = std::pin::pin!(wait);
        let mut closed = std::pin::pin!(listener.closed());
        std::future::poll_fn(|cx| {
            if closed.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            wait.as_mut().poll(cx)
        })
        .await;
        self.end_stall();
    }

    /// Moves the slot to `source`, the client a trusted intermediary
    /// reported in the request the carrier's outer handshake read (a
    /// WebSocket upgrade's forwarding header field): `false` when that
    /// source has its share, and the carrier is closed at once (counted
    /// as refused).
    pub fn set_source(&mut self, source: SocketAddr) -> bool {
        let key = source_key(source.ip());
        if key != self.key {
            let mut st = self.shared.lock();
            if !st.core.hold(key) {
                drop(st);
                self.shared.counts.refused.fetch_add(1, Relaxed);
                // Refused, not a failed handshake.
                self.handshaken = true;
                return false;
            }
            st.core.release(self.key);
            self.key = key;
        }
        self.source = source;
        true
    }

    /// The slot becomes a pending slot of the core.
    fn transfer(&mut self) {
        self.held = false;
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
        if self.held {
            self.shared.lock().core.release(self.key);
        }
    }
}

/// The address of a carrier the host gave without one.
const NO_ADDR: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// A listener: hand it every new carrier. It starts a
/// session for a carrier that opens one and routes a carrier that joins an
/// existing session to it, after verifying the join's token.
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
/// config.pipe_auth = PipeAuth::psk(b"a pre-shared key, 16 bytes or more".to_vec());
///
/// let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
/// let addr = tcp.local_addr()?;
/// let listener = Listener::new(config.clone(), ListenerConfig::default());
/// let l = listener.clone();
/// tokio::spawn(async move {
///     while let Ok((carrier, peer)) = tcp.accept().await {
///         let l = l.clone();
///         tokio::spawn(async move {
///             let _ = l.handle_pipe(PipeIo::tcp(carrier), PipeHint::from_peer(peer)).await;
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
/// let session = Session::connect(PipeIo::tcp(first), config).await?;
/// let second = tokio::net::TcpStream::connect(addr).await?;
/// let pipe = session.add_pipe(PipeIo::tcp(second), PipeOptions::default())?;
/// // The second path is the fallback: it carries data only while the
/// // first one is saturated or has failed, and the server is asked to do
/// // the same on its side.
/// pipe.set_send_priority(10)?;
/// pipe.set_receive_priority(10)?;
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
    /// A listener that starts sessions with `config` and applies `limits`.
    /// Must be created inside a tokio runtime.
    ///
    /// # Panics
    ///
    /// If `limits.instance_id` is longer than [`MAX_INSTANCE_ID_LEN`].
    pub fn new(config: impl Into<Arc<Config>>, limits: ListenerConfig) -> Self {
        assert!(
            limits.instance_id.len() <= MAX_INSTANCE_ID_LEN,
            "ListenerConfig::instance_id longer than MAX_INSTANCE_ID_LEN"
        );
        let config = config.into();
        let instance_id = limits.instance_id.clone();
        let trusted = limits.trusted_proxies.clone();
        let admission = limits.admission.clone();
        let fallback = limits.fallback.clone();
        let transform = limits.inbound_transform.clone();
        let answer_unknown = limits.answer_unknown_joins;
        let account = Account::new(
            limits.memory_budget.bytes(),
            limits.max_suspended,
            limits.on_memory_pressure.clone(),
        );
        let mut stall_key = [0u8; 32];
        for c in stall_key.as_chunks_mut::<8>().0 {
            *c = random_u64().to_le_bytes();
        }
        let shared = Arc::new(ListenShared {
            counts: Counts::default(),
            account,
            state: Mutex::new(State_ {
                core: Core::new(limits),
                sessions: HashMap::new(),
                pruned: 0,
                accept: VecDeque::new(),
                accept_waiters: WaitList::default(),
                close_waiters: WaitList::default(),
                evicted: Vec::new(),
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
            answer_unknown,
            _live: Live::new(Kind::Listener),
        });
        Self { shared }
    }

    /// The first step of every carrier at every entry of the listener,
    /// before its outer handshake: a place under the limit of pending
    /// carriers of its source (`source`, or `peer` when unset; an IPv6
    /// address counted by its /64), held by the returned [`Entry`]. `None`
    /// when the source has its share or the listener is closed: close the
    /// carrier at once, without a handshake (counted as refused). Then the
    /// outer handshake, [`Entry::admit`], and [`Listener::handle_pipe`].
    pub fn enter(&self, peer: SocketAddr, source: Option<SocketAddr>) -> Option<Entry> {
        let e = self.enter_uncounted(peer, source);
        if e.is_none() {
            self.shared.counts.refused.fetch_add(1, Relaxed);
        }
        e
    }

    fn enter_uncounted(&self, peer: SocketAddr, source: Option<SocketAddr>) -> Option<Entry> {
        let source = source.unwrap_or(peer);
        let key = source_key(source.ip());
        {
            let mut st = self.shared.lock();
            if st.closed || !st.core.hold(key) {
                return None;
            }
        }
        Some(Entry {
            shared: self.shared.clone(),
            key,
            held: true,
            stalling: false,
            source,
            peer,
            admitted: false,
            handshaken: false,
            deadline: None,
            value: None,
        })
    }

    /// The listener's admission ([`ListenerConfig::admission`]).
    pub fn admission(&self) -> Option<&Admission> {
        self.shared.admission.as_ref()
    }

    /// The intermediaries the listener trusts to report a carrier's client
    /// ([`ListenerConfig::trusted_proxies`]): its adapters take a carrier's
    /// source from them.
    pub fn trusted_proxies(&self) -> &crate::proto::trusted::TrustedProxies {
        &self.shared.trusted
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

    /// Resolves once the listener is closed ([`Listener::close`]): for
    /// accept loops of carriers, which end with it. Cancel-safe.
    pub async fn closed(&self) {
        Closing {
            shared: &self.shared,
            id: None,
            ticket: None,
        }
        .await;
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
    /// it accepts becomes a carrier ([`PipeIo::tcp`]), its source the
    /// peer or the client a trusted intermediary reports in a PROXY
    /// protocol header ([`ListenerConfig::trusted_proxies`],
    /// [`crate::proxied_source`]), admitted by the listener's admission
    /// and handed to [`Listener::handle_pipe`], as
    /// [`Listener::serve_streams`] says. Run it in a task of its own:
    ///
    /// ```no_run
    /// # async fn example() -> std::io::Result<()> {
    /// use zmux::{Config, Listener, ListenerConfig, PipeAuth};
    ///
    /// let config = Config::multipath(PipeAuth::psk(*b"a pre-shared key of 32 bytes...."));
    /// let listener = Listener::new(config, ListenerConfig::default());
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
            PipeIo::tcp,
        )
        .await;
    }

    /// Serves any listening byte-stream socket until [`Listener::close`]:
    /// `accept` yields a connection and its peer's address. Each
    /// connection, in a task of its own: a connection from an intermediary
    /// the listener trusts to send the PROXY protocol has its header read
    /// first ([`crate::proxied_source`]), and the client it reports is the
    /// source; the connection enters the listener ([`Listener::enter`]:
    /// refused at once when its source has its share); `setup` (a TLS
    /// handshake) runs within the listener's handshake timeout; the
    /// listener's admission reads the prefix and decides with the metadata
    /// `info` gives (the source and peer filled in); an accepted
    /// connection becomes a carrier by `carrier`, handed to
    /// [`Listener::handle_pipe`] with the rest of the prefix in front
    /// ([`PipeIo::with_prefix`]); one decided on with Fallback goes to
    /// [`ListenerConfig::fallback`], every byte read replayed, or is
    /// stalled without one. At most `max_pending` of the listener's limits
    /// are in setup at once, as [`Listener::serve_connections`] says.
    /// Nothing is written on a connection before it is accepted.
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
                        l.count_setup_failure();
                        return Err(());
                    };
                    let entry = l.enter(peer, Some(source)).ok_or(())?;
                    // A failed handshake counts with the entry dropped.
                    let conn = setup(conn).await.map_err(drop)?;
                    Ok((conn, entry))
                }
            },
            move |l, (mut conn, mut entry): (C, Entry)| {
                let (info, carrier) = (info.clone(), carrier.clone());
                async move {
                    let prefix = entry.read_prefix(&mut conn).await;
                    match entry.decide(info(&conn), prefix).await {
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
    /// carriers to [`Listener::handle_pipe`], for example). At most
    /// `max_pending` of the listener's limits are in setup at once: a new
    /// connection beyond them ends the oldest setup, so that slow
    /// handshakes cannot lock new clients out (MULTIPATH.md Section 5.6).
    /// A setup counts its own failures: an [`Entry`] dropped before its
    /// admission counts its handshake as failed, and a setup without one
    /// calls [`Listener::count_setup_failure`] (or holds a
    /// [`Listener::setup_guard`]); one ended by its timeout or for a newer
    /// one, or still running when the listener is closed, is dropped.
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
        let (limit, most) = (limits.handshake_timeout, limits.max_pending.max(1));
        let serve = Arc::new(serve);
        // The setup tasks, oldest first; each spawns its serving apart, so
        // that aborting it ends only the setup.
        let mut setups: VecDeque<tokio::task::AbortHandle> = VecDeque::new();
        while let Some(Some(accepted)) = self.accept_or_close(accept()).await {
            let conn = match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    accept_failed(&e).await;
                    continue;
                }
            };
            setups.retain(|h| !h.is_finished());
            if setups.len() >= most
                && let Some(oldest) = setups.pop_front()
            {
                oldest.abort();
            }
            let (l, made, serve) = (self.clone(), setup(conn), serve.clone());
            let task = tokio::spawn(async move {
                let made = l.accept_or_close(tokio::time::timeout(limit, made)).await;
                if let Some(Ok(Ok(c))) = made {
                    tokio::spawn(async move { serve(l, c).await });
                }
            });
            setups.push_back(task.abort_handle());
        }
    }

    /// A guard for a connection's setup that holds no [`Entry`] (the TLS
    /// handshake of an HTTP connection, whose requests enter the listener
    /// one by one): dropped before [`SetupGuard::done`], it counts a setup
    /// failure ([`ListenerStats::setup_failures`]).
    pub fn setup_guard(&self) -> SetupGuard {
        SetupGuard(Some(self.shared.clone()))
    }

    /// `accept`'s result, or `None` once the listener is closed.
    async fn accept_or_close<T>(&self, accept: impl Future<Output = T>) -> Option<T> {
        let mut accept = std::pin::pin!(accept);
        let mut closed = std::pin::pin!(self.closed());
        std::future::poll_fn(|cx| {
            if closed.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            accept.as_mut().poll(cx).map(Some)
        })
        .await
    }

    /// Counts `bytes` that a carrier holds for the listener's sessions in
    /// its memory budget for as long as the charge
    /// lives: for example the receive window of a QUIC connection whose
    /// streams carry their pipes and lanes.
    pub fn charge_memory(&self, bytes: u64) -> MemoryCharge {
        self.shared.account.charge(bytes, 0);
        MemoryCharge {
            account: self.shared.account.clone(),
            bytes,
        }
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
    /// and the session sends PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT)
    /// (MULTIPATH.md Section 5.4 step 7).
    pub async fn handle_pipe(&self, pipe: PipeIo, hint: PipeHint) -> Result<(), HandleError> {
        // The setup's state (admission, transform, first record) is boxed
        // and freed once it is done: what waits for the pipe's end is
        // small, as it is kept for the pipe's lifetime.
        let r = match Box::pin(self.handle(pipe, hint)).await {
            Ok(end) => {
                end.wait().await;
                Ok(())
            }
            Err(e) => Err(e),
        };
        if let Err(e) = r {
            let c = &self.shared.counts;
            match e {
                HandleError::Rejected => &c.rejected,
                HandleError::Refused => &c.refused,
                HandleError::TimedOut => &c.timed_out,
                HandleError::SetupFailed => &c.setup_failures,
                // Counted by the admission.
                HandleError::NotAdmitted => return r,
            }
            .fetch_add(1, Relaxed);
        }
        r
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

    /// Counts a connection that an accept loop could not make a pipe input
    /// of: a failed TLS handshake or its timeout (the handshake a join sent
    /// in early data waits for included), a failed HTTP or WebSocket
    /// upgrade, or the setup limit. For carrier adapters' own accept loops
    /// ([`ListenerStats::setup_failures`]); such a connection is counted
    /// nowhere else.
    pub fn count_setup_failure(&self) {
        self.shared.counts.setup_failures.fetch_add(1, Relaxed);
    }

    /// The carrier's entry: the adapter's, or one taken now, with the
    /// listener's admission applied to the carrier's own bytes.
    async fn entered(&self, pipe: &mut PipeIo, hint: &mut PipeHint) -> Result<Entry, HandleError> {
        let mut entry = match hint.entry.take() {
            Some(e) => e,
            None => {
                let peer = hint.peer.or(hint.source).unwrap_or(NO_ADDR);
                let mut e = self
                    .enter_uncounted(peer, hint.source)
                    .ok_or(HandleError::Refused)?;
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
        // for its first record outside the limits (MULTIPATH.md Section
        // 5.5): its connection was admitted, and it takes a slot once it
        // turns out a join or a new session.
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
        if let Some(t) = shared.transform.clone() {
            pipe = self.transform(&t, pipe, &hint).await?;
        }
        if let Some(token) = hint.pair.take() {
            let entry = entry.take().ok_or(HandleError::Rejected)?;
            return self.handle_paired(pipe, hint, entry, &token).await;
        }
        let now = now();
        let source = entry
            .as_ref()
            .map(|e| e.key)
            .or_else(|| hint.source.or(hint.peer).map(|a| source_key(a.ip())))
            .unwrap_or(0);
        // Wake-ups of an evicted carrier, after the listener's lock.
        let mut wakes = WakeList::default();
        let (limits, id) = {
            let mut st = shared.lock();
            if st.closed {
                return Err(HandleError::Refused);
            }
            let limits = st.core.config().clone();
            if let Some(e) = entry.as_mut() {
                e.transfer();
                match st.core.open_held(e.key, pipe.framing, now) {
                    Opened::Accepted { id, evicted } => {
                        st.evict(evicted, &mut wakes);
                        (limits, id)
                    }
                    Opened::Refused => return Err(HandleError::Refused),
                }
            } else {
                (limits, st.core.open_stream(pipe.framing, now))
            }
        };
        drop(entry);
        // The evicted carrier is woken now, not when this one is done.
        drop(std::mem::take(&mut wakes));
        // Leaves the pending carriers however this ends, a dropped handler
        // included (its source's limit is not used up for good).
        let mut pending = Pending {
            shared,
            id,
            done: false,
        };
        // A stream of a multiplexed session is never carrier-bound
        // (MULTIPATH.md Section 10.5): the binding of the connection below
        // it would vouch for streams the multiplexer's other carriers open.
        let binding = pipe
            .exporter
            .as_ref()
            .map(|e| e.pipe.clone())
            .unwrap_or_default();
        let classified = if let Some(frame) = &hint.join {
            shared.lock().core.oob(id, frame, now)
        } else {
            let first = tokio::time::timeout(
                limits.first_record_timeout,
                Self::first_record(shared, id, &mut pipe),
            );
            let mut first = std::pin::pin!(first);
            let mut closing = Closing {
                shared,
                id: Some(id),
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
            let mut st = shared.lock();
            match st.core.admit(id, source) {
                Opened::Accepted { evicted, .. } => st.evict(evicted, &mut wakes),
                Opened::Refused => return Err(HandleError::Refused),
            }
            drop(st);
            drop(std::mem::take(&mut wakes));
        }
        match classified {
            Classified::NewSession { .. } if shared.lock().draining => Err(HandleError::Refused),
            Classified::NewSession { first } => {
                pending.done();
                pipe.prefix = first;
                self.start_session(pipe).await
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
            Classified::Join {
                locator,
                frame,
                bytes,
                inband,
            } => {
                self.join(
                    &mut pending,
                    &locator,
                    &frame,
                    &binding,
                    bytes,
                    inband,
                    pipe,
                    &limits,
                )
                .await
            }
            _ => Err(HandleError::Rejected),
        }
    }

    /// Applies the inbound transform to `pipe`, within the handshake
    /// timeout and until the listener closes: a result of another kind, an
    /// error or the bound is a setup failure, and the carrier is dropped.
    async fn transform(
        &self,
        t: &InboundTransform,
        mut pipe: PipeIo,
        hint: &PipeHint,
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
        let timeout = self.shared.lock().core.config().handshake_timeout;
        let timed = tokio::time::timeout(timeout, t.call(pipe, hint));
        let mut timed = std::pin::pin!(timed);
        let mut closed = std::pin::pin!(self.closed());
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
            Some(_) => return Err(HandleError::SetupFailed),
        };
        if (
            io.reader.is_some(),
            io.writer.is_some(),
            io.framing,
            io.split_bootstrap,
        ) != kind
        {
            return Err(HandleError::SetupFailed);
        }
        io.carrier = carrier;
        io.admitted = value;
        Ok(io)
    }

    /// A half of a split bootstrap (SPEC.md Section 6.1.1): it takes a
    /// pending slot like any carrier (so the listener's limits bound the
    /// unpaired halves, per source too), an uplink delivers its first
    /// record (a new session's) within the first-record timeout, and the
    /// first half waits for the other, with the same token and the
    /// opposite direction, within the handshake timeout from its arrival.
    /// The first half then starts the session on the two; the second
    /// resolves when that session ends.
    async fn handle_paired(
        &self,
        mut pipe: PipeIo,
        hint: PipeHint,
        mut entry: Entry,
        token: &[u8],
    ) -> Result<PipeEnd, HandleError> {
        let shared = &self.shared;
        let Ok(token) = <[u8; PAIRING_TOKEN_LEN]>::try_from(token) else {
            return Err(HandleError::Rejected);
        };
        let uplink = pipe.reader.is_some();
        if uplink == pipe.writer.is_some() || hint.join.is_some() {
            return Err(HandleError::Rejected);
        }
        let arrived = now();
        let mut wakes = WakeList::default();
        let (limits, id) = {
            let mut st = shared.lock();
            // A split bootstrap is a new session.
            if st.closed || st.draining {
                return Err(HandleError::Refused);
            }
            let limits = st.core.config().clone();
            entry.transfer();
            match st.core.open_held(entry.key, pipe.framing, arrived) {
                Opened::Accepted { id, evicted } => {
                    st.evict(evicted, &mut wakes);
                    (limits, id)
                }
                Opened::Refused => return Err(HandleError::Refused),
            }
        };
        drop(std::mem::take(&mut wakes));
        let mut pending = Pending {
            shared,
            id,
            done: false,
        };
        if uplink {
            let r = {
                let first = tokio::time::timeout(
                    limits.first_record_timeout,
                    Self::first_record(shared, id, &mut pipe),
                );
                let mut first = std::pin::pin!(first);
                let mut closing = Closing {
                    shared,
                    id: Some(id),
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
            match r {
                Some(Ok(Classified::NewSession { first })) => pipe.prefix = first,
                Some(Ok(_)) => return Err(HandleError::Rejected),
                Some(Err(_)) => return Err(HandleError::TimedOut),
                None => return Err(HandleError::Refused),
            }
        }
        let first = {
            let mut st = shared.lock();
            if st.closed || st.draining {
                return Err(HandleError::Refused);
            }
            match st.core.pair(token, id, uplink, now()) {
                Paired::Waiting => {
                    st.pairs.insert(
                        token,
                        PairSlot {
                            waiter: id,
                            partner: None,
                        },
                    );
                    true
                }
                Paired::Complete(_) => false,
                Paired::Reject => return Err(HandleError::Rejected),
            }
        };
        if !first {
            let done = Arc::new(PipeDone::default());
            {
                let mut st = shared.lock();
                let Some(slot) = st.pairs.get_mut(&token).filter(|s| s.partner.is_none()) else {
                    // The first half gave up meanwhile.
                    return Err(HandleError::Rejected);
                };
                slot.partner = Some((pipe, done.clone()));
                st.close_waiters.wake_all(&mut wakes);
            }
            drop(std::mem::take(&mut wakes));
            pending.done();
            return Ok(PipeEnd::of(done));
        }
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
        let Some((other, done)) = partner else {
            let mut st = shared.lock();
            if st.pairs.get(&token).is_some_and(|s| s.waiter == id) {
                st.pairs.remove(&token);
            }
            return Err(HandleError::TimedOut);
        };
        // The second half resolves when the session ends, however it ends:
        // its release goes with what this half waits for.
        let finish = FinishOnDrop(done);
        pending.done();
        let (up, down) = if uplink { (pipe, other) } else { (other, pipe) };
        let mut io = PipeIo::paired(up, down);
        if let Some(taken) = io.taken.take() {
            taken();
        }
        let mut end = self.start_session(io).await?;
        end.partner = Some(finish);
        Ok(end)
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
        let mut buf = vec![0u8; 16 * 1024];
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

    /// A new session on its bootstrap carrier.
    async fn start_session(&self, pipe: PipeIo) -> Result<PipeEnd, HandleError> {
        let config = self.shared.config.clone();
        // Each session of the listener has its own locator unless one is
        // configured.
        let own = (config.offers_multipath() && config.own_locator().is_empty())
            .then(|| random_locator(&self.shared.instance_id));
        if self.shared.account.pressure() {
            // Under memory pressure new sessions are refused.
            return Err(HandleError::Refused);
        }
        let shared = Shared::create(
            pipe,
            config,
            RoleConfig::Responder,
            Some(Role::Responder),
            own.as_deref(),
            |shared| self.register_session(shared),
        )
        .map_err(|_| HandleError::Rejected)?;
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
            let mut st = self.shared.lock();
            st.live.push(Arc::downgrade(shared));
            if st.live.len() > 2 * st.live_pruned.max(16) {
                st.live.retain(|w| w.strong_count() > 0);
                st.live_pruned = st.live.len();
            }
        }
        if !locator.is_empty() {
            let mut st = self.shared.lock();
            st.sessions.insert(locator, Arc::downgrade(shared));
            // Ended sessions leave the table once it doubled since the last
            // pruning: amortized constant work per session.
            if st.sessions.len() > 2 * st.pruned.max(16) {
                st.sessions.retain(|_, w| w.strong_count() > 0);
                st.pruned = st.sessions.len();
            }
        }
    }

    /// Offers a join to its session and, once accepted, hands it the
    /// carrier (MULTIPATH.md Section 5.4).
    #[allow(clippy::too_many_arguments)]
    async fn join(
        &self,
        pending: &mut Pending<'_>,
        locator: &[u8],
        frame: &[u8],
        binding: &[u8],
        bytes: Vec<u8>,
        inband: bool,
        mut pipe: PipeIo,
        limits: &ListenerConfig,
    ) -> Result<PipeEnd, HandleError> {
        let session = {
            let st = self.shared.lock();
            st.sessions.get(locator).and_then(Weak::upgrade)
        };
        let Some(session) = session else {
            if self.shared.answer_unknown && locator.starts_with(&self.shared.instance_id) {
                let closed = self.shared.lock().closed;
                if !closed {
                    let wait = tokio::time::timeout(
                        limits.first_record_timeout,
                        answer_unknown(&mut pipe),
                    );
                    let _ = wait.await;
                }
            }
            return Err(HandleError::Rejected);
        };
        // A stream carrier of a session that runs over this one
        // (EXTENSIONS.md Section 10.2) is refused at MULTIPATH.md Section 5.4
        // step 7, so that a joiner that cannot see the loop backs off.
        let looped = pipe
            .outer
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|outer| runs_over(&outer, &session));
        // A deadline beyond the clock's range never comes.
        let deadline = now().checked_add(limits.handshake_timeout);
        // A join that arrived as carrier early data could be a replay: it
        // is offered only once the carrier's handshake completed, within
        // the handshake timeout; one that does not complete is a setup
        // failure.
        if let Some(done) = pipe.take_early_in() {
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
        let (inbound, outbound) = (
            pipe.reader.is_some().then_some(pipe.framing),
            pipe.writer.is_some().then_some(pipe.framing),
        );
        loop {
            // The listener's lock is never taken under a session's.
            let closed = {
                let st = self.shared.lock();
                // Evicted for a newer carrier while it waits (MULTIPATH.md
                // Section 5.6): closed like one waiting for its first
                // record.
                st.closed || st.evicted.contains(&pending.id)
            };
            let pressure = self.shared.account.pressure();
            if closed {
                return Err(HandleError::Refused);
            }
            let offer = JoinOffer {
                frame,
                binding,
                inbound,
                outbound,
                inband,
                looped,
                carrier: pipe.carrier,
                write_overhead: pipe.write_overhead,
                admitted: pipe.admitted.as_deref().cloned(),
            };
            // Only joins that let a session resume pass the budget.
            let Some(verdict) = session.offer_join(&offer, |suspended| suspended || !pressure)
            else {
                return Err(HandleError::Refused);
            };
            match verdict {
                JoinVerdict::Accepted(p) => {
                    // A pipe of its session now, no longer pending.
                    pending.done();
                    pipe.resolve_lanes();
                    if claim_carrier(&session, p.0, pipe.outer.take()).is_err() {
                        // A loop formed since the check above, through
                        // another session: ZMUX_PIPE_RESOURCE_LIMIT.
                        session.drop_pipe(p);
                        return Err(HandleError::Refused);
                    }
                    pipe.prefix = bytes;
                    // A session closing meanwhile takes no new pipe.
                    let Ok(done) = session.attach_task(p.0, pipe) else {
                        session.forget_pipe(p);
                        return Err(HandleError::Rejected);
                    };
                    // Counted once attached.
                    self.shared.counts.joins.fetch_add(1, Relaxed);
                    drop(session);
                    return Ok(PipeEnd::of(done));
                }
                JoinVerdict::Wait if deadline.is_none_or(|d| now() < d) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                JoinVerdict::ResourceLimit => return Err(HandleError::Refused),
                _ => return Err(HandleError::Rejected),
            }
        }
    }
}

/// Memory counted in a listener's budget on behalf of its sessions
/// ([`Listener::charge_memory`]) until dropped.
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

/// A carrier among the listener's pending carriers (MULTIPATH.md Section
/// 5.6), until it is classified, joined or given up.
struct Pending<'a> {
    shared: &'a ListenShared,
    id: CarrierId,
    done: bool,
}

impl Pending<'_> {
    fn done(&mut self) {
        if !std::mem::replace(&mut self.done, true) {
            let mut st = self.shared.lock();
            st.core.done(self.id);
            // An eviction it did not see (it ended first) is forgotten.
            let id = self.id;
            st.evicted.retain(|&e| e != id);
        }
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
        if st.closed || evicted.is_some() {
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
    type Output = Option<(PipeIo, Arc<PipeDone>)>;

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

/// A connection's setup without an [`Entry`] ([`Listener::setup_guard`]).
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
    use std::io::ErrorKind as K;
    if !matches!(
        e.kind(),
        K::ConnectionAborted | K::ConnectionReset | K::Interrupted | K::WouldBlock
    ) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The answer to a join that names no session (MULTIPATH.md Section 5.4
/// step 3): a record of CONNECTION_CLOSE 0x1c with ZMUX_RESUME_FAILED
/// (0x0f05f74e), Frame Type 0 and an empty Reason Phrase; a byte stream
/// carries the record's length first.
const UNKNOWN_JOIN_ANSWER: [u8; 8] = [0x07, 0x1c, 0x8f, 0x05, 0xf7, 0x4e, 0x00, 0x00];

/// Writes [`UNKNOWN_JOIN_ANSWER`] on the carrier and ends its sending half
/// gracefully.
async fn answer_unknown(pipe: &mut PipeIo) {
    let bytes: &'static [u8] = match pipe.framing {
        Framing::ByteStream => &UNKNOWN_JOIN_ANSWER,
        Framing::Records => &UNKNOWN_JOIN_ANSWER[1..],
    };
    let Some(w) = pipe.writer.as_mut() else {
        return;
    };
    let mut at = 0;
    let wrote = std::future::poll_fn(|cx| {
        while at < bytes.len() {
            let n = match w {
                super::tokio::Writer::Io(w) => {
                    std::task::ready!(w.as_mut().poll_write(cx, &bytes[at..]))
                }
                super::tokio::Writer::Chunks(w) => {
                    let mut c = [bytes::Bytes::from_static(&bytes[at..])];
                    std::task::ready!(w.as_mut().poll_write_chunks(cx, &mut c))
                }
                super::tokio::Writer::Stream(w) => {
                    std::task::ready!(Pin::new(w).poll_write(cx, &bytes[at..]))
                }
            };
            match n {
                Ok(n) if n > 0 => at += n,
                _ => return Poll::Ready(false),
            }
        }
        Poll::Ready(true)
    })
    .await;
    if wrote {
        let _ = std::future::poll_fn(|cx| w.poll_flush(cx)).await;
        let _ = std::future::poll_fn(|cx| w.poll_shutdown(cx)).await;
    }
}

/// A 16-byte session locator: `prefix`, then random bytes.
fn random_locator(prefix: &[u8]) -> Vec<u8> {
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
                let routed = self
                    .listener
                    .shared
                    .lock()
                    .sessions
                    .values()
                    .find_map(Weak::upgrade);
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
            let listener = Listener::new(config.clone(), ListenerConfig::default());
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
                RoleConfig::Responder,
                Some(Role::Responder),
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
            server.close(VarInt::ZERO, b"done");
            server.closed().await;
            client.closed().await;
            listener.close();
        })
        .await
        .expect("registration test deadline");
    }
}
