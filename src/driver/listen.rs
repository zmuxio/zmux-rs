//! The tokio listener: new carriers start sessions or
//! join existing ones after verification, with the limits of MULTIPATH.md
//! Section 5.6 and the memory budget and suspended-session limits of
//! RESUME.md Section 9.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use ::tokio::io::AsyncReadExt;

use super::account::{Account, AccountLink};
use super::handle::Shared;
use super::resources::{Kind, Live};
use super::stream_pipe::{claim_carrier, runs_over};
use super::tokio::{JoinOffer, PipeIo, Session, Tokio, now};
use super::wait::{Ticket, WaitList};
use super::wake::WakeList;
use crate::proto::listener::{
    CarrierId, Classified, ListenerConfig, ListenerCore as Core, Opened, source_key,
};
use crate::proto::params::Role;
use crate::proto::record::Framing;
use crate::proto::session::{Config, JoinVerdict, RoleConfig};

/// What a carrier came with besides its bytes.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PipeHint {
    /// The remote address, for the per-source limits.
    pub source: Option<IpAddr>,
    /// An out-of-band PIPE_JOIN (for example the decoded `Zmux-Pipe-Join`
    /// header).
    pub join: Option<Vec<u8>>,
}

impl PipeHint {
    /// A hint with the remote address.
    pub fn from_addr(addr: IpAddr) -> Self {
        Self {
            source: Some(addr),
            ..Self::default()
        }
    }

    /// Takes the out-of-band join from a `Zmux-Pipe-Join` header value.
    #[must_use]
    pub fn with_join_header(mut self, value: &str) -> Self {
        self.join = crate::proto::oob::decode_vec(value.as_bytes()).ok();
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
}

/// What happened to a listener's carriers ([`Listener::stats`]): counts
/// since it was made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListenerStats {
    /// Sessions started (offered to [`Listener::accept`]).
    pub sessions: u64,
    /// Joins accepted into existing sessions.
    pub joins: u64,
    /// Connections a `serve` loop could not make a carrier of: a failed
    /// TLS handshake or upgrade, its timeout, or the setup limit.
    pub setup_failures: u64,
    /// Carriers rejected: unknown, unauthenticated or replayed joins, or
    /// not zmux at all ([`HandleError::Rejected`]).
    pub rejected: u64,
    /// Carriers refused at a limit or after [`Listener::close`]
    /// ([`HandleError::Refused`]).
    pub refused: u64,
    /// Carriers without a first record in time ([`HandleError::TimedOut`]).
    pub timed_out: u64,
}

/// Why a carrier was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandleError {
    /// Closed without a distinguishable reason: unknown, unauthenticated,
    /// replayed or refused (MULTIPATH.md Section 5.4).
    Rejected,
    /// The listener is at a limit for this source, or closed.
    Refused,
    /// No first record (or join) in time.
    TimedOut,
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rejected => "carrier rejected",
            Self::Refused => "carrier refused",
            Self::TimedOut => "carrier timed out",
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
    closed: bool,
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
    _live: Live,
}

impl ListenShared {
    fn lock(&self) -> MutexGuard<'_, State_> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

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
///             let _ = l.handle_pipe(PipeIo::tcp(carrier), PipeHint::from_addr(peer.ip())).await;
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
    pub fn new(config: impl Into<Arc<Config>>, limits: ListenerConfig) -> Self {
        let config = config.into();
        let account = Account::new(
            limits.memory_budget,
            limits.max_suspended,
            limits.on_memory_pressure.clone(),
        );
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
                closed: false,
            }),
            config,
            _live: Live::new(Kind::Listener),
        });
        Self { shared }
    }

    /// The next session a carrier started, once established. `None` after
    /// [`Listener::close`]. Cancel-safe.
    pub async fn accept(&self) -> Option<Session> {
        Accept {
            shared: &self.shared,
            ticket: None,
        }
        .await
    }

    /// Stops accepting: `accept` returns `None`; new carriers are refused,
    /// carriers still waiting for their first record are given up, and
    /// sessions established but not accepted are closed (with code 0).
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
    /// it accepts becomes a carrier ([`PipeIo::tcp`]) handed to
    /// [`Listener::handle_pipe`] in a task of its own, with the peer's
    /// address as the hint. Accept errors (a connection reset before it
    /// was accepted, no file descriptors left) are retried after a pause
    /// of up to 100 ms, so the loop ends only with the listener. Run it in
    /// a task of its own:
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
    pub async fn serve(self, tcp: ::tokio::net::TcpListener) {
        self.serve_with(
            || tcp.accept(),
            |stream, peer| {
                std::future::ready(Ok((PipeIo::tcp(stream), PipeHint::from_addr(peer.ip()))))
            },
        )
        .await;
    }

    /// Serves any listening socket until [`Listener::close`], as
    /// [`Listener::serve`] does for TCP: `accept` yields a connection and
    /// its peer's address, and `carrier` turns a connection into a carrier
    /// and its hint in the connection's own task (a TLS handshake or a
    /// WebSocket upgrade, for example), within the listener's
    /// `handshake_timeout`; a connection it fails for is dropped. At most
    /// `max_pending` of the listener's limits are in that stage at once:
    /// a connection beyond them is dropped at once. The building block of
    /// the adapters' `serve`.
    ///
    /// The loop holds a handle of the listener until it is closed: call
    /// [`Listener::close`] to end it.
    pub async fn serve_with<T, A, AF, F, CF>(self, mut accept: A, carrier: F)
    where
        A: FnMut() -> AF,
        AF: Future<Output = std::io::Result<(T, std::net::SocketAddr)>>,
        F: Fn(T, std::net::SocketAddr) -> CF,
        CF: Future<Output = std::io::Result<(PipeIo, PipeHint)>> + Send + 'static,
    {
        let limits = self.limits();
        let (limit, most) = (limits.handshake_timeout, limits.max_pending.max(1));
        let pending = Arc::new(());
        while let Some(accepted) = self.accept_or_close(accept()).await {
            match accepted {
                // Each task holds a clone of `pending` while it sets up.
                Ok((conn, peer)) if Arc::strong_count(&pending) <= most => {
                    let (l, made, token) = (self.clone(), carrier(conn, peer), pending.clone());
                    ::tokio::spawn(async move {
                        let made = ::tokio::time::timeout(limit, made).await;
                        drop(token);
                        match made {
                            Ok(Ok((io, hint))) => {
                                let _ = l.handle_pipe(io, hint).await;
                            }
                            _ => l.count_setup_failure(),
                        }
                    });
                }
                Ok(_) => self.count_setup_failure(),
                Err(e) => accept_failed(&e).await,
            }
        }
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
    /// [`Listener::accept`]) or a join of an existing one. Resolves when the
    /// carrier is done, so that an HTTP handler stays alive with its pipe.
    /// A join over a stream of a session that runs over the session it
    /// joins ([`PipeIo::from_stream`]) is refused: the carrier is closed
    /// and the session sends PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT)
    /// (MULTIPATH.md Section 5.4 step 7).
    pub async fn handle_pipe(&self, pipe: PipeIo, hint: PipeHint) -> Result<(), HandleError> {
        let r = self.handle(pipe, hint).await;
        if let Err(e) = r {
            let c = &self.shared.counts;
            match e {
                HandleError::Rejected => &c.rejected,
                HandleError::Refused => &c.refused,
                HandleError::TimedOut => &c.timed_out,
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
        }
    }

    /// Counts a connection that a `serve` loop accepted but could not turn
    /// into a carrier (a failed TLS handshake or upgrade, or one beyond the
    /// setup limit or timeout): for carrier adapters' own accept loops
    /// ([`ListenerStats::setup_failures`]).
    pub fn count_setup_failure(&self) {
        self.shared.counts.setup_failures.fetch_add(1, Relaxed);
    }

    async fn handle(&self, mut pipe: PipeIo, hint: PipeHint) -> Result<(), HandleError> {
        let shared = &self.shared;
        let now = now();
        let source = hint.source.map_or(0, source_key);
        let mut exempt;
        // Wake-ups of an evicted carrier, after the listener's lock.
        let mut wakes = WakeList::default();
        let (limits, id) = {
            let mut st = shared.lock();
            if st.closed {
                return Err(HandleError::Refused);
            }
            let limits = st.core.config().clone();
            // A stream that may be a lane of a pipe on its connection
            // waits for its first record outside the limits (MULTIPATH.md
            // Section 5.5).
            exempt = pipe.conn().and_then(super::lanes::Exempt::new);
            if exempt.is_some() {
                (limits, st.core.open_stream(pipe.framing, now))
            } else {
                match st.core.open(source, pipe.framing, now) {
                    Opened::Accepted { id, evicted } => {
                        st.evict(evicted, &mut wakes);
                        (limits, id)
                    }
                    Opened::Refused => return Err(HandleError::Refused),
                }
            }
        };
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
            let first = ::tokio::time::timeout(
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
                )
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

    /// Reads until the listener classified the carrier.
    async fn first_record(shared: &ListenShared, id: CarrierId, pipe: &mut PipeIo) -> Classified {
        let Some(reader) = pipe.reader.as_mut() else {
            return Classified::Reject;
        };
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
    async fn start_session(&self, pipe: PipeIo) -> Result<(), HandleError> {
        let config = self.shared.config.clone();
        // Each session of the listener has its own locator unless one is
        // configured.
        let own =
            (config.offers_multipath() && config.own_locator().is_empty()).then(random_locator);
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
        )
        .map_err(|_| HandleError::Rejected)?;
        let locator = shared.lock().core.local_locator().to_vec();
        let done = shared.lock_pipe_done(0);
        shared.lock().io.account = Some(Box::new(AccountLink::new(self.shared.account.clone())));
        if !locator.is_empty() {
            let mut st = self.shared.lock();
            st.sessions.insert(locator, Arc::downgrade(&shared));
            // Ended sessions leave the table once it doubled since the last
            // pruning: amortized constant work per session.
            if st.sessions.len() > 2 * st.pruned.max(16) {
                st.sessions.retain(|_, w| w.strong_count() > 0);
                st.pruned = st.sessions.len();
            }
        }
        match shared.established().await {
            Ok(s) => {
                let mut wakes = WakeList::default();
                let mut st = self.shared.lock();
                if st.closed {
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
        if let Some(d) = done {
            d.wait().await;
        }
        Ok(())
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
    ) -> Result<(), HandleError> {
        let session = {
            let st = self.shared.lock();
            st.sessions.get(locator).and_then(Weak::upgrade)
        };
        let Some(session) = session else {
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
            };
            // Only joins that let a session resume pass the budget.
            let Some(verdict) = session.offer_join(&offer, |suspended| suspended || !pressure)
            else {
                return Err(HandleError::Rejected);
            };
            match verdict {
                JoinVerdict::Accepted(p) => {
                    // A pipe of its session now, no longer pending.
                    pending.done();
                    pipe.resolve_lanes();
                    if claim_carrier(&session, p.0, pipe.outer.take()).is_err() {
                        // A loop formed since the check above, through
                        // another session.
                        session.drop_pipe(p);
                        return Err(HandleError::Rejected);
                    }
                    pipe.prefix = bytes;
                    // A session closing meanwhile takes no new pipe.
                    let Ok(done) = session.attach_task(p.0, pipe) else {
                        session.forget_pipe(p);
                        return Err(HandleError::Rejected);
                    };
                    // Counted once attached: a refusal above is `rejected`.
                    self.shared.counts.joins.fetch_add(1, Relaxed);
                    drop(session);
                    done.wait().await;
                    return Ok(());
                }
                JoinVerdict::Wait if deadline.is_none_or(|d| now() < d) => {
                    ::tokio::time::sleep(Duration::from_millis(10)).await;
                }
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
            .finish()
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
            None => st.closed.then_some(None),
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
        ::tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A random session locator.
fn random_locator() -> Vec<u8> {
    let mut l = vec![0u8; 8];
    if getrandom::fill(&mut l).is_err() {
        use std::hash::BuildHasher;
        let t = std::collections::hash_map::RandomState::new().hash_one(0x006c_6f63_6174_6f72_u64);
        l.copy_from_slice(&t.to_le_bytes());
    }
    l
}
