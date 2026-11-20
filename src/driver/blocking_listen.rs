//! A listener for the std driver: the steps of the tokio one, on the caller's thread. New
//! sessions are accepted and Joins verified over the same `ListenerCore` and session
//! operations. Split carriers, lanes and admissions are tokio's.
//!
//! What both listeners decide is decided once: the first record's classification, the
//! slots, stalls and evictions, and whether a new session is admitted
//! (`ListenerCore`); a join's every outcome (`JoinAccept`); a later decision's end
//! (`hooks::settle_by`/`settle_blocking` with the listener's stop). What is written
//! here a second time is how each step waits and does its I/O: a parked thread with a
//! watchdog over a blocking carrier here, futures over an async one there. Sharing that
//! too would mean one listener over both I/O models, the blocking one emulated with
//! futures or the other way round, at the cost of a thread or a task per carrier.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use super::blocking::{Blocking, Closer, PipeIo, Session, Watchdog, run, spawn_pipe};
use super::handle::{self, Shared, WeakSession};
use crate::proto::VarInt;
use crate::proto::exporter::CarrierExporter;
use crate::proto::listener::{
    AdmissionStats, CarrierId, Classified, Entered, HandleError, ListenerConfig, ListenerCore,
    ListenerLimits, ListenerStats, RejectAction, RejectError, RejectInfo, Slot, random_locator,
};
use crate::proto::record::Framing;
use crate::proto::session::Config;

/// Where a carrier comes from.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipeHint {
    /// The carrier's source, for the per-source limit and the transform.
    pub source: Option<SocketAddr>,
}

type TransformFn = dyn Fn(PipeIo, &PipeHint) -> io::Result<PipeIo> + Send + Sync;

/// A listener's inbound transform: what every carrier passes through before its first
/// record is read, within the handshake timeout, enforced by the carrier's closer. A
/// `RejectError` goes to `on_reject`. Cheap to clone.
#[derive(Clone)]
pub struct InboundTransform(Arc<TransformFn>);

impl InboundTransform {
    /// The transform `f`.
    pub fn new(
        f: impl Fn(PipeIo, &PipeHint) -> io::Result<PipeIo> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(f))
    }
}

impl std::fmt::Debug for InboundTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InboundTransform(..)")
    }
}

#[derive(Default)]
struct Counts {
    sessions: AtomicU64,
    joins: AtomicU64,
    setup_failures: AtomicU64,
    rejected: AtomicU64,
    refused: AtomicU64,
    timed_out: AtomicU64,
    stall_overflow: AtomicU64,
}

struct State {
    core: ListenerCore,
    live: Vec<Weak<Shared<Blocking>>>,
    /// The length of `live` at which it is pruned next.
    live_prune: usize,
    accept: VecDeque<Session>,
    /// The closers of the carriers being set up: eviction and `close` end their calls.
    carriers: HashMap<CarrierId, Arc<Closer>>,
    /// The slots of stalled carriers evicted for a new carrier, until each saw it.
    evicted_slots: Vec<Slot>,
    /// The stalled carriers by slot: an eviction ends their setup at once.
    stalled: Vec<(Slot, CarrierId)>,
    closed: bool,
    draining: bool,
    /// The addresses `serve` accepts on, which `close` connects to so that
    /// a blocked accept returns.
    serving: Vec<SocketAddr>,
    /// The waits of carriers in setup on a host decision, a session's keys
    /// or a delay ([`Stopped`]), by key: woken by `close` and by their
    /// carrier's eviction; each leaves when it ends.
    stop_wakers: Vec<(u64, Option<CarrierId>, std::task::Waker)>,
    /// The key of the next [`Stopped`].
    stop_key: u64,
}

struct Inner {
    config: Arc<Config>,
    transform: Option<InboundTransform>,
    instance_id: Vec<u8>,
    /// The longest stall of a refused Establish, drawn.
    stall_max: Duration,
    st: Mutex<State>,
    /// The sessions by Locator.
    locators: handle::LocatorTable<Shared<Blocking>>,
    /// Wakes `accept` callers: a session queued, the listener closed.
    accepted: Condvar,
    /// Wakes stalled carriers: one evicted, the listener closed.
    stalls: Condvar,
    counts: Counts,
    /// The memory budget and suspended limit the sessions keep up to date
    /// (`super::account`), shared with the tokio listener's semantics.
    account: Arc<super::account::Account<Shared<Blocking>>>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ready once the listener closes or the carrier `id` (if any) is no
    /// longer in setup (evicted): what ends a carrier's waits, as on the
    /// tokio listener.
    fn stopped(&self, id: Option<CarrierId>) -> Stopped<'_> {
        Stopped {
            inner: self,
            id,
            key: None,
        }
    }
}

/// [`Inner::stopped`].
struct Stopped<'a> {
    inner: &'a Inner,
    id: Option<CarrierId>,
    /// Its entry in `stop_wakers` while registered.
    key: Option<u64>,
}

impl Future for Stopped<'_> {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let this = self.get_mut();
        let mut st = this.inner.lock();
        let gone = this.id.is_some_and(|id| !st.carriers.contains_key(&id));
        if st.closed || gone {
            if let Some(k) = this.key.take() {
                st.stop_wakers.retain(|e| e.0 != k);
            }
            return std::task::Poll::Ready(());
        }
        let found = this
            .key
            .and_then(|k| st.stop_wakers.iter_mut().find(|e| e.0 == k));
        if let Some(e) = found {
            e.2.clone_from(cx.waker());
        } else {
            let k = st.stop_key;
            st.stop_key += 1;
            st.stop_wakers.push((k, this.id, cx.waker().clone()));
            this.key = Some(k);
        }
        std::task::Poll::Pending
    }
}

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            self.inner.lock().stop_wakers.retain(|e| e.0 != k);
        }
    }
}

/// Wakes the waits [`Inner::stopped`] of carrier `id`, or all of them; they
/// stay registered until they end.
fn wake_stopped(st: &State, id: Option<CarrierId>) {
    for e in &st.stop_wakers {
        if id.is_none() || e.1 == id {
            e.2.wake_by_ref();
        }
    }
}

/// A listener for blocking sessions: hand it carriers with [`Listener::handle_pipe`], or a
/// socket with [`Listener::serve`], and take sessions with [`Listener::accept`]. Cheap to
/// clone. A carrier needs a closer for the timeouts to end a blocked call: `PipeIo::from_tcp`
/// has one, others take [`PipeIo::with_closer`]; one without is not taken
/// ([`HandleError::SetupFailed`]).
#[derive(Clone)]
pub struct Listener {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

/// A carrier's source slot and listener slot, from its arrival until it enters a
/// session or is closed; `None` once a new carrier evicted it while it stalled.
struct Held<'a> {
    inner: &'a Inner,
    slot: Option<Slot>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            self.inner.lock().core.release(slot);
        }
    }
}

/// Leaves the pending carriers however a carrier's setup ends.
struct Pending<'a> {
    inner: &'a Inner,
    id: CarrierId,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        let mut st = self.inner.lock();
        st.carriers.remove(&self.id);
        st.core.done(self.id);
    }
}

impl Listener {
    /// A listener of sessions of `config`. The admission, the fallback and the tokio
    /// transform of `limits` belong to the tokio driver's listener and must be unset.
    ///
    /// # Errors
    ///
    /// [`ConnectError::InvalidConfig`](crate::ConnectError::InvalidConfig) when one of
    /// them is set (it would silently not run), `config` is not valid, or
    /// `limits.instance_id` is too long.
    pub fn new(
        config: impl Into<Arc<Config>>,
        limits: ListenerConfig,
        transform: Option<InboundTransform>,
    ) -> Result<Self, crate::ConnectError> {
        Self::with_stall_max(
            config,
            limits,
            transform,
            crate::proto::admission::draw_stall_max(),
        )
    }

    /// [`Listener::new`] with the longest stall of a refused Establish.
    fn with_stall_max(
        config: impl Into<Arc<Config>>,
        limits: ListenerConfig,
        transform: Option<InboundTransform>,
        stall_max: Duration,
    ) -> Result<Self, crate::ConnectError> {
        use crate::ConnectError::InvalidConfig;
        if limits.admission.is_some() {
            return Err(InvalidConfig(crate::InvalidConfig::new(
                "ListenerConfig::admission",
                "the std driver's listener runs no admission",
            )));
        }
        #[cfg(feature = "tokio")]
        if limits.inbound_transform.is_some() || limits.fallback.is_some() {
            return Err(InvalidConfig(crate::InvalidConfig::new(
                "ListenerConfig::inbound_transform",
                "the std driver's listener runs no tokio transform or fallback",
            )));
        }
        limits.validate().map_err(InvalidConfig)?;
        let config = config.into();
        config.validate().map_err(InvalidConfig)?;
        let instance_id = limits.instance_id.clone();
        let account = super::account::Account::new(
            limits.limits.memory_budget,
            limits.on_memory_pressure.clone(),
            super::account::HookContext::Thread,
        )
        .ok_or_else(|| {
            InvalidConfig(crate::InvalidConfig::new(
                "ListenerConfig::on_memory_pressure",
                "its hook thread could not be started",
            ))
        })?;
        let inner = Arc::new(Inner {
            locators: handle::LocatorTable::default(),
            config,
            transform,
            instance_id,
            stall_max,
            st: Mutex::new(State {
                core: ListenerCore::new(limits),
                live: Vec::new(),
                live_prune: 16,
                accept: VecDeque::new(),
                carriers: HashMap::new(),
                stalled: Vec::new(),
                evicted_slots: Vec::new(),
                stop_wakers: Vec::new(),
                stop_key: 0,
                closed: false,
                draining: false,
                serving: Vec::new(),
            }),
            accepted: Condvar::new(),
            stalls: Condvar::new(),
            counts: Counts::default(),
            account,
        });
        let weak = Arc::downgrade(&inner);
        inner.account.bind_max_suspended(Box::new(move || {
            let i = weak.upgrade()?;
            let max = i.lock().core.config().limits.max_suspended;
            Some(max)
        }));
        Ok(Self { inner })
    }

    /// Takes a carrier: returns once it started a session or joined one, or was not used.
    /// The session's threads then own it.
    ///
    /// # Errors
    ///
    /// The [`HandleError`] that says why the carrier was not used; the carrier
    /// is closed.
    pub fn handle_pipe(&self, pipe: PipeIo, hint: PipeHint) -> Result<(), HandleError> {
        let r = self.handle(pipe, hint);
        if let Err(e) = r {
            let c = &self.inner.counts;
            match e {
                HandleError::Rejected => &c.rejected,
                HandleError::Refused => &c.refused,
                HandleError::TimedOut => &c.timed_out,
                HandleError::SetupFailed => &c.setup_failures,
                HandleError::NotAdmitted => return r,
            }
            .fetch_add(1, Relaxed);
        }
        r
    }

    fn handle(&self, mut pipe: PipeIo, hint: PipeHint) -> Result<(), HandleError> {
        let inner = &*self.inner;
        // A session cannot start on a thread that drives sessions (a tokio
        // runtime's, `spawn_blocking` included): a setup failure, before
        // anything is read, not a rejection of the peer.
        if super::context::on_driver_thread() {
            return Err(HandleError::SetupFailed);
        }
        // Without a closer no deadline could end a blocked read: a silent
        // carrier would hold its slot and thread for good. It is not taken.
        let Some(closer) = pipe.shared_closer() else {
            return Err(HandleError::SetupFailed);
        };
        // Its slots first, before anything is read: none, and it is closed at once.
        let (limits, id, slot, evicted) = {
            let mut st = inner.lock();
            let key = hint
                .source
                .map_or(0, |a| st.core.config().source_key(a.ip()));
            if st.closed {
                return Err(HandleError::Refused);
            }
            let (slot, evicted) = match st.core.enter(key) {
                Entered::Taken { slot, evicted } => {
                    if let Some(e) = evicted {
                        // Woken below, after the lock. Out of setup now, as
                        // on the tokio listener: its waits end.
                        st.evicted_slots.push(e);
                        if let Some(i) = st.stalled.iter().position(|s| s.0 == e) {
                            let (_, gone) = st.stalled.swap_remove(i);
                            st.carriers.remove(&gone);
                            wake_stopped(&st, Some(gone));
                        }
                    }
                    (slot, evicted.is_some())
                }
                Entered::SourceFull => return Err(HandleError::Refused),
                Entered::Full => return Err(HandleError::Rejected),
            };
            let limits = st.core.config().clone();
            let id = st.core.open(None, pipe.handshake_framing(), Instant::now());
            st.carriers.insert(id, closer.clone());
            (limits, id, slot, evicted)
        };
        // Only the stalled carriers wait for an eviction.
        if evicted {
            inner.stalls.notify_all();
        }
        let mut held = Held {
            inner,
            slot: Some(slot),
        };
        let pending = Pending { inner, id };
        // Without its watchdog a silent carrier would hold its slot and
        // thread for good: it is not taken.
        let watchdog = Watchdog::new(closer, limits.handshake_timeout)
            .map_err(|_| HandleError::SetupFailed)?;
        pipe.limit_handshake_wait(limits.handshake_timeout);
        if let Some(t) = &inner.transform {
            pipe = self.transform(
                t,
                (pipe, id),
                &hint,
                limits.handshake_timeout,
                &watchdog,
                &mut held,
            )?;
            inner.lock().core.set_framing(id, pipe.handshake_framing());
        }
        pipe.resolve_exporter(Instant::now().checked_add(limits.handshake_timeout));
        watchdog.reset(limits.limits.first_record_timeout);
        let classified = Self::first_record(inner, id, &mut pipe);
        if watchdog.fired() {
            return Err(HandleError::TimedOut);
        }
        watchdog.reset(limits.handshake_timeout);
        match classified {
            Classified::NewSession { first } => {
                self.start_session(pipe.with_prefix(first), hint, &watchdog)
            }
            Classified::Join { locator, hello } => self.join(
                pipe,
                (&locator, &hello),
                hint,
                &pending,
                &mut held,
                &watchdog,
            ),
            Classified::BadHello { reason } => {
                // Stalled, as every refused join, for the listener's join timeout.
                let info = RejectInfo::new(Some(2), None, reason, hint.source);
                self.reject_action(&info, id, inner.config.join_timeout, &mut held);
                Err(HandleError::Rejected)
            }
            // First bytes that are no carrier this listener knows (step 2).
            _ => {
                let info = RejectInfo::new(None, None, "malformed", hint.source);
                let limit = limits.handshake_timeout.min(inner.stall_max);
                self.reject_action(&info, id, limit, &mut held);
                Err(HandleError::Rejected)
            }
        }
    }

    fn transform(
        &self,
        t: &InboundTransform,
        (pipe, id): (PipeIo, CarrierId),
        hint: &PipeHint,
        timeout: Duration,
        watchdog: &Watchdog,
        held: &mut Held<'_>,
    ) -> Result<PipeIo, HandleError> {
        let kind = (pipe.has_reader(), pipe.has_writer());
        match t.0(pipe, hint) {
            Ok(io) if (io.has_reader(), io.has_writer()) == kind => Ok(io),
            Ok(_) => Err(HandleError::SetupFailed),
            Err(e) => {
                let inner = e.get_ref();
                let refused =
                    inner.and_then(|e| e.downcast_ref::<crate::proto::listener::Refused<PipeIo>>());
                // The carrier handed back stays open while it is stalled.
                let (reject, _held) = match refused {
                    Some(r) => (Some(&r.error), r.take_carrier()),
                    None => (inner.and_then(|e| e.downcast_ref::<RejectError>()), None),
                };
                let reject = reject.filter(|_| !watchdog.fired());
                let Some(r) = reject else {
                    return Err(HandleError::SetupFailed);
                };
                let info = RejectInfo::new(r.profile, r.record_mode, r.reason, hint.source);
                // The handshake timeout may be none: the stall ends by the
                // listener's maximum.
                self.reject_action(&info, id, timeout.min(self.inner.stall_max), held);
                Err(HandleError::Rejected)
            }
        }
    }

    /// The reject policy: closed, or stalled without a byte until `timeout`, the listener
    /// closes or a new carrier evicts it, keeping its slots; closed at once, counted as
    /// `stall_overflow`, when its source holds its maximum of stalls or the listener's
    /// stalls hold half of `max_pending`.
    fn reject_action(
        &self,
        info: &RejectInfo,
        id: CarrierId,
        timeout: Duration,
        held: &mut Held<'_>,
    ) {
        let (policy, logger) = {
            let st = self.inner.lock();
            (
                st.core.config().on_reject.clone(),
                st.core.config().logger.clone(),
            )
        };
        let action = match policy {
            None => RejectAction::default_for(info),
            Some(f) => {
                let deadline = Instant::now().checked_add(timeout);
                super::hooks::settle_blocking(f.ask(info), deadline, self.inner.stopped(Some(id)))
                    .flatten()
                    .unwrap_or_else(|| {
                        if let Some(l) = &logger {
                            l.log(
                                crate::LogLevel::Error,
                                "zmux: on_reject panicked or missed the handshake deadline; the carrier is closed",
                            );
                        }
                        RejectAction::Close
                    })
            }
        };
        if action == RejectAction::Stall {
            let Some(slot) = held.slot else {
                return;
            };
            let mut st = self.inner.lock();
            if st.closed || !st.core.stall(slot) {
                drop(st);
                self.inner.counts.stall_overflow.fetch_add(1, Relaxed);
                return;
            }
            st.stalled.push((slot, id));
            let until = Instant::now() + timeout;
            while !st.closed && !st.evicted_slots.contains(&slot) {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                st = self
                    .inner
                    .stalls
                    .wait_timeout(st, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            if !st.core.unstall(slot) {
                held.slot = None;
            }
            st.evicted_slots.retain(|&e| e != slot);
            st.stalled.retain(|s| s.0 != slot);
        }
    }

    fn first_record(inner: &Inner, id: CarrierId, pipe: &mut PipeIo) -> Classified {
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match pipe.read_handshake(&mut buf) {
                Ok(n) if n > 0 => {}
                _ => return Classified::Reject,
            }
            let mut st = inner.lock();
            let r = if pipe.handshake_framing() == Framing::Records {
                st.core.message(id, &buf, Instant::now())
            } else {
                st.core.data(id, &buf, Instant::now())
            };
            if r != Classified::NeedMore {
                return r;
            }
        }
    }

    fn session_config(&self, pipe: &PipeIo, hint: PipeHint) -> Result<Arc<Config>, HandleError> {
        let (chosen, logger) = {
            let st = self.inner.lock();
            (
                st.core.config().session_config.clone(),
                st.core.config().logger.clone(),
            )
        };
        let Some(f) = chosen else {
            return Ok(self.inner.config.clone());
        };
        let carrier = crate::SessionCarrier {
            source: hint.source,
            peer: hint.source,
            tls: None,
            admitted: pipe.admitted_value().cloned(),
        };
        let handshake = self.inner.lock().core.config().handshake_timeout;
        let answer = super::hooks::settle_blocking(
            f.ask(&carrier),
            Instant::now().checked_add(handshake),
            self.inner.stopped(None),
        )
        .flatten();
        match crate::SessionConfigFn::chosen(answer, logger.as_ref()) {
            Ok(None) => Ok(self.inner.config.clone()),
            Ok(Some(c)) => Ok(Arc::new(c)),
            Err(()) => Err(HandleError::Rejected),
        }
    }

    fn start_session(
        &self,
        pipe: PipeIo,
        hint: PipeHint,
        watchdog: &Watchdog,
    ) -> Result<(), HandleError> {
        let inner = &*self.inner;
        let config = self.session_config(&pipe, hint)?;
        let own = (config.offers_multipath() && config.own_locator().is_empty())
            .then(|| random_locator(&inner.instance_id));
        let mut created = None;
        let session = Session::listened(pipe, config, own.as_deref(), |shared| {
            created = Some(Arc::downgrade(shared));
            let locator = shared.lock().core.local_locator().to_vec();
            {
                // The Locators an epoch adds and deletes follow in the table.
                let listener = Arc::downgrade(&self.inner);
                let session = Arc::downgrade(shared);
                let mut held = vec![locator.clone()];
                let mut s = shared.lock();
                s.core.set_locator_instance(inner.instance_id.len());
                s.locator_hook = Some(Box::new(move |now: &[Vec<u8>]| {
                    let Some(l) = listener.upgrade() else {
                        return;
                    };
                    l.locators.replace(&held, now, &session);
                    held = now.to_vec();
                }));
            }
            shared.lock().io.account = Some(Box::new(super::account::AccountLink::new(
                inner.account.clone(),
            )));
            let mut st = inner.lock();
            // Ended sessions are pruned once the list doubled since the
            // last pruning: amortized, as the tokio listener does.
            if st.live.len() >= st.live_prune {
                st.live.retain(|w| w.strong_count() > 0);
                st.live_prune = (st.live.len() * 2).max(16);
            }
            st.live.push(Arc::downgrade(shared));
            if !locator.is_empty() {
                inner.locators.insert(locator, Arc::downgrade(shared));
            }
        })
        .map_err(|_| HandleError::Rejected)?;
        // Established: the watchdog no longer closes the carrier, which the
        // session owns now (N11).
        watchdog.disarm();
        if watchdog.fired() {
            return Err(HandleError::TimedOut);
        }
        let mut st = inner.lock();
        let closing = st.closed || st.draining;
        let refusal = st
            .core
            .admit_session(closing, inner.account.pressure())
            .err();
        if let Some(reason) = refusal {
            drop(st);
            // Refused after its own parameters, so that the peer reads why.
            if let Some(shared) = created.and_then(|w| w.upgrade()) {
                let limit = inner.lock().core.config().handshake_timeout;
                run(shared.refuse(reason), Instant::now().checked_add(limit));
            }
            drop(session);
            return Err(HandleError::Refused);
        }
        // The queued session holds the place until it is taken.
        st.accept.push_back(session);
        inner.counts.sessions.fetch_add(1, Relaxed);
        drop(st);
        inner.accepted.notify_all();
        Ok(())
    }

    /// The acceptor's processing of a Hello from its Locator lookup to Confirmed, and the session's
    /// threads on the carrier.
    fn join(
        &self,
        mut pipe: PipeIo,
        (locator, hello): (&[u8], &[u8]),
        hint: PipeHint,
        pending: &Pending<'_>,
        held: &mut Held<'_>,
        watchdog: &Watchdog,
    ) -> Result<(), HandleError> {
        use super::accept::{AcceptStep, JoinAccept, JoinCarrier};
        let inner = &*self.inner;
        let framing = pipe.handshake_framing();
        // A Hello in Bound needs a Binding of this carrier (see the tokio listener).
        let binding = (pipe.is_secure() && !pipe.is_split())
            .then(|| pipe.exporter_ref().and_then(CarrierExporter::pipe_binding))
            .flatten();
        let carrier = JoinCarrier {
            framing,
            binding,
            has_exporter: pipe.exporter_ref().is_some(),
            secure: pipe.is_secure(),
            admitted: pipe.admitted_value().cloned(),
            inbound: pipe.has_reader(),
            outbound: pipe.has_writer(),
            looped: false,
            overhead: pipe.overhead(),
            max_record: pipe.record_limit(),
            kind: pipe.carrier(),
            reports_failure: pipe.reports_failure,
        };
        let session = inner.locators.get(locator);
        let mut acc = JoinAccept::new(session, inner.config.join_timeout, hello, carrier);
        let deadline = acc.deadline();
        // The carrier's reads and writes end at the join's deadline, as the
        // tokio listener's do: the watchdog moves to it.
        watchdog.reset(deadline.map_or(Duration::MAX, |d| {
            d.saturating_duration_since(Instant::now())
        }));
        let timed_out = || watchdog.fired();
        let stopped = || inner.stopped(Some(pending.id));
        let open = |acc: &mut JoinAccept<Blocking>, ready: Option<bool>| {
            // Closed, or evicted for a newer carrier while it waited.
            let gone = {
                let st = inner.lock();
                st.closed || !st.carriers.contains_key(&pending.id)
            };
            if gone {
                return AcceptStep::End(HandleError::Refused);
            }
            let pressure = inner.account.pressure();
            match ready {
                None => acc.start(pressure),
                Some(r) => acc.keys_ready(r, pressure),
            }
        };
        let mut step = open(&mut acc, None);
        let reply = loop {
            step = match step {
                // A stall lasts the listener's join timeout from the refusal, whether
                // or not the Locator names a session: the response and the way of
                // ending are the same.
                AcceptStep::Reject(reason, mode) => {
                    let info = RejectInfo::new(Some(2), mode, reason, hint.source);
                    self.reject_action(&info, pending.id, inner.config.join_timeout, held);
                    return Err(HandleError::Rejected);
                }
                AcceptStep::End(e) => return Err(e),
                AcceptStep::WaitKeys => {
                    let session = acc.session().expect("named").clone();
                    match run(
                        super::hooks::first(stopped(), handle::join_keys_wait(&session)),
                        deadline,
                    ) {
                        Some(Some(ready)) => open(&mut acc, Some(ready)),
                        Some(None) => AcceptStep::End(HandleError::Refused),
                        None => AcceptStep::End(HandleError::TimedOut),
                    }
                }
                AcceptStep::Ask(d) => {
                    let session = acc.session().expect("named").clone();
                    let either =
                        super::hooks::first(stopped(), handle::session_ended_wait(&session));
                    let ended = async move {
                        let _ = either.await;
                    };
                    acc.allowed(super::hooks::settle_blocking(d, deadline, ended) == Some(true))
                }
                AcceptStep::Delay(delay) => {
                    let session = acc.session().expect("named").clone();
                    let until = Instant::now().checked_add(delay);
                    let end = match (until, deadline) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    };
                    if run(
                        super::hooks::first(stopped(), handle::session_ended_wait(&session)),
                        end,
                    )
                    .is_some()
                    {
                        acc.delayed(false)
                    } else if deadline.is_some_and(|d| Instant::now() >= d) {
                        AcceptStep::End(HandleError::TimedOut)
                    } else {
                        acc.delayed(true)
                    }
                }
                AcceptStep::Refuse(reply) => {
                    // The Reply ends with a graceful end of the writing half, so that
                    // the joiner sees the refusal.
                    if pipe.write_handshake(&reply).is_ok() {
                        pipe.shutdown_write();
                    }
                    return Err(HandleError::Refused);
                }
                AcceptStep::Reply(reply) => break reply,
            };
        };
        let session = acc.session().expect("named").clone();
        {
            let mut st = inner.lock();
            let evicted = st.core.unconfirmed(pending.id, locator).and_then(|e| {
                wake_stopped(&st, Some(e));
                st.carriers.remove(&e)
            });
            drop(st);
            if let Some(c) = evicted {
                c(Shutdown::Both);
            }
        }
        let outcome = |e: HandleError| {
            if timed_out() {
                HandleError::TimedOut
            } else {
                e
            }
        };
        pipe.write_handshake(&reply)
            .map_err(|_| outcome(HandleError::Rejected))?;
        let mut input = Vec::new();
        let rest = loop {
            match acc.confirm(&mut input) {
                Ok(true) => break input,
                Ok(false) => {}
                Err(()) => return Err(HandleError::Rejected),
            }
            match pipe.read_handshake(&mut input) {
                Ok(n) if n > 0 => {}
                _ => return Err(outcome(HandleError::Rejected)),
            }
        };
        let super::accept::Attached {
            pipe: attached,
            records,
            want_in,
            want_out,
        } = acc.attach()?;
        // Attached: the watchdog no longer closes the carrier.
        watchdog.disarm();
        let mut io = pipe.with_prefix(rest);
        if let Some((s, o)) = records {
            io = io.seal_records(s, o);
        }
        io.keep_directions(want_in, want_out);
        if let Some(m) = io.record_limit() {
            let mut st = session.lock();
            // Fits: checked against the join's mode before it was confirmed.
            if st.core.set_pipe_max_record(attached, m).is_err() {
                st.core.abandon_pipe_for_limit(attached, Instant::now());
                st.after_command();
                return Err(HandleError::Refused);
            }
            st.core.set_pipe_write_overhead(attached, io.overhead());
        }
        if spawn_pipe(&session, attached.0, io).is_err() {
            let mut st = session.lock();
            st.core.abandon_pipe_for_limit(attached, Instant::now());
            st.after_command();
            return Err(HandleError::Refused);
        }
        inner.counts.joins.fetch_add(1, Relaxed);
        Ok(())
    }

    /// The next session; `None` once the listener is closed.
    #[must_use]
    pub fn accept(&self) -> Option<Session> {
        // Without a deadline it never times out.
        self.accept_until(None).unwrap_or(None)
    }

    /// [`accept`](Listener::accept), waiting at most `timeout`
    /// ([`WaitError::TimedOut`](super::blocking::WaitError::TimedOut)).
    ///
    /// # Errors
    ///
    /// [`WaitError::TimedOut`](super::blocking::WaitError::TimedOut) when no
    /// session arrived and the listener did not close within `timeout`.
    pub fn accept_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<Session>, super::blocking::WaitError<std::convert::Infallible>> {
        self.accept_until(Instant::now().checked_add(timeout))
            .map_err(|()| super::blocking::WaitError::TimedOut)
    }

    /// The next session; `Err` once `until` passed.
    fn accept_until(&self, until: Option<Instant>) -> Result<Option<Session>, ()> {
        let mut st = self.inner.lock();
        loop {
            if let Some(s) = st.accept.pop_front() {
                st.core.release_unaccepted();
                return Ok(Some(s));
            }
            if st.closed || st.draining {
                return Ok(None);
            }
            st = match until {
                Some(u) => {
                    let left = u.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(());
                    }
                    self.inner
                        .accepted
                        .wait_timeout(st, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => self
                    .inner
                    .accepted
                    .wait(st)
                    .unwrap_or_else(PoisonError::into_inner),
            };
        }
    }

    /// Accepts on `tcp`, one thread per carrier, until the listener closes.
    ///
    /// # Errors
    ///
    /// Only the error of setting `tcp` non-blocking; accept errors are
    /// waited out.
    pub fn serve(&self, tcp: &TcpListener) -> io::Result<()> {
        // Blocking accepts: `close` wakes a waiting one with a connection of
        // its own to the socket's address.
        tcp.set_nonblocking(false)?;
        let mut wake = tcp.local_addr()?;
        if wake.ip().is_unspecified() {
            wake.set_ip(match wake {
                SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
                SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
            });
        }
        {
            let mut st = self.inner.lock();
            if st.closed {
                return Ok(());
            }
            st.serving.push(wake);
        }
        let served = self.accept_loop(tcp);
        self.inner.lock().serving.retain(|a| *a != wake);
        served
    }

    fn accept_loop(&self, tcp: &TcpListener) -> io::Result<()> {
        loop {
            let accepted = tcp.accept();
            if self.inner.lock().closed {
                return Ok(());
            }
            match accepted {
                Ok((stream, peer)) => {
                    let l = self.clone();
                    let spawned =
                        thread::Builder::new()
                            .name("zmux-carrier".into())
                            .spawn(move || {
                                let hint = PipeHint { source: Some(peer) };
                                let _ = l.handle_pipe(PipeIo::from_tcp(stream), hint);
                            });
                    if spawned.is_err() {
                        thread::sleep(super::ACCEPT_BACKOFF);
                    }
                }
                // Out of descriptors and the like pass; only closing ends the loop.
                Err(e) => {
                    if super::accept_backs_off(&e) {
                        thread::sleep(super::ACCEPT_BACKOFF);
                    }
                }
            }
        }
    }

    /// Closes: `accept` returns `None`, carriers in setup are shut down, sessions not
    /// accepted are closed. Sessions accepted go on.
    pub fn close(&self) {
        let mut st = self.inner.lock();
        st.closed = true;
        wake_stopped(&st, None);
        let carriers: Vec<_> = st.carriers.drain().map(|(_, c)| c).collect();
        let unaccepted = std::mem::take(&mut st.accept);
        for _ in 0..unaccepted.len() {
            st.core.release_unaccepted();
        }
        let serving = std::mem::take(&mut st.serving);
        drop(st);
        self.inner.accepted.notify_all();
        self.inner.stalls.notify_all();
        for c in carriers {
            c(Shutdown::Both);
        }
        drop(unaccepted);
        // A serving loop blocked in accept sees the close with this
        // connection, which it drops.
        for a in serving {
            let _ = TcpStream::connect_timeout(&a, Duration::from_secs(1));
        }
    }

    /// Closes gracefully: new sessions are refused while joins go on, every session is
    /// shut down with `code` and `reason`, all at once, and once they all ended the
    /// listener closes. Unbounded: see [`Listener::shutdown_timeout`].
    pub fn shutdown(&self, code: VarInt, reason: &[u8]) {
        self.shutdown_until(code, reason, None);
    }

    /// [`Listener::shutdown`] within `timeout` in all: the sessions that did not
    /// end by then are aborted with `code` and `reason`, and the listener closes.
    pub fn shutdown_timeout(&self, code: VarInt, reason: &[u8], timeout: Duration) {
        self.shutdown_until(code, reason, Instant::now().checked_add(timeout));
    }

    fn shutdown_until(&self, code: VarInt, reason: &[u8], until: Option<Instant>) {
        let (live, unaccepted) = {
            let mut st = self.inner.lock();
            st.draining = true;
            let live: Vec<_> = st
                .live
                .iter()
                .filter_map(|w| WeakSession::from_weak(w.clone()).upgrade())
                .collect();
            let unaccepted = std::mem::take(&mut st.accept);
            for _ in 0..unaccepted.len() {
                st.core.release_unaccepted();
            }
            (live, unaccepted)
        };
        self.inner.accepted.notify_all();
        drop(unaccepted);
        // Every session's GOAWAY goes out at once; one peer that does not
        // answer holds back no other session.
        let mut shutdowns: Vec<_> = live
            .iter()
            .map(|s| Some(Box::pin(s.shutdown_op(code, reason))))
            .collect();
        let all = std::future::poll_fn(|cx| {
            let mut left = false;
            for slot in &mut shutdowns {
                if let Some(f) = slot {
                    if f.as_mut().poll(cx).is_ready() {
                        *slot = None;
                    } else {
                        left = true;
                    }
                }
            }
            if left {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        });
        if run(all, until).is_none() {
            for (s, f) in live.iter().zip(&shutdowns) {
                if f.is_some() {
                    s.abort_op(code, reason);
                }
            }
        }
        drop(shutdowns);
        self.close();
    }

    /// The listener's operations for own accept loops
    /// ([`ListenerAdapter`]).
    #[must_use]
    pub fn adapter(&self) -> ListenerAdapter<'_> {
        ListenerAdapter { listener: self }
    }

    /// The limits in effect ([`Listener::set_limits`]).
    #[must_use]
    pub fn limits(&self) -> ListenerLimits {
        self.inner.lock().core.config().limits
    }

    /// Replaces the listener's limits, as the tokio listener's
    /// [`crate::Listener::set_limits`] says.
    ///
    /// # Errors
    ///
    /// Invalid limits, as [`ListenerLimits::validate`] says.
    pub fn set_limits(&self, limits: ListenerLimits) -> Result<(), crate::InvalidConfig> {
        // Trimmed under the listener's lock (then the account's), so that
        // no suspension slips past the new limit; closed after it.
        let over = {
            let mut st = self.inner.lock();
            st.core.set_limits(limits)?;
            let mut over = self.inner.account.set_budget(limits.memory_budget);
            over.extend(self.inner.account.trim_to(limits.max_suspended));
            over
        };
        for s in over {
            s.close_suspended();
        }
        Ok(())
    }

    /// What happened to the carriers handed to the listener.
    #[must_use]
    pub fn stats(&self) -> ListenerStats {
        let c = &self.inner.counts;
        ListenerStats {
            sessions: c.sessions.load(Relaxed),
            joins: c.joins.load(Relaxed),
            setup_failures: c.setup_failures.load(Relaxed),
            rejected: c.rejected.load(Relaxed),
            refused: c.refused.load(Relaxed),
            timed_out: c.timed_out.load(Relaxed),
            admission: AdmissionStats {
                stall_overflow: c.stall_overflow.load(Relaxed),
                ..AdmissionStats::default()
            },
        }
    }
}

/// The operations of a blocking [`Listener`] that only own accept loops
/// use ([`Listener::adapter`]).
#[derive(Debug, Clone, Copy)]
pub struct ListenerAdapter<'a> {
    listener: &'a Listener,
}

impl ListenerAdapter<'_> {
    /// Counts a connection that an accept loop could not make a pipe input
    /// of: a failed TLS handshake or its timeout, a failed upgrade, or the
    /// setup limit ([`ListenerStats::setup_failures`]); such a connection
    /// is counted nowhere else.
    pub fn count_setup_failure(&self) {
        self.listener
            .inner
            .counts
            .setup_failures
            .fetch_add(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use crate::ListenerLimits;
    use std::io::Read;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    use super::{InboundTransform, Listener, PipeHint};
    use crate::driver::blocking::PipeIo;
    use crate::proto::listener::{HandleError, ListenerConfig, Refused, RejectError};
    use crate::proto::session::Config;

    /// A listener whose transform refuses every carrier as an Establish of `profile`,
    /// handing the carrier back, with this maximum stall.
    fn refusing(profile: u64, limits: ListenerConfig, stall_max: Duration) -> Listener {
        let t = InboundTransform::new(move |p, _| {
            Err(Refused::error(
                RejectError::new(Some(profile), None, "auth"),
                p,
            ))
        });
        Listener::with_stall_max(Config::default(), limits, Some(t), stall_max).unwrap()
    }

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    fn from(port: u16) -> PipeHint {
        PipeHint {
            source: Some(SocketAddr::from(([192, 0, 2, 1], port))),
        }
    }

    /// The client's end reads nothing and then the end of the carrier.
    fn closed_silently(mut client: TcpStream) {
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0; 16];
        assert_eq!(client.read(&mut buf).unwrap(), 0);
    }

    /// Without `on_reject`, a refused Establish is stalled until the handshake timeout,
    /// never beyond the listener's maximum stall; a refused Join is closed at once.
    #[test]
    fn a_refused_establish_stalls_at_most_the_handshake_timeout_and_the_stall_max() {
        for (timeout, stall_max, want) in [
            (Duration::from_millis(300), Duration::from_secs(30), 300),
            (Duration::from_secs(10), Duration::from_millis(300), 300),
        ] {
            let limits = ListenerConfig {
                handshake_timeout: timeout,
                ..Default::default()
            };
            let l = refusing(1, limits, stall_max);
            let (client, server) = pair();
            let begun = Instant::now();
            let r = l.handle_pipe(PipeIo::from_tcp(server), from(1));
            let took = begun.elapsed();
            assert_eq!(r, Err(HandleError::Rejected));
            assert!(took >= Duration::from_millis(want - 10), "{took:?}");
            // A guard against a hang only: three stalls and a second.
            assert!(took < Duration::from_millis(3 * want + 1000), "{took:?}");
            closed_silently(client);
        }
        // Judged by the stall count, not elapsed time: with an hour to stall, a Join
        // that was stalled shows in its source's count while it waits.
        let hour = Duration::from_secs(3600);
        let limits = ListenerConfig {
            handshake_timeout: hour,
            ..Default::default()
        };
        let l = refusing(2, limits, hour);
        let key = ListenerConfig::default().source_key([192, 0, 2, 1].into());
        let (client, server) = pair();
        let lj = l.clone();
        let join = std::thread::spawn(move || lj.handle_pipe(PipeIo::from_tcp(server), from(1)));
        while !join.is_finished() {
            assert_eq!(
                l.inner.lock().core.stalled(key).1,
                0,
                "the Join was stalled"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(join.join().unwrap(), Err(HandleError::Rejected));
        closed_silently(client);
    }

    /// A source keeps a slot for a new attempt: with `max_pending_per_source` 2 it stalls
    /// one carrier, and the next refused one from it is closed at once; another source
    /// still stalls. `close` ends the stalls.
    ///
    /// Judged by the stall counts, not by elapsed time: the stalls last an hour, so a
    /// carrier that returns before `close` was not stalled, and one that was stalled
    /// shows in its source's count while it waits.
    #[test]
    fn a_source_with_its_stalls_full_is_closed_at_once() {
        let hour = Duration::from_secs(3600);
        let limits = ListenerConfig {
            limits: ListenerLimits {
                max_pending_per_source: 2,
                ..ListenerLimits::default()
            },
            handshake_timeout: hour,
            ..Default::default()
        };
        let l = refusing(1, limits, hour);
        let stalled = |key| l.inner.lock().core.stalled(key).1;
        let key = ListenerConfig::default().source_key([192, 0, 2, 1].into());
        let other_addr = SocketAddr::from(([198, 51, 100, 1], 3));
        let other_key = ListenerConfig::default().source_key(other_addr.ip());
        let (c1, s1) = pair();
        let l1 = l.clone();
        let first = std::thread::spawn(move || l1.handle_pipe(PipeIo::from_tcp(s1), from(1)));
        let (c3, s3) = pair();
        let l3 = l.clone();
        let other = std::thread::spawn(move || {
            let hint = PipeHint {
                source: Some(other_addr),
            };
            l3.handle_pipe(PipeIo::from_tcp(s3), hint)
        });
        // Both are stalled once their sources hold a stall.
        while stalled(key) == 0 || stalled(other_key) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        let (c2, s2) = pair();
        let l2 = l.clone();
        let second = std::thread::spawn(move || l2.handle_pipe(PipeIo::from_tcp(s2), from(2)));
        // Stalled, it would count a second stall of its source while it waits.
        while !second.is_finished() {
            assert_eq!(stalled(key), 1, "the second carrier was stalled");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(second.join().unwrap(), Err(HandleError::Rejected));
        closed_silently(c2);
        assert_eq!((stalled(key), stalled(other_key)), (1, 1));
        assert!(!first.is_finished() && !other.is_finished());
        l.close();
        assert_eq!(first.join().unwrap(), Err(HandleError::Rejected));
        assert_eq!(other.join().unwrap(), Err(HandleError::Rejected));
        assert_eq!((stalled(key), stalled(other_key)), (0, 0));
        closed_silently(c1);
        closed_silently(c3);
    }

    /// A carrier from a source that holds its share is closed at once, before anything is
    /// read, without the reject policy, and counted as refused.
    #[test]
    fn a_carrier_over_its_source_limit_is_closed_at_once() {
        use crate::proto::listener::{OnReject, RejectAction};
        let reasons = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = reasons.clone();
        let limits = ListenerConfig {
            limits: ListenerLimits {
                first_record_timeout: Duration::from_secs(3600),
                max_pending_per_source: 3,
                ..ListenerLimits::default()
            },
            handshake_timeout: Duration::from_secs(3600),
            on_reject: Some(OnReject::new(move |i| {
                seen.lock().unwrap().push((i.profile, i.reason));
                RejectAction::Stall
            })),
            ..Default::default()
        };
        let l = Listener::new(Config::default(), limits, None).unwrap();
        let key = ListenerConfig::default().source_key([192, 0, 2, 1].into());
        let mut held = Vec::new();
        for port in 1..=3 {
            let (c, s) = pair();
            let lh = l.clone();
            held.push((
                c,
                std::thread::spawn(move || lh.handle_pipe(PipeIo::from_tcp(s), from(port))),
            ));
        }
        let end = Instant::now() + Duration::from_secs(5);
        while l.inner.lock().core.held(key).1 < 3 {
            assert!(Instant::now() < end, "the carriers never took their slots");
            std::thread::sleep(Duration::from_millis(2));
        }
        let (c, s) = pair();
        assert_eq!(
            l.handle_pipe(PipeIo::from_tcp(s), from(4)),
            Err(HandleError::Refused)
        );
        closed_silently(c);
        assert!(reasons.lock().unwrap().is_empty());
        assert_eq!(l.stats().refused, 1);
        l.close();
        for (c, t) in held {
            drop(c);
            let _ = t.join().unwrap();
        }
    }

    /// With /24 and /56 source prefixes, addresses of one prefix share the per-source
    /// bound and addresses of another prefix do not; 0 and values past the family's
    /// length are the configuration error.
    #[test]
    fn source_prefixes_aggregate_the_per_source_bound() {
        for bad in [(0, 64), (33, 64), (32, 0), (32, 129)] {
            let limits = ListenerConfig {
                source_prefix_v4: bad.0,
                source_prefix_v6: bad.1,
                ..Default::default()
            };
            assert!(Listener::new(Config::default(), limits, None).is_err());
        }
        let limits = ListenerConfig {
            limits: ListenerLimits {
                first_record_timeout: Duration::from_secs(3600),
                max_pending_per_source: 2,
                ..ListenerLimits::default()
            },
            handshake_timeout: Duration::from_secs(3600),
            source_prefix_v4: 24,
            source_prefix_v6: 56,
            ..Default::default()
        };
        let l = Listener::new(Config::default(), limits.clone(), None).unwrap();
        let at = |ip: &str| PipeHint {
            source: Some(SocketAddr::new(ip.parse().unwrap(), 4000)),
        };
        for (a, b, same, other) in [
            ("192.0.2.1", "192.0.2.77", "192.0.2.200", "192.0.3.1"),
            (
                "2001:db8:0:a1::1",
                "2001:db8:0:a2::1",
                "2001:db8:0:ff::1",
                "2001:db8:0:1a1::1",
            ),
        ] {
            let key = limits.source_key(a.parse().unwrap());
            let mut held = Vec::new();
            for ip in [a, b] {
                let (c, s) = pair();
                let (lh, hint) = (l.clone(), at(ip));
                held.push((
                    c,
                    std::thread::spawn(move || lh.handle_pipe(PipeIo::from_tcp(s), hint)),
                ));
            }
            let end = Instant::now() + Duration::from_secs(5);
            while l.inner.lock().core.held(key).1 < 2 {
                assert!(Instant::now() < end, "the carriers never took their slots");
                std::thread::sleep(Duration::from_millis(2));
            }
            // A third address of the prefix: its share is taken.
            let (c, s) = pair();
            assert_eq!(
                l.handle_pipe(PipeIo::from_tcp(s), at(same)),
                Err(HandleError::Refused)
            );
            closed_silently(c);
            // Another prefix has its own share.
            let (c, s) = pair();
            let (lh, hint) = (l.clone(), at(other));
            held.push((
                c,
                std::thread::spawn(move || lh.handle_pipe(PipeIo::from_tcp(s), hint)),
            ));
            let other_key = limits.source_key(other.parse().unwrap());
            while l.inner.lock().core.held(other_key).1 < 1 {
                assert!(Instant::now() < end, "the other prefix was refused");
                std::thread::sleep(Duration::from_millis(2));
            }
            for (c, t) in held {
                drop(c);
                let _ = t.join().unwrap();
            }
        }
        assert_eq!(l.stats().refused, 2);
        l.close();
    }

    /// A waker that records it was woken.
    #[derive(Default)]
    struct Flag(std::sync::atomic::AtomicBool);

    impl std::task::Wake for Flag {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The listener's bound: stalls hold at most half of it (beyond, `stall_overflow`); a
    /// new carrier with every slot taken evicts the oldest stall, and is closed at once,
    /// counted as rejected, when none is stalled.
    #[test]
    fn the_global_bound_evicts_the_oldest_stall() {
        use crate::proto::listener::{OnReject, RejectAction};
        use std::io::Write;
        let hour = Duration::from_secs(3600);
        let limits = ListenerConfig {
            limits: ListenerLimits {
                first_record_timeout: hour,
                max_pending: Some(2),
                ..ListenerLimits::default()
            },
            handshake_timeout: hour,
            on_reject: Some(OnReject::new(|_| RejectAction::Stall)),
            ..Default::default()
        };
        let l = Listener::with_stall_max(Config::default(), limits, None, hour).unwrap();
        let total = |l: &Listener| l.inner.lock().core.held(0).0;
        let stalls = |l: &Listener| l.inner.lock().core.stalled(0).0;
        let wait = |what: &str, f: &dyn Fn() -> bool| {
            let end = Instant::now() + Duration::from_secs(5);
            while !f() {
                assert!(Instant::now() < end, "{what}");
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        let garbage = |port: u16| {
            let (mut c, s) = pair();
            c.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
            let lh = l.clone();
            let t = std::thread::spawn(move || lh.handle_pipe(PipeIo::from_tcp(s), from(port)));
            (c, t)
        };
        let silent = |port: u16| {
            let (c, s) = pair();
            let lh = l.clone();
            let t = std::thread::spawn(move || lh.handle_pipe(PipeIo::from_tcp(s), from(port)));
            (c, t)
        };
        let (c1, t1) = garbage(1);
        wait("the first is stalled", &|| stalls(&l) == 1);
        // A wait of the stalled carrier ends with its eviction.
        let first = *l.inner.lock().carriers.keys().next().unwrap();
        let woken = std::sync::Arc::new(Flag::default());
        let waker = std::task::Waker::from(woken.clone());
        let mut stopped = std::pin::pin!(l.inner.stopped(Some(first)));
        let cx = &mut std::task::Context::from_waker(&waker);
        assert!(stopped.as_mut().poll(cx).is_pending());
        // Half of 2 is stalled: the next is closed at once.
        let (c2, t2) = garbage(2);
        assert_eq!(t2.join().unwrap(), Err(HandleError::Rejected));
        closed_silently(c2);
        assert_eq!(l.stats().admission.stall_overflow, 1);
        let (c3, t3) = silent(3);
        wait("the second slot is taken", &|| total(&l) == 2);
        // Every slot taken: the stall goes.
        let (c4, t4) = silent(4);
        wait("the evicted carrier's wait is woken", &|| {
            woken.0.load(std::sync::atomic::Ordering::SeqCst)
        });
        assert!(stopped.as_mut().poll(cx).is_ready());
        assert_eq!(t1.join().unwrap(), Err(HandleError::Rejected));
        closed_silently(c1);
        wait("the new carrier holds the slot", &|| total(&l) == 2);
        assert_eq!(stalls(&l), 0);
        // None stalled: the new one is closed at once.
        let rejected = l.stats().rejected;
        let (c5, s5) = pair();
        assert_eq!(
            l.handle_pipe(PipeIo::from_tcp(s5), from(5)),
            Err(HandleError::Rejected)
        );
        closed_silently(c5);
        assert_eq!(l.stats().rejected, rejected + 1);
        l.close();
        for (c, t) in [(c3, t3), (c4, t4)] {
            drop(c);
            let _ = t.join().unwrap();
        }
        assert_eq!(total(&l), 0);
    }

    /// A draining listener refuses a new session with `CONNECTION_REFUSED` after its own
    /// parameters, so that the peer reads why, as the tokio and Go listeners.
    #[test]
    fn a_draining_listener_refuses_with_connection_refused() {
        let l = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        l.inner.lock().draining = true;
        let (c, s) = pair();
        let client = std::thread::spawn(move || {
            match crate::driver::blocking::Session::connect(PipeIo::from_tcp(c), Config::default())
            {
                Ok(s) => s.closing_timeout(Duration::from_secs(5)).unwrap(),
                Err(super::super::blocking::WaitError::Failed(
                    crate::ConnectError::SessionLost(e),
                )) => e,
                Err(e) => panic!("not refused: {e:?}"),
            }
        });
        assert_eq!(
            l.handle_pipe(PipeIo::from_tcp(s), PipeHint::default()),
            Err(HandleError::Refused)
        );
        match client.join().unwrap() {
            crate::SessionError::TransportClosed {
                code, remote: true, ..
            } => assert_eq!(code, crate::proto::TransportErrorCode::CONNECTION_REFUSED),
            other => panic!("not refused: {other:?}"),
        }
        assert_eq!(l.stats().refused, 1);
    }

    /// An accept loop's setup failures are counted, as with the tokio listener.
    #[test]
    fn setup_failures_are_counted() {
        let l = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        l.adapter().count_setup_failure();
        l.adapter().count_setup_failure();
        assert_eq!(l.stats().setup_failures, 2);
    }
}
