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
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use super::blocking::{
    Blocking, Closer, PipeIo, Session, Watchdog, run, spawn_pipe, wait_in_domain,
};
use super::handle::{self, Driver, Shared};
use super::setup::{Authority, CommitError, ListenerLock, Setup, SlotTable, Transfer};
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
    common: super::setup::ListenerCounts,
    stall_overflow: AtomicU64,
}

struct State {
    core: ListenerCore,
    live: super::setup::Sessions<Blocking>,
    accept: VecDeque<Session>,
    /// The closers of the carriers being set up: eviction and `close` end their calls.
    carriers: HashMap<CarrierId, Arc<Closer>>,
    /// The slots of stalled carriers evicted for a new carrier, until each saw it.
    evicted_slots: Vec<Slot>,
    /// The stalled carriers by slot: an eviction ends their setup at once.
    stalled: Vec<(Slot, CarrierId)>,
    closed: bool,
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

type CarrierSetup = Setup<Authority<Inner>, PipeIo>;

struct Inner {
    config: Arc<Config>,
    transform: Option<InboundTransform>,
    instance_id: Vec<u8>,
    /// The longest stall of a refused Establish, drawn.
    stall_max: Duration,
    st: Mutex<State>,
    /// The sessions by Locator.
    locators: Arc<handle::LocatorTable<Shared<Blocking>>>,
    /// Wakes `accept` callers: a session queued, the listener closed.
    accepted: Condvar,
    counts: Counts,
    /// The memory budget and suspended limit the sessions keep up to date
    /// (`super::account`), shared with the tokio listener's semantics.
    account: Arc<super::account::Account<Shared<Blocking>>>,
}

impl Inner {
    fn lock(&self) -> ListenerLock<'_, State> {
        self.st
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .into()
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
fn wake_stopped(st: &State, id: Option<CarrierId>, wakes: &mut super::wake::WakeList) {
    for e in &st.stop_wakers {
        if id.is_none() || e.1 == id {
            wakes.push(e.2.clone());
        }
    }
}

/// A listener for blocking sessions: hand it carriers with [`Listener::handle_pipe`], or a
/// socket with [`Listener::serve`], and take sessions with [`Listener::accept`]. Cheap to
/// clone. A carrier needs a closer for the timeouts to end a blocked call: `PipeIo::from_tcp`
/// has one, others take [`PipeIo::with_closer`]; one without is not taken
/// ([`HandleError::SetupFailed`]). Admission and the Tokio fallback are
/// available on the Tokio listener. Supply a blocking transform to
/// [`Listener::new`] for blocking carrier setup.
#[derive(Clone)]
pub struct Listener {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

impl SlotTable for Inner {
    fn deregister(&self, id: CarrierId) {
        let closer = {
            let mut st = self.lock();
            st.core.done(id);
            st.carriers.remove(&id)
        };
        drop(closer);
    }

    fn release(&self, slot: Slot) {
        let mut st = self.lock();
        st.core.release(slot);
        st.evicted_slots.retain(|&e| e != slot);
        st.stalled.retain(|s| s.0 != slot);
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
            || id.is_some_and(|id| !st.carriers.contains_key(&id));
        let removed = super::setup::check_handoff(st.closed, evicted, remove, id, willing)?
            .and_then(|id| {
                st.core.done(id);
                st.carriers.remove(&id)
            });
        drop(st);
        drop(removed);
        Ok(())
    }
}

type Pending = super::setup::Registration<Inner>;

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
            limits.limits,
            crate::proto::session::minimum_listener_admission(&config),
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
            locators: Arc::default(),
            config,
            transform,
            instance_id,
            stall_max,
            st: Mutex::new(State {
                core: ListenerCore::new(limits),
                live: super::setup::Sessions::default(),
                accept: VecDeque::new(),
                carriers: HashMap::new(),
                stalled: Vec::new(),
                evicted_slots: Vec::new(),
                stop_wakers: Vec::new(),
                stop_key: 0,
                closed: false,
                serving: Vec::new(),
            }),
            accepted: Condvar::new(),
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
        let incoming = Setup::new(Authority::listener(&self.inner), pipe);
        let r = self.handle(incoming, hint);
        if let Err(e) = &r {
            let c = &self.inner.counts;
            match e {
                HandleError::Rejected => &c.common.rejected,
                HandleError::Refused => &c.common.refused,
                HandleError::TimedOut => &c.common.timed_out,
                HandleError::SetupFailed | HandleError::Fallback(_) => &c.common.setup_failures,
                HandleError::NotAdmitted => return r,
            }
            .fetch_add(1, Relaxed);
        }
        r
    }

    fn handle(&self, mut incoming: CarrierSetup, hint: PipeHint) -> Result<(), HandleError> {
        let (held, pipe) = incoming.parts();
        let inner = &*self.inner;
        let clock = &inner.config.clock_domain;
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
        let interrupt = super::setup::Interrupt::new(closer);
        let closer = interrupt.closer();
        // Its slots first, before anything is read: none, and it is closed at once.
        let mut wakes = super::wake::WakeList::default();
        let (limits, id) = held.reserve(&self.inner, || {
            let mut st = inner.lock();
            let key = hint
                .source
                .map_or(0, |a| st.core.config().source_key(a.ip()));
            if st.closed {
                return Err(HandleError::Refused);
            }
            let slot = match st.core.enter(key) {
                Entered::Taken { slot, evicted } => {
                    if let Some(e) = evicted {
                        // Woken below, after the lock. Out of setup now, as
                        // on the tokio listener: its waits end.
                        st.evicted_slots.push(e);
                        if let Some(i) = st.stalled.iter().position(|s| s.0 == e) {
                            let (_, gone) = st.stalled.swap_remove(i);
                            st.carriers.remove(&gone);
                            wake_stopped(&st, Some(gone), &mut wakes);
                        }
                    }
                    slot
                }
                Entered::SourceFull => return Err(HandleError::Refused),
                Entered::Full => return Err(HandleError::Rejected),
            };
            let limits = st.core.config().clone();
            let id = st.core.open(
                None,
                pipe.handshake_framing(),
                clock.now_with(Blocking::now),
            );
            st.carriers.insert(id, closer.clone());
            Ok((slot, (limits, id)))
        })?;
        drop(wakes);
        let attachment = pipe.attachment.get_or_insert_default().clone();
        held.bind(&attachment);
        held.register(id);
        let pending = Arc::new(Pending {
            table: self.inner.clone(),
            id,
        });
        // Without its watchdog a silent carrier would hold its slot and
        // thread for good: it is not taken.
        let deadline = clock
            .now_with(Blocking::now)
            .checked_add(limits.handshake_timeout);
        let watchdog =
            Watchdog::new(closer, clock, deadline).map_err(|_| HandleError::SetupFailed)?;
        pipe.set_handshake_deadline(clock, deadline);
        if let Some(t) = &inner.transform {
            let adopt = |mut pipe: PipeIo| {
                interrupt.replace(pipe.shared_closer().ok_or(HandleError::SetupFailed)?)?;
                pipe.set_handshake_deadline(clock, deadline);
                pipe.attachment = Some(attachment.clone());
                Ok(pipe)
            };
            incoming = incoming.prepare_blocking(|held, pipe| {
                self.transform(
                    t,
                    (pipe, &pending),
                    &hint,
                    (limits.handshake_timeout, &watchdog),
                    held,
                    adopt,
                )
            })?;
            let (_, pipe) = incoming.parts();
            inner.lock().core.set_framing(id, pipe.handshake_framing());
        }
        let (held, pipe) = incoming.parts();
        if let Some(exporter) = pipe.exporter_ref().filter(|e| !e.is_resolved()) {
            let stop = async {
                let _ = super::hooks::first(inner.stopped(Some(id)), watchdog.ended()).await;
            };
            if run(super::hooks::first(stop, exporter.resolve()), None)
                .flatten()
                .is_none()
            {
                if watchdog.expired() {
                    return Err(HandleError::TimedOut);
                }
                held.stop()?;
                return Err(HandleError::Refused);
            }
        }
        if watchdog.expired() {
            return Err(HandleError::TimedOut);
        }
        watchdog.reset(limits.limits.first_record_timeout);
        let classified = Self::first_record(inner, id, pipe);
        if watchdog.expired() {
            return Err(HandleError::TimedOut);
        }
        match classified {
            Classified::NewSession { first } => {
                watchdog.reset(limits.handshake_timeout);
                self.start_session(
                    incoming.map(|pipe| pipe.with_prefix(first)),
                    hint,
                    &watchdog,
                    id,
                )
            }
            Classified::Join { locator, hello } => {
                self.join(incoming, (&locator, &hello), hint, &pending, watchdog)
            }
            Classified::BadHello { reason } => {
                watchdog.disarm();
                self.reject_setup(
                    incoming,
                    &RejectInfo::new(Some(2), None, reason, hint.source),
                    &pending,
                    inner.config.join_timeout,
                )
            }
            _ => {
                watchdog.disarm();
                self.reject_setup(
                    incoming,
                    &RejectInfo::new(None, None, "malformed", hint.source),
                    &pending,
                    limits.handshake_timeout.min(inner.stall_max),
                )
            }
        }
    }

    fn reject_setup(
        &self,
        setup: CarrierSetup,
        info: &RejectInfo,
        pending: &Arc<Pending>,
        timeout: Duration,
    ) -> Result<(), HandleError> {
        setup.prepare_blocking(|held, pipe| {
            self.reject_action(info, pending, timeout, held, Some(pipe));
            Ok(())
        })?;
        Err(HandleError::Rejected)
    }

    fn transform(
        &self,
        t: &InboundTransform,
        (pipe, pending): (PipeIo, &Arc<Pending>),
        hint: &PipeHint,
        (timeout, watchdog): (Duration, &Watchdog),
        held: &mut Authority<Inner>,
        adopt: impl Fn(PipeIo) -> Result<PipeIo, HandleError>,
    ) -> Result<PipeIo, HandleError> {
        let kind = (pipe.has_reader(), pipe.has_writer());
        let Some(transformed) = crate::proto::decision::host(|| t.0(pipe, hint)) else {
            held.host_failed()?;
            return Err(HandleError::SetupFailed);
        };
        match transformed {
            Ok(io) if (io.has_reader(), io.has_writer()) == kind => adopt(io),
            Ok(_) => Err(HandleError::SetupFailed),
            Err(e) => {
                let inner = e.get_ref();
                let refused =
                    inner.and_then(|e| e.downcast_ref::<crate::proto::listener::Refused<PipeIo>>());
                // The carrier handed back stays open while it is stalled.
                let (reject, carrier) = match refused {
                    Some(r) => (Some(&r.error), r.take_carrier().map(adopt).transpose()?),
                    None => (inner.and_then(|e| e.downcast_ref::<RejectError>()), None),
                };
                let reject = reject.filter(|_| !watchdog.expired());
                let Some(r) = reject else {
                    return Err(HandleError::SetupFailed);
                };
                watchdog.disarm();
                let info = RejectInfo::from_error(r.clone(), hint.source);
                // The handshake timeout may be none: the stall ends by the
                // listener's maximum.
                self.reject_action(
                    &info,
                    pending,
                    timeout.min(self.inner.stall_max),
                    held,
                    carrier,
                );
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
        pending: &Arc<Pending>,
        timeout: Duration,
        held: &mut Authority<Inner>,
        pipe: Option<PipeIo>,
    ) {
        let id = pending.id;
        let clock = &self.inner.config.clock_domain;
        let (policy, logger, handshake) = {
            let st = self.inner.lock();
            let config = st.core.config();
            (
                config.on_reject.clone(),
                config.logger.clone(),
                config.handshake_timeout,
            )
        };
        let action = match policy {
            None => RejectAction::default_for(info),
            Some(f) => {
                let deadline = clock.now_with(Blocking::now).checked_add(handshake);
                super::hooks::settle_blocking(f.ask(info), clock, deadline, self.inner.stopped(Some(id)))
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
            let Some(slot) = held.slot() else {
                return;
            };
            let mut st = self.inner.lock();
            if st.closed || !st.core.stall(slot) {
                drop(st);
                self.inner.counts.stall_overflow.fetch_add(1, Relaxed);
                return;
            }
            st.stalled.push((slot, id));
            drop(st);
            if held.stall().is_err() {
                return;
            }
            let Some(stall) = held.stalled(pipe) else {
                return;
            };
            let pending = pending.clone();
            let clock = clock.clone();
            let until = clock.now_with(Blocking::now).checked_add(timeout);
            thread::spawn(move || {
                stall.wait(|_| {
                    let _ = wait_in_domain(&clock, until, pending.table.stopped(Some(id)));
                });
                drop(pending);
            });
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
            let now = inner.config.clock_domain.now_with(Blocking::now);
            let mut st = inner.lock();
            let r = if pipe.handshake_framing() == Framing::Records {
                st.core.message(id, &buf, now)
            } else {
                st.core.data(id, &buf, now)
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
        let clock = &self.inner.config.clock_domain;
        let answer = super::hooks::settle_blocking(
            f.ask(&carrier),
            clock,
            clock.now_with(Blocking::now).checked_add(handshake),
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
        setup: CarrierSetup,
        hint: PipeHint,
        watchdog: &Watchdog,
        id: CarrierId,
    ) -> Result<(), HandleError> {
        let inner = &*self.inner;
        let admission = {
            let mut st = inner.lock();
            let closed = st.closed;
            st.core
                .bootstrap_admission(closed, inner.account.pressure())
        };
        let mut place = super::setup::QueuePlace::new(
            || inner.lock().core.release_unaccepted(),
            admission.is_ok(),
        );
        let setup = setup.prepare_blocking(|_, pipe| {
            let config = self.session_config(&pipe, hint)?;
            let own = (config.offers_multipath() && config.own_locator().is_empty())
                .then(|| random_locator(&inner.instance_id));
            let mut pipe = Some(pipe);
            let session = Session::listened(
                &mut pipe,
                config,
                own.as_deref(),
                Some(inner.account.ledger.clone()),
                |shared| {
                    if admission.is_ok() {
                        inner.locators.advertise(shared, inner.instance_id.len());
                    }
                    let mut st = inner.lock();
                    let registration = st.live.start(shared);
                    // Stop now belongs to the session, including the first parameter write.
                    if let Some(closer) = st.carriers.get_mut(&id) {
                        let session = Arc::downgrade(shared);
                        *closer = Arc::new(Box::new(move |_| {
                            if let Some(session) = session.upgrade() {
                                session.close_unaccepted();
                            }
                        }));
                    }
                    drop(st);
                    shared.lock().io.account = Some(Box::new(super::account::AccountLink::new(
                        inner.account.clone(),
                        Some(registration),
                    )));
                },
            );
            let session = match session {
                Ok(session) => session,
                Err(super::blocking::WaitError::Failed(crate::ConnectError::MemoryBudget)) => {
                    for session in inner.account.evict_under_pressure() {
                        session.close_suspended();
                    }
                    let mut carrier = pipe.take().expect("refused bootstrap carrier");
                    let mut bytes = [0; 128];
                    let record = super::setup::bootstrap_refusal_record(
                        carrier.handshake_framing(),
                        &mut bytes,
                    );
                    let _ = carrier.write_handshake(record);
                    return Err(HandleError::Refused);
                }
                Err(_) if watchdog.expired() => return Err(HandleError::TimedOut),
                Err(_) => return Err(HandleError::Rejected),
            };
            // Established: the watchdog no longer closes the carrier, which the
            // session owns now (N11).
            if !watchdog.finish() {
                return Err(HandleError::TimedOut);
            }
            Ok(session)
        })?;
        setup.publish(|session| {
            let mut st = inner.lock();
            let closed = st.closed;
            let unaccepted = closed || (st.core.shutting_down() && admission.is_ok());
            // The session driver owns its closer after registration.
            if unaccepted {
                st.carriers.remove(&id);
                drop(st);
                session.shared().close_unaccepted();
                return Err(HandleError::Refused);
            }
            // The session owns the carrier, including a refusal's close flush.
            st.carriers.remove(&id);
            if let Err(reason) = admission {
                drop(st);
                session.shared().refuse(reason.reason());
                return Err(HandleError::Refused);
            }
            // The queued session holds the place until it is taken.
            st.live.queue(session.shared().id)?;
            place.queued();
            st.accept.push_back(session);
            inner.counts.common.sessions.fetch_add(1, Relaxed);
            drop(st);
            inner.accepted.notify_all();
            Ok(())
        })
    }

    /// The acceptor's processing of a Hello from its Locator lookup to Confirmed, and the session's
    /// threads on the carrier.
    fn join(
        &self,
        mut setup: CarrierSetup,
        (locator, hello): (&[u8], &[u8]),
        hint: PipeHint,
        pending: &Arc<Pending>,
        watchdog: Watchdog,
    ) -> Result<(), HandleError> {
        use super::accept::{AcceptStep, JoinAccept, JoinCarrier};
        let inner = &*self.inner;
        let (_, pipe) = setup.parts();
        let framing = pipe.handshake_framing();
        // A Hello in Bound needs a Binding of this carrier (see the tokio listener).
        let binding = (pipe.is_secure() && !pipe.is_split())
            .then(|| pipe.exporter_ref().and_then(CarrierExporter::pipe_binding))
            .flatten();
        let carrier = JoinCarrier {
            attachment: pipe.attachment.get_or_insert_default().clone(),
            sources: pipe.record_sources(),
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
        let mut acc = JoinAccept::new(session, &inner.config, hello, carrier, pending.id);
        (|| {
            let (owner, pipe) = setup.parts();
            let clock = acc.clock_domain().clone();
            let deadline = acc.deadline();
            watchdog.reset_at(&clock, deadline);
            let timed_out = || watchdog.expired();
            let stopped = || async {
                let _ =
                    super::hooks::first(inner.stopped(Some(pending.id)), watchdog.ended()).await;
            };
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
            let (reply, evicted) = loop {
                if timed_out() {
                    return Err(HandleError::TimedOut);
                }
                step = match step {
                    // A stall lasts the listener's join timeout from the refusal, whether
                    // or not the Locator names a session: the response and the way of
                    // ending are the same.
                    AcceptStep::Reject(reason, mode) => {
                        watchdog.disarm();
                        let info = RejectInfo::new(Some(2), mode, reason, hint.source);
                        return self.reject_setup(setup, &info, pending, inner.config.join_timeout);
                    }
                    AcceptStep::End(e) => return Err(e),
                    AcceptStep::WaitKeys => {
                        let session = acc.session().expect("named").clone();
                        match run(
                            super::hooks::first(stopped(), handle::join_keys_wait(&session)),
                            None,
                        )
                        .flatten()
                        {
                            Some(ready) => open(&mut acc, Some(ready)),
                            None if timed_out() => AcceptStep::End(HandleError::TimedOut),
                            None => AcceptStep::End(acc.stopped(owner.checkpoint())),
                        }
                    }
                    AcceptStep::Ask(check, d) => {
                        let session = acc.session().expect("named").clone();
                        let either =
                            super::hooks::first(stopped(), handle::session_ended_wait(&session));
                        let ended = async move {
                            let _ = either.await;
                        };
                        match super::hooks::settle_blocking(d, &clock, None, ended) {
                            Some(ok) => {
                                if ok
                                    && matches!(check, super::accept::Check::Mode)
                                    && let Err(error) = pipe.reserve_carrier_memory(&session)
                                {
                                    return Err(acc.failed(error.into()));
                                }
                                acc.allowed(check, ok)
                            }
                            None if timed_out() => AcceptStep::End(HandleError::TimedOut),
                            None => AcceptStep::End(acc.stopped(owner.checkpoint())),
                        }
                    }
                    AcceptStep::Delay(delay) => {
                        let session = acc.session().expect("named").clone();
                        let until = clock.now_with(Blocking::now).checked_add(delay);
                        let ended =
                            super::hooks::first(stopped(), handle::session_ended_wait(&session));
                        let stopped = wait_in_domain(&clock, until, ended).is_some();
                        if timed_out() {
                            AcceptStep::End(HandleError::TimedOut)
                        } else if stopped {
                            AcceptStep::End(acc.stopped(owner.checkpoint()))
                        } else {
                            acc.delayed(true)
                        }
                    }
                    AcceptStep::Refuse(reply) => {
                        // The Reply ends with a graceful end of the writing half, so that
                        // the joiner sees the refusal.
                        let limit = clock
                            .now_with(Blocking::now)
                            .checked_add(super::DRAIN_LIMIT);
                        watchdog.reset_at(&clock, super::deadline::earlier(deadline, limit));
                        let mut write = super::accept::JoinWrite::new(
                            acc.session().expect("named").clone(),
                            reply,
                        );
                        let pipe = setup
                            .claim(Transfer::Reply)
                            .map_err(|e| acc.commit_failed(e))?;
                        let _ =
                            thread::Builder::new()
                                .name("zmux-refusal".into())
                                .spawn(move || {
                                    let mut pipe = pipe;
                                    if pipe.write_join(&mut write).is_ok() {
                                        pipe.shutdown_write();
                                    }
                                    watchdog.disarm();
                                });
                        return Err(HandleError::Refused);
                    }
                    AcceptStep::Reply { bytes, evicted } => break (bytes, evicted),
                };
            };
            let session = acc.session().expect("named").clone();
            for id in evicted {
                let mut wakes = super::wake::WakeList::default();
                let mut st = inner.lock();
                st.core.done(id);
                wake_stopped(&st, Some(id), &mut wakes);
                let evicted = st.carriers.remove(&id);
                drop(st);
                if let Some(c) = evicted {
                    c(Shutdown::Both);
                }
            }
            let io_failed = |acc: &mut JoinAccept<Blocking>, kind| {
                if let Err(e) = owner.checkpoint() {
                    acc.commit_failed(e)
                } else if timed_out() {
                    HandleError::TimedOut
                } else {
                    acc.carrier_failed(kind)
                }
            };
            let mut write = super::accept::JoinWrite::new(session.clone(), reply);
            pipe.write_join(&mut write)
                .map_err(|e| io_failed(&mut acc, e.kind()))?;
            let mut input = Vec::new();
            let rest = loop {
                match acc.confirm(&mut input) {
                    Ok(true) => break input,
                    Ok(false) => {}
                    Err(()) => return Err(acc.carrier_failed(io::ErrorKind::InvalidData)),
                }
                match pipe.read_handshake(&mut input) {
                    Ok(0) => {
                        return Err(io_failed(&mut acc, io::ErrorKind::UnexpectedEof));
                    }
                    Ok(_) => {}
                    Err(e) => return Err(io_failed(&mut acc, e.kind())),
                }
            };
            if acc.sends_on_pipe() {
                pipe.register_carrier_stats();
            }
            setup
                .publication()
                .map_err(|e| acc.commit_failed(e))?
                .finish(|pipe| {
                    if !watchdog.finish() {
                        return Err(HandleError::TimedOut);
                    }
                    let super::accept::Attached {
                        mut install,
                        records,
                        want_in,
                        want_out,
                    } = acc.attach()?;
                    let mut io = pipe.with_prefix(rest);
                    if let Some((s, o)) = records {
                        io = io.seal_records(s, o);
                    }
                    let attached = install.id();
                    io.keep_directions(want_in, want_out)
                        .map_err(|_| install.resource_limit())?;
                    if let Some(m) = io.record_limit() {
                        let mut st = session.lock();
                        st.core
                            .set_pipe_max_record(attached, m)
                            .map_err(|_| install.resource_limit())?;
                        st.core.set_pipe_write_overhead(attached, io.overhead());
                    }
                    spawn_pipe(&session, attached.0, io).map_err(|e| {
                        let reason = session.lock().core.error().cloned().map_or_else(
                            || crate::PipeError::Failed(crate::PipeFailure::Carrier(e.kind())),
                            crate::PipeError::SessionLost,
                        );
                        acc.failed(reason.into())
                    })?;
                    install.installed().map_err(|e| acc.failed(e.into()))
                })?;
            inner.counts.common.joins.fetch_add(1, Relaxed);
            Ok(())
        })()
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
                st.live.accept(s.shared().id);
                st.core.release_unaccepted();
                return Ok(Some(s));
            }
            if st.closed || st.core.shutting_down() {
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
                        .wait_timeout(st.into_wait(), left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => self
                    .inner
                    .accepted
                    .wait(st.into_wait())
                    .unwrap_or_else(PoisonError::into_inner),
            }
            .into();
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
        let served = self.accept_loop(|| tcp.accept());
        self.inner.lock().serving.retain(|a| *a != wake);
        served
    }

    fn accept_loop(
        &self,
        mut accept: impl FnMut() -> io::Result<(TcpStream, SocketAddr)>,
    ) -> io::Result<()> {
        loop {
            let accepted = accept();
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
        let mut wakes = super::wake::WakeList::default();
        let mut st = self.inner.lock();
        st.closed = true;
        wake_stopped(&st, None, &mut wakes);
        let carriers: Vec<_> = st.carriers.drain().map(|(_, c)| c).collect();
        let unaccepted = std::mem::take(&mut st.accept);
        for _ in 0..unaccepted.len() {
            st.core.release_unaccepted();
        }
        let serving = std::mem::take(&mut st.serving);
        let establishing = st.live.establishing();
        drop(st);
        drop(wakes);
        self.inner.accepted.notify_all();
        for c in carriers {
            c(Shutdown::Both);
        }
        for s in establishing {
            s.close_unaccepted();
        }
        for session in unaccepted {
            session.shared().close_unaccepted();
        }
        // A serving loop blocked in accept sees the close with this
        // connection, which it drops.
        for a in serving {
            let _ = TcpStream::connect_timeout(&a, Duration::from_secs(1));
        }
    }

    /// Refuses subsequent bootstrap carriers after their handshake with
    /// `CONNECTION_REFUSED` and these reason bytes. Joins and lanes stay open.
    /// Repeating the call replaces the reason until graceful shutdown begins.
    pub fn drain(&self, reason: &[u8]) {
        self.inner.lock().core.drain(reason);
    }

    /// Resumes accepting new sessions. Has no effect after graceful shutdown begins.
    pub fn undrain(&self) {
        self.inner.lock().core.undrain();
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
        let (live, unaccepted, establishing) = {
            let mut st = self.inner.lock();
            st.core.begin_shutdown(reason);
            let live = st.live.accepted();
            let establishing = st.live.establishing();
            let unaccepted = std::mem::take(&mut st.accept);
            for _ in 0..unaccepted.len() {
                st.core.release_unaccepted();
            }
            (live, unaccepted, establishing)
        };
        self.inner.accepted.notify_all();
        for s in establishing {
            s.close_unaccepted();
        }
        for session in unaccepted {
            session.shared().close_unaccepted();
        }
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
            let mut st = self.inner.lock();
            super::setup::update_listener_limits(&mut st.core, &self.inner.account, limits)?
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
        c.common.snapshot(AdmissionStats {
            stall_overflow: c.stall_overflow.load(Relaxed),
            ..AdmissionStats::default()
        })
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
            .common
            .setup_failures
            .fetch_add(1, Relaxed);
    }
}

#[cfg(test)]
use crate::{ClockDomain, MonotonicClock};

#[cfg(test)]
#[path = "../../tests/common/clock.rs"]
mod test_clock;

#[cfg(test)]
mod tests {
    use crate::ListenerLimits;
    use std::io::Read;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{InboundTransform, Listener, PipeHint};
    use crate::driver::blocking::PipeIo;
    use crate::proto::listener::{HandleError, ListenerConfig, Refused, RejectError};
    use crate::proto::session::Config;

    #[test]
    fn serve_goes_on_after_an_accept_error() {
        let listener = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        let (reentered, accepting) = mpsc::channel();
        let (closed, resume) = mpsc::channel();
        let limit = Duration::from_secs(30);
        let serving = {
            let listener = listener.clone();
            std::thread::spawn(move || {
                let mut attempts = 0;
                listener.accept_loop(|| {
                    attempts += 1;
                    if attempts == 2 {
                        reentered.send(()).unwrap();
                        resume.recv_timeout(limit).unwrap();
                    }
                    assert!(attempts <= 2);
                    Err(std::io::ErrorKind::ConnectionAborted.into())
                })
            })
        };
        accepting.recv_timeout(limit).unwrap();
        listener.close();
        closed.send(()).unwrap();
        serving.join().unwrap().unwrap();
    }

    #[test]
    fn ended_session_leaves_registry_before_closed_returns() {
        let listener = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        let (near, far) = pair();
        let setup = {
            let l = listener.clone();
            std::thread::spawn(move || l.handle_pipe(PipeIo::from_tcp(far), PipeHint::default()))
        };
        let client =
            crate::blocking::Session::connect(PipeIo::from_tcp(near), Config::default()).unwrap();
        setup.join().unwrap().unwrap();
        let server = listener.accept().unwrap();
        assert_eq!(listener.inner.lock().live.accepted().len(), 1);
        client.close();
        server.closed().unwrap();
        assert!(listener.inner.lock().live.accepted().is_empty());
    }

    #[test]
    // HS-04
    fn confirmed_pipe_installation_races_shutdown_and_writer_failure() {
        use crate::blocking::Session;
        use std::sync::mpsc;
        let config = Config::multipath(crate::PipeAuth::psk([7u8; 32]).with_end_to_end());
        for fail_writer in [false, true] {
            let listener = Listener::new(config.clone(), ListenerConfig::default(), None).unwrap();
            let (near, far) = pair();
            let l = listener.clone();
            let setup = std::thread::spawn(move || {
                l.handle_pipe(PipeIo::from_tcp(far), PipeHint::default())
            });
            let client = Session::connect(PipeIo::from_tcp(near), config.clone()).unwrap();
            let server = listener.accept().unwrap();
            setup.join().unwrap().unwrap();
            let (near, far) = pair();
            let (at, stage) = mpsc::channel();
            let (resume, gate) = mpsc::channel();
            let l = listener.clone();
            let setup = std::thread::spawn(move || {
                super::super::blocking::install_test::set(move |id, writer| {
                    if writer == fail_writer {
                        at.send(id).unwrap();
                        gate.recv_timeout(Duration::from_secs(3)).unwrap();
                        if writer {
                            return Err(std::io::ErrorKind::OutOfMemory.into());
                        }
                    }
                    Ok(())
                });
                let socket = far.try_clone().unwrap();
                let io = PipeIo::from_tcp(far).with_closer(move |how| {
                    let _ = socket.shutdown(how);
                    assert!(!fail_writer, "host closer");
                });
                l.handle_pipe(io, PipeHint::default())
            });
            let _added = client
                .test_begin_join(PipeIo::from_tcp(near), crate::PipeOptions::default())
                .unwrap();
            let id = stage.recv_timeout(Duration::from_secs(3)).unwrap();
            let pipe = server.pipe(crate::PipeId::new(id)).unwrap();
            if !fail_writer {
                server.abort(crate::VarInt::from_u32(0), b"");
            }
            resume.send(()).unwrap();
            assert_eq!(setup.join().unwrap(), Err(HandleError::Refused));
            let _ = pipe.closed();
        }
    }

    /// A listener whose transform refuses every carrier as an Establish of `profile`,
    /// handing the carrier back, with this maximum stall.
    fn refusing(
        config: Config,
        profile: u64,
        limits: ListenerConfig,
        stall_max: Duration,
    ) -> Listener {
        let t = InboundTransform::new(move |p, _| {
            Err(Refused::error(
                RejectError::new(Some(profile), None, "auth"),
                p,
            ))
        });
        Listener::with_stall_max(config, limits, Some(t), stall_max).unwrap()
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

    const WATCHDOG: Duration = Duration::from_secs(30);

    fn track_setups() -> (InboundTransform, mpsc::Receiver<()>) {
        let (entered, receive) = mpsc::channel();
        let transform = InboundTransform::new(move |pipe, _| {
            entered.send(()).unwrap();
            Ok(pipe)
        });
        (transform, receive)
    }

    /// The client's end reads nothing and then the end of the carrier.
    fn closed_silently(mut client: TcpStream) {
        client.set_read_timeout(Some(WATCHDOG)).unwrap();
        let mut buf = [0; 16];
        assert_eq!(client.read(&mut buf).unwrap(), 0);
    }

    /// Without `on_reject`, a refused Establish is stalled until the handshake timeout,
    /// never beyond the listener's maximum stall; a refused Join is closed at once.
    #[tokio::test]
    async fn a_refused_establish_stalls_at_most_the_handshake_timeout_and_the_stall_max() {
        let short = Duration::from_secs(20);
        let long = Duration::from_secs(90);
        for (timeout, stall_max) in [(short, long), (long, short)] {
            let (clock, domain) = super::test_clock::ManualClock::domain(long);
            let mut timers = clock.registrations();
            let deadline = domain.now() + short;
            let config = Config {
                clock_domain: domain,
                ..Config::default()
            };
            let limits = ListenerConfig {
                handshake_timeout: timeout,
                ..Default::default()
            };
            let l = refusing(config, 1, limits, stall_max);
            let (client, server) = pair();
            let accepting = l.clone();
            let handled = std::thread::spawn(move || {
                accepting.handle_pipe(PipeIo::from_tcp(server), from(1))
            });
            assert_eq!(handled.join().unwrap(), Err(HandleError::Rejected));
            let key = ListenerConfig::default().source_key(from(1).source.unwrap().ip());
            assert_eq!(l.inner.lock().core.stalled(key).1, 1);
            tokio::time::timeout(Duration::from_secs(30), async {
                while timers.recv().await.unwrap() != deadline {}
            })
            .await
            .unwrap();
            clock.advance(short);
            closed_silently(client);
        }
        let limits = ListenerConfig {
            handshake_timeout: long,
            ..Default::default()
        };
        let l = refusing(Config::default(), 2, limits, long);
        let key = ListenerConfig::default().source_key([192, 0, 2, 1].into());
        let (client, server) = pair();
        let accepting = l.clone();
        let handled =
            std::thread::spawn(move || accepting.handle_pipe(PipeIo::from_tcp(server), from(1)));
        assert_eq!(handled.join().unwrap(), Err(HandleError::Rejected));
        assert_eq!(l.inner.lock().core.stalled(key).1, 0);
        closed_silently(client);
    }

    /// A source keeps a slot for a new attempt: with `max_pending_per_source` 2 it stalls
    /// one carrier, and the next refused one from it is closed at once; another source
    /// still stalls. `close` ends the stalls.
    ///
    /// The setup result and the source stall count are observed independently.
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
        let l = refusing(Config::default(), 1, limits, hour);
        let stalled = |key| l.inner.lock().core.stalled(key).1;
        let key = ListenerConfig::default().source_key([192, 0, 2, 1].into());
        let other_addr = SocketAddr::from(([198, 51, 100, 1], 3));
        let other_key = ListenerConfig::default().source_key(other_addr.ip());
        let (c1, s1) = pair();
        assert_eq!(
            l.handle_pipe(PipeIo::from_tcp(s1), from(1)),
            Err(HandleError::Rejected)
        );
        let (c3, s3) = pair();
        let hint = PipeHint {
            source: Some(other_addr),
        };
        assert_eq!(
            l.handle_pipe(PipeIo::from_tcp(s3), hint),
            Err(HandleError::Rejected)
        );
        assert_eq!((stalled(key), stalled(other_key)), (1, 1));
        let (c2, s2) = pair();
        assert_eq!(
            l.handle_pipe(PipeIo::from_tcp(s2), from(2)),
            Err(HandleError::Rejected)
        );
        closed_silently(c2);
        assert_eq!((stalled(key), stalled(other_key)), (1, 1));
        l.close();
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
        let (transform, entering) = track_setups();
        let l = Listener::new(Config::default(), limits, Some(transform)).unwrap();
        let mut held = Vec::new();
        for port in 1..=3 {
            let (c, s) = pair();
            let lh = l.clone();
            held.push((
                c,
                std::thread::spawn(move || lh.handle_pipe(PipeIo::from_tcp(s), from(port))),
            ));
        }
        for _ in 0..3 {
            entering.recv_timeout(WATCHDOG).unwrap();
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
        let (transform, entering) = track_setups();
        let l = Listener::new(Config::default(), limits, Some(transform)).unwrap();
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
            let mut held = Vec::new();
            for ip in [a, b] {
                let (c, s) = pair();
                let (lh, hint) = (l.clone(), at(ip));
                held.push((
                    c,
                    std::thread::spawn(move || lh.handle_pipe(PipeIo::from_tcp(s), hint)),
                ));
            }
            for _ in 0..2 {
                entering.recv_timeout(WATCHDOG).unwrap();
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
            entering.recv_timeout(WATCHDOG).unwrap();
            for (c, t) in held {
                drop(c);
                let _ = t.join().unwrap();
            }
        }
        assert_eq!(l.stats().refused, 2);
        l.close();
    }

    struct WakeSignal(mpsc::Sender<()>);

    impl std::task::Wake for WakeSignal {
        fn wake(self: std::sync::Arc<Self>) {
            let _ = self.0.send(());
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
        let (transform, entering) = track_setups();
        let l = Listener::with_stall_max(Config::default(), limits, Some(transform), hour).unwrap();
        let total = |l: &Listener| l.inner.lock().core.held(0).0;
        let stalls = |l: &Listener| l.inner.lock().core.stalled(0).0;
        let garbage = |port: u16| {
            let (mut c, s) = pair();
            c.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
            assert_eq!(
                l.handle_pipe(PipeIo::from_tcp(s), from(port)),
                Err(HandleError::Rejected)
            );
            entering.recv_timeout(WATCHDOG).unwrap();
            c
        };
        let silent = |port: u16| {
            let (c, s) = pair();
            let lh = l.clone();
            let t = std::thread::spawn(move || lh.handle_pipe(PipeIo::from_tcp(s), from(port)));
            (c, t)
        };
        let c1 = garbage(1);
        assert_eq!(stalls(&l), 1);
        // A wait of the stalled carrier ends with its eviction.
        let first = *l.inner.lock().carriers.keys().next().unwrap();
        let (woken, wake) = mpsc::channel();
        let waker = std::task::Waker::from(std::sync::Arc::new(WakeSignal(woken)));
        let mut stopped = std::pin::pin!(l.inner.stopped(Some(first)));
        let cx = &mut std::task::Context::from_waker(&waker);
        assert!(stopped.as_mut().poll(cx).is_pending());
        // Half of 2 is stalled: the next is closed at once.
        let c2 = garbage(2);
        closed_silently(c2);
        assert_eq!(l.stats().admission.stall_overflow, 1);
        let (c3, t3) = silent(3);
        entering.recv_timeout(WATCHDOG).unwrap();
        assert_eq!(total(&l), 2);
        // Every slot taken: the stall goes.
        let (c4, t4) = silent(4);
        wake.recv_timeout(WATCHDOG).unwrap();
        assert!(stopped.as_mut().poll(cx).is_ready());
        closed_silently(c1);
        entering.recv_timeout(WATCHDOG).unwrap();
        assert_eq!(total(&l), 2);
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
        l.drain(b"maintenance");
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
