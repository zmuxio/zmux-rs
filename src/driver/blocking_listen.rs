//! A listener for the std driver: the steps of the tokio one, on the caller's thread. New
//! sessions are accepted and Joins verified over the same `ListenerCore` and session
//! operations. Split carriers, lanes and admissions are tokio's.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use super::blocking::{Blocking, Closer, PipeIo, Session, Watchdog, run, spawn_pipe};
use super::handle::{self, Shared, WeakSession};
use crate::proto::VarInt;
use crate::proto::listener::{
    AdmissionStats, CarrierId, Classified, Entered, HandleError, ListenerConfig, ListenerCore,
    ListenerStats, RejectAction, RejectError, RejectInfo, Slot, random_locator,
};
use crate::proto::record::Framing;
use crate::proto::seal::join::JoinHello;
use crate::proto::session::{
    ClaimedHello, Config, ConfirmedJoin, OpenedHello, PeerCarrier, RecordPolicyInput,
};

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
    accept: VecDeque<Session>,
    /// The closers of the carriers being set up: eviction and `close` end their calls.
    carriers: HashMap<CarrierId, Arc<Closer>>,
    /// The slots of stalled carriers evicted for a new carrier, until each saw it.
    evicted_slots: Vec<Slot>,
    closed: bool,
    draining: bool,
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
    accepted: Condvar,
    counts: Counts,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A listener for blocking sessions: hand it carriers with [`Listener::handle_pipe`], or a
/// socket with [`Listener::serve`], and take sessions with [`Listener::accept`]. Cheap to
/// clone. A carrier needs a closer for the timeouts to end a blocked call: `PipeIo::tcp`
/// has one, others take [`PipeIo::with_closer`].
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
        limits.check().map_err(InvalidConfig)?;
        let config = config.into();
        config.validate().map_err(InvalidConfig)?;
        let instance_id = limits.instance_id.clone();
        Ok(Self {
            inner: Arc::new(Inner {
                locators: Default::default(),
                config,
                transform,
                instance_id,
                stall_max: crate::proto::admission::draw_stall_max(),
                st: Mutex::new(State {
                    core: ListenerCore::new(limits),
                    live: Vec::new(),
                    accept: VecDeque::new(),
                    carriers: HashMap::new(),
                    evicted_slots: Vec::new(),
                    closed: false,
                    draining: false,
                }),
                accepted: Condvar::new(),
                counts: Counts::default(),
            }),
        })
    }

    /// Takes a carrier: returns once it started a session or joined one, or was not used.
    /// The session's threads then own it.
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
        let closer = pipe.shared_closer();
        // Its slots first, before anything is read: none, and it is closed at once.
        let (limits, id, slot) = {
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
                        // Woken below, after the lock.
                        st.evicted_slots.push(e);
                    }
                    slot
                }
                Entered::SourceFull => return Err(HandleError::Refused),
                Entered::Full => return Err(HandleError::Rejected),
            };
            let limits = st.core.config().clone();
            let id = st.core.open(None, pipe.handshake_framing(), Instant::now());
            if let Some(c) = &closer {
                st.carriers.insert(id, c.clone());
            }
            (limits, id, slot)
        };
        inner.accepted.notify_all();
        let mut held = Held {
            inner,
            slot: Some(slot),
        };
        let pending = Pending { inner, id };
        let watchdog = closer.map(|c| Watchdog::new(c, limits.handshake_timeout));
        pipe.limit_handshake_wait(limits.handshake_timeout);
        if let Some(t) = &inner.transform {
            pipe = self.transform(
                t,
                pipe,
                &hint,
                limits.handshake_timeout,
                watchdog.as_ref(),
                &mut held,
            )?;
            inner.lock().core.set_framing(id, pipe.handshake_framing());
        }
        if let Some(w) = &watchdog {
            w.reset(limits.first_record_timeout);
        }
        let classified = Self::first_record(inner, id, &mut pipe);
        if watchdog.as_ref().is_some_and(Watchdog::fired) {
            return Err(HandleError::TimedOut);
        }
        if let Some(w) = &watchdog {
            w.reset(limits.handshake_timeout);
        }
        match classified {
            Classified::NewSession { first } => self.start_session(pipe.with_prefix(first), hint),
            Classified::Join { locator, hello } => {
                self.join(pipe, &locator, &hello, hint, &pending, &mut held)
            }
            Classified::BadHello { reason } => {
                // Stalled, as every refused join, for the listener's join timeout.
                let info = RejectInfo::new(Some(2), None, reason, hint.source);
                self.reject_action(&info, inner.config.join_timeout, &mut held);
                Err(HandleError::Rejected)
            }
            // First bytes that are no carrier this listener knows (step 2).
            _ => {
                let info = RejectInfo::new(None, None, "malformed", hint.source);
                let limit = limits.handshake_timeout.min(inner.stall_max);
                self.reject_action(&info, limit, &mut held);
                Err(HandleError::Rejected)
            }
        }
    }

    fn transform(
        &self,
        t: &InboundTransform,
        pipe: PipeIo,
        hint: &PipeHint,
        timeout: Duration,
        watchdog: Option<&Watchdog>,
        held: &mut Held<'_>,
    ) -> Result<PipeIo, HandleError> {
        let kind = (pipe.has_reader(), pipe.has_writer());
        match (t.0)(pipe, hint) {
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
                let reject = reject.filter(|_| !watchdog.is_some_and(Watchdog::fired));
                let Some(r) = reject else {
                    return Err(HandleError::SetupFailed);
                };
                let info = RejectInfo::new(r.profile, r.record_mode, r.reason, hint.source);
                // The handshake timeout may be none: the stall ends by the
                // listener's maximum.
                self.reject_action(&info, timeout.min(self.inner.stall_max), held);
                Err(HandleError::Rejected)
            }
        }
    }

    /// The reject policy: closed, or stalled without a byte until `timeout`, the listener
    /// closes or a new carrier evicts it, keeping its slots; closed at once, counted as
    /// `stall_overflow`, when its source holds its maximum of stalls or the listener's
    /// stalls hold half of `max_pending`.
    fn reject_action(&self, info: &RejectInfo, timeout: Duration, held: &mut Held<'_>) {
        let (policy, logger) = {
            let st = self.inner.lock();
            (
                st.core.config().on_reject.clone(),
                st.core.config().logger.clone(),
            )
        };
        let action = policy.map_or_else(
            || RejectAction::default_for(info),
            |f| f.ask(info, logger.as_ref()),
        );
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
            let until = Instant::now() + timeout;
            while !st.closed && !st.evicted_slots.contains(&slot) {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                st = self
                    .inner
                    .accepted
                    .wait_timeout(st, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            if !st.core.unstall(slot) {
                held.slot = None;
            }
            st.evicted_slots.retain(|&e| e != slot);
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
            admitted: pipe.admitted_value(),
        };
        match f.choose(&carrier, logger.as_ref()) {
            Ok(None) => Ok(self.inner.config.clone()),
            Ok(Some(c)) => Ok(Arc::new(c)),
            Err(()) => Err(HandleError::Rejected),
        }
    }

    fn start_session(&self, pipe: PipeIo, hint: PipeHint) -> Result<(), HandleError> {
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
            let mut st = inner.lock();
            st.live.retain(|w| w.strong_count() > 0);
            st.live.push(Arc::downgrade(shared));
            if !locator.is_empty() {
                inner.locators.insert(locator, Arc::downgrade(shared));
            }
        })
        .map_err(|_| HandleError::Rejected)?;
        let mut st = inner.lock();
        if st.closed || st.draining {
            drop(st);
            // Refused after its own parameters, so that the peer reads why.
            if let Some(shared) = created.and_then(|w| w.upgrade()) {
                run(shared.refuse("draining"), None);
            }
            drop(session);
            return Err(HandleError::Refused);
        }
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
        locator: &[u8],
        hello: &[u8],
        hint: PipeHint,
        pending: &Pending<'_>,
        held: &mut Held<'_>,
    ) -> Result<(), HandleError> {
        let inner = &*self.inner;
        let session = inner.locators.get(locator);
        // The joined session's join timeout, or the listener's session
        // configuration's for an unknown Locator.
        let join_timeout = session.as_ref().map_or(inner.config.join_timeout, |s| {
            s.lock().core.config().join_timeout
        });
        let deadline = Instant::now().checked_add(join_timeout);
        let framing = pipe.handshake_framing();
        let Ok(parsed) = JoinHello::parse(framing, hello) else {
            let info = RejectInfo::new(Some(2), None, "malformed", hint.source);
            self.reject_action(&info, inner.config.join_timeout, held);
            return Err(HandleError::Rejected);
        };
        let mode = Some(parsed.mode());
        // A stall lasts the listener's join timeout from the refusal, whether or not the
        // Locator names a session: the response and the way of ending are the same.
        let mut rejected = |reason: &'static str| {
            let info = RejectInfo::new(Some(2), mode, reason, hint.source);
            self.reject_action(&info, inner.config.join_timeout, held);
            Err(HandleError::Rejected)
        };
        let Some(session) = session else {
            return rejected("unknown_locator");
        };
        // A Hello in Bound needs a Binding of this carrier (see the tokio listener).
        let binding = if parsed.mode() == crate::proto::seal::RecordMode::Bound {
            let binding = (pipe.is_secure() && !pipe.is_split())
                .then(|| pipe.exporter_ref().and_then(|e| e.pipe_binding()))
                .flatten();
            let Some(binding) = binding else {
                session.hello_without_binding();
                return rejected("auth");
            };
            binding
        } else {
            Vec::new()
        };
        let mut join = loop {
            if inner.lock().closed {
                return Err(HandleError::Refused);
            }
            match session.open_hello(&parsed, &binding, |_| true) {
                Some(OpenedHello::Verified(j)) => break j,
                Some(OpenedHello::AuthFailed) => return rejected("auth"),
                Some(OpenedHello::UnknownSuite) => return rejected("unknown_suite"),
                Some(OpenedHello::UnknownLocator) => return rejected("unknown_locator"),
                Some(OpenedHello::Hold | OpenedHello::KeyWait) => {
                    if run(handle::join_keys_wait(&session), deadline) != Some(true) {
                        return Err(HandleError::Rejected);
                    }
                }
                _ => return Err(HandleError::Rejected),
            }
        };
        let info = RecordPolicyInput {
            has_exporter: pipe.exporter_ref().is_some(),
            secure: pipe.is_secure(),
            ..RecordPolicyInput::default()
        };
        let admitted = pipe.admitted_value().cloned();
        if !session.join_allowed(&info, &join, admitted.as_ref()) {
            return Err(HandleError::Rejected);
        }
        let carrier = PeerCarrier {
            inbound: pipe.has_reader().then_some(framing),
            outbound: pipe.has_writer().then_some(framing),
            looped: false,
            overhead: pipe.overhead(),
            received: hello.len(),
        };
        let plan = session.join_plan(pipe.carrier(), "reply");
        if !plan.delay.is_zero() {
            let until = Instant::now().checked_add(plan.delay);
            let end = match (until, deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if run(handle::session_ended_wait(&session), end).is_some()
                || deadline.is_some_and(|d| Instant::now() >= d)
            {
                return Err(HandleError::Rejected);
            }
        }
        let reply = match session.claim_hello(&mut join, carrier, &plan) {
            ClaimedHello::Accept(reply) => reply,
            ClaimedHello::Refuse(reply) => {
                let _ = pipe.write_handshake(&reply);
                return Err(HandleError::Refused);
            }
            ClaimedHello::Close => return Err(HandleError::Rejected),
        };
        {
            let mut st = inner.lock();
            let evicted = st
                .core
                .unconfirmed(pending.id, locator)
                .and_then(|e| st.carriers.remove(&e));
            drop(st);
            if let Some(c) = evicted {
                c(Shutdown::Both);
            }
        }
        pipe.write_handshake(&reply)
            .map_err(|_| HandleError::Rejected)?;
        let mut input = Vec::new();
        let rest = loop {
            match join.read_confirm(&input) {
                Ok(Some(n)) => {
                    input.drain(..n);
                    break input;
                }
                Ok(None) => {}
                Err(_) => return Err(HandleError::Rejected),
            }
            if framing == Framing::Records {
                input.clear();
            }
            match pipe.read_handshake(&mut input) {
                Ok(n) if n > 0 => {}
                _ => return Err(HandleError::Rejected),
            }
        };
        let meta = (pipe.carrier(), pipe.overhead(), admitted);
        let (want_in, want_out) = (join.pipe().direction != 1, join.pipe().direction != 0);
        let (attached, records) = match session.confirm_join(*join, carrier, meta) {
            ConfirmedJoin::Attached { pipe, records } => (pipe, records),
            ConfirmedJoin::Refused => return Err(HandleError::Refused),
            ConfirmedJoin::Close => return Err(HandleError::Rejected),
        };
        let mut io = pipe.with_prefix(rest);
        if let Some((s, o)) = records {
            io = io.seal_records(s, o);
        }
        io.keep_directions(want_in, want_out);
        if let Some(m) = io.record_limit() {
            let mut st = session.lock();
            st.core.set_pipe_max_record(attached, m);
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

    /// The next session, waiting up to `timeout` (`None`: until the listener closes).
    pub fn accept(&self, timeout: Option<Duration>) -> Option<Session> {
        let until = timeout.and_then(|t| Instant::now().checked_add(t));
        let mut st = self.inner.lock();
        loop {
            if let Some(s) = st.accept.pop_front() {
                return Some(s);
            }
            if st.closed || st.draining {
                return None;
            }
            st = match until {
                Some(u) => {
                    let left = u.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
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
    pub fn serve(&self, tcp: &TcpListener) -> io::Result<()> {
        tcp.set_nonblocking(true)?;
        while !self.inner.lock().closed {
            match tcp.accept() {
                Ok((stream, peer)) => {
                    // A connection that cannot be served is that connection's end.
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    let l = self.clone();
                    let spawned =
                        thread::Builder::new()
                            .name("zmux-carrier".into())
                            .spawn(move || {
                                let hint = PipeHint { source: Some(peer) };
                                let _ = l.handle_pipe(PipeIo::tcp(stream), hint);
                            });
                    if spawned.is_err() {
                        thread::sleep(super::ACCEPT_BACKOFF);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                // Out of descriptors and the like pass; only closing ends the loop.
                Err(e) => {
                    if super::accept_backs_off(&e) {
                        thread::sleep(super::ACCEPT_BACKOFF);
                    }
                }
            }
        }
        Ok(())
    }

    /// Closes: `accept` returns `None`, carriers in setup are shut down, sessions not
    /// accepted are closed. Sessions accepted go on.
    pub fn close(&self) {
        let mut st = self.inner.lock();
        st.closed = true;
        let carriers: Vec<_> = st.carriers.drain().map(|(_, c)| c).collect();
        let unaccepted = std::mem::take(&mut st.accept);
        drop(st);
        self.inner.accepted.notify_all();
        for c in carriers {
            c(Shutdown::Both);
        }
        drop(unaccepted);
    }

    /// Closes gracefully: new sessions are refused while joins go on, every session is
    /// shut down with `code` and `reason`, then the listener closes.
    pub fn shutdown(&self, code: VarInt, reason: &[u8]) {
        let (live, unaccepted) = {
            let mut st = self.inner.lock();
            st.draining = true;
            let live: Vec<_> = st
                .live
                .iter()
                .filter_map(|w| WeakSession::from_weak(w.clone()).upgrade())
                .collect();
            (live, std::mem::take(&mut st.accept))
        };
        self.inner.accepted.notify_all();
        drop(unaccepted);
        for s in live {
            let _ = s.shutdown(code, reason);
        }
        self.close();
    }

    /// Counts a connection that an accept loop could not make a pipe input
    /// of: a failed TLS handshake or its timeout, a failed upgrade, or the
    /// setup limit. For the application's own accept loops
    /// ([`ListenerStats::setup_failures`]); such a connection is counted
    /// nowhere else.
    pub fn count_setup_failure(&self) {
        self.inner.counts.setup_failures.fetch_add(1, Relaxed);
    }

    /// What happened to the carriers handed to the listener.
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

#[cfg(test)]
mod tests {
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
        let mut l = Listener::new(Config::default(), limits, Some(t)).unwrap();
        std::sync::Arc::get_mut(&mut l.inner).unwrap().stall_max = stall_max;
        l
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
            let r = l.handle_pipe(PipeIo::tcp(server), from(1));
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
        let key = crate::ListenerConfig::default().source_key([192, 0, 2, 1].into());
        let (client, server) = pair();
        let lj = l.clone();
        let join = std::thread::spawn(move || lj.handle_pipe(PipeIo::tcp(server), from(1)));
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
            handshake_timeout: hour,
            max_pending_per_source: 2,
            ..Default::default()
        };
        let l = refusing(1, limits, hour);
        let stalled = |key| l.inner.lock().core.stalled(key).1;
        let key = crate::ListenerConfig::default().source_key([192, 0, 2, 1].into());
        let other_addr = SocketAddr::from(([198, 51, 100, 1], 3));
        let other_key = crate::ListenerConfig::default().source_key(other_addr.ip());
        let (c1, s1) = pair();
        let l1 = l.clone();
        let first = std::thread::spawn(move || l1.handle_pipe(PipeIo::tcp(s1), from(1)));
        let (c3, s3) = pair();
        let l3 = l.clone();
        let other = std::thread::spawn(move || {
            let hint = PipeHint {
                source: Some(other_addr),
            };
            l3.handle_pipe(PipeIo::tcp(s3), hint)
        });
        // Both are stalled once their sources hold a stall.
        while stalled(key) == 0 || stalled(other_key) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        let (c2, s2) = pair();
        let l2 = l.clone();
        let second = std::thread::spawn(move || l2.handle_pipe(PipeIo::tcp(s2), from(2)));
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
            handshake_timeout: Duration::from_secs(3600),
            first_record_timeout: Duration::from_secs(3600),
            max_pending_per_source: 3,
            on_reject: Some(OnReject(std::sync::Arc::new(move |i| {
                seen.lock().unwrap().push((i.profile, i.reason));
                RejectAction::Stall
            }))),
            ..Default::default()
        };
        let l = Listener::new(Config::default(), limits, None).unwrap();
        let key = crate::ListenerConfig::default().source_key([192, 0, 2, 1].into());
        let mut held = Vec::new();
        for port in 1..=3 {
            let (c, s) = pair();
            let lh = l.clone();
            held.push((
                c,
                std::thread::spawn(move || lh.handle_pipe(PipeIo::tcp(s), from(port))),
            ));
        }
        let end = Instant::now() + Duration::from_secs(5);
        while l.inner.lock().core.held(key).1 < 3 {
            assert!(Instant::now() < end, "the carriers never took their slots");
            std::thread::sleep(Duration::from_millis(2));
        }
        let (c, s) = pair();
        assert_eq!(
            l.handle_pipe(PipeIo::tcp(s), from(4)),
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
            handshake_timeout: Duration::from_secs(3600),
            first_record_timeout: Duration::from_secs(3600),
            max_pending_per_source: 2,
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
                    std::thread::spawn(move || lh.handle_pipe(PipeIo::tcp(s), hint)),
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
                l.handle_pipe(PipeIo::tcp(s), at(same)),
                Err(HandleError::Refused)
            );
            closed_silently(c);
            // Another prefix has its own share.
            let (c, s) = pair();
            let (lh, hint) = (l.clone(), at(other));
            held.push((
                c,
                std::thread::spawn(move || lh.handle_pipe(PipeIo::tcp(s), hint)),
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

    /// The listener's bound: stalls hold at most half of it (beyond, `stall_overflow`); a
    /// new carrier with every slot taken evicts the oldest stall, and is closed at once,
    /// counted as rejected, when none is stalled.
    #[test]
    fn the_global_bound_evicts_the_oldest_stall() {
        use crate::proto::listener::{OnReject, RejectAction};
        use std::io::Write;
        let hour = Duration::from_secs(3600);
        let limits = ListenerConfig {
            handshake_timeout: hour,
            first_record_timeout: hour,
            max_pending: Some(2),
            on_reject: Some(OnReject(std::sync::Arc::new(|_| RejectAction::Stall))),
            ..Default::default()
        };
        let mut l = Listener::new(Config::default(), limits, None).unwrap();
        std::sync::Arc::get_mut(&mut l.inner).unwrap().stall_max = hour;
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
            let t = std::thread::spawn(move || lh.handle_pipe(PipeIo::tcp(s), from(port)));
            (c, t)
        };
        let silent = |port: u16| {
            let (c, s) = pair();
            let lh = l.clone();
            let t = std::thread::spawn(move || lh.handle_pipe(PipeIo::tcp(s), from(port)));
            (c, t)
        };
        let (c1, t1) = garbage(1);
        wait("the first is stalled", &|| stalls(&l) == 1);
        // Half of 2 is stalled: the next is closed at once.
        let (c2, t2) = garbage(2);
        assert_eq!(t2.join().unwrap(), Err(HandleError::Rejected));
        closed_silently(c2);
        assert_eq!(l.stats().admission.stall_overflow, 1);
        let (c3, t3) = silent(3);
        wait("the second slot is taken", &|| total(&l) == 2);
        // Every slot taken: the stall goes.
        let (c4, t4) = silent(4);
        assert_eq!(t1.join().unwrap(), Err(HandleError::Rejected));
        closed_silently(c1);
        wait("the new carrier holds the slot", &|| total(&l) == 2);
        assert_eq!(stalls(&l), 0);
        // None stalled: the new one is closed at once.
        let rejected = l.stats().rejected;
        let (c5, s5) = pair();
        assert_eq!(
            l.handle_pipe(PipeIo::tcp(s5), from(5)),
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

    /// A draining listener refuses a new session with CONNECTION_REFUSED after its own
    /// parameters, so that the peer reads why, as the tokio and Go listeners.
    #[test]
    fn a_draining_listener_refuses_with_connection_refused() {
        let l = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        l.inner.lock().draining = true;
        let (c, s) = pair();
        let client = std::thread::spawn(move || {
            match crate::driver::blocking::Session::connect(PipeIo::tcp(c), Config::default()) {
                Ok(s) => {
                    s.set_wait_timeout(Some(Duration::from_secs(5)));
                    s.closing().unwrap()
                }
                Err(crate::ConnectError::SessionLost(e)) => e,
                Err(e) => panic!("not refused: {e:?}"),
            }
        });
        assert_eq!(
            l.handle_pipe(PipeIo::tcp(s), PipeHint::default()),
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
        l.count_setup_failure();
        l.count_setup_failure();
        assert_eq!(l.stats().setup_failures, 2);
    }
}
