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
    CarrierId, Classified, HandleError, ListenerConfig, ListenerCore, ListenerStats, Opened,
    RejectAction, RejectError, RejectInfo, random_locator, source_key,
};
use crate::proto::record::Framing;
use crate::proto::seal::join::JoinHello;
use crate::proto::session::{
    CarrierDescription, ClaimedHello, Config, ConfirmedJoin, OpenedHello, PeerCarrier,
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
}

struct State {
    core: ListenerCore,
    live: Vec<Weak<Shared<Blocking>>>,
    accept: VecDeque<Session>,
    /// The closers of the carriers being set up: eviction and `close` end their calls.
    carriers: HashMap<CarrierId, Arc<Closer>>,
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
            return Err(InvalidConfig("the std driver's listener runs no admission"));
        }
        #[cfg(feature = "tokio")]
        if limits.inbound_transform.is_some() || limits.fallback.is_some() {
            return Err(InvalidConfig(
                "the std driver's listener runs no tokio transform or fallback",
            ));
        }
        if limits.instance_id.len() > crate::proto::listener::MAX_INSTANCE_ID_LEN {
            return Err(InvalidConfig(
                "ListenerConfig::instance_id longer than MAX_INSTANCE_ID_LEN",
            ));
        }
        if limits.max_pending == 0
            || limits.max_pending_per_source == 0
            || limits.max_pending_per_session == 0
        {
            return Err(InvalidConfig(
                "ListenerConfig::max_pending, max_pending_per_source and max_pending_per_session must be at least 1",
            ));
        }
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
        let key = hint.source.map_or(0, |a| source_key(a.ip()));
        let closer = pipe.shared_closer();
        let (limits, id) = {
            let mut st = inner.lock();
            if st.closed {
                return Err(HandleError::Refused);
            }
            let limits = st.core.config().clone();
            let (id, evicted) = match st.core.open(key, pipe.handshake_framing(), Instant::now()) {
                Opened::Accepted { id, evicted } => (id, evicted),
                Opened::Refused => {
                    // Over the pending-carrier limits, checked before anything is read:
                    // the reject policy, holding only a stall slot of the source.
                    drop(st);
                    let info = RejectInfo::new(None, None, "pending_limit", hint.source);
                    self.reject_action(&info, limits.handshake_timeout.min(inner.stall_max));
                    return Err(HandleError::Refused);
                }
            };
            if let Some(c) = &closer {
                st.carriers.insert(id, c.clone());
            }
            let evicted = evicted.and_then(|e| st.carriers.remove(&e));
            drop(st);
            if let Some(c) = evicted {
                c(Shutdown::Both);
            }
            (limits, id)
        };
        let pending = Pending { inner, id };
        let watchdog = closer.map(|c| Watchdog::new(c, limits.handshake_timeout));
        pipe.limit_handshake_wait(limits.handshake_timeout);
        if let Some(t) = &inner.transform {
            pipe = self.transform(t, pipe, &hint, limits.handshake_timeout, watchdog.as_ref())?;
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
                self.join(pipe, &locator, &hello, &limits, hint, &pending)
            }
            Classified::BadHello { reason } => {
                // Stalled, as every refused join, for the listener's join timeout.
                let info = RejectInfo::new(Some(2), None, reason, hint.source);
                self.reject_action(&info, inner.config.join_timeout);
                Err(HandleError::Rejected)
            }
            // First bytes that are no carrier this listener knows (step 2).
            _ => {
                let info = RejectInfo::new(None, None, "malformed", hint.source);
                self.reject_action(&info, limits.handshake_timeout.min(inner.stall_max));
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
                let info = RejectInfo::new(r.profile, r.mode, r.reason, hint.source);
                // The handshake timeout may be none: the stall ends by the
                // listener's maximum.
                self.reject_action(&info, timeout.min(self.inner.stall_max));
                Err(HandleError::Rejected)
            }
        }
    }

    /// The reject policy: closed, or stalled without a byte until the handshake timeout.
    fn reject_action(&self, info: &RejectInfo, timeout: Duration) {
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
            let key = info.source.map_or(0, |a| source_key(a.ip()));
            if !self.inner.lock().core.stall(key) {
                return;
            }
            let until = Instant::now() + timeout;
            let mut st = self.inner.lock();
            while !st.closed {
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
            st.core.unstall(key);
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
        _limits: &ListenerConfig,
        hint: PipeHint,
        pending: &Pending<'_>,
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
            self.reject_action(&info, inner.config.join_timeout);
            return Err(HandleError::Rejected);
        };
        let mode = Some(parsed.mode());
        // A stall lasts the listener's join timeout from the refusal, whether or not the
        // Locator names a session: the response and the way of ending are the same.
        let rejected = |reason: &'static str| {
            let info = RejectInfo::new(Some(2), mode, reason, hint.source);
            self.reject_action(&info, inner.config.join_timeout);
            Err(HandleError::Rejected)
        };
        let Some(session) = session else {
            return rejected("unknown_locator");
        };
        // A Hello in Bound needs a Binding of this carrier (see the tokio listener).
        let binding = if parsed.mode() == crate::proto::seal::Mode::Bound {
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
        let info = CarrierDescription {
            has_exporter: pipe.exporter_ref().is_some(),
            secure: pipe.is_secure(),
            ..CarrierDescription::default()
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
            admission: Default::default(),
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
            assert!(took < Duration::from_millis(want + 700), "{took:?}");
            closed_silently(client);
        }
        let limits = ListenerConfig {
            handshake_timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let l = refusing(2, limits, Duration::from_secs(10));
        let (client, server) = pair();
        let begun = Instant::now();
        assert_eq!(
            l.handle_pipe(PipeIo::tcp(server), from(1)),
            Err(HandleError::Rejected)
        );
        assert!(begun.elapsed() < Duration::from_millis(300));
        closed_silently(client);
    }

    /// A source keeps a slot for a new attempt: with `max_pending_per_source` 2 it stalls
    /// one carrier, and the next refused one from it is closed at once; another source
    /// still stalls. `close` ends the stalls.
    #[test]
    fn a_source_with_its_stalls_full_is_closed_at_once() {
        let limits = ListenerConfig {
            handshake_timeout: Duration::from_secs(10),
            max_pending_per_source: 2,
            ..Default::default()
        };
        let l = refusing(1, limits, Duration::from_secs(10));
        let (c1, s1) = pair();
        let l1 = l.clone();
        let first = std::thread::spawn(move || l1.handle_pipe(PipeIo::tcp(s1), from(1)));
        let (c3, s3) = pair();
        let l3 = l.clone();
        let other = std::thread::spawn(move || {
            let mut hint = from(3);
            hint.source = Some(SocketAddr::from(([198, 51, 100, 1], 3)));
            l3.handle_pipe(PipeIo::tcp(s3), hint)
        });
        // The first is stalled once its source holds a stall.
        let end = Instant::now() + Duration::from_secs(5);
        let key = super::source_key([192, 0, 2, 1].into());
        while l.inner.lock().core.stalled(key) == 0 {
            assert!(Instant::now() < end, "the first carrier never stalled");
            std::thread::sleep(Duration::from_millis(2));
        }
        let (c2, s2) = pair();
        let begun = Instant::now();
        assert_eq!(
            l.handle_pipe(PipeIo::tcp(s2), from(2)),
            Err(HandleError::Rejected)
        );
        assert!(
            begun.elapsed() < Duration::from_millis(300),
            "{:?}",
            begun.elapsed()
        );
        closed_silently(c2);
        assert!(!first.is_finished() && !other.is_finished());
        let closing = Instant::now();
        l.close();
        assert_eq!(first.join().unwrap(), Err(HandleError::Rejected));
        assert_eq!(other.join().unwrap(), Err(HandleError::Rejected));
        assert!(closing.elapsed() < Duration::from_secs(1));
        closed_silently(c1);
        closed_silently(c3);
    }

    /// A carrier over its source's pending limit, checked before anything is read, goes to
    /// the reject policy: `pending_limit`, stalled for the handshake timeout.
    #[test]
    fn a_carrier_over_the_pending_limit_goes_to_the_reject_policy() {
        use crate::proto::listener::{OnReject, RejectAction};
        let reasons = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = reasons.clone();
        let limits = ListenerConfig {
            handshake_timeout: Duration::from_millis(300),
            first_record_timeout: Duration::from_secs(10),
            max_pending_per_source: 3,
            on_reject: Some(OnReject(std::sync::Arc::new(move |i| {
                seen.lock().unwrap().push((i.profile, i.reason));
                RejectAction::Stall
            }))),
            ..Default::default()
        };
        let l = Listener::new(Config::default(), limits, None).unwrap();
        let key = super::source_key([192, 0, 2, 1].into());
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
        while l.inner.lock().core.pending_of(key) < 3 {
            assert!(Instant::now() < end, "the carriers never became pending");
            std::thread::sleep(Duration::from_millis(2));
        }
        let (c, s) = pair();
        let begun = Instant::now();
        assert_eq!(
            l.handle_pipe(PipeIo::tcp(s), from(4)),
            Err(HandleError::Refused)
        );
        let took = begun.elapsed();
        assert!(
            took >= Duration::from_millis(290) && took < Duration::from_secs(2),
            "{took:?}"
        );
        closed_silently(c);
        assert_eq!(*reasons.lock().unwrap(), [(None, "pending_limit")]);
        l.close();
        for (c, t) in held {
            drop(c);
            let _ = t.join().unwrap();
        }
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
                Ok(s) => s.closed(Some(Duration::from_secs(5))).unwrap(),
                Err(crate::ConnectError::Closed(e)) => e,
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
