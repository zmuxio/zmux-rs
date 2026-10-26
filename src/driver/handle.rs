//! The application's handles, shared by both drivers: [`Session`],
//! [`SendStream`], [`RecvStream`], [`Pipe`] and [`PipeReservation`] are
//! generic over the [`Driver`], so that every operation is written once:
//! lock the core, run one command, then either return or register a wait.
//!
//! Waiting operations are futures: the tokio driver awaits them, the std
//! driver runs them on the calling thread, parking it between polls with a
//! waker that unparks it (`blocking::block`). A wait leaves its list when
//! its future is dropped: an `async` caller that is cancelled, or a
//! blocking call that timed out.
//!
//! What differs between the drivers is behind [`Driver`]: their part of the
//! state under the core lock, the work they defer until after it, how they
//! learn that a command produced output (the session task, or the writer
//! threads), the tokio driver's write-through and read-through fast paths
//! (`super::through`), and how a carrier is attached.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};

use super::events::EventQueue;
use super::hooks::{HookStart, Trace, TraceQueue, WindowHook, ask, trace};
use super::resources::{Kind, Live};
use super::sync::Mutex;
use super::wait::{Attempt, List, Open, Wait, Waiters, Waiting, open_now};
use super::wake::{Defer, Locked, WakeList};
use super::{Event as AppEvent, GoAway, PipeDirection, StreamId};
use crate::error::{ConnectError, ReadExactError, ReadToEndError};
use crate::proto::VarInt;
use crate::proto::frame::{Dir, Priority};
use crate::proto::limit::{self, DatagramLimiter};
use crate::proto::meter::Meter;
use crate::proto::params::Role;
use crate::proto::record::Framing;
use crate::proto::session::{
    self as core, CapacityFloor, Config, CoreEvent, DatagramError, LaneId, Multipath, OpenError,
    PipeError, PipeHalf, PipeId, PipeOptions, PipeStats, PipeWrite, Policy, Preamble, QualityBand,
    ReceivedDatagram, RoleConfig, SendOutcomeKind, SessionError, SessionStats, State as CoreState,
    StreamError, StreamKey, StreamStats,
};
#[cfg(feature = "tokio")]
use crate::proto::session::{Piece, PieceCursor, TransmitBuf};

/// A driver of sessions: the tokio driver (`Tokio`, feature `tokio`) or the
/// std driver (`Blocking`, feature `blocking`). Sealed: its items are the
/// drivers' internals.
pub trait Driver: sealed::Sealed + Sized + Send + Sync + 'static {
    /// The driver's part of the session state, under the core lock.
    #[doc(hidden)]
    type Io: Send;
    /// Work the driver decides under the core lock and does after it.
    #[doc(hidden)]
    type Deferred: Default + Send;
    /// The driver's part of the session outside the core lock.
    #[doc(hidden)]
    type Paths: Send + Sync;
    /// The driver's carrier type (`PipeIo`).
    #[doc(hidden)]
    type Carrier: Send;
    /// What a stream handle keeps for blocking calls (their timeout).
    #[doc(hidden)]
    type Timeout: Copy + Default + Send + Sync + Unpin;
    /// The application's dial function (`zmux::Dial`,
    /// `zmux::blocking::Dial`).
    #[doc(hidden)]
    type Dial: Clone + Send + Sync + 'static;

    /// The session clock.
    #[doc(hidden)]
    fn now() -> Instant;

    /// Whether deferred work is pending.
    #[doc(hidden)]
    fn deferred_pending(deferred: &Self::Deferred) -> bool;

    /// The core asked to close a carrier half.
    #[doc(hidden)]
    fn close_pipe(state: &mut State<Self>, pipe: u64, half: PipeHalf, abort: bool);

    /// The core asks for a lane of an outbound pipe (MULTIPATH.md Section
    /// 5.8): a driver whose carriers have no lanes refuses it, which costs
    /// the pipe nothing.
    #[doc(hidden)]
    fn open_lane(state: &mut State<Self>, lane: LaneId) {
        state
            .core
            .write_failed(lane, std::io::ErrorKind::Unsupported, Self::now());
    }

    /// The core resets an outbound lane not confirmed in time.
    #[doc(hidden)]
    fn reset_lane(_state: &mut State<Self>, _lane: LaneId) {}

    /// The session is CLOSED (in the critical section that closed it): the
    /// driver releases what it keeps for new lanes and pipes, which the
    /// session takes no more.
    #[doc(hidden)]
    fn session_closed(_state: &mut State<Self>) {}

    /// The driver has work outside the application's commands (a hook to
    /// start): wake whoever does it.
    #[doc(hidden)]
    fn wake_driver(state: &mut State<Self>);

    /// After a command's events were dispatched: wake whoever writes when
    /// the core has output, and whoever runs timers when they changed.
    #[doc(hidden)]
    fn kick(state: &mut State<Self>);

    /// Ends a command that may have produced output (the tokio driver
    /// writes it through when it can).
    #[doc(hidden)]
    fn finish_write<'a>(_shared: &'a Shared<Self>, mut locked: Lock<'a, Self>) {
        locked.after_command();
    }

    /// An application read found nothing: the tokio driver reads the
    /// carrier through. Returns the core, locked, and whether it was
    /// unlocked meanwhile (the caller looks again before it waits).
    #[doc(hidden)]
    fn read_through<'a>(
        _shared: &'a Shared<Self>,
        locked: Lock<'a, Self>,
        _reader: &Waker,
    ) -> (Lock<'a, Self>, bool) {
        (locked, false)
    }

    /// The carrier's halves, binding and protocol.
    #[doc(hidden)]
    fn carrier_info(carrier: &mut Self::Carrier) -> CarrierInfo;

    /// Whether `carrier` may become a pipe of the session: not when it
    /// runs over the session itself (EXTENSIONS.md Section 10.2).
    #[doc(hidden)]
    fn check_carrier(
        _shared: &Arc<Shared<Self>>,
        _carrier: &Self::Carrier,
    ) -> Result<(), PipeError> {
        Ok(())
    }

    /// Starts the I/O of pipe `id` on `carrier` (an added pipe).
    #[doc(hidden)]
    fn attach(shared: &Arc<Shared<Self>>, id: u64, carrier: Self::Carrier)
    -> Result<(), PipeError>;

    /// Starts `dial` in the background (a task or a thread), adding the
    /// carrier it dials to `session` if the session is still in use; a
    /// failed dial or add is dropped. Returns whether it was started.
    #[doc(hidden)]
    fn start_rejoin(session: WeakSession<Self>, dial: Self::Dial) -> bool;

    /// The driver's tables for the leak tests: waits, closes, new pipes.
    #[doc(hidden)]
    #[cfg(feature = "test-hooks")]
    fn io_tables(io: &Self::Io) -> (usize, usize, usize, usize);
}

/// Implemented by the drivers only.
mod sealed {
    pub trait Sealed {}
    #[cfg(feature = "blocking")]
    impl Sealed for super::super::blocking::Blocking {}
    #[cfg(feature = "tokio")]
    impl Sealed for super::super::tokio::Tokio {}
}

/// What the core needs to know about a carrier.
pub struct CarrierInfo {
    pub(crate) inbound: Option<Framing>,
    pub(crate) outbound: Option<Framing>,
    pub(crate) exporter: Option<Box<Exporters>>,
    pub(crate) protocol: Option<String>,
}

/// A carrier's TLS 1.3 exporter values for the labels zmux uses
/// (MULTIPATH.md Sections 10.2 and 10.5), taken when the carrier is made.
#[derive(Debug, Clone)]
pub(crate) struct Exporters {
    /// `EXPORTER-zmux-session`: the session secret's input.
    pub(crate) session: Vec<u8>,
    /// `EXPORTER-zmux-pipe`: a carrier-bound join's binding.
    pub(crate) pipe: Vec<u8>,
}

impl Exporters {
    /// The values `export` gives for both labels, if it gives them with
    /// their lengths (MULTIPATH.md Sections 10.2 and 10.5): 32 bytes, or
    /// 64 for the session label of a split bootstrap. Anything else is no
    /// exporter, never an empty binding that would turn the check off.
    pub(crate) fn take(mut export: impl FnMut(&str) -> Option<Vec<u8>>) -> Option<Box<Self>> {
        use crate::proto::keys::{EXPORTER_PIPE_LABEL, EXPORTER_SESSION_LABEL};
        let session = export(EXPORTER_SESSION_LABEL).filter(|v| v.len() == 32 || v.len() == 64)?;
        let pipe = export(EXPORTER_PIPE_LABEL).filter(|v| v.len() == 32)?;
        Some(Box::new(Self { session, pipe }))
    }
}

/// The work of a critical section done after the unlock, in field order:
/// the driver's, then the wake-ups.
pub struct AfterUnlock<X> {
    _deferred: X,
    _wakes: WakeList,
}

/// The state of a session behind its core lock.
pub struct State<D: Driver> {
    pub(super) core: core::SessionCore,
    pub(super) waiters: Waiters<StreamKey>,
    /// Wake-ups decided under the lock, delivered after it.
    pub(super) wakes: WakeList,
    /// The driver's work for after the lock.
    pub(super) deferred: D::Deferred,
    /// Application handles (sessions and streams) alive.
    handles: usize,
    established: bool,
    /// The core was seen CLOSED ([`Driver::session_closed`] ran).
    closed_seen: bool,
    /// This endpoint established the bootstrap carrier (EXTENSIONS.md
    /// Section 11), when known.
    dialer: Option<bool>,
    goaway: Option<GoAway>,
    /// Session events for the application.
    events: EventQueue,
    /// Out-of-band join frames the core handed out, by pipe, until their
    /// reservation takes or gives them up.
    oob: Vec<(u64, Bytes)>,
    protocol: Option<String>,
    /// `allow_connection_window_increase`'s mailbox.
    window_hook: WindowHook,
    /// The tracer's queue, with a tracer.
    traces: Option<Box<TraceQueue>>,
    /// The hook context is to be started (by the driver, after the lock;
    /// [`State::take_hook_start`]).
    start_hook: bool,
    /// The datagram limiters, until [`Shared::new`] takes them.
    datagram_limiter: DatagramLimiter,
    /// Received datagrams on their way past the receive limiter (reused).
    datagram_batch: Vec<ReceivedDatagram>,
    pub(super) io: D::Io,
}

/// The core lock of a session.
pub(crate) type Lock<'a, D> = Locked<'a, State<D>>;

impl<D: Driver> Defer for State<D> {
    type After = AfterUnlock<D::Deferred>;

    fn take_after(&mut self) -> Option<Self::After> {
        (!self.wakes.is_empty() || D::deferred_pending(&self.deferred)).then(|| AfterUnlock {
            _deferred: std::mem::take(&mut self.deferred),
            _wakes: std::mem::take(&mut self.wakes),
        })
    }
}

impl<D: Driver> Waiting for State<D> {
    type Key = StreamKey;

    fn waits(&mut self) -> (&mut Waiters<StreamKey>, &mut WakeList) {
        (&mut self.waiters, &mut self.wakes)
    }
}

const fn di(dir: Dir) -> usize {
    match dir {
        Dir::Bidi => 0,
        Dir::Uni => 1,
    }
}

impl<D: Driver> State<D> {
    /// A session on a bootstrap carrier: the core with the carrier attached.
    pub(crate) fn new(
        config: Arc<Config>,
        role: RoleConfig,
        transport: Option<Role>,
        locator: Option<&[u8]>,
        carrier: CarrierInfo,
        io: D::Io,
    ) -> Result<Self, ConnectError> {
        let now = D::now();
        let events = EventQueue::new(&config);
        let mut window_hook = WindowHook::new(&config);
        // A tracer starts the hook context with the session.
        let traces = config
            .tracer
            .clone()
            .map(|tracer| Box::new(TraceQueue::new(tracer)));
        let start_hook = traces.is_some();
        if start_hook {
            window_hook.mark_started();
        }
        let datagram_limiter = config.datagram_limiter.clone();
        let mut core = core::SessionCore::new(config, role, transport, now)
            .map_err(ConnectError::InvalidConfig)?;
        if let Some(l) = locator {
            core.set_locator(l).map_err(ConnectError::InvalidConfig)?;
        }
        if let Some(e) = &carrier.exporter {
            core.set_bootstrap_exporter(&e.session);
        }
        core.attach_bootstrap(carrier.inbound, carrier.outbound, now);
        Ok(Self {
            core,
            waiters: Waiters::default(),
            wakes: WakeList::default(),
            deferred: D::Deferred::default(),
            handles: 0,
            established: false,
            closed_seen: false,
            dialer: transport.map(|r| r == Role::Initiator),
            goaway: None,
            events,
            oob: Vec::new(),
            protocol: carrier.protocol,
            window_hook,
            traces,
            start_hook,
            datagram_limiter,
            datagram_batch: Vec::new(),
            io,
        })
    }

    /// Drains the core's events and wakes the operations they concern.
    pub(crate) fn dispatch(&mut self) {
        while let Some(e) = self.core.poll_event() {
            let w = &mut self.waiters;
            let wakes = &mut self.wakes;
            match e {
                CoreEvent::Established { protocol, .. } => {
                    self.established = true;
                    // The carrier's own protocol (ALPN) wins.
                    if self.protocol.is_none() {
                        self.protocol = protocol.map(String::from);
                    }
                    w.wake_list(List::State, wakes);
                    self.trace(Trace::Established);
                }
                CoreEvent::StreamOpened(d) => w.wake_list(List::Accept(di(d)), wakes),
                CoreEvent::StreamReadable(k) => w.readable(k, wakes),
                CoreEvent::StreamWritable(k) => w.writable(k, wakes),
                CoreEvent::StreamDatagram(k) => w.stream_datagram(k, wakes),
                CoreEvent::StreamsAvailable(d) => w.open[di(d)].credit(wakes),
                CoreEvent::DatagramReceived => w.wake_list(List::DatagramRecv, wakes),
                CoreEvent::DatagramsUnblocked => w.wake_list(List::DatagramSend, wakes),
                CoreEvent::GoAway {
                    max_bidi,
                    max_uni,
                    code,
                } => {
                    let g = GoAway {
                        max_bidi,
                        max_uni,
                        code,
                    };
                    self.goaway = Some(g);
                    w.fail_opens(wakes);
                    self.app_event(AppEvent::GoAway(g));
                }
                CoreEvent::ClosePipe { pipe, half, abort } => {
                    D::close_pipe(self, pipe.0, half, abort)
                }
                CoreEvent::OpenLane(lane) => D::open_lane(self, lane),
                CoreEvent::ResetLane(lane) => D::reset_lane(self, lane),
                CoreEvent::OobJoin { pipe, frame } => self.oob.push((pipe.0, frame)),
                CoreEvent::PipeState { pipe, half, state } => {
                    let failure = (state == core::PipeState::Failed)
                        .then(|| self.core.pipe_failure(pipe))
                        .flatten();
                    self.waiters.wake_list(List::Pipes, &mut self.wakes);
                    self.app_event(AppEvent::PipeState {
                        pipe,
                        half,
                        state,
                        failure,
                    });
                }
                CoreEvent::JoinAuthFailed { carrier_bound } => {
                    self.app_event(AppEvent::JoinAuthFailed {
                        carrier_bound,
                        count: 1,
                    });
                }
                CoreEvent::JoinSecurityUnavailable => {
                    self.app_event(AppEvent::JoinSecurityUnavailable);
                }
                CoreEvent::PipePriorityChanged {
                    pipe,
                    send_priority,
                    standby,
                    weight,
                    source,
                } => self.app_event(AppEvent::PipePriorityChanged {
                    pipe,
                    send_priority,
                    standby,
                    weight,
                    source,
                }),
                CoreEvent::TierSaturation {
                    priority,
                    saturated,
                } => self.app_event(AppEvent::TierSaturation {
                    priority,
                    saturated,
                }),
                CoreEvent::WindowIncrease => {
                    if self.window_hook.offer(&mut self.core) {
                        self.start_hook = true;
                        D::wake_driver(self);
                    }
                    if self.window_hook.pending() {
                        self.waiters.wake_list(List::Hook, &mut self.wakes);
                    }
                }
                CoreEvent::PipeQualityChanged {
                    pipe,
                    smoothed_rtt,
                    delivery_rate,
                } => self.app_event(AppEvent::PipeQualityChanged {
                    pipe,
                    smoothed_rtt,
                    delivery_rate,
                }),
                CoreEvent::CapacityBelow { rate } => {
                    self.app_event(AppEvent::CapacityBelow { rate });
                }
                CoreEvent::CapacityRestored { rate } => {
                    self.app_event(AppEvent::CapacityRestored { rate });
                }
                CoreEvent::Suspended => self.app_event(AppEvent::Suspended),
                CoreEvent::Resumed => self.app_event(AppEvent::Resumed),
                CoreEvent::PingAnswered { .. } => w.wake_list(List::Ping, wakes),
                CoreEvent::Closed(e) => {
                    w.close(wakes);
                    self.trace(Trace::Closed(e));
                }
                _ => {}
            }
        }
        if !self.closed_seen && self.core.state() == core::State::Closed {
            self.closed_seen = true;
            D::session_closed(self);
        }
    }

    fn app_event(&mut self, e: AppEvent) {
        if self.traces.is_some() {
            self.trace(Trace::Event(e.clone()));
        }
        self.events.push(e);
        self.waiters.wake_list(List::Events, &mut self.wakes);
    }

    /// The hooks to run on the hook context, once it is to be started.
    pub(crate) fn take_hook_start(&mut self) -> Option<HookStart> {
        std::mem::take(&mut self.start_hook).then(|| HookStart {
            predicate: self.window_hook.predicate(),
            tracer: self.traces.as_deref().map(|t| t.tracer.clone()),
        })
    }

    /// Queues an item for the tracer, if there is one.
    fn trace(&mut self, item: Trace) {
        if let Some(t) = self.traces.as_deref_mut() {
            t.push(item);
            self.waiters.wake_list(List::Hook, &mut self.wakes);
        }
    }

    /// After an application command: dispatch its events and wake the
    /// driver if it has something to do.
    pub(crate) fn after_command(&mut self) {
        self.dispatch();
        D::kick(self);
    }

    /// Takes the out-of-band frame of pipe `id`, if the core handed one out.
    fn take_oob(&mut self, id: u64) -> Option<Bytes> {
        let i = self.oob.iter().position(|(p, _)| *p == id)?;
        Some(self.oob.swap_remove(i).1)
    }
}

/// A stream the core opened or offered, with its meter.
type Opened = (StreamKey, Arc<Meter>);

/// The meter of a stream the core holds (a stream it just opened or
/// offered always is).
fn with_meter<D: Driver>(core: &mut core::SessionCore, key: StreamKey) -> Opened {
    let meter = core
        .stream_meter(key)
        .unwrap_or_else(|| Arc::new(Meter::new(D::now())));
    (key, meter)
}

/// The core's answer to opening a stream, for the openers' queue.
fn attempt<D: Driver>(
    core: &mut core::SessionCore,
    dir: Dir,
    preamble: Option<&Preamble>,
) -> Attempt<Opened, OpenError> {
    let opened = match preamble {
        Some(p) => core.open_with(dir, p),
        None => core.open(dir),
    };
    match opened {
        Ok(k) => Attempt::Opened(with_meter::<D>(core, k)),
        Err(OpenError::Blocked) => Attempt::Blocked,
        Err(e) => Attempt::Failed(e),
    }
}

/// A session's shared part: the state behind the core lock, and the
/// driver's paths outside it.
pub struct Shared<D: Driver> {
    pub(crate) inner: Mutex<State<D>>,
    // The std driver has no paths.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) paths: D::Paths,
    /// The session's application byte counters, read without the lock.
    meter: Arc<Meter>,
    /// The datagram limiters, called without the lock.
    datagram_limiter: DatagramLimiter,
    _live: Live,
}

impl<D: Driver> Shared<D> {
    pub(crate) fn new(mut state: State<D>, paths: D::Paths) -> Self {
        let meter = state.core.meter().clone();
        let datagram_limiter = std::mem::take(&mut state.datagram_limiter);
        Self {
            inner: Mutex::new(state),
            paths,
            meter,
            datagram_limiter,
            _live: Live::new(Kind::Session),
        }
    }

    /// After input: the received datagrams the core holds for the receive
    /// limiter pass it here, outside the lock, and go
    /// back to the core with the verdicts. Takes the lock of the critical
    /// section that received them; returns the core locked again, and
    /// whether it was unlocked meanwhile.
    pub(crate) fn police_datagrams<'a>(&'a self, mut locked: Lock<'a, D>) -> (Lock<'a, D>, bool) {
        let Some(limiter) = self.datagram_limiter.receive.as_deref() else {
            return (locked, false);
        };
        if !locked.core.has_received_datagrams() {
            return (locked, false);
        }
        let mut batch = std::mem::take(&mut locked.datagram_batch);
        locked.core.take_received_datagrams(&mut batch);
        drop(locked);
        // A limiter that panics leaves the datagrams to the guard, which
        // hands them back refused: their bytes never stay counted.
        let mut guard = Policed {
            shared: self,
            batch,
        };
        for d in &mut guard.batch {
            d.set_allowed(limit::police(limiter, d.payload_len()));
        }
        let mut batch = std::mem::take(&mut guard.batch);
        drop(guard);
        let mut locked = self.lock();
        locked.core.admit_datagrams(&mut batch);
        locked.datagram_batch = batch;
        locked.dispatch();
        (locked, true)
    }

    /// Whether the send limiter allows a datagram of `len` payload bytes,
    /// asked before the lock.
    fn datagram_allowed(&self, len: usize) -> bool {
        limit::allows(self.datagram_limiter.send.as_deref(), len)
    }

    /// Charges the send limiter for a datagram queued, after the lock.
    fn datagram_queued(
        &self,
        queued: Result<bool, DatagramError>,
        len: usize,
    ) -> Result<(), DatagramError> {
        if queued? {
            limit::charge(self.datagram_limiter.send.as_deref(), len);
        }
        Ok(())
    }

    /// Locks the core.
    pub(crate) fn lock(&self) -> Lock<'_, D> {
        Locked::lock(&self.inner)
    }

    /// Runs one command and ends it.
    fn command<R>(&self, f: impl FnOnce(&mut State<D>) -> R) -> R {
        let mut st = self.lock();
        let r = f(&mut st);
        st.after_command();
        r
    }

    /// Waits until the session is established. The handle is counted at
    /// once: dropping the future before establishment closes the session.
    pub(crate) fn established(
        self: Arc<Self>,
    ) -> impl Future<Output = Result<Session<D>, ConnectError>> {
        let conn = ConnRef::new(self);
        async move {
            Wait::new(&conn.inner, List::State, |st: &mut State<D>| {
                // With early data the session is usable as soon as its
                // parameters are written.
                if st.established || st.core.early_data_open() {
                    return Some(Ok(()));
                }
                st.core
                    .error()
                    .map(|e| Err(ConnectError::Closed(e.clone())))
            })
            .await?;
            Ok(Session { conn })
        }
    }
}

/// Work for the hook context.
enum HookWork {
    Window(u64, u64),
    Trace(std::collections::VecDeque<Trace>),
}

/// The session's hook context (a task or a thread): runs
/// `allow_connection_window_increase` for each proposal and tells the
/// tracer the session's events, outside every lock and off the session's
/// I/O, until the session ended and the tracer was told.
pub(crate) async fn run_hook<D: Driver>(shared: Arc<Shared<D>>, hooks: HookStart) {
    let _live = Live::new(Kind::Hook);
    loop {
        let next = Wait::new(&shared.inner, List::Hook, |st: &mut State<D>| {
            if let Some((generation, delta)) = st.window_hook.take() {
                return Some(Some(HookWork::Window(generation, delta)));
            }
            if let Some(items) = st.traces.as_deref_mut().and_then(TraceQueue::take) {
                return Some(Some(HookWork::Trace(items)));
            }
            let traced = st.traces.as_deref().is_none_or(TraceQueue::finished);
            (st.core.error().is_some() && traced).then_some(None)
        })
        .await;
        match next {
            None => return,
            Some(HookWork::Trace(items)) => {
                if let Some(t) = &hooks.tracer {
                    trace(t, items);
                }
            }
            Some(HookWork::Window(generation, delta)) => {
                let approved = hooks.predicate.as_ref().is_some_and(|p| ask(p, delta));
                let mut st = shared.lock();
                st.core.answer_window_increase(generation, approved);
                st.after_command();
            }
        }
    }
}

#[cfg(feature = "blocking")]
impl<D: Driver> State<D> {
    /// The hook context could not be started: the proposal is refused, so
    /// that the core proposes again later.
    pub(crate) fn hook_not_started(&mut self) {
        self.window_hook.not_started(&mut self.core);
        self.traces = None;
    }
}

/// A counted reference: the session closes with code 0 when the last
/// session and stream handle is dropped.
pub(crate) struct ConnRef<D: Driver>(Arc<Shared<D>>);

impl<D: Driver> ConnRef<D> {
    fn new(shared: Arc<Shared<D>>) -> Self {
        shared.lock().handles += 1;
        Self(shared)
    }
}

impl<D: Driver> Clone for ConnRef<D> {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl<D: Driver> Drop for ConnRef<D> {
    fn drop(&mut self) {
        let mut st = self.0.lock();
        st.handles -= 1;
        if st.handles == 0 {
            st.core.close(VarInt::ZERO, b"", D::now());
            st.after_command();
        }
    }
}

impl<D: Driver> std::ops::Deref for ConnRef<D> {
    type Target = Shared<D>;

    fn deref(&self) -> &Shared<D> {
        &self.0
    }
}

/// A reference to a session that does not keep it in use: a background
/// job's (a rejoin's dial), which must not delay the close that dropping
/// the application's last handle starts.
pub struct WeakSession<D: Driver>(std::sync::Weak<Shared<D>>);

impl<D: Driver> WeakSession<D> {
    /// The weak handle of a session's shared state.
    #[cfg(feature = "tokio")]
    pub(crate) fn from_weak(shared: std::sync::Weak<Shared<D>>) -> Self {
        Self(shared)
    }

    /// A handle, while the application still holds one.
    pub(crate) fn upgrade(&self) -> Option<Session<D>> {
        let shared = self.0.upgrade()?;
        let mut st = shared.lock();
        if st.handles == 0 {
            return None;
        }
        st.handles += 1;
        drop(st);
        Some(Session {
            conn: ConnRef(shared),
        })
    }
}

/// Closes the session when dropped: a graceful shutdown cancelled before
/// the session ended.
struct CloseOnDrop<'a, D: Driver> {
    session: &'a Session<D>,
    code: VarInt,
    reason: &'a [u8],
}

impl<D: Driver> Drop for CloseOnDrop<'_, D> {
    fn drop(&mut self) {
        self.session.close(self.code, self.reason);
    }
}

/// The result of a graceful shutdown: the local application close it
/// requested, or the error that ended the session first.
fn shutdown_result(e: SessionError) -> Result<(), SessionError> {
    match e {
        SessionError::ApplicationClosed { remote: false, .. } => Ok(()),
        e => Err(e),
    }
}

// ---- sessions ------------------------------------------------------------------------

/// A zmux session: `zmux::Session` with the tokio
/// driver, `zmux::blocking::Session` with the std driver. Clones share the
/// session; it closes with code 0 when the last session and stream handle
/// is dropped.
pub struct Session<D: Driver> {
    conn: ConnRef<D>,
}

impl<D: Driver> Clone for Session<D> {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
        }
    }
}

impl<D: Driver> std::fmt::Debug for Session<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.stable_id())
            .finish()
    }
}

impl<D: Driver> Session<D> {
    /// The session's shared state.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn shared(&self) -> &Arc<Shared<D>> {
        &self.conn.0
    }

    fn command<R>(&self, f: impl FnOnce(&mut State<D>) -> R) -> R {
        self.conn.command(f)
    }

    fn send_stream(&self, (key, meter): Opened) -> SendStream<D> {
        SendStream {
            conn: self.conn.clone(),
            key,
            meter,
            timeout: D::Timeout::default(),
        }
    }

    fn recv_stream(&self, (key, meter): Opened) -> RecvStream<D> {
        RecvStream {
            conn: self.conn.clone(),
            key,
            meter,
            timeout: D::Timeout::default(),
        }
    }

    fn bidi(&self, (key, meter): Opened) -> (SendStream<D>, RecvStream<D>) {
        (
            self.send_stream((key, meter.clone())),
            self.recv_stream((key, meter)),
        )
    }

    /// Opens a stream of type `dir` with `preamble`, waiting for stream
    /// credit in arrival order. Dropped while waiting, the opener gives up
    /// its place.
    fn open_key<'a>(
        &'a self,
        dir: Dir,
        preamble: Option<&'a Preamble>,
    ) -> impl Future<Output = Result<Opened, OpenError>> + 'a {
        Open::new(
            &self.conn.inner,
            di(dir),
            move |st: &mut State<D>| attempt::<D>(&mut st.core, dir, preamble),
            State::after_command,
        )
    }

    pub(crate) async fn open_bi_wait(
        &self,
        preamble: Option<&Preamble>,
    ) -> Result<(SendStream<D>, RecvStream<D>), OpenError> {
        Ok(self.bidi(self.open_key(Dir::Bidi, preamble).await?))
    }

    pub(crate) async fn open_uni_wait(
        &self,
        preamble: Option<&Preamble>,
    ) -> Result<SendStream<D>, OpenError> {
        Ok(self.send_stream(self.open_key(Dir::Uni, preamble).await?))
    }

    fn try_open(&self, dir: Dir, preamble: Option<&Preamble>) -> Result<Opened, OpenError> {
        self.command(|st| {
            open_now(&st.waiters.open[di(dir)], || {
                attempt::<D>(&mut st.core, dir, preamble)
            })
            .unwrap_or(Err(OpenError::Blocked))
        })
    }

    fn accept_key(&self, dir: Dir) -> impl Future<Output = Result<Opened, SessionError>> + '_ {
        Wait::new(
            &self.conn.inner,
            List::Accept(di(dir)),
            move |st: &mut State<D>| {
                let r = st
                    .core
                    .accept(dir)
                    .map(|k| k.map(|k| with_meter::<D>(&mut st.core, k)))
                    .transpose();
                // The first accept may grant lazy stream credit.
                st.after_command();
                r
            },
        )
    }

    pub(crate) async fn accept_bi_wait(
        &self,
    ) -> Result<(SendStream<D>, RecvStream<D>), SessionError> {
        Ok(self.bidi(self.accept_key(Dir::Bidi).await?))
    }

    pub(crate) async fn accept_uni_wait(&self) -> Result<RecvStream<D>, SessionError> {
        Ok(self.recv_stream(self.accept_key(Dir::Uni).await?))
    }

    pub(crate) async fn send_datagram_wait_op(&self, data: Bytes) -> Result<(), DatagramError> {
        let len = data.len();
        let allowed = self.conn.datagram_allowed(len);
        let mut data = Some(data);
        // A datagram the limiter refused does not wait for room.
        let queued = Wait::new(
            &self.conn.inner,
            List::DatagramSend,
            move |st: &mut State<D>| {
                if allowed && st.core.datagram_queue_full() && st.core.error().is_none() {
                    return None;
                }
                let r = st
                    .core
                    .send_datagram(data.take().unwrap_or_default(), allowed);
                st.after_command();
                Some(r)
            },
        )
        .await;
        self.conn.datagram_queued(queued, len)
    }

    pub(crate) fn read_datagram_op(
        &self,
    ) -> impl Future<Output = Result<Bytes, SessionError>> + '_ {
        Wait::new(&self.conn.inner, List::DatagramRecv, |st: &mut State<D>| {
            st.core.recv_datagram().transpose()
        })
    }

    pub(crate) async fn shutdown_op(
        &self,
        code: VarInt,
        reason: &[u8],
    ) -> Result<(), SessionError> {
        self.command(|st| {
            st.core.shutdown(code, reason, D::now());
            // No stream opens from now on: waiting openers fail.
            st.waiters.fail_opens(&mut st.wakes);
        });
        // Cancelled (the future dropped before the end), the shutdown
        // falls back to an immediate close.
        let guard = CloseOnDrop {
            session: self,
            code,
            reason,
        };
        let r = shutdown_result(self.closed_op().await);
        std::mem::forget(guard);
        r
    }

    pub(crate) fn closed_op(&self) -> impl Future<Output = SessionError> + '_ {
        Wait::new(&self.conn.inner, List::State, |st: &mut State<D>| {
            st.core.error().cloned()
        })
    }

    pub(crate) async fn ping_op(&self) -> Result<Duration, SessionError> {
        let ticket = self.command(|st| st.core.ping())?;
        Wait::new(
            &self.conn.inner,
            List::Ping,
            move |st: &mut State<D>| match st.core.ping_rtt(ticket) {
                Some(rtt) => Some(Ok(rtt)),
                None => st.core.error().cloned().map(Err),
            },
        )
        .await
    }

    /// Whether multipath is in use.
    pub(crate) fn is_multipath(&self) -> bool {
        self.conn.lock().core.is_multipath()
    }

    /// Whether this endpoint has room for a join of its own now (see the
    /// core's `join_wanted`).
    pub(crate) fn join_wanted(&self) -> bool {
        self.conn.lock().core.join_wanted(D::now())
    }

    /// A reference that does not keep the session in use.
    pub(crate) fn downgrade(&self) -> WeakSession<D> {
        WeakSession(Arc::downgrade(&self.conn.0))
    }

    /// Starts a graceful shutdown without waiting for it (see
    /// `shutdown`): GOAWAY when it is in use, no new streams, and the
    /// close once no stream remains.
    pub(crate) fn begin_shutdown(&self, code: VarInt, reason: &[u8]) {
        self.command(|st| {
            st.core.shutdown(code, reason, D::now());
            st.waiters.fail_opens(&mut st.wakes);
        });
    }

    /// Starts the I/O of a pipe the core knows; if that fails, the pipe
    /// fails.
    fn attach(&self, id: PipeId, pipe: D::Carrier) -> Result<Pipe<D>, PipeError> {
        if let Err(e) = D::attach(&self.conn.0, id.0, pipe) {
            self.command(|st| {
                st.take_oob(id.0);
                let _ = st.core.remove_pipe(id, false, D::now());
            });
            return Err(e);
        }
        Ok(Pipe {
            conn: self.conn.clone(),
            id,
        })
    }

    pub(crate) fn next_event_op(&self) -> impl Future<Output = Option<AppEvent>> + '_ {
        Wait::new(&self.conn.inner, List::Events, |st: &mut State<D>| {
            if let Some(e) = st.events.pop() {
                return Some(Some(e));
            }
            st.core.error().is_some().then_some(None)
        })
    }

    /// Unread event slots (tests of the queue's bound).
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn event_backlog(&self) -> usize {
        self.conn.lock().events.len()
    }

    /// The sizes of the session's driver tables, for leak tests.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn debug_tables(&self) -> super::resources::Tables {
        let st = self.conn.lock();
        let (waits, closing, new_pipes, lane_state) = D::io_tables(&st.io);
        super::resources::Tables {
            waits: st.waiters.entries() + waits,
            pipe_events: st.events.len(),
            oob: st.oob.len(),
            closing,
            new_pipes,
            lane_state,
            held_bytes: st.core.held_bytes(),
            memory_usage: st.core.memory_usage(),
            streams: st.core.stats().streams_active,
        }
    }
}

// ---- pipes ------------------------------------------------------------------------------

/// A pipe of a session: pipe 0, a pipe this
/// endpoint added or reserved, or one the peer joined
/// ([`Session::pipes`](crate::Session#method.pipes)). The setters return
/// [`PipeError::NotNegotiated`] on a session without multipath.
pub struct Pipe<D: Driver> {
    conn: ConnRef<D>,
    id: PipeId,
}

impl<D: Driver> Clone for Pipe<D> {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            id: self.id,
        }
    }
}

impl<D: Driver> std::fmt::Debug for Pipe<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipe").field("id", &self.id).finish()
    }
}

impl<D: Driver> Pipe<D> {
    fn command<R>(&self, f: impl FnOnce(&mut core::SessionCore, PipeId) -> R) -> R {
        self.conn.command(|st| f(&mut st.core, self.id))
    }

    /// Waits until the pipe's join is confirmed (the outbound pipe ACTIVE,
    /// an inbound-only pipe open; pipe 0 once established), or fails: the
    /// join failed or timed out ([`PipeError::Failed`]), the pipe is gone,
    /// the session ended. Adding a pipe never waits; this does.
    pub(crate) fn joined_op(&self) -> impl Future<Output = Result<(), PipeError>> + '_ {
        let id = self.id;
        Wait::new(&self.conn.inner, List::Pipes, move |st: &mut State<D>| {
            st.core.pipe_joined(id)
        })
    }
}

impl<D: Driver> Pipe<D> {
    /// Waits until the pipe ended (see the core's `pipe_closed`).
    pub(crate) fn closed_op(&self) -> impl Future<Output = Result<(), PipeError>> + '_ {
        let id = self.id;
        Wait::new(&self.conn.inner, List::Pipes, move |st: &mut State<D>| {
            st.core.pipe_closed(id)
        })
    }

    /// The session the pipe belongs to.
    pub(crate) fn session_handle(&self) -> Session<D> {
        Session {
            conn: self.conn.clone(),
        }
    }
}

/// A pipe reserved for an out-of-band join (MULTIPATH.md Section 5.3).
/// Dropping it gives the reservation up: the pipe fails (its ID stays
/// used).
#[must_use = "dropping a reservation gives it up"]
pub struct PipeReservation<D: Driver> {
    conn: Option<ConnRef<D>>,
    id: PipeId,
    frame: Bytes,
}

impl<D: Driver> std::fmt::Debug for PipeReservation<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeReservation")
            .field("id", &self.id)
            .finish()
    }
}

impl<D: Driver> PipeReservation<D> {}

impl<D: Driver> Drop for PipeReservation<D> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let id = self.id;
            conn.command(|st| {
                st.take_oob(id.0);
                let _ = st.core.remove_pipe(id, false, D::now());
            });
        }
    }
}

// ---- streams ------------------------------------------------------------------------------

/// What `write_chunks` wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Written {
    /// Whole chunks taken (the next one may be partly taken).
    pub chunks: usize,
    /// Bytes taken.
    pub bytes: usize,
}

/// A stream call that registers the stream's read or write waker while it
/// waits. Dropped while it waits (an `async` call cancelled, or a blocking
/// call timed out), it leaves that registration at once instead of keeping
/// the waker until the stream's next event.
struct StreamWait<'a, D: Driver, F> {
    conn: &'a ConnRef<D>,
    key: StreamKey,
    write: bool,
    waiting: bool,
    poll: F,
}

impl<'a, D: Driver, F> StreamWait<'a, D, F> {
    fn new(conn: &'a ConnRef<D>, key: StreamKey, write: bool, poll: F) -> Self {
        Self {
            conn,
            key,
            write,
            waiting: false,
            poll,
        }
    }
}

impl<D: Driver, R, F: FnMut(&Waker) -> Poll<R> + Unpin> Future for StreamWait<'_, D, F> {
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        let this = self.get_mut();
        let r = (this.poll)(cx.waker());
        this.waiting = r.is_pending();
        r
    }
}

impl<D: Driver, F> Drop for StreamWait<'_, D, F> {
    fn drop(&mut self) {
        if self.waiting {
            let mut st = self.conn.lock();
            if self.write {
                st.waiters.remove_writer(self.key);
            } else {
                st.waiters.remove_reader(self.key);
            }
        }
    }
}

/// The sending part of a stream. Dropping it without
/// `finish` resets the stream with code 0.
pub struct SendStream<D: Driver> {
    conn: ConnRef<D>,
    key: StreamKey,
    meter: Arc<Meter>,
    /// The tokio driver keeps none.
    #[cfg_attr(not(feature = "blocking"), allow(dead_code))]
    pub(crate) timeout: D::Timeout,
}

impl<D: Driver> std::fmt::Debug for SendStream<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendStream")
            .field("key", &self.key)
            .finish()
    }
}

impl<D: Driver> SendStream<D> {
    /// Runs a command that may produce output.
    fn command<R>(&self, f: impl FnOnce(&mut core::SessionCore, StreamKey) -> R) -> R {
        let mut st = self.conn.lock();
        let r = f(&mut st.core, self.key);
        D::finish_write(&self.conn, st);
        r
    }

    /// One write of `buf`: `Pending` registers the stream's writer.
    pub(crate) fn poll_write_buf(
        &self,
        waker: &Waker,
        buf: &[u8],
    ) -> Poll<Result<usize, StreamError>> {
        let mut st = self.conn.lock();
        match st.core.write(self.key, buf) {
            Ok(0) if !buf.is_empty() => {
                st.waiters.register_writer(self.key, waker);
                Poll::Pending
            }
            r => {
                D::finish_write(&self.conn, st);
                Poll::Ready(r)
            }
        }
    }

    pub(crate) fn write_op<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> impl Future<Output = Result<usize, StreamError>> + 'a {
        StreamWait::new(&self.conn, self.key, true, move |w: &Waker| {
            self.poll_write_buf(w, buf)
        })
    }

    pub(crate) async fn write_all_op(&self, mut buf: &[u8]) -> Result<(), StreamError> {
        while !buf.is_empty() {
            let n = self.write_op(buf).await?;
            buf = &buf[n..];
        }
        Ok(())
    }

    pub(crate) fn write_chunk_op(
        &self,
        mut data: Bytes,
    ) -> impl Future<Output = Result<(), StreamError>> + '_ {
        StreamWait::new(&self.conn, self.key, true, move |w: &Waker| {
            let mut st = self.conn.lock();
            let mut wrote = false;
            while !data.is_empty() {
                match st.core.write_chunk(self.key, data.clone()) {
                    Ok(0) => {
                        st.waiters.register_writer(self.key, w);
                        if wrote {
                            // What went in is written through meanwhile.
                            D::finish_write(&self.conn, st);
                        } else {
                            st.after_command();
                        }
                        return Poll::Pending;
                    }
                    Ok(n) => {
                        data.advance(n);
                        wrote = true;
                    }
                    Err(e) => {
                        st.after_command();
                        return Poll::Ready(Err(e));
                    }
                }
            }
            D::finish_write(&self.conn, st);
            Poll::Ready(Ok(()))
        })
    }

    pub(crate) fn write_chunks_op<'a>(
        &'a self,
        bufs: &'a mut [Bytes],
    ) -> impl Future<Output = Result<Written, StreamError>> + 'a {
        StreamWait::new(&self.conn, self.key, true, move |waker: &Waker| {
            let mut st = self.conn.lock();
            let mut w = Written::default();
            for b in bufs.iter_mut() {
                if b.is_empty() {
                    w.chunks += 1;
                    continue;
                }
                match st.core.write_chunk(self.key, b.clone()) {
                    Ok(0) => break,
                    Ok(n) => {
                        w.bytes += n;
                        b.advance(n);
                        if !b.is_empty() {
                            break;
                        }
                        w.chunks += 1;
                    }
                    Err(e) if w.bytes == 0 => {
                        st.after_command();
                        return Poll::Ready(Err(e));
                    }
                    Err(_) => break,
                }
            }
            if w.bytes == 0 && w.chunks < bufs.len() {
                st.waiters.register_writer(self.key, waker);
                st.after_command();
                return Poll::Pending;
            }
            D::finish_write(&self.conn, st);
            Poll::Ready(Ok(w))
        })
    }

    pub(crate) fn stopped_op(
        &self,
    ) -> impl Future<Output = Result<Option<VarInt>, StreamError>> + '_ {
        let key = self.key;
        Wait::new(
            &self.conn.inner,
            List::Stopped(key),
            move |st: &mut State<D>| {
                Some(match st.core.send_outcome(key)? {
                    Ok(SendOutcomeKind::Finished) => Ok(None),
                    Ok(SendOutcomeKind::Stopped(c)) => Ok(Some(c)),
                    Ok(_) => Err(StreamError::ClosedLocally),
                    Err(e) => Err(e),
                })
            },
        )
    }

    fn poll_capacity(&self, waker: &Waker, min: u64) -> Poll<Result<u64, StreamError>> {
        let mut st = self.conn.lock();
        match st.core.send_capacity(self.key) {
            Err(e) => Poll::Ready(Err(e)),
            Ok(c) if c.reaches(min) => Poll::Ready(Ok(c.capacity)),
            Ok(_) => {
                st.core.wait_send_capacity(self.key, min);
                st.waiters.register_writer(self.key, waker);
                Poll::Pending
            }
        }
    }

    pub(crate) fn send_capacity_op(
        &self,
        min: u64,
    ) -> impl Future<Output = Result<u64, StreamError>> + '_ {
        StreamWait::new(&self.conn, self.key, true, move |w: &Waker| {
            self.poll_capacity(w, min)
        })
    }
}

/// For the stream carriers and the relay helper (tokio driver).
#[cfg(feature = "tokio")]
impl<D: Driver> SendStream<D> {
    /// The session of the stream.
    pub(crate) fn shared(&self) -> &Arc<Shared<D>> {
        &self.conn.0
    }

    /// Whether `recv` is the receiving part of this part's stream.
    pub(crate) fn same_stream(&self, recv: &RecvStream<D>) -> bool {
        Arc::ptr_eq(&self.conn.0, &recv.conn.0) && self.key == recv.key
    }

    /// [`SendStream::poll_send_capacity`](crate::SendStream#method.poll_send_capacity) with a waker.
    pub(crate) fn poll_capacity_with(
        &self,
        waker: &Waker,
        min: u64,
    ) -> Poll<Result<u64, StreamError>> {
        self.poll_capacity(waker, min)
    }

    /// Registers `waker` as the part's writer, to be woken when it ends (a
    /// STOP_SENDING, the session's end) or gets room; fails at once with
    /// what ended it.
    pub(crate) fn watch(&self, waker: &Waker) -> Result<(), StreamError> {
        let mut st = self.conn.lock();
        st.core.write_room(self.key)?;
        st.waiters.register_writer(self.key, waker);
        Ok(())
    }

    /// Writes as much of `data` as the buffers take without copying,
    /// advancing it: `Pending` (the writer registered) when they take
    /// nothing.
    pub(crate) fn poll_write_part(
        &self,
        waker: &Waker,
        data: &mut Bytes,
    ) -> Poll<Result<usize, StreamError>> {
        let mut st = self.conn.lock();
        match st.core.write_chunk(self.key, data.clone()) {
            Ok(0) if !data.is_empty() => {
                st.waiters.register_writer(self.key, waker);
                st.after_command();
                Poll::Pending
            }
            Ok(n) => {
                data.advance(n);
                D::finish_write(&self.conn, st);
                Poll::Ready(Ok(n))
            }
            Err(e) => {
                st.after_command();
                Poll::Ready(Err(e))
            }
        }
    }

    /// `Ready` once every byte written was passed to a carrier, or with the
    /// error that ended the part.
    pub(crate) fn poll_sent(&self, waker: &Waker) -> Poll<Result<(), StreamError>> {
        let mut st = self.conn.lock();
        match st.core.data_sent(self.key) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => {
                st.waiters.register_writer(self.key, waker);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Whether the stream's peer accepts RESET_STREAM_AT.
    pub(crate) fn peer_accepts_reset_stream_at(&self) -> bool {
        self.conn.lock().core.peer_accepts_reset_stream_at()
    }

    /// [`SendStream::finish`](crate::SendStream#method.finish) through a shared reference.
    pub(crate) fn finish_shared(&self) -> Result<(), StreamError> {
        self.command(|c, k| c.finish(k))
    }

    /// [`SendStream::reset`](crate::SendStream#method.reset) through a shared reference.
    pub(crate) fn reset_shared(&self, code: VarInt) -> Result<(), StreamError> {
        self.command(|c, k| c.reset(k, code))
    }

    /// [`SendStream::set_reliable_boundary`](crate::SendStream#method.set_reliable_boundary) through a shared reference.
    pub(crate) fn set_reliable_boundary_shared(&self) -> Result<(), StreamError> {
        self.command(|c, k| c.set_reliable_boundary(k))
    }

    /// One write of at most `limit` bytes of a batch from byte `from` on,
    /// within the send capacity, so that the part is
    /// not writable while it lacks credit (EXTENSIONS.md Section 10.2):
    /// built bytes are copied, referenced payloads shared. `Pending` (the
    /// writer registered) while nothing can be written.
    pub(crate) fn poll_write_batch(
        &self,
        waker: &Waker,
        out: &TransmitBuf,
        cursor: &mut PieceCursor,
        from: usize,
        limit: usize,
    ) -> Poll<Result<usize, StreamError>> {
        let mut st = self.conn.lock();
        let capacity = match st.core.send_capacity(self.key) {
            Ok(c) => c.capacity,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if capacity == 0 {
            st.core.wait_send_capacity(self.key, 1);
            st.waiters.register_writer(self.key, waker);
            return Poll::Pending;
        }
        let limit = limit.min(usize::try_from(capacity).unwrap_or(usize::MAX));
        let key = self.key;
        let mut failed = None;
        let core = &mut st.core;
        let n = out.take_pieces(cursor, from, limit, |piece| {
            let r = match piece {
                Piece::Copied(s) => core.write(key, s),
                Piece::Shared(b) => core.write_chunk(key, b),
            };
            r.unwrap_or_else(|e| {
                failed = Some(e);
                0
            })
        });
        if n > 0 {
            D::finish_write(&self.conn, st);
            return Poll::Ready(Ok(n));
        }
        if let Some(e) = failed {
            st.after_command();
            return Poll::Ready(Err(e));
        }
        st.waiters.register_writer(self.key, waker);
        st.after_command();
        Poll::Pending
    }

    /// One write of `buf` within the send capacity (see
    /// [`SendStream::poll_write_batch`](crate::SendStream#method.poll_write_batch)).
    pub(crate) fn poll_write_capped(
        &self,
        waker: &Waker,
        buf: &[u8],
    ) -> Poll<Result<usize, StreamError>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let capacity = {
            let mut st = self.conn.lock();
            match st.core.send_capacity(self.key) {
                Ok(c) if c.capacity > 0 => c.capacity,
                Ok(_) => {
                    st.core.wait_send_capacity(self.key, 1);
                    st.waiters.register_writer(self.key, waker);
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        };
        let n = buf
            .len()
            .min(usize::try_from(capacity).unwrap_or(usize::MAX));
        self.poll_write_buf(waker, &buf[..n])
    }
}

impl<D: Driver> Drop for SendStream<D> {
    fn drop(&mut self) {
        let mut st = self.conn.lock();
        st.waiters.forget_send(self.key);
        st.core.release_send(self.key);
        D::finish_write(&self.conn, st);
    }
}

/// The receiving part of a stream. Dropping it before
/// the end stops the stream with code 0.
pub struct RecvStream<D: Driver> {
    conn: ConnRef<D>,
    key: StreamKey,
    meter: Arc<Meter>,
    /// The tokio driver keeps none.
    #[cfg_attr(not(feature = "blocking"), allow(dead_code))]
    pub(crate) timeout: D::Timeout,
}

impl<D: Driver> std::fmt::Debug for RecvStream<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvStream")
            .field("key", &self.key)
            .finish()
    }
}

/// Pieces of received data one `read` takes under the core lock.
const READ_PIECES: usize = 32;

/// The received data a `read` took from the core under its lock: copied
/// into the application's buffer after the lock is released, so that the
/// copy holds back neither the session task nor other streams.
#[derive(Default)]
struct Taken {
    pieces: [Bytes; READ_PIECES],
    count: usize,
    len: usize,
    fin: bool,
}

impl Taken {
    /// Copies the pieces into `buf`; `None` at the end of the stream.
    fn copy_into(self, buf: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        for p in &self.pieces[..self.count] {
            buf[at..at + p.len()].copy_from_slice(p);
            at += p.len();
        }
        (at > 0 || !self.fin).then_some(at)
    }
}

/// One `read` command for up to `max` bytes: `None` while there is
/// nothing to read. An error after data is reported by the next read.
fn take_read(
    core: &mut core::SessionCore,
    key: StreamKey,
    max: usize,
) -> Option<Result<Taken, StreamError>> {
    let mut t = Taken::default();
    while t.count < READ_PIECES && t.len < max {
        match core.read_chunk(key, max - t.len) {
            Ok(None) if t.count == 0 => return None,
            Ok(None) => break,
            Ok(Some((b, fin))) => {
                if !b.is_empty() {
                    t.len += b.len();
                    t.pieces[t.count] = b;
                    t.count += 1;
                }
                if fin {
                    t.fin = true;
                    break;
                }
            }
            Err(e) if t.count == 0 => return Some(Err(e)),
            Err(_) => break,
        }
    }
    Some(Ok(t))
}

impl<D: Driver> RecvStream<D> {
    fn command<R>(&self, f: impl FnOnce(&mut core::SessionCore, StreamKey) -> R) -> R {
        self.conn.command(|st| f(&mut st.core, self.key))
    }

    /// Runs a read command, `None` while there is nothing to read; then
    /// reads the carrier through once (the tokio driver on a single pipe,
    /// see `super::through`) and tries again before it registers the
    /// stream's reader.
    fn poll_read_cmd<R>(
        &self,
        waker: &Waker,
        f: impl FnMut(&mut core::SessionCore, StreamKey) -> Option<R>,
    ) -> Poll<R> {
        self.poll_read_keep(waker, f, |_| false)
    }

    /// [`RecvStream::poll_read_cmd`](crate::RecvStream#method.poll_read_cmd) that also leaves `waker` registered
    /// as the reader when `keep` says so of the result, in the same
    /// critical section: a task that goes on to wait on something else is
    /// still woken by the part's next event.
    fn poll_read_keep<R>(
        &self,
        waker: &Waker,
        mut f: impl FnMut(&mut core::SessionCore, StreamKey) -> Option<R>,
        keep: impl Fn(&R) -> bool,
    ) -> Poll<R> {
        let mut st = self.conn.lock();
        // This poll replaces an earlier registration, which data read
        // through below would otherwise wake again for nothing.
        st.waiters.remove_reader(self.key);
        let mut through = true;
        loop {
            if let Some(r) = f(&mut st.core, self.key) {
                if keep(&r) {
                    st.waiters.register_reader(self.key, waker);
                }
                st.after_command();
                return Poll::Ready(r);
            }
            if through {
                through = false;
                // Whatever happened while the lock was released (data read
                // by the session task, or the session's end, which woke no
                // reader of this stream yet) is seen by trying again before
                // registering.
                let (again, unlocked) = D::read_through(&self.conn, st, waker);
                st = again;
                if unlocked {
                    continue;
                }
            }
            // Registered under the lock before `Pending`: whatever the
            // driver reads for this stream wakes this read.
            st.waiters.register_reader(self.key, waker);
            st.after_command();
            return Poll::Pending;
        }
    }

    /// One read into `buf` (`AsyncRead`).
    #[cfg(feature = "tokio")]
    pub(crate) fn poll_read_buf(
        &self,
        waker: &Waker,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>, StreamError>> {
        let max = buf.len();
        self.poll_read_cmd(waker, |core, key| take_read(core, key, max))
            .map(|r| r.map(|t| t.copy_into(buf)))
    }

    fn read_wait<'a, R>(
        &'a self,
        mut f: impl FnMut(&mut core::SessionCore, StreamKey) -> Option<R> + Unpin + 'a,
    ) -> impl Future<Output = R> + 'a {
        StreamWait::new(&self.conn, self.key, false, move |w: &Waker| {
            self.poll_read_cmd(w, &mut f)
        })
    }

    pub(crate) fn read_op<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<Option<usize>, StreamError>> + 'a {
        let max = buf.len();
        let taken = self.read_wait(move |core, key| take_read(core, key, max));
        async move { Ok(taken.await?.copy_into(buf)) }
    }

    pub(crate) async fn read_exact_op(&self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        let mut done = 0;
        while done < buf.len() {
            match self
                .read_op(&mut buf[done..])
                .await
                .map_err(ReadExactError::Read)?
            {
                Some(n) => done += n,
                None => return Err(ReadExactError::FinishedEarly(done)),
            }
        }
        Ok(())
    }

    pub(crate) fn read_chunk_op(
        &self,
        max: usize,
    ) -> impl Future<Output = Result<Option<Bytes>, StreamError>> + '_ {
        self.read_wait(move |core, key| match core.read_chunk(key, max) {
            Ok(None) => None,
            Ok(Some((b, true))) if b.is_empty() => Some(Ok(None)),
            Ok(Some((b, _))) => Some(Ok(Some(b))),
            Err(e) => Some(Err(e)),
        })
    }

    pub(crate) fn read_chunks_op<'a>(
        &'a self,
        bufs: &'a mut [Bytes],
    ) -> impl Future<Output = Result<Option<usize>, StreamError>> + 'a {
        self.read_wait(move |core, key| {
            let mut n = 0;
            for slot in bufs.iter_mut() {
                match core.read_chunk(key, usize::MAX) {
                    Ok(Some((b, fin))) if !b.is_empty() => {
                        *slot = b;
                        n += 1;
                        if fin {
                            break;
                        }
                    }
                    Ok(Some((_, true))) if n == 0 => return Some(Ok(None)),
                    Ok(_) => break,
                    Err(e) if n == 0 => return Some(Err(e)),
                    Err(_) => break,
                }
            }
            (n > 0 || bufs.is_empty()).then_some(Ok(Some(n)))
        })
    }

    pub(crate) async fn read_to_end_op(&self, limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        let mut out = Vec::new();
        self.read_wait(|core, key| {
            loop {
                // One byte beyond the limit tells a stream that is too long.
                let max = (limit.saturating_add(1) - out.len()).min(64 * 1024);
                match core.read_append(key, &mut out, max) {
                    Ok(None) => return None,
                    Ok(Some((_, true))) => return Some(Ok(())),
                    Ok(Some(_)) if out.len() > limit => {
                        return Some(Err(ReadToEndError::TooLong));
                    }
                    Ok(Some(_)) => {}
                    Err(e) => return Some(Err(ReadToEndError::Read(e))),
                }
            }
        })
        .await?;
        Ok(out)
    }

    pub(crate) fn received_reset_op(
        &self,
    ) -> impl Future<Output = Result<Option<VarInt>, StreamError>> + '_ {
        self.read_wait(|core, key| match core.received_reset(key) {
            Ok(Some((code, _))) => Some(Ok(Some(code))),
            Ok(None) if core.recv_end_known(key) => Some(Ok(None)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
    }

    pub(crate) fn read_datagram_op(
        &self,
    ) -> impl Future<Output = Result<(u64, Bytes), StreamError>> + '_ {
        let key = self.key;
        Wait::new(
            &self.conn.inner,
            List::StreamDatagrams(key),
            move |st: &mut State<D>| st.core.recv_stream_datagram(key).transpose(),
        )
    }
}

/// What a receiving part has, as [`RecvStream::poll_upstream`](crate::RecvStream#method.poll_upstream) reports it.
#[cfg(feature = "tokio")]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Upstream {
    /// The peer's reset arrived, before the data below its Reliable Size
    /// was read: its code and that size in application bytes.
    Reset(VarInt, u64),
    /// `n > 0` bytes readable, or 0 at the end of a stream that ended
    /// cleanly (everything read).
    Readable(usize),
}

/// For the stream carriers and the relay helper (tokio driver).
#[cfg(feature = "tokio")]
impl<D: Driver> RecvStream<D> {
    /// In one critical section, the peer's reset if it arrived, before the
    /// data below its Reliable Size was read, or else what the part has
    /// for the application without taking it, or the error a read would
    /// report. `Pending` registers the reader, and so does `Readable(n)`
    /// with `n > 0`, so that the part's next event (a reset, the session's
    /// end) wakes a task that goes on to wait for capacity.
    pub(crate) fn poll_upstream(&self, waker: &Waker) -> Poll<Result<Upstream, StreamError>> {
        self.poll_read_keep(
            waker,
            |core, key| match core.received_reset(key) {
                Ok(Some((code, reliable))) => Some(Ok(Upstream::Reset(code, reliable))),
                Err(e) => Some(Err(e)),
                Ok(None) => core
                    .readable_len(key)
                    .transpose()
                    .map(|r| r.map(Upstream::Readable)),
            },
            |r| matches!(r, Ok(Upstream::Readable(n)) if *n > 0),
        )
    }

    /// The peer's reset if it arrived (see [`Upstream::Reset`]),
    /// or the error that ended the part's session; otherwise registers
    /// `waker` as the part's reader, in the same critical section, to be
    /// woken by its next event (data, a FIN, a reset, the session's end).
    pub(crate) fn watch(&self, waker: &Waker) -> Result<Option<(VarInt, u64)>, StreamError> {
        let mut st = self.conn.lock();
        let reset = st.core.received_reset(self.key)?;
        if reset.is_none() {
            st.waiters.register_reader(self.key, waker);
        }
        Ok(reset)
    }

    /// One chunk of at most `max` bytes without copying where possible;
    /// `None` at the end of the stream; `Pending` registers the reader.
    pub(crate) fn poll_read_chunk(
        &self,
        waker: &Waker,
        max: usize,
    ) -> Poll<Result<Option<Bytes>, StreamError>> {
        self.poll_read_cmd(waker, |core, key| Self::chunk_step(core, key, max))
    }

    /// [`RecvStream::poll_read_chunk`](crate::RecvStream#method.poll_read_chunk) that leaves the reader registered
    /// after a chunk, so that the part's next event wakes a task that goes
    /// on to wait for the chunk to be written.
    pub(crate) fn poll_take_chunk(
        &self,
        waker: &Waker,
        max: usize,
    ) -> Poll<Result<Option<Bytes>, StreamError>> {
        self.poll_read_keep(
            waker,
            |core, key| Self::chunk_step(core, key, max),
            |r| matches!(r, Ok(Some(_))),
        )
    }

    fn chunk_step(
        core: &mut core::SessionCore,
        key: StreamKey,
        max: usize,
    ) -> Option<Result<Option<Bytes>, StreamError>> {
        match core.read_chunk(key, max) {
            Ok(None) => None,
            Ok(Some((b, true))) if b.is_empty() => Some(Ok(None)),
            Ok(Some((b, _))) => Some(Ok(Some(b))),
            Err(e) => Some(Err(e)),
        }
    }

    /// [`RecvStream::stop`](crate::RecvStream#method.stop) through a shared reference.
    pub(crate) fn stop_shared(&self, code: VarInt) -> Result<(), StreamError> {
        self.command(|c, k| c.stop(k, code))
    }
}

impl<D: Driver> Drop for RecvStream<D> {
    fn drop(&mut self) {
        let mut st = self.conn.lock();
        st.waiters.forget_recv(self.key);
        st.core.release_recv(self.key);
        st.after_command();
    }
}

/// Received datagrams out of the core while the receive limiter polices
/// them: dropped with any left (the limiter panicked), they go back to the
/// core refused, so that the session's datagram bytes do not keep them.
struct Policed<'a, D: Driver> {
    shared: &'a Shared<D>,
    batch: Vec<core::ReceivedDatagram>,
}

impl<D: Driver> Drop for Policed<'_, D> {
    fn drop(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        for d in &mut self.batch {
            d.set_allowed(false);
        }
        let mut locked = self.shared.lock();
        locked.core.admit_datagrams(&mut self.batch);
        locked.dispatch();
    }
}

/// The Session operations both drivers share: the public methods of each
/// driver's type (`session_api!`) call them.
pub(crate) trait SessionApi<D: Driver> {
    fn try_open_bi(&self) -> Result<(SendStream<D>, RecvStream<D>), OpenError>;
    fn try_open_bi_with(
        &self,
        preamble: &Preamble,
    ) -> Result<(SendStream<D>, RecvStream<D>), OpenError>;
    fn try_open_uni(&self) -> Result<SendStream<D>, OpenError>;
    fn try_open_uni_with(&self, preamble: &Preamble) -> Result<SendStream<D>, OpenError>;
    fn send_datagram(&self, data: Bytes) -> Result<(), DatagramError>;
    fn max_datagram_size(&self) -> Option<usize>;
    fn close(&self, code: VarInt, reason: &[u8]);
    fn close_reason(&self) -> Option<SessionError>;
    fn role(&self) -> Role;
    fn rtt(&self) -> Option<Duration>;
    fn goaway(&self) -> Option<GoAway>;
    fn is_plain_qmux_peer(&self) -> bool;
    fn stats(&self) -> SessionStats;
    fn meter(&self) -> &Arc<Meter>;
    fn window_growth(&self) -> u64;
    fn stable_id(&self) -> usize;
    fn protocol(&self) -> Option<String>;
    fn parameters_to_remember(&self) -> Option<crate::proto::params::TransportParameters>;
    fn state(&self) -> CoreState;
    fn early_data(&self) -> crate::EarlyDataState;
    fn multipath(&self) -> Multipath;
    fn is_dialer(&self) -> Option<bool>;
    fn set_dialer(&self, dialer: bool);
    fn session_nonces(&self) -> Option<([u8; 16], [u8; 16])>;
    fn role_nonces(&self) -> Option<(u64, u64)>;
    fn set_scheduler(&self, policy: Policy);
    fn set_quality_band(&self, band: Option<QualityBand>);
    fn set_capacity_floor(&self, floor: Option<CapacityFloor>);
    fn add_pipe(&self, pipe: D::Carrier, opts: PipeOptions) -> Result<Pipe<D>, PipeError>;
    fn join_ready(&self) -> bool;
    fn reserve_pipe(
        &self,
        dir: PipeDirection,
        opts: PipeOptions,
    ) -> Result<PipeReservation<D>, PipeError>;
    fn pipes(&self) -> Vec<Pipe<D>>;
    fn pipe(&self, id: PipeId) -> Option<Pipe<D>>;
    fn pipe_stats(&self) -> Vec<PipeStats>;
    fn revalidate_pipes(&self) -> Result<(), PipeError>;
}

impl<D: Driver> SessionApi<D> for Session<D> {
    fn try_open_bi(&self) -> Result<(SendStream<D>, RecvStream<D>), OpenError> {
        Ok(self.bidi(self.try_open(Dir::Bidi, None)?))
    }

    fn try_open_bi_with(
        &self,
        preamble: &Preamble,
    ) -> Result<(SendStream<D>, RecvStream<D>), OpenError> {
        Ok(self.bidi(self.try_open(Dir::Bidi, Some(preamble))?))
    }

    fn try_open_uni(&self) -> Result<SendStream<D>, OpenError> {
        Ok(self.send_stream(self.try_open(Dir::Uni, None)?))
    }

    fn try_open_uni_with(&self, preamble: &Preamble) -> Result<SendStream<D>, OpenError> {
        Ok(self.send_stream(self.try_open(Dir::Uni, Some(preamble))?))
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), DatagramError> {
        let len = data.len();
        let allowed = self.conn.datagram_allowed(len);
        let queued = self.command(|st| st.core.send_datagram(data, allowed));
        self.conn.datagram_queued(queued, len)
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.conn.lock().core.max_datagram_size()
    }

    fn close(&self, code: VarInt, reason: &[u8]) {
        self.command(|st| st.core.close(code, reason, D::now()));
    }

    fn close_reason(&self) -> Option<SessionError> {
        self.conn.lock().core.error().cloned()
    }

    fn role(&self) -> Role {
        self.conn.lock().core.role()
    }

    fn rtt(&self) -> Option<Duration> {
        self.conn.lock().core.rtt()
    }

    fn goaway(&self) -> Option<GoAway> {
        self.conn.lock().goaway
    }

    fn is_plain_qmux_peer(&self) -> bool {
        self.conn.lock().core.is_plain_qmux_peer()
    }

    fn stats(&self) -> SessionStats {
        self.conn.lock().core.stats()
    }

    fn meter(&self) -> &Arc<Meter> {
        &self.conn.meter
    }

    fn window_growth(&self) -> u64 {
        self.conn.lock().core.window_growth()
    }

    fn stable_id(&self) -> usize {
        Arc::as_ptr(&self.conn.0) as usize
    }

    fn protocol(&self) -> Option<String> {
        self.conn.lock().protocol.clone()
    }

    fn parameters_to_remember(&self) -> Option<crate::proto::params::TransportParameters> {
        self.conn.lock().core.parameters_to_remember()
    }

    fn state(&self) -> CoreState {
        self.conn.lock().core.state()
    }

    fn early_data(&self) -> crate::EarlyDataState {
        self.conn.lock().core.early_data_state()
    }

    fn multipath(&self) -> Multipath {
        self.conn.lock().core.multipath()
    }

    fn is_dialer(&self) -> Option<bool> {
        self.conn.lock().dialer
    }

    fn set_dialer(&self, dialer: bool) {
        self.conn.lock().dialer = Some(dialer);
    }

    fn session_nonces(&self) -> Option<([u8; 16], [u8; 16])> {
        self.conn.lock().core.session_nonces()
    }

    fn role_nonces(&self) -> Option<(u64, u64)> {
        self.conn.lock().core.role_nonces()
    }

    fn set_scheduler(&self, policy: Policy) {
        self.command(|st| st.core.set_scheduler(policy));
    }

    fn set_quality_band(&self, band: Option<QualityBand>) {
        self.command(|st| st.core.set_quality_band(band));
    }

    fn set_capacity_floor(&self, floor: Option<CapacityFloor>) {
        self.command(|st| st.core.set_capacity_floor(floor));
    }

    fn add_pipe(&self, mut pipe: D::Carrier, opts: PipeOptions) -> Result<Pipe<D>, PipeError> {
        D::check_carrier(&self.conn.0, &pipe)?;
        let c = D::carrier_info(&mut pipe);
        if c.outbound.is_none() {
            return Err(PipeError::InvalidArgument);
        }
        let id = self.command(|st| {
            st.core.add_pipe(
                c.inbound,
                c.outbound,
                &opts,
                false,
                c.exporter.as_deref().map(|e| e.pipe.as_slice()),
                D::now(),
            )
        })?;
        self.attach(id, pipe)
    }

    fn join_ready(&self) -> bool {
        self.conn.lock().core.join_ready(D::now())
    }

    fn reserve_pipe(
        &self,
        dir: PipeDirection,
        opts: PipeOptions,
    ) -> Result<PipeReservation<D>, PipeError> {
        let (inbound, outbound) = match dir {
            PipeDirection::In => (Some(Framing::ByteStream), None),
            PipeDirection::Out => (None, Some(Framing::ByteStream)),
            PipeDirection::Bidi => (Some(Framing::ByteStream), Some(Framing::ByteStream)),
        };
        let (id, frame) = self.command(|st| {
            let now = D::now();
            let id = st
                .core
                .add_pipe(inbound, outbound, &opts, true, None, now)?;
            if st.core.join_deferred(id) {
                // The header is needed now: a join that may not go yet
                // (cap or refusal backoff) is given up and retried later.
                let _ = st.core.remove_pipe(id, false, now);
                st.dispatch();
                return Err(PipeError::Deferred);
            }
            // Nothing is written before the carrier is attached: the pipe
            // takes no bytes.
            st.core
                .pipe_write(id, PipeWrite::returned(now, now, 0, 0, true), now);
            st.dispatch();
            Ok::<_, PipeError>((id, st.take_oob(id.0).unwrap_or_default()))
        })?;
        // After the lock: cloning the handle takes it.
        Ok(PipeReservation {
            conn: Some(self.conn.clone()),
            id,
            frame,
        })
    }

    fn pipes(&self) -> Vec<Pipe<D>> {
        let ids = self.conn.lock().core.pipe_ids();
        // The handles after the lock: cloning one takes it.
        ids.into_iter()
            .map(|id| Pipe {
                conn: self.conn.clone(),
                id,
            })
            .collect()
    }

    fn pipe(&self, id: PipeId) -> Option<Pipe<D>> {
        let known = self.conn.lock().core.has_pipe(id);
        known.then(|| Pipe {
            conn: self.conn.clone(),
            id,
        })
    }

    fn pipe_stats(&self) -> Vec<PipeStats> {
        self.conn.lock().core.pipes()
    }

    fn revalidate_pipes(&self) -> Result<(), PipeError> {
        self.command(|st| st.core.revalidate_pipes(None, D::now()))
    }
}

/// The public methods of a driver's Session type: `$d` the driver,
/// `$carrier` its carrier type.
macro_rules! session_api {
    ($d:ty, $carrier:ty) => {
        /// Opens a bidirectional stream if credit is available now; while
        /// openers wait for credit it fails with [`OpenError::Blocked`] (it
        /// does not overtake them). Nothing is sent until the first write or
        /// [`SendStream::pin_id`](crate::SendStream#method.pin_id). Never waits.
        pub fn try_open_bi(&self) -> Result<(SendStream, RecvStream), crate::OpenError> {
            <Self as crate::driver::handle::SessionApi<$d>>::try_open_bi(self)
        }

        /// Opens a bidirectional stream with `preamble` if credit is available
        /// now (see [`Session::try_open_bi`](crate::Session#method.try_open_bi) and `open_bi_with`). Never waits.
        pub fn try_open_bi_with(
            &self,
            preamble: &crate::Preamble,
        ) -> Result<(SendStream, RecvStream), crate::OpenError> {
            <Self as crate::driver::handle::SessionApi<$d>>::try_open_bi_with(self, preamble)
        }

        /// Opens a unidirectional stream if credit is available now (see
        /// [`Session::try_open_bi`](crate::Session#method.try_open_bi)). Never waits.
        pub fn try_open_uni(&self) -> Result<SendStream, crate::OpenError> {
            <Self as crate::driver::handle::SessionApi<$d>>::try_open_uni(self)
        }

        /// Opens a unidirectional stream with `preamble` if credit is
        /// available now. Never waits.
        pub fn try_open_uni_with(
            &self,
            preamble: &crate::Preamble,
        ) -> Result<SendStream, crate::OpenError> {
            <Self as crate::driver::handle::SessionApi<$d>>::try_open_uni_with(self, preamble)
        }

        /// Queues a session datagram. Never waits: when the queue is full the
        /// oldest datagram is dropped.
        pub fn send_datagram(&self, data: ::bytes::Bytes) -> Result<(), crate::DatagramError> {
            <Self as crate::driver::handle::SessionApi<$d>>::send_datagram(self, data)
        }

        /// The largest session datagram payload the peer currently accepts
        /// (EXTENSIONS.md Section 6.6), the MTU of a packet interface: 65533
        /// for a zmux peer with datagram flows, 65534 without, 16381 for a
        /// plain QMux peer at the default record size; `None` when the peer
        /// accepts no datagrams. Every pipe of a multipath session takes it.
        pub fn max_datagram_size(&self) -> Option<usize> {
            <Self as crate::driver::handle::SessionApi<$d>>::max_datagram_size(self)
        }

        /// Closes the session at once with an application error code. Never waits.
        pub fn close(&self, code: crate::VarInt, reason: &[u8]) {
            <Self as crate::driver::handle::SessionApi<$d>>::close(self, code, reason)
        }

        /// Why the session ended, once it has.
        pub fn close_reason(&self) -> Option<crate::SessionError> {
            <Self as crate::driver::handle::SessionApi<$d>>::close_reason(self)
        }

        /// The local role (negotiated for a symmetric carrier).
        pub fn role(&self) -> crate::Role {
            <Self as crate::driver::handle::SessionApi<$d>>::role(self)
        }

        /// The smoothed RTT, once measured.
        pub fn rtt(&self) -> Option<::std::time::Duration> {
            <Self as crate::driver::handle::SessionApi<$d>>::rtt(self)
        }

        /// The peer's GOAWAY, if it sent one.
        pub fn goaway(&self) -> Option<crate::GoAway> {
            <Self as crate::driver::handle::SessionApi<$d>>::goaway(self)
        }

        /// Whether the peer is a plain QMux implementation.
        pub fn is_plain_qmux_peer(&self) -> bool {
            <Self as crate::driver::handle::SessionApi<$d>>::is_plain_qmux_peer(self)
        }

        /// A snapshot of the transport statistics.
        pub fn stats(&self) -> crate::SessionStats {
            <Self as crate::driver::handle::SessionApi<$d>>::stats(self)
        }

        /// The application byte counters of the session:
        /// totals over all its streams, released ones included, and its
        /// datagrams. Read without a lock, from any thread; the meter stays
        /// readable after the session closed and does not keep it open.
        pub fn meter(&self) -> &::std::sync::Arc<crate::Meter> {
            <Self as crate::driver::handle::SessionApi<$d>>::meter(self)
        }

        /// How far the session's receive window grew above its initial size
        /// (what a listener's memory budget charges for it;
        /// growth goes through `allow_connection_window_increase` when set).
        pub fn window_growth(&self) -> u64 {
            <Self as crate::driver::handle::SessionApi<$d>>::window_growth(self)
        }

        /// An identifier unique among live sessions of this process.
        pub fn stable_id(&self) -> usize {
            <Self as crate::driver::handle::SessionApi<$d>>::stable_id(self)
        }

        /// The application protocol: the bootstrap carrier's (its ALPN
        /// identifier, `PipeIo::with_protocol`), or else the one negotiated with
        /// [`Config::protocols`].
        pub fn protocol(&self) -> Option<String> {
            <Self as crate::driver::handle::SessionApi<$d>>::protocol(self)
        }

        /// The peer's transport parameters that carrier early data may
        /// assume on a later carrier that resumes this one's TLS session
        /// (the ones stored for 0-RTT), once the session is established
        /// with [`crate::EarlyData::carrier_early_data`] on. Carrier
        /// adapters keep them with the ticket.
        pub fn parameters_to_remember(&self) -> Option<crate::proto::params::TransportParameters> {
            <Self as crate::driver::handle::SessionApi<$d>>::parameters_to_remember(self)
        }

        /// The session state: established, suspended or closing.
        pub fn state(&self) -> crate::SessionState {
            <Self as crate::driver::handle::SessionApi<$d>>::state(self)
        }

        /// What became of the session's early data (SPEC.md Section
        /// 6.1.2): not sent, pending until the peer's parameters arrive and
        /// the carrier settles its own early data, accepted or rejected.
        pub fn early_data(&self) -> crate::EarlyDataState {
            <Self as crate::driver::handle::SessionApi<$d>>::early_data(self)
        }

        /// Whether multipath is in use, and why not (MULTIPATH.md Section 3.3).
        pub fn multipath(&self) -> crate::Multipath {
            <Self as crate::driver::handle::SessionApi<$d>>::multipath(self)
        }

        /// Whether this endpoint dialed the session, that is established its
        /// bootstrap carrier (EXTENSIONS.md Section 11), whatever role
        /// negotiation decided: known for a session started with `connect`
        /// (the dialer) or `accept` and a listener (not the dialer), and for a
        /// symmetric carrier (`peer`) once the application designated it with
        /// [`Session::set_dialer`](crate::Session#method.set_dialer).
        pub fn is_dialer(&self) -> Option<bool> {
            <Self as crate::driver::handle::SessionApi<$d>>::is_dialer(self)
        }

        /// Designates whether this endpoint dialed the session (EXTENSIONS.md
        /// Section 11): for a symmetric carrier, or a carrier whose client is
        /// not the session's initiator. Both endpoints must designate the same
        /// endpoint.
        pub fn set_dialer(&self, dialer: bool) {
            <Self as crate::driver::handle::SessionApi<$d>>::set_dialer(self, dialer)
        }

        /// The Session Nonces both endpoints sent in `zmux_multipath`
        /// (MULTIPATH.md Section 3.1), this endpoint's first, while multipath
        /// is in use.
        pub fn session_nonces(&self) -> Option<([u8; 16], [u8; 16])> {
            <Self as crate::driver::handle::SessionApi<$d>>::session_nonces(self)
        }

        /// The `zmux_role` nonces (EXTENSIONS.md Section 2), this endpoint's
        /// first, when both endpoints negotiated the roles with `auto`.
        pub fn role_nonces(&self) -> Option<(u64, u64)> {
            <Self as crate::driver::handle::SessionApi<$d>>::role_nonces(self)
        }

        /// Sets the default scheduling policy of new stream data.
        pub fn set_scheduler(&self, policy: crate::Policy) {
            <Self as crate::driver::handle::SessionApi<$d>>::set_scheduler(self, policy)
        }

        /// Sets the quality band of the session's outbound pipes that have
        /// none of their own (`None`: none), pipe 0 of a session without
        /// multipath included: [`SessionEvent::PipeQualityChanged`](crate::SessionEvent::PipeQualityChanged) reports a pipe
        /// whose smoothed RTT or delivery rate leaves the band around its last
        /// report. Off until set, and free then; it never
        /// influences scheduling. The rate of a session without multipath
        /// needs pipe acknowledgement.
        pub fn set_quality_band(&self, band: Option<crate::QualityBand>) {
            <Self as crate::driver::handle::SessionApi<$d>>::set_quality_band(self, band)
        }

        /// Sets the floor under the session's outbound capacity, the sum of
        /// the delivery rates of the usable non-standby outbound pipes (`None`:
        /// none): [`SessionEvent::CapacityBelow`](crate::SessionEvent::CapacityBelow) once when it falls below the
        /// floor, at once if it is below when set, and
        /// [`SessionEvent::CapacityRestored`](crate::SessionEvent::CapacityRestored) once when it rises to the floor
        /// times its ratio again. zmux only reports; the
        /// application decides, for example to dial another pipe.
        pub fn set_capacity_floor(&self, floor: Option<crate::CapacityFloor>) {
            <Self as crate::driver::handle::SessionApi<$d>>::set_capacity_floor(self, floor)
        }

        /// Adds a pipe: the local endpoint joins it with an in-band PIPE_JOIN
        /// (an outbound half is required; use [`Session::reserve_pipe`](crate::Session#method.reserve_pipe) for an
        /// inbound-only carrier). The join is confirmed by the peer's first
        /// acknowledgement or record; until then the pipe carries stream data
        /// only when no other pipe can (MULTIPATH.md Section 11), and after
        /// it the pipe is in probation for a while. Never waits.
        pub fn add_pipe(
            &self,
            pipe: $carrier,
            opts: crate::PipeOptions,
        ) -> Result<Pipe, crate::PipeError> {
            <Self as crate::driver::handle::SessionApi<$d>>::add_pipe(self, pipe, opts)
        }

        /// Whether a pipe added now would join at once rather than wait (the
        /// cap of unretired attachments, or the backoff after a refused join).
        /// Dial a carrier only then, so that none is held idle.
        pub fn join_ready(&self) -> bool {
            <Self as crate::driver::handle::SessionApi<$d>>::join_ready(self)
        }

        /// Reserves a pipe for an out-of-band join (MULTIPATH.md Section 5.3):
        /// send [`PipeReservation::header`](crate::PipeReservation#method.header) with the carrier's request (the
        /// `Zmux-Pipe-Join` header), then attach the carrier.
        pub fn reserve_pipe(
            &self,
            dir: crate::PipeDirection,
            opts: crate::PipeOptions,
        ) -> Result<PipeReservation, crate::PipeError> {
            <Self as crate::driver::handle::SessionApi<$d>>::reserve_pipe(self, dir, opts)
        }

        /// The session's pipes, every one alike: pipe 0,
        /// the pipes this endpoint added, those the peer joined and those a
        /// helper dialled; on a session without multipath, pipe 0 alone.
        pub fn pipes(&self) -> Vec<Pipe> {
            <Self as crate::driver::handle::SessionApi<$d>>::pipes(self)
        }

        /// The pipe `id`, while the session knows it (until it is retired).
        pub fn pipe(&self, id: crate::PipeId) -> Option<Pipe> {
            <Self as crate::driver::handle::SessionApi<$d>>::pipe(self, id)
        }

        /// The statistics of every pipe, in one critical
        /// section.
        pub fn pipe_stats(&self) -> Vec<crate::PipeStats> {
            <Self as crate::driver::handle::SessionApi<$d>>::pipe_stats(self)
        }

        /// Revalidates every live outbound pipe after a network change: each
        /// gets a PIPE_PING at once and takes no new stream
        /// data, while another pipe can, until it is acknowledged. Never waits.
        pub fn revalidate_pipes(&self) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::SessionApi<$d>>::revalidate_pipes(self)
        }
    };
}
pub(crate) use session_api;

/// The Pipe operations both drivers share: the public methods of each
/// driver's type (`pipe_api!`) call them.
pub(crate) trait PipeApi<D: Driver> {
    fn id(&self) -> PipeId;
    fn stats(&self) -> Option<PipeStats>;
    fn close(&self) -> Result<(), PipeError>;
    fn abort(&self) -> Result<(), PipeError>;
    fn set_send_priority(&self, priority: u64) -> Result<(), PipeError>;
    fn clear_send_priority(&self) -> Result<(), PipeError>;
    fn set_receive_priority(&self, priority: u64) -> Result<(), PipeError>;
    fn set_send_standby(&self, standby: bool) -> Result<(), PipeError>;
    fn clear_send_standby(&self) -> Result<(), PipeError>;
    fn set_receive_standby(&self, standby: bool) -> Result<(), PipeError>;
    fn set_weight(&self, weight: u64) -> Result<(), PipeError>;
    fn set_probation(&self, probation: Option<Duration>) -> Result<(), PipeError>;
    fn set_quality_band(&self, band: Option<QualityBand>) -> Result<(), PipeError>;
    fn revalidate(&self) -> Result<(), PipeError>;
}

impl<D: Driver> PipeApi<D> for Pipe<D> {
    fn id(&self) -> PipeId {
        self.id
    }

    fn stats(&self) -> Option<PipeStats> {
        self.conn.lock().core.pipe_info(self.id)
    }

    fn close(&self) -> Result<(), PipeError> {
        self.command(|c, p| c.remove_pipe(p, true, D::now()))
    }

    fn abort(&self) -> Result<(), PipeError> {
        self.command(|c, p| c.remove_pipe(p, false, D::now()))
    }

    fn set_send_priority(&self, priority: u64) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_send_priority(p, Some(priority)))
    }

    fn clear_send_priority(&self) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_send_priority(p, None))
    }

    fn set_receive_priority(&self, priority: u64) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_receive_priority(p, priority))
    }

    fn set_send_standby(&self, standby: bool) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_send_standby(p, Some(standby)))
    }

    fn clear_send_standby(&self) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_send_standby(p, None))
    }

    fn set_receive_standby(&self, standby: bool) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_receive_standby(p, standby))
    }

    fn set_weight(&self, weight: u64) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_weight(p, weight))
    }

    fn set_probation(&self, probation: Option<Duration>) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_probation(p, probation))
    }

    fn set_quality_band(&self, band: Option<QualityBand>) -> Result<(), PipeError> {
        self.command(|c, p| c.set_pipe_quality_band(p, band))
    }

    fn revalidate(&self) -> Result<(), PipeError> {
        self.command(|c, p| c.revalidate_pipes(Some(p), D::now()))
    }
}

/// The public methods of a driver's Pipe type: `$d` the driver,
/// `$carrier` its carrier type.
macro_rules! pipe_api {
    ($d:ty, $carrier:ty) => {
        /// Sets the tier of both directions: this endpoint's outbound
        /// direction ([`set_send_priority`](Self::set_send_priority)) and
        /// the one requested of the peer
        /// ([`set_receive_priority`](Self::set_receive_priority)), as
        /// [`PipeOptions::with_priority`](crate::PipeOptions::with_priority)
        /// does when the pipe is added.
        pub fn set_priority(&self, priority: u64) -> Result<(), crate::PipeError> {
            self.set_send_priority(priority)?;
            self.set_receive_priority(priority)
        }

        /// Makes both directions standby (data only on failover) or
        /// available, as [`set_priority`](Self::set_priority) does for the
        /// tier.
        pub fn set_standby(&self, standby: bool) -> Result<(), crate::PipeError> {
            self.set_send_standby(standby)?;
            self.set_receive_standby(standby)
        }

        /// The session the pipe belongs to. The handle keeps the session
        /// in use as the pipe's does.
        pub fn session(&self) -> crate::driver::handle::Session<$d> {
            self.session_handle()
        }

        /// The pipe ID.
        pub fn id(&self) -> crate::PipeId {
            <Self as crate::driver::handle::PipeApi<$d>>::id(self)
        }

        /// The pipe's quality and settings, while the
        /// session keeps its state.
        pub fn stats(&self) -> Option<crate::PipeStats> {
            <Self as crate::driver::handle::PipeApi<$d>>::stats(self)
        }

        /// Removes the pipe gracefully: PIPE_ABANDON(NO_ERROR) and drain
        /// (MULTIPATH.md Section 8.2).
        pub fn close(&self) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::close(self)
        }

        /// Removes the pipe abruptly: its information is re-sent elsewhere
        /// (MULTIPATH.md Section 8.3).
        pub fn abort(&self) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::abort(self)
        }

        /// Sets the tier of the local outbound direction (lower preferred). A
        /// local setting wins over the peer's
        /// request; nothing is sent.
        pub fn set_send_priority(&self, priority: u64) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::set_send_priority(self, priority)
        }

        /// Clears the local tier of the outbound direction: the peer's
        /// request applies again, else priority 0.
        pub fn clear_send_priority(&self) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::clear_send_priority(self)
        }

        /// Asks the peer to use this tier for its outbound direction (sent at
        /// once as PIPE_STATUS, MULTIPATH.md Section 9).
        pub fn set_receive_priority(&self, priority: u64) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::set_receive_priority(self, priority)
        }

        /// Makes the local outbound direction standby (data only on failover)
        /// or available; a local setting wins over the peer's request.
        pub fn set_send_standby(&self, standby: bool) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::set_send_standby(self, standby)
        }

        /// Clears the local standby setting: the peer's request applies again,
        /// else available.
        pub fn clear_send_standby(&self) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::clear_send_standby(self)
        }

        /// Asks the peer to use its outbound direction only on failover, or
        /// as an ordinary pipe (sent at once as PIPE_STATUS).
        pub fn set_receive_standby(&self, standby: bool) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::set_receive_standby(self, standby)
        }

        /// Sets the outbound direction's weight.
        pub fn set_weight(&self, weight: u64) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::set_weight(self, weight)
        }

        /// Sets the probation base (`None`: the session default; zero
        /// disables probation).
        pub fn set_probation(
            &self,
            probation: Option<::std::time::Duration>,
        ) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::set_probation(self, probation)
        }

        /// Sets the quality band of this pipe's outbound direction (`None`:
        /// the session's, [`Session::set_quality_band`](crate::Session#method.set_quality_band); a band with both
        /// halves off turns its reports off).
        pub fn set_quality_band(
            &self,
            band: Option<crate::QualityBand>,
        ) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::set_quality_band(self, band)
        }

        /// Revalidates the outbound pipe after a network change: a PIPE_PING at
        /// once, and no new stream data, while
        /// another pipe can take it, until it is acknowledged.
        pub fn revalidate(&self) -> Result<(), crate::PipeError> {
            <Self as crate::driver::handle::PipeApi<$d>>::revalidate(self)
        }
    };
}
pub(crate) use pipe_api;

/// The PipeReservation operations both drivers share: the public methods of each
/// driver's type (`pipereservation_api!`) call them.
pub(crate) trait PipeReservationApi<D: Driver> {
    fn id(&self) -> PipeId;
    fn frame(&self) -> &[u8];
    fn header(&self) -> String;
    fn attach(self, pipe: D::Carrier) -> Result<Pipe<D>, PipeError>;
    fn cancel(self);
}

impl<D: Driver> PipeReservationApi<D> for PipeReservation<D> {
    fn id(&self) -> PipeId {
        self.id
    }

    fn frame(&self) -> &[u8] {
        &self.frame
    }

    fn header(&self) -> String {
        crate::proto::oob::encode_string(&self.frame)
    }

    fn attach(mut self, mut pipe: D::Carrier) -> Result<Pipe<D>, PipeError> {
        if let Some(conn) = &self.conn {
            // Refused, the reservation is given up (dropped).
            D::check_carrier(&conn.0, &pipe)?;
        }
        let conn = self.conn.take().expect("a reservation holds its session");
        let id = self.id;
        // The carrier's framing (message framing on WebSocket, for
        // example), unknown when the pipe was reserved.
        let c = D::carrier_info(&mut pipe);
        conn.command(|st| {
            // An out-of-band frame no one took is nobody's now.
            st.take_oob(id.0);
            let now = D::now();
            st.core.set_reserved_framing(id, c.inbound, c.outbound, now);
            st.core
                .pipe_write(id, PipeWrite::returned(now, now, 0, 0, false), now);
        });
        Session { conn }.attach(id, pipe)
    }

    fn cancel(self) {
        drop(self);
    }
}

/// The public methods of a driver's PipeReservation type: `$d` the driver,
/// `$carrier` its carrier type.
macro_rules! pipereservation_api {
    ($d:ty, $carrier:ty) => {
        /// The pipe ID.
        pub fn id(&self) -> crate::PipeId {
            <Self as crate::driver::handle::PipeReservationApi<$d>>::id(self)
        }

        /// The PIPE_JOIN frame to deliver out of band.
        pub fn frame(&self) -> &[u8] {
            <Self as crate::driver::handle::PipeReservationApi<$d>>::frame(self)
        }

        /// The `Zmux-Pipe-Join` header value: the frame in base64url without
        /// padding.
        pub fn header(&self) -> String {
            <Self as crate::driver::handle::PipeReservationApi<$d>>::header(self)
        }

        /// Attaches the carrier. Fails when its I/O cannot be started; the
        /// pipe fails then.
        pub fn attach(self, pipe: $carrier) -> Result<Pipe, crate::PipeError> {
            <Self as crate::driver::handle::PipeReservationApi<$d>>::attach(self, pipe)
        }

        /// Gives the reservation up: the pipe fails (its ID stays used).
        pub fn cancel(self) {
            <Self as crate::driver::handle::PipeReservationApi<$d>>::cancel(self)
        }
    };
}
pub(crate) use pipereservation_api;

/// The SendStream operations both drivers share: the public methods of each
/// driver's type (`sendstream_api!`) call them.
pub(crate) trait SendStreamApi<D: Driver> {
    fn id(&self) -> Option<StreamId>;
    fn pin_id(&self) -> Result<StreamId, StreamError>;
    fn set_scheduler(&self, policy: Option<Policy>) -> Result<(), StreamError>;
    fn set_redundant(&self, on: bool) -> Result<(), StreamError>;
    fn finish(&mut self) -> Result<(), StreamError>;
    fn reset(&mut self, code: VarInt) -> Result<(), StreamError>;
    fn set_reliable_boundary(&mut self) -> Result<(), StreamError>;
    fn set_priority(&self, priority: Priority) -> Result<(), StreamError>;
    fn priority(&self) -> Result<Priority, StreamError>;
    fn set_send_buffer(&self, bytes: u64) -> Result<(), StreamError>;
    fn max_datagram_size(&self, context: u64) -> Option<usize>;
    fn send_datagram(&self, context: u64, data: Bytes) -> Result<(), DatagramError>;
    fn meter(&self) -> &Arc<Meter>;
    fn stats(&self) -> Option<StreamStats>;
    fn send_capacity(&self) -> u64;
    fn poll_send_capacity(&self, cx: &mut Context<'_>, min: u64) -> Poll<Result<u64, StreamError>>;
}

impl<D: Driver> SendStreamApi<D> for SendStream<D> {
    fn id(&self) -> Option<StreamId> {
        self.conn.lock().core.peek_stream_id(self.key).map(StreamId)
    }

    fn pin_id(&self) -> Result<StreamId, StreamError> {
        self.command(|c, k| c.stream_id(k)).map(StreamId)
    }

    fn set_scheduler(&self, policy: Option<Policy>) -> Result<(), StreamError> {
        self.command(|c, k| c.set_stream_scheduler(k, policy))
    }

    fn set_redundant(&self, on: bool) -> Result<(), StreamError> {
        self.command(|c, k| c.set_redundant(k, on))
    }

    fn finish(&mut self) -> Result<(), StreamError> {
        self.command(|c, k| c.finish(k))
    }

    fn reset(&mut self, code: VarInt) -> Result<(), StreamError> {
        self.command(|c, k| c.reset(k, code))
    }

    fn set_reliable_boundary(&mut self) -> Result<(), StreamError> {
        self.command(|c, k| c.set_reliable_boundary(k))
    }

    fn set_priority(&self, priority: Priority) -> Result<(), StreamError> {
        self.command(|c, k| c.set_priority(k, priority))
    }

    fn priority(&self) -> Result<Priority, StreamError> {
        self.conn
            .lock()
            .core
            .priority(self.key)
            .ok_or(StreamError::ClosedLocally)
    }

    fn set_send_buffer(&self, bytes: u64) -> Result<(), StreamError> {
        self.command(|c, k| c.set_send_buffer(k, bytes))
    }

    fn max_datagram_size(&self, context: u64) -> Option<usize> {
        self.conn
            .lock()
            .core
            .max_stream_datagram_size(self.key, context)
    }

    fn send_datagram(&self, context: u64, data: Bytes) -> Result<(), DatagramError> {
        let len = data.len();
        let allowed = self.conn.datagram_allowed(len);
        let queued = self.command(|c, k| c.send_stream_datagram(k, context, data, allowed));
        self.conn.datagram_queued(queued, len)
    }

    fn meter(&self) -> &Arc<Meter> {
        &self.meter
    }

    fn stats(&self) -> Option<StreamStats> {
        self.conn.lock().core.stream_stats(self.key)
    }

    fn send_capacity(&self) -> u64 {
        self.conn
            .lock()
            .core
            .send_capacity(self.key)
            .map_or(0, |c| c.capacity)
    }

    fn poll_send_capacity(&self, cx: &mut Context<'_>, min: u64) -> Poll<Result<u64, StreamError>> {
        self.poll_capacity(cx.waker(), min)
    }
}

/// The public methods of a driver's SendStream type: `$d` the driver,
/// `$carrier` its carrier type.
macro_rules! sendstream_api {
    ($d:ty, $carrier:ty) => {
        /// The stream's identifier, once it has one: a stream this
        /// endpoint opened gets it with its first frame (the first write,
        /// or [`pin_id`](Self::pin_id)), so that a stream cancelled before
        /// sends nothing (SPEC.md Section 7.2 rule 1). Reading it has no
        /// effect on the wire.
        pub fn id(&self) -> Option<crate::StreamId> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::id(self)
        }

        /// Assigns the stream's identifier now and returns it: before the
        /// first frame this pins the stream, whose opening frame (with its
        /// preamble) is sent as soon as flow control allows, ahead of any
        /// later stream's (SPEC.md Section 7.2); a reset after it is seen
        /// by the peer. Before establishment the identifier is not known
        /// yet ([`StreamError::NotEstablished`](crate::StreamError::NotEstablished)).
        pub fn pin_id(&self) -> Result<crate::StreamId, crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::pin_id(self)
        }

        /// Sets the scheduling policy of this stream direction; `None` uses the
        /// session's.
        pub fn set_scheduler(
            &self,
            policy: Option<crate::Policy>,
        ) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::set_scheduler(self, policy)
        }

        /// Turns redundancy on or off for this stream direction: copies of its
        /// chunks on a second pipe of the tier, within the session's copy
        /// bound. Until called,
        /// the session's `redundancy` parameter applies.
        pub fn set_redundant(&self, on: bool) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::set_redundant(self, on)
        }

        /// Ends the stream cleanly: a FIN follows the data written. Its
        /// delivery, like every delivery zmux reports, ends at the peer's zmux
        /// endpoint, not its application (SPEC.md Section 7.4).
        pub fn finish(&mut self) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::finish(self)
        }

        /// Resets the stream with `code`. Data below the reliable boundary is
        /// still delivered (RESET_STREAM_AT).
        pub fn reset(&mut self, code: crate::VarInt) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::reset(self, code)
        }

        /// Marks the data written so far as reliable: a later reset still
        /// delivers it.
        pub fn set_reliable_boundary(&mut self) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::set_reliable_boundary(self)
        }

        /// Sets the local scheduling priority (RFC 9218 urgency and
        /// incremental): stricter urgency goes first. In a multipath session
        /// urgency 0 to 2 also sends a
        /// redundant copy of each chunk on a second pipe of the tier, within
        /// the session's copy bound (the `redundancy` setting);
        /// [`set_redundant`](Self::set_redundant) overrides
        /// it for this stream.
        pub fn set_priority(&self, priority: crate::Priority) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::set_priority(self, priority)
        }

        /// The local scheduling priority.
        pub fn priority(&self) -> Result<crate::Priority, crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::priority(self)
        }

        /// Bounds the stream's written-but-unsent bytes.
        pub fn set_send_buffer(&self, bytes: u64) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::set_send_buffer(self, bytes)
        }

        /// The largest payload of a datagram on this stream with Context ID
        /// `context`: the session's limit less the stream's Flow and Context ID
        /// (EXTENSIONS.md Section 6.6); `None` without datagram flows.
        pub fn max_datagram_size(&self, context: u64) -> Option<usize> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::max_datagram_size(self, context)
        }

        /// Sends a datagram on this stream (Flow = stream ID + 1, EXTENSIONS.md
        /// Section 6.3). Never waits.
        pub fn send_datagram(
            &self,
            context: u64,
            data: ::bytes::Bytes,
        ) -> Result<(), crate::DatagramError> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::send_datagram(self, context, data)
        }

        /// The application byte counters of the stream:
        /// `bytes_written` and `datagram_bytes_sent` are this sending part's.
        /// Read without a lock, from any thread; final once the part is
        /// terminal. A bidirectional stream's two handles share the meter.
        pub fn meter(&self) -> &::std::sync::Arc<crate::Meter> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::meter(self)
        }

        /// A snapshot of the stream's statistics; `None`
        /// once the session no longer holds the stream.
        pub fn stats(&self) -> Option<crate::StreamStats> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::stats(self)
        }

        /// The send capacity: the bytes this part could
        /// transmit now, the smaller of its remaining stream credit and the
        /// session's remaining credit, minus what it holds unsent; 0 once the
        /// part ended. Never waits.
        pub fn send_capacity(&self) -> u64 {
            <Self as crate::driver::handle::SendStreamApi<$d>>::send_capacity(self)
        }

        /// Polls for send capacity of at least `min` bytes, or of any while the
        /// part holds nothing unsent (so that a peer window smaller than `min`
        /// cannot stall the caller); `Ready` with the capacity, or at once
        /// with the error that ended the part: a reset or finish, the peer's
        /// STOP_SENDING, the session's end. `Pending` registers `cx`'s waker
        /// as the part's writer, as a write that waits does.
        pub fn poll_send_capacity(
            &self,
            cx: &mut ::std::task::Context<'_>,
            min: u64,
        ) -> ::std::task::Poll<Result<u64, crate::StreamError>> {
            <Self as crate::driver::handle::SendStreamApi<$d>>::poll_send_capacity(self, cx, min)
        }
    };
}
pub(crate) use sendstream_api;

/// The RecvStream operations both drivers share: the public methods of each
/// driver's type (`recvstream_api!`) call them.
pub(crate) trait RecvStreamApi<D: Driver> {
    fn id(&self) -> Option<StreamId>;
    fn pin_id(&self) -> Result<StreamId, StreamError>;
    fn stop(&mut self, code: VarInt) -> Result<(), StreamError>;
    fn set_receive_window(&self, initial: u64, max: u64) -> Result<(), StreamError>;
    fn set_peer_priority(&self, priority: Priority) -> Result<(), StreamError>;
    fn reject(self) -> Result<(), StreamError>;
    fn preamble(&self) -> Preamble;
    fn is_replayable(&self) -> bool;
    fn requested_priority(&self) -> Option<Priority>;
    fn meter(&self) -> &Arc<Meter>;
    fn stats(&self) -> Option<StreamStats>;
}

impl<D: Driver> RecvStreamApi<D> for RecvStream<D> {
    fn id(&self) -> Option<StreamId> {
        self.conn.lock().core.peek_stream_id(self.key).map(StreamId)
    }

    fn pin_id(&self) -> Result<StreamId, StreamError> {
        self.command(|c, k| c.stream_id(k)).map(StreamId)
    }

    fn stop(&mut self, code: VarInt) -> Result<(), StreamError> {
        self.command(|c, k| c.stop(k, code))
    }

    fn set_receive_window(&self, initial: u64, max: u64) -> Result<(), StreamError> {
        self.command(|c, k| c.set_receive_window(k, initial, max))
    }

    fn set_peer_priority(&self, priority: Priority) -> Result<(), StreamError> {
        self.command(|c, k| c.set_peer_priority(k, priority))
    }

    fn reject(self) -> Result<(), StreamError> {
        self.command(|c, k| c.reject(k))
    }

    fn preamble(&self) -> Preamble {
        self.conn.lock().core.preamble(self.key)
    }

    fn is_replayable(&self) -> bool {
        self.conn.lock().core.is_replayable(self.key)
    }

    fn requested_priority(&self) -> Option<Priority> {
        self.conn.lock().core.requested_priority(self.key)
    }

    fn meter(&self) -> &Arc<Meter> {
        &self.meter
    }

    fn stats(&self) -> Option<StreamStats> {
        self.conn.lock().core.stream_stats(self.key)
    }
}

/// The public methods of a driver's RecvStream type: `$d` the driver,
/// `$carrier` its carrier type.
macro_rules! recvstream_api {
    ($d:ty, $carrier:ty) => {
        /// The stream's identifier, once it has one (see
        /// [`SendStream::id`](crate::SendStream#method.id)); a stream the
        /// peer opened always has one. No effect on the wire.
        pub fn id(&self) -> Option<crate::StreamId> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::id(self)
        }

        /// Assigns the identifier of a stream this endpoint opened now (see
        /// [`SendStream::pin_id`](crate::SendStream#method.pin_id)).
        pub fn pin_id(&self) -> Result<crate::StreamId, crate::StreamError> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::pin_id(self)
        }

        /// Stops reading: STOP_SENDING with `code`; unread data is discarded.
        pub fn stop(&mut self, code: crate::VarInt) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::stop(self, code)
        }

        /// Sets the stream's receive window: `initial` is advertised at once,
        /// `max` caps auto-tuning.
        pub fn set_receive_window(&self, initial: u64, max: u64) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::set_receive_window(
                self, initial, max,
            )
        }

        /// Asks the peer to schedule its sending part of this stream with
        /// `priority` (EXTENSIONS.md Section 5).
        pub fn set_peer_priority(
            &self,
            priority: crate::Priority,
        ) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::set_peer_priority(self, priority)
        }

        /// Declines the stream before reading it: STOP_SENDING and, on a
        /// sending part not written to, RESET_STREAM, both with ZMUX_REJECTED
        /// (EXTENSIONS.md Section 7.2).
        pub fn reject(self) -> Result<(), crate::StreamError> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::reject(self)
        }

        /// The stream's preamble (EXTENSIONS.md Section 4): the peer's for a
        /// stream it opened, which a relay passes on with
        /// [`Session::open_bi_with`](crate::Session#method.open_bi_with)-style opening; the one it was opened with
        /// for a local stream.
        pub fn preamble(&self) -> crate::Preamble {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::preamble(self)
        }

        /// Whether this stream's opening arrived as carrier early data (TLS
        /// 1.3 early data, QUIC 0-RTT) and the carrier's handshake has not
        /// completed yet: an attacker may have replayed it, so act on its
        /// request only if doing it twice is harmless, or wait until this
        /// turns false. Always false unless the server allowed carrier
        /// early data ([`crate::EarlyData::carrier_early_data`]).
        pub fn is_replayable(&self) -> bool {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::is_replayable(self)
        }

        /// The priority the peer requested for this stream in its preamble.
        pub fn requested_priority(&self) -> Option<crate::Priority> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::requested_priority(self)
        }

        /// The application byte counters of the stream:
        /// `bytes_read` and `datagram_bytes_received` are this receiving
        /// part's. Read without a lock, from any thread; final once the part
        /// is terminal. A bidirectional stream's two handles share the meter.
        pub fn meter(&self) -> &::std::sync::Arc<crate::Meter> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::meter(self)
        }

        /// A snapshot of the stream's statistics; `None`
        /// once the session no longer holds the stream.
        pub fn stats(&self) -> Option<crate::StreamStats> {
            <Self as crate::driver::handle::RecvStreamApi<$d>>::stats(self)
        }
    };
}
pub(crate) use recvstream_api;
