//! The std driver: a reader thread and a writer thread per pipe own its
//! I/O, a timer thread runs the core's timers. The application's handles
//! (`super::handle`) are the tokio driver's: a waiting call runs the shared
//! future on the calling thread, parking it between polls ([`run`]).

use std::future::Future;
use std::io::{self, IoSlice, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::context::{DriverThread, on_driver_thread};
use super::engine::{self, Calls, Outbound, Progress};
use super::handle::{self, CarrierInfo, Driver, Shared, State};
use super::sync::{park, thread_waker};
use super::tcp::{Probe, TcpSocket};
use super::wait::WaitList;
use super::{Event, IDLE_READ, IDLE_RELEASE, MAX_SLICES};
use crate::error::{ConnectError, ReadExactError, ReadToEndError};
use crate::proto::VarInt;
use crate::proto::params::Role;
use crate::proto::record::Framing;
use crate::proto::session::{
    Config, DatagramError, OpenError, PickRequest, PipeEnd, PipeError, PipeHalf, PipeId,
    PipeOptions, Preamble, RoleConfig, SessionError, State as CoreState, StreamError,
};

type Closer = Box<dyn Fn(Shutdown) + Send + Sync>;

/// A zmux session driven by threads: the API of `zmux::Session` with the
/// calls that wait blocking the calling thread. Clones share the session;
/// it closes with code 0 when the last session and stream handle is
/// dropped.
pub type Session = handle::Session<Blocking>;
/// The sending part of a stream of a blocking session; implements
/// `std::io::Write`. Dropping it without `finish` resets the stream with
/// code 0.
pub type SendStream = handle::SendStream<Blocking>;
/// The receiving part of a stream of a blocking session; implements
/// `std::io::Read`. Dropping it before the end stops the stream with code
/// 0.
pub type RecvStream = handle::RecvStream<Blocking>;
/// A pipe of a blocking session.
pub type Pipe = handle::Pipe<Blocking>;
/// A pipe of a blocking session reserved for an out-of-band join.
pub type PipeReservation = handle::PipeReservation<Blocking>;

impl Session {
    handle::session_api!(Blocking, PipeIo);
}

impl Pipe {
    handle::pipe_api!(Blocking, PipeIo);
}

impl PipeReservation {
    handle::pipereservation_api!(Blocking, PipeIo);
}

impl SendStream {
    handle::sendstream_api!(Blocking, PipeIo);
}

impl RecvStream {
    handle::recvstream_api!(Blocking, PipeIo);
}

/// Shuts a TCP socket down, each side on its own: on macOS,
/// `shutdown(SHUT_RDWR)` of a socket whose read side is already shut down
/// (the inbound half closed first) fails with ENOTCONN and leaves the write
/// side open, so a writer thread blocked in `write` on a peer that stopped
/// reading would never return.
///
/// On Windows a shutdown does not end a `recv` blocked in another thread
/// on a peer that sends nothing: the blocked calls are cancelled as well
/// (`super::tcp::cancel_blocked`).
fn shut_down(socket: &TcpStream, how: Shutdown) {
    match how {
        Shutdown::Both => {
            let _ = socket.shutdown(Shutdown::Write);
            let _ = socket.shutdown(Shutdown::Read);
            #[cfg(windows)]
            super::tcp::cancel_blocked(socket);
        }
        how => {
            let _ = socket.shutdown(how);
        }
    }
}

/// A TCP stream shared by a carrier's reader and writer threads (reads and
/// writes go through `&TcpStream`).
struct SharedTcp(Arc<TcpStream>);

impl Read for SharedTcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for SharedTcp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&*self.0).write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// A carrier for a blocking session: a readable half, a writable half, or
/// both.
pub struct PipeIo {
    reader: Option<Box<dyn Read + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    closer: Option<Closer>,
    framing: Framing,
    abort: Option<Box<dyn FnOnce() + Send>>,
    exporter: Option<Box<super::handle::Exporters>>,
    protocol: Option<String>,
    /// The TCP socket under the carrier: its minimum RTT, unsent bytes and
    /// low-water mark ([`Probe`]).
    socket: Option<TcpSocket>,
    /// The carrier has a low-water mark.
    low_water: bool,
}

impl PipeIo {
    /// A TCP carrier: the write side ends with `shutdown(Write)`, and the
    /// socket is shut down when the session ends (which also ends a read or
    /// write blocked on a peer that went silent). The kernel's minimum RTT
    /// and unsent bytes are queried and `TCP_NOTSENT_LOWAT` follows the send
    /// rate as for `zmux::PipeIo::tcp`.
    pub fn tcp(stream: TcpStream) -> io::Result<Self> {
        let _ = stream.set_nodelay(true);
        // One descriptor: the threads, the closer, the abort and the
        // socket queries share it.
        let stream = Arc::new(stream);
        let socket = Some(TcpSocket::shared(stream.clone()));
        // Where the platform has a low-water mark, the carrier offers it.
        let low_water = socket
            .as_ref()
            .is_some_and(|s| s.set_notsent_lowat(super::NOTSENT_LOWAT_SINGLE));
        let (control, abort) = (stream.clone(), stream.clone());
        Ok(Self {
            reader: Some(Box::new(SharedTcp(stream.clone()))),
            writer: Some(Box::new(SharedTcp(stream))),
            closer: Some(Box::new(move |how| shut_down(&control, how))),
            framing: Framing::ByteStream,
            abort: Some(Box::new(move || shut_down(&abort, Shutdown::Both))),
            exporter: None,
            protocol: None,
            socket,
            low_water,
        })
    }

    /// A carrier from separate halves. The write side ends by dropping the
    /// writer; the reader thread ends when its reader does. A read or write
    /// blocked in such halves is interrupted only by a closer
    /// ([`PipeIo::with_closer`]).
    pub fn from_halves<R, W>(reader: R, writer: W) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        Self {
            reader: Some(Box::new(reader)),
            writer: Some(Box::new(writer)),
            closer: None,
            framing: Framing::ByteStream,
            abort: None,
            exporter: None,
            protocol: None,
            socket: None,
            low_water: false,
        }
    }

    /// An inbound-only carrier.
    pub fn reader<R: Read + Send + 'static>(reader: R) -> Self {
        let mut p = Self::from_halves(reader, io::sink());
        p.writer = None;
        p
    }

    /// An outbound-only carrier.
    pub fn writer<W: Write + Send + 'static>(writer: W) -> Self {
        let mut p = Self::from_halves(io::empty(), writer);
        p.reader = None;
        p
    }

    /// Message framing: every read returns one whole message and every
    /// write call carries one (SPEC.md Section 3.4).
    #[must_use]
    pub fn records(mut self) -> Self {
        self.framing = Framing::Records;
        self
    }

    /// Ends the carrier's halves from another thread, like
    /// `TcpStream::shutdown`: called with [`Shutdown::Read`] when the
    /// inbound half is closed, [`Shutdown::Write`] after the outbound half
    /// ended gracefully, and [`Shutdown::Both`] once the session ended, so
    /// that a read or write blocked in the carrier returns. It must not block. TCP carriers
    /// ([`PipeIo::tcp`]) have one.
    #[must_use]
    pub fn with_closer(mut self, closer: impl Fn(Shutdown) + Send + Sync + 'static) -> Self {
        self.closer = Some(Box::new(closer));
        self
    }

    /// Declares that the carrier bounds what it holds unsent itself, as a
    /// socket with a low-water mark does: a write blocks while it holds
    /// more than a small amount, so that its buffer never becomes a deep
    /// queue. Such a carrier is not paced by the carrier queue limiter; one
    /// that declares nothing is, in
    /// multipath sessions. TCP carriers
    /// ([`PipeIo::tcp`]) declare it themselves where the platform has
    /// `TCP_NOTSENT_LOWAT`.
    #[must_use]
    pub fn with_low_water(mut self) -> Self {
        self.low_water = true;
        self
    }

    /// Called instead of a graceful close when zmux fails the pipe.
    #[must_use]
    pub fn with_abort(mut self, abort: impl FnOnce() + Send + 'static) -> Self {
        self.abort = Some(Box::new(abort));
        self
    }

    /// The carrier's TLS 1.3 exporter (RFC 8446 Section 7.5, MULTIPATH.md
    /// Section 10): `export(label)` returns TLS-Exporter(label, "", 32) of
    /// the handshake that carries the pipe and terminates at the peer (the
    /// carrier's own TLS connection, or the QUIC connection whose stream the
    /// carrier is, RFC 9001 Section 4), or `None` when there is none. It is
    /// called here once for each label zmux uses: `EXPORTER-zmux-session`
    /// (the session secret, for a bootstrap carrier with
    /// [`crate::PipeAuth::tls`]; for a split bootstrap the 64-byte
    /// concatenation of the uplink's and the downlink's values) and
    /// `EXPORTER-zmux-pipe` (the binding of a carrier-bound join, made or
    /// accepted on this carrier, 32 bytes). Values of other lengths are
    /// taken as no exporter.
    ///
    /// Export only once the handshake completed, never an early exporter,
    /// and send no carrier-bound join as TLS or QUIC early data (0-RTT). A
    /// carrier without such a handshake (plain TCP, KCP, a TLS connection
    /// that an intermediary terminates) has none (MULTIPATH.md Section
    /// 10.5).
    #[must_use]
    pub fn with_tls_exporter(mut self, export: impl FnMut(&str) -> Option<Vec<u8>>) -> Self {
        self.exporter = super::handle::Exporters::take(export);
        self
    }

    /// The application protocol the carrier negotiated (for example the
    /// ALPN identifier), reported by `Session::protocol`.
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }
}

impl std::fmt::Debug for PipeIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeIo")
            .field("reader", &self.reader.is_some())
            .field("writer", &self.writer.is_some())
            .finish()
    }
}

// ---- the driver -------------------------------------------------------------------------
//
// Concurrency (see `super::wake`): one core lock per session. Threads wait
// by parking: a waiting thread registers its waker under the lock, and
// wake-ups and carrier shutdowns decided under the lock are carried out
// after it was released. A timer thread per session runs the core's timers,
// so they fire while every writer is blocked in a write or gone, and once
// the session is closed it ends every carrier with a closer, so that no
// thread stays blocked in its I/O. The pipe threads own their halves
// outright: no side is shared with the application.

/// The std driver: threads per pipe and session (feature `blocking`).
#[derive(Debug)]
pub enum Blocking {}

/// The std driver's part of the session state.
pub struct Io {
    /// Carrier halves the core asked to close: pipe, half, abort.
    closing: Vec<(u64, PipeHalf, bool)>,
    /// A close was asked for since the writers were last woken.
    wake_writers: bool,
    /// Socket closers of the pipes with threads alive, to end a blocked
    /// read or write.
    closers: Vec<PipeThreads>,
    /// Writer threads waiting for output.
    writers: WaitList,
    /// Writer threads running.
    writers_alive: usize,
    /// The timer thread while it waits, and its deadline.
    timer: Option<(std::task::Waker, Option<Instant>)>,
}

/// The threads of a pipe and its closer.
struct PipeThreads {
    id: u64,
    closer: Arc<Closer>,
    threads: usize,
}

/// Work decided under the core lock, done after it (before the wake-ups).
#[derive(Default)]
pub struct Deferred {
    /// `shutdown(2)` calls: they do not block, and end a blocked read or
    /// write on the socket.
    shutdowns: Vec<(Arc<Closer>, Shutdown)>,
    /// Closers no thread needs any more: dropping the last one closes its
    /// socket.
    released: Vec<Arc<Closer>>,
}

impl Drop for Deferred {
    fn drop(&mut self) {
        for (c, how) in self.shutdowns.drain(..) {
            c(how);
        }
        // `released` drops next: the sockets close.
    }
}

/// The application's dial function for the std driver: a new carrier for
/// a [`DialRequest`](crate::DialRequest) (`resolve_duplicate`'s `rejoin`).
///
/// ```no_run
/// let dial = zmux::blocking::Dial::new(|_req| {
///     zmux::blocking::PipeIo::tcp(std::net::TcpStream::connect("127.0.0.1:4433")?)
/// });
/// # let _ = dial;
/// ```
#[derive(Clone)]
pub struct Dial(Arc<dyn Fn(super::DialRequest) -> io::Result<PipeIo> + Send + Sync>);

impl Dial {
    /// A dial function from a closure.
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(super::DialRequest) -> io::Result<PipeIo> + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }

    /// Dials a carrier for `req`.
    pub fn dial(&self, req: super::DialRequest) -> io::Result<PipeIo> {
        (self.0)(req)
    }
}

impl std::fmt::Debug for Dial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dial(..)")
    }
}

impl Driver for Blocking {
    type Io = Io;
    type Deferred = Deferred;
    type Paths = ();
    type Carrier = PipeIo;
    type Timeout = Option<Duration>;
    type Dial = Dial;

    fn now() -> Instant {
        Instant::now()
    }

    fn deferred_pending(d: &Deferred) -> bool {
        !d.shutdowns.is_empty() || !d.released.is_empty()
    }

    fn close_pipe(state: &mut State<Self>, pipe: u64, half: PipeHalf, abort: bool) {
        state.io.closing.push((pipe, half, abort));
        state.io.wake_writers = true;
        if half == PipeHalf::Inbound
            && let Some(p) = state.io.closers.iter().find(|p| p.id == pipe)
        {
            // shutdown(2) ends a blocked read (after the lock).
            state
                .deferred
                .shutdowns
                .push((p.closer.clone(), Shutdown::Read));
        }
    }

    fn wake_driver(state: &mut State<Self>) {
        state.wake_timer();
    }

    fn kick(state: &mut State<Self>) {
        if std::mem::take(&mut state.io.wake_writers)
            || state.core.wants_write_any()
            || state.core.wants_pick()
            || state.core.state() >= CoreState::Closing
        {
            state.io.writers.wake_all(&mut state.wakes);
        }
        if let Some((_, until)) = &state.io.timer {
            let earlier = state
                .core
                .poll_timeout()
                .is_some_and(|t| until.is_none_or(|u| t < u));
            if earlier || state.core.state() == CoreState::Closed {
                state.wake_timer();
            }
        }
    }

    fn carrier_info(carrier: &mut PipeIo) -> CarrierInfo {
        CarrierInfo {
            inbound: carrier.reader.is_some().then_some(carrier.framing),
            outbound: carrier.writer.is_some().then_some(carrier.framing),
            exporter: carrier.exporter.take(),
            protocol: carrier.protocol.take(),
        }
    }

    fn attach(shared: &Arc<Shared<Self>>, id: u64, carrier: PipeIo) -> Result<(), PipeError> {
        spawn_pipe(shared, id, carrier).map_err(|e| PipeError::Io(e.kind()))
    }

    fn start_rejoin(session: handle::WeakSession<Self>, dial: Dial) -> bool {
        thread::Builder::new()
            .name("zmux-rejoin".into())
            .spawn(move || {
                if let Ok(pipe) = dial.dial(super::DialRequest::bidi())
                    && let Some(session) = session.upgrade()
                {
                    let _ = session.add_pipe(pipe, PipeOptions::default());
                }
            })
            .is_ok()
    }

    #[cfg(feature = "test-hooks")]
    fn io_tables(io: &Io) -> (usize, usize, usize, usize) {
        (io.writers.len(), io.closing.len(), 0, 0)
    }
}

impl State<Blocking> {
    /// Ends every carrier (after the lock).
    fn shut_down_all(&mut self) {
        for p in &self.io.closers {
            self.deferred
                .shutdowns
                .push((p.closer.clone(), Shutdown::Both));
        }
    }

    /// A thread of pipe `id` ended: the pipe's closer goes with the last
    /// (dropped after the lock).
    fn thread_done(&mut self, id: PipeId) {
        if let Some(i) = self.io.closers.iter().position(|p| p.id == id.0) {
            self.io.closers[i].threads -= 1;
            if self.io.closers[i].threads == 0 {
                let p = self.io.closers.swap_remove(i);
                self.deferred.released.push(p.closer);
            }
        }
    }

    /// Wakes the timer thread (after the lock).
    fn wake_timer(&mut self) {
        if let Some((w, _)) = self.io.timer.take() {
            self.wakes.push(w);
        }
    }

    /// Whether the core asked to close a pipe's half; removes the request.
    fn take_close(&mut self, id: PipeId, half: PipeHalf) -> Option<bool> {
        let i = self
            .io
            .closing
            .iter()
            .position(|(p, h, _)| *p == id.0 && *h == half)?;
        Some(self.io.closing.swap_remove(i).2)
    }
}

/// Starts the threads of a pipe's halves. Added pipes (`id` > 0) belong to
/// a multipath session.
fn spawn_pipe(shared: &Arc<Shared<Blocking>>, id: u64, pipe: PipeIo) -> io::Result<()> {
    let PipeIo {
        reader,
        writer,
        closer,
        framing,
        abort,
        socket,
        low_water,
        ..
    } = pipe;
    let lowat = if id == 0 {
        super::NOTSENT_LOWAT_SINGLE
    } else {
        super::NOTSENT_LOWAT_MULTIPATH
    };
    if id != 0
        && let Some(s) = &socket
    {
        s.set_notsent_lowat(lowat);
    }
    // Only a writer thread uses the probe: without one there is nothing to
    // tune.
    let probe = socket.map(|s| Probe::new(s, lowat, Instant::now()));
    let closer: Option<Arc<Closer>> = closer.map(Arc::new);
    if let Some(c) = &closer {
        let threads = usize::from(reader.is_some()) + usize::from(writer.is_some());
        shared.lock().io.closers.push(PipeThreads {
            id,
            closer: c.clone(),
            threads,
        });
    }
    if let Some(r) = reader {
        let s = shared.clone();
        let spawned = thread::Builder::new()
            .name("zmux-read".into())
            .spawn(move || reader_thread(s, PipeId(id), r, framing));
        if let Err(e) = spawned {
            let mut st = shared.lock();
            st.thread_done(PipeId(id));
            if writer.is_some() {
                st.thread_done(PipeId(id));
            }
            return Err(e);
        }
    }
    if let Some(w) = writer {
        let s = shared.clone();
        let c = closer.clone();
        {
            let mut st = shared.lock();
            st.io.writers_alive += 1;
            // Before the pipe's first write.
            st.core.set_pipe_low_water(PipeId(id), low_water);
        }
        let spawned = thread::Builder::new()
            .name("zmux-write".into())
            .spawn(move || writer_thread(s, PipeId(id), w, c, abort, framing, probe));
        if let Err(e) = spawned {
            let mut st = shared.lock();
            st.io.writers_alive -= 1;
            st.thread_done(PipeId(id));
            return Err(e);
        }
    }
    Ok(())
}

// ---- threads -----------------------------------------------------------------------

/// Runs `fut` on this thread until it completes, parking the thread
/// between polls (its waker unparks it); `None` once `deadline` passed. The
/// future is dropped before this returns, so a wait that timed out leaves
/// its list.
fn run<F: Future>(fut: F, deadline: Option<Instant>) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let waker = thread_waker();
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            return Some(r);
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return None;
        }
        park(deadline);
    }
}

/// An error a blocking call returns when it is refused on a thread that
/// drives sessions.
trait Refused {
    fn on_driver_thread() -> Self;
}

/// An error a blocking stream call returns when its timeout expired.
trait Expired: Refused {
    fn timed_out() -> Self;
}

/// Why a session-wide wait of the std driver failed (`accept_bi`,
/// `read_datagram`, `ping`, `shutdown`, `closed`, `next_event`): the
/// session ended, or the call was refused on a thread that drives sessions
/// and the session is unaffected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitError {
    /// The session ended.
    Closed(SessionError),
    /// A blocking call on a thread that drives sessions (inside a tokio
    /// runtime, or on a session's own threads).
    OnDriverThread,
    /// The wait's timeout expired.
    TimedOut,
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(e) => e.fmt(f),
            Self::OnDriverThread => f.write_str(crate::proto::session::ON_DRIVER_THREAD),
            Self::TimedOut => f.write_str("wait timed out"),
        }
    }
}

impl std::error::Error for WaitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Closed(e) => Some(e),
            Self::OnDriverThread | Self::TimedOut => None,
        }
    }
}

impl From<SessionError> for WaitError {
    fn from(e: SessionError) -> Self {
        Self::Closed(e)
    }
}

impl From<WaitError> for io::Error {
    fn from(e: WaitError) -> Self {
        match e {
            WaitError::Closed(s) => s.into(),
            WaitError::OnDriverThread => io::Error::new(io::ErrorKind::Deadlock, e),
            WaitError::TimedOut => io::Error::new(io::ErrorKind::TimedOut, e),
        }
    }
}

impl Refused for WaitError {
    fn on_driver_thread() -> Self {
        Self::OnDriverThread
    }
}

impl Refused for OpenError {
    fn on_driver_thread() -> Self {
        Self::OnDriverThread
    }
}

impl Refused for DatagramError {
    fn on_driver_thread() -> Self {
        Self::OnDriverThread
    }
}

impl Refused for ConnectError {
    fn on_driver_thread() -> Self {
        Self::OnDriverThread
    }
}

impl Refused for StreamError {
    fn on_driver_thread() -> Self {
        Self::OnDriverThread
    }
}

impl Expired for StreamError {
    fn timed_out() -> Self {
        Self::TimedOut
    }
}

impl Refused for ReadExactError {
    fn on_driver_thread() -> Self {
        Self::Read(StreamError::OnDriverThread)
    }
}

impl Expired for ReadExactError {
    fn timed_out() -> Self {
        Self::Read(StreamError::TimedOut)
    }
}

impl Refused for ReadToEndError {
    fn on_driver_thread() -> Self {
        Self::Read(StreamError::OnDriverThread)
    }
}

impl Expired for ReadToEndError {
    fn timed_out() -> Self {
        Self::Read(StreamError::TimedOut)
    }
}

/// An application call that may wait, without a timeout: refused at once
/// on a thread that drives sessions.
fn call<T, E: Refused>(fut: impl Future<Output = Result<T, E>>) -> Result<T, E> {
    if on_driver_thread() {
        return Err(E::on_driver_thread());
    }
    run(fut, None).unwrap_or_else(|| Err(E::on_driver_thread()))
}

/// A stream call that may wait up to `timeout` (`None`: forever). A zero
/// timeout never blocks and works on any thread.
fn call_timeout<T, E: Expired>(
    timeout: Option<Duration>,
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    if timeout != Some(Duration::ZERO) && on_driver_thread() {
        return Err(E::on_driver_thread());
    }
    run(fut, timeout.map(|t| Instant::now() + t)).unwrap_or_else(|| Err(E::timed_out()))
}

fn reader_thread(
    shared: Arc<Shared<Blocking>>,
    id: PipeId,
    mut reader: Box<dyn Read + Send>,
    framing: Framing,
) {
    let _driver = DriverThread::enter();
    let mut buf = Some(super::read_pool::take_initialized());
    let mut filled = 0;
    loop {
        let started = Instant::now();
        let result = match &mut buf {
            Some(b) => reader.read(&mut b[filled..]),
            None => {
                // An idle byte stream waits for its next record in a small
                // stack buffer.
                let mut small = [0u8; IDLE_READ];
                let r = reader.read(&mut small);
                if let Ok(n @ 1..) = r {
                    let mut b = super::read_pool::take_initialized();
                    b[..n].copy_from_slice(&small[..n]);
                    buf = Some(b);
                }
                r
            }
        };
        let mut st = shared.lock();
        let now = Instant::now();
        if st.take_close(id, PipeHalf::Inbound).is_some() {
            st.after_command();
            st.thread_done(id);
            break;
        }
        let done = match result {
            Ok(0) => {
                st.core.pipe_ended(id, PipeEnd::Eof, now);
                true
            }
            Ok(n) if framing == Framing::Records => {
                let b = buf.as_deref().unwrap_or_default();
                st.core.receive_message(id, &b[..n], now);
                st.core.state() == CoreState::Closed
            }
            Ok(n) => {
                let b = buf.as_deref_mut().unwrap_or_default();
                filled += n;
                let used = st.core.receive_in_place(id, &b[..filled], now);
                if used > 0 {
                    b.copy_within(used..filled, 0);
                    filled -= used;
                }
                st.core.state() == CoreState::Closed
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => false,
            // An empty message: an empty record.
            Err(e) if framing == Framing::Records && super::is_empty_message(&e) => {
                st.core.receive_message(id, &[], now);
                st.core.state() == CoreState::Closed
            }
            Err(e) => {
                st.core.pipe_ended(id, PipeEnd::Error(e.kind()), now);
                true
            }
        };
        st.after_command();
        if done {
            st.thread_done(id);
            break;
        }
        drop(shared.police_datagrams(st));
        // A byte stream that waited this long for bytes that completed its
        // records is idle: its buffer goes until the next record starts.
        if framing == Framing::ByteStream
            && filled == 0
            && now.saturating_duration_since(started) >= IDLE_RELEASE
            && let Some(b) = buf.take()
        {
            super::read_pool::give(b);
        }
    }
    // The pipe's buffer serves the next reads of any pipe.
    if let Some(b) = buf {
        super::read_pool::give(b);
    }
}

/// Writes the batch in calls of at most `limit(left)` bytes, `left` being
/// what is left of it (one message per call on a message-framed carrier,
/// whose messages were built within the bound), then flushes.
fn write_batch(
    writer: &mut dyn Write,
    out: &mut Outbound,
    mut limit: impl FnMut(&mut Outbound) -> usize,
) -> io::Result<()> {
    while !out.is_empty() {
        let written = if out.framing() == Framing::Records {
            let msg = out.message();
            writer.write_all(msg)?;
            msg.len()
        } else {
            let mut slices = [IoSlice::new(&[]); MAX_SLICES];
            let max = limit(out);
            let n = out.slices(max, &mut slices);
            match writer.write_vectored(&slices[..n]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(w) => w,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => 0,
                Err(e) => return Err(e),
            }
        };
        out.written(written);
    }
    writer.flush()
}

fn writer_thread(
    shared: Arc<Shared<Blocking>>,
    id: PipeId,
    mut writer: Box<dyn Write + Send>,
    closer: Option<Arc<Closer>>,
    mut abort: Option<Box<dyn FnOnce() + Send>>,
    framing: Framing,
    mut probe: Option<Probe>,
) {
    let _driver = DriverThread::enter();
    let me = thread_waker();
    let mut ticket = None;
    let mut out = Outbound::new(framing, Calls::Blocking);
    let mut progress = Progress::default();
    // The write call in progress: its start and size.
    let mut call = (Instant::now(), 0);
    let mut pick = PickRequest::default();
    loop {
        // The carrier is queried without the lock, fed to the core under
        // it, and its low-water mark set after it (`Probe`).
        if let Some(p) = &mut probe {
            p.query(Instant::now());
        }
        let mut st = shared.lock();
        if let Some(p) = &mut probe {
            p.feed(&mut st.core, id, Instant::now());
        }
        let ready = loop {
            if let Some(abortive) = st.take_close(id, PipeHalf::Outbound) {
                break Err(abortive);
            }
            if st.core.state() == CoreState::Closed {
                break Err(false);
            }
            // Reads run on their own thread: no input is pending here, and
            // batches stay full.
            let now = Instant::now();
            let took = out.take_batch(&mut st.core, id, now, false);
            if took {
                // The write call is in progress (MULTIPATH.md 7.1).
                call = (now, out.left());
                progress.started(now, call.1);
                let _ = progress.report(&mut st.core, id, false, now);
            }
            st.after_command();
            if took {
                break Ok(());
            }
            // A custom scheduling decision: the policy runs on this thread without the lock (a
            // blocking zmux call there fails at once), and its answer is
            // applied if the view is still current.
            if st.core.take_pick(&mut pick) {
                drop(st);
                pick.run();
                st = shared.lock();
                st.core.answer_pick(&pick);
                st.after_command();
                continue;
            }
            // Timers are the timer thread's: wait for output or a close.
            st.io.writers.register(&mut ticket, &me);
            drop(st);
            park(None);
            st = shared.lock();
        };
        if let Some(t) = ticket.take() {
            st.io.writers.remove(t);
        }
        drop(st);
        if let Some(p) = &mut probe {
            p.apply();
        }
        if let Err(abortive) = ready {
            if abortive && let Some(f) = abort.take() {
                f();
            }
            break;
        }
        let shutdown = out.shutdown_pending();
        // Blocking write calls are bounded, each as
        // the core's state is when it starts; a limit holds for the calls
        // of the batch within the latency budget, without the lock.
        let result = write_batch(&mut *writer, &mut out, |out| {
            out.call_limit(false, Instant::now(), |left| {
                let st = shared.lock();
                (
                    st.core
                        .write_call_limit(id, left, true, false, Instant::now()),
                    st.core.latency_budget(),
                )
            })
        });
        let mut st = shared.lock();
        let now = Instant::now();
        // A blocking adapter's call returns once the bytes are handed on:
        // the carrier holds none of them unsent.
        progress.returned(call.0, now, call.1 - out.left(), false);
        let _ = progress.report(&mut st.core, id, false, now);
        if let Err(e) = &result {
            st.core.write_failed(id, e.kind(), Instant::now());
            st.after_command();
            break;
        }
        st.after_command();
        drop(st);
        if shutdown {
            out.shutdown_done();
            if let Some(c) = &closer {
                c(Shutdown::Write);
            }
            break;
        }
    }
    // The pipe is done: end the carrier half so its reader thread returns
    // once the session ended.
    drop(writer);
    let closed = {
        let mut st = shared.lock();
        st.io.writers_alive -= 1;
        st.thread_done(id);
        st.wake_timer();
        st.core.state() == CoreState::Closed
    };
    if closed && let Some(c) = closer {
        c(Shutdown::Both);
    }
}

/// Runs the session's timers until it is closed; then, after the last
/// batches had [`FINAL_WRITE`] to be written, ends every carrier with a
/// closer, so that no thread stays blocked in a read or write of a peer that
/// went silent. Starts the session's hook thread when the core needs it.
fn timer_thread(shared: Arc<Shared<Blocking>>) {
    let _driver = DriverThread::enter();
    let me = thread_waker();
    loop {
        let mut st = shared.lock();
        let now = Instant::now();
        if engine::fire_timers(&mut st.core, now) {
            st.after_command();
        }
        if let Some(hooks) = st.take_hook_start() {
            drop(st);
            let s = shared.clone();
            // `allow_connection_window_increase` and the tracer run on a
            // thread of their own; a blocking zmux call from them fails at
            // once.
            let spawned = thread::Builder::new()
                .name("zmux-hook".into())
                .spawn(move || {
                    let _driver = DriverThread::enter();
                    run(handle::run_hook(s, hooks), None);
                });
            if spawned.is_err() {
                // Refused, so that the core proposes again later.
                let mut st = shared.lock();
                st.hook_not_started();
                st.after_command();
            }
            continue;
        }
        // After the hook start: a tracer is told even of a session that
        // ended before this thread's first round.
        if st.core.state() == CoreState::Closed {
            break;
        }
        let until = engine::timer_deadline(st.core.poll_timeout(), now);
        st.io.timer = Some((me.clone(), until));
        drop(st);
        park(until);
    }
    let deadline = Instant::now() + engine::FINAL_WRITE;
    loop {
        let mut st = shared.lock();
        if st.io.writers_alive == 0 || Instant::now() >= deadline {
            st.io.timer = None;
            st.shut_down_all();
            return;
        }
        st.io.timer = Some((me.clone(), Some(deadline)));
        drop(st);
        park(Some(deadline));
    }
}

// ---- the application's calls ------------------------------------------------------------

impl Session {
    /// Establishes a session as the dialling side of `pipe`.
    pub fn connect(pipe: PipeIo, config: impl Into<Arc<Config>>) -> Result<Session, ConnectError> {
        Self::start(pipe, config, RoleConfig::Initiator, Some(Role::Initiator))
    }

    /// Establishes a session as the accepting side of `pipe`. Such a
    /// session cannot accept joins: a configuration that offers multipath
    /// is refused ([`ConnectError::InvalidConfig`]).
    pub fn accept(pipe: PipeIo, config: impl Into<Arc<Config>>) -> Result<Session, ConnectError> {
        let config = config.into();
        if config.offers_multipath() {
            return Err(ConnectError::InvalidConfig(
                "a session accepted without a listener cannot accept joins",
            ));
        }
        Self::start(pipe, config, RoleConfig::Responder, Some(Role::Responder))
    }

    /// Establishes a session over a symmetric carrier (`zmux_role` auto).
    pub fn peer(pipe: PipeIo, config: impl Into<Arc<Config>>) -> Result<Session, ConnectError> {
        let config = config.into();
        super::check_peer(&config)?;
        Self::start(pipe, config, RoleConfig::Auto, None)
    }

    fn start(
        mut pipe: PipeIo,
        config: impl Into<Arc<Config>>,
        role: RoleConfig,
        transport: Option<Role>,
    ) -> Result<Session, ConnectError> {
        // Before anything is spawned: nothing to release.
        if on_driver_thread() {
            return Err(ConnectError::OnDriverThread);
        }
        let carrier = Blocking::carrier_info(&mut pipe);
        let io = Io {
            closing: Vec::new(),
            wake_writers: false,
            closers: Vec::new(),
            writers: WaitList::default(),
            writers_alive: 0,
            timer: None,
        };
        let shared = Arc::new(Shared::new(
            State::new(config.into(), role, transport, None, carrier, io)?,
            (),
        ));
        // The handle counted first: if a thread cannot be started, dropping
        // it closes the session, and the threads started end.
        let establish = shared.clone().established();
        let s = shared.clone();
        thread::Builder::new()
            .name("zmux-timer".into())
            .spawn(move || timer_thread(s))
            .map_err(|e| ConnectError::Io(Arc::new(e)))?;
        spawn_pipe(&shared, 0, pipe).map_err(|e| ConnectError::Io(Arc::new(e)))?;
        drop(shared);
        call(establish)
    }

    /// Opens a bidirectional stream, waiting for stream credit; waiting
    /// openers get credit first come, first served.
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream), OpenError> {
        call(self.open_bi_wait(None))
    }

    /// Opens a bidirectional stream with `preamble`, waiting for stream
    /// credit (see `zmux::Session::open_bi_with`).
    pub fn open_bi_with(&self, preamble: &Preamble) -> Result<(SendStream, RecvStream), OpenError> {
        call(self.open_bi_wait(Some(preamble)))
    }

    /// Opens a unidirectional stream, waiting for stream credit.
    pub fn open_uni(&self) -> Result<SendStream, OpenError> {
        call(self.open_uni_wait(None))
    }

    /// Opens a unidirectional stream with `preamble`, waiting for stream
    /// credit.
    pub fn open_uni_with(&self, preamble: &Preamble) -> Result<SendStream, OpenError> {
        call(self.open_uni_wait(Some(preamble)))
    }

    /// Accepts the next bidirectional stream the peer opened.
    pub fn accept_bi(&self) -> Result<(SendStream, RecvStream), WaitError> {
        call(async { Ok(self.accept_bi_wait().await?) })
    }

    /// Accepts the next unidirectional stream the peer opened.
    pub fn accept_uni(&self) -> Result<RecvStream, WaitError> {
        call(async { Ok(self.accept_uni_wait().await?) })
    }

    /// Queues a session datagram, waiting while the queue is full.
    pub fn send_datagram_wait(&self, data: Bytes) -> Result<(), DatagramError> {
        call(self.send_datagram_wait_op(data))
    }

    /// Receives the next session datagram.
    pub fn read_datagram(&self) -> Result<Bytes, WaitError> {
        call(async { Ok(self.read_datagram_op().await?) })
    }

    /// Closes gracefully and waits until the session ended: `Ok` when it
    /// closed as requested, otherwise the error that ended it first. On a
    /// thread that drives sessions it fails at once and does nothing.
    pub fn shutdown(&self, code: VarInt, reason: &[u8]) -> Result<(), WaitError> {
        call(async { Ok(self.shutdown_op(code, reason).await?) })
    }

    /// Sends a QX_PING request, or joins the one outstanding, and waits
    /// for the round-trip time it measured; the sample
    /// also updates [`Session::rtt`](crate::blocking::Session#method.rtt) and the statistics. Works with every
    /// peer, plain QMux peers included. On a thread that drives sessions
    /// it fails at once.
    pub fn ping(&self) -> Result<Duration, WaitError> {
        call(async { Ok(self.ping_op().await?) })
    }

    /// Waits until the session ended and returns why; on a thread that
    /// drives sessions it fails at once ([`WaitError::OnDriverThread`]).
    pub fn closed(&self) -> Result<SessionError, WaitError> {
        call(async { Ok(self.closed_op().await) })
    }

    /// The next session event, waiting up to `timeout` (`None`: as long as
    /// it takes; [`WaitError::TimedOut`] when it expires); `None` once the
    /// session ended and every event was read. A zero timeout never waits
    /// (and works on any thread).
    pub fn next_event(&self, timeout: Option<Duration>) -> Result<Option<Event>, WaitError> {
        if timeout != Some(Duration::ZERO) && on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        let deadline = timeout.map(|t| Instant::now() + t);
        run(self.next_event_op(), deadline).ok_or(WaitError::TimedOut)
    }
}

impl Pipe {
    /// Waits until the pipe's join is confirmed or failed (see
    /// `zmux::Pipe::joined`), up to `timeout` (`None`: as long as it takes;
    /// [`PipeError::TimedOut`] when it expires).
    pub fn joined(&self, timeout: Option<Duration>) -> Result<(), PipeError> {
        if timeout != Some(Duration::ZERO) && on_driver_thread() {
            return Err(PipeError::OnDriverThread);
        }
        let deadline = timeout.map(|t| Instant::now() + t);
        run(self.joined_op(), deadline).unwrap_or(Err(PipeError::TimedOut))
    }
}

impl SendStream {
    /// Bounds how long each call that writes waits; `None` waits forever.
    /// A call that timed out fails with [`StreamError::TimedOut`].
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// Writes some of `buf`, waiting for room.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, StreamError> {
        call_timeout(self.timeout, self.write_op(buf))
    }

    /// Writes all of `buf`; the write timeout bounds the whole call.
    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), StreamError> {
        call_timeout(self.timeout, self.write_all_op(buf))
    }

    /// Writes a chunk without copying it.
    pub fn write_chunk(&mut self, data: Bytes) -> Result<(), StreamError> {
        call_timeout(self.timeout, self.write_chunk_op(data))
    }

    /// Writes as many of `bufs` as the buffers take without copying them;
    /// a chunk taken in part is advanced. Waits until something is written.
    pub fn write_chunks(&mut self, bufs: &mut [Bytes]) -> Result<handle::Written, StreamError> {
        call_timeout(self.timeout, self.write_chunks_op(bufs))
    }

    /// Waits until the sending part ended: `None` when the FIN was written,
    /// or the peer's STOP_SENDING code. `None` says the data reached the
    /// peer's zmux endpoint at most, not its application (SPEC.md Section
    /// 7.4).
    pub fn stopped(&self) -> Result<Option<VarInt>, StreamError> {
        call(self.stopped_op())
    }

    /// Waits for send capacity of at least `min`
    /// bytes, or of any while the part holds nothing unsent, and returns
    /// it; returns at once with the error that ended the part (a reset or
    /// finish, the peer's STOP_SENDING, the session's end). The write
    /// timeout bounds the wait.
    pub fn wait_send_capacity(&self, min: u64) -> Result<u64, StreamError> {
        call_timeout(self.timeout, self.send_capacity_op(min))
    }
}

impl Write for SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        SendStream::write(self, buf).map_err(io::Error::from)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RecvStream {
    /// Bounds how long each call that reads waits; `None` waits forever.
    /// A call that timed out fails with [`StreamError::TimedOut`].
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// Reads into `buf`; `None` at the end of the stream.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamError> {
        call_timeout(self.timeout, self.read_op(buf))
    }

    /// Fills `buf` exactly; the read timeout bounds the whole call.
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        call_timeout(self.timeout, self.read_exact_op(buf))
    }

    /// Reads up to `max` bytes as one chunk; `None` at the end.
    pub fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>, StreamError> {
        call_timeout(self.timeout, self.read_chunk_op(max))
    }

    /// Fills as many of `bufs` as data is available for, without copying;
    /// returns how many were filled, or `None` at the end of the stream.
    pub fn read_chunks(&mut self, bufs: &mut [Bytes]) -> Result<Option<usize>, StreamError> {
        call_timeout(self.timeout, self.read_chunks_op(bufs))
    }

    /// Reads the whole stream, failing beyond `limit` bytes; the read
    /// timeout bounds the whole call.
    pub fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        call_timeout(self.timeout, self.read_to_end_op(limit))
    }

    /// Waits until the peer reset the stream: its code, or `None` when the
    /// stream ended with a FIN instead.
    pub fn received_reset(&mut self) -> Result<Option<VarInt>, StreamError> {
        call_timeout(self.timeout, self.received_reset_op())
    }

    /// Receives the next datagram of this stream.
    pub fn read_datagram(&self) -> Result<(u64, Bytes), StreamError> {
        call_timeout(self.timeout, self.read_datagram_op())
    }
}

impl Read for RecvStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match RecvStream::read(self, buf) {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}

crate::helpers::duplicate_api!(Blocking, Session, Dial);
