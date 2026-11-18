//! The std driver: a reader thread and a writer thread per pipe own its
//! I/O, one timer thread of the process runs the core's timers of every
//! session ([`session_timer`]). The application's handles
//! (`super::handle`) are the tokio driver's: a waiting call runs the shared
//! future on the calling thread, parking it between polls ([`run`]).

use std::future::Future;
use std::io::{self, IoSlice, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::context::{DriverThread, on_driver_thread};
use super::engine::{self, Calls, Outbound, Progress};
use super::handle::{self, CarrierInfo, Driver, Shared, State};
use super::session_timer::{self, Next};
use super::sync::{park, thread_waker};
use super::tcp::{Probe, TcpSocket};
use super::unsent::{RetransmittedQuery, Unsent, UnsentQuery};
use super::wait::WaitList;
use super::{Event, IDLE_READ, IDLE_RELEASE, MAX_SLICES};
use crate::error::{ConnectError, ReadExactError, ReadToEndError};
use crate::proto::VarInt;
use crate::proto::record::Framing;
use crate::proto::session::{
    Config, DatagramError, OpenError, PickRequest, PipeEnd, PipeError, PipeHalf, PipeId,
    PipeOptions, Preamble, Role, SessionError, State as CoreState, StreamError,
};

pub(crate) type Closer = Box<dyn Fn(Shutdown) + Send + Sync>;

/// A zmux session driven by threads: the API of `zmux::Session` with the
/// calls that wait blocking the calling thread. Clones share the session;
/// it closes with code 0 when the last session and stream handle is
/// dropped.
pub type Session = handle::Session<Blocking>;
/// The sending part of a stream of a blocking session; implements
/// `std::io::Write`. Dropping it without `finish` resets the stream with
/// `ZMUX_CANCELLED`.
pub type SendStream = handle::SendStream<Blocking>;
/// The receiving part of a stream of a blocking session; implements
/// `std::io::Read`. Dropping it before the end stops the stream with code
/// 0.
pub type RecvStream = handle::RecvStream<Blocking>;
/// A pipe of a blocking session.
pub type Pipe = handle::Pipe<Blocking>;

impl Session {
    handle::session_api!(Blocking, PipeIo);
}

handle::session_adapter!(Blocking);

impl Pipe {
    handle::pipe_api!(Blocking, PipeIo);
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

/// What ends a wait of a handshake on a carrier: the carrier's shutdown, or the deadline
/// set for it. A shutdown carrier fails the handshake's next read or write.
#[derive(Clone, Default)]
pub struct HandshakeWait(Arc<HandshakeWaitState>);

/// How often [`HandshakeWait::block_on`] looks for the carrier's shutdown.
const SHUT_POLL: Duration = Duration::from_millis(50);

#[derive(Default)]
struct HandshakeWaitState {
    /// The carrier was shut down, and the deadline.
    state: std::sync::Mutex<(bool, Option<Instant>)>,
    changed: std::sync::Condvar,
}

impl HandshakeWait {
    /// Waits for `d`, at most until the carrier's shutdown or the deadline.
    pub fn sleep(&self, d: Duration) {
        let asked = Instant::now().checked_add(d);
        let mut st = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let end = match (asked, st.1) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if st.0 {
                return;
            }
            st = match end {
                Some(end) => {
                    let left = end.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return;
                    }
                    self.0
                        .changed
                        .wait_timeout(st, left)
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .0
                }
                None => self
                    .0
                    .changed
                    .wait(st)
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            };
        }
    }

    fn shut(&self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0 = true;
        self.0.changed.notify_all();
    }

    /// Runs `fut` on this thread until it completes, bounded as the
    /// handshake's waits are: past the deadline, or once the carrier was
    /// shut down, the future is dropped and the call fails with
    /// `TimedOut`. For the host's futures of a handshake (a Gate, a
    /// verifier), which do not read the carrier.
    ///
    /// # Errors
    ///
    /// `TimedOut` past the deadline or after the shutdown.
    pub fn block_on<F: Future>(&self, fut: F) -> io::Result<F::Output> {
        let mut fut = pin!(fut);
        let waker = thread_waker();
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
                return Ok(r);
            }
            let (shut, deadline) = *self
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if shut || deadline.is_some_and(|d| Instant::now() >= d) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            // Woken by the future, or checked again at the deadline; a
            // shutdown is seen within the poll interval.
            let end = Instant::now() + SHUT_POLL;
            park(Some(deadline.map_or(end, |d| d.min(end))));
        }
    }

    fn limit(&self, timeout: Duration) {
        let mut st = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.1 = Instant::now().checked_add(timeout);
        self.0.changed.notify_all();
    }
}

/// A carrier for a blocking session: a readable half, a writable half, or
/// both.
pub struct PipeIo {
    wait: HandshakeWait,
    reader: Option<Box<dyn Read + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    closer: Option<Closer>,
    framing: Framing,
    abort: Option<Box<dyn FnOnce() + Send>>,
    exporter: Option<crate::proto::exporter::CarrierExporter>,
    variant: Option<Arc<str>>,
    protocol: Option<String>,
    carrier: Option<crate::CarrierKind>,
    /// The TCP socket under the carrier: its minimum RTT, unsent bytes and
    /// low-water mark ([`Probe`]).
    socket: Option<TcpSocket>,
    /// The carrier's unsent count ([`PipeIo::with_unsent`]).
    unsent: Option<Unsent>,
    /// The carrier's retransmission count ([`PipeIo::with_retransmitted`]).
    retransmitted: Option<Unsent>,
    /// The padding of a handshake run on the carrier before this pipe
    /// ([`PipeIo::with_handshake_padding`]).
    handshake_padding: u64,
    /// The carrier's write overhead ([`PipeIo::with_write_overhead`]).
    write_overhead: u16,
    /// The carrier has a low-water mark.
    low_water: bool,
    /// The secure carrier's Bound contract holds.
    secure: bool,
    /// Two halves paired as one carrier.
    split: bool,
    /// The largest record the carrier takes.
    max_record: Option<usize>,
    /// The record mode of an Establish this carrier ran.
    first_mode: Option<crate::proto::seal::RecordMode>,
    /// The value of the peer a transform authenticated.
    admitted: Option<crate::AdmittedValue>,
}

impl PipeIo {
    /// One carrier of two one-way ones, the local endpoint's uplink and downlink.
    #[must_use]
    pub fn paired_join(mut uplink: PipeIo, mut downlink: PipeIo) -> PipeIo {
        uplink.reader = downlink.reader.take();
        uplink.split = true;
        uplink.secure &= downlink.secure;
        // Both halves end with the attachment.
        uplink.closer = match (uplink.closer.take(), downlink.closer.take()) {
            (Some(a), Some(b)) => Some(Box::new(move |how| {
                a(how);
                b(how);
            })),
            (a, b) => a.or(b),
        };
        uplink.abort = match (uplink.abort.take(), downlink.abort.take()) {
            (Some(a), Some(b)) => Some(Box::new(move || {
                a();
                b();
            })),
            (a, b) => a.or(b),
        };
        uplink
    }

    /// Declares that the carrier meets the secure carrier's Bound contract: confidentiality and
    /// integrity of its records.
    #[must_use]
    pub fn with_carrier_secure(mut self) -> Self {
        self.secure = true;
        self
    }

    /// The carrier ran an Establish with this record mode: a session's first pipe is then
    /// on the secure carrier, its exporter being the handshake's.
    #[must_use]
    pub fn with_secure_first_pipe(mut self, mode: crate::proto::seal::RecordMode) -> Self {
        self.first_mode = Some(mode);
        self
    }

    /// The framing of the carrier's handshake units.
    #[must_use]
    pub fn handshake_framing(&self) -> Framing {
        self.framing
    }

    /// Reads once from the carrier for a transform's handshake, appending to `into`: one
    /// message on a message carrier; 0 is its end.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::UnexpectedEof`] for a carrier without a readable
    /// half, or the read's error.
    pub fn read_handshake(&mut self, into: &mut Vec<u8>) -> io::Result<usize> {
        let r = self
            .reader
            .as_mut()
            .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let at = into.len();
        into.resize(at + super::HANDSHAKE_READ, 0);
        let got = r.read(&mut into[at..]);
        into.truncate(at + *got.as_ref().unwrap_or(&0));
        got
    }

    /// Writes one handshake unit in one write.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::BrokenPipe`] for a carrier without a writable half,
    /// or the write's or flush's error.
    pub fn write_handshake(&mut self, unit: &[u8]) -> io::Result<()> {
        let w = self
            .writer
            .as_mut()
            .ok_or(io::Error::from(io::ErrorKind::BrokenPipe))?;
        w.write_all(unit)?;
        w.flush()
    }

    /// The Binding of an Establish on this carrier, when it declares the Bound
    /// contract. The std driver has an exporter of one connection only: a paired
    /// carrier has no Binding.
    #[must_use]
    pub fn bound_exporter(&self) -> Option<Vec<u8>> {
        if !self.secure || self.split {
            return None;
        }
        self.exporter.as_ref()?.seal_binding(false)
    }

    /// Bytes already read from the carrier: they are read first. On a message carrier they
    /// are one message.
    #[must_use]
    pub fn with_prefix(mut self, prefix: Vec<u8>) -> Self {
        if !prefix.is_empty()
            && let Some(r) = self.reader.take()
        {
            self.reader = Some(Box::new(Read::chain(io::Cursor::new(prefix), r)));
        }
        self
    }

    /// This carrier as Sealed records, with the directions of a finished handshake: a
    /// message carrier without the exporter below.
    #[must_use]
    pub fn seal_records(
        mut self,
        sealer: crate::proto::seal::Sealer,
        opener: crate::proto::seal::Opener,
    ) -> Self {
        let framing = self.framing;
        self.reader = self.reader.take().map(|lower| {
            Box::new(SealedRead {
                lower,
                records: crate::proto::seal::SealedReader::new(framing, opener, Vec::new()),
            }) as Box<dyn Read + Send>
        });
        self.writer = self.writer.take().map(|lower| {
            Box::new(SealedWrite {
                lower,
                records: crate::proto::seal::SealedWriter::new(framing, sealer),
            }) as Box<dyn Write + Send>
        });
        let overhead = handle::sealed_overhead(framing);
        self.write_overhead = self.write_overhead.saturating_add(overhead);
        self.framing = Framing::Records;
        self.max_record = Some(handle::sealed_max_record(self.max_record, overhead));
        self.exporter = None;
        self
    }

    /// The host's value of the peer a transform authenticated: the session's admitted
    /// value.
    #[must_use]
    pub fn with_admitted(mut self, value: crate::AdmittedValue) -> Self {
        self.admitted = Some(value);
        self
    }

    /// Bounds this carrier's reads and writes: past `timeout` the carrier is shut down.
    /// `None` for a carrier without a closer ([`PipeIo::with_closer`]), which nothing can
    /// interrupt. Dropping the result disarms it.
    ///
    /// # Errors
    ///
    /// The error of starting the watchdog's thread: the bound would not hold.
    pub fn watchdog(&mut self, timeout: Duration) -> io::Result<Option<Watchdog>> {
        self.shared_closer()
            .map(|c| Watchdog::new(c, timeout))
            .transpose()
    }

    /// What a handshake's waits on this carrier end with.
    #[must_use]
    pub fn handshake_wait(&self) -> HandshakeWait {
        self.wait.clone()
    }

    /// Bounds the handshake's waits on this carrier to `timeout` from now, also without a
    /// closer.
    pub fn limit_handshake_wait(&mut self, timeout: Duration) {
        self.wait.limit(timeout);
    }

    pub(crate) fn has_reader(&self) -> bool {
        self.reader.is_some()
    }

    pub(crate) fn has_writer(&self) -> bool {
        self.writer.is_some()
    }

    pub(crate) fn is_secure(&self) -> bool {
        self.secure
    }

    pub(crate) fn is_split(&self) -> bool {
        self.split
    }

    pub(crate) fn exporter_ref(&self) -> Option<&crate::proto::exporter::CarrierExporter> {
        self.exporter.as_ref()
    }

    pub(crate) fn admitted_value(&self) -> Option<&crate::AdmittedValue> {
        self.admitted.as_ref()
    }

    pub(crate) fn overhead(&self) -> u16 {
        self.write_overhead
    }

    /// The carrier's write overhead ([`PipeIo::with_write_overhead`]).
    #[must_use]
    pub fn write_overhead(&self) -> u16 {
        self.write_overhead
    }

    pub(crate) fn record_limit(&self) -> Option<usize> {
        self.max_record
    }

    /// Ends what the attachment's direction does not use.
    pub(crate) fn keep_directions(&mut self, inbound: bool, outbound: bool) {
        if !inbound {
            self.reader = None;
        }
        if !outbound {
            self.writer = None;
        }
    }

    /// Ends the writing half gracefully: what is written is flushed, then
    /// the half is shut down (a carrier without a closer drops it).
    pub(crate) fn shutdown_write(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
        }
        match &self.closer {
            Some(c) => c(Shutdown::Write),
            None => self.writer = None,
        }
    }

    /// The carrier's closer, shared with whoever must end its blocked calls.
    pub(crate) fn shared_closer(&mut self) -> Option<Arc<Closer>> {
        let inner = self.closer.take()?;
        let wait = self.wait.clone();
        let c: Arc<Closer> = Arc::new(Box::new(move |how| {
            wait.shut();
            inner(how);
        }));
        let kept = c.clone();
        self.closer = Some(Box::new(move |how| kept(how)));
        Some(c)
    }

    /// A TCP carrier: the write side ends with `shutdown(Write)`, and the
    /// socket is shut down when the session ends (which also ends a read or
    /// write blocked on a peer that went silent). The kernel's minimum RTT
    /// and unsent bytes are queried and `TCP_NOTSENT_LOWAT` follows the send
    /// rate as for `zmux::PipeIo::from_tcp`.
    pub fn from_tcp(stream: TcpStream) -> Self {
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
        Self {
            secure: false,
            split: false,
            max_record: None,
            first_mode: None,
            wait: HandshakeWait::default(),
            admitted: None,
            reader: Some(Box::new(SharedTcp(stream.clone()))),
            writer: Some(Box::new(SharedTcp(stream))),
            closer: Some(Box::new(move |how| shut_down(&control, how))),
            framing: Framing::ByteStream,
            abort: Some(Box::new(move || shut_down(&abort, Shutdown::Both))),
            exporter: None,
            variant: None,
            protocol: None,
            carrier: None,
            unsent: socket.as_ref().and_then(TcpSocket::unsent_query),
            retransmitted: socket.as_ref().and_then(TcpSocket::retransmitted_query),
            write_overhead: 0,
            handshake_padding: 0,
            socket,
            low_water,
        }
    }

    /// The closer of [`PipeIo::from_tcp`] for a carrier built over a TCP socket by hand
    /// (separate halves, a wrapper that frames or counts), for [`PipeIo::with_closer`]:
    /// [`Shutdown::Read`] and [`Shutdown::Write`] shut that side, [`Shutdown::Both`] shuts
    /// both sides one by one and, on Windows, cancels the I/O blocked in other threads, which
    /// a shutdown alone does not end. `socket` is the stream or a shared handle to it.
    pub fn tcp_closer<S>(socket: S) -> impl Fn(Shutdown) + Send + Sync + 'static
    where
        S: std::borrow::Borrow<TcpStream> + Send + Sync + 'static,
    {
        move |how| shut_down(socket.borrow(), how)
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
            variant: None,
            protocol: None,
            carrier: None,
            socket: None,
            unsent: None,
            retransmitted: None,
            write_overhead: 0,
            handshake_padding: 0,
            secure: false,
            split: false,
            max_record: None,
            first_mode: None,
            wait: HandshakeWait::default(),
            admitted: None,
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
    /// write call carries one.
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
    /// ([`PipeIo::from_tcp`]) have one.
    ///
    /// The closer must really end a blocked read, not only mark the socket: a bare
    /// `TcpStream::shutdown` does not wake a `recv` blocked in another thread on Windows,
    /// and the reader thread would then outlive the session. A closer over a TCP socket
    /// should be built with [`PipeIo::tcp_closer`].
    #[must_use]
    pub fn with_closer(mut self, closer: impl Fn(Shutdown) + Send + Sync + 'static) -> Self {
        self.closer = Some(Box::new(closer));
        self
    }

    /// The carrier's unsent count, an optional capability: `unsent`
    /// returns the bytes write calls handed to the carrier that it has
    /// not transmitted yet, `None` while it has no count. The writer
    /// thread calls it at most every 20 ms, outside the session lock; it
    /// must not block. It is the pipe's `queued_bytes` and, with the
    /// bytes of the write call in progress, its `Q_p`. [`PipeIo::from_tcp`]
    /// installs the socket's query where the platform has one (Linux,
    /// Android).
    #[must_use]
    pub fn with_unsent(mut self, unsent: impl Fn() -> Option<u64> + Send + Sync + 'static) -> Self {
        self.unsent = Some(Box::new(unsent));
        self
    }

    /// The carrier's retransmission count, an optional capability, as
    /// `zmux::PipeIo::with_retransmitted`: the writer thread calls it
    /// at most once a second, outside the session lock.
    /// [`PipeIo::from_tcp`] installs the socket's query where the platform has
    /// one.
    #[must_use]
    pub fn with_retransmitted(
        mut self,
        retransmitted: impl Fn() -> Option<u64> + Send + Sync + 'static,
    ) -> Self {
        self.retransmitted = Some(Box::new(retransmitted));
        self
    }

    /// With the padding bytes a handshake run on the carrier before this pipe added; the
    /// session meters them.
    #[must_use]
    pub fn with_handshake_padding(mut self, bytes: u64) -> Self {
        self.handshake_padding = bytes;
        self
    }

    /// The fixed number of bytes the layers below zmux add to each write
    /// call on the carrier (0 by default), passed unchanged to the shaper
    /// factory ([`crate::shaping::ShapedPipe::write_overhead`]).
    #[must_use]
    pub fn with_write_overhead(mut self, bytes: u16) -> Self {
        self.write_overhead = bytes;
        self
    }

    /// The largest record plaintext the carrier takes, applied beside the peer's
    /// `max_record_size` on every pipe this input becomes, a session's first included.
    /// 0 keeps the carrier's default; the smaller of `max` and a limit the carrier already
    /// has holds, and a Sealed transform above keeps it less its overhead.
    ///
    /// # Errors
    ///
    /// [`InvalidConfig`](crate::InvalidConfig) for a value below 8192 (the carrier record
    /// floor; there is no upper bound, the peer's `max_record_size` and the record limit of
    /// the implementation reduce it); it is never clamped. A pipe whose limit, less a Sealed
    /// transform's overhead, is below 8192 is refused when it is added or joined
    /// ([`PipeError::InvalidOptions`](PipeError::InvalidOptions); a listener's join
    /// is refused).
    pub fn with_max_record(mut self, max: usize) -> Result<Self, crate::InvalidConfig> {
        self.max_record = handle::checked_max_record(self.max_record, max)?;
        Ok(self)
    }

    /// Declares that the carrier bounds what it holds unsent itself, as a
    /// socket with a low-water mark does: a write blocks while it holds
    /// more than a small amount, so that its buffer never becomes a deep
    /// queue. Such a carrier is not paced by the carrier queue limiter; one
    /// that declares nothing is, in
    /// multipath sessions. TCP carriers
    /// ([`PipeIo::from_tcp`]) declare it themselves where the platform has
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

    /// The exporter of the innermost end-to-end handshake of the carrier (RFC
    /// 5705, RFC 8446 Section 7.5): the one source of
    /// [`crate::PipeAuth::exporter`], of the Binding of Bound joins and of
    /// `Session::export_keying_material`. `export` fills its buffer for a label
    /// and a context, returning `false` while the handshake is incomplete: it is
    /// read when a value is needed, for the session secret when the carrier's
    /// first bytes arrive (they carry the peer's parameters), never earlier, from
    /// any thread and never under the session's lock. A carrier without such a
    /// handshake (plain TCP, TLS that an intermediary terminates) has none; a
    /// transform with its own handshake gives its own, not the one below it.
    /// Never give an early exporter.
    #[must_use]
    pub fn with_exporter(
        mut self,
        export: impl Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.exporter = Some(crate::proto::exporter::CarrierExporter::new(export));
        self
    }

    /// [`Self::with_exporter`] whose values come later (from another
    /// thread, a language binding): as the tokio driver's
    /// `PipeIo::with_exporter_async`; the thread that takes the carrier
    /// waits for the values zmux reads, bounded by its handshake (or join)
    /// deadline.
    #[must_use]
    pub fn with_exporter_async<F>(
        mut self,
        export: impl Fn(crate::ExportRequest) -> F + Send + Sync + 'static,
    ) -> Self
    where
        F: Future<Output = io::Result<Vec<u8>>> + Send + 'static,
    {
        self.exporter = Some(crate::proto::exporter::CarrierExporter::new_async(export));
        self
    }

    /// Fetches the values of an exporter whose values come later until
    /// `deadline`, parking the thread; nothing to do for others.
    pub(crate) fn resolve_exporter(&self, deadline: Option<Instant>) {
        if let Some(e) = self.exporter.as_ref().filter(|e| !e.is_resolved()) {
            let _ = run(e.resolve(), deadline);
        }
    }

    /// The application protocol the carrier negotiated (for example the
    /// ALPN identifier), reported by `Session::protocol`.
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// The host's short label of the transform the carrier runs (the
    #[cfg_attr(
        feature = "tokio",
        doc = " label a [`crate::Candidate`] or an admission gives; about 32 bytes at"
    )]
    #[cfg_attr(
        not(feature = "tokio"),
        doc = " label a `Candidate` or an admission gives; about 32 bytes at"
    )]
    /// most). zmux only reports it: in pipe statistics and events, to the
    #[cfg_attr(
        feature = "tokio",
        doc = " shaper factory and in the [`crate::CarrierCache`] keys."
    )]
    #[cfg_attr(
        not(feature = "tokio"),
        doc = " shaper factory and in the `CarrierCache` keys."
    )]
    #[must_use]
    pub fn with_variant(mut self, variant: impl Into<Arc<str>>) -> Self {
        self.variant = Some(variant.into());
        self
    }

    /// The carrier's variant ([`PipeIo::with_variant`]).
    #[must_use]
    pub fn variant(&self) -> Option<&Arc<str>> {
        self.variant.as_ref()
    }

    /// The carrier's kind: the [`ShapedPipe::carrier`] a shaper factory
    /// sees for its pipe, and the kind in pipe events and statistics. The
    /// adapters set it; a carrier without one (raw TCP or TLS) has none.
    ///
    /// [`ShapedPipe::carrier`]: crate::shaping::ShapedPipe::carrier
    #[must_use]
    pub fn with_carrier(mut self, kind: crate::CarrierKind) -> Self {
        self.carrier = Some(kind);
        self
    }

    /// The carrier's kind ([`PipeIo::with_carrier`]).
    #[must_use]
    pub fn carrier(&self) -> Option<crate::CarrierKind> {
        self.carrier
    }
}

impl std::fmt::Debug for PipeIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeIo")
            .field("reader", &self.reader.is_some())
            .field("writer", &self.writer.is_some())
            .finish_non_exhaustive()
    }
}

// ---- the driver -------------------------------------------------------------------------
//
// Concurrency (see `super::wake`): one core lock per session. Threads wait
// by parking: a waiting thread registers its waker under the lock, and
// wake-ups and carrier shutdowns decided under the lock are carried out
// after it was released. A timer thread of the process runs each session's timers,
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
    timer: Option<(Waker, Option<Instant>)>,
    /// The listener's account the session reports its charge to.
    pub(crate) account: Option<Box<super::account::AccountLink<Shared<Blocking>>>>,
}

impl Io {
    /// `threads` more threads of pipe `id` use `closer`: one entry per pipe,
    /// its count the threads alive (a join thread's carrier is the closer of
    /// the pipe threads it starts).
    fn add_threads(&mut self, id: u64, closer: &Arc<Closer>, threads: usize) {
        match self.closers.iter_mut().find(|p| p.id == id) {
            Some(p) => {
                p.threads += threads;
                p.closer = closer.clone();
            }
            None => self.closers.push(PipeThreads {
                id,
                closer: closer.clone(),
                threads,
            }),
        }
    }
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
///     Ok(zmux::blocking::PipeIo::from_tcp(std::net::TcpStream::connect("127.0.0.1:4433")?))
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
    ///
    /// # Errors
    ///
    /// The dial function's error.
    pub fn dial(&self, req: super::DialRequest) -> io::Result<PipeIo> {
        self.0.as_ref()(req)
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

    /// The writer threads have ended: the last of what goes out on the
    /// carriers is written or given up (each ends at most
    /// [`engine::FINAL_WRITE`] after CLOSED). A reader thread may stay in a
    /// read of a carrier without a socket to shut down until the carrier
    /// ends; it delivers nothing more.
    fn released(state: &State<Self>) -> bool {
        state.io.writers_alive == 0
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
            // Also kept: pipe 0's reader reads it (`spawn_pipe`).
            exporter: carrier.exporter.clone(),
            protocol: carrier.protocol.take(),
            // The std driver's carriers say nothing of a TLS handshake.
            tls: None,
            kind: carrier.carrier,
            variant: carrier.variant.take(),
            write_overhead: carrier.write_overhead,
            max_record: carrier.max_record,
            handshake_padding: carrier.handshake_padding,
            secure: carrier.secure,
            split: carrier.split,
            first_mode: carrier.first_mode,
            admitted: carrier.admitted.take(),
        }
    }

    fn attach(shared: &Arc<Shared<Self>>, id: u64, mut carrier: PipeIo) -> Result<(), PipeError> {
        if let Some(s) = &carrier.socket {
            s.set_notsent_lowat(super::NOTSENT_LOWAT_MULTIPATH);
        }
        // The handshake's read ends when the attachment fails: the closer is the session's
        // from now on.
        let closer: Option<Arc<Closer>> = carrier.closer.take().map(Arc::new);
        if let Some(c) = &closer {
            shared.lock().io.add_threads(id, c, 1);
            let c = c.clone();
            carrier.closer = Some(Box::new(move |how| c(how)));
        }
        let s = shared.clone();
        thread::Builder::new()
            .name("zmux-join".into())
            .spawn(move || join_thread(&s, PipeId(id), carrier, closer.is_some()))
            .map(drop)
            .map_err(|e| PipeError::Io(Arc::new(e)))
    }

    fn start_rejoin(session: handle::WeakSession<Self>, dial: Dial) -> bool {
        thread::Builder::new()
            .name("zmux-rejoin".into())
            .spawn(move || {
                if let Ok(pipe) = dial.dial(super::DialRequest::bidi())
                    && let Some(session) = session.upgrade()
                {
                    // Started only: waiting would keep the session in use,
                    // and a rejoin must not wait for a PIPE_ACK that only
                    // the direction it restores could carry. The core
                    // times the join out.
                    let _ = session.begin_add_pipe(pipe, PipeOptions::default());
                }
            })
            .is_ok()
    }

    #[cfg(feature = "test-hooks")]
    fn io_tables(io: &Io) -> (usize, usize, usize, usize) {
        (io.writers.len(), io.closing.len(), 0, 0)
    }
}

/// The redial hook of a blocking session ([`Config::redial`]): one member,
/// replaced when it fails, and make before break when its
/// [`replace_by`](crate::PipeStats::replace_by) passes, on a thread that holds no handle of the session between its
/// looks and ends with it. The tokio driver's pool of one member does the same.
struct Redialer {
    session: handle::WeakSession<Blocking>,
    dial: Dial,
    backoff: crate::Backoff,
    /// The pipe in use, while it serves; a failed one is dropped.
    member: Option<Pipe>,
    /// The member being replaced: closed once its successor serves.
    retiring: Option<Pipe>,
    was_usable: bool,
    /// Consecutive failed redials, reset once a member serves.
    failures: u32,
    /// The wait after the start of the last dial (or of the thread), drawn once.
    wait: Duration,
    since: Instant,
    _source: handle::RedialSource<Blocking>,
}

impl Redialer {
    fn spawn(session: &Session, dial: Dial, backoff: crate::Backoff, pipe0: Pipe) {
        let r = Self {
            session: session.downgrade(),
            dial,
            backoff,
            member: Some(pipe0),
            retiring: None,
            was_usable: true,
            failures: 0,
            wait: Duration::ZERO,
            since: Instant::now(),
            _source: handle::RedialSource::new(session.shared()),
        };
        // Without a thread the session has no redial source: the suspension says so.
        let _ = thread::Builder::new()
            .name("zmux-redial".into())
            .spawn(move || r.run());
    }

    fn set_failures(&mut self, failures: u32) {
        if failures != self.failures {
            self.failures = failures;
            self.wait = self.backoff.delay(failures.max(1));
        }
    }

    fn run(mut self) {
        loop {
            let Some(session) = self.session.upgrade() else {
                return;
            };
            if session.close_reason().is_some() || !session.is_multipath() {
                return;
            }
            let seen = session.pipe_changes();
            self.observe();
            let now = Instant::now();
            let due = self.since.checked_add(self.wait);
            if self.member.is_none()
                && session.adapter().join_ready()
                && due.is_some_and(|t| now >= t)
            {
                self.since = now;
                // A wait counts from this start, whatever comes of it.
                self.wait = self.backoff.delay(self.failures.max(1));
                // The dial holds no handle: dropping the last one closes the session.
                drop(session);
                if !self.redial() {
                    return;
                }
                continue;
            }
            let mut next = now + crate::helpers::POLL;
            if self.member.is_none()
                && let Some(t) = due
            {
                next = next.min(t.max(now));
            }
            let shared = session.shared().clone();
            drop(session);
            run(handle::pipes_changed_wait(&shared, seen), Some(next));
        }
    }

    /// Looks at the member: dropped once it no longer serves, and replaced once the
    /// epoch policy wants its carrier replaced.
    fn observe(&mut self) {
        if self
            .retiring
            .as_ref()
            .is_some_and(|p| handle::dead(p.stats().as_ref()))
        {
            self.retiring = None;
        }
        let Some(p) = &self.member else {
            return;
        };
        let info = p.stats();
        if handle::dead(info.as_ref()) {
            let _ = p.close();
            self.member = None;
            if !self.was_usable {
                self.set_failures(self.failures.saturating_add(1));
            }
        } else if let Some(i) = info.filter(|i| handle::usable(p, i)) {
            self.was_usable = true;
            self.set_failures(0);
            if let Some(old) = self.retiring.take() {
                let _ = old.close();
            } else if i.replace_by.is_some_and(|t| Instant::now() >= t) {
                // The successor is dialled at once; the member serves until it does.
                self.retiring = self.member.take();
                self.since = Instant::now();
                self.wait = Duration::ZERO;
            }
        }
    }

    /// Dials a replacement and starts its join; `false` when the session takes no more.
    fn redial(&mut self) -> bool {
        let added = match self.dial.dial(super::DialRequest::bidi()) {
            Ok(io) => {
                let Some(session) = self.session.upgrade() else {
                    return false;
                };
                // A redial must not wait for a PIPE_ACK that only the direction it
                // restores could carry.
                session.begin_add_pipe(io, PipeOptions::new().with_return_on_reply(true))
            }
            Err(e) => Err(PipeError::Io(Arc::new(e))),
        };
        match added {
            Ok(p) => {
                self.member = Some(p);
                self.was_usable = false;
                true
            }
            Err(PipeError::NotNegotiated | PipeError::SessionLost(_)) => false,
            Err(_) => {
                self.set_failures(self.failures.saturating_add(1));
                true
            }
        }
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
        if self.io.writers_alive == 0 {
            // `closed` may resolve now.
            self.waiters
                .wake_list(super::wait::List::Close, &mut self.wakes);
        }
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

/// A writer thread's carrier queries: the TCP socket's ([`Probe`]) and the
/// carrier's unsent count.
struct Queries {
    probe: Option<Probe>,
    unsent: Option<UnsentQuery>,
    retransmitted: Option<RetransmittedQuery>,
}

impl Queries {
    /// Without the lock: the queries that are due.
    fn query(&mut self, now: Instant) {
        if let Some(p) = &mut self.probe {
            p.query(now);
        }
        if let Some(q) = &mut self.unsent {
            q.query(now);
        }
        if let Some(q) = &mut self.retransmitted {
            q.query(now);
        }
    }

    /// Under the lock: their results go to the core.
    fn feed(&mut self, core: &mut crate::proto::session::SessionCore, id: PipeId, now: Instant) {
        if let Some(p) = &mut self.probe {
            p.feed(core, id);
        }
        if let Some(q) = &mut self.unsent {
            q.feed(core, id.into(), now);
        }
        if let Some(q) = &mut self.retransmitted {
            q.feed(core, id, now);
        }
    }
}

/// Runs the joiner's handshake, then the pipe's threads.
fn join_thread(shared: &Arc<Shared<Blocking>>, id: PipeId, mut pipe: PipeIo, closer: bool) {
    use super::accept::{DialStep, JoinDial};
    let _driver = DriverThread::enter();
    let done = |shared: &Arc<Shared<Blocking>>| {
        if closer {
            let mut st = shared.lock();
            st.thread_done(id);
            st.after_command();
        }
    };
    let framing = pipe.framing;
    let mut dial = JoinDial::new(
        shared.clone(),
        id,
        framing,
        pipe.carrier,
        pipe.write_overhead,
    );
    let (Some(mut r), Some(mut w)) = (pipe.reader.take(), pipe.writer.take()) else {
        dial.failed(io::ErrorKind::UnexpectedEof);
        return done(shared);
    };
    let mut input = Vec::new();
    let mut chunk = vec![0; super::HANDSHAKE_READ];
    let mut step = dial.start();
    let (consumed, records) = loop {
        step = match step {
            DialStep::Hold => {
                run(handle::join_released_wait(shared, id), None);
                dial.released()
            }
            DialStep::Delay(d) => dial.delayed(!join_wait(shared, id, d)),
            DialStep::Write(unit) => {
                let wrote = if unit.is_empty() {
                    Ok(())
                } else {
                    w.write_all(&unit).and_then(|()| w.flush())
                };
                dial.written(wrote)
            }
            DialStep::Read(want) => {
                while input.len() < want {
                    // Checked before it is appended.
                    let (got, n) = match r.read(&mut chunk) {
                        Ok(n) => (Ok(n), n),
                        Err(e) => (Err(e), 0),
                    };
                    if !dial.read(got, input.len() + n) {
                        return done(shared);
                    }
                    input.extend_from_slice(&chunk[..n]);
                }
                dial.input(&mut input)
            }
            DialStep::End => return done(shared),
            DialStep::Attach { consumed, records } => break (consumed, records),
        };
    };
    input.drain(..consumed);
    let Some((inbound, outbound)) = dial.limits(pipe.max_record, pipe.write_overhead) else {
        return done(shared);
    };
    let rest = io::Cursor::new(input);
    pipe.reader = Some(Box::new(Read::chain(rest, r)));
    pipe.writer = Some(w);
    if let Some((sealer, opener)) = records {
        pipe = pipe.seal_records(sealer, opener);
    }
    if !inbound {
        pipe.reader = None;
    }
    if !outbound {
        pipe.writer = None;
    }
    let gone = {
        let mut st = shared.lock();
        // The session or the attachment may have ended while the Confirm was
        // written.
        let gone = st.core.state() >= CoreState::Closing
            || matches!(st.core.pipe_joined(id), Some(Err(_)));
        if gone && closer {
            st.thread_done(id);
        }
        gone
    };
    if gone {
        // Nothing to fail: the join is over with its session or attachment.
        dial.attached();
        // No thread takes the carrier: it ends here, as the session's end
        // would have ended it.
        if let Some(c) = pipe.closer.take() {
            c(Shutdown::Both);
        }
        return;
    }
    let spawned = spawn_pipe(shared, id.0, pipe);
    if spawned.is_err() {
        dial.failed(io::ErrorKind::BrokenPipe);
    } else {
        dial.attached();
    }
    // The join's hold on the closer ends only once the pipe's threads hold
    // it: the session's end, whenever it comes, finds the closer.
    let mut st = shared.lock();
    if closer {
        st.thread_done(id);
    }
    st.after_command();
}

/// Waits out a plan's delay, holding no lock; `true` when the join failed meanwhile.
fn join_wait(shared: &Arc<Shared<Blocking>>, id: PipeId, delay: Duration) -> bool {
    if delay.is_zero() {
        return false;
    }
    let deadline = Instant::now().checked_add(delay);
    run(handle::join_failed_wait(shared, id), deadline).is_some()
}

/// Shuts a carrier down at a deadline, ending calls blocked on it. One thread until dropped.
#[derive(Debug)]
pub struct Watchdog {
    deadline: std::sync::mpsc::Sender<Instant>,
    /// 0 armed, 1 disarmed, 2 fired: decided under the lock, so that a
    /// watchdog disarmed never fires after.
    state: Arc<std::sync::Mutex<u8>>,
}

impl Watchdog {
    pub(crate) fn new(closer: Arc<Closer>, timeout: Duration) -> io::Result<Self> {
        use std::sync::mpsc::{RecvTimeoutError, channel};
        let (deadline, moves) = channel::<Instant>();
        let state = Arc::new(std::sync::Mutex::new(0u8));
        let flag = state.clone();
        let mut at = Instant::now().checked_add(timeout);
        thread::Builder::new()
            .name("zmux-watchdog".into())
            .spawn(move || {
                loop {
                    let next = match at {
                        Some(t) => moves.recv_timeout(t.saturating_duration_since(Instant::now())),
                        None => moves.recv().map_err(|_| RecvTimeoutError::Disconnected),
                    };
                    match next {
                        Ok(t) => at = Some(t),
                        Err(RecvTimeoutError::Disconnected) => return,
                        Err(RecvTimeoutError::Timeout) => {
                            let mut st = flag
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if *st == 0 {
                                *st = 2;
                                drop(st);
                                closer(Shutdown::Both);
                            }
                            return;
                        }
                    }
                }
            })?;
        Ok(Self { deadline, state })
    }

    /// Moves the deadline to `timeout` from now.
    pub fn reset(&self, timeout: Duration) {
        if let Some(t) = Instant::now().checked_add(timeout) {
            let _ = self.deadline.send(t);
        }
    }

    /// Ends the watch: once this returns, the carrier is never shut down by
    /// it (it fired before, or never will).
    pub fn disarm(&self) {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *st == 0 {
            *st = 1;
        }
    }

    /// Whether the deadline passed and the carrier was shut down.
    #[must_use]
    pub fn fired(&self) -> bool {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            == 2
    }
}

/// Byte-stream halves as Sealed records, for allocation tests.
///
/// # Panics
///
/// Never: both halves are given.
#[cfg(feature = "test-hooks")]
pub fn sealed_halves<R, W>(
    reader: R,
    writer: W,
    sealer: crate::proto::seal::Sealer,
    opener: crate::proto::seal::Opener,
) -> (Box<dyn Read + Send>, Box<dyn Write + Send>)
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let p = PipeIo::from_halves(reader, writer).seal_records(sealer, opener);
    (
        p.reader.expect("a reading half"),
        p.writer.expect("a writing half"),
    )
}

/// The reading half of a Sealed carrier: an I/O shell of
/// [`SealedReader`](crate::proto::seal::SealedReader).
struct SealedRead {
    lower: Box<dyn Read + Send>,
    records: crate::proto::seal::SealedReader,
}

fn sealed_failure(f: crate::proto::seal::SealedFailure) -> io::Error {
    match f {
        crate::proto::seal::SealedFailure::Invalid => io::ErrorKind::InvalidData.into(),
        crate::proto::seal::SealedFailure::Cut => io::ErrorKind::UnexpectedEof.into(),
    }
}

impl Read for SealedRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        use crate::proto::seal::SealedRead as R;
        loop {
            match self.records.read(out).map_err(sealed_failure)? {
                // The end at a record's boundary reads as the carrier's end (see the
                // tokio reader).
                R::End => return Ok(0),
                R::Data(n) => return Ok(n),
                R::More => {
                    let n = self.lower.read(self.records.space())?;
                    self.records.filled(n);
                }
            }
        }
    }
}

/// The writing half of a Sealed carrier: each write is one record, written
/// whole before the call returns (one write below on a message carrier).
struct SealedWrite {
    lower: Box<dyn Write + Send>,
    records: crate::proto::seal::SealedWriter,
}

impl Write for SealedWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            // Nothing to write is no record.
            return Ok(0);
        }
        self.records.seal(buf).map_err(io::Error::other)?;
        while !self.records.pending().is_empty() {
            match self.lower.write(self.records.pending()) {
                Ok(n) => self
                    .records
                    .wrote(n)
                    .map_err(|_| io::Error::from(io::ErrorKind::WriteZero))?,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    // A record cut or lost, no record may follow it.
                    self.records.failed();
                    return Err(e);
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.lower.flush()
    }
}

/// Starts the threads of a pipe's halves. Added pipes (`id` > 0) belong to
/// a multipath session.
pub(crate) fn spawn_pipe(shared: &Arc<Shared<Blocking>>, id: u64, pipe: PipeIo) -> io::Result<()> {
    let PipeIo {
        exporter,
        reader,
        writer,
        closer,
        framing,
        abort,
        socket,
        unsent,
        retransmitted,
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
    let queries = Queries {
        probe: socket.map(|s| Probe::new(s, lowat, Instant::now())),
        unsent: unsent.map(|q| UnsentQuery::new(q, Instant::now())),
        retransmitted: retransmitted.map(|q| RetransmittedQuery::new(q, Instant::now())),
    };
    let closer: Option<Arc<Closer>> = closer.map(Arc::new);
    if let Some(c) = &closer {
        let threads = usize::from(reader.is_some()) + usize::from(writer.is_some());
        shared.lock().io.add_threads(id, c, threads);
    }
    if let Some(r) = reader {
        let s = shared.clone();
        let late_exporter = exporter.filter(|_| id == 0);
        let spawned = thread::Builder::new()
            .name("zmux-read".into())
            .spawn(move || reader_thread(&s, PipeId(id), r, framing, late_exporter));
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
            .spawn(move || writer_thread(&s, PipeId(id), w, c, abort, framing, queries));
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
pub(crate) fn run<F: Future>(fut: F, deadline: Option<Instant>) -> Option<F::Output> {
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

/// The message of [`WaitError::OnDriverThread`].
const ON_DRIVER_THREAD: &str = "blocking call on a thread that drives sessions";

/// Why a blocking call of the std driver failed: the operation's own
/// error ([`WaitError::Failed`], the error the tokio driver's future
/// returns), the call's timeout, or its refusal on a thread that drives
/// sessions. The tokio driver has no such wrapper: a future is bounded by
/// its caller and never blocks a thread.
///
/// `E` is [`SessionError`] for the session-wide waits (`accept_bi`,
/// `read_datagram`, `ping`, `shutdown`, `established`, `closing`,
/// `closed`, `next_event`), the operation's error type for the others.
/// It converts into an [`io::Error`]: `Failed` as `E` does,
/// [`TimedOut`](WaitError::TimedOut) as [`io::ErrorKind::TimedOut`] and
/// [`OnDriverThread`](WaitError::OnDriverThread) as
/// [`io::ErrorKind::Deadlock`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitError<E = SessionError> {
    /// The operation failed.
    Failed(E),
    /// The call's timeout expired (an `x_timeout` call, or a stream's read
    /// or write timeout); the object stays usable.
    TimedOut,
    /// The call was refused on a thread that drives sessions (inside a
    /// tokio runtime, or on a session's own threads); nothing changed.
    OnDriverThread,
}

impl<E> WaitError<E> {
    /// The operation's error, if it failed (not on a timeout or refusal).
    pub fn failed(&self) -> Option<&E> {
        match self {
            Self::Failed(e) => Some(e),
            _ => None,
        }
    }

    /// Whether the call's timeout expired.
    pub fn is_timed_out(&self) -> bool {
        matches!(self, Self::TimedOut)
    }

    /// The same outcome with the operation's error mapped by `f`.
    pub fn map<F>(self, f: impl FnOnce(E) -> F) -> WaitError<F> {
        match self {
            Self::Failed(e) => WaitError::Failed(f(e)),
            Self::TimedOut => WaitError::TimedOut,
            Self::OnDriverThread => WaitError::OnDriverThread,
        }
    }
}

impl<E: std::fmt::Display> std::fmt::Display for WaitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(e) => e.fmt(f),
            Self::TimedOut => f.write_str("wait timed out"),
            Self::OnDriverThread => f.write_str(ON_DRIVER_THREAD),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for WaitError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(e) => Some(e),
            Self::TimedOut | Self::OnDriverThread => None,
        }
    }
}

impl<E> From<E> for WaitError<E> {
    fn from(e: E) -> Self {
        Self::Failed(e)
    }
}

impl<E> From<WaitError<E>> for io::Error
where
    E: Into<io::Error> + std::error::Error + Send + Sync + 'static,
{
    fn from(e: WaitError<E>) -> Self {
        match e {
            WaitError::Failed(e) => e.into(),
            WaitError::TimedOut => io::Error::new(io::ErrorKind::TimedOut, e),
            WaitError::OnDriverThread => io::Error::new(io::ErrorKind::Deadlock, e),
        }
    }
}

/// An application call that may wait, without a timeout: refused at once
/// on a thread that drives sessions.
fn call<T, E>(fut: impl Future<Output = Result<T, E>>) -> Result<T, WaitError<E>> {
    call_timeout(None, fut)
}

/// A call that may wait up to `timeout` (`None`: forever). A zero timeout
/// never blocks and works on any thread.
fn call_timeout<T, E>(
    timeout: Option<Duration>,
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T, WaitError<E>> {
    if timeout != Some(Duration::ZERO) && on_driver_thread() {
        return Err(WaitError::OnDriverThread);
    }
    match run(fut, timeout.and_then(|t| Instant::now().checked_add(t))) {
        Some(r) => r.map_err(WaitError::Failed),
        None => Err(WaitError::TimedOut),
    }
}

/// A session-wide wait (its result is not an error of its own).
fn wait_for<T>(
    timeout: Option<Duration>,
    fut: impl Future<Output = T>,
) -> Result<T, WaitError<SessionError>> {
    call_timeout(timeout, async { Ok(fut.await) })
}

fn reader_thread(
    shared: &Arc<Shared<Blocking>>,
    id: PipeId,
    mut reader: Box<dyn Read + Send>,
    framing: Framing,
    mut late_exporter: Option<crate::proto::exporter::CarrierExporter>,
) {
    let _driver = DriverThread::enter();
    let mut buf = Some(super::read_pool::take_initialized());
    let mut filled = 0;
    loop {
        let started = Instant::now();
        let result = if let Some(b) = &mut buf {
            reader.read(&mut b[filled..])
        } else {
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
        };
        // Pipe 0's exporter, with its first bytes: without the lock (it is
        // the host's code), for the core to have before the peer's
        // parameters.
        let exporter_value = match &result {
            Ok(1..) => late_exporter.take().and_then(|e| e.session_value()),
            _ => None,
        };
        let mut st = shared.lock();
        let now = Instant::now();
        if let Some(v) = exporter_value {
            st.core.set_bootstrap_exporter_value(v);
        }
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
    shared: &Arc<Shared<Blocking>>,
    id: PipeId,
    mut writer: Box<dyn Write + Send>,
    closer: Option<Arc<Closer>>,
    mut abort: Option<Box<dyn FnOnce() + Send>>,
    framing: Framing,
    mut queries: Queries,
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
        queries.query(Instant::now());
        let mut st = shared.lock();
        queries.feed(&mut st.core, id, Instant::now());
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
                // The write call is in progress.
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
        if let Some(p) = &mut queries.probe {
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
        out.tell(&mut st.core, id, now);
        let _ = progress.report(&mut st.core, id, false, now);
        if let Err(e) = &result {
            st.core.write_failed(id, e.kind(), Instant::now());
            st.after_command();
            break;
        }
        st.after_command();
        drop(st);
        if shutdown {
            if let Some(c) = &closer {
                c(Shutdown::Write);
            }
            // The write side is shut: the batch's last byte counts now, and with it a
            // close is handed off.
            out.shutdown_done();
            let mut st = shared.lock();
            out.tell(&mut st.core, id, Instant::now());
            st.after_command();
            break;
        }
    }
    // The pipe is done: end the carrier half so its reader thread returns
    // once the session ended.
    drop(writer);
    let session_closed = {
        let mut st = shared.lock();
        st.io.writers_alive -= 1;
        st.thread_done(id);
        st.wake_timer();
        st.core.state() == CoreState::Closed
    };
    if session_closed && let Some(c) = closer {
        c(Shutdown::Both);
    }
}

/// The session's timer task (see [`session_timer`]): runs the core's
/// timers until the session is closed; then, after the last batches had
/// [`FINAL_WRITE`] to be written, ends every carrier with a closer, so that
/// no thread stays blocked in a read or write of a peer that went silent.
/// Starts the session's hook thread when the core needs it.
fn timer_task(shared: Arc<Shared<Blocking>>) -> impl FnMut(&Waker) -> Next + Send + 'static {
    // The end of the wait for the writers, once the session is closed.
    let mut draining: Option<Instant> = None;
    move |me| {
        let deadline = match draining {
            Some(d) => d,
            None => match fire_timers(&shared, me) {
                Some(next) => return next,
                None => *draining.insert(Instant::now() + engine::FINAL_WRITE),
            },
        };
        let mut st = shared.lock();
        if st.io.writers_alive == 0 || Instant::now() >= deadline {
            st.io.timer = None;
            st.shut_down_all();
            return Next::Done;
        }
        st.io.timer = Some((me.clone(), Some(deadline)));
        Next::At(deadline)
    }
}

/// One run of the timer task while the session lives: what it asks next, or
/// `None` once the session is closed.
fn fire_timers(shared: &Arc<Shared<Blocking>>, me: &Waker) -> Option<Next> {
    loop {
        let mut st = shared.lock();
        let now = Instant::now();
        if engine::fire_timers(&mut st.core, now) {
            st.after_command();
        }
        // The listener's account: the charge, allowance, pressure and
        // suspended limit (`super::account`); suspended sessions it asks to
        // close are closed after the lock.
        let mut closing = Vec::new();
        {
            let s = &mut *st;
            if let Some(link) = s.io.account.as_mut() {
                link.report(&mut s.core, shared, now, &mut closing);
            }
        }
        if !closing.is_empty() {
            drop(st);
            for s in closing {
                s.close_suspended();
            }
            continue;
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
        // ended before the first round.
        if st.core.state() == CoreState::Closed {
            // Its charge leaves the listener's account.
            st.io.account = None;
            return None;
        }
        let mut until = engine::timer_deadline(st.core.poll_timeout(), now);
        // A charge report the interval held back.
        if let Some(t) = st.io.account.as_ref().and_then(|l| l.due()) {
            until = Some(until.map_or(t, |d| d.min(t)));
        }
        st.io.timer = Some((me.clone(), until));
        return Some(until.map_or(Next::Idle, Next::At));
    }
}

// ---- the application's calls ------------------------------------------------------------

impl Session {
    /// Establishes a session as the dialling side of `pipe`.
    pub fn connect(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
    ) -> Result<Session, WaitError<ConnectError>> {
        Self::start(pipe, config, Role::Client, Some(Role::Client), None, |_| {})
            .map(Self::redialing)
    }

    /// Establishes a session as the accepting side of `pipe`. Such a
    /// session cannot accept joins: a configuration that offers multipath
    /// is refused ([`ConnectError::InvalidConfig`]).
    pub fn accept(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
    ) -> Result<Session, WaitError<ConnectError>> {
        let config = config.into();
        if config.offers_multipath() {
            return Err(WaitError::Failed(ConnectError::InvalidConfig(
                crate::InvalidConfig::new(
                    "max_pipes",
                    "a session accepted without a listener cannot accept joins: multipath needs a Listener",
                ),
            )));
        }
        Self::start(pipe, config, Role::Server, Some(Role::Server), None, |_| {})
    }

    /// Establishes a session over a symmetric carrier (`zmux_role` auto).
    pub fn peer(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
    ) -> Result<Session, WaitError<ConnectError>> {
        let config = config.into();
        super::check_peer(&config)?;
        Self::start(pipe, config, Role::Auto, None, None, |_| {}).map(Self::redialing)
    }

    /// Starts the redial hook of a dialling session's configuration.
    fn redialing(self) -> Self {
        let config = self.shared().lock().core.config().clone();
        if let Some(dial) = config.redial.as_ref().and_then(crate::Redial::as_blocking)
            && self.multipath() == crate::Multipath::InUse
            && let Some(pipe0) = self.pipe(PipeId(0))
        {
            Redialer::spawn(&self, dial.clone(), config.redial_backoff, pipe0);
        }
        self
    }

    /// A session a listener accepts: `register` publishes it before its first byte.
    pub(crate) fn listened(
        pipe: PipeIo,
        config: Arc<Config>,
        locator: Option<&[u8]>,
        register: impl FnOnce(&Arc<Shared<Blocking>>),
    ) -> Result<Session, WaitError<ConnectError>> {
        Self::start(
            pipe,
            config,
            Role::Server,
            Some(Role::Server),
            locator,
            register,
        )
    }

    fn start(
        mut pipe: PipeIo,
        config: impl Into<Arc<Config>>,
        role: Role,
        transport: Option<Role>,
        locator: Option<&[u8]>,
        register: impl FnOnce(&Arc<Shared<Blocking>>),
    ) -> Result<Session, WaitError<ConnectError>> {
        // Before anything is spawned: nothing to release.
        if on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        let config = config.into();
        pipe.resolve_exporter(Instant::now().checked_add(config.handshake_wait()));
        let carrier = Blocking::carrier_info(&mut pipe);
        let io = Io {
            closing: Vec::new(),
            wake_writers: false,
            closers: Vec::new(),
            writers: WaitList::default(),
            writers_alive: 0,
            timer: None,
            account: None,
        };
        let shared = Arc::new(Shared::new(
            State::new(config, role, transport, locator, carrier, io)?,
            (),
        ));
        register(&shared);
        // The handle counted first: if a thread cannot be started, dropping
        // it closes the session, and the threads started end.
        let establish = shared.clone().established();
        session_timer::spawn(timer_task(shared.clone()))
            .map_err(|e| ConnectError::Io(Arc::new(e)))?;
        spawn_pipe(&shared, 0, pipe).map_err(|e| ConnectError::Io(Arc::new(e)))?;
        drop(shared);
        call(establish)
    }

    /// Opens a bidirectional stream, waiting for stream credit; waiting
    /// openers get credit first come, first served.
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream), WaitError<OpenError>> {
        call(self.open_bi_wait(None))
    }

    /// [`open_bi`](blocking::Session#method.open_bi), waiting at most
    /// `timeout` for credit ([`WaitError::TimedOut`]).
    pub fn open_bi_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(SendStream, RecvStream), WaitError<OpenError>> {
        call_timeout(Some(timeout), self.open_bi_wait(None))
    }

    /// Opens a bidirectional stream with `preamble`, waiting for stream
    /// credit (see `zmux::Session::open_bi_with`).
    pub fn open_bi_with(
        &self,
        preamble: &Preamble,
    ) -> Result<(SendStream, RecvStream), WaitError<OpenError>> {
        call(self.open_bi_wait(Some(preamble)))
    }

    /// [`open_bi_with`](blocking::Session#method.open_bi_with), waiting at
    /// most `timeout` for credit.
    pub fn open_bi_with_timeout(
        &self,
        preamble: &Preamble,
        timeout: Duration,
    ) -> Result<(SendStream, RecvStream), WaitError<OpenError>> {
        call_timeout(Some(timeout), self.open_bi_wait(Some(preamble)))
    }

    /// Opens a unidirectional stream, waiting for stream credit.
    pub fn open_uni(&self) -> Result<SendStream, WaitError<OpenError>> {
        call(self.open_uni_wait(None))
    }

    /// [`open_uni`](blocking::Session#method.open_uni), waiting at most
    /// `timeout` for credit.
    pub fn open_uni_timeout(&self, timeout: Duration) -> Result<SendStream, WaitError<OpenError>> {
        call_timeout(Some(timeout), self.open_uni_wait(None))
    }

    /// Opens a unidirectional stream with `preamble`, waiting for stream
    /// credit.
    pub fn open_uni_with(&self, preamble: &Preamble) -> Result<SendStream, WaitError<OpenError>> {
        call(self.open_uni_wait(Some(preamble)))
    }

    /// [`open_uni_with`](blocking::Session#method.open_uni_with), waiting
    /// at most `timeout` for credit.
    pub fn open_uni_with_timeout(
        &self,
        preamble: &Preamble,
        timeout: Duration,
    ) -> Result<SendStream, WaitError<OpenError>> {
        call_timeout(Some(timeout), self.open_uni_wait(Some(preamble)))
    }

    /// Accepts the next bidirectional stream the peer opened.
    pub fn accept_bi(&self) -> Result<(SendStream, RecvStream), WaitError> {
        call(self.accept_bi_wait())
    }

    /// [`accept_bi`](blocking::Session#method.accept_bi), waiting at most
    /// `timeout`.
    pub fn accept_bi_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(SendStream, RecvStream), WaitError> {
        call_timeout(Some(timeout), self.accept_bi_wait())
    }

    /// Accepts the next unidirectional stream the peer opened.
    pub fn accept_uni(&self) -> Result<RecvStream, WaitError> {
        call(self.accept_uni_wait())
    }

    /// [`accept_uni`](blocking::Session#method.accept_uni), waiting at most
    /// `timeout`.
    pub fn accept_uni_timeout(&self, timeout: Duration) -> Result<RecvStream, WaitError> {
        call_timeout(Some(timeout), self.accept_uni_wait())
    }

    /// Queues a session datagram, waiting while the queue is full.
    pub fn send_datagram_wait(&self, data: Bytes) -> Result<(), WaitError<DatagramError>> {
        call(self.send_datagram_wait_op(data))
    }

    /// [`send_datagram_wait`](blocking::Session#method.send_datagram_wait),
    /// waiting at most `timeout` for room.
    pub fn send_datagram_wait_timeout(
        &self,
        data: Bytes,
        timeout: Duration,
    ) -> Result<(), WaitError<DatagramError>> {
        call_timeout(Some(timeout), self.send_datagram_wait_op(data))
    }

    /// Receives the next session datagram.
    pub fn read_datagram(&self) -> Result<Bytes, WaitError> {
        call(self.read_datagram_op())
    }

    /// [`read_datagram`](blocking::Session#method.read_datagram), waiting
    /// at most `timeout`.
    pub fn read_datagram_timeout(&self, timeout: Duration) -> Result<Bytes, WaitError> {
        call_timeout(Some(timeout), self.read_datagram_op())
    }

    /// Closes the session gracefully with an application close of `code`
    /// and `reason` and blocks until `CONNECTION_CLOSE` has been handed to
    /// the carriers, flushing the streams' written data first, 1 s at the
    /// latest for the whole call (see `zmux::Session::close_with_error`);
    /// the half-close and the linger go on on the session's threads. The
    /// first close or abort decides the code and the reason. A process may
    /// exit once it returned. On a thread that drives sessions it starts
    /// the close without waiting.
    pub fn close_with_error(&self, code: VarInt, reason: &[u8]) {
        self.begin_close(code, reason);
        if !on_driver_thread() {
            run(self.close_handoff_op(), None);
        }
    }

    /// [`Session::close_with_error`](blocking::Session#method.close_with_error)
    /// with code 0 and an empty reason. Dropping the last handle starts the
    /// same close without waiting.
    pub fn close(&self) {
        self.close_with_error(VarInt::ZERO, b"");
    }

    /// Ends the session at once with an application close of `code` and
    /// `reason`, draining nothing (see `zmux::Session::abort`). Never
    /// blocks.
    pub fn abort(&self, code: VarInt, reason: &[u8]) {
        self.abort_op(code, reason);
    }

    /// Adds a pipe and blocks until the peer attached it, or, with
    /// [`PipeOptions::return_on_reply`], until the Reply has been
    /// verified; the join timeout bounds the call (see
    /// `zmux::Session::add_pipe`). A pipe not attached by then is aborted
    /// and the call fails with [`PipeFailure::JoinTimedOut`]; a failed call
    /// leaves no pipe behind. On a thread that drives sessions it fails at
    /// once with [`WaitError::OnDriverThread`], starting nothing;
    /// [`Session::begin_add_pipe`](blocking::Session#method.begin_add_pipe)
    /// starts a join without waiting.
    pub fn add_pipe(&self, pipe: PipeIo, opts: PipeOptions) -> Result<Pipe, WaitError<PipeError>> {
        if on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        let deadline = Instant::now() + self.add_pipe_limit();
        let no_wait = opts.return_on_reply;
        pipe.resolve_exporter(Some(deadline));
        let p = self.begin_add_pipe(pipe, opts)?;
        let guard = handle::AbortUnlessAdded(Some(&p));
        run(p.added_op(no_wait), Some(deadline)).unwrap_or(Err(JOIN_TIMED_OUT))?;
        guard.added();
        Ok(p)
    }

    /// [`replace_pipes_timeout`](blocking::Session#method.replace_pipes_timeout)
    /// without a bound.
    pub fn replace_pipes(&self) -> Result<(), WaitError<PipeError>> {
        self.replace_pipes_until(None)
    }

    /// Replaces every pipe after a suspected leak of a session-level secret, within
    /// `timeout`: advances the epoch as
    /// [`advance_epoch`](blocking::Session#method.advance_epoch) does, waits until new
    /// joins use the new epoch, and then replaces each pipe that existed when it was
    /// called, one after another: it dials a carrier of the same direction through the
    /// [`redial`](Config#structfield.redial) hook, adds it with the old
    /// pipe's options, and closes the old pipe gracefully once the new one is attached
    /// (make before break).
    ///
    /// Without a [`Redial::blocking`](crate::Redial::blocking) hook it fails at once with
    /// [`PipeError::InvalidOptions`]; outside a multipath session with
    /// [`PipeError::NotNegotiated`]; on a thread that drives sessions with
    /// [`WaitError::OnDriverThread`]. When `timeout` passes the call fails with
    /// [`WaitError::TimedOut`]: the pipes already replaced stay replaced and the others are
    /// kept as they are; a dial in progress runs to its end first, since the hook cannot be
    /// interrupted. A dial or join that fails ends the call with its error on the same
    /// terms. While the previous epoch is still kept, the next exchange waits until it is
    /// deleted, so a short timeout may end the call before any pipe is replaced. An epoch
    /// is kept for [`EPOCH_RETENTION`](crate::proto::session::EPOCH_RETENTION) (3 min)
    /// after this end switched away from it: called within that time after an exchange
    /// that completed, for example one [`advance_epoch`](Session::advance_epoch) started
    /// under [`EpochPolicy::MANUAL`](crate::EpochPolicy::MANUAL), it waits that long
    /// before its own exchange, by design. One called while an exchange is in progress
    /// takes that exchange's epoch as the new one.
    pub fn replace_pipes_timeout(&self, timeout: Duration) -> Result<(), WaitError<PipeError>> {
        self.replace_pipes_until(Instant::now().checked_add(timeout))
    }

    fn replace_pipes_until(&self, deadline: Option<Instant>) -> Result<(), WaitError<PipeError>> {
        if on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        let redial = self.shared().lock().core.config().redial.clone();
        let Some(redial) = redial.as_ref().and_then(crate::Redial::as_blocking) else {
            return Err(WaitError::Failed(PipeError::InvalidOptions(
                crate::InvalidConfig::new("redial", "replace_pipes needs a blocking redial hook"),
            )));
        };
        let (old, before) = self.begin_replace_pipes()?;
        run(self.epoch_in_use_op(before), deadline).ok_or(WaitError::TimedOut)??;
        for pipe in old {
            // Gone meanwhile: nothing to replace.
            let Some((direction, opts)) = handle::replacement(&pipe) else {
                continue;
            };
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Err(WaitError::TimedOut);
            }
            let io = redial
                .dial(super::DialRequest::new(direction))
                .map_err(|e| PipeError::Io(Arc::new(e)))?;
            let limit = Instant::now() + self.add_pipe_limit();
            let p = self.begin_add_pipe(io, opts)?;
            let guard = handle::AbortUnlessAdded(Some(&p));
            match deadline {
                Some(d) if d < limit => {
                    run(p.added_op(false), Some(d)).ok_or(WaitError::TimedOut)??;
                }
                _ => run(p.added_op(false), Some(limit)).unwrap_or(Err(JOIN_TIMED_OUT))?,
            }
            guard.added();
            match pipe.close() {
                Ok(()) | Err(PipeError::UnknownPipe) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Closes gracefully and waits until the session ended: `Ok` when it
    /// closed as requested, otherwise the error that ended it first. On a
    /// thread that drives sessions it fails at once and does nothing.
    pub fn shutdown(&self, code: VarInt, reason: &[u8]) -> Result<(), WaitError> {
        call(self.shutdown_op(code, reason))
    }

    /// [`shutdown`](blocking::Session#method.shutdown), waiting at most
    /// `timeout`; the close it started goes on.
    pub fn shutdown_timeout(
        &self,
        code: VarInt,
        reason: &[u8],
        timeout: Duration,
    ) -> Result<(), WaitError> {
        call_timeout(Some(timeout), self.shutdown_op(code, reason))
    }

    /// Sends a `QX_PING` request, or joins the one outstanding, and waits
    /// for the round-trip time it measured; the sample
    /// also updates [`Session::rtt`](blocking::Session#method.rtt) and the statistics. Works with every
    /// peer, plain QMux peers included. On a thread that drives sessions
    /// it fails at once.
    pub fn ping(&self) -> Result<Duration, WaitError> {
        call(self.ping_op())
    }

    /// [`ping`](blocking::Session#method.ping), waiting at most `timeout`.
    pub fn ping_timeout(&self, timeout: Duration) -> Result<Duration, WaitError> {
        call_timeout(Some(timeout), self.ping_op())
    }

    /// Waits until the peer's parameters arrived (the session is
    /// established: with early data it is usable before), or fails with the
    /// error that ended the session first.
    pub fn established(&self) -> Result<(), WaitError> {
        call(self.established_op())
    }

    /// [`established`](blocking::Session#method.established), waiting at
    /// most `timeout`.
    pub fn established_timeout(&self, timeout: Duration) -> Result<(), WaitError> {
        call_timeout(Some(timeout), self.established_op())
    }

    /// Waits until the session is closing, that is until it began to end,
    /// and returns why; its carriers may still be draining
    /// ([`Session::closed`](blocking::Session#method.closed) waits
    /// for the whole end).
    pub fn closing(&self) -> Result<SessionError, WaitError> {
        wait_for(None, self.closing_op())
    }

    /// [`closing`](blocking::Session#method.closing), waiting at most
    /// `timeout`.
    pub fn closing_timeout(&self, timeout: Duration) -> Result<SessionError, WaitError> {
        wait_for(Some(timeout), self.closing_op())
    }

    /// Waits until the session has ended entirely and returns why: every
    /// pipe's inbound side has ended (the peer read `CONNECTION_CLOSE` and
    /// ended its side) or the linger timeout passed, and the session's
    /// writer threads are done. Returning before the linger timeout thus
    /// confirms that the peer read the close.
    pub fn closed(&self) -> Result<SessionError, WaitError> {
        wait_for(None, self.wait_op())
    }

    /// [`closed`](blocking::Session#method.closed), waiting at most
    /// `timeout`: "delivered, or given up after it"; a timeout changes
    /// nothing in the session.
    pub fn closed_timeout(&self, timeout: Duration) -> Result<SessionError, WaitError> {
        wait_for(Some(timeout), self.wait_op())
    }

    /// The next session event; `None` once the session ended and every
    /// event was read.
    pub fn next_event(&self) -> Result<Option<Event>, WaitError> {
        wait_for(None, self.next_event_op())
    }

    /// [`next_event`](blocking::Session#method.next_event), waiting at most
    /// `timeout`.
    pub fn next_event_timeout(&self, timeout: Duration) -> Result<Option<Event>, WaitError> {
        wait_for(Some(timeout), self.next_event_op())
    }
}

/// What `add_pipe` fails with when its join bound passed.
const JOIN_TIMED_OUT: PipeError = PipeError::Failed(crate::PipeFailure::JoinTimedOut);

impl Pipe {
    /// Waits until the pipe's join is confirmed or failed (see
    /// `zmux::Pipe::joined`).
    pub fn joined(&self) -> Result<(), WaitError<PipeError>> {
        call(self.joined_op())
    }

    /// [`joined`](blocking::Pipe#method.joined), waiting at most `timeout`.
    pub fn joined_timeout(&self, timeout: Duration) -> Result<(), WaitError<PipeError>> {
        call_timeout(Some(timeout), self.joined_op())
    }

    /// Waits until the peer attached the pipe (see `zmux::Pipe::attached`).
    pub fn attached(&self) -> Result<(), WaitError<PipeError>> {
        call(self.attached_op())
    }

    /// [`attached`](blocking::Pipe#method.attached), waiting at most
    /// `timeout`.
    pub fn attached_timeout(&self, timeout: Duration) -> Result<(), WaitError<PipeError>> {
        call_timeout(Some(timeout), self.attached_op())
    }

    /// Waits until the pipe ended (see `zmux::Pipe::closed`).
    pub fn closed(&self) -> Result<(), WaitError<PipeError>> {
        call(self.closed_op())
    }

    /// [`closed`](blocking::Pipe#method.closed), waiting at most `timeout`.
    pub fn closed_timeout(&self, timeout: Duration) -> Result<(), WaitError<PipeError>> {
        call_timeout(Some(timeout), self.closed_op())
    }
}

impl SendStream {
    /// Bounds how long each call that writes waits; `None` waits forever.
    /// A call that timed out fails with [`WaitError::TimedOut`].
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// Writes some of `buf`, waiting for room.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, WaitError<StreamError>> {
        call_timeout(self.timeout, self.write_op(buf))
    }

    /// Writes all of `buf`; the write timeout bounds the whole call.
    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), WaitError<StreamError>> {
        call_timeout(self.timeout, self.write_all_op(buf))
    }

    /// Writes a chunk without copying it.
    pub fn write_chunk(&mut self, data: Bytes) -> Result<(), WaitError<StreamError>> {
        call_timeout(self.timeout, self.write_chunk_op(data))
    }

    /// Writes as many of `bufs` as the buffers take without copying them;
    /// a chunk taken in part is advanced. Waits until something is written.
    pub fn write_chunks(
        &mut self,
        bufs: &mut [Bytes],
    ) -> Result<handle::Written, WaitError<StreamError>> {
        call_timeout(self.timeout, self.write_chunks_op(bufs))
    }

    /// Waits until the sending part ended: `None` when the FIN was written,
    /// or the peer's `STOP_SENDING` code. `None` says the data reached the
    /// peer's zmux endpoint at most, not its application.
    pub fn stopped(&self) -> Result<Option<VarInt>, WaitError<StreamError>> {
        call(self.stopped_op())
    }

    /// Waits for send capacity of at least `min`
    /// bytes, or of any while the part holds nothing unsent, and returns
    /// it; returns at once with the error that ended the part (a reset or
    /// finish, the peer's `STOP_SENDING`, the session's end). The write
    /// timeout bounds the wait.
    pub fn wait_send_capacity(&self, min: u64) -> Result<u64, WaitError<StreamError>> {
        call_timeout(self.timeout, self.send_capacity_op(min))
    }

    /// Waits until the send buffers have room for a write and returns the
    /// bytes [`try_write`](Self::try_write) takes now (see
    /// [`poll_writable`](Self::poll_writable)); returns at once with the
    /// error that ended the part. The write timeout bounds the wait.
    pub fn wait_writable(&self) -> Result<u64, WaitError<StreamError>> {
        call_timeout(self.timeout, self.writable_op())
    }
}

impl Write for SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        SendStream::write(self, buf).map_err(io::Error::from)
    }

    /// Opens the stream now and waits until the opening frame and the data
    /// written so far left for a carrier: the peer sees the stream even
    /// with nothing written, for a protocol whose other side speaks first.
    /// Data written before goes in the opening frame. Before establishment
    /// the frame goes as soon as the stream may open, in early data if
    /// that is in use; while the first flight is held it returns at once
    /// and the frames leave with the flight. The write timeout bounds the
    /// wait.
    ///
    /// A `STOP_SENDING` from the peer fails the flush only if it arrives
    /// before all that left; once it left, the flush succeeds and the next
    /// write or finish reports the stop. A lost session fails it.
    fn flush(&mut self) -> io::Result<()> {
        call_timeout(self.timeout, self.flush_op()).map_err(io::Error::from)
    }
}

impl RecvStream {
    /// Bounds how long each call that reads waits; `None` waits forever.
    /// A call that timed out fails with [`WaitError::TimedOut`].
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// Reads into `buf`; `None` at the end of the stream.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, WaitError<StreamError>> {
        call_timeout(self.timeout, self.read_op(buf))
    }

    /// Fills `buf` exactly; the read timeout bounds the whole call.
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), WaitError<ReadExactError>> {
        call_timeout(self.timeout, self.read_exact_op(buf))
    }

    /// Reads up to `max` bytes as one chunk; `None` at the end.
    pub fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>, WaitError<StreamError>> {
        call_timeout(self.timeout, self.read_chunk_op(max))
    }

    /// Fills as many of `bufs` as data is available for, without copying;
    /// returns how many were filled, or `None` at the end of the stream.
    pub fn read_chunks(
        &mut self,
        bufs: &mut [Bytes],
    ) -> Result<Option<usize>, WaitError<StreamError>> {
        call_timeout(self.timeout, self.read_chunks_op(bufs))
    }

    /// Reads the whole stream, failing beyond `limit` bytes; the read
    /// timeout bounds the whole call.
    pub fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>, WaitError<ReadToEndError>> {
        call_timeout(self.timeout, self.read_to_end_op(limit))
    }

    /// Waits until the next read would not wait: data is readable, or the
    /// receiving part has ended (the FIN, a reset, a stop by this endpoint,
    /// the session's end). `Ok` in all of these: the read that follows
    /// reports the data or the end, once, in its own form. Consumes
    /// nothing; the read timeout bounds the wait and is its only error
    /// ([`WaitError::TimedOut`], besides the refusal on a driver thread):
    /// it never returns [`WaitError::Failed`], the error type being the one
    /// every blocking stream call shares.
    pub fn wait_readable(&self) -> Result<(), WaitError<StreamError>> {
        call_timeout(self.timeout, async {
            self.readable_op().await;
            Ok(())
        })
    }

    /// Waits until the peer reset the stream: its code, or `None` when the
    /// stream ended with a FIN instead.
    pub fn received_reset(&mut self) -> Result<Option<VarInt>, WaitError<StreamError>> {
        call_timeout(self.timeout, self.received_reset_op())
    }

    /// Receives the next datagram of this stream.
    pub fn read_datagram(&self) -> Result<crate::StreamDatagram, WaitError<StreamError>> {
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

// The doc link of the generated `resolve_duplicate`.
#[cfg(doc)]
use crate::helpers::DuplicateError;

crate::helpers::duplicate_api!(Blocking, Session, Dial);

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for HandshakeWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeWait").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Io {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Io").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deferred").finish_non_exhaustive()
    }
}
