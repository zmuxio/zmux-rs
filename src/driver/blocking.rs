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
use tokio::sync::watch;

use super::context::{DriverThread, on_driver_thread};
use super::engine::{self, Calls, Outbound, Progress};
use super::handle::{self, CarrierInfo, Driver, Shared, State};
use super::session_timer::{self, Next};
use super::sync::{park, thread_waker};
use super::tcp::{Probe, TcpSocket};
use super::unsent::{Unsent, UnsentQuery};
use super::wait::WaitList;
use super::{Event, IDLE_READ, IDLE_RELEASE, MAX_SLICES};
use crate::ClockDomain;
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

/// A blocking session capacity transaction.
pub type CapacityChange = super::capacity_change::CapacityChangeFor<Blocking>;
/// A queued blocking capacity request.
pub type ChangeAdmission = super::capacity_change::ChangeAdmissionFor<Blocking>;
/// An opener of blocking carriers.
pub type CarrierOpener = super::capacity_change::CarrierOpenerFor<PipeIo>;
/// Blocking carriers returned by an opener.
pub type OpenedCarriers = super::capacity_change::OpenedCarriersFor<PipeIo>;

/// Configuration for the session controller.
pub type ControllerOptions = super::controller::ControllerOptions<Blocking>;
/// Controls sessions and candidate admission in one host domain.
pub type SessionController = super::controller::SessionController<Blocking>;
/// The current generation of control over a session.
pub type SessionControl = super::controller::SessionControl<Blocking>;
/// A native blocking carrier candidate.
pub type Candidate = super::choice::Candidate<Blocking>;

impl SessionController {
    /// Establishes and manages a session using blocking carrier I/O.
    ///
    /// # Errors
    ///
    /// Returns the target, admission or transport error, or an invalid calling context.
    pub fn open(
        &self,
        config: Config,
        target: crate::SessionTarget,
    ) -> Result<(Session, Option<SessionControl>), WaitError<crate::ControllerError>> {
        call(self.open_async(config, target))
    }
}

impl SessionController {
    /// Waits until the controller and its bindings have stopped.
    ///
    /// # Errors
    ///
    /// Returns an error when called on a driver thread.
    pub fn done_blocking(&self) -> Result<(), WaitError> {
        wait_for(None, self.done())
    }
}

impl SessionControl {
    /// Waits until this generation has stopped.
    ///
    /// # Errors
    ///
    /// Returns an error when called on a driver thread.
    pub fn done_blocking(&self) -> Result<(), WaitError> {
        wait_for(None, self.done())
    }
}

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

impl super::capacity_change::CarrierOpenerFor<PipeIo> {
    /// Wraps a synchronous host opener.
    pub fn blocking<F, O>(open: F) -> Self
    where
        F: Fn(crate::OpenRequest) -> O + Send + Sync + 'static,
        O: Into<OpenedCarriers> + Send + 'static,
    {
        Self::new(move |request| std::future::ready(open(request)))
    }
}

impl ChangeAdmission {
    /// Waits for this change's admission on the calling thread.
    ///
    /// # Errors
    ///
    /// Returns the admission error or rejects waiting on a driver thread.
    pub fn wait_blocking(self) -> Result<CapacityChange, WaitError<crate::ChangeError>> {
        call(self.wait())
    }
}

impl crate::Attempt {
    /// Waits for the attempt result on the calling thread.
    ///
    /// # Errors
    ///
    /// Returns an error if called from a driver thread.
    pub fn wait_blocking(
        &self,
    ) -> Result<crate::AttemptResult, WaitError<std::convert::Infallible>> {
        if on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        run(self.wait(), None).ok_or(WaitError::TimedOut)
    }
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

/// An absolute bound and the clock that owns it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BlockingDeadline {
    clock: ClockDomain,
    at: Option<Instant>,
}

impl BlockingDeadline {
    fn after(clock: &ClockDomain, timeout: Duration) -> Self {
        Self {
            clock: clock.clone(),
            at: clock.now_with(Blocking::now).checked_add(timeout),
        }
    }

    fn elapsed(&self) -> bool {
        self.at
            .is_some_and(|at| self.clock.now_with(Blocking::now) >= at)
    }
}

/// What ends a wait of a handshake on a carrier: the carrier's shutdown, or the deadline
/// set for it. A shutdown carrier fails the handshake's next read or write.
#[derive(Clone, Default)]
pub struct HandshakeWait(Arc<watch::Sender<HandshakeWaitState>>);

#[derive(Clone, Default)]
struct HandshakeWaitState {
    shut: bool,
    deadline: BlockingDeadline,
}

impl HandshakeWait {
    /// Waits for `d`, at most until the carrier's shutdown or the deadline.
    pub fn sleep(&self, d: Duration) {
        self.drive(Some(d), std::future::pending::<()>());
    }

    fn shut(&self) {
        self.0.send_modify(|state| state.shut = true);
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
        self.drive(None, fut)
            .ok_or_else(|| io::ErrorKind::TimedOut.into())
    }

    fn drive<F: Future>(&self, delay: Option<Duration>, fut: F) -> Option<F::Output> {
        let mut fut = pin!(fut);
        let mut updates = self.0.subscribe();
        let mut requested = None;
        loop {
            let HandshakeWaitState { shut, deadline } = updates.borrow_and_update().clone();
            if shut {
                return None;
            }
            if let Some(delay) = delay
                && requested
                    .as_ref()
                    .is_none_or(|bound: &BlockingDeadline| bound.clock != deadline.clock)
            {
                requested = Some(BlockingDeadline::after(&deadline.clock, delay));
            }
            let due = super::deadline::earlier(
                requested.as_ref().and_then(|bound| bound.at),
                deadline.at,
            );
            let changed = async {
                let _ = updates.changed().await;
            };
            let step = super::hooks::first(changed, fut.as_mut());
            match wait_in_domain(&deadline.clock, due, step) {
                Some(None) => {}
                result => return result.flatten(),
            }
        }
    }

    fn limit(&self, deadline: BlockingDeadline) {
        self.0.send_modify(|state| state.deadline = deadline);
    }

    fn clock_domain(&self) -> ClockDomain {
        self.0.borrow().deadline.clock.clone()
    }
}

/// A carrier for a blocking session: a readable half, a writable half, or
/// both.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent properties of the carrier"
)]
pub struct PipeIo {
    wait: HandshakeWait,
    reader: Option<Reader>,
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
    carrier_stats: Option<Box<super::carrier_stats::Source>>,
    pub(super) accounting_sources: Option<Box<crate::CarrierHalfSources>>,
    /// The padding of a handshake run on the carrier before this pipe
    /// ([`PipeIo::with_establish_receipts`]).
    establish_receipts: crate::shaping::EstablishReceipts,
    /// The carrier's write overhead ([`PipeIo::with_write_overhead`]).
    write_overhead: u16,
    /// The carrier has a low-water mark.
    low_water: bool,
    /// The secure carrier's Bound contract holds.
    secure: bool,
    /// Two halves paired as one carrier.
    split: bool,
    /// The carrier reports its own failure.
    pub(crate) reports_failure: bool,
    /// The largest record the carrier takes.
    max_record: Option<usize>,
    /// The record mode of an Establish this carrier ran.
    first_mode: Option<crate::proto::seal::RecordMode>,
    /// The value of the peer a transform authenticated.
    admitted: Option<crate::AdmittedValue>,
    pub(crate) attachment: Option<Arc<super::attachment::Attachment>>,
}

impl PipeIo {
    /// One carrier of two one-way ones, the local endpoint's uplink and downlink.
    #[must_use]
    pub fn paired_join(mut uplink: PipeIo, mut downlink: PipeIo) -> PipeIo {
        let sources = crate::CarrierHalfSources {
            send: if uplink.writer.is_some() {
                uplink.record_sources().send
            } else {
                downlink.record_sources().send
            },
            receive: if uplink.reader.is_some() {
                uplink.record_sources().receive
            } else {
                downlink.record_sources().receive
            },
        };
        uplink.accounting_sources = Some(Box::new(sources));
        uplink.reader = downlink.reader.take();
        uplink.split = true;
        uplink.secure &= downlink.secure;
        uplink.reports_failure &= downlink.reports_failure;
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

    /// Declares whether the carrier reports its own failure: when the path
    /// under it fails, its reads or writes fail (an error, a reset, an
    /// unexpected end), as a stream of an outer session does when that
    /// session's liveness ends it (the tokio `PipeIo::from_stream` sets it). The
    /// pipe's stall then never fails it: a carrier queued behind a rate
    /// limit stalls without being dead, and its own end is the failure
    /// signal. The stalled pipe still turns suspect, is avoided and probed.
    /// The pipe's own [`PipeLiveness::dead_timeout`](crate::PipeLiveness::dead_timeout)
    /// overrides it. A transform that fails when the carrier below it
    /// fails keeps it. Two one-way halves made one carrier
    /// (`PipeIo::paired_join`) report their failure only if both do: a
    /// half that does not (a raw TCP stream) can stall silently.
    #[must_use]
    pub fn with_reports_failure(mut self, on: bool) -> Self {
        self.reports_failure = on;
        self
    }

    /// Whether the carrier reports its own failure
    /// ([`PipeIo::with_reports_failure`]).
    #[must_use]
    pub fn reports_failure(&self) -> bool {
        self.reports_failure
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

    pub(crate) fn write_join(
        &mut self,
        write: &mut super::accept::JoinWrite<Blocking>,
    ) -> io::Result<()> {
        let writer = self.writer.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        let result = write.write_blocking(writer, self.framing);
        write.settle(result.is_err());
        result
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
            self.reader = Some(Reader::Io(Box::new(Read::chain(
                io::Cursor::new(prefix),
                r,
            ))));
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
            Reader::Sealed(Box::new(SealedRead {
                lower,
                records: crate::proto::seal::SealedReader::new(
                    framing,
                    opener,
                    Vec::new(),
                    self.max_record,
                ),
                remainder: None,
            }))
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

    /// Attaches an opaque host value to the carrier.
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
        let deadline = BlockingDeadline::after(&self.wait.clock_domain(), timeout);
        self.shared_closer()
            .map(|c| Watchdog::start(c, deadline))
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
        self.wait
            .limit(BlockingDeadline::after(&self.wait.clock_domain(), timeout));
    }

    pub(super) fn set_handshake_deadline(&mut self, clock: &ClockDomain, at: Option<Instant>) {
        self.wait.limit(BlockingDeadline {
            clock: clock.clone(),
            at,
        });
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
    pub(crate) fn keep_directions(&mut self, inbound: bool, outbound: bool) -> io::Result<()> {
        if inbound && outbound {
            return Ok(());
        }
        let reader = (!inbound).then(|| self.reader.take());
        let writer = (!outbound).then(|| self.writer.take());
        let closer = self.shared_closer();
        let lease = self.attachment.clone();
        thread::Builder::new().spawn(move || {
            let _lease = lease;
            if let Some(c) = closer {
                c(if inbound {
                    Shutdown::Write
                } else {
                    Shutdown::Read
                });
            }
            drop((reader, writer));
        })?;
        Ok(())
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
        // The watchdog, listener and session threads may race to interrupt
        // the same carrier. Only the first full shutdown reaches the host.
        let closed = std::sync::atomic::AtomicBool::new(false);
        let c: Arc<Closer> = Arc::new(Box::new(move |how| {
            use std::sync::atomic::Ordering::Relaxed;
            if how == Shutdown::Both {
                if closed.swap(true, Relaxed) {
                    return;
                }
            } else if closed.load(Relaxed) {
                return;
            }
            if how == Shutdown::Both {
                wait.shut();
            }
            crate::proto::decision::host(|| inner(how));
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
            reports_failure: false,
            max_record: None,
            first_mode: None,
            wait: HandshakeWait::default(),
            attachment: None,
            admitted: None,
            reader: Some(Reader::Io(Box::new(SharedTcp(stream.clone())))),
            writer: Some(Box::new(SharedTcp(stream))),
            closer: Some(Box::new(move |how| shut_down(&control, how))),
            framing: Framing::ByteStream,
            abort: Some(Box::new(move || shut_down(&abort, Shutdown::Both))),
            exporter: None,
            variant: None,
            protocol: None,
            carrier: Some(crate::CarrierKind::Raw),
            unsent: socket.as_ref().and_then(TcpSocket::unsent_query),
            carrier_stats: None,
            accounting_sources: None,
            write_overhead: 0,
            establish_receipts: [None; 2],
            socket,
            low_water,
        }
    }

    /// The closer of [`PipeIo::from_tcp`] for a carrier built over a TCP socket by hand
    /// (separate halves, a wrapper that frames or counts), for [`PipeIo::with_closer`]:
    /// [`Shutdown::Read`] and [`Shutdown::Write`] shut that side, [`Shutdown::Both`] shuts
    /// both sides one by one and, on Windows, cancels the I/O blocked in other threads, which
    /// a shutdown alone does not end. Share the same `TcpStream` between the
    /// reader, writer and closer with an `Arc`. A socket created by
    /// `TcpStream::try_clone` has a different handle on Windows, so its
    /// cancellation cannot reach I/O pending on the original stream.
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
            reader: Some(Reader::Io(Box::new(reader))),
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
            carrier_stats: None,
            accounting_sources: None,
            write_overhead: 0,
            establish_receipts: [None; 2],
            secure: false,
            split: false,
            reports_failure: false,
            max_record: None,
            first_mode: None,
            wait: HandshakeWait::default(),
            attachment: None,
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
        self.closer = Some(Box::new(move |direction| {
            crate::proto::decision::host(|| closer(direction));
        }));
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

    /// Supplies the connection's paired counters for on-demand pipe statistics.
    #[must_use]
    pub fn with_carrier_counters(
        mut self,
        provider: crate::CarrierSource,
        query: impl Fn() -> Option<crate::CarrierCounts> + Send + Sync + 'static,
    ) -> Self {
        self.carrier_stats = Some(Box::new(super::carrier_stats::Source::new(provider, query)));
        self
    }

    pub(super) fn reserve_carrier_memory(
        &mut self,
        shared: &Shared<Blocking>,
    ) -> Result<(), PipeError> {
        if self.reader.is_some() {
            shared.reserve_reader_memory(self.attachment.get_or_insert_default())?;
        }
        Ok(())
    }

    pub(super) fn register_carrier_stats(&mut self) {
        let mut source = self
            .carrier_stats
            .take()
            .map(|source| *source)
            .or_else(|| self.socket.as_ref().map(TcpSocket::counter_source))
            .unwrap_or_default();
        source.dedicated |= self.socket.is_some();
        self.attachment
            .get_or_insert_default()
            .register_sample(source, Instant::now);
    }

    /// Carries the outbound Establish receipts into the session's initial accounting.
    #[must_use]
    pub fn with_establish_receipts(mut self, receipts: crate::shaping::EstablishReceipts) -> Self {
        self.establish_receipts = receipts;
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
    pub(crate) fn resolve_exporter(&self, clock: &ClockDomain, deadline: Option<Instant>) {
        if let Some(e) = self.exporter.as_ref().filter(|e| !e.is_resolved()) {
            let _ = wait_in_domain(clock, deadline, e.resolve());
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

    /// Supplies source attribution for ownership of each local half.
    #[must_use]
    pub fn with_accounting_sources(mut self, sources: crate::CarrierHalfSources) -> Self {
        self.accounting_sources = Some(Box::new(sources));
        self
    }

    pub(super) fn record_sources(&self) -> crate::CarrierHalfSources {
        self.accounting_sources
            .as_deref()
            .cloned()
            .unwrap_or_else(|| crate::CarrierHalfSources::from_carrier(self.carrier, None))
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
#[derive(Debug, Clone)]
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

fn redial_carrier(dial: &Dial, request: super::DialRequest) -> io::Result<PipeIo> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dial.dial(request)))
        .unwrap_or_else(|_| Err(crate::proto::session::RedialCompletion::panicked()))
}

impl Driver for Blocking {
    type Io = Io;
    type Deferred = Deferred;
    type Paths = ();
    type Carrier = PipeIo;
    type Timeout = Option<Duration>;
    type Dial = Dial;

    fn spawn_controller(future: impl Future<Output = ()> + Send + 'static) {
        thread::spawn(move || run(future, None));
    }

    fn candidate_metadata(io: &mut PipeIo, kind: crate::CarrierKind, variant: Option<&Arc<str>>) {
        io.carrier = Some(kind);
        if let Some(variant) = variant {
            io.variant = Some(variant.clone());
        }
    }

    fn hold_cleanup(io: &mut PipeIo, guard: impl Send + 'static) {
        io.attachment.get_or_insert_default().hold(guard);
    }

    fn controller_bootstrap(
        io: PipeIo,
        config: Arc<Config>,
    ) -> Result<Arc<Shared<Self>>, ConnectError> {
        Session::prepare(
            &mut Some(io),
            config,
            Role::Client,
            Some(Role::Client),
            None,
            None,
            |_| {},
        )
    }

    fn spawn_join(_: &Shared<Self>, f: impl Future<Output = ()> + Send + 'static) {
        thread::spawn(move || {
            run(f, None);
        });
    }

    async fn join_callback<T: Send + 'static>(
        call: impl FnOnce() -> crate::Decision<T> + Send + 'static,
    ) -> Option<crate::Decision<T>> {
        let reply = Arc::new((
            super::sync::Mutex::new(None),
            super::wait::PipeDone::default(),
        ));
        let worker = reply.clone();
        thread::Builder::new()
            .name("zmux-join-callback".into())
            .spawn(move || {
                let decision = crate::Decision::catch(call);
                *super::sync::lock(&worker.0) = decision;
                worker.1.finish_into(&mut super::wake::WakeList::default());
            })
            .ok()?;
        reply.1.wait().await;
        super::sync::lock(&reply.0).take()
    }

    async fn sleep_until(deadline: Instant) {
        let (send, receive) = ::tokio::sync::oneshot::channel();
        let mut send = Some(send);
        let _ = session_timer::spawn(move |waker| {
            let sender = send.as_mut().expect("live timer");
            if Instant::now() >= deadline {
                let _ = send.take().expect("live timer").send(());
                return Next::Done;
            }
            if sender
                .poll_closed(&mut Context::from_waker(waker))
                .is_ready()
            {
                return Next::Done;
            }
            Next::At(deadline)
        });
        let _ = receive.await;
    }

    fn resolve_join_exporter(carrier: &PipeIo) -> impl Future<Output = ()> + Send + 'static {
        let exporter = carrier.exporter_ref().filter(|e| !e.is_resolved());
        let wait = exporter.map(crate::proto::exporter::CarrierExporter::resolve);
        async move {
            if let Some(wait) = wait {
                wait.await;
            }
        }
    }

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

    fn session_closed(state: &mut State<Self>) {
        state.io.account = None;
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
            connection_memory: 0,
            #[cfg(feature = "tokio")]
            writer_memory: 0,
            attachment: carrier.attachment.get_or_insert_default().clone(),
            accounting_sources: carrier.record_sources(),
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
            establish_receipts: carrier.establish_receipts,
            secure: carrier.secure,
            reports_failure: carrier.reports_failure,
            split: carrier.split,
            first_mode: carrier.first_mode,
            admitted: carrier.admitted.take(),
            bound_prefix: None,
        }
    }

    fn register_carrier_stats(carrier: &mut PipeIo) {
        carrier.register_carrier_stats();
    }

    fn attach(shared: &Arc<Shared<Self>>, id: u64, mut carrier: PipeIo) -> Result<(), PipeError> {
        carrier.reserve_carrier_memory(shared)?;
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
        let lease = carrier.attachment.clone();
        thread::Builder::new()
            .name("zmux-join".into())
            .spawn(move || {
                let _lease = lease;
                join_thread(&s, PipeId(id), carrier, closer.is_some());
            })
            .map(drop)
            .map_err(|e| PipeError::Io(Arc::new(e)))
    }

    fn start_rejoin(session: handle::WeakSession<Self>, dial: Dial) -> bool {
        let Some(session) = session.upgrade() else {
            return false;
        };
        session.launch_recovery(CarrierOpener::blocking(move |_| {
            dial.dial(super::DialRequest::bidi()).map(|pipe| vec![pipe])
        }))
    }

    #[cfg(feature = "test-hooks")]
    fn io_tables(io: &Io) -> (usize, usize, usize, usize) {
        (io.writers.len(), io.closing.len(), 0, 0)
    }
}

struct PendingRedial {
    change: CapacityChange,
    attempt: crate::Attempt,
    report: crate::proto::session::RedialCompletion,
}

fn attempt_error(result: &crate::AttemptResult) -> PipeError {
    result
        .error
        .clone()
        .or_else(|| result.open_error.clone().map(PipeError::Io))
        .unwrap_or_else(|| match result.reason {
            crate::AttemptReason::Deadline => PipeError::Failed(crate::PipeFailure::JoinTimedOut),
            crate::AttemptReason::Cancelled | crate::AttemptReason::NoLongerNeeded => {
                PipeError::CallerCancelled(None)
            }
            _ => PipeError::Failed(crate::PipeFailure::JoinFailed),
        })
}

fn change_error(error: crate::ChangeError) -> PipeError {
    match error {
        crate::ChangeError::Closed(error) => PipeError::SessionLost(error),
        crate::ChangeError::NotNegotiated => PipeError::NotNegotiated,
        crate::ChangeError::Unauthorized => PipeError::InvalidArgument,
        crate::ChangeError::Drain(error) => error,
        crate::ChangeError::Coverage => PipeError::NoDirectionCoverage,
        _ => PipeError::Deferred,
    }
}

/// The redial hook of a blocking session ([`Config::redial`]): one member,
/// replaced when it fails, and make before break when its
/// [`replace_by`](crate::PipeStats::replace_by) passes, on a thread that holds no handle of the session between its
/// looks and ends with it. The tokio driver's pool of one member does the same.
struct Redialer {
    session: handle::WeakSession<Blocking>,
    hook: crate::Redial,
    retry: super::retry::PrivateRetry,
    host: Option<tokio::sync::watch::Receiver<()>>,
    /// The pipe in use, while it serves; a failed one is dropped.
    member: Option<Pipe>,
    pending: Option<PendingRedial>,
    /// The member being replaced: closed once its successor serves.
    retiring: Option<Pipe>,
    observation: super::retry::PrivateMember,
    attempted: Instant,
    _source: handle::RedialSource<Blocking>,
}

impl Redialer {
    fn spawn(session: &Session, hook: crate::Redial, backoff: crate::Backoff, pipe0: Pipe) {
        let now = session.clock_domain().now_with(Instant::now);
        let birth = pipe0
            .health()
            .and_then(|health| health.joined_at)
            .unwrap_or(now);
        let r = Self {
            session: session.downgrade(),
            hook,
            retry: super::retry::PrivateRetry::new(backoff),
            host: None,
            member: Some(pipe0),
            pending: None,
            retiring: None,
            observation: super::retry::PrivateMember::established(birth),
            attempted: now,
            _source: handle::RedialSource::new(session.shared()),
        };
        // Without a thread the session has no redial source: the suspension says so.
        let _ = thread::Builder::new()
            .name("zmux-redial".into())
            .spawn(move || r.run());
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
            self.observe(&session);
            let now = session.clock_domain().now_with(Instant::now);
            let capacity = session.capacity();
            let missing = capacity.required.difference(capacity.covered) != crate::Directions::NONE;
            let due = self.retry.deadline(now, missing);
            if self.member.is_none()
                && self.pending.is_none()
                && self
                    .host
                    .as_ref()
                    .is_none_or(|host| host.has_changed().is_err())
                && session.adapter().join_ready()
                && due.is_none()
            {
                self.attempted = now;
                // The dial holds no handle: dropping the last one closes the session.
                if !self.redial() {
                    return;
                }
                if self.pending.is_some() {
                    continue;
                }
            }
            let mut next = now + Duration::from_millis(100);
            if self.member.is_none()
                && let Some(t) = due
            {
                next = next.min(t);
            }
            let shared = session.shared().clone();
            let clock = session.clock_domain();
            drop(session);
            wait_in_domain(&clock, Some(next), async {
                tokio::select! {
                    () = handle::pipes_changed_wait(&shared, seen) => {},
                    () = async {
                        if let Some(host) = self.host.as_mut() {
                            let _ = host.changed().await;
                        } else { std::future::pending::<()>().await; }
                    } => self.host = None,
                }
            });
        }
    }

    /// Looks at the member: dropped once it no longer serves, and replaced once the
    /// epoch policy wants its carrier replaced.
    fn observe(&mut self, session: &Session) {
        if let Some(pending) = &self.pending
            && let Some(result) = pending.attempt.snapshot().result
        {
            let capacity = session.capacity();
            self.retry.attempt_ended(
                &result,
                session.clock_domain().now_with(Instant::now),
                capacity.required.difference(capacity.covered) != crate::Directions::NONE,
            );
            let committed = if result.reason == crate::AttemptReason::Confirmed {
                pending.change.commit().map(|_| ()).map_err(change_error)
            } else {
                Err(attempt_error(&result))
            };
            let mut pending = self.pending.take().expect("finished redial");
            if let Some(&pipe) = result.pipes.first() {
                pending.report.set_pipe(pipe);
                if committed.is_ok() {
                    self.member = session.pipe(pipe);
                    self.observation = super::retry::PrivateMember::default();
                }
            }
            if let Err(error) = &committed
                && let Some(reason) = super::retry::CooldownReason::from_pipe_error(error)
            {
                self.retry
                    .failure(session.clock_domain().now_with(Instant::now), reason);
            }
            pending.report.complete(committed);
        }
        if self
            .retiring
            .as_ref()
            .is_some_and(|p| handle::dead(p.pipe_signals().as_ref()))
        {
            self.retiring = None;
        }
        let Some(p) = &self.member else {
            return;
        };
        let info = p.pipe_signals();
        let dead = handle::dead(info.as_ref());
        let now = session.clock_domain().now_with(Instant::now);
        if dead
            && let Some(next) = p.replacement_id()
            && let Some(pipe) = session.pipe(next)
        {
            let joined = pipe
                .health()
                .and_then(|health| health.joined_at)
                .unwrap_or(now);
            self.member = Some(pipe);
            self.observation = super::retry::PrivateMember::established(joined);
            return;
        }
        self.observation.observe(
            &mut self.retry,
            now,
            self.attempted,
            super::retry::MemberHealth::from_pipes(
                std::slice::from_ref(p),
                std::slice::from_ref(&info),
            ),
        );
        if dead {
            let _ = p.close();
            self.member = None;
            drop(self.pending.take());
        } else if let Some(i) = info.filter(handle::usable) {
            if let Some(old) = &self.retiring {
                if i.health.settled() {
                    let member = session.shared().lock().core.member_for_pipe(old.id());
                    if let Some(member) = member {
                        let mut request =
                            crate::ChangeRequest::new(session.capacity(), Duration::ZERO);
                        request.drain.push(member);
                        if session
                            .begin_change(request)
                            .and_then(|change| change.commit())
                            .is_ok()
                        {
                            self.retiring = None;
                        }
                    } else {
                        self.retiring = None;
                    }
                }
            } else if i.replace_by.is_some_and(|t| now >= t) {
                self.retiring = self.member.take();
            }
        }
    }

    /// Dials a replacement and starts its join; `false` when the session takes no more.
    fn redial(&mut self) -> bool {
        let Some(session) = self.session.upgrade() else {
            return false;
        };
        let cause = if self.retiring.is_some() {
            crate::RedialCause::QualityReplacement
        } else {
            crate::RedialCause::Recovery
        };
        match session.single_member_change(PipeOptions::new(), None, None) {
            Ok(change) => {
                let report =
                    session
                        .shared()
                        .begin_redial(&self.hook, crate::PipeDirection::Bidi, cause);
                let request = report.request();
                let dial = self.hook.as_blocking().expect("this runtime").clone();
                let (host, returned) = tokio::sync::watch::channel(());
                self.host = Some(returned);
                let opener = CarrierOpener::blocking(move |_| {
                    let _physical = &host;
                    redial_carrier(&dial, request.clone()).map(|pipe| vec![pipe])
                });
                match change.start_member(0, opener) {
                    Ok(attempt) => {
                        self.pending = Some(PendingRedial {
                            change,
                            attempt,
                            report,
                        });
                    }
                    Err(error) => report.complete(Err(change_error(error))),
                }
                true
            }
            Err(error) => !matches!(
                error,
                crate::ChangeError::NotNegotiated | crate::ChangeError::Closed(_)
            ),
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
    }

    /// Under the lock: their results go to the core.
    fn feed(&mut self, core: &mut crate::proto::session::SessionCore, id: PipeId, now: Instant) {
        if let Some(p) = &mut self.probe {
            p.feed(core, id);
        }
        if let Some(q) = &mut self.unsent {
            q.feed(core, id.into(), now);
        }
    }
}

/// Runs the joiner's handshake, then the pipe's threads.
fn join_thread(shared: &Arc<Shared<Blocking>>, id: PipeId, mut pipe: PipeIo, closer: bool) {
    use super::accept::{DialStep, JoinDial, JoinWrite};
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
                let mut write = JoinWrite::new(shared.clone(), unit);
                let result = write.write_blocking(&mut w, framing);
                write.settle(result.is_err());
                dial.written(result)
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
    pipe.reader = Some(Reader::Io(Box::new(Read::chain(rest, r))));
    pipe.writer = Some(w);
    if let Some((sealer, opener)) = records {
        pipe = pipe.seal_records(sealer, opener);
    }
    if let Err(err) = pipe.keep_directions(inbound, outbound) {
        dial.failed(err.kind());
        return done(shared);
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
    let clock = shared.lock().core.config().clock_domain.clone();
    let deadline = clock.now_with(Blocking::now).checked_add(delay);
    wait_in_domain(&clock, deadline, handle::join_failed_wait(shared, id)).is_some()
}

/// Shuts a carrier down at a deadline, ending calls blocked on it. One thread until dropped.
#[derive(Debug)]
pub struct Watchdog(watch::Sender<WatchState>);

#[derive(Debug, PartialEq, Eq)]
enum WatchState {
    Armed(BlockingDeadline),
    Disarmed,
    Fired,
}

impl Watchdog {
    pub(super) fn new(
        closer: Arc<Closer>,
        clock: &ClockDomain,
        deadline: Option<Instant>,
    ) -> io::Result<Self> {
        Self::start(
            closer,
            BlockingDeadline {
                clock: clock.clone(),
                at: deadline,
            },
        )
    }

    fn start(closer: Arc<Closer>, deadline: BlockingDeadline) -> io::Result<Self> {
        let (state, mut changes) = watch::channel(WatchState::Armed(deadline));
        let worker = state.clone();
        thread::Builder::new()
            .name("zmux-watchdog".into())
            .spawn(move || {
                loop {
                    let deadline = match &*changes.borrow_and_update() {
                        WatchState::Armed(deadline) => deadline.clone(),
                        WatchState::Disarmed | WatchState::Fired => return,
                    };
                    if wait_in_domain(&deadline.clock, deadline.at, changes.changed()).is_some() {
                        continue;
                    }
                    if worker.send_if_modified(|state| {
                        if *state == WatchState::Armed(deadline) {
                            *state = WatchState::Fired;
                            true
                        } else {
                            false
                        }
                    }) {
                        closer(Shutdown::Both);
                        return;
                    }
                }
            })?;
        Ok(Self(state))
    }

    /// Moves the deadline to `timeout` from now in the current clock domain.
    pub fn reset(&self, timeout: Duration) {
        self.0.send_if_modified(|state| {
            let WatchState::Armed(bound) = state else {
                return false;
            };
            *bound = BlockingDeadline::after(&bound.clock, timeout);
            true
        });
    }

    pub(super) fn reset_at(&self, clock: &ClockDomain, at: Option<Instant>) {
        self.0.send_if_modified(|state| {
            let WatchState::Armed(bound) = state else {
                return false;
            };
            *bound = BlockingDeadline {
                clock: clock.clone(),
                at,
            };
            true
        });
    }

    /// Ends the watch: once this returns, it cannot claim the carrier for shutdown.
    pub fn disarm(&self) {
        self.0.send_if_modified(|state| {
            if matches!(state, WatchState::Armed(_)) {
                *state = WatchState::Disarmed;
                true
            } else {
                false
            }
        });
    }

    /// Completes the watch only while it is still within its deadline.
    pub(super) fn finish(&self) -> bool {
        self.0.send_if_modified(|state| {
            if matches!(state, WatchState::Armed(bound) if !bound.elapsed()) {
                *state = WatchState::Disarmed;
                true
            } else {
                false
            }
        })
    }

    /// Whether the deadline has passed and the watchdog has claimed shutdown.
    #[must_use]
    pub fn fired(&self) -> bool {
        matches!(*self.0.borrow(), WatchState::Fired)
    }

    pub(super) fn expired(&self) -> bool {
        match &*self.0.borrow() {
            WatchState::Armed(bound) => bound.elapsed(),
            WatchState::Disarmed => false,
            WatchState::Fired => true,
        }
    }

    pub(super) async fn ended(&self) {
        let _ = self
            .0
            .subscribe()
            .wait_for(|state| !matches!(state, WatchState::Armed(_)))
            .await;
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.disarm();
    }
}

enum Reader {
    Io(Box<dyn Read + Send>),
    Sealed(Box<SealedRead>),
}

impl Read for Reader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Io(reader) => reader.read(out),
            Self::Sealed(reader) => reader.read(out),
        }
    }
}

/// The reading half of a Sealed carrier, for allocation tests.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub struct SealedReadHalf(Box<SealedRead>);

#[cfg(feature = "test-hooks")]
impl std::fmt::Debug for SealedReadHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedReadHalf").finish_non_exhaustive()
    }
}

#[cfg(feature = "test-hooks")]
impl SealedReadHalf {
    /// Reads and authenticates the next owned record.
    ///
    /// # Errors
    ///
    /// The record or carrier failed.
    pub fn read_record(&mut self) -> io::Result<Option<crate::proto::ReceivedRecord>> {
        self.0.read_record()
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
) -> (SealedReadHalf, Box<dyn Write + Send>)
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let p = PipeIo::from_halves(reader, writer).seal_records(sealer, opener);
    let Some(Reader::Sealed(reader)) = p.reader else {
        unreachable!("sealed reader")
    };
    (SealedReadHalf(reader), p.writer.expect("a writing half"))
}

/// The std I/O shell of [`SealedReader`](crate::proto::seal::SealedReader).
struct SealedRead {
    lower: Reader,
    records: crate::proto::seal::SealedReader,
    remainder: Option<crate::proto::ReceivedRecord>,
}

impl SealedRead {
    fn read_record(&mut self) -> io::Result<Option<crate::proto::ReceivedRecord>> {
        use crate::proto::seal::SealedRead as R;
        if let Some(record) = self.remainder.take() {
            return Ok(Some(record));
        }
        loop {
            match self.records.read().map_err(super::sealed_failure)? {
                R::End => return Ok(None),
                R::Record(record) => return Ok(Some(record)),
                R::More => match self.lower.read(self.records.space()) {
                    Ok(0) => self.records.eof(),
                    Ok(n) => self.records.filled(n).map_err(super::sealed_failure)?,
                    Err(e) if super::is_empty_message(&e) => {
                        self.records.filled(0).map_err(super::sealed_failure)?;
                    }
                    Err(e) => return Err(e),
                },
            }
        }
    }
}

impl Read for SealedRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while let Some(mut record) = self.read_record()? {
            let n = record.copy_prefix(out.len(), |data| out[..data.len()].copy_from_slice(data));
            if n == 0 {
                continue;
            }
            if !record.as_ref().is_empty() {
                self.remainder = Some(record);
            }
            return Ok(n);
        }
        Ok(0)
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

#[cfg(test)]
pub(super) mod install_test {
    use super::*;
    type Hook = Box<dyn Fn(u64, bool) -> io::Result<()>>;
    thread_local! { pub(super) static HOOK: std::cell::RefCell<Option<Hook>> = const {std::cell::RefCell::new(None)}; }
    pub(in crate::driver) fn set(f: impl Fn(u64, bool) -> io::Result<()> + 'static) {
        HOOK.with_borrow_mut(|h| *h = Some(Box::new(f)));
    }
    pub(super) fn before(id: u64, writer: bool) -> io::Result<()> {
        HOOK.with_borrow(|h| h.as_ref().map_or(Ok(()), |f| f(id, writer)))
    }
}

/// An unstarted half remains the installer's responsibility until its thread exists.
struct ThreadInstall<'a> {
    shared: &'a Arc<Shared<Blocking>>,
    id: PipeId,
    closer: Option<&'a Arc<Closer>>,
    reader: bool,
    writer: bool,
}

impl<'a> ThreadInstall<'a> {
    fn reserve(
        shared: &'a Arc<Shared<Blocking>>,
        id: u64,
        closer: Option<&'a Arc<Closer>>,
        reader: bool,
        writer: bool,
    ) -> io::Result<Self> {
        let mut st = shared.lock();
        if st.core.state() >= CoreState::Closing
            || matches!(st.core.pipe_joined(PipeId(id)), Some(Err(_)))
        {
            drop(st);
            if let Some(c) = closer {
                crate::proto::decision::host(|| c(Shutdown::Both));
            }
            return Err(io::ErrorKind::NotConnected.into());
        }
        if let Some(c) = closer {
            st.io
                .add_threads(id, c, usize::from(reader) + usize::from(writer));
        }
        st.io.writers_alive += usize::from(writer);
        Ok(Self {
            shared,
            id: PipeId(id),
            closer,
            reader,
            writer,
        })
    }
}

impl Drop for ThreadInstall<'_> {
    fn drop(&mut self) {
        if !self.reader && !self.writer {
            return;
        }
        {
            let mut st = self.shared.lock();
            st.io.writers_alive -= usize::from(self.writer);
            for _ in 0..usize::from(self.reader) + usize::from(self.writer) {
                st.thread_done(self.id);
            }
        }
        if let Some(close) = self.closer {
            crate::proto::decision::host(|| close(Shutdown::Both));
        }
    }
}

/// Starts the threads of a pipe's halves. Added pipes (`id` > 0) belong to
/// a multipath session.
pub(crate) fn spawn_pipe(shared: &Arc<Shared<Blocking>>, id: u64, pipe: PipeIo) -> io::Result<()> {
    spawn_registered(shared, id, pipe, || {})
}

fn spawn_registered(
    shared: &Arc<Shared<Blocking>>,
    id: u64,
    pipe: PipeIo,
    registered: impl FnOnce(),
) -> io::Result<()> {
    if let Some(attachment) = &pipe.attachment {
        let mut st = shared.lock();
        if st.core.config().accounting.enabled {
            st.enable_pipe_accounting(attachment, PipeId(id), pipe.record_sources())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        }
    }
    let PipeIo {
        exporter,
        reader,
        writer,
        closer,
        framing,
        abort,
        socket,
        unsent,
        low_water,
        attachment,
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
    };
    let closer: Option<Arc<Closer>> = closer.map(Arc::new);
    #[cfg(test)]
    install_test::before(id, false)?;
    let mut install = ThreadInstall::reserve(
        shared,
        id,
        closer.as_ref(),
        reader.is_some(),
        writer.is_some(),
    )?;
    // Bootstrap transfers stop responsibility after registration but before
    // the first protocol write. A concurrently closing session owns its flush.
    registered();
    if let Some(r) = reader {
        let s = shared.clone();
        let lease = attachment.clone();
        let late_exporter = exporter.filter(|_| id == 0);
        let spawned = thread::Builder::new()
            .name("zmux-read".into())
            .spawn(move || {
                let _lease = lease;
                reader_thread(&s, PipeId(id), r, framing, late_exporter);
            });
        spawned?;
        install.reader = false;
    }
    if let Some(w) = writer {
        let s = shared.clone();
        let c = closer.clone();
        {
            let mut st = shared.lock();
            // Before the pipe's first write.
            st.core.set_pipe_low_water(PipeId(id), low_water);
        }
        #[cfg(test)]
        install_test::before(id, true)?;
        let spawned = thread::Builder::new()
            .name("zmux-write".into())
            .spawn(move || {
                let _lease = attachment;
                writer_thread(&s, PipeId(id), w, c, abort, framing, queries);
            });
        spawned?;
        install.writer = false;
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

pub(super) fn wait_in_domain<T>(
    clock: &ClockDomain,
    deadline: Option<Instant>,
    operation: impl Future<Output = T>,
) -> Option<T> {
    if let Some(wait) = deadline.and_then(|at| clock.wait_until(at)) {
        run(super::deadline::race(wait, operation), None).flatten()
    } else {
        run(operation, deadline)
    }
}

/// A session-wide wait (its result is not an error of its own).
pub(super) fn wait_for<T>(
    timeout: Option<Duration>,
    fut: impl Future<Output = T>,
) -> Result<T, WaitError<SessionError>> {
    call_timeout(timeout, async { Ok(fut.await) })
}

fn read_message(reader: &mut Reader) -> io::Result<Option<crate::proto::ReceivedRecord>> {
    if let Reader::Sealed(reader) = reader {
        return reader.read_record();
    }
    let mut buffer = crate::proto::receive::ReceiveBuffer::take(super::MESSAGE_READ);
    let n = match reader.read(&mut buffer.space()[..super::MESSAGE_READ]) {
        Ok(0) => return Ok(None),
        Ok(n) => n,
        Err(e) if super::is_empty_message(&e) => 0,
        Err(e) => return Err(e),
    };
    Ok(Some(buffer.publish(0..n)))
}

fn reader_thread(
    shared: &Arc<Shared<Blocking>>,
    id: PipeId,
    mut reader: Reader,
    framing: Framing,
    mut late_exporter: Option<crate::proto::exporter::CarrierExporter>,
) {
    let _driver = DriverThread::enter();
    let clock = shared.lock().core.config().clock_domain.clone();
    let clock_now = || clock.now_with(Instant::now);
    let mut buf: Option<bytes::BytesMut> = None;
    let mut small = [0u8; IDLE_READ];
    let mut filled = 0;
    loop {
        let started = clock_now();
        let (result, record) = if framing == Framing::Records {
            match read_message(&mut reader) {
                Ok(Some(record)) => (Ok(record.as_ref().len()), Some(record)),
                Ok(None) => (Ok(0), None),
                Err(e) => (Err(e), None),
            }
        } else if let Some(b) = &mut buf {
            (reader.read(&mut b[filled..]), None)
        } else {
            (reader.read(&mut small), None)
        };
        // Pipe 0's exporter, with its first bytes: without the lock (it is
        // the host's code), for the core to have before the peer's
        // parameters.
        let exporter_value = match &result {
            Ok(1..) => late_exporter.take().and_then(|e| e.session_value()),
            _ => None,
        };
        let mut st = shared.lock();
        let now = clock_now();
        if let Some(v) = exporter_value {
            st.core.set_bootstrap_exporter_value(v);
        }
        if st.take_close(id, PipeHalf::Inbound).is_some() {
            st.after_command();
            st.thread_done(id);
            break;
        }
        let done = match (record, result) {
            (Some(record), _) => {
                st.core.receive_message(id, record, now);
                st.core.state() == CoreState::Closed
            }
            (None, Ok(0)) => {
                st.core.pipe_ended(id, PipeEnd::Eof, now);
                true
            }
            (None, Ok(n)) => {
                if let Some(b) = &mut buf {
                    filled += n;
                    let used = st.core.receive_in_place(id, &b[..filled], now);
                    if used > 0 {
                        b.copy_within(used..filled, 0);
                        filled -= used;
                    }
                } else {
                    let used = st.core.receive_in_place(id, &small[..n], now);
                    if used < n || n == small.len() {
                        let mut b = super::read_pool::take_initialized();
                        filled = n - used;
                        b[..filled].copy_from_slice(&small[used..n]);
                        buf = Some(b);
                    }
                }
                st.core.state() == CoreState::Closed
            }
            (None, Err(e)) if e.kind() == io::ErrorKind::Interrupted => false,
            (None, Err(e)) => {
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
            super::read_pool::give(b, super::READ_BUFFER);
        }
    }
    // The pipe's buffer serves the next reads of any pipe.
    if let Some(b) = buf {
        super::read_pool::give(b, super::READ_BUFFER);
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
    let clock = shared.lock().core.config().clock_domain.clone();
    let clock_now = || clock.now_with(Instant::now);
    let me = thread_waker();
    let mut ticket = None;
    let mut memory_wait = None;
    let mut out = Outbound::new(framing, Calls::Blocking);
    let mut progress = Progress::default();
    // The write call in progress: its start and size.
    let mut call = (clock_now(), 0);
    let mut pick = PickRequest::default();
    loop {
        // The carrier is queried without the lock, fed to the core under
        // it, and its low-water mark set after it (`Probe`).
        queries.query(clock_now());
        let mut st = shared.lock();
        queries.feed(&mut st.core, id, clock_now());
        let ready = loop {
            if let Some(abortive) = st.take_close(id, PipeHalf::Outbound) {
                break Err(abortive);
            }
            if st.core.state() == CoreState::Closed {
                break Err(false);
            }
            // Reads run on their own thread: no input is pending here, and
            // batches stay full.
            let now = clock_now();
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
            if st.core.wake_memory_writers() {
                st.dispatch();
            }
            if st.core.watch_receive_budget(&mut memory_wait, &me) {
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
            out.call_limit(false, clock_now(), |left| {
                let st = shared.lock();
                (
                    st.core.write_call_limit(id, left, true, false, clock_now()),
                    st.core.latency_budget(),
                )
            })
        });
        let mut st = shared.lock();
        let now = clock_now();
        // A blocking adapter's call returns once the bytes are handed on:
        // the carrier holds none of them unsent.
        progress.returned(call.0, now, call.1 - out.left(), false);
        if result.is_err() {
            out.clear();
        }
        out.tell(&mut st.core, id, now);
        let _ = progress.report(&mut st.core, id, false, now);
        if let Err(e) = &result {
            st.core.write_failed(id, e.kind(), clock_now());
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
            break;
        }
    }
    // The pipe is done: end the carrier half so its reader thread returns
    // once the session ended.
    drop(writer);
    let session_closed = {
        let mut st = shared.lock();
        if out.cancel(&mut st.core, id, clock_now()) {
            st.after_command();
        }
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
    let mut injected = None;
    move |me| {
        let deadline = match draining {
            Some(d) => d,
            None => match fire_timers(&shared, me, &mut injected) {
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
fn fire_timers(
    shared: &Arc<Shared<Blocking>>,
    me: &Waker,
    injected: &mut Option<(Instant, crate::proto::session::ClockWait)>,
) -> Option<Next> {
    loop {
        let mut st = shared.lock();
        let now = st.now();
        if engine::fire_timers(&mut st.core, now) {
            st.after_command();
        }
        // The listener's account: the charge, allowance, pressure and
        // suspended limit (`super::account`); suspended sessions it asks to
        // close are closed after the lock.
        let mut closing = super::account::Evictions::new();
        {
            let s = &mut *st;
            if let Some(link) = s.io.account.as_mut() {
                link.report(&mut s.core, shared, &mut closing);
            }
        }
        if !closing.is_empty() {
            drop(st);
            for s in closing.take() {
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
            return None;
        }
        let until = engine::timer_deadline(st.core.poll_timeout(), now);
        st.io.timer = Some((me.clone(), until));
        let clock = st.core.config().clock_domain.clone();
        drop(st);
        let Some(at) = until else {
            *injected = None;
            return Some(Next::Idle);
        };
        if injected
            .as_ref()
            .is_none_or(|(previous, _)| *previous != at)
        {
            *injected = clock.wait_until(at).map(|wait| (at, wait));
        }
        let Some((_, wait)) = injected else {
            return Some(Next::At(at));
        };
        if wait
            .as_mut()
            .poll(&mut Context::from_waker(me))
            .is_pending()
        {
            return Some(Next::Idle);
        }
        *injected = None;
    }
}

// ---- the application's calls ------------------------------------------------------------

impl Session {
    /// Establishes a session as the dialling side of `pipe`.
    pub fn connect(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
    ) -> Result<Session, WaitError<ConnectError>> {
        Self::start(
            &mut Some(pipe),
            config,
            Role::Client,
            Some(Role::Client),
            None,
            None,
            |_| {},
        )
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
        super::check_accept(&config).map_err(WaitError::Failed)?;
        Self::start(
            &mut Some(pipe),
            config,
            Role::Server,
            Some(Role::Server),
            None,
            None,
            |_| {},
        )
    }

    /// Establishes a session over a symmetric carrier (`zmux_role` auto).
    pub fn peer(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
    ) -> Result<Session, WaitError<ConnectError>> {
        let config = config.into();
        super::check_peer(&config)?;
        Self::start(
            &mut Some(pipe),
            config,
            Role::Auto,
            None,
            None,
            None,
            |_| {},
        )
        .map(Self::redialing)
    }

    /// Starts the redial hook of a dialling session's configuration.
    fn redialing(self) -> Self {
        let config = self.shared().lock().core.config().clone();
        if let Some(hook) = config
            .redial
            .as_ref()
            .filter(|hook| hook.as_blocking().is_some())
            && self.multipath() == crate::Multipath::InUse
            && let Some(pipe0) = self.pipe(PipeId(0))
        {
            Redialer::spawn(&self, hook.clone(), config.redial_backoff, pipe0);
        }
        self
    }

    /// A session a listener accepts: `register` publishes it before its first byte.
    pub(crate) fn listened(
        pipe: &mut Option<PipeIo>,
        config: Arc<Config>,
        locator: Option<&[u8]>,
        listener_budget: Option<Arc<crate::proto::memory::Ledger>>,
        register: impl FnOnce(&Arc<Shared<Blocking>>),
    ) -> Result<Session, WaitError<ConnectError>> {
        Self::start(
            pipe,
            config,
            Role::Server,
            Some(Role::Server),
            locator,
            listener_budget,
            register,
        )
    }

    fn start(
        pending: &mut Option<PipeIo>,
        config: impl Into<Arc<Config>>,
        role: Role,
        transport: Option<Role>,
        locator: Option<&[u8]>,
        listener_budget: Option<Arc<crate::proto::memory::Ledger>>,
        register: impl FnOnce(&Arc<Shared<Blocking>>),
    ) -> Result<Session, WaitError<ConnectError>> {
        // Before anything is spawned: nothing to release.
        if on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        let shared = Self::prepare(
            pending,
            config.into(),
            role,
            transport,
            locator,
            listener_budget,
            register,
        )?;
        call(shared.established())
    }

    fn prepare(
        pending: &mut Option<PipeIo>,
        config: Arc<Config>,
        role: Role,
        transport: Option<Role>,
        locator: Option<&[u8]>,
        listener_budget: Option<Arc<crate::proto::memory::Ledger>>,
        register: impl FnOnce(&Arc<Shared<Blocking>>),
    ) -> Result<Arc<Shared<Blocking>>, ConnectError> {
        let pipe = pending.as_mut().expect("bootstrap carrier owned by setup");
        let clock = &config.clock_domain;
        pipe.resolve_exporter(
            clock,
            clock
                .now_with(Blocking::now)
                .checked_add(config.handshake_wait()),
        );
        pipe.register_carrier_stats();
        let carrier = Blocking::carrier_info(pipe);
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
            State::new(
                config,
                role,
                transport,
                locator,
                carrier,
                io,
                listener_budget,
            )?,
            (),
        ));
        let pipe = pending.take().expect("admitted bootstrap carrier");
        session_timer::spawn(timer_task(shared.clone()))
            .map_err(|e| ConnectError::Io(Arc::new(e)))?;
        if let Err(error) = spawn_registered(&shared, 0, pipe, || register(&shared)) {
            shared.abandon();
            return Err(ConnectError::Io(Arc::new(error)));
        }
        Ok(shared)
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

    /// Waits for the capacity watermark to change.
    ///
    /// # Errors
    ///
    /// Returns an error if called from a driver thread.
    pub fn capacity_changed(
        &self,
        observed: u64,
    ) -> Result<crate::CapacitySnapshot, WaitError<std::convert::Infallible>> {
        if on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        run(self.capacity_changed_op(observed), None).ok_or(WaitError::TimedOut)
    }

    /// Runs a raw Join for protocol fixtures until the peer confirms it.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "matches the asynchronous fixture"
    )]
    pub fn test_join(&self, pipe: PipeIo, opts: PipeOptions) -> Result<Pipe, WaitError<PipeError>> {
        if on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        let deadline = self.join_deadline();
        if let Some(exporter) = pipe.exporter_ref().filter(|e| !e.is_resolved()) {
            let _ = run(
                super::setup::while_open(
                    handle::session_ended_wait(self.shared()),
                    exporter.resolve(),
                ),
                deadline.map(crate::proto::session::JoinDeadline::at),
            );
        }
        let pipe = self.start_join_inner(pipe, &opts, deadline, None)?;
        let guard = handle::AbortUnlessAdded(Some(&pipe));
        run(pipe.attached_op(), None).ok_or(WaitError::TimedOut)??;
        guard.added();
        Ok(pipe)
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
    /// kept as they are. Any opener that is still executing releases its carrier when it returns.
    /// A dial or Join failure ends the call with its error. While the previous epoch is still kept, the next exchange waits until it is
    /// deleted, so a short timeout may end the call before any pipe is replaced. An epoch
    /// is kept for [`EPOCH_RETENTION`](crate::proto::session::EPOCH_RETENTION) (3 min)
    /// after this end switched away from it: called within that time after an exchange
    /// that completed, for example one [`advance_epoch`](Session::advance_epoch) started
    /// under [`EpochPolicy::MANUAL`](crate::EpochPolicy::MANUAL), it waits that long
    /// before its own exchange, by design. One called while an exchange is in progress
    /// takes that exchange's epoch as the new one.
    pub fn replace_pipes_timeout(&self, timeout: Duration) -> Result<(), WaitError<PipeError>> {
        let clock = self.clock_domain();
        self.replace_pipes_until(clock.now_with(Instant::now).checked_add(timeout))
    }

    fn replace_pipes_until(&self, deadline: Option<Instant>) -> Result<(), WaitError<PipeError>> {
        if on_driver_thread() {
            return Err(WaitError::OnDriverThread);
        }
        let clock = self.clock_domain();
        let redial = self.shared().lock().core.config().redial.clone();
        let Some((hook, dial)) = redial.as_ref().and_then(|h| Some((h, h.as_blocking()?))) else {
            return Err(WaitError::Failed(PipeError::InvalidOptions(
                crate::InvalidConfig::new("redial", "replace_pipes needs a blocking redial hook"),
            )));
        };
        let (old, before) = self.begin_replace_pipes()?;
        wait_in_domain(&clock, deadline, self.epoch_in_use_op(before))
            .ok_or(WaitError::TimedOut)??;
        for pipe in old {
            // Gone meanwhile: nothing to replace.
            let Some((direction, opts)) = handle::replacement(&pipe) else {
                continue;
            };
            if deadline.is_some_and(|d| clock.now_with(Instant::now) >= d) {
                return Err(WaitError::TimedOut);
            }
            let member = self.shared().lock().core.member_for_pipe(pipe.id());
            let change = self
                .single_member_change(opts, deadline, member)
                .map_err(change_error)?;
            let mut report =
                self.shared()
                    .begin_redial(hook, direction, crate::RedialCause::ReplacePipes);
            let request = report.request();
            let dial = dial.clone();
            let attempt = change
                .start_member(
                    0,
                    CarrierOpener::blocking(move |_| {
                        redial_carrier(&dial, request.clone()).map(|pipe| vec![pipe])
                    }),
                )
                .map_err(change_error)?;
            let result =
                wait_in_domain(&clock, deadline, attempt.wait()).ok_or(WaitError::TimedOut)?;
            if let Some(&id) = result.pipes.first() {
                report.set_pipe(id);
            }
            if result.reason != crate::AttemptReason::Confirmed {
                let error = attempt_error(&result);
                report.complete(Err(error.clone()));
                if result.reason == crate::AttemptReason::Deadline && deadline.is_some() {
                    return Err(WaitError::TimedOut);
                }
                return Err(error.into());
            }
            if let Some(joined) = result.pipes.first().and_then(|&id| self.pipe(id)) {
                pipe.record_replacement(&joined);
            }
            loop {
                let observed = self.capacity().observed;
                match change.commit() {
                    Ok(_) => break,
                    Err(crate::ChangeError::Unstable) => {
                        wait_in_domain(&clock, deadline, self.capacity_changed_op(observed))
                            .ok_or(WaitError::TimedOut)?;
                    }
                    Err(error) => return Err(change_error(error).into()),
                }
            }
            report.complete(Ok(()));
        }
        Ok(())
    }

    /// Closes gracefully and waits for the close to be handed to the usable
    /// carriers or for the hand-off deadline. Returns `Ok` for the requested
    /// close, otherwise the error that ended it first. On a
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

    /// Starts buffering health transitions for the session's event reader.
    ///
    /// Reading the first event starts this subscription as well. Read
    /// current pipe health when starting or after a sequence gap.
    pub fn subscribe_pipe_health(&self) {
        self.observe_pipe_health_events();
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
    pub fn write_chunk(&mut self, data: crate::Chunk) -> Result<(), WaitError<StreamError>> {
        call_timeout(self.timeout, self.write_chunk_op(data))
    }

    /// Writes as many of `bufs` as the buffers take without copying them;
    /// a chunk taken in part is advanced. Waits until something is written.
    pub fn write_chunks(
        &mut self,
        bufs: &mut [crate::Chunk],
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
    pub fn read_chunk(
        &mut self,
        max: usize,
    ) -> Result<Option<crate::Chunk>, WaitError<StreamError>> {
        call_timeout(self.timeout, self.read_chunk_op(max))
    }

    /// Fills as many of `bufs` as data is available for, without copying;
    /// returns how many were filled, or `None` at the end of the stream.
    pub fn read_chunks(
        &mut self,
        bufs: &mut [crate::Chunk],
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

#[cfg(test)]
mod tests {
    use super::PipeIo;

    #[test]
    fn setup_and_driver_share_one_full_shutdown() {
        use std::net::Shutdown;
        use std::sync::{Arc, Mutex};
        let calls = Arc::new(Mutex::new(Vec::new()));
        let host = calls.clone();
        let mut pipe = PipeIo::reader(std::io::empty()).with_closer(move |how| {
            host.lock().unwrap().push(how);
        });
        let setup = pipe.shared_closer().unwrap();
        let driver = pipe.closer.take().unwrap();
        driver(Shutdown::Write);
        setup(Shutdown::Both);
        driver(Shutdown::Both);
        assert_eq!(*calls.lock().unwrap(), [Shutdown::Write, Shutdown::Both]);
    }

    #[cfg(windows)]
    #[test]
    fn tcp_closer_interrupts_a_pending_receive_on_the_original_handle() {
        use std::net::{Shutdown, TcpListener, TcpStream};
        use std::os::windows::io::AsRawSocket;
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        use windows_sys::Win32::Networking::WinSock::{
            SOCKET_ERROR, WSA_INVALID_EVENT, WSA_IO_PENDING, WSA_OPERATION_ABORTED, WSABUF,
            WSACloseEvent, WSACreateEvent, WSAGetLastError, WSAGetOverlappedResult, WSARecv,
        };
        use windows_sys::Win32::System::IO::OVERLAPPED;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = Arc::new(TcpStream::connect(listener.local_addr().unwrap()).unwrap());
        let (peer, _) = listener.accept().unwrap();
        let closer = PipeIo::tcp_closer(socket.clone());
        let (started, pending) = mpsc::channel();
        let (finished, completion) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let id = usize::try_from(socket.as_raw_socket()).unwrap();
            let mut byte = 0;
            let buffer = WSABUF {
                len: 1,
                buf: &raw mut byte,
            };
            let (mut bytes, mut flags) = (0, 0);
            // SAFETY: The socket, event and operation storage stay live until
            // WSAGetOverlappedResult has waited for the pending receive.
            #[allow(unsafe_code)]
            let error = unsafe {
                let event = WSACreateEvent();
                assert_ne!(event, WSA_INVALID_EVENT);
                let mut op = OVERLAPPED {
                    hEvent: event as _,
                    ..OVERLAPPED::default()
                };
                let result = WSARecv(
                    id,
                    &raw const buffer,
                    1,
                    std::ptr::null_mut(),
                    &raw mut flags,
                    &raw mut op,
                    None,
                );
                if result != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING {
                    WSACloseEvent(event);
                    panic!("WSARecv did not pend");
                }
                let _ = started.send(());
                let result =
                    WSAGetOverlappedResult(id, &raw const op, &raw mut bytes, 1, &raw mut flags);
                let error = if result == 0 { WSAGetLastError() } else { 0 };
                WSACloseEvent(event);
                error
            };
            let _ = finished.send((error, bytes));
        });
        pending.recv_timeout(Duration::from_secs(5)).unwrap();
        closer(Shutdown::Both);
        let (error, bytes) = completion.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            error == WSA_OPERATION_ABORTED || (error == 0 && bytes == 0),
            "{error}, {bytes}"
        );
        worker.join().unwrap();
        drop(peer);
    }

    /// A split carrier reports its own failure only if both halves do: a
    /// half that does not can stall silently, so stall death stays on.
    #[test]
    fn split_halves_report_failure_only_together() {
        for (up, down) in [(false, false), (true, false), (false, true), (true, true)] {
            let up_half = PipeIo::writer(std::io::sink()).with_reports_failure(up);
            let down_half = PipeIo::reader(std::io::empty()).with_reports_failure(down);
            assert_eq!(
                PipeIo::paired_join(up_half, down_half).reports_failure(),
                up && down
            );
        }
    }
}
