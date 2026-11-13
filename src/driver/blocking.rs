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
/// code 0.
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
        let mut st = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
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
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                }
                None => self.0.changed.wait(st).unwrap_or_else(|e| e.into_inner()),
            };
        }
    }

    fn shut(&self) {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner()).0 = true;
        self.0.changed.notify_all();
    }

    fn limit(&self, timeout: Duration) {
        let mut st = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
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
    exporter: Option<crate::CarrierExporter>,
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
    pub fn handshake_framing(&self) -> Framing {
        self.framing
    }

    /// Reads once from the carrier for a transform's handshake, appending to `into`: one
    /// message on a message carrier; 0 is its end.
    pub fn read_handshake(&mut self, into: &mut Vec<u8>) -> io::Result<usize> {
        let r = self
            .reader
            .as_mut()
            .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let at = into.len();
        into.resize(at + core_join_chunk(), 0);
        let got = r.read(&mut into[at..]);
        into.truncate(at + *got.as_ref().unwrap_or(&0));
        got
    }

    /// Writes one handshake unit in one write.
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
                framing,
                opener,
                buf: vec![0; u16::MAX as usize + 1].into_boxed_slice(),
                failed: false,
            }) as Box<dyn Read + Send>
        });
        self.writer = self.writer.take().map(|lower| {
            Box::new(SealedWrite {
                lower,
                framing,
                sealer,
                unit: Vec::new(),
            }) as Box<dyn Write + Send>
        });
        let overhead = 16 + if framing == Framing::ByteStream { 2 } else { 0 };
        self.write_overhead = self.write_overhead.saturating_add(overhead);
        self.framing = Framing::Records;
        self.max_record = Some(u16::MAX as usize - 16);
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
    pub fn watchdog(&mut self, timeout: Duration) -> Option<Watchdog> {
        Some(Watchdog::new(self.shared_closer()?, timeout))
    }

    /// What a handshake's waits on this carrier end with.
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

    pub(crate) fn exporter_ref(&self) -> Option<&crate::CarrierExporter> {
        self.exporter.as_ref()
    }

    pub(crate) fn admitted_value(&self) -> Option<&crate::AdmittedValue> {
        self.admitted.as_ref()
    }

    pub(crate) fn overhead(&self) -> u16 {
        self.write_overhead
    }

    /// The carrier's write overhead ([`PipeIo::with_write_overhead`]).
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
    /// rate as for `zmux::PipeIo::tcp`.
    pub fn tcp(stream: TcpStream) -> Self {
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
    /// ([`PipeIo::tcp`]) have one.
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
    /// bytes of the write call in progress, its Q_p. [`PipeIo::tcp`]
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
    /// [`PipeIo::tcp`] installs the socket's query where the platform has
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
        self.exporter = Some(crate::CarrierExporter::new(export));
        self
    }

    /// The application protocol the carrier negotiated (for example the
    /// ALPN identifier), reported by `Session::protocol`.
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// The host's short label of the transform the carrier runs (the
    /// label a [`crate::Candidate`] or an admission gives; about 32 bytes at
    /// most). zmux only reports it: in pipe statistics and events, to the
    /// shaper factory and in the [`crate::CarrierCache`] keys.
    #[must_use]
    pub fn with_variant(mut self, variant: impl Into<Arc<str>>) -> Self {
        self.variant = Some(variant.into());
        self
    }

    /// The carrier's variant ([`PipeIo::with_variant`]).
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
///     Ok(zmux::blocking::PipeIo::tcp(std::net::TcpStream::connect("127.0.0.1:4433")?))
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

    fn wake_driver(state: &mut State<Self>) {
        state.wake_timer();
    }

    /// The writer threads have ended: the last of what goes out on the
    /// carriers is written or given up (each ends at most
    /// [`engine::FINAL_WRITE`] after CLOSED). A reader thread may stay in a
    /// read of a carrier without a socket to shut down until the carrier
    /// ends; it delivers nothing more.
    fn released(state: &State<Self>) -> bool {
        state.io.writers_alive == 0
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
            shared.lock().io.closers.push(PipeThreads {
                id,
                closer: c.clone(),
                threads: 1,
            });
            let c = c.clone();
            carrier.closer = Some(Box::new(move |how| c(how)));
        }
        let s = shared.clone();
        thread::Builder::new()
            .name("zmux-join".into())
            .spawn(move || join_thread(s, PipeId(id), carrier, closer.is_some()))
            .map(drop)
            .map_err(|e| PipeError::Io(std::sync::Arc::new(e)))
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

/// The redial hook of a blocking session ([`Config::blocking_redial`]): one member,
/// replaced when it fails, and make before break when its
/// [`replace_by`](crate::PipeStats::replace_by) passes, on a thread that holds no handle of the session between its
/// looks and ends with it. The tokio driver's pool of one member does the same.
struct Redial {
    session: handle::WeakSession<Blocking>,
    dial: Dial,
    backoff: crate::helpers::Backoff,
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

impl Redial {
    fn spawn(session: &Session, dial: Dial, backoff: crate::helpers::Backoff, pipe0: Pipe) {
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
            if self.member.is_none() && session.join_ready() && due.is_some_and(|t| now >= t) {
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
            Err(e) => Err(PipeError::Io(std::sync::Arc::new(e))),
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
            // `wait` may resolve now.
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

/// Starts the threads of a pipe's halves. Added pipes (`id` > 0) belong to
/// a multipath session.
/// How often a deferred join asks again.
const JOIN_HOLD_POLL: Duration = Duration::from_millis(50);

/// Runs the joiner's handshake, then the pipe's threads.
fn join_thread(shared: Arc<Shared<Blocking>>, id: PipeId, mut pipe: PipeIo, closer: bool) {
    let _driver = DriverThread::enter();
    let done = |shared: &Arc<Shared<Blocking>>, failed: bool| {
        let mut st = shared.lock();
        if failed {
            st.core
                .join_carrier_failed(id, io::ErrorKind::UnexpectedEof, Instant::now());
        }
        if closer {
            st.thread_done(id);
        }
        st.after_command();
    };
    let framing = pipe.framing;
    let (kind, overhead) = (pipe.carrier, pipe.write_overhead);
    let message = loop {
        let r = {
            let mut st = shared.lock();
            let r = st.core.join_prepare(id, Instant::now());
            st.after_command();
            r
        };
        match r {
            Ok(Some(message)) => break message,
            Ok(None) => thread::sleep(JOIN_HOLD_POLL),
            Err(_) => return done(&shared, false),
        }
    };
    let plan = shared.join_plan(kind, message);
    if join_wait(&shared, id, plan.delay) {
        return done(&shared, false);
    }
    let hello = {
        let mut st = shared.lock();
        let r = st
            .core
            .join_hello(id, (framing, overhead), &plan, Instant::now());
        st.after_command();
        r
    };
    let Ok(hello) = hello else {
        return done(&shared, false);
    };
    let (Some(mut r), Some(mut w)) = (pipe.reader.take(), pipe.writer.take()) else {
        return done(&shared, true);
    };
    if w.write_all(&hello).and_then(|()| w.flush()).is_err() {
        return done(&shared, true);
    }
    let mut input = Vec::new();
    let mut want = 1;
    let mut chunk = vec![0; core_join_chunk()];
    loop {
        while input.len() < want {
            match r.read(&mut chunk) {
                Ok(n @ 1..) if input.len() + n <= crate::proto::session::JOIN_READ_BOUND => {
                    input.extend_from_slice(&chunk[..n]);
                }
                _ => return done(&shared, true),
            }
        }
        let step = {
            let mut st = shared.lock();
            let step = st.core.verify_reply(id, &input, Instant::now());
            st.after_command();
            step
        };
        match step {
            crate::proto::session::JoinStep::More { consumed, need } => {
                input.drain(..consumed);
                want = if framing == Framing::Records {
                    input.clear();
                    1
                } else {
                    need.max(input.len() + 1)
                };
            }
            crate::proto::session::JoinStep::Verified { consumed, mode } => {
                let plan = if mode == crate::proto::seal::RecordMode::Bound {
                    crate::shaping::UnitPlan::default()
                } else {
                    let plan = shared.join_plan(kind, "confirm");
                    if join_wait(&shared, id, plan.delay) {
                        return done(&shared, false);
                    }
                    plan
                };
                let finished = {
                    let mut st = shared.lock();
                    let r = st.core.join_finish(id, &plan, Instant::now());
                    st.after_command();
                    r
                };
                let Ok(crate::proto::session::JoinFinished {
                    confirm, records, ..
                }) = finished
                else {
                    return done(&shared, false);
                };
                if !confirm.is_empty() && w.write_all(&confirm).and_then(|()| w.flush()).is_err() {
                    return done(&shared, true);
                }
                input.drain(..consumed);
                let (inbound, outbound) = {
                    let st = shared.lock();
                    st.core.pipe_directions(id)
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
                    if let Some(m) = pipe.max_record {
                        st.core.set_pipe_max_record(id, m);
                    }
                    st.core.set_pipe_write_overhead(id, pipe.write_overhead);
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
                    // No thread takes the carrier: it ends here, as the session's end
                    // would have ended it.
                    if let Some(c) = pipe.closer.take() {
                        c(Shutdown::Both);
                    }
                    return;
                }
                let spawned = spawn_pipe(&shared, id.0, pipe);
                // The join's hold on the closer ends only once the pipe's threads hold
                // it: the session's end, whenever it comes, finds the closer.
                let mut st = shared.lock();
                if spawned.is_err() {
                    st.core
                        .join_carrier_failed(id, io::ErrorKind::BrokenPipe, Instant::now());
                }
                if closer {
                    st.thread_done(id);
                }
                st.after_command();
                return;
            }
            crate::proto::session::JoinStep::Declined | crate::proto::session::JoinStep::Failed => {
                return done(&shared, false);
            }
        }
    }
}

/// Waits out a plan's delay, holding no lock; `true` when the join failed meanwhile.
fn join_wait(shared: &Arc<Shared<Blocking>>, id: PipeId, delay: Duration) -> bool {
    if delay.is_zero() {
        return false;
    }
    let deadline = Instant::now().checked_add(delay);
    run(handle::join_failed_wait(shared, id), deadline).is_some()
}

/// The size of the handshake's reads: a message carrier needs a whole unit to fit.
const fn core_join_chunk() -> usize {
    u16::MAX as usize + 64
}

/// Shuts a carrier down at a deadline, ending calls blocked on it. One thread until dropped.
#[derive(Debug)]
pub struct Watchdog {
    deadline: std::sync::mpsc::Sender<Instant>,
    fired: Arc<std::sync::atomic::AtomicBool>,
}

impl Watchdog {
    pub(crate) fn new(closer: Arc<Closer>, timeout: Duration) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc::{RecvTimeoutError, channel};
        let (deadline, moves) = channel::<Instant>();
        let fired = Arc::new(AtomicBool::new(false));
        let flag = fired.clone();
        let mut at = Instant::now().checked_add(timeout);
        let _ = thread::Builder::new()
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
                            flag.store(true, Ordering::SeqCst);
                            closer(Shutdown::Both);
                            return;
                        }
                    }
                }
            });
        Self { deadline, fired }
    }

    /// Moves the deadline to `timeout` from now.
    pub fn reset(&self, timeout: Duration) {
        if let Some(t) = Instant::now().checked_add(timeout) {
            let _ = self.deadline.send(t);
        }
    }

    /// Whether the deadline passed and the carrier was shut down.
    pub fn fired(&self) -> bool {
        self.fired.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Byte-stream halves as Sealed records, for allocation tests.
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

/// The reading half of a Sealed carrier: one record per read.
struct SealedRead {
    lower: Box<dyn Read + Send>,
    framing: Framing,
    opener: crate::proto::seal::Opener,
    /// The ciphertext of the record being read: allocated once, at the size of the
    /// largest message, and reused for every record.
    buf: Box<[u8]>,
    failed: bool,
}

impl Read for SealedRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::ErrorKind::InvalidData.into());
        }
        loop {
            // The end at a record's boundary reads as the carrier's end (see the tokio
            // reader); inside a record `read_exact` fails.
            let n = if self.framing == Framing::Records {
                match self.lower.read(&mut self.buf)? {
                    0 => return Ok(0),
                    n => n,
                }
            } else {
                let mut head = [0; 2];
                match self.lower.read(&mut head[..1])? {
                    0 => return Ok(0),
                    _ => self.lower.read_exact(&mut head[1..])?,
                }
                let n = usize::from(u16::from_be_bytes(head));
                self.lower.read_exact(&mut self.buf[..n])?;
                n
            };
            let plain = self.opener.open_in_place(&mut self.buf[..n]);
            let Some(plain) = plain.ok().filter(|p| p.len() <= out.len()) else {
                self.failed = true;
                return Err(io::ErrorKind::InvalidData.into());
            };
            // No bytes of a record are not the end of the carrier.
            if !plain.is_empty() {
                out[..plain.len()].copy_from_slice(plain);
                return Ok(plain.len());
            }
        }
    }
}

/// The writing half of a Sealed carrier: each write is one record in one write below.
struct SealedWrite {
    lower: Box<dyn Write + Send>,
    framing: Framing,
    sealer: crate::proto::seal::Sealer,
    /// A record, with its length prefix on a byte stream, reused for every
    /// record.
    unit: Vec<u8>,
}

impl Write for SealedWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            // Nothing to write is no record.
            return Ok(0);
        }
        self.unit.clear();
        if self.framing == Framing::ByteStream {
            self.unit.extend_from_slice(&[0, 0]);
        }
        let pre = self.unit.len();
        self.sealer
            .seal_into(buf, &mut self.unit)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        if pre > 0 {
            let len = u16::try_from(self.unit.len() - pre).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sealed record over 65535 bytes",
                )
            })?;
            self.unit[..pre].copy_from_slice(&len.to_be_bytes());
        }
        let written = self.lower.write_all(&self.unit);
        // A record cut or lost, no record may follow it.
        if let Err(e) = written {
            self.sealer.fail();
            return Err(e);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.lower.flush()
    }
}

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
        shared.lock().io.closers.push(PipeThreads {
            id,
            closer: c.clone(),
            threads,
        });
    }
    if let Some(r) = reader {
        let s = shared.clone();
        let late_exporter = exporter.filter(|_| id == 0);
        let spawned = thread::Builder::new()
            .name("zmux-read".into())
            .spawn(move || reader_thread(s, PipeId(id), r, framing, late_exporter));
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
            .spawn(move || writer_thread(s, PipeId(id), w, c, abort, framing, queries));
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
/// `read_datagram`, `ping`, `shutdown`, `established`, `closing`, `wait`,
/// `next_event`): the session ended, the session's wait timeout expired
/// ([`Session::set_wait_timeout`](crate::blocking::Session#method.set_wait_timeout)), or the call was refused on a thread
/// that drives sessions and the session is unaffected. The tokio driver's
/// futures return the [`SessionError`] alone, since a future is bounded
/// by its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitError {
    /// The session ended.
    SessionLost(SessionError),
    /// A blocking call on a thread that drives sessions (inside a tokio
    /// runtime, or on a session's own threads).
    OnDriverThread,
    /// The wait's timeout expired.
    TimedOut,
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionLost(e) => e.fmt(f),
            Self::OnDriverThread => f.write_str(crate::proto::session::ON_DRIVER_THREAD),
            Self::TimedOut => f.write_str("wait timed out"),
        }
    }
}

impl std::error::Error for WaitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionLost(e) => Some(e),
            Self::OnDriverThread | Self::TimedOut => None,
        }
    }
}

impl From<SessionError> for WaitError {
    fn from(e: SessionError) -> Self {
        Self::SessionLost(e)
    }
}

impl From<WaitError> for io::Error {
    fn from(e: WaitError) -> Self {
        match e {
            WaitError::SessionLost(s) => s.into(),
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

impl Expired for WaitError {
    fn timed_out() -> Self {
        Self::TimedOut
    }
}

impl Refused for OpenError {
    fn on_driver_thread() -> Self {
        Self::OnDriverThread
    }
}

impl Expired for OpenError {
    fn timed_out() -> Self {
        Self::TimedOut
    }
}

impl Refused for DatagramError {
    fn on_driver_thread() -> Self {
        Self::OnDriverThread
    }
}

impl Expired for DatagramError {
    fn timed_out() -> Self {
        Self::TimedOut
    }
}

impl Refused for PipeError {
    fn on_driver_thread() -> Self {
        Self::OnDriverThread
    }
}

impl Expired for PipeError {
    fn timed_out() -> Self {
        Self::TimedOut
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
    mut late_exporter: Option<crate::CarrierExporter>,
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
    shared: Arc<Shared<Blocking>>,
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
        Self::start(pipe, config, Role::Client, Some(Role::Client), None, |_| {})
            .map(Self::redialing)
    }

    /// Establishes a session as the accepting side of `pipe`. Such a
    /// session cannot accept joins: a configuration that offers multipath
    /// is refused ([`ConnectError::InvalidConfig`]).
    pub fn accept(pipe: PipeIo, config: impl Into<Arc<Config>>) -> Result<Session, ConnectError> {
        let config = config.into();
        if config.offers_multipath() {
            return Err(ConnectError::InvalidConfig(crate::InvalidConfig::new(
                "max_pipes",
                "a session accepted without a listener cannot accept joins: multipath needs a Listener",
            )));
        }
        Self::start(pipe, config, Role::Server, Some(Role::Server), None, |_| {})
    }

    /// Establishes a session over a symmetric carrier (`zmux_role` auto).
    pub fn peer(pipe: PipeIo, config: impl Into<Arc<Config>>) -> Result<Session, ConnectError> {
        let config = config.into();
        super::check_peer(&config)?;
        Self::start(pipe, config, Role::Auto, None, None, |_| {}).map(Self::redialing)
    }

    /// Starts the redial hook of a dialling session's configuration.
    fn redialing(self) -> Self {
        let config = self.shared().lock().core.config().clone();
        if let Some(dial) = &config.blocking_redial
            && self.multipath() == crate::Multipath::InUse
            && let Some(pipe0) = self.pipe(PipeId(0))
        {
            let backoff =
                crate::helpers::Backoff::new(config.redial_min_backoff, config.redial_max_backoff)
                    .with_jitter(0.2);
            Redial::spawn(&self, dial.clone(), backoff, pipe0);
        }
        self
    }

    /// A session a listener accepts: `register` publishes it before its first byte.
    pub(crate) fn listened(
        pipe: PipeIo,
        config: Arc<Config>,
        locator: Option<&[u8]>,
        register: impl FnOnce(&Arc<Shared<Blocking>>),
    ) -> Result<Session, ConnectError> {
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
            State::new(config.into(), role, transport, locator, carrier, io)?,
            (),
        ));
        if let Some(m) = pipe.max_record {
            shared.lock().core.set_pipe_max_record(PipeId(0), m);
        }
        register(&shared);
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
        self.bounded(self.open_bi_wait(None))
    }

    /// Opens a bidirectional stream with `preamble`, waiting for stream
    /// credit (see `zmux::Session::open_bi_with`).
    pub fn open_bi_with(&self, preamble: &Preamble) -> Result<(SendStream, RecvStream), OpenError> {
        self.bounded(self.open_bi_wait(Some(preamble)))
    }

    /// Opens a unidirectional stream, waiting for stream credit.
    pub fn open_uni(&self) -> Result<SendStream, OpenError> {
        self.bounded(self.open_uni_wait(None))
    }

    /// Opens a unidirectional stream with `preamble`, waiting for stream
    /// credit.
    pub fn open_uni_with(&self, preamble: &Preamble) -> Result<SendStream, OpenError> {
        self.bounded(self.open_uni_wait(Some(preamble)))
    }

    /// Accepts the next bidirectional stream the peer opened.
    pub fn accept_bi(&self) -> Result<(SendStream, RecvStream), WaitError> {
        self.bounded(async { Ok(self.accept_bi_wait().await?) })
    }

    /// Accepts the next unidirectional stream the peer opened.
    pub fn accept_uni(&self) -> Result<RecvStream, WaitError> {
        self.bounded(async { Ok(self.accept_uni_wait().await?) })
    }

    /// Queues a session datagram, waiting while the queue is full.
    pub fn send_datagram_with_backpressure(&self, data: Bytes) -> Result<(), DatagramError> {
        self.bounded(self.send_datagram_with_backpressure_op(data))
    }

    /// Receives the next session datagram.
    pub fn read_datagram(&self) -> Result<Bytes, WaitError> {
        self.bounded(async { Ok(self.read_datagram_op().await?) })
    }

    /// Closes the session gracefully with an application close of `code`
    /// and `reason` and blocks until CONNECTION_CLOSE has been handed to
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
    /// verified; the handshake timeout (its default without one) bounds the
    /// call (see `zmux::Session::add_pipe`). A pipe not attached by then is
    /// aborted and the call fails with [`PipeError::TimedOut`]; a failed
    /// call leaves no pipe behind. On a thread that drives sessions it
    /// fails at once with [`PipeError::OnDriverThread`], starting nothing;
    /// [`Session::begin_add_pipe`](blocking::Session#method.begin_add_pipe)
    /// starts a join without waiting.
    pub fn add_pipe(&self, pipe: PipeIo, opts: PipeOptions) -> Result<Pipe, PipeError> {
        if on_driver_thread() {
            return Err(PipeError::OnDriverThread);
        }
        let deadline = Instant::now() + self.add_pipe_limit();
        let no_wait = opts.return_on_reply;
        let p = self.begin_add_pipe(pipe, opts)?;
        let guard = handle::AbortUnlessAdded(Some(&p));
        run(p.added_op(no_wait), Some(deadline)).unwrap_or(Err(PipeError::TimedOut))?;
        guard.added();
        Ok(p)
    }

    /// Replaces every pipe after a suspected leak of a session-level secret, within
    /// `timeout`: advances the epoch as
    /// [`advance_epoch`](blocking::Session#method.advance_epoch) does, waits until new
    /// joins use the new epoch, and then replaces each pipe that existed when it was
    /// called, one after another: it dials a carrier of the same direction through the
    /// [`blocking_redial`](Config#structfield.blocking_redial) hook, adds it with the old
    /// pipe's options, and closes the old pipe gracefully once the new one is attached
    /// (make before break).
    ///
    /// Without the `blocking_redial` hook it fails at once with
    /// [`PipeError::InvalidOptions`]; outside a multipath session with
    /// [`PipeError::NotNegotiated`]; on a thread that drives sessions with
    /// [`PipeError::OnDriverThread`]. When `timeout` passes the call fails with
    /// [`PipeError::TimedOut`]: the pipes already replaced stay replaced and the others are
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
    pub fn replace_pipes(&self, timeout: Duration) -> Result<(), PipeError> {
        if on_driver_thread() {
            return Err(PipeError::OnDriverThread);
        }
        let deadline = Instant::now().checked_add(timeout);
        let Some(redial) = self.shared().lock().core.config().blocking_redial.clone() else {
            return Err(PipeError::InvalidOptions(crate::InvalidConfig::new(
                "blocking_redial",
                "replace_pipes needs the redial hook",
            )));
        };
        let (old, before) = self.begin_replace_pipes()?;
        run(self.epoch_in_use_op(before), deadline).ok_or(PipeError::TimedOut)??;
        for pipe in old {
            // Gone meanwhile: nothing to replace.
            let Some((direction, opts)) = handle::replacement(&pipe) else {
                continue;
            };
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Err(PipeError::TimedOut);
            }
            let io = redial
                .dial(super::DialRequest::new(direction))
                .map_err(|e| PipeError::Io(std::sync::Arc::new(e)))?;
            let limit = Instant::now() + self.add_pipe_limit();
            let p = self.begin_add_pipe(io, opts)?;
            let guard = handle::AbortUnlessAdded(Some(&p));
            let until = deadline.map_or(limit, |d| d.min(limit));
            run(p.added_op(false), Some(until)).unwrap_or(Err(PipeError::TimedOut))?;
            guard.added();
            match pipe.close() {
                Ok(()) | Err(PipeError::UnknownPipe) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Closes gracefully and waits until the session ended: `Ok` when it
    /// closed as requested, otherwise the error that ended it first. On a
    /// thread that drives sessions it fails at once and does nothing.
    pub fn shutdown(&self, code: VarInt, reason: &[u8]) -> Result<(), WaitError> {
        self.bounded(async { Ok(self.shutdown_op(code, reason).await?) })
    }

    /// Sends a QX_PING request, or joins the one outstanding, and waits
    /// for the round-trip time it measured; the sample
    /// also updates [`Session::rtt`](blocking::Session#method.rtt) and the statistics. Works with every
    /// peer, plain QMux peers included. On a thread that drives sessions
    /// it fails at once.
    pub fn ping(&self) -> Result<Duration, WaitError> {
        self.bounded(async { Ok(self.ping_op().await?) })
    }

    /// Waits until the peer's parameters arrived (the session is
    /// established: with early data it is usable before), or fails with the
    /// error that ended the session first.
    pub fn established(&self) -> Result<(), WaitError> {
        self.bounded(async { Ok(self.established_op().await?) })
    }

    /// Waits until the session is closing, that is until it began to end,
    /// and returns why; its carriers may still be draining
    /// ([`Session::wait`](blocking::Session#method.wait) waits
    /// for the whole end).
    pub fn closing(&self) -> Result<SessionError, WaitError> {
        self.bounded(async { Ok(self.closing_op().await) })
    }

    /// Waits until the session has ended entirely and returns why: every
    /// pipe's inbound side has ended (the peer read CONNECTION_CLOSE and
    /// ended its side) or the linger timeout passed, and the session's
    /// writer threads are done. Returning before the linger timeout thus
    /// confirms that the peer read the close. The session's wait timeout
    /// ([`Session::set_wait_timeout`](blocking::Session#method.set_wait_timeout))
    /// bounds it as "delivered, or given up after it"; a timeout changes
    /// nothing in the session.
    pub fn wait(&self) -> Result<SessionError, WaitError> {
        self.bounded(async { Ok(self.wait_op().await) })
    }

    /// The next session event; `None` once the session ended and every
    /// event was read.
    pub fn next_event(&self) -> Result<Option<Event>, WaitError> {
        self.bounded(async { Ok(self.next_event_op().await) })
    }

    /// Bounds every wait of the session and of its pipes, from every
    /// handle: the session calls that wait return
    /// [`WaitError::TimedOut`] (or the `TimedOut` variant of their error)
    /// when it expires; `None` (the default) waits as long as it takes. A
    /// zero timeout never waits and works on any thread, also on one that
    /// drives sessions. Streams have their own
    /// (`set_read_timeout`, `set_write_timeout`).
    pub fn set_wait_timeout(&self, timeout: Option<Duration>) {
        self.shared().set_wait_timeout(timeout);
    }

    /// The bound of the session's waits ([`Session::set_wait_timeout`]).
    pub fn wait_timeout(&self) -> Option<Duration> {
        self.shared().wait_timeout()
    }

    /// Runs a wait of the session under its wait timeout.
    fn bounded<T, E: Expired>(&self, fut: impl Future<Output = Result<T, E>>) -> Result<T, E> {
        call_timeout(self.shared().wait_timeout(), fut)
    }
}

impl Pipe {
    /// Waits until the pipe's join is confirmed or failed (see
    /// `zmux::Pipe::joined`), under the session's wait timeout
    /// ([`Session::set_wait_timeout`]; [`PipeError::TimedOut`] when it
    /// expires).
    pub fn joined(&self) -> Result<(), PipeError> {
        call_timeout(self.shared().wait_timeout(), self.joined_op())
    }

    /// Waits until the peer attached the pipe (see `zmux::Pipe::attached`),
    /// under the session's wait timeout.
    pub fn attached(&self) -> Result<(), PipeError> {
        call_timeout(self.shared().wait_timeout(), self.attached_op())
    }

    /// Waits until the pipe ended (see `zmux::Pipe::closed`), under the
    /// session's wait timeout.
    pub fn closed(&self) -> Result<(), PipeError> {
        call_timeout(self.shared().wait_timeout(), self.closed_op())
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
    /// peer's zmux endpoint at most, not its application.
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

    /// Opens the stream now and waits until the opening frame and the data
    /// written so far left for a carrier: the peer sees the stream even
    /// with nothing written, for a protocol whose other side speaks first.
    /// Data written before goes in the opening frame. Before establishment
    /// the frame goes as soon as the stream may open, in early data if
    /// that is in use; while the first flight is held it returns at once
    /// and the frames leave with the flight. The write timeout bounds the
    /// wait.
    pub fn flush(&mut self) -> Result<(), StreamError> {
        let this = &*self;
        call_timeout(
            self.timeout,
            std::future::poll_fn(move |cx| this.poll_flush_stream(cx.waker())),
        )
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
