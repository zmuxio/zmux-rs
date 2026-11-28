//! The tokio driver: one task per session owns the pipes' I/O; the
//! application's handles (`super::handle`) lock the core for one command
//! at a time, and await the shared waiting operations.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Weak};

use super::account::{AccountLink, Evictions};
use super::channel::DatagramChannel;
use super::handle::StreamDatagram;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Sleep;

use super::attachment::Attachment;
use super::engine::{self, Calls, Outbound, Progress};
use super::handle::{self, CarrierInfo, Driver, Lock, Shared, State, Written};
use super::lanes::{CarrierConnId, ConnClaim, LaneOpener, LaneWriter};
use super::resources::{Kind, Live};
use super::stream_pipe::{StreamReader, StreamWriter, claim_carrier, release_carriers, runs_over};
use super::sync::TryMutexGuard;
use super::tcp::{Probe, TcpSocket};
use super::through::{Carrier, Outbox, Polled, ReadPath, WritePath};
use super::unsent::{Unsent, UnsentQuery};
use super::{Event, IDLE_READ, IDLE_RELEASE, MAX_SLICES, READ_BUFFER};
use crate::error::{ConnectError, ReadExactError, ReadToEndError};
use crate::proto::VarInt;
use crate::proto::record::Framing;
use crate::proto::session::{
    Backing, Config, DatagramError, LaneAccept, LaneId, OpenError, PickRequest, PieceCursor,
    PipeEnd, PipeError, PipeHalf, PipeId, Preamble, Role, Segment, SessionError,
    State as CoreState, StreamError,
};

type BoxRead = Pin<Box<dyn AsyncRead + Send>>;
type BoxWrite = Pin<Box<dyn AsyncWrite + Send>>;

/// A carrier's receiving half: any reader, or the receiving part of a
/// stream of another session, read in chunks.
pub(crate) enum Reader {
    Io(BoxRead),
    Stream(StreamReader),
    /// Sealed records over another reader, whose buffer an idle pipe frees.
    Sealed(Pin<Box<super::sealed::SealedRead>>),
}

impl Reader {
    /// Whether the reader holds a buffer with nothing in it.
    fn idle_buffer(&self) -> bool {
        matches!(self, Self::Sealed(r) if r.idle_buffer())
    }

    /// Frees the buffer of an idle pipe's reader, if it holds one with
    /// nothing in it.
    fn release_idle(&mut self) {
        if let Self::Sealed(r) = self {
            r.as_mut().get_mut().release_idle();
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Io(r) => r.as_mut().poll_read(cx, buf),
            Self::Stream(r) => Pin::new(r).poll_read(cx, buf),
            Self::Sealed(r) => r.as_mut().poll_read(cx, buf),
        }
    }
}

/// The sending half of a carrier that takes owned buffers rather than
/// slices, such as a QUIC stream, an HTTP body or a WebSocket sink: the
/// pipe's referenced payloads reach it without copying, and only the bytes
/// the session builds (record and frame headers, small payloads) are
/// copied, once, into shared buffers. A carrier made with
/// [`PipeIo::from_chunk_halves`] or [`Lane::from_chunks`](super::lanes::Lane::from_chunks)
/// is written this way.
///
/// An accepted chunk keeps its backing reservation as long as the carrier
/// holds any view, including while it waits for its peer to acknowledge it.
/// Byte-only carriers can use [`crate::Chunk::into_bytes`] to transfer that
/// ownership to their underlying transport.
pub trait ChunkWrite: Send {
    /// Takes bytes from the front of `chunks` and returns how many: a
    /// buffer taken whole is left empty, and one taken in part is advanced
    /// past what was taken (as quinn's `SendStream::write_chunks` does).
    /// `chunks` is unchanged when the call returns `Pending` or an error.
    ///
    /// After `Pending` the caller either calls again with the same
    /// `chunks` (the same buffers, in the same order, none advanced) or
    /// drops the writer: an implementation may have started sending them
    /// (a frame header written, a write in flight) and continue where it
    /// stopped, so it may rely on that and need not cope with other
    /// buffers in between. zmux keeps to this; a carrier written by
    /// anything else must too.
    ///
    /// On a message-framed carrier ([`PipeIo::records`]) `chunks` is one
    /// message, taken whole or not at all. `Ok(0)` for non-empty `chunks`
    /// means the carrier is closed.
    fn poll_write_chunks(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [crate::Chunk],
    ) -> Poll<io::Result<usize>>;

    /// Whether the pending chunk write has been submitted to the carrier.
    ///
    /// A writer that can submit before reporting acceptance must return true
    /// from submission until it reports the result. zmux can then finish
    /// polling that same write if a Join is cancelled. A writer that is just
    /// waiting for space leaves this false.
    fn has_submitted_write(&self) -> bool {
        false
    }

    /// Whether a message-framed carrier takes the messages of an output
    /// batch in one [`Self::poll_write_message_batch`] call. The default,
    /// `false`, gives it one message per [`Self::poll_write_chunks`] call.
    fn takes_message_batches(&self) -> bool {
        false
    }

    /// Writes `messages` in order, as that many messages, in one write to the
    /// layer below: taken whole, all of them, or none. Returns their bytes;
    /// `messages` are left empty. `messages` is unchanged when the call
    /// returns `Pending` or an error, and an error fails the pipe. It keeps
    /// no buffer it was not given a share of. Only called when
    /// [`Self::takes_message_batches`] says so.
    fn poll_write_message_batch(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        messages: &mut [crate::Chunk],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_chunks(cx, messages)
    }

    /// Flushes what the carrier buffered, as `AsyncWrite::poll_flush`.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Ends the sending half gracefully, as `AsyncWrite::poll_shutdown`.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

/// Owned buffers as one [`bytes::Buf`], for a carrier that sends a write
/// call's buffers as one frame of its own framing (an HTTP/2 or HTTP/3
/// DATA frame) without joining them: small built bytes then travel with
/// the payload that follows them instead of in a frame of their own.
#[derive(Debug, Default, Clone)]
pub struct ChunkBuf {
    chunks: VecDeque<Bytes>,
    len: usize,
}

impl ChunkBuf {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the non-empty buffers of `chunks` (leaving them empty, as a
    /// [`ChunkWrite`] does) and returns their bytes.
    pub fn take_from(&mut self, chunks: &mut [crate::Chunk]) -> usize {
        let mut n = 0;
        for c in chunks.iter_mut().filter(|c| !c.is_empty()) {
            n += c.len();
            self.chunks.push_back(std::mem::take(c).into_bytes());
        }
        self.len += n;
        n
    }

    /// Appends one buffer.
    pub fn push(&mut self, chunk: Bytes) {
        if !chunk.is_empty() {
            self.len += chunk.len();
            self.chunks.push_back(chunk);
        }
    }

    /// The bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether it holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl bytes::Buf for ChunkBuf {
    fn remaining(&self) -> usize {
        self.len
    }

    fn chunk(&self) -> &[u8] {
        self.chunks.front().map_or(&[], |c| c)
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        let mut n = 0;
        for (d, c) in dst.iter_mut().zip(&self.chunks) {
            *d = IoSlice::new(c);
            n += 1;
        }
        n
    }

    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.len, "advance past the end");
        self.len -= cnt;
        while cnt > 0 {
            let Some(front) = self.chunks.front_mut() else {
                return;
            };
            if cnt < front.len() {
                front.advance(cnt);
                return;
            }
            cnt -= front.len();
            self.chunks.pop_front();
        }
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        match self.chunks.front_mut() {
            // Within the first buffer: shared.
            Some(front) if len <= front.len() => {
                let b = front.split_to(len);
                if front.is_empty() {
                    self.chunks.pop_front();
                }
                self.len -= len;
                b
            }
            _ => {
                assert!(len <= self.len, "copy_to_bytes past the end");
                let mut out = BytesMut::with_capacity(len);
                out.put((&mut *self).take(len));
                out.freeze()
            }
        }
    }
}

type BoxChunkWrite = Pin<Box<dyn ChunkWrite>>;

/// A carrier's sending half: any writer, a writer of owned buffers, or the
/// sending part of a stream of another session, written with shared
/// chunks.
pub(crate) enum Writer {
    Io(BoxWrite),
    Chunks(BoxChunkWrite),
    Stream(StreamWriter),
    /// Sealed records over another writer, whose buffer and key an idle
    /// pipe frees.
    Sealed(Pin<Box<super::sealed::SealedWrite>>),
}

impl Writer {
    fn needs_workspace(&self) -> bool {
        matches!(self, Self::Chunks(_) | Self::Sealed(_))
    }

    fn set_workspace(&mut self, workspace: Option<Arc<crate::proto::memory::WriteWorkspace>>) {
        if let Self::Sealed(w) = self {
            w.as_mut().get_mut().set_workspace(workspace);
        }
    }

    /// The writer as an `AsyncWrite` of slices, unless it takes chunks or is
    /// a stream.
    fn io(&mut self) -> Option<Pin<&mut (dyn AsyncWrite + Send)>> {
        match self {
            Self::Io(w) => Some(w.as_mut()),
            Self::Sealed(w) => Some(w.as_mut()),
            Self::Chunks(_) | Self::Stream(_) => None,
        }
    }

    /// Whether the writer holds state an idle pipe frees.
    fn idle_held(&self) -> bool {
        matches!(self, Self::Sealed(w) if w.idle_held())
    }

    /// Frees what an idle pipe's writer holds with nothing pending.
    fn release_idle(&mut self) {
        if let Self::Sealed(w) = self {
            w.as_mut().get_mut().release_idle();
        }
    }

    pub(crate) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Io(w) => w.as_mut().poll_flush(cx),
            Self::Sealed(w) => w.as_mut().poll_flush(cx),
            Self::Chunks(w) => w.as_mut().poll_flush(cx),
            Self::Stream(w) => Pin::new(w).poll_flush(cx),
        }
    }

    pub(crate) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Io(w) => w.as_mut().poll_shutdown(cx),
            Self::Sealed(w) => w.as_mut().poll_shutdown(cx),
            Self::Chunks(w) => w.as_mut().poll_shutdown(cx),
            Self::Stream(w) => Pin::new(w).poll_shutdown(cx),
        }
    }
}

/// The session clock: tokio's, so that a paused runtime clock (the
/// deterministic simulation of the conformance tests) drives the core's
/// timers as it drives the session task's sleep. Without tokio's `test-util`
/// feature this is `Instant::now()`.
pub(crate) fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// A zmux session, driven by a tokio task.
/// Clones share the session; it closes with code 0 when the last session
/// and stream handle is dropped. The methods that wait are `async` and
/// cancel-safe unless their documentation says otherwise.
pub type Session = handle::Session<Tokio>;
/// The sending part of a stream of a tokio session;
/// implements `AsyncWrite`, whose shutdown finishes the stream. Dropping it
/// without `finish` resets the stream with `ZMUX_CANCELLED`.
pub type SendStream = handle::SendStream<Tokio>;
/// The receiving part of a stream of a tokio session;
/// implements `AsyncRead`. Dropping it before the end stops the stream
/// with code 0.
pub type RecvStream = handle::RecvStream<Tokio>;
/// A pipe of a tokio session.
pub type Pipe = handle::Pipe<Tokio>;
/// A cheap reference to a stream of a tokio session: its metadata and its
/// readiness, while its `SendStream` or `RecvStream` is busy elsewhere.
pub type StreamHandle = handle::StreamHandle<Tokio>;
pub use handle::TryRead;

impl Session {
    handle::session_api!(Tokio, PipeIo);
}

handle::session_adapter!(Tokio);

/// Seeds the next sequence under the same lock used by the writers.
#[cfg(feature = "test-hooks")]
pub fn seed_datagram_sequence(session: &Session, next: u64) {
    session.command(|state| state.core.seed_datagram_sequence(next));
}

/// Wraps the adapter's own channel so a peer can observe physical datagrams.
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn tap_datagram_channel(
    mut pipe: PipeIo,
    tap: impl FnOnce(
        Arc<dyn super::channel::DatagramChannel>,
    ) -> Arc<dyn super::channel::DatagramChannel>,
) -> PipeIo {
    if let Some(lanes) = &mut pipe.lanes {
        lanes.channel = lanes.channel.take().map(tap);
    }
    pipe
}

/// Reads the lane-zero wire positions after pending setup acknowledgements.
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn reliable_setup_end(session: &Session, pipes: &[PipeId]) -> Option<Vec<u64>> {
    session.fixture_reliable_setup_end(pipes)
}

/// Installs deterministic ACK-stall input on a settled fixture pipe.
///
/// # Errors
/// The fixture pipe did not settle or has no outbound direction.
#[cfg(feature = "test-hooks")]
pub fn inject_stall_evidence(
    session: &Session,
    pipe: PipeId,
    cost: Duration,
    waiting: bool,
) -> Result<(), &'static str> {
    session.command(|state| {
        let now = state.now();
        state.core.fixture_stall_evidence(pipe, cost, waiting, now)
    })
}

/// Applies the regular timer owner at the fixture clock's current cut.
#[cfg(feature = "test-hooks")]
pub fn fire_session_timers(session: &Session) {
    session.command(|state| {
        let now = state.now();
        state.core.handle_timeout(now);
    });
}

/// Injects carrier backpressure and fires the datagram deadline deterministically.
///
/// # Errors
///
/// Returns an error if a fixture pipe was already blocked or the packet could
/// not be queued.
#[cfg(feature = "test-hooks")]
pub fn expire_blocked_datagram(
    session: &Session,
    pipes: &[PipeId],
) -> Result<(u64, bool), &'static str> {
    use crate::proto::session::{PipeWrite, SessionCore};

    session.command(|state| {
        let now = state.now();
        let core = &mut state.core;
        if pipes.is_empty()
            || pipes
                .iter()
                .any(|&pipe| !core.pipe_info(pipe).is_some_and(|info| info.writable))
        {
            return Err("deadline fixture requires writable pipes before injection");
        }
        let report = |core: &mut SessionCore, at, refused| {
            for &pipe in pipes {
                core.pipe_write(pipe, PipeWrite::returned(at, at, 0, 0, refused), at);
            }
        };
        report(core, now, true);
        let sequence = core.datagram_sequence();
        let drops = core.datagram_stats().drops.deadline;
        let deadline = now + Duration::from_micros(1);
        let queued = core.send_datagram_with(
            Bytes::from_static(&[1]),
            crate::DatagramSendOptions {
                deadline: Some(crate::DatagramDeadline::At(deadline)),
                copies: Some(crate::DatagramCopyPolicy::Single),
                ..crate::DatagramSendOptions::default()
            },
            true,
            now,
        );
        let result = if queued.is_ok() {
            core.handle_timeout(deadline);
            Ok((
                core.datagram_stats().drops.deadline - drops,
                core.datagram_sequence() != sequence,
            ))
        } else {
            Err("deadline fixture did not queue its datagram")
        };
        report(core, deadline, false);
        result
    })
}

impl Pipe {
    handle::pipe_api!(Tokio, PipeIo);
}

impl SendStream {
    handle::sendstream_api!(Tokio, PipeIo);
}

impl RecvStream {
    handle::recvstream_api!(Tokio, PipeIo);
}

/// A carrier for a pipe: a readable half, a writable half, or both. Shutting
/// the writable half down is the graceful end.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent properties of the carrier"
)]
pub struct PipeIo {
    pub(crate) reader: Option<Reader>,
    pub(crate) writer: Option<Writer>,
    pub(crate) framing: Framing,
    pub(crate) abort: Option<Box<dyn FnOnce() + Send>>,
    pub(crate) exporter: Option<crate::proto::exporter::CarrierExporter>,
    /// When the exporter can be read ([`PipeIo::with_early_data_in`]).
    pub(crate) exporter_ready: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    pub(crate) protocol: Option<String>,
    /// The carrier's kind ([`PipeIo::with_carrier`]).
    pub(crate) carrier: Option<crate::CarrierKind>,
    /// The host's label of the transform the carrier runs.
    pub(crate) variant: Option<Arc<str>>,
    /// The handshake this process ran for the carrier.
    pub(crate) tls: Option<TlsStateFn>,
    /// Bytes already read from the carrier (by a listener).
    pub(crate) prefix: Vec<u8>,
    /// The TCP socket under the carrier: its minimum RTT, unsent bytes and
    /// low-water mark ([`Probe`]).
    pub(crate) socket: Option<TcpSocket>,
    /// The carrier's unsent count ([`PipeIo::with_unsent`]).
    pub(crate) unsent: Option<Unsent>,
    carrier_stats: Option<Box<super::carrier_stats::Source>>,
    pub(super) accounting_sources: Option<Box<crate::CarrierHalfSources>>,
    /// The padding of a handshake run on the carrier before this pipe
    /// ([`PipeIo::with_establish_receipts`]).
    pub(crate) establish_receipts: crate::shaping::EstablishReceipts,
    /// The carrier's write overhead ([`PipeIo::with_write_overhead`]).
    pub(crate) write_overhead: u16,
    /// The largest record the carrier takes, beside the peer's `max_record_size`.
    pub(crate) max_record: Option<usize>,
    /// The secure carrier's Bound contract holds
    /// ([`PipeIo::with_carrier_secure`]).
    pub(crate) secure: bool,
    /// Two halves paired as one carrier.
    pub(crate) split: bool,
    /// The carrier reports its own failure ([`PipeIo::with_reports_failure`]).
    pub(crate) reports_failure: bool,
    /// The record mode of an Establish this carrier ran
    /// ([`PipeIo::with_secure_first_pipe`]).
    pub(crate) first_mode: Option<crate::proto::seal::RecordMode>,
    /// Admission evidence held until bootstrap or Join setup.
    pub(crate) admission_evidence: Option<Box<AdmissionEvidence>>,
    /// The carrier has a low-water mark.
    pub(crate) low_water: bool,
    /// A read may return less than the carrier holds although it had
    /// room ([`PipeIo::with_partial_reads`]).
    pub(crate) partial_reads: bool,
    /// The session whose stream is the carrier.
    pub(crate) outer: Option<Weak<Shared<Tokio>>>,
    /// The carrier's lane capability, allocated when it has one.
    pub(crate) lanes: Option<Box<LaneCaps>>,
    /// Memory the carrier's connection holds for the session
    /// ([`PipeIo::with_connection_memory`]).
    pub(crate) conn_memory: u64,
    /// Carrier early data ([`PipeIo::with_early_data`],
    /// [`PipeIo::with_early_data_in`]).
    pub(crate) early: Option<Box<EarlyIo>>,
    /// Called when a listener takes the carrier ([`PipeIo::with_taken`]);
    /// boxed twice to keep the carrier one pointer larger only.
    #[allow(clippy::type_complexity)]
    pub(crate) taken: Option<Box<Box<dyn FnOnce() + Send>>>,
    /// A split bootstrap ([`PipeIo::split_bootstrap`]): its pairing makes
    /// pipe pair 0 only, so it cannot join a session.
    pub(crate) split_bootstrap: bool,
    /// Told the session's close code once the session is done with the
    /// carrier ([`PipeIo::with_close_code`]).
    pub(crate) close_code: Option<TellCloseCode>,
    /// Run after the carrier's graceful end ([`PipeIo::with_drain`]).
    pub(crate) drain: Option<Box<Drain>>,
    pub(crate) attachment: Option<Arc<Attachment>>,
}

/// How long a [`PipeIo::with_drain`] future may run at most when the
/// adapter has no timeout of its own that fits: the upper bound of a
/// session's linger timeout, which waits for the peer's close the same way.
pub const DRAIN_LIMIT: Duration = super::DRAIN_LIMIT;

/// The rounds a session task makes in one poll before it yields to the
/// other tasks of its worker.
const TASK_ROUNDS: u32 = 64;

/// Runs `drain` on the current tokio runtime for at most `limit`: dropped
/// at the limit, or with the runtime when it shuts down earlier; dropped
/// at once outside a runtime. What [`PipeIo::with_drain`] does with its
/// future. A lane uses its own registered drain.
pub fn spawn_drain(drain: impl Future<Output = ()> + Send + 'static, limit: Duration) {
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(async move {
            let _ =
                tokio::time::timeout(limit, crate::proto::decision::host_future(|| drain)).await;
        });
    }
}

/// `dial` within `limit` ([`DIAL_TIMEOUT`](crate::adapter::DIAL_TIMEOUT) by
/// default in the adapters), or a `TimedOut` error: the one bound of an
/// adapter's dial, from its connect to the carrier being ready.
///
/// # Errors
///
/// `dial`'s error, or `TimedOut` when it is not done within `limit`.
pub async fn within<T>(
    limit: Duration,
    dial: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(limit, dial).await.unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the carrier was not ready in time",
        ))
    })
}

type DrainFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A [`PipeIo::with_drain`] future: spawned when dropped once the
/// carrier's sending half ended gracefully (armed), and dropped unrun
/// otherwise. Declared after the carrier's halves, so that it starts once
/// they are gone.
pub(crate) struct Drain {
    future: Option<DrainFuture>,
    limit: Duration,
    armed: bool,
}

impl Drain {
    pub(crate) fn add(
        slot: &mut Option<Box<Self>>,
        future: DrainFuture,
        limit: Duration,
        lease: &Arc<Attachment>,
    ) {
        let worker = lease.worker();
        let next = Self {
            future: Some(Box::pin(async move {
                let _worker = worker;
                future.await;
            })),
            limit,
            armed: false,
        };
        *slot = Some(Box::new(match slot.take() {
            Some(first) => Self::join(*first, next),
            None => next,
        }));
    }

    /// `a` and `b` together, each within its own limit.
    fn join(a: Drain, b: Drain) -> Drain {
        let limit = a.limit.max(b.limit);
        let armed = a.armed || b.armed;
        let mut a = a.take();
        let mut b = b.take();
        Drain {
            future: Some(Box::pin(std::future::poll_fn(move |cx| {
                for f in [&mut a, &mut b] {
                    if f.as_mut().is_some_and(|f| f.as_mut().poll(cx).is_ready()) {
                        *f = None;
                    }
                }
                if a.is_none() && b.is_none() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }))),
            limit,
            armed,
        }
    }

    /// The future bounded by its own limit.
    fn take(mut self) -> Option<DrainFuture> {
        let f = self.future.take()?;
        let limit = self.limit;
        Some(Box::pin(async move {
            let _ = tokio::time::timeout(limit, f).await;
        }))
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        if self.armed
            && let Some(f) = self.future.take()
        {
            spawn_drain(f, self.limit);
        }
    }
}

/// The hook of [`PipeIo::with_close_code`].
pub(crate) type CloseCode = Box<dyn FnOnce(VarInt) + Send>;

/// The application error code a carrier's own close carries for a session
/// that ended with `e`: the code of the `CONNECTION_CLOSE` 0x1d that ended
/// it, sent or received, and 0 for every other end.
fn close_code_of(e: Option<&SessionError>) -> VarInt {
    match e {
        Some(SessionError::ApplicationClosed { code, .. }) => *code,
        _ => VarInt::ZERO,
    }
}

/// A [`PipeIo::with_close_code`] hook, called with its code (dropped
/// uncalled without one) when this is dropped, after the core lock.
pub(crate) struct TellCloseCode(Option<CloseCode>, VarInt);

impl TellCloseCode {
    fn new(f: impl FnOnce(VarInt) + Send + 'static) -> Self {
        Self(Some(Box::new(f)), VarInt::ZERO)
    }
}

impl Drop for TellCloseCode {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            crate::proto::decision::host(|| f(self.1));
        }
    }
}

/// The carrier's early data: a client sending it under remembered
/// parameters until the carrier settles it, or a server receiving it until
/// the handshake completes.
/// A carrier's early data, and its restart hook after a rejection.
#[derive(Default)]
pub(crate) struct EarlyIo {
    pub(crate) io: Option<CarrierEarlyIo>,
    pub(crate) restart: Option<EarlyRestart>,
}

pub(crate) type EarlyRestart =
    Box<dyn FnMut() -> io::Result<Option<crate::CarrierHalfSources>> + Send>;

pub(crate) enum CarrierEarlyIo {
    Out {
        remembered: Box<crate::proto::params::TransportParameters>,
        settled: Pin<Box<dyn Future<Output = bool> + Send>>,
    },
    In {
        done: Pin<Box<dyn Future<Output = ()> + Send>>,
    },
}

/// A carrier that is a stream of a multi-stream connection: the
/// connection's identity, how to open further streams of it as lanes,
/// whether lanes are on (by default where the connection delivers its
/// streams independently), and the connection's datagram channel for the
/// pipe ([`PipeIo::with_datagram_channel`]).
#[derive(Default)]
pub(crate) struct LaneCaps {
    pub(crate) conn: Option<CarrierConnId>,
    pub(crate) opener: Option<LaneOpener>,
    pub(crate) on: Option<bool>,
    pub(crate) channel: Option<Arc<dyn DatagramChannel>>,
}

#[derive(Default)]
pub(crate) struct AdmissionEvidence {
    pub(crate) value: Option<crate::AdmittedValue>,
    pub(crate) bound_prefix: Option<[u8; 16]>,
}

impl PipeIo {
    /// A carrier from a duplex byte stream, such as a TLS stream. A TCP
    /// connection is [`PipeIo::from_tcp`]. Under another layer, such as
    /// TLS, disable Nagle's algorithm on the socket before
    /// (`set_nodelay(true)`): it would hold a record back until the
    /// previous one was acknowledged, merging records that shaping or
    /// pacing spaced out.
    pub fn new<T>(io: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (r, w) = tokio::io::split(io);
        Self::from_halves(r, w)
    }

    /// A TCP carrier, with Nagle's algorithm disabled. The kernel's
    /// minimum RTT (Linux, Windows) feeds receive-window auto-tuning, and the
    /// unsent bytes the kernel
    /// queues are limited by `TCP_NOTSENT_LOWAT` (Linux, Android, Apple
    /// platforms), which follows the send rate: max(128 KiB, rate x
    /// `RTT_min` / 8) on a single pipe, per pipe max(32 KiB, `R_p` x `RTT_min_p`
    /// / 8) in a multipath session, never above the socket's send buffer.
    pub fn from_tcp(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        #[cfg(any(unix, windows))]
        let socket = TcpSocket::new(&stream);
        let (r, w) = stream.into_split();
        let mut io = Self::from_halves(r, w);
        #[cfg(any(unix, windows))]
        {
            io.unsent = socket.as_ref().and_then(TcpSocket::unsent_query);
            io.socket = socket;
        }
        io.init_lowat();
        io
    }

    /// The TCP socket under this carrier (for example under TLS): it is
    /// then queried and tuned like that of a [`PipeIo::from_tcp`] carrier, which
    /// does this itself (its unsent bytes reported as by
    /// [`PipeIo::with_unsent`], unless the carrier has a query of its
    /// own), and, unless the carrier has an abort of its own
    /// ([`PipeIo::with_abort`]), a pipe that zmux fails is aborted by
    /// shutting the socket down, without the graceful end of the layer
    /// above (no TLS `close_notify`). One duplicate of the socket serves
    /// both.
    #[cfg(unix)]
    #[must_use]
    pub fn with_tcp_socket(self, socket: &impl std::os::fd::AsFd) -> Self {
        self.set_tcp_socket(TcpSocket::new(socket))
    }

    /// The TCP socket under this carrier (see the Unix variant).
    #[cfg(windows)]
    #[must_use]
    pub fn with_tcp_socket(self, socket: &impl std::os::windows::io::AsSocket) -> Self {
        self.set_tcp_socket(TcpSocket::new(socket))
    }

    #[cfg(any(unix, windows))]
    fn set_tcp_socket(mut self, socket: Option<TcpSocket>) -> Self {
        if let Some(s) = &socket
            && self.abort.is_none()
        {
            let s = s.clone();
            self.abort = Some(Box::new(move || s.shut_down()));
        }
        if self.unsent.is_none() {
            self.unsent = socket.as_ref().and_then(TcpSocket::unsent_query);
        }
        self.socket = socket;
        self.init_lowat();
        self
    }

    /// The single-pipe low-water mark until the session says otherwise;
    /// where the platform has one, the carrier offers it.
    fn init_lowat(&mut self) {
        if let Some(s) = &self.socket {
            self.low_water |= s.set_notsent_lowat(super::NOTSENT_LOWAT_SINGLE);
        }
    }

    /// The carrier's unsent count, an optional capability: `unsent`
    /// returns the bytes write calls handed to the carrier that it has not
    /// transmitted yet (its own buffer, or the socket's
    /// `tcpi_notsent_bytes`), `None` while it has no count. The driver
    /// calls it at most every 20 ms, outside the session lock, so it must
    /// be cheap and must not block; each lane has its own (a lane stream's
    /// [`PipeIo`] carries it, the streams of [`PipeIo::with_lane_opener`]
    /// have [`Lane::with_unsent`](super::lanes::Lane::with_unsent)). The count is
    /// the pipe's `queued_bytes` (summed over its lanes) and, with the bytes of
    /// write calls in progress, its `Q_p`. A carrier that reports it is not paced
    /// by the carrier queue limiter.
    /// [`PipeIo::from_tcp`] and [`PipeIo::with_tcp_socket`] install the socket's
    /// query where the platform has one (Linux, Android).
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

    /// Associates a counter source with a transport's connection ID. Its
    /// owner must keep the connection live while it can supply counters.
    #[doc(hidden)]
    #[must_use]
    pub fn with_carrier_counter_identity<K: 'static>(
        mut self,
        key: usize,
        owner: CarrierConnId,
    ) -> Self {
        if let Some(source) = &mut self.carrier_stats {
            source.set_transport_identity::<K>(key, owner);
        }
        self
    }

    /// Carries the outbound Establish receipts into the session's initial accounting.
    #[must_use]
    pub fn with_establish_receipts(mut self, receipts: crate::shaping::EstablishReceipts) -> Self {
        self.establish_receipts = receipts;
        self
    }

    /// The fixed number of bytes the layers below zmux add to each write
    /// call on the carrier's sending half (0 by default), such as a
    /// wrapping layer's record header and tag. zmux passes it unchanged to
    /// the shaper factory ([`crate::shaping::ShapedPipe::write_overhead`])
    /// and does not otherwise use it. A listener's inbound transform may
    /// set it on the carrier it returns.
    #[must_use]
    pub fn with_write_overhead(mut self, bytes: u16) -> Self {
        self.write_overhead = bytes;
        self
    }

    /// Declares that the carrier bounds what it holds unsent itself, as a
    /// socket with a low-water mark does: it reports not writable (a write
    /// returns `Pending`) while it holds more than a small amount, so that
    /// its buffer never becomes a deep queue. Such a carrier is not paced
    /// by the carrier queue limiter; one that
    /// declares nothing is, in multipath sessions. TCP
    /// carriers declare it themselves where the platform has
    /// `TCP_NOTSENT_LOWAT`.
    #[must_use]
    pub fn with_low_water(mut self) -> Self {
        self.low_water = true;
        self
    }

    /// Declares that a read may return fewer bytes than the carrier holds
    /// although it had room: a TLS layer that hands over one record per
    /// read, a carrier that delivers in chunks. After such a read returned
    /// data, input counts as pending
    /// until another read finds nothing, which the driver tries before it
    /// builds its next write call. A plain socket needs no declaration: a
    /// read that did not fill its room drained it. Message carriers
    /// ([`PipeIo::records`]) and stream carriers ([`PipeIo::from_stream`])
    /// are read this way anyway.
    #[must_use]
    pub fn with_partial_reads(mut self) -> Self {
        self.partial_reads = true;
        self
    }

    /// A carrier from separate halves (for example two HTTP bodies).
    pub fn from_halves<R, W>(reader: R, writer: W) -> Self
    where
        R: AsyncRead + Send + 'static,
        W: AsyncWrite + Send + 'static,
    {
        Self {
            reader: Some(Reader::Io(Box::pin(reader))),
            writer: Some(Writer::Io(Box::pin(writer))),
            framing: Framing::ByteStream,
            abort: None,
            exporter: None,
            exporter_ready: None,
            variant: None,
            tls: None,
            protocol: None,
            carrier: None,
            prefix: Vec::new(),
            socket: None,
            unsent: None,
            carrier_stats: None,
            accounting_sources: None,
            write_overhead: 0,
            establish_receipts: [None; 2],
            admission_evidence: None,
            low_water: false,
            partial_reads: false,
            outer: None,
            lanes: None,
            conn_memory: 0,
            early: None,
            taken: None,
            split_bootstrap: false,
            close_code: None,
            drain: None,
            attachment: None,
            max_record: None,
            secure: false,
            split: false,
            reports_failure: false,
            first_mode: None,
        }
    }

    /// A carrier from a reader and a writer of owned buffers
    /// ([`ChunkWrite`]): a QUIC stream, an HTTP body, a WebSocket sink.
    pub fn from_chunk_halves<R, W>(reader: R, writer: W) -> Self
    where
        R: AsyncRead + Send + 'static,
        W: ChunkWrite + 'static,
    {
        let mut io = Self::from_halves(reader, tokio::io::sink());
        io.writer = Some(Writer::Chunks(Box::pin(writer)));
        io
    }

    /// A carrier from a bidirectional stream of another session, the two parts of one stream: an
    /// accepted stream that carries `PIPE_CARRIER` ([`Preamble::is_pipe_carrier`]), or any the
    /// application knows to be a carrier;
    /// [`Session::open_pipe_stream`](Session#method.open_pipe_stream) opens one. It is used like
    /// any carrier: to bootstrap a nested session, to join one
    /// ([`Session::begin_change`](Session#method.begin_change)), or with the nested session's
    /// [`crate::Listener::handle_pipe`].
    ///
    /// The pipe's records pass as owned buffers in both directions, without
    /// copying: the nested session's referenced payloads are written to the
    /// stream as shared chunks, and the stream's chunks are taken as they
    /// are and parsed by the nested session where they lie, which copies
    /// only the stream data it delivers (as from any carrier) and the
    /// bytes of a record split across two chunks. A graceful end of the
    /// sending half finishes the stream; any other end resets it with
    /// `ZMUX_CARRIER_FAILED`, and closing the receiving half before its end
    /// stops it with that code. A received
    /// FIN ends the inbound pipe gracefully; a reset, a `STOP_SENDING` or the
    /// end of the stream's session fails the pipe. The carrier declares no
    /// capability (unsent bytes, low-water mark, RTT): the nested session
    /// paces it with its carrier queue limiter.
    /// A session refuses a stream carrier whose session runs over it,
    /// directly or through other sessions of the process: adding it fails
    /// ([`PipeError::CarrierLoop`]), and a listener refuses such a
    /// join with `PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT)`.
    ///
    /// # Panics
    ///
    /// If `send` and `recv` are not the two parts of one stream.
    #[must_use]
    pub fn from_stream(send: SendStream, recv: RecvStream) -> Self {
        assert!(
            send.same_stream(&recv),
            "PipeIo::from_stream: the parts of two different streams"
        );
        let outer = Arc::downgrade(send.shared());
        let conn = CarrierConnId::new(send.shared());
        Self {
            reader: Some(Reader::Stream(StreamReader::new(recv))),
            writer: Some(Writer::Stream(StreamWriter::new(send))),
            framing: Framing::ByteStream,
            abort: None,
            exporter: None,
            exporter_ready: None,
            variant: None,
            tls: None,
            protocol: None,
            carrier: None,
            prefix: Vec::new(),
            socket: None,
            unsent: None,
            carrier_stats: None,
            accounting_sources: None,
            write_overhead: 0,
            establish_receipts: [None; 2],
            admission_evidence: None,
            low_water: false,
            partial_reads: false,
            lanes: Some(Box::new(LaneCaps {
                conn: Some(conn),
                opener: Some(super::lanes::stream_opener(outer.clone(), Preamble::new())),
                on: None,
                channel: None,
            })),
            outer: Some(outer),
            conn_memory: 0,
            early: None,
            taken: None,
            split_bootstrap: false,
            close_code: None,
            drain: None,
            attachment: None,
            max_record: None,
            secure: false,
            split: false,
            reports_failure: true,
            first_mode: None,
        }
    }

    /// The carrier is a stream of a multi-stream connection whose identity
    /// is `conn`: the streams the peer opens on that
    /// connection may be lanes of its pipe ([`crate::adapter::handle_lane`],
    /// [`crate::Listener::handle_pipe`]), checked against it. A stream
    /// carrier ([`PipeIo::from_stream`]) reports its session.
    #[must_use]
    pub fn with_carrier_conn(mut self, conn: CarrierConnId) -> Self {
        self.lanes.get_or_insert_default().conn = Some(conn);
        self
    }

    /// Identifies a multiplexed carrier's kind and connection at handoff.
    ///
    /// A lane admitted on this connection inherits the source of its
    /// corresponding base half. The shared counter provider, when installed,
    /// identifies physical connections shared across adapter instances.
    #[must_use]
    pub fn with_carrier_transport(self, kind: crate::CarrierKind, conn: CarrierConnId) -> Self {
        self.with_carrier(kind).with_carrier_conn(conn)
    }

    /// Opens the lanes of the pipe on the carrier's connection: `open` returns a new stream of the
    /// connection whose sending part becomes the lane ([`Lane`](super::lanes::Lane)), once the
    /// connection's stream credit allows (waiting for it is not an error). Offer lanes only where
    /// the connection delivers its streams independently (QUIC, SCTP); together with
    /// [`PipeIo::with_carrier_conn`]. A stream carrier
    /// ([`PipeIo::from_stream`]) has its own.
    #[must_use]
    pub fn with_lane_opener<F, Fut>(mut self, open: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<super::lanes::Lane>> + Send + 'static,
    {
        self.lanes.get_or_insert_default().opener = Some(super::lanes::opener(open));
        self
    }

    /// Turns the pipe's lanes on or off, whatever the default: a carrier
    /// with a lane opener opens lanes; a stream carrier only when its
    /// session has lanes or more than one pipe in use, since over a single
    /// ordered pipe its streams share one byte stream and lanes recover
    /// nothing.
    #[must_use]
    pub fn with_lanes(mut self, on: bool) -> Self {
        self.lanes.get_or_insert_default().on = Some(on);
        self
    }

    /// The carrier's datagram channel: an unreliable datagram service of the
    /// carrier besides the stream that is the pipe, such as the QUIC
    /// datagrams of the stream's connection. A session with datagrams
    /// enabled announces the channel, and when the peer does too, sends each
    /// datagram that fits it there rather than in a record
    /// ([`DatagramChannel`]). The QUIC, HTTP/3 and WebTransport adapters
    /// give their carriers one.
    #[must_use]
    pub fn with_datagram_channel(mut self, channel: Arc<dyn DatagramChannel>) -> Self {
        self.lanes.get_or_insert_default().channel = Some(channel);
        self
    }

    /// The carrier's connection, when it reports one.
    pub(crate) fn conn(&self) -> Option<&CarrierConnId> {
        self.lanes.as_ref()?.conn.as_ref()
    }

    /// Whether the pipe opens lanes. Called before the session's own lock
    /// is taken: a stream carrier looks at its session.
    pub(crate) fn lanes_offered(&self) -> bool {
        let Some(caps) = self.lanes.as_deref() else {
            return false;
        };
        if caps.opener.is_none() || caps.conn.is_none() {
            return false;
        }
        if let Some(on) = caps.on {
            return on;
        }
        match &self.outer {
            Some(outer) => outer
                .upgrade()
                .is_some_and(|s| s.lock().core.carries_independent_streams()),
            None => true,
        }
    }

    /// Decides whether the pipe opens lanes while the carrier still knows
    /// its session (a stream carrier's session is taken over by the
    /// nesting table when the pipe is attached).
    pub(crate) fn resolve_lanes(&mut self) {
        let on = self.lanes_offered();
        if let Some(caps) = self.lanes.as_deref_mut() {
            caps.on = Some(on);
        }
    }

    /// Pipe pair 0 of a split bootstrap from its two carriers, on either side: `uplink` is the
    /// carrier from the initiator to the responder (the initiator writes it, the responder
    /// reads it), `downlink` the other. Each provides its one half; the pipe reads the one that
    /// has a reader and writes the one that has a writer. Aborting the pipe aborts both; a
    /// listener taking it takes both. An exporter value is that of the connection when both
    /// halves are one (32 bytes), the uplink's and the downlink's concatenated for two
    /// connections (64 bytes), and the one half's when only one has an exporter. A listener
    /// pairs the carriers itself ([`crate::PipeHint::pair`]); a dialer combines its two with
    /// this. It establishes a session only: [`Session::begin_change`](Session#method.begin_change)
    /// refuses it (join a split carrier with [`PipeIo::paired_join`] instead).
    #[must_use]
    pub fn split_bootstrap(uplink: PipeIo, downlink: PipeIo) -> PipeIo {
        let mut io = Self::paired(uplink, downlink);
        io.split_bootstrap = true;
        io
    }

    /// One carrier of two one-way ones, the local endpoint's uplink and downlink: one Join runs
    /// across them with
    /// [`Session::begin_change`](Session#method.begin_change), and the attachment fails as one.
    #[must_use]
    pub fn paired_join(uplink: PipeIo, downlink: PipeIo) -> PipeIo {
        Self::paired(uplink, downlink)
    }

    /// Declares that the carrier meets the secure carrier's Bound
    /// contract, record confidentiality and integrity included. An
    /// exporter alone is no such declaration.
    #[must_use]
    pub fn with_carrier_secure(mut self) -> Self {
        self.secure = true;
        self
    }

    /// Declares whether the carrier reports its own failure: when the path
    /// under it fails, its reads or writes fail (an error, a reset, an
    /// unexpected end), as a stream of an outer session does when that
    /// session's liveness ends it ([`PipeIo::from_stream`] sets it). The
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
    pub async fn read_handshake(&mut self, into: &mut Vec<u8>) -> io::Result<usize> {
        super::sealed::read_unit(self, into).await
    }

    /// Writes one handshake unit in one write.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::BrokenPipe`] for a carrier without a writable half,
    /// or the write's error.
    pub async fn write_handshake(&mut self, unit: &[u8]) -> io::Result<()> {
        super::sealed::write_unit(self, unit).await
    }

    /// The Binding of an Establish on this carrier, when it declares the Bound
    /// contract and every half of it has an exporter.
    #[must_use]
    pub fn bound_exporter(&self) -> Option<Vec<u8>> {
        if !self.secure {
            return None;
        }
        self.exporter.as_ref()?.seal_binding(self.split)
    }

    /// The carrier's bytes so far may be carrier early data: a Hello in Bound is refused.
    #[must_use]
    pub fn early_data_possible(&self) -> bool {
        self.early
            .as_deref()
            .is_some_and(|e| matches!(e.io, Some(CarrierEarlyIo::In { .. })))
    }

    /// This carrier as Sealed records, with the directions of a finished handshake: a
    /// message carrier that hides its lanes, datagram channel and exporter.
    #[must_use]
    pub fn seal_records(
        self,
        sealer: crate::proto::seal::Sealer,
        opener: crate::proto::seal::Opener,
    ) -> Self {
        super::sealed::seal_carrier(self, sealer, opener)
    }

    pub(crate) fn admitted_value(&self) -> Option<&crate::AdmittedValue> {
        self.admission_evidence
            .as_deref()
            .and_then(|evidence| evidence.value.as_ref())
    }

    /// Attaches an opaque host value in place of the admission's host value.
    #[must_use]
    pub fn with_admitted(mut self, value: crate::AdmittedValue) -> Self {
        self.admission_evidence
            .get_or_insert_with(Box::default)
            .value = Some(value);
        self
    }

    /// Hides what a Sealed wrapper must not offer: raw records would pass its protection.
    pub(crate) fn hide_capabilities(&mut self) {
        self.lanes = None;
        self.exporter = None;
        self.tls = None;
        self.early = None;
    }

    pub(crate) fn paired(mut up: PipeIo, mut down: PipeIo) -> PipeIo {
        let sources = crate::CarrierHalfSources {
            send: if up.writer.is_some() {
                up.record_sources().send
            } else {
                down.record_sources().send
            },
            receive: if up.reader.is_some() {
                up.record_sources().receive
            } else {
                down.record_sources().receive
            },
        };
        up.accounting_sources = Some(Box::new(sources));
        up.split = true;
        if let Some(other) = down.attachment.take() {
            match &up.attachment {
                Some(lease) => lease.adopt(Some(&other)),
                None => up.attachment = Some(other),
            }
        }
        // Bound's contract holds for the carrier only if both halves declare it.
        up.secure &= down.secure;
        up.reports_failure &= down.reports_failure;
        // The sending half's own: its overhead and unsent query.
        if up.writer.is_none() {
            up.write_overhead = down.write_overhead;
            up.establish_receipts = down.establish_receipts;
            up.carrier_stats = down.carrier_stats.take().or(up.carrier_stats);
            up.unsent = down.unsent.take();
            up.max_record = down.max_record;
        }
        up.reader = up.reader.take().or(down.reader.take());
        up.writer = up.writer.take().or(down.writer.take());
        if up.prefix.is_empty() {
            up.prefix = std::mem::take(&mut down.prefix);
        }
        up.carrier = up.carrier.or(down.carrier);
        // The session's admission value is the uplink's.
        up.abort = match (up.abort.take(), down.abort.take()) {
            (Some(a), Some(b)) => Some(Box::new(move || {
                a();
                b();
            })),
            (a, b) => a.or(b),
        };
        up.close_code = match (
            up.close_code.as_mut().and_then(|t| t.0.take()),
            down.close_code.as_mut().and_then(|t| t.0.take()),
        ) {
            (Some(a), Some(b)) => Some(TellCloseCode::new(move |code| {
                a(code);
                b(code);
            })),
            (a, b) => a.or(b).map(|f| TellCloseCode(Some(f), VarInt::ZERO)),
        };
        up.drain = match (up.drain.take(), down.drain.take()) {
            (Some(a), Some(b)) => Some(Box::new(Drain::join(*a, *b))),
            (a, b) => a.or(b),
        };
        up.taken = match (up.taken.take(), down.taken.take()) {
            (Some(a), Some(b)) => Some(Box::new(Box::new(move || {
                a();
                b();
            }))),
            (a, b) => a.or(b),
        };
        up.exporter = match (up.exporter.take(), down.exporter.take()) {
            (Some(u), Some(d)) => Some(crate::proto::exporter::CarrierExporter::split(&u, &d)),
            (u, d) => u.or(d),
        };
        up.exporter_ready = match (up.exporter_ready.take(), down.exporter_ready.take()) {
            (Some(u), Some(d)) => Some(Box::pin(async move {
                u.await;
                d.await;
            })),
            (u, d) => u.or(d),
        };
        // Two connections: no lanes, no socket or datagram channel of one
        // of them.
        up.lanes = None;
        up.socket = None;
        up.low_water = false;
        up.partial_reads |= down.partial_reads;
        up
    }

    /// An outbound-only carrier of owned buffers ([`ChunkWrite`]), for
    /// example an HTTP GET's response body.
    pub fn chunk_writer<W>(writer: W) -> Self
    where
        W: ChunkWrite + 'static,
    {
        let mut p = Self::from_chunk_halves(tokio::io::empty(), writer);
        p.reader = None;
        p
    }

    /// An inbound-only carrier (for example an HTTP GET response body).
    pub fn reader<R>(reader: R) -> Self
    where
        R: AsyncRead + Send + 'static,
    {
        let mut p = Self::from_halves(reader, tokio::io::sink());
        p.writer = None;
        p
    }

    /// An outbound-only carrier (for example an HTTP POST request body).
    pub fn writer<W>(writer: W) -> Self
    where
        W: AsyncWrite + Send + 'static,
    {
        let mut p = Self::from_halves(tokio::io::empty(), writer);
        p.reader = None;
        p
    }

    /// Message framing, for carriers such as a WebSocket: every read
    /// returns one whole message and every write call carries one. A stream
    /// carrier ([`PipeIo::from_stream`]) is a byte stream and stays one: it
    /// ignores this.
    #[must_use]
    pub fn records(mut self) -> Self {
        if self.outer.is_none() {
            self.framing = Framing::Records;
        }
        self
    }

    /// Called instead of a graceful close when zmux fails the pipe, so that
    /// the peer sees a failure.
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
    ///
    /// A stream carrier ([`PipeIo::from_stream`]) ignores it: a stream of
    /// a multiplexed session never has Bound joins and never vouches for
    /// the session secret with the exporter of a connection below it,
    /// which the multiplexer's other carriers share.
    #[must_use]
    pub fn with_exporter(
        mut self,
        export: impl Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        if self.outer.is_none() {
            self.exporter = Some(crate::proto::exporter::CarrierExporter::new(export));
        }
        self
    }

    /// [`Self::with_exporter`] whose values come later (from another
    /// thread, a language binding): `export` returns the value's future,
    /// an error while the handshake is incomplete or once the connection is
    /// gone. The values zmux reads are fetched outside every lock before the
    /// carrier's session, join or Establish needs them, bounded by its
    /// handshake (or join) deadline; other labels of
    /// `Session::export_keying_material` give nothing (a host reads them
    /// from its own TLS layer). Not for carrier early data: such a carrier
    /// gives the exporter that answers in the call.
    #[must_use]
    pub fn with_exporter_async<F>(
        mut self,
        export: impl Fn(crate::ExportRequest) -> F + Send + Sync + 'static,
    ) -> Self
    where
        F: Future<Output = io::Result<Vec<u8>>> + Send + 'static,
    {
        if self.outer.is_none() {
            self.exporter = Some(crate::proto::exporter::CarrierExporter::new_async(export));
        }
        self
    }

    /// Fetches the values of an exporter whose values come later
    /// ([`Self::with_exporter_async`]); nothing to do for
    /// others.
    pub(crate) fn resolve_exporter(&self) -> impl Future<Output = ()> + Send + 'static {
        let fut = self
            .exporter
            .as_ref()
            .filter(|e| !e.is_resolved())
            .map(crate::proto::exporter::CarrierExporter::resolve);
        async move {
            if let Some(fut) = fut {
                fut.await;
            }
        }
    }

    /// The exporter of a handshake run over this carrier itself, such as an
    /// Establish: unlike [`Self::with_exporter`] it also holds on a stream
    /// carrier, since it vouches for this carrier and nothing below it.
    #[must_use]
    pub fn with_handshake_exporter(
        mut self,
        export: impl Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.exporter = Some(crate::proto::exporter::CarrierExporter::new(export));
        self
    }

    /// Bytes the carrier's connection holds for the session it carries a
    /// pipe of (for example the receive window of a QUIC connection sized
    /// for lanes), counted once per
    /// connection ([`PipeIo::with_carrier_conn`]) in the session's own
    /// memory budget while a pipe of the session is on that connection.
    /// Behind a listener, charge
    /// the listener instead ([`ListenerAdapter::reserve_memory`](crate::adapter::ListenerAdapter::reserve_memory)).
    #[must_use]
    pub fn with_connection_memory(mut self, bytes: u64) -> Self {
        self.conn_memory = bytes;
        self
    }

    /// For carrier adapters: the carrier sends what is written as its own
    /// early data (TLS 1.3 early data, QUIC 0-RTT) until `settled`
    /// resolves with the carrier's verdict, true when the server accepted
    /// it. The session's first records then assume `remembered`, the
    /// server's parameters kept for the server's verified identity
    /// ([`Session::parameters_to_remember`](Session#method.parameters_to_remember)).
    /// Every send before the verdict (data, FIN, resets) is not final:
    /// after a rejection nothing written reached the server, and the
    /// session writes everything again from its first record once the
    /// carrier gave it the post-handshake byte stream
    /// ([`PipeIo::with_early_restart`]); stream data then waits for the
    /// server's new parameters and no stream fails. Sends become final
    /// once the carrier accepted its early data, or once their resend
    /// follows the server's parameters. An adapter that cannot report the
    /// verdict, or whose TLS library resends rejected early data itself,
    /// offers no carrier early data. What the pipe reads reaches the session
    /// only after the verdict, so `settled` must not depend on the session;
    /// the reader may deliver it, as long as it returns no bytes before.
    /// Used only with [`crate::EarlyData::carrier_early_data`] on.
    #[must_use]
    pub fn with_early_data(
        mut self,
        remembered: crate::proto::params::TransportParameters,
        settled: impl Future<Output = bool> + Send + 'static,
    ) -> Self {
        self.early.get_or_insert_default().io = Some(CarrierEarlyIo::Out {
            remembered: Box::new(remembered),
            settled: Box::pin(settled),
        });
        self
    }

    /// For carrier adapters with [`PipeIo::with_early_data`]: the restart
    /// hook after the carrier rejected its early data. The session calls
    /// it once per restart, before the first byte written again and after
    /// every byte written before was handed to the carrier (which drops
    /// them): the carrier moves to its post-handshake byte stream there
    /// (QUIC reopens the bootstrap stream, the 0-RTT one being void), or
    /// does nothing where the same stream goes on. Return the new source
    /// descriptions if the physical carrier changed. An error fails the
    /// session with it. Without a hook the same stream goes on.
    #[must_use]
    pub fn with_early_restart(
        mut self,
        restart: impl FnMut() -> io::Result<Option<crate::CarrierHalfSources>> + Send + 'static,
    ) -> Self {
        self.early.get_or_insert_default().restart = Some(Box::new(restart));
        self
    }

    /// For carrier adapters, on a server that accepted carrier early data:
    /// what arrives before `handshake_done` resolves may have been
    /// replayed, and the streams it opens report so
    /// ([`RecvStream::is_replayable`](RecvStream#method.is_replayable)).
    /// The exporter ([`Self::with_exporter`]) gives its value from then on,
    /// also when the handshake failed (it then gives none): a session with
    /// `PipeAuth::exporter` feeds the first bytes to the core then, so that
    /// reading the peer's parameters waits for the handshake, and nothing
    /// else does. `handshake_done` returns a new future each time; each
    /// resolves with the handshake.
    #[must_use]
    pub fn with_early_data_in<Fut>(mut self, mut handshake_done: impl FnMut() -> Fut) -> Self
    where
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.early.get_or_insert_default().io = Some(CarrierEarlyIo::In {
            done: Box::pin(handshake_done()),
        });
        self.exporter_ready = Some(Box::pin(handshake_done()));
        self
    }

    /// The completion of the handshake of a server carrier that accepted
    /// carrier early data ([`Self::with_early_data_in`]), taken out.
    pub(crate) fn take_early_in(&mut self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        let early = self.early.as_deref_mut()?;
        match early.io.take() {
            Some(CarrierEarlyIo::In { done }) => Some(done),
            other => {
                early.io = other;
                None
            }
        }
    }

    /// With `prefix` read before the rest of the carrier: bytes an adapter
    /// read from it already (an admission's prefix), given back in front of
    /// any given before. The driver takes them as they are; the rest of the
    /// carrier is read as before, without a further copy.
    #[must_use]
    pub fn with_prefix(mut self, mut prefix: Vec<u8>) -> Self {
        if !self.prefix.is_empty() {
            prefix.extend_from_slice(&self.prefix);
        }
        self.prefix = prefix;
        self
    }

    /// Calls `close_code` once, whenever zmux is done with the carrier,
    /// once the session's task has dropped its halves and lanes (outside
    /// the session's lock; a half an application still holds through a
    /// fast path goes with it): with the application error code of the
    /// `CONNECTION_CLOSE` (0x1d) that ended its session, sent or received,
    /// once that session has ended (every pipe's inbound side ended or its
    /// linger timeout passed, and the session's task released its
    /// carriers); with 0 for every other end (a transport error, an idle
    /// timeout, lost carriers, a carrier that never became a pipe of a
    /// session, one dropped unused) and for a pipe removed while its session
    /// goes on.
    ///
    /// For an adapter whose carriers share a connection that has a close of
    /// its own with an application code (a QUIC connection): it records each
    /// code it is told and closes the connection with the last one once none
    /// of its pipes is in use, so that the connection's close never cuts off
    /// the zmux close before it.
    /// On a connection several sessions share, the one that ends last
    /// decides, 0 included: a pipe removed after another session's coded
    /// close sets 0 again, the code being that of the connection's end.
    #[must_use]
    pub fn with_close_code(mut self, close_code: impl FnOnce(VarInt) + Send + 'static) -> Self {
        self.close_code = Some(TellCloseCode::new(close_code));
        self
    }

    /// Runs `drain` once the session is done with the carrier after its
    /// sending half ended gracefully (its `poll_shutdown` returned
    /// `Ok`), and the halves are dropped: on the tokio runtime, for at
    /// most `limit` ([`DRAIN_LIMIT`] when the adapter has no timeout of its
    /// own that fits), and no longer than the runtime runs. A carrier that
    /// failed, was aborted, has no sending half or never became a pipe
    /// drops `drain` unrun.
    ///
    /// For what the carrier's connection must still do after the pipe's
    /// own end: wait until the peer acknowledged the last bytes, or read a
    /// response to its end, holding the connection until then, so that its
    /// close does not discard them. `drain` holds what it needs (a clone of
    /// the connection handle) from the start, and none of the halves; what
    /// exists only inside a half (a response being received) reaches it
    /// through a channel the half sends on when it is dropped, such as a
    /// `tokio::sync::oneshot`. A second call adds its future beside the
    /// first, each within its limit.
    #[must_use]
    pub fn with_drain(
        mut self,
        drain: impl Future<Output = ()> + Send + 'static,
        limit: Duration,
    ) -> Self {
        Drain::add(
            &mut self.drain,
            Box::pin(drain),
            limit,
            self.attachment.get_or_insert_default(),
        );
        self
    }

    /// The carrier's sending half ended gracefully: its drain runs.
    fn arm_drain(drain: &mut Option<Box<Drain>>) {
        if let Some(d) = drain {
            d.armed = true;
        }
    }

    /// Calls `taken` once a listener takes the carrier
    /// ([`crate::Listener::handle_pipe`]): its first record made it a new
    /// session, a join or a lane. Not called for a carrier the listener
    /// refuses or rejects. An adapter that must not answer before the
    /// listener took a carrier (an HTTP request whose response the
    /// listener may never write) waits for it.
    #[must_use]
    pub fn with_taken(mut self, taken: impl FnOnce() + Send + 'static) -> Self {
        self.taken = Some(Box::new(Box::new(taken)));
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
            .unwrap_or_else(|| crate::CarrierHalfSources::from_carrier(self.carrier, self.conn()))
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

    pub(super) fn set_candidate_metadata(
        &mut self,
        kind: crate::CarrierKind,
        variant: Option<&Arc<str>>,
    ) {
        self.carrier = Some(kind);
        if let Some(variant) = variant {
            self.variant = Some(variant.clone());
        }
    }

    /// Says what the TLS or QUIC handshake that this process runs for the
    /// carrier negotiated; `state` answers `None` while it is incomplete,
    /// which counts as no TLS. Not to be set where TLS ends at a proxy.
    #[must_use]
    pub fn with_terminated_tls(
        mut self,
        state: impl Fn() -> Option<crate::TlsState> + Send + Sync + 'static,
    ) -> Self {
        self.tls = Some(Arc::new(state));
        self
    }

    /// The TLS or QUIC handshake this process ran for the carrier, complete:
    /// the admission's and a host's test of whether an entrance terminates
    /// TLS. `None` for a carrier without TLS, or whose TLS ends at a proxy.
    /// It is no proof of an end-to-end handshake: exporters come from
    /// [`PipeIo::with_exporter`].
    #[must_use]
    pub fn terminated_tls(&self) -> Option<crate::TlsState> {
        self.tls.as_ref().and_then(|f| f())
    }

    /// The carrier's write overhead ([`PipeIo::with_write_overhead`]).
    #[must_use]
    pub fn write_overhead(&self) -> u16 {
        self.write_overhead
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
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

/// The tokio driver: one task per session runs the pipes' I/O and the
/// core's timers (feature `tokio`).
#[derive(Debug, Clone)]
pub enum Tokio {}

/// The tokio driver's part of the session state.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent state flags of the session task"
)]
pub struct Io {
    runtime: tokio::runtime::Handle,
    /// The session task, when it waits.
    task: Option<Waker>,
    /// Pipes for the session task to take over.
    new_pipes: Vec<PipeTask>,
    /// Carrier halves the core asked to close: pipe, half, abort.
    close_halves: Vec<(u64, PipeHalf, bool)>,
    /// The session task polls its pipes again before it waits: an
    /// application read or write left a side to it (R4, W2 and H2 in
    /// `super::through`).
    repoll: bool,
    /// The session task has ended: carriers attached now are dropped.
    task_ended: bool,
    /// The session task has dropped its carriers, after it ended.
    released: bool,
    /// A read left bytes in its carrier that the core has not processed
    /// yet ("input"): new batches are smaller
    /// and write calls bounded, so that writes do not hold the reads back.
    /// Acknowledgements and credit that a read took whole leave nothing
    /// pending, so that a bulk sender writes whole batches.
    input_pending: bool,
    /// The sides of the pipes added to a multipath session, for the
    /// application's fast paths (the bootstrap pipe's are
    /// [`Shared::paths`]): an application command writes or reads through
    /// any pipe whose side is free, so that a session's I/O is not all on
    /// its one task.
    through: Vec<Through>,
    /// The listener's account the session reports its charge to.
    pub(crate) account: Option<Box<AccountLink<Shared<Tokio>>>>,
    /// Lanes, allocated with the first pipe whose carrier reports its
    /// connection or the first lane asked for.
    lanes: Option<Box<IoLanes>>,
}

/// The lanes' part of the driver state, under the core lock.
#[derive(Default)]
pub(crate) struct IoLanes {
    /// Lanes the core asked for, opened after the lock.
    requests: Vec<LaneId>,
    /// Lanes opened or accepted, for the session task to take over.
    new: Vec<NewLane>,
    /// Outbound lanes the core reset.
    resets: Vec<LaneId>,
    /// The carrier connection of each live pipe's lane 0 that has one,
    /// claimed for the listener.
    conns: Vec<(u64, ConnClaim)>,
    /// The weak index deduplicates grants. Carrier attachments own them
    /// through teardown, including workers that outlive a protocol pipe.
    memory: Vec<(CarrierConnId, Weak<crate::proto::memory::Reservation>)>,
}

impl PipeIo {
    pub(super) fn reserve_carrier_memory(
        &mut self,
        shared: &Shared<Tokio>,
    ) -> Result<(), PipeError> {
        if self.reader.is_some() {
            shared.reserve_reader_memory(self.attachment())?;
        }
        if self.writer.as_ref().is_some_and(Writer::needs_workspace)
            && self.attachment().writer_memory().is_none()
            && let Some(grant) = shared.lock().core.reserve_writer()?
        {
            self.attachment().hold_writer_memory(grant);
        }
        self.reserve_transport(shared)
    }

    fn reserve_transport(&mut self, shared: &Shared<Tokio>) -> Result<(), PipeError> {
        let Some(conn) = self.conn().filter(|_| self.conn_memory != 0).cloned() else {
            return Ok(());
        };
        let mut st = shared.lock();
        let state = &mut *st;
        let lanes = state.io.lanes.get_or_insert_default();
        lanes.memory.retain(|(_, grant)| grant.strong_count() != 0);
        let existing = lanes
            .memory
            .iter()
            .find_map(|(known, grant)| (known == &conn).then(|| grant.upgrade()).flatten());
        let grant = match existing {
            Some(grant) if grant.bytes() == self.conn_memory => grant,
            Some(_) => {
                return Err(PipeError::InvalidOptions(crate::InvalidConfig::new(
                    "connection_memory",
                    "inconsistent cap for a shared carrier connection",
                )));
            }
            None => {
                let Some(grant) = state.core.reserve_transport(self.conn_memory)? else {
                    return Ok(());
                };
                let grant = Arc::new(grant);
                lanes.memory.push((conn, Arc::downgrade(&grant)));
                grant
            }
        };
        self.attachment().hold(grant);
        Ok(())
    }
}

/// A lane for the session task: an inbound one with its reader and the
/// bytes read to route it, or an outbound one with its writer.
pub(crate) struct NewLane {
    at: LaneId,
    framing: Framing,
    /// Its reads may return less than it holds.
    partial: bool,
    read: Option<(Reader, Vec<u8>)>,
    write: Option<LaneWriter>,
    attachment: Option<Arc<Attachment>>,
    reader_memory: Option<crate::proto::memory::Reservation>,
    writer_memory: Option<Arc<crate::proto::memory::WriteWorkspace>>,
}

/// The bootstrap pipe's sides, for the application's fast paths. Weak: the
/// session task owns the sides, and the carrier goes with the task, however
/// long the application keeps its handles.
pub struct Through {
    id: PipeId,
    write: Weak<WritePath<WriteSide>>,
    read: Weak<ReadPath<ReadSide>>,
}

/// Reads pipe `id`'s carrier through ([`Driver::read_through`]); returns
/// the core, locked, and whether it was unlocked meanwhile.
fn read_through_on<'a>(
    shared: &'a Shared<Tokio>,
    locked: Lock<'a, Tokio>,
    reader: &Waker,
    id: PipeId,
    read: &Weak<ReadPath<ReadSide>>,
) -> (Lock<'a, Tokio>, bool) {
    let Some(read) = read.upgrade() else {
        return (locked, false);
    };
    let (locked, unlocked) = read.read_through(
        &shared.inner,
        locked,
        reader,
        |rs, outcome, st| {
            rs.apply(outcome, id.into(), st, st.now());
            // Bytes a read-through leaves in the carrier are pending input,
            // as the session task's are (which recomputes the flag).
            st.io.input_pending |= rs.left_more;
            st.dispatch();
        },
        State::repoll_task,
        |st| st.io.task.clone(),
    );
    let mut locked = locked;
    release_side(&mut locked, read);
    let (locked, policed) = shared.police_datagrams(locked);
    (locked, unlocked || policed)
}

/// The tokio driver's work after the core lock, before its wake-ups: what
/// is given up under the lock and dropped after it (a pipe's wait resolves
/// once what is left of it is gone). A pipe's carrier halves, a lane's
/// streams and an opener are the application's (an outer session's
/// streams take that session's lock and may write through), and no
/// application code runs under the core lock: the sides a fast path
/// released ([`release_side`]), finished pipes and lanes, lanes whose pipe
/// is gone, the lanes' state of an ended session.
#[derive(Default)]
pub struct Deferred {
    gone: Vec<Box<dyn Send>>,
}

impl Deferred {
    fn push(&mut self, gone: impl Send + 'static) {
        self.gone.push(Box::new(gone));
    }
}

/// Drops a side a fast path upgraded, under the core lock: when it was the
/// last reference (the session task ended meanwhile), the side goes to the
/// work after the lock instead.
fn release_side<S: Send + Sync + 'static>(st: &mut State<Tokio>, side: Arc<S>) {
    if let Some(side) = Arc::into_inner(side) {
        st.deferred.push(side);
    }
}

/// The future a [`Dial`] returns.
type Dialing = Pin<Box<dyn Future<Output = io::Result<PipeIo>> + Send>>;

/// The application's dial function: a new carrier for a
/// [`DialRequest`](crate::DialRequest), the one way the helpers dial
/// (`resolve_duplicate`'s `rejoin`). Cheap to clone.
///
/// ```no_run
/// let dial = zmux::Dial::new(|_req| async {
///     Ok(zmux::PipeIo::from_tcp(tokio::net::TcpStream::connect("127.0.0.1:4433").await?))
/// });
/// # let _ = dial;
/// ```
#[derive(Clone)]
pub struct Dial(Arc<dyn Fn(super::DialRequest) -> Dialing + Send + Sync>);

impl Dial {
    /// A dial function from an async closure.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(super::DialRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<PipeIo>> + Send + 'static,
    {
        Self(Arc::new(move |req| Box::pin(f(req))))
    }

    /// Dials a carrier for `req`.
    pub fn dial(
        &self,
        req: super::DialRequest,
    ) -> impl Future<Output = io::Result<PipeIo>> + Send + use<> {
        self.0.as_ref()(req)
    }
}

impl std::fmt::Debug for Dial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dial(..)")
    }
}

impl Driver for Tokio {
    type Io = Io;
    type Deferred = Deferred;
    type Paths = Through;
    type Carrier = PipeIo;
    type Timeout = ();
    type Dial = Dial;

    fn spawn_controller(future: impl Future<Output = ()> + Send + 'static) {
        tokio::spawn(future);
    }

    fn candidate_metadata(io: &mut PipeIo, kind: crate::CarrierKind, variant: Option<&Arc<str>>) {
        io.set_candidate_metadata(kind, variant);
    }

    fn hold_cleanup(io: &mut PipeIo, guard: impl Send + 'static) {
        io.attachment().hold(guard);
    }

    fn controller_bootstrap(
        io: PipeIo,
        config: Arc<Config>,
    ) -> Result<Arc<Shared<Self>>, ConnectError> {
        Shared::create(
            &mut Some(io),
            config,
            Role::Client,
            Some(Role::Client),
            None,
            None,
            |_| None,
        )
    }

    fn spawn_join(shared: &Shared<Self>, f: impl Future<Output = ()> + Send + 'static) {
        shared.runtime().spawn(f);
    }

    async fn join_callback<T: Send + 'static>(
        call: impl FnOnce() -> crate::Decision<T> + Send + 'static,
    ) -> Option<crate::Decision<T>> {
        tokio::task::spawn_blocking(move || crate::Decision::catch(call))
            .await
            .ok()
            .flatten()
    }

    async fn sleep_until(deadline: Instant) {
        tokio::time::sleep_until(deadline.into()).await;
    }

    fn resolve_join_exporter(carrier: &PipeIo) -> impl Future<Output = ()> + Send + 'static {
        carrier.resolve_exporter()
    }

    fn now() -> Instant {
        now()
    }

    fn deferred_pending(d: &Deferred) -> bool {
        !d.gone.is_empty()
    }

    fn close_pipe(state: &mut State<Self>, pipe: u64, half: PipeHalf, abort: bool) {
        state.io.close_halves.push((pipe, half, abort));
    }

    fn open_lane(state: &mut State<Self>, lane: LaneId) {
        // A closed session keeps no lane state.
        if state.core.state() == CoreState::Closed {
            return;
        }
        state.io.lanes.get_or_insert_default().requests.push(lane);
        state.wake_task();
    }

    fn reset_lane(state: &mut State<Self>, lane: LaneId) {
        if state.core.state() == CoreState::Closed {
            return;
        }
        state.io.lanes.get_or_insert_default().resets.push(lane);
        state.wake_task();
    }

    fn session_closed(state: &mut State<Self>) {
        state.io.account = None;
        release_lanes(state);
    }

    fn released(state: &State<Self>) -> bool {
        state.io.released
    }

    fn wake_driver(state: &mut State<Self>) {
        state.wake_task();
    }

    fn kick(state: &mut State<Self>) {
        // A task that runs looks at all of this before it waits again, in
        // the critical section that registers its waker.
        if state.io.task.is_none() {
            return;
        }
        if state.core.wants_write_any()
            || state.core.wants_pick()
            || state.core.state() >= CoreState::Closing
            || !state.io.close_halves.is_empty()
            || !state.io.new_pipes.is_empty()
            || state.io.lanes.as_ref().is_some_and(|l| !l.new.is_empty())
        {
            state.wake_task();
        }
    }

    /// The output is written through from the calling task on a pipe
    /// whose write side is idle, without waking the session task (W2 in
    /// `super::through`): on a single pipe, the bootstrap pipe; in a
    /// multipath session, each pipe with output in turn.
    fn finish_write<'a>(shared: &'a Shared<Self>, mut locked: Lock<'a, Self>) {
        #[cfg(feature = "test-hooks")]
        if locked.core.config().hooks.disable_write_through {
            locked.after_command();
            return;
        }
        locked.dispatch();
        let write_on = |locked: Lock<'a, Self>, id: PipeId, write: &Weak<WritePath<WriteSide>>| {
            let Some(write) = write.upgrade() else {
                return locked;
            };
            let mut locked = write.write_through(
                &shared.inner,
                locked,
                |ws, st| take_batch(ws, id, st, st.now()),
                State::repoll_task,
            );
            // What the carrier took goes into Q_p now, unless the session
            // task holds the side (it tells the core itself).
            if let Some(mut ws) = write.try_side() {
                let now = locked.now();
                ws.out.tell(&mut locked.core, id, now);
            }
            release_side(&mut locked, write);
            locked
        };
        locked = write_on(locked, shared.paths.id, &shared.paths.write);
        if locked.core.is_multipath() {
            // The other pipes, one at a time: each write-through releases
            // the core lock, so the list is looked at again each time. A
            // side that is busy is skipped at once; a free one asks the
            // core whether it wants to write (taking the batch).
            let mut i = 0;
            while let Some(t) = locked.io.through.get(i) {
                let (id, write) = (t.id, t.write.clone());
                i += 1;
                locked = write_on(locked, id, &write);
            }
        }
        locked.after_command();
    }

    /// Read-through (R3 and R4 in `super::through`) in a multipath session,
    /// unless the session task or another read is reading: the bootstrap
    /// pipe, then each other pipe in turn. A single-pipe session never
    /// reads through: its task keeps up with its one carrier, and a reader
    /// that reads through only doubles the wake-ups of each arrival (the
    /// pipe's waker wakes the task as well) and holds the task's next read
    /// back (measured on loopback TCP: bulk 11-14 % slower at more CPU per
    /// byte, request-response latency 10-20 % higher). A multipath session's
    /// acknowledgements and credit return through the reads, and its one
    /// task serves every pipe: readers that read through shorten that loop
    /// (one pipe under bulk: 25 % more throughput).
    fn read_through<'a>(
        shared: &'a Shared<Self>,
        locked: Lock<'a, Self>,
        reader: &Waker,
    ) -> (Lock<'a, Self>, bool) {
        if !locked.core.is_multipath() {
            return (locked, false);
        }
        let (mut locked, mut unlocked) =
            read_through_on(shared, locked, reader, shared.paths.id, &shared.paths.read);
        let mut i = 0;
        while let Some(t) = locked.io.through.get(i) {
            let (id, read) = (t.id, t.read.clone());
            i += 1;
            let (again, u) = read_through_on(shared, locked, reader, id, &read);
            locked = again;
            unlocked |= u;
        }
        (locked, unlocked)
    }

    fn carrier_info(carrier: &mut PipeIo) -> CarrierInfo {
        let evidence = carrier
            .admission_evidence
            .take()
            .map(|evidence| *evidence)
            .unwrap_or_default();
        CarrierInfo {
            connection_memory: carrier.conn().map_or(0, |_| carrier.conn_memory),
            writer_memory: if carrier.writer.as_ref().is_some_and(Writer::needs_workspace) {
                crate::proto::memory::WriteWorkspace::COST
            } else {
                0
            },
            attachment: carrier.attachment().clone(),
            accounting_sources: carrier.record_sources(),
            inbound: carrier.reader.is_some().then_some(carrier.framing),
            outbound: carrier.writer.is_some().then_some(carrier.framing),
            // Also kept: pipe 0's reader reads it (`PipeTask::new`).
            exporter: carrier.exporter.clone(),
            protocol: carrier.protocol.take(),
            tls: carrier.terminated_tls(),
            kind: carrier.carrier,
            variant: carrier.variant.take(),
            write_overhead: carrier.write_overhead,
            max_record: carrier.max_record,
            establish_receipts: carrier.establish_receipts,
            admitted: evidence.value,
            bound_prefix: evidence.bound_prefix,
            secure: carrier.secure,
            reports_failure: carrier.reports_failure,
            split: carrier.split,
            first_mode: carrier.first_mode,
        }
    }

    fn register_carrier_stats(carrier: &mut PipeIo) {
        carrier.register_carrier_stats();
    }

    fn check_carrier(shared: &Arc<Shared<Self>>, carrier: &PipeIo) -> Result<(), PipeError> {
        if carrier.split_bootstrap {
            // It makes pipe pair 0 only; a join takes `paired_join`.
            return Err(PipeError::InvalidArgument);
        }
        match carrier.outer.as_ref().and_then(Weak::upgrade) {
            Some(outer) if runs_over(&outer, shared) => Err(PipeError::CarrierLoop),
            _ => Ok(()),
        }
    }

    fn attach(shared: &Arc<Shared<Self>>, id: u64, mut carrier: PipeIo) -> Result<(), PipeError> {
        carrier.reserve_carrier_memory(shared)?;
        let rt = tokio::runtime::Handle::try_current().map_err(|_| PipeError::InvalidArgument)?;
        rt.spawn(Attachment::during(
            carrier.attachment.clone(),
            join_carrier(shared.clone(), PipeId(id), carrier),
        ));
        Ok(())
    }

    fn start_rejoin(session: handle::WeakSession<Self>, dial: Dial) -> bool {
        let Some(session) = session.upgrade() else {
            return false;
        };
        session.launch_recovery(crate::CarrierOpener::new(move |_| {
            let dial = dial.clone();
            async move {
                dial.dial(super::DialRequest::bidi())
                    .await
                    .map(|pipe| vec![pipe])
            }
        }))
    }

    #[cfg(feature = "test-hooks")]
    fn io_tables(io: &Io) -> (usize, usize, usize, usize) {
        let lanes = io.lanes.as_deref().map_or(0, |l| {
            1 + l.requests.len() + l.new.len() + l.resets.len() + l.conns.len()
        });
        (0, io.close_halves.len(), io.new_pipes.len(), lanes)
    }
}

impl State<Tokio> {
    /// Wakes the session task (after the lock).
    pub(crate) fn wake_task(&mut self) {
        if let Some(w) = self.io.task.take() {
            self.wakes.push(w);
        }
    }

    /// Asks the session task to poll its pipes before it waits.
    fn repoll_task(&mut self) {
        self.io.repoll = true;
        self.wake_task();
    }
}

impl Shared<Tokio> {
    pub(super) fn runtime(&self) -> tokio::runtime::Handle {
        self.lock().io.runtime.clone()
    }

    /// A stream the peer opened on connection `conn`, routed here by its
    /// Lane Key as lane `at`: accepted when the pipe's lane 0 is on that
    /// connection and the core takes it; its unused sending half is
    /// ended at once. Refused, the stream is aborted when dropped.
    pub(crate) fn accept_lane(
        &self,
        at: LaneId,
        conn: &CarrierConnId,
        mut io: PipeIo,
    ) -> LaneAccept {
        let mut st = self.lock();
        let claim = st.io.lanes.as_ref().and_then(|l| {
            l.conns
                .iter()
                .find(|(p, c)| *p == at.pipe.0 && c.conn() == conn)
        });
        let Some((_, claim)) = claim.filter(|_| !st.io.task_ended) else {
            drop(st);
            return LaneAccept::Refused;
        };
        let lease = claim.attachment.clone();
        let Ok(reader_memory) = st.core.reserve_reader() else {
            return LaneAccept::Refused;
        };
        let framing = io.framing;
        let now = st.now();
        let verdict = st.core.accept_lane(at, framing, now);
        if verdict == LaneAccept::Accepted
            && let Some(reader) = io.reader.take()
        {
            let prefix = std::mem::take(&mut io.prefix);
            st.io.lanes.get_or_insert_default().new.push(NewLane {
                at,
                framing,
                attachment: lease.clone(),
                partial: io.partial_reads,
                read: Some((reader, prefix)),
                write: None,
                reader_memory,
                writer_memory: None,
            });
        }
        st.after_command();
        drop(st);
        if verdict == LaneAccept::Accepted {
            if let Some(parent) = &lease {
                io.adopt_attachment(parent.clone());
            }
            io.release_unused(true, false);
        }
        verdict
    }
}

/// The listener's view of a session: the few operations its join path and memory budget
/// need, each one critical section. Runs the joiner's handshake on `pipe` and starts the
/// pipe. Nothing read from the carrier reaches the session before the Reply verifies; a
/// failure fails only the attachment.
async fn join_carrier(shared: Arc<Shared<Tokio>>, id: PipeId, mut pipe: PipeIo) {
    use super::accept::{DialStep, JoinDial, JoinWrite};
    use super::sealed::{read_unit, seal_carrier, until, write_join_unit};
    pipe.resolve_lanes();
    let mut pipe = Some(pipe);
    let shared_ref = &shared;
    let clock = shared.lock().core.config().clock_domain.clone();
    let stop = handle::join_failed_wait(shared_ref, id);
    let work = async move {
        let mut io = pipe.take().expect("present");
        let mut dial = JoinDial::new(
            shared_ref.clone(),
            id,
            io.framing,
            io.carrier,
            io.write_overhead,
        );
        let mut input = Vec::new();
        let mut next = dial.start();
        let (consumed, records) = loop {
            next = match next {
                DialStep::Hold => {
                    handle::join_released_wait(shared_ref, id).await;
                    dial.released()
                }
                DialStep::Delay(d) => {
                    super::deadline::sleep::<Tokio>(&clock, clock.now().checked_add(d)).await;
                    dial.delayed(true)
                }
                DialStep::Write(unit) => {
                    let write = JoinWrite::new(shared_ref.clone(), unit);
                    let result = write_join_unit(&mut io, write).await;
                    dial.written(result)
                }
                DialStep::Read(want) => {
                    while input.len() < want {
                        let r = read_unit(&mut io, &mut input).await;
                        if !dial.read(r, input.len()) {
                            return;
                        }
                    }
                    dial.input(&mut input)
                }
                DialStep::End => return,
                DialStep::Attach { consumed, records } => break (consumed, records),
            };
        };
        input.drain(..consumed);
        io.prefix = input;
        if let Some((s, o)) = records {
            io = seal_carrier(io, s, o);
        }
        let Some((inbound, outbound)) = dial.limits(io.max_record, io.write_overhead) else {
            return;
        };
        io.release_unused(inbound, outbound);
        if claim_carrier(shared_ref, id.0, io.outer.take()).is_err()
            || shared_ref.attach_task(id.0, io).is_err()
        {
            dial.failed(io::ErrorKind::BrokenPipe);
            return;
        }
        dial.attached();
    };
    let _ = until(stop, work).await;
}

impl PipeIo {
    /// Registers a host worker of this carrier. Drop the returned guard after
    /// the worker releases its transport, including on failure. The worker
    /// must observe the carrier halves' release independently of pipe closure.
    pub fn worker_guard(&mut self) -> impl Send + Sync + 'static + use<> {
        self.attachment().worker()
    }

    pub(crate) fn adopt_attachment(&mut self, lease: Arc<Attachment>) {
        lease.adopt(self.attachment.as_ref());
        self.attachment = Some(lease);
    }

    pub(crate) fn register_carrier_stats(&mut self) {
        let mut source = self
            .carrier_stats
            .take()
            .map(|source| *source)
            .or_else(|| self.socket.as_ref().map(TcpSocket::counter_source))
            .unwrap_or_default();
        source.dedicated |= self.socket.is_some();
        source.set_connection(self.conn().cloned());
        self.attachment().register_sample(source, now);
    }

    pub(crate) fn attachment(&mut self) -> &Arc<Attachment> {
        self.attachment.get_or_insert_default()
    }

    /// A confirmed inbound join transfers its used directions immediately.
    pub(crate) fn release_unused(&mut self, inbound: bool, outbound: bool) {
        if !inbound {
            self.prefix.clear();
            if let Some(reader) = self.reader.take() {
                let lease = self.attachment.clone();
                tokio::task::spawn_blocking(move || {
                    drop(reader);
                    drop(lease);
                });
            }
        }
        if !outbound && let Some(mut writer) = self.writer.take() {
            // The drain still belongs to the pipe. It runs after both its
            // retirement and successful shutdown of the detached writer.
            let flushed = self.drain.as_mut().and_then(|drain| {
                let future = drain.future.take()?;
                let (tx, rx) = tokio::sync::oneshot::channel();
                drain.armed = true;
                drain.future = Some(Box::pin(async move {
                    if rx.await.is_ok() {
                        future.await;
                    }
                }));
                Some(tx)
            });
            spawn_drain(
                Attachment::during(self.attachment.clone(), async move {
                    if std::future::poll_fn(|cx| writer.poll_shutdown(cx))
                        .await
                        .is_ok()
                        && let Some(tx) = flushed
                    {
                        let _ = tx.send(());
                    }
                }),
                DRAIN_LIMIT,
            );
        }
    }

    /// Ends what the attachment's direction does not use after the handshake.
    pub(crate) async fn end_unused(&mut self, inbound: bool, outbound: bool) {
        if !inbound {
            self.reader = None;
            self.prefix.clear();
        }
        if !outbound
            && let Some(mut w) = self.writer.take()
            && std::future::poll_fn(|cx| w.poll_shutdown(cx)).await.is_ok()
        {
            Self::arm_drain(&mut self.drain);
        }
    }
}

impl Shared<Tokio> {
    /// A Sealed carrier's limit and overhead, before the pipe's first record.
    pub(crate) fn set_pipe_limits(
        &self,
        p: PipeId,
        max: usize,
        overhead: u16,
    ) -> Result<(), crate::InvalidConfig> {
        let mut st = self.lock();
        st.core.set_pipe_max_record(p, max)?;
        st.core.set_pipe_write_overhead(p, overhead);
        Ok(())
    }
}

impl Shared<Tokio> {
    /// Creates the core and spawns the session task for a bootstrap pipe.
    pub(super) fn create(
        pending: &mut Option<PipeIo>,
        config: Arc<Config>,
        role: Role,
        transport: Option<Role>,
        locator: Option<&[u8]>,
        listener_budget: Option<Arc<crate::proto::memory::Ledger>>,
        before_start: impl FnOnce(&Arc<Self>) -> Option<Weak<super::listen::ListenShared>>,
    ) -> Result<Arc<Self>, ConnectError> {
        let pipe = pending.as_mut().expect("bootstrap carrier owned by setup");
        pipe.register_carrier_stats();
        let carrier = Tokio::carrier_info(pipe);
        let low_water = pipe.low_water;
        let lanes = pipe.lanes_offered();
        let conn = pipe.conn().cloned();
        let io = Io {
            runtime: tokio::runtime::Handle::current(),
            task: None,
            new_pipes: Vec::new(),
            close_halves: Vec::new(),

            repoll: false,
            task_ended: false,
            released: false,
            input_pending: false,
            through: Vec::new(),
            account: None,
            lanes: conn.clone().map(|c| {
                Box::new(IoLanes {
                    conns: vec![(0, ConnClaim::new(c, Some(carrier.attachment.clone())))],
                    ..IoLanes::default()
                })
            }),
        };
        let writer_memory = carrier.writer_memory;
        let mut state: State<Tokio> = State::new(
            config,
            role,
            transport,
            locator,
            carrier,
            io,
            listener_budget,
        )?;
        let mut pipe = pending.take().expect("admitted bootstrap carrier");
        let mut working = state.core.take_bootstrap_transport();
        if writer_memory != 0
            && let Some(work) = &mut working
        {
            pipe.attachment()
                .hold_writer_memory(work.split_off(writer_memory));
        }
        if let Some((conn, grant)) = conn.zip(working).filter(|(_, grant)| grant.bytes() != 0) {
            let grant = Arc::new(grant);
            state
                .io
                .lanes
                .get_or_insert_default()
                .memory
                .push((conn, Arc::downgrade(&grant)));
            pipe.attachment().hold(grant);
        }
        let outer = pipe.outer.take();
        let channel = pipe
            .lanes
            .as_deref_mut()
            .and_then(|l| l.channel.take())
            .filter(|_| state.core.config().enable_datagrams);
        let (early, early_restart) = match pipe.early.take() {
            Some(e) => (e.io, e.restart),
            None => (None, None),
        };
        if !state.core.config().pipe_auth.exporter {
            // Nothing needs the value at the first bytes: they do not wait.
            pipe.exporter_ready = None;
        }
        let mut first = PipeTask::new(PipeId(0), pipe, super::NOTSENT_LOWAT_SINGLE);
        let early = early.map(|e| match e {
            CarrierEarlyIo::Out {
                remembered,
                settled,
            } => {
                let sent = state.core.assume_remembered(&remembered);
                if sent && let Some(restart) = early_restart {
                    first.set_restart(restart);
                }
                let applied = sent.then(|| first.hold_reads_for_verdict());
                (sent.then_some(settled), None, applied)
            }
            CarrierEarlyIo::In { done } => {
                if state.core.carrier_early_data_allowed() {
                    state.core.set_carrier_early_data(true);
                    (None, Some(done), None)
                } else {
                    (None, None, None)
                }
            }
        });
        state.core.set_pipe_low_water(PipeId(0), low_water);
        state.core.set_pipe_lanes(PipeId(0), lanes);
        if let Some(ch) = &channel {
            // Before the parameters are written: they announce it.
            let (capacity, room) = ch.datagram_capacity();
            state
                .core
                .set_pipe_channel(PipeId(0), ch.channel_prefix(), capacity, room);
        }
        let lane_key = state
            .core
            .local_parameters()
            .zmux_max_lanes
            .filter(|l| l.max_lanes.get() > 1)
            .map(|l| l.lane_key);
        let through = Through {
            id: PipeId(0),
            write: Arc::downgrade(&first.write),
            read: Arc::downgrade(&first.read),
        };
        let shared = Arc::new(Shared::new(state, through));
        // The session accepts the peer's lanes: the streams that carry them
        // find it by its Lane Key.

        // A new session: no carrier can run over it yet.
        let _ = claim_carrier(&shared, 0, outer);
        // Publish listener routing and accounting before bootstrap parameters
        // can make the locator usable by a peer on another carrier.
        let listener = before_start(&shared);
        if let Some(key) = lane_key {
            super::lanes::register(&shared, key, listener);
        }
        // Registered before the task writes the parameters that announce
        // the channel.
        if let Some(ch) = channel {
            let receiving =
                super::channel::attach(&shared, PipeId(0), &ch, Some(first.attachment.clone()));
            super::channel::start(&shared, PipeId(0), ch, receiving);
        }
        let early = early.map(|verdict| {
            (
                verdict,
                first.attachment.clone(),
                first.attachment.retirement().clone(),
            )
        });
        tokio::spawn(Task::new(shared.clone(), first));
        if let Some(((settled, done, applied), lease, retiring)) = early {
            let weak = Arc::downgrade(&shared);
            let ended = shared.clone();
            tokio::spawn(async move {
                // Dropped last, whichever way this ends: the first bytes go on.
                let _lease = lease;
                let _applied = applied;
                let verdict = async move {
                    match (settled, done) {
                        (Some(s), _) => Some(Some(s.await)),
                        (None, Some(d)) => {
                            d.await;
                            Some(None)
                        }
                        (None, None) => None,
                    }
                };
                // The adapter's verdict is dropped with the session's end.
                let session_end = super::wait::Wait::new(
                    &ended.inner,
                    super::wait::List::State,
                    |st: &mut State<Tokio>| st.core.error().map(|_| ()),
                );
                let stopped = async {
                    let _ = super::hooks::first(session_end, retiring.wait()).await;
                };
                let Some(Some(accepted)) = super::sealed::until(stopped, verdict).await else {
                    return;
                };
                drop(ended);
                let Some(shared) = weak.upgrade() else {
                    return;
                };
                let mut st = shared.lock();
                match accepted {
                    Some(a) => {
                        let now = st.now();
                        st.core.carrier_early_data_settled(a, now);
                    }
                    None => st.core.set_carrier_early_data(false),
                }
                st.after_command();
            });
        }
        Ok(shared)
    }

    /// Hands the carrier of an added pipe to the session task as pipe `id`
    /// at handoff. A closing or closed session refuses the pipe and
    /// releases the carrier outside the session lock.
    pub(crate) fn attach_task(self: &Arc<Self>, id: u64, mut io: PipeIo) -> Result<(), PipeError> {
        // Pipes are added to multipath sessions only.
        if let Some(s) = &io.socket {
            s.set_notsent_lowat(super::NOTSENT_LOWAT_MULTIPATH);
        }
        let low_water = io.low_water;
        let lanes = io.lanes_offered();
        let conn = io.conn().cloned();
        let channel = io.lanes.as_deref_mut().and_then(|l| l.channel.take());
        // Asked before the lock: the adapter's own.
        let shape = channel
            .as_ref()
            .map(|c| (c.channel_prefix(), c.datagram_capacity()));
        let sources = io.record_sources();
        let task = PipeTask::new(PipeId(id), io, super::NOTSENT_LOWAT_MULTIPATH);
        // Registered before the pipe's task can announce the channel;
        // dropped with a refused pipe.
        let receiving = channel
            .as_ref()
            .filter(|_| self.lock().core.config().enable_datagrams)
            .map(|ch| super::channel::attach(self, PipeId(id), ch, Some(task.attachment.clone())));
        let mut st = self.lock();
        // The session or the attachment may have ended while the handshake's last message
        // was written.
        let id = PipeId(id);
        let admission = if st.io.task_ended
            || st.core.state() >= CoreState::Closing
            || matches!(st.core.pipe_joined(id), Some(Err(_)))
        {
            let err = st
                .core
                .error()
                .cloned()
                .unwrap_or(SessionError::PipesLost { last: None });
            Err(PipeError::SessionLost(err))
        } else {
            st.enable_pipe_accounting(&task.attachment, id, sources)
                .map_err(PipeError::InvalidOptions)
        };
        if let Err(error) = admission {
            let s = &mut *st;
            task.attachment.retire(&mut s.wakes);
            s.deferred.push(task);
            s.after_command();
            drop(st);
            release_carriers(self, Some(id.0));
            // The caller gives the pipe up in the core.
            return Err(error);
        }
        st.core.set_pipe_low_water(id, low_water);
        st.core.set_pipe_lanes(id, lanes);
        let channel = channel.filter(|_| st.core.config().enable_datagrams);
        if let (Some(_), Some((cid, (capacity, room)))) = (&channel, shape) {
            st.core.set_pipe_channel(id, cid, capacity, room);
        }
        if let Some(c) = conn {
            let l = st.io.lanes.get_or_insert_default();
            l.conns.retain(|(p, _)| *p != id.0);
            l.conns
                .push((id.0, ConnClaim::new(c, Some(task.attachment.clone()))));
        }
        st.io.through.push(Through {
            id,
            write: Arc::downgrade(&task.write),
            read: Arc::downgrade(&task.read),
        });
        st.io.new_pipes.push(task);
        st.wake_task();
        drop(st);
        if let (Some(ch), Some(r)) = (channel, receiving) {
            super::channel::start(self, id, ch, r);
        }
        Ok(())
    }
}
// ---- the session task ------------------------------------------------------------

/// Reads closer together than this are a burst once one of them filled the
/// idle read's stack buffer or [`BURST_READS`] came in a row: an idle pipe
/// takes its full read buffer for them instead of holding each read on its
/// own. A probe and its answer are not a burst.
const BURST: Duration = Duration::from_millis(10);

/// Reads in a row, each within [`BURST`] of the last, that make a burst.
const BURST_READS: u8 = 3;

/// The write side of a pipe. The session task writes batches on it, and
/// an application command may write its own output through while the pipe
/// is idle (W1 to W3 in `super::through`).
pub(crate) struct WriteSide {
    writer: Option<Writer>,
    /// The bootstrap pipe after its carrier rejected early data: called
    /// before the first batch of the session's new start
    /// ([`PipeIo::with_early_data`]), with the start it was last called
    /// for.
    restart: Option<(EarlyRestart, u32)>,
    out: Outbound,
    /// Where the last write of a stream carrier ended in the batch.
    cursor: PieceCursor,
    needs_flush: bool,
    /// The last write found the carrier full (reported to the core).
    blocked: bool,
    _lease: Option<Arc<Attachment>>,
}

impl WriteSide {
    /// One write call with at most `limit` bytes of the rest of the batch
    /// (one whole message on a message-framed carrier); the batch is done
    /// when it is empty afterwards.
    fn write_some(&mut self, cx: &mut Context<'_>, limit: usize) -> Poll<io::Result<usize>> {
        let Some(writer) = self.writer.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        #[cfg(feature = "test-hooks")]
        let left = self.out.left();
        let uncertain = matches!(writer, Writer::Chunks(_) | Writer::Sealed(_));
        let poll = match (self.out.framing(), writer) {
            // A stream carrier takes the referenced payloads as shared
            // chunks.
            (Framing::ByteStream, Writer::Stream(w)) => w.poll_write_batch(
                cx,
                self.out.batch(),
                &mut self.cursor,
                self.out.pos(),
                limit,
            ),
            (Framing::Records, Writer::Chunks(w))
                if w.takes_message_batches() && !self.out.batch().has_committed_cover() =>
            {
                let Some(messages) = self.out.message_batch(cx) else {
                    return Poll::Pending;
                };
                let before: usize = messages.iter().map(crate::Chunk::len).sum();
                let poll = w.as_mut().poll_write_message_batch(cx, messages);
                if let Poll::Ready(Ok(n)) = poll
                    && n != before
                {
                    return Poll::Ready(Err(io::Error::other(
                        "a carrier took part of a batch of messages",
                    )));
                }
                poll
            }
            (_, Writer::Chunks(w)) => {
                let Some(chunks) = self.out.chunks(limit, cx) else {
                    return Poll::Pending;
                };
                let before: usize = chunks.iter().map(crate::Chunk::len).sum();
                let poll = w.as_mut().poll_write_chunks(cx, chunks);
                if let Poll::Ready(Ok(n)) = poll {
                    let after: usize = chunks.iter().map(crate::Chunk::len).sum();
                    if before - after != n {
                        return Poll::Ready(Err(io::Error::other(
                            "a carrier took other bytes than it reported",
                        )));
                    }
                }
                poll
            }
            (Framing::ByteStream, w @ (Writer::Io(_) | Writer::Sealed(_))) => {
                let mut w = w.io().expect("a writer of slices");
                let mut slices = [IoSlice::new(&[]); MAX_SLICES];
                let n = self.out.slices(limit, &mut slices);
                w.as_mut().poll_write_vectored(cx, &slices[..n])
            }
            (Framing::Records, w @ (Writer::Io(_) | Writer::Sealed(_))) => {
                let mut w = w.io().expect("a writer of slices");
                // One write call per message.
                let msg = self.out.message();
                let len = msg.len();
                match w.as_mut().poll_write(cx, msg) {
                    Poll::Ready(Ok(w)) if w == len => Poll::Ready(Ok(w)),
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(0)),
                    other => other,
                }
            }
            // A stream carrier is a byte stream.
            (Framing::Records, Writer::Stream(_)) => Poll::Ready(Ok(0)),
        };
        match poll {
            Poll::Ready(Ok(n)) if n != 0 => self.out.note_unproved_progress(false),
            Poll::Pending | Poll::Ready(Err(_)) if uncertain => {
                self.out.note_unproved_progress(true);
            }
            _ => {}
        }
        if let Poll::Ready(Ok(w)) = poll
            && w > 0
        {
            self.needs_flush = true;
            self.out.written(w);
            #[cfg(feature = "test-hooks")]
            super::resources::count_write_call(w, limit < left && w == limit);
        }
        poll
    }
}

impl Outbox for WriteSide {
    fn idle(&self) -> bool {
        self.writer.is_some()
            && self.out.is_empty()
            && !self.out.shutdown_pending()
            && !self.blocked
    }

    fn write_now(&mut self, budget: usize) -> usize {
        let mut cx = Context::from_waker(Waker::noop());
        let mut written: usize = 0;
        // A message-framed carrier writes whole messages, which may pass
        // the budget: the arithmetic saturates.
        while !self.out.is_empty() && written < budget {
            let limit = self.out.current_call_limit().min(budget - written);
            match self.write_some(&mut cx, limit) {
                Poll::Ready(Ok(n)) if n > 0 => written = written.saturating_add(n),
                // Full, failed or closed: the session task takes over.
                _ => break,
            }
        }
        if self.out.is_empty()
            && self.needs_flush
            && let Some(w) = self.writer.as_mut()
            && let Poll::Ready(Ok(())) = w.poll_flush(&mut cx)
        {
            self.needs_flush = false;
        }
        written
    }

    fn call_limit(&self) -> usize {
        self.out.current_call_limit()
    }

    fn has_work(&self) -> bool {
        !self.out.is_empty() || self.needs_flush || self.out.shutdown_pending()
    }
}

impl WriteSide {
    fn poll_carrier_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let writer = self
            .writer
            .as_mut()
            .expect("writer with a pending shutdown");
        match writer.poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                self.writer = None;
                self.out.shutdown_done();
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

#[derive(Default)]
enum ReadStaging {
    #[default]
    Empty,
    Prefix(Vec<u8>),
    Message(crate::proto::receive::ReceiveBuffer),
}

impl ReadStaging {
    fn poll_message(&mut self, reader: &mut Reader, cx: &mut Context<'_>) -> Poll<ReadOutcome> {
        if !matches!(self, Self::Message(_)) {
            *self = Self::Message(crate::proto::receive::ReceiveBuffer::take(
                super::MESSAGE_READ,
            ));
        }
        let Self::Message(buffer) = self else {
            unreachable!("message target installed");
        };
        let mut out = ReadBuf::new(buffer.space());
        let result = std::task::ready!(Pin::new(reader).poll_read(cx, &mut out));
        let n = out.filled().len();
        let Self::Message(buffer) = std::mem::take(self) else {
            unreachable!("message target installed");
        };
        Poll::Ready(match result {
            Ok(()) if n == 0 => ReadOutcome::Eof,
            Ok(()) => ReadOutcome::Message(buffer.publish(0..n)),
            Err(e) if super::is_empty_message(&e) => ReadOutcome::Message(buffer.publish(0..0)),
            Err(e) => ReadOutcome::Error(e.kind()),
        })
    }
}

struct RetiredRead {
    buffer: BytesMut,
    grant: Option<crate::proto::memory::Reservation>,
}

impl RetiredRead {
    fn give(self) {
        super::read_pool::give(self.buffer, READ_BUFFER);
    }
}

/// The read side of a pipe. The session task reads the carrier, and an
/// application read that finds nothing may read it through itself in a
/// multipath session (R1 to R4 in `super::through`).
///
/// Bytes are read into a shared buffer that the core references for the
/// STREAM data it keeps ([`core::SessionCore::receive_shared`]): stream data
/// goes from the carrier to the application with one copy into the final
/// destination. A buffer the core still references when
/// the next read needs room stays with that data; the next read goes to a
/// buffer of the pool.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent state flags of the read side"
)]
pub(crate) struct ReadSide {
    /// Pipe 0's exporter until its first bytes: read then, without the core
    /// lock, for the core to have before the peer's parameters.
    late: Option<Box<LateExporter>>,
    verdict: Option<Box<VerdictHold>>,
    reader: Option<Reader>,
    /// A reader that ended, dropped once the core lock is released.
    ended: Option<Reader>,
    framing: Framing,
    /// The bytes read and not yet taken by the core (an incomplete record),
    /// in a buffer of the pool while the pipe is active; none while idle.
    buf: BytesMut,
    backing: Backing,
    /// The buffer is a pool buffer an idle pipe took for a burst or a
    /// partial record: it goes back to the pool as soon as it holds
    /// nothing, so idle pipes keep none and the pool's buffers circulate.
    lent: bool,
    /// Recently retired buffers eligible for local reuse. Older roots
    /// survive only when a published range still references them.
    retired: VecDeque<RetiredRead>,
    /// Setup bytes or the target of a pending message read.
    staging: ReadStaging,
    /// The last read; whether it brought [`IDLE_READ`] bytes or more; and
    /// the reads in a row each within [`BURST`] of the last.
    active: Instant,
    large: bool,
    streak: u8,
    /// The last read took all the room it had: the carrier may hold more.
    filled: bool,
    /// The last read may have left bytes in the carrier: it took all its
    /// room, or it returned data and its carrier delivers in parts
    /// ([`ReadSide::partial`]). A read of a socket that found less than
    /// its room drained it.
    left_more: bool,
    /// A read may return less than the carrier holds although it had room
    /// (messages, a stream's chunks, a TLS layer's records): after a read
    /// that returned data, only another read tells whether more is held.
    partial: bool,
    lease: Option<Arc<Attachment>>,
    lane_reader_memory: Option<crate::proto::memory::Reservation>,
}

/// Reads a round of a carrier whose reads may return less than it holds
/// ([`ReadSide::partial`]), at most.
const PARTIAL_READS: usize = 8;

/// Retired handles a reader can keep independently of the core.
const RETIRED_HANDLES: usize = 2;

impl ReadOutcome {
    /// The bytes it brought.
    fn len(&self) -> usize {
        match self {
            Self::Data(n) | Self::Idle(n) => *n,
            Self::Chunk(c) => c.bytes.len(),
            Self::Message(record) => record.as_ref().len(),
            Self::Eof | Self::Error(_) => 0,
        }
    }
}

/// The outcome of one read of a carrier.
pub(crate) enum ReadOutcome {
    /// `n` new bytes in the read buffer.
    Data(usize),
    /// `n` bytes of an idle pipe's read in the thread's
    /// [`IDLE_SCRATCH`], applied by the same thread right after the read.
    Idle(usize),
    /// A chunk of a stream carrier, read without copying.
    Chunk(Segment),
    Message(crate::proto::ReceivedRecord),
    Eof,
    Error(io::ErrorKind),
}

thread_local! {
    /// The buffer an idle pipe reads into first, for the records that
    /// follow the read in the same thread ([`ReadOutcome::Idle`]): a probe
    /// and its acknowledgement are applied without an allocation, and a
    /// quiet pipe holds no read buffer.
    static IDLE_SCRATCH: std::cell::RefCell<[u8; IDLE_READ]> =
        const { std::cell::RefCell::new([0; IDLE_READ]) };
}

/// Room a read of an active pipe wants in its buffer: a record header and
/// more; less and the next read goes to a fresh buffer.
const READ_ROOM: usize = 16 * 1024;

/// Pipe 0's exporter on its way to the core ([`ReadSide::late`]).
enum LateExporter {
    /// Not read yet; a value may have to wait for `ready`.
    Unread {
        exporter: crate::proto::exporter::CarrierExporter,
        ready: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    },
    /// The first bytes arrived before the handshake that gives the value:
    /// they wait here with the read path, nothing else does.
    Waiting {
        exporter: crate::proto::exporter::CarrierExporter,
        ready: Pin<Box<dyn Future<Output = ()> + Send>>,
        outcome: ReadOutcome,
    },
    /// Read with the first bytes; goes to the core with them.
    Read(Option<Vec<u8>>),
}

/// The first bytes of a bootstrap pipe with carrier early data wait for the
/// carrier's verdict to be applied: delivered first, a server's parameters
/// would end the session's chance to restart. The reader is still polled: it
/// may itself deliver the verdict.
struct VerdictHold {
    applied: tokio::sync::oneshot::Receiver<()>,
    outcome: Option<ReadOutcome>,
}

impl ReadSide {
    /// The read side of `reader`, which holds no buffer until it reads;
    /// `prefix` is fed first.
    fn new(reader: Option<Reader>, framing: Framing, prefix: Vec<u8>, partial: bool) -> Self {
        let partial =
            partial || framing == Framing::Records || matches!(reader, Some(Reader::Stream(_)));
        Self {
            late: None,
            verdict: None,
            reader,
            ended: None,
            framing,
            buf: BytesMut::new(),
            backing: Backing { id: 0, size: 0 },
            lent: false,
            retired: VecDeque::new(),
            staging: if prefix.is_empty() {
                ReadStaging::Empty
            } else {
                ReadStaging::Prefix(prefix)
            },
            active: now(),
            large: false,
            streak: 0,
            filled: false,
            left_more: false,
            lease: None,
            lane_reader_memory: None,
            partial,
        }
    }

    /// Makes room for `room` more bytes after what the buffer holds: in
    /// place when nothing else references the buffer, else in a buffer of
    /// the pool that the bytes held move to.
    fn make_room(&mut self, room: usize) {
        if self.buf.capacity() - self.buf.len() >= room {
            return;
        }
        if self.buf.capacity() > 0 && self.buf.try_reclaim(READ_BUFFER - self.buf.len()) {
            self.backing = super::read_pool::renew(&self.buf);
            return;
        }
        // Mostly the oldest is free first; one data never read keeps its
        // buffer, not the others.
        let free = self
            .retired
            .iter_mut()
            .position(|b| b.buffer.try_reclaim(READ_BUFFER));
        let (mut fresh, backing, grant) = if let Some(b) = free.and_then(|i| self.retired.remove(i))
        {
            let backing = super::read_pool::renew(&b.buffer);
            (b.buffer, backing, b.grant)
        } else {
            let (buf, backing) = super::read_pool::take();
            (buf, backing, None)
        };
        fresh.extend_from_slice(&self.buf);
        let mut old = std::mem::replace(&mut self.buf, fresh);
        // Its bytes moved to the new buffer: the handle keeps nothing, so
        // that the whole buffer can be reclaimed once the core lets go.
        old.clear();
        // A handle of a whole buffer (however little of it is left to
        // it), to reclaim it by.
        if std::mem::replace(&mut self.backing, backing).size >= READ_BUFFER {
            self.recycle_later(old, grant);
        }
        self.lent = false;
    }

    fn recycle_later(
        &mut self,
        buffer: BytesMut,
        grant: Option<crate::proto::memory::Reservation>,
    ) {
        let evicted = if self.retired.len() == RETIRED_HANDLES {
            let mut old = self.retired.pop_front().expect("full retire cache");
            let grant = old.grant.take();
            old.give();
            grant
        } else {
            None
        };
        let grant = if let Some(grant) = grant.or(evicted) {
            Some(grant)
        } else if let Some(owner) = self
            .lane_reader_memory
            .as_ref()
            .or_else(|| self.lease.as_deref().and_then(Attachment::reader_memory))
        {
            let Some(grant) = owner.domain().reserve_growth(READ_BUFFER as u64) else {
                super::read_pool::give(buffer, READ_BUFFER);
                return;
            };
            Some(grant)
        } else {
            None
        };
        self.retired.push_back(RetiredRead { buffer, grant });
    }

    /// Reads once (the prefix first). Without a read buffer (an idle pipe)
    /// it reads into a small stack buffer first.
    fn poll_once(&mut self, cx: &mut Context<'_>, max: usize) -> Poll<ReadOutcome> {
        let Some(reader) = self.reader.as_mut() else {
            return Poll::Pending;
        };
        if matches!(self.staging, ReadStaging::Prefix(_)) {
            let ReadStaging::Prefix(prefix) = std::mem::take(&mut self.staging) else {
                unreachable!("setup prefix present");
            };
            return Poll::Ready(if self.framing == Framing::Records {
                ReadOutcome::Message(crate::proto::ReceivedRecord::from_vec(prefix))
            } else if matches!(reader, Reader::Stream(_)) {
                ReadOutcome::Chunk(Segment {
                    backing: Backing::new(prefix.capacity()),
                    bytes: Bytes::from(prefix),
                })
            } else {
                self.make_room(prefix.len().max(READ_ROOM));
                self.buf.extend_from_slice(&prefix);
                ReadOutcome::Data(prefix.len())
            });
        }
        if self.framing == Framing::Records {
            if let Reader::Sealed(reader) = reader {
                return reader
                    .as_mut()
                    .get_mut()
                    .poll_record(cx)
                    .map(|result| match result {
                        Ok(Some(record)) => ReadOutcome::Message(record),
                        Ok(None) => ReadOutcome::Eof,
                        Err(e) => ReadOutcome::Error(e.kind()),
                    });
            }
            if matches!(reader, Reader::Stream(_)) {
                return Poll::Ready(ReadOutcome::Error(io::ErrorKind::InvalidData));
            }
            return self.staging.poll_message(reader, cx);
        }
        if let Reader::Stream(stream) = reader {
            return stream
                .poll_chunk(cx, max.min(READ_BUFFER))
                .map(|r| match r {
                    Ok(Some(chunk)) => ReadOutcome::Chunk(chunk),
                    Ok(None) => ReadOutcome::Eof,
                    Err(e) => ReadOutcome::Error(e.kind()),
                });
        }
        // An idle pipe reads into a small stack buffer first; reads in a
        // burst ([`BURST`]) go to a full buffer.
        let burst = (self.large || self.streak.saturating_add(1) >= BURST_READS)
            && now().saturating_duration_since(self.active) < BURST;
        if self.buf.capacity() == 0 && !burst {
            let read = IDLE_SCRATCH.with_borrow_mut(|stack| {
                let mut rb = ReadBuf::new(&mut stack[..]);
                match Pin::new(&mut *reader).poll_read(cx, &mut rb) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(r) => Poll::Ready(r.map(|()| rb.filled().len())),
                }
            });
            let Poll::Ready(r) = read else {
                return Poll::Pending;
            };
            return Poll::Ready(match r {
                Ok(0) => ReadOutcome::Eof,
                // Probably whole records (a probe, its acknowledgement):
                // applied from the scratch buffer as they are.
                Ok(n) if n < IDLE_READ => {
                    // No buffer of the pipe's holds these bytes.
                    self.backing = Backing { id: 0, size: 0 };
                    ReadOutcome::Idle(n)
                }
                // A full scratch buffer is the start of more, which goes to
                // a full buffer of the pool, lent until it holds nothing.
                Ok(n) => {
                    self.make_room(READ_BUFFER);
                    IDLE_SCRATCH.with_borrow(|stack| self.buf.extend_from_slice(&stack[..n]));
                    self.lent = true;
                    self.filled = true;
                    ReadOutcome::Data(n)
                }
                Err(e) => ReadOutcome::Error(e.kind()),
            });
        }
        let limit = max.max(1);
        self.make_room(READ_ROOM);
        let space = (self.buf.capacity() - self.buf.len()).min(limit);
        let Some(reader) = self.reader.as_mut() else {
            return Poll::Pending;
        };
        let before = self.buf.len();
        let result = {
            let mut limited = (&mut self.buf).limit(limit);
            let read = tokio::io::AsyncReadExt::read_buf(reader, &mut limited);
            match std::pin::pin!(read).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r,
            }
        };
        debug_assert!(
            result
                .as_ref()
                .map_or(true, |&n| self.buf.len() == before + n)
        );
        Poll::Ready(match result {
            Ok(0) => ReadOutcome::Eof,
            Ok(n) => {
                self.filled = n >= space;
                ReadOutcome::Data(n)
            }
            Err(e) => ReadOutcome::Error(e.kind()),
        })
    }

    /// One read that goes on waiting, past other tasks' reads: the bytes in
    /// the shared scratch buffer move to the pipe's own.
    fn keep(&mut self, outcome: ReadOutcome) -> ReadOutcome {
        let ReadOutcome::Idle(n) = outcome else {
            return outcome;
        };
        self.make_room(n.max(READ_ROOM));
        IDLE_SCRATCH.with_borrow(|stack| self.buf.extend_from_slice(&stack[..n]));
        ReadOutcome::Data(n)
    }

    /// A read, whose first bytes wait for the exporter's handshake if the
    /// value needs it.
    fn poll_exporter(&mut self, cx: &mut Context<'_>, max: usize) -> Poll<ReadOutcome> {
        if !matches!(self.late.as_deref(), Some(LateExporter::Waiting { .. })) {
            let outcome = self.poll_once(cx, max);
            let Some(late) = self.late.as_deref_mut() else {
                return outcome;
            };
            if !matches!(late, LateExporter::Unread { .. })
                || !matches!(
                    outcome,
                    Poll::Ready(
                        ReadOutcome::Data(_)
                            | ReadOutcome::Idle(_)
                            | ReadOutcome::Chunk(_)
                            | ReadOutcome::Message(_)
                    )
                )
            {
                return outcome;
            }
            let LateExporter::Unread { exporter, ready } =
                std::mem::replace(late, LateExporter::Read(None))
            else {
                unreachable!();
            };
            let Poll::Ready(read) = outcome else {
                unreachable!();
            };
            let value = exporter.session_value();
            match ready {
                Some(ready) if value.is_none() => {
                    *late = LateExporter::Read(None);
                    let outcome = self.keep(read);
                    self.late = Some(Box::new(LateExporter::Waiting {
                        exporter,
                        ready,
                        outcome,
                    }));
                }
                _ => {
                    *late = LateExporter::Read(value);
                    return Poll::Ready(read);
                }
            }
        }
        let Some(LateExporter::Waiting { ready, .. }) = self.late.as_deref_mut() else {
            unreachable!();
        };
        std::task::ready!(ready.as_mut().poll(cx));
        let Some(LateExporter::Waiting {
            exporter, outcome, ..
        }) = self.late.take().map(|l| *l)
        else {
            unreachable!();
        };
        // None: the handshake failed, which ends the read.
        Poll::Ready(match exporter.session_value() {
            Some(v) => {
                self.late = Some(Box::new(LateExporter::Read(Some(v))));
                outcome
            }
            None => ReadOutcome::Error(io::ErrorKind::ConnectionAborted),
        })
    }

    /// Hands what a read produced to the core: the buffered bytes for a
    /// byte stream (an incomplete record stays), one message for a message
    /// carrier, or the carrier's end.
    fn apply(&mut self, outcome: ReadOutcome, id: LaneId, st: &mut State<Tokio>, now: Instant) {
        if matches!(self.late.as_deref(), Some(LateExporter::Read(_)))
            && let Some(LateExporter::Read(Some(v))) = self.late.take().map(|l| *l)
        {
            st.core.set_bootstrap_exporter_value(v);
        }
        self.streak = if now.saturating_duration_since(self.active) < BURST {
            self.streak.saturating_add(1)
        } else {
            1
        };
        self.active = now;
        self.large = match &outcome {
            ReadOutcome::Data(n) => *n >= IDLE_READ,
            ReadOutcome::Chunk(c) => c.bytes.len() >= IDLE_READ,
            ReadOutcome::Message(record) => record.as_ref().len() >= IDLE_READ,
            ReadOutcome::Idle(_) | ReadOutcome::Eof | ReadOutcome::Error(_) => false,
        };
        self.left_more = match &outcome {
            ReadOutcome::Data(_) | ReadOutcome::Chunk(_) | ReadOutcome::Message(_) => {
                self.filled || self.partial
            }
            ReadOutcome::Idle(_) | ReadOutcome::Eof | ReadOutcome::Error(_) => false,
        };
        match outcome {
            ReadOutcome::Chunk(chunk) => st.core.receive_segment(id, &chunk, now),
            ReadOutcome::Message(record) => st.core.receive_message(id, record, now),
            ReadOutcome::Idle(n) => IDLE_SCRATCH.with_borrow(|stack| {
                let data = &stack[..n];
                let used = st.core.receive_in_place(id, data, now);
                if used < n {
                    // An incomplete record waits in a buffer of its size
                    // for the rest.
                    self.buf = BytesMut::from(&data[used..]);
                    self.backing = super::read_pool::renew(&self.buf);
                }
            }),
            ReadOutcome::Data(_) => {
                let data = self.buf.split().freeze();
                let used = st.core.receive_buffer(id, &data, self.backing, now);
                let left = &data[used..];
                if !left.is_empty() {
                    if left.len() >= READ_BUFFER {
                        // Cannot happen: records are smaller than the
                        // buffer.
                        st.core
                            .pipe_ended(id, PipeEnd::Error(io::ErrorKind::InvalidData), now);
                        self.ended = self.reader.take();
                        return;
                    }
                    // An incomplete record continues at the buffer's start.
                    self.make_room(left.len().max(READ_ROOM));
                    self.buf.extend_from_slice(left);
                }
                drop(data);
                if self.backing.size < READ_BUFFER && self.buf.is_empty() && !self.lent {
                    // The small buffer of an idle pipe's read: gone once
                    // its records are taken.
                    self.buf = BytesMut::new();
                    self.backing = Backing { id: 0, size: 0 };
                } else if self.lent && self.buf.is_empty() {
                    // Back to the pool once the core lets go of it.
                    self.lent = false;
                    let old = std::mem::take(&mut self.buf);
                    self.backing = Backing { id: 0, size: 0 };
                    self.recycle_later(old, None);
                }
            }
            ReadOutcome::Eof => {
                st.core.pipe_ended(id, PipeEnd::Eof, now);
                self.ended = self.reader.take();
            }
            ReadOutcome::Error(kind) => {
                st.core.pipe_ended(id, PipeEnd::Error(kind), now);
                self.ended = self.reader.take();
            }
        }
    }
}

impl Drop for ReadSide {
    /// A closed pipe's buffers go back to the pool.
    fn drop(&mut self) {
        super::read_pool::give(std::mem::take(&mut self.buf), self.backing.size);
        for b in self.retired.drain(..) {
            b.give();
        }
    }
}

impl Carrier for ReadSide {
    type Outcome = ReadOutcome;

    fn poll_read(&mut self, cx: &mut Context<'_>, max: usize) -> Poll<ReadOutcome> {
        if self.verdict.is_none() {
            return self.poll_exporter(cx, max);
        }
        if self.verdict.as_ref().is_some_and(|h| h.outcome.is_none()) {
            let read = std::task::ready!(self.poll_exporter(cx, max));
            if matches!(read, ReadOutcome::Eof | ReadOutcome::Error(_)) {
                self.verdict = None;
                return Poll::Ready(read);
            }
            let kept = self.keep(read);
            if let Some(h) = self.verdict.as_deref_mut() {
                h.outcome = Some(kept);
            }
        }
        let Some(h) = self.verdict.as_deref_mut() else {
            unreachable!();
        };
        // Sent or dropped, the verdict was applied or never will be.
        let _ = std::task::ready!(Pin::new(&mut h.applied).poll(cx));
        let outcome = h.outcome.take();
        self.verdict = None;
        match outcome {
            Some(o) => Poll::Ready(o),
            None => unreachable!(),
        }
    }

    fn outcome_bytes(outcome: &ReadOutcome) -> usize {
        outcome.len()
    }

    fn is_open(&self) -> bool {
        self.reader.is_some()
    }

    fn release(&mut self) {
        self.ended = None;
    }
}

/// One pipe's I/O inside the session task.
/// A carrier's source of its handshake's state.
type TlsStateFn = Arc<dyn Fn() -> Option<crate::TlsState> + Send + Sync>;

pub(crate) struct PipeTask {
    id: PipeId,
    /// What only some carriers report: their socket's and layers' queries.
    queries: Option<Box<PipeQueries>>,
    read: Arc<ReadPath<ReadSide>>,
    write: Arc<WritePath<WriteSide>>,
    /// The write side is closed (mirrors `WriteSide::writer`, which only
    /// the session task closes).
    write_closed: bool,
    abort: Option<Box<dyn FnOnce() + Send>>,
    /// The last write.
    active: Instant,
    /// The read side was busy this round (H1 in `super::through`).
    read_skipped: bool,
    /// The write side was busy this round.
    write_skipped: bool,
    /// A close of a busy side waits (H1 with `run`): inbound, outbound.
    close_deferred: [bool; 2],
    /// What the writes without the core lock found, for the core: their
    /// progress, or a failure of the write side.
    progress: Progress,
    /// The write side failed, with this kind of error.
    failed: Option<io::ErrorKind>,
    /// The pipe's lanes other than lane 0, allocated for a carrier that
    /// can open them or with the first one the peer opens.
    lanes: Option<Box<PipeLanes>>,
    /// The carrier's [`PipeIo::with_close_code`] hook, with the code
    /// [`PipeTask::tell_close_code`] set (0 without it). Declared after
    /// the carrier's halves and lanes, so that it is called once they are
    /// dropped: when the task drops the pipe, after the lock.
    close_code: Option<TellCloseCode>,
    /// The carrier's [`PipeIo::with_drain`] future, armed by a graceful
    /// end of the sending half; dropped after the halves too.
    drain: Option<Box<Drain>>,
    attachment: Arc<Attachment>,
    _live: Live,
}

/// The queries of a carrier that answers them (a TCP socket, a layer that
/// counts its unsent bytes).
#[derive(Default)]
struct PipeQueries {
    probe: Option<Probe>,
    unsent: Option<UnsentQuery>,
    /// The carrier has a low-water mark: a carrier that refuses bytes may
    /// hold up to the mark plus the last write unsent.
    low_water: bool,
}

/// A pipe's lanes: how to open more, the framing they share with lane 0,
/// and the lanes.
struct PipeLanes {
    opener: Option<LaneOpener>,
    framing: Framing,
    list: Vec<LaneTask>,
    /// The lane that offers to take a batch first next time: the one
    /// after the last that took one, so that lanes share what the pipe's
    /// limiter and the carrier's room let through in turns rather than in
    /// a fixed order that starves the last lanes.
    next: usize,
}

/// A lane of a pipe other than lane 0: a stream of lane 0's connection,
/// read or written by the session task alone (the application's fast
/// paths go through lane 0).
struct LaneTask {
    lane: u64,
    read: Option<ReadSide>,
    write: Option<WriteSide>,
    /// The unused receiving part of an outbound lane's bidirectional
    /// stream, kept with it.
    keep: Option<StreamReader>,
    drain: Option<Box<Drain>>,
    /// Its count among the lanes on an outer session, while it lives.
    _outer: Option<super::lanes::OuterLane>,
    progress: Progress,
    /// The write side failed, with this kind of error.
    failed: Option<io::ErrorKind>,
    /// The lane's unsent query.
    unsent: Option<UnsentQuery>,
    _lease: Option<Arc<Attachment>>,
}

impl LaneTask {
    fn new(lane: NewLane) -> Self {
        let read = lane.read.map(|(reader, prefix)| {
            let mut side = ReadSide::new(Some(reader), lane.framing, prefix, lane.partial);
            side.lane_reader_memory = lane.reader_memory;
            side
        });
        let (write, keep, outer, unsent, drain) = match lane.write {
            Some(mut w) => {
                w.writer.set_workspace(lane.writer_memory.clone());
                (
                    Some(WriteSide {
                        writer: Some(w.writer),
                        _lease: None,
                        restart: None,
                        out: Outbound::new(lane.framing, Calls::NonBlocking)
                            .with_workspace(lane.writer_memory),
                        cursor: PieceCursor::default(),
                        needs_flush: false,
                        blocked: false,
                    }),
                    w.keep,
                    w.outer,
                    w.unsent.map(|q| UnsentQuery::new(q, now())),
                    w.drain,
                )
            }
            None => (None, None, None, None, None),
        };
        Self {
            drain,
            lane: lane.at.lane.0,
            _lease: lane.attachment,
            read,
            write,
            keep,
            _outer: outer,
            progress: Progress::default(),
            failed: None,
            unsent,
        }
    }

    fn finished(&self) -> bool {
        self.read.as_ref().is_none_or(|r| r.reader.is_none())
            && self.write.as_ref().is_none_or(|w| w.writer.is_none())
    }

    /// Reads the lane once: whether it read, and whether the read left
    /// bytes in the carrier.
    fn poll_read(
        &mut self,
        at: LaneId,
        shared: &Shared<Tokio>,
        cx: &mut Context<'_>,
    ) -> (bool, bool) {
        let Some(rs) = self.read.as_mut() else {
            return (false, false);
        };
        let (mut read, mut left, mut bytes) = (false, false, 0);
        for _ in 0..PARTIAL_READS {
            let Poll::Ready(outcome) = rs.poll_once(cx, READ_BUFFER) else {
                // Found empty: nothing is left in the carrier.
                left = false;
                break;
            };
            bytes += outcome.len();
            let mut st = shared.lock();
            let now = st.now();
            rs.apply(outcome, at, &mut st, now);
            st.dispatch();
            drop(st);
            // A reader that ended goes after the lock.
            rs.ended = None;
            read = true;
            left = rs.left_more;
            if !(left && rs.partial) || bytes >= READ_BUFFER {
                break;
            }
        }
        (read, left)
    }

    /// One write call of the lane's batch, or its shutdown, without the
    /// core lock (as [`PipeTask::write_out`]); whether it made progress.
    fn write_out(
        &mut self,
        at: LaneId,
        shared: &Shared<Tokio>,
        cx: &mut Context<'_>,
        input: bool,
        clock: &crate::ClockDomain,
    ) -> bool {
        let Some(ws) = self.write.as_mut() else {
            return false;
        };
        if ws.writer.is_none() {
            return false;
        }
        if ws.out.is_empty() {
            if ws.out.shutdown_pending() {
                return match ws.poll_carrier_shutdown(cx) {
                    Poll::Ready(Ok(())) => {
                        PipeIo::arm_drain(&mut self.drain);
                        true
                    }
                    Poll::Ready(Err(error)) => self.fail(error.kind()),
                    Poll::Pending => false,
                };
            }
            if let Some(Writer::Stream(w)) = &mut ws.writer
                && let Err(e) = w.watch(cx)
            {
                return self.fail(e.kind());
            }
            if ws.needs_flush
                && let Some(w) = ws.writer.as_mut()
                && let Poll::Ready(r) = w.poll_flush(cx)
            {
                ws.needs_flush = false;
                if let Err(e) = r {
                    return self.fail(e.kind());
                }
            }
            return false;
        }
        let now = clock.now_with(now);
        let limit = ws.out.call_limit(input, now, |left| {
            let st = shared.lock();
            let pending = input || st.io.input_pending;
            (
                st.core.write_call_limit(at.pipe, left, false, pending, now),
                st.core.latency_budget(),
            )
        });
        match ws.write_some(cx, limit) {
            Poll::Ready(Ok(w)) if w > 0 => {
                ws.blocked = false;
                self.progress.returned(now, now, w, false);
                true
            }
            Poll::Ready(r) => self.fail(write_error(r)),
            Poll::Pending => {
                ws.blocked = true;
                self.progress.returned(now, now, 0, true);
                false
            }
        }
    }

    /// The lane's write side failed or ended under it: closed, and the core
    /// told in the next critical section.
    fn fail(&mut self, kind: io::ErrorKind) -> bool {
        if let Some(ws) = self.write.as_mut() {
            ws.writer = None;
            ws.out.clear();
        }
        self.failed = Some(kind);
        true
    }

    /// Closes the lane's half (its pipe's closes; an abort resets it).
    fn close(&mut self, half: PipeHalf, abort: bool) {
        if abort
            && half == PipeHalf::Outbound
            && let Some(drain) = &mut self.drain
        {
            drain.armed = false;
        }
        match half {
            PipeHalf::Inbound => {
                if let Some(rs) = self.read.as_mut() {
                    rs.reader = None;
                }
            }
            PipeHalf::Outbound => {
                if let Some(ws) = self.write.as_mut() {
                    ws.writer = None;
                    ws.out.clear();
                }
                self.keep = None;
            }
        }
    }
}

impl PipeTask {
    /// The session is done with this pipe's carrier: its close-code hook
    /// gets the session's code once the session is closing, and 0 for a
    /// pipe that left a session that goes on, when the pipe is dropped.
    fn tell_close_code(&mut self, st: &State<Tokio>) {
        if let Some(t) = &mut self.close_code
            && st.core.state() >= CoreState::Closing
        {
            t.1 = close_code_of(st.core.error());
        }
    }

    /// The first bytes wait until the returned sender is used or dropped.
    fn hold_reads_for_verdict(&mut self) -> tokio::sync::oneshot::Sender<()> {
        let (tx, applied) = tokio::sync::oneshot::channel();
        if let Some(mut rs) = self.read.try_side() {
            rs.verdict = Some(Box::new(VerdictHold {
                applied,
                outcome: None,
            }));
        }
        tx
    }

    /// The carrier's restart after a rejection of its early data.
    fn set_restart(&mut self, restart: EarlyRestart) {
        if let Some(mut ws) = self.write.try_side() {
            ws.restart = Some((restart, 0));
        }
    }
}

impl PipeTask {
    /// The task of pipe `id`; a TCP carrier's low-water mark is `lowat` now.
    fn new(id: PipeId, mut io: PipeIo, lowat: u64) -> Self {
        let late_exporter = if id == PipeId(0) {
            io.exporter.take()
        } else {
            None
        };
        let queries = PipeQueries {
            probe: io.socket.map(|s| Probe::new(s, lowat, now())),
            unsent: io.unsent.map(|q| UnsentQuery::new(q, now())),
            low_water: io.low_water,
        };
        let some = queries.probe.is_some() || queries.unsent.is_some() || queries.low_water;
        let workspace = io
            .attachment
            .as_deref()
            .and_then(Attachment::writer_memory)
            .cloned();
        if let Some(writer) = &mut io.writer {
            writer.set_workspace(workspace.clone());
        }
        Self {
            id,
            queries: some.then(|| Box::new(queries)),
            read: Arc::new(ReadPath::new({
                let mut side = ReadSide::new(io.reader, io.framing, io.prefix, io.partial_reads);
                side.lease.clone_from(&io.attachment);
                let ready = io.exporter_ready.take();
                side.late = late_exporter
                    .map(|exporter| Box::new(LateExporter::Unread { exporter, ready }));
                side
            })),
            write_closed: io.writer.is_none(),
            write: Arc::new(WritePath::new(WriteSide {
                writer: io.writer,
                _lease: io.attachment.clone(),
                restart: None,
                out: Outbound::new(io.framing, Calls::NonBlocking).with_workspace(workspace),
                cursor: PieceCursor::default(),
                needs_flush: false,
                blocked: false,
            })),
            abort: io.abort,
            close_code: io.close_code,
            drain: io.drain,
            attachment: io.attachment.unwrap_or_default(),
            active: now(),
            read_skipped: false,
            write_skipped: false,
            close_deferred: [false; 2],
            progress: Progress::default(),
            failed: None,
            lanes: io.lanes.and_then(|l| l.opener).map(|opener| {
                Box::new(PipeLanes {
                    opener: Some(opener),
                    framing: io.framing,
                    list: Vec::new(),
                    next: 0,
                })
            }),
            _live: Live::new(Kind::Pipe),
        }
    }

    fn finished(&self) -> bool {
        self.read.is_closed()
            && self.write_closed
            && self
                .lanes
                .as_ref()
                .is_none_or(|l| l.list.iter().all(LaneTask::finished))
    }

    /// The pipe has lanes other than lane 0.
    #[inline]
    fn has_lanes(&self) -> bool {
        self.lanes.as_ref().is_some_and(|l| !l.list.is_empty())
    }

    /// Takes over a lane opened or accepted.
    fn add_lane(&mut self, lane: NewLane) {
        let framing = lane.framing;
        self.lanes
            .get_or_insert_with(|| {
                Box::new(PipeLanes {
                    opener: None,
                    framing,
                    list: Vec::new(),
                    next: 0,
                })
            })
            .list
            .push(LaneTask::new(lane));
    }

    /// Step 1 of the unsent queries of the pipe and its lanes, without
    /// the core lock: whether any ran.
    fn query_unsent(&mut self, now: Instant) -> bool {
        let queries = self.queries.as_deref_mut();
        let mut ran = queries
            .and_then(|q| q.unsent.as_mut())
            .is_some_and(|q| q.query(now));
        for l in self.lanes_mut() {
            ran |= l.unsent.as_mut().is_some_and(|q| q.query(now));
        }
        ran
    }

    /// Step 2, under the core lock: the counts go to the core.
    fn feed_unsent(&mut self, core: &mut crate::proto::session::SessionCore, now: Instant) {
        let id = self.id;
        if let Some(q) = self.queries.as_deref_mut().and_then(|q| q.unsent.as_mut()) {
            q.feed(core, id.into(), now);
        }
        for l in self.lanes_mut() {
            if let Some(q) = &mut l.unsent {
                q.feed(core, id.lane(l.lane), now);
            }
        }
    }

    /// The pipe's lanes.
    fn lanes_mut(&mut self) -> &mut [LaneTask] {
        self.lanes.as_deref_mut().map_or(&mut [], |l| &mut l.list)
    }

    /// Reads and writes the pipe's other lanes once each
    /// (every lane in turn, none starving another): whether any read left bytes in its carrier, and whether
    /// any made progress.
    fn poll_lanes(
        &mut self,
        shared: &Shared<Tokio>,
        cx: &mut Context<'_>,
        input: bool,
        clock: &crate::ClockDomain,
    ) -> (bool, bool) {
        let (mut pending, mut progress) = (false, false);
        let id = self.id;
        for l in self.lanes_mut() {
            let at = id.lane(l.lane);
            let (read, left) = l.poll_read(at, shared, cx);
            pending |= left;
            progress |= read | l.write_out(at, shared, cx, input || pending, clock);
        }
        (pending, progress)
    }

    /// With the core locked: the lanes' write progress and failures.
    fn report_lanes(&mut self, st: &mut State<Tokio>, now: Instant) {
        let id = self.id;
        for l in self.lanes_mut() {
            let at = id.lane(l.lane);
            let written = l.write.as_mut().is_some_and(|ws| {
                if l.failed.is_some() || ws.writer.is_none() {
                    ws.out.cancel(&mut st.core, at, now)
                } else {
                    ws.out.tell(&mut st.core, at, now)
                }
            });
            if l.progress.report(&mut st.core, at, false, now) || written {
                st.dispatch();
            }
            if let Some(kind) = l.failed.take() {
                st.core.write_failed(at, kind, now);
                st.dispatch();
            }
        }
    }

    /// With the core locked: the next batch of each lane whose last one is
    /// written; whether one was taken. Lanes whose halves are closed go to
    /// the work after the lock (what is left of their streams is dropped
    /// there).
    fn before_wait_lanes(&mut self, st: &mut State<Tokio>, now: Instant) -> bool {
        let mut more = false;
        let id = self.id;
        let Some(lanes) = self.lanes.as_deref_mut() else {
            return false;
        };
        // Lane 0 took its batch first
        // (`before_wait`), then the copy lane, then the data lanes in
        // turns, starting after the one that last took a batch.
        let copy = st.core.copy_lane(id);
        let copy = lanes.list.iter().position(|l| Some(l.lane) == copy);
        let mut next = lanes.next;
        for i in in_turn(lanes.list.len(), copy, next) {
            let l = &mut lanes.list[i];
            let at = id.lane(l.lane);
            if let Some(ws) = l.write.as_mut()
                && ws.out.is_empty()
                && !ws.out.shutdown_pending()
                && take_batch(ws, at, st, now)
            {
                more = true;
                if Some(i) != copy {
                    next = i + 1;
                }
            }
        }
        lanes.next = next;
        for lane in lanes.list.extract_if(.., |l| l.finished()) {
            st.deferred.push(lane);
        }
        more
    }

    /// Reads once (R2 in `super::through`); returns whether anything
    /// happened, and whether the read left bytes in the carrier. A side an
    /// application reads through is skipped.
    ///
    /// A carrier whose reads may return less than it holds
    /// ([`ReadSide::partial`]) is read again at once after it delivered,
    /// up to [`PARTIAL_READS`] reads or [`READ_BUFFER`] bytes a round:
    /// input is pending only while it still delivers, and the next write call is built knowing it.
    fn poll_read(&mut self, shared: &Shared<Tokio>, cx: &mut Context<'_>) -> (bool, bool) {
        let id = self.id;
        let mut datagrams = false;
        let (mut read, mut left, mut bytes) = (false, false, 0);
        for _ in 0..PARTIAL_READS {
            let mut again = false;
            let polled = self
                .read
                .poll_task(&shared.inner, cx.waker(), |rs, outcome, st| {
                    bytes += outcome.len();
                    rs.apply(outcome, id.into(), st, st.now());
                    st.dispatch();
                    datagrams |= st.core.has_received_datagrams();
                    left = rs.left_more;
                    again = left && rs.partial && bytes < READ_BUFFER;
                });
            match polled {
                Polled::Read => read = true,
                // Found empty (or closed): nothing is left in the carrier.
                Polled::Idle => left = false,
                // An application reads through: it reports what it leaves.
                Polled::Busy => self.read_skipped = true,
            }
            if !again {
                break;
            }
        }
        if datagrams {
            drop(shared.police_datagrams(shared.lock()));
        }
        (read, left)
    }

    /// Frees the buffers of an idle pipe: its read buffers once reads
    /// stopped for a burst's gap (an idle pipe reads into a small buffer
    /// first), its write buffers after [`IDLE_RELEASE`] (a small batch's
    /// at once); returns when to
    /// check again while they are held. A side in use is not idle.
    fn release_idle(&mut self, now: Instant) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut at = |t: Instant| next = Some(next.map_or(t, |n| n.min(t)));
        if let Some(mut rs) = self.read.try_side()
            && rs.buf.is_empty()
            && (rs.buf.capacity() > 0
                || !rs.retired.is_empty()
                || rs.reader.as_ref().is_some_and(Reader::idle_buffer))
        {
            let due = rs.active + BURST;
            if now < due {
                at(due);
            } else {
                let capacity = rs.backing.size;
                super::read_pool::give(std::mem::take(&mut rs.buf), capacity);
                // The list's own storage goes too.
                for b in std::mem::take(&mut rs.retired) {
                    b.give();
                }
                rs.backing = Backing { id: 0, size: 0 };
                rs.lent = false;
                if let Some(r) = rs.reader.as_mut() {
                    r.release_idle();
                }
            }
        }
        if let Some(mut ws) = self.write.try_side()
            && ws.out.is_empty()
            && ws.out.capacity() > 0
        {
            let due = self.active + IDLE_RELEASE;
            if ws.out.is_small() {
                // A small batch's storage goes to the thread's spares at
                // once: a quiet pipe holds none, and arms no timer for it.
                ws.out.release();
            } else if now < due {
                at(due);
            } else {
                ws.out.release();
            }
        }
        // A Sealed writer's unit and expanded key go after the same idle
        // time: a pipe of small batches keeps them while it writes.
        if let Some(mut ws) = self.write.try_side()
            && ws.out.is_empty()
            && ws.writer.as_ref().is_some_and(Writer::idle_held)
        {
            let due = self.active + IDLE_RELEASE;
            if now < due {
                at(due);
            } else if let Some(w) = ws.writer.as_mut() {
                w.release_idle();
            }
        }
        next
    }

    /// With the core locked, before the session task decides whether it
    /// waits (W3 and H1 in `super::through`), in two passes over the
    /// pipes: [`PipeTask::report`] tells the core what the writes found,
    /// then [`PipeTask::before_wait`] takes the next batch when the write
    /// side is free and re-polls a side skipped this round that is free
    /// now, returning whether the task has work.
    fn report(&mut self, st: &mut State<Tokio>, now: Instant) {
        let id = self.id;
        // A side an application writes through tells the core itself.
        let written = self.write.try_side().is_some_and(|mut ws| {
            if self.failed.is_some() || ws.writer.is_none() {
                ws.out.cancel(&mut st.core, id, now)
            } else {
                ws.out.tell(&mut st.core, id, now)
            }
        });
        let low_water = self.queries.as_deref().is_some_and(|q| q.low_water);
        if self.progress.report(&mut st.core, id, low_water, now) || written {
            st.dispatch();
        }
        if let Some(kind) = self.failed.take() {
            st.core.write_failed(id, kind, now);
            st.dispatch();
        }
    }

    /// With the core locked, after every pipe's [`PipeTask::report`]: the
    /// rest of [`PipeTask::under_lock`]'s work, which a report of another
    /// pipe may have changed (a pipe that stops being writable moves new
    /// data to the others).
    fn before_wait(&mut self, st: &mut State<Tokio>, now: Instant) -> bool {
        let id = self.id;
        let [read_close, write_close] = std::mem::take(&mut self.close_deferred);
        let mut more = self.write.take_before_wait(
            st,
            std::mem::take(&mut self.write_skipped),
            write_close,
            |ws, st| take_batch(ws, id, st, now),
        );
        if std::mem::take(&mut self.read_skipped) || read_close {
            more |= self.read.recheck_before_wait(read_close);
        }
        more
    }

    /// Writes the current batch, one call, without the core lock (W1 in
    /// `super::through`); when it is done, the shutdown or flush it ends
    /// with. `input`: a read this round left bytes in its carrier. What
    /// the core must learn is kept for the next critical section. A side
    /// an application writes through is skipped.
    fn write_out(
        &mut self,
        shared: &Shared<Tokio>,
        cx: &mut Context<'_>,
        input: bool,
        clock: &crate::ClockDomain,
    ) -> bool {
        let id = self.id;
        let Some(mut ws) = self.write.try_side() else {
            self.write_skipped = true;
            return false;
        };
        if ws.writer.is_none() {
            return false;
        }
        if ws.out.is_empty() {
            if ws.out.shutdown_pending() {
                return match ws.poll_carrier_shutdown(cx) {
                    Poll::Ready(Ok(())) => {
                        self.write_closed = true;
                        PipeIo::arm_drain(&mut self.drain);
                        true
                    }
                    Poll::Ready(Err(error)) => {
                        Self::fail_write(ws, &mut self.write_closed, &mut self.failed, error.kind())
                    }
                    Poll::Pending => false,
                };
            }
            // An idle stream carrier is watched for its end: a STOP_SENDING
            // or the end of its session fails the pipe at once, not at its
            // next write.
            if let Some(Writer::Stream(w)) = &mut ws.writer
                && let Err(e) = w.watch(cx)
            {
                return Self::fail_write(ws, &mut self.write_closed, &mut self.failed, e.kind());
            }
            if ws.needs_flush
                && let Some(w) = ws.writer.as_mut()
                && let Poll::Ready(r) = w.poll_flush(cx)
            {
                ws.needs_flush = false;
                if let Err(e) = r {
                    return Self::fail_write(
                        ws,
                        &mut self.write_closed,
                        &mut self.failed,
                        e.kind(),
                    );
                }
            }
            return false;
        }
        // Whether latency-sensitive work waits is decided anew for each
        // call, or within the latency budget
        // of the last decision.
        let now = clock.now_with(now);
        let limit = ws.out.call_limit(input, now, |left| {
            let st = shared.lock();
            let pending = input || st.io.input_pending;
            (
                st.core.write_call_limit(id, left, false, pending, now),
                st.core.latency_budget(),
            )
        });
        match ws.write_some(cx, limit) {
            Poll::Ready(Ok(w)) if w > 0 => {
                self.active = now;
                ws.blocked = false;
                self.progress.returned(now, now, w, false);
                true
            }
            Poll::Ready(r) => {
                Self::fail_write(ws, &mut self.write_closed, &mut self.failed, write_error(r))
            }
            Poll::Pending => {
                ws.blocked = true;
                self.progress.returned(now, now, 0, true);
                false
            }
        }
    }

    /// The carrier's write side failed or ended under the pipe: closed, and
    /// the core told in the next critical section.
    fn fail_write(
        mut ws: TryMutexGuard<'_, WriteSide>,
        write_closed: &mut bool,
        failed: &mut Option<io::ErrorKind>,
        kind: io::ErrorKind,
    ) -> bool {
        ws.writer = None;
        ws.out.clear();
        drop(ws);
        *write_closed = true;
        *failed = Some(kind);
        true
    }

    /// The carrier's abort when its writer has not finished: output or the
    /// shutdown is pending. `None` for a side an application holds (it is
    /// written through) or a carrier that finished.
    fn stuck_abort(&mut self) -> Option<Box<dyn FnOnce() + Send>> {
        let ws = self.write.try_side()?;
        let pending = ws.writer.is_some() && (!ws.out.is_empty() || ws.out.shutdown_pending());
        drop(ws);
        if pending { self.abort.take() } else { None }
    }

    /// Closes a half the core asked to close; `false` while an application
    /// holds the side (tried again once it handed over).
    fn close(&mut self, half: PipeHalf, abort: bool) -> bool {
        for l in self.lanes_mut() {
            l.close(half, abort);
        }
        match half {
            PipeHalf::Inbound => {
                let done = self.read.try_close(|rs| rs.reader = None);
                self.close_deferred[0] |= !done;
                done
            }
            PipeHalf::Outbound => {
                let Some(mut ws) = self.write.try_side() else {
                    self.close_deferred[1] = true;
                    return false;
                };
                // The abort first: a writer that ends cleanly when dropped
                // must not have ended the carrier before the abort took it.
                if abort && let Some(f) = self.abort.take() {
                    f();
                    // An aborted carrier has no graceful end to drain.
                    if let Some(d) = &mut self.drain {
                        d.armed = false;
                    }
                }
                ws.writer = None;
                ws.out.clear();
                self.write_closed = true;
                drop(ws);
                true
            }
        }
    }
}

/// The order in which the lanes of a pipe other than lane 0 are offered a
/// batch: the copy lane (`copy`, an index of the `n` lanes) first, then the
/// data lanes in turns, starting at `next`, the one after the data lane
/// that last took a batch.
fn in_turn(n: usize, copy: Option<usize>, next: usize) -> impl Iterator<Item = usize> {
    let start = if n == 0 { 0 } else { next % n };
    copy.into_iter().chain(
        (0..n)
            .map(move |k| (start + k) % n)
            .filter(move |&i| Some(i) != copy),
    )
}

/// The kind of a write call's failure: its error, or `WriteZero` for a
/// carrier that took nothing.
fn write_error(r: io::Result<usize>) -> io::ErrorKind {
    r.err().map_or(io::ErrorKind::WriteZero, |e| e.kind())
}

/// Takes the next batch of pipe `id` from the core when the last one is
/// written.
fn take_batch(
    ws: &mut WriteSide,
    id: impl Into<LaneId>,
    st: &mut State<Tokio>,
    now: Instant,
) -> bool {
    if ws.writer.is_none() {
        return false;
    }
    let input = st.io.input_pending;
    let id: LaneId = id.into();
    let took = ws.out.take_batch(&mut st.core, id, now, input);
    if took && let Some((restart, start)) = ws.restart.as_mut() {
        // The previous batch is written: a new start's first batch goes to
        // the carrier's new stream.
        let now_start = st.core.bootstrap_start();
        if *start != now_start {
            *start = now_start;
            let restarted = restart().map_err(|error| error.kind()).and_then(|sources| {
                if let Some(sources) = sources {
                    st.core.switch_pipe_accounting(id.pipe, sources)
                } else {
                    Ok(())
                }
            });
            if let Err(kind) = restarted {
                // No byte stream to start again on: the pipe and session fail.
                ws.writer = None;
                st.core.pipe_ended(id, PipeEnd::Error(kind), now);
                st.dispatch();
                return false;
            }
        }
    }
    st.dispatch();
    took
}

/// The session task: runs the pipes' I/O, the core's timers and the custom
/// scheduling decisions until the session is closed.
struct Task {
    shared: Arc<Shared<Tokio>>,
    clock: crate::ClockDomain,
    pipes: Vec<PipeTask>,
    /// Closes collected under the core lock, applied after it (kept while
    /// an application holds the side).
    closes: Vec<(u64, PipeHalf, bool)>,
    /// The session's one timer, and the deadline it is armed for.
    timer: Pin<Box<Sleep>>,
    clock_timer: Option<crate::proto::session::ClockWait>,
    /// The wait for a deadline closer than [`super::precise::HORIZON`],
    /// served with the system's timer precision instead of `timer`.
    precise: Option<super::precise::Sleep>,
    deadline: Option<Instant>,
    /// Set when the session closed with a batch still being written.
    final_deadline: Option<Instant>,
    /// Custom scheduling decisions, made outside the lock (reused), and
    /// whether one waits to be applied in the next critical section.
    pick: PickRequest,
    pick_made: bool,
    /// Lanes to open and to reset, taken under the core lock and done
    /// after it, and requested lanes without an opener, refused in the
    /// next critical section; allocated with the first.
    lane_work: Option<Box<LaneWork>>,
    /// The last pass that made progress, until the core's idle storage was
    /// freed [`IDLE_RELEASE`] after it (then `None`).
    active: Option<Instant>,
    memory_wait: Option<Arc<crate::proto::memory::BudgetWait>>,
    _live: Live,
}

/// The session task's lane work between critical sections.
#[derive(Default)]
struct LaneWork {
    requests: Vec<LaneId>,
    resets: Vec<LaneId>,
    refusals: Vec<LaneId>,
}

impl Task {
    fn new(shared: Arc<Shared<Tokio>>, first: PipeTask) -> Self {
        let clock = shared.lock().core.config().clock_domain.clone();
        let active = Some(clock.now_with(now));
        Self {
            shared,
            clock,
            pipes: vec![first],
            closes: Vec::new(),
            clock_timer: None,
            timer: Box::pin(tokio::time::sleep(Duration::from_hours(24))),
            precise: None,
            deadline: None,
            final_deadline: None,
            pick: PickRequest::default(),
            pick_made: false,
            lane_work: None,
            active,
            memory_wait: None,
            _live: Live::new(Kind::Task),
        }
    }
}

/// Opens the lanes the core asked for (without the core lock: an opener is
/// the application's), and resets those it gave up: each opener runs on
/// its own task and hands the stream over once open; a request without an
/// opener is refused in the next critical section.
fn lanes_after_lock(shared: &Arc<Shared<Tokio>>, pipes: &mut [PipeTask], work: &mut LaneWork) {
    let LaneWork {
        requests,
        resets,
        refusals,
    } = work;
    for at in requests.drain(..) {
        let opener = pipes.iter().find(|p| p.id == at.pipe).and_then(|p| {
            let l = p.lanes.as_deref()?;
            Some((
                l.opener.clone()?,
                l.framing,
                p.attachment.retirement().clone(),
                Some(p.attachment.clone()),
            ))
        });
        let Some((open, framing, done, lease)) = opener else {
            refusals.push(at);
            continue;
        };
        let shared = Arc::downgrade(shared);
        tokio::spawn(Attachment::during(lease.clone(), async move {
            let opening = crate::proto::decision::host_future(|| open());
            if let Some(result) = super::setup::while_open(done.wait(), opening).await {
                let result =
                    result.unwrap_or_else(|| Err(io::Error::other("lane opener panicked")));
                lane_opened(&shared, at, framing, result, lease);
            }
        }));
    }
    for at in resets.drain(..) {
        if let Some(p) = pipes.iter_mut().find(|p| p.id == at.pipe)
            && let Some(l) = p.lanes_mut().iter_mut().find(|l| l.lane == at.lane.0)
        {
            // Dropping the stream resets it.
            l.close(PipeHalf::Outbound, true);
        }
    }
}

/// A lane's stream was opened, or could not be: handed to the session
/// task, or refused. A session that ended meanwhile drops it.
fn lane_opened(
    shared: &Weak<Shared<Tokio>>,
    at: LaneId,
    framing: Framing,
    r: io::Result<LaneWriter>,
    lease: Option<Arc<Attachment>>,
) {
    if let (Ok(writer), Some(lease)) = (&r, &lease) {
        lease.adopt(writer.attachment.as_ref());
    }
    let Some(shared) = shared.upgrade() else {
        return;
    };
    let mut st = shared.lock();
    let now = st.now();
    let mut unused = None;
    let writer_memory = match &r {
        Ok(w) if w.writer.needs_workspace() && !st.io.task_ended => st.core.reserve_writer(),
        _ => Ok(None),
    };
    match r {
        Ok(w) if writer_memory.is_err() => {
            st.core.write_failed(at, io::ErrorKind::OutOfMemory, now);
            unused = Some(w);
        }
        Ok(w) if !st.io.task_ended && st.core.lane_opened(at, framing, now) => {
            st.io.lanes.get_or_insert_default().new.push(NewLane {
                at,
                framing,
                attachment: lease,
                partial: false,
                read: None,
                write: Some(w),
                reader_memory: None,
                writer_memory: writer_memory
                    .expect("reserved")
                    .map(crate::proto::memory::WriteWorkspace::new),
            });
        }
        Ok(w) => unused = Some(w),
        // Not opened this time (a stream carrier with no stream for it
        // now): asked again later, no refusal.
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => st.core.lane_unopened(at, now),
        Err(e) if !st.io.task_ended => st.core.write_failed(at, e.kind(), now),
        Err(_) => {}
    }
    st.after_command();
    drop(st);
    drop(unused);
}

/// Takes over new pipes and lanes and collects the closes the core asked
/// for, to apply once the core is unlocked ([`apply_closes`]); a lane whose
/// pipe is gone is dropped (aborted) after the lock.
fn housekeeping(
    pipes: &mut Vec<PipeTask>,
    closes: &mut Vec<(u64, PipeHalf, bool)>,
    st: &mut State<Tokio>,
) -> bool {
    let mut progress = !st.io.new_pipes.is_empty() || !st.io.close_halves.is_empty();
    if !st.io.new_pipes.is_empty() {
        pipes.append(&mut st.io.new_pipes);
        // Pipes are added rarely: the handoff list's storage goes with the
        // handoff, and the task's list holds only its pipes.
        st.io.new_pipes = Vec::new();
        pipes.shrink_to_fit();
    }
    if let Some(preferences) = st.core.take_receive_order() {
        pipes.sort_unstable_by_key(|pipe| {
            let p = preferences.get(&pipe.id).copied().unwrap_or_default();
            (
                p.weight == 0,
                p.standby,
                p.tier,
                std::cmp::Reverse(p.weight),
                pipe.id.0,
            )
        });
    }
    closes.append(&mut st.io.close_halves);
    let s = &mut *st;
    if let Some(l) = s.io.lanes.as_deref_mut() {
        progress |= !l.new.is_empty();
        adopt_lanes(pipes, &mut l.new, &mut s.deferred);
        // A connection's new streams may be lanes only of its OPEN inbound
        // pipes.
        for (pipe, claim) in &mut l.conns {
            claim.set_open(s.core.inbound_open(PipeId(*pipe)));
        }
    }
    progress
}

/// Closes the carrier halves the core asked to close (without the core
/// lock: closing takes a pipe's side, and an abort calls into the
/// application). A side an application holds keeps its close for a later
/// round.
fn apply_closes(pipes: &mut [PipeTask], closes: &mut Vec<(u64, PipeHalf, bool)>) {
    closes.retain(|&(id, half, abort)| {
        pipes
            .iter_mut()
            .find(|p| p.id.0 == id)
            .is_some_and(|p| !p.close(half, abort))
    });
}

/// The session ended: pipes attached since are done too, and every pipe's
/// wait resolves (after the lock); the carriers are dropped with the task,
/// and the lanes of pipes that are gone after the lock.
fn end(pipes: &mut Vec<PipeTask>, st: &mut State<Tokio>, shared: &Shared<Tokio>) {
    st.io.task_ended = true;
    release_carriers(shared, None);
    st.io.through.clear();
    pipes.append(&mut st.io.new_pipes);
    release_lanes(st);
    let at = now();
    for p in pipes.iter_mut() {
        if let Some(mut ws) = p.write.try_side() {
            ws.out.cancel(&mut st.core, p.id, at);
        }
        let pipe = p.id;
        for lane in p.lanes_mut() {
            if let Some(ws) = lane.write.as_mut() {
                ws.out.cancel(&mut st.core, pipe.lane(lane.lane), at);
            }
        }
        p.attachment.retire(&mut st.wakes);
        p.tell_close_code(st);
    }
    st.dispatch();
}

/// The session task has released its carriers, the last of the session's
/// work: [`Session::closed`] resolves.
fn released(pipes: &mut Vec<PipeTask>, shared: &Shared<Tokio>) {
    pipes.clear();
    let mut st = shared.lock();
    st.io.released = true;
    let s = &mut *st;
    s.waiters.wake_list(super::wait::List::Close, &mut s.wakes);
}

/// Releases the session's lane state, lanes handed over but not taken
/// over included (after the lock), and removes its Lane Key entry: once
/// CLOSED, under the lock that saw it closed, the session takes no lanes
/// and creates no lane state again.
fn release_lanes(st: &mut State<Tokio>) {
    if let Some(l) = st.io.lanes.take() {
        st.deferred.push(l);
    }
    if let Some(key) = st.core.lane_key() {
        super::lanes::unregister(&key);
    }
}

/// Hands each new lane to its pipe; one whose pipe is gone goes to the
/// work after the lock.
fn adopt_lanes(pipes: &mut [PipeTask], new: &mut Vec<NewLane>, after: &mut Deferred) {
    for lane in new.drain(..) {
        match pipes.iter_mut().find(|p| p.id == lane.at.pipe) {
            Some(p) => p.add_lane(lane),
            None => after.push(lane),
        }
    }
}

impl Drop for Task {
    /// Dropped before the session ended (its runtime shut down): the
    /// session ends here, so that every wait resolves and no carrier is
    /// attached to a session nobody runs. The carriers are dropped after the
    /// lock, with this task.
    fn drop(&mut self) {
        let mut st = self.shared.lock();
        if st.io.task_ended {
            return;
        }
        let now = st.now();
        st.core.abort(VarInt::ZERO, b"session task stopped", now);
        st.dispatch();
        end(&mut self.pipes, &mut st, &self.shared);
        drop(st);
        released(&mut self.pipes, &self.shared);
    }
}

#[cfg(feature = "test-hooks")]
static MEASURE_POLLS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "test-hooks")]
static MEASURED_POLLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Enables or disables session-task poll counting and returns the previous count.
#[cfg(feature = "test-hooks")]
pub fn measure_session_polls(enabled: bool) -> usize {
    use std::sync::atomic::Ordering::Relaxed;
    MEASURE_POLLS.store(enabled, Relaxed);
    MEASURED_POLLS.swap(0, Relaxed)
}

impl Future for Task {
    type Output = ();

    /// Each round reads the pipes (an outcome goes to the core under its
    /// lock, R2 in `super::through`) and writes a call's worth of each
    /// batch without the lock; then one critical section hands the core
    /// everything else and takes what it has for the pipes: new pipes and
    /// closes, the writes' reports, the TCP probes, timers, the custom
    /// decision made last round, new batches (W3) and sides skipped (H1),
    /// the next custom request, and the deadline when nothing is left.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        #[cfg(feature = "test-hooks")]
        if MEASURE_POLLS.load(std::sync::atomic::Ordering::Relaxed) {
            MEASURED_POLLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let this = &mut *self;
        let shared = &*this.shared;
        let mut rounds = 0u32;
        loop {
            let mut progress = false;
            let mut input = false;
            let mut busy = false;
            for p in &mut this.pipes {
                // Input is pending while a read left bytes in its carrier:
                // what the reads took whole is processed already.
                let (read, left) = p.poll_read(shared, cx);
                input |= left;
                busy |= p.read_skipped;
                progress |= read;
                progress |= p.write_out(shared, cx, input, &this.clock);
                if p.has_lanes() {
                    let (left, moved) = p.poll_lanes(shared, cx, input, &this.clock);
                    input |= left;
                    progress |= moved;
                }
            }
            // The TCP carriers' periodic queries (`Probe`): the sockets are
            // read without the core lock, the results go to the core in the
            // critical section, and the socket options are set after it.
            let now = this.clock.now_with(now);
            let mut probing = false;
            for p in &mut this.pipes {
                if let Some(probe) = p.queries.as_deref_mut().and_then(|q| q.probe.as_mut()) {
                    probing |= probe.query(now);
                }
                probing |= p.query_unsent(now);
            }

            // Suspended sessions the listener's account asks to close, after
            // the lock.
            let mut closing = Evictions::new();
            let mut st = shared.lock();
            progress |= housekeeping(&mut this.pipes, &mut this.closes, &mut st);
            if let Some(w) = this.lane_work.as_deref_mut() {
                for at in w.refusals.drain(..) {
                    st.core.write_failed(at, io::ErrorKind::Unsupported, now);
                    st.dispatch();
                    progress = true;
                }
            }
            let start_hook = st.take_hook_start();
            if probing {
                for p in &mut this.pipes {
                    if let Some(probe) = p.queries.as_deref_mut().and_then(|q| q.probe.as_mut()) {
                        probe.feed(&mut st.core, p.id);
                    }
                    p.feed_unsent(&mut st.core, now);
                }
            }
            // A side an application reads through keeps what it reported.
            st.io.input_pending = input || (busy && st.io.input_pending);
            if std::mem::take(&mut this.pick_made) {
                st.core.answer_pick(&this.pick);
                st.dispatch();
            }
            for p in &mut this.pipes {
                p.report(&mut st, now);
                if p.has_lanes() {
                    p.report_lanes(&mut st, now);
                }
            }
            if engine::fire_timers(&mut st.core, now) {
                progress = true;
                st.dispatch();
            }
            progress |= housekeeping(&mut this.pipes, &mut this.closes, &mut st);
            {
                // The listener's account: the charge, allowance, pressure
                // and suspended limit (`super::account`).
                let s = &mut *st;
                if let Some(link) = s.io.account.as_mut() {
                    link.report(&mut s.core, &this.shared, &mut closing);
                }
            }
            let mut more = std::mem::take(&mut st.io.repoll);
            for p in &mut this.pipes {
                more |= p.before_wait(&mut st, now);
                if p.has_lanes() {
                    more |= p.before_wait_lanes(&mut st, now);
                }
            }
            // Lanes to open or reset, after the lock.
            if let Some(l) = st.io.lanes.as_deref_mut()
                && !(l.requests.is_empty() && l.resets.is_empty())
            {
                more = true;
                let w = this.lane_work.get_or_insert_default();
                w.requests.append(&mut l.requests);
                w.resets.append(&mut l.resets);
            }
            // Pipes whose halves are both closed are gone: what is left of
            // them, the lanes' streams included, is dropped after the lock,
            // and then their waits resolve.
            let s = &mut *st;
            for mut p in this.pipes.extract_if(.., |p| p.finished()) {
                p.attachment.retire(&mut s.wakes);
                p.tell_close_code(s);
                // Its stream carrier, if any, carries this session no more.
                release_carriers(shared, Some(p.id.0));
                s.io.through.retain(|t| t.id != p.id);
                // Its connection carries this pipe no more.
                if let Some(l) = s.io.lanes.as_deref_mut() {
                    l.conns.retain(|(id, _)| *id != p.id.0);
                }
                s.deferred.push(p);
            }
            if st.core.state() == CoreState::Closed {
                st.dispatch();
                // A side an application holds is being written through.
                let writing = this.pipes.iter().any(|p| {
                    p.write.try_side().is_none_or(|ws| {
                        ws.writer.is_some() && (!ws.out.is_empty() || ws.out.shutdown_pending())
                    })
                });
                let deadline = *this.final_deadline.get_or_insert(now + engine::FINAL_WRITE);
                if !writing || now >= deadline {
                    // The graceful end of a carrier did not complete in
                    // time (its last batch or its shutdown, which a peer
                    // that went away never lets finish): the carrier is
                    // aborted, not just dropped.
                    let stuck: Vec<_> = if writing {
                        this.pipes
                            .iter_mut()
                            .filter_map(PipeTask::stuck_abort)
                            .collect()
                    } else {
                        Vec::new()
                    };
                    end(&mut this.pipes, &mut st, shared);
                    drop(st);
                    // Aborts run without the lock; the carriers go with
                    // this task.
                    for abort in stuck {
                        abort();
                    }
                    apply_closes(&mut this.pipes, &mut this.closes);
                    for s in closing.take() {
                        s.close_suspended();
                    }
                    released(&mut this.pipes, shared);
                    return Poll::Ready(());
                }
            }
            if st.core.wake_memory_writers() {
                st.dispatch();
            }
            // A custom scheduling decision: the core copies a value-only view here, the policy
            // runs without the lock, and its answer is applied in the next
            // critical section if the view is still current.
            let pick = st.core.take_pick(&mut this.pick);
            let waiting = !(progress
                || more
                || pick
                || st
                    .core
                    .watch_receive_budget(&mut this.memory_wait, cx.waker()));
            let mut deadline = None;
            if waiting {
                match &mut st.io.task {
                    Some(w) => w.clone_from(cx.waker()),
                    none => *none = Some(cx.waker().clone()),
                }
                deadline = this.final_deadline.or(st.core.poll_timeout());
                // The core's empty queues go once the session has been idle
                // as long as a pipe's buffers: one timer per active period.
                if let Some(active) = this.active {
                    let due = active + IDLE_RELEASE;
                    if now < due {
                        deadline = Some(deadline.map_or(due, |d| d.min(due)));
                    } else {
                        st.core.release_idle();
                        this.active = None;
                    }
                }
                // A multipath pipe that is not writable has its unsent
                // bytes watched: its next query is due.
                if st.core.is_multipath() {
                    for p in &this.pipes {
                        if let Some(at) = p
                            .queries
                            .as_deref()
                            .and_then(|q| q.unsent.as_ref())
                            .map(UnsentQuery::next_query)
                            && p.write.try_side().is_some_and(|ws| ws.blocked)
                        {
                            deadline = Some(deadline.map_or(at, |d| d.min(at)));
                        }
                        let lanes = p.lanes.as_deref().map_or(&[][..], |l| &l.list);
                        for l in lanes {
                            if let Some(at) = l.unsent.as_ref().map(UnsentQuery::next_query)
                                && l.write.as_ref().is_some_and(|ws| ws.blocked)
                            {
                                deadline = Some(deadline.map_or(at, |d| d.min(at)));
                            }
                        }
                    }
                }
            } else {
                this.active = Some(now);
            }
            drop(st);
            if probing {
                for p in &mut this.pipes {
                    if let Some(probe) = p.queries.as_deref_mut().and_then(|q| q.probe.as_mut()) {
                        probe.apply();
                    }
                }
            }
            if let Some(hooks) = start_hook {
                tokio::spawn(handle::run_hook(this.shared.clone(), hooks));
            }
            apply_closes(&mut this.pipes, &mut this.closes);
            if let Some(w) = this.lane_work.as_deref_mut()
                && !(w.requests.is_empty() && w.resets.is_empty())
            {
                lanes_after_lock(&this.shared, &mut this.pipes, w);
            }
            for s in closing.take() {
                s.close_suspended();
            }
            if pick {
                this.pick.run();
                this.pick_made = true;
            }
            if !waiting {
                // Carriers that are always ready (nested sessions, custom
                // writers outside tokio's budget) never make the task
                // yield: it does, after a bounded number of rounds.
                rounds += 1;
                if rounds >= TASK_ROUNDS {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                continue;
            }
            for p in &mut this.pipes {
                if let Some(release) = p.release_idle(now) {
                    deadline = Some(deadline.map_or(release, |d| d.min(release)));
                }
            }
            let deadline = engine::timer_deadline(deadline, now);
            // One timer per session, re-armed only when the deadline moved
            // earlier or the armed one passed: a deadline that moves later
            // with every record (the idle timer) is recomputed when the
            // armed one fires.
            let passed = this.deadline.is_some_and(|armed| armed <= now);
            let rearm = match deadline {
                Some(d) => passed || this.deadline.is_none_or(|armed| d < armed),
                None => passed,
            };
            if rearm {
                this.deadline = deadline;
                let at = deadline.unwrap_or(now + Duration::from_hours(24));
                this.clock_timer = deadline.and_then(|at| this.clock.wait_until(at));
                this.precise = (this.clock_timer.is_none()
                    && at.saturating_duration_since(now) <= super::precise::HORIZON
                    && super::precise::available())
                .then(|| super::precise::Sleep::new(at));
                if this.clock_timer.is_none() && this.precise.is_none() {
                    this.timer
                        .as_mut()
                        .reset(tokio::time::Instant::from_std(at));
                }
            }
            let fired = if let Some(wait) = &mut this.clock_timer {
                wait.as_mut().poll(cx).is_ready()
            } else if let Some(precise) = &mut this.precise {
                Pin::new(precise).poll(cx).is_ready()
            } else {
                this.timer.as_mut().poll(cx).is_ready()
            };
            if fired {
                continue;
            }
            return Poll::Pending;
        }
    }
}

// ---- the application's calls ------------------------------------------------------------

impl Session {
    /// Establishes a session as the dialling side of `pipe`. Returns once
    /// the peer's transport parameters were processed.
    ///
    /// # Errors
    ///
    /// [`ConnectError`] when the configuration is invalid, the carrier fails
    /// or the handshake does not complete (the peer closed, refused or timed out).
    pub async fn connect(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
    ) -> Result<Session, ConnectError> {
        Self::start(pipe, config, Role::Client, Some(Role::Client)).await
    }

    /// Establishes a session as the accepting side of `pipe`, without a
    /// listener: such a session cannot accept joins, so a configuration
    /// that offers multipath (steady attachment limit above 1, or resume) is refused
    /// ([`ConnectError::InvalidConfig`]). Accept
    /// multipath sessions with a [`crate::Listener`].
    ///
    /// # Errors
    ///
    /// [`ConnectError`] when the configuration is invalid, the carrier fails
    /// or the handshake does not complete.
    pub async fn accept(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
    ) -> Result<Session, ConnectError> {
        let config = config.into();
        super::check_accept(&config)?;
        Self::start(pipe, config, Role::Server, Some(Role::Server)).await
    }

    /// Establishes a session over a symmetric carrier: the roles are
    /// negotiated with `zmux_role`.
    ///
    /// # Errors
    ///
    /// [`ConnectError`] when the configuration is invalid, the carrier fails
    /// or the handshake does not complete.
    pub async fn peer(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
    ) -> Result<Session, ConnectError> {
        let config = config.into();
        super::check_peer(&config)?;
        Self::start(pipe, config, Role::Auto, None).await
    }

    async fn start(
        pipe: PipeIo,
        config: impl Into<Arc<Config>>,
        role: Role,
        transport: Option<Role>,
    ) -> Result<Session, ConnectError> {
        let config = config.into();
        let clock = &config.clock_domain;
        let deadline = clock.now().checked_add(config.handshake_wait());
        let _ = super::deadline::timeout(clock, deadline, pipe.resolve_exporter()).await;
        let session = Shared::create(
            &mut Some(pipe),
            config.clone(),
            role,
            transport,
            None,
            None,
            |_| None,
        )?
        .established()
        .await?;
        Ok(session)
    }

    /// Opens a bidirectional stream, waiting for stream credit; waiting
    /// openers get credit first come, first served. Nothing is sent until
    /// the first write or [`SendStream::pin_id`](SendStream#method.pin_id). Cancel-safe: a cancelled
    /// opener gives up its place.
    ///
    /// The two parts are one connection for tokio's I/O traits:
    /// `tokio::io::join(recv, send)` is an `AsyncRead + AsyncWrite` whose
    /// shutdown finishes the stream.
    ///
    /// # Errors
    ///
    /// [`OpenError::SessionLost`] when the session ended, and the other
    /// [`OpenError`] variants when no stream can be opened (GOAWAY, limits).
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), OpenError> {
        self.open_bi_wait(None).await
    }

    // Public through the `Session` and `Pipe` aliases; the example runs.
    #[allow(rustdoc::private_doc_tests)]
    /// Opens a bidirectional stream with `preamble` (open info, application TLVs, `PIPE_CARRIER`),
    /// waiting for stream credit as [`Session::open_bi`](Session#method.open_bi) does. The
    /// preamble goes out with the stream's first frame; it is checked here
    /// ([`OpenError::InvalidArgument`], [`OpenError::PreambleTooLarge`],
    /// [`OpenError::NotNegotiated`] with a plain QMux peer). Cancel-safe.
    ///
    /// ```no_run
    /// # async fn example(session: zmux::Session, inbound: zmux::Session) -> Result<(), Box<dyn std::error::Error>> {
    /// use zmux::{Preamble, Priority};
    ///
    /// const DEST: u64 = 0x1000;
    /// let pre = Preamble::new().with_info("GET /video").with_tlv(DEST, b"10.0.0.7:443");
    /// let (mut send, mut recv) = session.open_bi_with(&pre).await?;
    /// send.set_priority(Priority::URGENT)?;
    /// recv.set_peer_priority(Priority::URGENT)?;
    ///
    /// // A relay passes the preamble of the stream it accepted on whole.
    /// let (s_in, r_in) = inbound.accept_bi().await?;
    /// let out = session.open_bi_with(&r_in.preamble()).await?;
    /// zmux::helpers::splice((s_in, r_in), out, Default::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_bi_with(
        &self,
        preamble: &Preamble,
    ) -> Result<(SendStream, RecvStream), OpenError> {
        self.open_bi_wait(Some(preamble)).await
    }

    /// Opens a unidirectional stream, waiting for stream credit (see
    /// [`Session::open_bi`](Session#method.open_bi)). Cancel-safe.
    ///
    /// # Errors
    ///
    /// [`OpenError::SessionLost`] when the session ended, and the other
    /// [`OpenError`] variants when no stream can be opened (GOAWAY, limits).
    pub async fn open_uni(&self) -> Result<SendStream, OpenError> {
        self.open_uni_wait(None).await
    }

    /// Opens a unidirectional stream with `preamble` (see
    /// [`Session::open_bi_with`](Session#method.open_bi_with)). Cancel-safe.
    pub async fn open_uni_with(&self, preamble: &Preamble) -> Result<SendStream, OpenError> {
        self.open_uni_wait(Some(preamble)).await
    }

    /// Accepts the next bidirectional stream the peer opened, in
    /// identifier order. Cancel-safe.
    ///
    /// # Errors
    ///
    /// The [`SessionError`] that ended the session, once no stream is left
    /// to accept.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        self.accept_bi_wait().await
    }

    /// Accepts the next unidirectional stream the peer opened. Cancel-safe.
    ///
    /// # Errors
    ///
    /// The [`SessionError`] that ended the session, once no stream is left
    /// to accept.
    pub async fn accept_uni(&self) -> Result<RecvStream, SessionError> {
        self.accept_uni_wait().await
    }

    /// Queues a session datagram, waiting while the queue is full.
    /// Cancel-safe: a cancelled call queued nothing.
    pub async fn send_datagram_wait(&self, data: Bytes) -> Result<(), DatagramError> {
        self.send_datagram_wait_op(data).await
    }

    /// Receives the next session datagram. Cancel-safe.
    pub async fn read_datagram(&self) -> Result<Bytes, SessionError> {
        self.read_datagram_op().await
    }

    /// Closes the session gracefully with an application close of `code`
    /// and `reason` (`CONNECTION_CLOSE` 0x1d, the reason cut to the length
    /// SPEC.md allows): the data the streams have written and not yet sent
    /// goes out first, as far as flow control and the carriers allow, then
    /// `CONNECTION_CLOSE` is handed to the carrier of every usable outbound
    /// pipe (written to it; for a socket, taken into the kernel's send
    /// buffer), so that the peer reads everything written before the call
    /// ahead of the code. Streams still open are not waited for: they fail
    /// locally with the session's error. Completes once `CONNECTION_CLOSE`
    /// has been handed over, without waiting for anything from the peer;
    /// at once when no pipe can carry it; and after 1 s at the latest, a
    /// bound of the whole call, flushing included: what has not been
    /// handed over by then is discarded. Each pipe's write side is then
    /// shut down and its input read until the peer ends it or the linger
    /// timeout passes, in the background while the runtime keeps running
    /// ([`Session::closed`](Session#method.closed) waits for that end). A
    /// process may exit once it completed.
    ///
    /// The peer sees [`SessionError::ApplicationClosed`] with this code and
    /// reason; code 0 is allowed. Idempotent with
    /// [`Session::abort`](Session#method.abort): the first call of either
    /// decides what is sent, code and reason included, and a later call
    /// completes no later than the first and sends nothing more, except an
    /// abort during the flush, which discards what remains and completes
    /// the close at once. On an ended session it completes at once. The
    /// close starts when this is called; dropping the future does not undo
    /// it.
    pub fn close_with_error(
        &self,
        code: VarInt,
        reason: &[u8],
    ) -> impl Future<Output = ()> + Send + '_ {
        self.begin_close(code, reason);
        self.close_handoff_op()
    }

    /// [`Session::close_with_error`](Session#method.close_with_error) with
    /// code 0 and an empty reason, the one plain close. Dropping the last
    /// handle of the session starts the same close without waiting:
    /// `CONNECTION_CLOSE` then leaves only while the runtime keeps running.
    pub fn close(&self) -> impl Future<Output = ()> + Send + '_ {
        self.close_with_error(VarInt::ZERO, b"")
    }

    /// Ends the session at once with an application close of `code` and
    /// `reason`, draining nothing: data not yet sent is discarded, open
    /// streams fail locally with the session's error, and `CONNECTION_CLOSE`
    /// is written on each usable outbound pipe whose carrier takes it,
    /// in the background; the carriers are then shut down there too.
    /// Returns at once. Code 0 is allowed; an abort differs from
    /// [`Session::close_with_error`](Session#method.close_with_error) with
    /// the same code only in what is drained. The carriers still end as a
    /// close's do: after the peer ended their input, or the linger timeout.
    pub fn abort(&self, code: VarInt, reason: &[u8]) {
        self.abort_op(code, reason);
    }

    /// Waits for the capacity watermark to change.
    pub async fn capacity_changed(&self, observed: u64) -> crate::CapacitySnapshot {
        self.capacity_changed_op(observed).await
    }

    /// Runs a raw Join for protocol fixtures until the peer confirms it.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn test_join(
        &self,
        pipe: PipeIo,
        opts: crate::PipeOptions,
    ) -> impl Future<Output = Result<Pipe, PipeError>> + Send + 'static {
        let session = self.clone();
        let deadline = session.join_deadline();
        async move {
            super::setup::while_open(
                handle::session_ended_wait(session.shared()),
                super::deadline::timeout(
                    &session.clock_domain(),
                    deadline.map(crate::proto::session::JoinDeadline::at),
                    pipe.resolve_exporter(),
                ),
            )
            .await;
            let pipe = session.start_join_inner(pipe, &opts, deadline, None)?;
            let guard = handle::AbortUnlessAdded(Some(&pipe));
            pipe.attached_op().await?;
            guard.added();
            Ok(pipe)
        }
    }

    /// Closes gracefully: GOAWAY, then `CONNECTION_CLOSE` once no stream
    /// remains. Resolves after the close is handed to the usable carriers
    /// or the hand-off deadline passes. Returns `Ok` for the requested
    /// close, otherwise the error that ended the session first. Cancelled
    /// (the future dropped after its first poll, for example by
    /// `tokio::time::timeout`), it starts the close of
    /// [`Session::close`](Session#method.close) with the same code and
    /// reason; awaiting `close` then waits for that close's completion.
    pub async fn shutdown(&self, code: VarInt, reason: &[u8]) -> Result<(), SessionError> {
        self.shutdown_op(code, reason).await
    }

    /// Resolves once the peer's parameters arrived (the session is
    /// established: with early data it is usable before), or with the
    /// error that ended the session first. Cancel-safe.
    pub async fn established(&self) -> Result<(), SessionError> {
        self.established_op().await
    }

    /// Resolves once the session is closing, that is once it began to end,
    /// with the reason; its carriers may still be draining
    /// ([`Session::closed`](Session#method.closed) waits for the whole end).
    /// Cancel-safe.
    pub async fn closing(&self) -> SessionError {
        self.closing_op().await
    }

    /// Resolves once the session has ended entirely, with the reason it
    /// ended: every pipe's inbound side has ended, that is the peer read
    /// `CONNECTION_CLOSE` and ended its side of the carrier, or the linger
    /// timeout passed, and the session's task has released its carriers.
    /// Resolving before the linger timeout thus confirms that the peer read
    /// the close. Cancel-safe.
    ///
    /// "Delivered, or given up after `d`" is this future under the caller's
    /// own bound; a timeout of the wait changes nothing in the session (the
    /// linger goes on and ends the carriers):
    ///
    /// ```no_run
    /// # async fn f(session: zmux::Session) {
    /// use std::time::Duration;
    ///
    /// session.close_with_error(zmux::VarInt::from_u32(0x2a), b"replaced").await;
    /// match tokio::time::timeout(Duration::from_secs(5), session.closed()).await {
    ///     Ok(end) => println!("ended: {end}"),
    ///     Err(_) => println!("not confirmed within 5 s; the linger goes on"),
    /// }
    /// # }
    /// ```
    pub async fn closed(&self) -> SessionError {
        self.wait_op().await
    }

    /// Sends a `QX_PING` request, or joins the one outstanding, and returns
    /// the round-trip time it measured; the sample
    /// also updates [`Session::rtt`](Session#method.rtt) and the statistics. Works with every
    /// peer, plain QMux peers included: it is how a session whose peer
    /// gives no acknowledgements refreshes its RTT. Cancel-safe.
    pub async fn ping(&self) -> Result<Duration, SessionError> {
        self.ping_op().await
    }

    /// Starts buffering health transitions for the session's event reader.
    ///
    /// Reading the first event starts this subscription as well. Read
    /// current pipe health when starting or after a sequence gap.
    pub fn subscribe_pipe_health(&self) {
        self.observe_pipe_health_events();
    }

    /// The next session event (pipe states and reports, GOAWAY,
    /// suspension, capacity; [`Event`]). `None` once the session ended and
    /// every event was read. Cancel-safe.
    pub async fn next_event(&self) -> Option<Event> {
        self.next_event_op().await
    }

    /// Opens a bidirectional stream as the carrier of a pipe pair of a
    /// nested session, waiting for stream credit: its preamble carries
    /// `PIPE_CARRIER` and the application TLVs `tlvs`, in order (for example
    /// the routing metadata of a relay). This endpoint is the pipe's
    /// joiner, or the initiator of a nested session it bootstraps; the
    /// stream's sending part is the pipe's up direction. Nothing is sent
    /// until the nested session writes its first record, which travels with
    /// the preamble. Use the result as
    /// [`PipeIo::from_stream`] describes.
    ///
    /// The carrier loop check runs where the carrier meets the session it is for, not here: opening
    /// does not know which session the carrier is for. The nested session refuses the carrier when
    /// this session runs over it, directly or through other sessions of the process:
    /// [`Session::begin_change`](Session#method.begin_change) fails ([`PipeError::CarrierLoop`]), and
    /// [`crate::Listener::handle_pipe`] refuses the join in its Reply, so that a joiner that cannot
    /// see the loop backs off. A session bootstrapped over the carrier is new, so nothing can run
    /// over it yet.
    ///
    /// When this session does not use the preamble (a plain QMux peer),
    /// the stream carries no preamble, which must then be empty
    /// ([`OpenError::NotNegotiated`] otherwise); the peer's application
    /// recognises the carrier by its own means. Cancel-safe: a cancelled
    /// call opened nothing.
    pub async fn open_pipe_stream(&self, preamble: &Preamble) -> Result<PipeIo, OpenError> {
        let carrier = self.carrier_preamble(preamble);
        let (send, recv) = self.open_bi_with(&carrier).await?;
        Ok(pipe_stream(send, recv, preamble))
    }

    /// The preamble of a carrier stream: `preamble` with `PIPE_CARRIER`,
    /// unless the session does not use preambles and it is empty.
    pub(crate) fn carrier_preamble(&self, preamble: &Preamble) -> Preamble {
        if preamble.is_empty() && self.is_plain_qmux_peer() {
            return Preamble::new();
        }
        preamble.clone().with_pipe_carrier()
    }
}

/// A stream just opened as a pipe's carrier ([`Session::open_pipe_stream`](Session#method.open_pipe_stream)):
/// its lanes are opened with the same preamble.
pub(crate) fn pipe_stream(send: SendStream, recv: RecvStream, preamble: &Preamble) -> PipeIo {
    let outer = Arc::downgrade(send.shared());
    let mut io = PipeIo::from_stream(send, recv);
    if !preamble.is_empty()
        && let Some(caps) = io.lanes.as_deref_mut()
    {
        // Its lanes carry the same TLVs (a relay routes them so).
        caps.opener = Some(super::lanes::stream_opener(outer, preamble.clone()));
    }
    io
}

impl Pipe {
    /// Waits for the local Join handshake. Use [`Pipe::attached`] to wait
    /// for peer confirmation. Cancel-safe.
    pub async fn joined(&self) -> Result<(), PipeError> {
        self.joined_op().await
    }

    /// Waits until the peer attached the pipe, so that it carries the
    /// session even if every other pipe goes. Pipe 0 is attached once
    /// the session is established, a pipe the peer joined from the
    /// start. One of our joins is attached once
    /// [`Pipe::joined`](Pipe#method.joined) resolved and the peer
    /// acknowledged a byte of its outbound pipe (on any lane) or, for an
    /// inbound-only pipe, once a record arrived on it: a joiner is ACTIVE
    /// once it wrote Confirm, the acceptor attaches only when Confirm
    /// arrives. Closing the pipe a new one replaces before then could
    /// leave the peer with none. Fails as `joined` does, or with
    /// [`PipeError::Failed`] when the pipe's direction ends first.
    /// Cancel-safe; bound it with a timeout (`tokio::time::timeout`).
    pub async fn attached(&self) -> Result<(), PipeError> {
        self.attached_op().await
    }

    /// Resolves when the pipe ended: `Ok` once every half of it closed
    /// (after [`Pipe::close`](Pipe#method.close) or the peer's
    /// graceful removal) or the session forgot it, [`PipeError::Failed`]
    /// when it failed, [`PipeError::SessionLost`] when the session ended
    /// first. Delivers that result after the carrier, its lanes, drains and
    /// attachment workers have been released. Cancel-safe.
    pub async fn closed(&self) -> Result<(), PipeError> {
        self.closed_op().await
    }
}

impl SendStream {
    /// Writes some of `buf`, waiting for room. Cancel-safe.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, StreamError> {
        self.write_op(buf).await
    }

    /// Writes all of `buf`. Not cancel-safe: on cancellation an unknown
    /// prefix was written.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), StreamError> {
        self.write_all_op(buf).await
    }

    /// Writes a chunk without copying it (it is referenced until it is
    /// sent). Not cancel-safe.
    pub async fn write_chunk(&mut self, data: crate::Chunk) -> Result<(), StreamError> {
        self.write_chunk_op(data).await
    }

    /// Writes as many of `bufs` as the buffers take without copying them;
    /// a chunk taken in part is advanced. Waits until something can be
    /// written. Cancel-safe.
    pub async fn write_chunks(
        &mut self,
        bufs: &mut [crate::Chunk],
    ) -> Result<Written, StreamError> {
        self.write_chunks_op(bufs).await
    }

    /// Resolves when the sending part ended: `None` once the FIN was
    /// written (acknowledged on a single pipe), or the peer's `STOP_SENDING`
    /// code. Cancel-safe. `None` says the data reached the peer's zmux
    /// endpoint at most, not its application.
    pub async fn stopped(&self) -> Result<Option<VarInt>, StreamError> {
        self.stopped_op().await
    }

    /// [`Self::stopped`] as a future that borrows nothing of the part, for a host that
    /// writes while it waits from another task.
    pub fn stopped_owned(
        &self,
    ) -> impl Future<Output = Result<Option<VarInt>, StreamError>> + Send + 'static {
        self.stopped_owned_op()
    }

    /// Waits for send capacity of at least `min`
    /// bytes, or of any while the part holds nothing unsent, and returns
    /// it; resolves at once with the error that ended the part (a reset or
    /// finish, the peer's `STOP_SENDING`, the session's end), so a caller
    /// never waits behind capacity for an error. Cancel-safe.
    pub async fn wait_send_capacity(&self, min: u64) -> Result<u64, StreamError> {
        self.send_capacity_op(min).await
    }

    /// Waits until the send buffers have room for a write and returns the
    /// bytes [`try_write`](Self::try_write) takes now (see
    /// [`poll_writable`](Self::poll_writable)); resolves at once with the
    /// error that ended the part. Cancel-safe: it consumes nothing.
    pub async fn writable(&self) -> Result<u64, StreamError> {
        self.writable_op().await
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_slot(|s, slot| s.poll_write_buf(cx.waker(), slot, buf))
            .map_err(io::Error::from)
    }

    /// Opens the stream now and waits until the opening frame and the data
    /// written so far left for a carrier: the peer sees the stream even
    /// with nothing written, for a protocol whose other side speaks first.
    /// Data written before goes in the opening frame. Before establishment
    /// the frame goes as soon as the stream may open, in early data if
    /// that is in use; while the first flight is held it returns at once
    /// and the frames leave with the flight. A flush that is cancelled leaves
    /// the frame owed. It is the stream's one flush: the inherent API has no
    /// other (`AsyncWriteExt::flush` calls it).
    ///
    /// A `STOP_SENDING` from the peer fails the flush only if it arrives
    /// before all that left; once it left, the flush succeeds and the next
    /// write or finish reports the stop. A lost session fails it.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_slot(|s, slot| s.poll_flush_stream(cx.waker(), slot))
            .map_err(io::Error::from)
    }

    /// Finishes the stream.
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(match self.finish() {
            Ok(()) | Err(StreamError::ClosedLocally) => Ok(()),
            Err(e) => Err(e.into()),
        })
    }
}

impl RecvStream {
    /// Reads into `buf`; `None` at the end of the stream. Cancel-safe.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamError> {
        self.read_op(buf).await
    }

    /// Fills `buf` exactly. Not cancel-safe.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        self.read_exact_op(buf).await
    }

    /// Reads up to `max` bytes as one chunk without copying where possible;
    /// `None` at the end of the stream. Cancel-safe.
    pub async fn read_chunk(&mut self, max: usize) -> Result<Option<crate::Chunk>, StreamError> {
        self.read_chunk_op(max).await
    }

    /// Fills as many of `bufs` as data is available for, without copying;
    /// returns how many were filled, or `None` at the end of the stream.
    /// Waits until something can be read. Cancel-safe.
    pub async fn read_chunks(
        &mut self,
        bufs: &mut [crate::Chunk],
    ) -> Result<Option<usize>, StreamError> {
        self.read_chunks_op(bufs).await
    }

    /// Reads the whole stream, failing beyond `limit` bytes. Not
    /// cancel-safe.
    pub async fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        self.read_to_end_op(limit).await
    }

    /// Resolves once the next read would not wait: data is readable, or the
    /// receiving part has ended (the FIN, a reset, a stop by this endpoint,
    /// the session's end). It resolves in all of these and never fails: the
    /// read that follows reports the data or the end, once, in its own
    /// form. Consumes nothing, is cancel-safe, and any number may wait at
    /// once. With [`try_read`](Self::try_read) it is a read that can be
    /// cancelled without losing data.
    pub async fn readable(&self) {
        self.readable_op().await;
    }

    /// Waits until the peer reset the stream: its code, or `None` when the
    /// stream ended with a FIN instead. Cancel-safe.
    pub async fn received_reset(&mut self) -> Result<Option<VarInt>, StreamError> {
        self.received_reset_op().await
    }

    /// Receives the next datagram of this stream: its context and payload.
    /// Cancel-safe.
    pub async fn read_datagram(&self) -> Result<StreamDatagram, StreamError> {
        self.read_datagram_op().await
    }

    /// [`Self::read_datagram`] as a future that borrows nothing of the part, for a host
    /// that reads the stream while it waits from another task.
    pub fn read_datagram_owned(
        &self,
    ) -> impl Future<Output = Result<StreamDatagram, StreamError>> + Send + 'static {
        self.read_datagram_owned_op()
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let dst = buf.initialize_unfilled();
        match self
            .get_mut()
            .with_slot(|s, slot| s.poll_read_buf(cx.waker(), slot, dst))
        {
            Poll::Ready(Ok(Some(n))) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Io {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Io").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Through {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Through").finish_non_exhaustive()
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
    use super::in_turn;
    #[cfg(debug_assertions)]
    use super::{Arc, Session};
    use super::{ChunkBuf, IoSlice, PipeIo};

    /// A pairing keeps what describes the half that writes, and the uplink's variant,
    /// whichever half is the local uplink.
    #[test]
    fn a_pending_message_read_keeps_its_target_until_delivery() {
        use super::{ReadOutcome, ReadStaging, Reader};
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};
        use tokio::io::{AsyncRead, ReadBuf};

        struct MessageReader(bool);

        impl AsyncRead for MessageReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                out: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if self.0 {
                    assert_eq!(out.initialize_unfilled()[0], 42);
                    out.put_slice(b"message");
                    Poll::Ready(Ok(()))
                } else {
                    self.0 = true;
                    out.initialize_unfilled()[0] = 42;
                    Poll::Pending
                }
            }
        }

        let mut reader = Reader::Io(Box::pin(MessageReader(false)));
        let mut staging = ReadStaging::default();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(staging.poll_message(&mut reader, &mut cx).is_pending());
        let Poll::Ready(ReadOutcome::Message(record)) = staging.poll_message(&mut reader, &mut cx)
        else {
            panic!("expected a message");
        };
        assert_eq!(record.as_ref(), b"message");
        assert!(matches!(staging, ReadStaging::Empty));
    }

    #[test]
    fn retiring_a_full_read_cache_keeps_the_incoming_grant() {
        use super::{BytesMut, Framing, RETIRED_HANDLES, ReadSide};
        use crate::proto::memory::Ledger;

        let old = Ledger::new(None, None);
        let incoming = Ledger::new(None, None);
        let mut read = ReadSide::new(None, Framing::ByteStream, Vec::new(), false);
        for _ in 0..RETIRED_HANDLES {
            read.recycle_later(BytesMut::new(), old.reserve(1));
        }
        read.recycle_later(BytesMut::new(), incoming.reserve(1));
        assert_eq!(read.retired.len(), RETIRED_HANDLES);
        assert_eq!(old.snapshot().used, RETIRED_HANDLES as u64 - 1);
        assert_eq!(incoming.snapshot().used, 1);
        drop(read);
        assert_eq!(incoming.snapshot().used, 0);
        assert_eq!(old.snapshot().used, 0);
    }

    #[test]
    fn a_pair_keeps_the_writing_halfs_fields() {
        let half = |overhead: u16, max: usize, read: bool| {
            let p = PipeIo::chunk_writer(ChunkTestWriter)
                .with_write_overhead(overhead)
                .with_max_record(max)
                .unwrap();
            if read {
                let (r, _w) = tokio::io::duplex(8);
                let mut p = PipeIo::from_halves(r, tokio::io::sink())
                    .with_write_overhead(overhead)
                    .with_max_record(max)
                    .unwrap();
                p.writer = None;
                p
            } else {
                p
            }
        };
        // A listener's uplink is the half it reads.
        let p = PipeIo::paired(
            half(9, 12000, true).with_variant("up"),
            half(5, 9000, false),
        );
        assert_eq!((p.write_overhead, p.max_record), (5, Some(9000)));
        assert_eq!(p.variant().map(|v| &**v), Some("up"));
        // A joiner's uplink is the half it writes.
        let p = PipeIo::paired(
            half(5, 9000, false).with_variant("up"),
            half(9, 12000, true),
        );
        assert_eq!((p.write_overhead, p.max_record), (5, Some(9000)));
        assert_eq!(p.variant().map(|v| &**v), Some("up"));
    }

    /// A split carrier reports its own failure only if both halves do: a
    /// half that does not can stall silently, so stall death stays on.
    #[test]
    fn split_halves_report_failure_only_together() {
        let half = |on: bool| PipeIo::new(tokio::io::empty()).with_reports_failure(on);
        for (up, down) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(
                PipeIo::paired(half(up), half(down)).reports_failure(),
                up && down
            );
            assert_eq!(
                PipeIo::paired_join(half(up), half(down)).reports_failure(),
                up && down
            );
        }
    }

    struct ChunkTestWriter;

    impl super::ChunkWrite for ChunkTestWriter {
        fn poll_write_chunks(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut [crate::Chunk],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(0))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A TCP stream given to `PipeIo::from_tcp` has Nagle's algorithm off:
    /// otherwise a record waits for the previous one's acknowledgement and
    /// records that shaping spaced out leave together (seen on Linux,
    /// whose delayed acknowledgements made bursts of a shaped session's
    /// records).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_tcp_stream_carrier_has_no_nagle() {
        use std::os::fd::AsFd;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = tokio::net::TcpStream::connect(l.local_addr().unwrap())
            .await
            .unwrap();
        assert!(!tcp.nodelay().unwrap());
        let same = std::net::TcpStream::from(tcp.as_fd().try_clone_to_owned().unwrap());
        let _io = PipeIo::from_tcp(tcp);
        assert!(same.nodelay().unwrap());
    }

    /// A `ChunkBuf` reads as its buffers in order, shares what lies within one
    /// buffer and copies only across them.
    #[test]
    fn chunk_buf_reads_its_buffers_in_order() {
        use bytes::Buf;
        let a = crate::Chunk::from_static(b"head");
        let b = crate::Chunk::from(vec![9u8; 100]);
        let mut chunks = [a, crate::Chunk::new(), b.clone()];
        let mut buf = ChunkBuf::new();
        assert_eq!(buf.take_from(&mut chunks), 104);
        assert!(chunks.iter().all(crate::Chunk::is_empty));
        let mut io = [IoSlice::new(&[]); 4];
        assert_eq!(buf.chunks_vectored(&mut io), 2);
        assert_eq!(&buf.copy_to_bytes(2)[..], b"he");
        let across = buf.copy_to_bytes(4);
        assert_eq!(&across[..], &[b'a', b'd', 9, 9]);
        let shared = buf.copy_to_bytes(10);
        assert_eq!(shared.as_ptr(), b[2..].as_ptr());
        buf.advance(88);
        assert!(buf.is_empty() && !buf.has_remaining());
    }

    /// A
    /// limiter lets fewer batches through a round than there are data
    /// lanes; offered in turns, every lane's bound direction gets at least
    /// half an equal share, and a direction that starts mid-transfer on
    /// any lane takes a batch within 9 rounds that let one through (one per
    /// data lane, plus one).
    #[test]
    fn lanes_take_the_batches_a_round_lets_through_in_turns() {
        const LANES: usize = 8;
        // Index 0 is the copy lane, which has nothing to send here.
        let copy = Some(0);
        let n = LANES + 1;
        for per_round in 1..LANES {
            let mut next = 0;
            let mut taken = [0u64; LANES + 1];
            let rounds = 2000;
            for _ in 0..rounds {
                let mut left = per_round;
                for i in in_turn(n, copy, next) {
                    if left == 0 || Some(i) == copy {
                        continue;
                    }
                    left -= 1;
                    taken[i] += 1;
                    next = i + 1;
                }
            }
            let share = (rounds * per_round) as u64 / LANES as u64;
            for (i, &t) in taken.iter().enumerate().skip(1) {
                assert!(
                    t * 2 >= share,
                    "{per_round}/round: lane {i} took {t} of {share}"
                );
            }
            // A new direction on any data lane, the others all busy.
            for lane in 1..n {
                let mut next = (lane + 1) % n;
                let mut waited = 0;
                'rounds: loop {
                    waited += 1;
                    assert!(waited <= 9, "lane {lane} waited {waited} rounds");
                    let mut left = per_round;
                    for i in in_turn(n, copy, next) {
                        if left == 0 || Some(i) == copy {
                            continue;
                        }
                        left -= 1;
                        next = i + 1;
                        if i == lane {
                            break 'rounds;
                        }
                    }
                }
            }
        }
        // The copy lane is offered first whatever the turn.
        assert_eq!(in_turn(4, Some(2), 3).collect::<Vec<_>>(), [2, 3, 0, 1]);
        assert_eq!(in_turn(0, None, 5).count(), 0);
    }

    /// The exporter is the host's code: read on the first bytes, without
    /// the session's lock, once per session.
    #[cfg(debug_assertions)]
    #[tokio::test(flavor = "multi_thread")]
    async fn the_exporter_is_read_outside_the_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (a, b) = tokio::io::duplex(1 << 16);
        let reads = Arc::new(AtomicUsize::new(0));
        let carrier = |s: tokio::io::DuplexStream, reads: Arc<AtomicUsize>| {
            let (r, w) = tokio::io::split(s);
            PipeIo::from_halves(r, w).with_exporter(move |label, _, out| {
                assert!(!crate::driver::wake::lock_held(), "{label} under the lock");
                if label == crate::proto::keys::EXPORTER_SESSION_LABEL {
                    reads.fetch_add(1, Ordering::SeqCst);
                }
                out.fill(9);
                true
            })
        };
        let c = crate::Config::multipath(crate::PipeAuth::exporter());
        let listener = crate::Listener::new(c.clone(), crate::ListenerConfig::default())
            .expect("valid listener configuration");
        let serving = listener.clone();
        let pipe = carrier(b, reads.clone());
        tokio::spawn(async move { serving.handle_pipe(pipe, crate::PipeHint::default()).await });
        let client = Session::connect(carrier(a, reads.clone()), c)
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        client.established().await.unwrap();
        server.established().await.unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(client.multipath(), crate::Multipath::InUse);
    }
}
