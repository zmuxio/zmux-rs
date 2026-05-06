use super::buffer::RecvBuffer;
use super::queue::WriteQueue;
use super::scheduler::BatchScheduler;
use crate::error::{Error, ErrorSource, Result};
use crate::event::{Event, EventHandler};
use crate::frame::Frame;
use crate::payload::StreamMetadata;
use crate::preface::{Negotiated, Preface};
use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const MAX_CONDVAR_TIMED_WAIT: Duration = Duration::from_secs(3600);

#[inline]
fn next_generation(current: u64) -> u64 {
    let next = current.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Ready,
    Draining,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActiveStreamStats {
    pub local_bidi: u64,
    pub local_uni: u64,
    pub peer_bidi: u64,
    pub peer_uni: u64,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStats {
    pub state: SessionState,
    pub sent_frames: u64,
    pub received_frames: u64,
    pub sent_data_bytes: u64,
    pub received_data_bytes: u64,
    pub open_streams: usize,
    pub accepted_streams: u64,
    pub active_streams: ActiveStreamStats,
    pub provisional: ProvisionalStats,
    pub accept_backlog: AcceptBacklogStats,
    pub retention: RetentionStats,
    pub memory: MemoryStats,
    pub abuse: AbuseStats,
    pub hidden: HiddenStateStats,
    pub reasons: ReasonStats,
    pub diagnostics: DiagnosticStats,
    pub pressure: PressureStats,
    pub flush: FlushStats,
    pub telemetry: TelemetryStats,
    pub progress: ProgressStats,
    pub blocked_write_total: Duration,
    pub writer_queue: WriterQueueStats,
    pub liveness: LivenessStats,
}

impl SessionStats {
    #[inline]
    pub fn empty(state: SessionState) -> Self {
        Self {
            state,
            sent_frames: 0,
            received_frames: 0,
            sent_data_bytes: 0,
            received_data_bytes: 0,
            open_streams: 0,
            accepted_streams: 0,
            active_streams: ActiveStreamStats::default(),
            provisional: ProvisionalStats::default(),
            accept_backlog: AcceptBacklogStats::default(),
            retention: RetentionStats::default(),
            memory: MemoryStats::default(),
            abuse: AbuseStats::default(),
            hidden: HiddenStateStats::default(),
            reasons: ReasonStats::default(),
            diagnostics: DiagnosticStats::default(),
            pressure: PressureStats::default(),
            flush: FlushStats::default(),
            telemetry: TelemetryStats::default(),
            progress: ProgressStats::default(),
            blocked_write_total: Duration::ZERO,
            writer_queue: WriterQueueStats::default(),
            liveness: LivenessStats::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCloseError {
    pub code: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerGoAwayError {
    pub code: u64,
    pub reason: String,
}

/// Optional control hooks for a custom duplex transport.
///
/// `Conn` uses these hooks during session establishment and when the runtime
/// needs to wake or close the underlying transport. Implement only the hooks
/// your transport can support; the timeout hooks default to no-ops.
pub trait DuplexTransportControl: Send + Sync {
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn close(&self) -> io::Result<()>;
}

struct TcpDuplexTransportControl {
    stream: TcpStream,
}

impl DuplexTransportControl for TcpDuplexTransportControl {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }

    fn close(&self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Both)
    }
}

impl<T> DuplexTransportControl for Box<T>
where
    T: DuplexTransportControl + ?Sized,
{
    #[inline]
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(timeout)
    }

    #[inline]
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_write_timeout(timeout)
    }

    #[inline]
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }
}

struct CloseFnTransportControl<F> {
    close: F,
}

impl<F> DuplexTransportControl for CloseFnTransportControl<F>
where
    F: Fn() -> io::Result<()> + Send + Sync,
{
    #[inline]
    fn close(&self) -> io::Result<()> {
        (self.close)()
    }
}

/// Owned split transport plus optional connection metadata for `Conn`.
pub struct DuplexTransport<R, W> {
    pub(super) reader: R,
    pub(super) writer: W,
    pub(super) control: Option<Arc<dyn DuplexTransportControl>>,
    pub(super) local_addr: Option<SocketAddr>,
    pub(super) peer_addr: Option<SocketAddr>,
}

impl<R, W> DuplexTransport<R, W> {
    /// Builds a transport from already split blocking read and write halves.
    ///
    /// Prefer the underlying connection type's native split/clone operation.
    /// Wrapping a single blocking duplex object behind one shared lock can let a
    /// blocked read starve writes and close propagation.
    #[inline]
    #[must_use]
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            control: None,
            local_addr: None,
            peer_addr: None,
        }
    }

    /// Records the local address reported by this transport.
    #[inline]
    #[must_use]
    pub fn with_local_addr(mut self, local_addr: SocketAddr) -> Self {
        self.local_addr = Some(local_addr);
        self
    }

    /// Records the peer address reported by this transport.
    #[inline]
    #[must_use]
    pub fn with_peer_addr(mut self, peer_addr: SocketAddr) -> Self {
        self.peer_addr = Some(peer_addr);
        self
    }

    /// Records optional local and peer addresses in one step.
    ///
    /// This is useful for adapters that can discover either address
    /// independently.
    #[inline]
    #[must_use]
    pub fn with_addresses(
        mut self,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        self.local_addr = local_addr;
        self.peer_addr = peer_addr;
        self
    }

    /// Installs transport-specific timeout and close operations.
    #[inline]
    #[must_use]
    pub fn with_control<C>(mut self, control: C) -> Self
    where
        C: DuplexTransportControl + 'static,
    {
        self.control = Some(Arc::new(control));
        self
    }

    /// Installs a close hook for the underlying connection resource.
    ///
    /// `Conn::close` calls this hook before tearing down the ZMux session, so a
    /// joined or split transport can still shut down its original connection.
    #[inline]
    #[must_use]
    pub fn with_close_fn<F>(self, close: F) -> Self
    where
        F: Fn() -> io::Result<()> + Send + Sync + 'static,
    {
        self.with_control(CloseFnTransportControl { close })
    }

    /// Returns the configured local address, when known.
    #[inline]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Returns the configured peer address, when known.
    #[inline]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Applies a read timeout through the optional transport control.
    #[inline]
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match &self.control {
            Some(control) => control.set_read_timeout(timeout),
            None => Ok(()),
        }
    }

    /// Applies a write timeout through the optional transport control.
    #[inline]
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match &self.control {
            Some(control) => control.set_write_timeout(timeout),
            None => Ok(()),
        }
    }

    /// Closes the underlying transport resource through the optional control.
    #[inline]
    pub fn close(&self) -> io::Result<()> {
        match &self.control {
            Some(control) => control.close(),
            None => Ok(()),
        }
    }

    /// Borrows the read half.
    #[inline]
    pub fn reader(&self) -> &R {
        &self.reader
    }

    /// Mutably borrows the read half.
    #[inline]
    pub fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Borrows the write half.
    #[inline]
    pub fn writer(&self) -> &W {
        &self.writer
    }

    /// Mutably borrows the write half.
    #[inline]
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Returns the owned split halves.
    #[inline]
    pub fn into_parts(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl DuplexTransport<(), ()> {
    /// Builds a transport by cloning a single reliable duplex I/O object into
    /// independent read and write handles.
    ///
    /// Use this only when `Clone` creates another handle that can read and
    /// write concurrently with the original handle. If the clone just shares
    /// one blocking mutex internally, prefer the transport's real split API or
    /// an async adapter.
    #[inline]
    #[must_use]
    pub fn from_cloneable<T>(io: T) -> DuplexTransport<T, T>
    where
        T: Clone + Read + Write + Send + 'static,
    {
        let reader = io.clone();
        DuplexTransport::new(reader, io)
    }

    /// Builds a transport by using a transport-specific clone operation.
    ///
    /// This is useful for reliable stream types that do not implement `Clone`
    /// but expose a `try_clone`-style API. The cloned value becomes the read
    /// half and the original value becomes the write half.
    #[inline]
    pub fn try_clone_with<T>(
        io: T,
        clone: impl FnOnce(&T) -> io::Result<T>,
    ) -> Result<DuplexTransport<T, T>>
    where
        T: Read + Write + Send + 'static,
    {
        let reader = clone(&io).map_err(Error::from)?;
        Ok(DuplexTransport::new(reader, io))
    }
}

/// Reliable blocking duplex connection accepted by `Conn`.
///
/// Rust's standard library has `Read` and `Write`, but no single trait like
/// Go's `net.Conn` that also promises connection cloning, splitting, timeout
/// control, and full-resource close semantics. ZMux uses this trait for that
/// boundary. Implement it for reliable byte streams that can become
/// independent blocking read/write handles.
///
/// Implementations are provided for `TcpStream`, `(reader, writer)`, and
/// `DuplexTransport`. Use `DuplexTransport` from custom implementations when a
/// transport needs addresses, timeout hooks, a close hook, or a clone-based
/// split.
pub trait DuplexConnection: Send + 'static {
    type Reader: Read + Send + 'static;
    type Writer: Write + Send + 'static;

    fn into_transport(self) -> Result<DuplexTransport<Self::Reader, Self::Writer>>;
}

impl<R, W> DuplexConnection for DuplexTransport<R, W>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    type Reader = R;
    type Writer = W;

    #[inline]
    fn into_transport(self) -> Result<DuplexTransport<Self::Reader, Self::Writer>> {
        Ok(self)
    }
}

impl<R, W> DuplexConnection for (R, W)
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    type Reader = R;
    type Writer = W;

    #[inline]
    fn into_transport(self) -> Result<DuplexTransport<Self::Reader, Self::Writer>> {
        Ok(DuplexTransport::new(self.0, self.1))
    }
}

impl<T> DuplexConnection for Box<T>
where
    T: DuplexConnection,
{
    type Reader = T::Reader;
    type Writer = T::Writer;

    #[inline]
    fn into_transport(self) -> Result<DuplexTransport<Self::Reader, Self::Writer>> {
        (*self).into_transport()
    }
}

impl DuplexConnection for TcpStream {
    type Reader = TcpStream;
    type Writer = TcpStream;

    fn into_transport(self) -> Result<DuplexTransport<Self::Reader, Self::Writer>> {
        let local_addr = self.local_addr().ok();
        let peer_addr = self.peer_addr().ok();
        let reader = self.try_clone().map_err(Error::from)?;
        let control = TcpDuplexTransportControl {
            stream: self.try_clone().map_err(Error::from)?,
        };
        Ok(DuplexTransport::new(reader, self)
            .with_addresses(local_addr, peer_addr)
            .with_control(control))
    }
}

impl<R, W> Read for DuplexTransport<R, W>
where
    R: Read,
{
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.reader.read(dst)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.reader.read_vectored(bufs)
    }
}

impl<R, W> Write for DuplexTransport<R, W>
where
    W: Write,
{
    #[inline]
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.writer.write(src)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.writer.write_vectored(bufs)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProvisionalStats {
    pub bidi: usize,
    pub uni: usize,
    pub bidi_limit: usize,
    pub uni_limit: usize,
    pub limited: u64,
    pub expired: u64,
}

impl ProvisionalStats {
    #[inline]
    #[must_use]
    pub fn bidi_at_limit(self) -> bool {
        self.bidi_limit != 0 && self.bidi >= self.bidi_limit
    }

    #[inline]
    #[must_use]
    pub fn uni_at_limit(self) -> bool {
        self.uni_limit != 0 && self.uni >= self.uni_limit
    }

    #[inline]
    #[must_use]
    pub fn at_limit(self) -> bool {
        self.bidi_at_limit() || self.uni_at_limit()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcceptBacklogStats {
    pub bidi: usize,
    pub uni: usize,
    pub limit: usize,
    pub bidi_limit: usize,
    pub uni_limit: usize,
    pub bytes: usize,
    pub bytes_limit: usize,
    pub refused: u64,
}

impl AcceptBacklogStats {
    #[inline]
    #[must_use]
    pub fn count(self) -> usize {
        self.bidi.saturating_add(self.uni)
    }

    #[inline]
    #[must_use]
    pub fn at_count_limit(self) -> bool {
        self.limit != 0 && self.count() >= self.limit
    }

    #[inline]
    #[must_use]
    pub fn at_bytes_limit(self) -> bool {
        self.bytes_limit != 0 && self.bytes >= self.bytes_limit
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionStats {
    pub tombstones: usize,
    pub tombstone_limit: usize,
    pub marker_only_used_streams: usize,
    pub marker_only_used_stream_ranges: usize,
    pub marker_only_used_stream_limit: usize,
    pub retained_open_info_bytes: usize,
    pub retained_open_info_bytes_budget: usize,
    pub retained_peer_reason_bytes: usize,
    pub retained_peer_reason_bytes_budget: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryStats {
    pub tracked_bytes: usize,
    pub hard_cap: usize,
    pub over_cap: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HiddenStateStats {
    pub retained: usize,
    pub soft_limit: usize,
    pub hard_limit: usize,
    pub at_soft_limit: bool,
    pub at_hard_limit: bool,
    pub refused: u64,
    pub reaped: u64,
    pub unread_bytes_discarded: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReasonStats {
    pub reset: HashMap<u64, u64>,
    pub reset_overflow: u64,
    pub abort: HashMap<u64, u64>,
    pub abort_overflow: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiagnosticStats {
    pub dropped_priority_updates: u64,
    pub dropped_local_priority_updates: u64,
    pub late_data_after_close_read: u64,
    pub late_data_after_reset: u64,
    pub late_data_after_abort: u64,
    pub coalesced_terminal_signals: u64,
    pub superseded_terminal_signals: u64,
    pub visible_terminal_churn_events: u64,
    pub group_rebucket_events: u64,
    pub hidden_abort_churn_events: u64,
    pub skipped_close_on_dead_io: u64,
    pub close_frame_flush_errors: u64,
    pub close_completion_timeouts: u64,
    pub graceful_close_timeouts: u64,
    pub keepalive_timeouts: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PressureStats {
    pub receive_backlog_bytes: u64,
    pub receive_backlog_high: bool,
    pub aggregate_late_data_bytes: u64,
    pub aggregate_late_data_at_cap: bool,
    pub retained_state_bytes: usize,
    pub tracked_buffered_bytes: usize,
    pub tracked_buffered_limit: usize,
    pub tracked_buffered_high: bool,
    pub tracked_buffered_at_cap: bool,
    pub buffered_receive_bytes: usize,
    pub recv_session_advertised_bytes: u64,
    pub recv_session_received_bytes: u64,
    pub recv_session_pending_bytes: u64,
    pub outstanding_ping_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlushStats {
    pub count: u64,
    pub last_at: Option<Instant>,
    pub last_frames: u64,
    pub last_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TelemetryStats {
    pub last_open_latency: Option<Duration>,
    pub send_rate_estimate_bytes_per_second: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgressStats {
    pub inbound_frame_at: Option<Instant>,
    pub control_progress_at: Option<Instant>,
    pub transport_write_at: Option<Instant>,
    pub stream_progress_at: Option<Instant>,
    pub application_progress_at: Option<Instant>,
    pub ping_sent_at: Option<Instant>,
    pub pong_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AbuseStats {
    pub ignored_control: u64,
    pub ignored_control_budget: u64,
    pub no_op_zero_data: u64,
    pub no_op_zero_data_budget: u64,
    pub inbound_ping: u64,
    pub inbound_ping_budget: u64,
    pub no_op_max_data: u64,
    pub no_op_max_data_budget: u64,
    pub no_op_blocked: u64,
    pub no_op_blocked_budget: u64,
    pub no_op_priority_update: u64,
    pub no_op_priority_update_budget: u64,
    pub dropped_priority_update: u64,
    pub inbound_control_frames: u64,
    pub inbound_control_frame_budget: u64,
    pub inbound_control_bytes: usize,
    pub inbound_control_bytes_budget: usize,
    pub inbound_ext_frames: u64,
    pub inbound_ext_frame_budget: u64,
    pub inbound_ext_bytes: usize,
    pub inbound_ext_bytes_budget: usize,
    pub inbound_mixed_frames: u64,
    pub inbound_mixed_frame_budget: u64,
    pub inbound_mixed_bytes: usize,
    pub inbound_mixed_bytes_budget: usize,
    pub group_rebucket_churn: u64,
    pub group_rebucket_churn_budget: u64,
    pub hidden_abort_churn: u64,
    pub hidden_abort_churn_budget: u64,
    pub visible_terminal_churn: u64,
    pub visible_terminal_churn_budget: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterQueueStats {
    pub urgent_jobs: usize,
    pub advisory_jobs: usize,
    pub ordinary_jobs: usize,
    pub queued_bytes: usize,
    pub max_bytes: usize,
    pub urgent_queued_bytes: usize,
    pub urgent_max_bytes: usize,
    pub advisory_queued_bytes: usize,
    pub data_queued_bytes: usize,
    pub session_data_high_watermark: usize,
    pub per_stream_data_high_watermark: usize,
    pub pending_control_bytes: usize,
    pub pending_control_bytes_budget: usize,
    pub pending_priority_bytes: usize,
    pub pending_priority_bytes_budget: usize,
    pub max_batch_frames: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LivenessStats {
    pub keepalive_interval: Duration,
    pub keepalive_max_ping_interval: Duration,
    pub keepalive_timeout: Duration,
    pub ping_outstanding: bool,
    pub ping_stalled: bool,
    pub last_ping_rtt: Option<Duration>,
    pub inbound_idle_for: Duration,
    pub outbound_idle_for: Duration,
}

#[derive(Debug)]
pub(super) enum WriteJob {
    Frame(Frame),
    Frames(Vec<Frame>),
    TrackedFrames(TrackedWriteJob),
    GracefulClose(Frame),
    Shutdown,
    DrainShutdown,
}

#[derive(Debug)]
pub(super) struct TrackedWriteJob {
    pub(super) frames: Vec<Frame>,
    pub(super) completion: WriteCompletion,
}

#[derive(Debug, Clone)]
pub(super) struct WriteCompletion {
    inner: Arc<WriteCompletionInner>,
}

#[derive(Debug)]
struct WriteCompletionInner {
    state: Mutex<WriteCompletionState>,
    cond: Condvar,
}

#[derive(Debug)]
struct WriteCompletionState {
    result: Option<Result<()>>,
    generation: u64,
}

impl WriteCompletion {
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(WriteCompletionInner {
                state: Mutex::new(WriteCompletionState {
                    result: None,
                    generation: 0,
                }),
                cond: Condvar::new(),
            }),
        }
    }

    #[inline]
    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    #[inline]
    pub(super) fn try_result(&self) -> Option<Result<()>> {
        self.inner.state.lock().unwrap().result.clone()
    }

    #[inline]
    pub(super) fn generation(&self) -> u64 {
        self.inner.state.lock().unwrap().generation
    }

    pub(super) fn wait_for_change_since(&self, generation: u64, timeout: Duration) {
        if timeout.is_zero() {
            return;
        }
        let state = self.inner.state.lock().unwrap();
        if state.result.is_none() && state.generation == generation {
            let timeout = timeout.min(MAX_CONDVAR_TIMED_WAIT);
            drop(
                self.inner
                    .cond
                    .wait_timeout_while(state, timeout, |state| {
                        state.result.is_none() && state.generation == generation
                    })
                    .unwrap(),
            );
        }
    }

    #[inline]
    pub(super) fn complete_ok(&self) {
        self.complete(Ok(()));
    }

    #[inline]
    pub(super) fn complete_err(&self, err: Error) {
        self.complete(Err(err));
    }

    #[inline]
    pub(super) fn notify_waiters(&self) {
        {
            let mut state = self.inner.state.lock().unwrap();
            state.generation = next_generation(state.generation);
        }
        self.inner.cond.notify_all();
    }

    #[inline]
    fn complete(&self, result: Result<()>) {
        let completed = {
            let mut state = self.inner.state.lock().unwrap();
            if state.result.is_some() {
                false
            } else {
                state.result = Some(result);
                state.generation = next_generation(state.generation);
                true
            }
        };
        if completed {
            self.inner.cond.notify_all();
        }
    }
}

#[derive(Clone)]
pub struct Conn {
    pub(super) inner: Arc<Inner>,
}

pub(super) trait RuntimeTransportControl: Send + Sync {
    fn close(&self);
}

pub(super) struct Inner {
    pub(super) write_queue: Arc<WriteQueue>,
    pub(super) transport_control: Option<Arc<dyn RuntimeTransportControl>>,
    pub(super) local_addr: Option<SocketAddr>,
    pub(super) peer_addr: Option<SocketAddr>,
    pub(super) state: Mutex<ConnState>,
    pub(super) cond: Condvar,
    pub(super) local_preface: Preface,
    pub(super) peer_preface: Preface,
    pub(super) negotiated: Negotiated,
    pub(super) close_drain_timeout: Duration,
    pub(super) go_away_drain_interval: Duration,
    pub(super) session_memory_cap: Option<usize>,
    pub(super) session_data_high_watermark: usize,
    pub(super) per_stream_data_high_watermark: usize,
    pub(super) stop_sending_graceful_drain_window: Option<Duration>,
    pub(super) stop_sending_graceful_tail_cap: Option<u64>,
    pub(super) keepalive_interval: Duration,
    pub(super) keepalive_max_ping_interval: Duration,
    pub(super) keepalive_timeout: Duration,
    pub(super) ping_padding: bool,
    pub(super) ping_padding_min_bytes: u64,
    pub(super) ping_padding_max_bytes: u64,
    pub(super) event_handler: Option<EventHandler>,
    pub(super) event_dispatch: Mutex<EventDispatchState>,
}

pub(super) struct EventDispatchState {
    pub(super) emitting: bool,
    pub(super) queue: VecDeque<Event>,
}

pub(super) struct ConnState {
    pub(super) state: SessionState,
    pub(super) close_error: Option<Error>,
    pub(super) peer_close_error: Option<PeerCloseError>,
    pub(super) peer_go_away_error: Option<PeerGoAwayError>,
    pub(super) session_closed_event_sent: bool,
    pub(super) graceful_close_active: bool,
    pub(super) ignore_peer_non_close: bool,
    pub(super) streams: HashMap<u64, Arc<StreamInner>>,
    pub(super) scheduler: BatchScheduler,
    pub(super) inflight_data_by_stream: HashMap<u64, usize>,
    pub(super) tombstones: HashMap<u64, StreamTombstone>,
    pub(super) tombstone_order: VecDeque<u64>,
    pub(super) hidden_tombstone_order: VecDeque<u64>,
    pub(super) tombstone_limit: usize,
    pub(super) hidden_tombstone_limit: usize,
    pub(super) hidden_tombstones: usize,
    pub(super) used_markers: HashMap<u64, TerminalDataDisposition>,
    pub(super) used_marker_order: VecDeque<u64>,
    pub(super) used_marker_ranges: Vec<UsedMarkerRange>,
    pub(super) used_marker_range_mode: bool,
    pub(super) used_marker_limit: usize,
    pub(super) provisional_bidi: VecDeque<Arc<StreamInner>>,
    pub(super) provisional_uni: VecDeque<Arc<StreamInner>>,
    pub(super) accept_bidi: VecDeque<Arc<StreamInner>>,
    pub(super) accept_uni: VecDeque<Arc<StreamInner>>,
    pub(super) accept_backlog_limit: usize,
    pub(super) accept_limit_bidi: usize,
    pub(super) accept_limit_uni: usize,
    pub(super) accept_backlog_bytes: usize,
    pub(super) accept_backlog_bytes_limit: usize,
    pub(super) accept_backlog_refused: u64,
    pub(super) retained_open_info_bytes: usize,
    pub(super) retained_open_info_bytes_budget: usize,
    pub(super) retained_peer_reason_bytes: usize,
    pub(super) retained_peer_reason_bytes_budget: usize,
    pub(super) reset_reason_counts: HashMap<u64, u64>,
    pub(super) reset_reason_overflow: u64,
    pub(super) abort_reason_counts: HashMap<u64, u64>,
    pub(super) abort_reason_overflow: u64,
    pub(super) next_accept_seq: u64,
    pub(super) next_local_bidi: u64,
    pub(super) next_local_uni: u64,
    pub(super) max_provisional_bidi: usize,
    pub(super) max_provisional_uni: usize,
    pub(super) provisional_open_limited_count: u64,
    pub(super) provisional_open_expired_count: u64,
    pub(super) next_peer_bidi: u64,
    pub(super) next_peer_uni: u64,
    pub(super) active: ActiveStreamStats,
    pub(super) send_session_used: u64,
    pub(super) send_session_max: u64,
    pub(super) send_session_blocked_at: Option<u64>,
    pub(super) recv_session_used: u64,
    pub(super) recv_session_buffered: u64,
    pub(super) recv_session_retained: usize,
    pub(super) recv_session_advertised: u64,
    pub(super) recv_session_pending: u64,
    pub(super) recv_replenish_retry: bool,
    pub(super) late_data_per_stream_cap: Option<u64>,
    pub(super) late_data_aggregate_received: u64,
    pub(super) late_data_aggregate_cap: u64,
    pub(super) ignored_control_window_start: Option<Instant>,
    pub(super) ignored_control_count: u64,
    pub(super) ignored_control_budget: u64,
    pub(super) no_op_zero_data_window_start: Option<Instant>,
    pub(super) no_op_zero_data_count: u64,
    pub(super) no_op_zero_data_budget: u64,
    pub(super) inbound_ping_window_start: Option<Instant>,
    pub(super) inbound_ping_count: u64,
    pub(super) inbound_ping_budget: u64,
    pub(super) no_op_max_data_window_start: Option<Instant>,
    pub(super) no_op_max_data_count: u64,
    pub(super) no_op_max_data_budget: u64,
    pub(super) no_op_blocked_window_start: Option<Instant>,
    pub(super) no_op_blocked_count: u64,
    pub(super) no_op_blocked_budget: u64,
    pub(super) no_op_priority_update_window_start: Option<Instant>,
    pub(super) no_op_priority_update_count: u64,
    pub(super) no_op_priority_update_budget: u64,
    pub(super) dropped_priority_update_count: u64,
    pub(super) dropped_local_priority_update_count: u64,
    pub(super) late_data_after_close_read_bytes: u64,
    pub(super) late_data_after_reset_bytes: u64,
    pub(super) late_data_after_abort_bytes: u64,
    pub(super) superseded_terminal_signal_count: u64,
    pub(super) hidden_streams_refused: u64,
    pub(super) hidden_streams_reaped: u64,
    pub(super) hidden_unread_bytes_discarded: u64,
    pub(super) skipped_close_on_dead_io_count: u64,
    pub(super) close_frame_flush_error_count: u64,
    pub(super) close_completion_timeout_count: u64,
    pub(super) graceful_close_timeout_count: u64,
    pub(super) keepalive_timeout_count: u64,
    pub(super) abuse_window: Duration,
    pub(super) inbound_control_window_start: Option<Instant>,
    pub(super) inbound_control_frames: u64,
    pub(super) inbound_control_bytes: usize,
    pub(super) inbound_control_frame_budget: u64,
    pub(super) inbound_control_bytes_budget: usize,
    pub(super) inbound_ext_window_start: Option<Instant>,
    pub(super) inbound_ext_frames: u64,
    pub(super) inbound_ext_bytes: usize,
    pub(super) inbound_ext_frame_budget: u64,
    pub(super) inbound_ext_bytes_budget: usize,
    pub(super) inbound_mixed_window_start: Option<Instant>,
    pub(super) inbound_mixed_frames: u64,
    pub(super) inbound_mixed_bytes: usize,
    pub(super) inbound_mixed_frame_budget: u64,
    pub(super) inbound_mixed_bytes_budget: usize,
    pub(super) group_rebucket_churn_window_start: Option<Instant>,
    pub(super) group_rebucket_churn_count: u64,
    pub(super) group_rebucket_churn_budget: u64,
    pub(super) hidden_abort_churn_window: Duration,
    pub(super) hidden_abort_churn_window_start: Option<Instant>,
    pub(super) hidden_abort_churn_count: u64,
    pub(super) hidden_abort_churn_budget: u64,
    pub(super) visible_terminal_churn_window: Duration,
    pub(super) visible_terminal_churn_window_start: Option<Instant>,
    pub(super) visible_terminal_churn_count: u64,
    pub(super) visible_terminal_churn_budget: u64,
    pub(super) local_go_away_bidi: u64,
    pub(super) local_go_away_uni: u64,
    pub(super) local_go_away_issued: bool,
    pub(super) peer_go_away_bidi: u64,
    pub(super) peer_go_away_uni: u64,
    pub(super) ping_waiter: Option<UserPing>,
    pub(super) canceled_ping_payload: Option<CanceledPingPayload>,
    pub(super) keepalive_ping: Option<KeepalivePing>,
    pub(super) last_inbound_at: Instant,
    pub(super) last_outbound_at: Instant,
    pub(super) send_rate_estimate: u64,
    pub(super) flush_count: u64,
    pub(super) last_flush_at: Option<Instant>,
    pub(super) last_flush_frames: u64,
    pub(super) last_flush_bytes: usize,
    pub(super) last_open_latency: Option<Duration>,
    pub(super) last_ping_rtt: Option<Duration>,
    pub(super) last_control_progress_at: Instant,
    pub(super) last_stream_progress_at: Option<Instant>,
    pub(super) last_application_progress_at: Option<Instant>,
    pub(super) last_ping_sent_at: Option<Instant>,
    pub(super) last_pong_at: Option<Instant>,
    pub(super) blocked_write_total: Duration,
    pub(super) read_idle_ping_due_at: Option<Instant>,
    pub(super) write_idle_ping_due_at: Option<Instant>,
    pub(super) max_ping_due_at: Option<Instant>,
    pub(super) keepalive_jitter_state: u64,
    pub(super) ping_nonce_state: u64,
    pub(super) last_ping_padding_len: u64,
    pub(super) sent_frames: u64,
    pub(super) received_frames: u64,
    pub(super) sent_data_bytes: u64,
    pub(super) received_data_bytes: u64,
    pub(super) accepted_streams: u64,
}

pub(super) struct PingSlot {
    pub(super) result: Mutex<Option<Result<Duration>>>,
    pub(super) cond: Condvar,
    pub(super) sent_at: Instant,
    pub(super) accepts_padded_pong: bool,
}

pub(super) struct UserPing {
    pub(super) payload: Vec<u8>,
    pub(super) slot: Arc<PingSlot>,
}

pub(super) struct KeepalivePing {
    pub(super) payload: Vec<u8>,
    pub(super) sent_at: Instant,
    pub(super) accepts_padded_pong: bool,
}

pub(super) struct CanceledPingPayload {
    pub(super) nonce: u64,
    pub(super) hash: u64,
    pub(super) len: usize,
    pub(super) accepts_padded_pong: bool,
}

pub(super) struct StreamInner {
    pub(super) conn: Arc<Inner>,
    pub(super) id: AtomicU64,
    pub(super) bidi: bool,
    pub(super) opened_locally: bool,
    pub(super) application_visible: bool,
    pub(super) local_send: bool,
    pub(super) local_recv: bool,
    pub(super) state: Mutex<StreamState>,
    pub(super) cond: Condvar,
}

pub(super) struct StreamState {
    pub(super) recv_buf: RecvBuffer,
    pub(super) recv_fin: bool,
    pub(super) recv_reset: Option<(u64, String)>,
    pub(super) aborted: Option<(u64, String)>,
    pub(super) abort_source: ErrorSource,
    pub(super) read_stopped: bool,
    pub(super) read_stop_pending_code: Option<u64>,
    pub(super) read_deadline: Option<Instant>,
    pub(super) write_deadline: Option<Instant>,
    pub(super) write_completion: Option<WriteCompletion>,
    pub(super) write_in_progress: bool,
    pub(super) pending_data_frames: usize,
    pub(super) pending_terminal_frames: usize,
    pub(super) send_fin: bool,
    pub(super) send_reset: Option<(u64, String)>,
    pub(super) send_reset_from_stop: bool,
    pub(super) stopped_by_peer: Option<(u64, String)>,
    pub(super) provisional_created_at: Option<Instant>,
    pub(super) opened_on_wire: bool,
    pub(super) peer_visible: bool,
    pub(super) received_open: bool,
    pub(super) send_used: u64,
    pub(super) send_max: u64,
    pub(super) send_blocked_at: Option<u64>,
    pub(super) recv_used: u64,
    pub(super) recv_advertised: u64,
    pub(super) recv_pending: u64,
    pub(super) late_data_received: u64,
    pub(super) late_data_cap: u64,
    pub(super) open_prefix: Vec<u8>,
    pub(super) open_info: Vec<u8>,
    pub(super) retained_open_info_bytes: usize,
    pub(super) metadata: StreamMetadata,
    pub(super) metadata_revision: u64,
    pub(super) pending_priority_update: Option<Vec<u8>>,
    pub(super) open_initial_group: Option<u64>,
    pub(super) opened_event_sent: bool,
    pub(super) accepted_event_sent: bool,
    pub(super) accept_pending: bool,
    pub(super) accept_seq: u64,
    pub(super) accept_backlog_bytes: usize,
    pub(super) active_counted: bool,
    pub(super) visible_churn_counted: bool,
    pub(super) retained_recv_reset_reason_bytes: usize,
    pub(super) retained_abort_reason_bytes: usize,
    pub(super) retained_stopped_reason_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TerminalDataAction {
    Ignore,
    Abort(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LateDataCause {
    None,
    CloseRead,
    Reset,
    Abort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TerminalDataDisposition {
    pub(super) action: TerminalDataAction,
    pub(super) cause: LateDataCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StreamTombstone {
    pub(super) data_disposition: TerminalDataDisposition,
    pub(super) late_data_received: u64,
    pub(super) late_data_cap: u64,
    pub(super) hidden: bool,
    pub(super) created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UsedMarkerRange {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) disposition: TerminalDataDisposition,
}

#[derive(Clone)]
pub struct Stream {
    pub(super) inner: Arc<StreamInner>,
}

#[derive(Clone)]
pub struct SendStream {
    pub(super) inner: Arc<StreamInner>,
}

#[derive(Clone)]
pub struct RecvStream {
    pub(super) inner: Arc<StreamInner>,
}
