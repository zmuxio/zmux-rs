//! Optional QUIC adapter support for zmux.
//!
//! This crate is intentionally separate from the core `zmux` crate so normal
//! users of native ZMux do not compile or import QUIC dependencies. Adapter
//! streams start with `varint(metadata_len) + STREAM-METADATA-TLV...` when
//! open-time metadata is present.
//!
//! Mapping rules:
//! - bidirectional and unidirectional open / accept map directly to QUIC
//!   streams;
//! - open-time zmux metadata is carried in the per-stream prelude;
//! - a fresh locally opened bidirectional stream writes that prelude before a
//!   read-side stop so the peer can parse adapter metadata before seeing
//!   STOP_SENDING;
//! - fresh write-side reset visibility is not treated as portable because QUIC
//!   RESET_STREAM may discard a just-written prelude;
//! - accepted-stream prelude parsing is concurrency-bounded so stalled or
//!   invalid adapter preludes do not block later ready streams;
//! - post-open metadata updates are not representable on the QUIC stream wire
//!   and return an adapter-local unsupported error;
//! - QUIC stream termination carries numeric codes, while stream-level reason
//!   strings remain advisory at the zmux API layer.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::future::Future;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex, Semaphore};
use zmux::{
    build_open_metadata_prefix, parse_stream_metadata_bytes_view, read_varint, AsyncBoxFuture,
    AsyncDuplexStreamHandle, AsyncRecvStreamHandle, AsyncSendStreamHandle, AsyncSession,
    AsyncStreamHandle, OpenOptions, OpenRequest, OpenSend, Result, StreamMetadata, WritePayload,
    CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_HINTS, CAPABILITY_STREAM_GROUPS,
};

const STREAM_PRELUDE_MAX_PAYLOAD: u64 = 16 << 10;
const QUINN_WRITE_VECTORED_COALESCE_MAX_BYTES: usize = 64 << 10;
const OPEN_METADATA_CAPABILITIES: u64 =
    CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
pub const DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT: usize = 8;
pub const MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT: usize = 1024;
const ACCEPTED_PRELUDE_RESULT_QUEUE_CAP: usize = 32;
const MAX_REASON_STATS_CODES: usize = 1024;

static DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT_VALUE: AtomicUsize =
    AtomicUsize::new(DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT);

#[derive(Debug, Clone, Copy, Default)]
struct AdapterAddresses {
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
}

pub fn target_claims() -> &'static [zmux::Claim] {
    &[zmux::Claim::StreamAdapterProfileV1]
}

pub fn target_implementation_profiles() -> &'static [zmux::ImplementationProfile] {
    &[]
}

pub fn target_suites() -> &'static [zmux::ConformanceSuite] {
    &[zmux::ConformanceSuite::StreamAdapterProfile]
}

fn default_accepted_prelude_max_concurrent() -> usize {
    let current = DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT_VALUE.load(Ordering::Acquire);
    if current > 0 {
        current.min(MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT)
    } else {
        1
    }
}

fn set_default_accepted_prelude_max_concurrent(max: usize) {
    let max = if max == 0 {
        DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT
    } else {
        max.min(MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT)
    };
    DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT_VALUE.store(max, Ordering::Release);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptedStreamMetadata {
    pub metadata: StreamMetadata,
    pub metadata_valid: bool,
}

impl AcceptedStreamMetadata {
    pub fn metadata(&self) -> &StreamMetadata {
        &self.metadata
    }

    pub fn is_metadata_valid(&self) -> bool {
        self.metadata_valid
    }

    pub fn open_info(&self) -> &[u8] {
        self.metadata.open_info()
    }

    pub fn has_open_info(&self) -> bool {
        self.metadata.has_open_info()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AcceptedPreludeReadTimeout {
    #[default]
    Default,
    Disabled,
    Timeout(Duration),
}

impl AcceptedPreludeReadTimeout {
    fn normalize(self) -> Option<Duration> {
        match self {
            Self::Default => Some(DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT),
            Self::Disabled => None,
            Self::Timeout(timeout) if timeout.is_zero() => {
                Some(DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT)
            }
            Self::Timeout(timeout) => Some(timeout),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionOptions {
    pub accepted_prelude_read_timeout: AcceptedPreludeReadTimeout,
    pub accepted_prelude_max_concurrent: Option<usize>,
    pub local_addr: Option<SocketAddr>,
    pub peer_addr: Option<SocketAddr>,
}

impl SessionOptions {
    /// Returns the process-wide default accepted prelude parsing concurrency.
    ///
    /// `SessionOptions::default()` follows this value until a session explicitly
    /// sets `accepted_prelude_max_concurrent`.
    pub fn default_accepted_prelude_max_concurrent() -> usize {
        default_accepted_prelude_max_concurrent()
    }

    /// Updates the process-wide accepted prelude parsing concurrency default.
    ///
    /// Values above `MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT` are clamped. Passing
    /// zero restores the built-in `DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT`
    /// value.
    pub fn set_default_accepted_prelude_max_concurrent(max: usize) {
        set_default_accepted_prelude_max_concurrent(max);
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn accepted_prelude_read_timeout(mut self, timeout: Duration) -> Self {
        self.accepted_prelude_read_timeout = AcceptedPreludeReadTimeout::Timeout(timeout);
        self
    }

    #[must_use]
    pub fn disable_accepted_prelude_read_timeout(mut self) -> Self {
        self.accepted_prelude_read_timeout = AcceptedPreludeReadTimeout::Disabled;
        self
    }

    /// Sets this session's accepted prelude parsing concurrency.
    ///
    /// Passing zero leaves the session on the current process-wide default.
    #[must_use]
    pub fn accepted_prelude_max_concurrent(mut self, max: usize) -> Self {
        self.accepted_prelude_max_concurrent = Some(max);
        self
    }

    #[must_use]
    pub fn local_addr(mut self, addr: SocketAddr) -> Self {
        self.local_addr = Some(addr);
        self
    }

    #[must_use]
    pub fn peer_addr(mut self, addr: SocketAddr) -> Self {
        self.peer_addr = Some(addr);
        self
    }

    #[must_use]
    pub fn addresses(
        mut self,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        self.local_addr = local_addr;
        self.peer_addr = peer_addr;
        self
    }
}

pub fn build_stream_prelude(opts: &OpenOptions) -> Result<Vec<u8>> {
    let prelude = build_open_metadata_prefix(
        OPEN_METADATA_CAPABILITIES,
        opts.initial_priority(),
        opts.initial_group(),
        opts.open_info_bytes(),
        STREAM_PRELUDE_MAX_PAYLOAD,
    )?;
    if prelude.is_empty() {
        Ok(vec![0])
    } else {
        Ok(prelude)
    }
}

pub fn read_stream_prelude<R: Read>(reader: &mut R) -> Result<AcceptedStreamMetadata> {
    let (metadata_len, prefix_len) =
        read_varint(reader).map_err(|_| protocol_prelude_error("parse stream prelude length"))?;
    if metadata_len == 0 {
        return Ok(AcceptedStreamMetadata {
            metadata: StreamMetadata::default(),
            metadata_valid: true,
        });
    }
    let metadata_len = checked_prelude_metadata_len(metadata_len, prefix_len)?;
    let mut metadata_raw = vec![0u8; metadata_len];
    reader.read_exact(&mut metadata_raw).map_err(|err| {
        if err.kind() == ErrorKind::UnexpectedEof {
            protocol_prelude_error("unexpected EOF in stream prelude")
        } else {
            err.into()
        }
    })?;
    let (metadata, metadata_valid) = parse_stream_metadata_bytes_view(&metadata_raw)
        .map_err(|_| protocol_prelude_error("malformed stream prelude metadata"))?;
    Ok(AcceptedStreamMetadata {
        metadata: metadata.try_to_owned()?,
        metadata_valid,
    })
}

fn normalize_accepted_prelude_read_timeout(opts: SessionOptions) -> Option<Duration> {
    opts.accepted_prelude_read_timeout.normalize()
}

fn normalize_accepted_prelude_max_concurrent(max: Option<usize>) -> usize {
    match max {
        Some(max) if max > 0 => max.min(MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT),
        _ => default_accepted_prelude_max_concurrent(),
    }
}

#[derive(Clone)]
pub struct QuinnSession {
    conn: quinn::Connection,
    accepted_prelude_read_timeout: Option<Duration>,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    prepare_sem: Arc<Semaphore>,
    active: Arc<ActiveCounters>,
    stats: Arc<AdapterStats>,
    accept_shutdown: watch::Sender<()>,
    bidi_accept: Arc<AsyncMutex<Option<mpsc::Receiver<Result<QuinnStream>>>>>,
    uni_accept: Arc<AsyncMutex<Option<mpsc::Receiver<Result<QuinnRecvStream>>>>>,
}

impl QuinnSession {
    #[must_use]
    pub fn new(conn: quinn::Connection) -> Self {
        Self::with_options(conn, SessionOptions::default())
    }

    #[must_use]
    pub fn with_options(conn: quinn::Connection, opts: SessionOptions) -> Self {
        let (accept_shutdown, _) = watch::channel(());
        let local_addr = opts.local_addr;
        let peer_addr = opts.peer_addr.or_else(|| Some(conn.remote_address()));
        Self {
            conn,
            accepted_prelude_read_timeout: normalize_accepted_prelude_read_timeout(opts),
            local_addr,
            peer_addr,
            prepare_sem: Arc::new(Semaphore::new(normalize_accepted_prelude_max_concurrent(
                opts.accepted_prelude_max_concurrent,
            ))),
            active: Arc::new(ActiveCounters::default()),
            stats: Arc::new(AdapterStats::new()),
            accept_shutdown,
            bidi_accept: Arc::new(AsyncMutex::new(None)),
            uni_accept: Arc::new(AsyncMutex::new(None)),
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    pub async fn accept_stream(&self) -> Result<QuinnStream> {
        let mut receiver = self.bidi_accept.lock().await;
        if receiver.is_none() {
            let (tx, rx) = mpsc::channel(ACCEPTED_PRELUDE_RESULT_QUEUE_CAP);
            *receiver = Some(rx);
            self.spawn_bidi_accept_loop(tx);
        }
        let receiver = receiver.as_mut().expect("bidi accept receiver initialized");
        loop {
            match receiver.recv().await {
                Some(Ok(stream)) => {
                    self.stats.note_accepted_stream();
                    return Ok(stream);
                }
                Some(Err(err)) if accepted_prelude_rejectable(&err) => continue,
                Some(Err(err)) => return Err(err),
                None => return Err(zmux::Error::session_closed()),
            }
        }
    }

    pub async fn accept_stream_timeout(&self, timeout: Duration) -> Result<QuinnStream> {
        with_timeout(self.accept_stream(), timeout, "accept").await
    }

    pub async fn accept_uni_stream(&self) -> Result<QuinnRecvStream> {
        let mut receiver = self.uni_accept.lock().await;
        if receiver.is_none() {
            let (tx, rx) = mpsc::channel(ACCEPTED_PRELUDE_RESULT_QUEUE_CAP);
            *receiver = Some(rx);
            self.spawn_uni_accept_loop(tx);
        }
        let receiver = receiver.as_mut().expect("uni accept receiver initialized");
        loop {
            match receiver.recv().await {
                Some(Ok(stream)) => {
                    self.stats.note_accepted_stream();
                    return Ok(stream);
                }
                Some(Err(err)) if accepted_prelude_rejectable(&err) => continue,
                Some(Err(err)) => return Err(err),
                None => return Err(zmux::Error::session_closed()),
            }
        }
    }

    pub async fn accept_uni_stream_timeout(&self, timeout: Duration) -> Result<QuinnRecvStream> {
        with_timeout(self.accept_uni_stream(), timeout, "accept").await
    }

    fn spawn_bidi_accept_loop(&self, tx: mpsc::Sender<Result<QuinnStream>>) {
        let conn = self.conn.clone();
        let timeout = self.accepted_prelude_read_timeout;
        let addresses = AdapterAddresses {
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
        };
        let sem = self.prepare_sem.clone();
        let active = self.active.clone();
        let stats = self.stats.clone();
        let mut shutdown = self.accept_shutdown.subscribe();
        tokio::spawn(async move {
            loop {
                let (send, recv) = match accept_bi_or_shutdown(&conn, &mut shutdown).await {
                    Some(Ok(streams)) => streams,
                    None => return,
                    Some(Err(err)) => {
                        publish_bidi_accept_result(
                            &tx,
                            Err(translate_connection_error(err)),
                            &conn,
                        )
                        .await;
                        return;
                    }
                };
                let permit = match acquire_prepare_permit_or_shutdown(&sem, &mut shutdown).await {
                    Some(Ok(permit)) => permit,
                    None => return,
                    Some(Err(_)) => {
                        let _ = tx.send(Err(zmux::Error::session_closed())).await;
                        return;
                    }
                };
                let tx = tx.clone();
                let active = active.clone();
                let stats = stats.clone();
                let conn = conn.clone();
                let mut worker_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(result) = prepare_accepted_bidi_stream_or_shutdown(
                        send,
                        recv,
                        timeout,
                        addresses,
                        active,
                        stats,
                        &mut worker_shutdown,
                    )
                    .await
                    {
                        publish_bidi_accept_result(&tx, result, &conn).await;
                    }
                });
            }
        });
    }

    fn spawn_uni_accept_loop(&self, tx: mpsc::Sender<Result<QuinnRecvStream>>) {
        let conn = self.conn.clone();
        let timeout = self.accepted_prelude_read_timeout;
        let addresses = AdapterAddresses {
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
        };
        let sem = self.prepare_sem.clone();
        let active = self.active.clone();
        let stats = self.stats.clone();
        let mut shutdown = self.accept_shutdown.subscribe();
        tokio::spawn(async move {
            loop {
                let recv = match accept_uni_or_shutdown(&conn, &mut shutdown).await {
                    Some(Ok(recv)) => recv,
                    None => return,
                    Some(Err(err)) => {
                        publish_uni_accept_result(&tx, Err(translate_connection_error(err)), &conn)
                            .await;
                        return;
                    }
                };
                let permit = match acquire_prepare_permit_or_shutdown(&sem, &mut shutdown).await {
                    Some(Ok(permit)) => permit,
                    None => return,
                    Some(Err(_)) => {
                        let _ = tx.send(Err(zmux::Error::session_closed())).await;
                        return;
                    }
                };
                let tx = tx.clone();
                let active = active.clone();
                let stats = stats.clone();
                let conn = conn.clone();
                let mut worker_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(result) = prepare_accepted_uni_stream_or_shutdown(
                        recv,
                        timeout,
                        addresses,
                        active,
                        stats,
                        &mut worker_shutdown,
                    )
                    .await
                    {
                        publish_uni_accept_result(&tx, result, &conn).await;
                    }
                });
            }
        });
    }

    pub async fn open_stream(&self) -> Result<QuinnStream> {
        self.open_stream_with(OpenRequest::new()).await
    }

    pub async fn open_stream_with(&self, request: impl Into<OpenRequest>) -> Result<QuinnStream> {
        let (opts, timeout) = request.into().into_parts();
        let open = self.open_stream_inner(opts);
        match timeout {
            Some(timeout) => with_timeout(open, timeout, "open").await,
            None => open.await,
        }
    }

    async fn open_stream_inner(&self, opts: OpenOptions) -> Result<QuinnStream> {
        let prelude = PreludeState::local(opts)?;
        let started_at = Instant::now();
        let (send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(translate_connection_error)?;
        let stream = QuinnStream::local(
            send,
            recv,
            prelude,
            self.stats.clone(),
            self.local_addr,
            self.peer_addr,
        );
        if let Err(err) = stream.maybe_send_open_prelude_on_open().await {
            stream.discard_after_open_error(&err).await;
            return Err(err);
        }
        self.stats.note_open_latency(started_at, Instant::now());
        Ok(stream.with_active(self.active.clone(), ActiveKind::LocalBidi))
    }

    pub async fn open_uni_stream(&self) -> Result<QuinnSendStream> {
        self.open_uni_stream_with(OpenRequest::new()).await
    }

    pub async fn open_uni_stream_with(
        &self,
        request: impl Into<OpenRequest>,
    ) -> Result<QuinnSendStream> {
        let (opts, timeout) = request.into().into_parts();
        let open = self.open_uni_stream_inner(opts);
        match timeout {
            Some(timeout) => with_timeout(open, timeout, "open").await,
            None => open.await,
        }
    }

    async fn open_uni_stream_inner(&self, opts: OpenOptions) -> Result<QuinnSendStream> {
        let prelude = PreludeState::local(opts)?;
        let started_at = Instant::now();
        let send = self
            .conn
            .open_uni()
            .await
            .map_err(translate_connection_error)?;
        let stream = QuinnSendStream::local(
            send,
            prelude,
            self.stats.clone(),
            self.local_addr,
            self.peer_addr,
        );
        if let Err(err) = stream.maybe_send_open_prelude_on_open().await {
            stream.discard_after_open_error(&err).await;
            return Err(err);
        }
        self.stats.note_open_latency(started_at, Instant::now());
        Ok(stream.with_active(self.active.clone(), ActiveKind::LocalUni))
    }

    pub async fn open_and_send<'a>(&self, request: impl Into<OpenSend<'a>>) -> Result<QuinnStream> {
        let (opts, payload, timeout) = request.into().into_parts();
        let requested = payload.checked_len()?;
        let start = Instant::now();
        let mut open = OpenRequest::new().options(opts);
        if let Some(timeout) = timeout {
            ensure_positive_session_timeout(timeout, "open", zmux::ErrorOperation::Open)?;
            open = open.timeout(timeout);
        }
        let stream = self
            .open_stream_with(open)
            .await
            .map_err(|err| err.with_session_context(zmux::ErrorOperation::Open))?;
        if requested == 0 {
            return Ok(stream);
        }
        let write_result: Result<()> = async {
            let timeout = timeout
                .map(|timeout| remaining_write_timeout(start, timeout))
                .transpose()?;
            match timeout {
                Some(timeout) => {
                    stream
                        .write_all_timeout(payload, timeout)
                        .await
                        .map_err(|err| {
                            err.with_stream_context(
                                zmux::ErrorOperation::Write,
                                zmux::ErrorDirection::Write,
                            )
                        })?;
                }
                None => {
                    stream.write_all(payload).await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(err) = write_result {
            stream.discard_after_open_error(&err).await;
            return Err(err);
        }
        Ok(stream)
    }

    pub async fn open_uni_and_send<'a>(
        &self,
        request: impl Into<OpenSend<'a>>,
    ) -> Result<QuinnSendStream> {
        let (opts, payload, timeout) = request.into().into_parts();
        let requested = payload.checked_len()?;
        let start = Instant::now();
        let mut open = OpenRequest::new().options(opts);
        if let Some(timeout) = timeout {
            ensure_positive_session_timeout(timeout, "open", zmux::ErrorOperation::Open)?;
            open = open.timeout(timeout);
        }
        let stream = self
            .open_uni_stream_with(open)
            .await
            .map_err(|err| err.with_session_context(zmux::ErrorOperation::Open))?;
        let write_result: Result<()> = async {
            let timeout = timeout
                .map(|timeout| remaining_write_timeout(start, timeout))
                .transpose()?;
            let n = match (payload, timeout) {
                (WritePayload::Bytes(data), Some(timeout)) => stream
                    .write_final_timeout(WritePayload::Bytes(data), timeout)
                    .await
                    .map_err(|err| {
                        err.with_stream_context(
                            zmux::ErrorOperation::Write,
                            zmux::ErrorDirection::Write,
                        )
                    })?,
                (WritePayload::Bytes(data), None) => {
                    stream.write_final(WritePayload::Bytes(data)).await?
                }
                (WritePayload::Vectored(parts), Some(timeout)) => stream
                    .write_vectored_final_timeout(parts, timeout)
                    .await
                    .map_err(|err| {
                        err.with_stream_context(
                            zmux::ErrorOperation::Write,
                            zmux::ErrorDirection::Write,
                        )
                    })?,
                (WritePayload::Vectored(parts), None) => stream.write_vectored_final(parts).await?,
            };
            validate_progress(n, requested)?;
            Ok(())
        }
        .await;
        if let Err(err) = write_result {
            stream.discard_after_open_error(&err).await;
            return Err(err);
        }
        Ok(stream)
    }

    fn close_now(&self, code: quinn::VarInt, reason: &[u8]) {
        let _ = self.accept_shutdown.send(());
        self.conn.close(code, reason);
    }

    pub async fn close(&self) -> Result<()> {
        self.close_now(quinn_varint(0), &[]);
        Ok(())
    }

    pub async fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        let code = checked_session_quinn_varint(code, zmux::ErrorOperation::Close)?;
        self.close_now(code, reason.as_bytes());
        Ok(())
    }

    pub async fn wait(&self) -> Result<()> {
        translate_wait_error(self.conn.closed().await)
    }

    pub async fn wait_timeout(&self, timeout: Duration) -> Result<bool> {
        if self.is_closed() {
            return Ok(true);
        }
        if timeout.is_zero() {
            return Ok(false);
        }
        match tokio::time::timeout(timeout, self.wait()).await {
            Ok(result) => result.map(|_| true),
            Err(_) => Ok(false),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    pub fn close_error(&self) -> Option<zmux::Error> {
        self.conn
            .close_reason()
            .and_then(|err| translate_wait_error(err).err())
    }

    pub fn state(&self) -> zmux::SessionState {
        if self.is_closed() {
            zmux::SessionState::Closed
        } else {
            zmux::SessionState::Ready
        }
    }

    pub fn stats(&self) -> zmux::SessionStats {
        let active_streams = self.active.snapshot();
        let adapter_stats = self.stats.snapshot();
        zmux::SessionStats {
            state: self.state(),
            sent_frames: 0,
            received_frames: 0,
            sent_data_bytes: adapter_stats.sent_data_bytes,
            received_data_bytes: adapter_stats.received_data_bytes,
            open_streams: usize::try_from(active_streams.total).unwrap_or(usize::MAX),
            accepted_streams: adapter_stats.accepted_streams,
            active_streams,
            provisional: Default::default(),
            accept_backlog: Default::default(),
            retention: Default::default(),
            memory: Default::default(),
            abuse: Default::default(),
            hidden: zmux::HiddenStateStats {
                refused: adapter_stats.hidden_refused,
                ..Default::default()
            },
            reasons: adapter_stats.reasons,
            diagnostics: Default::default(),
            pressure: Default::default(),
            flush: adapter_stats.flush,
            telemetry: adapter_stats.telemetry,
            progress: adapter_stats.progress,
            blocked_write_total: adapter_stats.blocked_write_total,
            writer_queue: Default::default(),
            liveness: Default::default(),
        }
    }
}

async fn with_timeout<T>(
    fut: impl Future<Output = Result<T>>,
    timeout: Duration,
    operation: &'static str,
) -> Result<T> {
    if timeout.is_zero() {
        return Err(zmux::Error::timeout(operation));
    }
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| zmux::Error::timeout(operation))?
}

async fn with_optional_timeout<T>(
    fut: impl Future<Output = Result<T>>,
    timeout: Option<Duration>,
    operation: &'static str,
) -> Result<T> {
    match timeout {
        Some(timeout) => with_timeout(fut, timeout, operation).await,
        None => fut.await,
    }
}

fn ensure_positive_session_timeout(
    timeout: Duration,
    operation_name: &'static str,
    operation: zmux::ErrorOperation,
) -> Result<()> {
    if timeout.is_zero() {
        Err(zmux::Error::timeout(operation_name).with_session_context(operation))
    } else {
        Ok(())
    }
}

fn remaining_timeout(start: Instant, timeout: Duration) -> Option<Duration> {
    timeout
        .checked_sub(start.elapsed())
        .filter(|duration| !duration.is_zero())
}

fn timeout_to_deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|timeout| Instant::now().checked_add(timeout))
}

fn remaining_write_timeout(start: Instant, timeout: Duration) -> Result<Duration> {
    remaining_timeout(start, timeout).ok_or_else(|| {
        zmux::Error::timeout("write")
            .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write)
    })
}

fn timeout_until(deadline: Option<Instant>, operation: &'static str) -> Result<Option<Duration>> {
    match deadline {
        Some(deadline) => deadline
            .checked_duration_since(Instant::now())
            .filter(|timeout| !timeout.is_zero())
            .map(Some)
            .ok_or_else(|| zmux::Error::timeout(operation)),
        None => Ok(None),
    }
}

#[derive(Debug)]
struct AdapterStats {
    origin: Instant,
    sent_data_bytes: AtomicU64,
    received_data_bytes: AtomicU64,
    accepted_streams: AtomicU64,
    hidden_refused: AtomicU64,
    flush_count: AtomicU64,
    blocked_write_nanos: AtomicU64,
    last_inbound_frame_at: AtomicU64,
    last_control_progress_at: AtomicU64,
    last_transport_write_at: AtomicU64,
    last_stream_progress_at: AtomicU64,
    last_application_progress_at: AtomicU64,
    last_flush_at: AtomicU64,
    last_flush_bytes: AtomicUsize,
    last_open_latency_nanos: AtomicU64,
    reasons: Mutex<AdapterReasonStats>,
}

#[derive(Debug, Clone)]
struct AdapterStatsSnapshot {
    sent_data_bytes: u64,
    received_data_bytes: u64,
    accepted_streams: u64,
    hidden_refused: u64,
    flush: zmux::FlushStats,
    telemetry: zmux::TelemetryStats,
    progress: zmux::ProgressStats,
    blocked_write_total: Duration,
    reasons: zmux::ReasonStats,
}

#[derive(Debug, Default)]
struct AdapterReasonStats {
    reset: HashMap<u64, u64>,
    reset_overflow: u64,
    abort: HashMap<u64, u64>,
    abort_overflow: u64,
}

impl AdapterStats {
    const NO_DURATION: u64 = u64::MAX;

    fn new() -> Self {
        Self {
            origin: Instant::now(),
            sent_data_bytes: AtomicU64::new(0),
            received_data_bytes: AtomicU64::new(0),
            accepted_streams: AtomicU64::new(0),
            hidden_refused: AtomicU64::new(0),
            flush_count: AtomicU64::new(0),
            blocked_write_nanos: AtomicU64::new(0),
            last_inbound_frame_at: AtomicU64::new(0),
            last_control_progress_at: AtomicU64::new(0),
            last_transport_write_at: AtomicU64::new(0),
            last_stream_progress_at: AtomicU64::new(0),
            last_application_progress_at: AtomicU64::new(0),
            last_flush_at: AtomicU64::new(0),
            last_flush_bytes: AtomicUsize::new(0),
            last_open_latency_nanos: AtomicU64::new(Self::NO_DURATION),
            reasons: Mutex::new(AdapterReasonStats::default()),
        }
    }

    fn snapshot(&self) -> AdapterStatsSnapshot {
        let last_open_latency = match self.last_open_latency_nanos.load(Ordering::Relaxed) {
            Self::NO_DURATION => None,
            nanos => Some(Duration::from_nanos(nanos)),
        };
        let flush_count = self.flush_count.load(Ordering::Relaxed);
        AdapterStatsSnapshot {
            sent_data_bytes: self.sent_data_bytes.load(Ordering::Relaxed),
            received_data_bytes: self.received_data_bytes.load(Ordering::Relaxed),
            accepted_streams: self.accepted_streams.load(Ordering::Relaxed),
            hidden_refused: self.hidden_refused.load(Ordering::Relaxed),
            flush: zmux::FlushStats {
                count: flush_count,
                last_at: self.instant_for_event(self.last_flush_at.load(Ordering::Relaxed)),
                last_frames: u64::from(flush_count != 0),
                last_bytes: self.last_flush_bytes.load(Ordering::Relaxed),
            },
            telemetry: zmux::TelemetryStats {
                last_open_latency,
                send_rate_estimate_bytes_per_second: 0,
            },
            progress: zmux::ProgressStats {
                inbound_frame_at: self
                    .instant_for_event(self.last_inbound_frame_at.load(Ordering::Relaxed)),
                control_progress_at: self
                    .instant_for_event(self.last_control_progress_at.load(Ordering::Relaxed)),
                transport_write_at: self
                    .instant_for_event(self.last_transport_write_at.load(Ordering::Relaxed)),
                stream_progress_at: self
                    .instant_for_event(self.last_stream_progress_at.load(Ordering::Relaxed)),
                application_progress_at: self
                    .instant_for_event(self.last_application_progress_at.load(Ordering::Relaxed)),
                ping_sent_at: None,
                pong_at: None,
            },
            blocked_write_total: Duration::from_nanos(
                self.blocked_write_nanos.load(Ordering::Relaxed),
            ),
            reasons: self.reasons.lock().unwrap().snapshot(),
        }
    }

    fn note_accepted_stream(&self) {
        saturating_add_atomic_u64(&self.accepted_streams, 1);
    }

    fn note_hidden_refused(&self) {
        saturating_add_atomic_u64(&self.hidden_refused, 1);
    }

    fn note_reset_reason(&self, code: u64) {
        self.reasons.lock().unwrap().note_reset(code);
    }

    fn note_abort_reason(&self, code: u64) {
        self.reasons.lock().unwrap().note_abort(code);
    }

    fn note_control_progress(&self) {
        self.note_control_progress_at(Instant::now());
    }

    fn note_control_progress_at(&self, at: Instant) {
        self.last_control_progress_at
            .store(self.event_nanos(at), Ordering::Relaxed);
    }

    fn note_data_read(&self, bytes: usize, at: Instant) {
        if bytes == 0 {
            return;
        }
        let event = self.event_nanos(at);
        saturating_add_atomic_u64(&self.received_data_bytes, usize_to_u64_saturating(bytes));
        self.last_inbound_frame_at.store(event, Ordering::Relaxed);
        self.last_stream_progress_at.store(event, Ordering::Relaxed);
        self.last_application_progress_at
            .store(event, Ordering::Relaxed);
    }

    fn note_data_write(&self, bytes: usize, at: Instant) {
        if bytes == 0 {
            return;
        }
        let event = self.event_nanos(at);
        saturating_add_atomic_u64(&self.sent_data_bytes, usize_to_u64_saturating(bytes));
        self.last_stream_progress_at.store(event, Ordering::Relaxed);
        self.last_application_progress_at
            .store(event, Ordering::Relaxed);
    }

    fn note_flush(&self, bytes: usize, at: Instant) {
        let event = self.event_nanos(at);
        saturating_add_atomic_u64(&self.flush_count, 1);
        self.last_transport_write_at.store(event, Ordering::Relaxed);
        self.last_flush_at.store(event, Ordering::Relaxed);
        self.last_flush_bytes.store(bytes, Ordering::Relaxed);
    }

    fn note_write_wait(&self, started_at: Instant, completed_at: Instant) {
        let elapsed = completed_at.saturating_duration_since(started_at);
        saturating_add_atomic_u64(
            &self.blocked_write_nanos,
            duration_nanos_saturating(elapsed),
        );
    }

    fn note_open_latency(&self, started_at: Instant, completed_at: Instant) {
        let elapsed = completed_at.saturating_duration_since(started_at);
        self.last_open_latency_nanos
            .store(duration_nanos_saturating(elapsed), Ordering::Relaxed);
        self.last_stream_progress_at
            .store(self.event_nanos(completed_at), Ordering::Relaxed);
    }

    fn event_nanos(&self, at: Instant) -> u64 {
        duration_nanos_saturating(at.saturating_duration_since(self.origin)).max(1)
    }

    fn instant_for_event(&self, nanos: u64) -> Option<Instant> {
        if nanos == 0 {
            None
        } else {
            self.origin.checked_add(Duration::from_nanos(nanos))
        }
    }
}

impl AdapterReasonStats {
    fn note_reset(&mut self, code: u64) {
        note_reason(&mut self.reset, &mut self.reset_overflow, code);
    }

    fn note_abort(&mut self, code: u64) {
        note_reason(&mut self.abort, &mut self.abort_overflow, code);
    }

    fn snapshot(&self) -> zmux::ReasonStats {
        zmux::ReasonStats {
            reset: self.reset.clone(),
            reset_overflow: self.reset_overflow,
            abort: self.abort.clone(),
            abort_overflow: self.abort_overflow,
        }
    }
}

#[derive(Debug, Default)]
struct ActiveCounters {
    local_bidi: AtomicUsize,
    local_uni: AtomicUsize,
    peer_bidi: AtomicUsize,
    peer_uni: AtomicUsize,
}

impl ActiveCounters {
    fn add(&self, kind: ActiveKind) {
        saturating_increment_atomic_usize(self.counter(kind));
    }

    fn done(&self, kind: ActiveKind) {
        let counter = self.counter(kind);
        let mut current = counter.load(Ordering::Relaxed);
        while current != 0 {
            match counter.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(next) => current = next,
            }
        }
    }

    fn snapshot(&self) -> zmux::ActiveStreamStats {
        let local_bidi = usize_to_u64_saturating(self.local_bidi.load(Ordering::Relaxed));
        let local_uni = usize_to_u64_saturating(self.local_uni.load(Ordering::Relaxed));
        let peer_bidi = usize_to_u64_saturating(self.peer_bidi.load(Ordering::Relaxed));
        let peer_uni = usize_to_u64_saturating(self.peer_uni.load(Ordering::Relaxed));
        zmux::ActiveStreamStats {
            local_bidi,
            local_uni,
            peer_bidi,
            peer_uni,
            total: local_bidi
                .saturating_add(local_uni)
                .saturating_add(peer_bidi)
                .saturating_add(peer_uni),
        }
    }

    fn counter(&self, kind: ActiveKind) -> &AtomicUsize {
        match kind {
            ActiveKind::LocalBidi => &self.local_bidi,
            ActiveKind::LocalUni => &self.local_uni,
            ActiveKind::PeerBidi => &self.peer_bidi,
            ActiveKind::PeerUni => &self.peer_uni,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ActiveKind {
    LocalBidi,
    LocalUni,
    PeerBidi,
    PeerUni,
}

#[derive(Debug)]
struct ActiveGuard {
    counters: Arc<ActiveCounters>,
    kind: ActiveKind,
    tracked: AtomicBool,
}

#[derive(Debug, Default)]
struct TerminalErrors {
    read: Option<zmux::Error>,
    write: Option<zmux::Error>,
}

impl ActiveGuard {
    fn new(counters: Arc<ActiveCounters>, kind: ActiveKind) -> Self {
        counters.add(kind);
        Self {
            counters,
            kind,
            tracked: AtomicBool::new(true),
        }
    }

    fn finish(&self) {
        if self.tracked.swap(false, Ordering::AcqRel) {
            self.counters.done(self.kind);
        }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

async fn accept_bi_or_shutdown(
    conn: &quinn::Connection,
    shutdown: &mut watch::Receiver<()>,
) -> Option<std::result::Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>> {
    tokio::select! {
        result = conn.accept_bi() => Some(result),
        _ = shutdown.changed() => None,
    }
}

async fn accept_uni_or_shutdown(
    conn: &quinn::Connection,
    shutdown: &mut watch::Receiver<()>,
) -> Option<std::result::Result<quinn::RecvStream, quinn::ConnectionError>> {
    tokio::select! {
        result = conn.accept_uni() => Some(result),
        _ = shutdown.changed() => None,
    }
}

async fn acquire_prepare_permit_or_shutdown(
    sem: &Arc<Semaphore>,
    shutdown: &mut watch::Receiver<()>,
) -> Option<std::result::Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError>> {
    let permit = sem.clone().acquire_owned();
    tokio::select! {
        result = permit => Some(result),
        _ = shutdown.changed() => None,
    }
}

async fn prepare_accepted_bidi_stream_or_shutdown(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    timeout: Option<Duration>,
    addresses: AdapterAddresses,
    active: Arc<ActiveCounters>,
    stats: Arc<AdapterStats>,
    shutdown: &mut watch::Receiver<()>,
) -> Option<Result<QuinnStream>> {
    tokio::select! {
        result = prepare_accepted_bidi_stream(send, recv, timeout, addresses, active, stats) => result,
        _ = shutdown.changed() => None,
    }
}

async fn prepare_accepted_uni_stream_or_shutdown(
    recv: quinn::RecvStream,
    timeout: Option<Duration>,
    addresses: AdapterAddresses,
    active: Arc<ActiveCounters>,
    stats: Arc<AdapterStats>,
    shutdown: &mut watch::Receiver<()>,
) -> Option<Result<QuinnRecvStream>> {
    tokio::select! {
        result = prepare_accepted_uni_stream(recv, timeout, addresses, active, stats) => result,
        _ = shutdown.changed() => None,
    }
}

async fn prepare_accepted_bidi_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    timeout: Option<Duration>,
    addresses: AdapterAddresses,
    active: Arc<ActiveCounters>,
    stats: Arc<AdapterStats>,
) -> Option<Result<QuinnStream>> {
    match read_accepted_metadata_with_timeout(&mut recv, timeout, true).await {
        Ok(metadata) => {
            stats.note_control_progress();
            let stream = QuinnStream::accepted(
                send,
                recv,
                metadata,
                stats,
                addresses.local_addr,
                addresses.peer_addr,
            );
            Some(Ok(stream.with_active(active, ActiveKind::PeerBidi)))
        }
        Err(err) if accepted_prelude_rejectable(&err) => {
            stats.note_hidden_refused();
            let _ = recv.stop(quinn_varint(zmux::ErrorCode::Protocol.as_u64()));
            let _ = send.reset(quinn_varint(zmux::ErrorCode::Protocol.as_u64()));
            None
        }
        Err(err) => Some(Err(err)),
    }
}

async fn prepare_accepted_uni_stream(
    mut recv: quinn::RecvStream,
    timeout: Option<Duration>,
    addresses: AdapterAddresses,
    active: Arc<ActiveCounters>,
    stats: Arc<AdapterStats>,
) -> Option<Result<QuinnRecvStream>> {
    match read_accepted_metadata_with_timeout(&mut recv, timeout, false).await {
        Ok(metadata) => {
            stats.note_control_progress();
            let stream = QuinnRecvStream::accepted(
                recv,
                metadata,
                stats,
                addresses.local_addr,
                addresses.peer_addr,
            );
            Some(Ok(stream.with_active(active, ActiveKind::PeerUni)))
        }
        Err(err) if accepted_prelude_rejectable(&err) => {
            stats.note_hidden_refused();
            let _ = recv.stop(quinn_varint(zmux::ErrorCode::Protocol.as_u64()));
            None
        }
        Err(err) => Some(Err(err)),
    }
}

async fn publish_bidi_accept_result(
    tx: &mpsc::Sender<Result<QuinnStream>>,
    result: Result<QuinnStream>,
    conn: &quinn::Connection,
) {
    let send = tx.send(result);
    tokio::pin!(send);
    tokio::select! {
        biased;
        result = &mut send => {
            if let Err(err) = result {
                if let Ok(stream) = err.0 {
                    let _ = stream
                        .close_with_error(zmux::ErrorCode::Cancelled.as_u64(), "")
                        .await;
                }
            }
        }
        _ = conn.closed() => {}
    }
}

async fn publish_uni_accept_result(
    tx: &mpsc::Sender<Result<QuinnRecvStream>>,
    result: Result<QuinnRecvStream>,
    conn: &quinn::Connection,
) {
    let send = tx.send(result);
    tokio::pin!(send);
    tokio::select! {
        biased;
        result = &mut send => {
            if let Err(err) = result {
                if let Ok(stream) = err.0 {
                    let _ = stream
                        .close_with_error(zmux::ErrorCode::Cancelled.as_u64(), "")
                        .await;
                }
            }
        }
        _ = conn.closed() => {}
    }
}

async fn read_accepted_metadata_with_timeout(
    recv: &mut quinn::RecvStream,
    timeout: Option<Duration>,
    bidirectional: bool,
) -> Result<AcceptedStreamMetadata> {
    let fut = read_accepted_metadata(recv);
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, fut).await.map_err(|_| {
            zmux::Error::timeout("accept").with_stream_context(
                zmux::ErrorOperation::Accept,
                accepted_direction(bidirectional),
            )
        })?,
        None => fut.await,
    }
}

fn accepted_direction(bidirectional: bool) -> zmux::ErrorDirection {
    if bidirectional {
        zmux::ErrorDirection::Both
    } else {
        zmux::ErrorDirection::Read
    }
}

async fn read_accepted_metadata(recv: &mut quinn::RecvStream) -> Result<AcceptedStreamMetadata> {
    read_stream_prelude_quinn(recv).await
}

fn accepted_prelude_rejectable(err: &zmux::Error) -> bool {
    err.scope() == zmux::ErrorScope::Stream
        && (err.operation() == zmux::ErrorOperation::Accept
            || err.operation() == zmux::ErrorOperation::Read)
        && (err.is_timeout()
            || err.is_error_code(zmux::ErrorCode::Protocol)
            || matches!(
                err.termination_kind(),
                zmux::TerminationKind::Abort
                    | zmux::TerminationKind::Reset
                    | zmux::TerminationKind::Stopped
            ))
}

async fn read_stream_prelude_quinn(recv: &mut quinn::RecvStream) -> Result<AcceptedStreamMetadata> {
    let first = read_byte(recv).await?;
    let prefix_len = match first >> 6 {
        0 => 1usize,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut prefix = [0u8; 8];
    prefix[0] = first;
    read_exact_quinn(recv, &mut prefix[1..prefix_len]).await?;
    let (metadata_len, _) = zmux::parse_varint(&prefix[..prefix_len])
        .map_err(|_| protocol_prelude_error("parse stream prelude length"))?;
    if metadata_len == 0 {
        return Ok(AcceptedStreamMetadata {
            metadata: StreamMetadata::default(),
            metadata_valid: true,
        });
    }
    let metadata_len = checked_prelude_metadata_len(metadata_len, prefix_len)?;
    let mut payload = vec![0u8; metadata_len];
    read_exact_quinn(recv, &mut payload).await?;
    let (metadata, metadata_valid) = parse_stream_metadata_bytes_view(&payload)
        .map_err(|_| protocol_prelude_error("malformed stream prelude metadata"))?;
    Ok(AcceptedStreamMetadata {
        metadata: metadata.try_to_owned()?,
        metadata_valid,
    })
}

async fn read_byte(recv: &mut quinn::RecvStream) -> Result<u8> {
    let mut buf = [0u8; 1];
    read_exact_quinn(recv, &mut buf).await?;
    Ok(buf[0])
}

async fn read_exact_quinn(recv: &mut quinn::RecvStream, mut dst: &mut [u8]) -> Result<()> {
    while !dst.is_empty() {
        let n = recv
            .read(dst)
            .await
            .map_err(translate_read_error)?
            .ok_or_else(|| protocol_prelude_error("unexpected EOF in stream prelude"))?;
        if n == 0 {
            return Err(protocol_prelude_error("zero-length read in stream prelude"));
        }
        if n > dst.len() {
            return Err(protocol_prelude_error(
                "stream prelude read reported invalid progress",
            ));
        }
        let (_, rest) = dst.split_at_mut(n);
        dst = rest;
    }
    Ok(())
}

#[derive(Debug)]
struct PreludeState {
    send_prelude: bool,
    prelude_sent: bool,
    prelude: Bytes,
    prelude_offset: usize,
    metadata: StreamMetadata,
}

impl PreludeState {
    fn local(opts: OpenOptions) -> Result<Self> {
        let prelude = build_stream_prelude(&opts)?;
        let (priority, group, open_info) = opts.into_parts();
        Ok(Self {
            send_prelude: true,
            prelude_sent: false,
            prelude: Bytes::from(prelude),
            prelude_offset: 0,
            metadata: StreamMetadata {
                priority,
                group,
                open_info,
            },
        })
    }

    fn accepted(metadata: AcceptedStreamMetadata) -> Self {
        Self {
            send_prelude: false,
            prelude_sent: true,
            prelude: Bytes::new(),
            prelude_offset: 0,
            metadata: metadata.metadata,
        }
    }

    fn has_peer_visible_open_metadata(&self) -> bool {
        self.metadata.priority.is_some()
            || self.metadata.group.is_some()
            || !self.metadata.open_info.is_empty()
    }

    fn update_pre_open_metadata(&mut self, update: zmux::MetadataUpdate) -> Result<bool> {
        if self.prelude_sent {
            return Ok(false);
        }
        if update.priority.is_none() && update.group.is_none() {
            return Err(zmux::Error::local("zmux: metadata update has no fields"));
        }
        if let Some(priority) = update.priority {
            self.metadata.priority = Some(priority);
        }
        if let Some(group) = update.group {
            self.metadata.group = Some(group);
        }
        let mut opts = OpenOptions::new().open_info(&self.metadata.open_info);
        if let Some(priority) = self.metadata.priority {
            opts = opts.priority(priority);
        }
        if let Some(group) = self.metadata.group {
            opts = opts.group(group);
        }
        self.prelude = Bytes::from(build_stream_prelude(&opts)?);
        self.prelude_offset = 0;
        Ok(true)
    }
}

fn prelude_open_info(prelude: &Mutex<PreludeState>) -> Vec<u8> {
    prelude.lock().unwrap().metadata.open_info.clone()
}

fn append_prelude_open_info_to(prelude: &Mutex<PreludeState>, dst: &mut Vec<u8>) {
    dst.extend_from_slice(prelude.lock().unwrap().metadata.open_info());
}

fn prelude_open_info_len(prelude: &Mutex<PreludeState>) -> usize {
    prelude.lock().unwrap().metadata.open_info.len()
}

fn prelude_has_open_info(prelude: &Mutex<PreludeState>) -> bool {
    prelude_open_info_len(prelude) != 0
}

pub struct QuinnStream {
    stream_id: u64,
    opened_locally: bool,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    send: AsyncMutex<quinn::SendStream>,
    recv: AsyncMutex<quinn::RecvStream>,
    prelude: Mutex<PreludeState>,
    read_deadline: Mutex<Option<Instant>>,
    write_deadline: Mutex<Option<Instant>>,
    terminal: Mutex<TerminalErrors>,
    stats: Arc<AdapterStats>,
    active: Option<ActiveGuard>,
    read_closed: AtomicBool,
    write_closed: AtomicBool,
}

impl QuinnStream {
    fn local(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        prelude: PreludeState,
        stats: Arc<AdapterStats>,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        let stream_id = quinn_stream_id(send.id());
        Self {
            stream_id,
            opened_locally: true,
            local_addr,
            peer_addr,
            send: AsyncMutex::new(send),
            recv: AsyncMutex::new(recv),
            prelude: Mutex::new(prelude),
            read_deadline: Mutex::new(None),
            write_deadline: Mutex::new(None),
            terminal: Mutex::new(TerminalErrors::default()),
            stats,
            active: None,
            read_closed: AtomicBool::new(false),
            write_closed: AtomicBool::new(false),
        }
    }

    fn accepted(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        metadata: AcceptedStreamMetadata,
        stats: Arc<AdapterStats>,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        let stream_id = quinn_stream_id(send.id());
        Self {
            stream_id,
            opened_locally: false,
            local_addr,
            peer_addr,
            send: AsyncMutex::new(send),
            recv: AsyncMutex::new(recv),
            prelude: Mutex::new(PreludeState::accepted(metadata)),
            read_deadline: Mutex::new(None),
            write_deadline: Mutex::new(None),
            terminal: Mutex::new(TerminalErrors::default()),
            stats,
            active: None,
            read_closed: AtomicBool::new(false),
            write_closed: AtomicBool::new(false),
        }
    }

    fn with_active(mut self, counters: Arc<ActiveCounters>, kind: ActiveKind) -> Self {
        self.active = Some(ActiveGuard::new(counters, kind));
        self
    }

    fn mark_read_closed(&self) {
        self.mark_read_closed_with(None);
    }

    fn mark_read_closed_with(&self, err: Option<zmux::Error>) {
        if self.read_closed.load(Ordering::Acquire) {
            return;
        }
        let first = {
            let mut terminal = self.terminal.lock().unwrap();
            if self.read_closed.load(Ordering::Acquire) {
                false
            } else {
                if let Some(err) = err {
                    terminal.read = Some(err);
                }
                self.read_closed.store(true, Ordering::Release);
                true
            }
        };
        if first {
            self.maybe_finish_active();
        }
    }

    fn mark_write_closed(&self) {
        self.mark_write_closed_with(None);
    }

    fn mark_write_closed_with(&self, err: Option<zmux::Error>) {
        if self.write_closed.load(Ordering::Acquire) {
            return;
        }
        let first = {
            let mut terminal = self.terminal.lock().unwrap();
            if self.write_closed.load(Ordering::Acquire) {
                false
            } else {
                if let Some(err) = err {
                    terminal.write = Some(err);
                }
                self.write_closed.store(true, Ordering::Release);
                true
            }
        };
        if first {
            self.maybe_finish_active();
        }
    }

    fn maybe_finish_active(&self) {
        if self.read_closed.load(Ordering::Acquire) && self.write_closed.load(Ordering::Acquire) {
            if let Some(active) = &self.active {
                active.finish();
            }
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn is_opened_locally(&self) -> bool {
        self.opened_locally
    }

    pub fn is_bidirectional(&self) -> bool {
        true
    }

    pub fn is_read_closed(&self) -> bool {
        self.read_closed.load(Ordering::Acquire)
    }

    pub fn is_write_closed(&self) -> bool {
        self.write_closed.load(Ordering::Acquire)
    }

    pub fn metadata(&self) -> StreamMetadata {
        self.prelude.lock().unwrap().metadata.clone()
    }

    pub fn open_info(&self) -> Vec<u8> {
        prelude_open_info(&self.prelude)
    }

    pub fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        append_prelude_open_info_to(&self.prelude, dst);
    }

    pub fn open_info_len(&self) -> usize {
        prelude_open_info_len(&self.prelude)
    }

    pub fn has_open_info(&self) -> bool {
        prelude_has_open_info(&self.prelude)
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    pub fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        *self.read_deadline.lock().unwrap() = deadline;
        Ok(())
    }

    pub fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        *self.write_deadline.lock().unwrap() = deadline;
        Ok(())
    }

    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.set_read_deadline(deadline)?;
        self.set_write_deadline(deadline)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_read_deadline(timeout_to_deadline(timeout))
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_write_deadline(timeout_to_deadline(timeout))
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }

    fn read_timeout_from_deadline(&self) -> Result<Option<Duration>> {
        timeout_until(*self.read_deadline.lock().unwrap(), "read")
    }

    fn write_timeout_from_deadline(&self) -> Result<Option<Duration>> {
        timeout_until(*self.write_deadline.lock().unwrap(), "write")
    }

    fn read_terminal_error(&self) -> zmux::Error {
        self.terminal
            .lock()
            .unwrap()
            .read
            .clone()
            .unwrap_or_else(local_read_closed_error)
    }

    fn write_terminal_error(&self) -> zmux::Error {
        self.terminal
            .lock()
            .unwrap()
            .write
            .clone()
            .unwrap_or_else(local_write_closed_error)
    }

    pub async fn update_metadata(&self, update: zmux::MetadataUpdate) -> Result<()> {
        let mut send = self.send.lock().await;
        let should_flush = {
            let mut state = self.prelude.lock().unwrap();
            match state.update_pre_open_metadata(update)? {
                true => true,
                false => return Err(priority_update_unavailable()),
            }
        };
        if should_flush {
            if let Err(err) = ensure_open_prelude(&self.prelude, &mut send, &self.stats).await {
                self.mark_write_closed_with(Some(err.clone()));
                return Err(err);
            }
        }
        Ok(())
    }

    pub async fn read(&self, dst: &mut [u8]) -> Result<usize> {
        let timeout = self.read_timeout_from_deadline()?;
        with_optional_timeout(self.read_inner(dst), timeout, "read").await
    }

    async fn read_inner(&self, dst: &mut [u8]) -> Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if self.read_closed.load(Ordering::Acquire) {
            return Err(self.read_terminal_error());
        }
        let mut recv = self.recv.lock().await;
        match recv.read(dst).await {
            Ok(Some(n)) => {
                self.stats.note_data_read(n, Instant::now());
                Ok(n)
            }
            Ok(None) => {
                self.mark_read_closed();
                Ok(0)
            }
            Err(err) => {
                if let quinn::ReadError::Reset(code) = &err {
                    self.stats.note_reset_reason((*code).into_inner());
                }
                let err = translate_read_error(err);
                self.mark_read_closed_with(Some(err.clone()));
                Err(err)
            }
        }
    }

    pub async fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        with_timeout(self.read(dst), timeout, "read").await
    }

    pub async fn read_exact(&self, dst: &mut [u8]) -> Result<()> {
        let timeout = self.read_timeout_from_deadline()?;
        with_optional_timeout(self.read_exact_inner(dst), timeout, "read").await
    }

    async fn read_exact_inner(&self, mut dst: &mut [u8]) -> Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        if self.read_closed.load(Ordering::Acquire) {
            return Err(self.read_terminal_error());
        }
        let mut recv = self.recv.lock().await;
        while !dst.is_empty() {
            match recv.read(dst).await {
                Ok(Some(n)) => {
                    if n == 0 {
                        return Err(unexpected_eof_error());
                    }
                    self.stats.note_data_read(n, Instant::now());
                    let (_, rest) = dst.split_at_mut(n);
                    dst = rest;
                }
                Ok(None) => {
                    self.mark_read_closed();
                    return Err(unexpected_eof_error());
                }
                Err(err) => {
                    if let quinn::ReadError::Reset(code) = &err {
                        self.stats.note_reset_reason((*code).into_inner());
                    }
                    let err = translate_read_error(err);
                    self.mark_read_closed_with(Some(err.clone()));
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    pub async fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        with_timeout(self.read_exact(dst), timeout, "read").await
    }

    pub async fn read_vectored(&self, dsts: &mut [IoSliceMut<'_>]) -> Result<usize> {
        match dsts.iter_mut().find(|dst| !dst.is_empty()) {
            Some(dst) => self.read(dst).await,
            None => Ok(0),
        }
    }

    pub async fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        with_timeout(self.read_vectored(dsts), timeout, "read").await
    }

    pub async fn write(&self, src: &[u8]) -> Result<usize> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_inner(src), timeout, "write").await
    }

    async fn write_inner(&self, src: &[u8]) -> Result<usize> {
        if src.is_empty() {
            return Ok(0);
        }
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        if let Err(err) = ensure_open_prelude(&self.prelude, &mut send, &self.stats).await {
            self.mark_write_closed_with(Some(err.clone()));
            return Err(err);
        }
        match write_payload_once(&mut send, src, &self.stats).await {
            Ok(n) => Ok(n),
            Err(err) => {
                self.mark_write_closed_with(Some(err.clone()));
                Err(err)
            }
        }
    }

    pub async fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        with_timeout(self.write(src), timeout, "write").await
    }

    pub async fn write_all<'a>(&self, src: impl Into<WritePayload<'a>>) -> Result<()> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_all_inner(src.into()), timeout, "write").await
    }

    pub async fn write_all_timeout<'a>(
        &self,
        src: impl Into<WritePayload<'a>>,
        timeout: Duration,
    ) -> Result<()> {
        with_timeout(self.write_all(src), timeout, "write").await
    }

    async fn write_all_inner(&self, payload: WritePayload<'_>) -> Result<()> {
        match payload {
            WritePayload::Bytes(data) => self.write_all_bytes_inner(data.as_ref()).await,
            WritePayload::Vectored(parts) => {
                for part in parts {
                    if !part.is_empty() {
                        self.write_all_bytes_inner(part.as_ref()).await?;
                    }
                }
                Ok(())
            }
        }
    }

    async fn write_all_bytes_inner(&self, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        let result = async {
            ensure_open_prelude(&self.prelude, &mut send, &self.stats).await?;
            write_payload_all(&mut send, src, &self.stats).await
        }
        .await;
        if result.is_err() {
            self.mark_write_closed_with(result.as_ref().err().cloned());
        }
        result
    }

    pub async fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_vectored_inner(parts), timeout, "write").await
    }

    async fn write_vectored_inner(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        let total = total_bytes(parts.iter().map(|part| part.len()))?;
        if total == 0 {
            return Ok(0);
        }
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        let result = async {
            ensure_open_prelude(&self.prelude, &mut send, &self.stats).await?;
            write_io_slices_once(&mut send, parts, total, &self.stats).await
        }
        .await;
        if let Err(err) = &result {
            self.mark_write_closed_with(Some(err.clone()));
        }
        result
    }

    pub async fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        with_timeout(self.write_vectored(parts), timeout, "write").await
    }

    pub async fn write_final<'a>(&self, src: impl Into<WritePayload<'a>>) -> Result<usize> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_final_inner(src.into()), timeout, "write").await
    }

    async fn write_final_inner(&self, payload: WritePayload<'_>) -> Result<usize> {
        match payload {
            WritePayload::Bytes(data) => self.write_final_bytes_inner(data.as_ref()).await,
            WritePayload::Vectored(parts) => self.write_vectored_final_inner(parts).await,
        }
    }

    async fn write_final_bytes_inner(&self, src: &[u8]) -> Result<usize> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        match write_all_final(&self.prelude, &mut send, src, &self.stats).await {
            Ok(n) => {
                self.mark_write_closed();
                Ok(n)
            }
            Err(err) => {
                self.mark_write_closed_with(Some(err.clone()));
                Err(err)
            }
        }
    }

    pub async fn write_final_timeout<'a>(
        &self,
        src: impl Into<WritePayload<'a>>,
        timeout: Duration,
    ) -> Result<usize> {
        with_timeout(self.write_final(src), timeout, "write").await
    }

    pub async fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_vectored_final_inner(parts), timeout, "write").await
    }

    async fn write_vectored_final_inner(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        match write_io_slices_final(&self.prelude, &mut send, parts, &self.stats).await {
            Ok(n) => {
                self.mark_write_closed();
                Ok(n)
            }
            Err(err) => {
                self.mark_write_closed_with(Some(err.clone()));
                Err(err)
            }
        }
    }

    pub async fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        with_timeout(self.write_vectored_final(parts), timeout, "write").await
    }

    pub async fn close_read(&self) -> Result<()> {
        self.cancel_read(zmux::ErrorCode::Cancelled.as_u64()).await
    }

    pub async fn cancel_read(&self, code: u64) -> Result<()> {
        if self.read_closed.load(Ordering::Acquire) {
            return Err(self.read_terminal_error());
        }
        let code =
            checked_quinn_varint(code, zmux::ErrorOperation::Read, zmux::ErrorDirection::Read)?;
        self.cancel_read_varint(code).await
    }

    async fn cancel_read_varint(&self, code: quinn::VarInt) -> Result<()> {
        let mut send = self.send.lock().await;
        if let Err(err) = ensure_open_prelude(&self.prelude, &mut send, &self.stats).await {
            self.mark_write_closed_with(Some(err.clone()));
            return Err(err);
        }
        drop(send);
        let mut recv = self.recv.lock().await;
        let result = recv.stop(code).map_err(translate_read_closed_stream);
        drop(recv);
        if result.is_ok() {
            self.stats.note_control_progress();
        }
        self.mark_read_closed();
        result
    }

    pub async fn close_write(&self) -> Result<()> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.close_write_inner(), timeout, "write").await
    }

    async fn close_write_inner(&self) -> Result<()> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        if let Err(err) = ensure_open_prelude(&self.prelude, &mut send, &self.stats).await {
            self.mark_write_closed_with(Some(err.clone()));
            return Err(err);
        }
        let result = finish_send(&mut send, &self.stats).await;
        drop(send);
        self.mark_write_closed_with(result.as_ref().err().cloned());
        result
    }

    pub async fn cancel_write(&self, code: u64) -> Result<()> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let code = checked_quinn_varint(
            code,
            zmux::ErrorOperation::Write,
            zmux::ErrorDirection::Write,
        )?;
        self.cancel_write_varint(code).await
    }

    async fn cancel_write_varint(&self, code: quinn::VarInt) -> Result<()> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        let result = send.reset(code).map_err(translate_write_closed_stream);
        drop(send);
        if result.is_ok() {
            self.stats.note_control_progress();
            self.stats.note_reset_reason(code.into_inner());
        }
        self.mark_write_closed_with(Some(local_stream_application_error(
            code.into_inner(),
            "",
            zmux::ErrorOperation::Write,
            zmux::ErrorDirection::Write,
            zmux::TerminationKind::Reset,
        )));
        result
    }

    pub async fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        if self.read_closed.load(Ordering::Acquire) && self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let code = checked_quinn_varint(
            code,
            zmux::ErrorOperation::Close,
            zmux::ErrorDirection::Both,
        )?;
        let terminal = local_stream_application_error(
            code.into_inner(),
            reason,
            zmux::ErrorOperation::Close,
            zmux::ErrorDirection::Both,
            zmux::TerminationKind::Abort,
        );
        {
            let mut recv = self.recv.lock().await;
            let _ = recv.stop(code);
        }
        {
            let mut send = self.send.lock().await;
            let _ = send.reset(code);
        }
        self.stats.note_control_progress();
        self.stats.note_abort_reason(code.into_inner());
        self.mark_read_closed_with(Some(terminal.clone()));
        self.mark_write_closed_with(Some(terminal));
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        let write = if self.write_closed.load(Ordering::Acquire) {
            Ok(())
        } else {
            self.close_write().await
        };
        let read = if self.read_closed.load(Ordering::Acquire) {
            Ok(())
        } else {
            self.close_read().await
        };
        write.and(read)
    }

    async fn maybe_send_open_prelude_on_open(&self) -> Result<()> {
        if !self
            .prelude
            .lock()
            .unwrap()
            .has_peer_visible_open_metadata()
        {
            return Ok(());
        }
        let mut send = self.send.lock().await;
        ensure_open_prelude(&self.prelude, &mut send, &self.stats).await
    }

    async fn discard_after_open_error(&self, err: &zmux::Error) {
        let code = open_error_cleanup_code(err);
        {
            let mut recv = self.recv.lock().await;
            let _ = recv.stop(code);
        }
        {
            let mut send = self.send.lock().await;
            let _ = send.reset(code);
        }
        self.mark_read_closed();
        self.mark_write_closed();
    }
}

pub struct QuinnSendStream {
    stream_id: u64,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    send: AsyncMutex<quinn::SendStream>,
    prelude: Mutex<PreludeState>,
    write_deadline: Mutex<Option<Instant>>,
    terminal: Mutex<TerminalErrors>,
    stats: Arc<AdapterStats>,
    active: Option<ActiveGuard>,
    write_closed: AtomicBool,
}

impl QuinnSendStream {
    fn local(
        send: quinn::SendStream,
        prelude: PreludeState,
        stats: Arc<AdapterStats>,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        let stream_id = quinn_stream_id(send.id());
        Self {
            stream_id,
            local_addr,
            peer_addr,
            send: AsyncMutex::new(send),
            prelude: Mutex::new(prelude),
            write_deadline: Mutex::new(None),
            terminal: Mutex::new(TerminalErrors::default()),
            stats,
            active: None,
            write_closed: AtomicBool::new(false),
        }
    }

    fn with_active(mut self, counters: Arc<ActiveCounters>, kind: ActiveKind) -> Self {
        self.active = Some(ActiveGuard::new(counters, kind));
        self
    }

    fn mark_write_closed(&self) {
        self.mark_write_closed_with(None);
    }

    fn mark_write_closed_with(&self, err: Option<zmux::Error>) {
        if self.write_closed.load(Ordering::Acquire) {
            return;
        }
        let first = {
            let mut terminal = self.terminal.lock().unwrap();
            if self.write_closed.load(Ordering::Acquire) {
                false
            } else {
                if let Some(err) = err {
                    terminal.write = Some(err);
                }
                self.write_closed.store(true, Ordering::Release);
                true
            }
        };
        if first {
            if let Some(active) = &self.active {
                active.finish();
            }
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn is_opened_locally(&self) -> bool {
        true
    }

    pub fn is_bidirectional(&self) -> bool {
        false
    }

    pub fn is_write_closed(&self) -> bool {
        self.write_closed.load(Ordering::Acquire)
    }

    pub fn metadata(&self) -> StreamMetadata {
        self.prelude.lock().unwrap().metadata.clone()
    }

    pub fn open_info(&self) -> Vec<u8> {
        prelude_open_info(&self.prelude)
    }

    pub fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        append_prelude_open_info_to(&self.prelude, dst);
    }

    pub fn open_info_len(&self) -> usize {
        prelude_open_info_len(&self.prelude)
    }

    pub fn has_open_info(&self) -> bool {
        prelude_has_open_info(&self.prelude)
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    pub fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        *self.write_deadline.lock().unwrap() = deadline;
        Ok(())
    }

    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.set_write_deadline(deadline)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_write_deadline(timeout_to_deadline(timeout))
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }

    fn write_timeout_from_deadline(&self) -> Result<Option<Duration>> {
        timeout_until(*self.write_deadline.lock().unwrap(), "write")
    }

    fn write_terminal_error(&self) -> zmux::Error {
        self.terminal
            .lock()
            .unwrap()
            .write
            .clone()
            .unwrap_or_else(local_write_closed_error)
    }

    pub async fn update_metadata(&self, update: zmux::MetadataUpdate) -> Result<()> {
        let mut send = self.send.lock().await;
        let should_flush = {
            let mut state = self.prelude.lock().unwrap();
            match state.update_pre_open_metadata(update)? {
                true => true,
                false => return Err(priority_update_unavailable()),
            }
        };
        if should_flush {
            if let Err(err) = ensure_open_prelude(&self.prelude, &mut send, &self.stats).await {
                self.mark_write_closed_with(Some(err.clone()));
                return Err(err);
            }
        }
        Ok(())
    }

    pub async fn write(&self, src: &[u8]) -> Result<usize> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_inner(src), timeout, "write").await
    }

    async fn write_inner(&self, src: &[u8]) -> Result<usize> {
        if src.is_empty() {
            return Ok(0);
        }
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        if let Err(err) = ensure_open_prelude(&self.prelude, &mut send, &self.stats).await {
            self.mark_write_closed_with(Some(err.clone()));
            return Err(err);
        }
        match write_payload_once(&mut send, src, &self.stats).await {
            Ok(n) => Ok(n),
            Err(err) => {
                self.mark_write_closed_with(Some(err.clone()));
                Err(err)
            }
        }
    }

    pub async fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        with_timeout(self.write(src), timeout, "write").await
    }

    pub async fn write_all<'a>(&self, src: impl Into<WritePayload<'a>>) -> Result<()> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_all_inner(src.into()), timeout, "write").await
    }

    pub async fn write_all_timeout<'a>(
        &self,
        src: impl Into<WritePayload<'a>>,
        timeout: Duration,
    ) -> Result<()> {
        with_timeout(self.write_all(src), timeout, "write").await
    }

    async fn write_all_inner(&self, payload: WritePayload<'_>) -> Result<()> {
        match payload {
            WritePayload::Bytes(data) => self.write_all_bytes_inner(data.as_ref()).await,
            WritePayload::Vectored(parts) => {
                for part in parts {
                    if !part.is_empty() {
                        self.write_all_bytes_inner(part.as_ref()).await?;
                    }
                }
                Ok(())
            }
        }
    }

    async fn write_all_bytes_inner(&self, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        let result = async {
            ensure_open_prelude(&self.prelude, &mut send, &self.stats).await?;
            write_payload_all(&mut send, src, &self.stats).await
        }
        .await;
        if result.is_err() {
            self.mark_write_closed_with(result.as_ref().err().cloned());
        }
        result
    }

    pub async fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_vectored_inner(parts), timeout, "write").await
    }

    async fn write_vectored_inner(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        let total = total_bytes(parts.iter().map(|part| part.len()))?;
        if total == 0 {
            return Ok(0);
        }
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        let result = async {
            ensure_open_prelude(&self.prelude, &mut send, &self.stats).await?;
            write_io_slices_once(&mut send, parts, total, &self.stats).await
        }
        .await;
        if let Err(err) = &result {
            self.mark_write_closed_with(Some(err.clone()));
        }
        result
    }

    pub async fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        with_timeout(self.write_vectored(parts), timeout, "write").await
    }

    pub async fn write_final<'a>(&self, src: impl Into<WritePayload<'a>>) -> Result<usize> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_final_inner(src.into()), timeout, "write").await
    }

    async fn write_final_inner(&self, payload: WritePayload<'_>) -> Result<usize> {
        match payload {
            WritePayload::Bytes(data) => self.write_final_bytes_inner(data.as_ref()).await,
            WritePayload::Vectored(parts) => self.write_vectored_final_inner(parts).await,
        }
    }

    async fn write_final_bytes_inner(&self, src: &[u8]) -> Result<usize> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        match write_all_final(&self.prelude, &mut send, src, &self.stats).await {
            Ok(n) => {
                self.mark_write_closed();
                Ok(n)
            }
            Err(err) => {
                self.mark_write_closed_with(Some(err.clone()));
                Err(err)
            }
        }
    }

    pub async fn write_final_timeout<'a>(
        &self,
        src: impl Into<WritePayload<'a>>,
        timeout: Duration,
    ) -> Result<usize> {
        with_timeout(self.write_final(src), timeout, "write").await
    }

    pub async fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.write_vectored_final_inner(parts), timeout, "write").await
    }

    async fn write_vectored_final_inner(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        match write_io_slices_final(&self.prelude, &mut send, parts, &self.stats).await {
            Ok(n) => {
                self.mark_write_closed();
                Ok(n)
            }
            Err(err) => {
                self.mark_write_closed_with(Some(err.clone()));
                Err(err)
            }
        }
    }

    pub async fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        with_timeout(self.write_vectored_final(parts), timeout, "write").await
    }

    pub async fn close_write(&self) -> Result<()> {
        let timeout = self.write_timeout_from_deadline()?;
        with_optional_timeout(self.close_write_inner(), timeout, "write").await
    }

    async fn close_write_inner(&self) -> Result<()> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        if let Err(err) = ensure_open_prelude(&self.prelude, &mut send, &self.stats).await {
            self.mark_write_closed_with(Some(err.clone()));
            return Err(err);
        }
        let result = finish_send(&mut send, &self.stats).await;
        drop(send);
        self.mark_write_closed_with(result.as_ref().err().cloned());
        result
    }

    pub async fn cancel_write(&self, code: u64) -> Result<()> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let code = checked_quinn_varint(
            code,
            zmux::ErrorOperation::Write,
            zmux::ErrorDirection::Write,
        )?;
        self.cancel_write_varint(code).await
    }

    async fn cancel_write_varint(&self, code: quinn::VarInt) -> Result<()> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let mut send = self.send.lock().await;
        let result = send.reset(code).map_err(translate_write_closed_stream);
        drop(send);
        if result.is_ok() {
            self.stats.note_control_progress();
            self.stats.note_reset_reason(code.into_inner());
        }
        self.mark_write_closed_with(Some(local_stream_application_error(
            code.into_inner(),
            "",
            zmux::ErrorOperation::Write,
            zmux::ErrorDirection::Write,
            zmux::TerminationKind::Reset,
        )));
        result
    }

    pub async fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        if self.write_closed.load(Ordering::Acquire) {
            return Err(self.write_terminal_error());
        }
        let code = checked_quinn_varint(
            code,
            zmux::ErrorOperation::Close,
            zmux::ErrorDirection::Write,
        )?;
        let terminal = local_stream_application_error(
            code.into_inner(),
            reason,
            zmux::ErrorOperation::Close,
            zmux::ErrorDirection::Write,
            zmux::TerminationKind::Abort,
        );
        let mut send = self.send.lock().await;
        let _ = send.reset(code);
        drop(send);
        self.stats.note_control_progress();
        self.stats.note_abort_reason(code.into_inner());
        self.mark_write_closed_with(Some(terminal));
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        if self.write_closed.load(Ordering::Acquire) {
            Ok(())
        } else {
            self.close_write().await
        }
    }

    async fn maybe_send_open_prelude_on_open(&self) -> Result<()> {
        if !self
            .prelude
            .lock()
            .unwrap()
            .has_peer_visible_open_metadata()
        {
            return Ok(());
        }
        let mut send = self.send.lock().await;
        ensure_open_prelude(&self.prelude, &mut send, &self.stats).await
    }

    async fn discard_after_open_error(&self, err: &zmux::Error) {
        let code = open_error_cleanup_code(err);
        let mut send = self.send.lock().await;
        let _ = send.reset(code);
        drop(send);
        self.mark_write_closed();
    }
}

pub struct QuinnRecvStream {
    stream_id: u64,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    recv: AsyncMutex<quinn::RecvStream>,
    prelude: Mutex<PreludeState>,
    read_deadline: Mutex<Option<Instant>>,
    terminal: Mutex<TerminalErrors>,
    stats: Arc<AdapterStats>,
    active: Option<ActiveGuard>,
    read_closed: AtomicBool,
}

impl QuinnRecvStream {
    fn accepted(
        recv: quinn::RecvStream,
        metadata: AcceptedStreamMetadata,
        stats: Arc<AdapterStats>,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        let stream_id = quinn_stream_id(recv.id());
        Self {
            stream_id,
            local_addr,
            peer_addr,
            recv: AsyncMutex::new(recv),
            prelude: Mutex::new(PreludeState::accepted(metadata)),
            read_deadline: Mutex::new(None),
            terminal: Mutex::new(TerminalErrors::default()),
            stats,
            active: None,
            read_closed: AtomicBool::new(false),
        }
    }

    fn with_active(mut self, counters: Arc<ActiveCounters>, kind: ActiveKind) -> Self {
        self.active = Some(ActiveGuard::new(counters, kind));
        self
    }

    fn mark_read_closed(&self) {
        self.mark_read_closed_with(None);
    }

    fn mark_read_closed_with(&self, err: Option<zmux::Error>) {
        if self.read_closed.load(Ordering::Acquire) {
            return;
        }
        let first = {
            let mut terminal = self.terminal.lock().unwrap();
            if self.read_closed.load(Ordering::Acquire) {
                false
            } else {
                if let Some(err) = err {
                    terminal.read = Some(err);
                }
                self.read_closed.store(true, Ordering::Release);
                true
            }
        };
        if first {
            if let Some(active) = &self.active {
                active.finish();
            }
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn is_opened_locally(&self) -> bool {
        false
    }

    pub fn is_bidirectional(&self) -> bool {
        false
    }

    pub fn is_read_closed(&self) -> bool {
        self.read_closed.load(Ordering::Acquire)
    }

    pub fn metadata(&self) -> StreamMetadata {
        self.prelude.lock().unwrap().metadata.clone()
    }

    pub fn open_info(&self) -> Vec<u8> {
        prelude_open_info(&self.prelude)
    }

    pub fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        append_prelude_open_info_to(&self.prelude, dst);
    }

    pub fn open_info_len(&self) -> usize {
        prelude_open_info_len(&self.prelude)
    }

    pub fn has_open_info(&self) -> bool {
        prelude_has_open_info(&self.prelude)
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    pub fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        *self.read_deadline.lock().unwrap() = deadline;
        Ok(())
    }

    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.set_read_deadline(deadline)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_read_deadline(timeout_to_deadline(timeout))
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }

    fn read_timeout_from_deadline(&self) -> Result<Option<Duration>> {
        timeout_until(*self.read_deadline.lock().unwrap(), "read")
    }

    fn read_terminal_error(&self) -> zmux::Error {
        self.terminal
            .lock()
            .unwrap()
            .read
            .clone()
            .unwrap_or_else(local_read_closed_error)
    }

    pub async fn read(&self, dst: &mut [u8]) -> Result<usize> {
        let timeout = self.read_timeout_from_deadline()?;
        with_optional_timeout(self.read_inner(dst), timeout, "read").await
    }

    async fn read_inner(&self, dst: &mut [u8]) -> Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if self.read_closed.load(Ordering::Acquire) {
            return Err(self.read_terminal_error());
        }
        let mut recv = self.recv.lock().await;
        match recv.read(dst).await {
            Ok(Some(n)) => {
                self.stats.note_data_read(n, Instant::now());
                Ok(n)
            }
            Ok(None) => {
                self.mark_read_closed();
                Ok(0)
            }
            Err(err) => {
                if let quinn::ReadError::Reset(code) = &err {
                    self.stats.note_reset_reason((*code).into_inner());
                }
                let err = translate_read_error(err);
                self.mark_read_closed_with(Some(err.clone()));
                Err(err)
            }
        }
    }

    pub async fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        with_timeout(self.read(dst), timeout, "read").await
    }

    pub async fn read_exact(&self, dst: &mut [u8]) -> Result<()> {
        let timeout = self.read_timeout_from_deadline()?;
        with_optional_timeout(self.read_exact_inner(dst), timeout, "read").await
    }

    async fn read_exact_inner(&self, mut dst: &mut [u8]) -> Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        if self.read_closed.load(Ordering::Acquire) {
            return Err(self.read_terminal_error());
        }
        let mut recv = self.recv.lock().await;
        while !dst.is_empty() {
            match recv.read(dst).await {
                Ok(Some(n)) => {
                    if n == 0 {
                        return Err(unexpected_eof_error());
                    }
                    self.stats.note_data_read(n, Instant::now());
                    let (_, rest) = dst.split_at_mut(n);
                    dst = rest;
                }
                Ok(None) => {
                    self.mark_read_closed();
                    return Err(unexpected_eof_error());
                }
                Err(err) => {
                    if let quinn::ReadError::Reset(code) = &err {
                        self.stats.note_reset_reason((*code).into_inner());
                    }
                    let err = translate_read_error(err);
                    self.mark_read_closed_with(Some(err.clone()));
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    pub async fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        with_timeout(self.read_exact(dst), timeout, "read").await
    }

    pub async fn read_vectored(&self, dsts: &mut [IoSliceMut<'_>]) -> Result<usize> {
        match dsts.iter_mut().find(|dst| !dst.is_empty()) {
            Some(dst) => self.read(dst).await,
            None => Ok(0),
        }
    }

    pub async fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        with_timeout(self.read_vectored(dsts), timeout, "read").await
    }

    pub async fn close_read(&self) -> Result<()> {
        self.cancel_read(zmux::ErrorCode::Cancelled.as_u64()).await
    }

    pub async fn cancel_read(&self, code: u64) -> Result<()> {
        if self.read_closed.load(Ordering::Acquire) {
            return Err(self.read_terminal_error());
        }
        let code =
            checked_quinn_varint(code, zmux::ErrorOperation::Read, zmux::ErrorDirection::Read)?;
        self.cancel_read_varint(code).await
    }

    async fn cancel_read_varint(&self, code: quinn::VarInt) -> Result<()> {
        let mut recv = self.recv.lock().await;
        let result = recv.stop(code).map_err(translate_read_closed_stream);
        drop(recv);
        if result.is_ok() {
            self.stats.note_control_progress();
        }
        self.mark_read_closed();
        result
    }

    pub async fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        if self.read_closed.load(Ordering::Acquire) {
            return Err(self.read_terminal_error());
        }
        let code = checked_quinn_varint(
            code,
            zmux::ErrorOperation::Close,
            zmux::ErrorDirection::Read,
        )?;
        let terminal = local_stream_application_error(
            code.into_inner(),
            reason,
            zmux::ErrorOperation::Close,
            zmux::ErrorDirection::Read,
            zmux::TerminationKind::Abort,
        );
        let mut recv = self.recv.lock().await;
        let _ = recv.stop(code);
        drop(recv);
        self.stats.note_control_progress();
        self.stats.note_abort_reason(code.into_inner());
        self.mark_read_closed_with(Some(terminal));
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        if self.read_closed.load(Ordering::Acquire) {
            Ok(())
        } else {
            self.close_read().await
        }
    }
}

impl AsyncStreamHandle for QuinnStream {
    fn stream_id(&self) -> u64 {
        QuinnStream::stream_id(self)
    }

    fn is_opened_locally(&self) -> bool {
        QuinnStream::is_opened_locally(self)
    }

    fn is_bidirectional(&self) -> bool {
        QuinnStream::is_bidirectional(self)
    }

    fn open_info_len(&self) -> usize {
        QuinnStream::open_info_len(self)
    }

    fn has_open_info(&self) -> bool {
        QuinnStream::has_open_info(self)
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        QuinnStream::append_open_info_to(self, dst)
    }

    fn open_info(&self) -> Vec<u8> {
        QuinnStream::open_info(self)
    }

    fn metadata(&self) -> StreamMetadata {
        QuinnStream::metadata(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        QuinnStream::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        QuinnStream::peer_addr(self)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        QuinnStream::set_deadline(self, deadline)
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnStream::close(self).await })
    }

    fn close_with_error<'a>(
        &'a self,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnStream::close_with_error(self, code, reason).await })
    }
}

impl AsyncRecvStreamHandle for QuinnStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::read(self, dst).await })
    }

    fn read_vectored<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::read_vectored(self, dsts).await })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::read_timeout(self, dst, timeout).await })
    }

    fn read_vectored_timeout<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::read_vectored_timeout(self, dsts, timeout).await })
    }

    fn read_exact<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnStream::read_exact(self, dst).await })
    }

    fn read_exact_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnStream::read_exact_timeout(self, dst, timeout).await })
    }

    fn is_read_closed(&self) -> bool {
        QuinnStream::is_read_closed(self)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        QuinnStream::set_read_deadline(self, deadline)
    }

    fn close_read(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnStream::close_read(self).await })
    }

    fn cancel_read(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnStream::cancel_read(self, code).await })
    }
}

impl AsyncSendStreamHandle for QuinnStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::write(self, src).await })
    }

    fn write_all<'a>(&'a self, src: WritePayload<'a>) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnStream::write_all(self, src).await })
    }

    fn write_all_timeout<'a>(
        &'a self,
        src: WritePayload<'a>,
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnStream::write_all_timeout(self, src, timeout).await })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::write_timeout(self, src, timeout).await })
    }

    fn write_vectored<'a>(&'a self, parts: &'a [IoSlice<'_>]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::write_vectored(self, parts).await })
    }

    fn write_vectored_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::write_vectored_timeout(self, parts, timeout).await })
    }

    fn write_final<'a>(&'a self, src: WritePayload<'a>) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::write_final(self, src).await })
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: WritePayload<'a>,
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::write_final_timeout(self, src, timeout).await })
    }

    fn write_vectored_final<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnStream::write_vectored_final(self, parts).await })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(
            async move { QuinnStream::write_vectored_final_timeout(self, parts, timeout).await },
        )
    }

    fn is_write_closed(&self) -> bool {
        QuinnStream::is_write_closed(self)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        QuinnStream::set_write_deadline(self, deadline)
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnStream::update_metadata(self, update).await })
    }

    fn close_write(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnStream::close_write(self).await })
    }

    fn cancel_write(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnStream::cancel_write(self, code).await })
    }
}

impl AsyncDuplexStreamHandle for QuinnStream {}

impl AsyncStreamHandle for QuinnSendStream {
    fn stream_id(&self) -> u64 {
        QuinnSendStream::stream_id(self)
    }

    fn is_opened_locally(&self) -> bool {
        QuinnSendStream::is_opened_locally(self)
    }

    fn is_bidirectional(&self) -> bool {
        QuinnSendStream::is_bidirectional(self)
    }

    fn open_info_len(&self) -> usize {
        QuinnSendStream::open_info_len(self)
    }

    fn has_open_info(&self) -> bool {
        QuinnSendStream::has_open_info(self)
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        QuinnSendStream::append_open_info_to(self, dst)
    }

    fn open_info(&self) -> Vec<u8> {
        QuinnSendStream::open_info(self)
    }

    fn metadata(&self) -> StreamMetadata {
        QuinnSendStream::metadata(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        QuinnSendStream::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        QuinnSendStream::peer_addr(self)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        QuinnSendStream::set_deadline(self, deadline)
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnSendStream::close(self).await })
    }

    fn close_with_error<'a>(
        &'a self,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnSendStream::close_with_error(self, code, reason).await })
    }
}

impl AsyncSendStreamHandle for QuinnSendStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnSendStream::write(self, src).await })
    }

    fn write_all<'a>(&'a self, src: WritePayload<'a>) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnSendStream::write_all(self, src).await })
    }

    fn write_all_timeout<'a>(
        &'a self,
        src: WritePayload<'a>,
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnSendStream::write_all_timeout(self, src, timeout).await })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnSendStream::write_timeout(self, src, timeout).await })
    }

    fn write_vectored<'a>(&'a self, parts: &'a [IoSlice<'_>]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnSendStream::write_vectored(self, parts).await })
    }

    fn write_vectored_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnSendStream::write_vectored_timeout(self, parts, timeout).await })
    }

    fn write_final<'a>(&'a self, src: WritePayload<'a>) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnSendStream::write_final(self, src).await })
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: WritePayload<'a>,
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnSendStream::write_final_timeout(self, src, timeout).await })
    }

    fn write_vectored_final<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnSendStream::write_vectored_final(self, parts).await })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            QuinnSendStream::write_vectored_final_timeout(self, parts, timeout).await
        })
    }

    fn is_write_closed(&self) -> bool {
        QuinnSendStream::is_write_closed(self)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        QuinnSendStream::set_write_deadline(self, deadline)
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnSendStream::update_metadata(self, update).await })
    }

    fn close_write(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnSendStream::close_write(self).await })
    }

    fn cancel_write(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnSendStream::cancel_write(self, code).await })
    }
}

impl AsyncStreamHandle for QuinnRecvStream {
    fn stream_id(&self) -> u64 {
        QuinnRecvStream::stream_id(self)
    }

    fn is_opened_locally(&self) -> bool {
        QuinnRecvStream::is_opened_locally(self)
    }

    fn is_bidirectional(&self) -> bool {
        QuinnRecvStream::is_bidirectional(self)
    }

    fn open_info_len(&self) -> usize {
        QuinnRecvStream::open_info_len(self)
    }

    fn has_open_info(&self) -> bool {
        QuinnRecvStream::has_open_info(self)
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        QuinnRecvStream::append_open_info_to(self, dst)
    }

    fn open_info(&self) -> Vec<u8> {
        QuinnRecvStream::open_info(self)
    }

    fn metadata(&self) -> StreamMetadata {
        QuinnRecvStream::metadata(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        QuinnRecvStream::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        QuinnRecvStream::peer_addr(self)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        QuinnRecvStream::set_deadline(self, deadline)
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnRecvStream::close(self).await })
    }

    fn close_with_error<'a>(
        &'a self,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnRecvStream::close_with_error(self, code, reason).await })
    }
}

impl AsyncRecvStreamHandle for QuinnRecvStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnRecvStream::read(self, dst).await })
    }

    fn read_vectored<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnRecvStream::read_vectored(self, dsts).await })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnRecvStream::read_timeout(self, dst, timeout).await })
    }

    fn read_vectored_timeout<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { QuinnRecvStream::read_vectored_timeout(self, dsts, timeout).await })
    }

    fn read_exact<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnRecvStream::read_exact(self, dst).await })
    }

    fn read_exact_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnRecvStream::read_exact_timeout(self, dst, timeout).await })
    }

    fn is_read_closed(&self) -> bool {
        QuinnRecvStream::is_read_closed(self)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        QuinnRecvStream::set_read_deadline(self, deadline)
    }

    fn close_read(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnRecvStream::close_read(self).await })
    }

    fn cancel_read(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnRecvStream::cancel_read(self, code).await })
    }
}

impl AsyncSession for QuinnSession {
    type Stream = QuinnStream;
    type SendStream = QuinnSendStream;
    type RecvStream = QuinnRecvStream;

    fn accept_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { QuinnSession::accept_stream(self).await })
    }

    fn accept_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { QuinnSession::accept_stream_timeout(self, timeout).await })
    }

    fn accept_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
        Box::pin(async move { QuinnSession::accept_uni_stream(self).await })
    }

    fn accept_uni_stream_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
        Box::pin(async move { QuinnSession::accept_uni_stream_timeout(self, timeout).await })
    }

    fn open_stream_with(&self, request: OpenRequest) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { QuinnSession::open_stream_with(self, request).await })
    }

    fn open_uni_stream_with(
        &self,
        request: OpenRequest,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move { QuinnSession::open_uni_stream_with(self, request).await })
    }

    fn open_and_send<'a>(
        &'a self,
        request: OpenSend<'a>,
    ) -> AsyncBoxFuture<'a, Result<Self::Stream>> {
        Box::pin(async move { QuinnSession::open_and_send(self, request).await })
    }

    fn open_uni_and_send<'a>(
        &'a self,
        request: OpenSend<'a>,
    ) -> AsyncBoxFuture<'a, Result<Self::SendStream>> {
        Box::pin(async move { QuinnSession::open_uni_and_send(self, request).await })
    }

    fn ping<'a>(&'a self, _echo: &'a [u8]) -> AsyncBoxFuture<'a, Result<Duration>> {
        Box::pin(async move {
            Err(adapter_session_control_unavailable(
                zmux::ErrorOperation::Ping,
                "zmux: feature not supported by adapter: ping",
            ))
        })
    }

    fn ping_timeout<'a>(
        &'a self,
        _echo: &'a [u8],
        _timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<Duration>> {
        Box::pin(async move {
            Err(adapter_session_control_unavailable(
                zmux::ErrorOperation::Ping,
                "zmux: feature not supported by adapter: ping_timeout",
            ))
        })
    }

    fn go_away(
        &self,
        _last_accepted_bidi: u64,
        _last_accepted_uni: u64,
    ) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            Err(adapter_session_control_unavailable(
                zmux::ErrorOperation::Close,
                "zmux: feature not supported by adapter: go_away",
            ))
        })
    }

    fn go_away_with_error<'a>(
        &'a self,
        _last_accepted_bidi: u64,
        _last_accepted_uni: u64,
        _code: u64,
        _reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            Err(adapter_session_control_unavailable(
                zmux::ErrorOperation::Close,
                "zmux: feature not supported by adapter: go_away_with_error",
            ))
        })
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnSession::close(self).await })
    }

    fn close_with_error<'a>(
        &'a self,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { QuinnSession::close_with_error(self, code, reason).await })
    }

    fn wait(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { QuinnSession::wait(self).await })
    }

    fn wait_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<bool>> {
        Box::pin(async move { QuinnSession::wait_timeout(self, timeout).await })
    }

    fn is_closed(&self) -> bool {
        QuinnSession::is_closed(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        QuinnSession::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        QuinnSession::peer_addr(self)
    }

    fn close_error(&self) -> Option<zmux::Error> {
        QuinnSession::close_error(self)
    }

    fn state(&self) -> zmux::SessionState {
        QuinnSession::state(self)
    }

    fn stats(&self) -> zmux::SessionStats {
        QuinnSession::stats(self)
    }

    fn peer_go_away_error(&self) -> Option<zmux::PeerGoAwayError> {
        None
    }

    fn peer_close_error(&self) -> Option<zmux::PeerCloseError> {
        None
    }

    fn local_preface(&self) -> zmux::Preface {
        adapter_empty_preface()
    }

    fn peer_preface(&self) -> zmux::Preface {
        adapter_empty_preface()
    }

    fn negotiated(&self) -> zmux::Negotiated {
        adapter_empty_negotiated()
    }
}

async fn ensure_open_prelude(
    state: &Mutex<PreludeState>,
    send: &mut quinn::SendStream,
    stats: &AdapterStats,
) -> Result<()> {
    loop {
        let chunk = {
            let state = state.lock().unwrap();
            if !state.send_prelude || state.prelude_sent {
                return Ok(());
            }
            state.prelude.slice(state.prelude_offset..)
        };
        if chunk.is_empty() {
            let mut state = state.lock().unwrap();
            state.prelude_sent = true;
            state.prelude = Bytes::new();
            drop(state);
            return Ok(());
        }
        let started_at = Instant::now();
        let n = send.write(&chunk).await.map_err(translate_write_error)?;
        let completed_at = Instant::now();
        if n == 0 {
            return Err(zmux::Error::local("zmux-quinn: zero-length prelude write"));
        }
        if n > chunk.len() {
            return Err(zmux::Error::local(
                "zmux-quinn: prelude write reported invalid progress",
            ));
        }
        stats.note_write_wait(started_at, completed_at);
        stats.note_flush(n, completed_at);
        stats.note_control_progress_at(completed_at);
        let mut state = state.lock().unwrap();
        state.prelude_offset = state.prelude_offset.saturating_add(n);
        if state.prelude_offset >= state.prelude.len() {
            state.prelude_sent = true;
            state.prelude = Bytes::new();
            state.prelude_offset = 0;
            drop(state);
            return Ok(());
        }
    }
}

async fn write_all_final(
    state: &Mutex<PreludeState>,
    send: &mut quinn::SendStream,
    src: &[u8],
    stats: &AdapterStats,
) -> Result<usize> {
    ensure_open_prelude(state, send, stats).await?;
    if !src.is_empty() {
        write_payload_all(send, src, stats).await?;
    }
    finish_send(send, stats).await?;
    Ok(src.len())
}

async fn write_io_slices_final(
    state: &Mutex<PreludeState>,
    send: &mut quinn::SendStream,
    parts: &[IoSlice<'_>],
    stats: &AdapterStats,
) -> Result<usize> {
    let total = total_bytes(parts.iter().map(|part| part.len()))?;
    ensure_open_prelude(state, send, stats).await?;
    if total == 0 {
        finish_send(send, stats).await?;
        return Ok(0);
    }
    if let Some(single) = single_non_empty_io_slice(parts) {
        write_payload_all(send, single, stats).await?;
        finish_send(send, stats).await?;
        return Ok(total);
    }
    if total <= QUINN_WRITE_VECTORED_COALESCE_MAX_BYTES {
        let mut coalesced = Vec::with_capacity(total);
        for part in parts {
            coalesced.extend_from_slice(part.as_ref());
        }
        write_payload_all(send, &coalesced, stats).await?;
    } else {
        for part in parts {
            if !part.is_empty() {
                write_payload_all(send, part.as_ref(), stats).await?;
            }
        }
    }
    finish_send(send, stats).await?;
    Ok(total)
}

async fn write_io_slices_once(
    send: &mut quinn::SendStream,
    parts: &[IoSlice<'_>],
    total: usize,
    stats: &AdapterStats,
) -> Result<usize> {
    if total == 0 {
        return Ok(0);
    }
    if let Some(single) = single_non_empty_io_slice(parts) {
        return write_payload_once(send, single, stats).await;
    }

    let prefix_len = total.min(QUINN_WRITE_VECTORED_COALESCE_MAX_BYTES);
    let mut coalesced = Vec::with_capacity(prefix_len);
    for part in parts {
        if coalesced.len() == prefix_len {
            break;
        }
        let remaining = prefix_len - coalesced.len();
        let bytes = part.as_ref();
        let take = bytes.len().min(remaining);
        coalesced.extend_from_slice(&bytes[..take]);
    }
    write_payload_once(send, &coalesced, stats).await
}

fn single_non_empty_io_slice<'a>(parts: &'a [IoSlice<'_>]) -> Option<&'a [u8]> {
    let mut single = None;
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if single.is_some() {
            return None;
        }
        single = Some(part.as_ref());
    }
    single
}

async fn write_payload_once(
    send: &mut quinn::SendStream,
    src: &[u8],
    stats: &AdapterStats,
) -> Result<usize> {
    let started_at = Instant::now();
    let n = send.write(src).await.map_err(translate_write_error)?;
    let completed_at = Instant::now();
    if n == 0 {
        return Err(zmux::Error::local("zmux-quinn: zero-length stream write"));
    }
    if n > src.len() {
        return Err(
            zmux::Error::local("zmux-quinn: stream write reported invalid progress")
                .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write),
        );
    }
    stats.note_write_wait(started_at, completed_at);
    stats.note_flush(n, completed_at);
    stats.note_data_write(n, completed_at);
    Ok(n)
}

async fn write_payload_all(
    send: &mut quinn::SendStream,
    src: &[u8],
    stats: &AdapterStats,
) -> Result<()> {
    let started_at = Instant::now();
    send.write_all(src).await.map_err(translate_write_error)?;
    let completed_at = Instant::now();
    stats.note_write_wait(started_at, completed_at);
    stats.note_flush(src.len(), completed_at);
    stats.note_data_write(src.len(), completed_at);
    Ok(())
}

async fn finish_send(send: &mut quinn::SendStream, stats: &AdapterStats) -> Result<()> {
    send.finish().map_err(translate_write_closed_stream)?;
    stats.note_control_progress();
    Ok(())
}

fn total_bytes(lengths: impl IntoIterator<Item = usize>) -> Result<usize> {
    lengths.into_iter().try_fold(0usize, |total, len| {
        total.checked_add(len).ok_or_else(|| {
            zmux::Error::local("zmux-quinn: vectored payload length exceeds usize")
                .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write)
        })
    })
}

fn validate_progress(n: usize, requested: usize) -> Result<()> {
    if n > requested {
        Err(
            zmux::Error::local("zmux-quinn: write reported invalid progress")
                .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write),
        )
    } else {
        Ok(())
    }
}

fn checked_prelude_metadata_len(metadata_len: u64, prefix_len: usize) -> Result<usize> {
    let prefix_len = u64::try_from(prefix_len)
        .map_err(|_| protocol_prelude_error("stream prelude prefix length exceeds u64"))?;
    if metadata_len
        .checked_add(prefix_len)
        .is_none_or(|len| len > STREAM_PRELUDE_MAX_PAYLOAD)
    {
        return Err(protocol_prelude_error(
            "stream prelude exceeds adapter payload cap",
        ));
    }
    usize::try_from(metadata_len)
        .map_err(|_| protocol_prelude_error("stream prelude length exceeds usize"))
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn duration_nanos_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX - 1)
}

fn note_reason(counts: &mut HashMap<u64, u64>, overflow: &mut u64, code: u64) {
    if let Some(count) = counts.get_mut(&code) {
        *count = count.saturating_add(1);
    } else if counts.len() < MAX_REASON_STATS_CODES {
        counts.insert(code, 1);
    } else {
        *overflow = overflow.saturating_add(1);
    }
}

fn saturating_add_atomic_u64(counter: &AtomicU64, delta: u64) {
    if delta == 0 {
        return;
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(delta);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn saturating_increment_atomic_usize(counter: &AtomicUsize) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current == usize::MAX {
            return;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn quinn_stream_id(id: quinn::StreamId) -> u64 {
    quinn::VarInt::from(id).into_inner()
}

fn quinn_varint(value: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(value).unwrap_or(quinn::VarInt::MAX)
}

fn open_error_cleanup_code(err: &zmux::Error) -> quinn::VarInt {
    quinn_varint(
        err.numeric_code()
            .unwrap_or(zmux::ErrorCode::Cancelled.as_u64()),
    )
}

fn checked_quinn_varint(
    value: u64,
    operation: zmux::ErrorOperation,
    direction: zmux::ErrorDirection,
) -> Result<quinn::VarInt> {
    quinn::VarInt::from_u64(value).map_err(|_| {
        zmux::Error::local("zmux-quinn: QUIC application error code exceeds varint62")
            .with_stream_context(operation, direction)
    })
}

fn checked_session_quinn_varint(
    value: u64,
    operation: zmux::ErrorOperation,
) -> Result<quinn::VarInt> {
    quinn::VarInt::from_u64(value).map_err(|_| {
        zmux::Error::local("zmux-quinn: QUIC application error code exceeds varint62")
            .with_session_context(operation)
    })
}

fn protocol_prelude_error(reason: &str) -> zmux::Error {
    zmux::Error::application(
        zmux::ErrorCode::Protocol.as_u64(),
        format!("zmux-quinn: {reason}"),
    )
    .with_source(zmux::ErrorSource::Remote)
    .with_stream_context(zmux::ErrorOperation::Accept, zmux::ErrorDirection::Both)
    .with_termination_kind(zmux::TerminationKind::Abort)
}

fn local_stream_application_error(
    code: u64,
    reason: &str,
    operation: zmux::ErrorOperation,
    direction: zmux::ErrorDirection,
    termination_kind: zmux::TerminationKind,
) -> zmux::Error {
    zmux::Error::application(code, reason)
        .with_source(zmux::ErrorSource::Local)
        .with_stream_context(operation, direction)
        .with_termination_kind(termination_kind)
}

fn priority_update_unavailable() -> zmux::Error {
    zmux::Error::local(
        "zmux: feature not supported by adapter: metadata update requires negotiated priority_update",
    )
        .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write)
}

fn adapter_session_control_unavailable(
    operation: zmux::ErrorOperation,
    message: &'static str,
) -> zmux::Error {
    zmux::Error::local(message).with_session_context(operation)
}

fn adapter_empty_preface() -> zmux::Preface {
    zmux::Preface {
        preface_version: 0,
        role: zmux::Role::Initiator,
        tie_breaker_nonce: 0,
        min_proto: 0,
        max_proto: 0,
        capabilities: 0,
        settings: zmux::default_settings(),
    }
}

fn adapter_empty_negotiated() -> zmux::Negotiated {
    zmux::Negotiated {
        proto: 0,
        capabilities: 0,
        local_role: zmux::Role::Initiator,
        peer_role: zmux::Role::Initiator,
        peer_settings: zmux::default_settings(),
    }
}

fn local_read_closed_error() -> zmux::Error {
    zmux::Error::read_closed()
        .with_source(zmux::ErrorSource::Local)
        .with_stream_context(zmux::ErrorOperation::Read, zmux::ErrorDirection::Read)
}

fn unexpected_eof_error() -> zmux::Error {
    zmux::Error::io(std::io::Error::new(
        ErrorKind::UnexpectedEof,
        "failed to fill whole buffer",
    ))
    .with_stream_context(zmux::ErrorOperation::Read, zmux::ErrorDirection::Read)
}

fn local_write_closed_error() -> zmux::Error {
    zmux::Error::write_closed()
        .with_source(zmux::ErrorSource::Local)
        .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write)
}

fn translate_read_closed_stream(_: quinn::ClosedStream) -> zmux::Error {
    zmux::Error::read_closed()
        .with_source(zmux::ErrorSource::Local)
        .with_stream_context(zmux::ErrorOperation::Close, zmux::ErrorDirection::Read)
}

fn translate_write_closed_stream(_: quinn::ClosedStream) -> zmux::Error {
    zmux::Error::write_closed()
        .with_source(zmux::ErrorSource::Local)
        .with_stream_context(zmux::ErrorOperation::Close, zmux::ErrorDirection::Write)
}

fn translate_read_error(err: quinn::ReadError) -> zmux::Error {
    match err {
        quinn::ReadError::Reset(code) => zmux::Error::application(code.into_inner(), "")
            .with_source(zmux::ErrorSource::Remote)
            .with_stream_context(zmux::ErrorOperation::Read, zmux::ErrorDirection::Read)
            .with_termination_kind(zmux::TerminationKind::Reset),
        quinn::ReadError::ConnectionLost(err) => translate_connection_error(err),
        quinn::ReadError::ClosedStream => zmux::Error::read_closed()
            .with_stream_context(zmux::ErrorOperation::Read, zmux::ErrorDirection::Read),
        quinn::ReadError::IllegalOrderedRead => {
            zmux::Error::local("zmux-quinn: illegal ordered read")
                .with_stream_context(zmux::ErrorOperation::Read, zmux::ErrorDirection::Read)
        }
        quinn::ReadError::ZeroRttRejected => zmux::Error::local("zmux-quinn: 0-RTT rejected")
            .with_stream_context(zmux::ErrorOperation::Read, zmux::ErrorDirection::Read),
    }
}

fn translate_write_error(err: quinn::WriteError) -> zmux::Error {
    match err {
        quinn::WriteError::Stopped(code) => zmux::Error::application(code.into_inner(), "")
            .with_source(zmux::ErrorSource::Remote)
            .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write)
            .with_termination_kind(zmux::TerminationKind::Stopped),
        quinn::WriteError::ConnectionLost(err) => translate_connection_error(err),
        quinn::WriteError::ClosedStream => zmux::Error::write_closed()
            .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write),
        quinn::WriteError::ZeroRttRejected => zmux::Error::local("zmux-quinn: 0-RTT rejected")
            .with_stream_context(zmux::ErrorOperation::Write, zmux::ErrorDirection::Write),
    }
}

fn translate_connection_error(err: quinn::ConnectionError) -> zmux::Error {
    match err {
        quinn::ConnectionError::ApplicationClosed(close) => {
            let reason = String::from_utf8_lossy(&close.reason).into_owned();
            zmux::Error::application(close.error_code.into_inner(), reason)
                .with_source(zmux::ErrorSource::Remote)
                .with_session_context(zmux::ErrorOperation::Close)
                .with_termination_kind(zmux::TerminationKind::SessionTermination)
        }
        quinn::ConnectionError::LocallyClosed => zmux::Error::session_closed()
            .with_source(zmux::ErrorSource::Local)
            .with_session_context(zmux::ErrorOperation::Close),
        quinn::ConnectionError::TimedOut => zmux::Error::new(
            zmux::ErrorCode::IdleTimeout,
            "zmux-quinn: QUIC connection idle timeout",
        )
        .with_source(zmux::ErrorSource::Transport)
        .with_session_context(zmux::ErrorOperation::Close)
        .with_termination_kind(zmux::TerminationKind::Timeout),
        other => zmux::Error::local(format!("zmux-quinn: {other}"))
            .with_source(zmux::ErrorSource::Transport)
            .with_session_context(zmux::ErrorOperation::Close),
    }
}

fn translate_wait_error(err: quinn::ConnectionError) -> Result<()> {
    match err {
        quinn::ConnectionError::LocallyClosed => Ok(()),
        quinn::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == 0 && close.reason.is_empty() =>
        {
            Ok(())
        }
        other => Err(translate_connection_error(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_publishes_stream_adapter_claim_only() {
        assert_eq!(target_claims(), &[zmux::Claim::StreamAdapterProfileV1]);
        assert!(target_implementation_profiles().is_empty());
        assert_eq!(
            target_suites(),
            &[zmux::ConformanceSuite::StreamAdapterProfile]
        );
    }

    #[test]
    fn prelude_round_trip_open_info_and_priority() {
        let opts = OpenOptions::new()
            .priority(7)
            .group(11)
            .open_info(&[1, 2, 3, 4]);
        let prelude = build_stream_prelude(&opts).unwrap();
        let parsed = read_stream_prelude(&mut prelude.as_slice()).unwrap();
        assert!(parsed.metadata_valid);
        assert!(parsed.is_metadata_valid());
        assert!(parsed.has_open_info());
        assert_eq!(parsed.open_info(), [1, 2, 3, 4]);
        assert_eq!(parsed.metadata.priority, Some(7));
        assert_eq!(parsed.metadata().priority, Some(7));
        assert_eq!(parsed.metadata.group, Some(11));
        assert_eq!(parsed.metadata.open_info, [1, 2, 3, 4]);
    }

    #[test]
    fn empty_prelude_is_one_zero_byte() {
        let prelude = build_stream_prelude(&OpenOptions::default()).unwrap();
        assert_eq!(prelude, vec![0]);
        let parsed = read_stream_prelude(&mut prelude.as_slice()).unwrap();
        assert!(parsed.metadata_valid);
        assert_eq!(parsed.metadata, StreamMetadata::default());
    }

    #[test]
    fn duplicate_singleton_metadata_is_ignored() {
        let mut prelude = Vec::new();
        let metadata = [
            zmux::METADATA_STREAM_PRIORITY as u8,
            1,
            5,
            zmux::METADATA_STREAM_PRIORITY as u8,
            1,
            6,
        ];
        zmux::append_varint(&mut prelude, metadata.len() as u64).unwrap();
        prelude.extend_from_slice(&metadata);

        let parsed = read_stream_prelude(&mut prelude.as_slice()).unwrap();
        assert!(!parsed.metadata_valid);
        assert_eq!(parsed.metadata, StreamMetadata::default());
    }

    #[test]
    fn malformed_metadata_is_rejected() {
        let mut prelude = Vec::new();
        let metadata = [zmux::METADATA_STREAM_PRIORITY as u8, 2, 5];
        zmux::append_varint(&mut prelude, metadata.len() as u64).unwrap();
        prelude.extend_from_slice(&metadata);

        let err = read_stream_prelude(&mut prelude.as_slice()).unwrap_err();
        assert!(err.is_error_code(zmux::ErrorCode::Protocol));
        assert_eq!(err.scope(), zmux::ErrorScope::Stream);
        assert_eq!(err.source(), zmux::ErrorSource::Remote);
        assert_eq!(err.direction(), zmux::ErrorDirection::Both);
    }

    #[test]
    fn session_option_defaults_match_go_adapter_bounds() {
        let previous_default = SessionOptions::default_accepted_prelude_max_concurrent();
        SessionOptions::set_default_accepted_prelude_max_concurrent(0);
        assert_eq!(
            normalize_accepted_prelude_max_concurrent(None),
            DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT
        );
        assert_eq!(
            SessionOptions::default_accepted_prelude_max_concurrent(),
            DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT
        );
        SessionOptions::set_default_accepted_prelude_max_concurrent(5);
        assert_eq!(SessionOptions::default_accepted_prelude_max_concurrent(), 5);
        assert_eq!(normalize_accepted_prelude_max_concurrent(None), 5);
        assert_eq!(normalize_accepted_prelude_max_concurrent(Some(0)), 5);
        SessionOptions::set_default_accepted_prelude_max_concurrent(
            MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT + 1,
        );
        assert_eq!(
            SessionOptions::default_accepted_prelude_max_concurrent(),
            MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT
        );
        SessionOptions::set_default_accepted_prelude_max_concurrent(previous_default);
        assert_eq!(
            normalize_accepted_prelude_read_timeout(SessionOptions::default()),
            Some(DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT)
        );
        let custom = SessionOptions::new()
            .accepted_prelude_read_timeout(Duration::from_secs(2))
            .accepted_prelude_max_concurrent(16);
        assert_eq!(
            normalize_accepted_prelude_read_timeout(custom),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            normalize_accepted_prelude_max_concurrent(custom.accepted_prelude_max_concurrent),
            16
        );
        assert_eq!(
            normalize_accepted_prelude_read_timeout(
                SessionOptions::new()
                    .accepted_prelude_read_timeout(Duration::from_secs(2))
                    .disable_accepted_prelude_read_timeout()
            ),
            None
        );
        assert_eq!(
            normalize_accepted_prelude_read_timeout(
                SessionOptions::new()
                    .disable_accepted_prelude_read_timeout()
                    .accepted_prelude_read_timeout(Duration::from_secs(2))
            ),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            normalize_accepted_prelude_read_timeout(SessionOptions {
                accepted_prelude_read_timeout: AcceptedPreludeReadTimeout::Timeout(Duration::ZERO),
                ..SessionOptions::default()
            }),
            Some(DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT)
        );
        assert_eq!(
            normalize_accepted_prelude_read_timeout(SessionOptions {
                accepted_prelude_read_timeout: AcceptedPreludeReadTimeout::Disabled,
                ..SessionOptions::default()
            }),
            None
        );
        assert_eq!(normalize_accepted_prelude_max_concurrent(Some(3)), 3);
        assert_eq!(
            normalize_accepted_prelude_max_concurrent(Some(
                MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT + 1
            )),
            MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT
        );
    }

    #[test]
    fn total_bytes_counts_empty_vectored_parts() {
        let parts = [IoSlice::new(b"abc"), IoSlice::new(b""), IoSlice::new(b"de")];
        assert_eq!(total_bytes(parts.iter().map(|part| part.len())).unwrap(), 5);
    }

    #[test]
    fn total_bytes_rejects_usize_overflow() {
        let err = total_bytes([usize::MAX, 1]).unwrap_err();
        assert_eq!(err.scope(), zmux::ErrorScope::Stream);
        assert_eq!(err.source(), zmux::ErrorSource::Local);
        assert_eq!(err.operation(), zmux::ErrorOperation::Write);
        assert_eq!(err.direction(), zmux::ErrorDirection::Write);
    }

    #[test]
    fn support_saturating_helpers_clamp_at_integer_limits() {
        let counter = AtomicU64::new(u64::MAX);
        saturating_add_atomic_u64(&counter, 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);

        let counter = AtomicU64::new(u64::MAX - 1);
        saturating_add_atomic_u64(&counter, 2);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);

        let counter = AtomicUsize::new(usize::MAX);
        saturating_increment_atomic_usize(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), usize::MAX);

        assert_eq!(
            duration_nanos_saturating(Duration::from_secs(u64::MAX)),
            u64::MAX - 1
        );
    }

    #[test]
    fn adapter_reason_stats_bound_distinct_codes_and_count_overflow() {
        let mut reasons = AdapterReasonStats::default();
        let overflow = 5;
        for i in 0..MAX_REASON_STATS_CODES + overflow {
            let code = u64::try_from(i).unwrap();
            reasons.note_reset(10_000 + code);
            reasons.note_abort(20_000 + code);
        }
        reasons.note_reset(10_000);
        reasons.note_abort(20_000);

        let snapshot = reasons.snapshot();
        assert_eq!(snapshot.reset.len(), MAX_REASON_STATS_CODES);
        assert_eq!(snapshot.abort.len(), MAX_REASON_STATS_CODES);
        assert_eq!(snapshot.reset_overflow, u64::try_from(overflow).unwrap());
        assert_eq!(snapshot.abort_overflow, u64::try_from(overflow).unwrap());
        assert_eq!(snapshot.reset.get(&10_000), Some(&2));
        assert_eq!(snapshot.abort.get(&20_000), Some(&2));
    }

    #[test]
    fn single_non_empty_io_slice_skips_empty_parts() {
        let parts = [IoSlice::new(b""), IoSlice::new(b"abc"), IoSlice::new(b"")];
        assert_eq!(single_non_empty_io_slice(&parts), Some(&b"abc"[..]));

        let parts = [IoSlice::new(b"abc"), IoSlice::new(b"de")];
        assert_eq!(single_non_empty_io_slice(&parts), None);

        let parts = [IoSlice::new(b""), IoSlice::new(b"")];
        assert_eq!(single_non_empty_io_slice(&parts), None);
    }

    #[test]
    fn prelude_metadata_len_rejects_cap_overflow() {
        let err = checked_prelude_metadata_len(STREAM_PRELUDE_MAX_PAYLOAD, 1).unwrap_err();
        assert!(err.is_error_code(zmux::ErrorCode::Protocol));
        assert_eq!(
            checked_prelude_metadata_len(STREAM_PRELUDE_MAX_PAYLOAD - 1, 1).unwrap(),
            usize::try_from(STREAM_PRELUDE_MAX_PAYLOAD - 1).unwrap()
        );
    }

    #[test]
    fn active_guard_finishes_once_before_drop() {
        let counters = Arc::new(ActiveCounters::default());
        let guard = ActiveGuard::new(counters.clone(), ActiveKind::LocalBidi);
        assert_eq!(counters.snapshot().total, 1);
        guard.finish();
        assert_eq!(counters.snapshot().total, 0);
        drop(guard);
        assert_eq!(counters.snapshot().total, 0);
    }

    #[test]
    fn adapter_stats_snapshot_reports_progress_without_ping_fields() {
        let stats = AdapterStats::new();
        let now = Instant::now();
        stats.note_accepted_stream();
        stats.note_hidden_refused();
        stats.note_reset_reason(7);
        stats.note_abort_reason(9);
        stats.note_data_write(7, now);
        stats.note_data_read(3, now);
        stats.note_flush(7, now);
        stats.note_control_progress_at(now);
        stats.note_open_latency(now, now + Duration::from_millis(2));
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.accepted_streams, 1);
        assert_eq!(snapshot.hidden_refused, 1);
        assert_eq!(snapshot.reasons.reset.get(&7), Some(&1));
        assert_eq!(snapshot.reasons.abort.get(&9), Some(&1));
        assert_eq!(snapshot.sent_data_bytes, 7);
        assert_eq!(snapshot.received_data_bytes, 3);
        assert_eq!(snapshot.flush.count, 1);
        assert_eq!(snapshot.flush.last_bytes, 7);
        assert_eq!(
            snapshot.telemetry.last_open_latency,
            Some(Duration::from_millis(2))
        );
        assert!(snapshot.progress.control_progress_at.is_some());
        assert!(snapshot.progress.transport_write_at.is_some());
        assert!(snapshot.progress.stream_progress_at.is_some());
        assert!(snapshot.progress.application_progress_at.is_some());
        assert!(snapshot.progress.inbound_frame_at.is_some());
        assert!(snapshot.progress.ping_sent_at.is_none());
        assert!(snapshot.progress.pong_at.is_none());
    }
}
