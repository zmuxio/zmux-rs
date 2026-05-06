use crate::api::DuplexInfoSide;
use crate::error::{Error, ErrorCode, ErrorDirection, ErrorOperation, Result};
use crate::open_send::{OpenRequest, OpenSend, WritePayload};
use crate::payload::{MetadataUpdate, StreamMetadata};
use crate::preface::{Negotiated, Preface};
use crate::protocol::Role;
use crate::session::{
    Conn, PeerCloseError, PeerGoAwayError, RecvStream, SendStream, SessionState, SessionStats,
    Stream,
};
use crate::settings::{SchedulerHint, Settings};
use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::{self, size_of_val};
use std::net::SocketAddr;
use std::pin::Pin;
use std::ptr::{from_ref, null};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MAX_CONDVAR_TIMED_WAIT: Duration = Duration::from_secs(3600);
const MAX_OPEN_INFO_PREALLOC: usize = 64 * 1024;

#[inline]
fn nonzero_duration_value(value: Duration) -> Option<Duration> {
    (!value.is_zero()).then_some(value)
}

#[inline]
fn condvar_timed_wait_step(remaining: Duration) -> (Duration, bool) {
    let wait = remaining.min(MAX_CONDVAR_TIMED_WAIT);
    (wait, wait == remaining)
}

#[inline]
fn next_generation(current: u64) -> u64 {
    let next = current.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

/// Boxed future used by the async session and stream traits.
pub type AsyncBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Boxed bidirectional async stream trait object.
pub type BoxAsyncDuplexStream = Box<dyn AsyncDuplexStreamHandle>;

/// Boxed send-only async stream trait object.
pub type BoxAsyncSendStream = Box<dyn AsyncSendStreamHandle>;

/// Boxed receive-only async stream trait object.
pub type BoxAsyncRecvStream = Box<dyn AsyncRecvStreamHandle>;

/// Boxed async session trait object.
pub type BoxAsyncSession = Box<
    dyn AsyncSession<
        Stream = BoxAsyncDuplexStream,
        SendStream = BoxAsyncSendStream,
        RecvStream = BoxAsyncRecvStream,
    >,
>;

/// Wrap an async session and erase its concrete stream types.
#[must_use]
pub fn box_async_session<S>(session: S) -> BoxAsyncSession
where
    S: AsyncSession + 'static,
{
    Box::new(BoxedAsyncSession::new(session))
}

/// A permanently closed async session.
///
/// Use this as a no-op fallback when upper-layer code wants to keep a concrete
/// session handle but no transport/session is available.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClosedAsyncSession;

/// Create a permanently closed async session.
#[must_use]
pub fn closed_async_session() -> ClosedAsyncSession {
    ClosedAsyncSession
}

/// Adapter that turns any `AsyncSession` into a boxed common async session.
pub(crate) struct BoxedAsyncSession<S> {
    inner: S,
}

impl<S> BoxedAsyncSession<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self { inner }
    }
}

/// Runtime-neutral stream metadata and close operations for async upper layers.
pub trait AsyncStreamHandle: Send + Sync {
    fn stream_id(&self) -> u64;
    fn is_opened_locally(&self) -> bool;
    fn is_bidirectional(&self) -> bool;
    fn open_info_len(&self) -> usize;
    fn has_open_info(&self) -> bool {
        self.open_info_len() != 0
    }
    /// Append opaque binary open metadata to `dst`.
    fn append_open_info_to(&self, dst: &mut Vec<u8>);
    /// Return opaque binary open metadata.
    fn open_info(&self) -> Vec<u8> {
        let mut open_info = Vec::with_capacity(self.open_info_len().min(MAX_OPEN_INFO_PREALLOC));
        self.append_open_info_to(&mut open_info);
        open_info
    }
    fn metadata(&self) -> StreamMetadata;
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn set_deadline(&self, _deadline: Option<Instant>) -> Result<()> {
        Err(deadline_unsupported_error())
    }
    fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }
    /// Stable resource identity used internally to avoid closing the same
    /// joined full stream twice.
    #[doc(hidden)]
    fn close_identity(&self) -> *const () {
        if size_of_val(self) == 0 {
            null()
        } else {
            from_ref(self).cast::<()>()
        }
    }
    fn close(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn close_with_error<'a>(&'a self, code: u64, reason: &'a str)
        -> AsyncBoxFuture<'a, Result<()>>;
}

/// Runtime-neutral receive stream operations.
pub trait AsyncRecvStreamHandle: AsyncStreamHandle {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<usize>>;
    fn read_vectored<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            for dst in dsts.iter_mut() {
                if !dst.is_empty() {
                    let requested = dst.len();
                    let n = self.read(dst).await?;
                    return validate_read_progress(n, requested);
                }
            }
            Ok(0)
        })
    }
    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>>;
    fn read_vectored_timeout<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            for dst in dsts.iter_mut() {
                if !dst.is_empty() {
                    let requested = dst.len();
                    let n = self.read_timeout(dst, timeout).await?;
                    return validate_read_progress(n, requested);
                }
            }
            Ok(0)
        })
    }
    fn read_exact<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut remaining = dst;
            while !remaining.is_empty() {
                let n = validate_read_progress(self.read(remaining).await?, remaining.len())?;
                if n == 0 {
                    return Err(unexpected_eof_error());
                }
                let (_, rest) = remaining.split_at_mut(n);
                remaining = rest;
            }
            Ok(())
        })
    }
    fn read_exact_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let start = Instant::now();
            let mut remaining = dst;
            while !remaining.is_empty() {
                let timeout = remaining_read_timeout(start, timeout)?;
                let n = validate_read_progress(
                    self.read_timeout(remaining, timeout).await?,
                    remaining.len(),
                )?;
                if n == 0 {
                    return Err(unexpected_eof_error());
                }
                let (_, rest) = remaining.split_at_mut(n);
                remaining = rest;
            }
            Ok(())
        })
    }
    fn is_read_closed(&self) -> bool;
    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.set_deadline(deadline)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_read_deadline(timeout_to_deadline(timeout))
    }
    fn read_to_end<'a>(&'a self, dst: &'a mut Vec<u8>) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let start_len = dst.len();
            let mut buf = [0u8; 8 * 1024];
            loop {
                let n = validate_read_progress(self.read(&mut buf).await?, buf.len())?;
                if n == 0 {
                    return Ok(dst.len() - start_len);
                }
                dst.try_reserve(n)
                    .map_err(|_| Error::local("zmux: read_to_end allocation failed"))?;
                dst.extend_from_slice(&buf[..n]);
            }
        })
    }
    fn read_to_end_limited(&self, max_bytes: usize) -> AsyncBoxFuture<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            let mut out = Vec::with_capacity(max_bytes.min(8 * 1024));
            let mut buf = [0u8; 8 * 1024];
            loop {
                let remaining = max_bytes.saturating_sub(out.len());
                if remaining == 0 {
                    let mut overflow = [0u8; 1];
                    let n =
                        validate_read_progress(self.read(&mut overflow).await?, overflow.len())?;
                    return match n {
                        0 => Ok(out),
                        _ => Err(read_limit_exceeded_error(max_bytes)),
                    };
                }
                let cap = remaining.min(buf.len());
                let n = validate_read_progress(self.read(&mut buf[..cap]).await?, cap)?;
                if n == 0 {
                    return Ok(out);
                }
                out.try_reserve(n)
                    .map_err(|_| Error::local("zmux: read_to_end allocation failed"))?;
                out.extend_from_slice(&buf[..n]);
            }
        })
    }
    fn close_read(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn cancel_read(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>>;
}

/// Runtime-neutral send stream operations.
pub trait AsyncSendStreamHandle: AsyncStreamHandle {
    fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>>;

    fn write_all<'a>(&'a self, payload: WritePayload<'a>) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            match payload {
                WritePayload::Bytes(data) => {
                    let mut remaining = data.as_ref();
                    while !remaining.is_empty() {
                        let n =
                            validate_write_progress(self.write(remaining).await?, remaining.len())?;
                        if n == 0 {
                            return Err(zero_length_write_error());
                        }
                        remaining = &remaining[n..];
                    }
                }
                WritePayload::Vectored(parts) => {
                    for part in parts {
                        let mut remaining = part.as_ref();
                        while !remaining.is_empty() {
                            let n = validate_write_progress(
                                self.write(remaining).await?,
                                remaining.len(),
                            )?;
                            if n == 0 {
                                return Err(zero_length_write_error());
                            }
                            remaining = &remaining[n..];
                        }
                    }
                }
            }
            Ok(())
        })
    }

    fn write_all_timeout<'a>(
        &'a self,
        payload: WritePayload<'a>,
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let start = Instant::now();
            match payload {
                WritePayload::Bytes(data) => {
                    let mut remaining = data.as_ref();
                    while !remaining.is_empty() {
                        let timeout = remaining_write_timeout(start, timeout)?;
                        let n = validate_write_progress(
                            self.write_timeout(remaining, timeout).await?,
                            remaining.len(),
                        )?;
                        if n == 0 {
                            return Err(zero_length_write_error());
                        }
                        remaining = &remaining[n..];
                    }
                }
                WritePayload::Vectored(parts) => {
                    for part in parts {
                        let mut remaining = part.as_ref();
                        while !remaining.is_empty() {
                            let timeout = remaining_write_timeout(start, timeout)?;
                            let n = validate_write_progress(
                                self.write_timeout(remaining, timeout).await?,
                                remaining.len(),
                            )?;
                            if n == 0 {
                                return Err(zero_length_write_error());
                            }
                            remaining = &remaining[n..];
                        }
                    }
                }
            }
            Ok(())
        })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>>;

    fn write_vectored<'a>(&'a self, parts: &'a [IoSlice<'_>]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            for part in parts {
                if !part.is_empty() {
                    let n = self.write(part).await?;
                    return validate_write_progress(n, part.len());
                }
            }
            Ok(0)
        })
    }

    fn write_vectored_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            for part in parts {
                if !part.is_empty() {
                    let n = self.write_timeout(part, timeout).await?;
                    return validate_write_progress(n, part.len());
                }
            }
            Ok(0)
        })
    }

    fn write_final<'a>(&'a self, payload: WritePayload<'a>) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let total = payload.checked_len()?;
            self.write_all(payload).await?;
            self.close_write().await?;
            Ok(total)
        })
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: WritePayload<'a>,
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>>;

    fn write_vectored_final<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move { self.write_final(WritePayload::vectored(parts)).await })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            self.write_final_timeout(WritePayload::vectored(parts), timeout)
                .await
        })
    }

    fn is_write_closed(&self) -> bool;
    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.set_deadline(deadline)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_write_deadline(timeout_to_deadline(timeout))
    }
    fn update_metadata(&self, update: MetadataUpdate) -> AsyncBoxFuture<'_, Result<()>>;
    fn close_write(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn cancel_write(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>>;
}

/// Runtime-neutral bidirectional async stream operations.
pub trait AsyncDuplexStreamHandle: AsyncRecvStreamHandle + AsyncSendStreamHandle {}

/// Runtime-neutral async session operations shared by native ZMux and adapters.
pub trait AsyncSession: Send + Sync {
    type Stream: AsyncDuplexStreamHandle + Send + Sync + 'static;
    type SendStream: AsyncSendStreamHandle + Send + Sync + 'static;
    type RecvStream: AsyncRecvStreamHandle + Send + Sync + 'static;

    fn accept_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn accept_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn accept_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::RecvStream>>;
    fn accept_uni_stream_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::RecvStream>>;
    fn open_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        self.open_stream_with(OpenRequest::new())
    }
    fn open_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        self.open_uni_stream_with(OpenRequest::new())
    }
    fn open_stream_with(&self, request: OpenRequest) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn open_uni_stream_with(
        &self,
        request: OpenRequest,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>>;

    fn open_and_send<'a>(
        &'a self,
        request: OpenSend<'a>,
    ) -> AsyncBoxFuture<'a, Result<Self::Stream>> {
        Box::pin(async move {
            let (opts, payload, timeout) = request.into_parts();
            let start = Instant::now();
            let mut open = OpenRequest::new().options(opts);
            if let Some(timeout) = timeout {
                ensure_positive_open_timeout(timeout)?;
                open = open.timeout(timeout);
            }
            let stream = self.open_stream_with(open).await?;
            let write_result: Result<()> = async {
                let timeout = timeout
                    .map(|timeout| remaining_write_timeout(start, timeout))
                    .transpose()?;
                write_open_payload_async(&stream, payload, timeout, false, true).await
            }
            .await;
            if let Err(err) = write_result {
                let code = err.numeric_code().unwrap_or(ErrorCode::Cancelled.as_u64());
                let _ = stream.close_with_error(code, "open_and_send failed").await;
                return Err(err);
            }
            Ok(stream)
        })
    }

    fn open_uni_and_send<'a>(
        &'a self,
        request: OpenSend<'a>,
    ) -> AsyncBoxFuture<'a, Result<Self::SendStream>> {
        Box::pin(async move {
            let (opts, payload, timeout) = request.into_parts();
            let start = Instant::now();
            let mut open = OpenRequest::new().options(opts);
            if let Some(timeout) = timeout {
                ensure_positive_open_timeout(timeout)?;
                open = open.timeout(timeout);
            }
            let stream = self.open_uni_stream_with(open).await?;
            let write_result: Result<()> = async {
                let timeout = timeout
                    .map(|timeout| remaining_write_timeout(start, timeout))
                    .transpose()?;
                write_open_payload_async(&stream, payload, timeout, true, false).await
            }
            .await;
            if let Err(err) = write_result {
                let code = err.numeric_code().unwrap_or(ErrorCode::Cancelled.as_u64());
                let _ = stream
                    .close_with_error(code, "open_uni_and_send failed")
                    .await;
                return Err(err);
            }
            Ok(stream)
        })
    }

    fn ping<'a>(&'a self, echo: &'a [u8]) -> AsyncBoxFuture<'a, Result<Duration>>;
    fn ping_timeout<'a>(
        &'a self,
        echo: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<Duration>>;

    fn go_away(
        &self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
    ) -> AsyncBoxFuture<'_, Result<()>>;

    fn go_away_with_error<'a>(
        &'a self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>>;

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn close_with_error<'a>(&'a self, code: u64, reason: &'a str)
        -> AsyncBoxFuture<'a, Result<()>>;
    fn wait(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn wait_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<bool>>;
    fn is_closed(&self) -> bool;
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn close_error(&self) -> Option<Error>;
    fn state(&self) -> SessionState;
    fn stats(&self) -> SessionStats;
    fn peer_go_away_error(&self) -> Option<PeerGoAwayError>;
    fn peer_close_error(&self) -> Option<PeerCloseError>;
    fn local_preface(&self) -> Preface;
    fn peer_preface(&self) -> Preface;
    fn negotiated(&self) -> Negotiated;
}

fn closed_async_session_error(operation: ErrorOperation) -> Error {
    Error::session_closed().with_session_context(operation)
}

fn closed_async_session_result<T>(operation: ErrorOperation) -> AsyncBoxFuture<'static, Result<T>> {
    Box::pin(async move { Err(closed_async_session_error(operation)) })
}

fn zero_session_settings() -> Settings {
    Settings {
        initial_max_stream_data_bidi_locally_opened: 0,
        initial_max_stream_data_bidi_peer_opened: 0,
        initial_max_stream_data_uni: 0,
        initial_max_data: 0,
        max_incoming_streams_bidi: 0,
        max_incoming_streams_uni: 0,
        max_frame_payload: 0,
        idle_timeout_millis: 0,
        keepalive_hint_millis: 0,
        max_control_payload_bytes: 0,
        max_extension_payload_bytes: 0,
        scheduler_hints: SchedulerHint::UnspecifiedOrBalanced,
        ping_padding_key: 0,
    }
}

fn zero_session_preface() -> Preface {
    Preface {
        preface_version: 0,
        role: Role::Initiator,
        tie_breaker_nonce: 0,
        min_proto: 0,
        max_proto: 0,
        capabilities: 0,
        settings: zero_session_settings(),
    }
}

fn zero_session_negotiated() -> Negotiated {
    Negotiated {
        proto: 0,
        capabilities: 0,
        local_role: Role::Initiator,
        peer_role: Role::Initiator,
        peer_settings: zero_session_settings(),
    }
}

impl AsyncSession for ClosedAsyncSession {
    type Stream = BoxAsyncDuplexStream;
    type SendStream = BoxAsyncSendStream;
    type RecvStream = BoxAsyncRecvStream;

    fn accept_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        closed_async_session_result(ErrorOperation::Accept)
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        closed_async_session_result(ErrorOperation::Accept)
    }

    fn accept_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
        closed_async_session_result(ErrorOperation::Accept)
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
        closed_async_session_result(ErrorOperation::Accept)
    }

    fn open_stream_with(&self, _request: OpenRequest) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn open_uni_stream_with(
        &self,
        _request: OpenRequest,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn ping<'a>(&'a self, _echo: &'a [u8]) -> AsyncBoxFuture<'a, Result<Duration>> {
        closed_async_session_result(ErrorOperation::Ping)
    }

    fn ping_timeout<'a>(
        &'a self,
        _echo: &'a [u8],
        _timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<Duration>> {
        closed_async_session_result(ErrorOperation::Ping)
    }

    fn go_away(
        &self,
        _last_accepted_bidi: u64,
        _last_accepted_uni: u64,
    ) -> AsyncBoxFuture<'_, Result<()>> {
        closed_async_session_result(ErrorOperation::Close)
    }

    fn go_away_with_error<'a>(
        &'a self,
        _last_accepted_bidi: u64,
        _last_accepted_uni: u64,
        _code: u64,
        _reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        closed_async_session_result(ErrorOperation::Close)
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> AsyncBoxFuture<'_, Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn is_closed(&self) -> bool {
        true
    }

    fn close_error(&self) -> Option<Error> {
        None
    }

    fn state(&self) -> SessionState {
        SessionState::Closed
    }

    fn stats(&self) -> SessionStats {
        SessionStats::empty(SessionState::Closed)
    }

    fn peer_go_away_error(&self) -> Option<PeerGoAwayError> {
        None
    }

    fn peer_close_error(&self) -> Option<PeerCloseError> {
        None
    }

    fn local_preface(&self) -> Preface {
        zero_session_preface()
    }

    fn peer_preface(&self) -> Preface {
        zero_session_preface()
    }

    fn negotiated(&self) -> Negotiated {
        zero_session_negotiated()
    }
}

/// Logical bidirectional stream made from one receive-only and one send-only stream.
pub struct AsyncDuplexStream<R, W> {
    recv: Arc<AsyncJoinedHalf<R>>,
    send: Arc<AsyncJoinedHalf<W>>,
    info_side: DuplexInfoSide,
}

type AsyncDeadlineApplier<T> = fn(&T, Option<Instant>) -> Result<()>;

struct AsyncJoinedHalf<T> {
    state: Mutex<AsyncJoinedHalfState<T>>,
    changed: Condvar,
    deadline_operation: &'static str,
}

struct AsyncJoinedHalfState<T> {
    current: Option<Arc<T>>,
    paused: bool,
    active_ops: usize,
    closed: bool,
    deadline: Option<Instant>,
    deadline_generation: u64,
    deadline_applied_generation: u64,
    deadline_applying_generation: Option<u64>,
    deadline_applier: Option<AsyncDeadlineApplier<T>>,
}

struct ActiveAsyncHalf<T> {
    owner: Arc<AsyncJoinedHalf<T>>,
    half: Arc<T>,
}

/// Pause handle returned by async joined stream read/write half pauses.
///
/// The handle owns the detached half until `resume` reattaches it. Dropping the
/// handle resumes with the currently staged half on a best-effort basis.
pub struct PausedAsyncHalf<T> {
    owner: Arc<AsyncJoinedHalf<T>>,
    current: Option<Arc<T>>,
    resumed: bool,
}

/// Detached receive half handle for `AsyncDuplexStream`.
pub type PausedAsyncRecvHalf<R> = PausedAsyncHalf<R>;

/// Detached send half handle for `AsyncDuplexStream`.
pub type PausedAsyncSendHalf<W> = PausedAsyncHalf<W>;

/// Join one async receive-capable stream half and one async send-capable stream
/// half into a bidirectional stream view.
///
/// This is intended for already-separated directions, including two
/// unidirectional streams or halves from different adapters.
#[must_use]
pub fn join_async_streams<R, W>(recv: R, send: W) -> AsyncDuplexStream<R, W> {
    AsyncDuplexStream::new(recv, send)
}

impl<T> AsyncJoinedHalf<T> {
    fn new_optional(current: Option<T>, deadline_operation: &'static str) -> Self {
        Self {
            state: Mutex::new(AsyncJoinedHalfState {
                current: current.map(Arc::new),
                paused: false,
                active_ops: 0,
                closed: false,
                deadline: None,
                deadline_generation: 0,
                deadline_applied_generation: 0,
                deadline_applying_generation: None,
                deadline_applier: None,
            }),
            changed: Condvar::new(),
            deadline_operation,
        }
    }

    fn current(&self) -> Option<Arc<T>> {
        let state = self.state.lock().unwrap();
        if state.closed || state.paused {
            return None;
        }
        state.current.clone()
    }

    fn with_current_or<U>(&self, default: U, visit: impl FnOnce(&T) -> U) -> U {
        self.current().as_deref().map_or(default, visit)
    }

    fn enter(self: &Arc<Self>, missing: impl FnOnce() -> Error) -> Result<ActiveAsyncHalf<T>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if !state.paused {
                let half = state.current.clone().ok_or_else(missing)?;
                state.active_ops += 1;
                return Ok(ActiveAsyncHalf {
                    owner: Arc::clone(self),
                    half,
                });
            }
            state = self.wait_while_paused(state)?;
        }
    }

    fn enter_optional(self: &Arc<Self>) -> Result<Option<ActiveAsyncHalf<T>>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if !state.paused {
                let Some(half) = state.current.clone() else {
                    return Ok(None);
                };
                state.active_ops += 1;
                return Ok(Some(ActiveAsyncHalf {
                    owner: Arc::clone(self),
                    half,
                }));
            }
            state = self.wait_while_paused(state)?;
        }
    }

    fn enter_timeout(
        self: &Arc<Self>,
        timeout: Duration,
        operation: &'static str,
        missing: impl FnOnce() -> Error,
    ) -> Result<ActiveAsyncHalf<T>> {
        let start = Instant::now();
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if !state.paused {
                let half = state.current.clone().ok_or_else(missing)?;
                state.active_ops += 1;
                return Ok(ActiveAsyncHalf {
                    owner: Arc::clone(self),
                    half,
                });
            }
            let Some(remaining) = self.paused_wait_timeout(&state, start, timeout) else {
                return Err(Error::timeout(operation));
            };
            let (wait_for, reaches_deadline) = condvar_timed_wait_step(remaining);
            let (next, wait) = self.changed.wait_timeout(state, wait_for).unwrap();
            state = next;
            if wait.timed_out() && reaches_deadline && state.paused {
                return Err(Error::timeout(operation));
            }
        }
    }

    fn pause(self: &Arc<Self>, timeout: Option<Duration>) -> Result<Option<Arc<T>>> {
        let start = Instant::now();
        let mut owns_pause = false;
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if !owns_pause && state.paused {
                state = wait_joined_half_state(&self.changed, state, start, timeout)?;
                continue;
            }
            if !owns_pause {
                state.paused = true;
                owns_pause = true;
                self.changed.notify_all();
                continue;
            }
            if state.active_ops == 0 {
                let current = state.current.take();
                self.changed.notify_all();
                return Ok(current);
            }
            match wait_joined_half_state(&self.changed, state, start, timeout) {
                Ok(next) => state = next,
                Err(err) => {
                    let mut state = self.state.lock().unwrap();
                    if state.paused && !state.closed {
                        state.paused = false;
                        self.changed.notify_all();
                    }
                    drop(state);
                    return Err(err);
                }
            }
        }
    }

    fn resume(&self, current: Option<Arc<T>>) -> Result<()> {
        let mut current = current;
        let mut deadline_result = Ok(());
        loop {
            let applied_generation = match current.as_ref() {
                Some(current) => match self.apply_deadline_to_candidate(current.as_ref()) {
                    Ok(generation) => generation,
                    Err(err) => {
                        deadline_result = Err(err);
                        None
                    }
                },
                None => None,
            };

            let mut state = self.state.lock().unwrap();
            if state.closed {
                state.paused = false;
                drop(state);
                self.changed.notify_all();
                return Err(Error::session_closed());
            }
            if deadline_result.is_ok()
                && current.is_some()
                && state.deadline_applier.is_some()
                && Some(state.deadline_generation) != applied_generation
            {
                drop(state);
                continue;
            }
            state.current = current.take();
            state.paused = false;
            drop(state);
            self.changed.notify_all();
            return deadline_result;
        }
    }

    fn replace(&self, next: Option<T>) -> Result<Option<Arc<T>>> {
        self.replace_arc(next.map(Arc::new))
    }

    fn replace_arc(&self, next: Option<Arc<T>>) -> Result<Option<Arc<T>>> {
        let mut applied_generation = None;
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if state.paused {
                return Err(Error::local("zmux: joined stream half is paused"));
            }
            if state.active_ops == 0 {
                if next.is_some()
                    && state.deadline_applier.is_some()
                    && Some(state.deadline_generation) != applied_generation
                {
                    drop(state);
                    applied_generation = match next.as_deref() {
                        Some(next) => self.apply_deadline_to_candidate(next)?,
                        None => None,
                    };
                    state = self.state.lock().unwrap();
                    continue;
                }
                let previous = mem::replace(&mut state.current, next);
                self.changed.notify_all();
                return Ok(previous);
            }
            state = self.changed.wait(state).unwrap();
        }
    }

    fn close_detached(&self) -> Option<Arc<T>> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return None;
        }
        state.closed = true;
        state.paused = false;
        let current = state.current.take();
        drop(state);
        self.changed.notify_all();
        current
    }

    fn leave(&self) {
        {
            let mut state = self.state.lock().unwrap();
            if state.active_ops > 0 {
                state.active_ops -= 1;
            }
        }
        self.changed.notify_all();
    }

    fn set_deadline(
        &self,
        deadline: Option<Instant>,
        applier: AsyncDeadlineApplier<T>,
    ) -> Result<()> {
        let current = {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(Error::session_closed());
            }
            state.deadline = deadline;
            state.deadline_generation = next_generation(state.deadline_generation);
            state.deadline_applier = Some(applier);
            self.changed.notify_all();
            let current = match state.current.clone() {
                Some(current) => {
                    state.active_ops += 1;
                    Some(current)
                }
                None => None,
            };
            drop(state);
            current
        };
        let Some(current) = current else {
            return Ok(());
        };

        let mut deadline_result = Ok(());
        loop {
            let applied_generation = match self.apply_deadline_to_current(&current) {
                Ok(generation) => generation,
                Err(err) => {
                    deadline_result = Err(err);
                    None
                }
            };

            let mut state = self.state.lock().unwrap();
            if deadline_result.is_ok()
                && !state.closed
                && state.current.is_some()
                && state.deadline_applier.is_some()
                && Some(state.deadline_generation) != applied_generation
            {
                drop(state);
                continue;
            }
            if state.active_ops > 0 {
                state.active_ops -= 1;
            }
            drop(state);
            self.changed.notify_all();
            return deadline_result;
        }
    }

    fn apply_deadline_to_current(&self, current: &Arc<T>) -> Result<Option<u64>> {
        let (deadline, generation, applier) = loop {
            let mut state = self.state.lock().unwrap();
            let Some(applier) = state.deadline_applier else {
                return Ok(None);
            };
            let generation = state.deadline_generation;
            if state
                .current
                .as_ref()
                .is_some_and(|stored| Arc::ptr_eq(stored, current))
                && state.deadline_applied_generation == generation
            {
                return Ok(Some(generation));
            }
            if state.deadline_applying_generation == Some(generation) {
                state = self.changed.wait(state).unwrap();
                drop(state);
                continue;
            }
            state.deadline_applying_generation = Some(generation);
            break (state.deadline, generation, applier);
        };

        let result = applier(current.as_ref(), deadline);
        let mut state = self.state.lock().unwrap();
        if state.deadline_applying_generation == Some(generation) {
            state.deadline_applying_generation = None;
        }
        if result.is_ok()
            && state.deadline_generation == generation
            && state
                .current
                .as_ref()
                .is_some_and(|stored| Arc::ptr_eq(stored, current))
        {
            state.deadline_applied_generation = generation;
        }
        drop(state);
        self.changed.notify_all();
        result.map(|_| Some(generation))
    }

    fn apply_deadline_to_candidate(&self, current: &T) -> Result<Option<u64>> {
        let Some((deadline, generation, applier)) = self.deadline_snapshot() else {
            return Ok(None);
        };
        applier(current, deadline)?;
        {
            let mut state = self.state.lock().unwrap();
            if state.deadline_generation == generation {
                state.deadline_applied_generation = generation;
            }
        }
        Ok(Some(generation))
    }

    fn deadline_snapshot(&self) -> Option<(Option<Instant>, u64, AsyncDeadlineApplier<T>)> {
        let state = self.state.lock().unwrap();
        state
            .deadline_applier
            .map(|applier| (state.deadline, state.deadline_generation, applier))
    }

    fn wait_while_paused<'a>(
        &self,
        state: MutexGuard<'a, AsyncJoinedHalfState<T>>,
    ) -> Result<MutexGuard<'a, AsyncJoinedHalfState<T>>> {
        match deadline_remaining(state.deadline) {
            Some(remaining) => {
                let (wait_for, reaches_deadline) = condvar_timed_wait_step(remaining);
                let (state, wait) = self.changed.wait_timeout(state, wait_for).unwrap();
                if wait.timed_out() && reaches_deadline && state.paused {
                    Err(Error::timeout(self.deadline_operation))
                } else {
                    Ok(state)
                }
            }
            None if state.deadline.is_some() => Err(Error::timeout(self.deadline_operation)),
            None => Ok(self.changed.wait(state).unwrap()),
        }
    }

    fn paused_wait_timeout(
        &self,
        state: &AsyncJoinedHalfState<T>,
        start: Instant,
        timeout: Duration,
    ) -> Option<Duration> {
        let explicit = remaining_timeout(start, timeout)?;
        Some(match deadline_remaining(state.deadline) {
            Some(deadline) => explicit.min(deadline),
            None if state.deadline.is_some() => return None,
            None => explicit,
        })
    }
}

impl<T> Drop for ActiveAsyncHalf<T> {
    fn drop(&mut self) {
        self.owner.leave();
    }
}

impl<T> PausedAsyncHalf<T> {
    /// Borrows the detached half currently staged for resume.
    pub fn current(&self) -> Option<&T> {
        self.current.as_deref()
    }

    /// Takes the detached half out of this pause handle.
    pub fn take(&mut self) -> Option<Arc<T>> {
        self.current.take()
    }

    /// Replaces the staged half with a newly owned value.
    pub fn set(&mut self, next: Option<T>) -> Option<Arc<T>> {
        self.set_arc(next.map(Arc::new))
    }

    /// Replaces the staged half with an existing shared owner.
    ///
    /// Use this when the async transport half is already in an `Arc`; it avoids
    /// adding a second layer of shared ownership.
    pub fn set_arc(&mut self, next: Option<Arc<T>>) -> Option<Arc<T>> {
        mem::replace(&mut self.current, next)
    }

    /// Replaces the staged half with a new value and returns the previous one.
    pub fn replace(&mut self, next: T) -> Option<Arc<T>> {
        self.current.replace(Arc::new(next))
    }

    /// Reattaches the currently staged half and wakes waiters.
    pub fn resume(mut self) -> Result<()> {
        self.resumed = true;
        let current = self.current.take();
        self.owner.resume(current)
    }
}

impl<T> Drop for PausedAsyncHalf<T> {
    fn drop(&mut self) {
        if !self.resumed {
            let current = self.current.take();
            let _ = self.owner.resume(current);
            self.resumed = true;
        }
    }
}

fn remaining_timeout(start: Instant, timeout: Duration) -> Option<Duration> {
    timeout
        .checked_sub(start.elapsed())
        .and_then(nonzero_duration_value)
}

fn timeout_to_deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|timeout| Instant::now().checked_add(timeout))
}

fn deadline_remaining(deadline: Option<Instant>) -> Option<Duration> {
    deadline.and_then(|deadline| {
        deadline
            .checked_duration_since(Instant::now())
            .and_then(nonzero_duration_value)
    })
}

fn ensure_positive_open_timeout(timeout: Duration) -> Result<()> {
    if timeout.is_zero() {
        Err(Error::timeout("open").with_session_context(ErrorOperation::Open))
    } else {
        Ok(())
    }
}

fn remaining_write_timeout(start: Instant, timeout: Duration) -> Result<Duration> {
    remaining_timeout(start, timeout).ok_or_else(|| {
        Error::timeout("write").with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
    })
}

async fn write_open_payload_async<S>(
    stream: &S,
    payload: WritePayload<'_>,
    timeout: Option<Duration>,
    fin: bool,
    skip_empty: bool,
) -> Result<()>
where
    S: AsyncSendStreamHandle + ?Sized,
{
    let requested = payload.checked_len()?;
    if skip_empty && requested == 0 {
        return Ok(());
    }
    let n = match (payload, timeout, fin) {
        (payload, Some(timeout), false) => {
            stream.write_all_timeout(payload, timeout).await?;
            requested
        }
        (WritePayload::Bytes(data), Some(timeout), true) => {
            stream
                .write_final_timeout(WritePayload::Bytes(data), timeout)
                .await?
        }
        (payload, None, false) => {
            stream.write_all(payload).await?;
            requested
        }
        (WritePayload::Bytes(data), None, true) => {
            stream.write_final(WritePayload::Bytes(data)).await?
        }
        (WritePayload::Vectored(parts), Some(timeout), true) => {
            stream
                .write_final_timeout(WritePayload::Vectored(parts), timeout)
                .await?
        }
        (WritePayload::Vectored(parts), None, true) => {
            stream.write_final(WritePayload::Vectored(parts)).await?
        }
    };
    validate_write_progress(n, requested)?;
    Ok(())
}

fn remaining_read_timeout(start: Instant, timeout: Duration) -> Result<Duration> {
    remaining_timeout(start, timeout).ok_or_else(|| {
        Error::timeout("read").with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
    })
}

fn wait_joined_half_state<'a, T>(
    changed: &Condvar,
    state: MutexGuard<'a, AsyncJoinedHalfState<T>>,
    start: Instant,
    timeout: Option<Duration>,
) -> Result<MutexGuard<'a, AsyncJoinedHalfState<T>>> {
    match timeout.and_then(|timeout| remaining_timeout(start, timeout)) {
        Some(remaining) => {
            let (wait_for, reaches_deadline) = condvar_timed_wait_step(remaining);
            let (state, wait) = changed.wait_timeout(state, wait_for).unwrap();
            if wait.timed_out() && reaches_deadline {
                Err(Error::timeout("joined half pause"))
            } else {
                Ok(state)
            }
        }
        None if timeout.is_some() => Err(Error::timeout("joined half pause")),
        None => Ok(changed.wait(state).unwrap()),
    }
}

fn joined_read_half_missing_error() -> Error {
    Error::local("zmux: joined stream has no readable half")
}

fn joined_write_half_missing_error() -> Error {
    Error::local("zmux: joined stream has no writable half")
}

fn same_close_identity(first: *const (), second: *const ()) -> bool {
    !first.is_null() && first == second
}

fn apply_async_read_deadline<T: AsyncRecvStreamHandle>(
    stream: &T,
    deadline: Option<Instant>,
) -> Result<()> {
    stream.set_read_deadline(deadline)
}

fn apply_async_write_deadline<T: AsyncSendStreamHandle>(
    stream: &T,
    deadline: Option<Instant>,
) -> Result<()> {
    stream.set_write_deadline(deadline)
}

impl<R, W> AsyncDuplexStream<R, W> {
    #[must_use]
    pub fn new(recv: R, send: W) -> Self {
        Self::from_parts(Some(recv), Some(send))
    }

    #[must_use]
    pub fn from_parts(recv: Option<R>, send: Option<W>) -> Self {
        Self {
            recv: Arc::new(AsyncJoinedHalf::new_optional(recv, "read")),
            send: Arc::new(AsyncJoinedHalf::new_optional(send, "write")),
            info_side: DuplexInfoSide::Read,
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::from_parts(None, None)
    }

    #[must_use]
    pub fn with_info_side(mut self, info_side: DuplexInfoSide) -> Self {
        self.info_side = info_side;
        self
    }

    pub fn info_side(&self) -> DuplexInfoSide {
        self.info_side
    }

    pub fn recv(&self) -> Option<Arc<R>> {
        self.recv.current()
    }

    pub fn send(&self) -> Option<Arc<W>> {
        self.send.current()
    }

    pub fn into_parts(self) -> (Option<Arc<R>>, Option<Arc<W>>) {
        (self.recv.current(), self.send.current())
    }

    pub fn pause_read(&self) -> Result<PausedAsyncRecvHalf<R>> {
        self.pause_read_timeout_option(None)
    }

    pub fn pause_read_timeout(&self, timeout: Duration) -> Result<PausedAsyncRecvHalf<R>> {
        self.pause_read_timeout_option(Some(timeout))
    }

    fn pause_read_timeout_option(
        &self,
        timeout: Option<Duration>,
    ) -> Result<PausedAsyncRecvHalf<R>> {
        Ok(PausedAsyncHalf {
            owner: Arc::clone(&self.recv),
            current: self.recv.pause(timeout)?,
            resumed: false,
        })
    }

    pub fn pause_write(&self) -> Result<PausedAsyncSendHalf<W>> {
        self.pause_write_timeout_option(None)
    }

    pub fn pause_write_timeout(&self, timeout: Duration) -> Result<PausedAsyncSendHalf<W>> {
        self.pause_write_timeout_option(Some(timeout))
    }

    fn pause_write_timeout_option(
        &self,
        timeout: Option<Duration>,
    ) -> Result<PausedAsyncSendHalf<W>> {
        Ok(PausedAsyncHalf {
            owner: Arc::clone(&self.send),
            current: self.send.pause(timeout)?,
            resumed: false,
        })
    }

    pub fn replace_recv(&self, recv: R) -> Result<Option<Arc<R>>> {
        self.recv.replace(Some(recv))
    }

    pub fn replace_send(&self, send: W) -> Result<Option<Arc<W>>> {
        self.send.replace(Some(send))
    }

    pub fn detach_recv(&self) -> Result<Option<Arc<R>>> {
        self.recv.replace(None)
    }

    pub fn detach_send(&self) -> Result<Option<Arc<W>>> {
        self.send.replace(None)
    }
}

impl<R, W> AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamHandle,
    W: AsyncSendStreamHandle,
{
    pub fn read_stream_id(&self) -> u64 {
        self.recv.with_current_or(0, |recv| recv.stream_id())
    }

    pub fn write_stream_id(&self) -> u64 {
        self.send.with_current_or(0, |send| send.stream_id())
    }
}

impl<R, W> AsyncStreamHandle for AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamHandle,
    W: AsyncSendStreamHandle,
{
    fn stream_id(&self) -> u64 {
        match self.info_side {
            DuplexInfoSide::Read => self.recv.with_current_or(0, |recv| recv.stream_id()),
            DuplexInfoSide::Write => self.send.with_current_or(0, |send| send.stream_id()),
        }
    }

    fn is_opened_locally(&self) -> bool {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(false, |recv| recv.is_opened_locally()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(false, |send| send.is_opened_locally()),
        }
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        match self.info_side {
            DuplexInfoSide::Read => self.recv.with_current_or(0, |recv| recv.open_info_len()),
            DuplexInfoSide::Write => self.send.with_current_or(0, |send| send.open_info_len()),
        }
    }

    fn has_open_info(&self) -> bool {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(false, |recv| recv.has_open_info()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(false, |send| send.has_open_info()),
        }
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        match self.info_side {
            DuplexInfoSide::Read => {
                self.recv
                    .with_current_or((), |recv| recv.append_open_info_to(dst));
            }
            DuplexInfoSide::Write => {
                self.send
                    .with_current_or((), |send| send.append_open_info_to(dst));
            }
        }
    }

    fn open_info(&self) -> Vec<u8> {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(Vec::new(), |recv| recv.open_info()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(Vec::new(), |send| send.open_info()),
        }
    }

    fn metadata(&self) -> StreamMetadata {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(StreamMetadata::default(), |recv| recv.metadata()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(StreamMetadata::default(), |send| send.metadata()),
        }
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(None, |recv| recv.local_addr())
                .or_else(|| self.send.with_current_or(None, |send| send.local_addr())),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(None, |send| send.local_addr())
                .or_else(|| self.recv.with_current_or(None, |recv| recv.local_addr())),
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(None, |recv| recv.peer_addr())
                .or_else(|| self.send.with_current_or(None, |send| send.peer_addr())),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(None, |send| send.peer_addr())
                .or_else(|| self.recv.with_current_or(None, |recv| recv.peer_addr())),
        }
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        let read = <Self as AsyncRecvStreamHandle>::set_read_deadline(self, deadline);
        let write = <Self as AsyncSendStreamHandle>::set_write_deadline(self, deadline);
        read.and(write)
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let send = self.send.close_detached();
            let recv = self.recv.close_detached();
            let same_identity = send
                .as_deref()
                .zip(recv.as_deref())
                .is_some_and(|(send, recv)| {
                    same_close_identity(send.close_identity(), recv.close_identity())
                });

            let write = match send.as_ref() {
                Some(send) => send.close().await,
                None => Ok(()),
            };
            let read = if same_identity {
                Ok(())
            } else {
                match recv.as_ref() {
                    Some(recv) => recv.close().await,
                    None => Ok(()),
                }
            };
            write.and(read)
        })
    }

    fn close_with_error<'a>(
        &'a self,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let send = self.send.close_detached();
            let recv = self.recv.close_detached();
            let same_identity = send
                .as_deref()
                .zip(recv.as_deref())
                .is_some_and(|(send, recv)| {
                    same_close_identity(send.close_identity(), recv.close_identity())
                });

            let write = match send.as_ref() {
                Some(send) => send.close_with_error(code, reason).await,
                None => Ok(()),
            };
            let read = if same_identity {
                Ok(())
            } else {
                match recv.as_ref() {
                    Some(recv) => recv.close_with_error(code, reason).await,
                    None => Ok(()),
                }
            };
            write.and(read)
        })
    }
}

impl<R, W> AsyncRecvStreamHandle for AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamHandle,
    W: AsyncSendStreamHandle,
{
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let active = self.recv.enter(joined_read_half_missing_error)?;
            let n = active.half.read(dst).await?;
            validate_read_progress(n, dst.len())
        })
    }

    fn read_vectored<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let requested = checked_vectored_read_len(dsts)?;
            let active = self.recv.enter(joined_read_half_missing_error)?;
            let n = active.half.read_vectored(dsts).await?;
            validate_read_progress(n, requested)
        })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let start = Instant::now();
            let active =
                self.recv
                    .enter_timeout(timeout, "read", joined_read_half_missing_error)?;
            let remaining = remaining_read_timeout(start, timeout)?;
            let n = active.half.read_timeout(dst, remaining).await?;
            validate_read_progress(n, dst.len())
        })
    }

    fn read_vectored_timeout<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let requested = checked_vectored_read_len(dsts)?;
            let start = Instant::now();
            let active =
                self.recv
                    .enter_timeout(timeout, "read", joined_read_half_missing_error)?;
            let remaining = remaining_read_timeout(start, timeout)?;
            let n = active.half.read_vectored_timeout(dsts, remaining).await?;
            validate_read_progress(n, requested)
        })
    }

    fn read_exact<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let active = self.recv.enter(joined_read_half_missing_error)?;
            active.half.read_exact(dst).await
        })
    }

    fn read_exact_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let start = Instant::now();
            let active =
                self.recv
                    .enter_timeout(timeout, "read", joined_read_half_missing_error)?;
            let remaining = remaining_read_timeout(start, timeout)?;
            active.half.read_exact_timeout(dst, remaining).await
        })
    }

    fn is_read_closed(&self) -> bool {
        self.recv
            .with_current_or(true, |recv| recv.is_read_closed())
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        AsyncJoinedHalf::set_deadline(self.recv.as_ref(), deadline, apply_async_read_deadline::<R>)
    }

    fn close_read(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            match self.recv.enter_optional() {
                Ok(Some(active)) => active.half.close_read().await,
                Ok(None) => Ok(()),
                Err(err) if err.is_session_closed() => Ok(()),
                Err(err) => Err(err),
            }
        })
    }

    fn cancel_read(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let active = self.recv.enter(joined_read_half_missing_error)?;
            active.half.cancel_read(code).await
        })
    }
}

impl<R, W> AsyncSendStreamHandle for AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamHandle,
    W: AsyncSendStreamHandle,
{
    fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let active = self.send.enter(joined_write_half_missing_error)?;
            let n = active.half.write(src).await?;
            validate_write_progress(n, src.len())
        })
    }

    fn write_all<'a>(&'a self, payload: WritePayload<'a>) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let active = self.send.enter(joined_write_half_missing_error)?;
            active.half.write_all(payload).await
        })
    }

    fn write_all_timeout<'a>(
        &'a self,
        payload: WritePayload<'a>,
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let start = Instant::now();
            let active =
                self.send
                    .enter_timeout(timeout, "write", joined_write_half_missing_error)?;
            let remaining = remaining_write_timeout(start, timeout)?;
            active.half.write_all_timeout(payload, remaining).await
        })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let start = Instant::now();
            let active =
                self.send
                    .enter_timeout(timeout, "write", joined_write_half_missing_error)?;
            let remaining = remaining_write_timeout(start, timeout)?;
            let n = active.half.write_timeout(src, remaining).await?;
            validate_write_progress(n, src.len())
        })
    }

    fn write_vectored<'a>(&'a self, parts: &'a [IoSlice<'_>]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let requested = checked_vectored_len(parts)?;
            let active = self.send.enter(joined_write_half_missing_error)?;
            let n = active.half.write_vectored(parts).await?;
            validate_write_progress(n, requested)
        })
    }

    fn write_vectored_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let requested = checked_vectored_len(parts)?;
            let start = Instant::now();
            let active =
                self.send
                    .enter_timeout(timeout, "write", joined_write_half_missing_error)?;
            let remaining = remaining_write_timeout(start, timeout)?;
            let n = active.half.write_vectored_timeout(parts, remaining).await?;
            validate_write_progress(n, requested)
        })
    }

    fn write_final<'a>(&'a self, payload: WritePayload<'a>) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let requested = payload.checked_len()?;
            let active = self.send.enter(joined_write_half_missing_error)?;
            let n = active.half.write_final(payload).await?;
            validate_write_progress(n, requested)
        })
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: WritePayload<'a>,
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let requested = payload.checked_len()?;
            let start = Instant::now();
            let active =
                self.send
                    .enter_timeout(timeout, "write", joined_write_half_missing_error)?;
            let remaining = remaining_write_timeout(start, timeout)?;
            let n = active.half.write_final_timeout(payload, remaining).await?;
            validate_write_progress(n, requested)
        })
    }

    fn write_vectored_final<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let requested = checked_vectored_len(parts)?;
            let active = self.send.enter(joined_write_half_missing_error)?;
            let n = active.half.write_vectored_final(parts).await?;
            validate_write_progress(n, requested)
        })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let requested = checked_vectored_len(parts)?;
            let start = Instant::now();
            let active =
                self.send
                    .enter_timeout(timeout, "write", joined_write_half_missing_error)?;
            let remaining = remaining_write_timeout(start, timeout)?;
            let n = active
                .half
                .write_vectored_final_timeout(parts, remaining)
                .await?;
            validate_write_progress(n, requested)
        })
    }

    fn is_write_closed(&self) -> bool {
        self.send
            .with_current_or(true, |send| send.is_write_closed())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        AsyncJoinedHalf::set_deadline(
            self.send.as_ref(),
            deadline,
            apply_async_write_deadline::<W>,
        )
    }

    fn update_metadata(&self, update: MetadataUpdate) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let active = self.send.enter(joined_write_half_missing_error)?;
            active.half.update_metadata(update).await
        })
    }

    fn close_write(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            match self.send.enter_optional() {
                Ok(Some(active)) => active.half.close_write().await,
                Ok(None) => Ok(()),
                Err(err) if err.is_session_closed() => Ok(()),
                Err(err) => Err(err),
            }
        })
    }

    fn cancel_write(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let active = self.send.enter(joined_write_half_missing_error)?;
            active.half.cancel_write(code).await
        })
    }
}

impl<R, W> AsyncDuplexStreamHandle for AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamHandle,
    W: AsyncSendStreamHandle,
{
}

macro_rules! impl_async_stream_info_forward {
    ($target:ty) => {
        impl<T> AsyncStreamHandle for $target
        where
            T: AsyncStreamHandle + ?Sized,
        {
            fn stream_id(&self) -> u64 {
                (**self).stream_id()
            }

            fn is_opened_locally(&self) -> bool {
                (**self).is_opened_locally()
            }

            fn is_bidirectional(&self) -> bool {
                (**self).is_bidirectional()
            }

            fn open_info_len(&self) -> usize {
                (**self).open_info_len()
            }

            fn has_open_info(&self) -> bool {
                (**self).has_open_info()
            }

            fn append_open_info_to(&self, dst: &mut Vec<u8>) {
                (**self).append_open_info_to(dst)
            }

            fn open_info(&self) -> Vec<u8> {
                (**self).open_info()
            }

            fn metadata(&self) -> StreamMetadata {
                (**self).metadata()
            }

            fn local_addr(&self) -> Option<SocketAddr> {
                (**self).local_addr()
            }

            fn peer_addr(&self) -> Option<SocketAddr> {
                (**self).peer_addr()
            }

            fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_deadline(deadline)
            }

            fn close_identity(&self) -> *const () {
                (**self).close_identity()
            }

            fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
                (**self).close()
            }

            fn close_with_error<'a>(
                &'a self,
                code: u64,
                reason: &'a str,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                (**self).close_with_error(code, reason)
            }
        }
    };
}

impl_async_stream_info_forward!(&T);
impl_async_stream_info_forward!(&mut T);
impl_async_stream_info_forward!(Box<T>);
impl_async_stream_info_forward!(Arc<T>);

macro_rules! impl_async_recv_stream_api_forward {
    ($target:ty) => {
        impl<T> AsyncRecvStreamHandle for $target
        where
            T: AsyncRecvStreamHandle + ?Sized,
        {
            fn read<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).read(dst)
            }

            fn read_vectored<'a>(
                &'a self,
                dsts: &'a mut [IoSliceMut<'_>],
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).read_vectored(dsts)
            }

            fn read_timeout<'a>(
                &'a self,
                dst: &'a mut [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).read_timeout(dst, timeout)
            }

            fn read_vectored_timeout<'a>(
                &'a self,
                dsts: &'a mut [IoSliceMut<'_>],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).read_vectored_timeout(dsts, timeout)
            }

            fn read_exact<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<()>> {
                (**self).read_exact(dst)
            }

            fn read_exact_timeout<'a>(
                &'a self,
                dst: &'a mut [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                (**self).read_exact_timeout(dst, timeout)
            }

            fn is_read_closed(&self) -> bool {
                (**self).is_read_closed()
            }

            fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_read_deadline(deadline)
            }

            fn read_to_end<'a>(
                &'a self,
                dst: &'a mut Vec<u8>,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).read_to_end(dst)
            }

            fn read_to_end_limited(&self, max_bytes: usize) -> AsyncBoxFuture<'_, Result<Vec<u8>>> {
                (**self).read_to_end_limited(max_bytes)
            }

            fn close_read(&self) -> AsyncBoxFuture<'_, Result<()>> {
                (**self).close_read()
            }

            fn cancel_read(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
                (**self).cancel_read(code)
            }
        }
    };
}

impl_async_recv_stream_api_forward!(&T);
impl_async_recv_stream_api_forward!(&mut T);
impl_async_recv_stream_api_forward!(Box<T>);
impl_async_recv_stream_api_forward!(Arc<T>);

macro_rules! impl_async_send_stream_api_forward {
    ($target:ty) => {
        impl<T> AsyncSendStreamHandle for $target
        where
            T: AsyncSendStreamHandle + ?Sized,
        {
            fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write(src)
            }

            fn write_all<'a>(
                &'a self,
                payload: WritePayload<'a>,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                (**self).write_all(payload)
            }

            fn write_all_timeout<'a>(
                &'a self,
                payload: WritePayload<'a>,
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                (**self).write_all_timeout(payload, timeout)
            }

            fn write_timeout<'a>(
                &'a self,
                src: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_timeout(src, timeout)
            }

            fn write_vectored<'a>(
                &'a self,
                parts: &'a [IoSlice<'_>],
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_vectored(parts)
            }

            fn write_vectored_timeout<'a>(
                &'a self,
                parts: &'a [IoSlice<'_>],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_vectored_timeout(parts, timeout)
            }

            fn write_final<'a>(
                &'a self,
                payload: WritePayload<'a>,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_final(payload)
            }

            fn write_final_timeout<'a>(
                &'a self,
                payload: WritePayload<'a>,
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_final_timeout(payload, timeout)
            }

            fn write_vectored_final<'a>(
                &'a self,
                parts: &'a [IoSlice<'_>],
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_vectored_final(parts)
            }

            fn write_vectored_final_timeout<'a>(
                &'a self,
                parts: &'a [IoSlice<'_>],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_vectored_final_timeout(parts, timeout)
            }

            fn is_write_closed(&self) -> bool {
                (**self).is_write_closed()
            }

            fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_write_deadline(deadline)
            }

            fn update_metadata(&self, update: MetadataUpdate) -> AsyncBoxFuture<'_, Result<()>> {
                (**self).update_metadata(update)
            }

            fn close_write(&self) -> AsyncBoxFuture<'_, Result<()>> {
                (**self).close_write()
            }

            fn cancel_write(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
                (**self).cancel_write(code)
            }
        }
    };
}

impl_async_send_stream_api_forward!(&T);
impl_async_send_stream_api_forward!(&mut T);
impl_async_send_stream_api_forward!(Box<T>);
impl_async_send_stream_api_forward!(Arc<T>);

impl<T> AsyncDuplexStreamHandle for &T where T: AsyncDuplexStreamHandle + ?Sized {}
impl<T> AsyncDuplexStreamHandle for &mut T where T: AsyncDuplexStreamHandle + ?Sized {}
impl<T> AsyncDuplexStreamHandle for Box<T> where T: AsyncDuplexStreamHandle + ?Sized {}
impl<T> AsyncDuplexStreamHandle for Arc<T> where T: AsyncDuplexStreamHandle + ?Sized {}

macro_rules! impl_async_session_forward {
    ($target:ty) => {
        impl<T> AsyncSession for $target
        where
            T: AsyncSession + ?Sized,
        {
            type Stream = T::Stream;
            type SendStream = T::SendStream;
            type RecvStream = T::RecvStream;

            fn accept_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
                AsyncSession::accept_stream(&**self)
            }

            fn accept_stream_timeout(
                &self,
                timeout: Duration,
            ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
                AsyncSession::accept_stream_timeout(&**self, timeout)
            }

            fn accept_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
                AsyncSession::accept_uni_stream(&**self)
            }

            fn accept_uni_stream_timeout(
                &self,
                timeout: Duration,
            ) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
                AsyncSession::accept_uni_stream_timeout(&**self, timeout)
            }

            fn open_stream_with(
                &self,
                request: OpenRequest,
            ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
                AsyncSession::open_stream_with(&**self, request)
            }

            fn open_uni_stream_with(
                &self,
                request: OpenRequest,
            ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
                AsyncSession::open_uni_stream_with(&**self, request)
            }

            fn open_and_send<'a>(
                &'a self,
                request: OpenSend<'a>,
            ) -> AsyncBoxFuture<'a, Result<Self::Stream>> {
                AsyncSession::open_and_send(&**self, request)
            }

            fn open_uni_and_send<'a>(
                &'a self,
                request: OpenSend<'a>,
            ) -> AsyncBoxFuture<'a, Result<Self::SendStream>> {
                AsyncSession::open_uni_and_send(&**self, request)
            }

            fn ping<'a>(&'a self, echo: &'a [u8]) -> AsyncBoxFuture<'a, Result<Duration>> {
                AsyncSession::ping(&**self, echo)
            }

            fn ping_timeout<'a>(
                &'a self,
                echo: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<Duration>> {
                AsyncSession::ping_timeout(&**self, echo, timeout)
            }

            fn go_away(
                &self,
                last_accepted_bidi: u64,
                last_accepted_uni: u64,
            ) -> AsyncBoxFuture<'_, Result<()>> {
                AsyncSession::go_away(&**self, last_accepted_bidi, last_accepted_uni)
            }

            fn go_away_with_error<'a>(
                &'a self,
                last_accepted_bidi: u64,
                last_accepted_uni: u64,
                code: u64,
                reason: &'a str,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                AsyncSession::go_away_with_error(
                    &**self,
                    last_accepted_bidi,
                    last_accepted_uni,
                    code,
                    reason,
                )
            }

            fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
                AsyncSession::close(&**self)
            }

            fn close_with_error<'a>(
                &'a self,
                code: u64,
                reason: &'a str,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                AsyncSession::close_with_error(&**self, code, reason)
            }

            fn wait(&self) -> AsyncBoxFuture<'_, Result<()>> {
                AsyncSession::wait(&**self)
            }

            fn wait_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<bool>> {
                AsyncSession::wait_timeout(&**self, timeout)
            }

            fn is_closed(&self) -> bool {
                AsyncSession::is_closed(&**self)
            }

            fn local_addr(&self) -> Option<SocketAddr> {
                AsyncSession::local_addr(&**self)
            }

            fn peer_addr(&self) -> Option<SocketAddr> {
                AsyncSession::peer_addr(&**self)
            }

            fn close_error(&self) -> Option<Error> {
                AsyncSession::close_error(&**self)
            }

            fn state(&self) -> SessionState {
                AsyncSession::state(&**self)
            }

            fn stats(&self) -> SessionStats {
                AsyncSession::stats(&**self)
            }

            fn peer_go_away_error(&self) -> Option<PeerGoAwayError> {
                AsyncSession::peer_go_away_error(&**self)
            }

            fn peer_close_error(&self) -> Option<PeerCloseError> {
                AsyncSession::peer_close_error(&**self)
            }

            fn local_preface(&self) -> Preface {
                AsyncSession::local_preface(&**self)
            }

            fn peer_preface(&self) -> Preface {
                AsyncSession::peer_preface(&**self)
            }

            fn negotiated(&self) -> Negotiated {
                AsyncSession::negotiated(&**self)
            }
        }
    };
}

impl_async_session_forward!(&T);
impl_async_session_forward!(&mut T);
impl_async_session_forward!(Box<T>);
impl_async_session_forward!(Arc<T>);

impl<S> AsyncSession for BoxedAsyncSession<S>
where
    S: AsyncSession + 'static,
{
    type Stream = BoxAsyncDuplexStream;
    type SendStream = BoxAsyncSendStream;
    type RecvStream = BoxAsyncRecvStream;

    fn accept_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.accept_stream().await?;
            Ok(Box::new(stream) as BoxAsyncDuplexStream)
        })
    }

    fn accept_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.accept_stream_timeout(timeout).await?;
            Ok(Box::new(stream) as BoxAsyncDuplexStream)
        })
    }

    fn accept_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
        Box::pin(async move {
            let stream = self.inner.accept_uni_stream().await?;
            Ok(Box::new(stream) as BoxAsyncRecvStream)
        })
    }

    fn accept_uni_stream_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
        Box::pin(async move {
            let stream = self.inner.accept_uni_stream_timeout(timeout).await?;
            Ok(Box::new(stream) as BoxAsyncRecvStream)
        })
    }

    fn open_stream_with(&self, request: OpenRequest) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.open_stream_with(request).await?;
            Ok(Box::new(stream) as BoxAsyncDuplexStream)
        })
    }

    fn open_uni_stream_with(
        &self,
        request: OpenRequest,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move {
            let stream = self.inner.open_uni_stream_with(request).await?;
            Ok(Box::new(stream) as BoxAsyncSendStream)
        })
    }

    fn open_and_send<'a>(
        &'a self,
        request: OpenSend<'a>,
    ) -> AsyncBoxFuture<'a, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.open_and_send(request).await?;
            Ok(Box::new(stream) as BoxAsyncDuplexStream)
        })
    }

    fn open_uni_and_send<'a>(
        &'a self,
        request: OpenSend<'a>,
    ) -> AsyncBoxFuture<'a, Result<Self::SendStream>> {
        Box::pin(async move {
            let stream = self.inner.open_uni_and_send(request).await?;
            Ok(Box::new(stream) as BoxAsyncSendStream)
        })
    }

    fn ping<'a>(&'a self, echo: &'a [u8]) -> AsyncBoxFuture<'a, Result<Duration>> {
        self.inner.ping(echo)
    }

    fn ping_timeout<'a>(
        &'a self,
        echo: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<Duration>> {
        self.inner.ping_timeout(echo, timeout)
    }

    fn go_away(
        &self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
    ) -> AsyncBoxFuture<'_, Result<()>> {
        self.inner.go_away(last_accepted_bidi, last_accepted_uni)
    }

    fn go_away_with_error<'a>(
        &'a self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        self.inner
            .go_away_with_error(last_accepted_bidi, last_accepted_uni, code, reason)
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        self.inner.close()
    }

    fn close_with_error<'a>(
        &'a self,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        self.inner.close_with_error(code, reason)
    }

    fn wait(&self) -> AsyncBoxFuture<'_, Result<()>> {
        self.inner.wait()
    }

    fn wait_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<bool>> {
        self.inner.wait_timeout(timeout)
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }

    fn close_error(&self) -> Option<Error> {
        self.inner.close_error()
    }

    fn state(&self) -> SessionState {
        self.inner.state()
    }

    fn stats(&self) -> SessionStats {
        self.inner.stats()
    }

    fn peer_go_away_error(&self) -> Option<PeerGoAwayError> {
        self.inner.peer_go_away_error()
    }

    fn peer_close_error(&self) -> Option<PeerCloseError> {
        self.inner.peer_close_error()
    }

    fn local_preface(&self) -> Preface {
        self.inner.local_preface()
    }

    fn peer_preface(&self) -> Preface {
        self.inner.peer_preface()
    }

    fn negotiated(&self) -> Negotiated {
        self.inner.negotiated()
    }
}

macro_rules! impl_native_async_stream_info {
    ($ty:ty) => {
        impl AsyncStreamHandle for $ty {
            fn stream_id(&self) -> u64 {
                <$ty>::stream_id(self)
            }

            fn is_opened_locally(&self) -> bool {
                <$ty>::is_opened_locally(self)
            }

            fn is_bidirectional(&self) -> bool {
                <$ty>::is_bidirectional(self)
            }

            fn open_info_len(&self) -> usize {
                <$ty>::open_info_len(self)
            }

            fn has_open_info(&self) -> bool {
                <$ty>::has_open_info(self)
            }

            fn append_open_info_to(&self, dst: &mut Vec<u8>) {
                <$ty>::append_open_info_to(self, dst)
            }

            fn open_info(&self) -> Vec<u8> {
                <$ty>::open_info(self)
            }

            fn metadata(&self) -> StreamMetadata {
                <$ty>::metadata(self)
            }

            fn local_addr(&self) -> Option<SocketAddr> {
                <$ty>::local_addr(self)
            }

            fn peer_addr(&self) -> Option<SocketAddr> {
                <$ty>::peer_addr(self)
            }

            fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                <$ty>::set_deadline(self, deadline)
            }

            fn close_identity(&self) -> *const () {
                <$ty>::close_identity(self)
            }

            fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
                Box::pin(async move { <$ty>::close(self) })
            }

            fn close_with_error<'a>(
                &'a self,
                code: u64,
                reason: &'a str,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                Box::pin(async move { <$ty>::close_with_error(self, code, reason) })
            }
        }
    };
}

impl_native_async_stream_info!(Stream);
impl_native_async_stream_info!(SendStream);
impl_native_async_stream_info!(RecvStream);

macro_rules! impl_native_async_recv {
    ($ty:ty) => {
        impl AsyncRecvStreamHandle for $ty {
            fn read<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::read(self, dst) })
            }

            fn read_vectored<'a>(
                &'a self,
                dsts: &'a mut [IoSliceMut<'_>],
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::read_vectored(self, dsts) })
            }

            fn read_timeout<'a>(
                &'a self,
                dst: &'a mut [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::read_timeout(self, dst, timeout) })
            }

            fn read_vectored_timeout<'a>(
                &'a self,
                dsts: &'a mut [IoSliceMut<'_>],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::read_vectored_timeout(self, dsts, timeout) })
            }

            fn read_exact<'a>(&'a self, dst: &'a mut [u8]) -> AsyncBoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    let mut remaining = dst;
                    while !remaining.is_empty() {
                        let n =
                            validate_read_progress(<$ty>::read(self, remaining)?, remaining.len())?;
                        if n == 0 {
                            return Err(unexpected_eof_error());
                        }
                        let (_, rest) = remaining.split_at_mut(n);
                        remaining = rest;
                    }
                    Ok(())
                })
            }

            fn read_exact_timeout<'a>(
                &'a self,
                dst: &'a mut [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                Box::pin(async move { <$ty>::read_exact_timeout(self, dst, timeout) })
            }

            fn is_read_closed(&self) -> bool {
                <$ty>::is_read_closed(self)
            }

            fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                <$ty>::set_read_deadline(self, deadline)
            }

            fn close_read(&self) -> AsyncBoxFuture<'_, Result<()>> {
                Box::pin(async move { <$ty>::close_read(self) })
            }

            fn cancel_read(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
                Box::pin(async move { <$ty>::cancel_read(self, code) })
            }
        }
    };
}

impl_native_async_recv!(Stream);
impl_native_async_recv!(RecvStream);

macro_rules! impl_native_async_send {
    ($ty:ty) => {
        impl AsyncSendStreamHandle for $ty {
            fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write(self, src) })
            }

            fn write_all<'a>(
                &'a self,
                payload: WritePayload<'a>,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                Box::pin(async move { <$ty>::write_all(self, payload) })
            }

            fn write_all_timeout<'a>(
                &'a self,
                payload: WritePayload<'a>,
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<()>> {
                Box::pin(async move { <$ty>::write_all_timeout(self, payload, timeout) })
            }

            fn write_timeout<'a>(
                &'a self,
                src: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_timeout(self, src, timeout) })
            }

            fn write_vectored<'a>(
                &'a self,
                parts: &'a [IoSlice<'_>],
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_vectored(self, parts) })
            }

            fn write_vectored_timeout<'a>(
                &'a self,
                parts: &'a [IoSlice<'_>],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_vectored_timeout(self, parts, timeout) })
            }

            fn write_final<'a>(
                &'a self,
                payload: WritePayload<'a>,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_final(self, payload) })
            }

            fn write_final_timeout<'a>(
                &'a self,
                payload: WritePayload<'a>,
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_final_timeout(self, payload, timeout) })
            }

            fn write_vectored_final<'a>(
                &'a self,
                parts: &'a [IoSlice<'_>],
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_vectored_final(self, parts) })
            }

            fn write_vectored_final_timeout<'a>(
                &'a self,
                parts: &'a [IoSlice<'_>],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_vectored_final_timeout(self, parts, timeout) })
            }

            fn is_write_closed(&self) -> bool {
                <$ty>::is_write_closed(self)
            }

            fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                <$ty>::set_write_deadline(self, deadline)
            }

            fn update_metadata(&self, update: MetadataUpdate) -> AsyncBoxFuture<'_, Result<()>> {
                Box::pin(async move { <$ty>::update_metadata(self, update) })
            }

            fn close_write(&self) -> AsyncBoxFuture<'_, Result<()>> {
                Box::pin(async move { <$ty>::close_write(self) })
            }

            fn cancel_write(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>> {
                Box::pin(async move { <$ty>::cancel_write(self, code) })
            }
        }
    };
}

impl_native_async_send!(Stream);
impl_native_async_send!(SendStream);

impl AsyncDuplexStreamHandle for Stream {}

impl AsyncSession for Conn {
    type Stream = Stream;
    type SendStream = SendStream;
    type RecvStream = RecvStream;

    fn accept_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { Conn::accept_stream(self) })
    }

    fn accept_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { Conn::accept_stream_timeout(self, timeout) })
    }

    fn accept_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
        Box::pin(async move { Conn::accept_uni_stream(self) })
    }

    fn accept_uni_stream_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
        Box::pin(async move { Conn::accept_uni_stream_timeout(self, timeout) })
    }

    fn open_stream_with(&self, request: OpenRequest) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { Conn::open_stream_with(self, request) })
    }

    fn open_uni_stream_with(
        &self,
        request: OpenRequest,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move { Conn::open_uni_stream_with(self, request) })
    }

    fn open_and_send<'a>(
        &'a self,
        request: OpenSend<'a>,
    ) -> AsyncBoxFuture<'a, Result<Self::Stream>> {
        Box::pin(async move { Conn::open_and_send(self, request) })
    }

    fn open_uni_and_send<'a>(
        &'a self,
        request: OpenSend<'a>,
    ) -> AsyncBoxFuture<'a, Result<Self::SendStream>> {
        Box::pin(async move { Conn::open_uni_and_send(self, request) })
    }

    fn ping<'a>(&'a self, echo: &'a [u8]) -> AsyncBoxFuture<'a, Result<Duration>> {
        Box::pin(async move { Conn::ping(self, echo) })
    }

    fn ping_timeout<'a>(
        &'a self,
        echo: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<Duration>> {
        Box::pin(async move { Conn::ping_timeout(self, echo, timeout) })
    }

    fn go_away(
        &self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
    ) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { Conn::go_away(self, last_accepted_bidi, last_accepted_uni) })
    }

    fn go_away_with_error<'a>(
        &'a self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            Conn::go_away_with_error(self, last_accepted_bidi, last_accepted_uni, code, reason)
        })
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { Conn::close(self) })
    }

    fn close_with_error<'a>(
        &'a self,
        code: u64,
        reason: &'a str,
    ) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move { Conn::close_with_error(self, code, reason) })
    }

    fn wait(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move { Conn::wait(self) })
    }

    fn wait_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<bool>> {
        Box::pin(async move { Conn::wait_timeout(self, timeout) })
    }

    fn is_closed(&self) -> bool {
        Conn::is_closed(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Conn::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Conn::peer_addr(self)
    }

    fn close_error(&self) -> Option<Error> {
        Conn::close_error(self)
    }

    fn state(&self) -> SessionState {
        Conn::state(self)
    }

    fn stats(&self) -> SessionStats {
        Conn::stats(self)
    }

    fn peer_go_away_error(&self) -> Option<PeerGoAwayError> {
        Conn::peer_go_away_error(self)
    }

    fn peer_close_error(&self) -> Option<PeerCloseError> {
        Conn::peer_close_error(self)
    }

    fn local_preface(&self) -> Preface {
        Conn::local_preface(self)
    }

    fn peer_preface(&self) -> Preface {
        Conn::peer_preface(self)
    }

    fn negotiated(&self) -> Negotiated {
        Conn::negotiated(self)
    }
}

fn checked_vectored_len(parts: &[IoSlice<'_>]) -> Result<usize> {
    parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or_else(vectored_len_overflow_error)
    })
}

fn checked_vectored_read_len(parts: &[IoSliceMut<'_>]) -> Result<usize> {
    parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or_else(vectored_read_len_overflow_error)
    })
}

fn zero_length_write_error() -> Error {
    Error::local("zmux: zero-length write")
        .with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
}

fn validate_read_progress(n: usize, requested: usize) -> Result<usize> {
    if n > requested {
        Err(invalid_read_progress_error())
    } else {
        Ok(n)
    }
}

fn validate_write_progress(n: usize, requested: usize) -> Result<usize> {
    if n > requested {
        Err(invalid_write_progress_error())
    } else {
        Ok(n)
    }
}

fn invalid_read_progress_error() -> Error {
    Error::local("zmux: read reported invalid progress")
        .with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
}

fn unexpected_eof_error() -> Error {
    Error::io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "failed to fill whole buffer",
    ))
    .with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
}

fn invalid_write_progress_error() -> Error {
    Error::local("zmux: write reported invalid progress")
        .with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
}

fn deadline_unsupported_error() -> Error {
    Error::local("zmux: stream deadlines are not supported by this implementation")
        .with_stream_context(ErrorOperation::Unknown, ErrorDirection::Both)
}

fn read_limit_exceeded_error(max_bytes: usize) -> Error {
    Error::new(
        crate::ErrorCode::FrameSize,
        format!("zmux: read limit exceeded ({max_bytes} bytes)"),
    )
    .with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
}

fn vectored_len_overflow_error() -> Error {
    Error::local("zmux: vectored write length overflow")
        .with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
}

fn vectored_read_len_overflow_error() -> Error {
    Error::local("zmux: vectored read length overflow")
        .with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
}
