use crate::api::DuplexInfoSide;
use crate::config::OpenOptions;
use crate::error::{Error, ErrorDirection, ErrorOperation, Result};
use crate::payload::{MetadataUpdate, StreamMetadata};
use crate::session::{Conn, RecvStream, SendStream, SessionState, SessionStats, Stream};
use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem;
use std::net::SocketAddr;
use std::pin::Pin;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Boxed future used by the async session and stream traits.
pub type AsyncBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Boxed bidirectional async stream trait object.
pub type BoxAsyncStream = Box<dyn AsyncStreamApi>;

/// Boxed send-only async stream trait object.
pub type BoxAsyncSendStream = Box<dyn AsyncSendStreamApi>;

/// Boxed receive-only async stream trait object.
pub type BoxAsyncRecvStream = Box<dyn AsyncRecvStreamApi>;

/// Boxed async session trait object.
pub type BoxAsyncSession = Box<
    dyn AsyncSession<
        Stream = BoxAsyncStream,
        SendStream = BoxAsyncSendStream,
        RecvStream = BoxAsyncRecvStream,
    >,
>;

/// Wrap an async session and erase its concrete stream types.
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
pub struct ClosedSession;

/// Create a permanently closed async session.
pub fn closed_session() -> ClosedSession {
    ClosedSession
}

/// Create a boxed permanently closed async session.
pub fn boxed_closed_session() -> BoxAsyncSession {
    Box::new(ClosedSession)
}

/// Adapter that turns any `AsyncSession` into a boxed common async session.
pub struct BoxedAsyncSession<S> {
    inner: S,
}

impl<S> BoxedAsyncSession<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Runtime-neutral stream metadata and close operations for async upper layers.
pub trait AsyncStreamInfo: Send + Sync {
    fn stream_id(&self) -> u64;
    fn opened_locally(&self) -> bool;
    fn bidirectional(&self) -> bool;
    fn open_info_len(&self) -> usize;
    fn has_open_info(&self) -> bool {
        self.open_info_len() != 0
    }
    fn copy_open_info_to(&self, dst: &mut Vec<u8>);
    fn open_info(&self) -> Vec<u8> {
        let mut open_info = Vec::with_capacity(self.open_info_len());
        self.copy_open_info_to(&mut open_info);
        open_info
    }
    fn metadata(&self) -> StreamMetadata;
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr()
    }
    fn set_deadline(&self, _deadline: Option<Instant>) -> Result<()> {
        Err(deadline_unsupported_error())
    }
    fn clear_deadline(&self) -> Result<()> {
        self.set_deadline(None)
    }
    fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }
    /// Stable resource identity used to avoid closing the same joined full
    /// stream twice.
    fn close_identity(&self) -> *const () {
        if mem::size_of_val(self) == 0 {
            ptr::null()
        } else {
            ptr::from_ref(self).cast::<()>()
        }
    }
    fn close(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn close_with_error<'a>(&'a self, code: u64, reason: &'a str)
        -> AsyncBoxFuture<'a, Result<()>>;
}

/// Runtime-neutral receive stream operations.
pub trait AsyncRecvStreamApi: AsyncStreamInfo {
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
    fn readv<'a>(&'a self, dsts: &'a mut [IoSliceMut<'_>]) -> AsyncBoxFuture<'a, Result<usize>> {
        self.read_vectored(dsts)
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
    fn readv_timeout<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        self.read_vectored_timeout(dsts, timeout)
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
    fn read_closed(&self) -> bool;
    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.set_deadline(deadline)
    }
    fn clear_read_deadline(&self) -> Result<()> {
        self.set_read_deadline(None)
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
                out.extend_from_slice(&buf[..n]);
            }
        })
    }
    fn close_read(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn cancel_read(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>>;
}

/// Runtime-neutral send stream operations.
pub trait AsyncSendStreamApi: AsyncStreamInfo {
    fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>>;

    fn write_all<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut remaining = src;
            while !remaining.is_empty() {
                let n = validate_write_progress(self.write(remaining).await?, remaining.len())?;
                if n == 0 {
                    return Err(zero_length_write_error());
                }
                remaining = &remaining[n..];
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
            match parts.iter().find(|part| !part.is_empty()) {
                Some(part) => {
                    let n = self.write(part).await?;
                    validate_write_progress(n, part.len())
                }
                None => Ok(0),
            }
        })
    }

    fn writev<'a>(&'a self, parts: &'a [IoSlice<'_>]) -> AsyncBoxFuture<'a, Result<usize>> {
        self.write_vectored(parts)
    }

    fn write_vectored_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            match parts.iter().find(|part| !part.is_empty()) {
                Some(part) => {
                    let n = self.write_timeout(part, timeout).await?;
                    validate_write_progress(n, part.len())
                }
                None => Ok(0),
            }
        })
    }

    fn writev_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        self.write_vectored_timeout(parts, timeout)
    }

    fn write_final<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            self.write_all(src).await?;
            self.close_write().await?;
            Ok(src.len())
        })
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>>;

    fn write_vectored_final<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let total = checked_vectored_len(parts)?;
            for part in parts.iter().filter(|part| !part.is_empty()) {
                self.write_all(part).await?;
            }
            self.close_write().await?;
            Ok(total)
        })
    }

    fn writev_final<'a>(&'a self, parts: &'a [IoSlice<'_>]) -> AsyncBoxFuture<'a, Result<usize>> {
        self.write_vectored_final(parts)
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>>;

    fn writev_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        self.write_vectored_final_timeout(parts, timeout)
    }

    fn write_closed(&self) -> bool;
    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.set_deadline(deadline)
    }
    fn clear_write_deadline(&self) -> Result<()> {
        self.set_write_deadline(None)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_write_deadline(timeout_to_deadline(timeout))
    }
    fn update_metadata(&self, update: MetadataUpdate) -> AsyncBoxFuture<'_, Result<()>>;
    fn close_write(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn cancel_write(&self, code: u64) -> AsyncBoxFuture<'_, Result<()>>;
}

/// Runtime-neutral bidirectional async stream operations.
pub trait AsyncStreamApi: AsyncRecvStreamApi + AsyncSendStreamApi {}

/// Runtime-neutral async session operations shared by native ZMux and adapters.
pub trait AsyncSession: Send + Sync {
    type Stream: AsyncStreamApi + Send + Sync + 'static;
    type SendStream: AsyncSendStreamApi + Send + Sync + 'static;
    type RecvStream: AsyncRecvStreamApi + Send + Sync + 'static;

    fn accept_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn accept_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn accept_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::RecvStream>>;
    fn accept_uni_stream_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::RecvStream>>;
    fn open_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn open_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn open_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::SendStream>>;
    fn open_uni_stream_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>>;
    fn open_stream_with_options(
        &self,
        opts: OpenOptions,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn open_stream_with_options_timeout(
        &self,
        opts: OpenOptions,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>>;
    fn open_uni_stream_with_options(
        &self,
        opts: OpenOptions,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>>;
    fn open_uni_stream_with_options_timeout(
        &self,
        opts: OpenOptions,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>>;

    fn open_and_send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            let stream = self.open_stream().await?;
            if data.is_empty() {
                return Ok((stream, 0));
            }
            let n = validate_write_progress(stream.write(data).await?, data.len())?;
            Ok((stream, n))
        })
    }

    fn open_and_send_timeout<'a>(
        &'a self,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            ensure_positive_open_timeout(timeout)?;
            let start = Instant::now();
            let stream = self.open_stream_timeout(timeout).await?;
            if data.is_empty() {
                return Ok((stream, 0));
            }
            let timeout = remaining_write_timeout(start, timeout)?;
            let n =
                validate_write_progress(stream.write_timeout(data, timeout).await?, data.len())?;
            Ok((stream, n))
        })
    }

    fn open_and_send_with_options<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            let stream = self.open_stream_with_options(opts).await?;
            if data.is_empty() {
                return Ok((stream, 0));
            }
            let n = validate_write_progress(stream.write(data).await?, data.len())?;
            Ok((stream, n))
        })
    }

    fn open_and_send_with_options_timeout<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            ensure_positive_open_timeout(timeout)?;
            let start = Instant::now();
            let stream = self.open_stream_with_options_timeout(opts, timeout).await?;
            if data.is_empty() {
                return Ok((stream, 0));
            }
            let timeout = remaining_write_timeout(start, timeout)?;
            let n =
                validate_write_progress(stream.write_timeout(data, timeout).await?, data.len())?;
            Ok((stream, n))
        })
    }

    fn open_and_send_vectored<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            let requested = checked_vectored_len(parts)?;
            let stream = self.open_stream().await?;
            if requested == 0 {
                return Ok((stream, 0));
            }
            let n = validate_write_progress(stream.write_vectored(parts).await?, requested)?;
            Ok((stream, n))
        })
    }

    fn open_and_send_vectored_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            ensure_positive_open_timeout(timeout)?;
            let requested = checked_vectored_len(parts)?;
            let start = Instant::now();
            let stream = self.open_stream_timeout(timeout).await?;
            if requested == 0 {
                return Ok((stream, 0));
            }
            let timeout = remaining_write_timeout(start, timeout)?;
            let n = validate_write_progress(
                stream.write_vectored_timeout(parts, timeout).await?,
                requested,
            )?;
            Ok((stream, n))
        })
    }

    fn open_and_send_vectored_with_options<'a>(
        &'a self,
        opts: OpenOptions,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            let requested = checked_vectored_len(parts)?;
            let stream = self.open_stream_with_options(opts).await?;
            if requested == 0 {
                return Ok((stream, 0));
            }
            let n = validate_write_progress(stream.write_vectored(parts).await?, requested)?;
            Ok((stream, n))
        })
    }

    fn open_and_send_vectored_with_options_timeout<'a>(
        &'a self,
        opts: OpenOptions,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            ensure_positive_open_timeout(timeout)?;
            let requested = checked_vectored_len(parts)?;
            let start = Instant::now();
            let stream = self.open_stream_with_options_timeout(opts, timeout).await?;
            if requested == 0 {
                return Ok((stream, 0));
            }
            let timeout = remaining_write_timeout(start, timeout)?;
            let n = validate_write_progress(
                stream.write_vectored_timeout(parts, timeout).await?,
                requested,
            )?;
            Ok((stream, n))
        })
    }

    fn open_uni_and_send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            let stream = self.open_uni_stream().await?;
            let n = validate_write_progress(stream.write_final(data).await?, data.len())?;
            Ok((stream, n))
        })
    }

    fn open_uni_and_send_timeout<'a>(
        &'a self,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            ensure_positive_open_timeout(timeout)?;
            let start = Instant::now();
            let stream = self.open_uni_stream_timeout(timeout).await?;
            let timeout = remaining_write_timeout(start, timeout)?;
            let n = validate_write_progress(
                stream.write_final_timeout(data, timeout).await?,
                data.len(),
            )?;
            Ok((stream, n))
        })
    }

    fn open_uni_and_send_with_options<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            let stream = self.open_uni_stream_with_options(opts).await?;
            let n = validate_write_progress(stream.write_final(data).await?, data.len())?;
            Ok((stream, n))
        })
    }

    fn open_uni_and_send_with_options_timeout<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            ensure_positive_open_timeout(timeout)?;
            let start = Instant::now();
            let stream = self
                .open_uni_stream_with_options_timeout(opts, timeout)
                .await?;
            let timeout = remaining_write_timeout(start, timeout)?;
            let n = validate_write_progress(
                stream.write_final_timeout(data, timeout).await?,
                data.len(),
            )?;
            Ok((stream, n))
        })
    }

    fn open_uni_and_send_vectored<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            let requested = checked_vectored_len(parts)?;
            let stream = self.open_uni_stream().await?;
            let n = validate_write_progress(stream.write_vectored_final(parts).await?, requested)?;
            Ok((stream, n))
        })
    }

    fn open_uni_and_send_vectored_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            ensure_positive_open_timeout(timeout)?;
            let requested = checked_vectored_len(parts)?;
            let start = Instant::now();
            let stream = self.open_uni_stream_timeout(timeout).await?;
            let timeout = remaining_write_timeout(start, timeout)?;
            let n = validate_write_progress(
                stream.write_vectored_final_timeout(parts, timeout).await?,
                requested,
            )?;
            Ok((stream, n))
        })
    }

    fn open_uni_and_send_vectored_with_options<'a>(
        &'a self,
        opts: OpenOptions,
        parts: &'a [IoSlice<'_>],
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            let requested = checked_vectored_len(parts)?;
            let stream = self.open_uni_stream_with_options(opts).await?;
            let n = validate_write_progress(stream.write_vectored_final(parts).await?, requested)?;
            Ok((stream, n))
        })
    }

    fn open_uni_and_send_vectored_with_options_timeout<'a>(
        &'a self,
        opts: OpenOptions,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            ensure_positive_open_timeout(timeout)?;
            let requested = checked_vectored_len(parts)?;
            let start = Instant::now();
            let stream = self
                .open_uni_stream_with_options_timeout(opts, timeout)
                .await?;
            let timeout = remaining_write_timeout(start, timeout)?;
            let n = validate_write_progress(
                stream.write_vectored_final_timeout(parts, timeout).await?,
                requested,
            )?;
            Ok((stream, n))
        })
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn close_with_error<'a>(&'a self, code: u64, reason: &'a str)
        -> AsyncBoxFuture<'a, Result<()>>;
    fn wait(&self) -> AsyncBoxFuture<'_, Result<()>>;
    fn wait_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<bool>>;
    fn wait_close_error(&self) -> AsyncBoxFuture<'_, Result<Option<Error>>> {
        Box::pin(async move {
            self.wait().await?;
            Ok(self.close_error())
        })
    }
    fn wait_close_error_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Option<Error>>> {
        Box::pin(async move {
            if !self.wait_timeout(timeout).await? {
                return Err(Error::timeout("session termination")
                    .with_session_context(ErrorOperation::Close));
            }
            Ok(self.close_error())
        })
    }
    fn closed(&self) -> bool;
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr()
    }
    fn close_error(&self) -> Option<Error>;
    fn state(&self) -> SessionState;
    fn stats(&self) -> SessionStats;
}

fn closed_async_session_error(operation: ErrorOperation) -> Error {
    Error::session_closed().with_session_context(operation)
}

fn closed_async_session_result<T>(operation: ErrorOperation) -> AsyncBoxFuture<'static, Result<T>> {
    Box::pin(async move { Err(closed_async_session_error(operation)) })
}

impl AsyncSession for ClosedSession {
    type Stream = BoxAsyncStream;
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

    fn open_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn open_stream_timeout(&self, _timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn open_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn open_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn open_stream_with_options(
        &self,
        _opts: OpenOptions,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn open_stream_with_options_timeout(
        &self,
        _opts: OpenOptions,
        _timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn open_uni_stream_with_options(
        &self,
        _opts: OpenOptions,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        closed_async_session_result(ErrorOperation::Open)
    }

    fn open_uni_stream_with_options_timeout(
        &self,
        _opts: OpenOptions,
        _timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        closed_async_session_result(ErrorOperation::Open)
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

    fn closed(&self) -> bool {
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

pub fn join_async_streams<R, W>(recv: R, send: W) -> AsyncDuplexStream<R, W> {
    AsyncDuplexStream::new(recv, send)
}

pub fn join_optional_streams<R, W>(recv: Option<R>, send: Option<W>) -> AsyncDuplexStream<R, W> {
    AsyncDuplexStream::from_parts(recv, send)
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
        match self.current() {
            Some(current) => visit(&current),
            None => default,
        }
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
            let (next, wait) = self.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if wait.timed_out() && state.paused {
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
        self.changed.notify_all();
        current
    }

    fn leave(&self) {
        let mut state = self.state.lock().unwrap();
        if state.active_ops > 0 {
            state.active_ops -= 1;
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
            state.deadline_generation = state.deadline_generation.wrapping_add(1);
            state.deadline_applier = Some(applier);
            self.changed.notify_all();
            match state.current.clone() {
                Some(current) => {
                    state.active_ops += 1;
                    Some(current)
                }
                None => None,
            }
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
        self.changed.notify_all();
        result.map(|_| Some(generation))
    }

    fn apply_deadline_to_candidate(&self, current: &T) -> Result<Option<u64>> {
        let Some((deadline, generation, applier)) = self.deadline_snapshot() else {
            return Ok(None);
        };
        applier(current, deadline)?;
        let mut state = self.state.lock().unwrap();
        if state.deadline_generation == generation {
            state.deadline_applied_generation = generation;
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
                let (state, wait) = self.changed.wait_timeout(state, remaining).unwrap();
                if wait.timed_out() && state.paused {
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
    pub fn current(&self) -> Option<Arc<T>> {
        self.current.clone()
    }

    pub fn take(&mut self) -> Option<Arc<T>> {
        self.current.take()
    }

    pub fn set(&mut self, next: Option<T>) -> Option<Arc<T>> {
        self.set_arc(next.map(Arc::new))
    }

    pub fn set_arc(&mut self, next: Option<Arc<T>>) -> Option<Arc<T>> {
        mem::replace(&mut self.current, next)
    }

    pub fn replace(&mut self, next: T) -> Option<Arc<T>> {
        self.set(Some(next))
    }

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
        .filter(|d| !d.is_zero())
}

fn timeout_to_deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|timeout| Instant::now().checked_add(timeout))
}

fn deadline_remaining(deadline: Option<Instant>) -> Option<Duration> {
    deadline.and_then(|deadline| {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
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
            let (state, wait) = changed.wait_timeout(state, remaining).unwrap();
            if wait.timed_out() {
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

fn apply_async_read_deadline<T: AsyncRecvStreamApi>(
    stream: &T,
    deadline: Option<Instant>,
) -> Result<()> {
    stream.set_read_deadline(deadline)
}

fn apply_async_write_deadline<T: AsyncSendStreamApi>(
    stream: &T,
    deadline: Option<Instant>,
) -> Result<()> {
    stream.set_write_deadline(deadline)
}

impl<R, W> AsyncDuplexStream<R, W> {
    pub fn new(recv: R, send: W) -> Self {
        Self::from_parts(Some(recv), Some(send))
    }

    pub fn from_parts(recv: Option<R>, send: Option<W>) -> Self {
        Self {
            recv: Arc::new(AsyncJoinedHalf::new_optional(recv, "read")),
            send: Arc::new(AsyncJoinedHalf::new_optional(send, "write")),
            info_side: DuplexInfoSide::Read,
        }
    }

    pub fn empty() -> Self {
        Self::from_parts(None, None)
    }

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
    R: AsyncRecvStreamApi,
    W: AsyncSendStreamApi,
{
    pub fn read_stream_id(&self) -> u64 {
        self.recv.with_current_or(0, |recv| recv.stream_id())
    }

    pub fn write_stream_id(&self) -> u64 {
        self.send.with_current_or(0, |send| send.stream_id())
    }
}

impl<R, W> AsyncStreamInfo for AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamApi,
    W: AsyncSendStreamApi,
{
    fn stream_id(&self) -> u64 {
        match self.info_side {
            DuplexInfoSide::Read => self.recv.with_current_or(0, |recv| recv.stream_id()),
            DuplexInfoSide::Write => self.send.with_current_or(0, |send| send.stream_id()),
        }
    }

    fn opened_locally(&self) -> bool {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(false, |recv| recv.opened_locally()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(false, |send| send.opened_locally()),
        }
    }

    fn bidirectional(&self) -> bool {
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

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
        match self.info_side {
            DuplexInfoSide::Read => {
                self.recv
                    .with_current_or((), |recv| recv.copy_open_info_to(dst));
            }
            DuplexInfoSide::Write => {
                self.send
                    .with_current_or((), |send| send.copy_open_info_to(dst));
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
        let read = <Self as AsyncRecvStreamApi>::set_read_deadline(self, deadline);
        let write = <Self as AsyncSendStreamApi>::set_write_deadline(self, deadline);
        read.and(write)
    }

    fn close(&self) -> AsyncBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let send = self.send.close_detached();
            let recv = self.recv.close_detached();
            let same_identity = match (send.as_deref(), recv.as_deref()) {
                (Some(send), Some(recv)) => {
                    same_close_identity(send.close_identity(), recv.close_identity())
                }
                _ => false,
            };

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
            let same_identity = match (send.as_deref(), recv.as_deref()) {
                (Some(send), Some(recv)) => {
                    same_close_identity(send.close_identity(), recv.close_identity())
                }
                _ => false,
            };

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

impl<R, W> AsyncRecvStreamApi for AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamApi,
    W: AsyncSendStreamApi,
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
            let remaining = remaining_timeout(start, timeout).unwrap_or(Duration::ZERO);
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
            let remaining = remaining_timeout(start, timeout).unwrap_or(Duration::ZERO);
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

    fn read_closed(&self) -> bool {
        self.recv.with_current_or(true, |recv| recv.read_closed())
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.recv
            .set_deadline(deadline, apply_async_read_deadline::<R>)
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

impl<R, W> AsyncSendStreamApi for AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamApi,
    W: AsyncSendStreamApi,
{
    fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let active = self.send.enter(joined_write_half_missing_error)?;
            let n = active.half.write(src).await?;
            validate_write_progress(n, src.len())
        })
    }

    fn write_all<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let active = self.send.enter(joined_write_half_missing_error)?;
            active.half.write_all(src).await
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
            let remaining = remaining_timeout(start, timeout).unwrap_or(Duration::ZERO);
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
            let remaining = remaining_timeout(start, timeout).unwrap_or(Duration::ZERO);
            let n = active.half.write_vectored_timeout(parts, remaining).await?;
            validate_write_progress(n, requested)
        })
    }

    fn write_final<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let active = self.send.enter(joined_write_half_missing_error)?;
            let n = active.half.write_final(src).await?;
            validate_write_progress(n, src.len())
        })
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let start = Instant::now();
            let active =
                self.send
                    .enter_timeout(timeout, "write", joined_write_half_missing_error)?;
            let remaining = remaining_timeout(start, timeout).unwrap_or(Duration::ZERO);
            let n = active.half.write_final_timeout(src, remaining).await?;
            validate_write_progress(n, src.len())
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
            let remaining = remaining_timeout(start, timeout).unwrap_or(Duration::ZERO);
            let n = active
                .half
                .write_vectored_final_timeout(parts, remaining)
                .await?;
            validate_write_progress(n, requested)
        })
    }

    fn write_closed(&self) -> bool {
        self.send.with_current_or(true, |send| send.write_closed())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.send
            .set_deadline(deadline, apply_async_write_deadline::<W>)
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

impl<R, W> AsyncStreamApi for AsyncDuplexStream<R, W>
where
    R: AsyncRecvStreamApi,
    W: AsyncSendStreamApi,
{
}

macro_rules! impl_async_stream_info_forward {
    ($target:ty) => {
        impl<T> AsyncStreamInfo for $target
        where
            T: AsyncStreamInfo + ?Sized,
        {
            fn stream_id(&self) -> u64 {
                (**self).stream_id()
            }

            fn opened_locally(&self) -> bool {
                (**self).opened_locally()
            }

            fn bidirectional(&self) -> bool {
                (**self).bidirectional()
            }

            fn open_info_len(&self) -> usize {
                (**self).open_info_len()
            }

            fn has_open_info(&self) -> bool {
                (**self).has_open_info()
            }

            fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
                (**self).copy_open_info_to(dst)
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

            fn remote_addr(&self) -> Option<SocketAddr> {
                (**self).remote_addr()
            }

            fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_deadline(deadline)
            }

            fn clear_deadline(&self) -> Result<()> {
                (**self).clear_deadline()
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
        impl<T> AsyncRecvStreamApi for $target
        where
            T: AsyncRecvStreamApi + ?Sized,
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

            fn read_closed(&self) -> bool {
                (**self).read_closed()
            }

            fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_read_deadline(deadline)
            }

            fn clear_read_deadline(&self) -> Result<()> {
                (**self).clear_read_deadline()
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
        impl<T> AsyncSendStreamApi for $target
        where
            T: AsyncSendStreamApi + ?Sized,
        {
            fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write(src)
            }

            fn write_all<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<()>> {
                (**self).write_all(src)
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

            fn write_final<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_final(src)
            }

            fn write_final_timeout<'a>(
                &'a self,
                src: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                (**self).write_final_timeout(src, timeout)
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

            fn write_closed(&self) -> bool {
                (**self).write_closed()
            }

            fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_write_deadline(deadline)
            }

            fn clear_write_deadline(&self) -> Result<()> {
                (**self).clear_write_deadline()
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

impl<T> AsyncStreamApi for &T where T: AsyncStreamApi + ?Sized {}
impl<T> AsyncStreamApi for &mut T where T: AsyncStreamApi + ?Sized {}
impl<T> AsyncStreamApi for Box<T> where T: AsyncStreamApi + ?Sized {}
impl<T> AsyncStreamApi for Arc<T> where T: AsyncStreamApi + ?Sized {}

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
                (**self).accept_stream()
            }

            fn accept_stream_timeout(
                &self,
                timeout: Duration,
            ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
                (**self).accept_stream_timeout(timeout)
            }

            fn accept_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
                (**self).accept_uni_stream()
            }

            fn accept_uni_stream_timeout(
                &self,
                timeout: Duration,
            ) -> AsyncBoxFuture<'_, Result<Self::RecvStream>> {
                (**self).accept_uni_stream_timeout(timeout)
            }

            fn open_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
                (**self).open_stream()
            }

            fn open_stream_timeout(
                &self,
                timeout: Duration,
            ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
                (**self).open_stream_timeout(timeout)
            }

            fn open_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
                (**self).open_uni_stream()
            }

            fn open_uni_stream_timeout(
                &self,
                timeout: Duration,
            ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
                (**self).open_uni_stream_timeout(timeout)
            }

            fn open_stream_with_options(
                &self,
                opts: OpenOptions,
            ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
                (**self).open_stream_with_options(opts)
            }

            fn open_stream_with_options_timeout(
                &self,
                opts: OpenOptions,
                timeout: Duration,
            ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
                (**self).open_stream_with_options_timeout(opts, timeout)
            }

            fn open_uni_stream_with_options(
                &self,
                opts: OpenOptions,
            ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
                (**self).open_uni_stream_with_options(opts)
            }

            fn open_uni_stream_with_options_timeout(
                &self,
                opts: OpenOptions,
                timeout: Duration,
            ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
                (**self).open_uni_stream_with_options_timeout(opts, timeout)
            }

            fn open_and_send<'a>(
                &'a self,
                data: &'a [u8],
            ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
                (**self).open_and_send(data)
            }

            fn open_and_send_timeout<'a>(
                &'a self,
                data: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
                (**self).open_and_send_timeout(data, timeout)
            }

            fn open_and_send_with_options<'a>(
                &'a self,
                opts: OpenOptions,
                data: &'a [u8],
            ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
                (**self).open_and_send_with_options(opts, data)
            }

            fn open_and_send_with_options_timeout<'a>(
                &'a self,
                opts: OpenOptions,
                data: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
                (**self).open_and_send_with_options_timeout(opts, data, timeout)
            }

            fn open_uni_and_send<'a>(
                &'a self,
                data: &'a [u8],
            ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
                (**self).open_uni_and_send(data)
            }

            fn open_uni_and_send_timeout<'a>(
                &'a self,
                data: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
                (**self).open_uni_and_send_timeout(data, timeout)
            }

            fn open_uni_and_send_with_options<'a>(
                &'a self,
                opts: OpenOptions,
                data: &'a [u8],
            ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
                (**self).open_uni_and_send_with_options(opts, data)
            }

            fn open_uni_and_send_with_options_timeout<'a>(
                &'a self,
                opts: OpenOptions,
                data: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
                (**self).open_uni_and_send_with_options_timeout(opts, data, timeout)
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

            fn wait(&self) -> AsyncBoxFuture<'_, Result<()>> {
                (**self).wait()
            }

            fn wait_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<bool>> {
                (**self).wait_timeout(timeout)
            }

            fn closed(&self) -> bool {
                (**self).closed()
            }

            fn local_addr(&self) -> Option<SocketAddr> {
                (**self).local_addr()
            }

            fn peer_addr(&self) -> Option<SocketAddr> {
                (**self).peer_addr()
            }

            fn remote_addr(&self) -> Option<SocketAddr> {
                (**self).remote_addr()
            }

            fn close_error(&self) -> Option<Error> {
                (**self).close_error()
            }

            fn state(&self) -> SessionState {
                (**self).state()
            }

            fn stats(&self) -> SessionStats {
                (**self).stats()
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
    type Stream = BoxAsyncStream;
    type SendStream = BoxAsyncSendStream;
    type RecvStream = BoxAsyncRecvStream;

    fn accept_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.accept_stream().await?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn accept_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.accept_stream_timeout(timeout).await?;
            Ok(Box::new(stream) as BoxAsyncStream)
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

    fn open_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.open_stream().await?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.open_stream_timeout(timeout).await?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move {
            let stream = self.inner.open_uni_stream().await?;
            Ok(Box::new(stream) as BoxAsyncSendStream)
        })
    }

    fn open_uni_stream_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move {
            let stream = self.inner.open_uni_stream_timeout(timeout).await?;
            Ok(Box::new(stream) as BoxAsyncSendStream)
        })
    }

    fn open_stream_with_options(
        &self,
        opts: OpenOptions,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self.inner.open_stream_with_options(opts).await?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_stream_with_options_timeout(
        &self,
        opts: OpenOptions,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move {
            let stream = self
                .inner
                .open_stream_with_options_timeout(opts, timeout)
                .await?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_uni_stream_with_options(
        &self,
        opts: OpenOptions,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move {
            let stream = self.inner.open_uni_stream_with_options(opts).await?;
            Ok(Box::new(stream) as BoxAsyncSendStream)
        })
    }

    fn open_uni_stream_with_options_timeout(
        &self,
        opts: OpenOptions,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move {
            let stream = self
                .inner
                .open_uni_stream_with_options_timeout(opts, timeout)
                .await?;
            Ok(Box::new(stream) as BoxAsyncSendStream)
        })
    }

    fn open_and_send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            let (stream, n) = self.inner.open_and_send(data).await?;
            let n = validate_write_progress(n, data.len())?;
            Ok((Box::new(stream) as BoxAsyncStream, n))
        })
    }

    fn open_and_send_timeout<'a>(
        &'a self,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            let (stream, n) = self.inner.open_and_send_timeout(data, timeout).await?;
            let n = validate_write_progress(n, data.len())?;
            Ok((Box::new(stream) as BoxAsyncStream, n))
        })
    }

    fn open_and_send_with_options<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            let (stream, n) = self.inner.open_and_send_with_options(opts, data).await?;
            let n = validate_write_progress(n, data.len())?;
            Ok((Box::new(stream) as BoxAsyncStream, n))
        })
    }

    fn open_and_send_with_options_timeout<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            let (stream, n) = self
                .inner
                .open_and_send_with_options_timeout(opts, data, timeout)
                .await?;
            let n = validate_write_progress(n, data.len())?;
            Ok((Box::new(stream) as BoxAsyncStream, n))
        })
    }

    fn open_uni_and_send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            let (stream, n) = self.inner.open_uni_and_send(data).await?;
            let n = validate_write_progress(n, data.len())?;
            Ok((Box::new(stream) as BoxAsyncSendStream, n))
        })
    }

    fn open_uni_and_send_timeout<'a>(
        &'a self,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            let (stream, n) = self.inner.open_uni_and_send_timeout(data, timeout).await?;
            let n = validate_write_progress(n, data.len())?;
            Ok((Box::new(stream) as BoxAsyncSendStream, n))
        })
    }

    fn open_uni_and_send_with_options<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            let (stream, n) = self
                .inner
                .open_uni_and_send_with_options(opts, data)
                .await?;
            let n = validate_write_progress(n, data.len())?;
            Ok((Box::new(stream) as BoxAsyncSendStream, n))
        })
    }

    fn open_uni_and_send_with_options_timeout<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            let (stream, n) = self
                .inner
                .open_uni_and_send_with_options_timeout(opts, data, timeout)
                .await?;
            let n = validate_write_progress(n, data.len())?;
            Ok((Box::new(stream) as BoxAsyncSendStream, n))
        })
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

    fn closed(&self) -> bool {
        self.inner.closed()
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
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
}

macro_rules! impl_native_async_stream_info {
    ($ty:ty) => {
        impl AsyncStreamInfo for $ty {
            fn stream_id(&self) -> u64 {
                <$ty>::stream_id(self)
            }

            fn opened_locally(&self) -> bool {
                <$ty>::opened_locally(self)
            }

            fn bidirectional(&self) -> bool {
                <$ty>::bidirectional(self)
            }

            fn open_info_len(&self) -> usize {
                <$ty>::open_info_len(self)
            }

            fn has_open_info(&self) -> bool {
                <$ty>::has_open_info(self)
            }

            fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
                <$ty>::copy_open_info_to(self, dst)
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

            fn remote_addr(&self) -> Option<SocketAddr> {
                <$ty>::remote_addr(self)
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
        impl AsyncRecvStreamApi for $ty {
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

            fn read_closed(&self) -> bool {
                <$ty>::read_closed(self)
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
        impl AsyncSendStreamApi for $ty {
            fn write<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write(self, src) })
            }

            fn write_all<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    let mut remaining = src;
                    while !remaining.is_empty() {
                        let n = <$ty>::write(self, remaining)?;
                        if n == 0 {
                            return Err(zero_length_write_error());
                        }
                        if n > remaining.len() {
                            return Err(invalid_write_progress_error());
                        }
                        remaining = &remaining[n..];
                    }
                    Ok(())
                })
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

            fn write_final<'a>(&'a self, src: &'a [u8]) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_final(self, src) })
            }

            fn write_final_timeout<'a>(
                &'a self,
                src: &'a [u8],
                timeout: Duration,
            ) -> AsyncBoxFuture<'a, Result<usize>> {
                Box::pin(async move { <$ty>::write_final_timeout(self, src, timeout) })
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

            fn write_closed(&self) -> bool {
                <$ty>::write_closed(self)
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

impl AsyncStreamApi for Stream {}

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

    fn open_stream(&self) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { Conn::open_stream(self) })
    }

    fn open_stream_timeout(&self, timeout: Duration) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { Conn::open_stream_timeout(self, timeout) })
    }

    fn open_uni_stream(&self) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move { Conn::open_uni_stream(self) })
    }

    fn open_uni_stream_timeout(
        &self,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move { Conn::open_uni_stream_timeout(self, timeout) })
    }

    fn open_stream_with_options(
        &self,
        opts: OpenOptions,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { Conn::open_stream_with_options(self, opts) })
    }

    fn open_stream_with_options_timeout(
        &self,
        opts: OpenOptions,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::Stream>> {
        Box::pin(async move { Conn::open_stream_with_options_timeout(self, opts, timeout) })
    }

    fn open_uni_stream_with_options(
        &self,
        opts: OpenOptions,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move { Conn::open_uni_stream_with_options(self, opts) })
    }

    fn open_uni_stream_with_options_timeout(
        &self,
        opts: OpenOptions,
        timeout: Duration,
    ) -> AsyncBoxFuture<'_, Result<Self::SendStream>> {
        Box::pin(async move { Conn::open_uni_stream_with_options_timeout(self, opts, timeout) })
    }

    fn open_and_send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            <Self as AsyncSession>::open_and_send_with_options(self, OpenOptions::default(), data)
                .await
        })
    }

    fn open_and_send_timeout<'a>(
        &'a self,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move {
            <Self as AsyncSession>::open_and_send_with_options_timeout(
                self,
                OpenOptions::default(),
                data,
                timeout,
            )
            .await
        })
    }

    fn open_and_send_with_options<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move { Conn::open_and_send_with_options(self, opts, data) })
    }

    fn open_and_send_with_options_timeout<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::Stream, usize)>> {
        Box::pin(async move { Conn::open_and_send_with_options_timeout(self, opts, data, timeout) })
    }

    fn open_uni_and_send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            <Self as AsyncSession>::open_uni_and_send_with_options(
                self,
                OpenOptions::default(),
                data,
            )
            .await
        })
    }

    fn open_uni_and_send_timeout<'a>(
        &'a self,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move {
            <Self as AsyncSession>::open_uni_and_send_with_options_timeout(
                self,
                OpenOptions::default(),
                data,
                timeout,
            )
            .await
        })
    }

    fn open_uni_and_send_with_options<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(async move { Conn::open_uni_and_send_with_options(self, opts, data) })
    }

    fn open_uni_and_send_with_options_timeout<'a>(
        &'a self,
        opts: OpenOptions,
        data: &'a [u8],
        timeout: Duration,
    ) -> AsyncBoxFuture<'a, Result<(Self::SendStream, usize)>> {
        Box::pin(
            async move { Conn::open_uni_and_send_with_options_timeout(self, opts, data, timeout) },
        )
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

    fn closed(&self) -> bool {
        Conn::closed(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Conn::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Conn::peer_addr(self)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Conn::remote_addr(self)
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
