#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
use crate::async_api::{AsyncRecvStreamHandle, AsyncSendStreamHandle};
#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
use std::future::Future;
#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
use std::io::{self, IoSlice};
#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
use std::pin::Pin;
use std::sync::Arc;
#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
use std::task::{Context, Poll};

const DEFAULT_READ_CHUNK: usize = 16 * 1024;
const DEFAULT_WRITE_CHUNK: usize = 16 * 1024;
#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
const MAX_RETAINED_IO_BUFFER: usize = 64 * 1024;

#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
type BoxIoFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
type PendingWriteFuture = BoxIoFuture<(Vec<u8>, io::Result<usize>)>;

/// Adapter from ZMux async stream traits to standard async I/O traits.
///
/// With the `tokio-io` feature this type implements `tokio::io::AsyncRead`
/// and/or `tokio::io::AsyncWrite`. With the `futures-io` feature it implements
/// `futures_io::AsyncRead` and/or `futures_io::AsyncWrite`.
pub struct AsyncIo<T: ?Sized> {
    inner: Arc<T>,
    read_chunk_size: usize,
    write_chunk_size: usize,
    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    read_ready: Vec<u8>,
    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    read_ready_offset: usize,
    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    pending_read: Option<BoxIoFuture<io::Result<Vec<u8>>>>,
    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    write_buf: Vec<u8>,
    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    pending_write: Option<PendingWriteFuture>,
    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    pending_shutdown: Option<BoxIoFuture<io::Result<()>>>,
    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    shutdown_done: bool,
}

impl<T> AsyncIo<T>
where
    T: Send + Sync + 'static,
{
    /// Wraps an owned async ZMux stream behind standard async I/O traits.
    #[inline]
    pub fn new(stream: T) -> Self {
        Self::from_arc(Arc::new(stream))
    }
}

impl<T: ?Sized> AsyncIo<T> {
    /// Wraps an already shared async ZMux stream.
    #[inline]
    pub fn from_arc(inner: Arc<T>) -> Self {
        Self {
            inner,
            read_chunk_size: DEFAULT_READ_CHUNK,
            write_chunk_size: DEFAULT_WRITE_CHUNK,
            #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
            read_ready: Vec::new(),
            #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
            read_ready_offset: 0,
            #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
            pending_read: None,
            #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
            write_buf: Vec::new(),
            #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
            pending_write: None,
            #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
            pending_shutdown: None,
            #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
            shutdown_done: false,
        }
    }

    /// Borrows the wrapped stream.
    #[inline]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Borrows the shared owner.
    #[inline]
    pub fn as_arc(&self) -> &Arc<T> {
        &self.inner
    }

    /// Returns the shared owner of the wrapped stream.
    #[inline]
    pub fn into_inner(self) -> Arc<T> {
        self.inner
    }

    /// Returns the maximum read buffer used per poll operation.
    #[inline]
    pub fn read_chunk_size(&self) -> usize {
        self.read_chunk_size
    }

    /// Sets the maximum read buffer used per poll operation.
    #[inline]
    pub fn set_read_chunk_size(&mut self, size: usize) {
        self.read_chunk_size = size.max(1);
    }

    /// Returns the maximum write buffer copied per poll operation.
    #[inline]
    pub fn write_chunk_size(&self) -> usize {
        self.write_chunk_size
    }

    /// Sets the maximum write buffer copied per poll operation.
    #[inline]
    pub fn set_write_chunk_size(&mut self, size: usize) {
        self.write_chunk_size = size.max(1);
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn copy_ready_read(&mut self, dst: &mut [u8]) -> usize {
        let available = self.read_ready.len() - self.read_ready_offset;
        let n = available.min(dst.len());
        dst[..n]
            .copy_from_slice(&self.read_ready[self.read_ready_offset..self.read_ready_offset + n]);
        self.read_ready_offset += n;
        if self.read_ready_offset >= self.read_ready.len() {
            recycle_io_buffer(&mut self.read_ready);
            self.read_ready_offset = 0;
        }
        n
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn poll_read_into(&mut self, cx: &mut Context<'_>, dst: &mut [u8]) -> Poll<io::Result<usize>>
    where
        T: AsyncRecvStreamHandle + 'static,
    {
        if dst.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.read_ready_offset < self.read_ready.len() {
            return Poll::Ready(Ok(self.copy_ready_read(dst)));
        }
        if self.pending_read.is_none() {
            let stream = Arc::clone(&self.inner);
            let len = dst.len().min(self.read_chunk_size);
            let mut buf = std::mem::take(&mut self.read_ready);
            self.pending_read = Some(Box::pin(async move {
                if buf.len() < len {
                    buf.try_reserve_exact(len - buf.len())
                        .map_err(|_| io_buffer_allocation_failed("read"))?;
                }
                buf.resize(len, 0);
                let n = stream.read(&mut buf).await.map_err(io::Error::from)?;
                if n > buf.len() {
                    return Err(invalid_progress_io("read"));
                }
                buf.truncate(n);
                Ok(buf)
            }));
        }

        let result = self
            .pending_read
            .as_mut()
            .expect("pending read future must exist")
            .as_mut()
            .poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_read = None;
                let chunk = result?;
                let n = dst.len().min(chunk.len());
                dst[..n].copy_from_slice(&chunk[..n]);
                self.read_ready = chunk;
                if n < self.read_ready.len() {
                    self.read_ready_offset = n;
                } else {
                    recycle_io_buffer(&mut self.read_ready);
                    self.read_ready_offset = 0;
                }
                Poll::Ready(Ok(n))
            }
        }
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let result = self
            .pending_write
            .as_mut()
            .expect("pending write future must exist")
            .as_mut()
            .poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_write = None;
                let (mut data, result) = result;
                recycle_io_buffer(&mut data);
                self.write_buf = data;
                Poll::Ready(result)
            }
        }
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn start_pending_write(&mut self, src: &[u8]) -> io::Result<()>
    where
        T: AsyncSendStreamHandle + 'static,
    {
        let mut data = std::mem::take(&mut self.write_buf);
        data.clear();
        data.try_reserve_exact(src.len())
            .map_err(|_| io_buffer_allocation_failed("write"))?;
        data.extend_from_slice(src);
        self.start_pending_write_data(data);
        Ok(())
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn start_pending_vectored_write(&mut self, bufs: &[IoSlice<'_>], len: usize) -> io::Result<()>
    where
        T: AsyncSendStreamHandle + 'static,
    {
        let mut data = std::mem::take(&mut self.write_buf);
        data.clear();
        copy_vectored_prefix_into(bufs, len, &mut data)?;
        self.start_pending_write_data(data);
        Ok(())
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn start_pending_write_data(&mut self, data: Vec<u8>)
    where
        T: AsyncSendStreamHandle + 'static,
    {
        let stream = Arc::clone(&self.inner);
        self.pending_write = Some(Box::pin(async move {
            let result = async {
                let n = stream.write(&data).await.map_err(io::Error::from)?;
                if n > data.len() {
                    return Err(invalid_progress_io("write"));
                }
                Ok(n)
            }
            .await;
            (data, result)
        }));
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn poll_write_bytes(&mut self, cx: &mut Context<'_>, src: &[u8]) -> Poll<io::Result<usize>>
    where
        T: AsyncSendStreamHandle + 'static,
    {
        if self.pending_write.is_some() {
            return self.poll_pending_write(cx);
        }
        if src.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = src.len().min(self.write_chunk_size);
        if let Err(err) = self.start_pending_write(&src[..len]) {
            return Poll::Ready(Err(err));
        }

        self.poll_pending_write(cx)
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn poll_write_vectored_bytes(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>>
    where
        T: AsyncSendStreamHandle + 'static,
    {
        if self.pending_write.is_none() {
            let len = vectored_prefix_len(bufs, self.write_chunk_size);
            if len == 0 {
                return Poll::Ready(Ok(0));
            }
            if let Err(err) = self.start_pending_vectored_write(bufs, len) {
                return Poll::Ready(Err(err));
            }
        }

        self.poll_pending_write(cx)
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn poll_flush_common(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        T: AsyncSendStreamHandle + 'static,
    {
        if self.pending_write.is_none() {
            return Poll::Ready(Ok(()));
        }

        match self.poll_pending_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(result.map(|_| ())),
        }
    }

    #[cfg(any(feature = "tokio-io", feature = "futures-io"))]
    fn poll_shutdown_common(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        T: AsyncSendStreamHandle + 'static,
    {
        match self.poll_flush_common(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if self.pending_shutdown.is_none() {
            let stream = Arc::clone(&self.inner);
            self.pending_shutdown = Some(Box::pin(async move {
                stream.close_write().await.map_err(io::Error::from)
            }));
        }
        let result = self
            .pending_shutdown
            .as_mut()
            .expect("pending shutdown future must exist")
            .as_mut()
            .poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_shutdown = None;
                if result.is_ok() {
                    self.shutdown_done = true;
                }
                Poll::Ready(result)
            }
        }
    }
}

impl<T: ?Sized> Unpin for AsyncIo<T> {}

#[cfg(feature = "tokio-io")]
impl<T> tokio::io::AsyncRead for AsyncIo<T>
where
    T: AsyncRecvStreamHandle + ?Sized + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let dst = buf.initialize_unfilled();
        match this.poll_read_into(cx, dst) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }
}

#[cfg(feature = "tokio-io")]
impl<T> tokio::io::AsyncWrite for AsyncIo<T>
where
    T: AsyncSendStreamHandle + ?Sized + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_bytes(cx, src)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_vectored_bytes(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_common(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_shutdown_common(cx)
    }
}

#[cfg(feature = "futures-io")]
impl<T> futures_io::AsyncRead for AsyncIo<T>
where
    T: AsyncRecvStreamHandle + ?Sized + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.poll_read_into(cx, dst)
    }
}

#[cfg(feature = "futures-io")]
impl<T> futures_io::AsyncWrite for AsyncIo<T>
where
    T: AsyncSendStreamHandle + ?Sized + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_bytes(cx, src)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_vectored_bytes(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_common(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_shutdown_common(cx)
    }
}

#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
fn vectored_prefix_len(bufs: &[IoSlice<'_>], limit: usize) -> usize {
    let limit = limit.max(1);
    let mut total = 0usize;
    for buf in bufs {
        if total == limit {
            break;
        }
        total += (limit - total).min(buf.len());
    }
    total
}

#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
fn copy_vectored_prefix_into(
    bufs: &[IoSlice<'_>],
    len: usize,
    data: &mut Vec<u8>,
) -> io::Result<()> {
    data.try_reserve_exact(len)
        .map_err(|_| io_buffer_allocation_failed("write"))?;
    for buf in bufs {
        if data.len() == len {
            break;
        }
        let remaining = len - data.len();
        let take = remaining.min(buf.len());
        data.extend_from_slice(&buf[..take]);
    }
    Ok(())
}

#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
fn recycle_io_buffer(buffer: &mut Vec<u8>) {
    buffer.clear();
    if buffer.capacity() > MAX_RETAINED_IO_BUFFER {
        *buffer = Vec::new();
    }
}

#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
fn io_buffer_allocation_failed(direction: &str) -> io::Error {
    io::Error::other(format!("zmux: async {direction} buffer allocation failed"))
}

#[cfg(any(feature = "tokio-io", feature = "futures-io"))]
fn invalid_progress_io(direction: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("zmux: {direction} reported invalid progress"),
    )
}
