#![cfg(any(feature = "tokio-io", feature = "futures-io"))]

#[cfg(feature = "tokio-io")]
use std::future::Future;
use std::io::{IoSlice, Result as IoResult};
#[cfg(feature = "futures-io")]
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
#[cfg(feature = "tokio-io")]
use std::thread;

struct CompatStream {
    read: Mutex<Vec<u8>>,
    written: Mutex<Vec<u8>>,
    write_closed: AtomicBool,
}

impl CompatStream {
    fn new(read: &[u8]) -> Self {
        Self {
            read: Mutex::new(read.to_vec()),
            written: Mutex::new(Vec::new()),
            write_closed: AtomicBool::new(false),
        }
    }

    fn written(&self) -> Vec<u8> {
        self.written.lock().unwrap().clone()
    }

    fn is_write_closed(&self) -> bool {
        self.write_closed.load(Ordering::Acquire)
    }
}

impl zmux::AsyncStreamHandle for CompatStream {
    fn stream_id(&self) -> u64 {
        7
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move {
            self.write_closed.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        self.close()
    }
}

impl zmux::AsyncRecvStreamHandle for CompatStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            let mut read = self.read.lock().unwrap();
            let n = dst.len().min(read.len());
            dst[..n].copy_from_slice(&read[..n]);
            read.drain(..n);
            Ok(n)
        })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: std::time::Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn is_read_closed(&self) -> bool {
        self.read.lock().unwrap().is_empty()
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for CompatStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.written.lock().unwrap().extend_from_slice(src);
            Ok(src.len())
        })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: std::time::Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: std::time::Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            let n = self.write(src).await?;
            self.close_write().await?;
            Ok(n)
        })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: std::time::Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            let mut total = 0usize;
            for part in parts {
                total += self.write(part).await?;
            }
            self.close_write().await?;
            Ok(total)
        })
    }

    fn is_write_closed(&self) -> bool {
        self.is_write_closed()
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move {
            self.write_closed.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        self.close_write()
    }
}

impl zmux::AsyncDuplexStreamHandle for CompatStream {}

#[cfg(feature = "tokio-io")]
fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::yield_now(),
        }
    }
}

#[cfg(feature = "futures-io")]
fn poll_ready<T>(poll: impl FnOnce(&mut Context<'_>) -> Poll<T>) -> T {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    match poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("compat stream unexpectedly returned Pending"),
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

#[cfg(feature = "tokio-io")]
#[test]
fn tokio_io_compat_reads_writes_and_shutdown() -> IoResult<()> {
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

    let stream = Arc::new(CompatStream::new(b"ping"));
    let mut io = zmux::AsyncIo::from_arc(Arc::clone(&stream));

    let mut buf = [0u8; 8];
    let n = block_on(AsyncReadExt::read(&mut io, &mut buf))?;
    assert_eq!(&buf[..n], b"ping");

    block_on(AsyncWriteExt::write_all(&mut io, b"pong"))?;
    let parts = [IoSlice::new(b"-"), IoSlice::new(b"vec")];
    let n = block_on(std::future::poll_fn(|cx| {
        std::pin::Pin::new(&mut io).poll_write_vectored(cx, &parts)
    }))?;
    assert_eq!(n, 4);
    block_on(AsyncWriteExt::shutdown(&mut io))?;

    assert_eq!(stream.written(), b"pong-vec");
    assert!(stream.is_write_closed());
    Ok(())
}

#[cfg(feature = "futures-io")]
#[test]
fn futures_io_compat_reads_writes_and_closes() -> IoResult<()> {
    use futures_io::{AsyncRead, AsyncWrite};

    let stream = Arc::new(CompatStream::new(b"abc"));
    let mut io = zmux::AsyncIo::from_arc(Arc::clone(&stream));

    let mut buf = [0u8; 8];
    let n = poll_ready(|cx| Pin::new(&mut io).poll_read(cx, &mut buf))?;
    assert_eq!(&buf[..n], b"abc");

    let n = poll_ready(|cx| Pin::new(&mut io).poll_write(cx, b"xyz"))?;
    assert_eq!(n, 3);
    let parts = [IoSlice::new(b"-"), IoSlice::new(b"vec")];
    let n = poll_ready(|cx| Pin::new(&mut io).poll_write_vectored(cx, &parts))?;
    assert_eq!(n, 4);
    poll_ready(|cx| Pin::new(&mut io).poll_flush(cx))?;
    poll_ready(|cx| Pin::new(&mut io).poll_close(cx))?;

    assert_eq!(stream.written(), b"xyz-vec");
    assert!(stream.is_write_closed());
    Ok(())
}
