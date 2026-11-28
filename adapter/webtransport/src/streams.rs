//! Session-owned halves, with ordinary QUIC cancellation on session close.

use std::collections::HashMap;
use std::future::Future as _;
use std::io;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll};

use bytes::Bytes;
use quinn::{ClosedStream, StreamId, VarInt};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::protocol::WT_SESSION_GONE;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
pub(crate) struct Streams(Mutex<Active>);

#[derive(Default)]
struct Active {
    gone: bool,
    send: HashMap<StreamId, Weak<Mutex<Sending>>>,
    recv: HashMap<StreamId, Weak<Mutex<quinn::RecvStream>>>,
}

struct Sending {
    stream: quinn::SendStream,
    finished: bool,
}

impl Streams {
    pub(crate) fn send(self: &Arc<Self>, mut stream: quinn::SendStream) -> io::Result<SendStream> {
        let mut active = lock(&self.0);
        if active.gone {
            let _ = stream.reset(WT_SESSION_GONE);
            return Err(io::ErrorKind::NotConnected.into());
        }
        let id = stream.id();
        let stream = Arc::new(Mutex::new(Sending {
            stream,
            finished: false,
        }));
        active.send.insert(id, Arc::downgrade(&stream));
        Ok(SendStream {
            id,
            stream,
            owner: self.clone(),
        })
    }

    pub(crate) fn recv(self: &Arc<Self>, mut stream: quinn::RecvStream) -> io::Result<RecvStream> {
        let mut active = lock(&self.0);
        if active.gone {
            let _ = stream.stop(WT_SESSION_GONE);
            return Err(io::ErrorKind::NotConnected.into());
        }
        let id = stream.id();
        let stream = Arc::new(Mutex::new(stream));
        active.recv.insert(id, Arc::downgrade(&stream));
        Ok(RecvStream {
            id,
            stream,
            owner: self.clone(),
        })
    }

    pub(crate) fn abort(&self) {
        let (send, recv) = {
            let mut active = lock(&self.0);
            active.gone = true;
            (
                std::mem::take(&mut active.send),
                std::mem::take(&mut active.recv),
            )
        };
        for stream in send.values().filter_map(Weak::upgrade) {
            let mut sending = lock(&stream);
            if !sending.finished {
                let _ = sending.stream.reset(WT_SESSION_GONE);
            }
        }
        for stream in recv.values().filter_map(Weak::upgrade) {
            let _ = lock(&stream).stop(WT_SESSION_GONE);
        }
    }
}

/// The sending half of a WebTransport stream owned by the session.
pub struct SendStream {
    id: StreamId,
    stream: Arc<Mutex<Sending>>,
    owner: Arc<Streams>,
}

impl Drop for SendStream {
    fn drop(&mut self) {
        lock(&self.owner.0).send.remove(&self.id);
    }
}

impl SendStream {
    /// The underlying QUIC stream ID.
    #[must_use]
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Writes the whole slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream fails before all bytes are written.
    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        AsyncWriteExt::write_all(self, bytes).await
    }

    /// Sends FIN after the queued bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when this half is already closed.
    pub fn finish(&mut self) -> Result<(), ClosedStream> {
        let mut sending = lock(&self.stream);
        sending.stream.finish()?;
        sending.finished = true;
        Ok(())
    }

    /// Resets this half with a wire-level code.
    ///
    /// # Errors
    ///
    /// Returns an error when this half is already closed.
    pub fn reset(&mut self, code: VarInt) -> Result<(), ClosedStream> {
        let mut sending = lock(&self.stream);
        sending.stream.reset(code)?;
        sending.finished = true;
        Ok(())
    }

    /// Waits for acknowledgments of the finished stream or the peer's STOP.
    pub fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<VarInt>, quinn::StoppedError>> + Send + 'static {
        lock(&self.stream).stream.stopped()
    }

    pub(crate) fn poll_chunks(
        &self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        // Quinn's chunk write is cancel-safe. A pending poll registers the waker.
        let mut sending = lock(&self.stream);
        pin!(sending.stream.write_chunks(chunks))
            .poll(cx)
            .map(|result| {
                result
                    .map(|written| written.bytes)
                    .map_err(crate::write_error)
            })
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut lock(&self.stream).stream), cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut lock(&self.stream).stream), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.finish().map_err(Into::into))
    }
}

/// The receiving half of a WebTransport stream owned by the session.
pub struct RecvStream {
    id: StreamId,
    stream: Arc<Mutex<quinn::RecvStream>>,
    owner: Arc<Streams>,
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        lock(&self.owner.0).recv.remove(&self.id);
    }
}

impl RecvStream {
    /// The underlying QUIC stream ID.
    #[must_use]
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Reads a complete stream of at most the given length.
    ///
    /// # Errors
    ///
    /// Returns an error on a failed stream or if the payload exceeds the limit.
    pub async fn read_to_end(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        self.take((limit as u64).saturating_add(1))
            .read_to_end(&mut out)
            .await?;
        if out.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WebTransport stream exceeded read limit",
            ));
        }
        Ok(out)
    }

    /// Sends `STOP_SENDING` with a wire-level code.
    ///
    /// # Errors
    ///
    /// Returns an error when this half is already closed.
    pub fn stop(&mut self, code: VarInt) -> Result<(), ClosedStream> {
        lock(&self.stream).stop(code)
    }

    /// Waits for a reset or the receive side's clean end.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails first.
    pub async fn received_reset(&mut self) -> Result<Option<VarInt>, quinn::ResetError> {
        std::future::poll_fn(|cx| {
            let mut recv = lock(&self.stream);
            pin!(recv.received_reset()).poll(cx)
        })
        .await
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut *lock(&self.stream)), cx, buf)
    }
}
