//! A listener's inbound transform: a function that every new carrier
//! passes through after the admission and before the listener classifies
//! it, and [`PipeStream`], a carrier's halves as one byte stream for the
//! layers such a transform runs.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::listen::PipeHint;
use super::tokio::{PipeIo, Reader, Writer};
use crate::proto::record::Framing;

type TransformFn = dyn Fn(PipeIo, &PipeHint) -> Pin<Box<dyn Future<Output = io::Result<PipeIo>> + Send>>
    + Send
    + Sync;

/// A listener's inbound transform ([`crate::ListenerConfig::inbound_transform`]):
/// called once for every carrier the listener takes, at every entry, after
/// the admission accepted it and before the listener reads its first record.
/// The two halves of a split carrier are one carrier: it is called once, when
/// they are paired, with both directions. It returns the carrier the
/// listener goes on with, such as one with a layer over
/// [`PipeIo::wrap`], or the carrier itself. Cheap to clone.
///
/// The hint is the carrier's ([`PipeHint::admitted`] is the admission's
/// value, the uplink's for a split carrier). While the transform runs, the carrier holds its
/// source's slot, and the listener's handshake timeout bounds it: at that
/// bound, or when the listener closes, its future is dropped, and with it
/// the carrier. The listener's first-record timeout runs from its return.
///
/// The result keeps the carrier's kind: the same halves (directions) and
/// framing as the carrier given, or the carrier is closed; its
/// [`crate::CarrierKind`] is set to the carrier's. An error, a result of
/// another kind or the bound closes the carrier and counts as a setup
/// failure ([`crate::ListenerStats::setup_failures`]).
///
/// A layer over a carrier, here or wherever a carrier is wrapped, must
/// make each write on the carrier it returns exactly one write on the
/// carrier below and must never merge writes: [`PipeIo::wrap`] flushes the
/// layer after every write for this, so that a buffering layer such as a
/// TLS stream hands each write's bytes on before it takes the next.
#[derive(Clone)]
pub struct InboundTransform(Arc<TransformFn>);

impl std::fmt::Debug for InboundTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InboundTransform(..)")
    }
}

impl InboundTransform {
    /// The transform `f`, given each carrier and its hint.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(PipeIo, &PipeHint) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<PipeIo>> + Send + 'static,
    {
        Self(Arc::new(move |io, hint| Box::pin(f(io, hint))))
    }

    /// Transforms `io`.
    pub(crate) fn call(
        &self,
        io: PipeIo,
        hint: &PipeHint,
    ) -> Pin<Box<dyn Future<Output = io::Result<PipeIo>> + Send>> {
        let handler = &self.0;
        handler(io, hint)
    }
}

/// A carrier's halves as one byte stream ([`PipeIo::into_stream`],
/// [`PipeIo::wrap`]), for a layer that runs over a stream, such as TLS.
///
/// On a byte-stream carrier reads and writes go to the halves as they are.
/// On a carrier with message framing each write is one message, and reads
/// return the bytes of the messages in order. Each write is exactly one
/// write on the carrier. A read without a receiving half is the end of the
/// stream; a write without a sending half fails. Shutting it down ends the
/// sending half gracefully. Bytes the listener already read from the
/// carrier come first.
pub struct PipeStream {
    reader: Option<Reader>,
    writer: Option<Writer>,
    framing: Framing,
    /// Bytes to deliver before the reader's: the carrier's prefix, then the
    /// rest of the current message.
    pending: Vec<u8>,
    at: usize,
}

impl std::fmt::Debug for PipeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeStream")
            .field("reader", &self.reader.is_some())
            .field("writer", &self.writer.is_some())
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

/// The largest message a [`PipeStream`] reads at once.
const MESSAGE_ROOM: usize = 1 << 17;

impl AsyncRead for PipeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.at < this.pending.len() {
                let n = (this.pending.len() - this.at).min(buf.remaining());
                buf.put_slice(&this.pending[this.at..this.at + n]);
                this.at += n;
                if this.at == this.pending.len() {
                    this.pending.clear();
                    this.at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            let Some(r) = this.reader.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            if this.framing == Framing::ByteStream {
                return Pin::new(r).poll_read(cx, buf);
            }
            // A message arrives whole: read it into room for the largest.
            this.pending.resize(MESSAGE_ROOM, 0);
            let mut rb = ReadBuf::new(&mut this.pending);
            let r = ready!(Pin::new(r).poll_read(cx, &mut rb));
            let n = rb.filled().len();
            this.pending.truncate(n);
            r?;
            if n == 0 {
                // The end of the carrier (an empty message is skipped by
                // the reader's framing).
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(w) = this.writer.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "a carrier without a sending half",
            )));
        };
        let records = this.framing == Framing::Records;
        let n = match w {
            Writer::Io(w) => ready!(w.as_mut().poll_write(cx, buf))?,
            Writer::Sealed(w) => ready!(w.as_mut().poll_write(cx, buf))?,
            Writer::Chunks(w) => {
                let mut chunk = [Bytes::copy_from_slice(buf)];
                ready!(w.as_mut().poll_write_chunks(cx, &mut chunk))?
            }
            Writer::Stream(w) => ready!(Pin::new(w).poll_write(cx, buf))?,
        };
        if records && n != buf.len() && !buf.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "a message carrier took part of a message",
            )));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().writer.as_mut() {
            Some(w) => w.poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().writer.as_mut() {
            Some(w) => w.poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

/// A layer whose every write is flushed before the next one starts, so
/// that a buffering layer makes one write below for each write on it.
struct FlushEach<T> {
    inner: T,
    flushing: bool,
}

impl<T: AsyncWrite + Unpin> FlushEach<T> {
    fn poll_flushed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flushing {
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.flushing = false;
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FlushEach<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FlushEach<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_flushed(cx))?;
        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.flushing = true;
        // The bytes are taken; a flush that cannot finish now does before
        // the next write.
        let _ = this.poll_flushed(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.flushing = true;
        this.poll_flushed(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flushed(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl PipeIo {
    /// The carrier's halves as one byte stream, for a layer that runs over
    /// a stream ([`PipeStream`]); bytes a listener already read from it
    /// come first. Every other property of the carrier is dropped:
    /// [`PipeIo::wrap`] keeps them.
    pub fn into_stream(mut self) -> PipeStream {
        self.take_stream()
    }

    fn take_stream(&mut self) -> PipeStream {
        PipeStream {
            reader: self.reader.take(),
            writer: self.writer.take(),
            framing: self.framing,
            pending: std::mem::take(&mut self.prefix),
            at: 0,
        }
    }

    /// Runs a layer over the carrier: `layer` gets the carrier's halves as
    /// one stream ([`PipeStream`]) and returns the layer's stream, such as
    /// a TLS stream over it, which becomes the carrier's halves in the
    /// directions the carrier has. The carrier keeps its framing and every
    /// other property (its kind, TCP socket, abort, lanes); its reads may
    /// return less than the layer holds. Each write on the result is
    /// flushed before the next starts, so that a buffering layer makes one
    /// write on the carrier for each write on it.
    ///
    /// For a listener's [`InboundTransform`], or for a dialer that runs the
    /// layer's client side over its carrier before the session starts.
    ///
    /// # Errors
    ///
    /// The layer's error; the carrier is dropped with it.
    pub async fn wrap<F, Fut, T>(mut self, layer: F) -> io::Result<Self>
    where
        F: FnOnce(PipeStream) -> Fut,
        Fut: Future<Output = io::Result<T>>,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (inbound, outbound) = (self.reader.is_some(), self.writer.is_some());
        let stream = self.take_stream();
        let layered = layer(stream).await?;
        let (r, w) = tokio::io::split(FlushEach {
            inner: layered,
            flushing: false,
        });
        self.reader = inbound.then(|| Reader::Io(Box::pin(r)));
        self.writer = outbound.then(|| Writer::Io(Box::pin(w)));
        self.partial_reads = true;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_stream_replays_the_prefix_then_reads_through() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut io = PipeIo::new(a);
        io.prefix = b"pre".to_vec();
        let mut s = io.into_stream();
        b.write_all(b"fix").await.unwrap();
        drop(b);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"prefix");
    }

    #[tokio::test]
    async fn wrap_keeps_directions_and_framing() {
        let (a, _b) = tokio::io::duplex(64);
        let io = PipeIo::reader(a).records();
        let io = io.wrap(|s| async move { Ok(s) }).await.unwrap();
        assert!(io.reader.is_some() && io.writer.is_none());
        assert_eq!(io.framing, Framing::Records);
    }

    /// A writer that records each write call it gets.
    struct Calls(Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

    impl AsyncWrite for Calls {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_buffered_layer_makes_one_write_per_write() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let io = PipeIo::writer(Calls(calls.clone())).records();
        let io = io
            .wrap(|s| async move { Ok(tokio::io::BufStream::new(s)) })
            .await
            .unwrap();
        let mut w = io.writer.unwrap();
        for m in [&b"one"[..], b"two", b"three"] {
            std::future::poll_fn(|cx| match &mut w {
                Writer::Io(w) => w.as_mut().poll_write(cx, m),
                _ => unreachable!(),
            })
            .await
            .unwrap();
        }
        assert_eq!(
            *calls.lock().unwrap(),
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
    }
}
