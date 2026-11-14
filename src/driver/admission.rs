//! The driver side of carrier admission ([`crate::Admission`]): reading a
//! carrier's prefix, discarding what a stalled carrier sends, giving the
//! prefix back in front of a byte stream ([`Prefixed`]), the fallback
//! target of byte-stream carriers ([`Fallback`]), and the PROXY protocol
//! header of a trusted intermediary ([`proxied_source`]). The listener
//! applies the admission itself ([`ListenerAdapter::enter`](crate::adapter::ListenerAdapter::enter)).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// Reads up to `peek` bytes from `r` into a buffer of that size, never
/// more; stops early at the end of `r`, at an error, or at `deadline`, and
/// returns what it read and whether the deadline ended it.
pub(crate) async fn read_prefix<R>(peek: usize, r: &mut R, deadline: Instant) -> (Vec<u8>, bool)
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = vec![0u8; peek];
    let mut got = 0;
    let fill = async {
        while got < buf.len() {
            match r.read(&mut buf[got..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
    };
    let late = tokio::time::timeout_at(deadline, fill).await.is_err();
    buf.truncate(got);
    (buf, late)
}

/// Reads and discards what arrives on `r`, `chunk` bytes at a time, until
/// it ends, fails, or `duration` has passed.
/// Reads on until `prefix` holds `need` bytes, the carrier ends, or
/// `deadline` passes; returns it and whether the deadline passed.
pub(crate) async fn read_more<R>(
    mut prefix: Vec<u8>,
    need: usize,
    r: &mut R,
    deadline: Instant,
) -> (Vec<u8>, bool)
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut got = prefix.len();
    prefix.resize(need.max(got), 0);
    let fill = async {
        while got < prefix.len() {
            match r.read(&mut prefix[got..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
    };
    let late = tokio::time::timeout_at(deadline, fill).await.is_err();
    prefix.truncate(got);
    (prefix, late)
}

pub(crate) async fn discard<R>(r: &mut R, chunk: usize, duration: Duration)
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = vec![0u8; chunk.max(1)];
    let discard = async {
        while let Ok(n) = r.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(duration, discard).await;
}

/// A future whose panic is its output `None`.
pub(crate) struct CatchUnwind<F>(pub(crate) F);

impl<F: Future + Unpin> Future for CatchUnwind<F> {
    type Output = Option<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = &mut self.0;
        match std::panic::catch_unwind(AssertUnwindSafe(|| Pin::new(inner).poll(cx))) {
            Ok(Poll::Ready(v)) => Poll::Ready(Some(v)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(None),
        }
    }
}

/// The source of a TCP connection that arrived from `peer`, which `trusted`
/// may say is an intermediary that reports its client with a PROXY protocol
/// header: from a trusted address with the PROXY protocol configured, the
/// header is read (exactly, nothing after it) and the client it reports is
/// returned, or `peer` for the intermediary's own connections (`LOCAL`,
/// `UNKNOWN`); a missing or invalid header is an error, and the caller
/// closes the connection. From any other address nothing is read and the
/// source is `peer`. Bound the call (the listener's handshake timeout, an
/// admission's peek timeout).
pub async fn proxied_source<S>(
    io: &mut S,
    peer: SocketAddr,
    trusted: &crate::proto::trusted::TrustedProxies,
) -> io::Result<SocketAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    use crate::proto::trusted::{ProxyHeader, parse_proxy_header};
    if !trusted.proxy_protocol() || !trusted.trusts(peer.ip()) {
        return Ok(peer);
    }
    let mut buf = Vec::with_capacity(crate::proto::trusted::PROXY_V1_MAX);
    loop {
        match parse_proxy_header(&buf) {
            ProxyHeader::Complete { source, .. } => return Ok(source.unwrap_or(peer)),
            ProxyHeader::Invalid => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no valid PROXY protocol header from a trusted intermediary",
                ));
            }
            ProxyHeader::Incomplete(need) => {
                let have = buf.len();
                buf.resize(need, 0);
                io.read_exact(&mut buf[have..]).await?;
            }
        }
    }
}

/// A byte stream with bytes read from it before given back in front: reads
/// return the prefix first, then the stream's own bytes, read into the
/// caller's buffer without a further copy. Writes and shutdown go to the
/// stream.
#[derive(Debug)]
pub struct Prefixed<T> {
    prefix: Vec<u8>,
    pos: usize,
    inner: T,
}

impl<T> Prefixed<T> {
    /// `inner` with `prefix` in front.
    pub fn new(inner: T, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// The stream.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// The stream, mutably: reading it directly skips what remains of the
    /// prefix.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// The prefix bytes not read yet.
    pub fn prefix(&self) -> &[u8] {
        &self.prefix[self.pos..]
    }

    /// The stream and the prefix bytes not read yet.
    pub fn into_parts(mut self) -> (T, Vec<u8>) {
        self.prefix.drain(..self.pos);
        (self.inner, self.prefix)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let rest = &this.prefix[this.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// A byte stream a fallback target is given.
pub trait FallbackStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> FallbackStream for T {}

type FallbackFn = dyn Fn(Prefixed<Box<dyn FallbackStream>>, SocketAddr) -> Pin<Box<dyn Future<Output = ()> + Send>>
    + Send
    + Sync;

/// The fallback target of byte-stream carriers
/// ([`crate::ListenerConfig::fallback`]): a connection handler given the
/// connection that the admission decided on with
/// [`crate::AdmissionVerdict::Fallback`], every byte the admission read replayed in
/// front ([`Prefixed`]), and its source. Cheap to clone.
#[derive(Clone)]
pub struct Fallback(Arc<FallbackFn>);

impl std::fmt::Debug for Fallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fallback(..)")
    }
}

impl Fallback {
    /// The handler `f`.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(Prefixed<Box<dyn FallbackStream>>, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self(Arc::new(move |c, source| Box::pin(f(c, source))))
    }

    /// Serves `conn` from `source`.
    pub async fn serve(&self, conn: Prefixed<Box<dyn FallbackStream>>, source: SocketAddr) {
        let handler = &self.0;
        handler(conn, source).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn prefixed_replays_then_reads_through() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"world").await.unwrap();
        drop(a);
        let mut p = Prefixed::new(b, b"hello ".to_vec());
        let mut out = String::new();
        p.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }

    #[tokio::test(start_paused = true)]
    async fn prefix_is_bounded() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(b"0123456789").await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (p, late) = read_prefix(4, &mut b, deadline).await;
        assert_eq!((&p[..], late), (&b"0123"[..], false));
        let mut rest = [0u8; 6];
        b.read_exact(&mut rest).await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(20);
        let (p, late) = read_prefix(4, &mut b, deadline).await;
        assert!(p.is_empty() && late, "timed out with nothing read");
    }
}
