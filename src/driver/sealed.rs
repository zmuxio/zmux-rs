//! Sealed records over a carrier, for a Join and for an Establish: the one
//! implementation. The result is a message-framed carrier with one zmux record in each
//! AEAD message. The carrier's lanes, datagram channel and exporter are hidden, since
//! they would pass the protection; what is asked of its socket stays.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tokio::{PipeIo, Reader, Writer};
use crate::proto::record::Framing;
use crate::proto::seal::{Opener, Sealer};

/// The AEAD tag and, on a byte stream, the length prefix of a Sealed record.
const TAG: u16 = 16;
const LEN: u16 = 2;
/// The largest plaintext of a Sealed record: its ciphertext fits in 16 bits.
pub(crate) const SEALED_MAX_RECORD: usize = u16::MAX as usize - TAG as usize;

/// The read buffer of a Sealed carrier: a byte-stream record whole, its length prefix
/// included, which also holds the largest message of a message carrier.
const READ_BUF: usize = LEN as usize + u16::MAX as usize;

/// The length prefix of a byte-stream Sealed record carrying `sealed`.
pub(crate) fn length_prefix(sealed: &[u8]) -> io::Result<[u8; 2]> {
    u16::try_from(sealed.len())
        .map(u16::to_be_bytes)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "sealed record over 65535 bytes",
            )
        })
}

/// Replaces `p`'s halves with Sealed records, and marks it message framed. Bytes `p`
/// holds as read ahead stay the Sealed stream's.
pub(crate) fn seal_carrier(mut p: PipeIo, sealer: Sealer, opener: Opener) -> PipeIo {
    let lower = p.framing;
    let prefix = std::mem::take(&mut p.prefix);
    p.reader = p
        .reader
        .take()
        .map(|r| Reader::Io(Box::pin(SealedRead::new(r, lower, opener, prefix))));
    p.writer = p.writer.take().map(|w| {
        Writer::Io(Box::pin(SealedWrite {
            lower: w,
            framing: lower,
            sealer,
            pending: Bytes::new(),
            taken: 0,
            unit: BytesMut::new(),
        }))
    });
    p.write_overhead = p
        .write_overhead
        .saturating_add(TAG + if lower == Framing::ByteStream { LEN } else { 0 });
    p.framing = Framing::Records;
    p.max_record = Some(SEALED_MAX_RECORD);
    p.hide_capabilities();
    p
}

/// A Sealed reading half, for allocation tests.
#[cfg(feature = "test-hooks")]
pub type SealedReadHalf = Pin<Box<dyn AsyncRead + Send>>;
/// A Sealed writing half, for allocation tests.
#[cfg(feature = "test-hooks")]
pub type SealedWriteHalf = Pin<Box<dyn AsyncWrite + Send>>;

/// A byte-stream carrier's halves as Sealed records, for allocation tests.
#[cfg(feature = "test-hooks")]
pub fn sealed_halves<T>(io: T, sealer: Sealer, opener: Opener) -> (SealedReadHalf, SealedWriteHalf)
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    let p = seal_carrier(PipeIo::new(io), sealer, opener);
    let (Some(Reader::Io(r)), Some(Writer::Io(w))) = (p.reader, p.writer) else {
        unreachable!("Sealed halves are boxed")
    };
    (r, w)
}

struct SealedRead {
    lower: Reader,
    framing: Framing,
    opener: Opener,
    /// The bytes read from the carrier and not opened yet are `buf[start..end]`; on a
    /// message carrier they are one message. Allocated once, at its full size, and
    /// reused for every record.
    buf: Vec<u8>,
    start: usize,
    end: usize,
    failed: bool,
}

impl SealedRead {
    fn new(lower: Reader, framing: Framing, opener: Opener, prefix: Vec<u8>) -> Self {
        let end = prefix.len();
        let mut buf = prefix;
        buf.resize(end.max(READ_BUF), 0);
        Self {
            lower,
            framing,
            opener,
            buf,
            start: 0,
            end,
            failed: false,
        }
    }

    /// The bounds in `buf` of the next whole unit, taken.
    fn cut(&mut self) -> Option<(usize, usize)> {
        let (start, end) = (self.start, self.end);
        if start == end {
            return None;
        }
        if self.framing == Framing::Records {
            (self.start, self.end) = (0, 0);
            return Some((start, end));
        }
        let head = self.buf.get(start..end)?.get(..2)?;
        let n = usize::from(u16::from_be_bytes([head[0], head[1]]));
        if end - start < 2 + n {
            return None;
        }
        self.start = start + 2 + n;
        if self.start == end {
            (self.start, self.end) = (0, 0);
        }
        Some((start + 2, start + 2 + n))
    }
}

impl AsyncRead for SealedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        loop {
            if let Some((a, b)) = this.cut() {
                let Ok(plain) = this.opener.open_in_place(&mut this.buf[a..b]) else {
                    this.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                };
                if plain.len() > out.remaining() {
                    this.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                // No bytes of a record are not the end of the carrier.
                if plain.is_empty() {
                    continue;
                }
                out.put_slice(plain);
                return Poll::Ready(Ok(()));
            }
            // A cut record moves to the front, so that the whole of it fits.
            if this.start > 0 {
                this.buf.copy_within(this.start..this.end, 0);
                (this.start, this.end) = (0, this.end - this.start);
            }
            let mut rb = ReadBuf::new(&mut this.buf[this.end..]);
            ready!(Pin::new(&mut this.lower).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            // The end at a record's boundary reads as the carrier's end, which closes no
            // stream and which the session judges by its frames: a pipe's graceful removal
            // ends so, its PIPE_ABANDON possibly on another pipe.
            if n == 0 {
                if this.end == 0 {
                    return Poll::Ready(Ok(()));
                }
                // A cut record is a carrier failure.
                this.failed = true;
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.end += n;
        }
    }
}

struct SealedWrite {
    lower: Writer,
    framing: Framing,
    sealer: Sealer,
    /// The unit being written.
    pending: Bytes,
    /// Plaintext bytes of it to report once written.
    taken: usize,
    /// Where units are built: once a unit is written and dropped below, its
    /// allocation is taken back for the next one.
    unit: BytesMut,
}

impl SealedWrite {
    /// Writes what is pending; it is one write of the carrier below. A failed write
    /// leaves a record cut or lost, after which no record may follow: it fails the
    /// direction.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let wrote = match &mut self.lower {
                Writer::Io(w) => w.as_mut().poll_write(cx, &self.pending),
                Writer::Chunks(w) => {
                    let mut c = [self.pending.clone()];
                    w.as_mut().poll_write_chunks(cx, &mut c)
                }
                Writer::Stream(w) => Pin::new(w).poll_write(cx, &self.pending),
            };
            match ready!(wrote) {
                Ok(n) if n > 0 => {
                    let _ = self.pending.split_to(n);
                }
                failed => {
                    self.sealer.fail();
                    self.pending = Bytes::new();
                    self.taken = 0;
                    return Poll::Ready(Err(failed
                        .err()
                        .unwrap_or_else(|| io::ErrorKind::WriteZero.into())));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SealedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_empty() && this.taken == 0 {
            if buf.is_empty() {
                // Nothing to write is no record: an empty write is done at
                // once, and leaves nothing pending to a later write.
                return Poll::Ready(Ok(0));
            }
            let pre = if this.framing == Framing::ByteStream {
                usize::from(LEN)
            } else {
                0
            };
            let u = &mut this.unit;
            u.clear();
            u.reserve(pre + buf.len() + usize::from(TAG));
            u.put_bytes(0, pre);
            u.extend_from_slice(buf);
            u.put_bytes(0, usize::from(TAG));
            this.sealer
                .seal_in_place(&mut u[pre..])
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            if pre > 0 {
                let prefix = length_prefix(&u[pre..])?;
                u[..pre].copy_from_slice(&prefix);
            }
            this.pending = u.split().freeze();
            this.taken = buf.len();
        }
        ready!(this.poll_pending(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.taken)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        this.lower.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        this.lower.poll_shutdown(cx)
    }
}

/// Writes one handshake unit in one write.
pub(crate) async fn write_unit(p: &mut PipeIo, unit: &[u8]) -> io::Result<()> {
    if unit.is_empty() {
        return Ok(());
    }
    let w = p
        .writer
        .as_mut()
        .ok_or(io::Error::from(io::ErrorKind::BrokenPipe))?;
    let mut rest = Bytes::copy_from_slice(unit);
    std::future::poll_fn(|cx| {
        while !rest.is_empty() {
            let n = match &mut *w {
                Writer::Io(w) => ready!(w.as_mut().poll_write(cx, &rest))?,
                Writer::Chunks(w) => {
                    let mut c = [rest.clone()];
                    ready!(w.as_mut().poll_write_chunks(cx, &mut c))?
                }
                Writer::Stream(w) => ready!(Pin::new(w).poll_write(cx, &rest))?,
            };
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            let _ = rest.split_to(n);
        }
        w.poll_flush(cx)
    })
    .await
}

/// Reads once from the carrier, its bytes read ahead first; appends to `into`. On a
/// message carrier that is one message; `Ok(0)` is the end.
pub(crate) async fn read_unit(p: &mut PipeIo, into: &mut Vec<u8>) -> io::Result<usize> {
    if !p.prefix.is_empty() {
        let n = p.prefix.len();
        into.append(&mut p.prefix);
        return Ok(n);
    }
    let r = p
        .reader
        .as_mut()
        .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let at = into.len();
    into.resize(at + 16 * 1024 + (u16::MAX as usize + 64), 0);
    let mut rb = ReadBuf::new(&mut into[at..]);
    let got = std::future::poll_fn(|cx| Pin::new(&mut *r).poll_read(cx, &mut rb)).await;
    let n = rb.filled().len();
    into.truncate(at + n);
    got?;
    Ok(n)
}

/// Runs `f` until the carrier's other wait says to stop: `stop` ready gives `None`.
pub(crate) async fn until<T>(
    stop: impl Future<Output = ()>,
    f: impl Future<Output = T>,
) -> Option<T> {
    let (mut stop, mut f) = (std::pin::pin!(stop), std::pin::pin!(f));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(v) = f.as_mut().poll(cx) {
            return Poll::Ready(Some(v));
        }
        stop.as_mut().poll(cx).map(|()| None)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::seal::aes_256_gcm;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn keys() -> (Sealer, Opener) {
        let key = vec![7; 32];
        (
            Sealer::new(aes_256_gcm(), key.clone()),
            Opener::new(aes_256_gcm(), key),
        )
    }

    fn unit(s: &mut Sealer, plain: &[u8]) -> Vec<u8> {
        let c = s.seal(plain).unwrap();
        let mut m = length_prefix(&c).unwrap().to_vec();
        m.extend_from_slice(&c);
        m
    }

    /// An empty write seals nothing and leaves nothing pending: a later
    /// write, after one that was pending, reports its own bytes.
    #[tokio::test]
    async fn an_empty_write_is_no_record() {
        use std::task::{Context, Poll, Waker};
        let (s, mut o) = keys();
        let (near, mut far) = duplex(64);
        let mut p = seal_carrier(PipeIo::new(near), s, keys().1);
        let Some(Writer::Io(w)) = p.writer.as_mut() else {
            panic!("sealed")
        };
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            w.as_mut().poll_write(&mut cx, &[]),
            Poll::Ready(Ok(0))
        ));
        // A record larger than the pipe's room is pending until read.
        let data = vec![5; 200];
        assert!(w.as_mut().poll_write(&mut cx, &data).is_pending());
        assert!(matches!(w.as_mut().poll_write(&mut cx, &[]), Poll::Pending));
        let reader = tokio::spawn(async move {
            let mut got = vec![0; 2 + 200 + 16];
            far.read_exact(&mut got).await.unwrap();
            got
        });
        let n = std::future::poll_fn(|cx| w.as_mut().poll_write(cx, &data))
            .await
            .unwrap();
        assert_eq!(n, 200);
        let got = reader.await.unwrap();
        assert_eq!(o.open(&got[2..]).unwrap(), data);
    }

    /// The records written are the allocating AEAD's, with their length
    /// prefixes, and read back whole.
    #[tokio::test]
    async fn written_units_match_the_aead() {
        let key = [7; 32];
        let (near, mut far) = duplex(1 << 20);
        let mut p = seal_carrier(PipeIo::new(near), keys().0, keys().1);
        let Some(Writer::Io(w)) = p.writer.as_mut() else {
            panic!("sealed")
        };
        let lens = [1, 2, 100, 4096, SEALED_MAX_RECORD];
        let mut want = Vec::new();
        for (n, &len) in lens.iter().enumerate() {
            let plain = vec![n as u8; len];
            w.write_all(&plain).await.unwrap();
            let c = aes_256_gcm().seal(&key, n as u64, b"", &plain);
            want.extend_from_slice(&length_prefix(&c).unwrap());
            want.extend_from_slice(&c);
        }
        let mut got = vec![0; want.len()];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(got, want);
        // And back through a Sealed reader.
        let (near, mut far) = duplex(1 << 20);
        let mut q = seal_carrier(PipeIo::new(near), keys().0, keys().1);
        far.write_all(&got).await.unwrap();
        let Some(Reader::Io(r)) = q.reader.as_mut() else {
            panic!("sealed")
        };
        let mut buf = vec![0; 1 << 16];
        for (n, &len) in lens.iter().enumerate() {
            assert_eq!(r.read(&mut buf).await.unwrap(), len);
            assert!(buf[..len].iter().all(|&b| b == n as u8));
        }
    }

    /// The carrier's end reads as an end at a record's boundary and as a failure inside one.
    #[tokio::test]
    async fn the_end_inside_a_record_is_a_failure() {
        let (mut s, o) = keys();
        let (near, mut far) = duplex(1 << 16);
        let mut p = seal_carrier(PipeIo::new(near), keys().0, o);
        far.write_all(&unit(&mut s, b"one")).await.unwrap();
        far.write_all(&[0, 40, 1]).await.unwrap();
        drop(far);
        let Some(Reader::Io(r)) = p.reader.as_mut() else {
            panic!("sealed")
        };
        let mut buf = vec![0; 64];
        assert_eq!(r.read(&mut buf).await.unwrap(), 3);
        for _ in 0..2 {
            assert!(r.read(&mut buf).await.is_err());
        }
    }

    /// A record of no bytes is not the end: the read goes on to the next one.
    #[tokio::test]
    async fn an_empty_record_is_read_past() {
        let (mut s, o) = keys();
        let (near, mut far) = duplex(1 << 16);
        let mut p = seal_carrier(PipeIo::new(near), keys().0, o);
        far.write_all(&unit(&mut s, b"")).await.unwrap();
        far.write_all(&unit(&mut s, b"next")).await.unwrap();
        let Some(Reader::Io(r)) = p.reader.as_mut() else {
            panic!("sealed")
        };
        let mut buf = vec![0; 64];
        assert_eq!(r.read(&mut buf).await.unwrap(), 4);
        assert_eq!(&buf[..4], b"next");
    }

    /// Records read together and a record cut across reads come out whole, in order,
    /// from the one reused buffer.
    #[tokio::test]
    async fn records_across_reads_come_out_whole() {
        let (mut s, o) = keys();
        let (near, mut far) = duplex(1 << 18);
        let mut p = seal_carrier(PipeIo::new(near), keys().0, o);
        let big = vec![9; SEALED_MAX_RECORD];
        let mut wire = unit(&mut s, b"a");
        wire.extend(unit(&mut s, &big));
        wire.extend(unit(&mut s, b"bc"));
        let (one, two) = wire.split_at(40_000);
        far.write_all(one).await.unwrap();
        let Some(Reader::Io(r)) = p.reader.as_mut() else {
            panic!("sealed")
        };
        let mut buf = vec![0; 1 << 16];
        assert_eq!(r.read(&mut buf).await.unwrap(), 1);
        far.write_all(two).await.unwrap();
        drop(far);
        assert_eq!(r.read(&mut buf).await.unwrap(), big.len());
        assert_eq!(&buf[..big.len()], &big[..]);
        assert_eq!(r.read(&mut buf).await.unwrap(), 2);
        assert_eq!(r.read(&mut buf).await.unwrap(), 0);
    }
}
