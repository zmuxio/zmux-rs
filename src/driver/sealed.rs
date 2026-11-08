//! Sealed records over a carrier, for a Join and for an Establish: the one
//! implementation. The result is a message-framed carrier with one zmux record in each
//! AEAD message. The carrier's lanes, datagram channel and exporter are hidden, since
//! they would pass the protection; what is asked of its socket stays.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tokio::{PipeIo, Reader, Writer};
use crate::proto::record::Framing;
use crate::proto::seal::{Opener, Sealer};

/// The AEAD tag and, on a byte stream, the length prefix of a Sealed record.
const TAG: u16 = 16;
const LEN: u16 = 2;
/// The largest plaintext of a Sealed record: its ciphertext fits in 16 bits.
pub(crate) const SEALED_MAX_RECORD: usize = u16::MAX as usize - TAG as usize;

/// Replaces `p`'s halves with Sealed records, and marks it message framed. Bytes `p`
/// holds as read ahead stay the Sealed stream's.
pub(crate) fn seal_carrier(mut p: PipeIo, sealer: Sealer, opener: Opener) -> PipeIo {
    let lower = p.framing;
    let prefix = std::mem::take(&mut p.prefix);
    p.reader = p.reader.take().map(|r| {
        Reader::Io(Box::pin(SealedRead {
            lower: r,
            framing: lower,
            opener,
            buf: prefix,
            have: 0,
            failed: false,
        }))
    });
    p.writer = p.writer.take().map(|w| {
        Writer::Io(Box::pin(SealedWrite {
            lower: w,
            framing: lower,
            sealer,
            pending: Bytes::new(),
            taken: 0,
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

struct SealedRead {
    lower: Reader,
    framing: Framing,
    opener: Opener,
    /// Bytes read from the carrier and not opened yet.
    buf: Vec<u8>,
    have: usize,
    failed: bool,
}

impl SealedRead {
    /// Takes the next whole unit from `buf`.
    fn cut(&mut self) -> Option<Vec<u8>> {
        if self.framing == Framing::Records {
            return (self.have > 0).then(|| {
                let mut m = std::mem::take(&mut self.buf);
                m.truncate(self.have);
                self.have = 0;
                m
            });
        }
        let head = self.buf.get(..2)?;
        let n = usize::from(u16::from_be_bytes([head[0], head[1]]));
        if self.buf.len() < 2 + n {
            return None;
        }
        let unit = self.buf[2..2 + n].to_vec();
        self.buf.drain(..2 + n);
        Some(unit)
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
        // A prefix on a message carrier is one read-ahead message.
        if this.framing == Framing::Records && this.have == 0 && !this.buf.is_empty() {
            this.have = this.buf.len();
        }
        loop {
            if let Some(unit) = this.cut() {
                let Ok(plain) = this.opener.open(&unit) else {
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
                out.put_slice(&plain);
                return Poll::Ready(Ok(()));
            }
            let at = this.buf.len();
            let want = if this.framing == Framing::Records {
                u16::MAX as usize + 1
            } else {
                16 * 1024
            };
            this.buf.resize(at + want, 0);
            let mut rb = ReadBuf::new(&mut this.buf[at..]);
            let read = Pin::new(&mut this.lower).poll_read(cx, &mut rb);
            let n = rb.filled().len();
            this.buf.truncate(at + n);
            // The read buffer is only a scratch space: an idle pipe, waiting for its
            // next record, keeps none.
            if this.buf.len() < this.buf.capacity() / 2 {
                this.buf.shrink_to_fit();
            }
            ready!(read)?;
            // The end at a record's boundary reads as the carrier's end, which closes no
            // stream and which the session judges by its frames: a pipe's graceful removal
            // ends so, its PIPE_ABANDON possibly on another pipe.
            if n == 0 {
                if this.buf.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                // A cut record is a carrier failure.
                this.failed = true;
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            if this.framing == Framing::Records {
                this.have = n;
            }
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
}

impl SealedWrite {
    /// Writes what is pending; it is one write of the carrier below.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = match &mut self.lower {
                Writer::Io(w) => ready!(w.as_mut().poll_write(cx, &self.pending))?,
                Writer::Chunks(w) => {
                    let mut c = [self.pending.clone()];
                    ready!(w.as_mut().poll_write_chunks(cx, &mut c))?
                }
                Writer::Stream(w) => ready!(Pin::new(w).poll_write(cx, &self.pending))?,
            };
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            let _ = self.pending.split_to(n);
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
            let sealed = this
                .sealer
                .seal(buf)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            this.taken = buf.len();
            this.pending = if this.framing == Framing::ByteStream {
                let mut unit = Vec::with_capacity(2 + sealed.len());
                unit.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
                unit.extend_from_slice(&sealed);
                unit.into()
            } else {
                sealed.into()
            };
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
        let mut m = (c.len() as u16).to_be_bytes().to_vec();
        m.extend_from_slice(&c);
        m
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
}
