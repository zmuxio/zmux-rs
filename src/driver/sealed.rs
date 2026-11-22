//! Sealed records over a carrier, for a Join and for an Establish: the one
//! implementation. The result is a message-framed carrier with one zmux record in each
//! AEAD message. The carrier's lanes, datagram channel and exporter are hidden, since
//! they would pass the protection; what is asked of its socket stays.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tokio::{PipeIo, Reader, Writer};
use crate::proto::record::Framing;
use crate::proto::seal::{
    Opener, SealedFailure, SealedRead as SealedRecordRead, SealedReader, SealedWriter, Sealer,
};

/// The length prefix of a byte-stream Sealed record carrying `sealed`.
#[cfg(test)]
fn length_prefix(sealed: &[u8]) -> io::Result<[u8; 2]> {
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
    p.reader = p.reader.take().map(|r| {
        Reader::Sealed(Box::pin(SealedRead {
            lower: r,
            records: SealedReader::new(lower, opener, prefix),
        }))
    });
    p.writer = p.writer.take().map(|w| {
        Writer::Sealed(Box::pin(SealedWrite {
            lower: w,
            records: SealedWriter::new(lower, sealer),
            error: None,
        }))
    });
    let overhead = super::handle::sealed_overhead(lower);
    p.write_overhead = p.write_overhead.saturating_add(overhead);
    p.framing = Framing::Records;
    p.max_record = Some(super::handle::sealed_max_record(p.max_record, overhead));
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
    let (Some(Reader::Sealed(r)), Some(Writer::Sealed(w))) = (p.reader, p.writer) else {
        unreachable!("Sealed halves are boxed")
    };
    (r, w)
}

/// The reading half: an I/O shell of [`SealedReader`].
pub(crate) struct SealedRead {
    lower: Reader,
    records: SealedReader,
}

impl SealedRead {
    /// Whether the buffer is held with no record bytes in it.
    pub(crate) fn idle_buffer(&self) -> bool {
        self.records.idle_buffer()
    }

    /// Frees the buffer of an idle pipe: the next read allocates it again.
    pub(crate) fn release_idle(&mut self) {
        self.records.release_idle();
    }
}

fn failure(f: SealedFailure) -> io::Error {
    match f {
        SealedFailure::Invalid => io::ErrorKind::InvalidData.into(),
        SealedFailure::Cut => io::ErrorKind::UnexpectedEof.into(),
    }
}

impl AsyncRead for SealedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this
                .records
                .read(out.initialize_unfilled())
                .map_err(failure)?
            {
                // The end at a record's boundary reads as the carrier's end, which
                // closes no stream and which the session judges by its frames.
                SealedRecordRead::End => return Poll::Ready(Ok(())),
                SealedRecordRead::Data(n) => {
                    out.advance(n);
                    return Poll::Ready(Ok(()));
                }
                SealedRecordRead::More => {
                    let mut rb = ReadBuf::new(this.records.space());
                    ready!(Pin::new(&mut this.lower).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    this.records.filled(n);
                }
            }
        }
    }
}

/// The writing half: an I/O shell of [`SealedWriter`]. A write is taken
/// (`Ready`) once its record is sealed; the record is written by this write
/// as far as the carrier takes it, then by the next write, flush or
/// shutdown, which wait for it first.
pub(crate) struct SealedWrite {
    lower: Writer,
    records: SealedWriter,
    /// The error that failed the direction after its write was reported.
    error: Option<io::ErrorKind>,
}

impl SealedWrite {
    /// Whether an idle pipe would free something.
    pub(crate) fn idle_held(&self) -> bool {
        self.records.idle_held()
    }

    /// Frees the unit's allocation and the expanded key with nothing
    /// pending: the next write takes them again.
    pub(crate) fn release_idle(&mut self) {
        self.records.release_idle();
    }

    /// Writes the committed record; a failure fails the direction.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.error {
            return Poll::Ready(Err(e.into()));
        }
        while !self.records.pending().is_empty() {
            let unit = self.records.pending();
            let wrote = match &mut self.lower {
                Writer::Io(w) => w.as_mut().poll_write(cx, unit),
                Writer::Sealed(w) => w.as_mut().poll_write(cx, unit),
                Writer::Chunks(w) => {
                    let mut c = [unit.clone()];
                    w.as_mut().poll_write_chunks(cx, &mut c)
                }
                Writer::Stream(w) => Pin::new(w).poll_write(cx, unit),
            };
            let r = match ready!(wrote) {
                Ok(n) => self.records.wrote(n).map_err(failure),
                Err(e) => {
                    self.records.failed();
                    Err(e)
                }
            };
            if let Err(e) = r {
                let e = if e.kind() == io::ErrorKind::InvalidData {
                    io::Error::from(io::ErrorKind::WriteZero)
                } else {
                    e
                };
                self.error = Some(e.kind());
                return Poll::Ready(Err(e));
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
        // A record committed before goes first: nothing of `buf` is taken
        // until it is out.
        ready!(this.poll_pending(cx))?;
        if buf.is_empty() {
            // Nothing to write is no record.
            return Poll::Ready(Ok(0));
        }
        this.records.seal(buf).map_err(io::Error::other)?;
        // Taken: the record is committed (its nonce spent) and goes out
        // here as far as the carrier takes it, the rest at the next call.
        match this.poll_pending(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
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
    let mut rest = bytes::Bytes::copy_from_slice(unit);
    std::future::poll_fn(|cx| {
        while !rest.is_empty() {
            let n = match &mut *w {
                Writer::Io(w) => ready!(w.as_mut().poll_write(cx, &rest))?,
                Writer::Sealed(w) => ready!(w.as_mut().poll_write(cx, &rest))?,
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
    into.resize(at + super::HANDSHAKE_READ, 0);
    let mut rb = ReadBuf::new(&mut into[at..]);
    let got = std::future::poll_fn(|cx| Pin::new(&mut *r).poll_read(cx, &mut rb)).await;
    let n = rb.filled().len();
    into.truncate(at + n);
    got?;
    Ok(n)
}

/// Runs `f` until the carrier's other wait says to stop: `stop` ready gives `None`.
pub(crate) use super::hooks::first as until;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::handle::SEALED_MAX_RECORD;
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
    #[allow(
        clippy::many_single_char_names,
        reason = "test: keys, carrier and writer of the usual short names"
    )]
    async fn an_empty_write_is_no_record() {
        use std::task::{Context, Poll, Waker};
        let (s, mut o) = keys();
        let (near, mut far) = duplex(64);
        let mut p = seal_carrier(PipeIo::new(near), s, keys().1);
        let Some(Writer::Sealed(w)) = p.writer.as_mut() else {
            panic!("sealed")
        };
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            w.as_mut().poll_write(&mut cx, &[]),
            Poll::Ready(Ok(0))
        ));
        // A write is taken once its record is sealed (S1: `Pending` takes
        // nothing): the record larger than the pipe's room goes out as the
        // reader makes room, and the next write waits for it first.
        let data = vec![5; 200];
        assert!(matches!(
            w.as_mut().poll_write(&mut cx, &data),
            Poll::Ready(Ok(200))
        ));
        assert!(w.as_mut().poll_write(&mut cx, &[1]).is_pending());
        assert!(w.as_mut().poll_flush(&mut cx).is_pending());
        let reader = tokio::spawn(async move {
            let mut got = vec![0; 2 + 200 + 16];
            far.read_exact(&mut got).await.unwrap();
            got
        });
        std::future::poll_fn(|cx| w.as_mut().poll_flush(cx))
            .await
            .unwrap();
        let got = reader.await.unwrap();
        assert_eq!(o.open(&got[2..]).unwrap(), data);
    }

    /// A record that cannot be sealed fails the direction, as a failed
    /// write does: nothing is written and no later record follows.
    #[tokio::test]
    async fn a_seal_failure_fails_the_direction() {
        let (near, mut far) = duplex(1 << 20);
        let mut p = seal_carrier(PipeIo::new(near), keys().0, keys().1);
        let Some(Writer::Sealed(w)) = p.writer.as_mut() else {
            panic!("sealed")
        };
        let over = vec![1; aes_256_gcm().max_plaintext() + 1];
        assert!(w.write(&over).await.is_err());
        assert!(w.records.pending().is_empty());
        assert!(w.write(&[1, 2, 3]).await.is_err(), "no record follows");
        drop(p);
        let mut rest = Vec::new();
        far.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, Vec::<u8>::new());
    }

    /// The records written are the allocating AEAD's, with their length
    /// prefixes, and read back whole.
    /// An idle pipe's halves free their buffers and expanded keys, and the
    /// records after continue the counters.
    #[tokio::test]
    async fn idle_halves_release_and_resume() {
        let (near, far) = duplex(1 << 20);
        let mut p = seal_carrier(PipeIo::new(near), keys().0, keys().1);
        let mut q = seal_carrier(PipeIo::new(far), keys().0, keys().1);
        let (Some(Writer::Sealed(w)), Some(Reader::Sealed(r))) =
            (p.writer.as_mut(), q.reader.as_mut())
        else {
            panic!("sealed")
        };
        let mut buf = vec![0; 1 << 16];
        for round in 0..3u8 {
            w.write_all(&[round; 300]).await.unwrap();
            assert_eq!(r.read(&mut buf).await.unwrap(), 300);
            assert!(buf[..300].iter().all(|&b| b == round));
            assert!(w.idle_held() && r.idle_buffer());
            w.as_mut().get_mut().release_idle();
            r.as_mut().get_mut().release_idle();
            assert!(!w.idle_held() && !r.idle_buffer());
        }
    }

    /// A Sealed transform keeps the carrier's record limit less its overhead, and the
    /// Sealed maximum without one.
    #[test]
    fn sealing_keeps_the_carrier_record_limit() {
        let (near, _far) = duplex(64);
        let p = seal_carrier(PipeIo::new(near), keys().0, keys().1);
        assert_eq!(p.max_record, Some(SEALED_MAX_RECORD));
        let (near, _far) = duplex(64);
        let p = seal_carrier(
            PipeIo::new(near).with_max_record(9000).unwrap(),
            keys().0,
            keys().1,
        );
        assert_eq!(p.max_record, Some(9000 - 18));
        let (near, _far) = duplex(64);
        let msg = PipeIo::new(near).records().with_max_record(9000).unwrap();
        let p = seal_carrier(msg, keys().0, keys().1);
        assert_eq!(p.max_record, Some(9000 - 16));
    }

    #[tokio::test]
    async fn written_units_match_the_aead() {
        let key = [7; 32];
        let (near, mut far) = duplex(1 << 20);
        let mut p = seal_carrier(PipeIo::new(near), keys().0, keys().1);
        let Some(Writer::Sealed(w)) = p.writer.as_mut() else {
            panic!("sealed")
        };
        let lens = [1, 2, 100, 4096, SEALED_MAX_RECORD];
        let mut want = Vec::new();
        for (n, &len) in lens.iter().enumerate() {
            let plain = vec![u8::try_from(n).unwrap(); len];
            w.write_all(&plain).await.unwrap();
            let c = aes_256_gcm().seal(&key, n as u64, b"", &plain).unwrap();
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
        let Some(Reader::Sealed(r)) = q.reader.as_mut() else {
            panic!("sealed")
        };
        let mut buf = vec![0; 1 << 16];
        for (n, &len) in lens.iter().enumerate() {
            assert_eq!(r.read(&mut buf).await.unwrap(), len);
            assert!(buf[..len].iter().all(|&b| usize::from(b) == n));
        }
    }

    /// A record larger than the caller's buffer is given over several reads
    /// (S2): the surplus plaintext stays.
    #[tokio::test]
    #[allow(
        clippy::many_single_char_names,
        reason = "test: carriers and halves of the usual short names"
    )]
    async fn a_small_read_takes_a_record_in_parts() {
        let (near, far) = duplex(1 << 20);
        let mut p = seal_carrier(PipeIo::new(near), keys().0, keys().1);
        let mut q = seal_carrier(PipeIo::new(far), keys().0, keys().1);
        let (Some(Writer::Sealed(w)), Some(Reader::Sealed(r))) =
            (p.writer.as_mut(), q.reader.as_mut())
        else {
            panic!("sealed")
        };
        w.write_all(&[3; 9000]).await.unwrap();
        w.flush().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0; 1000];
        while got.len() < 9000 {
            let n = r.read(&mut buf).await.unwrap();
            assert!(n > 0 && n <= 1000);
            got.extend_from_slice(&buf[..n]);
        }
        assert!(got.iter().all(|&b| b == 3));
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
        let Some(Reader::Sealed(r)) = p.reader.as_mut() else {
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
        let Some(Reader::Sealed(r)) = p.reader.as_mut() else {
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
        let Some(Reader::Sealed(r)) = p.reader.as_mut() else {
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
