//! Sealed records over a carrier, for a Join and for an Establish: the one
//! implementation. The result is a message-framed carrier with one zmux record in each
//! AEAD message. The carrier's lanes, datagram channel and exporter are hidden, since
//! they would pass the protection; what is asked of its socket stays.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::accept::JoinWrite;
use super::attachment::Attachment;
use super::sealed_failure as failure;
use super::tokio::{ChunkWrite, PipeIo, Reader, Tokio, Writer};
use crate::proto::ReceivedRecord;
use crate::proto::record::Framing;
use crate::proto::seal::{
    Opener, SealedRead as SealedRecordRead, SealedReader, SealedWriter, Sealer,
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
            records: SealedReader::new(lower, opener, prefix, p.max_record),
            remainder: None,
        }))
    });
    p.writer = p.writer.take().map(|w| {
        Writer::Sealed(Box::pin(SealedWrite {
            lower: w,
            records: SealedWriter::new(lower, sealer),
            memory_wait: None,
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
#[doc(hidden)]
pub struct SealedReadHalf(Pin<Box<SealedRead>>);

#[cfg(feature = "test-hooks")]
impl std::fmt::Debug for SealedReadHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedReadHalf").finish_non_exhaustive()
    }
}

#[cfg(feature = "test-hooks")]
impl SealedReadHalf {
    /// Polls for the next authenticated record.
    ///
    /// # Errors
    ///
    /// The record or carrier failed.
    pub fn poll_record(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<ReceivedRecord>>> {
        self.0.as_mut().get_mut().poll_record(cx)
    }
}

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
    (SealedReadHalf(r), w)
}

/// The reading half: an I/O shell of [`SealedReader`].
pub(crate) struct SealedRead {
    lower: Reader,
    records: SealedReader,
    /// A short byte read during setup may leave a plaintext suffix.
    remainder: Option<ReceivedRecord>,
}

impl SealedRead {
    /// Whether the reader can free resources.
    pub(crate) fn idle_buffer(&self) -> bool {
        self.remainder.is_none() && self.records.idle_buffer()
    }

    /// Frees resources held by an idle reader.
    pub(crate) fn release_idle(&mut self) {
        if self.remainder.is_none() {
            self.records.release_idle();
        }
    }

    pub(crate) fn poll_record(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<ReceivedRecord>>> {
        if let Some(record) = self.remainder.take() {
            return Poll::Ready(Ok(Some(record)));
        }
        loop {
            match self.records.read().map_err(failure)? {
                SealedRecordRead::Record(record) => return Poll::Ready(Ok(Some(record))),
                SealedRecordRead::End => return Poll::Ready(Ok(None)),
                SealedRecordRead::More => {
                    let mut rb = ReadBuf::new(self.records.space());
                    let result = ready!(Pin::new(&mut self.lower).poll_read(cx, &mut rb));
                    let n = rb.filled().len();
                    match result {
                        Ok(()) if n == 0 => self.records.eof(),
                        Ok(()) => self.records.filled(n).map_err(failure)?,
                        Err(e) if super::is_empty_message(&e) => {
                            self.records.filled(0).map_err(failure)?;
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
            }
        }
    }
}

// The setup APIs still read into a caller-owned destination. The session driver
// hands the authenticated record directly to the core.
impl AsyncRead for SealedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let Some(mut record) = ready!(this.poll_record(cx))? else {
                return Poll::Ready(Ok(()));
            };
            let n = record.copy_prefix(out.remaining(), |data| out.put_slice(data));
            if n == 0 {
                continue;
            }
            if !record.as_ref().is_empty() {
                this.remainder = Some(record);
            }
            return Poll::Ready(Ok(()));
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
    memory_wait: Option<std::sync::Arc<crate::proto::memory::BudgetWait>>,
    /// The error that failed the direction after its write was reported.
    error: Option<io::ErrorKind>,
}

impl SealedWrite {
    pub(super) fn set_workspace(
        &mut self,
        workspace: Option<std::sync::Arc<crate::proto::memory::WriteWorkspace>>,
    ) {
        self.records.set_workspace(workspace);
    }

    fn poll_memory(&mut self, cx: &Context<'_>, len: usize) -> Poll<()> {
        loop {
            let epoch = self
                .records
                .workspace()
                .map(|space| space.domain().release_epoch());
            if self.records.prepare(len) {
                self.memory_wait = None;
                return Poll::Ready(());
            }
            let space = self
                .records
                .workspace()
                .expect("only managed writer space can be denied");
            if !space
                .domain()
                .watch(epoch.unwrap(), &mut self.memory_wait, cx.waker())
            {
                return Poll::Pending;
            }
        }
    }
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
        ready!(this.poll_memory(cx, buf.len()));
        this.records.seal_prepared(buf).map_err(io::Error::other)?;
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
    write_unit_progress(p, unit, &mut 0, &mut false).await
}

async fn write_unit_progress(
    p: &mut PipeIo,
    unit: &[u8],
    accepted: &mut usize,
    attempted: &mut bool,
) -> io::Result<()> {
    if unit.is_empty() {
        return Ok(());
    }
    let w = p
        .writer
        .as_mut()
        .ok_or(io::Error::from(io::ErrorKind::BrokenPipe))?;
    let atomic = p.framing == Framing::Records;
    let mut rest = crate::Chunk::copy_from_slice(unit);
    std::future::poll_fn(|cx| {
        while !rest.is_empty() {
            *attempted = true;
            let progress = match &mut *w {
                Writer::Io(w) => w.as_mut().poll_write(cx, &rest),
                Writer::Sealed(w) => w.as_mut().poll_write(cx, &rest),
                Writer::Chunks(w) => {
                    let mut chunks = [rest.clone()];
                    w.as_mut().poll_write_chunks(cx, &mut chunks)
                }
                Writer::Stream(w) => Pin::new(w).poll_write(cx, &rest),
            };
            let Poll::Ready(result) = progress else {
                // Plain AsyncWrite and our sealed and stream writers take
                // no bytes on Pending. Join chunks use the separate path.
                *attempted = false;
                return Poll::Pending;
            };
            let n = result?;
            if n == 0 || atomic && n != rest.len() {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            *accepted += n;
            let _ = rest.split_to(n);
        }
        *attempted = false;
        w.poll_flush(cx)
    })
    .await
}

/// Writes a Join and preserves a submitted chunk call across cancellation.
pub(crate) async fn write_join_unit(
    pipe: &mut PipeIo,
    mut write: JoinWrite<Tokio>,
) -> io::Result<()> {
    if write.unit.is_empty() {
        write.settle(false);
        return Ok(());
    }
    if !matches!(pipe.writer, Some(Writer::Chunks(_))) {
        let result =
            write_unit_progress(pipe, &write.unit, &mut write.accepted, &mut write.attempted).await;
        write.settle(result.is_err());
        return result;
    }
    let Some(Writer::Chunks(writer)) = pipe.writer.take() else {
        unreachable!("chunk writer");
    };
    let mut submission = JoinChunkDrain(Some(JoinChunkOutput {
        rest: crate::Chunk::copy_from_slice(&write.unit),
        writer,
        write,
        atomic: pipe.framing == Framing::Records,
        submitted: false,
        _attachment: pipe.attachment().clone(),
    }));
    let output = submission.0.as_mut().expect("Join output");
    let result = poll_fn(|cx| {
        while !output.rest.is_empty() {
            ready!(output.poll_chunk(cx))?;
        }
        output.writer.as_mut().poll_flush(cx)
    })
    .await;
    let mut output = submission.0.take().expect("finished Join output");
    output.write.settle(result.is_err());
    pipe.writer = Some(Writer::Chunks(output.writer));
    result
}

struct JoinChunkOutput {
    writer: Pin<Box<dyn ChunkWrite>>,
    write: JoinWrite<Tokio>,
    rest: crate::Chunk,
    atomic: bool,
    submitted: bool,
    _attachment: Arc<Attachment>,
}

impl JoinChunkOutput {
    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.submitted = false;
        self.write.attempted = true;
        let before = self.rest.len();
        match self
            .writer
            .as_mut()
            .poll_write_chunks(cx, std::slice::from_mut(&mut self.rest))
        {
            Poll::Pending => {
                self.submitted = self.writer.has_submitted_write();
                self.write.attempted = self.submitted;
                Poll::Pending
            }
            Poll::Ready(Ok(n))
                if n != 0
                    && before.checked_sub(self.rest.len()) == Some(n)
                    && (!self.atomic || n == before) =>
            {
                self.write.accepted += n;
                self.write.attempted = false;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }
}

struct JoinChunkDrain(Option<JoinChunkOutput>);

impl Drop for JoinChunkDrain {
    fn drop(&mut self) {
        if let Some(mut output) = self.0.take()
            && output.submitted
        {
            // Keep the same writer and buffers. Finish the one submitted
            // call, leaving any unsubmitted suffix withdrawn.
            super::tokio::spawn_drain(
                async move {
                    let result = poll_fn(|cx| output.poll_chunk(cx)).await;
                    output.write.settle(result.is_err());
                },
                super::DRAIN_LIMIT,
            );
        }
    }
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
