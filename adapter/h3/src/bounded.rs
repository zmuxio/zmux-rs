//! The QUIC layer under h3 with a byte bound on HTTP/3 field sections.
//!
//! h3 buffers a whole HEADERS frame (and any other frame but DATA) before
//! it decodes it, and checks the field section size only after; quinn
//! gives the flow-control credit back as h3 reads. A peer could make h3
//! buffer an unbounded frame on every stream it may open. The receiving
//! halves here follow the frame headers of the bytes they hand h3 and fail
//! a stream (`H3_EXCESSIVE_LOAD`) whose frame other than DATA is longer
//! than [`MAX_FIELD_SECTION`] before h3 buffers it, so what h3 holds per
//! stream is bounded by that and the stream window. DATA payloads pass
//! through unread; non-control unidirectional streams (QPACK, unknown) too.

use std::io;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};

/// The largest HTTP/3 field section (and frame other than DATA) either end
/// takes, 64 KiB: h3's `max_field_section_size` on both ends, and the
/// frame bound of [`RecvStream`].
pub(crate) const MAX_FIELD_SECTION: u64 = 64 * 1024;

/// `H3_EXCESSIVE_LOAD` (RFC 9114 Section 8.1).
const H3_EXCESSIVE_LOAD: u64 = 0x0107;

/// What the next byte of a stream is.
#[derive(Debug, Clone, Copy)]
enum Scan {
    /// A variable-length integer of `part`: `left` bytes still to come
    /// (0 before its first byte), the value so far.
    Varint { part: Part, left: u8, value: u64 },
    /// The payload of a frame, this many bytes still to come.
    Payload(u64),
    /// Not followed (DATA-free non-control unidirectional stream).
    Free,
    /// Failed: a frame over the bound.
    Over,
}

#[derive(Debug, Clone, Copy)]
enum Part {
    /// The type of a unidirectional stream.
    StreamType,
    FrameType,
    /// A frame's length; whether the frame is DATA.
    Length {
        data: bool,
    },
}

impl Scan {
    const fn varint(part: Part) -> Self {
        Self::Varint {
            part,
            left: 0,
            value: 0,
        }
    }

    /// Follows `b`; false once a frame other than DATA is over the bound.
    fn scan(&mut self, mut b: &[u8]) -> bool {
        while let Some((&byte, rest)) = b.split_first() {
            match self {
                Self::Free => return true,
                Self::Over => return false,
                Self::Payload(n) => {
                    let k = usize::try_from(*n).unwrap_or(usize::MAX).min(b.len());
                    *n -= k as u64;
                    b = &b[k..];
                    if *n == 0 {
                        *self = Self::varint(Part::FrameType);
                    }
                }
                Self::Varint { part, left, value } => {
                    b = rest;
                    if *left == 0 {
                        *left = 1 << (byte >> 6);
                        *value = u64::from(byte & 0x3f);
                    } else {
                        *value = (*value << 8) | u64::from(byte);
                    }
                    *left -= 1;
                    if *left > 0 {
                        continue;
                    }
                    let v = *value;
                    *self = match *part {
                        // 0x00: the control stream, framed; the others are
                        // not followed.
                        Part::StreamType if v == 0 => Self::varint(Part::FrameType),
                        Part::StreamType => Self::Free,
                        Part::FrameType => Self::varint(Part::Length { data: v == 0 }),
                        Part::Length { data } if !data && v > MAX_FIELD_SECTION => Self::Over,
                        Part::Length { .. } if v == 0 => Self::varint(Part::FrameType),
                        Part::Length { .. } => Self::Payload(v),
                    };
                }
            }
        }
        !matches!(self, Self::Over)
    }
}

fn excessive() -> StreamErrorIncoming {
    StreamErrorIncoming::Unknown(Box::new(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP/3 frame over the field section bound",
    )))
}

/// A receiving half whose frames other than DATA are bounded to 64 KiB.
pub struct RecvStream {
    inner: h3_quinn::RecvStream,
    scan: Scan,
}

impl RecvStream {
    fn request(inner: h3_quinn::RecvStream) -> Self {
        Self {
            inner,
            scan: Scan::varint(Part::FrameType),
        }
    }

    fn unidirectional(inner: h3_quinn::RecvStream) -> Self {
        Self {
            inner,
            scan: Scan::varint(Part::StreamType),
        }
    }
}

impl std::fmt::Debug for RecvStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvStream").finish_non_exhaustive()
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if matches!(self.scan, Scan::Over) {
            return Poll::Ready(Err(excessive()));
        }
        let data = std::task::ready!(self.inner.poll_data(cx))?;
        if let Some(b) = &data
            && !self.scan.scan(b)
        {
            self.inner.stop_sending(H3_EXCESSIVE_LOAD);
            return Poll::Ready(Err(excessive()));
        }
        Poll::Ready(Ok(data))
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

/// A request stream with a bounded receiving half.
pub(crate) struct BidiStream<B: Buf> {
    send: h3_quinn::SendStream<B>,
    recv: RecvStream,
}

impl<B: Buf> BidiStream<B> {
    fn new(bidi: h3_quinn::BidiStream<B>) -> Self {
        let (send, recv) = quic::BidiStream::split(bidi);
        Self {
            send,
            recv: RecvStream::request(recv),
        }
    }
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = h3_quinn::SendStream<B>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl<B: Buf> quic::SendStreamUnframed<B> for BidiStream<B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.send.poll_send(cx, buf)
    }
}

/// h3-quinn's connection with bounded receiving halves.
pub(crate) struct Connection(h3_quinn::Connection);

impl Connection {
    pub(crate) fn new(conn: quinn::Connection) -> Self {
        Self(h3_quinn::Connection::new(conn))
    }
}

impl<B: Buf> quic::Connection<B> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        quic::Connection::<B>::poll_accept_recv(&mut self.0, cx).map_ok(RecvStream::unidirectional)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        quic::Connection::<B>::poll_accept_bidi(&mut self.0, cx).map_ok(BidiStream::new)
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams(quic::Connection::<B>::opener(&self.0))
    }
}

impl<B: Buf> quic::OpenStreams<B> for Connection {
    type BidiStream = BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.0, cx).map_ok(BidiStream::new)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.0, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.0, code, reason);
    }
}

/// h3-quinn's stream opener with bounded receiving halves.
#[derive(Clone)]
pub(crate) struct OpenStreams(h3_quinn::OpenStreams);

impl std::fmt::Debug for OpenStreams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenStreams").finish_non_exhaustive()
    }
}

impl<B: Buf> quic::OpenStreams<B> for OpenStreams {
    type BidiStream = BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.0, cx).map_ok(BidiStream::new)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.0, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.0, code, reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_other_than_data_are_bounded_before_they_are_read() {
        // DATA of any length passes; HEADERS at the bound passes.
        let mut s = Scan::varint(Part::FrameType);
        assert!(s.scan(&[0x00, 0x80, 0x10, 0x00, 0x00]));
        assert!(s.scan(&vec![0; 0x10_0000]));
        assert!(s.scan(&[0x01, 0x80, 0x01, 0x00, 0x00]));
        assert!(s.scan(&vec![0; 0x1_0000]));
        // A HEADERS frame one over, its length split across reads.
        let mut s = Scan::varint(Part::FrameType);
        assert!(s.scan(&[0x01, 0x80, 0x01]));
        assert!(!s.scan(&[0x00, 0x01]));
        assert!(!s.scan(&[0]));
        // An unknown frame type over the bound fails too.
        let mut s = Scan::varint(Part::FrameType);
        assert!(!s.scan(&[0x40, 0x21, 0x80, 0x10, 0x00, 0x00]));
        // The control stream is framed; another unidirectional one is not.
        let mut s = Scan::varint(Part::StreamType);
        assert!(!s.scan(&[0x00, 0x04, 0x80, 0x10, 0x00, 0x00]));
        let mut s = Scan::varint(Part::StreamType);
        assert!(s.scan(&[0x02, 0x04, 0x80, 0x10, 0x00, 0x00]));
    }
}
