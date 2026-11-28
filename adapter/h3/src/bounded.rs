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

use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll};
use zmux::adapter::SetupRead;

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
    inner: Receiver,
    scan: Scan,
    fallback_stop: Option<FallbackStop>,
    fallback_ended: bool,
}

enum Receiver {
    H3(h3_quinn::RecvStream),
    Request(SetupRead<quinn::RecvStream>, StreamId),
}

fn chunk(
    recv: &mut quinn::RecvStream,
    cx: &mut Context<'_>,
) -> Poll<Result<Option<quinn::Chunk>, quinn::ReadError>> {
    pin!(recv.read_chunk(usize::MAX, true)).poll(cx)
}

fn connection_error(error: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: close.error_code.into_inner(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        other => ConnectionErrorIncoming::Undefined(Arc::new(other)),
    }
}

impl quic::RecvStream for Receiver {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let result = match self {
            Self::H3(stream) => return stream.poll_data(cx),
            Self::Request(reader, _) => reader.poll(cx, chunk),
        };
        result
            .map_ok(|chunk| chunk.map(|c| c.bytes))
            .map_err(|error| match error {
                quinn::ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
                    error_code: code.into_inner(),
                },
                quinn::ReadError::ConnectionLost(e) => {
                    StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error: connection_error(e),
                    }
                }
                other => StreamErrorIncoming::Unknown(Box::new(other)),
            })
    }

    fn stop_sending(&mut self, code: u64) {
        let error = quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX);
        match self {
            Self::H3(s) => s.stop_sending(code),
            Self::Request(reader, _) => {
                let _ = reader.with(|r| r.stop(error));
            }
        }
    }

    fn recv_id(&self) -> StreamId {
        match self {
            Self::H3(s) => s.recv_id(),
            Self::Request(_, id) => *id,
        }
    }
}

impl RecvStream {
    fn request(inner: h3_quinn::RecvStream) -> Self {
        Self {
            inner: Receiver::H3(inner),
            scan: Scan::varint(Part::FrameType),
            fallback_stop: None,
            fallback_ended: false,
        }
    }

    fn unidirectional(inner: h3_quinn::RecvStream) -> Self {
        Self {
            inner: Receiver::H3(inner),
            scan: Scan::varint(Part::StreamType),
            fallback_stop: None,
            fallback_ended: false,
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
        if self.fallback_ended {
            return Poll::Ready(Ok(None));
        }
        if let Some(stop) = self.fallback_stop.as_ref().and_then(|stop| stop.0.get())
            && stop
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_mut()
                .poll(cx)
                .is_ready()
        {
            self.fallback_ended = true;
            self.fallback_stop = None;
            self.inner
                .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED.value());
            return Poll::Ready(Ok(None));
        }
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

/// The sending half of a request, also used by a host fallback.
pub struct SendStream<B: Buf> {
    sender: Sender<B>,
    ended: bool,
}

enum Sender<B: Buf> {
    H3(h3_quinn::SendStream<B>),
    Request(quinn::SendStream, Option<WriteBuf<B>>),
}

impl<B: Buf> SendStream<B> {
    fn h3(s: h3_quinn::SendStream<B>) -> Self {
        Self::new(Sender::H3(s))
    }

    fn new(sender: Sender<B>) -> Self {
        Self {
            sender,
            ended: false,
        }
    }
}

fn write_error(error: quinn::WriteError) -> StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(e) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: connection_error(e),
        },
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}

fn poll_bytes(
    stream: &mut quinn::SendStream,
    cx: &mut Context<'_>,
    buf: &mut impl Buf,
) -> Poll<Result<usize, StreamErrorIncoming>> {
    let n = std::task::ready!(Pin::new(stream).poll_write(cx, buf.chunk())).map_err(write_error)?;
    buf.advance(n);
    Poll::Ready(Ok(n))
}

impl<B: Buf> quic::SendStream<B> for SendStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match &mut self.sender {
            Sender::H3(s) => s.poll_ready(cx),
            Sender::Request(s, pending) => {
                if let Some(buf) = pending {
                    while buf.has_remaining() {
                        std::task::ready!(poll_bytes(s, cx, buf))?;
                    }
                }
                *pending = None;
                Poll::Ready(Ok(()))
            }
        }
    }
    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        match &mut self.sender {
            Sender::H3(s) => s.send_data(data),
            Sender::Request(_, slot @ None) => {
                *slot = Some(data.into());
                Ok(())
            }
            Sender::Request(_, Some(_)) => Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "request stream write already pending".into(),
                ),
            }),
        }
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        std::task::ready!(self.poll_ready(cx))?;
        let result = match &mut self.sender {
            Sender::H3(s) => s.poll_finish(cx),
            Sender::Request(s, _) => Poll::Ready(
                s.finish()
                    .map_err(|e| StreamErrorIncoming::Unknown(Box::new(e))),
            ),
        };
        if matches!(result, Poll::Ready(Ok(()))) {
            self.ended = true;
        }
        result
    }
    fn reset(&mut self, code: u64) {
        if std::mem::replace(&mut self.ended, true) {
            return;
        }
        match &mut self.sender {
            Sender::H3(s) => s.reset(code),
            Sender::Request(s, _) => {
                let _ = s.reset(quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX));
            }
        }
    }
    fn send_id(&self) -> StreamId {
        match &self.sender {
            Sender::H3(s) => s.send_id(),
            Sender::Request(s, _) => u64::from(s.id()).try_into().expect("QUIC stream ID"),
        }
    }
}

impl<B: Buf> Drop for SendStream<B> {
    fn drop(&mut self) {
        quic::SendStream::<B>::reset(self, super::carrier_failed().value());
    }
}

impl<B: Buf> quic::SendStreamUnframed<B> for SendStream<B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        match &mut self.sender {
            Sender::H3(s) => s.poll_send(cx, buf),
            Sender::Request(s, _) => poll_bytes(s, cx, buf),
        }
    }
}

/// A request stream with a bounded receiving half.
pub(crate) struct BidiStream<B: Buf> {
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B: Buf> BidiStream<B> {
    fn new(bidi: h3_quinn::BidiStream<B>) -> Self {
        let (send, recv) = quic::BidiStream::split(bidi);
        Self {
            send: SendStream::h3(send),
            recv: RecvStream::request(recv),
        }
    }
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = SendStream<B>;
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
pub(crate) struct Connection {
    streams: BoundedOpen<h3_quinn::Connection>,
    incoming: Option<Incoming>,
}

pub(crate) type Stopped = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;

type ListenerClosed = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Armed only when the request goes to the ordinary HTTP fallback.
#[derive(Clone, Default)]
pub(crate) struct FallbackStop(Arc<OnceLock<Mutex<ListenerClosed>>>);

impl FallbackStop {
    pub(crate) fn bind(&self, closed: impl Future<Output = ()> + Send + 'static) {
        assert!(self.0.set(Mutex::new(Box::pin(closed))).is_ok());
    }
}
type Accepted = Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>;

/// h3 accepts one request per poll. Hand its `STOP_SENDING` wait to the
/// same request before polling accept again; unresolved heads own their wait.
#[derive(Clone, Default)]
pub(crate) struct RequestStop(Arc<Mutex<Option<(Stopped, FallbackStop)>>>);

impl RequestStop {
    pub(crate) fn take(&self) -> (Stopped, FallbackStop) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .expect("just accepted a request")
    }
}

struct Incoming {
    conn: quinn::Connection,
    accept: Option<Pin<Box<dyn Future<Output = Accepted> + Send + Sync>>>,
    stop: RequestStop,
}

impl Connection {
    pub(crate) fn serving(conn: quinn::Connection, stop: RequestStop) -> Self {
        Self {
            streams: BoundedOpen {
                inner: h3_quinn::Connection::new(conn.clone()),
                owns_close: true,
            },
            incoming: Some(Incoming {
                conn,
                accept: None,
                stop,
            }),
        }
    }

    pub(crate) fn new(conn: quinn::Connection, owns_close: bool) -> Self {
        Self {
            streams: BoundedOpen {
                inner: h3_quinn::Connection::new(conn),
                owns_close,
            },
            incoming: None,
        }
    }
}

impl<B: Buf> quic::Connection<B> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        quic::Connection::<B>::poll_accept_recv(&mut self.streams.inner, cx)
            .map_ok(RecvStream::unidirectional)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let Some(incoming) = &mut self.incoming else {
            return quic::Connection::<B>::poll_accept_bidi(&mut self.streams.inner, cx)
                .map_ok(BidiStream::new);
        };
        let accept = incoming.accept.get_or_insert_with(|| {
            let conn = incoming.conn.clone();
            Box::pin(async move { conn.accept_bi().await })
        });
        let result = std::task::ready!(accept.as_mut().poll(cx));
        incoming.accept = None;
        let (send, recv) = result.map_err(connection_error)?;
        let id = u64::from(recv.id()).try_into().expect("QUIC stream ID");
        let (body, reading) = SetupRead::new(recv);
        let stopped = send.stopped();
        let cancel = async move {
            let mut stopped = pin!(stopped);
            let mut watch_reset = true;
            std::future::poll_fn(|cx| {
                if stopped.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
                if watch_reset
                    && let Some(result) =
                        reading.poll(cx, |r, cx| pin!(r.received_reset()).poll(cx))
                {
                    match result {
                        Poll::Ready(Ok(None)) => watch_reset = false, // ordinary request-body FIN
                        Poll::Ready(_) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                }
                Poll::Pending
            })
            .await;
        };
        let fallback_stop = FallbackStop::default();
        *incoming
            .stop
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner) =
            Some((Box::pin(cancel), fallback_stop.clone()));
        Poll::Ready(Ok(BidiStream {
            send: SendStream::new(Sender::Request(send, None)),
            recv: RecvStream {
                inner: Receiver::Request(body, id),
                scan: Scan::varint(Part::FrameType),
                fallback_stop: Some(fallback_stop),
                fallback_ended: false,
            },
        }))
    }

    fn opener(&self) -> Self::OpenStreams {
        BoundedOpen {
            inner: quic::Connection::<B>::opener(&self.streams.inner),
            owns_close: self.streams.owns_close,
        }
    }
}

impl<B: Buf> quic::OpenStreams<B> for Connection {
    type BidiStream = BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        self.streams.poll_open_bidi(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.streams.poll_open_send(cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.streams, code, reason);
    }
}

/// h3-quinn's stream opener with bounded receiving halves.
#[derive(Clone)]
pub(crate) struct BoundedOpen<T> {
    inner: T,
    owns_close: bool,
}

pub(crate) type OpenStreams = BoundedOpen<h3_quinn::OpenStreams>;

impl<T> std::fmt::Debug for BoundedOpen<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenStreams").finish_non_exhaustive()
    }
}

impl<B, T> quic::OpenStreams<B> for BoundedOpen<T>
where
    B: Buf,
    T: quic::OpenStreams<
            B,
            BidiStream = h3_quinn::BidiStream<B>,
            SendStream = h3_quinn::SendStream<B>,
        >,
{
    type BidiStream = BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx).map_ok(BidiStream::new)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        if self.owns_close {
            quic::OpenStreams::<B>::close(&mut self.inner, code, reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "rustls-ring")]
    mod net {
        use crate as zmux_h3;
        include!("../tests/common/net.rs");
    }

    #[cfg(feature = "rustls-ring")]
    #[tokio::test]
    async fn request_data_takes_the_direct_path_after_handoff() {
        let (server, client, addr) = net::endpoints(&crate::Options::default());
        let (peer, local) = tokio::join!(
            client.connect(addr, &addr.ip().to_string()).unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let peer = peer.unwrap();
        let stop = RequestStop::default();
        let mut conn = Connection::serving(local.unwrap(), stop.clone());
        let (mut send, _recv) = peer.open_bi().await.unwrap();
        send.write_all(b"a").await.unwrap();
        let mut stream =
            std::future::poll_fn(|cx| quic::Connection::<Bytes>::poll_accept_bidi(&mut conn, cx))
                .await
                .unwrap();
        let mut watcher = Some(stop.take().0);
        let body = &mut stream.recv.inner;
        for (index, expected) in b"abc".iter().copied().enumerate() {
            let bytes = std::future::poll_fn(|cx| quic::RecvStream::poll_data(body, cx))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bytes.as_ref(), &[expected]);
            let Receiver::Request(reader, _) = body else {
                panic!("request stream")
            };
            assert_eq!(reader.observing(), index == 0);
            if index == 0 {
                drop(watcher.take());
            }
            send.write_all(&[expected + 1]).await.unwrap();
        }
    }

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
