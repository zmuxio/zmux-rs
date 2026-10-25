//! Interoperability with an independent QMux implementation: the `qmux`
//! crate 0.6.2 (draft-ietf-quic-qmux-02), as a plain QMux peer (SPEC.md
//! Section 13, CONFORMANCE.md Section 6).
//!
//! A crate of its own, outside the zmux workspace, so that its
//! dependencies are fetched only when it runs:
//!
//! ```sh
//! cargo test --manifest-path interop/qmux/Cargo.toml -- --nocapture
//! ```
//!
//! Every run puts zmux in one role (TCP client or server) against the
//! `qmux` crate in the other, over TCP loopback or an in-memory duplex, and
//! covers:
//!
//! - establishment: zmux's transport parameters, zmux parameters and GREASE
//!   included, are accepted by the peer; zmux detects a plain QMux peer;
//! - bidirectional and unidirectional streams opened by either side, with
//!   more data than the initial windows of both sides (MAX_STREAM_DATA and
//!   MAX_DATA updates both ways);
//! - RESET_STREAM and STOP_SENDING in both directions, with their codes;
//! - QX_PING both ways and a DATAGRAM each way;
//! - a graceful close by either side, with code and reason.
//!
//! The bytes on the carrier are tapped in both directions and decoded
//! afterwards. Towards the plain peer zmux may send only QMux-02 frames
//! (SPEC.md Section 13.2): no GOAWAY, PRIORITY_UPDATE or PIPE_* frame, no
//! out-of-order or repeated STREAM data, no record above the peer's
//! `max_record_size`, and QX_TRANSPORT_PARAMETERS exactly once, first.

use std::collections::{BTreeMap, HashMap};
use std::io::IoSlice;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use qmux::transport::Stream as QmuxTransport;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use web_transport_trait::{
    Error as _, RecvStream as QRecv, SendStream as QSend, Session as QSession, Stats as _,
};
use zmux::proto::frame::Frame;
use zmux::proto::params::RawParameters;
use zmux::proto::{Event, Gates, RecordReader, TransportParameters};
use zmux::{PipeIo, SessionError, StreamError, VarInt};

/// The bound of every run; a hang is a bug.
const RUN_TIMEOUT: Duration = Duration::from_secs(60);
/// More than the initial session windows of both sides (1 MiB each).
const BULK: usize = 4 * 1024 * 1024;
/// More than the initial stream windows of both sides (256 KiB each).
const UNI_BULK: usize = 1024 * 1024;
/// The `qmux` crate's default `max_record_size` (QMux-02's default).
const QMUX_MAX_RECORD: u64 = 16382;
/// zmux's advertised `max_record_size`.
const ZMUX_MAX_RECORD: u64 = 65535;

#[derive(Debug, Clone, Copy)]
enum Carrier {
    Tcp,
    Duplex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closer {
    Zmux,
    Qmux,
}

// ---------------------------------------------------------------------------
// Carrier taps

/// Bytes seen on one direction of the zmux carrier.
#[derive(Clone, Default)]
struct Tap(Arc<Mutex<Vec<u8>>>);

impl Tap {
    fn push(&self, b: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(b);
    }

    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct TapWrite<W> {
    inner: W,
    tap: Tap,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TapWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.tap.push(&buf[..n]);
        }
        r
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = r {
            let mut left = n;
            for b in bufs {
                let k = left.min(b.len());
                self.tap.push(&b[..k]);
                left -= k;
                if left == 0 {
                    break;
                }
            }
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct TapRead<R> {
    inner: R,
    tap: Tap,
}

impl<R: AsyncRead + Unpin> AsyncRead for TapRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            self.tap.push(&buf.filled()[before..]);
        }
        r
    }
}

// ---------------------------------------------------------------------------
// Establishment

struct Pair {
    zmux: zmux::Session,
    qmux: qmux::Session,
    /// What zmux wrote.
    out: Tap,
    /// What zmux read (what the `qmux` crate wrote).
    inn: Tap,
}

fn zmux_config() -> zmux::Config {
    let mut c = zmux::Config::default();
    c.enable_datagrams = true;
    // CONFORMANCE.md: the full unidirectional credit at once.
    c.max_incoming_uni_streams = Some(256);
    c
}

fn qmux_config() -> qmux::Config {
    let mut c = qmux::Config::new(qmux::Version::QMux02);
    // The crate's RTT probe at a short cadence (QX_PING requests towards
    // zmux throughout the run).
    c.rtt_interval = Duration::from_millis(20);
    c
}

async fn qmux_establish<T>(io: T, zmux_client: bool) -> qmux::Session
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    let c = qmux_config();
    let t = QmuxTransport::new(io, c.version, c.max_record_size);
    let s = if zmux_client {
        qmux::Session::accept(t, c).await
    } else {
        qmux::Session::connect(t, c).await
    };
    s.expect("qmux establishment")
}

async fn zmux_establish(io: PipeIo, zmux_client: bool) -> zmux::Session {
    let s = if zmux_client {
        zmux::Session::connect(io, zmux_config()).await
    } else {
        zmux::Session::accept(io, zmux_config()).await
    };
    s.expect("zmux establishment")
}

/// A zmux carrier over `tcp` with taps, queried and tuned like
/// [`PipeIo::tcp`].
fn tapped_tcp(tcp: TcpStream, out: &Tap, inn: &Tap) -> PipeIo {
    tcp.set_nodelay(true).unwrap();
    #[cfg(unix)]
    let socket = std::os::fd::AsFd::as_fd(&tcp).try_clone_to_owned().unwrap();
    #[cfg(windows)]
    let socket = std::os::windows::io::AsSocket::as_socket(&tcp)
        .try_clone_to_owned()
        .unwrap();
    let (r, w) = tcp.into_split();
    let io = PipeIo::from_halves(
        TapRead {
            inner: r,
            tap: inn.clone(),
        },
        TapWrite {
            inner: w,
            tap: out.clone(),
        },
    );
    #[cfg(any(unix, windows))]
    let io = io.with_tcp_socket(&socket);
    io
}

async fn establish(carrier: Carrier, zmux_client: bool) -> Pair {
    let (out, inn) = (Tap::default(), Tap::default());
    let (zmux, qmux) = match carrier {
        Carrier::Tcp => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (dialed, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
            let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap().0);
            // The TCP client is the initiator (SPEC.md Section 5.6).
            let (z, q) = if zmux_client {
                (dialed, accepted)
            } else {
                (accepted, dialed)
            };
            q.set_nodelay(true).unwrap();
            tokio::join!(
                zmux_establish(tapped_tcp(z, &out, &inn), zmux_client),
                qmux_establish(q, zmux_client),
            )
        }
        Carrier::Duplex => {
            let (z, q) = tokio::io::duplex(256 * 1024);
            let (r, w) = tokio::io::split(z);
            let io = PipeIo::from_halves(
                TapRead {
                    inner: r,
                    tap: inn.clone(),
                },
                TapWrite {
                    inner: w,
                    tap: out.clone(),
                },
            );
            tokio::join!(
                zmux_establish(io, zmux_client),
                qmux_establish(q, zmux_client)
            )
        }
    };
    Pair {
        zmux,
        qmux,
        out,
        inn,
    }
}

// ---------------------------------------------------------------------------
// Scenarios

fn pattern(len: usize, seed: u8) -> Bytes {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[1] ^ seed)
        .collect::<Vec<u8>>()
        .into()
}

const RESET_BY_ZMUX: u32 = 0x5a5a_0001;
const STOP_BY_ZMUX: u32 = 0x5a5a_0002;
const RESET_BY_QMUX: u32 = 0x0a0a_0003;
const STOP_BY_QMUX: u32 = 0x0a0a_0004;

/// Reads a zmux stream until at least `n` bytes arrived.
async fn zmux_read_at_least(recv: &mut zmux::RecvStream, n: usize) -> usize {
    let mut got = 0;
    while got < n {
        match recv.read_chunk(64 * 1024).await.unwrap() {
            Some(c) => got += c.len(),
            None => panic!("stream ended after {got} bytes"),
        }
    }
    got
}

/// Reads a qmux stream until at least `n` bytes arrived.
async fn qmux_read_at_least(recv: &mut qmux::RecvStream, n: usize) -> usize {
    let mut got = 0;
    while got < n {
        match recv.read_chunk(64 * 1024).await.unwrap() {
            Some(c) => got += c.len(),
            None => panic!("stream ended after {got} bytes"),
        }
    }
    got
}

/// zmux opens, the `qmux` crate answers.
async fn zmux_drives(z: &zmux::Session, q: &qmux::Session) {
    // 1. Bidirectional stream: 4 MiB echoed while it is being sent.
    let data = pattern(BULK, 1);
    let zmux_side = async {
        let (mut send, mut recv) = z.open_bi().await.unwrap();
        let writer = async {
            send.write_chunk(data.clone()).await.unwrap();
            send.finish().unwrap();
        };
        let (_, back) = tokio::join!(writer, recv.read_to_end(2 * BULK));
        assert!(back.unwrap() == data, "bidirectional echo differs");
    };
    let qmux_side = async {
        let (mut send, mut recv) = q.accept_bi().await.unwrap();
        while let Some(chunk) = recv.read_chunk(64 * 1024).await.unwrap() {
            send.write_chunk(chunk).await.unwrap();
        }
        send.finish().unwrap();
        send.closed().await.unwrap();
    };
    tokio::join!(zmux_side, qmux_side);

    // 2. Unidirectional stream, answered on a unidirectional stream.
    let data = pattern(UNI_BULK, 2);
    let zmux_side = async {
        let mut send = z.open_uni().await.unwrap();
        send.write_chunk(data.clone()).await.unwrap();
        send.finish().unwrap();
        let mut back = z.accept_uni().await.unwrap();
        assert!(back.read_to_end(2 * UNI_BULK).await.unwrap() == data);
    };
    let qmux_side = async {
        let mut recv = q.accept_uni().await.unwrap();
        let got = recv.read_all().await.unwrap();
        let mut send = q.open_uni().await.unwrap();
        send.write_chunk(got).await.unwrap();
        send.finish().unwrap();
        send.closed().await.unwrap();
    };
    tokio::join!(zmux_side, qmux_side);

    // 3. RESET_STREAM from zmux, after data the peer has partly read.
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let zmux_side = async {
        let (mut send, mut recv) = z.open_bi().await.unwrap();
        send.write_chunk(pattern(100_000, 3)).await.unwrap();
        seen_rx.await.unwrap();
        send.reset(VarInt::from_u32(RESET_BY_ZMUX)).unwrap();
        assert!(recv.read_to_end(16).await.unwrap().is_empty());
    };
    let qmux_side = async {
        let (mut send, mut recv) = q.accept_bi().await.unwrap();
        send.finish().unwrap();
        qmux_read_at_least(&mut recv, 1000).await;
        seen_tx.send(()).unwrap();
        let err = loop {
            match recv.read_chunk(64 * 1024).await {
                Ok(Some(_)) => {}
                Ok(None) => panic!("qmux read a reset stream as complete"),
                Err(e) => break e,
            }
        };
        assert_eq!(err.stream_error(), Some(RESET_BY_ZMUX), "{err:?}");
    };
    tokio::join!(zmux_side, qmux_side);

    // 4. STOP_SENDING from zmux while the peer writes.
    let zmux_side = async {
        let (mut send, mut recv) = z.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        send.finish().unwrap();
        zmux_read_at_least(&mut recv, 64 * 1024).await;
        recv.stop(VarInt::from_u32(STOP_BY_ZMUX)).unwrap();
    };
    let qmux_side = async {
        let (mut send, mut recv) = q.accept_bi().await.unwrap();
        assert_eq!(&recv.read_all().await.unwrap()[..], b"x");
        let chunk = Bytes::from(vec![7u8; 1024]);
        let err = loop {
            if let Err(e) = send.write_chunk(chunk.clone()).await {
                break e;
            }
        };
        assert_eq!(err.stream_error(), Some(STOP_BY_ZMUX), "{err:?}");
    };
    tokio::join!(zmux_side, qmux_side);
}

/// The `qmux` crate opens, zmux answers.
async fn qmux_drives(z: &zmux::Session, q: &qmux::Session) {
    // 5. Bidirectional stream: 4 MiB echoed by zmux.
    let data = pattern(BULK, 5);
    let qmux_side = async {
        let (mut send, mut recv) = q.open_bi().await.unwrap();
        let writer = async {
            send.write_chunk(data.clone()).await.unwrap();
            send.finish().unwrap();
        };
        let (_, back) = tokio::join!(writer, recv.read_all());
        assert!(back.unwrap() == data, "bidirectional echo differs");
    };
    let zmux_side = async {
        let (mut send, mut recv) = z.accept_bi().await.unwrap();
        while let Some(chunk) = recv.read_chunk(64 * 1024).await.unwrap() {
            send.write_chunk(chunk).await.unwrap();
        }
        send.finish().unwrap();
    };
    tokio::join!(zmux_side, qmux_side);

    // 6. Unidirectional stream, answered on a unidirectional stream.
    let data = pattern(UNI_BULK, 6);
    let qmux_side = async {
        let mut send = q.open_uni().await.unwrap();
        send.write_chunk(data.clone()).await.unwrap();
        send.finish().unwrap();
        let mut back = q.accept_uni().await.unwrap();
        assert!(back.read_all().await.unwrap() == data);
    };
    let zmux_side = async {
        let mut recv = z.accept_uni().await.unwrap();
        let got = recv.read_to_end(2 * UNI_BULK).await.unwrap();
        let mut send = z.open_uni().await.unwrap();
        send.write_chunk(got.into()).await.unwrap();
        send.finish().unwrap();
    };
    tokio::join!(zmux_side, qmux_side);

    // 7. RESET_STREAM from the peer.
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let qmux_side = async {
        let (mut send, mut recv) = q.open_bi().await.unwrap();
        send.write_chunk(pattern(100_000, 7)).await.unwrap();
        seen_rx.await.unwrap();
        send.reset(RESET_BY_QMUX);
        assert!(recv.read_all().await.unwrap().is_empty());
    };
    let zmux_side = async {
        let (mut send, mut recv) = z.accept_bi().await.unwrap();
        send.finish().unwrap();
        zmux_read_at_least(&mut recv, 1000).await;
        seen_tx.send(()).unwrap();
        let err = loop {
            match recv.read_chunk(64 * 1024).await {
                Ok(Some(_)) => {}
                Ok(None) => panic!("zmux read a reset stream as complete"),
                Err(e) => break e,
            }
        };
        assert!(
            matches!(err, StreamError::Reset { code, .. } if code == VarInt::from_u32(RESET_BY_QMUX)),
            "{err:?}"
        );
    };
    tokio::join!(zmux_side, qmux_side);

    // 8. STOP_SENDING from the peer while zmux writes.
    let qmux_side = async {
        let (mut send, mut recv) = q.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        send.finish().unwrap();
        qmux_read_at_least(&mut recv, 64 * 1024).await;
        recv.stop(STOP_BY_QMUX);
    };
    let zmux_side = async {
        let (mut send, mut recv) = z.accept_bi().await.unwrap();
        assert_eq!(recv.read_to_end(16).await.unwrap(), b"x");
        let chunk = Bytes::from(vec![9u8; 1024]);
        let err = loop {
            if let Err(e) = send.write_chunk(chunk.clone()).await {
                break e;
            }
        };
        assert_eq!(err, StreamError::Stopped(VarInt::from_u32(STOP_BY_QMUX)));
        assert_eq!(
            send.stopped().await.unwrap(),
            Some(VarInt::from_u32(STOP_BY_QMUX))
        );
    };
    tokio::join!(zmux_side, qmux_side);
}

/// QX_PING and DATAGRAM, both ways.
async fn pings_and_datagrams(z: &zmux::Session, q: &qmux::Session) {
    // zmux's QX_PING request, answered by the peer.
    let rtt = z.ping().await.unwrap();
    assert!(rtt < Duration::from_secs(5));
    // The peer's RTT probe (every 20 ms), answered by zmux.
    let mut waited = Duration::ZERO;
    while q.stats().rtt().is_none() {
        assert!(waited < Duration::from_secs(5), "zmux answered no QX_PING");
        tokio::time::sleep(Duration::from_millis(10)).await;
        waited += Duration::from_millis(10);
    }
    let size = z.max_datagram_size().expect("the peer accepts DATAGRAM");
    assert!(size >= 1000, "{size}");
    let d = pattern(1000, 11);
    z.send_datagram(d.clone()).unwrap();
    assert_eq!(q.recv_datagram().await.unwrap(), d);
    let d = pattern(q.max_datagram_size().min(1200), 12);
    q.send_datagram(d.clone()).unwrap();
    assert_eq!(z.read_datagram().await.unwrap(), d);
}

async fn close(z: &zmux::Session, q: &qmux::Session, closer: Closer) {
    match closer {
        Closer::Zmux => {
            // Graceful: no GOAWAY towards a plain peer, CONNECTION_CLOSE
            // (application) once no stream remains.
            z.shutdown(VarInt::from_u32(42), b"bye").await.unwrap();
            let err = q.closed().await;
            assert_eq!(
                err.session_error(),
                Some((42, "bye".to_string())),
                "{err:?}"
            );
        }
        Closer::Qmux => {
            q.close(7, "done");
            let err = z.closed().await;
            assert_eq!(
                err,
                SessionError::ApplicationClosed {
                    code: VarInt::from_u32(7),
                    reason: Bytes::from_static(b"done"),
                    remote: true,
                }
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Wire checks

#[derive(Default)]
struct StreamTrack {
    frames: u64,
    next: u64,
    fin: bool,
    reset: bool,
}

/// What one direction of the carrier carried.
#[derive(Default)]
struct Wire {
    records: u64,
    wire_len: u64,
    max_record: u64,
    frames: BTreeMap<&'static str, u64>,
    params: Option<Vec<u8>>,
    /// The CONNECTION_CLOSE frames, decoded.
    closes: Vec<String>,
    violations: Vec<String>,
}

fn frame_name(f: &Frame<'_>) -> &'static str {
    match f {
        Frame::Padding(_) => "PADDING",
        Frame::ResetStream(_) => "RESET_STREAM",
        Frame::StopSending(_) => "STOP_SENDING",
        Frame::Stream(_) => "STREAM",
        Frame::MaxData(_) => "MAX_DATA",
        Frame::MaxStreamData(_) => "MAX_STREAM_DATA",
        Frame::MaxStreams(_) => "MAX_STREAMS",
        Frame::DataBlocked(_) => "DATA_BLOCKED",
        Frame::StreamDataBlocked(_) => "STREAM_DATA_BLOCKED",
        Frame::StreamsBlocked(_) => "STREAMS_BLOCKED",
        Frame::ConnectionClose(c) if c.application => "CONNECTION_CLOSE(0x1d)",
        Frame::ConnectionClose(_) => "CONNECTION_CLOSE(0x1c)",
        Frame::ResetStreamAt(_) => "RESET_STREAM_AT",
        Frame::Datagram(_) => "DATAGRAM",
        Frame::TransportParameters(_) => "QX_TRANSPORT_PARAMETERS",
        Frame::QxPing(p) if p.response => "QX_PING(response)",
        Frame::QxPing(_) => "QX_PING(request)",
        Frame::GoAway(_) => "GOAWAY",
        Frame::PriorityUpdate(_) => "PRIORITY_UPDATE",
        Frame::PipeJoin(_) => "PIPE_JOIN",
        Frame::PipeAck(_) => "PIPE_ACK",
        Frame::PipeLane(_) => "PIPE_LANE",
        Frame::PipePing => "PIPE_PING",
        Frame::PipeAbandon(_) => "PIPE_ABANDON",
        Frame::PipeStatus(_) => "PIPE_STATUS",
        _ => "UNKNOWN",
    }
}

/// Decodes one direction. `max_record` is the receiver's `max_record_size`;
/// `strict` applies the rules of SPEC.md Section 13.2 to the sender.
fn decode(bytes: &[u8], max_record: u64, strict: bool) -> Wire {
    let mut w = Wire::default();
    let mut streams: HashMap<u64, StreamTrack> = HashMap::new();
    let mut reader = RecordReader::new(max_record);
    let mut input = bytes;
    let mut first = true;
    loop {
        let ev = match reader.read(&mut input, &Gates::ALL) {
            Ok(Some(ev)) => ev,
            Ok(None) => break,
            Err(e) => {
                w.violations.push(format!("undecodable: {e:?}"));
                break;
            }
        };
        let f = match ev {
            Event::RecordEnd { len } => {
                w.records += 1;
                w.wire_len += len;
                w.max_record = w.max_record.max(len);
                continue;
            }
            Event::Frame(f) => f,
        };
        let name = frame_name(&f);
        *w.frames.entry(name).or_default() += 1;
        if first != matches!(f, Frame::TransportParameters(_)) {
            w.violations.push(format!(
                "{name} where QX_TRANSPORT_PARAMETERS was due or not allowed"
            ));
        }
        first = false;
        if !w.closes.is_empty() {
            w.violations.push(format!(
                "{name} after CONNECTION_CLOSE (SPEC.md Section 6.5)"
            ));
        }
        if let Frame::ConnectionClose(c) = f {
            w.closes.push(format!(
                "{} code {:#x} frame type {:#x} reason {:?}",
                if c.application { "0x1d" } else { "0x1c" },
                c.error_code,
                c.frame_type,
                String::from_utf8_lossy(c.reason)
            ));
        }
        if !strict {
            if let Frame::TransportParameters(p) = f {
                w.params = Some(p.block.to_vec());
            }
            continue;
        }
        match f {
            Frame::TransportParameters(p) => w.params = Some(p.block.to_vec()),
            Frame::Stream(s) => {
                let t = streams.entry(s.stream_id).or_default();
                if t.reset {
                    w.violations
                        .push(format!("STREAM {} after RESET_STREAM", s.stream_id));
                }
                if t.fin {
                    w.violations
                        .push(format!("STREAM {} after FIN", s.stream_id));
                }
                if s.offset != t.next {
                    w.violations.push(format!(
                        "STREAM {} at offset {}, expected {} (out of order or repeated)",
                        s.stream_id, s.offset, t.next
                    ));
                }
                // An empty frame without FIN only opens a stream (SPEC.md
                // Section 4.3).
                if s.data.is_empty() && !s.fin && t.frames != 0 {
                    w.violations
                        .push(format!("empty STREAM {} without FIN", s.stream_id));
                }
                t.frames += 1;
                t.next = s.offset + s.data.len() as u64;
                t.fin |= s.fin;
            }
            Frame::ResetStream(r) => {
                let t = streams.entry(r.stream_id).or_default();
                if t.reset {
                    w.violations
                        .push(format!("repeated RESET_STREAM {}", r.stream_id));
                }
                if r.final_size != t.next {
                    w.violations.push(format!(
                        "RESET_STREAM {} final size {} after {} bytes",
                        r.stream_id, r.final_size, t.next
                    ));
                }
                t.reset = true;
            }
            Frame::Padding(_)
            | Frame::StopSending(_)
            | Frame::MaxData(_)
            | Frame::MaxStreamData(_)
            | Frame::MaxStreams(_)
            | Frame::DataBlocked(_)
            | Frame::StreamDataBlocked(_)
            | Frame::StreamsBlocked(_)
            | Frame::ConnectionClose(_)
            | Frame::QxPing(_)
            // The peer advertised `reset_stream_at` and
            // `max_datagram_frame_size` (SPEC.md Section 13.2 rule 3).
            | Frame::ResetStreamAt(_)
            | Frame::Datagram(_) => {}
            _ => w
                .violations
                .push(format!("{name}: not a QMux-02 frame (SPEC.md Section 13.2)")),
        }
    }
    if w.wire_len != bytes.len() as u64 {
        w.violations.push(format!(
            "{} bytes after the last complete record",
            bytes.len() as u64 - w.wire_len
        ));
    }
    w
}

fn is_grease(id: u64) -> bool {
    id % 31 == 27
}

/// Checks both directions and prints what zmux wrote.
fn check_wire(label: &str, pair: &Pair, closer: Closer) {
    let out = pair.out.take();
    let inn = pair.inn.take();
    let zw = decode(&out, QMUX_MAX_RECORD, true);
    let qw = decode(&inn, ZMUX_MAX_RECORD, false);

    eprintln!(
        "[{label}] zmux wrote {} bytes in {} records (largest {}): {:?}",
        out.len(),
        zw.records,
        zw.max_record,
        zw.frames
    );
    eprintln!(
        "[{label}] qmux wrote {} bytes in {} records (largest {}): {:?}",
        inn.len(),
        qw.records,
        qw.max_record,
        qw.frames
    );
    eprintln!(
        "[{label}] zmux closes: {:?}; qmux closes: {:?}",
        zw.closes, qw.closes
    );
    assert!(
        zw.violations.is_empty(),
        "[{label}] zmux: {:#?}",
        zw.violations
    );
    assert!(
        qw.violations.is_empty(),
        "[{label}] qmux: {:#?}",
        qw.violations
    );

    // zmux's parameters: zmux parameters and GREASE, which the peer ignored.
    let block = zw
        .params
        .as_deref()
        .expect("zmux sent no QX_TRANSPORT_PARAMETERS");
    let ids: Vec<u64> = RawParameters::new(block).map(|p| p.unwrap().0).collect();
    eprintln!("[{label}] zmux parameter IDs: {ids:#x?}");
    let tp = TransportParameters::decode(block).unwrap();
    assert!(!tp.is_plain_qmux(), "zmux sent no zmux parameters");
    assert!(ids.iter().any(|&id| is_grease(id)), "zmux sent no GREASE");
    // The peer's: none of zmux's.
    let block = qw
        .params
        .as_deref()
        .expect("qmux sent no QX_TRANSPORT_PARAMETERS");
    let ids: Vec<u64> = RawParameters::new(block).map(|p| p.unwrap().0).collect();
    eprintln!("[{label}] qmux parameter IDs: {ids:#x?}");
    assert!(TransportParameters::decode(block).unwrap().is_plain_qmux());

    let n = |w: &Wire, k: &str| w.frames.get(k).copied().unwrap_or(0);
    // Flow-control updates both ways.
    for k in ["MAX_DATA", "MAX_STREAM_DATA"] {
        assert!(n(&zw, k) > 0, "[{label}] zmux sent no {k}");
        assert!(n(&qw, k) > 0, "[{label}] qmux sent no {k}");
    }
    // The resets and stops of the scenarios, each way; zmux answers the
    // peer's STOP_SENDING with RESET_STREAM.
    assert!(n(&zw, "RESET_STREAM") >= 2, "[{label}] {:?}", zw.frames);
    assert!(n(&zw, "STOP_SENDING") >= 1, "[{label}] {:?}", zw.frames);
    assert!(n(&qw, "RESET_STREAM") >= 1, "[{label}] {:?}", qw.frames);
    assert!(n(&qw, "STOP_SENDING") >= 1, "[{label}] {:?}", qw.frames);
    assert_eq!(
        n(&zw, "RESET_STREAM_AT"),
        0,
        "[{label}] unasked RESET_STREAM_AT"
    );
    let app_close = |code: u32, reason: &str| {
        vec![format!(
            "0x1d code {code:#x} frame type 0x0 reason {reason:?}"
        )]
    };
    match closer {
        Closer::Zmux => {
            assert_eq!(zw.closes, app_close(42, "bye"), "[{label}]");
            assert!(qw.closes.is_empty(), "[{label}] {:?}", qw.closes);
        }
        Closer::Qmux => {
            assert_eq!(qw.closes, app_close(7, "done"), "[{label}]");
            // At most one CONNECTION_CLOSE in response, without error
            // (QMux-02 Section 7.3, SPEC.md Section 6.5): whether it is
            // written depends on whether the carrier still takes it.
            let no_error = "0x1c code 0x0 frame type 0x0 reason \"\"".to_string();
            assert!(
                zw.closes.is_empty() || zw.closes == [no_error],
                "[{label}] {:?}",
                zw.closes
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Runs

async fn scenario(carrier: Carrier, zmux_client: bool, closer: Closer) {
    let label = format!(
        "{carrier:?}, zmux {}, {closer:?} closes",
        if zmux_client { "client" } else { "server" }
    );
    let run = async {
        let pair = establish(carrier, zmux_client).await;
        let (z, q) = (&pair.zmux, &pair.qmux);
        assert!(
            z.is_plain_qmux_peer(),
            "the qmux crate not detected as plain"
        );
        assert_eq!(z.multipath(), zmux::Multipath::Off);
        zmux_drives(z, q).await;
        qmux_drives(z, q).await;
        pings_and_datagrams(z, q).await;
        let budget = z.stats().no_effect_budget;
        assert!(budget >= 4000, "no-effect budget {budget}");
        close(z, q, closer).await;
        pair
    };
    let pair = tokio::time::timeout(RUN_TIMEOUT, run)
        .await
        .unwrap_or_else(|_| panic!("[{label}] timed out"));
    // Let the carriers drain before the taps are read.
    tokio::time::sleep(Duration::from_millis(50)).await;
    check_wire(&label, &pair, closer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_zmux_client_closes() {
    scenario(Carrier::Tcp, true, Closer::Zmux).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_zmux_client_peer_closes() {
    scenario(Carrier::Tcp, true, Closer::Qmux).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_zmux_server_closes() {
    scenario(Carrier::Tcp, false, Closer::Zmux).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_zmux_server_peer_closes() {
    scenario(Carrier::Tcp, false, Closer::Qmux).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplex_zmux_client() {
    scenario(Carrier::Duplex, true, Closer::Qmux).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplex_zmux_server() {
    scenario(Carrier::Duplex, false, Closer::Zmux).await;
}

/// CONFORMANCE.md test 11: zmux as client with `early_data`
/// wrongly declaring the target a zmux endpoint. The target stops at the
/// PIPE_ACK fence with FRAME_ENCODING_ERROR, its application sees no
/// stream, and zmux reports `EarlyDataRejected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn early_data_wrongly_declared() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (dialed, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let (z, q) = (dialed.unwrap(), accepted.unwrap().0);
    let (out, inn) = (Tap::default(), Tap::default());
    let mut cfg = zmux_config();
    cfg.early_data = zmux::EarlyData::for_zmux_peer();
    let client = zmux::Session::connect(tapped_tcp(z, &out, &inn), cfg)
        .await
        .expect("returns before the peer's parameters");
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let c = qmux_config();
    let t = QmuxTransport::new(q, c.version, c.max_record_size);
    let target = qmux::Session::accept(t, c).await;
    let e = tokio::time::timeout(Duration::from_secs(10), client.closed())
        .await
        .expect("closed in time");
    assert_eq!(e, zmux::SessionError::EarlyDataRejected, "{e:?}");
    if let Ok(target) = target {
        let accepted = tokio::time::timeout(Duration::from_millis(500), target.accept_bi()).await;
        assert!(
            !matches!(accepted, Ok(Ok(_))),
            "the target's application saw no stream"
        );
    }
}
