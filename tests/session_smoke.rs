use std::collections::VecDeque;
use std::future::Future;
use std::io::{IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};
use zmux::SchedulerHint;
use zmux::{
    append_tlv, build_go_away_payload, build_open_metadata_prefix, build_priority_update_payload,
    encode_varint, parse_data_payload, parse_error_payload, parse_go_away_payload, parse_varint,
    read_preface, Config, Conn, ErrorCode, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource,
    Event, EventType, Frame, FrameType, Limits, MetadataUpdate, OpenOptions, SessionState,
    Settings, TerminationKind, CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS, DIAG_DEBUG_TEXT, DIAG_RETRY_AFTER_MILLIS,
    EXT_PRIORITY_UPDATE, FRAME_FLAG_FIN, FRAME_FLAG_OPEN_METADATA, MAX_VARINT62,
    METADATA_STREAM_PRIORITY,
};

#[derive(Clone)]
struct MemoryConn {
    inbound: Arc<Queue>,
    outbound: Arc<Queue>,
}

#[derive(Clone)]
struct TlsLikeConn {
    inner: MemoryConn,
}

struct Queue {
    state: Mutex<QueueState>,
    cond: Condvar,
}

struct QueueState {
    bytes: VecDeque<u8>,
    closed: bool,
}

#[derive(Clone)]
struct BlockingWriter {
    inner: MemoryConn,
    state: Arc<BlockingWriterState>,
}

struct BlockingWriterState {
    state: Mutex<BlockingWriterInner>,
    cond: Condvar,
}

struct BlockingWriterInner {
    pass_writes: usize,
    blocked: bool,
    released: bool,
}

impl Queue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState {
                bytes: VecDeque::new(),
                closed: false,
            }),
            cond: Condvar::new(),
        })
    }
}

fn memory_pair() -> (MemoryConn, MemoryConn) {
    let a_to_b = Queue::new();
    let b_to_a = Queue::new();
    (
        MemoryConn {
            inbound: b_to_a.clone(),
            outbound: a_to_b.clone(),
        },
        MemoryConn {
            inbound: a_to_b,
            outbound: b_to_a,
        },
    )
}

fn blocking_writer(
    inner: MemoryConn,
    pass_writes: usize,
) -> (BlockingWriter, Arc<BlockingWriterState>) {
    let state = Arc::new(BlockingWriterState {
        state: Mutex::new(BlockingWriterInner {
            pass_writes,
            blocked: false,
            released: false,
        }),
        cond: Condvar::new(),
    });
    (
        BlockingWriter {
            inner,
            state: state.clone(),
        },
        state,
    )
}

impl BlockingWriterState {
    fn wait_blocked(&self) {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut state = self.state.lock().unwrap();
        while !state.blocked {
            let Some(wait) = deadline.checked_duration_since(Instant::now()) else {
                panic!("writer did not block");
            };
            let (next, timeout) = self.cond.wait_timeout(state, wait).unwrap();
            state = next;
            if timeout.timed_out() && !state.blocked {
                panic!("writer did not block");
            }
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.released = true;
        self.cond.notify_all();
    }
}

impl Write for BlockingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        {
            let mut state = self.state.state.lock().unwrap();
            if state.pass_writes > 0 {
                state.pass_writes -= 1;
            } else {
                state.blocked = true;
                self.state.cond.notify_all();
                while !state.released {
                    state = self.state.cond.wait(state).unwrap();
                }
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Clone)]
struct RendezvousConn {
    inbound: Arc<Mutex<Receiver<u8>>>,
    outbound: SyncSender<u8>,
    write_probe: Option<Sender<()>>,
}

fn rendezvous_pair() -> (RendezvousConn, RendezvousConn) {
    let (a_to_b_tx, a_to_b_rx) = mpsc::sync_channel(0);
    let (b_to_a_tx, b_to_a_rx) = mpsc::sync_channel(0);
    (
        RendezvousConn {
            inbound: Arc::new(Mutex::new(b_to_a_rx)),
            outbound: a_to_b_tx,
            write_probe: None,
        },
        RendezvousConn {
            inbound: Arc::new(Mutex::new(a_to_b_rx)),
            outbound: b_to_a_tx,
            write_probe: None,
        },
    )
}

fn rendezvous_pair_with_client_write_probe() -> (RendezvousConn, RendezvousConn, Receiver<()>) {
    let (mut client, peer) = rendezvous_pair();
    let (probe_tx, probe_rx) = mpsc::channel();
    client.write_probe = Some(probe_tx);
    (client, peer, probe_rx)
}

fn wait_for_rendezvous_frame(
    peer: &mut RendezvousConn,
    mut predicate: impl FnMut(&Frame) -> bool,
) -> Frame {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut read_buf = Vec::new();
    while Instant::now() < deadline {
        let mut byte = [0u8; 1];
        if peer.read(&mut byte).unwrap() == 0 {
            break;
        }
        read_buf.push(byte[0]);
        while !read_buf.is_empty() {
            let Ok((frame, n)) = Frame::parse(&read_buf, Limits::default()) else {
                break;
            };
            read_buf.drain(..n);
            if predicate(&frame) {
                return frame;
            }
        }
    }
    panic!("timed out waiting for rendezvous frame");
}

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    let waker = Waker::noop().clone();
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::yield_now(),
        }
    }
}

impl Read for RendezvousConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let inbound = self.inbound.lock().unwrap();
        let Ok(first) = inbound.recv() else {
            return Ok(0);
        };
        buf[0] = first;
        let mut n = 1;
        while n < buf.len() {
            match inbound.try_recv() {
                Ok(byte) => {
                    buf[n] = byte;
                    n += 1;
                }
                Err(_) => break,
            }
        }
        Ok(n)
    }
}

impl Write for RendezvousConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(probe) = &self.write_probe {
            let _ = probe.send(());
        }
        for byte in buf {
            self.outbound
                .send(*byte)
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for MemoryConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut state = self.inbound.state.lock().unwrap();
        while state.bytes.is_empty() && !state.closed {
            state = self.inbound.cond.wait(state).unwrap();
        }
        if state.bytes.is_empty() && state.closed {
            return Ok(0);
        }
        let n = buf.len().min(state.bytes.len());
        for slot in &mut buf[..n] {
            *slot = state.bytes.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for MemoryConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut state = self.outbound.state.lock().unwrap();
        state.bytes.extend(buf);
        self.outbound.cond.notify_all();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for MemoryConn {
    fn drop(&mut self) {
        let mut state = self.outbound.state.lock().unwrap();
        state.closed = true;
        self.outbound.cond.notify_all();
    }
}

impl Read for TlsLikeConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsLikeConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl TlsLikeConn {
    fn new(inner: MemoryConn) -> Self {
        Self { inner }
    }
}

#[derive(Clone)]
struct FailAfterWrites {
    inner: MemoryConn,
    remaining_successful_writes: Arc<AtomicUsize>,
    message: &'static str,
}

impl Write for FailAfterWrites {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut remaining = self.remaining_successful_writes.load(Ordering::Acquire);
        loop {
            if remaining == 0 {
                return Err(std::io::Error::other(self.message));
            }
            match self.remaining_successful_writes.compare_exchange(
                remaining,
                remaining - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return self.inner.write(buf),
                Err(next) => remaining = next,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn read_all_stream(stream: &zmux::Stream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8];
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn read_once_stream(stream: &zmux::Stream) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = stream
        .read_timeout(&mut buf, Duration::from_secs(1))
        .unwrap();
    buf[..n].to_vec()
}

fn read_all_recv_stream(stream: &zmux::RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8];
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap()
}

fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap()
}

fn error_payload(code: u64, reason: &str) -> Vec<u8> {
    let mut payload = encode_varint(code).unwrap();
    if !reason.is_empty() {
        payload.extend_from_slice(&encode_varint(DIAG_DEBUG_TEXT).unwrap());
        payload.extend_from_slice(&encode_varint(usize_to_u64(reason.len())).unwrap());
        payload.extend_from_slice(reason.as_bytes());
    }
    payload
}

fn error_payload_with_duplicate_standard_diag(code: u64, reason: &str) -> Vec<u8> {
    let mut payload = encode_varint(code).unwrap();
    append_tlv(
        &mut payload,
        DIAG_RETRY_AFTER_MILLIS,
        &encode_varint(1).unwrap(),
    )
    .unwrap();
    append_tlv(
        &mut payload,
        DIAG_RETRY_AFTER_MILLIS,
        &encode_varint(2).unwrap(),
    )
    .unwrap();
    if !reason.is_empty() {
        append_tlv(&mut payload, DIAG_DEBUG_TEXT, reason.as_bytes()).unwrap();
    }
    payload
}

fn error_payload_with_invalid_utf8_diag(code: u64) -> Vec<u8> {
    let mut payload = encode_varint(code).unwrap();
    append_tlv(&mut payload, DIAG_DEBUG_TEXT, &[0xe2, 0x82]).unwrap();
    payload
}

fn assert_bad_peer_close_diag_drops_reason(payload: Vec<u8>) {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload,
    });

    wait_for_state(&client, SessionState::Failed);
    let peer_error = client.peer_close_error().unwrap();
    assert_eq!(peer_error.code, ErrorCode::Protocol.as_u64());
    assert_eq!(peer_error.reason, "");
    let err = client.wait_timeout(Duration::ZERO).unwrap_err();
    assert_eq!(err.numeric_code(), Some(ErrorCode::Protocol.as_u64()));
    assert_eq!(err.reason(), None);
    assert_eq!(err.source(), zmux::ErrorSource::Remote);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);
}

fn assert_local_read_stopped_error(err: &zmux::Error) {
    assert!(err.to_string().contains("read side closed"));
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Read);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(err.termination_kind(), TerminationKind::Stopped);
}

fn assert_local_stream_terminal_error(
    err: &zmux::Error,
    code: ErrorCode,
    reason: &str,
    operation: ErrorOperation,
    direction: ErrorDirection,
    termination_kind: TerminationKind,
) {
    assert_eq!(err.code(), Some(code));
    assert_eq!(err.numeric_code(), Some(code.as_u64()));
    assert_eq!(err.reason(), Some(reason));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), operation);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), direction);
    assert_eq!(err.termination_kind(), termination_kind);
}

fn ping_padding_tag(key: u64, nonce: u64) -> u64 {
    let mut z = key ^ nonce ^ 0x6d1d_9f6d_33f9_772d;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn ping_echo_at_payload_limit(limit: u64) -> Vec<u8> {
    assert!(limit >= 8);
    vec![0; u64_to_usize(limit - 8)]
}

fn config_with_control_limit(mut config: Config, max_control_payload_bytes: u64) -> Config {
    config.settings.max_control_payload_bytes = max_control_payload_bytes;
    config
}

fn pre_open_overflow_open_info(
    caps: u64,
    max_frame_payload: u64,
    priority: u64,
    group: u64,
) -> Vec<u8> {
    for size in (0..=u64_to_usize(max_frame_payload)).rev() {
        let candidate = vec![b'x'; size];
        if build_open_metadata_prefix(caps, None, None, &candidate, max_frame_payload).is_err() {
            continue;
        }
        if build_open_metadata_prefix(
            caps,
            Some(priority),
            Some(group),
            &candidate,
            max_frame_payload,
        )
        .is_err()
        {
            return candidate;
        }
    }
    panic!("failed to find open_info that overflows only after metadata update");
}

fn open_info_len_for_prefix_size(caps: u64, target_size: u64) -> usize {
    let target_size = u64_to_usize(target_size);
    for len in 1..=target_size {
        let open_info = vec![b'm'; len];
        if let Ok(prefix) =
            build_open_metadata_prefix(caps, None, None, &open_info, usize_to_u64(target_size))
        {
            if prefix.len() == target_size {
                return len;
            }
        }
    }
    panic!("failed to find open_info length for prefix size {target_size}");
}

fn connected_pair(client_config: Config, server_config: Config) -> (Conn, Conn) {
    let (client_io, server_io) = memory_pair();
    let client_read = client_io.clone();
    let client_write = client_io;
    let server_read = server_io.clone();
    let server_write = server_io;

    let client_thread = thread::spawn(move || {
        Conn::client_with_config((client_read, client_write), client_config).unwrap()
    });
    let server_thread = thread::spawn(move || {
        Conn::server_with_config((server_read, server_write), server_config).unwrap()
    });

    (client_thread.join().unwrap(), server_thread.join().unwrap())
}

fn wait_closed_for_contract(conn: &Conn) -> Option<zmux::Error> {
    match conn.wait_timeout(Duration::from_secs(1)) {
        Ok(true) => {
            assert!(conn.is_closed());
            None
        }
        Ok(false) => panic!("session did not close before contract deadline"),
        Err(err) => {
            assert!(conn.is_closed());
            Some(err)
        }
    }
}

fn assert_application_error(err: &zmux::Error, code: u64, reason: Option<&str>) {
    assert_eq!(err.numeric_code(), Some(code));
    if let Some(reason) = reason {
        assert_eq!(err.reason(), Some(reason));
    }
}

fn assert_session_closed_or_application_error(err: &zmux::Error, code: u64) {
    assert!(err.is_session_closed() || err.numeric_code() == Some(code));
}

#[test]
fn tcp_constructors_establish_session_with_deadline_control() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        Conn::server(socket).unwrap()
    });

    let client = Conn::client(TcpStream::connect(addr).unwrap()).unwrap();
    let server = server_thread.join().unwrap();

    assert_eq!(client.state(), SessionState::Ready);
    assert_eq!(server.state(), SessionState::Ready);
    let _ = client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
}

#[test]
fn cloneable_duplex_io_can_back_native_session_without_manual_split() {
    let (client_io, server_io) = memory_pair();
    let client_thread =
        thread::spawn(move || Conn::client(zmux::duplex_io(TlsLikeConn::new(client_io))).unwrap());
    let server_thread =
        thread::spawn(move || Conn::server(zmux::duplex_io(TlsLikeConn::new(server_io))).unwrap());

    let client = client_thread.join().unwrap();
    let server = server_thread.join().unwrap();

    let stream = client.open_stream().unwrap();
    stream.write_final(b"tls-like").unwrap();

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(accepted.read(&mut buf).unwrap(), buf.len());
    assert_eq!(&buf, b"tls-like");

    let _ = client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
}

#[test]
fn try_duplex_io_can_attach_close_hook_for_full_resource_shutdown() {
    let (client_io, server_io) = memory_pair();
    let close_count = Arc::new(AtomicUsize::new(0));
    let client_close_count = Arc::clone(&close_count);
    let client_thread = thread::spawn(move || {
        let transport = zmux::try_duplex_io(TlsLikeConn::new(client_io), |io| Ok(io.clone()))
            .unwrap()
            .with_close_fn(move || {
                client_close_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            });
        Conn::client(transport).unwrap()
    });
    let server_thread =
        thread::spawn(move || Conn::server(zmux::duplex_io(TlsLikeConn::new(server_io))).unwrap());

    let client = client_thread.join().unwrap();
    let server = server_thread.join().unwrap();

    let stream = client.open_stream().unwrap();
    stream.write_final(b"close-hook").unwrap();

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut buf = [0u8; 10];
    assert_eq!(accepted.read(&mut buf).unwrap(), buf.len());
    assert_eq!(&buf, b"close-hook");

    let _ = client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = client.wait_timeout(Duration::from_secs(1));
    let _ = server.wait_timeout(Duration::from_secs(1));

    for _ in 0..50 {
        if close_count.load(Ordering::Relaxed) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_ne!(close_count.load(Ordering::Relaxed), 0);
}

#[test]
fn joined_streams_can_back_nested_native_session() {
    let (outer_client, outer_server) = connected_pair(Config::default(), Config::default());

    let outer_client_stream = outer_client.open_stream().unwrap();
    let inner_client_transport =
        zmux::join_streams(outer_client_stream.clone(), outer_client_stream);
    let inner_client_thread = thread::spawn(move || Conn::client(inner_client_transport).unwrap());

    let outer_server_stream = outer_server
        .accept_stream_timeout(Duration::from_secs(5))
        .unwrap();
    let inner_server_transport =
        zmux::join_streams(outer_server_stream.clone(), outer_server_stream);
    let inner_server_thread = thread::spawn(move || Conn::server(inner_server_transport).unwrap());
    let inner_client = inner_client_thread.join().unwrap();
    let inner_server = inner_server_thread.join().unwrap();

    let stream = inner_client.open_stream().unwrap();
    stream.write_final(b"nested").unwrap();
    let accepted = inner_server
        .accept_stream_timeout(Duration::from_secs(5))
        .unwrap();
    let mut buf = [0u8; 6];
    assert_eq!(accepted.read(&mut buf).unwrap(), buf.len());
    assert_eq!(&buf, b"nested");

    let _ = inner_client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = inner_server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = outer_client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = outer_server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
}

#[test]
fn bidirectional_stream_can_back_nested_native_session_directly() {
    let (outer_client, outer_server) = connected_pair(Config::default(), Config::default());

    let outer_client_stream = outer_client.open_stream().unwrap();
    let inner_client_thread = thread::spawn(move || Conn::client(outer_client_stream).unwrap());

    let outer_server_stream = outer_server
        .accept_stream_timeout(Duration::from_secs(5))
        .unwrap();
    let inner_server_thread = thread::spawn(move || Conn::server(outer_server_stream).unwrap());
    let inner_client = inner_client_thread.join().unwrap();
    let inner_server = inner_server_thread.join().unwrap();

    let stream = inner_client.open_stream().unwrap();
    stream.write_final(b"direct-nested").unwrap();
    let accepted = inner_server
        .accept_stream_timeout(Duration::from_secs(5))
        .unwrap();
    let mut buf = [0u8; 13];
    assert_eq!(accepted.read(&mut buf).unwrap(), buf.len());
    assert_eq!(&buf, b"direct-nested");

    let _ = inner_client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = inner_server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = outer_client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = outer_server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
}

#[test]
fn joined_ordinary_duplex_ios_can_back_native_session() {
    let (client_up, server_down) = memory_pair();
    let (server_up, client_down) = memory_pair();

    let client_joined =
        zmux::join_streams(TlsLikeConn::new(client_down), TlsLikeConn::new(client_up));
    let server_joined =
        zmux::join_streams(TlsLikeConn::new(server_down), TlsLikeConn::new(server_up));

    let client_thread = thread::spawn(move || Conn::client(client_joined).unwrap());
    let server_thread = thread::spawn(move || Conn::server(server_joined).unwrap());
    let client = client_thread.join().unwrap();
    let server = server_thread.join().unwrap();

    let stream = client.open_stream().unwrap();
    stream.write_final(b"ordinary-joined").unwrap();
    let accepted = server
        .accept_stream_timeout(Duration::from_secs(5))
        .unwrap();
    let mut buf = [0u8; 15];
    assert_eq!(accepted.read(&mut buf).unwrap(), buf.len());
    assert_eq!(&buf, b"ordinary-joined");

    let reply = server.open_uni_stream().unwrap();
    reply.write_final(b"reply").unwrap();
    let recv = client
        .accept_uni_stream_timeout(Duration::from_secs(5))
        .unwrap();
    let mut reply_buf = [0u8; 5];
    assert_eq!(recv.read(&mut reply_buf).unwrap(), reply_buf.len());
    assert_eq!(&reply_buf, b"reply");

    let _ = client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
}

#[test]
fn joined_uni_streams_bridge_as_duplex_byte_stream() {
    let (outer_client, outer_server) = connected_pair(Config::default(), Config::default());

    let client_send = outer_client.open_uni_stream().unwrap();
    let server_send = outer_server.open_uni_stream().unwrap();
    client_send.write_all(b"hi").unwrap();
    server_send.write_all(b"yo").unwrap();

    let client_recv = outer_client
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let server_recv = outer_server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut client_conn = zmux::join_streams(client_recv, client_send);
    let mut server_conn = zmux::join_streams(server_recv, server_send);

    let mut buf = [0u8; 8];
    let n = Read::read(&mut server_conn, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"hi");
    let n = Read::read(&mut client_conn, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"yo");

    Write::write_all(&mut client_conn, b"ping").unwrap();
    let n = Read::read(&mut server_conn, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping");

    Write::write_all(&mut server_conn, b"pong").unwrap();
    let n = Read::read(&mut client_conn, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"pong");

    zmux::StreamHandle::close(&client_conn).unwrap();
    zmux::StreamHandle::close(&server_conn).unwrap();
    let _ = outer_client.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    let _ = outer_server.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
}

#[test]
fn establishment_preface_exchange_does_not_deadlock_on_zero_buffer_transport() {
    let (client_io, server_io) = rendezvous_pair();
    let (done_tx, done_rx) = mpsc::channel();

    let client_done = done_tx.clone();
    let client_thread = thread::spawn(move || {
        let client_read = client_io.clone();
        let client_write = client_io;
        let _ = client_done.send(("client", Conn::client((client_read, client_write))));
    });
    let server_thread = thread::spawn(move || {
        let server_read = server_io.clone();
        let server_write = server_io;
        let _ = done_tx.send(("server", Conn::server((server_read, server_write))));
    });

    let mut client = None;
    let mut server = None;
    for _ in 0..2 {
        let (name, result) = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("session establishment timed out");
        match name {
            "client" => client = Some(result.unwrap()),
            "server" => server = Some(result.unwrap()),
            _ => unreachable!(),
        }
    }
    client_thread.join().unwrap();
    server_thread.join().unwrap();

    let client = client.unwrap();
    let server = server.unwrap();
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn preface_padding_is_accepted_during_session_establishment() {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    let client_write = client_io;
    let client_config = Config {
        preface_padding: true,
        preface_padding_min_bytes: 32,
        preface_padding_max_bytes: 32,
        ..Config::default()
    };

    let client_thread = thread::spawn(move || {
        Conn::client_with_config((client_read, client_write), client_config).unwrap()
    });
    let _client_preface = read_preface(&mut peer_io).unwrap();

    let server_preface = Config::responder().local_preface().unwrap();
    let padded_server_preface = server_preface
        .marshal_with_settings_padding(&[0xa5; 32])
        .unwrap();
    assert!(padded_server_preface.len() > server_preface.marshal().unwrap().len());
    peer_io.write_all(&padded_server_preface).unwrap();
    peer_io.flush().unwrap();

    let client = client_thread.join().unwrap();
    assert_eq!(client.state(), SessionState::Ready);

    let mut peer = RawPeer {
        io: peer_io,
        read_buf: Vec::new(),
    };
    let stream = client.open_uni_stream().unwrap();
    stream.write_final(b"x").unwrap();
    let data = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(data.payload, b"x");

    client.close().unwrap();
}

#[test]
fn session_trait_object_exposes_timeout_and_open_info_inspection() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_session<T: zmux::Session>() {}
    fn assert_stream_info<T: zmux::StreamHandle>() {}
    fn assert_recv_stream<T: zmux::RecvStreamHandle>() {}
    fn assert_send_stream<T: zmux::SendStreamHandle>() {}
    fn assert_bidi_stream<T: zmux::DuplexStreamHandle>() {}

    assert_send_sync::<Box<dyn zmux::DuplexStreamHandle>>();
    assert_send_sync::<Box<dyn zmux::SendStreamHandle>>();
    assert_send_sync::<Box<dyn zmux::RecvStreamHandle>>();
    assert_session::<Box<dyn zmux::Session>>();
    assert_session::<Arc<dyn zmux::Session>>();
    assert_session::<&'static dyn zmux::Session>();
    assert_stream_info::<Box<dyn zmux::DuplexStreamHandle>>();
    assert_recv_stream::<Box<dyn zmux::RecvStreamHandle>>();
    assert_send_stream::<Box<dyn zmux::SendStreamHandle>>();
    assert_bidi_stream::<Box<dyn zmux::DuplexStreamHandle>>();

    let (client, server) = connected_pair(Config::default(), Config::default());
    let session: &dyn zmux::Session = &client;

    assert!(!session.wait_timeout(Duration::ZERO).unwrap());

    let stream = session
        .open_stream_with(zmux::OpenRequest::new().timeout(Duration::from_millis(10)))
        .unwrap();
    assert!(stream.is_opened_locally());
    assert!(stream.is_bidirectional());
    assert_eq!(stream.open_info_len(), 0);
    assert!(!stream.has_open_info());
    let mut scratch = Vec::with_capacity(8);
    scratch.extend_from_slice(b"pre");
    stream.append_open_info_to(&mut scratch);
    assert_eq!(scratch, b"pre");
    stream
        .write_final(zmux::WritePayload::from(&b"trait-api"[..]))
        .unwrap();

    let recv = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert!(!recv.is_opened_locally());
    assert!(recv.is_bidirectional());
    assert_eq!(recv.open_info_len(), 0);
    assert!(!recv.has_open_info());
    recv.append_open_info_to(&mut scratch);
    assert_eq!(scratch, b"pre");

    let mut send = session
        .open_uni_stream_with(zmux::OpenRequest::new().timeout(Duration::from_millis(10)))
        .unwrap();
    let parts = [
        IoSlice::new(b"trait-"),
        IoSlice::new(b"write-vectored-plain"),
    ];
    assert_eq!(send.write_vectored(&parts).unwrap(), 26);
    send.close_write().unwrap();
    let recv_uni = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        read_all_recv_stream(&recv_uni),
        b"trait-write-vectored-plain"
    );

    let mut send = session
        .open_uni_stream_with(zmux::OpenRequest::new().timeout(Duration::from_millis(10)))
        .unwrap();
    let parts = [IoSlice::new(b"std-"), IoSlice::new(b"write-vectored")];
    assert_eq!(
        std::io::Write::write_vectored(&mut send, &parts).unwrap(),
        18
    );
    send.close_write().unwrap();
    let recv_uni = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_all_recv_stream(&recv_uni), b"std-write-vectored");

    let send = session
        .open_uni_stream_with(zmux::OpenRequest::new().timeout(Duration::from_millis(10)))
        .unwrap();
    let parts = [IoSlice::new(b"trait-"), IoSlice::new(b"write-vectored")];
    assert_eq!(send.write_vectored_final(&parts).unwrap(), 20);
    let recv_uni = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_all_recv_stream(&recv_uni), b"trait-write-vectored");
}

#[test]
fn std_io_traits_read_write_and_eof() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let mut stream = client.open_stream().unwrap();
    std::io::Write::write_all(&mut stream, b"bidi-io").unwrap();
    stream.close_write().unwrap();

    let mut accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut bidi = Vec::new();
    std::io::Read::read_to_end(&mut accepted, &mut bidi).unwrap();
    assert_eq!(bidi, b"bidi-io");
    accepted.close_write().unwrap();
    let mut empty = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut empty).unwrap();
    assert!(empty.is_empty());

    let mut send = client.open_uni_stream().unwrap();
    std::io::Write::write_all(&mut send, b"uni-io").unwrap();
    send.close_write().unwrap();

    let mut recv = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut uni = Vec::new();
    std::io::Read::read_to_end(&mut recv, &mut uni).unwrap();
    assert_eq!(uni, b"uni-io");

    client.close().unwrap();
    server.close().unwrap();
}

fn wait_for_state(conn: &Conn, expected: SessionState) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if conn.state() == expected {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(conn.state(), expected);
}

fn wait_for_open_streams(conn: &Conn, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if conn.stats().open_streams == expected {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(conn.stats().open_streams, expected);
}

fn wait_for_flush_count_at_least(conn: &Conn, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if conn.stats().flush.count >= expected {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(conn.stats().flush.count >= expected);
}

fn wait_for_event(events: &Arc<Mutex<Vec<Event>>>, event_type: EventType) -> Event {
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if let Some(event) = events
            .lock()
            .unwrap()
            .iter()
            .find(|event| event.event_type == event_type)
            .cloned()
        {
            return event;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for event {event_type:?}");
}

#[test]
fn default_config_uses_repository_keepalive_template() {
    let config = Config::default();

    assert_eq!(config.keepalive_interval, Duration::from_secs(60));
    assert_eq!(
        config.keepalive_max_ping_interval,
        Duration::from_secs(5 * 60)
    );
    assert_eq!(config.keepalive_timeout, Duration::ZERO);
    assert_eq!(config.close_drain_timeout, Duration::from_millis(500));
    assert_eq!(config.accept_backlog_limit, None);
    assert!(config.preface_padding);
    assert_eq!(config.preface_padding_min_bytes, 16);
    assert_eq!(config.preface_padding_max_bytes, 256);
    assert!(config.ping_padding);
    assert_eq!(config.ping_padding_min_bytes, 16);
    assert_eq!(config.ping_padding_max_bytes, 64);
}

#[test]
fn event_handler_reports_stream_and_session_lifecycle() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let server_events = Arc::new(Mutex::new(Vec::new()));
    let client_ref: Arc<Mutex<Option<Conn>>> = Arc::new(Mutex::new(None));
    let server_ref: Arc<Mutex<Option<Conn>>> = Arc::new(Mutex::new(None));
    let caps = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default().event_handler({
            let events = client_events.clone();
            let conn_ref = client_ref.clone();
            move |event| {
                let conn = conn_ref.lock().unwrap().clone();
                if let Some(conn) = conn {
                    let _ = conn.stats();
                }
                if let Some(stream) = event.stream.as_ref() {
                    let _ = stream.stream_id;
                    let _ = stream.open_info_len();
                }
                events.lock().unwrap().push(event);
            }
        })
    };
    let server_config = Config {
        capabilities: caps,
        ..Config::default().event_handler({
            let events = server_events.clone();
            let conn_ref = server_ref.clone();
            move |event| {
                let conn = conn_ref.lock().unwrap().clone();
                if let Some(conn) = conn {
                    let _ = conn.stats();
                }
                if let Some(stream) = event.stream.as_ref() {
                    let _ = stream.stream_id;
                    let _ = stream.open_info_len();
                }
                events.lock().unwrap().push(event);
            }
        })
    };
    let (client, server) = connected_pair(client_config, server_config);
    *client_ref.lock().unwrap() = Some(client.clone());
    *server_ref.lock().unwrap() = Some(server.clone());

    let open_info = b"event-info".to_vec();
    let open_options = OpenOptions::new()
        .priority(7)
        .group(9)
        .open_info(&open_info);
    let stream = client.open_stream_with(open_options).unwrap();
    stream.write_final(b"event").unwrap();
    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.session_state, SessionState::Ready);
    assert!(opened.local);
    assert!(opened.bidirectional);
    assert!(!opened.application_visible);
    assert_ne!(opened.stream_id, 0);
    assert!(opened.time.elapsed().unwrap() < Duration::from_secs(5));
    assert!(opened.error.is_none());
    assert_eq!(
        opened.stream.as_ref().unwrap().stream_id,
        stream.stream_id()
    );
    assert!(opened.stream.as_ref().unwrap().local);
    assert!(opened.stream.as_ref().unwrap().bidirectional);
    assert!(!opened.stream.as_ref().unwrap().application_visible);
    assert_eq!(opened.stream.as_ref().unwrap().open_info(), open_info);
    assert_eq!(opened.stream.as_ref().unwrap().metadata.priority, Some(7));
    assert_eq!(opened.stream.as_ref().unwrap().metadata.group, Some(9));

    let accepted = server.accept_stream().unwrap();
    assert_eq!(read_all_stream(&accepted), b"event");
    let accepted_event = wait_for_event(&server_events, EventType::StreamAccepted);
    assert_eq!(accepted_event.session_state, SessionState::Ready);
    assert!(!accepted_event.local);
    assert!(accepted_event.bidirectional);
    assert!(accepted_event.application_visible);
    assert_eq!(accepted_event.stream_id, accepted.stream_id());
    assert!(accepted_event.time.elapsed().unwrap() < Duration::from_secs(5));
    assert!(accepted_event.error.is_none());
    assert!(!accepted_event.stream.as_ref().unwrap().local);
    assert!(accepted_event.stream.as_ref().unwrap().bidirectional);
    assert!(accepted_event.stream.as_ref().unwrap().application_visible);
    assert_eq!(
        accepted_event.stream.as_ref().unwrap().open_info(),
        open_info
    );
    assert_eq!(
        accepted_event.stream.as_ref().unwrap().metadata.priority,
        Some(7)
    );
    assert_eq!(
        accepted_event.stream.as_ref().unwrap().metadata.group,
        Some(9)
    );

    accepted.close_write().unwrap();
    client.close().unwrap();
    let closed = wait_for_event(&client_events, EventType::SessionClosed);
    assert_eq!(closed.session_state, SessionState::Closed);
    assert!(closed.error.is_none());
}

#[test]
fn stream_opened_event_waits_until_stream_is_peer_visible() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, server) = connected_pair(client_config, Config::default());

    let stream = client.open_stream().unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(!client_events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.event_type == EventType::StreamOpened));

    stream.write(b"x").unwrap();
    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert!(!opened.application_visible);

    let accepted = server.accept_stream().unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(accepted.read(&mut buf).unwrap(), 1);
    assert_eq!(&buf, b"x");
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn inbound_stream_control_can_make_local_stream_peer_visible() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer, write_probe_rx) =
        client_with_rendezvous_raw_peer_and_write_probe(client_config);

    let stream = client.open_stream().unwrap();
    let (write_rx, write_thread) = start_blocked_rendezvous_write(stream.clone(), &write_probe_rx);
    assert!(!client_events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.event_type == EventType::StreamOpened));

    peer.write_all(
        &Frame {
            frame_type: FrameType::MaxData,
            flags: 0,
            stream_id: stream.stream_id(),
            payload: encode_varint(MAX_VARINT62).unwrap(),
        }
        .marshal()
        .unwrap(),
    )
    .unwrap();
    peer.flush().unwrap();

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert!(opened.local);
    assert!(!opened.application_visible);
    assert!(opened.error.is_none());
    finish_blocked_rendezvous_write(&mut peer, write_rx, write_thread);
}

#[test]
fn inbound_abort_can_make_local_stream_peer_visible() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer, write_probe_rx) =
        client_with_rendezvous_raw_peer_and_write_probe(client_config);

    let stream = client.open_stream().unwrap();
    let (write_rx, write_thread) = start_blocked_rendezvous_write(stream.clone(), &write_probe_rx);
    peer.write_all(
        &Frame {
            frame_type: FrameType::Abort,
            flags: 0,
            stream_id: stream.stream_id(),
            payload: vec![0],
        }
        .marshal()
        .unwrap(),
    )
    .unwrap();
    peer.flush().unwrap();

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert!(opened.local);
    assert!(opened.error.is_none());
    finish_blocked_rendezvous_write(&mut peer, write_rx, write_thread);
}

#[test]
fn inbound_data_can_make_local_stream_peer_visible() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer, write_probe_rx) =
        client_with_rendezvous_raw_peer_and_write_probe(client_config);

    let stream = client.open_stream().unwrap();
    let (write_rx, write_thread) = start_blocked_rendezvous_write(stream.clone(), &write_probe_rx);
    peer.write_all(
        &Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: stream.stream_id(),
            payload: b"y".to_vec(),
        }
        .marshal()
        .unwrap(),
    )
    .unwrap();
    peer.flush().unwrap();

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert!(opened.local);
    assert!(opened.error.is_none());
    finish_blocked_rendezvous_write(&mut peer, write_rx, write_thread);
}

#[test]
fn inbound_stop_sending_can_make_local_stream_peer_visible() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer, write_probe_rx) =
        client_with_rendezvous_raw_peer_and_write_probe(client_config);

    let stream = client.open_stream().unwrap();
    let (write_rx, write_thread) = start_blocked_rendezvous_write(stream.clone(), &write_probe_rx);
    peer.write_all(
        &Frame {
            frame_type: FrameType::StopSending,
            flags: 0,
            stream_id: stream.stream_id(),
            payload: vec![0],
        }
        .marshal()
        .unwrap(),
    )
    .unwrap();
    peer.flush().unwrap();

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert!(opened.local);
    assert!(opened.error.is_none());
    finish_blocked_rendezvous_write(&mut peer, write_rx, write_thread);
}

#[test]
fn inbound_reset_can_make_local_stream_peer_visible() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer, write_probe_rx) =
        client_with_rendezvous_raw_peer_and_write_probe(client_config);

    let stream = client.open_stream().unwrap();
    let (write_rx, write_thread) = start_blocked_rendezvous_write(stream.clone(), &write_probe_rx);
    peer.write_all(
        &Frame {
            frame_type: FrameType::Reset,
            flags: 0,
            stream_id: stream.stream_id(),
            payload: vec![0],
        }
        .marshal()
        .unwrap(),
    )
    .unwrap();
    peer.flush().unwrap();

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert!(opened.local);
    assert!(opened.error.is_none());
    finish_blocked_rendezvous_write(&mut peer, write_rx, write_thread);
}

#[test]
fn inbound_blocked_can_make_local_stream_peer_visible() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer, write_probe_rx) =
        client_with_rendezvous_raw_peer_and_write_probe(client_config);

    let stream = client.open_stream().unwrap();
    let (write_rx, write_thread) = start_blocked_rendezvous_write(stream.clone(), &write_probe_rx);
    peer.write_all(
        &Frame {
            frame_type: FrameType::Blocked,
            flags: 0,
            stream_id: stream.stream_id(),
            payload: encode_varint(0).unwrap(),
        }
        .marshal()
        .unwrap(),
    )
    .unwrap();
    peer.flush().unwrap();

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert!(opened.local);
    assert!(opened.error.is_none());
    finish_blocked_rendezvous_write(&mut peer, write_rx, write_thread);
}

#[test]
fn inbound_late_data_can_make_local_stream_peer_visible() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer) = client_with_raw_peer(client_config);

    let stream = client.open_stream().unwrap();
    stream.close_read().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: stream.stream_id(),
        payload: b"late".to_vec(),
    });

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert!(opened.local);
    assert!(opened.error.is_none());
}

#[test]
fn inbound_control_peer_visibility_event_is_emitted_once() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer, write_probe_rx) =
        client_with_rendezvous_raw_peer_and_write_probe(client_config);

    let stream = client.open_stream().unwrap();
    let (write_rx, write_thread) = start_blocked_rendezvous_write(stream.clone(), &write_probe_rx);
    for frame_type in [FrameType::MaxData, FrameType::Blocked] {
        let payload = if frame_type == FrameType::MaxData {
            encode_varint(MAX_VARINT62).unwrap()
        } else {
            encode_varint(0).unwrap()
        };
        peer.write_all(
            &Frame {
                frame_type,
                flags: 0,
                stream_id: stream.stream_id(),
                payload,
            }
            .marshal()
            .unwrap(),
        )
        .unwrap();
        peer.flush().unwrap();
    }

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_eq!(opened.stream_id, stream.stream_id());
    finish_blocked_rendezvous_write(&mut peer, write_rx, write_thread);
    thread::sleep(Duration::from_millis(50));
    let opened_count = client_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.event_type == EventType::StreamOpened)
        .count();
    assert_eq!(opened_count, 1);
}

#[test]
fn inbound_stream_control_does_not_emit_opened_for_uncommitted_local_open() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, mut peer) = client_with_raw_peer(client_config);

    let stream = client.open_stream().unwrap();
    assert_eq!(stream.stream_id(), 0);
    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(MAX_VARINT62).unwrap(),
    });
    thread::sleep(Duration::from_millis(50));
    assert!(!client_events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.event_type == EventType::StreamOpened));
}

#[test]
fn stream_accepted_event_waits_until_accept_returns_stream() {
    let server_events = Arc::new(Mutex::new(Vec::new()));
    let server_config = Config::default().event_handler({
        let events = server_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, server) = connected_pair(Config::default(), server_config);

    let stream = client.open_stream().unwrap();
    stream.write_final(b"x").unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while server.stats().accept_backlog.bidi == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(server.stats().accept_backlog.bidi, 1);
    assert!(!server_events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.event_type == EventType::StreamAccepted));

    let accepted = server.accept_stream().unwrap();
    let accepted_event = wait_for_event(&server_events, EventType::StreamAccepted);
    assert_eq!(accepted_event.stream_id, accepted.stream_id());
    assert!(accepted_event.application_visible);
    assert_eq!(read_all_stream(&accepted), b"x");

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn close_write_emits_stream_opened_event() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, server) = connected_pair(client_config, Config::default());

    let stream = client.open_stream().unwrap();
    stream.close_write().unwrap();

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_ne!(opened.stream_id, 0);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert_eq!(opened.session_state, SessionState::Ready);
    assert!(opened.local);
    assert!(opened.bidirectional);
    assert!(!opened.application_visible);
    assert!(opened.error.is_none());
    assert_eq!(
        opened.stream.as_ref().unwrap().stream_id,
        stream.stream_id()
    );

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(accepted.stream_id(), stream.stream_id());

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn close_read_emits_stream_opened_event() {
    let client_events = Arc::new(Mutex::new(Vec::new()));
    let client_config = Config::default().event_handler({
        let events = client_events.clone();
        move |event| {
            events.lock().unwrap().push(event);
        }
    });
    let (client, server) = connected_pair(client_config, Config::default());

    let stream = client.open_stream().unwrap();
    stream.close_read().unwrap();

    let opened = wait_for_event(&client_events, EventType::StreamOpened);
    assert_ne!(opened.stream_id, 0);
    assert_eq!(opened.stream_id, stream.stream_id());
    assert_eq!(opened.session_state, SessionState::Ready);
    assert!(opened.local);
    assert!(opened.bidirectional);
    assert!(!opened.application_visible);
    assert!(opened.error.is_none());
    assert_eq!(
        opened.stream.as_ref().unwrap().stream_id,
        stream.stream_id()
    );

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(accepted.stream_id(), stream.stream_id());

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn session_closed_event_carries_terminal_error_and_allows_reentrant_close() {
    let conn_ref: Arc<Mutex<Option<Conn>>> = Arc::new(Mutex::new(None));
    let handler_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let (event_tx, event_rx) = mpsc::channel();
    let client_config = Config::default().event_handler({
        let conn_ref = conn_ref.clone();
        let handler_error = handler_error.clone();
        move |event| {
            if event.event_type != EventType::SessionClosed {
                return;
            }
            let conn = conn_ref.lock().unwrap().clone();
            if let Some(conn) = conn {
                let _ = conn.stats();
                if conn.peer_close_error().is_some() {
                    *handler_error.lock().unwrap() =
                        Some("local close exposed a peer close error".to_owned());
                }
                if let Err(err) = conn.close() {
                    *handler_error.lock().unwrap() = Some(format!("reentrant close failed: {err}"));
                }
            }
            let _ = event_tx.send(event);
        }
    });
    let (client, server) = connected_pair(client_config, Config::default());
    *conn_ref.lock().unwrap() = Some(client.clone());
    let (close_tx, close_rx) = mpsc::channel();
    let closer = client.clone();
    thread::spawn(move || {
        let _ = close_tx.send(closer.close_with_error(ErrorCode::Internal.as_u64(), "close test"));
    });

    let closed = event_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let close_result = close_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(close_result.is_ok());
    assert!(handler_error.lock().unwrap().is_none());
    assert_eq!(closed.session_state, SessionState::Failed);
    assert_eq!(closed.stream_id, 0);
    assert!(closed.stream.is_none());
    assert!(!closed.local);
    assert!(!closed.bidirectional);
    assert!(!closed.application_visible);
    assert!(closed.time.elapsed().unwrap() < Duration::from_secs(5));
    let err = closed.error.as_ref().unwrap();
    assert_eq!(err.application_code(), Some(ErrorCode::Internal.as_u64()));
    assert_eq!(err.reason(), Some("close test"));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);
    assert!(!err.is_timeout());
    assert!(!err.is_interrupted());

    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn fatal_session_close_surfaces_code_and_reason_on_live_and_provisional_streams() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let live = client.accept_stream().unwrap();
    let provisional = client.open_stream().unwrap();

    client
        .close_with_error(ErrorCode::FrameSize.as_u64(), "payload too large")
        .unwrap();
    wait_for_state(&client, SessionState::Failed);

    let live_write = live.write(b"x").unwrap_err();
    assert_local_stream_terminal_error(
        &live_write,
        ErrorCode::FrameSize,
        "payload too large",
        ErrorOperation::Write,
        ErrorDirection::Write,
        TerminationKind::SessionTermination,
    );
    let provisional_write = provisional.write(b"x").unwrap_err();
    assert_local_stream_terminal_error(
        &provisional_write,
        ErrorCode::FrameSize,
        "payload too large",
        ErrorOperation::Write,
        ErrorDirection::Write,
        TerminationKind::SessionTermination,
    );

    let mut buf = [0u8; 1];
    let live_read = live
        .read_timeout(&mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert_local_stream_terminal_error(
        &live_read,
        ErrorCode::FrameSize,
        "payload too large",
        ErrorOperation::Read,
        ErrorDirection::Read,
        TerminationKind::SessionTermination,
    );
    let provisional_read = provisional
        .read_timeout(&mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert_local_stream_terminal_error(
        &provisional_read,
        ErrorCode::FrameSize,
        "payload too large",
        ErrorOperation::Read,
        ErrorDirection::Read,
        TerminationKind::SessionTermination,
    );

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FrameSize.as_u64());
    assert_eq!(reason, "payload too large");
}

#[test]
fn event_handler_panics_are_contained() {
    let config = Config::default().event_handler(|event| {
        if event.event_type == EventType::StreamOpened {
            panic!("event handler panic should be contained");
        }
    });
    let (client, server) = connected_pair(config, Config::default());

    let stream = client.open_stream().unwrap();
    stream.write_final(b"x").unwrap();
    let accepted = server.accept_stream().unwrap();
    assert_eq!(read_all_stream(&accepted), b"x");
    server.close().unwrap();
    client.close().unwrap();
}

#[test]
fn event_handler_serializes_concurrent_emitters_without_dropping_events() {
    fn record_failure(slot: &Arc<Mutex<Option<String>>>, message: impl Into<String>) {
        let mut guard = slot.lock().unwrap();
        if guard.is_none() {
            *guard = Some(message.into());
        }
    }

    let (first_entered_tx, first_entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let calls = Arc::new(AtomicUsize::new(0));
    let active_handlers = Arc::new(AtomicUsize::new(0));
    let max_active_handlers = Arc::new(AtomicUsize::new(0));
    let handler_failure: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let config = Config::default().event_handler({
        let release_rx = release_rx.clone();
        let calls = calls.clone();
        let active_handlers = active_handlers.clone();
        let max_active_handlers = max_active_handlers.clone();
        let handler_failure = handler_failure.clone();
        move |_event| {
            let current_active = active_handlers.fetch_add(1, Ordering::AcqRel) + 1;
            max_active_handlers.fetch_max(current_active, Ordering::AcqRel);
            let call = calls.fetch_add(1, Ordering::AcqRel) + 1;

            if call == 1 {
                if first_entered_tx.send(()).is_err() {
                    record_failure(&handler_failure, "first handler signal was dropped");
                }
                if release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .is_err()
                {
                    record_failure(&handler_failure, "first handler was not released");
                }
            }

            active_handlers.fetch_sub(1, Ordering::AcqRel);
        }
    });
    let (client, _peer) = client_with_raw_peer(config);

    let stream = client.open_uni_stream().unwrap();
    stream.write_final(b"x").unwrap();
    first_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first event handler should be entered");

    let (second_done_tx, second_done_rx) = mpsc::channel();
    let closer = client.clone();
    let second_emitter = thread::spawn(move || {
        let result = closer
            .close_with_error(ErrorCode::Internal.as_u64(), "queued event")
            .map_err(|err| err.to_string());
        let _ = second_done_tx.send(result);
    });
    let close_result = second_done_rx
        .recv_timeout(Duration::from_millis(500))
        .expect("non-empty event emitter should not wait behind an active handler");
    if let Err(err) = close_result {
        panic!("second event emitter failed: {err}");
    }

    thread::sleep(Duration::from_millis(50));
    release_tx.send(()).unwrap();
    second_emitter.join().unwrap();

    let deadline = Instant::now() + Duration::from_secs(1);
    while calls.load(Ordering::Acquire) < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(calls.load(Ordering::Acquire), 2);
    assert_eq!(max_active_handlers.load(Ordering::Acquire), 1);
    assert!(handler_failure.lock().unwrap().is_none());
    assert_eq!(client.state(), SessionState::Failed);
}

#[test]
fn stream_opened_event_handler_can_close_without_writer_deadlock() {
    let conn_ref: Arc<Mutex<Option<Conn>>> = Arc::new(Mutex::new(None));
    let close_called = Arc::new(AtomicBool::new(false));
    let config = Config {
        close_drain_timeout: Duration::from_millis(50),
        ..Config::default().event_handler({
            let conn_ref = conn_ref.clone();
            let close_called = close_called.clone();
            move |event| {
                if event.event_type != EventType::StreamOpened {
                    return;
                }
                let Some(conn) = conn_ref.lock().unwrap().clone() else {
                    return;
                };
                close_called.store(true, Ordering::Release);
                conn.close().unwrap();
            }
        })
    };
    let (client, mut peer) = client_with_raw_peer(config);
    *conn_ref.lock().unwrap() = Some(client.clone());

    let stream = client.open_uni_stream().unwrap();
    stream.write_final(b"x").unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_data = false;
    let mut saw_close = false;
    while Instant::now() < deadline && (!saw_data || !saw_close) {
        for frame in peer.drain_frames() {
            if frame.frame_type == FrameType::Data && frame.payload.last().copied() == Some(b'x') {
                saw_data = true;
            }
            if frame.frame_type == FrameType::Close && frame.stream_id == 0 {
                saw_close = true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(saw_data);
    assert!(saw_close);
    assert!(close_called.load(Ordering::Acquire));
    assert!(client.wait_timeout(Duration::from_secs(1)).unwrap());
}

#[test]
fn session_timeouts_fail_locally_without_protocol_side_effects() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let accept_err = match client.accept_stream_timeout(Duration::from_millis(20)) {
        Ok(_) => panic!("accept timeout unexpectedly returned a stream"),
        Err(err) => err,
    };
    assert!(accept_err.to_string().contains("accept timed out"));

    let open_err = match client.open_stream_with(zmux::OpenRequest::new().timeout(Duration::ZERO)) {
        Ok(_) => panic!("open timeout unexpectedly returned a stream"),
        Err(err) => err,
    };
    assert!(open_err.to_string().contains("open timed out"));

    let open_uni_err =
        match client.open_uni_stream_with(zmux::OpenRequest::new().timeout(Duration::ZERO)) {
            Ok(_) => panic!("open_uni timeout unexpectedly returned a stream"),
            Err(err) => err,
        };
    assert!(open_uni_err.to_string().contains("open timed out"));
    assert_eq!(client.stats().provisional.bidi, 0);
    assert_eq!(client.stats().provisional.uni, 0);
    assert_eq!(client.stats().provisional.limited, 0);

    let ping_err = client.ping_timeout(b"timeout", Duration::ZERO).unwrap_err();
    assert!(ping_err.to_string().contains("ping timed out"));
    assert!(!client.stats().liveness.ping_outstanding);
    assert_eq!(client.stats().pressure.outstanding_ping_bytes, 0);
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Ping));

    assert!(!client.wait_timeout(Duration::from_millis(20)).unwrap());
    client.close().unwrap();
    assert!(client.wait_timeout(Duration::from_millis(20)).unwrap());
}

#[test]
fn open_send_request_timeout_carries_budget_into_first_write() {
    let mut server_config = Config::default();
    server_config.settings.initial_max_data = 1;
    server_config
        .settings
        .initial_max_stream_data_bidi_peer_opened = 1;
    server_config.role = zmux::Role::Responder;
    let (client, _peer) = client_with_raw_peer_configs(Config::default(), server_config);

    let err =
        match client.open_and_send(zmux::OpenSend::new(b"xy").timeout(Duration::from_millis(30))) {
            Ok(_) => panic!("open_send request unexpectedly succeeded"),
            Err(err) => err,
        };
    assert!(err.to_string().contains("write timed out"));
    assert_open_and_send_failure_released_local_open(&client);
}

fn assert_open_and_send_failure_released_local_open(conn: &Conn) {
    let stats = conn.stats();
    assert_eq!(stats.provisional.bidi, 0);
    assert_eq!(stats.provisional.uni, 0);
    assert_eq!(stats.active_streams.local_bidi, 0);
    assert_eq!(stats.active_streams.local_uni, 0);
}

#[test]
fn open_uni_send_request_timeout_carries_budget_into_final_write() {
    let mut server_config = Config::default();
    server_config.settings.initial_max_data = 1;
    server_config.settings.initial_max_stream_data_uni = 1;
    server_config.role = zmux::Role::Responder;
    let (client, _peer) = client_with_raw_peer_configs(Config::default(), server_config);

    let err = match client
        .open_uni_and_send(zmux::OpenSend::new(b"xy").timeout(Duration::from_millis(30)))
    {
        Ok(_) => panic!("open_uni_send request unexpectedly succeeded"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("write timed out"));
    assert_open_and_send_failure_released_local_open(&client);
}

#[test]
fn vectored_open_send_request_timeout_carries_budget_into_first_write() {
    let mut server_config = Config::default();
    server_config.settings.initial_max_data = 1;
    server_config
        .settings
        .initial_max_stream_data_bidi_peer_opened = 1;
    server_config.role = zmux::Role::Responder;
    let (client, _peer) = client_with_raw_peer_configs(Config::default(), server_config);
    let parts = [IoSlice::new(b"x"), IoSlice::new(b"y")];

    let err = match client
        .open_and_send(zmux::OpenSend::vectored(&parts).timeout(Duration::from_millis(30)))
    {
        Ok(_) => panic!("vectored open_send request unexpectedly succeeded"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("write timed out"));
    assert_open_and_send_failure_released_local_open(&client);
}

#[test]
fn vectored_open_uni_send_request_timeout_carries_budget_into_final_write() {
    let mut server_config = Config::default();
    server_config.settings.initial_max_data = 1;
    server_config.settings.initial_max_stream_data_uni = 1;
    server_config.role = zmux::Role::Responder;
    let (client, _peer) = client_with_raw_peer_configs(Config::default(), server_config);
    let parts = [IoSlice::new(b"x"), IoSlice::new(b"y")];

    let err = match client
        .open_uni_and_send(zmux::OpenSend::vectored(&parts).timeout(Duration::from_millis(30)))
    {
        Ok(_) => panic!("vectored open_uni_send request unexpectedly succeeded"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("write timed out"));
    assert_open_and_send_failure_released_local_open(&client);
}

#[test]
fn open_send_request_timeout_success_uses_single_budget() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let stream = client
        .open_and_send(zmux::OpenSend::new(b"ok").timeout(Duration::from_secs(1)))
        .unwrap();
    assert_ne!(stream.stream_id(), 0);
    let write_stats = client.stats();
    assert!(write_stats.progress.stream_progress_at.is_some());
    assert!(write_stats.progress.application_progress_at.is_some());

    let accepted = server.accept_stream().unwrap();
    let mut buf = [0u8; 2];
    assert_eq!(accepted.read(&mut buf).unwrap(), 2);
    assert_eq!(&buf, b"ok");
}

#[test]
fn open_uni_send_request_options_preserve_open_info() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let server_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, server_config);

    let stream = client
        .open_uni_and_send(
            zmux::OpenSend::new(b"hello").options(OpenOptions::new().open_info(b"ssh")),
        )
        .unwrap();
    assert_ne!(stream.stream_id(), 0);

    let accepted = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(accepted.open_info(), b"ssh");
    assert_eq!(read_all_recv_stream(&accepted), b"hello");

    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn local_write_records_progress_open_latency_and_flush_stats() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    let stream = client.open_stream().unwrap();

    thread::sleep(Duration::from_millis(25));
    stream.write(b"local").unwrap();

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut buf = [0u8; 5];
    assert_eq!(accepted.read(&mut buf).unwrap(), 5);
    assert_eq!(&buf, b"local");

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let stats = client.stats();
        if stats.flush.count == 0 || stats.telemetry.last_open_latency.is_none() {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        assert!(stats.progress.stream_progress_at.is_some());
        assert!(stats.progress.application_progress_at.is_some());
        assert!(stats.progress.transport_write_at.is_some());
        assert!(stats.telemetry.last_open_latency.unwrap() >= Duration::from_millis(20));
        assert!(stats.flush.last_at.is_some());
        assert!(stats.flush.last_frames > 0);
        assert!(stats.flush.last_bytes > 0);
        client.close().ok();
        server.close().ok();
        return;
    }
    panic!("timed out waiting for local write progress stats");
}

#[test]
fn stream_read_timeout_is_local_and_preserves_buffered_data() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    let stream = client.open_stream().unwrap();
    stream.write(b"abc").unwrap();

    let accepted = server.accept_stream().unwrap();
    let mut buf = [0u8; 3];
    assert_eq!(accepted.read_timeout(&mut buf, Duration::ZERO).unwrap(), 3);
    assert_eq!(&buf, b"abc");

    let mut one = [0u8; 1];
    let err = accepted
        .read_timeout(&mut one, Duration::from_millis(20))
        .unwrap_err();
    assert!(err.to_string().contains("read timed out"));
}

#[test]
fn set_read_deadline_wakes_blocked_read() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();

    let accepted = server.accept_stream().unwrap();
    let mut first = [0u8; 1];
    assert_eq!(accepted.read(&mut first).unwrap(), 1);

    let reader = accepted.clone();
    let blocked_read = thread::spawn(move || {
        let mut buf = [0u8; 1];
        reader.read(&mut buf)
    });
    thread::sleep(Duration::from_millis(10));
    accepted
        .set_read_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();

    let err = blocked_read.join().unwrap().unwrap_err();
    assert!(err.to_string().contains("read timed out"));
}

#[test]
fn read_deadline_allows_data_before_expiry_and_can_be_cleared() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();

    let accepted = server.accept_stream().unwrap();
    let mut first = [0u8; 1];
    assert_eq!(accepted.read(&mut first).unwrap(), 1);

    accepted
        .set_read_deadline(Some(Instant::now() + Duration::from_secs(1)))
        .unwrap();
    stream.write_final(b"y").unwrap();

    let mut next = [0u8; 1];
    assert_eq!(accepted.read(&mut next).unwrap(), 1);
    assert_eq!(next, *b"y");
    accepted.set_read_deadline(None).unwrap();
}

#[test]
fn stream_write_timeout_expires_on_flow_control_wait() {
    // The raw peer grants no stream credit and never replenishes it.
    let peer_config = Config {
        settings: Settings {
            initial_max_stream_data_bidi_peer_opened: 0,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(Config::default(), peer_config);

    let stream = client.open_stream().unwrap();
    let err = stream
        .write_timeout(b"hello", Duration::from_millis(30))
        .unwrap_err();
    assert!(err.to_string().contains("write timed out"));
    assert!(client.stats().blocked_write_total > Duration::ZERO);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    let stream_frames: Vec<_> = frames
        .iter()
        .filter(|frame| frame.stream_id == stream.stream_id())
        .collect();
    // The zero-length opener still makes the stream visible, and a stream-scoped
    // BLOCKED is never the stream's first frame.
    let opener = stream_frames.first().expect("opening frame");
    assert_eq!(opener.frame_type, FrameType::Data);
    assert!(parse_data_payload(&opener.payload, opener.flags)
        .unwrap()
        .app_data
        .is_empty());

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn native_write_waits_for_transport_flush() {
    let (client, mut peer) = client_with_rendezvous_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    let writer = stream.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let write_thread = thread::spawn(move || {
        let _ = result_tx.send(writer.write(b"x"));
    });

    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    let data = wait_for_rendezvous_frame(&mut peer, |frame| frame.frame_type == FrameType::Data);
    let payload = parse_data_payload(&data.payload, data.flags).unwrap();
    assert_eq!(payload.app_data, b"x");
    assert_eq!(
        result_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap(),
        1
    );
    write_thread.join().unwrap();

    let closer = client.clone();
    let close_thread = thread::spawn(move || {
        let _ = closer.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    });
    let _ = wait_for_rendezvous_frame(&mut peer, |frame| frame.frame_type == FrameType::Close);
    close_thread.join().unwrap();
}

#[test]
fn native_go_away_waits_for_transport_flush() {
    let (client, mut peer) = client_with_rendezvous_raw_peer(Config::default());
    let sender = client.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let go_away_thread = thread::spawn(move || {
        let _ = result_tx.send(sender.go_away(0, 0));
    });

    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    let goaway =
        wait_for_rendezvous_frame(&mut peer, |frame| frame.frame_type == FrameType::GoAway);
    let payload = parse_go_away_payload(&goaway.payload).unwrap();
    assert_eq!(payload.last_accepted_bidi, 0);
    assert_eq!(payload.last_accepted_uni, 0);
    result_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    go_away_thread.join().unwrap();

    let closer = client.clone();
    let close_thread = thread::spawn(move || {
        let _ = closer.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    });
    let _ = wait_for_rendezvous_frame(&mut peer, |frame| frame.frame_type == FrameType::Close);
    close_thread.join().unwrap();
}

#[test]
fn native_close_read_waits_for_transport_flush() {
    let (client, mut peer) = client_with_rendezvous_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    let closer = stream.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let close_read_thread = thread::spawn(move || {
        let _ = result_tx.send(closer.close_read());
    });

    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    let stop = wait_for_rendezvous_frame(&mut peer, |frame| {
        frame.frame_type == FrameType::StopSending
    });
    assert_eq!(stop.stream_id, stream.stream_id());
    result_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    close_read_thread.join().unwrap();

    let closer = client.clone();
    let close_thread = thread::spawn(move || {
        let _ = closer.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    });
    let _ = wait_for_rendezvous_frame(&mut peer, |frame| frame.frame_type == FrameType::Close);
    close_thread.join().unwrap();
}

#[test]
fn native_write_batches_fragmented_payload_into_single_transport_flush() {
    let (client, mut peer) = client_with_raw_peer_configs(Config::default(), Config::responder());
    let stream = client.open_stream().unwrap();
    let payload = vec![7u8; 40_000];

    assert_eq!(stream.write(&payload).unwrap(), payload.len());
    wait_for_flush_count_at_least(&client, 1);
    assert_eq!(client.stats().flush.count, 1);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    let data_frames: Vec<_> = frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::Data)
        .collect();
    assert!(
        data_frames.len() > 1,
        "payload should be fragmented for the burst regression check"
    );
    let mut received = 0usize;
    for frame in data_frames {
        let payload = parse_data_payload(&frame.payload, frame.flags).unwrap();
        received = received.saturating_add(payload.app_data.len());
    }
    assert_eq!(received, payload.len());

    client.close().ok();
}

#[test]
fn concurrent_writes_on_same_stream_are_serialized() {
    let (client, mut peer) = client_with_raw_peer_configs(Config::default(), Config::responder());
    let stream = client.open_stream().unwrap();
    let writers = 8usize;
    let start = Arc::new(Barrier::new(writers));
    let mut handles = Vec::new();

    for index in 0..writers {
        let writer = stream.clone();
        let start = start.clone();
        handles.push(thread::spawn(move || {
            start.wait();
            let payload = format!("concurrent-write-{index:02}").into_bytes();
            writer.write_all(payload.clone()).unwrap();
            payload
        }));
    }

    let mut expected = Vec::new();
    for handle in handles {
        expected.push(handle.join().unwrap());
    }
    expected.sort();

    let mut actual = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    while actual.len() < writers && Instant::now() < deadline {
        for frame in peer.drain_frames() {
            if frame.frame_type == FrameType::Data {
                let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
                if !data.app_data.is_empty() {
                    actual.push(data.app_data.to_vec());
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    actual.sort();

    assert_eq!(actual, expected);
    client.close().ok();
}

#[test]
fn native_async_write_waits_for_transport_flush() {
    let (client, mut peer) = client_with_rendezvous_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    let writer = stream.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let write_thread = thread::spawn(move || {
        let _ = result_tx.send(block_on(zmux::AsyncSendStreamHandle::write(&writer, b"x")));
    });

    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    let data = wait_for_rendezvous_frame(&mut peer, |frame| frame.frame_type == FrameType::Data);
    let payload = parse_data_payload(&data.payload, data.flags).unwrap();
    assert_eq!(payload.app_data, b"x");
    assert_eq!(
        result_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap(),
        1
    );
    write_thread.join().unwrap();

    let closer = client.clone();
    let close_thread = thread::spawn(move || {
        let _ = closer.close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown");
    });
    let _ = wait_for_rendezvous_frame(&mut peer, |frame| frame.frame_type == FrameType::Close);
    close_thread.join().unwrap();
}

#[test]
fn native_async_write_reports_transport_write_error() {
    let message = "synthetic async data write failure";
    let (client, _peer) =
        client_with_raw_peer_and_failing_writer_after_preface(Config::default(), message);
    let stream = client.open_stream().unwrap();

    let write_err = block_on(zmux::AsyncSendStreamHandle::write(&stream, b"payload")).unwrap_err();
    assert_eq!(write_err.code(), Some(ErrorCode::Internal));
    assert_eq!(write_err.scope(), ErrorScope::Stream);
    assert_eq!(write_err.operation(), ErrorOperation::Write);
    assert_eq!(write_err.source(), ErrorSource::Transport);
    assert_eq!(write_err.direction(), ErrorDirection::Write);
    assert!(write_err.to_string().contains(message));
    wait_for_state(&client, SessionState::Failed);
}

#[test]
fn local_close_with_error_unblocks_blocked_write() {
    let mut server_config = Config::default();
    server_config.settings.initial_max_data = 1;
    server_config
        .settings
        .initial_max_stream_data_bidi_peer_opened = 1;
    let (client, server) = connected_pair(Config::default(), server_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();

    let writer = stream.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let write_thread = thread::spawn(move || {
        started_tx.send(()).unwrap();
        let _ = result_tx.send(writer.write(b"y"));
    });

    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    client
        .close_with_error(ErrorCode::Protocol.as_u64(), "bye")
        .unwrap();

    let err = result_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap_err();
    assert_eq!(err.numeric_code(), Some(ErrorCode::Protocol.as_u64()));
    assert_eq!(err.reason(), Some("bye"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);
    write_thread.join().unwrap();
    wait_for_state(&client, SessionState::Failed);
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn graceful_close_start_unblocks_blocked_write() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(20),
        ..Config::default()
    };
    let mut server_config = Config::default();
    server_config.settings.initial_max_data = 1;
    server_config
        .settings
        .initial_max_stream_data_bidi_peer_opened = 1;
    let (client, server) = connected_pair(client_config, server_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();

    let writer = stream.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let write_thread = thread::spawn(move || {
        started_tx.send(()).unwrap();
        let _ = result_tx.send(writer.write(b"y"));
    });

    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    let close_err = client.close().unwrap_err();
    assert!(close_err
        .to_string()
        .contains("graceful close drain timed out"));
    assert_eq!(close_err.scope(), ErrorScope::Session);
    assert_eq!(close_err.operation(), ErrorOperation::Close);
    assert_eq!(close_err.source(), ErrorSource::Local);
    assert_eq!(close_err.termination_kind(), TerminationKind::Timeout);

    let write_err = result_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap_err();
    assert!(write_err.is_session_closed());
    assert_eq!(write_err.scope(), ErrorScope::Stream);
    assert_eq!(write_err.operation(), ErrorOperation::Write);
    assert_eq!(write_err.source(), ErrorSource::Local);
    assert_eq!(write_err.direction(), ErrorDirection::Write);
    assert_eq!(
        write_err.termination_kind(),
        TerminationKind::SessionTermination
    );
    write_thread.join().unwrap();
    assert_eq!(client.state(), SessionState::Closed);
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn set_write_deadline_wakes_blocked_write() {
    // The raw peer grants no stream credit and never replenishes it.
    let peer_config = Config {
        settings: Settings {
            initial_max_stream_data_bidi_peer_opened: 0,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, _peer) = client_with_raw_peer_configs(Config::default(), peer_config);

    let stream = client.open_stream().unwrap();
    let writer = stream.clone();
    let blocked_write = thread::spawn(move || writer.write(b"hello"));
    thread::sleep(Duration::from_millis(10));
    stream
        .set_write_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();

    let err = blocked_write.join().unwrap().unwrap_err();
    assert!(err.to_string().contains("write timed out"));
}

#[test]
fn peer_stream_max_data_wakes_flow_blocked_write() {
    let mut peer_config = Config::responder();
    peer_config
        .settings
        .initial_max_stream_data_bidi_peer_opened = 4;
    let (client, mut peer) =
        client_with_raw_peer_configs(Config::default().disable_capabilities(), peer_config);
    assert_eq!(client.negotiated().capabilities, 0);
    let stream = client.open_stream().unwrap();
    assert_eq!(stream.write(b"abcd").unwrap(), 4);

    let first = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(first.stream_id, stream.stream_id());
    assert_eq!(
        parse_data_payload(&first.payload, first.flags)
            .unwrap()
            .app_data,
        b"abcd"
    );

    let writer = stream.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let write_thread = thread::spawn(move || {
        let _ = result_tx.send(writer.write_timeout(b"e", Duration::from_secs(30)));
    });

    let blocked = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Blocked && frame.stream_id == stream.stream_id()
    });
    let (offset, _) = parse_varint(&blocked.payload).unwrap();
    assert_eq!(offset, 4);
    assert!(result_rx.recv_timeout(Duration::from_millis(50)).is_err());

    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: stream.stream_id(),
        payload: encode_varint(5).unwrap(),
    });

    assert_eq!(
        result_rx
            .recv_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap(),
        1
    );
    write_thread.join().unwrap();

    let second = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(second.stream_id, stream.stream_id());
    assert_eq!(
        parse_data_payload(&second.payload, second.flags)
            .unwrap()
            .app_data,
        b"e"
    );
    client.close().ok();
}

#[test]
fn close_read_does_not_wait_for_flow_blocked_writer_after_opener() {
    let mut peer_config = Config::responder();
    peer_config
        .settings
        .initial_max_stream_data_bidi_peer_opened = 0;
    let (client, mut peer) = client_with_raw_peer_configs(Config::default(), peer_config);

    let stream = client.open_stream().unwrap();
    let writer = stream.clone();
    let (write_tx, write_rx) = mpsc::channel();
    let write_thread = thread::spawn(move || {
        let _ = write_tx.send(writer.write_timeout(b"hello", Duration::from_secs(2)));
    });

    let opening = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(opening.stream_id, stream.stream_id());

    let closer = stream.clone();
    let (close_tx, close_rx) = mpsc::channel();
    let close_thread = thread::spawn(move || {
        let _ = close_tx.send(closer.close_read());
    });

    let close_result = close_rx.recv_timeout(Duration::from_millis(200));

    stream.set_write_deadline(Some(Instant::now())).unwrap();
    let write_result = write_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("blocked writer did not wake after deadline");
    assert!(write_result
        .unwrap_err()
        .to_string()
        .contains("write timed out"));
    write_thread.join().unwrap();
    close_thread.join().unwrap();

    close_result
        .expect("close_read waited behind a flow-blocked writer")
        .unwrap();
    let stop = peer.wait_for_frame(|frame| frame.frame_type == FrameType::StopSending);
    assert_eq!(stop.stream_id, stream.stream_id());
}

#[test]
fn blocked_write_emits_session_and_stream_blocked_signals() {
    let peer_config = Config {
        settings: Settings {
            initial_max_data: 1,
            initial_max_stream_data_bidi_peer_opened: 1,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(Config::default(), peer_config);

    let stream = client.open_stream().unwrap();
    let writer = stream.clone();
    let write_thread =
        thread::spawn(move || writer.write_timeout(b"ab", Duration::from_millis(80)));

    let frames = peer.collect_frames_for(Duration::from_millis(120));
    let opening = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Data)
        .expect("opening DATA should be emitted before blocking");
    let blocked_offsets: Vec<_> = frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::Blocked)
        .map(|frame| {
            let (offset, n) = parse_varint(&frame.payload).unwrap();
            assert_eq!(n, frame.payload.len());
            (frame.stream_id, offset)
        })
        .collect();

    assert!(blocked_offsets.contains(&(0, 1)));
    assert!(blocked_offsets.contains(&(opening.stream_id, 1)));

    // The first byte was committed before the flow-control wait timed out, so the
    // partial write reports it; the next write surfaces the timeout.
    assert_eq!(write_thread.join().unwrap().unwrap(), 1);
    let err = stream
        .write_timeout(b"b", Duration::from_millis(20))
        .unwrap_err();
    assert!(err.to_string().contains("write timed out"));
    assert!(client.stats().blocked_write_total > Duration::ZERO);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn writer_queue_deadline_does_not_emit_unqueued_data() {
    let config = Config {
        write_queue_max_bytes: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(config);

    let stream = client.open_stream().unwrap();
    let err = stream
        .write_timeout(b"x", Duration::from_millis(20))
        .unwrap_err();
    assert!(err.to_string().contains("write timed out"));
    assert!(client.stats().blocked_write_total > Duration::ZERO);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Data));
}

#[test]
fn final_write_deadline_before_queue_admission_does_not_latch_fin() {
    let peer_config = Config {
        settings: Settings {
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_peer_opened: 0,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(Config::default(), peer_config);
    let stream = client.open_stream().unwrap();

    stream.set_write_deadline(Some(Instant::now())).unwrap();
    let err = stream.write_final(b"\x01").unwrap_err();

    assert!(err.is_timeout());
    assert!(!stream.is_write_closed());
    assert_eq!(client.stats().writer_queue.data_queued_bytes, 0);
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| frame.frame_type == FrameType::Data));

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn final_write_deadline_after_queue_admission_cancels_before_writer_starts() {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    let (client_write, writer_gate) = blocking_writer(client_io, 1);

    let client_thread = thread::spawn(move || Conn::client((client_read, client_write)).unwrap());
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = Config::responder().local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();
    let client = client_thread.join().unwrap();
    let mut peer = RawPeer {
        io: peer_io,
        read_buf: Vec::new(),
    };

    let first = client.open_stream().unwrap();
    let second = client.open_stream().unwrap();

    let (first_tx, first_rx) = mpsc::channel();
    let first_writer = first.clone();
    let first_thread = thread::spawn(move || {
        let _ = first_tx.send(first_writer.write(b"x"));
    });
    writer_gate.wait_blocked();
    assert!(first_rx.recv_timeout(Duration::from_millis(20)).is_err());

    let (second_tx, second_rx) = mpsc::channel();
    let second_writer = second.clone();
    let second_thread = thread::spawn(move || {
        let _ = second_tx.send(second_writer.write_final(b"y"));
    });

    let queue_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match second_rx.try_recv() {
            Ok(result) => panic!("final write completed before queued cancellation: {result:?}"),
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("final write worker disconnected before queued cancellation")
            }
        }
        if client.stats().writer_queue.data_queued_bytes > 0 {
            break;
        }
        if Instant::now() >= queue_deadline {
            panic!("final write did not enter the writer queue");
        }
        thread::sleep(Duration::from_millis(1));
    }

    second
        .set_write_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();
    let err = second_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("queued final write did not finish after deadline")
        .unwrap_err();
    assert!(err.is_timeout());
    second_thread.join().unwrap();
    assert!(!second.is_write_closed());
    assert_eq!(client.stats().writer_queue.data_queued_bytes, 0);

    writer_gate.release();
    assert_eq!(
        first_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap(),
        1
    );
    first_thread.join().unwrap();

    second.set_write_deadline(None).unwrap();
    assert_eq!(second.write(b"z").unwrap(), 1);
    let first_id = first.stream_id();
    let second_id = second.stream_id();

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let first_payload = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Data && frame.stream_id == first_id)
        .map(|frame| {
            parse_data_payload(&frame.payload, frame.flags)
                .unwrap()
                .app_data
        })
        .unwrap_or_else(|| panic!("missing first DATA after releasing writer: {frames:?}"));
    assert_eq!(first_payload, b"x");

    let second_data: Vec<_> = frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::Data && frame.stream_id == second_id)
        .map(|frame| {
            (
                parse_data_payload(&frame.payload, frame.flags)
                    .unwrap()
                    .app_data
                    .to_vec(),
                frame.flags,
            )
        })
        .collect();
    assert_eq!(
        second_data,
        vec![(b"z".to_vec(), 0)],
        "queued final write leaked or retry changed FIN state: {frames:?}"
    );

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn native_async_set_deadline_after_queue_admission_cancels_queued_write() {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    let (client_write, writer_gate) = blocking_writer(client_io, 1);

    let client_thread = thread::spawn(move || Conn::client((client_read, client_write)).unwrap());
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = Config::responder().local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();
    let client = client_thread.join().unwrap();

    let first = client.open_stream().unwrap();
    let second = client.open_stream().unwrap();

    let (first_tx, first_rx) = mpsc::channel();
    let first_writer = first.clone();
    let first_thread = thread::spawn(move || {
        let _ = first_tx.send(first_writer.write(b"x"));
    });
    writer_gate.wait_blocked();
    assert!(first_rx.recv_timeout(Duration::from_millis(20)).is_err());

    let (second_tx, second_rx) = mpsc::channel();
    let second_writer = second.clone();
    let second_thread = thread::spawn(move || {
        let _ = second_tx.send(block_on(zmux::AsyncSendStreamHandle::write(
            &second_writer,
            b"y",
        )));
    });

    let queue_deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().writer_queue.data_queued_bytes == 0 {
        if Instant::now() >= queue_deadline {
            panic!("async write did not enter the writer queue");
        }
        thread::sleep(Duration::from_millis(1));
    }

    second
        .set_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();
    let err = second_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("queued async write did not finish after set_deadline")
        .unwrap_err();
    assert!(err.is_timeout());
    second_thread.join().unwrap();
    assert!(!second.is_write_closed());
    assert_eq!(client.stats().writer_queue.data_queued_bytes, 0);

    writer_gate.release();
    assert_eq!(
        first_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap(),
        1
    );
    first_thread.join().unwrap();

    second.set_deadline(None).unwrap();
    assert_eq!(second.write(b"z").unwrap(), 1);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn close_write_deadline_failure_keeps_local_write_open_for_retry() {
    let config = Config {
        capabilities: CAPABILITY_OPEN_METADATA,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: CAPABILITY_OPEN_METADATA,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().open_info(b"x"))
        .unwrap();

    stream.set_write_deadline(Some(Instant::now())).unwrap();
    let err = stream.close_write().unwrap_err();
    assert!(err.is_timeout());
    assert!(!stream.is_write_closed());
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());

    stream.set_write_deadline(None).unwrap();
    stream.close_write().unwrap();
    assert!(stream.is_write_closed());

    let stream_id = stream.stream_id();
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let fin = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Data && frame.stream_id == stream_id)
        .unwrap_or_else(|| panic!("missing opener FIN after close_write retry: {frames:?}"));
    assert_ne!(fin.flags & FRAME_FLAG_OPEN_METADATA, 0);
    assert_ne!(fin.flags & FRAME_FLAG_FIN, 0);
    assert!(!fin.payload.is_empty());

    let repeated = stream.close_write().unwrap_err();
    assert_eq!(repeated.operation(), ErrorOperation::Close);
    assert_eq!(repeated.direction(), ErrorDirection::Write);
    assert_eq!(repeated.source(), ErrorSource::Local);
    assert_eq!(repeated.termination_kind(), TerminationKind::Graceful);
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames.iter().any(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    }));

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn write_deadline_failure_keeps_local_write_open_for_retry() {
    let config = Config {
        capabilities: CAPABILITY_OPEN_METADATA,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: CAPABILITY_OPEN_METADATA,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().open_info(b"x"))
        .unwrap();

    stream.set_write_deadline(Some(Instant::now())).unwrap();
    let err = stream.write(b"x").unwrap_err();
    assert!(err.is_timeout());
    assert!(!stream.is_write_closed());
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());

    stream.set_write_deadline(None).unwrap();
    assert_eq!(stream.write(b"x").unwrap(), 1);
    assert!(!stream.is_write_closed());

    let stream_id = stream.stream_id();
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let data = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Data && frame.stream_id == stream_id)
        .unwrap_or_else(|| panic!("missing opener DATA after write retry: {frames:?}"));
    assert_ne!(data.flags & FRAME_FLAG_OPEN_METADATA, 0);
    assert_eq!(data.flags & FRAME_FLAG_FIN, 0);
    assert!(!data.payload.is_empty());

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn set_write_deadline_wakes_close_read_blocked_on_writer_queue() {
    let config = Config {
        capabilities: CAPABILITY_OPEN_METADATA,
        write_queue_max_bytes: 1,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: CAPABILITY_OPEN_METADATA,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().open_info(b"x"))
        .unwrap();

    let closer = stream.clone();
    let blocked_close = thread::spawn(move || closer.close_read());
    thread::sleep(Duration::from_millis(10));
    stream
        .set_write_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();

    let err = blocked_close.join().unwrap().unwrap_err();
    assert!(err.to_string().contains("write timed out"));

    let mut buf = [0u8; 1];
    assert!(stream
        .read(&mut buf)
        .unwrap_err()
        .to_string()
        .contains("read side closed"));

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| matches!(frame.frame_type, FrameType::Data | FrameType::StopSending)));
}

#[test]
fn close_read_deadline_keeps_pending_signal_for_retry() {
    let config = Config {
        capabilities: CAPABILITY_OPEN_METADATA,
        write_queue_max_bytes: 1,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: CAPABILITY_OPEN_METADATA,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().open_info(b"x"))
        .unwrap();

    stream
        .set_write_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();
    let first_err = stream.close_read().unwrap_err();
    assert!(first_err.to_string().contains("write timed out"));

    stream.set_write_deadline(Some(Instant::now())).unwrap();
    let retry_err = stream.close_read().unwrap_err();
    assert!(retry_err.to_string().contains("write timed out"));

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| matches!(frame.frame_type, FrameType::Data | FrameType::StopSending)));
}

#[test]
fn close_read_retry_after_deadline_failure_queues_opener_and_stop_sending() {
    let config = Config {
        capabilities: CAPABILITY_OPEN_METADATA,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: CAPABILITY_OPEN_METADATA,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().open_info(b"x"))
        .unwrap();

    stream.set_write_deadline(Some(Instant::now())).unwrap();
    let first_err = stream.close_read().unwrap_err();
    assert!(first_err.is_timeout());
    assert!(stream.is_read_closed());
    let mut buf = [0u8; 1];
    let read_err = stream.read(&mut buf).unwrap_err();
    assert_local_read_stopped_error(&read_err);
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());

    stream.set_write_deadline(None).unwrap();
    stream.close_read().unwrap();

    let stream_id = stream.stream_id();
    let frames = peer.collect_frames_for(Duration::from_millis(200));
    let opener_index = frames
        .iter()
        .position(|frame| frame.frame_type == FrameType::Data && frame.stream_id == stream_id)
        .unwrap_or_else(|| panic!("missing opener DATA after retry: {frames:?}"));
    let stop_index = frames
        .iter()
        .position(|frame| {
            frame.frame_type == FrameType::StopSending && frame.stream_id == stream_id
        })
        .unwrap_or_else(|| panic!("missing STOP_SENDING after retry: {frames:?}"));
    assert!(
        opener_index < stop_index,
        "retry frames out of order: {frames:?}"
    );
    let opener = &frames[opener_index];
    assert_eq!(opener.stream_id, stream_id);
    assert_ne!(opener.flags & FRAME_FLAG_OPEN_METADATA, 0);
    assert!(!opener.payload.is_empty());

    let stop = &frames[stop_index];
    let (code, _) = parse_error_payload(&stop.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());

    let repeated = stream.close_read().unwrap_err();
    assert_eq!(repeated.operation(), ErrorOperation::Close);
    assert_eq!(repeated.direction(), ErrorDirection::Read);
    assert_eq!(repeated.source(), ErrorSource::Local);
    assert_eq!(repeated.termination_kind(), TerminationKind::Stopped);
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == stream_id));

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn update_metadata_bypasses_ordinary_queue_byte_limit() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS;
    let client_config = Config {
        capabilities: caps,
        write_queue_max_bytes: 17,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    stream
        .set_write_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();
    stream
        .update_metadata(MetadataUpdate {
            priority: Some(7),
            group: None,
        })
        .unwrap();
    assert_eq!(stream.metadata().priority, Some(7));

    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ext);
    assert_eq!(frame.stream_id, stream.stream_id());
}

#[test]
fn update_metadata_pending_priority_budget_error_does_not_mutate() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS;
    let client_config = Config {
        capabilities: caps,
        pending_priority_bytes_budget: Some(1),
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    let err = stream
        .update_metadata(MetadataUpdate {
            priority: Some(9),
            group: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("pending priority budget"));
    assert_eq!(stream.metadata().priority, None);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Ext));
    assert_eq!(client.stats().diagnostics.dropped_local_priority_updates, 1);
}

#[test]
fn empty_metadata_update_fails_with_stream_write_context() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();

    let err = stream
        .update_metadata(MetadataUpdate {
            priority: None,
            group: None,
        })
        .unwrap_err();

    assert!(err.to_string().contains("metadata update has no fields"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(stream.metadata().priority, None);
    assert_eq!(stream.metadata().group, None);
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn pre_open_priority_update_requires_open_metadata_capability() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();

    let err = stream
        .update_metadata(MetadataUpdate {
            priority: Some(7),
            group: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("metadata update requires"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(stream.metadata().priority, None);
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());
}

#[test]
fn post_open_priority_update_requires_negotiated_capability() {
    let (client, mut peer) = client_with_raw_peer(Config::default().disable_capabilities());
    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    let err = stream
        .update_metadata(MetadataUpdate {
            priority: Some(7),
            group: None,
        })
        .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("metadata update requires"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(stream.metadata().priority, None);
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| frame.frame_type == FrameType::Ext));
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn default_metadata_capabilities_do_not_mark_plain_open_data() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();

    stream.write_all(b"x").unwrap();
    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    assert_eq!(frame.flags & FRAME_FLAG_OPEN_METADATA, 0);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, b"x");
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .all(|frame| frame.frame_type != FrameType::Data));
    client.close().ok();
}

#[test]
fn pre_open_metadata_update_overflow_does_not_mutate() {
    let caps = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let open_info = pre_open_overflow_open_info(caps, Settings::default().max_frame_payload, 7, 11);
    let stream = client
        .open_stream_with(OpenOptions::new().open_info(&open_info))
        .unwrap();

    let err = stream
        .update_metadata(MetadataUpdate {
            priority: Some(7),
            group: Some(11),
        })
        .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err
        .to_string()
        .contains("opening metadata exceeds peer max_frame_payload"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(stream.metadata().priority, None);
    assert_eq!(stream.metadata().group, None);
    assert_eq!(stream.open_info(), open_info);
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());
    client.close().unwrap();
}

#[test]
fn pre_open_open_metadata_updates_merge_partial_fields() {
    let caps = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();

    stream
        .update_metadata(MetadataUpdate {
            priority: Some(7),
            group: None,
        })
        .unwrap();
    stream
        .update_metadata(MetadataUpdate {
            priority: None,
            group: Some(9),
        })
        .unwrap();
    assert_eq!(stream.metadata().priority, Some(7));
    assert_eq!(stream.metadata().group, Some(9));

    stream.write(b"x").unwrap();
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let opening = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Data)
        .expect("missing opening DATA");
    assert_eq!(opening.stream_id, stream.stream_id());
    assert!(frames
        .iter()
        .all(|frame| frame.frame_type != FrameType::Ext));
    let expected_prefix = build_open_metadata_prefix(
        caps,
        Some(7),
        Some(9),
        &[],
        Settings::default().max_frame_payload,
    )
    .unwrap();
    assert!(opening.flags & FRAME_FLAG_OPEN_METADATA != 0);
    assert!(opening.payload.starts_with(&expected_prefix));
}

#[test]
fn group_zero_is_wire_clear_not_public_group() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    stream
        .update_metadata(MetadataUpdate {
            priority: None,
            group: Some(9),
        })
        .unwrap();
    assert_eq!(stream.metadata().group, Some(9));
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ext);

    stream
        .update_metadata(MetadataUpdate {
            priority: None,
            group: Some(0),
        })
        .unwrap();
    assert_eq!(stream.metadata().group, None);
    let clear = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ext);
    assert_eq!(
        clear.payload,
        build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: None,
                group: Some(0),
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap()
    );
}

#[test]
fn open_metadata_preserves_explicit_group_zero_when_rebuilt() {
    let caps = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().group(0))
        .unwrap();
    assert_eq!(stream.metadata().group, None);

    stream
        .update_metadata(MetadataUpdate {
            priority: Some(5),
            group: None,
        })
        .unwrap();
    stream.write(b"x").unwrap();
    let opening = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    let expected_prefix = build_open_metadata_prefix(
        caps,
        Some(5),
        Some(0),
        &[],
        Settings::default().max_frame_payload,
    )
    .unwrap();
    assert!(opening.flags & FRAME_FLAG_OPEN_METADATA != 0);
    assert!(opening.payload.starts_with(&expected_prefix));
}

#[test]
fn unnegotiated_priority_update_is_ignored() {
    let (client, mut peer) = client_with_raw_peer(Config::default().disable_capabilities());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"body".to_vec(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&stream), b"body");

    let payload_caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS;
    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            payload_caps,
            MetadataUpdate {
                priority: Some(9),
                group: None,
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });
    thread::sleep(Duration::from_millis(50));

    assert_eq!(stream.metadata().priority, None);
    assert_eq!(client.stats().abuse.dropped_priority_update, 0);
    assert_eq!(client.stats().abuse.no_op_priority_update, 0);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn open_metadata_ignores_unnegotiated_priority_and_group_fields() {
    let negotiated_caps = CAPABILITY_OPEN_METADATA;
    let payload_caps =
        CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: negotiated_caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: negotiated_caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let mut payload = build_open_metadata_prefix(
        payload_caps,
        Some(5),
        Some(7),
        b"ssh",
        Settings::default().max_frame_payload,
    )
    .unwrap();
    payload.extend_from_slice(b"body");

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA,
        stream_id: 1,
        payload,
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();

    assert_eq!(read_once_stream(&stream), b"body");
    let metadata = stream.metadata();
    assert_eq!(metadata.priority, None);
    assert_eq!(metadata.group, None);
    assert_eq!(stream.open_info(), b"ssh".as_slice());
    assert_eq!(metadata.open_info, b"ssh");
    assert_eq!(metadata.open_info(), stream.open_info().as_slice());
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn accepted_stream_metadata_snapshot_includes_peer_open_info() {
    let caps = CAPABILITY_OPEN_METADATA
        | CAPABILITY_PRIORITY_UPDATE
        | CAPABILITY_PRIORITY_HINTS
        | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let mut payload = build_open_metadata_prefix(
        caps,
        Some(5),
        Some(7),
        b"ssh",
        Settings::default().max_frame_payload,
    )
    .unwrap();
    payload.extend_from_slice(b"body");
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA,
        stream_id: 1,
        payload,
    });

    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let metadata = stream.metadata();
    assert_eq!(metadata.priority, Some(5));
    assert_eq!(metadata.group, Some(7));
    assert_eq!(metadata.open_info, b"ssh");
    assert_eq!(metadata.open_info, stream.open_info());

    let boxed: zmux::BoxDuplexStream = Box::new(stream.clone());
    assert_eq!(boxed.metadata().open_info, b"ssh");
    let info: &dyn zmux::StreamHandle = &stream;
    assert_eq!(info.metadata().open_info, b"ssh");

    assert_eq!(read_once_stream(&stream), b"body");

    // A later advisory update changes only the advisory fields of the snapshot.
    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: Some(9),
                group: None,
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while stream.metadata().priority != Some(9) {
        assert!(Instant::now() < deadline, "priority update was not applied");
        thread::sleep(Duration::from_millis(5));
    }
    let metadata = stream.metadata();
    assert_eq!(metadata.group, Some(7));
    assert_eq!(metadata.open_info, b"ssh");

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn local_and_accepted_stream_metadata_snapshots_include_open_info() {
    let caps = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let server_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, server_config);

    let stream = client
        .open_stream_with(OpenOptions::new().priority(3).open_info(b"x"))
        .unwrap();
    let metadata = stream.metadata();
    assert_eq!(metadata.priority, Some(3));
    assert_eq!(metadata.open_info, b"x");
    stream.write(b"ping").unwrap();
    assert_eq!(stream.metadata().open_info, b"x");
    assert_eq!(stream.metadata().open_info, stream.open_info());

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(accepted.metadata().priority, Some(3));
    assert_eq!(accepted.metadata().open_info, b"x");
    assert_eq!(read_once_stream(&accepted), b"ping");

    let send = client
        .open_uni_stream_with(OpenOptions::new().open_info(b"uni"))
        .unwrap();
    assert_eq!(send.metadata().open_info, b"uni");
    send.write(b"hello").unwrap();
    assert_eq!(send.metadata().open_info, send.open_info());
    let boxed_send: zmux::BoxSendStream = Box::new(send.clone());
    assert_eq!(boxed_send.metadata().open_info, send.open_info());

    let recv = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(recv.metadata().open_info, b"uni");
    assert_eq!(recv.metadata().open_info, recv.open_info());
    let boxed_recv: zmux::BoxRecvStream = Box::new(recv.clone());
    assert_eq!(boxed_recv.metadata().open_info, b"uni");

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
    server
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn priority_update_ignores_unnegotiated_priority_and_group_fields() {
    let negotiated_caps = CAPABILITY_PRIORITY_UPDATE;
    let payload_caps =
        CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: negotiated_caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: negotiated_caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"body".to_vec(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&stream), b"body");

    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            payload_caps,
            MetadataUpdate {
                priority: Some(9),
                group: Some(11),
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });
    thread::sleep(Duration::from_millis(50));

    let metadata = stream.metadata();
    assert_eq!(metadata.priority, None);
    assert_eq!(metadata.group, None);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn inbound_partial_priority_updates_preserve_unspecified_fields() {
    let caps = CAPABILITY_OPEN_METADATA
        | CAPABILITY_PRIORITY_UPDATE
        | CAPABILITY_PRIORITY_HINTS
        | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let mut payload = build_open_metadata_prefix(
        caps,
        Some(5),
        Some(7),
        &[],
        Settings::default().max_frame_payload,
    )
    .unwrap();
    payload.extend_from_slice(b"body");

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA,
        stream_id: 1,
        payload,
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&stream), b"body");
    assert_eq!(stream.metadata().priority, Some(5));
    assert_eq!(stream.metadata().group, Some(7));

    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: Some(9),
                group: None,
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while stream.metadata().priority != Some(9) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(stream.metadata().priority, Some(9));
    assert_eq!(stream.metadata().group, Some(7));

    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: None,
                group: Some(11),
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while stream.metadata().group != Some(11) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(stream.metadata().priority, Some(9));
    assert_eq!(stream.metadata().group, Some(11));

    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: None,
                group: Some(0),
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while stream.metadata().group.is_some() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(stream.metadata().priority, Some(9));
    assert_eq!(stream.metadata().group, None);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn pre_open_open_metadata_survives_opener_deadline() {
    let caps = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS;
    let client_config = Config {
        capabilities: caps,
        write_queue_max_bytes: 1,
        ..Config::default()
    };
    let peer_config = Config {
        role: zmux::Role::Responder,
        capabilities: caps,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    stream
        .update_metadata(MetadataUpdate {
            priority: Some(7),
            group: None,
        })
        .unwrap();

    let err = stream
        .write_timeout(b"x", Duration::from_millis(20))
        .unwrap_err();
    assert!(err.to_string().contains("write timed out"));
    assert_eq!(stream.metadata().priority, Some(7));

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| matches!(frame.frame_type, FrameType::Data | FrameType::Ext)));
}

#[test]
fn cancel_write_queues_reset_despite_tiny_writer_queue() {
    let config = Config {
        write_queue_max_bytes: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(config);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });

    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .expect("peer-opened stream should be accepted");
    accepted.cancel_write(77).unwrap();

    let reset = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == accepted.stream_id()
    });
    let (code, reason) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, 77);
    assert!(reason.is_empty());
}

#[test]
fn close_with_error_queues_abort_despite_tiny_writer_queue() {
    let config = Config {
        write_queue_max_bytes: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(config);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });

    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .expect("peer-opened stream should be accepted");
    accepted.close_with_error(55, "bye").unwrap();

    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == accepted.stream_id()
    });
    let (code, reason) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, 55);
    assert_eq!(reason, "bye");
}

#[test]
fn uni_stream_close_with_error_helpers_queue_abort_frames() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let send = client.open_uni_stream().unwrap();
    send.write(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data && frame.stream_id == send.stream_id()
    });
    send.close_with_error(55, "send abort").unwrap();
    let send_abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == opened.stream_id
    });
    let (code, reason) = parse_error_payload(&send_abort.payload).unwrap();
    assert_eq!(code, 55);
    assert_eq!(reason, "send abort");

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 3,
        payload: b"x".to_vec(),
    });
    let recv = client
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    recv.close_with_error(66, "recv abort").unwrap();
    let recv_abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == recv.stream_id()
    });
    let (code, reason) = parse_error_payload(&recv_abort.payload).unwrap();
    assert_eq!(code, 66);
    assert_eq!(reason, "recv abort");

    client.close().ok();
}

#[test]
fn repeated_stream_close_with_error_keeps_first_pending_abort() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });
    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .expect("peer-opened stream should be accepted");

    accepted.close_with_error(7, "abort").unwrap();
    accepted.close_with_error(8, "later").unwrap();

    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == accepted.stream_id()
    });
    let (code, reason) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, 7);
    assert_eq!(reason, "abort");
    let frames = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames.iter().any(
        |frame| frame.frame_type == FrameType::Abort && frame.stream_id == accepted.stream_id()
    ));
    let stats = client.stats();
    assert_eq!(stats.reasons.abort.get(&7), Some(&1));
    assert!(!stats.reasons.abort.contains_key(&8));
    assert_eq!(stats.diagnostics.coalesced_terminal_signals, 0);
    assert_eq!(stats.diagnostics.superseded_terminal_signals, 0);

    client.close().ok();
}

#[test]
fn final_read_compacts_terminal_accepted_stream_after_local_reset() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let payload = b"fin".to_vec();

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: payload.clone(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    stream.cancel_write(ErrorCode::Cancelled.as_u64()).unwrap();

    let reset =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Reset && frame.stream_id == 1);
    let (code, _) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());
    assert_eq!(client.stats().active_streams.peer_bidi, 0);

    let mut dst = [0u8; 3];
    assert_eq!(stream.read(&mut dst).unwrap(), payload.len());
    assert_eq!(&dst, payload.as_slice());
    wait_for_open_streams(&client, 0);
    assert!(client.stats().retention.tombstones > 0);

    let mut eof = [0u8; 1];
    assert_eq!(stream.read(&mut eof).unwrap(), 0);
    client.close().ok();
}

#[test]
fn local_cancel_write_compacts_terminal_accepted_stream_without_buffered_payload() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    stream.cancel_write(ErrorCode::Cancelled.as_u64()).unwrap();

    let reset =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Reset && frame.stream_id == 1);
    let (code, _) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());
    wait_for_open_streams(&client, 0);
    assert!(client.stats().retention.tombstones > 0);

    let mut eof = [0u8; 1];
    assert_eq!(stream.read(&mut eof).unwrap(), 0);
    client.close().ok();
}

#[test]
fn local_abort_compacts_after_discarding_buffered_payload() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"buf".to_vec(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(client.stats().pressure.buffered_receive_bytes, 3);

    stream.close_with_error(55, "abort").unwrap();
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);
    let (code, reason) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, 55);
    assert_eq!(reason, "abort");
    wait_for_open_streams(&client, 0);
    assert_eq!(client.stats().pressure.buffered_receive_bytes, 0);
    assert!(client.stats().retention.tombstones > 0);

    let mut dst = [0u8; 1];
    let err = stream.read(&mut dst).unwrap_err();
    assert_eq!(err.numeric_code(), Some(55));
    client.close().ok();
}

#[test]
fn session_close_with_invalid_varint_code_does_not_terminate() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let err = client
        .close_with_error(MAX_VARINT62 + 1, "out of range")
        .unwrap_err();
    assert!(err.is_error_code(ErrorCode::Protocol));
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(client.state(), SessionState::Ready);
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close_with_error(55, "bye").unwrap();
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, 55);
    assert_eq!(reason, "bye");
}

#[test]
fn committed_local_abort_invalid_code_keeps_stream_abortable() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    let err = stream
        .close_with_error(MAX_VARINT62 + 1, "out of range")
        .unwrap_err();
    assert!(err.is_error_code(ErrorCode::Protocol));
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.direction(), ErrorDirection::Both);

    stream.close_with_error(41, "").unwrap();
    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == opened.stream_id
    });
    let (code, reason) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, 41);
    assert!(reason.is_empty());
}

#[test]
fn committed_local_cancel_read_invalid_code_keeps_stream_read_stoppable() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    let err = stream.cancel_read(MAX_VARINT62 + 1).unwrap_err();
    assert!(err.is_error_code(ErrorCode::Protocol));
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert!(!stream.is_read_closed());
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| frame.frame_type == FrameType::StopSending));

    stream.close_read().unwrap();
    let stop = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::StopSending && frame.stream_id == opened.stream_id
    });
    let (code, reason) = parse_error_payload(&stop.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());
    assert!(reason.is_empty());
}

struct RawPeer {
    io: MemoryConn,
    read_buf: Vec<u8>,
}

impl RawPeer {
    fn write_frame(&mut self, frame: Frame) {
        self.io.write_all(&frame.marshal().unwrap()).unwrap();
        self.io.flush().unwrap();
    }

    fn write_raw_frame_parts(
        &mut self,
        frame_type: FrameType,
        flags: u8,
        stream_id: u64,
        payload: &[u8],
    ) {
        let stream_id = encode_varint(stream_id).unwrap();
        let body_len = 1usize
            .checked_add(stream_id.len())
            .and_then(|len| len.checked_add(payload.len()))
            .unwrap();
        let mut raw = encode_varint(usize_to_u64(body_len)).unwrap();
        raw.push(frame_type.as_u8() | flags);
        raw.extend_from_slice(&stream_id);
        raw.extend_from_slice(payload);
        self.io.write_all(&raw).unwrap();
        self.io.flush().unwrap();
    }

    fn drain_frames(&mut self) -> Vec<Frame> {
        {
            let mut state = self.io.inbound.state.lock().unwrap();
            while let Some(byte) = state.bytes.pop_front() {
                self.read_buf.push(byte);
            }
        }

        let mut frames = Vec::new();
        while !self.read_buf.is_empty() {
            let Ok((frame, n)) = Frame::parse(&self.read_buf, Limits::default()) else {
                break;
            };
            self.read_buf.drain(..n);
            frames.push(frame);
        }
        frames
    }

    fn wait_for_frame(&mut self, predicate: impl FnMut(&Frame) -> bool) -> Frame {
        self.wait_for_frame_with_limits(Limits::default(), predicate)
    }

    fn wait_for_frame_with_limits(
        &mut self,
        limits: Limits,
        mut predicate: impl FnMut(&Frame) -> bool,
    ) -> Frame {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            {
                let mut state = self.io.inbound.state.lock().unwrap();
                while let Some(byte) = state.bytes.pop_front() {
                    self.read_buf.push(byte);
                }
            }

            let mut frames = Vec::new();
            while !self.read_buf.is_empty() {
                let Ok((frame, n)) = Frame::parse(&self.read_buf, limits) else {
                    break;
                };
                self.read_buf.drain(..n);
                frames.push(frame);
            }

            for frame in frames {
                if predicate(&frame) {
                    return frame;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for frame");
    }

    fn collect_frames_for(&mut self, duration: Duration) -> Vec<Frame> {
        let deadline = Instant::now() + duration;
        let mut frames = Vec::new();
        while Instant::now() < deadline {
            frames.extend(self.drain_frames());
            thread::sleep(Duration::from_millis(10));
        }
        frames.extend(self.drain_frames());
        frames
    }
}

fn client_with_raw_peer(client_config: Config) -> (Conn, RawPeer) {
    client_with_raw_peer_configs(client_config, Config::responder())
}

fn client_with_raw_peer_configs(client_config: Config, peer_config: Config) -> (Conn, RawPeer) {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    let client_write = client_io;

    let client_thread = thread::spawn(move || {
        Conn::client_with_config((client_read, client_write), client_config).unwrap()
    });
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = peer_config.local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();

    (
        client_thread.join().unwrap(),
        RawPeer {
            io: peer_io,
            read_buf: Vec::new(),
        },
    )
}

fn client_with_rendezvous_raw_peer(client_config: Config) -> (Conn, RendezvousConn) {
    let (client_io, mut peer_io) = rendezvous_pair();
    let client_read = client_io.clone();
    let client_write = client_io;

    let client_thread = thread::spawn(move || {
        Conn::client_with_config((client_read, client_write), client_config).unwrap()
    });
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = Config::responder().local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();

    (client_thread.join().unwrap(), peer_io)
}

fn client_with_rendezvous_raw_peer_and_write_probe(
    client_config: Config,
) -> (Conn, RendezvousConn, Receiver<()>) {
    let (client_io, mut peer_io, write_probe_rx) = rendezvous_pair_with_client_write_probe();
    let client_read = client_io.clone();
    let client_write = client_io;

    let client_thread = thread::spawn(move || {
        Conn::client_with_config((client_read, client_write), client_config).unwrap()
    });
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = Config::responder().local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();
    while write_probe_rx.try_recv().is_ok() {}

    (client_thread.join().unwrap(), peer_io, write_probe_rx)
}

fn start_blocked_rendezvous_write(
    stream: zmux::Stream,
    write_probe_rx: &Receiver<()>,
) -> (Receiver<zmux::Result<usize>>, thread::JoinHandle<()>) {
    let (result_tx, result_rx) = mpsc::channel();
    let write_thread = thread::spawn(move || {
        let _ = result_tx.send(stream.write(b"x"));
    });
    write_probe_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("writer did not attempt rendezvous transport write");
    assert!(result_rx.recv_timeout(Duration::from_millis(20)).is_err());
    (result_rx, write_thread)
}

fn finish_blocked_rendezvous_write(
    peer: &mut RendezvousConn,
    result_rx: Receiver<zmux::Result<usize>>,
    write_thread: thread::JoinHandle<()>,
) {
    let data = wait_for_rendezvous_frame(peer, |frame| frame.frame_type == FrameType::Data);
    let payload = parse_data_payload(&data.payload, data.flags).unwrap();
    assert_eq!(payload.app_data, b"x");
    assert_eq!(
        result_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap(),
        1
    );
    write_thread.join().unwrap();
}

fn client_with_raw_peer_and_failing_writer_after_preface(
    client_config: Config,
    message: &'static str,
) -> (Conn, RawPeer) {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    let client_write = FailAfterWrites {
        inner: client_io,
        remaining_successful_writes: Arc::new(AtomicUsize::new(1)),
        message,
    };

    let client_thread = thread::spawn(move || {
        Conn::client_with_config((client_read, client_write), client_config).unwrap()
    });
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = Config::responder().local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();

    (
        client_thread.join().unwrap(),
        RawPeer {
            io: peer_io,
            read_buf: Vec::new(),
        },
    )
}

#[test]
fn failed_establishment_emits_fatal_close_after_local_preface() {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    let client_write = client_io;

    let client_thread = thread::spawn(move || Conn::client((client_read, client_write)));
    let _client_preface = read_preface(&mut peer_io).unwrap();
    peer_io.write_all(b"ZMUX\x01\xff").unwrap();
    peer_io.flush().unwrap();

    let result = client_thread.join().unwrap();
    assert!(result.is_err());

    let mut written = Vec::new();
    peer_io.read_to_end(&mut written).unwrap();
    let (frame, used) = Frame::parse(&written, Limits::default()).unwrap();
    assert_eq!(used, written.len());
    assert_eq!(frame.frame_type, FrameType::Close);
    let (code, _) = parse_error_payload(&frame.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
}

#[test]
fn same_role_establishment_conflict_emits_role_conflict_close() {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    let client_write = client_io;

    let client_thread = thread::spawn(move || Conn::client((client_read, client_write)));
    let client_preface = read_preface(&mut peer_io).unwrap();
    assert_eq!(client_preface.role, zmux::Role::Initiator);

    let peer_config = Config {
        role: zmux::Role::Initiator,
        ..Config::default()
    };
    let peer_preface = peer_config.local_preface().unwrap();
    peer_io.write_all(&peer_preface.marshal().unwrap()).unwrap();
    peer_io.flush().unwrap();

    let result = client_thread.join().unwrap();
    let err = match result {
        Ok(_) => panic!("same-role establishment unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.code(), Some(ErrorCode::RoleConflict));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);

    let mut written = Vec::new();
    peer_io.read_to_end(&mut written).unwrap();
    let (frame, used) = Frame::parse(&written, Limits::default()).unwrap();
    assert_eq!(used, written.len());
    assert_eq!(frame.frame_type, FrameType::Close);
    let (code, _) = parse_error_payload(&frame.payload).unwrap();
    assert_eq!(code, ErrorCode::RoleConflict.as_u64());
}

#[test]
fn graceful_close_sends_final_goaway_before_close() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let _stream = client.open_stream().unwrap();

    client.close().unwrap();
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let goaway_indices: Vec<_> = frames
        .iter()
        .enumerate()
        .filter_map(|(index, frame)| (frame.frame_type == FrameType::GoAway).then_some(index))
        .collect();
    assert!(!goaway_indices.is_empty(), "close must send final GOAWAY");
    let close_index = frames
        .iter()
        .position(|frame| frame.frame_type == FrameType::Close)
        .expect("close must send CLOSE");
    let goaway_index = goaway_indices
        .iter()
        .copied()
        .rfind(|index| *index < close_index)
        .expect("close must send final GOAWAY before CLOSE");

    assert!(goaway_index < close_index);

    let goaway = parse_go_away_payload(&frames[goaway_index].payload).unwrap();
    assert_eq!(goaway.last_accepted_bidi, 0);
    assert_eq!(goaway.last_accepted_uni, 0);
    assert_eq!(goaway.code, ErrorCode::NoError.as_u64());
    assert!(goaway.reason.is_empty());

    let (code, reason) = parse_error_payload(&frames[close_index].payload).unwrap();
    assert_eq!(code, ErrorCode::NoError.as_u64());
    assert!(reason.is_empty());
}

#[test]
fn close_without_graceful_pending_work_sends_direct_close() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    client.close().unwrap();
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::GoAway));
    let close = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Close)
        .expect("close must send CLOSE");
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::NoError.as_u64());
    assert!(reason.is_empty());
}

#[test]
fn manual_goaway_still_allows_local_open() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    client
        .go_away_with_error(0, 0, ErrorCode::NoError.as_u64(), "")
        .unwrap();

    let stream = client.open_stream().unwrap();
    stream.write_final(b"ok").unwrap();
    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_all_stream(&accepted), b"ok");
    accepted.close_write().unwrap();

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn graceful_close_blocks_new_local_opens_during_drain() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let stream = client.open_uni_stream().unwrap();
    stream.write(b"hello").unwrap();
    let _accepted = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    stream
        .set_write_deadline(Some(Instant::now() + Duration::from_secs(5)))
        .unwrap();
    let closer = client.clone();
    let (close_tx, close_rx) = mpsc::channel();
    let close_thread = thread::spawn(move || {
        let _ = close_tx.send(closer.close());
    });

    wait_for_state(&client, SessionState::Draining);
    let err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded during graceful close"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), zmux::ErrorSource::Local);

    stream.close_write().unwrap();
    assert!(close_rx
        .recv_timeout(Duration::from_secs(6))
        .unwrap()
        .is_ok());
    close_thread.join().unwrap();
    server.close().ok();
}

#[test]
fn graceful_close_blocks_new_local_opens_during_initial_goaway_drain() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(5),
        go_away_drain_interval: Duration::from_millis(200),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"hold-open").unwrap();

    let closer = client.clone();
    let close_thread = thread::spawn(move || closer.close());
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    wait_for_state(&client, SessionState::Draining);

    let err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded during graceful close"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Local);

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::NoError.as_u64(), ""),
    });
    close_thread.join().unwrap().unwrap();
}

#[test]
fn graceful_close_drain_keeps_session_ops_until_terminal_close() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let stream = client.open_uni_stream().unwrap();
    stream.write(b"held").unwrap();
    let _accepted = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();

    let closer = client.clone();
    let (close_tx, close_rx) = mpsc::channel();
    let close_thread = thread::spawn(move || {
        let _ = close_tx.send(closer.close());
    });

    wait_for_state(&client, SessionState::Draining);

    // During the drain only new local opens stop; the session keeps working
    // for existing streams and peer-facing operations (SPEC §6.9).
    let open_err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded during graceful close"),
        Err(err) => err,
    };
    assert!(open_err.is_session_closed());
    let accept_err = match client.accept_stream_timeout(Duration::from_millis(20)) {
        Ok(_) => panic!("accept_stream unexpectedly returned a stream"),
        Err(err) => err,
    };
    assert!(accept_err.is_timeout(), "{accept_err:?}");
    client
        .ping_timeout(b"probe", Duration::from_secs(1))
        .unwrap();
    stream
        .set_write_deadline(Some(Instant::now() + Duration::from_secs(5)))
        .unwrap();

    stream.close_write().unwrap();
    assert!(close_rx
        .recv_timeout(Duration::from_secs(6))
        .unwrap()
        .is_ok());
    close_thread.join().unwrap();

    let accept_err = match client.accept_stream_timeout(Duration::from_millis(20)) {
        Ok(_) => panic!("accept_stream unexpectedly succeeded after local close"),
        Err(err) => err,
    };
    assert!(accept_err.is_session_closed());
    assert_eq!(accept_err.scope(), ErrorScope::Session);
    assert_eq!(accept_err.operation(), ErrorOperation::Accept);
    assert_eq!(accept_err.source(), ErrorSource::Local);

    let ping_err = client
        .ping_timeout(b"probe", Duration::from_millis(20))
        .unwrap_err();
    assert!(ping_err.is_session_closed());
    assert_eq!(ping_err.scope(), ErrorScope::Session);
    assert_eq!(ping_err.source(), ErrorSource::Local);
    assert!(!client.stats().liveness.ping_outstanding);

    let goaway_err = client.go_away(0, 0).unwrap_err();
    assert!(goaway_err.is_session_closed());
    assert_eq!(goaway_err.scope(), ErrorScope::Session);
    assert_eq!(goaway_err.operation(), ErrorOperation::Close);
    assert_eq!(goaway_err.source(), ErrorSource::Local);

    let deadline_err = stream.set_write_deadline(Some(Instant::now())).unwrap_err();
    assert!(deadline_err.is_session_closed());
    assert_eq!(deadline_err.scope(), ErrorScope::Stream);
    assert_eq!(deadline_err.operation(), ErrorOperation::Write);
    assert_eq!(deadline_err.source(), ErrorSource::Local);
    server.close().ok();
}

#[test]
fn completed_local_close_blocks_subsequent_open_with_local_session_error() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    client.close().unwrap();

    let err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded after local close"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    server.close().ok();
}

#[test]
fn graceful_close_reclaims_provisional_local_streams_with_refused_stream() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(20),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let bidi = client.open_stream().unwrap();
    let uni = client.open_uni_stream().unwrap();

    client.close().unwrap();

    let bidi_err = bidi.write(b"x").unwrap_err();
    assert_eq!(
        bidi_err.numeric_code(),
        Some(ErrorCode::RefusedStream.as_u64())
    );
    let uni_err = uni.write(b"y").unwrap_err();
    assert_eq!(
        uni_err.numeric_code(),
        Some(ErrorCode::RefusedStream.as_u64())
    );
    server.close().ok();
}

#[test]
fn graceful_close_ignores_unread_peer_uni_stream() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(20),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let peer_stream = server.open_uni_stream().unwrap();
    peer_stream.write_final(b"peer").unwrap();
    let _accepted = client
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();

    let started = Instant::now();
    client.close().unwrap();
    assert!(started.elapsed() < Duration::from_millis(200));
    server.close().ok();
}

#[test]
fn graceful_close_waits_for_peer_bidi_local_send_to_finish() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(1),
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let peer_stream = server.open_stream().unwrap();
    peer_stream.write_final(b"peer").unwrap();
    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    accepted.write(b"reply").unwrap();
    accepted
        .set_write_deadline(Some(Instant::now() + Duration::from_secs(1)))
        .unwrap();
    let closer = client.clone();
    let (close_tx, close_rx) = mpsc::channel();
    let close_thread = thread::spawn(move || {
        let _ = close_tx.send(closer.close());
    });

    wait_for_state(&client, SessionState::Draining);
    assert!(close_rx.recv_timeout(Duration::from_millis(50)).is_err());

    accepted.close_write().unwrap();
    assert!(close_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .is_ok());
    close_thread.join().unwrap();
    server.close().ok();
}

#[test]
fn local_abort_releases_graceful_close_blocker() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(1),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"live").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    let closer = client.clone();
    let (close_tx, close_rx) = mpsc::channel();
    let close_thread = thread::spawn(move || {
        let _ = close_tx.send(closer.close());
    });

    wait_for_state(&client, SessionState::Draining);
    assert!(close_rx.recv_timeout(Duration::from_millis(50)).is_err());

    stream.close_with_error(41, "").unwrap();
    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == opened.stream_id
    });
    let (code, reason) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, 41);
    assert!(reason.is_empty());

    assert!(close_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .is_ok());
    close_thread.join().unwrap();
}

#[test]
fn peer_stop_sending_unblocks_graceful_close_with_local_send_work() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"peer".to_vec(),
    });
    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    accepted.write(b"reply").unwrap();
    peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data && frame.stream_id == 1);

    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "peer stop"),
    });
    let terminal = peer.wait_for_frame(|frame| {
        frame.stream_id == 1
            && (frame.frame_type == FrameType::Reset
                || (frame.frame_type == FrameType::Data && frame.flags & FRAME_FLAG_FIN != 0))
    });
    assert!(matches!(
        terminal.frame_type,
        FrameType::Reset | FrameType::Data
    ));

    let started = Instant::now();
    client.close().unwrap();
    assert!(started.elapsed() < Duration::from_millis(200));
}

#[test]
fn peer_close_error_preserves_code_and_reason() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(ErrorCode::Internal.as_u64()).unwrap(),
    });

    wait_for_state(&client, SessionState::Failed);
    let peer_error = client.peer_close_error().unwrap();
    assert_eq!(peer_error.code, ErrorCode::Internal.as_u64());
    assert_eq!(peer_error.reason, "");
    let err = client.wait_timeout(Duration::ZERO).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::Internal));
    assert_eq!(err.source(), zmux::ErrorSource::Remote);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);
}

#[test]
fn peer_no_error_close_blocks_new_open_with_session_closed_error() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::NoError.as_u64(), ""),
    });

    wait_for_state(&client, SessionState::Closed);
    assert!(client.wait_timeout(Duration::ZERO).unwrap());
    let err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded after peer CLOSE(NO_ERROR)"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);
}

#[test]
fn peer_close_discards_buffered_data_on_accepted_stream() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"hello".to_vec(),
    });
    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::Protocol.as_u64(), "protocol"),
    });

    wait_for_state(&client, SessionState::Failed);
    let mut buf = [0u8; 8];
    let err = accepted.read(&mut buf).unwrap_err();
    assert_eq!(err.numeric_code(), Some(ErrorCode::Protocol.as_u64()));
    assert_eq!(err.reason(), Some("protocol"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Read);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);
    assert_eq!(client.stats().pressure.buffered_receive_bytes, 0);
}

#[test]
fn peer_close_clears_accepted_backlog() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"hello".to_vec(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().accept_backlog.bidi == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client.stats().accept_backlog.bidi, 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::Protocol.as_u64(), "protocol"),
    });

    wait_for_state(&client, SessionState::Failed);
    let stats = client.stats();
    assert_eq!(stats.open_streams, 0);
    assert_eq!(stats.accept_backlog.bidi, 0);
    assert_eq!(stats.accept_backlog.bytes, 0);
    assert_eq!(stats.pressure.buffered_receive_bytes, 0);

    let err = match client.accept_stream_timeout(Duration::from_millis(10)) {
        Ok(_) => panic!("accept_stream unexpectedly succeeded after peer CLOSE"),
        Err(err) => err,
    };
    assert_eq!(err.numeric_code(), Some(ErrorCode::Protocol.as_u64()));
    assert_eq!(err.reason(), Some("protocol"));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Accept);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);
}

#[test]
fn peer_transport_eof_while_ready_fails_session() {
    let (client, peer) = client_with_raw_peer(Config::default());

    drop(peer);

    wait_for_state(&client, SessionState::Failed);
    let cause = client.close_error().unwrap();
    assert_eq!(cause.scope(), ErrorScope::Session);
    assert_eq!(cause.operation(), ErrorOperation::Read);
    assert_eq!(cause.source(), ErrorSource::Transport);
    assert_eq!(cause.direction(), ErrorDirection::Read);
    let err = client.wait_timeout(Duration::ZERO).unwrap_err();
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), ErrorSource::Transport);
    assert_eq!(err.direction(), ErrorDirection::Read);
}

#[test]
fn peer_transport_eof_while_local_close_in_progress_completes_closed() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(5),
        go_away_drain_interval: Duration::from_millis(100),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"hold-open").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(opened.stream_id, stream.stream_id());

    let closer = client.clone();
    let close_thread = thread::spawn(move || closer.close());
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);

    drop(peer);

    assert!(close_thread.join().unwrap().is_ok());
    assert_eq!(client.state(), SessionState::Closed);
    assert!(client.wait_timeout(Duration::ZERO).unwrap());
}

#[test]
fn peer_truncated_frame_while_local_close_in_progress_fails_session() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(5),
        go_away_drain_interval: Duration::from_millis(100),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"hold-open").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(opened.stream_id, stream.stream_id());

    let closer = client.clone();
    let close_thread = thread::spawn(move || closer.close());
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);

    let mut raw = encode_varint(3).unwrap();
    raw.push(FrameType::Ping.as_u8());
    raw.extend_from_slice(&encode_varint(0).unwrap());
    peer.io.write_all(&raw).unwrap();
    drop(peer);

    let close_result = close_thread.join().unwrap();
    assert!(close_result.is_err());
    wait_for_state(&client, SessionState::Failed);
    let cause = client.close_error().unwrap();
    assert!(cause.is_error_code(ErrorCode::Protocol));
    assert_eq!(cause.source(), ErrorSource::Remote);
    assert_eq!(cause.direction(), ErrorDirection::Read);
}

/// Waits for the CLOSE the session sends after a fatal peer error and checks
/// that it carries `expected` and that the local cause agrees.
fn assert_peer_receives_fatal_close(
    client: &Conn,
    peer: &mut RawPeer,
    expected: ErrorCode,
    case: &str,
) -> String {
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, expected.as_u64(), "{case}: CLOSE reason {reason:?}");
    wait_for_state(client, SessionState::Failed);
    let cause = client.close_error().unwrap();
    assert!(cause.is_error_code(expected), "{case}: local cause {cause}");
    assert_eq!(cause.source(), ErrorSource::Remote, "{case}");
    reason
}

#[test]
fn frame_read_envelope_errors_emit_close_before_transport_shutdown() {
    let max_frame_payload = Settings::default().max_frame_payload;
    let max_control_payload = Settings::default().max_control_payload_bytes;
    let mut oversized_data = encode_varint(max_frame_payload + 3).unwrap();
    oversized_data.extend_from_slice(&[FrameType::Data.as_u8(), 0x04]);
    let mut oversized_ping = encode_varint(max_control_payload + 3).unwrap();
    oversized_ping.extend_from_slice(&[FrameType::Ping.as_u8(), 0x00]);
    let mut ping_with_fin = vec![0x0a, FrameType::Ping.as_u8() | FRAME_FLAG_FIN, 0x00];
    ping_with_fin.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut ping_on_stream = vec![0x0a, FrameType::Ping.as_u8(), 0x04];
    ping_on_stream.extend_from_slice(&[0; 8]);

    let cases: [(&str, Vec<u8>, ErrorCode); 8] = [
        ("oversized DATA", oversized_data, ErrorCode::FrameSize),
        ("oversized PING", oversized_ping, ErrorCode::FrameSize),
        ("frame_length=1", vec![0x01, 0x04], ErrorCode::FrameSize),
        (
            "unknown frame type",
            vec![0x02, 0x0c, 0x00],
            ErrorCode::Protocol,
        ),
        ("PING with FIN", ping_with_fin, ErrorCode::Protocol),
        ("PING on stream 4", ping_on_stream, ErrorCode::Protocol),
        (
            "non-canonical stream_id",
            vec![0x04, FrameType::Data.as_u8(), 0x40, 0x04, 0x68],
            ErrorCode::Protocol,
        ),
        (
            "non-canonical frame_length",
            vec![0x40, 0x02, FrameType::Data.as_u8(), 0x04],
            ErrorCode::Protocol,
        ),
    ];

    for (case, raw, expected) in cases {
        let (client, mut peer) = client_with_raw_peer(Config::default());
        peer.io.write_all(&raw).unwrap();
        peer.io.flush().unwrap();

        let _ = assert_peer_receives_fatal_close(&client, &mut peer, expected, case);
        let cause = client.close_error().unwrap();
        assert_eq!(cause.direction(), ErrorDirection::Read, "{case}");
    }
}

#[test]
fn malformed_mandatory_payload_fields_close_with_frame_size() {
    let truncated_diag = [ErrorCode::Cancelled.as_u64() as u8, DIAG_DEBUG_TEXT as u8];
    let overrunning_diag = [
        ErrorCode::Cancelled.as_u64() as u8,
        DIAG_DEBUG_TEXT as u8,
        0x05,
        0x41,
    ];
    let cases: [(&str, FrameType, u8, u64, &[u8]); 21] = [
        // WIRE_EXAMPLES §2.6: `02 03 04` is a repository-default FRAME_SIZE.
        ("empty STOP_SENDING", FrameType::StopSending, 0, 4, &[]),
        ("empty RESET", FrameType::Reset, 0, 4, &[]),
        ("truncated RESET code", FrameType::Reset, 0, 4, &[0x40]),
        ("empty ABORT", FrameType::Abort, 0, 4, &[]),
        (
            "truncated ABORT DIAG",
            FrameType::Abort,
            0,
            4,
            &truncated_diag,
        ),
        (
            "overrunning RESET DIAG",
            FrameType::Reset,
            0,
            4,
            &overrunning_diag,
        ),
        ("empty CLOSE", FrameType::Close, 0, 0, &[]),
        (
            "truncated CLOSE DIAG",
            FrameType::Close,
            0,
            0,
            &truncated_diag,
        ),
        ("empty MAX_DATA", FrameType::MaxData, 0, 0, &[]),
        ("truncated MAX_DATA", FrameType::MaxData, 0, 0, &[0x40]),
        (
            "non-canonical MAX_DATA",
            FrameType::MaxData,
            0,
            0,
            &[0x40, 0x01],
        ),
        ("empty BLOCKED", FrameType::Blocked, 0, 0, &[]),
        ("truncated BLOCKED", FrameType::Blocked, 0, 4, &[0x40]),
        ("GOAWAY missing fields", FrameType::GoAway, 0, 0, &[0x00]),
        (
            "non-canonical GOAWAY watermark",
            FrameType::GoAway,
            0,
            0,
            &[0x40, 0x04, 0x00, 0x00],
        ),
        (
            "GOAWAY truncated DIAG",
            FrameType::GoAway,
            0,
            0,
            &[0x00, 0x00, 0x00, DIAG_DEBUG_TEXT as u8],
        ),
        (
            "OPEN_METADATA missing metadata_len",
            FrameType::Data,
            FRAME_FLAG_OPEN_METADATA,
            1,
            &[],
        ),
        (
            "OPEN_METADATA truncated metadata_len",
            FrameType::Data,
            FRAME_FLAG_OPEN_METADATA,
            1,
            &[0x40],
        ),
        (
            "OPEN_METADATA non-canonical metadata_len",
            FrameType::Data,
            FRAME_FLAG_OPEN_METADATA,
            1,
            &[0x40, 0x00],
        ),
        (
            "OPEN_METADATA truncated TLV",
            FrameType::Data,
            FRAME_FLAG_OPEN_METADATA,
            1,
            &[0x01, METADATA_STREAM_PRIORITY as u8, b'h', b'i'],
        ),
        (
            "PRIORITY_UPDATE truncated TLV",
            FrameType::Ext,
            0,
            4,
            &[EXT_PRIORITY_UPDATE as u8, METADATA_STREAM_PRIORITY as u8],
        ),
    ];

    for (case, frame_type, flags, stream_id, payload) in cases {
        let (client, mut peer) = client_with_raw_peer(Config::default());
        peer.write_raw_frame_parts(frame_type, flags, stream_id, payload);

        let _ = assert_peer_receives_fatal_close(&client, &mut peer, ErrorCode::FrameSize, case);
        assert_eq!(
            client.stats().received_data_bytes,
            0,
            "{case}: malformed opener must not deliver application data"
        );
    }
}

#[test]
fn payload_rules_with_protocol_codes_still_close_with_protocol() {
    let cases: [(&str, FrameType, u64, &[u8]); 4] = [
        // SPEC §4.3: exactly one varint; trailing bytes are PROTOCOL.
        (
            "MAX_DATA trailing bytes",
            FrameType::MaxData,
            0,
            &[0x05, 0x00],
        ),
        (
            "BLOCKED trailing bytes",
            FrameType::Blocked,
            0,
            &[0x05, 0x00],
        ),
        // SPEC §6.11: EXT too short for its ext_type is PROTOCOL.
        ("empty EXT", FrameType::Ext, 4, &[]),
        ("truncated ext_type", FrameType::Ext, 4, &[0x40]),
    ];

    for (case, frame_type, stream_id, payload) in cases {
        let (client, mut peer) = client_with_raw_peer(Config::default());
        peer.write_raw_frame_parts(frame_type, 0, stream_id, payload);

        let _ = assert_peer_receives_fatal_close(&client, &mut peer, ErrorCode::Protocol, case);
    }
}

#[test]
fn abort_with_duplicate_then_truncated_diag_fails_session_with_frame_size() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"hi".to_vec(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&stream), b"hi");

    // CANCELLED, debug_text "a", duplicate debug_text "b", truncated TLV.
    peer.write_raw_frame_parts(
        FrameType::Abort,
        0,
        1,
        &[0x08, 0x01, 0x01, 0x61, 0x01, 0x01, 0x62, 0x40],
    );

    let reason =
        assert_peer_receives_fatal_close(&client, &mut peer, ErrorCode::FrameSize, "ABORT");
    assert!(reason.contains("truncated tlv"), "{reason}");
    let err = stream.read(&mut [0u8; 8]).unwrap_err();
    assert!(
        !err.is_application_code(ErrorCode::Cancelled.as_u64()),
        "{err}"
    );
}

#[test]
fn goaway_with_duplicate_then_overrunning_diag_fails_session_without_draining() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    // Duplicate retry_after_millis, then a debug_text overrunning the payload.
    peer.write_raw_frame_parts(
        FrameType::GoAway,
        0,
        0,
        &[
            0x00, 0x00, 0x00, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06, 0x01, 0x09, 0x78,
        ],
    );

    let reason =
        assert_peer_receives_fatal_close(&client, &mut peer, ErrorCode::FrameSize, "GOAWAY");
    assert!(reason.contains("tlv value overruns"), "{reason}");
    assert!(client.peer_go_away_error().is_none());
}

#[test]
fn peer_close_duplicate_standard_diag_drops_reason_but_keeps_primary_semantics() {
    assert_bad_peer_close_diag_drops_reason(error_payload_with_duplicate_standard_diag(
        ErrorCode::Protocol.as_u64(),
        "peer close",
    ));
}

#[test]
fn peer_close_invalid_utf8_diag_drops_reason_but_keeps_primary_semantics() {
    assert_bad_peer_close_diag_drops_reason(error_payload_with_invalid_utf8_diag(
        ErrorCode::Protocol.as_u64(),
    ));
}

#[test]
fn duplicate_malformed_close_after_peer_close_preserves_error_and_budgets() {
    let client_config = Config {
        inbound_mixed_frame_budget: Some(100),
        ignored_control_budget: 100,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::Protocol.as_u64(), "peer-close"),
    });
    wait_for_state(&client, SessionState::Failed);
    let first = client.peer_close_error().unwrap();
    assert_eq!(first.code, ErrorCode::Protocol.as_u64());
    assert_eq!(first.reason, "peer-close");
    let before = client.stats().abuse;

    let mut malformed_close = encode_varint(3).unwrap();
    malformed_close.push(FrameType::Close.as_u8());
    malformed_close.extend_from_slice(&encode_varint(0).unwrap());
    malformed_close.push(0xff);
    peer.io.write_all(&malformed_close).unwrap();
    peer.io.flush().unwrap();
    thread::sleep(Duration::from_millis(50));

    let after_close = client.peer_close_error().unwrap();
    assert_eq!(after_close.code, ErrorCode::Protocol.as_u64());
    assert_eq!(after_close.reason, "peer-close");
    let after = client.stats().abuse;
    assert_eq!(after.inbound_control_frames, before.inbound_control_frames);
    assert_eq!(after.inbound_control_bytes, before.inbound_control_bytes);
    assert_eq!(after.inbound_mixed_frames, before.inbound_mixed_frames);
    assert_eq!(after.inbound_mixed_bytes, before.inbound_mixed_bytes);
    assert_eq!(after.ignored_control, before.ignored_control);
}

#[test]
fn locally_closed_session_ignores_peer_frames_without_inbound_budget() {
    let client_config = Config {
        inbound_control_frame_budget: 1,
        inbound_mixed_frame_budget: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    client
        .close_with_error(ErrorCode::NoError.as_u64(), "")
        .unwrap();
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let before = client.stats().abuse;

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id: 0,
            payload: [0u8; 8].to_vec(),
        });
        peer.write_frame(Frame {
            frame_type: FrameType::Close,
            flags: 0,
            stream_id: 0,
            payload: error_payload(ErrorCode::NoError.as_u64(), ""),
        });
    }
    thread::sleep(Duration::from_millis(50));

    let after = client.stats().abuse;
    assert_eq!(after.inbound_control_frames, before.inbound_control_frames);
    assert_eq!(after.inbound_control_bytes, before.inbound_control_bytes);
    assert_eq!(after.inbound_mixed_frames, before.inbound_mixed_frames);
    assert_eq!(after.inbound_mixed_bytes, before.inbound_mixed_bytes);
    assert_eq!(after.ignored_control, before.ignored_control);
}

#[test]
fn close_frame_write_failure_tracks_close_flush_diagnostic() {
    let (client, _peer) = client_with_raw_peer_and_failing_writer_after_preface(
        Config::default(),
        "synthetic close flush failure",
    );

    client
        .close_with_error(ErrorCode::Internal.as_u64(), "close flush")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().diagnostics.close_frame_flush_errors == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }

    let stats = client.stats();
    assert_eq!(stats.diagnostics.close_frame_flush_errors, 1);
    assert_eq!(stats.diagnostics.skipped_close_on_dead_io, 0);
}

#[test]
fn writer_dead_io_without_close_tracks_skipped_close_diagnostic_and_transport_error() {
    let message = "synthetic data write failure";
    let (client, _peer) =
        client_with_raw_peer_and_failing_writer_after_preface(Config::default(), message);
    let stream = client.open_stream().unwrap();

    let write_err = stream.write(b"payload").unwrap_err();
    assert_eq!(write_err.code(), Some(ErrorCode::Internal));
    assert_eq!(write_err.scope(), ErrorScope::Stream);
    assert_eq!(write_err.operation(), ErrorOperation::Write);
    assert_eq!(write_err.source(), ErrorSource::Transport);
    assert_eq!(write_err.direction(), ErrorDirection::Write);
    assert!(write_err.to_string().contains(message));
    wait_for_state(&client, SessionState::Failed);
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().diagnostics.skipped_close_on_dead_io == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }

    let stats = client.stats();
    assert_eq!(stats.diagnostics.skipped_close_on_dead_io, 1);
    assert_eq!(stats.diagnostics.close_frame_flush_errors, 0);
    let err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded after writer failure"),
        Err(err) => err,
    };
    assert_eq!(err.code(), Some(ErrorCode::Internal));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Transport);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert_eq!(err.termination_kind(), TerminationKind::SessionTermination);
    assert!(err.to_string().contains(message));
}

#[test]
fn stream_application_errors_expose_code_and_reason() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 1,
        payload: error_payload(77, "gone"),
    });

    let mut buf = [0u8; 1];
    let err = stream
        .read_timeout(&mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(err.application_code(), Some(77));
    assert_eq!(err.reason(), Some("gone"));
    assert!(err.is_application_code(77));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Read);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(err.termination_kind(), TerminationKind::Reset);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn peer_reset_wakes_blocked_read_waiter_with_remote_reset_error() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    let reader = stream.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let _ = started_tx.send(());
        let mut buf = [0u8; 1];
        let _ = done_tx.send(reader.read(&mut buf));
    });

    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    thread::sleep(Duration::from_millis(20));
    assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());

    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "peer reset"),
    });

    let err = done_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::Cancelled));
    assert_eq!(err.reason(), Some("peer reset"));
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.operation(), ErrorOperation::Read);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(err.termination_kind(), TerminationKind::Reset);
    handle.join().unwrap();

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn local_send_reset_wins_over_peer_recv_reset_for_writes() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(11, "peer reset"),
    });
    stream.cancel_write(17).unwrap();

    let reset = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, 17);

    let err = stream.write(b"x").unwrap_err();
    assert_eq!(err.numeric_code(), Some(17));
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::Reset);

    client.close().ok();
}

#[test]
fn peer_reset_and_late_data_update_reason_and_diagnostics() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"abc".to_vec(),
    });
    let stream = client.accept_stream().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 1,
        payload: error_payload(7, ""),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while !client.stats().reasons.reset.contains_key(&7) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let mut buf = [0u8; 1];
    let err = stream
        .read_timeout(&mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(err.numeric_code(), Some(7));

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"later".to_vec(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().diagnostics.late_data_after_reset != 5 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }

    let stats = client.stats();
    assert_eq!(stats.reasons.reset.get(&7), Some(&1));
    assert_eq!(stats.diagnostics.late_data_after_reset, 5);
    client.close().ok();
}

#[test]
fn peer_abort_and_late_data_update_reason_and_diagnostics() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"abc".to_vec(),
    });
    let stream = client.accept_stream().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: error_payload(9, ""),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while !client.stats().reasons.abort.contains_key(&9) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let mut buf = [0u8; 1];
    let err = stream
        .read_timeout(&mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(err.numeric_code(), Some(9));
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Read);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(err.termination_kind(), TerminationKind::Abort);

    let write_err = stream.write(b"x").unwrap_err();
    assert_eq!(write_err.numeric_code(), Some(9));
    assert_eq!(write_err.source(), ErrorSource::Remote);
    assert_eq!(write_err.scope(), ErrorScope::Stream);
    assert_eq!(write_err.operation(), ErrorOperation::Write);
    assert_eq!(write_err.direction(), ErrorDirection::Write);
    assert_eq!(write_err.termination_kind(), TerminationKind::Abort);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"later".to_vec(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().diagnostics.late_data_after_abort != 5 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }

    let stats = client.stats();
    assert_eq!(stats.reasons.abort.get(&9), Some(&1));
    assert_eq!(stats.diagnostics.late_data_after_abort, 5);
    client.close().ok();
}

#[test]
fn repeated_peer_abort_keeps_first_terminal_reason() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });
    let _stream = client.accept_stream().unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: error_payload(9, "first"),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while !client.stats().reasons.abort.contains_key(&9) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ignored_before = client.stats().abuse.ignored_control;

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: error_payload(13, "second"),
    });
    thread::sleep(Duration::from_millis(50));

    let stats = client.stats();
    assert_eq!(stats.reasons.abort.get(&9), Some(&1));
    assert!(!stats.reasons.abort.contains_key(&13));
    assert_eq!(
        stats.abuse.ignored_control,
        ignored_before.saturating_add(1)
    );

    client.close().ok();
}

#[test]
fn peer_reset_bad_diag_drops_reason_but_keeps_reset_semantics() {
    for payload in [
        error_payload_with_duplicate_standard_diag(ErrorCode::Cancelled.as_u64(), "peer reset"),
        error_payload_with_invalid_utf8_diag(ErrorCode::Cancelled.as_u64()),
    ] {
        let (client, mut peer) = client_with_raw_peer(Config::default());
        peer.write_frame(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 1,
            payload: b"abc".to_vec(),
        });
        let stream = client.accept_stream().unwrap();

        peer.write_frame(Frame {
            frame_type: FrameType::Reset,
            flags: 0,
            stream_id: 1,
            payload,
        });
        let code = ErrorCode::Cancelled.as_u64();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !client.stats().reasons.reset.contains_key(&code) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }

        let mut buf = [0u8; 1];
        let err = stream
            .read_timeout(&mut buf, Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(err.numeric_code(), Some(code));
        assert_eq!(err.reason(), None);
        assert_eq!(client.stats().pressure.buffered_receive_bytes, 0);
        client.close().ok();
    }
}

#[test]
fn peer_abort_bad_diag_drops_reason_but_keeps_abort_semantics() {
    for payload in [
        error_payload_with_duplicate_standard_diag(ErrorCode::RefusedStream.as_u64(), "peer abort"),
        error_payload_with_invalid_utf8_diag(ErrorCode::RefusedStream.as_u64()),
    ] {
        let (client, mut peer) = client_with_raw_peer(Config::default());
        peer.write_frame(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 1,
            payload: b"abc".to_vec(),
        });
        let stream = client.accept_stream().unwrap();

        peer.write_frame(Frame {
            frame_type: FrameType::Abort,
            flags: 0,
            stream_id: 1,
            payload,
        });
        let code = ErrorCode::RefusedStream.as_u64();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !client.stats().reasons.abort.contains_key(&code) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }

        let mut buf = [0u8; 1];
        let err = stream
            .read_timeout(&mut buf, Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(err.numeric_code(), Some(code));
        assert_eq!(err.reason(), None);
        assert_eq!(client.stats().pressure.buffered_receive_bytes, 0);
        client.close().ok();
    }
}

#[test]
fn structured_errors_mark_session_open_failures() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(0, 0, ErrorCode::RefusedStream.as_u64(), "drain").unwrap(),
    });
    wait_for_state(&client, SessionState::Draining);

    let err = match client.open_uni_stream() {
        Ok(_) => panic!("open_uni_stream unexpectedly succeeded past GOAWAY"),
        Err(err) => err,
    };
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert!(err.is_error_code(ErrorCode::RefusedStream));
    assert_eq!(err.numeric_code(), Some(ErrorCode::RefusedStream.as_u64()));

    client.close().ok();
}

#[test]
fn peer_go_away_error_preserves_latest_payload_without_closing() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(0, 0, ErrorCode::Protocol.as_u64(), "maintenance").unwrap(),
    });
    wait_for_state(&client, SessionState::Draining);
    let first = client.peer_go_away_error().unwrap();
    assert_eq!(first.code, ErrorCode::Protocol.as_u64());
    assert_eq!(first.reason, "maintenance");
    assert!(!client.is_closed());

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(0, 0, ErrorCode::FrameSize.as_u64(), "closing soon")
            .unwrap(),
    });
    thread::sleep(Duration::from_millis(20));
    let second = client.peer_go_away_error().unwrap();
    assert_eq!(second.code, ErrorCode::FrameSize.as_u64());
    assert_eq!(second.reason, "closing soon");
    assert!(!client.is_closed());
}

#[test]
fn peer_goaway_bad_diag_drops_reason_but_keeps_watermarks() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let mut duplicate_diag = encode_varint(0).unwrap();
    duplicate_diag.extend_from_slice(&encode_varint(0).unwrap());
    duplicate_diag.extend_from_slice(&encode_varint(ErrorCode::Protocol.as_u64()).unwrap());
    append_tlv(
        &mut duplicate_diag,
        DIAG_RETRY_AFTER_MILLIS,
        &encode_varint(1).unwrap(),
    )
    .unwrap();
    append_tlv(
        &mut duplicate_diag,
        DIAG_RETRY_AFTER_MILLIS,
        &encode_varint(2).unwrap(),
    )
    .unwrap();
    append_tlv(&mut duplicate_diag, DIAG_DEBUG_TEXT, b"maintenance").unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: duplicate_diag,
    });
    wait_for_state(&client, SessionState::Draining);

    let first = client.peer_go_away_error().unwrap();
    assert_eq!(first.code, ErrorCode::Protocol.as_u64());
    assert_eq!(first.reason, "");

    let (client, mut peer) = client_with_raw_peer(Config::default());
    let mut invalid_utf8 = encode_varint(0).unwrap();
    invalid_utf8.extend_from_slice(&encode_varint(0).unwrap());
    invalid_utf8.extend_from_slice(&encode_varint(ErrorCode::Internal.as_u64()).unwrap());
    append_tlv(&mut invalid_utf8, DIAG_DEBUG_TEXT, &[0xe2, 0x82]).unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: invalid_utf8,
    });
    wait_for_state(&client, SessionState::Draining);

    let second = client.peer_go_away_error().unwrap();
    assert_eq!(second.code, ErrorCode::Internal.as_u64());
    assert_eq!(second.reason, "");
    assert_eq!(client.state(), SessionState::Draining);

    client.close().ok();
}

#[test]
fn peer_goaway_reason_uses_retained_reason_budget() {
    let client_config = Config {
        retained_peer_reason_bytes_budget: Some(2),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(0, 0, ErrorCode::NoError.as_u64(), "first").unwrap(),
    });
    wait_for_state(&client, SessionState::Draining);

    let first = client.peer_go_away_error().unwrap();
    assert_eq!(first.code, ErrorCode::NoError.as_u64());
    assert_eq!(first.reason, "fi");
    assert_eq!(client.stats().retention.retained_peer_reason_bytes, 2);
    assert_eq!(
        client.stats().retention.retained_peer_reason_bytes_budget,
        2
    );

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(0, 0, ErrorCode::NoError.as_u64(), "xy").unwrap(),
    });
    thread::sleep(Duration::from_millis(20));

    let second = client.peer_go_away_error().unwrap();
    assert_eq!(second.code, ErrorCode::NoError.as_u64());
    assert_eq!(second.reason, "xy");
    assert_eq!(client.stats().retention.retained_peer_reason_bytes, 2);
    assert!(!client.is_closed());
}

#[test]
fn local_goaway_validates_watermark_direction_and_creator() {
    let (client, _server) = connected_pair(Config::default(), Config::default());

    let err = client.go_away(4, 0).unwrap_err();
    assert!(err.to_string().contains("not creatable"));

    let err = client.go_away(0, 1).unwrap_err();
    assert!(err.to_string().contains("wrong direction"));

    client.close().unwrap();
}

#[test]
fn invalid_local_goaway_code_does_not_commit_or_queue() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let err = client
        .go_away_with_error(0, 0, MAX_VARINT62 + 1, "invalid")
        .unwrap_err();

    assert!(err.to_string().contains("varint62 value out of range"));
    assert_eq!(client.state(), SessionState::Ready);
    let frames = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::GoAway));

    client.close().ok();
}

#[test]
fn invalid_local_close_code_does_not_commit_or_queue() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let err = client
        .close_with_error(MAX_VARINT62 + 1, "invalid")
        .unwrap_err();

    assert!(err.to_string().contains("varint62 value out of range"));
    assert_eq!(client.state(), SessionState::Ready);
    let frames = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client
        .close_with_error(ErrorCode::NoError.as_u64(), "")
        .unwrap();
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, _) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::NoError.as_u64());
}

#[test]
fn local_goaway_reason_is_capped_to_peer_control_payload_limit() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    client
        .go_away_with_error(0, 0, ErrorCode::Protocol.as_u64(), &"x".repeat(10_000))
        .unwrap();

    let goaway = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    assert!(
        usize_to_u64(goaway.payload.len())
            <= client.peer_preface().settings.max_control_payload_bytes
    );
    let parsed = parse_go_away_payload(&goaway.payload).unwrap();
    assert_eq!(parsed.code, ErrorCode::Protocol.as_u64());
    assert!(!parsed.reason.is_empty());
    assert!(parsed.reason.len() < 10_000);
}

#[test]
fn session_close_reason_is_capped_to_peer_control_payload_limit() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let reason = "x".repeat(5_000);

    client
        .close_with_error(ErrorCode::Internal.as_u64(), &reason)
        .unwrap();

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    assert!(
        usize_to_u64(close.payload.len())
            <= client.peer_preface().settings.max_control_payload_bytes
    );
    let (code, parsed_reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Internal.as_u64());
    assert_eq!(parsed_reason, reason[..4092]);
}

#[test]
fn stream_close_with_error_reason_is_capped_to_peer_control_payload_limit() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    let reason = "x".repeat(5_000);
    stream
        .close_with_error(ErrorCode::RefusedStream.as_u64(), &reason)
        .unwrap();
    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == opened.stream_id
    });
    assert!(
        usize_to_u64(abort.payload.len())
            <= client.peer_preface().settings.max_control_payload_bytes
    );
    let (code, parsed_reason) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());
    assert!(parsed_reason.len() < reason.len());
    assert!(reason.starts_with(&parsed_reason));

    client.close().ok();
}

#[test]
fn repeated_session_close_with_error_does_not_queue_duplicate_close_frames() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    client
        .close_with_error(ErrorCode::Internal.as_u64(), "fatal")
        .unwrap();
    client
        .close_with_error(ErrorCode::Protocol.as_u64(), "duplicate")
        .unwrap();

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Internal.as_u64());
    assert_eq!(reason, "fatal");
    let frames = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));
}

#[test]
fn outbound_control_reasons_may_exceed_local_default_when_peer_limit_allows() {
    let mut peer_config = Config::responder();
    peer_config.settings.max_control_payload_bytes = 8192;
    let (client, mut peer) =
        client_with_raw_peer_configs(Config::default().disable_capabilities(), peer_config);
    let reason = "x".repeat(9_000);
    let limits = Limits {
        max_control_payload_bytes: 8192,
        ..Limits::default()
    };

    client
        .go_away_with_error(0, 0, ErrorCode::Internal.as_u64(), &reason)
        .unwrap();
    let goaway =
        peer.wait_for_frame_with_limits(limits, |frame| frame.frame_type == FrameType::GoAway);
    assert!(goaway.payload.len() > u64_to_usize(Settings::default().max_control_payload_bytes));
    assert!(goaway.payload.len() <= 8192);
    let parsed_goaway = parse_go_away_payload(&goaway.payload).unwrap();
    assert_eq!(parsed_goaway.code, ErrorCode::Internal.as_u64());
    assert!(parsed_goaway.reason.len() > 4090);

    client
        .close_with_error(ErrorCode::Internal.as_u64(), &reason)
        .unwrap();
    let close =
        peer.wait_for_frame_with_limits(limits, |frame| frame.frame_type == FrameType::Close);
    assert!(close.payload.len() > u64_to_usize(Settings::default().max_control_payload_bytes));
    assert!(close.payload.len() <= 8192);
    let (code, parsed_reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Internal.as_u64());
    assert!(parsed_reason.len() > 4092);
}

#[test]
fn duplicate_local_goaway_is_not_resent_after_first_frame() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    client.go_away(0, 0).unwrap();
    let first = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    let parsed = parse_go_away_payload(&first.payload).unwrap();
    assert_eq!(parsed.last_accepted_bidi, 0);
    assert_eq!(parsed.last_accepted_uni, 0);

    client.go_away(0, 0).unwrap();
    let frames = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::GoAway));

    client.close().unwrap();
}

#[test]
fn weaker_local_goaway_covered_by_existing_strict_watermark_is_not_sent() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    client.go_away(0, 0).unwrap();
    let first = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    let parsed = parse_go_away_payload(&first.payload).unwrap();
    assert_eq!(parsed.last_accepted_bidi, 0);
    assert_eq!(parsed.last_accepted_uni, 0);

    client.go_away(1, 3).unwrap();
    let frames = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::GoAway));

    client.close().ok();
}

#[test]
fn peer_goaway_wrong_direction_fails_session() {
    let (_client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(0, 1, ErrorCode::Protocol.as_u64(), "bad").unwrap(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (_, reason) = parse_error_payload(&close.payload).unwrap();
    assert!(reason.contains("wrong direction"));
}

#[test]
fn peer_goaway_wrong_creator_fails_session() {
    let (_client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(1, 0, ErrorCode::Protocol.as_u64(), "bad").unwrap(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (_, reason) = parse_error_payload(&close.payload).unwrap();
    assert!(reason.contains("not creatable") || reason.contains("stream 1"));
}

#[test]
fn stream_closed_state_matches_native_api_surface() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let stream = client.open_stream().unwrap();
    assert!(!stream.is_read_closed());
    assert!(!stream.is_write_closed());

    stream.write_final(b"ping").unwrap();
    assert!(stream.is_write_closed());
    assert!(!stream.is_read_closed());

    let accepted = server.accept_stream().unwrap();
    assert_eq!(read_all_stream(&accepted), b"ping");
    assert!(accepted.is_read_closed());
    assert!(!accepted.is_write_closed());

    stream.close_read().unwrap();
    assert!(stream.is_read_closed());
}

#[test]
fn native_stream_direction_queries_match_public_surface() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let bidi = client.open_stream().unwrap();
    assert!(bidi.is_opened_locally());
    assert!(bidi.is_bidirectional());
    assert!(!bidi.is_read_closed());
    assert!(!bidi.is_write_closed());
    bidi.write(b"x").unwrap();

    let accepted_bidi = server.accept_stream().unwrap();
    assert!(!accepted_bidi.is_opened_locally());
    assert!(accepted_bidi.is_bidirectional());
    assert!(!accepted_bidi.is_read_closed());
    assert!(!accepted_bidi.is_write_closed());

    let send = client.open_uni_stream().unwrap();
    assert!(send.is_opened_locally());
    assert!(!send.is_bidirectional());
    assert!(!send.is_write_closed());
    send.write(b"y").unwrap();

    let recv = server.accept_uni_stream().unwrap();
    assert!(!recv.is_opened_locally());
    assert!(!recv.is_bidirectional());
    assert!(!recv.is_read_closed());

    bidi.close_read().unwrap();
    assert!(bidi.is_read_closed());

    send.cancel_write(ErrorCode::Cancelled.as_u64()).unwrap();
    assert!(send.is_write_closed());
}

#[test]
fn uni_stream_close_helpers_ignore_absent_directions() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let send = client.open_uni_stream().unwrap();
    send.write(b"payload").unwrap();
    send.close().unwrap();
    assert!(send.is_write_closed());

    let recv = server.accept_uni_stream().unwrap();
    recv.close().unwrap();
    assert!(recv.is_read_closed());
}

#[test]
fn write_vectored_sends_all_parts_without_closing_write_side() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_uni_stream().unwrap();
    let parts = [IoSlice::new(b"he"), IoSlice::new(b"ll"), IoSlice::new(b"o")];

    assert_eq!(stream.write_vectored(&parts).unwrap(), 5);
    assert!(!stream.is_write_closed());

    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(frame.flags & FRAME_FLAG_FIN, 0);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, b"hello");

    stream.close_write().unwrap();
    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(frame.flags & FRAME_FLAG_FIN, FRAME_FLAG_FIN);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert!(data.app_data.is_empty());

    let mut stream = client.open_uni_stream().unwrap();
    let parts = [IoSlice::new(b"io-"), IoSlice::new(b"trait")];
    assert_eq!(
        std::io::Write::write_vectored(&mut stream, &parts).unwrap(),
        8
    );
    stream.close_write().unwrap();

    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(frame.flags & FRAME_FLAG_FIN, 0);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, b"io-trait");
}

#[test]
fn write_vectored_final_sends_all_parts_and_closes_write_side() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    let stream = client.open_uni_stream().unwrap();
    let parts = [IoSlice::new(b"he"), IoSlice::new(b"ll"), IoSlice::new(b"o")];

    assert_eq!(stream.write_vectored_final(&parts).unwrap(), 5);
    assert!(stream.is_write_closed());

    let accepted = server.accept_uni_stream().unwrap();
    assert_eq!(read_all_recv_stream(&accepted), b"hello");

    let timed = client.open_uni_stream().unwrap();
    let parts = [IoSlice::new(b"ti"), IoSlice::new(b"med")];
    assert_eq!(
        timed
            .write_vectored_final_timeout(&parts, Duration::from_secs(1))
            .unwrap(),
        5
    );
    let accepted = server.accept_uni_stream().unwrap();
    assert_eq!(read_all_recv_stream(&accepted), b"timed");
}

#[test]
fn write_vectored_final_packs_small_parts_into_single_fin_frame() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    let parts = [
        IoSlice::new(b"hello"),
        IoSlice::new(b""),
        IoSlice::new(b"world"),
    ];

    assert_eq!(stream.write_vectored_final(&parts).unwrap(), 10);
    assert!(stream.is_write_closed());

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let data_frames = frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::Data)
        .collect::<Vec<_>>();
    assert_eq!(data_frames.len(), 1, "frames: {frames:?}");
    let frame = data_frames[0];
    assert_eq!(frame.stream_id, stream.stream_id());
    assert_eq!(frame.flags & FRAME_FLAG_FIN, FRAME_FLAG_FIN);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, b"helloworld");
    assert!(data.metadata.open_info.is_empty());

    client.close().ok();
}

#[test]
fn write_final_empty_opens_and_finishes_stream() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();

    assert_eq!(stream.write_final([]).unwrap(), 0);
    assert!(stream.is_write_closed());

    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(frame.stream_id, stream.stream_id());
    assert_eq!(frame.flags & FRAME_FLAG_FIN, FRAME_FLAG_FIN);
    assert!(frame.payload.is_empty());

    client.close().ok();
}

#[test]
fn zero_length_write_does_not_emit_open_metadata_opener() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().open_info(b"meta"))
        .unwrap();

    assert_eq!(stream.write(&[]).unwrap(), 0);
    assert!(peer
        .collect_frames_for(Duration::from_millis(150))
        .is_empty());

    client.close().ok();
}

#[test]
fn open_and_send_empty_does_not_emit_open_metadata_opener() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client
        .open_and_send(zmux::OpenSend::new([]).options(OpenOptions::new().open_info(b"meta")))
        .unwrap();

    assert!(peer
        .collect_frames_for(Duration::from_millis(150))
        .is_empty());

    assert_eq!(stream.write_final(b"x").unwrap(), 1);
    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(frame.stream_id, stream.stream_id());
    assert_eq!(
        frame.flags & FRAME_FLAG_OPEN_METADATA,
        FRAME_FLAG_OPEN_METADATA
    );
    assert_eq!(frame.flags & FRAME_FLAG_FIN, FRAME_FLAG_FIN);
    let payload = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(payload.metadata.open_info, b"meta");
    assert_eq!(payload.app_data, b"x");

    client.close().ok();
}

#[test]
fn write_vectored_final_splits_when_open_metadata_consumes_whole_first_frame() {
    let caps = CAPABILITY_OPEN_METADATA;
    let settings = Settings::default();
    let max_frame_payload = settings.max_frame_payload;
    let open_info = vec![b'm'; open_info_len_for_prefix_size(caps, max_frame_payload)];
    let client_config = Config {
        capabilities: caps,
        settings,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        settings,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().open_info(&open_info))
        .unwrap();
    let parts = [IoSlice::new(b"x")];

    assert_eq!(stream.write_vectored_final(&parts).unwrap(), 1);
    assert!(stream.is_write_closed());

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let data_frames = frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::Data)
        .collect::<Vec<_>>();
    assert_eq!(data_frames.len(), 2, "frames: {frames:?}");
    let opener = data_frames[0];
    assert_eq!(opener.stream_id, stream.stream_id());
    assert_eq!(
        opener.flags & FRAME_FLAG_OPEN_METADATA,
        FRAME_FLAG_OPEN_METADATA
    );
    assert_eq!(opener.flags & FRAME_FLAG_FIN, 0);
    assert_eq!(opener.payload.len(), u64_to_usize(max_frame_payload));
    let parsed_opener = parse_data_payload(&opener.payload, opener.flags).unwrap();
    assert_eq!(parsed_opener.metadata.open_info, open_info);
    assert!(parsed_opener.app_data.is_empty());

    let fin = data_frames[1];
    assert_eq!(fin.stream_id, stream.stream_id());
    assert_eq!(fin.flags & FRAME_FLAG_OPEN_METADATA, 0);
    assert_eq!(fin.flags & FRAME_FLAG_FIN, FRAME_FLAG_FIN);
    assert_eq!(fin.payload, b"x");

    client.close().ok();
}

#[test]
fn writes_do_not_retain_caller_payload_buffers() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();

    let mut opening = b"hello".to_vec();
    assert_eq!(stream.write(&opening).unwrap(), opening.len());
    opening[0] = b'x';
    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, b"hello");

    let mut later = b"later".to_vec();
    assert_eq!(stream.write(&later).unwrap(), later.len());
    later[0] = b'x';
    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, b"later");
}

#[test]
fn vectored_final_write_does_not_retain_caller_payload_buffers() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_uni_stream().unwrap();
    let mut first = b"he".to_vec();
    let mut second = b"llo".to_vec();

    let parts = [IoSlice::new(&first), IoSlice::new(&second)];
    assert_eq!(stream.write_vectored_final(&parts).unwrap(), 5);
    first[0] = b'x';
    second[0] = b'y';

    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(frame.flags & FRAME_FLAG_FIN, FRAME_FLAG_FIN);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, b"hello");

    let stream = client.open_uni_stream().unwrap();
    let mut tiny_parts = (0..20)
        .map(|i| vec![b'a' + u8::try_from(i).unwrap()])
        .collect::<Vec<_>>();
    let expected = tiny_parts
        .iter()
        .flat_map(|part| part.iter().copied())
        .collect::<Vec<_>>();
    let slices = tiny_parts
        .iter()
        .map(|part| IoSlice::new(part))
        .collect::<Vec<_>>();
    assert_eq!(
        stream.write_vectored_final(&slices).unwrap(),
        expected.len()
    );
    tiny_parts[0][0] = b'x';

    let frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(frame.flags & FRAME_FLAG_FIN, FRAME_FLAG_FIN);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, expected);
}

#[test]
fn zero_length_write_after_close_write_does_not_enqueue_frames() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    stream.close_write().unwrap();
    let _ = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data && frame.flags & FRAME_FLAG_FIN != 0
    });

    assert_eq!(stream.write(&[]).unwrap(), 0);
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(frames.is_empty());

    let err = stream.write(b"x").unwrap_err();
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::Graceful);
}

#[test]
fn large_negotiated_data_frame_uses_peer_limit_on_writer_path() {
    let peer_limits = Limits {
        max_frame_payload: 32 * 1024,
        ..Limits::default()
    };
    let peer_config = Config {
        settings: Settings {
            max_frame_payload: peer_limits.max_frame_payload,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(Config::default(), peer_config);
    let payload = vec![b'l'; 24 * 1024];

    let stream = client.open_uni_stream().unwrap();
    assert_eq!(stream.write_final(&payload).unwrap(), payload.len());

    let frame =
        peer.wait_for_frame_with_limits(peer_limits, |frame| frame.frame_type == FrameType::Data);
    assert_eq!(frame.stream_id, 2);
    assert_eq!(frame.flags & FRAME_FLAG_FIN, FRAME_FLAG_FIN);
    let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
    assert_eq!(data.app_data, payload);
    assert!(data.metadata.open_info.is_empty());

    client.close().unwrap();
}

#[test]
fn latency_hint_shrinks_default_write_fragments() {
    let peer_config = Config {
        settings: Settings {
            max_frame_payload: 16_384,
            scheduler_hints: SchedulerHint::Latency,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(Config::default(), peer_config);
    let stream = client.open_stream().unwrap();
    let payload = vec![b'l'; 9_000];

    assert_eq!(stream.write(&payload).unwrap(), payload.len());

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let data_frames = frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::Data)
        .collect::<Vec<_>>();
    assert_eq!(data_frames.len(), 2, "frames: {frames:?}");
    let first = data_frames[0];
    let second = data_frames[1];
    assert_eq!(first.stream_id, stream.stream_id());
    assert_eq!(second.stream_id, stream.stream_id());
    assert_eq!(
        parse_data_payload(&first.payload, first.flags)
            .unwrap()
            .app_data
            .len(),
        8_192
    );
    assert_eq!(
        parse_data_payload(&second.payload, second.flags)
            .unwrap()
            .app_data
            .len(),
        808
    );

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn saturated_priority_chunks_after_open_metadata_prefix() {
    let caps = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS;
    let peer_max_frame_payload = 16_384;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        settings: Settings {
            max_frame_payload: peer_max_frame_payload,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client
        .open_stream_with(OpenOptions::new().priority(20).open_info(b"ssh"))
        .unwrap();
    let payload = vec![b's'; 5_000];

    assert_eq!(stream.write(&payload).unwrap(), payload.len());

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let data_frames = frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::Data)
        .collect::<Vec<_>>();
    assert_eq!(data_frames.len(), 2, "frames: {frames:?}");
    let first = data_frames[0];
    let second = data_frames[1];
    let prefix =
        build_open_metadata_prefix(caps, Some(20), None, b"ssh", peer_max_frame_payload).unwrap();
    let expected_first_app_bytes =
        usize::try_from((peer_max_frame_payload - u64::try_from(prefix.len()).unwrap()) / 4)
            .unwrap();

    assert_eq!(first.stream_id, stream.stream_id());
    assert_eq!(second.stream_id, stream.stream_id());
    assert_ne!(first.flags & FRAME_FLAG_OPEN_METADATA, 0);
    assert!(first.payload.starts_with(&prefix));
    assert_eq!(first.payload.len(), prefix.len() + expected_first_app_bytes);
    assert_eq!(
        parse_data_payload(&first.payload, first.flags)
            .unwrap()
            .app_data
            .len(),
        expected_first_app_bytes
    );
    assert_eq!(
        parse_data_payload(&second.payload, second.flags)
            .unwrap()
            .app_data
            .len(),
        payload.len() - expected_first_app_bytes
    );

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn graceful_close_initial_goaway_allows_inflight_peer_open() {
    let client_config = Config {
        go_away_drain_interval: Duration::from_millis(100),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let _local_stream = client.open_stream().unwrap();

    let closer = client.clone();
    let close_thread = thread::spawn(move || closer.close().unwrap());
    let initial_goaway = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    let initial = parse_go_away_payload(&initial_goaway.payload).unwrap();
    assert!(initial.last_accepted_bidi > 0);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"inflight".to_vec(),
    });
    thread::sleep(Duration::from_millis(20));

    let accepted = client.accept_stream().unwrap();
    assert_eq!(read_all_stream(&accepted), b"inflight");
    close_thread.join().unwrap();
}

#[test]
fn peer_goaway_is_processed_during_graceful_close_drain() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(2),
        go_away_drain_interval: Duration::ZERO,
        ignored_control_budget: 0,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let local_stream = client.open_stream().unwrap();
    local_stream.write(b"hold-open").unwrap();
    let local_id = local_stream.stream_id();

    let closer = client.clone();
    let close_thread = thread::spawn(move || closer.close().unwrap());
    // The final GOAWAY (no peer stream accepted) starts the stream drain.
    let _ = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::GoAway
            && parse_go_away_payload(&frame.payload)
                .unwrap()
                .last_accepted_bidi
                == 0
    });
    assert_eq!(client.state(), SessionState::Draining);

    // A GOAWAY that still accepts the open local stream is ordinary drain
    // traffic: it is applied, not dropped and not charged as ignored control.
    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(local_id, 0, 0, "peer drain").unwrap(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.peer_go_away_error().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(client.peer_go_away_error().unwrap().reason, "peer drain");
    assert_eq!(client.state(), SessionState::Draining);
    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::NoError.as_u64(), ""),
    });

    close_thread.join().unwrap();
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    if let Some(close) = frames
        .iter()
        .rev()
        .find(|frame| frame.frame_type == FrameType::Close)
    {
        let (code, _) = parse_error_payload(&close.payload).unwrap();
        assert_eq!(code, ErrorCode::NoError.as_u64());
    }
    assert_ne!(client.state(), SessionState::Failed);
    drop(local_stream);
}

#[test]
fn concurrent_close_waits_for_existing_close() {
    let client_config = Config {
        go_away_drain_interval: Duration::from_millis(100),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let _local_stream = client.open_stream().unwrap();

    let closer = client.clone();
    let close_thread = thread::spawn(move || closer.close().unwrap());
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);

    client.close().unwrap();
    close_thread.join().unwrap();

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame.frame_type == FrameType::Close)
            .count(),
        1
    );
}

#[test]
fn graceful_close_drain_allows_existing_stream_to_finish() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(500),
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let stream = client.open_stream().unwrap();
    assert_eq!(stream.write(b"prefix").unwrap(), 6);
    let server_thread = thread::spawn(move || {
        let peer_stream = server.accept_stream().unwrap();
        assert_eq!(read_all_stream(&peer_stream), b"prefixsuffix");
        assert_eq!(peer_stream.write_final(b"ack").unwrap(), 3);
        server.close().ok();
    });

    let closer = client.clone();
    let close_thread = thread::spawn(move || closer.close().unwrap());
    wait_for_state(&client, SessionState::Draining);

    assert_eq!(stream.write_final(b"suffix").unwrap(), 6);
    close_thread.join().unwrap();
    server_thread.join().unwrap();
    assert_eq!(client.state(), SessionState::Closed);
}

#[test]
fn graceful_close_drain_timeout_returns_error_after_no_error_close() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(20),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"held").unwrap();

    let err = client.close().unwrap_err();
    assert!(err.to_string().contains("graceful close drain timed out"));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert_eq!(err.termination_kind(), TerminationKind::Timeout);
    assert_eq!(client.state(), SessionState::Closed);
    assert_eq!(client.stats().diagnostics.graceful_close_timeouts, 1);
    assert_eq!(client.stats().diagnostics.keepalive_timeouts, 0);

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::NoError.as_u64());
    assert_eq!(reason, "");
}

#[test]
fn graceful_close_reclaims_uncommitted_local_open_without_timeout() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(20),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let stream = client.open_stream().unwrap();
    assert_eq!(stream.stream_id(), 0);

    let started = Instant::now();
    client.close().unwrap();
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(client.state(), SessionState::Closed);
    assert!(stream.write(b"late").is_err());

    server.close().ok();
}

#[test]
fn graceful_close_drain_ignores_peer_stream_without_local_send_commit() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(20),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let peer_stream = server.open_stream().unwrap();
    assert_eq!(peer_stream.write(b"peer").unwrap(), 4);
    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(accepted.stream_id(), peer_stream.stream_id());

    let started = Instant::now();
    client.close().unwrap();
    assert!(started.elapsed() < Duration::from_millis(200));
    server.close().ok();
}

#[test]
fn bidirectional_stream_round_trip_over_memory_transport() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let client_stream = client.open_stream().unwrap();
    assert_eq!(client_stream.write_final(b"ping").unwrap(), 4);

    let server_stream = server.accept_stream().unwrap();
    assert_eq!(read_all_stream(&server_stream), b"ping");

    assert_eq!(server_stream.write_final(b"pong").unwrap(), 4);
    assert_eq!(read_all_stream(&client_stream), b"pong");
    assert_eq!(client.stats().active_streams.local_bidi, 0);
    assert_eq!(server.stats().active_streams.peer_bidi, 0);

    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn native_session_contract_bidi() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    assert!(!client.is_closed());
    assert!(!server.is_closed());

    let client_stream = client.open_stream().unwrap();
    assert_eq!(client_stream.write(b"adapter-contract-bidi").unwrap(), 21);
    client_stream.close_write().unwrap();

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_all_stream(&accepted), b"adapter-contract-bidi");
    accepted.close().unwrap();
    client_stream.close().unwrap();

    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn native_session_contract_uni() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    assert!(!client.is_closed());
    assert!(!server.is_closed());

    let send = client.open_uni_stream().unwrap();
    assert_eq!(send.write(b"adapter-contract-uni").unwrap(), 20);

    let accepted = server
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    send.close_write().unwrap();
    assert_eq!(read_all_recv_stream(&accepted), b"adapter-contract-uni");
    accepted.close().unwrap();
    send.close().unwrap();

    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn native_session_contract_stream_abortive_close() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let client_stream = client.open_stream().unwrap();
    assert_eq!(client_stream.write(b"x").unwrap(), 1);

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(accepted.read(&mut buf).unwrap(), 1);

    client_stream
        .close_with_error(55, "adapter-contract-abort")
        .unwrap();
    let read_err = client_stream.read(&mut buf).unwrap_err();
    assert_application_error(&read_err, 55, Some("adapter-contract-abort"));
    let write_err = client_stream.write(b"y").unwrap_err();
    assert_application_error(&write_err, 55, Some("adapter-contract-abort"));

    accepted
        .set_read_deadline(Some(Instant::now() + Duration::from_secs(1)))
        .unwrap();
    let peer_err = accepted.read(&mut buf).unwrap_err();
    assert_eq!(peer_err.numeric_code(), Some(55));

    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn native_session_contract_read_stop() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let client_stream = client.open_stream().unwrap();
    assert_eq!(client_stream.write(b"p").unwrap(), 1);

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(accepted.read(&mut buf).unwrap(), 1);

    accepted.cancel_read(77).unwrap();
    let read_err = accepted.read(&mut buf).unwrap_err();
    assert_local_read_stopped_error(&read_err);

    let deadline = Instant::now() + Duration::from_secs(1);
    client_stream.set_write_deadline(Some(deadline)).unwrap();
    loop {
        match client_stream.write(b"x") {
            Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(_) => panic!("write did not observe read stop before deadline"),
            Err(err) => {
                assert!(
                    err.numeric_code() == Some(77) || err.to_string().contains("write side closed"),
                    "unexpected write error after read stop: {err}"
                );
                break;
            }
        }
    }

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn native_session_contract_close() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    client.close().unwrap();
    assert!(wait_closed_for_contract(&client).is_none());
    assert!(wait_closed_for_contract(&server).is_none());

    let err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded after close"),
        Err(err) => err,
    };
    assert_session_closed_or_application_error(&err, ErrorCode::SessionClosing.as_u64());
}

#[test]
fn native_session_contract_abort() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    client
        .close_with_error(91, "adapter-contract-session-abort")
        .unwrap();

    let client_err = wait_closed_for_contract(&client);
    if let Some(err) = client_err.as_ref() {
        assert_session_closed_or_application_error(err, 91);
    }

    let server_err = wait_closed_for_contract(&server);
    if let Some(err) = server_err.as_ref() {
        assert_session_closed_or_application_error(err, 91);
    }

    let err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded after abort"),
        Err(err) => err,
    };
    assert_session_closed_or_application_error(&err, 91);
}

#[test]
fn provisional_local_cancel_does_not_consume_stream_id() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(2),
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());

    let cancelled = client.open_stream().unwrap();
    assert_eq!(cancelled.stream_id(), 0);
    cancelled.cancel_write(8).unwrap();

    let stream = client.open_stream().unwrap();
    assert_eq!(stream.stream_id(), 0);
    assert_eq!(stream.write_final(b"after-cancel").unwrap(), 12);
    assert_eq!(stream.stream_id(), 4);

    let accepted = server.accept_stream().unwrap();
    assert_eq!(accepted.stream_id(), 4);
    assert_eq!(read_all_stream(&accepted), b"after-cancel");

    stream.close_read().unwrap();
    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn abandoned_provisional_head_expiry_wakes_waiting_openers() {
    // An opened but never-written stream heads the provisional queue, so later
    // same-class streams wait for their opener turn (here without deadlines).
    // On an otherwise quiet session nothing else notifies them when that head
    // expires; they must still wake, reap it and open in order. They are opened
    // right after the head: the time they spend waiting behind it does not age
    // them, so they do not expire along with it.
    let (client, server) = connected_pair(Config::default(), Config::default());
    let abandoned = client.open_stream().unwrap();
    let writer = client.open_stream().unwrap();
    let reader = client.open_stream().unwrap();
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    {
        let tx = tx.clone();
        let writer = writer.clone();
        thread::spawn(move || {
            let _ = tx.send(("write", writer.write(b"w").map(|_| ())));
        });
    }
    {
        let reader = reader.clone();
        thread::spawn(move || {
            let _ = tx.send(("close_read", reader.close_read()));
        });
    }
    for _ in 0..2 {
        let (op, result) = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("opener waiter was not woken when the provisional head expired");
        result.unwrap_or_else(|err| panic!("{op} failed: {err:?}"));
    }
    assert!(started.elapsed() < Duration::from_secs(15));

    assert_eq!(abandoned.stream_id(), 0);
    assert_eq!(writer.stream_id(), 4);
    assert_eq!(reader.stream_id(), 8);
    let err = abandoned.write(b"late").unwrap_err();
    assert_eq!(err.numeric_code(), Some(ErrorCode::Cancelled.as_u64()));
    let accepted = server
        .accept_stream_timeout(Duration::from_secs(2))
        .unwrap();
    assert_eq!(accepted.stream_id(), 4);
    assert!(!client.is_closed());
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn invalid_fresh_provisional_abort_keeps_slot_for_valid_retry() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    assert_eq!(stream.stream_id(), 0);
    assert_eq!(client.stats().provisional.bidi, 1);

    let err = stream
        .close_with_error(MAX_VARINT62 + 1, "out of range")
        .unwrap_err();
    assert!(err.is_error_code(ErrorCode::Protocol));
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert_eq!(stream.stream_id(), 0);
    assert_eq!(client.stats().provisional.bidi, 1);
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort));

    stream.close_with_error(41, "").unwrap();
    assert_eq!(stream.stream_id(), 0);
    assert_eq!(client.stats().provisional.bidi, 0);
    let err = stream.write(b"late").unwrap_err();
    assert_eq!(err.numeric_code(), Some(41));
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| matches!(frame.frame_type, FrameType::Data | FrameType::Abort)));

    client.close().unwrap();
}

#[test]
fn invalid_fresh_provisional_cancel_write_keeps_slot_for_valid_retry() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    assert_eq!(stream.stream_id(), 0);
    assert_eq!(client.stats().provisional.bidi, 1);

    let err = stream.cancel_write(MAX_VARINT62 + 1).unwrap_err();
    assert!(err.is_error_code(ErrorCode::Protocol));
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(stream.stream_id(), 0);
    assert_eq!(client.stats().provisional.bidi, 1);
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| matches!(frame.frame_type, FrameType::Abort | FrameType::Reset)));

    stream.cancel_write(41).unwrap();
    assert_eq!(stream.stream_id(), 0);
    assert_eq!(client.stats().provisional.bidi, 0);
    let err = stream.write(b"late").unwrap_err();
    assert_eq!(err.numeric_code(), Some(41));
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| matches!(
            frame.frame_type,
            FrameType::Data | FrameType::Abort | FrameType::Reset
        )));

    client.close().unwrap();
}

#[test]
fn provisional_open_limit_is_enforced_without_consuming_id() {
    let client_config = Config {
        max_provisional_streams_bidi: 1,
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());

    let first = client.open_stream().unwrap();
    assert_eq!(first.stream_id(), 0);
    let err = client.open_stream().err().unwrap();
    assert!(err.to_string().contains("provisional open limit"));

    assert_eq!(first.write_final(b"first").unwrap(), 5);
    assert_eq!(first.stream_id(), 4);

    let accepted = server.accept_stream().unwrap();
    assert_eq!(accepted.stream_id(), 4);
    assert_eq!(read_all_stream(&accepted), b"first");
    accepted.close_write().unwrap();

    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn peer_incoming_stream_limit_counts_uncommitted_local_provisionals() {
    let server_config = Config {
        settings: Settings {
            max_incoming_streams_bidi: 1,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, server) = connected_pair(Config::default(), server_config);

    let first = client.open_stream().unwrap();
    assert_eq!(first.stream_id(), 0);
    let err = client.open_stream().err().unwrap();
    assert_eq!(err.numeric_code(), Some(ErrorCode::RefusedStream.as_u64()));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert_eq!(err.termination_kind(), TerminationKind::Unknown);

    first.cancel_write(ErrorCode::Cancelled.as_u64()).unwrap();
    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn peer_incoming_stream_limit_refuses_new_active_peer_stream() {
    let client_config = Config {
        settings: Settings {
            max_incoming_streams_bidi: 1,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"first".to_vec(),
    });
    let first = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(first.stream_id(), 1);
    assert_eq!(client.stats().active_streams.peer_bidi, 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 5,
        payload: b"second".to_vec(),
    });
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 5);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());

    let stats = client.stats();
    assert_eq!(stats.active_streams.peer_bidi, 1);
    assert_eq!(stats.accept_backlog.refused, 1);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn peer_goaway_rejects_new_local_streams() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    server.go_away(0, 0).unwrap();
    wait_for_state(&client, SessionState::Draining);

    let err = client.open_stream().err().unwrap();
    assert!(err.to_string().contains("GOAWAY"));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Remote);

    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn peer_go_away_reclaims_excess_provisional_streams() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let first = client.open_stream().unwrap();
    let second = client.open_stream().unwrap();
    assert_eq!(first.stream_id(), 0);
    assert_eq!(second.stream_id(), 0);

    server.go_away(4, MAX_VARINT62 - 1).unwrap();
    wait_for_state(&client, SessionState::Draining);

    let err = second.write_final(b"second").err().unwrap();
    assert!(err.to_string().contains("application error 4"));

    assert_eq!(first.write_final(b"first").unwrap(), 5);
    assert_eq!(first.stream_id(), 4);

    let accepted = server.accept_stream().unwrap();
    assert_eq!(accepted.stream_id(), 4);
    assert_eq!(read_all_stream(&accepted), b"first");
    accepted.close_write().unwrap();

    client.close().unwrap();
    server.close().unwrap();
}

#[test]
fn close_read_discards_late_data_without_stream_replenish() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();

    stream.close_read().unwrap();
    let stop = peer
        .wait_for_frame(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1);
    assert_eq!(stop.frame_type, FrameType::StopSending);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late".to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));

    assert!(frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 1));

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn receive_window_replenishes_after_application_read_not_arrival() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 4,
            initial_max_stream_data_bidi_peer_opened: 4,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"abcd".to_vec(),
    });
    let frames_before_read = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames_before_read
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData));

    let stream = client.accept_stream().unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(stream.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf, b"abcd");

    let frames_after_read = peer.collect_frames_for(Duration::from_millis(100));
    assert!(frames_after_read
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert!(frames_after_read
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 1));

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn small_read_waits_for_blocked_before_credit_flush() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"hello".to_vec(),
    });

    let stream = client.accept_stream().unwrap();
    let mut buf = [0u8; 5];
    assert_eq!(stream.read(&mut buf).unwrap(), 5);
    assert_eq!(&buf, b"hello");
    assert_eq!(client.stats().pressure.recv_session_pending_bytes, 5);

    let frames_before_blocked = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames_before_blocked
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData));

    peer.write_frame(Frame {
        frame_type: FrameType::Blocked,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(0).unwrap(),
    });

    let frames_after_blocked = peer.collect_frames_for(Duration::from_millis(500));
    assert!(
        frames_after_blocked
            .iter()
            .any(|frame| frame.frame_type == FrameType::MaxData),
        "no MAX_DATA after BLOCKED; stats={:?}, frames={:?}",
        client.stats(),
        frames_after_blocked
    );
    let first = frames_after_blocked
        .iter()
        .find(|frame| frame.frame_type == FrameType::MaxData)
        .unwrap();
    let second = frames_after_blocked
        .iter()
        .filter(|frame| frame.frame_type == FrameType::MaxData)
        .nth(1)
        .expect("second MAX_DATA after BLOCKED");
    let saw_session = first.stream_id == 0 || second.stream_id == 0;
    let saw_stream = first.stream_id == 1 || second.stream_id == 1;
    assert!(saw_session);
    assert!(saw_stream);

    client.close().unwrap();
}

#[test]
fn unread_receive_window_still_enforces_session_max_data() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 4,
            initial_max_stream_data_bidi_peer_opened: 8,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"abcd".to_vec(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"e".to_vec(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, _) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    assert_eq!(client.state(), SessionState::Failed);
}

#[test]
fn stream_flow_control_rejection_releases_session_credit() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 8,
            initial_max_stream_data_bidi_peer_opened: 1,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"ab".to_vec(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let abort = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1)
        .expect("stream ABORT");
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    // The sender counted the rejected bytes against the session window, so they
    // are counted and released here too (SPEC §8), without being buffered.
    let max_data = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0)
        .expect("session MAX_DATA");
    assert_eq!(parse_varint(&max_data.payload).unwrap().0, 10);

    let stats = client.stats();
    assert_eq!(stats.received_data_bytes, 2);
    assert_eq!(stats.pressure.recv_session_received_bytes, 2);
    assert_eq!(stats.pressure.recv_session_advertised_bytes, 10);
    assert_eq!(stats.pressure.buffered_receive_bytes, 0);
    assert_eq!(stats.pressure.aggregate_late_data_bytes, 0);
    assert_eq!(stats.accept_backlog.bidi, 0);
    assert!(client
        .accept_stream_timeout(Duration::from_millis(20))
        .is_err());

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn data_exceeding_session_and_stream_windows_prefers_session_flow_control() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 0,
            initial_max_stream_data_bidi_peer_opened: 0,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    assert!(reason.contains("session MAX_DATA"));
    let frames = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1));
    assert_eq!(client.state(), SessionState::Failed);
}

#[test]
fn rapid_stream_flow_control_aborts_trip_visible_terminal_churn_budget() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 2,
            initial_max_stream_data_bidi_peer_opened: 0,
            ..Settings::default()
        },
        visible_terminal_churn_budget: 1,
        accept_backlog_limit: Some(1024),
        accept_backlog_bytes_limit: Some(1 << 20),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"a".to_vec(),
    });
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);
    let (abort_code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(abort_code, ErrorCode::FlowControl.as_u64());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 5,
        payload: b"b".to_vec(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("open-then-reset/abort churn"));
    assert_eq!(client.stats().diagnostics.visible_terminal_churn_events, 2);
}

#[test]
fn close_read_late_data_within_stream_credit_ignores_small_per_stream_cap() {
    // The configured per-stream figure only bounds late data beyond the stream
    // credit that was outstanding when the read side stopped.
    let client_config = Config {
        late_data_per_stream_cap: Some(3),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    stream.close_read().unwrap();
    let _ = peer
        .wait_for_frame(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late".to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert!(
        !frames
            .iter()
            .any(|frame| matches!(frame.frame_type, FrameType::Close | FrameType::Abort)),
        "unexpected frames: {frames:?}"
    );
    assert_ne!(client.state(), SessionState::Failed);
    assert_eq!(client.stats().diagnostics.late_data_after_close_read, 4);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn local_abort_late_data_beyond_outstanding_credit_still_fails_session() {
    let client_config = Config {
        settings: Settings {
            initial_max_stream_data_bidi_peer_opened: 8,
            ..Settings::default()
        },
        late_data_per_stream_cap: Some(3),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"ab".to_vec(),
    });
    let stream = client.accept_stream().unwrap();
    stream
        .close_with_error(ErrorCode::Cancelled.as_u64(), "")
        .unwrap();
    let _ =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);

    // Six bytes of stream credit were outstanding when the ABORT committed: a
    // compliant peer's tail stays within them.
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"cdefgh".to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(
        !frames
            .iter()
            .any(|frame| frame.frame_type == FrameType::Close),
        "unexpected frames: {frames:?}"
    );
    assert_ne!(client.state(), SessionState::Failed);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"i".to_vec(),
    });
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("late-data cap"));
}

#[test]
fn local_goaway_refuses_too_new_peer_stream() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    client.go_away(1, 0).unwrap();
    let goaway = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    assert_eq!(goaway.stream_id, 0);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 5,
        payload: b"too-new".to_vec(),
    });
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 5);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, 4);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn goaway_refused_opening_data_does_not_parse_malformed_open_metadata() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    client.go_away(0, 0).unwrap();
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);

    // metadata_len = 2 covers a truncated TLV; only the length prefix is decoded
    // for a refused opener, so the TLV error is never seen.
    peer.write_raw_frame_parts(
        FrameType::Data,
        FRAME_FLAG_OPEN_METADATA,
        5,
        &[0x02, 0x40, 0xff, b'a', b'p', b'p'],
    );
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 5);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());
    assert_ne!(client.state(), SessionState::Failed);
    assert_eq!(client.stats().pressure.recv_session_received_bytes, 3);

    client.close().ok();
}

#[test]
fn unnegotiated_open_metadata_emits_fatal_close() {
    let caps = CAPABILITY_OPEN_METADATA;
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) =
        client_with_raw_peer_configs(Config::default().disable_capabilities(), peer_config);
    assert_eq!(client.negotiated().capabilities, 0);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"seed".to_vec(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&stream), b"seed");

    let mut payload = build_open_metadata_prefix(
        caps,
        None,
        None,
        b"meta",
        Settings::default().max_frame_payload,
    )
    .unwrap();
    payload.extend_from_slice(b"x");

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA,
        stream_id: 1,
        payload,
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("OPEN_METADATA"));
    wait_for_state(&client, SessionState::Failed);
    let err = client.wait_timeout(Duration::ZERO).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.source(), zmux::ErrorSource::Remote);
}

#[test]
fn open_metadata_on_existing_local_stream_fails_session() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let stream = client.open_stream().unwrap();
    stream.write_all(b"open").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    peer.write_raw_frame_parts(
        FrameType::Data,
        FRAME_FLAG_OPEN_METADATA,
        opened.stream_id,
        &[],
    );

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("OPEN_METADATA"));
    wait_for_state(&client, SessionState::Failed);

    client.close().ok();
}

#[test]
fn terminal_fin_stream_uses_tombstone_for_late_data() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);

    stream.close_write().unwrap();
    let fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == 1
            && frame.flags & FRAME_FLAG_FIN != 0
    });
    assert_eq!(fin.stream_id, 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late".to_vec(),
    });
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamClosed.as_u64());

    client.close().unwrap();
}

fn create_reaped_graceful_bidi_marker(client: &Conn, peer: &mut RawPeer) -> u64 {
    let marker_stream_id = 1;
    for stream_id in [marker_stream_id, 5] {
        peer.write_frame(Frame {
            frame_type: FrameType::Data,
            flags: FRAME_FLAG_FIN,
            stream_id,
            payload: Vec::new(),
        });
        let stream = client.accept_stream().unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
        stream.close_write().unwrap();
        let _ = peer.wait_for_frame(|frame| {
            frame.frame_type == FrameType::Data
                && frame.stream_id == stream_id
                && frame.flags & FRAME_FLAG_FIN != 0
        });
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let retention = client.stats().retention;
        if retention.tombstones == 1 && retention.marker_only_used_streams >= 1 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let retention = client.stats().retention;
    assert_eq!(retention.tombstones, 1);
    assert!(retention.marker_only_used_streams >= 1);
    let _ = peer.collect_frames_for(Duration::from_millis(50));
    marker_stream_id
}

#[test]
fn late_data_on_reaped_graceful_tombstone_aborts_stream_closed() {
    let client_config = Config {
        tombstone_limit: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let marker_stream_id = create_reaped_graceful_bidi_marker(&client, &mut peer);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: marker_stream_id,
        payload: vec![1],
    });

    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == marker_stream_id
    });
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamClosed.as_u64());
    assert_ne!(client.state(), SessionState::Failed);

    client.close().ok();
}

#[test]
fn late_data_on_reaped_graceful_tombstone_does_not_fail_on_aggregate_cap() {
    let client_config = Config {
        tombstone_limit: 1,
        late_data_aggregate_cap: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let marker_stream_id = create_reaped_graceful_bidi_marker(&client, &mut peer);

    for payload in [vec![1], vec![2]] {
        peer.write_frame(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: marker_stream_id,
            payload,
        });
        let abort = peer.wait_for_frame(|frame| {
            frame.frame_type == FrameType::Abort && frame.stream_id == marker_stream_id
        });
        let (code, _) = parse_error_payload(&abort.payload).unwrap();
        assert_eq!(code, ErrorCode::StreamClosed.as_u64());
    }
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));
    assert_ne!(client.state(), SessionState::Failed);
    let stats = client.stats();
    assert_eq!(stats.pressure.recv_session_received_bytes, 2);
    // Marker-only IDs retain no late-data accounting.
    assert_eq!(stats.pressure.aggregate_late_data_bytes, 0);

    client.close().ok();
}

#[test]
fn marker_only_terminal_controls_do_not_consume_noop_budgets() {
    let client_config = Config {
        tombstone_limit: 1,
        abuse_window: Duration::from_secs(3600),
        ignored_control_budget: 1,
        no_op_max_data_budget: 1,
        no_op_blocked_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let marker_stream_id = create_reaped_graceful_bidi_marker(&client, &mut peer);

    let control_error = error_payload(ErrorCode::Cancelled.as_u64(), "");
    let credit = encode_varint(32).unwrap();
    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::StopSending,
            flags: 0,
            stream_id: marker_stream_id,
            payload: control_error.clone(),
        });
        peer.write_frame(Frame {
            frame_type: FrameType::Reset,
            flags: 0,
            stream_id: marker_stream_id,
            payload: control_error.clone(),
        });
        peer.write_frame(Frame {
            frame_type: FrameType::Abort,
            flags: 0,
            stream_id: marker_stream_id,
            payload: control_error.clone(),
        });
        peer.write_frame(Frame {
            frame_type: FrameType::MaxData,
            flags: 0,
            stream_id: marker_stream_id,
            payload: credit.clone(),
        });
        peer.write_frame(Frame {
            frame_type: FrameType::Blocked,
            flags: 0,
            stream_id: marker_stream_id,
            payload: credit.clone(),
        });
    }

    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));
    assert_ne!(client.state(), SessionState::Failed);
    let abuse = client.stats().abuse;
    assert_eq!(abuse.ignored_control, 0);
    assert_eq!(abuse.no_op_max_data, 0);
    assert_eq!(abuse.no_op_blocked, 0);

    client.close().ok();
}

#[test]
fn marker_only_priority_update_does_not_consume_noop_budget() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        tombstone_limit: 1,
        abuse_window: Duration::from_secs(3600),
        ignored_control_budget: 1,
        no_op_priority_update_budget: 1,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let marker_stream_id = create_reaped_graceful_bidi_marker(&client, &mut peer);
    let priority_update = build_priority_update_payload(
        caps,
        MetadataUpdate {
            priority: Some(7),
            group: None,
        },
        Settings::default().max_extension_payload_bytes,
    )
    .unwrap();

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: marker_stream_id,
            payload: priority_update.clone(),
        });
    }

    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));
    assert_ne!(client.state(), SessionState::Failed);
    let abuse = client.stats().abuse;
    assert_eq!(abuse.ignored_control, 0);
    assert_eq!(abuse.no_op_priority_update, 0);

    client.close().ok();
}

#[test]
fn peer_stop_sending_gracefully_finishes_committed_local_stream() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(opened.stream_id, 4);
    assert_eq!(opened.payload, b"hello");

    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: 4,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "stop"),
    });

    let fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == 4
            && frame.flags & FRAME_FLAG_FIN != 0
    });
    assert!(fin.payload.is_empty());

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Reset && frame.stream_id == 4));

    let write_err = stream.write(b"tail").unwrap_err();
    assert_eq!(write_err.scope(), ErrorScope::Stream);
    assert_eq!(write_err.operation(), ErrorOperation::Write);
    assert_eq!(write_err.source(), ErrorSource::Local);
    assert_eq!(write_err.direction(), ErrorDirection::Write);
    assert_eq!(write_err.termination_kind(), TerminationKind::Graceful);

    client.close().ok();
}

#[test]
fn repeated_stop_sending_after_stop_seen_is_ignored() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "stop"),
    });
    let _fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    });
    let ignored_before = client.stats().abuse.ignored_control;

    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "duplicate"),
    });
    thread::sleep(Duration::from_millis(50));

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames.iter().any(|frame| {
        frame.stream_id == opened.stream_id
            && matches!(frame.frame_type, FrameType::Reset | FrameType::Abort)
    }));
    assert_eq!(
        client.stats().abuse.ignored_control,
        ignored_before.saturating_add(1)
    );

    client.close().ok();
}

#[test]
fn cancel_write_after_graceful_stop_sending_finish_stays_gracefully_closed() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "stop"),
    });

    let fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    });
    assert!(fin.payload.is_empty());

    let write_err = stream.write(b"x").unwrap_err();
    assert_eq!(write_err.source(), ErrorSource::Local);
    assert_eq!(write_err.termination_kind(), TerminationKind::Graceful);

    let cancel_err = stream
        .cancel_write(ErrorCode::Cancelled.as_u64())
        .unwrap_err();
    assert_eq!(cancel_err.source(), ErrorSource::Local);
    assert_eq!(cancel_err.termination_kind(), TerminationKind::Graceful);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames.iter().any(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    }));

    client.close().ok();
}

#[test]
fn update_metadata_after_close_write_fails_with_local_graceful_error() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    stream.close_write().unwrap();
    let _fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    });

    let err = stream
        .update_metadata(MetadataUpdate {
            priority: Some(7),
            group: None,
        })
        .unwrap_err();

    assert!(err.to_string().contains("write side closed"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::Graceful);
    assert_eq!(stream.metadata().priority, None);
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| frame.frame_type == FrameType::Ext));

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: opened.stream_id,
        payload: Vec::new(),
    });
    assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
    client.close().ok();
}

#[test]
fn update_metadata_after_peer_stop_sending_finish_uses_local_graceful_error() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });
    let _fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    });

    let err = stream
        .update_metadata(MetadataUpdate {
            priority: Some(9),
            group: None,
        })
        .unwrap_err();

    assert!(err.to_string().contains("write side closed"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::Graceful);
    assert_eq!(stream.metadata().priority, None);
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| {
            frame.frame_type == FrameType::Ext
                || (frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id)
        }));

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: opened.stream_id,
        payload: Vec::new(),
    });
    assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
    client.close().ok();
}

#[test]
fn peer_stop_sending_after_recv_reset_prefers_reset() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(opened.stream_id, 4);

    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 4,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "reset"),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: 4,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "stop"),
    });

    let reset =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Reset && frame.stream_id == 4);
    let (code, _) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());

    client.close().ok();
}

#[test]
fn write_after_stop_driven_reset_surfaces_peer_stop() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "reset"),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(77, "peer stop"),
    });

    let reset = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());

    let err = stream.write(b"x").unwrap_err();
    assert_eq!(err.numeric_code(), Some(77));
    assert_eq!(err.reason(), Some("peer stop"));
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.termination_kind(), TerminationKind::Stopped);

    client.close().ok();
}

#[test]
fn close_write_after_stop_sending_reset_is_noop() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "reset"),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "stop"),
    });

    let reset = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());

    stream.close_write().unwrap();
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames.iter().any(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    }));

    client.close().ok();
}

#[test]
fn repeated_close_write_returns_local_graceful_error_without_duplicate_fin() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    stream.close_write().unwrap();
    let _fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    });

    let err = stream.close_write().unwrap_err();
    assert!(err.to_string().contains("write side closed"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::Graceful);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames.iter().any(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    }));

    client.close().ok();
}

#[test]
fn cancel_write_after_close_write_returns_local_graceful_error_without_reset() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    stream.close_write().unwrap();
    let _fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    });

    let err = stream
        .cancel_write(ErrorCode::Cancelled.as_u64())
        .unwrap_err();
    assert!(err.to_string().contains("write side closed"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::Graceful);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames.iter().any(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    }));

    client.close().ok();
}

#[test]
fn close_write_after_local_cancel_write_returns_reset_error_without_fin() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    stream.cancel_write(77).unwrap();
    let reset = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, 77);

    let err = stream.close_write().unwrap_err();
    assert_eq!(err.numeric_code(), Some(77));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::Reset);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames.iter().any(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == opened.stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    }));

    client.close().ok();
}

#[test]
fn repeated_cancel_write_returns_local_reset_error_without_duplicate_reset() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    stream.cancel_write(77).unwrap();
    let _reset = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    });

    let err = stream.cancel_write(77).unwrap_err();
    assert_eq!(err.numeric_code(), Some(77));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert_eq!(err.termination_kind(), TerminationKind::Reset);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames.iter().any(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    }));

    client.close().ok();
}

#[test]
fn stream_close_commits_write_fin_and_read_stop() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.close().unwrap();

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let fin = frames
        .iter()
        .find(|frame| {
            frame.frame_type == FrameType::Data
                && frame.stream_id == 4
                && frame.flags & FRAME_FLAG_FIN != 0
        })
        .expect("missing DATA|FIN");
    assert_eq!(fin.payload.len(), 0);

    let stop = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 4)
        .expect("missing STOP_SENDING");
    let (code, _) = parse_error_payload(&stop.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());

    let mut buf = [0u8; 1];
    assert!(stream.read(&mut buf).is_err());
    assert!(stream.write(b"x").is_err());

    client.close().ok();
}

#[test]
fn stream_close_ignores_already_cancelled_write_side() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hello").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    stream.cancel_write(ErrorCode::Cancelled.as_u64()).unwrap();
    let reset = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Reset && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&reset.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());

    stream.close().unwrap();
    let stop = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::StopSending && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&stop.payload).unwrap();
    assert_eq!(code, ErrorCode::Cancelled.as_u64());

    client.close().ok();
}

#[test]
fn read_stop_does_not_complete_stream_until_peer_fin() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    stream.close().unwrap();

    assert_eq!(client.stats().active_streams.peer_bidi, 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: Vec::new(),
    });
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline && client.stats().active_streams.peer_bidi != 0 {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client.stats().active_streams.peer_bidi, 0);

    client.close().ok();
}

#[test]
fn close_read_after_peer_fin_does_not_send_stop_sending() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);

    let err = stream.close_read().unwrap_err();
    assert!(err.to_string().contains("read side closed"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(err.termination_kind(), TerminationKind::Graceful);
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1));

    client.close().ok();
}

#[test]
fn repeated_close_read_returns_local_stopped_error_without_duplicate_stop() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    stream.close_read().unwrap();
    let _ = peer
        .wait_for_frame(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1);

    let err = stream.close_read().unwrap_err();
    assert!(err.to_string().contains("read side closed"));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Close);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(err.termination_kind(), TerminationKind::Stopped);

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1));

    client.close().ok();
}

#[test]
fn close_read_stops_peer_writes_but_preserves_reverse_read() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let stream = client.open_stream().unwrap();
    stream.write(b"hi").unwrap();

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut buf = [0u8; 2];
    assert_eq!(accepted.read(&mut buf).unwrap(), 2);
    assert_eq!(&buf, b"hi");

    accepted.close_read().unwrap();
    accepted.write_final(b"ok").unwrap();

    let deadline = Instant::now() + Duration::from_secs(1);
    stream.set_write_deadline(Some(deadline)).unwrap();
    loop {
        match stream.write(b"x") {
            Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(_) => panic!("peer close_read was not observed before write deadline"),
            Err(err) => {
                assert_eq!(err.scope(), ErrorScope::Stream);
                assert_eq!(err.operation(), ErrorOperation::Write);
                assert_eq!(err.direction(), ErrorDirection::Write);
                assert!(matches!(
                    err.termination_kind(),
                    TerminationKind::Stopped | TerminationKind::Graceful
                ));
                break;
            }
        }
    }

    assert_eq!(read_all_stream(&stream), b"ok");
    client.close().ok();
    server.close().ok();
}

#[test]
fn local_close_read_after_consuming_buffered_data_returns_stopped_error() {
    let (client, server) = connected_pair(Config::default(), Config::default());

    let client_stream = client.open_stream().unwrap();
    client_stream.write(b"x").unwrap();

    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(accepted.read(&mut buf).unwrap(), 1);
    assert_eq!(buf, *b"x");

    accepted.close_read().unwrap();

    let err = accepted.read(&mut buf).unwrap_err();
    assert_local_read_stopped_error(&err);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
    let _ = server.wait_timeout(Duration::from_secs(1));
}

#[test]
fn read_after_close_read_and_peer_fin_remains_local_stopped() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();

    stream.close_read().unwrap();
    let _ = peer
        .wait_for_frame(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: Vec::new(),
    });
    thread::sleep(Duration::from_millis(50));

    let mut buf = [0u8; 1];
    let err = stream.read(&mut buf).unwrap_err();
    assert_local_read_stopped_error(&err);
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1));

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn read_after_close_read_and_peer_reset_remains_local_stopped() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();

    stream.close_read().unwrap();
    let _ = peer
        .wait_for_frame(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "peer reset"),
    });
    thread::sleep(Duration::from_millis(50));

    let mut buf = [0u8; 1];
    let err = stream.read(&mut buf).unwrap_err();
    assert_local_read_stopped_error(&err);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn read_after_close_read_and_local_abort_remains_local_stopped() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let stream = client.open_stream().unwrap();
    stream.close_read().unwrap();
    let _ = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::StopSending && frame.stream_id == stream.stream_id()
    });

    stream.close_with_error(99, "local abort").unwrap();
    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == stream.stream_id()
    });
    let (code, reason) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, 99);
    assert_eq!(reason, "local abort");

    let mut buf = [0u8; 1];
    let err = stream.read(&mut buf).unwrap_err();
    assert_local_read_stopped_error(&err);

    let write_err = stream.write(b"x").unwrap_err();
    assert_eq!(write_err.numeric_code(), Some(99));
}

#[test]
fn hidden_abort_tombstone_ignores_late_data() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late".to_vec(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1));
    let stats = client.stats();
    assert_eq!(
        stats.reasons.abort.get(&ErrorCode::Cancelled.as_u64()),
        Some(&1)
    );
    assert_eq!(stats.hidden.reaped, 1);
    assert_eq!(stats.hidden.retained, 1);
    assert_eq!(stats.hidden.unread_bytes_discarded, 4);
    assert_eq!(stats.diagnostics.late_data_after_abort, 4);

    client.close().unwrap();
}

#[test]
fn abort_first_hidden_stream_tracks_hidden_reap_stats() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().hidden.retained == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let stats = client.stats();
    assert_eq!(
        stats.reasons.abort.get(&ErrorCode::Cancelled.as_u64()),
        Some(&1)
    );
    assert_eq!(stats.hidden.reaped, 1);
    assert_eq!(stats.hidden.retained, 1);

    client.close().unwrap();
}

#[test]
fn first_abort_on_unopened_local_stream_fails_session() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 4,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("ABORT"));
    wait_for_state(&client, SessionState::Failed);
    let err = client.wait_timeout(Duration::ZERO).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.source(), zmux::ErrorSource::Remote);
}

#[test]
fn late_data_on_terminal_hidden_stream_still_obeys_session_flow_control() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 0,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    assert!(reason.contains("session MAX_DATA"));
    assert_eq!(client.stats().pressure.recv_session_received_bytes, 0);
}

#[test]
fn hidden_abort_after_local_goaway_gets_refused_abort() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    client.go_away(0, 0).unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });

    let refused =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);
    let (code, _) = parse_error_payload(&refused.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());
    let stats = client.stats();
    assert_eq!(stats.hidden.refused, 1);
    assert_eq!(stats.abuse.hidden_abort_churn, 0);
    assert_eq!(
        stats.reasons.abort.get(&ErrorCode::RefusedStream.as_u64()),
        Some(&1)
    );

    client.close().unwrap();
}

#[test]
fn hidden_abort_limit_reaps_to_marker_without_late_abort() {
    let client_config = Config {
        hidden_control_opened_limit: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 5,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late".to_vec(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1));

    client.close().unwrap();
}

#[test]
fn hidden_abort_under_memory_pressure_reaps_to_marker_and_ignores_late_data() {
    let client_config = Config {
        // Leave room for credit while still forcing hidden tombstone reaping.
        session_memory_cap: Some(80),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().retention.marker_only_used_streams == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let stats = client.stats();
    assert_ne!(client.state(), SessionState::Failed);
    assert_eq!(stats.hidden.retained, 0);
    assert!(stats.retention.marker_only_used_streams >= 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late".to_vec(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1));
    assert!(
        !frames
            .iter()
            .any(|frame| frame.frame_type == FrameType::Close),
        "unexpected frames: {frames:?}"
    );
    assert_ne!(client.state(), SessionState::Failed);

    client.close().unwrap();
}

#[test]
fn hidden_abort_tombstone_expires_to_marker_after_max_age() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().hidden.retained == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client.stats().hidden.retained, 1);

    thread::sleep(Duration::from_millis(1100));
    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: vec![0; 8],
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().hidden.retained != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client.stats().hidden.retained, 0);
    assert_eq!(client.stats().retention.marker_only_used_streams, 1);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late".to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1));

    client.close().unwrap();
}

#[test]
fn marker_only_used_streams_compact_to_range() {
    let client_config = Config {
        hidden_control_opened_limit: Some(1),
        marker_only_used_stream_limit: Some(4),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for i in 0..65u64 {
        peer.write_frame(Frame {
            frame_type: FrameType::Abort,
            flags: 0,
            stream_id: 1 + i * 4,
            payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
        });
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().retention.marker_only_used_stream_ranges == 0 && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    let stats = client.stats();
    assert_eq!(stats.hidden.retained, 1);
    assert_eq!(stats.retention.marker_only_used_stream_ranges, 1);
    assert!(stats.retention.marker_only_used_streams <= 4);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 5,
        payload: b"late".to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 5));

    client.close().unwrap();
}

#[test]
fn marker_only_used_stream_cap_coarsens_instead_of_failing_session() {
    let client_config = Config {
        tombstone_limit: 0,
        marker_only_used_stream_limit: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 3,
        payload: Vec::new(),
    });
    let uni = client.accept_uni_stream().unwrap();
    assert_eq!(uni.stream_id(), 3);
    drop(uni);
    for stream_id in [5, 9, 13] {
        peer.write_frame(Frame {
            frame_type: FrameType::Abort,
            flags: 0,
            stream_id,
            payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
        });
    }
    let stats = wait_for_stats(&client, |stats| {
        stats.reasons.abort.get(&ErrorCode::Cancelled.as_u64()) == Some(&4)
    });
    assert_eq!(
        stats.reasons.abort.get(&ErrorCode::Cancelled.as_u64()),
        Some(&4)
    );
    assert!(stats.retention.marker_only_used_streams <= 1);
    assert!(stats.retention.marker_only_used_stream_ranges <= 1);
    assert_eq!(stats.retention.marker_only_used_stream_limit, 1);

    // Coarsened IDs stay used: late DATA and control are ignored, not treated
    // as frames on unseen streams, and the session budget is still released.
    peer.write_frame(data_frame(5, 0, b"late".to_vec()));
    peer.write_frame(error_frame(
        FrameType::StopSending,
        9,
        ErrorCode::Cancelled.as_u64(),
    ));
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(frames
        .iter()
        .all(|frame| frame.frame_type != FrameType::Abort));
    assert!(frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert_eq!(client.state(), SessionState::Ready);

    client.close().ok();
}

#[test]
fn tombstone_late_data_over_aggregate_cap_is_discarded_without_failing_session() {
    let client_config = Config {
        late_data_aggregate_cap: Some(3),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late".to_vec(),
    });

    let max_data =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0);
    assert!(parse_varint(&max_data.payload).unwrap().0 >= 4);
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));
    assert_ne!(client.state(), SessionState::Failed);
    let stats = client.stats();
    assert_eq!(stats.pressure.aggregate_late_data_bytes, 4);
    assert!(stats.pressure.aggregate_late_data_at_cap);
    assert_eq!(stats.diagnostics.late_data_after_abort, 4);

    client.close().ok();
}

#[test]
fn repeated_ignored_terminal_reset_exhausts_control_budget() {
    let client_config = Config {
        ignored_control_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("ignored control budget"));

    client.close().ok();
}

#[test]
fn malformed_pong_before_close_start_fails_session() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_raw_frame_parts(FrameType::Pong, 0, 0, &[1]);

    wait_for_state(&client, SessionState::Failed);
    client.close().ok();
}

#[test]
fn ping_during_graceful_close_drain_is_answered() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(2),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"hold-open").unwrap();

    let close_client = client.clone();
    let closer = thread::spawn(move || close_client.close());
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    thread::sleep(Duration::from_millis(50));

    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: b"closing!".to_vec(),
    });
    // The drain is still waiting for the open stream: the session keeps
    // processing peer frames and answers before any CLOSE.
    let reply =
        peer.wait_for_frame(|frame| matches!(frame.frame_type, FrameType::Pong | FrameType::Close));
    assert_eq!(reply.frame_type, FrameType::Pong);
    assert!(reply.payload.starts_with(b"closing!"));
    assert_eq!(client.state(), SessionState::Draining);
    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::NoError.as_u64(), ""),
    });
    let _ = closer.join().unwrap();
    assert_ne!(client.state(), SessionState::Failed);
}

#[test]
fn malformed_pong_during_graceful_close_drain_fails_session() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(2),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"hold-open").unwrap();

    let close_client = client.clone();
    let closer = thread::spawn(move || close_client.close());
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    thread::sleep(Duration::from_millis(50));

    // CLOSE has not been sent yet, so the frame is processed like any other
    // frame of a draining session (STATE_MACHINE §10) and is fatal.
    peer.write_raw_frame_parts(FrameType::Pong, 0, 0, &[1]);
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, _) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FrameSize.as_u64());
    assert!(closer.join().unwrap().is_err());
    assert_eq!(client.state(), SessionState::Failed);
}

#[test]
fn unexpected_pong_exhausts_control_budget() {
    let client_config = Config {
        ignored_control_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Pong,
            flags: 0,
            stream_id: 0,
            payload: b"unexpected-pong".to_vec(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("ignored control budget"));

    client.close().ok();
}

#[test]
fn matching_pong_clears_control_budget() {
    let client_config = Config {
        ignored_control_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: b"unexpected-a".to_vec(),
    });

    let ping_client = client.clone();
    let ping_thread = thread::spawn(move || ping_client.ping(b"budget").unwrap());
    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });
    let _ = ping_thread.join().unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: b"unexpected-b".to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: b"unexpected-c".to_vec(),
    });
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("ignored control budget"));

    client.close().ok();
}

#[test]
fn effective_reset_clears_ignored_control_budget() {
    let client_config = Config {
        ignored_control_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: b"unexpected-a".to_vec(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 3,
        payload: b"x".to_vec(),
    });
    let recv = client.accept_uni_stream().unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(recv.read(&mut byte).unwrap(), 1);
    assert_eq!(&byte, b"x");
    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 3,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "reset"),
    });

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: b"unexpected-b".to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close().unwrap();
}

#[test]
fn ignored_reset_after_peer_fin_counts_control_budget() {
    let client_config = Config {
        ignored_control_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"x".to_vec(),
    });
    let stream = client.accept_stream().unwrap();
    assert_eq!(read_all_stream(&stream), b"x");

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Reset,
            flags: 0,
            stream_id: 1,
            payload: error_payload(ErrorCode::Cancelled.as_u64(), "reset"),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("ignored control budget"));

    client.close().ok();
}

#[test]
fn accepted_visible_abort_does_not_count_terminal_churn() {
    let client_config = Config {
        visible_terminal_churn_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for (stream_id, payload) in [(1, b"a".as_slice()), (5, b"b".as_slice())] {
        peer.write_frame(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id,
            payload: payload.to_vec(),
        });
        let stream = client.accept_stream().unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(stream.read(&mut byte).unwrap(), 1);
        assert_eq!(&byte, payload);
        peer.write_frame(Frame {
            frame_type: FrameType::Abort,
            flags: 0,
            stream_id,
            payload: error_payload(ErrorCode::Cancelled.as_u64(), "abort"),
        });
    }

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close().unwrap();
}

#[test]
fn unaccepted_visible_peer_abort_tracks_terminal_churn_diagnostic() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().accept_backlog.bidi == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: error_payload(13, ""),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().diagnostics.visible_terminal_churn_events == 0 && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }

    let stats = client.stats();
    assert_eq!(stats.diagnostics.visible_terminal_churn_events, 1);
    assert_eq!(stats.reasons.abort.get(&13), Some(&1));

    client.close().unwrap();
}

#[test]
fn inbound_ping_pong_over_urgent_cap_is_dropped_without_failing_session() {
    let client_config = Config {
        urgent_queue_max_bytes: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: b"drop-pong".to_vec(),
    });

    thread::sleep(Duration::from_millis(50));
    assert_eq!(client.state(), SessionState::Ready);
    let frames = peer.collect_frames_for(Duration::from_millis(80));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Pong));

    client.close().unwrap();
}

#[test]
fn ping_rejects_payload_over_default_control_limit_without_queueing() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let oversized = vec![0u8; u64_to_usize(Settings::default().max_control_payload_bytes - 7)];

    let err = client
        .ping_timeout(&oversized, Duration::from_millis(20))
        .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err
        .to_string()
        .contains("PING payload exceeds negotiated limit"));
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());
    client.close().unwrap();
}

#[test]
fn ping_timeout_bounds_urgent_queue_backpressure() {
    let client_config = Config {
        urgent_queue_max_bytes: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    let start = Instant::now();
    let err = client
        .ping_timeout(b"", Duration::from_millis(30))
        .unwrap_err();

    assert!(err.to_string().contains("ping timed out"));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(!client.stats().liveness.ping_outstanding);
    assert_eq!(client.stats().pressure.outstanding_ping_bytes, 0);
    assert!(peer
        .collect_frames_for(Duration::from_millis(80))
        .is_empty());
    assert_eq!(client.state(), SessionState::Ready);
    client.close().unwrap();
}

#[test]
fn ping_payload_limit_uses_min_local_control_limit() {
    let client_config = config_with_control_limit(Config::default(), 4096);
    let peer_config = config_with_control_limit(Config::responder(), 8192);
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let oversized = vec![0u8; 4089];

    let err = client
        .ping_timeout(&oversized, Duration::from_millis(20))
        .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());
    client.close().unwrap();
}

#[test]
fn ping_payload_limit_uses_min_peer_control_limit() {
    let client_config = config_with_control_limit(Config::default(), 8192);
    let peer_config = config_with_control_limit(Config::responder(), 4096);
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let oversized = vec![0u8; 4089];

    let err = client
        .ping_timeout(&oversized, Duration::from_millis(20))
        .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .is_empty());
    client.close().unwrap();
}

#[test]
fn ping_accepts_payload_at_negotiated_control_limit() {
    let client_config = config_with_control_limit(Config::default(), 8192);
    let peer_config = config_with_control_limit(Config::responder(), 4096);
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let echo = ping_echo_at_payload_limit(4096);

    let ping_client = client.clone();
    let ping_thread =
        thread::spawn(move || ping_client.ping_timeout(&echo, Duration::from_secs(1)));
    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(usize_to_u64(ping.payload.len()), 4096);

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });
    ping_thread.join().unwrap().unwrap();
    client.close().unwrap();
}

#[test]
fn ping_padding_accepts_padded_pong_suffix() {
    let client_config = Config {
        ping_padding: true,
        ping_padding_min_bytes: 16,
        ping_padding_max_bytes: 16,
        keepalive_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    assert_ne!(client.local_preface().settings.ping_padding_key, 0);

    let ping_client = client.clone();
    let ping_thread =
        thread::spawn(move || ping_client.ping_timeout(b"echo", Duration::from_secs(1)));
    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(ping.stream_id, 0);
    assert!(ping.payload.len() >= 8 + 16 + 4);
    let nonce = u64::from_be_bytes(ping.payload[..8].try_into().unwrap());
    let tag = u64::from_be_bytes(ping.payload[8..16].try_into().unwrap());
    assert_eq!(
        tag,
        ping_padding_tag(client.local_preface().settings.ping_padding_key, nonce)
    );
    assert_ne!(&ping.payload[8..12], b"echo");
    assert_eq!(&ping.payload[16..20], b"echo");

    let mut pong_payload = ping.payload.clone();
    pong_payload.extend_from_slice(b"suffix");
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: pong_payload,
    });

    ping_thread.join().unwrap().unwrap();
    client.close().unwrap();
}

#[test]
fn ping_padding_clamps_to_control_payload_limit() {
    let client_config = Config {
        ping_padding: true,
        ping_padding_min_bytes: 5000,
        ping_padding_max_bytes: 5000,
        keepalive_interval: Duration::ZERO,
        settings: Settings {
            max_control_payload_bytes: 4096,
            ..Settings::default()
        },
        ..Config::default()
    };
    let peer_config = Config {
        settings: Settings {
            max_control_payload_bytes: 4096,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let ping_client = client.clone();
    let ping_thread = thread::spawn(move || ping_client.ping_timeout(b"", Duration::from_secs(1)));
    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(ping.payload.len(), 4096);
    let nonce = u64::from_be_bytes(ping.payload[..8].try_into().unwrap());
    let tag = u64::from_be_bytes(ping.payload[8..16].try_into().unwrap());
    assert_eq!(
        tag,
        ping_padding_tag(client.local_preface().settings.ping_padding_key, nonce)
    );

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });

    ping_thread.join().unwrap().unwrap();
    client.close().unwrap();
}

#[test]
fn ping_padding_skips_when_tag_cannot_fit() {
    let client_config = Config {
        ping_padding: true,
        ping_padding_min_bytes: 16,
        ping_padding_max_bytes: 64,
        keepalive_interval: Duration::ZERO,
        settings: Settings {
            max_control_payload_bytes: 4096,
            ..Settings::default()
        },
        ..Config::default()
    };
    let peer_config = Config {
        settings: Settings {
            max_control_payload_bytes: 4096,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let echo = vec![b'x'; 4081];

    let ping_client = client.clone();
    let expected = echo.clone();
    let ping_thread =
        thread::spawn(move || ping_client.ping_timeout(&echo, Duration::from_secs(1)));
    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(ping.payload.len(), 8 + expected.len());
    assert_eq!(&ping.payload[8..], expected.as_slice());

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });

    ping_thread.join().unwrap().unwrap();
    client.close().unwrap();
}

#[test]
fn unrecognized_peer_ping_is_echoed_without_padding_even_when_enabled() {
    let client_config = Config {
        ping_padding: true,
        ping_padding_min_bytes: 16,
        ping_padding_max_bytes: 16,
        keepalive_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let payload = b"plain-user-ping".to_vec();

    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: payload.clone(),
    });

    let pong = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Pong);
    assert_eq!(pong.payload, payload);

    client.close().unwrap();
}

#[test]
fn tagged_peer_ping_gets_padded_pong_suffix() {
    let peer_key = 0x1234_5678;
    let client_config = Config {
        ping_padding: true,
        ping_padding_min_bytes: 16,
        ping_padding_max_bytes: 16,
        keepalive_interval: Duration::ZERO,
        ..Config::default()
    };
    let peer_config = Config {
        ping_padding: true,
        settings: Settings {
            ping_padding_key: peer_key,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let nonce = 0x0102_0304_0506_0708u64;
    let mut payload = Vec::new();
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.extend_from_slice(&ping_padding_tag(peer_key, nonce).to_be_bytes());
    payload.extend_from_slice(b"echo");
    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: payload.clone(),
    });

    let pong = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Pong);
    assert!(pong.payload.starts_with(&payload));
    assert!(pong.payload.len() > payload.len());

    client.close().unwrap();
}

#[test]
fn second_ping_waits_for_outstanding_ping() {
    let (client, mut peer) = client_with_raw_peer(Config {
        ping_padding: false,
        ..Config::default()
    });

    let first_client = client.clone();
    let first = thread::spawn(move || first_client.ping(b"one"));
    let first_ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);

    let second_client = client.clone();
    let second = thread::spawn(move || second_client.ping(b"two"));
    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert!(
        !frames
            .iter()
            .any(|frame| frame.frame_type == FrameType::Ping),
        "second PING must wait while the first is outstanding"
    );

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: first_ping.payload,
    });
    let second_ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(&second_ping.payload[8..], b"two");
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: second_ping.payload,
    });

    first.join().unwrap().unwrap();
    second.join().unwrap().unwrap();
    client.close().unwrap();
}

#[test]
fn ping_fails_when_session_closes() {
    let (client, mut peer) = client_with_raw_peer(Config {
        ping_padding: false,
        ..Config::default()
    });

    let ping_client = client.clone();
    let ping = thread::spawn(move || ping_client.ping_timeout(b"close", Duration::from_secs(1)));
    let ping_frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(&ping_frame.payload[8..], b"close");
    assert!(client.stats().liveness.ping_outstanding);

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::NoError.as_u64(), ""),
    });

    let err = ping.join().unwrap().unwrap_err();
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Both);
    wait_for_state(&client, SessionState::Closed);
    assert!(!client.stats().liveness.ping_outstanding);
    assert_eq!(client.stats().pressure.outstanding_ping_bytes, 0);
    client.close().unwrap();
}

#[test]
fn ping_queues_payload_snapshot() {
    let (client, mut peer) = client_with_raw_peer(Config {
        ping_padding: false,
        ..Config::default()
    });
    let echo = b"ping-echo".to_vec();
    let expected = echo.clone();

    let ping_client = client.clone();
    let ping = thread::spawn(move || ping_client.ping_timeout(&echo, Duration::from_secs(1)));
    let ping_frame = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);

    assert_eq!(ping_frame.payload.len(), 8 + expected.len());
    assert_eq!(&ping_frame.payload[8..], expected.as_slice());

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping_frame.payload,
    });
    ping.join().unwrap().unwrap();
    client.close().unwrap();
}

#[test]
fn ping_timeout_releases_slot_and_ignores_matching_late_pong() {
    let client_config = Config {
        ignored_control_budget: 0,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    let ping_client = client.clone();
    let ping_thread =
        thread::spawn(move || ping_client.ping_timeout(b"timeout", Duration::from_millis(30)));
    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    let err = ping_thread.join().unwrap().unwrap_err();
    assert!(err.to_string().contains("ping timed out"));
    assert!(!client.stats().liveness.ping_outstanding);

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close().unwrap();
}

#[test]
fn late_matching_pong_after_timeout_clears_control_budget() {
    let client_config = Config {
        ignored_control_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: [1u8; 8].to_vec(),
    });

    let ping_client = client.clone();
    let ping_thread =
        thread::spawn(move || ping_client.ping_timeout(b"timeout", Duration::from_millis(30)));
    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    let err = ping_thread.join().unwrap().unwrap_err();
    assert!(err.to_string().contains("ping timed out"));

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: [2u8; 8].to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: [3u8; 8].to_vec(),
    });
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("ignored control budget"));

    client.close().ok();
}

#[test]
fn ping_timeout_ignores_matching_late_padded_pong() {
    let client_config = Config {
        ignored_control_budget: 0,
        ping_padding: true,
        ping_padding_min_bytes: 16,
        ping_padding_max_bytes: 16,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    let ping_client = client.clone();
    let ping_thread =
        thread::spawn(move || ping_client.ping_timeout(b"timeout", Duration::from_millis(30)));
    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert!(ping.payload.len() >= 8 + 16 + b"timeout".len());
    let err = ping_thread.join().unwrap().unwrap_err();
    assert!(err.to_string().contains("ping timed out"));
    assert!(!client.stats().liveness.ping_outstanding);

    let mut late_pong = ping.payload;
    late_pong.extend_from_slice(b"late-padding");
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: late_pong,
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close().unwrap();
}

#[test]
fn unexpected_pong_updates_progress_timestamp_without_rtt() {
    let client_config = Config {
        keepalive_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    assert!(client.stats().progress.pong_at.is_none());
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: [7u8; 8].to_vec(),
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let stats = client.stats();
        if stats.progress.pong_at.is_some() {
            assert!(stats.liveness.last_ping_rtt.is_none());
            assert!(!stats.liveness.ping_outstanding);
            client.close().unwrap();
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for unexpected PONG progress timestamp");
}

#[test]
fn keepalive_sends_idle_ping_and_records_rtt() {
    let client_config = Config {
        keepalive_interval: Duration::from_millis(20),
        keepalive_timeout: Duration::from_millis(500),
        ping_padding: false,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(ping.stream_id, 0);
    assert_eq!(ping.payload.len(), 8);
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let stats = client.stats();
        if stats.liveness.last_ping_rtt.is_some() && !stats.liveness.ping_outstanding {
            assert!(stats.progress.ping_sent_at.is_some());
            assert!(stats.progress.pong_at.is_some());
            client.close().unwrap();
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for keepalive RTT");
}

#[test]
fn keepalive_timeout_closes_session_with_idle_timeout() {
    let client_config = Config {
        keepalive_interval: Duration::from_millis(80),
        keepalive_timeout: Duration::from_millis(70),
        ping_padding: false,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let live = client.accept_stream().unwrap();
    let provisional = client.open_stream().unwrap();

    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(ping.payload.len(), 8);

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::IdleTimeout.as_u64());
    assert_eq!(reason, "zmux: keepalive timeout");
    wait_for_state(&client, SessionState::Failed);
    let cause = client.close_error().expect("keepalive timeout close error");
    assert_eq!(cause.code(), Some(ErrorCode::IdleTimeout));
    assert_eq!(cause.reason(), Some("zmux: keepalive timeout"));
    assert_eq!(cause.scope(), ErrorScope::Session);
    assert_eq!(cause.source(), zmux::ErrorSource::Local);
    assert_eq!(cause.direction(), ErrorDirection::Both);
    assert_eq!(cause.termination_kind(), TerminationKind::Timeout);
    let err = client.wait_timeout(Duration::ZERO).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::IdleTimeout));
    assert_eq!(err.reason(), Some("zmux: keepalive timeout"));
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.termination_kind(), TerminationKind::Timeout);
    assert!(err.is_timeout());
    assert_eq!(client.stats().diagnostics.keepalive_timeouts, 1);
    assert_eq!(client.stats().diagnostics.graceful_close_timeouts, 0);

    let live_write = live.write(b"x").unwrap_err();
    assert_local_stream_terminal_error(
        &live_write,
        ErrorCode::IdleTimeout,
        "zmux: keepalive timeout",
        ErrorOperation::Write,
        ErrorDirection::Write,
        TerminationKind::Timeout,
    );
    let provisional_write = provisional.write(b"x").unwrap_err();
    assert_local_stream_terminal_error(
        &provisional_write,
        ErrorCode::IdleTimeout,
        "zmux: keepalive timeout",
        ErrorOperation::Write,
        ErrorDirection::Write,
        TerminationKind::Timeout,
    );

    let mut buf = [0u8; 1];
    let live_read = live
        .read_timeout(&mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert_local_stream_terminal_error(
        &live_read,
        ErrorCode::IdleTimeout,
        "zmux: keepalive timeout",
        ErrorOperation::Read,
        ErrorDirection::Read,
        TerminationKind::Timeout,
    );
    let provisional_read = provisional
        .read_timeout(&mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert_local_stream_terminal_error(
        &provisional_read,
        ErrorCode::IdleTimeout,
        "zmux: keepalive timeout",
        ErrorOperation::Read,
        ErrorDirection::Read,
        TerminationKind::Timeout,
    );

    client.close().ok();
}

#[test]
fn outbound_write_does_not_mask_read_idle_keepalive() {
    let client_config = Config {
        keepalive_interval: Duration::from_millis(80),
        keepalive_timeout: Duration::from_millis(500),
        ping_padding: false,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    thread::sleep(Duration::from_millis(40));
    let stream = client.open_uni_stream().unwrap();
    stream.write_final(b"x").unwrap();
    let data = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(data.frame_type, FrameType::Data);

    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(ping.payload.len(), 8);
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });

    client.close().unwrap();
}

#[test]
fn keepalive_max_ping_interval_triggers_before_idle_interval() {
    let client_config = Config {
        keepalive_interval: Duration::from_secs(1),
        keepalive_max_ping_interval: Duration::from_millis(80),
        keepalive_timeout: Duration::from_millis(500),
        ping_padding: false,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    let ping = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Ping);
    assert_eq!(ping.payload.len(), 8);
    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: ping.payload,
    });

    client.close().unwrap();
}

#[test]
fn zero_length_data_exhausts_no_op_budget() {
    let client_config = Config {
        no_op_zero_data_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let _stream = client.accept_stream().unwrap();

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 1,
            payload: Vec::new(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("zero-length DATA budget"));

    client.close().ok();
}

#[test]
fn material_data_clears_zero_length_data_budget() {
    let client_config = Config {
        no_op_zero_data_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });

    let mut buf = [0u8; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 1);
    assert_eq!(&buf, b"x");
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close().unwrap();
}

#[test]
fn repeated_noop_max_data_exhausts_flow_control_budget() {
    let client_config = Config {
        no_op_max_data_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::MaxData,
            flags: 0,
            stream_id: 0,
            payload: encode_varint(0).unwrap(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("no-op MAX_DATA budget"));

    client.close().ok();
}

#[test]
fn no_op_budget_resets_after_abuse_window() {
    let client_config = Config {
        no_op_max_data_budget: 1,
        abuse_window: Duration::from_millis(20),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::MaxData,
            flags: 0,
            stream_id: 0,
            payload: encode_varint(0).unwrap(),
        });
        thread::sleep(Duration::from_millis(40));
    }
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::MaxData,
            flags: 0,
            stream_id: 0,
            payload: encode_varint(0).unwrap(),
        });
    }
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("no-op MAX_DATA budget"));

    client.close().ok();
}

#[test]
fn terminal_stream_max_data_exhausts_noop_budget() {
    let client_config = Config {
        no_op_max_data_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"hello".to_vec(),
    });
    let stream = client.accept_stream().unwrap();
    assert_eq!(read_all_stream(&stream), b"hello");
    stream.close_write().unwrap();
    let _ = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == 1
            && frame.flags & FRAME_FLAG_FIN != 0
    });

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::MaxData,
            flags: 0,
            stream_id: 1,
            payload: encode_varint(1_000_000).unwrap(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("no-op MAX_DATA budget"));

    client.close().ok();
}

#[test]
fn late_max_data_on_terminal_recv_only_stream_is_ignored() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 3,
        payload: b"hello".to_vec(),
    });
    let recv = client.accept_uni_stream().unwrap();
    assert_eq!(read_all_recv_stream(&recv), b"hello");

    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 3,
        payload: encode_varint(1024).unwrap(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| { matches!(frame.frame_type, FrameType::Abort | FrameType::Close) }));

    client.close().unwrap();
}

#[test]
fn late_blocked_on_terminal_send_only_stream_is_ignored() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let send = client.open_uni_stream().unwrap();
    send.write_final(b"x").unwrap();
    let opener = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data && frame.flags & FRAME_FLAG_FIN != 0
    });

    peer.write_frame(Frame {
        frame_type: FrameType::Blocked,
        flags: 0,
        stream_id: opener.stream_id,
        payload: encode_varint(0).unwrap(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| { matches!(frame.frame_type, FrameType::Abort | FrameType::Close) }));

    client.close().unwrap();
}

#[test]
fn max_data_on_recv_only_stream_aborts_stream_state() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 3,
        payload: b"x".to_vec(),
    });
    let recv = client.accept_uni_stream().unwrap();
    assert_eq!(recv.stream_id(), 3);

    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: recv.stream_id(),
        payload: encode_varint(1024).unwrap(),
    });

    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == recv.stream_id()
    });
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamState.as_u64());

    client.close().ok();
}

#[test]
fn blocked_on_send_only_stream_aborts_stream_state() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let send = client.open_uni_stream().unwrap();
    send.write(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data && frame.stream_id == send.stream_id()
    });

    peer.write_frame(Frame {
        frame_type: FrameType::Blocked,
        flags: 0,
        stream_id: opened.stream_id,
        payload: encode_varint(0).unwrap(),
    });

    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamState.as_u64());

    client.close().ok();
}

#[test]
fn reset_on_send_only_stream_aborts_stream_state() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let send = client.open_uni_stream().unwrap();
    send.write(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data && frame.stream_id == send.stream_id()
    });

    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });

    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamState.as_u64());

    client.close().ok();
}

#[test]
fn data_on_send_only_stream_aborts_stream_state() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    let send = client.open_uni_stream().unwrap();
    send.write(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data && frame.stream_id == send.stream_id()
    });

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: opened.stream_id,
        payload: b"wrong-way".to_vec(),
    });

    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == opened.stream_id
    });
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamState.as_u64());

    client.close().ok();
}

#[test]
fn stop_sending_on_recv_only_stream_aborts_stream_state() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 3,
        payload: b"x".to_vec(),
    });
    let recv = client.accept_uni_stream().unwrap();
    assert_eq!(recv.stream_id(), 3);

    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: recv.stream_id(),
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });

    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == recv.stream_id()
    });
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamState.as_u64());

    client.close().ok();
}

#[test]
fn effective_max_data_clears_noop_flow_control_budget() {
    let client_config = Config {
        no_op_max_data_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(0).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(262_145).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(262_145).unwrap(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close().unwrap();
}

#[test]
fn effective_max_data_clears_mixed_noop_control_budgets() {
    let client_config = Config {
        no_op_blocked_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Blocked,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(0).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(262_145).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Blocked,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(0).unwrap(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close().unwrap();
}

#[test]
fn repeated_noop_blocked_exhausts_flow_control_budget() {
    let client_config = Config {
        no_op_blocked_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Blocked,
            flags: 0,
            stream_id: 0,
            payload: encode_varint(0).unwrap(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("no-op BLOCKED budget"));

    client.close().ok();
}

#[test]
fn effective_stream_blocked_clears_noop_flow_control_budget() {
    let client_config = Config {
        no_op_blocked_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Blocked,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(0).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });
    let mut stream = client.accept_stream().unwrap();
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Blocked,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(0).unwrap(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Blocked,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(0).unwrap(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));

    client.close().unwrap();
}

#[test]
fn repeated_noop_priority_update_exhausts_priority_budget() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        no_op_priority_update_budget: 1,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });

    let payload = build_priority_update_payload(
        caps,
        MetadataUpdate {
            priority: Some(7),
            group: None,
        },
        Settings::default().max_extension_payload_bytes,
    )
    .unwrap();
    for _ in 0..3 {
        peer.write_frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 1,
            payload: payload.clone(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("no-op PRIORITY_UPDATE budget"));

    client.close().ok();
}

#[test]
fn invalid_priority_update_payload_is_counted_as_dropped() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: vec![1, 1, 1, 1, 1, 1, 2],
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let stats = client.stats();
        if stats.abuse.dropped_priority_update == 1 {
            assert_eq!(stats.abuse.no_op_priority_update, 0);
            client.close().unwrap();
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for dropped PRIORITY_UPDATE stat");
}

#[test]
fn duplicate_priority_update_on_live_stream_is_counted_as_dropped() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"body".to_vec(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&stream), b"body");

    peer.write_raw_frame_parts(FrameType::Ext, 0, 1, &duplicate_priority_update_payload());

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let stats = client.stats();
        if stats.abuse.dropped_priority_update == 1 {
            assert_eq!(stats.abuse.no_op_priority_update, 0);
            assert_eq!(stream.metadata().priority, None);
            assert_eq!(client.state(), SessionState::Ready);
            client
                .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
                .ok();
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for duplicate PRIORITY_UPDATE drop stat");
}

fn duplicate_priority_update_payload() -> Vec<u8> {
    let mut payload = encode_varint(EXT_PRIORITY_UPDATE).unwrap();
    append_tlv(
        &mut payload,
        METADATA_STREAM_PRIORITY,
        &encode_varint(3).unwrap(),
    )
    .unwrap();
    append_tlv(
        &mut payload,
        METADATA_STREAM_PRIORITY,
        &encode_varint(7).unwrap(),
    )
    .unwrap();
    payload
}

fn malformed_priority_update_payload() -> Vec<u8> {
    let mut payload = encode_varint(EXT_PRIORITY_UPDATE).unwrap();
    payload.extend_from_slice(&encode_varint(METADATA_STREAM_PRIORITY).unwrap());
    payload
}

#[test]
fn duplicate_priority_update_on_terminal_stream_counts_as_dropped() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        no_op_priority_update_budget: 1,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"body").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    stream.close_with_error(41, "").unwrap();
    let _abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == opened.stream_id
    });

    peer.write_raw_frame_parts(
        FrameType::Ext,
        0,
        opened.stream_id,
        &duplicate_priority_update_payload(),
    );

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let stats = client.stats();
        if stats.abuse.dropped_priority_update == 1 {
            assert_eq!(stats.abuse.no_op_priority_update, 0);
            assert!(!peer
                .collect_frames_for(Duration::from_millis(50))
                .iter()
                .any(|frame| frame.frame_type == FrameType::Close));
            client.close().ok();
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for duplicate PRIORITY_UPDATE drop stat");
}

#[test]
fn unknown_ext_on_terminal_stream_skips_priority_accounting() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"x".to_vec(),
    });
    let stream = client.accept_stream().unwrap();
    stream.close_write().unwrap();
    let _fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == 1
            && frame.flags & FRAME_FLAG_FIN != 0
    });

    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: encode_varint(99).unwrap(),
    });
    thread::sleep(Duration::from_millis(50));

    let stats = client.stats();
    assert_eq!(stats.abuse.dropped_priority_update, 0);
    assert_eq!(stats.abuse.no_op_priority_update, 0);
    client.close().ok();
    drop(stream);
}

#[test]
fn priority_update_does_not_revive_terminal_stream_metadata() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"done".to_vec(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_all_stream(&stream), b"done");
    stream.close_write().unwrap();
    let _ = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == 1
            && frame.flags & FRAME_FLAG_FIN != 0
    });

    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: Some(7),
                group: None,
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });
    thread::sleep(Duration::from_millis(50));

    assert_eq!(stream.metadata().priority, None);
    assert_eq!(client.state(), SessionState::Ready);
    client.close().ok();
    drop(stream);
}

#[test]
fn malformed_ext_subtype_without_priority_capability_fails_session() {
    let client_config = Config {
        capabilities: 0,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: 0,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_raw_frame_parts(FrameType::Ext, 0, 4, &[0x40]);

    wait_for_state(&client, SessionState::Failed);
    client.close().ok();
}

#[test]
fn negotiated_priority_update_on_stream_zero_fails_session() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_raw_frame_parts(FrameType::Ext, 0, 0, &[EXT_PRIORITY_UPDATE as u8]);

    let reason = assert_peer_receives_fatal_close(
        &client,
        &mut peer,
        ErrorCode::Protocol,
        "PRIORITY_UPDATE on stream 0",
    );
    assert!(
        reason.contains("PRIORITY_UPDATE requires non-zero stream_id"),
        "{reason}"
    );
}

#[test]
fn unnegotiated_priority_update_on_stream_zero_is_ignored() {
    let (client, mut peer) = client_with_raw_peer_configs(
        Config::default().disable_capabilities(),
        Config::responder().disable_capabilities(),
    );

    peer.write_raw_frame_parts(FrameType::Ext, 0, 0, &[EXT_PRIORITY_UPDATE as u8]);
    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: vec![7; 8],
    });

    let pong = peer.wait_for_frame(|frame| {
        assert_ne!(frame.frame_type, FrameType::Close);
        frame.frame_type == FrameType::Pong
    });
    assert_eq!(pong.payload, vec![7; 8]);
    assert_eq!(client.state(), SessionState::Ready);
    client.close().ok();
}

#[test]
fn priority_update_duplicate_then_truncated_tlv_fails_session_instead_of_dropping() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"body".to_vec(),
    });
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&stream), b"body");

    // Two stream_priority TLVs (a duplicate singleton), then a TLV header
    // truncated after its type: structurally malformed, not a dropped update.
    let mut payload = duplicate_priority_update_payload();
    payload.push(METADATA_STREAM_PRIORITY as u8);
    peer.write_raw_frame_parts(FrameType::Ext, 0, 1, &payload);

    let reason = assert_peer_receives_fatal_close(
        &client,
        &mut peer,
        ErrorCode::FrameSize,
        "PRIORITY_UPDATE duplicate then truncated",
    );
    assert!(reason.contains("truncated tlv"), "{reason}");
    assert_eq!(client.stats().abuse.dropped_priority_update, 0);
}

#[test]
fn open_metadata_duplicate_then_truncated_tlv_fails_session_without_accepting() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    // metadata_len=7: stream_priority twice (a duplicate singleton), then a
    // TLV header truncated after its type; "hi" is application data.
    peer.write_raw_frame_parts(
        FrameType::Data,
        FRAME_FLAG_OPEN_METADATA,
        1,
        &[0x07, 0x01, 0x01, 0x02, 0x01, 0x01, 0x03, 0x01, b'h', b'i'],
    );

    let reason = assert_peer_receives_fatal_close(
        &client,
        &mut peer,
        ErrorCode::FrameSize,
        "OPEN_METADATA duplicate then truncated",
    );
    assert!(reason.contains("truncated tlv"), "{reason}");
    assert_eq!(client.stats().received_data_bytes, 0);
    assert!(client
        .accept_stream_timeout(Duration::from_millis(10))
        .is_err());
}

#[test]
fn priority_update_during_graceful_close_drain_is_applied() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        close_drain_timeout: Duration::from_secs(2),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"hold-open").unwrap();

    let close_client = client.clone();
    let closer = thread::spawn(move || close_client.close());
    let _goaway = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    thread::sleep(Duration::from_millis(50));

    let payload = build_priority_update_payload(
        caps,
        MetadataUpdate {
            priority: Some(9),
            group: None,
        },
        Settings::default().max_extension_payload_bytes,
    )
    .unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: stream.stream_id(),
        payload,
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while stream.metadata().priority != Some(9) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }

    let stats = client.stats();
    assert_eq!(client.state(), SessionState::Draining);
    assert_eq!(stream.metadata().priority, Some(9));
    assert_eq!(stats.abuse.dropped_priority_update, 0);
    assert_eq!(stats.abuse.no_op_priority_update, 0);
    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::NoError.as_u64(), ""),
    });
    let _ = closer.join().unwrap();
    drop(stream);
}

#[test]
fn malformed_priority_update_during_graceful_close_drain_fails_session() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        close_drain_timeout: Duration::from_secs(2),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"hold-open").unwrap();

    let close_client = client.clone();
    let closer = thread::spawn(move || close_client.close());
    let _goaway = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    thread::sleep(Duration::from_millis(50));

    peer.write_raw_frame_parts(
        FrameType::Ext,
        0,
        stream.stream_id(),
        &malformed_priority_update_payload(),
    );
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, _) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FrameSize.as_u64());
    assert!(closer.join().unwrap().is_err());
    assert_eq!(client.state(), SessionState::Failed);
    drop(stream);
}

#[test]
fn priority_update_on_fully_terminal_live_stream_counts_as_noop() {
    let caps = CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
    let client_config = Config {
        capabilities: caps,
        no_op_priority_update_budget: 1,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"x".to_vec(),
    });
    let stream = client.accept_stream().unwrap();
    stream.close_write().unwrap();
    let _ = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == 1
            && frame.flags & FRAME_FLAG_FIN != 0
    });

    let payload = build_priority_update_payload(
        caps,
        MetadataUpdate {
            priority: Some(1),
            group: None,
        },
        Settings::default().max_extension_payload_bytes,
    )
    .unwrap();
    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 1,
            payload: payload.clone(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("no-op PRIORITY_UPDATE budget"));
    drop(stream);
}

#[test]
fn group_rebucket_churn_budget_fails_repeated_effective_group_updates() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        group_rebucket_churn_budget: 1,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        settings: Settings {
            scheduler_hints: SchedulerHint::GroupFair,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let stream = client.open_stream().unwrap();
    stream.write(b"x").unwrap();
    let opening = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    for group in [1, 2] {
        peer.write_frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: opening.stream_id,
            payload: build_priority_update_payload(
                caps,
                MetadataUpdate {
                    priority: None,
                    group: Some(group),
                },
                Settings::default().max_extension_payload_bytes,
            )
            .unwrap(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("stream_group rebucketing"));

    client.close().ok();
}

#[test]
fn priority_update_group_rebucket_tracks_diagnostic() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        settings: Settings {
            scheduler_hints: SchedulerHint::GroupFair,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: None,
                group: Some(7),
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while stream.metadata().group != Some(7) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(stream.metadata().group, Some(7));
    assert_eq!(client.stats().diagnostics.group_rebucket_events, 1);

    client.close().ok();
}

#[test]
fn group_update_outside_group_fair_does_not_track_rebucket_diagnostic() {
    let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_STREAM_GROUPS;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let stream = client.accept_stream().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 1,
        payload: build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: None,
                group: Some(7),
            },
            Settings::default().max_extension_payload_bytes,
        )
        .unwrap(),
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while stream.metadata().group != Some(7) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(stream.metadata().group, Some(7));
    assert_eq!(client.stats().diagnostics.group_rebucket_events, 0);
    client.close().ok();
}

#[test]
fn hidden_abort_churn_budget_fails_repeated_open_then_abort() {
    let client_config = Config {
        hidden_abort_churn_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for stream_id in [1, 5] {
        peer.write_frame(Frame {
            frame_type: FrameType::Abort,
            flags: 0,
            stream_id,
            payload: error_payload(ErrorCode::Cancelled.as_u64(), "abort"),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("hidden open-then-abort churn"));

    client.close().ok();
}

#[test]
fn hidden_abort_churn_budget_resets_after_window() {
    let client_config = Config {
        hidden_abort_churn_budget: 1,
        hidden_abort_churn_window: Duration::from_millis(20),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "abort"),
    });
    thread::sleep(Duration::from_millis(40));
    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 5,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "abort"),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Close));
    assert_eq!(client.stats().abuse.hidden_abort_churn, 1);

    client.close().unwrap();
}

#[test]
fn visible_terminal_churn_budget_fails_repeated_uni_reset() {
    let client_config = Config {
        visible_terminal_churn_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for stream_id in [3, 7] {
        peer.write_frame(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id,
            payload: b"x".to_vec(),
        });
        peer.write_frame(Frame {
            frame_type: FrameType::Reset,
            flags: 0,
            stream_id,
            payload: error_payload(ErrorCode::Cancelled.as_u64(), "reset"),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("open-then-reset/abort churn"));

    client.close().ok();
}

#[test]
fn repeated_ping_exhausts_inbound_ping_budget() {
    let client_config = Config {
        inbound_ping_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for payload in [b"ping-one".to_vec(), b"ping-two".to_vec()] {
        peer.write_frame(Frame {
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id: 0,
            payload,
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("inbound PING budget"));

    client.close().ok();
}

#[test]
fn inbound_control_frame_budget_fails_high_rate_control() {
    let client_config = Config {
        inbound_control_frame_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Pong,
            flags: 0,
            stream_id: 0,
            payload: [0u8; 8].to_vec(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("inbound control flood"));

    client.close().ok();
}

#[test]
fn inbound_control_byte_budget_fails_large_control_payload() {
    let client_config = Config {
        inbound_control_bytes_budget: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: [1u8; 8].to_vec(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("inbound control flood"));

    client.close().ok();
}

#[test]
fn inbound_ext_frame_budget_fails_high_rate_extensions() {
    let client_config = Config {
        inbound_ext_frame_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let payload = encode_varint(999).unwrap();

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 0,
            payload: payload.clone(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("inbound EXT flood"));

    client.close().ok();
}

#[test]
fn inbound_mixed_frame_budget_counts_control_and_ext_together() {
    let client_config = Config {
        inbound_mixed_frame_budget: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload: [0u8; 8].to_vec(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(99).unwrap(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("mixed control/EXT flood"));

    client.close().ok();
}

#[test]
fn max_varint_goaway_watermark_fails_direction_validation() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: build_go_away_payload(MAX_VARINT62, MAX_VARINT62, 0, "").unwrap(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (_, reason) = parse_error_payload(&close.payload).unwrap();
    assert!(reason.contains("wrong direction"));

    client.close().ok();
}

#[test]
fn duplicate_goaway_exhausts_control_budget() {
    let client_config = Config {
        ignored_control_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let payload = build_go_away_payload(0, 0, 0, "").unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: payload.clone(),
    });
    wait_for_state(&client, SessionState::Draining);

    for _ in 0..2 {
        peer.write_frame(Frame {
            frame_type: FrameType::GoAway,
            flags: 0,
            stream_id: 0,
            payload: payload.clone(),
        });
    }

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("ignored control budget"));

    client.close().ok();
}

#[test]
fn changed_peer_goaway_clears_ignored_control_budget() {
    let client_config = Config {
        ignored_control_budget: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let high = build_go_away_payload(4, 0, 0, "").unwrap();
    let low = build_go_away_payload(0, 0, 0, "").unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: high.clone(),
    });
    wait_for_state(&client, SessionState::Draining);

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: high,
    });
    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: low.clone(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: low.clone(),
    });
    assert!(peer
        .collect_frames_for(Duration::from_millis(80))
        .iter()
        .all(|frame| frame.frame_type != FrameType::Close));

    peer.write_frame(Frame {
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
        payload: low,
    });
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("ignored control budget"));

    client.close().ok();
}

#[test]
fn terminal_uni_releases_incoming_slot_before_accept_backlog_drains() {
    let client_config = Config {
        settings: Settings {
            max_incoming_streams_uni: 1,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 3,
        payload: b"first".to_vec(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 7,
        payload: b"second".to_vec(),
    });

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 7));
    assert_eq!(client.stats().active_streams.peer_uni, 0);
    assert_eq!(client.stats().accept_backlog.uni, 2);

    let accepted = client.accept_uni_stream().unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(accepted.read(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"first");
    let second = client.accept_uni_stream().unwrap();
    assert_eq!(second.read(&mut buf).unwrap(), 6);
    assert_eq!(&buf[..6], b"second");

    client.close().unwrap();
}

#[test]
fn accept_backlog_byte_limit_refuses_newest_visible_stream() {
    let client_config = Config {
        accept_backlog_bytes_limit: Some(3),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"ab".to_vec(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 5,
        payload: b"cd".to_vec(),
    });

    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 5);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());
    assert_eq!(client.stats().accept_backlog.refused, 1);

    let accepted = client.accept_stream().unwrap();
    assert_eq!(read_all_stream(&accepted), b"ab");

    client.close().unwrap();
}

#[test]
fn retained_open_info_budget_refuses_newest_visible_stream() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        retained_open_info_bytes_budget: Some(3),
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let mut first_payload = build_open_metadata_prefix(
        caps,
        None,
        None,
        b"aa",
        Settings::default().max_frame_payload,
    )
    .unwrap();
    first_payload.extend_from_slice(b"a");
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN,
        stream_id: 1,
        payload: first_payload,
    });

    let mut second_payload = build_open_metadata_prefix(
        caps,
        None,
        None,
        b"bb",
        Settings::default().max_frame_payload,
    )
    .unwrap();
    second_payload.extend_from_slice(b"b");
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN,
        stream_id: 5,
        payload: second_payload,
    });

    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 5);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());

    let stats = client.stats();
    assert_eq!(stats.accept_backlog.bidi, 1);
    assert_eq!(stats.retention.retained_open_info_bytes, 2);
    assert_eq!(stats.retention.retained_open_info_bytes_budget, 3);
    assert_eq!(stats.accept_backlog.refused, 1);
    assert_eq!(client.state(), SessionState::Ready);

    let accepted = client.accept_stream().unwrap();
    assert_eq!(accepted.open_info(), b"aa");
    assert_eq!(read_all_stream(&accepted), b"a");

    client.close().unwrap();
}

#[test]
fn tracked_session_memory_counts_open_metadata_backing_until_consumed() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let open_info = vec![7u8; 17];
    let mut payload = build_open_metadata_prefix(
        caps,
        None,
        None,
        &open_info,
        Settings::default().max_frame_payload,
    )
    .unwrap();
    payload.extend_from_slice(b"x");
    let expected_frame_storage = payload.len();

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA,
        stream_id: 1,
        payload,
    });
    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();

    let queued_stats = client.stats();
    assert_eq!(accepted.open_info(), open_info);
    assert_eq!(queued_stats.pressure.buffered_receive_bytes, 1);
    assert_eq!(
        queued_stats.pressure.tracked_buffered_bytes,
        expected_frame_storage + open_info.len()
    );
    assert_eq!(queued_stats.retention.retained_open_info_bytes, 0);

    let mut dst = [0u8; 1];
    assert_eq!(accepted.read(&mut dst).unwrap(), 1);
    assert_eq!(&dst, b"x");

    let drained_stats = client.stats();
    assert_eq!(drained_stats.pressure.buffered_receive_bytes, 0);
    assert_eq!(
        drained_stats.pressure.tracked_buffered_bytes,
        open_info.len()
    );
    assert_eq!(drained_stats.retention.retained_open_info_bytes, 0);

    client.close().unwrap();
}

#[test]
fn terminal_unaccepted_uni_stream_preserves_open_info_until_accept() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let payload = build_open_metadata_prefix(
        caps,
        None,
        None,
        b"ssh",
        Settings::default().max_frame_payload,
    )
    .unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN,
        stream_id: 3,
        payload,
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().accept_backlog.uni == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client.stats().accept_backlog.uni, 1);
    assert_eq!(client.stats().retention.retained_open_info_bytes, 3);

    let accepted = client
        .accept_uni_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(accepted.open_info(), b"ssh");
    assert!(read_all_recv_stream(&accepted).is_empty());
    assert_eq!(client.stats().accept_backlog.uni, 0);
    assert_eq!(client.stats().retention.retained_open_info_bytes, 0);

    client.close().unwrap();
}

#[test]
fn default_accept_backlog_count_limit_refuses_newest_visible_stream() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    for i in 0..129u64 {
        peer.write_frame(Frame {
            frame_type: FrameType::Data,
            flags: FRAME_FLAG_FIN,
            stream_id: 1 + i * 4,
            payload: vec![b'x'],
        });
    }

    let refused_stream_id = 1 + 128 * 4;
    let abort = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Abort && frame.stream_id == refused_stream_id
    });
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());

    let stats = client.stats();
    assert_eq!(stats.accept_backlog.limit, 128);
    assert_eq!(stats.accept_backlog.bidi, 128);
    assert_eq!(stats.accept_backlog.refused, 1);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn stats_report_accept_backlog_abuse_and_writer_limits() {
    let session_memory_cap = 32_768;
    let client_config = Config {
        write_queue_max_bytes: 1234,
        session_memory_cap: Some(session_memory_cap),
        urgent_queue_max_bytes: Some(555),
        per_stream_queued_data_high_watermark: Some(111),
        session_queued_data_high_watermark: Some(222),
        pending_control_bytes_budget: Some(333),
        pending_priority_bytes_budget: Some(444),
        marker_only_used_stream_limit: Some(12),
        write_batch_max_frames: 7,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"ab".to_vec(),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 0,
        payload: encode_varint(0).unwrap(),
    });
    thread::sleep(Duration::from_millis(50));

    let stats = client.stats();
    assert!(stats.received_frames >= 2);
    assert_eq!(stats.received_data_bytes, 2);
    assert_eq!(stats.open_streams, 1);
    assert_eq!(stats.active_streams.total, 1);
    assert_eq!(stats.accept_backlog.bidi, 1);
    assert_eq!(stats.accept_backlog.bytes, 2);
    assert_eq!(stats.abuse.no_op_max_data, 1);
    assert_eq!(stats.pressure.buffered_receive_bytes, 2);
    assert_eq!(stats.pressure.recv_session_received_bytes, 2);
    assert_eq!(stats.writer_queue.max_bytes, 1234);
    assert_eq!(stats.writer_queue.urgent_max_bytes, 555);
    assert_eq!(stats.writer_queue.per_stream_data_high_watermark, 111);
    assert_eq!(stats.writer_queue.session_data_high_watermark, 222);
    assert_eq!(stats.writer_queue.pending_control_bytes_budget, 333);
    assert_eq!(stats.writer_queue.pending_priority_bytes_budget, 444);
    assert_eq!(stats.writer_queue.max_batch_frames, 7);
    assert_eq!(stats.memory.hard_cap, session_memory_cap);
    assert!(!stats.memory.over_cap);
    assert_eq!(stats.retention.marker_only_used_stream_limit, 12);

    let stream = client.accept_stream().unwrap();
    assert_eq!(client.stats().accepted_streams, 1);
    assert_eq!(client.stats().accept_backlog.bytes, 0);
    let mut buf = [0u8; 2];
    assert_eq!(stream.read(&mut buf).unwrap(), 2);
    let read_stats = client.stats();
    assert_eq!(&buf, b"ab");
    assert!(read_stats.progress.stream_progress_at.is_some());
    assert!(read_stats.progress.application_progress_at.is_some());
    stream.close_read().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"z".to_vec(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().diagnostics.late_data_after_close_read != 1 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client.stats().diagnostics.late_data_after_close_read, 1);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn terminal_session_close_releases_accept_backlog_and_stream_storage() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"ab".to_vec(),
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().accept_backlog.bidi == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }

    let before = client.stats();
    assert_eq!(before.open_streams, 1);
    assert_eq!(before.accept_backlog.bidi, 1);
    assert_eq!(before.accept_backlog.bytes, 2);
    assert_eq!(before.pressure.buffered_receive_bytes, 2);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();

    let after = client.stats();
    assert_eq!(after.open_streams, 0);
    assert_eq!(after.active_streams.total, 0);
    assert_eq!(after.accept_backlog.bidi, 0);
    assert_eq!(after.accept_backlog.uni, 0);
    assert_eq!(after.accept_backlog.bytes, 0);
    assert_eq!(after.pressure.buffered_receive_bytes, 0);
    assert_eq!(after.pressure.receive_backlog_bytes, 0);
    assert_eq!(after.pressure.recv_session_received_bytes, 0);
    assert_eq!(after.pressure.recv_session_pending_bytes, 0);
    assert!(client
        .accept_stream_timeout(Duration::from_millis(1))
        .is_err());
}

#[test]
fn inbound_data_session_memory_cap_closes_session() {
    let client_config = Config {
        session_memory_cap: Some(3),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"abcd".to_vec(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Internal.as_u64());
    assert!(reason.contains("session memory cap exceeded"));
    wait_for_state(&client, SessionState::Failed);
}

#[test]
fn outbound_data_session_memory_cap_fails_session_and_rolls_back_write() {
    let retained_unit = usize::try_from(Settings::default().max_frame_payload).unwrap();
    let client_config = Config {
        session_memory_cap: Some(retained_unit),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();

    stream.set_write_deadline(Some(Instant::now())).unwrap();
    let err = stream.write(b"x").unwrap_err();

    assert!(err.is_error_code(ErrorCode::Internal));
    assert!(err.to_string().contains("session memory cap exceeded"));
    wait_for_state(&client, SessionState::Failed);
    assert_eq!(client.stats().writer_queue.data_queued_bytes, 0);

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Internal.as_u64());
    assert!(reason.contains("session memory cap exceeded"));
    assert_eq!(client.stats().writer_queue.queued_bytes, 0);
    assert!(peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .all(|frame| frame.frame_type != FrameType::Data));
}

#[test]
fn accept_backlog_byte_accounting_releases_on_accept() {
    let client_config = Config {
        accept_backlog_bytes_limit: Some(3),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 1,
        payload: b"ab".to_vec(),
    });
    let first = client.accept_stream().unwrap();
    assert_eq!(read_all_stream(&first), b"ab");

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: 5,
        payload: b"cd".to_vec(),
    });
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 5));

    let second = client.accept_stream().unwrap();
    assert_eq!(read_all_stream(&second), b"cd");

    client.close().unwrap();
}

#[test]
fn local_open_info_budget_releases_when_uncommitted_open_is_cancelled() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        retained_open_info_bytes_budget: Some(3),
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, _peer) = client_with_raw_peer_configs(client_config, peer_config);

    let first = client
        .open_stream_with(OpenOptions::new().open_info(b"abc"))
        .unwrap();
    assert_eq!(client.stats().retention.retained_open_info_bytes, 3);

    let err = match client.open_stream_with(OpenOptions::new().open_info(b"x")) {
        Ok(_) => panic!("open_stream_with unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.code(), Some(ErrorCode::StreamLimit));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert!(err.to_string().contains("open_info budget"));

    first.cancel_write(ErrorCode::Cancelled.as_u64()).unwrap();
    assert_eq!(client.stats().retention.retained_open_info_bytes, 0);

    let replacement = client
        .open_stream_with(OpenOptions::new().open_info(b"x"))
        .unwrap();
    assert_eq!(client.stats().retention.retained_open_info_bytes, 1);
    replacement
        .cancel_write(ErrorCode::Cancelled.as_u64())
        .unwrap();
    client.close().unwrap();
}

#[test]
fn local_open_session_memory_cap_rejects_open_info_over_cap() {
    let caps = CAPABILITY_OPEN_METADATA;
    let retained_unit = usize::try_from(Settings::default().max_frame_payload).unwrap();
    let open_info = b"abc".to_vec();
    let baseline = local_open_memory_cap_baseline(caps);
    let client_config = Config {
        capabilities: caps,
        session_memory_cap: Some(baseline + retained_unit + open_info.len() - 1),
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, _peer) = client_with_raw_peer_configs(client_config, peer_config);

    let err = match client.open_stream_with(OpenOptions::new().open_info(&open_info)) {
        Ok(_) => panic!("open_stream_with unexpectedly succeeded"),
        Err(err) => err,
    };

    assert_eq!(err.code(), Some(ErrorCode::StreamLimit));
    assert!(err
        .to_string()
        .contains("local open limited by session memory cap"));
    assert_eq!(client.stats().retention.retained_open_info_bytes, 0);
    assert_eq!(client.stats().provisional.bidi, 0);
    client.close().unwrap();
}

fn local_open_memory_cap_baseline(caps: u64) -> usize {
    let client_config = Config {
        capabilities: caps,
        session_memory_cap: Some(usize::MAX),
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, _peer) = client_with_raw_peer_configs(client_config, peer_config);
    let baseline = client.stats().memory.tracked_bytes;
    client.close().unwrap();
    baseline
}

#[test]
fn local_open_rejects_open_info_without_negotiated_open_metadata() {
    let (client, mut peer) = client_with_raw_peer(Config::default().disable_capabilities());

    let err = match client.open_stream_with(OpenOptions::new().open_info(b"need-metadata")) {
        Ok(_) => panic!("open_stream_with unexpectedly succeeded"),
        Err(err) => err,
    };

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert!(err
        .to_string()
        .contains("open_info requires negotiated open_metadata"));
    assert_eq!(client.stats().retention.retained_open_info_bytes, 0);
    assert!(peer
        .collect_frames_for(Duration::from_millis(100))
        .is_empty());

    client.close().unwrap();
}

#[test]
fn local_open_rejects_oversized_open_metadata_at_open_time() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let open_info = vec![0; Settings::default().max_frame_payload as usize + 1];

    let err = match client.open_stream_with(OpenOptions::new().open_info(&open_info)) {
        Ok(_) => panic!("open_stream_with unexpectedly succeeded"),
        Err(err) => err,
    };

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.scope(), ErrorScope::Stream);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
    assert!(err
        .to_string()
        .contains("opening metadata exceeds peer max_frame_payload"));
    assert_eq!(client.stats().retention.retained_open_info_bytes, 0);
    assert!(peer
        .collect_frames_for(Duration::from_millis(100))
        .is_empty());

    client.close().unwrap();
}

#[test]
fn local_open_session_memory_cap_rejects_without_emitting_frames() {
    let client_config = Config {
        session_memory_cap: Some(4096),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    let err = match client.open_stream() {
        Ok(_) => panic!("open_stream unexpectedly succeeded"),
        Err(err) => err,
    };

    assert_eq!(err.code(), Some(ErrorCode::StreamLimit));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Open);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Both);
    assert!(err
        .to_string()
        .contains("local open limited by session memory cap"));
    assert_eq!(client.stats().retention.retained_open_info_bytes, 0);
    assert!(peer
        .collect_frames_for(Duration::from_millis(100))
        .is_empty());

    client.close().unwrap();
}

#[test]
fn inbound_data_session_memory_cap_refuses_newest_visible_stream_first() {
    let client_config = Config {
        session_memory_cap: Some(4096),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: vec![1],
    });

    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());
    assert_eq!(client.state(), SessionState::Ready);
    assert_eq!(client.stats().accept_backlog.refused, 1);

    client.close().unwrap();
}

#[test]
fn local_open_metadata_prefix_releases_after_first_frame_is_visible_to_peer() {
    let caps = CAPABILITY_OPEN_METADATA;
    let client_config = Config {
        capabilities: caps,
        ..Config::default()
    };
    let peer_config = Config {
        capabilities: caps,
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);

    let stream = client
        .open_stream_with(OpenOptions::new().open_info(b"abc"))
        .unwrap();
    stream.write_final(b"x").unwrap();

    let opener = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(
        opener.flags & FRAME_FLAG_OPEN_METADATA,
        FRAME_FLAG_OPEN_METADATA
    );

    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().memory.tracked_bytes != 3 && Instant::now() < deadline {
        thread::yield_now();
    }
    let stats = client.stats();
    assert_eq!(stats.retention.retained_open_info_bytes, 3);
    assert_eq!(stats.memory.tracked_bytes, 3);

    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn peer_reset_reason_uses_retained_reason_budget() {
    let client_config = Config {
        retained_peer_reason_bytes_budget: Some(2),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"x".to_vec(),
    });
    let accepted = client.accept_stream().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Internal.as_u64(), "abcd"),
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().retention.retained_peer_reason_bytes != 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client.stats().retention.retained_peer_reason_bytes, 2);

    let mut byte = [0u8; 1];
    let err = accepted.read(&mut byte).unwrap_err();
    assert!(err.to_string().contains(": ab"));
    assert!(!err.to_string().contains("abcd"));

    client.close().unwrap();
}

#[test]
fn peer_reset_reason_releases_after_terminal_compaction() {
    let client_config = Config {
        retained_peer_reason_bytes_budget: Some(2),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 3,
        payload: b"payload".to_vec(),
    });
    let accepted = client.accept_uni_stream().unwrap();

    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 3,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), "abcd"),
    });

    let mut buf = [0u8; 32];
    let err = match accepted.read_timeout(&mut buf, Duration::from_secs(1)) {
        Ok(_) => accepted
            .read_timeout(&mut buf, Duration::from_secs(1))
            .unwrap_err(),
        Err(err) => err,
    };

    assert_eq!(err.code(), Some(ErrorCode::Cancelled));
    assert_eq!(err.reason(), Some("ab"));
    assert_eq!(client.stats().retention.retained_peer_reason_bytes, 0);

    client.close().unwrap();
}

#[test]
fn peer_reset_reason_is_trimmed_by_session_memory_cap() {
    let retained_unit = usize::try_from(Settings::default().max_frame_payload).unwrap();
    let client_config = Config {
        session_memory_cap: Some(retained_unit + 3),
        retained_peer_reason_bytes_budget: Some(16),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: Vec::new(),
    });
    let accepted = client.accept_stream().unwrap();
    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Internal.as_u64(), "abcd"),
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().retention.retained_peer_reason_bytes != 3 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client.stats().retention.retained_peer_reason_bytes, 3);

    let mut byte = [0u8; 1];
    let err = accepted.read(&mut byte).unwrap_err();
    assert!(err.to_string().contains(": abc"));
    assert!(!err.to_string().contains("abcd"));
    assert!(!client.is_closed());

    client.close().unwrap();
}

fn run_concurrent_open_write_round(
    threads: usize,
    payload_len: usize,
    priority: impl Fn(usize) -> Option<u64> + Send + Sync + 'static,
    client_config: Config,
    server_config: Config,
) {
    // Every worker opens before any commits, so allow them all to be provisional.
    let client_config = Config {
        max_provisional_streams_bidi: threads,
        ..client_config
    };
    let (client, server) = connected_pair(client_config, server_config);
    let client = Arc::new(client);
    let priority = Arc::new(priority);
    let start = Arc::new(Barrier::new(threads));
    let mut workers = Vec::with_capacity(threads);
    for idx in 0..threads {
        let client = Arc::clone(&client);
        let start = Arc::clone(&start);
        let priority = Arc::clone(&priority);
        workers.push(thread::spawn(move || {
            let opts = match priority(idx) {
                Some(priority) => OpenOptions::new().priority(priority),
                None => OpenOptions::new(),
            };
            start.wait();
            let stream = client.open_stream_with(opts)?;
            stream.write_all(vec![idx as u8; payload_len])?;
            stream.close_write()?;
            Ok::<_, zmux::Error>(stream)
        }));
    }

    let mut accepted_ids = Vec::with_capacity(threads);
    let mut readers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let stream = server
            .accept_stream_timeout(Duration::from_secs(10))
            .unwrap_or_else(|err| {
                let worker_errors: Vec<String> = std::mem::take(&mut workers)
                    .into_iter()
                    .filter_map(|worker| worker.join().unwrap().err())
                    .map(|err| err.to_string())
                    .collect();
                panic!(
                    "accept failed: {err}; server closed={} err={:?} worker errors={worker_errors:?}",
                    server.is_closed(),
                    server.wait_timeout(Duration::ZERO),
                )
            });
        accepted_ids.push(stream.stream_id());
        readers.push(thread::spawn(move || read_all_stream(&stream).len()));
    }
    for worker in workers {
        worker.join().unwrap().unwrap();
    }
    for reader in readers {
        assert_eq!(reader.join().unwrap(), payload_len);
    }
    let mut sorted = accepted_ids.clone();
    sorted.sort_unstable();
    assert_eq!(
        accepted_ids, sorted,
        "accepted stream IDs must be ascending"
    );
    assert!(!server.is_closed());
    assert!(!client.is_closed());
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn concurrent_open_and_first_write_keeps_stream_ids_in_wire_order() {
    for _ in 0..10 {
        run_concurrent_open_write_round(100, 100, |_| None, Config::default(), Config::default());
    }
    for _ in 0..100 {
        run_concurrent_open_write_round(8, 100, |_| None, Config::default(), Config::default());
    }
}

#[test]
fn concurrent_open_with_mixed_priorities_keeps_stream_ids_in_wire_order() {
    let caps = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS;
    for round in 0..10 {
        let (client_config, server_config) = if round % 2 == 0 {
            (Config::default(), Config::default())
        } else {
            (
                Config {
                    capabilities: caps,
                    ..Config::default()
                },
                Config {
                    capabilities: caps,
                    ..Config::default()
                },
            )
        };
        run_concurrent_open_write_round(
            64,
            100,
            |idx| Some(u64::try_from(idx % 16).unwrap()),
            client_config,
            server_config,
        );
    }
}

#[test]
fn concurrent_open_with_credit_blocked_first_writes_keeps_stream_ids_in_wire_order() {
    for _ in 0..5 {
        run_concurrent_open_write_round(
            32,
            200_000,
            |idx| Some(u64::try_from(idx % 4).unwrap()),
            Config::default(),
            Config::default(),
        );
    }
}

#[test]
fn concurrent_uni_open_and_first_write_keeps_stream_ids_in_wire_order() {
    for _ in 0..10 {
        let client_config = Config {
            max_provisional_streams_uni: 48,
            ..Config::default()
        };
        let (client, server) = connected_pair(client_config, Config::default());
        let client = Arc::new(client);
        let start = Arc::new(Barrier::new(48));
        let workers: Vec<_> = (0..48)
            .map(|idx| {
                let client = Arc::clone(&client);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    let stream = client.open_uni_stream()?;
                    stream.write_final(vec![idx as u8; 100])?;
                    Ok::<_, zmux::Error>(())
                })
            })
            .collect();
        let mut accepted_ids = Vec::new();
        for _ in 0..48 {
            let stream = server
                .accept_uni_stream_timeout(Duration::from_secs(10))
                .unwrap();
            accepted_ids.push(stream.stream_id());
            assert_eq!(read_all_recv_stream(&stream).len(), 100);
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        let mut sorted = accepted_ids.clone();
        sorted.sort_unstable();
        assert_eq!(accepted_ids, sorted);
        assert!(!server.is_closed());
        client
            .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
            .unwrap();
    }
}

fn gated_client_with_raw_peer(client_config: Config) -> (Conn, RawPeer, Arc<BlockingWriterState>) {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    // The preface write passes; the first frame batch blocks until released.
    let (client_write, writer_gate) = blocking_writer(client_io, 1);
    let client_thread = thread::spawn(move || {
        Conn::client_with_config((client_read, client_write), client_config).unwrap()
    });
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = Config::responder().local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();
    let client = client_thread.join().unwrap();
    (
        client,
        RawPeer {
            io: peer_io,
            read_buf: Vec::new(),
        },
        writer_gate,
    )
}

fn wait_for_queued_data_at_least(conn: &Conn, bytes: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while conn.stats().writer_queue.data_queued_bytes < bytes {
        assert!(
            Instant::now() < deadline,
            "queued data did not reach {bytes} bytes: {:?}",
            conn.stats().writer_queue
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn spawn_write(stream: &zmux::Stream, payload: &[u8]) -> thread::JoinHandle<zmux::Result<usize>> {
    let stream = stream.clone();
    let payload = payload.to_vec();
    thread::spawn(move || stream.write(&payload))
}

fn stream_frame_summary(frames: &[Frame], stream_id: u64) -> Vec<(FrameType, Vec<u8>)> {
    frames
        .iter()
        .filter(|frame| frame.stream_id == stream_id)
        .map(|frame| {
            let payload = if frame.frame_type == FrameType::Data {
                parse_data_payload(&frame.payload, frame.flags)
                    .unwrap()
                    .app_data
                    .to_vec()
            } else {
                frame.payload.clone()
            };
            (frame.frame_type, payload)
        })
        .collect()
}

fn first_frame_index(frames: &[Frame], stream_id: u64) -> usize {
    frames
        .iter()
        .position(|frame| frame.stream_id == stream_id)
        .unwrap_or_else(|| panic!("no frame for stream {stream_id}: {frames:?}"))
}

#[test]
fn cancel_write_with_queued_opener_keeps_opener_ahead_of_reset() {
    let (client, mut peer, gate) = gated_client_with_raw_peer(Config::default());
    let first = client.open_stream().unwrap();
    let second = client.open_stream().unwrap();
    let first_write = spawn_write(&first, b"x");
    gate.wait_blocked();
    let second_write = spawn_write(&second, b"y");
    wait_for_queued_data_at_least(&client, 1);

    second.cancel_write(77).unwrap();
    gate.release();
    assert_eq!(first_write.join().unwrap().unwrap(), 1);
    assert!(second_write.join().unwrap().is_err());

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        stream_frame_summary(&frames, second.stream_id()),
        vec![
            (FrameType::Data, Vec::new()),
            (FrameType::Reset, error_payload(77, "")),
        ],
        "{frames:?}"
    );
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn close_with_error_with_queued_opener_opens_with_abort_in_place() {
    let (client, mut peer, gate) = gated_client_with_raw_peer(Config::default());
    // Block the writer on a peer-opened stream so both local openers stay queued.
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"p".to_vec(),
    });
    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let blocker_write = spawn_write(&accepted, b"q");
    gate.wait_blocked();

    let earlier = client.open_stream().unwrap();
    let later = client.open_stream().unwrap();
    let earlier_write = spawn_write(&earlier, b"y");
    wait_for_queued_data_at_least(&client, 1);
    let queued = client.stats().writer_queue.data_queued_bytes;
    let later_write = spawn_write(&later, b"z");
    wait_for_queued_data_at_least(&client, queued + 1);

    later.close_with_error(9, "").unwrap();
    gate.release();
    assert_eq!(blocker_write.join().unwrap().unwrap(), 1);
    assert_eq!(earlier_write.join().unwrap().unwrap(), 1);
    assert!(later_write.join().unwrap().is_err());

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        stream_frame_summary(&frames, later.stream_id()),
        vec![(FrameType::Abort, error_payload(9, ""))],
        "{frames:?}"
    );
    assert!(
        first_frame_index(&frames, earlier.stream_id())
            < first_frame_index(&frames, later.stream_id()),
        "opening ABORT overtook an earlier same-class opener: {frames:?}"
    );
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn close_read_with_queued_opener_orders_stop_sending_after_opener() {
    let (client, mut peer, gate) = gated_client_with_raw_peer(Config::default());
    let first = client.open_stream().unwrap();
    let second = client.open_stream().unwrap();
    let first_write = spawn_write(&first, b"x");
    gate.wait_blocked();
    let second_write = spawn_write(&second, b"y");
    wait_for_queued_data_at_least(&client, 1);

    let closer = second.clone();
    let close_read = thread::spawn(move || closer.close_read());
    thread::sleep(Duration::from_millis(20));
    gate.release();
    close_read.join().unwrap().unwrap();
    assert_eq!(first_write.join().unwrap().unwrap(), 1);
    assert_eq!(second_write.join().unwrap().unwrap(), 1);

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        stream_frame_summary(&frames, second.stream_id()),
        vec![
            (FrameType::Data, b"y".to_vec()),
            (
                FrameType::StopSending,
                error_payload(ErrorCode::Cancelled.as_u64(), "")
            ),
        ],
        "{frames:?}"
    );
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

struct QueueBlockedOpener {
    client: Conn,
    peer: RawPeer,
    gate: Arc<BlockingWriterState>,
    target: zmux::Stream,
    writes: Vec<thread::JoinHandle<zmux::Result<usize>>>,
}

fn queue_blocked_opener_setup() -> QueueBlockedOpener {
    queue_blocked_opener_setup_with(Config::default())
}

fn queue_blocked_opener_setup_with(config: Config) -> QueueBlockedOpener {
    let config = Config {
        session_queued_data_high_watermark: Some(4096),
        ..config
    };
    let (client, peer, gate) = gated_client_with_raw_peer(config);
    let first = client.open_stream().unwrap();
    let filler = client.open_stream().unwrap();
    let target = client.open_stream().unwrap();
    let first_write = spawn_write(&first, b"x");
    gate.wait_blocked();
    let filler_write = spawn_write(&filler, &[b'f'; 3500]);
    wait_for_queued_data_at_least(&client, 3500);
    // The target's opener (1000 bytes + overhead) exceeds the remaining session
    // queued-data budget, so it stays prepared but unqueued in the writer queue.
    let target_write = spawn_write(&target, &[b't'; 1000]);
    let deadline = Instant::now() + Duration::from_secs(2);
    while target.stream_id() == 0 {
        assert!(Instant::now() < deadline, "target stream did not commit");
        thread::sleep(Duration::from_millis(1));
    }
    thread::sleep(Duration::from_millis(20));
    assert!(client.stats().writer_queue.data_queued_bytes < 4096);
    QueueBlockedOpener {
        client,
        peer,
        gate,
        target,
        writes: vec![first_write, filler_write, target_write],
    }
}

#[test]
fn cancel_write_while_opener_waits_for_queue_space_opens_with_abort() {
    let QueueBlockedOpener {
        client,
        mut peer,
        gate,
        target,
        mut writes,
    } = queue_blocked_opener_setup();
    target.cancel_write(77).unwrap();
    gate.release();
    let target_write = writes.pop().unwrap();
    assert!(target_write.join().unwrap().is_err());
    for write in writes {
        write.join().unwrap().unwrap();
    }

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let target_frames = stream_frame_summary(&frames, target.stream_id());
    assert_eq!(
        target_frames.first(),
        Some(&(FrameType::Abort, error_payload(77, ""))),
        "{frames:?}"
    );
    assert!(!target_frames
        .iter()
        .any(|(frame_type, _)| *frame_type == FrameType::Reset));
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn refused_opening_abort_push_does_not_wedge_the_class_opener_turn() {
    // The target holds the class opener turn with its opener prepared but not
    // queued. Its opening ABORT exceeds the whole pending-control budget, so the
    // ordinary push is refused; the turn must still pass on, and the ABORT must
    // still open the target ahead of the next same-class opener (SPEC §3.1).
    let reason = "r".repeat(64);
    let QueueBlockedOpener {
        client,
        mut peer,
        gate,
        target,
        mut writes,
    } = queue_blocked_opener_setup_with(Config {
        pending_control_bytes_budget: Some(16),
        ..Config::default()
    });
    target.close_with_error(9, &reason).unwrap();
    gate.release();
    let target_write = writes.pop().unwrap();
    assert!(target_write.join().unwrap().is_err());
    for write in writes {
        write.join().unwrap().unwrap();
    }

    let next = client.open_stream().unwrap();
    assert_eq!(
        next.write_timeout(b"n", Duration::from_secs(2)).unwrap(),
        1,
        "later same-class open stayed blocked behind the failed ABORT's turn"
    );
    assert_eq!(next.stream_id(), target.stream_id() + 4);

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        stream_frame_summary(&frames, target.stream_id()),
        vec![(FrameType::Abort, error_payload(9, &reason))],
        "{frames:?}"
    );
    assert!(
        first_frame_index(&frames, target.stream_id())
            < first_frame_index(&frames, next.stream_id()),
        "{frames:?}"
    );
    assert!(!client.is_closed());
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn close_read_while_opener_waits_for_queue_space_keeps_opener_first() {
    let QueueBlockedOpener {
        client,
        mut peer,
        gate,
        target,
        writes,
    } = queue_blocked_opener_setup();
    let closer = target.clone();
    let close_read = thread::spawn(move || closer.close_read());
    thread::sleep(Duration::from_millis(20));
    gate.release();
    close_read.join().unwrap().unwrap();
    for write in writes {
        write.join().unwrap().unwrap();
    }

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let target_frames = stream_frame_summary(&frames, target.stream_id());
    assert_eq!(target_frames.len(), 2, "{frames:?}");
    assert_eq!(target_frames[0], (FrameType::Data, vec![b't'; 1000]));
    assert_eq!(target_frames[1].0, FrameType::StopSending);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn deadline_cancel_of_queued_opener_keeps_place_before_later_opener() {
    let (client, mut peer, gate) = gated_client_with_raw_peer(Config::default());
    let first = client.open_stream().unwrap();
    let second = client.open_stream().unwrap();
    let third = client.open_stream().unwrap();
    let first_write = spawn_write(&first, b"x");
    gate.wait_blocked();
    let second_write = spawn_write(&second, b"y");
    wait_for_queued_data_at_least(&client, 1);
    let queued = client.stats().writer_queue.data_queued_bytes;
    let third_write = spawn_write(&third, b"z");
    wait_for_queued_data_at_least(&client, queued + 1);

    second
        .set_write_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();
    assert!(second_write.join().unwrap().unwrap_err().is_timeout());
    assert!(!second.is_write_closed());

    gate.release();
    assert_eq!(first_write.join().unwrap().unwrap(), 1);
    assert_eq!(third_write.join().unwrap().unwrap(), 1);
    second.set_write_deadline(None).unwrap();
    assert_eq!(second.write(b"w").unwrap(), 1);

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        stream_frame_summary(&frames, second.stream_id()),
        vec![
            (FrameType::Data, Vec::new()),
            (FrameType::Data, b"w".to_vec())
        ],
        "{frames:?}"
    );
    assert!(
        first_frame_index(&frames, second.stream_id())
            < first_frame_index(&frames, third.stream_id()),
        "{frames:?}"
    );
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn later_open_consumes_abandoned_committed_opener_with_abort() {
    let (client, mut peer, gate) = gated_client_with_raw_peer(Config::default());
    let first = client.open_stream().unwrap();
    let second = client.open_stream().unwrap();
    let third = client.open_stream().unwrap();
    let first_write = spawn_write(&first, b"x");
    gate.wait_blocked();
    let second_write = spawn_write(&second, b"y");
    wait_for_queued_data_at_least(&client, 1);
    second
        .set_write_deadline(Some(Instant::now() + Duration::from_millis(20)))
        .unwrap();
    assert!(second_write.join().unwrap().unwrap_err().is_timeout());
    let second_id = second.stream_id();
    assert_ne!(second_id, 0);

    let third_write = spawn_write(&third, b"z");
    wait_for_queued_data_at_least(&client, 1);
    gate.release();
    assert_eq!(first_write.join().unwrap().unwrap(), 1);
    assert_eq!(third_write.join().unwrap().unwrap(), 1);
    assert_eq!(third.stream_id(), second_id + 4);

    let err = second.write(b"w").unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::Cancelled));
    assert_eq!(err.termination_kind(), TerminationKind::Abort);
    assert_eq!(err.source(), ErrorSource::Local);

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let second_frames = stream_frame_summary(&frames, second_id);
    assert_eq!(second_frames.len(), 1, "{frames:?}");
    assert_eq!(second_frames[0].0, FrameType::Abort);
    assert_eq!(
        parse_error_payload(&second_frames[0].1).unwrap().0,
        ErrorCode::Cancelled.as_u64()
    );
    assert!(
        first_frame_index(&frames, second_id) < first_frame_index(&frames, third.stream_id()),
        "{frames:?}"
    );
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

fn wait_for_read_abort(stream: &zmux::Stream, code: u64) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buf = [0u8; 16];
    loop {
        match stream.read_timeout(&mut buf, Duration::from_millis(50)) {
            Err(err) if err.termination_kind() == TerminationKind::Abort => {
                assert_eq!(err.numeric_code(), Some(code));
                return;
            }
            Err(err) if err.is_timeout() => {}
            Ok(_) => {}
            Err(err) => panic!("unexpected read error while waiting for abort: {err:?}"),
        }
        assert!(Instant::now() < deadline, "stream was not aborted");
    }
}

#[test]
fn write_after_peer_abort_of_finished_send_half_reports_abort() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    let stream = client.open_stream().unwrap();
    stream.write_all(&b"hi"[..]).unwrap();
    stream.close_write().unwrap();
    let accepted = server.accept_stream().unwrap();
    assert_eq!(read_all_stream(&accepted), b"hi");
    accepted.close_with_error(42, "boom").unwrap();
    wait_for_read_abort(&stream, 42);

    let err = stream.write_all(&b"x"[..]).unwrap_err();
    assert_eq!(err.numeric_code(), Some(42));
    assert_eq!(err.reason(), Some("boom"));
    assert_eq!(err.termination_kind(), TerminationKind::Abort);
    assert_eq!(err.source(), ErrorSource::Remote);
    client.close().unwrap();
}

#[test]
fn write_after_local_abort_of_finished_send_half_reports_abort() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    let stream = client.open_stream().unwrap();
    stream.write_all(&b"hi"[..]).unwrap();
    stream.close_write().unwrap();
    let _accepted = server.accept_stream().unwrap();
    stream.close_with_error(43, "local").unwrap();

    let err = stream.write(b"x").unwrap_err();
    assert_eq!(err.numeric_code(), Some(43));
    assert_eq!(err.reason(), Some("local"));
    assert_eq!(err.termination_kind(), TerminationKind::Abort);
    assert_eq!(err.source(), ErrorSource::Local);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn write_after_abort_of_peer_stopped_send_half_reports_abort() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    let stream = client.open_stream().unwrap();
    stream.write_all(&b"hi"[..]).unwrap();
    let accepted = server.accept_stream().unwrap();
    accepted.cancel_read(77).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !stream.is_write_closed() {
        assert!(Instant::now() < deadline, "peer STOP_SENDING not observed");
        thread::sleep(Duration::from_millis(5));
    }
    stream.close_with_error(50, "").unwrap();

    let err = stream.write(b"x").unwrap_err();
    assert_eq!(err.numeric_code(), Some(50));
    assert_eq!(err.termination_kind(), TerminationKind::Abort);
    assert_eq!(err.source(), ErrorSource::Local);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

fn assert_large_write_round_trip(client_config: Config, server_settings: Settings, len: usize) {
    let server_config = Config {
        settings: server_settings,
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, server_config);
    let payload: Vec<u8> = (0..len).map(|idx| (idx % 251) as u8).collect();
    let expected = payload.clone();
    let reader = thread::spawn(move || {
        let mut stream = server
            .accept_stream_timeout(Duration::from_secs(5))
            .unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        (server, received)
    });
    let stream = client.open_stream().unwrap();
    stream
        .write_all_timeout(payload, Duration::from_secs(10))
        .unwrap();
    stream.close_write().unwrap();
    let (server, received) = reader.join().unwrap();
    assert_eq!(received.len(), expected.len());
    assert!(received == expected);
    assert!(!client.is_closed());
    assert!(!server.is_closed());
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn peer_max_frame_payload_above_queue_watermark_does_not_stall_writes() {
    let large_windows = Settings {
        max_frame_payload: 1 << 20,
        initial_max_data: 64 << 20,
        initial_max_stream_data_bidi_peer_opened: 16 << 20,
        ..Settings::default()
    };
    assert_large_write_round_trip(Config::default(), large_windows, 300 << 10);
    assert_large_write_round_trip(Config::default(), large_windows, 1 << 20);

    let default_windows = Settings {
        max_frame_payload: 1 << 20,
        ..Settings::default()
    };
    assert_large_write_round_trip(Config::default(), default_windows, 1 << 20);
    assert_large_write_round_trip(Config::default(), default_windows, 4 << 20);
}

#[test]
fn write_deadline_expiring_mid_burst_does_not_deadlock_session() {
    // A write deadline that expires after part of a burst was prepared rolls the
    // burst back; doing that while still holding the session lock re-locked it
    // and hung every session thread. The deadlines below land mid-burst.
    for attempt in 0..600u64 {
        let (client, server) = connected_pair(Config::default(), Config::default());
        let stream = client.open_stream().unwrap();
        let (tx, rx) = mpsc::channel();
        let timeout = Duration::from_micros(10 + 7 * (attempt % 60));
        thread::spawn(move || {
            let payload = vec![7u8; 200 << 10];
            let result = if attempt % 2 == 0 {
                stream.write_timeout(&payload, timeout)
            } else {
                let (head, tail) = payload.split_at(100 << 10);
                stream.write_vectored_timeout(&[IoSlice::new(head), IoSlice::new(tail)], timeout)
            };
            let _ = tx.send(result.map_err(|err| err.is_timeout()));
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(_) | Err(true)) => {}
            Ok(Err(false)) => panic!("attempt {attempt}: write failed with a non-timeout error"),
            Err(_) => {
                // Both sessions are wedged; do not block the test on their drop.
                std::mem::forget(client);
                std::mem::forget(server);
                panic!("attempt {attempt}: write_timeout deadlocked the session");
            }
        }
        assert!(!client.is_closed());
        client.stats();
        client
            .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
            .unwrap();
    }
}

#[test]
fn per_stream_queue_watermark_below_one_frame_still_admits_writes() {
    let client_config = Config {
        per_stream_queued_data_high_watermark: Some(4096),
        ..Config::default()
    };
    assert_large_write_round_trip(client_config, Settings::default(), 60_000);

    let client_config = Config {
        session_queued_data_high_watermark: Some(2048),
        ..Config::default()
    };
    assert_large_write_round_trip(client_config, Settings::default(), 60_000);
}

fn client_with_tiny_stream_window_peer() -> (Conn, RawPeer) {
    let peer_config = Config {
        settings: Settings {
            initial_max_stream_data_bidi_peer_opened: 4,
            ..Settings::default()
        },
        ..Config::responder()
    };
    client_with_raw_peer_configs(Config::default(), peer_config)
}

fn peer_stream_app_bytes(frames: &[Frame], stream_id: u64) -> Vec<u8> {
    stream_frame_summary(frames, stream_id)
        .into_iter()
        .filter(|(frame_type, _)| *frame_type == FrameType::Data)
        .flat_map(|(_, payload)| payload)
        .collect()
}

#[test]
fn credit_granted_while_writer_signals_blocked_is_not_missed() {
    // The peer grants 4 more bytes of stream credit as soon as it sees each DATA
    // frame, so grants race with the writer running out of credit and queueing
    // BLOCKED. A grant handled in between must still wake the writer; otherwise
    // both sides wait on each other until the write deadline.
    for round in 0..16 {
        let (client, mut peer) = client_with_tiny_stream_window_peer();
        let stream = client.open_stream().unwrap();
        let payload: Vec<u8> = (0..2048).map(|idx| (idx % 251) as u8).collect();
        let writer = {
            let stream = stream.clone();
            let payload = payload.clone();
            thread::spawn(move || {
                if round % 2 == 0 {
                    stream.write_all_timeout(payload, Duration::from_secs(5))?;
                } else {
                    let (head, tail) = payload.split_at(1000);
                    let parts = [IoSlice::new(head), IoSlice::new(tail)];
                    stream.write_all_timeout(&parts[..], Duration::from_secs(5))?;
                }
                stream.close_write()
            })
        };
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut received = Vec::new();
        let mut granted = 4u64;
        let mut fin = false;
        while !fin && Instant::now() < deadline {
            for frame in peer.drain_frames() {
                if frame.frame_type != FrameType::Data || frame.stream_id == 0 {
                    continue;
                }
                let data = parse_data_payload(&frame.payload, frame.flags).unwrap();
                received.extend_from_slice(&data.app_data);
                fin |= frame.flags & FRAME_FLAG_FIN != 0;
                if !data.app_data.is_empty() {
                    granted += 4;
                    peer.write_frame(Frame {
                        frame_type: FrameType::MaxData,
                        flags: 0,
                        stream_id: frame.stream_id,
                        payload: encode_varint(granted).unwrap(),
                    });
                }
            }
            thread::yield_now();
        }
        let result = writer.join().unwrap();
        assert!(
            result.is_ok(),
            "round {round}: writer stalled after {} bytes: {result:?}",
            received.len()
        );
        assert!(fin, "round {round}: FIN not observed");
        assert_eq!(received, payload);
        client
            .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
            .unwrap();
    }
}

#[test]
fn write_timeout_after_partial_progress_returns_written_count() {
    let (client, mut peer) = client_with_tiny_stream_window_peer();
    let stream = client.open_stream().unwrap();

    let n = stream
        .write_timeout(b"abcdefgh", Duration::from_millis(200))
        .unwrap();
    assert_eq!(n, 4);
    let err = stream
        .write_timeout(b"efgh", Duration::from_millis(50))
        .unwrap_err();
    assert!(err.is_timeout());
    let err = stream
        .write_all_timeout(&b"efgh"[..], Duration::from_millis(50))
        .unwrap_err();
    assert!(err.is_timeout());

    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert_eq!(peer_stream_app_bytes(&frames, stream.stream_id()), b"abcd");
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn vectored_and_std_writes_report_partial_progress() {
    let (client, mut peer) = client_with_tiny_stream_window_peer();
    let stream = client.open_stream().unwrap();
    let n = stream
        .write_vectored_timeout(
            &[IoSlice::new(b"ABC"), IoSlice::new(b"DEFGH")],
            Duration::from_millis(200),
        )
        .unwrap();
    assert_eq!(n, 4);
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert_eq!(peer_stream_app_bytes(&frames, stream.stream_id()), b"ABCD");

    let other = client.open_stream().unwrap();
    other
        .set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    assert_eq!(Write::write(&mut &other, b"wxyz1234").unwrap(), 4);
    let err = Write::write(&mut &other, b"1234").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    let frames = peer.collect_frames_for(Duration::from_millis(50));
    assert_eq!(peer_stream_app_bytes(&frames, other.stream_id()), b"wxyz");
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn buffered_writer_retry_after_write_timeout_does_not_duplicate_bytes() {
    let (client, mut peer) = client_with_tiny_stream_window_peer();
    let stream = client.open_stream().unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buffered = std::io::BufWriter::with_capacity(64, &stream);
    buffered.write_all(b"abcdefgh").unwrap();
    let err = buffered.flush().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

    let opener = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: opener.stream_id,
        payload: encode_varint(1000).unwrap(),
    });
    stream.set_write_timeout(None).unwrap();
    buffered.flush().unwrap();
    drop(buffered);

    let mut frames = vec![opener];
    frames.extend(peer.collect_frames_for(Duration::from_millis(100)));
    assert_eq!(
        peer_stream_app_bytes(&frames, stream.stream_id()),
        b"abcdefgh"
    );
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

fn transfer_bulk_one_way(client: &Conn, server: &Conn, total: usize, read_chunk: usize) {
    let stream = client.open_stream().unwrap();
    let writer = stream.clone();
    let write_thread = thread::spawn(move || {
        let chunk = vec![7u8; 64 * 1024];
        let mut sent = 0usize;
        while sent < total {
            let n = chunk.len().min(total - sent);
            writer.write_all(&chunk[..n])?;
            sent += n;
        }
        writer.close_write()
    });
    let accepted = server
        .accept_stream_timeout(Duration::from_secs(5))
        .unwrap();
    let mut buf = vec![0u8; read_chunk];
    let mut received = 0usize;
    loop {
        let n = accepted
            .read_timeout(&mut buf, Duration::from_secs(10))
            .unwrap_or_else(|err| {
                panic!(
                    "read failed after {received} bytes: {err}; client={:?} server={:?}",
                    client.state(),
                    server.state()
                )
            });
        if n == 0 {
            break;
        }
        received += n;
    }
    write_thread
        .join()
        .unwrap()
        .unwrap_or_else(|err| panic!("write failed: {err}"));
    assert_eq!(received, total);
    assert_ne!(client.state(), SessionState::Failed);
    assert_ne!(server.state(), SessionState::Failed);
}

struct HeldWriter {
    inner: MemoryConn,
    hold: Arc<(Mutex<bool>, Condvar)>,
}

impl Write for HeldWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let (held, cond) = &*self.hold;
        let mut held = held.lock().unwrap();
        while *held {
            held = cond.wait(held).unwrap();
        }
        drop(held);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn data_frame(stream_id: u64, flags: u8, payload: Vec<u8>) -> Frame {
    Frame {
        frame_type: FrameType::Data,
        flags,
        stream_id,
        payload,
    }
}

fn varint_frame(frame_type: FrameType, stream_id: u64, value: u64) -> Frame {
    Frame {
        frame_type,
        flags: 0,
        stream_id,
        payload: encode_varint(value).unwrap(),
    }
}

fn assert_peer_stream_round_trips(client: &Conn, peer: &mut RawPeer, stream_id: u64) {
    peer.write_frame(data_frame(stream_id, FRAME_FLAG_FIN, b"ping".to_vec()));
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(stream.stream_id(), stream_id);
    assert_eq!(read_all_stream(&stream), b"ping");
}

fn assert_no_frame_of_type(frames: &[Frame], frame_type: FrameType) {
    assert!(
        !frames.iter().any(|frame| frame.frame_type == frame_type),
        "unexpected {frame_type:?} in {frames:?}"
    );
}

fn wait_for_stats(
    conn: &Conn,
    mut done: impl FnMut(&zmux::SessionStats) -> bool,
) -> zmux::SessionStats {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let stats = conn.stats();
        if done(&stats) || Instant::now() >= deadline {
            return stats;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn close_read_tolerates_full_stream_window_of_in_flight_data() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let window = Settings::default().initial_max_stream_data_bidi_peer_opened;
    let frame_payload = usize::try_from(Settings::default().max_frame_payload).unwrap();

    peer.write_frame(data_frame(1, 0, Vec::new()));
    let stream = client.accept_stream().unwrap();
    stream.close_read().unwrap();
    let _ = peer
        .wait_for_frame(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1);
    let advertised_before = client.stats().pressure.recv_session_advertised_bytes;

    // The peer may legally have the whole stream window in flight when it sees
    // STOP_SENDING: four maximum-size frames with the default settings.
    for _ in 0..window / 16_384 {
        peer.write_frame(data_frame(1, 0, vec![7; frame_payload]));
    }
    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert_no_frame_of_type(&frames, FrameType::Abort);
    assert!(frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 1));
    assert_ne!(client.state(), SessionState::Failed);
    let stats = client.stats();
    assert_eq!(stats.pressure.recv_session_received_bytes, window);
    assert_eq!(
        stats.pressure.recv_session_advertised_bytes,
        advertised_before + window
    );
    assert_eq!(stats.diagnostics.late_data_after_close_read, window);

    // One byte beyond the stream credit is a stream flow-control violation, not a
    // session failure.
    peer.write_frame(data_frame(1, 0, vec![8]));
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    assert_no_frame_of_type(
        &peer.collect_frames_for(Duration::from_millis(50)),
        FrameType::Close,
    );
    assert_eq!(
        client.stats().pressure.recv_session_received_bytes,
        window + 1
    );

    assert_peer_stream_round_trips(&client, &mut peer, 5);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn local_abort_tolerates_full_stream_window_of_in_flight_data() {
    let (client, mut peer) = client_with_raw_peer(Config::default());
    let window = Settings::default().initial_max_stream_data_bidi_peer_opened;
    let frame_payload = usize::try_from(Settings::default().max_frame_payload).unwrap();

    peer.write_frame(data_frame(1, 0, Vec::new()));
    let stream = client.accept_stream().unwrap();
    stream
        .close_with_error(ErrorCode::Cancelled.as_u64(), "")
        .unwrap();
    let _ =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);

    for _ in 0..window / 16_384 {
        peer.write_frame(data_frame(1, 0, vec![7; frame_payload]));
    }
    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert!(frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert_ne!(client.state(), SessionState::Failed);
    assert_eq!(client.stats().diagnostics.late_data_after_abort, window);

    assert_peer_stream_round_trips(&client, &mut peer, 5);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

fn stop_or_abort_reader_during_in_flight_write(abort: bool) {
    // Hold the server's outbound frames so that its STOP_SENDING / ABORT cannot
    // reach the writer before a full stream window of DATA is in flight.
    let hold = Arc::new((Mutex::new(false), Condvar::new()));
    let (client_io, server_io) = memory_pair();
    let server_writer = HeldWriter {
        inner: server_io.clone(),
        hold: hold.clone(),
    };
    let client_thread =
        thread::spawn(move || Conn::client((client_io.clone(), client_io)).unwrap());
    let server_thread = thread::spawn(move || Conn::server((server_io, server_writer)).unwrap());
    let client = client_thread.join().unwrap();
    let server = server_thread.join().unwrap();

    let stream = client.open_stream().unwrap();
    stream.write_all(b"x").unwrap();
    let accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&accepted), b"x");

    *hold.0.lock().unwrap() = true;
    let stopper = thread::spawn(move || {
        if abort {
            accepted.close_with_error(ErrorCode::Cancelled.as_u64(), "")
        } else {
            accepted.close_read()
        }
    });
    let window = Settings::default().initial_max_stream_data_bidi_peer_opened;
    let tail = vec![5u8; usize::try_from(window - 1).unwrap()];
    stream
        .write_all_timeout(&tail[..], Duration::from_secs(1))
        .unwrap();
    let stats = wait_for_stats(&server, |stats| {
        stats.pressure.recv_session_received_bytes == window
    });
    assert_eq!(stats.pressure.recv_session_received_bytes, window);
    *hold.0.lock().unwrap() = false;
    hold.1.notify_all();
    stopper.join().unwrap().unwrap();

    thread::sleep(Duration::from_millis(50));
    assert_ne!(client.state(), SessionState::Failed);
    assert_ne!(server.state(), SessionState::Failed);
    let next = client.open_stream().unwrap();
    next.write_final(b"after").unwrap();
    let next_accepted = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_all_stream(&next_accepted), b"after");
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn close_read_during_in_flight_write_keeps_same_impl_session() {
    stop_or_abort_reader_during_in_flight_write(false);
}

#[test]
fn local_abort_during_in_flight_write_keeps_same_impl_session() {
    stop_or_abort_reader_during_in_flight_write(true);
}

fn close_read_cycle_with_late_tail_and_reset(client: &Conn, peer: &mut RawPeer, stream_id: u64) {
    peer.write_frame(data_frame(stream_id, 0, b"x".to_vec()));
    let stream = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(read_once_stream(&stream), b"x");
    stream.close_write().unwrap();
    stream.close_read().unwrap();
    let _ = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::StopSending && frame.stream_id == stream_id
    });
    peer.write_frame(data_frame(stream_id, 0, vec![9; 6000]));
    peer.write_frame(Frame {
        frame_type: FrameType::Reset,
        flags: 0,
        stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });
}

#[test]
fn repeated_close_read_late_tails_do_not_exhaust_aggregate_late_data_allowance() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    for i in 0..20u64 {
        close_read_cycle_with_late_tail_and_reset(&client, &mut peer, 1 + 4 * i);
        let stats = wait_for_stats(&client, |stats| {
            stats.diagnostics.late_data_after_close_read == 6000 * (i + 1)
        });
        assert_eq!(stats.diagnostics.late_data_after_close_read, 6000 * (i + 1));
        assert_ne!(client.state(), SessionState::Failed, "cycle {i}");
    }
    assert_no_frame_of_type(
        &peer.collect_frames_for(Duration::from_millis(50)),
        FrameType::Close,
    );
    assert_peer_stream_round_trips(&client, &mut peer, 81);
    client.close().unwrap();
}

#[test]
fn aggregate_late_data_counts_only_retained_late_tail_accounting() {
    let client_config = Config {
        tombstone_limit: 1,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    close_read_cycle_with_late_tail_and_reset(&client, &mut peer, 1);
    let stats = wait_for_stats(&client, |stats| stats.retention.tombstones == 1);
    assert_eq!(stats.retention.tombstones, 1);
    assert_eq!(stats.pressure.aggregate_late_data_bytes, 6000);

    // Compacting the second stream reaps the first tombstone and its accounting.
    close_read_cycle_with_late_tail_and_reset(&client, &mut peer, 5);
    let stats = wait_for_stats(&client, |stats| {
        stats.diagnostics.late_data_after_close_read == 12_000
            && stats.retention.marker_only_used_streams >= 1
    });
    assert_eq!(stats.diagnostics.late_data_after_close_read, 12_000);
    assert_eq!(stats.retention.tombstones, 1);
    assert_eq!(stats.pressure.aggregate_late_data_bytes, 6000);
    assert_ne!(client.state(), SessionState::Failed);
    client.close().unwrap();
}

#[test]
fn data_after_peer_fin_on_read_stopped_live_stream_aborts_stream_closed() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(data_frame(1, 0, b"a".to_vec()));
    let stream = client.accept_stream().unwrap();
    assert_eq!(read_once_stream(&stream), b"a");
    stream.close_read().unwrap();
    let _ = peer
        .wait_for_frame(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1);

    peer.write_frame(data_frame(1, FRAME_FLAG_FIN, b"x".to_vec()));
    peer.write_frame(data_frame(1, 0, b"late".to_vec()));
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamClosed.as_u64());

    client.close().ok();
}

#[test]
fn data_after_peer_fin_on_read_stopped_tombstone_aborts_stream_closed() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(data_frame(1, 0, b"a".to_vec()));
    let stream = client.accept_stream().unwrap();
    assert_eq!(read_once_stream(&stream), b"a");
    stream.close_write().unwrap();
    stream.close_read().unwrap();
    let _ = peer
        .wait_for_frame(|frame| frame.frame_type == FrameType::StopSending && frame.stream_id == 1);

    peer.write_frame(data_frame(1, FRAME_FLAG_FIN, b"x".to_vec()));
    let stats = wait_for_stats(&client, |stats| stats.retention.tombstones == 1);
    assert_eq!(stats.retention.tombstones, 1);

    peer.write_frame(data_frame(1, 0, b"late".to_vec()));
    let abort =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1);
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamClosed.as_u64());

    client.close().ok();
}

#[test]
fn data_after_fin_on_live_stream_releases_session_credit_without_late_data_caps() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(data_frame(1, FRAME_FLAG_FIN, b"a".to_vec()));
    let stream = client.accept_stream().unwrap();
    assert_eq!(read_all_stream(&stream), b"a");

    // Larger than the 8 KiB repository late-data figure: DATA after FIN is a
    // stream-state violation answered on the stream, not late data.
    peer.write_frame(data_frame(1, 0, vec![3; 9000]));
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let abort = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == 1)
        .expect("stream ABORT");
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamClosed.as_u64());
    assert!(frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0));
    assert_no_frame_of_type(&frames, FrameType::Close);
    let stats = client.stats();
    assert_eq!(stats.pressure.recv_session_received_bytes, 9001);
    assert_eq!(stats.pressure.aggregate_late_data_bytes, 0);
    assert_ne!(client.state(), SessionState::Failed);

    client.close().ok();
}

#[test]
fn data_after_fin_on_live_stream_still_obeys_session_flow_control() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 100,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(data_frame(1, FRAME_FLAG_FIN, b"a".to_vec()));
    // Left unread so that no session credit is released before the violation.
    let _stream = client.accept_stream().unwrap();

    peer.write_frame(data_frame(1, 0, vec![3; 150]));
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    assert!(reason.contains("session MAX_DATA"));
}

fn open_local_uni_stream_seen_by_peer(client: &Conn, peer: &mut RawPeer) -> u64 {
    let stream = client.open_uni_stream().unwrap();
    stream.write_all(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    assert_eq!(opened.stream_id, stream.stream_id());
    opened.stream_id
}

#[test]
fn wrong_direction_data_still_obeys_session_flow_control() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 1000,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream_id = open_local_uni_stream_seen_by_peer(&client, &mut peer);

    peer.write_frame(data_frame(stream_id, 0, vec![1; 1500]));
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    assert!(reason.contains("session MAX_DATA"));
}

#[test]
fn wrong_direction_data_releases_session_credit() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 1000,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream_id = open_local_uni_stream_seen_by_peer(&client, &mut peer);

    peer.write_frame(data_frame(stream_id, 0, vec![1; 100]));
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    let abort = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == stream_id)
        .expect("stream ABORT");
    let (code, _) = parse_error_payload(&abort.payload).unwrap();
    assert_eq!(code, ErrorCode::StreamState.as_u64());
    let max_data = frames
        .iter()
        .find(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0)
        .expect("session MAX_DATA");
    assert_eq!(parse_varint(&max_data.payload).unwrap().0, 1100);
    let stats = client.stats();
    assert_eq!(stats.pressure.recv_session_received_bytes, 100);
    assert_eq!(stats.pressure.aggregate_late_data_bytes, 0);

    // Later DATA on the aborted stream is ignored late data, still released.
    peer.write_frame(data_frame(stream_id, 0, vec![1; 10]));
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == stream_id));
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert_eq!(client.stats().pressure.recv_session_received_bytes, 110);

    client.close().ok();
}

#[test]
fn late_peer_abort_after_local_fin_and_peer_fin_preserves_unread_data() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(data_frame(1, FRAME_FLAG_FIN, b"hello".to_vec()));
    let stream = client.accept_stream().unwrap();
    stream.close_write().unwrap();
    let _ = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == 1
            && frame.flags & FRAME_FLAG_FIN != 0
    });
    let ignored_before = client.stats().abuse.ignored_control;

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });
    let stats = wait_for_stats(&client, |stats| {
        stats.abuse.ignored_control > ignored_before
    });
    assert!(stats.abuse.ignored_control > ignored_before);
    assert!(!stats
        .reasons
        .abort
        .contains_key(&ErrorCode::Cancelled.as_u64()));

    assert_eq!(read_all_stream(&stream), b"hello");
    let write_err = stream.write(b"x").unwrap_err();
    assert_ne!(write_err.termination_kind(), TerminationKind::Abort);
    assert_no_frame_of_type(
        &peer.collect_frames_for(Duration::from_millis(50)),
        FrameType::Abort,
    );

    client.close().ok();
}

#[test]
fn late_peer_abort_after_local_reset_and_peer_fin_keeps_terminal_errors() {
    let (client, mut peer) = client_with_raw_peer(Config::default());

    peer.write_frame(data_frame(1, FRAME_FLAG_FIN, b"hello".to_vec()));
    let stream = client.accept_stream().unwrap();
    stream.cancel_write(ErrorCode::Cancelled.as_u64()).unwrap();
    let _ =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::Reset && frame.stream_id == 1);
    let ignored_before = client.stats().abuse.ignored_control;

    peer.write_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: 1,
        payload: error_payload(ErrorCode::Internal.as_u64(), ""),
    });
    let stats = wait_for_stats(&client, |stats| {
        stats.abuse.ignored_control > ignored_before
    });
    assert!(stats.abuse.ignored_control > ignored_before);

    assert_eq!(read_all_stream(&stream), b"hello");
    let write_err = stream.write(b"x").unwrap_err();
    assert_eq!(write_err.termination_kind(), TerminationKind::Reset);
    assert_eq!(write_err.source(), ErrorSource::Local);

    client.close().ok();
}

#[test]
fn interleaved_data_does_not_reset_inbound_ping_budget() {
    let client_config = Config {
        inbound_ping_budget: 2,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(data_frame(1, 0, b"a".to_vec()));
    let _stream = client.accept_stream().unwrap();
    for payload in [b"ping-one".to_vec(), b"ping-two".to_vec()] {
        peer.write_frame(Frame {
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id: 0,
            payload,
        });
    }
    peer.write_frame(data_frame(1, 0, b"b".to_vec()));
    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: b"ping-thr".to_vec(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("inbound PING budget"));
}

#[test]
fn state_advancing_max_data_is_not_charged_to_inbound_control_budgets() {
    let client_config = Config {
        inbound_control_frame_budget: 4,
        inbound_mixed_frame_budget: Some(4),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write_all(b"x").unwrap();
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    let session_base = Settings::default().initial_max_data;
    let stream_base = Settings::default().initial_max_stream_data_bidi_peer_opened;
    for i in 1..=64u64 {
        peer.write_frame(varint_frame(FrameType::MaxData, 0, session_base + i));
        peer.write_frame(varint_frame(
            FrameType::MaxData,
            opened.stream_id,
            stream_base + i,
        ));
    }
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert_ne!(client.state(), SessionState::Failed);
    assert_eq!(client.stats().abuse.inbound_control_frames, 0);

    // MAX_DATA that does not raise a limit is still charged.
    for _ in 0..5 {
        peer.write_frame(varint_frame(FrameType::MaxData, 0, session_base));
    }
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("inbound control flood"), "{reason}");
}

#[test]
fn blocked_for_new_limits_is_not_charged_but_repeats_are() {
    let client_config = Config {
        inbound_control_frame_budget: 2,
        inbound_mixed_frame_budget: Some(2),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let window = Settings::default().initial_max_stream_data_bidi_peer_opened;

    peer.write_frame(data_frame(1, 0, vec![1; 16_384]));
    peer.write_frame(data_frame(1, 0, vec![1; 16_384]));
    let stream = client.accept_stream().unwrap();
    let mut buf = vec![0u8; 32 * 1024];
    stream
        .read_exact_timeout(&mut buf, Duration::from_secs(1))
        .unwrap();
    let _ =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 1);

    // The sender reports the limit it was blocked at; this report crossed the
    // grant above on the wire, so it is stale but still new information.
    peer.write_frame(varint_frame(FrameType::Blocked, 1, window));
    peer.write_frame(varint_frame(
        FrameType::Blocked,
        0,
        Settings::default().initial_max_data,
    ));
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_no_frame_of_type(&frames, FrameType::Close);
    let stats = client.stats();
    assert_eq!(stats.abuse.inbound_control_frames, 0);
    assert_eq!(stats.abuse.no_op_blocked, 0);

    for _ in 0..3 {
        peer.write_frame(varint_frame(FrameType::Blocked, 1, window));
    }
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("inbound control flood"), "{reason}");
}

#[test]
fn default_config_bulk_transfer_survives_replenish_and_blocked_rates() {
    let (client, server) = connected_pair(Config::default(), Config::default());
    transfer_bulk_one_way(&client, &server, 64 << 20, 16 * 1024);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn small_read_bulk_transfer_does_not_trip_tight_control_budgets() {
    let config = || Config {
        inbound_control_frame_budget: 16,
        inbound_mixed_frame_budget: Some(16),
        ignored_control_budget: 16,
        no_op_blocked_budget: 16,
        ..Config::default()
    };
    let (client, server) = connected_pair(config(), config());
    transfer_bulk_one_way(&client, &server, 8 << 20, 4 * 1024);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

fn zero_window_pair_round_trip(server_settings: Settings, uni: bool) {
    let server_config = Config {
        settings: server_settings,
        ..Config::default()
    };
    let (client, server) = connected_pair(Config::default(), server_config);
    let payload = b"0123456789";
    if uni {
        let stream = client.open_uni_stream().unwrap();
        let writer = thread::spawn(move || {
            stream.write_all_timeout(&payload[..], Duration::from_secs(2))?;
            stream.close_write()
        });
        let accepted = server
            .accept_uni_stream_timeout(Duration::from_secs(2))
            .unwrap();
        let mut buf = [0u8; 10];
        accepted
            .read_exact_timeout(&mut buf, Duration::from_secs(2))
            .unwrap();
        assert_eq!(&buf, payload);
        writer.join().unwrap().unwrap();
    } else {
        let stream = client.open_stream().unwrap();
        let writer = thread::spawn(move || {
            stream.write_all_timeout(&payload[..], Duration::from_secs(2))?;
            stream.close_write()
        });
        let accepted = server
            .accept_stream_timeout(Duration::from_secs(2))
            .unwrap();
        let mut buf = [0u8; 10];
        accepted
            .read_exact_timeout(&mut buf, Duration::from_secs(2))
            .unwrap();
        assert_eq!(&buf, payload);
        writer.join().unwrap().unwrap();
    }
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .unwrap();
}

#[test]
fn zero_initial_bidi_stream_window_is_granted_to_peer() {
    zero_window_pair_round_trip(
        Settings {
            initial_max_stream_data_bidi_peer_opened: 0,
            ..Settings::default()
        },
        false,
    );
}

#[test]
fn zero_initial_uni_stream_window_is_granted_to_peer() {
    zero_window_pair_round_trip(
        Settings {
            initial_max_stream_data_uni: 0,
            ..Settings::default()
        },
        true,
    );
}

#[test]
fn zero_initial_session_window_is_granted_to_peer() {
    zero_window_pair_round_trip(
        Settings {
            initial_max_data: 0,
            ..Settings::default()
        },
        false,
    );
}

fn zero_window_client(settings: Settings) -> (Conn, RawPeer) {
    client_with_raw_peer(Config {
        settings,
        ..Config::default()
    })
}

#[test]
fn peer_blocked_on_zero_stream_window_gets_stream_credit() {
    let (client, mut peer) = zero_window_client(Settings {
        initial_max_stream_data_bidi_peer_opened: 0,
        ..Settings::default()
    });

    peer.write_frame(data_frame(1, 0, Vec::new()));
    peer.write_frame(varint_frame(FrameType::Blocked, 1, 0));
    let max_data =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 1);
    assert!(parse_varint(&max_data.payload).unwrap().0 > 0);
    assert_eq!(client.stats().abuse.no_op_blocked, 0);

    client.close().ok();
}

#[test]
fn peer_blocked_on_zero_session_window_gets_session_credit() {
    let (client, mut peer) = zero_window_client(Settings {
        initial_max_data: 0,
        ..Settings::default()
    });

    peer.write_frame(data_frame(1, 0, Vec::new()));
    peer.write_frame(varint_frame(FrameType::Blocked, 0, 0));
    let max_data =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0);
    assert!(parse_varint(&max_data.payload).unwrap().0 > 0);
    assert_eq!(client.stats().abuse.no_op_blocked, 0);

    client.close().ok();
}

#[test]
fn reader_waiting_on_zero_stream_window_grants_credit_without_blocked() {
    let (client, mut peer) = zero_window_client(Settings {
        initial_max_stream_data_bidi_peer_opened: 0,
        ..Settings::default()
    });

    peer.write_frame(data_frame(1, 0, Vec::new()));
    let stream = client.accept_stream().unwrap();
    assert_no_frame_of_type(
        &peer.collect_frames_for(Duration::from_millis(50)),
        FrameType::MaxData,
    );
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4];
        stream.read_timeout(&mut buf, Duration::from_secs(1))
    });
    let max_data =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 1);
    assert!(parse_varint(&max_data.payload).unwrap().0 > 0);
    peer.write_frame(data_frame(1, 0, b"data".to_vec()));
    assert_eq!(reader.join().unwrap().unwrap(), 4);

    client.close().ok();
}

#[test]
fn accept_waiting_on_zero_session_window_grants_credit_without_blocked() {
    let (client, mut peer) = zero_window_client(Settings {
        initial_max_data: 0,
        ..Settings::default()
    });

    let Err(err) = client.accept_stream_timeout(Duration::from_millis(20)) else {
        panic!("no stream was opened");
    };
    assert!(err.is_timeout());
    let max_data =
        peer.wait_for_frame(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0);
    assert!(parse_varint(&max_data.payload).unwrap().0 > 0);

    client.close().ok();
}

#[test]
fn unread_full_stream_window_is_not_granted_on_blocked() {
    let (client, mut peer) = zero_window_client(Settings {
        initial_max_stream_data_bidi_peer_opened: 4,
        ..Settings::default()
    });

    peer.write_frame(data_frame(1, 0, b"abcd".to_vec()));
    let _stream = client.accept_stream().unwrap();
    peer.write_frame(varint_frame(FrameType::Blocked, 1, 4));
    // Unread data is released by the application's next read; until then the
    // full window is backpressure, not a stall that needs a grant.
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert!(!frames
        .iter()
        .any(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 1));

    client.close().ok();
}

fn error_frame(frame_type: FrameType, stream_id: u64, code: u64) -> Frame {
    Frame {
        frame_type,
        flags: 0,
        stream_id,
        payload: error_payload(code, ""),
    }
}

fn abort_codes_for(frames: &[Frame], stream_id: u64) -> Vec<u64> {
    frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::Abort && frame.stream_id == stream_id)
        .map(|frame| parse_error_payload(&frame.payload).unwrap().0)
        .collect()
}

fn max_session_max_data(frames: &[Frame]) -> Option<u64> {
    frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::MaxData && frame.stream_id == 0)
        .map(|frame| parse_varint(&frame.payload).unwrap().0)
        .max()
}

fn client_after_local_goaway(client_config: Config, peer_config: Config) -> (Conn, RawPeer) {
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    client.go_away(0, 0).unwrap();
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    (client, peer)
}

#[test]
fn goaway_refused_stream_ignores_racing_control_frames() {
    let (client, mut peer) = client_after_local_goaway(Config::default(), Config::responder());

    // The peer opened stream 1 and kept using it before it observed the GOAWAY
    // or the refusal; none of this is a frame on a previously unseen stream.
    peer.write_frame(data_frame(1, 0, vec![7; 1000]));
    peer.write_frame(error_frame(
        FrameType::StopSending,
        1,
        ErrorCode::Cancelled.as_u64(),
    ));
    peer.write_frame(varint_frame(
        FrameType::Blocked,
        1,
        Settings::default().initial_max_stream_data_bidi_peer_opened,
    ));
    peer.write_frame(varint_frame(FrameType::MaxData, 1, 1 << 20));
    peer.write_frame(error_frame(
        FrameType::Reset,
        1,
        ErrorCode::Cancelled.as_u64(),
    ));
    peer.write_frame(error_frame(
        FrameType::Abort,
        1,
        ErrorCode::Cancelled.as_u64(),
    ));

    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert_eq!(
        abort_codes_for(&frames, 1),
        vec![ErrorCode::RefusedStream.as_u64()]
    );
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert_eq!(client.state(), SessionState::Draining);
    let stats = client.stats();
    assert_eq!(stats.pressure.recv_session_received_bytes, 1000);
    assert_eq!(
        stats.reasons.abort.get(&ErrorCode::RefusedStream.as_u64()),
        Some(&1)
    );

    client.close().ok();
}

#[test]
fn goaway_refused_stream_data_is_credited_back_with_one_abort_per_id() {
    let (client, mut peer) = client_after_local_goaway(Config::default(), Config::responder());

    for _ in 0..3 {
        peer.write_frame(data_frame(1, 0, vec![7; 1000]));
    }
    peer.write_frame(data_frame(5, FRAME_FLAG_FIN, vec![7; 500]));
    peer.write_frame(data_frame(1, FRAME_FLAG_FIN, Vec::new()));

    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert_eq!(
        abort_codes_for(&frames, 1),
        vec![ErrorCode::RefusedStream.as_u64()]
    );
    assert_eq!(
        abort_codes_for(&frames, 5),
        vec![ErrorCode::RefusedStream.as_u64()]
    );
    assert_eq!(
        max_session_max_data(&frames),
        Some(Settings::default().initial_max_data + 3500)
    );
    assert_no_frame_of_type(&frames, FrameType::Close);
    let stats = client.stats();
    assert_eq!(stats.pressure.recv_session_received_bytes, 3500);
    assert_eq!(stats.pressure.aggregate_late_data_bytes, 0);
    assert_eq!(client.state(), SessionState::Draining);

    // Refused IDs are tracked per stream class.
    peer.write_frame(data_frame(3, 0, b"uni".to_vec()));
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        abort_codes_for(&frames, 3),
        vec![ErrorCode::RefusedStream.as_u64()]
    );

    client.close().ok();
}

#[test]
fn goaway_refused_stream_data_still_obeys_session_flow_control() {
    let client_config = Config {
        settings: Settings {
            initial_max_data: 1000,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (_client, mut peer) = client_after_local_goaway(client_config, Config::responder());

    peer.write_frame(data_frame(1, 0, vec![7; 1500]));
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    assert!(reason.contains("session MAX_DATA"));
}

#[test]
fn goaway_refused_opening_data_counts_only_application_bytes() {
    let caps = CAPABILITY_OPEN_METADATA;
    let (client, mut peer) = client_after_local_goaway(
        Config {
            capabilities: caps,
            ..Config::default()
        },
        Config {
            capabilities: caps,
            ..Config::responder()
        },
    );

    let mut payload = build_open_metadata_prefix(
        caps,
        None,
        None,
        b"open-info",
        Settings::default().max_frame_payload,
    )
    .unwrap();
    let prefix_len = payload.len();
    payload.extend_from_slice(&[9; 100]);
    peer.write_frame(data_frame(1, FRAME_FLAG_OPEN_METADATA, payload));

    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        abort_codes_for(&frames, 1),
        vec![ErrorCode::RefusedStream.as_u64()]
    );
    assert!(prefix_len > 0);
    assert_eq!(
        max_session_max_data(&frames),
        Some(Settings::default().initial_max_data + 100)
    );
    assert_eq!(client.stats().pressure.recv_session_received_bytes, 100);

    client.close().ok();
}

#[test]
fn goaway_refused_opening_data_with_truncated_metadata_len_fails_with_frame_size() {
    let caps = CAPABILITY_OPEN_METADATA;
    let (client, mut peer) = client_after_local_goaway(
        Config {
            capabilities: caps,
            ..Config::default()
        },
        Config {
            capabilities: caps,
            ..Config::responder()
        },
    );

    // The refusal may skip the metadata TLVs, but the metadata_len prefix has to
    // be decoded to find the application bytes (SPEC §8, §6.1).
    peer.write_raw_frame_parts(FrameType::Data, FRAME_FLAG_OPEN_METADATA, 5, &[0x40]);
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, _) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FrameSize.as_u64());
    wait_for_state(&client, SessionState::Failed);
}

#[test]
fn incoming_limit_refused_stream_ignores_late_data_and_credits_session() {
    let client_config = Config {
        settings: Settings {
            max_incoming_streams_bidi: 0,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for _ in 0..3 {
        peer.write_frame(data_frame(1, 0, vec![7; 1000]));
    }
    peer.write_frame(data_frame(1, 0, Vec::new()));

    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert_eq!(
        abort_codes_for(&frames, 1),
        vec![ErrorCode::RefusedStream.as_u64()]
    );
    assert_eq!(
        max_session_max_data(&frames),
        Some(Settings::default().initial_max_data + 3000)
    );
    assert_no_frame_of_type(&frames, FrameType::Close);
    let stats = client.stats();
    assert_eq!(stats.pressure.recv_session_received_bytes, 3000);
    // The opener itself is refused data, not late data; the frames behind it
    // are late data after the local ABORT.
    assert_eq!(stats.diagnostics.late_data_after_abort, 2000);
    assert_eq!(stats.accept_backlog.refused, 1);
    assert_eq!(client.state(), SessionState::Ready);

    client.close().ok();
}

#[test]
fn incoming_limit_refused_stream_with_many_in_flight_frames_aborts_once() {
    let client_config = Config {
        settings: Settings {
            max_incoming_streams_bidi: 0,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    for _ in 0..200 {
        peer.write_frame(data_frame(1, 0, vec![1]));
    }
    let frames = peer.collect_frames_for(Duration::from_millis(200));
    assert_eq!(
        abort_codes_for(&frames, 1),
        vec![ErrorCode::RefusedStream.as_u64()]
    );
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert_eq!(client.stats().pressure.recv_session_received_bytes, 200);
    assert_eq!(client.state(), SessionState::Ready);

    client.close().ok();
}

#[test]
fn accept_backlog_refused_stream_ignores_late_data_and_credits_session() {
    let client_config = Config {
        accept_backlog_limit: Some(1),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(data_frame(1, 0, b"queued".to_vec()));
    let stats = wait_for_stats(&client, |stats| stats.accept_backlog.bidi == 1);
    assert_eq!(stats.accept_backlog.bidi, 1);

    for _ in 0..3 {
        peer.write_frame(data_frame(5, 0, vec![7; 1000]));
    }
    let frames = peer.collect_frames_for(Duration::from_millis(150));
    assert_eq!(
        abort_codes_for(&frames, 5),
        vec![ErrorCode::RefusedStream.as_u64()]
    );
    assert!(abort_codes_for(&frames, 1).is_empty());
    assert_eq!(
        max_session_max_data(&frames),
        Some(Settings::default().initial_max_data + 3000)
    );
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert_eq!(client.stats().pressure.recv_session_received_bytes, 3006);

    let stream = client.accept_stream().unwrap();
    assert_eq!(stream.stream_id(), 1);
    client.close().ok();
}

#[test]
fn incoming_limit_refused_stream_late_data_allowance_covers_initial_window() {
    let client_config = Config {
        settings: Settings {
            max_incoming_streams_bidi: 0,
            initial_max_stream_data_bidi_peer_opened: 64,
            ..Settings::default()
        },
        late_data_per_stream_cap: Some(16),
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);

    // The peer may still send its whole initial stream window (64 bytes)
    // before it sees the refusal, even though the per-stream figure is 16.
    peer.write_frame(data_frame(1, 0, vec![1; 24]));
    peer.write_frame(data_frame(1, 0, vec![1; 40]));
    let frames = peer.collect_frames_for(Duration::from_millis(100));
    assert_eq!(
        abort_codes_for(&frames, 1),
        vec![ErrorCode::RefusedStream.as_u64()]
    );
    assert_no_frame_of_type(&frames, FrameType::Close);
    assert_eq!(client.state(), SessionState::Ready);

    // Beyond what a compliant peer could have in flight.
    peer.write_frame(data_frame(1, 0, vec![1]));
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert!(reason.contains("late-data cap"));
}

#[test]
fn refused_opener_data_still_obeys_session_flow_control() {
    let client_config = Config {
        settings: Settings {
            max_incoming_streams_bidi: 0,
            initial_max_data: 100,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (_client, mut peer) = client_with_raw_peer(client_config);

    peer.write_frame(data_frame(1, 0, vec![7; 1000]));
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, reason) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::FlowControl.as_u64());
    assert!(reason.contains("session MAX_DATA"));
}

#[test]
fn accept_backlog_refusals_do_not_leak_session_window() {
    let server_config = Config {
        accept_backlog_limit: Some(1),
        session_queued_data_high_watermark: Some(4096),
        settings: Settings {
            initial_max_data: 16_384,
            ..Settings::default()
        },
        ..Config::default()
    };
    let (client, server) = connected_pair(Config::default(), server_config);

    let first = client.open_stream().unwrap();
    first.write_all(b"x").unwrap();
    let stats = wait_for_stats(&server, |stats| stats.accept_backlog.bidi == 1);
    assert_eq!(stats.accept_backlog.bidi, 1);

    // Each opener is refused by the full accept backlog after the client has
    // irrevocably spent session credit on its 4 KiB payload.
    for _ in 0..3 {
        let refused = client.open_stream().unwrap();
        refused
            .write_all_timeout(&[7u8; 4096][..], Duration::from_secs(1))
            .unwrap();
    }
    let stats = wait_for_stats(&server, |stats| stats.accept_backlog.refused == 3);
    assert_eq!(stats.accept_backlog.refused, 3);

    let accepted = server.accept_stream().unwrap();
    assert_eq!(accepted.stream_id(), first.stream_id());
    // Without the refused bytes being released this needs more session credit
    // than the client has left.
    first
        .write_all_timeout(&[1u8; 8192][..], Duration::from_secs(2))
        .unwrap();
    let mut received = 0usize;
    let mut buf = [0u8; 4096];
    while received < 8193 {
        let n = accepted
            .read_timeout(&mut buf, Duration::from_secs(2))
            .unwrap();
        assert!(n > 0);
        received += n;
    }

    client.close().ok();
    server.close().ok();
}

fn finish_request_round_trip(opener: &Conn, acceptor: &Conn, abortive: bool) {
    let local = opener.open_stream().unwrap();
    if abortive {
        local.write_all(b"q").unwrap();
    } else {
        local.write_final(&b"q"[..]).unwrap();
    }
    let remote = acceptor
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(
        remote
            .read_timeout(&mut buf, Duration::from_secs(1))
            .unwrap(),
        1
    );
    if abortive {
        local
            .close_with_error(ErrorCode::Cancelled.as_u64(), "")
            .unwrap();
        let err = remote
            .read_timeout(&mut buf, Duration::from_secs(1))
            .unwrap_err();
        assert!(!err.is_timeout(), "{err:?}");
    } else {
        assert_eq!(read_all_stream(&remote), b"");
        remote.write_final(&b"r"[..]).unwrap();
        assert_eq!(read_all_stream(&local), b"r");
    }
}

#[test]
fn interleaved_stream_classes_keep_marker_retention_bounded() {
    let config = || Config {
        tombstone_limit: 4,
        marker_only_used_stream_limit: Some(16),
        ..Config::default()
    };
    let (client, server) = connected_pair(config(), config());

    // Both sides open bidi streams, so the two classes interleave in ID order,
    // and graceful and abortive closes alternate within each class.
    for i in 0..150 {
        finish_request_round_trip(&client, &server, i % 2 == 0);
        finish_request_round_trip(&server, &client, i % 3 == 0);
    }

    for conn in [&client, &server] {
        let stats = wait_for_stats(conn, |stats| stats.active_streams.total == 0);
        assert_eq!(conn.state(), SessionState::Ready);
        assert!(stats.retention.marker_only_used_streams <= 16, "{stats:?}");
        assert!(
            stats.retention.marker_only_used_stream_ranges <= 16,
            "{stats:?}"
        );
    }
    // The session keeps working after coarsening.
    finish_request_round_trip(&client, &server, false);
    finish_request_round_trip(&server, &client, false);

    client.close().unwrap();
    server.close().unwrap();
}

/// Gate for a client transport writer that can stall like a socket whose peer
/// stopped reading: a stalled write blocks until the transport is closed
/// through its control hook, which then fails the write.
struct StallGate {
    state: Mutex<StallGateState>,
    cond: Condvar,
}

#[derive(Default)]
struct StallGateState {
    stalled: bool,
    blocked: bool,
    closed: bool,
}

impl StallGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(StallGateState::default()),
            cond: Condvar::new(),
        })
    }

    fn stall(&self) {
        self.state.lock().unwrap().stalled = true;
    }

    fn wait_for(&self, timeout: Duration, mut done: impl FnMut(&StallGateState) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap();
        while !done(&state) {
            let Some(wait) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            state = self.cond.wait_timeout(state, wait).unwrap().0;
        }
        true
    }

    fn wait_blocked(&self, timeout: Duration) -> bool {
        self.wait_for(timeout, |state| state.blocked)
    }

    fn wait_closed(&self, timeout: Duration) -> bool {
        self.wait_for(timeout, |state| state.closed)
    }
}

struct StallableWriter {
    inner: MemoryConn,
    gate: Arc<StallGate>,
}

impl Write for StallableWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        {
            let mut state = self.gate.state.lock().unwrap();
            if state.stalled && !state.closed {
                state.blocked = true;
                self.gate.cond.notify_all();
                while !state.closed {
                    state = self.gate.cond.wait(state).unwrap();
                }
            }
            if state.closed {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct StallControl {
    gate: Arc<StallGate>,
    inbound: Arc<Queue>,
}

impl zmux::DuplexTransportControl for StallControl {
    fn close(&self) -> std::io::Result<()> {
        {
            let mut state = self.gate.state.lock().unwrap();
            state.closed = true;
            self.gate.cond.notify_all();
        }
        let mut inbound = self.inbound.state.lock().unwrap();
        inbound.closed = true;
        self.inbound.cond.notify_all();
        Ok(())
    }
}

fn client_with_stallable_raw_peer(client_config: Config) -> (Conn, RawPeer, Arc<StallGate>) {
    let (client_io, mut peer_io) = memory_pair();
    let gate = StallGate::new();
    let control = StallControl {
        gate: gate.clone(),
        inbound: client_io.inbound.clone(),
    };
    let client_read = client_io.clone();
    let client_write = StallableWriter {
        inner: client_io,
        gate: gate.clone(),
    };
    let transport = zmux::DuplexTransport::new(client_read, client_write).with_control(control);

    let client_thread =
        thread::spawn(move || Conn::client_with_config(transport, client_config).unwrap());
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = Config::responder().local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();

    (
        client_thread.join().unwrap(),
        RawPeer {
            io: peer_io,
            read_buf: Vec::new(),
        },
        gate,
    )
}

/// Starts an application write that the stalled transport writer never
/// completes and returns a receiver for its result.
fn start_stalled_write(stream: &zmux::Stream, gate: &StallGate) -> Receiver<zmux::Result<usize>> {
    gate.stall();
    let (tx, rx) = mpsc::channel();
    let writer = stream.clone();
    thread::spawn(move || {
        let _ = tx.send(writer.write(b"stalled"));
    });
    assert!(
        gate.wait_blocked(Duration::from_secs(1)),
        "writer did not stall"
    );
    rx
}

#[test]
fn close_with_error_closes_transport_when_writer_stalls() {
    let (client, mut peer, gate) = client_with_stallable_raw_peer(Config::default());
    let stream = client.open_stream().unwrap();
    stream.write(b"first").unwrap();
    peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    let write_result = start_stalled_write(&stream, &gate);

    let started = Instant::now();
    client.close_with_error(5, "x").unwrap();
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(client.state(), SessionState::Failed);

    // The CLOSE cannot be flushed; after the bounded close-frame wait the
    // transport is closed, which fails the stuck write and releases the writer.
    assert!(
        gate.wait_closed(Duration::from_secs(3)),
        "transport was never closed while the writer was stalled"
    );
    let write_err = write_result
        .recv_timeout(Duration::from_secs(3))
        .expect("stalled application write was not released")
        .unwrap_err();
    assert!(!write_err.is_timeout(), "{write_err:?}");

    let err = client.close_error().unwrap();
    assert_eq!(err.numeric_code(), Some(5));
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(client.stats().diagnostics.close_completion_timeouts, 1);
}

#[test]
fn graceful_close_closes_transport_when_writer_stalls() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(100),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer, gate) = client_with_stallable_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"first").unwrap();
    peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    let write_result = start_stalled_write(&stream, &gate);

    let started = Instant::now();
    let err = client.close().unwrap_err();
    assert!(err.to_string().contains("graceful close drain timed out"));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(client.state(), SessionState::Closed);
    assert!(
        gate.wait_closed(Duration::from_secs(3)),
        "transport was never closed while the writer was stalled"
    );
    assert!(write_result
        .recv_timeout(Duration::from_secs(3))
        .expect("stalled application write was not released")
        .is_err());
    // A graceful close keeps its graceful outcome despite the forced close.
    assert!(client.close_error().is_none());
}

#[test]
fn keepalive_timeout_fires_while_transport_write_is_stalled() {
    let client_config = Config {
        keepalive_interval: Duration::from_millis(200),
        keepalive_timeout: Duration::from_millis(300),
        ..Config::default()
    };
    let (client, _peer, gate) = client_with_stallable_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    // The writer blocks before the first keepalive PING is due, so the PING
    // can never reach the transport and the peer never answers anything.
    let write_result = start_stalled_write(&stream, &gate);

    let err = match client.wait_timeout(Duration::from_secs(3)) {
        Ok(closed) => panic!("session still open (closed={closed}) after keepalive timeout"),
        Err(err) => err,
    };
    assert_eq!(err.numeric_code(), Some(ErrorCode::IdleTimeout.as_u64()));
    assert_eq!(client.stats().diagnostics.keepalive_timeouts, 1);
    assert!(
        gate.wait_closed(Duration::from_secs(3)),
        "keepalive timeout did not close the stalled transport"
    );
    assert!(write_result
        .recv_timeout(Duration::from_secs(3))
        .expect("stalled application write was not released")
        .is_err());
}

#[test]
fn graceful_close_drain_delivers_peer_response_to_pending_request() {
    let client_config = Config {
        close_drain_timeout: Duration::from_millis(1500),
        ..Config::default()
    };
    let (client, server) = connected_pair(client_config, Config::default());
    let stream = client.open_stream().unwrap();
    stream.write_final(b"req").unwrap();
    let (response_read_tx, response_read_rx) = mpsc::channel();
    let server_thread = thread::spawn(move || {
        let accepted = server
            .accept_stream_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(read_all_stream(&accepted), b"req");
        thread::sleep(Duration::from_millis(200));
        assert_eq!(accepted.write(b"resp").unwrap(), 4);
        // Finish only after the client application has the response, so the
        // drain cannot end (and release the stream) before it is read.
        response_read_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        accepted.close_write().unwrap();
        server
    });
    let reader_stream = stream.clone();
    let reader = thread::spawn(move || {
        let mut response = [0u8; 4];
        let result = reader_stream.read_exact_timeout(&mut response, Duration::from_secs(2));
        let _ = response_read_tx.send(());
        result.map(|()| response)
    });

    let started = Instant::now();
    client.close().unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "graceful close waited out the drain timeout: {:?}",
        started.elapsed()
    );
    assert_eq!(&reader.join().unwrap().unwrap(), b"resp");
    assert_eq!(client.state(), SessionState::Closed);
    server_thread.join().unwrap().close().ok();
}

#[test]
fn graceful_close_drain_completes_when_peer_finishes_stream() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(2),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write_final(b"req").unwrap();
    let opened = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data && frame.flags & FRAME_FLAG_FIN != 0
    });

    let closer = client.clone();
    let started = Instant::now();
    let close_thread = thread::spawn(move || closer.close());
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: opened.stream_id,
        payload: b"resp".to_vec(),
    });
    // Peer data written during the drain reaches the application.
    let mut response = [0u8; 4];
    stream
        .read_exact_timeout(&mut response, Duration::from_secs(1))
        .unwrap();
    assert_eq!(&response, b"resp");
    assert_eq!(client.state(), SessionState::Draining);

    // The peer FIN makes the last blocking stream terminal and ends the drain.
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id: opened.stream_id,
        payload: Vec::new(),
    });
    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, _) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::NoError.as_u64());
    close_thread.join().unwrap().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn graceful_close_drain_refuses_peer_open_above_final_watermark() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(2),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let (client, mut peer) = client_with_raw_peer(client_config);
    let stream = client.open_stream().unwrap();
    stream.write(b"hold-open").unwrap();
    peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);

    let closer = client.clone();
    let close_thread = thread::spawn(move || closer.close());
    // No peer stream was accepted, so the final GOAWAY refuses every peer bidi ID.
    let _final = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::GoAway
            && parse_go_away_payload(&frame.payload)
                .unwrap()
                .last_accepted_bidi
                == 0
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"late open".to_vec(),
    });

    let reply = peer
        .wait_for_frame(|frame| matches!(frame.frame_type, FrameType::Abort | FrameType::Close));
    assert_eq!(reply.frame_type, FrameType::Abort);
    assert_eq!(reply.stream_id, 1);
    let (code, _) = parse_error_payload(&reply.payload).unwrap();
    assert_eq!(code, ErrorCode::RefusedStream.as_u64());
    assert_eq!(client.state(), SessionState::Draining);

    peer.write_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: error_payload(ErrorCode::NoError.as_u64(), ""),
    });
    let _ = close_thread.join().unwrap();
    assert_ne!(client.state(), SessionState::Failed);
}

#[test]
fn graceful_close_drain_delivers_peer_credit_to_blocked_writer() {
    let client_config = Config {
        close_drain_timeout: Duration::from_secs(2),
        go_away_drain_interval: Duration::ZERO,
        ..Config::default()
    };
    let peer_config = Config {
        settings: Settings {
            initial_max_stream_data_bidi_peer_opened: 16,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    let writer_stream = stream.clone();
    let writer = thread::spawn(move || writer_stream.write_final(&[7u8; 64][..]));
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    let stream_id = opened.stream_id;

    let closer = client.clone();
    let started = Instant::now();
    let close_thread = thread::spawn(move || closer.close());
    let _ = peer.wait_for_frame(|frame| frame.frame_type == FrameType::GoAway);
    // Credit granted during the drain reaches the blocked writer.
    peer.write_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id,
        payload: encode_varint(1024).unwrap(),
    });
    let _fin = peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data
            && frame.stream_id == stream_id
            && frame.flags & FRAME_FLAG_FIN != 0
    });
    assert_eq!(writer.join().unwrap().unwrap(), 64);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_FIN,
        stream_id,
        payload: Vec::new(),
    });

    let close = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Close);
    let (code, _) = parse_error_payload(&close.payload).unwrap();
    assert_eq!(code, ErrorCode::NoError.as_u64());
    close_thread.join().unwrap().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
}

fn go_away_watermarks(frames: &[Frame]) -> Vec<(u64, u64)> {
    frames
        .iter()
        .filter(|frame| frame.frame_type == FrameType::GoAway)
        .map(|frame| {
            let payload = parse_go_away_payload(&frame.payload).unwrap();
            (payload.last_accepted_bidi, payload.last_accepted_uni)
        })
        .collect()
}

fn assert_non_increasing_go_aways(watermarks: &[(u64, u64)]) {
    for pair in watermarks.windows(2) {
        assert!(
            pair[1].0 <= pair[0].0 && pair[1].1 <= pair[0].1,
            "GOAWAY watermarks increased on the wire: {watermarks:?}"
        );
    }
}

#[test]
fn concurrent_go_away_calls_keep_wire_watermarks_non_increasing() {
    // Watermarks of peer-opened (responder) streams, most permissive first.
    let requests: Vec<(u64, u64)> = (0..8u64)
        .map(|i| (4 * (200 - 20 * i) + 1, 4 * (200 - 20 * i) + 3))
        .chain([(5, 7)])
        .collect();
    for _ in 0..200 {
        let (client, mut peer) = client_with_raw_peer(Config::default());
        let barrier = Arc::new(Barrier::new(requests.len()));
        let callers: Vec<_> = requests
            .iter()
            .copied()
            .map(|(bidi, uni)| {
                let client = client.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    client.go_away(bidi, uni)
                })
            })
            .collect();
        for caller in callers {
            caller.join().unwrap().unwrap();
        }

        // Both calls returned after their GOAWAY (if any) was written.
        let watermarks = go_away_watermarks(&peer.drain_frames());
        assert!(!watermarks.is_empty());
        assert_non_increasing_go_aways(&watermarks);
        assert_eq!(watermarks.last(), Some(&(5, 7)));
        client.close_with_error(0, "").ok();
    }
}

#[test]
fn graceful_close_racing_go_away_keeps_wire_watermarks_non_increasing() {
    for _ in 0..60 {
        let client_config = Config {
            close_drain_timeout: Duration::from_millis(20),
            go_away_drain_interval: Duration::ZERO,
            ..Config::default()
        };
        let (client, mut peer) = client_with_raw_peer(client_config);
        let stream = client.open_stream().unwrap();
        stream.write(b"hold-open").unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let closer = {
            let client = client.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let _ = client.close();
            })
        };
        let go_away = {
            let client = client.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let _ = client.go_away(5, 7);
            })
        };
        closer.join().unwrap();
        go_away.join().unwrap();

        let frames = peer.collect_frames_for(Duration::from_millis(20));
        assert!(frames
            .iter()
            .any(|frame| frame.frame_type == FrameType::Close));
        assert_non_increasing_go_aways(&go_away_watermarks(&frames));
    }
}

#[test]
fn peer_stop_sending_does_not_stall_reader_behind_blocked_local_write() {
    let client_config = Config {
        stop_sending_graceful_drain_window: Some(Duration::from_millis(1500)),
        ..Config::default()
    };
    let peer_config = Config {
        settings: Settings {
            initial_max_stream_data_bidi_peer_opened: 16,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    let writer_stream = stream.clone();
    let writer = thread::spawn(move || writer_stream.write_all(&[7u8; 64][..]));
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    thread::sleep(Duration::from_millis(20));

    let started = Instant::now();
    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: b"liveness".to_vec(),
    });

    // The reader answers the PING without waiting out the drain window, and
    // the stopped send half ends at once (RESET, or FIN if it was immediate).
    let mut saw_pong = false;
    let mut saw_terminal = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !(saw_pong && saw_terminal) && Instant::now() < deadline {
        for frame in peer.drain_frames() {
            if frame.frame_type == FrameType::Pong {
                saw_pong = true;
            } else if frame.stream_id == opened.stream_id
                && (frame.frame_type == FrameType::Reset
                    || (frame.frame_type == FrameType::Data && frame.flags & FRAME_FLAG_FIN != 0))
            {
                saw_terminal = true;
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        saw_pong && saw_terminal,
        "pong={saw_pong} terminal={saw_terminal}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(1000),
        "reader stalled for {:?}",
        started.elapsed()
    );
    assert!(writer.join().unwrap().is_err());
    assert_eq!(client.state(), SessionState::Ready);
}

#[test]
fn peer_stop_sending_while_write_awaits_transport_does_not_stall_reader() {
    let (client_io, mut peer_io) = memory_pair();
    let client_read = client_io.clone();
    let (client_write, writer_gate) = blocking_writer(client_io, 1);
    let client_config = Config {
        stop_sending_graceful_drain_window: Some(Duration::from_millis(1500)),
        ..Config::default()
    };
    let client_thread = thread::spawn(move || {
        Conn::client_with_config((client_read, client_write), client_config).unwrap()
    });
    let _client_preface = read_preface(&mut peer_io).unwrap();
    let server_preface = Config::responder().local_preface().unwrap();
    peer_io
        .write_all(&server_preface.marshal().unwrap())
        .unwrap();
    peer_io.flush().unwrap();
    let client = client_thread.join().unwrap();
    let mut peer = RawPeer {
        io: peer_io,
        read_buf: Vec::new(),
    };

    // The application write holds the stream's write path while it waits for
    // the stuck transport write to complete.
    let stream = client.open_stream().unwrap();
    let writer_stream = stream.clone();
    let writer = thread::spawn(move || writer_stream.write(b"x"));
    writer_gate.wait_blocked();

    let started = Instant::now();
    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: stream.stream_id(),
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 1,
        payload: b"next".to_vec(),
    });
    // The reader must not wait out the STOP_SENDING drain window for the busy
    // write path before handling the next frame.
    let accepted = client
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(accepted.stream_id(), 1);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "reader stalled for {:?}",
        started.elapsed()
    );
    assert_eq!(client.state(), SessionState::Ready);

    writer_gate.release();
    let _ = writer.join().unwrap();
    let terminal = peer.wait_for_frame(|frame| {
        frame.stream_id == stream.stream_id()
            && (frame.frame_type == FrameType::Reset
                || (frame.frame_type == FrameType::Data && frame.flags & FRAME_FLAG_FIN != 0))
    });
    assert_eq!(terminal.frame_type, FrameType::Reset);
    client
        .close_with_error(ErrorCode::Cancelled.as_u64(), "test shutdown")
        .ok();
}

#[test]
fn local_abort_racing_peer_stop_sending_keeps_session_open() {
    let client_config = Config {
        stop_sending_graceful_drain_window: Some(Duration::from_millis(1500)),
        ..Config::default()
    };
    let peer_config = Config {
        settings: Settings {
            initial_max_stream_data_bidi_peer_opened: 16,
            ..Settings::default()
        },
        ..Config::responder()
    };
    let (client, mut peer) = client_with_raw_peer_configs(client_config, peer_config);
    let stream = client.open_stream().unwrap();
    let writer_stream = stream.clone();
    let writer = thread::spawn(move || writer_stream.write_all(&[7u8; 64][..]));
    let opened = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Data);
    thread::sleep(Duration::from_millis(20));

    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: opened.stream_id,
        payload: error_payload(ErrorCode::Cancelled.as_u64(), ""),
    });
    thread::sleep(Duration::from_millis(200));
    stream.close_with_error(0x77, "local abort").unwrap();
    let _ = writer.join().unwrap();

    // A stream-local race never escalates to a session CLOSE.
    let frames = peer.collect_frames_for(Duration::from_millis(300));
    assert!(
        !frames
            .iter()
            .any(|frame| frame.frame_type == FrameType::Close),
        "{frames:?}"
    );
    assert_eq!(client.state(), SessionState::Ready);
}

/// Accepts one TCP connection, reads the client preface, and sends a responder
/// preface in `chunk`-byte pieces with `delay` before each piece. The socket is
/// returned so it stays open until the test ends.
fn spawn_delayed_preface_server(
    delay: Duration,
    chunk: usize,
) -> (std::net::SocketAddr, thread::JoinHandle<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let _ = read_preface(&mut socket).unwrap();
        let preface = Config::responder()
            .local_preface()
            .unwrap()
            .marshal()
            .unwrap();
        for piece in preface.chunks(chunk) {
            thread::sleep(delay);
            if socket.write_all(piece).is_err() {
                break;
            }
        }
        socket
    });
    (addr, server)
}

#[test]
fn establishment_timeout_bounds_a_silent_tcp_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || listener.accept().unwrap().0);

    let started = Instant::now();
    let config = Config::default().establishment_timeout(Duration::from_millis(200));
    let err = match Conn::client_with_config(TcpStream::connect(addr).unwrap(), config) {
        Ok(_) => panic!("establishment with a silent peer unexpectedly succeeded"),
        Err(err) => err,
    };
    let elapsed = started.elapsed();
    // A real socket read timeout (WouldBlock on Unix) is reported as the
    // establishment timeout.
    assert!(err.is_timeout(), "{err:?}");
    assert_eq!(err.code(), Some(ErrorCode::Internal));
    assert_eq!(err.termination_kind(), TerminationKind::Timeout);
    assert!(err
        .to_string()
        .contains("peer preface read stalled during establishment"));
    assert!(elapsed >= Duration::from_millis(150), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    drop(server.join().unwrap());
}

#[test]
fn establishment_timeout_allows_a_slow_but_compliant_peer() {
    // Longer than the old fixed 1 s bound, inside the configured timeout.
    let (addr, server) = spawn_delayed_preface_server(Duration::from_millis(1300), usize::MAX);
    let config = Config::default().establishment_timeout(Duration::from_secs(3));
    let client = Conn::client_with_config(TcpStream::connect(addr).unwrap(), config).unwrap();
    assert_eq!(client.state(), SessionState::Ready);
    let _socket = server.join().unwrap();
    client.close_with_error(0, "").ok();
}

#[test]
fn establishment_timeout_bounds_the_whole_peer_preface() {
    // Every piece arrives well inside the timeout, but the whole preface does
    // not: the deadline covers the preface, not each read.
    let (addr, server) = spawn_delayed_preface_server(Duration::from_millis(120), 1);
    let config = Config::default().establishment_timeout(Duration::from_millis(500));
    let started = Instant::now();
    let err = match Conn::client_with_config(TcpStream::connect(addr).unwrap(), config) {
        Ok(_) => panic!("trickled preface unexpectedly established"),
        Err(err) => err,
    };
    assert!(err.is_timeout(), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(server.join().unwrap());
}

#[test]
fn write_discarded_by_peer_stop_sending_reports_the_stop() {
    let (client, mut peer, gate) = client_with_stallable_raw_peer(Config::default());
    let stopped = client.open_stream().unwrap();
    stopped.write(b"opened").unwrap();
    let stopped_id = stopped.stream_id();
    peer.wait_for_frame(|frame| {
        frame.frame_type == FrameType::Data && frame.stream_id == stopped_id
    });

    // Another stream's write wedges the transport writer, so the next write on
    // `stopped` stays queued while it holds that stream's write path.
    let other = client.open_stream().unwrap();
    let _stuck = start_stalled_write(&other, &gate);
    let (tx, rx) = mpsc::channel();
    let writer = stopped.clone();
    thread::spawn(move || {
        let _ = tx.send(writer.write(b"queued"));
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while client.stats().writer_queue.data_queued_bytes == 0 {
        assert!(Instant::now() < deadline, "write did not queue");
        thread::sleep(Duration::from_millis(1));
    }

    peer.write_frame(Frame {
        frame_type: FrameType::StopSending,
        flags: 0,
        stream_id: stopped_id,
        payload: error_payload(77, "peer stop"),
    });
    // The RESET answering the stop discards the queued write; the write reports
    // the peer's stop, not a bare local discard.
    let err = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("queued write was not released")
        .unwrap_err();
    assert_eq!(err.numeric_code(), Some(77), "{err:?}");
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.termination_kind(), TerminationKind::Stopped);
    assert_eq!(client.state(), SessionState::Ready);
    client.close_with_error(0, "").ok();
}

// Spec fixture runners: invalid_cases.ndjson cases driven against a live
// responder session by a raw initiator peer, asserting the fixture's
// expected_result (CLOSE / ABORT code or ignore) as it reaches the wire.

const INVALID_CASE_FIXTURES: &str = include_str!("../testdata/fixtures/invalid_cases.ndjson");
const WIRE_VALID_FIXTURES: &str = include_str!("../testdata/fixtures/wire_valid.ndjson");

fn fixture_cases(name: &str, content: &str) -> Vec<serde_json::Value> {
    serde_json::Deserializer::from_str(content)
        .into_iter::<serde_json::Value>()
        .map(|case| case.unwrap_or_else(|err| panic!("{name}: invalid JSON: {err}")))
        .collect()
}

fn fixture_hex(id: &str, hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "{id}: odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn shape_u64(id: &str, shape: &serde_json::Value, key: &str) -> u64 {
    shape[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{id}: input_shape.{key} missing"))
}

fn shape_str<'a>(id: &str, shape: &'a serde_json::Value, key: &str) -> &'a str {
    shape[key]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: input_shape.{key} missing"))
}

fn shape_usize(id: &str, shape: &serde_json::Value, key: &str) -> usize {
    u64_to_usize(shape_u64(id, shape, key))
}

fn frame_type_named(id: &str, name: &str) -> FrameType {
    [
        FrameType::Data,
        FrameType::MaxData,
        FrameType::StopSending,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::Blocked,
        FrameType::Reset,
        FrameType::Abort,
        FrameType::GoAway,
        FrameType::Close,
        FrameType::Ext,
    ]
    .into_iter()
    .find(|frame_type| frame_type.to_string() == name)
    .unwrap_or_else(|| panic!("{id}: unknown frame type {name:?}"))
}

fn raw_frame_bytes(frame_type: FrameType, flags: u8, stream_id: u64, payload: &[u8]) -> Vec<u8> {
    let stream_id = encode_varint(stream_id).unwrap();
    let mut raw = encode_varint(usize_to_u64(1 + stream_id.len() + payload.len())).unwrap();
    raw.push(frame_type.as_u8() | flags);
    raw.extend_from_slice(&stream_id);
    raw.extend_from_slice(payload);
    raw
}

/// Encodes `input_shape.stream_metadata_tlvs` ({type, value} or {type, value_hex}).
fn shape_metadata_tlvs(id: &str, shape: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    for tlv in shape["stream_metadata_tlvs"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: input_shape.stream_metadata_tlvs missing"))
    {
        let typ = match shape_str(id, tlv, "type") {
            "stream_priority" => METADATA_STREAM_PRIORITY,
            "stream_group" => zmux::METADATA_STREAM_GROUP,
            "open_info" => zmux::METADATA_OPEN_INFO,
            other => panic!("{id}: unknown metadata TLV {other:?}"),
        };
        let value = match (tlv["value"].as_u64(), tlv["value_hex"].as_str()) {
            (Some(value), None) => encode_varint(value).unwrap(),
            (None, Some(hex)) => fixture_hex(id, hex),
            _ => panic!("{id}: metadata TLV needs exactly one of value or value_hex"),
        };
        append_tlv(&mut out, typ, &value).unwrap();
    }
    out
}

/// The raw peer's capabilities for `input_shape.capabilities`: absent keeps the
/// defaults, `[]` negotiates nothing. A listed priority_update also enables
/// priority hints so an applied (or ignored) stream_priority is observable.
fn shape_peer_config(id: &str, shape: &serde_json::Value) -> Config {
    let Some(names) = shape.get("capabilities") else {
        return Config::initiator();
    };
    let names = names
        .as_array()
        .unwrap_or_else(|| panic!("{id}: input_shape.capabilities is not an array"));
    if names.is_empty() {
        return Config::initiator().disable_capabilities();
    }
    let mut capabilities = 0;
    for name in names {
        capabilities |= match name.as_str() {
            Some("open_metadata") => CAPABILITY_OPEN_METADATA,
            Some("priority_update") => CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS,
            Some("priority_hints") => CAPABILITY_PRIORITY_HINTS,
            Some("stream_groups") => CAPABILITY_STREAM_GROUPS,
            other => panic!("{id}: unknown capability {other:?}"),
        };
    }
    Config::initiator().capabilities(capabilities)
}

/// A responder session under test with a raw initiator peer. invalid_cases
/// fixtures describe peer-opened streams with initiator stream IDs (4, 8, ...),
/// so those IDs are used verbatim.
fn server_with_raw_peer(server_config: Config) -> (Conn, RawPeer) {
    server_with_raw_peer_configs(server_config, Config::initiator())
}

fn server_with_raw_peer_configs(server_config: Config, peer_config: Config) -> (Conn, RawPeer) {
    let (server_io, mut peer_io) = memory_pair();
    let server_read = server_io.clone();
    let server_write = server_io;

    let server_thread = thread::spawn(move || {
        Conn::server_with_config((server_read, server_write), server_config).unwrap()
    });
    let peer_preface = peer_config.local_preface().unwrap();
    peer_io.write_all(&peer_preface.marshal().unwrap()).unwrap();
    peer_io.flush().unwrap();
    let _server_preface = read_preface(&mut peer_io).unwrap();

    (
        server_thread.join().unwrap(),
        RawPeer {
            io: peer_io,
            read_buf: Vec::new(),
        },
    )
}

fn open_raw_peer_stream(
    server: &Conn,
    peer: &mut RawPeer,
    stream_id: u64,
    flags: u8,
) -> zmux::Stream {
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags,
        stream_id,
        payload: b"hi".to_vec(),
    });
    let stream = server
        .accept_stream_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(stream.stream_id(), stream_id);
    stream
}

/// What an invalid_cases.ndjson fixture expects from the receiving session.
#[derive(Debug)]
enum InvalidCaseExpectation {
    /// CLOSE(code) on the wire and a failed session.
    Session(ErrorCode),
    /// ABORT(code) on the offending stream while the session stays open.
    Stream(ErrorCode),
    /// No ABORT or CLOSE: the frame, or its metadata block, is ignored.
    Ignore,
    /// A local send policy rejects the operation before anything is written.
    ForbidSend,
}

fn invalid_case_expectation(id: &str, case: &serde_json::Value) -> InvalidCaseExpectation {
    let expected = &case["expected_result"];
    if let Some(name) = expected["error"].as_str() {
        let code = (0..=u64::from(u8::MAX))
            .filter_map(ErrorCode::from_u64)
            .find(|code| code.as_str() == name)
            .unwrap_or_else(|| panic!("{id}: unknown error code {name:?}"));
        return match expected["scope"].as_str() {
            Some("session") => InvalidCaseExpectation::Session(code),
            Some("stream") => InvalidCaseExpectation::Stream(code),
            other => panic!("{id}: unexpected error scope {other:?}"),
        };
    }
    match expected["action"].as_str() {
        Some("ignore" | "ignore_entire_update_payload" | "ignore_entire_open_metadata_block") => {
            InvalidCaseExpectation::Ignore
        }
        Some("forbid_send") => InvalidCaseExpectation::ForbidSend,
        other => panic!("{id}: unsupported expected action {other:?}"),
    }
}

/// The PONG proves the session handled every earlier frame and is still open;
/// no ABORT or CLOSE may precede it.
fn assert_raw_peer_session_survives(id: &str, server: &Conn, peer: &mut RawPeer) {
    let token = b"fixture!".to_vec();
    peer.write_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        payload: token.clone(),
    });
    let frame = peer.wait_for_frame(|frame| {
        matches!(
            frame.frame_type,
            FrameType::Pong | FrameType::Abort | FrameType::Close
        )
    });
    assert_eq!(frame.frame_type, FrameType::Pong, "{id}: {frame:?}");
    assert_eq!(frame.payload, token, "{id}");
    assert_eq!(server.state(), SessionState::Ready, "{id}");
}

fn assert_invalid_case_outcome(
    id: &str,
    expected: &InvalidCaseExpectation,
    server: &Conn,
    peer: &mut RawPeer,
    stream_id: u64,
) {
    match *expected {
        InvalidCaseExpectation::Session(code) => {
            let _ = assert_peer_receives_fatal_close(server, peer, code, id);
        }
        InvalidCaseExpectation::Stream(code) => {
            let frame = peer.wait_for_frame(|frame| {
                frame.frame_type == FrameType::Close
                    || (frame.frame_type == FrameType::Abort && frame.stream_id == stream_id)
            });
            assert_eq!(frame.frame_type, FrameType::Abort, "{id}: {frame:?}");
            let (got, reason) = parse_error_payload(&frame.payload).unwrap();
            assert_eq!(got, code.as_u64(), "{id}: ABORT reason {reason:?}");
            assert_raw_peer_session_survives(id, server, peer);
        }
        InvalidCaseExpectation::Ignore => assert_raw_peer_session_survives(id, server, peer),
        InvalidCaseExpectation::ForbidSend => {
            panic!("{id}: a local send policy is not a peer input")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvalidCaseGroup {
    /// Malformed frames the reader rejects before any stream state applies.
    MalformedFrame,
    /// A non-opening frame is the first frame on a never-opened peer stream.
    FirstFrameOnUnusedStream,
    /// PRIORITY_UPDATE and unknown EXT subtypes.
    Ext,
    OpenMetadata,
    FlowControl,
    /// Wrong-side uni frames, peer stream ID gaps and GOAWAY watermarks.
    StreamState,
    LocalSendPolicy,
}

fn invalid_case_group(id: &str) -> Option<InvalidCaseGroup> {
    use InvalidCaseGroup::{
        Ext, FirstFrameOnUnusedStream, FlowControl, LocalSendPolicy, MalformedFrame, OpenMetadata,
        StreamState,
    };
    Some(match id {
        "frame_length_too_small"
        | "frame_length_smaller_than_stream_id_prefix"
        | "frame_ext_payload_underflow"
        | "frame_ping_with_forbidden_fin_flag"
        | "frame_pong_too_short"
        | "frame_abort_on_stream_zero"
        | "frame_max_data_trailing_garbage"
        | "frame_blocked_trailing_garbage"
        | "frame_unknown_core_type" => MalformedFrame,
        "frame_first_max_data_on_unused_stream"
        | "frame_first_blocked_on_unused_stream"
        | "frame_first_stop_sending_on_unused_stream"
        | "frame_first_reset_on_unused_stream" => FirstFrameOnUnusedStream,
        "frame_priority_update_duplicate_singleton"
        | "frame_priority_update_truncated_tlv_header"
        | "frame_priority_update_tlv_value_overrun"
        | "frame_priority_update_noncanonical_value"
        | "frame_priority_update_without_capability"
        | "frame_priority_update_on_unused_stream"
        | "frame_priority_update_on_terminal_stream"
        | "frame_unknown_ext_subtype" => Ext,
        "frame_data_open_metadata_without_capability"
        | "frame_data_open_metadata_on_open_stream"
        | "frame_data_open_metadata_duplicate_singleton" => OpenMetadata,
        "frame_data_exceeds_stream_max_data" | "frame_data_exceeds_session_max_data" => FlowControl,
        "frame_peer_stream_id_gap"
        | "frame_blocked_wrong_side_uni"
        | "frame_data_wrong_side_uni"
        | "frame_max_data_wrong_side_uni"
        | "frame_stop_sending_wrong_side_uni"
        | "frame_reset_wrong_side_uni"
        | "session_goaway_last_accepted_increase" => StreamState,
        "frame_ping_payload_exceeds_local_echoable_limit" => LocalSendPolicy,
        _ => return None,
    })
}

/// invalid_cases fixtures this runner deliberately does not drive: they are
/// local retention/churn policies rather than one peer input. preface_* cases
/// are checked by tests/codec_fixtures.rs (parse and negotiation).
const INVALID_CASES_NOT_DRIVEN_BY_RAW_PEER: &[&str] = &[
    "local_provisional_open_cancel_must_not_burn_stream_id",
    "hidden_control_opened_stream_exceeds_hard_cap_without_shedding",
    "late_data_after_close_read_exceeds_session_aggregate_cap",
    "rapid_open_abort_churn_without_local_limit",
];

fn run_invalid_case_group(group: InvalidCaseGroup) {
    let mut ran = 0usize;
    for case in fixture_cases("invalid_cases.ndjson", INVALID_CASE_FIXTURES) {
        let id = case["id"].as_str().unwrap();
        if invalid_case_group(id) != Some(group) {
            continue;
        }
        let expected = invalid_case_expectation(id, &case);
        let shape = &case["input_shape"];
        match group {
            InvalidCaseGroup::MalformedFrame => run_malformed_frame_case(id, &case, &expected),
            InvalidCaseGroup::FirstFrameOnUnusedStream => {
                run_first_frame_on_unused_stream_case(id, shape, &expected);
            }
            InvalidCaseGroup::Ext => run_ext_case(id, shape, &expected),
            InvalidCaseGroup::OpenMetadata => run_open_metadata_case(id, shape, &expected),
            InvalidCaseGroup::FlowControl => run_flow_control_case(id, shape, &expected),
            InvalidCaseGroup::StreamState => run_stream_state_case(id, shape, &expected),
            InvalidCaseGroup::LocalSendPolicy => run_ping_send_policy_case(id, shape, &expected),
        }
        ran += 1;
    }
    assert!(ran > 0, "{group:?}: no invalid_cases fixtures");
}

fn run_malformed_frame_case(id: &str, case: &serde_json::Value, expected: &InvalidCaseExpectation) {
    let shape = &case["input_shape"];
    let raw = if let Some(hex) = case["hex"].as_str() {
        fixture_hex(id, hex)
    } else {
        match id {
            "frame_length_too_small" => {
                let mut raw = encode_varint(shape_u64(id, shape, "frame_length")).unwrap();
                raw.push(FrameType::Data.as_u8());
                raw
            }
            "frame_length_smaller_than_stream_id_prefix" => {
                let stream_id = match shape_u64(id, shape, "stream_id_encoding_length") {
                    2 => 1 << 6,
                    4 => 1 << 14,
                    8 => 1 << 30,
                    other => panic!("{id}: unsupported stream_id_encoding_length {other}"),
                };
                let mut raw = encode_varint(shape_u64(id, shape, "frame_length")).unwrap();
                raw.push(FrameType::Data.as_u8());
                raw.extend(encode_varint(stream_id).unwrap());
                raw
            }
            "frame_ext_payload_underflow" => raw_frame_bytes(FrameType::Ext, 0, 0, &[]),
            "frame_pong_too_short" => {
                let payload: Vec<u8> = (1..=shape_usize(id, shape, "payload_len"))
                    .map(|byte| byte as u8)
                    .collect();
                raw_frame_bytes(FrameType::Pong, 0, 0, &payload)
            }
            "frame_abort_on_stream_zero" => raw_frame_bytes(
                FrameType::Abort,
                0,
                shape_u64(id, shape, "stream_id"),
                &encode_varint(ErrorCode::Cancelled.as_u64()).unwrap(),
            ),
            "frame_max_data_trailing_garbage" | "frame_blocked_trailing_garbage" => {
                assert_eq!(
                    shape_str(id, shape, "payload_shape"),
                    "canonical_varint_plus_trailing_bytes"
                );
                raw_frame_bytes(
                    frame_type_named(id, shape_str(id, shape, "frame_type")),
                    0,
                    shape_u64(id, shape, "stream_id"),
                    &[0x05, 0x01],
                )
            }
            other => panic!("{other}: no malformed-frame bytes"),
        }
    };

    let (server, mut peer) = server_with_raw_peer(Config::default());
    peer.io.write_all(&raw).unwrap();
    peer.io.flush().unwrap();
    assert_invalid_case_outcome(id, expected, &server, &mut peer, 0);
}

fn run_first_frame_on_unused_stream_case(
    id: &str,
    shape: &serde_json::Value,
    expected: &InvalidCaseExpectation,
) {
    assert_eq!(shape_str(id, shape, "initial_stream_state"), "idle");
    let stream_id = shape_u64(id, shape, "stream_id");
    let frame_type = frame_type_named(id, shape_str(id, shape, "incoming_frame"));
    let payload = match frame_type {
        FrameType::MaxData | FrameType::Blocked => encode_varint(1024).unwrap(),
        _ => error_payload(ErrorCode::Cancelled.as_u64(), ""),
    };

    let (server, mut peer) = server_with_raw_peer(Config::default());
    peer.write_frame(Frame {
        frame_type,
        flags: 0,
        stream_id,
        payload,
    });
    assert_invalid_case_outcome(id, expected, &server, &mut peer, stream_id);
    assert!(server
        .accept_stream_timeout(Duration::from_millis(10))
        .is_err());
}

fn run_ext_case(id: &str, shape: &serde_json::Value, expected: &InvalidCaseExpectation) {
    let stream_id = shape_u64(id, shape, "stream_id");
    let (server, mut peer) =
        server_with_raw_peer_configs(Config::default(), shape_peer_config(id, shape));

    let stream = match id {
        "frame_unknown_ext_subtype" | "frame_priority_update_on_unused_stream" => None,
        "frame_priority_update_on_terminal_stream" => {
            assert_eq!(shape_str(id, shape, "stream_state"), "terminal");
            let stream = open_raw_peer_stream(&server, &mut peer, stream_id, FRAME_FLAG_FIN);
            assert_eq!(read_all_stream(&stream), b"hi");
            stream.close_write().unwrap();
            peer.wait_for_frame(|frame| {
                frame.frame_type == FrameType::Data
                    && frame.stream_id == stream_id
                    && frame.flags & FRAME_FLAG_FIN != 0
            });
            Some(stream)
        }
        _ => Some(open_raw_peer_stream(&server, &mut peer, stream_id, 0)),
    };
    if id == "frame_priority_update_on_unused_stream" {
        assert_eq!(shape["stream_exists"].as_bool(), Some(false));
    }

    let payload = if id == "frame_unknown_ext_subtype" {
        encode_varint(shape_u64(id, shape, "ext_type")).unwrap()
    } else {
        assert_eq!(shape_str(id, shape, "ext_type"), "PRIORITY_UPDATE");
        let mut payload = encode_varint(EXT_PRIORITY_UPDATE).unwrap();
        match shape["payload_shape"].as_str() {
            Some("truncated_stream_hint_tlv_header") => {
                payload.push(METADATA_STREAM_PRIORITY as u8);
            }
            Some("stream_hint_tlv_value_overrun") => {
                payload.extend_from_slice(&[METADATA_STREAM_PRIORITY as u8, 0x02, 0x01]);
            }
            Some(other) => panic!("{id}: unknown payload_shape {other:?}"),
            None if shape.get("stream_metadata_tlvs").is_some() => {
                payload.extend(shape_metadata_tlvs(id, shape));
            }
            None => append_tlv(&mut payload, METADATA_STREAM_PRIORITY, &[0x07]).unwrap(),
        }
        payload
    };
    peer.write_raw_frame_parts(FrameType::Ext, 0, stream_id, &payload);
    assert_invalid_case_outcome(id, expected, &server, &mut peer, stream_id);

    if matches!(expected, InvalidCaseExpectation::Ignore) {
        if let Some(stream) = stream {
            assert_eq!(
                stream.metadata().priority,
                None,
                "{id}: an ignored PRIORITY_UPDATE must not change the stream"
            );
        } else {
            assert!(
                server
                    .accept_stream_timeout(Duration::from_millis(10))
                    .is_err(),
                "{id}: an ignored EXT must not open a stream"
            );
        }
    }
}

fn run_open_metadata_case(id: &str, shape: &serde_json::Value, expected: &InvalidCaseExpectation) {
    let stream_id = shape_u64(id, shape, "stream_id");
    let (server, mut peer) =
        server_with_raw_peer_configs(Config::default(), shape_peer_config(id, shape));
    let _existing = (shape["stream_exists"].as_bool() == Some(true))
        .then(|| open_raw_peer_stream(&server, &mut peer, stream_id, 0));

    let (tlvs, app_data) = if shape.get("stream_metadata_tlvs").is_some() {
        let app_hex = shape_str(id, shape, "application_payload_hex");
        (shape_metadata_tlvs(id, shape), fixture_hex(id, app_hex))
    } else {
        let mut tlvs = Vec::new();
        append_tlv(&mut tlvs, zmux::METADATA_OPEN_INFO, b"x").unwrap();
        (tlvs, b"hi".to_vec())
    };
    let mut payload = encode_varint(usize_to_u64(tlvs.len())).unwrap();
    payload.extend(tlvs);
    payload.extend_from_slice(&app_data);
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: FRAME_FLAG_OPEN_METADATA,
        stream_id,
        payload,
    });
    assert_invalid_case_outcome(id, expected, &server, &mut peer, stream_id);

    if matches!(expected, InvalidCaseExpectation::Ignore) {
        // The whole metadata block is dropped; the stream still opens and
        // delivers its application bytes.
        let stream = server
            .accept_stream_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(stream.stream_id(), stream_id);
        assert!(stream.open_info().is_empty(), "{id}");
        let metadata = stream.metadata();
        assert_eq!((metadata.priority, metadata.group), (None, None), "{id}");
        assert_eq!(read_once_stream(&stream), app_data, "{id}");
    }
}

fn run_flow_control_case(id: &str, shape: &serde_json::Value, expected: &InvalidCaseExpectation) {
    let stream_id = shape_u64(id, shape, "stream_id");
    let mut settings = Settings::default();
    let received = match id {
        "frame_data_exceeds_stream_max_data" => {
            settings.initial_max_stream_data_bidi_peer_opened =
                shape_u64(id, shape, "peer_stream_max_data");
            shape_usize(id, shape, "stream_bytes_received")
        }
        "frame_data_exceeds_session_max_data" => {
            settings.initial_max_data = shape_u64(id, shape, "peer_session_max_data");
            shape_usize(id, shape, "session_bytes_received")
        }
        other => panic!("{other}: not a flow-control fixture"),
    };

    let (server, mut peer) = server_with_raw_peer(Config {
        settings,
        ..Config::default()
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id,
        payload: vec![b'a'; received],
    });
    peer.write_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id,
        payload: vec![b'b'; shape_usize(id, shape, "incoming_data_length")],
    });
    assert_invalid_case_outcome(id, expected, &server, &mut peer, stream_id);
}

fn run_stream_state_case(id: &str, shape: &serde_json::Value, expected: &InvalidCaseExpectation) {
    let (server, mut peer) = server_with_raw_peer(Config::default());
    match id {
        "frame_peer_stream_id_gap" => {
            // A fresh responder expects the first initiator-owned bidi ID.
            assert_eq!(shape_u64(id, shape, "expected_next_stream_id"), 4);
            let stream_id = shape_u64(id, shape, "incoming_stream_id");
            peer.write_frame(Frame {
                frame_type: frame_type_named(id, shape_str(id, shape, "incoming_frame")),
                flags: 0,
                stream_id,
                payload: b"hi".to_vec(),
            });
            assert_invalid_case_outcome(id, expected, &server, &mut peer, stream_id);
        }
        "session_goaway_last_accepted_increase" => {
            for (bidi, uni) in [
                (
                    "prior_last_accepted_bidi_stream_id",
                    "prior_last_accepted_uni_stream_id",
                ),
                (
                    "incoming_last_accepted_bidi_stream_id",
                    "incoming_last_accepted_uni_stream_id",
                ),
            ] {
                peer.write_frame(Frame {
                    frame_type: FrameType::GoAway,
                    flags: 0,
                    stream_id: 0,
                    payload: build_go_away_payload(
                        shape_u64(id, shape, bidi),
                        shape_u64(id, shape, uni),
                        ErrorCode::NoError.as_u64(),
                        "",
                    )
                    .unwrap(),
                });
            }
            assert_invalid_case_outcome(id, expected, &server, &mut peer, 0);
        }
        _ => {
            let frame_type = frame_type_named(id, shape_str(id, shape, "incoming_frame"));
            let mut _send = None;
            let mut _recv = None;
            let stream_id = match shape_str(id, shape, "stream_kind") {
                "uni_local_send_only" => {
                    let send = server.open_uni_stream().unwrap();
                    send.write(b"x").unwrap();
                    let stream_id = send.stream_id();
                    peer.wait_for_frame(|frame| {
                        frame.frame_type == FrameType::Data && frame.stream_id == stream_id
                    });
                    _send = Some(send);
                    stream_id
                }
                "uni_local_receive_only" => {
                    // The first initiator-owned uni stream.
                    peer.write_frame(Frame {
                        frame_type: FrameType::Data,
                        flags: 0,
                        stream_id: 2,
                        payload: b"x".to_vec(),
                    });
                    let recv = server
                        .accept_uni_stream_timeout(Duration::from_secs(1))
                        .unwrap();
                    let stream_id = recv.stream_id();
                    _recv = Some(recv);
                    stream_id
                }
                other => panic!("{id}: unknown stream_kind {other:?}"),
            };
            let payload = match frame_type {
                FrameType::MaxData | FrameType::Blocked => encode_varint(1024).unwrap(),
                FrameType::Data => b"wrong-way".to_vec(),
                _ => error_payload(ErrorCode::Cancelled.as_u64(), ""),
            };
            peer.write_frame(Frame {
                frame_type,
                flags: 0,
                stream_id,
                payload,
            });
            assert_invalid_case_outcome(id, expected, &server, &mut peer, stream_id);
        }
    }
}

fn run_ping_send_policy_case(
    id: &str,
    shape: &serde_json::Value,
    expected: &InvalidCaseExpectation,
) {
    assert!(
        matches!(expected, InvalidCaseExpectation::ForbidSend),
        "{id}: {expected:?}"
    );
    let (server, mut peer) = server_with_raw_peer_configs(
        config_with_control_limit(
            Config::default(),
            shape_u64(id, shape, "local_max_control_payload_bytes"),
        ),
        config_with_control_limit(
            Config::initiator(),
            shape_u64(id, shape, "peer_max_control_payload_bytes"),
        ),
    );
    // The 8-byte PING nonce counts toward the attempted payload length.
    let echo = vec![0u8; shape_usize(id, shape, "attempted_ping_payload_len") - 8];

    let err = server
        .ping_timeout(&echo, Duration::from_millis(20))
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::FrameSize), "{id}: {err}");
    assert!(!peer
        .collect_frames_for(Duration::from_millis(50))
        .iter()
        .any(|frame| frame.frame_type == FrameType::Ping));
    assert_eq!(server.state(), SessionState::Ready);
}

#[test]
fn invalid_case_fixtures_are_mapped_by_raw_peer_runner() {
    for case in fixture_cases("invalid_cases.ndjson", INVALID_CASE_FIXTURES) {
        let id = case["id"].as_str().unwrap();
        assert!(
            id.starts_with("preface_")
                || invalid_case_group(id).is_some()
                || INVALID_CASES_NOT_DRIVEN_BY_RAW_PEER.contains(&id),
            "invalid_cases fixture {id:?} is not mapped by the raw-peer runner"
        );
    }
}

#[test]
fn invalid_case_malformed_frame_fixtures_close_session() {
    run_invalid_case_group(InvalidCaseGroup::MalformedFrame);
}

#[test]
fn invalid_case_first_frame_on_unused_stream_fixtures_close_session() {
    run_invalid_case_group(InvalidCaseGroup::FirstFrameOnUnusedStream);
}

#[test]
fn invalid_case_ext_fixtures_on_live_session() {
    run_invalid_case_group(InvalidCaseGroup::Ext);
}

#[test]
fn invalid_case_open_metadata_fixtures_on_live_session() {
    run_invalid_case_group(InvalidCaseGroup::OpenMetadata);
}

#[test]
fn invalid_case_flow_control_fixtures_on_live_session() {
    run_invalid_case_group(InvalidCaseGroup::FlowControl);
}

#[test]
fn invalid_case_stream_state_fixtures_on_live_session() {
    run_invalid_case_group(InvalidCaseGroup::StreamState);
}

#[test]
fn invalid_case_local_send_policy_fixtures_on_live_session() {
    run_invalid_case_group(InvalidCaseGroup::LocalSendPolicy);
}

#[test]
fn wire_valid_padded_ping_tag_is_recognized() {
    let case = fixture_cases("wire_valid.ndjson", WIRE_VALID_FIXTURES)
        .into_iter()
        .find(|case| case["id"] == "frame_ping_padded_tag")
        .expect("frame_ping_padded_tag fixture");
    let raw = fixture_hex("frame_ping_padded_tag", case["hex"].as_str().unwrap());
    let key = case["expect"]["decoded"]["ping_padding_tag"]["ping_padding_key"]
        .as_u64()
        .unwrap();
    let (ping, _) = Frame::parse(&raw, Limits::default()).unwrap();

    // The tag is keyed by the PING sender's advertised ping_padding_key: under
    // that key the responder recognizes it and pads its PONG; under any other
    // key it is opaque and echoed exactly.
    for (peer_key, padded) in [(key, true), (key ^ 1, false)] {
        let server_config = Config {
            ping_padding: true,
            ping_padding_min_bytes: 16,
            ping_padding_max_bytes: 16,
            keepalive_interval: Duration::ZERO,
            ..Config::default()
        };
        let peer_config = Config {
            settings: Settings {
                ping_padding_key: peer_key,
                ..Settings::default()
            },
            ..Config::initiator()
        };
        let (server, mut peer) = server_with_raw_peer_configs(server_config, peer_config);
        peer.io.write_all(&raw).unwrap();
        peer.io.flush().unwrap();

        let pong = peer.wait_for_frame(|frame| frame.frame_type == FrameType::Pong);
        assert!(pong.payload.starts_with(&ping.payload));
        assert_eq!(
            pong.payload.len() > ping.payload.len(),
            padded,
            "key {peer_key:#x}"
        );
        server.close().unwrap();
    }
}
