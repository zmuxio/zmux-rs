//! Randomised robustness of the session core: arbitrary peer frames and
//! application calls never panic, and the transmit path always settles
//! (`wants_write` never stays true while `poll_transmit` produces nothing).

use std::time::{Duration, Instant};

use bytes::Bytes;
use proptest::prelude::*;
use zmux::proto::frame::{
    ConnectionClose, DataBlocked, Datagram, Dir, Frame, GoAwayFrame, MaxData, MaxStreamData,
    MaxStreams, Priority, PriorityUpdate, QxPing, ResetStream, ResetStreamAt, StopSending, Stream,
    StreamDataBlocked, StreamsBlocked,
};
use zmux::proto::params::TransportParameters;
use zmux::proto::record::Framing;
use zmux::proto::session::{
    Config, PipeEnd, PipeId, RoleConfig, SessionCore, StreamKey, TransmitBuf,
};
use zmux::proto::{VarInt, varint};

const P0: PipeId = PipeId(0);

#[derive(Debug, Clone)]
enum PeerFrame {
    Stream {
        s: u8,
        off: Option<u16>,
        len: u16,
        fin: bool,
    },
    Reset {
        s: u8,
        code: u8,
        size: u16,
    },
    ResetAt {
        s: u8,
        code: u8,
        size: u16,
        reliable: u16,
    },
    Stop {
        s: u8,
        code: u8,
    },
    MaxData(u32),
    MaxStreamData {
        s: u8,
        max: u32,
    },
    MaxStreams {
        bidi: bool,
        max: u16,
    },
    DataBlocked(u32),
    StreamDataBlocked {
        s: u8,
        limit: u32,
    },
    StreamsBlocked {
        bidi: bool,
        limit: u16,
    },
    Ping {
        response: bool,
        seq: u8,
    },
    GoAway {
        bidi: u16,
        uni: u16,
    },
    PriorityUpdate {
        s: u8,
        seq: u8,
        urgency: u8,
    },
    Datagram(u8),
    Close,
}

#[derive(Debug, Clone)]
enum Op {
    Peer(Vec<PeerFrame>),
    Open(bool),
    Accept(bool),
    Write { h: u8, len: u16 },
    Finish(u8),
    Reset(u8),
    Stop(u8),
    Read(u8),
    Release(u8),
    Reject(u8),
    Pin(u8),
    Boundary(u8),
    Ping,
    Datagram(u8),
    Shutdown,
    Advance(u16),
    PeerEof,
    Transmit,
}

/// Stream IDs: mostly the peer's first streams of each type, sometimes
/// local ones or arbitrary IDs. `peer_client` tells whether the peer is the
/// initiator.
fn stream_id(s: u8, peer_client: bool) -> u64 {
    let index = u64::from(s % 4);
    let uni = s & 4 != 0;
    let peer = s % 32 != 31;
    let client = if peer { peer_client } else { !peer_client };
    if s >= 240 {
        return u64::from(s % 40);
    }
    (index << 2) | if uni { 2 } else { 0 } | if client { 0 } else { 1 }
}

fn peer_frame() -> impl Strategy<Value = PeerFrame> {
    prop_oneof![
        8 => (any::<u8>(), prop::option::weighted(0.1, 0u16..3000), 0u16..1200, prop::bool::weighted(0.2))
            .prop_map(|(s, off, len, fin)| PeerFrame::Stream { s, off, len, fin }),
        2 => (any::<u8>(), 0u8..4, 0u16..3000).prop_map(|(s, code, size)| PeerFrame::Reset { s, code, size }),
        2 => (any::<u8>(), 0u8..4, 0u16..3000, 0u16..3000)
            .prop_map(|(s, code, size, reliable)| PeerFrame::ResetAt { s, code, size, reliable }),
        2 => (any::<u8>(), 0u8..4).prop_map(|(s, code)| PeerFrame::Stop { s, code }),
        2 => (0u32..2_000_000).prop_map(PeerFrame::MaxData),
        2 => (any::<u8>(), 0u32..2_000_000).prop_map(|(s, max)| PeerFrame::MaxStreamData { s, max }),
        1 => (any::<bool>(), 0u16..40).prop_map(|(bidi, max)| PeerFrame::MaxStreams { bidi, max }),
        1 => (0u32..2_000_000).prop_map(PeerFrame::DataBlocked),
        1 => (any::<u8>(), 0u32..10_000).prop_map(|(s, limit)| PeerFrame::StreamDataBlocked { s, limit }),
        1 => (any::<bool>(), 0u16..40).prop_map(|(bidi, limit)| PeerFrame::StreamsBlocked { bidi, limit }),
        2 => (any::<bool>(), any::<u8>()).prop_map(|(response, seq)| PeerFrame::Ping { response, seq }),
        1 => (0u16..20, 0u16..20).prop_map(|(bidi, uni)| PeerFrame::GoAway { bidi, uni }),
        1 => (any::<u8>(), any::<u8>(), 0u8..8)
            .prop_map(|(s, seq, urgency)| PeerFrame::PriorityUpdate { s, seq, urgency }),
        1 => any::<u8>().prop_map(PeerFrame::Datagram),
        1 => Just(PeerFrame::Close),
    ]
    .prop_filter("rare close", |f| !matches!(f, PeerFrame::Close) || rand_rare())
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        10 => prop::collection::vec(peer_frame(), 1..4).prop_map(Op::Peer),
        3 => any::<bool>().prop_map(Op::Open),
        2 => any::<bool>().prop_map(Op::Accept),
        4 => (any::<u8>(), 0u16..5000).prop_map(|(h, len)| Op::Write { h, len }),
        1 => any::<u8>().prop_map(Op::Finish),
        1 => any::<u8>().prop_map(Op::Reset),
        1 => any::<u8>().prop_map(Op::Stop),
        3 => any::<u8>().prop_map(Op::Read),
        1 => any::<u8>().prop_map(Op::Release),
        1 => any::<u8>().prop_map(Op::Reject),
        1 => any::<u8>().prop_map(Op::Pin),
        1 => any::<u8>().prop_map(Op::Boundary),
        1 => Just(Op::Ping),
        1 => any::<u8>().prop_map(Op::Datagram),
        1 => Just(Op::Shutdown),
        2 => (0u16..3000).prop_map(Op::Advance),
        1 => Just(Op::PeerEof),
        4 => Just(Op::Transmit),
    ]
}

fn rand_rare() -> bool {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    N.fetch_add(1, Ordering::Relaxed).is_multiple_of(8)
}

/// What the scripted peer knows, so that most frames are valid.
struct Peer {
    client: bool,
    zmux: bool,
    datagrams: bool,
    offsets: std::collections::HashMap<u64, u64>,
    ping: u64,
}

fn encode(f: &PeerFrame, out: &mut Vec<u8>, payload: &[u8], peer: &mut Peer) {
    let pc = peer.client;
    let stream_id = |s: u8| stream_id(s, pc);
    let offsets = &mut peer.offsets;
    let f = match *f {
        PeerFrame::GoAway { .. } | PeerFrame::PriorityUpdate { .. } if !peer.zmux => return,
        PeerFrame::Datagram(_) if !peer.datagrams => return,
        PeerFrame::Ping {
            response: false, ..
        } => {
            peer.ping += 1;
            PeerFrame::Ping {
                response: false,
                seq: peer.ping as u8,
            }
        }
        PeerFrame::Ping {
            response: true,
            seq,
        } if seq > 2 => return,
        PeerFrame::DataBlocked(l) => PeerFrame::DataBlocked(l % 20_000),
        PeerFrame::StreamsBlocked { bidi, limit } => PeerFrame::StreamsBlocked {
            bidi,
            limit: limit % 5,
        },
        PeerFrame::StreamDataBlocked { s, limit } => PeerFrame::StreamDataBlocked {
            s,
            limit: limit % 3000,
        },
        PeerFrame::Stop { s, code } => PeerFrame::Stop { s: s & !4, code },
        PeerFrame::MaxStreamData { s, max } => PeerFrame::MaxStreamData { s: s & !4, max },
        PeerFrame::PriorityUpdate { s, seq, urgency } => PeerFrame::PriorityUpdate {
            s: s & !4,
            seq,
            urgency,
        },
        PeerFrame::Reset { s, code, size } if peer.zmux => PeerFrame::ResetAt {
            s,
            code,
            size,
            reliable: size,
        },
        ref other => other.clone(),
    };
    let mut first = Vec::new();
    let frame = match f {
        PeerFrame::Stream { s, off, len, fin } => {
            let id = stream_id(s);
            let next = offsets.entry(id).or_insert(0);
            let off = off.map_or(*next, u64::from);
            *next = (*next).max(off + u64::from(len));
            // A zmux peer's first frame carries an (empty) preamble.
            let len = usize::from(len);
            if peer.zmux && off == 0 && len > 0 {
                first.clear();
                first.push(0);
                first.extend_from_slice(&payload[..len - 1]);
            }
            let data: &[u8] = if peer.zmux && off == 0 && len > 0 {
                &first
            } else {
                &payload[..len]
            };
            Frame::Stream(Stream::new(id, off, data, fin))
        }
        PeerFrame::Reset { s, code, size } => Frame::ResetStream(ResetStream {
            stream_id: stream_id(s),
            error_code: u64::from(code),
            final_size: u64::from(size),
        }),
        PeerFrame::ResetAt {
            s,
            code,
            size,
            reliable,
        } => Frame::ResetStreamAt(ResetStreamAt {
            stream_id: stream_id(s),
            error_code: u64::from(code),
            final_size: u64::from(size.max(reliable)),
            reliable_size: u64::from(reliable.min(size)),
        }),
        PeerFrame::Stop { s, code } => Frame::StopSending(StopSending {
            stream_id: stream_id(s),
            error_code: u64::from(code),
        }),
        PeerFrame::MaxData(m) => Frame::MaxData(MaxData {
            maximum: u64::from(m),
        }),
        PeerFrame::MaxStreamData { s, max } => Frame::MaxStreamData(MaxStreamData {
            stream_id: stream_id(s),
            maximum: u64::from(max),
        }),
        PeerFrame::MaxStreams { bidi, max } => Frame::MaxStreams(MaxStreams {
            dir: if bidi { Dir::Bidi } else { Dir::Uni },
            maximum: u64::from(max),
        }),
        PeerFrame::DataBlocked(l) => Frame::DataBlocked(DataBlocked {
            limit: u64::from(l),
        }),
        PeerFrame::StreamDataBlocked { s, limit } => Frame::StreamDataBlocked(StreamDataBlocked {
            stream_id: stream_id(s),
            limit: u64::from(limit),
        }),
        PeerFrame::StreamsBlocked { bidi, limit } => Frame::StreamsBlocked(StreamsBlocked {
            dir: if bidi { Dir::Bidi } else { Dir::Uni },
            limit: u64::from(limit),
        }),
        PeerFrame::Ping { response, seq } => Frame::QxPing(QxPing {
            response,
            sequence: u64::from(seq),
        }),
        PeerFrame::GoAway { bidi, uni } => Frame::GoAway(GoAwayFrame {
            max_bidi: u64::from(bidi),
            max_uni: u64::from(uni),
            error_code: 0,
        }),
        PeerFrame::PriorityUpdate { s, seq, urgency } => Frame::PriorityUpdate(PriorityUpdate {
            stream_id: stream_id(s),
            sequence: u64::from(seq),
            priority: Priority::new(urgency, true).unwrap(),
        }),
        PeerFrame::Datagram(n) => Frame::Datagram(Datagram {
            data: &payload[..usize::from(n)],
            explicit_len: true,
        }),
        PeerFrame::Close => Frame::ConnectionClose(ConnectionClose {
            application: true,
            error_code: 9,
            frame_type: 0,
            reason: b"",
        }),
    };
    let start = out.len();
    out.resize(start + frame.encoded_len(), 0);
    let n = frame.encode(&mut out[start..]).unwrap();
    out.truncate(start + n);
}

fn record(frames: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; varint::len(frames.len() as u64)];
    varint::encode(frames.len() as u64, &mut out).unwrap();
    out.extend_from_slice(frames);
    out
}

fn peer_parameters(preamble: bool, datagrams: bool) -> Vec<u8> {
    let tp = TransportParameters {
        max_idle_timeout: Some(10_000),
        initial_max_data: Some(20_000),
        initial_max_stream_data_bidi_local: Some(3000),
        initial_max_stream_data_bidi_remote: Some(3000),
        initial_max_stream_data_uni: Some(3000),
        initial_max_streams_bidi: Some(4),
        initial_max_streams_uni: Some(4),
        reset_stream_at: true,
        max_datagram_frame_size: datagrams.then_some(1200),
        zmux_goaway: preamble,
        zmux_preamble: preamble.then_some(512),
        zmux_priority: preamble,
        zmux_datagram_flows: datagrams && preamble,
        ..TransportParameters::default()
    };
    let mut buf = vec![0u8; tp.frame_len(None)];
    let n = tp.encode_frame(None, &mut buf).unwrap();
    buf.truncate(n);
    record(&buf)
}

struct Harness {
    s: SessionCore,
    out: TransmitBuf,
    keys: Vec<StreamKey>,
    now: Instant,
}

impl Harness {
    fn handle(&self, h: u8) -> Option<StreamKey> {
        (!self.keys.is_empty()).then(|| self.keys[usize::from(h) % self.keys.len()])
    }

    /// Writes everything; panics if the transmit path does not settle.
    fn transmit(&mut self) {
        for _ in 0..10_000 {
            if !self.s.wants_write(P0) {
                return;
            }
            self.s.poll_transmit(P0, self.now, &mut self.out);
            while self.s.poll_event().is_some() {}
        }
        panic!("wants_write stays true: {:?}", self.s.stats());
    }
}

fn run(ops: &[Op], preamble: bool, datagrams: bool, role: bool) {
    let now = Instant::now();
    let mut config = Config::default();
    config.max_incoming_streams = 4;
    config.max_incoming_uni_streams = Some(4);
    config.initial_stream_receive_window = 4096;
    config.initial_connection_receive_window = 20_000;
    config.enable_datagrams = datagrams;
    let r = if role {
        RoleConfig::Initiator
    } else {
        RoleConfig::Responder
    };
    let mut s = SessionCore::new(config, r, None, now).unwrap();
    s.attach_pipe(P0, Framing::ByteStream, now);
    let mut h = Harness {
        s,
        out: TransmitBuf::default(),
        keys: Vec::new(),
        now,
    };
    h.transmit();
    h.s.receive(P0, &peer_parameters(preamble, datagrams), h.now);
    let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    let mut peer = Peer {
        client: !role,
        zmux: preamble,
        datagrams,
        offsets: std::collections::HashMap::new(),
        ping: 0,
    };
    let mut buf = vec![0u8; 4096];
    for op in ops {
        match op {
            Op::Peer(frames) => {
                let mut body = Vec::new();
                for f in frames {
                    encode(f, &mut body, &payload, &mut peer);
                }
                if body.is_empty() {
                    continue;
                }
                h.s.receive(P0, &record(&body), h.now);
            }
            Op::Open(bidi) => {
                // Every other stream opens with a preamble.
                let pre = if h.keys.len().is_multiple_of(2) {
                    zmux::Preamble::new().with_info(&b"info"[..])
                } else {
                    zmux::Preamble::new()
                };
                if let Ok(k) =
                    h.s.open_with(if *bidi { Dir::Bidi } else { Dir::Uni }, &pre)
                {
                    h.keys.push(k);
                }
            }
            Op::Accept(bidi) => {
                if let Ok(Some(k)) = h.s.accept(if *bidi { Dir::Bidi } else { Dir::Uni }) {
                    h.keys.push(k);
                }
            }
            Op::Write { h: i, len } => {
                if let Some(k) = h.handle(*i) {
                    let _ =
                        h.s.write(k, &payload[..usize::from(*len).min(payload.len())]);
                }
            }
            Op::Finish(i) => {
                if let Some(k) = h.handle(*i) {
                    let _ = h.s.finish(k);
                }
            }
            Op::Reset(i) => {
                if let Some(k) = h.handle(*i) {
                    let _ = h.s.reset(k, VarInt::from_u32(1));
                }
            }
            Op::Stop(i) => {
                if let Some(k) = h.handle(*i) {
                    let _ = h.s.stop(k, VarInt::from_u32(2));
                }
            }
            Op::Read(i) => {
                if let Some(k) = h.handle(*i) {
                    let _ = h.s.read(k, &mut buf);
                    let _ = h.s.read_chunk(k, 100);
                    let _ = h.s.recv_stream_datagram(k);
                }
            }
            Op::Release(i) => {
                if let Some(k) = h.handle(*i) {
                    h.s.release(k);
                }
            }
            Op::Reject(i) => {
                if let Some(k) = h.handle(*i) {
                    let _ = h.s.reject(k);
                }
            }
            Op::Pin(i) => {
                if let Some(k) = h.handle(*i) {
                    let _ = h.s.stream_id(k);
                }
            }
            Op::Boundary(i) => {
                if let Some(k) = h.handle(*i) {
                    let _ = h.s.set_reliable_boundary(k);
                    let _ = h.s.set_peer_priority(k, Priority::new(1, false).unwrap());
                }
            }
            Op::Ping => {
                let _ = h.s.ping();
            }
            Op::Datagram(i) => {
                let _ = h.s.send_datagram(Bytes::from_static(b"dgram"), true);
                let _ = h.s.recv_datagram();
                if let Some(k) = h.handle(*i) {
                    let _ =
                        h.s.send_stream_datagram(k, 3, Bytes::from_static(b"sd"), true);
                }
            }
            Op::Shutdown => h.s.shutdown(VarInt::from_u32(0), b"", h.now),
            Op::Advance(ms) => {
                h.now += Duration::from_millis(u64::from(*ms));
                h.s.handle_timeout(h.now);
            }
            Op::PeerEof if rand_rare() => h.s.pipe_ended(P0, PipeEnd::Eof, h.now),
            Op::PeerEof => {}
            Op::Transmit => h.transmit(),
        }
        while h.s.poll_event().is_some() {}
        let _ = h.s.poll_timeout();
        let _ = h.s.stats();
    }
    h.transmit();
    // Run every remaining timer.
    for _ in 0..1000 {
        match h.s.poll_timeout() {
            Some(t) => {
                h.now = h.now.max(t);
                h.s.handle_timeout(h.now);
                h.transmit();
            }
            None => break,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn random_sessions_never_panic(
        ops in prop::collection::vec(op(), 1..60),
        preamble in any::<bool>(),
        datagrams in any::<bool>(),
        role in any::<bool>(),
    ) {
        run(&ops, preamble, datagrams, role);
    }
}
