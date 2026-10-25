//! Lanes (MULTIPATH.md Sections 2.5 and 5.8)
//! between two sans-IO cores, with the pitfalls that are cheap to check
//! deterministically: the unsent
//! count of a pipe is the sum of its lanes', a stream direction never
//! moves to another lane before its frames there are acknowledged without
//! multipath, only PIPE_LANE goes on a lane until it is confirmed and
//! a lane refused costs its pipe nothing, and a lane reserves no
//! record buffer. The traces of the `core.lanes` and
//! `multipath.lanes` groups cover the wire rules; the cumulative
//! acknowledgement point that every whole-pipe consumer uses is
//! checked where it is computed (`pipes/lanes.rs`).

use std::time::{Duration, Instant};

use zmux::proto::frame::Dir;
use zmux::proto::record::Framing;
use zmux::proto::session::{
    Config, CoreEvent, LaneAccept, LaneId, PipeId, RoleConfig, SessionCore, State, StreamKey,
    TransmitBuf,
};

const P0: PipeId = PipeId(0);

/// Two cores on pipe 0, each opening lanes toward the other as its core
/// asks; the "driver" here hands every lane to the other side at once and
/// delivers the lanes' bytes in an order of its own (`reverse`: the
/// highest lane first, so that lanes overtake each other).
struct LanePair {
    a: SessionCore,
    b: SessionCore,
    now: Instant,
    out: TransmitBuf,
    wire: Vec<u8>,
    /// The lanes each side opened toward the other.
    lanes_a: Vec<u64>,
    lanes_b: Vec<u64>,
    reverse: bool,
    /// Refuse every lane the sides open (an intermediary that splits the
    /// connection).
    refuse: bool,
}

impl LanePair {
    fn new(a: Config, b: Config) -> Self {
        let now = Instant::now();
        let mut a = SessionCore::new(a, RoleConfig::Initiator, None, now).unwrap();
        let mut b = SessionCore::new(b, RoleConfig::Responder, None, now).unwrap();
        for s in [&mut a, &mut b] {
            s.attach_pipe(P0, Framing::ByteStream, now);
            s.set_pipe_low_water(P0, true);
            s.set_pipe_lanes(P0, true);
        }
        let mut p = Self {
            a,
            b,
            now,
            out: TransmitBuf::default(),
            wire: Vec::new(),
            lanes_a: Vec::new(),
            lanes_b: Vec::new(),
            reverse: true,
            refuse: false,
        };
        p.run(Duration::from_millis(100));
        assert!(p.a.is_established() && p.b.is_established());
        p
    }

    /// Hands the lanes each side asked for to it and to the other side.
    fn events(&mut self) {
        for side in [true, false] {
            let (from, to, lanes) = if side {
                (&mut self.a, &mut self.b, &mut self.lanes_a)
            } else {
                (&mut self.b, &mut self.a, &mut self.lanes_b)
            };
            while let Some(e) = from.poll_event() {
                if let CoreEvent::OpenLane(l) = e {
                    if self.refuse {
                        from.write_failed(l, std::io::ErrorKind::BrokenPipe, self.now);
                        continue;
                    }
                    assert!(from.lane_opened(l, Framing::ByteStream, self.now));
                    assert_eq!(
                        to.accept_lane(l, Framing::ByteStream, self.now),
                        LaneAccept::Accepted
                    );
                    lanes.push(l.lane.0);
                }
            }
        }
    }

    /// Moves what one side has for each of its lanes to the other side.
    fn send(&mut self, a_to_b: bool) -> usize {
        let (from, to, lanes) = if a_to_b {
            (&mut self.a, &mut self.b, &self.lanes_a)
        } else {
            (&mut self.b, &mut self.a, &self.lanes_b)
        };
        let mut order: Vec<u64> = std::iter::once(0).chain(lanes.iter().copied()).collect();
        if self.reverse {
            order.reverse();
        }
        let mut moved = 0;
        for lane in order {
            let at: LaneId = P0.lane(lane);
            while from.wants_write(at) {
                from.poll_transmit(at, self.now, &mut self.out);
                if self.out.is_empty() {
                    break;
                }
                self.wire.clear();
                self.out.copy_to_vec(&mut self.wire);
                let used = to.receive_in_place(at, &self.wire, self.now);
                assert_eq!(used, self.wire.len(), "a batch is whole records");
                moved += self.wire.len();
            }
        }
        moved
    }

    /// Runs both sides for `d`, a millisecond at a time.
    fn run(&mut self, d: Duration) {
        let end = self.now + d;
        while self.now < end {
            for _ in 0..64 {
                self.events();
                let moved = self.send(true) + self.send(false);
                self.events();
                if moved == 0 {
                    break;
                }
            }
            self.now += Duration::from_millis(1);
            self.a.handle_timeout(self.now);
            self.b.handle_timeout(self.now);
        }
    }

    /// Reads everything readable on `key` of `s`.
    fn read_all(s: &mut SessionCore, key: StreamKey, into: &mut Vec<u8>) -> bool {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match s.read(key, &mut buf) {
                Ok(Some((n, fin))) => {
                    into.extend_from_slice(&buf[..n]);
                    if fin {
                        return true;
                    }
                }
                Ok(None) => return false,
                Err(e) => panic!("read: {e:?}"),
            }
        }
    }
}

fn pattern(stream: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i * 31 + stream * 7 + i / 977) as u8)
        .collect()
}

/// Bulk streams of a session without multipath spread over lanes, which
/// the "driver" delivers out of order across lanes: every stream arrives
/// whole and in order (a frame of a stream direction that overtook an
/// earlier one would be a PROTOCOL_VIOLATION, SPEC.md Section 7.3), and
/// the writer opened lanes for them.
#[test]
fn bulk_streams_spread_over_lanes_and_keep_their_order_without_multipath() {
    let mut p = LanePair::new(Config::default(), Config::default());
    const STREAMS: usize = 4;
    const LEN: usize = 192 * 1024;
    let keys: Vec<StreamKey> = (0..STREAMS).map(|_| p.a.open(Dir::Uni).unwrap()).collect();
    let data: Vec<Vec<u8>> = (0..STREAMS).map(|i| pattern(i, LEN)).collect();
    let mut written = [0usize; STREAMS];
    let mut got: Vec<Vec<u8>> = vec![Vec::new(); STREAMS];
    let mut peers: [Option<StreamKey>; STREAMS] = [None; STREAMS];
    let mut done = 0;
    for _ in 0..20_000 {
        for i in 0..STREAMS {
            if written[i] < LEN {
                let end = (written[i] + 8192).min(LEN);
                if let Ok(n) = p.a.write(keys[i], &data[i][written[i]..end]) {
                    written[i] += n;
                    if written[i] == LEN {
                        p.a.finish(keys[i]).unwrap();
                    }
                }
            }
        }
        p.run(Duration::from_millis(1));
        while let Ok(Some(k)) = p.b.accept(Dir::Uni) {
            let id = p.b.peek_stream_id(k).unwrap();
            peers[(id >> 2) as usize] = Some(k);
        }
        for i in 0..STREAMS {
            if let Some(k) = peers[i]
                && got[i].len() < LEN
                && LanePair::read_all(&mut p.b, k, &mut got[i])
            {
                done += 1;
            }
        }
        if done == STREAMS {
            break;
        }
    }
    assert_eq!(p.a.state(), State::Active, "{:?}", p.a.error());
    assert_eq!(p.b.state(), State::Active, "{:?}", p.b.error());
    for i in 0..STREAMS {
        assert!(got[i] == data[i], "stream {i} arrived whole and in order");
    }
    let info = p.a.pipe_info(P0).unwrap();
    assert!(info.lanes_out > 1, "lanes opened: {info:?}");
    assert_eq!(info.lanes_refused, 0);
    assert_eq!(p.b.pipe_info(P0).unwrap().lanes_in, info.lanes_out);
}

/// A lane that ends before it is confirmed is refused: the pipe goes on,
/// its data stays on lane 0, and no further lane is opened.
#[test]
fn a_refused_lane_costs_the_pipe_nothing() {
    let mut p = LanePair::new(Config::default(), Config::default());
    p.refuse = true;
    let k = p.a.open(Dir::Uni).unwrap();
    let data = pattern(0, 256 * 1024);
    let mut at = 0;
    let mut got = Vec::new();
    let mut peer = None;
    for _ in 0..10_000 {
        if at < data.len() {
            let end = (at + 8192).min(data.len());
            if let Ok(n) = p.a.write(k, &data[at..end]) {
                at += n;
                if at == data.len() {
                    p.a.finish(k).unwrap();
                }
            }
        }
        p.run(Duration::from_millis(1));
        if peer.is_none() {
            peer = p.b.accept(Dir::Uni).unwrap();
        }
        if let Some(pk) = peer
            && LanePair::read_all(&mut p.b, pk, &mut got)
        {
            break;
        }
    }
    assert!(got == data, "the data arrived on lane 0");
    assert_eq!(p.a.state(), State::Active);
    let info = p.a.pipe_info(P0).unwrap();
    assert_eq!(info.lanes_refused, 1, "one lane asked for and refused");
    assert_eq!(info.lanes_out, 2, "and no further one");
}

/// The unsent bytes of a pipe with lanes are the sum of its lanes'
/// (counting a lane's bytes as the adapter reports them, not by record).
#[test]
fn the_unsent_count_of_a_pipe_is_the_sum_of_its_lanes() {
    let mut p = LanePair::new(Config::default(), Config::default());
    let k = p.a.open(Dir::Uni).unwrap();
    for _ in 0..200 {
        let _ = p.a.write(k, &[7u8; 8192]);
        p.run(Duration::from_millis(1));
        if p.lanes_a.len() == 1 && p.a.pipe_info(P0).unwrap().lanes.len() == 2 {
            break;
        }
    }
    assert_eq!(p.lanes_a.len(), 1, "a lane opened");
    let now = p.now;
    p.a.set_pipe_unsent(P0, 3000, now);
    p.a.set_pipe_unsent(P0.lane(1), 4000, now);
    assert_eq!(p.a.pipe_info(P0).unwrap().queued_bytes, 7000);
    p.a.set_pipe_unsent(P0.lane(1), 0, now);
    assert_eq!(p.a.pipe_info(P0).unwrap().queued_bytes, 3000);
}

/// A lane holds no record buffer of its own until a record spans reads:
/// a peer that opens many lanes costs little memory each.
#[test]
fn lanes_reserve_no_record_buffer() {
    let mut p = LanePair::new(Config::default(), Config::default());
    let before = p.b.memory_usage();
    let now = p.now;
    for n in 1..=64 {
        assert_eq!(
            p.b.accept_lane(P0.lane(n), Framing::ByteStream, now),
            LaneAccept::Accepted
        );
    }
    let per_lane = (p.b.memory_usage() - before) / 64;
    assert!(per_lane < 1024, "{per_lane} bytes per lane");
    // A lane number used twice, or 0, or beyond Max Lanes, is the peer's
    // protocol violation.
    assert_eq!(
        p.b.accept_lane(P0.lane(3), Framing::ByteStream, now),
        LaneAccept::Violation
    );
    assert!(p.b.state() >= State::Closing);
}

/// In a multipath session whose tier has a single usable pipe, the copy
/// of a redundant (urgent) chunk goes on the pipe's copy lane, paired with
/// lane 0; both copies arrive, the
/// stream reads once.
#[test]
fn urgent_data_of_a_single_pipe_tier_is_copied_on_the_copy_lane() {
    let multipath = || {
        let mut c = Config::default();
        c.max_pipes = 2;
        c.pipe_auth = zmux::PipeAuth::psk(*b"lanes-psk-------0123456789abcdef");
        c
    };
    let mut p = LanePair::new(multipath(), multipath());
    assert!(p.a.is_multipath());
    let k = p.a.open(Dir::Uni).unwrap();
    p.a.set_priority(k, zmux::Priority::new(0, false).unwrap())
        .unwrap();
    let mut peer = None;
    let mut got = Vec::new();
    let mut sent = Vec::new();
    for round in 0..200u32 {
        let msg = pattern(round as usize, 512);
        p.a.write(k, &msg).unwrap();
        sent.extend_from_slice(&msg);
        p.run(Duration::from_millis(5));
        if peer.is_none() {
            peer = p.b.accept(Dir::Uni).unwrap();
        }
        if let Some(pk) = peer {
            LanePair::read_all(&mut p.b, pk, &mut got);
        }
    }
    assert!(got == sent, "every message once, in order");
    assert!(p.a.stats().bytes_redundant > 0, "copies went out");
    let info = p.a.pipe_info(P0).unwrap();
    assert!(info.lanes_out >= 2, "a copy lane opened: {info:?}");
    assert!(
        info.lanes
            .iter()
            .any(|l| l.lane.0 > 0 && l.position_acked > Some(23)),
        "the copies went on a lane: {info:?}"
    );
}
