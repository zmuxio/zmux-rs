//! Exactly-once delivery of multipath sessions under pipe churn, sans IO:
//! two cores joined by modelled TCP carriers that fail, stall, delay,
//! reorder and deliver late, while both ends open, write, read, finish,
//! reset and stop streams, switch policies and change pipe tiers in random
//! order (MULTIPATH.md Sections 7, 8, 11 to 13).
//!
//! Properties: every byte read is the byte written at that offset (nothing
//! duplicated, reordered or invented), a FIN only after everything, a reset
//! only after its reliable prefix; no panic; sessions end only for the
//! reasons multipath allows; the retained data stays within the retransmit
//! budget's 16 MiB cap; and when both sessions survive, a healed network
//! delivers and acknowledges everything and retires every dead attachment.
//!
//! The tests at the end reproduce bugs the fuzzer found (all fixed).
//!
//! `PROPTEST_CASES` sets the case count (default 128, about 5 s
//! unoptimized). A long session runs best optimized, several processes in
//! parallel (each draws its own seed), for example:
//!
//! ```text
//! PROPTEST_CASES=10000 cargo test --release --test mp_fuzz exactly_once -- --nocapture
//! ```
//!
//! `MP_FUZZ_STATS=1` prints one line of coverage counters per case.

use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "common/basics.rs"]
mod basics;
#[path = "common/mp_net.rs"]
mod mp_net;

use basics::small_windows;
use bytes::Bytes;
use mp_net::{A, B, Joined, MpNet, Observe};
use proptest::prelude::*;
use zmux::proto::frame::{Dir, Frame, Frames, Gates};
use zmux::proto::session::{
    Config, CoreEvent, FrameInfo, Pick, PickAnswer, PipeAuth, PipeId, PipeOptions, PipeSnapshot,
    PipeState, Policy, SessionCore, SessionError, SessionStats, State, StreamError, StreamKey,
};
use zmux::proto::{TransportErrorCode, VarInt, varint};

const MIB: u64 = 1 << 20;
/// The retransmit budget's cap.
const RETAINED_CAP: u64 = 16 * MIB;

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// The byte at `offset` of one direction of a stream: different at every
/// offset, so data delivered at the wrong offset is caught whatever the
/// distance (a pattern repeating every 256 bytes would miss 16 KiB shifts).
fn byte_at(tag: usize, half: usize, offset: u64) -> u8 {
    let word = mix(((tag as u64) << 1 | half as u64) << 40 ^ (offset >> 3));
    (word >> ((offset & 7) * 8)) as u8
}

fn pattern(tag: usize, half: usize, from: u64, len: usize) -> Vec<u8> {
    (from..from + len as u64)
        .map(|i| byte_at(tag, half, i))
        .collect()
}

/// Admits every frame the cores send.
const ALL_FRAMES: Gates = Gates {
    reset_stream_at: true,
    max_datagram_frame_size: u64::MAX,
    goaway: true,
    priority: true,
    multipath: true,
    pipe_ack: true,
    lanes: true,
};

/// A batch is whole records whose frames decode. `Err(true)` when what
/// breaks the framing is a STREAM frame with only a FIN, written outside a
/// record (`fin_only_frame_at_the_end_of_a_batch_stays_in_a_record` in
/// `tests/framing_regressions.rs`).
fn check_batch(batch: &[u8]) -> Result<(), bool> {
    let mut rest = batch;
    while !rest.is_empty() {
        let stray_fin = matches!(
            Frame::decode(rest, &ALL_FRAMES),
            Ok((Frame::Stream(s), _)) if s.fin && s.data.is_empty()
        );
        let body = varint::decode(rest)
            .and_then(|(size, n)| Some((rest.get(n..n + usize::try_from(size).ok()?)?, n)));
        let Some((body, n)) = body else {
            return Err(stray_fin);
        };
        if Frames::new(body, ALL_FRAMES).any(|f| f.is_err()) {
            return Err(stray_fin);
        }
        rest = &rest[n + body.len()..];
    }
    Ok(())
}

// ---- streams --------------------------------------------------------------------

/// The sending part of one direction of a stream, as the harness knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sending {
    Open,
    Finished,
    /// Reset with this code; the reader must get this reliable prefix.
    Reset {
        code: u64,
        reliable: u64,
    },
    /// The writer saw the reader's STOP_SENDING.
    Stopped,
}

/// One direction of a stream.
#[derive(Debug)]
struct Half {
    /// Bytes the writer's core took.
    sent: u64,
    /// The reliable boundary set by the writer.
    boundary: Option<u64>,
    sending: Sending,
    /// Bytes the reader got.
    read: u64,
    fin_read: bool,
    reset_read: bool,
    /// The reader stopped with this code (STOP_SENDING or release).
    stopped: Option<u64>,
}

impl Half {
    fn new() -> Self {
        Self {
            sent: 0,
            boundary: None,
            sending: Sending::Open,
            read: 0,
            fin_read: false,
            reset_read: false,
            stopped: None,
        }
    }

    fn readable(&self) -> bool {
        self.stopped.is_none() && !self.fin_read && !self.reset_read
    }
}

#[derive(Debug)]
struct Stream {
    opener: usize,
    bidi: bool,
    /// Each end's handle, until it releases the stream.
    keys: [Option<StreamKey>; 2],
    /// The opener's handle, kept after a release to learn the identifier.
    opener_key: StreamKey,
    id: Option<u64>,
    /// `[opener to acceptor, acceptor to opener]`.
    halves: [Half; 2],
}

impl Stream {
    fn writer(&self, half: usize) -> usize {
        if half == 0 {
            self.opener
        } else {
            1 - self.opener
        }
    }

    fn has(&self, half: usize) -> bool {
        half == 0 || self.bidi
    }
}

fn reset_code(tag: usize) -> u64 {
    0x100 + tag as u64
}

fn stop_code(tag: usize) -> u64 {
    0x10_000 + tag as u64
}

// ---- policies ---------------------------------------------------------------------

/// A custom policy: a stable hash of the stream and chunk picks a pipe, and
/// one value in `n + 1` is out of range (the core falls back to affinity).
#[derive(Debug)]
struct HashPick;

impl Pick for HashPick {
    fn pick(&self, reqs: &[FrameInfo], pipes: &[PipeSnapshot], out: &mut [PickAnswer]) {
        for (frame, answer) in reqs.iter().zip(out) {
            let h = mix(frame.stream.unwrap_or(u64::MAX) ^ frame.len << 32);
            // Sticky for a few chunks, or until invalidated; now and then
            // a wait.
            *answer = match h % 7 {
                0 => PickAnswer::Wait,
                k => PickAnswer::Pipe {
                    index: (h >> 8) as usize % (pipes.len() + 1),
                    bytes: (k - 1) * 16 * 1024,
                },
            };
        }
    }
}

fn policy() -> impl Strategy<Value = Policy> {
    prop_oneof![
        Just(Policy::Affinity),
        Just(Policy::SpreadEta),
        Just(Policy::SpreadRateWeighted),
        Just(Policy::SpreadRoundRobin),
        Just(Policy::SessionAffinity),
        Just(Policy::Custom(Arc::new(HashPick))),
    ]
}

/// Session errors a multipath session may end with when its pipes fail.
fn allowed(e: &SessionError) -> bool {
    match e {
        SessionError::PipesLost { .. }
        | SessionError::ResumeTimeout { .. }
        | SessionError::IdleTimeout { .. } => true,
        SessionError::TransportClosed { code, .. } => [
            TransportErrorCode::NO_VIABLE_PATH,
            TransportErrorCode::ZMUX_RESUME_TIMEOUT,
            TransportErrorCode::ZMUX_IDLE_TIMEOUT,
        ]
        .contains(code),
        _ => false,
    }
}

// ---- the network ------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Setup {
    resume: bool,
    policies: [Policy; 2],
    /// Small stream and session windows: credit pressure, opportunistic
    /// copies.
    tight_windows: bool,
    suspect_floor: Duration,
    probation: Option<Duration>,
    spread_chunk: usize,
    max_pipes: u32,
    dead_timeout: Option<Duration>,
    /// The bootstrap carrier's capacity and abort behaviour.
    cap: usize,
    rst: bool,
    /// The cores' random values (GREASE, nonces): a case replays exactly.
    seed: u64,
}

impl Setup {
    fn config(&self, side: usize) -> Config {
        let mut c = Config::default();
        c.max_pipes = self.max_pipes;
        c.pipe_auth = PipeAuth::psk(*b"0123456789abcdef0123456789abcdef");
        c.scheduler = self.policies[side].clone();
        c.max_idle_timeout = Duration::from_secs(60);
        c.suspect_floor = self.suspect_floor;
        c.probation = self.probation;
        c.spread_chunk = self.spread_chunk;
        c.dead_timeout = self.dead_timeout;
        if self.resume {
            c.resume_timeout = Some(Duration::from_secs(30));
        }
        if self.tight_windows {
            c = small_windows(c);
        }
        if side == B {
            c.test_hooks().locator = b"server".to_vec();
        }
        let seed = mix(self.seed ^ side as u64);
        let hooks = c.test_hooks();
        // A GREASE transport parameter (ID 31 N + 27) of 0 to 16 bytes.
        hooks.grease_tp = Some((
            31 * (seed % 1024) + 27,
            seed.to_le_bytes()
                .iter()
                .cycle()
                .take((seed >> 32) as usize % 17)
                .copied()
                .collect(),
        ));
        let nonce = (u128::from(mix(seed)) << 64 | u128::from(mix(!seed))).to_le_bytes();
        hooks.session_nonce = Some(nonce);
        // The first preamble's GREASE TLV (type 0x1f N + 0x21, 0 to 8
        // bytes); unpinned, every call draws another one.
        hooks.grease_tlv = Some((
            zmux::proto::payload::grease_tlv_type(seed % 1024).unwrap_or(0x21),
            seed.to_be_bytes()[..(seed >> 10) as usize % 9].to_vec(),
        ));
        c
    }
}

/// What happened in a case, for coverage reports (`MP_FUZZ_STATS`).
#[derive(Debug, Default)]
struct Coverage {
    suspended: u64,
    resumed: u64,
    late_bytes: u64,
}

/// Every batch an end writes is well formed ([`check_batch`]).
#[derive(Default)]
struct Wellformed;

fn check_wellformed(end: usize, batch: &[u8]) {
    if let Err(lone_fin) = check_batch(batch) {
        panic!("end {end}: malformed batch (lone FIN outside a record: {lone_fin}) {batch:02x?}");
    }
}

impl Observe for Wellformed {
    fn a_batch(&mut self, bytes: &[u8]) {
        check_wellformed(A, bytes);
    }

    fn b_batch(&mut self, bytes: &[u8]) {
        check_wellformed(B, bytes);
    }
}

/// What a case knows besides the network.
struct Fuzz {
    /// Send buffer and session window cap per end.
    limits: [(u64, u64); 2],
    streams: Vec<Stream>,
    cov: Coverage,
    /// The largest statistics seen per end (counters only grow).
    peak: [SessionStats; 2],
    max_pipes: usize,
    /// Pipes each end removed gracefully (the retirement bug of
    /// `abandon_after_a_failed_drain_is_sent`).
    drained: [Vec<PipeId>; 2],
}

type Net = MpNet<Wellformed, Fuzz>;

/// The network of `setup`, its sessions established on pipe 0.
fn net(setup: &Setup) -> Net {
    let configs = [setup.config(A), setup.config(B)];
    let limits = configs.each_ref().map(|c| {
        // An automatic cap grows within the memory budget.
        let window = match c.max_connection_receive_window {
            zmux::Cap::Fixed(w) => w,
            _ => c.memory_budget,
        };
        (c.send_buffer, window)
    });
    let [ca, cb] = configs;
    let fuzz = Fuzz {
        limits,
        streams: Vec::new(),
        cov: Coverage::default(),
        peak: [SessionStats::default(), SessionStats::default()],
        max_pipes: setup.max_pipes as usize,
        drained: [Vec::new(), Vec::new()],
    };
    let mut n = Net::new(ca, cb, fuzz);
    let l = n.links.get_mut(&0).expect("pipe 0");
    l.cap = setup.cap;
    l.rst = setup.rst;
    for _ in 0..4 {
        n.tick(usize::MAX);
    }
    assert!(n.ends[A].is_multipath() && n.ends[B].is_multipath());
    n
}

impl Net {
    // ---- the network -----------------------------------------------------------

    /// A round of the network ([`MpNet::step`]); then the events are
    /// checked and the stream identifiers learnt.
    fn tick(&mut self, limit: usize) {
        self.step(limit);
        self.check_events();
        self.refresh_ids();
    }

    /// Time passes ([`MpNet::advance`]); then the events are checked.
    fn wait(&mut self, ms: u64) {
        self.advance(ms);
        self.check_events();
    }

    /// Takes both ends' events: a session ends only for a reason multipath
    /// allows.
    fn check_events(&mut self) {
        self.handle_events();
        for side in [A, B] {
            for e in self.events[side].drain(..) {
                match e {
                    CoreEvent::Closed(e) => {
                        assert!(allowed(&e), "end {side} closed: {e:?}");
                    }
                    CoreEvent::Suspended => self.s.cov.suspended += 1,
                    CoreEvent::Resumed => self.s.cov.resumed += 1,
                    _ => {}
                }
            }
        }
    }

    /// The network runs for `ms`: 10 ms ticks, each flow delivering at most
    /// `per_tick` bytes per tick, both ends reading.
    fn run(&mut self, ms: u64, per_tick: usize) {
        for _ in 0..ms.div_ceil(10) {
            self.tick(per_tick);
            self.read_all(A);
            self.read_all(B);
            self.wait(10);
        }
    }

    /// A joins a pipe over a carrier of capacity `cap` (`rst`: an abortive
    /// close resets it); `force` ignores the pipe-credit guard.
    fn join_pipe(&mut self, opts: &PipeOptions, cap: usize, rst: bool, force: bool) -> bool {
        // Joins beyond max_pipes + H are refused: keep them rare.
        let local = self.ends[A]
            .pipes()
            .iter()
            .filter(|i| i.local && i.pipe != PipeId(0))
            .count();
        if !force && local + 1 >= self.s.max_pipes {
            return false;
        }
        let Some(id) = self.add_pipe(opts) else {
            return false;
        };
        let l = self.links.get_mut(&id).expect("link");
        l.cap = cap;
        l.rst = rst;
        self.check_events();
        true
    }

    fn link_at(&self, sel: u8) -> Option<u64> {
        let ids: Vec<u64> = self.links.keys().copied().collect();
        ids.get(sel as usize % ids.len().max(1)).copied()
    }

    // ---- streams ---------------------------------------------------------------

    /// Learns the identifiers the openers' cores assigned.
    fn refresh_ids(&mut self) {
        for s in &mut self.s.streams {
            if s.id.is_none() {
                s.id = self.ends[s.opener].peek_stream_id(s.opener_key);
            }
        }
    }

    fn open(&mut self, side: usize, bidi: bool, len: usize, commit: bool) {
        let dir = if bidi { Dir::Bidi } else { Dir::Uni };
        let Ok(k) = self.ends[side].open(dir) else {
            return;
        };
        let tag = self.s.streams.len();
        self.s.streams.push(Stream {
            opener: side,
            bidi,
            keys: [None, None],
            opener_key: k,
            id: None,
            halves: [Half::new(), Half::new()],
        });
        self.s.streams[tag].keys[side] = Some(k);
        if commit {
            let _ = self.ends[side].stream_id(k);
        }
        self.write_half(tag, 0, len, false);
    }

    /// `(tag, half)` pairs matching `f`, in a stable order.
    fn halves(&self, f: impl Fn(&Stream, usize) -> bool) -> Vec<(usize, usize)> {
        let f = &f;
        self.s
            .streams
            .iter()
            .enumerate()
            .flat_map(|(t, s)| {
                (0..2)
                    .filter(move |&h| s.has(h) && f(s, h))
                    .map(move |h| (t, h))
            })
            .collect()
    }

    /// Halves end `side` can still write to.
    fn sendable(&self, side: usize, also_finished: bool) -> Vec<(usize, usize)> {
        self.halves(|s, h| {
            let st = s.halves[h].sending;
            s.writer(h) == side
                && s.keys[side].is_some()
                && (st == Sending::Open || (also_finished && st == Sending::Finished))
        })
    }

    /// Halves end `side` can still read from.
    fn receivable(&self, side: usize) -> Vec<(usize, usize)> {
        self.halves(|s, h| s.writer(h) != side && s.keys[side].is_some() && s.halves[h].readable())
    }

    /// The writer of a half saw STOP_SENDING.
    fn saw_stop(&mut self, tag: usize, h: usize, code: VarInt) {
        let half = &mut self.s.streams[tag].halves[h];
        assert_eq!(
            half.stopped,
            Some(code.into_inner()),
            "stream {tag}/{h}: STOP_SENDING the reader did not send"
        );
        half.sending = Sending::Stopped;
    }

    fn write_half(&mut self, tag: usize, h: usize, len: usize, chunk: bool) {
        let s = &self.s.streams[tag];
        let w = s.writer(h);
        let Some(key) = s.keys[w] else {
            return;
        };
        let data = pattern(tag, h, s.halves[h].sent, len);
        let r = if chunk {
            self.ends[w].write_chunk(key, Bytes::from(data))
        } else {
            self.ends[w].write(key, &data)
        };
        match r {
            Ok(n) => self.s.streams[tag].halves[h].sent += n as u64,
            Err(StreamError::Stopped(code)) => self.saw_stop(tag, h, code),
            Err(StreamError::SessionLost(_)) => {}
            Err(e) => panic!("write on stream {tag}/{h}: {e:?}"),
        }
    }

    fn finish(&mut self, tag: usize, h: usize) {
        let s = &self.s.streams[tag];
        let w = s.writer(h);
        let key = s.keys[w].expect("writer handle");
        match self.ends[w].finish(key) {
            Ok(()) => self.s.streams[tag].halves[h].sending = Sending::Finished,
            Err(StreamError::Stopped(code)) => self.saw_stop(tag, h, code),
            Err(StreamError::SessionLost(_)) => {}
            Err(e) => panic!("finish on stream {tag}/{h}: {e:?}"),
        }
    }

    fn reset(&mut self, tag: usize, h: usize, boundary: bool) {
        let s = &self.s.streams[tag];
        let w = s.writer(h);
        let key = s.keys[w].expect("writer handle");
        if lost(&self.ends[w]) {
            return;
        }
        if boundary && self.ends[w].set_reliable_boundary(key).is_ok() {
            let half = &mut self.s.streams[tag].halves[h];
            half.boundary = Some(half.sent);
        }
        let code = reset_code(tag);
        if self.ends[w]
            .reset(key, VarInt::from_u32(code as u32))
            .is_ok()
        {
            let half = &mut self.s.streams[tag].halves[h];
            half.sending = Sending::Reset {
                code,
                reliable: half.boundary.unwrap_or(0),
            };
        }
    }

    fn stop(&mut self, tag: usize, h: usize) {
        let s = &self.s.streams[tag];
        let r = 1 - s.writer(h);
        let key = s.keys[r].expect("reader handle");
        let code = stop_code(tag);
        self.ends[r]
            .stop(key, VarInt::from_u32(code as u32))
            .unwrap_or_else(|e| panic!("stop on stream {tag}/{h}: {e:?}"));
        self.s.streams[tag].halves[h].stopped = Some(code);
    }

    /// End `side` drops its handle: an unfinished sending part is reset and
    /// an unread receiving part stopped, both with code 0.
    fn release(&mut self, side: usize, tag: usize) {
        self.refresh_ids();
        let Some(key) = self.s.streams[tag].keys[side].take() else {
            return;
        };
        let lost = lost(&self.ends[side]);
        self.ends[side].release(key);
        let s = &mut self.s.streams[tag];
        for h in 0..2 {
            if !s.has(h) {
                continue;
            }
            let writer = s.writer(h);
            let half = &mut s.halves[h];
            if writer == side {
                if half.sending == Sending::Open && !lost {
                    half.sending = Sending::Reset {
                        code: 0,
                        reliable: half.boundary.unwrap_or(0),
                    };
                }
            } else if half.readable() {
                half.stopped = Some(0);
            }
        }
    }

    fn accept_all(&mut self, side: usize) {
        for dir in [Dir::Bidi, Dir::Uni] {
            while let Ok(Some(k)) = self.ends[side].accept(dir) {
                let id = self.ends[side]
                    .peek_stream_id(k)
                    .expect("an accepted stream has an identifier");
                self.refresh_ids();
                let tag = self
                    .s
                    .streams
                    .iter()
                    .position(|s| s.opener != side && s.id == Some(id))
                    .unwrap_or_else(|| panic!("end {side} accepted unknown stream {id}"));
                let s = &mut self.s.streams[tag];
                assert_eq!(s.bidi, dir == Dir::Bidi, "stream {tag}: wrong type");
                assert!(s.keys[side].is_none(), "stream {tag} accepted twice");
                s.keys[side] = Some(k);
            }
        }
    }

    /// Reads up to `max` bytes of one half, checking each byte.
    fn read_half(&mut self, tag: usize, h: usize, max: usize) {
        let s = &self.s.streams[tag];
        let r = 1 - s.writer(h);
        let Some(key) = s.keys[r] else {
            return;
        };
        let mut buf = vec![0u8; max.clamp(1, 64 * 1024)];
        let mut left = max;
        while left > 0 && self.s.streams[tag].halves[h].readable() {
            let want = left.min(buf.len());
            match self.ends[r].read(key, &mut buf[..want]) {
                Ok(Some((n, fin))) => {
                    let half = &mut self.s.streams[tag].halves[h];
                    assert!(
                        half.read + n as u64 <= half.sent,
                        "stream {tag}/{h}: read {} bytes, {} written",
                        half.read + n as u64,
                        half.sent
                    );
                    for (i, &b) in buf[..n].iter().enumerate() {
                        let off = half.read + i as u64;
                        assert_eq!(
                            b,
                            byte_at(tag, h, off),
                            "stream {tag}/{h}: wrong byte at offset {off}"
                        );
                    }
                    half.read += n as u64;
                    left -= n;
                    if fin {
                        assert_eq!(half.sending, Sending::Finished, "stream {tag}/{h}: FIN");
                        assert_eq!(half.read, half.sent, "stream {tag}/{h}: early FIN");
                        half.fin_read = true;
                    }
                    if n == 0 {
                        break;
                    }
                }
                Ok(None) | Err(StreamError::SessionLost(_)) => break,
                Err(StreamError::Reset {
                    code,
                    reliable_size,
                }) => {
                    // A lost session reports the reset even when the data
                    // below its Reliable Size never arrived
                    // (`reset_after_session_loss_claims_unread_reliable_data`).
                    let lost = lost(&self.ends[r]);
                    let half = &mut self.s.streams[tag].halves[h];
                    let Sending::Reset {
                        code: sent_code,
                        reliable,
                    } = half.sending
                    else {
                        panic!("stream {tag}/{h}: reset {code} the writer did not send");
                    };
                    assert_eq!(code.into_inner(), sent_code, "stream {tag}/{h}: reset code");
                    assert_eq!(reliable_size, reliable, "stream {tag}/{h}: reliable size");
                    assert!(
                        half.read >= reliable || lost,
                        "stream {tag}/{h}: reliable prefix lost"
                    );
                    half.reset_read = true;
                }
                Err(e) => panic!("read on stream {tag}/{h}: {e:?}"),
            }
        }
    }

    fn read_all(&mut self, side: usize) {
        self.accept_all(side);
        for (t, h) in self.receivable(side) {
            self.read_half(t, h, usize::MAX);
        }
    }

    // ---- checks ----------------------------------------------------------------

    /// Holds after every operation.
    fn check(&mut self) {
        for side in [A, B] {
            let s = &self.ends[side];
            if let Some(e) = s.error() {
                assert!(allowed(e), "end {side} closed: {e:?}");
            }
            let st = s.stats();
            let (send_buffer, window) = self.s.limits[side];
            assert!(st.retained <= RETAINED_CAP, "end {side}: {st:?}");
            assert!(st.send_buffered <= send_buffer, "end {side}: {st:?}");
            assert!(st.recv_buffered <= window, "end {side}: {st:?}");
            let held = s.held_bytes();
            assert!(
                held <= st.send_buffered + st.recv_buffered + 2 * RETAINED_CAP,
                "end {side}: held {held}, {st:?}"
            );
            let p = &mut self.s.peak[side];
            p.bytes_duplicate = p.bytes_duplicate.max(st.bytes_duplicate);
            p.bytes_reinjected = p.bytes_reinjected.max(st.bytes_reinjected);
            p.bytes_opportunistic = p.bytes_opportunistic.max(st.bytes_opportunistic);
            p.reinjections = p.reinjections.max(st.reinjections);
            p.pipe_failures = p.pipe_failures.max(st.pipe_failures);
            p.penalties = p.penalties.max(st.penalties);
            p.scheduler_fallbacks = p.scheduler_fallbacks.max(st.scheduler_fallbacks);
            p.retained = p.retained.max(st.retained);
        }
        // The bytes a receiving part
        // counts are distinct offsets, so duplicates over several pipes
        // (reinjection, redundancy, opportunistic copies) never make them
        // exceed what was written, and a complete half counts each byte
        // once.
        for (tag, s) in self.s.streams.iter().enumerate() {
            for h in (0..2).filter(|&h| s.has(h)) {
                let reader = 1 - s.writer(h);
                let Some(st) = s.keys[reader].and_then(|k| self.ends[reader].stream_stats(k))
                else {
                    continue;
                };
                let half = &s.halves[h];
                assert!(
                    st.bytes_received <= half.sent,
                    "stream {tag}/{h}: {} bytes received of {} written",
                    st.bytes_received,
                    half.sent
                );
                if half.fin_read {
                    assert_eq!(st.bytes_received, half.sent, "stream {tag}/{h}");
                }
            }
        }
    }

    /// Whether every stream is complete and everything acknowledged.
    fn complete(&self) -> bool {
        let streams = self.s.streams.iter().enumerate().all(|(tag, s)| {
            (0..2)
                .filter(|&h| s.has(h))
                .all(|h| self.half_complete(tag, h).is_ok())
        });
        streams
            && self.ends.iter().all(|s| {
                let st = s.stats();
                st.retained == 0 && st.send_buffered == 0 && st.recv_buffered == 0
            })
    }

    fn half_complete(&self, tag: usize, h: usize) -> Result<(), String> {
        let s = &self.s.streams[tag];
        let half = &s.halves[h];
        if half.stopped.is_some() {
            return Ok(());
        }
        let reader = 1 - s.writer(h);
        match half.sending {
            Sending::Stopped => Ok(()),
            Sending::Open | Sending::Finished if half.read != half.sent => Err(format!(
                "stream {tag}/{h}: {} of {} bytes read",
                half.read, half.sent
            )),
            Sending::Finished if !half.fin_read => Err(format!("stream {tag}/{h}: no FIN")),
            Sending::Reset { reliable, .. } if half.read < reliable => Err(format!(
                "stream {tag}/{h}: {} of {reliable} reliable bytes read",
                half.read
            )),
            Sending::Reset { .. } if !half.reset_read && s.keys[reader].is_some() => {
                Err(format!("stream {tag}/{h}: reset not seen"))
            }
            _ => Ok(()),
        }
    }

    /// A pipe pair both ends use.
    fn live_pair(&self) -> bool {
        let usable = |st: Option<PipeState>| {
            matches!(
                st,
                Some(PipeState::Active | PipeState::Joining | PipeState::Suspect)
            )
        };
        self.links.iter().any(|(&id, l)| {
            l.healthy()
                && self.ends.iter().all(|s| {
                    s.pipe_info(PipeId(id))
                        .is_some_and(|i| usable(i.outbound) && i.inbound == Some(PipeState::Open))
                })
        })
    }

    /// Heals the network and runs it until everything is delivered and
    /// acknowledged (or the sessions end): stalls end, and a fresh pipe
    /// joins while no healthy pipe pair is left.
    fn settle(&mut self) {
        for l in self.links.values_mut() {
            for f in &mut l.flows {
                f.stalled = false;
            }
        }
        let deadline = self.now + Duration::from_secs(90);
        let mut last_add = None;
        while self.alive() && self.now < deadline {
            self.heal(&mut last_add);
            self.tick(usize::MAX);
            self.read_all(A);
            self.read_all(B);
            self.check();
            if self.complete() {
                return;
            }
            self.wait(10);
        }
    }

    /// Joins a fresh pipe while no healthy pipe pair is left, at most once
    /// a second.
    fn heal(&mut self, last_add: &mut Option<Instant>) {
        if !self.live_pair() && last_add.is_none_or(|t| self.now >= t + Duration::from_secs(1)) {
            *last_add = Some(self.now);
            self.join_pipe(&PipeOptions::default(), 256 * 1024, true, true);
        }
    }

    /// Lets acknowledgements, PIPE_ABANDON exchanges and retirement finish
    /// on a healed network (unilateral retirement waits up to max(2 s,
    /// 3 x PTO) after the acknowledgement): afterwards no attachment may be
    /// left with no live direction.
    fn linger(&mut self) {
        let mut last_add = None;
        for _ in 0..1_500 {
            if !self.alive() {
                return;
            }
            self.heal(&mut last_add);
            self.tick(usize::MAX);
            self.read_all(A);
            self.read_all(B);
            self.wait(20);
        }
        if !self.alive() {
            return;
        }
        for side in [A, B] {
            let dead: Vec<_> = self.ends[side]
                .pipes()
                .into_iter()
                .filter(|i| {
                    !matches!(
                        i.outbound,
                        Some(
                            PipeState::Active
                                | PipeState::Joining
                                | PipeState::Suspect
                                | PipeState::Draining
                        )
                    ) && i.inbound != Some(PipeState::Open)
                        && i.inbound != Some(PipeState::Joining)
                })
                // `abandon_after_a_failed_drain_is_sent`.
                .filter(|i| !self.s.drained[side].contains(&i.pipe))
                .map(|i| (i.pipe, i.inbound, i.outbound))
                .collect();
            assert!(
                dead.is_empty(),
                "end {side} ({:?}): attachments not retired after 30 s: {dead:?}",
                self.ends[side].state()
            );
        }
    }

    fn report(&self, label: &str) {
        if std::env::var_os("MP_FUZZ_STATS").is_none() {
            return;
        }
        let [a, b] = &self.s.peak;
        let bytes: u64 = self
            .s
            .streams
            .iter()
            .flat_map(|s| s.halves.iter().map(|h| h.sent))
            .sum();
        eprintln!(
            "MPFUZZ {label} streams={} bytes={bytes} dup={} reinj={} opp={} episodes={} fail={} penal={} fallback={} retained_max={} susp={} resumed={} joins={} refused={} late={}",
            self.s.streams.len(),
            a.bytes_duplicate + b.bytes_duplicate,
            a.bytes_reinjected + b.bytes_reinjected,
            a.bytes_opportunistic + b.bytes_opportunistic,
            a.reinjections + b.reinjections,
            a.pipe_failures + b.pipe_failures,
            a.penalties + b.penalties,
            a.scheduler_fallbacks + b.scheduler_fallbacks,
            a.retained.max(b.retained),
            self.s.cov.suspended,
            self.s.cov.resumed,
            self.links.values().filter(|l| l.attached()).count() - 1,
            self.links
                .values()
                .filter(|l| l.joined == Joined::Refused)
                .count(),
            self.s.cov.late_bytes,
        );
    }
}

/// The session ended: commands are no-ops.
fn lost(s: &SessionCore) -> bool {
    s.state() >= State::Closing
}

// ---- operations -----------------------------------------------------------------

#[derive(Debug, Clone)]
enum Break {
    /// The carrier is reset: both ends read an error, writes fail.
    Rst,
    /// One direction fails: its reader reads an error, its writer's
    /// writes fail.
    Error(usize),
    /// A middlebox ends one direction: its reader reads the end of stream,
    /// and what the writer sends from now on is lost.
    Eof(usize),
}

#[derive(Debug, Clone)]
enum TierChange {
    SendPriority(Option<u64>),
    ReceivePriority(u64),
    SendStandby(Option<bool>),
    ReceiveStandby(bool),
    Weight(u64),
    Probation(Option<Duration>),
    /// Revalidation of the pipe, or of every pipe.
    Revalidate(bool),
}

#[derive(Debug, Clone)]
enum Op {
    Open {
        side: usize,
        bidi: bool,
        len: usize,
        commit: bool,
    },
    Write {
        side: usize,
        sel: u8,
        len: usize,
        chunk: bool,
    },
    Finish {
        side: usize,
        sel: u8,
    },
    Reset {
        side: usize,
        sel: u8,
        boundary: bool,
    },
    Stop {
        side: usize,
        sel: u8,
    },
    Release {
        side: usize,
        sel: u8,
    },
    Read {
        side: usize,
        sel: u8,
        max: usize,
    },
    ReadAll(usize),
    /// One round: writes, then at most `limit` bytes per flow.
    Step(usize),
    Advance(u64),
    /// The network runs: `ms` in 10 ms ticks of at most `per_tick` bytes.
    Run {
        ms: u64,
        per_tick: usize,
    },
    Add {
        opts: PipeOptions,
        cap: usize,
        rst: bool,
    },
    Remove {
        side: usize,
        sel: u8,
        graceful: bool,
    },
    Break {
        sel: u8,
        how: Break,
    },
    /// 0: A to B, 1: B to A, 2: both.
    Stall {
        sel: u8,
        which: u8,
    },
    Unstall(u8),
    Delay {
        sel: u8,
        which: u8,
        ms: u64,
    },
    SetPolicy {
        side: usize,
        policy: Policy,
    },
    StreamPolicy {
        side: usize,
        sel: u8,
        policy: Option<Policy>,
    },
    Tier {
        side: usize,
        sel: u8,
        change: TierChange,
    },
}

fn side() -> impl Strategy<Value = usize> {
    prop_oneof![3 => Just(A), 2 => Just(B)]
}

fn data_len() -> impl Strategy<Value = usize> {
    prop_oneof![
        4 => 0usize..2_000,
        4 => 2_000usize..40_000,
        1 => 40_000usize..300_000,
    ]
}

fn pipe_options() -> impl Strategy<Value = PipeOptions> {
    (
        prop_oneof![3 => Just(0u64), 1 => Just(1u64)],
        prop_oneof![3 => Just(None), 1 => (0u64..4).prop_map(Some)],
        prop_oneof![3 => Just(0u64), 1 => 1u64..4],
        prop_oneof![4 => Just(None), 1 => any::<bool>().prop_map(Some)],
        prop_oneof![4 => Just(1u64), 1 => Just(0u64), 1 => 2u64..6, 1 => Just(u64::MAX)],
        prop_oneof![
            2 => Just(None),
            1 => Just(Some(Duration::ZERO)),
            1 => Just(Some(Duration::from_millis(300))),
        ],
        prop_oneof![3 => Just(None), 1 => Just(Some(Duration::from_millis(50)))],
        prop_oneof![3 => Just(None), 1 => Just(Some(Duration::from_secs(1)))],
    )
        .prop_map(
            |(fate, send, recv, standby, weight, probation, floor, dead)| {
                let mut o = PipeOptions::default();
                o.fate_group = fate;
                o.send_priority = send;
                o.receive_priority = recv;
                o.send_standby = standby;
                o.receive_standby = standby.unwrap_or(false);
                o.weight = weight;
                o.probation = probation;
                o.suspect_floor = floor;
                o.dead_timeout = dead;
                o
            },
        )
}

fn cap() -> impl Strategy<Value = usize> {
    prop_oneof![Just(16 * 1024), Just(64 * 1024), Just(1 << 20)]
}

fn tier_change() -> impl Strategy<Value = TierChange> {
    prop_oneof![
        prop_oneof![
            Just(None),
            (0u64..4).prop_map(Some),
            Just(Some((1 << 62) - 1))
        ]
        .prop_map(TierChange::SendPriority),
        prop_oneof![0u64..4, Just((1u64 << 62) - 1)].prop_map(TierChange::ReceivePriority),
        prop_oneof![Just(None), any::<bool>().prop_map(Some)].prop_map(TierChange::SendStandby),
        any::<bool>().prop_map(TierChange::ReceiveStandby),
        prop_oneof![0u64..4, Just(u64::MAX)].prop_map(TierChange::Weight),
        prop_oneof![
            Just(None),
            Just(Some(Duration::ZERO)),
            Just(Some(Duration::from_millis(200)))
        ]
        .prop_map(TierChange::Probation),
        any::<bool>().prop_map(TierChange::Revalidate),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    let sel = any::<u8>;
    prop_oneof![
        6 => (side(), any::<bool>(), data_len(), any::<bool>())
            .prop_map(|(side, b, len, commit)| Op::Open { side, bidi: b, len, commit }),
        8 => (side(), sel(), data_len(), any::<bool>())
            .prop_map(|(side, sel, len, chunk)| Op::Write { side, sel, len, chunk }),
        3 => (side(), sel()).prop_map(|(side, sel)| Op::Finish { side, sel }),
        1 => (side(), sel(), any::<bool>())
            .prop_map(|(side, sel, boundary)| Op::Reset { side, sel, boundary }),
        1 => (side(), sel()).prop_map(|(side, sel)| Op::Stop { side, sel }),
        1 => (side(), sel()).prop_map(|(side, sel)| Op::Release { side, sel }),
        5 => (side(), sel(), 1usize..100_000)
            .prop_map(|(side, sel, max)| Op::Read { side, sel, max }),
        2 => side().prop_map(Op::ReadAll),
        8 => prop_oneof![1usize..4_000, 4_000usize..70_000, Just(usize::MAX)].prop_map(Op::Step),
        6 => prop_oneof![4 => 1u64..30, 3 => 30u64..400, 1 => 400u64..3_000].prop_map(Op::Advance),
        4 => (1u64..600, prop_oneof![1usize..8_000, 8_000usize..200_000])
            .prop_map(|(ms, per_tick)| Op::Run { ms, per_tick }),
        3 => (pipe_options(), cap(), any::<bool>())
            .prop_map(|(opts, cap, rst)| Op::Add { opts, cap, rst }),
        1 => (side(), sel(), any::<bool>())
            .prop_map(|(side, sel, graceful)| Op::Remove { side, sel, graceful }),
        2 => (sel(), prop_oneof![
                Just(Break::Rst),
                (0usize..2).prop_map(Break::Error),
                (0usize..2).prop_map(Break::Eof),
            ])
            .prop_map(|(sel, how)| Op::Break { sel, how }),
        2 => (sel(), 0u8..3).prop_map(|(sel, which)| Op::Stall { sel, which }),
        2 => sel().prop_map(Op::Unstall),
        2 => (sel(), 0u8..3, prop_oneof![Just(0u64), 1u64..20, 20u64..300])
            .prop_map(|(sel, which, ms)| Op::Delay { sel, which, ms }),
        1 => (side(), policy()).prop_map(|(side, policy)| Op::SetPolicy { side, policy }),
        1 => (side(), sel(), prop::option::of(policy()))
            .prop_map(|(side, sel, policy)| Op::StreamPolicy { side, sel, policy }),
        2 => (side(), sel(), tier_change())
            .prop_map(|(side, sel, change)| Op::Tier { side, sel, change }),
    ]
}

fn setup() -> impl Strategy<Value = Setup> {
    (
        any::<bool>(),
        policy(),
        policy(),
        prop_oneof![2 => Just(false), 1 => Just(true)],
        prop_oneof![
            Just(Duration::from_millis(250)),
            Just(Duration::from_millis(50))
        ],
        prop_oneof![
            Just(None),
            Just(Some(Duration::ZERO)),
            Just(Some(Duration::from_millis(200)))
        ],
        prop_oneof![Just(16 * 1024), Just(4 * 1024)],
        prop_oneof![Just(2u32), Just(4u32), Just(8u32)],
        prop_oneof![3 => Just(None), 1 => Just(Some(Duration::from_secs(1)))],
        cap(),
        any::<bool>(),
        any::<u64>(),
    )
        .prop_map(
            |(resume, pa, pb, tight, floor, probation, chunk, max_pipes, dead, cap, rst, seed)| {
                Setup {
                    resume,
                    policies: [pa, pb],
                    tight_windows: tight,
                    suspect_floor: floor,
                    probation,
                    spread_chunk: chunk,
                    max_pipes,
                    dead_timeout: dead,
                    cap,
                    rst,
                    seed,
                }
            },
        )
}

impl Net {
    fn apply(&mut self, op: &Op) {
        match *op {
            Op::Open {
                side,
                bidi,
                len,
                commit,
            } => self.open(side, bidi, len, commit),
            Op::Write {
                side,
                sel,
                len,
                chunk,
            } => {
                self.accept_all(side);
                if let Some(&(t, h)) = pick(&self.sendable(side, false), sel) {
                    self.write_half(t, h, len, chunk);
                }
            }
            Op::Finish { side, sel } => {
                self.accept_all(side);
                if let Some(&(t, h)) = pick(&self.sendable(side, false), sel) {
                    self.finish(t, h);
                }
            }
            Op::Reset {
                side,
                sel,
                boundary,
            } => {
                self.accept_all(side);
                if let Some(&(t, h)) = pick(&self.sendable(side, true), sel) {
                    self.reset(t, h, boundary);
                }
            }
            Op::Stop { side, sel } => {
                self.accept_all(side);
                if let Some(&(t, h)) = pick(&self.receivable(side), sel) {
                    self.stop(t, h);
                }
            }
            Op::Release { side, sel } => {
                self.accept_all(side);
                let held: Vec<usize> = (0..self.s.streams.len())
                    .filter(|&t| self.s.streams[t].keys[side].is_some())
                    .collect();
                if let Some(&t) = pick(&held, sel) {
                    self.release(side, t);
                }
            }
            Op::Read { side, sel, max } => {
                self.accept_all(side);
                if let Some(&(t, h)) = pick(&self.receivable(side), sel) {
                    self.read_half(t, h, max);
                }
            }
            Op::ReadAll(side) => self.read_all(side),
            Op::Step(limit) => self.tick(limit),
            Op::Advance(ms) => self.wait(ms),
            Op::Run { ms, per_tick } => self.run(ms, per_tick),
            Op::Add { ref opts, cap, rst } => {
                self.join_pipe(opts, cap, rst, false);
            }
            Op::Remove {
                side,
                sel,
                graceful,
            } => {
                if let Some(id) = self.link_at(sel) {
                    let pipe = PipeId(id);
                    if self.ends[side]
                        .remove_pipe(pipe, graceful, self.now)
                        .is_ok()
                        && graceful
                    {
                        self.s.drained[side].push(pipe);
                    }
                    self.check_events();
                }
            }
            Op::Break { sel, ref how } => {
                if let Some(id) = self.link_at(sel) {
                    let l = self.links.get_mut(&id).expect("link");
                    match *how {
                        Break::Rst => {
                            for f in &mut l.flows {
                                f.reset = true;
                                f.write_err = true;
                            }
                        }
                        Break::Error(w) => {
                            l.flows[w].reset = true;
                            l.flows[w].write_err = true;
                        }
                        Break::Eof(w) => {
                            l.flows[w].fin = true;
                            l.flows[w].blackhole = true;
                        }
                    }
                }
            }
            Op::Stall { sel, which } => {
                if let Some(id) = self.link_at(sel) {
                    let l = self.links.get_mut(&id).expect("link");
                    for (w, f) in l.flows.iter_mut().enumerate() {
                        if which == 2 || usize::from(which) == w {
                            f.stalled = true;
                        }
                    }
                }
            }
            Op::Unstall(sel) => {
                if let Some(id) = self.link_at(sel) {
                    let l = self.links.get_mut(&id).expect("link");
                    for f in &mut l.flows {
                        if std::mem::take(&mut f.stalled) {
                            self.s.cov.late_bytes += f.queued as u64;
                        }
                    }
                }
            }
            Op::Delay { sel, which, ms } => {
                if let Some(id) = self.link_at(sel) {
                    let l = self.links.get_mut(&id).expect("link");
                    for (w, f) in l.flows.iter_mut().enumerate() {
                        if which == 2 || usize::from(which) == w {
                            f.delay = Duration::from_millis(ms);
                        }
                    }
                }
            }
            Op::SetPolicy { side, ref policy } => self.ends[side].set_scheduler(policy.clone()),
            Op::StreamPolicy {
                side,
                sel,
                ref policy,
            } => {
                if let Some(&(t, _)) = pick(&self.sendable(side, false), sel)
                    && let Some(key) = self.s.streams[t].keys[side]
                {
                    self.ends[side]
                        .set_stream_scheduler(key, policy.clone())
                        .unwrap();
                }
            }
            Op::Tier {
                side,
                sel,
                ref change,
            } => {
                if let Some(id) = self.link_at(sel) {
                    let pipe = PipeId(id);
                    let now = self.now;
                    let s = &mut self.ends[side];
                    let _ = match *change {
                        TierChange::SendPriority(p) => s.set_pipe_send_priority(pipe, p),
                        TierChange::ReceivePriority(p) => s.set_pipe_receive_priority(pipe, p),
                        TierChange::SendStandby(v) => s.set_pipe_send_standby(pipe, v),
                        TierChange::ReceiveStandby(v) => s.set_pipe_receive_standby(pipe, v),
                        TierChange::Weight(w) => s.set_pipe_weight(pipe, w),
                        TierChange::Probation(p) => s.set_pipe_probation(pipe, p),
                        TierChange::Revalidate(all) => {
                            s.revalidate_pipes((!all).then_some(pipe), now)
                        }
                    };
                    self.check_events();
                }
            }
        }
    }
}

/// `PipeOptions` from field values (the struct is non-exhaustive).
macro_rules! po {
    ($($field:ident: $value:expr),* $(,)?) => {{
        let mut o = PipeOptions::default();
        $(o.$field = $value;)*
        o
    }};
}

fn pick<T>(v: &[T], sel: u8) -> Option<&T> {
    v.get(sel as usize % v.len().max(1))
}

/// Runs a case: the operations, then (when both sessions survive) healing
/// and the completeness checks.
fn run_case(setup: &Setup, ops: &[Op]) {
    let mut n = net(setup);
    for op in ops {
        n.apply(op);
        n.check();
    }
    if n.alive() {
        n.settle();
    }
    if n.alive() {
        for (tag, s) in n.s.streams.iter().enumerate() {
            for h in (0..2).filter(|&h| s.has(h)) {
                if let Err(e) = n.half_complete(tag, h) {
                    panic!(
                        "{e} after settling; A {:?} B {:?}\nA pipes {:#?}\nB pipes {:#?}",
                        n.ends[A].stats(),
                        n.ends[B].stats(),
                        n.ends[A].pipes(),
                        n.ends[B].pipes()
                    );
                }
            }
        }
        for side in [A, B] {
            let st = n.ends[side].stats();
            assert!(
                st.retained == 0 && st.send_buffered == 0 && st.recv_buffered == 0,
                "end {side}: data left after settling: {st:?}"
            );
            assert_eq!(n.ends[side].held_bytes(), 0, "end {side}: held bytes");
        }
        n.linger();
        n.report("complete");
    } else {
        n.report("ended");
    }
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_shrink_iters: 20_000,
        ..ProptestConfig::default()
    })]

    /// Random traffic, faults and settings: every byte read is the byte
    /// written there, budgets hold, and a healed network completes every
    /// stream.
    #[test]
    fn exactly_once_under_churn(setup in setup(), ops in prop::collection::vec(op(), 1..120)) {
        run_case(&setup, &ops);
    }
}

/// BUG (`mpath.rs` `remove_pipe` and `fail_attachment`, `output.rs`
/// `write_abandon`): a graceful removal of a writable pipe queues its
/// PIPE_ABANDON(NO_ERROR) as the pipe's own last frame (`abandon_on_self`).
/// When the pipe fails before its next batch (an abrupt removal, a carrier
/// error), `fail_attachment` keeps that pending frame (the code is already
/// set) and `abandon_on_self` stays set, so `write_abandon` never puts it on
/// another pipe and the failed pipe writes nothing more. The frame is never
/// sent, so it is never acknowledged, and the attachment is never retired
/// at the remover (unilateral retirement also waits for that
/// acknowledgement, MULTIPATH.md Section 8.4): its state and a slot of the
/// unretired-attachment cap leak for the session's life. The peer retires
/// it on its own after 2 s. `abandon_on_self` must be cleared when the
/// attachment fails.
#[test]
fn abandon_after_a_failed_drain_is_sent() {
    for carrier_error in [false, true] {
        let setup = Setup {
            resume: false,
            policies: [Policy::Affinity, Policy::Affinity],
            tight_windows: false,
            suspect_floor: Duration::from_millis(250),
            probation: None,
            spread_chunk: 16 * 1024,
            max_pipes: 4,
            dead_timeout: None,
            cap: 64 * 1024,
            rst: false,
            seed: 0,
        };
        let mut n = net(&setup);
        assert!(n.join_pipe(&PipeOptions::default(), 64 * 1024, false, true));
        n.run(2_000, usize::MAX);
        let pipe = PipeId(2);
        n.ends[A].remove_pipe(pipe, true, n.now).unwrap();
        if carrier_error {
            for f in &mut n.links.get_mut(&pipe.0).unwrap().flows {
                f.reset = true;
                f.write_err = true;
            }
        } else {
            n.ends[A].remove_pipe(pipe, false, n.now).unwrap();
        }
        n.check_events();
        n.run(10_000, usize::MAX);
        assert!(n.alive());
        assert!(
            n.ends[A].pipe_info(pipe).is_none(),
            "carrier error {carrier_error}: {:?}",
            n.ends[A].pipe_info(pipe)
        );
    }
}

/// A custom policy whose every answer is out of range.
#[derive(Debug)]
struct OutOfRange;

impl Pick for OutOfRange {
    fn pick(&self, _: &[FrameInfo], _: &[PipeSnapshot], out: &mut [PickAnswer]) {
        for answer in out {
            *answer = PickAnswer::Pipe {
                index: usize::MAX,
                bytes: 0,
            };
        }
    }
}

/// BUG (`sched.rs` `custom_ok`, `SessionStats::scheduler_fallbacks`): a custom
/// policy's out-of-range answer falls back to `affinity`, but nothing ever
/// increments `scheduler_fallbacks` ("custom scheduler
/// answers that fell back"); `custom_ok` takes `&self` and cannot count.
#[test]
fn custom_policy_fallbacks_are_counted() {
    let custom = Policy::Custom(Arc::new(OutOfRange));
    let setup = Setup {
        resume: false,
        policies: [custom.clone(), custom],
        tight_windows: false,
        suspect_floor: Duration::from_millis(250),
        probation: None,
        spread_chunk: 16 * 1024,
        max_pipes: 4,
        dead_timeout: None,
        cap: 64 * 1024,
        rst: false,
        seed: 0,
    };
    let mut n = net(&setup);
    assert!(n.join_pipe(&PipeOptions::default(), 64 * 1024, false, true));
    n.run(1_500, usize::MAX);
    n.open(A, true, 100_000, false);
    n.run(500, usize::MAX);
    assert_eq!(
        n.s.streams[0].halves[0].read, 100_000,
        "the fallback carries the data"
    );
    assert!(
        n.ends[A].stats().scheduler_fallbacks > 0,
        "{:?}",
        n.ends[A].stats()
    );
}

/// BUG (`opp.rs` `session_blocking` and `stream_blocking`, `output.rs`
/// `write_copy`): opportunistic reinjection picks the oldest unacknowledged
/// STREAM frame from the pipe logs without checking whether the stream's
/// sending part was reset; after RESET_STREAM (or above the Reliable Size
/// of RESET_STREAM_AT) the send buffer no longer holds those bytes, and
/// `write_copy` fills the frame with zeros when `copy_kept` fails
/// (`dst.fill(0)`). The peer receives zeros as stream data and, when the
/// RESET_STREAM is still in flight on a slow pipe, delivers them to the
/// application: here end A reads 3294 zero bytes of a stream end B reset
/// (B's statistics: `bytes_opportunistic` 28435, `bytes_reinjected` 0). The
/// copy must skip reset data exactly as `reinject_frame` does (only ranges
/// below the Reliable Size), and `write_copy` must never send bytes it does
/// not hold. Found by `exactly_once_under_churn` (minimized; the network is
/// deterministic, the case replays the same way every run).
#[test]
fn opportunistic_copy_of_a_reset_stream() {
    let setup = Setup {
        resume: false,
        policies: [Policy::Affinity, Policy::Affinity],
        tight_windows: true,
        suspect_floor: Duration::from_millis(250),
        probation: Some(Duration::from_nanos(0)),
        spread_chunk: 16384,
        max_pipes: 8,
        dead_timeout: None,
        cap: 65536,
        rst: false,
        seed: 1,
    };
    let ops = vec![
        Op::Add {
            opts: po! { fate_group: 0, send_priority: None, receive_priority: 0, send_standby: None, weight: 1, probation: None, suspect_floor: None, dead_timeout: None, },
            cap: 16384,
            rst: false,
        },
        Op::Open {
            side: 1,
            bidi: true,
            len: 62234,
            commit: true,
        },
        Op::Open {
            side: 1,
            bidi: true,
            len: 8755,
            commit: false,
        },
        Op::Stall { sel: 100, which: 1 },
        Op::Open {
            side: 1,
            bidi: true,
            len: 3294,
            commit: false,
        },
        Op::Add {
            opts: po! { fate_group: 0, send_priority: None, receive_priority: 0, send_standby: None, weight: 1, probation: Some( Duration::from_millis(300), ), suspect_floor: Some( Duration::from_millis(50), ), dead_timeout: None, },
            cap: 16384,
            rst: false,
        },
        Op::Add {
            opts: po! { fate_group: 0, send_priority: None, receive_priority: 0, send_standby: Some( true, ), receive_standby: true, weight: 1, probation: None, suspect_floor: None, dead_timeout: None, },
            cap: 16384,
            rst: true,
        },
        Op::Step(18446744073709551615),
        Op::Step(41644),
        Op::Advance(918),
        Op::Reset {
            side: 1,
            sel: 149,
            boundary: false,
        },
        Op::Add {
            opts: po! { fate_group: 0, send_priority: None, receive_priority: 0, send_standby: None, weight: 1, probation: Some( Duration::from_millis(300), ), suspect_floor: None, dead_timeout: None, },
            cap: 1048576,
            rst: true,
        },
        Op::Write {
            side: 1,
            sel: 229,
            len: 268770,
            chunk: true,
        },
        Op::Step(638),
        Op::Step(66061),
        Op::Open {
            side: 0,
            bidi: true,
            len: 611,
            commit: false,
        },
        Op::Advance(205),
        Op::Open {
            side: 0,
            bidi: true,
            len: 35886,
            commit: false,
        },
        Op::Run {
            ms: 248,
            per_tick: 2805,
        },
    ];
    // Every byte read is checked against what was written: zeros of a
    // reset stream would fail there.
    let mut n = net(&setup);
    for op in &ops {
        n.apply(op);
        n.check();
    }
}

/// The reader's session ended before the data below a RESET_STREAM_AT's
/// Reliable Size arrived: `read` reports `Reset { reliable_size: 2 }`
/// although none of those bytes was read.
fn reset_then_session_loss() -> (Net, usize) {
    let setup = Setup {
        resume: false,
        policies: [Policy::Affinity, Policy::SpreadRoundRobin],
        tight_windows: false,
        suspect_floor: Duration::from_millis(250),
        probation: Some(Duration::ZERO),
        spread_chunk: 16 * 1024,
        max_pipes: 2,
        dead_timeout: None,
        cap: 16 * 1024,
        rst: false,
        seed: 0,
    };
    // Found by `exactly_once_under_churn` (minimized).
    let ops = [
        Op::Write {
            side: B,
            sel: 0,
            len: 0,
            chunk: false,
        },
        Op::Add {
            opts: PipeOptions::default(),
            cap: 16 * 1024,
            rst: false,
        },
        Op::Run {
            ms: 11,
            per_tick: 31,
        },
        Op::Open {
            side: B,
            bidi: false,
            len: 1,
            commit: false,
        },
        Op::Step(1),
        Op::Write {
            side: B,
            sel: 0,
            len: 1,
            chunk: false,
        },
        Op::Stall { sel: 31, which: 1 },
        Op::Step(16),
        Op::Reset {
            side: B,
            sel: 0,
            boundary: true,
        },
        Op::Break {
            sel: 67,
            how: Break::Rst,
        },
        Op::Run {
            ms: 11,
            per_tick: 32,
        },
        Op::Remove {
            side: A,
            sel: 6,
            graceful: false,
        },
    ];
    let mut n = net(&setup);
    for op in &ops {
        n.apply(op);
    }
    (n, 0)
}

/// MINOR BUG (`api.rs` `readable`): after the session ended, a stream that
/// received RESET_STREAM_AT reports `StreamError::Reset { reliable_size }`
/// even when the data below the Reliable Size never arrived (`read_offset <
/// reliable`), because the reset branch also fires on `lost.is_some()`.
/// `reliable_size` is documented as the application bytes delivered before
/// the reset took effect, and STATE_MACHINE.md Section 2.5 reports the
/// reset only "after reliable data read"; the read should report the
/// session error (`SessionLost`) instead.
#[test]
fn reset_after_session_loss_claims_unread_reliable_data() {
    let (mut n, tag) = reset_then_session_loss();
    assert!(lost(&n.ends[A]), "the reader's session ended");
    n.accept_all(A);
    let key = n.s.streams[tag].keys[A].expect("accepted");
    let mut buf = [0u8; 16];
    match n.ends[A].read(key, &mut buf) {
        Err(StreamError::Reset { reliable_size, .. }) => assert!(
            n.s.streams[tag].halves[0].read >= reliable_size,
            "Reset claims {reliable_size} reliable bytes, {} read",
            n.s.streams[tag].halves[0].read
        ),
        other => assert!(
            matches!(other, Err(StreamError::SessionLost(_))),
            "{other:?}"
        ),
    }
}
