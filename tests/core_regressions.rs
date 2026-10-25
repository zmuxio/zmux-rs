//! Regression tests from the review of the session core: two cores
//! connected in memory.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;
use zmux::VarInt;
use zmux::proto::frame::Dir;
use zmux::proto::record::Framing;
use zmux::proto::session::{
    Cap, Config, OpenError, Preamble, RoleConfig, SessionCore, State, StreamKey, TransmitBuf,
};

#[path = "common/core_pair.rs"]
mod core_pair;

use core_pair::{CorePair as Pair, P0};

fn take(s: &mut SessionCore, out: &mut TransmitBuf, now: Instant) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut n = 0;
    while s.wants_write(P0) {
        s.poll_transmit(P0, now, out);
        if out.is_empty() {
            break;
        }
        out.copy_to_vec(&mut wire);
        n += 1;
        assert!(n < 10_000, "runaway");
    }
    wire
}

#[test]
fn receive_window_set_before_first_frame_is_advertised() {
    let mut p = Pair::new(Config::default(), Config::default());
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.set_receive_window(k, 1 << 20, 16 << 20).unwrap();
    p.a.write(k, b"req").unwrap();
    p.a.finish(k).unwrap();
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().unwrap();
    let total = 600 * 1024;
    let data = vec![7u8; total];
    let mut written = 0;
    let mut got = 0;
    let mut buf = vec![0u8; 64 * 1024];
    for _ in 0..200 {
        while written < total {
            match p.b.write(s, &data[written..]).unwrap() {
                0 => break,
                n => written += n,
            }
        }
        p.pump();
        while let Some((n, _)) = p.a.read(k, &mut buf).unwrap() {
            got += n;
            if n == 0 {
                break;
            }
        }
        p.pump();
    }
    assert_eq!(
        got, total,
        "peer stalled after {got} bytes (written {written})"
    );
}

#[test]
fn session_credit_stall_does_not_spin() {
    let mut a_cfg = Config::default();
    a_cfg.test_hooks().grease_tlv = Some((0x21, Vec::new()));
    let mut b_cfg = Config::default();
    b_cfg.initial_stream_receive_window = 65_436;
    b_cfg.initial_connection_receive_window = 65_536;
    b_cfg.max_incoming_uni_streams = Some(4);
    let mut p = Pair::new(a_cfg, b_cfg);
    let k1 = p.a.open(Dir::Uni).unwrap();
    let data = vec![1u8; 70_000];
    let mut written = 0;
    while written < data.len() {
        match p.a.write(k1, &data[written..]).unwrap() {
            0 => break,
            n => written += n,
        }
    }
    // Everything A may send goes out; B's credit is not delivered (its
    // application does not read and B is at its buffer cap).
    let _ = take(&mut p.a, &mut p.out, p.now);
    let k2 =
        p.a.open_with(Dir::Uni, &Preamble::new().with_info(vec![b'x'; 200]))
            .unwrap();
    p.a.write(k2, b"y").unwrap();
    // At most one empty poll, then `wants_write` turns false until MAX_DATA
    // arrives: a driver never spins.
    let mut empty = 0;
    for _ in 0..10 {
        if !p.a.wants_write(P0) {
            break;
        }
        p.a.poll_transmit(P0, p.now, &mut p.out);
        if p.out.is_empty() {
            empty += 1;
        }
    }
    assert!(
        empty <= 1,
        "{empty} empty polls while wants_write() was true"
    );
    assert!(!p.a.wants_write(P0));
}

#[test]
fn small_send_records_still_carry_stream_data() {
    let mut a_cfg = Config::default();
    a_cfg.max_send_record = 1024; // accepted by Config::validate
    let mut b_cfg = Config::default();
    b_cfg.max_incoming_uni_streams = Some(4);
    let mut p = Pair::new(a_cfg, b_cfg);
    let k = p.a.open(Dir::Uni).unwrap();
    p.a.write(k, &[5u8; 5000]).unwrap();
    p.pump();
    let wants = p.a.wants_write(P0);
    p.a.poll_transmit(P0, p.now, &mut p.out);
    let s = p.b.accept(Dir::Uni).unwrap();
    assert!(
        s.is_some(),
        "stream never sent; wants_write={wants}, batch empty={}",
        p.out.is_empty()
    );
}

#[test]
fn memory_pressure_rejects_before_offering() {
    let now = Instant::now();
    let tp = {
        let s = SessionCore::new(Config::default(), RoleConfig::Initiator, None, now).unwrap();
        let mut tp = s.local_parameters();
        tp.zmux_preamble = None;
        tp
    };
    let mut a_cfg = Config::default();
    a_cfg.test_hooks().transport_parameters = Some(tp);
    let mut p = Pair::new(a_cfg, Config::default());
    assert!(!p.b.features().preamble);
    p.b.set_memory_pressure(true);
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"request").unwrap();
    // One flight A -> B; B's application accepts before the peer answers
    // the rejection.
    p.send(true);
    let offered = p.b.accept(Dir::Bidi).unwrap();
    assert_eq!(
        offered, None,
        "a stream rejected under memory pressure was offered"
    );
}

#[test]
fn shutdown_completed_by_release_still_writes_close() {
    let mut p = Pair::new(Config::default(), Config::default());
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"x").unwrap();
    p.a.finish(k).unwrap();
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().unwrap();
    p.now += Duration::from_secs(10);
    p.a.handle_timeout(p.now);
    p.b.handle_timeout(p.now);
    p.b.shutdown(VarInt::ZERO, b"bye", p.now);
    p.pump();
    let mut buf = [0u8; 16];
    loop {
        match p.b.read(s, &mut buf).unwrap() {
            Some((_, true)) => break,
            Some(_) => {}
            None => panic!("no data"),
        }
    }
    p.b.finish(s).unwrap();
    p.b.release(s);
    // The FIN goes out, the stream is discarded and the shutdown closes.
    p.b.poll_transmit(P0, p.now, &mut p.out);
    assert_eq!(p.b.state(), State::Closing);
    // The std driver runs due timers before it transmits.
    p.b.handle_timeout(p.now);
    assert_eq!(p.b.state(), State::Closing, "the close is still written");
    let wire = take(&mut p.b, &mut p.out, p.now);
    assert!(!wire.is_empty());
    assert!(p.b.poll_timeout().unwrap() > p.now, "lingers from now");
}

/// B shuts down while A's stream 0 is open; returns B's final GOAWAY
/// (watermark 1) without delivering it.
fn goaway_setup() -> (Pair, Vec<u8>) {
    let mut p = Pair::new(Config::default(), Config::default());
    let k0 = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k0, b"first").unwrap();
    p.pump();
    let _s0 = p.b.accept(Dir::Bidi).unwrap().unwrap();
    p.b.shutdown(VarInt::ZERO, b"", p.now);
    let w = take(&mut p.b, &mut p.out, p.now);
    p.a.receive(P0, &w, p.now);
    let w = take(&mut p.a, &mut p.out, p.now);
    p.b.receive(P0, &w, p.now);
    let held = take(&mut p.b, &mut p.out, p.now);
    assert!(!held.is_empty());
    (p, held)
}

#[test]
fn no_stream_opens_after_a_goaway() {
    // A has the peer's first GOAWAY: nothing new opens, whatever the
    // watermarks (EXTENSIONS.md Section 3.5 rule 2).
    let (mut p, held) = goaway_setup();
    assert!(matches!(p.a.open(Dir::Bidi), Err(OpenError::GoingAway)));
    p.a.receive(P0, &held, p.now);
    p.pump();
    assert!(matches!(p.a.open(Dir::Uni), Err(OpenError::GoingAway)));
    assert_eq!(p.b.stats().streams_opened_remote, 1);
}

#[test]
fn stream_datagrams_stay_within_session_limit() {
    let mut cfg = Config::default();
    cfg.enable_datagrams = true;
    let mut p = Pair::new(cfg.clone(), cfg);
    let mut keys = Vec::new();
    for _ in 0..4 {
        let k = p.a.open(Dir::Bidi).unwrap();
        p.a.write(k, b"o").unwrap();
        keys.push(k);
    }
    p.pump();
    let mut peer = Vec::new();
    while let Some(s) = p.b.accept(Dir::Bidi).unwrap() {
        peer.push(s);
    }
    assert_eq!(peer.len(), 4);
    let payload = Bytes::from(vec![9u8; 16_000]);
    for &k in &keys {
        for _ in 0..32 {
            p.a.send_stream_datagram(k, 0, payload.clone(), true)
                .unwrap();
            p.pump();
        }
    }
    let mut held = 0usize;
    for &s in &peer {
        while let Ok(Some((_, d))) = p.b.recv_stream_datagram(s) {
            held += d.len();
        }
    }
    assert!(
        held <= 1 << 20,
        "held {held} bytes of unread datagrams, above the 1 MiB session limit"
    );
}

#[test]
fn stale_clock_linger_still_writes_close() {
    let mut p = Pair::new(Config::default(), Config::default());
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"x").unwrap();
    p.a.finish(k).unwrap();
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().unwrap();
    p.b.shutdown(VarInt::ZERO, b"bye", p.now);
    p.b.finish(s).unwrap();
    p.pump();
    // No I/O for 10 s; then the application reads the end and drops the
    // stream, which completes the shutdown.
    p.now += Duration::from_secs(10);
    let mut buf = [0u8; 16];
    while let Some((_, fin)) = p.b.read(s, &mut buf).unwrap() {
        if fin {
            break;
        }
    }
    p.b.release(s);
    assert_eq!(p.b.state(), State::Closing);
    // The deadline came from a stale clock: the first expiry gives the
    // close a linger period from now instead of dropping it.
    p.b.handle_timeout(p.now);
    assert_eq!(p.b.state(), State::Closing);
    assert!(p.b.wants_write(P0));
    let wire = take(&mut p.b, &mut p.out, p.now);
    assert!(!wire.is_empty(), "CONNECTION_CLOSE written");
    assert!(p.b.poll_timeout().unwrap() > p.now);
}

#[test]
fn stop_before_first_frame_is_sent_with_it() {
    let mut p = Pair::new(Config::default(), Config::default());
    let k = p.a.open(Dir::Bidi).unwrap();
    // `let (mut send, _) = session.open_bi()` drops the receiving half here.
    p.a.release_recv(k);
    p.a.write(k, b"req").unwrap();
    p.a.finish(k).unwrap();
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().unwrap();
    let data = vec![1u8; 600 * 1024];
    let mut written = 0;
    let mut result = Ok(0);
    for _ in 0..50 {
        result = p.b.write(s, &data[written..]);
        if let Ok(n) = result {
            written += n;
        } else {
            break;
        }
        p.pump();
    }
    assert!(
        result.is_err(),
        "peer never learns of the stop: wrote {written} bytes, last write {result:?}"
    );
}

#[test]
fn config_out_of_varint_range_is_rejected() {
    let now = Instant::now();
    let mut cfg = Config::default();
    cfg.max_idle_timeout = Duration::MAX;
    assert!(SessionCore::new(cfg, RoleConfig::Initiator, None, now).is_err());
    let mut cfg = Config::default();
    cfg.max_connection_receive_window = zmux::Cap::Fixed(1 << 62);
    assert!(SessionCore::new(cfg, RoleConfig::Initiator, None, now).is_err());
    let mut cfg = Config::default();
    cfg.send_buffer = 0;
    assert!(SessionCore::new(cfg, RoleConfig::Initiator, None, now).is_err());
}

#[test]
fn pinned_openings_go_out_in_identifier_order() {
    // A peer advertising less than the floor (scripted, as a plain peer
    // may): 250 bytes of session credit.
    let mut b_cfg = Config::default();
    b_cfg.test_hooks().transport_parameters = Some(zmux::proto::params::TransportParameters {
        initial_max_data: Some(250),
        initial_max_streams_bidi: Some(16),
        initial_max_stream_data_bidi_remote: Some(65536),
        initial_max_stream_data_bidi_local: Some(65536),
        initial_max_stream_data_uni: Some(65536),
        zmux_preamble: Some(4096),
        reset_stream_at: true,
        zmux_pipe_ack: true,
        ..Default::default()
    });
    let mut p = Pair::new(Config::default(), b_cfg);
    let s1 =
        p.a.open_with(Dir::Bidi, &Preamble::new().with_info(vec![b'x'; 300]))
            .unwrap();
    let s2 = p.a.open(Dir::Bidi).unwrap();
    assert_eq!(p.a.stream_id(s1), Ok(0));
    assert_eq!(p.a.stream_id(s2), Ok(4));
    // The first opening does not fit in the session credit; the second
    // would, but must not precede it.
    p.send(true);
    assert_eq!(p.b.stats().streams_opened_remote, 0);
    assert!(!p.a.wants_write(P0), "no spinning while blocked");
}

#[test]
fn shutdown_before_establishment_drains_after_it() {
    let mut p = Pair::attached(Config::default(), Config::default());
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"x").unwrap();
    p.a.shutdown(VarInt::from_u32(4), b"bye", p.now);
    p.pump();
    assert_eq!(p.a.state(), State::Draining);
    let s = p.b.accept(Dir::Bidi).unwrap().unwrap();
    p.b.finish(s).unwrap();
    p.b.release(s);
    p.a.finish(k).unwrap();
    p.a.release(k);
    p.pump();
    assert!(p.a.state() >= State::Closing, "{:?}", p.a.state());
    assert!(matches!(
        p.b.error(),
        Some(zmux::SessionError::ApplicationClosed { remote: true, .. })
    ));
}

/// With pipe acknowledgement on a single pipe, the sender's sample state is
/// bounded: past its limit a batch joins the latest entry. An endpoint
/// that only acknowledges for a long time fills it with batches nobody
/// acknowledges (PIPE_ACK alone elicits nothing); its next data must not
/// inherit their old send time, which made an RTT sample of seconds: after 120 s of receiving only,
/// every sample of a 1 MiB write and the smoothed RTT stay within one
/// acknowledgement delay (25 ms) and one 30 ms step.
#[test]
fn pipe_ack_samples_after_a_long_receive_only_period_stay_fresh() {
    let mut p = Pair::new(Config::default(), Config::default());
    let k = p.b.open(Dir::Uni).unwrap();
    let mut sink = vec![0u8; 64 * 1024];
    let mut recv = None;
    let step = Duration::from_millis(30);
    for _ in 0..4000 {
        p.b.write(k, &[1u8; 200]).unwrap();
        p.pump();
        let r = *recv.get_or_insert_with(|| p.a.accept(Dir::Uni).unwrap().expect("stream"));
        while let Some((n, _)) = p.a.read(r, &mut sink).unwrap() {
            if n == 0 {
                break;
            }
        }
        p.now += step;
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.pump();
    }
    let s = p.a.open(Dir::Uni).unwrap();
    let mut left = 1usize << 20;
    let mut peer = None;
    let mut samples = 0;
    let bound = Duration::from_millis(60);
    for _ in 0..10_000 {
        if left > 0 {
            left -= p.a.write(s, &vec![2u8; left.min(64 * 1024)]).unwrap();
        }
        p.pump();
        let r = *peer.get_or_insert_with(|| p.b.accept(Dir::Uni).unwrap().expect("stream"));
        while let Some((n, _)) = p.b.read(r, &mut sink).unwrap() {
            if n == 0 {
                break;
            }
        }
        p.now += step;
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.pump();
        let st = p.a.stats();
        if let Some(latest) = st.latest_rtt {
            samples += 1;
            assert!(latest <= bound, "RTT sample {latest:?}");
            let srtt = st.smoothed_rtt.expect("a smoothed RTT");
            assert!(srtt <= bound, "smoothed RTT {srtt:?}");
        }
        if left == 0 && p.a.stream_stats(s).is_none_or(|x| x.send_buffered == 0) {
            break;
        }
    }
    assert_eq!(left, 0, "the 1 MiB was not written");
    assert!(samples > 0, "no RTT sample");
}

/// One endpoint of a [`Line`]: its core, its timer, the stream it keeps
/// full while `bulk`, and the bytes its application read.
struct End {
    s: SessionCore,
    timer: Option<Instant>,
    bulk: bool,
    send: Option<StreamKey>,
    recv: Vec<StreamKey>,
    read: u64,
    /// Batches on their way to the other end: arrival time and bytes.
    line: VecDeque<(Instant, Vec<u8>)>,
    /// When the bottleneck towards the other end has sent what it holds.
    busy: Instant,
}

/// A single pipe with pipe acknowledgement over a carrier that reports
/// nothing, so the carrier queue limiter paces it, behind a delay line like the
/// `shaped` carrier of the session
/// benchmark: a bottleneck of `rate` bytes per second in each direction,
/// then `owd` of propagation, read 64 KiB at a time and delivered on whole
/// milliseconds. The endpoints are driven as the tokio driver drives them:
/// every batch the core offers is written at once and received bytes are
/// processed on arrival; the timer is armed no earlier than 1 ms from now,
/// moved only to an earlier deadline or once it passed, and fires on a
/// whole millisecond, then `late` later, as a host that is not idle wakes.
struct Line {
    ends: [End; 2],
    out: TransmitBuf,
    start: Instant,
    now: Instant,
    rate: f64,
    owd: Duration,
    late: Duration,
    chunk: Bytes,
}

impl Line {
    fn new(rate_bps: f64, owd: Duration, late: Duration, config: impl Fn() -> Config) -> Self {
        let now = Instant::now();
        let end = |role| {
            let mut s = SessionCore::new(config(), role, None, now).unwrap();
            s.attach_pipe(P0, Framing::ByteStream, now);
            End {
                s,
                timer: None,
                bulk: false,
                send: None,
                recv: Vec::new(),
                read: 0,
                line: VecDeque::new(),
                busy: now,
            }
        };
        let mut l = Self {
            ends: [end(RoleConfig::Initiator), end(RoleConfig::Responder)],
            out: TransmitBuf::default(),
            start: now,
            now,
            rate: rate_bps / 8.0,
            owd,
            late,
            chunk: Bytes::from(vec![7u8; 64 * 1024]),
        };
        l.react();
        l
    }

    /// The first whole millisecond at or after `t`.
    fn ms(&self, t: Instant) -> Instant {
        let ms = t
            .saturating_duration_since(self.start)
            .as_nanos()
            .div_ceil(1_000_000);
        self.start + Duration::from_millis(u64::try_from(ms).unwrap())
    }

    /// The applications and the writers after an event: a bulk sender
    /// keeps its stream's send buffer full, everything received is read,
    /// and both ends write what their cores offer.
    fn react(&mut self) {
        let now = self.now;
        for i in 0..2 {
            let e = &mut self.ends[i];
            while e.s.poll_event().is_some() {}
            if e.bulk && e.s.is_established() {
                let k = *e.send.get_or_insert_with(|| e.s.open(Dir::Uni).unwrap());
                while e.s.write_chunk(k, self.chunk.clone()).unwrap() > 0 {}
            }
            while let Some(k) = e.s.accept(Dir::Uni).unwrap() {
                e.recv.push(k);
            }
            let mut buf = [0u8; 64 * 1024];
            for &k in &e.recv {
                while let Ok(Some((n, _))) = e.s.read(k, &mut buf) {
                    if n == 0 {
                        break;
                    }
                    e.read += n as u64;
                }
            }
            let mut n = 0;
            while e.s.wants_write(P0) {
                e.s.poll_transmit(P0, now, &mut self.out);
                if self.out.is_empty() {
                    break;
                }
                let mut v = Vec::new();
                self.out.copy_to_vec(&mut v);
                for piece in v.chunks(64 * 1024) {
                    e.busy =
                        e.busy.max(now) + Duration::from_secs_f64(piece.len() as f64 / self.rate);
                    let ms = (e.busy + self.owd).saturating_duration_since(self.start);
                    let at = self.start
                        + Duration::from_millis(
                            u64::try_from(ms.as_nanos().div_ceil(1_000_000)).unwrap(),
                        );
                    e.line.push_back((at, piece.to_vec()));
                }
                n += 1;
                assert!(n < 100_000, "runaway");
            }
            while e.s.poll_event().is_some() {}
        }
        for i in 0..2 {
            let due = self.ends[i]
                .s
                .poll_timeout()
                .map(|t| t.max(now + Duration::from_millis(1)));
            let armed = self.ends[i].timer;
            let passed = armed.is_some_and(|t| self.fires(t) <= now);
            self.ends[i].timer = match due {
                Some(d) if passed || armed.is_none_or(|t| d < t) => Some(d),
                _ if passed => None,
                _ => armed,
            };
        }
    }

    /// When a timer armed for `t` fires.
    fn fires(&self, t: Instant) -> Instant {
        self.ms(t) + self.late
    }

    /// Runs until `until`, event by event.
    fn run(&mut self, until: Instant) {
        loop {
            let next = self
                .ends
                .iter()
                .flat_map(|e| [e.line.front().map(|x| x.0), e.timer.map(|t| self.fires(t))])
                .flatten()
                .min();
            let Some(t) = next.filter(|&t| t <= until) else {
                self.now = until;
                return;
            };
            self.now = self.now.max(t);
            let now = self.now;
            for i in 0..2 {
                while let Some((_, v)) = self.ends[i].line.pop_front_if(|x| x.0 <= now) {
                    self.ends[1 - i].s.receive(P0, &v, now);
                }
            }
            for i in 0..2 {
                let fired = self.ends[i].timer.is_some_and(|t| self.fires(t) <= now);
                let e = &mut self.ends[i];
                if fired && e.s.poll_timeout().is_some_and(|t| t <= now) {
                    e.s.handle_timeout(now);
                }
            }
            self.react();
        }
    }

    /// What end `i`'s application read each second over `secs` seconds,
    /// in bits per second.
    fn per_second(&mut self, i: usize, secs: u64) -> Vec<f64> {
        let mut v = Vec::new();
        for _ in 0..secs {
            let before = self.ends[i].read;
            self.run(self.now + Duration::from_secs(1));
            v.push((self.ends[i].read - before) as f64 * 8.0);
        }
        v
    }
}

/// A single paced pipe on a long fat path keeps its rate. The drivers'
/// timers let a pipe that the limiter's bucket holds back go later than its
/// release time; when that lateness was lost to the bucket's depth, the
/// pipe sent below its pacing rate, its bottleneck samples fell below R_p,
/// and R_p decayed round by round to a fraction of the path while the RTT
/// stayed at the base (100 Mbit/s x 100 ms: 33 Mbit/s after 12 s, with a
/// timer half a millisecond late). Timers 0.5 and
/// 2 ms late.
#[test]
fn paced_single_pipe_keeps_the_rate_of_a_long_fat_path() {
    let rate = 100e6;
    // A quantum of R_p x G, not of two chunks, at this rate (spread_chunk
    // 4 KiB), or the default one of two chunks (2.6 ms at this rate, which
    // the bucket's two quanta cover with timers 2 ms late).
    for (late, chunk) in [
        (Duration::from_micros(500), Some(4096)),
        (Duration::from_millis(2), None),
    ] {
        let mut l = Line::new(rate, Duration::from_millis(50), late, || {
            let mut c = Config::default();
            if let Some(chunk) = chunk {
                c.spread_chunk = chunk;
            }
            c
        });
        l.ends[0].bulk = true;
        let per_s = l.per_second(1, 12);
        let last = per_s[7..].iter().sum::<f64>() / 5.0;
        assert!(
            last >= 0.9 * rate,
            "{late:?} late, chunk {chunk:?}: {:?} Mbit/s",
            per_s.iter().map(|r| (r / 1e6) as u64).collect::<Vec<_>>()
        );
    }
}

/// The in-flight cap of the carrier queue limiter counts what the peer
/// acknowledges. An endpoint that only receives sends records of PIPE_ACK
/// alone, which elicit no acknowledgement; counted in flight, they filled
/// the cap after a few seconds of receiving at 1 Gbit/s (the rate estimate
/// of a pipe that sent nothing is the initial 1 MB/s), and the pipe was
/// held back for good: the data written then never left (RFC 9002 Section 2).
#[test]
fn paced_pipe_of_a_receiving_endpoint_is_not_held_by_its_acknowledgements() {
    let mut l = Line::new(1e9, Duration::from_millis(1), Duration::ZERO, || {
        let mut c = Config::default();
        c.spread_chunk = 1024;
        // No credit update, which would elicit an acknowledgement, within
        // the test.
        let w = 16 << 30;
        c.initial_stream_receive_window = w;
        c.max_stream_receive_window = Cap::Fixed(w);
        c.initial_connection_receive_window = w;
        c.max_connection_receive_window = Cap::Fixed(w);
        c
    });
    l.ends[1].bulk = true;
    l.run(l.now + Duration::from_secs(4));
    l.ends[1].bulk = false;
    l.run(l.now + Duration::from_millis(100));
    let a = &mut l.ends[0].s;
    let k = a.open(Dir::Uni).unwrap();
    a.write(k, &[1u8; 4096]).unwrap();
    a.finish(k).unwrap();
    l.react();
    l.run(l.now + Duration::from_secs(1));
    assert_eq!(l.ends[1].read, 4096);
}

/// BUG (`mpath.rs` `set_pipe_unsent`): a carrier's unsent count reported on
/// a single-pipe session reached the multipath state of the pipe, which a
/// single-pipe session does not have, and panicked.
#[test]
fn unsent_counts_on_a_single_pipe_are_taken() {
    let mut p = Pair::new(Config::default(), Config::default());
    let now = p.now;
    p.a.set_pipe_unsent(P0, 1000, now);
    p.a.set_pipe_unsent(P0, 0, now);
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"x").unwrap();
    p.pump();
    assert!(p.b.accept(Dir::Bidi).unwrap().is_some());
}

/// Carrier early data that the carrier rejects (SPEC.md Section 6.1.2):
/// nothing reached the peer, so a unidirectional stream finished and
/// released meanwhile, a bidirectional one with its FIN and one reset with
/// a reliable prefix all go again once the peer's parameters arrive, with
/// none of them failed or lost.
#[test]
fn rejected_carrier_early_data_is_sent_again_whole() {
    let mut a_cfg = Config::default();
    a_cfg.early_data = zmux::EarlyData::default().with_carrier_early_data(true);
    let mut p = Pair::attached(a_cfg, Config::default());
    // The server's parameters, as remembered from an earlier session.
    let remembered = p.b.local_parameters();
    assert!(p.a.assume_remembered(&remembered));
    let uni = p.a.open(Dir::Uni).unwrap();
    p.a.write(uni, b"uni data").unwrap();
    p.a.finish(uni).unwrap();
    p.a.release(uni);
    let bi = p.a.open(Dir::Bidi).unwrap();
    p.a.write(bi, b"bidi data").unwrap();
    p.a.finish(bi).unwrap();
    let rs = p.a.open(Dir::Bidi).unwrap();
    p.a.write(rs, b"reliable").unwrap();
    p.a.set_reliable_boundary(rs).unwrap();
    p.a.write(rs, b" and more").unwrap();
    p.a.reset(rs, VarInt::from_u32(9)).unwrap();
    // Everything goes out as early data, and the carrier drops it.
    while p.a.wants_write(P0) {
        p.a.poll_transmit(P0, p.now, &mut p.out);
        if p.out.is_empty() {
            break;
        }
    }
    p.a.carrier_early_data_settled(false, p.now);
    p.pump();
    assert_eq!(p.a.state(), State::Active);
    let mut got = Vec::new();
    for dir in [Dir::Uni, Dir::Bidi, Dir::Bidi] {
        let k = p.b.accept(dir).unwrap().expect("the stream arrived");
        let mut buf = [0u8; 64];
        let mut data = Vec::new();
        let end = loop {
            match p.b.read(k, &mut buf) {
                Ok(Some((n, fin))) => {
                    data.extend_from_slice(&buf[..n]);
                    if fin {
                        break "fin".to_owned();
                    }
                }
                Ok(None) => break "pending".to_owned(),
                Err(e) => break format!("{e:?}"),
            }
        };
        got.push((data, end));
    }
    assert_eq!(got[0], (b"uni data".to_vec(), "fin".to_owned()));
    assert_eq!(got[1], (b"bidi data".to_vec(), "fin".to_owned()));
    assert_eq!(got[2].0, b"reliable".to_vec());
    assert!(got[2].1.contains("Reset"), "{:?}", got[2].1);
}
