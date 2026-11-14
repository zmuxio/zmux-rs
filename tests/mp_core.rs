//! Multipath sessions end to end, sans IO: two cores joined by in-memory
//! pipes. Data spread over pipes, pipes that fail with data in flight,
//! joins, removals and suspension: every stream is delivered exactly once,
//! in order, and nothing panics.

use std::collections::BTreeMap;
use std::time::Duration;

#[path = "common/mp_net.rs"]
mod mp_net;

use mp_net::{A, B, MpNet};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use zmux::proto::frame::{Dir, Frame, Padding, Priority, Stream};
use zmux::proto::record::RecordBuilder;
use zmux::proto::session::{
    Config, CoreEvent, DirectionState, OutboundState, PipeAuth, PipeEnd, PipeHalf, PipeId,
    PipeOptions, QualityBand, Scheduler, State, StreamKey,
};

/// The streams A wrote, with their data, and what B read of them.
#[derive(Default)]
struct Book {
    /// Data A wrote per stream, and what B read.
    sent: BTreeMap<u64, Vec<u8>>,
    recv: BTreeMap<u64, Vec<u8>>,
    fin: BTreeMap<u64, bool>,
    a_streams: Vec<(StreamKey, u64)>,
    b_streams: BTreeMap<u64, StreamKey>,
}

type Net = MpNet<(), Book>;

fn config(policy: Scheduler, resume: bool) -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end();
    c.scheduler = policy;
    c.max_idle_timeout = Some(Duration::from_secs(60));
    if resume {
        c.resume_timeout = Some(Duration::from_secs(30));
    }
    c
}

/// A multipath pair on pipe 0, established.
fn net(policy: Scheduler, resume: bool) -> Net {
    net_with_b(policy, resume, |_| {})
}

/// [`net`] with B's configuration changed by `f`.
fn net_with_b(policy: Scheduler, resume: bool, f: impl FnOnce(&mut Config)) -> Net {
    let mut b_cfg = config(policy.clone(), resume);
    b_cfg.test_hooks().locator = b"server".to_vec();
    f(&mut b_cfg);
    let mut n = Net::new(config(policy, resume), b_cfg, Book::default());
    n.pump(10);
    assert!(n.ends[A].is_multipath() && n.ends[B].is_multipath());
    n
}

impl Net {
    fn pump(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.step(usize::MAX);
            self.read_b();
        }
        for e in &mut self.events {
            e.clear();
        }
    }

    fn open_and_write(&mut self, len: usize, fin: bool) {
        let Ok(k) = self.ends[A].open(Dir::Bidi) else {
            return;
        };
        let tag = self.s.a_streams.len() as u64;
        if tag % 2 == 1 {
            // Urgent: its chunks go redundantly on two pipes.
            let urgent = Priority::new(1, false).expect("valid");
            self.ends[A].set_priority(k, urgent).unwrap();
        }
        let data: Vec<u8> = (0..len).map(|i| (tag as usize * 31 + i) as u8).collect();
        let n = self.ends[A].write(k, &data).unwrap();
        self.s.a_streams.push((k, tag));
        self.s.sent.insert(tag, data[..n].to_vec());
        if fin && n == len {
            self.ends[A].finish(k).unwrap();
            self.s.fin.insert(tag, true);
        }
    }

    fn write_more(&mut self, which: usize, len: usize) {
        let Some(&(k, tag)) = self.s.a_streams.get(which) else {
            return;
        };
        if self.s.fin.get(&tag).copied().unwrap_or(false) {
            return;
        }
        let at = self.s.sent[&tag].len();
        let data: Vec<u8> = (at..at + len)
            .map(|i| (tag as usize * 31 + i) as u8)
            .collect();
        if let Ok(n) = self.ends[A].write(k, &data) {
            self.s
                .sent
                .get_mut(&tag)
                .unwrap()
                .extend_from_slice(&data[..n]);
        }
    }

    /// B accepts and reads everything available; the stream index tells
    /// the tag (streams open in order).
    fn read_b(&mut self) {
        while let Ok(Some(k)) = self.ends[B].accept(Dir::Bidi) {
            let id = self.ends[B].peek_stream_id(k).unwrap();
            // The tag of the stream A opened with this identifier.
            let tag = self
                .s
                .a_streams
                .iter()
                .find(|(ak, _)| self.ends[A].peek_stream_id(*ak) == Some(id))
                .map(|(_, t)| *t)
                .unwrap_or(u64::MAX - id);
            self.s.b_streams.insert(tag, k);
        }
        let keys: Vec<(u64, StreamKey)> = self.s.b_streams.iter().map(|(a, b)| (*a, *b)).collect();
        for (tag, k) in keys {
            let mut buf = [0u8; 8192];
            while let Ok(Some((n, fin))) = self.ends[B].read(k, &mut buf) {
                self.s
                    .recv
                    .entry(tag)
                    .or_default()
                    .extend_from_slice(&buf[..n]);
                if fin || n == 0 {
                    break;
                }
            }
        }
    }

    fn check_prefix(&self) {
        for (tag, got) in &self.s.recv {
            let sent = &self.s.sent[tag];
            assert!(
                got.len() <= sent.len(),
                "stream {tag}: {} read, {} sent",
                got.len(),
                sent.len()
            );
            if let Some(i) = got.iter().zip(sent).position(|(a, b)| a != b) {
                panic!(
                    "stream {tag}: wrong byte at {i} of {} (got {}, sent {})",
                    got.len(),
                    got[i],
                    sent[i]
                );
            }
        }
    }

    /// The application byte counters are exact
    /// whatever pipes failed, were reinjected or carried redundant copies:
    /// each stream's written bytes at A, and read bytes at B, are what the
    /// application handed over and got; a stream's sent bytes count every
    /// copy.
    fn check_application_bytes(&mut self) {
        let mut total = 0;
        for &(k, tag) in &self.s.a_streams {
            let sent = self.s.sent[&tag].len() as u64;
            total += sent;
            let m = self.ends[A].stream_meter(k).expect("A holds its streams");
            assert_eq!(m.bytes_written(), sent, "stream {tag}");
            let st = self.ends[A].stream_stats(k).unwrap();
            assert!(st.bytes_sent >= sent, "stream {tag}: {st:?}");
            if let Some(&bk) = self.s.b_streams.get(&tag) {
                let m = self.ends[B].stream_meter(bk).expect("B holds its streams");
                assert_eq!(m.bytes_read(), sent, "stream {tag}");
            }
        }
        assert_eq!(self.ends[A].meter().bytes_written(), total);
        assert_eq!(self.ends[B].meter().bytes_read(), total);
    }

    fn settle(&mut self) {
        for _ in 0..400 {
            self.pump(4);
            self.advance(20);
        }
        self.read_b();
    }
}

#[test]
fn spread_over_two_pipes_and_survive_a_failure() {
    let mut n = net(Scheduler::SpreadEta, false);
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    n.pump(10);
    for _ in 0..4 {
        n.open_and_write(100_000, true);
    }
    // Deliver some, then kill pipe 0 with data in flight.
    for _ in 0..5 {
        n.step(3000);
        n.advance(1);
    }
    n.fail(0);
    let _ = id;
    n.settle();
    n.check_prefix();
    n.check_application_bytes();
    for (tag, sent) in &n.s.sent {
        assert_eq!(
            n.s.recv.get(tag).map_or(0, Vec::len),
            sent.len(),
            "stream {tag}"
        );
    }
    assert!(
        n.ends[A].state() < State::Closing,
        "{:?}",
        n.ends[A].error()
    );
}

/// A request lost with its
/// pipe stops being outstanding; a ping still waiting asks again on the
/// pipes left, so it is answered.
#[test]
fn a_ping_lost_with_its_pipe_asks_again() {
    let mut n = net(Scheduler::SpreadEta, false);
    n.add_pipe(&PipeOptions::default()).unwrap();
    n.pump(10);
    n.advance(5);
    n.pump(10);
    let ticket = n.ends[A].ping().unwrap();
    // Nothing is delivered: the request is in flight on one pipe.
    for l in n.links.values_mut() {
        l.stall(true);
    }
    n.step(usize::MAX);
    let carrying: Vec<u64> = n
        .links
        .iter()
        .filter(|(_, l)| l.flows[A].queued > 0)
        .map(|(&id, _)| id)
        .collect();
    assert_eq!(carrying.len(), 1, "one pipe carries the request");
    n.fail(carrying[0]);
    for l in n.links.values_mut() {
        l.stall(false);
    }
    for _ in 0..20 {
        n.pump(1);
        n.advance(1);
        if n.ends[A].ping_rtt(ticket).is_some() {
            break;
        }
    }
    assert!(
        n.ends[A].ping_rtt(ticket).is_some(),
        "the ping is answered on the pipe left"
    );
    assert!(
        n.ends[A].state() < State::Closing,
        "{:?}",
        n.ends[A].error()
    );
}

/// A keep-alive period set while the session runs counts from the last
/// activity, not from the call.
#[test]
fn a_new_keep_alive_counts_from_the_last_activity() {
    let mut n = net(Scheduler::SpreadEta, false);
    let mut l = n.ends[A].config().liveness;
    l.keep_alive_period = None;
    l.probe_interval = None;
    l.probe_jitter = 0.0;
    n.ends[A].set_liveness(&l).unwrap();
    n.pump(2);
    let activity = n.now;
    n.advance(600);
    l.keep_alive_period = Some(Duration::from_secs(1));
    n.ends[A].set_liveness(&l).unwrap();
    assert!(n.ends[A].poll_timeout().unwrap() <= activity + Duration::from_secs(1));
}

/// A pipe already suspect keeps the dead timeout it turned suspect under.
#[test]
fn a_suspect_pipe_keeps_its_dead_timeout() {
    let mut n = net(Scheduler::SpreadEta, false);
    let mut l = n.ends[A].config().liveness;
    l.dead_timeout = zmux::Cap::Fixed(Duration::from_secs(50));
    n.ends[A].set_liveness(&l).unwrap();
    n.open_and_write(200_000, true);
    n.step(4000);
    n.links.get_mut(&0).unwrap().stall(true);
    n.links.get_mut(&0).unwrap().cap = 64 * 1024;
    let suspect = |n: &Net| {
        n.ends[A].pipe_state(PipeId::new(0), PipeHalf::Outbound)
            == Some(DirectionState::Outbound(OutboundState::Suspect))
    };
    for _ in 0..2000 {
        if suspect(&n) {
            break;
        }
        n.pump(1);
        n.advance(10);
    }
    assert!(suspect(&n));
    l.dead_timeout = zmux::Cap::Fixed(Duration::from_secs(1));
    n.ends[A].set_liveness(&l).unwrap();
    for _ in 0..500 {
        n.pump(1);
        n.advance(10);
    }
    assert!(suspect(&n), "five seconds under the old 50 s");
}

#[test]
fn silently_stalled_pipe_fails_over() {
    let mut n = net(Scheduler::SpreadEta, false);
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    n.pump(10);
    n.advance(5);
    n.pump(10);
    for _ in 0..3 {
        n.open_and_write(200_000, true);
    }
    for _ in 0..5 {
        n.step(4000);
        n.read_b();
        n.advance(1);
    }
    // Silently stalled: bytes are taken, never delivered, and the writers
    // see the carrier full past 64 KiB.
    let l = n.links.get_mut(&id).unwrap();
    l.stall(true);
    l.cap = 64 * 1024;
    for _ in 0..2000 {
        n.pump(1);
        n.advance(10);
        if n.s
            .sent
            .iter()
            .all(|(t, s)| n.s.recv.get(t).map_or(0, Vec::len) == s.len())
        {
            break;
        }
    }
    n.check_prefix();
    for (tag, sent) in &n.s.sent {
        assert_eq!(
            n.s.recv.get(tag).map_or(0, Vec::len),
            sent.len(),
            "stream {tag}; a {:?} b {:?}; a pipes {:?}; b pipes {:?}",
            n.ends[A].error(),
            n.ends[B].error(),
            n.ends[A].pipes(),
            n.ends[B].pipes()
        );
    }
}

/// A quality band is judged where acknowledgements
/// update a pipe's estimates. The first RTT samples are the first report;
/// acknowledgements held back for 40 ms move the smoothed RTT out of a
/// ±2 ms band, and the event carries the estimates the pipe's statistics
/// report.
#[test]
fn acknowledgements_drive_quality_events() {
    let mut n = net(Scheduler::SpreadEta, false);
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    n.pump(10);
    n.advance(5);
    n.pump(10);
    n.ends[A]
        .set_quality_band(Some(QualityBand {
            min_interval: Duration::ZERO,
            ..QualityBand::new(Some(Duration::from_millis(2)), None)
        }))
        .unwrap();
    n.open_and_write(50_000, false);
    n.pump(10);
    let quality = |n: &Net| {
        n.events[A]
            .iter()
            .filter_map(|e| match e {
                CoreEvent::PipeQualityChanged {
                    pipe, smoothed_rtt, ..
                } => Some((pipe.get(), *smoothed_rtt)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    n.handle_events();
    assert!(quality(&n).is_empty(), "the first samples are no event");
    for l in n.links.values_mut() {
        l.stall(true);
    }
    n.write_more(0, 50_000);
    n.step(usize::MAX);
    n.advance(40);
    for l in n.links.values_mut() {
        l.stall(false);
    }
    for _ in 0..10 {
        n.step(usize::MAX);
        n.read_b();
    }
    let seen = quality(&n);
    assert!(!seen.is_empty(), "{:?}", n.ends[A].pipes());
    for (pipe, rtt) in seen {
        assert!(pipe == 0 || pipe == id);
        assert!(rtt.is_some_and(|r| r > Duration::from_millis(2)), "{rtt:?}");
    }
}

/// Carrier liveness and zmux's timers: a
/// carrier's own verdict, reported by the adapter as a read error, an
/// unexpected end or a write error, fails the pipe at once, while another
/// pipe is ACTIVE, without waiting for T_suspect or T_fail: no time
/// passes between the report and the failure.
#[test]
fn a_carrier_verdict_fails_the_pipe_at_once() {
    let reports: [fn(&mut Net, u64); 3] = [
        |n, id| {
            n.ends[A].pipe_ended(
                PipeId::new(id),
                PipeEnd::Error(std::io::ErrorKind::ConnectionReset),
                n.now,
            )
        },
        |n, id| n.ends[A].pipe_ended(PipeId::new(id), PipeEnd::Eof, n.now),
        |n, id| n.ends[A].write_failed(PipeId::new(id), std::io::ErrorKind::BrokenPipe, n.now),
    ];
    for (i, report) in reports.into_iter().enumerate() {
        let mut n = net(Scheduler::SpreadEta, false);
        let id = n.add_pipe(&PipeOptions::default()).unwrap();
        n.pump(10);
        n.advance(5);
        n.pump(10);
        assert_eq!(
            n.ends[A].pipe_state(PipeId::new(id), PipeHalf::Outbound),
            Some(DirectionState::Outbound(OutboundState::Active))
        );
        report(&mut n, id);
        assert_eq!(
            n.ends[A].pipe_state(PipeId::new(id), PipeHalf::Outbound),
            Some(DirectionState::Outbound(OutboundState::Failed)),
            "report {i}"
        );
        assert!(n.ends[A].state() < State::Closing, "report {i}");
    }
}

/// Secret sources: E names a secret source the
/// endpoint can provide. Without the bootstrap exporter it is not offered,
/// so a session secret is never derived from the public nonces alone:
/// with E as the only source, multipath stays off; with the exporter on
/// both ends it is used.
#[test]
fn the_exporter_flag_needs_an_exporter() {
    for exporter in [false, true] {
        let mut a = config(Scheduler::SpreadEta, false);
        a.pipe_auth = PipeAuth::exporter();
        let mut b = a.clone();
        b.test_hooks().locator = b"server".to_vec();
        let mut n = Net::new(a, b, Book::default());
        if exporter {
            for end in &mut n.ends {
                end.announce_bootstrap_exporter();
                end.set_bootstrap_exporter_value(vec![7; 32]);
            }
        }
        for _ in 0..10 {
            n.step(usize::MAX);
        }
        for side in [A, B] {
            // The parameters the peer sent, E as it offered it.
            assert!(n.ends[side].is_established(), "side {side}");
            let peer = n.ends[1 - side].local_parameters();
            let flags = peer.zmux_multipath.as_ref().unwrap().secret_flags;
            assert_eq!(flags & 0x01 != 0, exporter, "side {side}: E");
            assert_eq!(n.ends[side].is_multipath(), exporter, "side {side}");
        }
    }
}

#[test]
fn affinity_and_graceful_removal() {
    let mut n = net(Scheduler::Affinity, false);
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    n.pump(10);
    n.open_and_write(50_000, false);
    n.pump(5);
    n.ends[A].remove_pipe(PipeId::new(id), true, n.now).unwrap();
    n.write_more(0, 50_000);
    n.settle();
    n.check_prefix();
    assert_eq!(n.s.recv[&0].len(), 100_000);
    assert!(n.ends[A].state() < State::Closing);
}

/// A pipe removed abruptly fails: its carrier is aborted, and the core
/// asks for no graceful shutdown of it besides (a shutdown written first,
/// by a write-through before the driver applied the abort, was a clean end
/// at the peer).
#[test]
fn an_aborted_pipe_is_never_shut_down_gracefully() {
    let mut n = net(Scheduler::SpreadEta, false);
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    n.pump(10);
    n.open_and_write(50_000, false);
    n.pump(2);
    n.ends[A]
        .remove_pipe(PipeId::new(id), false, n.now)
        .unwrap();
    assert!(
        !n.ends[A].wants_write(PipeId::new(id)),
        "nothing more to write"
    );
    n.handle_events();
    assert!(n.events[A].iter().any(|e| matches!(
        e,
        CoreEvent::ClosePipe { pipe, half: PipeHalf::Outbound, abort: true } if pipe.get() == id
    )));
    n.write_more(0, 50_000);
    n.settle();
    n.check_prefix();
    assert_eq!(n.s.recv[&0].len(), 100_000);
}

#[test]
fn resume_after_losing_every_pipe() {
    let mut n = net(Scheduler::SpreadEta, true);
    n.open_and_write(20_000, false);
    n.step(5000);
    n.fail(0);
    assert_eq!(n.ends[A].state(), State::Suspended);
    n.write_more(0, 10_000);
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    let _ = id;
    n.settle();
    n.check_prefix();
    assert_eq!(n.s.recv[&0].len(), 30_000);
    assert!(
        n.ends[A].state() < State::Closing,
        "{:?}",
        n.ends[A].error()
    );
    assert!(
        n.ends[B].state() < State::Closing,
        "{:?}",
        n.ends[B].error()
    );
}

#[derive(Debug, Clone)]
enum Op {
    Open(u16),
    Write(u8, u16),
    Step(u16),
    Advance(u8),
    Fail(u8),
    Add,
    Remove(u8, bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (1u16..20_000).prop_map(Op::Open),
        (any::<u8>(), 1u16..20_000).prop_map(|(s, l)| Op::Write(s, l)),
        (1u16..6000).prop_map(Op::Step),
        (1u8..200).prop_map(Op::Advance),
        any::<u8>().prop_map(Op::Fail),
        Just(Op::Add),
        (any::<u8>(), any::<bool>()).prop_map(|(p, g)| Op::Remove(p, g)),
    ]
}

fn policy() -> impl Strategy<Value = Scheduler> {
    prop_oneof![
        Just(Scheduler::Affinity),
        Just(Scheduler::SpreadEta),
        Just(Scheduler::SpreadRateWeighted),
        Just(Scheduler::SessionAffinity),
    ]
}

static COMPLETED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        // Seeds go to tests/mp_core.proptest-regressions.
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    })]

    /// Random pipe failures, joins and removals: no panic, and every byte a
    /// stream delivers is the byte that was sent at that offset; with a
    /// pipe left, every stream completes (exactly once, in order).
    #[test]
    fn exactly_once_under_pipe_churn(
        resume in any::<bool>(),
        policy in policy(),
        ops in prop::collection::vec(op(), 1..60),
    ) {
        run_churn(policy, resume, ops);
    }
}

/// Applies `ops` to a fresh pair, heals it with a new pipe and checks that
/// every stream completed exactly once, in order.
fn run_churn(policy: Scheduler, resume: bool, ops: Vec<Op>) {
    let mut n = net(policy, resume);
    for op in ops {
        n.apply(op);
        n.check_prefix();
    }
    // Heal: a fresh pipe, then run to completion.
    if n.ends[A].state() < State::Closing && n.ends[B].state() < State::Closing {
        let _ = n.add_pipe(&PipeOptions::default());
        n.settle();
        n.check_prefix();
        if n.ends[A].state() < State::Closing && n.ends[B].state() < State::Closing {
            COMPLETED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if std::env::var("MP_STATS").is_ok() {
                eprintln!(
                    "completed: {} streams, {} bytes, reinjected {}",
                    n.s.sent.len(),
                    n.s.sent.values().map(Vec::len).sum::<usize>(),
                    n.ends[A].stats().bytes_reinjected
                );
            }
            for (tag, sent) in &n.s.sent {
                let got = n.s.recv.get(tag).map_or(0, Vec::len);
                assert_eq!(got, sent.len(), "stream {tag} incomplete");
            }
            n.check_application_bytes();
        }
    }
}

impl Net {
    fn apply(&mut self, op: Op) {
        match op {
            Op::Open(len) => self.open_and_write(len as usize, false),
            Op::Write(s, len) => {
                let i = s as usize % self.s.a_streams.len().max(1);
                self.write_more(i, len as usize);
            }
            Op::Step(limit) => {
                self.step(limit as usize);
                self.read_b();
            }
            Op::Advance(ms) => self.advance(u64::from(ms)),
            Op::Fail(p) => {
                let ids: Vec<u64> = self
                    .links
                    .iter()
                    .filter(|(_, l)| l.alive())
                    .map(|(k, _)| *k)
                    .collect();
                if let Some(&id) = ids.get(p as usize % ids.len().max(1)) {
                    self.fail(id);
                }
            }
            Op::Add => {
                let _ = self.add_pipe(&PipeOptions::default());
            }
            Op::Remove(p, g) => {
                let ids: Vec<u64> = self.links.keys().copied().collect();
                if let Some(&id) = ids.get(p as usize % ids.len().max(1)) {
                    let _ = self.ends[A].remove_pipe(PipeId::new(id), g, self.now);
                }
            }
        }
    }
}

/// A churn under session affinity with resume (found by
/// `exactly_once_under_pipe_churn`): a record of PIPE_ACK alone,
/// acknowledged late with the next acknowledgement, gave a delivery-rate
/// sample of a few hundred bytes a second, and the limiter then held the
/// active pipe past the end of the run.
#[test]
fn session_affinity_churn_with_removals_completes() {
    use Op::*;
    let ops = vec![
        Open(7518),
        Fail(189),
        Add,
        Add,
        Fail(245),
        Add,
        Step(4452),
        Write(80, 18608),
        Add,
        Open(14161),
        Add,
        Step(5414),
        Advance(5),
        Write(194, 14420),
        Add,
        Fail(159),
        Step(2459),
        Fail(144),
        Add,
        Write(214, 13776),
        Step(5427),
        Open(10797),
        Write(52, 13957),
        Add,
        Add,
        Add,
        Fail(244),
        Advance(133),
        Remove(161, false),
        Fail(12),
        Remove(228, false),
        Advance(73),
        Step(3465),
        Step(4498),
        Remove(135, true),
        Fail(221),
        Write(91, 1385),
    ];
    run_churn(Scheduler::SessionAffinity, true, ops);
}

/// A stream that never completed after a churn of joins and failures
/// (found by `exactly_once_under_pipe_churn`).
#[test]
fn churn_with_failures_completes() {
    let mut n = net(Scheduler::Affinity, false);
    let ops = [
        Op::Add,
        Op::Add,
        Op::Open(1),
        Op::Add,
        Op::Remove(128, false),
        Op::Open(1),
        Op::Add,
        Op::Open(4980),
        Op::Fail(237),
        Op::Step(5070),
        Op::Add,
        Op::Add,
        Op::Fail(235),
        Op::Fail(194),
        Op::Add,
        Op::Add,
        Op::Fail(100),
        Op::Fail(111),
    ];
    for op in ops {
        match op {
            Op::Open(len) => n.open_and_write(len as usize, false),
            Op::Step(limit) => {
                n.step(limit as usize);
                n.read_b();
            }
            Op::Fail(p) => {
                let ids: Vec<u64> = n
                    .links
                    .iter()
                    .filter(|(_, l)| l.alive())
                    .map(|(k, _)| *k)
                    .collect();
                if let Some(&id) = ids.get(p as usize % ids.len().max(1)) {
                    n.fail(id);
                }
            }
            Op::Add => {
                let _ = n.add_pipe(&PipeOptions::default());
            }
            Op::Remove(p, g) => {
                let ids: Vec<u64> = n.links.keys().copied().collect();
                if let Some(&id) = ids.get(p as usize % ids.len().max(1)) {
                    let _ = n.ends[A].remove_pipe(PipeId::new(id), g, n.now);
                }
            }
            _ => unreachable!(),
        }
    }
    let _ = n.add_pipe(&PipeOptions::default());
    n.settle();
    n.check_prefix();
    if std::env::var("MP_DEBUG").is_ok() {
        eprintln!("a {:?} {:#?}", n.ends[A].state(), n.ends[A].pipes());
        eprintln!("b {:?} {:#?}", n.ends[B].state(), n.ends[B].pipes());
        eprintln!("a stats {:?}", n.ends[A].stats());
    }
    if n.ends[A].state() < State::Closing && n.ends[B].state() < State::Closing {
        for (tag, sent) in &n.s.sent {
            let got = n.s.recv.get(tag).map_or(0, Vec::len);
            assert_eq!(got, sent.len(), "stream {tag} incomplete");
        }
    }
}

/// Drives A's pipes in steps of `step_us` microseconds for `rounds`
/// rounds, with `urgent` more bytes of the urgent stream every round, and
/// delivers what they wrote at the end of each round when `deliver`: the
/// in-memory carriers report neither unsent bytes nor a low-water mark, so
/// the carrier queue limiter paces them and holds them back between quanta.
/// Every write the driver is asked for must
/// write something; the STREAM frames written are returned (stream
/// identifier, length).
fn paced_writes(
    n: &mut Net,
    rounds: usize,
    step_us: u64,
    urgent: usize,
    deliver: bool,
) -> Vec<(u64, usize)> {
    use zmux::proto::frame::{Frame, Gates};
    use zmux::proto::record::{Event, RecordReader};
    let ids: Vec<u64> = n.links.keys().copied().collect();
    let mut readers: BTreeMap<u64, RecordReader> = ids
        .iter()
        .map(|&id| (id, RecordReader::new(1 << 20)))
        .collect();
    let mut frames = Vec::new();
    for round in 0..rounds {
        if urgent > 0 {
            // Its chunks are copied to the second pipe.
            n.write_more(1, urgent);
        }
        for &id in &ids {
            for _ in 0..64 {
                if !n.ends[A].wants_write(PipeId::new(id)) {
                    break;
                }
                n.ends[A].poll_transmit(PipeId::new(id), n.now, &mut n.out);
                let mut v = Vec::new();
                n.out.copy_to_vec(&mut v);
                assert!(
                    !v.is_empty(),
                    "pipe {id} asked for a write and wrote nothing (round {round})"
                );
                let mut input = &v[..];
                let r = readers.get_mut(&id).unwrap();
                while let Ok(Some(ev)) = r.read(&mut input, &Gates::ALL) {
                    if let Event::Frame(Frame::Stream(f)) = ev {
                        frames.push((f.stream_id, f.data.len()));
                    }
                }
                if deliver {
                    n.feed(id, B, &v);
                }
            }
        }
        if deliver {
            // B reads, then writes its acknowledgements and credit, which
            // reach A at once.
            n.read_b();
            for &id in &ids {
                for _ in 0..64 {
                    if !n.ends[B].wants_write(PipeId::new(id)) {
                        break;
                    }
                    n.ends[B].poll_transmit(PipeId::new(id), n.now, &mut n.out);
                    let mut v = Vec::new();
                    n.out.copy_to_vec(&mut v);
                    if v.is_empty() {
                        break;
                    }
                    n.ends[A].receive(PipeId::new(id), &v, n.now);
                }
            }
        }
        n.now += Duration::from_micros(step_us);
        n.ends[A].handle_timeout(n.now);
    }
    frames
}

/// A pipe the limiter holds back takes no stream data, no redundant copy
/// and no opportunistic copy, so the driver is not asked to write to it
/// until the limiter lets it go: asked anyway, it would write nothing, and
/// the blocking driver's writer threads would wake each other in a loop.
#[test]
fn held_pipes_are_not_asked_to_write() {
    let mut n = net(Scheduler::SpreadEta, false);
    n.add_pipe(&PipeOptions::default()).unwrap();
    n.pump(20);
    n.open_and_write(64 << 20, false);
    n.open_and_write(1024, false);
    paced_writes(&mut n, 4000, 20, 1024, true);
}

/// The limiter lets a held pipe go with whole chunks, not with the few
/// bytes the bucket refilled since its last batch, and never cuts a frame
/// at its room: paced bulk data goes out in full STREAM frames, without
/// the fragments that would then wait for the stream's next turn.
#[test]
fn paced_pipes_send_whole_chunks() {
    let mut n = net(Scheduler::SpreadEta, false);
    n.add_pipe(&PipeOptions::default()).unwrap();
    n.pump(20);
    n.open_and_write(8 << 20, false);
    let frames = paced_writes(&mut n, 400, 10, 0, false);
    let bulk = n.ends[A].peek_stream_id(n.s.a_streams[0].0).unwrap();
    let sizes: Vec<usize> = frames
        .iter()
        .filter(|&&(id, _)| id == bulk)
        .map(|&(_, len)| len)
        .collect();
    assert!(sizes.len() > 4, "{} bulk frames", sizes.len());
    assert!(
        sizes.iter().all(|&len| len >= 4096),
        "bulk STREAM frames cut short: {sizes:?}"
    );
}

/// A peer that fragments on purpose (fragmentation the
/// receiver must accept): one byte at every other offset of each stream's window,
/// in 1-byte STREAM frames alternating between two pipes, in records of
/// those frames alone and with each frame in its own record padded to
/// 64 KiB. The session stays open, the received data costs at most 2.5 x
/// the session's flow-control consumption plus 4 KiB per stream, and
/// filling the holes delivers every stream complete.
#[test]
fn deliberate_fragmentation_is_bounded_by_the_span() {
    for padded in [false, true] {
        const WINDOW: u64 = 4096;
        const STREAMS: u64 = 4;
        let mut n = net_with_b(Scheduler::SpreadEta, false, |c| {
            c.initial_stream_receive_window = WINDOW;
            c.initial_connection_receive_window = WINDOW * STREAMS;
        });
        let p1 = n.add_pipe(&PipeOptions::default()).expect("second pipe");
        n.pump(10);
        assert!(n.links[&p1].attached(), "the second pipe joined");
        let pipes = [0, p1];
        let mut buf = vec![0u8; 65535];
        let mut records: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        // Frames go out in records, alternating between the pipes.
        let mut send = |n: &mut Net, k: &mut usize, f: Option<Frame<'_>>| {
            if let Some(f) = f {
                let i = *k % 2;
                *k += 1;
                let mut b = RecordBuilder::new(&mut buf, 65531).unwrap();
                b.push(&f).unwrap();
                if padded {
                    let pad = b.remaining();
                    b.push(&Frame::Padding(Padding { len: pad })).unwrap();
                }
                let len = b.finish().unwrap();
                records[i].extend_from_slice(&buf[..len]);
                if !padded && records[i].len() < 60_000 {
                    return;
                }
            }
            for (i, r) in records.iter_mut().enumerate() {
                let r = std::mem::take(r);
                n.ends[B].receive(PipeId::new(pipes[i]), &r, n.now);
            }
        };
        // Offset 0 holds an empty stream preamble:
        // the application data starts at 1.
        let byte = |id: u64, off: u64| if off == 0 { 0 } else { (id * 7 + off) as u8 };
        let mut k = 0;
        for s in 0..STREAMS {
            let id = 4 * s;
            for off in (1..WINDOW).step_by(2) {
                let d = [byte(id, off)];
                send(
                    &mut n,
                    &mut k,
                    Some(Frame::Stream(Stream::new(id, off, &d, false))),
                );
            }
        }
        send(&mut n, &mut k, None);
        assert!(
            n.ends[B].error().is_none(),
            "padded {padded}: {:?}",
            n.ends[B].error()
        );
        let consumed = STREAMS * (WINDOW - 1);
        let mem = n.ends[B].received_data_memory() as u64;
        assert!(
            mem <= consumed * 5 / 2 + 4096 * STREAMS,
            "padded {padded}: {mem} B for {consumed} B of flow control"
        );
        // The holes, then a FIN: every stream complete.
        for s in 0..STREAMS {
            let id = 4 * s;
            for off in (0..WINDOW).step_by(2) {
                let d = [byte(id, off)];
                send(
                    &mut n,
                    &mut k,
                    Some(Frame::Stream(Stream::new(id, off, &d, false))),
                );
            }
            let fin = Frame::Stream(Stream::new(id, WINDOW, &[], true));
            send(&mut n, &mut k, Some(fin));
        }
        send(&mut n, &mut k, None);
        assert!(
            n.ends[B].error().is_none(),
            "padded {padded}: {:?}",
            n.ends[B].error()
        );
        let mut done = 0;
        while let Ok(Some(key)) = n.ends[B].accept(Dir::Bidi) {
            let id = n.ends[B].peek_stream_id(key).unwrap();
            let mut got = Vec::new();
            let mut chunk = [0u8; 8192];
            while let Ok(Some((len, fin))) = n.ends[B].read(key, &mut chunk) {
                got.extend_from_slice(&chunk[..len]);
                if fin {
                    break;
                }
            }
            let want: Vec<u8> = (1..WINDOW).map(|off| byte(id, off)).collect();
            assert_eq!(got, want, "stream {id}");
            done += 1;
        }
        assert_eq!(done, STREAMS);
    }
}

/// The bootstrap pair is no join: its end counts no failed join.
#[test]
fn the_end_of_the_bootstrap_pair_is_no_failed_join() {
    let mut n = net(Scheduler::default(), false);
    assert_eq!(n.ends[A].stats().join_failures, 0);
    n.ends[A].pipe_ended(
        PipeId::new(0),
        PipeEnd::Error(std::io::ErrorKind::ConnectionReset),
        n.now,
    );
    assert_eq!(n.ends[A].stats().join_failures, 0);
}

/// At the cap of unretired attachments, joins held back are judged one by one: while
/// suspended for want of an outbound pipe, a held outbound join displaces a failed
/// attachment and goes, although an inbound join held before it keeps waiting.
/// `join_ready` asks for a displaceable attachment only once the cap is reached.
#[test]
fn held_joins_are_judged_one_by_one_at_the_cap() {
    let mut a_cfg = config(Scheduler::SpreadEta, true);
    a_cfg.max_pipes = 1;
    a_cfg.pipe_headroom = 1;
    let mut b_cfg = config(Scheduler::SpreadEta, true);
    b_cfg.test_hooks().locator = b"server".to_vec();
    let mut n = Net::new(a_cfg, b_cfg, Book::default());
    n.pump(10);
    assert!(n.ends[A].join_ready(n.now), "below the cap");
    let inbound = n
        .add_pipe_directed(true, false, &PipeOptions::default())
        .unwrap();
    n.pump(10);
    assert!(!n.ends[A].join_deferred(PipeId::new(inbound)));
    // The bootstrap pair and the inbound pipe: the cap of 2 is reached.
    assert!(!n.ends[A].join_ready(n.now), "at the cap, not suspended");
    let held_in = n
        .add_pipe_directed(true, false, &PipeOptions::default())
        .unwrap();
    let held_out = n
        .add_pipe_directed(false, true, &PipeOptions::default())
        .unwrap();
    assert!(n.ends[A].join_deferred(PipeId::new(held_in)));
    assert!(n.ends[A].join_deferred(PipeId::new(held_out)));
    // The bootstrap pair fails: no outbound pipe is left.
    n.fail(0);
    assert_eq!(n.ends[A].state(), State::Suspended);
    n.advance(1);
    assert!(
        n.ends[A].join_deferred(PipeId::new(held_in)),
        "brings no missing direction"
    );
    assert!(
        !n.ends[A].join_deferred(PipeId::new(held_out)),
        "displaced the failed pair"
    );
}

/// PIPE_ABANDON frames A wrote, by Pipe ID.
struct Abandons {
    reader: zmux::proto::record::RecordReader,
    sent: Vec<u64>,
}

impl Default for Abandons {
    fn default() -> Self {
        Self {
            reader: zmux::proto::record::RecordReader::new(1 << 20),
            sent: Vec::new(),
        }
    }
}

impl mp_net::Observe for Abandons {
    fn a_batch(&mut self, mut input: &[u8]) {
        use zmux::proto::frame::Gates;
        use zmux::proto::record::Event as Rec;
        while let Ok(Some(ev)) = self.reader.read(&mut input, &Gates::ALL) {
            if let Rec::Frame(Frame::PipeAbandon(f)) = ev {
                self.sent.push(f.pipe_id);
            }
        }
    }
}

/// A at the cap of 2 attachments on the bootstrap pair and an outbound-only
/// pipe 1, then the bootstrap pair fails: A is SUSPENDED for want of an
/// inbound pipe and owes PIPE_ABANDON(0), which it may write only on pipe 1.
/// `hold` keeps pipe 1 from taking it (queued); otherwise pipe 1 takes it and
/// loses it in flight (sent, awaiting acknowledgement). An inbound join then
/// displaces the failed pair (MULTIPATH.md Section 5.4), or, with `displace`
/// false, finds room under a cap of 3. Returns the PIPE_ABANDON(0) frames A
/// wrote in all.
fn abandons_written(hold: bool, displace: bool) -> usize {
    let mut a_cfg = config(Scheduler::SpreadEta, true);
    a_cfg.max_pipes = 1;
    a_cfg.pipe_headroom = if displace { 1 } else { 2 };
    let mut b_cfg = config(Scheduler::SpreadEta, true);
    b_cfg.test_hooks().locator = b"server".to_vec();
    let mut n = MpNet::<Abandons, Book>::new(a_cfg, b_cfg, Book::default());
    for _ in 0..10 {
        n.step(usize::MAX);
    }
    let out = n
        .add_pipe_directed(false, true, &PipeOptions::default())
        .unwrap();
    for _ in 0..10 {
        n.step(usize::MAX);
    }
    assert!(n.links[&out].attached());
    if hold {
        n.links.get_mut(&out).unwrap().flows[A].takes = false;
    } else {
        n.links.get_mut(&out).unwrap().flows[A].blackhole = true;
    }
    n.fail(0);
    assert_eq!(n.ends[A].state(), State::Suspended);
    n.step(usize::MAX);
    assert_eq!(
        n.links[&out].sent.iter().filter(|&&p| p == 0).count(),
        usize::from(!hold),
        "PIPE_ABANDON(0) written before the displacement"
    );
    let inbound = n
        .add_pipe_directed(true, false, &PipeOptions::default())
        .unwrap();
    assert!(!n.ends[A].join_deferred(PipeId::new(inbound)));
    assert_eq!(
        n.ends[A].pipes().iter().any(|p| p.pipe == PipeId::new(0)),
        !displace,
        "the failed pair displaced"
    );
    let l = n.links.get_mut(&out).unwrap();
    l.flows[A].takes = true;
    l.flows[A].blackhole = false;
    // Long past every retransmission timeout.
    for _ in 0..100 {
        n.step(usize::MAX);
        n.advance(100);
    }
    assert!(n.links[&inbound].attached());
    n.links
        .values()
        .map(|l| l.sent.iter().filter(|&&p| p == 0).count())
        .sum()
}

/// Displacing an attachment drops the PIPE_ABANDON it still has queued: it
/// is never sent. Without the displacement it is.
#[test]
fn displacement_drops_a_queued_abandon() {
    assert_eq!(abandons_written(true, false), 1, "sent without it");
    assert_eq!(abandons_written(true, true), 0);
}

/// Displacing an attachment drops the PIPE_ABANDON it sent and awaits the
/// acknowledgement of: lost, it is not sent again. Without the
/// displacement it is.
#[test]
fn displacement_drops_a_retained_abandon() {
    assert!(abandons_written(false, false) > 1, "re-sent without it");
    assert_eq!(abandons_written(false, true), 1);
}

/// A join removed abruptly after its Hello was written stays failed: the
/// Reply that arrives later confirms nothing (found by
/// `exactly_once_under_pipe_churn`, where the revived attachment was ACTIVE
/// with no carrier, held a place under the attachment cap and kept the
/// healing join deferred).
#[test]
fn a_reply_after_an_abrupt_removal_revives_nothing() {
    let mut n = net(Scheduler::Affinity, false);
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    // The Hello goes out; nothing arrives yet.
    n.links.get_mut(&id).unwrap().stall(true);
    n.step(usize::MAX);
    assert!(n.links[&id].flows[A].queued > 0, "the Hello is in flight");
    n.ends[A]
        .remove_pipe(PipeId::new(id), false, n.now)
        .unwrap();
    // The Hello reaches B before the PIPE_ABANDON does, and B accepts it.
    n.links.get_mut(&0).unwrap().flows[A].stalled = true;
    n.links.get_mut(&id).unwrap().stall(false);
    n.pump(4);
    assert_eq!(
        n.ends[A].pipe_state(PipeId::new(id), PipeHalf::Outbound),
        Some(DirectionState::Outbound(OutboundState::Failed))
    );
    n.links.get_mut(&0).unwrap().flows[A].stalled = false;
    // The session goes on, and a new pipe joins.
    let healed = n.add_pipe(&PipeOptions::default()).unwrap();
    n.open_and_write(10_000, true);
    n.settle();
    assert_eq!(
        n.ends[A].pipe_state(PipeId::new(healed), PipeHalf::Outbound),
        Some(DirectionState::Outbound(OutboundState::Active))
    );
    assert_eq!(n.s.recv[&0].len(), 10_000);
    assert!(n.alive());
}
