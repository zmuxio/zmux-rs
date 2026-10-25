//! Tier gating, standby takeover, probation and acknowledgement snapshots
//! (MULTIPATH.md Sections 6.2 and 9), sans IO: two cores joined by
//! in-memory pipes, with the harness deciding when each of A's carriers
//! takes bytes, and counting what A puts on each pipe.

use std::time::Duration;

#[path = "common/mp_net.rs"]
mod mp_net;

use mp_net::{A, B, MpNet, Observe};
use zmux::proto::frame::{Dir, Frame, Gates};
use zmux::proto::record::{Event as Rec, RecordReader};
use zmux::proto::session::{
    Config, CoreEvent, PipeAuth, PipeId, PipeOptions, PipeWrite, Policy, StreamKey,
};

/// What a link's batches showed.
struct Seen {
    a_reader: RecordReader,
    b_reader: RecordReader,
    /// Stream payload bytes A wrote on the pipe.
    stream_bytes: u64,
    /// PIPE_STATUS frames A wrote: (pipe, seq, standby, priority).
    statuses: Vec<(u64, u64, bool, u64)>,
    /// PIPE_ACK frames B wrote: the number of entries of each.
    b_acks: Vec<usize>,
    /// For each batch of B's that holds a PIPE_ACK: whether it also holds
    /// a PIPE_PING.
    b_ack_pings: Vec<bool>,
    /// DATA_BLOCKED frames A wrote.
    a_data_blocked: usize,
    /// PIPE_PING frames A wrote.
    a_pings: usize,
}

impl Default for Seen {
    fn default() -> Self {
        Self {
            a_reader: RecordReader::new(1 << 20),
            b_reader: RecordReader::new(1 << 20),
            stream_bytes: 0,
            statuses: Vec::new(),
            b_acks: Vec::new(),
            b_ack_pings: Vec::new(),
            a_data_blocked: 0,
            a_pings: 0,
        }
    }
}

impl Observe for Seen {
    fn a_batch(&mut self, mut input: &[u8]) {
        while let Ok(Some(ev)) = self.a_reader.read(&mut input, &Gates::ALL) {
            match ev {
                Rec::Frame(Frame::Stream(f)) => self.stream_bytes += f.data.len() as u64,
                Rec::Frame(Frame::PipeStatus(f)) => self.statuses.push((
                    f.pipe_id,
                    f.sequence,
                    f.status == zmux::proto::frame::PipeStatusValue::Standby,
                    f.priority,
                )),
                Rec::Frame(Frame::DataBlocked(_)) => self.a_data_blocked += 1,
                Rec::Frame(Frame::PipePing) => self.a_pings += 1,
                _ => {}
            }
        }
    }

    fn b_batch(&mut self, mut input: &[u8]) {
        let (mut ack, mut ping) = (false, false);
        while let Ok(Some(ev)) = self.b_reader.read(&mut input, &Gates::ALL) {
            match ev {
                Rec::Frame(Frame::PipeAck(f)) => {
                    self.b_acks.push(f.entries().count());
                    ack = true;
                }
                Rec::Frame(Frame::PipePing) => ping = true,
                _ => {}
            }
        }
        if ack {
            self.b_ack_pings.push(ping);
        }
    }
}

/// The pair, with B's accepted streams.
type Net = MpNet<Seen, Vec<StreamKey>>;

fn config(edit: impl Fn(&mut Config)) -> Config {
    let mut c = Config::default();
    c.max_pipes = 16;
    c.pipe_auth = PipeAuth::psk(*b"0123456789abcdef0123456789abcdef");
    c.scheduler = Policy::SpreadEta;
    c.max_idle_timeout = Duration::from_secs(120);
    // Credit never limits the backlog here.
    c.initial_stream_receive_window = 16 << 20;
    c.max_stream_receive_window = zmux::Cap::Fixed(16 << 20);
    c.initial_connection_receive_window = 24 << 20;
    c.max_connection_receive_window = zmux::Cap::Fixed(24 << 20);
    c.send_buffer = 64 << 20;
    c.probation = Some(Duration::ZERO);
    // The idle-probe phase is random per session: pinned, the probe times
    // are deterministic.
    c.test_hooks().probe_phase = Some(0.0);
    edit(&mut c);
    c
}

/// A multipath pair on pipe 0, established, both configurations changed by
/// `edit`.
fn net(edit: impl Fn(&mut Config)) -> Net {
    let mut b_cfg = config(&edit);
    b_cfg.test_hooks().locator = b"server".to_vec();
    let mut n = Net::new(config(&edit), b_cfg, Vec::new());
    n.strict_joins = true;
    n.pump(8);
    assert!(n.ends[A].is_multipath() && n.ends[B].is_multipath());
    n
}

impl Net {
    fn read_b(&mut self) {
        while let Ok(Some(k)) = self.ends[B].accept(Dir::Bidi) {
            self.s.push(k);
        }
        let mut buf = vec![0u8; 1 << 16];
        for &k in &self.s {
            while let Ok(Some((n, _))) = self.ends[B].read(k, &mut buf) {
                if n == 0 {
                    break;
                }
            }
        }
    }

    /// Rounds of traffic, every byte delivered, B reading.
    fn pump(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.step(usize::MAX);
            self.read_b();
        }
    }

    /// Time passes in small steps with traffic in between.
    fn run_for(&mut self, ms: u64) {
        for _ in 0..ms / 5 {
            self.pump(2);
            self.advance(5);
        }
        self.pump(2);
    }

    fn write(&mut self, len: usize) -> StreamKey {
        let k = self.ends[A].open(Dir::Bidi).unwrap();
        let data = vec![0x5au8; len];
        assert_eq!(self.ends[A].write(k, &data).unwrap(), len);
        k
    }

    fn stream_bytes(&self, id: u64) -> u64 {
        self.links[&id].stream_bytes
    }
}

/// A preferred tier (pipe 0, priority 0) and a fallback tier (pipe 1,
/// priority 5), both joined and usable.
fn two_tiers(edit: impl Fn(&mut Config)) -> Net {
    let mut n = net(edit);
    let mut opts = PipeOptions::default();
    opts.send_priority = Some(5);
    let id = n.add_pipe(&opts).unwrap();
    assert_eq!(id, 2);
    n.run_for(200);
    n
}

#[test]
fn a_burst_that_drains_within_the_overflow_delay_stays_in_its_tier() {
    let mut n = two_tiers(|c| {
        c.overflow_delay = Duration::from_millis(100);
        c.suspect_floor = Duration::from_secs(5);
    });
    // Pipe 0 refuses bytes for a while (a full carrier): a burst it can
    // drain within D waits for it.
    n.links.get_mut(&0).unwrap().flows[A].takes = false;
    let now = n.now;
    n.ends[A].pipe_write(PipeId(0), PipeWrite::returned(now, now, 0, 0, true), now);
    let before = n.stream_bytes(2);
    n.write(32 * 1024);
    n.run_for(60);
    assert_eq!(n.stream_bytes(2), before, "a short burst overflowed");
    // Data that waits longer than D overflows while pipe 0 still cannot
    // take it.
    n.run_for(100);
    assert!(n.stream_bytes(2) > before, "a long wait did not overflow");
}

#[test]
fn sustained_overload_overflows_only_the_excess() {
    let d = Duration::from_secs(5);
    let mut n = two_tiers(|c| c.overflow_delay = d);
    n.links.get_mut(&0).unwrap().flows[A].takes = false;
    let r0 = n.ends[A]
        .pipe_info(PipeId(0))
        .unwrap()
        .delivery_rate
        .unwrap();
    // More than the preferred tier drains within D: the excess, and only
    // the excess, goes to the fallback tier (before the wait reaches D).
    let len = 12u64 << 20;
    n.write(len as usize);
    n.run_for(2000);
    let excess = len - (r0 as f64 * d.as_secs_f64()) as u64;
    let got = n.stream_bytes(2);
    let slack = 64 * 1024;
    assert!(
        got + slack >= excess && got <= excess + slack,
        "fallback carried {got}, the excess is {excess} (rate {r0})"
    );
    // The rest waits for the preferred tier.
    assert_eq!(n.stream_bytes(0), 0);
    assert!(
        n.events[A].contains(&CoreEvent::TierSaturation {
            priority: 0,
            saturated: true
        }),
        "no saturation event"
    );
}

#[test]
fn a_standby_takeover_is_announced_and_withdrawn() {
    let mut n = net(|c| c.resume_timeout = Some(Duration::from_secs(30)));
    let mut opts = PipeOptions::default();
    opts.send_standby = Some(true);
    opts.receive_standby = true;
    let standby = n.add_pipe(&opts).unwrap();
    n.run_for(200);
    let req = |n: &Net| {
        n.ends[B]
            .pipe_info(PipeId(standby))
            .unwrap()
            .peer_request
            .unwrap()
    };
    assert!(req(&n).standby);
    n.write(4096);
    n.run_for(50);
    assert_eq!(n.stream_bytes(standby), 0);
    // The only non-standby pipe fails: the standby pipe takes over, and
    // the peer is asked to follow with its configured priority.
    n.fail(0);
    n.write(4096);
    n.run_for(50);
    assert!(n.stream_bytes(standby) >= 4096);
    assert!(!req(&n).standby, "takeover not announced");
    // A new pipe becomes usable: the takeover is withdrawn.
    let fresh = n.add_pipe(&PipeOptions::default()).unwrap();
    n.run_for(200);
    assert!(req(&n).standby, "takeover not withdrawn");
    let before = n.stream_bytes(standby);
    n.write(4096);
    n.run_for(50);
    assert_eq!(n.stream_bytes(standby), before);
    assert!(n.stream_bytes(fresh) >= 4096);
    let seqs: Vec<u64> = n.links[&standby]
        .statuses
        .iter()
        .chain(&n.links[&0].statuses)
        .chain(&n.links[&fresh].statuses)
        .map(|s| s.1)
        .collect();
    // The initial request went in the PIPE_JOIN (sequence 0): the takeover
    // is 1, its withdrawal 2.
    assert!(seqs.contains(&2), "requests {seqs:?}");
}

#[test]
fn a_fate_group_keeps_the_probation_backoff_across_rejoins() {
    let base = Duration::from_secs(1);
    let probation = |n: &Net, id: u64| {
        let info = n.ends[A].pipe_info(PipeId(id)).unwrap();
        info.probation_until
            .map(|u| u.saturating_duration_since(n.now))
    };
    for (group, factor) in [(0, 1), (7, 2)] {
        let mut n = net(|c| {
            c.probation = Some(base);
            c.resume_timeout = Some(Duration::from_secs(30));
        });
        let mut opts = PipeOptions::default();
        opts.fate_group = group;
        let first = n.add_pipe(&opts).unwrap();
        n.run_for(100);
        assert!(probation(&n, first).is_some());
        // The path fails during the probation, and a pipe rejoins on it.
        n.fail(first);
        n.run_for(20);
        let again = n.add_pipe(&opts).unwrap();
        n.pump(4);
        let left = probation(&n, again).expect("in probation");
        let want = base * factor;
        assert!(
            left <= want && left + Duration::from_millis(100) >= want,
            "group {group}: probation {left:?}, expected about {want:?}"
        );
    }
}

#[test]
fn large_acknowledgement_snapshots_omit_unchanged_pipes() {
    let mut n = net(|c| c.scheduler = Policy::Affinity);
    let ids: Vec<u64> = (0..10)
        .map(|_| n.add_pipe(&PipeOptions::default()).unwrap())
        .collect();
    n.run_for(500);
    // Every inbound pipe of B has a position; then traffic on few pipes.
    for l in n.links.values_mut() {
        l.b_acks.clear();
    }
    for _ in 0..40 {
        n.write(2048);
        n.run_for(20);
    }
    let acks: Vec<usize> = n.links.values().flat_map(|l| l.b_acks.clone()).collect();
    let full = ids.len() + 1;
    assert!(acks.iter().any(|&e| e < full), "never partial: {acks:?}");
    assert!(acks.iter().any(|&e| e >= full), "never complete: {acks:?}");
}

/// BUG (reinjection hold): a new pipe may reinject one chunk until the first
/// PIPE_ACK; a stream with nothing but reinjected data was still chosen for
/// it after that chunk, found no new data and reported the session window
/// as the bottleneck (a false DATA_BLOCKED, which also masked a later real
/// one).
#[test]
fn a_reinjection_hold_reports_no_false_blocked() {
    let mut n = net(|c| c.resume_timeout = Some(Duration::from_secs(30)));
    // Bytes in flight on pipe 0 that B never acknowledges.
    n.links.get_mut(&0).unwrap().stall(true);
    n.write(64 * 1024);
    n.run_for(20);
    // A new pipe whose join is not confirmed yet carries the reinjection,
    // one chunk at first.
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    n.links.get_mut(&id).unwrap().stall(true);
    n.fail(0);
    n.run_for(100);
    let l = &n.links[&id];
    assert!(
        l.stream_bytes > 0 && l.stream_bytes <= 16 * 1024,
        "{}",
        l.stream_bytes
    );
    assert_eq!(l.a_data_blocked, 0);
}

/// The newest pipe, whatever its state.
struct Newest;

impl zmux::proto::session::Pick for Newest {
    fn pick(
        &self,
        reqs: &[zmux::proto::session::FrameInfo],
        pipes: &[zmux::proto::session::PipeSnapshot],
        out: &mut [zmux::proto::session::PickAnswer],
    ) {
        let newest = pipes
            .iter()
            .enumerate()
            .max_by_key(|(_, p)| p.pipe.0)
            .map(|(i, _)| i);
        for a in out.iter_mut().take(reqs.len()) {
            if let Some(index) = newest {
                *a = zmux::proto::session::PickAnswer::Pipe { index, bytes: 0 };
            }
        }
    }
}

/// BUG (custom policies and rule S1): a custom policy saw JOINING pipes
/// and could put new data on one while another pipe was usable.
#[test]
fn a_custom_policy_never_puts_new_data_on_a_joining_pipe() {
    let mut n = net(|c| {
        c.resume_timeout = Some(Duration::from_secs(30));
        c.scheduler = zmux::proto::session::Policy::Custom(std::sync::Arc::new(Newest));
    });
    let id = n.add_pipe(&PipeOptions::default()).unwrap();
    // The join never reaches B: the pipe stays JOINING.
    n.links.get_mut(&id).unwrap().stall(true);
    n.write(64 * 1024);
    n.run_for(50);
    assert_eq!(n.stream_bytes(id), 0);
    assert!(n.stream_bytes(0) >= 64 * 1024);
}

/// BUG (probation settings): disabling probation while a pipe is in it left
/// the pipe in probation for ever, and a huge probation base overflowed the
/// time arithmetic.
#[test]
fn probation_settings_take_effect_safely() {
    let mut n = net(|c| c.resume_timeout = Some(Duration::from_secs(30)));
    let mut opts = PipeOptions::default();
    opts.probation = Some(Duration::from_secs(10));
    let id = n.add_pipe(&opts).unwrap();
    n.run_for(200);
    assert!(n.ends[A].pipe_info(PipeId(id)).unwrap().in_probation);
    n.ends[A]
        .set_pipe_probation(PipeId(id), Some(Duration::ZERO))
        .unwrap();
    assert!(!n.ends[A].pipe_info(PipeId(id)).unwrap().in_probation);
    // A huge base: in probation, without overflow, for as long as it runs.
    let other = n.add_pipe(&PipeOptions::default()).unwrap();
    n.ends[A]
        .set_pipe_probation(PipeId(other), Some(Duration::MAX))
        .unwrap();
    n.run_for(500);
    let info = n.ends[A].pipe_info(PipeId(other)).unwrap();
    assert!(info.probation_until.is_none() || info.in_probation);
}

/// A PIPE_ACK on a pipe that has carried nothing ack-eliciting for more
/// than max(1 s, T_suspect) brings a PIPE_PING in the same record
/// (MULTIPATH.md Section 6.5), also when it is the answer to a PIPE_PING
/// on that pipe pair rather than the primary acknowledgement: the peer's
/// return path is probed while it is in use.
#[test]
fn a_ping_answer_on_a_quiet_pipe_carries_a_liveness_ping() {
    let mut n = two_tiers(|c| {
        c.standby_probe = Duration::ZERO;
        c.redundancy = zmux::Redundancy::Off;
    });
    n.run_for(3000);
    let before = n.links[&2].b_ack_pings.len();
    n.ends[A].revalidate_pipes(Some(PipeId(2)), n.now).unwrap();
    n.run_for(100);
    let answer = n.links[&2].b_ack_pings.get(before).copied();
    assert_eq!(
        answer,
        Some(true),
        "the answer on the quiet pipe came without a PIPE_PING"
    );
}

/// MULTIPATH.md Section 7.1: a quiet session
/// (no traffic frame for the 15 s busy window) probes its less-preferred
/// pipe at the probe interval, not every `standby_probe`; `probe_interval`
/// sets that interval for pipe pairs, and 0 turns those probes off.
#[test]
fn quiet_sessions_probe_at_the_probe_interval() {
    let quiet_minute = |n: &mut Net| {
        // Past the busy window of establishment, then one quiet minute.
        for _ in 0..400 {
            n.pump(2);
            n.advance(50);
        }
        let before = [n.links[&0].a_pings, n.links[&2].a_pings];
        for _ in 0..1200 {
            n.pump(2);
            n.advance(50);
        }
        [
            n.links[&0].a_pings - before[0],
            n.links[&2].a_pings - before[1],
        ]
    };
    // The 15 s default: about four probes a minute on each pipe, never the
    // sixty of the busy rule on the less-preferred one.
    let mut n = two_tiers(|_| {});
    for pings in quiet_minute(&mut n) {
        assert!((3..=5).contains(&pings), "{pings} probes");
    }
    let mut n = two_tiers(|c| c.probe_interval = Duration::from_secs(60));
    for pings in quiet_minute(&mut n) {
        assert!((1..=2).contains(&pings), "{pings} probes");
    }
    let mut n = two_tiers(|c| c.probe_interval = Duration::ZERO);
    assert_eq!(quiet_minute(&mut n), [0, 0]);
    // Traffic resumes: the less-preferred pipe is probed at once.
    let before = n.links[&2].a_pings;
    n.write(100);
    n.pump(2);
    assert_eq!(n.links[&2].a_pings, before + 1);
}

/// The phase brings forward only the first
/// idle probe after the pipe becomes usable or a quiet session becomes busy;
/// a session busy with a message every 10 s keeps the 15 s probe interval of
/// the pipe carrying them, not a PIPE_PING after each message.
#[test]
fn intermittent_traffic_does_not_bring_probes_forward() {
    let mut n = two_tiers(|c| {
        c.scheduler = Policy::Affinity;
        c.redundancy = zmux::Redundancy::Off;
        c.standby_probe = Duration::ZERO;
        c.test_hooks().probe_phase = Some(0.5);
    });
    let message = |n: &mut Net| {
        n.write(100);
        for _ in 0..200 {
            n.pump(2);
            n.advance(50);
        }
    };
    // Past the first probe, which the phase may bring forward.
    for _ in 0..3 {
        message(&mut n);
    }
    let before = n.links[&0].a_pings;
    for _ in 0..12 {
        message(&mut n);
    }
    let pings = n.links[&0].a_pings - before;
    assert!(pings <= 2, "{pings} probes in two minutes of messages");
}

/// Config durations take any value: a deadline beyond the clock's range
/// never comes, instead of overflowing `Instant` in the core.
#[test]
fn huge_timer_settings_never_overflow_the_clock() {
    let huge = Duration::MAX;
    let settings: [&dyn Fn(&mut Config); 4] = [
        &|c| {
            c.probe_interval = huge;
            c.standby_probe = huge;
        },
        &|c| {
            c.probe_interval = huge - Duration::from_secs(1);
            c.standby_probe = huge - Duration::from_secs(1);
            c.test_hooks().probe_phase = Some(0.999);
        },
        &|c| {
            c.handshake_timeout = huge;
            c.max_idle_timeout = Duration::ZERO;
            c.keep_alive_period = Some(huge);
            c.overflow_delay = huge;
        },
        &|c| {
            c.suspect_floor = huge;
            c.dead_timeout = Some(huge);
            c.probation = Some(huge);
        },
    ];
    for edit in settings {
        let mut n = two_tiers(edit);
        n.write(64 * 1024);
        n.run_for(500);
        // Quiet, then busy again.
        for _ in 0..400 {
            n.pump(2);
            n.advance(50);
        }
        n.write(100);
        n.run_for(500);
        n.fail(2);
        n.run_for(500);
    }
}
