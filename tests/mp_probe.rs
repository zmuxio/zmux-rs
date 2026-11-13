//! Idle-pipe probes as the per-pipe heartbeat,
//! sans IO: per-pipe intervals and jitter, the bounds of each wait, their
//! isolation from the session's idle and keep-alive timers, the answer's
//! pipe pair, the pipes' traffic clock and shaping of the probes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[path = "common/mp_net.rs"]
mod mp_net;

use mp_net::{A, B, MpNet, Observe};
use zmux::proto::frame::{Dir, Frame, Gates};
use zmux::proto::record::{Event as Rec, RecordReader};
use zmux::proto::session::{
    Config, PipeAuth, PipeError, PipeId, PipeOptions, Role, SessionCore, SessionError,
};
use zmux::shaping::{Caps, Effects, Event, RecordPlan, RecordView, Shaper};

/// What a link's batches showed.
struct Seen {
    a_reader: RecordReader,
    b_reader: RecordReader,
    /// PIPE_PING frames A wrote.
    a_pings: u64,
    /// QX_PING frames A wrote.
    a_qx_pings: u64,
    /// PIPE_ACK frames B wrote.
    b_acks: u64,
    /// PIPE_PING frames B wrote.
    b_pings: u64,
}

impl Default for Seen {
    fn default() -> Self {
        Self {
            a_reader: RecordReader::new(1 << 20),
            b_reader: RecordReader::new(1 << 20),
            a_pings: 0,
            a_qx_pings: 0,
            b_acks: 0,
            b_pings: 0,
        }
    }
}

impl Observe for Seen {
    fn a_batch(&mut self, mut input: &[u8]) {
        while let Ok(Some(ev)) = self.a_reader.read(&mut input, &Gates::ALL) {
            match ev {
                Rec::Frame(Frame::PipePing) => self.a_pings += 1,
                Rec::Frame(Frame::QxPing(_)) => self.a_qx_pings += 1,
                _ => {}
            }
        }
    }

    fn b_batch(&mut self, mut input: &[u8]) {
        while let Ok(Some(ev)) = self.b_reader.read(&mut input, &Gates::ALL) {
            match ev {
                Rec::Frame(Frame::PipeAck(_)) => self.b_acks += 1,
                Rec::Frame(Frame::PipePing) => self.b_pings += 1,
                _ => {}
            }
        }
    }
}

type Net = MpNet<Seen, ()>;

const STEP: u64 = 10;

fn config(edit: &dyn Fn(&mut Config)) -> Config {
    let mut c = Config::default();
    c.max_pipes = 8;
    c.pipe_auth = PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end();
    c.max_idle_timeout = None;
    c.probation = None;
    c.liveness.standby_probe = None;
    c.liveness.probe_jitter = 0.0;
    // Keep-alive would keep idle sessions open and put QX_PINGs on pipe 0.
    c.liveness.keep_alive_period = None;
    c.test_hooks().probe_seed = Some(7);
    edit(&mut c);
    c
}

/// A multipath pair on pipe 0; B never probes of its own, so that A's
/// PIPE_PINGs are those of its own schedule.
fn net(a: &dyn Fn(&mut Config), b: &dyn Fn(&mut Config)) -> Net {
    let mut b_cfg = config(&|c| {
        c.liveness.probe_interval = None;
        b(c);
    });
    b_cfg.test_hooks().locator = b"server".to_vec();
    let mut n = Net::new(config(a), b_cfg, ());
    n.strict_joins = true;
    for _ in 0..8 {
        n.step(usize::MAX);
    }
    assert!(n.ends[A].is_multipath() && n.ends[B].is_multipath());
    n
}

/// Runs for `ms`, returning the times at which A wrote a PIPE_PING on
/// link `id`.
fn ping_times(n: &mut Net, id: u64, ms: u64) -> Vec<Instant> {
    let mut times = Vec::new();
    for _ in 0..ms / STEP {
        let before = n.links[&id].a_pings;
        n.step(usize::MAX);
        n.step(usize::MAX);
        if n.links[&id].a_pings > before {
            times.push(n.now);
        }
        n.advance(STEP);
    }
    times
}

fn gaps(times: &[Instant]) -> Vec<Duration> {
    times.windows(2).map(|w| w[1] - w[0]).collect()
}

/// Idle probe settings: a pipe's probe interval below 1 s and a jitter outside
/// [0, 1) are refused, and so is a session jitter outside it.
#[test]
fn probe_settings_are_validated() {
    for j in [-0.1, 1.0, f64::NAN] {
        let mut c = config(&|_| {});
        c.liveness.probe_jitter = j;
        assert!(
            SessionCore::new(c, Role::Client, None, Instant::now()).is_err(),
            "{j}"
        );
    }
    // Both intervals: off (None) or a period of at least 1 s; a period of
    // 0 is not off.
    let ms = |k| Some(Duration::from_millis(k));
    for (k, ok) in [
        (None, true),
        (ms(0), false),
        (ms(1), false),
        (ms(999), false),
        (ms(1000), true),
    ] {
        let mut c = config(&|_| {});
        c.liveness.probe_interval = k;
        let r = SessionCore::new(c, Role::Client, None, Instant::now());
        assert_eq!(r.is_ok(), ok, "probe_interval {k:?}");
        let mut c = config(&|_| {});
        c.liveness.standby_probe = k;
        let r = SessionCore::new(c, Role::Client, None, Instant::now());
        assert_eq!(r.is_ok(), ok, "standby_probe {k:?}");
    }
    let mut n = net(&|_| {}, &|_| {});
    let bs = Some(zmux::proto::record::Framing::ByteStream);
    let bad = [
        PipeOptions::new().with_liveness(zmux::PipeLiveness {
            probe_interval: zmux::Inherit::Set(Some(Duration::from_millis(999))),
            ..Default::default()
        }),
        PipeOptions::new().with_liveness(zmux::PipeLiveness {
            probe_jitter: zmux::Inherit::Set(1.0),
            ..Default::default()
        }),
        PipeOptions::new().with_liveness(zmux::PipeLiveness {
            probe_jitter: zmux::Inherit::Set(-0.01),
            ..Default::default()
        }),
    ];
    for opts in bad {
        let r = n.ends[A].add_pipe(
            bs,
            bs,
            &opts,
            zmux::proto::seal::RecordMode::Trusted,
            None,
            n.now,
        );
        assert!(matches!(r, Err(PipeError::InvalidOptions(_))), "{opts:?}");
    }
    let ok = PipeOptions::new().with_liveness(zmux::PipeLiveness {
        probe_interval: zmux::Inherit::Set(Some(Duration::from_secs(1))),
        probe_jitter: zmux::Inherit::Set(0.0),
        ..Default::default()
    });
    assert!(n.add_pipe(&ok).is_some());
    // Off: no idle probes on the pipe; a zero interval is not off.
    assert!(
        PipeOptions::new()
            .with_liveness(zmux::PipeLiveness {
                probe_interval: zmux::Inherit::Set(None),
                ..Default::default()
            })
            .validate()
            .is_ok()
    );
    assert!(
        PipeOptions::new()
            .with_liveness(zmux::PipeLiveness {
                probe_interval: zmux::Inherit::Set(Some(Duration::ZERO)),
                ..Default::default()
            })
            .validate()
            .is_err()
    );
}

/// Idle probe waits: without jitter each wait is the interval; with it, each
/// lies in [k (1 - j), k] and they differ.
#[test]
fn probe_waits_lie_within_the_jittered_interval() {
    let k = Duration::from_secs(2);
    let slack = Duration::from_millis(3 * STEP);
    let mut n = net(&|c| c.liveness.probe_interval = Some(k), &|_| {});
    let g = gaps(&ping_times(&mut n, 0, 40_000));
    assert!(g.len() >= 15, "{g:?}");
    for d in &g {
        assert!(d.abs_diff(k) <= slack, "{g:?}");
    }
    let mut n = net(
        &|c| {
            c.liveness.probe_interval = Some(k);
            c.liveness.probe_jitter = 0.5;
        },
        &|_| {},
    );
    let g = gaps(&ping_times(&mut n, 0, 60_000));
    assert!(g.len() >= 30, "{g:?}");
    for d in &g {
        assert!(*d + slack >= k / 2 && *d <= k + slack, "{g:?}");
    }
    let (lo, hi) = (g.iter().min().unwrap(), g.iter().max().unwrap());
    assert!(*hi - *lo >= Duration::from_millis(400), "{g:?}");
}

/// A pipe's own settings override the session's: a pipe added with a 1 s
/// interval and no jitter is probed every second.
#[test]
fn pipe_options_override_the_session_settings() {
    let mut n = net(&|c| c.liveness.probe_jitter = 0.5, &|_| {});
    let opts = PipeOptions::new().with_liveness(zmux::PipeLiveness {
        probe_interval: zmux::Inherit::Set(Some(Duration::from_secs(1))),
        probe_jitter: zmux::Inherit::Set(0.0),
        ..Default::default()
    });
    let id = n.add_pipe(&opts).unwrap();
    ping_times(&mut n, id, 1000);
    let g = gaps(&ping_times(&mut n, id, 20_000));
    assert!(g.len() >= 15, "{g:?}");
    for d in &g {
        assert!(
            d.abs_diff(Duration::from_secs(1)) <= Duration::from_millis(30),
            "{g:?}"
        );
    }
}

/// Idle probes and the idle timeout: a session with nothing but probes and their answers
/// still closes on its idle timeout; probes do not move keep-alive, whose
/// QX_PINGs (ack-eliciting) only move the start of the probes' waits.
#[test]
fn probes_neither_keep_the_session_alive_nor_follow_keep_alive() {
    let mut n = net(
        &|c| {
            c.liveness.probe_interval = Some(Duration::from_secs(2));
            c.max_idle_timeout = Some(Duration::from_secs(10));
        },
        &|c| c.max_idle_timeout = Some(Duration::from_secs(10)),
    );
    let pings = ping_times(&mut n, 0, 12_000);
    assert!(pings.len() >= 3, "{pings:?}");
    assert!(
        matches!(n.ends[A].error(), Some(SessionError::IdleTimeout { .. })),
        "{:?}",
        n.ends[A].error()
    );
    // The keep-alive QX_PINGs of a quiet session come at the same times
    // with probes every second as without any.
    let keep_alive = |k: Option<Duration>| {
        let mut n = net(
            &|c| {
                c.liveness.probe_interval = k;
                c.liveness.probe_jitter = 0.3;
                c.max_idle_timeout = Some(Duration::from_secs(60));
                c.liveness.keep_alive_period = Some(Duration::from_secs(3));
            },
            &|c| c.max_idle_timeout = Some(Duration::from_secs(60)),
        );
        let t0 = n.now;
        let mut times = Vec::new();
        for _ in 0..20_000 / STEP {
            let before = n.links[&0].a_qx_pings;
            n.step(usize::MAX);
            n.step(usize::MAX);
            if n.links[&0].a_qx_pings > before {
                times.push(n.now - t0);
            }
            n.advance(STEP);
        }
        times
    };
    let with = keep_alive(Some(Duration::from_secs(1)));
    assert!(with.len() >= 5, "{with:?}");
    assert_eq!(with, keep_alive(None));
}

/// Probe answers: with jitter, each PIPE_PING on a pipe pair is answered by
/// a PIPE_ACK on the same pair's other direction.
#[test]
fn jittered_probes_are_answered_on_their_pipe_pair() {
    let mut n = net(
        &|c| {
            c.liveness.probe_interval = Some(Duration::from_secs(1));
            c.liveness.probe_jitter = 0.4;
        },
        &|_| {},
    );
    let id = n.add_pipe(&PipeOptions::new()).unwrap();
    ping_times(&mut n, id, 1000);
    let (p0, a0) = (n.links[&id].a_pings, n.links[&id].b_acks);
    ping_times(&mut n, id, 20_000);
    let (p, a) = (n.links[&id].a_pings - p0, n.links[&id].b_acks - a0);
    assert!(p >= 15, "{p} probes");
    assert!(a >= p, "{p} probes, {a} answers on the pair");
}

/// The traffic clock: probes, their answers and padding leave a pipe's traffic
/// clock alone; stream data in either direction restarts it.
#[test]
fn since_last_traffic_counts_traffic_frames_only() {
    let mut n = net(
        &|c| c.liveness.probe_interval = Some(Duration::from_secs(1)),
        &|_| {},
    );
    let since = |n: &Net, end: usize| {
        n.ends[end]
            .pipe_info(PipeId::new(0))
            .unwrap()
            .since_last_traffic
            .unwrap()
    };
    let pings = ping_times(&mut n, 0, 5000);
    assert!(pings.len() >= 4);
    assert!(
        since(&n, A) >= Duration::from_millis(4900),
        "{:?}",
        since(&n, A)
    );
    assert!(since(&n, B) >= Duration::from_millis(4900));
    let k = n.ends[A].open(Dir::Bidi).unwrap();
    n.ends[A].write(k, b"traffic").unwrap();
    ping_times(&mut n, 0, 100);
    assert!(
        since(&n, A) <= Duration::from_millis(100),
        "{:?}",
        since(&n, A)
    );
    assert!(since(&n, B) <= Duration::from_millis(100));
    ping_times(&mut n, 0, 3000);
    assert!(since(&n, A) >= Duration::from_millis(2900));
}

/// A shaper that delays every record and counts its plans.
struct Delay {
    plans: Arc<AtomicU64>,
    by: Duration,
}

impl Shaper for Delay {
    fn capabilities(&self) -> Caps {
        Caps::PLAN
    }

    fn plan(&mut self, _: &RecordView, plan: &mut RecordPlan) {
        self.plans.fetch_add(1, Ordering::Relaxed);
        plan.delay = self.by;
    }

    fn on_event(&mut self, _: &Event, _: &mut Effects) {}
}

/// Probes and shaping: probe records pass through the shaper; a delay longer
/// than T_suspect's floor holds them, and the stall clock starts when the
/// record goes, so the pipe is never suspected.
#[test]
fn probes_are_shaped_and_a_delay_is_no_stall() {
    let mut n = net(
        &|c| {
            c.liveness.probe_interval = Some(Duration::from_secs(1));
            c.liveness.suspect_floor = Duration::from_millis(100);
        },
        &|_| {},
    );
    let plans = Arc::new(AtomicU64::new(0));
    let p = plans.clone();
    n.ends[A].set_shaper(Some(Arc::new(move |_: &zmux::shaping::ShapedPipe| {
        Some(Box::new(Delay {
            plans: p.clone(),
            by: Duration::from_millis(400),
        }) as Box<dyn Shaper>)
    })));
    ping_times(&mut n, 0, 2000);
    let (p0, k0) = (plans.load(Ordering::Relaxed), n.links[&0].a_pings);
    ping_times(&mut n, 0, 20_000);
    let pings = n.links[&0].a_pings - k0;
    assert!(pings >= 10, "{pings} probes");
    assert!(
        plans.load(Ordering::Relaxed) - p0 >= pings,
        "probes not shaped"
    );
    let info = n.ends[A].pipe_info(PipeId::new(0)).unwrap();
    assert_eq!(info.suspect_count, 0, "{info:?}");
    assert!(n.ends[A].error().is_none());
}

/// The first probe wait: the first wait of the bootstrap pipe, which has sent no
/// PIPE_PING, is drawn from [0, k] when j > 0, and is k with j = 0.
#[test]
fn the_bootstrap_pipe_draws_its_first_wait_from_the_whole_interval() {
    let k = Duration::from_secs(10);
    let first = |j: f64, seed: u64| {
        let mut n = net(
            &|c| {
                c.liveness.probe_interval = Some(k);
                c.liveness.probe_jitter = j;
                c.test_hooks().probe_seed = Some(seed);
            },
            &|_| {},
        );
        let t0 = n.now;
        ping_times(&mut n, 0, 10_100)[0] - t0
    };
    let slack = Duration::from_millis(3 * STEP);
    assert!(first(0.0, 1).abs_diff(k) <= slack);
    let draws: Vec<Duration> = (1..=12).map(|s| first(0.25, s)).collect();
    assert!(draws.iter().all(|d| *d <= k + slack), "{draws:?}");
    // Below k (1 - j): the whole interval, not the later waits' range.
    assert!(draws.iter().any(|d| *d < k * 3 / 4), "{draws:?}");
}

/// The probe deadline: it is measured to the carrier. Records
/// that shaping may hold for up to `max_delay` (here held 2 s each) are
/// built that much before the interval ends, so that each PIPE_PING is
/// handed to the carrier at most k after the previous one.
#[test]
fn probes_reach_the_carrier_within_the_interval_despite_shaping_holds() {
    let k = Duration::from_secs(10);
    let mut n = net(
        &|c| {
            c.liveness.probe_interval = Some(k);
            c.shaping_limits.max_delay = Some(Duration::from_secs(3));
        },
        &|_| {},
    );
    let plans = Arc::new(AtomicU64::new(0));
    let p = plans.clone();
    n.ends[A].set_shaper(Some(Arc::new(move |_: &zmux::shaping::ShapedPipe| {
        Some(Box::new(Delay {
            plans: p.clone(),
            by: Duration::from_secs(2),
        }) as Box<dyn Shaper>)
    })));
    let g = gaps(&ping_times(&mut n, 0, 60_000));
    assert!(g.len() >= 4, "{g:?}");
    // The answers to B's PIPE_PINGs, held 2 s, carry PIPE_PINGs of their
    // own (A's pipe is idle for longer than R_p by then): shorter gaps.
    assert!(g.iter().all(|d| *d <= k), "{g:?}");
    let longest = *g.iter().max().unwrap();
    assert!(
        longest + Duration::from_millis(3 * STEP) >= k - Duration::from_secs(1),
        "{g:?}"
    );
}

/// A shaper that sees records but plans none of them.
struct Unplanned;

impl Shaper for Unplanned {
    fn capabilities(&self) -> Caps {
        Caps::RECORD_IN
    }

    fn on_event(&mut self, _: &Event, _: &mut Effects) {}
}

/// H_p is nonzero only for a pipe whose shaper plans its records: a
/// shaper that plans none holds nothing, so the probes keep the full
/// interval k although `max_delay` is set.
#[test]
fn probes_of_a_pipe_without_plans_keep_the_whole_interval() {
    let k = Duration::from_secs(10);
    let mut n = net(
        &|c| {
            c.liveness.probe_interval = Some(k);
            c.liveness.probe_jitter = 0.0;
            c.shaping_limits.max_delay = Some(Duration::from_secs(3));
        },
        &|c| c.liveness.probe_jitter = 0.0,
    );
    n.ends[A].set_shaper(Some(Arc::new(|_: &zmux::shaping::ShapedPipe| {
        Some(Box::new(Unplanned) as Box<dyn Shaper>)
    })));
    let g = gaps(&ping_times(&mut n, 0, 60_000));
    assert!(g.len() >= 3, "{g:?}");
    let slack = Duration::from_millis(3 * STEP);
    assert!(g.iter().all(|d| d.abs_diff(k) <= slack), "{g:?}");
}

/// Probe answers in a quiet session: in a quiet session the answer to a PIPE_PING
/// goes only on the probed pipe pair, never on the primary pipe, and
/// carries a PIPE_PING of its own once the answering pipe has been idle
/// for R_p, even at an end whose idle probes are off.
#[test]
fn quiet_answers_stay_on_the_probed_pair_and_probe_back() {
    let mut n = net(&|c| c.liveness.probe_interval = None, &|_| {});
    let opts = PipeOptions::new().with_liveness(zmux::PipeLiveness {
        probe_interval: zmux::Inherit::Set(Some(Duration::from_secs(2))),
        probe_jitter: zmux::Inherit::Set(0.0),
        ..Default::default()
    });
    let id = n.add_pipe(&opts).unwrap();
    // Past the busy window of establishment and of the join.
    ping_times(&mut n, id, 16_000);
    let before = |n: &Net| {
        (
            n.links[&0].b_acks,
            n.links[&id].b_acks,
            n.links[&id].b_pings,
            n.links[&id].a_pings,
        )
    };
    let b0 = before(&n);
    ping_times(&mut n, id, 20_000);
    let b1 = before(&n);
    let pings = b1.3 - b0.3;
    assert!(pings >= 8, "{pings} probes");
    assert_eq!(b1.0, b0.0, "an answer went on the primary pipe");
    assert!(b1.1 - b0.1 >= pings, "answers on the pair");
    // Each answer of B, idle since its previous one (2 s > R_p), probes.
    assert!(
        b1.2 - b0.2 >= pings - 1,
        "{} pings with the answers",
        b1.2 - b0.2
    );
    assert_eq!(
        n.ends[A].pipe_info(PipeId::new(id)).unwrap().suspect_count,
        0
    );
}

/// When `DeadTimeout` is below T_suspect, the
/// suspicion and the failure of the last pipe fall due together, and the
/// timer pass that suspects the pipe also fails it.
#[test]
fn a_suspicion_and_a_failure_due_together_fire_in_one_pass() {
    let mut n = net(
        &|c| {
            c.liveness.suspect_floor = Duration::from_secs(3);
            c.liveness.dead_timeout = zmux::Cap::Fixed(Duration::from_secs(1));
        },
        &|_| {},
    );
    let k = n.ends[A].open(Dir::Bidi).unwrap();
    n.ends[A].write(k, b"stalls").unwrap();
    for f in &mut n.links.get_mut(&0).unwrap().flows {
        f.blackhole = true;
    }
    n.step(usize::MAX);
    let end = n.now + Duration::from_secs(30);
    while n.ends[A].error().is_none() {
        let t = n.ends[A].poll_timeout().expect("a deadline");
        assert!(t <= end, "never failed");
        n.now = n.now.max(t);
        n.ends[A].handle_timeout(n.now);
        let out = n.ends[A].pipe_state(PipeId::new(0), zmux::proto::session::PipeHalf::Outbound);
        assert_ne!(
            out,
            Some(zmux::DirectionState::Outbound(zmux::OutboundState::Suspect)),
            "suspected without failing"
        );
    }
    assert!(
        matches!(n.ends[A].error(), Some(SessionError::PipesLost { .. })),
        "{:?}",
        n.ends[A].error()
    );
}

/// A suspicion deadline that passed before its
/// timer pass ran stays pending through a critical section in between (a
/// transmit at the later time), so the timer armed after it still fires it.
#[test]
fn a_passed_suspicion_stays_pending() {
    let mut n = net(
        &|c| c.liveness.suspect_floor = Duration::from_secs(1),
        &|_| {},
    );
    let k = n.ends[A].open(Dir::Bidi).unwrap();
    n.ends[A].write(k, b"stalls").unwrap();
    for f in &mut n.links.get_mut(&0).unwrap().flows {
        f.blackhole = true;
    }
    n.step(usize::MAX);
    // The deadline passes without a timer pass; a write and a transmit at
    // the later time run first.
    n.now += Duration::from_secs(5);
    n.ends[A].write(k, b"more").unwrap();
    n.step(usize::MAX);
    let t = n.ends[A].poll_timeout().expect("a deadline");
    assert!(
        t <= n.now,
        "passed suspicion deadline reported {:?} ahead",
        t - n.now
    );
    n.ends[A].handle_timeout(n.now);
    assert_eq!(
        n.ends[A].pipe_state(PipeId::new(0), zmux::proto::session::PipeHalf::Outbound),
        Some(zmux::DirectionState::Outbound(zmux::OutboundState::Suspect))
    );
}

/// The keep-alive period in effect is capped at half
/// the effective idle timeout, and each wait is drawn from [k (1 - j), k]
/// with the probe jitter j; an idle session whose peer answers stays open.
#[test]
fn keep_alive_is_capped_at_half_the_idle_timeout_and_jittered() {
    let qx_times = |j: f64| {
        let mut n = net(
            &|c| {
                c.liveness.probe_interval = None;
                c.liveness.probe_jitter = j;
                c.max_idle_timeout = Some(Duration::from_secs(10));
                c.liveness.keep_alive_period = Some(Duration::from_secs(15));
            },
            &|c| c.max_idle_timeout = Some(Duration::from_secs(10)),
        );
        let mut times = Vec::new();
        for _ in 0..60_000 / STEP {
            let before = n.links[&0].a_qx_pings;
            n.step(usize::MAX);
            n.step(usize::MAX);
            if n.links[&0].a_qx_pings > before {
                times.push(n.now);
            }
            n.advance(STEP);
        }
        assert!(n.ends[A].error().is_none(), "{:?}", n.ends[A].error());
        gaps(&times)
    };
    let k = Duration::from_secs(5);
    let slack = Duration::from_millis(3 * STEP);
    let g = qx_times(0.0);
    assert!(g.len() >= 10, "{g:?}");
    assert!(g.iter().all(|d| d.abs_diff(k) <= slack), "{g:?}");
    let g = qx_times(0.5);
    assert!(g.len() >= 10, "{g:?}");
    assert!(
        g.iter().all(|d| *d + slack >= k / 2 && *d <= k + slack),
        "{g:?}"
    );
    assert!(
        g.iter().max().unwrap().abs_diff(*g.iter().min().unwrap()) >= Duration::from_millis(300)
    );
}
