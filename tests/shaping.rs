//! Record shaping on two cores connected in memory.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test and bench values are small and bounded; checked conversions would only add noise"
)]
#![allow(
    clippy::large_stack_arrays,
    reason = "scenario code: buffers and futures stay on the stack on purpose, long scripted scenarios read top to bottom"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use zmux::proto::frame::Dir;
use zmux::proto::session::{Config, Preamble};
use zmux::shaping::{
    Account, Caps, Effects, Event, EventKind, Factory, Gate, Injection, Limits, RecordPlan,
    RecordView, Shaper, varint_len,
};

#[path = "common/core_pair.rs"]
mod core_pair;

use core_pair::{CorePair as Pair, P0};

type EventFn = Box<dyn FnMut(&Event, &mut Effects) + Send>;

/// The wire length of a record of `frames` bytes on the byte stream of these tests.
fn wire(frames: usize) -> usize {
    frames + varint_len(frames as u64)
}

/// A shaper made of closures.
struct Fns {
    caps: Caps,
    plan: Box<dyn FnMut(&mut RecordPlan) + Send>,
    event: EventFn,
}

impl Shaper for Fns {
    fn capabilities(&self) -> Caps {
        self.caps
    }

    fn plan(&mut self, _: &RecordView, plan: &mut RecordPlan) {
        (self.plan)(plan);
    }

    fn on_event(&mut self, e: &Event, r: &mut Effects) {
        (self.event)(e, r);
    }
}

fn plan_factory(f: impl Fn(&mut RecordPlan) + Send + Sync + Clone + 'static) -> Arc<dyn Factory> {
    Arc::new(move |_: &zmux::shaping::ShapedPipe| {
        let f = f.clone();
        Some(Box::new(Fns {
            caps: Caps::PLAN,
            plan: Box::new(move |p| f(p)),
            event: Box::new(|_, _| {}),
        }) as Box<dyn Shaper>)
    })
}

fn event_factory(
    f: impl Fn(&Event, &mut Effects) + Send + Sync + Clone + 'static,
) -> Arc<dyn Factory> {
    Arc::new(move |_: &zmux::shaping::ShapedPipe| {
        let f = f.clone();
        Some(Box::new(Fns {
            caps: Caps::NONE,
            plan: Box::new(|_| {}),
            event: Box::new(move |e, r| f(e, r)),
        }) as Box<dyn Shaper>)
    })
}

/// The frames lengths of the records in `wire`, and their trailing zero
/// bytes.
fn records(mut wire: &[u8], out: &mut Vec<(usize, usize)>) {
    while !wire.is_empty() {
        let len = 1 << (wire[0] >> 6);
        let mut v = u64::from(wire[0] & 0x3f);
        for b in &wire[1..len] {
            v = v << 8 | u64::from(*b);
        }
        let body = &wire[len..len + v as usize];
        let zeros = body.iter().rev().take_while(|&&b| b == 0).count();
        out.push((v as usize, zeros));
        wire = &wire[len + v as usize..];
    }
}

/// Sends `n` bytes on a new stream from A and checks that B reads them;
/// returns A's records.
fn transfer(p: &mut Pair, n: usize, recs: &mut Vec<(usize, usize)>) {
    let data = vec![7u8; n];
    let k = p.a.open(Dir::Bidi).unwrap();
    let mut off = 0;
    let mut got = Vec::new();
    let mut accepted = None;
    for _ in 0..10_000 {
        if off < n {
            off += p.a.write(k, &data[off..]).unwrap_or(0);
            if off == n {
                p.a.finish(k).unwrap();
            }
        }
        let moved = p.send_with(true, |w| records(w, recs)) + p.send(false);
        p.drain_events();
        if accepted.is_none() {
            accepted = p.b.accept(Dir::Bidi).unwrap();
        }
        if let Some(r) = accepted {
            let mut buf = [0u8; 4096];
            while let Ok(Some((m, _))) = p.b.read(r, &mut buf) {
                if m == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..m]);
            }
        }
        if got.len() == n && off == n && moved == 0 {
            return;
        }
        if moved == 0 {
            p.now += Duration::from_millis(1);
            p.a.handle_timeout(p.now);
            p.b.handle_timeout(p.now);
        }
    }
    panic!("transfer: {} of {n} bytes", got.len());
}

fn request_cover(e: &Event, effects: &mut Effects, len: usize, repeat: bool) {
    match e.kind {
        EventKind::Start => effects.wake = Some(Some(e.now + 1_000)),
        EventKind::Timer => {
            effects.inject = Some(Some(Injection::new(e.now + 1, e.now, len)));
            if repeat {
                effects.wake = Some(Some(e.now + 1_000));
            }
        }
        _ => {}
    }
}

fn fund_cover(p: &mut Pair) {
    let mut limits = p.a.shaping_limits();
    limits.wire = Some(Account::new(1_000_000_000, 1_000_000_000, 0, 0));
    p.a.set_shaping_limits(limits).unwrap();
}

fn install(p: &mut Pair, factory: Option<Arc<dyn Factory>>) {
    use zmux::shaping::{Budget, ProfileLimits};
    let local = p.a.shaping_limits();
    let profile = local.profile.or_else(|| {
        local
            .wire
            .map(|_| ProfileLimits::new(10, 50_000, 30_000, Duration::from_micros(2000)))
    });
    p.a.set_shaper_budgeted(factory, Budget::new(local.wire, profile, false))
        .unwrap();
}

/// Repeated injections every millisecond for one second of session time.
fn inject_for_a_second(p: &mut Pair) -> (usize, zmux::shaping::Stats) {
    install(p, Some(event_factory(|e, r| request_cover(e, r, 20, true))));
    let mut recs = Vec::new();
    for _ in 0..1000 {
        p.now += Duration::from_millis(1);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.send_with(true, |w| records(w, &mut recs));
        p.send(false);
        p.drain_events();
    }
    install(p, None);
    let pad = recs.iter().filter(|&&(n, z)| n == 20 && z == 20).count();
    (pad, p.a.shaping_stats())
}

#[test]
fn injection_toward_a_zmux_peer() {
    let mut p = Pair::new(Config::default(), Config::default());
    fund_cover(&mut p);
    let (pad, st) = inject_for_a_second(&mut p);
    assert!(
        st.injection_accepted_requests > 16
            && pad as u64 == st.injection_accepted_requests
            && st.injection_rejected == 0,
        "{st:?}, {pad}"
    );
    assert_eq!(p.b.state(), zmux::proto::session::State::Active);
}

#[test]
fn injection_toward_a_plain_qmux_peer() {
    let mut qmux = Config::default();
    qmux.test_hooks().transport_parameters = Some(zmux::proto::params::TransportParameters {
        initial_max_data: Some(1 << 20),
        initial_max_stream_data_bidi_local: Some(1 << 18),
        initial_max_stream_data_bidi_remote: Some(1 << 18),
        initial_max_stream_data_uni: Some(1 << 18),
        initial_max_streams_bidi: Some(16),
        initial_max_streams_uni: Some(16),
        ..Default::default()
    });
    let mut p = Pair::new(Config::default(), qmux);
    assert!(p.a.is_plain_qmux_peer());
    fund_cover(&mut p);
    let (pad, st) = inject_for_a_second(&mut p);
    // PADDING-only records and QX_PING requests share 16 per second.
    assert!(
        pad <= 16 && pad as u64 == st.injection_accepted_requests,
        "{st:?}, {pad}"
    );
    assert!(pad > 0 && st.injection_rejected > 0, "{st:?}");
    assert_eq!(p.b.state(), zmux::proto::session::State::Active);
}

#[test]
fn injection_bounds() {
    let mut cfg = Config::default();
    let mut limits = Limits::default();
    // The account covers five records of 21 bytes on the wire.
    limits.wire = Some(Account::new(5 * wire(20) as u64, 5 * wire(20) as u64, 0, 0));
    cfg.shaping_limits = Some(Box::new(limits));
    let mut p = Pair::new(cfg, Config::default());
    let (pad, st) = inject_for_a_second(&mut p);
    assert_eq!((pad, st.injection_accepted_requests), (5, 5));
    assert_eq!(st.wire_spent, 5 * wire(20) as u64);
    assert_eq!(p.a.shaping_meters().wire_left, 0);
    assert!(st.injection_rejected > 0);
}

#[test]
fn gate_rate() {
    let mut p = Pair::new(Config::default(), Config::default());
    install(
        &mut p,
        Some(event_factory(|e, r| {
            if e.kind == EventKind::Start {
                r.gate = Some(Gate::new(0, 100_000, 10_000));
            }
        })),
    );
    let t0 = p.now;
    transfer(&mut p, 50_000, &mut Vec::new());
    assert!(p.now - t0 >= Duration::from_millis(300), "{:?}", p.now - t0);
}

#[test]
fn wake_replace_and_unknown_pipe() {
    let mut p = Pair::new(Config::default(), Config::default());
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    install(
        &mut p,
        Some(event_factory(move |e, r| {
            match e.kind {
                EventKind::Start => r.wake = Some(Some(e.now + 10_000)),
                EventKind::Timer => r.wake = Some(None),
                _ => {}
            }
            g.lock().unwrap().push(e.kind);
        })),
    );
    p.now += Duration::from_millis(10);
    p.a.handle_timeout(p.now);
    assert!(!p.a.set_pipe_shaper(zmux::PipeId::new(99), None));
    assert!(p.a.set_pipe_shaper(P0, None));
    assert_eq!(
        *got.lock().unwrap(),
        [EventKind::Start, EventKind::Timer, EventKind::Replaced]
    );
}

#[test]
fn fault_stops_shaping_of_the_pipe() {
    let mut p = Pair::new(Config::default(), Config::default());
    install(&mut p, Some(plan_factory(|_| panic!("plan"))));
    transfer(&mut p, 1000, &mut Vec::new());
    assert_eq!(p.a.shaping_stats().faults, 1);
}

#[test]
fn delayed_baseline_releases_when_its_wait_expires() {
    let mut p = Pair::new(Config::default(), Config::default());
    install(
        &mut p,
        Some(plan_factory(|p| {
            p.delay = Duration::from_millis(2);
            p.flush = true;
        })),
    );
    let t0 = p.now;
    transfer(&mut p, 3000, &mut Vec::new());
    assert!(p.now - t0 >= Duration::from_millis(2));
    assert!(p.a.shaping_stats().stall_spent >= Duration::from_millis(2));
}

/// A planned delay holds the whole record and everything else on the pipe:
/// with every record of A delayed 5 ms, the control frames A
/// owes while it receives a transfer (credit, acknowledgements) never go
/// in a record of their own ahead of the delay. Every batch of A is one
/// record, each at least the delay after the one before; the shaping
/// deadline is the delayed record's time exactly; and the transfer still
/// completes, the delayed records woken by the shaping timer alone.
#[test]
fn a_delay_holds_control_frames_too() {
    const DELAY: Duration = Duration::from_millis(2);
    let mut p = Pair::new(Config::default(), Config::default());
    p.pump();
    install(&mut p, Some(plan_factory(|plan| plan.delay = DELAY)));
    let n = 4 << 20;
    let data = vec![7u8; n];
    let k = p.b.open(Dir::Bidi).unwrap();
    let (mut off, mut got) = (0, 0);
    let mut accepted = None;
    let mut sent: Vec<(std::time::Instant, usize)> = Vec::new();
    for _ in 0..200_000 {
        if off < n {
            off += p.b.write(k, &data[off..]).unwrap_or(0);
            if off == n {
                p.b.finish(k).unwrap();
            }
        }
        p.send(false);
        let now = p.now;
        while p.a.wants_write(P0) {
            let mut recs = Vec::new();
            if p.send_with(true, |w| records(w, &mut recs)) == 0 {
                break;
            }
            sent.push((now, recs.len()));
        }
        p.drain_events();
        if accepted.is_none() {
            accepted = p.a.accept(Dir::Bidi).unwrap();
        }
        if let Some(r) = accepted {
            let mut buf = [0u8; 65536];
            while let Ok(Some((m, _))) = p.a.read(r, &mut buf) {
                if m == 0 {
                    break;
                }
                got += m;
            }
        }
        if got == n {
            break;
        }
        // The shaping deadline, when it is the next one, is exact.
        if let Some(t) = p.a.poll_timeout()
            && t > p.now
            && t - p.now < Duration::from_millis(1)
        {
            p.now = t;
        } else {
            p.now += Duration::from_micros(250);
        }
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
    }
    assert_eq!(got, n, "transfer incomplete");
    assert!(sent.len() > 3, "A sent {sent:?}");
    for w in sent.windows(2) {
        assert_eq!(
            w[1].1, 1,
            "a batch of A held more than one record: {sent:?}"
        );
        assert!(
            w[1].0 - w[0].0 >= DELAY,
            "records {:?} apart",
            w[1].0 - w[0].0
        );
    }
}

/// `pad_to` and `pad_multiple` are met exactly, and `pad` is added in full
/// on top: the last frame keeps its Length field, so the
/// PADDING after it never falls short of or past the target.
#[test]
fn padding_targets_are_exact() {
    for (pad_to, multiple, pad) in [(300, 0, 0), (300, 0, 7), (301, 64, 3)] {
        let mut p = deterministic_pair();
        install(
            &mut p,
            Some(plan_factory(move |plan| {
                plan.pad_to = pad_to;
                plan.pad_multiple = multiple;
                plan.pad = pad;
            })),
        );
        let stream = p.a.open(Dir::Bidi).unwrap();
        assert_eq!(p.a.write(stream, &[7; 80]).unwrap(), 80);
        let mut recs = Vec::new();
        p.send_with(true, |wire| records(wire, &mut recs));
        assert_eq!(recs.len(), 1);
        let expected = if multiple == 0 {
            pad_to
        } else {
            pad_to.div_ceil(multiple) * multiple
        };
        assert_eq!(wire(recs[0].0), expected + pad);
    }
}

/// A gate that a plan applies in the middle of a batch bounds the
/// rest of that batch: the stream data after it is its burst (and the
/// frame that crosses it), not whatever the batch would have taken
/// without a gate.
#[test]
fn a_gate_applied_by_a_plan_bounds_its_batch() {
    const BURST: u64 = 10_000;
    let mut p = Pair::new(Config::default(), Config::default());
    p.pump();
    install(
        &mut p,
        Some(plan_factory(move |plan| {
            plan.effects.gate = Some(Gate::new(0, 100_000, BURST));
        })),
    );
    let k = p.a.open(Dir::Bidi).unwrap();
    let data = vec![7u8; 200_000];
    let wrote = p.a.write(k, &data).unwrap();
    assert!(wrote > 100_000);
    // Everything A sends at this instant: three records before the gate,
    // then the burst.
    let moved = p.send(true);
    assert!(
        (moved as u64) < 3 * 1000 + BURST + 2000,
        "{moved} bytes at once under a burst of {BURST}"
    );
}

struct FirstDelay {
    delay: Duration,
    all: bool,
    n: u64,
}

impl Shaper for FirstDelay {
    fn capabilities(&self) -> Caps {
        Caps::PLAN
    }

    fn plan(&mut self, _: &RecordView, plan: &mut RecordPlan) {
        if self.n == 0 || self.all {
            plan.delay = self.delay;
        }
        self.n += 1;
    }
}

/// A shaping delay of the first record of the bootstrap pipe, installed
/// from the session's creation on both ends (`Config::shaper`), holds
/// `QX_TRANSPORT_PARAMETERS`, which still lead the pipe once it ends (design
/// 18.9: the delay is the whole record's earliest send time, the first
/// record included): both sessions establish and carry a stream, and
/// nothing is written before the delay.
#[test]
fn a_delayed_first_record_keeps_the_parameters_first() {
    const DELAY: Duration = Duration::from_millis(2);
    for all in [false, true] {
        let factory = || -> Arc<dyn Factory> {
            Arc::new(move |_: &zmux::shaping::ShapedPipe| {
                Some(Box::new(FirstDelay {
                    delay: DELAY,
                    all,
                    n: 0,
                }) as Box<dyn Shaper>)
            })
        };
        let (mut ca, mut cb) = (Config::default(), Config::default());
        ca.shaper = Some(factory());
        cb.shaper = Some(factory());
        let mut p = Pair::attached(ca, cb);
        let start = p.now;
        let mut first = None;
        for _ in 0..10_000 {
            let n = p.send(true) + p.send(false);
            if n > 0 && first.is_none() {
                first = Some(p.now);
            }
            p.drain_events();
            assert!(
                p.a.error().is_none() && p.b.error().is_none(),
                "all={all}: closed {:?} {:?}",
                p.a.error(),
                p.b.error()
            );
            if p.a.is_established() && p.b.is_established() {
                break;
            }
            if n == 0 {
                let t = [p.a.poll_timeout(), p.b.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min()
                    .expect("a deadline");
                p.now = t.max(p.now + Duration::from_micros(100));
                p.a.handle_timeout(p.now);
                p.b.handle_timeout(p.now);
            }
        }
        assert!(
            p.a.is_established() && p.b.is_established(),
            "all={all}: not established"
        );
        assert!(
            first.is_some_and(|t| t - start >= DELAY),
            "all={all}: first bytes at {:?}",
            first.map(|t| t - start)
        );
        let mut recs = Vec::new();
        transfer(&mut p, 10_000, &mut recs);
    }
}

/// The cover account and ongoing shaping ledger enforce different limits.
#[test]
fn an_account_refuses_injections_and_never_padding() {
    let mut cfg = Config::default();
    let mut limits = Limits::default();
    limits.wire = Some(Account::new(1, 1, 0, 0));
    cfg.shaping_limits = Some(Box::new(limits));
    let mut p = Pair::new(cfg, Config::default());
    let dropped = Arc::new(Mutex::new(0));
    let d = dropped.clone();
    install(
        &mut p,
        Some(Arc::new(move |_: &zmux::shaping::ShapedPipe| {
            let d = d.clone();
            Some(Box::new(Fns {
                caps: Caps::PLAN,
                plan: Box::new(|p| p.pad_to = 8000),
                event: Box::new(move |e, r| {
                    request_cover(e, r, 500, false);
                    if e.kind == EventKind::InjectionRejected {
                        *d.lock().unwrap() += 1;
                    }
                }),
            }) as Box<dyn Shaper>)
        })),
    );
    let mut recs = Vec::new();
    transfer(&mut p, 3000, &mut recs);
    for _ in 0..20 {
        p.now += Duration::from_millis(1);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.send(true);
        p.send(false);
        p.drain_events();
    }
    let st = p.a.shaping_stats();
    assert_eq!(
        (st.injection_accepted_requests, st.injection_rejected),
        (0, 1),
        "{st:?}"
    );
    assert_eq!(*dropped.lock().unwrap(), 1);
    assert_eq!(st.wire_spent, 0);
    assert!(st.ledger.measured_bytes > 0, "{st:?}");
    let m = p.a.shaping_meters();
    assert_eq!(m.wire_left, 1);
    assert!(m.earned_bytes > 0 && m.wire_spent == st.wire_spent, "{m:?}");
}

/// `earned_bytes` leaves padding and injections out and grows with the data alone.
#[test]
fn padding_earns_nothing() {
    let run = |pad: usize| {
        let mut p = Pair::new(Config::default(), Config::default());
        install(&mut p, Some(plan_factory(move |x| x.pad_to = pad)));
        transfer(&mut p, 20_000, &mut Vec::new());
        (p.a.shaping_meters(), p.a.shaping_stats().ledger)
    };
    let ((plain, base), (padded, shaped)) = (run(0), run(4000));
    assert_eq!((padded.wire_spent, plain.wire_spent), (0, 0));
    assert!(shaped.measured_bytes > 0 && base.measured_bytes == 0);
    assert!(padded.earned_bytes.abs_diff(plain.earned_bytes) * 10 < plain.earned_bytes);
}

/// A profile budget with an explicit zero ceiling never funds cover.
#[test]
fn a_budget_of_zeros_allows_no_injection() {
    use zmux::shaping::{Budget, ShapingBudget};
    let mut cfg = Config::default();
    cfg.shaping_budget = Some(ShapingBudget::new(|| {
        Budget::new(Some(Account::default()), None, false)
    }));
    cfg.shaper = Some(event_factory(|e, r| request_cover(e, r, 20, false)));
    let mut p = Pair::new(cfg, Config::default());
    for _ in 0..50 {
        p.now += Duration::from_millis(1);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.send(true);
        p.send(false);
        p.drain_events();
    }
    let st = p.a.shaping_stats();
    assert_eq!(st.injection_accepted_requests, 0, "{st:?}");
    assert!(st.injection_rejected > 0, "{st:?}");
}

/// A new shaper without a budget leaves the account unset; the spending stays.
#[test]
fn a_shaper_without_a_budget_unsets_the_account() {
    use zmux::shaping::Budget;
    let mut p = Pair::new(Config::default(), Config::default());
    p.a.set_shaper_budgeted(
        Some(event_factory(|_, _| {})),
        Budget::new(Some(Account::new(7, 7, 0, 0)), None, false),
    )
    .unwrap();
    assert_eq!(p.a.shaping_meters().wire_left, 7);
    install(&mut p, None);
    assert_eq!(p.a.shaping_meters().wire_left, 0);
}

#[test]
fn shaping_limits_are_validated() {
    use zmux::proto::session::{Role, SessionCore};
    let now = std::time::Instant::now();
    for (initial, ok) in [(0, true), (1 << 53, true), ((1 << 53) + 1, false)] {
        let mut cfg = Config::default();
        let mut limits = Limits::default();
        limits.wire = Some(Account::new(initial, initial, 0, 0));
        cfg.shaping_limits = Some(Box::new(limits));
        assert_eq!(limits.validate().is_ok(), ok, "{initial}");
        let r = SessionCore::new(cfg, Role::Client, None, now);
        assert_eq!(r.is_ok(), ok, "{initial}");
    }
}

/// A record split without a priced baseline leaves the ordinary layout available.
#[test]
fn a_record_split_without_a_cost_model_is_clamped() {
    let mut p = Pair::new(Config::default(), Config::default());
    install(&mut p, Some(plan_factory(|p| p.max_len = 10)));
    transfer(&mut p, 3000, &mut Vec::new());
    assert!(p.a.shaping_stats().clamped > 0);
}

/// Padding targets beyond a record (a shaper of the application's own may
/// ask for any) are bounded by the record and counted as clamped, so that
/// the padding arithmetic cannot overflow.
#[test]
fn padding_targets_beyond_a_record_are_clamped() {
    let mut p = Pair::new(Config::default(), Config::default());
    install(
        &mut p,
        Some(plan_factory(|p| {
            p.pad_to = usize::MAX;
            p.pad_multiple = usize::MAX;
            p.pad = usize::MAX;
        })),
    );
    transfer(&mut p, 3000, &mut Vec::new());
    assert!(p.a.shaping_stats().clamped > 0);
}

/// A preamble above the open gate's tokens goes whole, and what follows pays for it.
#[test]
fn a_preamble_overdraws_the_open_gate() {
    let mut p = Pair::new(Config::default(), Config::default());
    install(
        &mut p,
        Some(event_factory(|e, r| {
            if e.kind == EventKind::Start {
                r.gate = Some(Gate::new(0, 1_000_000, 100));
            }
        })),
    );
    let k =
        p.a.open_with(Dir::Bidi, &Preamble::new().with_info(vec![1u8; 300]))
            .unwrap();
    p.a.write(k, &[7; 10]).unwrap();
    let mut recs = Vec::new();
    p.send_with(true, |w| records(w, &mut recs));
    assert!(recs.iter().any(|r| r.0 > 300), "{recs:?}");
    p.drain_events();
    let r = p.b.accept(Dir::Bidi).unwrap().expect("opened");
    let mut buf = [0u8; 64];
    let read = |p: &mut Pair, buf: &mut [u8]| match p.b.read(r, buf) {
        Ok(Some((n, _))) => n,
        _ => 0,
    };
    assert_eq!(read(&mut p, &mut buf), 0);
    // In debt: what follows waits for the bucket's recovery.
    p.a.write(k, &[7; 10]).unwrap();
    let t0 = p.now;
    let mut got = 0;
    while got == 0 && p.now - t0 < Duration::from_secs(2) {
        p.now += Duration::from_millis(10);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.send(true);
        p.send(false);
        p.drain_events();
        got = read(&mut p, &mut buf);
    }
    assert_eq!(got, 20);
    assert!(p.a.shaping_stats().max_added_delay <= Duration::from_micros(2000));
}

fn deterministic_pair() -> Pair {
    let mut config = Config::default();
    config.test_hooks().grease_tlv = Some((0x21, Vec::new()));
    Pair::new(config.clone(), config)
}

#[test]
fn merged_cover_charges_the_size_growth_and_confirms_only_the_accepted_prefix() {
    use zmux::proto::session::{CoreEvent, Transmit};
    use zmux::shaping::RuntimeReason;

    let mut p = deterministic_pair();
    fund_cover(&mut p);
    let earned_before = p.a.shaping_meters().earned_bytes;
    install(
        &mut p,
        Some(event_factory(|e, effects| {
            request_cover(e, effects, 10, false);
        })),
    );
    let stream = p.a.open(Dir::Bidi).unwrap();
    assert_eq!(p.a.write(stream, &[7; 57]).unwrap(), 57);
    let at = p.now + Duration::from_millis(1);
    p.a.handle_timeout(at);
    assert_eq!(p.a.poll_transmit(P0, at, &mut p.out), Transmit::Data);

    let mut wire = Vec::new();
    p.out.copy_to_vec(&mut wire);
    let (len, size_field) = zmux::proto::varint::decode(&wire).unwrap();
    assert_eq!((len, size_field), (73, 2));
    assert_eq!(&wire[wire.len() - 10..], &[0; 10]);
    let stats = p.a.shaping_stats();
    assert_eq!(stats.injection_accepted_bytes, 10);
    assert_eq!(stats.injection_sent_bytes, 0);
    assert_eq!(stats.wire_spent, 11);
    assert_eq!(p.a.shaping_meters().earned_bytes, earned_before);

    install(&mut p, None);
    let written = p.out.stream_len() - 6;
    p.a.transmit_progress(P0.into(), &mut p.out, written, true, at);
    p.a.transmit_progress(P0.into(), &mut p.out, written, true, at);
    let stats = p.a.shaping_stats();
    assert_eq!(stats.injection_accepted_bytes, 10);
    assert_eq!(stats.injection_sent_bytes, 4);
    assert_eq!(stats.wire_spent, 11);
    assert_eq!(p.a.shaping_meters().earned_bytes, earned_before);

    let results: Vec<_> = std::iter::from_fn(|| p.a.poll_event())
        .filter_map(|e| match e {
            CoreEvent::Shaping(e) => Some((e.kind, e.len, e.reason)),
            _ => None,
        })
        .collect();
    assert_eq!(
        results,
        [
            (EventKind::InjectionAccepted, 10, None),
            (
                EventKind::InjectionCarrierCompleted,
                4,
                Some(RuntimeReason::PartialProgress)
            ),
        ],
    );
}

#[test]
fn hard_limits_preserve_baseline_layout_and_bound_record_delay() {
    use zmux::proto::session::Transmit;
    use zmux::shaping::ProfileLimits;

    let run = |shaped: bool| {
        let mut p = deterministic_pair();
        let delay = Duration::from_micros(20);
        if shaped {
            let mut limits = p.a.shaping_limits();
            limits.profile = Some(ProfileLimits::new(10, 0, 0, delay));
            p.a.set_shaping_limits(limits).unwrap();
            install(
                &mut p,
                Some(plan_factory(|plan| {
                    plan.max_len = 64;
                    plan.flush = true;
                    plan.pad = 100;
                    plan.delay = Duration::from_secs(4);
                })),
            );
        }
        let stream = p.a.open(Dir::Bidi).unwrap();
        assert_eq!(p.a.write(stream, &[7; 600]).unwrap(), 600);
        if shaped {
            assert_eq!(p.a.poll_transmit(P0, p.now, &mut p.out), Transmit::Idle);
            assert_eq!(p.a.poll_timeout(), Some(p.now + delay));
            p.now += delay;
            p.a.handle_timeout(p.now);
        }
        assert_eq!(p.a.poll_transmit(P0, p.now, &mut p.out), Transmit::Data);
        assert_eq!(p.a.shaping_stats().wire_spent, 0);
        assert_eq!(
            p.a.shaping_stats().max_added_delay,
            if shaped { delay } else { Duration::ZERO }
        );
        let mut wire = Vec::new();
        p.out.copy_to_vec(&mut wire);
        wire
    };
    assert_eq!(run(false), run(true));
}

#[test]
fn outbound_control_is_opt_in_and_observed_once() {
    for include_control in [false, true] {
        let mut p = Pair::new(Config::default(), Config::default());
        let stream = p.a.open(Dir::Bidi).unwrap();
        assert_eq!(p.a.write(stream, b"open").unwrap(), 4);
        p.pump();

        let event = Arc::new(Mutex::new(Vec::new()));
        let log = event.clone();
        let caps = if include_control {
            Caps::OUTBOUND | Caps::INCLUDE_CONTROL
        } else {
            Caps::OUTBOUND
        };
        assert!(p.a.set_pipe_shaper(
            P0,
            Some(Box::new(Fns {
                caps,
                plan: Box::new(|_| {}),
                event: Box::new(move |e, _| {
                    if e.kind == EventKind::Outbound {
                        log.lock().unwrap().push((e.data, e.control));
                    }
                }),
            }))
        ));
        p.a.finish(stream).unwrap();
        p.pump();
        let expected = if include_control {
            &[(false, true)][..]
        } else {
            &[]
        };
        assert_eq!(&*event.lock().unwrap(), expected);
    }
}

#[test]
fn a_cover_reserved_before_a_lengthless_datagram_reduces_later_padding_room() {
    use bytes::Bytes;
    use zmux::shaping::ProfileLimits;

    let mut config = Config::default();
    config.enable_datagrams = true;
    config.test_hooks().no_first_ping = true;
    let mut peer = config.clone();
    let mut tp = Pair::attached(config.clone(), peer.clone())
        .b
        .local_parameters();
    tp.max_datagram_frame_size = Some(63);
    peer.test_hooks().transport_parameters = Some(tp);
    let mut p = Pair::new(config, peer);

    let mut limits = p.a.shaping_limits();
    limits.wire = Some(Account::new(100, 100, 0, 0));
    limits.profile = Some(ProfileLimits::new(10, 0, 10, Duration::ZERO));
    p.a.set_shaping_limits(limits).unwrap();
    install(
        &mut p,
        Some(Arc::new(|_: &zmux::shaping::ShapedPipe| {
            let mut planned = 0;
            Some(Box::new(Fns {
                caps: Caps::PLAN,
                plan: Box::new(move |plan| {
                    if planned != 0 {
                        plan.pad = 100;
                    }
                    planned += 1;
                }),
                event: Box::new(|e, effects| request_cover(e, effects, 2, false)),
            }) as Box<dyn Shaper>)
        })),
    );

    let mut payload = [7; 60];
    payload[59] = 0;
    let payload = Bytes::copy_from_slice(&payload);
    p.a.send_datagram(payload.clone(), true, p.now).unwrap();
    let stream = p.a.open(Dir::Bidi).unwrap();
    assert_eq!(p.a.write(stream, &[7; 500]).unwrap(), 500);
    p.now += Duration::from_millis(1);
    p.a.handle_timeout(p.now);
    p.pump();

    let stats = p.a.shaping_stats();
    assert_eq!(stats.injection_accepted_bytes, 2);
    assert_eq!(stats.injection_sent_bytes, 2);
    assert_eq!(stats.wire_spent, 3);
    assert_eq!(stats.ledger.measured_bytes, 10);
    assert_eq!(p.b.recv_datagram(p.now).unwrap(), Some(payload));
}

#[test]
fn unknown_terminal_cover_progress_expires_in_its_dispatch_window() {
    use zmux::shaping::{Budget, CostPrecision, ProfileLimits};
    let mut p = deterministic_pair();
    let profile = ProfileLimits::new(3, 0, 8, Duration::ZERO);
    p.a.set_shaper_budgeted(
        Some(event_factory(|event, effects| {
            request_cover(event, effects, 7, false);
        })),
        Budget::new(Some(Account::new(16, 16, 0, 0)), Some(profile), false),
    )
    .unwrap();
    let at = p.now + Duration::from_millis(1);
    p.a.handle_timeout(at);
    p.a.poll_transmit(P0, at, &mut p.out);
    assert_eq!(p.out.stream_len(), 8);
    p.a.transmit_progress(P0.into(), &mut p.out, 4, false, at);
    p.a.transmit_progress(P0.into(), &mut p.out, 4, false, at);
    p.a.transmit_progress_unknown(P0.into(), &mut p.out, 4, at);
    let stats = p.a.shaping_stats();
    let window = stats.ledger.policy.unwrap();
    assert_eq!(stats.ledger.precision, CostPrecision::Unavailable);
    assert_eq!((window.consumed_bytes, window.reserved_bytes), (4, 4));
    assert_eq!(
        (
            stats.injection_accepted_bytes,
            stats.injection_sent_bytes,
            stats.wire_spent
        ),
        (7, 3, 8)
    );
    p.a.handle_timeout(p.now + Duration::from_secs(4));
    let stats = p.a.shaping_stats();
    let window = stats.ledger.policy.unwrap();
    assert_eq!(stats.ledger.precision, CostPrecision::Exact);
    assert_eq!(
        (
            window.consumed_bytes,
            window.reserved_bytes,
            stats.ledger.measured_bytes
        ),
        (0, 0, 4)
    );
}

#[test]
fn timer_cover_reuses_the_idle_floor_only_after_its_window_scrolls() {
    use zmux::shaping::{Budget, ProfileLimits};
    let mut pair = deterministic_pair();
    let profile = ProfileLimits::new(3, 0, 8, Duration::ZERO);
    let factory = event_factory(|event, effects| match (event.kind, event.now) {
        (EventKind::Start, _) => effects.wake = Some(Some(event.now + 1_000_000)),
        (EventKind::Timer, now) => {
            effects.inject = Some(Some(Injection::new(now, now, 7)));
            effects.wake = match now {
                1_000_000 => Some(Some(2_000_000)),
                2_000_000 => Some(Some(5_000_000)),
                _ => None,
            };
        }
        _ => {}
    });
    pair.a
        .set_shaper_budgeted(
            Some(factory),
            Budget::new(Some(Account::new(16, 0, 0, 8)), Some(profile), false),
        )
        .unwrap();
    let start = pair.now;
    // This half receives no activity during the run, including while idle.
    for (seconds, measured, sent, lifetime) in [(1, 8, 7, 8), (2, 8, 7, 8), (5, 8, 14, 16)] {
        pair.now = start + Duration::from_secs(seconds);
        pair.a.handle_timeout(pair.now);
        pair.send(true);
        let stats = pair.a.shaping_stats();
        assert_eq!(stats.ledger.policy.unwrap().consumed_bytes, measured);
        assert_eq!(stats.injection_sent_bytes, sent);
        assert_eq!(stats.ledger.measured_bytes, lifetime);
        assert_eq!(stats.wire_spent, lifetime);
    }
}

#[test]
fn g4_unwritable_carrier_does_not_spend_the_gate_delay() {
    use zmux::proto::session::PipeWrite;
    let mut p = deterministic_pair();
    p.a.pipe_write(P0, PipeWrite::returned(p.now, p.now, 0, 1, true), p.now);
    install(
        &mut p,
        Some(event_factory(|event, effects| {
            if event.kind == EventKind::Start {
                effects.gate = Some(Gate::new(event.now + 2000, 0, 0));
            }
        })),
    );
    let stream = p.a.open(Dir::Bidi).unwrap();
    p.a.write(stream, b"queued while the carrier is blocked")
        .unwrap();
    p.now += Duration::from_millis(2);
    p.a.handle_timeout(p.now);
    install(&mut p, None);
    let stats = p.a.shaping_stats();
    assert_eq!(stats.stall_spent, Duration::ZERO);
    assert_eq!(stats.max_added_delay, Duration::ZERO);
}

#[test]
fn g4_a_pure_pipe_ack_proves_baseline_without_earning_cover() {
    use zmux::proto::frame::{Frame, Gates};
    use zmux::proto::record::{Event as RecordEvent, RecordReader};
    use zmux::shaping::{Budget, ProfileLimits};

    let mut p = deterministic_pair();
    let mut limits = p.b.shaping_limits();
    limits.wire = Some(Account::new(100, 0, 1_000_000, 0));
    p.b.set_shaping_limits(limits).unwrap();
    let outbound = Arc::new(Mutex::new(Vec::new()));
    let events = outbound.clone();
    let factory = Arc::new(move |_: &zmux::shaping::ShapedPipe| {
        let events = events.clone();
        Some(Box::new(Fns {
            caps: Caps::OUTBOUND | Caps::INCLUDE_CONTROL,
            plan: Box::new(|_| {}),
            event: Box::new(move |event, _| {
                if event.kind == EventKind::Outbound {
                    events.lock().unwrap().push(*event);
                }
            }),
        }) as Box<dyn Shaper>)
    });
    p.b.set_shaper_budgeted(
        Some(factory),
        Budget::new(limits.wire, Some(ProfileLimits::LIGHTWEIGHT), false),
    )
    .unwrap();
    let before = p.b.shaping_meters();
    let baseline = p.b.shaping_stats().ledger.baseline_bytes;
    let stream = p.a.open(Dir::Bidi).unwrap();
    p.a.write(stream, &[7; 4096]).unwrap();
    assert!(p.send(true) > 0);
    p.now += Duration::from_millis(100);
    p.b.handle_timeout(p.now);
    let mut acks = 0;
    assert!(
        p.send_with(false, |wire| {
            let mut reader = RecordReader::new(65_535);
            let mut input = wire;
            while let Some(event) = reader.read(&mut input, &Gates::ALL).unwrap() {
                if let RecordEvent::Frame(frame) = event {
                    assert!(matches!(frame, Frame::PipeAck(_)));
                    acks += 1;
                }
            }
        }) > 0
    );
    assert!(acks > 0);
    let after = p.b.shaping_meters();
    assert_eq!(after.earned_bytes, before.earned_bytes);
    assert_eq!(after.wire_left, before.wire_left);
    assert!(p.b.shaping_stats().ledger.baseline_bytes > baseline);
    assert!(outbound.lock().unwrap().is_empty());
}
