//! Record shaping on two cores connected in memory, with the
//! language-independent cases of `testdata/shaping/contract.json`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use zmux::proto::frame::Dir;
use zmux::proto::session::Config;
use zmux::shaping::{
    Caps, Event, EventKind, Factory, Gate, Inject, Limits, RecordPlan, RecordView, Reply, Shaper,
    Timer,
};

#[path = "common/core_pair.rs"]
mod core_pair;

use core_pair::{CorePair as Pair, P0};

type EventFn = Box<dyn FnMut(&Event, &mut Reply) + Send>;

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

    fn on_event(&mut self, e: &Event, r: &mut Reply) {
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
    f: impl Fn(&Event, &mut Reply) + Send + Sync + Clone + 'static,
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

#[derive(Deserialize)]
struct Contract {
    records: Vec<Case>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Case {
    name: String,
    /// The shaped sender: "client" (default) or "server".
    side: String,
    limits: CaseLimits,
    plan: CasePlan,
    send: usize,
    repeat: usize,
    expect: Expect,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CaseLimits {
    max_padding_bytes: Option<u64>,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(default)]
struct CasePlan {
    max_len: usize,
    pad_to: usize,
    pad_multiple: usize,
    pad: usize,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Expect {
    min_len: usize,
    max_len: usize,
    #[serde(rename = "mod")]
    modulus: usize,
    rem: usize,
    min_records: usize,
    max_padding_bytes: u64,
    clamped: bool,
    padding: bool,
    /// Trailing zero bytes of every record.
    min_pad: usize,
}

#[test]
fn contract_records() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/shaping/contract.json"
    );
    let k: Contract = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for c in k.records {
        let mut cfg = Config::default();
        let mut limits = Limits::default();
        limits.max_padding_bytes = c.limits.max_padding_bytes;
        cfg.shaping_limits = limits;
        let mut p = if c.side == "server" {
            // A is the shaped sender: the responder's core.
            let mut p = Pair::new(Config::default(), cfg);
            std::mem::swap(&mut p.a, &mut p.b);
            std::mem::swap(&mut p.events_a, &mut p.events_b);
            p
        } else {
            Pair::new(cfg, Config::default())
        };
        let v = c.plan;
        p.a.set_shaper(Some(plan_factory(move |p| {
            p.max_len = v.max_len;
            p.pad_to = v.pad_to;
            p.pad_multiple = v.pad_multiple;
            p.pad = v.pad;
        })));
        let mut recs = Vec::new();
        for _ in 0..c.repeat.max(1) {
            transfer(&mut p, c.send, &mut recs);
        }
        let e = &c.expect;
        let name = &c.name;
        assert!(
            !recs.is_empty() && recs.len() >= e.min_records,
            "{name}: {} records",
            recs.len()
        );
        for &(n, zeros) in &recs {
            assert!(
                n >= e.min_len
                    && (e.max_len == 0 || n <= e.max_len)
                    && (e.modulus == 0 || n % e.modulus == e.rem)
                    && zeros >= e.min_pad,
                "{name}: record of {n} bytes, {zeros} trailing zero bytes"
            );
        }
        let st = p.a.shaping_stats();
        assert!(
            (e.max_padding_bytes == 0 || st.padding_bytes <= e.max_padding_bytes)
                && (!e.clamped || st.clamped > 0)
                && (!e.padding || st.padding_bytes > 0)
                && st.padding_bytes >= (recs.len() * e.min_pad) as u64,
            "{name}: {st:?}"
        );
    }
}

/// Repeated injections every millisecond for one second of session time.
fn inject_for_a_second(p: &mut Pair) -> (usize, zmux::shaping::Stats) {
    p.a.set_shaper(Some(event_factory(|e, r| {
        if matches!(e.kind, EventKind::Start | EventKind::Injected) {
            r.inject = Some(Inject::Send {
                after: Duration::from_millis(1),
                len: 20,
            });
        }
    })));
    let mut recs = Vec::new();
    for _ in 0..1000 {
        p.now += Duration::from_millis(1);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.send_with(true, |w| records(w, &mut recs));
        p.send(false);
        p.drain_events();
    }
    p.a.set_shaper(None);
    let pad = recs.iter().filter(|&&(n, z)| n == 20 && z == 20).count();
    (pad, p.a.shaping_stats())
}

#[test]
fn injection_toward_a_zmux_peer() {
    let mut p = Pair::new(Config::default(), Config::default());
    let (pad, st) = inject_for_a_second(&mut p);
    assert!(
        st.injected > 16 && pad as u64 == st.injected && st.inject_dropped == 0,
        "{st:?}, {pad}"
    );
    assert!(p.b.state() == zmux::proto::session::State::Active);
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
    let (pad, st) = inject_for_a_second(&mut p);
    // PADDING-only records and QX_PING requests share 16 per second.
    assert!(pad <= 16 && pad as u64 == st.injected, "{st:?}, {pad}");
    assert!(pad > 0 && st.inject_dropped > 0, "{st:?}");
    assert!(p.b.state() == zmux::proto::session::State::Active);
}

#[test]
fn injection_bounds() {
    let mut cfg = Config::default();
    let mut limits = Limits::default();
    limits.max_injected = Some(5);
    cfg.shaping_limits = limits;
    let mut p = Pair::new(cfg, Config::default());
    let (pad, st) = inject_for_a_second(&mut p);
    assert_eq!((pad, st.injected), (5, 5));
    assert!(st.inject_dropped > 0);
}

#[test]
fn gate_rate() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.a.set_shaper(Some(event_factory(|e, r| {
        if e.kind == EventKind::Start {
            r.gate = Some(Gate::new(Duration::ZERO, 100_000, 10_000));
        }
    })));
    let t0 = p.now;
    transfer(&mut p, 50_000, &mut Vec::new());
    assert!(p.now - t0 >= Duration::from_millis(300), "{:?}", p.now - t0);
}

#[test]
fn timer_replace_and_unknown_pipe() {
    let mut p = Pair::new(Config::default(), Config::default());
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    p.a.set_shaper(Some(event_factory(move |e, r| {
        if e.kind == EventKind::Start {
            r.timers[1] = Some(Timer::After(Duration::from_millis(10)));
        }
        g.lock().unwrap().push((e.kind, e.timer));
    })));
    p.now += Duration::from_millis(10);
    p.a.handle_timeout(p.now);
    assert!(!p.a.set_pipe_shaper(zmux::PipeId::new(99), None));
    assert!(p.a.set_pipe_shaper(P0, None));
    assert_eq!(
        *got.lock().unwrap(),
        [
            (EventKind::Start, 0),
            (EventKind::Timer, 1),
            (EventKind::Replaced, 0)
        ]
    );
}

#[test]
fn fault_stops_shaping_of_the_pipe() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.a.set_shaper(Some(plan_factory(|_| panic!("plan"))));
    transfer(&mut p, 1000, &mut Vec::new());
    assert_eq!(p.a.shaping_stats().faults, 1);
}

#[test]
fn delay_and_flush() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.a.set_shaper(Some(plan_factory(|p| {
        p.delay = Duration::from_millis(2);
        p.flush = true;
    })));
    let t0 = p.now;
    transfer(&mut p, 3000, &mut Vec::new());
    assert!(p.now - t0 >= Duration::from_millis(2));
    assert!(p.a.shaping_stats().pause_total >= Duration::from_millis(2));
}

/// A record whose plan cuts it shorter than the record before is cut by its
/// own plan: STREAM data is not sized by the previous record's cut.
#[test]
fn a_shorter_cut_applies_to_its_own_record() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let n = Arc::new(AtomicUsize::new(0));
    let plans = Arc::new(Mutex::new(Vec::new()));
    let (counter, log) = (n.clone(), plans.clone());
    let mut p = Pair::new(Config::default(), Config::default());
    p.a.set_shaper(Some(plan_factory(move |plan| {
        let i = counter.fetch_add(1, Ordering::Relaxed);
        plan.max_len = if i % 2 == 0 { 1000 } else { 200 };
        log.lock().unwrap().push(plan.max_len);
    })));
    let mut recs = Vec::new();
    transfer(&mut p, 20_000, &mut recs);
    let plans = plans.lock().unwrap();
    // Plans are made for the records in order; the first records of the
    // pair were sent before the shaper.
    let shaped = &recs[recs.len() - plans.len().min(recs.len())..];
    for (i, (&(len, _), &max)) in shaped.iter().zip(plans.iter()).enumerate() {
        assert!(len <= max, "record {i}: {len} bytes under a cut of {max}");
    }
    assert!(shaped.iter().filter(|&&(l, _)| l > 200).count() > 5);
}

/// An injection due right after a record whose plan flushes goes in the
/// next batch rather than being dropped.
#[test]
fn an_injection_after_a_flush_is_deferred() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.a.set_shaper(Some(Arc::new(|_: &zmux::shaping::ShapedPipe| {
        Some(Box::new(Fns {
            caps: Caps::PLAN,
            plan: Box::new(|plan| {
                plan.flush = true;
                plan.max_len = 500;
            }),
            event: Box::new(|e, r| {
                if matches!(e.kind, EventKind::Start | EventKind::Injected) {
                    r.inject = Some(Inject::Send {
                        after: Duration::from_millis(1),
                        len: 20,
                    });
                }
            }),
        }) as Box<dyn Shaper>)
    })));
    let k = p.a.open(Dir::Bidi).unwrap();
    let data = vec![7u8; 3000];
    for _ in 0..300 {
        let _ = p.a.write(k, &data);
        p.now += Duration::from_millis(1);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.send(true);
        p.send(false);
        p.drain_events();
        if let Some(r) = p.b.accept(Dir::Bidi).unwrap() {
            let mut buf = [0u8; 65536];
            while let Ok(Some((m, _))) = p.b.read(r, &mut buf) {
                if m == 0 {
                    break;
                }
            }
        }
    }
    let st = p.a.shaping_stats();
    assert!(st.injected > 100, "{st:?}");
    assert_eq!(st.inject_dropped, 0, "{st:?}");
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
    const DELAY: Duration = Duration::from_millis(5);
    let mut p = Pair::new(Config::default(), Config::default());
    p.pump();
    p.a.set_shaper(Some(plan_factory(|plan| plan.delay = DELAY)));
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
    for (pad_to, multiple, pad) in [
        (300, 0, 0),
        (300, 0, 7),
        (0, 32, 0),
        (0, 32, 5),
        (301, 64, 3),
    ] {
        let mut p = Pair::new(Config::default(), Config::default());
        p.pump();
        let i = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        p.a.set_shaper(Some(plan_factory(move |plan| {
            // Records of varying natural length, all under the target.
            let k = i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            plan.max_len = 100 + (k * 37) % 150;
            plan.pad_to = pad_to;
            plan.pad_multiple = multiple;
            plan.pad = pad;
        })));
        let mut recs = Vec::new();
        transfer(&mut p, 30_000, &mut recs);
        let shaped: Vec<_> = recs.iter().filter(|&&(n, _)| n > 0).collect();
        assert!(shaped.len() > 20, "{shaped:?}");
        for &&(n, zeros) in &shaped {
            assert!(zeros >= pad, "{n} bytes, {zeros} zeros under pad {pad}");
            if pad_to > 0 && multiple == 0 {
                // Every record's natural length is under the target.
                assert_eq!(n, pad_to + pad, "pad_to {pad_to}, pad {pad}");
            }
            if multiple > 0 && pad == 0 {
                assert_eq!(n % multiple, 0, "{n} not a multiple of {multiple}");
            }
            if multiple > 0 {
                assert_eq!(
                    (n - pad) % multiple,
                    0,
                    "{n} - {pad} not a multiple of {multiple}"
                );
            }
        }
    }
}

/// A gate that a plan's reply applies in the middle of a batch bounds the
/// rest of that batch: the stream data after it is its burst (and the
/// frame that crosses it), not whatever the batch would have taken
/// without a gate.
#[test]
fn a_gate_applied_by_a_plan_bounds_its_batch() {
    const BURST: u64 = 10_000;
    let mut p = Pair::new(Config::default(), Config::default());
    p.pump();
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    p.a.set_shaper(Some(plan_factory(move |plan| {
        plan.max_len = 1000;
        if n.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 3 {
            plan.reply.gate = Some(Gate::new(Duration::ZERO, 100_000, BURST));
        }
    })));
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

/// A planned record opens only where the batch holds its target: a
/// control frame may fit the batch's end while the PADDING to `pad_to`
/// does not, and the target would be clamped.
#[test]
fn a_planned_record_is_never_cut_by_the_batch_end() {
    // Replies that just fill the records of 1000 and 200 bytes, so that
    // the credit their completion releases needs a third record.
    for len in (1100..1220).step_by(3) {
        planned_records_with_replies(len);
    }
}

fn planned_records_with_replies(len: usize) {
    let mut a_cfg = Config::default();
    a_cfg.max_incoming_streams = 4;
    let mut p = Pair::new(a_cfg, Config::default());
    p.pump();
    let i = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    p.a.set_shaper(Some(plan_factory(move |plan| {
        let k = i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let target = if k.is_multiple_of(2) { 1000 } else { 200 };
        plan.max_len = target;
        plan.pad_to = target;
    })));
    // A write call of 1500 bytes: after records of 1000 and 200 bytes a
    // control frame still fits, the next record of 1000 does not. B opens
    // short streams that A answers and finishes: the MAX_STREAMS that a
    // completed stream releases is written after A's stream data, near
    // the end of the batch.
    p.out.set_max_len(1500);
    let reply = vec![7u8; len];
    let mut recs = Vec::new();
    let mut open: Vec<_> = Vec::new();
    let mut b_open: Vec<_> = Vec::new();
    for round in 0..2000 {
        if round < 1000
            && let Ok(k) = p.b.open(Dir::Bidi)
        {
            p.b.write(k, b"ping").unwrap();
            p.b.finish(k).unwrap();
            b_open.push(k);
        }
        let moved = p.send_with(true, |w| records(w, &mut recs)) + p.send(false);
        p.drain_events();
        while let Ok(Some(k)) = p.a.accept(Dir::Bidi) {
            open.push(k);
        }
        let mut buf = [0u8; 1024];
        open.retain(|&k| {
            while let Ok(Some((m, fin))) = p.a.read(k, &mut buf) {
                if fin {
                    let _ = p.a.write(k, &reply);
                    let _ = p.a.finish(k);
                    p.a.release(k);
                    return false;
                }
                if m == 0 {
                    break;
                }
            }
            true
        });
        b_open.retain(|&k| {
            while let Ok(Some((m, fin))) = p.b.read(k, &mut buf) {
                if fin {
                    p.b.release(k);
                    return false;
                }
                if m == 0 {
                    break;
                }
            }
            true
        });
        if moved == 0 {
            p.now += Duration::from_millis(1);
            p.a.handle_timeout(p.now);
            p.b.handle_timeout(p.now);
        }
    }
    let shaped: Vec<_> = recs.iter().filter(|&&(n, _)| n > 0).collect();
    assert!(shaped.len() > 100, "{}", shaped.len());
    for &&(n, _) in &shaped {
        assert!(
            n == 1000 || n == 200,
            "reply {len}: a record of {n} bytes {:?} {:?}",
            p.a.shaping_stats(),
            &recs[recs.len().saturating_sub(12)..]
        );
    }
    assert_eq!(p.a.shaping_stats().clamped, 0, "reply {len}");
}

/// Delays the first record of the pipe it shapes, or every record.
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
/// QX_TRANSPORT_PARAMETERS, which still lead the pipe once it ends (design
/// 18.9: the delay is the whole record's earliest send time, the first
/// record included): both sessions establish and carry a stream, and
/// nothing is written before the delay.
#[test]
fn a_delayed_first_record_keeps_the_parameters_first() {
    const DELAY: Duration = Duration::from_millis(20);
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

/// The padding ratio bound starts with one record's allowance, and an
/// injection it does not cover waits whole until more has been sent: a
/// 16000-byte injection at the start goes whole at a 1 % ratio, the next
/// one of 1000 bytes only once 1.7 MB have been sent, never cut.
#[test]
fn padding_ratio_startup_allowance_and_deferral() {
    let mut cfg = Config::default();
    let mut limits = Limits::default();
    limits.max_padding_ratio = Some(0.01);
    cfg.shaping_limits = limits;
    let mut p = Pair::new(cfg, Config::default());
    let n = Arc::new(Mutex::new(0));
    p.a.set_shaper(Some(event_factory(move |e, r| {
        let mut n = n.lock().unwrap();
        let len = match (e.kind, *n) {
            (EventKind::Start, 0) => 16_000,
            (EventKind::Injected, 1) => 1000,
            _ => return,
        };
        *n += 1;
        r.inject = Some(Inject::Send {
            after: Duration::from_millis(1),
            len,
        });
    })));
    let mut recs = Vec::new();
    for _ in 0..20 {
        p.now += Duration::from_millis(1);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.send_with(true, |w| records(w, &mut recs));
        p.send(false);
        p.drain_events();
    }
    let st = p.a.shaping_stats();
    assert_eq!((st.injected, st.padding_bytes), (1, 16_000), "{st:?}");
    for _ in 0..4 {
        transfer(&mut p, 500_000, &mut recs);
    }
    let st = p.a.shaping_stats();
    assert_eq!(st.padding_bytes, 17_000, "{st:?}");
    assert_eq!((st.clamped, st.inject_dropped), (0, 0), "{st:?}");
}

/// An injection that does not fit in what remains of a batch goes whole in
/// a later one instead of being cut to the room.
#[test]
fn an_injection_beyond_the_batch_room_waits_whole() {
    const LEN: usize = 16_000;
    let mut p = Pair::new(Config::default(), Config::default());
    p.out.set_max_len(LEN + 600);
    p.a.set_shaper(Some(event_factory(|e, r| {
        if matches!(e.kind, EventKind::Start | EventKind::Injected) {
            r.inject = Some(Inject::Send {
                after: Duration::from_millis(1),
                len: LEN,
            });
        }
    })));
    let mut recs = Vec::new();
    let k = p.a.open(Dir::Bidi).unwrap();
    let data = vec![7u8; 1000];
    for i in 0..400 {
        if i < 300 {
            let _ = p.a.write(k, &data);
        }
        p.now += Duration::from_millis(1);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.send_with(true, |w| records(w, &mut recs));
        p.send(false);
        p.drain_events();
        if let Some(r) = p.b.accept(Dir::Bidi).unwrap() {
            let mut buf = [0u8; 65536];
            while let Ok(Some((m, _))) = p.b.read(r, &mut buf) {
                if m == 0 {
                    break;
                }
            }
        }
    }
    let st = p.a.shaping_stats();
    assert!(st.injected > 10, "{st:?}");
    assert_eq!(st.padding_bytes % LEN as u64, 0, "{st:?}");
    assert_eq!(st.clamped, 0, "{st:?}");
}

#[test]
fn shaping_limits_are_validated() {
    use zmux::proto::session::{RoleConfig, SessionCore};
    let now = std::time::Instant::now();
    for (ratio, ok) in [
        (0.0, true),
        (1.0, true),
        (1.5, false),
        (-0.1, false),
        (f64::NAN, false),
    ] {
        let mut cfg = Config::default();
        let mut limits = Limits::default();
        limits.max_padding_ratio = Some(ratio);
        cfg.shaping_limits = limits;
        assert_eq!(limits.validate().is_ok(), ok, "{ratio}");
        let r = SessionCore::new(cfg, RoleConfig::Initiator, None, now);
        assert_eq!(r.is_ok(), ok, "{ratio}");
    }
}

/// A `max_len` below the minimum is raised to it and counted as clamped.
#[test]
fn a_max_len_below_the_minimum_is_raised_and_counted() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.a.set_shaper(Some(plan_factory(|p| p.max_len = 10)));
    transfer(&mut p, 3000, &mut Vec::new());
    assert!(p.a.shaping_stats().clamped > 0);
}

/// Padding targets beyond a record (a shaper of the application's own may
/// ask for any) are bounded by the record and counted as clamped, so that
/// the padding arithmetic cannot overflow.
#[test]
fn padding_targets_beyond_a_record_are_clamped() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.a.set_shaper(Some(plan_factory(|p| {
        p.pad_to = usize::MAX;
        p.pad_multiple = usize::MAX;
        p.pad = usize::MAX;
    })));
    transfer(&mut p, 3000, &mut Vec::new());
    assert!(p.a.shaping_stats().clamped > 0);
}
