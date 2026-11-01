//! The engine, with the language-independent cases of
//! `testdata/shaping/contract.json`.

use std::time::{Duration, Instant};

use serde::Deserialize;
use zmux::PipeId;
use zmux::shaping::{
    Caps, Event, EventKind, Gate, Inject, RecordPlan, RecordView, Reply, Shaper, Timer,
};
use zmux_shaping::{
    Action, Definition, Dist, DistKind, Machine, MachineFactory, Op, Options, Record, Scope,
    SizeLimits, Source, State, Transition, Trigger, Value, parse_sequence,
};

struct SplitMix(u64);

impl Source for SplitMix {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn seeded() -> Options {
    Options::default().with_source(|| Box::new(SplitMix(1)))
}

fn view(seq: u64) -> RecordView {
    RecordView::new(PipeId::new(0), 0, seq, 65535, Instant::now())
}

fn start(s: &mut dyn Shaper) -> Reply {
    let mut r = Reply::default();
    s.on_event(
        &Event::new(EventKind::Start, PipeId::new(0), Instant::now()),
        &mut r,
    );
    r
}

fn plans(d: &Definition, o: Options, n: usize) -> Vec<RecordPlan> {
    let mut s = d.factory(o).unwrap().shaper();
    start(&mut s);
    (0..n)
        .map(|i| {
            let mut p = RecordPlan::default();
            s.plan(&view(i as u64), &mut p);
            p
        })
        .collect()
}

fn record(r: Record) -> Definition {
    Definition::new(vec![Machine::new(
        0,
        vec![State::new(Some(r), vec![], vec![])],
    )])
}

#[derive(Deserialize)]
struct Contract {
    definitions: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    json: Option<serde_json::Value>,
    #[serde(default)]
    raw: Option<String>,
    #[serde(default)]
    sequence: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    plans: Vec<PlanVec>,
}

#[derive(Deserialize, Default, Debug, PartialEq)]
#[serde(default)]
struct PlanVec {
    max_len: usize,
    pad_to: usize,
    pad_multiple: usize,
    pad: usize,
    delay_ns: u64,
    flush: bool,
    stop: bool,
}

#[test]
fn contract_definitions() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/shaping/contract.json"
    );
    let k: Contract = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for c in k.definitions {
        let d = match (&c.sequence, &c.raw, &c.json) {
            (Some(s), _, _) => parse_sequence(s),
            (None, Some(r), _) => Definition::from_json(r.as_bytes()),
            (None, None, Some(j)) => Definition::from_json(j.to_string().as_bytes()),
            _ => panic!("{}: no input", c.name),
        };
        if let Some(want) = &c.error {
            let e = d.expect_err(&c.name).to_string();
            assert!(
                e.to_lowercase().contains(&want.to_lowercase()),
                "{}: {e}, want {want:?}",
                c.name
            );
            continue;
        }
        let d = d.unwrap_or_else(|e| panic!("{}: {e}", c.name));
        for (i, p) in plans(&d, seeded(), c.plans.len()).into_iter().enumerate() {
            let got = PlanVec {
                max_len: p.max_len,
                pad_to: p.pad_to,
                pad_multiple: p.pad_multiple,
                pad: p.pad,
                delay_ns: p.delay.as_nanos() as u64,
                flush: p.flush,
                stop: p.stop,
            };
            assert_eq!(got, c.plans[i], "{}: plan {i}", c.name);
        }
    }
}

#[test]
fn json_round_trip() {
    let d = parse_sequence("10/inject=2:30, 20-40/delay=0.001/scope=pipe, gamma(2,3)").unwrap();
    let again = Definition::from_json(d.to_json().as_bytes()).unwrap();
    assert_eq!(again.machines[0].states.len(), d.machines[0].states.len());
}

#[test]
fn scopes_and_bounds() {
    let d = Definition::new(vec![
        Machine::new(
            0,
            vec![State::new(
                Some(Record::default().with_pad(Value::range(0.0, 1000.0).with_scope(Scope::Pipe))),
                vec![],
                vec![],
            )],
        ),
        Machine::new(
            0,
            vec![State::new(
                Some(
                    Record::default()
                        .with_pad_to(Value::range(0.0, 1000.0))
                        .with_pad_multiple(
                            Value::range(0.0, 1000.0).with_bounds(Some(10.0), Some(20.0)),
                        ),
                ),
                vec![],
                vec![],
            )],
        ),
    ]);
    let ps = plans(&d, seeded(), 20);
    assert!(ps.iter().all(|p| p.pad == ps[0].pad));
    assert!(ps.iter().any(|p| p.pad_to != ps[0].pad_to));
    assert!(ps.iter().all(|p| (10..=20).contains(&p.pad_multiple)));
    assert_eq!(ps, plans(&d, seeded(), 20));
}

#[test]
fn shared_scope() {
    let d = record(Record::default().with_pad(Value::range(0.0, 1e6).with_scope(Scope::Shared)));
    let f = d.factory(Options::default()).unwrap();
    let (mut a, mut b) = (f.shaper(), f.shaper());
    let (mut x, mut y) = (RecordPlan::default(), RecordPlan::default());
    a.plan(&view(0), &mut x);
    b.plan(&view(0), &mut y);
    assert_eq!(x.pad, y.pad);
}

#[test]
fn enter_actions() {
    let a = |op, f: fn(&mut Action)| {
        let mut a = Action::new(op);
        f(&mut a);
        a
    };
    let d = Definition::new(vec![Machine::new(
        0,
        vec![State::new(
            None,
            vec![
                a(Op::Inject, |a| {
                    a.after = Some(Value::constant(0.001));
                    a.len = Some(Value::constant(9.0));
                }),
                a(Op::Rate, |a| {
                    a.rate = Some(Value::constant(100.0));
                    a.burst = Some(Value::constant(50.0));
                }),
                a(Op::Timer, |a| {
                    a.slot = 1;
                    a.after = Some(Value::constant(0.003));
                }),
                a(Op::Weight, |a| a.value = Some(Value::constant(2.0))),
            ],
            vec![],
        )],
    )]);
    let r = start(&mut d.factory(Options::default()).unwrap().shaper());
    assert_eq!(
        r.inject,
        Some(Inject::Send {
            after: Duration::from_millis(1),
            len: 9
        })
    );
    assert_eq!(r.gate, Some(Gate::new(Duration::ZERO, 100, 50)));
    assert_eq!(
        r.timers,
        [None, Some(Timer::After(Duration::from_millis(3)))]
    );
    assert_eq!(r.weight, Some(2.0));
}

#[test]
fn bag_draws_without_replacement() {
    let d = record(Record::default().with_pad(Value::dist(
        Dist::new(DistKind::Bag, vec![]).with_points(vec![1.0, 2.0, 3.0], vec![]),
    )));
    let ps = plans(&d, seeded(), 6);
    for k in [0, 3] {
        let mut s: Vec<usize> = ps[k..k + 3].iter().map(|p| p.pad).collect();
        s.sort_unstable();
        assert_eq!(s, [1, 2, 3]);
    }
}

/// Binomial trials and the Poisson mean are bounded by 2^53, the counts
/// exact in an f64; the samplers take O(log n) steps up to it.
#[test]
fn count_distribution_bounds() {
    use DistKind as K;
    let max = 9_007_199_254_740_992.0;
    for (d, ok) in [
        (Dist::new(K::Binomial, vec![max, 0.5]), true),
        (Dist::new(K::Binomial, vec![2.0 * max, 0.5]), false),
        (Dist::new(K::Poisson, vec![max]), true),
        (Dist::new(K::Poisson, vec![2.0 * max]), false),
    ] {
        let def = record(
            Record::default().with_pad(Value::dist(d.clone()).with_bounds(None, Some(100.0))),
        );
        assert_eq!(def.factory(Options::default()).is_ok(), ok, "{d:?}");
        if ok {
            assert!(plans(&def, seeded(), 20).iter().all(|p| p.pad == 100));
        }
    }
}

#[test]
fn distributions_in_range() {
    use DistKind as K;
    let cases = [
        (Dist::new(K::Uniform, vec![2.0, 3.0]), 2, 3),
        (Dist::new(K::LogUniform, vec![2.0, 3.0]), 2, 3),
        (Dist::new(K::Exponential, vec![1.0]), 0, usize::MAX),
        (Dist::new(K::Normal, vec![5.0, 1.0]), 0, usize::MAX),
        (Dist::new(K::LogNormal, vec![0.0, 1.0]), 0, usize::MAX),
        (Dist::new(K::Weibull, vec![1.0, 2.0]), 0, usize::MAX),
        (Dist::new(K::Pareto, vec![1.0, 2.0]), 1, usize::MAX),
        (Dist::new(K::Gamma, vec![0.5, 1.0]), 0, usize::MAX),
        (Dist::new(K::Beta, vec![2.0, 2.0]), 0, 1),
        (Dist::new(K::Geometric, vec![0.5]), 1, usize::MAX),
        (Dist::new(K::Binomial, vec![4.0, 0.5]), 0, 4),
        (Dist::new(K::Poisson, vec![40.0]), 0, usize::MAX),
        (
            Dist::new(K::Empirical, vec![]).with_points(vec![1.0, 2.0], vec![0.0, 1.0]),
            2,
            2,
        ),
        (
            Dist::new(K::Mixture, vec![]).with_components(vec![Value::constant(4.0)], vec![1.0]),
            4,
            4,
        ),
    ];
    for (d, lo, hi) in cases {
        let kind = d.kind;
        let def = record(Record::default().with_pad(Value::dist(d).with_bounds(Some(0.0), None)));
        for p in plans(&def, seeded(), 50) {
            assert!((lo..=hi).contains(&p.pad), "{kind:?}: {}", p.pad);
        }
    }
}

/// Beta of small shapes, whose Gamma variates both underflow to zero, is
/// drawn from their logarithms: a number in [0, 1], never NaN (which as a
/// delay would not convert to a duration).
#[test]
fn beta_of_small_shapes_is_finite() {
    let d = Dist::new(DistKind::Beta, vec![0.001, 0.001]);
    let def = record(Record::default().with_delay(Value::dist(d)));
    for p in plans(&def, seeded(), 500) {
        assert!(p.delay <= Duration::from_secs(1), "{:?}", p.delay);
    }
}

#[test]
fn sequence_inject() {
    let mut s = MachineFactory::from_sequence("10/inject=2:30, 20", Options::default())
        .unwrap()
        .shaper();
    start(&mut s);
    let mut p = RecordPlan::default();
    s.plan(&view(0), &mut p);
    assert_eq!(p.pad_to, 10);
    assert_eq!(p.reply.inject, None);
    let mut n = 0;
    let mut kind = EventKind::RecordIn;
    loop {
        let mut r = Reply::default();
        s.on_event(&Event::new(kind, PipeId::new(0), Instant::now()), &mut r);
        let Some(i) = r.inject else { break };
        assert_eq!(
            i,
            Inject::Send {
                after: Duration::ZERO,
                len: 30
            }
        );
        n += 1;
        kind = EventKind::Injected;
    }
    assert_eq!(n, 2);
    let mut p = RecordPlan::default();
    s.plan(&view(1), &mut p);
    // The stop follows the record: the reply applied first leaves it.
    assert!(p.pad_to == 20 && p.stop && !p.reply.stop);
}

#[test]
fn size_limits() {
    let w = |_| {
        let mut a = Action::new(Op::Weight);
        a.value = Some(Value::constant(1.0));
        a
    };
    let d = Definition::new(vec![Machine::new(
        0,
        vec![
            State::new(
                None,
                (0..2).map(w).collect(),
                vec![Transition::new(Trigger::RecordOut, 1)],
            ),
            State::default(),
        ],
    )]);
    let mut states = SizeLimits::default();
    states.max_states = Some(1);
    let mut actions = SizeLimits::default();
    actions.max_actions = Some(1);
    for (l, ok) in [
        (states, false),
        (actions, false),
        (SizeLimits::default(), true),
    ] {
        assert_eq!(
            d.factory(Options::default().with_limits(l)).is_ok(),
            ok,
            "{l:?}"
        );
    }
    let mut bytes = SizeLimits::default();
    bytes.max_bytes = Some(8);
    let json = br#"{"version":1,"machines":[{"states":[{}]}]}"#;
    assert!(MachineFactory::from_json(json, Options::default().with_limits(bytes)).is_err());
    // A set zero bound allows none; unset bounds nothing.
    let mut zero = SizeLimits::default();
    zero.max_machines = Some(0);
    assert!(d.factory(Options::default().with_limits(zero)).is_err());
    zero = SizeLimits::default();
    zero.max_bytes = Some(0);
    assert!(MachineFactory::from_json(json, Options::default().with_limits(zero)).is_err());
}

#[test]
fn stream_trigger_caps() {
    let d = Definition::new(vec![Machine::new(
        0,
        vec![
            State::new(None, vec![], vec![Transition::new(Trigger::StreamOpen, 1)]),
            State::new(
                Some(Record::default().with_pad(Value::constant(5.0))),
                vec![],
                vec![],
            ),
        ],
    )]);
    let mut s = d.factory(Options::default()).unwrap().shaper();
    let c = s.capabilities();
    assert!(c.contains(Caps::STREAMS) && !c.contains(Caps::RECORD_IN));
    start(&mut s);
    let e = Event::new(EventKind::StreamOpen, PipeId::new(0), Instant::now()).with_stream(4);
    s.on_event(&e, &mut Reply::default());
    let mut p = RecordPlan::default();
    s.plan(&view(0), &mut p);
    assert_eq!(p.pad, 5);
}

/// A negative or non-finite length, delay, rate, burst or counter value
/// fails the whole definition instead of counting as 0, and so does a
/// distribution that may draw below 0 without a `min` of at least 0.
#[test]
fn negative_values_fail_the_definition() {
    let def = |state: &str| {
        format!(r#"{{"version":1,"machines":[{{"states":[{state}]}}]}}"#).into_bytes()
    };
    for (state, ok) in [
        (r#"{"record":{"pad":{"const":-1}}}"#, false),
        (r#"{"record":{"delay":{"range":[-0.1,0.2]}}}"#, false),
        (r#"{"record":{"pad_to":{"const":10,"min":-5}}}"#, false),
        (
            r#"{"record":{"max_len":{"dist":{"kind":"empirical","points":[100,-1],"weights":[1,1]}}}}"#,
            false,
        ),
        (
            r#"{"enter":[{"op":"inject","after":{"const":-1},"len":{"const":10}}]}"#,
            false,
        ),
        (r#"{"enter":[{"op":"rate","rate":{"const":-100}}]}"#, false),
        (r#"{"record":{"pad":{"const":10}}}"#, true),
        (
            r#"{"record":{"pad":{"dist":{"kind":"normal","params":[10,20]}}}}"#,
            false,
        ),
        (
            r#"{"record":{"pad":{"dist":{"kind":"normal","params":[10,20]},"min":0}}}"#,
            true,
        ),
        (r#"{"enter":[{"op":"set","value":{"const":-3}}]}"#, false),
        (r#"{"enter":[{"op":"weight","value":{"const":-3}}]}"#, true),
    ] {
        let r = MachineFactory::from_json(&def(state), Options::default());
        assert_eq!(r.is_ok(), ok, "{state}: {:?}", r.err());
    }
}

/// A pipe's write overhead comes off `max_len` and `pad_to` on the first
/// record of each carrier write only; none leaves the plans as they are.
#[test]
fn write_overhead_comes_off_the_first_record_of_a_write() {
    use zmux::shaping::{Factory, ShapedPipe};
    let d = Definition::from_json(
        br#"{"version": 1, "machines": [{"states": [{"record": {"max_len": {"const": 1000}, "pad_to": {"const": 800}}}]}]}"#,
    )
    .unwrap();
    let f = d.factory(seeded()).unwrap();
    let plan = |overhead: u16, write_start: bool| {
        let pipe = ShapedPipe::new(PipeId::new(0), None).with_write_overhead(overhead);
        let mut s = Factory::shaper(&f, &pipe).unwrap();
        start(&mut *s);
        let mut p = RecordPlan::default();
        s.plan(&view(0).with_write_start(write_start), &mut p);
        (p.max_len, p.pad_to)
    };
    assert_eq!(plan(0, true), (1000, 800));
    assert_eq!(plan(29, true), (971, 771));
    assert_eq!(plan(29, false), (1000, 800));
    // Below the session's minimum: left to the session to raise.
    assert_eq!(plan(5000, true), (1, 0));
}
