//! The engine: a [`Factory`] that runs a definition on each pipe.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use zmux::shaping::ShapedPipe;
use zmux::shaping::{
    Caps, Event, EventKind, Factory, Gate, Inject, RecordPlan, RecordView, Reply, Shaper, Timer,
};

use crate::check::SizeLimits;
use crate::def::{Comparison, Definition, Error, Op, Quantity, Scope, Trigger, Value};
use crate::random::{OsSeeded, Rand, Source};
use crate::value::{Draw, Keep, Num, compile};

type NewSource = Arc<dyn Fn() -> Box<dyn Source> + Send + Sync>;

/// Configures a [`MachineFactory`]. The default is valid.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Options {
    new_source: Option<NewSource>,
    /// Bounds of the definition.
    pub limits: SizeLimits,
}

impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Options {
    /// The random source of each pipe (and of shared values); default:
    /// ChaCha8 seeded from the operating system.
    #[must_use]
    pub fn with_source(mut self, f: impl Fn() -> Box<dyn Source> + Send + Sync + 'static) -> Self {
        self.new_source = Some(Arc::new(f));
        self
    }

    /// With `limits`.
    #[must_use]
    pub fn with_limits(mut self, limits: SizeLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) fn source(&self) -> Box<dyn Source> {
        self.new_source
            .as_ref()
            .map_or_else(|| Box::new(OsSeeded::new()) as Box<dyn Source>, |f| f())
    }
}

struct PRecord {
    max_len: Option<usize>,
    pad_to: Option<usize>,
    pad_multiple: Option<usize>,
    pad: Option<usize>,
    delay: Option<usize>,
    flush: bool,
    one_len: bool,
}

struct PAction {
    op: Op,
    cancel: bool,
    slot: usize,
    after: Option<usize>,
    len: Option<usize>,
    rate: Option<usize>,
    burst: Option<usize>,
    value: Option<usize>,
}

struct PTrans {
    on: Trigger,
    to: usize,
    prob: Option<usize>,
    cond: Option<(Quantity, Comparison, usize)>,
}

struct PState {
    record: Option<PRecord>,
    enter: Vec<PAction>,
    next: Vec<PTrans>,
}

struct PMachine {
    start: usize,
    states: Vec<PState>,
}

struct Program {
    machines: Vec<PMachine>,
    nums: Vec<Num>,
    caps: Caps,
    /// Triggers processed per event at most.
    bound: usize,
    /// Shared values, drawn once.
    shared: Vec<Option<f64>>,
    options: Options,
}

impl Program {
    fn num(&mut self, v: &Value) -> usize {
        compile(&mut self.nums, v)
    }

    fn opt(&mut self, v: Option<&Value>) -> Option<usize> {
        v.map(|v| self.num(v))
    }
}

/// A [`Factory`] running a definition.
#[derive(Clone)]
pub struct MachineFactory(Arc<Program>);

impl fmt::Debug for MachineFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineFactory").finish_non_exhaustive()
    }
}

impl Definition {
    /// The factory running the definition, which is checked against
    /// `options.limits`.
    pub fn factory(&self, options: Options) -> Result<MachineFactory, Error> {
        self.check(&options.limits)?;
        let mut p = Program {
            machines: Vec::new(),
            nums: Vec::new(),
            caps: Caps::PLAN,
            bound: 0,
            shared: Vec::new(),
            options,
        };
        for m in &self.machines {
            p.bound += 4 * (m.states.len() + 1);
            let mut states = Vec::new();
            for st in &m.states {
                let record = st.record.as_ref().map(|r| PRecord {
                    max_len: p.opt(r.max_len.as_ref()),
                    pad_to: if r.one_len {
                        None
                    } else {
                        p.opt(r.pad_to.as_ref())
                    },
                    pad_multiple: p.opt(r.pad_multiple.as_ref()),
                    pad: p.opt(r.pad.as_ref()),
                    delay: p.opt(r.delay.as_ref()),
                    flush: r.flush,
                    one_len: r.one_len,
                });
                let enter = st
                    .enter
                    .iter()
                    .map(|a| PAction {
                        op: a.op,
                        cancel: a.cancel,
                        slot: a.slot,
                        after: p.opt(a.after.as_ref()),
                        len: p.opt(a.len.as_ref()),
                        rate: p.opt(a.rate.as_ref()),
                        burst: p.opt(a.burst.as_ref()),
                        value: p.opt(a.value.as_ref()),
                    })
                    .collect();
                let mut next = Vec::new();
                for t in &st.next {
                    match t.on {
                        Trigger::RecordIn | Trigger::PaddingIn => p.caps = p.caps | Caps::RECORD_IN,
                        Trigger::StreamOpen | Trigger::StreamEnd => p.caps = p.caps | Caps::STREAMS,
                        _ => {}
                    }
                    next.push(PTrans {
                        on: t.on,
                        to: t.to,
                        prob: p.opt(t.prob.as_ref()),
                        cond: t.cond.as_ref().map(|c| (c.what, c.cmp, p.num(&c.value))),
                    });
                }
                states.push(PState {
                    record,
                    enter,
                    next,
                });
            }
            p.machines.push(PMachine {
                start: m.start,
                states,
            });
        }
        // Shared values are drawn once, here.
        let p = Arc::new(p);
        let shared: Vec<Option<f64>> = {
            let mut m = MachineShaper::new(&p);
            (0..p.nums.len())
                .map(|i| {
                    (p.nums[i].v.scope == Scope::Shared).then(|| {
                        let mut k = PipeKeep {
                            shared: &[],
                            kept: &mut m.kept,
                        };
                        m.d.draw(&p.nums, i, &mut k)
                    })
                })
                .collect()
        };
        let mut p = Arc::try_unwrap(p).unwrap_or_else(|_| unreachable!("one owner"));
        p.shared = shared;
        Ok(MachineFactory(Arc::new(p)))
    }
}

impl MachineFactory {
    /// Parses a JSON definition (bounded by `options.limits.max_bytes`)
    /// and returns its factory.
    pub fn from_json(b: &[u8], options: Options) -> Result<Self, Error> {
        options.limits.input("machine", b.len())?;
        Definition::from_json(b)?.factory(options)
    }

    /// Parses the sequence form (bounded by `options.limits.max_bytes`)
    /// and returns its factory.
    pub fn from_sequence(s: &str, options: Options) -> Result<Self, Error> {
        options.limits.input("sequence", s.len())?;
        crate::parse_sequence(s)?.factory(options)
    }

    /// A new instance, for a pipe without write overhead.
    #[must_use]
    pub fn shaper(&self) -> MachineShaper {
        MachineShaper::new(&self.0)
    }
}

/// Every pipe runs the definition as defined, whatever its [`ShapedPipe`]
/// says, except for its write overhead: the `max_len` and `pad_to` lengths
/// of the definition are those of a carrier write below the pipe, so that
/// the pipe's [`ShapedPipe::write_overhead`] is taken off them on the first
/// record of each write ([`RecordView::write_start`]); a `max_len` that
/// falls below the session's minimum is raised to it (and counted as
/// clamped).
impl Factory for MachineFactory {
    fn shaper(&self, pipe: &ShapedPipe) -> Option<Box<dyn Shaper>> {
        let mut s = MachineFactory::shaper(self);
        s.overhead = usize::from(pipe.write_overhead);
        Some(Box::new(s))
    }
}

#[derive(Clone, Copy, Default)]
struct MState {
    cur: usize,
    ctr: [f64; 2],
}

/// The [`Shaper`] of one pipe.
pub struct MachineShaper {
    p: Arc<Program>,
    d: Draw,
    ms: Vec<MState>,
    /// Pipe-scoped values.
    kept: Vec<Option<f64>>,
    seq: u64,
    /// Len of the triggering event.
    n: usize,
    q: VecDeque<(usize, Trigger)>,
    /// The pipe's write overhead ([`ShapedPipe::write_overhead`]).
    overhead: usize,
}

impl fmt::Debug for MachineShaper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineShaper")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// `x` validated non-negative; up to 1e9 s, and a non-finite or negative
/// draw (NaN) as zero, so that the conversion cannot panic.
fn seconds(x: f64) -> Duration {
    if x > 0.0 {
        Duration::from_secs_f64(x.min(1e9))
    } else {
        Duration::ZERO
    }
}

impl MachineShaper {
    fn new(p: &Arc<Program>) -> Self {
        let n = p.nums.len();
        Self {
            d: Draw::new(Rand(p.options.source()), n),
            ms: p
                .machines
                .iter()
                .map(|m| MState {
                    cur: m.start,
                    ctr: [0.0; 2],
                })
                .collect(),
            kept: vec![None; n],
            seq: 0,
            n: 0,
            q: VecDeque::new(),
            overhead: 0,
            p: p.clone(),
        }
    }

    /// Offers `t` to every machine.
    fn fire(&mut self, t: Trigger, n: usize, r: &mut Reply) {
        self.n = n;
        for m in 0..self.ms.len() {
            self.q.push_back((m, t));
        }
        self.drain(r);
    }

    /// Processes pending triggers, at most `bound` per call.
    fn drain(&mut self, r: &mut Reply) {
        let mut steps = 0;
        while steps < self.p.bound
            && let Some((m, t)) = self.q.pop_front()
        {
            self.step(m, t, r);
            steps += 1;
        }
        self.q.clear();
    }

    fn step(&mut self, m: usize, t: Trigger, r: &mut Reply) {
        let p = self.p.clone();
        let st = &p.machines[m].states[self.ms[m].cur];
        for tr in &st.next {
            if tr.on != t || tr.cond.is_some_and(|c| !self.cond(m, c)) {
                continue;
            }
            if let Some(prob) = tr.prob
                && self.d.r.float() >= self.sample(prob)
            {
                continue;
            }
            self.enter(m, tr.to, r);
            return;
        }
    }

    fn enter(&mut self, m: usize, to: usize, r: &mut Reply) {
        self.ms[m].cur = to;
        let p = self.p.clone();
        for a in &p.machines[m].states[to].enter {
            self.act(m, a, r);
        }
        self.q.push_back((m, Trigger::Enter));
    }

    fn act(&mut self, m: usize, a: &PAction, r: &mut Reply) {
        let num = |x: Option<usize>| x.expect("validated");
        match a.op {
            Op::Inject if a.cancel => r.inject = Some(Inject::Cancel),
            Op::Inject => {
                let after = self.dur(num(a.after));
                let len = self.length(num(a.len));
                r.inject = Some(Inject::Send { after, len });
            }
            Op::Pause => r.gate = Some(Gate::new(self.dur(num(a.after)), 0, 0)),
            Op::Rate => {
                // Validated non-negative.
                let rate = self.sample(num(a.rate)) as u64;
                let burst = a.burst.map_or(0, |b| self.sample(b) as u64);
                r.gate = Some(Gate::new(Duration::ZERO, rate, burst));
            }
            Op::Timer if a.cancel => r.timers[a.slot] = Some(Timer::Cancel),
            Op::Timer => r.timers[a.slot] = Some(Timer::After(self.dur(num(a.after)))),
            Op::Set | Op::Add | Op::Sub => {
                // Validated non-negative.
                let x = self.sample(num(a.value));
                let c = &mut self.ms[m].ctr[a.slot];
                let was = *c;
                *c = match a.op {
                    Op::Set => x,
                    Op::Add => *c + x,
                    _ => (*c - x).max(0.0),
                };
                if *c == 0.0 && (was != 0.0 || a.op != Op::Set) {
                    let z = [Trigger::Zero0, Trigger::Zero1][a.slot];
                    self.q.push_back((m, z));
                }
            }
            Op::Weight => r.weight = Some(self.sample(num(a.value))),
            Op::Stop => r.stop = true,
            Op::Restart => {
                let start = self.p.machines[m].start;
                self.enter(m, start, r);
            }
            Op::Unknown => {}
        }
    }

    fn cond(&mut self, m: usize, (what, cmp, v): (Quantity, Comparison, usize)) -> bool {
        let x = match what {
            Quantity::Counter0 => self.ms[m].ctr[0],
            Quantity::Counter1 => self.ms[m].ctr[1],
            Quantity::Len => self.n as f64,
            Quantity::Seq => self.seq as f64,
            Quantity::Unknown => return false,
        };
        let y = self.sample(v);
        match cmp {
            Comparison::Lt => x < y,
            Comparison::Le => x <= y,
            Comparison::Eq => x == y,
            Comparison::Ne => x != y,
            Comparison::Ge => x >= y,
            Comparison::Gt => x > y,
            Comparison::Unknown => false,
        }
    }

    fn length(&mut self, v: usize) -> usize {
        // Validated non-negative.
        self.sample(v).round().min(i32::MAX as f64) as usize
    }

    fn dur(&mut self, v: usize) -> Duration {
        seconds(self.sample(v))
    }

    /// The value of number `i`, kept per its scope.
    fn sample(&mut self, i: usize) -> f64 {
        let p = self.p.clone();
        let mut k = PipeKeep {
            shared: &p.shared,
            kept: &mut self.kept,
        };
        self.d.sample(&p.nums, i, &mut k)
    }
}

/// The values of one pipe: shared ones drawn by the factory, pipe-scoped
/// ones kept on first use.
struct PipeKeep<'a> {
    shared: &'a [Option<f64>],
    kept: &'a mut [Option<f64>],
}

impl Keep for PipeKeep<'_> {
    fn kept(&mut self, i: usize, scope: Scope) -> Option<f64> {
        match scope {
            Scope::Shared => self.shared.get(i).copied().flatten(),
            Scope::Pipe => self.kept[i],
            _ => None,
        }
    }

    fn keep(&mut self, i: usize, scope: Scope, x: f64) {
        if scope == Scope::Pipe {
            self.kept[i] = Some(x);
        }
    }
}

impl Shaper for MachineShaper {
    fn capabilities(&self) -> Caps {
        self.p.caps
    }

    fn plan(&mut self, view: &RecordView, plan: &mut RecordPlan) {
        let p = self.p.clone();
        for i in 0..self.ms.len() {
            let Some(rec) = &p.machines[i].states[self.ms[i].cur].record else {
                continue;
            };
            let mut m = 0;
            if let Some(v) = rec.max_len {
                m = self.length(v);
                if plan.max_len == 0 || m > 0 && m < plan.max_len {
                    plan.max_len = m;
                }
            }
            if rec.one_len {
                plan.pad_to = plan.pad_to.max(m);
            } else if let Some(v) = rec.pad_to {
                plan.pad_to = plan.pad_to.max(self.length(v));
            }
            if let Some(v) = rec.pad_multiple {
                plan.pad_multiple = plan.pad_multiple.max(self.length(v));
            }
            if let Some(v) = rec.pad {
                // Lengths are at most 2^31-1.
                plan.pad = (plan.pad + self.length(v)).min(i32::MAX as usize);
            }
            if let Some(v) = rec.delay {
                plan.delay = plan.delay.max(self.dur(v));
            }
            plan.flush |= rec.flush;
        }
        if self.overhead > 0 && view.write_start {
            if plan.max_len > 0 {
                // Below the minimum: raised and counted by the session.
                plan.max_len = plan.max_len.saturating_sub(self.overhead).max(1);
            }
            plan.pad_to = plan.pad_to.saturating_sub(self.overhead);
        }
        let mut reply = std::mem::take(&mut plan.reply);
        self.fire(Trigger::RecordOut, 0, &mut reply);
        self.seq += 1;
        plan.stop = std::mem::take(&mut reply.stop);
        plan.reply = reply;
    }

    fn on_event(&mut self, e: &Event, r: &mut Reply) {
        match e.kind {
            EventKind::Start => {
                for i in 0..self.ms.len() {
                    let start = self.p.machines[i].start;
                    self.enter(i, start, r);
                }
                self.drain(r);
            }
            EventKind::RecordIn if e.padding_only => self.fire(Trigger::PaddingIn, e.len, r),
            EventKind::RecordIn => self.fire(Trigger::RecordIn, e.len, r),
            EventKind::Injected => self.fire(Trigger::Injected, e.len, r),
            EventKind::Timer => {
                self.fire([Trigger::Timer0, Trigger::Timer1][e.timer & 1], 0, r);
            }
            EventKind::StreamOpen => self.fire(Trigger::StreamOpen, 0, r),
            EventKind::StreamEnd => self.fire(Trigger::StreamEnd, 0, r),
            _ => {}
        }
    }
}
