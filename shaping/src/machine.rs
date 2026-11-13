//! The engine: state machines read from a definition, running on each pipe.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use zmux::shaping::{
    Caps, Effects, Event, EventKind, Factory, Gate, Injection, Meters, RecordPlan, RecordView,
    ShapedPipe, Shaper, wire_ppm,
};

use crate::error::{Error, err};
use crate::json::{Json, parse};
use crate::random::{OsSeeded, Source};
use crate::value::{ALL_SCOPES, Family, Reader, Sampler, Scope, Value, int, parse_value};

type NewSource = Arc<dyn Fn() -> Box<dyn Source> + Send + Sync>;

/// The default of [`SizeLimits::max_slots`].
pub const DEFAULT_MAX_SLOTS: u64 = 4096;

/// Bounds of a definition's size. A set bound bounds as it is, zero allowing none; `None`
/// is no bound, the default of every field but [`max_slots`](Self::max_slots).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SizeLimits {
    /// Input bytes.
    pub max_bytes: Option<usize>,
    /// Machines.
    pub max_machines: Option<usize>,
    /// States per machine.
    pub max_states: Option<usize>,
    /// Actions per state.
    pub max_actions: Option<usize>,
    /// Transitions per state.
    pub max_transitions: Option<usize>,
    /// Segments per value or table.
    pub max_segments: Option<usize>,
    /// Counters and timers of all machines of a candidate together (default
    /// [`DEFAULT_MAX_SLOTS`]). They are declared by a number and allocated for each pipe,
    /// so a short document could otherwise ask for any amount of memory.
    pub max_slots: Option<u64>,
}

impl Default for SizeLimits {
    fn default() -> Self {
        Self {
            max_bytes: None,
            max_machines: None,
            max_states: None,
            max_actions: None,
            max_transitions: None,
            max_segments: None,
            max_slots: Some(DEFAULT_MAX_SLOTS),
        }
    }
}

impl SizeLimits {
    pub(crate) fn input(&self, n: usize) -> Result<(), Error> {
        over(n, self.max_bytes, "input bytes")
    }
}

pub(crate) fn over(n: usize, m: Option<usize>, what: &str) -> Result<(), Error> {
    match m {
        Some(m) if n > m => Err(err("limit", format!("{what}: {n}, limit {m}"))),
        _ => Ok(()),
    }
}

/// How configuration is read and run. The default is valid.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Options {
    new_source: Option<NewSource>,
    /// Bounds of a definition.
    pub limits: SizeLimits,
    /// The features this reader has, for the `requires` of a candidate.
    pub features: Vec<String>,
    /// A kind all of whose candidates are skipped has no entry, instead of an error.
    pub allow_unshaped: bool,
}

impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("limits", &self.limits)
            .field("features", &self.features)
            .field("allow_unshaped", &self.allow_unshaped)
            .finish_non_exhaustive()
    }
}

impl Options {
    /// The random source of each compilation and each pipe; default: ChaCha8 seeded
    /// from the operating system.
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

    /// With the `features` of this reader.
    #[must_use]
    pub fn with_features(mut self, features: Vec<String>) -> Self {
        self.features = features;
        self
    }

    /// With [`Options::allow_unshaped`].
    #[must_use]
    pub fn with_allow_unshaped(mut self, allow: bool) -> Self {
        self.allow_unshaped = allow;
        self
    }

    pub(crate) fn sampler(&self) -> Sampler {
        Sampler::new(
            self.new_source
                .as_ref()
                .map_or_else(|| Box::new(OsSeeded::new()) as Box<dyn Source>, |f| f()),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    RecordOut,
    RecordIn,
    PaddingIn,
    Injected,
    InjectDropped,
    Enter,
    StreamOpen,
    StreamEnd,
    Timer(u32),
    Zero(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Lt,
    Le,
    Eq,
    Ne,
    Ge,
    Gt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum What {
    Counter(u32),
    Len,
    Seq,
    WireLeft,
    StallLeft,
    WireSpent,
    SentBytes,
    WirePpm,
}

#[derive(Debug, Clone)]
struct Cond {
    what: What,
    cmp: Cmp,
    value: Value,
}

#[derive(Debug, Clone)]
struct Transition {
    on: Trigger,
    to: u32,
    cond: Option<Cond>,
    prob: Option<Value>,
}

#[derive(Debug, Clone)]
enum Action {
    Inject { after: Value, len: Value },
    InjectCancel,
    Pause { after: Value },
    Rate { rate: Value, burst: Option<Value> },
    Timer { slot: u32, after: Value },
    TimerCancel { slot: u32 },
    Set { slot: u32, value: Value },
    Add { slot: u32, value: Value },
    Sub { slot: u32, value: Value },
    Weight { value: Value },
    Stop,
    Restart,
}

impl Action {
    fn values_mut(&mut self) -> [Option<&mut Value>; 2] {
        match self {
            Self::Inject { after, len } => [Some(after), Some(len)],
            Self::Pause { after } | Self::Timer { after, .. } => [Some(after), None],
            Self::Rate { rate, burst } => [Some(rate), burst.as_mut()],
            Self::Set { value, .. }
            | Self::Add { value, .. }
            | Self::Sub { value, .. }
            | Self::Weight { value } => [Some(value), None],
            _ => [None, None],
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Record {
    target: Option<Value>,
    max_len: Option<Value>,
    pad_to: Option<Value>,
    pad_multiple: Option<Value>,
    pad: Option<Value>,
    delay: Option<Value>,
    flush: bool,
}

#[derive(Debug, Clone, Default)]
struct State {
    record: Option<Record>,
    enter: Vec<Action>,
    next: Vec<Transition>,
}

#[derive(Debug, Clone)]
pub(crate) struct Machine {
    start: u32,
    counters: u32,
    timers: u32,
    states: Vec<State>,
}

fn known(x: &Json, allowed: &[&str], what: &str) -> Result<(), Error> {
    let Json::Obj(m) = x else {
        return Err(err("type", what.to_owned()));
    };
    match m.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
        Some((k, _)) => Err(err("unknown_member", format!("{what}.{k}"))),
        None => Ok(()),
    }
}

fn req<'a>(x: &'a Json, k: &str, what: &str) -> Result<&'a Json, Error> {
    x.get(k).ok_or_else(|| err("type", format!("{what}.{k}")))
}

fn count(x: Option<&Json>, what: &str) -> Result<u32, Error> {
    let Some(x) = x else {
        return Ok(0);
    };
    match int(x) {
        Some(v) if v >= 0 => u32::try_from(v).map_err(|_| err("range", what.to_owned())),
        _ => Err(err("type", what.to_owned())),
    }
}

fn slot(x: &Json, limit: u32, what: &str) -> Result<u32, Error> {
    let v = x
        .get("slot")
        .and_then(int)
        .ok_or_else(|| err("type", format!("{what}.slot")))?;
    if v < 0 || v >= i128::from(limit) {
        return Err(err("reference", format!("{what}.slot")));
    }
    Ok(v as u32)
}

struct Ctx<'a, 'b> {
    reader: &'b Reader<'a>,
    n: usize,
    counters: u32,
    timers: u32,
}

impl Ctx<'_, '_> {
    fn value(&self, x: &Json, fam: Family, what: &str) -> Result<Value, Error> {
        parse_value(x, fam, self.reader, ALL_SCOPES, what)
    }

    fn opt(&self, r: &Json, k: &str, fam: Family) -> Result<Option<Value>, Error> {
        r.get(k).map(|x| self.value(x, fam, k)).transpose()
    }

    fn state(&self, x: &Json) -> Result<State, Error> {
        let limits = &self.reader.limits;
        known(x, &["record", "enter", "next"], "state")?;
        let mut st = State::default();
        if let Some(r) = x.get("record") {
            known(
                r,
                &[
                    "target",
                    "max_len",
                    "pad_to",
                    "pad_multiple",
                    "pad",
                    "delay",
                    "flush",
                ],
                "record",
            )?;
            if r.get("target").is_some()
                && (r.get("max_len").is_some() || r.get("pad_to").is_some())
            {
                return Err(err("conflict", "target with max_len or pad_to"));
            }
            let flush = match r.get("flush") {
                None => false,
                Some(Json::Bool(b)) => *b,
                Some(_) => return Err(err("type", "flush")),
            };
            st.record = Some(Record {
                target: self.opt(r, "target", Family::Length)?,
                max_len: self.opt(r, "max_len", Family::Length)?,
                pad_to: self.opt(r, "pad_to", Family::Length)?,
                pad_multiple: self.opt(r, "pad_multiple", Family::Length)?,
                pad: self.opt(r, "pad", Family::Length)?,
                delay: self.opt(r, "delay", Family::Time)?,
                flush,
            });
        }
        if let Some(e) = x.get("enter") {
            let Json::Arr(list) = e else {
                return Err(err("type", "enter"));
            };
            over(list.len(), limits.max_actions, "actions")?;
            st.enter = list
                .iter()
                .map(|a| self.action(a))
                .collect::<Result<_, _>>()?;
        }
        if let Some(e) = x.get("next") {
            let Json::Arr(list) = e else {
                return Err(err("type", "next"));
            };
            over(list.len(), limits.max_transitions, "transitions")?;
            st.next = list
                .iter()
                .map(|t| self.transition(t))
                .collect::<Result<_, _>>()?;
        }
        Ok(st)
    }

    fn cancel(x: &Json) -> Result<bool, Error> {
        match x.get("cancel") {
            None => Ok(false),
            Some(Json::Bool(true)) => Ok(true),
            Some(_) => Err(err("type", "cancel")),
        }
    }

    fn action(&self, x: &Json) -> Result<Action, Error> {
        let Json::Obj(_) = x else {
            return Err(err("type", "action"));
        };
        let op = match x.get("op") {
            Some(Json::Str(s)) => s.as_str(),
            _ => return Err(err("type", "op")),
        };
        Ok(match op {
            "inject" => {
                known(x, &["op", "cancel", "after", "len"], op)?;
                if Self::cancel(x)? {
                    if x.get("after").is_some() || x.get("len").is_some() {
                        return Err(err("unknown_member", "inject cancel"));
                    }
                    Action::InjectCancel
                } else {
                    Action::Inject {
                        after: self.value(req(x, "after", op)?, Family::Time, "after")?,
                        len: self.value(req(x, "len", op)?, Family::Length, "len")?,
                    }
                }
            }
            "pause" => {
                known(x, &["op", "after"], op)?;
                Action::Pause {
                    after: self.value(req(x, "after", op)?, Family::Time, "after")?,
                }
            }
            "rate" => {
                known(x, &["op", "rate", "burst"], op)?;
                Action::Rate {
                    rate: self.value(req(x, "rate", op)?, Family::Rate, "rate")?,
                    burst: self.opt(x, "burst", Family::Length)?,
                }
            }
            "timer" => {
                known(x, &["op", "slot", "cancel", "after"], op)?;
                let s = slot(x, self.timers, op)?;
                if Self::cancel(x)? {
                    if x.get("after").is_some() {
                        return Err(err("unknown_member", "timer cancel"));
                    }
                    Action::TimerCancel { slot: s }
                } else {
                    Action::Timer {
                        slot: s,
                        after: self.value(req(x, "after", op)?, Family::Time, "after")?,
                    }
                }
            }
            "set" | "add" | "sub" => {
                known(x, &["op", "slot", "value"], op)?;
                let s = slot(x, self.counters, op)?;
                let value = self.value(req(x, "value", op)?, Family::Counter, "value")?;
                match op {
                    "set" => Action::Set { slot: s, value },
                    "add" => Action::Add { slot: s, value },
                    _ => Action::Sub { slot: s, value },
                }
            }
            "weight" => {
                known(x, &["op", "value"], op)?;
                Action::Weight {
                    value: self.value(req(x, "value", op)?, Family::Weight, "value")?,
                }
            }
            "stop" | "restart" => {
                known(x, &["op"], op)?;
                if op == "stop" {
                    Action::Stop
                } else {
                    Action::Restart
                }
            }
            _ => return Err(err("type", format!("op {op}"))),
        })
    }

    fn transition(&self, x: &Json) -> Result<Transition, Error> {
        known(x, &["on", "slot", "to", "if", "prob"], "transition")?;
        let on = req(x, "on", "transition")?;
        let to = int(req(x, "to", "transition")?).ok_or_else(|| err("type", "to"))?;
        if to < 0 || to >= self.n as i128 {
            return Err(err("reference", "to"));
        }
        let Json::Str(on) = on else {
            return Err(err("type", "on"));
        };
        let on = match on.as_str() {
            "timer" => Trigger::Timer(slot(x, self.timers, "timer")?),
            "zero" => Trigger::Zero(slot(x, self.counters, "zero")?),
            other => {
                let t = match other {
                    "record_out" => Trigger::RecordOut,
                    "record_in" => Trigger::RecordIn,
                    "padding_in" => Trigger::PaddingIn,
                    "injected" => Trigger::Injected,
                    "inject_dropped" => Trigger::InjectDropped,
                    "enter" => Trigger::Enter,
                    "stream_open" => Trigger::StreamOpen,
                    "stream_end" => Trigger::StreamEnd,
                    _ => return Err(err("type", format!("on {other}"))),
                };
                if x.get("slot").is_some() {
                    return Err(err("unknown_member", "slot"));
                }
                t
            }
        };
        let cond = x.get("if").map(|c| self.cond(c)).transpose()?;
        let prob = self.opt(x, "prob", Family::Ppm)?;
        Ok(Transition {
            on,
            to: to as u32,
            cond,
            prob,
        })
    }

    fn cond(&self, c: &Json) -> Result<Cond, Error> {
        known(c, &["what", "slot", "cmp", "value"], "if")?;
        let Json::Str(w) = req(c, "what", "if")? else {
            return Err(err("type", "if.what"));
        };
        let what = match w.as_str() {
            "counter" => What::Counter(slot(c, self.counters, "if")?),
            "len" | "seq" | "wire_left" | "stall_left" | "wire_spent" | "sent_bytes"
            | "wire_ppm" => {
                if c.get("slot").is_some() {
                    return Err(err("unknown_member", "if.slot"));
                }
                match w.as_str() {
                    "len" => What::Len,
                    "seq" => What::Seq,
                    "wire_left" => What::WireLeft,
                    "stall_left" => What::StallLeft,
                    "wire_spent" => What::WireSpent,
                    "sent_bytes" => What::SentBytes,
                    _ => What::WirePpm,
                }
            }
            _ => return Err(err("type", "if.what")),
        };
        let cmp = match req(c, "cmp", "if")? {
            Json::Str(s) => match s.as_str() {
                "lt" => Cmp::Lt,
                "le" => Cmp::Le,
                "eq" => Cmp::Eq,
                "ne" => Cmp::Ne,
                "ge" => Cmp::Ge,
                "gt" => Cmp::Gt,
                _ => return Err(err("type", "if.cmp")),
            },
            _ => return Err(err("type", "if.cmp")),
        };
        Ok(Cond {
            what,
            cmp,
            value: self.value(req(c, "value", "if")?, Family::Counter, "if.value")?,
        })
    }
}

pub(crate) fn parse_machines(x: &Json, reader: &Reader<'_>) -> Result<Vec<Machine>, Error> {
    let Json::Arr(list) = x else {
        return Err(err("type", "machines"));
    };
    if list.is_empty() {
        return Err(err("type", "machines"));
    }
    over(list.len(), reader.limits.max_machines, "machines")?;
    list.iter().map(|m| parse_machine(m, reader)).collect()
}

fn parse_machine(x: &Json, reader: &Reader<'_>) -> Result<Machine, Error> {
    known(x, &["start", "counters", "timers", "states"], "machine")?;
    let start = int(req(x, "start", "machine")?).ok_or_else(|| err("type", "machine.start"))?;
    if start < 0 {
        return Err(err("type", "machine.start"));
    }
    let counters = count(x.get("counters"), "machine.counters")?;
    let timers = count(x.get("timers"), "machine.timers")?;
    reader.use_slots(counters)?;
    reader.use_slots(timers)?;
    let Json::Arr(list) = req(x, "states", "machine")? else {
        return Err(err("type", "states"));
    };
    if list.is_empty() {
        return Err(err("type", "states"));
    }
    over(list.len(), reader.limits.max_states, "states")?;
    if start >= list.len() as i128 {
        return Err(err("reference", "start"));
    }
    let cx = Ctx {
        reader,
        n: list.len(),
        counters,
        timers,
    };
    let states = list.iter().map(|s| cx.state(s)).collect::<Result<_, _>>()?;
    let m = Machine {
        start: start as u32,
        counters,
        timers,
        states,
    };
    m.check()?;
    Ok(m)
}

impl Machine {
    /// The edges out of state `i` on the triggers `on` accepts, with a restart's.
    fn edges(&self, i: usize, on: impl Fn(Trigger) -> bool) -> Vec<usize> {
        let st = &self.states[i];
        let mut out: Vec<usize> = st
            .next
            .iter()
            .filter(|t| on(t.on))
            .map(|t| t.to as usize)
            .collect();
        if st.enter.iter().any(|a| matches!(a, Action::Restart)) {
            out.push(self.start as usize);
        }
        out
    }

    fn on_cycle(&self, on: impl Fn(Trigger) -> bool + Copy) -> Vec<bool> {
        let adj: Vec<Vec<usize>> = (0..self.states.len()).map(|i| self.edges(i, on)).collect();
        on_cycle(&adj)
    }

    fn check(&self) -> Result<(), Error> {
        let n = self.states.len();
        let mut seen = vec![false; n];
        let mut stack = vec![self.start as usize];
        seen[self.start as usize] = true;
        while let Some(s) = stack.pop() {
            for o in self.edges(s, |_| true) {
                if !seen[o] {
                    seen[o] = true;
                    stack.push(o);
                }
            }
        }
        if let Some(i) = seen.iter().position(|s| !s) {
            return Err(err("unreachable", format!("state {i}")));
        }
        let fast = |t| matches!(t, Trigger::Enter | Trigger::Zero(_));
        if self.on_cycle(fast).iter().any(|c| *c) {
            return Err(err("cycle", "enter, zero or restart"));
        }
        let slow = |t| {
            matches!(
                t,
                Trigger::Enter
                    | Trigger::Zero(_)
                    | Trigger::Injected
                    | Trigger::InjectDropped
                    | Trigger::Timer(_)
            )
        };
        for (i, c) in self.on_cycle(slow).iter().enumerate() {
            let zero = self.states[i].enter.iter().any(|a| match a {
                Action::Inject { after, .. } | Action::Timer { after, .. } => after.lower() == 0,
                _ => false,
            });
            if *c && zero {
                return Err(err("zero_delay_cycle", format!("state {i}")));
            }
        }
        Ok(())
    }
}

/// Reports for each vertex whether it lies on a cycle: Tarjan's strongly connected
/// components without recursion, in time linear in the graph.
fn on_cycle(adj: &[Vec<usize>]) -> Vec<bool> {
    let n = adj.len();
    let mut out = vec![false; n];
    let mut index = vec![0usize; n]; // 0: not visited
    let mut low = vec![0usize; n];
    let mut open = vec![false; n];
    let mut comp: Vec<usize> = Vec::new();
    let mut calls: Vec<(usize, usize)> = Vec::new();
    let mut clock = 0;
    for root in 0..n {
        if index[root] != 0 {
            continue;
        }
        clock += 1;
        index[root] = clock;
        low[root] = clock;
        open[root] = true;
        comp.push(root);
        calls.push((root, 0));
        while let Some(&mut (v, ref mut next)) = calls.last_mut() {
            if let Some(&w) = adj[v].get(*next) {
                *next += 1;
                if w == v {
                    out[v] = true;
                } else if index[w] == 0 {
                    clock += 1;
                    index[w] = clock;
                    low[w] = clock;
                    open[w] = true;
                    comp.push(w);
                    calls.push((w, 0));
                } else if open[w] {
                    low[v] = low[v].min(index[w]);
                }
                continue;
            }
            calls.pop();
            if let Some(&(p, _)) = calls.last() {
                low[p] = low[p].min(low[v]);
            }
            if low[v] != index[v] {
                continue;
            }
            let first = comp.iter().rposition(|&w| w == v).expect("on the stack");
            let many = comp.len() - first > 1;
            for w in comp.drain(first..) {
                open[w] = false;
                out[w] |= many;
            }
        }
    }
    out
}

pub(crate) struct Program {
    machines: Vec<Machine>,
    caps: Caps,
    pipe_slots: usize,
    counters: usize,
    timers: usize,
    /// Queue room by the structure: no event grows it further.
    queue: usize,
    shared: Vec<u64>,
    options: Options,
}

/// Settles the `shared` values and places the `pipe` ones, in the order of the contract.
fn settle(machines: &mut [Machine], s: &mut Sampler, shared: &mut Vec<u64>) -> usize {
    let mut slots = 0;
    let mut one = |v: &mut Value| {
        if v.scope == Scope::Pipe {
            v.slot = slots;
            slots += 1;
        } else {
            v.settle(s, shared);
        }
    };
    for m in machines {
        for st in &mut m.states {
            if let Some(r) = &mut st.record {
                for v in [
                    &mut r.target,
                    &mut r.max_len,
                    &mut r.pad_to,
                    &mut r.pad_multiple,
                    &mut r.pad,
                    &mut r.delay,
                ]
                .into_iter()
                .flatten()
                {
                    one(v);
                }
            }
            for a in &mut st.enter {
                for v in a.values_mut().into_iter().flatten() {
                    one(v);
                }
            }
            for t in &mut st.next {
                if let Some(c) = &mut t.cond {
                    one(&mut c.value);
                }
                if let Some(p) = &mut t.prob {
                    one(p);
                }
            }
        }
    }
    slots
}

pub(crate) fn compile(
    mut machines: Vec<Machine>,
    s: &mut Sampler,
    shared: &mut Vec<u64>,
    options: Options,
) -> Program {
    let first = shared.len();
    let pipe_slots = settle(&mut machines, s, shared);
    let mut caps = Caps::PLAN;
    // No enter or zero cycle: a drain enters a state at most once.
    let mut queue = 0;
    for m in &machines {
        queue += 1;
        for st in &m.states {
            for t in &st.next {
                match t.on {
                    Trigger::RecordIn | Trigger::PaddingIn => caps = caps | Caps::RECORD_IN,
                    Trigger::StreamOpen | Trigger::StreamEnd => caps = caps | Caps::STREAMS,
                    _ => {}
                }
                if t.cond
                    .as_ref()
                    .is_some_and(|c| !matches!(c.what, What::Counter(_) | What::Len | What::Seq))
                {
                    caps = caps | Caps::BUDGET;
                }
            }
            queue += 1 + st.enter.len();
        }
    }
    Program {
        caps,
        pipe_slots,
        counters: machines.iter().map(|m| m.counters as usize).sum(),
        timers: machines.iter().map(|m| m.timers as usize).sum(),
        queue,
        shared: shared[first..].to_vec(),
        machines,
        options,
    }
}

/// A [`Factory`] running a definition.
#[derive(Clone)]
pub struct MachineFactory(pub(crate) Arc<Program>);

impl fmt::Debug for MachineFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineFactory").finish_non_exhaustive()
    }
}

impl MachineFactory {
    /// Reads a definition: a JSON object with `machines` and optional `tables`.
    pub fn from_json(b: &[u8], options: Options) -> Result<Self, Error> {
        options.limits.input(b.len())?;
        let doc = parse(b)?;
        known(&doc, &["machines", "tables"], "definition")?;
        let tables = doc.get("tables");
        if tables.is_some_and(|t| !matches!(t, Json::Obj(_))) {
            return Err(err("type", "tables"));
        }
        let reader = Reader::new(tables, options.limits);
        let machines = parse_machines(req(&doc, "machines", "definition")?, &reader)?;
        let mut s = options.sampler();
        let mut shared = Vec::new();
        Ok(Self(Arc::new(compile(
            machines,
            &mut s,
            &mut shared,
            options,
        ))))
    }

    /// A new instance.
    #[must_use]
    pub fn shaper(&self) -> MachineShaper {
        MachineShaper::new(&self.0)
    }

    /// The `shared` values, in the order they were drawn.
    #[must_use]
    pub fn shared(&self) -> &[u64] {
        &self.0.shared
    }

    /// What its instances ask for.
    #[must_use]
    pub fn capabilities(&self) -> Caps {
        self.0.caps
    }
}

impl Factory for MachineFactory {
    fn shaper(&self, _: &ShapedPipe) -> Option<Box<dyn Shaper>> {
        Some(Box::new(MachineFactory::shaper(self)))
    }
}

#[derive(Clone, Copy)]
struct Queued {
    machine: u32,
    gen_: u64,
    trigger: Trigger,
}

/// The [`Shaper`] of one pipe.
pub struct MachineShaper {
    p: Arc<Program>,
    run: Run,
}

struct Run {
    src: Sampler,
    cur: Vec<u32>,
    gens: Vec<u64>,
    /// Offsets of each machine's counters and timers.
    ctr_at: Vec<u32>,
    tm_at: Vec<u32>,
    ctr: Vec<u64>,
    tm: Vec<Option<u64>>,
    inj: Vec<Option<(u64, usize)>>,
    rate: Vec<(u64, u64)>,
    weight: Vec<u32>,
    kept: Vec<Option<u64>>,
    q: VecDeque<Queued>,
    due: Vec<(u64, u32, u32)>,
    pause_until: u64,
    seq: u64,
    len: u64,
    meters: Meters,
    now: u64,
    stop: bool,
    surfaced: Option<usize>,
    last_inject: Option<Injection>,
    last_wake: Option<u64>,
    last_gate: Gate,
    last_weight: u32,
}

impl fmt::Debug for MachineShaper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineShaper")
            .field("seq", &self.run.seq)
            .finish_non_exhaustive()
    }
}

impl MachineShaper {
    fn new(p: &Arc<Program>) -> Self {
        let n = p.machines.len();
        let (mut ctr_at, mut tm_at) = (Vec::with_capacity(n), Vec::with_capacity(n));
        let (mut c, mut t) = (0, 0);
        for m in &p.machines {
            ctr_at.push(c);
            tm_at.push(t);
            c += m.counters;
            t += m.timers;
        }
        Self {
            run: Run {
                src: p.options.sampler(),
                cur: p.machines.iter().map(|m| m.start).collect(),
                gens: vec![0; n],
                ctr_at,
                tm_at,
                ctr: vec![0; p.counters],
                tm: vec![None; p.timers],
                inj: vec![None; n],
                rate: vec![(0, 0); n],
                weight: vec![0; n],
                kept: vec![None; p.pipe_slots],
                q: VecDeque::with_capacity(p.queue),
                due: Vec::with_capacity(p.timers),
                pause_until: 0,
                seq: 0,
                len: 0,
                meters: Meters::new(u64::MAX, u64::MAX, 0, 0),
                now: 0,
                stop: false,
                surfaced: None,
                last_inject: None,
                last_wake: None,
                last_gate: Gate::default(),
                last_weight: 0,
            },
            p: p.clone(),
        }
    }

    /// The current state of each machine.
    #[must_use]
    pub fn states(&self) -> &[u32] {
        &self.run.cur
    }

    /// The counters of machine `m`.
    #[must_use]
    pub fn counters(&self, m: usize) -> &[u64] {
        let at = self.run.ctr_at[m] as usize;
        &self.run.ctr[at..at + self.p.machines[m].counters as usize]
    }
}

impl Run {
    #[inline]
    fn val(&mut self, v: &Value) -> u64 {
        if v.scope == Scope::Pipe {
            if let Some(x) = self.kept[v.slot] {
                return x;
            }
            let x = self.src.draw(v);
            self.kept[v.slot] = Some(x);
            return x;
        }
        self.src.draw(v)
    }

    fn fire(&mut self, p: &Program, trigger: Trigger, len: u64, only: Option<u32>) {
        self.len = len;
        match only {
            Some(m) => self.push(m, trigger),
            None => {
                for m in 0..p.machines.len() as u32 {
                    self.push(m, trigger);
                }
            }
        }
        self.drain(p);
    }

    #[inline]
    fn push(&mut self, machine: u32, trigger: Trigger) {
        self.q.push_back(Queued {
            machine,
            gen_: self.gens[machine as usize],
            trigger,
        });
    }

    fn drain(&mut self, p: &Program) {
        while let Some(e) = self.q.pop_front() {
            if e.gen_ == self.gens[e.machine as usize] {
                self.step(p, e.machine, e.trigger);
            }
        }
    }

    fn step(&mut self, p: &Program, m: u32, trigger: Trigger) {
        let st = &p.machines[m as usize].states[self.cur[m as usize] as usize];
        for t in &st.next {
            if t.on != trigger {
                continue;
            }
            if let Some(c) = &t.cond
                && !self.cond(m, c)
            {
                continue;
            }
            if let Some(v) = &t.prob {
                let x = self.val(v);
                if !self.src.prob(x) {
                    continue;
                }
            }
            self.enter(p, m, t.to);
            return;
        }
    }

    fn cond(&mut self, m: u32, c: &Cond) -> bool {
        let x = match c.what {
            What::Counter(s) => self.ctr[(self.ctr_at[m as usize] + s) as usize],
            What::Len => self.len,
            What::Seq => self.seq,
            What::WireLeft => self.meters.wire_left,
            What::StallLeft => self.meters.stall_left,
            What::WireSpent => self.meters.wire_spent,
            What::SentBytes => self.meters.sent_bytes,
            What::WirePpm => wire_ppm(self.meters.wire_spent, self.meters.sent_bytes),
        };
        let y = self.val(&c.value);
        match c.cmp {
            Cmp::Lt => x < y,
            Cmp::Le => x <= y,
            Cmp::Eq => x == y,
            Cmp::Ne => x != y,
            Cmp::Ge => x >= y,
            Cmp::Gt => x > y,
        }
    }

    fn enter(&mut self, p: &Program, m: u32, to: u32) {
        let i = m as usize;
        self.cur[i] = to;
        self.gens[i] += 1;
        for a in &p.machines[i].states[to as usize].enter {
            if matches!(a, Action::Restart) {
                self.enter(p, m, p.machines[i].start);
                return;
            }
            self.act(m, a);
        }
        self.push(m, Trigger::Enter);
    }

    fn counter(&mut self, m: u32, s: u32, op: impl FnOnce(u64) -> u64, set: bool) {
        let at = (self.ctr_at[m as usize] + s) as usize;
        let was = self.ctr[at];
        self.ctr[at] = op(was);
        if self.ctr[at] == 0 && (was != 0 || !set) {
            self.push(m, Trigger::Zero(s));
        }
    }

    fn act(&mut self, m: u32, a: &Action) {
        let i = m as usize;
        match a {
            Action::Inject { after, len } => {
                let after = self.val(after);
                let len = self.val(len);
                self.inj[i] = Some((self.now.saturating_add(after), len as usize));
            }
            Action::InjectCancel => self.inj[i] = None,
            Action::Pause { after } => {
                let after = self.val(after);
                self.pause_until = self.pause_until.max(self.now.saturating_add(after));
            }
            Action::Rate { rate, burst } => {
                let r = self.val(rate);
                let b = burst.as_ref().map_or(0, |b| self.val(b));
                self.rate[i] = (r, b);
            }
            Action::Timer { slot, after } => {
                let after = self.val(after);
                let at = (self.tm_at[i] + slot) as usize;
                self.tm[at] = Some(self.now.saturating_add(after));
            }
            Action::TimerCancel { slot } => self.tm[(self.tm_at[i] + slot) as usize] = None,
            Action::Set { slot, value } => {
                let x = self.val(value);
                self.counter(m, *slot, |_| x, true);
            }
            Action::Add { slot, value } => {
                let x = self.val(value);
                self.counter(m, *slot, |c| c.saturating_add(x), false);
            }
            Action::Sub { slot, value } => {
                let x = self.val(value);
                self.counter(m, *slot, |c| c.saturating_sub(x), false);
            }
            Action::Weight { value } => {
                let w = self.val(value) as u32;
                if w != 0 {
                    self.weight[i] = w;
                }
            }
            Action::Stop => self.stop = true,
            Action::Restart => {}
        }
    }

    /// What changed since the last entrance.
    fn effects(&mut self, out: &mut Effects) {
        let mut best: Option<usize> = None;
        for (m, x) in self.inj.iter().enumerate() {
            if let Some((at, _)) = x
                && best.is_none_or(|b| self.inj[b].is_some_and(|(t, _)| *at < t))
            {
                best = Some(m);
            }
        }
        self.surfaced = best;
        let inject = best
            .and_then(|b| self.inj[b])
            .map(|(at, len)| Injection::new(at, len));
        if inject != self.last_inject {
            out.inject = Some(inject);
            self.last_inject = inject;
        }
        let wake = self.tm.iter().flatten().copied().min();
        if wake != self.last_wake {
            out.wake = Some(wake);
            self.last_wake = wake;
        }
        let mut rb = (0, 0);
        for &(r, b) in &self.rate {
            if r != 0 && (rb.0 == 0 || r < rb.0) {
                rb = (r, b);
            }
        }
        let gate = Gate::new(self.pause_until, rb.0, rb.1);
        if gate != self.last_gate {
            out.gate = Some(gate);
            self.last_gate = gate;
        }
        let w = self
            .weight
            .iter()
            .copied()
            .filter(|w| *w != 0)
            .min()
            .unwrap_or(0);
        if w != self.last_weight {
            out.weight = Some(w);
            self.last_weight = w;
        }
    }

    fn plan_record(&mut self, r: &Record, plan: &mut RecordPlan) {
        let mut cut = None;
        if let Some(v) = &r.target {
            let t = self.val(v) as usize;
            cut = Some(t);
            plan.pad_to = plan.pad_to.max(t);
        } else if let Some(v) = &r.max_len {
            cut = Some(self.val(v) as usize);
        }
        if let Some(c) = cut.filter(|c| *c != 0)
            && (plan.max_len == 0 || c < plan.max_len)
        {
            plan.max_len = c;
        }
        if let Some(v) = &r.pad_to {
            plan.pad_to = plan.pad_to.max(self.val(v) as usize);
        }
        if let Some(v) = &r.pad_multiple {
            plan.pad_multiple = plan.pad_multiple.max(self.val(v) as usize);
        }
        if let Some(v) = &r.pad {
            plan.pad = (plan.pad + self.val(v) as usize).min((1 << 31) - 1);
        }
        if let Some(v) = &r.delay {
            plan.delay = plan.delay.max(Duration::from_micros(self.val(v)));
        }
        plan.flush |= r.flush;
    }
}

impl Shaper for MachineShaper {
    fn capabilities(&self) -> Caps {
        self.p.caps
    }

    fn plan(&mut self, view: &RecordView, plan: &mut RecordPlan) {
        let Self { p, run } = self;
        run.now = view.now;
        run.meters = view.meters;
        for (m, def) in p.machines.iter().enumerate() {
            if let Some(r) = &def.states[run.cur[m] as usize].record {
                run.plan_record(r, plan);
            }
        }
        run.fire(p, Trigger::RecordOut, 0, None);
        run.seq += 1;
        plan.stop = run.stop;
        run.effects(&mut plan.effects);
    }

    fn on_event(&mut self, e: &Event, r: &mut Effects) {
        let Self { p, run } = self;
        run.now = e.now;
        run.meters = e.meters;
        match e.kind {
            EventKind::Start => {
                for (m, def) in p.machines.iter().enumerate() {
                    run.enter(p, m as u32, def.start);
                }
                run.drain(p);
            }
            EventKind::RecordIn if e.padding_only => {
                run.fire(p, Trigger::PaddingIn, e.len as u64, None);
            }
            EventKind::RecordIn => run.fire(p, Trigger::RecordIn, e.len as u64, None),
            EventKind::Injected => {
                if let Some(m) = run.surfaced {
                    run.inj[m] = None;
                }
                run.fire(p, Trigger::Injected, e.len as u64, None);
            }
            EventKind::InjectDropped => {
                if let Some(m) = run.surfaced {
                    run.inj[m] = None;
                    run.fire(p, Trigger::InjectDropped, 0, Some(m as u32));
                }
            }
            EventKind::Wake => {
                let mut due = std::mem::take(&mut run.due);
                due.clear();
                for (m, def) in p.machines.iter().enumerate() {
                    let at = run.tm_at[m] as usize;
                    for s in 0..def.timers {
                        if let Some(d) = run.tm[at + s as usize].filter(|d| *d <= run.now) {
                            due.push((d, m as u32, s));
                        }
                    }
                }
                due.sort_unstable();
                for &(d, m, s) in &due {
                    let at = (run.tm_at[m as usize] + s) as usize;
                    if run.tm[at] == Some(d) {
                        run.tm[at] = None;
                        run.fire(p, Trigger::Timer(s), 0, Some(m));
                    }
                }
                run.due = due;
            }
            EventKind::StreamOpen => run.fire(p, Trigger::StreamOpen, 0, None),
            EventKind::StreamEnd => run.fire(p, Trigger::StreamEnd, 0, None),
            _ => return,
        }
        run.effects(r);
        r.stop = run.stop;
    }
}

#[cfg(test)]
mod size_tests {
    use super::*;
    use crate::bundle::Bundle;

    fn slots(c: u64, t: u64) -> String {
        format!(r#"{{"machines":[{{"start":0,"counters":{c},"timers":{t},"states":[{{}}]}}]}}"#)
    }

    fn class(r: Result<MachineFactory, Error>) -> String {
        r.err().map_or(String::new(), |e| e.class().to_owned())
    }

    fn with(l: SizeLimits) -> Options {
        Options::default().with_limits(l)
    }

    fn max_slots(n: Option<u64>) -> SizeLimits {
        SizeLimits {
            max_slots: n,
            ..SizeLimits::default()
        }
    }

    #[test]
    fn max_slots_bounds_counters_and_timers() {
        let default = SizeLimits::default().max_slots;
        let cases: [(u64, u64, Option<u64>, &str); 8] = [
            (1 << 25, 1 << 25, default, "limit"),
            (DEFAULT_MAX_SLOTS, 0, default, ""),
            (DEFAULT_MAX_SLOTS, 1, default, "limit"),
            (2, 2, Some(3), "limit"),
            (DEFAULT_MAX_SLOTS, 1, None, ""),
            (1 << 30, 1 << 30, Some(3), "limit"),
            // None at all.
            (0, 0, Some(0), ""),
            (1, 0, Some(0), "limit"),
        ];
        for (c, t, l, want) in cases {
            let r = MachineFactory::from_json(slots(c, t).as_bytes(), with(max_slots(l)));
            assert_eq!(class(r), want, "{c} {t} {l:?}");
        }
        // Before anything is allocated, even with no bound asked for: beyond what a slot
        // number holds.
        let r =
            MachineFactory::from_json(slots(1 << 31, 1 << 31).as_bytes(), with(max_slots(None)));
        assert_eq!(class(r), "limit");
    }

    #[test]
    fn slots_count_across_machines() {
        let js = r#"{"machines":[{"start":0,"counters":4096,"states":[{}]},{"start":0,"timers":1,"states":[{}]}]}"#;
        assert_eq!(
            class(MachineFactory::from_json(js.as_bytes(), Options::default())),
            "limit"
        );
    }

    fn table_doc(refs: usize) -> String {
        let segs = vec!["[1,1,2]"; 2000].join(",");
        let refs = vec![r#"{"t":"a"}"#; refs].join(",");
        format!(
            r#"{{"tables":{{"a":[{segs}]}},"kinds":{{"default":[{{"pool":{{"dial_after":[{refs}]}}}}]}}}}"#
        )
    }

    /// References to a table share it: thousands of them over thousands of segments take no
    /// more than one parse, and its segment count is checked once.
    #[test]
    fn a_table_is_parsed_once() {
        let doc = table_doc(50_000);
        let t0 = std::time::Instant::now();
        Bundle::from_json(doc.as_bytes(), &Options::default()).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(30));
        let l = SizeLimits {
            max_segments: Some(1999),
            ..SizeLimits::default()
        };
        let e = Bundle::from_json(doc.as_bytes(), &with(l)).unwrap_err();
        assert_eq!(e.class(), "limit");
    }

    #[test]
    fn max_bytes_counts_the_tables() {
        let doc = table_doc(1);
        let mut l = SizeLimits {
            max_bytes: Some(doc.len()),
            ..SizeLimits::default()
        };
        Bundle::from_json(doc.as_bytes(), &with(l)).unwrap();
        l.max_bytes = Some(doc.len() - 1);
        let e = Bundle::from_json(doc.as_bytes(), &with(l)).unwrap_err();
        assert_eq!(e.class(), "limit");
    }

    #[test]
    fn on_cycle_finds_the_vertices_on_cycles() {
        let got = on_cycle(&[vec![1], vec![2], vec![1, 3], vec![3], vec![]]);
        assert_eq!(got, [false, true, true, true, false]);
    }

    /// A long chain of states is checked in linear time.
    #[test]
    fn the_structure_check_is_linear() {
        const N: usize = 200_000;
        let mut b = String::from(r#"{"machines":[{"start":0,"states":["#);
        for i in 0..N - 1 {
            b += &format!(r#"{{"next":[{{"on":"enter","to":{}}}]}},"#, i + 1);
        }
        b += "{}]}]}";
        let t0 = std::time::Instant::now();
        MachineFactory::from_json(b.as_bytes(), Options::default()).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(30));
    }

    /// A document cannot ask each pipe for the product of its states and its longest list.
    #[test]
    fn a_shapers_queue_is_linear_in_the_document() {
        let actions = vec![r#"{"op":"stop"}"#; 1000].join(",");
        let states = vec!["{}"; 1000].join(",");
        let doc = format!(
            r#"{{"machines":[{{"start":0,"states":[{{"enter":[{actions}],"next":[{}]}},{states}]}}]}}"#,
            (1..=1000)
                .map(|i| format!(r#"{{"on":"record_out","to":{i}}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let f = MachineFactory::from_json(doc.as_bytes(), Options::default()).unwrap();
        assert!(f.0.queue < 3000, "{}", f.0.queue);
    }

    /// Nesting far beyond the bound is a syntax error, not a stack overflow, on a test
    /// thread's small stack.
    #[test]
    fn deep_nesting_is_an_error() {
        for open in ["[", r#"{"a":"#] {
            let doc = open.repeat(1_000_000);
            let e = Bundle::from_json(doc.as_bytes(), &Options::default()).unwrap_err();
            assert_eq!(e.class(), "syntax");
        }
    }

    /// Duplicate names are found in time linear in the members.
    #[test]
    fn many_members_are_checked_in_linear_time() {
        let members: Vec<String> = (0..200_000)
            .map(|i| format!(r#""{i}":[[1,1,2]]"#))
            .collect();
        let doc = format!(
            r#"{{"tables":{{{}}},"kinds":{{"default":[{{}}]}}}}"#,
            members.join(",")
        );
        let t0 = std::time::Instant::now();
        Bundle::from_json(doc.as_bytes(), &Options::default()).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(30));
    }
}
