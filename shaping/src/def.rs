//! The definition: its JSON form and its validation.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bound::Family;
use crate::random::MAX_COUNT;

/// The definition version this crate reads.
pub const VERSION: u32 = 1;

/// An invalid definition or sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub(crate) String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub(crate) fn err(s: impl Into<String>) -> Error {
    Error(s.into())
}

/// A set of machines that run side by side on each pipe.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Definition {
    /// Must be [`VERSION`].
    #[serde(default)]
    pub version: u32,
    /// The machines.
    #[serde(default)]
    pub machines: Vec<Machine>,
}

/// A state machine with two counters.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Machine {
    /// Index into `states`.
    #[serde(default)]
    pub start: usize,
    /// The states.
    #[serde(default)]
    pub states: Vec<State>,
}

/// A machine state.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct State {
    /// Applies to each record planned while the machine is in the state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<Record>,
    /// Runs in order when the state is entered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enter: Vec<Action>,
    /// Tried in order on each trigger; the first match moves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<Transition>,
}

/// Record decisions; `None`: none. Lengths in bytes, times in seconds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Record {
    /// [`RecordPlan::max_len`](zmux::shaping::RecordPlan::max_len).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<Value>,
    /// [`RecordPlan::pad_to`](zmux::shaping::RecordPlan::pad_to).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad_to: Option<Value>,
    /// [`RecordPlan::pad_multiple`](zmux::shaping::RecordPlan::pad_multiple).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad_multiple: Option<Value>,
    /// [`RecordPlan::pad`](zmux::shaping::RecordPlan::pad).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad: Option<Value>,
    /// [`RecordPlan::delay`](zmux::shaping::RecordPlan::delay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<Value>,
    /// [`RecordPlan::flush`](zmux::shaping::RecordPlan::flush).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub flush: bool,
    /// `max_len` and `pad_to` take one draw of `max_len`.
    #[serde(skip)]
    pub(crate) one_len: bool,
}

/// An operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Op {
    /// `len` bytes after `after` seconds; with `cancel`: cancels the
    /// pending one.
    Inject,
    /// Stream data waits `after` seconds.
    Pause,
    /// `rate` bytes per second, `burst` bytes; rate 0: no limit.
    Rate,
    /// Timer `slot` fires after `after` seconds; with `cancel`: disarms it.
    Timer,
    /// Counter `slot` = `value`.
    Set,
    /// Counter `slot` += `value`.
    Add,
    /// Counter `slot` -= `value`, not below 0.
    Sub,
    /// The pipe's weight = `value`.
    Weight,
    /// Shaping of the pipe ends.
    Stop,
    /// The machine re-enters its start state.
    Restart,
    /// Not a known operation (rejected by validation).
    #[serde(other)]
    Unknown,
}

/// An operation and its operands; an operand the operation does not use
/// is an error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ActionJson")]
#[non_exhaustive]
pub struct Action {
    /// The operation.
    pub op: Op,
    /// [`Op::Inject`], [`Op::Timer`]: cancels.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cancel: bool,
    /// Timer or counter slot, 0 or 1.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub slot: usize,
    /// Seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    /// Bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<Value>,
    /// Bytes per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Value>,
    /// Bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<Value>,
    /// The operand of [`Op::Set`], [`Op::Add`], [`Op::Sub`], [`Op::Weight`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

impl Record {
    /// With `max_len`.
    #[must_use]
    pub fn with_max_len(mut self, v: Value) -> Self {
        self.max_len = Some(v);
        self
    }

    /// With `pad_to`.
    #[must_use]
    pub fn with_pad_to(mut self, v: Value) -> Self {
        self.pad_to = Some(v);
        self
    }

    /// With `pad_multiple`.
    #[must_use]
    pub fn with_pad_multiple(mut self, v: Value) -> Self {
        self.pad_multiple = Some(v);
        self
    }

    /// With `pad`.
    #[must_use]
    pub fn with_pad(mut self, v: Value) -> Self {
        self.pad = Some(v);
        self
    }

    /// With `delay`.
    #[must_use]
    pub fn with_delay(mut self, v: Value) -> Self {
        self.delay = Some(v);
        self
    }

    /// With `flush`.
    #[must_use]
    pub fn with_flush(mut self, flush: bool) -> Self {
        self.flush = flush;
        self
    }
}

impl Action {
    /// `op` without operands.
    #[must_use]
    pub fn new(op: Op) -> Self {
        Self {
            op,
            cancel: false,
            slot: 0,
            after: None,
            len: None,
            rate: None,
            burst: None,
            value: None,
        }
    }
}

fn is_zero(x: &usize) -> bool {
    *x == 0
}

/// What a [`Transition`] reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Trigger {
    /// A record was planned.
    RecordOut,
    /// A record arrived.
    RecordIn,
    /// A record of PADDING only arrived.
    PaddingIn,
    /// An injection was sent.
    Injected,
    /// Timer 0 fired.
    Timer0,
    /// Timer 1 fired.
    Timer1,
    /// Counter 0 reached 0.
    Zero0,
    /// Counter 1 reached 0.
    Zero1,
    /// Tried once after the state is entered.
    Enter,
    /// A stream got its identifier.
    StreamOpen,
    /// A stream's state was discarded.
    StreamEnd,
    /// Not a known trigger (rejected by validation).
    #[serde(other)]
    Unknown,
}

/// Moves the machine to `to` when `on` happens, `cond` holds and a draw
/// falls below `prob`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Transition {
    /// The trigger.
    pub on: Trigger,
    /// Index of the target state.
    pub to: usize,
    /// In [0, 1]; `None`: 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prob: Option<Value>,
    /// The condition; `None`: always.
    #[serde(default, rename = "if", skip_serializing_if = "Option::is_none")]
    pub cond: Option<Cond>,
}

impl Transition {
    /// On `on` to `to`, unconditionally.
    #[must_use]
    pub fn new(on: Trigger, to: usize) -> Self {
        Self {
            on,
            to,
            prob: None,
            cond: None,
        }
    }
}

/// Compares a quantity with a value: `what cmp value`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Cond {
    /// The quantity.
    pub what: Quantity,
    /// The comparison.
    pub cmp: Comparison,
    /// The value.
    pub value: Value,
}

impl Cond {
    /// `what cmp value`.
    #[must_use]
    pub fn new(what: Quantity, cmp: Comparison, value: Value) -> Self {
        Self { what, cmp, value }
    }
}

/// What a [`Cond`] compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Quantity {
    /// Counter 0 of the machine.
    Counter0,
    /// Counter 1 of the machine.
    Counter1,
    /// Bytes of the triggering record.
    Len,
    /// Records planned on the pipe.
    Seq,
    /// Not a known quantity (rejected by validation).
    #[serde(other)]
    Unknown,
}

/// How a [`Cond`] compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Comparison {
    /// <
    Lt,
    /// <=
    Le,
    /// ==
    Eq,
    /// !=
    Ne,
    /// >=
    Ge,
    /// >
    Gt,
    /// Not a known comparison (rejected by validation).
    #[serde(other)]
    Unknown,
}

/// How long a sampled value is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Scope {
    /// Sampled at each use.
    #[default]
    Each,
    /// Once per pipe (of a pool policy: per member).
    Pipe,
    /// Once per factory, shared by its pipes (of a pool policy: once per
    /// policy).
    Shared,
    /// Not a known scope (rejected by validation).
    #[serde(other)]
    Unknown,
}

/// A number: `const`, a uniform `range` or a `dist`; then bounded by
/// `min` and `max` when set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Value {
    /// A constant.
    #[serde(default, rename = "const", skip_serializing_if = "Option::is_none")]
    pub constant: Option<f64>,
    /// Uniform in [a, b].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<Vec<f64>>,
    /// A distribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dist: Option<Box<Dist>>,
    /// How long a sample is kept.
    #[serde(default, skip_serializing_if = "is_each")]
    pub scope: Scope,
    /// Lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    /// Upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

fn is_each(s: &Scope) -> bool {
    *s == Scope::Each
}

impl Value {
    /// The constant `x`.
    #[must_use]
    pub fn constant(x: f64) -> Self {
        Self {
            constant: Some(x),
            ..Self::default()
        }
    }

    /// Uniform in [a, b].
    #[must_use]
    pub fn range(a: f64, b: f64) -> Self {
        Self {
            range: Some(vec![a, b]),
            ..Self::default()
        }
    }

    /// The distribution `d`.
    #[must_use]
    pub fn dist(d: Dist) -> Self {
        Self {
            dist: Some(Box::new(d)),
            ..Self::default()
        }
    }

    /// With `scope`.
    #[must_use]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// With bounds; `None`: unbounded on that side.
    #[must_use]
    pub fn with_bounds(mut self, min: Option<f64>, max: Option<f64>) -> Self {
        self.min = min;
        self.max = max;
        self
    }
}

/// A distribution kind. Parameters (`params`) by kind:
/// uniform a b; loguniform a b (0 < a <= b); exponential rate; normal mean
/// sd; lognormal mu sigma; weibull scale shape; pareto scale shape; gamma
/// shape scale; beta a b; geometric p; binomial n p (n integral, at most
/// 2^53); poisson mean (at most 2^53).
/// empirical: `points` with `weights`; bag: `points`, drawn without
/// replacement and refilled when empty; mixture: `of` with `weights`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum DistKind {
    Uniform,
    LogUniform,
    Exponential,
    Normal,
    LogNormal,
    Weibull,
    Pareto,
    Gamma,
    Beta,
    Geometric,
    Binomial,
    Poisson,
    Empirical,
    Bag,
    Mixture,
    /// Not a known kind (rejected by validation).
    #[serde(other)]
    Unknown,
}

impl DistKind {
    pub(crate) fn from_name(s: &str) -> Self {
        serde_json::from_value(serde_json::Value::String(s.to_owned())).unwrap_or(Self::Unknown)
    }

    fn params(self) -> Option<usize> {
        use DistKind as K;
        Some(match self {
            K::Exponential | K::Geometric | K::Poisson => 1,
            K::Empirical | K::Bag | K::Mixture => 0,
            K::Unknown => return None,
            _ => 2,
        })
    }

    /// The members a distribution of the kind may have, besides `kind`.
    fn members(self) -> &'static [&'static str] {
        use DistKind as K;
        match self {
            K::Empirical => &["points", "weights"],
            K::Bag => &["points"],
            K::Mixture => &["of", "weights"],
            K::Unknown => &["params", "points", "weights", "of"],
            _ => &["params"],
        }
    }

    fn name(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    }
}

/// A distribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DistJson")]
#[non_exhaustive]
pub struct Dist {
    /// The kind.
    pub kind: DistKind,
    /// Parameters, by kind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<f64>,
    /// Points (empirical, bag).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub points: Vec<f64>,
    /// Weights (empirical, mixture).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weights: Vec<f64>,
    /// Components (mixture).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub of: Vec<Value>,
}

/// The JSON form of a [`Dist`], which tells an absent member from an empty
/// one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DistJson {
    kind: DistKind,
    params: Option<Vec<f64>>,
    points: Option<Vec<f64>>,
    weights: Option<Vec<f64>>,
    of: Option<Vec<Value>>,
}

impl TryFrom<DistJson> for Dist {
    type Error = Error;

    fn try_from(d: DistJson) -> Result<Self, Error> {
        let name = d.kind.name();
        let members = [
            ("params", d.params.is_some()),
            ("points", d.points.is_some()),
            ("weights", d.weights.is_some()),
            ("of", d.of.is_some()),
        ];
        let allowed = d.kind.members();
        if let Some((m, _)) = members.iter().find(|(m, set)| *set && !allowed.contains(m)) {
            return Err(err(format!("dist {name}: unknown field `{m}`")));
        }
        Ok(Self {
            kind: d.kind,
            params: d.params.unwrap_or_default(),
            points: d.points.unwrap_or_default(),
            weights: d.weights.unwrap_or_default(),
            of: d.of.unwrap_or_default(),
        })
    }
}

impl Dist {
    /// `kind` with `params`.
    #[must_use]
    pub fn new(kind: DistKind, params: Vec<f64>) -> Self {
        Self {
            kind,
            params,
            points: Vec::new(),
            weights: Vec::new(),
            of: Vec::new(),
        }
    }

    /// With `points` and `weights`.
    #[must_use]
    pub fn with_points(mut self, points: Vec<f64>, weights: Vec<f64>) -> Self {
        self.points = points;
        self.weights = weights;
        self
    }

    /// With components `of` and `weights`.
    #[must_use]
    pub fn with_components(mut self, of: Vec<Value>, weights: Vec<f64>) -> Self {
        self.of = of;
        self.weights = weights;
        self
    }
}

impl Definition {
    /// `machines` at [`VERSION`].
    #[must_use]
    pub fn new(machines: Vec<Machine>) -> Self {
        Self {
            version: VERSION,
            machines,
        }
    }

    /// Reads a JSON definition and validates it.
    pub fn from_json(b: &[u8]) -> Result<Self, Error> {
        let d: Self = crate::json::from_slice("machine", b)?;
        d.validate()?;
        Ok(d)
    }

    /// The JSON form.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Reports the first error.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION {
            return Err(err(format!(
                "machine: version {}, want {VERSION}",
                self.version
            )));
        }
        if self.machines.is_empty() {
            return Err(err("machine: no machines"));
        }
        for (i, m) in self.machines.iter().enumerate() {
            m.validate().map_err(|e| err(format!("machine {i}: {e}")))?;
        }
        Ok(())
    }
}

impl Machine {
    /// `states`, starting at `start`.
    #[must_use]
    pub fn new(start: usize, states: Vec<State>) -> Self {
        Self { start, states }
    }

    fn validate(&self) -> Result<(), Error> {
        let n = self.states.len();
        if self.start >= n {
            return Err(err(format!("start {} out of range", self.start)));
        }
        for (i, st) in self.states.iter().enumerate() {
            st.validate(n).map_err(|e| err(format!("state {i}: {e}")))?;
        }
        self.structure()
    }
}

impl State {
    /// A state with `record`, `enter` and `next`.
    #[must_use]
    pub fn new(record: Option<Record>, enter: Vec<Action>, next: Vec<Transition>) -> Self {
        Self {
            record,
            enter,
            next,
        }
    }

    fn validate(&self, n: usize) -> Result<(), Error> {
        if let Some(r) = &self.record {
            let names = ["max_len", "pad_to", "pad_multiple", "pad", "delay"];
            for (v, what) in r.values().into_iter().zip(names) {
                let fam = if what == "delay" {
                    Family::Seconds
                } else {
                    Family::Length
                };
                v.map_or(Ok(()), |v| v.check(fam, what))?;
            }
        }
        for (j, a) in self.enter.iter().enumerate() {
            a.validate().map_err(|e| err(format!("action {j}: {e}")))?;
        }
        for (j, t) in self.next.iter().enumerate() {
            t.validate(n)
                .map_err(|e| err(format!("transition {j}: {e}")))?;
        }
        Ok(())
    }
}

impl Record {
    pub(crate) fn values(&self) -> [Option<&Value>; 5] {
        [
            self.max_len.as_ref(),
            self.pad_to.as_ref(),
            self.pad_multiple.as_ref(),
            self.pad.as_ref(),
            self.delay.as_ref(),
        ]
    }
}

/// The operands an operation may have, besides `op`.
fn operands(op: Op) -> &'static [&'static str] {
    match op {
        Op::Inject => &["cancel", "after", "len"],
        Op::Pause => &["after"],
        Op::Rate => &["rate", "burst"],
        Op::Timer => &["cancel", "slot", "after"],
        Op::Set | Op::Add | Op::Sub => &["slot", "value"],
        Op::Weight => &["value"],
        Op::Stop | Op::Restart | Op::Unknown => &[],
    }
}

fn op_name(op: Op) -> String {
    serde_json::to_value(op)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The JSON form of an [`Action`], which tells an absent `cancel` or
/// `slot` from a default one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionJson {
    op: Op,
    cancel: Option<bool>,
    slot: Option<usize>,
    after: Option<Value>,
    len: Option<Value>,
    rate: Option<Value>,
    burst: Option<Value>,
    value: Option<Value>,
}

impl TryFrom<ActionJson> for Action {
    type Error = Error;

    fn try_from(a: ActionJson) -> Result<Self, Error> {
        for (name, set) in [("cancel", a.cancel.is_some()), ("slot", a.slot.is_some())] {
            if set && a.op != Op::Unknown && !operands(a.op).contains(&name) {
                return Err(err(format!("{}: unknown field `{name}`", op_name(a.op))));
            }
        }
        Ok(Self {
            op: a.op,
            cancel: a.cancel.unwrap_or_default(),
            slot: a.slot.unwrap_or_default(),
            after: a.after,
            len: a.len,
            rate: a.rate,
            burst: a.burst,
            value: a.value,
        })
    }
}

impl Action {
    pub(crate) fn values(&self) -> [Option<&Value>; 5] {
        [
            self.after.as_ref(),
            self.len.as_ref(),
            self.rate.as_ref(),
            self.burst.as_ref(),
            self.value.as_ref(),
        ]
    }

    fn validate(&self) -> Result<(), Error> {
        if self.op == Op::Unknown {
            return Err(err("unknown op"));
        }
        let op = op_name(self.op);
        let allowed = operands(self.op);
        let fields = [
            ("cancel", self.cancel),
            ("slot", self.slot != 0),
            ("after", self.after.is_some()),
            ("len", self.len.is_some()),
            ("rate", self.rate.is_some()),
            ("burst", self.burst.is_some()),
            ("value", self.value.is_some()),
        ];
        if let Some((name, _)) = fields.iter().find(|(n, set)| *set && !allowed.contains(n)) {
            return Err(err(format!("{op}: unknown field `{name}`")));
        }
        if self.slot > 1 {
            return Err(err(format!("slot {}", self.slot)));
        }
        let value = match self.op {
            Op::Weight => Family::Any,
            _ => Family::Counter,
        };
        for (v, fam, what) in [
            (&self.after, Family::Seconds, "after"),
            (&self.len, Family::Length, "len"),
            (&self.rate, Family::Rate, "rate"),
            (&self.burst, Family::Length, "burst"),
            (&self.value, value, "value"),
        ] {
            v.as_ref().map_or(Ok(()), |v| v.check(fam, what))?;
        }
        let need: &[(&Option<Value>, &str)] = match self.op {
            Op::Inject | Op::Timer if self.cancel => &[],
            Op::Inject => &[(&self.after, "after"), (&self.len, "len")],
            Op::Pause | Op::Timer => &[(&self.after, "after")],
            Op::Rate => &[(&self.rate, "rate")],
            Op::Set | Op::Add | Op::Sub | Op::Weight => &[(&self.value, "value")],
            Op::Stop | Op::Restart | Op::Unknown => &[],
        };
        match need.iter().find(|(v, _)| v.is_none()) {
            Some((_, what)) => Err(err(format!("{op}: missing {what}"))),
            None => Ok(()),
        }
    }
}

impl Transition {
    fn validate(&self, n: usize) -> Result<(), Error> {
        if self.on == Trigger::Unknown {
            return Err(err("unknown trigger"));
        }
        if self.to >= n {
            return Err(err(format!("target {} out of range", self.to)));
        }
        if let Some(p) = &self.prob {
            p.check(Family::Prob, "prob")?;
        }
        if let Some(c) = &self.cond {
            if c.what == Quantity::Unknown {
                return Err(err("unknown quantity"));
            }
            if c.cmp == Comparison::Unknown {
                return Err(err("unknown comparison"));
            }
            c.value.check(Family::Any, "if")?;
        }
        Ok(())
    }
}

fn finite(x: f64) -> bool {
    x.is_finite()
}

impl Value {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let mut k = 0;
        if let Some(c) = self.constant {
            k += 1;
            if !finite(c) {
                return Err(err("value: not finite"));
            }
        }
        if let Some(r) = &self.range {
            k += 1;
            if r.len() != 2 || !finite(r[0]) || !finite(r[1]) || r[0] > r[1] {
                return Err(err("value: range needs two finite numbers a <= b"));
            }
        }
        if let Some(d) = &self.dist {
            k += 1;
            d.validate()?;
        }
        if k != 1 {
            return Err(err("value: exactly one of const, range, dist"));
        }
        if self.scope == Scope::Unknown {
            return Err(err("value: unknown scope"));
        }
        if !self.min.is_none_or(finite) || !self.max.is_none_or(finite) {
            return Err(err("value: bound not finite"));
        }
        if let (Some(a), Some(b)) = (self.min, self.max)
            && a > b
        {
            return Err(err("value: min > max"));
        }
        Ok(())
    }
}

impl Dist {
    fn validate(&self) -> Result<(), Error> {
        use DistKind as K;
        let Some(want) = self.kind.params() else {
            return Err(err("dist: unknown kind"));
        };
        let name = self.kind.name();
        let members = [
            ("params", !self.params.is_empty()),
            ("points", !self.points.is_empty()),
            ("weights", !self.weights.is_empty()),
            ("of", !self.of.is_empty()),
        ];
        let allowed = self.kind.members();
        if let Some((m, _)) = members.iter().find(|(m, set)| *set && !allowed.contains(m)) {
            return Err(err(format!("dist {name}: unknown field `{m}`")));
        }
        if self.params.len() != want {
            return Err(err(format!(
                "dist {name}: {} params, want {want}",
                self.params.len()
            )));
        }
        if !self.params.iter().all(|p| finite(*p)) {
            return Err(err(format!("dist {name}: param not finite")));
        }
        let p = &self.params;
        let bad = match self.kind {
            K::Uniform => p[0] > p[1],
            K::LogUniform => p[0] <= 0.0 || p[0] > p[1],
            K::Exponential => p[0] <= 0.0,
            K::Poisson => p[0] <= 0.0 || p[0] > MAX_COUNT,
            K::Normal | K::LogNormal => p[1] < 0.0,
            K::Weibull | K::Pareto | K::Gamma | K::Beta => p[0] <= 0.0 || p[1] <= 0.0,
            K::Geometric => p[0] <= 0.0 || p[0] > 1.0,
            K::Binomial => {
                p[0] < 0.0 || p[0] > MAX_COUNT || p[0] != p[0].trunc() || p[1] < 0.0 || p[1] > 1.0
            }
            K::Empirical => {
                self.points.is_empty()
                    || self.weights.len() != self.points.len()
                    || !weights(&self.weights)
            }
            K::Bag => self.points.is_empty(),
            K::Mixture => {
                for v in &self.of {
                    v.validate()?;
                }
                self.of.is_empty() || self.weights.len() != self.of.len() || !weights(&self.weights)
            }
            K::Unknown => true,
        };
        if bad {
            return Err(err(format!("dist {name}: invalid parameters")));
        }
        if !self.points.iter().all(|x| finite(*x)) {
            return Err(err(format!("dist {name}: point not finite")));
        }
        Ok(())
    }
}

fn weights(w: &[f64]) -> bool {
    w.iter().all(|x| finite(*x) && *x >= 0.0) && w.iter().sum::<f64>() > 0.0
}
