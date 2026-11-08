//! Numbers: integer tables of weighted segments, and their sampling.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{Error, err};
use crate::json::Json;
use crate::machine::{SizeLimits, over};
use crate::random::Source;

/// Where a value is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Each,
    Pipe,
    Shared,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Segment {
    /// The sum of the weights up to and with this segment.
    acc: u64,
    lo: u64,
    hi: u64,
}

/// A number of a configuration: a constant, or a table of segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// Shared by the references to one table.
    segments: Arc<[Segment]>,
    /// The least segment bound; segments of weight 0 count.
    low: u64,
    pub(crate) scope: Scope,
    /// The slot of a `pipe` value.
    pub(crate) slot: usize,
}

impl Value {
    /// Reads a value of the widest family: an integer in \[0, 2^53\] or
    /// `{"t": segments, "scope": ...}`. Table names need a bundle.
    pub fn from_json(json: &[u8]) -> Result<Self, Error> {
        parse_value(
            &crate::json::parse(json)?,
            Family::Counter,
            &Reader::new(None, SizeLimits::default()),
            ALL_SCOPES,
            "value",
        )
    }

    pub(crate) fn constant(v: u64) -> Self {
        Self {
            segments: Arc::new([Segment {
                acc: 1,
                lo: v,
                hi: v,
            }]),
            low: v,
            scope: Scope::Each,
            slot: 0,
        }
    }

    /// The least value a draw can take; segments of weight 0 count.
    pub(crate) const fn lower(&self) -> u64 {
        self.low
    }

    /// Fixes a `shared` value with its one draw, which `out` records.
    pub(crate) fn settle(&mut self, s: &mut Sampler, out: &mut Vec<u64>) {
        if self.scope == Scope::Shared {
            let v = s.draw(self);
            out.push(v);
            *self = Self::constant(v);
        }
    }
}

/// `(a x b) >> 64`.
#[inline]
pub(crate) const fn mulhi64(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) >> 64) as u64
}

const JITTER_SCALE: u64 = 18_446_744_073_709;

/// `v` reduced by the draw `u`, by up to `j` parts per million.
#[inline]
pub(crate) const fn jitter_with(u: u64, v: u64, j: u32) -> u64 {
    let m = mulhi64(v, j as u64 * JITTER_SCALE);
    v - mulhi64(u, m + 1)
}

/// Draws numbers from a [`Source`].
pub struct Sampler(Box<dyn Source>);

impl Sampler {
    /// A sampler over `source`.
    #[must_use]
    pub fn new(source: Box<dyn Source>) -> Self {
        Self(source)
    }

    /// The next raw value.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    /// A draw of `v`. One segment takes no value to choose it, and a point none to
    /// place it.
    #[inline]
    pub fn draw(&mut self, v: &Value) -> u64 {
        let s = match &*v.segments {
            [one] => one,
            all => {
                let total = all.last().map_or(0, |s| s.acc);
                let c = mulhi64(self.0.next_u64(), total);
                &all[all.partition_point(|s| s.acc <= c)]
            }
        };
        if s.lo == s.hi {
            return s.lo;
        }
        s.lo + mulhi64(self.0.next_u64(), s.hi - s.lo + 1)
    }

    /// Whether an event of `p` parts per million happens.
    #[inline]
    pub fn prob(&mut self, p: u64) -> bool {
        if p == 0 {
            return false;
        }
        if p >= 1_000_000 {
            return true;
        }
        mulhi64(self.0.next_u64(), 1_000_000) < p
    }

    /// `v` reduced by a random amount of up to `j` parts per million.
    #[inline]
    pub fn jitter(&mut self, v: u64, j: u32) -> u64 {
        if j == 0 {
            return v;
        }
        jitter_with(self.0.next_u64(), v, j)
    }
}

impl std::fmt::Debug for Sampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sampler")
    }
}

/// What a value stands for, which bounds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Length,
    Time,
    Ppm,
    Weight,
    Counter,
    Rate,
    PoolCount,
}

pub(crate) const P53: u64 = 1 << 53;

impl Family {
    const fn range(self) -> (u64, u64) {
        match self {
            Self::Length => (0, (1 << 31) - 1),
            Self::Time => (0, 1_000_000_000_000_000),
            Self::Ppm => (0, 1_000_000),
            Self::Weight => (0, (1 << 32) - 1),
            Self::Counter => (0, P53),
            Self::Rate => (0, 1 << 43),
            Self::PoolCount => (1, P53),
        }
    }
}

/// The scopes every place allows.
pub(crate) const ALL_SCOPES: &[Scope] = &[Scope::Each, Scope::Pipe, Scope::Shared];
/// The scopes outside a pipe.
pub(crate) const FREE_SCOPES: &[Scope] = &[Scope::Each, Scope::Shared];
/// The scope of a budget's values.
pub(crate) const BUDGET_SCOPES: &[Scope] = &[Scope::Session];

pub(crate) fn int(x: &Json) -> Option<i128> {
    match x {
        Json::Int(v) => Some(*v),
        _ => None,
    }
}

/// A parsed list of segments, which references share.
#[derive(Clone)]
struct Table {
    segments: Arc<[Segment]>,
    lo: u64,
    hi: u64,
}

/// The state of reading one configuration: its tables, each parsed once at its first
/// reference, its limits and the counters and timers it declared so far.
pub(crate) struct Reader<'a> {
    tables: HashMap<&'a str, &'a Json>,
    parsed: RefCell<HashMap<&'a str, Table>>,
    pub(crate) limits: SizeLimits,
    slots: Cell<u64>,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(tables: Option<&'a Json>, limits: SizeLimits) -> Self {
        let tables = match tables {
            Some(Json::Obj(m)) => m.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            _ => HashMap::new(),
        };
        Self {
            tables,
            parsed: RefCell::default(),
            limits,
            slots: Cell::new(0),
        }
    }

    /// Counts a machine's counters and timers, before anything is made of them.
    pub(crate) fn use_slots(&self, n: u32) -> Result<(), Error> {
        let used = self.slots.get() + u64::from(n);
        self.slots.set(used);
        let bound = self.limits.slots_bound().unwrap_or(u64::from(u32::MAX));
        if used > bound {
            return Err(err(
                "limit",
                format!("{used} counters and timers, limit {bound}"),
            ));
        }
        Ok(())
    }

    fn named(&self, name: &str, what: &str) -> Result<Table, Error> {
        if let Some(t) = self.parsed.borrow().get(name) {
            return Ok(t.clone());
        }
        let Some((&key, &raw)) = self.tables.get_key_value(name) else {
            return Err(err("table", name.to_owned()));
        };
        let t = segments(raw, what, &self.limits)?;
        self.parsed.borrow_mut().insert(key, t.clone());
        Ok(t)
    }
}

/// Reads a list of segments; its count is checked before anything is made of it.
fn segments(t: &Json, what: &str, limits: &SizeLimits) -> Result<Table, Error> {
    let Json::Arr(list) = t else {
        return Err(err("type", format!("{what}: segments")));
    };
    if list.is_empty() {
        return Err(err("type", format!("{what}: no segments")));
    }
    over(list.len(), limits.max_segments, "segments")?;
    let mut acc = 0u64;
    let (mut low, mut high) = (u64::MAX, 0);
    let mut segs = Vec::with_capacity(list.len());
    for s in list {
        let Json::Arr(s) = s else {
            return Err(err("type", format!("{what}: segment")));
        };
        let [w, lo, hi] = s.as_slice() else {
            return Err(err("type", format!("{what}: segment")));
        };
        let (Some(w), Some(lo), Some(hi)) = (int(w), int(lo), int(hi)) else {
            return Err(err("type", format!("{what}: segment")));
        };
        if !(0..=(1 << 32) - 1).contains(&w) || lo < 0 || lo > hi || hi > i128::from(P53) {
            return Err(err("range", format!("{what}: segment")));
        }
        acc += w as u64;
        low = low.min(lo as u64);
        high = high.max(hi as u64);
        segs.push(Segment {
            acc,
            lo: lo as u64,
            hi: hi as u64,
        });
    }
    if acc == 0 {
        return Err(err("range", format!("{what}: total weight 0")));
    }
    Ok(Table {
        segments: segs.into(),
        lo: low,
        hi: high,
    })
}

/// Reads a value of `fam`; `scopes` are those this place allows.
pub(crate) fn parse_value(
    x: &Json,
    fam: Family,
    reader: &Reader<'_>,
    scopes: &[Scope],
    what: &str,
) -> Result<Value, Error> {
    let (min, max) = fam.range();
    match x {
        Json::Int(v) => {
            if *v < i128::from(min) || *v > i128::from(max) {
                return Err(err("range", format!("{what}: {v}")));
            }
            Ok(Value::constant(*v as u64))
        }
        Json::Obj(members) => {
            if let Some((k, _)) = members.iter().find(|(k, _)| k != "t" && k != "scope") {
                return Err(err("unknown_member", format!("{what}.{k}")));
            }
            let t = x
                .get("t")
                .ok_or_else(|| err("type", format!("{what}: t")))?;
            let scope = match x.get("scope") {
                None => Scope::Each,
                Some(Json::Str(s)) if s == "each" => Scope::Each,
                Some(Json::Str(s)) if s == "pipe" => Scope::Pipe,
                Some(Json::Str(s)) if s == "shared" => Scope::Shared,
                Some(Json::Str(s)) if s == "session" => Scope::Session,
                Some(_) => return Err(err("type", format!("{what}: scope"))),
            };
            if !scopes.contains(&scope) {
                return Err(err("scope", format!("{what}: scope")));
            }
            let t = match t {
                Json::Str(name) => reader.named(name, what)?,
                other => segments(other, what, &reader.limits)?,
            };
            if t.lo < min || t.hi > max {
                return Err(err("range", format!("{what}: outside its family")));
            }
            Ok(Value {
                segments: t.segments,
                low: t.lo,
                scope,
                slot: 0,
            })
        }
        _ => Err(err("type", what.to_owned())),
    }
}
