//! Local limits and a candidate's budget, read from JSON.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use zmux::shaping::{
    Account, Budget, Limits, MAX_ACCOUNT_INITIAL, MAX_ACCOUNT_RATE, ShapingBudget,
};

use crate::error::{Error, err};
use crate::json::{Json, parse};
use crate::value::{BUDGET_SCOPES, Family, Reader, Sampler, Value, int, parse_value};

const TIME: i128 = 1_000_000_000_000_000;

fn known(x: &Json, allowed: &[&str], what: &str) -> Result<(), Error> {
    let Json::Obj(m) = x else {
        return Err(err("type", what.to_owned()));
    };
    if let Some((k, _)) = m.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
        return Err(err("unknown_member", format!("{what}.{k}")));
    }
    Ok(())
}

/// A candidate's parsed budget.
#[derive(Debug, Clone, Default)]
pub(crate) struct BudgetDef {
    /// `initial`, `per_mb`, `per_sec`; `None`: no `wire` member.
    wire: Option<[Option<Value>; 3]>,
    pub(crate) max_delay: Option<Duration>,
}

const WIRE: [(&str, Family); 3] = [
    ("initial", Family::Counter),
    ("per_mb", Family::Rate),
    ("per_sec", Family::Rate),
];

pub(crate) fn parse_budget(x: &Json, reader: &Reader<'_>) -> Result<BudgetDef, Error> {
    known(x, &["wire", "max_delay"], "budget")?;
    let mut b = BudgetDef::default();
    if let Some(w) = x.get("wire") {
        known(w, &["initial", "per_mb", "per_sec"], "wire")?;
        let mut vals = [None, None, None];
        for (slot, (k, fam)) in vals.iter_mut().zip(WIRE) {
            if let Some(v) = w.get(k) {
                *slot = Some(parse_value(v, fam, reader, BUDGET_SCOPES, k)?);
            }
        }
        b.wire = Some(vals);
    }
    if let Some(v) = x.get("max_delay") {
        let n = int(v).ok_or_else(|| err("type", "max_delay"))?;
        if !(1..=TIME).contains(&n) {
            return Err(err("range", format!("max_delay: {n}")));
        }
        b.max_delay = Some(Duration::from_micros(n as u64));
    }
    Ok(b)
}

impl BudgetDef {
    /// One session's budget: `initial`, `per_mb`, `per_sec` in order. A wire of zeros
    /// allows no injection.
    fn draw(&self, s: &mut Sampler) -> Budget {
        let mut wire = Account::default();
        let mut none = false;
        if let Some([a, b, c]) = &self.wire {
            let mut d = |v: &Option<Value>| v.as_ref().map_or(0, |v| s.draw(v));
            let (initial, per_mb, per_sec) = (d(a), d(b), d(c));
            wire = Account::new(initial, per_mb, per_sec);
            none = wire.is_unset();
        }
        Budget::new(wire, self.max_delay, none)
    }

    /// The source of budgets of a compiled candidate, drawing from `s`.
    pub(crate) fn source(self, s: Sampler) -> ShapingBudget {
        let s = Arc::new(Mutex::new(s));
        ShapingBudget::new(move || {
            let mut s = s.lock().unwrap_or_else(|p| p.into_inner());
            self.draw(&mut s)
        })
    }
}

fn switch(x: &Json, key: &str) -> Result<bool, Error> {
    match x.get(key) {
        None => Ok(false),
        Some(Json::Bool(b)) => Ok(*b),
        Some(_) => Err(err("type", key.to_owned())),
    }
}

/// Reads local limits: a JSON object with `wire` (integer `initial` in \[0, 2^53\], `per_mb`
/// and `per_sec` in \[0, 2^43\]), `max_delay` (microseconds up to 10^15, 0 the default and a
/// negative number no bound) and the switches `no_padding`, `no_pause` and `no_injection`.
/// A wire of zeros means `no_injection`. An absent or `null` member is its default.
pub fn parse_limits(json: &[u8]) -> Result<Limits, Error> {
    let x = parse(json)?;
    known(
        &x,
        &[
            "wire",
            "max_delay",
            "no_padding",
            "no_pause",
            "no_injection",
        ],
        "limits",
    )?;
    let mut l = Limits::default();
    l.no_padding = switch(&x, "no_padding")?;
    l.no_pause = switch(&x, "no_pause")?;
    l.no_injection = switch(&x, "no_injection")?;
    if let Some(w) = x.get("wire") {
        known(w, &["initial", "per_mb", "per_sec"], "wire")?;
        let read = |k: &str, max: u64| -> Result<u64, Error> {
            let Some(v) = w.get(k) else {
                return Ok(0);
            };
            let n = int(v).ok_or_else(|| err("type", k.to_owned()))?;
            if n < 0 || n > i128::from(max) {
                return Err(err("range", format!("{k}: {n}")));
            }
            Ok(n as u64)
        };
        l.wire = Account::new(
            read("initial", MAX_ACCOUNT_INITIAL)?,
            read("per_mb", MAX_ACCOUNT_RATE)?,
            read("per_sec", MAX_ACCOUNT_RATE)?,
        );
        l.no_injection |= l.wire.is_unset();
    }
    if let Some(v) = x.get("max_delay") {
        let n = int(v).ok_or_else(|| err("type", "max_delay"))?;
        if n > TIME {
            return Err(err("range", format!("max_delay: {n}")));
        }
        l.max_delay = match n {
            0 => Limits::default().max_delay,
            n if n < 0 => None,
            n => Some(Duration::from_micros(n as u64)),
        };
    }
    Ok(l)
}
