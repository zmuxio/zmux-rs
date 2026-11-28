//! Local limits and a candidate's budget, parsed from JSON.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use zmux::shaping::{
    Account, Budget, Limits, MAX_ACCOUNT_INITIAL, MAX_ACCOUNT_RATE, ProfileLimits, ShapingBudget,
};

use crate::error::{Error, err};
use crate::json::{Json, known, parse};
use crate::value::{BUDGET_SCOPES, Family, Reader, Sampler, Value, int, parse_value, to_u64};

const TIME: u64 = 1_000_000_000_000_000;
const ACCOUNT: [(&str, Family, u64); 4] = [
    ("ceiling", Family::Counter, MAX_ACCOUNT_INITIAL),
    ("initial", Family::Counter, MAX_ACCOUNT_INITIAL),
    ("per_mb", Family::Rate, MAX_ACCOUNT_RATE),
    ("per_sec", Family::Rate, MAX_ACCOUNT_RATE),
];

/// A candidate's parsed budget.
#[derive(Debug, Clone, Default)]
pub(crate) struct BudgetDef {
    wire: Option<[Value; 4]>,
    pub(crate) profile: Option<ProfileLimits>,
    no_injection: bool,
}

fn account<T>(
    wire: &Json,
    parse: impl Fn(&Json, &str, Family, u64) -> Result<T, Error>,
    default: impl Fn() -> T,
) -> Result<[T; 4], Error> {
    known(wire, &["ceiling", "initial", "per_mb", "per_sec"], "wire")?;
    member(wire, "ceiling")?;
    let mut fields = ACCOUNT.into_iter().map(|(k, family, max)| {
        wire.get(k)
            .map_or_else(|| Ok(default()), |v| parse(v, k, family, max))
    });
    Ok([
        fields.next().expect("ceiling")?,
        fields.next().expect("initial")?,
        fields.next().expect("per_mb")?,
        fields.next().expect("per_sec")?,
    ])
}

fn member<'a>(x: &'a Json, k: &str) -> Result<&'a Json, Error> {
    x.get(k).ok_or_else(|| err("type", format!("missing {k}")))
}

fn number(x: &Json, key: &str, max: u64) -> Result<u64, Error> {
    let n = int(x).ok_or_else(|| err("type", key))?;
    if !(0..=i128::from(max)).contains(&n) {
        return Err(err("range", format!("{key}: {n}")));
    }
    Ok(to_u64(n))
}

fn profile(x: &Json) -> Result<ProfileLimits, Error> {
    known(
        x,
        &[
            "window_seconds",
            "extra_bytes_ppm",
            "floor_bytes",
            "max_added_delay",
        ],
        "profile",
    )?;
    let required = |key| member(x, key);
    let window = number(
        required("window_seconds")?,
        "window_seconds",
        u64::from(u32::MAX),
    )?;
    if window == 0 {
        return Err(err("range", "window_seconds"));
    }
    let floor = number(required("floor_bytes")?, "floor_bytes", MAX_ACCOUNT_INITIAL)?;
    let ppm = number(required("extra_bytes_ppm")?, "extra_bytes_ppm", 1_000_000)?;
    let delay = number(required("max_added_delay")?, "max_added_delay", TIME)?;
    Ok(ProfileLimits::new(
        u32::try_from(window).expect("window"),
        u32::try_from(ppm).expect("ppm"),
        floor,
        Duration::from_micros(delay),
    ))
}

pub(crate) fn parse_budget(x: &Json, reader: &Reader<'_>) -> Result<BudgetDef, Error> {
    known(x, &["wire", "profile", "no_injection"], "budget")?;
    let wire = x
        .get("wire")
        .map(|w| {
            let values = account(
                w,
                |v, k, family, _| parse_value(v, family, reader, BUDGET_SCOPES, k),
                || Value::constant(0),
            )?;
            if values[1].upper() > values[0].lower() {
                return Err(err("range", "sampled initial can exceed ceiling"));
            }
            Ok(values)
        })
        .transpose()?;
    Ok(BudgetDef {
        wire,
        profile: x.get("profile").map(profile).transpose()?,
        no_injection: switch(x, "no_injection")?,
    })
}

impl BudgetDef {
    fn draw(&self, s: &mut Sampler) -> Budget {
        let wire = self.wire.as_ref().map(|fields| {
            let [ceiling, initial, per_mb, per_sec] = std::array::from_fn(|i| s.draw(&fields[i]));
            Account::new(ceiling, initial, per_mb, per_sec)
        });
        Budget::new(wire, self.profile, self.no_injection)
    }

    pub(crate) fn source(self, s: Sampler) -> ShapingBudget {
        let s = Arc::new(Mutex::new(s));
        ShapingBudget::new(move || {
            let mut s = s.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            self.draw(&mut s)
        })
    }
}

pub(crate) fn switch(x: &Json, key: &str) -> Result<bool, Error> {
    match x.get(key) {
        None => Ok(false),
        Some(Json::Bool(b)) => Ok(*b),
        Some(_) => Err(err("type", key)),
    }
}

/// Loads local shaping limits from a development profile.
///
/// # Errors
///
/// Returns an error for malformed, unsupported or out-of-range fields.
pub fn parse_limits(json: &[u8]) -> Result<Limits, Error> {
    let x = parse(json)?;
    known(
        &x,
        &["wire", "profile", "no_padding", "no_pause", "no_injection"],
        "limits",
    )?;
    let mut limits = Limits::default();
    limits.no_padding = switch(&x, "no_padding")?;
    limits.no_pause = switch(&x, "no_pause")?;
    limits.no_injection = switch(&x, "no_injection")?;
    limits.profile = x.get("profile").map(profile).transpose()?;
    if let Some(wire) = x.get("wire") {
        let [ceiling, initial, per_mb, per_sec] =
            account(wire, |v, k, _, max| number(v, k, max), || 0)?;
        if initial > ceiling {
            return Err(err("range", "initial exceeds ceiling"));
        }
        limits.wire = Some(Account::new(ceiling, initial, per_mb, per_sec));
    }
    Ok(limits)
}
