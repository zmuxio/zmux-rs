//! Session limits read from JSON.

use std::time::Duration;

use serde::Deserialize;

use crate::def::{Error, err};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    max_padding_bytes: Option<u64>,
    max_padding_ratio: Option<f64>,
    max_injected: Option<u64>,
    max_pause_total: Option<f64>,
    max_delay: Option<f64>,
}

fn count(x: Option<u64>, what: &str) -> Result<Option<u64>, Error> {
    match x {
        Some(n) if n > 1 << 53 => Err(err(format!(
            "session limits {what}: {n} above the maximum 2^53"
        ))),
        x => Ok(x),
    }
}

fn secs(x: Option<f64>, what: &str) -> Result<Option<Duration>, Error> {
    x.map(|s| {
        if s < 0.0 {
            Err(err(format!("session limits {what}: negative ({s})")))
        } else if s > 1e9 {
            Err(err(format!(
                "session limits {what}: {s} above the maximum 1e9"
            )))
        } else {
            Ok(Duration::from_secs_f64(s))
        }
    })
    .transpose()
}

/// Reads session limits: a JSON object with the optional members
/// `max_padding_bytes`, `max_injected` (integers in \[0, 2^53\]),
/// `max_padding_ratio` (in \[0, 1\]), `max_pause_total` and `max_delay`
/// (seconds in \[0, 1e9\]). An absent or `null` member is no limit; 0
/// allows none. Parsing is strict: unknown or duplicate members, integers
/// written with a fraction or exponent and numbers outside binary64 are
/// errors.
pub fn session_limits(json: &[u8]) -> Result<zmux::shaping::Limits, Error> {
    let s: Spec = crate::json::from_slice("session limits", json)?;
    let mut l = zmux::shaping::Limits::default();
    l.max_padding_bytes = count(s.max_padding_bytes, "max_padding_bytes")?;
    l.max_injected = count(s.max_injected, "max_injected")?;
    if let Some(r) = s.max_padding_ratio.filter(|r| !(0.0..=1.0).contains(r)) {
        return Err(err(format!(
            "session limits max_padding_ratio: {r} outside [0, 1]"
        )));
    }
    l.max_padding_ratio = s.max_padding_ratio;
    l.max_pause_total = secs(s.max_pause_total, "max_pause_total")?;
    l.max_delay = secs(s.max_delay, "max_delay")?;
    Ok(l)
}
