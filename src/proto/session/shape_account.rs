//! The integer arithmetic of shaping: the wire account and the token bucket of a gate.

use super::shaping::{Account, MIN_MAX_LEN};

/// What `d` units earn at `per` per 10^6 units; `rem` keeps the remainder. `per` is at most
/// 2^43, so the remainder's product stays below 2^63.
fn refill(d: u64, per: u64, rem: &mut u64) -> u64 {
    let (q, r) = (d / 1_000_000, d % 1_000_000);
    let x = r * per + *rem;
    *rem = x % 1_000_000;
    q.saturating_mul(per).saturating_add(x / 1_000_000)
}

/// The session's allowance for cover and the meter of committed overhead.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct WireAccount {
    params: Option<Account>,
    initialized: bool,
    level: u64,
    remainder: u64,
    pub(super) last_us: u64,
    pub(super) spent: u64,
}

impl WireAccount {
    pub(super) fn accrue(&mut self, us: u64, confirmed: u64) {
        let elapsed = us.saturating_sub(self.last_us);
        self.last_us = self.last_us.max(us);
        let Some(p) = self.params else { return };
        let room = p.ceiling - self.level;
        if room == 0 {
            return;
        }
        let scale = 1_000_000;
        let refill = u128::from(confirmed) * u128::from(p.per_mb)
            + u128::from(elapsed) * u128::from(p.per_sec)
            + u128::from(self.remainder);
        if refill >= u128::from(room) * scale {
            self.level = p.ceiling;
            self.remainder = 0;
        } else {
            self.level += u64::try_from(refill / scale).expect("refill bounded by ceiling");
            self.remainder = u64::try_from(refill % scale).expect("fraction bounded by scale");
        }
    }

    pub(super) const fn left(&self) -> u64 {
        if self.params.is_some() { self.level } else { 0 }
    }

    pub(super) const fn spend(&mut self, cost: u64) {
        self.spent = self.spent.saturating_add(cost);
    }

    pub(super) fn charge(&mut self, us: u64, cost: u64) -> bool {
        self.accrue(us, 0);
        if cost == 0 || cost > self.left() {
            return false;
        }
        self.level -= cost;
        self.spend(cost);
        true
    }

    pub(super) fn set(&mut self, us: u64, params: Option<Account>) {
        self.accrue(us, 0);
        match params {
            Some(p) => {
                if !self.initialized && p.ceiling > 0 {
                    self.level = p.initial;
                    self.initialized = true;
                }
                if self.level >= p.ceiling {
                    self.level = p.ceiling;
                    self.remainder = 0;
                }
            }
            None => self.remainder = 0,
        }
        self.params = params;
    }
}

/// The integer gate of a pipe: bytes, in microseconds of the session clock.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct TokenBucket {
    pub(super) rate: u64,
    rem: u64,
    filled: u64,
    pub(super) burst: i64,
    pub(super) tokens: i64,
}

impl TokenBucket {
    pub(super) const fn reset(&mut self, us: u64) {
        self.tokens = self.burst;
        self.rem = 0;
        self.filled = us;
    }

    pub(super) fn fill(&mut self, us: u64) {
        if us <= self.filled {
            return;
        }
        let add = refill(us - self.filled, self.rate, &mut self.rem);
        self.filled = us;
        let level = i128::from(self.tokens) + i128::from(add);
        if level >= i128::from(self.burst) {
            self.tokens = self.burst;
            self.rem = 0;
        } else {
            self.tokens = i64::try_from(level).unwrap_or(i64::MIN);
        }
    }

    #[allow(
        clippy::cast_possible_wrap,
        reason = "rate x 1000 / 10^6 is below 2^54, MIN_MAX_LEN a small constant"
    )]
    pub(super) fn quantum(&self) -> i64 {
        ((self.rate.saturating_mul(1000) / 1_000_000) as i64)
            .min(self.burst)
            .max(MIN_MAX_LEN as i64)
    }

    pub(super) fn held(&self) -> bool {
        self.tokens < self.quantum()
    }

    /// The microsecond a held bucket reaches its quantum; `None` beyond any clock.
    pub(super) fn release(&self) -> Option<u64> {
        let need = u128::from((self.quantum() - self.tokens).cast_unsigned());
        let wait = (need * 1_000_000 - u128::from(self.rem)).div_ceil(u128::from(self.rate));
        u64::try_from(wait).ok()?.checked_add(self.filled)
    }
}

#[cfg(test)]
#[path = "../../../shaping/tests/common/fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::super::shaping::{burst_floor, wire_ppm};
    use super::*;
    use serde_json::Value as J;
    use std::path::Path;

    fn vectors() -> Option<J> {
        let dir = std::env::var("ZMUX_SHAPING_VECTORS")
            .unwrap_or_else(|_| format!("{}/testdata/shaping", env!("CARGO_MANIFEST_DIR")));
        let bytes = fixture::read_fixture(&Path::new(&dir).join("machine.json"))?;
        Some(serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn account_vectors() {
        let Some(vectors) = vectors() else { return };
        let account = |data: &J| {
            data.as_object().map(|_| {
                Account::new(
                    data["ceiling"].as_u64().unwrap(),
                    data["initial"].as_u64().unwrap_or(0),
                    data["per_mb"].as_u64().unwrap_or(0),
                    data["per_sec"].as_u64().unwrap_or(0),
                )
            })
        };
        for case in vectors["account"].as_array().unwrap() {
            let mut state = WireAccount::default();
            state.set(0, account(&case["account"]));
            let mut earned = 0;
            for step in case["steps"].as_array().unwrap() {
                let now = step["now"].as_u64().unwrap();
                let total = step["earn"].as_u64().unwrap();
                state.accrue(now, total - earned);
                earned = total;
                if step["op"] == "set" {
                    state.set(now, account(&step["account"]));
                } else {
                    let accepted = state.charge(now, step["n"].as_u64().unwrap());
                    assert_eq!(accepted, step["granted"] == true, "{case} {step}");
                }
                assert_eq!(
                    state.left(),
                    step["left"].as_u64().unwrap(),
                    "{case} {step}"
                );
                assert_eq!(
                    state.spent,
                    step["spent"].as_u64().unwrap(),
                    "{case} {step}"
                );
            }
        }
    }

    #[test]
    fn gate_vectors() {
        let Some(d) = vectors() else { return };
        for c in d["gate"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let mut b = TokenBucket {
                rate: c["rate"].as_u64().unwrap(),
                burst: c["burst"].as_i64().unwrap(),
                ..TokenBucket::default()
            };
            b.reset(0);
            if let Some(recovery) = c["recovery"].as_object() {
                b.tokens = recovery["min_tokens"].as_i64().unwrap();
                let wait = if b.rate != 0 && b.held() {
                    b.release().unwrap()
                } else {
                    0
                };
                assert_eq!(wait, recovery["wait_us"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    wait > recovery["max_added_delay"].as_u64().unwrap(),
                    recovery.contains_key("error"),
                    "{name}",
                );
                continue;
            }
            for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
                b.fill(s["now"].as_u64().unwrap());
                assert_eq!(b.held(), s["held"] == true, "{name} {i}");
                assert_eq!(b.tokens, s["tokens"].as_i64().unwrap(), "{name} {i}");
                let release = if b.held() { b.release() } else { None };
                assert_eq!(release, s["release"].as_u64(), "{name} {i}");
                b.tokens -= s["take"].as_i64().unwrap_or(0);
            }
        }
    }

    #[test]
    fn burst_floor_and_ppm_vectors() {
        let Some(d) = vectors() else { return };
        for c in d["burst_floor"].as_array().unwrap() {
            let (got, clamped) = burst_floor(
                c["burst"].as_u64().unwrap(),
                c["record_max"].as_u64().unwrap(),
            );
            assert_eq!(got, c["want"].as_u64().unwrap(), "{c}");
            assert_eq!(clamped, c["clamped"] == true, "{c}");
        }
        for c in d["wire_ppm"].as_array().unwrap() {
            let got = wire_ppm(c["s"].as_u64().unwrap(), c["e"].as_u64().unwrap());
            assert_eq!(got, c["want"].as_u64().unwrap(), "{c}");
        }
    }
}
