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

/// The session's allowance for spontaneous actions and the meter of all added wire bytes.
/// Its level never goes below zero.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct WireAccount {
    p: Account,
    on: bool,
    /// At most `i64::MAX`.
    level: u64,
    rem_mb: u64,
    rem_s: u64,
    pub(super) last_us: u64,
    earn: u64,
    pub(super) spent: u64,
}

impl WireAccount {
    pub(super) fn accrue(&mut self, us: u64, earn: u64) {
        let us = us.max(self.last_us);
        let earn = earn.max(self.earn);
        if self.on {
            let add = refill(earn - self.earn, self.p.per_mb, &mut self.rem_mb)
                .saturating_add(refill(us - self.last_us, self.p.per_sec, &mut self.rem_s));
            self.level = self.level.saturating_add(add).min(i64::MAX as u64);
        }
        self.last_us = us;
        self.earn = earn;
    }

    pub(super) const fn left(&self) -> u64 {
        if self.on { self.level } else { u64::MAX }
    }

    /// Meters an accompanying action; it never fails and takes nothing.
    pub(super) const fn spend(&mut self, c: u64) {
        self.spent = self.spent.saturating_add(c);
    }

    /// Takes `c` for a spontaneous action if the account has it.
    pub(super) fn charge(&mut self, us: u64, earn: u64, c: u64) -> bool {
        self.accrue(us, earn);
        if self.on {
            if c > self.level {
                return false;
            }
            self.level -= c;
        }
        self.spend(c);
        true
    }

    /// Replaces the parameters; what was spent stays, and the level moves by the
    /// difference of the initial amounts.
    pub(super) fn set(&mut self, us: u64, earn: u64, p: Account) {
        self.accrue(us, earn);
        if p.is_unset() {
            self.on = false;
            self.level = 0;
            self.rem_mb = 0;
            self.rem_s = 0;
        } else if !self.on {
            self.on = true;
            self.level = p.initial;
            self.rem_mb = 0;
            self.rem_s = 0;
        } else if p.initial >= self.p.initial {
            self.level = self
                .level
                .saturating_add(p.initial - self.p.initial)
                .min(i64::MAX as u64);
        } else {
            self.level = self.level.saturating_sub(self.p.initial - p.initial);
        }
        self.p = p;
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
            self.tokens = level as i64;
        }
    }

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
        let need = (self.quantum() - self.tokens) as u128;
        let wait = (need * 1_000_000 - u128::from(self.rem)).div_ceil(u128::from(self.rate));
        u64::try_from(wait).ok()?.checked_add(self.filled)
    }
}

#[cfg(test)]
mod tests {
    use super::super::shaping::{Budget, Limits, burst_floor, rate_floor, wire_ppm};
    use super::*;
    use serde_json::Value as J;
    use std::time::Duration;

    fn vectors() -> J {
        let dir = std::env::var("ZMUX_SHAPING_VECTORS")
            .unwrap_or_else(|_| format!("{}/testdata/shaping", env!("CARGO_MANIFEST_DIR")));
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/budget.json")).unwrap())
            .unwrap()
    }

    fn acct(v: &J) -> Account {
        let f = |k: &str| v[k].as_u64().unwrap_or(0);
        Account::new(f("initial"), f("per_mb"), f("per_sec"))
    }

    #[test]
    fn account_vectors() {
        for c in vectors()["account"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let mut a = WireAccount::default();
            a.set(0, 0, acct(&c["account"]));
            for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
                let (now, earn) = (s["now"].as_u64().unwrap(), s["earn"].as_u64().unwrap());
                let n = s["n"].as_u64().unwrap_or(0);
                match s["op"].as_str().unwrap() {
                    "spend" => a.spend(n),
                    "charge" => {
                        assert_eq!(a.charge(now, earn, n), s["granted"] == true, "{name} {i}");
                    }
                    "set" => a.set(now, earn, acct(&s["account"])),
                    o => panic!("{o}"),
                }
                a.accrue(now, earn);
                assert_eq!(a.left(), s["left"].as_u64().unwrap(), "{name} {i}");
                assert_eq!(a.spent, s["spent"].as_u64().unwrap(), "{name} {i}");
                let level = a.on.then_some(a.level);
                assert_eq!(level, s["level"].as_u64(), "{name} {i}");
            }
        }
    }

    #[test]
    fn gate_vectors() {
        for c in vectors()["gate"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let mut b = TokenBucket {
                rate: c["rate"].as_u64().unwrap(),
                burst: c["burst"].as_i64().unwrap(),
                ..TokenBucket::default()
            };
            b.reset(0);
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

    /// A side of a vector: its `max_delay` of 0 is the default (the local
    /// limits') or none (the configuration's), a negative one no bound.
    fn side(v: &J, default: Option<Duration>) -> (Account, Option<Duration>) {
        let d = match v["max_delay"].as_i64().unwrap_or(0) {
            0 => default,
            d if d < 0 => None,
            d => Some(Duration::from_micros(d as u64)),
        };
        (acct(&v["wire"]), d)
    }

    #[test]
    fn merge_vectors() {
        for c in vectors()["merge"].as_array().unwrap() {
            let (wire, max_delay) = side(&c["local"], Limits::default().max_delay);
            let l = Limits {
                wire,
                max_delay,
                ..Limits::default()
            };
            let (wire, max_delay) = side(&c["config"], None);
            let set = !l.wire.is_unset() && !wire.is_unset();
            let e = l.under(&Budget::new(wire, max_delay, false));
            assert_eq!(e.no_injection, set && e.wire.is_unset(), "{c}");
            assert_eq!(e.wire, acct(&c["want"]["wire"]), "{c}");
            let want = c["want"]["max_delay"].as_i64().unwrap();
            let got = e.max_delay.map_or(-1, |d| d.as_micros() as i64);
            assert_eq!(got, want, "{c}");
        }
    }

    #[test]
    fn rate_floor_and_ppm_vectors() {
        let d = vectors();
        for c in d["rate_floor"].as_array().unwrap() {
            let md = u64::try_from(c["max_delay"].as_i64().unwrap()).ok();
            let (got, clamped) = rate_floor(c["rate"].as_u64().unwrap(), md);
            assert_eq!(got, c["want"].as_u64().unwrap(), "{c}");
            assert_eq!(clamped, c["clamped"] == true, "{c}");
        }
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
