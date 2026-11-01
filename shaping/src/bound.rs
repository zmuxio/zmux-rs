//! The families of values and the derivation of their bounds.

use crate::def::{Dist, DistKind, Error, Scope, Value, err};
use crate::random::MAX_COUNT;

/// The largest length, in bytes.
const MAX_LEN: f64 = 2_147_483_647.0;
/// The largest time, in seconds.
const MAX_SECS: f64 = 1e9;

/// What a value stands for, which bounds every number it declares
/// (constants, range ends, bounds, points, uniform and loguniform
/// parameters, those of mixture components included) and its draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// Bytes: record lengths and paddings, injection lengths, bursts.
    Length,
    /// Seconds of a definition.
    Seconds,
    /// Bytes per second: 0 (no limit) or at least 1.
    Rate,
    /// A counter operand.
    Counter,
    /// A probability: every draw in \[0, 1\].
    Prob,
    /// Any finite number: weights and conditions.
    Any,
    /// Pool members wanted: every draw at least 1.
    PoolCount,
    /// Seconds before a pool's next dial.
    PoolSeconds,
    /// A pool's idle-probe interval, in seconds; decisions are bounded by
    /// the pool.
    PoolProbe,
    /// A time threshold of a retire rule, in seconds.
    RuleSeconds,
    /// A count threshold of a retire rule.
    RuleCount,
}

impl Family {
    /// The least and greatest number declared, `None`: unbounded.
    fn range(self) -> (Option<f64>, Option<f64>) {
        use Family as F;
        match self {
            F::Length => (Some(0.0), Some(MAX_LEN)),
            F::Seconds | F::PoolSeconds | F::RuleSeconds => (Some(0.0), Some(MAX_SECS)),
            F::Rate | F::Counter | F::RuleCount => (Some(0.0), Some(MAX_COUNT)),
            F::Prob => (Some(0.0), Some(1.0)),
            F::Any => (None, None),
            F::PoolCount => (Some(1.0), Some(MAX_COUNT)),
            F::PoolProbe => (Some(0.0), None),
        }
    }

    /// Whether values of scope `pipe` are allowed.
    fn pipe_scope(self) -> bool {
        !matches!(
            self,
            Family::PoolCount | Family::PoolSeconds | Family::PoolProbe
        )
    }
}

impl Value {
    /// Validates `v` as a value of `fam`; errors name `what`.
    pub(crate) fn check(&self, fam: Family, what: &str) -> Result<(), Error> {
        let at = |e: Error| err(format!("{what}: {e}"));
        self.validate().map_err(at)?;
        self.declared(fam).map_err(at)?;
        if fam == Family::Any {
            return Ok(());
        }
        let (lo, _) = fam.range();
        let floor = lo.unwrap_or(f64::NEG_INFINITY);
        let lb = self.lower();
        if lb < floor {
            return Err(at(err(if floor == 0.0 {
                "negative: may draw below 0 (set a min of at least 0)".to_owned()
            } else {
                format!("may draw below {floor} (set a min of at least {floor})")
            })));
        }
        if fam == Family::Prob && self.upper() > 1.0 {
            return Err(at(err("may draw above 1 (set a max of at most 1)")));
        }
        if fam == Family::Rate && !self.rate_ok() {
            return Err(at(err(
                "may draw in (0, 1) (0 is no limit; otherwise at least 1)",
            )));
        }
        Ok(())
    }

    /// Bounds the numbers the value declares, and its scope, by `fam`.
    fn declared(&self, fam: Family) -> Result<(), Error> {
        if self.scope == Scope::Pipe && !fam.pipe_scope() {
            return Err(err("scope pipe only in retire"));
        }
        let (lo, hi) = fam.range();
        let one = |x: f64| -> Result<(), Error> {
            if lo.is_some_and(|lo| x < lo) {
                let lo = lo.unwrap_or_default();
                return Err(err(if lo == 0.0 {
                    format!("negative ({x})")
                } else {
                    format!("{x} below {lo}")
                }));
            }
            if let Some(hi) = hi.filter(|hi| x > *hi) {
                return Err(err(format!("{x} above the maximum {hi}")));
            }
            if fam == Family::Rate && x > 0.0 && x < 1.0 {
                return Err(err(format!("rate {x} in (0, 1)")));
            }
            Ok(())
        };
        let d = self.dist.as_deref();
        let params = d
            .filter(|d| matches!(d.kind, DistKind::Uniform | DistKind::LogUniform))
            .map(|d| d.params.as_slice())
            .unwrap_or_default();
        self.constant
            .iter()
            .chain(self.range.iter().flatten())
            .chain(&self.min)
            .chain(&self.max)
            .chain(d.map(|d| d.points.as_slice()).unwrap_or_default())
            .chain(params)
            .try_for_each(|x| one(*x))?;
        for c in d.map(|d| d.of.as_slice()).unwrap_or_default() {
            c.declared(fam)?;
        }
        Ok(())
    }

    fn bounded(&self, x: f64) -> f64 {
        let x = self.min.map_or(x, |m| x.max(m));
        self.max.map_or(x, |m| x.min(m))
    }

    /// The least value a draw can take; `-inf` when a distribution can
    /// draw any low value. Points and components of weight 0 count.
    pub(crate) fn lower(&self) -> f64 {
        self.bounded(if let Some(c) = self.constant {
            c
        } else if let Some(r) = &self.range {
            r[0]
        } else {
            self.dist.as_ref().map_or(0.0, |d| d.lower())
        })
    }

    /// The greatest value a draw can take; `inf` when unbounded.
    pub(crate) fn upper(&self) -> f64 {
        self.bounded(if let Some(c) = self.constant {
            c
        } else if let Some(r) = &self.range {
            r[1]
        } else {
            self.dist.as_ref().map_or(f64::INFINITY, |d| d.upper())
        })
    }

    /// For a rate: no draw in (0, 1).
    fn rate_ok(&self) -> bool {
        if self.constant.is_some() {
            let x = self.lower();
            return x == 0.0 || x >= 1.0;
        }
        if let Some(d) = self.dist.as_deref()
            && d.kind == DistKind::Mixture
            && self.min.is_none()
            && self.max.is_none()
        {
            return d.of.iter().all(Value::rate_ok);
        }
        self.lower() >= 1.0
    }
}

impl Dist {
    fn lower(&self) -> f64 {
        use DistKind as K;
        match self.kind {
            K::Uniform | K::LogUniform | K::Pareto => self.params[0],
            K::Geometric => 1.0,
            K::Normal => f64::NEG_INFINITY,
            K::Empirical | K::Bag => self.points.iter().copied().fold(f64::INFINITY, f64::min),
            K::Mixture => self
                .of
                .iter()
                .map(Value::lower)
                .fold(f64::INFINITY, f64::min),
            _ => 0.0,
        }
    }

    fn upper(&self) -> f64 {
        use DistKind as K;
        match self.kind {
            K::Uniform | K::LogUniform => self.params[1],
            K::Beta => 1.0,
            K::Binomial => self.params[0],
            K::Geometric if self.params[0] == 1.0 => 1.0,
            K::Empirical | K::Bag => self
                .points
                .iter()
                .copied()
                .fold(f64::NEG_INFINITY, f64::max),
            K::Mixture => self
                .of
                .iter()
                .map(Value::upper)
                .fold(f64::NEG_INFINITY, f64::max),
            _ => f64::INFINITY,
        }
    }
}
