//! Values compiled to numbers, and their sampling.

use crate::def::{DistKind, Scope, Value};
use crate::random::Rand;

/// A compiled `Value` with the indices of its components.
pub(crate) struct Num {
    pub(crate) v: Value,
    pub(crate) of: Vec<usize>,
}

/// Appends `v` and its components to `nums`; returns the index of `v`.
pub(crate) fn compile(nums: &mut Vec<Num>, v: &Value) -> usize {
    let of = v
        .dist
        .as_ref()
        .map(|d| d.of.iter().map(|c| compile(nums, c)).collect())
        .unwrap_or_default();
    nums.push(Num { v: v.clone(), of });
    nums.len() - 1
}

/// Where sampled values are kept, per scope.
pub(crate) trait Keep {
    /// The kept value of number `i`, if any.
    fn kept(&mut self, i: usize, scope: Scope) -> Option<f64>;
    /// Keeps `x` as the value of number `i`, if its scope keeps values.
    fn keep(&mut self, i: usize, scope: Scope, x: f64);
}

/// Draws numbers from a random source; holds the state of `bag`s.
pub(crate) struct Draw {
    pub(crate) r: Rand,
    bags: Vec<Option<Vec<f64>>>,
}

impl Draw {
    pub(crate) fn new(r: Rand, n: usize) -> Self {
        Self {
            r,
            bags: vec![None; n],
        }
    }

    /// The value of number `i`, kept per its scope in `k`.
    pub(crate) fn sample(&mut self, nums: &[Num], i: usize, k: &mut dyn Keep) -> f64 {
        let scope = nums[i].v.scope;
        if let Some(x) = k.kept(i, scope) {
            return x;
        }
        let x = self.draw(nums, i, k);
        k.keep(i, scope, x);
        x
    }

    /// A new draw of number `i` within its bounds.
    pub(crate) fn draw(&mut self, nums: &[Num], i: usize, k: &mut dyn Keep) -> f64 {
        let v = &nums[i].v;
        let mut x = if let Some(c) = v.constant {
            c
        } else if let Some(r) = &v.range {
            r[0] + (r[1] - r[0]) * self.r.float()
        } else {
            self.dist(nums, i, k)
        };
        if let Some(m) = v.min {
            x = x.max(m);
        }
        if let Some(m) = v.max {
            x = x.min(m);
        }
        x
    }

    fn dist(&mut self, nums: &[Num], i: usize, k: &mut dyn Keep) -> f64 {
        use DistKind as K;
        let d = nums[i].v.dist.as_deref().expect("validated");
        let a = &d.params;
        let r = &mut self.r;
        match d.kind {
            K::Uniform => a[0] + (a[1] - a[0]) * r.float(),
            K::LogUniform => (a[0].ln() + (a[1].ln() - a[0].ln()) * r.float()).exp(),
            K::Exponential => r.exp() / a[0],
            K::Normal => a[0] + a[1] * r.normal(),
            K::LogNormal => (a[0] + a[1] * r.normal()).exp(),
            K::Weibull => a[0] * (-r.open().ln()).powf(1.0 / a[1]),
            K::Pareto => a[0] / r.open().powf(1.0 / a[1]),
            K::Gamma => r.gamma(a[0]) * a[1],
            K::Beta => {
                let (x, lx) = r.gamma_ln(a[0]);
                let (y, ly) = r.gamma_ln(a[1]);
                let t = x + y;
                if t > 0.0 && t.is_finite() {
                    x / t
                } else {
                    // Both variates underflowed (small shapes): their
                    // ratio from the logarithms.
                    1.0 / (1.0 + (ly - lx).exp())
                }
            }
            K::Geometric if a[0] == 1.0 => 1.0,
            K::Geometric => (r.open().ln() / (1.0 - a[0]).ln()).ceil(),
            K::Binomial => r.binomial(a[0], a[1]),
            K::Poisson => r.poisson(a[0]),
            K::Empirical => d.points[r.pick(&d.weights)],
            K::Bag => {
                let b = self.bags[i].get_or_insert_with(Vec::new);
                if b.is_empty() {
                    b.extend_from_slice(&d.points);
                }
                let j = self.r.below(b.len());
                b.swap_remove(j)
            }
            K::Mixture => {
                let j = nums[i].of[r.pick(&d.weights)];
                self.sample(nums, j, k)
            }
            K::Unknown => 0.0,
        }
    }
}
