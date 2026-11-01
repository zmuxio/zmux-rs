//! Random sources and sampling.

use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};

/// A source of uniformly distributed 64-bit values.
pub trait Source: Send {
    /// The next value.
    fn next_u64(&mut self) -> u64;
}

/// ChaCha8 seeded from the operating system.
pub(crate) struct OsSeeded(ChaCha8Rng);

impl OsSeeded {
    pub(crate) fn new() -> Self {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        getrandom::fill(&mut seed).expect("operating system random source");
        Self(ChaCha8Rng::from_seed(seed))
    }
}

impl Source for OsSeeded {
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
}

/// The largest Binomial trial count, and Poisson mean, accepted: 2^53,
/// beyond which counts are not exact in an `f64`.
pub(crate) const MAX_COUNT: f64 = 9_007_199_254_740_992.0;

/// Trials a binomial sample takes one by one at most.
const DIRECT_TRIALS: f64 = 64.0;

/// The largest mean a Poisson sample takes by the product of uniforms.
const DIRECT_MEAN: f64 = 30.0;

/// Sampling over a [`Source`].
pub(crate) struct Rand(pub(crate) Box<dyn Source>);

impl Rand {
    /// Uniform in [0, 1).
    pub(crate) fn float(&mut self) -> f64 {
        (self.0.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Uniform in (0, 1].
    pub(crate) fn open(&mut self) -> f64 {
        1.0 - self.float()
    }

    /// Uniform in [0, n).
    pub(crate) fn below(&mut self, n: usize) -> usize {
        ((self.0.next_u64() as u128 * n as u128) >> 64) as usize
    }

    /// Standard normal (polar method).
    pub(crate) fn normal(&mut self) -> f64 {
        loop {
            let u = 2.0 * self.float() - 1.0;
            let v = 2.0 * self.float() - 1.0;
            let s = u * u + v * v;
            if s > 0.0 && s < 1.0 {
                return u * (-2.0 * s.ln() / s).sqrt();
            }
        }
    }

    /// Exponential with rate 1.
    pub(crate) fn exp(&mut self) -> f64 {
        -self.open().ln()
    }

    /// Gamma(a, 1) (Marsaglia and Tsang).
    pub(crate) fn gamma(&mut self, a: f64) -> f64 {
        self.gamma_ln(a).0
    }

    /// Gamma(a, 1) with its logarithm, which stays finite for a shape below
    /// 1 where the variate underflows to 0.
    pub(crate) fn gamma_ln(&mut self, a: f64) -> (f64, f64) {
        if a < 1.0 {
            let g = self.gamma1(a + 1.0);
            let u = self.open();
            return (g * u.powf(1.0 / a), g.ln() + u.ln() / a);
        }
        let x = self.gamma1(a);
        (x, x.ln())
    }

    /// Gamma(a, 1) for a shape of at least 1.
    fn gamma1(&mut self, a: f64) -> f64 {
        let d = a - 1.0 / 3.0;
        let c = 1.0 / (9.0 * d).sqrt();
        loop {
            let x = self.normal();
            let v = 1.0 + c * x;
            if v <= 0.0 {
                continue;
            }
            let v = v * v * v;
            if self.open().ln() < 0.5 * x * x + d - d * v + d * v.ln() {
                return d * v;
            }
        }
    }

    /// Binomial(n, p) for an integral `n` in [0, 2^53] (Knuth, TAOCP
    /// 3.4.1 F): while n is large, the median order statistic of n
    /// uniforms, a Beta variate, halves the trials; O(log n) steps, then
    /// at most [`DIRECT_TRIALS`] Bernoulli trials.
    pub(crate) fn binomial(&mut self, mut n: f64, mut p: f64) -> f64 {
        let mut k = 0.0;
        while n > DIRECT_TRIALS {
            // Exact at the ends, where a rounded Beta variate could skip trials.
            if p <= 0.0 {
                return k;
            }
            if p >= 1.0 {
                return k + n;
            }
            let a = 1.0 + (n / 2.0).floor();
            let b = n + 1.0 - a;
            let x = self.gamma(a);
            let x = x / (x + self.gamma(b));
            if x >= p {
                n = a - 1.0;
                p /= x;
            } else {
                k += a;
                n = b - 1.0;
                p = (p - x) / (1.0 - x);
            }
        }
        for _ in 0..n as u64 {
            if self.float() < p {
                k += 1.0;
            }
        }
        k
    }

    /// Poisson(mean) for a mean in (0, 2^53] (Knuth, TAOCP 3.4.1 F):
    /// while the mean is large, a Gamma variate takes 7/8 of it at once,
    /// or the rest is binomial; O(log mean) steps, then the product of
    /// uniforms for a mean of at most [`DIRECT_MEAN`].
    pub(crate) fn poisson(&mut self, mut mean: f64) -> f64 {
        let mut k = 0.0;
        while mean > DIRECT_MEAN {
            let m = (mean * 7.0 / 8.0).floor();
            let x = self.gamma(m);
            if x >= mean {
                return k + self.binomial(m - 1.0, mean / x);
            }
            k += m;
            mean -= x;
        }
        let l = (-mean).exp();
        let mut t = self.float();
        while t > l {
            k += 1.0;
            t *= self.float();
        }
        k
    }

    /// An index drawn by `weights`.
    pub(crate) fn pick(&mut self, weights: &[f64]) -> usize {
        let mut t = weights.iter().sum::<f64>() * self.float();
        for (i, w) in weights.iter().enumerate() {
            if t < *w {
                return i;
            }
            t -= w;
        }
        weights.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Seeded(ChaCha8Rng);

    impl Source for Seeded {
        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }
    }

    fn rand() -> Rand {
        Rand(Box::new(Seeded(ChaCha8Rng::seed_from_u64(7))))
    }

    /// The sample mean and variance of `n` draws.
    fn moments(n: usize, mut f: impl FnMut() -> f64) -> (f64, f64) {
        let xs: Vec<f64> = (0..n).map(|_| f()).collect();
        let mean = xs.iter().sum::<f64>() / n as f64;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
        (mean, var)
    }

    #[test]
    fn binomial_moments() {
        let mut r = rand();
        for (n, p) in [(10.0, 0.3), (1000.0, 0.3), (1e9, 0.01), (1e15, 0.5)] {
            let (mean, var) = moments(4000, || r.binomial(n, p));
            let (m, v) = (n * p, n * p * (1.0 - p));
            assert!(
                (mean - m).abs() < 5.0 * (v / 4000.0).sqrt() + 1e-9,
                "{n} {p}: mean {mean}"
            );
            assert!((var / v - 1.0).abs() < 0.15, "{n} {p}: variance {var}");
        }
        let mut r = rand();
        for _ in 0..100 {
            let x = r.binomial(1000.0, 0.3);
            assert!(x.fract() == 0.0 && (0.0..=1000.0).contains(&x));
        }
        assert_eq!(r.binomial(MAX_COUNT, 1.0), MAX_COUNT);
        assert_eq!(r.binomial(MAX_COUNT, 0.0), 0.0);
    }

    #[test]
    fn poisson_moments() {
        let mut r = rand();
        for mean in [0.5, 29.0, 1000.0, 1e12, MAX_COUNT] {
            let (m, v) = moments(4000, || r.poisson(mean));
            assert!(
                (m - mean).abs() < 5.0 * (mean / 4000.0).sqrt() + 1e-9,
                "{mean}: mean {m}"
            );
            assert!((v / mean - 1.0).abs() < 0.15, "{mean}: variance {v}");
        }
    }
}
