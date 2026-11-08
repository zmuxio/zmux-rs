//! Random sources.

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
