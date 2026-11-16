//! Random sources.

use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};

/// A source of uniformly distributed 64-bit values.
pub trait Source: Send {
    /// The next value.
    fn next_u64(&mut self) -> u64;
}

/// `ChaCha8` seeded from the operating system.
pub(crate) struct OsSeeded(ChaCha8Rng);

impl OsSeeded {
    pub(crate) fn new() -> Self {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        // Shaping draws need to differ, not to be secret: a failed system
        // source falls back to a process-local randomly seeded one.
        if getrandom::fill(&mut seed).is_err() {
            use std::hash::BuildHasher;
            let s = std::collections::hash_map::RandomState::new();
            for (i, c) in seed.chunks_mut(8).enumerate() {
                c.copy_from_slice(&s.hash_one(i).to_le_bytes()[..c.len()]);
            }
        }
        Self(ChaCha8Rng::from_seed(seed))
    }
}

impl Source for OsSeeded {
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
}
