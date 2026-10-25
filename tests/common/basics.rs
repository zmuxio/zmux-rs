//! Std-only helpers of every kind of test (sans IO, std driver, tokio
//! driver): the serializing lock, seeded randomness, soak and seed ranges,
//! descriptor counts and small flow-control windows.

#![allow(dead_code)]

use std::ops::Range;
use std::sync::{Mutex, MutexGuard, PoisonError};

use zmux::Config;

/// The tests of a binary that share process-wide counts: one at a time.
pub(crate) fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// xorshift64*: reproducible randomness without a dependency.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Rounds multiplied by `ZMUX_SOAK` (default 1).
pub(crate) fn soak(rounds: usize) -> usize {
    let k = std::env::var("ZMUX_SOAK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    rounds * k
}

/// The seeds of a seeded test: `ZMUX_SEED=<n>` replays one, else
/// `default` of them, times `ZMUX_SOAK`.
pub(crate) fn seeds(default: u64) -> Range<u64> {
    if let Some(s) = std::env::var("ZMUX_SEED").ok().and_then(|v| v.parse().ok()) {
        return s..s + 1;
    }
    0..soak(default as usize) as u64
}

/// The process's open file descriptors.
pub(crate) fn open_fds() -> usize {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir).map_or(0, Iterator::count)
}

/// Small stream and session windows: credit pressure.
pub(crate) fn small_windows(mut c: Config) -> Config {
    c.initial_stream_receive_window = 16 * 1024;
    c.max_stream_receive_window = zmux::Cap::Fixed(64 * 1024);
    c.initial_connection_receive_window = 64 * 1024;
    c.max_connection_receive_window = zmux::Cap::Fixed(256 * 1024);
    c
}

/// A connected pair of std TCP sockets on the loopback.
pub(crate) fn tcp() -> (std::net::TcpStream, std::net::TcpStream) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (b, _) = l.accept().unwrap();
    (a, b)
}
