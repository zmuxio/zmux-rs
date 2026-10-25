//! Application byte counters.
//!
//! A [`Meter`] counts what the application handed to a stream or session
//! and got from it: payload bytes only, each byte once, whatever pipes,
//! copies or failures carried it. The core counts at the event (a write
//! accepted, a read returned, a datagram handed out or received) with one
//! relaxed atomic add, inside the critical section the operation holds
//! anyway, where it costs nothing more; counting never takes a lock of its
//! own. Any thread reads the counters at any time without a lock, through
//! a shared handle (`Arc<Meter>`) that outlives the stream or session.
//!
//! Rates are computed on the reading side only: the meter keeps one
//! reference sample, and [`Meter::rate`] returns the increase since it
//! divided by the time since it, moving the reference to the current
//! reading once it is more than one second old. Counting costs nothing
//! for rates.

use std::sync::atomic::{AtomicU64, Ordering, fence};
use std::time::{Duration, Instant};

/// How old the reference sample may grow before a rate read replaces it.
const REFERENCE_AGE: Duration = Duration::from_secs(1);

/// The counters of a [`Meter`], or their rates in bytes per second.
///
/// On a stream, `bytes_written` and `datagram_bytes_sent` belong to its
/// sending part, `bytes_read` and `datagram_bytes_received` to its
/// receiving part; on a session each is the sum over all its streams,
/// released ones included, and for the datagram counters its session
/// datagrams too.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AppBytes {
    /// Payload bytes the application handed to a sending part and the
    /// call accepted. Bytes later lost to a reset stay counted.
    pub bytes_written: u64,
    /// Payload bytes a receiving part returned to the application. Bytes
    /// discarded unread (after a stop, a reset or release) never count.
    pub bytes_read: u64,
    /// Datagram payload bytes handed to a carrier. A datagram dropped from
    /// the queue or by a limiter never counts.
    pub datagram_bytes_sent: u64,
    /// Datagram payload bytes returned to the application.
    pub datagram_bytes_received: u64,
}

/// Which counter of a [`Meter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Count {
    Written = 0,
    Read = 1,
    DatagramSent = 2,
    DatagramReceived = 3,
}

const COUNTS: usize = 4;

/// One reference sample: the counters and when they were read, in
/// nanoseconds since the meter's epoch. `seq` is odd while a reader
/// replaces it (a sequence lock whose data are atomics).
#[derive(Debug, Default)]
struct Sample {
    seq: AtomicU64,
    at: AtomicU64,
    counts: [AtomicU64; COUNTS],
}

/// The application byte counters of a stream or a session: unsigned 64-bit
/// counts that zmux never decreases or resets.
///
/// Reads are lock-free and never disturb the session: a read returns a
/// value between the counter's values at the start and at the end of the
/// read, one reader's successive reads never decrease, and two counters
/// read one after the other are not a consistent snapshot. A stream's
/// meter is final once its parts are terminal; a session's stays readable
/// after the session closed.
#[derive(Debug)]
pub struct Meter {
    counts: [AtomicU64; COUNTS],
    epoch: Instant,
    /// The reference sample of the rates: two slots, the current one named
    /// by `current` (its generation; the slot is the generation's low bit),
    /// so that a reader replacing it writes the other slot and readers
    /// never wait for it. `CLAIMED` is set while a reader replaces it.
    slots: [Sample; 2],
    current: AtomicU64,
}

const CLAIMED: u64 = 1 << 63;

impl Meter {
    /// A meter at zero, its reference sample taken at `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            counts: Default::default(),
            epoch: now,
            slots: Default::default(),
            current: AtomicU64::new(0),
        }
    }

    /// Adds `n` to a counter.
    #[inline]
    pub(crate) fn add(&self, c: Count, n: u64) {
        self.counts[c as usize].fetch_add(n, Ordering::Relaxed);
    }

    fn load(&self) -> [u64; COUNTS] {
        std::array::from_fn(|i| self.counts[i].load(Ordering::Relaxed))
    }

    /// The counters now.
    pub fn get(&self) -> AppBytes {
        to_bytes(self.load())
    }

    /// Payload bytes written (see [`AppBytes::bytes_written`]).
    pub fn bytes_written(&self) -> u64 {
        self.counts[Count::Written as usize].load(Ordering::Relaxed)
    }

    /// Payload bytes read (see [`AppBytes::bytes_read`]).
    pub fn bytes_read(&self) -> u64 {
        self.counts[Count::Read as usize].load(Ordering::Relaxed)
    }

    /// Datagram payload bytes sent (see [`AppBytes::datagram_bytes_sent`]).
    pub fn datagram_bytes_sent(&self) -> u64 {
        self.counts[Count::DatagramSent as usize].load(Ordering::Relaxed)
    }

    /// Datagram payload bytes received (see
    /// [`AppBytes::datagram_bytes_received`]).
    pub fn datagram_bytes_received(&self) -> u64 {
        self.counts[Count::DatagramReceived as usize].load(Ordering::Relaxed)
    }

    /// The counters' rates in bytes per second at `now` (the clock the
    /// meter was created with): the increase since the reference sample
    /// divided by the time since it. A reference more than one second old
    /// is replaced by the current reading, so a reader that reads at least
    /// once a second sees the average of the last one to two seconds, and
    /// a rare reader the average since its previous read (since the start
    /// before the first). Concurrent readers may each read; one of them
    /// replaces the reference, and the others keep their result.
    pub fn rate(&self, now: Instant) -> AppBytes {
        let at_now = nanos(now.saturating_duration_since(self.epoch));
        let (generation, at, reference) = self.reference();
        let counts = self.load();
        let elapsed = at_now.saturating_sub(at);
        let rate = if elapsed == 0 {
            [0; COUNTS]
        } else {
            std::array::from_fn(|i| {
                let delta = u128::from(counts[i].saturating_sub(reference[i]));
                u64::try_from(delta * 1_000_000_000 / u128::from(elapsed)).unwrap_or(u64::MAX)
            })
        };
        if elapsed > nanos(REFERENCE_AGE) {
            self.replace(generation, at_now, &counts);
        }
        to_bytes(rate)
    }

    /// The current reference sample, read consistently: its generation,
    /// time and counters.
    fn reference(&self) -> (u64, u64, [u64; COUNTS]) {
        loop {
            let generation = self.current.load(Ordering::Acquire) & !CLAIMED;
            let slot = &self.slots[(generation & 1) as usize];
            let seq = slot.seq.load(Ordering::Acquire);
            if seq & 1 == 0 {
                let at = slot.at.load(Ordering::Relaxed);
                let counts = std::array::from_fn(|i| slot.counts[i].load(Ordering::Relaxed));
                fence(Ordering::Acquire);
                if slot.seq.load(Ordering::Relaxed) == seq {
                    return (generation, at, counts);
                }
            }
            // The slot was being rewritten: two replacements happened
            // since `current` was read, and the next read names the slot
            // that is stable now.
            std::hint::spin_loop();
        }
    }

    /// Replaces the reference of `generation` by a reading at `at`, unless
    /// another reader replaces it or did already.
    fn replace(&self, generation: u64, at: u64, counts: &[u64; COUNTS]) {
        if self
            .current
            .compare_exchange(
                generation,
                generation | CLAIMED,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }
        let next = generation.wrapping_add(1) & !CLAIMED;
        let slot = &self.slots[(next & 1) as usize];
        let seq = slot.seq.load(Ordering::Relaxed);
        slot.seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        slot.at.store(at, Ordering::Relaxed);
        for (c, &v) in slot.counts.iter().zip(counts) {
            c.store(v, Ordering::Relaxed);
        }
        slot.seq.store(seq.wrapping_add(2), Ordering::Release);
        self.current.store(next, Ordering::Release);
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

fn to_bytes(c: [u64; COUNTS]) -> AppBytes {
    AppBytes {
        bytes_written: c[Count::Written as usize],
        bytes_read: c[Count::Read as usize],
        datagram_bytes_sent: c[Count::DatagramSent as usize],
        datagram_bytes_received: c[Count::DatagramReceived as usize],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_are_averages_since_a_reference_at_most_two_seconds_old() {
        let t0 = Instant::now();
        let m = Meter::new(t0);
        m.add(Count::Written, 1000);
        // Since the start: 1000 bytes in 0.5 s.
        assert_eq!(m.rate(t0 + Duration::from_millis(500)).bytes_written, 2000);
        m.add(Count::Written, 1000);
        // 2000 bytes in 1.5 s; the reference moves to this reading.
        assert_eq!(m.rate(t0 + Duration::from_millis(1500)).bytes_written, 1333);
        m.add(Count::Read, 300);
        let r = m.rate(t0 + Duration::from_millis(1800));
        assert_eq!((r.bytes_written, r.bytes_read), (0, 1000));
        // The counters themselves never move back.
        assert_eq!(m.get().bytes_written, 2000);
        // A clock behind the reference reads 0, not a spike.
        assert_eq!(m.rate(t0).bytes_read, 0);
    }

    #[test]
    fn concurrent_readers_replace_the_reference_once_and_keep_their_results() {
        let t0 = Instant::now();
        let m = std::sync::Arc::new(Meter::new(t0));
        m.add(Count::DatagramSent, 4000);
        let at = t0 + Duration::from_secs(2);
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let m = m.clone();
                std::thread::spawn(move || m.rate(at).datagram_bytes_sent)
            })
            .collect();
        for r in readers {
            // Each reader computed against a consistent reference: the
            // start (2000 B/s), or the reading at `at` (an instant ago).
            let v = r.join().unwrap();
            assert!(v == 2000 || v == 0, "{v}");
        }
        assert_eq!(m.current.load(Ordering::Relaxed), 1);
    }
}
