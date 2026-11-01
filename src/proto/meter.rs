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
//! zmux keeps no rates and no reference sample: a reader that wants a
//! rate divides the increase between two of its own reads by the time
//! between them, so that readers never disturb each other.

use std::sync::atomic::{AtomicU64, Ordering};

/// The counters of a [`Meter`].
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

/// The application byte counters of a stream or a session: unsigned 64-bit
/// counts that zmux never decreases or resets.
///
/// Reads are lock-free and never disturb the session: a read returns a
/// value between the counter's values at the start and at the end of the
/// read, one reader's successive reads never decrease, and two counters
/// read one after the other are not a consistent snapshot. A stream's
/// meter is final once its parts are terminal; a session's stays readable
/// after the session closed.
#[derive(Debug, Default)]
pub struct Meter {
    counts: [AtomicU64; COUNTS],
}

impl Meter {
    /// A meter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    fn counters_only_increase() {
        let m = Meter::new();
        m.add(Count::Written, 1000);
        m.add(Count::Written, 500);
        m.add(Count::DatagramReceived, 7);
        let b = m.get();
        assert_eq!((b.bytes_written, b.bytes_read), (1500, 0));
        assert_eq!((b.datagram_bytes_sent, b.datagram_bytes_received), (0, 7));
        assert_eq!(m.bytes_written(), 1500);
    }
}
