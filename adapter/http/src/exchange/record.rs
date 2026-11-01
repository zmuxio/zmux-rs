//! The record of (Carrier ID, Nonce) pairs of authenticated requests.

use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};

/// A recorded pair: the Carrier ID then the Nonce.
pub(crate) type Pair = [u8; 24];

/// The pairs of requests whose Time is still within the window, grouped in
/// buckets of `width` seconds by Time. A bucket is discarded as a whole once
/// all of its times are more than the window behind the clock, so a pair is
/// kept at least as long as a request with it can be within the window, and
/// expiry costs O(1) per request. At most `max` pairs are held; a pair that
/// finds the record full is not recorded.
pub(crate) struct Record {
    width: i64,
    max: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    len: usize,
    buckets: Vec<Bucket>,
}

struct Bucket {
    /// Time / width of its pairs; meaningful while `pairs` is not empty.
    index: i64,
    pairs: HashSet<Pair>,
}

impl Record {
    /// A record for a window of `window` seconds either side of the clock
    /// holding at most `max` pairs.
    pub(crate) fn new(window: i64, max: usize) -> Self {
        let width = window.max(1);
        // The window spans 2 * window + 1 times, which touch at most three
        // buckets of `width`; two more keep the ring free of live buckets
        // when it wraps.
        let n = ((2 * window + width) / width) as usize + 2;
        Self {
            width,
            max,
            inner: Mutex::new(Inner {
                len: 0,
                buckets: (0..n)
                    .map(|_| Bucket {
                        index: 0,
                        pairs: HashSet::new(),
                    })
                    .collect(),
            }),
        }
    }

    /// Records `pair` sent at `time` while times below `low` are outside
    /// the window. False when the pair is recorded already or the record
    /// is full.
    pub(crate) fn insert(&self, pair: Pair, time: i64, low: i64) -> bool {
        let index = time.div_euclid(self.width);
        let low_index = low.div_euclid(self.width);
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let inner = &mut *g;
        for b in &mut inner.buckets {
            if b.index < low_index && !b.pairs.is_empty() {
                inner.len -= b.pairs.len();
                b.pairs.clear();
            }
        }
        let n = inner.buckets.len() as i64;
        let b = &mut inner.buckets[index.rem_euclid(n) as usize];
        if b.index != index {
            // The slot's pairs are outside the window, or it is empty.
            inner.len -= b.pairs.len();
            b.pairs.clear();
            b.index = index;
        }
        if b.pairs.contains(&pair) || inner.len >= self.max {
            return false;
        }
        b.pairs.insert(pair);
        inner.len += 1;
        true
    }

    /// The pairs held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(n: u8) -> Pair {
        [n; 24]
    }

    #[test]
    fn a_pair_is_recorded_once() {
        let r = Record::new(60, 16);
        assert!(r.insert(pair(1), 1000, 940));
        assert!(!r.insert(pair(1), 1000, 940));
        assert!(r.insert(pair(2), 1000, 940));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn a_full_record_takes_nothing() {
        let r = Record::new(60, 2);
        assert!(r.insert(pair(1), 1000, 940));
        assert!(r.insert(pair(2), 1001, 941));
        assert!(!r.insert(pair(3), 1001, 941));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn buckets_expire_whole_and_never_early() {
        let r = Record::new(60, 4);
        // Bucket 16 holds times 960..1020.
        assert!(r.insert(pair(1), 960, 900));
        assert!(r.insert(pair(2), 1019, 959));
        // Time 1019 is within the window until the clock passes 1079.
        assert!(!r.insert(pair(2), 1019, 1019));
        assert_eq!(r.len(), 2);
        // Once every time of the bucket is below the window, the bucket
        // goes, and the space it held is free.
        assert!(r.insert(pair(3), 1080, 1020));
        assert_eq!(r.len(), 1);
        assert!(r.insert(pair(1), 1080, 1020));
    }

    #[test]
    fn a_zero_window_records_per_second() {
        let r = Record::new(0, 4);
        assert!(r.insert(pair(1), 5, 5));
        assert!(!r.insert(pair(1), 5, 5));
        assert!(r.insert(pair(1), 6, 6));
        assert_eq!(r.len(), 1);
    }
}
