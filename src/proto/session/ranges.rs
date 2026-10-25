//! Sets of byte ranges for multipath retention and reassembly.

/// Disjoint, non-adjacent half-open ranges in increasing order. Small in
/// practice (a few gaps per stream); the vector keeps its capacity, so a
/// steady transfer allocates nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RangeSet {
    ranges: Vec<(u64, u64)>,
}

impl RangeSet {
    /// An empty set.
    pub(crate) const fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The number of ranges.
    pub(crate) fn len(&self) -> usize {
        self.ranges.len()
    }

    /// The end of the last range.
    pub(crate) fn end(&self) -> Option<u64> {
        self.ranges.last().map(|&(_, e)| e)
    }

    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.ranges.iter().copied()
    }

    /// The first range.
    pub(crate) fn first(&self) -> Option<(u64, u64)> {
        self.ranges.first().copied()
    }

    /// Adds `[start, end)`; returns the number of bytes that were new.
    pub(crate) fn insert(&mut self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        // Index of the first range that ends at or after `start` (touching
        // ranges merge).
        let i = self.ranges.partition_point(|&(_, e)| e < start);
        let mut new_start = start;
        let mut new_end = end;
        let mut covered = 0u64;
        let mut j = i;
        while j < self.ranges.len() && self.ranges[j].0 <= end {
            let (s, e) = self.ranges[j];
            covered += e.min(end).saturating_sub(s.max(start));
            new_start = new_start.min(s);
            new_end = new_end.max(e);
            j += 1;
        }
        let added = (end - start) - covered;
        if j == i {
            self.ranges.insert(i, (new_start, new_end));
        } else {
            self.ranges[i] = (new_start, new_end);
            self.ranges.drain(i + 1..j);
        }
        added
    }

    /// Removes `[start, end)`.
    pub(crate) fn remove(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut i = self.ranges.partition_point(|&(_, e)| e <= start);
        while i < self.ranges.len() {
            let (s, e) = self.ranges[i];
            if s >= end {
                break;
            }
            if s < start && e > end {
                self.ranges[i] = (s, start);
                self.ranges.insert(i + 1, (end, e));
                return;
            }
            if s < start {
                self.ranges[i] = (s, start);
                i += 1;
            } else if e > end {
                self.ranges[i] = (end, e);
                return;
            } else {
                self.ranges.remove(i);
            }
        }
    }

    /// Drops everything below `floor`.
    pub(crate) fn remove_below(&mut self, floor: u64) {
        self.remove(0, floor);
    }

    /// Whether `[start, end)` is entirely in the set.
    pub(crate) fn contains(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return true;
        }
        let i = self.ranges.partition_point(|&(_, e)| e <= start);
        self.ranges
            .get(i)
            .is_some_and(|&(s, e)| s <= start && e >= end)
    }

    /// The end of the range that contains `at`, or `at` when none does.
    pub(crate) fn contiguous_end(&self, at: u64) -> u64 {
        let i = self.ranges.partition_point(|&(_, e)| e < at);
        match self.ranges.get(i) {
            Some(&(s, e)) if s <= at => e.max(at),
            _ => at,
        }
    }

    /// The parts of `[start, end)` in the set, in order.
    pub(crate) fn within(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let i = self.ranges.partition_point(|&(_, e)| e <= start);
        self.ranges[i..]
            .iter()
            .take_while(move |&&(s, _)| s < end)
            .map(move |&(s, e)| (s.max(start), e.min(end)))
    }

    /// The parts of `[start, end)` not in the set, in order.
    pub(crate) fn gaps(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let mut at = start;
        self.within(start, end)
            .map(Some)
            .chain(std::iter::once(None))
            .filter_map(move |r| {
                let (s, e) = r.unwrap_or((end, end));
                let gap = (at < s).then_some((at, s));
                at = at.max(e);
                gap
            })
    }

    /// Bytes of `[start, end)` in the set.
    pub(crate) fn covered(&self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        let i = self.ranges.partition_point(|&(_, e)| e <= start);
        self.ranges[i..]
            .iter()
            .take_while(|&&(s, _)| s < end)
            .map(|&(s, e)| e.min(end) - s.max(start))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_and_gaps_partition_a_span() {
        let mut r = RangeSet::default();
        r.insert(10, 20);
        r.insert(30, 40);
        assert_eq!(
            r.within(15, 35).collect::<Vec<_>>(),
            vec![(15, 20), (30, 35)]
        );
        assert_eq!(r.gaps(15, 35).collect::<Vec<_>>(), vec![(20, 30)]);
        assert_eq!(
            r.gaps(0, 50).collect::<Vec<_>>(),
            vec![(0, 10), (20, 30), (40, 50)]
        );
        assert_eq!(r.gaps(10, 20).count(), 0);
        assert_eq!(r.gaps(20, 30).collect::<Vec<_>>(), vec![(20, 30)]);
        assert_eq!(r.within(20, 30).count(), 0);
    }

    #[test]
    fn insert_merges_and_counts_new_bytes() {
        let mut r = RangeSet::default();
        assert_eq!(r.insert(10, 20), 10);
        assert_eq!(r.insert(30, 40), 10);
        assert_eq!(r.insert(15, 35), 10);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![(10, 40)]);
        assert_eq!(r.insert(40, 45), 5);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![(10, 45)]);
        assert_eq!(r.insert(0, 5), 5);
        assert_eq!(r.iter().count(), 2);
        assert_eq!(r.contiguous_end(0), 5);
        assert_eq!(r.contiguous_end(5), 5);
        assert!(r.contains(12, 44));
        assert!(!r.contains(4, 11));
    }

    #[test]
    fn covered_counts_overlap() {
        let mut r = RangeSet::default();
        r.insert(10, 20);
        r.insert(30, 40);
        assert_eq!(r.covered(0, 100), 20);
        assert_eq!(r.covered(15, 35), 10);
        assert_eq!(r.covered(20, 30), 0);
        assert_eq!(r.covered(5, 5), 0);
    }

    #[test]
    fn remove_splits() {
        let mut r = RangeSet::default();
        r.insert(0, 100);
        r.remove(10, 20);
        r.remove(90, 120);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![(0, 10), (20, 90)]);
        r.remove_below(50);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![(50, 90)]);
        assert_eq!(r.covered(0, u64::MAX), 40);
    }
}
