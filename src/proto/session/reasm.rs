//! Arrival evidence for connection credit, including discarded data.

use std::collections::VecDeque;

use super::ranges::RangeSet;

/// Bookkeeping of one range of an arrival set in range mode.
const ARRIVAL_RANGE_COST: u64 = 16;

/// Ranges are cheap below this many, whatever the span.
const FEW_RANGES: usize = 8;

// The common small range set can coexist with its bitmap replacement.
// Each bitmap also has a word at either edge and allocation rounding.
pub(super) const EVIDENCE_MARGIN: usize =
    6 * (FEW_RANGES + 1) * size_of::<(u64, u64)>() + 12 * 2 * size_of::<u64>();

/// A set of stream offsets, one bit each, from `first` (a multiple of 64).
#[derive(Debug, Default)]
pub(crate) struct Bits {
    first: u64,
    words: VecDeque<u64>,
    ones: u64,
}

impl Bits {
    fn word_of(&self, at: u64) -> Option<usize> {
        at.checked_sub(self.first)
            .map(|d| (d / 64) as usize)
            .filter(|&i| i < self.words.len())
    }

    /// Adds `[start, end)`; returns how many offsets were new.
    pub(crate) fn insert(&mut self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        if self.words.is_empty() {
            self.first = start & !63;
        }
        while start < self.first {
            self.words.push_front(0);
            self.first -= 64;
        }
        let last = ((end - 1 - self.first) / 64) as usize;
        if self.words.len() <= last {
            self.words.resize(last + 1, 0);
        }
        let mut added = 0;
        let mut at = start;
        while at < end {
            let i = ((at - self.first) / 64) as usize;
            let lo = (at - self.first) % 64;
            let hi = (end - self.first - i as u64 * 64).min(64);
            let mask = mask(lo, hi);
            let w = &mut self.words[i];
            added += u64::from((mask & !*w).count_ones());
            *w |= mask;
            at = self.first + i as u64 * 64 + hi;
        }
        self.ones += added;
        added
    }

    pub(crate) fn remove_below(&mut self, floor: u64) -> u64 {
        self.remove(0, floor)
    }

    pub(super) fn remove_from(&mut self, limit: u64) -> u64 {
        self.remove(limit, u64::MAX)
    }

    fn remove(&mut self, start: u64, end: u64) -> u64 {
        let end = end.min(self.first + self.words.len() as u64 * 64);
        let mut at = start.max(self.first);
        let mut removed = 0;
        while at < end {
            let i = ((at - self.first) / 64) as usize;
            let hi = (end - self.first - i as u64 * 64).min(64);
            let mask = mask((at - self.first) % 64, hi);
            removed += u64::from((self.words[i] & mask).count_ones());
            self.words[i] &= !mask;
            at = self.first + i as u64 * 64 + hi;
        }
        self.ones -= removed;
        self.trim();
        removed
    }

    /// Drops empty words at both ends.
    fn trim(&mut self) {
        if self.ones == 0 {
            self.words.clear();
            return;
        }
        while self.words.front() == Some(&0) {
            self.words.pop_front();
            self.first += 64;
        }
        while self.words.back() == Some(&0) {
            self.words.pop_back();
        }
        if self.words.capacity() / 4 > self.words.len() {
            self.words.shrink_to_fit();
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ones == 0
    }

    /// The first offset at or beyond `at` that is not in the set.
    pub(crate) fn run_end(&self, at: u64) -> u64 {
        let Some(mut i) = self.word_of(at) else {
            return at;
        };
        let lo = (at - self.first) % 64;
        let mut w = !self.words[i] & mask(lo, 64);
        loop {
            if w != 0 {
                return self.first + i as u64 * 64 + u64::from(w.trailing_zeros());
            }
            i += 1;
            match self.words.get(i) {
                Some(&next) => w = !next,
                None => return self.first + i as u64 * 64,
            }
        }
    }

    /// Offsets of `[start, end)` in the set.
    pub(crate) fn covered(&self, start: u64, end: u64) -> u64 {
        let start = start.max(self.first);
        let end = end.min(self.first + self.words.len() as u64 * 64);
        let mut n = 0;
        let mut at = start;
        while at < end {
            let i = ((at - self.first) / 64) as usize;
            let lo = (at - self.first) % 64;
            let hi = (end - self.first - i as u64 * 64).min(64);
            n += u64::from((self.words[i] & mask(lo, hi)).count_ones());
            at = self.first + i as u64 * 64 + hi;
        }
        n
    }

    pub(super) fn first_from(&self, at: u64) -> Option<u64> {
        let at = at.max(self.first);
        let mut i = self.word_of(at)?;
        let mut word = self.words[i] & mask((at - self.first) % 64, 64);
        loop {
            if word != 0 {
                return Some(self.first + i as u64 * 64 + u64::from(word.trailing_zeros()));
            }
            i += 1;
            word = *self.words.get(i)?;
        }
    }

    /// The span from the first stored offset to one past the last.
    pub(super) fn bounds(&self) -> Option<(u64, u64)> {
        let first = self.first_from(self.first)?;
        let last = self.words.back().copied().expect("present word");
        let end = self.first + self.words.len() as u64 * 64 - u64::from(last.leading_zeros());
        Some((first, end))
    }

    pub(super) fn memory(&self) -> usize {
        self.words.capacity() * 8
    }
}

/// Bits `lo..hi` of a word.
fn mask(lo: u64, hi: u64) -> u64 {
    let upper = if hi >= 64 { u64::MAX } else { (1u64 << hi) - 1 };
    upper & !((1u64 << lo) - 1)
}

/// Offsets use small ordered ranges when sparse and a bitmap once the
/// range descriptors cost more than the bitmap of the protected span.
#[derive(Debug)]
enum Offsets {
    Ranges(RangeSet),
    Bits(Bits),
}

impl Default for Offsets {
    fn default() -> Self {
        Self::Ranges(RangeSet::new())
    }
}

impl Offsets {
    fn is_empty(&self) -> bool {
        match self {
            Self::Ranges(r) => r.is_empty(),
            Self::Bits(b) => b.is_empty(),
        }
    }

    fn insert(&mut self, start: u64, end: u64, floor: u64) -> u64 {
        match self {
            Self::Ranges(r) => {
                let added = r.insert(start, end);
                let span = r.end().unwrap_or(floor).saturating_sub(floor);
                if r.len() > FEW_RANGES && r.len() as u64 * ARRIVAL_RANGE_COST > span / 8 {
                    let mut bits = Bits::default();
                    for (lo, hi) in r.iter() {
                        bits.insert(lo, hi);
                    }
                    *self = Self::Bits(bits);
                }
                added
            }
            Self::Bits(b) => b.insert(start, end),
        }
    }

    fn first_from(&self, offset: u64) -> Option<u64> {
        match self {
            Self::Ranges(r) => r.within(offset, u64::MAX).next().map(|(lo, _)| lo),
            Self::Bits(b) => b.first_from(offset),
        }
    }

    fn run_end(&self, offset: u64) -> u64 {
        match self {
            Self::Ranges(r) => r.contiguous_end(offset),
            Self::Bits(b) => b.run_end(offset),
        }
    }

    fn remove(&mut self, start: u64, end: u64) {
        match self {
            Self::Ranges(r) => {
                r.remove(start, end);
                r.trim_spare();
            }
            Self::Bits(b) => {
                b.remove(start, end);
            }
        }
    }

    fn covered(&self, start: u64, end: u64) -> u64 {
        match self {
            Self::Ranges(r) => r.covered(start, end),
            Self::Bits(b) => b.covered(start, end),
        }
    }

    fn memory(&self) -> usize {
        match self {
            Self::Ranges(r) => r.memory(),
            Self::Bits(b) => b.memory(),
        }
    }
}

/// Arrival evidence beyond the contiguous prefix. After a local stop
/// the same offset set records the complement, so filling the last hole
/// can release the earlier discarded history without storing its data.
#[derive(Debug, Default)]
pub(crate) struct Arrived {
    offsets: Offsets,
    missing: Option<Missing>,
}

#[derive(Debug)]
struct Missing {
    end: u64,
    seen: u64,
}

impl Arrived {
    pub(crate) fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    pub(super) fn missing(floor: u64) -> Self {
        Self {
            offsets: Offsets::default(),
            missing: Some(Missing {
                end: floor,
                seen: 0,
            }),
        }
    }

    pub(super) fn protected_history(&self) -> u64 {
        self.missing.as_ref().map_or(0, |missing| missing.seen)
    }

    pub(super) fn discard_data(&mut self, start: u64, end: u64) {
        if self.missing.is_some() {
            return;
        }
        let mut holes = Offsets::default();
        let mut hole_bytes = 0;
        let mut at = start;
        while at < end {
            let next = self.offsets.first_from(at).unwrap_or(end).min(end);
            hole_bytes += holes.insert(at, next, start);
            at = self.offsets.run_end(next);
        }
        self.offsets = holes;
        self.missing = Some(Missing {
            end,
            seen: end - start - hole_bytes,
        });
    }

    /// Discard evidence for offsets the peer can no longer deliver.
    pub(super) fn remove_from(&mut self, limit: u64) {
        if let Some(missing) = &mut self.missing {
            let cut = missing.end.max(limit);
            let removed = cut - limit - self.offsets.covered(limit, cut);
            missing.seen -= removed;
            missing.end = missing.end.min(limit);
        }
        self.offsets.remove(limit, u64::MAX);
    }

    /// Adds only the offsets actually in this frame.
    pub(crate) fn insert(&mut self, start: u64, end: u64, floor: u64) -> u64 {
        let Some(missing) = &mut self.missing else {
            return self.offsets.insert(start, end, floor);
        };
        let fresh = self.offsets.covered(start, end) + end.saturating_sub(start.max(missing.end));
        if start > missing.end {
            self.offsets.insert(missing.end.max(floor), start, floor);
        }
        self.offsets.remove(start, end);
        missing.end = missing.end.max(end);
        missing.seen += fresh;
        fresh
    }

    pub(crate) fn advance(&mut self, floor: u64) -> Option<u64> {
        if let Some(missing) = &mut self.missing {
            let until = self.offsets.first_from(floor).unwrap_or(missing.end);
            missing.seen -= until.saturating_sub(floor);
            return (until > floor).then_some(until);
        }
        let end = self.offsets.run_end(floor);
        if end > floor {
            self.offsets.remove(0, end);
            Some(end)
        } else {
            None
        }
    }

    pub(crate) fn covered(&self, start: u64, end: u64) -> u64 {
        if let Some(missing) = &self.missing {
            let end = end.min(missing.end);
            end.saturating_sub(start) - self.offsets.covered(start, end)
        } else {
            self.offsets.covered(start, end)
        }
    }

    pub(crate) fn memory(&self) -> usize {
        self.offsets.memory()
    }
}

#[cfg(test)]
mod tests {
    use super::Offsets;

    #[test]
    fn an_empty_range_above_stale_holes_keeps_the_span_nonnegative() {
        let mut holes = Offsets::default();
        assert_eq!(holes.insert(0, 1, 0), 1);
        assert_eq!(holes.insert(8, 8, 8), 0);
    }
}
