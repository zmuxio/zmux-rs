//! Out-of-order stream data and arrival sets whose memory does not depend
//! on how the peer fragments the data (SPEC.md Section 9.8).
//!
//! A few ranges are kept as ranges: a map entry each, with the range's
//! bytes in chunks that go to the stream's received data without a copy
//! once the gap before them fills. A chunk is a piece of the driver's read
//! buffer, referenced as in-order data is (and subject to the session's bound
//! on the buffers it keeps alive), or
//! storage of the range's own for pieces below the copy threshold. A peer that scatters small pieces beyond holes would make that
//! bookkeeping cost far more than the bytes it holds, so once a stream's
//! ranges cost more than an eighth of its span (the offsets from what the
//! application read to the highest received, which flow control charges),
//! the data moves to a flat store over the span: pages of [`PAGE`] bytes
//! allocated when first written and a presence bitmap of one bit per byte,
//! whose size no longer depends on the number of ranges. It moves back to
//! ranges once nothing is held out of order.

use std::collections::{BTreeMap, VecDeque};

use bytes::{Buf, Bytes, BytesMut};

use super::recv_buf::{Backing, REFERENCE_MIN, RecvBuf};

use super::ranges::RangeSet;

/// The page of the flat store.
pub(crate) const PAGE: usize = 4096;

/// Bookkeeping of one held range in range mode: its map entry (key and
/// buffer handle, with the tree's node overhead) and its allocation's
/// header and rounding.
const RANGE_COST: u64 = 96;

/// Bookkeeping of one range of an arrival set in range mode.
const ARRIVAL_RANGE_COST: u64 = 16;

/// Ranges are cheap below this many, whatever the span.
const FEW_RANGES: usize = 8;

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

    /// Removes the offsets below `floor`; returns how many were in the set.
    pub(crate) fn remove_below(&mut self, floor: u64) -> u64 {
        let mut removed = 0;
        while let Some(&w) = self.words.front() {
            if self.first + 64 > floor {
                break;
            }
            removed += u64::from(w.count_ones());
            self.words.pop_front();
            self.first += 64;
        }
        if let Some(w) = self.words.front_mut()
            && floor > self.first
        {
            let m = mask(0, floor - self.first);
            removed += u64::from((*w & m).count_ones());
            *w &= !m;
        }
        self.ones -= removed;
        self.trim();
        removed
    }

    /// Removes the offsets at or beyond `limit`; returns how many were in
    /// the set.
    pub(crate) fn remove_from(&mut self, limit: u64) -> u64 {
        let mut removed = 0;
        while let Some(&w) = self.words.back() {
            let start = self.first + (self.words.len() as u64 - 1) * 64;
            if start < limit {
                let m = mask(limit - start, 64);
                removed += u64::from((w & m).count_ones());
                if let Some(w) = self.words.back_mut() {
                    *w &= !m;
                }
                break;
            }
            removed += u64::from(w.count_ones());
            self.words.pop_back();
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
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ones == 0
    }

    /// Whether `at` is in the set.
    pub(crate) fn contains(&self, at: u64) -> bool {
        self.word_of(at)
            .is_some_and(|i| self.words[i] >> ((at - self.first) % 64) & 1 == 1)
    }

    /// The lowest offset in the set.
    pub(crate) fn first(&self) -> Option<u64> {
        self.words
            .iter()
            .position(|&w| w != 0)
            .map(|i| self.first + i as u64 * 64 + u64::from(self.words[i].trailing_zeros()))
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

    /// The ranges of the set, in order.
    #[cfg(test)]
    fn ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        let mut at = self.first;
        std::iter::from_fn(move || {
            let s = self.first_from(at)?;
            let e = self.run_end(s);
            at = e;
            Some((s, e))
        })
    }

    /// The first offset in the set at or beyond `at`.
    fn first_from(&self, at: u64) -> Option<u64> {
        let at = at.max(self.first);
        let mut i = self.word_of(at)?;
        let mut w = self.words[i] & mask((at - self.first) % 64, 64);
        loop {
            if w != 0 {
                return Some(self.first + i as u64 * 64 + u64::from(w.trailing_zeros()));
            }
            i += 1;
            w = *self.words.get(i)?;
        }
    }

    fn memory(&self) -> usize {
        self.words.capacity() * 8
    }
}

/// Bits `lo..hi` of a word.
fn mask(lo: u64, hi: u64) -> u64 {
    let upper = if hi >= 64 { u64::MAX } else { (1u64 << hi) - 1 };
    upper & !((1u64 << lo) - 1)
}

/// Stream offsets that arrived beyond the contiguous ones (session credit,
/// SPEC.md Section 8.3): ranges while they are few, a bitmap over the span
/// once they cost more than an eighth of it.
#[derive(Debug)]
pub(crate) enum Arrived {
    Ranges(RangeSet),
    Bits(Bits),
}

impl Default for Arrived {
    fn default() -> Self {
        Self::Ranges(RangeSet::new())
    }
}

impl Arrived {
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            Self::Ranges(r) => r.is_empty(),
            Self::Bits(b) => b.is_empty(),
        }
    }

    /// Adds `[start, end)`, all beyond `floor` (the contiguous end); returns
    /// the offsets that were new.
    pub(crate) fn insert(&mut self, start: u64, end: u64, floor: u64) -> u64 {
        match self {
            Self::Ranges(r) => {
                let n = r.insert(start, end);
                let count = r.len();
                if count > FEW_RANGES {
                    let span = r.end().unwrap_or(floor) - floor;
                    if count as u64 * ARRIVAL_RANGE_COST > span / 8 {
                        let mut b = Bits::default();
                        for (s, e) in r.iter() {
                            b.insert(s, e);
                        }
                        *self = Self::Bits(b);
                    }
                }
                n
            }
            Self::Bits(b) => b.insert(start, end),
        }
    }

    /// The end of the run that starts at or below `floor`, if any: the new
    /// contiguous end. What lies below it leaves the set.
    pub(crate) fn advance(&mut self, floor: u64) -> Option<u64> {
        match self {
            Self::Ranges(r) => {
                let (s, e) = r.first()?;
                if s > floor {
                    return None;
                }
                r.remove_below(e);
                Some(e)
            }
            Self::Bits(b) => {
                b.remove_below(floor);
                if !b.contains(floor) {
                    return None;
                }
                let e = b.run_end(floor);
                b.remove_below(e);
                if b.is_empty() {
                    *self = Self::default();
                }
                Some(e)
            }
        }
    }

    /// Offsets of `[start, end)` in the set.
    pub(crate) fn covered(&self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        match self {
            Self::Ranges(r) => r.covered(start, end),
            Self::Bits(b) => b.covered(start, end),
        }
    }

    /// Heap bytes of the bookkeeping.
    pub(crate) fn memory(&self) -> usize {
        match self {
            Self::Ranges(r) => r.len() * ARRIVAL_RANGE_COST as usize,
            Self::Bits(b) => b.memory(),
        }
    }
}

/// Data held beyond a gap.
#[derive(Debug, Default)]
pub(crate) struct Held {
    mode: Mode,
    /// Bytes held.
    bytes: u64,
    /// Bytes held in pieces of read buffers.
    referenced: u64,
}

#[derive(Debug)]
enum Mode {
    /// Non-overlapping ranges by offset; adjacent data extends a range.
    Ranges(Ranges),
    /// Pages over the span with a presence bitmap.
    Flat(Box<Flat>),
}

impl Default for Mode {
    fn default() -> Self {
        Self::Ranges(Ranges::default())
    }
}

#[derive(Debug, Default)]
struct Flat {
    present: Bits,
    /// Pages from offset `first` (a multiple of [`PAGE`]).
    first: u64,
    pages: VecDeque<Option<Box<[u8; PAGE]>>>,
}

/// The held ranges of range mode, by offset, and their chunks counted.
#[derive(Debug, Default)]
struct Ranges {
    map: BTreeMap<u64, Range>,
    chunks: usize,
}

/// One held range: its bytes in chunks, in order. Data that extends the
/// range is added to it without moving what it holds, and the chunks go to
/// the stream's received data as they are once the gap before them fills.
#[derive(Debug, Default)]
struct Range {
    chunks: Vec<Chunk>,
    len: u64,
}

/// A chunk of a held range.
#[derive(Debug)]
enum Chunk {
    /// Copies, in storage of the range's own that small pieces share.
    Own(BytesMut),
    /// A piece of a read buffer, referenced.
    Ref(Bytes, Backing),
}

impl Chunk {
    fn len(&self) -> usize {
        match self {
            Self::Own(b) => b.len(),
            Self::Ref(b, _) => b.len(),
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Own(b) => b,
            Self::Ref(b, _) => b,
        }
    }

    /// Bytes of a read buffer.
    fn referenced(&self) -> u64 {
        match self {
            Self::Own(_) => 0,
            Self::Ref(b, _) => b.len() as u64,
        }
    }
}

/// Where a piece being stored lies: in the read buffer the driver handed
/// over (it may be referenced), or not.
pub(crate) type Source<'a> = Option<(&'a Bytes, Backing)>;

/// The piece `part` of `src` as a reference of it, when it is large enough
/// and lies in it.
fn reference(src: Source<'_>, part: &[u8]) -> Option<(Bytes, Backing)> {
    let (whole, backing) = src?;
    if part.len() < REFERENCE_MIN {
        return None;
    }
    let (w, p) = (whole.as_ptr() as usize, part.as_ptr() as usize);
    (p >= w && p + part.len() <= w + whole.len()).then(|| (whole.slice_ref(part), backing))
}

/// The smallest chunk: small pieces share one.
const CHUNK_MIN: usize = 4096;

/// Bookkeeping of one chunk: its handle in the range and its allocation's
/// header and rounding.
const CHUNK_COST: u64 = 48;

impl Range {
    /// Appends `piece`, referenced when it is a large piece of `src`, else
    /// copied; returns the chunks added (0 or 1) and the bytes referenced.
    fn push(&mut self, piece: &[u8], src: Source<'_>) -> (usize, u64) {
        self.len += piece.len() as u64;
        if let Some((b, backing)) = reference(src, piece) {
            self.chunks.push(Chunk::Ref(b, backing));
            return (1, piece.len() as u64);
        }
        if let Some(Chunk::Own(last)) = self.chunks.last_mut()
            && last.capacity() - last.len() >= piece.len()
        {
            last.extend_from_slice(piece);
            return (0, 0);
        }
        let mut c = BytesMut::with_capacity(piece.len().max(CHUNK_MIN));
        c.extend_from_slice(piece);
        self.chunks.push(Chunk::Own(c));
        (1, 0)
    }

    /// Bytes of read buffers it references.
    fn referenced(&self) -> u64 {
        self.chunks.iter().map(Chunk::referenced).sum()
    }

    /// Appends the range that follows this one, moving its chunks.
    fn append(&mut self, next: Range) {
        self.len += next.len;
        self.chunks.extend(next.chunks);
    }

    /// Keeps the first `keep` bytes; returns the chunks dropped.
    fn truncate(&mut self, keep: u64) -> usize {
        let mut left = keep;
        let mut n = 0;
        for c in &mut self.chunks {
            if left == 0 {
                break;
            }
            let k = (c.len() as u64).min(left);
            match c {
                Chunk::Own(b) => b.truncate(k as usize),
                Chunk::Ref(b, _) => b.truncate(k as usize),
            }
            left -= k;
            n += 1;
        }
        let dropped = self.chunks.len() - n;
        self.chunks.truncate(n);
        self.len = keep.min(self.len);
        dropped
    }

    /// Heap bytes: its own storage, the chunk list, and twice the bytes
    /// it references (the read buffers they keep alive, within the
    /// session's bound).
    fn capacity(&self) -> usize {
        self.chunks
            .iter()
            .map(|c| match c {
                Chunk::Own(b) => b.capacity(),
                Chunk::Ref(b, _) => 2 * b.len(),
            })
            .sum::<usize>()
            + self.chunks.capacity() * std::mem::size_of::<Chunk>()
    }
}

impl Ranges {
    /// The bookkeeping cost of the ranges (the flat store's trigger).
    fn cost(&self) -> u64 {
        self.map.len() as u64 * RANGE_COST + self.chunks as u64 * CHUNK_COST
    }

    /// Removes the range at `off`.
    fn remove(&mut self, off: u64) -> Option<Range> {
        let r = self.map.remove(&off)?;
        self.chunks -= r.chunks.len();
        Some(r)
    }

    /// Inserts `data` at `off`, trimmed against the ranges held; returns
    /// the bytes stored and the bytes of them referenced.
    fn store(&mut self, mut off: u64, mut data: &[u8], src: Source<'_>) -> (u64, u64) {
        let mut stored = 0u64;
        let mut referenced = 0u64;
        while !data.is_empty() {
            let end = off + data.len() as u64;
            if let Some((&o, r)) = self.map.range(..=off).next_back() {
                let r_end = o + r.len;
                if r_end > off {
                    // Overlaps the held range: skip what it covers.
                    let covered = (r_end.min(end) - off) as usize;
                    off += covered as u64;
                    data = &data[covered..];
                    continue;
                }
            }
            let next = self.map.range(off..).next().map(|(&o, _)| o);
            let until = next.map_or(end, |n| n.min(end));
            let k = (until - off) as usize;
            referenced += self.insert(off, &data[..k], next == Some(until), src);
            stored += k as u64;
            off = until;
            data = &data[k..];
        }
        (stored, referenced)
    }

    /// Holds `piece` at `off`, in no held range; `touches_next` when a held
    /// range starts at its end. Data that continues a range extends it, and
    /// a range takes the chunks of the one after it when that one is not
    /// longer, which keeps the chunks moved linear in the bytes held.
    /// Returns the bytes referenced.
    fn insert(&mut self, off: u64, piece: &[u8], touches_next: bool, src: Source<'_>) -> u64 {
        let end = off + piece.len() as u64;
        let prev = self
            .map
            .range(..off)
            .next_back()
            .filter(|(o, r)| **o + r.len == off)
            .map(|(&o, _)| o);
        let next_len = if touches_next {
            self.map.get(&end).map(|r| r.len)
        } else {
            None
        };
        match prev {
            Some(p) => {
                let Some(r) = self.map.get_mut(&p) else {
                    return 0;
                };
                let (added, referenced) = r.push(piece, src);
                self.chunks += added;
                let len = r.len;
                if next_len.is_some_and(|n| n <= len)
                    && let Some(n) = self.map.remove(&end)
                    && let Some(r) = self.map.get_mut(&p)
                {
                    r.append(n);
                }
                referenced
            }
            None => {
                let mut r = Range::default();
                let (added, referenced) = r.push(piece, src);
                self.chunks += added;
                if next_len.is_some_and(|n| n <= r.len)
                    && let Some(n) = self.map.remove(&end)
                {
                    r.append(n);
                }
                self.map.insert(off, r);
                referenced
            }
        }
    }
}

impl Flat {
    /// Copies `data` to offset `off`; returns the bytes that were new.
    fn write(&mut self, off: u64, data: &[u8]) -> u64 {
        if data.is_empty() {
            return 0;
        }
        let page = PAGE as u64;
        if self.pages.is_empty() {
            self.first = off - off % page;
        }
        while off < self.first {
            self.pages.push_front(None);
            self.first -= page;
        }
        let mut at = off;
        let mut rest = data;
        while !rest.is_empty() {
            let i = ((at - self.first) / page) as usize;
            if self.pages.len() <= i {
                self.pages.resize_with(i + 1, || None);
            }
            let p = self.pages[i].get_or_insert_with(|| Box::new([0; PAGE]));
            let o = ((at - self.first) % page) as usize;
            let k = (PAGE - o).min(rest.len());
            p[o..o + k].copy_from_slice(&rest[..k]);
            rest = &rest[k..];
            at += k as u64;
        }
        self.present.insert(off, at)
    }

    /// Appends the held bytes of `[start, end)` (all present) to `out`.
    fn read_into(&self, start: u64, end: u64, out: &mut RecvBuf) {
        let page = PAGE as u64;
        let mut at = start;
        while at < end {
            let i = ((at - self.first) / page) as usize;
            let o = ((at - self.first) % page) as usize;
            let k = ((page - o as u64).min(end - at)) as usize;
            if let Some(Some(p)) = self.pages.get(i) {
                out.push_copy(&p[o..o + k]);
            }
            at += k as u64;
        }
    }

    /// Frees the pages that hold nothing at the ends.
    fn trim(&mut self) {
        let page = PAGE as u64;
        if self.present.is_empty() {
            self.pages.clear();
            return;
        }
        while !self.pages.is_empty() && self.present.covered(self.first, self.first + page) == 0 {
            self.pages.pop_front();
            self.first += page;
        }
        while let Some(last) = self.pages.len().checked_sub(1) {
            let s = self.first + last as u64 * page;
            if self.present.covered(s, s + page) > 0 {
                break;
            }
            self.pages.pop_back();
        }
    }

    fn memory(&self) -> usize {
        self.present.memory()
            + self.pages.capacity() * std::mem::size_of::<Option<Box<[u8; PAGE]>>>()
            + self.pages.iter().flatten().count() * PAGE
    }
}

impl Held {
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// Bytes held.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The lowest offset held.
    pub(crate) fn first(&self) -> Option<u64> {
        match &self.mode {
            Mode::Ranges(m) => m.map.keys().next().copied(),
            Mode::Flat(f) => f.present.first(),
        }
    }

    /// Ranges held beyond a gap.
    #[cfg(test)]
    pub(crate) fn ranges(&self) -> usize {
        match &self.mode {
            Mode::Ranges(m) => m.map.len(),
            Mode::Flat(f) => f.present.ranges().count(),
        }
    }

    /// Whether the flat store is in use.
    #[cfg(test)]
    pub(crate) fn is_flat(&self) -> bool {
        matches!(self.mode, Mode::Flat(_))
    }

    /// Stores `data` at `off`, all beyond the contiguous data; bytes already
    /// held are duplicates. `span_from` is where the span starts (what the
    /// application read); `src` the read buffer `data` lies in, if any.
    /// Returns the bytes newly stored.
    pub(crate) fn store(&mut self, off: u64, data: &[u8], span_from: u64, src: Source<'_>) -> u64 {
        let stored = match &mut self.mode {
            Mode::Ranges(m) => {
                let (stored, referenced) = m.store(off, data, src);
                self.referenced += referenced;
                stored
            }
            Mode::Flat(f) => f.write_new(off, data),
        };
        self.bytes += stored;
        if let Mode::Ranges(m) = &self.mode
            && m.map.len() > FEW_RANGES
        {
            let end = m.map.last_key_value().map_or(0, |(&o, r)| o + r.len);
            if m.cost() > (end - span_from) / 8 {
                self.go_flat();
            }
        }
        stored
    }

    fn go_flat(&mut self) {
        let Mode::Ranges(m) = std::mem::take(&mut self.mode) else {
            return;
        };
        let mut f = Flat::default();
        for (mut o, r) in m.map {
            for c in &r.chunks {
                f.write(o, c.bytes());
                o += c.len() as u64;
            }
        }
        self.referenced = 0;
        self.mode = Mode::Flat(Box::new(f));
    }

    /// Moves the data that continues `contig` into `buf`; returns the new
    /// contiguous end and the bytes held below `contig`, dropped.
    pub(crate) fn pull(&mut self, mut contig: u64, buf: &mut RecvBuf) -> (u64, u64) {
        let mut trimmed = 0;
        match &mut self.mode {
            Mode::Ranges(m) => {
                while let Some(o) = m.map.keys().next().copied().filter(|&o| o <= contig) {
                    let Some(r) = m.remove(o) else {
                        break;
                    };
                    self.bytes -= r.len;
                    self.referenced -= r.referenced();
                    let mut skip = (contig - o).min(r.len);
                    trimmed += skip;
                    if skip == r.len {
                        continue;
                    }
                    // The chunks go as they are, without the bytes below
                    // `contig`.
                    for c in r.chunks {
                        let k = (c.len() as u64).min(skip);
                        skip -= k;
                        if k as usize == c.len() {
                            continue;
                        }
                        match c {
                            Chunk::Own(mut b) => {
                                b.advance(k as usize);
                                buf.push_owned(b.freeze());
                            }
                            Chunk::Ref(mut b, backing) => {
                                b.advance(k as usize);
                                buf.push_shared(b, backing);
                            }
                        }
                    }
                    contig = o + r.len;
                }
            }
            Mode::Flat(f) => {
                trimmed = f.present.remove_below(contig);
                self.bytes -= trimmed;
                if f.present.contains(contig) {
                    let end = f.present.run_end(contig);
                    f.read_into(contig, end, buf);
                    let n = f.present.remove_below(end);
                    self.bytes -= n;
                    contig = end;
                }
                f.trim();
                if self.bytes == 0 {
                    self.mode = Mode::default();
                }
            }
        }
        (contig, trimmed)
    }

    /// Drops the data at or beyond `limit`; returns the bytes dropped.
    pub(crate) fn drop_from(&mut self, limit: u64) -> u64 {
        let mut dropped = 0;
        match &mut self.mode {
            Mode::Ranges(m) => {
                while let Some((&o, r)) = m.map.last_key_value() {
                    let len = r.len;
                    if o + len <= limit {
                        break;
                    }
                    if o >= limit {
                        if let Some(r) = m.remove(o) {
                            self.referenced -= r.referenced();
                        }
                        dropped += len;
                    } else {
                        let k = o + len - limit;
                        if let Some(r) = m.map.get_mut(&o) {
                            let before = r.referenced();
                            m.chunks -= r.truncate(len - k);
                            self.referenced -= before - r.referenced();
                        }
                        dropped += k;
                        break;
                    }
                }
            }
            Mode::Flat(f) => {
                dropped = f.present.remove_from(limit);
                f.trim();
            }
        }
        self.bytes -= dropped;
        if self.bytes == 0 {
            self.mode = Mode::default();
        }
        dropped
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }

    /// Whether any chunk references a read buffer.
    pub(crate) fn references(&self) -> bool {
        self.referenced > 0
    }

    /// Bytes of the chunks that reference read buffers.
    pub(crate) fn referenced(&self) -> u64 {
        self.referenced
    }

    /// Calls `f` with each read buffer the chunks reference and the bytes
    /// they reference in it (a run of chunks of one buffer at a time).
    pub(crate) fn tally(&self, f: &mut impl FnMut(Backing, usize)) {
        let Mode::Ranges(m) = &self.mode else {
            return;
        };
        if self.referenced == 0 {
            return;
        }
        let mut run: Option<(Backing, usize)> = None;
        for c in m.map.values().flat_map(|r| &r.chunks) {
            let Chunk::Ref(b, k) = c else {
                continue;
            };
            match &mut run {
                Some((rk, n)) if rk.id == k.id => *n += b.len(),
                _ => {
                    if let Some((rk, n)) = run.replace((*k, b.len())) {
                        f(rk, n);
                    }
                }
            }
        }
        if let Some((rk, n)) = run {
            f(rk, n);
        }
    }

    /// Copies the chunks of the read buffers `out` names into storage of
    /// their own (the session's bound on the buffers kept alive).
    pub(crate) fn copy_out(&mut self, out: &impl Fn(u64) -> bool) {
        let Mode::Ranges(m) = &mut self.mode else {
            return;
        };
        for c in m.map.values_mut().flat_map(|r| r.chunks.iter_mut()) {
            if let Chunk::Ref(b, k) = c
                && out(k.id)
            {
                self.referenced -= b.len() as u64;
                *c = Chunk::Own(BytesMut::from(&b[..]));
            }
        }
    }

    /// Heap bytes held, with the bookkeeping.
    pub(crate) fn memory(&self) -> usize {
        match &self.mode {
            Mode::Ranges(m) => {
                m.map
                    .values()
                    .map(|r| r.capacity() + RANGE_COST as usize)
                    .sum::<usize>()
                    + m.chunks * CHUNK_COST as usize
            }
            Mode::Flat(f) => std::mem::size_of::<Flat>() + f.memory(),
        }
    }
}

impl Flat {
    /// Stores the bytes of `data` at `off` that are not held yet; returns
    /// how many. Held bytes keep their copy (a retransmission repeats them).
    fn write_new(&mut self, off: u64, data: &[u8]) -> u64 {
        let end = off + data.len() as u64;
        let mut stored = 0;
        let mut at = off;
        while at < end {
            if self.present.contains(at) {
                at = self.present.run_end(at).min(end);
                continue;
            }
            let next = self.present.first_from(at).map_or(end, |n| n.min(end));
            let s = (at - off) as usize;
            let e = (next - off) as usize;
            stored += self.write(at, &data[s..e]);
            at = next;
        }
        stored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Held {
        /// Stores a copy (no read buffer).
        fn store_copy(&mut self, off: u64, data: &[u8], span_from: u64) -> u64 {
            self.store(off, data, span_from, None)
        }
    }

    #[test]
    fn bits_insert_count_and_runs() {
        let mut b = Bits::default();
        assert_eq!(b.insert(100, 200), 100);
        assert_eq!(b.insert(150, 250), 50);
        assert_eq!(b.insert(10, 20), 10);
        assert_eq!(b.first(), Some(10));
        assert_eq!(b.run_end(10), 20);
        assert_eq!(b.run_end(100), 250);
        assert_eq!(b.covered(0, 1000), 160);
        assert_eq!(b.ranges().collect::<Vec<_>>(), vec![(10, 20), (100, 250)]);
        assert_eq!(b.remove_below(120), 30);
        assert_eq!(b.first(), Some(120));
        assert_eq!(b.remove_from(200), 50);
        assert_eq!(b.covered(0, 1000), 80);
        assert_eq!(b.remove_below(1000), 80);
        assert!(b.is_empty());
        assert_eq!(b.memory(), b.words.capacity() * 8);
    }

    /// Ranges grow and merge by their chunks; a pull hands the chunks over
    /// in order, without the bytes below the contiguous end, and a drop
    /// truncates the last range.
    #[test]
    fn ranges_keep_their_chunks_in_order() {
        let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        let mut h = Held::default();
        assert_eq!(h.store_copy(20_000, &data[20_000..30_000], 0), 10_000);
        assert_eq!(h.store_copy(30_000, &data[30_000..40_000], 0), 10_000);
        assert_eq!(h.store_copy(10_000, &data[10_000..20_000], 0), 10_000);
        // A repeat across two chunks stores nothing.
        assert_eq!(h.store_copy(15_000, &data[15_000..25_000], 0), 0);
        // The range after the new one is longer: they stay apart.
        assert_eq!(h.ranges(), 2);
        assert_eq!(h.drop_from(35_000), 5_000);
        let mut buf = RecvBuf::default();
        buf.push_copy(&data[..12_000]);
        let (contig, trimmed) = h.pull(12_000, &mut buf);
        assert_eq!((contig, trimmed), (35_000, 2_000));
        assert!(h.is_empty());
        let mut out = vec![0u8; buf.len()];
        assert_eq!(buf.copy_to(&mut out), 35_000);
        assert_eq!(&out[..], &data[..35_000]);
    }

    #[test]
    fn scattered_bytes_move_to_the_flat_store_and_back() {
        let mut h = Held::default();
        let mut buf = RecvBuf::default();
        // One byte at every other offset beyond a hole at 0.
        for i in 0..10_000u64 {
            assert_eq!(h.store_copy(1 + 2 * i, &[i as u8], 0), 1);
        }
        assert!(h.is_flat());
        assert_eq!(h.bytes(), 10_000);
        // A repeat stores nothing.
        assert_eq!(h.store_copy(1, &[0, 0, 0], 0), 1);
        assert_eq!(h.bytes(), 10_001);
        // Bookkeeping within an eighth of the span, plus the pages.
        assert!(
            h.memory() <= 20_001 / 8 + 20_001 + 2 * PAGE + 256,
            "{}",
            h.memory()
        );
        // Filling the holes delivers everything in order.
        let mut contig = 0;
        for i in 0..=10_000u64 {
            let at = 2 * i;
            if at < contig {
                continue;
            }
            buf.push_copy(&[0xaa]);
            contig = at + 1;
            let (c, t) = h.pull(contig, &mut buf);
            assert_eq!(t, 0);
            contig = c;
        }
        assert_eq!(contig, 20_001);
        assert!(h.is_empty() && !h.is_flat());
        assert_eq!(buf.len(), 20_001);
        let mut out = vec![0u8; buf.len()];
        buf.copy_to(&mut out);
        let buf = out;
        assert_eq!(buf[1], 0);
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 1);
        assert_eq!(buf[5], 2);
    }
}
