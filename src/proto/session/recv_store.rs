//! Session-local storage for accepted receive ranges. Ordered ranges carry
//! indices and offsets. Immutable backing views are owned by the span table.

use std::cell::Cell;
use std::num::NonZeroU32;

use super::recv_buf::{Backing, Segment};
use bytes::{Buf, Bytes, BytesMut};
use std::collections::VecDeque;

use crate::proto::receive;

/// Stable until its slot is removed. Zero is the sentinel in queue and tree links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key(NonZeroU32);

impl Key {
    fn new(index: usize) -> Self {
        Self(NonZeroU32::new(u32::try_from(index + 1).expect("receive index fits in u32")).unwrap())
    }

    const fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

#[derive(Debug)]
enum Slot<T> {
    Live(T),
    Free(Option<Key>),
}

#[derive(Debug)]
struct Slots<T> {
    rows: Vec<Slot<T>>,
    free: Option<Key>,
}

impl<T> Default for Slots<T> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            free: None,
        }
    }
}

impl<T> Slots<T> {
    const INITIAL: usize = 4;

    fn insert(&mut self, value: T) -> Key {
        if let Some(key) = self.free {
            let old = std::mem::replace(&mut self.rows[key.index()], Slot::Live(value));
            let Slot::Free(next) = old else {
                unreachable!("free receive slot")
            };
            self.free = next;
            return key;
        }
        let key = Key::new(self.rows.len());
        if self.rows.len() == self.rows.capacity() {
            // The commitment covers the occupied table and one geometric
            // growth even if the allocator has to move the allocation.
            let additional = self.rows.len().max(Self::INITIAL);
            self.rows.reserve_exact(additional);
        }
        self.rows.push(Slot::Live(value));
        key
    }

    fn get(&self, key: Key) -> &T {
        match &self.rows[key.index()] {
            Slot::Live(value) => value,
            Slot::Free(_) => unreachable!("live receive slot"),
        }
    }

    fn get_mut(&mut self, key: Key) -> &mut T {
        match &mut self.rows[key.index()] {
            Slot::Live(value) => value,
            Slot::Free(_) => unreachable!("live receive slot"),
        }
    }

    fn remove(&mut self, key: Key) -> T {
        let old = std::mem::replace(&mut self.rows[key.index()], Slot::Free(self.free));
        self.free = Some(key);
        let Slot::Live(value) = old else {
            unreachable!("live receive slot")
        };
        value
    }

    fn heap_bytes(&self) -> usize {
        self.rows.capacity() * size_of::<Slot<T>>()
    }

    fn occupied(&self) -> impl Iterator<Item = &T> {
        self.rows.iter().filter_map(|slot| match slot {
            Slot::Live(value) => Some(value),
            Slot::Free(_) => None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Range {
    span: Key,
    start: u32,
    len: u32,
}

impl Range {
    fn slice(self) -> std::ops::Range<usize> {
        self.start as usize..self.start as usize + self.len as usize
    }
}

#[derive(Debug)]
struct Span {
    segment: Segment,
    users: u32,
    copied_input: bool,
}

#[derive(Clone, Copy, Debug)]
struct Node {
    offset: u64,
    range: Range,
    left: Option<Key>,
    right: Option<Key>,
    height: u8,
}

impl Node {
    fn end(self) -> u64 {
        self.offset + u64::from(self.range.len)
    }
}

/// The endpoint's span and descriptor storage. In-order data is a FIFO;
/// while a hole exists the same nodes are indexed by stream offset in an AVL tree.
#[derive(Debug, Default)]
pub(super) struct ReceiveStore {
    arenas: Option<Box<ReceiveArenas>>,
    copied: usize,
    copies: Option<Box<CopiedInput>>,
}

#[derive(Debug, Default)]
struct ReceiveArenas {
    nodes: Slots<Node>,
    spans: Slots<Span>,
}

static EMPTY_ARENAS: ReceiveArenas = ReceiveArenas {
    nodes: Slots {
        rows: Vec::new(),
        free: None,
    },
    spans: Slots {
        rows: Vec::new(),
        free: None,
    },
};

#[derive(Debug, Default)]
struct CopiedInput {
    tail: Option<CopyBlock>,
    /// Each retired block still has at least one span in the queue. This
    /// handle returns it to the pool when the queue's last span leaves.
    retired: VecDeque<CopyBlock>,
}

#[derive(Debug)]
struct CopyBlock {
    tail: BytesMut,
    root: Backing,
    spans: u32,
}

impl Drop for CopyBlock {
    fn drop(&mut self) {
        receive::give_streaming(std::mem::take(&mut self.tail), self.root.size);
    }
}

impl CopiedInput {
    fn pack(&mut self, data: &[u8]) -> (Segment, usize) {
        let mut retired = 0;
        if self.tail.as_mut().is_none_or(|block| {
            if block.tail.capacity() >= data.len() {
                return false;
            }
            if !block.tail.try_reclaim(data.len()) {
                return true;
            }
            // Reclaim can move the visible tail only once every previous
            // view has gone. Appending to an existing tail keeps its ID.
            block.root = Backing::new(block.root.size);
            false
        }) {
            let tail = receive::take_streaming(data.len());
            let root = Backing::new(tail.capacity());
            let next = CopyBlock {
                tail,
                root,
                spans: 0,
            };
            if let Some(old) = self.tail.replace(next)
                && old.spans != 0
            {
                retired = old.root.size;
                if self.retired.len() == self.retired.capacity() {
                    self.retired.reserve_exact(self.retired.len().max(4));
                }
                self.retired.push_back(old);
            }
        }
        let block = self.tail.as_mut().expect("copy block installed");
        block.tail.extend_from_slice(data);
        let bytes = block.tail.split().freeze();
        block.spans += 1;
        (
            Segment {
                bytes,
                backing: block.root,
            },
            retired,
        )
    }

    fn release(&mut self, root: Backing) {
        if let Some(block) = &mut self.tail
            && block.root.id == root.id
        {
            block.spans -= 1;
            return;
        }
        let index = self
            .retired
            .binary_search_by_key(&root.id, |block| block.root.id)
            .expect("live copy block");
        let block = &mut self.retired[index];
        block.spans -= 1;
        if block.spans == 0 {
            self.retired.remove(index);
        }
    }
}

impl ReceiveStore {
    /// The descriptor index has a zero sentinel. Two more entries can be
    /// live while an input span is being handed over or a root compacted.
    pub(super) const MAX_POSITIONS: u64 = u32::MAX as u64 - 2;
    // The two arenas, the copy-owner queue and the root-tally scratch
    // allow their old and growing allocations to coexist. The bytes
    // owner adds at most a small header for each independently held root.
    const DESCRIPTOR: u64 = 3
        * (size_of::<Slot<Node>>()
            + size_of::<Slot<Span>>()
            + size_of::<CopyBlock>()
            + size_of::<(u64, usize, usize)>()) as u64
        + 6 * size_of::<usize>() as u64;

    // Gap nodes can temporarily double when a frame splits around them.
    // Each contiguous promotion adds at most one node per page before
    // the ready list is packed. The allowances cover clipped page edges
    // and the receive turn's unattached span as well.
    const DESCRIPTORS_PER_PAGE: u64 = 8;
    const DESCRIPTORS_PER_DIRECTION: u64 = 40;

    // One byte of payload per compact page position, its directory, and
    // the temporary old/new capacity of the two presence bitmaps.
    const PAGE_ROW: u64 = 6 * size_of::<Option<Page>>() as u64;
    pub(super) const POSITION_COST: u64 = 3
        + 1
        + 2
        + (Self::PAGE_ROW + Self::DESCRIPTORS_PER_PAGE * Self::DESCRIPTOR).div_ceil(PAGE as u64);

    // A direction can have two partially occupied pages, and adds fixed
    // bitmap alignment, directory rounding, and the small range allowance.
    pub(super) const DIRECTION_ARENA: u64 = Self::DESCRIPTORS_PER_DIRECTION * Self::DESCRIPTOR;
    pub(super) const DIRECTION_PRIVATE: u64 = 2 * (PAGE as u64 + Self::PAGE_ROW)
        + size_of::<ReceiveQueue>() as u64
        + size_of::<Sparse>() as u64
        + size_of::<super::reasm::Arrived>() as u64
        + super::reasm::EVIDENCE_MARGIN as u64;
    pub(super) const DIRECTION_COST: u64 = Self::DIRECTION_ARENA + Self::DIRECTION_PRIVATE;

    pub(super) const BASE_COST: u64 = (Slots::<Node>::INITIAL * size_of::<Slot<Node>>()
        + (Slots::<Span>::INITIAL + 6) * size_of::<Slot<Span>>()
        + size_of::<ReceiveArenas>()
        + size_of::<CopiedInput>()
        + 4 * size_of::<CopyBlock>()) as u64;

    pub(super) fn heap_bytes(&self) -> usize {
        self.arenas.as_deref().map_or(0, |arenas| {
            size_of::<ReceiveArenas>() + arenas.nodes.heap_bytes() + arenas.spans.heap_bytes()
        }) + self.copies.as_deref().map_or(0, |copies| {
            size_of::<CopiedInput>() + copies.retired.capacity() * size_of::<CopyBlock>()
        })
    }

    fn arenas(&self) -> &ReceiveArenas {
        self.arenas.as_deref().unwrap_or(&EMPTY_ARENAS)
    }

    fn arenas_mut(&mut self) -> &mut ReceiveArenas {
        self.arenas.as_deref_mut().expect("live receive ranges")
    }

    pub(super) fn take_copied_capacity(&mut self) -> usize {
        std::mem::take(&mut self.copied)
    }

    pub(super) fn discard_unused(&mut self) -> bool {
        if self.arenas().nodes.occupied().next().is_some()
            || self.arenas().spans.occupied().next().is_some()
        {
            return false;
        }
        *self = Self::default();
        true
    }

    pub(super) fn copying_backing(&self) -> Option<Backing> {
        Some(self.copies.as_deref()?.tail.as_ref()?.root)
    }

    /// Lists each charged root once, with the live payload of its ranges.
    pub(super) fn tally(&self, roots: &mut Vec<(u64, usize, usize)>) {
        roots.clear();
        if roots.capacity() < self.arenas().nodes.rows.len() {
            roots.reserve_exact(self.arenas().nodes.rows.len());
        }
        roots.extend(self.arenas().nodes.occupied().map(|node| {
            let root = self.arenas().spans.get(node.range.span).segment.backing;
            (root.id, root.size, node.range.len as usize)
        }));
        roots.sort_unstable_by_key(|&(id, _, _)| id);
        roots.dedup_by(|next, root| {
            if next.0 != root.0 {
                return false;
            }
            root.2 += next.2;
            true
        });
    }

    /// Packs sparse ranges into exact-capacity blocks. Each selected node
    /// stays in its own queue position, even when many streams share a block.
    pub(super) fn compact(&mut self, selected: &[(u64, usize, usize)]) {
        use crate::proto::receive::MAX_CLASS;

        let mut begin = 0;
        while begin < self.arenas().nodes.rows.len() {
            let mut size = 0;
            let mut end = begin;
            while end < self.arenas().nodes.rows.len() {
                if let Some(node) = self.selected_node(end, selected) {
                    let len = node.range.len as usize;
                    if size != 0 && size + len > MAX_CLASS {
                        break;
                    }
                    size += len;
                }
                end += 1;
            }
            if size == 0 {
                break;
            }
            let mut block = Vec::with_capacity(size);
            for index in begin..end {
                if let Some(node) = self.selected_node(index, selected) {
                    block.extend_from_slice(self.slice(node));
                }
            }
            let span = self.open_span(Segment {
                backing: Backing::new(block.capacity()),
                bytes: Bytes::from(block),
            });
            let mut start = 0;
            for index in begin..end {
                if let Some(node) = self.selected_node(index, selected) {
                    self.arenas_mut().spans.get_mut(span).users += 1;
                    self.arenas_mut().nodes.get_mut(Key::new(index)).range = Range {
                        span,
                        start,
                        len: node.range.len,
                    };
                    start += node.range.len;
                    self.close_span(node.range.span);
                }
            }
            self.close_span(span);
            begin = end;
        }
    }

    fn selected_node(&self, index: usize, selected: &[(u64, usize, usize)]) -> Option<Node> {
        let Slot::Live(node) = self.arenas().nodes.rows[index] else {
            return None;
        };
        let id = self.arenas().spans.get(node.range.span).segment.backing.id;
        selected
            .binary_search_by_key(&id, |root| root.0)
            .ok()
            .map(|_| node)
    }

    fn open_span(&mut self, segment: Segment) -> Key {
        self.insert_span(Span {
            segment,
            users: 1,
            copied_input: false,
        })
    }

    fn insert_span(&mut self, span: Span) -> Key {
        // The first payload initializes the two shared descriptor tables.
        self.arenas
            .get_or_insert_with(Box::default)
            .spans
            .insert(span)
    }

    fn close_span(&mut self, key: Key) {
        let span = self.arenas_mut().spans.get_mut(key);
        span.users -= 1;
        if span.users == 0 {
            let span = self.arenas_mut().spans.remove(key);
            if span.copied_input {
                let backing = span.segment.backing;
                drop(span);
                self.copies
                    .as_mut()
                    .expect("copy block exists")
                    .release(backing);
            }
        }
    }

    fn node(&mut self, offset: u64, span: Key, start: usize, len: usize) -> Key {
        debug_assert!(len > 0);
        let start = u32::try_from(start).expect("start within the receive span");
        let len = u32::try_from(len).expect("length within the receive span");
        self.arenas_mut().spans.get_mut(span).users += 1;
        self.arenas_mut().nodes.insert(Node {
            offset,
            range: Range { span, start, len },
            left: None,
            right: None,
            height: 1,
        })
    }

    fn discard(&mut self, key: Key) -> Node {
        let node = self.arenas_mut().nodes.remove(key);
        self.close_span(node.range.span);
        node
    }

    fn slice(&self, node: Node) -> &[u8] {
        &self.arenas().spans.get(node.range.span).segment.bytes[node.range.slice()]
    }

    fn segment(&self, node: Node, count: usize) -> Segment {
        let span = &self.arenas().spans.get(node.range.span).segment;
        let from = node.range.start as usize;
        Segment {
            bytes: span.bytes.slice(from..from + count),
            backing: span.backing,
        }
    }

    fn take_segment(&mut self, node: Node, count: usize) -> Segment {
        let span = self.arenas_mut().spans.get_mut(node.range.span);
        if count == node.range.len as usize && span.users == 1 {
            // The final descriptor can transfer its owner. Even a view of
            // the whole Bytes would clone it and promote an unshared Vec.
            let mut bytes = std::mem::take(&mut span.segment.bytes);
            bytes.advance(node.range.start as usize);
            bytes.truncate(count);
            Segment {
                bytes,
                backing: span.segment.backing,
            }
        } else {
            self.segment(node, count)
        }
    }

    fn height(&self, key: Option<Key>) -> u8 {
        key.map_or(0, |key| self.arenas().nodes.get(key).height)
    }

    fn set_children(&mut self, key: Key, left: Option<Key>, right: Option<Key>) {
        let height = self.height(left).max(self.height(right)) + 1;
        let node = self.arenas_mut().nodes.get_mut(key);
        node.left = left;
        node.right = right;
        node.height = height;
    }

    fn rotate_left(&mut self, key: Key) -> Key {
        let root = *self.arenas().nodes.get(key);
        let child = root.right.expect("right child");
        let pivot = *self.arenas().nodes.get(child);
        self.set_children(key, root.left, pivot.left);
        self.set_children(child, Some(key), pivot.right);
        child
    }

    fn rotate_right(&mut self, key: Key) -> Key {
        let root = *self.arenas().nodes.get(key);
        let child = root.left.expect("left child");
        let pivot = *self.arenas().nodes.get(child);
        self.set_children(key, pivot.right, root.right);
        self.set_children(child, pivot.left, Some(key));
        child
    }

    fn balance(&mut self, key: Key, mut left: Option<Key>, mut right: Option<Key>) -> Key {
        let l = self.height(left);
        let r = self.height(right);
        if l > r + 1 {
            let child = left.expect("taller left subtree");
            let pivot = *self.arenas().nodes.get(child);
            if self.height(pivot.right) > self.height(pivot.left) {
                left = Some(self.rotate_left(child));
            }
            self.set_children(key, left, right);
            return self.rotate_right(key);
        }
        if r > l + 1 {
            let child = right.expect("taller right subtree");
            let pivot = *self.arenas().nodes.get(child);
            if self.height(pivot.left) > self.height(pivot.right) {
                right = Some(self.rotate_right(child));
            }
            self.set_children(key, left, right);
            return self.rotate_left(key);
        }
        self.set_children(key, left, right);
        key
    }

    fn insert(&mut self, root: Option<Key>, key: Key, offset: u64) -> Key {
        let Some(root) = root else { return key };
        let mut node = *self.arenas().nodes.get(root);
        if offset < node.offset {
            node.left = Some(self.insert(node.left, key, offset));
        } else {
            debug_assert!(offset >= node.end());
            node.right = Some(self.insert(node.right, key, offset));
        }
        self.balance(root, node.left, node.right)
    }

    fn first(&self, mut key: Key) -> Key {
        while let Some(left) = self.arenas().nodes.get(key).left {
            key = left;
        }
        key
    }

    fn last(&self, mut key: Key) -> Key {
        while let Some(right) = self.arenas().nodes.get(key).right {
            key = right;
        }
        key
    }

    fn remove_first(&mut self, key: Key) -> (Option<Key>, Key) {
        let node = *self.arenas().nodes.get(key);
        let Some(left) = node.left else {
            return (node.right, key);
        };
        let (left, first) = self.remove_first(left);
        (Some(self.balance(key, left, node.right)), first)
    }

    fn remove_last(&mut self, key: Key) -> (Option<Key>, Key) {
        let node = *self.arenas().nodes.get(key);
        let Some(right) = node.right else {
            return (node.left, key);
        };
        let (right, last) = self.remove_last(right);
        (Some(self.balance(key, node.left, right)), last)
    }

    /// The node that contains `offset`, or the next held range after it.
    fn at_or_after(&self, mut root: Option<Key>, offset: u64) -> Option<Node> {
        let mut next = None;
        while let Some(key) = root {
            let node = *self.arenas().nodes.get(key);
            if offset < node.offset {
                next = Some(node);
                root = node.left;
            } else if offset < node.end() {
                return Some(node);
            } else {
                root = node.right;
            }
        }
        next
    }
}

/// An input turn temporarily owns one immutable span. All fresh ranges from
/// the turn can refer to it without cloning `Bytes` for each descriptor.
#[derive(Debug)]
pub(super) struct InputSpan<'a> {
    bytes: &'a Bytes,
    backing: Backing,
    span: Cell<Option<Key>>,
}

pub(super) type Source<'a> = Option<&'a InputSpan<'a>>;

impl<'a> InputSpan<'a> {
    pub(super) fn new(bytes: &'a Bytes, backing: Backing) -> Self {
        Self {
            bytes,
            backing,
            span: Cell::new(None),
        }
    }

    fn range(&self, store: &mut ReceiveStore, offset: u64, data: &[u8]) -> Key {
        let root = self.bytes.as_ptr_range();
        let part = data.as_ptr_range();
        if self.backing.size <= crate::proto::receive::MAX_CLASS
            && root.start <= part.start
            && part.end <= root.end
        {
            let span = self.span.get().unwrap_or_else(|| {
                let span = store.open_span(Segment {
                    bytes: self.bytes.clone(),
                    backing: self.backing,
                });
                self.span.set(Some(span));
                span
            });
            return store.node(
                offset,
                span,
                part.start.addr() - root.start.addr(),
                data.len(),
            );
        }
        copy_range(store, offset, data)
    }

    pub(super) fn finish(self, store: &mut ReceiveStore) {
        if let Some(span) = self.span.get() {
            store.close_span(span);
        }
    }
}

fn copy_range(store: &mut ReceiveStore, offset: u64, data: &[u8]) -> Key {
    let (segment, retired) = store.copies.get_or_insert_with(Box::default).pack(data);
    store.copied += retired;
    let span = store.insert_span(Span {
        segment,
        users: 1,
        copied_input: true,
    });
    let key = store.node(offset, span, 0, data.len());
    store.close_span(span);
    key
}

/// A mutable page can fill unseen offsets without holding a separate node for
/// each byte. When its prefix is available, the prefix becomes a normal span.
const PAGE: usize = 4096;
const PAGE_FLOOR: u64 = (PAGE as u64) - 1;
const INLINE_RANGES: usize = 8;

#[derive(Debug)]
struct Page {
    first: u64,
    bytes: BytesMut,
    backing: Backing,
}

#[derive(Debug, Default)]
struct Sparse {
    first: u64,
    pages: VecDeque<Option<Page>>,
    present: super::reasm::Bits,
}

impl Sparse {
    fn write(&mut self, mut offset: u64, mut data: &[u8]) {
        let base = offset & !PAGE_FLOOR;
        if self.pages.is_empty() {
            self.first = base;
        }
        while base < self.first {
            self.pages.push_front(None);
            self.first -= PAGE as u64;
        }
        while !data.is_empty() {
            let index = usize::try_from((offset - self.first) / PAGE as u64).unwrap();
            if self.pages.len() <= index {
                self.pages.resize_with(index + 1, || None);
            }
            let page = self.pages[index].get_or_insert_with(|| Page {
                first: offset & !PAGE_FLOOR,
                bytes: BytesMut::zeroed(PAGE),
                backing: Backing::new(PAGE),
            });
            let start = usize::try_from(offset - page.first).unwrap();
            let count = (page.bytes.len() - start).min(data.len());
            page.bytes[start..start + count].copy_from_slice(&data[..count]);
            offset += count as u64;
            data = &data[count..];
        }
    }

    fn promote(
        &mut self,
        mut from: u64,
        store: &mut ReceiveStore,
        queue: &mut ReceiveQueue,
    ) -> (u64, u64) {
        let trimmed = self.present.remove_below(from);
        let end = self.present.run_end(from);
        while from < end {
            let index = usize::try_from((from - self.first) / PAGE as u64).unwrap();
            let page = self.pages[index].as_mut().expect("present receive page");
            if page.first < from {
                let count = usize::try_from(from - page.first).unwrap();
                page.bytes.advance(count);
                page.first = from;
            }
            let count = usize::try_from(end - from).unwrap().min(page.bytes.len());
            let bytes = page.bytes.split_to(count).freeze();
            page.first += count as u64;
            let span = store.open_span(Segment {
                bytes,
                backing: page.backing,
            });
            let key = store.node(from, span, 0, count);
            store.close_span(span);
            queue.push(store, key);
            from += count as u64;
        }
        queue.pending -= trimmed + self.present.remove_below(end);
        self.trim();
        (end, trimmed)
    }

    fn trim(&mut self) {
        if self.present.is_empty() {
            self.pages.clear();
            return;
        }
        let start = self
            .present
            .first_from(self.first)
            .expect("nonempty presence map");
        let remove = usize::try_from((start - self.first) / PAGE as u64).unwrap();
        if remove != 0 {
            self.pages.drain(..remove);
            self.first += (remove * PAGE) as u64;
        }
        while let Some(last) = self.pages.len().checked_sub(1) {
            let start = self.first + (last * PAGE) as u64;
            if self.present.covered(start, start + PAGE as u64) != 0 {
                break;
            }
            self.pages.pop_back();
        }
        if self.pages.capacity() / 4 > self.pages.len() {
            self.pages.shrink_to_fit();
        }
    }

    fn remaining_span(&self) -> u64 {
        self.present.bounds().map_or(0, |(first, end)| end - first)
    }

    fn has_at_most_runs(&self, limit: usize) -> bool {
        let mut next = self.present.first_from(self.first);
        for _ in 0..limit {
            let Some(at) = next else { return true };
            next = self.present.first_from(self.present.run_end(at));
        }
        next.is_none()
    }

    fn restore_ranges(self, store: &mut ReceiveStore, queue: &mut ReceiveQueue) {
        let mut next = self.present.first_from(self.first);
        while let Some(mut offset) = next {
            let end = self.present.run_end(offset);
            while offset < end {
                let index = usize::try_from((offset - self.first) / PAGE as u64).unwrap();
                let page = self.pages[index].as_ref().expect("present receive page");
                let start = usize::try_from(offset - page.first).unwrap();
                let count = crate::util::usize_sat(end - offset).min(page.bytes.len() - start);
                let key = copy_range(store, offset, &page.bytes[start..start + count]);
                queue.push_gap(store, key, offset);
                offset += count as u64;
            }
            next = self.present.first_from(end);
        }
    }

    fn heap_bytes(&self) -> usize {
        size_of::<Self>()
            + self.present.memory()
            + self.pages.capacity() * size_of::<Option<Page>>()
            + self
                .pages
                .iter()
                .flatten()
                .map(|page| page.backing.size)
                .sum::<usize>()
    }
}

/// A stream's descriptor links. The FIFO uses `left` as its next link. When
/// a gap closes, the node moves straight from the offset tree to the FIFO.
#[derive(Debug, Default)]
pub(super) struct ReceiveQueue {
    head: Option<Key>,
    tail: Option<Key>,
    gaps: Option<Key>,
    short_gaps: usize,
    sparse: Option<Box<Sparse>>,
    ready: usize,
    ready_nodes: usize,
    ready_packed_through: Option<Key>,
    pending: u64,
}

impl ReceiveQueue {
    pub(super) const fn len(&self) -> usize {
        self.ready
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.ready == 0
    }

    pub(super) const fn held(&self) -> u64 {
        self.ready as u64 + self.pending
    }

    pub(super) fn heap_bytes(&self) -> usize {
        self.sparse.as_deref().map_or(0, Sparse::heap_bytes)
    }

    fn maybe_pack(&mut self, store: &mut ReceiveStore, contig: u64) {
        if self.short_gaps <= INLINE_RANGES {
            return;
        }
        let root = self.gaps.expect("short gap nodes present");
        let end = store.arenas().nodes.get(store.last(root)).end();
        // Pack fragments whose descriptors outweigh a bitmap of their span.
        // Long extents keep their original backing, even while the same
        // stream has short packed gaps elsewhere.
        if (self.short_gaps - INLINE_RANGES) as u64 <= (end - contig) / PAGE as u64 {
            return;
        }
        let mut sparse = self.sparse.take().unwrap_or_default();
        self.gaps = None;
        self.short_gaps = 0;
        let mut old = Some(root);
        while let Some(root) = old {
            let (remaining, key) = store.remove_first(root);
            old = remaining;
            let node = *store.arenas().nodes.get(key);
            if Self::short(node) {
                sparse.write(node.offset, store.slice(node));
                sparse.present.insert(node.offset, node.end());
                store.discard(key);
            } else {
                store.set_children(key, None, None);
                self.push_gap(store, key, node.offset);
            }
        }
        self.sparse = Some(sparse);
    }

    fn short(node: Node) -> bool {
        (node.range.len as usize) < PAGE
    }

    fn push_gap(&mut self, store: &mut ReceiveStore, key: Key, offset: u64) {
        self.short_gaps += usize::from(Self::short(*store.arenas().nodes.get(key)));
        self.gaps = Some(store.insert(self.gaps, key, offset));
    }

    fn keep_sparse(&mut self, store: &mut ReceiveStore, sparse: Box<Sparse>) {
        if sparse.present.is_empty() {
            return;
        }
        // Once the span is shorter than a page, keeping whole pages would
        // charge padding to positions the application has already consumed.
        if sparse.remaining_span() < PAGE as u64 && sparse.has_at_most_runs(INLINE_RANGES) {
            sparse.restore_ranges(store, self);
        } else {
            self.sparse = Some(sparse);
        }
    }

    fn push(&mut self, store: &mut ReceiveStore, key: Key) {
        let node = store.arenas_mut().nodes.get_mut(key);
        self.ready += node.range.len as usize;
        let new = *node;
        node.left = None;
        node.right = None;
        if let Some(tail) = self.tail {
            let last = store.arenas_mut().nodes.get_mut(tail);
            let adjacent = last.range.span == new.range.span
                && last.range.start + last.range.len == new.range.start
                && last.end() == new.offset;
            if adjacent {
                last.range.len += new.range.len;
                store.discard(key);
                return;
            }
            last.left = Some(key);
        } else {
            self.head = Some(key);
        }
        self.tail = Some(key);
        self.ready_nodes += 1;
    }

    /// Consecutive short ranges are compacted only if their descriptor
    /// density would exceed two per page, plus the stream's small reserve.
    /// An intact extent of at least a page is never moved here.
    fn pack_ready(&mut self, store: &mut ReceiveStore) {
        if self.ready_nodes <= INLINE_RANGES + 2 * self.ready.div_ceil(PAGE) {
            return;
        }
        let mut at = self
            .ready_packed_through
            .map_or(self.head, |key| store.arenas().nodes.get(key).left);
        while let Some(key) = at {
            let node = *store.arenas().nodes.get(key);
            at = node.left;
            if !Self::short(node) {
                self.ready_packed_through = Some(key);
                continue;
            }
            let mut len = node.range.len as usize;
            let mut end = at;
            while len < PAGE {
                let Some(next) = end else { break };
                let node = *store.arenas().nodes.get(next);
                if !Self::short(node) {
                    break;
                }
                len += node.range.len as usize;
                end = node.left;
            }
            if at == end {
                if end.is_some() {
                    self.ready_packed_through = Some(key);
                }
                continue;
            }
            let mut block = Vec::with_capacity(len);
            block.extend_from_slice(store.slice(node));
            while at != end {
                let next = at.expect("short runs precede the end");
                let part = *store.arenas().nodes.get(next);
                block.extend_from_slice(store.slice(part));
                at = part.left;
                store.discard(next);
                self.ready_nodes -= 1;
            }
            let span = store.open_span(Segment {
                backing: Backing::new(block.capacity()),
                bytes: Bytes::from(block),
            });
            let head = store.arenas_mut().nodes.get_mut(key);
            head.range = Range {
                span,
                start: 0,
                len: u32::try_from(len).expect("one compact run"),
            };
            head.left = end;
            store.close_span(node.range.span);
            if end.is_none() {
                self.tail = Some(key);
            }
            if len >= PAGE || end.is_some() {
                self.ready_packed_through = Some(key);
            }
        }
    }

    /// Keeps only offsets not already received. Returns the contiguous end
    /// and the increase in held bytes (including bytes retained beyond a gap).
    pub(super) fn insert(
        &mut self,
        store: &mut ReceiveStore,
        mut contig: u64,
        mut offset: u64,
        mut data: &[u8],
        input: Source<'_>,
    ) -> (u64, u64) {
        let end = offset + data.len() as u64;
        if end <= contig {
            return (contig, 0);
        }
        if offset < contig {
            data = &data[usize::try_from(contig - offset).unwrap()..];
            offset = contig;
        }
        let before = self.held();
        while offset < end {
            let next = store.at_or_after(self.gaps, offset);
            if let Some(overlap) = next.filter(|r| r.offset <= offset) {
                let skip = usize::try_from(end.min(overlap.end()) - offset).unwrap();
                offset += skip as u64;
                data = &data[skip..];
                continue;
            }
            let packed = self
                .sparse
                .as_ref()
                .and_then(|s| s.present.first_from(offset));
            if packed == Some(offset) {
                let until = self
                    .sparse
                    .as_ref()
                    .expect("packed data")
                    .present
                    .run_end(offset);
                let skip = usize::try_from(end.min(until) - offset).unwrap();
                offset += skip as u64;
                data = &data[skip..];
                continue;
            }
            let until = end
                .min(next.map_or(end, |r| r.offset))
                .min(packed.unwrap_or(end));
            let count = usize::try_from(until - offset).unwrap();
            if offset != contig
                && count < PAGE
                && let Some(sparse) = &mut self.sparse
            {
                sparse.write(offset, &data[..count]);
                sparse.present.insert(offset, until);
                self.pending += count as u64;
            } else {
                let key = match input {
                    Some(input) => input.range(store, offset, &data[..count]),
                    None => copy_range(store, offset, &data[..count]),
                };
                if offset == contig {
                    self.push(store, key);
                    contig = until;
                    // Normalize after each newly contiguous range. One
                    // frame can close many disjoint packed prefixes.
                    (contig, _) = self.promote(store, contig);
                } else {
                    self.pending += count as u64;
                    self.push_gap(store, key, offset);
                }
            }
            // A previously accepted range may extend beyond the new data.
            let done = contig.max(until).min(end);
            data = &data[usize::try_from(done - offset).unwrap()..];
            offset = done;
        }
        self.maybe_pack(store, contig);
        self.pack_ready(store);
        (contig, self.held() - before)
    }

    /// Moves newly contiguous nodes into the FIFO, discarding any parts
    /// that precede a preamble's newly recognized application boundary.
    pub(super) fn promote(&mut self, store: &mut ReceiveStore, mut contig: u64) -> (u64, u64) {
        let mut trimmed = 0;
        loop {
            if self
                .sparse
                .as_ref()
                .and_then(|s| s.present.bounds())
                .is_some_and(|(first, _)| first <= contig)
            {
                let mut sparse = self.sparse.take().expect("packed gaps");
                let (end, skipped) = sparse.promote(contig, store, self);
                contig = end;
                trimmed += skipped;
                self.keep_sparse(store, sparse);
            }
            let Some(root) = self.gaps else { break };
            let first = *store.arenas().nodes.get(store.first(root));
            if first.offset > contig {
                break;
            }
            let (remaining, key) = store.remove_first(root);
            self.gaps = remaining;
            self.short_gaps -= usize::from(Self::short(first));
            self.pending -= u64::from(first.range.len);
            let skip = (contig - first.offset).min(u64::from(first.range.len));
            trimmed += skip;
            if contig < first.end() {
                let node = store.arenas_mut().nodes.get_mut(key);
                let skip = u32::try_from(skip).unwrap();
                node.range.start += skip;
                node.range.len -= skip;
                node.offset = contig;
                self.push(store, key);
                contig = first.end();
            } else {
                store.discard(key);
            }
        }
        self.pack_ready(store);
        (contig, trimmed)
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(super) fn front(&self, store: &ReceiveStore) -> Option<(Backing, usize)> {
        let node = store.arenas().nodes.get(self.head?);
        Some((
            store.arenas().spans.get(node.range.span).segment.backing,
            node.range.len as usize,
        ))
    }

    #[cfg(test)]
    pub(super) fn gaps(&self, store: &ReceiveStore) -> usize {
        fn collect(store: &ReceiveStore, key: Option<Key>, ranges: &mut Vec<(u64, u64)>) {
            let Some(key) = key else { return };
            let node = *store.arenas().nodes.get(key);
            collect(store, node.left, ranges);
            ranges.push((node.offset, node.end()));
            collect(store, node.right, ranges);
        }
        let mut ranges = Vec::new();
        collect(store, self.gaps, &mut ranges);
        if let Some(sparse) = &self.sparse {
            let mut next = sparse.present.first_from(0);
            while let Some(offset) = next {
                let end = sparse.present.run_end(offset);
                ranges.push((offset, end));
                next = sparse.present.first_from(end);
            }
            ranges.sort_unstable();
        }
        let mut previous = None;
        ranges
            .into_iter()
            .filter(|&(offset, end)| previous.replace(end) != Some(offset))
            .count()
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(super) fn transferable_front(&self, store: &ReceiveStore, count: usize) -> bool {
        let Some(head) = self.head.map(|key| store.arenas().nodes.get(key)) else {
            return false;
        };
        if count != head.range.len as usize {
            return false;
        }
        let span = store.arenas().spans.get(head.range.span);
        span.users == 1 && span.segment.bytes.is_unique()
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(super) fn peek(&self, store: &ReceiveStore, max: usize) -> Option<Segment> {
        let node = *store.arenas().nodes.get(self.head?);
        Some(store.segment(node, max.min(node.range.len as usize)))
    }

    pub(super) fn take(&mut self, store: &mut ReceiveStore, max: usize) -> Segment {
        let Some(key) = self.head.filter(|_| max != 0) else {
            return Segment::default();
        };
        let node = *store.arenas().nodes.get(key);
        let count = max.min(node.range.len as usize);
        let segment = store.take_segment(node, count);
        self.consume_front(store, key, node, count);
        segment
    }

    pub(super) fn consume(
        &mut self,
        store: &mut ReceiveStore,
        max: usize,
        mut visit: impl FnMut(usize, &[u8]),
    ) -> usize {
        let mut done = 0;
        while done < max {
            let Some(key) = self.head else { break };
            let node = *store.arenas().nodes.get(key);
            let count = (max - done).min(node.range.len as usize);
            visit(done, &store.slice(node)[..count]);
            self.consume_front(store, key, node, count);
            done += count;
        }
        done
    }

    fn consume_front(&mut self, store: &mut ReceiveStore, key: Key, node: Node, count: usize) {
        self.ready -= count;
        if count == node.range.len as usize {
            self.head = node.left;
            if self.head.is_none() {
                self.tail = None;
            }
            self.ready_nodes -= 1;
            if self.ready_packed_through == Some(key) {
                self.ready_packed_through = None;
            }
            store.discard(key);
        } else {
            let current = store.arenas_mut().nodes.get_mut(key);
            let count = u32::try_from(count).unwrap();
            current.offset += u64::from(count);
            current.range.start += count;
            current.range.len -= count;
        }
    }

    pub(super) fn truncate(&mut self, store: &mut ReceiveStore, limit: u64) -> u64 {
        let before = self.held();
        if let Some(mut sparse) = self.sparse.take() {
            self.pending -= sparse.present.remove_from(limit);
            sparse.trim();
            self.keep_sparse(store, sparse);
        }
        while let Some(root) = self.gaps {
            let last = store.last(root);
            let node = *store.arenas().nodes.get(last);
            if node.end() <= limit {
                break;
            }
            if node.offset < limit {
                let retained = u32::try_from(limit - node.offset).unwrap();
                store.arenas_mut().nodes.get_mut(last).range.len = retained;
                self.short_gaps += usize::from(!Self::short(node) && (retained as usize) < PAGE);
                self.pending -= u64::from(node.range.len - retained);
                break;
            }
            let (remaining, key) = store.remove_last(root);
            self.gaps = remaining;
            self.short_gaps -= usize::from(Self::short(node));
            self.pending -= u64::from(store.discard(key).range.len);
        }
        if let Some(tail) = self.tail
            && store.arenas().nodes.get(tail).end() > limit
        {
            let mut next = self.head;
            let mut last = None;
            self.tail = None;
            self.ready_packed_through = None;
            while let Some(key) = next {
                let node = *store.arenas().nodes.get(key);
                next = node.left;
                if node.end() <= limit {
                    last = Some(key);
                } else if node.offset < limit {
                    let kept = u32::try_from(limit - node.offset).unwrap();
                    store.arenas_mut().nodes.get_mut(key).range.len = kept;
                    self.ready -= (node.range.len - kept) as usize;
                    last = Some(key);
                } else {
                    self.ready -= store.discard(key).range.len as usize;
                    self.ready_nodes -= 1;
                }
            }
            if let Some(tail) = last {
                store.arenas_mut().nodes.get_mut(tail).left = None;
            } else {
                self.head = None;
            }
            self.tail = last;
        }
        before - self.held()
    }

    pub(super) fn clear(&mut self, store: &mut ReceiveStore) -> u64 {
        // Discarding at offset zero drops both the FIFO and the tree.
        self.truncate(store, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishing_from_a_borrowed_tail_keeps_live_root_identity() {
        let mut store = ReceiveStore::default();
        let mut queue = ReceiveQueue::default();
        queue.insert(&mut store, 0, 0, &[1; 8], None);
        let first = queue.take(&mut store, 8);

        queue.insert(&mut store, 8, 8, &[2; 16], None);
        let second = queue.take(&mut store, 16);
        assert_eq!(first.backing, second.backing);
        assert_eq!(first.bytes.as_ref(), &[1; 8]);
        assert_eq!(second.bytes.as_ref(), &[2; 16]);

        queue.insert(&mut store, 24, 24, &[3; receive::MIN_CLASS], None);
        let third = queue.take(&mut store, receive::MIN_CLASS);
        assert_ne!(third.backing.id, second.backing.id);
        assert_eq!(first.bytes.as_ref(), &[1; 8]);
        assert_eq!(second.bytes.as_ref(), &[2; 16]);
        assert_eq!(third.bytes.as_ref(), &[3; receive::MIN_CLASS]);
    }

    #[test]
    fn fragmented_and_contiguous_ranges_share_the_span_table() {
        // Exercise every descriptor with a one-byte range. The data that
        // closes the holes deliberately disagrees with previously stored bytes.
        const POSITIONS: usize = 16;
        let mut store = ReceiveStore::default();
        let mut queue = ReceiveQueue::default();
        let original = Bytes::from_static(&[5; POSITIONS]);
        let backing = Backing::new(original.len());
        let source = InputSpan::new(&original, backing);
        for index in (1..POSITIONS).step_by(2).rev() {
            assert_eq!(
                queue.insert(
                    &mut store,
                    0,
                    index as u64,
                    &original[index..=index],
                    Some(&source)
                ),
                (0, 1)
            );
        }
        assert_eq!(queue.gaps(&store), POSITIONS / 2);
        assert_eq!(store.arenas().spans.rows.len(), 1);
        assert!(
            store.heap_bytes() as u64
                <= ReceiveStore::POSITION_COST * (POSITIONS as u64 / 2) + ReceiveStore::BASE_COST
        );
        source.finish(&mut store);

        let overlap = Bytes::from_static(&[7; POSITIONS]);
        let source = InputSpan::new(&overlap, Backing::new(overlap.len()));
        assert_eq!(
            queue.insert(&mut store, 0, 0, &overlap, Some(&source)),
            (POSITIONS as u64, POSITIONS as u64 / 2)
        );
        source.finish(&mut store);
        assert_eq!(queue.gaps(&store), 0);
        assert_eq!(store.take_copied_capacity(), 0);
        assert_eq!(queue.truncate(&mut store, POSITIONS as u64 - 1), 1);
        assert_eq!(
            queue.consume(&mut store, POSITIONS, |offset, bytes| {
                for (i, byte) in bytes.iter().enumerate() {
                    assert_eq!(*byte, if (offset + i) % 2 == 0 { 7 } else { 5 });
                }
            }),
            POSITIONS - 1
        );
        assert_eq!(store.arenas().spans.occupied().count(), 0);
        assert_eq!(store.arenas().nodes.occupied().count(), 0);
    }

    #[test]
    fn sparse_truncation_inside_a_page_keeps_original_bytes_and_reverts_to_ranges() {
        let mut store = ReceiveStore::default();
        let mut queue = ReceiveQueue::default();
        let page = PAGE as u64;
        queue.insert(&mut store, 0, page + 1, &[7; 30], None);
        for i in (1..257u64).step_by(2) {
            queue.insert(&mut store, 0, 2 * page + i, &[8], None);
        }
        assert!(queue.sparse.is_some());

        let wire = Bytes::from(vec![3; 4 * PAGE]);
        let backing = Backing::new(wire.len());
        let source = InputSpan::new(&wire, backing);
        let offset = 8 * page;
        queue.insert(&mut store, 0, offset, &wire, Some(&source));
        source.finish(&mut store);
        let node = store.at_or_after(queue.gaps, offset).unwrap();
        let kept = store.segment(node, wire.len());
        assert_eq!(kept.backing, backing);
        assert_eq!(kept.bytes.as_ptr(), wire.as_ptr());

        assert_eq!(queue.truncate(&mut store, page + 15), 16 + 128 + 4 * page);
        assert!(queue.sparse.is_none());
        assert_eq!(queue.held(), 14);
        let filler = vec![9; PAGE + 15];
        assert_eq!(
            queue.insert(&mut store, 0, 0, &filler, None),
            (page + 15, page + 1)
        );
        let mut got = Vec::new();
        queue.consume(&mut store, filler.len(), |_, bytes| {
            got.extend_from_slice(bytes);
        });
        assert_eq!(&got[..=PAGE], &filler[..=PAGE]);
        assert_eq!(&got[PAGE + 1..], &[7; 14]);
    }

    #[test]
    fn compacting_a_retired_copy_block_returns_its_owner() {
        let mut store = ReceiveStore::default();
        let mut queue = ReceiveQueue::default();
        let size = receive::MIN_CLASS;
        queue.insert(&mut store, 0, 0, &vec![4; size], None);
        let old = store.copying_backing().unwrap();
        queue.insert(&mut store, size as u64, size as u64, &[5], None);
        assert_eq!(store.copies.as_ref().unwrap().retired.len(), 1);
        store.compact(&[(old.id, old.size, size)]);
        assert!(store.copies.as_ref().unwrap().retired.is_empty());
        let mut got = Vec::new();
        queue.consume(&mut store, size + 1, |_, bytes| {
            got.extend_from_slice(bytes);
        });
        assert_eq!(&got[..size], &vec![4; size]);
        assert_eq!(got[size], 5);
    }

    #[test]
    fn consecutive_tiny_frames_keep_a_page_granularity_of_descriptors() {
        let mut store = ReceiveStore::default();
        let mut queue = ReceiveQueue::default();
        let byte = Bytes::from_static(b"x");
        for offset in 0..257u64 {
            let input = InputSpan::new(&byte, Backing::new(1));
            assert_eq!(
                queue.insert(&mut store, offset, offset, &byte, Some(&input)),
                (offset + 1, 1)
            );
            input.finish(&mut store);
            let ready = usize::try_from(offset + 1).unwrap();
            let bound = INLINE_RANGES + 2 * ready.div_ceil(PAGE);
            assert!(store.arenas().nodes.occupied().count() <= bound);
            assert!(store.arenas().spans.occupied().count() <= bound);
        }
        assert_eq!(queue.clear(&mut store), 257);
    }

    #[test]
    fn one_frame_filling_packed_holes_keeps_the_arena_high_water_at_page_density() {
        const PAGES: usize = 128;
        const POSITIONS: usize = PAGES * PAGE;

        let mut store = ReceiveStore::default();
        let mut queue = ReceiveQueue::default();
        for offset in (1..POSITIONS).step_by(2) {
            queue.insert(&mut store, 0, offset as u64, b"x", None);
        }
        assert!(queue.sparse.is_some());
        let filler = Bytes::from(vec![b'y'; POSITIONS]);
        let input = InputSpan::new(&filler, Backing::new(filler.len()));
        assert_eq!(
            queue.insert(&mut store, 0, 0, &filler, Some(&input)),
            (POSITIONS as u64, (POSITIONS / 2) as u64)
        );
        input.finish(&mut store);

        let committed = PAGES as u64 * ReceiveStore::DESCRIPTORS_PER_PAGE
            + ReceiveStore::DESCRIPTORS_PER_DIRECTION;
        assert!(store.arenas().nodes.rows.len() as u64 <= committed);
        assert!(store.arenas().spans.rows.len() as u64 <= committed);
        assert_eq!(
            queue.consume(&mut store, POSITIONS, |offset, bytes| {
                for (i, byte) in bytes.iter().enumerate() {
                    assert_eq!(*byte, if (offset + i) % 2 == 0 { b'y' } else { b'x' });
                }
            }),
            POSITIONS
        );
        assert!(queue.ready_packed_through.is_none());
    }

    #[test]
    fn compacted_sparse_roots_are_packed_across_streams() {
        let mut store = ReceiveStore::default();
        let mut left = ReceiveQueue::default();
        let mut right = ReceiveQueue::default();
        for byte in 0..8u8 {
            let original = Bytes::from(vec![byte; 128 * 1024]);
            let source = InputSpan::new(&original, Backing::new(original.len()));
            for queue in [&mut left, &mut right] {
                queue.insert(
                    &mut store,
                    u64::from(byte),
                    u64::from(byte),
                    &original[..1],
                    Some(&source),
                );
            }
            source.finish(&mut store);
        }
        let mut selected = Vec::new();
        store.tally(&mut selected);
        assert_eq!(selected.len(), 8);
        store.compact(&selected);
        store.tally(&mut selected);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1, 16);
        assert_eq!(selected[0].2, 16);
        for queue in [&mut left, &mut right] {
            queue.consume(&mut store, 8, |offset, bytes| {
                assert_eq!(bytes, &[u8::try_from(offset).unwrap()]);
            });
        }
        assert_eq!(store.arenas().spans.occupied().count(), 0);
    }
}
