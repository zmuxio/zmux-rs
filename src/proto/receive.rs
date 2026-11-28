//! Ownership of initialized carrier receive storage.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ops::Range;
use std::sync::Mutex;
#[cfg(all(
    feature = "test-hooks",
    any(feature = "tokio", feature = "blocking"),
    not(loom)
))]
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use bytes::{Bytes, BytesMut};

pub(crate) const MIN_CLASS: usize = 256;
pub(crate) const MAX_CLASS: usize = 128 * 1024;
const TYPICAL_SEALED_CLASS: usize = 1280;
const CLASS_COUNT: usize = (MAX_CLASS.ilog2() - MIN_CLASS.ilog2() + 2) as usize;
const MAX_IDLE: usize = 8 * 1024 * 1024;

struct Pool {
    classes: [Vec<Vec<u8>>; CLASS_COUNT],
    // A retired tail can return to a reader when its last exported view
    // has gone. Retain it within the same cap as the ready buffers.
    streaming: [VecDeque<BytesMut>; CLASS_COUNT],
    /// Shared retained capacity and the space reserved by thread-local slots.
    idle: usize,
    max_idle: usize,
}

impl Pool {
    const fn new(max_idle: usize) -> Self {
        Self {
            classes: [const { Vec::new() }; CLASS_COUNT],
            streaming: [const { VecDeque::new() }; CLASS_COUNT],
            idle: 0,
            max_idle,
        }
    }

    fn reserve_idle(&mut self, bytes: usize, class_empty: bool) -> bool {
        if bytes > self.max_idle || (!class_empty && bytes > self.max_idle - self.idle) {
            return false;
        }
        // A warm class must not be crowded out permanently by a burst
        // that filled the pool with other sizes.
        while bytes > self.max_idle - self.idle {
            let Some(evicted) = self.evict() else {
                return false;
            };
            self.idle -= evicted;
        }
        self.idle += bytes;
        true
    }

    fn evict(&mut self) -> Option<usize> {
        if let Some((index, buffer)) = self
            .streaming
            .iter_mut()
            .enumerate()
            .rev()
            .find_map(|(index, class)| class.pop_front().map(|buffer| (index, buffer)))
        {
            drop(buffer);
            return Some(class_size(index));
        }
        self.classes
            .iter_mut()
            .rev()
            .find_map(Vec::pop)
            .map(|buffer| buffer.capacity())
    }

    fn give_record(&mut self, index: usize, storage: &mut Vec<u8>) {
        if self.reserve_idle(storage.capacity(), self.classes[index].is_empty()) {
            self.classes[index].push(std::mem::take(storage));
        }
    }

    fn give_streaming(&mut self, index: usize, buffer: BytesMut) {
        let capacity = class_size(index);
        if !self.reserve_idle(capacity, self.streaming[index].is_empty())
            && self.streaming[index].pop_front().is_none()
        {
            return;
        }
        self.streaming[index].push_back(buffer);
    }

    fn take_streaming(&mut self, index: usize) -> Option<BytesMut> {
        let capacity = class_size(index);
        let buffers = &mut self.streaming[index];
        let ready = buffers
            .iter_mut()
            .rposition(|bytes| bytes.try_reclaim(capacity))?;
        self.idle -= capacity;
        buffers.remove(ready)
    }
}

static POOL: Mutex<Pool> = Mutex::new(Pool::new(MAX_IDLE));

/// Same-thread receives can reuse a record without taking the global pool
/// lock. A slot reserves its byte capacity until the thread exits. The
/// reservation also bounds what can be returned later by that thread.
struct LocalPool {
    slots: [Option<Vec<u8>>; CLASS_COUNT],
    reserved: [bool; CLASS_COUNT],
    bytes: usize,
}

impl LocalPool {
    const fn new() -> Self {
        Self {
            slots: [const { None }; CLASS_COUNT],
            reserved: [false; CLASS_COUNT],
            bytes: 0,
        }
    }

    fn take(&mut self, index: usize) -> Option<Vec<u8>> {
        let storage = self.slots[index].take()?;
        #[cfg(all(
            feature = "test-hooks",
            any(feature = "tokio", feature = "blocking"),
            not(loom)
        ))]
        LOCAL_CHECKED_OUT.fetch_add(storage.capacity(), Relaxed);
        Some(storage)
    }

    fn give(&mut self, index: usize, storage: &mut Vec<u8>) -> bool {
        if self.slots[index].is_some() {
            return false;
        }
        let bytes = storage.capacity();
        if self.reserved[index] {
            #[cfg(all(
                feature = "test-hooks",
                any(feature = "tokio", feature = "blocking"),
                not(loom)
            ))]
            LOCAL_CHECKED_OUT.fetch_sub(bytes, Relaxed);
        } else {
            let Ok(mut pool) = POOL.lock() else {
                return false;
            };
            if !pool.reserve_idle(bytes, false) {
                return false;
            }
            self.reserved[index] = true;
            self.bytes += bytes;
        }
        self.slots[index] = Some(std::mem::take(storage));
        true
    }
}

impl Drop for LocalPool {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        if let Ok(mut pool) = POOL.lock() {
            #[cfg(all(
                feature = "test-hooks",
                any(feature = "tokio", feature = "blocking"),
                not(loom)
            ))]
            LOCAL_CHECKED_OUT.fetch_sub(
                self.bytes
                    - self
                        .slots
                        .iter()
                        .flatten()
                        .map(Vec::capacity)
                        .sum::<usize>(),
                Relaxed,
            );
            pool.idle -= self.bytes;
        }
    }
}

thread_local! {
    static LOCAL: RefCell<LocalPool> = const { RefCell::new(LocalPool::new()) };
}

#[cfg(all(
    feature = "test-hooks",
    any(feature = "tokio", feature = "blocking"),
    not(loom)
))]
static LOCAL_CHECKED_OUT: AtomicUsize = AtomicUsize::new(0);

fn class(capacity: usize) -> Option<usize> {
    if capacity == TYPICAL_SEALED_CLASS {
        return Some(3);
    }
    if (MIN_CLASS..=MAX_CLASS).contains(&capacity) && capacity.is_power_of_two() {
        let index = (capacity.ilog2() - MIN_CLASS.ilog2()) as usize;
        Some(index + usize::from(capacity > TYPICAL_SEALED_CLASS))
    } else {
        None
    }
}

fn class_size(index: usize) -> usize {
    if index == 3 {
        TYPICAL_SEALED_CLASS
    } else {
        MIN_CLASS << (index - usize::from(index > 3))
    }
}

fn class_capacity(len: usize) -> usize {
    if (1025..=TYPICAL_SEALED_CLASS).contains(&len) {
        return TYPICAL_SEALED_CLASS;
    }
    len.max(MIN_CLASS)
        .checked_next_power_of_two()
        .unwrap_or(len)
}

pub(crate) fn take_streaming(length: usize) -> BytesMut {
    let capacity = class_capacity(length);
    let reused = class(capacity).and_then(|index| POOL.lock().ok()?.take_streaming(index));
    reused.unwrap_or_else(|| BytesMut::with_capacity(capacity))
}

/// Returns a tail to the pool, optionally while an exported view still
/// pins the root. `capacity` is the root capacity recorded when rented.
pub(crate) fn give_streaming(mut buffer: BytesMut, capacity: usize) {
    let Some(index) = class(capacity) else {
        return;
    };
    buffer.clear();
    if let Ok(mut pool) = POOL.lock() {
        pool.give_streaming(index, buffer);
    }
}

#[cfg(all(
    feature = "test-hooks",
    any(feature = "tokio", feature = "blocking"),
    not(loom)
))]
pub(crate) fn idle_bytes() -> usize {
    POOL.lock().map_or(0, |pool| {
        pool.idle.saturating_sub(LOCAL_CHECKED_OUT.load(Relaxed))
    })
}

/// Storage exclusively held by a carrier while it fills a record.
#[derive(Default)]
pub(crate) struct ReceiveBuffer {
    storage: Vec<u8>,
}

impl ReceiveBuffer {
    pub(crate) fn take(len: usize) -> Self {
        let capacity = class_capacity(len);
        let reused = class(capacity).and_then(|index| {
            if let Some(storage) = LOCAL
                .try_with(|pool| pool.borrow_mut().take(index))
                .ok()
                .flatten()
            {
                return Some(storage);
            }
            let mut pool = POOL.lock().ok()?;
            let storage = pool.classes[index].pop()?;
            pool.idle -= storage.capacity();
            Some(storage)
        });
        let mut storage = reused.unwrap_or_else(|| Vec::with_capacity(capacity));
        // The callback receives an initialized slice. Initialize only the
        // exact range it can observe, leaving the spare capacity private.
        storage.clear();
        storage.resize(len, 0);
        Self { storage }
    }

    pub(crate) fn from_vec(storage: Vec<u8>) -> Self {
        Self { storage }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    pub(crate) fn space(&mut self) -> &mut [u8] {
        &mut self.storage
    }

    pub(crate) fn publish(self, valid: Range<usize>) -> ReceivedRecord {
        assert!(valid.start <= valid.end && valid.end <= self.storage.len());
        ReceivedRecord {
            storage: self,
            valid,
        }
    }
}

impl Drop for ReceiveBuffer {
    fn drop(&mut self) {
        let capacity = self.storage.capacity();
        let Some(index) = class(capacity) else {
            return;
        };
        if matches!(
            LOCAL.try_with(|pool| pool.borrow_mut().give(index, &mut self.storage)),
            Ok(true)
        ) {
            return;
        }
        if let Ok(mut pool) = POOL.lock() {
            pool.give_record(index, &mut self.storage);
        }
    }
}

/// One complete, immutable carrier record. Only its verified range is exposed.
pub struct ReceivedRecord {
    storage: ReceiveBuffer,
    valid: Range<usize>,
}

impl ReceivedRecord {
    /// Takes ownership of an initialized carrier message without copying.
    #[must_use]
    pub fn from_vec(data: Vec<u8>) -> Self {
        let len = data.len();
        ReceiveBuffer::from_vec(data).publish(0..len)
    }

    /// Copies a short-lived carrier message into owned receive storage.
    #[must_use]
    pub fn copy_from_slice(data: &[u8]) -> Self {
        if data.is_empty() {
            return ReceiveBuffer::default().publish(0..0);
        }
        let mut buf = ReceiveBuffer::take(data.len());
        buf.space()[..data.len()].copy_from_slice(data);
        buf.publish(0..data.len())
    }

    /// The capacity of the backing allocation, including unpublished bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.storage.storage.capacity()
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn copy_prefix(&mut self, max: usize, copy: impl FnOnce(&[u8])) -> usize {
        let len = max.min(self.valid.len());
        copy(&self.as_ref()[..len]);
        self.valid.start += len;
        len
    }

    pub(crate) fn into_bytes(self) -> Bytes {
        if self.valid.is_empty() {
            return Bytes::new();
        }
        Bytes::from_owner(self)
    }
}

impl AsRef<[u8]> for ReceivedRecord {
    fn as_ref(&self) -> &[u8] {
        &self.storage.storage[self.valid.clone()]
    }
}

impl std::fmt::Debug for ReceivedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedRecord")
            .field("len", &self.valid.len())
            .field("capacity", &self.capacity())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_classes_cover_sealed_and_byte_stream_sizes() {
        let capacities = [
            256, 512, 1024, 1280, 2048, 4096, 8192, 16384, 32768, 65_536, 131_072,
        ];
        let mut previous = 0;
        for (i, capacity) in capacities.into_iter().enumerate() {
            assert_eq!(class(capacity), Some(i));
            assert_eq!(class_size(i), capacity);
            assert_eq!(class_capacity(previous + 1), capacity);
            assert_eq!(class_capacity(capacity), capacity);
            previous = capacity;
        }
        assert_eq!(capacities.len(), CLASS_COUNT);
        assert_eq!(class(class_capacity(MAX_CLASS + 1)), None);
    }

    #[test]
    fn an_idle_class_can_make_space_in_a_full_pool() {
        let mut pool = Pool::new(1024);
        let mut large = vec![0; 1024];
        pool.give_record(class(1024).unwrap(), &mut large);
        assert_eq!(large.capacity(), 0);
        assert_eq!(pool.idle, 1024);

        let mut small = vec![0; 256];
        pool.give_record(class(256).unwrap(), &mut small);
        assert_eq!(small.capacity(), 0);
        assert_eq!(pool.classes[class(1024).unwrap()].first(), None);
        assert_eq!(pool.idle, 256);
    }

    #[test]
    fn a_retired_streaming_root_returns_after_its_last_view() {
        let capacity = MIN_CLASS;
        let index = class(capacity).unwrap();
        let mut pool = Pool::new(capacity);
        let mut tail = BytesMut::with_capacity(capacity);
        tail.extend_from_slice(b"published bytes");
        let view = tail.split().freeze();
        let pointer = view.as_ptr();
        pool.give_streaming(index, tail);

        assert_eq!(pool.idle, capacity);
        assert!(pool.take_streaming(index).is_none());
        assert_eq!(view.as_ref(), b"published bytes");
        drop(view);
        let ready = pool.take_streaming(index).unwrap();
        assert_eq!(ready.as_ptr(), pointer);
        assert_eq!(ready.capacity(), capacity);
        assert!(ready.is_empty());
        assert_eq!(pool.idle, 0);
    }

    #[test]
    fn a_pinned_streaming_root_can_be_displaced_at_the_limit() {
        let capacity = MIN_CLASS;
        let index = class(capacity).unwrap();
        let mut pool = Pool::new(capacity);
        let mut tail = BytesMut::with_capacity(capacity);
        tail.extend_from_slice(b"published bytes");
        let view = tail.split().freeze();
        pool.give_streaming(index, tail);

        let next = BytesMut::with_capacity(capacity);
        let pointer = next.as_ptr();
        pool.give_streaming(index, next);
        assert_eq!(pool.idle, capacity);
        assert_eq!(view.as_ref(), b"published bytes");
        assert_eq!(pool.take_streaming(index).unwrap().as_ptr(), pointer);
        assert_eq!(pool.idle, 0);
    }
}
