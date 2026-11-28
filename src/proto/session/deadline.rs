//! Absolute deadlines indexed by their owner. Each owner has at most one entry.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Instant;

type Entry<K> = (Instant, K);

#[derive(Debug)]
pub(super) struct Deadlines<K>(Queue<K>);

#[derive(Debug)]
enum Queue<K> {
    Inline([Option<Entry<K>>; 2]),
    Indexed(Indexed<K>),
}

impl<K> Default for Deadlines<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> Deadlines<K> {
    pub(super) const fn new() -> Self {
        Self(Queue::Inline([None, None]))
    }
}

impl<K: Copy + Eq + Hash + Ord> Deadlines<K> {
    pub(super) fn heap_bytes(&self) -> usize {
        match &self.0 {
            Queue::Inline(_) => 0,
            Queue::Indexed(queue) => {
                queue.heap.capacity() * size_of::<Entry<K>>()
                    + queue.positions.capacity() * (size_of::<(K, usize)>() + 1)
            }
        }
    }

    pub(super) fn next(&self) -> Option<Instant> {
        match &self.0 {
            Queue::Inline(entries) => entries[0].map(|(at, _)| at),
            Queue::Indexed(queue) => queue.next(),
        }
    }

    pub(super) fn set(&mut self, key: K, at: Option<Instant>) {
        match &mut self.0 {
            Queue::Indexed(queue) => queue.set(key, at),
            Queue::Inline(entries) => {
                let next = at.map(|at| (at, key));
                if let Some(entry) = entries
                    .iter_mut()
                    .find(|entry| entry.is_some_and(|(_, owner)| owner == key))
                {
                    *entry = next;
                } else if next.is_none() {
                    return;
                } else if let Some(entry) = entries.iter_mut().find(|entry| entry.is_none()) {
                    *entry = next;
                } else {
                    let mut queue = Indexed::default();
                    for (at, key) in entries.iter().copied().flatten() {
                        queue.set(key, Some(at));
                    }
                    queue.set(key, at);
                    self.0 = Queue::Indexed(queue);
                    return;
                }
                if entries[0].is_none()
                    || entries[1].is_some_and(|second| Some(second) < entries[0])
                {
                    entries.swap(0, 1);
                }
            }
        }
    }

    pub(super) fn take_due(&mut self, now: Instant) -> Option<Entry<K>> {
        self.next().filter(|&at| at <= now)?;
        match &mut self.0 {
            Queue::Inline(entries) => {
                let second = entries[1].take();
                std::mem::replace(&mut entries[0], second)
            }
            Queue::Indexed(queue) => Some(queue.remove(0)),
        }
    }
}

#[derive(Debug)]
struct Indexed<K> {
    heap: Vec<Entry<K>>,
    positions: HashMap<K, usize>,
}

impl<K> Default for Indexed<K> {
    fn default() -> Self {
        Self {
            heap: Vec::new(),
            positions: HashMap::new(),
        }
    }
}

impl<K: Copy + Eq + Hash + Ord> Indexed<K> {
    fn next(&self) -> Option<Instant> {
        self.heap.first().map(|&(at, _)| at)
    }

    fn set(&mut self, key: K, at: Option<Instant>) {
        match (self.positions.get(&key).copied(), at) {
            (Some(i), Some(at)) if at < self.heap[i].0 => {
                self.heap[i].0 = at;
                self.up(i);
            }
            (Some(i), Some(at)) if at > self.heap[i].0 => {
                self.heap[i].0 = at;
                self.down(i);
            }
            (None, Some(at)) => {
                let i = self.heap.len();
                self.heap.push((at, key));
                self.positions.insert(key, i);
                self.up(i);
            }
            (Some(i), None) => {
                self.remove(i);
            }
            _ => {}
        }
    }

    fn remove(&mut self, i: usize) -> (Instant, K) {
        let old = self.heap.swap_remove(i);
        self.positions.remove(&old.1);
        if let Some(moved) = self.heap.get(i).copied() {
            self.positions.insert(moved.1, i);
            if moved < old {
                self.up(i);
            } else {
                self.down(i);
            }
        }
        old
    }

    fn up(&mut self, mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if self.heap[parent] <= self.heap[i] {
                break;
            }
            self.swap(i, parent);
            i = parent;
        }
    }

    fn down(&mut self, mut i: usize) {
        loop {
            let left = i * 2 + 1;
            let right = left + 1;
            if left >= self.heap.len() {
                break;
            }
            let child = if right < self.heap.len() && self.heap[right] < self.heap[left] {
                right
            } else {
                left
            };
            if self.heap[i] <= self.heap[child] {
                break;
            }
            self.swap(i, child);
            i = child;
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        self.positions.insert(self.heap[a].1, a);
        self.positions.insert(self.heap[b].1, b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn two_owners_remain_inline_while_deadlines_move() {
        let now = Instant::now();
        let later = now + Duration::from_millis(1);
        let mut queue = Deadlines::default();
        queue.set(9, Some(now));
        queue.set(5, Some(later));
        queue.set(9, Some(later));
        assert_eq!(queue.next(), Some(later));
        assert_eq!(queue.take_due(now), None);
        assert_eq!(queue.take_due(later), Some((later, 5)));
        queue.set(9, None);
        assert_eq!(queue.next(), None);
        assert!(matches!(queue.0, Queue::Inline([None, None])));
    }

    #[test]
    fn advances_postpones_and_removes_keys_in_place() {
        let start = Instant::now();
        let at = |offset| start + Duration::from_millis(offset);
        let mut queue = Deadlines::default();
        for key in 1..=32 {
            queue.set(key, Some(at(key)));
        }
        queue.set(16, None);
        queue.set(32, Some(at(1)));
        queue.set(2, Some(at(19)));
        queue.set(2, Some(at(19)));
        assert!(matches!(&queue.0, Queue::Indexed(index) if index.heap.len() == 31));
        assert_eq!(queue.take_due(start), None);
        assert_eq!(queue.take_due(at(1)), Some((at(1), 1)));
        assert_eq!(queue.take_due(at(1)), Some((at(1), 32)));
        assert_eq!(queue.next(), Some(at(3)));
        let mut expected = (3..32).filter(|&key| key != 16).collect::<Vec<_>>();
        expected.push(2);
        expected.sort_unstable_by_key(|&key| (if key == 2 { 19 } else { key }, key));
        for key in expected {
            let deadline = at(if key == 2 { 19 } else { key });
            assert_eq!(queue.take_due(at(32)), Some((deadline, key)));
        }
        assert_eq!(queue.next(), None);
        assert!(matches!(&queue.0, Queue::Indexed(index) if index.positions.is_empty()));
    }
}
