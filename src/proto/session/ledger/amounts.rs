//! A multiset of amounts kept in order with subtree counts and sums, so that
//! the capped sum (the sum over a level's stream
//! directions of min(ready_j, r)) costs O(log n) for any r.
//!
//! A treap: one node per distinct amount, with its multiplicity; node
//! priorities come from a process-wide random seed, so the expected depth is
//! O(log n) whatever amounts the peer's credit makes the directions hold.

use std::sync::OnceLock;

type Link = Option<u32>;

#[derive(Debug, Clone)]
struct Node {
    amount: u64,
    count: u64,
    priority: u64,
    left: Link,
    right: Link,
    /// The amounts in the subtree, counted with multiplicity, and their sum.
    n: u64,
    sum: u128,
}

/// A multiset of amounts (see the module documentation).
#[derive(Debug, Clone, Default)]
pub(super) struct Amounts {
    nodes: Vec<Node>,
    free: Vec<u32>,
    root: Link,
    /// Priorities drawn so far.
    draws: u64,
}

/// SplitMix64, for the node priorities.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(super::super::random_u64)
}

impl Amounts {
    /// The amounts, counted with multiplicity.
    #[cfg(test)]
    fn len(&self) -> u64 {
        self.n(self.root)
    }

    /// The sum of all amounts.
    #[cfg(test)]
    fn total(&self) -> u128 {
        self.sum(self.root)
    }

    /// The sum over the amounts a of min(a, cap).
    pub(super) fn capped_sum(&self, cap: u64) -> u128 {
        let mut acc = 0u128;
        let mut at = self.root;
        while let Some(i) = at {
            let x = &self.nodes[i as usize];
            if x.amount < cap {
                acc += self.sum(x.left) + u128::from(x.amount) * u128::from(x.count);
                at = x.right;
            } else {
                acc += u128::from(cap) * u128::from(x.count + self.n(x.right));
                at = x.left;
            }
        }
        acc
    }

    /// Adds one amount.
    pub(super) fn insert(&mut self, amount: u64) {
        if self.find(amount).is_some() {
            self.walk(amount, true);
            return;
        }
        let node = Node {
            amount,
            count: 1,
            priority: mix(seed() ^ self.draws),
            left: None,
            right: None,
            n: 1,
            sum: u128::from(amount),
        };
        self.draws = self.draws.wrapping_add(1);
        let i = match self.free.pop() {
            Some(i) => {
                self.nodes[i as usize] = node;
                i
            }
            None => {
                let i = u32::try_from(self.nodes.len()).expect("a node index fits 32 bits");
                self.nodes.push(node);
                i
            }
        };
        let (lo, hi) = self.split(self.root, amount);
        let lo = self.merge(lo, Some(i));
        self.root = self.merge(lo, hi);
    }

    /// Removes one amount, which must be there.
    pub(super) fn remove(&mut self, amount: u64) {
        let Some(i) = self.find(amount) else {
            debug_assert!(false, "removing an amount not counted");
            return;
        };
        if self.nodes[i as usize].count > 1 {
            self.walk(amount, false);
            return;
        }
        // Unlink the node: every ancestor loses it, its parent takes the
        // merge of its children.
        let mut parent: Option<(u32, bool)> = None;
        let mut at = self.root;
        while let Some(j) = at {
            if j == i {
                break;
            }
            let x = &mut self.nodes[j as usize];
            x.n -= 1;
            x.sum -= u128::from(amount);
            let left = amount < x.amount;
            parent = Some((j, left));
            at = if left { x.left } else { x.right };
        }
        let (l, r) = {
            let x = &self.nodes[i as usize];
            (x.left, x.right)
        };
        let joined = self.merge(l, r);
        match parent {
            None => self.root = joined,
            Some((p, true)) => self.nodes[p as usize].left = joined,
            Some((p, false)) => self.nodes[p as usize].right = joined,
        }
        self.free.push(i);
        if self.root.is_none() {
            // Empty: the slots go, the vectors keep their room.
            self.nodes.clear();
            self.free.clear();
        }
    }

    /// The amounts in order with their multiplicities (debug recounts).
    #[cfg(debug_assertions)]
    pub(super) fn items(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut stack = Vec::new();
        let mut at = self.root;
        while at.is_some() || !stack.is_empty() {
            while let Some(i) = at {
                stack.push(i);
                at = self.nodes[i as usize].left;
            }
            let i = stack.pop().expect("non-empty");
            let x = &self.nodes[i as usize];
            out.push((x.amount, x.count));
            at = x.right;
        }
        out
    }

    fn n(&self, at: Link) -> u64 {
        at.map_or(0, |i| self.nodes[i as usize].n)
    }

    fn sum(&self, at: Link) -> u128 {
        at.map_or(0, |i| self.nodes[i as usize].sum)
    }

    fn find(&self, amount: u64) -> Link {
        let mut at = self.root;
        while let Some(i) = at {
            let x = &self.nodes[i as usize];
            if amount == x.amount {
                return Some(i);
            }
            at = if amount < x.amount { x.left } else { x.right };
        }
        None
    }

    /// One more (`add`) or one less of an amount that has a node, along
    /// the path to it.
    fn walk(&mut self, amount: u64, add: bool) {
        let mut at = self.root;
        while let Some(i) = at {
            let x = &mut self.nodes[i as usize];
            if add {
                x.n += 1;
                x.sum += u128::from(amount);
            } else {
                x.n -= 1;
                x.sum -= u128::from(amount);
            }
            if amount == x.amount {
                if add {
                    x.count += 1;
                } else {
                    x.count -= 1;
                }
                return;
            }
            at = if amount < x.amount { x.left } else { x.right };
        }
    }

    fn pull(&mut self, i: u32) {
        let (l, r) = {
            let x = &self.nodes[i as usize];
            (x.left, x.right)
        };
        let (n, sum) = (self.n(l) + self.n(r), self.sum(l) + self.sum(r));
        let x = &mut self.nodes[i as usize];
        x.n = n + x.count;
        x.sum = sum + u128::from(x.amount) * u128::from(x.count);
    }

    /// Splits a subtree into the amounts below `amount` and the others.
    fn split(&mut self, at: Link, amount: u64) -> (Link, Link) {
        let Some(i) = at else {
            return (None, None);
        };
        if self.nodes[i as usize].amount < amount {
            let (lo, hi) = self.split(self.nodes[i as usize].right, amount);
            self.nodes[i as usize].right = lo;
            self.pull(i);
            (Some(i), hi)
        } else {
            let (lo, hi) = self.split(self.nodes[i as usize].left, amount);
            self.nodes[i as usize].left = hi;
            self.pull(i);
            (lo, Some(i))
        }
    }

    /// Joins two subtrees, every amount of `a` below every amount of `b`.
    fn merge(&mut self, a: Link, b: Link) -> Link {
        match (a, b) {
            (None, x) | (x, None) => x,
            (Some(i), Some(j)) => {
                if self.nodes[i as usize].priority >= self.nodes[j as usize].priority {
                    let r = self.merge(self.nodes[i as usize].right, Some(j));
                    self.nodes[i as usize].right = r;
                    self.pull(i);
                    Some(i)
                } else {
                    let l = self.merge(Some(i), self.nodes[j as usize].left);
                    self.nodes[j as usize].left = l;
                    self.pull(j);
                    Some(j)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(v: &[u64], cap: u64) -> u128 {
        v.iter().map(|&a| u128::from(a.min(cap))).sum()
    }

    /// The capped sums equal a recount through inserts and removals,
    /// duplicates included.
    #[test]
    fn capped_sums_match_a_recount() {
        let mut a = Amounts::default();
        let mut v: Vec<u64> = Vec::new();
        let mut x = 7u64;
        for step in 0..4000u64 {
            x = mix(x);
            let amount = (x % 64) * 16_384 + (x >> 60);
            if !v.is_empty() && (x >> 8).is_multiple_of(3) {
                let k = v.swap_remove(((x >> 16) as usize) % v.len());
                a.remove(k);
            } else {
                v.push(amount);
                a.insert(amount);
            }
            if step.is_multiple_of(97) {
                for cap in [0, 1, 16_384, 300_000, 1 << 20, u64::MAX] {
                    assert_eq!(a.capped_sum(cap), naive(&v, cap), "cap {cap}");
                }
                assert_eq!(a.len(), v.len() as u64);
                assert_eq!(a.total(), naive(&v, u64::MAX));
            }
        }
        while let Some(k) = v.pop() {
            a.remove(k);
        }
        assert_eq!((a.len(), a.total(), a.capped_sum(5)), (0, 0, 0));
        assert!(a.nodes.is_empty());
    }
}
