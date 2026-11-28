//! The send owner attributes proved bytes to the original dispatch second.

use std::collections::VecDeque;

use super::shaping::{CostPrecision, LedgerStats, Limits, ProfileLimits, WindowStats};

#[derive(Debug, Default)]
struct Bin {
    second: u64,
    baseline: u64,
    provisional: u64,
    consumed: u64,
    unresolved: Option<u64>,
}

/// A reservation belongs to exactly one handoff and survives policy changes.
#[derive(Debug)]
pub(super) struct Dispatch {
    second: u64,
    remaining: u64,
}

#[derive(Debug, Default)]
pub(super) struct Ledger {
    bins: VecDeque<Bin>,
    reserved: u64,
    measured: u64,
    baseline: u64,
    provisional: u64,
    discarded_until: u64,
}

impl Ledger {
    fn prune(&mut self, second: u64, limits: Limits) -> u64 {
        let longest = limits
            .profiles()
            .map(|profile| u64::from(profile.window_seconds))
            .max()
            .unwrap_or(u64::from(ProfileLimits::LIGHTWEIGHT.window_seconds));
        let first = second.saturating_sub(longest);
        while self.bins.front().is_some_and(|bin| bin.second < first) {
            let bin = self.bins.pop_front().expect("expired bin");
            if bin.consumed != 0 || bin.unresolved.is_some() {
                self.discarded_until = self.discarded_until.max(bin.second + 1);
            }
        }
        first
    }

    fn bin(&mut self, second: u64) -> &mut Bin {
        let index = self.bins.partition_point(|bin| bin.second < second);
        if self.bins.get(index).is_none_or(|bin| bin.second != second) {
            // Setup and otherwise idle sessions normally use one observation bin.
            if self.bins.capacity() == 0 {
                self.bins.reserve_exact(1);
            }
            self.bins.insert(
                index,
                Bin {
                    second,
                    ..Bin::default()
                },
            );
        }
        &mut self.bins[index]
    }

    fn window(&self, second: u64, profile: ProfileLimits) -> WindowStats {
        let first = second.checked_sub(u64::from(profile.window_seconds));
        let mut stats = WindowStats {
            profile,
            history_complete: first
                .map_or(self.discarded_until == 0, |s| s >= self.discarded_until),
            baseline_bytes: 0,
            consumed_bytes: 0,
            reserved_bytes: self.reserved,
            allowance_bytes: 0,
        };
        for bin in self.bins.iter().rev() {
            if first.is_some_and(|s| bin.second < s) {
                break;
            }
            if first != Some(bin.second) {
                stats.baseline_bytes = stats.baseline_bytes.saturating_add(bin.baseline);
            }
            stats.consumed_bytes = stats.consumed_bytes.saturating_add(bin.consumed);
            stats.reserved_bytes = stats
                .reserved_bytes
                .saturating_add(bin.unresolved.unwrap_or(0));
        }
        stats.allowance_bytes = profile.allowance(stats.baseline_bytes);
        stats
    }

    fn precision(&self, second: u64, limits: Limits) -> CostPrecision {
        let longest = limits
            .profiles()
            .map(|p| p.window_seconds)
            .max()
            .unwrap_or(0);
        if self
            .bins
            .iter()
            .rev()
            .take_while(|bin| second.saturating_sub(bin.second) <= u64::from(longest))
            .any(|bin| bin.unresolved.is_some())
        {
            CostPrecision::Unavailable
        } else {
            CostPrecision::Exact
        }
    }

    pub(super) fn room(&self, second: u64, limits: Limits) -> u64 {
        if self.precision(second, limits) == CostPrecision::Unavailable {
            return 0;
        }
        limits
            .profiles()
            .map(|profile| {
                let window = self.window(second, profile);
                if window.history_complete {
                    window
                        .allowance_bytes
                        .saturating_sub(window.consumed_bytes)
                        .saturating_sub(window.reserved_bytes)
                } else {
                    0
                }
            })
            .min()
            .unwrap_or(0)
    }

    pub(super) fn reserve(&mut self, extra: u64) {
        self.reserved = self
            .reserved
            .checked_add(extra)
            .expect("bounded live reservations");
    }

    pub(super) fn release(&mut self, extra: u64) {
        self.reserved -= extra;
    }

    pub(super) fn commit(&mut self, second: u64, limits: Limits, extra: u64) -> Dispatch {
        self.prune(second, limits);
        // Layout and immediate submission run in the same owner turn.
        debug_assert!(extra == 0 || extra <= self.room(second, limits));
        self.reserve(extra);
        Dispatch {
            second,
            remaining: extra,
        }
    }

    pub(super) fn progress(
        &mut self,
        dispatch: &mut Dispatch,
        now: (u64, Limits),
        baseline: u64,
        extra: u64,
        provisional: bool,
    ) {
        dispatch.remaining -= extra;
        self.reserved -= extra;
        self.measured = self.measured.saturating_add(extra);
        let credit = if provisional {
            &mut self.provisional
        } else {
            &mut self.baseline
        };
        *credit = credit.saturating_add(baseline);
        if dispatch.second < self.prune(now.0, now.1) {
            if extra != 0 {
                self.discarded_until = self.discarded_until.max(dispatch.second + 1);
            }
        } else if baseline != 0 || extra != 0 {
            let bin = self.bin(dispatch.second);
            let credit = if provisional {
                &mut bin.provisional
            } else {
                &mut bin.baseline
            };
            *credit = credit.saturating_add(baseline);
            bin.consumed = bin.consumed.saturating_add(extra);
        }
    }

    pub(super) fn finish(
        &mut self,
        Dispatch { second, remaining }: Dispatch,
        now: (u64, Limits),
        unknown: bool,
    ) {
        self.reserved -= remaining;
        if unknown && second >= self.prune(now.0, now.1) {
            let unresolved = self.bin(second).unresolved.get_or_insert(0);
            *unresolved = unresolved.saturating_add(remaining);
        }
    }

    pub(super) fn prove_baseline(&mut self, at: u64, now: (u64, Limits), baseline: u64) {
        self.baseline = self.baseline.saturating_add(baseline);
        if baseline != 0 && at >= self.prune(now.0, now.1) {
            let bin = self.bin(at);
            bin.baseline = bin.baseline.saturating_add(baseline);
        }
    }

    pub(super) fn early_verdict(&mut self, accepted: bool) {
        let provisional = std::mem::take(&mut self.provisional);
        if accepted {
            self.baseline = self.baseline.saturating_add(provisional);
        }
        for bin in &mut self.bins {
            let baseline = std::mem::take(&mut bin.provisional);
            if accepted {
                bin.baseline = bin.baseline.saturating_add(baseline);
            }
        }
    }

    pub(super) fn stats(&self, second: u64, limits: Limits) -> LedgerStats {
        LedgerStats {
            boundary: super::shaping::ObservationBoundary::ZmuxHandoff,
            precision: self.precision(second, limits),
            policy: limits.profile.map(|p| self.window(second, p)),
            local: limits.local_profile.map(|p| self.window(second, p)),
            measured_bytes: self.measured,
            baseline_bytes: self.baseline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shaping::Budget;
    use std::time::Duration;

    fn limits(window: u32, ppm: u32, floor: u64) -> Limits {
        Limits::default().under(&Budget::new(
            None,
            Some(ProfileLimits::new(window, ppm, floor, Duration::ZERO)),
            false,
        ))
    }

    #[test]
    fn a_held_increment_cannot_reuse_expired_baseline() {
        let mut ledger = Ledger::default();
        let policy = limits(10, 50_000, 0);
        ledger.prove_baseline(0, (0, policy), 100);
        assert_eq!(ledger.room(9, policy), 5);
        ledger.reserve(5);
        assert_eq!(ledger.stats(9, policy).policy.unwrap().reserved_bytes, 5);
        ledger.release(5);
        assert_eq!(ledger.room(10, policy), 0);
        assert_eq!(ledger.stats(10, policy).policy.unwrap().baseline_bytes, 0);
    }

    #[test]
    fn a_longer_window_waits_for_discarded_charges_and_late_unknown_keeps_its_bin() {
        let mut ledger = Ledger::default();
        let original = limits(3, 0, 8);
        let mut done = ledger.commit(0, original, 8);
        ledger.progress(&mut done, (0, original), 0, 8, false);
        ledger.finish(done, (0, original), false);
        let old = ledger.commit(0, original, 0);
        ledger.finish(old, (4, original), true);
        let longer = limits(10, 0, 8);
        let stats = ledger.stats(4, longer);
        assert_eq!(stats.precision, CostPrecision::Exact);
        assert!(!stats.policy.unwrap().history_complete);
        assert_eq!(ledger.room(4, longer), 0);
        assert_eq!(ledger.room(11, longer), 8);
        assert_eq!(ledger.stats(11, longer).measured_bytes, 8);
    }
}
