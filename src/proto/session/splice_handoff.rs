//! Prepaid logical delivery that outlives the splice direction.

use std::{
    collections::BTreeMap,
    ops::Range,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use crate::{Limiter, proto::limit::refund};

/// A consistent snapshot of logical target acceptance and settlement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpliceHandoffStats {
    /// Logical bytes accepted by the target.
    pub accepted_bytes: u64,
    /// Logical bytes with a first complete local carrier handoff.
    pub first_carrier_bytes: u64,
    /// Logical bytes that have no remaining local carrier opportunity.
    pub unsent_bytes: u64,
    /// Accepted bytes still awaiting their first carrier outcome.
    pub pending_bytes: u64,
    /// Prepaid bytes refunded after their final opportunity was lost.
    pub unsent_refunded_bytes: u64,
    /// Logical datagrams whose first complete handoff was native.
    pub native_count: u64,
    /// Logical datagrams whose first complete handoff was in a record.
    pub record_count: u64,
}

/// A live view of target handoffs, including those completed after the splice ends.
#[derive(Clone, Debug, Default)]
pub struct SpliceHandoffs(Arc<Mutex<SpliceHandoffStats>>);

impl SpliceHandoffs {
    /// Observes the current target settlement.
    #[must_use]
    pub fn get(&self) -> SpliceHandoffStats {
        *lock(&self.0)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) struct Prepayment<'a> {
    tally: &'a SpliceHandoffs,
    grant: Option<(&'a Arc<dyn Limiter>, &'a mut u64)>,
}

impl<'a> Prepayment<'a> {
    pub(crate) fn new(
        tally: &'a SpliceHandoffs,
        grant: Option<(&'a Arc<dyn Limiter>, &'a mut u64)>,
    ) -> Self {
        Self { tally, grant }
    }

    pub(crate) fn prepare(&self, bytes: usize) -> HandoffSpan {
        // An empty datagram has an item outcome even though it costs no bytes.
        let end = bytes.max(1);
        HandoffSpan(Arc::new(View {
            delivery: Arc::new(Delivery {
                bytes,
                tally: self.tally.clone(),
                limiter: self.grant.as_ref().map(|(limiter, _)| (*limiter).clone()),
                state: Mutex::new(State {
                    accepted: false,
                    ranges: BTreeMap::from([(
                        0,
                        Part {
                            end,
                            views: 1,
                            pending: true,
                        },
                    )]),
                }),
            }),
            range: 0..end,
        }))
    }

    pub(crate) fn accept(&mut self, span: &HandoffSpan) {
        let delivery = &span.0.delivery;
        let mut state = lock(&delivery.state);
        assert!(!state.accepted);
        let n = delivery.bytes as u64;
        if let Some((_, left)) = &mut self.grant {
            **left -= n;
        }
        state.accepted = true;
        let mut tally = lock(&self.tally.0);
        tally.accepted_bytes += n;
        tally.pending_bytes += n;
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Medium {
    Stream,
    Record,
    Native,
}

#[derive(Clone)]
pub(crate) struct HandoffSpan(Arc<View>);

impl std::fmt::Debug for HandoffSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandoffSpan")
            .field("range", &self.0.range)
            .finish_non_exhaustive()
    }
}

struct View {
    delivery: Arc<Delivery>,
    range: Range<usize>,
}

struct Delivery {
    bytes: usize,
    tally: SpliceHandoffs,
    limiter: Option<Arc<dyn Limiter>>,
    state: Mutex<State>,
}

struct State {
    accepted: bool,
    ranges: BTreeMap<usize, Part>,
}

#[derive(Clone, Copy)]
struct Part {
    end: usize,
    views: usize,
    pending: bool,
}

impl State {
    fn split(&mut self, at: usize) {
        if let Some((_, left)) = self.ranges.range_mut(..at).next_back()
            && at < left.end
        {
            let right = *left;
            left.end = at;
            self.ranges.insert(at, right);
        }
    }

    fn boundaries(&mut self, range: &Range<usize>) {
        self.split(range.start);
        self.split(range.end);
    }
}

impl HandoffSpan {
    pub(super) fn slice(&self, offset: usize, count: usize) -> Self {
        let source = &self.0;
        if offset == 0 && count == source.range.len() {
            return self.clone();
        }
        let start = source.range.start + offset;
        let range = start..start + count;
        assert!(range.end <= source.range.end && !range.is_empty());
        let mut state = lock(&source.delivery.state);
        state.boundaries(&range);
        for (_, part) in state.ranges.range_mut(range.clone()) {
            part.views += 1;
        }
        drop(state);
        Self(Arc::new(View {
            delivery: source.delivery.clone(),
            range,
        }))
    }

    pub(super) fn handed_off(&self, medium: Medium) {
        let view = &self.0;
        let delivery = &view.delivery;
        let mut state = lock(&delivery.state);
        debug_assert!(state.accepted);
        let mut first = 0;
        for (&start, part) in state.ranges.range_mut(view.range.clone()) {
            if std::mem::take(&mut part.pending) {
                first += part.end - start;
            }
        }
        let mut tally = lock(&delivery.tally.0);
        let bytes = first.min(delivery.bytes) as u64;
        tally.pending_bytes -= bytes;
        tally.first_carrier_bytes += bytes;
        match medium {
            Medium::Stream => {}
            Medium::Record => {
                tally.record_count += u64::from(first != 0);
            }
            Medium::Native => {
                tally.native_count += u64::from(first != 0);
            }
        }
    }
}

impl Drop for View {
    fn drop(&mut self) {
        let mut state = lock(&self.delivery.state);
        if !state.accepted {
            return;
        }
        let mut unsent = 0;
        for _ in state.ranges.extract_if(self.range.clone(), |&start, part| {
            part.views -= 1;
            if part.views != 0 {
                return false;
            }
            if part.pending {
                unsent += part.end - start;
            }
            true
        }) {}
        let unsent = unsent.min(self.delivery.bytes) as u64;
        if unsent == 0 {
            return;
        }
        let mut tally = lock(&self.delivery.tally.0);
        tally.pending_bytes -= unsent;
        tally.unsent_bytes += unsent;
        drop(tally);
        drop(state);
        if let Some(limiter) = &self.delivery.limiter {
            let limiter = limiter.clone();
            let tally = self.delivery.tally.clone();
            crate::lock_scope::outside_session(move || {
                crate::lock_scope::assert_none();
                refund(Some(&*limiter), unsent);
                lock(&tally.0).unsent_refunded_bytes += unsent;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        task::{Context, Poll},
    };

    use super::{super::TransmitBuf, *};

    #[derive(Default)]
    struct Refunds(AtomicU64);

    impl Limiter for Refunds {
        fn poll_acquire(
            &self,
            _: &mut Context<'_>,
            _: u64,
            _: u64,
        ) -> Poll<Result<u64, crate::LimitError>> {
            unreachable!()
        }

        fn try_acquire(&self, _: u64, _: u64) -> u64 {
            unreachable!()
        }

        fn refund(&self, n: u64) {
            crate::lock_scope::assert_none();
            self.0.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[test]
    fn complete_record_prefix_keeps_only_the_live_retry() {
        let tally = SpliceHandoffs::default();
        let refunds = Arc::new(Refunds::default());
        let limiter: Arc<dyn Limiter> = refunds.clone();
        let mut credit = 6;
        let mut payment = Prepayment::new(&tally, Some((&limiter, &mut credit)));
        let span = payment.prepare(6);
        payment.accept(&span);
        assert_eq!(credit, 0);

        let retry = span.slice(3, 1);
        let mut transmit = TransmitBuf::default();
        for (offset, capsule) in [(0, b"\x21\x01a"), (3, b"\x22\x01b")] {
            transmit.begin_record(3);
            transmit.push_bytes(capsule);
            transmit.track_handoff(span.slice(offset, 3), Medium::Stream);
            assert!(transmit.end_record());
        }
        drop(span);
        assert_eq!(tally.get().pending_bytes, 6);

        {
            let _scope = crate::lock_scope::ReceiptScope::new();
            #[cfg(debug_assertions)]
            let _lock = crate::lock_scope::Token::new();
            transmit.settle_handoffs(5, true);
            assert_eq!(refunds.0.load(Ordering::Relaxed), 0);
            assert_eq!(tally.get().first_carrier_bytes, 3);
            assert_eq!(tally.get().pending_bytes, 1);
            assert_eq!(tally.get().unsent_bytes, 2);
        }
        assert_eq!(tally.get().unsent_refunded_bytes, 2);
        assert_eq!(refunds.0.load(Ordering::Relaxed), 2);

        retry.handed_off(Medium::Stream);
        retry.handed_off(Medium::Stream);
        drop(retry);
        assert_eq!(
            tally.get(),
            SpliceHandoffStats {
                accepted_bytes: 6,
                first_carrier_bytes: 4,
                unsent_bytes: 2,
                unsent_refunded_bytes: 2,
                ..SpliceHandoffStats::default()
            }
        );
    }

    #[test]
    fn late_datagram_replica_settles_once_across_representations() {
        let tally = SpliceHandoffs::default();
        let refunds = Arc::new(Refunds::default());
        let limiter: Arc<dyn Limiter> = refunds.clone();
        let mut credit = 5;
        let mut payment = Prepayment::new(&tally, Some((&limiter, &mut credit)));
        let accepted = payment.prepare(2);
        let rejected = payment.prepare(3);
        payment.accept(&accepted);
        payment.accept(&rejected);
        assert_eq!(credit, 0);

        let replica = accepted.clone();
        let other_replica = accepted.clone();
        drop(accepted);
        assert_eq!(tally.get().pending_bytes, 5);
        replica.handed_off(Medium::Native);
        other_replica.handed_off(Medium::Record);
        drop(rejected);
        drop(replica);
        drop(other_replica);
        assert_eq!(
            tally.get(),
            SpliceHandoffStats {
                accepted_bytes: 5,
                first_carrier_bytes: 2,
                unsent_bytes: 3,
                unsent_refunded_bytes: 3,
                native_count: 1,
                ..SpliceHandoffStats::default()
            }
        );
        assert_eq!(refunds.0.load(Ordering::Relaxed), 3);
    }
}
