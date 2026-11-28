//! Completed protocol records attributed to the carrier halves that carried them.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::{CarrierConnId, CarrierKind, PipeId};

/// Accounting settings for each attachment in a session.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct AccountingPolicy {
    /// Enable tickets and in-service totals, including bootstrap.
    pub enabled: bool,
    /// Maximum distinct known sources per attachment. Zero selects 16.
    pub source_limit: usize,
    /// Reject an attachment that cannot retain every known source.
    pub strict: bool,
}

/// Attribution supplied at the ownership boundary of a carrier half.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CarrierHalfSource {
    /// Physical connection identity, where the adapter can prove it.
    pub connection: Option<CarrierConnId>,
    /// Carrier kind, where known.
    pub kind: Option<CarrierKind>,
    /// Host's opaque route identity.
    pub route: Option<std::sync::Arc<str>>,
}

impl CarrierHalfSource {
    /// Creates the source of this physical connection and carrier kind.
    #[must_use]
    pub fn new(kind: CarrierKind, connection: Option<CarrierConnId>) -> Self {
        Self {
            connection,
            kind: Some(kind),
            route: None,
        }
    }
}

/// Immutable source descriptions for the two local directions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarrierHalfSources {
    /// Local sending source.
    pub send: CarrierHalfSource,
    /// Local receiving source.
    pub receive: CarrierHalfSource,
}

impl CarrierHalfSources {
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn over_budget(&self, send: bool, receive: bool, policy: AccountingPolicy) -> bool {
        policy.enabled
            && send
            && receive
            && policy.source_limit == 1
            && self.send != self.receive
            && self.send != CarrierHalfSource::default()
            && self.receive != CarrierHalfSource::default()
    }

    /// A carrier that explicitly identifies the same connection for both halves.
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn from_carrier(
        kind: Option<CarrierKind>,
        connection: Option<&CarrierConnId>,
    ) -> Self {
        let send = CarrierHalfSource {
            kind,
            connection: connection.cloned(),
            route: None,
        };
        Self {
            receive: send.clone(),
            send,
        }
    }
}

/// Completed records and known incomplete bytes from a single source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HalfTotals {
    /// Origin of the bytes.
    pub source: CarrierHalfSource,
    /// Bytes in complete records, including any protocol Size field.
    pub bytes: u64,
    /// Complete records.
    pub records: u64,
    /// Complete record bytes still held by active lanes in this source segment.
    pub active_complete_record_bytes: u64,
    /// Complete record bytes folded from retired lanes and source segments.
    pub retired_complete_record_bytes: u64,
    /// Bytes of incomplete records already accepted or received.
    pub partial_bytes: u64,
    /// A carrier I/O error could not report its exact partial bytes.
    pub imprecise: bool,
    /// The source exceeded the configured attribution budget.
    pub source_overflow: bool,
}

/// Directional record accounting for an attachment, including retired lanes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeAccounting {
    /// Attachment ID.
    pub pipe: PipeId,
    /// Outbound totals.
    pub send: Vec<HalfTotals>,
    /// Inbound totals.
    pub receive: Vec<HalfTotals>,
}

#[derive(Debug, Default)]
struct HalfAccounting {
    totals: Vec<HalfTotals>,
    active: Option<usize>,
    lanes: HashMap<u64, LaneTotals>,
}

#[derive(Debug, Default)]
struct LaneTotals {
    bytes: u64,
    records: u64,
    partial: u64,
}

impl HalfTotals {
    fn merge_lane(&mut self, lane: &LaneTotals, retired: bool) {
        let bytes = if retired {
            &mut self.retired_complete_record_bytes
        } else {
            &mut self.active_complete_record_bytes
        };
        *bytes = bytes.saturating_add(lane.bytes);
        self.bytes = self.bytes.saturating_add(lane.bytes);
        self.records = self.records.saturating_add(lane.records);
        self.partial_bytes = self.partial_bytes.saturating_add(lane.partial);
    }
}

impl HalfAccounting {
    fn charge(&mut self, lane: u64, bytes: u64, records: u64, partial: u64) {
        if self.active.is_some()
            && (bytes != 0 || records != 0 || partial != 0 || self.lanes.contains_key(&lane))
        {
            let total = self.lanes.entry(lane).or_default();
            total.bytes = total.bytes.saturating_add(bytes);
            total.records = total.records.saturating_add(records);
            total.partial = partial;
        }
    }

    fn close_lane(&mut self, lane: u64) {
        if let Some(active) = self.active
            && let Some(lane) = self.lanes.remove(&lane)
        {
            self.totals[active].merge_lane(&lane, true);
        }
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    fn close_all_lanes(&mut self) {
        if let Some(active) = self.active {
            for (_, lane) in self.lanes.drain() {
                self.totals[active].merge_lane(&lane, true);
            }
        }
    }

    fn imprecise(&mut self) {
        if let Some(active) = self.active {
            self.totals[active].imprecise = true;
        }
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    fn select(&mut self, source: CarrierHalfSource, overflow: bool) {
        if let Some(active) = self.active {
            let total = &self.totals[active];
            if total.source == source && total.source_overflow == overflow {
                return;
            }
            self.close_all_lanes();
        }
        let index = self
            .totals
            .iter()
            .position(|total| total.source == source && total.source_overflow == overflow)
            .unwrap_or_else(|| {
                self.totals.push(HalfTotals {
                    source,
                    source_overflow: overflow,
                    ..HalfTotals::default()
                });
                self.totals.len() - 1
            });
        self.active = Some(index);
    }

    fn snapshot(&self) -> Vec<HalfTotals> {
        let mut totals = self.totals.clone();
        if let Some(active) = self.active {
            for lane in self.lanes.values() {
                totals[active].merge_lane(lane, false);
            }
        }
        totals
    }
}

#[derive(Debug)]
struct Counters {
    pipe: PipeId,
    send: HalfAccounting,
    receive: HalfAccounting,
    #[cfg(all(feature = "tokio", not(loom)))]
    policy: AccountingPolicy,
}

#[derive(Debug)]
pub(crate) struct Ledger(Mutex<Counters>);

impl Ledger {
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn new(
        pipe: PipeId,
        sources: CarrierHalfSources,
        send: bool,
        receive: bool,
        policy: AccountingPolicy,
    ) -> Self {
        let mut c = Counters {
            pipe,
            send: HalfAccounting::default(),
            receive: HalfAccounting::default(),
            #[cfg(all(feature = "tokio", not(loom)))]
            policy,
        };
        let overflow = sources.over_budget(send, receive, policy);
        if receive {
            c.receive.select(sources.receive, false);
        }
        if send {
            let source = if overflow {
                CarrierHalfSource::default()
            } else {
                sources.send
            };
            c.send.select(source, overflow);
        }
        Self(Mutex::new(c))
    }

    fn lock(&self) -> MutexGuard<'_, Counters> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Switches to confirmed new source metadata, preserving all prior buckets.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn switch(&self, sources: CarrierHalfSources) -> bool {
        let mut c = self.lock();
        let mut known = Vec::new();
        for total in c.send.totals.iter().chain(&c.receive.totals) {
            if total.source != CarrierHalfSource::default() && !known.contains(&total.source) {
                known.push(total.source.clone());
            }
        }
        let limit = if c.policy.source_limit == 0 {
            16
        } else {
            c.policy.source_limit
        };
        let mut admit = |source: CarrierHalfSource| {
            if source == CarrierHalfSource::default() || known.contains(&source) {
                return (source, false);
            }
            if known.len() < limit {
                known.push(source.clone());
                (source, false)
            } else {
                (CarrierHalfSource::default(), true)
            }
        };
        let receive = c.receive.active.map(|_| admit(sources.receive));
        let send = c.send.active.map(|_| admit(sources.send));
        if c.policy.strict
            && [send.as_ref(), receive.as_ref()]
                .into_iter()
                .flatten()
                .any(|(_, overflow)| *overflow)
        {
            return false;
        }
        if let Some((source, overflow)) = receive {
            c.receive.select(source, overflow);
        }
        if let Some((source, overflow)) = send {
            c.send.select(source, overflow);
        }
        true
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn write_progress(&self, lane: u64, bytes: u64, records: u64, partial: u64) {
        self.lock().send.charge(lane, bytes, records, partial);
    }

    pub(crate) fn write_imprecise(&self) {
        self.lock().send.imprecise();
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn finish_write(&self, lane: u64) {
        self.lock().send.close_lane(lane);
    }

    pub(crate) fn receive_complete(
        &self,
        lane: u64,
        len: u64,
        framing: crate::proto::record::Framing,
    ) {
        use crate::proto::record::{Framing, message_len};
        let bytes = if framing == Framing::ByteStream {
            len
        } else {
            message_len(len)
        };
        self.lock().receive.charge(lane, bytes, 1, 0);
    }

    pub(crate) fn pending_read(&self, lane: u64, bytes: u64) {
        self.lock().receive.charge(lane, 0, 0, bytes);
    }

    pub(crate) fn finish_read(&self, lane: u64) {
        self.lock().receive.close_lane(lane);
    }

    pub(crate) fn snapshot(&self) -> PipeAccounting {
        let c = self.lock();
        Self::totals(&c)
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn final_snapshot(&self) -> PipeAccounting {
        let mut c = self.lock();
        c.send.close_all_lanes();
        c.receive.close_all_lanes();
        Self::totals(&c)
    }

    fn totals(c: &Counters) -> PipeAccounting {
        PipeAccounting {
            pipe: c.pipe,
            send: c.send.snapshot(),
            receive: c.receive.snapshot(),
        }
    }
}

#[cfg(all(test, feature = "tokio", not(loom)))]
mod tests {
    use super::*;
    use crate::proto::record::Framing;
    use std::sync::Arc;

    fn source(route: &str) -> CarrierHalfSource {
        CarrierHalfSource {
            route: Some(Arc::from(route)),
            ..CarrierHalfSource::new(CarrierKind::Streaming, None)
        }
    }

    #[test]
    fn lane_and_source_retirement_preserve_complete_and_partial_bytes() {
        let send = source("outbound");
        let receive = source("inbound");
        let ledger = Ledger::new(
            PipeId(5),
            CarrierHalfSources {
                send: send.clone(),
                receive: receive.clone(),
            },
            true,
            true,
            AccountingPolicy {
                enabled: true,
                source_limit: 2,
                strict: false,
            },
        );

        ledger.write_progress(0, 18, 2, 3);
        ledger.write_progress(7, 11, 1, 2);
        ledger.receive_complete(0, 13, Framing::ByteStream);
        ledger.pending_read(3, 4);
        let active = ledger.snapshot();
        ledger.finish_write(7);
        ledger.finish_write(7);
        ledger.finish_read(3);
        let after = ledger.snapshot();
        assert_eq!(after.send[0].active_complete_record_bytes, 18);
        assert_eq!(after.send[0].retired_complete_record_bytes, 11);
        assert_eq!(after.send[0].bytes, active.send[0].bytes);
        assert_eq!(after.send[0].partial_bytes, active.send[0].partial_bytes);
        assert_eq!(after.receive, active.receive);
        assert_eq!(
            active.send[0],
            HalfTotals {
                source: send.clone(),
                bytes: 29,
                active_complete_record_bytes: 29,
                records: 3,
                partial_bytes: 5,
                ..HalfTotals::default()
            }
        );
        assert_eq!(
            active.receive[0],
            HalfTotals {
                source: receive.clone(),
                bytes: 13,
                active_complete_record_bytes: 13,
                records: 1,
                partial_bytes: 4,
                ..HalfTotals::default()
            }
        );

        assert!(ledger.switch(CarrierHalfSources {
            send: source("new-outbound"),
            receive
        }));
        ledger.write_progress(0, 17, 1, 3);
        ledger.finish_write(0);
        let final_totals = ledger.snapshot();
        assert_eq!(final_totals.send[0].retired_complete_record_bytes, 29);
        assert_eq!(final_totals.send[0].bytes, active.send[0].bytes);
        assert_eq!(
            final_totals.send[0].partial_bytes,
            active.send[0].partial_bytes
        );
        assert_eq!(final_totals.receive, active.receive);
        assert_eq!(
            final_totals.send[1],
            HalfTotals {
                bytes: 17,
                retired_complete_record_bytes: 17,
                records: 1,
                partial_bytes: 3,
                source_overflow: true,
                ..HalfTotals::default()
            }
        );
        assert_eq!(ledger.snapshot(), final_totals);
    }

    #[test]
    fn a_strict_source_change_is_atomic() {
        let sources = CarrierHalfSources {
            send: source("outbound"),
            receive: source("inbound"),
        };
        let ledger = Ledger::new(
            PipeId(6),
            sources.clone(),
            true,
            true,
            AccountingPolicy {
                enabled: true,
                source_limit: 2,
                strict: true,
            },
        );
        ledger.pending_read(0, 6);
        let before = ledger.snapshot();
        assert!(!ledger.switch(CarrierHalfSources {
            send: source("other"),
            receive: sources.send
        }));
        assert_eq!(ledger.snapshot(), before);
        ledger.receive_complete(0, 13, Framing::ByteStream);
        let after = ledger.snapshot();
        assert_eq!(after.receive[0].source, sources.receive);
        assert_eq!(after.receive[0].bytes, 13);
        assert_eq!(after.receive[0].partial_bytes, 0);
    }
}
