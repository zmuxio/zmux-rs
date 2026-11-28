//! Redundant urgent data: a chunk of a stream direction whose redundancy
//! is on is taken by whichever of the two pipes of its eligible tier with
//! the earliest arrival writes first, and a copy is queued for the other;
//! the first `spread_chunk` of new data after an idle period of a pipe is
//! copied likewise. Copies wait outside the carrier for their pipe's next
//! write opportunity, go ahead of its other stream data, and are bounded
//! by the copy bytes outstanding, counted by the ledger.

use std::time::Duration;

use crate::proto::session::output::Records;
use crate::proto::session::pipes::{Attachment, OutPipe, QueuedCopy};
use crate::proto::session::stream::SendPart;
use crate::proto::session::tier::Gate;
use crate::proto::session::{Redundancy, Scheduler, SessionCore, StreamKey};

/// An idle period lasts at least max(this, `T_suspect`).
const IDLE: Duration = Duration::from_secs(1);
const REPLICA_WINDOW: usize = 10;
const REPLICA_BUCKETS: usize = REPLICA_WINDOW + 1;

#[derive(Debug, Default)]
pub(in crate::proto::session) struct ReplicaBudget {
    buckets: [ReplicaBucket; REPLICA_BUCKETS],
}

#[derive(Clone, Copy, Debug, Default)]
struct ReplicaBucket {
    second: u64,
    original: u64,
    extra: u64,
}

impl ReplicaBudget {
    fn record(&mut self, second: u64, bytes: u64, extra: bool) {
        let index = usize::try_from(second % REPLICA_BUCKETS as u64).expect("bucket index");
        let slot = &mut self.buckets[index];
        if slot.second != second {
            *slot = ReplicaBucket {
                second,
                ..ReplicaBucket::default()
            };
        }
        let counter = if extra {
            &mut slot.extra
        } else {
            &mut slot.original
        };
        *counter = counter.saturating_add(bytes);
    }

    fn room(&self, second: u64, percent: u8, burst: u64) -> u64 {
        let (mut original, mut extra) = (0u128, 0u128);
        for slot in &self.buckets {
            let age = second.saturating_sub(slot.second);
            if age < REPLICA_WINDOW as u64 {
                original += u128::from(slot.original);
            }
            if age <= REPLICA_WINDOW as u64 {
                extra += u128::from(slot.extra);
            }
        }
        let allowance = original * u128::from(percent) / 100 + u128::from(burst);
        u64::try_from(allowance.saturating_sub(extra)).unwrap_or(u64::MAX)
    }
}

impl SessionCore {
    fn replicas_enabled(&self) -> bool {
        self.config.datagram_config().replica_percent != 0
    }

    pub(in crate::proto::session) fn replica_bytes(&mut self, bytes: u64, extra: bool) {
        if bytes == 0 || self.mp.is_none() {
            return;
        }
        let second = self.now.saturating_duration_since(self.started).as_secs();
        self.mp_mut()
            .replica_budget
            .get_or_insert_with(Box::default)
            .record(second, bytes, extra);
    }

    pub(in crate::proto::session) fn replica_room(&self) -> u64 {
        let Some(mp) = self.mp.as_deref() else {
            return 0;
        };
        if !self.replicas_enabled() {
            return 0;
        }
        let percent = self.config.datagram_config().replica_percent;
        let second = self.now.saturating_duration_since(self.started).as_secs();
        mp.replica_budget
            .as_ref()
            .map_or(mp.replica_burst, |budget| {
                budget.room(second, percent, mp.replica_burst)
            })
    }

    pub(in crate::proto::session) fn next_replica_tier(&self, first: u64) -> Option<u64> {
        self.atts
            .iter()
            .filter(|a| {
                !a.standby() && a.send_tier() > first && a.out().is_some_and(|o| o.usable(false))
            })
            .map(Attachment::send_tier)
            .min()
    }

    pub(in crate::proto::session) fn replica_eligible(
        &self,
        original: &Attachment,
        candidate: &Attachment,
        next_tier: Option<u64>,
    ) -> bool {
        let tier = candidate.send_tier();
        candidate.id() != original.id()
            && candidate.out().is_some_and(|o| o.usable(false))
            && if candidate.standby() {
                self.config.datagram_config().replica_standby
            } else {
                tier == original.send_tier() || next_tier == Some(tier)
            }
    }
}

pub(in crate::proto::session) fn independent_fates(a: &Attachment, b: &Attachment) -> bool {
    let fate = a.fate();
    if fate.1 != 0 && fate == b.fate() {
        return false;
    }
    if a.physical_connection()
        .is_some_and(|id| Some(id) == b.physical_connection())
    {
        return false;
    }
    matches!((a.replica_domain(), b.replica_domain()), (Some(x), Some(y)) if x != y)
}

/// The policy that schedules a direction.
fn policy_of<'a>(send: &'a SendPart, session: &'a Scheduler) -> &'a Scheduler {
    send.mp().scheduler.as_ref().unwrap_or(session)
}

/// Whether a stream direction's chunks are sent redundantly: its own
/// `set_redundant` setting, else the session's `redundancy` (urgency 0 to
/// 2). Never under `session-affinity`, whose tiers are a single pipe.
pub(in crate::proto::session) fn redundant(
    send: &SendPart,
    session: Redundancy,
    policy: &Scheduler,
) -> bool {
    !matches!(policy_of(send, policy), Scheduler::SessionAffinity)
        && send
            .mp()
            .redundant
            .unwrap_or(session == Redundancy::Urgent && send.priority.urgency() <= 2)
}

/// Whether the first chunk after an idle period is copied for a stream
/// direction: unless `redundancy` is off or the direction's redundancy is
/// turned off.
fn idle_copied(send: &SendPart, session: Redundancy, policy: &Scheduler) -> bool {
    !matches!(policy_of(send, policy), Scheduler::SessionAffinity)
        && send.mp().redundant.unwrap_or(session != Redundancy::Off)
}

impl SessionCore {
    /// Whether a stream direction's chunks are sent redundantly.
    pub(in crate::proto::session) fn redundant(&self, send: &SendPart) -> bool {
        redundant(send, self.config.redundancy, &self.config.scheduler)
    }

    /// The two pipes of `tier` under `gate` with the smallest `ETA_p(len)`,
    /// `except` left out, the earliest first.
    fn earliest_two(
        &self,
        gate: &Gate,
        tier: u64,
        len: u64,
        except: Option<u64>,
    ) -> [Option<u64>; 2] {
        let views = self.views();
        let mut best: [Option<(f64, u64)>; 2] = [None, None];
        let earlier = |x: (f64, u64), y: Option<(f64, u64)>| {
            y.is_none_or(|y| x.0.total_cmp(&y.0).then(x.1.cmp(&y.1)).is_lt())
        };
        let mut consider = |a: &Attachment| {
            let Some(o) = a.out().filter(|_| Some(a.id()) != except) else {
                return;
            };
            let x = (self.eta(a, o, len), a.id());
            if earlier(x, best[0]) {
                best = [Some(x), best[0]];
            } else if earlier(x, best[1]) {
                best[1] = Some(x);
            }
        };
        if views.class() == Some(gate.class()) {
            if let Some(t) = views.tier(tier) {
                views
                    .pipes(t)
                    .iter()
                    .for_each(|&i| consider(self.atts.at(i)));
            }
        } else {
            // A gate of an earlier moment of the same decision.
            self.atts
                .iter()
                .filter(|a| gate.usable(a) && a.send_tier() == tier)
                .for_each(consider);
        }
        best.map(|b| b.map(|(_, id)| id))
    }

    /// Whether pipe `id` of `tier` is one of the pair that may take a
    /// redundant chunk of `len` bytes: the two pipes of the tier with the
    /// smallest ETA. A tier with a single usable pipe has no pair.
    pub(in crate::proto::session) fn in_pair(
        &self,
        gate: &Gate,
        tier: u64,
        len: u64,
        id: u64,
    ) -> bool {
        match self.earliest_two(gate, tier, len, None) {
            [Some(a), Some(b)] => a == id || b == id,
            _ => false,
        }
    }

    /// The eligible target with the smallest ETA for a copy.
    fn copy_target(&self, gate: &Gate, writer: u64, len: u64) -> Option<u64> {
        let original = self.att(writer)?;
        if !gate.admits(original) {
            return None;
        }
        let next = self.next_replica_tier(original.send_tier());
        self.atts
            .iter()
            .filter(|a| self.replica_eligible(original, a, next))
            .filter_map(|a| a.out().map(|o| (self.eta(a, o, len), a.id())))
            .min_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)))
            .map(|(_, id)| id)
    }

    /// The bound on the copy bytes outstanding: `max(spread_chunk`,
    /// retransmit budget / 64).
    pub(super) fn copy_bound(&self) -> u64 {
        (self.config.spread_chunk as u64).max(self.retransmit_budget() / 64)
    }

    /// Whether a pipe is idle: nothing ack-eliciting unacknowledged and no
    /// acknowledgement progress for max(1 s, `T_suspect`), counted from when
    /// it became usable if it never had any.
    fn idle(&self, o: &OutPipe) -> bool {
        let quiet = self.now.saturating_duration_since(o.last_advance());
        quiet >= IDLE
            && o.oldest_unacked_eliciting().is_none()
            && quiet >= self.absolute_stall_limit(o)
    }

    /// A frame of new data, stream bytes `off..off + n` and maybe the FIN,
    /// went on pipe `pipe` under `gate`: a copy of it is queued for the
    /// other pipe of the eligible tier when the direction is redundant, or
    /// of its part within the first `spread_chunk` after an idle period of
    /// the pipe; at most one copy, within the bound.
    pub(in crate::proto::session) fn copy_chunk(
        &mut self,
        pipe: u64,
        key: StreamKey,
        (off, n, fin): (u64, u64, bool),
        gate: Option<&Gate>,
    ) {
        if !self.replicas_enabled() {
            return;
        }
        let chunk = self.config.spread_chunk as u64;
        // The first new data of the batch on a pipe idle until it: the
        // frames before it in the batch are not in flight yet. Copies and
        // reinjected data ahead of it in the batch do not count.
        let arm = !self.mp().batch().new_data()
            && self
                .out_ref(pipe)
                .is_some_and(|o| o.idle_copy_clear() && self.idle(o));
        let Some(o) = self.out_mut(pipe) else {
            return;
        };
        let idle = o.idle_copy_take(arm.then_some(chunk), n);
        let Some(send) = self.streams.send(key) else {
            return;
        };
        let redundant = self.redundant(send);
        let (end, fin) = if redundant {
            (off + n, fin)
        } else if idle > 0 && idle_copied(send, self.config.redundancy, &self.config.scheduler) {
            (off + idle, fin && idle == n)
        } else {
            return;
        };
        let Some(gate) = gate else {
            return;
        };
        // The other pipe of the pair; in a tier whose only usable pipe has
        // lanes, the pair is its lane 0 and its copy lane. A lane of the same pipe shares its fate:
        // never for the copy after an idle period.
        let (target, lane) = match self.copy_target(gate, pipe, end - off) {
            Some(t) => (t, 0),
            None if redundant => match self.copy_lane_for(gate, pipe, end - off) {
                Some(n) => (pipe, n),
                None => return,
            },
            None => return,
        };
        let outstanding = self.ledger().map_or(0, |l| l.copies());
        if outstanding + (end - off) > self.copy_bound() || end - off > self.replica_room() {
            return;
        }
        if let Some(send) = self.streams.send_mut(key) {
            send.mp_mut().copy(off, end);
        }
        // Copies whose data was acknowledged meanwhile leave the queue
        // first.
        while let Some(c) = self.out_ref(target).and_then(|o| o.next_copy(lane))
            && self.copy_done(&c)
        {
            self.out_mut(target).expect("present").pop_copy(lane);
        }
        let c = QueuedCopy::new(pipe, key, off, end, fin);
        let o = self.out_mut(target).expect("present");
        // Finished copies behind an unfinished one leave the queue too,
        // whenever it doubles: amortized constant work per copy, and a
        // queue no longer than its copies with data left (times two).
        let len = o.queue_copy(lane, c);
        if len >= 16 && len.is_power_of_two() {
            let mut q = o.take_copies(lane);
            q.retain(|c| !self.copy_done(c));
            self.out_mut(target)
                .expect("present")
                .restore_copies(lane, q);
        }
    }

    /// The copy lane of pipe `pipe` when it is the only usable pipe of its
    /// tier under `gate` and has lanes:
    /// the lowest-numbered lane without a bound direction, or none while a
    /// lane is opened for the purpose.
    fn copy_lane_for(&mut self, gate: &Gate, pipe: u64, len: u64) -> Option<u64> {
        if !self.out_ref(pipe).is_some_and(OutPipe::lanes_offered) {
            return None;
        }
        let tier = self.att(pipe)?.send_tier();
        if tier > gate.last() || self.earliest_two(gate, tier, len, None) != [Some(pipe), None] {
            return None;
        }
        let found = self
            .out_mut(pipe)?
            .lanes_mut()
            .and_then(crate::proto::session::pipes::OutLanes::find_copy_lane);
        if found.is_none() {
            // A lane opened for the purpose (one already opening becomes
            // it once confirmed).
            self.request_lane(pipe);
            if let Some(l) = self.out_mut(pipe).and_then(OutPipe::lanes_mut) {
                l.want_copy_lane();
            }
        }
        found
    }

    /// Whether a queued copy has nothing left to send: its bytes are
    /// acknowledged or no longer held, and its FIN acknowledged or not
    /// owed.
    fn copy_done(&self, c: &QueuedCopy) -> bool {
        let Some(send) = self.streams.send(c.key()) else {
            return true;
        };
        let fin = c.fin() && !send.mp().fin_acked && send.cold().reset.is_none();
        let end = c.end().min(send.offset).min(send.owed_end());
        !fin && send.first_unacked(c.off()) >= end
    }

    /// Whether copies wait for lane `lane` of pipe `id`.
    pub(in crate::proto::session) fn copies_queued(&self, id: u64, lane: u64) -> bool {
        self.out_ref(id)
            .is_some_and(|o| o.takes_new_data() && o.copies_queued(lane))
    }

    /// Writes the copies queued for pipe `id`, ahead of its other stream
    /// data; those whose data is acknowledged or no longer owed are
    /// dropped, and all of them when the pipe is no longer eligible under
    /// the tier gate of the write (late binding, rule S2). `false` when
    /// the batch filled up.
    pub(in crate::proto::session) fn write_copies(&mut self, id: u64, w: &mut Records<'_>) -> bool {
        let lane = self.tx_lane;
        if !self.copies_queued(id, lane) {
            return true;
        }
        if !self.replicas_enabled() {
            self.drop_copies(id);
            return true;
        }
        while let Some(c) = self.out_ref(id).and_then(|o| o.next_copy(lane)) {
            if self.copy_done(&c) {
                self.out_mut(id).expect("present").pop_copy(lane);
                continue;
            }
            let eligible = match (self.att(c.source()), self.att(id)) {
                (Some(_), Some(target)) if c.source() == id => {
                    self.gate().is_some_and(|g| g.admits(target))
                }
                (Some(source), Some(target)) => {
                    let next = self.next_replica_tier(source.send_tier());
                    self.replica_eligible(source, target, next)
                }
                _ => false,
            };
            if !eligible {
                self.out_mut(id).expect("present").pop_copy(lane);
                if let Some(send) = self.streams.send_mut(c.key()) {
                    send.mp_mut().uncopy(c.off(), c.end());
                }
                continue;
            }
            let send = self
                .streams
                .send(c.key())
                .expect("a copy with data left has its stream");
            // An acknowledged prefix is not sent again; the frame at offset
            // 0 carries the whole preamble.
            let start = match send.first_unacked(c.off()) {
                s if s < send.base => 0,
                s => s,
            };
            let fin = c.fin() && !send.mp().fin_acked && send.cold().reset.is_none();
            let end = c.end().min(send.owed_end());
            let budget_end = start.saturating_add(self.replica_room()).min(end);
            if budget_end == start && start < end {
                self.drop_copies(id);
                return true;
            }
            let Ok((n, _)) =
                self.write_copy(c.key(), start, budget_end, fin && budget_end == end, w)
            else {
                return false;
            };
            self.replica_bytes(n, true);
            self.mp_mut().counters.bytes_redundant += n;
            let o = self.out_mut(id).expect("present");
            o.redundant(n);
            if n == 0 || start + n >= end {
                o.pop_copy(lane);
            } else {
                o.copy_sent_to(lane, start + n);
            }
        }
        true
    }

    /// Drops the copies queued for pipe `id`, on lane 0 and on its copy
    /// lane: they leave the bound.
    fn drop_copies(&mut self, id: u64) {
        let copy_lane = self
            .out_ref(id)
            .and_then(OutPipe::lanes)
            .and_then(crate::proto::session::pipes::OutLanes::copy_lane);
        for lane in std::iter::once(0).chain(copy_lane) {
            let Some(o) = self.out_mut(id) else {
                return;
            };
            let mut copies = o.take_copies(lane);
            for c in copies.drain(..) {
                if let Some(send) = self.streams.send_mut(c.key()) {
                    send.mp_mut().uncopy(c.off(), c.end());
                }
            }
            // The queue keeps its capacity.
            if let Some(o) = self.out_mut(id) {
                o.restore_copies(lane, copies);
            }
        }
    }

    /// Pipe `id` became suspect, failed or started draining: its queued
    /// copies are dropped, its idle copy and its revalidation end.
    pub(in crate::proto::session) fn unsettle(&mut self, id: u64) {
        self.drop_copies(id);
        if let Some(o) = self.out_mut(id) {
            o.end_idle_copy();
        }
        self.end_revalidation(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::Priority;
    use crate::proto::session::stream::SendBuf;

    #[test]
    fn copy_budget_expires_originals_before_charges() {
        let rate = crate::proto::session::Config::default()
            .datagram_config()
            .replica_percent;
        assert_eq!(rate, 20);
        let mut budget = ReplicaBudget::default();
        let burst = 100;
        budget.record(0, 500, false);
        for _ in 0..2 {
            budget.record(0, 100, false);
            assert!(budget.room(0, rate, burst) >= 100);
            budget.record(0, 100, true);
        }
        assert_eq!(budget.room(9, rate, burst), 40);
        budget.record(10, 100, false);
        assert_eq!(budget.room(10, rate, burst), 0);
        budget.record(11, 104, false);
        assert_eq!(budget.room(11, rate, burst), 140);
        budget.record(11, 1, false);
        assert_eq!(budget.room(11, rate, burst), 141);
    }

    #[test]
    fn clearing_the_stream_setting_follows_the_session_again() {
        let mut send = SendPart::with_buf(0, SendBuf::default());
        send.priority = Priority::new(1, false).unwrap_or(Priority::WIRE_DEFAULT);
        let urgent = |s: &SendPart, r| redundant(s, r, &Scheduler::Affinity);
        // Unset: urgency 1 under "urgent" is redundant, under "off" not.
        assert!(urgent(&send, Redundancy::Urgent));
        assert!(!urgent(&send, Redundancy::Off));
        send.mp_mut().redundant = Some(false);
        assert!(!urgent(&send, Redundancy::Urgent));
        send.mp_mut().redundant = Some(true);
        assert!(urgent(&send, Redundancy::Off));
        // `set_redundant(None)` clears it: the session's parameter again.
        send.mp_mut().redundant = None;
        assert!(urgent(&send, Redundancy::Urgent));
        assert!(!urgent(&send, Redundancy::Off));
    }
}
