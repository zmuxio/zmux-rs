//! Redundant urgent data (MULTIPATH.md Section
//! 7.5): a chunk of a stream direction whose redundancy is on is taken by
//! whichever of the two pipes of its eligible tier with the earliest
//! arrival writes first, and a copy is queued for the other; the first
//! `spread_chunk` of new data after an idle period of a pipe is copied
//! likewise. Copies wait outside the carrier for their pipe's next write
//! opportunity, go ahead of its other stream data, and are bounded by the
//! copy bytes outstanding, counted by the ledger.

use std::time::Duration;

use super::output::Records;
use super::pipes::{Attachment, OutPipe, QueuedCopy};
use super::stream::SendPart;
use super::tier::Gate;
use super::{Policy, Redundancy, SessionCore, StreamKey};

/// An idle period lasts at least max(this, T_suspect).
const IDLE: Duration = Duration::from_secs(1);

/// The policy that schedules a direction.
fn policy_of<'a>(send: &'a SendPart, session: &'a Policy) -> &'a Policy {
    send.mp().scheduler.as_ref().unwrap_or(session)
}

/// Whether a stream direction's chunks are sent redundantly: its own
/// `set_redundant` setting, else the session's `redundancy` (urgency 0 to
/// 2). Never under `session-affinity`, whose tiers are a single pipe.
pub(super) fn redundant(send: &SendPart, session: Redundancy, policy: &Policy) -> bool {
    !matches!(policy_of(send, policy), Policy::SessionAffinity)
        && send
            .mp()
            .redundant
            .unwrap_or(session == Redundancy::Urgent && send.priority.urgency() <= 2)
}

/// Whether the first chunk after an idle period is copied for a stream
/// direction: unless `redundancy` is off or the direction's redundancy is
/// turned off.
fn idle_copied(send: &SendPart, session: Redundancy, policy: &Policy) -> bool {
    !matches!(policy_of(send, policy), Policy::SessionAffinity)
        && send.mp().redundant.unwrap_or(session != Redundancy::Off)
}

impl SessionCore {
    /// Whether a stream direction's chunks are sent redundantly.
    pub(super) fn redundant(&self, send: &SendPart) -> bool {
        redundant(send, self.config.redundancy, &self.config.scheduler)
    }

    /// The two pipes of `tier` under `gate` with the smallest ETA_p(len),
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
    pub(super) fn in_pair(&self, gate: &Gate, tier: u64, len: u64, id: u64) -> bool {
        match self.earliest_two(gate, tier, len, None) {
            [Some(a), Some(b)] => a == id || b == id,
            _ => false,
        }
    }

    /// The pipe for a copy of `len` bytes written on `writer`: the eligible
    /// pipe of its tier with the smallest ETA other than the writer.
    fn copy_target(&self, gate: &Gate, writer: u64, len: u64) -> Option<u64> {
        let tier = self.att(writer)?.send_tier();
        if tier > gate.last() {
            return None;
        }
        self.earliest_two(gate, tier, len, Some(writer))[0]
    }

    /// The bound on the copy bytes outstanding: max(spread_chunk,
    /// retransmit budget / 64).
    fn copy_bound(&self) -> u64 {
        (self.config.spread_chunk as u64).max(self.retransmit_budget() / 64)
    }

    /// Whether a pipe is idle: nothing ack-eliciting unacknowledged and no
    /// acknowledgement progress for max(1 s, T_suspect), counted from when
    /// it became usable if it never had any.
    fn idle(&self, o: &OutPipe) -> bool {
        let quiet = self.now.saturating_duration_since(o.last_advance());
        quiet >= IDLE && o.oldest_unacked_eliciting().is_none() && quiet >= self.limits(o).0
    }

    /// A frame of new data, stream bytes `off..off + n` and maybe the FIN,
    /// went on pipe `pipe` under `gate`: a copy of it is queued for the
    /// other pipe of the eligible tier when the direction is redundant, or
    /// of its part within the first `spread_chunk` after an idle period of
    /// the pipe; at most one copy, within the bound.
    pub(super) fn copy_chunk(
        &mut self,
        pipe: u64,
        key: StreamKey,
        (off, n, fin): (u64, u64, bool),
        gate: Option<&Gate>,
    ) {
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
        if outstanding + (end - off) > self.copy_bound() {
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
        let c = QueuedCopy::new(key, off, end, fin);
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
            .and_then(super::pipes::OutLanes::find_copy_lane);
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
    pub(super) fn copies_queued(&self, id: u64, lane: u64) -> bool {
        self.out_ref(id)
            .is_some_and(|o| o.takes_new_data() && o.copies_queued(lane))
    }

    /// Writes the copies queued for pipe `id`, ahead of its other stream
    /// data; those whose data is acknowledged or no longer owed are
    /// dropped, and all of them when the pipe is no longer eligible under
    /// the tier gate of the write (late binding, MULTIPATH.md Section 11
    /// rule S2). `false` when the batch filled up.
    pub(super) fn write_copies(&mut self, id: u64, w: &mut Records<'_>) -> bool {
        let lane = self.tx_lane;
        if !self.copies_queued(id, lane) {
            return true;
        }
        let eligible = self
            .att(id)
            .is_some_and(|a| self.gate().is_some_and(|g| g.admits(a)));
        if !eligible {
            self.drop_copies(id);
            return true;
        }
        while let Some(c) = self.out_ref(id).and_then(|o| o.next_copy(lane)) {
            if self.copy_done(&c) {
                self.out_mut(id).expect("present").pop_copy(lane);
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
            let Ok((n, _)) = self.write_copy(c.key(), start, end, fin, w) else {
                return false;
            };
            self.stats.bytes_redundant += n;
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
            .and_then(super::pipes::OutLanes::copy_lane);
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
    pub(super) fn unsettle(&mut self, id: u64) {
        self.drop_copies(id);
        if let Some(o) = self.out_mut(id) {
            o.end_idle_copy();
        }
        self.end_revalidation(id);
    }
}
