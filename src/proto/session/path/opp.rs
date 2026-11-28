//! Repairs a blocked STREAM prefix through the existing opportunistic
//! reinjection scheduler and reliable send ranges.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::proto::session::ledger::{Blocking, Held};
use crate::proto::session::mpath::Mp;
use crate::proto::session::output::Records;
use crate::proto::session::pipes::{OutPipe, OutState};
use crate::proto::session::stream::{Carry, SendPart};
use crate::proto::session::tier::Gate;
use crate::proto::session::{SessionCore, StreamKey};

/// The stream directions held back by stream credit, for opportunistic
/// reinjection, and the next place in that list.
#[derive(Debug, Default)]
pub(crate) struct CreditBlocked {
    list: Vec<StreamKey>,
    seq: u64,
    // poll_timeout and wants_write both observe the same range and may
    // tighten its deadline. Only the session owner accesses this index.
    work: RefCell<BTreeMap<StreamKey, PrefixWork>>,
    copies: BTreeMap<StreamKey, Vec<RepairCopy>>,
}

#[derive(Debug, Default)]
struct PrefixWork {
    opening: bool,
    cap: Option<(Blocking, Instant)>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RepairCopy {
    pub(super) target: u64,
    pub(super) start: u64,
    pub(super) end: u64,
}

struct Opportunity {
    range: Blocking,
    penalize: bool,
}

#[derive(Default)]
struct RepairPlan {
    due: Option<Opportunity>,
    next: Option<Instant>,
}

impl CreditBlocked {
    pub(super) fn note_opening(&mut self, key: StreamKey) {
        self.work.get_mut().entry(key).or_default().opening = true;
    }

    pub(super) fn forget(&mut self, key: StreamKey) {
        self.work.get_mut().remove(&key);
        self.copies.remove(&key);
    }

    pub(super) fn copies(&self, key: StreamKey) -> &[RepairCopy] {
        self.copies.get(&key).map_or(&[], Vec::as_slice)
    }

    /// The directions listed; a stream gone since stays until the next
    /// prune (`prune_credit_blocked`, every batch of new data), and readers
    /// skip it.
    pub(in crate::proto::session) fn keys(&self) -> &[StreamKey] {
        &self.list
    }
}

impl SessionCore {
    fn connection_credit_blocked(&self) -> bool {
        self.streams.send_flow().used >= self.streams.send_flow().max
            && !self.streams.queue().is_empty()
    }

    /// What a direction listed as held back by stream credit contributes
    /// to the ledger: its place in the list, whether stream credit holds
    /// it back now, and then its blocking data.
    pub(in crate::proto::session) fn held_of(
        &self,
        key: StreamKey,
        send: &SendPart,
    ) -> Option<Held> {
        let seq = send.mp.as_deref()?.listed?;
        let blocked = send.held_back();
        Some(Held {
            seq,
            blocking: blocked.then(|| self.stream_blocking(key, send)).flatten(),
        })
    }

    /// The lowest unacknowledged range of the first transmission.
    /// A partial repair continues in that same frame, while an already
    /// copied frame awaits ACK or ordinary reinjection.
    fn stream_blocking(&self, key: StreamKey, send: &SendPart) -> Option<Blocking> {
        let lowest = send.first_unacked(0);
        if lowest >= send.offset || send.mp().lost.contains(lowest, lowest + 1) {
            return None;
        }
        let c = send.mp().carriers(lowest).next()?;
        let o = self.out_ref(c.pipe)?;
        if o.state() != OutState::Active || !o.confirmed() || o.covered_at(c.pos) {
            return None;
        }
        let mut b = self.blocking_at(o, c, key, send, lowest)?;
        let start = b.start.max(send.mp().opportunistic_to);
        // A proactive copy may already own the range in the shared budget.
        let (first, end) = send.mp().copied.gaps(start.min(b.end), b.end).next()?;
        if first != start || (start < send.base && end < send.base.min(b.end)) {
            return None;
        }
        b.start = start;
        b.end = end;
        Some(b)
    }

    /// Describes the part from `x` to the end of the frame `c` of pipe
    /// `o`.
    fn blocking_at(
        &self,
        o: &OutPipe,
        c: Carry,
        key: StreamKey,
        send: &SendPart,
        x: u64,
    ) -> Option<Blocking> {
        let (pipe, frame_end) = (c.pipe, c.end);
        let batch = o.batch_reaching(c.pos)?;
        // The part ends at the next acknowledged byte, and never goes past
        // the Reliable Size of a reset: the peer does not need what a reset
        // dropped, and the sender no longer holds it.
        let reliable = match send.cold().reset {
            Some(_) => send.reset_reliable().unwrap_or(0),
            None => u64::MAX,
        };
        let end = send
            .mp()
            .acked
            .iter()
            .find(|&(s, _)| s > x)
            .map_or(frame_end, |(s, _)| s.min(frame_end))
            .min(send.offset)
            .min(reliable)
            .min(x.saturating_add(
                (self.config.spread_chunk as u64).max(send.base.saturating_sub(x)),
            ));
        if end <= x {
            return None;
        }
        Some(Blocking {
            key,
            start: x,
            end,
            pipe,
            sent: batch.time,
            source_wait: batch
                .confirmation?
                .after(end - if x < send.base { 0 } else { x }),
            original: (c.pos, c.off),
        })
    }

    // Choose the minimum ETA over destinations that can admit this exact
    // range. The ACK detector independently chooses by PTO plus queue.
    fn opp_target(&self, b: &Blocking, gate: Gate, now: Instant) -> Option<(u64, Duration)> {
        let source = self.att(b.pipe)?;
        let out = source.out()?;
        let inbound_live = self.atts.any_in_live();
        if self
            .suspect_deadline(b.pipe, out, inbound_live, now)
            .is_some_and(|(due, _)| due <= now)
        {
            return None;
        }
        let len = b.end - b.start;
        let source_arrival = self.eta(source, out, len) + (out.est().srtt / 2).as_secs_f64();
        let mad = self.mp().peer_mad();
        self.atts
            .iter()
            .filter(|a| a.id() != b.pipe && gate.admits(a))
            .filter_map(|a| {
                let o = a.out()?;
                let (proof, _) = self.delivery_reference(a, inbound_live, now)?;
                if proof <= b.sent
                    || !o.open()
                    || !o.write_idle()
                    || o.limiter_held()
                    || self.reinject_room(a.id()) < len
                    || self.shape_held(a.id())
                    || self.shape_delayed(a.id())
                    || self
                        .suspect_deadline(a.id(), o, inbound_live, now)
                        .is_some_and(|(due, _)| due <= now)
                {
                    return None;
                }
                let eta = self.eta(a, o, len);
                let margin = Duration::from_millis(50).max(o.est().srtt / 2 + mad);
                (eta + margin.as_secs_f64() < source_arrival).then_some((eta, a.id(), margin))
            })
            .min_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)))
            .and_then(|(eta, id, margin)| {
                Some((
                    id,
                    Duration::try_from_secs_f64(eta)
                        .ok()?
                        .saturating_add(margin),
                ))
            })
    }

    fn opening_unacked(send: &SendPart) -> bool {
        let lowest = send.first_unacked(0);
        send.mp()
            .carried
            .front()
            .is_some_and(|head| head.off == 0 && lowest < head.end.min(send.owed_end()))
    }

    fn repair_plan(
        &self,
        now: Instant,
        gate: impl FnOnce() -> Option<Gate>,
        writer: Option<u64>,
    ) -> RepairPlan {
        let mut result = RepairPlan::default();
        let Some(mp) = self.mp.as_deref().filter(|_| self.atts.len() > 1) else {
            return result;
        };
        let connection_blocked = self.connection_credit_blocked();
        let mut work = mp.blocked().work.borrow_mut();
        if work.is_empty() && !connection_blocked && mp.blocked().keys().is_empty() {
            return result;
        }
        let ledger = self.ledger();
        if connection_blocked {
            for key in self.streams.keys() {
                if self
                    .streams
                    .send(key)
                    .is_some_and(|send| send.first_unacked(0) < send.offset)
                {
                    work.entry(key).or_default();
                }
            }
        } else if let Some(ledger) = ledger.as_ref() {
            for b in ledger.blocking() {
                work.entry(b.key).or_default();
            }
        }
        if work.is_empty() {
            return result;
        }
        let budget = self
            .copy_bound()
            .saturating_sub(ledger.map_or(0, |l| l.copies()));
        let gate = gate();
        work.retain(|&key, item| {
            let Some(send) = self.streams.send(key) else {
                return false;
            };
            item.opening &= Self::opening_unacked(send);
            let blocked_credit =
                connection_blocked || (send.mp().listed.is_some() && send.held_back());
            let Some(b) = self.stream_blocking(key, send) else {
                item.cap = None;
                return item.opening;
            };
            if !blocked_credit && !item.opening {
                return item.cap.is_some();
            }
            let start = if b.start < send.base { 0 } else { b.start };
            // Split writes share the cap of the original frame.
            let prior = item
                .cap
                .filter(|(old, _)| old.pipe == b.pipe && old.original == b.original)
                .map(|(_, due)| due);
            let target = gate.and_then(|gate| self.opp_target(&Blocking { start, ..b }, gate, now));
            let cap = target.and_then(|(_, after)| b.sent.checked_add(after.min(b.source_wait)));
            let due = prior.into_iter().chain(cap).min();
            item.cap = due.map(|t| (b, t));
            if let Some(due) = due {
                if due > now {
                    result.next = Some(result.next.map_or(due, |t: Instant| t.min(due)));
                } else if let Some((target, _)) = target
                    && writer == Some(target)
                    && b.end - start <= budget
                    && result
                        .due
                        .as_ref()
                        .is_none_or(|copy| (b.sent, b.key) < (copy.range.sent, copy.range.key))
                {
                    result.due = Some(Opportunity {
                        range: Blocking { start, ..b },
                        penalize: blocked_credit,
                    });
                }
            }
            true
        });
        result
    }

    pub(in crate::proto::session) fn opp_due(&self, writer: u64, now: Instant) -> bool {
        self.repair_plan(now, || self.gate(), Some(writer))
            .due
            .is_some()
    }

    /// Only a future deadline wakes the timer. Past-due work waits for an
    /// input that changes delivery proof or scheduler admission.
    pub(in crate::proto::session) fn opp_deadline(&self) -> Option<Instant> {
        self.repair_plan(self.now, || self.gate(), None).next
    }

    pub(in crate::proto::session) fn write_opportunistic(
        &mut self,
        id: u64,
        now: Instant,
        gate: Option<Gate>,
        w: &mut Records<'_>,
    ) -> bool {
        if self.tx_lane != 0 {
            return true;
        }
        let Some(copy) = self.repair_plan(now, || gate, Some(id)).due else {
            return true;
        };
        let b = copy.range;
        let Ok((n, _)) = self.write_copy(b.key, b.start, b.end, false, w) else {
            return false;
        };
        if n == 0 {
            return true;
        }
        let end = b.start + n;
        if let Some(send) = self.streams.send_mut(b.key) {
            send.mp_mut().opportunistic_to = end;
            send.mp_mut().copy(b.start, end);
        }
        self.mp_mut()
            .blocked_mut()
            .copies
            .entry(b.key)
            .or_default()
            .push(RepairCopy {
                target: id,
                start: b.start,
                end,
            });
        self.mp_mut().counters.bytes_opportunistic += n;
        if let Some(o) = self.out_mut(id) {
            o.opportunistic(n);
        }
        if copy.penalize {
            self.penalize(b.pipe);
        }
        true
    }

    /// Acknowledgement on any transmission releases the corresponding
    /// repair reservation through the stream's normal copy accounting.
    pub(super) fn acknowledge_repair(&mut self, key: StreamKey) {
        let send = self.streams.send(key);
        if let Some(work) = self
            .mp
            .as_deref_mut()
            .map(|mp| mp.blocked_mut().work.get_mut())
            && let Some(item) = work.get_mut(&key)
        {
            item.opening &= send.is_some_and(Self::opening_unacked);
            item.cap = item.cap.filter(|(b, _)| {
                send.is_some_and(|send| send.first_unacked(b.start) < b.end.min(send.owed_end()))
            });
            if !item.opening && item.cap.is_none() {
                work.remove(&key);
            }
        }
        if let Some(copies) = self
            .mp
            .as_deref_mut()
            .and_then(|mp| mp.blocked_mut().copies.get_mut(&key))
        {
            copies.retain(|c| {
                self.streams
                    .send(key)
                    .is_some_and(|send| send.first_unacked(c.start) < c.end.min(send.owed_end()))
            });
            if copies.is_empty() {
                self.mp_mut().blocked_mut().copies.remove(&key);
            }
        }
    }

    /// Release optional copy reservations on a departing writer. Its
    /// retained frames are still handled by ordinary reinjection.
    pub(super) fn release_repair_copies(&mut self, id: u64) {
        let Some(mp) = self.mp.as_deref_mut() else {
            return;
        };
        mp.blocked_mut().copies.retain(|&key, copies| {
            copies.retain(|copy| {
                if copy.target != id {
                    return true;
                }
                if let Some(send) = self.streams.send_mut(key) {
                    send.mp_mut().uncopy(copy.start, copy.end);
                }
                false
            });
            !copies.is_empty()
        });
    }

    /// The opportunistic-reinjection penalty, once per episode: the
    /// pipe's rate samples are discarded and its rate halved, and it
    /// takes no new stream data until everything sent on it so far is
    /// acknowledged. Each direction bound to it moves off, and its stream data
    /// on the pipe not yet acknowledged is re-sent once, for the new binding:
    /// on a later penalty only what is still unacknowledged then and was not
    /// re-sent before. The penalty is the only trigger, and the copies are
    /// bounded by what the pipe has in flight.
    fn penalize(&mut self, id: u64) {
        let Some(first) = self.out_mut(id).and_then(OutPipe::penalize) else {
            return;
        };
        self.resend_on_penalty(id);
        self.advance_pick_generation();
        self.check_standby_takeover();
        if first {
            self.mp_mut().counters.penalties += 1;
        }
        self.quality_sample(id, self.now);
    }

    /// Re-sends the unacknowledged stream data on pipe `id` of the directions
    /// bound to it, which its penalty moves off.
    fn resend_on_penalty(&mut self, id: u64) {
        let mut bound: Vec<StreamKey> = self
            .streams
            .keys()
            .filter(|&k| {
                self.streams
                    .send(k)
                    .and_then(|s| s.mp().bound)
                    .is_some_and(|b| b.pipe == id)
            })
            .collect();
        if bound.is_empty() {
            return;
        }
        bound.sort_unstable();
        let mut frames = Vec::new();
        if let Some(o) = self.out_mut(id) {
            o.take_penalty_resend(|k| bound.binary_search(&k).is_ok(), &mut frames);
        }
        let now = self.now;
        for f in frames {
            self.reinject_frame(f, now);
        }
    }

    /// Records a stream direction that stream credit, or a binding that waits on
    /// another pipe, holds back.
    pub(in crate::proto::session) fn note_credit_blocked(&mut self, key: StreamKey) {
        let Some(blocked) = self.mp.as_deref_mut().map(Mp::blocked_mut) else {
            return;
        };
        let seq = blocked.seq;
        let Some(send) = self.streams.send_mut(key) else {
            return;
        };
        if send.held_back() && send.mp().listed.is_none() {
            send.mp_mut().listed = Some(seq);
            blocked.seq += 1;
            blocked.list.push(key);
        }
    }

    /// Forgets stream directions no longer held back.
    pub(in crate::proto::session) fn prune_credit_blocked(&mut self) {
        let Some(mut list) = self
            .mp
            .as_deref_mut()
            .map(|m| std::mem::take(&mut m.blocked_mut().list))
        else {
            return;
        };
        list.retain(|&k| {
            let Some(send) = self.streams.send(k) else {
                return false;
            };
            if send.held_back() {
                return true;
            }
            if let Some(send) = self.streams.send_mut(k) {
                send.mp_mut().listed = None;
            }
            false
        });
        self.mp_mut().blocked_mut().list = list;
    }
}
