//! Opportunistic reinjection (MULTIPATH.md Section 7.5.1): when flow
//! control holds new data back and the data that blocks it sits on a slower
//! pipe for longer than expected, one copy of it goes on the pipe with the
//! earliest arrival, and the slow pipe is penalized.

use std::time::{Duration, Instant};

use super::ledger::{Blocking, Held};
use super::mpath::Mp;
use super::output::Records;
use super::pipes::{OutPipe, SentFrame};
use super::stream::{Carry, SendPart};
use super::tier::Gate;
use super::{SessionCore, StreamKey};

/// What holds new stream data back (the trigger of Section 7.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    /// Session flow control.
    Session,
    /// Stream flow control of at least one stream direction.
    Streams,
}

/// The stream directions held back by stream credit, for opportunistic
/// reinjection (MULTIPATH.md Section 7.5.1), and the next place in that
/// list.
#[derive(Debug, Default)]
pub(crate) struct CreditBlocked {
    list: Vec<StreamKey>,
    seq: u64,
}

impl CreditBlocked {
    /// The directions listed.
    pub(super) fn keys(&self) -> &[StreamKey] {
        &self.list
    }

    /// A stream is gone.
    pub(super) fn forget(&mut self, key: StreamKey) {
        self.list.retain(|&k| k != key);
    }
}

impl SessionCore {
    /// The trigger that holds now, if any.
    fn opp_trigger(&self) -> Option<Trigger> {
        self.mp.as_deref()?;
        if self.streams.send_flow().used >= self.streams.send_flow().max
            && !self.streams.queue().is_empty()
        {
            return Some(Trigger::Session);
        }
        self.ledger()?.credit_blocked().then_some(Trigger::Streams)
    }

    /// The blocking data: for session flow control the unacknowledged
    /// stream data sent first, for stream flow control the blocking data
    /// sent first of the directions it holds back (kept by the ledger).
    fn opp_blocking(&self) -> Option<Blocking> {
        match self.opp_trigger()? {
            Trigger::Session => self.session_blocking(),
            Trigger::Streams => self.ledger()?.blocking(),
        }
    }

    /// What a direction listed as held back by stream credit contributes
    /// to the ledger: its place in the list, whether stream credit holds
    /// it back now, and then its blocking data.
    pub(super) fn held_of(&self, key: StreamKey, send: &SendPart) -> Option<Held> {
        let seq = send.mp.as_deref()?.listed?;
        let blocked = send.credit_blocked();
        Some(Held {
            seq,
            blocked,
            blocking: blocked.then(|| self.stream_blocking(key, send)).flatten(),
        })
    }

    /// The first part of a direction's data not yet acknowledged, not re-sent
    /// opportunistically and not waiting for reinjection, with the frame
    /// that last carried it (the first of those sent at that time, by pipe
    /// and position).
    fn stream_blocking(&self, key: StreamKey, send: &SendPart) -> Option<Blocking> {
        let x = send.first_unacked(send.mp().opportunistic_to);
        if x >= send.offset || send.mp().lost.contains(x, x + 1) {
            return None;
        }
        let mut best: Option<(Blocking, u64)> = None;
        for c in send.mp().carriers(x) {
            // Frames of the live pipes' logs.
            let Some(o) = self
                .out_ref(c.pipe)
                .filter(|o| o.is_live() && !o.covered_at(c.pos))
            else {
                continue;
            };
            if let Some(b) = self.blocking_at(o, c, key, send, x)
                && best.is_none_or(|(d, pos)| {
                    b.sent > d.sent || (b.sent == d.sent && (b.pipe, c.pos) < (d.pipe, pos))
                })
            {
                best = Some((b, c.pos));
            }
        }
        best.map(|(b, _)| b)
    }

    /// The unacknowledged stream data sent first, over every pipe.
    fn session_blocking(&self) -> Option<Blocking> {
        let mut best: Option<Blocking> = None;
        for a in &self.atts {
            let Some(o) = a.out().filter(|o| o.is_live()) else {
                continue;
            };
            // Each lane's frames in the order sent: its first one that
            // blocks is its oldest.
            for lane in o.retained() {
                for (pos, f) in lane {
                    let SentFrame::Stream { key, off, len, .. } = f else {
                        continue;
                    };
                    let Some(send) = self.streams.send(key) else {
                        continue;
                    };
                    let x = send.first_unacked(off.max(send.mp().opportunistic_to));
                    if x >= off + len || x >= send.offset || send.mp().lost.contains(x, x + 1) {
                        continue;
                    }
                    let c = Carry {
                        off,
                        end: off + len,
                        pipe: a.id(),
                        pos,
                    };
                    if let Some(b) = self.blocking_at(o, c, key, send, x)
                        && best.is_none_or(|c| b.sent < c.sent)
                    {
                        best = Some(b);
                    }
                    // The lane's later frames were sent later.
                    break;
                }
            }
        }
        best
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
            .min(reliable);
        if end <= x {
            return None;
        }
        Some(Blocking {
            key,
            start: x,
            end,
            pipe,
            sent: batch.time,
            expect: batch.expect,
        })
    }

    /// The pipe a copy of `len` bytes would reach first under `gate` (the
    /// gate now): the usable pipe with the smallest ETA that takes new
    /// data (not penalized).
    fn opp_target(&self, gate: Option<Gate>, len: u64) -> Option<u64> {
        self.fastest_eligible(&gate?, len)
    }

    /// When the copy of `b` becomes allowed: max(2 x srtt_f + peer max ACK
    /// delay, min(PTO_p, 2E)) after its last send.
    fn opp_due_at(&self, b: &Blocking, f: u64) -> Option<Instant> {
        let fo = self.out_ref(f)?;
        Some(
            self.opp_earliest(b)?
                .max(b.sent + fo.est().srtt * 2 + self.mp().peer_mad()),
        )
    }

    /// The earliest a copy of `b` can become allowed on any pipe:
    /// max(peer max ACK delay, min(PTO_p, 2E)) after its last send, which
    /// the threshold of [`Self::opp_due_at`] never undercuts.
    fn opp_earliest(&self, b: &Blocking) -> Option<Instant> {
        let mad = self.mp().peer_mad();
        let p = self.out_ref(b.pipe)?;
        Some(b.sent + mad.max(p.est().pto(mad).min(b.expect.saturating_mul(2))))
    }

    /// The blocking data to copy on pipe `id` now, if the conditions hold;
    /// `gate` is the gate now, when the caller has it.
    pub(super) fn opp_due(
        &self,
        id: u64,
        now: Instant,
        gate: Option<Option<Gate>>,
    ) -> Option<Blocking> {
        let b = self.opp_blocking()?;
        // Not due on any pipe yet: the usual case, decided before the
        // target (a gate and the ETA of every eligible pipe).
        if now <= self.opp_earliest(&b)? {
            return None;
        }
        let chunk = (b.end - b.start).min(self.config.spread_chunk as u64);
        let f = self.opp_target(gate.unwrap_or_else(|| self.gate()), chunk)?;
        if f != id || b.pipe == f {
            return None;
        }
        (now > self.opp_due_at(&b, f)?).then_some(b)
    }

    /// The time an opportunistic copy becomes allowed, while in the future.
    pub(super) fn opp_deadline(&self) -> Option<Instant> {
        let b = self.opp_blocking()?;
        let chunk = (b.end - b.start).min(self.config.spread_chunk as u64);
        let f = self.opp_target(self.gate(), chunk)?;
        if b.pipe == f {
            return None;
        }
        // "More than" the threshold ago.
        let t = self.opp_due_at(&b, f)? + Duration::from_micros(1);
        (t > self.now).then_some(t)
    }

    /// Writes the opportunistic copies due on pipe `id`, one chunk at a
    /// time while the conditions hold; `gate` is the gate now. `false`
    /// when the batch filled up.
    pub(super) fn write_opportunistic(
        &mut self,
        id: u64,
        now: Instant,
        gate: Option<Gate>,
        w: &mut Records<'_>,
    ) -> bool {
        let mut gate = Some(gate);
        while let Some(b) = self.opp_due(id, now, gate) {
            let end = b.end.min(b.start + self.config.spread_chunk as u64);
            let (start, end) = match self.streams.send(b.key) {
                // The frame at offset 0 carries the whole preamble.
                Some(s) if b.start < s.base => (0, end.max(s.base)),
                _ => (b.start, end),
            };
            let Ok((n, _)) = self.write_copy(b.key, start, end, false, w) else {
                return false;
            };
            if n == 0 {
                return true;
            }
            if let Some(send) = self.streams.send_mut(b.key) {
                send.mp_mut().opportunistic_to = send.mp().opportunistic_to.max(start + n);
            }
            self.stats.bytes_opportunistic += n;
            if let Some(o) = self.out_mut(id) {
                o.opportunistic(n);
            }
            // The penalty changes the pipes the gate depends on.
            self.penalize(b.pipe);
            gate = None;
        }
        true
    }

    /// The penalty of Section 7.5.1, once per episode: the pipe's rate
    /// samples are discarded and its rate halved, and it takes no new
    /// stream data until everything sent on it so far is acknowledged.
    fn penalize(&mut self, id: u64) {
        let Some(first) = self.out_mut(id).and_then(OutPipe::penalize) else {
            return;
        };
        self.advance_pick_generation();
        if first {
            self.stats.penalties += 1;
        }
        self.quality_sample(id, self.now);
    }

    /// Records a stream direction that stream credit holds back.
    pub(super) fn note_credit_blocked(&mut self, key: StreamKey) {
        let Some(blocked) = self.mp.as_deref_mut().map(Mp::blocked_mut) else {
            return;
        };
        let seq = blocked.seq;
        let Some(send) = self.streams.send_mut(key) else {
            return;
        };
        if send.credit_blocked() && send.mp().listed.is_none() {
            send.mp_mut().listed = Some(seq);
            blocked.seq += 1;
            blocked.list.push(key);
        }
    }

    /// Forgets stream directions no longer held back by stream credit.
    pub(super) fn prune_credit_blocked(&mut self) {
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
            if send.credit_blocked() {
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
