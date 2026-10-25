//! The fair share of the session send buffer and the write marks of the
//! sending parts.
//!
//! **Fair sharing** (by water-filling). The
//! session `send_buffer` bounds the written-but-unreleased bytes of all
//! stream directions together (unsent on a single pipe, unacknowledged in a
//! multipath session, where the buffer grows to the retransmit budget up to
//! `send_buffer_max`). Every direction may always hold 64 KiB. A direction
//! within that floor and with no write waiting keeps what it holds; the
//! other n directions share the rest: each may hold max(64 KiB,
//! (send_buffer - the small holdings) / n). A message of up to 64 KiB is
//! never blocked behind bulk data, bulk streams progress at similar rates,
//! and a small message stream does not halve a bulk stream's share.
//!
//! **Waiting data** (the age test of tier
//! saturation). Each sending part keeps write marks (end offset, time),
//! writes within 1 ms merged; a write that has to wait for buffer space
//! dates its bytes from when it started waiting (a next write that starts
//! waiting within 1 ms of the previous one completing continues that
//! wait); data that waited for credit dates from when the credit arrived;
//! reinjected information from when it was queued.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::super::CoreEvent;
use super::super::stream::{Age, SendPart, StreamKey};
use super::Streams;

/// Every stream direction may hold this much whatever the others hold.
pub(in super::super) const SHARE_FLOOR: u64 = 64 * 1024;

/// Writes this close together share one mark.
const MARK_MERGE: Duration = Duration::from_millis(1);

/// The session send buffer the fair share divides: its size in force, and
/// in a multipath session the retained (sent, unacknowledged) bytes it
/// holds besides the unsent ones.
#[derive(Debug, Clone, Copy)]
pub(in super::super) struct SendBuffer {
    pub(in super::super) total: u64,
    pub(in super::super) retained: Option<u64>,
}

impl SendBuffer {
    fn mp(self) -> bool {
        self.retained.is_some()
    }
}

impl SendPart {
    /// Written-but-unreleased bytes: unsent, plus unacknowledged ones in a
    /// multipath session.
    pub(crate) fn held(&self, mp: bool) -> u64 {
        self.buf.len() + if mp { self.unacked() } else { 0 }
    }

    /// Application bytes committed to a pipe (taken out of the unsent
    /// part of the buffer).
    fn committed(&self) -> u64 {
        self.written - self.buf.len()
    }

    /// The time the oldest uncommitted byte started to wait, if the part
    /// has uncommitted bytes.
    fn oldest_mark(&self) -> Option<Instant> {
        let committed = self.committed();
        self.waits
            .age
            .as_ref()?
            .marks
            .iter()
            .find(|&&(end, _)| end > committed)
            .map(|&(_, t)| t)
    }

    /// The wait starts of a part's data: since when its oldest data that
    /// is ready (within stream credit) has waited, session credit aside,
    /// and the earlier of its writer's wait and its reinjection.
    pub(crate) fn wait_starts(&self, ready: bool) -> (Option<Instant>, Option<Instant>) {
        let Some(a) = self.waits.age.as_deref() else {
            return (None, None);
        };
        let mark = self
            .oldest_mark()
            .filter(|_| ready)
            .map(|t| a.credit_at.map_or(t, |c| c.max(t)));
        let writer = a.wait_start.filter(|_| self.waits.waiting);
        let lost = a.lost_at.filter(|_| self.has_lost());
        let wait = match (writer, lost) {
            (Some(w), Some(l)) => Some(w.min(l)),
            (w, l) => w.or(l),
        };
        (mark, wait)
    }

    /// Drops the marks of bytes committed to a pipe.
    pub(in super::super) fn pop_marks(&mut self) {
        let done = self.committed();
        let lost = self.has_lost();
        let Some(a) = self.waits.age.as_deref_mut() else {
            return;
        };
        while a.marks.front().is_some_and(|&(e, _)| e <= done) {
            a.marks.pop_front();
        }
        if !lost {
            a.lost_at = None;
        }
    }
}

impl Streams {
    // ---- fair sharing --------------------------------------------------------

    /// Room for new data on a stream direction, within its own limit, its
    /// fair share and the session buffer (with the 64 KiB floor).
    pub(in super::super) fn send_room(&self, key: StreamKey, buffer: SendBuffer) -> u64 {
        #[cfg(debug_assertions)]
        if self.slab.len() <= 64 {
            self.check_holders();
        }
        let Some(send) = self.send(key) else {
            return 0;
        };
        let total = buffer.total;
        let held = send.held(buffer.mp());
        // Water-filling (max-min): directions within the floor keep what
        // they hold; the rest of the buffer is shared by the others, this
        // one counted among them as it asks for more.
        let n = self.send_holders + u64::from(!send.waits.holding);
        let small = self.small_held - send.waits.small;
        let share = SHARE_FLOOR.max(total.saturating_sub(small) / n.max(1));
        let own = send.cold().send_limit.unwrap_or(total);
        let stream_room = own.min(share).saturating_sub(held);
        let session_room = total.saturating_sub(self.session_held(buffer));
        let floor_room = SHARE_FLOOR.min(own).saturating_sub(held);
        stream_room.min(session_room.max(floor_room))
    }

    /// Written-but-unreleased bytes of the session.
    fn session_held(&self, buffer: SendBuffer) -> u64 {
        self.send_flow.buffered + buffer.retained.unwrap_or(0)
    }

    /// The bytes below which a waiting writer that counts in the fair share
    /// and has no limit of its own has room (see [`Self::send_room`]):
    /// its share, and its floor while the session buffer is full.
    pub(in super::super) fn room_below(&self, buffer: SendBuffer) -> u64 {
        let total = buffer.total;
        let n = self.send_holders.max(1);
        let share = SHARE_FLOOR.max(total.saturating_sub(self.small_held) / n);
        match total.saturating_sub(self.session_held(buffer)) {
            0 => SHARE_FLOOR.min(total),
            _ => share.min(total),
        }
    }

    /// Whether a direction within its floor holds bytes (on a single pipe
    /// every byte held is unsent).
    pub(in super::super) fn small_held(&self) -> bool {
        self.small_held > 0
    }

    /// Updates whether a direction counts in the fair share: it holds
    /// more written-but-unreleased bytes than its floor, or has a write
    /// waiting. `true` when it left the fair share: a larger share for the
    /// others, whose writers are to be woken.
    pub(in super::super) fn sync_holder(&mut self, key: StreamKey, mp: bool) -> bool {
        let Some(send) = self.send(key) else {
            return false;
        };
        // A direction within its 64 KiB floor takes nothing from the shared
        // part (the floor is on top of it), so only one holding more, or
        // whose writer waits, counts in n.
        let held = if send.state.is_terminal() {
            0
        } else {
            send.held(mp)
        };
        let holding = held > SHARE_FLOOR || (send.waits.waiting && !send.state.is_terminal());
        let small = if holding { 0 } else { held };
        if (holding, small) == (send.waits.holding, send.waits.small) {
            return false;
        }
        let Some(send) = self.slab.get_mut(key).and_then(|s| s.send.as_mut()) else {
            return false;
        };
        let before = std::mem::replace(&mut send.waits.small, small);
        self.small_held = self.small_held - before + small;
        if holding == send.waits.holding {
            return false;
        }
        send.waits.holding = holding;
        if holding {
            self.send_holders += 1;
            false
        } else {
            self.send_holders -= 1;
            true
        }
    }

    /// A stream leaves the table: it no longer counts in the fair share.
    pub(super) fn drop_holder(&mut self, send: &SendPart) {
        if send.waiter.is_some() {
            self.waiters_gone += 1;
        }
        if send.waits.holding {
            self.send_holders -= 1;
        }
        self.small_held -= send.waits.small;
    }

    /// Recounts the fair-share holders (debug builds check the running
    /// count against it).
    #[cfg(debug_assertions)]
    fn check_holders(&self) {
        let parts = || self.slab.keys().filter_map(|k| self.send(k));
        let n = parts().filter(|s| s.waits.holding).count() as u64;
        debug_assert_eq!(n, self.send_holders, "fair-share holders out of step");
        let small: u64 = parts().map(|s| s.waits.small).sum();
        debug_assert_eq!(small, self.small_held, "fair-share small bytes out of step");
    }

    // ---- waiting writers -----------------------------------------------------

    /// Registers the writer of `key` as waiting for room, once.
    pub(in super::super) fn add_send_waiter(&mut self, key: StreamKey) {
        let waits = self.send(key).is_some_and(|s| s.waiter.is_some());
        if !waits && let Some(send) = self.slab.get_mut(key).and_then(|s| s.send.as_mut()) {
            send.waiter = Some(self.send_waiters.len() as u32);
            self.send_waiters.push(key);
        }
    }

    /// The writers waiting for room, in the order they began to wait (the
    /// entries of streams that stopped waiting included), for the debug
    /// recounts.
    #[cfg(debug_assertions)]
    pub(in super::super) fn send_waiters(&self) -> &[StreamKey] {
        &self.send_waiters
    }

    /// Starts waking writers: `None` when none waits or writers are being
    /// woken already, else whether at most half of the entries are stale
    /// (a multipath session then looks only at those its ledger points
    /// to). [`Self::stop_waking`] ends it.
    pub(in super::super) fn start_waking(&mut self) -> Option<bool> {
        if self.send_waiters.is_empty() || self.waking {
            return None;
        }
        self.waking = true;
        Some(self.waiters_gone * 2 <= self.send_waiters.len())
    }

    /// Writers are woken no more.
    pub(in super::super) fn stop_waking(&mut self) {
        self.waking = false;
    }

    /// The scratch list of waiting entries to look at, empty.
    pub(in super::super) fn take_wake_scratch(&mut self) -> Vec<u32> {
        let mut v = std::mem::take(&mut self.wake_scratch);
        v.clear();
        v
    }

    /// Keeps the scratch list for the next wake.
    pub(in super::super) fn put_wake_scratch(&mut self, v: Vec<u32>) {
        self.wake_scratch = v;
    }

    /// Wakes the writer of entry `at`, if the entry is current and the
    /// writer has room (or its part ended).
    pub(in super::super) fn wake_at(
        &mut self,
        at: u32,
        buffer: SendBuffer,
        events: &mut VecDeque<CoreEvent>,
    ) -> bool {
        let key = self.send_waiters[at as usize];
        self.wake_key(key, at, buffer, events)
    }

    fn wake_key(
        &mut self,
        key: StreamKey,
        at: u32,
        buffer: SendBuffer,
        events: &mut VecDeque<CoreEvent>,
    ) -> bool {
        let Some(send) = self.send(key) else {
            return false;
        };
        if send.waiter != Some(at) || (send.outcome.is_none() && self.send_room(key, buffer) == 0) {
            return false;
        }
        if let Some(send) = self.send_mut(key) {
            send.waiter = None;
        }
        self.waiters_gone += 1;
        // Waking re-syncs the part's standing; a share that grew wakes no
        // one more while writers are being woken.
        self.sync_holder(key, buffer.mp());
        self.notify_writable(key, events);
        true
    }

    /// Looks at every entry, wakes the writers with room, and drops the
    /// entries that are no longer current.
    pub(in super::super) fn wake_every(
        &mut self,
        buffer: SendBuffer,
        events: &mut VecDeque<CoreEvent>,
    ) {
        let mut waiters = std::mem::take(&mut self.send_waiters);
        let mut kept = 0;
        for at in 0..waiters.len() {
            let k = waiters[at];
            if self.wake_key(k, at as u32, buffer, events) {
                continue;
            }
            let current = self.send(k).is_some_and(|s| s.waiter == Some(at as u32));
            if current {
                waiters[kept] = k;
                self.renumber_waiter(k, kept);
                kept += 1;
            }
        }
        waiters.truncate(kept);
        // Writers that began to wait meanwhile come after.
        for k in std::mem::take(&mut self.send_waiters) {
            self.renumber_waiter(k, waiters.len());
            waiters.push(k);
        }
        self.waiters_gone = 0;
        self.send_waiters = waiters;
    }

    /// Moves a waiting writer's entry to `at`.
    fn renumber_waiter(&mut self, key: StreamKey, at: usize) {
        let at = Some(at as u32);
        let moved = self
            .send(key)
            .is_some_and(|s| s.waiter.is_some() && s.waiter != at);
        if moved && let Some(send) = self.send_mut(key) {
            send.waiter = at;
        }
    }

    /// Whether the writer of entry `at` would be woken now (debug builds
    /// check the ledger's candidates against it).
    #[cfg(debug_assertions)]
    pub(in super::super) fn has_room_at(&self, at: usize, buffer: SendBuffer) -> bool {
        let k = self.send_waiters[at];
        self.send(k).is_some_and(|s| {
            s.waiter == Some(at as u32) && (s.outcome.is_some() || self.send_room(k, buffer) > 0)
        })
    }

    // ---- write marks ---------------------------------------------------------

    /// Records `n` bytes the application just wrote at `now`; `waiting`
    /// when the write could not take all its data and waits for space.
    pub(in super::super) fn mark_write(
        &mut self,
        key: StreamKey,
        n: u64,
        waiting: bool,
        mp: bool,
        now: Instant,
    ) {
        let Some(send) = self.send(key) else {
            return;
        };
        // Nothing to record: no bytes, and the writer waits as before (a
        // wait in a multipath session already dated).
        let dated = |a: &Age| !waiting || a.wait_start.is_some();
        if n == 0
            && send.waits.waiting == waiting
            && (!mp || send.waits.age.as_deref().is_some_and(dated))
        {
            return;
        }
        let Some(send) = self.send_mut(key) else {
            return;
        };
        let started = waiting && !send.waits.waiting;
        let ended = !waiting && send.waits.waiting;
        send.waits.waiting = waiting;
        if !mp {
            // Only the fair share needs to know: no ages on a single pipe.
            return;
        }
        let end = send.written;
        let done = send.committed();
        let a = send.waits.age_mut();
        // A wait that began before the session became multipath (a writer
        // blocked since before establishment) has no start yet: it starts
        // now rather than never.
        if started || (waiting && a.wait_start.is_none()) {
            // A write that starts waiting within 1 ms of the previous one
            // completing continues that wait.
            let continues = a
                .wait_end
                .is_some_and(|e| now.saturating_duration_since(e) <= MARK_MERGE);
            if !continues || a.wait_start.is_none() {
                a.wait_start = Some(now);
            }
        }
        let at = if waiting || ended {
            a.wait_start.unwrap_or(now)
        } else {
            now
        };
        if ended {
            a.wait_end = Some(now);
        }
        if n == 0 {
            return;
        }
        while a.marks.front().is_some_and(|&(e, _)| e <= done) {
            a.marks.pop_front();
        }
        match a.marks.back_mut() {
            Some(back) if at.saturating_duration_since(back.1) <= MARK_MERGE && back.1 <= at => {
                back.0 = end;
            }
            _ => a.marks.push_back((end, at)),
        }
    }

    // ---- capacity waits ------------------------------------------------------

    /// A sending part waits for `min` bytes of send capacity (the latest
    /// registration counts); `false` when the part is gone.
    pub(in super::super) fn add_capacity_wait(&mut self, key: StreamKey, min: u64) -> bool {
        let Some(send) = self.slab.get_mut(key).and_then(|s| s.send.as_mut()) else {
            return false;
        };
        if send.cold_mut().capacity_wait.replace(min).is_none() {
            self.capacity_waiters.push(key);
        }
        true
    }

    /// The send capacity a part waits for.
    pub(in super::super) fn capacity_wait(&self, key: StreamKey) -> Option<u64> {
        self.send(key)?.cold().capacity_wait
    }

    /// A part's capacity wait is over; its entry leaves the list.
    pub(in super::super) fn end_capacity_wait(&mut self, key: StreamKey) {
        self.clear_capacity_wait(key);
        if let Some(i) = self.capacity_waiters.iter().position(|&k| k == key) {
            self.capacity_waiters.swap_remove(i);
        }
    }

    /// A part's capacity wait is over (its entry is dropped by the caller).
    pub(in super::super) fn clear_capacity_wait(&mut self, key: StreamKey) {
        if let Some(send) = self.send_mut(key) {
            send.cold_mut().capacity_wait = None;
        }
    }

    /// The parts waiting for send capacity, taken out to be looked at.
    pub(in super::super) fn take_capacity_waiters(&mut self) -> Vec<StreamKey> {
        std::mem::take(&mut self.capacity_waiters)
    }

    /// The parts still waiting after a look, none of them stale.
    pub(in super::super) fn restore_capacity_waiters(&mut self, waiters: Vec<StreamKey>) {
        self.capacity_waiters = waiters;
        self.capacity_gone = 0;
    }
}
