//! The session send buffer in force and the waking of writers that wait
//! for room in it. The fair share of the buffer between the stream
//! directions and the write marks are the stream layer's
//! (`streams/share.rs`); a multipath session grows the buffer to its
//! retransmit budget and finds the writers to wake through its ledger.

use super::SessionCore;
use super::stream::StreamKey;
use super::streams::SendBuffer;

impl SessionCore {
    /// Room for new data on a stream direction, within its own limit, its
    /// fair share and the session buffer (with the 64 KiB floor).
    pub(super) fn send_room(&self, key: StreamKey) -> u64 {
        self.streams.send_room(key, self.send_buffer())
    }

    /// Looks at the entries that may have room: those of the writers whose
    /// room depends only on the bytes they hold and who hold less than it
    /// starts below, and the others. A larger share midway (a woken writer
    /// left the fair share) brings in the further writers below it.
    pub(super) fn wake_some(&mut self, buffer: SendBuffer) {
        let mut below = self.streams.room_below(buffer);
        let mut cands = self.streams.take_wake_scratch();
        if let Some(l) = self.ledger() {
            l.waiters_below(below, 0, &mut cands);
        }
        cands.sort_unstable();
        cands.dedup();
        #[cfg(debug_assertions)]
        for i in 0..self.streams.send_waiters().len() {
            debug_assert!(
                !self.streams.has_room_at(i, buffer) || cands.binary_search(&(i as u32)).is_ok(),
                "a waiting writer with room left out"
            );
        }
        let mut next = 0;
        while let Some(&at) = cands.get(next) {
            next += 1;
            self.streams.wake_at(at, buffer, &mut self.events);
            let now = self.streams.room_below(buffer);
            if now > below {
                // The woken writer's part had ended: waking it re-synced
                // its standing, it left the fair share, and the share grew.
                // Rare (once per ended part), so the list of the further
                // writers is allocated here.
                let mut more = Vec::new();
                if let Some(l) = self.ledger() {
                    l.waiters_below(now, below, &mut more);
                }
                more.retain(|&i| i > at && cands[next..].binary_search(&i).is_err());
                cands.extend(more);
                cands[next..].sort_unstable();
                let mut rest = cands.split_off(next);
                rest.dedup();
                cands.append(&mut rest);
                below = now;
            }
        }
        self.streams.put_wake_scratch(cands);
    }
}
