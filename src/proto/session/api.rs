//! Application commands: opening and accepting streams, reading and
//! writing, termination, priorities, datagrams and pings.

#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::datagram::{DatagramDrop, ResolvedDatagramOptions};
use super::recv_store::{ReceiveQueue, ReceiveStore};

use super::stream::{
    GoAwayFail, LocalReset, RecvPart, RecvState, SendOutcome, SendPart, SendState, Stream,
    StreamKey,
};
use super::streams::Stopped;
use super::tp::TpValues;
use super::{
    CoreEvent, DatagramError, DatagramSendOptions, OpenError, OutDatagram, PacketAdmission,
    PacketRepresentation, SendPolicy, SessionCore, SessionError, StreamError, di, dir_of_index,
};
use crate::proto::frame::{Dir, Priority};
use crate::proto::meter::Count;
use crate::proto::payload::{AppTlvs, GreaseTlv, WirePreamble};
use crate::proto::{ApplicationErrorCode, VarInt, varint};
use crate::util::usize_sat;

/// The preamble limit before the peer's parameters without remembered
/// ones.
const MIN_PREAMBLE_FLOOR: u64 = 1024;
/// This endpoint's own limit on the preambles it sends.
pub(super) const MAX_LOCAL_PREAMBLE: u64 = 4096;

/// What a preamble leaves of the carrier record floor for the STREAM frame header and the
/// record's own: the one margin of every language (EXTENSIONS.md Section 4.1), so the
/// bound is 8160.
const PREAMBLE_MARGIN: usize = 32;

/// Smallest per-stream window or send buffer.
const MIN_STREAM_WINDOW: u64 = 16 * 1024;
/// The floor of `initial_stream_receive_window`, and of what
/// `set_receive_window` takes as its initial window.
const MIN_INITIAL_STREAM_WINDOW: u64 = 4 * 1024;

/// What a read found.
enum Readable {
    /// This many bytes are buffered.
    Data(usize),
    /// The stream ended cleanly and everything was read.
    End,
    /// Nothing yet.
    Pending,
}

/// The outcome of a write-side wait (see [`SessionCore::send_outcome`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcomeKind {
    /// The FIN was written (on a single pipe: acknowledged). Delivery ends
    /// at the peer's zmux endpoint, not its application.
    Finished,
    /// The peer sent `STOP_SENDING` with this code.
    Stopped(VarInt),
    /// The application reset the stream.
    Reset,
}

/// The send capacity of a sending part (see
/// [`SessionCore::send_capacity`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendCapacity {
    /// The bytes the part could transmit now: the smaller of its remaining
    /// stream credit and the session's remaining credit, minus what it
    /// holds unsent (0 at least). Before the first frame the preamble is
    /// not counted yet.
    pub capacity: u64,
    /// The bytes the part holds unsent (preamble included).
    pub unsent: u64,
}

impl SendCapacity {
    /// Whether a wait for `min` bytes of capacity is over: the capacity is at
    /// least `min` (taken as 1 at least), or above
    /// 0 while the part holds nothing unsent, since a peer window smaller
    /// than `min` would otherwise never satisfy it.
    #[must_use]
    pub fn reaches(&self, min: u64) -> bool {
        self.capacity >= min.max(1) || (self.capacity > 0 && self.unsent == 0)
    }
}

impl SessionCore {
    // ---- opening and accepting ------------------------------------------------

    /// Opens a stream of a type. Opening reserves stream-count credit, so
    /// the stream's identifier is always below the peer's limit; nothing is
    /// sent until the first write or [`SessionCore::stream_id`]. Fails with [`OpenError::Blocked`]
    /// without credit; the driver waits for [`CoreEvent::StreamsAvailable`] and tries again.
    /// Before establishment the peer's limits are unknown: the stream is created
    /// and its data waits for the peer's parameters (and for credit).
    pub fn open(&mut self, dir: Dir) -> Result<StreamKey, OpenError> {
        if let Some(e) = self.lost() {
            return Err(OpenError::SessionLost(e));
        }
        // After any GOAWAY from the peer no new stream opens, whatever the
        // watermarks.
        if self.goaway().shutdown.is_some() || self.streams.goaway_received() {
            return Err(OpenError::GoingAway);
        }
        let established = self.is_established();
        let d = di(dir);
        if !self.streams.reserve_local(d, established) {
            return Err(OpenError::Blocked);
        }
        if dir == Dir::Bidi && !self.reserve_local_receive() {
            self.streams.unreserve_local(d);
            return Err(OpenError::MemoryBudget);
        }
        let peer = self.send_tp();
        let mut s = Stream::new(dir, true);
        match dir {
            Dir::Bidi => {
                let send = peer.map_or(0, |p| p.window_bidi_remote);
                s.send = Some(self.streams.new_send_part(send));
                let window = self.local_tp().window_bidi_local;
                let mut recv = RecvPart::new(window, self.config.stream_window_cap());
                // Counts in n_local while open.
                recv.counts_open = true;
                s.recv = Some(recv);
            }
            Dir::Uni => {
                let send = peer.map_or(0, |p| p.window_uni);
                s.send = Some(self.streams.new_send_part(send));
            }
        }
        self.stats.streams_opened_local += 1;
        Ok(self.streams.insert(s))
    }

    /// The next peer stream of a type, in identifier order, or `None` when
    /// none is ready (wait for [`CoreEvent::StreamOpened`]).
    pub fn accept(&mut self, dir: Dir) -> Result<Option<StreamKey>, SessionError> {
        if let Some(e) = self.lost() {
            return Err(e);
        }
        let d = di(dir);
        if self.streams.remote_dir(d).staged() {
            let grant = !self.goaway_announced();
            self.streams.unstage(d, grant);
            if self.streams.remote_dir(d).activating() {
                self.grow_peer_stream_credit(d);
            }
        }
        Ok(self.streams.accept(d))
    }

    /// The peer's reset of the stream, once received: its code and Reliable
    /// Size in application bytes; `Ok(None)` when the stream ended with a
    /// FIN instead, or while neither arrived (`Err` once the session ended).
    pub fn received_reset(&self, key: StreamKey) -> Result<Option<(VarInt, u64)>, StreamError> {
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        let r = s.recv.as_ref().ok_or(StreamError::ClosedLocally)?;
        if let Some((code, reliable)) = r.cold().reset {
            let base = r.preamble_size().unwrap_or(0);
            return Ok(Some((super::varint(code), reliable.saturating_sub(base))));
        }
        if r.final_size.is_none()
            && let Some(e) = self.lost()
        {
            return Err(StreamError::SessionLost(e));
        }
        Ok(None)
    }

    /// What the receiving part has for the application, without taking
    /// it: `Ok(Some(n))` with `n` bytes readable now, `Ok(Some(0))` once the
    /// stream ended cleanly and everything was read, `Ok(None)` while
    /// nothing is available (wait for [`CoreEvent::StreamReadable`]), or
    /// the error a read would report.
    pub fn readable_len(&self, key: StreamKey) -> Result<Option<usize>, StreamError> {
        Ok(match self.readable(key)? {
            Readable::Data(n) => Some(n),
            Readable::End => Some(0),
            Readable::Pending => None,
        })
    }

    /// Whether the receiving part's end is known: a FIN (final size) or a
    /// reset arrived.
    pub fn recv_end_known(&self, key: StreamKey) -> bool {
        self.streams
            .recv(key)
            .is_some_and(|r| r.final_size.is_some())
    }

    /// The stream's identifier. Before the stream's first frame this pins
    /// the identifier and sends the opening frame as soon as flow control
    /// allows, before any later stream of the type.
    pub fn stream_id(&mut self, key: StreamKey) -> Result<u64, StreamError> {
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        if let Some(id) = s.id {
            return Ok(id);
        }
        if !self.is_established() && self.lost().is_none() {
            // The role, and so the identifier, is known at establishment.
            return Err(StreamError::NotEstablished);
        }
        if let Some(f) = s.goaway {
            return Err(f.error());
        }
        if let Some(e) = self.lost() {
            return Err(StreamError::SessionLost(e));
        }
        if s.send.as_ref().is_some_and(|x| x.state.is_terminal()) {
            // Cancelled before its first frame: it never gets one.
            return Err(StreamError::ClosedLocally);
        }
        let d = di(s.dir);
        let ld = &self.streams.local_dir(d);
        if ld.goaway.is_some() {
            // Unemitted and unpinned when the GOAWAY arrived.
            self.unschedule(key);
            self.reject_unopened(key, GoAwayFail::GoingAway);
            return Err(StreamError::GoingAway);
        }
        if ld.next_index >= ld.peer_max {
            // Opened before establishment beyond the peer's limit.
            return Err(StreamError::Blocked);
        }
        if self.preamble_len(key) as u64 > self.preamble_limit() {
            // The peer's parameters arrived below the limit the open
            // assumed: only this stream fails, nothing is sent.
            self.unschedule(key);
            let max = self.preamble_limit();
            self.reject_unopened(key, GoAwayFail::too_large(max));
            return Err(StreamError::PreambleTooLarge { max });
        }
        self.unschedule(key);
        self.assign_id(key);
        // Opening frames go out in identifier order (`write_openings`).
        self.streams.pin(key).ok_or(StreamError::ClosedLocally)?;
        s_id(self, key)
    }

    /// The stream with this identifier, while the core holds it.
    pub fn stream_key(&self, id: u64) -> Option<StreamKey> {
        self.streams.key_of(id)
    }

    /// The stream's identifier if it has one, without pinning it.
    pub fn peek_stream_id(&self, key: StreamKey) -> Option<u64> {
        self.streams.get(key)?.id
    }

    /// The stream's type, while the core holds it.
    pub fn stream_dir(&self, key: StreamKey) -> Option<Dir> {
        self.streams.get(key).map(|s| s.dir)
    }

    /// Whether this endpoint opened the stream.
    pub fn is_local_stream(&self, key: StreamKey) -> Option<bool> {
        self.streams.get(key).map(|s| s.local)
    }

    // ---- writing -------------------------------------------------------------

    /// Room for new data on the stream's sending part, or the outcome that
    /// ended it.
    pub fn write_room(&self, key: StreamKey) -> Result<u64, StreamError> {
        self.writable_part(key)?;
        Ok(self.send_room(key))
    }

    /// Room for new data on the stream's sending part, as
    /// [`SessionCore::write`] takes it, or the outcome that ended it; with
    /// no room, registers for [`CoreEvent::StreamWritable`] once
    /// there is some or the part ends, as a write that took nothing does.
    pub fn poll_write_room(&mut self, key: StreamKey) -> Result<u64, StreamError> {
        let room = self.write_room(key)?;
        if room == 0 {
            self.wait_writable(key);
        }
        Ok(room)
    }

    /// The sending part, while the application may still write to it.
    fn writable_part(&self, key: StreamKey) -> Result<&SendPart, StreamError> {
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        if let Some(f) = s.goaway {
            return Err(f.error());
        }
        let send = s.send.as_ref().ok_or(StreamError::ClosedLocally)?;
        match send.outcome {
            Some(SendOutcome::Finished | SendOutcome::Reset) => {
                return Err(StreamError::ClosedLocally);
            }
            Some(SendOutcome::Stopped(code)) => return Err(stopped_error(code)),
            None => {}
        }
        if let Some(e) = self.lost() {
            return Err(StreamError::SessionLost(e));
        }
        Ok(send)
    }

    /// The send capacity of the sending part, or the
    /// outcome that ended it, as [`SessionCore::write`] reports it. Nothing
    /// changes it but credit from the peer and the part's own writes: what
    /// is sent leaves both the credit and the unsent bytes.
    pub fn send_capacity(&self, key: StreamKey) -> Result<SendCapacity, StreamError> {
        let send = self.writable_part(key)?;
        let stream_left = send.max_data.saturating_sub(send.offset);
        let session_left = self.streams.send_flow().room();
        let unsent = send.buf.len() + send.preamble_left as u64;
        Ok(SendCapacity {
            capacity: stream_left.min(session_left).saturating_sub(unsent),
            unsent,
        })
    }

    /// Registers for [`CoreEvent::StreamWritable`] once a wait for
    /// `min` bytes of send capacity is over ([`SendCapacity::reaches`]), or
    /// the part ended. The part is woken only then, not on every change of
    /// credit, so that a caller that wants a chunk's worth costs one
    /// wake-up per chunk. Registrations until the notification keep the
    /// smallest `min` (a waiter for more checks again when it is woken);
    /// one that is over already notifies at once.
    pub fn wait_send_capacity(&mut self, key: StreamKey, min: u64) {
        if self.streams.add_capacity_wait(key, min) {
            self.check_capacity_wait(key);
        }
    }

    /// Whether the capacity wait of `key` for `min` bytes is over: it
    /// reached `min`, or the part ended.
    fn capacity_wait_over(&self, key: StreamKey, min: u64) -> bool {
        self.send_capacity(key)
            .as_ref()
            .map_or(true, |c| c.reaches(min))
    }

    /// The part's own credit grew or its unsent bytes left: ends its
    /// capacity wait, waking it, if that is over.
    pub(super) fn check_capacity_wait(&mut self, key: StreamKey) {
        let Some(min) = self.streams.capacity_wait(key) else {
            return;
        };
        if !self.capacity_wait_over(key, min) {
            return;
        }
        self.streams.end_capacity_wait(key);
        self.notify_writable(key);
    }

    /// Session credit arrived: wakes the parts whose capacity wait is over
    /// now; the others stay listed. Keys of discarded streams leave.
    pub(super) fn wake_capacity_waiters(&mut self) {
        let mut waiters = self.streams.take_capacity_waiters();
        waiters.retain(|&key| {
            let Some(min) = self.streams.capacity_wait(key) else {
                return false;
            };
            if !self.capacity_wait_over(key, min) {
                return true;
            }
            self.streams.clear_capacity_wait(key);
            self.notify_writable(key);
            false
        });
        self.streams.restore_capacity_waiters(waiters);
    }

    /// Writes as much of `data` as the send buffers take and returns the
    /// count; 0 means wait for [`CoreEvent::StreamWritable`].
    pub fn write(&mut self, key: StreamKey, data: &[u8]) -> Result<usize, StreamError> {
        let room = self.write_room(key)?;
        let n = usize_sat(room.min(data.len() as u64));
        if n == 0 {
            if !data.is_empty() {
                self.wait_writable(key);
            }
            return Ok(0);
        }
        let epoch = self.current_budget_epoch();
        let written = self
            .streams
            .write_slice(key, &data[..n])
            .expect("checked by write_room");
        if written < n {
            self.wait_for_write_memory(key, epoch);
        }
        self.wrote(key, written, written == n && n < data.len());
        Ok(written)
    }

    /// Writes a chunk without copying it. Returns the bytes taken: all of
    /// `data`, a prefix when the buffers are nearly full, or 0.
    pub fn write_chunk(
        &mut self,
        key: StreamKey,
        data: super::Chunk,
    ) -> Result<usize, StreamError> {
        self.write_chunk_inner(
            key,
            data,
            #[cfg(all(feature = "tokio", not(loom)))]
            None,
        )
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn write_splice_chunk(
        &mut self,
        key: StreamKey,
        data: super::Chunk,
        payment: &mut super::splice_handoff::Prepayment<'_>,
    ) -> Result<usize, StreamError> {
        self.write_chunk_inner(key, data, Some(payment))
    }

    fn write_chunk_inner(
        &mut self,
        key: StreamKey,
        mut data: super::Chunk,
        #[cfg(all(feature = "tokio", not(loom)))] mut payment: Option<
            &mut super::splice_handoff::Prepayment<'_>,
        >,
    ) -> Result<usize, StreamError> {
        let room = self.write_room(key)?;
        let n = usize_sat(room.min(data.len() as u64));
        if n == 0 {
            if !data.is_empty() {
                self.wait_writable(key);
            }
            return Ok(0);
        }
        let epoch = self.current_budget_epoch();
        let backing = data.backing;
        let data_len = data.len();
        if n < data_len {
            data.truncate(n);
        }
        #[cfg(all(feature = "tokio", not(loom)))]
        let receipt = payment.as_ref().map(|payment| {
            let receipt = payment.prepare(n);
            data.handoff = Some(receipt.clone());
            receipt
        });
        if !self
            .streams
            .write_bytes(key, data)
            .expect("checked by write_room")
        {
            if self
                .write_domain()
                .is_some_and(|domain| !domain.write_root_fits(backing))
            {
                return Err(StreamError::MemoryBudget);
            }
            self.wait_for_write_memory(key, epoch);
            return Ok(0);
        }
        #[cfg(all(feature = "tokio", not(loom)))]
        if let (Some(payment), Some(receipt)) = (payment.as_mut(), receipt) {
            payment.accept(&receipt);
        }
        let partial = n < data_len;
        self.wrote(key, n, partial);
        Ok(n)
    }

    /// Whether every byte written to the sending part has been passed to a
    /// carrier (none is unsent); if not, registers for
    /// [`CoreEvent::StreamWritable`] once that is so or the part ends.
    pub fn data_sent(&mut self, key: StreamKey) -> Result<bool, StreamError> {
        self.data_sent_through(key, None)
    }

    /// Waits for a prefix up to the given application offset to leave the
    /// send buffer. None means all bytes written.
    pub(crate) fn data_sent_through(
        &mut self,
        key: StreamKey,
        through: Option<u64>,
    ) -> Result<bool, StreamError> {
        let send = self.writable_part(key)?;
        let through = through.unwrap_or(send.written);
        if send.offset.saturating_sub(send.base) >= through {
            return Ok(true);
        }
        self.send_part(key).wait_sent_through(through);
        Ok(false)
    }

    fn send_part(&mut self, key: StreamKey) -> &mut SendPart {
        self.streams.send_mut(key).expect("checked by write_room")
    }

    /// Bookkeeping after `n` bytes were written: the application bytes,
    /// the write marks, the fair share and the scheduler.
    fn wrote(&mut self, key: StreamKey, n: usize, waiting: bool) {
        self.meter.add(Count::Written, n as u64);
        if let Some(s) = self.streams.get(key) {
            s.count(Count::Written, n as u64);
        }
        self.mark_write(key, n as u64, waiting);
        if waiting {
            self.wait_writable(key);
        }
        self.sync_holder(key);
        self.schedule(key);
        // Data that a moving binding holds back waits for the blocking data on the
        // old pipe: the direction is held, for opportunistic reinjection.
        self.note_credit_blocked(key);
    }

    /// Registers a writer that waits for room; it is woken once
    /// [`SessionCore::send_room`] is positive again.
    fn wait_writable(&mut self, key: StreamKey) {
        self.mark_write(key, 0, true);
        self.streams.add_send_waiter(key);
        self.sync_holder(key);
    }

    fn wait_for_write_memory(&mut self, key: StreamKey, epoch: Option<u64>) {
        if self.write_blocked_at.is_none() {
            self.write_blocked_at = epoch;
        }
        if !self.memory_writers.contains(&key) {
            self.memory_writers.push(key);
        }
        self.mark_write(key, 0, true);
    }

    /// Makes the stream's opening frame owed, with the data written so far
    /// in it: as soon as credit lets, even with nothing written; before
    /// establishment as soon as the stream may open, in early data if that
    /// is in use. [`SessionCore::flushed`] tells when it left.
    ///
    /// A finished or reset part flushes as usual: only a part the peer
    /// stopped or a lost session reports an error, and a stop only before
    /// everything the flush waits for was passed on ([`SessionCore::flushed`]).
    pub fn flush(&mut self, key: StreamKey) -> Result<(), StreamError> {
        if self.sent_before_stop(key) {
            return Ok(());
        }
        let reset = self.flushable_part(key)?.outcome == Some(SendOutcome::Reset);
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        if s.id.is_none() && !reset {
            self.send_part(key).open_want = true;
            self.schedule(key);
        }
        Ok(())
    }

    /// Whether the stream's opening frame and every byte written were passed
    /// to a carrier (nothing is left to pass of a reset part), or are queued
    /// in the held first flight, which leaves with them; if not,
    /// registers for [`CoreEvent::StreamWritable`] once that is so or
    /// the part ends.
    ///
    /// A `STOP_SENDING` that arrives once the opening frame and every byte
    /// written were passed on does not fail the flush: what it waited for
    /// happened, and the next write or finish reports the stop. A stop
    /// before that fails it.
    pub fn flushed(&mut self, key: StreamKey) -> Result<bool, StreamError> {
        if self.sent_before_stop(key) {
            return Ok(true);
        }
        let send = self.flushable_part(key)?;
        if send.outcome == Some(SendOutcome::Reset) {
            return Ok(true);
        }
        if self.first_held.is_some() {
            return Ok(true);
        }
        let done = send.buf.is_empty() && send.preamble_left == 0 && !send.open_want;
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        if done && s.id.is_some() && !s.open_pending {
            return Ok(true);
        }
        let through = send.written;
        self.send_part(key).wait_sent_through(through);
        Ok(false)
    }

    /// Whether the peer stopped a sending part only after its opening frame
    /// and every byte written were passed to a carrier.
    fn sent_before_stop(&self, key: StreamKey) -> bool {
        let Some(s) = self.streams.get(key) else {
            return false;
        };
        let Some(send) = s.send.as_ref() else {
            return false;
        };
        matches!(send.outcome, Some(SendOutcome::Stopped(_)))
            && s.goaway.is_none()
            && self.lost().is_none()
            && s.id.is_some()
            && !s.open_pending
            && send.preamble_left == 0
            && send.offset.saturating_sub(send.base) >= send.written
    }

    /// The sending part as a flush sees it: finishing or resetting it is no
    /// error.
    fn flushable_part(&self, key: StreamKey) -> Result<&SendPart, StreamError> {
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        if let Some(f) = s.goaway {
            return Err(f.error());
        }
        let send = s.send.as_ref().ok_or(StreamError::ClosedLocally)?;
        if let Some(SendOutcome::Stopped(code)) = send.outcome {
            return Err(stopped_error(code));
        }
        if let Some(e) = self.lost() {
            return Err(StreamError::SessionLost(e));
        }
        Ok(send)
    }

    /// Ends the stream cleanly: a FIN follows the data written.
    pub fn finish(&mut self, key: StreamKey) -> Result<(), StreamError> {
        let lost = self.lost();
        let s = self
            .streams
            .get_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        if let Some(f) = s.goaway {
            return Err(f.error());
        }
        let send = s.send.as_mut().ok_or(StreamError::ClosedLocally)?;
        match send.outcome {
            Some(SendOutcome::Finished | SendOutcome::Reset) => {
                return Err(StreamError::ClosedLocally);
            }
            Some(SendOutcome::Stopped(code)) => return Err(stopped_error(code)),
            None => {}
        }
        if let Some(e) = lost {
            return Err(StreamError::SessionLost(e));
        }
        send.fin = true;
        send.outcome = Some(SendOutcome::Finished);
        self.schedule(key);
        Ok(())
    }

    /// Resets the sending part. Data below the reliable boundary is still
    /// delivered (`RESET_STREAM_AT`); a stream that has
    /// sent nothing yet consumes no identifier.
    pub fn reset(&mut self, key: StreamKey, code: VarInt) -> Result<(), StreamError> {
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        let send = s.send.as_ref().ok_or(StreamError::ClosedLocally)?;
        if send.fin_sent {
            return Err(StreamError::ClosedLocally);
        }
        if send.cold().reset.is_some() || s.goaway.is_some() {
            return Ok(());
        }
        if let Some(e) = self.lost() {
            // A pending local write after the peer's close fails with the
            // session's error (SPEC.md Section 6.5).
            if self.draining_peer_close() {
                return Err(StreamError::SessionLost(e));
            }
            return Ok(());
        }
        self.local_reset(key, code.into_inner());
        Ok(())
    }

    /// Marks the data written so far as reliable: a later reset still
    /// delivers it.
    pub fn set_reliable_boundary(&mut self, key: StreamKey) -> Result<(), StreamError> {
        self.set_reliable_boundary_at(key, None)
    }

    /// Marks a prefix up to an application offset as reliable. None marks
    /// all bytes written.
    pub(crate) fn set_reliable_boundary_at(
        &mut self,
        key: StreamKey,
        through: Option<u64>,
    ) -> Result<(), StreamError> {
        let send = self
            .streams
            .send_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        if send.outcome.is_some() {
            return Err(StreamError::ClosedLocally);
        }
        let boundary = through.unwrap_or(send.written);
        debug_assert!(boundary <= send.written);
        send.cold_mut().reliable_boundary = Some(boundary.min(send.written));
        Ok(())
    }

    /// The outcome of the sending part, once it ended: for `stopped()`.
    pub fn send_outcome(&self, key: StreamKey) -> Option<Result<SendOutcomeKind, StreamError>> {
        let Some(s) = self.streams.get(key) else {
            return Some(Err(StreamError::ClosedLocally));
        };
        if let Some(f) = s.goaway {
            return Some(Err(f.error()));
        }
        let send = s.send.as_ref()?;
        match send.outcome {
            Some(SendOutcome::Stopped(code)) => {
                return Some(Ok(SendOutcomeKind::Stopped(super::varint(code))));
            }
            Some(SendOutcome::Reset) => return Some(Ok(SendOutcomeKind::Reset)),
            Some(SendOutcome::Finished) if send.state == SendState::DataRecvd => {
                return Some(Ok(SendOutcomeKind::Finished));
            }
            _ => {}
        }
        self.lost().map(|e| Err(StreamError::SessionLost(e)))
    }

    /// Resets the local sending part with `code`.
    pub(super) fn local_reset(&mut self, key: StreamKey, code: u64) {
        let preamble = self.features.preamble;
        let Some(s) = self.streams.get_mut(key) else {
            return;
        };
        let local = s.local;
        let unopened = local && s.id.is_none();
        let Some(send) = s.send.as_mut() else {
            return;
        };
        if send.cold().reset.is_some() || send.fin_sent || send.state.is_terminal() {
            return;
        }
        if send.outcome.is_none() || send.outcome == Some(SendOutcome::Finished) {
            send.outcome = Some(SendOutcome::Reset);
        }
        send.fin = false;
        if unopened && send.cold().reliable_boundary.is_none_or(|b| b == 0) {
            // Nothing was sent: no identifier is consumed.
            let unsent = send.buf.len();
            send.buf.clear();
            send.open_want = false;
            send.state = SendState::ResetRecvd;
            send.cold_mut().reset = Some(LocalReset {
                code,
                reliable_app: None,
                keep_preamble: false,
                answer: false,
                written: true,
            });
            let dir = s.dir;
            if let Some(r) = s.recv.as_mut() {
                // The peer never heard of the stream: nothing will arrive,
                // so the receiving part ends cleanly where it is (a reader
                // sees the end, as on a stream the peer finished empty).
                r.final_size = Some(r.read_offset);
                r.state = RecvState::DataRead;
            }
            self.streams.drop_unsent(unsent);
            let d = di(dir);
            if self.streams.unreserve_local(d) {
                self.push_event(CoreEvent::StreamsAvailable(dir_of_index(d)));
            }
            self.unschedule(key);
            self.wake_send_waiters();
            self.notify_writable(key);
            self.notify_readable(key);
            self.try_discard(key);
            return;
        }
        // Keep the preamble reliable on streams this endpoint opened, unless
        // the peer asked to stop; keep the data
        // below the application's boundary.
        let keep_preamble = preamble && local && send.cold().stopped.is_none();
        let reliable_app = send.cold().reliable_boundary.filter(|&b| b > 0);
        let app_sent = send.offset.saturating_sub(send.base);
        let keep = reliable_app.map_or(0, |b| b.saturating_sub(app_sent));
        let before = send.buf.len();
        send.buf.truncate(keep);
        let dropped = before - send.buf.len();
        send.cold_mut().reset = Some(LocalReset {
            code,
            reliable_app,
            keep_preamble,
            answer: false,
            written: false,
        });
        send.state = SendState::ResetSent;
        self.streams.drop_unsent(dropped);
        self.unschedule(key);
        self.schedule(key);
        self.streams.queue_ctrl(key);
        self.wake_send_waiters();
        self.notify_writable(key);
    }

    /// Answers the peer's `STOP_SENDING` with a reset carrying its code; the
    /// reset keeps nothing reliable.
    pub(super) fn respond_to_stop(&mut self, key: StreamKey, code: u64) {
        let Some(send) = self.streams.send_mut(key) else {
            return;
        };
        if send.fin_sent || send.state.is_terminal() || send.cold().reset.is_some() {
            return;
        }
        let unsent = send.buf.len();
        let before = send.unacked();
        send.buf.clear();
        if let Some(m) = send.mp.as_deref_mut() {
            m.lost.clear();
            m.fin_lost = false;
        }
        send.fin = false;
        send.cold_mut().reset = Some(LocalReset {
            code,
            reliable_app: None,
            keep_preamble: false,
            answer: true,
            written: false,
        });
        let freed = before - send.unacked();
        send.state = SendState::ResetSent;
        self.streams.drop_unsent(unsent);
        self.release_retained(freed);
        self.unschedule(key);
        self.streams.queue_ctrl(key);
        self.wake_send_waiters();
    }

    // ---- reading -------------------------------------------------------------

    /// What the receiving part has for the application.
    fn readable(&self, key: StreamKey) -> Result<Readable, StreamError> {
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        if let Some(f) = s.goaway {
            return Err(f.error());
        }
        let r = s.recv.as_ref().ok_or(StreamError::ClosedLocally)?;
        if r.cold().stopped.is_some() || s.rejected {
            return Err(StreamError::ClosedLocally);
        }
        let lost = self.lost();
        if !r.buf.is_empty() {
            // After the peer's close, what arrived stays readable until the
            // session is CLOSED (SessionCore::peer_close_unread).
            if let Some(e) = lost
                && r.final_size.is_none()
                && r.cold().reset.is_none()
                && !self.draining_peer_close()
            {
                return Err(StreamError::SessionLost(e));
            }
            return Ok(Readable::Data(r.buf.len()));
        }
        if let Some((code, reliable)) = r.cold().reset {
            // The reset takes effect once the data below its Reliable Size
            // was read; a session that ended before that data arrived
            // reports its own error.
            if r.read_offset >= reliable {
                let base = r.preamble_size().unwrap_or(0);
                return Err(reset_error(code, reliable.saturating_sub(base)));
            }
        } else if r.final_size.is_some_and(|f| r.read_offset >= f) {
            return Ok(Readable::End);
        }
        match lost {
            Some(e) => Err(StreamError::SessionLost(e)),
            None => Ok(Readable::Pending),
        }
    }

    /// Reads into `buf`. Returns `Some((n, fin))` with `fin` set when the
    /// stream ended cleanly and everything was read (`n` may then be 0),
    /// or `None` when nothing is available yet (wait for
    /// [`CoreEvent::StreamReadable`]). Data below a peer's Reliable Size
    /// is read before the reset is reported.
    pub fn read(
        &mut self,
        key: StreamKey,
        buf: &mut [u8],
    ) -> Result<Option<(usize, bool)>, StreamError> {
        self.read_with(key, buf.len(), |queue, store, n| {
            let read = queue.consume(store, n, |offset, bytes| {
                buf[offset..offset + bytes.len()].copy_from_slice(bytes);
            });
            (read, ())
        })
        .map(|r| r.map(|(n, fin, ())| (n, fin)))
    }

    /// Appends up to `max` bytes to `out`. The stream's buffer keeps its
    /// capacity (unlike [`SessionCore::read_chunk`], which may share it), so
    /// collecting a stream into a vector allocates only the vector.
    pub fn read_append(
        &mut self,
        key: StreamKey,
        out: &mut Vec<u8>,
        max: usize,
    ) -> Result<Option<(usize, bool)>, StreamError> {
        self.read_with(key, max, |queue, store, n| {
            (
                queue.consume(store, n, |_, bytes| out.extend_from_slice(bytes)),
                (),
            )
        })
        .map(|r| r.map(|(n, fin, ())| (n, fin)))
    }

    /// Reads up to `max` bytes as one chunk without copying: a piece of the
    /// received data (the data may be held in several pieces; a chunk ends
    /// with its piece). Same results as [`SessionCore::read`].
    pub fn read_chunk(
        &mut self,
        key: StreamKey,
        max: usize,
    ) -> Result<Option<(super::Chunk, bool)>, StreamError> {
        self.read_segment(key, max).map(|read| {
            read.map(|(segment, fin)| (super::Chunk::backed(segment.bytes, segment.backing), fin))
        })
    }

    pub(crate) fn read_segment(
        &mut self,
        key: StreamKey,
        max: usize,
    ) -> Result<Option<(super::Segment, bool)>, StreamError> {
        self.read_with(key, max, |queue, store, n| {
            let segment = queue.take(store, n);
            (segment.bytes.len(), segment)
        })
        .map(|r| r.map(|(_, fin, b)| (b, fin)))
    }

    /// Checks external pin eligibility before asking the splice owner whether
    /// the destination fits. Only the normal read commit removes receive
    /// ownership and advances offset and credit.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn read_splice_chunk(
        &mut self,
        key: StreamKey,
        max: usize,
        mut fits_root: impl FnMut(super::Backing) -> bool,
        mut fits_copy: impl FnMut(usize) -> bool,
    ) -> Result<Option<(usize, bool, super::SpliceChunk)>, StreamError> {
        let ready = self.readable(key);
        let Ok(Readable::Data(available)) = ready else {
            return self.read_ready(key, max, ready, |_, _, _| unreachable!());
        };
        let recv = self.streams.recv(key).expect("checked by readable");
        let (backing, segment) = recv.buf.front(&self.receive).expect("readable range");
        let count = max.min(available).min(segment);
        if count == 0 {
            return Ok(Some((0, false, super::SpliceChunk::default())));
        }
        let loan = self.read_loans.get_or_init(Arc::default).acquire(backing);
        if let Some(loan) = loan
            && fits_root(backing)
            && recv.buf.transferable_front(&self.receive, count)
        {
            return self.read_ready(key, count, ready, |queue, store, n| {
                let segment = queue.take(store, n);
                let chunk = super::Chunk::backed(loan.attach(segment.bytes), backing);
                (
                    chunk.len(),
                    super::SpliceChunk {
                        data: chunk,
                        copied: false,
                    },
                )
            });
        }
        if !fits_copy(count) {
            return Err(StreamError::BorrowLimit);
        }
        self.read_ready(key, count, ready, |queue, store, n| {
            let mut bytes = vec![0; n].into_boxed_slice();
            let consumed = queue.consume(store, n, |offset, data| {
                bytes[offset..offset + data.len()].copy_from_slice(data);
            });
            debug_assert_eq!(n, consumed);
            (
                consumed,
                super::SpliceChunk {
                    data: super::Chunk::from(bytes.into_vec()),
                    copied: true,
                },
            )
        })
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn prepare_read(
        &mut self,
        key: StreamKey,
        max: usize,
        chunk: bool,
    ) -> Result<Option<(usize, Option<Bytes>)>, StreamError> {
        let ready = self.readable(key);
        match ready {
            Ok(Readable::Data(n)) => {
                let n = n.min(max);
                if !chunk {
                    return Ok(Some((n, None)));
                }
                let loans = self.read_loans.get_or_init(Arc::default);
                let recv = self.streams.recv(key).expect("checked by readable");
                let (backing, _) = recv.buf.front(&self.receive).expect("readable range");
                let bytes = loans
                    .lend(backing, || {
                        recv.buf
                            .peek(&self.receive, n)
                            .expect("readable range")
                            .bytes
                    })
                    .ok_or(StreamError::BorrowLimit)?;
                Ok(Some((bytes.len(), Some(bytes))))
            }
            Ok(Readable::End) => Ok(Some((0, chunk.then(Bytes::new)))),
            Ok(Readable::Pending) => Ok(None),
            Err(_) => self
                .read_ready::<()>(key, 0, ready, |_, _, _| unreachable!())
                .map(|_| unreachable!()),
        }
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn commit_read(
        &mut self,
        key: StreamKey,
        n: usize,
        mut buffer: Option<&mut [u8]>,
    ) -> bool {
        let ready = self.readable(key);
        let unchanged = match ready {
            Ok(Readable::Data(available)) => n != 0 && available >= n,
            Ok(Readable::End) => n == 0,
            _ => false,
        };
        if !unchanged {
            return false;
        }
        self.read_ready(key, n, ready, |queue, store, count| {
            let consumed = queue.consume(store, count, |offset, bytes| {
                if let Some(buffer) = &mut buffer {
                    buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
                }
            });
            debug_assert_eq!(consumed, count);
            (consumed, ())
        })
        .is_ok()
    }

    #[cfg(all(feature = "test-hooks", feature = "tokio", not(loom)))]
    pub(crate) fn test_read_loan_slots(&self, slots: usize) -> bool {
        self.read_loans
            .set(Arc::new(super::recv_buf::ReadLoans::with_slots(slots)))
            .is_ok()
    }

    fn read_with<T: Default>(
        &mut self,
        key: StreamKey,
        max: usize,
        take: impl FnOnce(&mut ReceiveQueue, &mut ReceiveStore, usize) -> (usize, T),
    ) -> Result<Option<(usize, bool, T)>, StreamError> {
        let ready = self.readable(key);
        self.read_ready(key, max, ready, take)
    }

    fn read_ready<T: Default>(
        &mut self,
        key: StreamKey,
        max: usize,
        ready: Result<Readable, StreamError>,
        take: impl FnOnce(&mut ReceiveQueue, &mut ReceiveStore, usize) -> (usize, T),
    ) -> Result<Option<(usize, bool, T)>, StreamError> {
        let counted = self.draining_peer_close() && self.holds_unread(key);
        let r = self.read_inner(key, max, ready, take);
        if counted && !self.holds_unread(key) {
            // The last unread data or end after the peer's close may hold CLOSED.
            self.unread_drained();
        }
        r
    }

    fn read_inner<T: Default>(
        &mut self,
        key: StreamKey,
        max: usize,
        ready: Result<Readable, StreamError>,
        take: impl FnOnce(&mut ReceiveQueue, &mut ReceiveStore, usize) -> (usize, T),
    ) -> Result<Option<(usize, bool, T)>, StreamError> {
        let n = match ready {
            Ok(Readable::Data(n)) => n.min(max),
            Ok(Readable::End) => {
                self.end_read(key);
                return Ok(Some((0, true, T::default())));
            }
            Ok(Readable::Pending) => return Ok(None),
            Err(e) => {
                if matches!(e, StreamError::Reset { .. } | StreamError::Rejected) {
                    self.reset_read(key);
                }
                return Err(e);
            }
        };
        if n == 0 {
            return Ok(Some((0, false, T::default())));
        }
        let s = self.streams.get_mut(key).expect("checked by readable");
        let r = s.recv.as_mut().expect("checked by readable");
        let (n, out) = take(&mut r.buf, &mut self.receive, n);
        s.count(Count::Read, n as u64);
        let r = s.recv.as_mut().expect("checked by readable");
        r.read_offset += n as u64;
        r.app_read += n as u64;
        self.meter.add(Count::Read, n as u64);
        let fin =
            r.buf.is_empty() && r.cold().reset.is_none() && r.final_size == Some(r.read_offset);
        self.credit_consumed(n as u64);
        self.streams.check_stream_credit(key);
        if fin {
            self.end_read(key);
        }
        Ok(Some((n, fin, out)))
    }

    /// The application read the end of the stream.
    fn end_read(&mut self, key: StreamKey) {
        let Some(r) = self.streams.recv_mut(key) else {
            return;
        };
        r.end_read = true;
        r.state = RecvState::DataRead;
        self.try_discard(key);
    }

    /// The application saw the peer's reset.
    fn reset_read(&mut self, key: StreamKey) {
        if let Some(r) = self.streams.recv_mut(key)
            && r.state == RecvState::ResetRecvd
        {
            r.state = RecvState::ResetRead;
        }
        self.try_discard(key);
    }

    /// Stops reading: `STOP_SENDING` with `code`, and unread data is
    /// discarded.
    pub fn stop(&mut self, key: StreamKey, code: VarInt) -> Result<(), StreamError> {
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        if s.recv.is_none() {
            return Err(StreamError::ClosedLocally);
        }
        // During the read drain after the peer's close: what was unread is
        // discarded, nothing is sent, and the call fails with the session's
        // error, as every pending local operation does (SPEC.md Section 6.5).
        let lost = self.lost().filter(|_| self.draining_peer_close());
        self.local_stop(key, code.into_inner());
        self.try_discard(key);
        lost.map_or(Ok(()), |e| Err(StreamError::SessionLost(e)))
    }

    /// `STOP_SENDING` on the local receiving part (application stop, release
    /// or rejection). Data still buffered is discarded and counts as
    /// consumed.
    pub(super) fn local_stop(&mut self, key: StreamKey, code: u64) {
        let counted = self.draining_peer_close() && self.holds_unread(key);
        self.stop_recv_part(key, code);
        if counted {
            self.unread_drained();
        } else if self.state == super::State::Closing {
            self.maybe_closed(self.now);
        }
    }

    fn stop_recv_part(&mut self, key: StreamKey, code: u64) {
        let Some(Stopped {
            local,
            dropped,
            stop_pending,
        }) = self.streams.stop_recv(key, code, &mut self.receive)
        else {
            return;
        };
        self.credit_consumed(dropped);
        if stop_pending {
            self.streams.queue_ctrl(key);
        }
        self.streams.settle_local_recv(key);
        if !local {
            // A stream stopped before its preamble arrived is never offered.
            self.offer(key);
        }
    }

    // ---- releasing -------------------------------------------------------------

    /// The application dropped every handle of the stream without finishing
    /// it: an unfinished sending part is reset with `ZMUX_CANCELLED` and an
    /// unread receiving part stopped with code 0. The stream's
    /// state is discarded once both parts end.
    pub fn release(&mut self, key: StreamKey) {
        self.release_send(key);
        self.release_recv(key);
    }

    /// The application dropped its sending handle.
    pub fn release_send(&mut self, key: StreamKey) {
        let Some(s) = self.streams.get_mut(key) else {
            return;
        };
        if s.send_released {
            return;
        }
        s.send_released = true;
        let unfinished = s
            .send
            .as_ref()
            .is_some_and(|x| x.outcome.is_none() && !x.state.is_terminal());
        if unfinished {
            self.local_reset(key, ApplicationErrorCode::ZMUX_CANCELLED.0);
        }
        self.mark_released(key);
    }

    /// The application dropped its receiving handle.
    pub fn release_recv(&mut self, key: StreamKey) {
        let Some(s) = self.streams.get_mut(key) else {
            return;
        };
        if s.recv_released {
            return;
        }
        s.recv_released = true;
        if s.recv.is_some() {
            self.local_stop(key, 0);
        }
        self.clear_stream_datagrams(key);
        self.mark_released(key);
    }

    fn mark_released(&mut self, key: StreamKey) {
        let Some(s) = self.streams.get_mut(key) else {
            return;
        };
        let send_done = s.send.is_none() || s.send_released;
        let recv_done = s.recv.is_none() || s.recv_released;
        if send_done && recv_done {
            s.released = true;
            self.try_discard(key);
        }
    }

    /// Declines an accepted stream before reading it: `STOP_SENDING` with
    /// `ZMUX_REJECTED`, and `RESET_STREAM` with `ZMUX_REJECTED` on a sending
    /// part not written to. Releases the
    /// receiving handle, and the sending handle when it was reset.
    pub fn reject(&mut self, key: StreamKey) -> Result<(), StreamError> {
        let s = self
            .streams
            .get_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        if s.recv.is_none() {
            return Err(StreamError::ClosedLocally);
        }
        s.rejected = true;
        let code = ApplicationErrorCode::ZMUX_REJECTED.0;
        let unwritten = s
            .send
            .as_ref()
            .is_some_and(|x| x.written == 0 && x.outcome.is_none());
        self.local_stop(key, code);
        if unwritten {
            self.local_reset(key, code);
            if let Some(s) = self.streams.get_mut(key) {
                s.send_released = true;
            }
        }
        if let Some(s) = self.streams.get_mut(key) {
            s.recv_released = true;
        }
        self.clear_stream_datagrams(key);
        self.mark_released(key);
        Ok(())
    }

    // ---- priorities and metadata -------------------------------------------------

    /// Sets the session's default scheduling policy.
    pub fn set_scheduler(&mut self, policy: super::Scheduler) {
        std::sync::Arc::make_mut(&mut self.config).scheduler = policy;
        // The previous policy's state is discarded; the new one starts
        // from its initial state at the next chunk.
        self.reset_round_robin();
        self.reset_picks(None);
        let keys: Vec<StreamKey> = self.streams.keys().collect();
        for k in keys {
            if let Some(m) = self.streams.send_mut(k).and_then(|s| s.mp.as_deref_mut())
                && m.scheduler.is_none()
            {
                m.bound = None;
            }
        }
    }

    /// The session's default scheduling policy: the configured one or the
    /// last [`Self::set_scheduler`].
    pub fn scheduler(&self) -> super::Scheduler {
        self.config.scheduler.clone()
    }

    /// Sets the host preference for receive scheduling. Peer path requests
    /// use the per-pipe priority and standby settings.
    pub fn set_receive_scheduler(&mut self, policy: super::Scheduler) {
        std::sync::Arc::make_mut(&mut self.config).receive_scheduler = policy;
    }

    /// Returns the local receive scheduling preference.
    pub fn receive_scheduler(&self) -> super::Scheduler {
        self.config.receive_scheduler.clone()
    }

    /// The scheduling policy set on a stream's sending part; `None`: the
    /// session's.
    pub fn stream_scheduler(
        &self,
        key: StreamKey,
    ) -> Result<Option<super::Scheduler>, StreamError> {
        let send = self.streams.send(key).ok_or(StreamError::ClosedLocally)?;
        Ok(send.mp().scheduler.clone())
    }

    /// The redundancy set on a stream's sending part; `None`: the part
    /// follows the session's `redundancy` parameter.
    pub fn stream_redundant(&self, key: StreamKey) -> Result<Option<bool>, StreamError> {
        let send = self.streams.send(key).ok_or(StreamError::ClosedLocally)?;
        Ok(send.mp().redundant)
    }

    /// Sets the scheduling policy of a stream's sending part; `None` uses
    /// the session default.
    pub fn set_stream_scheduler(
        &mut self,
        key: StreamKey,
        policy: Option<super::Scheduler>,
    ) -> Result<(), StreamError> {
        let send = self
            .streams
            .send_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        let m = send.mp_mut();
        m.scheduler = policy;
        m.bound = None;
        self.reset_picks(Some(key));
        Ok(())
    }

    /// Turns redundancy on (`Some(true)`) or off (`Some(false)`) for the
    /// stream's sending part: copies of its chunks on a second pipe of the
    /// tier, within the session's copy bound. `None`, as before the first
    /// call, has the part follow the session's `redundancy` parameter.
    pub fn set_redundant(&mut self, key: StreamKey, on: Option<bool>) -> Result<(), StreamError> {
        let send = self
            .streams
            .send_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        send.mp_mut().redundant = on;
        Ok(())
    }

    /// Sets the local scheduling priority of the stream's sending part
    /// (RFC 9218 urgency and incremental).
    pub fn set_priority(&mut self, key: StreamKey, priority: Priority) -> Result<(), StreamError> {
        let send = self
            .streams
            .send_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        send.priority = priority;
        self.reschedule(key);
        Ok(())
    }

    /// The local scheduling priority of the stream's sending part.
    pub fn priority(&self, key: StreamKey) -> Option<Priority> {
        Some(self.streams.get(key)?.send.as_ref()?.priority)
    }

    /// Asks the peer to schedule its sending part of the stream with
    /// `priority`: the PRIORITY TLV of a local stream's preamble before its
    /// first frame, `PRIORITY_UPDATE` otherwise.
    pub fn set_peer_priority(
        &mut self,
        key: StreamKey,
        priority: Priority,
    ) -> Result<(), StreamError> {
        let preamble = self.features.preamble;
        // Before the peer's parameters only the preamble's PRIORITY TLV of
        // an early stream can carry the request.
        let early = self.early_open();
        if !(self.features.priority || early && preamble) {
            return Err(StreamError::NotNegotiated);
        }
        let s = self
            .streams
            .get_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        if s.recv.is_none() {
            return Err(StreamError::ClosedLocally);
        }
        if s.local && s.id.is_none() && preamble {
            s.extra_mut().peer_priority = Some(priority);
            return Ok(());
        }
        if !self.features.priority {
            // An early stream past its first frame: no PRIORITY_UPDATE yet.
            return Err(StreamError::NotNegotiated);
        }
        let s = self.streams.get_mut(key).expect("checked above");
        s.extra_mut().priority_update = Some(priority);
        self.streams.queue_ctrl(key);
        Ok(())
    }

    /// Opens a stream of type `dir` with `preamble`: [`SessionCore::open`] when it is empty. The
    /// preamble must fit the peer's Maximum Preamble Size and one of our records, with room for a
    /// PRIORITY TLV set later ([`OpenError::PreambleTooLarge`]), and needs the
    /// peer's `zmux_preamble` ([`OpenError::NotNegotiated`]; before
    /// establishment [`OpenError::NotEstablished`], unless the stream is
    /// an early one, whose preamble counts within the assumed set).
    pub fn open_with(
        &mut self,
        dir: Dir,
        preamble: &super::Preamble,
    ) -> Result<StreamKey, OpenError> {
        if preamble.is_empty() {
            return self.open(dir);
        }
        if let Some(e) = self.lost() {
            return Err(OpenError::SessionLost(e));
        }
        // Early streams carry their preamble within the assumed set.
        if !self.is_established() && !self.early_open() {
            return Err(OpenError::NotEstablished);
        }
        if !self.features.preamble {
            return Err(OpenError::NotNegotiated);
        }
        preamble.check(dir)?;
        let (info, tlvs, carrier) = preamble.parts();
        let limit = self.preamble_limit();
        // Room for the GREASE TLV of the first preamble: the test hook's,
        // or the largest random one (an 8-byte type and 8 bytes of value).
        let grease = (!self.grease_tlv_used).then(|| {
            self.config.hooks.grease_tlv.clone().unwrap_or((
                crate::proto::payload::grease_tlv_type(1 << 40).unwrap_or(0x21),
                vec![0; 8],
            ))
        });
        let len = WirePreamble {
            open_info: info.as_deref(),
            // A PRIORITY set before the first frame always fits.
            priority: Some(Priority::WIRE_DEFAULT),
            pipe_carrier: carrier,
            app_tlvs: AppTlvs::whole(tlvs.as_deref().unwrap_or_default()),
        }
        .encoded_len(
            grease
                .as_ref()
                .map(|(ty, v)| GreaseTlv { ty: *ty, value: v }),
        );
        if len as u64 > limit {
            return Err(OpenError::PreambleTooLarge { max: limit });
        }
        let key = self.open(dir)?;
        let s = self.streams.get_mut(key).expect("just opened");
        let e = s.extra_mut();
        (e.open_info, e.app_tlvs, e.pipe_carrier) = (info, tlvs, carrier);
        Ok(key)
    }

    /// The largest preamble a local stream may send now: the peer's
    /// Maximum Preamble Size, or before its parameters the assumed set's
    /// (remembered, or the 1024-byte floor every zmux endpoint advertises); at
    /// most [`MAX_LOCAL_PREAMBLE`] and whole in one record of the carrier record floor, which
    /// every pipe's records hold (SPEC.md Section 3.2): a preamble that passes fits any pipe,
    /// now or later.
    pub(super) fn preamble_limit(&self) -> u64 {
        self.send_tp()
            .map_or(MIN_PREAMBLE_FLOOR, TpValues::preamble)
            .min(MAX_LOCAL_PREAMBLE)
            .min((super::RECORD_FLOOR - PREAMBLE_MARGIN) as u64)
    }

    /// The stream's preamble: the peer's for a peer stream, the one it was
    /// opened with for a local stream. The values share the stream's
    /// buffer.
    pub fn preamble(&self, key: StreamKey) -> super::Preamble {
        let Some(s) = self.streams.get(key) else {
            return super::Preamble::default();
        };
        let e = s.extra();
        super::Preamble::from_parts(e.open_info.clone(), e.app_tlvs.as_ref(), e.pipe_carrier)
    }

    /// The PRIORITY the peer requested in its preamble (peer streams).
    pub fn preamble_priority(&self, key: StreamKey) -> Option<Priority> {
        let s = self.streams.get(key)?;
        if s.local {
            None
        } else {
            s.extra().peer_priority
        }
    }

    /// Sets the stream's receive window: `initial` is advertised at once
    /// when it is above the window in force, `max` caps auto-tuning, 0
    /// making the cap automatic whatever the session's configuration says.
    /// Both must be at most the largest varint (2^62 - 1). Credit already advertised is never withdrawn: an
    /// `initial` below the window in force changes only the setting
    /// [`Self::receive_window`] reads back.
    ///
    /// # Errors
    ///
    /// [`StreamError::InvalidArgument`]: an `initial` below 4 KiB (the floor
    /// of `initial_stream_receive_window`), an `initial` or `max` above the
    /// largest varint, or a nonzero `max` below `initial`; nothing changed. [`StreamError::ClosedLocally`]: the stream has no
    /// receiving part.
    pub fn set_receive_window(
        &mut self,
        key: StreamKey,
        initial: u64,
        max: u64,
    ) -> Result<(), StreamError> {
        let largest = varint::MAX;
        if initial < MIN_INITIAL_STREAM_WINDOW
            || initial > largest
            || max > largest
            || (max != 0 && max < initial)
        {
            return Err(StreamError::InvalidArgument);
        }
        let r = self
            .streams
            .recv_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        r.max_window = if max == 0 { largest } else { max };
        r.initial_window = initial;
        if initial > r.window {
            r.window = initial;
            if r.state == RecvState::Recv
                && r.cold().stopped.is_none()
                && r.read_offset + r.window > r.limit
            {
                self.streams.mark_stream_update(key, true);
                self.streams.queue_ctrl(key);
            }
        }
        Ok(())
    }

    /// The stream's receive window settings: the initial window as set (the
    /// session's, or what `set_receive_window` set it to), never the
    /// window auto-tuning has grown it to, and the cap as set, 0 when it is
    /// automatic.
    pub fn receive_window(&self, key: StreamKey) -> Option<(u64, u64)> {
        let r = self.streams.recv(key)?;
        let cap = if r.automatic_cap() { 0 } else { r.max_window };
        Some((r.initial_window, cap))
    }

    /// The bound of the sending part's written-but-unsent bytes in force:
    /// its own ([`Self::set_send_buffer`]) or the session's.
    pub fn stream_send_buffer(&self, key: StreamKey) -> Option<u64> {
        let send = self.streams.send(key)?;
        Some(send.cold().send_limit.unwrap_or(self.session_send_buffer()))
    }

    /// The priority asked of the peer for the stream's sending part, the
    /// latest request: one still to be sent, the last one sent, or the
    /// PRIORITY TLV of a local stream's preamble. `None`: none asked.
    pub fn asked_peer_priority(&self, key: StreamKey) -> Option<Priority> {
        let s = self.streams.get(key)?;
        s.recv.as_ref()?;
        let e = s.extra();
        e.priority_update
            .or(e.priority_sent.map(|(_, p)| p))
            .or(if s.local { e.peer_priority } else { None })
    }

    /// The stream's runtime settings as it holds them now: the one place
    /// that reads them, for the sending part, the receiving part and a
    /// handle that holds neither. A setting of a part the stream does not
    /// have is the default of [`StreamSettings`]. `None` once the core no
    /// longer holds the stream.
    pub fn stream_settings(&self, key: StreamKey) -> Option<super::StreamSettings> {
        self.streams.get(key)?;
        Some(super::StreamSettings {
            priority: self.priority(key).unwrap_or(Priority::LOCAL_DEFAULT),
            scheduler: self.stream_scheduler(key).ok().flatten(),
            redundant: self.stream_redundant(key).ok().flatten(),
            send_buffer: self.stream_send_buffer(key).unwrap_or_default(),
            receive_window: self.receive_window(key).unwrap_or_default(),
            peer_priority: self.asked_peer_priority(key),
        })
    }

    /// Bounds the stream's written-but-unsent bytes. A write already
    /// waiting for room (the setting does not need the part: a handle sets
    /// it while the part is in a write) takes the new bound: a larger one
    /// wakes it.
    pub fn set_send_buffer(&mut self, key: StreamKey, bytes: u64) -> Result<(), StreamError> {
        let send = self
            .streams
            .send_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        send.cold_mut().send_limit = Some(bytes.max(MIN_STREAM_WINDOW));
        self.wake_send_waiters();
        Ok(())
    }

    // ---- datagrams ---------------------------------------------------------------

    /// The largest session datagram payload the peer accepts, accounting for
    /// the next sequence's encoded width and the session Flow when applicable.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.datagram_payload_limit(self.max_datagram_frame()?, None)
    }

    /// The largest payload of a datagram on this stream for the specified context.
    /// An unpinned stream uses its next possible identifier without claiming it.
    pub fn max_stream_datagram_size(&self, key: StreamKey, context: u64) -> Option<usize> {
        let flow = self.stream_datagram_candidate(key, context).ok()?;
        self.datagram_payload_limit(self.max_datagram_frame()?, Some(flow))
    }

    fn datagram_payload_limit(&self, frame: usize, flow: Option<(u64, u64)>) -> Option<usize> {
        frame.checked_sub(1 + self.next_datagram_prefix(flow)?.encoded_len())
    }

    /// The largest DATAGRAM frame this endpoint may send: the peer's
    /// limits and the largest record of every carrier that may carry it,
    /// whatever this endpoint's own record size. The one bound of both the
    /// sizes reported and the frames written: a frame is a record of its own
    /// at most, written without a Length field when it is last in its record.
    pub(super) fn max_datagram_frame(&self) -> Option<usize> {
        let peer = self.peer_tp.as_ref()?;
        let frame = Some(peer.max_datagram_frame_size()).filter(|&m| m > 0)?;
        let protocol_limit = usize_sat(frame.min(peer.max_record_size()));
        let record = self
            .atts
            .iter()
            .filter(|a| a.out().is_some_and(super::pipes::OutPipe::is_live))
            .filter_map(|a| self.datagram_record_limit(a.id()))
            .max()
            .unwrap_or(protocol_limit);
        let native = self
            .atts
            .iter()
            .filter_map(|a| self.channel_for(a.id()))
            .map(|ch| {
                ch.capacity
                    .saturating_sub(ch.prefix.id().map_or(0, varint::len))
            })
            .max()
            .unwrap_or(0)
            .min(usize_sat(frame));
        Some(record.max(native))
    }

    /// Queues a session datagram (Flow 0 with datagram flows). Never waits.
    /// At capacity, queued originals make room in arrival order. If carrier
    /// outcomes occupy every slot, the new datagram is dropped.
    ///
    /// `allowed` is the send limiter's verdict on it
    /// ([`super::Config::datagram_limiter`]), which the caller asks before
    /// it takes the session's lock (`true` without a limiter): the core
    /// never calls the limiter. A datagram it refused
    /// is dropped and counted (`datagrams_dropped_limit`) once the checks
    /// that fail the call passed. A refused send returns its local drop reason.
    pub fn send_datagram(
        &mut self,
        data: Bytes,
        allowed: bool,
        now: Instant,
    ) -> Result<(), DatagramError> {
        self.send_datagram_with(data, super::DatagramSendOptions::default(), allowed, now)
    }

    /// Queues a session datagram with per-packet settings.
    pub fn send_datagram_with(
        &mut self,
        data: Bytes,
        options: super::DatagramSendOptions,
        allowed: bool,
        now: Instant,
    ) -> Result<(), DatagramError> {
        self.tick(now);
        if let Some(e) = self.lost() {
            return Err(DatagramError::SessionLost(e));
        }
        self.check_datagram_sequence()?;
        let options = options
            .inherit(self.config.datagram_config().defaults)
            .resolve(self.now)?;
        self.check_datagram_deadline(options)?;
        let max = self
            .structural_datagram_frame_limit()
            .and_then(|frame| self.datagram_payload_limit(frame, None))
            .ok_or(DatagramError::NotNegotiated)?;
        if data.len() > max {
            return Err(DatagramError::TooLarge { max });
        }
        self.check_datagram_admission(options, allowed)?;
        self.queue_datagram(self.outgoing_datagram(None, data, options))
    }

    pub(super) fn structural_datagram_frame_limit(&self) -> Option<usize> {
        let peer = self.peer_tp.as_ref()?;
        let mut bytes = peer.max_datagram_frame_size();
        if !self.features.carrier_datagrams {
            let record = self
                .atts
                .iter()
                .filter_map(|attachment| self.datagram_record_limit(attachment.id()))
                .max()
                .map_or_else(|| peer.max_record_size(), |size| size as u64);
            bytes = bytes.min(record);
        }
        (bytes > 0).then(|| usize_sat(bytes))
    }

    pub(crate) fn drop_datagram_admission(&mut self, reason: DatagramDrop) -> DatagramError {
        self.count_datagram_drop(reason, 1);
        DatagramError::Dropped(reason)
    }

    fn check_datagram_deadline(
        &mut self,
        options: ResolvedDatagramOptions,
    ) -> Result<(), DatagramError> {
        if options.deadline.is_some_and(|at| at <= self.now) {
            return Err(self.drop_datagram_admission(DatagramDrop::Deadline));
        }
        Ok(())
    }

    fn check_datagram_admission(
        &mut self,
        options: ResolvedDatagramOptions,
        allowed: bool,
    ) -> Result<(), DatagramError> {
        if options.require_native && !self.features.carrier_datagrams {
            return Err(self.drop_datagram_admission(DatagramDrop::NoNativePath));
        }
        if !allowed {
            return Err(self.drop_datagram_admission(DatagramDrop::Limiter));
        }
        Ok(())
    }

    /// Queues a datagram on a bidirectional stream (Flow = stream ID + 1). A stream without an
    /// identifier is pinned first. `allowed` and the result as for
    /// [`SessionCore::send_datagram`].
    pub fn send_stream_datagram(
        &mut self,
        key: StreamKey,
        context: u64,
        data: Bytes,
        allowed: bool,
        now: Instant,
    ) -> Result<(), DatagramError> {
        self.send_stream_datagram_with(
            key,
            context,
            data,
            super::DatagramSendOptions::default(),
            allowed,
            now,
        )
    }

    /// Sets the default settings of a stream's outbound datagram flow.
    pub fn set_stream_datagram_options(
        &mut self,
        key: StreamKey,
        options: super::DatagramSendOptions,
    ) -> Result<(), DatagramError> {
        options
            .deadline_at(self.now)
            .map_err(DatagramError::InvalidOptions)?;
        let stream = self
            .streams
            .get_mut(key)
            .ok_or(DatagramError::ClosedStream)?;
        stream.datagrams_mut().options = options;
        Ok(())
    }

    /// Effective per-packet settings on this flow.
    pub(crate) fn stream_datagram_options(
        &self,
        key: StreamKey,
        options: super::DatagramSendOptions,
    ) -> super::DatagramSendOptions {
        options
            .inherit(
                self.streams
                    .get(key)
                    .and_then(|s| s.datagrams.as_deref())
                    .map_or_else(super::DatagramSendOptions::default, |d| d.options),
            )
            .inherit(self.config.datagram_config().defaults)
    }

    /// Queues a stream datagram with per-packet settings.
    pub fn send_stream_datagram_with(
        &mut self,
        key: StreamKey,
        context: u64,
        data: Bytes,
        options: super::DatagramSendOptions,
        allowed: bool,
        now: Instant,
    ) -> Result<(), DatagramError> {
        match self.admit_stream_packet(
            (key, context),
            data,
            options,
            SendPolicy::DatagramOnly,
            allowed,
            now,
        )? {
            PacketAdmission::Datagram => Ok(()),
            PacketAdmission::Capsule { data, deadline } => {
                unreachable!(
                    "datagram-only policy for {} bytes at {deadline:?}",
                    data.len()
                )
            }
        }
    }

    /// Selects the packet's representation and admits a datagram in the same owner turn.
    pub(crate) fn admit_stream_packet(
        &mut self,
        flow: (StreamKey, u64),
        data: Bytes,
        options: DatagramSendOptions,
        policy: SendPolicy,
        allowed: bool,
        now: Instant,
    ) -> Result<PacketAdmission, DatagramError> {
        let (options, representation) =
            self.prepare_stream_packet(flow, data.len(), options, policy, now)?;
        match representation {
            PacketRepresentation::Capsule => Ok(PacketAdmission::Capsule {
                data,
                deadline: options.deadline,
            }),
            PacketRepresentation::Datagram { stream_id, context } => {
                self.queue_stream_packet(flow.0, (stream_id, context), data, options, allowed)?;
                Ok(PacketAdmission::Datagram)
            }
        }
    }

    pub(crate) fn prepare_stream_packet(
        &mut self,
        flow: (StreamKey, u64),
        largest: usize,
        options: DatagramSendOptions,
        policy: SendPolicy,
        now: Instant,
    ) -> Result<(ResolvedDatagramOptions, PacketRepresentation), DatagramError> {
        self.tick(now);
        let options = self
            .stream_datagram_options(flow.0, options)
            .resolve(self.now)?;
        let candidate = self.stream_packet_representation(flow, largest, options, policy)?;
        Ok((options, candidate))
    }

    /// The authoritative representation choice for a single packet or group.
    pub(crate) fn stream_packet_representation(
        &mut self,
        (key, context): (StreamKey, u64),
        largest: usize,
        options: ResolvedDatagramOptions,
        policy: SendPolicy,
    ) -> Result<PacketRepresentation, DatagramError> {
        if let Some(e) = self.lost() {
            return Err(DatagramError::SessionLost(e));
        }
        if policy == SendPolicy::StreamOnly && options.require_native {
            return Err(DatagramError::InvalidOptions(crate::InvalidConfig::new(
                "packet_policy",
                "a capsule-only stream cannot require native datagrams",
            )));
        }
        if context > varint::MAX {
            return Err(DatagramError::InvalidOptions(crate::InvalidConfig::new(
                "datagram_context",
                "above 2^62 - 1",
            )));
        }
        if !self
            .streams
            .get(key)
            .is_some_and(Self::stream_can_send_datagrams)
        {
            return Err(DatagramError::ClosedStream);
        }
        self.check_datagram_deadline(options)?;
        if policy == SendPolicy::StreamOnly {
            return Ok(PacketRepresentation::Capsule);
        }
        let fallback = policy == SendPolicy::PreferDatagram && !options.require_native;
        let frame = self
            .structural_datagram_frame_limit()
            .filter(|_| self.features.same_family);
        let Some(frame) = frame else {
            return if fallback && self.peer_tp.is_some() {
                Ok(PacketRepresentation::Capsule)
            } else {
                Err(DatagramError::NotNegotiated)
            };
        };
        self.check_datagram_sequence()?;
        let candidate = self.stream_datagram_candidate(key, context)?;
        let max = self.datagram_payload_limit(frame, Some(candidate));
        if max.is_none_or(|max| largest > max) {
            return if fallback {
                Ok(PacketRepresentation::Capsule)
            } else {
                Err(DatagramError::TooLarge {
                    max: max.unwrap_or(0),
                })
            };
        }
        if options.require_native && !self.features.carrier_datagrams {
            return Err(self.drop_datagram_admission(DatagramDrop::NoNativePath));
        }
        let (stream_id, context) = candidate;
        Ok(PacketRepresentation::Datagram { stream_id, context })
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn commit_stream_packet(
        &mut self,
        key: StreamKey,
        context: u64,
        data: Bytes,
        options: ResolvedDatagramOptions,
        allowed: bool,
    ) -> Result<(), DatagramError> {
        let PacketRepresentation::Datagram { stream_id, context } = self
            .stream_packet_representation(
                (key, context),
                data.len(),
                options,
                SendPolicy::DatagramOnly,
            )?
        else {
            unreachable!("datagram-only policy selected a capsule")
        };
        self.queue_stream_packet(key, (stream_id, context), data, options, allowed)
    }

    fn queue_stream_packet(
        &mut self,
        key: StreamKey,
        candidate: (u64, u64),
        data: Bytes,
        options: ResolvedDatagramOptions,
        allowed: bool,
    ) -> Result<(), DatagramError> {
        if !allowed {
            return Err(self.drop_datagram_admission(DatagramDrop::Limiter));
        }
        let id = self.stream_id(key).map_err(|e| match e {
            StreamError::Blocked => DatagramError::Blocked,
            _ => DatagramError::ClosedStream,
        })?;
        debug_assert_eq!(candidate.0, id);
        self.queue_datagram(self.outgoing_datagram(Some(candidate), data, options))
    }

    /// Checks stream and Flow/Context admissibility without assigning a stream ID.
    pub(super) fn stream_datagram_candidate(
        &self,
        key: StreamKey,
        context: u64,
    ) -> Result<(u64, u64), DatagramError> {
        if !self.features.same_family {
            return Err(DatagramError::NotNegotiated);
        }
        let stream = self.streams.get(key).ok_or(DatagramError::ClosedStream)?;
        if !Self::stream_can_send_datagrams(stream) || context > varint::MAX {
            return Err(DatagramError::ClosedStream);
        }
        let id = stream.id.unwrap_or_else(|| {
            let client = matches!(self.role, super::Role::Client);
            super::stream::make_id(
                self.streams.local_dir(di(stream.dir)).next_index,
                stream.dir,
                client,
            )
        });
        Ok((id, context))
    }

    fn stream_can_send_datagrams(stream: &Stream) -> bool {
        stream.dir == Dir::Bidi
            && !stream.send_released
            && !stream.parts_terminal()
            && stream.goaway.is_none()
    }

    pub(super) fn datagram_flow_open(&self, flow: Option<(u64, u64)>) -> bool {
        flow.is_none_or(|(id, _)| {
            self.streams
                .key_of(id)
                .and_then(|key| self.streams.get(key))
                .is_some_and(Self::stream_can_send_datagrams)
        })
    }

    fn queue_datagram(&mut self, packet: super::OutDatagram) -> Result<(), DatagramError> {
        let turn = self.streams.next_send_turn();
        let dgram = self.dgram.get_or_insert_with(Box::default);
        let (accepted, dropped) = dgram.send.queue(packet, &self.config, turn);
        self.count_datagram_drop(DatagramDrop::QueueOverflow, dropped);
        self.constrain_native_flows();
        self.prepare_datagram_dispatch();
        self.channel_kick();
        if accepted {
            Ok(())
        } else {
            Err(DatagramError::Dropped(DatagramDrop::QueueOverflow))
        }
    }

    /// Removes the queued datagram `i`, which leaves the send queue; the
    /// queue's delay bound ends when it empties.
    pub(super) fn take_send_datagram(&mut self, i: usize) -> Option<OutDatagram> {
        let send_queue = self.config.datagram_send_queue;
        if let Some(pipe) = self
            .dgram()
            .send
            .get(i)
            .and_then(|p| self.reserved_native_pipe(p.tag))
        {
            self.clear_native_plan(pipe);
        }
        let turn = self.streams.next_send_turn();
        let d = self.dgram_mut();
        let was_full = d.send.occupied() >= send_queue;
        let o = d.send.take(i, turn)?;
        if was_full && d.send.occupied() < send_queue {
            self.events.push_back(CoreEvent::DatagramsUnblocked);
        }
        Some(o)
    }

    /// Decides on the queued datagram `i`, about to leave the send queue
    /// ([`super::Config::datagram_queue_delay`]): `true` drops it, removed
    /// and counted.
    pub(super) fn send_delay_drop(&mut self, i: usize) -> bool {
        let (target, now) = (self.config.datagram_queue_delay, self.now);
        let d = self.dgram_mut();
        if !d.send.delayed(i, now, target) {
            return false;
        }
        let _ = self.take_send_datagram(i);
        self.count_datagram_drop(DatagramDrop::Codel, 1);
        true
    }

    /// Whether the datagram send queue is full (a waiting sender waits for
    /// [`CoreEvent::DatagramsUnblocked`]).
    pub fn datagram_queue_full(&self) -> bool {
        self.dgram().send.occupied() >= self.config.datagram_send_queue
    }

    /// Whether received datagrams are held for the receive limiter
    /// ([`super::ReceivedDatagram`]).
    pub fn has_received_datagrams(&self) -> bool {
        !self.dgram().held.is_empty()
    }

    /// Moves the received datagrams held for the receive limiter to the
    /// end of `into`, oldest first ([`super::ReceivedDatagram`]).
    pub fn take_received_datagrams(&mut self, into: &mut Vec<super::ReceivedDatagram>) {
        // Their bytes stay counted until they are handed back.
        if let Some(d) = self.dgram.as_deref_mut() {
            into.extend(d.held.drain(..));
        }
    }

    /// Takes back the datagrams of [`SessionCore::take_received_datagrams`]
    /// with the limiter's verdicts, emptying `datagrams`: those it allowed
    /// go to the application's queues (a stream that ended or was released
    /// meanwhile drops its own), the others are dropped and counted
    /// (`datagrams_dropped_limit`). Returns the grants of the allowed ones
    /// the queues refused, for the driver to refund outside the lock.
    #[must_use = "the grants of refused datagrams are refunded"]
    pub fn admit_datagrams(&mut self, datagrams: &mut Vec<super::ReceivedDatagram>) -> u64 {
        let mut refused = 0;
        for d in datagrams.drain(..) {
            super::debit(&mut self.dgram_mut().held_bytes, d.data.len());
            let Some(granted) = d.granted else {
                self.dgram_mut().counters.dropped_limit += 1;
                self.occupy_datagram(d.sequence, false);
                continue;
            };
            let usable = d
                .stream
                .is_none_or(|(k, _)| self.streams.get(k).is_some_and(Stream::takes_datagrams));
            if !usable {
                refused += granted;
                self.drop_received_datagram(d.stream);
                self.occupy_datagram(d.sequence, false);
            } else if !self.queue_received_datagram(d.stream, d.data) {
                self.occupy_datagram(d.sequence, false);
                // The queue refused it: its grant goes back too.
                refused += granted;
            }
        }
        refused
    }

    /// The next session datagram at `now`. Datagrams queued longer than
    /// [`super::Config::datagram_queue_delay`] allows are dropped on the
    /// way (CoDel), counted.
    pub fn recv_datagram(&mut self, now: Instant) -> Result<Option<Bytes>, SessionError> {
        self.tick(now);
        let (target, now) = (self.config.datagram_queue_delay, self.now);
        let mut dropped = 0;
        let mut next = None;
        if let Some(d) = self.dgram.as_deref_mut() {
            while let Some((data, at)) = d.recv.pop_front() {
                if d.recv_codel.drop(at, now, target, d.recv.is_empty()) {
                    super::debit(&mut d.recv_bytes, data.len());
                    dropped += 1;
                    continue;
                }
                next = Some(data);
                break;
            }
            if d.recv.is_empty() {
                d.recv_codel.idle();
            }
        }
        if dropped > 0 {
            self.count_dropped(dropped);
        }
        match next {
            Some(d) => {
                super::debit(&mut self.dgram_mut().recv_bytes, d.len());
                self.meter.add(Count::DatagramReceived, d.len() as u64);
                Ok(Some(d))
            }
            None => self.lost().map_or(Ok(None), Err),
        }
    }

    /// The next datagram of a stream at `now`, with its context. Datagrams
    /// queued longer than [`super::Config::datagram_queue_delay`] allows
    /// are dropped on the way (CoDel), counted.
    pub fn recv_stream_datagram(
        &mut self,
        key: StreamKey,
        now: Instant,
    ) -> Result<Option<(u64, Bytes)>, StreamError> {
        if !self.stream_datagram_head(key, now)? {
            return Ok(None);
        }
        let packet = self.take_stream_datagram(key);
        Ok(Some((packet.context, packet.data.into_bytes())))
    }

    fn stream_datagram_head(&mut self, key: StreamKey, now: Instant) -> Result<bool, StreamError> {
        self.tick(now);
        let (target, now) = (self.config.datagram_queue_delay, self.now);
        self.expire_stream_datagrams(now);
        let s = self
            .streams
            .get_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        let mut dropped = 0;
        let mut capacity = 0;
        let mut refresh_expiry = false;
        let mut ready = false;
        if let Some(q) = s.datagrams.as_mut() {
            while q
                .queue
                .front()
                .is_some_and(|head| q.codel.drop(head.at, now, target, q.queue.len() == 1))
            {
                let head = q.queue.pop_front().expect("queued datagram");
                super::debit(&mut q.bytes, head.data.len());
                capacity += head.data.backing_capacity();
                refresh_expiry |= head.expires.is_some();
                dropped += 1;
            }
            ready = !q.queue.is_empty();
            if !ready {
                q.codel.idle();
            }
            q.counts.dropped_recv += dropped;
        }
        if dropped > 0 {
            super::debit(&mut self.dgram_mut().stream_bytes, capacity);
            self.count_dropped(dropped);
        }
        if refresh_expiry {
            self.refresh_stream_datagram_expiry(key);
        }
        if ready {
            Ok(true)
        } else {
            self.lost()
                .map_or(Ok(false), |error| Err(StreamError::SessionLost(error)))
        }
    }

    fn take_stream_datagram(&mut self, key: StreamKey) -> super::stream::QueuedStreamDatagram {
        let stream = self.streams.get_mut(key).expect("ready datagram stream");
        let queue = stream.datagrams_mut();
        let packet = queue.queue.pop_front().expect("ready datagram");
        let len = packet.data.len();
        queue.counts.bytes_received += len as u64;
        super::debit(&mut queue.bytes, len);
        if queue.queue.is_empty() {
            queue.codel.idle();
        }
        stream.count(Count::DatagramReceived, len as u64);
        super::debit(
            &mut self.dgram_mut().stream_bytes,
            packet.data.backing_capacity(),
        );
        self.meter.add(Count::DatagramReceived, len as u64);
        if packet.expires.is_some() {
            self.refresh_stream_datagram_expiry(key);
        }
        packet
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn read_splice_datagram(
        &mut self,
        key: StreamKey,
        now: Instant,
        max: usize,
        fits_root: impl FnOnce(super::Backing) -> bool,
        fits_copy: impl FnOnce(usize) -> bool,
    ) -> Result<Option<super::SpliceDatagram>, StreamError> {
        if !self.stream_datagram_head(key, now)? {
            return Ok(None);
        }
        let queue = self
            .streams
            .get(key)
            .and_then(|stream| stream.datagrams.as_ref())
            .expect("checked by stream_datagram_head");
        let head = queue.queue.front().expect("ready datagram");
        let len = head.data.len();
        if len > max {
            self.take_stream_datagram(key);
            return Ok(Some(super::SpliceDatagram::TooLarge));
        }
        let backing = head.data.backing;
        let (data, copied) = if len == 0 {
            (super::Chunk::new(), false)
        } else {
            let loan = self.read_loans.get_or_init(Arc::default).acquire(backing);
            if let Some(loan) = loan
                && fits_root(backing)
            {
                let packet = self.take_stream_datagram(key);
                let chunk = super::Chunk::backed(loan.attach(packet.data.bytes), backing);
                return Ok(Some(super::SpliceDatagram::Data {
                    context: packet.context,
                    data: chunk,
                    remaining: packet
                        .expires
                        .map(|expires| expires.saturating_duration_since(self.now)),
                    copied: false,
                }));
            }
            if !fits_copy(len) {
                return Err(StreamError::BorrowLimit);
            }
            let copy = super::Chunk::copy_from_slice(&head.data);
            (copy, true)
        };
        let packet = self.take_stream_datagram(key);
        Ok(Some(super::SpliceDatagram::Data {
            context: packet.context,
            data,
            remaining: packet
                .expires
                .map(|expires| expires.saturating_duration_since(self.now)),
            copied,
        }))
    }

    #[cfg(all(feature = "test-hooks", feature = "tokio", not(loom)))]
    pub(crate) fn fixture_splice_receive_datagram(
        &mut self,
        stream: u64,
        context: u64,
        data: super::Chunk,
        expires: Option<Instant>,
    ) -> bool {
        let Some(key) = self.streams.key_of(stream) else {
            return false;
        };
        self.queue_stream_datagram(key, context, data, expires)
    }

    #[cfg(all(feature = "test-hooks", feature = "tokio", not(loom)))]
    pub(crate) fn fixture_splice_receive_state(&self, stream: u64) -> Option<(usize, usize, u64)> {
        let queue = self
            .streams
            .get(self.streams.key_of(stream)?)?
            .datagrams
            .as_ref()?;
        Some((
            queue.queue.len(),
            self.dgram().stream_bytes,
            queue.counts.expired_recv,
        ))
    }

    /// Raises the number of bidirectional and of unidirectional streams the
    /// peer may have open to `bidi` and `uni`, sending the credit as
    /// `MAX_STREAMS`. The credit only grows: a value at
    /// or below the current one leaves that type as it is, so 0 raises
    /// nothing. While unidirectional credit is staged, `uni` raises the
    /// value the first accept moves it to. After a GOAWAY no credit is
    /// sent. A value above [`MAX_STREAM_CREDIT`](crate::MAX_STREAM_CREDIT)
    /// (2^60) or beyond the available memory budget is refused atomically.
    pub fn raise_incoming_streams(
        &mut self,
        bidi: u64,
        uni: u64,
    ) -> Result<(), crate::InvalidConfig> {
        use super::config::MAX_STREAM_CREDIT;
        if bidi > MAX_STREAM_CREDIT || uni > MAX_STREAM_CREDIT {
            return Err(crate::InvalidConfig::new(
                "raise_incoming_streams",
                "a limit above MAX_STREAM_CREDIT (2^60)",
            ));
        }
        if self.goaway().sent.is_some() || self.lost().is_some() {
            return Ok(());
        }
        let bidi_dir = di(Dir::Bidi);
        let uni_dir = di(Dir::Uni);
        let requested = [(bidi_dir, bidi), (uni_dir, uni)].map(|(d, n)| {
            if n > self.streams.remote_dir(d).target {
                n
            } else {
                0
            }
        });
        if !self.reserve_peer_directions(requested) {
            return Err(crate::InvalidConfig::new(
                "memory_budget",
                "cannot reserve more incoming stream directions",
            ));
        }
        self.streams.raise_remote(bidi_dir, bidi);
        self.streams.raise_remote(uni_dir, uni);
        Ok(())
    }

    // ---- liveness ----------------------------------------------------------------

    /// Sends a `QX_PING` request, or joins the one outstanding, with every peer, plain QMux peers
    /// included. The response updates the RTT estimate. Returns the
    /// request's ticket for [`SessionCore::ping_rtt`]. Until the ticket is
    /// answered, a request that stops being outstanding without its
    /// response (its timeout, or the loss of its pipe) is sent again.
    pub fn ping(&mut self) -> Result<u64, SessionError> {
        if let Some(e) = self.lost() {
            return Err(e);
        }
        if self.ping.outstanding.is_none() {
            self.ping.request_pending = true;
        }
        let ticket = self.ping.answered + 1;
        self.ping.wanted = self.ping.wanted.max(ticket);
        Ok(ticket)
    }

    /// The RTT measured by the request of a [`SessionCore::ping`] ticket, once
    /// its response arrived (or a later one's, which was sent after it).
    pub fn ping_rtt(&self, ticket: u64) -> Option<Duration> {
        if self.ping.answered >= ticket {
            self.ping.latest
        } else {
            None
        }
    }
}

fn s_id(s: &SessionCore, key: StreamKey) -> Result<u64, StreamError> {
    s.streams
        .get(key)
        .and_then(|s| s.id)
        .ok_or(StreamError::ClosedLocally)
}

/// The write error for a peer's `STOP_SENDING` code.
fn stopped_error(code: u64) -> StreamError {
    if code == ApplicationErrorCode::ZMUX_REJECTED.0 {
        StreamError::Rejected
    } else {
        StreamError::Stopped(super::varint(code))
    }
}

/// The read error for a peer's reset: its code and the Reliable Size in
/// application bytes.
fn reset_error(code: u64, reliable_app: u64) -> StreamError {
    if code == ApplicationErrorCode::ZMUX_REJECTED.0 {
        StreamError::Rejected
    } else {
        StreamError::Reset {
            code: super::varint(code),
            reliable_size: reliable_app,
        }
    }
}
