//! Application commands: opening and accepting streams, reading and
//! writing, termination, priorities, datagrams and pings.

use std::time::Duration;

use bytes::Bytes;

use super::recv_buf::RecvBuf;

use super::stream::{
    GoAwayFail, LocalReset, Offer, RECV_KEEP, RecvState, SendOutcome, SendPart, SendState, Stream,
    StreamKey,
};
use super::streams::Stopped;
use super::{
    DatagramError, OpenError, SEND_DATAGRAM_QUEUE, SessionCore, SessionError, StreamError, di,
    dir_of_index,
};
use crate::proto::frame::{Dir, Priority};
use crate::proto::meter::Count;
use crate::proto::payload::{AppTlvs, GreaseTlv, WirePreamble};
use crate::proto::{ApplicationErrorCode, VarInt, varint};

/// Smallest per-stream window or send buffer.
const MIN_STREAM_WINDOW: u64 = 16 * 1024;

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
    /// at the peer's zmux endpoint, not its application (SPEC.md Section
    /// 7.4).
    Finished,
    /// The peer sent STOP_SENDING with this code.
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
    pub fn reaches(&self, min: u64) -> bool {
        self.capacity >= min.max(1) || (self.capacity > 0 && self.unsent == 0)
    }
}

impl SessionCore {
    // ---- opening and accepting ------------------------------------------------

    /// Opens a stream of a type. Opening reserves stream-count credit, so
    /// the stream's identifier is always below the peer's limit; nothing is
    /// sent until the first write or [`SessionCore::stream_id`] (SPEC.md Section
    /// 7.2). Fails with [`OpenError::Blocked`] without credit; the driver
    /// waits for [`super::CoreEvent::StreamsAvailable`] and tries again. Before
    /// establishment the peer's limits are unknown: the stream is created
    /// and its data waits for the peer's parameters (and for credit).
    pub fn open(&mut self, dir: Dir) -> Result<StreamKey, OpenError> {
        if let Some(e) = self.lost() {
            return Err(OpenError::SessionLost(e));
        }
        // After any GOAWAY from the peer no new stream opens, whatever the
        // watermarks (EXTENSIONS.md Section 3.5).
        if self.goaway().shutdown.is_some() || self.streams.goaway_received() {
            return Err(OpenError::GoingAway);
        }
        let established = self.is_established();
        let d = di(dir);
        if !self.streams.reserve_local(d, established) {
            return Err(OpenError::Blocked);
        }
        let peer = self.send_tp();
        let mut s = Stream::new(dir, true);
        match dir {
            Dir::Bidi => {
                let send = peer.map_or(0, |p| p.window_bidi_remote);
                s.send = Some(self.streams.new_send_part(send));
                let window = self.local_tp().window_bidi_local;
                let mut recv = self
                    .streams
                    .new_recv_part(window, self.config.stream_window_cap());
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
    /// none is ready (wait for [`super::CoreEvent::StreamOpened`]).
    pub fn accept(&mut self, dir: Dir) -> Result<Option<StreamKey>, SessionError> {
        if let Some(e) = self.lost() {
            return Err(e);
        }
        let d = di(dir);
        // Staged unidirectional credit: 256 on the first accept, unless a
        // GOAWAY was sent (SPEC.md Section 8.5 rule 4).
        if self.streams.remote_dir(d).staged {
            let grant = !self.goaway_announced();
            self.streams.unstage(d, grant);
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
            let base = r.preamble_size.unwrap_or(0);
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
    /// nothing is available (wait for [`super::CoreEvent::StreamReadable`]), or
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
    /// allows, before any later stream of the type (SPEC.md Section 7.2).
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
            // Unemitted and unpinned when the GOAWAY arrived (EXTENSIONS.md
            // Section 3.5 rule 2).
            self.unschedule(key);
            self.reject_unopened(key, GoAwayFail::GoingAway);
            return Err(StreamError::GoingAway);
        }
        if ld.next_index >= ld.peer_max {
            // Opened before establishment beyond the peer's limit.
            return Err(StreamError::Blocked);
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

    /// Registers for [`super::CoreEvent::StreamWritable`] once a wait for
    /// `min` bytes of send capacity is over ([`SendCapacity::reaches`]), or
    /// the part ended. The part is woken only then, not on every change of
    /// credit, so that a caller that wants a chunk's worth costs one
    /// wake-up per chunk. A later registration
    /// replaces `min`; one that is over already notifies at once.
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
    /// count; 0 means wait for [`super::CoreEvent::StreamWritable`].
    pub fn write(&mut self, key: StreamKey, data: &[u8]) -> Result<usize, StreamError> {
        let room = self.write_room(key)?;
        let n = (room.min(data.len() as u64)) as usize;
        if n == 0 {
            if !data.is_empty() {
                self.wait_writable(key);
            }
            return Ok(0);
        }
        self.streams
            .write_slice(key, &data[..n])
            .expect("checked by write_room");
        self.wrote(key, n, n < data.len());
        Ok(n)
    }

    /// Writes a chunk without copying it. Returns the bytes taken: all of
    /// `data`, a prefix when the buffers are nearly full, or 0.
    pub fn write_chunk(&mut self, key: StreamKey, data: Bytes) -> Result<usize, StreamError> {
        let room = self.write_room(key)?;
        let n = (room.min(data.len() as u64)) as usize;
        if n == 0 {
            if !data.is_empty() {
                self.wait_writable(key);
            }
            return Ok(0);
        }
        let data_len = data.len();
        let chunk = if n == data.len() {
            data
        } else {
            data.slice(..n)
        };
        self.streams
            .write_bytes(key, chunk)
            .expect("checked by write_room");
        let partial = n < data_len;
        self.wrote(key, n, partial);
        Ok(n)
    }

    /// Whether every byte written to the sending part has been passed to a
    /// carrier (none is unsent); if not, registers for
    /// [`super::CoreEvent::StreamWritable`] once that is so or the part ends.
    pub fn data_sent(&mut self, key: StreamKey) -> Result<bool, StreamError> {
        if self.writable_part(key)?.buf.is_empty() {
            return Ok(true);
        }
        self.send_part(key).sent_waiting = true;
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
    }

    /// Registers a writer that waits for room; it is woken once
    /// [`SessionCore::send_room`] is positive again.
    fn wait_writable(&mut self, key: StreamKey) {
        self.mark_write(key, 0, true);
        self.streams.add_send_waiter(key);
        self.sync_holder(key);
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
    /// delivered (RESET_STREAM_AT, SPEC.md Section 4.3); a stream that has
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
        if self.lost().is_some() {
            return Ok(());
        }
        self.local_reset(key, code.into_inner());
        Ok(())
    }

    /// Marks the data written so far as reliable: a later reset still
    /// delivers it.
    pub fn set_reliable_boundary(&mut self, key: StreamKey) -> Result<(), StreamError> {
        let send = self
            .streams
            .send_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        if send.outcome.is_some() {
            return Err(StreamError::ClosedLocally);
        }
        send.cold_mut().reliable_boundary = Some(send.written);
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
            // Nothing was sent: no identifier is consumed (SPEC.md 7.2).
            let unsent = send.buf.len();
            send.buf.clear();
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
                // The peer never heard of the stream: nothing will arrive.
                r.state = RecvState::ResetRead;
            }
            self.streams.drop_unsent(unsent);
            let d = di(dir);
            if self.streams.unreserve_local(d) {
                self.push_event(super::CoreEvent::StreamsAvailable(dir_of_index(d)));
            }
            self.unschedule(key);
            self.wake_send_waiters();
            self.notify_writable(key);
            self.notify_readable(key);
            self.try_discard(key);
            return;
        }
        // Keep the preamble reliable on streams this endpoint opened, unless
        // the peer asked to stop (EXTENSIONS.md Section 4.5); keep the data
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

    /// Answers the peer's STOP_SENDING with a reset carrying its code; the
    /// reset keeps nothing reliable (SPEC.md Section 4.3).
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
        if let Some(mp) = self.mp.as_deref_mut() {
            mp.release(freed);
        }
        send.state = SendState::ResetSent;
        self.streams.drop_unsent(unsent);
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
            if let Some(e) = lost
                && r.final_size.is_none()
                && r.cold().reset.is_none()
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
                let base = r.preamble_size.unwrap_or(0);
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
    /// [`super::CoreEvent::StreamReadable`]). Data below a peer's Reliable Size
    /// is read before the reset is reported.
    pub fn read(
        &mut self,
        key: StreamKey,
        buf: &mut [u8],
    ) -> Result<Option<(usize, bool)>, StreamError> {
        self.read_with(key, buf.len(), |src, n| (src.copy_to(&mut buf[..n]), ()))
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
        self.read_with(key, max, |src, n| (src.append_to(out, n), ()))
            .map(|r| r.map(|(n, fin, ())| (n, fin)))
    }

    /// Reads up to `max` bytes as one chunk without copying: a piece of the
    /// received data (the data may be held in several pieces; a chunk ends
    /// with its piece). Same results as [`SessionCore::read`].
    pub fn read_chunk(
        &mut self,
        key: StreamKey,
        max: usize,
    ) -> Result<Option<(Bytes, bool)>, StreamError> {
        self.read_with(key, max, |src, n| {
            let b = src.take(n);
            (b.len(), b)
        })
        .map(|r| r.map(|(_, fin, b)| (b, fin)))
    }

    fn read_with<T: Default>(
        &mut self,
        key: StreamKey,
        max: usize,
        take: impl FnOnce(&mut RecvBuf, usize) -> (usize, T),
    ) -> Result<Option<(usize, bool, T)>, StreamError> {
        let n = match self.readable(key) {
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
        let (s, spare) = self
            .streams
            .stream_and_spare(key)
            .expect("checked by readable");
        let r = s.recv.as_mut().expect("checked by readable");
        let (n, out) = take(&mut r.buf, n);
        if r.buf.is_empty() && r.buf.storage_capacity() > RECV_KEEP {
            // An emptied large buffer is not kept by an idle stream.
            spare.put_drained(std::mem::take(&mut r.buf).into_storage());
        }
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

    /// Stops reading: STOP_SENDING with `code`, and unread data is
    /// discarded.
    pub fn stop(&mut self, key: StreamKey, code: VarInt) -> Result<(), StreamError> {
        let s = self.streams.get(key).ok_or(StreamError::ClosedLocally)?;
        if s.recv.is_none() {
            return Err(StreamError::ClosedLocally);
        }
        self.local_stop(key, code.into_inner());
        Ok(())
    }

    /// STOP_SENDING on the local receiving part (application stop, release
    /// or rejection). Data still buffered is discarded and counts as
    /// consumed.
    pub(super) fn local_stop(&mut self, key: StreamKey, code: u64) {
        let Some(Stopped {
            local,
            dropped,
            stop_pending,
        }) = self.streams.stop_recv(key, code)
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
    /// it: an unfinished sending part is reset and an unread receiving part
    /// stopped, both with code 0 (EXTENSIONS.md Section 7.4). The stream's
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
            self.local_reset(key, 0);
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

    /// Declines an accepted stream before reading it: STOP_SENDING with
    /// ZMUX_REJECTED, and RESET_STREAM with ZMUX_REJECTED on a sending
    /// part not written to (EXTENSIONS.md Section 7.2). Releases the
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
        self.mark_released(key);
        Ok(())
    }

    // ---- priorities and metadata -------------------------------------------------

    /// Sets the session's default scheduling policy.
    pub fn set_scheduler(&mut self, policy: super::Policy) {
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

    /// Sets the scheduling policy of a stream's sending part; `None` uses
    /// the session default.
    pub fn set_stream_scheduler(
        &mut self,
        key: StreamKey,
        policy: Option<super::Policy>,
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

    /// Turns redundancy on or off for the stream's sending part: copies of
    /// its chunks on a second pipe of the tier, within the session's copy
    /// bound. Until called,
    /// the part follows the session's `redundancy` parameter.
    pub fn set_redundant(&mut self, key: StreamKey, on: bool) -> Result<(), StreamError> {
        let send = self
            .streams
            .send_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        send.mp_mut().redundant = Some(on);
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
    /// first frame, PRIORITY_UPDATE otherwise (EXTENSIONS.md Section 5).
    pub fn set_peer_priority(
        &mut self,
        key: StreamKey,
        priority: Priority,
    ) -> Result<(), StreamError> {
        let preamble = self.features.preamble;
        // Before the peer's parameters only the preamble's PRIORITY TLV of
        // an early stream can carry the request (SPEC.md Section 6.1.2).
        let early = self.early_open();
        if !self.features.priority && !(early && preamble) {
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

    /// Opens a stream of type `dir` with `preamble` (EXTENSIONS.md Section
    /// 4): [`SessionCore::open`] when it is empty. The preamble must fit the
    /// peer's Maximum Preamble Size and one of our records, with room for a
    /// PRIORITY TLV set later ([`OpenError::TooLarge`]), and needs the
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
        // Early streams carry their preamble within the assumed set
        // (SPEC.md Section 6.1.2).
        if !self.is_established() && !self.early_open() {
            return Err(OpenError::NotEstablished);
        }
        if !self.features.preamble {
            return Err(OpenError::NotNegotiated);
        }
        preamble.check(dir)?;
        let (info, tlvs, carrier) = preamble.parts();
        // Within the peer's limit, and whole in one of our records.
        let limit = self
            .send_tp()
            .map_or(0, |t| t.preamble())
            .min((self.max_record() - 25) as u64);
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
            priority: Some(Priority::DEFAULT),
            pipe_carrier: carrier,
            app_tlvs: AppTlvs::new(tlvs.as_deref().unwrap_or_default()),
        }
        .encoded_len(
            grease
                .as_ref()
                .map(|(ty, v)| GreaseTlv { ty: *ty, value: v }),
        );
        if len as u64 > limit {
            return Err(OpenError::TooLarge);
        }
        let key = self.open(dir)?;
        let s = self.streams.get_mut(key).expect("just opened");
        let e = s.extra_mut();
        (e.open_info, e.app_tlvs, e.pipe_carrier) = (info, tlvs, carrier);
        Ok(key)
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
    pub fn requested_priority(&self, key: StreamKey) -> Option<Priority> {
        let s = self.streams.get(key)?;
        if s.local {
            None
        } else {
            s.extra().peer_priority
        }
    }

    /// Sets the stream's receive window: `initial` is advertised at once,
    /// `max` caps auto-tuning.
    pub fn set_receive_window(
        &mut self,
        key: StreamKey,
        initial: u64,
        max: u64,
    ) -> Result<(), StreamError> {
        let cap = self.config.session_window_cap();
        let r = self
            .streams
            .recv_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        let initial = initial.max(MIN_STREAM_WINDOW).min(cap);
        r.max_window = max.max(initial).min(cap);
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

    /// Bounds the stream's written-but-unsent bytes.
    pub fn set_send_buffer(&mut self, key: StreamKey, bytes: u64) -> Result<(), StreamError> {
        let send = self
            .streams
            .send_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        send.cold_mut().send_limit = Some(bytes.max(MIN_STREAM_WINDOW));
        Ok(())
    }

    // ---- datagrams ---------------------------------------------------------------

    /// The largest session datagram payload the peer accepts, or `None`
    /// when it accepts none (EXTENSIONS.md Section 6.6): the smaller of the
    /// peer's `max_datagram_frame_size` and `max_record_size`, minus the
    /// frame type and, with datagram flows, Flow 0. 65533 with datagram
    /// flows and 65534 without for a zmux peer, 16381 for a plain QMux peer
    /// at the default record size; a datagram too large to share a record
    /// goes last in a record or in one of its own. Applications that carry
    /// packets use it as their MTU.
    pub fn max_datagram_size(&self) -> Option<usize> {
        let prefix = usize::from(self.features.datagram_flows);
        self.max_datagram_frame()
            .map(|max| max.saturating_sub(1 + prefix))
    }

    /// The largest payload of a datagram on stream `key` with Context ID
    /// `context` (EXTENSIONS.md Section 6.6): the session's limit less the
    /// stream's Flow and Context ID. Before the stream has an identifier
    /// its Flow counts as the longest one. `None` without datagram flows.
    pub fn max_stream_datagram_size(&self, key: StreamKey, context: u64) -> Option<usize> {
        if !self.features.datagram_flows {
            return None;
        }
        let flow = self
            .streams
            .get(key)?
            .id
            .map_or(8, |id| varint::len(id + 1));
        self.max_datagram_frame()
            .map(|max| max.saturating_sub(1 + flow + varint::len(context)))
    }

    /// The largest DATAGRAM frame this endpoint may send: the peer's
    /// limits, whatever this endpoint's own record size.
    pub(super) fn max_datagram_frame(&self) -> Option<usize> {
        let peer = self.peer_tp.as_ref()?;
        let frame = Some(peer.max_datagram_frame_size()).filter(|&m| m > 0)?;
        Some(frame.min(peer.max_record_size()) as usize)
    }

    /// Queues a session datagram (Flow 0 with datagram flows). Never waits:
    /// when the queue is full the oldest datagram is dropped.
    ///
    /// `allowed` is the send limiter's verdict on it
    /// ([`super::Config::datagram_limiter`]), which the caller asks before
    /// it takes the session's lock (`true` without a limiter): the core
    /// never calls the limiter. A datagram it refused
    /// is dropped and counted (`datagrams_dropped_limit`) once the checks
    /// that fail the call passed. Returns whether the datagram was queued:
    /// the caller then charges the limiter, after releasing the lock.
    pub fn send_datagram(&mut self, data: Bytes, allowed: bool) -> Result<bool, DatagramError> {
        if let Some(e) = self.lost() {
            return Err(DatagramError::SessionLost(e));
        }
        if self.early_datagrams() {
            if self.admitted(allowed) {
                self.queue_early_datagram(None, data);
            }
            return Ok(allowed);
        }
        let max = self
            .max_datagram_size()
            .ok_or(DatagramError::NotNegotiated)?;
        if data.len() > max {
            return Err(DatagramError::TooLarge { max });
        }
        if self.admitted(allowed) {
            self.queue_datagram(None, data);
        }
        Ok(allowed)
    }

    /// Counts a datagram the send limiter refused.
    fn admitted(&mut self, allowed: bool) -> bool {
        if !allowed {
            self.stats.datagrams_dropped_limit += 1;
        }
        allowed
    }

    /// Queues a datagram on a bidirectional stream (Flow = stream ID + 1,
    /// EXTENSIONS.md Section 6.3). A stream without an identifier is
    /// pinned first. `allowed` and the result as for
    /// [`SessionCore::send_datagram`].
    pub fn send_stream_datagram(
        &mut self,
        key: StreamKey,
        context: u64,
        data: Bytes,
        allowed: bool,
    ) -> Result<bool, DatagramError> {
        if let Some(e) = self.lost() {
            return Err(DatagramError::SessionLost(e));
        }
        if self.early_datagrams() {
            let s = self.streams.get(key).ok_or(DatagramError::ClosedStream)?;
            if s.dir != Dir::Bidi || s.parts_terminal() || context >= 1 << 62 {
                return Err(DatagramError::ClosedStream);
            }
            if self.admitted(allowed) {
                self.queue_early_datagram(Some((key, context)), data);
            }
            return Ok(allowed);
        }
        let (id, context) = self.stream_datagram_flow(key, context, data.len())?;
        if self.admitted(allowed) {
            self.queue_datagram(Some((id, context)), data);
        }
        Ok(allowed)
    }

    /// The flow of a datagram of `len` payload bytes on stream `key` after
    /// establishment, pinning the stream's identifier: the checks that fail
    /// [`SessionCore::send_stream_datagram`].
    fn stream_datagram_flow(
        &mut self,
        key: StreamKey,
        context: u64,
        len: usize,
    ) -> Result<(u64, u64), DatagramError> {
        if !self.features.datagram_flows {
            return Err(DatagramError::NotNegotiated);
        }
        let frame = self
            .max_datagram_frame()
            .ok_or(DatagramError::NotNegotiated)?;
        let s = self.streams.get(key).ok_or(DatagramError::ClosedStream)?;
        if s.dir != Dir::Bidi || s.parts_terminal() || s.goaway.is_some() || context >= 1 << 62 {
            return Err(DatagramError::ClosedStream);
        }
        let id = self
            .stream_id(key)
            .map_err(|_| DatagramError::ClosedStream)?;
        let prefix = varint::len(id + 1) + varint::len(context);
        let max = frame.saturating_sub(1 + prefix);
        if len > max {
            return Err(DatagramError::TooLarge { max });
        }
        Ok((id, context))
    }

    /// Before establishment a datagram waits for the peer's parameters.
    fn early_datagrams(&self) -> bool {
        !self.is_established() && self.config.enable_datagrams
    }

    /// Queues a datagram until establishment.
    fn queue_early_datagram(&mut self, flow: Option<(StreamKey, u64)>, data: Bytes) {
        if self.dgram_mut().early.len() >= SEND_DATAGRAM_QUEUE {
            self.dgram_mut().early.pop_front();
            self.stats.datagrams_dropped_send += 1;
        }
        self.dgram_mut().early.push_back((flow, data));
    }

    /// Establishment: datagrams sent before it go out now, those the
    /// parameters do not allow (no datagram support, too large, stream
    /// datagrams without datagram flows) are dropped and counted.
    pub(super) fn release_early_datagrams(&mut self) {
        let Some(early) = self
            .dgram
            .as_deref_mut()
            .map(|d| std::mem::take(&mut d.early))
        else {
            return;
        };
        for (flow, data) in early {
            // The send limiter passed them when they were queued.
            let sent = match flow {
                None => self.send_datagram(data, true).is_ok(),
                Some((key, context)) => self.send_stream_datagram(key, context, data, true).is_ok(),
            };
            if !sent {
                self.stats.datagrams_dropped_send += 1;
            }
        }
    }

    fn queue_datagram(&mut self, flow: Option<(u64, u64)>, data: Bytes) {
        if self.dgram_mut().send.len() >= SEND_DATAGRAM_QUEUE {
            self.dgram_mut().send.pop_front();
            self.stats.datagrams_dropped_send += 1;
        }
        self.dgram_mut().send.push_back((flow, data));
    }

    /// Whether the datagram send queue is full (a waiting sender waits for
    /// [`super::CoreEvent::DatagramsUnblocked`]).
    pub fn datagram_queue_full(&self) -> bool {
        self.dgram().send.len() >= SEND_DATAGRAM_QUEUE
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
    /// (`datagrams_dropped_limit`).
    pub fn admit_datagrams(&mut self, datagrams: &mut Vec<super::ReceivedDatagram>) {
        for d in datagrams.drain(..) {
            let held = &mut self.dgram_mut().held_bytes;
            *held = held.saturating_sub(d.data.len());
            if !d.allowed {
                self.stats.datagrams_dropped_limit += 1;
                continue;
            }
            let usable = d.stream.is_none_or(|(k, _)| {
                self.streams.get(k).is_some_and(|s| {
                    !s.released && !s.parts_terminal() && s.offer != Offer::Rejected
                })
            });
            if usable {
                self.queue_received_datagram(d.stream, d.data);
            } else {
                self.drop_received_datagram(d.stream);
            }
        }
    }

    /// The next session datagram.
    pub fn recv_datagram(&mut self) -> Result<Option<Bytes>, SessionError> {
        match self.dgram.as_deref_mut().and_then(|d| d.recv.pop_front()) {
            Some(d) => {
                self.dgram_mut().recv_bytes -= d.len();
                self.meter.add(Count::DatagramReceived, d.len() as u64);
                Ok(Some(d))
            }
            None => self.lost().map_or(Ok(None), Err),
        }
    }

    /// The next datagram of a stream, with its context.
    pub fn recv_stream_datagram(
        &mut self,
        key: StreamKey,
    ) -> Result<Option<(u64, Bytes)>, StreamError> {
        let s = self
            .streams
            .get_mut(key)
            .ok_or(StreamError::ClosedLocally)?;
        match s.datagrams.as_mut().and_then(|q| q.queue.pop_front()) {
            Some((context, d)) => {
                let n = d.len() as u64;
                s.datagrams_mut().counts.bytes_received += n;
                s.count(Count::DatagramReceived, n);
                self.dgram_mut().recv_bytes -= d.len();
                self.meter.add(Count::DatagramReceived, n);
                Ok(Some((context, d)))
            }
            None => match self.lost() {
                Some(e) => Err(StreamError::SessionLost(e)),
                None => Ok(None),
            },
        }
    }

    // ---- liveness ----------------------------------------------------------------

    /// Sends a QX_PING request, or joins the one outstanding (SPEC.md
    /// Section 4.5), with every peer, plain QMux peers included. The response
    /// updates the RTT estimate. Returns the
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

/// The write error for a peer's STOP_SENDING code.
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
