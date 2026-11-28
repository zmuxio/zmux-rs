//! The receive path: records and frames from the peer.

use std::time::Instant;

use bytes::Bytes;

use super::pipes::{Attachment, Classified, InPipe};
use super::recv_store::{InputSpan, Source};
use super::stream::{self, Offer, RecvPart, RecvState, SendOutcome, SendState, Stream, StreamKey};
use super::{
    BIDI, CloseFrame, CoreEvent, InState, LaneId, SessionCore, SessionError, State, UNI, di,
    dir_of_index, varint, violation,
};
use crate::proto::frame::{
    ConnectionClose, Dir, Frame, GoAwayFrame, PriorityUpdate, QxPing, ResetStreamAt, StopSending,
};
use crate::proto::ident::Classifier;
use crate::proto::payload::{Flow, WirePreamble};
use crate::proto::record::{Event as RecordEvent, Framing};
use crate::proto::{DetailKey, Error, Gates, TransportErrorCode as T};
use crate::util::usize_sat;

/// Which part of a stream a frame refers to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    /// The local receiving part: STREAM, `RESET_STREAM`(_AT),
    /// `STREAM_DATA_BLOCKED`.
    Recv,
    /// The local sending part: `MAX_STREAM_DATA`, `STOP_SENDING`,
    /// `PRIORITY_UPDATE`.
    Send,
}

enum Lookup {
    Stream {
        key: StreamKey,
        opened: bool,
    },
    /// The stream's state was discarded: ignore the frame.
    Discarded,
}

impl SessionCore {
    /// Bytes read from an inbound pipe (one of its lanes), split
    /// anywhere. A record that is incomplete in `data` is kept by the core
    /// and applied later.
    pub fn receive(&mut self, at: impl Into<LaneId>, data: &[u8], now: Instant) {
        self.receive_inner(at.into(), data, now, false, None);
    }

    /// Applies the complete records at the start of `data` without
    /// copying and returns how many bytes were used. The driver keeps the
    /// rest (an incomplete record) and passes it again with more bytes
    /// appended; its buffer must hold `max_record_size + 4` bytes.
    pub fn receive_in_place(&mut self, at: impl Into<LaneId>, data: &[u8], now: Instant) -> usize {
        self.receive_inner(at.into(), data, now, true, None)
    }

    /// [`SessionCore::receive_in_place`] for a chunk whose backing is known.
    /// Complete STREAM ranges within `data` can retain its allocation.
    pub fn receive_shared(
        &mut self,
        at: impl Into<LaneId>,
        data: &super::Chunk,
        now: Instant,
    ) -> usize {
        self.receive_backed(at.into(), &data.bytes, data.backing, now, true)
    }

    /// Receives bytes from a driver buffer whose backing the driver allocated.
    #[cfg(any(test, all(feature = "tokio", not(loom))))]
    pub(crate) fn receive_buffer(
        &mut self,
        at: impl Into<LaneId>,
        data: &Bytes,
        backing: super::Backing,
        now: Instant,
    ) -> usize {
        self.receive_backed(at.into(), data, backing, now, true)
    }

    /// Receives a range handed over by an outer stream. An incomplete
    /// record stays in the record reader, while complete records borrow
    /// their stream payloads from the original allocation.
    #[cfg(any(test, all(feature = "tokio", not(loom))))]
    pub(crate) fn receive_segment(&mut self, at: LaneId, segment: &super::Segment, now: Instant) {
        self.receive_backed(at, &segment.bytes, segment.backing, now, false);
    }

    fn receive_backed(
        &mut self,
        at: LaneId,
        data: &Bytes,
        backing: super::Backing,
        now: Instant,
        retain: bool,
    ) -> usize {
        let refs = &mut self.recv_refs;
        let mut moved = false;
        match refs.current.iter_mut().find(|(lane, _)| *lane == at) {
            Some((_, b)) if b.id == backing.id => {}
            Some((_, b)) => {
                // The lane's reads moved on: its last buffer is retired.
                refs.retired_at_most += std::mem::replace(b, backing).size;
                moved = true;
            }
            None => refs.current.push((at, backing)),
        }
        let input = InputSpan::new(data, backing);
        let used = self.receive_inner(at, data, now, retain, Some(&input));
        input.finish(&mut self.receive);
        // Checked with the new buffer's data referenced.
        let refs = &self.recv_refs;
        if moved && refs.retired_at_most > 2 * refs.referenced_at_least {
            self.settle_recv_refs();
        }
        used
    }

    /// A lane of pipe `pipe` ended or the pipe left: the buffer it read
    /// into last is retired (the bound below).
    pub(super) fn recv_lane_gone(&mut self, pipe: u64) {
        if self.recv_refs.current.iter().any(|(l, _)| l.pipe.0 == pipe) {
            self.settle_recv_refs();
        }
    }

    /// The bound on the read buffers that received data keeps alive, checked
    /// whenever a lane's reads move
    /// on to a new buffer or a lane ends: the retired buffers that received
    /// data keeps alive stay within twice the bytes it references in all
    /// buffers (those the driver still reads into are alive anyway, and
    /// their referenced bytes count). Beyond that, the pieces of the least
    /// used retired buffers are copied out until the bound holds again. A
    /// buffer that many streams share is counted once, and a bulk transfer
    /// whose reader leaves a rest of each buffer it moved on from copies
    /// nothing. Streams that reference no buffer leave the list.
    pub(super) fn settle_recv_refs(&mut self) {
        // A lane that ended reads into no buffer any more.
        let atts = &self.atts;
        self.recv_refs.current.retain(|(lane, _)| {
            atts.get(lane.pipe.0)
                .and_then(Attachment::inp)
                .is_some_and(|p| p.state() != InState::Ended && p.lane_reads(lane.lane.0))
        });
        let refs = &mut self.recv_refs;
        let tally = refs.tally.get_mut();
        self.receive.tally(tally);
        let referenced: usize = tally.iter().map(|&(_, _, n)| n).sum();
        let current = &refs.current;
        let packing = self.receive.copying_backing();
        tally.retain(|&(id, _, _)| {
            packing.is_none_or(|packing| packing.id != id)
                && !current.iter().any(|&(_, c)| c.id == id)
        });
        let mut retired: usize = tally.iter().map(|&(_, size, _)| size).sum();
        if retired > 2 * referenced {
            // Pack the sparsest retired roots first, preserving every node's
            // offset and queue links. A compacted range retains its exact size.
            let used = |&(_, size, held): &(u64, usize, usize)| (held as u128, size as u128);
            tally.sort_unstable_by(|a, b| {
                let ((ha, sa), (hb, sb)) = (used(a), used(b));
                (ha * sb).cmp(&(hb * sa))
            });
            let selected = tally
                .iter()
                .take_while(|&&(_, size, held)| {
                    if retired <= 2 * referenced {
                        return false;
                    }
                    retired -= size.saturating_sub(held);
                    true
                })
                .count();
            tally.truncate(selected);
            tally.sort_unstable_by_key(|&(id, _, _)| id);
            self.receive.compact(tally);
        }
        refs.retired_at_most = retired;
        refs.referenced_at_least = referenced;
    }

    /// The physical capacity of roots kept alive by unread STREAM data.
    pub(super) fn receive_root_capacity(&self) -> usize {
        let mut tally = self.recv_refs.tally.borrow_mut();
        self.receive.tally(&mut tally);
        tally.iter().map(|&(_, capacity, _)| capacity).sum()
    }

    /// The bytes of the retired read buffers that received data keeps
    /// alive, and the bytes it references in all read buffers.
    #[cfg(test)]
    pub(super) fn recv_bound(&self) -> (usize, usize) {
        let mut t = self.recv_refs.tally.borrow_mut();
        self.receive.tally(&mut t);
        let referenced = t.iter().map(|&(_, _, n)| n).sum();
        let current = &self.recv_refs.current;
        let packing = self.receive.copying_backing();
        t.retain(|&(id, _, _)| {
            packing.is_none_or(|packing| packing.id != id)
                && !current.iter().any(|&(_, c)| c.id == id)
        });
        (t.iter().map(|&(_, size, _)| size).sum(), referenced)
    }

    /// One complete message from a message-framed pipe, or lane of one.
    pub fn receive_message(
        &mut self,
        at: impl Into<LaneId>,
        message: crate::proto::ReceivedRecord,
        now: Instant,
    ) {
        let at = at.into();
        let len = message.as_ref().len();
        let pipe = at.pipe.0;
        self.tick(now);
        self.pick_input();
        let scanning = self.discarding();
        let Some(p) = self.inp_mut(pipe) else {
            return;
        };
        if scanning && !p.scannable() {
            return;
        }
        let Some(li) = p.lane_index(at.lane.0) else {
            return;
        };
        if p.framing() != Framing::Records || p.state() == InState::Ended {
            return;
        }
        if li == 0 && !p.classify_message(message.as_ref()) {
            self.protocol_error(Classifier::rejection_error(), now);
            return;
        }
        let Some(mut reader) = p.take_reader(li) else {
            return;
        };
        let result = reader.begin_message(len);
        if let Err(e) = result {
            if let Some(p) = self.inp_mut(pipe) {
                p.return_reader(li, reader);
            }
            self.protocol_error(e, now);
            return;
        }
        self.rx = pipe;
        self.rx_lane = li;
        let backing = super::Backing::new(message.capacity());
        let message = message.into_bytes();
        let mut input = message.as_ref();
        let source = InputSpan::new(&message, backing);
        self.drain_reader(&mut reader, &mut input, now, false, Some(&source));
        source.finish(&mut self.receive);
        if let Some(p) = self.inp_mut(pipe) {
            p.return_reader(li, reader);
        }
        self.stats.bytes_received += len as u64;
        self.account_copied_input();
        // This carrier handed over a complete root. No driver will fill
        // any remaining capacity on a later call.
        self.recv_refs.retired_at_most += backing.size;
        if self.recv_refs.retired_at_most > 2 * self.recv_refs.referenced_at_least {
            self.settle_recv_refs();
        }
    }

    fn receive_inner(
        &mut self,
        at: LaneId,
        data: &[u8],
        now: Instant,
        retain: bool,
        source: Source<'_>,
    ) -> usize {
        let pipe = at.pipe.0;
        self.tick(now);
        self.pick_input();
        // Lingering discards what it reads, looking only for the peer's
        // `CONNECTION_CLOSE` ([`Self::drain_reader`]).
        let scanning = self.discarding();
        let Some(p) = self.inp_mut(pipe) else {
            return data.len();
        };
        if scanning && !p.scannable() {
            return data.len();
        }
        // A lane not accepted reads nothing (the driver aborts it).
        let Some(li) = p.lane_index(at.lane.0) else {
            return data.len();
        };
        if p.state() == InState::Ended || p.framing() == Framing::Records {
            return data.len();
        }
        if li == 0 {
            // In place, the driver passes unconsumed bytes again: the
            // classifier sees each byte once.
            match p.classify(data, retain) {
                Classified::Read => {}
                Classified::Wait => return 0,
                Classified::Rejected(seen) => {
                    self.stats.bytes_received += seen as u64;
                    self.protocol_error(Classifier::rejection_error(), now);
                    return data.len();
                }
            }
        }
        let Some(mut reader) = p.take_reader(li) else {
            return data.len();
        };
        self.rx = pipe;
        self.rx_lane = li;
        let mut input = data;
        self.drain_reader(&mut reader, &mut input, now, retain, source);
        let ended = self
            .inp_mut(pipe)
            .is_none_or(|p| p.return_reader(li, reader));
        let used = if ended || self.discarding() && !self.scanning(pipe) {
            data.len()
        } else {
            data.len() - input.len()
        };
        self.account_copied_input();
        if retain && let Some(p) = self.inp_mut(pipe) {
            // The driver holds an incomplete record (for `pipe_ended`).
            p.set_partial(li, used < data.len());
        }
        self.stats.bytes_received += if retain { used } else { data.len() } as u64;
        used
    }

    fn account_copied_input(&mut self) {
        self.recv_refs.retired_at_most += self.receive.take_copied_capacity();
        if self.recv_refs.retired_at_most > 2 * self.recv_refs.referenced_at_least {
            self.settle_recv_refs();
        }
    }

    fn drain_reader(
        &mut self,
        reader: &mut crate::proto::RecordReader,
        input: &mut &[u8],
        now: Instant,
        retain: bool,
        source: Source<'_>,
    ) {
        let account = if self.config.accounting.enabled {
            self.att(self.rx).and_then(|attachment| {
                let ledger = attachment.accounting()?.clone();
                let lane = attachment.inp()?.lane_number(self.rx_lane);
                Some((ledger, lane))
            })
        } else {
            None
        };
        self.read_record_events(reader, input, now, retain, account.as_ref(), source);
        if let Some((ledger, lane)) = account {
            if self.discarding()
                && let Some(len) = reader.complete_record_len()
            {
                // A close can end scanning before the parser yields RecordEnd.
                ledger.receive_complete(lane, len, reader.framing());
                return;
            }
            let retained = if retain && !self.discarding() {
                input.len() as u64
            } else {
                0
            };
            ledger.pending_read(lane, reader.pending_record_bytes().saturating_add(retained));
        }
    }

    fn read_record_events(
        &mut self,
        reader: &mut crate::proto::RecordReader,
        input: &mut &[u8],
        now: Instant,
        retain: bool,
        account: Option<&(std::sync::Arc<super::accounting::Ledger>, u64)>,
        source: Source<'_>,
    ) {
        self.budget.refill(now);
        let (pipe, lane) = (self.rx, self.rx_lane);
        let framing = reader.framing();
        // A frame other than PADDING in the record being read (shaping).
        loop {
            let gates = self.receive_gates();
            let event = if retain {
                reader.read_complete(input, &gates)
            } else {
                reader.read(input, &gates)
            };
            // The pipe's frames are processed with `rx` set to it, also
            // after frames of other pipes changed it.
            self.rx = pipe;
            self.rx_lane = lane;
            if self.discarding() {
                // Closing: nothing is processed. The peer's
                // CONNECTION_CLOSE ends the pipe's linger; what is no valid
                // record sequence ends the look for it.
                match event {
                    Ok(Some(RecordEvent::Frame(Frame::ConnectionClose(_)))) => {
                        self.peer_close_read(pipe, now);
                    }
                    Ok(Some(RecordEvent::RecordEnd { len })) => {
                        if let Some((ledger, lane)) = account {
                            ledger.receive_complete(*lane, len, framing);
                        }
                    }
                    Ok(Some(RecordEvent::Frame(_))) => {}
                    Ok(None) => return,
                    Err(_) => {
                        if let Some(p) = self.inp_mut(pipe) {
                            p.stop_scan();
                        }
                    }
                }
                if !self.scanning(pipe) {
                    return;
                }
                continue;
            }
            let result = match event {
                Ok(Some(RecordEvent::Frame(f))) => self.on_frame(f, now, source),
                Ok(Some(RecordEvent::RecordEnd { len })) => {
                    if let Some((ledger, lane)) = account {
                        ledger.receive_complete(*lane, len, framing);
                    }
                    self.on_record_end(len, now)
                }
                Ok(None) => return,
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                self.protocol_error(e, now);
            }
            if self
                .att(pipe)
                .and_then(|a| a.inp())
                .is_none_or(|p| p.state() == InState::Ended)
                || self.discarding() && !self.scanning(pipe)
            {
                return;
            }
        }
    }

    /// Whether what arrives on `pipe` is looked through for the peer's
    /// `CONNECTION_CLOSE`: the session is closing and nothing ruled it out.
    fn scanning(&self, pipe: u64) -> bool {
        self.discarding()
            && self
                .att(pipe)
                .and_then(Attachment::inp)
                .is_some_and(InPipe::scannable)
    }

    /// Whether what arrives is discarded: the session is closing, unless its orderly close waits
    /// for the other lanes, processing what it receives meanwhile.
    fn discarding(&self) -> bool {
        self.state >= State::Closing && !self.close_waiting()
    }

    /// The frames the local endpoint accepts now.
    pub(super) fn receive_gates(&self) -> Gates {
        if let Some(peer) = &self.peer_tp {
            let mut gates = self.features.receive_gates(
                self.local_tp().reset_stream_at,
                self.local_tp().max_datagram_frame_size(),
            );
            gates.datagram_ack = self.features.same_family && peer.max_datagram_frame_size() != 0;
            gates
        } else {
            Gates {
                reset_stream_at: self.local_tp().reset_stream_at,
                max_datagram_frame_size: self.local_tp().max_datagram_frame_size(),
                ..Gates::NONE
            }
        }
    }

    pub(super) fn charge(&mut self) -> Result<(), Error> {
        if self.budget.charge() {
            Ok(())
        } else {
            Err(violation(
                T::ZMUX_EXCESSIVE_LOAD,
                0,
                "no-effect budget exhausted",
            ))
        }
    }

    /// Charges a duplicate or outdated frame (NE-3, NE-4, NE-6 to NE-8),
    /// which multipath sessions never charge (a
    /// protocol rule of the mode, kept here).
    fn charge_dup(&mut self) -> Result<(), Error> {
        if self.is_multipath() {
            return Ok(());
        }
        self.charge()
    }

    fn on_frame(
        &mut self,
        frame: Frame<'_>,
        now: Instant,
        source: Source<'_>,
    ) -> Result<(), Error> {
        let (id, li) = (self.rx, self.rx_lane);
        if li > 0 && self.inp_mut(id).is_some_and(|p| p.in_first_record(li)) {
            return self.on_lane_first_frame(&frame);
        }
        if !matches!(
            frame,
            Frame::Padding(_)
                | Frame::PipeAck(_)
                | Frame::DatagramAck(_)
                | Frame::MaxData(_)
                | Frame::MaxStreamData(_)
                | Frame::MaxStreams(_)
                | Frame::DataBlocked(_)
                | Frame::StreamDataBlocked(_)
                | Frame::StreamsBlocked(_)
        ) {
            // An exchange tends to go on: write calls stay short for a
            // while.
            self.exchange_at = Some(now);
        }
        let first = {
            let Some(p) = self.inp_mut(id) else {
                return Ok(());
            };
            let eliciting = frame.is_ack_eliciting();
            let activity = matches!(
                frame,
                Frame::Stream(_)
                    | Frame::ResetStream(_)
                    | Frame::ResetStreamAt(_)
                    | Frame::StopSending(_)
                    | Frame::Datagram(_)
                    | Frame::QxPing(_)
            );
            p.frame_in(li, eliciting, activity, matches!(frame, Frame::PipePing))
                && id == 0
                && li == 0
        };
        if matches!(
            frame,
            Frame::Stream(_)
                | Frame::ResetStream(_)
                | Frame::ResetStreamAt(_)
                | Frame::StopSending(_)
                | Frame::Datagram(_)
        ) {
            self.note_traffic(id, now);
        }
        let ty = frame.frame_type().0;
        if first && !matches!(frame, Frame::TransportParameters(_)) {
            return Err(violation(
                T::PROTOCOL_VIOLATION,
                ty,
                "first frame is not QX_TRANSPORT_PARAMETERS",
            ));
        }
        if self.carrier_early_in()
            && matches!(
                frame,
                Frame::Stream(_)
                    | Frame::ResetStream(_)
                    | Frame::ResetStreamAt(_)
                    | Frame::StopSending(_)
                    | Frame::Datagram(_)
            )
            && (self.features.same_family || !matches!(frame, Frame::Stream(_)))
        {
            return Err(violation(
                T::PROTOCOL_VIOLATION,
                ty,
                "application frame in carrier early data",
            ));
        }
        match frame {
            Frame::Padding(_) => Ok(()),
            Frame::TransportParameters(f) => {
                if !first {
                    return Err(violation(
                        T::PROTOCOL_VIOLATION,
                        ty,
                        "QX_TRANSPORT_PARAMETERS not first",
                    ));
                }
                self.on_peer_parameters(f.parameters()?.as_ref(), now)
            }
            Frame::Stream(s) => self.on_stream(s, ty, now, source),
            Frame::ResetStream(f) => {
                self.on_reset(f.stream_id, f.error_code, f.final_size, None, ty, now)
            }
            Frame::ResetStreamAt(f) => self.on_reset_at(f, ty, now),
            Frame::StopSending(f) => self.on_stop_sending(f, ty, now),
            Frame::MaxData(f) => {
                if self.streams.max_data_received(f.maximum, self.now) {
                    // Streams waiting for session credit (and pinned
                    // openings, `opening_ready`) may send again.
                    self.wake_capacity_waiters();
                    Ok(())
                } else {
                    self.charge_dup()
                }
            }
            Frame::MaxStreamData(f) => self.on_max_stream_data(f.stream_id, f.maximum, ty),
            Frame::MaxStreams(f) => {
                let d = di(f.dir);
                if self.streams.raise_local(d, f.maximum) {
                    if self.streams.take_waiting(d) {
                        self.events.push_back(CoreEvent::StreamsAvailable(f.dir));
                    }
                    let ld = self.streams.local_dir(d);
                    if ld.reserved > ld.next_index {
                        // Streams opened before establishment beyond the limit.
                        self.schedule_unopened(di(f.dir));
                    }
                    Ok(())
                } else {
                    self.charge_dup()
                }
            }
            Frame::DataBlocked(f) => {
                if f.limit > self.streams.recv_flow().limit_sent {
                    return Err(violation(
                        T::PROTOCOL_VIOLATION,
                        ty,
                        "DATA_BLOCKED above the advertised limit",
                    )
                    .detail(DetailKey::Value, f.limit)
                    .detail(DetailKey::Limit, self.streams.recv_flow().limit_sent));
                }
                if self
                    .streams
                    .recv_flow()
                    .blocked_seen
                    .is_some_and(|b| f.limit <= b)
                {
                    return self.charge_dup();
                }
                self.streams.data_blocked_received(f.limit);
                Ok(())
            }
            Frame::StreamDataBlocked(f) => self.on_stream_data_blocked(f.stream_id, f.limit, ty),
            Frame::StreamsBlocked(f) => {
                let d = self.streams.remote_dir(di(f.dir));
                if f.limit > d.limit_sent {
                    return Err(violation(
                        T::PROTOCOL_VIOLATION,
                        ty,
                        "STREAMS_BLOCKED above the advertised limit",
                    )
                    .detail(DetailKey::Value, f.limit)
                    .detail(DetailKey::Limit, d.limit_sent));
                }
                if d.blocked_seen.is_some_and(|b| f.limit <= b) {
                    return self.charge_dup();
                }
                self.streams.remote_blocked(di(f.dir), f.limit);
                Ok(())
            }
            Frame::ConnectionClose(f) => {
                self.on_connection_close(f, now);
                Ok(())
            }
            Frame::Datagram(d) => self.on_datagram(d, ty, id),
            Frame::DatagramAck(ack) => {
                self.on_datagram_ack(ack);
                Ok(())
            }
            Frame::QxPing(p) => self.on_qx_ping(p, ty, now),
            Frame::GoAway(g) => self.on_goaway(g, now),
            Frame::PriorityUpdate(p) => self.on_priority_update(p, ty),
            // Multipath frames are only decoded when multipath is in use
            // (the receive gates).
            // Decoded only while lanes are available toward us: anywhere but
            // first on a new lane.
            Frame::PipeLane(_) => Err(violation(
                T::PROTOCOL_VIOLATION,
                ty,
                "PIPE_LANE not first on a new lane",
            )),
            // Protocol rule: the pipe layer's frames are those of a feature
            // not in use outside multipath.
            Frame::PipeAck(f) if self.is_multipath() => self.on_pipe_ack(&f, now),
            Frame::PipeAck(f) if self.pipe_ack.is_some() => self.on_single_pipe_ack(&f, now),
            Frame::PipePing if self.is_multipath() => {
                if let Some(p) = self.inp_mut(id) {
                    p.ping_in(li);
                }
                // NE-2.
                self.charge()
            }
            Frame::PipeAbandon(f) if self.is_multipath() => {
                self.on_pipe_abandon(f.pipe_id, f.error_code, now)
            }
            Frame::PipeStatus(f) if self.is_multipath() => self.on_pipe_status(
                f.pipe_id,
                f.sequence,
                f.status == crate::proto::frame::PipeStatusValue::Standby,
                f.priority,
            ),
            Frame::SessionEpoch(f) if self.is_multipath() => self.on_session_epoch(f, now),
            _ => Err(violation(
                T::FRAME_ENCODING_ERROR,
                ty,
                "frame of a feature not in use",
            )),
        }
    }

    // ---- streams ---------------------------------------------------------

    /// Finds or implicitly opens the stream a frame refers to: lower-numbered
    /// streams of the type open with it, a frame at or above the stream limit or
    /// for a local stream not yet opened is an error.
    fn lookup(&mut self, id: u64, part: Part, ty: u64) -> Result<Lookup, Error> {
        let dir = stream::dir_of(id);
        let d = di(dir);
        let client = stream::client_initiated(id);
        let local = client == matches!(self.role, crate::proto::params::Role::Client);
        let index = stream::index(id);
        if local {
            if index >= self.streams.local_dir(d).next_index {
                return Err(violation(
                    T::STREAM_STATE_ERROR,
                    ty,
                    "frame for an unopened local stream",
                )
                .detail(DetailKey::Stream, id));
            }
            if dir == Dir::Uni && part == Part::Recv {
                return Err(violation(
                    T::STREAM_STATE_ERROR,
                    ty,
                    "peer sends on a local unidirectional stream",
                )
                .detail(DetailKey::Stream, id));
            }
            return Ok(match self.streams.key_of(id) {
                Some(key) => Lookup::Stream { key, opened: false },
                None => Lookup::Discarded,
            });
        }
        if dir == Dir::Uni && part == Part::Send {
            return Err(violation(
                T::STREAM_STATE_ERROR,
                ty,
                "frame for the receive-only direction of a peer stream",
            )
            .detail(DetailKey::Stream, id));
        }
        if index >= self.streams.remote_dir(d).limit_sent {
            return Err(
                violation(T::STREAM_LIMIT_ERROR, ty, "stream opened beyond the limit")
                    .detail(DetailKey::Stream, id)
                    .detail(DetailKey::Limit, self.streams.remote_dir(d).limit_sent),
            );
        }
        if index < self.streams.remote_dir(d).opened {
            return Ok(match self.streams.key_of(id) {
                Some(key) => Lookup::Stream { key, opened: false },
                None => Lookup::Discarded,
            });
        }
        // Open every stream up to this one.
        let first = self.streams.remote_dir(d).opened;
        let mut key = None;
        while let Some(i) = self.streams.open_peer_index(d, index) {
            key = Some(self.open_peer_stream(make_peer_id(i, dir, client), dir));
        }
        let now = self.now;
        self.flush_rejects(now);
        if !self.features.preamble {
            // Without preambles, streams are offered as they open.
            for i in first..=index {
                if let Some(k) = self.streams.key_of(make_peer_id(i, dir, client)) {
                    self.offer(k);
                }
            }
        }
        if dir == Dir::Bidi {
            // Datagrams that overtook the opening frames.
            self.release_waiting();
        }
        Ok(Lookup::Stream {
            key: key.unwrap_or(StreamKey {
                slot: 0,
                generation: u32::MAX,
            }),
            opened: true,
        })
    }

    fn open_peer_stream(&mut self, id: u64, dir: Dir) -> StreamKey {
        let peer = self.peer_tp.as_ref();
        let local = self.local_tp();
        let max_window = self.config.stream_window_cap();
        let mut s = Stream::new(dir, false);
        s.id = Some(id);
        s.replayable = self.carrier_early_in();
        match dir {
            Dir::Bidi => {
                let send_max = peer.map_or(0, |p| p.window_bidi_local);
                s.send = Some(self.streams.new_send_part(send_max));
                s.recv = Some(RecvPart::new(local.window_bidi_remote, max_window));
            }
            Dir::Uni => {
                s.recv = Some(RecvPart::new(local.window_uni, max_window));
            }
        }
        self.stats.streams_opened_remote += 1;
        if self.shape.is_some() || self.shape_pending.is_some() {
            self.shape_stream(super::shaping::EventKind::StreamOpen, id);
        }
        let key = self.streams.insert_peer(id, di(dir), s);
        if let Some(goaway) = &mut self.goaway
            && goaway.shutdown.is_some()
        {
            // The first GOAWAY still lets the peer use already granted IDs.
            goaway.draining.insert(key);
        }
        key
    }

    /// Offers peer stream `key` if it is ready.
    pub(super) fn offer(&mut self, key: StreamKey) {
        let preamble = self.features.preamble;
        self.streams.offer(key, preamble, &mut self.events);
    }

    #[allow(
        clippy::many_single_char_names,
        reason = "f the frame, r its receiving part, k and n byte counts, as in the receive path"
    )]
    pub(super) fn on_stream(
        &mut self,
        f: crate::proto::frame::Stream<'_>,
        ty: u64,
        now: Instant,
        source: Source<'_>,
    ) -> Result<(), Error> {
        let (key, opened) = match self.lookup(f.stream_id, Part::Recv, ty)? {
            Lookup::Stream { key, opened } => (key, opened),
            Lookup::Discarded => return Ok(()),
        };
        self.flush_rejects(now);
        let preamble_in_use = self.features.preamble;
        let preamble_limit = self.local_tp().preamble();
        let Some(s) = self.streams.get_mut(key) else {
            return Ok(());
        };
        let peer_opened = !s.local;
        let dir = s.dir;
        let Some(r) = s.recv.as_mut() else {
            return Ok(());
        };
        let offset = f.offset;
        let len = f.data.len() as u64;
        let end = offset + len;
        let mp = self.mp.is_some();
        // Single pipe: data arrives in order, without gaps or repeats. Multipath: any order,
        // duplicates allowed. Protocol rule.
        if !mp && offset != r.received && (len > 0 || offset > r.received) {
            return Err(
                violation(T::PROTOCOL_VIOLATION, ty, "STREAM data out of order")
                    .detail(DetailKey::Stream, f.stream_id)
                    .detail(DetailKey::Offset, offset)
                    .detail(DetailKey::Value, r.received),
            );
        }
        if let Some(fs) = r.final_size
            && (end > fs || (f.fin && end != fs))
        {
            return Err(
                violation(T::FINAL_SIZE_ERROR, ty, "STREAM beyond the final size")
                    .detail(DetailKey::Stream, f.stream_id)
                    .detail(DetailKey::Offset, offset)
                    .detail(DetailKey::Length, len)
                    .detail(DetailKey::Limit, fs),
            );
        }
        if f.fin && end < r.received {
            return Err(
                violation(T::FINAL_SIZE_ERROR, ty, "FIN below the data received")
                    .detail(DetailKey::Stream, f.stream_id)
                    .detail(DetailKey::Value, end)
                    .detail(DetailKey::Limit, r.received),
            );
        }
        if end > r.limit {
            return Err(violation(
                T::FLOW_CONTROL_ERROR,
                ty,
                "stream flow-control limit exceeded",
            )
            .detail(DetailKey::Stream, f.stream_id)
            .detail(DetailKey::Offset, offset)
            .detail(DetailKey::Length, len)
            .detail(DetailKey::Limit, r.limit));
        }
        let new_final = f.fin && r.final_size.is_none();
        let before = r.counted();
        let increase = before.max(end) - before;
        let terminal = r.state.is_terminal();
        let flow = self.streams.recv_flow();
        if !flow.admits(increase) {
            return Err(violation(
                T::FLOW_CONTROL_ERROR,
                ty,
                "session flow-control limit exceeded",
            )
            .detail(DetailKey::Stream, f.stream_id)
            .detail(DetailKey::Value, flow.used + increase)
            .detail(DetailKey::Limit, flow.limit_sent));
        }
        if !opened && !terminal {
            // NE-5: neither opens, nor new data, nor a new final size. In a
            // multipath session only empty frames without FIN count.
            let chargeable = if mp {
                len == 0 && !f.fin
            } else {
                len == 0 && !new_final
            };
            if chargeable {
                self.charge()?;
            }
        }
        self.streams.count_received(increase);
        let s = self.streams.get_mut(key).expect("present");
        let r = s.recv.as_mut().expect("present");
        r.received = r.received.max(end);
        if f.fin {
            r.final_size = Some(end);
            if r.state == RecvState::Recv {
                r.state = RecvState::SizeKnown;
            }
        }
        // The preamble of a peer stream: the
        // frame at offset 0 carries it whole.
        let mut data = f.data;
        let mut data_offset = offset;
        let mut parsed = false;
        if preamble_in_use
            && peer_opened
            && r.preamble_size().is_none()
            && offset == 0
            && r.cold().stopped.is_none()
            && (len > 0 || f.fin)
        {
            if f.fin && end == 0 {
                return Err(violation(
                    T::PROTOCOL_VIOLATION,
                    ty,
                    "stream without a preamble",
                ));
            }
            let (p, size) = WirePreamble::parse(f.data, preamble_limit)
                .map_err(|e| Error::new(e.code(), ty, e.reason()))?;
            if let Some((_, reliable)) = r.cold().reset
                && reliable < size as u64
            {
                return Err(violation(
                    T::PROTOCOL_VIOLATION,
                    ty,
                    "Reliable Size below the preamble",
                ));
            }
            r.set_preamble_size(size);
            r.read_offset = size as u64;
            if r.contig < size as u64 {
                // Data held beyond the preamble becomes readable from its
                // end on.
                r.contig = size as u64;
            }
            // One copy holds OPEN_INFO and the application TLVs.
            if p.open_info.is_some() || !p.app_tlvs.is_empty() {
                let tlvs = p.app_tlvs.encoded();
                let at = |v: &[u8]| v.as_ptr() as usize - tlvs.as_ptr() as usize;
                let body = Bytes::copy_from_slice(tlvs);
                let e = s.extra_mut();
                e.open_info = p.open_info.map(|v| body.slice(at(v)..at(v) + v.len()));
                e.app_tlvs = (!p.app_tlvs.is_empty()).then_some(body);
            }
            // Ignored on a unidirectional stream.
            let carrier = p.pipe_carrier && dir == Dir::Bidi;
            if carrier || p.priority.is_some() {
                let e = s.extra_mut();
                e.pipe_carrier = carrier;
                e.peer_priority = p.priority;
            }
            if let (Some(p), Some(send)) = (p.priority, s.send.as_mut()) {
                send.priority = p;
            }
            data = &f.data[size..];
            data_offset = size as u64;
            parsed = true;
        } else if preamble_in_use && peer_opened && r.preamble_size().is_none() && mp {
            // Data before its preamble (multipath): held from offset 0.
        } else if let Some(size) = r.preamble_size()
            && data_offset < size
        {
            // A repeated frame at offset 0 (multipath): its preamble part is
            // known already.
            let skip = usize_sat(size - data_offset).min(data.len());
            data = &data[skip..];
            data_offset += skip as u64;
        }
        let stack_rejected = s.offer == Offer::Rejected;
        let r = s.recv.as_mut().expect("present");
        let discard = r.cold().stopped.is_some() || stack_rejected || r.end_read;
        // Bytes at or beyond a peer's Reliable Size are never delivered.
        let keep = match r.cold().reset {
            Some((_, reliable)) => {
                usize_sat(reliable.saturating_sub(data_offset).min(data.len() as u64))
            }
            None => data.len(),
        };
        let mut buffered = 0u64;
        let contig = r.contig;
        // Held bytes below the preamble's end (copies of preamble bytes that
        // arrived before it) leave the buffers once it is parsed.
        let mut trimmed = 0u64;
        if !discard && keep > 0 {
            if parsed {
                trimmed = r.pull_held(&mut self.receive);
            }
            buffered = r.store(&mut self.receive, data_offset, &data[..keep], source);
            self.recv_refs.referenced(usize_sat(buffered));
            let dup = keep as u64 - buffered;
            self.stats.bytes_duplicate_received += dup;
            if dup > 0
                && let Some(p) = self.atts.get_mut(self.rx).and_then(Attachment::inp_mut)
            {
                p.duplicate(dup);
            }
        } else if parsed {
            trimmed = r.pull_held(&mut self.receive);
        }
        // Release credit for the offsets in this frame, including when the
        // application has stopped reading and their payload is discarded.
        let previous_history = r.protected_history();
        let fresh = r.arrive(offset, end);
        let protected_history = r.protected_history();
        // Every byte stored is new; the others (preamble bytes, discarded
        // data) are consumed on arrival.
        let fresh_buffered = buffered.min(fresh);
        let fresh_consumed = fresh - fresh_buffered;
        if discard {
            r.read_offset = r.received.max(r.read_offset);
            r.contig = r.contig.max(r.read_offset);
        }
        let mut complete = false;
        if r.cold().reset.is_none() && r.final_size.is_some() {
            complete = r.final_size == Some(r.contig) || (discard && r.final_size.is_some());
            if complete {
                if discard {
                    r.state = RecvState::DataRead;
                } else if r.state == RecvState::SizeKnown {
                    r.state = RecvState::DataRecvd;
                }
            }
        }
        // A reader has something new only when the data it can read grew or
        // the end became known: data held beyond a gap (multipath) wakes
        // nobody until the gap fills.
        let readable = r.contig > contig || new_final || complete;
        let received = r.received;
        self.streams
            .replace_protected_history(previous_history, protected_history);
        self.credit_received(buffered, fresh_buffered, fresh_consumed);
        if trimmed > 0 {
            self.credit_consumed(trimmed);
        }
        if increase > 0 {
            self.autotune_data(key, received, now);
        }
        if parsed || discard {
            self.streams.check_stream_credit(key);
        }
        if parsed {
            self.offer(key);
        }
        if readable {
            self.notify_readable(key);
        }
        self.try_discard(key);
        Ok(())
    }

    fn on_reset_at(&mut self, f: ResetStreamAt, ty: u64, now: Instant) -> Result<(), Error> {
        self.on_reset(
            f.stream_id,
            f.error_code,
            f.final_size,
            Some(f.reliable_size),
            ty,
            now,
        )
    }

    fn on_reset(
        &mut self,
        id: u64,
        code: u64,
        final_size: u64,
        reliable: Option<u64>,
        ty: u64,
        now: Instant,
    ) -> Result<(), Error> {
        let key = match self.lookup(id, Part::Recv, ty)? {
            Lookup::Stream { key, .. } => key,
            Lookup::Discarded => return Ok(()),
        };
        self.flush_rejects(now);
        let preamble_in_use = self.features.preamble;
        let Some(s) = self.streams.get_mut(key) else {
            return Ok(());
        };
        let peer_opened = !s.local;
        let Some(r) = s.recv.as_mut() else {
            return Ok(());
        };
        let reliable_size = reliable.unwrap_or(0);
        if let Some(fs) = r.final_size
            && fs != final_size
        {
            return Err(violation(T::FINAL_SIZE_ERROR, ty, "final size changed")
                .detail(DetailKey::Stream, id)
                .detail(DetailKey::Value, final_size)
                .detail(DetailKey::Limit, fs));
        }
        if final_size < r.received {
            return Err(violation(
                T::FINAL_SIZE_ERROR,
                ty,
                "final size below the data received",
            )
            .detail(DetailKey::Stream, id)
            .detail(DetailKey::Value, final_size)
            .detail(DetailKey::Limit, r.received));
        }
        if final_size > r.limit {
            return Err(violation(
                T::FLOW_CONTROL_ERROR,
                ty,
                "final size beyond the stream limit",
            )
            .detail(DetailKey::Stream, id)
            .detail(DetailKey::Value, final_size)
            .detail(DetailKey::Limit, r.limit));
        }
        if let Some((old_code, old_reliable)) = r.cold().reset {
            if old_code != code {
                return Err(
                    violation(T::STREAM_STATE_ERROR, ty, "reset error code changed")
                        .detail(DetailKey::Stream, id)
                        .detail(DetailKey::Value, code),
                );
            }
            if reliable_size >= old_reliable {
                // NE-6: a repeat, or no reduction of the Reliable Size.
                if !r.state.is_terminal() {
                    self.charge_dup()?;
                }
                return Ok(());
            }
        }
        if preamble_in_use && peer_opened && r.cold().stopped.is_none() {
            if reliable.is_none() || final_size == 0 {
                return Err(violation(
                    T::PROTOCOL_VIOLATION,
                    ty,
                    "reset does not keep the preamble",
                ));
            }
            if let Some(p) = r.preamble_size()
                && reliable_size < p
            {
                return Err(violation(
                    T::PROTOCOL_VIOLATION,
                    ty,
                    "Reliable Size below the preamble",
                ));
            }
        }
        let before = r.counted();
        let increase = before.max(final_size) - before;
        let flow = self.streams.recv_flow();
        if !flow.admits(increase) {
            return Err(violation(
                T::FLOW_CONTROL_ERROR,
                ty,
                "session flow-control limit exceeded",
            )
            .detail(DetailKey::Stream, id)
            .detail(DetailKey::Value, flow.used + increase)
            .detail(DetailKey::Limit, flow.limit_sent));
        }
        self.streams.count_received(increase);
        let s = self.streams.get_mut(key).expect("present");
        let r = s.recv.as_mut().expect("present");
        r.final_size = Some(final_size);
        r.cold_mut().reset = Some((code, reliable_size));
        if !r.state.is_terminal() {
            r.state = RecvState::ResetRecvd;
        }
        // Unread data at or beyond the Reliable Size is never delivered.
        let dropped = r.drop_from(&mut self.receive, reliable_size.max(r.read_offset));
        if r.end_read || r.cold().stopped.is_some() {
            r.state = RecvState::ResetRead;
        }
        // Bytes at or above the Reliable Size that have not arrived never
        // will: their credit is released once, now, and data arriving later
        // releases none.
        let previous_history = r.protected_history();
        let lost = r.credit_reset(reliable_size, final_size);
        let protected_history = r.protected_history();
        self.streams
            .replace_protected_history(previous_history, protected_history);
        self.credit_received(0, 0, lost);
        self.credit_consumed(dropped);
        self.notify_readable(key);
        self.try_discard(key);
        Ok(())
    }

    fn on_stop_sending(&mut self, f: StopSending, ty: u64, now: Instant) -> Result<(), Error> {
        let key = match self.lookup(f.stream_id, Part::Send, ty)? {
            Lookup::Stream { key, .. } => key,
            Lookup::Discarded => return Ok(()),
        };
        self.flush_rejects(now);
        let Some(send) = self.streams.send_mut(key) else {
            return Ok(());
        };
        if send.state.is_terminal() {
            // Crossing a FIN or reset: not chargeable.
            return Ok(());
        }
        if send.cold().stopped.is_some() {
            return self.charge_dup();
        }
        send.cold_mut().stopped = Some(f.error_code);
        if send.outcome.is_none() || (send.outcome == Some(SendOutcome::Finished) && !send.fin_sent)
        {
            send.outcome = Some(SendOutcome::Stopped(f.error_code));
        }
        match send.cold().reset {
            Some(r) if r.written => {}
            Some(_) => {
                // A pending reset owes no more data once the peer stopped.
                if let Some(r) = send.reset_mut() {
                    r.reliable_app = None;
                    r.keep_preamble = false;
                }
                let unsent = send.buf.len();
                let before = send.unacked();
                send.buf.clear();
                if let Some(m) = send.mp.as_deref_mut() {
                    m.lost.clear();
                    m.fin_lost = false;
                }
                let freed = before - send.unacked();
                self.streams.drop_unsent(unsent);
                self.release_retained(freed);
                self.unschedule(key);
                self.streams.queue_ctrl(key);
            }
            None => self.respond_to_stop(key, f.error_code),
        }
        self.notify_writable(key);
        Ok(())
    }

    fn on_max_stream_data(&mut self, id: u64, maximum: u64, ty: u64) -> Result<(), Error> {
        let key = match self.lookup(id, Part::Send, ty)? {
            Lookup::Stream { key, .. } => key,
            Lookup::Discarded => return Ok(()),
        };
        let mp = self.per_pipe();
        let Some(send) = self.streams.send_mut(key) else {
            return Ok(());
        };
        if maximum > send.max_data {
            if mp && send.credit_blocked() {
                send.waits.age_mut().credit_at = Some(self.now);
            }
            send.max_data = maximum;
            // A pinned stream's opening frame is retried by `opening_ready`.
            self.schedule(key);
            // Credit changes the fair-share standing; it wakes only a
            // capacity wait that is over.
            self.sync_holder(key);
            self.check_capacity_wait(key);
            return Ok(());
        }
        if send.state.is_terminal() {
            return Ok(());
        }
        // NE-3.
        self.charge_dup()
    }

    fn on_stream_data_blocked(&mut self, id: u64, limit: u64, ty: u64) -> Result<(), Error> {
        let key = match self.lookup(id, Part::Recv, ty)? {
            Lookup::Stream { key, .. } => key,
            Lookup::Discarded => return Ok(()),
        };
        let Some(r) = self.streams.recv_mut(key) else {
            return Ok(());
        };
        if limit > r.limit_sent_max() {
            return Err(violation(
                T::PROTOCOL_VIOLATION,
                ty,
                "STREAM_DATA_BLOCKED above the advertised limit",
            )
            .detail(DetailKey::Stream, id)
            .detail(DetailKey::Value, limit)
            .detail(DetailKey::Limit, r.limit_sent_max()));
        }
        if r.state.is_terminal() {
            return Ok(());
        }
        if r.cold().blocked_seen.is_some_and(|b| limit <= b) {
            return self.charge_dup();
        }
        r.cold_mut().blocked_seen = Some(limit);
        self.streams.autotune_blocked(key, limit);
        self.streams.check_stream_credit(key);
        Ok(())
    }

    fn on_priority_update(&mut self, p: PriorityUpdate, ty: u64) -> Result<(), Error> {
        let key = match self.lookup(p.stream_id, Part::Send, ty)? {
            Lookup::Stream { key, .. } => key,
            Lookup::Discarded => return Ok(()),
        };
        let Some(send) = self.streams.send_mut(key) else {
            return Ok(());
        };
        if send.state.is_terminal() {
            return Ok(());
        }
        if send
            .cold()
            .peer_priority_seq
            .is_some_and(|last| p.sequence <= last)
        {
            // NE-7.
            return self.charge_dup();
        }
        send.cold_mut().peer_priority_seq = Some(p.sequence);
        send.priority = p.priority;
        self.reschedule(key);
        Ok(())
    }

    // ---- session frames --------------------------------------------------

    fn on_connection_close(&mut self, f: ConnectionClose<'_>, now: Instant) {
        // An orderly close waiting for the other lanes goes now.
        self.end_close_wait();
        let first = self.state < State::Closing;
        let reason = Bytes::copy_from_slice(f.reason);
        let err = if !f.application && self.acknowledged() && f.error_code == T::ZMUX_IDLE_TIMEOUT.0
        {
            // The peer's idle timeout in a session with acknowledgement.
            SessionError::IdleTimeout { remote: true }
        } else if f.application {
            SessionError::ApplicationClosed {
                code: varint(f.error_code),
                reason,
                remote: true,
            }
        } else if f.error_code == T::ZMUX_RESUME_FAILED.0 {
            SessionError::ResumeFailed {
                reason: super::error::split_reason(reason).0,
                remote: true,
            }
        } else {
            let (reason, details) = super::error::split_reason(reason);
            SessionError::TransportClosed {
                code: T(f.error_code),
                frame_type: f.frame_type,
                reason,
                details,
                remote: true,
            }
        };
        self.set_error(err);
        if first {
            self.peer_close_received();
        }
        // Answer with at most one CONNECTION_CLOSE.
        self.enter_closing(
            Some(CloseFrame::Transport {
                code: 0,
                frame_type: 0,
                reason: Bytes::new(),
            }),
            now,
        );
        self.peer_close_read(self.rx, now);
    }

    fn on_qx_ping(&mut self, p: QxPing, ty: u64, now: Instant) -> Result<(), Error> {
        if p.response {
            if self.ping.largest_sent.is_none_or(|s| p.sequence > s) {
                return Err(violation(
                    T::PROTOCOL_VIOLATION,
                    ty,
                    "QX_PING response to a request never sent",
                ));
            }
            let fresh = self.ping.peer_response.is_none_or(|r| p.sequence > r);
            if fresh {
                self.ping.peer_response = Some(p.sequence);
            }
            if let Some((seq, sent)) = self.ping.outstanding
                && p.sequence >= seq
            {
                self.ping.outstanding = None;
                let sample = now.saturating_duration_since(sent);
                self.loop_min.sample(now, sample, super::filter::LOOP_SPAN);
                let (srtt, rttvar) =
                    super::filter::smooth_rtt(self.srtt, self.ping.rttvar, sample, sample);
                self.ping.rttvar = Some(rttvar);
                self.single_ping_sample(sample, now);
                self.srtt = Some(srtt);
                self.session_rtt_sampled(now);
                self.ping.answered += 1;
                self.ping.latest = Some(sample);
                self.events
                    .push_back(CoreEvent::PingAnswered { rtt: sample });
            }
            if let Some(fence) = self.goaway().fence
                && p.sequence >= fence
            {
                self.fence_completed(now);
            }
            if !fresh {
                // NE-8: an outdated response.
                return self.charge_dup();
            }
            return Ok(());
        }
        if self.ping.peer_request.is_some_and(|r| p.sequence <= r) {
            if self.is_multipath() {
                // Stale: it crossed a later request on another pipe. Ignored,
                // neither answered nor charged.
                return Ok(());
            }
            return Err(
                violation(T::PROTOCOL_VIOLATION, ty, "QX_PING sequence not increasing")
                    .detail(DetailKey::Value, p.sequence),
            );
        }
        self.ping.peer_request = Some(p.sequence);
        // NE-2: chargeable only while the answer to an earlier request is
        // still owed (not yet handed to a carrier or committed to a pipe):
        // that answer is coalesced away. A request answered before the
        // next one arrives had an effect.
        let owed = self.ping.response_pending.replace(p.sequence).is_some();
        if owed { self.charge() } else { Ok(()) }
    }

    fn on_goaway(&mut self, g: GoAwayFrame, now: Instant) -> Result<(), Error> {
        let _ = now;
        let mut lowered = false;
        for (d, w) in [(BIDI, g.max_bidi), (UNI, g.max_uni)] {
            lowered |= self.streams.lower_goaway(d, w);
        }
        if !lowered {
            // NE-8.
            return self.charge_dup();
        }
        if self.state == State::Active {
            self.state = State::Draining;
        } else if self.state == State::Suspended {
            self.drain_after_suspension();
        }
        self.events.push_back(CoreEvent::GoAway {
            max_bidi: self.streams.local_dir(BIDI).goaway.unwrap_or(g.max_bidi),
            max_uni: self.streams.local_dir(UNI).goaway.unwrap_or(g.max_uni),
            code: g.error_code,
        });
        // Local streams that have neither emitted their first frame nor
        // been pinned never open: they fail with "going away". Emitted and pinned streams at or
        // above the watermark were not processed: "rejected"; a pinned one
        // below it still sends its opening frame.
        let keys: Vec<StreamKey> = self.streams.keys().collect();
        for k in keys {
            let Some(s) = self.streams.get_mut(k) else {
                continue;
            };
            if !s.local || s.goaway.is_some() {
                continue;
            }
            let Some(id) = s.id else {
                self.reject_unopened(k, stream::GoAwayFail::GoingAway);
                self.unschedule(k);
                self.try_discard(k);
                continue;
            };
            let d = di(s.dir);
            let open_pending = s.open_pending;
            if self
                .streams
                .local_dir(d)
                .goaway
                .is_some_and(|w| stream::index(id) >= w)
            {
                if open_pending {
                    // A pinned identifier above the watermark is never
                    // sent.
                    self.streams.unpin(d, k);
                    self.reject_unopened(k, stream::GoAwayFail::Rejected);
                    self.unschedule(k);
                    self.try_discard(k);
                    continue;
                }
                let Some(s) = self.streams.get_mut(k) else {
                    continue;
                };
                // Never processed by the peer.
                s.goaway = Some(stream::GoAwayFail::Rejected);
                let (mut unsent, mut freed) = (0, 0);
                if let Some(send) = s.send.as_mut() {
                    unsent = send.buf.len();
                    freed = send.unacked();
                    send.buf.clear();
                    if let Some(m) = send.mp.as_deref_mut() {
                        m.lost.clear();
                        m.fin_lost = false;
                    }
                    send.state = SendState::ResetRecvd;
                }
                if let Some(r) = s.recv.as_mut() {
                    r.state = RecvState::ResetRead;
                }
                self.streams.drop_unsent(unsent);
                self.release_retained(freed);
                self.unschedule(k);
                self.notify_readable(k);
                self.notify_writable(k);
                self.try_discard(k);
            }
        }
        // Dropped data freed send-buffer room.
        self.wake_send_waiters();
        for d in 0..2 {
            if self.streams.take_waiting(d) {
                self.events
                    .push_back(CoreEvent::StreamsAvailable(dir_of_index(d)));
            }
        }
        Ok(())
    }

    pub(super) fn on_datagram(
        &mut self,
        d: crate::proto::frame::Datagram<'_>,
        ty: u64,
        pipe: u64,
    ) -> Result<(), Error> {
        if !self.features.same_family {
            self.dgram_mut().counters.received += 1;
            let data = super::Chunk::copy_from_slice(d.data);
            self.datagram_arrived(None, None, data);
            return Ok(());
        }
        let (sequence, encoded_flow) = d.sequence_data()?;
        self.expire_waiting(self.now);
        let fresh = self.datagram_sequence_fresh(sequence);
        let checked = d
            .flow_data(encoded_flow)
            .and_then(|(flow, data)| Ok((flow, data, self.datagram_waits_for_open(flow, ty)?)));
        if !fresh && checked.is_err() {
            return Ok(());
        }
        let (flow, payload, waiting) = checked?;
        let channel = if self.rx_channel {
            crate::proto::frame::DatagramChannelKind::Native
        } else {
            crate::proto::frame::DatagramChannelKind::Record
        };
        self.note_datagram_arrival(pipe, channel, sequence, payload.len());
        if !fresh {
            return Ok(());
        }
        self.advance_datagram_sequence(sequence);
        let sequence = Some(sequence);
        let data = super::Chunk::copy_from_slice(payload);
        let accepted = match flow {
            Flow::Session => {
                self.dgram_mut().counters.received += 1;
                self.datagram_arrived(None, sequence, data)
            }
            Flow::Stream { stream_id, context } if waiting => {
                self.hold_datagram(stream_id, context, sequence, data)
            }
            Flow::Stream { stream_id, context } => {
                self.dgram_mut().counters.received += 1;
                self.stream_datagram_arrived(stream_id, context, sequence, data)
            }
        };
        self.occupy_datagram(sequence, accepted);
        Ok(())
    }

    fn datagram_waits_for_open(&self, flow: Flow, ty: u64) -> Result<bool, Error> {
        let Flow::Stream { stream_id, .. } = flow else {
            return Ok(false);
        };
        let index = stream::index(stream_id);
        let local = stream::client_initiated(stream_id)
            == matches!(self.role, crate::proto::params::Role::Client);
        if local {
            if index >= self.streams.local_dir(BIDI).next_index {
                return Err(violation(
                    T::PROTOCOL_VIOLATION,
                    ty,
                    "datagram for an unopened local stream",
                ));
            }
            return Ok(false);
        }
        let remote = self.streams.remote_dir(BIDI);
        if index >= remote.limit_sent {
            return Err(violation(
                T::PROTOCOL_VIOLATION,
                ty,
                "datagram for a stream beyond the limit",
            ));
        }
        Ok(index >= remote.opened)
    }

    /// A datagram for the opened stream `stream_id`: to its queue when the
    /// stream is usable, else dropped and counted.
    fn stream_datagram_arrived(
        &mut self,
        stream_id: u64,
        context: u64,
        sequence: Option<u64>,
        data: super::Chunk,
    ) -> bool {
        let key = self.streams.key_of(stream_id);
        let usable = key
            .and_then(|k| self.streams.get(k))
            .is_some_and(Stream::takes_datagrams);
        match key {
            Some(k) if usable => {
                if let Some(s) = self.streams.get_mut(k) {
                    s.datagrams_mut().counts.received += 1;
                }
                self.datagram_arrived(Some((k, context)), sequence, data)
            }
            _ => {
                self.drop_received_datagram(key.map(|k| (k, context)));
                false
            }
        }
    }

    /// Drops the datagrams queued for a stream whose receiving handle was
    /// released, unread: counted as dropped, their bytes leave the stream's
    /// and the session's accounting.
    pub(super) fn clear_stream_datagrams(&mut self, key: StreamKey) {
        let Some(s) = self.streams.get_mut(key) else {
            return;
        };
        let Some(q) = s.datagrams.as_mut() else {
            return;
        };
        let n = q.queue.len() as u64;
        let capacity = q
            .queue
            .iter()
            .map(|packet| packet.data.backing_capacity())
            .sum();
        q.queue.clear();
        q.bytes = 0;
        q.codel.idle();
        q.counts.dropped_recv += n;
        if n > 0 {
            super::debit(&mut self.dgram_mut().stream_bytes, capacity);
            self.count_dropped(n);
            self.refresh_stream_datagram_expiry(key);
        }
    }

    /// Holds a datagram for the peer stream `stream_id`, within the limit
    /// and not opened yet, until it opens or one smoothed RTT passed; it
    /// counts in the session's datagram bytes, where the oldest held ones
    /// make room first.
    fn hold_datagram(
        &mut self,
        stream_id: u64,
        context: u64,
        sequence: Option<u64>,
        data: super::Chunk,
    ) -> bool {
        let recv_bytes_cap = self.config.datagram_receive_bytes;
        let hold_packets = self.config.datagram_config().hold_packets;
        if hold_packets.is_some_and(|limit| self.dgram().waiting.len() >= limit) {
            self.count_dropped(1);
            return false;
        }
        let cost = data.len() + super::WAITING_COST;
        self.trim_waiting(cost);
        let d = self.dgram_mut();
        if d.recv_bytes + d.held_bytes + cost > recv_bytes_cap {
            self.count_dropped(1);
            return false;
        }
        let channel = self.rx_channel;
        let Some(until) = self
            .now
            .checked_add(
                self.config
                    .datagram_config()
                    .hold_time
                    .unwrap_or_else(|| self.rtt_or_default()),
            )
            .filter(|&until| until > self.now)
        else {
            self.count_dropped(1);
            return false;
        };
        let d = self.dgram_mut();
        d.recv_bytes += cost;
        d.waiting.push(
            super::WaitingDatagram {
                sequence,
                stream_id,
                context,
                data,
                channel,
            },
            until,
        );
        true
    }

    /// Drops the oldest datagrams held for streams not opened yet until
    /// `len` more bytes fit in the session's datagram bytes.
    fn trim_waiting(&mut self, len: usize) {
        let recv_bytes_cap = self.config.datagram_receive_bytes;
        let mut dropped = 0;
        let d = self.dgram_mut();
        while d.recv_bytes + d.held_bytes + len > recv_bytes_cap
            && let Some(old) = d.waiting.pop_front()
        {
            d.release_waiting_slot(&old);
            dropped += 1;
        }
        if dropped > 0 {
            self.count_dropped(dropped);
        }
    }

    /// Delivers the datagrams held for peer streams that opened, in
    /// arrival order.
    fn release_waiting(&mut self) {
        self.expire_waiting(self.now);
        let opened = self.streams.remote_dir(BIDI).opened;
        let Some(d) = self.dgram.as_deref_mut() else {
            return;
        };
        let ready: Vec<_> = d
            .waiting
            .take_opened(opened)
            .inspect(|w| super::debit(&mut d.recv_bytes, w.cost()))
            .collect();
        for w in ready {
            self.dgram_mut().counters.received += 1;
            if w.channel {
                self.dgram_mut().counters.received_channel += 1;
            }
            if !self.stream_datagram_arrived(w.stream_id, w.context, w.sequence, w.data) {
                self.occupy_datagram(w.sequence, false);
            }
        }
    }

    /// When the first datagram held for a stream not opened yet expires.
    pub(super) fn waiting_deadline(&self) -> Option<Instant> {
        self.dgram().waiting.deadline()
    }

    /// Drops the held datagrams whose stream did not open within one
    /// smoothed RTT.
    pub(super) fn expire_waiting(&mut self, now: Instant) {
        let mut dropped = 0;
        if let Some(d) = self.dgram.as_deref_mut() {
            while let Some(entry) = d.waiting.take_due(now) {
                d.release_waiting_slot(&entry);
                dropped += 1;
            }
        }
        if dropped > 0 {
            self.count_dropped(dropped);
        }
    }

    /// A datagram for the session (`stream` `None`) or for a stream and
    /// context: queued for the application at once without a receive
    /// limiter; with one, held for the driver, which asks the limiter
    /// outside the lock ([`SessionCore::take_received_datagrams`]). Every
    /// datagram held, whether waiting for the limiter
    /// or queued, counts in the session's datagram bytes: the oldest waiting ones make room, and
    /// one that still does not fit is dropped.
    fn datagram_arrived(
        &mut self,
        stream: Option<(StreamKey, u64)>,
        sequence: Option<u64>,
        data: super::Chunk,
    ) -> bool {
        let recv_bytes_cap = self.config.datagram_receive_bytes;
        if self.config.datagram_limiter.receive.is_none() {
            if stream.is_none() {
                self.trim_waiting(data.len());
            }
            return self.queue_received_datagram(stream, data);
        }
        self.trim_waiting(data.len());
        let len = data.len();
        let mut dropped = Vec::new();
        {
            let d = self.dgram_mut();
            while d.held_bytes + d.recv_bytes + len > recv_bytes_cap
                && let Some(old) = d.held.pop_front()
            {
                super::debit(&mut d.held_bytes, old.data.len());
                super::datagram::occupy_window(&mut d.window, old.sequence, false);
                dropped.push(old.stream);
            }
        }
        for old in dropped {
            self.drop_received_datagram(old);
        }
        let d = self.dgram_mut();
        if d.held_bytes + d.recv_bytes + len > recv_bytes_cap {
            self.drop_received_datagram(stream);
            return false;
        }
        d.held_bytes += data.len();
        d.held.push_back(super::ReceivedDatagram {
            sequence,
            stream,
            data,
            granted: None,
        });
        true
    }

    /// Queues a received datagram for the application; `false` when the
    /// queue refused it (dropped and counted).
    pub(super) fn queue_received_datagram(
        &mut self,
        stream: Option<(StreamKey, u64)>,
        data: super::Chunk,
    ) -> bool {
        match stream {
            None => self.queue_session_datagram(data.into_bytes()),
            Some((key, context)) => {
                let expires = self
                    .config
                    .datagram_config()
                    .receive_lifetime
                    .and_then(|lifetime| self.now.checked_add(lifetime));
                self.queue_stream_datagram(key, context, data, expires)
            }
        }
    }

    /// Drops a received datagram, counted (and on its stream).
    pub(super) fn drop_received_datagram(&mut self, stream: Option<(StreamKey, u64)>) {
        if let Some(s) = stream.and_then(|(k, _)| self.streams.get_mut(k)) {
            s.datagrams_mut().counts.dropped_recv += 1;
        }
        self.count_dropped(1);
    }

    /// Queues a session datagram: the oldest session datagrams make room
    /// (128 at most); one that still does not fit within the session's
    /// datagram bytes is dropped (`false`).
    fn queue_session_datagram(&mut self, data: Bytes) -> bool {
        let recv_queue = self.config.datagram_receive_queue;
        let recv_bytes_cap = self.config.datagram_receive_bytes;
        let mut dropped = 0;
        let held = self.dgram_mut().held_bytes;
        while (self.dgram_mut().recv.len() >= recv_queue
            || self.dgram_mut().recv_bytes + held + data.len() > recv_bytes_cap)
            && let Some((old, _)) = self.dgram_mut().recv.pop_front()
        {
            super::debit(&mut self.dgram_mut().recv_bytes, old.len());
            dropped += 1;
        }
        if self.dgram_mut().recv_bytes + held + data.len() > recv_bytes_cap {
            // Stream queues hold the bytes: drop the new one.
            self.count_dropped(dropped + 1);
            return false;
        }
        if dropped > 0 {
            self.count_dropped(dropped);
        }
        self.dgram_mut().recv_bytes += data.len();
        let at = self.now;
        let was_empty = self.dgram_mut().recv.is_empty();
        self.dgram_mut().recv.push_back((data, at));
        if was_empty {
            self.events.push_back(CoreEvent::DatagramReceived);
        }
        true
    }

    /// Queues a stream datagram within the stream's own two bounds, the
    /// count ([`Config::datagram_stream_queue`]) and the bytes
    /// ([`super::DatagramConfig::stream_receive_bytes`]): the stream's oldest datagrams
    /// make room until both hold, each counted as dropped; one larger than
    /// the bytes alone is kept alone. Stream queues do not count in the
    /// session's datagram bytes. `false` when the stream is gone.
    pub(super) fn queue_stream_datagram(
        &mut self,
        key: StreamKey,
        context: u64,
        data: super::Chunk,
        expires: Option<Instant>,
    ) -> bool {
        let stream_queue = self.config.datagram_stream_queue;
        let stream_bytes = self.config.datagram_config().stream_receive_bytes;
        let now = self.now;
        let mut dropped = 0;
        let len = data.len();
        let Some(s) = self.streams.get_mut(key) else {
            return false;
        };
        let s = s.datagrams_mut();
        let dgram = self.dgram.get_or_insert_with(Box::default);
        let mut refresh_expiry = expires.is_some();
        while (s.queue.len() >= stream_queue || stream_bytes.is_some_and(|cap| s.bytes + len > cap))
            && let Some(old) = s.queue.pop_front()
        {
            super::debit(&mut s.bytes, old.data.len());
            super::debit(&mut dgram.stream_bytes, old.data.backing_capacity());
            refresh_expiry |= old.expires.is_some();
            dropped += 1;
        }
        s.counts.dropped_recv += dropped;
        let was_empty = s.queue.is_empty();
        dgram.stream_bytes += data.backing_capacity();
        s.queue.push_back(stream::QueuedStreamDatagram {
            context,
            data,
            at: now,
            expires,
        });
        s.bytes += len;
        if dropped > 0 {
            self.count_dropped(dropped);
        }
        if refresh_expiry {
            self.refresh_stream_datagram_expiry(key);
        }
        if was_empty {
            self.events.push_back(CoreEvent::StreamDatagram(key));
        }
        true
    }

    pub(super) fn refresh_stream_datagram_expiry(&mut self, key: StreamKey) {
        let Some(queue) = self.streams.get_mut(key).and_then(|s| s.datagrams.as_mut()) else {
            return;
        };
        let next = queue.queue.iter().filter_map(|packet| packet.expires).min();
        let previous = std::mem::replace(&mut queue.expiry, next);
        if previous == next {
            return;
        }
        let index = &mut self.dgram_mut().stream_expiry;
        if let Some(at) = previous {
            index.remove(&(at, key));
        }
        if let Some(at) = next {
            index.insert((at, key));
        }
    }

    pub(super) fn expire_stream_datagrams(&mut self, now: Instant) {
        while let Some(&(at, key)) = self
            .dgram()
            .stream_expiry
            .first()
            .filter(|(at, _)| *at <= now)
        {
            self.dgram_mut().stream_expiry.remove(&(at, key));
            let Some(queue) = self.streams.get_mut(key).and_then(|s| s.datagrams.as_mut()) else {
                continue;
            };
            queue.expiry = None;
            let mut capacity = 0;
            let before = queue.queue.len();
            queue.queue.retain(|packet| {
                if packet.expires.is_some_and(|at| at <= now) {
                    queue.bytes -= packet.data.len();
                    capacity += packet.data.backing_capacity();
                    return false;
                }
                true
            });
            let expired = (before - queue.queue.len()) as u64;
            queue.counts.dropped_recv += expired;
            queue.counts.expired_recv += expired;
            if queue.queue.is_empty() {
                queue.codel.idle();
            }
            super::debit(&mut self.dgram_mut().stream_bytes, capacity);
            self.count_dropped(expired);
            self.refresh_stream_datagram_expiry(key);
        }
    }

    pub(super) fn count_dropped(&mut self, n: u64) {
        self.dgram_mut().counters.dropped_recv += n;
        if let Some(CoreEvent::DatagramsDropped { count }) = self
            .events
            .iter_mut()
            .rev()
            .find(|e| matches!(e, CoreEvent::DatagramsDropped { .. }))
        {
            *count += n;
            return;
        }
        self.events
            .push_back(CoreEvent::DatagramsDropped { count: n });
    }

    /// Rejects streams that opened above a GOAWAY watermark.
    fn flush_rejects(&mut self, now: Instant) {
        while let Some(k) = self.streams.take_reject() {
            self.stack_reject(k, now);
        }
    }

    /// A stream opened before establishment gets the peer's limits.
    pub(super) fn after_establish(&mut self, key: StreamKey) {
        let peer = self.peer_tp.as_ref();
        let bidi = peer.map_or(0, |p| p.window_bidi_remote);
        let uni = peer.map_or(0, |p| p.window_uni);
        if let Some(s) = self.streams.get_mut(key)
            && s.local
            && let Some(send) = s.send.as_mut()
        {
            send.max_data = match s.dir {
                Dir::Bidi => bidi,
                Dir::Uni => uni,
            };
        }
        self.schedule(key);
    }
}

/// The identifier of the peer's stream `index`; `client` tells whether the
/// peer is the initiator.
fn make_peer_id(index: u64, dir: Dir, client: bool) -> u64 {
    stream::make_id(index, dir, client)
}

impl RecvPart {
    /// The largest `MAX_STREAM_DATA` advertised.
    pub(crate) fn limit_sent_max(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests;
