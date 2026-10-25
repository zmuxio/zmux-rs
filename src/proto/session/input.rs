//! The receive path: records and frames from the peer.

use std::time::Instant;

use bytes::Bytes;

use super::pipes::{Attachment, Classified, FrameIn};
use super::stream::{self, Offer, RecvPart, RecvState, SendOutcome, SendState, Stream, StreamKey};
use super::{
    BIDI, CloseFrame, CoreEvent, DATAGRAM_RECV_BYTES, InState, LaneId, RECV_DATAGRAM_QUEUE,
    STREAM_DATAGRAM_QUEUE, SessionCore, SessionError, State, UNI, di, dir_of_index, varint,
    violation,
};
use crate::proto::frame::{
    ConnectionClose, Dir, Frame, GoAwayFrame, PriorityUpdate, QxPing, ResetStreamAt, StopSending,
};
use crate::proto::ident::Classifier;
use crate::proto::params::TransportParameters;
use crate::proto::payload::{Flow, WirePreamble};
use crate::proto::record::{Event as RecordEvent, Framing};
use crate::proto::{DetailKey, Error, Gates, TransportErrorCode as T};

/// Which part of a stream a frame refers to (SPEC.md Section 7.2).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    /// The local receiving part: STREAM, RESET_STREAM(_AT),
    /// STREAM_DATA_BLOCKED.
    Recv,
    /// The local sending part: MAX_STREAM_DATA, STOP_SENDING,
    /// PRIORITY_UPDATE.
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
        self.receive_inner(at.into(), data, now, false);
    }

    /// Applies the complete records at the start of `data` without
    /// copying and returns how many bytes were used. The driver keeps the
    /// rest (an incomplete record) and passes it again with more bytes
    /// appended; its buffer must hold `max_record_size + 4` bytes.
    pub fn receive_in_place(&mut self, at: impl Into<LaneId>, data: &[u8], now: Instant) -> usize {
        self.receive_inner(at.into(), data, now, true)
    }

    /// [`SessionCore::receive_in_place`] for bytes the driver read into a
    /// shared buffer `backing`: STREAM data of 4 KiB or more is kept as a
    /// reference to `data` instead of a copy.
    /// Backing identifiers grow with every new buffer: the received data
    /// that references older ones is copied out when it keeps more than
    /// twice its size alive.
    pub fn receive_shared(
        &mut self,
        at: impl Into<LaneId>,
        data: &Bytes,
        backing: super::Backing,
        now: Instant,
    ) -> usize {
        let at = at.into();
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
        self.rx_src = Some((data.clone(), backing));
        let used = self.receive_inner(at, data, now, true);
        self.rx_src = None;
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
        if refs.holders.is_empty() {
            refs.retired_at_most = 0;
            refs.referenced_at_least = 0;
            return;
        }
        let tally = &mut refs.tally;
        tally.clear();
        for &k in &refs.holders {
            if let Some(r) = self.streams.recv(k) {
                r.tally(&mut |b, n| tally.push((b.id, b.size, n)));
            }
        }
        tally.sort_unstable_by_key(|&(id, _, _)| id);
        tally.dedup_by(|b, a| {
            let same = a.0 == b.0;
            if same {
                a.2 += b.2;
            }
            same
        });
        let referenced: usize = tally.iter().map(|&(_, _, n)| n).sum();
        let current = &refs.current;
        tally.retain(|&(id, _, _)| !current.iter().any(|&(_, c)| c.id == id));
        let mut retired: usize = tally.iter().map(|&(_, size, _)| size).sum();
        let mut kept = referenced;
        let streams = &mut self.streams;
        if retired <= 2 * kept {
            refs.retired_at_most = retired;
            refs.referenced_at_least = kept;
            refs.holders
                .retain(|&k| streams.recv_mut(k).is_some_and(RecvPart::keep_listed));
            return;
        }
        // The least used first: each copied buffer frees its size for the
        // bytes it held.
        let used = |&(_, size, held): &(u64, usize, usize)| (held as u128, size as u128);
        tally.sort_unstable_by(|a, b| {
            let ((ha, sa), (hb, sb)) = (used(a), used(b));
            (ha * sb).cmp(&(hb * sa))
        });
        let mut n = 0;
        while retired > 2 * kept && n < tally.len() {
            let (_, size, held) = tally[n];
            retired -= size;
            kept -= held;
            n += 1;
        }
        refs.retired_at_most = retired;
        refs.referenced_at_least = kept;
        tally.truncate(n);
        tally.sort_unstable_by_key(|&(id, _, _)| id);
        let out = |id: u64| tally.binary_search_by_key(&id, |&(id, _, _)| id).is_ok();
        refs.holders
            .retain(|&k| streams.recv_mut(k).is_some_and(|r| r.copy_out(&out)));
    }

    /// The bytes of the retired read buffers that received data keeps
    /// alive, and the bytes it references in all read buffers.
    #[cfg(test)]
    pub(super) fn recv_bound(&self) -> (usize, usize) {
        let mut t = Vec::new();
        for &k in &self.recv_refs.holders {
            if let Some(r) = self.streams.recv(k) {
                r.tally(&mut |b, n| t.push((b.id, b.size, n)));
            }
        }
        let referenced = t.iter().map(|&(_, _, n)| n).sum();
        let current = &self.recv_refs.current;
        t.retain(|&(id, _, _)| !current.iter().any(|&(_, c)| c.id == id));
        t.sort_unstable_by_key(|&(id, _, _)| id);
        t.dedup_by_key(|&mut (id, _, _)| id);
        (t.iter().map(|&(_, size, _)| size).sum(), referenced)
    }

    /// One complete message from a message-framed pipe (SPEC.md Section
    /// 3.4), or lane of one.
    pub fn receive_message(&mut self, at: impl Into<LaneId>, message: &[u8], now: Instant) {
        let at = at.into();
        let pipe = at.pipe.0;
        self.tick(now);
        self.pick_input();
        if self.discarding() {
            return;
        }
        let Some(p) = self.inp_mut(pipe) else {
            return;
        };
        let Some(li) = p.lane_index(at.lane.0) else {
            return;
        };
        if p.framing() != Framing::Records || p.state() == InState::Ended {
            return;
        }
        if li == 0 && !p.classify_message(message) {
            self.protocol_error(Classifier::rejection_error(), now);
            return;
        }
        let Some(mut reader) = p.take_reader(li) else {
            return;
        };
        let result = reader.begin_message(message.len());
        if let Err(e) = result {
            if let Some(p) = self.inp_mut(pipe) {
                p.return_reader(li, reader);
            }
            self.protocol_error(e, now);
            return;
        }
        self.rx = pipe;
        self.rx_lane = li;
        let mut input = message;
        self.drain_reader(&mut reader, &mut input, now, false);
        if let Some(p) = self.inp_mut(pipe) {
            p.return_reader(li, reader);
        }
        self.stats.bytes_received += message.len() as u64;
    }

    fn receive_inner(&mut self, at: LaneId, data: &[u8], now: Instant, retain: bool) -> usize {
        let pipe = at.pipe.0;
        self.tick(now);
        self.pick_input();
        if self.discarding() {
            // Lingering discards what it reads (SPEC.md Section 6.5).
            return data.len();
        }
        let Some(p) = self.inp_mut(pipe) else {
            return data.len();
        };
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
        self.drain_reader(&mut reader, &mut input, now, retain);
        let ended = self
            .inp_mut(pipe)
            .is_none_or(|p| p.return_reader(li, reader));
        let used = if self.discarding() || ended {
            data.len()
        } else {
            data.len() - input.len()
        };
        if retain && let Some(p) = self.inp_mut(pipe) {
            // The driver holds an incomplete record (for `pipe_ended`).
            p.set_partial(li, used < data.len());
        }
        self.stats.bytes_received += if retain { used } else { data.len() } as u64;
        used
    }

    fn drain_reader(
        &mut self,
        reader: &mut crate::proto::RecordReader,
        input: &mut &[u8],
        now: Instant,
        retain: bool,
    ) {
        self.budget.refill(now);
        let (pipe, lane) = (self.rx, self.rx_lane);
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
            let result = match event {
                Ok(Some(RecordEvent::Frame(f))) => self.on_frame(f, now),
                Ok(Some(RecordEvent::RecordEnd { len })) => self.on_record_end(len, now),
                Ok(None) => return,
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                self.protocol_error(e, now);
            }
            if self.discarding()
                || self
                    .att(pipe)
                    .and_then(|a| a.inp())
                    .is_none_or(|p| p.state() == InState::Ended)
            {
                return;
            }
        }
    }

    /// Whether what arrives is discarded: the session is closing (SPEC.md
    /// Section 6.5), unless its orderly close waits for the other lanes,
    /// processing what it receives meanwhile.
    fn discarding(&self) -> bool {
        self.state >= State::Closing && !self.close_waiting()
    }

    /// The frames the local endpoint accepts now.
    fn receive_gates(&self) -> Gates {
        if self.peer_tp.is_some() {
            self.features.receive_gates(
                self.local_tp().reset_stream_at,
                self.local_tp().max_datagram_frame_size(),
            )
        } else {
            Gates {
                reset_stream_at: self.local_tp().reset_stream_at,
                max_datagram_frame_size: self.local_tp().max_datagram_frame_size(),
                ..Gates::NONE
            }
        }
    }

    fn charge(&mut self) -> Result<(), Error> {
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
    /// which multipath sessions never charge (SPEC.md Section 9.4.1).
    fn charge_dup(&mut self) -> Result<(), Error> {
        if self.mp.is_some() {
            return Ok(());
        }
        self.charge()
    }

    fn on_record_end(&mut self, len: u64, now: Instant) -> Result<(), Error> {
        self.stats.records_received += 1;
        let (id, li) = (self.rx, self.rx_lane);
        let Some(p) = self.inp_mut(id) else {
            return Ok(());
        };
        // A leading QX_TRANSPORT_PARAMETERS record on a pipe we joined
        // confirms nothing, is not counted and is not acknowledged
        // (MULTIPATH.md Section 5.7 step 3).
        let Some(padding_only) = p.record_closed(li) else {
            return Ok(());
        };
        if padding_only {
            // NE-1: a record of PADDING only.
            self.charge()?;
        }
        if self.mp.is_some() {
            self.mp_record_end(len, now);
        } else {
            let mut activity = false;
            if let Some(p) = self.inp_mut(id) {
                let (eliciting, act) = p.single_record(li, len);
                activity = act;
                self.single_record_end(len, eliciting, now);
            }
            // With acknowledgement only a record with an activity frame
            // counts; without it, every record (SPEC.md Section 6.4).
            if activity || !self.acknowledged() {
                self.restart_idle(now);
            }
        }
        Ok(())
    }

    fn on_frame(&mut self, frame: Frame<'_>, now: Instant) -> Result<(), Error> {
        let (id, li) = (self.rx, self.rx_lane);
        if li > 0 && self.inp_mut(id).is_some_and(|p| p.in_first_record(li)) {
            return self.on_lane_first_frame(&frame);
        }
        // Our join's first inbound record, which may be a leading
        // QX_TRANSPORT_PARAMETERS record to discard (MULTIPATH.md Section 5.7
        // step 3), also while the join itself is deferred.
        let (leading, deferred) = match self.att(id) {
            Some(a) if id != 0 && li == 0 && a.joiner_local() => {
                a.inp().map_or((false, false), |p| {
                    (p.leading_possible(), p.state() == InState::Deferred)
                })
            }
            _ => (false, false),
        };
        if !matches!(
            frame,
            Frame::Padding(_)
                | Frame::PipeAck(_)
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
        let (first, skip) = {
            let Some(p) = self.inp_mut(id) else {
                return Ok(());
            };
            let leading_tp = leading && matches!(frame, Frame::TransportParameters(_));
            let padding = matches!(frame, Frame::Padding(_));
            let eliciting = !matches!(
                frame,
                Frame::Padding(_) | Frame::PipeAck(_) | Frame::ConnectionClose(_)
            );
            let activity = matches!(
                frame,
                Frame::Stream(_)
                    | Frame::ResetStream(_)
                    | Frame::ResetStreamAt(_)
                    | Frame::StopSending(_)
                    | Frame::Datagram(_)
                    | Frame::QxPing(_)
            );
            match p.frame_in(li, leading_tp, padding, eliciting, activity) {
                FrameIn::Discarded => return Ok(()),
                FrameIn::Process { first, skip_join } => (first && id == 0 && li == 0, skip_join),
            }
        };
        if deferred {
            // The peer cannot know a deferred join: anything else on its
            // carrier is the carrier's fault, and only this join fails.
            self.fail_attachment(id, super::PipeFailure::Protocol, now);
            return Ok(());
        }
        if matches!(
            frame,
            Frame::Stream(_)
                | Frame::ResetStream(_)
                | Frame::ResetStreamAt(_)
                | Frame::StopSending(_)
                | Frame::Datagram(_)
        ) {
            self.note_traffic(now);
        }
        let ty = frame.frame_type().0;
        if skip && matches!(frame, Frame::PipeJoin(_)) {
            // The in-band PIPE_JOIN the listener verified (MULTIPATH.md 5.2).
            return Ok(());
        }
        if first && !matches!(frame, Frame::TransportParameters(_)) {
            return Err(violation(
                T::PROTOCOL_VIOLATION,
                ty,
                "first frame is not QX_TRANSPORT_PARAMETERS",
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
                let tp = TransportParameters::decode(f.block)
                    .map_err(|e| Error::new(e.code(), ty, e.reason()))?;
                self.on_peer_parameters(tp, now)
            }
            Frame::Stream(s) => self.on_stream(s, ty, now),
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
            Frame::Datagram(d) => self.on_datagram(d, ty),
            Frame::QxPing(p) => self.on_qx_ping(p, ty, now),
            Frame::GoAway(g) => self.on_goaway(g, now),
            Frame::PriorityUpdate(p) => self.on_priority_update(p, ty),
            // Multipath frames are only decoded when multipath is in use
            // (the receive gates).
            Frame::PipeJoin(_) => Err(violation(
                T::PROTOCOL_VIOLATION,
                ty,
                "PIPE_JOIN on a pipe of the session",
            )),
            // Decoded only while lanes are available toward us: anywhere but
            // first on a new lane (MULTIPATH.md Section 5.8).
            Frame::PipeLane(_) => Err(violation(
                T::PROTOCOL_VIOLATION,
                ty,
                "PIPE_LANE not first on a new lane",
            )),
            Frame::PipeAck(f) if self.mp.is_some() => self.on_pipe_ack(&f, now),
            Frame::PipeAck(f) if self.pipe_ack.is_some() => self.on_single_pipe_ack(&f, now),
            Frame::PipePing if self.mp.is_some() => {
                if let Some(p) = self.inp_mut(id) {
                    p.ping_in(li);
                }
                // NE-2.
                self.charge()
            }
            Frame::PipeAbandon(f) if self.mp.is_some() => {
                self.on_pipe_abandon(f.pipe_id, f.error_code, now)
            }
            Frame::PipeStatus(f) if self.mp.is_some() => self.on_pipe_status(
                f.pipe_id,
                f.sequence,
                f.status == crate::proto::frame::PipeStatusValue::Standby,
                f.priority,
            ),
            _ => Err(violation(
                T::FRAME_ENCODING_ERROR,
                ty,
                "frame of a feature not in use",
            )),
        }
    }

    // ---- streams ---------------------------------------------------------

    /// Finds or implicitly opens the stream a frame refers to (SPEC.md
    /// Section 7.2 rules 2 to 4).
    fn lookup(&mut self, id: u64, part: Part, ty: u64) -> Result<Lookup, Error> {
        let dir = stream::dir_of(id);
        let d = di(dir);
        let client = stream::client_initiated(id);
        let local = client == matches!(self.role, crate::proto::params::Role::Initiator);
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
        match dir {
            Dir::Bidi => {
                let send_max = peer.map_or(0, |p| p.window_bidi_local);
                s.send = Some(self.streams.new_send_part(send_max));
                s.recv = Some(
                    self.streams
                        .new_recv_part(local.window_bidi_remote, max_window),
                );
            }
            Dir::Uni => {
                s.recv = Some(self.streams.new_recv_part(local.window_uni, max_window));
            }
        }
        self.stats.streams_opened_remote += 1;
        self.streams.insert_peer(id, di(dir), s)
    }

    /// Offers peer stream `key` if it is ready (SPEC.md Section 7.2 rule 5).
    pub(super) fn offer(&mut self, key: StreamKey) {
        let preamble = self.features.preamble;
        self.streams.offer(key, preamble, &mut self.events);
    }

    fn on_stream(
        &mut self,
        f: crate::proto::frame::Stream<'_>,
        ty: u64,
        now: Instant,
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
        // Single pipe: data arrives in order, without gaps or repeats
        // (SPEC.md Section 7.3). Multipath: any order, duplicates allowed.
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
        let (s, spare) = self.streams.stream_and_spare(key).expect("present");
        let r = s.recv.as_mut().expect("present");
        r.received = r.received.max(end);
        if f.fin {
            r.final_size = Some(end);
            if r.state == RecvState::Recv {
                r.state = RecvState::SizeKnown;
            }
        }
        // The preamble of a peer stream (EXTENSIONS.md Section 4.4): the
        // frame at offset 0 carries it whole.
        let mut data = f.data;
        let mut data_offset = offset;
        let mut parsed = false;
        if preamble_in_use
            && peer_opened
            && r.preamble_size.is_none()
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
            r.preamble_size = Some(size as u64);
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
            // Ignored on a unidirectional stream (EXTENSIONS.md 4.3).
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
        } else if preamble_in_use && peer_opened && r.preamble_size.is_none() && mp {
            // Data before its preamble (multipath): held from offset 0.
        } else if let Some(size) = r.preamble_size
            && data_offset < size
        {
            // A repeated frame at offset 0 (multipath): its preamble part is
            // known already.
            let skip = ((size - data_offset) as usize).min(data.len());
            data = &data[skip..];
            data_offset += skip as u64;
        }
        let stack_rejected = s.offer == Offer::Rejected;
        let r = s.recv.as_mut().expect("present");
        let discard = r.cold().stopped.is_some() || stack_rejected || r.end_read;
        // Bytes at or beyond a peer's Reliable Size are never delivered.
        let keep = match r.cold().reset {
            Some((_, reliable)) => {
                reliable.saturating_sub(data_offset).min(data.len() as u64) as usize
            }
            None => data.len(),
        };
        let mut buffered = 0u64;
        let mut settle = false;
        let contig = r.contig;
        // Held bytes below the preamble's end (copies of preamble bytes that
        // arrived before it) leave the buffers once it is parsed.
        let mut trimmed = 0u64;
        if !discard && keep > 0 {
            if parsed {
                trimmed = r.pull_held();
            }
            if r.buf.storage_capacity() == 0
                && let Some(b) = spare.take_drained()
            {
                r.buf.give_storage(b);
            }
            let src = self.rx_src.as_ref().map(|(b, k)| (b, *k));
            let before = r.referenced();
            buffered = r.store(data_offset, &data[..keep], src);
            // What it now references counts towards the bound's estimate
            // (held data moved to the flat store references less).
            let after = r.referenced();
            self.recv_refs.referenced(after.saturating_sub(before));
            settle |= self.recv_refs.consumed(before.saturating_sub(after) as u64);
            if r.needs_listing() {
                self.recv_refs.holders.push(key);
            }
            let dup = keep as u64 - buffered;
            self.stats.bytes_duplicate += dup;
            if dup > 0
                && let Some(p) = self.atts.get_mut(self.rx).and_then(Attachment::inp_mut)
            {
                p.duplicate(dup);
            }
        } else if parsed {
            trimmed = r.pull_held();
        }
        // Session credit: each byte once, when it arrives (SPEC.md Section
        // 8.3), below the bytes a reset released. Bytes beyond a gap
        // release nothing before they arrive; a part that discards its data
        // counts every byte below the frame's end as arrived.
        let fresh = if discard {
            r.arrive(0, end)
        } else {
            r.arrive(offset, end)
        };
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
        if settle {
            self.settle_recv_refs();
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
            if let Some(p) = r.preamble_size
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
        let dropped = r.drop_from(reliable_size.max(r.read_offset));
        if r.end_read || r.cold().stopped.is_some() {
            r.state = RecvState::ResetRead;
        }
        // Bytes at or above the Reliable Size that have not arrived never
        // will: their credit is released once, now, and data arriving later
        // releases none (SPEC.md Section 8.3).
        let lost = r.credit_reset(reliable_size, final_size);
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
                if let Some(mp) = self.mp.as_deref_mut() {
                    mp.release(freed);
                }
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
        let mp = self.mp.is_some();
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
        // An orderly close waiting for the other lanes goes now (SPEC.md
        // Section 6.5 step 1).
        self.end_close_wait();
        let reason = Bytes::copy_from_slice(f.reason);
        let err = if !f.application && self.acknowledged() && f.error_code == T::ZMUX_IDLE_TIMEOUT.0
        {
            // The peer's idle timeout in a session with acknowledgement
            // (SPEC.md 6.4).
            SessionError::IdleTimeout { remote: true }
        } else if f.application {
            SessionError::ApplicationClosed {
                code: varint(f.error_code),
                reason,
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
        // Answer with at most one CONNECTION_CLOSE (SPEC.md Section 6.5).
        self.enter_closing(
            Some(CloseFrame::Transport {
                code: 0,
                frame_type: 0,
                reason: Bytes::new(),
            }),
            now,
        );
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
                if self.mp.is_none() {
                    self.quality_sample(0, now);
                }
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
            if self.mp.is_some() {
                // Stale: it crossed a later request on another pipe. Ignored,
                // neither answered nor charged (SPEC.md Sections 4.5, 9.4.1).
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
        // next one arrives had an effect (SPEC.md Section 4.5).
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
        } else if self.state == State::Suspended
            && let Some(mp) = self.mp.as_deref_mut()
        {
            mp.suspension_mut().drain_after();
        }
        self.events.push_back(CoreEvent::GoAway {
            max_bidi: self.streams.local_dir(BIDI).goaway.unwrap_or(g.max_bidi),
            max_uni: self.streams.local_dir(UNI).goaway.unwrap_or(g.max_uni),
            code: g.error_code,
        });
        // Local streams that have neither emitted their first frame nor
        // been pinned never open: they fail with "going away" (EXTENSIONS.md
        // Section 3.5 rule 2). Emitted and pinned streams at or above the
        // watermark were not processed: "rejected" (rule 3); a pinned one
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
                // Never processed by the peer (EXTENSIONS.md Section 3.4).
                s.goaway = Some(stream::GoAwayFail::Rejected);
                let mut unsent = 0;
                if let Some(send) = s.send.as_mut() {
                    unsent = send.buf.len();
                    let freed = send.unacked();
                    send.buf.clear();
                    if let Some(m) = send.mp.as_deref_mut() {
                        m.lost.clear();
                        m.fin_lost = false;
                    }
                    send.state = SendState::ResetRecvd;
                    if let Some(mp) = self.mp.as_deref_mut() {
                        mp.release(freed);
                    }
                }
                if let Some(r) = s.recv.as_mut() {
                    r.state = RecvState::ResetRead;
                }
                self.streams.drop_unsent(unsent);
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

    fn on_datagram(&mut self, d: crate::proto::frame::Datagram<'_>, ty: u64) -> Result<(), Error> {
        self.stats.datagrams_received += 1;
        if !self.features.datagram_flows {
            self.datagram_arrived(None, d.data);
            return Ok(());
        }
        let (flow, payload) =
            Flow::parse(d.data).map_err(|e| Error::new(e.code(), ty, e.reason()))?;
        match flow {
            Flow::Session => {
                self.datagram_arrived(None, payload);
                Ok(())
            }
            Flow::Stream { stream_id, context } => {
                let client = stream::client_initiated(stream_id);
                let local = client == matches!(self.role, crate::proto::params::Role::Initiator);
                let index = stream::index(stream_id);
                if local {
                    if index >= self.streams.local_dir(BIDI).next_index {
                        return Err(violation(
                            T::PROTOCOL_VIOLATION,
                            ty,
                            "datagram for an unopened local stream",
                        ));
                    }
                } else if index >= self.streams.remote_dir(BIDI).limit_sent {
                    return Err(violation(
                        T::PROTOCOL_VIOLATION,
                        ty,
                        "datagram for a stream beyond the limit",
                    ));
                }
                let key = self.streams.key_of(stream_id);
                let usable = key.and_then(|k| self.streams.get(k)).is_some_and(|s| {
                    !s.released && !s.parts_terminal() && s.offer != Offer::Rejected
                });
                match key {
                    Some(k) if usable => {
                        if let Some(s) = self.streams.get_mut(k) {
                            s.datagrams_mut().counts.received += 1;
                        }
                        self.datagram_arrived(Some((k, context)), payload);
                    }
                    _ => self.count_dropped(1),
                }
                Ok(())
            }
        }
    }

    /// A datagram for the session (`stream` `None`) or for a stream and
    /// context: queued for the application at once without a receive
    /// limiter; with one, held for the driver, which asks the limiter
    /// outside the lock ([`SessionCore::take_received_datagrams`]). Every
    /// datagram held, whether waiting for the limiter
    /// or queued, counts in the session's datagram bytes (EXTENSIONS.md
    /// Section 6.5): the oldest waiting ones make room, and one that still
    /// does not fit is dropped.
    fn datagram_arrived(&mut self, stream: Option<(StreamKey, u64)>, payload: &[u8]) {
        let data = Bytes::copy_from_slice(payload);
        if self.config.datagram_limiter.receive.is_none() {
            self.queue_received_datagram(stream, data);
            return;
        }
        let len = data.len();
        let mut dropped = Vec::new();
        {
            let d = self.dgram_mut();
            while d.held_bytes + d.recv_bytes + len > DATAGRAM_RECV_BYTES
                && let Some(old) = d.held.pop_front()
            {
                d.held_bytes -= old.data.len();
                dropped.push(old.stream);
            }
        }
        for old in dropped {
            self.drop_received_datagram(old);
        }
        let d = self.dgram_mut();
        if d.held_bytes + d.recv_bytes + len > DATAGRAM_RECV_BYTES {
            self.drop_received_datagram(stream);
            return;
        }
        self.dgram_mut().held_bytes += data.len();
        self.dgram_mut().held.push_back(super::ReceivedDatagram {
            stream,
            data,
            allowed: false,
        });
    }

    /// Queues a received datagram for the application.
    pub(super) fn queue_received_datagram(
        &mut self,
        stream: Option<(StreamKey, u64)>,
        data: Bytes,
    ) {
        match stream {
            None => self.queue_session_datagram(data),
            Some((key, context)) => self.queue_stream_datagram(key, context, data),
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
    /// datagram bytes is dropped.
    fn queue_session_datagram(&mut self, data: Bytes) {
        let mut dropped = 0;
        let held = self.dgram_mut().held_bytes;
        while (self.dgram_mut().recv.len() >= RECV_DATAGRAM_QUEUE
            || self.dgram_mut().recv_bytes + held + data.len() > DATAGRAM_RECV_BYTES)
            && let Some(old) = self.dgram_mut().recv.pop_front()
        {
            self.dgram_mut().recv_bytes -= old.len();
            dropped += 1;
        }
        if self.dgram_mut().recv_bytes + held + data.len() > DATAGRAM_RECV_BYTES {
            // Stream queues hold the bytes: drop the new one.
            self.count_dropped(dropped + 1);
            return;
        }
        if dropped > 0 {
            self.count_dropped(dropped);
        }
        self.dgram_mut().recv_bytes += data.len();
        let was_empty = self.dgram_mut().recv.is_empty();
        self.dgram_mut().recv.push_back(data);
        if was_empty {
            self.events.push_back(CoreEvent::DatagramReceived);
        }
    }

    /// Queues a stream datagram: the stream's oldest datagrams make room
    /// (32 at most); one that still does not fit within the session's
    /// datagram bytes is dropped, so every queue together stays bounded.
    fn queue_stream_datagram(&mut self, key: StreamKey, context: u64, data: Bytes) {
        let mut dropped = 0;
        let len = data.len();
        let Some(s) = self.streams.get_mut(key) else {
            return;
        };
        let s = s.datagrams_mut();
        let dgram = self.dgram.get_or_insert_with(Box::default);
        let held = dgram.held_bytes;
        while (s.queue.len() >= STREAM_DATAGRAM_QUEUE
            || dgram.recv_bytes + held + len > DATAGRAM_RECV_BYTES)
            && let Some((_, old)) = s.queue.pop_front()
        {
            dgram.recv_bytes -= old.len();
            dropped += 1;
        }
        if dgram.recv_bytes + held + len > DATAGRAM_RECV_BYTES {
            s.counts.dropped_recv += dropped + 1;
            self.count_dropped(dropped + 1);
            return;
        }
        s.counts.dropped_recv += dropped;
        let was_empty = s.queue.is_empty();
        s.queue.push_back((context, data));
        dgram.recv_bytes += len;
        if dropped > 0 {
            self.count_dropped(dropped);
        }
        if was_empty {
            self.events.push_back(CoreEvent::StreamDatagram(key));
        }
    }

    pub(super) fn count_dropped(&mut self, n: u64) {
        self.stats.datagrams_dropped_recv += n;
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
    /// The largest MAX_STREAM_DATA advertised.
    pub(crate) fn limit_sent_max(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests;
