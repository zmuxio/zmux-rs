//! Datagrams on a carrier's datagram channel.
//!
//! A pipe carrier may have an unreliable datagram service of its own: QUIC
//! datagrams of the connection a QUIC stream pipe belongs to, the HTTP
//! Datagrams of an HTTP/3 request stream, the datagrams of a WebTransport
//! session. The driver tells the core about it
//! ([`SessionCore::set_pipe_channel`]); when both endpoints negotiated
//! `zmux_carrier_datagrams`, the core decides per DATAGRAM frame whether it
//! goes on the channel of the pipe it would otherwise go to (it fits the
//! channel's structural capacity) or in a record,
//! and hands channel datagrams to the driver
//! ([`SessionCore::poll_channel`]), which sends them on a task of the pipe
//! so that they never wait behind a batch. Received ones are processed by
//! [`SessionCore::receive_channel_datagram`] with the rules of records,
//! without the accounting of records: no `PIPE_ACK` position, no no-effect
//! budget, no idle timer restart. The sizes, queues and limiters of
//! datagrams are unchanged.

use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};

use super::datagram::{DatagramDrop, DatagramRoute, ReplicaDegradation};
use super::pipes::{Channel, InState};
use super::shaping::{DatagramView, RuntimeReason, UnitPlan};
use super::{CoreEvent, PipeId, SessionCore, State, StreamKey};
use crate::proto::frame::{DatagramPrefix, FrameType, channel};
use crate::proto::payload::Flow;

/// A handoff to a native datagram channel and its accounting token.
#[derive(Debug)]
pub struct NativeDatagram {
    pub bytes: Bytes,
    pub outcome: NativeDatagramOutcome,
}

/// The local outcome of a handoff to a carrier datagram channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeDatagramResult {
    /// The carrier took ownership.
    Accepted,
    /// The carrier returned an error.
    Rejected,
    /// The unit reached its deadline before the carrier took it.
    Expired,
    /// The channel was shut down before it took the unit.
    Cancelled,
    /// The carrier's terminal acceptance is unknown.
    Unresolved,
}

/// Identifies a single channel handoff until the carrier completes it.
#[derive(Debug)]
pub struct NativeDatagramOutcome {
    pub(super) sequence: u64,
    flow: Flow,
    bytes: u64,
    queue_bytes: usize,
    wire_len: usize,
    pad: usize,
    dispatch: super::shape_ledger::Dispatch,
    replica: bool,
    generation: Option<u64>,
    pub expiry: Option<Instant>,
    #[cfg(all(feature = "tokio", not(loom)))]
    handoff: Option<super::splice_handoff::HandoffSpan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeUnit {
    Original(u64),
    Replica(u64),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NativePlan {
    pipe: u64,
    key: NativeUnit,
    unit: UnitPlan,
    ready: Instant,
    generation: u64,
    reserved: u64,
}

#[derive(Debug, Default)]
pub(super) struct NativePlans {
    entries: Vec<NativePlan>,
    deadlines: super::deadline::Deadlines<u64>,
}

impl NativePlans {
    pub(super) fn heap_bytes(&self) -> usize {
        size_of::<Self>()
            + self.entries.capacity() * size_of::<NativePlan>()
            + self.deadlines.heap_bytes()
    }

    fn insert(&mut self, plan: NativePlan) {
        self.deadlines.set(plan.pipe, Some(plan.ready));
        self.entries.push(plan);
    }

    fn remove(&mut self, pipe: u64) -> Option<NativePlan> {
        self.deadlines.set(pipe, None);
        let index = self.entries.iter().position(|plan| plan.pipe == pipe)?;
        Some(self.entries.swap_remove(index))
    }
}

impl NativeDatagram {
    #[cfg(all(feature = "tokio", not(loom)))]
    fn with_splice_handoff(mut self, handoff: Option<super::splice_handoff::HandoffSpan>) -> Self {
        self.outcome.handoff = handoff;
        self
    }

    fn new(
        route_prefix: channel::Prefix,
        prefix: DatagramPrefix,
        data: &Bytes,
        (pad, dispatch): (usize, super::shape_ledger::Dispatch),
        generation: Option<u64>,
        expiry: Option<Instant>,
        replica: bool,
    ) -> Self {
        let DatagramPrefix::Sequenced { sequence, flow } = prefix else {
            unreachable!("native channels require a sequenced session");
        };
        let id = route_prefix.id();
        let size = channel::datagram_len(id, prefix.encoded_len() + data.len()) + pad;
        let mut buf = BytesMut::with_capacity(size);
        let mut header = [0u8; 9 + 24];
        let first = channel::encode_header(id, &mut header).expect("sized channel header");
        let len = first
            + prefix
                .encode(&mut header[first..])
                .expect("sized datagram prefix");
        let id_end = first - 1;
        buf.put_slice(&header[..id_end]);
        if pad != 0 {
            buf.put_bytes(0, pad);
        }
        buf.put_slice(&header[id_end..len]);
        buf.put_slice(data);
        Self {
            bytes: buf.freeze(),
            outcome: NativeDatagramOutcome {
                sequence,
                flow,
                bytes: data.len() as u64,
                queue_bytes: data.len() + if replica { prefix.encoded_len() } else { 0 },
                wire_len: size - route_prefix.outer_bytes(),
                pad,
                dispatch,
                replica,
                generation,
                expiry,
                #[cfg(all(feature = "tokio", not(loom)))]
                handoff: None,
            },
        }
    }
}

impl SessionCore {
    /// Records a native channel on `pipe`. The structural capacity and writable
    /// room both include the encoded routing prefix. The driver calls it again whenever
    /// it learns a new maximum, and owns the channel's I/O: it sends what
    /// [`SessionCore::poll_channel`] returns and passes what arrives to
    /// [`SessionCore::receive_channel_datagram`].
    ///
    /// Given for the bootstrap pipe before its first transmit, it makes a
    /// session with datagrams enabled send `zmux_carrier_datagrams` (a
    /// multipath session sends it anyway: a pipe it joins may have a
    /// channel).
    pub fn set_pipe_channel(
        &mut self,
        pipe: PipeId,
        prefix: impl Into<channel::Prefix>,
        capacity: usize,
        room: usize,
    ) {
        if pipe == PipeId(0) && self.config.enable_datagrams {
            self.local.carrier_datagrams = true;
        }
        let Some(o) = self.out_ref(pipe.0) else {
            return;
        };
        let prefix = prefix.into();
        let new = Channel {
            prefix,
            capacity,
            room: room.min(capacity),
        };
        if o.channel() == Some(new) {
            return;
        }
        let old = o.channel();
        let changed_id = old.is_some_and(|old| old.prefix != prefix);
        self.out_mut(pipe.0).expect("pipe").set_channel(new);
        if changed_id {
            self.reset_datagram_outbound((
                pipe.0,
                crate::proto::frame::DatagramChannelKind::Native,
            ));
        }
        if changed_id
            || self
                .native_plan(pipe.0)
                .is_some_and(|plan| !self.native_plan_fits(pipe.0, plan.key, new.room))
        {
            self.clear_native_plan(pipe.0);
        }
        self.constrain_native_flow(pipe.0);
        // A larger maximum may take queued datagrams.
        self.channel_kick();
        self.note_datagram_path();
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn stop_pipe_channel(&mut self, pipe: PipeId) {
        if let Some(out) = self.out_mut(pipe.0)
            && out.clear_channel()
        {
            self.clear_native_plan(pipe.0);
            self.reset_datagram_outbound((
                pipe.0,
                crate::proto::frame::DatagramChannelKind::Native,
            ));
            self.channel_kick();
            self.note_datagram_path();
        }
    }

    /// Changes whenever datagrams were queued that may go on a channel, or
    /// the channels' pipes changed: a driver's channel task that polled
    /// [`SessionCore::poll_channel`] waits for it to change (it is woken by
    /// [`CoreEvent::ChannelDatagrams`] and by the pipe events).
    pub fn channel_generation(&self) -> u64 {
        self.dgram().channel_gen
    }

    /// Whether the datagram channel of `pipe` may still be used: its
    /// outbound pipe is live, the session is not closed, and the peer did
    /// not establish the session without the channel. Once it is false, the
    /// driver ends the channel's task.
    pub fn channel_live(&self, pipe: PipeId) -> bool {
        self.state < State::Closing
            && (!self.is_established()
                || self.features.carrier_datagrams
                    && self
                        .out_ref(pipe.0)
                        .is_some_and(|o| o.channel().is_some() && o.is_live()))
    }

    /// Hands selected datagrams to the native writer. The writer reports each
    /// outcome with [`Self::channel_done`].
    pub fn poll_channel(
        &mut self,
        pipe: PipeId,
        out: &mut Vec<NativeDatagram>,
        now: Instant,
    ) -> bool {
        self.tick(now);
        if !self.channel_live(pipe) {
            self.clear_native_plan(pipe.0);
            return false;
        }
        self.note_datagram_path();
        self.prepare_datagram_dispatch();
        let Some(ch) = self.channel_for(pipe.0) else {
            self.clear_native_plan(pipe.0);
            return true;
        };
        let route = DatagramRoute::Native(pipe.0);
        let planned = self.shape_activate(pipe.0);
        if let Some(plan) = self.native_plan(pipe.0)
            && self.shape_instance(pipe.0) != Some(plan.generation)
        {
            self.clear_native_plan(pipe.0);
        }
        self.constrain_native_flow(pipe.0);
        loop {
            let pending = self.native_plan(pipe.0);
            if pending.is_some_and(|plan| self.now < plan.ready) {
                return true;
            }
            let found = match pending.map(|p| p.key) {
                Some(NativeUnit::Original(tag)) => self.reserved_native_original(pipe.0, tag),
                Some(NativeUnit::Replica(_)) => None,
                None => self.next_datagram_flow(route).map(|(i, _)| i),
            };
            if let Some(i) = found {
                if self.send_delay_drop(i) {
                    self.clear_native_plan(pipe.0);
                } else {
                    self.native_original(pipe, ch, i, out);
                    if planned {
                        return true;
                    }
                }
                continue;
            }
            let required = match pending.map(|p| p.key) {
                Some(NativeUnit::Replica(sequence)) => Some(sequence),
                Some(NativeUnit::Original(_)) => {
                    self.clear_native_plan(pipe.0);
                    continue;
                }
                None => None,
            };
            if !self.native_replica(pipe, ch, required, out) {
                if pending.is_some() {
                    self.clear_native_plan(pipe.0);
                    continue;
                }
                break;
            }
            if planned {
                break;
            }
        }
        true
    }

    fn native_original(
        &mut self,
        pipe: PipeId,
        ch: Channel,
        i: usize,
        out: &mut Vec<NativeDatagram>,
    ) {
        let packet = self.dgram().send.get(i).expect("selected flow head");
        let Some(prefix) = self.next_datagram_prefix(packet.flow) else {
            return;
        };
        let key = NativeUnit::Original(packet.tag);
        let stream = packet.flow.map(|(id, _)| id);
        let (len, expiry, prior) = (packet.data.len(), packet.deadline, packet.shape_held);
        let base = channel::datagram_len(ch.prefix.id(), prefix.encoded_len() + len);
        let Some(pad) = self.native_padding(pipe, ch, key, base, expiry, prior) else {
            return;
        };
        self.dgram_mut().send.begin_native(stream, len);
        let packet = self.take_send_datagram(i).expect("selected flow head");
        let generation = self.shape_instance(pipe.0);
        let dispatch = self.commit_shape_bytes(pad as u64);
        let datagram = NativeDatagram::new(
            ch.prefix,
            prefix,
            &packet.data,
            (pad, dispatch),
            generation,
            expiry,
            false,
        );
        #[cfg(all(feature = "tokio", not(loom)))]
        let datagram = datagram.with_splice_handoff(packet.handoff.clone());
        out.push(datagram);
        self.datagram_dispatched(DatagramRoute::Native(pipe.0), &packet);
    }

    fn native_replica(
        &mut self,
        pipe: PipeId,
        ch: Channel,
        sequence: Option<u64>,
        out: &mut Vec<NativeDatagram>,
    ) -> bool {
        let route = DatagramRoute::Native(pipe.0);
        let Some((i, copy)) = self.next_datagram_replica_for(route, sequence) else {
            return false;
        };
        let prefix = copy.prefix;
        let DatagramPrefix::Sequenced { sequence, .. } = prefix else {
            unreachable!("only sequenced datagrams have replicas");
        };
        let (data, expiry, prior) = (copy.data.clone(), copy.deadline, copy.shape_held);
        #[cfg(all(feature = "tokio", not(loom)))]
        let handoff = copy.handoff.clone();
        let base = channel::datagram_len(ch.prefix.id(), prefix.encoded_len() + data.len());
        let key = NativeUnit::Replica(sequence);
        if let Some(pad) = self.native_padding(pipe, ch, key, base, expiry, prior) {
            let dispatch = self.commit_shape_bytes(pad as u64);
            let datagram = NativeDatagram::new(
                ch.prefix,
                prefix,
                &data,
                (pad, dispatch),
                None,
                expiry,
                true,
            );
            #[cfg(all(feature = "tokio", not(loom)))]
            let datagram = datagram.with_splice_handoff(handoff);
            out.push(datagram);
            self.dispatch_datagram_replica(route, i);
        }
        true
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one selected datagram and its shaping context"
    )]
    fn native_padding(
        &mut self,
        pipe: PipeId,
        ch: Channel,
        key: NativeUnit,
        base: usize,
        expiry: Option<Instant>,
        prior: Duration,
    ) -> Option<usize> {
        let Some(generation) = self.native_shaper_instance(pipe.0) else {
            return Some(0);
        };
        let now = self.now;
        let frame_room = channel::max_padded_frame_len() + channel::header_len(ch.prefix.id()) - 1;
        let mut room = ch.room.min(frame_room).saturating_sub(base);
        let outer = ch.prefix.outer_bytes();
        let base = base - outer;
        let padding = self.features.carrier_datagram_padding;
        if !padding {
            room = 0;
        }
        let unit = if let Some(p) = self.native_plan(pipe.0) {
            debug_assert_eq!(p.key, key);
            if now < p.ready {
                return None;
            }
            self.clear_native_plan(pipe.0);
            p.unit
        } else {
            let mut view = DatagramView::new(pipe, 0, base, ch.capacity - outer, ch.room - outer);
            view.padding = padding && room > 0 && !self.shaping_limits_in_force().no_padding;
            view.replica = matches!(key, NativeUnit::Replica(_));
            let Some(unit) = self.shape_native_plan(view) else {
                return Some(0);
            };
            let bounded = self.bounded_native_delay(unit.delay, prior);
            let delay = expiry.map_or(bounded, |at| bounded.min(at.saturating_duration_since(now)));
            if !delay.is_zero() {
                let ready = super::shape::later(now, delay);
                let want = unit.pad_for(base).saturating_sub(base);
                let reserved = (want.min(room) as u64).min(self.shape_overhead_room());
                self.shape_ledger.reserve(reserved);
                self.dgram_mut()
                    .native_plans
                    .get_or_insert_default()
                    .insert(NativePlan {
                        pipe: pipe.0,
                        key,
                        unit,
                        ready,
                        generation,
                        reserved,
                    });
                self.constrain_native_flow(pipe.0);
                return None;
            }
            unit
        };
        let want = unit.pad_for(base).saturating_sub(base);
        let no_padding = self.shaping_limits_in_force().no_padding;
        if no_padding {
            room = 0;
        }
        let pad = want
            .min(room)
            .min(crate::util::usize_sat(self.shape_overhead_room()));
        if pad < want {
            self.note_shape_clip(if !padding {
                RuntimeReason::UnsupportedCapability
            } else if no_padding {
                RuntimeReason::Disabled
            } else if pad < room.min(want) {
                RuntimeReason::OverheadLimit
            } else {
                RuntimeReason::ClippedRoom
            });
        }
        Some(pad)
    }

    pub(super) fn reserved_native_pipe(&self, tag: u64) -> Option<u64> {
        self.dgram()
            .native_plans
            .as_ref()?
            .entries
            .iter()
            .find(|p| p.key == NativeUnit::Original(tag))
            .map(|p| p.pipe)
    }

    fn native_plan(&self, pipe: u64) -> Option<NativePlan> {
        self.dgram()
            .native_plans
            .as_ref()?
            .entries
            .iter()
            .find(|p| p.pipe == pipe)
            .copied()
    }

    pub(super) fn native_shape_deadline(&self) -> Option<Instant> {
        self.dgram
            .as_deref()?
            .native_plans
            .as_ref()?
            .deadlines
            .next()
    }

    pub(super) fn native_shape_timeout(&mut self) {
        let now = self.now;
        let Some(plans) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.native_plans.as_mut())
        else {
            return;
        };
        let mut due = false;
        while plans.deadlines.take_due(now).is_some() {
            due = true;
        }
        if due {
            self.channel_kick();
        }
    }

    fn native_plan_fits(&self, pipe: u64, key: NativeUnit, room: usize) -> bool {
        let Some(ch) = self.channel_for(pipe) else {
            return false;
        };
        let len = match key {
            NativeUnit::Original(tag) => self
                .dgram()
                .send
                .held_flow(tag)
                .and_then(|packets| packets.front())
                .filter(|packet| self.datagram_flow_open(packet.flow))
                .and_then(|packet| {
                    let prefix = self.next_datagram_prefix(packet.flow)?;
                    Some(prefix.encoded_len() + packet.data.len())
                }),
            NativeUnit::Replica(sequence) => self
                .native_replica_for_wait(pipe, sequence)
                .map(|copy| copy.prefix.encoded_len() + copy.data.len()),
        };
        len.is_some_and(|len| channel::datagram_len(ch.prefix.id(), len) <= room)
    }

    fn native_plan_ready(&self, pipe: u64, key: NativeUnit) -> bool {
        let Some(channel) = self.channel_for(pipe) else {
            return false;
        };
        self.native_plan_fits(pipe, key, channel.room)
    }

    pub(super) fn native_shaping_wait(&self, pipe: u64) -> Option<Instant> {
        let plan = self.native_plan(pipe)?;
        self.native_plan_ready(pipe, plan.key).then_some(plan.ready)
    }

    fn constrain_native_flow(&mut self, pipe: u64) {
        let Some(plan) = self.native_plan(pipe) else {
            return;
        };
        if !self.native_plan_ready(pipe, plan.key) {
            self.clear_native_plan(pipe);
            return;
        }
        let left = self.datagram_flow_budget(DatagramRoute::Native(pipe));
        let end = plan.ready.min(super::shape::later(self.now, left));
        if end < plan.ready {
            let plans = self.dgram_mut().native_plans.as_mut().expect("held plan");
            let entry = plans
                .entries
                .iter_mut()
                .find(|p| p.pipe == pipe)
                .expect("held plan");
            entry.ready = end;
            plans.deadlines.set(pipe, Some(end));
            self.note_shape_clip(RuntimeReason::PolicyDeadline);
            self.channel_kick();
        }
    }

    pub(super) fn constrain_native_flows(&mut self) {
        let Some(plans) = self.dgram().native_plans.as_ref() else {
            return;
        };
        let pipes: Vec<_> = plans.entries.iter().map(|plan| plan.pipe).collect();
        for pipe in pipes {
            self.constrain_native_flow(pipe);
        }
    }

    pub(super) fn clear_native_plan(&mut self, pipe: u64) {
        if let Some(plan) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.native_plans.as_mut())
            .and_then(|plans| plans.remove(pipe))
        {
            self.shape_ledger.release(plan.reserved);
            self.channel_kick();
        }
    }

    pub(super) fn clear_native_plans(&mut self) {
        while let Some(pipe) = self
            .dgram()
            .native_plans
            .as_ref()
            .and_then(|plans| plans.entries.last())
            .map(|plan| plan.pipe)
        {
            self.clear_native_plan(pipe);
        }
    }

    /// Completes one native carrier handoff. A refusal does not retry the dispatch.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "consumes the one-time channel handoff token"
    )]
    pub fn channel_done(
        &mut self,
        pipe: PipeId,
        outcome: NativeDatagramOutcome,
        result: NativeDatagramResult,
        now: Instant,
    ) {
        self.tick(now);
        if outcome.replica {
            self.dgram_mut()
                .copies
                .as_deref_mut()
                .expect("native replica charge")
                .finish_native(outcome.queue_bytes);
        } else {
            let was_full = self.datagram_queue_full();
            let stream = match outcome.flow {
                Flow::Session => None,
                Flow::Stream { stream_id, .. } => Some(stream_id),
            };
            self.dgram_mut()
                .send
                .finish_native(stream, outcome.queue_bytes);
            if was_full {
                self.events.push_back(CoreEvent::DatagramsUnblocked);
            }
        }
        self.channel_kick();
        let accepted = result == NativeDatagramResult::Accepted;
        #[cfg(all(feature = "tokio", not(loom)))]
        if accepted && let Some(handoff) = &outcome.handoff {
            handoff.handed_off(super::splice_handoff::Medium::Native);
        }
        if accepted {
            self.settle_native_shape(outcome.dispatch, outcome.wire_len, outcome.pad);
        } else {
            self.finish_shape_bytes(outcome.dispatch, result == NativeDatagramResult::Unresolved);
        }
        self.settle_native_dispatch(pipe, outcome.sequence, accepted);
        self.dgram_mut()
            .stats
            .native
            .finish(outcome.replica, accepted, outcome.bytes);
        #[cfg(all(feature = "tokio", not(loom)))]
        if accepted {
            self.member_bytes(pipe, true, outcome.wire_len as u64);
        }
        if !accepted {
            let (shape, original, replica) = match result {
                NativeDatagramResult::Rejected => (
                    RuntimeReason::CarrierRejected,
                    DatagramDrop::CarrierRejected,
                    ReplicaDegradation::CarrierRejected,
                ),
                NativeDatagramResult::Expired => (
                    RuntimeReason::ApplicationExpired,
                    DatagramDrop::Deadline,
                    ReplicaDegradation::Deadline,
                ),
                NativeDatagramResult::Cancelled | NativeDatagramResult::Unresolved => (
                    RuntimeReason::Cancelled,
                    DatagramDrop::CarrierCancelled,
                    ReplicaDegradation::CarrierCancelled,
                ),
                NativeDatagramResult::Accepted => unreachable!("accepted"),
            };
            self.note_shape_reason(shape);
            if outcome.replica {
                self.dgram_mut().stats.replica_degradation.count(replica, 1);
            } else {
                self.count_datagram_drop(original, 1);
            }
        } else if !outcome.replica {
            self.datagram_sent(Some(outcome.flow), outcome.bytes);
            self.dgram_mut().counters.sent_channel += 1;
            self.shaping_earn(outcome.bytes);
            self.shape_outbound(
                pipe.0,
                0,
                outcome.generation,
                outcome.wire_len,
                true,
                false,
                true,
            );
        }
    }

    /// `n` channel datagrams the driver dropped before handing them over
    /// (its queue was full): counted as received datagrams dropped.
    pub fn channel_dropped(&mut self, n: u64) {
        if n > 0 {
            self.count_dropped(n);
        }
    }

    /// A channel datagram received for `pipe`, its Pipe Stream ID removed. Dropped and counted when
    /// the pipe is not an open inbound pipe of the session or the session did not
    /// negotiate the channel; otherwise anything but one DATAGRAM frame of
    /// type 0x30 closes the session with `PROTOCOL_VIOLATION`, and the frame
    /// is processed as one in a record on that pipe, without the
    /// accounting of a record (no `PIPE_ACK` position, no no-effect budget,
    /// no idle timer restart).
    pub fn receive_channel_datagram(&mut self, pipe: PipeId, frame: &[u8], now: Instant) {
        self.tick(now);
        if self.state >= State::Closing {
            return;
        }
        let open = self
            .att(pipe.0)
            .and_then(|a| a.inp())
            .is_some_and(|p| p.state() == InState::Open);
        if !open || !self.is_established() || !self.features.carrier_datagrams {
            self.count_dropped(1);
            return;
        }
        let gates = self.receive_gates();
        let d = match channel::decode_frame(frame, &gates, self.features.carrier_datagram_padding) {
            Ok(d) => d,
            Err(e) => {
                self.protocol_error(e, now);
                return;
            }
        };
        #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
        self.member_bytes(pipe, false, frame.len() as u64);
        // A subset of datagrams_received: those counted now (a held one
        // counts when it is delivered).
        let before = self.dgram().counters.received;
        self.rx_channel = true;
        let r = self.on_datagram(d, FrameType::DATAGRAM.0, pipe.0);
        self.rx_channel = false;
        if let Err(e) = r {
            self.protocol_error(e, now);
            return;
        }
        self.dgram_mut().counters.received_channel += self.dgram().counters.received - before;
    }

    /// Current native capacity before full per-packet path eligibility.
    pub(super) fn channel_for(&self, pipe: u64) -> Option<Channel> {
        if !self.features.carrier_datagrams {
            return None;
        }
        self.out_ref(pipe)?.channel().filter(|c| c.capacity > 0)
    }

    /// Current payload capacity of eligible outgoing paths for this session.
    pub fn datagram_path(&self) -> super::DatagramPath {
        self.path_capacities(None)
    }

    /// Largest payload supported by any eligible path for a session datagram.
    pub fn path_datagram_size(&self) -> Option<usize> {
        self.datagram_path().payload
    }

    /// Current payload capacity of eligible outgoing paths for a stream.
    pub fn stream_datagram_path(&self, key: StreamKey, context: u64) -> super::DatagramPath {
        let Ok(flow) = self.stream_datagram_candidate(key, context) else {
            return super::DatagramPath::default();
        };
        self.path_capacities(Some(flow))
    }

    /// Largest payload supported by any eligible path for this stream datagram.
    pub fn path_stream_datagram_size(&self, key: StreamKey, context: u64) -> Option<usize> {
        self.stream_datagram_path(key, context).payload
    }

    /// Reports a change of [`SessionCore::path_datagram_size`]
    /// ([`CoreEvent::DatagramPathChanged`]).
    pub(super) fn note_datagram_path(&mut self) {
        if !self.is_established() {
            return;
        }
        let path = self.datagram_path();
        if self.dgram().path != path {
            self.dgram_mut().path = path;
            self.events
                .push_back(CoreEvent::DatagramPathChanged { path });
        }
    }

    /// The flow prefix of a queued datagram, with datagram flows in use.
    pub(super) fn flow_of(&self, flow: Option<(u64, u64)>) -> Option<Flow> {
        match (self.features.same_family, flow) {
            (false, _) => None,
            (true, None) => Some(Flow::Session),
            (true, Some((stream_id, context))) => Some(Flow::Stream { stream_id, context }),
        }
    }

    /// Datagrams may wait for a channel: the channel tasks look again.
    pub(super) fn channel_kick(&mut self) {
        if !self.atts.outs().any(|o| o.channel().is_some()) {
            return;
        }
        let d = self.dgram_mut();
        d.channel_gen = d.channel_gen.wrapping_add(1);
        if !self
            .events
            .iter()
            .any(|e| matches!(e, CoreEvent::ChannelDatagrams))
        {
            self.events.push_back(CoreEvent::ChannelDatagrams);
        }
    }
}
