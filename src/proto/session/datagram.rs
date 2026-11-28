//! Session-direction Datagram sequence spaces, shared by records and native channels.

use crate::proto::frame::{DatagramChannelKind, DatagramPrefix};
use crate::proto::varint;

use super::SessionCore;
use std::collections::BTreeMap;
use std::time::Duration;

mod stats;
pub(super) use stats::ReplicaDegradation;
pub use stats::{
    DatagramDispatchStats, DatagramDrop, DatagramDrops, DatagramReplicaDegradation, DatagramStats,
};

#[derive(Debug)]
pub(super) struct ReceiveWindow {
    highest: u64,
    width: u64,
    bits: Box<[u64]>,
}

pub(super) enum Arrival {
    New,
    Duplicate,
    Stale,
}

impl ReceiveWindow {
    pub(super) fn new(width: usize, first: u64) -> Self {
        Self {
            highest: first,
            width: width as u64,
            bits: vec![0; width.div_ceil(64)].into_boxed_slice(),
        }
    }

    pub(super) fn heap_bytes(&self) -> usize {
        std::mem::size_of_val(&*self.bits)
    }

    fn slot(&self, sequence: u64) -> (usize, u64) {
        let offset = sequence % (self.bits.len() as u64 * 64);
        ((offset / 64) as usize, 1 << (offset % 64))
    }

    pub(super) fn advance(&mut self, sequence: u64) {
        let width = self.width;
        if sequence > self.highest {
            if sequence - self.highest >= width {
                self.bits.fill(0);
            } else {
                let mut first = self.highest + 1;
                while first <= sequence {
                    let (word, _) = self.slot(first);
                    let shift = first % 64;
                    let count = (64 - shift).min(sequence - first + 1);
                    let mask = (u64::MAX >> (64 - count)) << shift;
                    self.bits[word] &= !mask;
                    first += count;
                }
            }
            self.highest = sequence;
        }
    }

    fn classify(&self, sequence: u64) -> Arrival {
        if sequence > self.highest {
            return Arrival::New;
        }
        if self.highest - sequence >= self.width {
            return Arrival::Stale;
        }
        let (word, mask) = self.slot(sequence);
        if self.bits[word] & mask == 0 {
            Arrival::New
        } else {
            Arrival::Duplicate
        }
    }

    /// Changes occupancy only while this sequence still owns its slot.
    pub(super) fn set(&mut self, sequence: u64, occupied: bool) {
        if sequence > self.highest || self.highest - sequence >= self.width {
            return;
        }
        let (word, mask) = self.slot(sequence);
        if occupied {
            self.bits[word] |= mask;
        } else {
            self.bits[word] &= !mask;
        }
    }
}

impl SessionCore {
    /// Additional datagram outcome counters for this session.
    pub fn datagram_stats(&self) -> DatagramStats {
        self.dgram().stats
    }

    pub(super) fn next_sequence_len(&self) -> Option<usize> {
        let next = self.dgram().next_sequence;
        if self.features.same_family {
            (next <= varint::MAX).then(|| varint::len(next))
        } else {
            Some(0)
        }
    }

    pub(super) fn check_datagram_sequence(&self) -> Result<(), super::DatagramError> {
        self.next_sequence_len()
            .ok_or(super::DatagramError::SequenceExhausted)
            .map(|_| ())
    }

    pub(super) fn count_datagram_drop(&mut self, reason: DatagramDrop, count: u64) {
        if count > 0 {
            self.dgram_mut().stats.drops.count(reason, count);
        }
    }

    pub(super) fn discard_unsendable_datagrams(&mut self, reason: DatagramDrop) {
        let mut count = 0;
        while self.take_send_datagram(0).is_some() {
            count += 1;
        }
        self.count_datagram_drop(reason, count);
    }

    /// The prefix that will go on the next actual dispatch. Plain QMux uses
    /// an empty prefix. The maximum sequence is usable once.
    pub(super) fn next_datagram_prefix(&self, flow: Option<(u64, u64)>) -> Option<DatagramPrefix> {
        if !self.features.same_family {
            return Some(DatagramPrefix::Opaque);
        }
        let sequence = self.dgram().next_sequence;
        (sequence <= varint::MAX).then(|| DatagramPrefix::Sequenced {
            sequence,
            flow: self.flow_of(flow).expect("same family has a flow"),
        })
    }

    pub(super) fn datagram_dispatched(&mut self, route: DatagramRoute, packet: &OutDatagram) {
        self.dgram_mut()
            .stats
            .dispatch(route, false, packet.data.len() as u64);
        if self.features.same_family {
            let sequence = self.dgram().next_sequence;
            self.note_datagram_dispatch((route.pipe(), route.channel()), sequence);
            self.replica_bytes(packet.data.len() as u64, false);
            self.queue_datagram_replicas(route, packet, sequence);
            let width = varint::len(sequence);
            self.dgram_mut().next_sequence += 1;
            let next = self.dgram().next_sequence;
            if next > varint::MAX {
                self.discard_unsendable_datagrams(DatagramDrop::SequenceExhausted);
            }
            if next > varint::MAX || varint::len(next) != width {
                self.note_datagram_path();
            }
        }
    }

    pub(super) fn advance_datagram_sequence(&mut self, sequence: u64) {
        let width = self.config.datagram_config().dedup_window;
        self.dgram_mut()
            .window
            .get_or_insert_with(|| ReceiveWindow::new(width, sequence))
            .advance(sequence);
    }

    pub(super) fn datagram_sequence_fresh(&mut self, sequence: u64) -> bool {
        let arrival = self
            .dgram()
            .window
            .as_ref()
            .map_or(Arrival::New, |w| w.classify(sequence));
        match arrival {
            Arrival::New => true,
            Arrival::Duplicate => {
                self.dgram_mut().stats.duplicates_dropped += 1;
                false
            }
            Arrival::Stale => {
                self.dgram_mut().stats.stale_dropped += 1;
                false
            }
        }
    }

    pub(super) fn occupy_datagram(&mut self, sequence: Option<u64>, occupied: bool) {
        if let Some(dgram) = self.dgram.as_deref_mut() {
            occupy_window(&mut dgram.window, sequence, occupied);
        }
    }
}

pub(super) fn occupy_window(
    window: &mut Option<ReceiveWindow>,
    sequence: Option<u64>,
    occupied: bool,
) {
    if let (Some(window), Some(sequence)) = (window, sequence) {
        window.set(sequence, occupied);
    }
}

use std::collections::VecDeque;
use std::time::Instant;

use super::path::tier::Gate;
use super::pipes::Attachment;
use super::{OutDatagram, State};

/// An optional local deadline on a logical datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramDeadline {
    /// Overrides an inherited deadline.
    Never,
    /// Converts to an absolute deadline when this hop accepts the packet.
    After(std::time::Duration),
    /// An absolute instant on this process's monotonic clock.
    At(Instant),
}

/// Carrier policy for the original and any extra copies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DatagramCarrier {
    /// Use a native channel when possible, with reliable fallback.
    #[default]
    PreferNative,
    /// Only a native datagram channel may carry this packet.
    RequireNative,
}

/// The representations a packet stream allows when sending a packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendPolicy {
    /// Use a datagram when negotiated and structurally large enough.
    /// Otherwise use a reliable DATAGRAM capsule.
    #[default]
    PreferDatagram,
    /// Use a reliable DATAGRAM capsule.
    StreamOnly,
    /// Allow datagram representations only.
    DatagramOnly,
}

pub(crate) enum PacketRepresentation {
    Datagram { stream_id: u64, context: u64 },
    Capsule,
}

pub(crate) enum PacketAdmission {
    Datagram,
    Capsule {
        data: bytes::Bytes,
        deadline: Option<Instant>,
    },
}

/// How many copies to attempt for a datagram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DatagramCopyPolicy {
    #[default]
    Single,
    Duplicate(std::num::NonZeroU8),
    Adaptive,
}

/// Local send options. Fields that are absent inherit the flow or session default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DatagramSendOptions {
    pub deadline: Option<DatagramDeadline>,
    pub carrier: Option<DatagramCarrier>,
    pub copies: Option<DatagramCopyPolicy>,
    pub urgent: Option<bool>,
    pub independent_fate: Option<bool>,
}

impl DatagramSendOptions {
    pub(crate) fn inherit(self, defaults: Self) -> Self {
        Self {
            deadline: self.deadline.or(defaults.deadline),
            carrier: self.carrier.or(defaults.carrier),
            copies: self.copies.or(defaults.copies),
            urgent: self.urgent.or(defaults.urgent),
            independent_fate: self.independent_fate.or(defaults.independent_fate),
        }
    }

    pub(super) fn deadline_at(self, now: Instant) -> Result<Option<Instant>, crate::InvalidConfig> {
        match self.deadline.unwrap_or(DatagramDeadline::Never) {
            DatagramDeadline::Never => Ok(None),
            DatagramDeadline::After(ttl) => {
                crate::util::checked_clock_deadline(now, ttl, "datagram_deadline").map(Some)
            }
            DatagramDeadline::At(at) => Ok(Some(at)),
        }
    }

    pub(crate) fn resolve(
        self,
        now: Instant,
    ) -> Result<ResolvedDatagramOptions, super::DatagramError> {
        let copies = match self.copies.unwrap_or_default() {
            DatagramCopyPolicy::Duplicate(n) if n.get() == 1 => DatagramCopyPolicy::Single,
            copies => copies,
        };
        Ok(ResolvedDatagramOptions {
            deadline: self
                .deadline_at(now)
                .map_err(super::DatagramError::InvalidOptions)?,
            require_native: self.carrier == Some(DatagramCarrier::RequireNative),
            copies,
            urgent: self.urgent,
            independent_fate: self.independent_fate.unwrap_or_default(),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ResolvedDatagramOptions {
    pub(crate) deadline: Option<Instant>,
    pub(super) require_native: bool,
    copies: DatagramCopyPolicy,
    urgent: Option<bool>,
    independent_fate: bool,
}

/// Datagram queue limits and direction defaults.
#[derive(Clone, Debug)]
pub struct DatagramConfig {
    /// Number of same-family receive sequences to remember (64 to 16,384).
    pub dedup_window: usize,
    /// Maximum payload bytes held across all sending flows, including
    /// native submissions awaiting a carrier outcome.
    pub send_bytes: usize,
    /// Maximum queued and submitted packets held in a single sending flow.
    pub send_flow_queue: usize,
    /// Maximum payload bytes held in a single sending flow, including
    /// native submissions awaiting a carrier outcome.
    pub send_flow_bytes: usize,
    /// Maximum bytes held for one receiving stream, if bounded separately.
    pub stream_receive_bytes: Option<usize>,
    /// Local lifetime of datagrams in a stream's receive queue.
    /// `None` leaves expiry to the queue's delay policy.
    pub receive_lifetime: Option<std::time::Duration>,
    /// Maximum datagrams held while waiting for a peer to open their streams.
    pub hold_packets: Option<usize>,
    /// Holding lifetime. The default uses one smoothed RTT.
    pub hold_time: Option<std::time::Duration>,
    /// Maximum total copies of a logical datagram.
    pub copy_limit: std::num::NonZeroU8,
    /// Shared outgoing STREAM and datagram allowance, as a percentage of original bytes.
    pub replica_percent: u8,
    /// Permits standby paths to carry replicas.
    pub replica_standby: bool,
    /// Scheduling priority of the session-level datagram flow.
    pub priority: crate::proto::frame::Priority,
    /// Defaults for datagrams sent in this direction.
    pub defaults: DatagramSendOptions,
}

pub(super) const DEFAULT_DATAGRAM_CONFIG: DatagramConfig = DatagramConfig {
    dedup_window: 1024,
    send_bytes: 64 * u16::MAX as usize,
    send_flow_queue: 64,
    send_flow_bytes: 64 * u16::MAX as usize,
    stream_receive_bytes: Some(super::config::DEFAULT_DATAGRAM_STREAM_BYTES),
    receive_lifetime: None,
    hold_packets: None,
    hold_time: None,
    copy_limit: std::num::NonZeroU8::new(2).expect("nonzero default"),
    replica_percent: 20,
    replica_standby: false,
    priority: crate::proto::frame::Priority::LOCAL_DEFAULT,
    defaults: DatagramSendOptions {
        deadline: None,
        carrier: None,
        copies: None,
        urgent: None,
        independent_fate: None,
    },
};

impl Default for DatagramConfig {
    fn default() -> Self {
        DEFAULT_DATAGRAM_CONFIG
    }
}

#[cfg(feature = "test-hooks")]
impl SessionCore {
    /// Seeds the outbound sequence for boundary tests.
    #[doc(hidden)]
    pub fn seed_datagram_sequence(&mut self, next: u64) {
        assert!(next <= varint::MAX);
        self.dgram_mut().next_sequence = next;
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn datagram_sequence(&self) -> u64 {
        self.dgram().next_sequence
    }
}

#[cfg(all(
    feature = "test-hooks",
    any(feature = "tokio", feature = "blocking"),
    not(loom)
))]
pub(crate) fn datagram_send_state(core: &SessionCore) -> (usize, u64) {
    (core.dgram().send.packets, core.datagram_sequence())
}

#[cfg(all(
    feature = "test-hooks",
    any(feature = "tokio", feature = "blocking"),
    not(loom)
))]
pub(crate) fn datagram_replica_credit(core: &mut SessionCore, bytes: u64) {
    core.replica_bytes(bytes, false);
}

/// Payload capacity of eligible paths for the original copy of a datagram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DatagramPath {
    /// Largest payload supported by an eligible record or native path.
    pub payload: Option<usize>,
    /// Largest payload supported by an eligible native datagram channel.
    pub native_payload: Option<usize>,
    /// Largest payload that fits in an eligible channel's current room.
    pub native_room: Option<usize>,
}

type Flow = Option<(u64, u64)>;

/// Datagrams held for unopened peer streams. Arrival order is independent
/// of the expiration order, because the RTT may change between arrivals.
#[derive(Debug, Default)]
pub(super) struct WaitingDatagrams {
    arrivals: std::collections::BTreeMap<u64, super::WaitingDatagram>,
    expires: super::deadline::Deadlines<u64>,
}

impl WaitingDatagrams {
    pub(super) const fn new() -> Self {
        Self {
            arrivals: std::collections::BTreeMap::new(),
            expires: super::deadline::Deadlines::new(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.arrivals.len()
    }

    pub(super) fn heap_bytes(&self) -> usize {
        self.arrivals.len() * std::mem::size_of::<(u64, super::WaitingDatagram)>()
            + self.expires.heap_bytes()
    }

    pub(super) fn push(&mut self, packet: super::WaitingDatagram, until: Instant) {
        let tag = self
            .arrivals
            .last_key_value()
            .map_or(0, |(&tag, _)| tag + 1);
        self.arrivals.insert(tag, packet);
        self.expires.set(tag, Some(until));
    }

    pub(super) fn pop_front(&mut self) -> Option<super::WaitingDatagram> {
        let (tag, packet) = self.arrivals.pop_first()?;
        self.expires.set(tag, None);
        Some(packet)
    }

    pub(super) fn take_opened(
        &mut self,
        opened: u64,
    ) -> impl Iterator<Item = super::WaitingDatagram> + '_ {
        let expires = &mut self.expires;
        self.arrivals
            .extract_if(.., move |tag, packet| {
                let ready = super::stream::index(packet.stream_id) < opened;
                if ready {
                    expires.set(*tag, None);
                }
                ready
            })
            .map(|(_, packet)| packet)
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.expires.next()
    }

    pub(super) fn take_due(&mut self, now: Instant) -> Option<super::WaitingDatagram> {
        let (_, tag) = self.expires.take_due(now)?;
        Some(
            self.arrivals
                .remove(&tag)
                .expect("indexed waiting datagram"),
        )
    }
}

#[cfg(test)]
mod waiting_tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn expiry_order_is_independent_of_arrival_and_stream_open_order() {
        let mut waiting = WaitingDatagrams::new();
        let now = Instant::now();
        let short = now + Duration::from_millis(3);
        let medium = now + Duration::from_millis(9);
        let long = now + Duration::from_millis(15);
        let packet = |stream_id, context| super::super::WaitingDatagram {
            sequence: Some(context),
            stream_id,
            context,
            data: crate::Chunk::new(),
            channel: false,
        };
        waiting.push(packet(4, 1), long);
        waiting.push(packet(8, 2), short);
        waiting.push(packet(4, 3), medium);
        waiting.push(packet(12, 4), medium);

        assert_eq!(waiting.deadline(), Some(short));
        let just_before = short.checked_sub(Duration::from_nanos(1)).unwrap();
        assert!(waiting.take_due(just_before).is_none());
        assert_eq!(waiting.take_due(short).unwrap().context, 2);
        assert_eq!(
            waiting
                .take_opened(2)
                .map(|p| p.context)
                .collect::<Vec<_>>(),
            [1, 3]
        );
        assert_eq!(waiting.deadline(), Some(medium));
        assert_eq!(waiting.pop_front().unwrap().context, 4);
        assert_eq!(waiting.deadline(), None);
        assert!(waiting.take_due(long).is_none());
    }
}

#[derive(Debug)]
struct FlowQueue {
    stream: Option<u64>,
    turn: u64,
    packets: VecDeque<OutDatagram>,
    bytes: usize,
    codel: super::codel::Codel,
}

#[derive(Clone, Copy, Debug, Default)]
struct QueueCharge {
    items: usize,
    bytes: usize,
}

impl QueueCharge {
    const EMPTY: Self = Self { items: 0, bytes: 0 };

    fn add(&mut self, bytes: usize) {
        self.items += 1;
        self.bytes += bytes;
    }

    fn remove(&mut self, bytes: usize) {
        self.items -= 1;
        self.bytes -= bytes;
    }
}

/// Flow heads compete by urgency, with a deque rotation after service.
/// CoDel tracks each flow's standing delay independently.
#[derive(Debug, Default)]
pub(super) struct SendDatagrams {
    flows: VecDeque<FlowQueue>,
    spare: VecDeque<OutDatagram>,
    packets: usize,
    bytes: usize,
    deadline: Option<Instant>,
    next_tag: u64,
    native: QueueCharge,
    native_flows: BTreeMap<Option<u64>, QueueCharge>,
}

impl SendDatagrams {
    pub(super) const fn new() -> Self {
        Self {
            flows: VecDeque::new(),
            spare: VecDeque::new(),
            packets: 0,
            bytes: 0,
            deadline: None,
            next_tag: 0,
            native: QueueCharge::EMPTY,
            native_flows: BTreeMap::new(),
        }
    }

    pub(super) fn occupied(&self) -> usize {
        self.packets + self.native.items
    }

    fn occupied_bytes(&self) -> usize {
        self.bytes + self.native.bytes
    }

    pub(super) fn begin_native(&mut self, stream: Option<u64>, bytes: usize) {
        self.native.add(bytes);
        self.native_flows.entry(stream).or_default().add(bytes);
    }

    pub(super) fn finish_native(&mut self, stream: Option<u64>, bytes: usize) {
        self.native.remove(bytes);
        let std::collections::btree_map::Entry::Occupied(mut flow) =
            self.native_flows.entry(stream)
        else {
            unreachable!("native original has a charged Flow");
        };
        flow.get_mut().remove(bytes);
        if flow.get().items == 0 {
            flow.remove();
        }
    }

    fn native_flow(&self, stream: Option<u64>) -> QueueCharge {
        self.native_flows.get(&stream).copied().unwrap_or_default()
    }

    pub(super) fn bytes(&self) -> u64 {
        self.bytes as u64
    }

    pub(super) fn is_empty(&self) -> bool {
        self.packets == 0
    }

    pub(super) fn heap_bytes(&self) -> usize {
        self.occupied_bytes()
            + self.native_flows.len() * std::mem::size_of::<(Option<u64>, QueueCharge)>()
            + self.flows.capacity() * std::mem::size_of::<FlowQueue>()
            + (self.spare.capacity()
                + self
                    .flows
                    .iter()
                    .map(|f| f.packets.capacity())
                    .sum::<usize>())
                * std::mem::size_of::<OutDatagram>()
    }

    pub(super) fn get(&self, flow: usize) -> Option<&OutDatagram> {
        self.flows.get(flow)?.packets.front()
    }

    pub(super) fn held_flow(&self, tag: u64) -> Option<&VecDeque<OutDatagram>> {
        self.flows
            .iter()
            .find(|flow| flow.packets.front().is_some_and(|p| p.tag == tag))
            .map(|flow| &flow.packets)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &OutDatagram> {
        self.flows.iter().filter_map(|flow| flow.packets.front())
    }

    pub(super) fn remove(&mut self, flow: usize) -> Option<OutDatagram> {
        let mut q = self.flows.remove(flow)?;
        let packet = q.packets.pop_front().expect("nonempty flow");
        q.bytes -= packet.data.len();
        self.bytes -= packet.data.len();
        self.packets -= 1;
        if q.packets.is_empty() {
            self.spare = q.packets;
        } else {
            self.flows.push_back(q);
        }
        if packet.deadline.is_some() && packet.deadline == self.deadline {
            self.refresh_deadline();
        }
        Some(packet)
    }

    pub(super) fn take(&mut self, flow: usize, next_turn: u64) -> Option<OutDatagram> {
        self.flows.get_mut(flow)?.turn = next_turn;
        self.remove(flow)
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    fn splice_group_fits(
        &self,
        stream: u64,
        mut sizes: impl ExactSizeIterator<Item = usize>,
        config: &super::Config,
    ) -> bool {
        let settings = config.datagram_config();
        let flow = self.flows.iter().find(|flow| flow.stream == Some(stream));
        let native = self.native_flow(Some(stream));
        let slots = config
            .datagram_send_queue
            .saturating_sub(self.occupied())
            .min(
                settings
                    .send_flow_queue
                    .saturating_sub(native.items + flow.map_or(0, |flow| flow.packets.len())),
            );
        let room = settings
            .send_bytes
            .saturating_sub(self.occupied_bytes())
            .min(
                settings
                    .send_flow_bytes
                    .saturating_sub(native.bytes + flow.map_or(0, |flow| flow.bytes)),
            );
        sizes.len() <= slots && sizes.try_fold(room, usize::checked_sub).is_some()
    }

    pub(super) fn queue(
        &mut self,
        mut packet: OutDatagram,
        config: &super::Config,
        turn: u64,
    ) -> (bool, u64) {
        let settings = config.datagram_config();
        let len = packet.data.len();
        let stream = packet.flow.map(|(stream, _)| stream);
        let native = self.native_flow(stream);
        let flow_slots = settings.send_flow_queue.saturating_sub(native.items);
        let flow_room = settings.send_flow_bytes.saturating_sub(native.bytes);
        let total_room = settings.send_bytes.saturating_sub(self.native.bytes);
        if self.native.items >= config.datagram_send_queue
            || flow_slots == 0
            || len > flow_room.min(total_room)
        {
            return (false, 1);
        }
        let mut dropped = 0;
        while let Some(index) = self.flows.iter().position(|q| q.stream == stream)
            && (self.flows[index].packets.len() >= flow_slots
                || len > flow_room.saturating_sub(self.flows[index].bytes))
        {
            self.remove(index);
            dropped += 1;
        }
        while self.occupied() >= config.datagram_send_queue
            || len > total_room.saturating_sub(self.bytes)
        {
            let oldest = self
                .iter()
                .enumerate()
                .min_by_key(|(_, o)| o.at)
                .expect("nonempty send queue")
                .0;
            self.remove(oldest);
            dropped += 1;
        }
        let q = if let Some(index) = self.flows.iter().position(|q| q.stream == stream) {
            &mut self.flows[index]
        } else {
            self.flows.push_back(FlowQueue {
                stream,
                turn,
                packets: std::mem::take(&mut self.spare),
                bytes: 0,
                codel: super::codel::Codel::new(),
            });
            self.flows.back_mut().expect("new send flow")
        };
        if let Some(deadline) = packet.deadline {
            self.deadline = self
                .deadline
                .map_or(Some(deadline), |current| Some(current.min(deadline)));
        }
        self.next_tag = self.next_tag.wrapping_add(1);
        packet.tag = self.next_tag;
        q.packets.push_back(packet);
        q.bytes += len;
        self.packets += 1;
        self.bytes += len;
        (true, dropped)
    }

    fn refresh_deadline(&mut self) {
        self.deadline = self
            .flows
            .iter()
            .flat_map(|q| q.packets.iter().filter_map(|p| p.deadline))
            .min();
    }

    fn expire(&mut self, now: Instant) -> u64 {
        if self.deadline.is_none_or(|deadline| deadline > now) {
            return 0;
        }
        let before = self.packets;
        self.flows.retain_mut(|q| {
            q.packets.retain(|p| {
                if p.deadline.is_some_and(|due| due <= now) {
                    q.bytes -= p.data.len();
                    self.bytes -= p.data.len();
                    self.packets -= 1;
                    false
                } else {
                    true
                }
            });
            !q.packets.is_empty()
        });
        self.refresh_deadline();
        (before - self.packets) as u64
    }

    pub(super) fn delayed(
        &mut self,
        flow: usize,
        now: Instant,
        target: Option<std::time::Duration>,
    ) -> bool {
        let Some(q) = self.flows.get_mut(flow) else {
            return false;
        };
        let head = &q.packets[0];
        let eligible = head.at.checked_add(head.shape_held).unwrap_or(now);
        q.codel.drop(eligible, now, target, q.packets.len() == 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DatagramRoute {
    Record(u64),
    Native(u64),
}

impl DatagramRoute {
    fn pipe(self) -> u64 {
        match self {
            Self::Record(id) | Self::Native(id) => id,
        }
    }

    fn channel(self) -> DatagramChannelKind {
        match self {
            Self::Record(_) => DatagramChannelKind::Record,
            Self::Native(_) => DatagramChannelKind::Native,
        }
    }

    fn feedback_path(self) -> (u64, DatagramChannelKind) {
        (self.pipe(), self.channel())
    }
}

#[derive(Debug)]
pub(super) struct DatagramReplica {
    original: u64,
    target: u64,
    pub(super) prefix: DatagramPrefix,
    pub(super) data: bytes::Bytes,
    turn: u64,
    pub(crate) deadline: Option<Instant>,
    require_native: bool,
    independent: bool,
    adaptive: Option<super::datagram_feedback::AdaptivePair>,
    pub(super) shape_held: std::time::Duration,
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(super) handoff: Option<super::splice_handoff::HandoffSpan>,
}

impl OutDatagram {
    fn independent_replicas(&self) -> bool {
        self.copy_policy == DatagramCopyPolicy::Adaptive || self.independent_fate
    }
}

fn charge_shape_wait(
    spent: &mut Duration,
    start: Instant,
    end: Instant,
    deadline: Option<Instant>,
    limit: Duration,
) -> Duration {
    let end = deadline.map_or(end, |at| end.min(at));
    let added = end
        .saturating_duration_since(start)
        .min(limit.saturating_sub(*spent));
    *spent += added;
    added
}

fn compare_replica_eta(a: &(f64, DatagramRoute), b: &(f64, DatagramRoute)) -> std::cmp::Ordering {
    a.0.total_cmp(&b.0)
        .then_with(|| a.1.pipe().cmp(&b.1.pipe()))
}

fn datagram_replica_charge(bytes: usize) -> u64 {
    bytes.max(1) as u64
}

/// A transmit turn in its urgency level, shared with reliable streams.
pub(super) type SendRank = (usize, u64);

/// A datagram ready for the record writer on one pipe.
#[derive(Clone, Copy)]
pub(super) struct ReadyDatagram {
    pub(super) index: usize,
    pub(super) rank: SendRank,
    pub(super) replica: bool,
}

#[derive(Debug, Default)]
pub(super) struct PendingCopies {
    queue: VecDeque<DatagramReplica>,
    bytes: usize,
    native: QueueCharge,
    deadline: Option<Instant>,
}

impl PendingCopies {
    pub(super) fn get(&self, index: usize) -> &DatagramReplica {
        &self.queue[index]
    }

    fn occupied(&self) -> usize {
        self.queue.len() + self.native.items
    }

    fn occupied_bytes(&self) -> usize {
        self.bytes + self.native.bytes
    }

    pub(super) fn finish_native(&mut self, bytes: usize) {
        self.native.remove(bytes);
    }

    pub(super) fn heap_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.queue.capacity() * std::mem::size_of::<DatagramReplica>()
            + self.occupied_bytes()
    }

    fn insert(&mut self, packet: DatagramReplica) {
        self.bytes += packet.data.len() + packet.prefix.encoded_len();
        if let Some(deadline) = packet.deadline {
            self.deadline = self
                .deadline
                .map_or(Some(deadline), |at| Some(at.min(deadline)));
        }
        self.queue.push_back(packet);
    }

    fn remove(&mut self, i: usize) -> DatagramReplica {
        let packet = self.queue.remove(i).expect("queued replica");
        self.bytes -= packet.data.len() + packet.prefix.encoded_len();
        if self.deadline.is_some() && self.deadline == packet.deadline {
            self.deadline = self.queue.iter().filter_map(|copy| copy.deadline).min();
        }
        packet
    }
}

#[derive(Clone, Copy)]
enum Affinity {
    Any,
    Follow(u64),
    Wait,
}

impl SessionCore {
    fn datagram_affinity(&self, flow: Flow) -> Affinity {
        let Some((id, _)) = flow.filter(|_| self.mp.is_some()) else {
            return Affinity::Any;
        };
        let Some(stream) = self
            .streams
            .key_of(id)
            .and_then(|key| self.streams.get(key))
        else {
            return Affinity::Wait;
        };
        if !stream.local {
            return Affinity::Any;
        }
        let Some(send) = stream.send.as_ref() else {
            return Affinity::Wait;
        };
        let mp = send.mp();
        if mp.open_acked {
            Affinity::Any
        } else {
            mp.open_pipe.map_or(Affinity::Wait, Affinity::Follow)
        }
    }

    pub(super) fn path_capacities(&self, flow: Flow) -> DatagramPath {
        let Some(data_limit) = self
            .peer_tp
            .as_ref()
            .map(super::tp::TpValues::max_datagram_frame_size)
            .filter(|&limit| limit > 0)
        else {
            return DatagramPath::default();
        };
        let Some(prefix) = self.next_datagram_prefix(flow) else {
            return DatagramPath::default();
        };
        let frame_header = 1 + prefix.encoded_len();
        let gate = self.path_gate();
        let mut path = DatagramPath::default();
        let affinity = self.datagram_affinity(flow);
        for a in self
            .atts
            .iter()
            .filter(|a| self.datagram_original_eligible(a, gate.as_ref(), affinity))
        {
            let pipe = a.id();
            let record = self
                .datagram_record_limit(pipe)
                .and_then(|limit| limit.checked_sub(frame_header));
            path.payload = path.payload.max(record);
            if matches!(affinity, Affinity::Any)
                && let Some(ch) = self.channel_for(pipe)
            {
                let prefix = ch.prefix.id().map_or(0, varint::len);
                let protocol = crate::util::usize_sat(data_limit);
                let payload = |size: usize| {
                    size.saturating_sub(prefix)
                        .min(protocol)
                        .checked_sub(frame_header)
                };
                path.native_payload = path.native_payload.max(payload(ch.capacity));
                path.native_room = path.native_room.max(payload(ch.room));
            }
        }
        path.payload = path.payload.max(path.native_payload);
        path
    }

    fn datagram_original_eligible(
        &self,
        a: &Attachment,
        gate: Option<&Gate>,
        affinity: Affinity,
    ) -> bool {
        a.out().is_some_and(super::pipes::OutPipe::takes_new_data)
            && match affinity {
                Affinity::Wait => false,
                Affinity::Follow(pipe) => pipe == a.id(),
                Affinity::Any => self.mp.is_none() || gate.is_some_and(|gate| self.takes(gate, a)),
            }
    }

    pub(super) fn datagram_record_limit(&self, id: u64) -> Option<usize> {
        let peer = self.peer_tp.as_ref()?;
        let record =
            crate::util::usize_sat(peer.max_datagram_frame_size().min(peer.max_record_size()));
        let carrier = self.out_ref(id)?.max_record().unwrap_or(usize::MAX);
        Some(record.min(carrier))
    }

    fn datagram_route(
        &self,
        packet: &OutDatagram,
        gate: Option<&Gate>,
        before_shaping: bool,
    ) -> Option<(f64, u64, DatagramRoute)> {
        let prefix = self.next_datagram_prefix(packet.flow)?;
        let affinity = self.datagram_affinity(packet.flow);
        if matches!(affinity, Affinity::Wait) || self.state >= State::Closing {
            return None;
        }
        let data_len = prefix.encoded_len() + packet.data.len();
        if let Some(pipe) = self.reserved_native_pipe(packet.tag)
            && self.native_original_fits(pipe, gate, affinity, data_len)
        {
            let a = self.att(pipe).expect("eligible pipe");
            if let Ok((eta, route)) =
                self.datagram_placement(a, data_len, true, true, before_shaping)
            {
                return Some((eta, pipe, route));
            }
        }
        self.atts
            .iter()
            .filter_map(|a| {
                let id = a.id();
                if !self.datagram_original_eligible(a, gate, affinity) {
                    return None;
                }
                let native = matches!(affinity, Affinity::Any);
                self.datagram_placement(a, data_len, packet.require_native, native, before_shaping)
                    .ok()
                    .map(|(eta, route)| (eta, id, route))
            })
            .min_by(|a, b| {
                a.2.channel()
                    .cmp(&b.2.channel())
                    .reverse()
                    .then_with(|| a.0.total_cmp(&b.0))
                    .then_with(|| a.1.cmp(&b.1))
            })
    }

    fn native_original_fits(
        &self,
        pipe: u64,
        gate: Option<&Gate>,
        affinity: Affinity,
        data_len: usize,
    ) -> bool {
        matches!(affinity, Affinity::Any)
            && self
                .att(pipe)
                .is_some_and(|a| self.datagram_original_eligible(a, gate, affinity))
            && self.channel_for(pipe).is_some_and(|ch| {
                crate::proto::frame::channel::datagram_len(ch.prefix.id(), data_len) <= ch.room
            })
    }

    pub(super) fn reserved_native_original(&self, pipe: u64, tag: u64) -> Option<usize> {
        let gate = self.path_gate();
        self.dgram().send.iter().position(|p| {
            p.tag == tag
                && self.next_datagram_prefix(p.flow).is_some_and(|prefix| {
                    self.native_original_fits(
                        pipe,
                        gate.as_ref(),
                        self.datagram_affinity(p.flow),
                        prefix.encoded_len() + p.data.len(),
                    )
                })
        })
    }

    fn datagram_placement(
        &self,
        attachment: &Attachment,
        data_len: usize,
        require_native: bool,
        native: bool,
        before_shaping: bool,
    ) -> Result<(f64, DatagramRoute), ReplicaDegradation> {
        let out = attachment.out().ok_or(ReplicaDegradation::NoEligiblePipe)?;
        let id = attachment.id();
        let limit = self
            .datagram_record_limit(id)
            .ok_or(ReplicaDegradation::NoEligiblePipe)?;
        let channel = native.then(|| self.channel_for(id)).flatten();
        if let Some(ch) = channel
            && crate::proto::frame::channel::datagram_len(ch.prefix.id(), data_len) <= ch.capacity
        {
            let eta =
                if crate::proto::frame::channel::datagram_len(ch.prefix.id(), data_len) > ch.room {
                    f64::INFINITY
                } else {
                    let travel = self
                        .rtt_of(Some(out))
                        .srtt
                        .unwrap_or_else(|| self.rtt_or_default())
                        / 2;
                    travel.as_secs_f64()
                };
            Ok((eta, DatagramRoute::Native(id)))
        } else if !require_native && data_len < limit {
            if !out.open()
                || out.limiter_held()
                || (before_shaping && !out.write_idle())
                || (!before_shaping && self.shape_delayed(id))
            {
                return Err(ReplicaDegradation::NoEligiblePipe);
            }
            let eta = if self.mp.is_some() {
                self.eta(attachment, out, (data_len + 1) as u64)
            } else {
                0.0
            };
            Ok((eta, DatagramRoute::Record(id)))
        } else if require_native && channel.is_none() {
            Err(ReplicaDegradation::NoEligiblePipe)
        } else {
            Err(ReplicaDegradation::Size)
        }
    }

    /// Supplies a local failure-domain identity for this pipe's outbound
    /// carrier. A missing identity cannot establish independence.
    pub fn set_pipe_replica_domain(
        &mut self,
        pipe: super::PipeId,
        domain: Option<std::num::NonZeroU64>,
    ) -> Result<(), super::PipeError> {
        if self.mp.is_none() {
            return Err(super::PipeError::NotNegotiated);
        }
        let attachment = self
            .att_mut(pipe.0)
            .filter(|a| a.out().is_some())
            .ok_or(super::PipeError::UnknownPipe)?;
        if attachment.replica_domain() != domain {
            attachment.set_replica_domain(domain);
            self.reset_datagram_pairings(pipe.0);
        }
        Ok(())
    }

    fn queue_datagram_replicas(
        &mut self,
        route: DatagramRoute,
        packet: &OutDatagram,
        sequence: u64,
    ) {
        let requested = match packet.copy_policy {
            DatagramCopyPolicy::Duplicate(total) => usize::from(total.get()),
            DatagramCopyPolicy::Adaptive => 2,
            DatagramCopyPolicy::Single => return,
        };
        let prefix = DatagramPrefix::Sequenced {
            sequence,
            flow: self.flow_of(packet.flow).expect("same family has a flow"),
        };
        let wire_len = prefix.encoded_len() + packet.data.len();
        let first_copy = self
            .dgram()
            .copies
            .as_ref()
            .map_or(0, |copies| copies.queue.len());
        let adaptive = packet.copy_policy == DatagramCopyPolicy::Adaptive;
        let independent = packet.independent_replicas();
        let limit = usize::from(self.config.datagram_config().copy_limit.get());
        let count = requested.min(limit).saturating_sub(1);
        if count == 0 {
            return;
        }
        if self.mp.is_none() || !matches!(self.datagram_affinity(packet.flow), Affinity::Any) {
            if adaptive {
                return;
            }
            let reason = if self.mp.is_none() {
                ReplicaDegradation::NoEligiblePipe
            } else {
                ReplicaDegradation::OpenFence
            };
            self.dgram_mut()
                .stats
                .replica_degradation
                .count(reason, count as u64);
            return;
        }
        let urgent = adaptive
            && packet.urgent.unwrap_or_else(|| {
                packet
                    .flow
                    .is_some_and(|(id, _)| self.datagram_urgency(Some(id)) <= 2)
            });
        let mut queued = false;
        for i in 0..count {
            let target = if datagram_replica_charge(packet.data.len()) > self.replica_room()
                || self.dgram().copies.as_ref().is_some_and(|copies| {
                    copies.occupied() >= self.config.datagram_send_queue
                        || wire_len
                            > self
                                .config
                                .datagram_config()
                                .send_bytes
                                .saturating_sub(copies.occupied_bytes())
                })
                || wire_len > self.config.datagram_config().send_bytes
            {
                Err(ReplicaDegradation::Budget)
            } else if adaptive {
                match self.adaptive_target(route, packet, wire_len, first_copy, urgent) {
                    Err(_) if !urgent => break,
                    target => target,
                }
            } else {
                self.pick_datagram_replica(route.pipe(), packet, wire_len, first_copy)
            };
            let target = match target {
                Ok(target) => target,
                Err(reason) => {
                    self.dgram_mut()
                        .stats
                        .replica_degradation
                        .count(reason, (count - i) as u64);
                    break;
                }
            };
            queued = true;
            let turn = self.streams.next_send_turn();
            let adaptive = adaptive.then(|| {
                self.bind_adaptive_pair(route.feedback_path(), target.feedback_path(), urgent)
            });
            self.dgram_mut()
                .copies
                .get_or_insert_with(Box::default)
                .insert(DatagramReplica {
                    original: route.pipe(),
                    target: target.pipe(),
                    prefix,
                    data: packet.data.clone(),
                    #[cfg(all(feature = "tokio", not(loom)))]
                    handoff: packet.handoff.clone(),
                    turn,
                    deadline: packet.deadline,
                    require_native: packet.require_native,
                    independent,
                    adaptive,
                    shape_held: std::time::Duration::ZERO,
                });
        }
        if queued {
            self.channel_kick();
        }
    }

    fn pick_datagram_replica(
        &self,
        source: u64,
        packet: &OutDatagram,
        wire_len: usize,
        first_copy: usize,
    ) -> Result<DatagramRoute, ReplicaDegradation> {
        let mut reason = ReplicaDegradation::NoEligiblePipe;
        let chosen = self
            .datagram_replica_candidates(source, packet, wire_len, first_copy)
            .filter_map(|place| match place {
                Ok(place) => Some(place),
                Err(failure) => {
                    reason = reason.max(failure);
                    None
                }
            })
            .min_by(compare_replica_eta);
        chosen.map(|(_, route)| route).ok_or(reason)
    }

    fn datagram_replica_candidates<'a>(
        &'a self,
        source: u64,
        packet: &'a OutDatagram,
        wire_len: usize,
        first_copy: usize,
    ) -> impl Iterator<Item = Result<(f64, DatagramRoute), ReplicaDegradation>> + 'a {
        let original = self.att(source);
        let next_tier = original.and_then(|a| self.next_replica_tier(a.send_tier()));
        self.atts
            .iter()
            .filter(move |target| {
                self.dgram().copies.as_ref().is_none_or(|copies| {
                    copies
                        .queue
                        .iter()
                        .skip(first_copy)
                        .all(|selected| selected.target != target.id())
                })
            })
            .filter_map(move |target| {
                let original = original?;
                let place = self.place_datagram_replica(
                    original, target, next_tier, wire_len, packet, first_copy,
                );
                Some(place.and_then(|(eta, route)| {
                    if packet.copy_policy == DatagramCopyPolicy::Adaptive && eta.is_infinite() {
                        return Err(ReplicaDegradation::NoEligiblePipe);
                    }
                    self.datagram_can_arrive(eta, packet.deadline)
                        .then_some((eta, route))
                        .ok_or(ReplicaDegradation::Deadline)
                }))
            })
    }

    fn place_datagram_replica(
        &self,
        original: &Attachment,
        target: &Attachment,
        next_tier: Option<u64>,
        wire_len: usize,
        packet: &OutDatagram,
        first_copy: usize,
    ) -> Result<(f64, DatagramRoute), ReplicaDegradation> {
        use super::path::redundancy::independent_fates;
        let independent = packet.independent_replicas();
        self.check_datagram_replica(original, target, next_tier, independent)?;
        if independent
            && self.dgram().copies.as_ref().is_some_and(|copies| {
                copies.queue.iter().skip(first_copy).any(|selected| {
                    self.att(selected.target)
                        .is_none_or(|prev| !independent_fates(prev, target))
                })
            })
        {
            return Err(ReplicaDegradation::Fate);
        }
        self.datagram_placement(target, wire_len, packet.require_native, true, false)
    }

    fn check_datagram_replica(
        &self,
        original: &Attachment,
        target: &Attachment,
        next_tier: Option<u64>,
        independent: bool,
    ) -> Result<(), ReplicaDegradation> {
        if !self.replica_eligible(original, target, next_tier) {
            return Err(ReplicaDegradation::NoEligiblePipe);
        }
        if independent && !super::path::redundancy::independent_fates(original, target) {
            return Err(ReplicaDegradation::Fate);
        }
        Ok(())
    }

    fn adaptive_target(
        &mut self,
        route: DatagramRoute,
        packet: &OutDatagram,
        wire_len: usize,
        first_copy: usize,
        urgent: bool,
    ) -> Result<DatagramRoute, ReplicaDegradation> {
        if urgent {
            return self.pick_datagram_replica(route.pipe(), packet, wire_len, first_copy);
        }
        let mut candidates: Vec<_> = self
            .datagram_replica_candidates(route.pipe(), packet, wire_len, first_copy)
            .filter_map(Result::ok)
            .collect();
        candidates.sort_unstable_by(compare_replica_eta);
        let target = candidates.into_iter().find_map(|(_, candidate)| {
            self.datagram_impairment(route.feedback_path(), candidate.feedback_path())
                .then_some(candidate)
        });
        if target.is_none() {
            self.clear_datagram_impairment(route.feedback_path());
        }
        target.ok_or(ReplicaDegradation::NoEligiblePipe)
    }

    fn datagram_can_arrive(&self, eta: f64, deadline: Option<Instant>) -> bool {
        deadline.is_none_or(|deadline| {
            deadline > self.now && eta <= deadline.saturating_duration_since(self.now).as_secs_f64()
        })
    }

    fn datagram_replica_route(
        &self,
        copy: &DatagramReplica,
        before_shaping: bool,
    ) -> Result<DatagramRoute, ReplicaDegradation> {
        let source = self
            .att(copy.original)
            .ok_or(ReplicaDegradation::NoEligiblePipe)?;
        let target = self
            .att(copy.target)
            .ok_or(ReplicaDegradation::NoEligiblePipe)?;
        let next_tier = self.next_replica_tier(source.send_tier());
        self.check_datagram_replica(source, target, next_tier, copy.independent)?;
        let (eta, route) = self.datagram_placement(
            target,
            copy.prefix.encoded_len() + copy.data.len(),
            copy.require_native,
            true,
            before_shaping,
        )?;
        if copy.adaptive.as_ref().is_some_and(|pair| {
            pair.channel() != route.channel() || !self.adaptive_pair_current(pair)
        }) {
            return Err(ReplicaDegradation::NoEligiblePipe);
        }
        (eta.is_infinite() || self.datagram_can_arrive(eta, copy.deadline))
            .then_some(route)
            .ok_or(ReplicaDegradation::Deadline)
    }

    pub(super) fn datagrams_pending(&self) -> bool {
        let state = self.dgram();
        !state.send.is_empty()
            || state
                .copies
                .as_ref()
                .is_some_and(|copies| !copies.queue.is_empty())
    }

    pub(super) fn prune_datagram_replicas(&mut self) {
        if self
            .dgram()
            .copies
            .as_ref()
            .is_none_or(|copies| copies.queue.is_empty())
        {
            return;
        }
        let mut copies = self.dgram_mut().copies.take().expect("queued replicas");
        let mut i = copies.queue.len();
        while i > 0 {
            i -= 1;
            let copy = &copies.queue[i];
            if self
                .out_ref(copy.target)
                .is_none_or(|out| !out.takes_new_data())
                || self.att(copy.original).is_none()
            {
                copies.remove(i);
                self.dgram_mut()
                    .stats
                    .replica_degradation
                    .count(ReplicaDegradation::NoEligiblePipe, 1);
            }
        }
        self.dgram_mut().copies = Some(copies);
    }

    /// A candidate on the current writer. A replica whose path became
    /// invalid also makes the writer ready so the queue can release it.
    pub(super) fn datagram_replica_due(&self, route: DatagramRoute) -> bool {
        self.dgram().copies.as_ref().is_some_and(|copies| {
            copies.queue.iter().any(|copy| {
                copy.target == route.pipe()
                    && !self
                        .datagram_replica_route(copy, false)
                        .is_ok_and(|place| place != route)
            })
        })
    }

    pub(super) fn next_datagram_replica_for(
        &mut self,
        route: DatagramRoute,
        required: Option<u64>,
    ) -> Option<(usize, &DatagramReplica)> {
        loop {
            let copies = self.dgram().copies.as_ref()?;
            let candidate = copies.queue.iter().enumerate().filter_map(|(i, copy)| {
                if copy.target != route.pipe()
                    || required.is_some_and(|sequence| !matches!(copy.prefix, DatagramPrefix::Sequenced { sequence: actual, .. } if actual == sequence))
                {
                    return None;
                }
                match self.datagram_replica_route(copy, false) {
                    Ok(place) if place == route => Some((i, Ok(()))),
                    Ok(_) => None,
                    Err(reason) => Some((i, Err(reason))),
                }
            }).min_by_key(|&(i, result)| result.ok().map(|()| self.replica_rank(&copies.queue[i])));
            let (i, path) = candidate?;
            let result = path.and_then(|()| {
                // The record writer still has to arbitrate against other data.
                // Only the native writer has already chosen this replica.
                if matches!(route, DatagramRoute::Native(_)) {
                    self.datagram_replica_budget(&copies.queue[i])
                } else {
                    Ok(())
                }
            });
            let Err(reason) = result else {
                let copy = &copies.queue[i];
                if let DatagramRoute::Native(id) = route
                    && !self.channel_for(id).is_some_and(|ch| {
                        crate::proto::frame::channel::datagram_len(
                            ch.prefix.id(),
                            copy.prefix.encoded_len() + copy.data.len(),
                        ) <= ch.room
                    })
                {
                    return None;
                }
                return Some((i, &self.dgram().copies.as_ref()?.queue[i]));
            };
            self.drop_datagram_replica(i, reason);
        }
    }

    fn datagram_replica_budget(&self, copy: &DatagramReplica) -> Result<(), ReplicaDegradation> {
        (datagram_replica_charge(copy.data.len()) <= self.replica_room())
            .then_some(())
            .ok_or(ReplicaDegradation::Budget)
    }

    fn drop_datagram_replica(&mut self, i: usize, reason: ReplicaDegradation) {
        let state = self.dgram_mut();
        state
            .copies
            .as_deref_mut()
            .expect("candidate queue")
            .remove(i);
        state.stats.replica_degradation.count(reason, 1);
    }

    pub(super) fn record_replica_has_budget(&mut self, i: usize) -> bool {
        let copy = self
            .dgram()
            .copies
            .as_ref()
            .expect("selected replica")
            .get(i);
        match self.datagram_replica_budget(copy) {
            Ok(()) => true,
            Err(reason) => {
                self.drop_datagram_replica(i, reason);
                false
            }
        }
    }

    pub(super) fn native_replica_for_wait(
        &self,
        pipe: u64,
        sequence: u64,
    ) -> Option<&DatagramReplica> {
        self.dgram().copies.as_ref()?.queue.iter().find(|copy| {
            copy.target == pipe
                && matches!(copy.prefix, DatagramPrefix::Sequenced { sequence: seq, .. } if seq == sequence)
        })
    }

    pub(super) fn dispatch_datagram_replica(&mut self, route: DatagramRoute, i: usize) {
        let state = self.dgram_mut();
        let copies = state.copies.as_deref_mut().expect("queued replica");
        let copy = copies.remove(i);
        if matches!(route, DatagramRoute::Native(_)) {
            copies
                .native
                .add(copy.data.len() + copy.prefix.encoded_len());
        }
        let DatagramPrefix::Sequenced { sequence, .. } = copy.prefix else {
            unreachable!("only same-family datagrams have replicas");
        };
        let bytes = copy.data.len() as u64;
        state.stats.dispatch(route, true, bytes);
        self.replica_bytes(datagram_replica_charge(copy.data.len()), true);
        self.note_datagram_dispatch((route.pipe(), route.channel()), sequence);
    }

    fn datagram_urgency(&self, stream: Option<u64>) -> usize {
        usize::from(
            match stream {
                None => self.config.datagram_config().priority,
                Some(id) => self
                    .streams
                    .key_of(id)
                    .and_then(|key| self.priority(key))
                    .unwrap_or(crate::proto::frame::Priority::LOCAL_DEFAULT),
            }
            .urgency(),
        )
    }

    fn replica_rank(&self, copy: &DatagramReplica) -> SendRank {
        let stream = match copy.prefix {
            DatagramPrefix::Sequenced {
                flow: crate::proto::payload::Flow::Stream { stream_id, .. },
                ..
            } => Some(stream_id),
            _ => None,
        };
        (self.datagram_urgency(stream), copy.turn)
    }

    /// The dispatch a queued packet could use without a reliable shaping hold.
    fn ready_datagram_route(
        &self,
        packet: &OutDatagram,
        gate: Option<&Gate>,
    ) -> Option<DatagramRoute> {
        if !self.datagram_flow_open(packet.flow) {
            return None;
        }
        let (eta, _, route) = self.datagram_route(packet, gate, true)?;
        (eta.is_finite() && self.datagram_can_arrive(eta, packet.deadline)).then_some(route)
    }

    /// A shaping hold of a Flow's head also holds its otherwise ready successors.
    fn ready_shape_flow<'a>(
        &'a self,
        packets: &'a VecDeque<OutDatagram>,
        gate: Option<&'a Gate>,
    ) -> impl Iterator<Item = &'a OutDatagram> {
        packets
            .iter()
            .filter(move |packet| self.ready_datagram_route(packet, gate).is_some())
    }

    fn datagram_wait_left(&self, spent: Duration, deadline: Option<Instant>) -> Duration {
        let left = self
            .shaping_limits_in_force()
            .max_added_delay()
            .saturating_sub(spent);
        deadline.map_or(left, |at| left.min(at.saturating_duration_since(self.now)))
    }

    pub(super) fn record_flow_budget(&self, pipe: u64) -> Duration {
        self.datagram_flow_budget(DatagramRoute::Record(pipe))
    }

    pub(super) fn datagram_flow_budget(&self, route: DatagramRoute) -> Duration {
        if !self.datagrams_pending() {
            return Duration::MAX;
        }
        let gate = self.path_gate();
        let originals = self
            .dgram()
            .send
            .flows
            .iter()
            .filter(|flow| {
                self.ready_datagram_route(&flow.packets[0], gate.as_ref()) == Some(route)
            })
            .flat_map(|flow| self.ready_shape_flow(&flow.packets, gate.as_ref()))
            .map(|packet| self.datagram_wait_left(packet.shape_held, packet.deadline));
        let replicas = self
            .dgram()
            .copies
            .iter()
            .flat_map(|copies| &copies.queue)
            .filter(|copy| self.ready_replica_route(copy) == Some(route))
            .map(|copy| self.datagram_wait_left(copy.shape_held, copy.deadline));
        originals.chain(replicas).min().unwrap_or(Duration::MAX)
    }

    fn ready_replica_route(&self, copy: &DatagramReplica) -> Option<DatagramRoute> {
        let route = self.datagram_replica_route(copy, true).ok()?;
        if let DatagramRoute::Native(pipe) = route {
            let channel = self.channel_for(pipe)?;
            let len = crate::proto::frame::channel::datagram_len(
                channel.prefix.id(),
                copy.prefix.encoded_len() + copy.data.len(),
            );
            if len > channel.room {
                return None;
            }
        }
        Some(route)
    }

    fn datagram_wait_end(&self, route: DatagramRoute) -> Option<Instant> {
        match route {
            DatagramRoute::Record(pipe) => self.record_shaping_wait(pipe),
            DatagramRoute::Native(pipe) => self.native_shaping_wait(pipe),
        }
        .filter(|&end| end > self.now)
    }

    /// The owner charges each queued unit once for elapsed shaping time,
    /// irrespective of which writer held its Flow. Queueing, expiry, route
    /// changes and writer completions advance the clock before changing eligibility.
    pub(super) fn advance_datagram_waits(&mut self, until: Instant) {
        if !self.datagrams_pending() {
            return;
        }
        let now = self.now;
        let limit = self.shaping_limits_in_force().max_added_delay();
        let gate = self.path_gate();
        let mut originals = Vec::new();
        for (flow, queue) in self.dgram().send.flows.iter().enumerate() {
            let head = &queue.packets[0];
            let Some(route) = self.ready_datagram_route(head, gate.as_ref()) else {
                continue;
            };
            let Some(end) = self.datagram_wait_end(route) else {
                continue;
            };
            for (index, packet) in queue.packets.iter().enumerate() {
                if self.ready_datagram_route(packet, gate.as_ref()).is_some() {
                    originals.push((flow, index, end, route));
                }
            }
        }
        let mut replicas = Vec::new();
        for (index, copy) in self
            .dgram()
            .copies
            .iter()
            .flat_map(|c| &c.queue)
            .enumerate()
        {
            let Some(route) = self.ready_replica_route(copy) else {
                continue;
            };
            if let Some(end) = self.datagram_wait_end(route) {
                replicas.push((index, end, route));
            }
        }
        for (flow, index, end, route) in originals {
            let packet = &mut self.dgram_mut().send.flows[flow].packets[index];
            let added = charge_shape_wait(
                &mut packet.shape_held,
                now.max(packet.at),
                until.min(end),
                packet.deadline,
                limit,
            );
            let spent = packet.shape_held;
            self.note_datagram_delay(route, now + added, added, spent);
        }
        for (index, end, route) in replicas {
            let copy = &mut self
                .dgram_mut()
                .copies
                .as_mut()
                .expect("waiting replicas")
                .queue[index];
            let added = charge_shape_wait(
                &mut copy.shape_held,
                now,
                until.min(end),
                copy.deadline,
                limit,
            );
            let spent = copy.shape_held;
            self.note_datagram_delay(route, now + added, added, spent);
        }
    }

    pub(super) fn ready_record_datagram(&mut self, pipe: u64) -> Option<ReadyDatagram> {
        let route = DatagramRoute::Record(pipe);
        let original = self.next_datagram_flow(route);
        let replica = self
            .next_datagram_replica_for(route, None)
            .map(|(index, _)| index);
        let replica = replica.map(|index| ReadyDatagram {
            index,
            rank: self.replica_rank(&self.dgram().copies.as_ref().unwrap().queue[index]),
            replica: true,
        });
        match original {
            Some((index, rank)) if replica.as_ref().is_none_or(|copy| rank < copy.rank) => {
                Some(ReadyDatagram {
                    index,
                    rank,
                    replica: false,
                })
            }
            _ => replica,
        }
    }

    pub(super) fn next_datagram_flow(&self, route: DatagramRoute) -> Option<(usize, SendRank)> {
        let send = &self.dgram().send;
        if send.is_empty() {
            return None;
        }
        let gate = self.path_gate();
        let mut best = None;
        for (index, flow) in send.flows.iter().enumerate() {
            let rank = (self.datagram_urgency(flow.stream), flow.turn);
            if best.is_some_and(|(_, current)| current <= rank) {
                continue;
            }
            let packet = flow.packets.front().expect("nonempty flow");
            if self.reserved_native_pipe(packet.tag).is_some() {
                continue;
            }
            if self
                .datagram_route(packet, gate.as_ref(), false)
                .is_some_and(|(eta, _, candidate)| {
                    route == candidate
                        && eta.is_finite()
                        && self.datagram_can_arrive(eta, packet.deadline)
                })
            {
                best = Some((index, rank));
            }
        }
        best
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn plan_splice_datagrams(
        &mut self,
        flow: (super::StreamKey, u64),
        sizes: impl ExactSizeIterator<Item = usize> + Clone,
        options: ResolvedDatagramOptions,
        policy: SendPolicy,
    ) -> Result<PacketRepresentation, super::DatagramError> {
        if options
            .deadline
            .is_some_and(|deadline| deadline <= self.now)
        {
            return Err(super::DatagramError::Dropped(DatagramDrop::Deadline));
        }
        let remaining = (varint::MAX + 1).saturating_sub(self.dgram().next_sequence);
        if remaining < sizes.len() as u64 {
            return Err(super::DatagramError::SequenceExhausted);
        }
        let largest = sizes.clone().max().unwrap_or(0);
        let selected = self.stream_packet_representation(flow, largest, options, policy)?;
        if let PacketRepresentation::Datagram { stream_id, .. } = selected
            && !self
                .dgram()
                .send
                .splice_group_fits(stream_id, sizes, &self.config)
        {
            return Err(super::DatagramError::Dropped(DatagramDrop::QueueOverflow));
        }
        Ok(selected)
    }

    /// Admits all splice children under the same target state before making
    /// any of them visible to ordinary datagram dispatch.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn commit_splice_datagrams(
        &mut self,
        flow: (super::StreamKey, u64),
        data: &[bytes::Bytes],
        options: ResolvedDatagramOptions,
        policy: SendPolicy,
        mut payment: Option<&mut super::splice_handoff::Prepayment<'_>>,
    ) -> Result<PacketRepresentation, super::DatagramError> {
        let selected =
            self.plan_splice_datagrams(flow, data.iter().map(bytes::Bytes::len), options, policy)?;
        let PacketRepresentation::Datagram { stream_id, context } = selected else {
            return Ok(selected);
        };
        let id = self.stream_id(flow.0).map_err(|error| match error {
            super::StreamError::Blocked => super::DatagramError::Blocked,
            _ => super::DatagramError::ClosedStream,
        })?;
        debug_assert_eq!(stream_id, id);
        for child in data {
            let mut packet = self.outgoing_datagram(Some((id, context)), child.clone(), options);
            if let Some(payment) = payment.as_mut() {
                let handoff = payment.prepare(child.len());
                payment.accept(&handoff);
                packet.handoff = Some(handoff);
            }
            let turn = self.streams.next_send_turn();
            let dgram = self.dgram.get_or_insert_with(Box::default);
            let (accepted, dropped) = dgram.send.queue(packet, &self.config, turn);
            debug_assert!(
                accepted && dropped == 0,
                "the complete splice group was reserved"
            );
        }
        self.constrain_native_flows();
        self.prepare_datagram_dispatch();
        self.channel_kick();
        Ok(selected)
    }

    pub(super) fn outgoing_datagram(
        &self,
        flow: Flow,
        data: bytes::Bytes,
        options: ResolvedDatagramOptions,
    ) -> OutDatagram {
        OutDatagram {
            flow,
            data,
            at: self.now,
            deadline: options.deadline,
            require_native: options.require_native,
            copy_policy: options.copies,
            urgent: options.urgent,
            independent_fate: options.independent_fate,
            tag: 0,
            shape_held: std::time::Duration::ZERO,
            #[cfg(all(feature = "tokio", not(loom)))]
            handoff: None,
        }
    }

    pub(super) fn datagram_send_deadline(&self) -> Option<Instant> {
        self.dgram()
            .send
            .deadline
            .into_iter()
            .chain(
                self.dgram()
                    .copies
                    .as_ref()
                    .and_then(|copies| copies.deadline),
            )
            .min()
    }

    pub(super) fn expire_send_datagrams(&mut self) {
        let Some(d) = self.dgram.as_deref_mut() else {
            return;
        };
        let was_full = d.send.occupied() >= self.config.datagram_send_queue;
        if let Some(copies) = d.copies.as_deref_mut()
            && copies.deadline.is_some_and(|at| at <= self.now)
        {
            let mut i = copies.queue.len();
            while i > 0 {
                i -= 1;
                if copies.queue[i].deadline.is_some_and(|at| at <= self.now) {
                    copies.remove(i);
                    d.stats
                        .replica_degradation
                        .count(ReplicaDegradation::Deadline, 1);
                }
            }
        }
        let dropped = d.send.expire(self.now);
        if dropped > 0 {
            d.stats.drops.count(DatagramDrop::Deadline, dropped);
            if was_full && d.send.occupied() < self.config.datagram_send_queue {
                self.events.push_back(super::CoreEvent::DatagramsUnblocked);
            }
            self.channel_kick();
        }
    }

    fn drop_datagrams_missing_eta(&mut self) {
        if self.datagram_send_deadline().is_none() {
            return;
        }
        let gate = self.path_gate();
        loop {
            let late = self.dgram().send.iter().position(|packet| {
                let Some(deadline) = packet.deadline else {
                    return false;
                };
                self.datagram_route(packet, gate.as_ref(), false)
                    .is_some_and(|(eta, _, _)| {
                        eta.is_finite()
                            && eta > deadline.saturating_duration_since(self.now).as_secs_f64()
                    })
            });
            let Some(i) = late else {
                return;
            };
            self.take_send_datagram(i);
            self.count_datagram_drop(DatagramDrop::Deadline, 1);
        }
    }

    pub(super) fn prepare_datagram_dispatch(&mut self) {
        if !self.datagrams_pending() {
            return;
        }
        self.expire_send_datagrams();
        self.drop_datagrams_missing_eta();
        self.discard_oversized_datagram_heads();
    }

    fn discard_oversized_datagram_heads(&mut self) {
        let Some(max_frame) = self.structural_datagram_frame_limit() else {
            self.discard_unsendable_datagrams(DatagramDrop::Size);
            return;
        };
        loop {
            let invalid = self
                .dgram()
                .send
                .iter()
                .enumerate()
                .find_map(|(i, packet)| {
                    let reason = if !self.datagram_flow_open(packet.flow) {
                        DatagramDrop::ClosedFlow
                    } else if packet.require_native && !self.features.carrier_datagrams {
                        DatagramDrop::NoNativePath
                    } else if self.next_datagram_prefix(packet.flow).is_none_or(|prefix| {
                        prefix.encoded_len() + 1 + packet.data.len() > max_frame
                    }) {
                        DatagramDrop::Size
                    } else {
                        return None;
                    };
                    Some((i, reason))
                });
            let Some((i, reason)) = invalid else {
                break;
            };
            self.take_send_datagram(i);
            self.count_datagram_drop(reason, 1);
        }
    }
}
