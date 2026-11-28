//! Admissions that protect outstanding connection credit on the live ledger.

use std::sync::Arc;

use super::{PipeError, SessionCore, recv_store::ReceiveStore};
use crate::ConnectError;
use crate::proto::memory::{Ledger, ReceiveWindow, Reservation};
use crate::proto::receive::MAX_CLASS;

/// Smallest initial `MAX_DATA` accepted when admission reduces the requested value.
pub(super) const MIN_INITIAL: u64 = 16 * 1024;

/// The current root, its replacement, and the parser or message staging
/// root can coexist even when no STREAM byte is buffered. A driver books
/// retained old roots separately as it keeps them.
const INBOUND_WORK: u64 = 3 * MAX_CLASS as u64;

/// Hello verification, key exchange, and the outgoing reply or confirm may
/// overlap while the carrier's setup bytes are still present.
const JOIN_WORK: u64 = 3 * MAX_CLASS as u64;

const RECEIVE_POSITION: u64 = ReceiveStore::POSITION_COST;

const RECEIVE_FIXED: u64 = MAX_CLASS as u64
    + INBOUND_WORK
    + ReceiveStore::BASE_COST
    + 4 * size_of::<(u64, usize, usize)>() as u64;

// A regular credit step of the default stream byte window funds one batch
// of direction descriptors.
const EARLY_BIDI_CREDIT: u64 = 4;
const BATCH_FROM_STREAM_WINDOW: u64 = (super::config::DEFAULT_INITIAL_STREAM_RECEIVE_WINDOW / 4)
    * RECEIVE_POSITION
    / ReceiveStore::DIRECTION_COST;
const ADMISSION_BATCH: u64 = if BATCH_FROM_STREAM_WINDOW < EARLY_BIDI_CREDIT {
    EARLY_BIDI_CREDIT
} else {
    BATCH_FROM_STREAM_WINDOW
};

#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
fn listener_directions(config: &super::Config) -> [u64; 2] {
    let (uni, staged) = match config.max_incoming_uni_streams {
        super::UniCredit::Staged => (super::config::STAGED_UNI_STREAMS.0, true),
        super::UniCredit::Limit(count) => (count, false),
    };
    listener_stream_limits([config.max_incoming_streams, uni], staged)
}

pub(super) fn listener_stream_limits([bidi, uni]: [u64; 2], staged: bool) -> [u64; 2] {
    let uni = if staged {
        uni
    } else {
        uni.min(ADMISSION_BATCH)
    };
    [bidi.min(ADMISSION_BATCH), uni]
}

fn bootstrap_fixed(peer_directions: u64, transport: u64) -> Option<u64> {
    RECEIVE_FIXED
        .checked_add(peer_directions.checked_mul(ReceiveStore::DIRECTION_COST)?)?
        .checked_add(transport)
}

#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub(crate) fn minimum_listener_admission(config: &super::Config) -> u64 {
    bootstrap_fixed(listener_directions(config).into_iter().sum(), 0)
        .and_then(|fixed| fixed.checked_add(MIN_INITIAL * RECEIVE_POSITION))
        .unwrap_or(u64::MAX)
}

/// Direction-local backing can leave as the direction is discarded. The
/// shared arenas retain their descriptor allowance until they can be freed.
#[derive(Debug)]
struct DirectionCredit {
    grant: Reservation,
    slots: [u64; 3],
    arena_slots: u64,
}

const LOCAL: usize = 2;

impl DirectionCredit {
    fn reusable(&self) -> u64 {
        self.arena_slots - self.slots.iter().sum::<u64>()
    }

    fn try_fund(&mut self, slots: [u64; 3]) -> bool {
        let added: u64 = slots
            .iter()
            .zip(self.slots)
            .map(|(new, old)| new - old)
            .sum();
        let new_arena = added.saturating_sub(self.reusable());
        let Some(bytes) = added
            .checked_mul(ReceiveStore::DIRECTION_PRIVATE)
            .and_then(|bytes| {
                bytes.checked_add(new_arena.checked_mul(ReceiveStore::DIRECTION_ARENA)?)
            })
        else {
            return false;
        };
        let Some(total) = self.grant.bytes().checked_add(bytes) else {
            return false;
        };
        if !self.grant.resize_growth(total) {
            return false;
        }
        self.arena_slots += new_arena;
        self.slots = slots;
        true
    }

    fn fund_peer(&mut self, d: usize, target: u64) -> u64 {
        let wanted = target.saturating_sub(self.slots[d]);
        let reuse = self
            .grant
            .grow_units(ReceiveStore::DIRECTION_PRIVATE, wanted.min(self.reusable()));
        let fresh = self
            .grant
            .grow_units(ReceiveStore::DIRECTION_COST, wanted - reuse);
        self.arena_slots += fresh;
        self.slots[d] += reuse + fresh;
        self.slots[d].min(target)
    }

    fn release(&mut self, d: usize, keep: u64) {
        let freed = self.slots[d].saturating_sub(keep);
        if freed != 0 {
            self.slots[d] -= freed;
            assert!(
                self.grant
                    .resize(self.grant.bytes() - freed * ReceiveStore::DIRECTION_PRIVATE)
            );
        }
    }

    fn release_arena(&mut self) {
        let excess = self.reusable();
        if excess != 0 {
            assert!(
                self.grant
                    .resize(self.grant.bytes() - excess * ReceiveStore::DIRECTION_ARENA)
            );
            self.arena_slots -= excess;
        }
    }
}

#[derive(Debug)]
pub(super) struct ReceiveCredit {
    grant: Reservation,
    #[cfg(all(feature = "tokio", not(loom)))]
    transport: Option<Reservation>,
    /// High watermark of promised and still-buffered positions. Free slots
    /// remain available in both arenas and can fund newly promised bytes.
    window: ReceiveWindow,
    directions: DirectionCredit,
    blocked_at: Option<u64>,
    streams_blocked_at: [Option<(u64, u64)>; 2],
}

impl ReceiveCredit {
    pub(super) fn admit(
        ledger: &Arc<Ledger>,
        wanted: u64,
        transport: u64,
        [bidi, uni]: [u64; 2],
    ) -> Result<(Self, u64), ConnectError> {
        // Trusted trace hooks can override the protocol parameters below
        // the minimum. Application configuration always passes validation.
        let minimum = wanted.min(MIN_INITIAL);
        let total = bidi.checked_add(uni).ok_or(ConnectError::MemoryBudget)?;
        let directions = total
            .checked_mul(ReceiveStore::DIRECTION_COST)
            .ok_or(ConnectError::MemoryBudget)?;
        let fixed = bootstrap_fixed(total, transport).ok_or(ConnectError::MemoryBudget)?;
        let (mut grant, window) = ledger
            .reserve_receive(fixed, RECEIVE_POSITION, minimum, wanted)
            .ok_or(ConnectError::MemoryBudget)?;
        #[cfg(all(feature = "tokio", not(loom)))]
        let transport = (transport != 0).then(|| grant.split_off(transport));
        #[cfg(not(all(feature = "tokio", not(loom))))]
        drop(grant.split_off(transport));
        let positions = window.bytes() / RECEIVE_POSITION;
        let directions = DirectionCredit {
            grant: grant.split_off(directions),
            slots: [bidi, uni, 0],
            arena_slots: total,
        };
        Ok((
            Self {
                grant,
                #[cfg(all(feature = "tokio", not(loom)))]
                transport,
                window,
                directions,
                blocked_at: None,
                streams_blocked_at: [None; 2],
            },
            positions,
        ))
    }

    fn positions(&self) -> u64 {
        self.window.bytes() / RECEIVE_POSITION
    }

    pub(super) fn possible(&self) -> u64 {
        self.positions() + self.window.growth_room() / RECEIVE_POSITION
    }

    fn join_work(&self) -> Result<JoinWork, PipeError> {
        let grant = self
            .grant
            .reserve(JOIN_WORK)
            .ok_or(PipeError::MemoryBudget)?;
        Ok(JoinWork {
            _grant: Arc::new(grant),
        })
    }

    fn open_direction(&mut self) -> bool {
        let mut slots = self.directions.slots;
        slots[LOCAL] += 1;
        self.directions.try_fund(slots)
    }

    fn stream_release_epoch(&self, d: usize, limit: u64) -> Option<u64> {
        self.streams_blocked_at[d]
            .and_then(|(blocked_limit, epoch)| (blocked_limit == limit).then_some(epoch))
    }

    fn release_unused(&mut self, needed: u64) {
        self.window
            .shrink(needed.min(self.positions()) * RECEIVE_POSITION);
        self.directions.release_arena();
    }

    fn reserve(&mut self, positions: u64) -> u64 {
        let epoch = self.grant.release_epoch();
        let wanted = positions.saturating_sub(self.positions());
        self.window.grow_units(RECEIVE_POSITION, wanted);
        let granted = self.positions().min(positions);
        self.blocked_at = (granted < positions).then_some(epoch);
        granted
    }
}

/// The working grant travels with the handshake instead of an attachment ID.
/// Its work may survive the attachment, for example during an outgoing write.
#[derive(Debug, Clone)]
pub(crate) struct JoinWork {
    _grant: Arc<Reservation>,
}

impl SessionCore {
    pub(crate) fn write_domain(&self) -> Option<&Arc<Ledger>> {
        self.receive_credit
            .as_ref()
            .map(|credit| credit.grant.domain())
    }

    pub(super) fn current_budget_epoch(&self) -> Option<u64> {
        self.receive_credit
            .as_ref()
            .map(|credit| credit.grant.release_epoch())
    }

    #[inline]
    pub(crate) fn wake_memory_writers(&mut self) -> bool {
        self.write_blocked_at.is_some() && self.resume_memory_writers()
    }

    #[cold]
    fn resume_memory_writers(&mut self) -> bool {
        if self.write_blocked_at == self.current_budget_epoch() {
            return false;
        }
        self.write_blocked_at = None;
        let mut writers = std::mem::take(&mut self.memory_writers);
        for key in writers.drain(..) {
            self.notify_writable(key);
        }
        self.memory_writers = writers;
        true
    }

    /// Gives the inbound work reservation to the I/O owner after bootstrap.
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn take_bootstrap_reader(&mut self) -> Option<Reservation> {
        Some(self.receive_credit.as_mut()?.grant.split_off(INBOUND_WORK))
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn reserve_reader(&self) -> Result<Option<Reservation>, PipeError> {
        self.reserve_work(INBOUND_WORK)
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    fn reserve_work(&self, bytes: u64) -> Result<Option<Reservation>, PipeError> {
        self.receive_credit
            .as_ref()
            .map(|memory| memory.grant.reserve(bytes).ok_or(PipeError::MemoryBudget))
            .transpose()
    }

    /// Detaches the bootstrap transport grant so that physical teardown, not
    /// protocol retirement, returns the memory.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn take_bootstrap_transport(&mut self) -> Option<Reservation> {
        self.receive_credit.as_mut()?.transport.take()
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn reserve_writer(&self) -> Result<Option<Reservation>, PipeError> {
        self.reserve_work(crate::proto::memory::WriteWorkspace::COST)
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn reserve_transport(&self, bytes: u64) -> Result<Option<Reservation>, PipeError> {
        self.reserve_work(bytes)
    }

    pub(super) fn reserve_join_work(&self) -> Result<Option<JoinWork>, PipeError> {
        self.receive_credit
            .as_ref()
            .map(ReceiveCredit::join_work)
            .transpose()
    }

    pub(super) fn reserve_local_receive(&mut self) -> bool {
        self.receive_credit
            .as_mut()
            .is_none_or(ReceiveCredit::open_direction)
    }

    /// Extends the receive commitment before granting more peer slots.
    pub(super) fn reserve_peer_directions(&mut self, [bidi, uni]: [u64; 2]) -> bool {
        self.receive_credit.as_mut().is_none_or(|credit| {
            let old = credit.directions.slots;
            credit
                .directions
                .try_fund([old[0].max(bidi), old[1].max(uni), old[LOCAL]])
        })
    }

    pub(super) fn peer_stream_growth_ready(&self, d: usize) -> bool {
        let remote = self.streams.remote_dir(d);
        remote.needs_batch()
            && self.receive_credit.as_ref().is_none_or(|credit| {
                credit
                    .stream_release_epoch(d, remote.limit_sent)
                    .is_none_or(|epoch| epoch != credit.grant.release_epoch())
            })
    }

    pub(super) fn grow_peer_stream_credit(&mut self, d: usize) {
        let remote = self.streams.remote_dir(d);
        let (older, wire_limit) = (remote.initial, remote.limit_sent);
        let target = if remote.activating() {
            remote.target
        } else {
            remote.target.min(older.saturating_add(ADMISSION_BATCH))
        };
        let target = target
            .min(super::config::MAX_STREAM_CREDIT.saturating_sub(remote.discarded))
            .max(older);
        let limit = self.receive_credit.as_mut().map_or(target, |credit| {
            let epoch = credit.grant.release_epoch();
            let allowed = credit.directions.fund_peer(d, target);
            credit.streams_blocked_at[d] =
                (allowed == older && target > older).then_some((wire_limit, epoch));
            allowed
        });
        self.streams.peer_stream_growth(d, limit);
    }

    pub(super) fn release_local_receive(&mut self) {
        if let Some(credit) = &mut self.receive_credit {
            credit
                .directions
                .release(LOCAL, credit.directions.slots[LOCAL] - 1);
        }
    }

    pub(super) fn release_peer_receive(&mut self, d: usize) {
        if let Some(credit) = &mut self.receive_credit {
            credit
                .directions
                .release(d, self.streams.committed_peer_direction(d));
        }
    }

    /// A lower current window can shed allocations once no ranges still
    /// use their indices. Outstanding advertised credit continues to count.
    pub(super) fn reclaim_receive_space(&mut self, idle: bool) {
        let flow = self.streams.recv_flow();
        if flow.buffered != 0 || flow.has_protected_history() {
            return;
        }
        let Some(credit) = &mut self.receive_credit else {
            return;
        };
        let needed = flow.unsettled(flow.limit_sent).max(flow.window);
        let excess = credit.positions().saturating_sub(needed);
        let reclaim_small = idle || self.streams.memory_pressure();
        let unused_limit = if reclaim_small { 0 } else { needed / 2 };
        if excess <= unused_limit && !(reclaim_small && credit.directions.reusable() != 0) {
            return;
        }
        if self.receive.discard_unused() {
            *self.recv_refs.tally.get_mut() = Vec::new();
            self.recv_refs.retired_at_most = 0;
            self.recv_refs.referenced_at_least = 0;
            credit.release_unused(needed);
        }
    }

    pub(super) fn max_data_ready(&self) -> bool {
        let flow = self.streams.recv_flow();
        flow.update_pending
            && self.receive_credit.as_ref().is_none_or(|credit| {
                credit
                    .blocked_at
                    .is_none_or(|epoch| epoch != credit.grant.release_epoch())
                    || flow.unsettled(flow.limit_sent) < credit.positions()
            })
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn watch_receive_budget(
        &self,
        slot: &mut Option<Arc<crate::proto::memory::BudgetWait>>,
        waker: &std::task::Waker,
    ) -> bool {
        if self.state < super::State::Closing
            && let Some(credit) = &self.receive_credit
            && let Some(epoch) = (self
                .streams
                .recv_flow()
                .update_pending
                .then_some(credit.blocked_at)
                .flatten())
            .into_iter()
            .chain(self.write_blocked_at)
            .chain((0..2).filter_map(|d| {
                let remote = self.streams.remote_dir(d);
                if !remote.needs_batch() {
                    return None;
                }
                credit.stream_release_epoch(d, remote.limit_sent)
            }))
            .min()
        {
            return credit.grant.watch(epoch, slot, waker);
        }
        *slot = None;
        false
    }

    /// Reserves a new absolute `MAX_DATA` before it is written into a batch.
    pub(super) fn reserve_receive_credit(&mut self, wanted: u64) -> u64 {
        let flow = self.streams.recv_flow();
        let outstanding = flow.unsettled(wanted);
        let positions = outstanding.min(ReceiveStore::MAX_POSITIONS);
        let granted = self.receive_credit.as_mut().map_or(positions, |credit| {
            let granted = credit.reserve(positions);
            if granted < outstanding && credit.blocked_at.is_none() {
                credit.blocked_at = Some(credit.grant.release_epoch());
            }
            granted
        });
        wanted
            .saturating_sub(outstanding.saturating_sub(granted))
            .max(flow.limit_sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "tokio", not(loom)))]
    #[test]
    fn default_shared_budget_funds_many_full_initial_windows() {
        use crate::proto::session::{Config, DEFAULT_MEMORY_BUDGET};

        let config = Config::default();
        let peer_directions = listener_directions(&config);
        let transport = 6_250_000;
        let growth_floor = bootstrap_fixed(peer_directions.into_iter().sum(), transport).unwrap();
        let wanted = config.initial_connection_receive_window;
        let ledger = Ledger::with_ingress(
            Some(DEFAULT_MEMORY_BUDGET),
            None,
            growth_floor + MIN_INITIAL * RECEIVE_POSITION,
        );
        let mut full = Vec::new();
        while let Ok((credit, admitted)) =
            ReceiveCredit::admit(&ledger, wanted, transport, peer_directions)
        {
            if admitted < wanted {
                break;
            }
            full.push(credit);
        }
        assert!(
            full.len() >= 64,
            "default budget funded {} full windows",
            full.len()
        );
        println!(
            "{} B/position, {} full initial windows, {} B fixed per session",
            RECEIVE_POSITION,
            full.len(),
            growth_floor
        );
    }

    #[test]
    fn shared_growth_cannot_spend_the_next_sessions_admission() {
        const ENTRY: u64 = RECEIVE_FIXED + MIN_INITIAL * RECEIVE_POSITION;
        const BUDGET: u64 = 8 * ENTRY;
        let ledger = Ledger::with_ingress(Some(BUDGET), None, ENTRY);
        let (mut first, _) = ReceiveCredit::admit(&ledger, MIN_INITIAL, 0, [0; 2]).unwrap();
        assert!(first.reserve(u64::from(u32::MAX)) > MIN_INITIAL);
        let held = ledger
            .reserve(BUDGET - ENTRY - ledger.snapshot().used)
            .unwrap();
        let (second, granted) = ReceiveCredit::admit(&ledger, MIN_INITIAL, 0, [0; 2]).unwrap();
        assert_eq!(granted, MIN_INITIAL);
        assert!(ledger.snapshot().pressure);
        first.release_unused(MIN_INITIAL);
        drop(held);
        assert!(!ledger.snapshot().pressure);
        assert!(ledger.set_limit(Some(2 * ENTRY)));
        drop((first, second));
        assert_eq!(ledger.snapshot().used, 0);
    }

    #[test]
    fn a_peer_writer_retries_when_the_carrier_returns_its_last_view() {
        use crate::proto::session::{Config, CoreEvent, Dir, Role, UniCredit};

        const PAYLOAD: usize = 96 * 1024;
        let config = Config {
            initial_connection_receive_window: MIN_INITIAL,
            max_incoming_streams: 0,
            max_incoming_uni_streams: UniCredit::Limit(0),
            ..Config::default()
        };
        let entry = bootstrap_fixed(0, 0).unwrap() + MIN_INITIAL * RECEIVE_POSITION;
        let ledger = Ledger::new(Some(2 * entry + 128 * 1024), None);
        let now = std::time::Instant::now();
        let open = |role| {
            SessionCore::new_in(
                config.clone().into(),
                role,
                None,
                now,
                Some(ledger.clone()),
                0,
            )
            .unwrap()
        };
        let mut first = open(Role::Client);
        let mut second = open(Role::Server);
        let key = first.open(Dir::Uni).unwrap();
        let waiting = second.open(Dir::Uni).unwrap();
        let mut data = crate::Chunk::from(vec![1; PAYLOAD]);
        assert!(data.reserve(&ledger, None));
        assert_ne!(first.write_chunk(key, data.clone()).unwrap(), 0);
        let carrier = data.into_bytes().slice(..1);
        let next = crate::Chunk::from(vec![2; PAYLOAD]);
        assert_eq!(second.write_chunk(waiting, next.clone()).unwrap(), 0);
        assert!(
            !std::iter::from_fn(|| second.poll_event())
                .any(|event| { matches!(event, CoreEvent::StreamWritable(k) if k == waiting) })
        );

        first.reset(key, crate::VarInt::ZERO).unwrap();
        assert_eq!(second.write_chunk(waiting, next.clone()).unwrap(), 0);
        drop(carrier);
        assert!(
            std::iter::from_fn(|| second.poll_event())
                .any(|event| { matches!(event, CoreEvent::StreamWritable(k) if k == waiting) })
        );
        assert_ne!(second.write_chunk(waiting, next).unwrap(), 0);
    }

    #[test]
    fn an_incoming_stream_increase_reserves_both_directions_without_ingress() {
        use crate::proto::session::{BIDI, Config, Role, UNI, UniCredit};

        let config = Config {
            initial_connection_receive_window: MIN_INITIAL,
            max_incoming_streams: 2,
            max_incoming_uni_streams: UniCredit::Limit(1),
            ..Config::default()
        };
        let uni = 1;
        let entry = bootstrap_fixed(2 + uni, 0).unwrap() + MIN_INITIAL * RECEIVE_POSITION;
        let cost = ReceiveStore::DIRECTION_COST;
        let ledger = Ledger::with_ingress(Some(entry + 3 * cost), None, cost);
        let mut core = SessionCore::new_in(
            config.into(),
            Role::Client,
            None,
            std::time::Instant::now(),
            Some(ledger.clone()),
            0,
        )
        .unwrap();

        assert_eq!(ledger.snapshot().used, entry);
        assert!(core.raise_incoming_streams(4, uni + 1).is_err());
        assert_eq!(core.streams.remote_dir(BIDI).target, 2);
        assert_eq!(core.streams.remote_dir(UNI).target, uni);
        assert_eq!(ledger.snapshot().used, entry);

        core.raise_incoming_streams(3, uni + 1).unwrap();
        assert_eq!(core.streams.remote_dir(BIDI).target, 3);
        assert_eq!(core.streams.remote_dir(UNI).target, uni + 1);
        assert_eq!(ledger.snapshot().used, entry + 2 * cost);
    }

    #[test]
    fn peer_slots_retry_after_release_and_return_after_drain() {
        use crate::proto::session::{BIDI, Config, Role, UniCredit};
        let config = Config {
            initial_connection_receive_window: 2 * MIN_INITIAL,
            max_incoming_streams: 4 * ADMISSION_BATCH,
            max_incoming_uni_streams: UniCredit::Limit(0),
            ..Config::default()
        };
        let entry = bootstrap_fixed(ADMISSION_BATCH, 0).unwrap() + MIN_INITIAL * RECEIVE_POSITION;
        let cost = ReceiveStore::DIRECTION_COST;
        let ledger = Ledger::new(Some(entry + cost), None);
        let held = ledger.reserve(cost).unwrap();
        let mut core = SessionCore::new_in(
            config.into(),
            Role::Server,
            None,
            std::time::Instant::now(),
            Some(ledger.clone()),
            0,
        )
        .unwrap();
        let wire = core.local_parameters();
        assert_eq!(wire.initial_max_data, Some(MIN_INITIAL));
        assert_eq!(wire.initial_max_streams_bidi, Some(ADMISSION_BATCH));
        for i in 0..ADMISSION_BATCH.div_ceil(2) {
            assert!(!core.peer_stream_growth_ready(BIDI));
            assert_eq!(core.streams.open_peer_index(BIDI, i), Some(i));
        }
        assert!(core.peer_stream_growth_ready(BIDI));
        core.grow_peer_stream_credit(BIDI);
        assert!(!core.peer_stream_growth_ready(BIDI));
        assert_eq!(core.streams.remote_dir(BIDI).initial, ADMISSION_BATCH);

        drop(held);
        assert!(core.peer_stream_growth_ready(BIDI));
        core.grow_peer_stream_credit(BIDI);
        assert_eq!(core.streams.remote_dir(BIDI).initial, ADMISSION_BATCH + 1);
        assert_eq!(ledger.snapshot().used, entry + cost);

        core.streams.max_streams_written(BIDI, ADMISSION_BATCH + 1);
        core.streams.max_streams_settled(BIDI);
        core.reclaim_receive_space(true);
        assert_eq!(
            ledger.snapshot().used,
            entry + cost,
            "unused wire credit stays backed"
        );
        core.stream_count_credit(BIDI);
        assert_eq!(
            ledger.snapshot().used,
            entry + ReceiveStore::DIRECTION_ARENA
        );
        core.reclaim_receive_space(true);
        assert_eq!(ledger.snapshot().used, entry);
    }

    #[test]
    fn staged_uni_accept_buys_available_slots_and_retries_without_peer_traffic() {
        use crate::proto::frame::Dir;
        use crate::proto::session::{Config, Role, UNI, config::STAGED_UNI_STREAMS};

        let (initial, target) = STAGED_UNI_STREAMS;
        let config = Config {
            initial_connection_receive_window: MIN_INITIAL,
            max_incoming_streams: 0,
            ..Config::default()
        };
        let entry = bootstrap_fixed(initial, 0).unwrap() + MIN_INITIAL * RECEIVE_POSITION;
        let cost = ReceiveStore::DIRECTION_COST;
        let ledger = Ledger::new(Some(entry + (target - initial) * cost), None);
        let other = ledger.reserve((target - initial - 1) * cost).unwrap();
        let mut core = SessionCore::new_in(
            config.into(),
            Role::Server,
            None,
            std::time::Instant::now(),
            Some(ledger.clone()),
            0,
        )
        .unwrap();
        assert_eq!(
            core.local_parameters().initial_max_streams_uni,
            Some(initial)
        );
        assert!(!core.peer_stream_growth_ready(UNI));

        assert_eq!(core.accept(Dir::Uni).unwrap(), None);
        let partial = initial + 1;
        assert_eq!(core.streams.remote_dir(UNI).initial, partial);
        assert_eq!(ledger.snapshot().used, entry + cost + other.bytes());
        core.streams.max_streams_written(UNI, partial);
        core.streams.max_streams_settled(UNI);
        assert!(core.peer_stream_growth_ready(UNI));
        core.grow_peer_stream_credit(UNI);
        assert!(!core.peer_stream_growth_ready(UNI));

        drop(other);
        assert!(core.peer_stream_growth_ready(UNI));
        core.grow_peer_stream_credit(UNI);
        assert_eq!(core.streams.remote_dir(UNI).initial, target);
        assert_eq!(ledger.snapshot().used, entry + (target - initial) * cost);
    }

    #[test]
    fn freeing_one_direction_preserves_another_directions_live_storage() {
        use crate::proto::session::{BIDI, Config, Role, UNI, UniCredit};

        let config = Config {
            initial_connection_receive_window: MIN_INITIAL,
            max_incoming_streams: ADMISSION_BATCH + 1,
            max_incoming_uni_streams: UniCredit::Limit(1),
            ..Config::default()
        };
        let entry =
            bootstrap_fixed(ADMISSION_BATCH + 1, 0).unwrap() + MIN_INITIAL * RECEIVE_POSITION;
        let ledger = Ledger::new(Some(entry + ReceiveStore::DIRECTION_COST), None);
        let mut core = SessionCore::new_in(
            config.into(),
            Role::Server,
            None,
            std::time::Instant::now(),
            Some(ledger.clone()),
            0,
        )
        .unwrap();
        for i in 0..ADMISSION_BATCH.div_ceil(2) {
            assert_eq!(core.streams.open_peer_index(BIDI, i), Some(i));
        }
        assert!(core.peer_stream_growth_ready(BIDI));
        core.grow_peer_stream_credit(BIDI);
        core.streams.max_streams_written(BIDI, ADMISSION_BATCH + 1);
        core.streams.max_streams_settled(BIDI);

        assert_eq!(core.streams.open_peer_index(UNI, 0), Some(0));
        core.streams.count_received(1);
        core.credit_received(1, 1, 0);
        core.stream_count_credit(BIDI);
        core.reclaim_receive_space(true);
        assert_eq!(core.streams.recv_flow().buffered, 1);
        assert_eq!(
            core.receive_credit.as_ref().unwrap().directions.slots[UNI],
            1
        );
        assert_eq!(
            ledger.snapshot().used,
            entry + ReceiveStore::DIRECTION_ARENA
        );
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    #[test]
    fn pressure_keeps_advertised_credit_then_returns_space_as_it_is_consumed() {
        use crate::proto::session::{Config, Role, UniCredit, WindowIncrease};

        let config = Config {
            initial_connection_receive_window: MIN_INITIAL,
            max_incoming_streams: 0,
            max_incoming_uni_streams: UniCredit::Limit(0),
            allow_connection_window_increase: Some(WindowIncrease::new(|_| true)),
            ..Config::default()
        };
        let entry = minimum_listener_admission(&config);
        let ledger = Ledger::with_ingress(Some(4 * entry), None, entry);
        let now = std::time::Instant::now();
        let mut core = SessionCore::new_in(
            config.into(),
            Role::Client,
            None,
            now,
            Some(ledger.clone()),
            0,
        )
        .unwrap();
        let advertised = 2 * MIN_INITIAL;
        core.grow_session_window(advertised);
        let (generation, _) = core.take_window_increase().unwrap();
        core.answer_window_increase(generation, true);
        let granted = core.reserve_receive_credit(advertised);
        assert_eq!(granted, advertised);
        core.streams.max_data_written(granted, now);
        core.grow_session_window(2 * advertised);
        let (stale, _) = core.take_window_increase().unwrap();

        core.set_memory_pressure(true);
        core.answer_window_increase(stale, true);
        assert_eq!(core.streams.recv_flow().window, MIN_INITIAL);
        assert_eq!(core.streams.recv_flow().limit_sent, advertised);
        assert!(!ledger.set_limit(Some(entry)));

        core.streams.count_received(MIN_INITIAL);
        core.credit_received(MIN_INITIAL, MIN_INITIAL, 0);
        core.credit_consumed(MIN_INITIAL);
        assert_eq!(core.streams.recv_flow().limit_sent, advertised);
        assert!(ledger.set_limit(Some(entry)));
        assert_eq!(ledger.snapshot().used, entry);
    }

    #[test]
    fn join_reservation_outlives_protocol_cancellation() {
        const CAP: u64 = RECEIVE_FIXED + MIN_INITIAL * RECEIVE_POSITION + 2 * JOIN_WORK;
        let ledger = Ledger::new(Some(CAP), None);
        let (credit, _) = ReceiveCredit::admit(&ledger, MIN_INITIAL, 0, [0; 2]).unwrap();

        let first = credit.join_work().unwrap();
        let writing = first.clone();
        drop(first);
        let second = credit.join_work().unwrap();
        assert_eq!(ledger.snapshot().used, CAP);
        assert!(matches!(credit.join_work(), Err(PipeError::MemoryBudget)));

        drop(writing);
        let replacement = credit.join_work().unwrap();
        assert_eq!(ledger.snapshot().used, CAP);
        drop(credit);
        assert_eq!(ledger.snapshot().used, 2 * JOIN_WORK);

        drop(second);
        assert_eq!(ledger.snapshot().used, JOIN_WORK);
        drop(replacement);
        assert_eq!(ledger.snapshot().used, 0);
    }

    #[test]
    fn initial_credit_has_an_exact_minimum_and_is_reserved_on_the_shared_ledger() {
        const CUTOFF: u64 = RECEIVE_FIXED + MIN_INITIAL * RECEIVE_POSITION;
        let ledger = Ledger::new(Some(CUTOFF + 64), None);
        let carrier = ledger.reserve(65).unwrap();
        assert!(ReceiveCredit::admit(&ledger, 1 << 20, 0, [0; 2]).is_err());
        assert_eq!(ledger.snapshot().used, 65);
        drop(carrier);
        let carrier = ledger.reserve(64).unwrap();
        let (mut credit, advertised) = ReceiveCredit::admit(&ledger, 1 << 20, 0, [0; 2]).unwrap();
        assert_eq!(advertised, 16 * 1024);
        assert_eq!(ledger.snapshot().used, CUTOFF + 64);
        assert_eq!(credit.reserve(advertised + 1), advertised);
        assert!(ledger.reserve(1).is_none());
        drop((carrier, credit));
        assert_eq!(ledger.snapshot().used, 0);
    }
}
