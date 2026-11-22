//! Read-driven connection statistics. Native queries never hold driver or cache locks.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak, mpsc};
use std::time::{Duration, Instant};
#[cfg(feature = "tokio")]
use std::{any::TypeId, collections::HashMap};

use crate::{CarrierConnId, CarrierCounts, CarrierSample, CarrierSource, PipeDirection};

enum Query {
    Tcp(Weak<std::net::TcpStream>),
    Adapter(Box<dyn Fn() -> Option<CarrierCounts> + Send + Sync>),
}

impl Query {
    fn observe(&self) -> Option<CarrierCounts> {
        match self {
            Self::Tcp(socket) => super::tcp::TcpSocket::from_weak(socket)?.carrier_counters(),
            Self::Adapter(query) => {
                let counts: Option<Option<CarrierCounts>> =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(query)).ok();
                counts.flatten()
            }
        }
    }
}

pub(crate) struct Source {
    provider: CarrierSource,
    query: Option<Query>,
    pub(super) dedicated: bool,
    #[cfg(feature = "tokio")]
    connection: Option<(ConnectionKey, CarrierConnId)>,
}

impl Default for Source {
    fn default() -> Self {
        Self {
            provider: CarrierSource::Unknown,
            query: None,
            dedicated: false,
            #[cfg(feature = "tokio")]
            connection: None,
        }
    }
}

impl Source {
    pub(crate) fn new(
        provider: CarrierSource,
        query: impl Fn() -> Option<CarrierCounts> + Send + Sync + 'static,
    ) -> Self {
        Self {
            provider,
            query: queryable(provider).then(|| Query::Adapter(Box::new(query))),
            dedicated: false,
            #[cfg(feature = "tokio")]
            connection: None,
        }
    }

    pub(crate) fn tcp(provider: CarrierSource, socket: Weak<std::net::TcpStream>) -> Self {
        Self {
            provider,
            query: queryable(provider).then_some(Query::Tcp(socket)),
            dedicated: true,
            #[cfg(feature = "tokio")]
            connection: None,
        }
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn set_connection(&mut self, connection: Option<CarrierConnId>) {
        if self.connection.is_none() {
            self.connection =
                connection.map(|owner| (ConnectionKey::Allocation(owner.clone()), owner));
        }
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn set_transport_identity<K: 'static>(&mut self, key: usize, owner: CarrierConnId) {
        self.connection = Some((ConnectionKey::Transport(TypeId::of::<K>(), key), owner));
    }

    pub(super) fn attach(self, now: fn() -> Instant) -> Option<Registration> {
        #[cfg(feature = "tokio")]
        let mut transport_owner = None;
        #[cfg(feature = "tokio")]
        let cache = match self.connection {
            Some((key, owner)) => {
                if matches!(key, ConnectionKey::Transport(..)) {
                    transport_owner = Some(owner.clone());
                }
                shared_cache(key, owner)
            }
            None if self.dedicated => Arc::default(),
            None => return None,
        };
        #[cfg(not(feature = "tokio"))]
        let cache = self.dedicated.then(Arc::<Cache>::default)?;

        let mut state = cache.lock();
        state.users += 1;
        let mut initial = None;
        let query = self.query.map(Arc::new);
        #[cfg(feature = "tokio")]
        if let Some(owner) = transport_owner {
            state
                .transport_providers
                .retain(|(owner, _, _)| owner.is_live());
            if let Some(query) = &query
                && !state
                    .transport_providers
                    .iter()
                    .any(|(existing, source, _)| *existing == owner && *source == self.provider)
            {
                state
                    .transport_providers
                    .push((owner, self.provider, query.clone()));
            }
        }
        if state.source.is_none()
            || (state.source == Some(CarrierSource::Unknown)
                && self.provider != CarrierSource::Unknown)
        {
            state.change_provider(self.provider);
            state.sampled_at = None;
            if let Some(query) = query {
                state.provider = Some(query.clone());
                state.in_flight = true;
                initial = Some(query);
            } else {
                state.publish(now(), self.provider, None);
            }
        }
        // The first known source owns the cache for the connection's lifetime.
        drop(state);
        if let Some(query) = initial {
            let at = now();
            let counts = query.observe();
            let mut state = cache.lock();
            state.publish(at, self.provider, counts);
            state.in_flight = false;
        }
        Some(Registration {
            cache,
            attached: AtomicBool::new(true),
        })
    }
}

fn queryable(provider: CarrierSource) -> bool {
    !matches!(
        provider,
        CarrierSource::Unknown | CarrierSource::WindowsSioTcpInfo
    )
}

#[cfg(feature = "tokio")]
#[derive(Clone, PartialEq, Eq, Hash)]
enum ConnectionKey {
    Allocation(CarrierConnId),
    Transport(TypeId, usize),
}

#[cfg(feature = "tokio")]
#[derive(Default)]
struct SharedCache {
    owners: Vec<CarrierConnId>,
    cache: Arc<Cache>,
}

#[cfg(feature = "tokio")]
#[derive(Default)]
struct Connections {
    entries: HashMap<ConnectionKey, SharedCache>,
    until_sweep: usize,
}

#[cfg(feature = "tokio")]
fn shared_cache(key: ConnectionKey, owner: CarrierConnId) -> Arc<Cache> {
    static CACHES: OnceLock<Mutex<Connections>> = OnceLock::new();
    let mut registry = CACHES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let live = |entry: &SharedCache| entry.owners.iter().any(CarrierConnId::is_live);
    if registry.entries.get(&key).is_some_and(|entry| !live(entry)) {
        registry.entries.remove(&key);
    }
    if !registry.entries.contains_key(&key) {
        if registry.until_sweep == 0 {
            registry.entries.retain(|_, entry| live(entry));
            if registry.entries.capacity() > registry.entries.len().saturating_mul(4).max(64) {
                registry.entries.shrink_to_fit();
            }
            registry.until_sweep = registry.entries.capacity().max(64);
        }
        registry.until_sweep -= 1;
    }
    let entry = registry.entries.entry(key).or_default();
    entry.owners.retain(CarrierConnId::is_live);
    if !entry.owners.contains(&owner) {
        entry.owners.push(owner);
    }
    entry.cache.clone()
}

pub(super) struct Registration {
    pub(super) cache: Arc<Cache>,
    attached: AtomicBool,
}

impl Registration {
    pub(super) fn detach(&self) {
        let mut state = self.cache.lock();
        if self.attached.swap(false, Ordering::Relaxed) {
            state.users -= 1;
            if state.users == 0 {
                state.epoch += 1;
            }
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.detach();
    }
}

#[derive(Default)]
pub(super) struct Cache(Mutex<CacheState>);

impl Cache {
    fn lock(&self) -> MutexGuard<'_, CacheState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn read(self: &Arc<Self>, now: Instant) -> (Option<CarrierSample>, Option<Refresh>) {
        let mut state = self.lock();
        let sample = state.sample();
        let request = if state.users > 0
            && !state.in_flight
            && sample.as_ref().is_some_and(|s| {
                now.saturating_duration_since(s.sampled_at) >= Duration::from_secs(1)
            })
            && let Some(provider) = state.live_provider()
        {
            state.in_flight = true;
            Some(Refresh {
                cache: self.clone(),
                provider,
                epoch: state.epoch,
                now,
                submitted: Instant::now(),
            })
        } else {
            None
        };
        (sample, request)
    }
}

pub(super) struct Refresh {
    cache: Arc<Cache>,
    provider: Arc<Query>,
    epoch: u64,
    now: Instant,
    submitted: Instant,
}

impl Refresh {
    pub(super) fn submit(self) {
        static WORK: OnceLock<mpsc::Sender<Refresh>> = OnceLock::new();
        let queue = WORK.get_or_init(|| {
            let (send, receive) = mpsc::channel();
            let receive = Arc::new(Mutex::new(receive));
            for _ in 0..4 {
                let receive = receive.clone();
                let _ = std::thread::Builder::new()
                    .name("zmux-carrier-stats".into())
                    .spawn(move || {
                        loop {
                            let work: Result<Refresh, _> = receive
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .recv();
                            let Ok(work) = work else { break };
                            work.run();
                        }
                    });
            }
            send
        });
        // The pool has a fixed worker count. Single flight bounds queued
        // work to one request per connection, without blocking readers.
        let _ = queue.send(self);
    }

    fn run(&self) {
        let source = {
            let state = self.cache.lock();
            if state.epoch != self.epoch {
                return;
            }
            state.source.expect("selected provider")
        };
        let at = self
            .now
            .checked_add(self.submitted.elapsed())
            .unwrap_or(self.now);
        let counts = self.provider.observe();
        let mut state = self.cache.lock();
        if state.epoch == self.epoch {
            state.publish(at, source, counts);
        }
    }
}

impl Drop for Refresh {
    fn drop(&mut self) {
        self.cache.lock().in_flight = false;
    }
}

#[derive(Default)]
struct CacheState {
    provider: Option<Arc<Query>>,
    #[cfg(feature = "tokio")]
    transport_providers: Vec<(CarrierConnId, CarrierSource, Arc<Query>)>,
    in_flight: bool,
    users: usize,
    epoch: u64,
    sampled_at: Option<Instant>,
    carrier_id: u64,
    generation: u64,
    source: Option<CarrierSource>,
    counts_present: bool,
    last_known: Option<CarrierCounts>,
}

impl CacheState {
    fn live_provider(&self) -> Option<Arc<Query>> {
        #[cfg(feature = "tokio")]
        if !self.transport_providers.is_empty() {
            return self
                .transport_providers
                .iter()
                .find(|(owner, source, _)| owner.is_live() && Some(*source) == self.source)
                .map(|(_, _, query)| query.clone());
        }
        self.provider.clone()
    }

    fn sample(&self) -> Option<CarrierSample> {
        Some(CarrierSample {
            carrier_id: CarrierConnId::from_sampled(self.carrier_id),
            generation: self.generation,
            direction: PipeDirection::Out,
            source: self.source?,
            sampled_at: self.sampled_at?,
            counts: if self.counts_present {
                self.last_known
            } else {
                None
            },
        })
    }

    fn change_provider(&mut self, source: CarrierSource) {
        self.source = Some(source);
        self.last_known = None;
        self.counts_present = false;
    }

    fn publish(
        &mut self,
        sampled_at: Instant,
        source: CarrierSource,
        counts: Option<CarrierCounts>,
    ) {
        if self.carrier_id == 0 {
            self.carrier_id = CarrierConnId::sampled().get();
        }
        if self.source != Some(source) {
            self.change_provider(source);
        }
        self.sampled_at = Some(sampled_at);
        self.counts_present = counts.is_some();
        if let Some(raw) = counts {
            let (counts, reset) = match (self.last_known, raw) {
                (
                    Some(CarrierCounts::TcpSegments {
                        data_segs_out: sent,
                        total_retrans: retrans,
                    }),
                    CarrierCounts::TcpSegments {
                        data_segs_out,
                        total_retrans,
                    },
                ) => match (extend(sent, data_segs_out), extend(retrans, total_retrans)) {
                    (Some(data_segs_out), Some(total_retrans)) => (
                        CarrierCounts::TcpSegments {
                            data_segs_out,
                            total_retrans,
                        },
                        false,
                    ),
                    _ => (raw, true),
                },
                (
                    Some(CarrierCounts::TcpPackets {
                        packets_sent: sent,
                        packets_retransmitted: retrans,
                    }),
                    CarrierCounts::TcpPackets {
                        packets_sent,
                        packets_retransmitted,
                    },
                ) => (raw, packets_sent < sent || packets_retransmitted < retrans),
                (
                    Some(CarrierCounts::Quic {
                        packets_sent: sent, ..
                    }),
                    CarrierCounts::Quic { packets_sent, .. },
                ) => (raw, packets_sent < sent),
                _ => (raw, false),
            };
            self.generation += u64::from(reset);
            self.last_known = Some(counts);
        }
    }
}

fn extend(previous: u64, current: u64) -> Option<u64> {
    const MODULUS: u64 = 1 << 32;
    const MASK: u64 = MODULUS - 1;
    let low = previous & MASK;
    if current >= low {
        Some((previous & !MASK) | current)
    } else if low >= 3 * (MODULUS / 4) && current < MODULUS / 4 {
        ((previous & !MASK) | current).checked_add(MODULUS)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::attachment::Attachment;
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn quic(packets_sent: u64, packets_lost: u64) -> CarrierCounts {
        CarrierCounts::Quic {
            packets_sent,
            packets_lost,
        }
    }

    fn dedicated(mut source: Source) -> Registration {
        source.dedicated = true;
        source.attach(Instant::now).unwrap()
    }

    #[test]
    fn no_identity_does_not_query() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let source = Source::new(CarrierSource::Quinn, move || {
            count.fetch_add(1, Ordering::Relaxed);
            None
        });
        assert!(source.attach(Instant::now).is_none());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn windows_publishes_once_and_last_detach_keeps_the_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let windows = dedicated(Source::new(CarrierSource::WindowsSioTcpInfo, move || {
            count.fetch_add(1, Ordering::Relaxed);
            None
        }));
        let first = windows.cache.read(Instant::now()).0.unwrap();
        assert_eq!(
            (first.source, first.counts),
            (CarrierSource::WindowsSioTcpInfo, None)
        );
        let due = first.sampled_at + Duration::from_secs(2);
        let (sample, refresh) = windows.cache.read(due);
        assert_eq!(sample, Some(first));
        assert!(refresh.is_none());
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        let attachment = Arc::<Attachment>::default();
        let mut source = Source::new(CarrierSource::Quinn, || Some(quic(0, 0)));
        source.dedicated = true;
        attachment.register_sample(source, Instant::now);
        let end = attachment.outcome().clone();
        let weak = Arc::downgrade(&end);
        let cache = end.sample.get().unwrap();
        let last = cache.read(Instant::now()).0.unwrap();
        drop(attachment);
        let (sample, refresh) = cache.read(last.sampled_at + Duration::from_secs(2));
        assert_eq!(sample, Some(last));
        assert!(refresh.is_none());
        drop(end);
        assert!(weak.upgrade().is_none());
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn transport_provider_survives_the_first_wrapper() {
        struct Transport;
        let attach = |owner: &Arc<u64>| {
            let weak = Arc::downgrade(owner);
            let mut source = Source::new(CarrierSource::Quinn, move || {
                weak.upgrade().map(|count| quic(*count, 0))
            });
            source.set_transport_identity::<Transport>(1, CarrierConnId::new(owner));
            source.attach(Instant::now).unwrap()
        };
        let first = Arc::new(10);
        let second = Arc::new(20);
        let first_registration = attach(&first);
        let second_registration = attach(&second);
        let cache = &second_registration.cache;
        let original = cache.read(Instant::now()).0.unwrap();
        drop(first_registration);
        drop(first);
        let due = original.sampled_at + Duration::from_secs(2);
        cache.read(due).1.unwrap().run();
        let updated = cache.read(due).0.unwrap();
        assert_eq!(updated.carrier_id, original.carrier_id);
        assert_eq!(updated.generation, original.generation);
        assert_eq!(updated.counts, Some(quic(20, 0)));
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn shared_connection_clears_during_upgrade_and_keeps_the_first_known_provider() {
        let owner = Arc::new(());
        let attach = |mut source: Source| {
            source.set_connection(Some(CarrierConnId::new(&owner)));
            source.attach(Instant::now).unwrap()
        };
        let initial = attach(Source::default());
        let old = initial.cache.read(Instant::now()).0.unwrap();
        assert_eq!(old.source, CarrierSource::Unknown);
        let (started, start) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let gate = Mutex::new(gate);
        let seeded = Arc::new(AtomicBool::new(false));
        let first = std::thread::scope(|scope| {
            let seed = scope.spawn(|| {
                attach(Source::new(CarrierSource::Quinn, move || {
                    if !seeded.swap(true, Ordering::Relaxed) {
                        started.send(()).unwrap();
                        gate.lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(3))
                            .unwrap();
                    }
                    Some(quic(9, 3))
                }))
            });
            start.recv_timeout(Duration::from_secs(3)).unwrap();
            let (absent, refresh) = initial.cache.read(Instant::now());
            release.send(()).unwrap();
            assert!(absent.is_none() && refresh.is_none());
            seed.join().unwrap()
        });
        let sample = first.cache.read(Instant::now()).0.unwrap();
        assert_eq!(sample.carrier_id, old.carrier_id);
        assert_eq!(sample.counts, Some(quic(9, 3)));
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let second = attach(Source::new(CarrierSource::LinuxTcpInfo, move || {
            count.fetch_add(1, Ordering::Relaxed);
            None
        }));
        drop(first);
        let (cached, refresh) = second
            .cache
            .read(sample.sampled_at + Duration::from_secs(1));
        assert_eq!(cached, Some(sample));
        assert_eq!(refresh.unwrap().provider.observe(), Some(quic(9, 3)));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn blocked_refresh_is_single_flight() {
        let limit = Duration::from_secs(3);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let (started, start) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let gate = Mutex::new(gate);
        let registration = dedicated(Source::new(CarrierSource::Quinn, move || {
            if count.fetch_add(1, Ordering::Relaxed) == 0 {
                return Some(quic(200, 10));
            }
            started.send(()).unwrap();
            gate.lock().unwrap().recv_timeout(limit).unwrap();
            Some(quic(400, 8))
        }));
        let cache = &registration.cache;
        let old = cache.read(Instant::now()).0.unwrap();
        let due = old.sampled_at + Duration::from_secs(1);
        cache.read(due).1.unwrap().submit();
        start.recv_timeout(limit).unwrap();
        let (send, results) = mpsc::channel();
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let send = send.clone();
                scope.spawn(move || {
                    let (sample, refresh) = cache.read(due);
                    send.send((sample, refresh.is_none())).unwrap();
                });
            }
            let observations: Vec<_> = (0..16).map(|_| results.recv_timeout(limit)).collect();
            release.send(()).unwrap();
            for observed in observations {
                assert_eq!(observed.unwrap(), (Some(old.clone()), true));
            }
        });
        let deadline = Instant::now() + limit;
        while cache.lock().in_flight {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let updated = cache.read(due).0.unwrap();
        assert!(updated.sampled_at >= due);
        assert_eq!(
            (updated.generation, updated.counts),
            (0, Some(quic(400, 8)))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn linux_wrap_and_reset() {
        const WRAP: u64 = 1 << 32;
        let mut state = CacheState::default();
        for (sent, retrans, expected_sent, expected_retrans, generation) in [
            (WRAP - 10, WRAP - 2, WRAP - 10, WRAP - 2, 0),
            (5, 3, WRAP + 5, WRAP + 3, 0),
            (20, 1, 20, 1, 1),
            (18, 2, 18, 2, 2),
        ] {
            state.publish(
                Instant::now(),
                CarrierSource::LinuxTcpInfo,
                Some(CarrierCounts::TcpSegments {
                    data_segs_out: sent,
                    total_retrans: retrans,
                }),
            );
            let sample = state.sample().unwrap();
            assert_eq!(sample.generation, generation);
            assert_eq!(
                sample.counts,
                Some(CarrierCounts::TcpSegments {
                    data_segs_out: expected_sent,
                    total_retrans: expected_retrans,
                })
            );
        }
        assert_eq!(extend(3 * WRAP / 4 - 1, 0), None);
        assert_eq!(extend(3 * WRAP / 4, WRAP / 4), None);
    }
}
