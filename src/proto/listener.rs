//! A sans-IO listener (MULTIPATH.md Sections 5.4 to 5.6):
//! it classifies new carriers by their first record, extracts PIPE_JOIN
//! frames (in band or out of band), pairs split bootstraps, and bounds the
//! carriers that are not authenticated yet. It never touches session state:
//! the driver looks up the session by locator and offers the join to it
//! ([`crate::proto::session::SessionCore::offer_join`]).

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use crate::proto::frame::{LANE_KEY_LEN, MAX_JOIN_FRAME_LEN, PipeJoin, PipeLane};
use crate::proto::ident::{Classifier, FirstRecord, Verdict};
use crate::proto::oob::PAIRING_TOKEN_LEN;
use crate::proto::record::Framing;
use crate::proto::varint;

/// A change of a listener's memory pressure: it
/// started (the sessions' charges reached the budget) or ended (they fell
/// below three quarters of it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryPressure {
    /// The sum of the sessions' charges, in bytes, when it changed.
    pub used: u64,
    /// The budget.
    pub budget: u64,
    /// Pressure started (`true`) or ended.
    pub active: bool,
}

/// The hook `on_memory_pressure`: called outside every
/// lock on the listener's own serial context, never on an I/O path, when
/// pressure starts and when it ends; free to close sessions. A panic is
/// ignored.
#[derive(Clone)]
pub struct OnMemoryPressure(pub std::sync::Arc<dyn Fn(MemoryPressure) + Send + Sync>);

impl std::fmt::Debug for OnMemoryPressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnMemoryPressure(..)")
    }
}

/// Listener limits (MULTIPATH.md Section 5.6, RESUME.md Section 9).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ListenerConfig {
    /// Carriers being classified or verified at once (default 64); a new
    /// carrier evicts the oldest when full.
    pub max_pending: usize,
    /// Pending carriers per source (default 8).
    pub max_pending_per_source: usize,
    /// Pending joins per session (default 4).
    pub max_pending_per_session: usize,
    /// The first record (or the out-of-band join) must arrive within this
    /// (default 2 s).
    pub first_record_timeout: Duration,
    /// A pending carrier is closed after this (default 10 s).
    pub handshake_timeout: Duration,
    /// The listener's own `max_record_size` (default 65535).
    pub max_record_size: u64,
    /// Whether carriers may start new sessions.
    pub accept_sessions: bool,
    /// Suspended sessions held at once (default 1024).
    pub max_suspended: usize,
    /// Bytes the sessions may hold together; 0 is unlimited (default
    /// 1 GiB).
    pub memory_budget: u64,
    /// Called when memory pressure starts and ends (unset by default).
    pub on_memory_pressure: Option<OnMemoryPressure>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            max_pending: 64,
            max_pending_per_source: 8,
            max_pending_per_session: 4,
            first_record_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(10),
            max_record_size: 65535,
            accept_sessions: true,
            max_suspended: 1024,
            memory_budget: 1 << 30,
            on_memory_pressure: None,
        }
    }
}

/// A carrier the listener tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CarrierId(pub u64);

/// The result of opening a carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// Tracked; `evicted` is the oldest pending carrier that made room and
    /// must be closed.
    Accepted {
        /// The new carrier.
        id: CarrierId,
        /// A carrier to close.
        evicted: Option<CarrierId>,
    },
    /// The source has too many pending carriers: close it.
    Refused,
}

/// What a carrier turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// More bytes are needed.
    NeedMore,
    /// Close the carrier without writing anything.
    Reject,
    /// A new session: create it and feed it `first`, the bytes so far.
    NewSession {
        /// The bytes received so far.
        first: Vec<u8>,
    },
    /// A lane (MULTIPATH.md Section 5.8): route it by `lane_key` over the
    /// sessions (comparing in constant time), check that the pipe's lane 0
    /// is on the stream's connection, and offer it to the session
    /// ([`crate::proto::session::SessionCore::accept_lane`]); once it is
    /// accepted, feed `bytes`, the stream's bytes so far, to that lane.
    Lane {
        /// The Lane Key it carries.
        lane_key: [u8; LANE_KEY_LEN],
        /// The pipe it names.
        pipe: u64,
        /// Its lane number.
        lane: u64,
        /// The stream's bytes so far.
        bytes: Vec<u8>,
    },
    /// A join: offer `frame` to the session whose locator is `locator`.
    /// Once it is accepted, feed `bytes` (in band: starting with the record
    /// that carries the frame) to the session as the pipe's first bytes.
    Join {
        /// The Session Locator.
        locator: Vec<u8>,
        /// The PIPE_JOIN frame, Type through Join Token.
        frame: Vec<u8>,
        /// The carrier's bytes so far.
        bytes: Vec<u8>,
        /// Whether the frame came in band.
        inband: bool,
    },
}

/// The result of pairing a split-bootstrap carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paired {
    /// The first carrier with this token: wait for the other.
    Waiting,
    /// Both carriers are here.
    Complete(CarrierId),
    /// A third carrier with the token, or the same direction twice: close.
    Reject,
}

#[derive(Debug)]
struct Pending {
    id: CarrierId,
    source: u64,
    opened: Instant,
    framing: Framing,
    classifier: Classifier,
    buf: Vec<u8>,
    /// The locator once a join was parsed (per-session limit).
    locator: Option<Vec<u8>>,
    /// The first record (or join) arrived.
    first: bool,
    /// A new stream of a connection that already carries a pipe of the
    /// endpoint: not an unauthenticated carrier (the connection's stream
    /// credit bounds them), so outside the source and pending limits, and
    /// only the first-record timeout applies (MULTIPATH.md Section 5.5).
    stream: bool,
}

/// A sans-IO listener.
#[derive(Debug)]
pub struct ListenerCore {
    config: ListenerConfig,
    next: u64,
    /// Pending carriers, oldest first.
    pending: VecDeque<Pending>,
    /// Split-bootstrap pairing: token -> (carrier, inbound half?, opened).
    pairs: HashMap<[u8; PAIRING_TOKEN_LEN], (CarrierId, bool, Instant, bool)>,
}

/// A source key from a remote address, aggregated to /64 for IPv6
/// (MULTIPATH.md Section 5.6).
pub fn source_key(addr: std::net::IpAddr) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match addr {
        std::net::IpAddr::V4(a) => a.octets().hash(&mut h),
        std::net::IpAddr::V6(a) => a.octets()[..8].hash(&mut h),
    }
    h.finish()
}

/// A source key from an opaque name.
pub fn source_name(name: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    h.finish()
}

impl ListenerCore {
    /// A listener with these limits.
    pub fn new(config: ListenerConfig) -> Self {
        Self {
            config,
            next: 1,
            pending: VecDeque::new(),
            pairs: HashMap::new(),
        }
    }

    /// The limits.
    pub fn config(&self) -> &ListenerConfig {
        &self.config
    }

    /// Carriers pending.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// A new stream that the peer opened on a connection that carries lane
    /// 0 of an open inbound pipe of the endpoint, within the streams such
    /// pipes let wait for their first record unlimited (MULTIPATH.md
    /// Section 5.5, which the caller counts): its first record may begin a
    /// lane, which takes no slot; one that turns out a join or a new
    /// session takes a slot then ([`ListenerCore::admit`]).
    pub fn open_stream(&mut self, framing: Framing, now: Instant) -> CarrierId {
        let id = CarrierId(self.next);
        self.next += 1;
        self.pending.push_back(Pending {
            id,
            source: 0,
            opened: now,
            framing,
            classifier: Classifier::new(
                self.config.max_record_size,
                self.config.accept_sessions,
                true,
            )
            .with_lanes(),
            buf: Vec::new(),
            locator: None,
            first: false,
            stream: true,
        });
        id
    }

    /// A new carrier from `source` (MULTIPATH.md Section 5.6).
    pub fn open(&mut self, source: u64, framing: Framing, now: Instant) -> Opened {
        let evicted = match self.make_slot(source) {
            Ok(evicted) => evicted,
            Err(()) => return Opened::Refused,
        };
        let id = CarrierId(self.next);
        self.next += 1;
        self.pending.push_back(Pending {
            id,
            source,
            opened: now,
            framing,
            classifier: Classifier::new(
                self.config.max_record_size,
                self.config.accept_sessions,
                true,
            ),
            buf: Vec::new(),
            locator: None,
            first: false,
            stream: false,
        });
        Opened::Accepted { id, evicted }
    }

    /// A slot for a carrier from `source`: refused when the source has
    /// its share, else the oldest pending carrier evicted when all are
    /// taken (MULTIPATH.md Section 5.6).
    fn make_slot(&mut self, source: u64) -> Result<Option<CarrierId>, ()> {
        let carriers = || self.pending.iter().filter(|p| !p.stream);
        let from_source = carriers().filter(|p| p.source == source).count();
        if from_source >= self.config.max_pending_per_source {
            return Err(());
        }
        if carriers().count() >= self.config.max_pending
            && let Some(i) = self.pending.iter().position(|p| !p.stream)
        {
            return Ok(self.pending.remove(i).map(|p| p.id));
        }
        Ok(None)
    }

    /// A stream opened by [`ListenerCore::open_stream`] turned out a join or a
    /// new session: it takes a slot from `source` now, like any carrier
    /// (MULTIPATH.md Section 5.5). `Refused`: close it.
    pub fn admit(&mut self, id: CarrierId, source: u64) -> Opened {
        if self.find(id).is_none() {
            return Opened::Refused;
        }
        let evicted = match self.make_slot(source) {
            Ok(evicted) => evicted,
            Err(()) => return Opened::Refused,
        };
        if let Some(i) = self.find(id) {
            let p = &mut self.pending[i];
            p.stream = false;
            p.source = source;
        }
        Opened::Accepted { id, evicted }
    }

    fn find(&mut self, id: CarrierId) -> Option<usize> {
        self.pending.iter().position(|p| p.id == id)
    }

    /// Bytes from a byte-stream carrier.
    pub fn data(&mut self, id: CarrierId, bytes: &[u8], now: Instant) -> Classified {
        let _ = now;
        let max_hold = self.config.max_record_size as usize + 8;
        let Some(i) = self.find(id) else {
            return Classified::Reject;
        };
        let p = &mut self.pending[i];
        let start = p.buf.len();
        p.buf.extend_from_slice(bytes);
        let verdict = if p.classifier.verdict() == Verdict::NeedMore {
            p.classifier.push(&p.buf[start..])
        } else {
            p.classifier.verdict()
        };
        match verdict {
            Verdict::NeedMore => {
                if p.buf.len() > max_hold {
                    self.done(id);
                    return Classified::Reject;
                }
                Classified::NeedMore
            }
            Verdict::Reject { .. } => {
                self.done(id);
                Classified::Reject
            }
            Verdict::Accept(FirstRecord::Session) => {
                let first = std::mem::take(&mut self.pending[i].buf);
                self.done(id);
                Classified::NewSession { first }
            }
            Verdict::Accept(FirstRecord::Lane) => {
                let c = lane_record(&mut p.buf);
                if c != Classified::NeedMore {
                    self.done(id);
                }
                c
            }
            Verdict::Accept(FirstRecord::Join) => {
                let Some((size, width)) = varint::decode(&p.buf) else {
                    return Classified::NeedMore;
                };
                let body = &p.buf[width..];
                let have = body.len().min(size as usize);
                match PipeJoin::decode(&body[..have]) {
                    Ok((join, len)) => {
                        let locator = join.locator.to_vec();
                        let frame = body[..len].to_vec();
                        p.first = true;
                        p.locator = Some(locator.clone());
                        let bytes = p.buf.clone();
                        if self.over_session_limit(i) {
                            self.done(id);
                            return Classified::Reject;
                        }
                        Classified::Join {
                            locator,
                            frame,
                            bytes,
                            inband: true,
                        }
                    }
                    Err(_) if have < (size as usize).min(MAX_JOIN_FRAME_LEN) => {
                        Classified::NeedMore
                    }
                    Err(_) => {
                        self.done(id);
                        Classified::Reject
                    }
                }
            }
        }
    }

    /// One message from a message-framed carrier.
    pub fn message(&mut self, id: CarrierId, message: &[u8], now: Instant) -> Classified {
        let _ = now;
        let Some(i) = self.find(id) else {
            return Classified::Reject;
        };
        let p = &mut self.pending[i];
        if p.first {
            // Later messages before the join is decided.
            if p.buf.len() + message.len() > self.config.max_record_size as usize * 2 {
                self.done(id);
                return Classified::Reject;
            }
            p.buf.extend_from_slice(message);
            return Classified::NeedMore;
        }
        match p.classifier.message(message) {
            Verdict::Accept(FirstRecord::Session) => {
                let first = message.to_vec();
                self.done(id);
                Classified::NewSession { first }
            }
            Verdict::Accept(FirstRecord::Lane) => {
                self.done(id);
                lane_message(message)
            }
            Verdict::Accept(FirstRecord::Join) => match PipeJoin::decode(message) {
                Ok((join, len)) => {
                    let locator = join.locator.to_vec();
                    p.first = true;
                    p.locator = Some(locator.clone());
                    if self.over_session_limit(i) {
                        self.done(id);
                        return Classified::Reject;
                    }
                    Classified::Join {
                        locator,
                        frame: message[..len].to_vec(),
                        bytes: message.to_vec(),
                        inband: true,
                    }
                }
                Err(_) => {
                    self.done(id);
                    Classified::Reject
                }
            },
            _ => {
                self.done(id);
                Classified::Reject
            }
        }
    }

    /// An out-of-band PIPE_JOIN delivered with the carrier (MULTIPATH.md
    /// Section 5.3); it must be exactly one frame of at most 64 bytes.
    pub fn oob(&mut self, id: CarrierId, frame: &[u8], now: Instant) -> Classified {
        let _ = now;
        let Some(i) = self.find(id) else {
            return Classified::Reject;
        };
        match PipeJoin::decode(frame) {
            Ok((join, len)) if len == frame.len() => {
                let locator = join.locator.to_vec();
                let p = &mut self.pending[i];
                p.first = true;
                p.locator = Some(locator.clone());
                if self.over_session_limit(i) {
                    self.done(id);
                    return Classified::Reject;
                }
                Classified::Join {
                    locator,
                    frame: frame.to_vec(),
                    bytes: Vec::new(),
                    inband: false,
                }
            }
            _ => {
                self.done(id);
                Classified::Reject
            }
        }
    }

    fn over_session_limit(&self, i: usize) -> bool {
        let Some(l) = &self.pending[i].locator else {
            return false;
        };
        self.pending
            .iter()
            .filter(|p| p.locator.as_ref() == Some(l))
            .count()
            > self.config.max_pending_per_session
    }

    /// The carrier left the listener (attached, rejected or closed).
    pub fn done(&mut self, id: CarrierId) {
        if let Some(i) = self.find(id) {
            self.pending.remove(i);
        }
    }

    /// The bytes held for a carrier that waits for its session.
    pub fn held_bytes(&self, id: CarrierId) -> &[u8] {
        self.pending
            .iter()
            .find(|p| p.id == id)
            .map_or(&[], |p| &p.buf)
    }

    /// The framing of a pending carrier.
    pub fn framing(&self, id: CarrierId) -> Option<Framing> {
        self.pending.iter().find(|p| p.id == id).map(|p| p.framing)
    }

    /// Pairs a split-bootstrap carrier by its token (SPEC.md Section
    /// 6.1.1); `inbound` is the half the carrier gives the local endpoint.
    pub fn pair(
        &mut self,
        token: [u8; PAIRING_TOKEN_LEN],
        id: CarrierId,
        inbound: bool,
        now: Instant,
    ) -> Paired {
        match self.pairs.get_mut(&token) {
            None => {
                if self.pairs.len() >= self.config.max_pending {
                    // Drop the oldest entry: the table stays bounded.
                    if let Some(old) = self.pairs.iter().min_by_key(|(_, v)| v.2).map(|(k, _)| *k) {
                        self.pairs.remove(&old);
                    }
                }
                self.pairs.insert(token, (id, inbound, now, false));
                Paired::Waiting
            }
            Some(entry) if !entry.3 && entry.1 != inbound => {
                entry.3 = true;
                Paired::Complete(entry.0)
            }
            Some(_) => Paired::Reject,
        }
    }

    /// The next timeout.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.pending
            .iter()
            .filter_map(|p| {
                // A deadline beyond the clock's range never comes.
                p.opened.checked_add(if p.first {
                    self.config.handshake_timeout
                } else {
                    self.config.first_record_timeout
                })
            })
            .min()
    }

    /// Carriers whose first-record or handshake timeout expired: close
    /// them.
    pub fn expired(&mut self, now: Instant) -> Vec<CarrierId> {
        let first_timeout = self.config.first_record_timeout;
        let handshake = self.config.handshake_timeout;
        let mut out = Vec::new();
        self.pending.retain(|p| {
            let limit = if p.first { handshake } else { first_timeout };
            if p.opened.checked_add(limit).is_some_and(|t| now >= t) {
                out.push(p.id);
                false
            } else {
                true
            }
        });
        let pairs_limit = handshake;
        self.pairs
            .retain(|_, v| now.saturating_duration_since(v.2) < pairs_limit);
        out
    }
}

/// The PIPE_LANE that begins the first record held in `buf` (byte-stream
/// framing), once it decodes: the lane, with the bytes (taken), or a
/// rejection when the record holds no valid PIPE_LANE first.
fn lane_record(buf: &mut Vec<u8>) -> Classified {
    let Some((size, width)) = varint::decode(buf) else {
        return Classified::NeedMore;
    };
    let body = &buf[width..];
    let have = body.len().min(usize::try_from(size).unwrap_or(usize::MAX));
    match PipeLane::decode(&body[..have]) {
        Ok((f, _)) => Classified::Lane {
            lane_key: f.lane_key,
            pipe: f.pipe_id,
            lane: f.lane,
            bytes: std::mem::take(buf),
        },
        Err(_) if (have as u64) < size => Classified::NeedMore,
        Err(_) => Classified::Reject,
    }
}

/// The PIPE_LANE that begins the first message of a message-framed
/// stream.
fn lane_message(message: &[u8]) -> Classified {
    match PipeLane::decode(message) {
        Ok((f, _)) => Classified::Lane {
            lane_key: f.lane_key,
            pipe: f.pipe_id,
            lane: f.lane,
            bytes: message.to_vec(),
        },
        Err(_) => Classified::Reject,
    }
}

/// The first record of a new stream of a connection that already carries a
/// pipe of the endpoint, checked for a lane without a listener
/// (MULTIPATH.md Sections 5.5 and 5.8): an endpoint whose adapter hands
/// such streams to its sessions directly classifies them the same way. It
/// decides within the first record; only a lane is accepted.
#[derive(Debug, Clone)]
pub struct LaneProbe {
    classifier: Classifier,
    framing: Framing,
    buf: Vec<u8>,
}

impl LaneProbe {
    /// A probe for a stream with `framing`; `max_record_size` is the
    /// receiver's own limit.
    pub const fn new(max_record_size: u64, framing: Framing) -> Self {
        Self {
            classifier: Classifier::new(max_record_size, false, false).with_lanes(),
            framing,
            buf: Vec::new(),
        }
    }

    /// Bytes of a byte-stream carrier: [`Classified::NeedMore`],
    /// [`Classified::Reject`] or [`Classified::Lane`].
    pub fn data(&mut self, bytes: &[u8]) -> Classified {
        if self.framing == Framing::Records {
            return self.message(bytes);
        }
        let start = self.buf.len();
        self.buf.extend_from_slice(bytes);
        let verdict = match self.classifier.verdict() {
            Verdict::NeedMore => self.classifier.push(&self.buf[start..]),
            v => v,
        };
        match verdict {
            Verdict::NeedMore => Classified::NeedMore,
            Verdict::Accept(FirstRecord::Lane) => lane_record(&mut self.buf),
            _ => Classified::Reject,
        }
    }

    /// The first message of a message-framed carrier.
    pub fn message(&mut self, message: &[u8]) -> Classified {
        match self.classifier.message(message) {
            Verdict::Accept(FirstRecord::Lane) => lane_message(message),
            _ => Classified::Reject,
        }
    }
}

/// The memory budget of a listener's sessions: above
/// the budget sessions behave as if at their buffer cap; normal operation
/// resumes below three quarters of it.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryBudget {
    budget: u64,
    pressure: bool,
}

impl MemoryBudget {
    /// A budget of `bytes`; 0 is unlimited.
    pub fn new(bytes: u64) -> Self {
        Self {
            budget: bytes,
            pressure: false,
        }
    }

    /// Updates with the bytes the sessions hold; returns the new pressure
    /// state when it changed.
    pub fn update(&mut self, used: u64) -> Option<bool> {
        if self.budget == 0 {
            return None;
        }
        let next = if self.pressure {
            used >= self.budget / 4 * 3
        } else {
            used > self.budget
        };
        (next != self.pressure).then(|| {
            self.pressure = next;
            next
        })
    }

    /// Whether the sessions are above the budget.
    pub fn pressure(&self) -> bool {
        self.pressure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_source_and_first_record_limits() {
        let mut l = ListenerCore::new(ListenerConfig::default());
        let now = Instant::now();
        let a = source_name("a");
        for _ in 0..8 {
            assert!(matches!(
                l.open(a, Framing::ByteStream, now),
                Opened::Accepted { .. }
            ));
        }
        assert_eq!(l.open(a, Framing::ByteStream, now), Opened::Refused);
        assert!(matches!(
            l.open(source_name("b"), Framing::ByteStream, now),
            Opened::Accepted { .. }
        ));
        assert!(l.expired(now + Duration::from_millis(1999)).is_empty());
        assert_eq!(l.expired(now + Duration::from_secs(2)).len(), 9);
    }

    #[test]
    fn garbage_is_rejected() {
        let mut l = ListenerCore::new(ListenerConfig::default());
        let now = Instant::now();
        let Opened::Accepted { id, .. } = l.open(1, Framing::ByteStream, now) else {
            panic!()
        };
        assert_eq!(l.data(id, b"GET / HTTP/1.1\r\n", now), Classified::Reject);
    }

    #[test]
    fn memory_budget_hysteresis() {
        let mut m = MemoryBudget::new(1000);
        assert_eq!(m.update(900), None);
        assert_eq!(m.update(1001), Some(true));
        assert_eq!(m.update(800), None);
        assert_eq!(m.update(700), Some(false));
    }
}
