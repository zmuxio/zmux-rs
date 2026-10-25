//! The running aggregates the multipath scheduler reads at every decision
//! (MULTIPATH.md Section 7.5.1, 7 and 10): per urgency level the ready data within stream credit (X
//! of tier saturation, the backlog of `spread-eta`), in total and per
//! direction in order (the round robin's share of ECF's backlog), and the
//! incremental directions with data ready (BLEST's n), the reinjected
//! information pending, the oldest wait start, per pipe the expected bytes
//! of the directions bound to it (A_p of `affinity`), the directions with
//! new data by how a decision treats them, the blocking data of the
//! directions held back by stream credit, the waiting writers, and the
//! redundant copy bytes outstanding.
//!
//! The ledger keeps what each stream contributes. The stream slab notes
//! every stream it hands out for change, and those are brought up to date
//! before any read ([`super::SessionCore::ledger`]), so no change can bypass
//! the aggregates and a read costs O(1), or O(log n), instead of a pass
//! over the streams. Debug builds check them against a recount.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

mod amounts;

use amounts::Amounts;

use super::stream::{SendPart, StreamKey};
use super::{Policy, Redundancy};

/// Tags kept in the ledger, empty ones included, before the empty ones are
/// dropped: the fixed tags (Lost, eight Chunk levels, SessionAffinity,
/// RoundRobin, Each) and the Bound tags of a few pipes.
const TAGS_KEPT: usize = 32;

/// The data that blocks the window, where and when it was last sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Blocking {
    pub(super) key: StreamKey,
    /// Stream offsets of the part to copy: the unacknowledged rest of the
    /// frame that carried `start`.
    pub(super) start: u64,
    pub(super) end: u64,
    /// The pipe it was last sent on, the send time, and the acknowledgement
    /// time then expected (E).
    pub(super) pipe: u64,
    pub(super) sent: Instant,
    pub(super) expect: Duration,
}

/// What one scheduled stream direction contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Share {
    /// Its queue (urgency level).
    pub(super) level: u8,
    /// Ready data within the stream credit.
    pub(super) ready: u64,
    /// The direction is incremental: the round robin of its level serves
    /// it in turns.
    incremental: bool,
    /// Reinjected bytes pending.
    lost: u64,
    /// Reinjected information pending (bytes or a FIN).
    losing: bool,
    /// New data is ready and the direction holds at most 64 KiB unsent: a
    /// small direction whose data is latency-sensitive.
    small: bool,
    /// When its oldest ready data started to wait, session credit aside.
    mark: Option<Instant>,
    /// When its writer started to wait or its reinjected information was
    /// queued, whichever is first.
    wait: Option<Instant>,
    /// The pipe it is bound to (or moves to), and its expected bytes.
    load: Option<(u64, Expected)>,
    /// How a decision for a pipe treats it.
    pub(super) tag: Tag,
}

/// How a scheduling decision for a pipe treats a direction with new data
/// (`data_for_pipe`): alike for all directions of a tag, or one by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Tag {
    /// Reinjected information pending: it goes first, alike for every
    /// direction.
    Lost,
    /// `affinity`, bound to this pipe with data of it unacknowledged
    /// there and no move decided: it goes there while the pipe is usable,
    /// and nowhere else.
    Bound(u64),
    /// `spread-eta` with a whole chunk ready within stream credit, by
    /// urgency.
    Chunk(u8),
    /// `session-affinity`, and the session's `spread-round-robin`: one
    /// pipe for all.
    SessionAffinity,
    RoundRobin,
    /// Any other: looked at one by one.
    Each,
}

impl Share {
    /// The contribution of a sending part: `None` unless it is queued.
    /// `policy` is the session's scheduling policy, `chunk` its spread
    /// chunk, `redundancy` its redundancy setting.
    pub(super) fn of(
        send: &SendPart,
        policy: &Policy,
        chunk: u64,
        redundancy: Redundancy,
    ) -> Option<Self> {
        let level = send.queued?;
        let raw = send.buf.len() + send.preamble_left as u64;
        let ready = raw.min(send.max_data.saturating_sub(send.offset));
        let losing = send.has_lost();
        let (mark, wait) = send.wait_starts(ready > 0);
        let m = send.mp();
        let tag = match m.scheduler.as_ref().unwrap_or(policy) {
            _ if losing => Tag::Lost,
            // Either pipe of its pair may take it, whatever the policy.
            _ if super::redundancy::redundant(send, redundancy, policy) => Tag::Each,
            Policy::Affinity => match m.bound {
                Some(b) if b.move_to.is_none() && send.unacked() > 0 => Tag::Bound(b.pipe),
                _ => Tag::Each,
            },
            Policy::SpreadEta if ready >= chunk => Tag::Chunk(send.priority.urgency()),
            Policy::SessionAffinity => Tag::SessionAffinity,
            Policy::SpreadRoundRobin | Policy::SpreadRateWeighted if m.scheduler.is_none() => {
                Tag::RoundRobin
            }
            _ => Tag::Each,
        };
        Some(Self {
            level,
            ready,
            incremental: send.priority.incremental(),
            lost: m.lost.iter().map(|(a, b)| b - a).sum(),
            losing,
            small: ready > 0 && raw <= super::streams::SHARE_FLOOR,
            mark,
            wait,
            load: m
                .bound
                .map(|b| (b.move_to.unwrap_or(b.pipe), Expected::of(send))),
            tag,
        })
    }
}

/// The expected bytes E of a stream direction:
/// what the application has written and not yet committed to a pipe, and
/// at least its stream send buffer limit while a write on it waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Expected {
    Bytes(u64),
    /// The ready bytes of a direction whose write waits and that has no
    /// limit of its own: at least the session send buffer, which changes
    /// with the estimates.
    Session(u64),
}

impl Expected {
    pub(super) fn of(send: &SendPart) -> Self {
        let ready = send.buf.len() + send.preamble_left as u64;
        match (send.waits.waiting, send.cold().send_limit) {
            (false, _) => Self::Bytes(ready),
            (true, Some(limit)) => Self::Bytes(ready.max(limit)),
            (true, None) => Self::Session(ready),
        }
    }

    /// The bytes, with the session send buffer in force.
    pub(super) fn bytes(self, session_buffer: u64) -> u64 {
        match self {
            Self::Bytes(n) => n,
            Self::Session(ready) => ready.max(session_buffer),
        }
    }
}

/// The expected bytes of the directions bound to one pipe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PipeLoad {
    pipe: u64,
    streams: u64,
    /// The sum of the known expected bytes.
    bytes: u128,
    /// The ready bytes of the directions at least at the session buffer,
    /// as a multiset.
    session: BTreeMap<u64, u64>,
    session_streams: u64,
}

/// What a stream direction listed as held back by stream credit
/// contributes to opportunistic reinjection (MULTIPATH.md Section 7.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Held {
    /// Its place in the list.
    pub(super) seq: u64,
    /// Stream credit holds it back now.
    pub(super) blocked: bool,
    /// The data that blocks it, where and when it was last sent.
    pub(super) blocking: Option<Blocking>,
}

/// A writer waiting for send-buffer room,
/// with its entry in the list of waiting writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Waiter {
    /// One whose room depends only on the bytes it holds: it counts in the
    /// fair share, has no limit of its own, and its part goes on.
    Holds { held: u64, at: u32 },
    /// Any other, which only a look at the part tells.
    Other { at: u32 },
}

impl Waiter {
    pub(super) fn of(send: &SendPart) -> Option<Self> {
        let at = send.waiter?;
        let plain = send.outcome.is_none()
            && send.waits.holding
            && send.cold().send_limit.is_none()
            && !send.state.is_terminal();
        Some(match plain {
            true => Self::Holds {
                held: send.held(true),
                at,
            },
            false => Self::Other { at },
        })
    }
}

/// The contributions counted for one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    key: StreamKey,
    share: Option<Share>,
    held: Option<Held>,
    waiter: Option<Waiter>,
    copies: u64,
}

/// What a stream contributes, worked out from its sending part.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Parts {
    pub(super) share: Option<Share>,
    pub(super) held: Option<Held>,
    pub(super) waiter: Option<Waiter>,
    /// Its redundant copy bytes outstanding.
    pub(super) copies: u64,
}

/// The running aggregates (see the module documentation).
#[derive(Debug, Default)]
pub(crate) struct Ledger {
    /// The contributions counted for each slab slot.
    entries: Vec<Option<Entry>>,
    ready: [u64; 8],
    /// Per level, the ready data of each incremental direction that has
    /// some, in order, and how many they are; and the ready data of the
    /// non-incremental ones, which the round robin serves in full (N_u).
    amounts: [Amounts; 8],
    sharers: [u64; 8],
    whole: [u64; 8],
    lost: u64,
    losing: u64,
    /// Scheduled small directions with new data ready.
    small: u64,
    /// Multisets of the wait starts.
    marks: BTreeMap<Instant, u64>,
    waits: BTreeMap<Instant, u64>,
    loads: Vec<PipeLoad>,
    /// The directions with new data, by how a decision treats them.
    tags: BTreeMap<Tag, BTreeSet<StreamKey>>,
    /// The listed directions that stream credit holds back, and their
    /// blocking data by last send time (ties in list order).
    blocked: u64,
    blocking: BTreeMap<(Instant, u64), Blocking>,
    /// The view generation the blocking data was found in: it depends on
    /// which pipes are live.
    pub(super) held_generation: Option<u64>,
    /// The entries of the waiting writers whose room depends only on the
    /// bytes they hold, by those bytes, and of the others, with their
    /// streams (while entries are renumbered, two streams may name one for
    /// a moment).
    holds: BTreeSet<(u64, u32, StreamKey)>,
    others: BTreeSet<(u32, StreamKey)>,
    /// Redundant copy bytes outstanding.
    copies: u64,
}

fn add(set: &mut BTreeMap<Instant, u64>, t: Option<Instant>) {
    if let Some(t) = t {
        *set.entry(t).or_default() += 1;
    }
}

fn sub(set: &mut BTreeMap<Instant, u64>, t: Option<Instant>) {
    if let Some(t) = t
        && let std::collections::btree_map::Entry::Occupied(mut e) = set.entry(t)
    {
        *e.get_mut() -= 1;
        if *e.get() == 0 {
            e.remove();
        }
    }
}

impl Ledger {
    /// Brings the contributions of `key` up to date.
    pub(super) fn update(&mut self, key: StreamKey, p: Parts) {
        let slot = key.slot as usize;
        let new = (p != Parts::default()).then_some(Entry {
            key,
            share: p.share,
            held: p.held,
            waiter: p.waiter,
            copies: p.copies,
        });
        if self.entries.len() <= slot {
            if new.is_none() {
                return;
            }
            self.entries.resize(slot + 1, None);
        }
        let old = self.entries[slot];
        if old == new {
            return;
        }
        if new.is_none() && old.is_some_and(|e| e.key != key) {
            // A stale key (a discarded stream's, the slot reused since)
            // must not clear the entry of the stream that has it now.
            return;
        }
        // A removed stream's key goes first, so a different key here is a
        // stale one.
        self.entries[slot] = new;
        self.count_tag(
            key,
            old.and_then(|e| e.share).map(|s| s.tag),
            p.share.map(|s| s.tag),
        );
        self.count(old.and_then(|e| e.share), p.share);
        let (a, b) = (old.and_then(|e| e.held), p.held);
        if a != b {
            if let Some(h) = a {
                self.count_held(&h, false);
            }
            if let Some(h) = b {
                self.count_held(&h, true);
            }
        }
        let (a, b) = (old.and_then(|e| e.waiter), p.waiter);
        if a != b {
            if let Some(w) = a {
                self.count_waiter(key, w, false);
            }
            if let Some(w) = b {
                self.count_waiter(key, w, true);
            }
        }
        self.copies = self.copies - old.map_or(0, |e| e.copies) + p.copies;
    }

    /// Brings the blocking data of a listed direction up to date.
    pub(super) fn update_held(&mut self, key: StreamKey, held: Option<Held>) {
        if self
            .entries
            .get(key.slot as usize)
            .is_some_and(|e| e.is_some_and(|e| e.key != key))
        {
            // A stale key: its slot belongs to another stream now.
            return;
        }
        let e = self.entry(key);
        self.update(
            key,
            Parts {
                share: e.and_then(|e| e.share),
                held,
                waiter: e.and_then(|e| e.waiter),
                copies: e.map_or(0, |e| e.copies),
            },
        );
    }

    fn count_waiter(&mut self, key: StreamKey, w: Waiter, add_it: bool) {
        match (w, add_it) {
            (Waiter::Holds { held, at }, true) => self.holds.insert((held, at, key)),
            (Waiter::Holds { held, at }, false) => self.holds.remove(&(held, at, key)),
            (Waiter::Other { at }, true) => self.others.insert((at, key)),
            (Waiter::Other { at }, false) => self.others.remove(&(at, key)),
        };
    }

    /// Adds the entries of the waiting writers that may have room when
    /// room starts below `below` bytes held: those holding less, but not
    /// less than `from`, and the others unless `from` is above 0 (they
    /// were taken before).
    pub(super) fn waiters_below(&self, below: u64, from: u64, out: &mut Vec<u32>) {
        let least = StreamKey {
            slot: 0,
            generation: 0,
        };
        if from < below {
            let range = (from, 0, least)..(below, 0, least);
            out.extend(self.holds.range(range).map(|&(_, at, _)| at));
        }
        if from == 0 {
            out.extend(self.others.iter().map(|&(at, _)| at));
        }
    }

    fn count_held(&mut self, h: &Held, add_it: bool) {
        if add_it {
            self.blocked += u64::from(h.blocked);
        } else {
            self.blocked -= u64::from(h.blocked);
        }
        if let Some(b) = h.blocking {
            if add_it {
                self.blocking.insert((b.sent, h.seq), b);
            } else {
                self.blocking.remove(&(b.sent, h.seq));
            }
        }
    }

    fn entry(&self, key: StreamKey) -> Option<Entry> {
        match self.entries.get(key.slot as usize) {
            Some(&Some(e)) if e.key == key => Some(e),
            _ => None,
        }
    }

    /// Whether a listed direction is held back by stream credit.
    pub(super) fn credit_blocked(&self) -> bool {
        self.blocked > 0
    }

    /// The blocking data sent first among the directions held back by
    /// stream credit.
    pub(super) fn blocking(&self) -> Option<Blocking> {
        self.blocking.first_key_value().map(|(_, &b)| b)
    }

    /// Replaces a contribution `old` by `new`, touching the multisets only
    /// where they differ.
    fn count(&mut self, old: Option<Share>, new: Option<Share>) {
        if old == new {
            return;
        }
        if let Some(s) = old {
            self.ready[usize::from(s.level)] -= s.ready;
            self.lost -= s.lost;
            self.losing -= u64::from(s.losing);
            self.small -= u64::from(s.small);
        }
        if let Some(s) = new {
            self.ready[usize::from(s.level)] += s.ready;
            self.lost += s.lost;
            self.losing += u64::from(s.losing);
            self.small += u64::from(s.small);
        }
        let ready =
            |s: Share| (s.ready > 0).then_some((usize::from(s.level), s.ready, s.incremental));
        let (a, b) = (old.and_then(ready), new.and_then(ready));
        if a != b {
            if let Some((level, r, incremental)) = a {
                if incremental {
                    self.amounts[level].remove(r);
                    self.sharers[level] -= 1;
                } else {
                    self.whole[level] -= r;
                }
            }
            if let Some((level, r, incremental)) = b {
                if incremental {
                    self.amounts[level].insert(r);
                    self.sharers[level] += 1;
                } else {
                    self.whole[level] += r;
                }
            }
        }
        let (a, b) = (old.and_then(|s| s.mark), new.and_then(|s| s.mark));
        if a != b {
            sub(&mut self.marks, a);
            add(&mut self.marks, b);
        }
        let (a, b) = (old.and_then(|s| s.wait), new.and_then(|s| s.wait));
        if a != b {
            sub(&mut self.waits, a);
            add(&mut self.waits, b);
        }
        let (a, b) = (old.and_then(|s| s.load), new.and_then(|s| s.load));
        if a != b {
            if let Some((pipe, e)) = a {
                self.count_load(pipe, e, false);
            }
            if let Some((pipe, e)) = b {
                self.count_load(pipe, e, true);
            }
        }
    }

    fn count_tag(&mut self, key: StreamKey, old: Option<Tag>, new: Option<Tag>) {
        if old == new {
            return;
        }
        // A set that empties is kept, with its node: a direction that
        // leaves its queue and comes back (a stream drained and written
        // again, thousands of times a second at 10 Gbit/s) allocates
        // nothing. Empty sets are dropped only when a new tag needs room
        // beyond a few dozen (tags of pipes gone).
        if let Some(t) = old
            && let Some(set) = self.tags.get_mut(&t)
        {
            set.remove(&key);
        }
        if let Some(t) = new {
            if !self.tags.contains_key(&t) && self.tags.len() >= TAGS_KEPT {
                self.tags.retain(|_, s| !s.is_empty());
            }
            self.tags.entry(t).or_default().insert(key);
        }
    }

    fn count_load(&mut self, pipe: u64, expected: Expected, add_it: bool) {
        let i = match self.loads.iter().position(|l| l.pipe == pipe) {
            Some(i) => i,
            None => {
                self.loads.push(PipeLoad {
                    pipe,
                    ..PipeLoad::default()
                });
                self.loads.len() - 1
            }
        };
        let l = &mut self.loads[i];
        let sign = |a: u64| if add_it { a + 1 } else { a - 1 };
        l.streams = sign(l.streams);
        match expected {
            Expected::Bytes(n) if add_it => l.bytes += u128::from(n),
            Expected::Bytes(n) => l.bytes -= u128::from(n),
            Expected::Session(r) => {
                l.session_streams = sign(l.session_streams);
                if add_it {
                    *l.session.entry(r).or_default() += 1;
                } else if let std::collections::btree_map::Entry::Occupied(mut e) =
                    l.session.entry(r)
                {
                    *e.get_mut() -= 1;
                    if *e.get() == 0 {
                        e.remove();
                    }
                }
            }
        }
        if l.streams == 0 {
            self.loads.swap_remove(i);
        }
    }

    /// The contribution of a scheduled stream direction.
    pub(super) fn share(&self, key: StreamKey) -> Option<Share> {
        self.entry(key)?.share
    }

    /// Ready data within stream credit of the levels below `levels`.
    pub(super) fn ready_below(&self, levels: usize) -> u64 {
        self.ready[..levels.min(8)].iter().sum()
    }

    /// The ready data within stream credit of level `level`.
    pub(super) fn ready_at(&self, level: u8) -> u64 {
        self.ready.get(usize::from(level)).copied().unwrap_or(0)
    }

    /// The ready data within stream credit of level `level` that comes
    /// before `cap` bytes of an incremental direction: every
    /// non-incremental direction's in full (N_u), each incremental one's up
    /// to `cap`.
    pub(super) fn ready_capped(&self, level: u8, cap: u64) -> u64 {
        let l = usize::from(level);
        let shared = self
            .amounts
            .get(l)
            .map_or(0, |a| u64::try_from(a.capped_sum(cap)).unwrap_or(u64::MAX));
        self.whole
            .get(l)
            .copied()
            .unwrap_or(0)
            .saturating_add(shared)
    }

    /// The incremental directions of level `level` with data ready within
    /// stream credit.
    pub(super) fn sharers(&self, level: u8) -> u64 {
        self.sharers.get(usize::from(level)).copied().unwrap_or(0)
    }

    /// Reinjected bytes pending.
    pub(super) fn lost(&self) -> u64 {
        self.lost
    }

    /// Redundant copy bytes outstanding.
    pub(super) fn copies(&self) -> u64 {
        self.copies
    }

    /// The directions with new data, by how a decision treats them.
    pub(super) fn tags(&self) -> impl Iterator<Item = (Tag, &BTreeSet<StreamKey>)> {
        self.tags
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(&t, s)| (t, s))
    }

    /// The scheduled directions with reinjected information pending.
    pub(super) fn losing(&self) -> Option<&BTreeSet<StreamKey>> {
        self.tags.get(&Tag::Lost).filter(|s| !s.is_empty())
    }

    /// Whether a scheduled small direction has new data ready.
    pub(super) fn any_small(&self) -> bool {
        self.small > 0
    }

    /// Whether a scheduled direction has reinjected information pending.
    pub(super) fn any_lost(&self) -> bool {
        self.losing > 0
    }

    /// The earliest start of the ready data's waits, and of the writers'
    /// waits and the reinjections.
    pub(super) fn oldest(&self) -> (Option<Instant>, Option<Instant>) {
        let first = |m: &BTreeMap<Instant, u64>| m.first_key_value().map(|(&t, _)| t);
        (first(&self.marks), first(&self.waits))
    }

    /// A_p: the expected bytes of the directions bound to `pipe`, but for
    /// `except`'s, with the session send buffer in force.
    pub(super) fn load(&self, pipe: u64, except: StreamKey, session_buffer: u64) -> u64 {
        let Some(l) = self.loads.iter().find(|l| l.pipe == pipe) else {
            return 0;
        };
        let sb = u128::from(session_buffer);
        let mut sum = l.bytes + u128::from(l.session_streams) * sb;
        for (&r, &n) in l.session.range(session_buffer.saturating_add(1)..) {
            sum += (u128::from(r) - sb) * u128::from(n);
        }
        if let Some((p, e)) = self.share(except).and_then(|s| s.load)
            && p == pipe
        {
            sum -= u128::from(e.bytes(session_buffer));
        }
        u64::try_from(sum).unwrap_or(u64::MAX)
    }

    /// Debug builds: the aggregates equal `fresh`, a recount.
    #[cfg(debug_assertions)]
    fn check(&self, fresh: &Self) {
        let entries = |l: &Self| -> Vec<Entry> { l.entries.iter().flatten().copied().collect() };
        debug_assert_eq!(entries(self), entries(fresh), "ledger: stale contributions");
        debug_assert_eq!(self.ready, fresh.ready, "ledger: ready data");
        debug_assert!(
            self.amounts
                .iter()
                .zip(&fresh.amounts)
                .all(|(a, b)| a.items() == b.items()),
            "ledger: ready amounts"
        );
        debug_assert_eq!(self.sharers, fresh.sharers, "ledger: sharers");
        debug_assert_eq!(
            self.whole, fresh.whole,
            "ledger: non-incremental ready data"
        );
        debug_assert_eq!(self.lost, fresh.lost, "ledger: lost bytes");
        debug_assert_eq!(self.losing, fresh.losing, "ledger: lost parts");
        debug_assert_eq!(self.small, fresh.small, "ledger: small directions");
        debug_assert_eq!(self.marks, fresh.marks, "ledger: marks");
        debug_assert_eq!(self.waits, fresh.waits, "ledger: waits");
        let sorted = |v: &[PipeLoad]| {
            let mut v = v.to_vec();
            v.sort_by_key(|l| l.pipe);
            v
        };
        debug_assert_eq!(
            sorted(&self.loads),
            sorted(&fresh.loads),
            "ledger: pipe loads"
        );
        debug_assert!(self.tags().eq(fresh.tags()), "ledger: decision tags");
        debug_assert_eq!(self.blocked, fresh.blocked, "ledger: blocked parts");
        debug_assert_eq!(self.blocking, fresh.blocking, "ledger: blocking data");
        debug_assert_eq!(self.holds, fresh.holds, "ledger: waiting writers");
        debug_assert_eq!(self.others, fresh.others, "ledger: other writers");
        debug_assert_eq!(self.copies, fresh.copies, "ledger: copy bytes");
    }
}

impl super::SessionCore {
    /// The ledger of a multipath session, brought up to date with the
    /// streams changed since the last read. Debug builds check it against
    /// a recount.
    pub(super) fn ledger(&self) -> Option<std::cell::Ref<'_, Ledger>> {
        let mp = self.mp.as_deref()?;
        let generation = Some(mp.tiers().view_generation());
        let ledger = mp.ledger();
        if self.streams.has_touched() || ledger.borrow().held_generation != generation {
            let mut l = ledger.borrow_mut();
            if l.held_generation != generation {
                // Pipes went live or stopped being so.
                l.held_generation = generation;
                for &key in mp.blocked().keys() {
                    let held = self
                        .streams
                        .send(key)
                        .and_then(|send| self.held_of(key, send));
                    l.update_held(key, held);
                }
            }
            self.streams.take_touched(|key, s| {
                let parts = s
                    .and_then(|s| s.send.as_ref())
                    .map_or_else(Parts::default, |send| self.parts_of(key, send));
                l.update(key, parts);
            });
        }
        let l = ledger.borrow();
        #[cfg(debug_assertions)]
        if self.streams.len() <= 64 {
            l.check(&self.recount());
        }
        Some(l)
    }

    /// What a stream contributes to the ledger.
    fn parts_of(&self, key: StreamKey, send: &SendPart) -> Parts {
        Parts {
            share: Share::of(
                send,
                &self.config.scheduler,
                self.config.spread_chunk as u64,
                self.config.redundancy,
            ),
            held: self.held_of(key, send),
            waiter: Waiter::of(send),
            copies: send.copies_outstanding(),
        }
    }

    /// A ledger counted from scratch, from the scheduler queues, the
    /// directions held back by stream credit, the waiting writers and the
    /// directions with copies outstanding.
    #[cfg(debug_assertions)]
    fn recount(&self) -> Ledger {
        let mut fresh = Ledger::default();
        let mut keys: Vec<StreamKey> = Vec::new();
        for (u, q) in self.streams.queue().levels().iter().enumerate() {
            for &key in q {
                if let Some(send) = self.streams.send(key) {
                    debug_assert_eq!(send.queued, Some(u as u8), "queued at another level");
                    keys.push(key);
                }
            }
        }
        keys.extend(self.mp().blocked().keys());
        keys.extend(self.streams.send_waiters());
        keys.extend(self.streams.keys().filter(|&k| {
            self.streams
                .send(k)
                .is_some_and(|send| send.copies_outstanding() > 0)
        }));
        keys.sort_unstable();
        keys.dedup();
        for key in keys {
            if let Some(send) = self.streams.send(key) {
                fresh.update(key, self.parts_of(key, send));
            }
        }
        fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stale key (a discarded stream's, its slot reused) never touches
    /// the entry of the stream that has the slot now.
    #[test]
    fn a_stale_key_leaves_the_slots_new_owner_alone() {
        let old = StreamKey {
            slot: 3,
            generation: 1,
        };
        let new = StreamKey {
            slot: 3,
            generation: 2,
        };
        let held = Held {
            seq: 7,
            blocked: true,
            blocking: None,
        };
        let mut l = Ledger::default();
        l.update(
            new,
            Parts {
                held: Some(held),
                ..Parts::default()
            },
        );
        l.update_held(old, None);
        l.update(old, Parts::default());
        assert_eq!(l.entry(new).and_then(|e| e.held), Some(held));
        l.update_held(old, Some(Held { seq: 8, ..held }));
        assert_eq!(l.entry(new).and_then(|e| e.held), Some(held));
    }
}
