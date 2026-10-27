//! Multipath scheduling (MULTIPATH.md Section 11): which stream data goes
//! on which outbound pipe when the pipe can take bytes (late binding).

use std::cell::{Cell, OnceCell, RefCell};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::ledger::{Expected, Tag};
use super::mpath::Mp;
use super::pipes::{Attachment, Attachments, OutPipe};
use super::policy::{Binding, FrameInfo, PickAnswer, PickRequest, Picked, PipeSnapshot, Policy};
use super::stream::SendPart;
use super::tier::{Class, Gate};
use super::{PipeId, SessionCore, StreamKey};

/// The carrier low-water mark in multipath sessions.
pub(super) const NOTSENT_LOWAT: u64 = 32 * 1024;

/// ECF hysteresis.
const BETA: f64 = 0.25;
/// Stream directions expected to be smaller are bound to the lowest-delay
/// pipe.
const SMALL_STREAM: u64 = 256 * 1024;
/// The placement rate lasts this many of the pipe's own round trips.
const PLACEMENT_ROUNDS: u64 = 4;

/// Bulk `affinity` directions are rebalanced at most once per
/// max(this, 4 x RTT_max).
const REBALANCE: Duration = Duration::from_secs(1);
/// A bulk direction moves only for at least this much more share.
const REBALANCE_GAIN: f64 = 1.25;

/// The custom-policy decisions of a multipath session.
#[derive(Debug, Default)]
pub(crate) struct Picks {
    /// Answers that could not be applied (stale, invalid, or a panic): the
    /// chunk took the `affinity` choice.
    fallbacks: Cell<u64>,
    /// Answers applied.
    applied: u64,
    /// The generation: it advances when a decision can no longer be
    /// applied (the pipe set, a pipe's state or eligibility changed), never
    /// with metrics.
    generation: u64,
    /// Advances with every input (records, timers, writes, pipe changes):
    /// a "wait" answer holds until the next one.
    input_epoch: u64,
    /// Stream directions whose next chunk needs a custom decision, for the
    /// next call.
    pending: RefCell<Vec<StreamKey>>,
    /// The directions of the call under way, and its generation.
    out: Vec<StreamKey>,
    out_gen: u64,
    /// Stream directions holding an answer not yet used.
    picked: Vec<StreamKey>,
}

impl Picks {
    /// Answers not applied, and answers applied.
    pub(super) fn counts(&self) -> (u64, u64) {
        (self.fallbacks.get(), self.applied)
    }

    /// A stream is gone: it waits for no decision and holds no answer.
    pub(super) fn forget(&mut self, key: StreamKey) {
        if let Some(i) = self.picked.iter().position(|&k| k == key) {
            self.picked.swap_remove(i);
        }
        self.pending.get_mut().retain(|&k| k != key);
    }
}

/// The re-evaluation of `affinity` bindings.
#[derive(Debug, Default)]
pub(crate) struct Affinity {
    /// Provisional bindings wait for re-evaluation.
    provisional: bool,
    /// The usable outbound pipes at the last look, and a generation that
    /// grows when a pipe becomes usable.
    usable_seen: Vec<u64>,
    usable_epoch: u64,
    /// A scheduled binding may be older than the generation: set when the
    /// generation grows or such a direction is queued, cleared once every
    /// scheduled binding was brought up to it.
    bindings_stale: bool,
    /// When bulk directions may be rebalanced next, and the scratch of that
    /// pass.
    rebalance_at: Option<Instant>,
    rebalance_scratch: Vec<(u64, u64, u64, u64, bool)>,
}

impl Affinity {
    /// A direction bound in generation `epoch` is queued: its binding is
    /// re-evaluated with the next batch when it is older than the usable
    /// pipes.
    pub(super) fn queued(&mut self, epoch: u64) {
        if epoch < self.usable_epoch {
            self.bindings_stale = true;
        }
    }
}

/// [`SessionCore::placement_rate`] of `a`'s outbound pipe `o` among the
/// attachments `atts`; `off` is the ablation without it.
fn placement_rate(atts: &Attachments, a: &Attachment, o: &OutPipe, off: bool) -> u64 {
    let own = o.est().rate;
    let est = o.est();
    let from = est.placed_from.get();
    if off
        || est.rate_measured
        || est.penalized
        || from.is_some_and(|r| est.round >= r.saturating_add(PLACEMENT_ROUNDS))
        || !o.usable(false)
    {
        return own;
    }
    let (tier, standby) = (a.send_tier(), a.standby());
    let fastest = atts
        .iter()
        .filter(|q| q.id() != a.id() && q.send_tier() == tier && q.standby() == standby)
        .filter_map(|q| q.out())
        .filter(|q| (q.est().rate_measured || q.est().penalized) && q.usable(false))
        .map(|q| q.est().rate)
        .max()
        .unwrap_or(0);
    if fastest <= own {
        return own;
    }
    if from.is_none() {
        // The four round trips start now, while the pipe is usable.
        est.placed_from.set(Some(est.round));
    }
    fastest
}

/// What every stream's choice at one write opportunity of a pipe shares
/// (MULTIPATH.md Section 11): the tier gate and the pipe's place in it,
/// worked out once for the decision instead of once per stream.
#[derive(Debug)]
pub(super) struct Decision {
    pub(super) id: u64,
    pub(super) gate: Option<Gate>,
    /// The pipe exists and is writable: no stream goes on it otherwise.
    open: bool,
    tier: u64,
    /// The pipe is usable, and takes new data under the gate.
    usable: bool,
    takes: bool,
    /// A JOINING pipe takes data while no pipe is usable (rule S1).
    joining_takes: bool,
    /// The pipe of the tier with the earliest arrival of a whole chunk.
    fastest: Option<u64>,
    /// Computed when a policy needs them: the reorder budget, the session
    /// send buffer, the active pipe of `session-affinity` and the session's
    /// `spread-round-robin` choice.
    reorder: OnceCell<u64>,
    session_buffer: OnceCell<u64>,
    session_pipe: OnceCell<Option<u64>>,
    round_robin: OnceCell<Option<u64>>,
    /// The `affinity` bindings chosen in the decision, by what they depend
    /// on (expected bytes, small or urgent, the pipe whose load counts the
    /// direction).
    bindings: Cell<[Option<Bound>; BINDING_MEMO]>,
    /// The ETA inputs of the pipe and of the fastest of its tier.
    etas: OnceCell<(Option<Eta>, Option<Eta>)>,
    /// Whether the pipe is in the pair of its tier for a redundant chunk,
    /// by chunk length: redundant directions are decided one by one, and
    /// the first answer for a length serves the others.
    pairs: Cell<[Option<(u64, bool)>; PAIR_MEMO]>,
    /// ECF backlogs by what they depend on: the directions of a level with
    /// the same ready data share one.
    backlogs: Cell<[Option<(Backlog, u64)>; BACKLOG_MEMO]>,
}

impl Decision {
    /// Readies the decision for the pipe's next chunk under an unchanged
    /// gate and unchanged pipe views (one gate per
    /// chunk; the same inputs give the same gate, and the same decision).
    /// What the chunk just written may have changed is worked out again:
    /// the reorder budget and the session send buffer (credit and
    /// holdings), the round-robin choice (its current values), the
    /// bindings (the pipe loads) and the ECF backlogs (ready data). The
    /// arrival estimates, the pair answers and the active pipe depend only
    /// on the pipes, which a chunk does not change.
    pub(super) fn renew(&mut self) {
        self.reorder = OnceCell::new();
        self.session_buffer = OnceCell::new();
        self.round_robin = OnceCell::new();
        self.bindings.set([None; BINDING_MEMO]);
        self.backlogs.set([None; BACKLOG_MEMO]);
    }

    /// Debug builds: what the decision keeps across chunks equals a fresh
    /// decision's.
    #[cfg(debug_assertions)]
    pub(super) fn check_renewed(&self, s: &SessionCore) {
        let fresh = s.decision(self.id, self.gate);
        let core = |d: &Self| {
            (
                d.id,
                d.gate,
                d.open,
                d.tier,
                d.usable,
                d.takes,
                d.joining_takes,
                d.fastest,
            )
        };
        debug_assert_eq!(core(self), core(&fresh), "renewed decision out of date");
        if let Some(&(p, f)) = self.etas.get() {
            let (q, g) = s.decision_etas(&fresh);
            let same = |a: Option<Eta>, b: Option<Eta>| match (a, b) {
                (Some(a), Some(b)) => {
                    (a.queued, a.rate, a.estimate, a.owd.to_bits())
                        == (b.queued, b.rate, b.estimate, b.owd.to_bits())
                }
                (a, b) => a.is_none() && b.is_none(),
            };
            debug_assert!(
                same(p, q) && same(f, g),
                "renewed arrival estimates out of date"
            );
        }
        if let Some(&p) = self.session_pipe.get() {
            let gate = self.gate.expect("a session pipe needs a gate");
            debug_assert_eq!(
                p,
                s.tier_active(gate.class(), self.tier),
                "renewed active pipe"
            );
        }
        for (len, pair) in self.pairs.get().into_iter().flatten() {
            let gate = self.gate.expect("a pair needs a gate");
            debug_assert_eq!(
                pair,
                s.in_pair(&gate, self.tier, len, self.id),
                "renewed pair"
            );
        }
    }
}

/// What ETA_p(L) needs of a pipe at a
/// decision: Q_p, R_p as divided by (at least 1), R_p as estimated, and
/// the one-way delay in seconds.
#[derive(Debug, Clone, Copy)]
struct Eta {
    queued: u64,
    rate: u64,
    estimate: u64,
    owd: f64,
}

impl Eta {
    /// ETA_p(L) in seconds.
    fn of(&self, len: u64) -> f64 {
        (self.queued + len) as f64 / self.rate as f64 + self.owd
    }
}

/// What an `affinity` binding choice depends on besides the pipes.
type Like = (u64, bool, Option<u64>);

/// A binding chosen in a decision, by what it depended on.
type Bound = (Like, Option<u64>);

/// Bindings remembered per decision: enough for the kinds of direction a
/// session has at once; others are chosen one by one.
const BINDING_MEMO: usize = 8;

/// Pair answers remembered per decision: whole chunks share one length,
/// smaller redundant writes are looked at one by one beyond these.
const PAIR_MEMO: usize = 4;

/// What an ECF backlog depends on: the urgency level, the ready data of the
/// direction whose round-robin share it is (`None`: all of the level) and
/// the chunk length.
type Backlog = (u8, Option<u64>, u64);

/// ECF backlogs remembered per decision: the levels and ready amounts of
/// the directions looked at in one decision are few; others are worked out
/// one by one (each in O(log n)).
const BACKLOG_MEMO: usize = 8;

impl SessionCore {
    /// How much more a pipe may reinject now: one chunk in all while its
    /// reinjection hold lasts (RESUME.md Section 6), else no limit.
    pub(super) fn reinject_room(&self, id: u64) -> u64 {
        self.out_ref(id)
            .and_then(|o| o.reinject_room(self.config.spread_chunk as u64, self.now))
            .unwrap_or(u64::MAX)
    }

    /// Whether any stream direction has reinjected information pending.
    pub(super) fn any_lost(&self) -> bool {
        self.ledger().is_some_and(|l| l.any_lost())
    }

    /// ETA_p(L) in seconds of an attachment's
    /// outbound pipe `o`.
    pub(super) fn eta(&self, a: &Attachment, o: &OutPipe, len: u64) -> f64 {
        self.eta_inputs(a, o).of(len)
    }

    /// What ETA_p(L) needs of a pipe now.
    fn eta_inputs(&self, a: &Attachment, o: &OutPipe) -> Eta {
        let rate = self.placement_rate(a, o);
        Eta {
            queued: Self::queued(o),
            rate: rate.max(1),
            estimate: rate,
            owd: self.owd(o).as_secs_f64(),
        }
    }

    /// The ETA inputs of pipe `id`.
    fn eta_of(&self, id: u64) -> Option<Eta> {
        let a = self.att(id)?;
        Some(self.eta_inputs(a, a.out()?))
    }

    /// The rate at which the spreading policies place data on a pipe: R_p,
    /// except for a usable pipe without a
    /// bottleneck sample while another usable pipe of its tier with the
    /// same standby flag has one (or was penalized): that pipe counts as
    /// fast as the fastest such pipe, for four of its own round trips from
    /// the first time that is more than R_p, or until its first bottleneck
    /// sample or a penalty. A pipe that joins while the others carry the
    /// load would otherwise get nothing but urgent copies on a fast path:
    /// its 1 MB/s start fails BLEST, and the application-limited samples
    /// of the copies keep it there. Only the arrival estimate (and with it
    /// ECF, BLEST and the redundant pair) and the rate weights use it;
    /// bindings, tier gating, failure detection, the limiter and the
    /// budgets keep R_p.
    fn placement_rate(&self, a: &Attachment, o: &OutPipe) -> u64 {
        placement_rate(&self.atts, a, o, self.config.hooks.no_placement_rate)
    }

    /// The ETA inputs of the decision's pipe and of the fastest pipe of its
    /// tier for a whole chunk.
    fn decision_etas(&self, d: &Decision) -> (Option<Eta>, Option<Eta>) {
        *d.etas
            .get_or_init(|| (self.eta_of(d.id), d.fastest.and_then(|f| self.eta_of(f))))
    }

    /// The pipe of a tier with the smallest ETA for `len` bytes.
    fn fastest_in(&self, gate: &Gate, tier: u64, len: u64) -> Option<u64> {
        let views = self.views();
        let eta = |a: &Attachment| Some((self.eta(a, a.out()?, len), a.id()));
        let min = |a: (f64, u64), b: (f64, u64)| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1));
        if views.class() == Some(gate.class()) {
            views
                .pipes(views.tier(tier)?)
                .iter()
                .filter_map(|&i| eta(self.atts.at(i)))
                .min_by(|a, b| min(*a, *b))
        } else {
            // A gate of an earlier moment of the same decision.
            self.atts
                .iter()
                .filter(|a| gate.usable(a) && a.send_tier() == tier)
                .filter_map(eta)
                .min_by(|a, b| min(*a, *b))
        }
        .map(|(_, q)| q)
    }

    /// The eligible pipe with the smallest ETA for `len` bytes, whatever
    /// its tier (opportunistic copies, MULTIPATH.md Section 7.5.1).
    pub(super) fn fastest_eligible(&self, gate: &Gate, len: u64) -> Option<u64> {
        let views = self.views();
        views
            .tiers()
            .iter()
            .take_while(|t| t.priority <= gate.last())
            .flat_map(|t| views.pipes(t))
            .filter_map(|&i| {
                let a = self.atts.at(i);
                Some((self.eta(a, a.out()?, len), a.id()))
            })
            .min_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)))
            .map(|(_, q)| q)
    }

    /// The scheduling policy of a stream direction.
    pub(super) fn policy_for(&self, key: StreamKey) -> &Policy {
        self.streams
            .send(key)
            .and_then(|s| s.mp().scheduler.as_ref())
            .unwrap_or(&self.config.scheduler)
    }

    /// The decision at a write opportunity of pipe `id` under `gate`.
    pub(super) fn decision(&self, id: u64, gate: Option<Gate>) -> Decision {
        let a = self.att(id);
        let o = a.and_then(Attachment::out).filter(|o| o.writable());
        let tier = a.map_or(0, Attachment::send_tier);
        let usable = a.is_some_and(|a| gate.is_some_and(|g| g.usable(a)));
        let takes = match (a, &gate) {
            (Some(a), Some(g)) => self.takes(g, a),
            _ => false,
        };
        let chunk = self.config.spread_chunk as u64;
        Decision {
            id,
            gate,
            open: o.is_some(),
            tier,
            usable,
            takes,
            joining_takes: o.is_some_and(OutPipe::joining_takes),
            fastest: gate.and_then(|g| self.fastest_in(&g, tier, chunk)),
            reorder: OnceCell::new(),
            session_buffer: OnceCell::new(),
            session_pipe: OnceCell::new(),
            round_robin: OnceCell::new(),
            bindings: Cell::new([None; BINDING_MEMO]),
            etas: OnceCell::new(),
            pairs: Cell::new([None; PAIR_MEMO]),
            backlogs: Cell::new([None; BACKLOG_MEMO]),
        }
    }

    /// Whether the next chunk of a stream may go on the decision's pipe
    /// now.
    pub(super) fn stream_on_pipe(&self, d: &Decision, key: StreamKey) -> bool {
        if !d.open {
            return false;
        }
        let Some(send) = self.streams.send(key) else {
            return false;
        };
        let Some(gate) = d.gate else {
            // No pipe is usable: a JOINING pipe carries stream data,
            // reinjected information first (rule S1, MULTIPATH.md Section
            // 11).
            if !d.joining_takes {
                return false;
            }
            let room = self.reinject_room(d.id) > 0;
            if send.has_lost() {
                // Reinjected information first; while the reinjection hold
                // is used up, the stream's new data does not wait for it
                // (when stream and session credit and the retransmit budget
                // let it go: else nothing would be written for the write
                // interest).
                return room
                    || self.fin_only(key)
                    || (send.has_fresh()
                        && !send.credit_blocked()
                        && !self.streams.session_stalled()
                        && self.mp().retained() < self.retransmit_budget());
            }
            return !self.any_lost() || !room;
        };
        let id = d.id;
        if send.has_lost() {
            // Reinjected information first, on the eligible pipe of the
            // tier with the earliest arrival (rule S3), while the
            // pipe's reinjection hold leaves room.
            return d.takes && d.fastest == Some(id) && self.reinject_room(id) > 0;
        }
        // Redundant data: either pipe of the pair takes the chunk, whatever
        // the policy would give it.
        if d.takes && self.redundant(send) {
            let ready = send.buf.len() + send.preamble_left as u64;
            let len = ready.min(self.config.spread_chunk as u64).max(1);
            if self.decision_in_pair(d, &gate, len) {
                return true;
            }
        }
        match self.policy_for(key) {
            // A binding and a custom policy apply the gate themselves.
            Policy::Affinity => d.usable && self.affinity_target(key, d) == Some(id),
            Policy::Custom(_) => self.custom_ok(d, key),
            _ if !d.takes => false,
            Policy::SpreadEta => self.spread_eta_ok(d, send),
            Policy::SpreadRoundRobin | Policy::SpreadRateWeighted if self.own_round_robin(key) => {
                self.round_robin_pick(key, &gate, d.tier) == Some(id)
            }
            Policy::SpreadRoundRobin | Policy::SpreadRateWeighted => {
                *d.round_robin
                    .get_or_init(|| self.round_robin_pick(key, &gate, d.tier))
                    == Some(id)
            }
            Policy::SessionAffinity => {
                *d.session_pipe
                    .get_or_init(|| self.tier_active(gate.class(), d.tier))
                    == Some(id)
            }
        }
    }

    /// Whether the decision's pipe is one of the pair of its tier that may
    /// take a redundant chunk of `len` bytes, worked out once per length.
    fn decision_in_pair(&self, d: &Decision, gate: &Gate, len: u64) -> bool {
        let mut memo = d.pairs.get();
        if let Some(&(_, pair)) = memo.iter().flatten().find(|(l, _)| *l == len) {
            return pair;
        }
        let pair = self.in_pair(gate, d.tier, len, d.id);
        if let Some(free) = memo.iter_mut().find(|m| m.is_none()) {
            *free = Some((len, pair));
            d.pairs.set(memo);
        }
        pair
    }

    /// Whether the decision puts some scheduled direction on its pipe:
    /// reinjected information always counts, new data only with `fresh`.
    /// The directions of a ledger tag are decided alike, so one stands for
    /// all; only those decided one by one are looked at each.
    pub(super) fn any_stream_on(&self, d: &Decision, fresh: bool) -> bool {
        let Some(l) = self.ledger() else {
            return false;
        };
        let first = |set: &std::collections::BTreeSet<StreamKey>| set.first().copied();
        let each = |set: &std::collections::BTreeSet<StreamKey>| {
            set.iter().any(|&k| self.stream_on_pipe(d, k))
        };
        let mut tags = l.tags().peekable();
        if let Some((Tag::Lost, set)) = tags.peek() {
            let found = if self.reinject_room(d.id) > 0 {
                first(set).is_some_and(|k| self.stream_on_pipe(d, k))
            } else {
                // The reinjection hold is used up: only new data of these
                // streams may go, without a tier gate, each by its own.
                d.gate.is_none() && each(set)
            };
            if found {
                return true;
            }
            tags.next();
        }
        if !fresh {
            return false;
        }
        let Some(gate) = d.gate else {
            // Without a usable pipe, new data goes alike for all.
            return tags
                .next()
                .and_then(|(_, set)| first(set))
                .is_some_and(|k| self.stream_on_pipe(d, k));
        };
        let class = gate.class();
        for (tag, set) in tags {
            let found = match tag {
                Tag::Lost => unreachable!("the lost tag comes first"),
                // Bound elsewhere: there only while that pipe is usable.
                Tag::Bound(p) if p != d.id && self.att(p).is_some_and(|a| class.usable(a)) => false,
                Tag::Bound(p) if p != d.id => each(set),
                Tag::Chunk(_) if !d.takes => false,
                Tag::Chunk(_) => match first(set) {
                    Some(k) => match self.whole_chunk_on(d, k) {
                        Some(all) => all,
                        None => each(set),
                    },
                    None => false,
                },
                Tag::Bound(_) | Tag::SessionAffinity | Tag::RoundRobin => {
                    first(set).is_some_and(|k| self.stream_on_pipe(d, k))
                }
                Tag::Each => each(set),
            };
            if found {
                return true;
            }
        }
        false
    }

    /// The pipe an `affinity` stream direction sends on now: its binding while
    /// data of it is unacknowledged there, none
    /// while a decided move waits for that, and at an idle point (or when
    /// the pipe is no longer usable) a new binding.
    fn affinity_target(&self, key: StreamKey, d: &Decision) -> Option<u64> {
        let send = self.streams.get(key)?.send.as_ref()?;
        let class = d.gate?.class();
        let works = |p: u64| self.att(p).is_some_and(|a| class.usable(a));
        let idle = send.unacked() == 0 && !send.has_lost();
        match send.mp().bound {
            Some(b) if !idle && works(b.pipe) => b.move_to.is_none().then_some(b.pipe),
            Some(Binding {
                move_to: Some(m), ..
            }) if works(m) => Some(m),
            Some(b) => self.binding_for(d, key, send, Some(b.move_to.unwrap_or(b.pipe))),
            None => self.binding_for(d, key, send, None),
        }
    }

    /// [`Self::binding_choice`] within a decision: directions alike in
    /// what the choice depends on (their expected bytes, whether they are
    /// small, and the pipe whose load counts them) get the same pipe, so
    /// the first answer serves the others.
    fn binding_for(
        &self,
        d: &Decision,
        key: StreamKey,
        send: &SendPart,
        counted_on: Option<u64>,
    ) -> Option<u64> {
        let sb = *d.session_buffer.get_or_init(|| self.session_send_buffer());
        let expected = Expected::of(send).bytes(sb);
        let like = (expected, send.priority.urgency() <= 2, counted_on);
        let mut memo = d.bindings.get();
        if let Some((_, pipe)) = memo.iter().flatten().find(|(l, _)| *l == like) {
            debug_assert_eq!(*pipe, self.binding_choice(key, sb), "unlike bindings");
            return *pipe;
        }
        let pipe = self.binding_choice(key, sb);
        if let Some(free) = memo.iter_mut().find(|m| m.is_none()) {
            *free = Some((like, pipe));
            d.bindings.set(memo);
        }
        pipe
    }

    /// Records the pipe an `affinity` direction sent `n` bytes of new data
    /// on; a custom answer uses up its bytes (a miss serves one chunk).
    pub(super) fn bind_on_send(&mut self, id: u64, key: StreamKey, n: u64) {
        if !matches!(self.policy_for(key), Policy::Affinity | Policy::Custom(_)) {
            return;
        }
        if let Some(send) = self.streams.send_mut(key) {
            let m = send.mp_mut();
            let used = match &mut m.picked {
                Some(Picked::Pipe {
                    left: Some(left), ..
                }) => {
                    *left = left.saturating_sub(n);
                    *left == 0
                }
                Some(Picked::Pipe { left: None, .. }) | Some(Picked::Wait { .. }) | None => false,
                Some(Picked::Affinity) => true,
            };
            if used {
                m.picked = None;
                if let Some(p) = self.mp.as_deref_mut().map(Mp::picks_mut)
                    && let Some(i) = p.picked.iter().position(|&k| k == key)
                {
                    p.picked.swap_remove(i);
                }
            }
        }
        let class = self.class();
        let all_sampled = self
            .atts
            .iter()
            .filter(|a| class.is_some_and(|c| c.usable(a)))
            .filter_map(|a| a.out())
            .all(|o| o.est().sampled);
        let epoch = self.mp().affinity().usable_epoch;
        let Some(send) = self.streams.send_mut(key) else {
            return;
        };
        if send
            .mp()
            .bound
            .is_some_and(|b| b.pipe == id && b.move_to.is_none())
        {
            return;
        }
        send.mp_mut().bound = Some(Binding {
            pipe: id,
            provisional: !all_sampled,
            epoch,
            move_to: None,
        });
        if !all_sampled {
            self.mp_mut().affinity_mut().provisional = true;
        }
    }

    /// Re-evaluates `affinity` bindings, once per batch:
    /// provisional bindings once every usable pipe has an RTT sample,
    /// bindings made before a pipe that is usable now became usable, and
    /// bindings in a less-preferred tier when a more-preferred tier passes
    /// the binding wait test for them. A direction that should move stops
    /// new data until its data on the old pipe is acknowledged.
    pub(super) fn refresh_bindings(&mut self, gate: Option<&Gate>) {
        let Some(gate) = gate else {
            return;
        };
        let class = gate.class();
        let top = gate.top();
        let all_sampled = self
            .atts
            .iter()
            .filter(|a| class.usable(a))
            .filter_map(|a| a.out())
            .all(|o| o.est().sampled);
        let provisional =
            self.mp.as_deref().is_some_and(|m| m.affinity().provisional) && all_sampled;
        if provisional {
            self.mp_mut().affinity_mut().provisional = false;
        }
        // A pipe became usable since the last look: a new generation.
        let mut seen = std::mem::take(&mut self.mp_mut().affinity_mut().usable_seen);
        let grew = self
            .atts
            .iter()
            .any(|a| class.usable(a) && !seen.contains(&a.id()));
        seen.clear();
        seen.extend(self.atts.iter().filter(|a| class.usable(a)).map(|a| a.id()));
        let mp = self.mp_mut().affinity_mut();
        mp.usable_seen = seen;
        if grew {
            mp.usable_epoch += 1;
            mp.bindings_stale = true;
        }
        let epoch = mp.usable_epoch;
        // Nothing to re-evaluate: no provisional binding to firm up, no
        // scheduled one older than the usable pipes (one with a move
        // decided waits for it anyway), and no pipe in a less-preferred
        // tier to move up from.
        let stale = all_sampled && mp.bindings_stale;
        if !provisional && !stale && self.atts.iter().all(|a| a.send_tier() <= top) {
            if all_sampled {
                self.rebalance_bulk(class);
            }
            return;
        }
        if all_sampled {
            self.mp_mut().affinity_mut().bindings_stale = false;
        }
        let sb = self.session_send_buffer();
        for u in 0..self.streams.queue().levels().len() {
            for i in 0..self.streams.queue().level(u).len() {
                let key = self.streams.queue().level(u)[i];
                if !matches!(self.policy_for(key), Policy::Affinity) {
                    continue;
                }
                let Some(b) = self
                    .streams
                    .send(key)
                    .and_then(|s| s.mp().bound)
                    .filter(|b| b.move_to.is_none())
                else {
                    continue;
                };
                let stale = all_sampled && b.epoch < epoch;
                let target = if (provisional && b.provisional) || stale {
                    self.binding_choice(key, sb)
                } else {
                    let tier = self.att(b.pipe).map_or(top, Attachment::send_tier);
                    if tier <= top {
                        continue;
                    }
                    // Up only, to a tier that passes the test.
                    self.passing_tier(key, sb)
                        .filter(|&t| t < tier)
                        .and_then(|t| self.binding_pipe(key, sb, Some(t)))
                };
                if let Some(send) = self.streams.send_mut(key) {
                    send.mp_mut().bound = Some(Binding {
                        provisional: false,
                        epoch: if stale { epoch } else { b.epoch },
                        move_to: target.filter(|&t| t != b.pipe),
                        ..b
                    });
                }
            }
        }
        if all_sampled {
            self.rebalance_bulk(class);
        }
    }

    /// Whether a stream direction counts as bulk for `affinity`: expected
    /// bytes of at least 256 KiB, and not urgent.
    fn is_bulk(&self, send: &SendPart) -> bool {
        self.expected_bytes(send) >= SMALL_STREAM && send.priority.urgency() > 2
    }

    /// Fair shares for bulk `affinity` directions: a bulk direction never
    /// reaches an idle point, so a binding made with poor estimates (a new
    /// pipe has no rate sample) would be permanent. At most once per
    /// interval, bulk directions move, through the idle point the sender
    /// creates, from the pipe where each gets the smallest share of
    /// capacity (R_p / n_p) to the one where it would get the largest
    /// (R_q / (n_q + 1)) while that is at least 25 % more. A move to a
    /// less-preferred tier keeps a bulk direction on the donor pipe, so
    /// that the preferred tier stays fully used and only the excess goes
    /// down; a pipe without bulk directions (whose rate is not measured
    /// yet) takes one per interval.
    fn rebalance_bulk(&mut self, class: Class) {
        let now = self.now;
        if self.mp().affinity().rebalance_at.is_some_and(|t| now < t) {
            return;
        }
        let rtt_max = self
            .atts
            .iter()
            .filter(|a| class.usable(a))
            .filter_map(|a| a.out())
            .map(|o| o.est().srtt)
            .max()
            .unwrap_or_default();
        self.mp_mut().affinity_mut().rebalance_at = Some(now + REBALANCE.max(rtt_max * 4));
        // (pipe, tier, rate, bulk directions, took one this round).
        let mut pipes = std::mem::take(&mut self.mp_mut().affinity_mut().rebalance_scratch);
        pipes.clear();
        // A pipe whose rate was never measured as a bottleneck (only
        // application-limited samples, or none) counts with the best rate of
        // its tier, so that it gets a bulk direction that measures it.
        let best = |tier: u64| {
            self.atts
                .iter()
                .filter(|a| class.usable(a) && a.send_tier() == tier)
                .filter_map(|a| a.out())
                .map(|o| o.est().rate)
                .max()
                .unwrap_or(1)
        };
        pipes.extend(
            self.atts
                .iter()
                .filter(|a| class.usable(a))
                .filter_map(|a| {
                    let o = a.out()?;
                    let tier = a.send_tier();
                    let rate = if o.est().rate_measured {
                        o.est().rate
                    } else {
                        o.est().rate.max(best(tier))
                    };
                    Some((a.id(), tier, rate.max(1), 0u64, false))
                }),
        );
        for k in self.streams.queue().keys() {
            if !matches!(self.policy_for(k), Policy::Affinity) {
                continue;
            }
            let Some(send) = self.streams.send(k) else {
                continue;
            };
            if let Some(b) = send.mp().bound.filter(|_| self.is_bulk(send))
                && let Some(p) = pipes
                    .iter_mut()
                    .find(|p| p.0 == b.move_to.unwrap_or(b.pipe))
            {
                p.3 += 1;
            }
        }
        let share = |rate: u64, n: u64| rate as f64 / n.max(1) as f64;
        // The pipe whose bulk directions get the smallest share.
        let donor = |pipes: &[(u64, u64, u64, u64, bool)]| {
            (0..pipes.len())
                .filter(|&i| pipes[i].3 > 0)
                .min_by(|&i, &j| {
                    share(pipes[i].2, pipes[i].3).total_cmp(&share(pipes[j].2, pipes[j].3))
                })
        };
        while let Some(d) = donor(&pipes) {
            let from = share(pipes[d].2, pipes[d].3);
            let Some(r) = (0..pipes.len())
                .filter(|&i| i != d && !pipes[i].4)
                .filter(|&i| pipes[i].1 <= pipes[d].1 || pipes[d].3 >= 2)
                .max_by(|&i, &j| {
                    share(pipes[i].2, pipes[i].3 + 1).total_cmp(&share(pipes[j].2, pipes[j].3 + 1))
                })
            else {
                break;
            };
            if share(pipes[r].2, pipes[r].3 + 1) < from * REBALANCE_GAIN {
                break;
            }
            let (donor, receiver) = (pipes[d].0, pipes[r].0);
            let mover = self.streams.queue().keys().find(|&k| {
                matches!(self.policy_for(k), Policy::Affinity)
                    && self.streams.send(k).is_some_and(|s| {
                        self.is_bulk(s)
                            && s.mp()
                                .bound
                                .is_some_and(|b| b.pipe == donor && b.move_to.is_none())
                    })
            });
            let Some(key) = mover else {
                break;
            };
            if let Some(b) = self
                .streams
                .send_mut(key)
                .and_then(|s| s.mp_mut().bound.as_mut())
            {
                b.move_to = Some(receiver);
            }
            pipes[d].3 -= 1;
            if pipes[r].3 == 0 {
                pipes[r].4 = true;
            }
            pipes[r].3 += 1;
        }
        self.mp_mut().affinity_mut().rebalance_scratch = pipes;
    }

    /// The expected bytes E of a stream direction: what the
    /// application has written and not yet committed to a pipe, and at
    /// least its stream send buffer limit
    /// while a write on it waits for send-buffer space. A bulk writer thus
    /// counts with a whole stream buffer even when the fair share of the
    /// session buffer gives it less (with 16 bulk streams each holds a
    /// sixteenth, which would make every one look small and bind all of
    /// them to the lowest-delay pipe).
    fn expected_bytes(&self, send: &SendPart) -> u64 {
        Expected::of(send).bytes(self.session_send_buffer())
    }

    /// The most-preferred tier whose binding wait (Q_t + A_t) / R_t is at
    /// most the overflow delay for a stream direction, with
    /// the session send buffer `sb` in force.
    fn passing_tier(&self, key: StreamKey, sb: u64) -> Option<u64> {
        let d = self.overflow_delay().as_secs_f64();
        let views = self.views();
        let ledger = self.ledger()?;
        views.tiers().iter().map(|t| t.priority).find(|&tier| {
            let (mut wait, mut rate) = (0u64, 0u64);
            for &i in views.pipes(views.tier(tier).expect("listed")) {
                let a = self.atts.at(i);
                if let Some(o) = a.out() {
                    wait = wait
                        .saturating_add(Self::queued(o))
                        .saturating_add(ledger.load(a.id(), key, sb));
                    rate = rate.saturating_add(o.est().rate.max(1));
                }
            }
            wait as f64 / rate as f64 <= d
        })
    }

    /// The pipe an `affinity` stream direction binds to:
    /// within the most-preferred tier that passes the binding wait test,
    /// the smallest OWD + (Q + A + expected) / R, or the smallest OWD for
    /// small and urgent directions. When no tier passes, small and urgent
    /// directions bind in the most-preferred tier, and the others where
    /// they get the largest share of capacity over all usable tiers, so
    /// that bulk directions spread in proportion to capacity and share it
    /// fairly; such a binding is never moved for lack of room. `sb` is the
    /// session send buffer in force.
    fn binding_choice(&self, key: StreamKey, sb: u64) -> Option<u64> {
        let tier = self.passing_tier(key, sb);
        self.binding_pipe(key, sb, tier)
    }

    /// The pipe within `tier` (or, `None`, the fallback when no tier
    /// passes) for a stream direction.
    fn binding_pipe(&self, key: StreamKey, sb: u64, tier: Option<u64>) -> Option<u64> {
        let send = self.streams.get(key)?.send.as_ref()?;
        let expected = Expected::of(send).bytes(sb);
        let small = expected < SMALL_STREAM || send.priority.urgency() <= 2;
        let views = self.views();
        let ledger = self.ledger()?;
        let within = match tier {
            Some(t) => views.tier(t).map(|t| views.pipes(t)),
            None if small => views.tiers().first().map(|t| views.pipes(t)),
            None => Some(views.usable()),
        };
        within?
            .iter()
            .filter_map(|&i| {
                let a = self.atts.at(i);
                let o = a.out()?;
                let mut score = views.owd(o).as_secs_f64();
                if !small {
                    let load = Self::queued(o)
                        .saturating_add(ledger.load(a.id(), key, sb))
                        .saturating_add(expected);
                    score += load as f64 / o.est().rate.max(1) as f64;
                }
                Some((score, a.id()))
            })
            .min_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)))
            .map(|(_, id)| id)
    }

    /// `spread-eta`.
    fn spread_eta_ok(&self, d: &Decision, send: &SendPart) -> bool {
        let Some(gate) = d.gate else {
            return false;
        };
        let ready = send.buf.len() + send.preamble_left as u64;
        let whole = self.config.spread_chunk as u64;
        let chunk = whole.min(ready).max(1);
        // f: the pipe of the tier with the smallest ETA.
        let (fid, p, f) = if chunk == whole {
            let (p, f) = self.decision_etas(d);
            (d.fastest, p, f)
        } else {
            let fid = self.fastest_in(&gate, d.tier, chunk);
            (fid, self.eta_of(d.id), fid.and_then(|f| self.eta_of(f)))
        };
        let Some(fid) = fid else {
            return false;
        };
        if fid == d.id {
            return true;
        }
        let (Some(p), Some(f)) = (p, f) else {
            return false;
        };
        let eta_p = p.of(chunk);
        if eta_p <= f.of(chunk) {
            // A tie goes to the pipe with the write opportunity (step 1):
            // equal pipes share a stream instead of one waiting for ECF
            // and BLEST.
            return true;
        }
        // ECF with the backlog f carries before this direction's last ready
        // byte.
        let u = send.priority.urgency();
        let ready = ready.min(send.max_data.saturating_sub(send.offset));
        let share = self.round_robin_share(send).then_some(ready);
        let (backlog, beta) = self.ecf_backlog(d, u, share, chunk);
        if eta_p > (1.0 + beta) * f.of(backlog + chunk) {
            return false;
        }
        // BLEST: the fast pipe must not stall on the window meanwhile.
        let stream_room = send.max_data.saturating_sub(send.offset);
        let n = if self.config.hooks.no_blest_share || !send.priority.incremental() {
            1
        } else {
            self.ledger().map_or(1, |l| l.sharers(u)).max(1)
        };
        self.blest_ok(d, f, eta_p, stream_room, n)
    }

    /// Whether ECF counts the round robin's share of a direction's level
    /// rather than all of it: an incremental direction, which the level
    /// serves in turns.
    fn round_robin_share(&self, send: &SendPart) -> bool {
        send.priority.incremental() && !self.config.hooks.no_ecf_share
    }

    /// BLEST: the fast pipe `f` does not stall on
    /// the window while a chunk arrives at `eta_p` over the slower pipe.
    /// All of F = R_f x (ETA_p - OWD_f) must fit the session's credit and
    /// the reorder budget; the stream's own credit takes F / n, its share
    /// of f among the `n` directions of its level served in turns.
    fn blest_ok(&self, d: &Decision, f: Eta, eta_p: f64, stream_room: u64, n: u64) -> bool {
        let need = f.estimate as f64 * (eta_p - f.owd).max(0.0);
        need <= self.blest_room(d) as f64 && need / n as f64 <= stream_room as f64
    }

    /// W of BLEST but for the stream's credit: the smaller of the session's
    /// remaining send credit and the reorder budget.
    fn blest_room(&self, d: &Decision) -> u64 {
        let session_room = self.streams.send_flow().room();
        session_room.min(*d.reorder.get_or_init(|| self.reorder_budget()))
    }

    /// Whether `spread-eta` puts the directions of urgency `u` with a whole
    /// chunk ready within stream credit, `key` one of them, on the
    /// decision's pipe: `Some` when it decides alike for all of them, `None`
    /// when only some go. ECF's backlog grows with a direction's ready data
    /// (at least a chunk here, at most all of the level), and BLEST's
    /// stream term takes F / n <= F against a stream credit of at least a
    /// chunk; the other conditions are the same for all.
    fn whole_chunk_on(&self, d: &Decision, key: StreamKey) -> Option<bool> {
        let whole = self.config.spread_chunk as u64;
        let send = self.streams.get(key)?.send.as_ref()?;
        let (Some(fid), (Some(p), Some(f))) = (d.fastest, self.decision_etas(d)) else {
            return Some(self.stream_on_pipe(d, key));
        };
        let eta_p = p.of(whole);
        if fid == d.id || eta_p <= f.of(whole) {
            return Some(true);
        }
        let u = send.priority.urgency();
        let ecf = |share: Option<u64>| {
            let (backlog, beta) = self.ecf_backlog(d, u, share, whole);
            eta_p <= (1.0 + beta) * f.of(backlog + whole)
        };
        // The largest backlog: all of the level.
        if !ecf(None) {
            return Some(false);
        }
        let need = f.estimate as f64 * (eta_p - f.owd).max(0.0);
        let w = self.blest_room(d);
        if need > w as f64 {
            Some(false)
        } else if need <= w.min(whole) as f64
            && (self.config.hooks.no_ecf_share || ecf(Some(whole)))
        {
            // The smallest backlog passes too.
            Some(true)
        } else {
            None
        }
    }

    /// The ECF backlog B before a chunk of `len` bytes of urgency `u`, and
    /// beta: min(session send credit, U + the
    /// level's part) - len, where U is the ready data of the more urgent
    /// levels and the level's part is, for a direction served in turns with
    /// `share` = Some(r) bytes ready, the sum over the level of min(ready_j,
    /// r), else all ready data of the level. Urgency 0 to 2 counts only the
    /// more urgent levels: min(session send credit, U), beta 0.
    fn ecf_backlog(&self, d: &Decision, u: u8, share: Option<u64>, len: u64) -> (u64, f64) {
        if u <= 2 {
            return (self.backlog_of(d, (u, None, 0)), 0.0);
        }
        (self.backlog_of(d, (u, share, len)), BETA)
    }

    /// [`Self::ecf_backlog`]'s B, remembered within the decision.
    fn backlog_of(&self, d: &Decision, key: Backlog) -> u64 {
        let mut memo = d.backlogs.get();
        if let Some(&(_, b)) = memo.iter().flatten().find(|(k, _)| *k == key) {
            return b;
        }
        let (u, share, len) = key;
        let b = self.ledger().map_or(0, |l| {
            let more_urgent = l.ready_below(usize::from(u));
            let level = match share {
                _ if u <= 2 => 0,
                Some(r) => l.ready_capped(u, r),
                None => l.ready_at(u),
            };
            more_urgent
                .saturating_add(level)
                .min(self.streams.send_flow().room())
                .saturating_sub(len)
        });
        if let Some(free) = memo.iter_mut().find(|m| m.is_none()) {
            *free = Some((key, b));
            d.backlogs.set(memo);
        }
        b
    }

    /// The reorder budget.
    pub(super) fn reorder_budget(&self) -> u64 {
        let session_room = self.streams.send_flow().room();
        // The rate of every live pipe, the delay spread of those that take
        // new data, whatever their tier.
        let mut sum_rate = 0u64;
        let mut min_owd: Option<Duration> = None;
        let mut max_owd = Duration::ZERO;
        for o in self
            .atts
            .iter()
            .filter_map(|a| a.out())
            .filter(|o| o.is_live())
        {
            sum_rate = sum_rate.saturating_add(o.est().rate);
            if o.takes_new_data() {
                let d = self.owd(o);
                min_owd = Some(min_owd.map_or(d, |m| m.min(d)));
                max_owd = max_owd.max(d);
            }
        }
        let spread = max_owd.saturating_sub(min_owd.unwrap_or_default());
        let budget = 2.0 * sum_rate as f64 * spread.as_secs_f64() + self.config.spread_chunk as f64;
        session_room.min(budget as u64)
    }

    /// Whether a stream direction has a round-robin policy of its own (its
    /// own current values), rather than the session's.
    fn own_round_robin(&self, key: StreamKey) -> bool {
        self.streams.send(key).is_some_and(|s| {
            matches!(
                s.mp().scheduler,
                Some(Policy::SpreadRoundRobin | Policy::SpreadRateWeighted)
            )
        })
    }

    /// The weights of the round-robin engine:
    /// Weight for `spread-round-robin`, Weight x R_q for
    /// `spread-rate-weighted`.
    fn rr_weights<'a>(
        &'a self,
        key: StreamKey,
        gate: &Gate,
        tier: u64,
    ) -> impl Iterator<Item = (u64, f64)> + 'a {
        let by_rate = matches!(self.policy_for(key), Policy::SpreadRateWeighted);
        let off = self.config.hooks.no_placement_rate;
        self.weighted_candidates(gate, tier)
            .map(move |(a, o, w)| (a.id(), Self::rr_weight(&self.atts, a, o, w, by_rate, off)))
    }

    /// A candidate's round-robin weight, as an f64: a weight times a rate
    /// in bytes per second may exceed a u64. Values above 2^53 round to a
    /// relative error of 2^-53, which only perturbs the shares that much;
    /// the engine stays smooth, since it only adds, subtracts and compares.
    /// The rate is the placement rate.
    fn rr_weight(
        atts: &Attachments,
        a: &Attachment,
        o: &OutPipe,
        w: u64,
        by_rate: bool,
        off: bool,
    ) -> f64 {
        let w = w as f64;
        if by_rate {
            w * placement_rate(atts, a, o, off).max(1) as f64
        } else {
            w
        }
    }

    /// The current value of a pipe in the round-robin instance a stream
    /// direction uses.
    fn rr_current(&self, key: StreamKey, own: bool, pipe: u64) -> f64 {
        if own {
            self.streams
                .send(key)
                .and_then(|s| s.mp().rr.iter().find(|e| e.0 == pipe))
                .map_or(0.0, |e| e.1)
        } else {
            self.out_ref(pipe).map_or(0.0, OutPipe::rr_current)
        }
    }

    /// The pipe the round-robin gives the next chunk among the candidates
    /// of a tier: the largest current value plus weight, the lowest ID on a
    /// tie.
    fn round_robin_pick(&self, key: StreamKey, gate: &Gate, tier: u64) -> Option<u64> {
        let own = self.own_round_robin(key);
        self.rr_weights(key, gate, tier)
            .map(|(id, w)| (self.rr_current(key, own, id) + w, id))
            .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)))
            .map(|(_, id)| id)
    }

    /// A chunk of `key` went to `pipe` under a round-robin policy: every
    /// candidate of the pipe's tier gains its weight and the chosen one
    /// gives up the sum; pipes that were not candidates gain nothing, and
    /// a pipe that is not eligible starts from 0 when it is again.
    pub(super) fn round_robin_commit(&mut self, pipe: u64, key: StreamKey, gate: &Gate) {
        let Some(tier) = self.att(pipe).map(Attachment::send_tier) else {
            return;
        };
        let own = self.own_round_robin(key);
        let by_rate = matches!(self.policy_for(key), Policy::SpreadRateWeighted);
        let all_zero = self.weights_all_zero(gate, tier);
        let off = self.config.hooks.no_placement_rate;
        let weight = |atts: &Attachments, a: &Attachment| {
            let w = Self::candidate_weight(gate, tier, a, all_zero)?;
            Some(Self::rr_weight(atts, a, a.out()?, w, by_rate, off))
        };
        let sum: f64 = self.atts.iter().filter_map(|a| weight(&self.atts, a)).sum();
        // The change of every pipe's current value: `None` for a pipe that
        // is not eligible, which starts from 0 when it is again.
        let delta = |atts: &Attachments, a: &Attachment| {
            gate.admits(a).then(|| {
                let w = weight(atts, a).unwrap_or(0.0);
                if a.id() == pipe { w - sum } else { w }
            })
        };
        if !own {
            for i in 0..self.atts.len() {
                let d = delta(&self.atts, self.atts.at(i));
                if let Some(o) = self.atts.at_mut(i).out_mut() {
                    o.rr_step(d);
                }
            }
            return;
        }
        let atts = &self.atts;
        let Some(send) = self.streams.send_mut(key) else {
            return;
        };
        let rr = &mut send.mp_mut().rr;
        // Pipes gone or not eligible drop out.
        rr.retain(|e| atts.iter().any(|a| a.id() == e.0 && gate.admits(a)));
        for a in atts {
            let Some(d) = delta(atts, a) else { continue };
            match rr.iter_mut().find(|e| e.0 == a.id()) {
                Some(e) => e.1 += d,
                None if d != 0.0 => rr.push((a.id(), d)),
                None => {}
            }
        }
    }

    /// Discards the session's round-robin state (a policy change).
    pub(super) fn reset_round_robin(&mut self) {
        for o in self.atts.outs_mut() {
            o.rr_step(None);
        }
    }

    /// Whether the chunk of a custom-policy direction goes on the
    /// decision's pipe: per its answer while that is current, else (a
    /// stale or invalid answer) the `affinity` choice; without an answer
    /// the decision is requested from the driver. The policy sees every
    /// pipe that may carry new data with the gate's view and may override
    /// the gate, not rule S1.
    fn custom_ok(&self, d: &Decision, key: StreamKey) -> bool {
        let id = d.id;
        let Some(send) = self.streams.send(key) else {
            return false;
        };
        let mp = self.mp().picks();
        // A custom policy may override the tiers, not rule S1: a JOINING
        // pipe takes no new data while another pipe is usable.
        let may_carry = || {
            d.gate
                .is_some_and(|g| self.att(id).is_some_and(|a| g.class().usable(a)))
        };
        // A sticky answer holds only while its pipe exists and takes new
        // data.
        let holds = |pipe: u64| self.out_ref(pipe).is_some_and(|o| o.takes_new_data());
        match send.mp().picked {
            Some(Picked::Pipe {
                pipe, generation, ..
            }) if generation == mp.generation && holds(pipe) => pipe == id && may_carry(),
            Some(Picked::Wait { generation, epoch })
                if generation == mp.generation && epoch == mp.input_epoch =>
            {
                false
            }
            Some(Picked::Pipe { .. } | Picked::Affinity) => {
                // A stale answer: this chunk goes by `affinity`.
                d.usable && self.affinity_target(key, d) == Some(id)
            }
            Some(Picked::Wait { .. }) | None => {
                // Joins the next call (the one under way already asks for
                // the directions it carries).
                if self
                    .streams
                    .get(key)
                    .is_some_and(|s| !s.pick_queued.replace(true))
                {
                    mp.pending.borrow_mut().push(key);
                }
                false
            }
        }
    }

    /// A policy change of direction `only`, or
    /// of every direction that follows the session's policy: their custom
    /// answers are discarded, not counted as misses, and so is the call
    /// under way, whole (its answers find nothing to apply to when they
    /// come back); a direction still under a custom policy is asked again.
    pub(super) fn reset_picks(&mut self, only: Option<StreamKey>) {
        let Some(mp) = self.mp.as_deref_mut().map(Mp::picks_mut) else {
            return;
        };
        for k in mp.out.drain(..) {
            if let Some(s) = self.streams.get(k) {
                s.pick_queued.set(false);
            }
        }
        let streams = &mut self.streams;
        let affected = |streams: &mut super::streams::Streams, k: StreamKey| {
            let Some(send) = streams.send_mut(k) else {
                return true;
            };
            let follows = match only {
                Some(x) => x == k,
                None => send.mp().scheduler.is_none(),
            };
            if follows {
                send.mp_mut().picked = None;
            }
            follows
        };
        mp.pending.get_mut().retain(|&k| {
            let drop = affected(streams, k);
            if drop && let Some(s) = streams.get(k) {
                s.pick_queued.set(false);
            }
            !drop
        });
        mp.picked.retain(|&k| !affected(streams, k));
        if let Some(k) = only
            && let Some(send) = self.streams.send_mut(k)
        {
            send.mp_mut().rr.clear();
        }
    }

    /// A direction no longer waits for a custom decision.
    fn unqueue_pick(&self, key: StreamKey) {
        if let Some(s) = self.streams.get(key) {
            s.pick_queued.set(false);
        }
    }

    /// Whether custom decisions wait for the driver.
    pub fn wants_pick(&self) -> bool {
        self.mp
            .as_deref()
            .map(Mp::picks)
            .is_some_and(|p| !p.pending.borrow().is_empty() && p.out.is_empty())
    }

    /// Hands the driver every stream direction waiting for a custom
    /// decision, with a value-only view of the pipes, copied into `req`
    /// (no handle, nothing that leads back to the session). Returns `false`
    /// when none waits.
    pub fn take_pick(&mut self, req: &mut PickRequest) -> bool {
        if !self.wants_pick() {
            return false;
        }
        let pending = std::mem::take(&mut *self.mp().picks().pending.borrow_mut());
        let Some(gate) = self.gate() else {
            // Nothing can carry data: the directions ask again when
            // something can.
            for &key in &pending {
                self.unqueue_pick(key);
            }
            return false;
        };
        req.frames.clear();
        req.keys.clear();
        req.answers.clear();
        req.panicked = false;
        req.policy = None;
        for key in pending {
            let Some(Policy::Custom(policy)) = self.streams.get(key).map(|_| self.policy_for(key))
            else {
                self.unqueue_pick(key);
                continue;
            };
            // One policy per call: directions with another wait for the
            // next one.
            if req.policy.as_ref().is_some_and(|p| !Arc::ptr_eq(p, policy)) {
                self.mp().picks().pending.borrow_mut().push(key);
                continue;
            }
            let policy = policy.clone();
            let Some(s) = self.streams.get(key) else {
                continue;
            };
            let Some(send) = s.send.as_ref() else {
                self.unqueue_pick(key);
                continue;
            };
            req.frames.push(FrameInfo {
                stream: s.id,
                urgency: send.priority.urgency(),
                len: send.buf.len(),
                last_pipe: send.mp().bound.map(|b| PipeId(b.pipe)),
                eligible_tier: Some(gate.top()),
            });
            req.keys.push(key);
            req.policy = Some(policy);
        }
        if req.keys.is_empty() {
            return false;
        }
        req.pipes.clear();
        let class = gate.class();
        req.pipes.extend(self.atts.iter().filter_map(|a| {
            // The usable pipes: not a JOINING one while another is usable
            // (rule S1, MULTIPATH.md Section 11).
            let o = a.out().filter(|o| o.takes_new_data() && class.usable(a))?;
            Some(PipeSnapshot {
                pipe: PipeId(a.id()),
                state: o.public_state(),
                srtt: o.est().srtt,
                rttvar: o.est().rttvar,
                rate: o.est().rate,
                unsent: o.carrier_unsent(),
                in_flight: o.in_flight(),
                writable: o.writable(),
                priority: a.send_tier(),
                standby: a.standby(),
                saturated: gate.saturated(a.send_tier()).unwrap_or(false),
                probation: o.in_probation(),
                eligible: gate.admits(a),
                weight: a.tier().weight(),
            })
        }));
        let generation = self.mp().picks().generation;
        req.generation = generation;
        let mp = self.mp_mut().picks_mut();
        mp.out.clear();
        mp.out.extend_from_slice(&req.keys);
        mp.out_gen = generation;
        true
    }

    /// Applies the answers of `req` if its view is still current;
    /// otherwise (and for an invalid answer or a panic) the next chunk of
    /// each direction takes the `affinity` choice and the miss is counted,
    /// with no retry.
    pub fn answer_pick(&mut self, req: &PickRequest) {
        let Some(mp) = self.mp.as_deref_mut().map(Mp::picks_mut) else {
            return;
        };
        if mp.out.is_empty() {
            return;
        }
        mp.out.clear();
        let current = mp.out_gen == req.generation && req.generation == mp.generation;
        let epoch = mp.input_epoch;
        let generation = req.generation;
        for (i, &key) in req.keys.iter().enumerate() {
            self.unqueue_pick(key);
            let answer = if req.panicked {
                None
            } else {
                req.answers.get(i).copied()
            };
            let picked = match answer {
                Some(PickAnswer::Pipe { index, bytes }) if current => req
                    .pipes
                    .get(index)
                    .filter(|p| {
                        self.atts.iter().any(|a| {
                            a.id() == p.pipe.0 && a.out().is_some_and(|o| o.takes_new_data())
                        })
                    })
                    .map_or(Picked::Affinity, |p| Picked::Pipe {
                        pipe: p.pipe.0,
                        generation,
                        left: (bytes > 0).then_some(bytes),
                    }),
                Some(PickAnswer::Wait) if current => Picked::Wait { generation, epoch },
                _ => Picked::Affinity,
            };
            let mp = self.mp_mut().picks_mut();
            match picked {
                Picked::Affinity => mp.fallbacks.set(mp.fallbacks.get() + 1),
                Picked::Pipe { .. } => mp.applied += 1,
                Picked::Wait { .. } => {}
            }
            let Some(send) = self.streams.send_mut(key) else {
                continue;
            };
            let fresh = send.mp_mut().picked.replace(picked).is_none();
            if fresh {
                self.mp_mut().picks_mut().picked.push(key);
            }
        }
    }

    /// The custom-policy view no longer applies: sticky answers become misses.
    pub(super) fn advance_pick_generation(&mut self) {
        self.views_changed();
        let Some(mp) = self.mp.as_deref_mut().map(Mp::picks_mut) else {
            return;
        };
        mp.generation += 1;
        let picked = std::mem::take(&mut mp.picked);
        let mut misses = 0;
        for &k in &picked {
            if let Some(send) = self.streams.send_mut(k)
                && matches!(send.mp().picked, Some(Picked::Pipe { .. }))
            {
                send.mp_mut().picked = Some(Picked::Affinity);
                misses += 1;
            }
        }
        let mp = self.mp_mut().picks_mut();
        mp.fallbacks.set(mp.fallbacks.get() + misses);
        mp.picked = picked;
    }

    /// An input arrived: "wait" answers expire.
    pub(super) fn pick_input(&mut self) {
        if let Some(mp) = self.mp.as_deref_mut() {
            mp.picks_mut().input_epoch += 1;
        }
    }

    /// The retransmit budget.
    pub(super) fn retransmit_budget(&self) -> u64 {
        let Some(mp) = self.mp.as_deref() else {
            return u64::MAX;
        };
        let mad = mp.peer_mad();
        let mut sum = 0.0;
        for a in &self.atts {
            if let Some(o) = a.out().filter(|o| o.is_live()) {
                sum += o.est().rate as f64 * (o.est().srtt + mad).as_secs_f64();
            }
        }
        let budget = (4.0 * sum) as u64;
        // Capped by the `max` of `send_buffer` (no fixed cap).
        let max = self
            .send_buffer_limit()
            .max(self.config.send_buffer)
            .max(1 << 20);
        budget.clamp(1 << 20, max)
    }
}

#[cfg(test)]
pub(super) mod tests;
