//! Executes the [`Shaper`]s of the outbound pipes within the protocol's
//! limits and the session's [`Limits`]. Nothing here exists until a
//! factory, an instance or something to meter is set: the paths that
//! consult it test `SessionCore::shape` for `None`.
//!
//! While a batch is built the state moves into the batch's [`Records`]
//! ([`ShapeTx`]) and comes back when the batch ends; stream events of that
//! time wait in `SessionCore::shape_pending`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::output::Records;
use super::pipes::Attachment;
use super::shape_account::{TokenBucket, WireAccount};
use super::shape_ledger::Dispatch;
use super::shaping::{
    Budget, Caps, DatagramPlan, DatagramView, Effects, Event, EventKind, Factory, Injection,
    JoinDispatch, JoinUnit, Limits, MAX_ACCOUNT_RATE, Meters, RecordPlan, RecordView, RecordWire,
    RuntimeReason, ShapedPipe, Shaper, Stats, UnitKind, UnitPlan, burst_floor,
};
use super::transmit::{CoverWrite, ShapeWrite};
use super::{CarrierKind, LaneId, PipeId, SessionCore, State, TransmitBuf};

/// Backs PADDING frames (0x00 bytes).
static ZERO: [u8; 65535] = [0; 65535];

/// Minimum increment when rearming a wake at the current clock instant.
const GRANULARITY_US: u64 = 1_000;

pub(crate) struct Shaping {
    factory: Option<Arc<dyn Factory>>,
    /// Bumped by `set_shaper`: an instance of an older one is replaced.
    generation: u64,
    next_instance: u64,
    /// The local limits under the budget.
    limits: Limits,
    account: WireAccount,
    /// The session's bytes earned, as of the last batch.
    earn: u64,
    pub(super) stats: Stats,
    pipes: Vec<PipeShape>,
    /// Time 0 of the session clock shapers see.
    base: Instant,
}

impl std::fmt::Debug for Shaping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shaping")
            .field("generation", &self.generation)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// The shaping state of one outbound pipe.
struct PipeShape {
    pipe: u64,
    generation: u64,
    instance: u64,
    /// `None`: not shaped.
    shaper: Option<Box<dyn Shaper>>,
    caps: Caps,
    seq: u64,
    /// The plan of the next record, once made.
    plan: Option<RecordPlan>,
    /// How that record's lengths convert.
    wire: RecordWire,
    delay_start: Option<Instant>,
    delay_prior: Duration,
    datagram_wait_until: Option<Instant>,
    record_wait: Duration,
    gate_wait: Duration,
    /// The planned record's earliest send time (`RecordPlan::delay`):
    /// until then the pipe sends nothing but `CONNECTION_CLOSE`, and the
    /// frames owed meanwhile wait in that record.
    delay_until: Option<Instant>,
    /// Stream data waits until then (a gate's pause).
    hold: Option<Instant>,
    /// The latest `pause_until` taken, whose pause is counted.
    paused_until: u64,
    /// Gates applied: a batch that sees it change takes the new gate's
    /// room.
    gates: u64,
    /// The rate as answered; the bucket holds the rate in force.
    rate_asked: u64,
    bucket: TokenBucket,
    /// Start of the current contiguous shaping gate interval.
    held_since: Option<u64>,
    inject: Option<Injection>,
    inject_due: bool,
    wake: Option<u64>,
    weight: Option<u32>,
}

impl PipeShape {
    fn new(pipe: u64, generation: u64) -> Self {
        Self {
            pipe,
            generation,
            instance: 0,
            shaper: None,
            caps: Caps::NONE,
            seq: 0,
            plan: None,
            wire: RecordWire::default(),
            delay_start: None,
            delay_prior: Duration::ZERO,
            datagram_wait_until: None,
            record_wait: Duration::ZERO,
            gate_wait: Duration::ZERO,
            delay_until: None,
            hold: None,
            paused_until: 0,
            gates: 0,
            rate_asked: 0,
            bucket: TokenBucket::default(),
            held_since: None,
            inject: None,
            inject_due: false,
            wake: None,
            weight: None,
        }
    }

    /// The bucket at `us`.
    fn bucket_at(&self, us: u64) -> TokenBucket {
        let mut b = self.bucket;
        b.fill(us);
        b
    }

    /// Whether the planned record waits for its delay: it has not passed,
    /// and `ack` (the deadline of a `PIPE_ACK` the record carries, see
    /// [`SessionCore::ack_release`]) has not either.
    fn delayed(&self, now: Instant, ack: Option<Instant>) -> bool {
        self.shaper.is_some()
            && self.plan.is_some()
            && self.delay_until.is_some_and(|t| now < t)
            && ack.is_none_or(|t| now < t)
    }

    fn held(&self, now: Instant, us: u64, max: Duration) -> bool {
        self.shaper.is_some()
            && !max.is_zero()
            && self
                .held_since
                .is_none_or(|start| Duration::from_micros(us.saturating_sub(start)) < max)
            && (self.hold.is_some_and(|h| now < h)
                || self.bucket.rate > 0 && self.bucket_at(us).held())
    }
}

impl Shaping {
    /// `H_p`: the longest the next pause may
    /// last; zero when none may or nothing bounds one.
    pub(super) fn hold_bound(&self) -> Duration {
        self.limits.max_added_delay()
    }

    /// `H_p` of `pipe`: [`Self::hold_bound`] for a
    /// pipe whose shaper plans its records, zero for any other.
    pub(super) fn probe_hold(&self, pipe: u64) -> Duration {
        let planned = self.index(pipe).is_some_and(|i| {
            let p = &self.pipes[i];
            p.shaper.is_some() && p.caps.contains(Caps::PLAN)
        });
        if planned {
            self.hold_bound()
        } else {
            Duration::ZERO
        }
    }

    pub(super) fn new(limits: Limits, base: Instant, now: Instant, earn: u64) -> Self {
        let mut account = WireAccount::default();
        let us = u64::try_from(now.saturating_duration_since(base).as_micros()).unwrap_or(u64::MAX);
        account.set(us, limits.wire);
        Self {
            factory: None,
            generation: 0,
            next_instance: 0,
            limits,
            account,
            earn,
            stats: Stats::default(),
            pipes: Vec::new(),
            base,
        }
    }

    /// Puts new limits in force; the account carries over.
    fn set_limits(&mut self, limits: Limits, now: Instant) {
        self.limits = limits;
        self.account.set(self.micros(now), limits.wire);
        for i in 0..self.pipes.len() {
            let p = &mut self.pipes[i];
            if limits.no_pause {
                p.hold = None;
                p.rate_asked = 0;
                p.bucket = TokenBucket::default();
                p.gates += 1;
                self.settle_held(i);
            } else if let Some(hold) = p.hold {
                let start = p
                    .held_since
                    .map_or(now, |us| later(self.base, Duration::from_micros(us)));
                p.hold = Some(
                    hold.min(later(start, limits.max_added_delay()))
                        .max(now.min(hold)),
                );
            }
            let p = &mut self.pipes[i];
            if let Some((start, until)) = p.delay_start.zip(p.delay_until) {
                let delay = bounded_delay(
                    limits,
                    until.saturating_duration_since(start),
                    p.delay_prior,
                );
                p.delay_until = Some(now.min(until).max(later(start, delay)));
            }
            if limits.no_padding
                && let Some(plan) = &mut p.plan
            {
                plan.pad_to = 0;
                plan.pad_multiple = 0;
                plan.pad = 0;
            }
        }
    }

    /// The session clock as last seen by the account.
    const fn account_now(&self) -> u64 {
        self.account.last_us
    }

    /// Finishes the gate's accumulated eligible stream wait.
    fn settle_held(&mut self, i: usize) -> Duration {
        self.pipes[i].held_since = None;
        let elapsed = std::mem::take(&mut self.pipes[i].gate_wait);
        self.stats.stall_spent = self.stats.stall_spent.saturating_add(elapsed);
        self.stats.max_added_delay = self.stats.max_added_delay.max(elapsed);
        elapsed
    }

    /// The session's readings at `us`.
    fn meters(&self, us: u64) -> Meters {
        let mut account = self.account;
        account.accrue(us, 0);
        let stall = u64::try_from(self.stats.stall_spent.as_micros()).unwrap_or(u64::MAX);
        let mut m = Meters::new(account.left(), u64::MAX, account.spent, self.earn);
        m.stall_spent = stall;
        m
    }

    /// `now` on the session clock.
    fn micros(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.base).as_micros()).unwrap_or(u64::MAX)
    }

    /// The instant of time `t` of the session clock.
    fn instant(&self, t: u64) -> Instant {
        later(self.base, Duration::from_micros(t))
    }

    fn index(&self, pipe: u64) -> Option<usize> {
        self.pipes.iter().position(|p| p.pipe == pipe)
    }

    /// The index of `pipe`'s active state, installing the factory's
    /// instance when it has none of the current generation.
    pub(super) fn active(
        &mut self,
        shaped: &ShapedPipe,
        now: Instant,
        record: usize,
    ) -> Option<usize> {
        let pipe = shaped.id.0;
        let i = match self.index(pipe) {
            Some(i) if self.pipes[i].generation == self.generation => i,
            _ => {
                let x = self.factory.clone().and_then(|f| {
                    catch_unwind(AssertUnwindSafe(|| f.shaper(shaped))).unwrap_or_else(|_| {
                        self.stats.faults += 1;
                        None
                    })
                });
                self.install(pipe, x, now, record)
            }
        };
        self.pipes[i].shaper.is_some().then_some(i)
    }

    fn install(
        &mut self,
        pipe: u64,
        x: Option<Box<dyn Shaper>>,
        now: Instant,
        record: usize,
    ) -> usize {
        let i = if let Some(i) = self.index(pipe) {
            let e = Event::new(EventKind::Replaced, PipeId(pipe), self.micros(now));
            self.event(i, e, record);
            self.settle_held(i);
            let p = &self.pipes[i];
            let elapsed = p.record_wait;
            let carried = p.delay_prior.saturating_add(elapsed);
            self.stats.stall_spent = self.stats.stall_spent.saturating_add(elapsed);
            self.stats.max_added_delay = self.stats.max_added_delay.max(carried);
            self.pipes[i] = PipeShape::new(pipe, self.generation);
            self.pipes[i].delay_prior = carried;
            i
        } else {
            self.pipes.push(PipeShape::new(pipe, self.generation));
            self.pipes.len() - 1
        };
        let Some(x) = x else {
            return i;
        };
        self.next_instance = self.next_instance.wrapping_add(1);
        self.pipes[i].instance = self.next_instance;
        self.pipes[i].shaper = Some(x);
        let mut caps = Caps::NONE;
        if self.call(i, |x| caps = x.capabilities()) {
            self.pipes[i].caps = caps;
            let e = Event::new(EventKind::Start, PipeId(pipe), self.micros(now));
            self.event(i, e, record);
        }
        i
    }

    /// Runs the instance; a panic ends shaping of the pipe.
    fn call(&mut self, i: usize, f: impl FnOnce(&mut dyn Shaper)) -> bool {
        let Some(x) = self.pipes[i].shaper.as_deref_mut() else {
            return false;
        };
        if catch_unwind(AssertUnwindSafe(|| f(x))).is_ok() {
            return true;
        }
        self.stats.faults += 1;
        let now = self.instant(self.account_now());
        self.stop(i, false, now);
        false
    }

    fn stop(&mut self, i: usize, notify: bool, now: Instant) {
        let p = &self.pipes[i];
        if p.shaper.is_none() {
            return;
        }
        let pipe = p.pipe;
        self.settle_held(i);
        if notify {
            let e = Event::new(EventKind::Stopped, PipeId(pipe), self.micros(now));
            self.call(i, |x| x.on_event(&e, &mut Effects::default()));
        }
        let (pipe, generation) = (self.pipes[i].pipe, self.pipes[i].generation);
        self.pipes[i] = PipeShape::new(pipe, generation);
    }

    /// Delivers a notification and applies the answer.
    fn event(&mut self, i: usize, mut e: Event, record: usize) {
        if self.pipes[i].caps.contains(Caps::BUDGET) {
            e.meters = self.meters(e.now);
        }
        let mut r = Effects::default();
        if !self.call(i, |x| x.on_event(&e, &mut r)) {
            return;
        }
        if !matches!(
            e.kind,
            EventKind::Replaced | EventKind::Stopped | EventKind::PipeFailed
        ) {
            self.apply(i, &r, self.instant(e.now), record, Some(e.kind));
        }
    }

    fn apply(
        &mut self,
        i: usize,
        r: &Effects,
        now: Instant,
        record: usize,
        origin: Option<EventKind>,
    ) {
        let us = self.micros(now);
        let p = &mut self.pipes[i];
        match r.inject {
            Some(Some(request)) if request.id != 0 && request.pad_bytes != 0 => {
                if matches!(origin, Some(EventKind::Outbound | EventKind::Timer)) {
                    p.inject = Some(request);
                    p.inject_due = request.at <= us;
                }
            }
            Some(_) => {
                p.inject = None;
                p.inject_due = false;
            }
            None => {}
        }
        if let Some(wake) = r.wake {
            p.wake = wake.map(|at| {
                if at <= us && origin != Some(EventKind::Start) {
                    us.saturating_add(GRANULARITY_US)
                } else {
                    at
                }
            });
        }
        if let Some(w) = r.weight.filter(|w| *w > 0) {
            p.weight = Some(w);
        }
        if let Some(g) = r.gate.filter(|_| !self.limits.no_pause) {
            let (burst, raised) = burst_floor(g.burst, record as u64);
            let rate = g.rate.min(MAX_ACCOUNT_RATE);
            let bound = self.limits.max_added_delay();
            let p = &mut self.pipes[i];
            let was_held = p.held(now, us, bound);
            let rated = p.rate_asked != rate || p.bucket.burst != burst.cast_signed();
            let paused = g.pause_until > p.paused_until && g.pause_until > us;
            if paused {
                p.paused_until = g.pause_until;
                let start = p.held_since.filter(|_| was_held).unwrap_or(us);
                let cap =
                    start.saturating_add(u64::try_from(bound.as_micros()).unwrap_or(u64::MAX));
                let until = g.pause_until.min(cap);
                p.hold = Some(later(now, Duration::from_micros(until.saturating_sub(us))));
                if until < g.pause_until {
                    self.stats.clamped += 1;
                    self.stats.runtime_reasons[RuntimeReason::PolicyDeadline as usize] += 1;
                }
                if !was_held {
                    p.held_since = Some(us);
                }
            }
            if rated {
                if raised && rate != 0 {
                    self.stats.clamped += 1;
                }
                p.rate_asked = rate;
                p.bucket.burst = burst.cast_signed();
                p.bucket.rate = rate;
                p.bucket.reset(us);
            }
            if paused || rated {
                p.gates += 1;
            }
        }
        if r.stop {
            self.stop(i, true, now);
        }
    }

    /// Bounds a pause by the limits; returns its end.
    fn pause(&mut self, asked: Duration, now: Instant, prior: Duration) -> Option<Instant> {
        let delay = bounded_delay(self.limits, asked, prior);
        if delay < asked {
            self.stats.clamped += 1;
            self.stats.runtime_reasons[RuntimeReason::PolicyDeadline as usize] += 1;
        }
        (!delay.is_zero()).then(|| later(now, delay))
    }

    fn max_added_delay(&self) -> Duration {
        self.pipes
            .iter()
            .map(|pipe| {
                pipe.delay_prior
                    .saturating_add(pipe.record_wait)
                    .max(pipe.gate_wait)
            })
            .fold(self.stats.max_added_delay, Duration::max)
    }

    pub(super) fn held(&self, pipe: u64, now: Instant) -> bool {
        let us = self.micros(now);
        self.index(pipe)
            .is_some_and(|i| self.pipes[i].held(now, us, self.limits.max_added_delay()))
    }

    pub(super) fn delayed(&self, pipe: u64, now: Instant, ack: Option<Instant>) -> bool {
        self.index(pipe)
            .is_some_and(|i| self.pipes[i].delayed(now, ack))
    }

    /// Whether `pipe` has an injection due.
    pub(super) fn inject_due(&self, pipe: u64) -> bool {
        self.index(pipe).is_some_and(|i| self.pipes[i].inject_due)
    }

    /// When a held pipe is released.
    fn release(&self, i: usize, now: Instant) -> Instant {
        let p = &self.pipes[i];
        let mut t = p.hold.unwrap_or(now);
        let us = self.micros(now);
        let b = p.bucket_at(us);
        if b.rate > 0 && b.held() {
            let at = b
                .release()
                .map_or_else(|| later(now, Duration::MAX), |x| self.instant(x));
            t = t.max(at);
        }
        if let Some(start) = p.held_since {
            t = t.min(later(self.instant(start), self.limits.max_added_delay()));
        }
        t.max(now)
    }

    /// The shaper weight of `pipe`: `None` when the pipe has no shaper, `Some(None)` when
    /// its shaper sets no weight.
    #[allow(
        clippy::option_option,
        reason = "no shaper and a shaper without a weight differ for the scheduler"
    )]
    pub(super) fn weight(&self, pipe: u64) -> Option<Option<u32>> {
        let p = &self.pipes[self.index(pipe)?];
        p.shaper.is_some().then_some(p.weight)
    }

    /// Stream data room of a batch by the gate: `None` unbounded.
    fn room(&mut self, i: usize, now: Instant) -> (Option<u64>, Duration) {
        let us = self.micros(now);
        let bound = self.limits.max_added_delay();
        let p = &mut self.pipes[i];
        if p.held(now, us, bound) {
            return (Some(0), Duration::ZERO);
        }
        p.bucket.fill(us);
        p.hold = None;
        let room = (p.bucket.rate != 0 && !p.bucket.held())
            .then_some(p.bucket.tokens.max(0).cast_unsigned());
        let prior = self.settle_held(i);
        (room, prior)
    }

    /// The earliest shaping deadline; `data` whether stream data waits,
    /// `ack` the deadline of a `PIPE_ACK` a pipe's next record carries.
    pub(super) fn deadline(
        &self,
        now: Instant,
        data: bool,
        ack: impl Fn(u64) -> Option<Instant>,
    ) -> Option<Instant> {
        let mut t: Option<Instant> = None;
        let mut at = |x: Instant| t = Some(t.map_or(x, |t| t.min(x)));
        let us = self.micros(now);
        for (i, p) in self
            .pipes
            .iter()
            .enumerate()
            .filter(|(_, p)| p.shaper.is_some())
        {
            if let Some(x) = p.wake {
                at(self.instant(x));
            }
            if let Some(x) = p.inject.filter(|_| !p.inject_due) {
                at(self.instant(x.at));
            }
            if let Some(until) = p.delay_until.filter(|_| p.plan.is_some()) {
                // Exactly: the delayed record goes at its time, or at the
                // deadline of the PIPE_ACK it carries.
                let ack = ack(p.pipe);
                if p.delayed(now, ack) {
                    at(ack.map_or(until, |a| a.min(until)));
                }
            }
            if data && p.held(now, us, self.limits.max_added_delay()) {
                at(self.release(i, now));
            }
        }
        t
    }

    /// Sends the due wakes and marks the due injections.
    pub(super) fn timeout(&mut self, now: Instant, record: usize) {
        let t = self.micros(now);
        for i in 0..self.pipes.len() {
            let p = &self.pipes[i];
            if p.shaper.is_some() && p.wake.is_some_and(|w| w <= t) {
                let pipe = p.pipe;
                self.pipes[i].wake = None;
                self.event(i, Event::new(EventKind::Timer, PipeId(pipe), t), record);
            }
            let p = &mut self.pipes[i];
            if p.shaper.is_some() && !p.inject_due && p.inject.is_some_and(|x| x.at <= t) {
                p.inject_due = true;
            }
        }
    }

    /// Delivers an event to every pipe whose instance asked for `cap`.
    pub(super) fn broadcast(&mut self, cap: Caps, e: Event, record: usize) {
        for i in 0..self.pipes.len() {
            let p = &self.pipes[i];
            if p.shaper.is_some() && p.caps.contains(cap) {
                let mut e = e;
                e.pipe = PipeId(p.pipe);
                self.event(i, e, record);
            }
        }
    }

    /// Ends shaping of a pipe: its outbound direction failed
    /// ([`EventKind::PipeFailed`]) or it was retired ([`EventKind::Stopped`]).
    /// The one place a pipe's shaping state goes.
    pub(super) fn pipe_ended(&mut self, pipe: u64, kind: EventKind, now: Instant) {
        if let Some(i) = self.index(pipe) {
            let e = Event::new(kind, PipeId(pipe), self.micros(now));
            self.event(i, e, 0);
            self.settle_held(i);
            let p = &self.pipes[i];
            self.stats.stall_spent = self.stats.stall_spent.saturating_add(p.record_wait);
            self.stats.max_added_delay = self
                .stats
                .max_added_delay
                .max(p.delay_prior + p.record_wait);
            self.pipes.swap_remove(i);
        }
    }
}

/// The shaping state lent to a batch.
pub(super) struct ShapeTx {
    s: Box<Shaping>,
    extra_room: u64,
    i: usize,
    pipe: u64,
    lane: u64,
    now: Instant,
    /// The carrier's write overhead.
    overhead: usize,
    /// The deadline of a `PIPE_ACK` the batch's records carry: a shaping
    /// delay ends there.
    ack: Option<Instant>,
    gate_delay: Duration,
    pub(super) datagram_delay_left: Duration,
    /// Stream data room by the gate; `None`: unbounded.
    pub(super) room: Option<u64>,
    /// Stream data bytes written.
    pub(super) spent: u64,
    /// Stream data waits for the rest of the batch.
    pub(super) data_held: bool,
    /// The record that opens next waits for its plan's delay: the batch
    /// takes nothing more.
    pub(super) delayed: bool,
    /// The pipe's gate count the room is of.
    gates: u64,
    /// `spent` when the gate the room is of was applied in the batch.
    gate_spent: u64,
}

/// `now + d` for a duration of a shaper, of any size: one beyond the clock's
/// range is a time that does not come in the life of a session.
pub(super) fn later(now: Instant, d: Duration) -> Instant {
    const FAR: Duration = Duration::from_secs(1 << 32);
    now.checked_add(d)
        .or_else(|| now.checked_add(FAR))
        .unwrap_or(now)
}

pub(super) fn bounded_delay(limits: Limits, asked: Duration, prior: Duration) -> Duration {
    asked.min(limits.max_added_delay().saturating_sub(prior))
}

#[derive(Clone, Copy)]
pub(super) struct CoverOutcome {
    request: Injection,
    write: Option<CoverWrite>,
    cost: usize,
    reason: Option<RuntimeReason>,
}

impl ShapeTx {
    /// Plans the record that opens next, the first of a carrier write call
    /// when `write_start`; returns its largest frames length.
    pub(super) fn prep(&mut self, limit: usize, write_start: bool, size_field: bool) -> usize {
        let now = self.now;
        let s = &mut *self.s;
        let i = self.i;
        if s.pipes[i].shaper.is_none() {
            return limit;
        }
        let wire = RecordWire {
            size_field,
            overhead: if write_start { self.overhead } else { 0 },
        };
        s.pipes[i].wire = wire;
        let fresh = s.pipes[i].plan.is_none();
        if fresh {
            let mut plan = RecordPlan::default();
            if s.pipes[i].caps.contains(Caps::PLAN) {
                let us = s.micros(now);
                let mut v =
                    RecordView::new(PipeId(self.pipe), self.lane, s.pipes[i].seq, limit, us)
                        .with_write_start(write_start);
                if s.pipes[i].caps.contains(Caps::BUDGET) {
                    v = v.with_meters(s.meters(us));
                }
                if !s.call(i, |x| x.plan(&v, &mut plan)) {
                    return limit;
                }
            }
            if s.limits.no_padding && (plan.pad_to | plan.pad_multiple | plan.pad) != 0 {
                plan.pad_to = 0;
                plan.pad_multiple = 0;
                plan.pad = 0;
                s.stats.clamped += 1;
            }
            // No padding target goes beyond a record, so that the padding
            // arithmetic cannot overflow.
            let most = wire.wire(limit);
            for (f, m) in [
                (&mut plan.pad_to, most),
                (&mut plan.pad_multiple, most),
                (&mut plan.pad, limit),
            ] {
                if *f > m {
                    *f = m;
                    s.stats.clamped += 1;
                }
            }
            if plan.max_len != 0 || plan.flush {
                // The current writer can price padding on the ordinary layout.
                // A shaped partition would need a proved counterfactual layout.
                s.stats.clamped += 1;
                s.stats.runtime_reasons[RuntimeReason::UnsupportedCapability as usize] += 1;
                plan.max_len = 0;
                plan.flush = false;
            }
            let effects = std::mem::take(&mut plan.effects);
            let delay = plan.delay;
            s.pipes[i].plan = Some(plan);
            if !effects.is_empty() {
                s.apply(i, &effects, now, limit, None);
                self.regate();
                if self.s.pipes[i].shaper.is_none() {
                    return limit;
                }
            }
            let s = &mut *self.s;
            let prior = s.pipes[i]
                .delay_prior
                .saturating_add(std::mem::take(&mut self.gate_delay));
            let bounded = delay.min(self.datagram_delay_left);
            if bounded < delay {
                s.stats.clamped += 1;
                s.stats.runtime_reasons[RuntimeReason::PolicyDeadline as usize] += 1;
            }
            s.pipes[i].delay_until = s.pause(bounded, now, prior);
            s.pipes[i].delay_prior = prior;
            s.pipes[i].delay_start = s.pipes[i].delay_until.map(|_| now);
        }
        let s = &mut *self.s;
        if s.pipes[i].delayed(now, self.ack) {
            // The whole record, control frames included, waits.
            self.delayed = true;
            return limit;
        }
        limit
    }

    /// After a gate was applied during the batch (by a plan or an event), the stream data room is
    /// the new gate's: from its full bucket, which pays only for the data written after it.
    fn regate(&mut self) {
        let gates = self.s.pipes[self.i].gates;
        if gates == self.gates {
            return;
        }
        self.gates = gates;
        self.gate_spent = self.spent;
        let (room, delay) = self.s.room(self.i, self.now);
        self.room = room;
        self.gate_delay = self.gate_delay.max(delay);
        self.data_held = self.room == Some(0);
    }

    fn planned(&self) -> Option<&RecordPlan> {
        self.s.pipes[self.i].plan.as_ref()
    }

    /// The PADDING the plan adds to a record of `n` frames bytes.
    fn padding_for(&self, n: usize) -> usize {
        let Some(p) = self.planned() else {
            return 0;
        };
        let s = &self.s.pipes[self.i];
        s.wire.frames(n, p) - n
    }

    /// Closes the plan of a record that is ending with `len` frames bytes
    /// and `avail` bytes of room; returns the PADDING to add.
    pub(super) fn end_record(&mut self, len: usize, avail: usize) -> usize {
        if self.planned().is_none() || len == 0 {
            return 0;
        }
        let want = self.padding_for(len);
        let s = &mut *self.s;
        let p = &s.pipes[self.i];
        let wire = p.wire;
        let base = wire.wire(len);
        let most = want.min(avail);
        let budget = crate::util::usize_sat(self.extra_room).min(wire.wire(len + most) - base);
        let pad = most.min(
            wire.frames_within(base.saturating_add(budget))
                .saturating_sub(len),
        );
        let extra = wire.wire(len + pad) - base;
        self.extra_room -= extra as u64;
        if pad < want {
            let reason = if pad < want.min(avail) {
                RuntimeReason::OverheadLimit
            } else {
                RuntimeReason::ClippedRoom
            };
            s.stats.clamped += 1;
            s.stats.runtime_reasons[reason as usize] += 1;
        }
        let p = &mut s.pipes[self.i];
        let plan = p.plan.take().expect("planned");
        let prior = std::mem::take(&mut p.delay_prior);
        p.delay_start = None;
        p.delay_until = None;
        let elapsed = std::mem::take(&mut p.record_wait);
        s.stats.stall_spent = s.stats.stall_spent.saturating_add(elapsed);
        s.stats.max_added_delay = s.stats.max_added_delay.max(prior.saturating_add(elapsed));
        p.seq += 1;
        if plan.stop {
            self.s.stop(self.i, true, self.now);
            self.regate();
        }
        pad
    }
}

impl SessionCore {
    pub(super) fn note_join_delay(&mut self, delay: Duration) {
        if !delay.is_zero() {
            let s = self.shaping();
            s.stats.max_added_delay = s.stats.max_added_delay.max(delay);
        }
    }

    /// The factory installed on every outbound pipe (the configured one or
    /// the last [`Self::set_shaper`]); `None`: no shaping.
    pub fn shaper(&self) -> Option<Arc<dyn Factory>> {
        self.shape.as_deref()?.factory.clone()
    }

    /// Installs `factory` on every outbound pipe, with no configuration budget; `None`: no
    /// shaping. The account carries over.
    pub fn set_shaper(
        &mut self,
        factory: Option<Arc<dyn Factory>>,
    ) -> Result<(), crate::InvalidConfig> {
        self.set_shaper_budgeted(factory, Budget::default())
    }

    /// Installs `factory` as [`Self::set_shaper`] does, under `budget`, one session's
    /// answer of a [`super::shaping::ShapingBudget`].
    pub fn set_shaper_budgeted(
        &mut self,
        factory: Option<Arc<dyn Factory>>,
        budget: Budget,
    ) -> Result<(), crate::InvalidConfig> {
        budget.validate()?;
        if let Some(factory) = &factory {
            Self::validate_gate(
                factory.required_gate_wait(Self::shape_preamble_bound()),
                self.shaping_limits().under(&budget),
            )?;
        }
        self.clear_native_plans();
        self.shape_budget = factory.as_ref().map(|_| Box::new(budget));
        let limits = self.shaping_limits_in_force();
        let now = self.now;
        self.shaping().set_limits(limits, now);
        self.install_shaper(factory);
        Ok(())
    }

    fn install_shaper(&mut self, factory: Option<Arc<dyn Factory>>) {
        if let Some(mp) = &mut self.mp {
            mp.acks_mut().invalidate_backlog();
        }
        let record = self.max_record();
        let now = self.now;
        let s = self.shaping();
        s.factory = factory;
        s.generation += 1;
        let pipes: Vec<ShapedPipe> = self
            .atts
            .iter()
            .filter(|a| a.out().is_some())
            .map(Attachment::shaped)
            .collect();
        let s = self.shape.as_deref_mut().expect("present");
        for p in pipes {
            s.active(&p, now, record);
        }
        self.channel_kick();
    }

    /// Replaces the session's local limits, tighter or looser; invalid ones change
    /// nothing. The account's spending carries over.
    pub fn set_shaping_limits(&mut self, limits: Limits) -> Result<(), crate::InvalidConfig> {
        limits.validate()?;
        if let Some(budget) = self.shape_budget.as_deref()
            && let Some(s) = self.shape.as_deref()
        {
            let effective = limits.under(budget);
            let preamble = Self::shape_preamble_bound();
            if let Some(factory) = &s.factory {
                Self::validate_gate(factory.required_gate_wait(preamble), effective)?;
            }
            for pipe in &s.pipes {
                if let Some(shaper) = &pipe.shaper {
                    Self::validate_gate(shaper.required_gate_wait(preamble), effective)?;
                }
            }
        }
        Arc::make_mut(&mut self.config).shaping_limits = Some(Box::new(limits));
        let eff = self.shaping_limits_in_force();
        let now = self.now;
        self.shaping().set_limits(eff, now);
        self.constrain_native_flows();
        Ok(())
    }

    const fn shape_preamble_bound() -> u64 {
        // A peer can increase the advertised allowance at confirmation.
        super::api::MAX_LOCAL_PREAMBLE
    }

    fn validate_gate(required: Duration, limits: Limits) -> Result<(), crate::InvalidConfig> {
        if !limits.no_pause && required > limits.max_added_delay() {
            return Err(crate::InvalidConfig::new(
                "shaping profile",
                "conflict: rate and burst cannot meet max_added_delay",
            ));
        }
        Ok(())
    }

    /// The session's local limits.
    pub fn shaping_limits(&self) -> Limits {
        self.config
            .shaping_limits
            .as_deref()
            .copied()
            .unwrap_or_default()
    }

    /// The local limits under the budget.
    pub fn shaping_limits_in_force(&self) -> Limits {
        let limits = self.shaping_limits();
        self.shape_budget.as_deref().map_or_else(
            || {
                let mut disabled = limits;
                disabled.wire = None;
                disabled.profile = None;
                disabled
            },
            |budget| limits.under(budget),
        )
    }

    /// The session's readings at the last owner input.
    pub fn shaping_meters(&self) -> Meters {
        self.shaping_meters_at(self.now)
    }

    pub(crate) fn shaping_meters_at(&self, now: Instant) -> Meters {
        self.shape.as_deref().map_or_else(
            || Meters::new(0, u64::MAX, 0, self.earn_bytes),
            |s| s.meters(s.micros(now.max(self.now))),
        )
    }

    /// Reserves the structural layout before the seal callback writes it.
    pub(super) fn seal_shaped_join<T, E>(
        &mut self,
        extra_at: usize,
        extra: usize,
        seal: impl FnOnce() -> Result<(Vec<u8>, T), E>,
    ) -> Result<(JoinUnit, T), E> {
        if extra != 0 {
            self.shaping().stats.handshake_reserved_bytes += extra as u64;
        }
        match seal() {
            Ok((bytes, state)) => {
                assert!(extra_at.saturating_add(extra) <= bytes.len());
                let dispatch = JoinDispatch {
                    at: self.shape_second(),
                    extra_at,
                    extra,
                };
                Ok((JoinUnit::new(bytes, dispatch), state))
            }
            Err(error) => {
                if extra != 0 {
                    self.shaping().stats.handshake_reserved_bytes -= extra as u64;
                }
                Err(error)
            }
        }
    }

    /// Settles an outbound Join once, with the carrier-proved prefix and whether
    /// terminal progress after that prefix is unidentified.
    pub fn complete_join_write(
        &mut self,
        unit: &mut JoinUnit,
        accepted: usize,
        unknown: bool,
        now: Instant,
    ) {
        self.tick(now);
        let Some(dispatch) = unit.dispatch.take() else {
            return;
        };
        let accepted = accepted.min(unit.len());
        #[cfg(all(feature = "tokio", not(loom)))]
        {
            let complete = accepted == unit.len();
            for handoff in unit.handoffs.drain(..) {
                if complete {
                    handoff.handed_off(super::splice_handoff::Medium::Stream);
                }
            }
        }

        let extra = accepted
            .saturating_sub(dispatch.extra_at)
            .min(dispatch.extra);
        let ledger_now = self.shape_ledger_now();
        self.shape_ledger
            .prove_baseline(dispatch.at, ledger_now, (accepted - extra) as u64);
        if dispatch.extra != 0 {
            let stats = &mut self.shaping().stats;
            stats.handshake_reserved_bytes -= dispatch.extra as u64;
            stats.handshake_measured_bytes =
                stats.handshake_measured_bytes.saturating_add(extra as u64);
            if unknown {
                stats.handshake_unresolved_bytes = stats
                    .handshake_unresolved_bytes
                    .saturating_add((dispatch.extra - extra) as u64);
            }
        }
    }

    /// Validates and transfers completed Establish layouts as one owner operation.
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn complete_establish(
        &mut self,
        receipts: super::shaping::EstablishReceipts,
    ) -> Result<(), crate::InvalidConfig> {
        if receipts[0].is_none() && receipts[1].is_some() {
            return Err(crate::InvalidConfig::new(
                "shaping Establish",
                "missing first structural receipt",
            ));
        }
        let mut last = None;
        let delay_bound = self.shape_budget.as_ref().map_or_else(
            || self.shaping_limits().max_added_delay(),
            |_| self.shaping_limits_in_force().max_added_delay(),
        );
        for receipt in receipts.iter().flatten() {
            if receipt.extra > receipt.allowance
                || receipt.allowance > crate::proto::seal::HANDSHAKE_MESSAGE_FLOOR as u64
                || receipt.delay > delay_bound
                || last.is_some_and(|at| receipt.at < at)
                || receipt.at > self.now
            {
                return Err(crate::InvalidConfig::new(
                    "shaping Establish",
                    "invalid structural receipt",
                ));
            }
            last = Some(receipt.at);
        }
        // A session created after Establish uses the first outbound message as
        // its observation clock origin, before any records have been dispatched.
        if let [Some(first), _] = receipts {
            self.started = self.started.min(first.at);
            if let Some(shaping) = &mut self.shape {
                shaping.base = self.started;
                shaping.account.last_us = self
                    .now
                    .saturating_duration_since(self.started)
                    .as_micros()
                    .try_into()
                    .unwrap_or(u64::MAX);
            }
        }
        for receipt in receipts.into_iter().flatten() {
            let at = receipt.at.saturating_duration_since(self.started).as_secs();
            let ledger_now = self.shape_ledger_now();
            self.shape_ledger
                .prove_baseline(at, ledger_now, receipt.baseline);
            let stats = &mut self.shaping().stats;
            stats.handshake_measured_bytes =
                stats.handshake_measured_bytes.saturating_add(receipt.extra);
            stats.stall_spent = stats.stall_spent.saturating_add(receipt.delay);
            stats.max_added_delay = stats.max_added_delay.max(receipt.delay);
        }
        Ok(())
    }

    pub(super) fn shaping_earn(&mut self, n: u64) {
        self.earn_bytes = self.earn_bytes.saturating_add(n);
        if let Some(s) = self.shape.as_deref_mut() {
            s.earn = self.earn_bytes;
            s.account.accrue(s.micros(self.now), n);
        }
    }

    /// Records whether `pipe`'s carrier reports its own failure (its reads
    /// or writes fail when its path fails): its stall then never fails it
    /// unless its own dead timeout is set. Set when the pipe is created;
    /// `false` when there is no such pipe.
    pub fn set_pipe_reports_failure(&mut self, pipe: PipeId, on: bool) -> bool {
        let c = self.config.liveness;
        let Some(a) = self.att_mut(pipe.0) else {
            return false;
        };
        a.set_carrier_reports_failure(on);
        let own = a.own_liveness();
        let dead = crate::proto::session::path::mpath::dead_timeout_of(&c, own.dead_timeout, on);
        if let Some(o) = a.out_mut() {
            o.set_detection_limits(own.suspect_floor.or(c.suspect_floor), dead);
        }
        true
    }

    /// Records the kind of pipe `pipe`'s carrier: the [`ShapedPipe`] a
    /// shaper factory sees, and the kind in pipe events and statistics.
    /// Set it before the pipe's first record is made (on the bootstrap
    /// pipe right after the core is created, on others when they are
    /// added or accepted). `false` when there is no such pipe.
    pub fn set_pipe_carrier(&mut self, pipe: PipeId, kind: Option<CarrierKind>) -> bool {
        match self.att_mut(pipe.0) {
            Some(a) => {
                a.set_carrier(kind);
                true
            }
            None => false,
        }
    }

    /// Records the host's label of the transform pipe `pipe`'s carrier runs:
    /// the [`ShapedPipe`] a shaper factory sees, and pipe statistics. Set it
    /// like [`Self::set_pipe_carrier`]. `false` when there is no such pipe.
    pub fn set_pipe_variant(&mut self, pipe: PipeId, variant: Option<Arc<str>>) -> bool {
        let Some(a) = self.att_mut(pipe.0) else {
            return false;
        };
        a.set_variant(variant);
        true
    }

    /// Records the write overhead of pipe `pipe`'s carrier: the fixed
    /// bytes the layers below zmux add to each write call, which the
    /// [`ShapedPipe`] a shaper factory sees carries and nothing else uses.
    /// Set it with the kind. `false` when there is no such pipe.
    pub fn set_pipe_write_overhead(&mut self, pipe: PipeId, bytes: u16) -> bool {
        match self.att_mut(pipe.0) {
            Some(a) => {
                a.set_write_overhead(bytes);
                true
            }
            None => false,
        }
    }

    /// Keeps the host's value of the admission that accepted pipe `pipe`'s
    /// carrier ([`crate::AdmissionVerdict::Accept`]), opaque to the core, for as
    /// long as the pipe's state. `false` when there is no such pipe.
    pub fn set_pipe_admitted(
        &mut self,
        pipe: PipeId,
        value: Option<crate::proto::admission::AdmittedValue>,
    ) -> bool {
        match self.att_mut(pipe.0) {
            Some(a) => {
                a.set_admitted(value);
                true
            }
            None => false,
        }
    }

    /// The host's admission value of pipe `pipe`'s carrier
    /// ([`SessionCore::set_pipe_admitted`]).
    pub fn pipe_admitted(&self, pipe: PipeId) -> Option<crate::proto::admission::AdmittedValue> {
        self.att(pipe.0).and_then(|a| a.admitted().cloned())
    }

    /// The kind of pipe `pipe`'s carrier ([`SessionCore::set_pipe_carrier`]).
    pub fn pipe_carrier(&self, pipe: PipeId) -> Option<CarrierKind> {
        self.att(pipe.0).and_then(Attachment::carrier)
    }

    /// Installs `shaper` on an outbound pipe until the next
    /// [`SessionCore::set_shaper`]; `None`: the pipe is not shaped. `false`
    /// when the pipe has no outbound direction.
    pub fn set_pipe_shaper(&mut self, pipe: PipeId, shaper: Option<Box<dyn Shaper>>) -> bool {
        if self.out_ref(pipe.0).is_none() {
            return false;
        }
        let budget = self.shape_budget.as_deref().copied().unwrap_or_default();
        let limits = self.shaping_limits().under(&budget);
        if let Some(shaper) = &shaper
            && Self::validate_gate(
                shaper.required_gate_wait(Self::shape_preamble_bound()),
                limits,
            )
            .is_err()
        {
            return false;
        }
        if let Some(mp) = &mut self.mp {
            mp.acks_mut().invalidate_backlog();
        }
        self.clear_native_plan(pipe.0);
        let (record, now) = (self.max_record(), self.now);
        if self.shape_budget.is_none() && shaper.is_some() {
            self.shape_budget = Some(Box::new(budget));
            self.shaping().set_limits(limits, now);
        }
        self.shaping().install(pipe.0, shaper, now, record);
        if self
            .shape
            .as_deref()
            .is_some_and(|s| s.factory.is_none() && s.pipes.iter().all(|p| p.shaper.is_none()))
        {
            self.shape_budget = None;
            let limits = self.shaping_limits_in_force();
            self.shaping().set_limits(limits, now);
        }
        self.channel_kick();
        true
    }

    /// The shaping counters.
    pub fn shaping_stats(&self) -> Stats {
        let mut stats = Stats::default();
        if let Some(s) = self.shape.as_ref() {
            stats = s.stats;
            stats.generation = s.generation;
            stats.wire_spent = s.account.spent;
            stats.max_added_delay = s.max_added_delay();
        }
        stats.ledger = self.shape_ledger.stats(
            self.now.saturating_duration_since(self.started).as_secs(),
            self.shaping_limits_in_force(),
        );
        stats.handshake_unplanned = self.join_shaping.unplanned;
        stats.faults += self.join_shaping.faults;
        stats
    }

    fn shaping(&mut self) -> &mut Shaping {
        let limits = self.shaping_limits_in_force();
        let (base, now, earn) = (self.started, self.now, self.earn_bytes);
        self.shape
            .get_or_insert_with(|| Box::new(Shaping::new(limits, base, now, earn)))
    }

    /// Lends the shaping state of pipe `id` to a batch of lane `lane`;
    /// `limit` is the batch's record size.
    pub(super) fn shape_lend(
        &mut self,
        id: u64,
        lane: u64,
        limit: usize,
        now: Instant,
    ) -> Option<ShapeTx> {
        let shaped = self
            .att(id)
            .map_or(ShapedPipe::new(PipeId(id), None), Attachment::shaped);
        let overhead = usize::from(shaped.write_overhead);
        let extra_room = self.shape_overhead_room();
        let datagram_delay_left = if lane == 0 {
            self.record_flow_budget(id)
        } else {
            Duration::MAX
        };
        let mut s = self.shape.take()?;
        let Some(i) = s.active(&shaped, now, limit) else {
            self.shape = Some(s);
            return None;
        };
        let pipe = &mut s.pipes[i];
        if let Some(until) = &mut pipe.delay_until {
            *until = (*until).min(later(now, datagram_delay_left));
        }
        let (room, gate_delay) = s.room(i, now);
        let gates = s.pipes[i].gates;
        let ack = self.ack_release(id);
        self.shape_pending = Some(Vec::new());
        Some(ShapeTx {
            s,
            i,
            pipe: id,
            lane,
            now,
            extra_room,
            overhead,
            ack,
            gate_delay,
            datagram_delay_left,
            room,
            spent: 0,
            data_held: room == Some(0),
            delayed: false,
            gates,
            gate_spent: 0,
        })
    }

    /// Takes the shaping state back from a batch.
    #[allow(
        clippy::many_single_char_names,
        reason = "the batch notation: w the records, t the lent state, s the shaper, p its pipe, e an event"
    )]
    pub(super) fn shape_return(&mut self, w: &mut Records<'_>) {
        let Some(mut t) = w.shape.take() else {
            return;
        };
        let p = &mut t.s.pipes[t.i];
        if p.bucket.rate > 0 && t.spent != t.gate_spent {
            p.bucket.tokens -= (t.spent - t.gate_spent).cast_signed();
            if p.bucket.held() {
                p.held_since.get_or_insert(
                    self.now
                        .saturating_duration_since(t.s.base)
                        .as_micros()
                        .try_into()
                        .unwrap_or(u64::MAX),
                );
            }
        }
        let record = w.max_record();
        let mut s = t.s;
        for (kind, stream) in self.shape_pending.take().unwrap_or_default() {
            let e = Event::new(kind, PipeId(0), s.micros(self.now)).with_stream(stream);
            s.broadcast(Caps::STREAMS, e, record);
        }
        self.shape = Some(s);
    }

    pub(super) fn cover_eligible(&self, pipe: u64) -> bool {
        self.state == State::Active
            && self.is_established()
            && !self.early_retains()
            && self
                .out_ref(pipe)
                .is_some_and(|out| out.takes_new_data() && out.confirmed())
    }

    fn cover_pending(w: &Records<'_>) -> bool {
        w.cover.is_none()
            && w.cover_eligible
            && w.shape
                .as_ref()
                .is_some_and(|t| t.lane == 0 && t.s.pipes[t.i].inject_due)
    }

    /// Finalizes optional padding before a Length-less DATAGRAM tail.
    pub(super) fn shape_tail(&mut self, w: &mut Records<'_>, tail: usize) {
        w.end_shaped_layout(tail);
        if Self::cover_pending(w) {
            self.cover_layout(w, tail, false);
        }
    }

    /// Consumes at most one due cover request after laying out business and protocol work.
    pub(super) fn shape_inject(&mut self, w: &mut Records<'_>) {
        if !Self::cover_pending(w) {
            return;
        }
        if w.out.in_record() && w.out.record_len() > 0 {
            w.end_shaped_layout(0);
            self.cover_layout(w, 0, false);
            w.end_plain();
        }
        if Self::cover_pending(w) && w.shape.as_ref().is_some_and(|t| !t.delayed) {
            self.cover_layout(w, 0, true);
        }
    }

    fn cover_layout(&mut self, w: &mut Records<'_>, tail: usize, standalone: bool) {
        let Some(t) = w.shape.as_ref() else { return };
        let Some(request) = t.s.pipes[t.i].inject else {
            return;
        };
        let limited = standalone && self.is_plain_qmux_peer();
        let before = w.out.record_len() + tail;
        let max = w.max_record();
        let width = |body| w.out.size_width(body);
        let room = if standalone {
            w.out.room().saturating_sub(width(max))
        } else {
            w.out.room().saturating_sub(tail)
        };
        let want = request.pad_bytes.min(max.saturating_sub(before));
        if standalone && !w.out.is_empty() && want > room {
            return;
        }
        let wire = RecordWire {
            size_field: !w.out.is_records(),
            overhead: 0,
        };
        let base = if standalone { 0 } else { wire.wire(before) };
        let t = w.shape.as_mut().expect("shaped");
        let us = t.s.micros(t.now);
        t.s.account.accrue(us, 0);
        let pad = want.min(room);
        let cost = wire.wire(before + pad).saturating_sub(base);
        let reason = if t.s.limits.no_padding || t.s.limits.no_injection {
            Some(RuntimeReason::Disabled)
        } else if limited && self.requests.available(t.now) < 2 {
            Some(RuntimeReason::RateLimit)
        } else if want.min(room) == 0 {
            if !standalone || !w.out.is_empty() {
                return;
            }
            Some(RuntimeReason::ClippedRoom)
        } else if cost as u64 > t.extra_room {
            Some(RuntimeReason::OverheadLimit)
        } else if cost as u64 > t.s.account.left() {
            Some(RuntimeReason::InsufficientCoverCredit)
        } else {
            None
        };
        let p = &mut t.s.pipes[t.i];
        p.inject = None;
        p.inject_due = false;
        let mut write = None;
        if reason.is_none() {
            t.extra_room -= cost as u64;
            let head = crate::proto::varint::len((before + pad) as u64);
            let start = w.out.stream_len() + (head + before - tail) as u64;
            write = Some(CoverWrite {
                start,
                len: pad,
                request_id: request.id,
            });
            if standalone {
                w.padding_record(pad);
            } else {
                w.shaping_padding(pad);
            }
            if limited {
                self.requests.record(self.now);
            }
        }
        w.cover = Some(CoverOutcome {
            request,
            write,
            cost,
            reason,
        });
    }

    /// Whether pipe `id` has an injection due.
    pub(super) fn shape_wants(&self, id: u64) -> bool {
        self.cover_eligible(id) && self.shape.as_deref().is_some_and(|s| s.inject_due(id))
    }

    /// Whether the planned record of pipe `id` waits for its delay: the
    /// pipe sends nothing but `CONNECTION_CLOSE` until then.
    pub(super) fn shape_delayed(&self, id: u64) -> bool {
        self.shape
            .as_deref()
            .is_some_and(|s| s.delayed(id, self.now, self.ack_release(id)))
            && !self.record_flow_budget(id).is_zero()
    }

    /// Whether the gate of pipe `id` holds stream data now.
    pub(super) fn shape_held(&self, id: u64) -> bool {
        self.shape.as_deref().is_some_and(|s| s.held(id, self.now))
    }

    pub(super) fn shape_deadline(&self) -> Option<Instant> {
        if self.state >= State::Closing {
            return None;
        }
        let s = self.shape.as_deref()?;
        let ordinary = s.deadline(self.now, self.data_pending(), |id| self.ack_release(id));
        let datagrams = s.pipes.iter().filter_map(|p| {
            let end = self.record_shaping_wait(p.pipe)?;
            let budget = self.record_flow_budget(p.pipe);
            (!budget.is_zero() && budget != Duration::MAX)
                .then(|| end.min(later(self.now, budget)))
                .filter(|&end| end > self.now)
        });
        ordinary.into_iter().chain(datagrams).min()
    }

    pub(super) fn shape_timeout(&mut self, now: Instant) {
        if self.state >= State::Closing {
            return;
        }
        let record = self.max_record();
        if let Some(s) = self.shape.as_deref_mut() {
            s.timeout(now, record);
        }
    }

    pub(super) fn shape_pipe_failed(&mut self, id: u64) {
        self.clear_native_plan(id);
        let now = self.now;
        if let Some(s) = self.shape.as_deref_mut() {
            s.pipe_ended(id, EventKind::PipeFailed, now);
        }
    }

    /// A retired pipe's shaping state goes (a failed one's went already).
    pub(super) fn shape_retired(&mut self, id: u64) {
        self.clear_native_plan(id);
        let now = self.now;
        if let Some(s) = self.shape.as_deref_mut() {
            s.pipe_ended(id, EventKind::Stopped, now);
        }
    }

    /// Reports a stream event.
    pub(super) fn shape_stream(&mut self, kind: EventKind, stream: u64) {
        let (record, now) = (self.max_record(), self.now);
        if let Some(s) = self.shape.as_deref_mut() {
            let e = Event::new(kind, PipeId(0), s.micros(now)).with_stream(stream);
            s.broadcast(Caps::STREAMS, e, record);
        } else if let Some(q) = self.shape_pending.as_mut() {
            q.push((kind, stream));
        }
    }
}

impl SessionCore {
    pub(super) fn shape_activate(&mut self, pipe: u64) -> bool {
        if self.shape.is_none() {
            return false;
        }
        let Some(attachment) = self.att(pipe) else {
            return false;
        };
        let pipe = attachment.shaped();
        let record = self.max_record();
        let s = self.shape.as_deref_mut().expect("present");
        s.active(&pipe, self.now, record).is_some()
    }

    pub(super) fn native_shaper_instance(&self, pipe: u64) -> Option<u64> {
        let s = self.shape.as_deref()?;
        let p = &s.pipes[s.index(pipe)?];
        (p.shaper.is_some() && p.caps.contains(Caps::DATAGRAM_PLAN)).then_some(p.instance)
    }

    pub(super) fn shape_instance(&self, pipe: u64) -> Option<u64> {
        let s = self.shape.as_deref()?;
        let p = &s.pipes[s.index(pipe)?];
        p.shaper.as_ref().map(|_| p.instance)
    }

    pub(super) fn shape_native_plan(&mut self, mut view: DatagramView) -> Option<UnitPlan> {
        let record = self.max_record();
        let s = self.shape.as_deref_mut()?;
        let i = s.index(view.pipe.0)?;
        let caps = s.pipes[i].caps;
        if !caps.contains(Caps::DATAGRAM_PLAN) {
            return None;
        }
        view.now = s.micros(self.now);
        if caps.contains(Caps::BUDGET) {
            view.meters = s.meters(view.now);
        }
        let mut plan = DatagramPlan::default();
        if !s.call(i, |shaper| shaper.plan_datagram(&view, &mut plan)) {
            return None;
        }
        s.apply(i, &plan.effects, self.now, record, None);
        s.pipes[i].shaper.as_ref().map(|_| plan.unit)
    }

    pub(super) fn bounded_native_delay(&mut self, asked: Duration, prior: Duration) -> Duration {
        let delay = bounded_delay(self.shaping_limits_in_force(), asked, prior);
        if delay < asked {
            self.note_shape_clip(RuntimeReason::PolicyDeadline);
        }
        delay
    }

    fn shape_second(&self) -> u64 {
        self.now.saturating_duration_since(self.started).as_secs()
    }

    pub(super) fn shape_overhead_room(&self) -> u64 {
        self.shape_ledger
            .room(self.shape_second(), self.shaping_limits_in_force())
    }

    fn shape_ledger_now(&self) -> (u64, Limits) {
        (self.shape_second(), self.shaping_limits_in_force())
    }

    pub(super) fn commit_shape_bytes(&mut self, extra: u64) -> Dispatch {
        let (second, limits) = self.shape_ledger_now();
        self.shape_ledger.commit(second, limits, extra)
    }

    pub(super) fn finish_shape_bytes(&mut self, dispatch: Dispatch, unknown: bool) {
        let now = self.shape_ledger_now();
        self.shape_ledger.finish(dispatch, now, unknown);
    }

    pub(super) fn settle_native_shape(&mut self, mut dispatch: Dispatch, bytes: usize, pad: usize) {
        let now = self.shape_ledger_now();
        self.shape_ledger
            .progress(&mut dispatch, now, (bytes - pad) as u64, pad as u64, false);
        self.shape_ledger.finish(dispatch, now, false);
    }

    pub(super) fn note_shape_reason(&mut self, reason: RuntimeReason) {
        if let Some(s) = self.shape.as_deref_mut() {
            let count = &mut s.stats.runtime_reasons[reason as usize];
            *count = count.saturating_add(1);
        }
    }

    pub(super) fn note_shape_clip(&mut self, reason: RuntimeReason) {
        if let Some(s) = self.shape.as_deref_mut() {
            s.stats.clamped = s.stats.clamped.saturating_add(1);
            let count = &mut s.stats.runtime_reasons[reason as usize];
            *count = count.saturating_add(1);
        }
    }

    pub(super) fn record_shaping_wait(&self, pipe: u64) -> Option<Instant> {
        let s = self.shape.as_deref()?;
        let i = s.index(pipe)?;
        let p = &s.pipes[i];
        let ack = self.ack_release(pipe);
        let record = p
            .delay_until
            .filter(|_| p.delayed(self.now, ack))
            .map(|end| ack.map_or(end, |ack| end.min(ack)));
        let gate = s.held(pipe, self.now).then(|| s.release(i, self.now));
        record.into_iter().chain(gate).max()
    }

    pub(super) fn advance_shaping_waits(&mut self, until: Instant) {
        let Some(s) = self.shape.as_ref() else {
            return;
        };
        if self.state >= State::Closing {
            return;
        }
        let now = self.now;
        let reliable = s
            .pipes
            .iter()
            .any(|p| p.delayed(now, self.ack_release(p.pipe)) || s.held(p.pipe, now));
        if reliable || self.native_shape_deadline().is_some() {
            self.advance_datagram_waits(until);
        }
        if !reliable {
            return;
        }
        let pipes = self.shape.as_ref().expect("shaping").pipes.len();
        for i in 0..pipes {
            let s = self.shape.as_ref().expect("shaping");
            let p = &s.pipes[i];
            let pipe = p.pipe;
            if !self
                .out_ref(pipe)
                .is_some_and(|out| out.open() && out.write_idle())
            {
                continue;
            }
            let ack = self.ack_release(pipe);
            let accounted = p.datagram_wait_until.unwrap_or(now);
            let record_end = p
                .delay_until
                .filter(|_| p.delayed(now, ack))
                .map(|end| until.min(end).min(ack.unwrap_or(end)));
            let gate_wait = if s.held(pipe, now)
                && if self.mp.is_some() {
                    self.data_for_pipe(pipe)
                } else {
                    self.data_pending()
                } {
                let end = until.min(s.release(i, now));
                end.saturating_duration_since(record_end.unwrap_or(now).max(accounted))
            } else {
                Duration::ZERO
            };
            let p = &mut self.shape.as_mut().expect("shaping").pipes[i];
            if let Some(end) = record_end {
                p.record_wait += end.saturating_duration_since(now.max(accounted));
            }
            p.gate_wait += gate_wait;
            p.datagram_wait_until = None;
        }
    }

    pub(super) fn note_datagram_delay(
        &mut self,
        route: super::datagram::DatagramRoute,
        until: Instant,
        added: Duration,
        spent: Duration,
    ) {
        if added.is_zero() {
            return;
        }
        if let Some(s) = self.shape.as_deref_mut() {
            s.stats.stall_spent = s.stats.stall_spent.saturating_add(added);
            s.stats.max_added_delay = s.stats.max_added_delay.max(spent);
            if let super::datagram::DatagramRoute::Record(pipe) = route
                && let Some(i) = s.index(pipe)
            {
                let p = &mut s.pipes[i];
                p.datagram_wait_until =
                    Some(p.datagram_wait_until.map_or(until, |at| at.max(until)));
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "attribution of a completed outbound unit"
    )]
    pub(super) fn shape_outbound(
        &mut self,
        pipe: u64,
        lane: u64,
        generation: Option<u64>,
        len: usize,
        data: bool,
        control: bool,
        native: bool,
    ) -> bool {
        if generation.is_none()
            || self.shape_instance(pipe) != generation
            || !self.cover_eligible(pipe)
        {
            return false;
        }
        let record = self.max_record();
        let s = self.shape.as_deref_mut().expect("generation matched");
        let i = s.index(pipe).expect("generation matched");
        let caps = s.pipes[i].caps;
        if !caps.contains(Caps::OUTBOUND)
            || !(data || control && caps.contains(Caps::INCLUDE_CONTROL))
        {
            return false;
        }
        let mut event = Event::new(EventKind::Outbound, PipeId(pipe), s.micros(self.now))
            .with_lane(lane)
            .with_len(len);
        event.unit = if native {
            UnitKind::NativeDatagram
        } else {
            UnitKind::Record
        };
        event.data = data;
        event.control = control;
        s.event(i, event, record);
        true
    }

    /// Closes a batch, taking a lent shaping state back and committing its attribution.
    pub(super) fn shape_finish(&mut self, w: &mut Records<'_>) -> u64 {
        let generation = w.shape.as_ref().and_then(|t| {
            let pipe = &t.s.pipes[t.i];
            (w.cover_eligible && (pipe.caps.contains(Caps::OUTBOUND) || w.cover.is_some()))
                .then_some(pipe.instance)
        });
        let records = w.finish();
        self.shape_return(w);
        let dispatch = (records != 0).then(|| {
            let extra = w
                .out
                .records()
                .iter()
                .map(|record| record.extra(w.out.is_records()))
                .sum();
            self.commit_shape_bytes(extra)
        });
        let cover = w
            .cover
            .take()
            .and_then(|outcome| self.commit_cover(outcome));
        if let Some(dispatch) = dispatch {
            w.out.shape_write = Some(ShapeWrite {
                generation,
                cover,
                provisional: w.provisional,
                dispatch,
            });
        }
        if w.oversized {
            self.fail_internal("a frame exceeds the record limit", self.now);
        }
        records
    }

    fn commit_cover(&mut self, outcome: CoverOutcome) -> Option<CoverWrite> {
        let record = self.max_record();
        let s = self.shape.as_deref_mut()?;
        let now = s.micros(self.now);
        let pipe = PipeId(self.tx);
        let mut event = Event::new(EventKind::InjectionRejected, pipe, now);
        event.request_id = outcome.request.id;
        if let Some(write) = outcome.write {
            assert!(
                s.account.charge(now, outcome.cost as u64),
                "checked cover layout"
            );
            s.stats.injection_accepted_requests =
                s.stats.injection_accepted_requests.saturating_add(1);
            s.stats.injection_accepted_bytes = s
                .stats
                .injection_accepted_bytes
                .saturating_add(write.len as u64);
            event.kind = EventKind::InjectionAccepted;
            event.len = write.len;
            event.wire_cost = outcome.cost;
        } else if let Some(reason) = outcome.reason {
            s.stats.injection_rejected = s.stats.injection_rejected.saturating_add(1);
            let count = &mut s.stats.injection_rejected_by_reason[reason as usize];
            *count = count.saturating_add(1);
            let count = &mut s.stats.runtime_reasons[reason as usize];
            *count = count.saturating_add(1);
            event.reason = Some(reason);
        }
        if let Some(i) = s.index(pipe.0) {
            s.event(i, event, record);
        }
        self.push_event(super::CoreEvent::Shaping(Box::new(event)));
        outcome.write
    }

    /// Reports the absolute accepted byte-stream prefix of this batch. For a
    /// message carrier the prefix includes the synthetic record Size fields.
    pub fn transmit_progress(
        &mut self,
        lane: LaneId,
        out: &mut TransmitBuf,
        accepted: u64,
        final_result: bool,
        now: Instant,
    ) -> bool {
        self.settle_transmit(lane, out, accepted, final_result, false, now)
    }

    /// Reports the last proved prefix when a handoff's outcome cannot be identified.
    pub fn transmit_progress_unknown(
        &mut self,
        lane: LaneId,
        out: &mut TransmitBuf,
        accepted: u64,
        now: Instant,
    ) -> bool {
        self.settle_transmit(lane, out, accepted, true, true, now)
    }

    fn settle_transmit(
        &mut self,
        lane: LaneId,
        out: &mut TransmitBuf,
        accepted: u64,
        final_result: bool,
        unknown: bool,
        now: Instant,
    ) -> bool {
        if out.finalized {
            return false;
        }
        out.finalized = final_result;
        self.tick(now);
        let ledger_now = self.shape_ledger_now();
        let accepted = accepted.min(out.stream_len()).max(out.reported);
        #[cfg(all(feature = "tokio", not(loom)))]
        out.settle_handoffs(accepted, final_result);
        let provisional = out.shape_write.as_ref().and_then(|s| s.provisional);
        let generation = out.shape_write.as_ref().and_then(|s| s.generation);
        let mut notified = false;
        let mut cover_delta = 0;
        let cover = out.shape_write.as_ref().and_then(|s| s.cover);
        if accepted > out.reported {
            let records = out.records();
            let framed = out.is_records();
            let first = records.partition_point(|r| r.end <= out.reported);
            let mut start = first.checked_sub(1).map_or(0, |i| records[i].end);
            let mut baseline = 0;
            let mut extra = 0;
            for record in &records[first..] {
                let before = out.reported.saturating_sub(start);
                let after = accepted.min(record.end) - start;
                let step = record.progress(framed, before, after);
                baseline += step.0;
                extra += step.1;
                if record.end >= accepted {
                    break;
                }
                start = record.end;
            }
            let current = provisional.is_none_or(|start| start == self.bootstrap_start());
            if let Some(write) = &mut out.shape_write {
                self.shape_ledger.progress(
                    &mut write.dispatch,
                    ledger_now,
                    if current { baseline } else { 0 },
                    extra,
                    provisional.is_some() && self.early_retains(),
                );
            }
            if let Some(cover) = cover {
                let intersection = |pos: u64| pos.saturating_sub(cover.start).min(cover.len as u64);
                cover_delta = intersection(accepted) - intersection(out.reported);
                let s = self.shape.as_deref_mut().expect("cover account");
                s.stats.injection_sent_bytes =
                    s.stats.injection_sent_bytes.saturating_add(cover_delta);
            }
            let records = out.records();
            let mut index = if out.reported == 0 {
                0
            } else {
                records.partition_point(|record| record.end <= out.reported)
            };
            while let Some(record) = records.get(index).filter(|r| r.end <= accepted) {
                let len = record.end - index.checked_sub(1).map_or(0, |prev| records[prev].end);
                #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
                self.member_bytes(lane.pipe, true, len);
                let len = if out.is_records() {
                    RecordWire {
                        size_field: true,
                        overhead: 0,
                    }
                    .frames_within(crate::util::usize_sat(len))
                } else {
                    crate::util::usize_sat(len)
                };
                if let Some(start) = provisional {
                    self.confirm_provisional_own(start, u64::from(record.own));
                } else {
                    self.shaping_earn(u64::from(record.own));
                    notified |= self.shape_outbound(
                        lane.pipe.0,
                        lane.lane.0,
                        generation,
                        len,
                        record.data,
                        record.control,
                        false,
                    );
                }
                index += 1;
            }
            out.reported = accepted;
        }
        if final_result && let Some(write) = out.shape_write.take() {
            self.shape_ledger
                .finish(write.dispatch, ledger_now, unknown);
        }
        let reason = if final_result && unknown {
            Some(RuntimeReason::PartialProgress)
        } else if final_result && accepted == 0 {
            Some(RuntimeReason::CarrierRejected)
        } else if final_result && accepted < out.stream_len() {
            Some(RuntimeReason::PartialProgress)
        } else {
            None
        };
        if let Some(cover) = cover
            && (cover_delta != 0 || reason.is_some())
        {
            let record = self.max_record();
            let s = self.shape.as_deref_mut().expect("cover account");
            let mut e = Event::new(
                EventKind::InjectionCarrierCompleted,
                lane.pipe,
                s.micros(self.now),
            )
            .with_lane(lane.lane.0)
            .with_len(crate::util::usize_sat(cover_delta));
            e.request_id = cover.request_id;
            e.reason = reason;
            if let Some(reason) = reason {
                let count = &mut s.stats.runtime_reasons[reason as usize];
                *count = count.saturating_add(1);
            }
            if let Some(i) = s.index(lane.pipe.0)
                && generation == Some(s.pipes[i].instance)
            {
                s.event(i, e, record);
            }
            self.push_event(super::CoreEvent::Shaping(Box::new(e)));
            notified = true;
        }
        notified
    }
}

impl Records<'_> {
    /// Writes a record of `n` bytes of PADDING.
    pub(super) fn padding_record(&mut self, n: usize) {
        self.end_record();
        self.out.begin_record(self.max_record());
        self.shaping_padding(n);
        self.end_plain();
    }

    /// PADDING bytes.
    pub(super) fn padding(&mut self, n: usize) {
        if n > 0 {
            self.payload(&ZERO[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn shaping(limits: Limits) -> Shaping {
        {
            let now = Instant::now();
            Shaping::new(limits, now, now, 0)
        }
    }

    fn pipe(s: &mut Shaping, shaper: impl Shaper + 'static) {
        s.pipes.push(PipeShape::new(1, 0));
        s.pipes[0].shaper = Some(Box::new(shaper));
    }

    /// Answers a wake with nothing, or with a time of its own.
    struct Waked(Arc<AtomicUsize>, Option<u64>);

    impl Shaper for Waked {
        fn capabilities(&self) -> Caps {
            Caps::default()
        }
        fn on_event(&mut self, e: &Event, r: &mut Effects) {
            if e.kind == EventKind::Timer {
                self.0.fetch_add(1, Ordering::SeqCst);
                if let Some(at) = self.1 {
                    r.wake = Some(Some(at));
                }
            }
        }
    }

    /// A pipe that ends, failed or retired, leaves the shaping state with
    /// its shaper, which is told once; a retired pipe's wake no longer
    /// drives the session's timer.
    #[test]
    fn an_ended_pipe_leaves_the_shaping_state() {
        for kind in [EventKind::Stopped, EventKind::PipeFailed] {
            let mut s = shaping(Limits::default());
            let woken = Arc::new(AtomicUsize::new(0));
            pipe(&mut s, Waked(woken, Some(1)));
            assert!(s.index(1).is_some());
            s.pipe_ended(1, kind, Instant::now());
            assert!(s.index(1).is_none(), "{kind:?}");
            assert_eq!(s.pipes.len(), 0);
        }
    }

    /// The core's release point: a `PipeRetired` event, pushed as the
    /// retirement paths push it, takes the pipe's shaping state with it.
    #[test]
    fn a_retired_pipe_event_releases_its_shaping_state() {
        let now = Instant::now();
        let mut core =
            SessionCore::new(crate::Config::default(), crate::Role::Client, None, now).unwrap();
        let woken = Arc::new(AtomicUsize::new(0));
        pipe(core.shaping(), Waked(woken, Some(1)));
        assert!(core.shaping().index(1).is_some());
        core.push_event(crate::proto::session::CoreEvent::PipeRetired {
            pipe: PipeId(1),
            join_failure: None,
            failed: false,
        });
        assert!(core.shaping().index(1).is_none());
    }

    #[test]
    fn hold_bound_uses_profile_and_local_prohibition() {
        let mut limits = Limits::default();
        assert_eq!(shaping(limits).hold_bound(), Duration::from_micros(2000));
        limits.profile = Some(super::super::shaping::ProfileLimits::new(
            10,
            0,
            0,
            Duration::from_millis(300),
        ));
        assert_eq!(shaping(limits).hold_bound(), Duration::from_millis(300));
        limits.no_pause = true;
        assert_eq!(shaping(limits).hold_bound(), Duration::ZERO);
    }

    fn pause_to(s: &mut Shaping, at: u64, now: Instant) {
        let effects = Effects {
            gate: Some(super::super::shaping::Gate::new(at, 0, 0)),
            ..Effects::default()
        };
        s.apply(0, &effects, now, 1200, None);
    }

    #[test]
    fn repeated_pauses_count_once() {
        let mut s = shaping(Limits {
            profile: Some(super::super::shaping::ProfileLimits::new(
                10,
                0,
                0,
                Duration::from_millis(100),
            )),
            ..Limits::default()
        });
        pipe(&mut s, Waked(Arc::default(), None));
        let now = s.base;
        pause_to(&mut s, 500_000, now);
        assert_eq!(s.stats.stall_spent, Duration::ZERO);
        assert_eq!(s.pipes[0].hold, Some(now + Duration::from_millis(100)));
        assert_eq!(s.stats.clamped, 1);
        for _ in 0..5 {
            pause_to(&mut s, 500_000, now);
        }
        assert_eq!(s.stats.stall_spent, Duration::ZERO);
        assert_eq!(s.stats.clamped, 1);
        // Repeated or extended effects share the already-running wait.
        pause_to(&mut s, 510_000, now);
        assert_eq!(s.pipes[0].hold, Some(now + Duration::from_millis(100)));
    }

    /// A shaper's times take a duration of any size.
    #[test]
    fn the_longest_duration_does_not_panic() {
        let now = Instant::now();
        assert!(later(now, Duration::MAX) > now);
        let mut s = shaping(Limits::default());
        assert!(
            s.pause(Duration::MAX, now, Duration::ZERO)
                .is_some_and(|t| t > now)
        );
    }

    #[test]
    fn switches_and_the_default_bound_reduce_a_pause() {
        let now = Instant::now();
        let five = Duration::from_secs(5);
        let mut s = shaping(Limits::default());
        assert_eq!(
            s.pause(five, now, Duration::ZERO),
            Some(now + Duration::from_micros(2000))
        );
        assert_eq!(s.stats.clamped, 1);
        let mut s = shaping(Limits {
            no_pause: true,
            ..Limits::default()
        });
        assert_eq!(s.pause(five, now, Duration::ZERO), None);
        assert_eq!(s.stats.stall_spent, Duration::ZERO);
    }
}
