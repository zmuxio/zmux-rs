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

use bytes::Bytes;

use super::output::Records;
use super::pipes::Attachment;
use super::shape_account::{TokenBucket, WireAccount};
use super::shaping::{
    Budget, Caps, Effects, Event, EventKind, Factory, Injection, Limits, MAX_ACCOUNT_RATE, Meters,
    RecordPlan, RecordView, RecordWire, ShapedPipe, Shaper, Stats, burst_floor, rate_floor,
};
use super::{CarrierKind, PipeId, SessionCore};

/// Backs PADDING frames (0x00 bytes).
static ZERO: [u8; 65535] = [0; 65535];

/// No release is scheduled closer than this.
const GRANULARITY: Duration = Duration::from_millis(1);

pub(crate) struct Shaping {
    factory: Option<Arc<dyn Factory>>,
    /// Bumped by `set_shaper`: an instance of an older one is replaced.
    generation: u64,
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
    /// `None`: not shaped.
    shaper: Option<Box<dyn Shaper>>,
    caps: Caps,
    seq: u64,
    /// The plan of the next record, once made.
    plan: Option<RecordPlan>,
    /// How that record's lengths convert.
    wire: RecordWire,
    /// PADDING frames bytes an injection added to that record.
    added: usize,
    /// Of those, what the account already metered.
    added_paid: usize,
    /// The planned record's earliest send time (`RecordPlan::delay`):
    /// until then the pipe sends nothing but CONNECTION_CLOSE, and the
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
    /// The rate gate holds data since then.
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
            shaper: None,
            caps: Caps::NONE,
            seq: 0,
            plan: None,
            wire: RecordWire::default(),
            added: 0,
            added_paid: 0,
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
    /// and `ack` (the deadline of a PIPE_ACK the record carries, see
    /// [`SessionCore::ack_release`]) has not either.
    fn delayed(&self, now: Instant, ack: Option<Instant>) -> bool {
        self.shaper.is_some()
            && self.plan.is_some()
            && self.delay_until.is_some_and(|t| now < t)
            && ack.is_none_or(|t| now < t)
    }

    fn held(&self, now: Instant, us: u64) -> bool {
        self.shaper.is_some()
            && (self.hold.is_some_and(|h| now < h)
                || self.bucket.rate > 0 && self.bucket_at(us).held())
    }
}

impl Shaping {
    /// H_p: the longest the next pause may
    /// last; zero when none may or nothing bounds one.
    pub(super) fn hold_bound(&self) -> Duration {
        if self.limits.no_pause {
            return Duration::ZERO;
        }
        self.limits.max_delay.unwrap_or(Duration::ZERO)
    }

    /// H_p of `pipe`: [`Self::hold_bound`] for a
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

    pub(super) fn new(limits: Limits, base: Instant, earn: u64) -> Self {
        let mut account = WireAccount::default();
        // The account runs from the session's start, whenever it is first needed.
        account.set(0, 0, limits.wire);
        Self {
            factory: None,
            generation: 0,
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
        self.account.set(self.micros(now), self.earn, limits.wire);
        for i in 0..self.pipes.len() {
            if self.pipes[i].shaper.is_some() && self.pipes[i].rate_asked != 0 {
                let us = self.micros(now);
                self.pipes[i].bucket.fill(us);
                self.settle_held(i, us);
                self.set_rate(i);
            }
        }
    }

    /// The session clock as last seen by the account.
    const fn account_now(&self) -> u64 {
        self.account.last_us
    }

    /// Counts the wait of a rate gate that holds data up to `us` and ends it.
    fn settle_held(&mut self, i: usize, us: u64) {
        if let Some(from) = self.pipes[i].held_since.take() {
            let d = Duration::from_micros(us.saturating_sub(from));
            self.stats.stall_spent = self.stats.stall_spent.saturating_add(d);
        }
    }

    /// Puts the rate asked in force, within the lower bound of one wait.
    fn set_rate(&mut self, i: usize) {
        let md = self
            .limits
            .max_delay
            .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        let (rate, clamped) = rate_floor(self.pipes[i].rate_asked, md);
        if clamped {
            self.stats.clamped += 1;
        }
        self.pipes[i].bucket.rate = rate;
    }

    /// The session's readings at `us`.
    fn meters(&mut self, us: u64) -> Meters {
        self.account.accrue(us, self.earn);
        let stall = u64::try_from(self.stats.stall_spent.as_micros()).unwrap_or(u64::MAX);
        let mut m = Meters::new(self.account.left(), u64::MAX, self.account.spent, self.earn);
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
        shaped: ShapedPipe,
        now: Instant,
        record: usize,
    ) -> Option<usize> {
        let pipe = shaped.id.0;
        let i = match self.index(pipe) {
            Some(i) if self.pipes[i].generation == self.generation => i,
            _ => {
                let x = self.factory.clone().and_then(|f| {
                    catch_unwind(AssertUnwindSafe(|| f.shaper(&shaped))).unwrap_or_else(|_| {
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
        let i = match self.index(pipe) {
            Some(i) => {
                let e = Event::new(EventKind::Replaced, PipeId(pipe), self.micros(now));
                self.event(i, e, record);
                self.settle_held(i, self.micros(now));
                self.pipes[i] = PipeShape::new(pipe, self.generation);
                i
            }
            None => {
                self.pipes.push(PipeShape::new(pipe, self.generation));
                self.pipes.len() - 1
            }
        };
        let Some(x) = x else {
            return i;
        };
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
        self.settle_held(i, self.micros(now));
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
            self.apply(i, &r, self.instant(e.now), record);
        }
    }

    fn apply(&mut self, i: usize, r: &Effects, now: Instant, record: usize) {
        let p = &mut self.pipes[i];
        if let Some(inject) = r.inject {
            p.inject = inject;
            p.inject_due = false;
        }
        if let Some(wake) = r.wake {
            p.wake = wake;
        }
        if let Some(w) = r.weight.filter(|w| *w > 0) {
            p.weight = Some(w);
        }
        if let Some(g) = r.gate {
            let (burst, raised) = burst_floor(g.burst, record as u64);
            let p = &self.pipes[i];
            let rate = g.rate.min(MAX_ACCOUNT_RATE);
            let rated = p.rate_asked != rate || p.bucket.burst != burst as i64;
            // Only what extends the pauses asked for so far counts: an answer repeats its
            // pause_until, and a limit may have shortened that pause.
            let asked = p.paused_until;
            let current = p.hold.filter(|&h| h > now).unwrap_or(now);
            let from = self.micros(current);
            let paused = g.pause_until > from.max(asked);
            if paused {
                self.pipes[i].paused_until = g.pause_until;
                let d = g.pause_until - from.max(asked);
                if let Some(end) = self.pause(Duration::from_micros(d), current) {
                    self.pipes[i].hold = Some(end);
                }
            }
            if rated {
                let us = self.micros(now);
                if raised && rate != 0 {
                    self.stats.clamped += 1;
                }
                self.pipes[i].bucket.fill(us);
                self.settle_held(i, us);
                self.pipes[i].rate_asked = rate;
                self.pipes[i].bucket.burst = burst as i64;
                self.set_rate(i);
                self.pipes[i].bucket.reset(us);
            }
            let p = &mut self.pipes[i];
            if paused || rated {
                p.gates += 1;
            }
        }
        if r.stop {
            self.stop(i, true, now);
        }
    }

    /// Bounds a pause by the limits; returns its end.
    fn pause(&mut self, mut d: Duration, now: Instant) -> Option<Instant> {
        if d.is_zero() {
            return None;
        }
        if self.limits.no_pause {
            self.stats.clamped += 1;
            return None;
        }
        if let Some(m) = self.limits.max_delay.filter(|&m| d > m) {
            d = m;
            self.stats.clamped += 1;
        }
        self.stats.stall_spent = self.stats.stall_spent.saturating_add(d);
        Some(later(now, d))
    }

    /// Reports an injection that will not go. An answer that keeps it is tried again a
    /// granularity later, not at once.
    fn dropped(&mut self, i: usize, us: u64, record: usize) {
        self.stats.inject_dropped += 1;
        self.pipes[i].inject_due = false;
        let e = Event::new(EventKind::InjectDropped, PipeId(self.pipes[i].pipe), us);
        self.event(i, e, record);
        let next = us.saturating_add(GRANULARITY.as_micros() as u64);
        if let Some(x) = self.pipes[i].inject.as_mut().filter(|x| x.at < next) {
            x.at = next;
        }
    }

    /// Whether the records of `pipe` are shaped: its instance of the
    /// current generation has a shaper, or the factory would install one
    /// for it (a factory may return none for a pipe: then it is counted as
    /// shaped until it was asked).
    pub(super) fn shaped(&self, pipe: u64) -> bool {
        match self.index(pipe) {
            Some(i) if self.pipes[i].generation == self.generation => {
                self.pipes[i].shaper.is_some()
            }
            _ => self.factory.is_some(),
        }
    }

    pub(super) fn held(&self, pipe: u64, now: Instant) -> bool {
        let us = self.micros(now);
        self.index(pipe)
            .is_some_and(|i| self.pipes[i].held(now, us))
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
        t.max(now + GRANULARITY)
    }

    pub(super) fn weight(&self, pipe: u64) -> Option<Option<u32>> {
        let p = &self.pipes[self.index(pipe)?];
        p.shaper.is_some().then_some(p.weight)
    }

    /// Stream data room of a batch by the gate: `None` unbounded.
    fn room(&mut self, i: usize, now: Instant) -> Option<u64> {
        let us = self.micros(now);
        let p = &mut self.pipes[i];
        if p.bucket.rate == 0 {
            self.settle_held(i, us);
        } else {
            p.bucket.fill(us);
            match (p.bucket.held(), p.held_since) {
                (true, None) => p.held_since = Some(us),
                (false, Some(_)) => self.settle_held(i, us),
                _ => {}
            }
        }
        let p = &self.pipes[i];
        if p.held(now, us) {
            return Some(0);
        }
        if p.bucket.rate == 0 {
            return None;
        }
        Some(p.bucket.tokens.max(0) as u64)
    }

    /// The earliest shaping deadline; `data` whether stream data waits,
    /// `ack` the deadline of a PIPE_ACK a pipe's next record carries.
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
            if data && p.held(now, us) {
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
            if p.shaper.is_some()
                && let Some(w) = p.wake.filter(|w| *w <= t)
            {
                self.event(i, Event::new(EventKind::Wake, PipeId(p.pipe), t), record);
                // Not replaced: not again at once, or the deadline stays in the past.
                let p = &mut self.pipes[i];
                if p.wake == Some(w) {
                    p.wake = Some(t.saturating_add(GRANULARITY.as_micros() as u64));
                }
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

    pub(super) fn record_in(&mut self, e: Event, record: usize) {
        if let Some(i) = self.index(e.pipe.0)
            && self.pipes[i].caps.contains(Caps::RECORD_IN)
        {
            self.event(i, e, record);
        }
    }

    /// Ends shaping of a pipe whose outbound direction failed.
    pub(super) fn pipe_failed(&mut self, pipe: u64, now: Instant) {
        if let Some(i) = self.index(pipe) {
            let e = Event::new(EventKind::PipeFailed, PipeId(pipe), self.micros(now));
            self.event(i, e, 0);
            self.pipes.swap_remove(i);
        }
    }
}

/// The shaping state lent to a batch.
pub(super) struct ShapeTx {
    s: Box<Shaping>,
    i: usize,
    pipe: u64,
    lane: u64,
    now: Instant,
    /// The carrier's write overhead.
    overhead: usize,
    /// The deadline of a PIPE_ACK the batch's records carry: a shaping
    /// delay ends there.
    ack: Option<Instant>,
    /// The largest frames length of the open plan; 0: none.
    cut: usize,
    /// Stream data room by the gate; `None`: unbounded.
    pub(super) room: Option<u64>,
    /// Stream data bytes written.
    pub(super) spent: u64,
    /// Stream data waits for the rest of the batch.
    pub(super) data_held: bool,
    /// The batch ended at a record (`flush`).
    pub(super) closed: bool,
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
fn later(now: Instant, d: Duration) -> Instant {
    const FAR: Duration = Duration::from_secs(1 << 32);
    now.checked_add(d)
        .or_else(|| now.checked_add(FAR))
        .unwrap_or(now)
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
            let effects = std::mem::take(&mut plan.effects);
            let delay = plan.delay;
            s.pipes[i].plan = Some(plan);
            if !effects.is_empty() {
                s.apply(i, &effects, now, limit);
                self.regate();
                if self.s.pipes[i].shaper.is_none() {
                    return limit;
                }
            }
            let s = &mut *self.s;
            s.pipes[i].delay_until = s.pause(delay, now);
        }
        let s = &mut *self.s;
        if s.pipes[i].delayed(now, self.ack) {
            // The whole record, control frames included, waits.
            self.delayed = true;
            return limit;
        }
        let plan = s.pipes[i].plan.as_mut().expect("planned");
        let (most, raised) = wire.frames_max(plan);
        if raised && fresh {
            s.stats.clamped += 1;
        }
        self.cut = if most > 0 && most < limit { most } else { 0 };
        if self.cut > 0 { self.cut } else { limit }
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
        self.room = self.s.room(self.i, self.now);
        self.data_held = self.room == Some(0);
    }

    /// A preamble beyond the plan's largest record opens the record anyway.
    pub(super) const fn count_clamped(&mut self) {
        self.s.stats.clamped += 1;
    }

    /// The open plan's largest frames length, or `limit`.
    pub(super) fn cut_or(&self, limit: usize) -> usize {
        if self.cut > 0 { self.cut } else { limit }
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
        s.wire.frames(n, p) - n + s.added
    }

    /// The most frames bytes the planned record may hold so that, padded
    /// to its target, it fits in `total` bytes of body; `None` when the
    /// target itself does not fit (or nothing is planned: no bound).
    pub(super) fn frames_bound(&self, total: usize) -> Option<usize> {
        let Some(p) = self.planned() else {
            return Some(usize::MAX);
        };
        let (wire, added) = (self.s.pipes[self.i].wire, self.s.pipes[self.i].added);
        let total = total.checked_sub(added)?;
        if p.pad_to == 0 && p.pad_multiple == 0 && p.pad == 0 {
            return Some(total);
        }
        let mut b = wire.wire(total).checked_sub(p.pad)?;
        if p.pad_multiple > 0 {
            b -= b % p.pad_multiple;
        }
        (b >= p.pad_to).then(|| wire.frames_within(b))
    }

    /// Closes the plan of a record that is ending with `len` frames bytes
    /// and `avail` bytes of room; returns the PADDING to add.
    pub(super) fn end_record(&mut self, len: usize, avail: usize) -> usize {
        if self.planned().is_none() || len == 0 {
            return 0;
        }
        let mut pad = self.padding_for(len);
        if pad > avail {
            pad = avail;
            self.s.stats.clamped += 1;
        }
        let s = &mut *self.s;
        let p = &s.pipes[self.i];
        if self.cut > 0 && len >= self.cut {
            // Cut at the plan's largest record: the next record's head.
            s.account.spend((p.wire.wire(self.cut) - self.cut) as u64);
        }
        s.account.spend(pad.saturating_sub(p.added_paid) as u64);
        let p = &mut self.s.pipes[self.i];
        let plan = p.plan.take().expect("planned");
        p.added = 0;
        p.added_paid = 0;
        p.delay_until = None;
        p.seq += 1;
        self.cut = 0;
        if plan.flush {
            self.closed = true;
        }
        if plan.stop {
            self.s.stop(self.i, true, self.now);
            self.regate();
        }
        pad
    }
}

impl SessionCore {
    /// The factory installed on every outbound pipe (the configured one or
    /// the last [`Self::set_shaper`]); `None`: no shaping.
    pub fn shaper(&self) -> Option<Arc<dyn Factory>> {
        self.shape.as_deref()?.factory.clone()
    }

    /// Installs `factory` on every outbound pipe, with no configuration budget; `None`: no
    /// shaping. The account carries over.
    pub fn set_shaper(&mut self, factory: Option<Arc<dyn Factory>>) {
        self.set_shaper_budgeted(factory, Budget::default());
    }

    /// Installs `factory` as [`Self::set_shaper`] does, under `budget`, one session's
    /// answer of a [`super::shaping::ShapingBudget`].
    pub fn set_shaper_budgeted(&mut self, factory: Option<Arc<dyn Factory>>, budget: Budget) {
        self.shape_budget = budget;
        let limits = self.shaping_limits_in_force();
        let now = self.now;
        self.shaping().set_limits(limits, now);
        self.install_shaper(factory);
    }

    pub(super) fn install_shaper(&mut self, factory: Option<Arc<dyn Factory>>) {
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
            s.active(p, now, record);
        }
    }

    /// Replaces the session's local limits, tighter or looser; invalid ones change
    /// nothing. The account's spending carries over.
    pub fn set_shaping_limits(&mut self, limits: Limits) -> Result<(), crate::InvalidConfig> {
        limits.validate()?;
        Arc::make_mut(&mut self.config).shaping_limits = limits;
        let eff = self.shaping_limits_in_force();
        let now = self.now;
        self.shaping().set_limits(eff, now);
        Ok(())
    }

    /// The session's local limits.
    pub fn shaping_limits(&self) -> Limits {
        self.config.shaping_limits
    }

    /// The local limits under the budget.
    pub fn shaping_limits_in_force(&self) -> Limits {
        self.config.shaping_limits.under(&self.shape_budget)
    }

    /// The session's readings.
    pub fn shaping_meters(&mut self) -> Meters {
        let now = self.now;
        let s = self.shaping();
        let us = s.micros(now);
        s.meters(us)
    }

    /// Meters wire bytes of an accompanying action.
    pub(super) fn shaping_spend(&mut self, n: u64) {
        if n > 0 {
            self.shaping().account.spend(n);
        }
    }

    /// Meters the padding of a handshake run on the carrier before the session.
    pub fn shaping_spend_handshake(&mut self, n: u64) {
        self.shaping_spend(n);
    }

    /// Counts a batch of `bytes` as earned, but for its padding, injections and copies
    /// and what a discarded first flight already earned.
    pub(super) fn count_earned(&mut self, bytes: u64) {
        let earned = bytes.saturating_sub(std::mem::take(&mut self.batch_not_earned));
        let skip = earned.min(self.earn_skip);
        self.earn_skip -= skip;
        self.earn_bytes += earned - skip;
        if let Some(s) = self.shape.as_deref_mut() {
            s.earn = self.earn_bytes;
        }
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
        self.att(pipe.0).and_then(|a| a.carrier())
    }

    /// Installs `shaper` on an outbound pipe until the next
    /// [`SessionCore::set_shaper`]; `None`: the pipe is not shaped. `false`
    /// when the pipe has no outbound direction.
    pub fn set_pipe_shaper(&mut self, pipe: PipeId, shaper: Option<Box<dyn Shaper>>) -> bool {
        if self.out_ref(pipe.0).is_none() {
            return false;
        }
        let (record, now) = (self.max_record(), self.now);
        self.shaping().install(pipe.0, shaper, now, record);
        true
    }

    /// The shaping counters.
    pub fn shaping_stats(&self) -> Stats {
        let mut stats = Stats::default();
        if let Some(s) = self.shape.as_ref() {
            stats = s.stats;
            stats.wire_spent = s.account.spent;
        }
        stats.handshake_unplanned = self.join_shaping.unplanned;
        stats.faults += self.join_shaping.faults;
        stats
    }

    fn shaping(&mut self) -> &mut Shaping {
        let limits = self.shaping_limits_in_force();
        let (base, earn) = (self.started, self.earn_bytes);
        self.shape
            .get_or_insert_with(|| Box::new(Shaping::new(limits, base, earn)))
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
        let mut s = self.shape.take()?;
        let Some(i) = s.active(shaped, now, limit) else {
            self.shape = Some(s);
            return None;
        };
        let room = s.room(i, now);
        let gates = s.pipes[i].gates;
        let ack = self.ack_release(id);
        self.shape_pending = Some(Vec::new());
        Some(ShapeTx {
            s,
            i,
            pipe: id,
            lane,
            now,
            overhead,
            ack,
            cut: 0,
            room,
            spent: 0,
            data_held: room == Some(0),
            closed: false,
            delayed: false,
            gates,
            gate_spent: 0,
        })
    }

    /// Takes the shaping state back from a batch.
    pub(super) fn shape_return(&mut self, w: &mut Records<'_>) {
        let Some(mut t) = w.shape.take() else {
            return;
        };
        let p = &mut t.s.pipes[t.i];
        if p.bucket.rate > 0 {
            p.bucket.tokens -= (t.spent - t.gate_spent) as i64;
        }
        let record = w.max_record();
        let mut s = t.s;
        for (kind, stream) in self.shape_pending.take().unwrap_or_default() {
            let e = Event::new(kind, PipeId(0), s.micros(self.now)).with_stream(stream);
            s.broadcast(Caps::STREAMS, e, record);
        }
        self.shape = Some(s);
    }

    /// Sends a due injection on lane 0 of the batch's pipe: as PADDING of the open record,
    /// or as a record of PADDING only within the limit on such records (16 per second) toward
    /// a peer not known to be a zmux endpoint. What a limit, the account or that rule refuses is
    /// dropped; only a batch without room defers it, before anything is charged.
    pub(super) fn shape_inject(&mut self, w: &mut Records<'_>) {
        let record = w.max_record();
        let Some(t) = w.shape.as_mut() else {
            return;
        };
        let (i, now) = (t.i, t.now);
        let p = &t.s.pipes[i];
        if t.lane != 0 || !p.inject_due || p.delayed(now, t.ack) {
            return;
        }
        let Some(x) = p.inject else {
            t.s.pipes[i].inject_due = false;
            return;
        };
        // An injection is one write of its own.
        let wire = RecordWire {
            size_field: !w.out.is_records(),
            overhead: t.overhead,
        };
        let n = wire.frames_of(x.len).max(1);
        let pipe = PipeId(t.pipe);
        let clock = t.s.micros(now);
        let injected = |n| Event::new(EventKind::Injected, pipe, clock).with_len(n, false);
        let off = t.s.limits.no_injection || t.s.limits.no_padding;
        // Into the open record only where it fits whole, its planned
        // PADDING included; else a record of its own.
        let len = w.out.record_len();
        // `n` is a shaper's, of any size, until it is cut below.
        let fits = |pad: usize| {
            pad.saturating_add(n) <= t.cut_or(record).saturating_sub(len)
                && pad.saturating_add(n) <= w.out.room()
        };
        if w.out.in_record() && len > 0 && fits(t.padding_for(len)) && t.s.pipes[i].plan.is_some() {
            let earn = t.s.earn;
            if off || !t.s.account.charge(clock, earn, n as u64) {
                t.s.dropped(i, clock, record);
            } else {
                let p = &mut t.s.pipes[i];
                p.added += n;
                p.added_paid += n;
                p.inject_due = false;
                t.s.event(i, injected(n), record);
            }
            t.regate();
            return;
        }
        w.end_record();
        let limited = self.peer_tp.as_ref().is_none_or(|p| p.plain_qmux);
        let Some(t) = w.shape.as_mut() else {
            return;
        };
        if limited && self.requests.available(now) < 2 || off {
            t.s.dropped(i, clock, record);
            t.regate();
            return;
        }
        if t.closed {
            // The record before it closed the batch (its plan flushes):
            // the injection goes first in the next batch.
            return;
        }
        // A record holds at most `record` bytes: a longer injection is cut
        // to it. One that does not fit in what remains of this batch goes
        // whole, first, in the next one; only a batch that has nothing in
        // it yet cuts it to its room.
        let mut n = n;
        let mut cuts = 0;
        if n > record {
            n = record;
            cuts += 1;
        }
        let room = w.out.room().saturating_sub(w.out.size_width(record));
        if n > room {
            if !w.out.is_empty() {
                return;
            }
            n = room;
            cuts += 1;
        }
        t.s.stats.clamped += cuts;
        let earn = t.s.earn;
        // What goes on the wire: the write overhead is the batch's first record's.
        let actual = RecordWire {
            overhead: if w.out.is_records() || w.out.is_empty() {
                t.overhead
            } else {
                0
            },
            ..wire
        };
        if n == 0 || !t.s.account.charge(clock, earn, actual.wire(n) as u64) {
            t.s.dropped(i, clock, record);
            t.regate();
            return;
        }
        t.s.pipes[i].inject_due = false;
        t.s.stats.injected += 1;
        t.s.event(i, injected(n), record);
        t.regate();
        w.padding_record(n);
        if limited {
            self.requests.record(now);
        }
    }

    /// Whether the records of pipe `id` are shaped (outside a batch).
    pub(super) fn shape_shaped(&self, id: u64) -> bool {
        self.shape.as_deref().is_some_and(|s| s.shaped(id))
    }

    /// Whether pipe `id` has an injection due.
    pub(super) fn shape_wants(&self, id: u64) -> bool {
        self.shape.as_deref().is_some_and(|s| s.inject_due(id))
    }

    /// Whether the planned record of pipe `id` waits for its delay: the
    /// pipe sends nothing but CONNECTION_CLOSE until then.
    pub(super) fn shape_delayed(&self, id: u64) -> bool {
        self.shape
            .as_deref()
            .is_some_and(|s| s.delayed(id, self.now, self.ack_release(id)))
    }

    /// Whether the gate of pipe `id` holds stream data now.
    pub(super) fn shape_held(&self, id: u64) -> bool {
        self.shape.as_deref().is_some_and(|s| s.held(id, self.now))
    }

    pub(super) fn shape_deadline(&self) -> Option<Instant> {
        let s = self.shape.as_deref()?;
        s.deadline(self.now, self.data_pending(), |id| self.ack_release(id))
    }

    pub(super) fn shape_timeout(&mut self, now: Instant) {
        let record = self.max_record();
        if let Some(s) = self.shape.as_deref_mut() {
            s.timeout(now, record);
        }
    }

    /// Reports a received record of `len` frames bytes on lane `lane` of
    /// pipe `id`.
    pub(super) fn shape_record_in(&mut self, id: u64, lane: u64, len: usize, padding_only: bool) {
        let (record, now) = (self.max_record(), self.now);
        if let Some(s) = self.shape.as_deref_mut() {
            let e = Event::new(EventKind::RecordIn, PipeId(id), s.micros(now))
                .with_lane(lane)
                .with_len(len, padding_only);
            s.record_in(e, record);
        }
    }

    pub(super) fn shape_pipe_failed(&mut self, id: u64) {
        let now = self.now;
        if let Some(s) = self.shape.as_deref_mut() {
            s.pipe_failed(id, now);
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
    /// Closes a batch, taking a lent shaping state back.
    pub(super) fn shape_finish(&mut self, mut w: Records<'_>) -> u64 {
        if w.shape.is_some() {
            w.end_record();
            self.shape_return(&mut w);
        }
        self.batch_not_earned = w.not_earned;
        w.finish()
    }
}

impl Records<'_> {
    /// Writes a record of `n` bytes of PADDING.
    pub(super) fn padding_record(&mut self, n: usize) {
        self.end_record();
        self.out.begin_record(self.max_record());
        self.padding(n);
        self.end_plain();
        if !self.out.is_records() {
            self.not_earned += super::shaping::varint_len(n as u64) as u64;
        }
    }

    /// PADDING bytes.
    pub(super) fn padding(&mut self, n: usize) {
        if n > 0 {
            self.payload(Bytes::from_static(&ZERO[..n]));
            self.not_earned += n as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shaping::Account;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn shaping(limits: Limits) -> Shaping {
        Shaping::new(limits, Instant::now(), 0)
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
            if e.kind == EventKind::Wake {
                self.0.fetch_add(1, Ordering::SeqCst);
                if let Some(at) = self.1 {
                    r.wake = Some(Some(at));
                }
            }
        }
    }

    #[test]
    fn hold_bound_follows_the_bound_on_one_wait() {
        let limits = |max_delay, no_pause| Limits {
            max_delay,
            no_pause,
            ..Limits::default()
        };
        let ms = Duration::from_millis;
        let default = Limits::default().max_delay;
        assert_eq!(shaping(limits(default, false)).hold_bound(), ms(1000));
        assert_eq!(shaping(limits(Some(ms(300)), false)).hold_bound(), ms(300));
        assert_eq!(shaping(limits(None, false)).hold_bound(), ms(0));
        assert_eq!(shaping(limits(default, true)).hold_bound(), ms(0));
    }

    #[test]
    fn an_unanswered_wake_comes_again_one_granularity_later() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut s = shaping(Limits::default());
        pipe(&mut s, Waked(calls.clone(), None));
        s.pipes[0].wake = Some(1_000);
        let now = s.base + Duration::from_millis(5);
        s.timeout(now, 1200);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The deadline is ahead of the clock, and a second look at this time sends nothing.
        assert_eq!(s.deadline(now, false, |_| None), Some(now + GRANULARITY));
        s.timeout(now, 1200);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        s.timeout(now + GRANULARITY, 1200);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // A time the shaper set stays, the same one included.
        s.pipes[0].shaper = Some(Box::new(Waked(calls.clone(), Some(50_000))));
        s.pipes[0].wake = Some(1_000);
        s.timeout(now, 1200);
        assert_eq!(s.pipes[0].wake, Some(50_000));
    }

    fn pause_to(s: &mut Shaping, until: u64, now: Instant) {
        let e = Effects {
            gate: Some(crate::shaping::Gate::new(until, 0, 0)),
            ..Effects::default()
        };
        s.apply(0, &e, now, 1000);
    }

    /// An answer repeats its `pause_until`, and the bound may have shortened that pause:
    /// it is taken and counted once, and only what extends it counts afterwards.
    #[test]
    fn repeated_pauses_count_once() {
        let mut s = shaping(Limits {
            max_delay: Some(Duration::from_millis(100)),
            ..Limits::default()
        });
        pipe(&mut s, Waked(Arc::default(), None));
        let now = s.base;
        pause_to(&mut s, 500_000, now);
        assert_eq!(s.stats.stall_spent, Duration::from_millis(100));
        assert_eq!(s.pipes[0].hold, Some(now + Duration::from_millis(100)));
        assert_eq!(s.stats.clamped, 1);
        for _ in 0..5 {
            pause_to(&mut s, 500_000, now);
        }
        assert_eq!(s.stats.stall_spent, Duration::from_millis(100));
        assert_eq!(s.stats.clamped, 1);
        // 10 ms beyond what was asked: 10 ms beyond the current end.
        pause_to(&mut s, 510_000, now);
        assert_eq!(s.stats.stall_spent, Duration::from_millis(110));
        assert_eq!(s.pipes[0].hold, Some(now + Duration::from_millis(110)));
    }

    /// A shaper's times take a duration of any size.
    #[test]
    fn the_longest_duration_does_not_panic() {
        let now = Instant::now();
        assert!(later(now, Duration::MAX) > now);
        let mut s = shaping(Limits {
            max_delay: Some(Duration::MAX),
            ..Limits::default()
        });
        assert!(s.pause(Duration::MAX, now).is_some_and(|t| t > now));
    }

    #[test]
    fn switches_and_the_default_bound_reduce_a_pause() {
        let now = Instant::now();
        let five = Duration::from_secs(5);
        let mut s = shaping(Limits::default());
        assert_eq!(s.pause(five, now), Some(now + Duration::from_secs(1)));
        assert_eq!(s.stats.clamped, 1);
        let mut s = shaping(Limits {
            no_pause: true,
            ..Limits::default()
        });
        assert_eq!(s.pause(five, now), None);
        assert_eq!(s.stats.stall_spent, Duration::ZERO);
    }

    /// Keeps an injection in the slot, whatever happens to it.
    struct Keeps;

    impl Shaper for Keeps {
        fn capabilities(&self) -> Caps {
            Caps::default()
        }
    }

    /// A dropped injection the answer keeps comes again a granularity later, not at once.
    #[test]
    fn a_kept_dropped_injection_waits_one_granularity() {
        let mut s = shaping(Limits {
            wire: Account::new(1, 0, 0),
            ..Limits::default()
        });
        pipe(&mut s, Keeps);
        s.pipes[0].inject = Some(Injection::new(0, 100));
        s.pipes[0].inject_due = true;
        s.dropped(0, 5_000, 1200);
        assert_eq!(s.stats.inject_dropped, 1);
        assert!(!s.pipes[0].inject_due);
        assert_eq!(s.pipes[0].inject.map(|x| x.at), Some(6_000));
    }
}
