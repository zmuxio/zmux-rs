//! Executes the [`Shaper`]s of the outbound pipes within the protocol's
//! limits and the session's [`Limits`]. Nothing here exists until a
//! factory or instance is set: the paths that consult it test
//! `SessionCore::shape` for `None`.
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
use super::shaping::{
    Caps, Event, EventKind, Factory, Inject, Limits, MIN_MAX_LEN, RecordPlan, RecordView, Reply,
    STARTUP_ALLOWANCE, ShapedPipe, Shaper, Stats, Timer,
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
    limits: Limits,
    pub(super) stats: Stats,
    pipes: Vec<PipeShape>,
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
    /// The planned record's earliest send time (`RecordPlan::delay`):
    /// until then the pipe sends nothing but CONNECTION_CLOSE, and the
    /// frames owed meanwhile wait in that record.
    delay_until: Option<Instant>,
    /// Stream data waits until then (a gate's pause).
    hold: Option<Instant>,
    /// Gates applied: a batch that sees it change takes the new gate's
    /// room.
    gates: u64,
    rate: u64,
    burst: u64,
    tokens: f64,
    filled: Instant,
    inject: Option<(Instant, usize)>,
    inject_due: bool,
    timers: [Option<Instant>; 2],
    weight: Option<f64>,
}

impl PipeShape {
    fn new(pipe: u64, generation: u64, now: Instant) -> Self {
        Self {
            pipe,
            generation,
            shaper: None,
            caps: Caps::NONE,
            seq: 0,
            plan: None,
            delay_until: None,
            hold: None,
            gates: 0,
            rate: 0,
            burst: 0,
            tokens: 0.0,
            filled: now,
            inject: None,
            inject_due: false,
            timers: [None; 2],
            weight: None,
        }
    }

    /// The bucket level at `now`.
    fn tokens_at(&self, now: Instant) -> f64 {
        let dt = now.saturating_duration_since(self.filled).as_secs_f64();
        (self.tokens + self.rate as f64 * dt).min(self.burst as f64)
    }

    /// The level that releases a held pipe: one granularity's bytes.
    fn quantum(&self) -> f64 {
        (self.rate as f64 * GRANULARITY.as_secs_f64())
            .min(self.burst as f64)
            .max(1.0)
    }

    /// Whether the planned record waits for its delay.
    fn delayed(&self, now: Instant) -> bool {
        self.shaper.is_some() && self.plan.is_some() && self.delay_until.is_some_and(|t| now < t)
    }

    fn held(&self, now: Instant) -> bool {
        self.shaper.is_some()
            && (self.hold.is_some_and(|h| now < h)
                || self.rate > 0 && self.tokens_at(now) < self.quantum())
    }

    /// When a held pipe is released.
    fn release(&self, now: Instant) -> Instant {
        let mut t = self.hold.unwrap_or(now);
        let tokens = self.tokens_at(now);
        if self.rate > 0 && tokens < self.quantum() {
            let wait = (self.quantum() - tokens) / self.rate as f64;
            t = t.max(now + Duration::from_secs_f64(wait) + Duration::from_nanos(1));
        }
        t.max(now + GRANULARITY)
    }
}

impl Shaping {
    /// H_p (MULTIPATH.md Section 7.1): the longest the next pause may
    /// last, the smaller of `Limits::max_delay` and what remains of
    /// `Limits::max_pause_total` (each counted only when set); zero when
    /// neither is set.
    pub(super) fn hold_bound(&self) -> Duration {
        let l = &self.limits;
        let per = l.max_delay;
        let rest = l
            .max_pause_total
            .map(|t| t.saturating_sub(self.stats.pause_total));
        match (per, rest) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => Duration::ZERO,
        }
    }

    /// H_p of `pipe` (MULTIPATH.md Section 7.1): [`Self::hold_bound`] for a
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

    pub(super) fn new(limits: Limits) -> Self {
        Self {
            factory: None,
            generation: 0,
            limits,
            stats: Stats::default(),
            pipes: Vec::new(),
        }
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
                self.event(
                    i,
                    Event::new(EventKind::Replaced, PipeId(pipe), now),
                    record,
                );
                self.pipes[i] = PipeShape::new(pipe, self.generation, now);
                i
            }
            None => {
                self.pipes.push(PipeShape::new(pipe, self.generation, now));
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
            self.event(i, Event::new(EventKind::Start, PipeId(pipe), now), record);
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
        let filled = self.pipes[i].filled;
        self.stop(i, false, filled);
        false
    }

    fn stop(&mut self, i: usize, notify: bool, now: Instant) {
        let p = &self.pipes[i];
        if p.shaper.is_none() {
            return;
        }
        if notify {
            let e = Event::new(EventKind::Stopped, PipeId(p.pipe), now);
            self.call(i, |x| x.on_event(&e, &mut Reply::default()));
        }
        let (pipe, generation) = (self.pipes[i].pipe, self.pipes[i].generation);
        self.pipes[i] = PipeShape::new(pipe, generation, now);
    }

    /// Delivers a notification and applies the reply.
    fn event(&mut self, i: usize, e: Event, record: usize) {
        let mut r = Reply::default();
        if !self.call(i, |x| x.on_event(&e, &mut r)) {
            return;
        }
        if !matches!(
            e.kind,
            EventKind::Replaced | EventKind::Stopped | EventKind::PipeFailed
        ) {
            self.apply(i, &r, e.now, record);
        }
    }

    fn apply(&mut self, i: usize, r: &Reply, now: Instant, record: usize) {
        if let Some(inject) = r.inject {
            let p = &mut self.pipes[i];
            p.inject = None;
            p.inject_due = false;
            if let Inject::Send { after, len } = inject {
                p.inject = Some((now + after, len.max(1)));
            }
        }
        if let Some(g) = r.gate {
            let hold = self.pause(g.pause, now);
            let p = &mut self.pipes[i];
            p.hold = hold;
            p.rate = g.rate;
            p.burst = if g.burst == 0 { record as u64 } else { g.burst };
            p.tokens = p.burst as f64;
            p.filled = now;
            p.gates += 1;
        }
        for (slot, t) in self.pipes[i].timers.iter_mut().zip(&r.timers) {
            match t {
                Some(Timer::After(d)) => *slot = Some(now + *d),
                Some(Timer::Cancel) => *slot = None,
                None => {}
            }
        }
        if let Some(w) = r.weight.filter(|w| w.is_finite() && *w > 0.0) {
            self.pipes[i].weight = Some(w);
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
        let l = self.limits;
        if let Some(m) = l.max_delay.filter(|&m| d > m) {
            d = m;
            self.stats.clamped += 1;
        }
        if let Some(m) = l
            .max_pause_total
            .filter(|&m| d > m.saturating_sub(self.stats.pause_total))
        {
            d = m.saturating_sub(self.stats.pause_total);
            self.stats.clamped += 1;
        }
        if d.is_zero() {
            return None;
        }
        self.stats.pause_total = self.stats.pause_total.saturating_add(d);
        Some(now + d)
    }

    /// The PADDING bytes the limits still allow, `sent` the session's
    /// bytes sent: by `max_padding_bytes` (a hard bound) and by
    /// `max_padding_ratio`, with the [`STARTUP_ALLOWANCE`] at least;
    /// `u64::MAX`: unbounded.
    fn padding_room(&self, sent: u64) -> (u64, u64) {
        let l = self.limits;
        let have = self.stats.padding_bytes;
        let mut hard = u64::MAX;
        let mut ratio = u64::MAX;
        if let Some(b) = l.max_padding_bytes {
            hard = b.saturating_sub(have);
        }
        if let Some(r) = l.max_padding_ratio {
            let other = sent.saturating_sub(have);
            let m = ((r * other as f64) as u64).max(STARTUP_ALLOWANCE);
            ratio = m.saturating_sub(have);
        }
        (hard, ratio)
    }

    /// Whether an injection of `n` bytes may go now: the ratio allows it
    /// whole, or a hard bound, which cuts it, binds first.
    fn inject_covered(&self, n: usize, sent: u64) -> bool {
        let (hard, ratio) = self.padding_room(sent);
        ratio >= n as u64 || hard <= ratio
    }

    /// Bounds `n` bytes of PADDING by the limits and counts them; `sent`
    /// is the session's bytes sent.
    fn allow_padding(&mut self, n: usize, sent: u64) -> usize {
        let (hard, ratio) = self.padding_room(sent);
        let u = (n as u64).min(hard).min(ratio);
        if u < n as u64 {
            self.stats.clamped += 1;
        }
        self.stats.padding_bytes += u;
        u as usize
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
        self.index(pipe).is_some_and(|i| self.pipes[i].held(now))
    }

    pub(super) fn delayed(&self, pipe: u64, now: Instant) -> bool {
        self.index(pipe).is_some_and(|i| self.pipes[i].delayed(now))
    }

    /// Whether `pipe` has an injection due that the limits let go now.
    pub(super) fn inject_due(&self, pipe: u64, sent: u64) -> bool {
        self.index(pipe).is_some_and(|i| {
            let p = &self.pipes[i];
            p.inject_due && p.inject.is_none_or(|(_, n)| self.inject_covered(n, sent))
        })
    }

    pub(super) fn weight(&self, pipe: u64) -> Option<Option<f64>> {
        let p = &self.pipes[self.index(pipe)?];
        p.shaper.is_some().then_some(p.weight)
    }

    /// Stream data room of a batch by the gate: `None` unbounded.
    fn room(&mut self, i: usize, now: Instant) -> Option<u64> {
        let p = &mut self.pipes[i];
        if p.held(now) {
            return Some(0);
        }
        if p.rate == 0 {
            return None;
        }
        p.tokens = p.tokens_at(now);
        p.filled = now;
        Some(p.tokens as u64)
    }

    /// The earliest shaping deadline; `data` whether stream data waits.
    pub(super) fn deadline(&self, now: Instant, data: bool) -> Option<Instant> {
        let mut t: Option<Instant> = None;
        let mut at = |x: Instant| t = Some(t.map_or(x, |t| t.min(x)));
        for p in self.pipes.iter().filter(|p| p.shaper.is_some()) {
            p.timers.iter().flatten().for_each(|&x| at(x));
            if let Some((x, _)) = p.inject.filter(|_| !p.inject_due) {
                at(x);
            }
            if p.delayed(now) {
                // Exactly: the delayed record goes at its time.
                at(p.delay_until.expect("delayed"));
            }
            if data && p.held(now) {
                at(p.release(now));
            }
        }
        t
    }

    /// Runs the due timers and injections.
    pub(super) fn timeout(&mut self, now: Instant, record: usize) {
        for i in 0..self.pipes.len() {
            for slot in 0..2 {
                let p = &mut self.pipes[i];
                if p.shaper.is_none() || p.timers[slot].is_none_or(|t| t > now) {
                    continue;
                }
                p.timers[slot] = None;
                let e = Event::new(EventKind::Timer, PipeId(p.pipe), now).with_timer(slot);
                self.event(i, e, record);
            }
            let p = &mut self.pipes[i];
            if p.shaper.is_some() && !p.inject_due && p.inject.is_some_and(|(t, _)| t <= now) {
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
            self.event(i, Event::new(EventKind::PipeFailed, PipeId(pipe), now), 0);
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
    /// The session's bytes sent before the batch.
    sent: u64,
    /// `max_len` of the open plan; 0: none.
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

impl ShapeTx {
    /// Plans the record that opens next, the first of a carrier write call
    /// when `write_start`; returns its largest frames length.
    pub(super) fn prep(&mut self, limit: usize, write_start: bool) -> usize {
        let now = self.now;
        let s = &mut *self.s;
        let i = self.i;
        if s.pipes[i].shaper.is_none() {
            return limit;
        }
        if s.pipes[i].plan.is_none() {
            let mut plan = RecordPlan::default();
            if s.pipes[i].caps.contains(Caps::PLAN) {
                let v = RecordView::new(PipeId(self.pipe), self.lane, s.pipes[i].seq, limit, now)
                    .with_write_start(write_start);
                if !s.call(i, |x| x.plan(&v, &mut plan)) {
                    return limit;
                }
            }
            if plan.max_len > 0 && plan.max_len < MIN_MAX_LEN {
                plan.max_len = MIN_MAX_LEN;
                s.stats.clamped += 1;
            }
            // No padding target goes beyond a record, so that the padding
            // arithmetic cannot overflow.
            for f in [&mut plan.pad_to, &mut plan.pad_multiple, &mut plan.pad] {
                if *f > limit {
                    *f = limit;
                    s.stats.clamped += 1;
                }
            }
            let reply = std::mem::take(&mut plan.reply);
            let delay = plan.delay;
            s.pipes[i].plan = Some(plan);
            if !reply.is_empty() {
                s.apply(i, &reply, now, limit);
                self.regate();
                if self.s.pipes[i].shaper.is_none() {
                    return limit;
                }
            }
            let s = &mut *self.s;
            s.pipes[i].delay_until = s.pause(delay, now);
        }
        let s = &mut *self.s;
        if s.pipes[i].delayed(now) {
            // The whole record, control frames included, waits.
            self.delayed = true;
            return limit;
        }
        let plan = s.pipes[i].plan.as_ref().expect("planned");
        self.cut = match plan.max_len {
            m if m > 0 && m < limit => m.max(MIN_MAX_LEN),
            _ => 0,
        };
        if self.cut > 0 { self.cut } else { limit }
    }

    /// After a gate was applied during the batch (a plan's or an event's
    /// reply), the stream data room is the new gate's: from its full
    /// bucket, which pays only for the data written after it.
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
        let mut t = n.max(p.pad_to);
        if p.pad_multiple > 0 && t % p.pad_multiple != 0 {
            t += p.pad_multiple - t % p.pad_multiple;
        }
        t - n + p.pad
    }

    /// The most frames bytes the planned record may hold so that, padded
    /// to its target, it fits in `total` bytes of body; `None` when the
    /// target itself does not fit (or nothing is planned: no bound).
    pub(super) fn frames_bound(&self, total: usize) -> Option<usize> {
        let Some(p) = self.planned() else {
            return Some(usize::MAX);
        };
        let mut b = total.checked_sub(p.pad)?;
        if p.pad_multiple > 0 {
            b -= b % p.pad_multiple;
        }
        (b >= p.pad_to).then_some(b)
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
        let pad = self.s.allow_padding(pad, self.sent);
        let p = &mut self.s.pipes[self.i];
        let plan = p.plan.take().expect("planned");
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
    /// Installs `factory` on every outbound pipe; `None`: no shaping.
    pub fn set_shaper(&mut self, factory: Option<Arc<dyn Factory>>) {
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
    /// carrier ([`crate::Verdict::Accept`]), opaque to the core, for as
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
        self.shape.as_ref().map(|s| s.stats).unwrap_or_default()
    }

    fn shaping(&mut self) -> &mut Shaping {
        let limits = self.config.shaping_limits;
        self.shape
            .get_or_insert_with(|| Box::new(Shaping::new(limits)))
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
        let mut s = self.shape.take()?;
        let Some(i) = s.active(shaped, now, limit) else {
            self.shape = Some(s);
            return None;
        };
        let room = s.room(i, now);
        let gates = s.pipes[i].gates;
        self.shape_pending = Some(Vec::new());
        Some(ShapeTx {
            s,
            i,
            pipe: id,
            lane,
            now,
            sent: self.stats.bytes_sent,
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
        if p.rate > 0 {
            p.tokens -= (t.spent - t.gate_spent) as f64;
        }
        let record = w.max_record();
        let mut s = t.s;
        for (kind, stream) in self.shape_pending.take().unwrap_or_default() {
            let e = Event::new(kind, PipeId(0), self.now).with_stream(stream);
            s.broadcast(Caps::STREAMS, e, record);
        }
        self.shape = Some(s);
    }

    /// Sends a due injection on lane 0 of the batch's pipe: as PADDING of
    /// the open record, or as a record of PADDING only within the limits
    /// and, toward a peer not known to be a zmux endpoint, SPEC.md
    /// Section 13.2 rule 9 (together with QX_PING requests).
    pub(super) fn shape_inject(&mut self, w: &mut Records<'_>) {
        let record = w.max_record();
        let Some(t) = w.shape.as_mut() else {
            return;
        };
        let (i, now) = (t.i, t.now);
        let p = &mut t.s.pipes[i];
        if t.lane != 0 || !p.inject_due || p.delayed(now) {
            return;
        }
        let taken = p.inject.take();
        let n = taken.as_ref().map_or(0, |(_, n)| *n);
        p.inject_due = false;
        let pipe = PipeId(t.pipe);
        let injected = |n| Event::new(EventKind::Injected, pipe, now).with_len(n, false);
        if !t.s.inject_covered(n, t.sent) {
            // The ratio allows it later, as more is sent.
            let p = &mut t.s.pipes[i];
            p.inject = taken;
            p.inject_due = true;
            return;
        }
        // Into the open record only where it fits whole, its planned
        // PADDING included; else a record of its own.
        let len = w.out.record_len();
        let fits = |pad: usize| len + pad + n <= t.cut_or(record) && pad + n <= w.out.room();
        if w.out.in_record()
            && len > 0
            && fits(t.padding_for(len))
            && let Some(plan) = t.s.pipes[i].plan.as_mut()
        {
            plan.pad += n;
            t.s.event(i, injected(n), record);
            t.regate();
            return;
        }
        w.end_record();
        let limited = self.peer_tp.as_ref().is_none_or(|p| p.plain_qmux);
        let Some(t) = w.shape.as_mut() else {
            return;
        };
        if t.closed {
            // The record before it closed the batch (its plan flushes):
            // the injection goes first in the next batch.
            let p = &mut t.s.pipes[i];
            p.inject = taken;
            p.inject_due = true;
            return;
        }
        let max = t.s.limits.max_injected;
        if limited && self.requests.available(now) < 2
            || max.is_some_and(|m| t.s.stats.injected >= m)
        {
            t.s.stats.inject_dropped += 1;
            return;
        }
        // A record holds at most `record` bytes: a longer injection is cut
        // to it. One that does not fit in what remains of this batch goes
        // whole, first, in the next one; only a batch that has nothing in
        // it yet cuts it to its room.
        let mut n = n;
        if n > record {
            n = record;
            t.s.stats.clamped += 1;
        }
        let room = w.out.room().saturating_sub(w.out.size_width(record));
        if n > room {
            if !w.out.is_empty() {
                let p = &mut t.s.pipes[i];
                p.inject = taken.map(|(at, _)| (at, n));
                p.inject_due = true;
                return;
            }
            n = room;
            t.s.stats.clamped += 1;
        }
        let n = t.s.allow_padding(n, t.sent);
        if n == 0 {
            t.s.stats.inject_dropped += 1;
            return;
        }
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
        let sent = self.stats.bytes_sent;
        self.shape
            .as_deref()
            .is_some_and(|s| s.inject_due(id, sent))
    }

    /// Whether the planned record of pipe `id` waits for its delay: the
    /// pipe sends nothing but CONNECTION_CLOSE until then.
    pub(super) fn shape_delayed(&self, id: u64) -> bool {
        self.shape
            .as_deref()
            .is_some_and(|s| s.delayed(id, self.now))
    }

    /// Whether the gate of pipe `id` holds stream data now.
    pub(super) fn shape_held(&self, id: u64) -> bool {
        self.shape.as_deref().is_some_and(|s| s.held(id, self.now))
    }

    pub(super) fn shape_deadline(&self) -> Option<Instant> {
        let s = self.shape.as_deref()?;
        s.deadline(self.now, self.data_pending())
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
            let e = Event::new(EventKind::RecordIn, PipeId(id), now)
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
            let e = Event::new(kind, PipeId(0), now).with_stream(stream);
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
        w.finish()
    }
}

impl Records<'_> {
    /// Writes a record of `n` bytes of PADDING.
    pub(super) fn padding_record(&mut self, n: usize) {
        self.end_record();
        self.out.begin_record(self.max_record());
        self.payload(Bytes::from_static(&ZERO[..n]));
        self.end_plain();
    }

    /// PADDING bytes.
    pub(super) fn padding(&mut self, n: usize) {
        if n > 0 {
            self.payload(Bytes::from_static(&ZERO[..n]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shaping(max_delay: Option<u64>, max_pause_total: Option<u64>, paused: u64) -> Shaping {
        let mut s = Shaping::new(Limits {
            max_delay: max_delay.map(Duration::from_millis),
            max_pause_total: max_pause_total.map(Duration::from_millis),
            ..Limits::default()
        });
        s.stats.pause_total = Duration::from_millis(paused);
        s
    }

    #[test]
    fn hold_bound_is_the_smaller_set_bound() {
        let ms = Duration::from_millis;
        // Neither set: no bound counted.
        assert_eq!(shaping(None, None, 0).hold_bound(), Duration::ZERO);
        // Only one delay bounded.
        assert_eq!(shaping(Some(300), None, 5_000).hold_bound(), ms(300));
        // Only the total bounded: what remains of it.
        assert_eq!(shaping(None, Some(2_000), 500).hold_bound(), ms(1_500));
        // Both: the smaller, recomputed from the total spent so far.
        assert_eq!(shaping(Some(300), Some(2_000), 0).hold_bound(), ms(300));
        assert_eq!(shaping(Some(300), Some(2_000), 1_900).hold_bound(), ms(100));
        // A spent total leaves nothing, never below zero.
        assert_eq!(
            shaping(Some(300), Some(2_000), 2_500).hold_bound(),
            Duration::ZERO
        );
    }

    /// A pause is bounded by what remains of `max_pause_total` without
    /// adding to the total first, which could overflow.
    #[test]
    fn pause_total_bound_does_not_overflow() {
        let now = Instant::now();
        let mut s = shaping(None, Some(2_000), 500);
        assert_eq!(
            s.pause(Duration::MAX, now),
            Some(now + Duration::from_millis(1_500))
        );
        assert_eq!(s.stats.pause_total, Duration::from_millis(2_000));
        let mut s = shaping(None, Some(2_000), 0);
        s.stats.pause_total = Duration::MAX;
        assert_eq!(s.pause(Duration::from_secs(1), now), None);
    }

    #[test]
    fn zero_limits_allow_nothing() {
        let now = Instant::now();
        // A set zero bound allows no pause; unset bounds none.
        let mut s = shaping(Some(0), None, 0);
        assert_eq!(s.pause(Duration::from_millis(5), now), None);
        assert_eq!(s.stats.pause_total, Duration::ZERO);
        let mut s = shaping(None, Some(0), 0);
        assert_eq!(s.pause(Duration::from_millis(5), now), None);
        let mut s = shaping(None, None, 0);
        let five = Duration::from_millis(5);
        assert_eq!(s.pause(five, now), Some(now + five));
        // Padding: a zero byte limit allows none; no ratio limit, no
        // allowance; a set zero ratio keeps the allowance.
        let pad = |l: Limits| Shaping::new(l).padding_room(1_000_000);
        let none = Limits::default();
        assert_eq!(pad(none), (u64::MAX, u64::MAX));
        let zero_bytes = Limits {
            max_padding_bytes: Some(0),
            ..none
        };
        assert_eq!(pad(zero_bytes).0, 0);
        let zero_ratio = Limits {
            max_padding_ratio: Some(0.0),
            ..none
        };
        assert_eq!(pad(zero_ratio).1, STARTUP_ALLOWANCE);
    }
}
