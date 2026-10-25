//! Tiers (MULTIPATH.md Section 9, 10 and 11): the
//! priority, standby
//! flag and weight of each outbound direction, PIPE_STATUS requests for the
//! peer's directions, standby takeover, probation, tier saturation, and the
//! tier gate that every scheduling policy runs behind.
//!
//! Tier saturation is a property of a tier, not of a pipe: the data offered
//! to a tier (what is ready and what the more-preferred tiers cannot absorb
//! within the overflow delay D), plus what its pipes already queue, takes
//! longer than D to drain at the tier's aggregate rate, or data has waited
//! for the tier longer than D. Only that excess flows on to the next tier;
//! a pipe that merely refuses bytes for a moment saturates nothing.

use std::time::{Duration, Instant};

use super::output::Records;
use super::pipes::{Attachment, History, OutPipe, OutState, SentFrame, TierState};
use super::sched::NOTSENT_LOWAT;
use super::{CoreEvent, PipeError, PipeId, Policy, SessionCore};
use crate::proto::Error;
use crate::proto::frame::{Frame, PipeStatus, PipeStatusValue};

/// The floor of the probation base for a path with history.
const PROBATION_FLOOR: Duration = Duration::from_secs(1);
/// Probation probes go out at least every max(srtt, this).
const PROBATION_PROBE: Duration = Duration::from_millis(200);
/// At most one saturation event per tier in this interval.
const SATURATION_EVENTS: Duration = Duration::from_secs(1);

/// Which outbound pipes are usable for new stream data at one moment
/// (11 and 11.1): ACTIVE, not penalized, out of
/// probation and not awaiting revalidation unless no pipe in neither state
/// is usable, and standby pipes only on failover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Class {
    /// Failover: only standby pipes are usable.
    standby: bool,
    /// Pipes in probation or awaiting revalidation count as usable: no
    /// pipe in neither state, standby pipes included, is usable.
    probation_ok: bool,
}

impl Class {
    /// Whether the attachment's outbound pipe is usable in this class.
    pub(super) fn usable(self, a: &Attachment) -> bool {
        a.standby() == self.standby && a.out().is_some_and(|o| o.usable(self.probation_ok))
    }

    /// Failover: the usable pipes are standby ones.
    pub(super) fn standby(self) -> bool {
        self.standby
    }
}

/// The tier gate at one scheduling decision.
/// The usable tiers in order of preference: the first is eligible, and
/// each further one while every tier before it is saturated. A policy runs
/// within the tier of the pipe that has a write opportunity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Gate {
    class: Class,
    /// The most-preferred usable tier.
    top: u64,
    /// The least-preferred eligible tier.
    last: u64,
    /// The least-preferred eligible tier that is offered data the tiers
    /// before it cannot drain within D (their excess). A tier after it is
    /// eligible because data has waited longer than D, and takes data only
    /// while no pipe of a more-preferred tier can take it.
    fed: u64,
    /// `last` is saturated too (every usable tier is).
    all_saturated: bool,
}

impl Gate {
    /// The usable class.
    pub(super) fn class(&self) -> Class {
        self.class
    }

    /// Whether the attachment's outbound pipe is usable.
    pub(super) fn usable(&self, a: &Attachment) -> bool {
        self.class.usable(a)
    }

    /// Whether the attachment's outbound pipe is eligible: usable, in an
    /// eligible tier.
    pub(super) fn admits(&self, a: &Attachment) -> bool {
        self.usable(a) && a.send_tier() <= self.last
    }

    /// The most-preferred usable tier.
    pub(super) fn top(&self) -> u64 {
        self.top
    }

    /// The least-preferred eligible tier.
    pub(super) fn last(&self) -> u64 {
        self.last
    }

    /// Whether an eligible tier is saturated (`None` beyond the eligible
    /// tiers, where the cascade did not look).
    pub(super) fn saturated(&self, tier: u64) -> Option<bool> {
        (tier <= self.last).then_some(tier < self.last || self.all_saturated)
    }
}

impl Gate {
    /// The gate over the usable tiers of `class`, most preferred first:
    /// the first is eligible, and each further one while every tier before
    /// it is saturated.
    fn of(class: Class, tiers: impl Iterator<Item = Tier>) -> Option<Self> {
        let mut gate: Option<Self> = None;
        for t in tiers {
            let g = gate.get_or_insert(Self {
                class,
                top: t.priority,
                last: t.priority,
                fed: t.priority,
                all_saturated: false,
            });
            g.last = t.priority;
            if t.offered > 0 {
                g.fed = t.priority;
            }
            g.all_saturated = t.saturated;
            if !t.saturated {
                break;
            }
        }
        gate
    }
}

/// Q_t and R_t of one usable tier, and when it last became eligible (the
/// age test of the tiers after the most-preferred one).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct TierLoad {
    priority: u64,
    queued: u64,
    rate: u64,
    since: Option<Instant>,
}

/// The tier loads a batch's gates are worked out from (see
/// [`SessionCore::gate_from`]); kept by the session so that the batches reuse
/// one allocation.
#[derive(Debug, Default)]
pub(crate) struct GateInputs {
    generation: Option<u64>,
    class: Option<Class>,
    loads: Vec<TierLoad>,
}

impl GateInputs {
    /// Forgets the loads: they are taken again at the next gate.
    pub(super) fn reset(&mut self) {
        self.generation = None;
    }
}

/// The cascade over the usable tiers, most
/// preferred first: each tier is offered the ready data (the most-preferred
/// one) or the excess of the tier before it, and is saturated when that and
/// its queue take longer than D to drain at its rate, or when the oldest
/// waiting data has waited D for it.
struct Cascade {
    offered: u64,
    oldest: Option<Instant>,
    now: Instant,
    d: Duration,
    drain_test: bool,
    /// The next tier is the most-preferred one.
    first: bool,
}

impl Cascade {
    fn next(&mut self, t: &TierLoad) -> Tier {
        let drain = Duration::from_secs_f64((t.queued + self.offered) as f64 / t.rate as f64);
        let drained_late = self.drain_test && drain > self.d;
        // The age test: the oldest waiting data has waited D or longer,
        // counted for a tier other than the most-preferred one from when
        // it last became eligible.
        let aged = self.oldest.is_some_and(|w| {
            let since = match self.first {
                true => w,
                false => w.max(t.since.unwrap_or(self.now)),
            };
            self.now.saturating_duration_since(since) >= self.d
        });
        let tier = Tier {
            priority: t.priority,
            queued: t.queued,
            rate: t.rate,
            offered: self.offered,
            saturated: drained_late || aged,
        };
        // Only what this tier cannot absorb within D moves on.
        let room = (t.rate as f64 * self.d.as_secs_f64()) as u64;
        self.offered = self.offered.saturating_sub(room.saturating_sub(t.queued));
        self.first = false;
        tier
    }
}

/// One usable tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Tier {
    pub(super) priority: u64,
    /// Q_t: bytes committed to the tier's pipes and not yet transmitted.
    pub(super) queued: u64,
    /// R_t: the aggregate delivery rate.
    pub(super) rate: u64,
    /// The data offered to the tier: ready data for the most-preferred
    /// tier, the excess of the tier before it otherwise.
    pub(super) offered: u64,
    pub(super) saturated: bool,
}

/// Stream data waiting for the pipes (X of the most-preferred tier), and
/// since when the oldest of that data has waited (the age test).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Backlog {
    pub(super) bytes: u64,
    pub(super) oldest: Option<Instant>,
}

/// The tier state of a multipath session: the pipe views and their
/// generation, since when data waits for each tier and the tiers last
/// seen, the saturation reports, and the probation history of each
/// non-zero fate group.
#[derive(Debug, Default)]
pub(crate) struct Tiers {
    /// The pipe views and the generation they stand for.
    view_generation: u64,
    views: std::cell::RefCell<Views>,
    /// Since when data waits for each tier (by priority), and the tiers
    /// with their last evaluation.
    wait: Vec<(u64, Instant)>,
    seen: Vec<(u64, bool)>,
    /// Tier saturation as last reported.
    reports: Vec<TierReport>,
    /// The probation history of each non-zero fate group, keyed by
    /// (joined locally, fate group).
    fate_history: Vec<((bool, u64), History)>,
}

impl Tiers {
    /// The generation of the pipe views: it advances whenever a view may
    /// change.
    #[inline]
    pub(super) fn view_generation(&self) -> u64 {
        self.view_generation
    }
}

/// A tier's saturation as last reported (one event per second).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TierReport {
    pub(crate) priority: u64,
    pub(crate) saturated: bool,
    pub(crate) at: Instant,
}

/// The pipe views every scheduling decision reads (MULTIPATH.md), kept while
/// the view generation stands
/// ([`SessionCore::views_changed`]): it advances whenever an attachment comes or
/// goes, or an outbound pipe changes state, usability, tier, standby flag
/// or minimum RTT. A decision reads them instead of passing over every
/// pipe, or every pair of pipes, again; debug builds check them against a
/// rebuild.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Views {
    generation: Option<u64>,
    /// The smallest min_rtt of the live outbound pipes (OWD).
    owd_floor: Duration,
    /// The usable class, `None` when no pipe is usable.
    class: Option<Class>,
    /// The usable tiers, most preferred first.
    tiers: Vec<TierView>,
    /// The attachment indices of the usable pipes, tier by tier, in
    /// attachment order within a tier.
    usable: Vec<usize>,
    /// The attachment indices of the pipes that may carry control frames,
    /// in control order (Section 6.5).
    control: Vec<usize>,
}

/// One usable tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TierView {
    pub(super) priority: u64,
    /// Its pipes: `usable[start..end]`.
    start: usize,
    end: usize,
    /// The usable pipe with the smallest OWD (the active pipe of
    /// `session-affinity`), an attachment index.
    active: usize,
}

impl Views {
    /// The usable class, `None` when no pipe is usable.
    pub(super) fn class(&self) -> Option<Class> {
        self.class
    }

    /// The usable tiers, most preferred first.
    pub(super) fn tiers(&self) -> &[TierView] {
        &self.tiers
    }

    /// The attachment indices of a tier's usable pipes.
    pub(super) fn pipes(&self, t: &TierView) -> &[usize] {
        &self.usable[t.start..t.end]
    }

    /// The usable tier of a priority.
    pub(super) fn tier(&self, priority: u64) -> Option<&TierView> {
        let i = self
            .tiers
            .binary_search_by_key(&priority, |t| t.priority)
            .ok()?;
        Some(&self.tiers[i])
    }

    /// The attachment indices of every usable pipe.
    pub(super) fn usable(&self) -> &[usize] {
        &self.usable
    }

    /// The candidates for control frames, in control order.
    pub(super) fn control(&self) -> &[usize] {
        &self.control
    }

    /// The estimated one-way delay of an outbound pipe.
    pub(super) fn owd(&self, o: &OutPipe) -> Duration {
        owd(o, self.owd_floor)
    }
}

/// The one-way delay of a pipe given the smallest min_rtt of the live
/// pipes: its min_rtt less half that, or srtt / 2 before a sample.
pub(super) fn owd(o: &OutPipe, floor: Duration) -> Duration {
    match o.est().min_rtt.get() {
        None => o.est().srtt / 2,
        Some(m) => m.saturating_sub(floor / 2),
    }
}

impl SessionCore {
    // ---- the pipe views ------------------------------------------------------------

    /// A pipe changed in a way the pipe views depend on.
    pub(super) fn views_changed(&mut self) {
        if let Some(mp) = self.mp.as_deref_mut() {
            mp.tiers_mut().view_generation += 1;
        }
    }

    /// The pipe views, rebuilt when the generation moved on.
    pub(super) fn views(&self) -> std::cell::Ref<'_, Views> {
        let tiers = self.mp().tiers();
        let generation = tiers.view_generation;
        if tiers.views.borrow().generation != Some(generation) {
            let mut v = tiers.views.borrow_mut();
            self.build_views(&mut v);
            v.generation = Some(generation);
        }
        let v = tiers.views.borrow();
        #[cfg(debug_assertions)]
        {
            let mut fresh = Views::default();
            self.build_views(&mut fresh);
            fresh.generation = v.generation;
            debug_assert_eq!(
                *v, fresh,
                "pipe views out of date: a change did not advance the view generation"
            );
        }
        v
    }

    fn build_views(&self, v: &mut Views) {
        v.owd_floor = self
            .atts
            .outs()
            .filter(|x| x.is_live())
            .filter_map(|x| x.est().min_rtt.get())
            .min()
            .unwrap_or_default();
        let any = |c: Class| self.atts.iter().any(|a| c.usable(a));
        let settled = any(Class {
            standby: false,
            probation_ok: false,
        }) || any(Class {
            standby: true,
            probation_ok: false,
        });
        let probation_ok = !settled;
        let standby = !any(Class {
            standby: false,
            probation_ok,
        });
        let class = Class {
            standby,
            probation_ok,
        };
        v.class = any(class).then_some(class);
        v.usable.clear();
        v.tiers.clear();
        if let Some(class) = v.class {
            v.usable
                .extend((0..self.atts.len()).filter(|&i| class.usable(self.atts.at(i))));
            // Stable: attachment order within a tier.
            v.usable.sort_by_key(|&i| self.atts.at(i).send_tier());
            let mut start = 0;
            while start < v.usable.len() {
                let priority = self.atts.at(v.usable[start]).send_tier();
                let end = start
                    + v.usable[start..]
                        .iter()
                        .take_while(|&&i| self.atts.at(i).send_tier() == priority)
                        .count();
                let active = v.usable[start..end]
                    .iter()
                    .filter_map(|&i| {
                        let a = self.atts.at(i);
                        Some((owd(a.out()?, v.owd_floor), a.id(), i))
                    })
                    .min()
                    .map_or(v.usable[start], |(_, _, i)| i);
                v.tiers.push(TierView {
                    priority,
                    start,
                    end,
                    active,
                });
                start = end;
            }
        }
        // The control order: ACTIVE first, then the most preferred tier
        // (non-standby, then the lowest priority), then the lowest one-way
        // delay.
        v.control.clear();
        v.control.extend((0..self.atts.len()).filter(|&i| {
            self.atts
                .at(i)
                .out()
                .and_then(OutPipe::control_rank)
                .is_some()
        }));
        let key = |i: usize| {
            let a = self.atts.at(i);
            let o = a.out().expect("control candidates have one");
            (
                o.control_rank(),
                a.standby(),
                a.send_tier(),
                owd(o, v.owd_floor),
                a.id(),
            )
        };
        v.control.sort_by_key(|&i| key(i));
    }

    // ---- the gate ------------------------------------------------------------------

    /// The usable class now; `None` when no pipe is usable.
    pub(super) fn class(&self) -> Option<Class> {
        self.views().class
    }

    /// Bytes committed to a pipe and not yet transmitted (Q_p): the
    /// carrier's unsent bytes, and at least its low-water mark while it
    /// refuses bytes.
    pub(super) fn queued(o: &OutPipe) -> u64 {
        if o.open() {
            o.carrier_unsent()
        } else {
            o.carrier_unsent().max(NOTSENT_LOWAT)
        }
    }

    /// Stream data ready to send and not committed to a pipe, within the
    /// stream and session credit, plus the reinjected information pending
    /// (X), from the ledger. Outside multipath
    /// there are no tiers to saturate: nothing waits for one.
    pub(super) fn waiting_data(&self) -> Backlog {
        let Some(l) = self.ledger() else {
            return Backlog::default();
        };
        let session_room = self.streams.send_flow().room();
        let fresh = l.ready_below(8).min(session_room);
        let (marks, waits) = l.oldest();
        // Ready data waits from when session credit last arrived at the
        // earliest.
        let marks = marks
            .filter(|_| session_room > 0)
            .map(|t| self.streams.send_flow().credit_at.map_or(t, |c| c.max(t)));
        let oldest = match (marks, waits) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        Backlog {
            bytes: fresh + l.lost(),
            oldest,
        }
    }

    /// The overflow delay D of tier saturation.
    pub(super) fn overflow_delay(&self) -> Duration {
        self.config.overflow_delay
    }

    /// Calls `f` with the usable tiers in order of preference, while it
    /// returns `true`.
    pub(super) fn for_each_tier(&self, backlog: Backlog, mut f: impl FnMut(Tier) -> bool) {
        let views = self.views();
        let mut c = self.cascade(backlog);
        for t in views.tiers() {
            if !f(c.next(&self.tier_load(&views, t, c.first))) {
                return;
            }
        }
    }

    /// The cascade for `backlog` now.
    fn cascade(&self, backlog: Backlog) -> Cascade {
        Cascade {
            offered: backlog.bytes,
            oldest: backlog.oldest,
            now: self.now,
            d: self.overflow_delay(),
            drain_test: !self.config.hooks.sojourn_only,
            first: true,
        }
    }

    /// Q_t and R_t of a usable tier, and when it last became eligible
    /// unless it is the most-preferred one (`first`).
    fn tier_load(&self, views: &Views, t: &TierView, first: bool) -> TierLoad {
        let (mut queued, mut rate) = (0u64, 0u64);
        // Under `session-affinity` a tier consists of its active pipe only:
        // the other pipes, which carry nothing, count neither in Q_t nor in
        // R_t.
        let only = [t.active];
        let pipes = match self.config.scheduler {
            Policy::SessionAffinity => &only[..],
            _ => views.pipes(t),
        };
        for &i in pipes {
            if let Some(o) = self.atts.at(i).out() {
                // Q_p of tier saturation: what is known committed, with no
                // allowance for a pipe that merely refuses bytes: "not
                // writable" is not saturation.
                queued += o.committed();
                rate = rate.saturating_add(o.est().rate.max(1));
            }
        }
        TierLoad {
            priority: t.priority,
            queued,
            rate,
            since: (!first).then(|| self.eligible_since(t.priority)).flatten(),
        }
    }

    /// The tier gate of a decision (see [`Self::gate`]) from the tier loads
    /// of `inputs`, taken once per view generation: within one batch only
    /// the backlog moves, so the gate costs a few operations per tier
    /// instead of a pass over the pipes. `inputs` must be
    /// [reset](GateInputs::reset) whenever anything else may have changed
    /// (the time, the carriers' queues, the rates).
    pub(super) fn gate_from(&self, inputs: &mut GateInputs) -> Option<Gate> {
        let generation = self.mp().tiers().view_generation;
        if inputs.generation != Some(generation) {
            let views = self.views();
            inputs.generation = Some(generation);
            inputs.class = views.class();
            inputs.loads.clear();
            for (n, t) in views.tiers().iter().enumerate() {
                inputs.loads.push(self.tier_load(&views, t, n == 0));
            }
        }
        let gate = match inputs.class {
            Some(class) => {
                let mut c = self.cascade(self.waiting_data());
                Gate::of(class, inputs.loads.iter().map(|t| c.next(t)))
            }
            None => None,
        };
        debug_assert_eq!(gate, self.gate(), "gate inputs out of date");
        gate
    }

    /// The active pipe of a usable tier of `class` under
    /// `session-affinity`: the usable pipe with the smallest
    /// OWD.
    pub(super) fn tier_active(&self, class: Class, tier: u64) -> Option<u64> {
        let views = self.views();
        if views.class() == Some(class) {
            return views.tier(tier).map(|t| self.atts.at(t.active).id());
        }
        // A class of an earlier moment of the same decision.
        self.atts
            .iter()
            .filter(|a| class.usable(a) && a.send_tier() == tier)
            .filter_map(|a| Some((views.owd(a.out()?), a.id())))
            .min()
            .map(|(_, id)| id)
    }

    /// When a tier last became eligible, as last recorded.
    fn eligible_since(&self, priority: u64) -> Option<Instant> {
        self.mp
            .as_deref()?
            .tiers()
            .wait
            .iter()
            .find(|&&(p, _)| p == priority)
            .map(|&(_, t)| t)
    }

    /// The tier gate now; `None` when no pipe is usable.
    pub(super) fn gate(&self) -> Option<Gate> {
        let class = self.class()?;
        let views = self.views();
        let mut c = self.cascade(self.waiting_data());
        Gate::of(
            class,
            views
                .tiers()
                .iter()
                .map(|t| c.next(&self.tier_load(&views, t, c.first))),
        )
    }

    /// Whether an eligible pipe takes new data now: only the excess
    /// overflows, so a pipe of a tier that is
    /// eligible only because data waited too long takes data only while no
    /// pipe of a more-preferred tier can take bytes.
    pub(super) fn takes(&self, gate: &Gate, a: &Attachment) -> bool {
        if !gate.admits(a) {
            return false;
        }
        let tier = a.send_tier();
        if tier <= gate.fed {
            return true;
        }
        let sa = matches!(self.config.scheduler, Policy::SessionAffinity);
        let open = |b: &Attachment| b.out().is_some_and(|o| o.open() && !o.limiter_held());
        let views = self.views();
        if views.class() != Some(gate.class()) {
            // A gate of an earlier moment of the same decision.
            return !self.atts.iter().any(|b| {
                gate.usable(b)
                    && b.send_tier() < tier
                    && (!sa || self.tier_active(gate.class(), b.send_tier()) == Some(b.id()))
                    && open(b)
            });
        }
        !views
            .tiers()
            .iter()
            .take_while(|t| t.priority < tier)
            .any(|t| match sa {
                true => open(self.atts.at(t.active)),
                false => views.pipes(t).iter().any(|&i| open(self.atts.at(i))),
            })
    }

    /// Whether the tier of an attachment's outbound pipe is saturated now.
    pub(super) fn tier_saturated(&self, a: &Attachment) -> bool {
        if !self.class().is_some_and(|c| c.usable(a)) {
            return false;
        }
        let tier = a.send_tier();
        let mut saturated = false;
        self.for_each_tier(self.waiting_data(), |t| {
            if t.priority == tier {
                saturated = t.saturated;
                return false;
            }
            true
        });
        saturated
    }

    /// Updates since when data waits for each tier, reports tier
    /// saturation changes, and the standby takeover (MULTIPATH.md Section
    /// 9). Called at every batch and timer, and when writers or
    /// pipes change.
    pub(super) fn refresh_tiers(&mut self) {
        if self.mp.is_none() {
            return;
        }
        let now = self.now;
        self.check_standby_takeover();
        let class = self.class();
        let backlog = self.waiting_data();
        // The moment each eligible tier became eligible (the age test of
        // the tiers after the most-preferred one).
        let mut since = std::mem::take(&mut self.mp_mut().tiers_mut().wait);
        let mut seen = std::mem::take(&mut self.mp_mut().tiers_mut().seen);
        seen.clear();
        if class.is_some() {
            self.for_each_tier(backlog, |t| {
                seen.push((t.priority, t.saturated));
                t.saturated
            });
        }
        since.retain(|&(p, _)| seen.iter().any(|&(q, _)| q == p));
        for &(p, _) in &seen {
            if !since.iter().any(|w| w.0 == p) {
                since.push((p, now));
            }
        }
        self.mp_mut().tiers_mut().wait = since;
        seen.clear();
        if class.is_some() {
            self.for_each_tier(backlog, |t| {
                seen.push((t.priority, t.saturated));
                true
            });
        }
        self.report_saturation(&seen, now);
        self.mp_mut().tiers_mut().seen = seen;
    }

    /// Emits `TierSaturation` for tiers whose state changed, at most once
    /// per tier per second, the latest state winning; a tier that is gone
    /// is reported unsaturated.
    fn report_saturation(&mut self, seen: &[(u64, bool)], now: Instant) {
        let mut reports = std::mem::take(&mut self.mp_mut().tiers_mut().reports);
        for &(priority, saturated) in seen {
            match reports.iter_mut().find(|r| r.priority == priority) {
                Some(r) if r.saturated == saturated => {}
                Some(r) if now < r.at + SATURATION_EVENTS => {}
                Some(r) => {
                    r.saturated = saturated;
                    r.at = now;
                    self.push_event(CoreEvent::TierSaturation {
                        priority,
                        saturated,
                    });
                }
                None if saturated => {
                    reports.push(TierReport {
                        priority,
                        saturated,
                        at: now,
                    });
                    self.push_event(CoreEvent::TierSaturation {
                        priority,
                        saturated,
                    });
                }
                None => {}
            }
        }
        reports.retain(|r| {
            if seen.iter().any(|&(p, _)| p == r.priority) {
                return true;
            }
            if r.saturated {
                self.events.push_back(CoreEvent::TierSaturation {
                    priority: r.priority,
                    saturated: false,
                });
            }
            false
        });
        self.mp_mut().tiers_mut().reports = reports;
    }

    /// The next tier deadline: a wait that will exceed D, or a held-back
    /// saturation report.
    pub(super) fn tier_deadline(&self) -> Option<Instant> {
        let mp = self.mp.as_deref()?.tiers();
        let d = self.overflow_delay();
        let now = self.now;
        // The oldest waiting data reaches D: in the most-preferred tier, and
        // in each eligible tier from when it became eligible.
        let oldest = (!self.streams.queue().is_empty())
            .then(|| self.waiting_data().oldest)
            .flatten();
        let waits = oldest.into_iter().flat_map(|t| {
            std::iter::once(t.checked_add(d))
                .chain(mp.wait.iter().map(move |&(_, s)| t.max(s).checked_add(d)))
                .flatten()
        });
        let reports = mp
            .reports
            .iter()
            .filter(|r| {
                mp.seen
                    .iter()
                    .any(|&(p, s)| p == r.priority && s != r.saturated)
            })
            .map(|r| r.at + SATURATION_EVENTS);
        waits.chain(reports).filter(|&t| t > now).min()
    }

    // ---- settings ------------------------------------------------------------------

    fn tier_att(&self, pipe: PipeId) -> Result<usize, PipeError> {
        if self.mp.is_none() {
            return Err(PipeError::NotNegotiated);
        }
        self.att_index(pipe.0).ok_or(PipeError::UnknownPipe)
    }

    /// Sets the priority of the local outbound direction of a pipe (lower
    /// preferred); `None` clears the local setting, returning to the peer's
    /// request, else 0 (MULTIPATH.md Section 9). Used from the next
    /// scheduling decision; nothing is sent.
    pub fn set_pipe_send_priority(
        &mut self,
        pipe: PipeId,
        priority: Option<u64>,
    ) -> Result<(), PipeError> {
        let i = self.tier_att(pipe)?;
        self.change_tier(i, |t| t.set_send_priority(priority));
        Ok(())
    }

    /// Sets whether the local outbound direction of a pipe is standby
    /// (data only on failover); `None` clears the local setting, returning
    /// to the peer's request, else available. Nothing is sent.
    pub fn set_pipe_send_standby(
        &mut self,
        pipe: PipeId,
        standby: Option<bool>,
    ) -> Result<(), PipeError> {
        let i = self.tier_att(pipe)?;
        self.change_tier(i, |t| t.set_send_standby(standby));
        Ok(())
    }

    /// Sets the priority requested for the peer's outbound direction of a
    /// pipe; the request goes out at once as PIPE_STATUS.
    pub fn set_pipe_receive_priority(
        &mut self,
        pipe: PipeId,
        priority: u64,
    ) -> Result<(), PipeError> {
        let i = self.tier_att(pipe)?;
        self.change_tier(i, |t| t.set_receive(None, Some(priority)));
        self.request_status(i);
        Ok(())
    }

    /// Asks the peer to use its outbound direction of a pipe only on
    /// failover (`true`) or as an ordinary pipe; the request goes out at
    /// once as PIPE_STATUS.
    pub fn set_pipe_receive_standby(
        &mut self,
        pipe: PipeId,
        standby: bool,
    ) -> Result<(), PipeError> {
        let i = self.tier_att(pipe)?;
        self.change_tier(i, |t| t.set_receive(Some(standby), None));
        self.request_status(i);
        Ok(())
    }

    /// Sets the whole request for the peer's outbound direction of a pipe,
    /// standby flag and priority, sent at once as one PIPE_STATUS.
    pub fn set_pipe_receive_status(
        &mut self,
        pipe: PipeId,
        standby: bool,
        priority: u64,
    ) -> Result<(), PipeError> {
        let i = self.tier_att(pipe)?;
        self.change_tier(i, |t| t.set_receive(Some(standby), Some(priority)));
        self.request_status(i);
        Ok(())
    }

    /// Sets the weight of a pipe's outbound direction for
    /// `spread-round-robin` and `spread-rate-weighted` (local only).
    pub fn set_pipe_weight(&mut self, pipe: PipeId, weight: u64) -> Result<(), PipeError> {
        let i = self.tier_att(pipe)?;
        self.change_tier(i, |t| t.set_weight(weight));
        Ok(())
    }

    /// `RevalidatePipes` / `Revalidate`: the named
    /// live outbound pipe, or every one, sends a PIPE_PING at once (within
    /// the PIPE_PING limit, longest waiting first) and awaits revalidation
    /// until its acknowledged position reaches it. A pipe already awaiting
    /// revalidation, or one that is suspect,
    /// draining or gone, is left as it is.
    pub fn revalidate_pipes(
        &mut self,
        pipe: Option<PipeId>,
        now: Instant,
    ) -> Result<(), PipeError> {
        self.tick(now);
        if self.mp.is_none() {
            return Err(PipeError::NotNegotiated);
        }
        let named = match pipe {
            Some(p) => {
                let i = self.att_index(p.0).ok_or(PipeError::UnknownPipe)?;
                i..i + 1
            }
            None => 0..self.atts.len(),
        };
        let mut started = false;
        for i in named {
            if let Some(o) = self.atts.at_mut(i).out_mut() {
                started |= o.revalidate(now);
            }
        }
        if started {
            // Usability changed.
            self.advance_pick_generation();
            self.check_standby_takeover();
        }
        Ok(())
    }

    /// A revalidation of pipe `id` ends: its PIPE_PING was acknowledged,
    /// or the pipe became suspect, failed, started draining or went away.
    pub(super) fn end_revalidation(&mut self, id: u64) {
        if self.out_mut(id).is_some_and(OutPipe::end_revalidation) {
            self.advance_pick_generation();
            self.check_standby_takeover();
        }
    }

    /// Sets the probation base of a pipe; `None` for the session default,
    /// zero disables probation. Applies from the pipe's next probation.
    pub fn set_pipe_probation(
        &mut self,
        pipe: PipeId,
        probation: Option<Duration>,
    ) -> Result<(), PipeError> {
        let i = self.tier_att(pipe)?;
        self.atts.at_mut(i).tier_mut().set_probation(probation);
        if self.probation_base(self.atts.at(i)).is_none()
            && let Some(o) = self.atts.at_mut(i).out_mut()
            && o.cancel_probation()
        {
            // Disabled while in probation: it ends now.
            self.advance_pick_generation();
            self.check_standby_takeover();
        }
        Ok(())
    }

    /// Applies a change to an attachment's settings and reports a change
    /// of the effective values.
    fn change_tier(&mut self, i: usize, f: impl FnOnce(&mut TierState)) {
        let before = effective(self.atts.at(i));
        f(self.atts.at_mut(i).tier_mut());
        self.report_tier(i, before);
        self.check_standby_takeover();
    }

    /// A PIPE_STATUS request is owed for an attachment that has an inbound
    /// direction to ask about.
    fn request_status(&mut self, i: usize) {
        let a = self.atts.at_mut(i);
        if a.inp().is_some() {
            a.tier_mut().request();
        }
    }

    /// Emits `PipePriorityChanged` when the effective values differ from
    /// `before`.
    fn report_tier(&mut self, i: usize, before: (u64, bool, u64)) {
        let a = self.atts.at(i);
        let now = effective(a);
        if now != before && a.out().is_some() {
            let (send_priority, source) = a.tier().send_priority();
            self.push_event(CoreEvent::PipePriorityChanged {
                pipe: PipeId(a.id()),
                send_priority,
                standby: now.1,
                weight: now.2,
                source,
            });
        }
    }

    /// Applies the options of a new attachment.
    pub(super) fn init_tier(&mut self, i: usize, opts: &super::PipeOptions) {
        // The initial request travels in the PIPE_JOIN (MULTIPATH.md
        // Section 5.1).
        self.atts.at_mut(i).tier_mut().configure(
            opts.send_priority,
            opts.send_standby,
            opts.receive_priority,
            opts.receive_standby,
            opts.weight,
            opts.probation,
        );
    }

    // ---- PIPE_STATUS -----------------------------------------------------------------

    /// PIPE_STATUS (MULTIPATH.md Section 9): the peer's request for the
    /// local outbound direction of an attachment.
    pub(super) fn on_pipe_status(
        &mut self,
        id: u64,
        seq: u64,
        standby: bool,
        priority: u64,
    ) -> Result<(), Error> {
        const TYPE: u64 = 0x227b_2811;
        if self.mp().is_local(id) && !self.local_id_taken(id) {
            return Err(Error::protocol_violation(
                TYPE,
                "PIPE_STATUS for an untaken local pipe ID",
            )
            .detail(crate::proto::DetailKey::Pipe, id));
        }
        // Without attachment state, retired, or without an outbound
        // direction: ignored, never stored.
        let Some(i) = self.att_index(id) else {
            return Ok(());
        };
        let a = self.atts.at(i);
        if a.out().is_none() || a.unattached() || !a.tier().newer(seq) {
            return Ok(());
        }
        self.change_tier(i, |t| t.peer_status(seq, standby, priority));
        Ok(())
    }

    /// Writes attachment `i`'s PIPE_STATUS when one is owed; `false` when
    /// the batch is full.
    pub(super) fn write_status(&mut self, i: usize, w: &mut Records<'_>) -> bool {
        while let Some((seq, standby, priority)) = self.atts.at(i).tier().owed() {
            let pipe = self.atts.at(i).id();
            let frame = Frame::PipeStatus(PipeStatus {
                pipe_id: pipe,
                sequence: seq,
                status: if standby {
                    PipeStatusValue::Standby
                } else {
                    PipeStatusValue::Available
                },
                priority,
            });
            if !w.try_frame(&frame) {
                return false;
            }
            self.atts.at_mut(i).tier_mut().status_written();
            self.log(w, SentFrame::PipeStatus { pipe, seq });
        }
        true
    }

    /// A standby takeover (MULTIPATH.md Section 9): while an attachment's
    /// own standby outbound pipe carries the traffic because no non-standby
    /// pipe is usable, the standby request for the peer's direction is
    /// replaced by "available" with the configured priority; once a
    /// non-standby pipe is usable again (after its probation) the
    /// configured request is restored.
    pub(super) fn check_standby_takeover(&mut self) {
        if self.mp.is_none() {
            return;
        }
        let class = self.class();
        for i in 0..self.atts.len() {
            let a = self.atts.at(i);
            let want = a.tier().receive_standby()
                && a.standby()
                && class.is_some_and(|c| c.standby() && c.usable(a));
            if want != a.tier().takeover() {
                self.atts.at_mut(i).tier_mut().set_takeover(want);
                self.request_status(i);
            }
        }
    }

    // ---- probation ------------------------------------------

    /// The probation base of attachment `a` now, from the current smoothed
    /// RTT: 4 x smoothed_rtt for a path without history, max(1 s, 4 x
    /// smoothed_rtt) otherwise; `None` when probation is disabled.
    fn probation_base(&self, a: &Attachment) -> Option<Duration> {
        let srtt = a.out()?.est().srtt;
        match a.tier().probation().or(self.config.probation) {
            Some(d) if d.is_zero() => None,
            Some(d) => Some(d),
            None if self.history(a).trouble() => Some(PROBATION_FLOOR.max(srtt * 4)),
            None => Some(srtt * 4),
        }
    }

    /// The base of the 10 x base windows of the backoff: always with the
    /// 1 s floor.
    fn backoff_base(&self, a: &Attachment) -> Duration {
        let srtt = a.out().map_or_else(Duration::default, |o| o.est().srtt);
        match a.tier().probation().or(self.config.probation) {
            Some(d) if !d.is_zero() => d,
            _ => PROBATION_FLOOR.max(srtt * 4),
        }
    }

    /// When the probation of attachment `a` ends: its start plus
    /// min(base x 2^k, max(base, 2 x U_max)), with the base of now, and
    /// without the uptime cap while no uptime was observed.
    pub(super) fn probation_end(&self, a: &Attachment) -> Option<Instant> {
        let (started, k) = a.out()?.probation()?;
        let base = self.probation_base(a)?;
        let backoff = base.checked_mul(1 << k);
        let cap = (!self.config.hooks.no_probation_cap)
            .then(|| {
                self.history(a)
                    .u_max()
                    .map(|u| base.max(u.saturating_mul(2)))
            })
            .flatten();
        let length = match (backoff, cap) {
            (Some(b), Some(c)) => Some(b.min(c)),
            (b, c) => b.or(c),
        };
        // A huge configured base never ends rather than overflowing.
        length.and_then(|d| started.checked_add(d))
    }

    /// The probation history of attachment `a`: its fate group's, or its
    /// own for fate group 0.
    fn history(&self, a: &Attachment) -> History {
        match (a.fate_group(), self.mp.as_deref()) {
            (0, _) | (_, None) => a.out().map(OutPipe::history).unwrap_or_default(),
            (_, Some(mp)) => mp
                .tiers()
                .fate_history
                .iter()
                .find(|h| h.0 == a.fate())
                .map(|h| h.1)
                .unwrap_or_default(),
        }
    }

    /// Changes the probation history of attachment `i`.
    fn update_history<R>(&mut self, i: usize, f: impl FnOnce(&mut History) -> R) -> R {
        let a = self.atts.at_mut(i);
        let (local, group) = a.fate();
        if group == 0 || self.mp.is_none() {
            return match a.out_mut() {
                Some(o) => f(o.history_mut()),
                None => f(&mut History::default()),
            };
        }
        let mp = self
            .mp
            .as_deref_mut()
            .expect("multipath in use")
            .tiers_mut();
        match mp.fate_history.iter_mut().find(|h| h.0 == (local, group)) {
            Some(h) => f(&mut h.1),
            None => {
                let mut h = History::default();
                let r = f(&mut h);
                mp.fate_history.push(((local, group), h));
                r
            }
        }
    }

    /// The pipe joined, or returned from SUSPECT to ACTIVE: it is in
    /// probation, with k raised when a suspicion or failure is pending.
    pub(super) fn start_probation(&mut self, id: u64, now: Instant) {
        let Some(i) = self.att_index(id) else {
            return;
        };
        if self.atts.at(i).out().is_none() {
            return;
        }
        let k = self.update_history(i, History::next_k);
        let a = self.atts.at(i);
        let enabled = self.probation_base(a).is_some();
        // An ACTIVE period that begins once the path has history counts
        // for the uptime cap.
        let counted = self.history(a).trouble();
        if let Some(o) = self.atts.at_mut(i).out_mut() {
            o.start_probation(k, enabled, counted, now);
        }
    }

    /// Ends the probation of attachment `i` when it is due.
    fn end_probation_if_due(&mut self, i: usize, now: Instant) {
        let a = self.atts.at(i);
        let Some(end) = self.probation_end(a).filter(|&e| now >= e) else {
            return;
        };
        let base = self.backoff_base(a);
        if let Some(o) = self.atts.at_mut(i).out_mut() {
            o.end_probation();
        }
        self.update_history(i, |h| h.probation_ended(end, base));
        // Eligibility changed.
        self.advance_pick_generation();
        self.check_standby_takeover();
    }

    /// The pipe became suspect: a probation in progress ends, and the
    /// suspicion counts in the history (unless the attachment is being
    /// removed gracefully): within or soon after a probation it raises k
    /// for the next one.
    pub(super) fn probation_suspect(&mut self, id: u64, now: Instant) {
        let Some(i) = self.att_index(id) else {
            return;
        };
        let Some(o) = self.atts.at_mut(i).out_mut() else {
            return;
        };
        let (in_probation, up_since) = o.probation_suspected();
        if self.atts.at(i).outside_fate() {
            return;
        }
        self.update_history(i, |h| h.trouble_at(in_probation, up_since, now));
    }

    /// The pipe returned from SUSPECT to ACTIVE: every return enters
    /// probation.
    pub(super) fn probation_recovered(&mut self, id: u64, now: Instant) {
        self.start_probation(id, now);
    }

    /// The attachment failed: the failure counts like a suspicion in its
    /// fate group's history, so that a rejoin on the same path starts with
    /// the raised backoff.
    pub(super) fn probation_failed(&mut self, i: usize, now: Instant) {
        let a = self.atts.at_mut(i);
        if a.fate_group() == 0 || a.outside_fate() {
            return;
        }
        let (in_probation, up_since) = a.out_mut().map_or((false, None), OutPipe::probation_failed);
        self.update_history(i, |h| h.trouble_at(in_probation, up_since, now));
    }

    /// Probations that ended by `now`, the decay of k, and the probes
    /// probation asks for.
    pub(super) fn probation_timers(&mut self, now: Instant) {
        for i in 0..self.atts.len() {
            self.end_probation_if_due(i, now);
            let a = self.atts.at_mut(i);
            let own = a.fate_group() == 0;
            let Some(o) = a.out_mut() else {
                continue;
            };
            let busy = o.in_probation() || o.state() == OutState::Suspect;
            if own {
                o.history_mut().decay(!busy, now);
            }
            let every = o.est().srtt.max(PROBATION_PROBE);
            o.probation_probe(every, now);
        }
        // The fate groups: quiet while no pipe of the group is suspect or
        // in probation.
        if let Some(mp) = self.mp.as_deref_mut() {
            let atts = &self.atts;
            for ((local, group), h) in &mut mp.tiers_mut().fate_history {
                let busy = atts.iter().any(|a| {
                    a.fate() == (*local, *group)
                        && !a.failed()
                        && a.out()
                            .is_some_and(|o| o.in_probation() || o.state() == OutState::Suspect)
                });
                h.decay(!busy, now);
            }
        }
        self.prune_fate_history(now);
    }

    /// Forgets the probation history of fate groups that no attachment
    /// uses any more once it no longer matters (a suspicion would start
    /// over at k = 0), and keeps at most max_pipes + H such groups (the
    /// most recent), so that a peer cycling through fate groups cannot
    /// grow the state.
    fn prune_fate_history(&mut self, now: Instant) {
        let Some(mp) = self.mp.as_deref() else {
            return;
        };
        if mp.tiers().fate_history.is_empty() {
            return;
        }
        let cap = self.cap();
        let atts = &self.atts;
        let unused = |key: (bool, u64)| !atts.iter().any(|a| a.fate() == key && !a.failed());
        let Some(mp) = self.mp.as_deref_mut().map(super::mpath::Mp::tiers_mut) else {
            return;
        };
        mp.fate_history
            .retain(|&(key, h)| !unused(key) || !h.quiet(now));
        let mut idle = mp
            .fate_history
            .iter()
            .filter(|&&(key, _)| unused(key))
            .count();
        while idle > cap {
            // The group whose last probation ended first.
            let Some(oldest) = mp
                .fate_history
                .iter()
                .enumerate()
                .filter(|&(_, &(key, _))| unused(key))
                .min_by_key(|&(_, &(_, h))| h.ended())
                .map(|(i, _)| i)
            else {
                break;
            };
            mp.fate_history.swap_remove(oldest);
            idle -= 1;
        }
    }

    /// The next probation deadline of attachment `a`: its end, or its next
    /// probe.
    pub(super) fn probation_deadline(&self, a: &Attachment, now: Instant) -> Option<Instant> {
        let o = a.out().filter(|o| o.is_live())?;
        let end = self.probation_end(a)?;
        let probe = o.next_probation_probe(o.est().srtt.max(PROBATION_PROBE), now);
        Some(end.min(probe))
    }

    // ---- spread-round-robin ------------------------------------------------------------

    /// Whether a pipe is a candidate of `spread-round-robin` and
    /// `spread-rate-weighted` at an opportunity in `tier`: eligible, in
    /// the tier, and writable.
    fn rr_candidate(gate: &Gate, tier: u64, a: &Attachment) -> bool {
        gate.admits(a)
            && a.send_tier() == tier
            && a.out().is_some_and(|o| o.open() && !o.limiter_held())
    }

    /// Every candidate of the tier has weight 0: then all count as 1.
    pub(super) fn weights_all_zero(&self, gate: &Gate, tier: u64) -> bool {
        !self
            .atts
            .iter()
            .any(|a| Self::rr_candidate(gate, tier, a) && a.tier().weight() > 0)
    }

    /// A candidate's weight; `None` for a pipe that is no candidate (a
    /// weight of 0 excludes a pipe unless every candidate has it).
    pub(super) fn candidate_weight(
        gate: &Gate,
        tier: u64,
        a: &Attachment,
        all_zero: bool,
    ) -> Option<u64> {
        let w = if all_zero { 1 } else { a.tier().weight() };
        (Self::rr_candidate(gate, tier, a) && w > 0).then_some(w)
    }

    /// The candidates of `spread-round-robin` and `spread-rate-weighted`
    /// at an opportunity in `tier`, with their weights.
    pub(super) fn weighted_candidates(
        &self,
        gate: &Gate,
        tier: u64,
    ) -> impl Iterator<Item = (&Attachment, &OutPipe, u64)> + '_ {
        let gate = *gate;
        let all_zero = self.weights_all_zero(&gate, tier);
        self.atts.iter().filter_map(move |a| {
            let w = Self::candidate_weight(&gate, tier, a, all_zero)?;
            Some((a, a.out()?, w))
        })
    }
}

/// The effective priority, standby flag and weight of an attachment's
/// outbound direction.
fn effective(a: &Attachment) -> (u64, bool, u64) {
    (a.send_tier(), a.standby(), a.tier().weight())
}
