//! Quality events: an optional band around the last
//! reported smoothed RTT and delivery rate of each outbound pipe, and an
//! optional floor under the session's outbound capacity.
//!
//! Both are off until the application sets them, and cost nothing then: a
//! session without either holds no state for them (one empty pointer), and
//! the paths that update the estimates test that pointer and nothing else.
//! Once set, each estimate change is judged in O(1): the pipe's band
//! against its last report, and the floor's sum, which keeps each counted
//! pipe's contribution and is rebuilt only when the set of usable pipes
//! changes (when the scheduler's pipe views are rebuilt anyway). They never
//! influence scheduling.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::pipes::OutPipe;
use super::{CoreEvent, PipeError, PipeId, SessionCore};

/// The band of [`SessionCore::set_quality_band`] (`QualityBand`):
/// `PipeQualityChanged` is reported for an outbound pipe
/// when its smoothed RTT leaves ±`rtt` around the last reported value, or
/// its delivery rate R_p leaves [last / `rate_ratio`, last × `rate_ratio`];
/// the band then recentres on the reported values. The first estimates
/// measured after the band is set are the first report, without an event.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QualityBand {
    /// The half-width of the RTT band; zero turns the RTT half off.
    pub rtt: Duration,
    /// The ratio of the rate band; zero (or a value that is not a number)
    /// turns the rate half off, and a ratio of 1 or less reports every
    /// change of the rate.
    pub rate_ratio: f64,
    /// At most one event per pipe in this interval, the latest values
    /// winning (default 1 s); zero sets no minimum.
    pub min_interval: Duration,
}

impl QualityBand {
    /// The default minimum interval between two events of a pipe.
    pub const DEFAULT_MIN_INTERVAL: Duration = Duration::from_secs(1);

    /// A band of ±`rtt` and [last / `rate_ratio`, last × `rate_ratio`],
    /// with the default minimum interval.
    pub fn new(rtt: Duration, rate_ratio: f64) -> Self {
        Self {
            rtt,
            rate_ratio,
            min_interval: Self::DEFAULT_MIN_INTERVAL,
        }
    }

    /// Whether the band reports anything.
    fn reports(&self) -> bool {
        !self.rtt.is_zero() || self.rate_on()
    }

    fn rate_on(&self) -> bool {
        self.rate_ratio > 0.0
    }
}

impl Default for QualityBand {
    /// Both halves off, the default minimum interval.
    fn default() -> Self {
        Self::new(Duration::ZERO, 0.0)
    }
}

/// The floor of [`SessionCore::set_capacity_floor`] (`CapacityFloor`):
/// `CapacityBelow` is reported once when the sum of the
/// delivery rates of the usable, non-standby outbound pipes falls below
/// `rate`, and `CapacityRestored` once when it rises to `rate` ×
/// `rate_ratio` or more again. A pipe counts 0 until its rate has been
/// measured (the initial value is not a measurement). zmux only reports:
/// the application decides.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CapacityFloor {
    /// The floor in bytes per second.
    pub rate: u64,
    /// The ratio above the floor that restores it (default 1.25); a ratio
    /// below 1, or one that is not a number, counts as 1.
    pub rate_ratio: f64,
}

impl CapacityFloor {
    /// The default ratio that restores the floor.
    pub const DEFAULT_RATE_RATIO: f64 = 1.25;

    /// A floor of `rate` bytes per second with the default ratio.
    pub fn new(rate: u64) -> Self {
        Self {
            rate,
            rate_ratio: Self::DEFAULT_RATE_RATIO,
        }
    }
}

/// The state of quality events, boxed in a session that set any.
#[derive(Debug, Default)]
pub(super) struct Quality {
    /// The band of the pipes that have none of their own.
    default: Option<QualityBand>,
    /// Per outbound pipe (retired pipes leave).
    pipes: HashMap<u64, PipeQuality>,
    floor: Option<Floor>,
    /// The earliest moment a held-back report is due.
    due: Option<Instant>,
    /// Reused for the held-back reports and the floor's members.
    scratch: Vec<(u64, u64)>,
}

#[derive(Debug, Default)]
struct PipeQuality {
    /// The pipe's own band, which overrides the default (one with both
    /// halves off reports nothing).
    own: Option<QualityBand>,
    /// The last reported smoothed RTT, the band's centre.
    rtt: Option<Duration>,
    /// The last reported delivery rate.
    rate: Option<u64>,
    /// When the last event was reported.
    at: Option<Instant>,
    /// A report waits for the minimum interval.
    held: bool,
    /// The pipe's contribution to the floor's sum while it counts.
    counted: Option<u64>,
}

impl PipeQuality {
    /// The band changed: the next estimates are the first report.
    fn recentre(&mut self) {
        self.rtt = None;
        self.rate = None;
        self.held = false;
    }
}

#[derive(Debug)]
struct Floor {
    floor: CapacityFloor,
    /// `CapacityBelow` was reported last.
    below: bool,
    /// The sum of the counted pipes' rates.
    sum: u64,
    /// The pipe-view generation the counted pipes were taken at (a
    /// multipath session), or `None` before.
    generation: Option<u64>,
}

impl Quality {
    fn band(&self, id: u64) -> Option<QualityBand> {
        self.pipes
            .get(&id)
            .and_then(|p| p.own)
            .or(self.default)
            .filter(QualityBand::reports)
    }

    /// Whether nothing is set any more.
    fn unused(&self) -> bool {
        self.default.is_none()
            && self.floor.is_none()
            && self.pipes.values().all(|p| p.own.is_none())
    }

    pub(super) fn heap_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.pipes.capacity() * (std::mem::size_of::<(u64, PipeQuality)>() + 1)
            + self.scratch.capacity() * std::mem::size_of::<(u64, u64)>()
    }
}

/// `k` as a ratio of at least 1.
fn at_least_one(k: f64) -> f64 {
    if k >= 1.0 { k } else { 1.0 }
}

impl SessionCore {
    /// Sets the quality band of the session's outbound pipes that have
    /// none of their own (`None`: none), pipe 0 of a session without
    /// multipath included: see [`QualityBand`] and
    /// [`CoreEvent::PipeQualityChanged`]. Off until set; inbound directions
    /// have no sender estimates (the peer reports its own), and the rate
    /// of a session without multipath needs pipe acknowledgement.
    pub fn set_quality_band(&mut self, band: Option<QualityBand>) {
        let q = self.quality.get_or_insert_default();
        q.default = band;
        for p in q.pipes.values_mut().filter(|p| p.own.is_none()) {
            p.recentre();
        }
        self.quality_settled();
    }

    /// Sets the quality band of one pipe; `None` returns it to the
    /// session's default (a band with both halves off turns its reports
    /// off).
    pub fn set_pipe_quality_band(
        &mut self,
        pipe: PipeId,
        band: Option<QualityBand>,
    ) -> Result<(), PipeError> {
        if self.att(pipe.0).is_none() {
            return Err(PipeError::UnknownPipe);
        }
        let p = self
            .quality
            .get_or_insert_default()
            .pipes
            .entry(pipe.0)
            .or_default();
        p.own = band;
        p.recentre();
        self.quality_settled();
        Ok(())
    }

    /// Sets the floor under the session's outbound capacity (`None`:
    /// none): see [`CapacityFloor`], [`CoreEvent::CapacityBelow`] and
    /// [`CoreEvent::CapacityRestored`]. A capacity already below the floor is
    /// reported at once.
    pub fn set_capacity_floor(&mut self, floor: Option<CapacityFloor>) {
        let q = self.quality.get_or_insert_default();
        q.floor = floor.map(|floor| Floor {
            floor,
            below: false,
            sum: 0,
            generation: None,
        });
        for p in q.pipes.values_mut() {
            p.counted = None;
        }
        self.quality_settled();
        self.floor_rebuild();
    }

    /// Drops the state once nothing is set, and the entries of pipes that
    /// need none.
    fn quality_settled(&mut self) {
        let Some(q) = self.quality.as_deref_mut() else {
            return;
        };
        if q.unused() {
            self.quality = None;
            return;
        }
        if q.default.is_none() && q.floor.is_none() {
            q.pipes.retain(|_, p| p.own.is_some());
        }
    }

    /// A pipe was retired: its state goes.
    pub(super) fn quality_retired(&mut self, id: u64) {
        if let Some(q) = self.quality.as_deref_mut() {
            q.pipes.remove(&id);
        }
    }

    /// The estimates of outbound pipe `id` may have changed: its band and
    /// the floor are judged. Free when neither is set.
    #[inline]
    pub(super) fn quality_sample(&mut self, id: u64, now: Instant) {
        if self.quality.is_some() {
            self.band_check(id, now);
            self.floor_update(id);
        }
    }

    /// The smoothed RTT and the measured delivery rate of an outbound
    /// pipe, as its statistics report them.
    fn quality_estimates(&self, o: &OutPipe) -> (Option<Duration>, Option<u64>) {
        let rtt = self.rtt_of(Some(o)).srtt;
        let acked = self.mp.is_some() || self.pipe_ack.is_some();
        let est = o.est();
        (rtt, (acked && est.rate_sampled).then_some(est.rate))
    }

    /// Judges pipe `id`'s estimates against its band.
    fn band_check(&mut self, id: u64, now: Instant) {
        let Some(band) = self.quality.as_deref().and_then(|q| q.band(id)) else {
            return;
        };
        let Some(o) = self.out_ref(id) else {
            return;
        };
        let (rtt, rate) = self.quality_estimates(o);
        let Some(q) = self.quality.as_deref_mut() else {
            return;
        };
        let p = q.pipes.entry(id).or_default();
        let mut out = false;
        match (p.rtt, rtt) {
            (None, Some(r)) => p.rtt = Some(r),
            (Some(last), Some(r)) if !band.rtt.is_zero() => out |= r.abs_diff(last) > band.rtt,
            _ => {}
        }
        match (p.rate, rate) {
            (None, Some(r)) => p.rate = Some(r),
            (Some(last), Some(r)) if band.rate_on() => {
                let k = at_least_one(band.rate_ratio);
                let (r, last) = (r as f64, last as f64);
                out |= r < last / k || r > last * k;
            }
            _ => {}
        }
        if !out {
            // Back within the band: a held report lapses.
            p.held = false;
            return;
        }
        let due = match p.at {
            None => Some(now),
            // A deadline beyond the clock never comes.
            Some(t) => t.checked_add(band.min_interval),
        };
        if due.is_some_and(|d| now >= d) {
            p.rtt = rtt.or(p.rtt);
            p.rate = rate.or(p.rate);
            p.at = Some(now);
            p.held = false;
            self.events.push_back(CoreEvent::PipeQualityChanged {
                pipe: PipeId(id),
                smoothed_rtt: rtt,
                delivery_rate: rate,
            });
        } else if let Some(d) = due {
            p.held = true;
            q.due = Some(q.due.map_or(d, |e| e.min(d)));
        }
    }

    /// The pipe-view generation of a multipath session.
    fn view_generation(&self) -> Option<u64> {
        self.mp.as_deref().map(|m| m.tiers().view_generation())
    }

    /// What an outbound pipe adds to the floor's sum: its rate once
    /// measured.
    fn floor_rate(&self, o: &OutPipe) -> u64 {
        let est = o.est();
        let acked = self.mp.is_some() || self.pipe_ack.is_some();
        if acked && est.rate_sampled {
            est.rate
        } else {
            0
        }
    }

    /// Pipe `id`'s rate may have changed: the sum takes the difference
    /// while the counted pipes are current, else they are taken again.
    fn floor_update(&mut self, id: u64) {
        let Some(f) = self.quality.as_deref().and_then(|q| q.floor.as_ref()) else {
            return;
        };
        if self.mp.is_none() {
            self.floor_rebuild();
            return;
        }
        if f.generation != self.view_generation() {
            // The usable pipes changed: they are taken again at the next
            // timer, which is due at once ([`SessionCore::quality_deadline`]),
            // where the pipe views are current.
            return;
        }
        let rate = self.out_ref(id).map_or(0, |o| self.floor_rate(o));
        let Some(q) = self.quality.as_deref_mut() else {
            return;
        };
        let (Some(counted), Some(f)) = (
            q.pipes.get_mut(&id).and_then(|p| p.counted.as_mut()),
            q.floor.as_mut(),
        ) else {
            return;
        };
        let old = std::mem::replace(counted, rate);
        if old != rate {
            f.sum = f.sum.saturating_sub(old).saturating_add(rate);
            self.floor_report();
        }
    }

    /// Takes the counted pipes and their sum afresh: the usable,
    /// non-standby outbound pipes, and none on
    /// failover; pipe 0 while it is active outside multipath. In a
    /// multipath session it reads the pipe views, so it runs only where
    /// they are current: at a command or a timer, never while an input is
    /// being processed.
    fn floor_rebuild(&mut self) {
        if self.state >= super::State::Closing {
            return;
        }
        let Some(mut members) = self
            .quality
            .as_deref_mut()
            .filter(|q| q.floor.is_some())
            .map(|q| std::mem::take(&mut q.scratch))
        else {
            return;
        };
        members.clear();
        let generation = self.view_generation();
        if generation.is_some() {
            let v = self.views();
            if v.class().is_some_and(|c| !c.standby()) {
                members.extend(v.usable().iter().map(|&i| {
                    let a = self.atts.at(i);
                    (a.id(), a.out().map_or(0, |o| self.floor_rate(o)))
                }));
            }
        } else if let Some(o) = self.out_ref(0).filter(|o| o.usable(true)) {
            members.push((0, self.floor_rate(o)));
        }
        let Some(q) = self.quality.as_deref_mut() else {
            return;
        };
        for p in q.pipes.values_mut() {
            p.counted = None;
        }
        let mut sum = 0u64;
        for &(id, rate) in &members {
            q.pipes.entry(id).or_default().counted = Some(rate);
            sum = sum.saturating_add(rate);
        }
        q.scratch = members;
        if let Some(f) = q.floor.as_mut() {
            f.sum = sum;
            f.generation = generation;
        }
        self.floor_report();
    }

    /// Reports a crossing of the floor.
    fn floor_report(&mut self) {
        let Some(f) = self.quality.as_deref_mut().and_then(|q| q.floor.as_mut()) else {
            return;
        };
        let rate = f.sum;
        let event = if !f.below && rate < f.floor.rate {
            CoreEvent::CapacityBelow { rate }
        } else if f.below && rate as f64 >= f.floor.rate as f64 * at_least_one(f.floor.rate_ratio) {
            CoreEvent::CapacityRestored { rate }
        } else {
            return;
        };
        f.below = !f.below;
        self.events.push_back(event);
    }

    /// The next quality deadline: a held-back report, or at once when the
    /// usable pipes changed since the floor took them.
    pub(super) fn quality_deadline(&self) -> Option<Instant> {
        let q = self.quality.as_deref()?;
        if self.floor_stale() {
            Some(self.now)
        } else {
            q.due
        }
    }

    /// The usable pipes may have changed since the floor took them.
    fn floor_stale(&self) -> bool {
        self.state < super::State::Closing
            && self
                .quality
                .as_deref()
                .and_then(|q| q.floor.as_ref())
                .is_some_and(|f| self.mp.is_some() && f.generation != self.view_generation())
    }

    /// Timers: held-back reports that are due are judged again with the
    /// latest estimates, and the floor follows changes of the usable
    /// pipes.
    pub(super) fn quality_timeout(&mut self, now: Instant) {
        let Some(q) = self.quality.as_deref_mut() else {
            return;
        };
        if q.due.is_some_and(|d| d <= now) {
            q.due = None;
            let mut held = std::mem::take(&mut q.scratch);
            held.clear();
            held.extend(
                q.pipes
                    .iter()
                    .filter(|(_, p)| p.held)
                    .map(|(&id, _)| (id, 0)),
            );
            for &(id, _) in &held {
                if let Some(p) = self
                    .quality
                    .as_deref_mut()
                    .and_then(|q| q.pipes.get_mut(&id))
                {
                    p.held = false;
                }
                self.band_check(id, now);
            }
            if let Some(q) = self.quality.as_deref_mut() {
                q.scratch = held;
            }
        }
        if self.floor_stale() {
            self.floor_rebuild();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::sched::tests::{FAST, two_pipes};
    use super::*;
    use crate::proto::session::Policy;

    const MS: Duration = Duration::from_millis(1);

    fn events(a: &mut SessionCore) -> Vec<CoreEvent> {
        std::iter::from_fn(|| a.poll_event())
            .filter(|e| {
                matches!(
                    e,
                    CoreEvent::PipeQualityChanged { .. }
                        | CoreEvent::CapacityBelow { .. }
                        | CoreEvent::CapacityRestored { .. }
                )
            })
            .collect()
    }

    fn set_srtt(a: &mut SessionCore, id: u64, srtt: Duration) {
        let i = a.att_index(id).unwrap();
        a.atts.at_mut(i).out_mut().unwrap().est_mut().srtt = srtt;
    }

    fn set_rate(a: &mut SessionCore, id: u64, rate: u64) {
        let i = a.att_index(id).unwrap();
        let est = a.atts.at_mut(i).out_mut().unwrap().est_mut();
        est.rate = rate;
        est.rate_sampled = true;
    }

    fn quality(pipe: u64, rtt: Duration, rate: u64) -> CoreEvent {
        CoreEvent::PipeQualityChanged {
            pipe: PipeId(pipe),
            smoothed_rtt: Some(rtt),
            delivery_rate: Some(rate),
        }
    }

    /// Nothing set, nothing held; clearing what was set frees it again.
    #[test]
    fn unset_quality_holds_no_state() {
        let (mut a, _) = two_pipes(Policy::SpreadEta, Some(FAST), 0);
        assert!(a.quality.is_none());
        let now = a.now;
        a.quality_sample(0, now);
        assert!(a.quality.is_none() && events(&mut a).is_empty());
        a.set_quality_band(Some(QualityBand::new(MS, 1.5)));
        a.set_pipe_quality_band(PipeId(2), Some(QualityBand::default()))
            .unwrap();
        a.set_capacity_floor(Some(CapacityFloor::new(1)));
        a.quality_sample(0, now);
        assert!(a.quality.is_some());
        a.set_quality_band(None);
        a.set_capacity_floor(None);
        assert!(a.quality.is_some(), "pipe 2 still has its own band");
        a.set_pipe_quality_band(PipeId(2), None).unwrap();
        assert!(a.quality.is_none());
        assert_eq!(
            a.set_pipe_quality_band(PipeId(4), None),
            Err(PipeError::UnknownPipe)
        );
    }

    /// The first estimates after the band is set are the first report; an
    /// event when the RTT leaves ±RTT or the rate leaves [last / k, last ×
    /// k], and the band recentres on what was reported.
    #[test]
    fn a_band_reports_leaving_it_and_recentres() {
        let (mut a, _) = two_pipes(Policy::SpreadEta, Some(FAST), 0);
        let now = a.now;
        a.set_quality_band(Some(QualityBand {
            min_interval: Duration::ZERO,
            ..QualityBand::new(5 * MS, 2.0)
        }));
        a.quality_sample(0, now);
        a.quality_sample(2, now);
        assert!(events(&mut a).is_empty(), "the first report has no event");
        // Within the band: 10 ± 5 ms, FAST / 2 to FAST x 2.
        set_srtt(&mut a, 0, 15 * MS);
        set_rate(&mut a, 0, FAST * 2);
        a.quality_sample(0, now);
        assert!(events(&mut a).is_empty());
        set_srtt(&mut a, 0, 16 * MS);
        a.quality_sample(0, now);
        assert_eq!(events(&mut a), [quality(0, 16 * MS, FAST * 2)]);
        // Recentred on 16 ms and 2 x FAST: 20 ms is within, half of FAST
        // below.
        set_srtt(&mut a, 0, 20 * MS);
        a.quality_sample(0, now);
        assert!(events(&mut a).is_empty());
        set_rate(&mut a, 0, FAST / 2);
        a.quality_sample(0, now);
        assert_eq!(events(&mut a), [quality(0, 20 * MS, FAST / 2)]);
        // A pipe's own band wins; one with both halves off reports nothing.
        a.set_pipe_quality_band(PipeId(2), Some(QualityBand::default()))
            .unwrap();
        set_srtt(&mut a, 2, 500 * MS);
        a.quality_sample(2, now);
        assert!(events(&mut a).is_empty());
    }

    /// At most one event per pipe per MinInterval, with the latest values
    /// when the interval ends; a pipe that went back into its band by
    /// then reports nothing.
    #[test]
    fn min_interval_holds_reports_back_with_the_latest_values() {
        let (mut a, _) = two_pipes(Policy::SpreadEta, Some(FAST), 0);
        let t0 = a.now;
        a.set_quality_band(Some(QualityBand::new(5 * MS, 0.0)));
        a.quality_sample(0, t0);
        set_srtt(&mut a, 0, 30 * MS);
        a.quality_sample(0, t0);
        assert_eq!(events(&mut a), [quality(0, 30 * MS, FAST)]);
        // Out again 100 ms later: held until t0 + 1 s.
        let t1 = t0 + 100 * MS;
        set_srtt(&mut a, 0, 50 * MS);
        a.quality_sample(0, t1);
        assert!(events(&mut a).is_empty());
        let due = t0 + Duration::from_secs(1);
        assert!(a.poll_timeout().is_some_and(|t| t <= due));
        set_srtt(&mut a, 0, 60 * MS);
        a.quality_sample(0, t1 + MS);
        a.handle_timeout(due);
        assert_eq!(events(&mut a), [quality(0, 60 * MS, FAST)]);
        // Out and back within the interval: nothing at its end.
        set_srtt(&mut a, 0, 90 * MS);
        a.quality_sample(0, due + MS);
        set_srtt(&mut a, 0, 62 * MS);
        a.quality_sample(0, due + 2 * MS);
        a.handle_timeout(due + Duration::from_secs(1));
        assert!(events(&mut a).is_empty());
        assert!(a.quality.as_deref().unwrap().due.is_none());
    }

    /// The floor: reported at once when set below it, the initial rate of
    /// an unmeasured pipe counts 0, standby pipes do not count, and the
    /// restore needs the ratio above the floor.
    #[test]
    fn the_capacity_floor_reports_crossings_once() {
        // Pipe 2 has not measured its rate: only pipe 0 counts.
        let (mut a, _) = two_pipes(Policy::SpreadEta, None, 0);
        a.set_capacity_floor(Some(CapacityFloor::new(FAST + 1)));
        assert_eq!(events(&mut a), [CoreEvent::CapacityBelow { rate: FAST }]);
        let now = a.now;
        // Measured, but not 1.25 x the floor yet: no event, and none again
        // for the same state.
        set_rate(&mut a, 2, FAST / 8);
        a.quality_sample(2, now);
        a.quality_sample(0, now);
        assert!(events(&mut a).is_empty());
        set_rate(&mut a, 2, FAST / 2);
        a.quality_sample(2, now);
        assert_eq!(
            events(&mut a),
            [CoreEvent::CapacityRestored {
                rate: FAST + FAST / 2
            }]
        );

        // Above the floor when set: nothing; a pipe becoming standby
        // leaves the sum, reported at the next timer, which is due at once.
        let (mut a, _) = two_pipes(Policy::SpreadEta, Some(FAST), 0);
        a.set_capacity_floor(Some(CapacityFloor::new(FAST + FAST / 2)));
        assert!(events(&mut a).is_empty());
        a.set_pipe_send_standby(PipeId(2), Some(true)).unwrap();
        let now = a.now;
        assert_eq!(a.poll_timeout(), Some(now));
        a.handle_timeout(now);
        assert_eq!(events(&mut a), [CoreEvent::CapacityBelow { rate: FAST }]);
        assert_ne!(a.poll_timeout(), Some(now));
        // Back to two pipes: restored.
        a.set_pipe_send_standby(PipeId(2), Some(false)).unwrap();
        a.handle_timeout(now);
        assert_eq!(
            events(&mut a),
            [CoreEvent::CapacityRestored { rate: 2 * FAST }]
        );
        // On failover (only standby pipes usable) nothing counts.
        a.set_pipe_send_standby(PipeId(0), Some(true)).unwrap();
        a.set_pipe_send_standby(PipeId(2), Some(true)).unwrap();
        a.handle_timeout(now);
        assert_eq!(events(&mut a), [CoreEvent::CapacityBelow { rate: 0 }]);
    }
}
