//! Datagram feedback is evidence of arrival. Its dispatch ledger and arrival
//! history have independent bounds and never change reliable pipe positions.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::proto::frame::{DatagramAck, DatagramChannelKind, Frame};
use crate::proto::varint;

use super::output::Records;
use super::{PipeId, SessionCore};

const TUPLE_INTERVAL: Duration = Duration::from_millis(25);
const RATE_WINDOW: Duration = Duration::from_secs(1);
const ARRIVAL_HISTORY_TTL: Duration = Duration::from_secs(60);
const OBSERVATION_WINDOW: Duration = Duration::from_secs(10);
const ADAPTIVE_LATCH: Duration = Duration::from_millis(100);
type Path = (u64, DatagramChannelKind);

#[derive(Debug)]
pub(super) struct AdaptivePair {
    original: Path,
    alternate: Path,
    revisions: (u64, u64),
    urgent: bool,
}

impl AdaptivePair {
    pub(super) fn channel(&self) -> DatagramChannelKind {
        self.alternate.1
    }
}

/// Authoritative finalized outcomes of original datagrams on one outbound path.
/// Report only attributable final outcomes, excluding copies and unresolved attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramLossSample {
    /// Local monotonic observation time.
    pub observed_at: Instant,
    /// Positive source generation scoped to this pipe and representation.
    /// Use a strictly higher generation to announce a replacement, with zero
    /// finalized attempts if outcomes are not yet available.
    pub source_generation: u64,
    /// Original attempts for which the provider knows the final outcome.
    pub finalized: u64,
    /// Finalized attempts known to be lost.
    pub lost: u64,
}

/// The engine replaced the path identity since this source was registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramLossSourceExpired {
    /// The expired source generation. A replacement must use a higher value.
    pub source_generation: u64,
}

impl std::fmt::Display for DatagramLossSourceExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "datagram loss source generation {} expired; use a higher generation",
            self.source_generation
        )
    }
}

impl std::error::Error for DatagramLossSourceExpired {}

/// Source of the timing sample for an outgoing datagram path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatagramEvidenceSource {
    /// A peer `DATAGRAM_ACK` matched to this path and carrier mode.
    DatagramAck,
}

/// Bounded evidence for one outgoing pipe and carrier mode. Awaiting and
/// expired reports do not establish packet loss.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramFeedback {
    /// Locally accepted dispatches still in the history.
    pub tracking: u64,
    /// Recent dispatches with no matched arrival report.
    pub awaiting: u64,
    /// Recent dispatches with a matched arrival report.
    pub arrived: u64,
    /// Dispatches still in the history whose report window has ended.
    pub expired: u64,
    /// Time to the report, minus its reported dwell at the peer. The
    /// forward and reverse paths may be different.
    pub report_rtt: Option<Duration>,
    pub report_variation: Option<Duration>,
    pub sampled_at: Option<Instant>,
    pub sample_age: Option<Duration>,
    pub samples: u64,
    pub sample_source: Option<DatagramEvidenceSource>,
}

/// Reportable arrivals on one inbound pipe and carrier mode before
/// deduplication or application admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramArrivals {
    /// Number of frames, including reportable duplicates and stale sequences.
    pub frames: u64,
    /// Payload bytes in those frames.
    pub bytes: u64,
    /// Time of the most recent arrival.
    pub last_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct Report {
    at: Instant,
    delay: Option<Duration>,
}

#[derive(Debug)]
enum DispatchState {
    Pending(Option<Report>),
    Refused,
    Awaiting,
    Arrived,
}

#[derive(Debug)]
struct Dispatch {
    sequence: u64,
    at: Instant,
    state: DispatchState,
}

#[derive(Debug)]
struct Timing {
    rtt: i64,
    variation: i64,
    recent: [Option<Instant>; 3],
    since: Instant,
    samples: u64,
}

impl Timing {
    fn at(&self) -> Instant {
        self.recent[2].expect("at least one timing sample")
    }

    fn evidence(&self, now: Instant) -> Option<(Instant, i64)> {
        fresh(self.recent[0]?, now).then_some((self.since, self.rtt + 4 * self.variation))
    }

    fn update(&mut self, sample: i64, at: Instant) {
        if self.evidence(at).is_none() {
            self.since = at;
        }
        self.variation += ((self.rtt - sample).abs() - self.variation) / 4;
        self.rtt += (sample - self.rtt) / 8;
        self.recent.rotate_left(1);
        self.recent[2] = Some(at);
        self.samples = self.samples.saturating_add(1);
    }
}

fn fresh(at: Instant, now: Instant) -> bool {
    now >= at && now.duration_since(at) < OBSERVATION_WINDOW
}

#[derive(Debug)]
struct Loss {
    sample: DatagramLossSample,
    since: Instant,
    alternative_since: Instant,
}

#[derive(Debug)]
enum LossSource {
    Current(Loss),
    Expired(u64),
}

impl LossSource {
    fn generation(&self) -> u64 {
        match self {
            Self::Current(loss) => loss.sample.source_generation,
            Self::Expired(generation) => *generation,
        }
    }

    fn current(&self) -> Option<&Loss> {
        match self {
            Self::Current(loss) => Some(loss),
            Self::Expired(_) => None,
        }
    }
}

impl Loss {
    fn evidence(&self, now: Instant) -> Option<&Self> {
        (self.sample.finalized >= 32 && fresh(self.sample.observed_at, now)).then_some(self)
    }

    fn qualifies_as_alternative(&self, now: Instant) -> bool {
        self.evidence(now).is_some() && self.compare(2).is_le()
    }

    fn compare(&self, percent: u8) -> std::cmp::Ordering {
        (u128::from(self.sample.lost) * 100)
            .cmp(&(u128::from(self.sample.finalized) * u128::from(percent)))
    }
}

#[derive(Default, Debug)]
struct Impairments {
    loss: Option<Instant>,
    timing: Option<Instant>,
}

fn latch(
    entry: Option<Instant>,
    now: Instant,
    since: Instant,
    above_entry: bool,
    above_retention: bool,
) -> Option<Instant> {
    if let Some(entry) = entry.filter(|&entry| entry >= since)
        && (now.duration_since(entry) < ADAPTIVE_LATCH || above_retention)
    {
        return Some(entry);
    }
    above_entry.then_some(now)
}

#[derive(Debug, Default)]
struct Dispatches {
    recent: VecDeque<Dispatch>,
    timing: Option<Timing>,
    loss: Option<LossSource>,
    revision: u64,
}

impl Dispatches {
    fn push(&mut self, dispatch: Dispatch, limit: usize) {
        let mut index = self.recent.len();
        if self
            .recent
            .back()
            .is_some_and(|last| last.sequence >= dispatch.sequence)
        {
            index = match self
                .recent
                .binary_search_by_key(&dispatch.sequence, |d| d.sequence)
            {
                Ok(_) => return,
                Err(index) => index,
            };
        }
        if self.recent.len() == limit {
            if index == 0 {
                return;
            }
            self.recent.pop_front();
            index -= 1;
        }
        self.recent.insert(index, dispatch);
    }

    fn observe(dispatch: &mut Dispatch, timing: &mut Option<Timing>, report: Report) {
        let elapsed = report.at.saturating_duration_since(dispatch.at);
        if elapsed >= OBSERVATION_WINDOW {
            return;
        }
        match &mut dispatch.state {
            DispatchState::Pending(early) => {
                early.get_or_insert(report);
                return;
            }
            DispatchState::Awaiting => dispatch.state = DispatchState::Arrived,
            DispatchState::Refused | DispatchState::Arrived => return,
        }
        let Some(sample) = report
            .delay
            .and_then(|delay| elapsed.checked_sub(delay))
            .and_then(|rtt| i64::try_from(rtt.as_micros()).ok())
            .filter(|&sample| sample > 0)
        else {
            return;
        };
        if let Some(prior) = timing.as_mut() {
            if report.at < prior.at() {
                return;
            }
            if fresh(prior.at(), report.at) {
                prior.update(sample, report.at);
                return;
            }
        }
        *timing = Some(Timing {
            rtt: sample,
            variation: sample / 2,
            recent: [None, None, Some(report.at)],
            since: report.at,
            samples: 1,
        });
    }
}

#[derive(Debug, Default)]
struct Arrivals {
    sequences: BTreeMap<u64, Instant>,
    dirty: bool,
    observed: Option<DatagramArrivals>,
}

impl Arrivals {
    fn observe(&mut self, now: Instant, bytes: usize) {
        let counts = self.observed.get_or_insert(DatagramArrivals {
            frames: 0,
            bytes: 0,
            last_at: now,
        });
        counts.frames += 1;
        counts.bytes += bytes as u64;
        counts.last_at = now;
        self.dirty = true;
    }

    fn empty(&self) -> bool {
        self.observed.is_none() && self.sequences.is_empty()
    }
}

#[derive(Debug, Default)]
pub(super) struct Feedback {
    arrivals: BTreeMap<Path, Arrivals>,
    arrival_count: usize,
    arrivals_expire_at: Option<Instant>,
    sent_at: VecDeque<Instant>,
    tuple_sent: BTreeMap<Path, Instant>,
    dispatched: BTreeMap<Path, Dispatches>,
    impairments: BTreeMap<Path, (Path, Impairments)>,
}

impl Feedback {
    fn clear_pairings(&mut self, path: Path) {
        self.impairments
            .retain(|&a, (b, _)| a != path && *b != path);
    }

    fn reset_outbound(&mut self, path: Path) {
        let dispatches = self.dispatched.entry(path).or_default();
        dispatches.revision += 1;
        dispatches.recent.clear();
        dispatches.timing = None;
        if let Some(source) = &mut dispatches.loss {
            *source = LossSource::Expired(source.generation());
        }
        self.clear_pairings(path);
    }

    fn report_loss(
        &mut self,
        path: Path,
        sample: DatagramLossSample,
        now: Instant,
    ) -> Result<bool, DatagramLossSourceExpired> {
        let generation = sample.source_generation;
        let source = self.dispatched.get(&path).and_then(|d| d.loss.as_ref());
        if matches!(source, Some(LossSource::Expired(old)) if *old == generation) {
            return Err(DatagramLossSourceExpired {
                source_generation: generation,
            });
        }
        if generation == 0 || sample.lost > sample.finalized || !fresh(sample.observed_at, now) {
            return Ok(false);
        }
        if let Some(source) = source {
            let previous = source.generation();
            if generation < previous
                || (generation == previous
                    && source
                        .current()
                        .is_some_and(|loss| sample.observed_at <= loss.sample.observed_at))
            {
                return Ok(false);
            }
            if generation > previous {
                self.reset_outbound(path);
            }
        }
        let dispatches = self.dispatched.entry(path).or_default();
        let prior = dispatches.loss.as_ref().and_then(LossSource::current);
        let at = sample.observed_at;
        dispatches.loss = Some(LossSource::Current(Loss {
            sample,
            since: prior.and_then(|p| p.evidence(at)).map_or(at, |p| p.since),
            alternative_since: prior
                .filter(|p| p.qualifies_as_alternative(at))
                .map_or(at, |p| p.alternative_since),
        }));
        Ok(true)
    }

    fn revisions(&self, original: Path, alternate: Path) -> (u64, u64) {
        let revision = |path| self.dispatched.get(&path).map_or(0, |d| d.revision);
        (revision(original), revision(alternate))
    }

    fn try_pair(&mut self, primary: Path, alternate: Path, now: Instant) -> bool {
        let impairments = self.evaluate(primary, alternate, now);
        if impairments.loss.is_some() || impairments.timing.is_some() {
            self.impairments.insert(primary, (alternate, impairments));
            true
        } else {
            // A failed comparison only invalidates its own prior entry.
            if self
                .impairments
                .get(&primary)
                .is_some_and(|(path, _)| *path == alternate)
            {
                self.impairments.remove(&primary);
            }
            false
        }
    }

    fn evaluate(&self, primary: Path, alternate: Path, now: Instant) -> Impairments {
        let Some(a) = self.dispatched.get(&primary) else {
            return Impairments::default();
        };
        let Some(b) = self.dispatched.get(&alternate) else {
            return Impairments::default();
        };
        let prior = self
            .impairments
            .get(&primary)
            .filter(|(path, _)| *path == alternate)
            .map(|(_, impairments)| impairments);
        let loss = match (
            a.loss.as_ref().and_then(LossSource::current),
            b.loss.as_ref().and_then(LossSource::current),
        ) {
            (Some(a), Some(b)) if a.evidence(now).is_some() && b.qualifies_as_alternative(now) => {
                latch(
                    prior.and_then(|p| p.loss),
                    now,
                    a.since.max(b.alternative_since),
                    a.compare(5).is_ge(),
                    a.compare(2).is_gt(),
                )
            }
            _ => None,
        };
        let timing = a
            .timing
            .as_ref()
            .and_then(|a| a.evidence(now))
            .zip(b.timing.as_ref().and_then(|b| b.evidence(now)))
            .and_then(|((a_since, a), (b_since, b))| {
                latch(
                    prior.and_then(|p| p.timing),
                    now,
                    a_since.max(b_since),
                    2 * a > 3 * b,
                    4 * a > 5 * b,
                )
            });
        Impairments { loss, timing }
    }

    fn prune(&mut self, now: Instant) {
        if self.arrivals_expire_at.is_some_and(|at| now >= at) {
            self.arrival_count = 0;
            self.arrivals_expire_at = None;
            self.arrivals.retain(|_, arrivals| {
                arrivals.sequences.retain(|_, at| {
                    let expiry = *at + ARRIVAL_HISTORY_TTL;
                    if now >= expiry {
                        return false;
                    }
                    self.arrivals_expire_at =
                        Some(self.arrivals_expire_at.map_or(expiry, |at| at.min(expiry)));
                    self.arrival_count += 1;
                    true
                });
                arrivals.dirty &= !arrivals.sequences.is_empty();
                !arrivals.empty()
            });
        }
        while self
            .sent_at
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= RATE_WINDOW)
        {
            self.sent_at.pop_front();
        }
    }
}

impl SessionCore {
    fn datagram_feedback_mut(&mut self) -> &mut Feedback {
        self.dgram_mut().feedback.get_or_insert_with(Box::default)
    }

    pub(super) fn note_datagram_arrival(
        &mut self,
        pipe: u64,
        channel: DatagramChannelKind,
        sequence: u64,
        bytes: usize,
    ) {
        let now = self.now;
        let width = self.config.datagram_config().dedup_window;
        let history = self.datagram_feedback_mut();
        let path = (pipe, channel);
        if let Some(arrivals) = history.arrivals.get_mut(&path)
            && arrivals.sequences.contains_key(&sequence)
        {
            arrivals.observe(now, bytes);
            return;
        }
        if history.arrival_count >= width {
            let victim = if history
                .arrivals
                .get(&path)
                .is_some_and(|a| !a.sequences.is_empty())
            {
                path
            } else {
                *history
                    .arrivals
                    .iter()
                    .find(|(_, a)| !a.sequences.is_empty())
                    .expect("bounded arrival history")
                    .0
            };
            let arrivals = history.arrivals.get_mut(&victim).expect("victim tuple");
            arrivals.sequences.pop_first();
            arrivals.dirty &= !arrivals.sequences.is_empty();
            if arrivals.empty() && victim != path {
                history.arrivals.remove(&victim);
            }
            history.arrival_count -= 1;
        }
        let arrivals = history.arrivals.entry(path).or_default();
        arrivals.sequences.insert(sequence, now);
        history
            .arrivals_expire_at
            .get_or_insert(now + ARRIVAL_HISTORY_TTL);
        history.arrival_count += 1;
        arrivals.observe(now, bytes);
    }

    /// Reportable arrivals on this live inbound path and carrier mode.
    pub fn datagram_arrivals(
        &self,
        pipe: PipeId,
        channel: DatagramChannelKind,
    ) -> Option<DatagramArrivals> {
        self.dgram()
            .feedback
            .as_ref()?
            .arrivals
            .get(&(pipe.0, channel))?
            .observed
    }

    pub(super) fn note_datagram_dispatch(&mut self, path: Path, sequence: u64) {
        let width = self.config.datagram_config().dedup_window;
        let now = self.now;
        let h = self
            .datagram_feedback_mut()
            .dispatched
            .entry(path)
            .or_default();
        let state = if path.1 == DatagramChannelKind::Native {
            DispatchState::Pending(None)
        } else {
            DispatchState::Awaiting
        };
        h.push(
            Dispatch {
                sequence,
                at: now,
                state,
            },
            width,
        );
    }

    pub(super) fn settle_native_dispatch(&mut self, pipe: PipeId, sequence: u64, accepted: bool) {
        let Some(h) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.feedback.as_deref_mut())
            .and_then(|h| h.dispatched.get_mut(&(pipe.0, DatagramChannelKind::Native)))
        else {
            return;
        };
        if let Ok(index) = h.recent.binary_search_by_key(&sequence, |d| d.sequence)
            && let Some(dispatch) = h.recent.get_mut(index)
            && let DispatchState::Pending(early) = dispatch.state
        {
            dispatch.state = if accepted {
                DispatchState::Awaiting
            } else {
                DispatchState::Refused
            };
            if let Some(report) = early {
                Dispatches::observe(dispatch, &mut h.timing, report);
            }
        }
    }

    pub(super) fn on_datagram_ack(&mut self, ack: DatagramAck<'_>) {
        let now = self.now;
        let Some(h) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.feedback.as_deref_mut())
            .and_then(|h| h.dispatched.get_mut(&(ack.pipe, ack.channel)))
        else {
            return;
        };
        // Both histories are ordered. A large range still costs one visit per
        // tracked dispatch rather than one per sequence value.
        let mut ranges = ack.ranges().peekable();
        let largest = ranges.peek().expect("first ACK range").1;
        let end = h.recent.partition_point(|d| d.sequence <= largest);
        for dispatch in h.recent.range_mut(..end).rev() {
            while ranges
                .next_if(|&(start, _)| start > dispatch.sequence)
                .is_some()
            {}
            let Some(&(_, end)) = ranges.peek() else {
                break;
            };
            if dispatch.sequence <= end {
                let delay =
                    (dispatch.sequence == largest).then(|| Duration::from_micros(ack.delay_micros));
                Dispatches::observe(dispatch, &mut h.timing, Report { at: now, delay });
            }
        }
    }

    /// Bounded arrival evidence for this outgoing pipe and carrier mode.
    pub fn datagram_feedback(
        &self,
        pipe: PipeId,
        channel: DatagramChannelKind,
    ) -> Option<DatagramFeedback> {
        self.datagram_feedback_at(pipe, channel, self.now)
    }

    pub(crate) fn datagram_feedback_at(
        &self,
        pipe: PipeId,
        channel: DatagramChannelKind,
        now: Instant,
    ) -> Option<DatagramFeedback> {
        let now = now.max(self.now);
        let h = self
            .dgram()
            .feedback
            .as_ref()?
            .dispatched
            .get(&(pipe.0, channel))?;
        let mut quality = DatagramFeedback::default();
        for dispatch in &h.recent {
            if matches!(
                dispatch.state,
                DispatchState::Pending(_) | DispatchState::Refused
            ) {
                continue;
            }
            quality.tracking += 1;
            if now.saturating_duration_since(dispatch.at) >= OBSERVATION_WINDOW {
                quality.expired += 1;
            } else if matches!(dispatch.state, DispatchState::Arrived) {
                quality.arrived += 1;
            } else {
                quality.awaiting += 1;
            }
        }
        if let Some(timing) = h.timing.as_ref().filter(|timing| fresh(timing.at(), now)) {
            quality.report_rtt = Some(Duration::from_micros(timing.rtt.cast_unsigned()));
            quality.report_variation =
                Some(Duration::from_micros(timing.variation.cast_unsigned()));
            quality.sampled_at = Some(timing.at());
            quality.sample_age = Some(now.saturating_duration_since(timing.at()));
            quality.samples = timing.samples;
            quality.sample_source = Some(DatagramEvidenceSource::DatagramAck);
        }
        (quality.tracking > 0).then_some(quality)
    }

    /// Records a dated delta from a provider that can attribute final outcomes to this path.
    /// Returns `Ok(false)` for an invalid or inapplicable sample.
    ///
    /// # Errors
    /// Returns [`DatagramLossSourceExpired`] if the engine replaced the identity of this
    /// path and the provider is still reporting the expired generation.
    pub fn report_datagram_loss(
        &mut self,
        pipe: PipeId,
        channel: DatagramChannelKind,
        sample: DatagramLossSample,
        now: Instant,
    ) -> Result<bool, DatagramLossSourceExpired> {
        self.tick(now);
        if !self.is_established()
            || !self.features.same_family
            || !self
                .out_ref(pipe.0)
                .is_some_and(super::pipes::OutPipe::is_live)
            || (channel == DatagramChannelKind::Native && self.channel_for(pipe.0).is_none())
        {
            return Ok(false);
        }
        let now = self.now;
        self.datagram_feedback_mut()
            .report_loss((pipe.0, channel), sample, now)
    }

    pub(super) fn datagram_impairment(&mut self, primary: Path, alternate: Path) -> bool {
        let now = self.now;
        let Some(history) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.feedback.as_deref_mut())
        else {
            return false;
        };
        history.try_pair(primary, alternate, now)
    }

    pub(super) fn clear_datagram_impairment(&mut self, primary: Path) {
        if let Some(history) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.feedback.as_deref_mut())
        {
            history.impairments.remove(&primary);
        }
    }

    pub(super) fn bind_adaptive_pair(
        &self,
        original: Path,
        alternate: Path,
        urgent: bool,
    ) -> AdaptivePair {
        let revisions = self
            .dgram()
            .feedback
            .as_ref()
            .map_or((0, 0), |h| h.revisions(original, alternate));
        AdaptivePair {
            original,
            alternate,
            revisions,
            urgent,
        }
    }

    pub(super) fn adaptive_pair_current(&self, pair: &AdaptivePair) -> bool {
        self.dgram()
            .feedback
            .as_ref()
            .map_or(pair.urgent, |history| {
                if history.revisions(pair.original, pair.alternate) != pair.revisions {
                    return false;
                }
                if pair.urgent {
                    return true;
                }
                let status = history.evaluate(pair.original, pair.alternate, self.now);
                status.loss.is_some() || status.timing.is_some()
            })
    }

    pub(super) fn reset_datagram_outbound(&mut self, path: Path) {
        if let Some(history) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.feedback.as_deref_mut())
        {
            history.reset_outbound(path);
        }
    }

    pub(super) fn reset_datagram_pairings(&mut self, pipe: u64) {
        if let Some(history) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.feedback.as_deref_mut())
        {
            for channel in [DatagramChannelKind::Record, DatagramChannelKind::Native] {
                history.clear_pairings((pipe, channel));
            }
        }
    }

    pub(super) fn retire_datagram_feedback(&mut self, pipe: PipeId) {
        if let Some(history) = self
            .dgram
            .as_deref_mut()
            .and_then(|d| d.feedback.as_deref_mut())
        {
            for channel in [DatagramChannelKind::Record, DatagramChannelKind::Native] {
                let path = (pipe.0, channel);
                history.dispatched.remove(&path);
                history.clear_pairings(path);
                if let Some(arrivals) = history.arrivals.get_mut(&path) {
                    arrivals.observed = None;
                    if arrivals.empty() {
                        history.arrivals.remove(&path);
                    }
                }
            }
        }
    }

    fn datagram_ack_limit(&self) -> usize {
        self.atts
            .iter()
            .filter(|a| a.inp().is_some_and(super::pipes::InPipe::is_live))
            .count()
            .saturating_mul(2)
    }

    fn datagram_ack_interval(&self, pipe: u64) -> Duration {
        self.rtt_of(self.out_ref(pipe))
            .srtt
            .map_or(TUPLE_INTERVAL, |rtt| TUPLE_INTERVAL.max(rtt / 4))
    }

    pub(super) fn datagram_ack_deadline(&self) -> Option<Instant> {
        let history = self.dgram().feedback.as_deref()?;
        let mut dirty = history.arrivals.iter().filter(|(_, h)| h.dirty).peekable();
        dirty.peek()?;
        let limit = self.datagram_ack_limit();
        if limit == 0 {
            return None;
        }
        let rate_gate = history
            .sent_at
            .iter()
            .rev()
            .nth(limit - 1)
            .map(|t| *t + RATE_WINDOW);
        dirty
            .map(|(&path, _)| {
                let tuple_gate = history
                    .tuple_sent
                    .get(&path)
                    .map(|t| *t + self.datagram_ack_interval(path.0));
                rate_gate
                    .into_iter()
                    .chain(tuple_gate)
                    .max()
                    .unwrap_or(self.now)
            })
            .min()
    }

    /// Only future rate gates need a timer. Once eligible, write opportunity
    /// or the appearance of a reverse pipe wakes the pending report.
    pub(super) fn datagram_feedback_deadline(&self) -> Option<Instant> {
        let history = self.dgram().feedback.as_deref()?;
        self.datagram_ack_deadline()
            .filter(|at| *at > self.now)
            .into_iter()
            .chain(history.arrivals_expire_at)
            .min()
    }

    pub(super) fn expire_datagram_feedback(&mut self) {
        let Some(mut history) = self.dgram.as_deref_mut().and_then(|d| d.feedback.take()) else {
            return;
        };
        history.prune(self.now);
        history.tuple_sent.retain(|&(pipe, _), at| {
            self.now.saturating_duration_since(*at) < self.datagram_ack_interval(pipe)
        });
        self.dgram_mut().feedback = Some(history);
    }

    pub(super) fn wants_datagram_ack(&self, pipe: u64) -> bool {
        self.out_ref(pipe)
            .is_some_and(|p| p.state() == super::pipes::OutState::Active)
            && self
                .datagram_ack_deadline()
                .is_some_and(|at| at <= self.now)
    }

    pub(super) fn write_datagram_acks(&mut self, pipe: u64, w: &mut Records<'_>) {
        if !self.wants_datagram_ack(pipe) {
            return;
        }
        let now = self.now;
        let limit = self.datagram_ack_limit();
        self.expire_datagram_feedback();
        while self
            .dgram()
            .feedback
            .as_ref()
            .is_some_and(|h| h.sent_at.len() < limit)
        {
            let Some(path) = self.dgram().feedback.as_ref().and_then(|h| {
                h.arrivals.iter().find_map(|(&(pipe, channel), arrivals)| {
                    (arrivals.dirty
                        && h.tuple_sent.get(&(pipe, channel)).is_none_or(|last| {
                            now.saturating_duration_since(*last) >= self.datagram_ack_interval(pipe)
                        }))
                    .then_some((pipe, channel))
                })
            }) else {
                break;
            };
            let h = self.datagram_feedback_mut();
            let arrivals = h.arrivals.get_mut(&path).expect("selected arrival tuple");
            let Some((&largest, &at)) = arrivals.sequences.last_key_value() else {
                break;
            };
            let delay = u64::try_from(now.saturating_duration_since(at).as_micros())
                .unwrap_or(varint::MAX)
                .min(varint::MAX);
            // Bound the locally generated frame's work and size to one
            // small record, even if its arrivals were all disjoint.
            let mut pairs = [0; 256];
            let (first_range, n) =
                encode_ranges(arrivals.sequences.keys().rev().copied(), &mut pairs);
            let ack = DatagramAck::new(path.0, path.1, delay, largest, first_range, &pairs[..n])
                .expect("bounded arrival ranges");
            if !w.try_frame(&Frame::DatagramAck(ack)) {
                break;
            }
            h.sent_at.push_back(now);
            h.tuple_sent.insert(path, now);
            arrivals.dirty = false;
        }
    }
}

fn encode_ranges(mut descending: impl Iterator<Item = u64>, out: &mut [u8]) -> (u64, usize) {
    let mut next = descending.next();
    let mut previous: Option<u64> = None;
    let mut first_range = 0;
    let mut written = 0;
    while let Some(end) = next {
        let mut start = end;
        next = descending.next();
        while next.is_some_and(|sequence| sequence + 1 == start) {
            start = next.expect("contiguous sequence");
            next = descending.next();
        }
        let len = end - start;
        if let Some(previous) = previous {
            let gap = previous - end - 2;
            let bytes = varint::len(gap) + varint::len(len);
            if out.len() - written < bytes {
                break;
            }
            written += varint::encode(gap, &mut out[written..]).expect("space for gap");
            written += varint::encode(len, &mut out[written..]).expect("space for length");
        } else {
            first_range = len;
        }
        previous = Some(start);
    }
    (first_range, written)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Path = (0, DatagramChannelKind::Record);
    const B: Path = (2, DatagramChannelKind::Native);

    fn evaluate(feedback: &mut Feedback, now: Instant) -> bool {
        feedback.try_pair(A, B, now)
    }

    #[test]
    fn adaptive_loss_thresholds_latch_and_source_identity() {
        let now = Instant::now();
        let mut feedback = Feedback::default();
        let report =
            |feedback: &mut Feedback, path, observed_at, source_generation, finalized, lost| {
                feedback
                    .report_loss(
                        path,
                        DatagramLossSample {
                            observed_at,
                            source_generation,
                            finalized,
                            lost,
                        },
                        observed_at,
                    )
                    .unwrap()
            };
        let start = now + Duration::from_micros(1);
        assert!(report(&mut feedback, A, now, 1, 31, 31));
        assert!(report(&mut feedback, B, now, 1, 100, 2));
        assert!(!evaluate(&mut feedback, now));
        assert!(report(&mut feedback, A, start, 1, 100, 5));
        assert!(evaluate(&mut feedback, start));
        let next = now + Duration::from_micros(2);
        assert!(!report(&mut feedback, A, start, 1, 100, 0));
        assert!(!report(&mut feedback, A, now, 1, 100, 0));
        assert!(report(&mut feedback, A, next, 1, 100, 2));
        assert!(evaluate(
            &mut feedback,
            start + Duration::from_micros(99_999)
        ));
        assert!(!evaluate(&mut feedback, start + ADAPTIVE_LATCH));

        let retry = start + ADAPTIVE_LATCH + Duration::from_micros(1);
        assert!(report(&mut feedback, A, retry, 1, 100, 5));
        assert!(report(&mut feedback, B, retry, 1, 100, 2));
        assert!(evaluate(&mut feedback, retry));
        assert!(report(&mut feedback, B, next, 2, 0, 0));
        assert!(!report(
            &mut feedback,
            B,
            retry + Duration::from_micros(1),
            1,
            100,
            0
        ));
        assert!(!evaluate(&mut feedback, retry));
        assert!(report(
            &mut feedback,
            B,
            retry + Duration::from_micros(1),
            2,
            100,
            3
        ));
        assert!(!evaluate(&mut feedback, retry + Duration::from_micros(1)));
    }

    #[test]
    fn skipped_alternative_cannot_resume_its_old_latch() {
        let now = Instant::now();
        let mut feedback = Feedback::default();
        let c = (4, DatagramChannelKind::Record);
        for (path, lost) in [(A, 5), (B, 0), (c, 0)] {
            assert!(
                feedback
                    .report_loss(
                        path,
                        DatagramLossSample {
                            observed_at: now,
                            source_generation: 1,
                            finalized: 100,
                            lost,
                        },
                        now,
                    )
                    .unwrap()
            );
        }
        assert!(feedback.try_pair(A, B, now));
        let next = now + Duration::from_millis(1);
        assert!(feedback.try_pair(A, c, next));
        let later = now + ADAPTIVE_LATCH + Duration::from_millis(1);
        assert!(
            feedback
                .report_loss(
                    A,
                    DatagramLossSample {
                        observed_at: later,
                        source_generation: 1,
                        finalized: 100,
                        lost: 3,
                    },
                    later,
                )
                .unwrap()
        );
        assert!(!feedback.try_pair(A, B, later));
        assert!(feedback.try_pair(A, c, later));
    }

    #[test]
    fn generation_zero_and_a_replaced_source_are_distinct_rejections() {
        let now = Instant::now();
        let mut feedback = Feedback::default();
        let record = (0, DatagramChannelKind::Record);
        let native = (0, DatagramChannelKind::Native);
        let sample = |source_generation, observed_at| DatagramLossSample {
            observed_at,
            source_generation,
            finalized: 100,
            lost: 5,
        };
        assert_eq!(feedback.report_loss(record, sample(0, now), now), Ok(false));
        assert_eq!(feedback.report_loss(record, sample(1, now), now), Ok(true));
        assert_eq!(feedback.report_loss(native, sample(1, now), now), Ok(true));

        feedback.reset_outbound(native);
        let next = now + Duration::from_millis(1);
        assert_eq!(
            feedback.report_loss(native, sample(1, next), next),
            Err(DatagramLossSourceExpired {
                source_generation: 1
            })
        );
        assert_eq!(
            feedback.report_loss(record, sample(1, next), next),
            Ok(true)
        );
        assert_eq!(feedback.report_loss(native, sample(2, now), next), Ok(true));
        assert_eq!(
            feedback.report_loss(native, sample(1, next), next),
            Ok(false)
        );
    }

    fn ack(dispatches: &mut Dispatches, sequence: u64, now: Instant, sample: u64) {
        let mut dispatch = Dispatch {
            sequence,
            at: now.checked_sub(Duration::from_micros(sample + 7)).unwrap(),
            state: DispatchState::Awaiting,
        };
        let report = Report {
            at: now,
            delay: Some(Duration::from_micros(7)),
        };
        Dispatches::observe(&mut dispatch, &mut dispatches.timing, report);
        Dispatches::observe(&mut dispatch, &mut dispatches.timing, report);
    }

    #[test]
    fn adaptive_timing_needs_three_distinct_fresh_matches_and_strict_ratios() {
        let origin = Instant::now();
        let now = origin + Duration::from_millis(1);
        let mut feedback = Feedback::default();
        for seq in 0..2 {
            ack(feedback.dispatched.entry(A).or_default(), seq, now, 101);
        }
        for seq in 2..5 {
            ack(feedback.dispatched.entry(B).or_default(), seq, now, 66);
        }
        assert!(!evaluate(&mut feedback, now));
        ack(feedback.dispatched.entry(A).or_default(), 5, now, 101);
        let timing = feedback.dispatched[&A].timing.as_ref().unwrap();
        assert_eq!((timing.rtt, timing.variation, timing.samples), (101, 29, 3));
        assert!(evaluate(&mut feedback, now));
        assert!(
            feedback
                .report_loss(
                    A,
                    DatagramLossSample {
                        observed_at: now,
                        source_generation: 1,
                        finalized: 0,
                        lost: 0,
                    },
                    now,
                )
                .unwrap()
        );
        assert!(evaluate(&mut feedback, now));

        let start = now + ADAPTIVE_LATCH;
        let original = feedback
            .dispatched
            .get_mut(&A)
            .unwrap()
            .timing
            .as_mut()
            .unwrap();
        original.variation = 0;
        original.rtt = 180;
        let alternate = feedback
            .dispatched
            .get_mut(&B)
            .unwrap()
            .timing
            .as_mut()
            .unwrap();
        alternate.variation = 0;
        alternate.rtt = 120;
        assert!(evaluate(&mut feedback, start)); // 3/2 retains.
        feedback
            .dispatched
            .get_mut(&A)
            .unwrap()
            .timing
            .as_mut()
            .unwrap()
            .rtt = 150;
        assert!(!evaluate(&mut feedback, start)); // 5/4 clears at equality.
        feedback
            .dispatched
            .get_mut(&A)
            .unwrap()
            .timing
            .as_mut()
            .unwrap()
            .rtt = 180;
        assert!(!evaluate(&mut feedback, start)); // 3/2 cannot enter at equality.
        feedback
            .dispatched
            .get_mut(&A)
            .unwrap()
            .timing
            .as_mut()
            .unwrap()
            .rtt = 181;
        assert!(evaluate(&mut feedback, start));
        ack(
            feedback.dispatched.get_mut(&B).unwrap(),
            6,
            now + OBSERVATION_WINDOW,
            12,
        );
        assert!(!evaluate(&mut feedback, now + OBSERVATION_WINDOW));
        assert_eq!(feedback.dispatched[&B].timing.as_ref().unwrap().samples, 1);
    }
}
