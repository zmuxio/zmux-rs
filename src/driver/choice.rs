//! Candidate registration, staggered bootstrap and committed member feedback.

use super::controller::domain::{CleanupObserver, Demand, Grant, Owner, confirm};
use super::controller::{CONTROLLER_STAGGER, ControllerBlock};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use super::cache::{AttemptPermit, CacheOutcome, CarrierCache, CarrierObservation, CarrierRank};
use super::handle;
use super::handle::{Driver, Session};
use crate::ConnectError;
use crate::proto::session::{
    CandidateOutcome, CandidateResult, CarrierKind, Config, PipeFailure, PipeId, PipeOptions,
    SessionError,
};

use super::capacity_change::{
    AttachmentSpec, AttemptCause, AttemptId, CarrierOpenerFor, OpenRequest, OpenStage,
    OpenedCarriersFor,
};
/// One carrier a [`crate::SessionController`] may use: its kind and how to open a carrier
/// of it (the adapter's options, with the credential the server's
/// admission wants, captured in the dial). The adapters' `candidate`
/// constructors give ready ones. Cheap to clone.
pub struct Candidate<D: Driver> {
    kind: CarrierKind,
    pub(super) tier: u64,
    pub(super) standby: bool,
    variant: Option<Arc<str>>,
    target: Option<Arc<HttpTarget>>,
    opener: CarrierOpenerFor<D::Carrier>,
    pub(super) id: Option<crate::CandidateId>,
    pub(super) cache_key: Option<Arc<str>>,
    pub(super) can_start: bool,
    pub(super) layout: Vec<crate::AttachmentSpec>,
}

impl<D: Driver> Clone for Candidate<D> {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            tier: self.tier,
            standby: self.standby,
            variant: self.variant.clone(),
            target: self.target.clone(),
            opener: self.opener.clone(),
            id: self.id.clone(),
            cache_key: self.cache_key.clone(),
            can_start: self.can_start,
            layout: self.layout.clone(),
        }
    }
}

/// The URL of a candidate dialed at a URL and the URL redirects last led
/// it to: later carriers start from the final URL. Safe for concurrent use.
#[derive(Debug)]
pub struct HttpTarget {
    base: String,
    current: std::sync::Mutex<Option<String>>,
}

impl HttpTarget {
    /// A target at `base`.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            current: std::sync::Mutex::new(None),
        }
    }

    /// The URL the next carrier starts from.
    pub fn url(&self) -> String {
        self.lock().clone().unwrap_or_else(|| self.base.clone())
    }

    /// The URL the target was made with.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Records the final URL of a carrier that redirects led to.
    pub fn redirected(&self, last: &str) {
        *self.lock() = (last != self.base).then(|| last.to_owned());
    }

    /// Starts the next carrier from the base URL again.
    pub fn reset(&self) {
        *self.lock() = None;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<D: Driver> fmt::Debug for Candidate<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl<D: Driver> Candidate<D> {
    /// A candidate of `kind` whose carriers `dial` opens. A carrier must
    /// live until its pipe ends; the choice bounds the opening.
    pub(super) fn from_dial<F, Fut>(kind: CarrierKind, dial: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<D::Carrier>> + Send + 'static,
    {
        let opener = CarrierOpenerFor::new(move |_| {
            let future = dial();
            async move { future.await.map(|carrier| vec![carrier]) }
        });
        Self {
            kind,
            tier: 0,
            standby: false,
            variant: None,
            target: None,
            opener,
            id: None,
            cache_key: None,
            can_start: true,
            layout: vec![crate::AttachmentSpec::new(
                crate::Directions::BOTH,
                PipeOptions::default(),
            )],
        }
    }

    /// Registers this candidate with a host identity and a stable v2 cache key.
    #[must_use]
    pub fn with_identity(
        mut self,
        id: impl Into<crate::CandidateId>,
        cache_key: impl Into<Arc<str>>,
    ) -> Self {
        self.id = Some(id.into());
        self.cache_key = Some(cache_key.into());
        self
    }

    pub(super) fn can_bootstrap(&self) -> bool {
        self.can_start
            && self.layout.len() == 1
            && self.layout[0].directions == crate::Directions::BOTH
    }

    /// Prohibits using this candidate to establish a new session.
    #[must_use]
    pub fn join_only(mut self) -> Self {
        self.can_start = false;
        self
    }

    /// Declares the exact Join layout and how to open its carriers.
    #[must_use]
    pub fn with_join_opener(
        mut self,
        layout: Vec<crate::AttachmentSpec>,
        opener: CarrierOpenerFor<D::Carrier>,
    ) -> Self {
        self.layout = layout;
        let bootstrap = self.opener;
        self.opener = CarrierOpenerFor::new(move |req| {
            let open = if req.stage == OpenStage::Bootstrap {
                bootstrap.clone()
            } else {
                opener.clone()
            };
            async move { open.open(req).await }
        });
        self
    }

    /// Registers a candidate's single opener for Bootstrap and Join.
    #[must_use]
    pub fn with_opener(
        mut self,
        layout: Vec<AttachmentSpec>,
        opener: CarrierOpenerFor<D::Carrier>,
    ) -> Self {
        self.layout = layout;
        self.opener = opener;
        self
    }

    pub(super) fn opener(&self) -> CarrierOpenerFor<D::Carrier> {
        let candidate = self.clone();
        CarrierOpenerFor::new(move |request| {
            let candidate = candidate.clone();
            async move {
                let mut opened = candidate.opener.open(request).await;
                for carrier in &mut opened.carriers {
                    D::candidate_metadata(carrier, candidate.kind, candidate.variant.as_ref());
                }
                opened
            }
        })
    }

    /// Sets candidate priority within a selection round. Smaller tiers go first.
    #[must_use]
    pub fn with_tier(mut self, tier: u64) -> Self {
        self.tier = tier;
        self
    }

    /// Defers this candidate to the standby round.
    #[must_use]
    pub fn with_standby(mut self, standby: bool) -> Self {
        self.standby = standby;
        self
    }

    /// Wraps the candidate's dial: `wrap` gets each carrier the dial opens,
    /// once it is open, and returns the carrier to use, such as the same
    /// one with a host's shaping or accounting around it.
    #[must_use]
    pub fn wrap_dial<F, Fut>(self, wrap: F) -> Self
    where
        F: Fn(D::Carrier) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<D::Carrier>> + Send + 'static,
    {
        let (inner, wrap) = (self.opener, Arc::new(wrap));
        Self {
            opener: CarrierOpenerFor::new(move |request| {
                let (inner, wrap) = (inner.clone(), wrap.clone());
                async move {
                    let mut opened = inner.open(request).await;
                    if opened.error.is_none() {
                        let mut carriers = Vec::with_capacity(opened.carriers.len());
                        for carrier in opened.carriers {
                            match wrap(carrier).await {
                                Ok(io) => carriers.push(io),
                                Err(error) => {
                                    opened.error = Some(error);
                                    break;
                                }
                            }
                        }
                        opened.carriers = carriers;
                    }
                    opened
                }
            }),
            ..self
        }
    }

    /// Names the target its dial opens carriers at, for a kind dialed at a
    /// URL: the dial starts at [`HttpTarget::url`] and records where
    /// redirects led it ([`HttpTarget::redirected`]); a carrier choice keeps
    /// that URL per server in its [`CarrierCache`] while the kind is
    /// usable, and starts the target at its base URL again after a failure.
    #[must_use]
    pub fn with_target(mut self, target: Arc<HttpTarget>) -> Self {
        self.target = Some(target);
        self
    }

    /// The candidate's target ([`Candidate::with_target`]).
    #[must_use]
    pub fn target(&self) -> Option<&Arc<HttpTarget>> {
        self.target.as_ref()
    }

    /// The candidate's kind.
    #[must_use]
    pub fn kind(&self) -> CarrierKind {
        self.kind
    }

    /// Labels the transform the candidate's carriers run: the carriers'
    /// variant ([`PipeIo::with_variant`]). A kind with different variants
    /// makes different candidates, each with its own place in the
    /// [`CarrierCache`]. Order expresses the preference, as for kinds.
    #[must_use]
    pub fn with_variant(mut self, variant: impl Into<Arc<str>>) -> Self {
        self.variant = Some(variant.into());
        self
    }

    /// The candidate's variant ([`Candidate::with_variant`]).
    #[must_use]
    pub fn variant(&self) -> Option<&Arc<str>> {
        self.variant.as_ref()
    }

    /// Opens a carrier of the candidate.
    /// Its kind is the candidate's (the registered transport kind).
    ///
    /// # Errors
    ///
    /// The candidate's dial function's error.
    pub async fn dial(&self) -> io::Result<D::Carrier> {
        let deadline = D::now() + crate::DEFAULT_HANDSHAKE_TIMEOUT;
        let request = bootstrap_request(AttemptId(1), deadline);
        one_bootstrap_carrier(self.opener().open(request).await)
    }
}

#[cfg(feature = "tokio")]
impl Candidate<super::tokio::Tokio> {
    /// Registers an asynchronous host dial function.
    pub fn new<F, Fut>(kind: CarrierKind, dial: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<super::tokio::PipeIo>> + Send + 'static,
    {
        Self::from_dial(kind, dial)
    }
}

#[cfg(feature = "blocking")]
impl Candidate<super::blocking::Blocking> {
    /// Registers a synchronous host dial function for the native blocking driver.
    pub fn new(
        kind: CarrierKind,
        dial: impl Fn() -> io::Result<super::blocking::PipeIo> + Send + Sync + 'static,
    ) -> Self {
        Self::from_dial(kind, move || std::future::ready(dial()))
    }
}

/// Outcomes when no candidate could establish the session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BootstrapError {
    /// Actual attempts in observation order.
    pub results: Vec<CandidateResult>,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no usable carrier")?;
        for result in &self.results {
            write!(f, " {} {}", result.kind, result.outcome)?;
            if let Some(error) = &result.error {
                write!(f, " ({error})")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for BootstrapError {}

fn result<D: Driver>(
    cand: &Candidate<D>,
    joined: bool,
    r: Result<(), (CandidateOutcome, String)>,
) -> CandidateResult {
    let (outcome, error) = match r {
        Ok(()) => (CandidateOutcome::Usable, None),
        Err((o, e)) => (o, Some(e)),
    };
    CandidateResult {
        kind: cand.kind,
        variant: cand.variant.clone(),
        outcome,
        joined,
        error,
    }
}

struct PendingEstablishment<D: Driver>(Option<std::sync::Weak<handle::Shared<D>>>);

impl<D: Driver> Drop for PendingEstablishment<D> {
    fn drop(&mut self) {
        if let Some(shared) = self.0.take().and_then(|weak| weak.upgrade()) {
            shared.abandon();
        }
    }
}

/// The outcome of a carrier that failed to open: a refusal (an HTTP status,
/// a refused connection or upgrade), a timeout, or another failure.
fn io_outcome(e: &io::Error) -> CandidateOutcome {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => CandidateOutcome::Refused,
        io::ErrorKind::TimedOut => CandidateOutcome::TimedOut,
        _ => CandidateOutcome::Failed,
    }
}

fn connect_outcome(e: &ConnectError) -> CandidateOutcome {
    match e {
        ConnectError::Io(e) => io_outcome(e),
        ConnectError::SessionLost(SessionError::HandshakeTimeout) => CandidateOutcome::TimedOut,
        ConnectError::SessionLost(SessionError::PipesLost {
            last: Some(PipeFailure::Carrier(kind)),
        }) => io_outcome(&io::Error::from(*kind)),
        _ => CandidateOutcome::Failed,
    }
}

struct PreparedCarrier<D: Driver> {
    io: D::Carrier,
    open_time: Duration,
    deadline: Instant,
    cleanup: CleanupObserver,
}

fn bootstrap_request(attempt: AttemptId, deadline: Instant) -> OpenRequest {
    OpenRequest {
        attempt,
        cause: AttemptCause::Initial,
        need: crate::Directions::BOTH,
        stage: OpenStage::Bootstrap,
        layout: vec![AttachmentSpec::new(
            crate::Directions::BOTH,
            PipeOptions::default(),
        )],
        deadline,
    }
}

fn one_bootstrap_carrier<C>(mut opened: OpenedCarriersFor<C>) -> io::Result<C> {
    if let Some(error) = opened.error {
        return Err(error);
    }
    if opened.carriers.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected one bootstrap carrier",
        ));
    }
    opened
        .carriers
        .pop()
        .ok_or_else(|| io::Error::other("missing bootstrap carrier"))
}

async fn prepare_bootstrap<D: Driver>(
    candidate: &Candidate<D>,
    clock: &crate::ClockDomain,
    sequence: Arc<AtomicU64>,
    start: Instant,
    deadline: Instant,
    mut grant: Grant,
    admission: super::cache::AttemptStart,
) -> Result<PreparedCarrier<D>, CandidateResult> {
    // The domain remains busy through the physical return and its cache bookkeeping.
    let execution = grant.opener.take();
    let (opener, cleanup) = grant.reserve_opener::<D>(candidate.opener());
    let host_clock = clock.clone();
    let host_admission = admission.clone();
    let (send, task) = tokio::sync::oneshot::channel();
    D::spawn_controller(async move {
        let _execution = execution;
        let result = async {
            if host_clock.now() >= deadline {
                host_admission.suppress(crate::RetryAdmission::Deadline);
                return Err(crate::RetryAdmission::Deadline);
            }
            let _host = super::capacity_change::OpenerLifetime(&host_admission);
            host_admission.start()?;
            let previous = sequence
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .map_err(|_| crate::RetryAdmission::Stale)?;
            let attempt = AttemptId(previous + 1);
            super::capacity_change::catch_callback(async move {
                one_bootstrap_carrier(opener.open(bootstrap_request(attempt, deadline)).await)
            })
            .await
            .map_err(|_| crate::RetryAdmission::Stale)
        }
        .await;
        let _ = send.send(result);
    });
    let timed = super::deadline::sleep::<D>(clock, Some(deadline));
    let completion = tokio::select! {
        biased;
        () = timed => None,
        finished = task => Some(finished),
    };
    let io = match completion {
        Some(Ok(Ok(Ok(io)))) => io,
        Some(Ok(Ok(Err(error)))) => {
            admission.record_refusal(&error);
            return Err(result(
                candidate,
                false,
                Err((io_outcome(&error), error.to_string())),
            ));
        }
        Some(Ok(Err(reason))) => {
            return Err(result(
                candidate,
                false,
                Err((CandidateOutcome::Cancelled, reason.to_string())),
            ));
        }
        Some(Err(error)) => {
            return Err(result(
                candidate,
                false,
                Err((CandidateOutcome::Failed, error.to_string())),
            ));
        }
        None => {
            return Err(result(
                candidate,
                false,
                Err((
                    CandidateOutcome::TimedOut,
                    "the carrier did not open before the deadline".into(),
                )),
            ));
        }
    };
    Ok(PreparedCarrier {
        io,
        cleanup: cleanup
            .into_iter()
            .next()
            .expect("one bootstrap attachment"),
        open_time: clock.now().saturating_duration_since(start),
        deadline,
    })
}

async fn establish_bootstrap<D: Driver>(
    cand: &Candidate<D>,
    config: &Arc<Config>,
    prepared: PreparedCarrier<D>,
) -> (Option<Session<D>>, CandidateResult) {
    let now = config.clock_domain.now();
    let remaining = prepared.deadline.saturating_duration_since(now);
    let limit = prepared
        .open_time
        .saturating_mul(3)
        .clamp(Duration::from_secs(1), Duration::from_secs(3))
        .min(remaining);
    if remaining.is_zero() {
        let error = "the carrier's bootstrap deadline elapsed".to_owned();
        return (
            None,
            result(cand, false, Err((CandidateOutcome::TimedOut, error))),
        );
    }
    let deadline = now.checked_add(limit).unwrap_or(prepared.deadline);
    let mut timer = std::pin::pin!(super::deadline::sleep::<D>(
        &config.clock_domain,
        Some(deadline)
    ));
    // Exporter resolution and carrier registration may block on the native driver.
    // Keep the abandonment guard with the result even if the receiver has timed out.
    let (send, ready) = tokio::sync::oneshot::channel();
    let setup = config.clone();
    D::spawn_controller(async move {
        let result = D::controller_bootstrap(prepared.io, setup).map(|shared| {
            let guard = PendingEstablishment(Some(Arc::downgrade(&shared)));
            (shared, guard)
        });
        let _ = send.send(result);
    });
    let (shared, guard) = tokio::select! {
        biased;
        () = &mut timer => {
            return (None, result(cand, false, Err((CandidateOutcome::TimedOut, "bootstrap deadline elapsed during carrier setup".into()))));
        }
        setup = ready => match setup {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(error)) => return (None, result(cand, false, Err((connect_outcome(&error), error.to_string())))),
            Err(error) => return (None, result(cand, false, Err((CandidateOutcome::Failed, error.to_string())))),
        }
    };
    let mut established = std::pin::pin!(shared.established());
    // Abandon before dropping the establishment future closes the transport.
    let mut pending = guard;
    let r = std::future::poll_fn(|cx| {
        if config.clock_domain.now() >= deadline {
            return Poll::Ready(None);
        }
        if let Poll::Ready(r) = established.as_mut().poll(cx) {
            return Poll::Ready(Some(r));
        }
        timer.as_mut().poll(cx).map(|()| None)
    })
    .await;
    match r {
        Some(Ok(s)) => {
            pending.0 = None;
            confirm(&prepared.cleanup);
            (Some(s), result(cand, false, Ok(())))
        }
        Some(Err(e)) => (
            None,
            result(cand, false, Err((connect_outcome(&e), e.to_string()))),
        ),
        None => {
            // Abandoned before the pending establishment is dropped, so
            // that the session closes without CONNECTION_CLOSE.
            let e = format!(
                "{} carrier: no transport parameters within {limit:?}",
                cand.kind
            );
            (
                None,
                result(cand, false, Err((CandidateOutcome::TimedOut, e))),
            )
        }
    }
}

/// Candidate registry, selection policy and shared observations of one choice.
pub(crate) struct ChoiceSource<D: Driver> {
    candidates: Vec<Candidate<D>>,
    scored: bool,
    cache: CarrierCache,
    attempt_timeout: Duration,
    dial_after: super::controller::DialSchedule,
}

struct Ranked {
    index: usize,
    group: (u8, u64),
    score: CarrierRank,
}

pub(super) fn score_order(score: f64) -> u64 {
    // At 2^23, adjacent f64 scores already differ by more than a bucket.
    let rounded = if score < f64::from(1 << 23) {
        (score * 1e9).round_ties_even() / 1e9 + 0.0
    } else {
        score
    };
    rounded.to_bits()
}

struct OpeningTrial<'a, D: Driver> {
    index: usize,
    permit: AttemptPermit,
    work: TrialWork<'a, Result<PreparedCarrier<D>, CandidateResult>>,
}

type TrialWork<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

struct BootstrapTrial<'a, D: Driver> {
    index: usize,
    work: TrialWork<'a, (Option<Session<D>>, CandidateResult)>,
}

enum RaceStep<D: Driver> {
    Opened(usize, Box<Result<PreparedCarrier<D>, CandidateResult>>),
    Established(Option<Session<D>>, CandidateResult),
    StartNext(Option<(Grant, AttemptPermit)>),
}

/// The health observer attached to a member's pipes runs in the state commit.
pub(crate) struct MemberFaults {
    joined: Instant,
    window_end: Option<Instant>,
    state: std::sync::Mutex<MemberFaultState>,
}

struct MemberFaultState {
    source: Option<FeedbackSource>,
    needed: Vec<MemberDirection>,
    window_closed: bool,
    faulted: bool,
    service_since: Option<Instant>,
    exposure_since: Option<Instant>,
    sampled_rtt: Option<Instant>,
}

struct MemberDirection {
    pipe: PipeId,
    half: crate::PipeHalf,
    recovered: bool,
    settled: bool,
}

impl crate::proto::session::CapacityObserver for MemberFaults {
    fn capacity_sample(&self, rate: crate::AckDelivery) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.observation(
            CacheOutcome::Performance,
            CarrierObservation {
                at: Some(rate.end),
                rate: rate.bytes_per_second,
                valid_for: rate.valid_for,
                ..CarrierObservation::default()
            },
        );
    }
}

impl MemberFaults {
    pub(super) fn new(
        source: FeedbackSource,
        joined: Instant,
        stats: &[crate::PipeStats],
    ) -> Arc<Self> {
        let mut needed = Vec::new();
        for info in stats {
            for (half, direction) in [
                (crate::PipeHalf::Outbound, info.health.send),
                (crate::PipeHalf::Inbound, info.health.receive),
            ] {
                if direction.state != crate::PipeHealthState::Absent {
                    needed.push(MemberDirection {
                        pipe: info.pipe,
                        half,
                        recovered: direction.recovered(),
                        settled: direction.settled,
                    });
                }
            }
        }
        let service_since = needed.iter().all(|part| part.recovered).then_some(joined);
        Arc::new(Self {
            joined,
            window_end: joined.checked_add(source.cache.drop_window()),
            state: std::sync::Mutex::new(MemberFaultState {
                source: Some(source),
                needed,
                window_closed: false,
                faulted: false,
                service_since,
                exposure_since: None,
                sampled_rtt: None,
            }),
        })
    }

    pub(super) fn transfer(&self, next: Option<FeedbackSource>, at: Instant) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.advance(&mut state, at);
        let same = state
            .source
            .as_ref()
            .zip(next.as_ref())
            .is_some_and(|(old, new)| old.cache.shares_history(&new.cache) && old.key == new.key);
        if !same {
            state.close_exposure(at);
            state.service_since = state.service_since.map(|_| at);
        }
        state.source = next;
    }

    pub(crate) fn observe(&self, change: &crate::PipeHealthChange) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.advance(&mut state, change.at);
        if let Some(part) = state
            .needed
            .iter_mut()
            .find(|part| part.pipe == change.pipe && part.half == change.half)
        {
            part.recovered = change.after.recovered();
            part.settled = change.after.settled;
        }
        let recovered = !state.needed.is_empty() && state.needed.iter().all(|part| part.recovered);
        if recovered {
            state.service_since.get_or_insert(change.at);
        } else {
            state.service_since = None;
        }
        let settled = recovered && state.needed.iter().all(|part| part.settled);
        if !settled {
            state.close_exposure(change.at);
        }
        if change.at >= self.joined && change.reason.is_fault() && !change.before.reason.is_fault()
        {
            if state.faulted {
                return;
            }
            state.faulted = true;
            let outcome = if self.window_end.is_none_or(|end| change.at < end) {
                state.window_closed = true;
                CacheOutcome::ShortDrop
            } else {
                CacheOutcome::LateDrop
            };
            state.observation(
                outcome,
                CarrierObservation {
                    at: Some(change.at),
                    physical_failure: change.physical_failure.clone(),
                    ..CarrierObservation::default()
                },
            );
        } else if state.faulted && recovered {
            state.faulted = false;
        }
    }

    pub(crate) fn observe_time(&self, now: Instant) -> Option<Instant> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.advance(&mut state, now)
    }

    pub(super) fn observe_performance(&self, pipes: &[&crate::PipeStats]) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rtt = pipes
            .iter()
            .filter_map(|pipe| pipe.protocol_rtt)
            .max_by_key(|sample| sample.0);
        if let Some((at, rtt, valid_for)) = rtt
            && state.sampled_rtt.is_none_or(|old| at > old)
        {
            state.sampled_rtt = Some(at);
            state.observation(
                CacheOutcome::Performance,
                CarrierObservation {
                    at: Some(at),
                    rtt,
                    valid_for,
                    ..CarrierObservation::default()
                },
            );
        }
    }

    fn advance(&self, state: &mut MemberFaultState, now: Instant) -> Option<Instant> {
        let boundary = self.window_end?;
        let settled = !state.faulted
            && !state.needed.is_empty()
            && state.needed.iter().all(|part| part.settled);
        let mut next = None;
        if !state.window_closed && now >= boundary {
            state.window_closed = true;
            if settled {
                state.observation(
                    CacheOutcome::Survived,
                    CarrierObservation {
                        at: Some(boundary),
                        ..CarrierObservation::default()
                    },
                );
                state.exposure_since = state.source.is_some().then_some(boundary);
            }
        } else if !state.window_closed {
            next = Some(boundary);
        }
        if settled && now >= boundary && state.source.is_some() {
            state.exposure_since.get_or_insert(now);
        }
        if settled
            && let Some(start) = state.service_since
            && let Some(source) = &state.source
            && let Some((deadline, hold)) = source.cache.health_deadline(&source.key, start, now)
        {
            if deadline <= now {
                state.observation(
                    CacheOutcome::Recovered,
                    CarrierObservation {
                        at: Some(deadline),
                        duration: hold,
                        ..CarrierObservation::default()
                    },
                );
            } else {
                next = Some(next.map_or(deadline, |at| at.min(deadline)));
            }
        }
        next
    }
}

impl MemberFaultState {
    fn observation(&self, outcome: CacheOutcome, observation: CarrierObservation) {
        if let Some(source) = &self.source {
            source.observation(outcome, observation);
        }
    }

    fn close_exposure(&mut self, at: Instant) {
        if let Some(start) = self.exposure_since.take() {
            let duration = at.saturating_duration_since(start);
            if !duration.is_zero() {
                self.observation(
                    CacheOutcome::Lifetime,
                    CarrierObservation {
                        at: Some(at),
                        duration,
                        ..CarrierObservation::default()
                    },
                );
            }
        }
    }
}

impl<D: Driver> ChoiceSource<D> {
    pub(super) fn new(
        candidates: Vec<Candidate<D>>,
        scored: bool,
        cache: CarrierCache,
        attempt_timeout: Duration,
        dial_after: super::controller::DialSchedule,
    ) -> Self {
        Self {
            candidates,
            scored,
            cache,
            attempt_timeout,
            dial_after,
        }
    }

    pub(super) fn next_dial_after(&self) -> Option<Instant> {
        let now = self.cache.clock_domain().now();
        self.candidates
            .iter()
            .filter(|candidate| candidate.can_bootstrap())
            .filter_map(|candidate| self.dial_after.blocked(candidate.id.as_ref()?, now))
            .min()
    }

    fn key(candidate: &Candidate<D>) -> &str {
        candidate
            .cache_key
            .as_deref()
            .expect("registered candidates have cache keys")
    }

    fn score(&self, i: usize, now: Instant) -> CarrierRank {
        let candidate = &self.candidates[i];
        self.cache.rank_at(
            Self::key(candidate),
            candidate.kind,
            candidate.variant.as_deref().unwrap_or_default(),
            now,
        )
    }

    fn ranked(&self) -> Vec<Ranked> {
        let now = self.cache.clock_domain().now();
        let mut order: Vec<_> = self
            .candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| candidate.can_bootstrap())
            .map(|(index, candidate)| {
                let score = self.score(index, now);
                let round = if candidate.standby {
                    2
                } else {
                    u8::from(score.retry_at.is_some())
                };
                Ranked {
                    index,
                    group: (round, candidate.tier),
                    score,
                }
            })
            .collect();
        order.sort_by_key(|rank| {
            (
                rank.group,
                rank.score.retry_at,
                std::cmp::Reverse(if self.scored {
                    score_order(rank.score.score)
                } else {
                    0
                }),
                rank.index,
            )
        });
        order
    }

    pub(super) async fn race_bootstrap(
        &self,
        config: &Arc<Config>,
        owner: &Owner,
        results: &mut Vec<CandidateResult>,
    ) -> Option<(usize, Session<D>, u64)> {
        let deadline = self
            .cache
            .clock_domain()
            .now()
            .checked_add(config.handshake_wait())?;
        let sequence = Arc::new(AtomicU64::new(0));
        let mut changed = self.cache.subscribe();
        loop {
            let order = self.ranked();
            for stage in order.chunk_by(|a, b| a.group == b.group) {
                let during = self.race_stage(config, owner, stage, results, &sequence, deadline);
                let established = tokio::select! {
                    biased;
                    () = super::deadline::sleep::<D>(self.cache.clock_domain(), Some(deadline)) => None,
                    established = during => established,
                };
                if let Some((index, session)) = established {
                    return Some((index, session, sequence.load(Ordering::Relaxed)));
                }
            }
            let now = self.cache.clock_domain().now();
            if !results.is_empty() || order.is_empty() || now >= deadline {
                return None;
            }
            let retry = order
                .iter()
                .filter_map(|rank| {
                    let candidate = &self.candidates[rank.index];
                    self.dial_after
                        .blocked(candidate.id.as_ref()?, now)
                        .or_else(|| {
                            self.cache
                                .next_candidate_retry(Self::key(candidate), candidate, false)
                        })
                })
                .min()
                .unwrap_or(deadline)
                .min(deadline);
            owner.blocked();
            tokio::select! {
                () = super::deadline::sleep::<D>(self.cache.clock_domain(), Some(retry)) => {}
                _ = changed.changed() => {}
            }
        }
    }

    async fn race_stage(
        &self,
        config: &Arc<Config>,
        owner: &Owner,
        stage: &[Ranked],
        results: &mut Vec<CandidateResult>,
        sequence: &Arc<AtomicU64>,
        deadline: Instant,
    ) -> Option<(usize, Session<D>)> {
        let mut remaining = stage.iter();
        let mut opening = Vec::<OpeningTrial<'_, D>>::new();
        let mut ready = VecDeque::<(usize, AttemptPermit, PreparedCarrier<D>)>::new();
        let mut establishing = None::<BootstrapTrial<'_, D>>;
        let mut next_start = self.cache.clock_domain().now();
        loop {
            if establishing.is_none()
                && let Some((index, permit, opened)) = ready.pop_front()
            {
                let work = async move {
                    let result = establish_bootstrap(&self.candidates[index], config, opened).await;
                    if result.0.is_some() {
                        permit.confirm();
                    }
                    self.record(index, result.1.outcome, true);
                    result
                };
                establishing = Some(BootstrapTrial {
                    index,
                    work: Box::pin(work),
                });
            }
            let occupied = opening.len() + ready.len() + usize::from(establishing.is_some());
            let can_start = remaining.len() != 0;
            if !can_start {
                if occupied == 0 {
                    return None;
                }
                owner.blocked();
            }
            let progress = std::future::poll_fn(|cx| {
                if let Some(trial) = &mut establishing
                    && let Poll::Ready((session, result)) = trial.work.as_mut().poll(cx)
                {
                    return Poll::Ready(RaceStep::Established(session, result));
                }
                for (i, trial) in opening.iter_mut().enumerate() {
                    if let Poll::Ready(result) = trial.work.as_mut().poll(cx) {
                        return Poll::Ready(RaceStep::Opened(i, Box::new(result)));
                    }
                }
                Poll::Pending
            });
            let step = tokio::select! {
                biased;
                step = progress => step,
                grant = self.bootstrap_grant(owner, remaining.as_slice(), next_start), if can_start => RaceStep::StartNext(grant),
            };

            match step {
                RaceStep::StartNext(grant) => {
                    let index = remaining.next()?.index;
                    let Some((grant, permit)) = grant else {
                        continue;
                    };
                    let at = self.cache.clock_domain().now();
                    if at >= deadline {
                        return None;
                    }
                    let candidate = &self.candidates[index];
                    self.cache.prime(Self::key(candidate), candidate);
                    let work = prepare_bootstrap(
                        candidate,
                        self.cache.clock_domain(),
                        sequence.clone(),
                        at,
                        at.checked_add(self.attempt_timeout)
                            .map_or(deadline, |attempt| attempt.min(deadline)),
                        grant,
                        permit.start_handle(),
                    );
                    opening.push(OpeningTrial {
                        index,
                        permit,
                        work: Box::pin(work),
                    });
                    next_start = at + CONTROLLER_STAGGER;
                }
                RaceStep::Opened(i, opened) => {
                    let trial = opening.remove(i);
                    match *opened {
                        Ok(carrier) => ready.push_back((trial.index, trial.permit, carrier)),
                        Err(report) => {
                            self.record(trial.index, report.outcome, true);
                            results.push(report);
                            next_start = self.cache.clock_domain().now();
                        }
                    }
                }
                RaceStep::Established(session, report) => {
                    let index = establishing.take()?.index;
                    results.push(report);
                    if let Some(session) = session {
                        let cancelled = ready
                            .into_iter()
                            .map(|(i, _, _)| i)
                            .chain(opening.into_iter().map(|trial| trial.index));
                        results.extend(cancelled.map(|i| CandidateResult {
                            kind: self.candidates[i].kind,
                            variant: self.candidates[i].variant.clone(),
                            outcome: CandidateOutcome::Cancelled,
                            joined: false,
                            error: None,
                        }));
                        return Some((index, session));
                    }
                    next_start = self.cache.clock_domain().now();
                }
            }
        }
    }

    async fn bootstrap_grant(
        &self,
        owner: &Owner,
        remaining: &[Ranked],
        next_start: Instant,
    ) -> Option<(Grant, AttemptPermit)> {
        struct PendingDemand<'a>(&'a Owner);
        impl Drop for PendingDemand<'_> {
            fn drop(&mut self) {
                self.0.blocked();
            }
        }

        let index = remaining.first()?.index;
        let gate = self.dial_after.gate(self.candidates[index].id.as_ref()?);
        super::deadline::sleep::<D>(self.cache.clock_domain(), Some(next_start)).await;
        let _demand = PendingDemand(owner);
        let mut domain_changed = owner.subscribe();
        let mut cache_changed = self.cache.subscribe();
        loop {
            match self.grant_attempt(owner, index, 1, false, true, &gate) {
                Ok(grant) => return Some(grant),
                Err(
                    ControllerBlock::Retry
                    | ControllerBlock::DialAfter
                    | ControllerBlock::OwnerClosed,
                ) => return None,
                Err(_) => {
                    tokio::select! {
                        _ = domain_changed.changed() => {}
                        _ = cache_changed.changed() => {}
                    }
                }
            }
        }
    }

    pub(super) fn suppress_due(
        &self,
        owner: &Owner,
        index: usize,
        recovery: bool,
        reason: crate::RetryAdmission,
    ) {
        let candidate = &self.candidates[index];
        let key = Self::key(candidate);
        if owner
            .starts
            .opportunity(super::cache::candidate_key(key, candidate), recovery)
            .count()
        {
            self.cache.suppress(key, candidate, reason);
        }
    }

    pub(super) fn grant_attempt(
        &self,
        owner: &Owner,
        index: usize,
        cleanup: usize,
        recovery: bool,
        keep_pending: bool,
        gate: &super::controller::DialGate,
    ) -> Result<(Grant, AttemptPermit), ControllerBlock> {
        let candidate = &self.candidates[index];
        let key = Self::key(candidate);
        let block = |reason| {
            if reason == crate::RetryAdmission::DialAfter {
                ControllerBlock::DialAfter
            } else {
                ControllerBlock::Retry
            }
        };
        let suppress = |reason| {
            self.suppress_due(owner, index, recovery, reason);
            block(reason)
        };
        let at = self.cache.clock_domain().now();
        if let Err(reason) = if gate.blocked(at).is_some() {
            Err(crate::RetryAdmission::DialAfter)
        } else {
            self.cache.candidate_admission(key, candidate, recovery)
        } {
            owner.blocked();
            return Err(suppress(reason));
        }
        let mut refused = None;
        let grant = owner.grant_with(
            Demand {
                opener: true,
                cleanup,
            },
            keep_pending,
            || {
                self.cache
                    .begin(key, candidate, recovery, Some(gate.clone()))
                    .map(|permit| {
                        permit.with_opportunity(
                            owner
                                .starts
                                .opportunity(super::cache::candidate_key(key, candidate), recovery),
                        )
                    })
                    .map_err(|reason| {
                        refused = Some(reason);
                        block(reason)
                    })
            },
        );
        if let Some(reason) = refused {
            owner.blocked();
            suppress(reason);
        } else if let Err(
            ControllerBlock::Execution | ControllerBlock::Cleanup | ControllerBlock::QueueFull,
        ) = &grant
        {
            self.suppress_due(owner, index, recovery, crate::RetryAdmission::Capacity);
        }
        grant
    }

    pub(super) fn record(&self, i: usize, feedback: CandidateOutcome, start_cooling: bool) {
        let outcome = match feedback {
            CandidateOutcome::Usable => CacheOutcome::Usable,
            CandidateOutcome::Refused | CandidateOutcome::Failed | CandidateOutcome::TimedOut => {
                CacheOutcome::Failed
            }
            CandidateOutcome::Cancelled => return,
        };
        let candidate = &self.candidates[i];
        self.cache
            .record(Self::key(candidate), candidate, outcome, start_cooling);
    }

    pub(super) fn feedback(&self, index: usize) -> FeedbackSource {
        let candidate = &self.candidates[index];
        FeedbackSource {
            cache: self.cache.clone(),
            key: super::cache::candidate_key(Self::key(candidate), candidate),
        }
    }
}

#[derive(Clone)]
pub(super) struct FeedbackSource {
    cache: CarrierCache,
    key: super::cache::Key,
}

impl FeedbackSource {
    fn observation(&self, outcome: CacheOutcome, sample: CarrierObservation) {
        let (key, kind, variant) = &self.key;
        let _ = self.cache.report(key, *kind, variant, outcome, sample);
    }
}

#[cfg(test)]
#[test]
fn score_order_treats_signed_zero_as_one_bucket() {
    assert_eq!(score_order(-0.0), score_order(0.0));
    assert_eq!(score_order(0.5e-9), score_order(0.0));
    assert!(score_order(1e-9) > score_order(0.0));
}

#[cfg(test)]
#[test]
fn feedback_transfer_keeps_original_window_and_closes_exposure() {
    let origin = crate::ClockDomain::default().now();
    let cache = |window| {
        let mut config = crate::CarrierCacheConfig::default();
        config.drop_window = Duration::from_secs(window);
        CarrierCache::new(config).unwrap()
    };
    let old = cache(10);
    let next = cache(1);
    let key = ("route".into(), crate::CarrierKind::Streaming, String::new());
    let joined = origin.checked_sub(Duration::from_secs(20)).unwrap();
    let observer = MemberFaults {
        joined,
        window_end: Some(joined + Duration::from_secs(10)),
        state: std::sync::Mutex::new(MemberFaultState {
            source: Some(FeedbackSource {
                cache: old.clone(),
                key: key.clone(),
            }),
            needed: vec![MemberDirection {
                pipe: PipeId(0),
                half: crate::PipeHalf::Outbound,
                recovered: true,
                settled: true,
            }],
            window_closed: false,
            faulted: false,
            service_since: Some(joined),
            exposure_since: None,
            sampled_rtt: None,
        }),
    };
    let boundary = joined + Duration::from_secs(10);
    observer.transfer(
        Some(FeedbackSource {
            cache: next.clone(),
            key,
        }),
        joined + Duration::from_secs(2),
    );
    assert_eq!(
        observer.observe_time(joined + Duration::from_secs(3)),
        Some(boundary)
    );
    assert_eq!(
        next.score("route", crate::CarrierKind::Streaming, "")
            .window_survived,
        0.0
    );
    observer.observe_time(boundary);
    observer.transfer(None, boundary + Duration::from_secs(3));
    assert_eq!(
        old.score("route", crate::CarrierKind::Streaming, "")
            .window_survived,
        0.0
    );
    let score = next.score("route", crate::CarrierKind::Streaming, "");
    assert!(score.window_survived > 0.0);
    assert!(score.post_window_seconds > 2.9);
}
