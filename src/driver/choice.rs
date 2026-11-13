//! Carrier choice: a client dials a session over the carrier kind a
//! [`CarrierChoice`] selects, explicitly one, or automatically among candidates in
//! their order of preference, remembering per server and local network
//! which kinds the path lets through ([`CarrierCache`]).

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use super::cache::{CarrierCache, Known};
use super::handle;
use super::tokio::{Pipe, PipeIo, Session, Tokio};
use crate::ConnectError;
use crate::proto::session::{
    CandidateOutcome, CandidateResult, CarrierKind, Config, EarlyData, Multipath, PipeError,
    PipeFailure, PipeId, PipeOptions, Role, SessionError,
};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type DialFn = dyn Fn() -> BoxFuture<io::Result<PipeIo>> + Send + Sync;
type JoinFn = dyn Fn(Session, PipeOptions) -> BoxFuture<io::Result<Vec<Pipe>>> + Send + Sync;

/// One carrier kind a [`CarrierChoice`] may use: its kind and how to open a carrier
/// of it (the adapter's options, with the credential the server's
/// admission wants, captured in the dial). The adapters' `candidate`
/// constructors give ready ones. Cheap to clone.
#[derive(Clone)]
pub struct Candidate {
    kind: CarrierKind,
    variant: Option<Arc<str>>,
    target: Option<Arc<HttpTarget>>,
    dial: Arc<DialFn>,
    join: Option<Arc<JoinFn>>,
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

impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Candidate {
    /// A candidate of `kind` whose carriers `dial` opens. A carrier must
    /// live until its pipe ends; the choice bounds the opening.
    pub fn new<F, Fut>(kind: CarrierKind, dial: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<PipeIo>> + Send + 'static,
    {
        Self {
            kind,
            variant: None,
            target: None,
            dial: Arc::new(move || Box::pin(dial())),
            join: None,
        }
    }

    /// Joins carriers of the kind to an established session with `join`
    /// instead of [`Session::add_pipe`](Session#method.add_pipe) on a carrier of the dial: for a
    /// kind whose dial opens no carrier that can join, such as a split
    /// bootstrap, which joins as an uplink and a downlink. `join` joins
    /// with the options given and returns the pipes once their joins are
    /// confirmed.
    #[must_use]
    pub fn with_join<F, Fut>(mut self, join: F) -> Self
    where
        F: Fn(Session, PipeOptions) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<Vec<Pipe>>> + Send + 'static,
    {
        self.join = Some(Arc::new(move |s, o| Box::pin(join(s, o))));
        self
    }

    /// Wraps the candidate's dial: `wrap` gets each carrier the dial opens,
    /// once it is open, and returns the carrier to use, such as the same
    /// one with a host's shaping or accounting around it. Joins of
    /// [`with_join`](Self::with_join) open their own carriers and are not
    /// wrapped.
    #[must_use]
    pub fn wrap_dial<F, Fut>(self, wrap: F) -> Self
    where
        F: Fn(PipeIo) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<PipeIo>> + Send + 'static,
    {
        let (inner, wrap) = (self.dial, Arc::new(wrap));
        Self {
            dial: Arc::new(move || {
                let (open, wrap) = (inner(), wrap.clone());
                Box::pin(async move { wrap(open.await?).await })
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
    pub fn target(&self) -> Option<&Arc<HttpTarget>> {
        self.target.as_ref()
    }

    /// The candidate's kind.
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
    pub fn variant(&self) -> Option<&Arc<str>> {
        self.variant.as_ref()
    }

    /// Opens a carrier of the candidate.
    /// Its kind is the candidate's ([`PipeIo::with_carrier`]).
    pub async fn dial(&self) -> io::Result<PipeIo> {
        (self.dial)().await.map(|io| {
            let io = io.with_carrier(self.kind);
            match &self.variant {
                Some(v) => io.with_variant(v.clone()),
                None => io,
            }
        })
    }
}

/// How [`dial_choice`], or a pipe pool
/// ([`PipePool::choice`](crate::helpers::PipePool::choice)), chooses the
/// carrier.
#[derive(Debug, Clone)]
pub struct CarrierChoice {
    auto: bool,
    candidates: Vec<Candidate>,
}

impl CarrierChoice {
    /// `candidate` only: a failure is reported, never replaced by another
    /// kind.
    pub fn explicit(candidate: Candidate) -> Self {
        Self {
            auto: false,
            candidates: vec![candidate],
        }
    }

    /// A choice among `candidates`, in their order of preference (most
    /// preferred first).
    pub fn auto(candidates: impl IntoIterator<Item = Candidate>) -> Self {
        Self {
            auto: true,
            candidates: candidates.into_iter().collect(),
        }
    }

    /// Whether the choice chooses among candidates.
    pub fn is_auto(&self) -> bool {
        self.auto
    }

    /// The candidates, in order of preference.
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }
}

/// The local policy of [`CarrierChoice::auto`]. The defaults are those of each
/// field.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CarrierChoicePolicy {
    /// Remembers the outcomes per server and local network across dials
    /// (`None`: a cache private to the session).
    pub cache: Option<CarrierCache>,
    /// Names the server and the local network in the cache, such as the
    /// server's host with the name of the local network (empty by
    /// default).
    pub key: String,
    /// A candidate's timer is the round trip of opening its carrier times
    /// this (3), within [`timer_min`](Self::timer_min) (1 s) and
    /// [`timer_max`](Self::timer_max) (3 s). Request carriers return
    /// before any round trip, so for them the timer is the minimum.
    pub timer_factor: f64,
    /// The shortest timer (1 s).
    pub timer_min: Duration,
    /// The longest timer (3 s).
    pub timer_max: Duration,
    /// How long a joined pipe of a preferred kind stays joined before the
    /// pipes of the kind it replaces are retired (1 s).
    pub settle: Duration,
    /// A kind whose pipes (or session) fail within this long of being
    /// chosen counts as failed, so that the next dials skip it until its
    /// backoff expires (30 s).
    pub drop_window: Duration,
    /// Turns off establishing on the most robust candidate and joining the
    /// preferred ones: the candidates are then tried one after another
    /// (off). It does not apply to a pool.
    pub no_join: bool,
}

impl Default for CarrierChoicePolicy {
    fn default() -> Self {
        Self {
            cache: None,
            key: String::new(),
            timer_factor: 3.0,
            timer_min: Duration::from_secs(1),
            timer_max: Duration::from_secs(3),
            settle: Duration::from_secs(1),
            drop_window: Duration::from_secs(30),
            no_join: false,
        }
    }
}

impl CarrierChoicePolicy {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// With this cache and key.
    #[must_use]
    pub fn with_cache(mut self, cache: CarrierCache, key: impl Into<String>) -> Self {
        self.cache = Some(cache);
        self.key = key.into();
        self
    }

    /// Without joins ([`no_join`](Self::no_join)).
    #[must_use]
    pub fn without_join(mut self) -> Self {
        self.no_join = true;
        self
    }

    /// A candidate's timer for the round trip `rtt` of opening its carrier.
    pub fn timer(&self, rtt: Duration) -> Duration {
        let min = self.timer_min;
        let max = self.timer_max.max(min);
        rtt.mul_f64(self.timer_factor.max(0.0)).clamp(min, max)
    }
}

/// [`dial_choice`] found no usable candidate: the outcome of every one it
/// tried.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CarrierChoiceError {
    /// The tries, in order.
    pub results: Vec<CandidateResult>,
    /// The choice or the policy is invalid (nothing was tried): why.
    pub invalid: Option<crate::InvalidConfig>,
}

impl CarrierChoiceError {
    fn tried(results: Vec<CandidateResult>) -> Self {
        Self {
            results,
            invalid: None,
        }
    }

    fn invalid(why: crate::InvalidConfig) -> Self {
        Self {
            results: Vec::new(),
            invalid: Some(why),
        }
    }
}

impl fmt::Display for CarrierChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(why) = self.invalid {
            return write!(f, "invalid carrier choice: {why}");
        }
        f.write_str("no usable carrier")?;
        for (i, r) in self.results.iter().enumerate() {
            f.write_str(if i == 0 { ": " } else { "; " })?;
            write!(f, "{} {}", r.kind, r.outcome)?;
            if let Some(e) = &r.error {
                write!(f, " ({e})")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for CarrierChoiceError {}

/// Dials a client session over the carrier `choice` selects. `policy` is the policy of
/// [`CarrierChoice::auto`].
///
/// [`CarrierChoice::explicit`] dials its one candidate, within the configuration's
/// handshake timeout. [`CarrierChoice::auto`] sends no early data (the
/// configuration's [`EarlyData`] is ignored), so that nothing the
/// application sends goes out before a carrier is chosen, and races no
/// candidates. It skips the kinds the cache holds as failed (unless all
/// are), and a candidate whose session is not established within its
/// timer ([`CarrierChoicePolicy::timer`]) is abandoned without CONNECTION_CLOSE.
/// With `max_pipes` above 1 it establishes the session on the most robust
/// candidate (a kind the cache holds as usable, else the exchange carrier,
/// else the last) and, once multipath is in use, runs a pool of one member
/// over the same choice ([`PipePool::choice`](crate::helpers::PipePool::choice))
/// that takes the bootstrap pipe as its first member: the pool upgrades it
/// to a preferred kind, make before break, retries preferred kinds as
/// their backoff expires, and joins the best kind available again when the
/// member fails. Without joins (`max_pipes` 1, [`CarrierChoicePolicy::no_join`], or
/// a peer without multipath) it tries the candidates one after another, in
/// order, and keeps the first usable one.
///
/// Each try is reported as a
/// [`SessionEvent::CarrierCandidate`](crate::SessionEvent::CarrierCandidate),
/// the choice as a
/// [`SessionEvent::CarrierChosen`](crate::SessionEvent::CarrierChosen)
/// (again on every switch), and both in the session's statistics
/// ([`crate::SessionStats::carrier`]). The background work holds no handle
/// of the session and ends with it. A choice without candidates or with two
/// of one kind, or a policy with an invalid timer factor, is a
/// [`CarrierChoiceError`] with [`CarrierChoiceError::invalid`](CarrierChoiceError#structfield.invalid) set.
pub async fn dial_choice(
    choice: &CarrierChoice,
    config: impl Into<Arc<Config>>,
    policy: &CarrierChoicePolicy,
) -> Result<Session, CarrierChoiceError> {
    let src = ChoiceSource::new(choice, policy).map_err(CarrierChoiceError::invalid)?;
    let config = config.into();
    if !choice.auto {
        let first = &choice.candidates[0];
        let (session, res) = start(first, &config, None).await;
        let results = vec![res];
        let Some(s) = session else {
            return Err(CarrierChoiceError::tried(results));
        };
        s.report_carrier(&results, Some((first.kind, first.variant.clone())));
        return Ok(s);
    }
    let src = Arc::new(src);
    let mut cfg = (*config).clone();
    cfg.early_data = EarlyData::default();
    let config = Arc::new(cfg);
    let now = Instant::now();
    let mut order = src.usable(now);
    let join = !policy.no_join && config.max_pipes > 1;
    if join {
        let base = src.base(&order, now);
        order.retain(|&i| i != base);
        order.insert(0, base);
    }
    let p = &src.p;
    let mut results = Vec::new();
    for i in order {
        let cand = &src.cands[i];
        let (session, res) = start(cand, &config, Some(p)).await;
        results.push(res);
        p.cache.record(
            &p.key,
            cand.kind,
            cand.variant(),
            cand.target().map(|t| &**t),
            session.is_some(),
            Instant::now(),
        );
        let Some(s) = session else {
            continue;
        };
        s.report_carrier(&results, Some((cand.kind, cand.variant.clone())));
        let chosen = Instant::now();
        if join
            && s.multipath() == Multipath::InUse
            && let Some(pipe0) = s.pipe(PipeId(0))
        {
            crate::helpers::maintain_choice(&s, src, i, pipe0, chosen);
        } else if let Some(shared) = s.downgrade().shared() {
            // One carrier: the session ends with it, and counts against
            // its kind when it fails soon after it was chosen.
            tokio::spawn(async move {
                handle::closed_wait(&shared).await;
                if session_failed(&shared) {
                    src.dropped(i, chosen);
                }
            });
        }
        return Ok(s);
    }
    Err(CarrierChoiceError::tried(results))
}

/// The resolved policy.
#[derive(Clone)]
struct Params {
    policy: CarrierChoicePolicy,
    cache: CarrierCache,
    key: String,
}

impl Params {
    fn new(policy: &CarrierChoicePolicy) -> Self {
        Self {
            cache: policy.cache.clone().unwrap_or_default(),
            key: policy.key.clone(),
            policy: policy.clone(),
        }
    }

    fn timer(&self, rtt: Duration) -> Duration {
        self.policy.timer(rtt)
    }
}

fn result(
    cand: &Candidate,
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

fn pipe_outcome(e: &PipeError) -> CandidateOutcome {
    match e {
        PipeError::Failed(PipeFailure::Carrier(kind)) => io_outcome(&io::Error::from(*kind)),
        _ => CandidateOutcome::Failed,
    }
}

/// Opens a carrier of `cand` and starts a session on it, within the
/// configuration's handshake timeout; with `p` (an auto choice) the session
/// must be established within the candidate's timer, or it is abandoned
/// without CONNECTION_CLOSE.
async fn start(
    cand: &Candidate,
    config: &Arc<Config>,
    p: Option<&Params>,
) -> (Option<Session>, CandidateResult) {
    if let Some(p) = p {
        p.cache.prime(&p.key, cand);
    }
    let bound = config.handshake_wait();
    let t0 = Instant::now();
    let io = match tokio::time::timeout(bound, cand.dial()).await {
        Ok(Ok(io)) => io,
        Ok(Err(e)) => {
            return (
                None,
                result(cand, false, Err((io_outcome(&e), e.to_string()))),
            );
        }
        Err(_) => {
            let e = "the carrier did not open in time".to_owned();
            return (
                None,
                result(cand, false, Err((CandidateOutcome::TimedOut, e))),
            );
        }
    };
    let limit = match p {
        Some(p) => p.timer(t0.elapsed()),
        None => bound.saturating_sub(t0.elapsed()),
    };
    let shared = match handle::Shared::<Tokio>::create(
        io,
        config.clone(),
        Role::Client,
        Some(Role::Client),
        None,
        |_| {},
    ) {
        Ok(s) => s,
        Err(e) => {
            return (
                None,
                result(cand, false, Err((connect_outcome(&e), e.to_string()))),
            );
        }
    };
    let weak = Arc::downgrade(&shared);
    let established = shared.established();
    let mut established = std::pin::pin!(established);
    let mut timer = std::pin::pin!(tokio::time::sleep(limit));
    let r = std::future::poll_fn(|cx| {
        if let Poll::Ready(r) = established.as_mut().poll(cx) {
            return Poll::Ready(Some(r));
        }
        timer.as_mut().poll(cx).map(|()| None)
    })
    .await;
    match r {
        Some(Ok(s)) => (Some(s), result(cand, false, Ok(()))),
        Some(Err(e)) => (
            None,
            result(cand, false, Err((connect_outcome(&e), e.to_string()))),
        ),
        None => {
            // Abandoned before the pending establishment is dropped, so
            // that the session closes without CONNECTION_CLOSE.
            if let Some(s) = weak.upgrade() {
                s.abandon();
            }
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

/// Joins carriers of `cand` to `s` with `options` within the candidate's
/// timer.
async fn join_candidate(
    s: &Session,
    cand: &Candidate,
    p: &Params,
    options: PipeOptions,
) -> (Vec<Pipe>, CandidateResult) {
    p.cache.prime(&p.key, cand);
    let r: Result<Vec<Pipe>, (CandidateOutcome, String)> = async {
        if let Some(join) = &cand.join {
            return match tokio::time::timeout(p.policy.timer_min, join(s.clone(), options)).await {
                Ok(Ok(pipes)) if !pipes.is_empty() => Ok(pipes),
                Ok(Ok(_)) => Err((CandidateOutcome::Failed, "joined no pipe".into())),
                Ok(Err(e)) => Err((io_outcome(&e), e.to_string())),
                Err(_) => Err((
                    CandidateOutcome::TimedOut,
                    "join not confirmed in time".into(),
                )),
            };
        }
        let bound = s.shared().lock().core.config().handshake_wait();
        let t0 = Instant::now();
        let io = match tokio::time::timeout(bound, cand.dial()).await {
            Ok(Ok(io)) => io,
            Ok(Err(e)) => return Err((io_outcome(&e), e.to_string())),
            Err(_) => {
                return Err((
                    CandidateOutcome::TimedOut,
                    "the carrier did not open in time".into(),
                ));
            }
        };
        let limit = p.timer(t0.elapsed());
        // The candidate's timer bounds the join, and the pipe is aborted
        // here when it ends first.
        let pipe = s
            .begin_add_pipe(io, options)
            .map_err(|e| (pipe_outcome(&e), e.to_string()))?;
        let confirmed = async {
            pipe.joined().await?;
            inbound_open(&pipe).await;
            Ok::<(), PipeError>(())
        };
        match tokio::time::timeout(limit, confirmed).await {
            Ok(Ok(())) => Ok(vec![pipe]),
            Ok(Err(e)) => {
                let _ = pipe.abort();
                Err((pipe_outcome(&e), e.to_string()))
            }
            Err(_) => {
                let _ = pipe.abort();
                Err((
                    CandidateOutcome::TimedOut,
                    "join not confirmed in time".into(),
                ))
            }
        }
    }
    .await;
    match r {
        Ok(pipes) => (pipes, result(cand, true, Ok(()))),
        Err(e) => (Vec::new(), result(cand, true, Err(e))),
    }
}

/// Resolves once a joined pipe with an inbound half has received a record
/// on it: a carrier whose outbound direction passes but whose inbound one
/// an intermediary holds back (a response forwarded only after the
/// request) joins, yet carries nothing to this endpoint.
async fn inbound_open(pipe: &Pipe) {
    loop {
        match pipe.stats() {
            Some(s) if s.inbound.is_none() || s.records_received > 0 => return,
            None => return,
            _ => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}

/// Whether the session closed with an error other than an application
/// close (not merely dropped by the application).
pub(crate) fn session_failed(shared: &handle::Shared<Tokio>) -> bool {
    let error = shared.lock().core.error().cloned();
    !matches!(error, None | Some(SessionError::ApplicationClosed { .. }))
}

/// The carrier kinds of a pipe pool dialed by a carrier choice
/// ([`PipePool::choice`](crate::helpers::PipePool::choice)): stable first,
/// then upgrade. A member is dialed over the most robust kind available
/// ([`ChoiceSource::pick`]), and a member of a kind that a preferred kind not
/// backing off could replace is rotated to it ([`ChoiceSource::better`]).
/// The pool records the outcomes: a failed join, a replacement that ends
/// before it settled, and a member that fails within the drop window of
/// being joined count as failed. An explicit choice dials its one kind, without
/// the cache.
pub(crate) struct ChoiceSource {
    cands: Vec<Candidate>,
    auto: bool,
    p: Params,
}

impl ChoiceSource {
    /// Checks `choice` (candidates, no kind twice) and `policy`.
    pub(crate) fn new(
        choice: &CarrierChoice,
        policy: &CarrierChoicePolicy,
    ) -> Result<Self, crate::InvalidConfig> {
        if choice.candidates.is_empty() {
            return Err(crate::InvalidConfig::new("CarrierChoice", "no candidate"));
        }
        for (i, c) in choice.candidates.iter().enumerate() {
            if choice.candidates[..i].iter().any(|o| o.kind == c.kind) {
                return Err(crate::InvalidConfig::new(
                    "CarrierChoice",
                    "two candidates of one kind",
                ));
            }
        }
        if !(policy.timer_factor >= 0.0 && policy.timer_factor.is_finite()) {
            return Err(crate::InvalidConfig::new(
                "CarrierChoicePolicy::timer_factor",
                "negative or not finite",
            ));
        }
        Ok(Self {
            cands: choice.candidates.clone(),
            auto: choice.auto,
            p: Params::new(policy),
        })
    }

    fn failed(&self, i: usize, now: Instant) -> bool {
        matches!(
            self.p.cache.state(
                &self.p.key,
                self.cands[i].kind,
                self.cands[i].variant(),
                now
            ),
            Known::Failed(_)
        )
    }

    /// The candidates not backing off, in order (all of them when every
    /// one is).
    fn usable(&self, now: Instant) -> Vec<usize> {
        let order: Vec<usize> = (0..self.cands.len())
            .filter(|&i| !self.failed(i, now))
            .collect();
        if order.is_empty() {
            (0..self.cands.len()).collect()
        } else {
            order
        }
    }

    /// The most robust of `order`: a kind the cache holds as usable, else
    /// the exchange carrier, else the last.
    fn base(&self, order: &[usize], now: Instant) -> usize {
        let p = &self.p;
        order
            .iter()
            .copied()
            .find(|&i| {
                p.cache
                    .state(&p.key, self.cands[i].kind, self.cands[i].variant(), now)
                    == Known::Usable
            })
            .or_else(|| {
                order
                    .iter()
                    .copied()
                    .find(|&i| self.cands[i].kind == CarrierKind::Exchange)
            })
            .unwrap_or(order[order.len() - 1])
    }

    /// The kind to dial a new member over: the most robust one available.
    pub(crate) fn pick(&self) -> usize {
        if !self.auto {
            return 0;
        }
        let now = Instant::now();
        self.base(&self.usable(now), now)
    }

    /// The most preferred kind before `cur` that is not backing off, which
    /// a member of kind `cur` is rotated to.
    pub(crate) fn better(&self, cur: usize) -> Option<usize> {
        let now = Instant::now();
        (0..cur).find(|&i| self.auto && !self.failed(i, now))
    }

    /// The settle time of an upgrade.
    pub(crate) fn settle(&self) -> Duration {
        self.p.policy.settle
    }

    /// Joins a member of kind `i` to `session` with `options`, reporting
    /// the try; a failed try is recorded in the cache.
    pub(crate) fn join(
        self: &Arc<Self>,
        session: Session,
        i: usize,
        options: PipeOptions,
    ) -> impl Future<Output = io::Result<Vec<Pipe>>> + Send + 'static {
        let this = self.clone();
        async move {
            let cand = &this.cands[i];
            let (pipes, res) = join_candidate(&session, cand, &this.p, options).await;
            session.report_carrier(std::slice::from_ref(&res), None);
            if pipes.is_empty() {
                this.record(i, false);
                let kind = match res.outcome {
                    CandidateOutcome::Refused => io::ErrorKind::ConnectionRefused,
                    CandidateOutcome::TimedOut => io::ErrorKind::TimedOut,
                    _ => io::ErrorKind::Other,
                };
                return Err(io::Error::new(kind, res.error.unwrap_or_default()));
            }
            Ok(pipes)
        }
    }

    pub(crate) fn record(&self, i: usize, usable: bool) {
        if self.auto {
            self.p.cache.record(
                &self.p.key,
                self.cands[i].kind,
                self.cands[i].variant(),
                self.cands[i].target().map(|t| &**t),
                usable,
                Instant::now(),
            );
        }
    }

    /// Records kind `i` as usable and reports it as the session's carrier
    /// when it is not already.
    pub(crate) fn established(&self, session: &Session, i: usize) {
        self.record(i, true);
        let (kind, variant) = (self.cands[i].kind, &self.cands[i].variant);
        if !session.carrier_is(kind, variant.as_ref()) {
            session.report_carrier(&[], Some((kind, variant.clone())));
        }
    }

    /// Records kind `i` as failed when its member was joined (at `joined`)
    /// less than the drop window ago.
    pub(crate) fn dropped(&self, i: usize, joined: Instant) {
        if joined.elapsed() < self.p.policy.drop_window {
            self.record(i, false);
        }
    }
}
