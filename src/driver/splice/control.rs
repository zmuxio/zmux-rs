use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};

use crate::{DatagramDrop, DatagramError, VarInt, helpers::SpliceHandoffs};

use super::{
    SpliceAbort, SpliceEnd, SpliceHooks, SpliceKind, SpliceRoute,
    hooks::{HookChain, ResolvedLimits, UnitBounds},
};

/// Handles for one controlled splice. Poll the accompanying future to
/// accept commands and drive the transfer.
#[derive(Clone, Debug)]
pub struct SpliceController {
    /// Commands for the first stream's incoming direction.
    pub a_to_b: SpliceControl,
    /// Commands for the second stream's incoming direction.
    pub b_to_a: SpliceControl,
    pub(super) abort: SpliceAbort,
}

impl SpliceController {
    /// Abort both remaining directions with the given code.
    pub fn abort(&self, code: VarInt) {
        self.abort.abort(code);
    }
}

/// An event committed by a direction owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpliceEvent {
    /// A chain change has been published for new admissions.
    HooksReplaced {
        /// The new admission generation.
        generation: u64,
    },
    /// The direction reached a safe pause boundary.
    PauseAcknowledged {
        /// The direction-local pause token.
        token: u64,
    },
    /// The direction committed its terminal result.
    DirectionFinished {
        /// The terminal reason and its application code, when applicable.
        end: SpliceEnd,
    },
}

/// Receives direction events on the task driving the splice.
#[derive(Clone)]
pub struct SpliceEventSink(Arc<dyn Fn(SpliceRoute, SpliceEvent) + Send + Sync>);

impl SpliceEventSink {
    /// Register a short synchronous observer. It runs outside session locks
    /// and must return promptly without waiting on the splice.
    pub fn new(observe: impl Fn(SpliceRoute, SpliceEvent) + Send + Sync + 'static) -> Self {
        Self(Arc::new(observe))
    }

    pub(super) fn emit(&self, route: SpliceRoute, event: SpliceEvent) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.0)(route, event)));
    }
}

impl fmt::Debug for SpliceEventSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpliceEventSink").finish_non_exhaustive()
    }
}

/// One direction's command sender.
#[derive(Clone, Debug)]
pub struct SpliceControl {
    tx: mpsc::Sender<Command>,
    bytes: Arc<Semaphore>,
    limits: ResolvedLimits,
    bounds: UnitBounds,
    packets: bool,
    end: watch::Receiver<Option<SpliceEnd>>,
    handoffs: SpliceHandoffs,
    pre_admission_refunds: Arc<AtomicU64>,
    #[cfg(feature = "test-hooks")]
    fixture: Arc<FixtureState>,
}

/// Why a direction refused a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpliceCommandError {
    /// The direction sealed admissions.
    Closed,
    /// The supplied unit or hook set is invalid.
    InvalidParameter,
    /// The command or injection budget was exhausted.
    SpliceBudget,
    /// The direction is paused.
    Paused,
    /// The splice was cancelled before acceptance.
    Cancelled,
    /// A newer pause superseded the token, or it belongs to another direction.
    StalePause,
}

impl fmt::Display for SpliceCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "closed",
            Self::InvalidParameter => "invalid_parameter",
            Self::SpliceBudget => "splice_budget",
            Self::Paused => "paused",
            Self::Cancelled => "cancelled",
            Self::StalePause => "stale splice pause token",
        })
    }
}

impl std::error::Error for SpliceCommandError {}

/// A typed local input offered to the current chain.
#[derive(Debug)]
pub struct SpliceInjection {
    /// Input shape and protocol metadata.
    pub kind: SpliceKind,
    /// Immutable payload. For a DATAGRAM capsule this excludes Context ID.
    pub payload: crate::Chunk,
}

/// Acknowledgement that an injection obtained a direction-local position.
#[derive(Debug)]
pub struct SpliceReceipt {
    /// Direction-local sequence number.
    pub sequence: u64,
    /// Hook generation used for the injection.
    pub generation: u64,
    pub(super) done: oneshot::Receiver<SpliceDisposition>,
}

impl SpliceReceipt {
    /// Wait for local disposition. Dropping the receipt leaves the injection admitted.
    ///
    /// # Errors
    ///
    /// The driving future was dropped before publishing the disposition.
    pub async fn disposition(self) -> Result<SpliceDisposition, SpliceCommandError> {
        result(self.done).await
    }
}

/// Why a source group was discarded before target publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpliceDropReason {
    /// A hook dropped the unit or removed all its children.
    Hook,
    /// A deadline elapsed.
    Expired,
    /// An item or backing capacity bound was reached.
    QueueFull,
    /// A nonblocking reservation was refused or short.
    Limiter,
    /// Admission was temporarily unavailable.
    Blocked,
    /// The payload was too large for the selected representation.
    TooLarge,
    /// No permitted representation was structurally available.
    NoPath,
    /// The target exhausted its sequence space.
    SequenceExhausted,
    /// The owning flow closed.
    FlowClosed,
    /// The core delay controller discarded the datagram.
    Codel,
}

impl SpliceDropReason {
    pub(super) fn from_datagram(error: &DatagramError) -> Self {
        match error {
            DatagramError::Dropped(DatagramDrop::Deadline) => Self::Expired,
            DatagramError::Dropped(DatagramDrop::QueueOverflow) => Self::QueueFull,
            DatagramError::Dropped(DatagramDrop::Limiter) => Self::Limiter,
            DatagramError::Dropped(DatagramDrop::Codel) => Self::Codel,
            DatagramError::Dropped(DatagramDrop::SequenceExhausted)
            | DatagramError::SequenceExhausted => Self::SequenceExhausted,
            DatagramError::Dropped(DatagramDrop::ClosedFlow)
            | DatagramError::ClosedStream
            | DatagramError::SessionLost(_) => Self::FlowClosed,
            DatagramError::Dropped(DatagramDrop::Size) | DatagramError::TooLarge { .. } => {
                Self::TooLarge
            }
            DatagramError::Dropped(DatagramDrop::NoNativePath) | DatagramError::NotNegotiated => {
                Self::NoPath
            }
            _ => Self::Blocked,
        }
    }

    /// The stable name used in comparable observations.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hook => "dropped_hook",
            Self::Expired => "dropped_expired",
            Self::QueueFull => "dropped_queue_full",
            Self::Limiter => "dropped_limiter",
            Self::Blocked => "dropped_blocked",
            Self::TooLarge => "dropped_too_large",
            Self::NoPath => "dropped_no_path",
            Self::SequenceExhausted => "dropped_sequence_exhausted",
            Self::FlowClosed => "dropped_flow_closed",
            Self::Codel => "dropped_codel",
        }
    }
}

/// Final status of an accepted injection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SpliceInjectionStatus {
    /// Target acceptance completed.
    #[default]
    Submitted,
    /// The group was discarded before target publication.
    Dropped(SpliceDropReason),
    /// The direction ended before local submission completed.
    DirectionEnded(SpliceEnd),
}

/// Outcome of an admitted injection at the local target queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpliceDisposition {
    /// Disposition of the accepted input.
    pub status: SpliceInjectionStatus,
    /// Direction-local sequence number.
    pub sequence: u64,
    /// Hook generation used for the injection.
    pub generation: u64,
    /// Logical bytes enqueued at the target, including any partial write.
    pub accepted_bytes: u64,
    /// Complete items enqueued at the target.
    pub enqueued_items: u64,
}

/// A single pause generation in a direction.
#[derive(Debug)]
pub struct SplicePause {
    /// The direction-local pause generation.
    pub generation: u64,
    owner: mpsc::WeakSender<Command>,
    ready: watch::Receiver<Option<Result<(), SpliceCommandError>>>,
    _lease: oneshot::Sender<()>,
}

impl SplicePause {
    /// Wait until the current write has reached a safe pause boundary.
    ///
    /// # Errors
    ///
    /// The direction ended or resumed before reaching the boundary.
    pub async fn acknowledged(&self) -> Result<(), SpliceCommandError> {
        let mut ready = self.ready.clone();
        ready
            .wait_for(Option::is_some)
            .await
            .map_err(|_| SpliceCommandError::Closed)?
            .expect("published pause acknowledgement")
    }
}

type Reply<T> = oneshot::Sender<Result<T, SpliceCommandError>>;

pub(super) enum Command {
    Replace(HookChain, Reply<u64>),
    Pause(mpsc::WeakSender<Command>, Reply<SplicePause>),
    Resume(u64, Reply<()>),
    Inject(SpliceInjection, OwnedSemaphorePermit, Reply<SpliceReceipt>),
}

pub(super) struct Inbox {
    pub(super) commands: mpsc::Receiver<Command>,
    end: watch::Sender<Option<SpliceEnd>>,
    pub(super) handoffs: SpliceHandoffs,
    pub(super) pre_admission_refunds: Arc<AtomicU64>,
    pub(super) generation: AtomicU64,
    #[cfg(feature = "test-hooks")]
    pub(super) fixture: Arc<FixtureState>,
}

#[cfg(feature = "test-hooks")]
#[derive(Debug, Default)]
pub(super) struct FixtureState {
    pub(super) source_batches: AtomicU64,
    pub(super) control_reads: AtomicU64,
    pub(super) queue_full: AtomicU64,
    pub(super) refused: AtomicU64,
}

impl Inbox {
    pub(super) fn start_source_batch(&self) -> u64 {
        #[cfg(feature = "test-hooks")]
        self.fixture.source_batches.fetch_add(1, Ordering::Relaxed);
        let generation = self.generation.load(Ordering::Relaxed);
        #[cfg(feature = "test-hooks")]
        self.fixture.control_reads.fetch_add(1, Ordering::Relaxed);
        generation
    }

    pub(super) fn finish(mut self, end: SpliceEnd) {
        self.commands.close();
        let error = match end {
            SpliceEnd::Cancelled(_) => SpliceCommandError::Cancelled,
            _ => SpliceCommandError::Closed,
        };
        while let Ok(command) = self.commands.try_recv() {
            match command {
                Command::Replace(_, reply) => {
                    let _ = reply.send(Err(error));
                }
                Command::Pause(_, reply) => {
                    let _ = reply.send(Err(error));
                }
                Command::Resume(_, reply) => {
                    let _ = reply.send(Err(error));
                }
                Command::Inject(_, _, reply) => {
                    let _ = reply.send(Err(error));
                }
            }
        }
        self.end.send_replace(Some(end));
    }
}

async fn result<T>(
    rx: impl Future<Output = Result<T, oneshot::error::RecvError>>,
) -> Result<T, SpliceCommandError> {
    rx.await.map_err(|_| SpliceCommandError::Closed)
}

impl SpliceControl {
    pub(super) fn new(packets: bool, bounds: UnitBounds, limits: ResolvedLimits) -> (Self, Inbox) {
        let (tx, commands) = mpsc::channel(limits.queue_items);
        let (finish, end) = watch::channel(None);
        let handoffs = SpliceHandoffs::default();
        let pre_admission_refunds = Arc::new(AtomicU64::default());
        #[cfg(feature = "test-hooks")]
        let fixture = Arc::new(FixtureState::default());
        (
            Self {
                tx,
                bytes: Arc::new(Semaphore::new(limits.queue_bytes)),
                limits,
                bounds,
                packets,
                end,
                handoffs: handoffs.clone(),
                pre_admission_refunds: pre_admission_refunds.clone(),
                #[cfg(feature = "test-hooks")]
                fixture: fixture.clone(),
            },
            Inbox {
                commands,
                end: finish,
                handoffs,
                pre_admission_refunds,
                generation: AtomicU64::default(),
                #[cfg(feature = "test-hooks")]
                fixture,
            },
        )
    }

    /// Observes target settlements during and after the direction's lifetime.
    #[must_use]
    pub fn handoffs(&self) -> &SpliceHandoffs {
        &self.handoffs
    }

    /// Bytes returned by limiter requests before target acceptance, including
    /// late grants refunded after the direction ends.
    #[must_use]
    pub fn pre_admission_refunded_bytes(&self) -> u64 {
        self.pre_admission_refunds.load(Ordering::Relaxed)
    }

    /// Observes the number of source read batches and atomic control reads.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn fixture_read_work(&self) -> (u64, u64) {
        (
            self.fixture.source_batches.load(Ordering::Relaxed),
            self.fixture.control_reads.load(Ordering::Relaxed),
        )
    }

    /// Observes settled queue and limiter rejections for a fixture barrier.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn fixture_datagram_drops(&self) -> (u64, u64) {
        (
            self.fixture.queue_full.load(Ordering::Relaxed),
            self.fixture.refused.load(Ordering::Relaxed),
        )
    }

    /// Observe the direction's reliable end. Session-owned datagrams may
    /// still be draining when this completes.
    ///
    /// # Errors
    ///
    /// The splice was dropped before it published an end.
    pub async fn finished(&self) -> Result<SpliceEnd, SpliceCommandError> {
        let mut end = self.end.clone();
        end.wait_for(Option::is_some)
            .await
            .map(|value| value.expect("published end"))
            .map_err(|_| SpliceCommandError::Closed)
    }

    async fn command<T>(
        &self,
        build: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, SpliceCommandError> {
        let (reply, rx) = oneshot::channel();
        self.tx.try_send(build(reply)).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => SpliceCommandError::SpliceBudget,
            mpsc::error::TrySendError::Closed(_) => SpliceCommandError::Closed,
        })?;
        result(rx).await?
    }

    /// Install a whole chain at the next admission boundary. The returned
    /// generation applies to new inputs.
    ///
    /// # Errors
    ///
    /// The configuration is invalid, the queue is full or the direction is closed.
    pub async fn replace_hooks(&self, hooks: SpliceHooks) -> Result<u64, SpliceCommandError> {
        if !hooks.valid(self.packets, self.limits) {
            return Err(SpliceCommandError::InvalidParameter);
        }
        self.command(|reply| Command::Replace(hooks.into(), reply))
            .await
    }

    /// Freeze new admissions and submissions. The returned token reports
    /// when the safe output boundary has been reached. Dropping the token
    /// releases the pause, including when the caller withdraws the command.
    ///
    /// # Errors
    ///
    /// The command queue is full or the direction is closed.
    pub async fn pause(&self) -> Result<SplicePause, SpliceCommandError> {
        self.command(|reply| Command::Pause(self.tx.downgrade(), reply))
            .await
    }

    /// Resume a pause of this direction, idempotently for that generation.
    ///
    /// # Errors
    ///
    /// The token belongs to another pause, the queue is full or the direction is closed.
    pub async fn resume(&self, pause: &SplicePause) -> Result<(), SpliceCommandError> {
        if !pause
            .owner
            .upgrade()
            .is_some_and(|tx| tx.same_channel(&self.tx))
        {
            return Err(SpliceCommandError::StalePause);
        }
        self.command(|reply| Command::Resume(pause.generation, reply))
            .await
    }

    /// Offer an input to the current chain and receive its admission receipt.
    ///
    /// # Errors
    ///
    /// The input is invalid, exceeds a budget, or the direction is paused or closed.
    pub async fn inject(
        &self,
        injection: SpliceInjection,
    ) -> Result<SpliceReceipt, SpliceCommandError> {
        let valid_kind = match injection.kind {
            SpliceKind::Stream => !self.packets,
            SpliceKind::Capsule { ty, context } => {
                self.packets && (ty == VarInt::ZERO) == context.is_some()
            }
            SpliceKind::Datagram { .. } => true,
        };
        if !valid_kind || injection.payload.len() > self.bounds.cap(injection.kind) {
            return Err(SpliceCommandError::InvalidParameter);
        }
        let len = u32::try_from(injection.payload.backing_capacity())
            .map_err(|_| SpliceCommandError::SpliceBudget)?;
        let permit = self
            .bytes
            .clone()
            .try_acquire_many_owned(len)
            .map_err(|_| SpliceCommandError::SpliceBudget)?;
        self.command(move |reply| Command::Inject(injection, permit, reply))
            .await
    }

    pub(super) fn pause_token(
        generation: u64,
        owner: mpsc::WeakSender<Command>,
        ready: watch::Receiver<Option<Result<(), SpliceCommandError>>>,
        lease: oneshot::Sender<()>,
    ) -> SplicePause {
        SplicePause {
            generation,
            owner,
            ready,
            _lease: lease,
        }
    }
}
