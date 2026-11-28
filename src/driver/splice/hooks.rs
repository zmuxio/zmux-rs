//! Scoped transformations and group bounds.

use super::SpliceEnd;
use crate::{Preamble, StreamId, VarInt, proto::session::Backing};
use std::{
    collections::HashSet,
    fmt,
    future::Future,
    ops::Range,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

/// Direction in which a unit travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpliceRoute {
    /// From the first stream to the second.
    AtoB,
    /// From the second stream to the first.
    BtoA,
}

/// Shape and fixed protocol metadata of a splice unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpliceKind {
    /// A reliable byte block.
    Stream,
    /// A reliable capsule.
    Capsule {
        /// The capsule Type.
        ty: VarInt,
        /// The Context ID of a DATAGRAM capsule.
        context: Option<VarInt>,
    },
    /// A complete stream datagram.
    Datagram {
        /// The application's Context ID.
        context: VarInt,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) struct UnitBounds {
    pub(super) chunk: usize,
    pub(super) packet: usize,
    pub(super) opaque: usize,
}

impl From<&super::SpliceOptions> for UnitBounds {
    fn from(options: &super::SpliceOptions) -> Self {
        Self {
            chunk: options.chunk,
            packet: options.max_packet_payload,
            opaque: options.max_opaque_value,
        }
    }
}

impl UnitBounds {
    pub(super) fn cap(self, kind: SpliceKind) -> usize {
        match kind {
            SpliceKind::Stream => self.chunk,
            SpliceKind::Capsule { context: None, .. } => self.opaque,
            SpliceKind::Capsule {
                context: Some(_), ..
            }
            | SpliceKind::Datagram { .. } => self.packet,
        }
    }
}

/// Metadata fixed at the unit's admission. Stream IDs are hop-local.
#[derive(Debug)]
pub struct SpliceMeta<'a> {
    /// Direction that admitted this unit.
    pub route: SpliceRoute,
    /// Shape and fixed protocol metadata.
    pub kind: SpliceKind,
    /// Direction-local unit sequence.
    pub sequence: u64,
    /// Hook generation at admission.
    pub generation: u64,
    /// Offset of the original reliable input, when applicable.
    pub source_offset: Option<u64>,
    /// Whether the unit was injected locally.
    pub injected: bool,
    /// Source identifier, if assigned.
    pub source_stream: Option<StreamId>,
    /// Target identifier, if assigned.
    pub target_stream: Option<StreamId>,
    /// Whether the source can carry replayable data.
    pub replayable: bool,
    /// The inbound stream's opening metadata.
    pub preamble: &'a Preamble,
    /// A trusted route label supplied by the application.
    pub label: &'a str,
}

/// Hard bounds on retained splice work per direction.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SpliceLimits {
    /// Maximum transform steps per shape.
    pub hook_steps: usize,
    /// Maximum items in a replacement group.
    pub group_items: usize,
    /// Maximum logical output bytes, including reliable capsule headers.
    pub group_bytes: Option<usize>,
    /// Maximum distinct backing capacity held by a group at any instant.
    pub group_backing_bytes: Option<usize>,
    /// Maximum retained payload descriptors per unit or group.
    pub descriptors: usize,
    /// Maximum pending items across a direction's queues.
    pub queue_items: usize,
    /// Maximum distinct backing capacity held across a direction's queues.
    pub queue_bytes: Option<usize>,
    /// In-flight reliable limiter callbacks per direction.
    pub reliable_cleanup_slots: usize,
    /// In-flight datagram limiter callbacks per direction.
    pub datagram_cleanup_slots: usize,
    /// Enable queueing datagrams deferred by hooks.
    pub datagram_delay: bool,
    /// Safety cap from first admission. Zero selects 30 seconds.
    /// Use `None` to disable the safety cap.
    pub wait_cap: Option<Duration>,
}

impl Default for SpliceLimits {
    fn default() -> Self {
        Self {
            hook_steps: 16,
            group_items: 16,
            group_bytes: None,
            group_backing_bytes: None,
            descriptors: 256,
            queue_items: 64,
            queue_bytes: None,
            reliable_cleanup_slots: 1,
            datagram_cleanup_slots: 4,
            datagram_delay: false,
            wait_cap: Some(Duration::ZERO),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ResolvedLimits {
    pub(super) hook_steps: usize,
    pub(super) group_items: usize,
    pub(super) group_bytes: usize,
    pub(super) group_backing_bytes: usize,
    pub(super) descriptors: usize,
    pub(super) queue_items: usize,
    pub(super) queue_bytes: usize,
    pub(super) reliable_cleanup_slots: usize,
    pub(super) datagram_cleanup_slots: usize,
    pub(super) datagram_delay: bool,
    pub(super) wait_cap: Option<Duration>,
}

impl SpliceLimits {
    pub(super) fn resolve(self, unit: usize) -> Option<ResolvedLimits> {
        let group_bytes = resolve_bytes(self.group_bytes, 256 * 1024, unit)?;
        let min_backing = unit.checked_add(group_bytes)?;
        let group_backing_bytes =
            resolve_bytes(self.group_backing_bytes, 1024 * 1024, min_backing)?;
        let queue_bytes = resolve_bytes(self.queue_bytes, 4 * 1024 * 1024, unit)?;
        let wait_cap = self.wait_cap.map(|duration| {
            if duration.is_zero() {
                Duration::from_secs(30)
            } else {
                duration
            }
        });
        if self.hook_steps == 0
            || self.group_items == 0
            || self.descriptors == 0
            || self.queue_items == 0
            || self.queue_items > tokio::sync::Semaphore::MAX_PERMITS
            || queue_bytes > tokio::sync::Semaphore::MAX_PERMITS
            || !(1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&self.reliable_cleanup_slots)
            || !(1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&self.datagram_cleanup_slots)
            || wait_cap.is_some_and(|cap| Instant::now().checked_add(cap).is_none())
        {
            return None;
        }
        Some(ResolvedLimits {
            hook_steps: self.hook_steps,
            group_items: self.group_items,
            group_bytes,
            group_backing_bytes,
            descriptors: self.descriptors,
            queue_items: self.queue_items,
            queue_bytes,
            reliable_cleanup_slots: self.reliable_cleanup_slots,
            datagram_cleanup_slots: self.datagram_cleanup_slots,
            datagram_delay: self.datagram_delay,
            wait_cap,
        })
    }
}

fn resolve_bytes(configured: Option<usize>, default: usize, minimum: usize) -> Option<usize> {
    match configured {
        Some(bytes) => (bytes >= minimum).then_some(bytes),
        None => Some(default.max(minimum)),
    }
}

/// The transformation or admission exceeded a local budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpliceBudget;

impl fmt::Display for SpliceBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("splice_budget")
    }
}

impl std::error::Error for SpliceBudget {}

/// A short synchronous callback outside the session. It must not wait for
/// the splice or read or write either of its stream halves.
pub type SpliceHook =
    Arc<dyn Fn(&mut SpliceUnit<'_>) -> Result<SpliceDecision, SpliceBudget> + Send + Sync>;

/// One direction's hook lists.
#[derive(Clone, Default)]
pub struct SpliceHooks {
    /// Reliable byte blocks in a byte splice.
    pub stream: Vec<SpliceHook>,
    /// Complete reliable capsules in a packet splice.
    pub capsule: Vec<SpliceHook>,
    /// Complete stream datagrams in either mode.
    pub datagram: Vec<SpliceHook>,
}

impl SpliceHooks {
    pub(super) fn valid(&self, packets: bool, limits: ResolvedLimits) -> bool {
        let unused = if packets { &self.stream } else { &self.capsule };
        unused.is_empty()
            && [&self.stream, &self.capsule, &self.datagram]
                .iter()
                .all(|chain| chain.len() <= limits.hook_steps)
    }
}

#[derive(Clone, Default)]
pub(super) struct HookChain {
    pub(super) stream: Option<Arc<[SpliceHook]>>,
    pub(super) capsule: Option<Arc<[SpliceHook]>>,
    datagram: Option<Arc<[SpliceHook]>>,
}

impl From<SpliceHooks> for HookChain {
    fn from(hooks: SpliceHooks) -> Self {
        Self {
            stream: freeze(hooks.stream),
            capsule: freeze(hooks.capsule),
            datagram: freeze(hooks.datagram),
        }
    }
}

fn freeze(hooks: Vec<SpliceHook>) -> Option<Arc<[SpliceHook]>> {
    (!hooks.is_empty()).then(|| hooks.into())
}

impl HookChain {
    pub(super) fn get(&self, kind: SpliceKind) -> Option<&Arc<[SpliceHook]>> {
        match kind {
            SpliceKind::Stream => self.stream.as_ref(),
            SpliceKind::Capsule { .. } => self.capsule.as_ref(),
            SpliceKind::Datagram { .. } => self.datagram.as_ref(),
        }
    }

    pub(super) fn empty(&self) -> bool {
        self.stream.is_none() && self.capsule.is_none() && self.datagram.is_none()
    }
}

impl fmt::Debug for SpliceHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpliceHooks")
            .field("stream", &self.stream.len())
            .field("capsule", &self.capsule.len())
            .field("datagram", &self.datagram.len())
            .finish()
    }
}

/// A chain step's decision. Waits apply to the surviving group.
#[derive(Debug)]
pub enum SpliceDecision {
    /// Keep the current group, with optional readiness conditions.
    Pass(SpliceWait),
    /// Use the ordered outputs made by this invocation's builder.
    Replace(SpliceWait),
    /// Discard the group.
    Drop,
    /// Reset the target and stop the source with this code.
    Reset(VarInt),
}

impl Default for SpliceDecision {
    fn default() -> Self {
        Self::Pass(SpliceWait::default())
    }
}

/// One-shot signal shared between a hook and its resumer.
#[derive(Clone, Debug)]
pub struct SpliceSignal(watch::Sender<bool>);

impl Default for SpliceSignal {
    fn default() -> Self {
        Self(watch::Sender::new(false))
    }
}

impl SpliceSignal {
    /// Signal readiness. Signalling before the splice waits is supported.
    pub fn resume(&self) {
        self.0.send_replace(true);
    }
}

/// Readiness conditions for one hook step, on the Tokio monotonic clock.
#[derive(Debug, Default)]
pub struct SpliceWait {
    /// Earliest submission time.
    pub ready_at: Option<Instant>,
    /// Expiry, including time spent paused.
    pub expires_at: Option<Instant>,
    /// An optional one-shot readiness signal.
    pub resume: Option<SpliceSignal>,
}

#[derive(Default)]
pub(super) struct Readiness {
    pub(super) ready_at: Option<Instant>,
    pub(super) expires_at: Option<Instant>,
    signals: Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl Readiness {
    fn add(&mut self, wait: SpliceWait) {
        self.ready_at = self.ready_at.max(wait.ready_at);
        self.expires_at = self.expires_at.into_iter().chain(wait.expires_at).min();
        if let Some(signal) = wait.resume {
            let mut receiver = signal.0.subscribe();
            self.signals.push(Box::pin(async move {
                let _ = receiver.wait_for(|ready| *ready).await;
            }));
        }
    }

    pub(super) fn has_wait(&self) -> bool {
        self.ready_at.is_some() || self.expires_at.is_some() || !self.signals.is_empty()
    }

    pub(super) fn expire_by(&mut self, deadline: Instant) {
        self.expires_at = Some(self.expires_at.map_or(deadline, |t| t.min(deadline)));
    }

    pub(super) fn ready(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        self.signals
            .retain_mut(|signal| signal.as_mut().poll(cx) == Poll::Pending);
        self.signals.is_empty() && self.ready_at.is_none_or(|t| now >= t)
    }
}

/// A root identity changes when the receive allocator recycles a backing.
#[derive(Debug, Default)]
pub(super) struct Roots {
    ids: HashSet<u64>,
    bytes: usize,
}

impl Roots {
    pub(super) fn add(&mut self, chunk: &crate::Chunk, limit: usize) -> Result<(), SpliceBudget> {
        self.add_backing(chunk.backing, limit)
    }

    pub(super) fn add_backing(&mut self, root: Backing, limit: usize) -> Result<(), SpliceBudget> {
        if root.size != 0 && self.ids.insert(root.id) {
            self.reserve(root.size, limit)?;
        }
        Ok(())
    }

    pub(super) fn extend<'a>(
        &mut self,
        chunks: impl IntoIterator<Item = &'a crate::Chunk>,
        limit: usize,
    ) -> Result<(), SpliceBudget> {
        for chunk in chunks {
            self.add(chunk, limit)?;
        }
        Ok(())
    }

    pub(super) fn remaining(&self, limit: usize) -> usize {
        limit.saturating_sub(self.bytes)
    }

    pub(super) fn fits(&self, backing: Backing, limit: usize) -> bool {
        self.ids.contains(&backing.id) || backing.size <= self.remaining(limit)
    }

    pub(super) fn reserve(&mut self, capacity: usize, limit: usize) -> Result<(), SpliceBudget> {
        self.bytes = self
            .bytes
            .checked_add(capacity)
            .filter(|&n| n <= limit)
            .ok_or(SpliceBudget)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct Payload {
    pub(super) pieces: Vec<crate::Chunk>,
    pub(super) len: usize,
    pub(super) receive_view: bool,
}

impl Payload {
    pub(super) fn single(bytes: crate::Chunk) -> Self {
        let len = bytes.len();
        let pieces = if len == 0 { Vec::new() } else { vec![bytes] };
        Self {
            pieces,
            len,
            receive_view: false,
        }
    }

    pub(super) fn leased(bytes: crate::Chunk) -> Self {
        Self {
            receive_view: true,
            ..Self::single(bytes)
        }
    }

    fn windows(&self, range: Range<usize>) -> impl Iterator<Item = (&crate::Chunk, Range<usize>)> {
        let mut offset = 0;
        self.pieces.iter().filter_map(move |piece| {
            let lo = range.start.saturating_sub(offset);
            let hi = range.end.saturating_sub(offset).min(piece.len());
            offset += piece.len();
            (lo < hi).then_some((piece, lo..hi))
        })
    }

    fn slice(&self, range: Range<usize>) -> Self {
        Self {
            pieces: self
                .windows(range.clone())
                .map(|(piece, view)| piece.slice(view))
                .collect(),
            len: range.len(),
            receive_view: self.receive_view,
        }
    }
}

/// Borrowed input and bounded output builder for a single callback.
#[derive(Debug)]
pub struct SpliceUnit<'a> {
    /// Metadata shared by every step in the chain.
    pub meta: &'a SpliceMeta<'a>,
    payloads: SplicePayloads,
}

/// The bounded payload editor of one splice hook invocation.
///
/// Owns the immutable input and any outputs built for the next step. A host
/// binding can lend the editor to its callback without lending Rust references
/// or exposing the backing buffers.
#[derive(Debug)]
pub struct SplicePayloads {
    input: Vec<Payload>,
    output: Vec<Payload>,
    size: usize,
    pieces: usize,
    cap: usize,
    kind: SpliceKind,
    limits: ResolvedLimits,
    failure: Option<HookFailure>,
    roots: Roots,
}

impl SpliceUnit<'_> {
    /// Expose a revocable payload editor to a synchronous host callback.
    /// All escaped handles are invalidated when the callback exits.
    pub fn edit<T>(&mut self, edit: impl FnOnce(SpliceEditor) -> T) -> T {
        let empty = SplicePayloads::new(
            Vec::new(),
            self.payloads.cap,
            self.payloads.kind,
            self.payloads.limits,
            Roots::default(),
        );
        let scope = Scope {
            original: &mut self.payloads,
            editor: SpliceEditor(Arc::new(Mutex::new(None))),
        };
        *scope.editor.lock() = Some(std::mem::replace(scope.original, empty));
        edit(scope.editor.clone())
    }

    /// Number of ordered items seen by this step.
    #[must_use]
    pub fn items(&self) -> usize {
        self.payloads.items()
    }

    /// Immutable segments of an item by index.
    #[must_use]
    pub fn segments(&self, item: usize) -> Option<impl Iterator<Item = &[u8]>> {
        self.payloads.segments(item)
    }

    /// Append an immutable subview as one output.
    ///
    /// # Errors
    ///
    /// The range is invalid or the group exceeds its budget.
    pub fn slice(&mut self, item: usize, range: Range<usize>) -> Result<(), SpliceBudget> {
        self.payloads.slice(item, range)
    }

    /// Fill an output allocation directly, then freeze it.
    ///
    /// # Errors
    ///
    /// The group would exceed its budget.
    pub fn write(&mut self, len: usize, fill: impl FnOnce(&mut [u8])) -> Result<(), SpliceBudget> {
        self.payloads.write(len, fill)
    }
}

/// Revocable access to one hook's bounded payload editor.
#[derive(Clone, Debug)]
pub struct SpliceEditor(Arc<Mutex<Option<SplicePayloads>>>);

impl SpliceEditor {
    fn lock(&self) -> MutexGuard<'_, Option<SplicePayloads>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Use the editor if the callback has not returned. Keep the operation
    /// short and do not recursively access this editor from it.
    pub fn with<T>(&self, use_editor: impl FnOnce(&mut SplicePayloads) -> T) -> Option<T> {
        self.lock().as_mut().map(use_editor)
    }
}

struct Scope<'a> {
    original: &'a mut SplicePayloads,
    editor: SpliceEditor,
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        *self.original = self.editor.lock().take().expect("an editor in scope");
    }
}

impl SplicePayloads {
    fn new(
        input: Vec<Payload>,
        cap: usize,
        kind: SpliceKind,
        limits: ResolvedLimits,
        roots: Roots,
    ) -> Self {
        Self {
            input,
            output: Vec::new(),
            size: 0,
            pieces: 0,
            cap,
            kind,
            limits,
            failure: None,
            roots,
        }
    }

    /// Move immutable owned bytes into the output group without copying.
    ///
    /// # Errors
    ///
    /// The group would exceed its budget.
    pub fn push(&mut self, bytes: crate::Chunk) -> Result<(), SpliceBudget> {
        self.reserve(bytes.len(), usize::from(!bytes.is_empty()))?;
        if self
            .roots
            .add(&bytes, self.limits.group_backing_bytes)
            .is_err()
        {
            return self.fail(HookFailure::Budget);
        }
        self.output.push(Payload::single(bytes));
        Ok(())
    }

    /// Number of ordered items seen by this step.
    #[must_use]
    pub fn items(&self) -> usize {
        self.input.len()
    }

    /// Total payload length of an item, if present.
    #[must_use]
    pub fn len(&self, item: usize) -> Option<usize> {
        self.input.get(item).map(|p| p.len)
    }

    /// Immutable segments of an item by index.
    #[must_use]
    pub fn segments(&self, item: usize) -> Option<impl Iterator<Item = &[u8]>> {
        self.input
            .get(item)
            .map(|p| p.pieces.iter().map(AsRef::as_ref))
    }

    fn reserve(&mut self, len: usize, pieces: usize) -> Result<(), SpliceBudget> {
        if len > self.cap
            || self.output.len() >= self.limits.group_items
            || pieces > self.limits.descriptors - self.pieces
        {
            return self.fail(HookFailure::Budget);
        }
        let logical = if let SpliceKind::Capsule { ty, context } = self.kind {
            use crate::helpers::capsule;
            let mut header = [0; capsule::MAX_WIRE_HEADER];
            let width = capsule::encode_header(
                ty.into_inner(),
                context.map(VarInt::into_inner),
                len,
                &mut header,
            );
            len.checked_add(width)
        } else {
            Some(len)
        };
        let Some(logical) = logical.filter(|&n| n <= self.limits.group_bytes - self.size) else {
            return self.fail(HookFailure::Budget);
        };
        self.size += logical;
        self.pieces += pieces;
        Ok(())
    }

    fn fail(&mut self, failure: HookFailure) -> Result<(), SpliceBudget> {
        self.failure.get_or_insert(failure);
        Err(SpliceBudget)
    }

    /// Append an immutable subview as one output.
    ///
    /// # Errors
    ///
    /// The range is invalid or the group exceeds its budget.
    pub fn slice(&mut self, item: usize, range: Range<usize>) -> Result<(), SpliceBudget> {
        let Some(payload) = self.input.get(item) else {
            return self.fail(HookFailure::End(SpliceEnd::HookFailed));
        };
        if range.start > range.end || range.end > payload.len {
            return self.fail(HookFailure::End(SpliceEnd::HookFailed));
        }
        let pieces = payload.windows(range.clone()).count();
        self.reserve(range.len(), pieces)?;
        self.output.push(self.input[item].slice(range));
        Ok(())
    }

    /// Fill an output allocation directly. The writable borrow ends before
    /// it is frozen into the next stage's input.
    ///
    /// # Errors
    ///
    /// The group would exceed its budget.
    pub fn write(&mut self, len: usize, fill: impl FnOnce(&mut [u8])) -> Result<(), SpliceBudget> {
        self.reserve(len, usize::from(len > 0))?;
        if self
            .roots
            .reserve(len, self.limits.group_backing_bytes)
            .is_err()
        {
            return self.fail(HookFailure::Budget);
        }
        let mut bytes = vec![0; len].into_boxed_slice();
        fill(&mut bytes);
        self.output
            .push(Payload::single(crate::Chunk::from(bytes.into_vec())));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum HookFailure {
    End(SpliceEnd),
    Budget,
}

pub(super) type Verdict = Result<(Vec<Payload>, Readiness, u64), HookFailure>;

/// Owned metadata keeps the scoped callback independent of the owner and streams.
pub(super) struct HookInput {
    pub(super) chain: Arc<[SpliceHook]>,
    pub(super) route: SpliceRoute,
    pub(super) kind: SpliceKind,
    pub(super) sequence: u64,
    pub(super) generation: u64,
    pub(super) source_offset: Option<u64>,
    pub(super) injected: bool,
    pub(super) source_stream: Option<StreamId>,
    pub(super) target_stream: Option<StreamId>,
    pub(super) replayable: bool,
    pub(super) preamble: Preamble,
    pub(super) label: Option<Arc<str>>,
    pub(super) payload: Payload,
    pub(super) header: Option<Backing>,
}

impl HookInput {
    pub(super) fn run(self, limits: ResolvedLimits, cap: usize) -> Verdict {
        let meta = SpliceMeta {
            route: self.route,
            kind: self.kind,
            sequence: self.sequence,
            generation: self.generation,
            source_offset: self.source_offset,
            injected: self.injected,
            source_stream: self.source_stream,
            target_stream: self.target_stream,
            replayable: self.replayable,
            preamble: &self.preamble,
            label: self.label.as_deref().unwrap_or(""),
        };
        transform(
            &self.chain,
            &meta,
            limits,
            cap,
            vec![self.payload],
            self.header,
        )
    }
}

fn transform(
    chain: &[SpliceHook],
    meta: &SpliceMeta<'_>,
    limits: ResolvedLimits,
    cap: usize,
    mut payloads: Vec<Payload>,
    header: Option<Backing>,
) -> Verdict {
    let mut readiness = Readiness::default();
    let mut replacements = 0;
    for hook in chain {
        let mut roots = Roots::default();
        roots
            .extend(
                payloads.iter().flat_map(|payload| &payload.pieces),
                limits.group_backing_bytes,
            )
            .map_err(|_| HookFailure::Budget)?;
        if let Some(header) = header {
            roots
                .add_backing(header, limits.group_backing_bytes)
                .map_err(|_| HookFailure::Budget)?;
        }
        let mut unit = SpliceUnit {
            meta,
            payloads: SplicePayloads::new(payloads, cap, meta.kind, limits, roots),
        };
        let decision = catch_unwind(AssertUnwindSafe(|| hook(&mut unit)));
        if let Some(failure) = unit.payloads.failure {
            return Err(failure);
        }
        payloads = unit.payloads.input;
        match decision {
            Ok(Ok(SpliceDecision::Pass(wait))) => readiness.add(wait),
            Ok(Ok(SpliceDecision::Replace(wait))) => {
                payloads = unit.payloads.output;
                replacements += 1;
                if payloads.is_empty() {
                    break;
                }
                readiness.add(wait);
            }
            Ok(Ok(SpliceDecision::Drop)) => {
                payloads.clear();
                break;
            }
            Ok(Ok(SpliceDecision::Reset(code))) => {
                return Err(HookFailure::End(SpliceEnd::HookReset(code)));
            }
            Ok(Err(SpliceBudget)) => return Err(HookFailure::Budget),
            Err(_) => return Err(HookFailure::End(SpliceEnd::HookFailed)),
        }
    }
    Ok((payloads, readiness, replacements))
}
