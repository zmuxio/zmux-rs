use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep_until},
};

use crate::driver::{
    handle::{Upstream, WaitSlot},
    tokio::Tokio,
};
use crate::helpers::{SendPolicy, SpliceHandoffs, capsule};
use crate::proto::session::splice_handoff::Prepayment;
use crate::proto::session::{
    Backing, PacketRepresentation, ResolvedDatagramOptions, SpliceDatagram,
};
use crate::{
    DatagramError, DatagramSendOptions, RecvStream, SendStream, StreamError, VarInt,
    proto::ApplicationErrorCode,
};

use super::{
    AbortSlot, ControlledSpliceOptions, POLL_STEPS, STEP, SpliceAbort, SpliceBudget,
    SpliceCommandError as CommandError, SpliceControl, SpliceController, SpliceDirection,
    SpliceDisposition, SpliceDropReason as DropReason, SpliceDrops, SpliceEnd, SpliceError,
    SpliceEvent, SpliceEventSink, SpliceInjection, SpliceInjectionStatus as Status, SpliceKind,
    SpliceLimits, SpliceMeta, SpliceMirror, SpliceOptions, SpliceReceipt, SpliceResult,
    SpliceRoute, code,
    control::{Command, Inbox},
    hooks::{
        HookChain, HookFailure, HookInput, Payload, Readiness, ResolvedLimits, Roots, UnitBounds,
        Verdict,
    },
    mirror::MirrorPublisher,
    permit::{Grant, ReliableRequest, Request, Requests},
};

type Halves = (SendStream, RecvStream);

/// Construct a controlled byte splice and its driving future.
///
/// # Errors
///
/// Invalid initial options or streams that would forward into themselves.
pub fn controlled_splice(
    a: Halves,
    b: Halves,
    opts: ControlledSpliceOptions,
) -> Result<(SpliceController, impl Future<Output = SpliceResult> + Send), SpliceError> {
    controlled(a, b, opts, false)
}

/// Construct a controlled splice of two streams carrying capsules.
///
/// # Errors
///
/// Invalid initial options or streams that would forward into themselves.
pub fn controlled_splice_packets(
    a: Halves,
    b: Halves,
    opts: ControlledSpliceOptions,
) -> Result<(SpliceController, impl Future<Output = SpliceResult> + Send), SpliceError> {
    controlled(a, b, opts, true)
}

fn controlled(
    a: Halves,
    b: Halves,
    opts: ControlledSpliceOptions,
    packets: bool,
) -> Result<(SpliceController, impl Future<Output = SpliceResult> + Send), SpliceError> {
    validate_halves(&a, &b)?;
    let limits = opts.forwarding.resolve(packets, opts.limits)?;
    if !opts.a_to_b_hooks.valid(packets, limits) || !opts.b_to_a_hooks.valid(packets, limits) {
        return Err(SpliceError::InvalidOptions);
    }
    let bounds = UnitBounds::from(&opts.forwarding);
    let (a_to_b, ab) = SpliceControl::new(packets, bounds, limits);
    let (b_to_a, ba) = SpliceControl::new(packets, bounds, limits);
    let abort = opts.forwarding.abort.clone().unwrap_or_default();
    let ctl = SpliceController {
        a_to_b,
        b_to_a,
        abort: abort.clone(),
    };
    Ok((ctl, async move {
        run(
            a,
            b,
            Run {
                forwarding: &opts.forwarding,
                policy: Some(&opts),
                packets,
                limits,
                abort: Some(&abort),
            },
            [Some(ab), Some(ba)],
        )
        .await
    }))
}

pub(super) fn validate_halves(a: &Halves, b: &Halves) -> Result<(), SpliceError> {
    if b.0.same_stream(&a.1) || a.0.same_stream(&b.1) {
        return Err(SpliceError::SameStream);
    }
    Ok(())
}

pub(super) async fn run_static(
    a: Halves,
    b: Halves,
    opts: SpliceOptions,
) -> Result<SpliceResult, SpliceError> {
    validate_halves(&a, &b)?;
    let limits = opts.resolve(true, SpliceLimits::default())?;
    Ok(run(
        a,
        b,
        Run {
            forwarding: &opts,
            policy: None,
            packets: true,
            limits,
            abort: opts.abort.as_ref(),
        },
        [None, None],
    )
    .await)
}

struct Run<'a> {
    forwarding: &'a SpliceOptions,
    policy: Option<&'a ControlledSpliceOptions>,
    packets: bool,
    limits: ResolvedLimits,
    abort: Option<&'a SpliceAbort>,
}

async fn run(
    (a_send, a_recv): Halves,
    (b_send, b_recv): Halves,
    options: Run<'_>,
    [ab_commands, ba_commands]: [Option<Inbox>; 2],
) -> SpliceResult {
    let mut ab = Relay::new(&a_recv, &b_send, &options, SpliceRoute::AtoB, ab_commands);
    let mut ba = Relay::new(&b_recv, &a_send, &options, SpliceRoute::BtoA, ba_commands);
    let mut abort = AbortSlot(options.abort, None);
    poll_fn(|cx| {
        if let Some(handle) = abort.0
            && let Some(code) = handle.poll(&mut abort.1, cx.waker())
        {
            for direction in [&mut ab, &mut ba] {
                direction.fail(SpliceEnd::Cancelled(code), code);
            }
        }
        if ab.end.is_none() || ba.end.is_none() {
            ab.poll(cx);
            ba.poll(cx);
        }
        match (ab.end, ba.end) {
            (Some(a), Some(b)) => {
                ab.discard_datagrams(a);
                ba.discard_datagrams(b);
                Poll::Ready(SpliceResult {
                    a_to_b: ab.result(a),
                    b_to_a: ba.result(b),
                })
            }
            _ => Poll::Pending,
        }
    })
    .await
}

#[derive(Default)]
struct Counts {
    input_units: u64,
    input_bytes: u64,
    enqueued_items: u64,
    replacements: u64,
    mirror_misses: u64,
    wait_us: u64,
    bytes: u64,
    dg_bytes: u64,
    drops: SpliceDrops,
    converted: u64,
    capsules: u64,
    accepted_bytes: u64,
    payload_copy_bytes: u64,
    encode_bytes: u64,
    mirror_copy_bytes: u64,
}

type Completion = oneshot::Sender<SpliceDisposition>;

struct Group {
    kind: SpliceKind,
    sequence: u64,
    source_end: Option<u64>,
    admitted: Instant,
    items: VecDeque<Output>,
    readiness: Readiness,
    receipt: Option<Completion>,
    disposition: SpliceDisposition,
    options: Option<ResolvedDatagramOptions>,
    queued: bool,
    write_state: GroupWrite,
    waiting_since: Option<Instant>,
    grant: Option<Grant>,
    priced: Option<DatagramClass>,
    request: Option<Request>,
    hook: Option<PendingHook>,
    original_header: Option<crate::Chunk>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupWrite {
    Waiting,
    Released,
    FallbackFirstByte,
    FallbackWriting,
}

impl Group {
    fn roots(&self) -> impl Iterator<Item = Backing> + '_ {
        self.items
            .iter()
            .flat_map(Output::roots)
            .map(|chunk| chunk.backing)
            .chain(self.original_header.iter().map(|chunk| chunk.backing))
            .chain(self.hook.iter().flat_map(|hook| hook.roots.iter().copied()))
    }

    fn complete(mut self) {
        let receipt = self.receipt.take();
        let disposition = self.disposition;
        drop(self);
        if let Some(receipt) = receipt {
            let _ = receipt.send(disposition);
        }
    }

    fn settle(mut self, status: Status) {
        self.disposition.status = status;
        self.complete();
    }

    fn fallback(&self) -> bool {
        matches!(
            self.write_state,
            GroupWrite::FallbackFirstByte | GroupWrite::FallbackWriting
        )
    }

    fn capsule(&self) -> bool {
        self.fallback() || matches!(self.kind, SpliceKind::Capsule { .. })
    }

    fn deadline_active(&self) -> bool {
        matches!(
            self.write_state,
            GroupWrite::Waiting | GroupWrite::FallbackFirstByte
        )
    }
}

type HookSlot = Pin<Box<dyn Future<Output = OwnedSemaphorePermit> + Send>>;

struct PendingHook {
    roots: Vec<Backing>,
    task: Option<HookTask>,
}

enum HookTask {
    Input(Box<HookInput>, Option<HookSlot>),
    Running(JoinHandle<Verdict>),
}

impl PendingHook {
    fn new(input: HookInput) -> Self {
        Self {
            roots: input
                .payload
                .pieces
                .iter()
                .map(|chunk| chunk.backing)
                .collect(),
            task: Some(HookTask::Input(Box::new(input), None)),
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        slots: &Arc<Semaphore>,
        limits: ResolvedLimits,
        cap: usize,
    ) -> Poll<Verdict> {
        if let Some(HookTask::Input(_, slot)) = &mut self.task {
            let slot = slot.get_or_insert_with(|| {
                let slots = slots.clone();
                Box::pin(async move { slots.acquire_owned().await.expect("hook slots stay open") })
            });
            let Poll::Ready(slot) = slot.as_mut().poll(cx) else {
                return Poll::Pending;
            };
            let Some(HookTask::Input(input, _)) = self.task.take() else {
                unreachable!()
            };
            self.task = Some(HookTask::Running(tokio::task::spawn_blocking(move || {
                let verdict = input.run(limits, cap);
                drop(slot);
                verdict
            })));
        }
        let Some(HookTask::Running(task)) = &mut self.task else {
            unreachable!()
        };
        Pin::new(task)
            .poll(cx)
            .map(|outcome| outcome.unwrap_or(Err(HookFailure::End(SpliceEnd::HookFailed))))
    }
}

struct Output {
    payload_len: usize,
    pieces: VecDeque<crate::Chunk>,
    header: Option<crate::Chunk>,
    len: u64,
    left: u64,
}

impl Output {
    fn new(payload: Payload) -> Self {
        let len = payload.len as u64;
        Self {
            payload_len: payload.len,
            pieces: payload.pieces.into(),
            header: None,
            len,
            left: len,
        }
    }

    fn roots(&self) -> impl Iterator<Item = &crate::Chunk> {
        self.header.iter().chain(&self.pieces)
    }

    fn prepend(&mut self, header: crate::Chunk) {
        self.len += header.len() as u64;
        self.left = self.len;
        self.header = Some(header);
    }

    fn started(&self) -> bool {
        self.left < self.len
    }
}

struct Queue {
    groups: VecDeque<Group>,
}

impl Queue {
    fn new() -> Self {
        Self {
            groups: VecDeque::new(),
        }
    }

    fn push(&mut self, mut group: Group) {
        group.queued = true;
        self.groups.push_back(group);
    }

    fn take(&mut self, i: usize) -> Group {
        self.groups.remove(i).expect("index from queue")
    }
}

/// A reliable read result can span several chunks and capsules. The policy
/// applies through the end observed when the batch started.
#[derive(Default)]
struct ReadBatch {
    through: u64,
    generation: u64,
    hooks: HookChain,
}

struct Admission {
    sequence: u64,
    generation: u64,
    at: Instant,
    offset: Option<u64>,
    source_end: Option<u64>,
    injected: bool,
    receive_expiry: Option<Instant>,
}

impl Admission {
    fn disposition(&self, status: Status) -> SpliceDisposition {
        SpliceDisposition {
            status,
            sequence: self.sequence,
            generation: self.generation,
            accepted_bytes: 0,
            enqueued_items: 0,
        }
    }

    fn settle(&self, receipt: Option<Completion>, status: Status) {
        if let Some(receipt) = receipt {
            let _ = receipt.send(self.disposition(status));
        }
    }
}

struct Assembly {
    admission: Admission,
    hooks: HookChain,
    header: capsule::HeaderCursor,
    payload: Payload,
    compact: Option<Vec<u8>>,
    transparent: Option<TransparentCapsule>,
}

struct TransparentCapsule {
    remaining: usize,
    output: Output,
}

impl Assembly {
    fn new(admission: Admission, hooks: HookChain) -> Self {
        Self {
            admission,
            hooks,
            header: capsule::HeaderCursor::default(),
            payload: Payload::default(),
            compact: None,
            transparent: None,
        }
    }
    fn add_payload(
        &mut self,
        chunk: crate::Chunk,
        remaining: usize,
        limits: ResolvedLimits,
    ) -> Result<usize, SpliceBudget> {
        let ceiling = limits.group_backing_bytes;
        let mut roots = Roots::default();
        roots.extend(self.payload.pieces.iter().chain([&chunk]), ceiling)?;
        let copied = if let Some(compact) = &mut self.compact {
            roots.reserve(compact.capacity(), ceiling)?;
            compact.extend_from_slice(&chunk);
            chunk.len()
        } else if self.payload.pieces.len() == limits.descriptors {
            let size = self
                .payload
                .len
                .checked_add(remaining)
                .ok_or(SpliceBudget)?;
            roots.reserve(size, ceiling)?;
            let mut compact = Vec::with_capacity(size);
            roots.reserve(compact.capacity() - size, ceiling)?;
            for piece in self.payload.pieces.drain(..) {
                compact.extend_from_slice(&piece);
            }
            compact.extend_from_slice(&chunk);
            self.payload.receive_view = false;
            self.compact = Some(compact);
            self.payload.len + chunk.len()
        } else {
            self.payload.receive_view = true;
            self.payload.pieces.push(chunk);
            let end = self.payload.pieces.last().expect("new piece");
            self.payload.len += end.len();
            return Ok(0);
        };
        self.payload.len = self.compact.as_ref().expect("compacting").len();
        Ok(copied)
    }

    fn finish_header(&self, limits: ResolvedLimits) -> Result<crate::Chunk, SpliceBudget> {
        let mut roots = Roots::default();
        roots.extend(&self.payload.pieces, limits.group_backing_bytes)?;
        if let Some(compact) = &self.compact {
            roots.reserve(compact.capacity(), limits.group_backing_bytes)?;
        }
        let header = self.header.bytes();
        roots.reserve(header.len(), limits.group_backing_bytes)?;
        Ok(crate::Chunk::copy_from_slice(header))
    }
}

struct HeaderBytes {
    bytes: [u8; capsule::MAX_WIRE_HEADER],
    len: usize,
}

fn encoded_header(kind: SpliceKind, payload: usize) -> HeaderBytes {
    let (ty, context) = match kind {
        SpliceKind::Capsule { ty, context } => (ty.into_inner(), context),
        SpliceKind::Datagram { context } => (capsule::DATAGRAM, Some(context)),
        SpliceKind::Stream => unreachable!("only capsules have headers"),
    };
    let mut bytes = [0; capsule::MAX_WIRE_HEADER];
    let len = capsule::encode_header(ty, context.map(VarInt::into_inner), payload, &mut bytes);
    HeaderBytes { bytes, len }
}

fn encode_group(
    items: &mut VecDeque<Output>,
    kind: SpliceKind,
    original: Option<crate::Chunk>,
    limits: ResolvedLimits,
) -> Result<usize, SpliceBudget> {
    let mut roots = Roots::default();
    roots.extend(
        items.iter().flat_map(Output::roots).chain(original.iter()),
        limits.group_backing_bytes,
    )?;
    let (_, encoded) = capsule_cost(items, kind, original.as_ref(), &mut roots, limits)?;
    let mut original = original;
    for item in items {
        item.prepend(original.take().unwrap_or_else(|| {
            let header = encoded_header(kind, item.payload_len);
            crate::Chunk::copy_from_slice(&header.bytes[..header.len])
        }));
    }
    Ok(encoded)
}

fn capsule_cost(
    items: &VecDeque<Output>,
    kind: SpliceKind,
    original: Option<&crate::Chunk>,
    roots: &mut Roots,
    limits: ResolvedLimits,
) -> Result<(usize, usize), SpliceBudget> {
    let mut logical = 0usize;
    let mut encoded = 0usize;
    // Preflight the whole group while only stack header buffers exist.
    for (index, item) in items.iter().enumerate() {
        let header = original.filter(|_| index == 0);
        let len = if let Some(header) = header {
            header.len()
        } else {
            let len = encoded_header(kind, item.payload_len).len;
            roots.reserve(len, limits.group_backing_bytes)?;
            encoded += len;
            len
        };
        logical = logical
            .checked_add(item.payload_len)
            .and_then(|n| n.checked_add(len))
            .filter(|&n| n <= limits.group_bytes)
            .ok_or(SpliceBudget)?;
    }
    Ok((logical, encoded))
}

#[derive(Clone, Copy)]
enum Source {
    Open,
    Final,
    Drained,
    Reset {
        code: VarInt,
        size: u64,
        discard_tail: bool,
    },
}

impl Source {
    fn reset(self) -> Option<(VarInt, u64)> {
        match self {
            Self::Reset { code, size, .. } => Some((code, size)),
            _ => None,
        }
    }

    fn open(self) -> bool {
        matches!(self, Self::Open)
    }

    fn drained(self) -> bool {
        matches!(self, Self::Drained)
    }
}

struct Direct {
    data: crate::Chunk,
    offset: u64,
}

enum Write {
    Progress(usize),
    Expired,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DatagramClass {
    Datagram,
    Capsules,
}

struct PendingReset {
    reason: SpliceEnd,
    code: VarInt,
    through: Option<u64>,
}

struct Relay<'a> {
    r: &'a RecvStream,
    w: &'a SendStream,
    r_wait: WaitSlot<'a, Tokio>,
    w_wait: WaitSlot<'a, Tokio>,
    requests: Option<Requests>,
    handoffs: Option<SpliceHandoffs>,
    abort: Option<&'a SpliceAbort>,
    bounds: UnitBounds,
    packets: bool,
    limits: ResolvedLimits,
    route: SpliceRoute,
    label: Option<Arc<str>>,
    reliable_hooks: Option<Arc<Semaphore>>,
    datagram_hooks: Option<Arc<Semaphore>>,
    mirror: Option<MirrorPublisher>,
    events: Option<&'a SpliceEventSink>,
    hooks: HookChain,
    commands: Option<Inbox>,
    read_batch: ReadBatch,
    sequence: u64,
    pause_generation: u64,
    paused: bool,
    pause_ack: Option<watch::Sender<Option<Result<(), CommandError>>>>,
    pause_lease: Option<oneshot::Receiver<()>>,
    reliable: Queue,
    datagrams: Queue,
    active: Option<Group>,
    direct: Option<Direct>,
    permit: Option<Grant>,
    reliable_request: Option<ReliableRequest>,
    assembly: Option<Assembly>,
    dg_wait: Option<WaitSlot<'a, Tokio>>,
    dg_options: DatagramSendOptions,
    source_offset: u64,
    output_start: u64,
    complete_output: u64,
    source: Source,
    /// If the source reports a reset again after the reliable read is exhausted,
    /// its announced size is still the original value.
    read_exhausted: bool,
    flush: Option<PendingReset>,
    end: Option<SpliceEnd>,
    cause: Option<SpliceBudget>,
    counts: Counts,
    clock: crate::ClockDomain,
    timer: Option<(Instant, crate::proto::session::ClockWait)>,
}

impl Drop for Relay<'_> {
    fn drop(&mut self) {
        if let Some(end) = self.end {
            self.discard_datagrams(end);
        } else {
            let _ = self.r.stop_shared(VarInt::ZERO);
            let _ = self
                .w
                .reset_shared(code(ApplicationErrorCode::ZMUX_CANCELLED));
            self.finish(SpliceEnd::Cancelled(VarInt::ZERO));
        }
    }
}

impl<'a> Relay<'a> {
    fn new(
        r: &'a RecvStream,
        w: &'a SendStream,
        opts: &Run<'a>,
        route: SpliceRoute,
        mut commands: Option<Inbox>,
    ) -> Self {
        let forwarding = opts.forwarding;
        let (limiter, dg_options) = match route {
            SpliceRoute::AtoB => (&forwarding.a_to_b, forwarding.a_to_b_datagrams),
            SpliceRoute::BtoA => (&forwarding.b_to_a, forwarding.b_to_a_datagrams),
        };
        let (hooks, label, mirror) = match (route, opts.policy) {
            (SpliceRoute::AtoB, Some(policy)) => (
                policy.a_to_b_hooks.clone().into(),
                Some(policy.a_to_b_label.clone()),
                policy.a_to_b_mirror.as_ref(),
            ),
            (SpliceRoute::BtoA, Some(policy)) => (
                policy.b_to_a_hooks.clone().into(),
                Some(policy.b_to_a_label.clone()),
                policy.b_to_a_mirror.as_ref(),
            ),
            (_, None) => (HookChain::default(), None, None),
        };
        let output_start = w.meter().bytes_written();
        if let Some(inbox) = &mut commands {
            *inbox.generation.get_mut() = u64::from(!hooks.empty());
        }
        Self {
            r,
            w,
            r_wait: r.wait_slot(),
            w_wait: w.wait_slot(),
            requests: limiter.as_ref().map(|limiter| {
                Requests::new(
                    limiter.clone(),
                    commands
                        .as_ref()
                        .map_or_else(Arc::default, |inbox| inbox.pre_admission_refunds.clone()),
                    opts.limits.reliable_cleanup_slots,
                    opts.limits.datagram_cleanup_slots,
                )
            }),
            abort: opts.abort,
            handoffs: commands
                .as_ref()
                .map(|inbox| inbox.handoffs.clone())
                .or_else(|| limiter.as_ref().map(|_| SpliceHandoffs::default())),
            bounds: forwarding.into(),
            packets: opts.packets,
            limits: opts.limits,
            route,
            label,
            reliable_hooks: None,
            datagram_hooks: None,
            mirror: mirror.map(SpliceMirror::attach),
            events: opts.policy.and_then(|policy| policy.events.as_ref()),
            read_batch: ReadBatch::default(),
            hooks,
            commands,
            sequence: 0,
            pause_generation: 0,
            paused: false,
            pause_ack: None,
            pause_lease: None,
            reliable: Queue::new(),
            datagrams: Queue::new(),
            active: None,
            direct: None,
            permit: None,
            reliable_request: None,
            assembly: None,
            dg_wait: Some(r.splice_datagram_slot()),
            dg_options,
            source_offset: r.meter().bytes_read(),
            output_start,
            complete_output: output_start,
            source: Source::Open,
            read_exhausted: false,
            flush: None,
            end: None,
            cause: None,
            counts: Counts::default(),
            clock: w.packet_clock(),
            timer: None,
        }
    }

    fn result(&self, end: SpliceEnd) -> SpliceDirection {
        let n = &self.counts;
        SpliceDirection {
            bytes: n.bytes,
            datagram_bytes: n.dg_bytes,
            datagrams_as_capsules: n.converted,
            input_units: n.input_units,
            input_bytes: n.input_bytes,
            enqueued_items: n.enqueued_items,
            replacements: n.replacements,
            drops: n.drops,
            mirror_misses: n.mirror_misses,
            wait_us: n.wait_us,
            capsule_count: n.capsules,
            accepted_bytes: n.accepted_bytes,
            handoffs: self.handoffs.clone(),
            end,
            cause: self.cause,
            payload_copy_bytes: n.payload_copy_bytes,
            encode_bytes: n.encode_bytes,
            mirror_copy_bytes: n.mirror_copy_bytes,
            pre_admission_refunded_bytes: self.requests.as_ref().map_or(0, Requests::refunded),
        }
    }

    fn fail(&mut self, end: SpliceEnd, error: VarInt) {
        if self.end.is_none() {
            let _ = self.r.stop_shared(error);
            let _ = self.w.reset_shared(error);
            self.finish(end);
        }
    }

    fn finish(&mut self, end: SpliceEnd) {
        self.end = Some(end);
        self.flush = None;
        self.clear_writer();
        self.assembly = None;
        self.direct = None;
        self.acknowledge_pause(Err(CommandError::Closed));
        self.pause_lease = None;
        let reliable = std::mem::replace(&mut self.reliable, Queue::new());
        for group in self.active.take().into_iter().chain(reliable.groups) {
            self.end_group(group, end);
        }
        if end != SpliceEnd::Finished {
            self.discard_datagrams(end);
        }
        self.event(SpliceEvent::DirectionFinished { end });
        if let Some(inbox) = self.commands.take() {
            inbox.finish(end);
        }
    }

    fn event(&self, event: SpliceEvent) {
        if let Some(sink) = self.events {
            sink.emit(self.route, event);
        }
    }

    fn discard_datagrams(&mut self, end: SpliceEnd) {
        self.dg_wait = None;
        while !self.datagrams.groups.is_empty() {
            let group = self.datagrams.take(0);
            self.end_group(group, end);
        }
    }

    fn finish_wait(&mut self, group: &mut Group, now: Instant) {
        if let Some(start) = group.waiting_since.take() {
            let elapsed = now.saturating_duration_since(start).as_micros();
            let micros = u64::try_from(elapsed).unwrap_or(u64::MAX);
            self.counts.wait_us = self.counts.wait_us.saturating_add(micros);
        }
    }

    fn end_group(&mut self, mut group: Group, end: SpliceEnd) {
        self.finish_wait(&mut group, self.now());
        if matches!(group.kind, SpliceKind::Datagram { .. })
            && group.write_state != GroupWrite::FallbackWriting
        {
            self.counts.drops.count(DropReason::FlowClosed);
        }
        group.settle(Status::DirectionEnded(end));
    }

    fn drop_datagram(&mut self, mut group: Group, reason: DropReason) {
        self.finish_wait(&mut group, self.now());
        self.counts.drops.count(reason);
        group.settle(Status::Dropped(reason));
        #[cfg(feature = "test-hooks")]
        if let Some(inbox) = &self.commands {
            let counter = match reason {
                DropReason::QueueFull => Some(&inbox.fixture.queue_full),
                DropReason::Limiter => Some(&inbox.fixture.refused),
                _ => None,
            };
            if let Some(counter) = counter {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn acknowledge_pause(&mut self, answer: Result<(), CommandError>) {
        if let Some(ack) = self.pause_ack.take() {
            if answer.is_ok() {
                self.event(SpliceEvent::PauseAcknowledged {
                    token: self.pause_generation,
                });
            }
            ack.send_replace(Some(answer));
        }
    }

    fn local_failure(&mut self, end: SpliceEnd) {
        let error = match end {
            SpliceEnd::HookReset(code) => code,
            _ => code(ApplicationErrorCode::ZMUX_CANCELLED),
        };
        self.fail(end, error);
    }

    fn hook_failure(&mut self, failure: HookFailure) -> SpliceEnd {
        if let Some(end) = self.end {
            return end;
        }
        let end = match failure {
            HookFailure::End(end) => end,
            HookFailure::Budget => {
                self.cause = Some(SpliceBudget);
                SpliceEnd::HookFailed
            }
        };
        self.local_failure(end);
        end
    }

    fn clear_writer(&mut self) {
        self.reliable_request = None;
        self.permit = None;
    }

    fn packet_error(&mut self) {
        let error = code(ApplicationErrorCode::ZMUX_PACKET_ERROR);
        self.clear_writer();
        self.reset_after_prefix(SpliceEnd::PacketError, error, Some(self.complete_output));
    }

    fn source_failed(&mut self, error: &StreamError) {
        let (reason, error) = super::upstream_end(error);
        let _ = self.w.reset_shared(error);
        self.finish(reason);
    }

    fn target_failed(&mut self, error: &StreamError) {
        let (reason, error) = super::downstream_end(error);
        let _ = self.r.stop_shared(error);
        self.finish(reason);
    }

    fn expired(group: &Group, now: Instant) -> bool {
        group.readiness.expires_at.is_some_and(|t| now >= t)
    }

    fn poll(&mut self, cx: &mut Context<'_>) {
        for _ in 0..POLL_STEPS {
            let now = self.now();
            if !self.step(cx, now) {
                self.timer(cx, now);
                return;
            }
        }
        cx.waker().wake_by_ref();
    }

    fn step(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        if self.end.is_some() {
            return self.datagram_step(cx, now);
        }
        let mut readable = self.observe(cx);
        if self.end.is_some() {
            return true;
        }
        if let Some(reset) = self.flush.take() {
            return match self
                .w
                .poll_sent(cx.waker(), &mut self.w_wait.ticket, reset.through)
            {
                Poll::Ready(Ok(())) => {
                    self.reset_target(reset.reason, reset.code);
                    true
                }
                Poll::Ready(Err(e)) => {
                    self.target_failed(&e);
                    true
                }
                Poll::Pending => {
                    self.flush = Some(reset);
                    false
                }
            };
        }
        let released = self
            .pause_lease
            .as_mut()
            .is_some_and(|lease| Pin::new(lease).poll(cx).is_ready());
        if released {
            self.resume_pause();
        }
        let commanded = self.command(cx, now);
        if commanded && !self.paused {
            readable = self.observe(cx);
        }
        let now = self.now();
        let mut ready = commanded | released;
        let started_capsule = self
            .active
            .as_ref()
            .is_some_and(|g| g.capsule() && g.items.front().is_some_and(Output::started))
            || self
                .assembly
                .as_ref()
                .and_then(|a| a.transparent.as_ref())
                .is_some_and(|t| t.output.started());
        if self.paused && !started_capsule {
            self.clear_writer();
            self.acknowledge_pause(Ok(()));
        }
        if self.end.is_some() {
            return true;
        }
        if let Some(index) = self
            .reliable
            .groups
            .iter()
            .position(|group| group.fallback() && Self::expired(group, now))
        {
            let group = self.reliable.take(index);
            self.drop_datagram(group, DropReason::Expired);
            ready = true;
        }
        ready |= self.datagram_step(cx, now);
        if self.end.is_some() {
            return true;
        }
        ready | self.reliable_step(cx, now, readable, started_capsule)
    }

    fn observe(&mut self, cx: &mut Context<'_>) -> Option<usize> {
        if let Some(code) = self.abort.and_then(SpliceAbort::code) {
            self.fail(SpliceEnd::Cancelled(code), code);
            return None;
        }
        if let Err(error) = self.w.watch(cx.waker(), &mut self.w_wait.ticket) {
            self.target_failed(&error);
            return None;
        }
        self.observe_source(cx)
    }

    fn observe_source(&mut self, cx: &mut Context<'_>) -> Option<usize> {
        if self.source.drained() {
            return Some(0);
        }
        let mut source = self.r.poll_upstream(cx.waker(), &mut self.r_wait.ticket);
        if self.source.open()
            && (self.commands.is_some() || self.packets)
            && matches!(
                source,
                Poll::Pending | Poll::Ready(Ok(Upstream::Readable(1..)))
            )
        {
            let mut end = std::pin::pin!(self.r.received_reset_op());
            match end.as_mut().poll(cx) {
                Poll::Ready(Ok(None)) => self.source = Source::Final,
                Poll::Ready(Ok(Some(_))) => {
                    // A reset arrived after the readable check. Obtain its
                    // cutoff before accepting a command or submitting output.
                    source = self.r.poll_upstream(cx.waker(), &mut self.r_wait.ticket);
                }
                Poll::Ready(Err(error)) => source = Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        match source {
            Poll::Ready(Ok(Upstream::Readable(n))) => {
                if n == 0 {
                    self.source = Source::Drained;
                }
                Some(n)
            }
            Poll::Ready(Ok(Upstream::Reset(code, size))) => {
                let size = if self.read_exhausted {
                    size.min(self.source_offset)
                } else {
                    size
                };
                self.observe_reset(code, size);
                Some(crate::util::usize_sat(
                    size.saturating_sub(self.source_offset),
                ))
            }
            Poll::Ready(Err(e)) => {
                self.source_failed(&e);
                None
            }
            Poll::Pending => None,
        }
    }

    fn observe_reset(&mut self, code: VarInt, size: u64) {
        if self.source.reset() == Some((code, size)) {
            return;
        }
        let discard_tail = self.read_exhausted
            || matches!(
                self.source,
                Source::Reset {
                    discard_tail: true,
                    ..
                }
            );
        self.source = Source::Reset {
            code,
            size,
            discard_tail,
        };
        while !self.reliable.groups.is_empty() {
            let group = self.reliable.take(0);
            self.end_group(group, SpliceEnd::Reset(code));
        }
        self.cut_active(code, size);
    }

    fn cut_active(&mut self, code: VarInt, size: u64) {
        let Some(mut group) = self.active.take() else {
            return;
        };
        let end = SpliceEnd::Reset(code);
        if group.source_end.is_some_and(|end| end <= size) {
            self.active = Some(group);
        } else if group.source_end.is_none()
            && group.capsule()
            && group.items.front().is_some_and(Output::started)
        {
            group.items.truncate(1);
            group.disposition.status = Status::DirectionEnded(end);
            self.active = Some(group);
        } else {
            self.end_group(group, end);
            self.clear_writer();
        }
    }

    fn resume_pause(&mut self) {
        self.paused = false;
        self.pause_lease = None;
        self.acknowledge_pause(Err(CommandError::StalePause));
    }

    fn command(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        let Some(inbox) = &mut self.commands else {
            return false;
        };
        let Poll::Ready(Some(cmd)) = inbox.commands.poll_recv(cx) else {
            return false;
        };
        match cmd {
            Command::Replace(hooks, reply) => {
                if !reply.is_closed() {
                    let generation = inbox.generation.get_mut();
                    *generation += 1;
                    let generation = *generation;
                    self.hooks = hooks;
                    self.event(SpliceEvent::HooksReplaced { generation });
                    let _ = reply.send(Ok(generation));
                }
            }
            Command::Pause(owner, reply) => {
                let generation = self.pause_generation + 1;
                let (ack, ready) = watch::channel(None);
                let (hold, lease) = oneshot::channel();
                if reply
                    .send(Ok(SpliceControl::pause_token(
                        generation, owner, ready, hold,
                    )))
                    .is_ok()
                {
                    self.acknowledge_pause(Err(CommandError::StalePause));
                    self.pause_generation = generation;
                    self.paused = true;
                    if let Some(slot) = &mut self.dg_wait {
                        *slot = self.r.splice_datagram_slot();
                    }
                    self.pause_ack = Some(ack);
                    self.pause_lease = Some(lease);
                }
            }
            Command::Resume(generation, reply) => {
                if generation == self.pause_generation {
                    if reply.send(Ok(())).is_ok() {
                        self.resume_pause();
                    }
                } else {
                    let _ = reply.send(Err(CommandError::StalePause));
                }
            }
            Command::Inject(injection, _budget, reply) => self.inject(injection, reply, now),
        }
        true
    }

    fn sequence(
        &mut self,
        now: Instant,
        offset: Option<u64>,
        injected: bool,
        generation: Option<u64>,
    ) -> Admission {
        self.sequence += 1;
        let generation = generation.unwrap_or_else(|| {
            self.commands
                .as_mut()
                .map_or(0, |inbox| *inbox.generation.get_mut())
        });
        Admission {
            sequence: self.sequence,
            generation,
            at: now,
            offset,
            source_end: None,
            injected,
            receive_expiry: None,
        }
    }

    fn inject(
        &mut self,
        injection: SpliceInjection,
        reply: oneshot::Sender<Result<SpliceReceipt, CommandError>>,
        now: Instant,
    ) {
        if reply.is_closed() {
            return;
        }
        let error = if !self.source.open() {
            Some(CommandError::Closed)
        } else if self.paused {
            Some(CommandError::Paused)
        } else {
            (!self.queue_fits(1, [injection.payload.backing])
                || injection.payload.backing_capacity() > self.limits.group_backing_bytes)
                .then_some(CommandError::SpliceBudget)
        };
        if let Some(error) = error {
            let _ = reply.send(Err(error));
            return;
        }
        let admission = self.sequence(now, None, true, None);
        let (done, rx) = oneshot::channel();
        if reply
            .send(Ok(SpliceReceipt {
                sequence: admission.sequence,
                generation: admission.generation,
                done: rx,
            }))
            .is_err()
        {
            return;
        }
        let group = self.group(
            &admission,
            injection.kind,
            Payload::single(injection.payload),
            None,
            None,
            Some(done),
        );
        if let Some(group) = group {
            if group.hook.is_some() || !group.items.is_empty() {
                self.enqueue(group);
            } else {
                group.complete();
            }
        }
    }

    fn queue_fits(&self, items: usize, chunks: impl IntoIterator<Item = Backing>) -> bool {
        let groups = self
            .reliable
            .groups
            .iter()
            .chain(&self.datagrams.groups)
            .chain(self.active.iter().filter(|group| group.queued));
        let remaining = groups
            .clone()
            .try_fold(self.limits.queue_items, |room, group| {
                room.checked_sub(group.items.len().max(1))
            });
        if remaining.is_none_or(|room| items > room) {
            return false;
        }
        let mut roots = Roots::default();
        groups
            .flat_map(Group::roots)
            .chain(chunks)
            .try_for_each(|root| roots.add_backing(root, self.limits.queue_bytes))
            .is_ok()
    }

    fn enqueue(&mut self, group: Group) {
        let datagram = matches!(group.kind, SpliceKind::Datagram { .. });
        if !self.queue_fits(group.items.len().max(1), group.roots()) {
            if datagram {
                self.drop_datagram(group, DropReason::QueueFull);
            } else {
                let end = self.hook_failure(HookFailure::Budget);
                self.end_group(group, end);
            }
        } else if datagram && !group.fallback() {
            self.datagrams.push(group);
        } else {
            self.reliable.push(group);
        }
    }

    fn group(
        &mut self,
        admission: &Admission,
        kind: SpliceKind,
        payload: Payload,
        header: Option<crate::Chunk>,
        hooks: Option<&HookChain>,
        receipt: Option<Completion>,
    ) -> Option<Group> {
        let is_datagram = matches!(kind, SpliceKind::Datagram { .. });
        let options = if is_datagram {
            let Ok(mut options) = self
                .w
                .resolve_splice_datagram_options(self.dg_options, admission.at.into_std())
            else {
                self.counts.drops.count(DropReason::Blocked);
                admission.settle(receipt, Status::Dropped(DropReason::Blocked));
                return None;
            };
            if let Some(expires) = admission.receive_expiry.map(Instant::into_std) {
                options.deadline = Some(options.deadline.map_or(expires, |at| at.min(expires)));
            }
            Some(options)
        } else {
            None
        };
        let chain = hooks.unwrap_or(&self.hooks).get(kind).cloned();
        self.counts.input_units += 1;
        self.counts.input_bytes += payload.len as u64;
        let mut group = Group {
            kind,
            sequence: admission.sequence,
            source_end: admission.source_end,
            admitted: admission.at,
            items: VecDeque::new(),
            readiness: Readiness::default(),
            receipt,
            disposition: admission.disposition(Status::Submitted),
            options,
            queued: false,
            write_state: GroupWrite::Waiting,
            waiting_since: None,
            grant: None,
            priced: None,
            request: None,
            hook: None,
            original_header: header,
        };
        if let Some(deadline) = options.and_then(|options| options.deadline) {
            group.readiness.expire_by(deadline.into());
        }
        if let Some(mirror) = &self.mirror {
            let preamble = self.r.preamble();
            let meta = SpliceMeta {
                route: self.route,
                kind,
                sequence: admission.sequence,
                generation: admission.generation,
                source_offset: admission.offset,
                injected: admission.injected,
                source_stream: self.r.id(),
                target_stream: self.w.id(),
                replayable: self.r.is_replayable(),
                preamble: &preamble,
                label: self.label.as_deref().unwrap_or(""),
            };
            if let Some(copied) = mirror.publish(&meta, &payload) {
                self.counts.mirror_copy_bytes += copied as u64;
            } else {
                self.counts.mirror_misses += 1;
            }
        }
        if let Some(chain) = chain {
            group.hook = Some(PendingHook::new(HookInput {
                chain,
                route: self.route,
                kind,
                sequence: admission.sequence,
                generation: admission.generation,
                source_offset: admission.offset,
                injected: admission.injected,
                source_stream: self.r.id(),
                target_stream: self.w.id(),
                replayable: self.r.is_replayable(),
                preamble: self.r.preamble(),
                label: self.label.clone(),
                payload,
                header: group.original_header.as_ref().map(|chunk| chunk.backing),
            }));
        } else {
            self.apply_verdict(&mut group, Ok((vec![payload], Readiness::default(), 0)));
        }
        Some(group)
    }

    fn poll_hook(&mut self, cx: &mut Context<'_>, group: &mut Group) -> Poll<()> {
        let Some(hook) = &mut group.hook else {
            return Poll::Ready(());
        };
        let slots = if matches!(group.kind, SpliceKind::Datagram { .. }) {
            &mut self.datagram_hooks
        } else {
            &mut self.reliable_hooks
        };
        let slots = slots.get_or_insert_with(|| Arc::new(Semaphore::new(1)));
        let Poll::Ready(verdict) = hook.poll(cx, slots, self.limits, self.bounds.cap(group.kind))
        else {
            return Poll::Pending;
        };
        group.hook = None;
        if self.end.is_none() {
            self.observe(cx);
        }
        if let Some(end) = self.end.filter(|end| *end != SpliceEnd::Finished) {
            group.disposition.status = Status::DirectionEnded(end);
        } else if let Some((code, through)) = self.source.reset()
            && !matches!(group.kind, SpliceKind::Datagram { .. })
            && group.source_end.is_none_or(|end| end > through)
        {
            group.disposition.status = Status::DirectionEnded(SpliceEnd::Reset(code));
        } else if matches!(group.kind, SpliceKind::Datagram { .. })
            && Self::expired(group, self.now())
        {
            self.counts.drops.count(DropReason::Expired);
            group.disposition.status = Status::Dropped(DropReason::Expired);
        } else {
            self.apply_verdict(group, verdict);
        }
        Poll::Ready(())
    }

    fn apply_verdict(&mut self, group: &mut Group, verdict: Verdict) {
        let (payloads, mut readiness, replacements) = match verdict {
            Ok(result) => result,
            Err(failure) => {
                let end = self.hook_failure(failure);
                group.disposition.status = Status::DirectionEnded(end);
                return;
            }
        };
        self.counts.replacements += replacements;
        if payloads.is_empty() {
            if matches!(group.kind, SpliceKind::Datagram { .. }) {
                self.counts.drops.count(DropReason::Hook);
            }
            group.disposition.status = Status::Dropped(DropReason::Hook);
            return;
        }
        group.waiting_since = readiness.has_wait().then(|| self.now());
        for deadline in [
            group.readiness.expires_at,
            group
                .waiting_since
                .and_then(|_| self.wait_deadline(group.admitted)),
        ]
        .into_iter()
        .flatten()
        {
            readiness.expire_by(deadline);
        }
        group.readiness = readiness;
        let mut items = payloads
            .into_iter()
            .filter(|p| p.len > 0 || !matches!(group.kind, SpliceKind::Stream))
            .map(Output::new)
            .collect::<VecDeque<_>>();
        let mut roots = Roots::default();
        let fits = roots.extend(
            items.iter().flat_map(Output::roots),
            self.limits.group_backing_bytes,
        );
        let encoded = fits.and_then(|()| {
            if matches!(group.kind, SpliceKind::Capsule { .. }) {
                let original = group.original_header.take().filter(|_| replacements == 0);
                encode_group(&mut items, group.kind, original, self.limits)
            } else {
                Ok(0)
            }
        });
        if let Ok(bytes) = encoded {
            self.counts.encode_bytes += bytes as u64;
            group.items = items;
        } else {
            let end = self.hook_failure(HookFailure::Budget);
            group.disposition.status = Status::DirectionEnded(end);
        }
    }

    fn datagram_step(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        if self.dg_wait.is_none() && self.datagrams.groups.is_empty() {
            return false;
        }
        if let Some(i) = self
            .datagrams
            .groups
            .iter()
            .position(|g| Self::expired(g, now))
        {
            let group = self.datagrams.take(i);
            self.drop_datagram(group, DropReason::Expired);
            return true;
        }
        if self.paused && self.end.is_none() {
            return false;
        }
        let pending_hook = self
            .datagrams
            .groups
            .iter()
            .position(|group| group.hook.is_some());
        if let Some(index) = pending_hook {
            let mut group = self.datagrams.take(index);
            if self.poll_hook(cx, &mut group).is_pending() {
                self.datagrams.groups.insert(index, group);
            } else {
                if group.items.is_empty() {
                    group.complete();
                } else if !self.queue_fits(group.items.len(), group.roots()) {
                    self.drop_datagram(group, DropReason::QueueFull);
                } else if !self.limits.datagram_delay && !group.readiness.ready(cx, now) {
                    self.drop_datagram(group, DropReason::Blocked);
                } else {
                    self.datagrams.groups.insert(index, group);
                }
                return true;
            }
        }
        let next = self
            .datagrams
            .groups
            .iter_mut()
            .enumerate()
            .filter_map(|(i, group)| {
                if group.hook.is_some() {
                    return None;
                }
                if let Some(request) = &mut group.request {
                    let Poll::Ready(grant) = request.poll(cx) else {
                        return None;
                    };
                    group.request = None;
                    group.grant = grant;
                }
                group.readiness.ready(cx, now).then_some((
                    (
                        group.readiness.ready_at.unwrap_or(group.admitted),
                        group.sequence,
                    ),
                    i,
                ))
            })
            .min()
            .map(|(_, i)| i);
        if let Some(i) = next {
            let group = self.datagrams.take(i);
            self.submit_datagrams(cx, group);
            return true;
        }
        // One input may be evaluated while the delayed queue is full. The
        // verdict and its children determine whether it needs a queue slot.
        pending_hook.is_none() && self.read_datagram(cx)
    }

    fn read_datagram(&mut self, cx: &mut Context<'_>) -> bool {
        if self.dg_wait.is_none() {
            return false;
        }
        let group_limit = self.limits.group_backing_bytes;
        let queue_limit = self.limits.queue_bytes;
        let backings = self.queue_roots();
        let fits_root = |root: Backing| {
            root.size <= group_limit
                && backings
                    .as_ref()
                    .is_some_and(|roots| roots.fits(root, queue_limit))
        };
        let fits_copy = |size: usize| {
            size <= group_limit
                && backings
                    .as_ref()
                    .is_some_and(|roots| size <= roots.remaining(queue_limit))
        };
        let (context, data, remaining, copied) = match self.r.poll_splice_datagram(
            cx,
            self.dg_wait.as_mut().expect("live datagram reader"),
            self.bounds.packet,
            fits_root,
            fits_copy,
        ) {
            Poll::Pending | Poll::Ready(Err(StreamError::BorrowLimit)) => return false,
            Poll::Ready(Err(_)) => {
                self.dg_wait = None;
                return false;
            }
            Poll::Ready(Ok(SpliceDatagram::TooLarge)) => {
                if let Some(inbox) = &self.commands {
                    inbox.start_source_batch();
                }
                self.counts.drops.count(DropReason::TooLarge);
                return true;
            }
            Poll::Ready(Ok(SpliceDatagram::Data {
                context,
                data,
                remaining,
                copied,
            })) => (context, data, remaining, copied),
        };
        let context = VarInt::from_u64(context).expect("decoded datagram context");
        let now = self.now();
        let generation = self.commands.as_ref().map(Inbox::start_source_batch);
        let mut admission = self.sequence(now, None, false, generation);
        admission.receive_expiry = remaining.and_then(|remaining| now.checked_add(remaining));
        let payload = if copied {
            self.counts.payload_copy_bytes += data.len() as u64;
            Payload::single(data)
        } else {
            Payload::leased(data)
        };
        if let Some(mut group) = self.group(
            &admission,
            SpliceKind::Datagram { context },
            payload,
            None,
            None,
            None,
        ) {
            if group.hook.is_some() {
                self.datagrams.push(group);
            } else if group.items.is_empty() {
                group.complete();
            } else if Self::expired(&group, now) {
                self.drop_datagram(group, DropReason::Expired);
            } else if group.readiness.ready(cx, now) {
                self.submit_datagrams(cx, group);
            } else if self.limits.datagram_delay {
                self.enqueue(group);
            } else {
                self.drop_datagram(group, DropReason::Blocked);
            }
        }
        true
    }

    fn queue_roots(&self) -> Option<Roots> {
        let mut roots = Roots::default();
        self.reliable
            .groups
            .iter()
            .chain(&self.datagrams.groups)
            .chain(self.active.iter().filter(|group| group.queued))
            .flat_map(Group::roots)
            .try_for_each(|root| roots.add_backing(root, self.limits.queue_bytes))
            .ok()?;
        Some(roots)
    }

    fn datagram_policy(&self) -> SendPolicy {
        if self.packets && self.source.open() && self.end.is_none() {
            SendPolicy::PreferDatagram
        } else {
            SendPolicy::DatagramOnly
        }
    }

    fn datagram_class(
        &self,
        group: &Group,
        sizes: &[usize],
    ) -> Result<DatagramClass, DatagramError> {
        let SpliceKind::Datagram { context } = group.kind else {
            unreachable!("datagram queue")
        };
        let options = group.options.expect("resolved datagram options");
        self.w
            .datagram_group(context.into_inner(), sizes, options, self.datagram_policy())
            .map(|class| match class {
                PacketRepresentation::Capsule => DatagramClass::Capsules,
                PacketRepresentation::Datagram { .. } => DatagramClass::Datagram,
            })
    }

    fn submit_datagrams(&mut self, cx: &mut Context<'_>, mut group: Group) {
        let SpliceKind::Datagram { context } = group.kind else {
            unreachable!("datagram queue")
        };
        if self.end.is_none() {
            self.observe(cx);
            if let Some(end) = self.end {
                self.end_group(group, end);
                return;
            }
        }
        if Self::expired(&group, self.now()) {
            self.drop_datagram(group, DropReason::Expired);
            return;
        }
        self.finish_wait(&mut group, self.now());
        group.readiness.expires_at = group
            .options
            .and_then(|options| options.deadline)
            .map(Into::into);
        let sizes: Vec<_> = group.items.iter().map(|out| out.payload_len).collect();
        let class = match self.datagram_class(&group, &sizes) {
            Ok(class) => class,
            Err(error) => {
                self.drop_datagram(group, DropReason::from_datagram(&error));
                return;
            }
        };
        if group.priced != Some(class) {
            // A new representation discards the entire old authorization.
            group.grant = None;
            group.priced = None;
        } else if self.requests.is_some() && group.grant.is_none() {
            self.drop_datagram(group, DropReason::Limiter);
            return;
        }
        let cost = if class == DatagramClass::Capsules {
            let mut roots = Roots::default();
            let planned = roots
                .extend(
                    group.items.iter().flat_map(Output::roots),
                    self.limits.group_backing_bytes,
                )
                .and_then(|()| {
                    capsule_cost(&group.items, group.kind, None, &mut roots, self.limits)
                });
            let Ok((cost, _)) = planned else {
                let end = self.hook_failure(HookFailure::Budget);
                self.end_group(group, end);
                return;
            };
            cost as u64
        } else {
            group.items.iter().map(|out| out.len).sum()
        };
        if cost > 0
            && group.grant.is_none()
            && let Some(requests) = &self.requests
        {
            if !self.queue_fits(group.items.len().max(1), group.roots()) {
                self.drop_datagram(group, DropReason::QueueFull);
                return;
            }
            let Some(request) = requests.try_exact(cost) else {
                self.drop_datagram(group, DropReason::Blocked);
                return;
            };
            group.priced = Some(class);
            group.request = Some(request);
            self.datagrams.push(group);
            cx.waker().wake_by_ref();
            return;
        }

        if class == DatagramClass::Capsules {
            let Ok(bytes) = encode_group(&mut group.items, group.kind, None, self.limits) else {
                let end = self.hook_failure(HookFailure::Budget);
                self.end_group(group, end);
                return;
            };
            self.counts.encode_bytes += bytes as u64;
            group.write_state = GroupWrite::FallbackFirstByte;
            self.enqueue(group);
            return;
        }

        // Acquire every target-side policy grant before publishing any child.
        let mut allowances: Vec<_> = group
            .items
            .iter()
            .map(|output| self.w.datagram_allowance(output.payload_len))
            .collect();
        if allowances.iter().any(|allowance| !allowance.allowed()) {
            self.drop_datagram(group, DropReason::Limiter);
            return;
        }
        let options = group.options.expect("resolved datagram options");
        let data: Vec<_> = group
            .items
            .iter()
            .map(|output| {
                debug_assert!(output.pieces.len() <= 1);
                output
                    .pieces
                    .front()
                    .cloned()
                    .unwrap_or_default()
                    .into_bytes()
            })
            .collect();
        match self.w.commit_datagram_group(
            context.into_inner(),
            &data,
            options,
            self.datagram_policy(),
            self.handoffs
                .as_ref()
                .map(|handoffs| Prepayment::new(handoffs, group.grant.as_mut().map(Grant::prepaid)))
                .as_mut(),
        ) {
            Ok(PacketRepresentation::Datagram { .. }) => {
                for allowance in &mut allowances {
                    allowance.commit();
                }
                self.counts.enqueued_items += group.items.len() as u64;
                self.counts.dg_bytes += cost;
                self.counts.accepted_bytes += cost;
                group.disposition.enqueued_items = group.items.len() as u64;
                group.disposition.accepted_bytes = cost;
                group.complete();
            }
            Ok(PacketRepresentation::Capsule) => {
                drop(allowances);
                group.grant = None;
                group.priced = None;
                self.enqueue(group);
            }
            Err(error) => {
                drop(allowances);
                self.drop_datagram(group, DropReason::from_datagram(&error));
            }
        }
    }

    fn reliable_step(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
        readable: Option<usize>,
        started: bool,
    ) -> bool {
        if self.direct.is_some() {
            return self.direct_step(cx);
        }
        if let Some(mut group) = self.active.take() {
            let arrived_with_hook = group.hook.is_some();
            if self.poll_hook(cx, &mut group).is_pending() {
                self.active = Some(group);
                return false;
            }
            if group.items.is_empty() {
                group.complete();
                return true;
            }
            if arrived_with_hook
                && group.queued
                && !self.queue_fits(group.items.len(), group.roots())
            {
                let end = self.hook_failure(HookFailure::Budget);
                self.end_group(group, end);
                return true;
            }
            if Self::expired(&group, now) && group.deadline_active() {
                self.clear_writer();
                if group.fallback() {
                    self.drop_datagram(group, DropReason::Expired);
                } else {
                    self.end_group(group, SpliceEnd::WaitTimeout);
                    self.local_failure(SpliceEnd::WaitTimeout);
                }
                return true;
            }
            let ready = if (!self.paused || started)
                && (group.write_state != GroupWrite::Waiting || group.readiness.ready(cx, now))
            {
                self.finish_wait(&mut group, now);
                if group.write_state == GroupWrite::Waiting {
                    group.write_state = GroupWrite::Released;
                }
                self.write(cx, &mut group)
            } else {
                false
            };
            if let Some(end) = self.end {
                self.end_group(group, end);
            } else if group.items.is_empty() {
                group.complete();
            } else {
                self.active = Some(group);
            }
            return ready;
        }
        if self.assembly.is_some() {
            return self.assemble(cx, now, readable);
        }
        if !self.reliable.groups.is_empty() && !self.paused {
            self.active = Some(self.reliable.take(0));
            return true;
        }
        if self.source.drained() && self.reliable.groups.is_empty() {
            let _ = self
                .r
                .poll_read_chunk(cx.waker(), &mut self.r_wait.ticket, 1);
            match self.w.finish_shared() {
                Ok(()) | Err(StreamError::ClosedLocally) => self.finish(SpliceEnd::Finished),
                Err(error) => self.target_failed(&error),
            }
            return true;
        }
        if let Some((reset, size)) = self.source.reset()
            && self.source_offset >= size
        {
            if size == 0 {
                self.reset_target(SpliceEnd::Reset(reset), reset);
            } else {
                let through = self.packets.then_some(self.complete_output);
                self.reset_after_prefix(SpliceEnd::Reset(reset), reset, through);
            }
            return true;
        }
        let Some(n) = readable.filter(|&n| n > 0 && !self.paused) else {
            return false;
        };
        self.begin_reliable_batch(Some(n));
        if matches!(
            self.source,
            Source::Reset {
                discard_tail: true,
                ..
            }
        ) {
            return self.read(cx, n).is_ready();
        }
        if self.packets {
            let (generation, hooks) = self.reliable_policy();
            let hooks = hooks.clone();
            let admission = self.sequence(now, Some(self.source_offset), false, generation);
            self.assembly = Some(Assembly::new(admission, hooks));
            return self.assemble(cx, now, readable);
        }
        self.byte_unit(cx, now, n)
    }

    fn reset_after_prefix(&mut self, reason: SpliceEnd, code: VarInt, through: Option<u64>) {
        let _ = self.w.set_reliable_boundary_shared(through);
        if through != Some(0) && !self.w.peer_accepts_reset_stream_at() {
            self.flush = Some(PendingReset {
                reason,
                code,
                through,
            });
        } else {
            self.reset_target(reason, code);
        }
    }

    fn reset_target(&mut self, reason: SpliceEnd, code: VarInt) {
        if reason == SpliceEnd::PacketError {
            let _ = self.r.stop_shared(code);
        }
        let _ = self.w.reset_shared(code);
        self.finish(reason);
    }

    fn begin_reliable_batch(&mut self, readable: Option<usize>) {
        if self.source_offset >= self.read_batch.through
            && let Some(n) = readable.filter(|&n| n != 0)
            && let Some(inbox) = &self.commands
        {
            self.read_batch = ReadBatch {
                through: self.source_offset + n as u64,
                generation: inbox.start_source_batch(),
                hooks: self.hooks.clone(),
            };
        }
    }

    fn reliable_policy(&self) -> (Option<u64>, &HookChain) {
        if self.commands.is_some() {
            (Some(self.read_batch.generation), &self.read_batch.hooks)
        } else {
            (None, &self.hooks)
        }
    }

    fn read_limit(&self, limit: usize) -> usize {
        let limit = limit.min(self.bounds.chunk);
        if self.commands.is_some() {
            limit.min(crate::util::usize_sat(
                self.read_batch.through.saturating_sub(self.source_offset),
            ))
        } else {
            limit
        }
    }

    fn read(&mut self, cx: &mut Context<'_>, limit: usize) -> Poll<Option<crate::Chunk>> {
        let limit = self.read_limit(limit);
        if limit == 0 {
            return Poll::Pending;
        }
        let result = self
            .r
            .poll_take_chunk(cx.waker(), &mut self.r_wait.ticket, limit);
        self.read_result(result)
    }

    fn read_splice(
        &mut self,
        cx: &mut Context<'_>,
        limit: usize,
        fits_root: impl FnMut(Backing) -> bool,
        fits_copy: impl FnMut(usize) -> bool,
    ) -> Poll<Option<crate::Chunk>> {
        let limit = self.read_limit(limit);
        if limit == 0 {
            return Poll::Pending;
        }
        let result = self.r.poll_take_splice_chunk(
            cx.waker(),
            &mut self.r_wait.ticket,
            limit,
            fits_root,
            fits_copy,
        );
        let result = result.map_ok(|item| {
            item.map(|(data, copied)| {
                if copied {
                    self.counts.payload_copy_bytes += data.len() as u64;
                }
                data
            })
        });
        if matches!(result, Poll::Ready(Err(StreamError::BorrowLimit))) {
            self.hook_failure(HookFailure::Budget);
            return Poll::Ready(None);
        }
        self.read_result(result)
    }

    fn read_result(
        &mut self,
        result: Poll<Result<Option<crate::Chunk>, StreamError>>,
    ) -> Poll<Option<crate::Chunk>> {
        match result {
            Poll::Ready(Ok(Some(bytes))) => {
                self.source_offset += bytes.len() as u64;
                Poll::Ready(Some(bytes))
            }
            Poll::Ready(Ok(None)) => {
                self.source = Source::Drained;
                Poll::Ready(None)
            }
            Poll::Ready(Err(StreamError::Reset { code, .. })) => {
                self.read_exhausted = true;
                let size = self
                    .source
                    .reset()
                    .map_or(self.source_offset, |(_, size)| size.min(self.source_offset));
                self.observe_reset(code, size);
                Poll::Ready(None)
            }
            Poll::Ready(Err(error)) => {
                self.source_failed(&error);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn assemble(&mut self, cx: &mut Context<'_>, now: Instant, readable: Option<usize>) -> bool {
        let mut assembly = self.assembly.take().expect("one capsule in flight");
        if self
            .wait_deadline(assembly.admission.at)
            .is_some_and(|deadline| now >= deadline)
        {
            self.local_failure(SpliceEnd::WaitTimeout);
            return true;
        }
        if assembly.transparent.is_some() {
            return self.stream_capsule(cx, assembly, readable);
        }
        let next = assembly
            .header
            .state(self.bounds.packet, self.bounds.opaque);
        let reading_header = matches!(next, capsule::HeaderState::Need(_));
        let remaining = match next {
            capsule::HeaderState::Fault(_) => {
                self.packet_error();
                return true;
            }
            capsule::HeaderState::Need(n) => n,
            capsule::HeaderState::Complete(header) => {
                let kind = SpliceKind::Capsule {
                    ty: VarInt::from_u64(header.ty).expect("decoded varint"),
                    context: header
                        .context
                        .map(|c| VarInt::from_u64(c).expect("decoded varint")),
                };
                if assembly.hooks.capsule.is_none()
                    && self.mirror.is_none()
                    && self.w.peer_accepts_reset_stream_at()
                {
                    let header_bytes = crate::Chunk::copy_from_slice(assembly.header.bytes());
                    let mut output = Output::new(Payload::default());
                    output.payload_len = header.payload;
                    output.len = header.payload as u64;
                    output.prepend(header_bytes);
                    assembly.transparent = Some(TransparentCapsule {
                        remaining: header.payload,
                        output,
                    });
                    return self.stream_capsule(cx, assembly, readable);
                }
                if assembly.payload.len == header.payload {
                    let Ok(header) = assembly.finish_header(self.limits) else {
                        self.hook_failure(HookFailure::Budget);
                        return true;
                    };
                    assembly.admission.source_end = Some(self.source_offset);
                    if let Some(compact) = assembly.compact {
                        assembly.payload = Payload::single(crate::Chunk::from(compact));
                    }
                    self.active = self.group(
                        &assembly.admission,
                        kind,
                        assembly.payload,
                        Some(header),
                        Some(&assembly.hooks),
                        None,
                    );
                    return true;
                }
                header.payload - assembly.payload.len
            }
        };
        if let Some((_, size)) = self.source.reset() {
            if size <= self.source_offset {
                return true;
            }
        } else if self.source.drained() {
            self.packet_error();
            return true;
        }
        if self.paused {
            self.assembly = Some(assembly);
            return false;
        }
        let limit = self.limits.group_backing_bytes;
        let mut roots = Roots::default();
        let valid = roots.extend(&assembly.payload.pieces, limit).is_ok()
            && match &assembly.compact {
                Some(compact) => roots.reserve(compact.capacity(), limit).is_ok(),
                None if !reading_header
                    && assembly.payload.pieces.len() == self.limits.descriptors =>
                {
                    roots
                        .reserve(assembly.payload.len + remaining, limit)
                        .is_ok()
                }
                None => true,
            };
        self.begin_reliable_batch(readable);
        let result = if reading_header {
            self.read(cx, remaining)
        } else {
            self.read_splice(
                cx,
                remaining,
                |root| valid && roots.fits(root, limit),
                |len| valid && len <= roots.remaining(limit),
            )
        };
        match result {
            Poll::Pending => {
                self.assembly = Some(assembly);
                false
            }
            Poll::Ready(None) => {
                if self.end.is_none() && self.source.reset().is_none() {
                    self.packet_error();
                }
                true
            }
            Poll::Ready(Some(chunk)) => {
                if reading_header {
                    assembly.header.append(&chunk);
                } else {
                    let Ok(copied) = assembly.add_payload(chunk, remaining, self.limits) else {
                        self.hook_failure(HookFailure::Budget);
                        return true;
                    };
                    self.counts.payload_copy_bytes += copied as u64;
                }
                self.assembly = Some(assembly);
                true
            }
        }
    }

    fn byte_unit(&mut self, cx: &mut Context<'_>, now: Instant, n: usize) -> bool {
        let mut n = n.min(self.bounds.chunk);
        let transparent = self.reliable_policy().1.stream.is_none() && self.mirror.is_none();
        if transparent {
            let room = match self.w.poll_capacity_with(
                cx.waker(),
                &mut self.w_wait.ticket,
                n.min(STEP) as u64,
            ) {
                Poll::Ready(Ok(room)) => crate::util::usize_sat(room),
                Poll::Ready(Err(e)) => {
                    self.target_failed(&e);
                    return true;
                }
                Poll::Pending => return false,
            };
            n = n.min(room);
        }
        let offset = self.source_offset;
        let result = if transparent {
            self.read(cx, n)
        } else {
            let limit = self.limits.group_backing_bytes;
            self.read_splice(cx, n, |root| root.size <= limit, |len| len <= limit)
        };
        match result {
            Poll::Pending => false,
            Poll::Ready(None) => true,
            Poll::Ready(Some(data)) if transparent => {
                self.direct = Some(Direct { data, offset });
                self.direct_step(cx)
            }
            Poll::Ready(Some(data)) => {
                let (generation, hooks) = self.reliable_policy();
                let hooks = hooks.clone();
                let mut admission = self.sequence(now, Some(offset), false, generation);
                admission.source_end = Some(self.source_offset);
                self.active = self.group(
                    &admission,
                    SpliceKind::Stream,
                    Payload::leased(data),
                    None,
                    Some(&hooks),
                    None,
                );
                true
            }
        }
    }

    fn direct_step(&mut self, cx: &mut Context<'_>) -> bool {
        if self.paused {
            return false;
        }
        let Some(mut direct) = self.direct.take() else {
            return true;
        };
        if let Some((_, size)) = self.source.reset() {
            direct
                .data
                .truncate(crate::util::usize_sat(size.saturating_sub(direct.offset)));
        }
        if direct.data.is_empty() {
            return true;
        }
        let room = match self
            .w
            .poll_capacity_with(cx.waker(), &mut self.w_wait.ticket, 1)
        {
            Poll::Ready(Ok(room)) => room,
            Poll::Ready(Err(e)) => {
                self.target_failed(&e);
                return true;
            }
            Poll::Pending => {
                self.direct = Some(direct);
                return false;
            }
        };
        let max = room.min(direct.data.len() as u64);
        let allowed = match self.poll_grant(cx, 1, max) {
            Poll::Pending => {
                self.direct = Some(direct);
                return false;
            }
            Poll::Ready(Err(())) => return true,
            Poll::Ready(Ok(max)) => max,
        };
        let status = self.commit_piece(cx, &mut direct.data, allowed, None, None);
        if let Poll::Ready(Write::Progress(n)) = status {
            self.permit = None;
            direct.offset += n as u64;
        }
        if self.end.is_none() && !direct.data.is_empty() {
            self.direct = Some(direct);
        } else if self.end.is_none() {
            self.counts.enqueued_items += 1;
        }
        status.is_ready()
    }

    fn write(&mut self, cx: &mut Context<'_>, group: &mut Group) -> bool {
        let capsule = group.capsule();
        let fallback = group.fallback();
        let Some(out) = group.items.front_mut() else {
            return true;
        };
        let deadline = (group.write_state == GroupWrite::FallbackFirstByte)
            .then_some(group.readiness.expires_at)
            .flatten();
        match self.write_output(cx, out, capsule, fallback, &mut group.grant, deadline) {
            Poll::Pending => false,
            Poll::Ready(Write::Failed) => true,
            Poll::Ready(Write::Expired) => {
                self.counts.drops.count(DropReason::Expired);
                group.disposition.status = Status::Dropped(DropReason::Expired);
                group.items.clear();
                true
            }
            Poll::Ready(Write::Progress(n)) => {
                group.disposition.accepted_bytes += n as u64;
                if n != 0 && group.write_state == GroupWrite::FallbackFirstByte {
                    group.write_state = GroupWrite::FallbackWriting;
                }
                if out.left == 0 {
                    let out = group.items.pop_front().expect("completed front");
                    self.counts.enqueued_items += 1;
                    if capsule {
                        self.counts.capsules += 1;
                        self.complete_output = self.output_start + self.counts.bytes;
                    }
                    group.disposition.enqueued_items += 1;
                    if group.fallback() {
                        self.counts.converted += 1;
                        self.counts.dg_bytes += out.payload_len as u64;
                    }
                    self.permit = None;
                }
                true
            }
        }
    }

    fn stream_capsule(
        &mut self,
        cx: &mut Context<'_>,
        mut assembly: Assembly,
        readable: Option<usize>,
    ) -> bool {
        let state = assembly.transparent.as_mut().expect("parsed header");
        let waker = cx.waker();
        if self.paused && !state.output.started() {
            self.assembly = Some(assembly);
            return false;
        }
        if let Source::Reset { code, size, .. } = self.source
            && self.source_offset.saturating_add(state.remaining as u64) > size
        {
            self.source = Source::Reset {
                code,
                size,
                discard_tail: true,
            };
            self.permit = None;
            return true;
        }
        let step = if state.output.header.is_some() || !state.output.pieces.is_empty() {
            self.write_output(cx, &mut state.output, true, false, &mut None, None)
                .is_ready()
        } else if state.remaining > 0 {
            if self.source.drained() {
                self.packet_error();
                return true;
            }
            let capacity = match self.w.poll_capacity_with(waker, &mut self.w_wait.ticket, 1) {
                Poll::Ready(Ok(room)) => crate::util::usize_sat(room),
                Poll::Ready(Err(e)) => {
                    self.target_failed(&e);
                    return true;
                }
                Poll::Pending => {
                    self.assembly = Some(assembly);
                    return false;
                }
            };
            self.begin_reliable_batch(readable);
            match self.read(cx, capacity.min(state.remaining)) {
                Poll::Pending => false,
                Poll::Ready(Some(piece)) => {
                    state.remaining -= piece.len();
                    state.output.pieces.push_back(piece);
                    true
                }
                Poll::Ready(None) => {
                    if self.end.is_none() && self.source.reset().is_none() {
                        self.packet_error();
                    }
                    return true;
                }
            }
        } else {
            true
        };
        if self.end.is_none() {
            if state.output.left == 0 {
                self.permit = None;
                self.counts.enqueued_items += 1;
                self.counts.capsules += 1;
                self.complete_output = self.output_start + self.counts.bytes;
            } else {
                self.assembly = Some(assembly);
            }
        }
        step
    }

    fn write_output(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut Output,
        capsule: bool,
        fallback: bool,
        grant: &mut Option<Grant>,
        deadline: Option<Instant>,
    ) -> Poll<Write> {
        let Some(piece) = out.header.as_mut().or_else(|| out.pieces.front_mut()) else {
            return Poll::Ready(Write::Progress(0));
        };
        let room = match self
            .w
            .poll_capacity_with(cx.waker(), &mut self.w_wait.ticket, 1)
        {
            Poll::Ready(Ok(room)) => room,
            Poll::Ready(Err(error)) => {
                self.target_failed(&error);
                return Poll::Ready(Write::Failed);
            }
            Poll::Pending => return Poll::Pending,
        };
        let max = room.min(piece.len() as u64);
        let allowed = if fallback {
            max
        } else {
            let (min, requested) = if capsule {
                (out.left, out.left)
            } else {
                (1, max)
            };
            match self.poll_grant(cx, min, requested) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(())) => return Poll::Ready(Write::Failed),
                Poll::Ready(Ok(allowed)) => max.min(allowed),
            }
        };
        let result = self.commit_piece(cx, piece, allowed, deadline, grant.as_mut());
        if let Poll::Ready(Write::Progress(n)) = result {
            if !capsule {
                self.permit = None;
            }
            out.left -= n as u64;
            if piece.is_empty() {
                if out.header.is_some() {
                    out.header = None;
                } else {
                    out.pieces.pop_front();
                }
            }
        }
        result
    }

    fn poll_grant(&mut self, cx: &mut Context<'_>, min: u64, max: u64) -> Poll<Result<u64, ()>> {
        if let Some(permit) = &self.permit {
            return Poll::Ready(Ok(permit.len().min(max)));
        }
        let Some(requests) = &self.requests else {
            return Poll::Ready(Ok(max));
        };
        let request = self
            .reliable_request
            .get_or_insert_with(|| requests.acquire(min, max));
        let Poll::Ready(grant) = request.as_mut().poll(cx) else {
            return Poll::Pending;
        };
        self.reliable_request = None;
        if let Some(grant) = grant {
            if let Some(code) = self.abort.and_then(SpliceAbort::code) {
                self.fail(SpliceEnd::Cancelled(code), code);
                return Poll::Ready(Err(()));
            }
            let allowed = grant.len().min(max);
            self.permit = Some(grant);
            Poll::Ready(Ok(allowed))
        } else {
            self.local_failure(SpliceEnd::LimiterFailed);
            Poll::Ready(Err(()))
        }
    }

    fn commit_piece(
        &mut self,
        cx: &mut Context<'_>,
        piece: &mut crate::Chunk,
        max: u64,
        deadline: Option<Instant>,
        grant: Option<&mut Grant>,
    ) -> Poll<Write> {
        let allowed = crate::util::usize_sat(max);
        let waker = cx.waker();
        let deadline = deadline.map(Instant::into_std);
        let mut payment = self.handoffs.as_ref().map(|handoffs| {
            let grant = grant.or(self.permit.as_mut()).map(Grant::prepaid);
            Prepayment::new(handoffs, grant)
        });
        let outcome = if allowed == piece.len() {
            self.w.poll_write_part_before(
                waker,
                &mut self.w_wait.ticket,
                piece,
                deadline,
                payment.as_mut(),
            )
        } else {
            let mut prefix = piece.slice(..allowed);
            let outcome = self.w.poll_write_part_before(
                waker,
                &mut self.w_wait.ticket,
                &mut prefix,
                deadline,
                payment.as_mut(),
            );
            if let Poll::Ready(Ok(Some(n))) = outcome {
                let _ = piece.split_to(n);
            }
            outcome
        };
        match outcome {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.target_failed(&e);
                Poll::Ready(Write::Failed)
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Write::Expired),
            Poll::Ready(Ok(Some(n))) => {
                self.counts.bytes += n as u64;
                self.counts.accepted_bytes += n as u64;
                Poll::Ready(Write::Progress(n))
            }
        }
    }

    fn now(&self) -> Instant {
        self.clock.now().into()
    }

    fn wait_deadline(&self, admitted: Instant) -> Option<Instant> {
        admitted.checked_add(self.limits.wait_cap?)
    }

    fn timer(&mut self, cx: &mut Context<'_>, now: Instant) {
        let held = self
            .active
            .iter()
            .chain(&self.reliable.groups)
            .chain(&self.datagrams.groups);
        let soonest = held
            .filter(|group| group.deadline_active())
            .flat_map(|group| [group.readiness.expires_at, group.readiness.ready_at])
            .chain(
                self.assembly
                    .iter()
                    .map(|a| self.wait_deadline(a.admission.at)),
            )
            .flatten()
            .filter(|at| *at > now)
            .min();
        if let Some(at) = soonest {
            if self
                .timer
                .as_ref()
                .is_none_or(|(deadline, _)| *deadline != at)
            {
                let timer = self
                    .clock
                    .wait_until(at.into_std())
                    .unwrap_or_else(|| Box::pin(sleep_until(at)));
                self.timer = Some((at, timer));
            }
            if let Some((_, timer)) = &mut self.timer
                && timer.as_mut().poll(cx).is_ready()
            {
                self.timer = None;
                cx.waker().wake_by_ref();
            }
        } else {
            self.timer = None;
        }
    }
}
