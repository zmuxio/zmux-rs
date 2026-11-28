//! An attachment: one pipe ID with up to one pipe in each direction, and
//! its multipath part (fate group, join and failure state, the
//! `PIPE_ABANDON` exchange, the tier settings).

use std::time::{Duration, Instant};

use super::{InPipe, InState, OutPipe, OutState, TierState};
use crate::proto::TransportErrorCode as T;
use crate::proto::session::health::HealthTracker;

/// What a pipe held when the session retired it, for the handles that
/// outlive it: its options and how it ended.
pub(crate) type FinalPipe = std::sync::Arc<std::sync::OnceLock<crate::proto::session::PipeFinal>>;

/// An attachment: one pipe ID with up to one pipe in each direction.
#[derive(Debug)]
pub(crate) struct Attachment {
    id: u64,
    joiner_local: bool,
    inp: Option<InPipe>,
    out: Option<OutPipe>,
    /// The multipath part, allocated for the attachments of a multipath
    /// session (and on the first write to it otherwise).
    mp: Option<Box<AttMp>>,
    /// The carrier's kind ([`SessionCore::set_pipe_carrier`]).
    ///
    /// [`SessionCore::set_pipe_carrier`]: crate::proto::session::SessionCore::set_pipe_carrier
    carrier: Option<crate::proto::session::CarrierKind>,
    /// The carrier reports its own failure (`PipeIo::with_reports_failure`).
    carrier_reports_failure: bool,
    /// The carrier's write overhead
    /// ([`SessionCore::set_pipe_write_overhead`]).
    ///
    /// [`SessionCore::set_pipe_write_overhead`]: crate::proto::session::SessionCore::set_pipe_write_overhead
    write_overhead: u16,
    /// When a traffic frame was last sent or received on it.
    traffic_at: Option<Instant>,
}

/// Peer evidence can only advance a pending local join. Retirement and
/// public statistics use this decision even if a late ACK advanced counters.
#[derive(Debug, Clone, Copy)]
enum PeerAttachment {
    Pending(Option<crate::proto::session::JoinDeadline>),
    Attached,
    Ended,
}

/// The multipath part of an attachment: its fate group, join and failure
/// state, the `PIPE_ABANDON` exchange and the tier settings.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent state flags, not a mode that an enum would encode"
)]
struct AttMp {
    accounting: Option<std::sync::Arc<crate::proto::session::accounting::Ledger>>,
    health: HealthTracker,
    fate_group: u64,
    replica_domain: Option<std::num::NonZeroU64>,
    physical_connection: Option<Box<super::super::CarrierConnId>>,
    /// A peer ID used without attachment state (refused join, or abandoned
    /// before it was seen): only its `PIPE_ABANDON` is kept, while the ID is
    /// in the replay window.
    unattached: bool,
    /// The join was confirmed: the acceptor attached it. Always true for
    /// attachments the peer joined.
    joined: bool,
    peer: PeerAttachment,
    /// The attachment failed (or was refused).
    failed: bool,
    /// Creation order, for "oldest".
    seq: u64,
    /// The record mode, fixed by its handshake.
    mode: Option<crate::proto::seal::RecordMode>,
    /// The Group of the join's key share, once the join has chosen it.
    key_group: Option<u64>,
    /// Our joins refused in a row before this one was confirmed: they
    /// continue if the peer abandons it for a resource limit.
    refusals_at_join: u32,
    /// The code of the local `PIPE_ABANDON`, once decided.
    abandon_code: Option<u64>,
    /// `PIPE_ABANDON` to (re)send.
    abandon_pending: bool,
    /// A graceful removal of our own outbound pipe puts `PIPE_ABANDON` on
    /// that pipe.
    abandon_on_self: bool,
    /// The local `PIPE_ABANDON` was written at least once.
    abandon_sent: bool,
    abandon_acked: bool,
    /// The peer's `PIPE_ABANDON` code.
    abandon_received: Option<u64>,
    /// Unilateral retirement deadline.
    retire_at: Option<Instant>,
    /// Priority, standby and weight.
    tier: TierState,
    /// Why it failed, once it did.
    failure: Option<crate::proto::session::PipeFailure>,
    /// The options of a pipe the application added (its fields that the
    /// tier state does not hold: label, fate group, detection settings).
    options: Option<Box<crate::proto::session::PipeOptions>>,
    /// Where the options and the end go when the attachment is retired, once
    /// a handle asked for it ([`SessionCore::pipe_final`]).
    ///
    /// [`SessionCore::pipe_final`]: crate::proto::session::SessionCore::pipe_final
    final_pipe: Option<FinalPipe>,
    /// The host's value of the admission that accepted the carrier
    /// ([`SessionCore::set_pipe_admitted`]).
    ///
    /// [`SessionCore::set_pipe_admitted`]: crate::proto::session::SessionCore::set_pipe_admitted
    admitted: Option<crate::proto::admission::AdmittedValue>,
    /// The host's label of the transform the carrier runs.
    variant: Option<std::sync::Arc<str>>,
}

impl AttMp {
    const fn new(fate_group: u64, seq: u64) -> Self {
        Self {
            accounting: None,
            health: HealthTracker::new(),
            fate_group,
            replica_domain: None,
            physical_connection: None,
            unattached: false,
            joined: false,
            peer: PeerAttachment::Attached,
            failed: false,
            seq,
            mode: None,
            key_group: None,
            refusals_at_join: 0,
            abandon_code: None,
            abandon_pending: false,
            abandon_on_self: false,
            abandon_sent: false,
            abandon_acked: false,
            abandon_received: None,
            retire_at: None,
            tier: TierState::new(),
            failure: None,
            options: None,
            final_pipe: None,
            admitted: None,
            variant: None,
        }
    }
}

/// What an attachment without a multipath part reads.
static NO_ATT_MP: AttMp = AttMp::new(0, 0);

impl Attachment {
    pub(in crate::proto::session) fn accounting(
        &self,
    ) -> Option<&std::sync::Arc<crate::proto::session::accounting::Ledger>> {
        self.mp().accounting.as_ref()
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(in crate::proto::session) fn set_accounting(
        &mut self,
        ledger: std::sync::Arc<crate::proto::session::accounting::Ledger>,
    ) {
        self.mp_mut().accounting = Some(ledger);
    }

    pub(in crate::proto::session) fn health(&self) -> Option<&HealthTracker> {
        self.mp.as_deref().map(|mp| &mp.health)
    }

    pub(in crate::proto::session) fn health_mut(&mut self) -> Option<&mut HealthTracker> {
        self.mp.as_deref_mut().map(|mp| &mut mp.health)
    }

    /// An attachment of a multipath session.
    pub(crate) fn new(id: u64, joiner_local: bool, fate_group: u64, seq: u64) -> Self {
        Self {
            id,
            joiner_local,
            inp: None,
            out: None,
            mp: Some(Box::new(AttMp {
                peer: if id != 0 && joiner_local {
                    PeerAttachment::Pending(None)
                } else {
                    PeerAttachment::Attached
                },
                ..AttMp::new(fate_group, seq)
            })),
            carrier: None,
            carrier_reports_failure: false,
            write_overhead: 0,
            traffic_at: None,
        }
    }

    /// An attachment the peer joined: its join is confirmed by being
    /// attached.
    pub(crate) fn accepted(id: u64, fate_group: u64, seq: u64) -> Self {
        let mut a = Self::new(id, false, fate_group, seq);
        a.mp_mut().joined = true;
        a
    }

    /// A peer-parity ID used without attachment state, with our
    /// `PIPE_ABANDON` (`code`) for it pending and the peer's, when it sent
    /// one.
    pub(crate) fn unattached_id(id: u64, seq: u64, code: u64, received: Option<u64>) -> Self {
        let mut a = Self::new(id, false, 0, seq);
        let m = a.mp_mut();
        m.unattached = true;
        m.failed = true;
        m.abandon_code = Some(code);
        m.abandon_pending = true;
        m.abandon_received = received;
        a
    }

    /// A traffic frame was sent or received on it.
    pub(crate) fn note_traffic(&mut self, now: Instant) {
        self.traffic_at = Some(now);
    }

    /// When a traffic frame was last sent or received on it.
    pub(crate) fn traffic_at(&self) -> Option<Instant> {
        self.traffic_at
    }

    /// The bootstrap pair of a session without multipath (yet).
    pub(crate) fn bootstrap(joiner_local: bool) -> Self {
        Self {
            id: 0,
            joiner_local,
            inp: None,
            out: None,
            mp: None,
            carrier: None,
            carrier_reports_failure: false,
            write_overhead: 0,
            traffic_at: None,
        }
    }

    /// The bootstrap pair becomes attachment 0 of a multipath session,
    /// joined by the initiator: its multipath parts are allocated with the
    /// outbound pipe's detection settings, and its clocks start now.
    pub(crate) fn start_multipath(
        &mut self,
        joiner_local: bool,
        detection: super::Detection,
        now: Instant,
    ) {
        self.joiner_local = joiner_local;
        if self.mp.is_none() {
            self.mp = Some(Box::new(AttMp::new(0, 0)));
        }
        if let Some(o) = self.out.take() {
            self.out = Some(o.start_multipath(detection, now));
        }
        if let Some(p) = &mut self.inp {
            p.restart(now);
        }
    }

    /// With the inbound pipe `p`.
    pub(crate) fn with_inp(mut self, p: InPipe) -> Self {
        self.inp = Some(p);
        self
    }

    /// With the outbound pipe `o`.
    pub(crate) fn with_out(mut self, o: OutPipe) -> Self {
        self.out = Some(o);
        self
    }

    /// Attaches the inbound half of the bootstrap pair, unless it has one.
    pub(crate) fn attach_inp(&mut self, p: impl FnOnce() -> InPipe) {
        if self.inp.is_none() {
            self.inp = Some(p());
        }
    }

    /// Attaches the outbound half of the bootstrap pair, unless it has one.
    pub(crate) fn attach_out(&mut self, o: impl FnOnce() -> OutPipe) {
        if self.out.is_none() {
            self.out = Some(o());
        }
    }

    /// Replaces the outbound half with a fresh one (the bootstrap pipe
    /// after its carrier rejected early data).
    pub(crate) fn replace_out(&mut self, o: OutPipe) {
        self.out = Some(o);
    }

    #[inline]
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn attach_by(&self) -> Option<crate::proto::session::JoinDeadline> {
        match self.mp().peer {
            PeerAttachment::Pending(deadline) => deadline,
            PeerAttachment::Attached | PeerAttachment::Ended => None,
        }
    }

    pub(crate) fn set_attach_by(&mut self, deadline: Option<crate::proto::session::JoinDeadline>) {
        if let PeerAttachment::Pending(slot) = &mut self.mp_mut().peer {
            *slot = deadline;
        }
    }

    /// The local endpoint joined it.
    #[inline]
    pub(crate) fn joiner_local(&self) -> bool {
        self.joiner_local
    }

    /// The peer has attached the pipe: pipe 0 and a pipe the peer joined
    /// are attached from the start; one of our joins once the peer showed
    /// it attached it, by a `PIPE_ACK` covering any byte on any lane of the
    /// outbound pipe or, for an inbound-only pipe, by a record received
    /// on it.
    pub(crate) fn peer_attached(&self) -> bool {
        matches!(self.mp().peer, PeerAttachment::Attached)
    }

    pub(crate) fn confirm_peer(&mut self) -> bool {
        if !matches!(self.mp().peer, PeerAttachment::Pending(_)) {
            return false;
        }
        let confirmed = match (self.out(), self.inp()) {
            (Some(o), _) => o.acked_total() > 0,
            (None, Some(i)) => i.records_received() > 0,
            (None, None) => false,
        };
        if confirmed {
            self.mp_mut().peer = PeerAttachment::Attached;
        }
        confirmed
    }

    #[inline]
    pub(crate) fn inp(&self) -> Option<&InPipe> {
        self.inp.as_ref()
    }

    #[inline]
    pub(crate) fn inp_mut(&mut self) -> Option<&mut InPipe> {
        self.inp.as_mut()
    }

    #[inline]
    pub(crate) fn out(&self) -> Option<&OutPipe> {
        self.out.as_ref()
    }

    #[inline]
    pub(crate) fn out_mut(&mut self) -> Option<&mut OutPipe> {
        self.out.as_mut()
    }

    /// The multipath part (the defaults while it is not allocated).
    #[inline]
    fn mp(&self) -> &AttMp {
        self.mp.as_deref().unwrap_or(&NO_ATT_MP)
    }

    /// The multipath part, allocated on first use.
    fn mp_mut(&mut self) -> &mut AttMp {
        self.mp.get_or_insert_with(|| Box::new(AttMp::new(0, 0)))
    }

    /// Heap bytes the attachment holds.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.out.as_ref().map_or(0, OutPipe::heap_bytes)
            + self.inp.as_ref().map_or(0, InPipe::heap_bytes)
            + self
                .mp
                .as_deref()
                .map_or(0, |m| size_of::<AttMp>() + m.tier.heap_bytes())
    }

    // ---- fate group, join and failure ---------------------------------------

    #[inline]
    pub(crate) fn fate_group(&self) -> u64 {
        self.mp().fate_group
    }

    /// The key of its fate group's probation history: the joiner and the
    /// group.
    #[inline]
    pub(crate) fn fate(&self) -> (bool, u64) {
        (self.joiner_local, self.mp().fate_group)
    }

    pub(crate) fn physical_connection(&self) -> Option<&super::super::CarrierConnId> {
        self.mp().physical_connection.as_deref()
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn set_physical_connection(&mut self, connection: super::super::CarrierConnId) {
        let physical = &mut self.mp_mut().physical_connection;
        if let Some(current) = physical {
            **current = connection;
        } else {
            *physical = Some(Box::new(connection));
        }
    }

    pub(crate) fn replica_domain(&self) -> Option<std::num::NonZeroU64> {
        self.mp().replica_domain
    }

    pub(crate) fn set_replica_domain(&mut self, domain: Option<std::num::NonZeroU64>) {
        self.mp_mut().replica_domain = domain;
    }

    /// A peer ID used without attachment state.
    #[inline]
    pub(crate) fn unattached(&self) -> bool {
        self.mp().unattached
    }

    /// The join was confirmed (or the peer joined it).
    #[inline]
    pub(crate) fn joined(&self) -> bool {
        self.mp().joined
    }

    /// The attachment failed (or was refused).
    #[inline]
    pub(crate) fn failed(&self) -> bool {
        self.mp().failed
    }

    /// Creation order.
    #[inline]
    pub(crate) fn seq(&self) -> u64 {
        self.mp().seq
    }

    /// Our join was confirmed, with `refusals` of our joins refused in a
    /// row before it: a request for the peer's direction changed while
    /// JOINING goes out with its latest value only.
    pub(crate) fn join_confirmed(&mut self, refusals: u32) {
        let m = self.mp_mut();
        m.refusals_at_join = refusals;
        m.joined = true;
        m.tier.keep_latest_request();
    }

    /// The record mode, fixed by its handshake.
    pub(crate) fn mode(&self) -> Option<crate::proto::seal::RecordMode> {
        self.mp().mode
    }

    /// The Group of the join's key share, once the join has chosen it.
    pub(crate) fn key_group(&self) -> Option<u64> {
        self.mp().key_group
    }

    /// Fixes the Group of the join's key share.
    pub(crate) fn set_key_group(&mut self, group: u64) {
        self.mp_mut().key_group = Some(group);
    }

    /// Fixes the record mode.
    pub(crate) fn set_mode(&mut self, mode: crate::proto::seal::RecordMode) {
        self.mp_mut().mode = Some(mode);
    }

    /// Our joins refused in a row before this one was confirmed.
    pub(crate) fn refusals_at_join(&self) -> u32 {
        self.mp().refusals_at_join
    }

    /// Marks the attachment failed: `false` when it had failed already. A
    /// `PIPE_ABANDON` meant as the pipe's own last frame goes on another pipe
    /// now: the failed pipe writes nothing more.
    pub(crate) fn fail(&mut self) -> bool {
        let m = self.mp_mut();
        if m.failed {
            return false;
        }
        if matches!(m.peer, PeerAttachment::Pending(_)) {
            m.peer = PeerAttachment::Ended;
        }
        m.failed = true;
        m.abandon_on_self = false;
        true
    }

    /// Records why the attachment failed (the first cause stays).
    pub(crate) fn set_failure(&mut self, cause: crate::proto::session::PipeFailure) {
        self.mp_mut().failure.get_or_insert(cause);
    }

    /// Why the attachment failed, once it did.
    pub(crate) fn failure(&self) -> Option<crate::proto::session::PipeFailure> {
        self.mp().failure
    }

    /// Why our join ended before it was confirmed, if it did.
    pub(crate) fn join_failure(&self) -> Option<crate::proto::session::PipeFailure> {
        if !self.joiner_local() || self.peer_attached() {
            return None;
        }
        self.failure()
    }

    /// The carrier's kind.
    pub(crate) fn carrier(&self) -> Option<crate::proto::session::CarrierKind> {
        self.carrier
    }

    /// Sets the carrier's kind.
    pub(crate) fn set_carrier_reports_failure(&mut self, on: bool) {
        self.carrier_reports_failure = on;
    }

    /// Whether the carrier reports its own failure.
    pub(crate) fn carrier_reports_failure(&self) -> bool {
        self.carrier_reports_failure
    }

    pub(crate) fn set_carrier(&mut self, kind: Option<crate::proto::session::CarrierKind>) {
        self.carrier = kind;
    }

    /// Sets the carrier's write overhead.
    pub(crate) fn set_write_overhead(&mut self, bytes: u16) {
        self.write_overhead = bytes;
    }

    /// The outbound pipe as a shaper factory sees it.
    pub(crate) fn shaped(&self) -> crate::proto::session::shaping::ShapedPipe {
        crate::proto::session::shaping::ShapedPipe::new(
            crate::proto::session::PipeId(self.id),
            self.carrier,
        )
        .with_write_overhead(self.write_overhead)
        .with_variant(self.variant().cloned())
    }

    /// The host's label of the transform the carrier runs.
    pub(crate) fn variant(&self) -> Option<&std::sync::Arc<str>> {
        self.mp().variant.as_ref()
    }

    /// Keeps the host's label of the transform the carrier runs.
    pub(crate) fn set_variant(&mut self, variant: Option<std::sync::Arc<str>>) {
        // The cold part is allocated only for a label.
        if variant.is_some() || self.mp.is_some() {
            self.mp_mut().variant = variant;
        }
    }

    /// The host's admission value of the carrier.
    pub(crate) fn admitted(&self) -> Option<&crate::proto::admission::AdmittedValue> {
        self.mp().admitted.as_ref()
    }

    /// Keeps the host's admission value of the carrier.
    pub(crate) fn set_admitted(&mut self, value: Option<crate::proto::admission::AdmittedValue>) {
        if value.is_some() || self.mp.is_some() {
            self.mp_mut().admitted = value;
        }
    }

    /// The application's label.
    pub(crate) fn label(&self) -> Option<&std::sync::Arc<str>> {
        self.mp().options.as_ref()?.label.as_ref()
    }

    /// The pipe's own liveness settings.
    pub(crate) fn own_liveness(&self) -> crate::proto::session::PipeLiveness {
        self.mp
            .as_deref()
            .and_then(|m| m.options.as_deref())
            .map(crate::proto::session::PipeOptions::own_liveness)
            .unwrap_or_default()
    }

    /// The options the application added the pipe with.
    pub(crate) fn options(&self) -> Option<&crate::proto::session::PipeOptions> {
        self.mp().options.as_deref()
    }

    /// Keeps the options the application adds the pipe with.
    pub(crate) fn set_options(&mut self, options: &crate::proto::session::PipeOptions) {
        self.mp_mut().options = Some(Box::new(options.clone()));
    }

    /// The slot that receives the pipe's options and its end when it is
    /// retired, created on the first call.
    pub(crate) fn final_pipe(&mut self) -> FinalPipe {
        self.mp_mut()
            .final_pipe
            .get_or_insert_with(Default::default)
            .clone()
    }

    /// The slot of the final snapshot, when a handle other than the
    /// attachment holds it.
    pub(crate) fn final_pipe_wanted(&self) -> Option<&FinalPipe> {
        self.mp
            .as_deref()?
            .final_pipe
            .as_ref()
            .filter(|s| std::sync::Arc::strong_count(s) > 1)
    }

    // ---- the PIPE_ABANDON exchange --------------------------------------------------

    /// The peer's `PIPE_ABANDON` code, once received.
    #[inline]
    pub(crate) fn abandon_received(&self) -> Option<u64> {
        self.mp().abandon_received
    }

    /// Our `PIPE_ABANDON` was acknowledged.
    #[inline]
    pub(crate) fn abandon_acked(&self) -> bool {
        self.mp().abandon_acked
    }

    /// Decides the local `PIPE_ABANDON` with `code` unless one was decided,
    /// and owes it.
    pub(crate) fn abandon(&mut self, code: u64) {
        let m = self.mp_mut();
        if m.abandon_code.is_none() {
            m.abandon_code = Some(code);
            m.abandon_pending = true;
        }
    }

    /// A graceful removal: `PIPE_ABANDON(NO_ERROR)` unless one was decided, as
    /// the last frame of the drained pipe itself when it can still carry it.
    pub(crate) fn abandon_gracefully(&mut self) {
        let on_self = self
            .out
            .as_ref()
            .is_some_and(|o| o.is_live() && o.writable());
        let m = self.mp_mut();
        if m.abandon_code.is_none() {
            m.abandon_code = Some(0);
            m.abandon_pending = true;
            m.abandon_on_self = on_self;
        }
    }

    /// The attachment is retired at once without its `PIPE_ABANDON`.
    pub(crate) fn drop_abandon(&mut self) {
        self.mp_mut().abandon_pending = false;
    }

    /// The local `PIPE_ABANDON` waits to be written: on the attachment's own
    /// pipe (`on_self`) or on the control pipe.
    #[inline]
    pub(crate) fn abandon_owed(&self, on_self: bool) -> bool {
        let m = self.mp();
        m.abandon_pending && m.abandon_on_self == on_self
    }

    /// The local `PIPE_ABANDON` to write: its code, when it is owed and goes
    /// on the control pipe (or, with `own`, on whatever pipe writes it).
    pub(crate) fn abandon_to_write(&self, own: bool) -> Option<u64> {
        let m = self.mp();
        (m.abandon_pending && (own || !m.abandon_on_self)).then(|| m.abandon_code.unwrap_or(0))
    }

    /// The local `PIPE_ABANDON` was written.
    pub(crate) fn abandon_written(&mut self) {
        let m = self.mp_mut();
        m.abandon_pending = false;
        m.abandon_sent = true;
    }

    /// The local `PIPE_ABANDON` was acknowledged; without the peer's, the
    /// attachment retires unilaterally after `delay`.
    pub(crate) fn abandon_acknowledged(&mut self, delay: Duration, now: Instant) {
        let m = self.mp_mut();
        m.abandon_acked = true;
        m.abandon_pending = false;
        if m.abandon_received.is_none() {
            m.retire_at = Some(now + delay);
        }
    }

    /// The frame that carried the local `PIPE_ABANDON` was lost: it is owed
    /// again, on the control pipe, unless it was acknowledged.
    pub(crate) fn abandon_lost(&mut self) {
        let m = self.mp_mut();
        if !m.abandon_acked {
            m.abandon_pending = true;
            m.abandon_on_self = false;
        }
    }

    /// The peer's `PIPE_ABANDON` with `code`: `false` for a copy of one
    /// received already.
    pub(crate) fn abandon_arrived(&mut self, code: u64) -> bool {
        let m = self.mp_mut();
        if m.abandon_received.is_some() {
            return false;
        }
        m.abandon_received = Some(code);
        true
    }

    /// When the attachment retires unilaterally.
    #[inline]
    pub(crate) fn retire_at(&self) -> Option<Instant> {
        self.mp().retire_at
    }

    /// Its graceful removal has started: `PIPE_ABANDON(NO_ERROR)` sent (or
    /// decided) or received. Its failure or suspicion then affects no other
    /// attachment of its fate group and does not count in the group's
    /// probation history.
    #[inline]
    pub(crate) fn draining(&self) -> bool {
        self.mp().abandon_code == Some(0) || self.mp().abandon_received == Some(0)
    }

    /// Abandoned with `ZMUX_PIPE_RESOURCE_LIMIT`, by either endpoint: it did
    /// not fail with its path.
    #[inline]
    pub(crate) fn limit_abandoned(&self) -> bool {
        let rl = Some(T::ZMUX_PIPE_RESOURCE_LIMIT.0);
        self.mp().abandon_code == rl || self.mp().abandon_received == rl
    }

    /// This endpoint abandoned it for its own resource limit: the peer's
    /// answer starts no join backoff.
    #[inline]
    pub(crate) fn own_limit_abandon(&self) -> bool {
        self.mp().abandon_code == Some(T::ZMUX_PIPE_RESOURCE_LIMIT.0)
    }

    /// Its failure or suspicion affects no other attachment of its fate
    /// group and counts for nothing in the probation history: its graceful
    /// removal started, or it was abandoned for a resource limit.
    #[inline]
    pub(crate) fn outside_fate(&self) -> bool {
        self.draining() || self.limit_abandoned()
    }

    /// The `PIPE_ABANDON` exchange is complete: ours sent, the peer's
    /// received.
    #[inline]
    pub(crate) fn exchange_complete(&self) -> bool {
        self.mp().abandon_sent && self.mp().abandon_received.is_some()
    }

    /// A graceful end of the inbound pipe is expected: the peer abandoned
    /// the attachment, or this endpoint started its graceful removal.
    pub(crate) fn end_expected(&self) -> bool {
        self.mp().abandon_received.is_some() || self.mp().abandon_code == Some(0)
    }

    /// Our `PIPE_ABANDON` is acknowledged; `unattached` too when only a bit
    /// in the replay window remains.
    pub(crate) fn own_abandon_done(&self) -> bool {
        self.mp().abandon_code.is_some() && self.mp().abandon_acked
    }

    // ---- tier settings --------------------------------------------------------------

    /// The tier settings.
    #[inline]
    pub(crate) fn tier(&self) -> &TierState {
        &self.mp().tier
    }

    /// The tier settings, to change through their own operations.
    pub(crate) fn tier_mut(&mut self) -> &mut TierState {
        &mut self.mp_mut().tier
    }

    /// The outbound direction is standby: it takes new stream data only on failover.
    #[inline]
    pub(crate) fn standby(&self) -> bool {
        self.mp().tier.standby().0
    }

    /// The effective priority of the outbound direction: the local
    /// setting, then the peer's request, then 0.
    #[inline]
    pub(crate) fn send_tier(&self) -> u64 {
        self.mp().tier.send_priority().0
    }

    // ---- the pipes --------------------------------------------------------------

    /// A changed request of ours waits: while JOINING, for the attachment's own first
    /// record, or on a down attachment for the first record to arrive on it.
    pub(crate) fn status_held(&self) -> bool {
        if !self.joiner_local || self.id == 0 {
            return false;
        }
        self.joining_local()
            || self.out().is_some_and(OutPipe::joined_first)
            || (self.out().is_none() && self.inp().is_some_and(|p| p.records_received() == 0))
    }

    /// One of our joins that is not confirmed yet: it sends no `PIPE_STATUS`.
    #[inline]
    pub(crate) fn joining_local(&self) -> bool {
        self.id != 0 && self.joiner_local && !self.mp().joined && !self.mp().failed
    }

    /// The last progress: the later of the last advance of the outbound acknowledged
    /// position, the last record received inbound, and the attachment.
    pub(crate) fn last_progress(&self) -> Option<Instant> {
        let out = self.out.as_ref().map(OutPipe::last_progress);
        let inp = self.inp.as_ref().map(InPipe::last_progress);
        out.into_iter().chain(inp).max()
    }

    #[inline]
    pub(crate) fn in_live(&self) -> bool {
        self.inp.as_ref().is_some_and(InPipe::is_live)
    }

    #[inline]
    pub(crate) fn out_live(&self) -> bool {
        self.out.as_ref().is_some_and(OutPipe::is_live)
    }

    /// A local join not sent yet ([`OutState::Deferred`]).
    #[inline]
    pub(crate) fn deferred(&self) -> bool {
        self.out
            .as_ref()
            .is_some_and(|o| o.state() == OutState::Deferred)
            || self
                .inp
                .as_ref()
                .is_some_and(|p| p.state() == InState::Deferred)
    }

    /// Both halves ended (or absent).
    pub(crate) fn ends_done(&self) -> bool {
        self.inp
            .as_ref()
            .is_none_or(|p| p.state() == InState::Ended)
            && self.out.as_ref().is_none_or(|o| !o.state().is_live())
            && !self.graceful_shutdown_pending()
    }

    pub(crate) fn graceful_shutdown_pending(&self) -> bool {
        self.out
            .as_ref()
            .is_some_and(OutPipe::graceful_shutdown_pending)
    }

    pub(crate) fn displaceable(&self, local: bool) -> bool {
        self.joiner_local() == local
            && !self.unattached()
            && !self.deferred()
            && !self.graceful_shutdown_pending()
    }
}
