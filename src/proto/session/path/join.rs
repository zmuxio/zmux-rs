//! The Join handshake at the session layer: the session's join keys, the joiner's and
//! the acceptor's steps. The protocol itself is [`seal::join`]; this
//! module decides what a verified message does to the session. A driver runs the
//! bytes: it writes what these calls return on the carrier, and starts the pipe's
//! records once a call says so.

use std::time::Instant;

use crate::proto::frame::{Frame, JoinDirection};
use crate::proto::ident::{Classifier, FirstRecord, Verdict};
use crate::proto::record::Framing;
use crate::proto::seal::join::{
    Acceptor, AcceptorKeys, AwaitConfirm, Finished, HelloSent, JoinConfig, JoinHello, Joiner,
    Proven, Unconfirmed, key_share_item_len,
};
use crate::proto::seal::{
    self, Group, JoinPipe, JoinRole, Opener, Payload, RecordMode, Sealer, Secret, Suite,
    derive_join_psk, encode_payload,
};
use crate::proto::session::pipes::{
    Attachment, InPipe, InState, OutPipe, OutState, PipeHalf, SentFrame,
};
use crate::proto::session::shaping::{
    PlanAnswer, UnitPlan, first_batch_limit, fit_item, join_hello_len, join_reply_len, message_len,
    pad_fill, pad_item, reply_room, varint_len,
};
use crate::proto::session::{CoreEvent, PipeError, PipeFailure, PipeId, SessionCore, State};
use crate::proto::{Error, TransportErrorCode as T, keys};

/// What a joiner reads before a verified Reply: one transport parameters record and a
/// Reply of the largest unit, never `max_record_size`.
pub const JOIN_READ_BOUND: usize = 2 * 65_535 + 64;

const JOIN_PIPE_ITEM: u64 = 5;
const FRAMES_ITEM: u64 = 6;
const JOIN_DECISION_ITEM: u64 = 7;

/// The join keys of one usable Suite in one epoch.
pub(in crate::proto::session) struct SuiteKeys {
    suite: &'static Suite,
    initiator: Secret,
    responder: Secret,
}

/// The secret of one epoch and the join keys derived from it.
pub(in crate::proto::session) struct EpochKeys {
    pub(in crate::proto::session) epoch: u64,
    pub(in crate::proto::session) secret: Secret,
    suites: Vec<SuiteKeys>,
}

impl EpochKeys {
    /// Derives both `join_psk` values of each usable Suite from the secret of `epoch`.
    pub(in crate::proto::session) fn derive(
        epoch: u64,
        secret: Secret,
        usable: &[&'static Suite],
        session_crypto: &[u8],
    ) -> Self {
        let suites = usable
            .iter()
            .filter_map(|&suite| {
                let k = |role| derive_join_psk(suite, &secret, role, session_crypto).ok();
                Some(SuiteKeys {
                    suite,
                    initiator: k(JoinRole::Initiator)?.into(),
                    responder: k(JoinRole::Responder)?.into(),
                })
            })
            .collect();
        Self {
            epoch,
            secret,
            suites,
        }
    }

    /// `join_psk` of a joiner's role for a usable Suite.
    pub(in crate::proto::session) fn psk(&self, suite: u64, initiator: bool) -> Option<&[u8]> {
        let k = self.suites.iter().find(|k| k.suite.value() == suite)?;
        Some(if initiator {
            &k.initiator
        } else {
            &k.responder
        })
    }
}

/// The session's join keys once derived: `session_crypto`, the usable Suites and Groups,
/// and the epochs whose secrets the session holds (at most two, adjacent).
pub(in crate::proto::session) struct ReadyKeys {
    pub(in crate::proto::session) session_crypto: Vec<u8>,
    pub(in crate::proto::session) suites: Vec<&'static Suite>,
    pub(in crate::proto::session) groups: Vec<&'static Group>,
    pub(in crate::proto::session) psk: bool,
    /// Ascending; the epochs this end accepts are among them.
    pub(in crate::proto::session) epochs: Vec<EpochKeys>,
}

impl ReadyKeys {
    pub(in crate::proto::session) fn epoch(&self, e: u64) -> Option<&EpochKeys> {
        self.epochs.iter().find(|k| k.epoch == e)
    }

    /// The usable Group values, ascending.
    pub(in crate::proto::session) fn group_values(&self) -> Vec<u64> {
        self.groups.iter().map(|g| g.value()).collect()
    }

    /// The Group of a local join: `wanted` when usable, `None` when it is not; without a
    /// wish Group 1 when usable, else the usable Group of highest priority.
    pub(in crate::proto::session) fn join_group(
        &self,
        wanted: Option<u64>,
    ) -> Option<&'static Group> {
        match wanted {
            Some(v) => self.groups.iter().copied().find(|g| g.value() == v),
            None => self
                .groups
                .iter()
                .copied()
                .find(|g| g.value() == seal::group::GROUP_X25519)
                .or_else(|| Group::highest(&self.group_values())),
        }
    }

    /// The Suite a joiner uses: by local preference, an end without AES hardware
    /// leaving Suite 1 for when nothing else is usable.
    fn preferred(&self) -> Option<&'static Suite> {
        prefer(&self.suites, seal::has_aes_hardware())
    }
}

/// The session's join keys, or what deriving them waits for.
pub(in crate::proto::session) enum JoinKeys {
    /// Derived.
    Ready(ReadyKeys),
    /// Join pending: the inputs held until a deferred key or a declaration arrives.
    Pending {
        i_nonce: [u8; 16],
        r_nonce: [u8; 16],
        exporter: Vec<u8>,
        psk: bool,
        session_crypto: Vec<u8>,
        usable: Vec<&'static Suite>,
        groups: Vec<&'static Group>,
    },
}

impl std::fmt::Debug for JoinKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JoinKeys(..)")
    }
}

impl JoinKeys {
    /// Derives the keys of epoch 0 now when `psk_key` and the declaration allow it. A
    /// session secret from empty input keying material does not exist: the source holds a
    /// real input.
    pub(in crate::proto::session) fn advance(&mut self, psk_key: Option<&[u8]>, declared: bool) {
        let Self::Pending {
            i_nonce,
            r_nonce,
            exporter,
            psk,
            session_crypto,
            usable,
            groups,
        } = self
        else {
            return;
        };
        let key: &[u8] = match (*psk, psk_key) {
            (true, None) => return,
            (true, Some(k)) => k,
            (false, _) => &[],
        };
        if !declared {
            return;
        }
        let secret = Secret::from(&keys::session_secret(i_nonce, r_nonce, exporter, key)[..]);
        exporter.fill(0);
        let epoch0 = EpochKeys::derive(0, secret, usable, session_crypto);
        *self = Self::Ready(ReadyKeys {
            session_crypto: std::mem::take(session_crypto),
            suites: std::mem::take(usable),
            groups: std::mem::take(groups),
            psk: *psk,
            epochs: vec![epoch0],
        });
    }

    /// Overwrites the exporter value held for keys that never came.
    pub(in crate::proto::session) fn wipe(&mut self) {
        if let Self::Pending { exporter, .. } = self {
            exporter.fill(0);
            exporter.clear();
        }
    }

    pub(in crate::proto::session) fn uses_psk(&self) -> bool {
        match self {
            Self::Ready(r) => r.psk,
            Self::Pending { psk, .. } => *psk,
        }
    }

    pub(in crate::proto::session) fn pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    pub(in crate::proto::session) fn ready(&self) -> Option<&ReadyKeys> {
        match self {
            Self::Ready(r) => Some(r),
            Self::Pending { .. } => None,
        }
    }

    pub(in crate::proto::session) fn ready_mut(&mut self) -> Option<&mut ReadyKeys> {
        match self {
            Self::Ready(r) => Some(r),
            Self::Pending { .. } => None,
        }
    }
}

/// The Suite for a Hello and its first batch, and for its Sealed records, among the usable
/// ones: suite 1 (AES-256-GCM) only with AES hardware or when nothing else is usable.
fn prefer(usable: &[&'static Suite], aes_hardware: bool) -> Option<&'static Suite> {
    let first = usable.iter().copied().find(|s| s.value() == 1);
    if aes_hardware {
        return first.or_else(|| usable.first().copied());
    }
    usable.iter().copied().find(|s| s.value() != 1).or(first)
}

#[cfg(all(test, feature = "seal-chacha"))]
mod suite_tests {
    use super::*;

    #[test]
    fn suite_1_only_with_hardware_or_when_nothing_else_is_usable() {
        let both: Vec<_> = Suite::all().collect();
        let one: Vec<_> = Suite::all().filter(|s| s.value() == 1).collect();
        assert_eq!(prefer(&both, true).unwrap().value(), 1);
        assert_eq!(prefer(&both, false).unwrap().value(), 2);
        assert_eq!(prefer(&one, false).unwrap().value(), 1);
        assert_eq!(prefer(&one, true).unwrap().value(), 1);
        assert!(prefer(&[], true).is_none());
    }
}

/// The handshake of a local join.
#[derive(Default)]
pub(in crate::proto::session) struct LocalJoin {
    pub(in crate::proto::session) id: u64,
    pub(in crate::proto::session) mode: Option<RecordMode>,
    pub(in crate::proto::session) binding: Vec<u8>,
    /// The Group the host asked for; `None` is the local preference.
    pub(in crate::proto::session) group: Option<u64>,
    /// The epoch of the Hello's key, once written: the join is in flight with it.
    pub(in crate::proto::session) epoch: Option<u64>,
    framing: Option<Framing>,
    overhead: u16,
    suite: Option<&'static Suite>,
    sent: Option<HelloSent>,
    /// The Reply verified: what Confirm is made from.
    proven: Option<Proven>,
    /// The one leading transport parameters record was consumed.
    leading_seen: bool,
}

impl std::fmt::Debug for LocalJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalJoin").field("id", &self.id).finish()
    }
}

impl LocalJoin {
    pub(in crate::proto::session) fn new(
        id: u64,
        mode: RecordMode,
        binding: Vec<u8>,
        group: Option<u64>,
    ) -> Self {
        Self {
            id,
            mode: Some(mode),
            binding,
            group,
            ..Self::default()
        }
    }
}

/// A finished handshake's record directions, past Confirm, in Sealed; `None` otherwise.
pub type JoinRecords = Option<(Sealer, Opener)>;

/// Type 0 of a handshake payload: padding.
const PADDING_ITEM: u64 = 0;

/// What [`SessionCore::join_finish`] made.
pub struct JoinFinished {
    /// The confirmation, possibly empty.
    pub confirm: Vec<u8>,
    /// The record directions in Sealed.
    pub records: JoinRecords,
    /// The handshake's exporter.
    pub finished: Box<Finished>,
}

impl std::fmt::Debug for JoinFinished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JoinFinished")
    }
}

const fn item_size(v: usize) -> usize {
    1 + varint_len(v as u64) + v
}

/// What [`SessionCore::verify_reply`] concluded from the bytes of a JOINING carrier.
pub enum JoinStep {
    /// More bytes are wanted. `consumed` bytes are done with, and progress needs `need`
    /// bytes in all from there.
    More {
        /// Bytes to drop from the input.
        consumed: usize,
        /// The total length that can progress.
        need: usize,
    },
    /// The Reply verified with decision 0: the attachment is still joining. Plan the
    /// confirmation and call [`SessionCore::join_finish`]; the records begin after
    /// `consumed` bytes of the input.
    Verified {
        /// Bytes of the input the handshake took.
        consumed: usize,
        /// The record mode: Bound has no confirmation.
        mode: RecordMode,
    },
    /// The Reply verified with decision 1: the attachment is retired, close the carrier.
    Declined,
    /// The attachment failed: close the carrier.
    Failed,
}

impl std::fmt::Debug for JoinStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::More { consumed, need } => f
                .debug_struct("More")
                .field("consumed", consumed)
                .field("need", need)
                .finish(),
            Self::Verified { consumed, mode } => f
                .debug_struct("Verified")
                .field("consumed", consumed)
                .field("mode", mode)
                .finish(),
            Self::Declined => f.write_str("Declined"),
            Self::Failed => f.write_str("Failed"),
        }
    }
}

/// A Hello the session verified: no session state, and an Unconfirmed carrier once
/// claimed.
pub struct PeerJoin {
    pipe: JoinPipe,
    mode: RecordMode,
    /// The epoch of the Hello's key.
    epoch: u64,
    suite: &'static Suite,
    payload: Payload,
    state: PeerJoinState,
}

enum PeerJoinState {
    Opened(Unconfirmed),
    AwaitConfirm(AwaitConfirm),
    Confirmed(Box<Finished>),
    Gone,
}

impl std::fmt::Debug for PeerJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerJoin")
            .field("pipe", &self.pipe)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl PeerJoin {
    /// The Hello's join pipe item.
    pub fn pipe(&self) -> &JoinPipe {
        &self.pipe
    }

    /// The Mode the joiner chose.
    pub fn mode(&self) -> RecordMode {
        self.mode
    }

    /// Reads the joiner's confirmation at the start of `input`: `Ok(Some(consumed))` once
    /// it is Confirmed, `Ok(None)` while it wants more bytes. In Bound there is none. A
    /// failure is permanent for the carrier.
    pub fn read_confirm(&mut self, input: &[u8]) -> Result<Option<usize>, seal::Error> {
        let PeerJoinState::AwaitConfirm(wait) = &self.state else {
            return match self.state {
                PeerJoinState::Confirmed(_) => Ok(Some(0)),
                _ => Err(seal::Error::InvalidConfig),
            };
        };
        match wait.ready(input) {
            Ok(()) => {}
            Err(seal::Error::Incomplete { .. }) => return Ok(None),
            Err(e) => return Err(e),
        }
        let PeerJoinState::AwaitConfirm(wait) =
            std::mem::replace(&mut self.state, PeerJoinState::Gone)
        else {
            return Err(seal::Error::InvalidConfig);
        };
        let (done, consumed) = wait.read_confirm(input)?;
        self.state = PeerJoinState::Confirmed(Box::new(done));
        Ok(Some(consumed))
    }

    /// The finished handshake of a Confirmed carrier, for its exporter.
    pub fn finished(&self) -> Option<&Finished> {
        match &self.state {
            PeerJoinState::Confirmed(d) => Some(d),
            _ => None,
        }
    }
}

/// What [`SessionCore::open_hello`] made of a Hello.
#[derive(Debug)]
pub enum OpenedHello {
    /// The session is not established yet: offer the Hello again afterwards, or close at
    /// the handshake timeout.
    Hold,
    /// Join pending: hold the carrier without session state until
    /// [`CoreEvent::JoinKeysReady`], or close it at the handshake timeout.
    KeyWait,
    /// The Hello's Suite is outside the session's: an unauthenticated rejection, given
    /// the listener's reject policy like an unknown Locator. Nothing is written.
    UnknownSuite,
    /// The Hello's Locator is not one the session accepts now (an epoch deleted it): an
    /// unknown Locator, given the listener's reject policy. Nothing is written.
    UnknownLocator,
    /// Close the carrier and write nothing: a replay, a session that cannot take joins.
    Close,
    /// The Hello did not verify: close the carrier. Reported as
    /// [`CoreEvent::JoinAuthFailed`].
    AuthFailed,
    /// The session is closing for what the Hello said: close the carrier.
    Fatal,
    /// Authenticated: apply the Mode and authorization policy, then
    /// [`SessionCore::claim_hello`].
    Verified(Box<PeerJoin>),
}

/// What [`SessionCore::claim_hello`] did.
#[derive(Debug)]
pub enum ClaimedHello {
    /// Write this Reply: the carrier is Unconfirmed and waits for the confirmation.
    Accept(Vec<u8>),
    /// Write this Reply and close the carrier: decision 1.
    Refuse(Vec<u8>),
    /// Close the carrier and write nothing.
    Close,
}

/// What [`SessionCore::confirm_join`] did.
pub enum ConfirmedJoin {
    /// Attached: the records on the carrier are the pipe's.
    Attached {
        /// The new pipe.
        pipe: PipeId,
        /// The record directions in Sealed.
        records: JoinRecords,
    },
    /// The cap no longer allows it: close the carrier. PIPE_ABANDON goes on another pipe.
    Refused,
    /// Close the carrier: the session is ending.
    Close,
}

impl std::fmt::Debug for ConfirmedJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Attached { pipe, .. } => f.debug_tuple("Attached").field(pipe).finish(),
            Self::Refused => f.write_str("Refused"),
            Self::Close => f.write_str("Close"),
        }
    }
}

/// What the acceptor's carrier provides and how it stands to the session.
#[derive(Debug, Clone, Copy)]
pub struct PeerCarrier {
    /// The acceptor can read it.
    pub inbound: Option<Framing>,
    /// The acceptor can write it.
    pub outbound: Option<Framing>,
    /// It runs over this session.
    pub looped: bool,
    /// The carrier's write overhead.
    pub overhead: u16,
    /// The bytes received on it: at least what the Hello consumed.
    pub received: usize,
}

/// Whether bytes in `b` begin as one leading transport parameters record: its length, or
/// `None` while undecided, `Err` when they cannot.
fn leading_record(b: &[u8], framing: Framing) -> Result<Option<usize>, ()> {
    if framing == Framing::Records {
        let mut c = Classifier::bootstrap(65_535);
        return match c.message(b) {
            Verdict::Accept(FirstRecord::Session) => Ok(Some(b.len())),
            _ => Err(()),
        };
    }
    let mut c = Classifier::bootstrap(65_535);
    match c.push(b) {
        Verdict::NeedMore => Ok(None),
        Verdict::Accept(FirstRecord::Session) => {
            let Some((size, width)) = crate::proto::varint::decode(b) else {
                return Ok(None);
            };
            let total = width + usize::try_from(size).map_err(|_| ())?;
            Ok((b.len() >= total).then_some(total))
        }
        _ => Err(()),
    }
}

impl SessionCore {
    // ---- joiner ---------------------------------------------------------------------

    /// Whether a local join may go: the name of its Hello, `hello_early` when the session has no
    /// other usable outbound pipe and first batches are on, whatever is queued, and `Ok(None)`
    /// while the cap or the refusal backoff defers it.
    pub fn join_prepare(
        &mut self,
        pipe: PipeId,
        now: Instant,
    ) -> Result<Option<&'static str>, PipeError> {
        self.tick(now);
        if self.join_deferred(pipe) {
            return Ok(None);
        }
        let initiator = self.is_initiator();
        let mp = self.mp.as_deref().ok_or(PipeError::NotNegotiated)?;
        if !mp.local_joins.iter().any(|j| j.id == pipe.0) {
            return Err(PipeError::UnknownPipe);
        }
        let pending = || self.join_pending_error();
        let keys = mp.keys.ready().ok_or_else(pending)?;
        let suite = keys.preferred().ok_or_else(pending)?;
        let (epoch, _) = self.join_epoch();
        keys.epoch(epoch)
            .and_then(|k| k.psk(suite.value(), initiator))
            .ok_or_else(pending)?;
        let wanted = mp
            .local_joins
            .iter()
            .find(|j| j.id == pipe.0)
            .and_then(|j| j.group);
        keys.join_group(wanted).ok_or(PipeError::InvalidArgument)?;
        let early = self.config.join_early_hello.unwrap_or(0);
        Ok(Some(if early > 0 && !self.other_usable(pipe.0) {
            "hello_early"
        } else {
            "hello"
        }))
    }

    fn other_usable(&self, id: u64) -> bool {
        self.atts
            .iter()
            .any(|a| a.id() != id && !a.failed() && a.out().is_some_and(|o| o.usable(true)))
    }

    /// Writes the Hello of a prepared local join under `plan`, with a first batch while no
    /// other outbound pipe is usable; one write. `overhead` is the carrier's write overhead.
    pub fn join_hello(
        &mut self,
        pipe: PipeId,
        (framing, overhead): (Framing, u16),
        plan: &UnitPlan,
        now: Instant,
    ) -> Result<Vec<u8>, PipeError> {
        self.tick(now);
        if self.state >= State::Closing {
            return Err(PipeError::NotEstablished);
        }
        let id = pipe.0;
        let initiator = self.is_initiator();
        let mp = self.mp.as_deref().ok_or(PipeError::NotNegotiated)?;
        let i = mp.local_joins.iter().position(|j| j.id == id);
        let i = i.ok_or(PipeError::UnknownPipe)?;
        let pending = || self.join_pending_error();
        let keys = mp.keys.ready().ok_or_else(pending)?;
        let suite = keys.preferred().ok_or_else(pending)?;
        let (epoch, locator) = self.join_epoch();
        let locator = locator.clone();
        let psk = keys
            .epoch(epoch)
            .and_then(|k| k.psk(suite.value(), initiator))
            .ok_or_else(pending)?;
        let j = &mp.local_joins[i];
        let group = keys.join_group(j.group).ok_or(PipeError::InvalidArgument)?;
        let joiner = Joiner::new(JoinConfig {
            suite,
            group,
            mode: j.mode.unwrap_or(RecordMode::Sealed),
            phase: (epoch & 1) as u8,
            framing,
            locator: locator.as_bytes(),
            psk,
            binding: &j.binding,
        })
        .map_err(|_| PipeError::InvalidArgument)?;
        let a = self.att(id).ok_or(PipeError::UnknownPipe)?;
        let up = a.inp().is_none();
        let direction = match (a.inp().is_some(), a.out().is_some()) {
            (true, true) => JoinDirection::Bidi,
            (false, _) => JoinDirection::Up,
            (true, false) => JoinDirection::Down,
        };
        let item = JoinPipe {
            id,
            direction: direction.to_bits(),
            fate_group: a.fate_group(),
            // The acceptor has no outbound direction on an up attachment.
            priority: if up { 0 } else { a.tier().receive_priority() },
            standby: !up && a.tier().receive_standby(),
        }
        .encode();
        // The unit without its frames and padding: the join pipe and the key share.
        let item_len = item_size(item.len()) + key_share_item_len(group, true);
        let stream = framing == Framing::ByteStream;
        let unit = |plain: usize| {
            join_hello_len(
                suite.value(),
                locator.as_bytes().len(),
                suite.r_len(),
                stream,
                plain + suite.tag_len(),
                usize::from(overhead),
            )
        };
        let early = self.config.join_early_hello.unwrap_or(0);
        let limit = first_batch_limit(early, plan.pad_to, unit(item_len));
        // The frames item stays within what the Hello's ciphertext holds.
        let hello_room = (u16::MAX as usize).saturating_sub(item_len + suite.tag_len());
        let limit = fit_item(hello_room).map_or(0, |v| v.min(limit));
        let batch = self.first_batch(id, limit);
        let plain = item_len
            + if batch.is_empty() {
                0
            } else {
                item_size(batch.len())
            };
        let w = unit(plain);
        let gap = plan.pad_for(w) as isize - w as isize;
        let room = (u16::MAX as usize).saturating_sub(plain + suite.tag_len());
        let padding = pad_item(gap, room);
        let zeros = vec![0; padding.unwrap_or(0)];
        let mut items: Vec<(u64, &[u8])> = Vec::with_capacity(3);
        if padding.is_some() {
            items.push((PADDING_ITEM, &zeros));
        }
        items.push((JOIN_PIPE_ITEM, &item));
        if !batch.is_empty() {
            items.push((FRAMES_ITEM, &batch));
        }
        let payload = encode_payload(&items);
        let (wire, sent) = joiner
            .write_hello(&payload)
            .map_err(|_| PipeError::InvalidArgument)?;
        self.shaping_spend(padding.map_or(0, |v| item_size(v) as u64));
        let j = &mut self.mp_mut().local_joins[i];
        j.framing = Some(framing);
        j.overhead = overhead;
        j.suite = Some(suite);
        j.sent = Some(sent);
        j.epoch = Some(epoch);
        j.binding = Vec::new();
        self.epoch_note_join();
        Ok(wire)
    }

    /// Counts a handshake shaper's answer about a message of a Join.
    pub fn note_join_plan(&mut self, answer: PlanAnswer) -> UnitPlan {
        match answer {
            PlanAnswer::Plan(p) => return p,
            PlanAnswer::Unplanned => self.join_shaping.unplanned += 1,
            PlanAnswer::Fault => self.join_shaping.faults += 1,
        }
        UnitPlan::default()
    }

    /// Feeds bytes read from a JOINING carrier; nothing of them reaches the session before
    /// they verify, and at most one leading transport parameters record is consumed
    /// unprocessed. Anything else fails only the attachment.
    pub fn verify_reply(&mut self, pipe: PipeId, input: &[u8], now: Instant) -> JoinStep {
        self.tick(now);
        let id = pipe.0;
        let Some(i) = self
            .mp
            .as_deref()
            .and_then(|m| m.local_joins.iter().position(|j| j.id == id))
        else {
            return JoinStep::Failed;
        };
        if input.len() > JOIN_READ_BOUND {
            return self.join_failed(id, now);
        }
        let j = &self.mp().local_joins[i];
        let Some(framing) = j.framing else {
            return JoinStep::Failed;
        };
        let leading_seen = j.leading_seen;
        let mut skip = 0;
        let mut b = input;
        if b.first().is_some_and(|&x| x != seal::join::REPLY_TYPE) {
            if leading_seen {
                return self.join_failed(id, now);
            }
            match leading_record(b, framing) {
                Ok(None) => {
                    return JoinStep::More {
                        consumed: 0,
                        need: input.len() + 1,
                    };
                }
                Ok(Some(n)) => {
                    self.mp_mut().local_joins[i].leading_seen = true;
                    skip = n;
                    b = &b[n..];
                    if framing == Framing::Records {
                        return JoinStep::More {
                            consumed: skip,
                            need: 1,
                        };
                    }
                }
                Err(()) => return self.join_failed(id, now),
            }
        }
        let Some(sent) = self.mp_mut().local_joins[i].sent.as_ref() else {
            return JoinStep::Failed;
        };
        match sent.ready(b) {
            Ok(()) => {}
            Err(seal::Error::Incomplete { need }) => {
                return JoinStep::More {
                    consumed: skip,
                    need,
                };
            }
            Err(_) => return self.join_failed(id, now),
        }
        let Some(sent) = self.mp_mut().local_joins[i].sent.take() else {
            return JoinStep::Failed;
        };
        let Ok((proven, used)) = sent.read_reply(b) else {
            return self.join_failed(id, now);
        };
        let consumed = skip + used;
        self.stats.join_failures = 0;
        if proven.payload().join_accepted() == Some(false) {
            self.mp_mut().local_joins.remove(i);
            self.join_declined(id, now);
            return JoinStep::Declined;
        }
        let mode = proven.mode();
        self.mp_mut().local_joins[i].proven = Some(proven);
        JoinStep::Verified { consumed, mode }
    }

    /// Makes the confirmation of a verified Reply under `plan`: the attachment becomes
    /// ACTIVE and the Reply's frames apply. Write the confirmation before any record.
    pub fn join_finish(
        &mut self,
        pipe: PipeId,
        plan: &UnitPlan,
        now: Instant,
    ) -> Result<JoinFinished, PipeError> {
        self.tick(now);
        let id = pipe.0;
        if self.state >= State::Closing {
            return Err(PipeError::NotEstablished);
        }
        let mp = self.mp.as_deref().ok_or(PipeError::NotNegotiated)?;
        let i = mp.local_joins.iter().position(|j| j.id == id);
        let i = i.ok_or(PipeError::UnknownPipe)?;
        let j = &mut self.mp_mut().local_joins[i];
        let (framing, overhead) = (j.framing, usize::from(j.overhead));
        let (Some(framing), Some(suite), Some(proven)) = (framing, j.suite, j.proven.take()) else {
            return Err(PipeError::UnknownPipe);
        };
        let frames = proven.payload().frames().map(<[u8]>::to_vec);
        let mode = proven.mode();
        let epoch = self.mp().local_joins[i].epoch.unwrap_or(0);
        let (body, room) = match mode {
            RecordMode::Sealed => (suite.tag_len(), u16::MAX as usize - suite.tag_len()),
            RecordMode::Trusted => (suite.hash_len(), u16::MAX as usize - suite.hash_len()),
            RecordMode::Bound | RecordMode::Unmanaged => (0, 0),
        };
        let w = message_len(framing == Framing::ByteStream, body, overhead);
        let zeros = pad_fill(plan.pad_for(w) as isize - w as isize, room);
        let Ok((confirm, finished)) = proven.write_confirm(zeros) else {
            self.join_failed(id, now);
            return Err(PipeError::Failed(PipeFailure::JoinFailed));
        };
        self.shaping_spend(zeros as u64);
        let mut finished = Box::new(finished);
        let records = finished.take_records();
        self.mp_mut().local_joins.remove(i);
        self.epoch_attached(id, epoch, now);
        self.join_proven(id, mode, now);
        if let Some(frames) = frames {
            self.apply_batch(&frames, now);
        }
        Ok(JoinFinished {
            confirm,
            records,
            finished,
        })
    }

    fn join_failed(&mut self, id: u64, now: Instant) -> JoinStep {
        self.fail_attachment(id, PipeFailure::JoinFailed, now);
        self.after_pipe_change(now);
        JoinStep::Failed
    }

    /// A verified Reply with decision 0: Proven, and the attachment ACTIVE. Stall clocks
    /// start here.
    fn join_proven(&mut self, id: u64, mode: RecordMode, now: Instant) {
        let sealed = mode == RecordMode::Sealed;
        if mode != RecordMode::Trusted {
            self.epoch_first_pipe();
        }
        self.join_confirmed(id);
        let max = self.local_tp().max_record_size();
        if let Some(a) = self.att_mut(id) {
            a.set_mode(mode);
        }
        if let Some(p) = self.inp_mut(id) {
            if sealed {
                p.set_framing(Framing::Records, max, now);
            }
            p.join_proven(now);
        }
        let out = self.out_mut(id).map(|o| {
            if sealed {
                o.set_framing(Framing::Records);
            }
            o.join_proven(now);
        });
        if out.is_some() {
            self.start_probation(id, now);
        }
        for half in [PipeHalf::Inbound, PipeHalf::Outbound] {
            self.pipe_event(id, half);
        }
        self.views_changed();
        self.release_deferred_joins(now);
        self.check_standby_takeover();
        if self.state == State::Suspended {
            self.check_resume(now);
        }
        self.after_pipe_change(now);
    }

    // ---- acceptor -------------------------------------------------------------------

    /// A Hello in Bound on a carrier without a Binding: an authentication failure, refused
    /// before it is opened.
    pub fn hello_without_binding(&mut self) {
        self.stats.join_auth_failures += 1;
        self.push_event(CoreEvent::JoinAuthFailed { reason: "auth" });
    }

    /// Steps 3 to 6 for a Hello that named this session's locator: a Suite outside the
    /// session's is refused before the AEAD, and the key is that of the joiner's role in
    /// the session, never inferred from the Pipe ID. `binding` is the carrier's when it
    /// has one.
    pub fn open_hello(
        &mut self,
        hello: &JoinHello<'_>,
        binding: &[u8],
        now: Instant,
    ) -> OpenedHello {
        self.tick(now);
        match self.state {
            State::Establishing => return OpenedHello::Hold,
            State::Closing | State::Closed => return OpenedHello::Close,
            _ => {}
        }
        let Some(mp) = self.mp.as_deref() else {
            return OpenedHello::Close;
        };
        if mp.keys.pending() {
            self.stats.join_pending += 1;
            return OpenedHello::KeyWait;
        }
        if !self.accepts_locator(hello.locator()) {
            return OpenedHello::UnknownLocator;
        }
        // Step 5: the join key of the peer's role, of the accepted epoch the key phase
        // selects.
        let peer_initiator = !self.is_initiator();
        let Some(keys) = mp.keys.ready() else {
            return OpenedHello::KeyWait;
        };
        if !keys
            .suites
            .iter()
            .any(|s| s.value() == hello.suite().value())
        {
            return OpenedHello::UnknownSuite; // without opening the Hello
        }
        let groups = keys.group_values();
        let epoch = self
            .accepted_epochs()
            .into_iter()
            .find(|e| e & 1 == u64::from(hello.phase()));
        let psk = epoch.and_then(|e| keys.epoch(e)?.psk(hello.suite().value(), peer_initiator));
        // No accepted epoch of this phase: a key no joiner has, so that the Hello fails
        // as any wrong key does.
        // Without randomness there is no such key, and the Hello fails as auth unopened.
        let psk = match psk.or_else(|| unknown_phase_key(hello.suite().hash_len())) {
            Some(k) => k,
            None => {
                self.stats.join_auth_failures += 1;
                self.push_event(CoreEvent::JoinAuthFailed { reason: "auth" });
                return OpenedHello::AuthFailed;
            }
        };
        let opened = Acceptor::open(
            hello,
            AcceptorKeys {
                psk,
                binding,
                groups: &groups,
            },
        );
        let epoch = epoch.unwrap_or(0);
        let (opened, payload) = match opened {
            Ok(v) => v,
            Err(e) => {
                let reason = match e {
                    seal::Error::MissingField
                    | seal::Error::BadField
                    | seal::Error::TlvNonMinimal
                    | seal::Error::TlvTruncated
                    | seal::Error::TlvOrder
                    | seal::Error::TlvUnknownCritical => e.class(),
                    _ => "auth",
                };
                self.stats.join_auth_failures += 1;
                self.push_event(CoreEvent::JoinAuthFailed { reason });
                return OpenedHello::AuthFailed;
            }
        };
        let Some(pipe) = payload.join_pipe() else {
            return OpenedHello::Close;
        };
        let id = pipe.id;
        let mp = self.mp();
        if !mp.is_local(id) && (self.att_index(id).is_some() || self.is_retired(id)) {
            // Step 6: a replay, or too late.
            self.stats.join_replays += 1;
            return OpenedHello::Close;
        }
        if mp.is_local(id) {
            self.protocol_error(
                Error::new(T::PROTOCOL_VIOLATION, 0, "join with the acceptor's parity"),
                now,
            );
            return OpenedHello::Fatal;
        }
        self.epoch_peer_joined(epoch, now);
        OpenedHello::Verified(Box::new(PeerJoin {
            pipe,
            epoch,
            mode: hello.mode(),
            suite: hello.suite(),
            payload,
            state: PeerJoinState::Opened(opened),
        }))
    }

    /// The rest of step 7: sets the Pipe ID's bit, applies the first batch and writes the
    /// Reply under `plan` with its read-only decision. It changes no pipe, cap or
    /// suspension. Before Confirmed, a Reply in Sealed or Bound keeps within three times
    /// the bytes received, padding included.
    pub fn claim_hello(
        &mut self,
        join: &mut PeerJoin,
        carrier: PeerCarrier,
        plan: &UnitPlan,
        now: Instant,
    ) -> ClaimedHello {
        self.tick(now);
        let id = join.pipe.id;
        let replay = self.att_index(id).is_some() || self.is_retired(id);
        if self.state >= State::Closing || self.mp.is_none() || replay {
            self.stats.join_replays += u64::from(replay);
            return ClaimedHello::Close;
        }
        self.use_peer_id(id, true);
        let (want_in, want_out) = wanted(join.pipe.direction);
        let refuse = (want_in && carrier.inbound.is_none())
            || (want_out && carrier.outbound.is_none())
            || carrier.looped
            || !self.room_predicted(false, want_in, want_out);
        let PeerJoinState::Opened(opened) = std::mem::replace(&mut join.state, PeerJoinState::Gone)
        else {
            return ClaimedHello::Close;
        };
        let decision = [u8::from(refuse)];
        let framing = carrier
            .outbound
            .or(carrier.inbound)
            .unwrap_or(Framing::ByteStream);
        let plain = item_size(decision.len()) + key_share_item_len(opened.group(), false);
        let w = join_reply_len(
            join.suite.r_len(),
            framing == Framing::ByteStream,
            plain + join.suite.tag_len(),
            usize::from(carrier.overhead),
        );
        let mut room = (u16::MAX as usize).saturating_sub(plain + join.suite.tag_len());
        if join.mode != RecordMode::Trusted {
            room = room.min(reply_room(carrier.received, w, 0).1);
        }
        let padding = pad_item(plan.pad_for(w) as isize - w as isize, room);
        let zeros = vec![0; padding.unwrap_or(0)];
        let mut items: Vec<(u64, &[u8])> = Vec::with_capacity(2);
        if padding.is_some() {
            items.push((PADDING_ITEM, &zeros));
        }
        items.push((JOIN_DECISION_ITEM, &decision));
        let payload = encode_payload(&items);
        // The key exchange runs only now, with the Pipe ID's bit set: a replayed Hello costs
        // at most its AEAD. A refused share closes the carrier and leaves the bit set.
        let (reply, wait) = match opened.write_reply(&payload) {
            Ok(v) => v,
            Err(seal::Error::Kex) => {
                self.stats.join_auth_failures += 1;
                self.push_event(CoreEvent::JoinAuthFailed { reason: "kex" });
                return ClaimedHello::Close;
            }
            Err(_) => return ClaimedHello::Close,
        };
        self.shaping_spend(padding.map_or(0, |v| item_size(v) as u64));
        if let Some(frames) = join.payload.frames().map(<[u8]>::to_vec) {
            self.apply_batch(&frames, now);
        }
        join.state = PeerJoinState::AwaitConfirm(wait);
        // A Bound carrier is Confirmed by the Hello having passed.
        if join.mode == RecordMode::Bound && !refuse {
            let _ = join.read_confirm(&[]);
        }
        if refuse {
            ClaimedHello::Refuse(reply)
        } else {
            ClaimedHello::Accept(reply)
        }
    }

    /// Step 8: the only place where a peer join moves a pipe, the cap or a suspension.
    pub fn confirm_join(
        &mut self,
        join: PeerJoin,
        carrier: PeerCarrier,
        now: Instant,
    ) -> ConfirmedJoin {
        self.tick(now);
        if self.state >= State::Closing {
            return ConfirmedJoin::Close;
        }
        let PeerJoinState::Confirmed(mut finished) = join.state else {
            return ConfirmedJoin::Close;
        };
        let j = join.pipe;
        let id = j.id;
        let (want_in, want_out) = wanted(j.direction);
        if carrier.looped || !self.room_for_join(false, want_in, want_out, now) {
            self.add_unattached(id, T::ZMUX_PIPE_RESOURCE_LIMIT.0, None);
            self.after_pipe_change(now);
            return ConfirmedJoin::Refused;
        }
        let seq = self.next_att_seq();
        let mut att = Attachment::accepted(id, j.fate_group, seq);
        att.set_mode(join.mode);
        let sealed = join.mode == RecordMode::Sealed;
        let framed = |f: Framing| if sealed { Framing::Records } else { f };
        let max = self.local_tp().max_record_size();
        if want_in && let Some(framing) = carrier.inbound {
            att = att.with_inp(InPipe::new(framed(framing), max, InState::Open, now));
        }
        if want_out && let Some(framing) = carrier.outbound {
            let rtt = self.initial_rtt(id);
            // The first record carries a complete snapshot and PIPE_PING (step 8).
            let o = OutPipe::new(framed(framing), OutState::Active, rtt, now)
                .with_mp(self.detection(id, None), now)
                .accepted(now);
            att = att.with_out(o);
            att.tier_mut().join_request(j.standby, j.priority);
        }
        self.insert_attachment(att);
        self.stats.pipes_added += 1;
        self.epoch_note_join();
        self.epoch_attached(id, join.epoch, now);
        if join.mode != RecordMode::Trusted {
            self.epoch_first_pipe();
        }
        if want_out {
            self.start_probation(id, now);
        }
        for half in [PipeHalf::Inbound, PipeHalf::Outbound] {
            self.pipe_event(id, half);
        }
        self.check_standby_takeover();
        if self.state == State::Suspended {
            self.check_resume(now);
        }
        self.epoch_progress(now);
        ConfirmedJoin::Attached {
            pipe: PipeId(id),
            records: finished.take_records(),
        }
    }

    /// Applies frames of a verified Hello or Reply: STREAM without FIN only. A frame in
    /// error is dropped and counted and never closes the session, because a batch can be
    /// a replay; it counts in no position and acknowledges nothing.
    fn apply_batch(&mut self, mut bytes: &[u8], now: Instant) {
        while !bytes.is_empty() {
            let Ok((frame, used)) = Frame::decode(bytes, &self.receive_gates()) else {
                self.stats.join_batch_dropped += 1;
                return;
            };
            bytes = &bytes[used..];
            match frame {
                Frame::Stream(f) if !f.fin => {
                    if self.batch_stream(f, now).is_err() {
                        self.stats.join_batch_dropped += 1;
                    }
                }
                _ => self.stats.join_batch_dropped += 1,
            }
        }
    }
}

/// The process's key for a Hello whose key phase matches no accepted epoch: random, drawn
/// once, and never a join key. `None` while the random source fails: nothing is cached
/// then, so a later Hello draws again. Never a constant, which anyone could compute.
fn unknown_phase_key(len: usize) -> Option<&'static [u8]> {
    static KEY: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    unknown_phase_key_in(&KEY, len, |k| seal::fill_random(k).is_ok())
}

fn unknown_phase_key_in(
    cell: &'static std::sync::OnceLock<[u8; 64]>,
    len: usize,
    fill: impl FnOnce(&mut [u8; 64]) -> bool,
) -> Option<&'static [u8]> {
    let key = match cell.get() {
        Some(k) => k,
        None => {
            let mut k = [0; 64];
            if !fill(&mut k) {
                return None;
            }
            cell.get_or_init(|| k)
        }
    };
    Some(&key[..len.min(64)])
}

fn wanted(direction: u8) -> (bool, bool) {
    (direction != 1, direction != 0)
}

impl SessionCore {
    /// The first batch of `id`'s Hello: unacknowledged and unsent stream data, as STREAM
    /// frames without FIN, while no other outbound pipe is usable. New bytes count as sent
    /// here, against session credit and the retransmit budget, as the acceptor counts them;
    /// since the batch counts in no position, all it carries goes again as reinjected
    /// information and the receiver deduplicates. A new stream's ID is allocated here and
    /// not cancelled afterwards.
    fn first_batch(&mut self, id: u64, limit: usize) -> Vec<u8> {
        if limit == 0
            || self.other_usable(id)
            || self.atts.get(id).is_none_or(|a| a.out().is_none())
        {
            return Vec::new();
        }
        let keys: Vec<_> = self.streams.keys().collect();
        for &key in &keys {
            self.first_batch_open(key);
        }
        let now = self.now;
        let mut out = Vec::new();
        for key in keys {
            let left = limit.saturating_sub(out.len());
            if left == 0 {
                break;
            }
            let room = self.streams.send_flow().room().min(
                self.retransmit_budget()
                    .saturating_sub(self.mp().retained()),
            );
            let Some((stream, frame, new)) = self
                .streams
                .get(key)
                .and_then(|s| Some((s.id?, s.send.as_ref()?)))
                .and_then(|(id, send)| {
                    let (frame, new) = send.first_batch_frame(id, left, room)?;
                    Some((id, frame, new))
                })
            else {
                continue;
            };
            frame.write(stream, &mut out);
            if new > 0 {
                let (s, chunks) = self.streams.stream_and_chunks(key).expect("stream present");
                let (new, app) = s
                    .send
                    .as_mut()
                    .expect("sending part")
                    .batch_sent(new, chunks);
                self.streams.sent(new, app);
                self.mp_mut().retain(new);
                self.after_send_progress(key);
            }
            self.reinject_frame(
                SentFrame::Stream {
                    key,
                    off: frame.off,
                    len: frame.data.len() as u64,
                    fin: false,
                },
                now,
            );
        }
        out
    }

    /// A stream with data that has no identifier takes one when nothing else holds it back,
    /// as its first frame would.
    fn first_batch_open(&mut self, key: crate::proto::session::StreamKey) {
        let Some(s) = self.streams.get(key) else {
            return;
        };
        if s.id.is_some()
            || s.goaway.is_some()
            || s.send.as_ref().is_none_or(|send| send.buf.is_empty())
        {
            return;
        }
        let d = super::di(s.dir);
        let ld = self.streams.local_dir(d);
        if ld.goaway.is_some()
            || !self.streams.pinned(d).is_empty()
            || ld.next_index >= ld.peer_max
            || self.preamble_len(key) as u64 > self.preamble_limit()
        {
            return;
        }
        self.assign_id(key);
    }

    fn is_initiator(&self) -> bool {
        self.role == crate::proto::params::Role::Client
    }

    fn batch_stream(
        &mut self,
        frame: crate::proto::frame::Stream<'_>,
        now: Instant,
    ) -> Result<(), Error> {
        let ty = Frame::Stream(frame).frame_type().0;
        self.on_stream(frame, ty, now)
    }

    /// The carrier of a JOINING attachment failed.
    pub fn join_carrier_failed(&mut self, pipe: PipeId, kind: std::io::ErrorKind, now: Instant) {
        self.tick(now);
        self.fail_attachment(pipe.0, PipeFailure::Carrier(kind), now);
        self.after_pipe_change(now);
    }

    /// The largest record plaintext of a pipe, local and applied beside the peer's
    /// `max_record_size`.
    pub fn set_pipe_max_record(&mut self, pipe: PipeId, max: usize) {
        if let Some(o) = self.out_mut(pipe.0) {
            o.set_max_record(max);
        }
    }

    /// Whether the attachment reads and writes.
    pub fn pipe_directions(&self, pipe: PipeId) -> (bool, bool) {
        self.att(pipe.0)
            .map_or((false, false), |a| (a.inp().is_some(), a.out().is_some()))
    }
}

#[cfg(test)]
mod tests {
    use super::unknown_phase_key_in;
    use std::sync::OnceLock;

    #[test]
    fn unknown_phase_key_never_falls_back_to_a_constant() {
        static CELL: OnceLock<[u8; 64]> = OnceLock::new();
        // A failing random source yields no key and caches nothing.
        assert!(unknown_phase_key_in(&CELL, 32, |_| false).is_none());
        assert!(CELL.get().is_none());
        // The next Hello draws again; the drawn key is then kept.
        let k = unknown_phase_key_in(&CELL, 32, |k| {
            k.fill(7);
            true
        })
        .unwrap();
        assert_eq!(k, &[7; 32][..]);
        let again = unknown_phase_key_in(&CELL, 48, |_| false).unwrap();
        assert_eq!(again, &[7; 48][..]);
    }
}
