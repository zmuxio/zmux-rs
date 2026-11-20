//! The acceptor's side of a join, from a classified Hello to the attached
//! pipe, as one step machine both listeners drive: it decides every
//! outcome, its classification and the one deadline (the joined session's
//! join timeout); a listener only does what a step asks (wait, write, read)
//! within that deadline and reports back. What only one driver has (carrier
//! early data, carriers that loop over a session, memory pressure) enters
//! as facts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::handle::{self, Driver, Shared};
use crate::proto::admission::AdmittedValue;
use crate::proto::listener::HandleError;
use crate::proto::record::Framing;
use crate::proto::seal::RecordMode;
use crate::proto::seal::join::JoinHello;
use crate::proto::session::{
    ClaimedHello, ConfirmedJoin, JoinRecords, OpenedHello, PeerCarrier, PeerJoin, PipeId,
    RecordPolicyInput,
};

/// What the acceptor knows of the carrier a Hello arrived on.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts of the carrier, not one state"
)]
pub(crate) struct JoinCarrier {
    pub(crate) framing: Framing,
    /// Its Binding when it declares the Bound contract, is not split and
    /// has an exporter.
    pub(crate) binding: Option<Vec<u8>>,
    pub(crate) has_exporter: bool,
    pub(crate) secure: bool,
    pub(crate) admitted: Option<AdmittedValue>,
    pub(crate) inbound: bool,
    pub(crate) outbound: bool,
    pub(crate) looped: bool,
    pub(crate) overhead: u16,
    pub(crate) max_record: Option<usize>,
    pub(crate) kind: Option<crate::CarrierKind>,
    pub(crate) reports_failure: bool,
}

/// What the listener does next.
pub(crate) enum AcceptStep {
    /// Refused before authentication: the reject policy (stall or close)
    /// for `reason`; counted as rejected.
    Reject(&'static str, Option<RecordMode>),
    /// Ended with this outcome; the carrier is closed.
    End(HandleError),
    /// Wait until the session can take the join (`handle::join_keys_wait`)
    /// within the deadline, then [`JoinAccept::keys_ready`].
    WaitKeys,
    /// Settle the session's checks within the deadline, then
    /// [`JoinAccept::allowed`].
    Ask(crate::Decision<bool>),
    /// Wait `0` (the Reply's plan), within the deadline and while the
    /// session lives, then [`JoinAccept::delayed`].
    Delay(Duration),
    /// Write the refusing Reply, end the writing half gracefully within the
    /// deadline, then end as refused.
    Refuse(Vec<u8>),
    /// Write the Reply, then read units into [`JoinAccept::confirm`] until
    /// it is whole, within the deadline.
    Reply(Vec<u8>),
}

/// A confirmed join's pipe.
pub(crate) struct Attached {
    pub(crate) pipe: PipeId,
    pub(crate) records: JoinRecords,
    pub(crate) want_in: bool,
    pub(crate) want_out: bool,
}

/// The acceptor's steps of one join.
pub(crate) struct JoinAccept<D: Driver> {
    session: Option<Arc<Shared<D>>>,
    hello: Vec<u8>,
    carrier: JoinCarrier,
    deadline: Option<Instant>,
    mode: Option<RecordMode>,
    join: Option<Box<PeerJoin>>,
    peer: Option<PeerCarrier>,
    plan: Option<crate::shaping::UnitPlan>,
}

impl<D: Driver> JoinAccept<D> {
    /// The join of `hello` to `session` (none: an unknown Locator), bounded
    /// by the session's join timeout from now, or `listener_join_timeout`
    /// for an unknown Locator.
    pub(crate) fn new(
        session: Option<Arc<Shared<D>>>,
        listener_join_timeout: Duration,
        hello: &[u8],
        carrier: JoinCarrier,
    ) -> Self {
        let timeout = session.as_ref().map_or(listener_join_timeout, |s| {
            s.lock().core.config().join_timeout
        });
        Self {
            session,
            hello: hello.to_vec(),
            carrier,
            deadline: D::now().checked_add(timeout),
            mode: None,
            join: None,
            peer: None,
            plan: None,
        }
    }

    /// The one deadline of every step.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The session joined, once the Hello named one.
    pub(crate) fn session(&self) -> Option<&Arc<Shared<D>>> {
        self.session.as_ref()
    }

    /// The Hello's record mode, without opening it.
    #[cfg(feature = "tokio")]
    pub(crate) fn parse_mode(framing: Framing, hello: &[u8]) -> Option<RecordMode> {
        JoinHello::parse(framing, hello).ok().map(|h| h.mode())
    }

    /// The first step: the Hello parsed and opened. `pressure`: the
    /// listener is over its memory budget, which only joins that let a
    /// suspended session resume pass.
    pub(crate) fn start(&mut self, pressure: bool) -> AcceptStep {
        let Ok(parsed) = JoinHello::parse(self.carrier.framing, &self.hello) else {
            return AcceptStep::Reject("malformed", None);
        };
        self.mode = Some(parsed.mode());
        let Some(session) = self.session.clone() else {
            return AcceptStep::Reject("unknown_locator", self.mode);
        };
        if parsed.mode() == RecordMode::Bound && self.carrier.binding.is_none() {
            session.hello_without_binding();
            return AcceptStep::Reject("auth", self.mode);
        }
        self.open(pressure)
    }

    /// After [`AcceptStep::WaitKeys`]: whether the session became ready.
    pub(crate) fn keys_ready(&mut self, ready: bool, pressure: bool) -> AcceptStep {
        if ready {
            self.open(pressure)
        } else {
            AcceptStep::End(HandleError::Refused)
        }
    }

    fn open(&mut self, pressure: bool) -> AcceptStep {
        let session = self.session.clone().expect("named");
        let Ok(parsed) = JoinHello::parse(self.carrier.framing, &self.hello) else {
            return AcceptStep::Reject("malformed", None);
        };
        let binding = self.carrier.binding.as_deref().unwrap_or_default();
        let binding = if parsed.mode() == RecordMode::Bound {
            binding
        } else {
            &[]
        };
        let Some(opened) = session.open_hello(&parsed, binding, |suspended| suspended || !pressure)
        else {
            return AcceptStep::Reject("memory_pressure", self.mode);
        };
        match opened {
            OpenedHello::Verified(join) => {
                let info = RecordPolicyInput {
                    has_exporter: self.carrier.has_exporter,
                    secure: self.carrier.secure,
                    ..RecordPolicyInput::default()
                };
                let ask = session.join_allowed(&info, &join, self.carrier.admitted.as_ref());
                self.join = Some(join);
                AcceptStep::Ask(ask)
            }
            OpenedHello::AuthFailed => AcceptStep::Reject("auth", self.mode),
            OpenedHello::UnknownSuite => AcceptStep::Reject("unknown_suite", self.mode),
            OpenedHello::UnknownLocator => AcceptStep::Reject("unknown_locator", self.mode),
            // Offered again only when the session is ready, so that each carrier
            // counts once in `join_pending`.
            OpenedHello::Hold | OpenedHello::KeyWait => AcceptStep::WaitKeys,
            OpenedHello::Close | OpenedHello::Fatal => AcceptStep::End(HandleError::Rejected),
        }
    }

    /// After [`AcceptStep::Ask`]: the checks' answer (a missed deadline or a
    /// panic is `false`).
    pub(crate) fn allowed(&mut self, allowed: bool) -> AcceptStep {
        // Step 7: a Mode or authorization that local policy refuses leaves the Pipe ID's
        // bit clear and is counted.
        if !allowed {
            return AcceptStep::End(HandleError::Rejected);
        }
        let (Some(session), Some(join)) = (&self.session, &self.join) else {
            return AcceptStep::End(HandleError::Rejected);
        };
        // A carrier limit the Sealed overhead takes below the record floor refuses the
        // join, as it does an added pipe.
        let c = &self.carrier;
        let limit = handle::pipe_record_limit(join.mode(), c.max_record, c.framing);
        if handle::check_pipe_record_limit(limit).is_err() {
            return AcceptStep::End(HandleError::Refused);
        }
        self.peer = Some(PeerCarrier {
            inbound: c.inbound.then_some(c.framing),
            outbound: c.outbound.then_some(c.framing),
            looped: c.looped,
            overhead: c.overhead,
            received: self.hello.len(),
        });
        let plan = session.join_plan(c.kind, "reply");
        if plan.delay.is_zero() {
            self.claim(&plan)
        } else {
            let delay = plan.delay;
            self.plan = Some(plan);
            AcceptStep::Delay(delay)
        }
    }

    /// After [`AcceptStep::Delay`]: whether the wait ended at its time (not by
    /// the session's end or the deadline).
    pub(crate) fn delayed(&mut self, waited: bool) -> AcceptStep {
        if !waited {
            return AcceptStep::End(HandleError::Refused);
        }
        let Some(plan) = self.plan.take() else {
            return AcceptStep::End(HandleError::Rejected);
        };
        self.claim(&plan)
    }

    fn claim(&mut self, plan: &crate::shaping::UnitPlan) -> AcceptStep {
        let (Some(session), Some(join), Some(peer)) =
            (&self.session, self.join.as_mut(), self.peer)
        else {
            return AcceptStep::End(HandleError::Rejected);
        };
        match session.claim_hello(join, peer, plan) {
            ClaimedHello::Accept(reply) => AcceptStep::Reply(reply),
            // The Reply ends with a graceful end of the writing half: closing the half
            // abruptly could discard it on the way, and the joiner would not see the
            // refusal.
            ClaimedHello::Refuse(reply) => AcceptStep::Refuse(reply),
            ClaimedHello::Close => AcceptStep::End(HandleError::Rejected),
        }
    }

    /// After [`AcceptStep::Reply`]: the units read so far (the listener
    /// appends each unit it reads). `Ok(true)` once Confirmed is whole: the
    /// bytes after it, the pipe's first records, are left in `input`;
    /// `Ok(false)` for another unit; `Err` for a bad one (rejected).
    pub(crate) fn confirm(&mut self, input: &mut Vec<u8>) -> Result<bool, ()> {
        match self.join.as_mut().ok_or(())?.read_confirm(input) {
            Ok(Some(n)) => {
                input.drain(..n);
                Ok(true)
            }
            Ok(None) => {
                // A message carrier's next unit is read on its own.
                if self.carrier.framing == Framing::Records {
                    input.clear();
                }
                Ok(false)
            }
            Err(_) => Err(()),
        }
    }

    /// The join confirmed: the pipe attached, or the outcome.
    pub(crate) fn attach(&mut self) -> Result<Attached, HandleError> {
        let (Some(session), Some(join), Some(peer)) = (&self.session, self.join.take(), self.peer)
        else {
            return Err(HandleError::Rejected);
        };
        let (want_in, want_out) = (join.pipe().direction != 1, join.pipe().direction != 0);
        let c = &self.carrier;
        let meta = (c.kind, c.overhead, c.admitted.clone(), c.reports_failure);
        match session.confirm_join(*join, peer, meta) {
            ConfirmedJoin::Attached { pipe, records } => Ok(Attached {
                pipe,
                records,
                want_in,
                want_out,
            }),
            // Nothing the peer did: no authentication failure.
            ConfirmedJoin::Refused | ConfirmedJoin::Close => Err(HandleError::Refused),
        }
    }
}

/// What a joiner does next.
pub(crate) enum DialStep {
    /// The cap or the refusal backoff holds the join: wait for
    /// `handle::join_released_wait`, then [`JoinDial::released`].
    Hold,
    /// Wait the plan's delay (ended early by the join's failure), then
    /// [`JoinDial::delayed`].
    Delay(Duration),
    /// Write this unit in one write (nothing for an empty one), then
    /// [`JoinDial::written`].
    Write(Vec<u8>),
    /// Read until the input holds at least this many bytes (a message
    /// carrier: one more unit), then [`JoinDial::input`].
    Read(usize),
    /// The join is done with: nothing to report.
    End,
    /// Confirmed: the records follow `consumed` bytes of the input, in
    /// Sealed with these directions. Then [`JoinDial::limits`], and
    /// [`JoinDial::attached`] once the pipe's carrier runs.
    Attach {
        consumed: usize,
        records: JoinRecords,
    },
}

enum Dialing {
    Prepare,
    /// The Hello's plan, waited out.
    Hello(crate::shaping::UnitPlan),
    /// The Hello is out: the Reply is read.
    Reply,
    /// The Reply verified; the Confirm's plan, waited out.
    Confirm(usize, crate::shaping::UnitPlan),
    /// The Confirm is out.
    Confirmed(usize, JoinRecords),
    /// Confirmed; the pipe's carrier does not run yet.
    Attaching,
    Done,
}

/// The joiner's steps of one join: both drivers' carriers of a pipe they
/// add run it, and only perform its steps; it maps their reads' and writes'
/// outcomes and applies the carrier's limits, so that the drivers do not
/// decide them differently. Dropped before the join ended (its driver's
/// future dropped), it fails the join at once, rather than leaving it to
/// the handshake timeout.
pub(crate) struct JoinDial<D: Driver> {
    shared: Arc<Shared<D>>,
    id: PipeId,
    framing: Framing,
    kind: Option<crate::CarrierKind>,
    overhead: u16,
    state: Dialing,
    /// The std driver ends the unused directions without waiting.
    #[cfg(feature = "tokio")]
    deadline: Option<Instant>,
}

impl<D: Driver> JoinDial<D> {
    pub(crate) fn new(
        shared: Arc<Shared<D>>,
        id: PipeId,
        framing: Framing,
        kind: Option<crate::CarrierKind>,
        overhead: u16,
    ) -> Self {
        #[cfg(feature = "tokio")]
        let deadline = D::now().checked_add(shared.lock().core.config().join_timeout);
        Self {
            shared,
            id,
            framing,
            kind,
            overhead,
            state: Dialing::Prepare,
            #[cfg(feature = "tokio")]
            deadline,
        }
    }

    /// The bound of the steps after the handshake (the session's join
    /// timeout from the start), which the core's own timer does not cover.
    #[cfg(feature = "tokio")]
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The first step.
    pub(crate) fn start(&mut self) -> DialStep {
        let r = {
            let mut st = self.shared.lock();
            let r = st.core.join_prepare(self.id, D::now());
            st.after_command();
            r
        };
        match r {
            Ok(Some(message)) => {
                let plan = self.shared.join_plan(self.kind, message);
                if plan.delay.is_zero() {
                    self.hello(&plan)
                } else {
                    let delay = plan.delay;
                    self.state = Dialing::Hello(plan);
                    DialStep::Delay(delay)
                }
            }
            Ok(None) => DialStep::Hold,
            Err(_) => self.end(),
        }
    }

    /// After [`DialStep::Hold`].
    pub(crate) fn released(&mut self) -> DialStep {
        self.start()
    }

    /// After [`DialStep::Delay`]: `false` when the join failed meanwhile.
    pub(crate) fn delayed(&mut self, waited: bool) -> DialStep {
        if !waited {
            return self.end();
        }
        match std::mem::replace(&mut self.state, Dialing::Done) {
            Dialing::Hello(plan) => self.hello(&plan),
            Dialing::Confirm(consumed, plan) => self.confirm(consumed, &plan),
            _ => self.end(),
        }
    }

    fn hello(&mut self, plan: &crate::shaping::UnitPlan) -> DialStep {
        let hello = {
            let mut st = self.shared.lock();
            let r = st
                .core
                .join_hello(self.id, (self.framing, self.overhead), plan, D::now());
            st.after_command();
            r
        };
        match hello {
            Ok(hello) => {
                self.state = Dialing::Reply;
                DialStep::Write(hello)
            }
            Err(_) => self.end(),
        }
    }

    /// After [`DialStep::Write`]: the write's outcome (a failed one fails
    /// the join with its error kind).
    pub(crate) fn written(&mut self, wrote: std::io::Result<()>) -> DialStep {
        if let Err(e) = wrote {
            self.failed(e.kind());
            return DialStep::End;
        }
        match std::mem::replace(&mut self.state, Dialing::Done) {
            Dialing::Reply => {
                self.state = Dialing::Reply;
                DialStep::Read(1)
            }
            Dialing::Confirmed(consumed, records) => {
                self.state = Dialing::Attaching;
                DialStep::Attach { consumed, records }
            }
            _ => self.end(),
        }
    }

    /// One read of a [`DialStep::Read`]: its outcome, and the input's
    /// length with what it read. `true` to go on reading (an interrupted
    /// read is retried); `false` once the join failed: the carrier ended
    /// (`UnexpectedEof`), its error's kind, or more input than a join
    /// reads before the Reply verifies ([`JOIN_READ_BOUND`], `InvalidData`).
    /// A driver that reads into a separate buffer checks before appending.
    ///
    /// [`JOIN_READ_BOUND`]: crate::proto::session::JOIN_READ_BOUND
    pub(crate) fn read(&mut self, r: std::io::Result<usize>, total: usize) -> bool {
        let kind = match r {
            Ok(0) => std::io::ErrorKind::UnexpectedEof,
            Ok(_) if total > crate::proto::session::JOIN_READ_BOUND => {
                std::io::ErrorKind::InvalidData
            }
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return true,
            Err(e) => e.kind(),
        };
        self.failed(kind);
        false
    }

    /// After [`DialStep::Attach`]: the carrier's record limit and write
    /// overhead applied to the pipe, and the directions it uses; `None`
    /// when the limit does not fit (checked when the pipe was added, so
    /// only a carrier that changed): the join failed (`InvalidInput`).
    pub(crate) fn limits(
        &mut self,
        max_record: Option<usize>,
        overhead: u16,
    ) -> Option<(bool, bool)> {
        let directions = {
            let mut st = self.shared.lock();
            let fit = max_record.is_none_or(|m| st.core.set_pipe_max_record(self.id, m).is_ok());
            st.core.set_pipe_write_overhead(self.id, overhead);
            fit.then(|| st.core.pipe_directions(self.id))
        };
        if directions.is_none() {
            self.failed(std::io::ErrorKind::InvalidInput);
        }
        directions
    }

    /// The pipe's carrier runs: the join is the pipe's now.
    pub(crate) fn attached(&mut self) {
        self.state = Dialing::Done;
    }

    /// After [`DialStep::Read`]: the bytes read so far, which it trims.
    pub(crate) fn input(&mut self, input: &mut Vec<u8>) -> DialStep {
        use crate::proto::session::JoinStep;
        let verdict = {
            let mut st = self.shared.lock();
            let v = st.core.verify_reply(self.id, input, D::now());
            st.after_command();
            v
        };
        match verdict {
            JoinStep::More { consumed, need } => {
                input.drain(..consumed);
                if self.framing == Framing::Records {
                    input.clear();
                    DialStep::Read(1)
                } else {
                    DialStep::Read(need.max(input.len() + 1))
                }
            }
            JoinStep::Verified { consumed, mode } => {
                // Bound has no confirmation to plan.
                if mode == RecordMode::Bound {
                    return self.confirm(consumed, &crate::shaping::UnitPlan::default());
                }
                let plan = self.shared.join_plan(self.kind, "confirm");
                if plan.delay.is_zero() {
                    self.confirm(consumed, &plan)
                } else {
                    let delay = plan.delay;
                    self.state = Dialing::Confirm(consumed, plan);
                    DialStep::Delay(delay)
                }
            }
            JoinStep::Declined | JoinStep::Failed => self.end(),
        }
    }

    fn confirm(&mut self, consumed: usize, plan: &crate::shaping::UnitPlan) -> DialStep {
        let finished = {
            let mut st = self.shared.lock();
            let r = st.core.join_finish(self.id, plan, D::now());
            st.after_command();
            r
        };
        match finished {
            Ok(crate::proto::session::JoinFinished {
                confirm, records, ..
            }) => {
                self.state = Dialing::Confirmed(consumed, records);
                DialStep::Write(confirm)
            }
            Err(_) => self.end(),
        }
    }

    /// The carrier failed with `kind`: the join fails.
    pub(crate) fn failed(&mut self, kind: std::io::ErrorKind) {
        self.state = Dialing::Done;
        let mut st = self.shared.lock();
        st.core.join_carrier_failed(self.id, kind, D::now());
        st.after_command();
    }

    fn end(&mut self) -> DialStep {
        self.state = Dialing::Done;
        DialStep::End
    }
}

impl<D: Driver> Drop for JoinDial<D> {
    fn drop(&mut self) {
        if matches!(self.state, Dialing::Done) {
            return;
        }
        let mut st = self.shared.lock();
        // Not when the join already failed (its driver stopped for that).
        if !matches!(st.core.pipe_joined(self.id), Some(Err(_))) {
            st.core
                .join_carrier_failed(self.id, std::io::ErrorKind::BrokenPipe, D::now());
            st.after_command();
        }
    }
}
