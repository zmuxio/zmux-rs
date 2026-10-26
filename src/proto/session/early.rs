//! Early data under the zmux floor (SPEC.md Section 6.1.2): stream data an
//! initiator sends before it has processed the peer's parameters, when the
//! application declares the peer a zmux endpoint.
//!
//! The floor stands for the peer's parameters until they arrive: at most
//! four bidirectional streams, 4096 bytes each (preamble included) and
//! 16384 in all, preambles up to 1024 bytes, records up to 16382 bytes. A
//! PIPE_ACK with one entry at Position 0 (the fence) precedes the first
//! early STREAM frame, so that a peer without PIPE_ACK stops before it.
//! When the parameters arrive, the outcome rules decide: the peer could
//! not take it (`EarlyDataRejected`), it advertised less than the floor
//! (TRANSPORT_PARAMETER_ERROR), or the session goes on with the peer's
//! limits, which cover everything sent.

use bytes::Bytes;

use super::output::Records;
use super::stream::SendState;
use super::tp::TpValues;
use super::{CloseFrame, SessionCore, SessionError, State};
use crate::proto::error::{Error, TransportErrorCode};
use crate::proto::frame::{Frame, PipeAck, PipeAckEntry};
use crate::proto::params::{Features, Role, RoleParameter, TransportParameters, floor};

/// Early data of a session that may send it.
#[derive(Debug)]
pub(super) struct Early {
    /// The assumed set: the floor, or the remembered parameters.
    assumed: TpValues,
    /// The set and its limits, to judge the peer's parameters by.
    set: TransportParameters,
    /// Under remembered parameters, as carrier early data.
    remembered: bool,
    /// The fence goes before the first early STREAM frame: the assumed
    /// set has zmux parameters.
    fence: bool,
    /// Early STREAM data went out (behind the fence, when there is one).
    sent: bool,
}

/// A session's early data, allocated only when it has some.
#[derive(Debug, Default)]
pub(super) struct EarlyState {
    /// The assumed set, until the peer's parameters are processed.
    sending: Option<Early>,
    /// Carrier early data sent, until the carrier settles it.
    carrier: CarrierEarly,
    /// Inbound data is carrier early data: peer streams are replayable.
    carrier_in: bool,
    /// How often the bootstrap pipe started again after a rejection.
    starts: u32,
    /// The peer's parameters stored for a later carrier's early data.
    remember: Option<TransportParameters>,
    /// What became of the early data, as far as the peer's parameters
    /// tell (the carrier's verdict is applied on reading).
    outcome: EarlyDataState,
}

/// What became of a session's early data
/// ([`Session::early_data`](crate::Session#method.early_data)).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EarlyDataState {
    /// No early stream data went out: early data is not configured, or
    /// nothing was written before the peer's parameters arrived.
    #[default]
    NotSent,
    /// Early stream data went out and its outcome is not known yet: the
    /// peer's parameters have not arrived, or the carrier has not settled
    /// its own early data.
    Pending,
    /// The peer processed the early data.
    Accepted,
    /// The peer processed none of it. After a carrier's rejection (TLS 1.3
    /// early data, QUIC 0-RTT) the session wrote the data again once the
    /// handshake completed and the streams go on; after a zmux peer's
    /// rejection the session ended with
    /// [`SessionError::EarlyDataRejected`](crate::SessionError::EarlyDataRejected).
    Rejected,
}

/// Carrier early data a client sent, until the carrier tells whether it
/// was accepted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum CarrierEarly {
    /// None sent, or settled.
    #[default]
    Off,
    /// Sent: the bytes stay held until the carrier accepts them.
    Pending,
}

/// The parameters stored for 0-RTT (RFC 9000 Section 7.4.1; SPEC.md
/// Section 6.1.2): the flow-control limits, `max_record_size`,
/// `zmux_preamble`, `zmux_pipe_ack` and `reset_stream_at`.
fn stored(tp: &TransportParameters) -> TransportParameters {
    TransportParameters {
        initial_max_data: tp.initial_max_data,
        initial_max_stream_data_bidi_local: tp.initial_max_stream_data_bidi_local,
        initial_max_stream_data_bidi_remote: tp.initial_max_stream_data_bidi_remote,
        initial_max_stream_data_uni: tp.initial_max_stream_data_uni,
        initial_max_streams_bidi: tp.initial_max_streams_bidi,
        initial_max_streams_uni: tp.initial_max_streams_uni,
        max_record_size: tp.max_record_size,
        zmux_preamble: tp.zmux_preamble,
        zmux_pipe_ack: tp.zmux_pipe_ack,
        reset_stream_at: tp.reset_stream_at,
        ..TransportParameters::default()
    }
}

/// The floor as transport parameters.
fn floor_parameters() -> TransportParameters {
    TransportParameters {
        initial_max_data: Some(floor::MAX_DATA),
        initial_max_streams_bidi: Some(floor::MAX_STREAMS_BIDI),
        initial_max_stream_data_bidi_remote: Some(floor::MAX_STREAM_DATA),
        max_record_size: Some(floor::MAX_RECORD_SIZE),
        zmux_preamble: Some(floor::MAX_PREAMBLE),
        zmux_pipe_ack: true,
        reset_stream_at: true,
        ..TransportParameters::default()
    }
}

impl SessionCore {
    /// Prepares early data when the configuration declares the peer a
    /// zmux endpoint and the role does not depend on the peer (SPEC.md
    /// Section 6.1.2, Sending rule 1): it has a transport role and sends
    /// no `zmux_role` auto.
    pub(super) fn early_setup(&mut self, transport_role: Option<Role>) {
        let local = self.local_parameters();
        let independent = match (local.zmux_role, transport_role) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(RoleParameter::Initiator), Some(t)) => t == Role::Initiator,
            (Some(RoleParameter::Responder), Some(t)) => t == Role::Responder,
            (Some(RoleParameter::Auto { .. }), Some(_)) => false,
        };
        if !self.config.early_data.zmux_peer || !independent {
            return;
        }
        let floor = floor_parameters();
        self.streams
            .peer_limits(floor::MAX_DATA, [floor::MAX_STREAMS_BIDI, 0]);
        self.features = Features {
            preamble: local.zmux_preamble.is_some(),
            ..Features::default()
        };
        self.early_state().sending = Some(Early {
            assumed: TpValues::of(&floor),
            set: floor,
            remembered: false,
            fence: true,
            sent: false,
        });
    }

    /// Carrier early data (TLS 1.3 early data, QUIC 0-RTT on a resumed
    /// carrier): the first records go out under `remembered`, the server's
    /// parameters of the session that issued the ticket, instead of the
    /// floor. Call it before anything is written on the bootstrap pipe,
    /// with [`super::EarlyData::carrier_early_data`] set; then tell the
    /// outcome with [`SessionCore::carrier_early_data_settled`]. Returns
    /// whether the session sends carrier early data. Only the parameters
    /// QUIC stores for 0-RTT are used: the flow-control limits,
    /// `max_record_size`, `zmux_preamble`, `zmux_pipe_ack` and
    /// `reset_stream_at`.
    pub fn assume_remembered(&mut self, remembered: &TransportParameters) -> bool {
        if !self.config.early_data.carrier_early_data
            || self.config.offers_multipath()
            || self.state != State::Establishing
            || self.stats.bytes_sent > 0
        {
            return false;
        }
        let local = self.local_parameters();
        let independent = match (local.zmux_role, self.transport_role) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(RoleParameter::Initiator), Some(t)) => t == Role::Initiator,
            (Some(RoleParameter::Responder), Some(t)) => t == Role::Responder,
            (Some(RoleParameter::Auto { .. }), Some(_)) => false,
        };
        if !independent {
            return false;
        }
        let set = stored(remembered);
        let zmux = set.zmux_preamble.is_some() || set.zmux_pipe_ack;
        self.streams.peer_limits(
            set.initial_max_data.unwrap_or(0),
            [
                set.initial_max_streams_bidi.unwrap_or(0),
                set.initial_max_streams_uni.unwrap_or(0),
            ],
        );
        self.features = Features {
            preamble: local.zmux_preamble.is_some() && set.zmux_preamble.is_some(),
            ..Features::default()
        };
        self.early_state().sending = Some(Early {
            assumed: TpValues::of(&set),
            set,
            remembered: true,
            fence: zmux,
            sent: false,
        });
        self.early_state().carrier = CarrierEarly::Pending;
        true
    }

    /// The peer's parameters that a later carrier's early data may assume:
    /// the ones stored for 0-RTT, kept when carrier early data is on.
    pub fn parameters_to_remember(&self) -> Option<TransportParameters> {
        self.early.as_deref()?.remember.clone()
    }

    /// Keeps the stored part of the peer's parameters (on establishment).
    pub(super) fn keep_to_remember(&mut self, tp: &TransportParameters) {
        if self.config.early_data.carrier_early_data {
            self.early_state().remember = Some(stored(tp));
        }
    }

    /// Whether written stream bytes stay held: carrier early data that the
    /// carrier may still reject.
    pub(super) fn early_retains(&self) -> bool {
        self.early
            .as_deref()
            .is_some_and(|e| e.carrier == CarrierEarly::Pending)
    }

    /// The carrier settled its early data: `accepted`, or rejected (none
    /// of it reached the peer). After a rejection the session writes its
    /// parameters again as the first record of the bootstrap pipe, and the
    /// early streams' data again from offset 0 once the peer's parameters
    /// arrived; the streams do not fail (SPEC.md Section 6.1.2).
    pub fn carrier_early_data_settled(&mut self, accepted: bool, now: std::time::Instant) {
        if !self.early_retains() {
            return;
        }
        self.early_state().carrier = CarrierEarly::Off;
        let mp = self.mp.is_some();
        let _ = mp;
        if accepted {
            // The held bytes are not needed any more, and what was written
            // is final, as on any single pipe (SPEC.md Section 7.4).
            let keys: Vec<_> = self.streams.keys().collect();
            for k in keys {
                let mut finished = false;
                if let Some((s, chunks)) = self.streams.stream_and_chunks(k)
                    && let Some(send) = s.send.as_mut()
                {
                    let kept = send.buf.kept();
                    send.buf.release(kept, chunks);
                    match send.state {
                        SendState::DataSent => {
                            send.state = SendState::DataRecvd;
                            finished = true;
                        }
                        SendState::ResetSent if send.cold().reset.is_some_and(|r| r.written) => {
                            send.state = SendState::ResetRecvd;
                        }
                        _ => {}
                    }
                }
                if finished {
                    self.notify_writable(k);
                }
                self.try_discard(k);
            }
            return;
        }
        let st = self.early_state();
        if st.outcome != EarlyDataState::NotSent {
            st.outcome = EarlyDataState::Rejected;
        }
        st.sending = None;
        // Everything written was never sent.
        let mut rewound = 0;
        let keys: Vec<_> = self.streams.keys().collect();
        for k in keys {
            let Some(s) = self.streams.get_mut(k) else {
                continue;
            };
            if !s.local {
                continue;
            }
            let Some(send) = s.send.as_mut() else {
                continue;
            };
            rewound += send.offset.saturating_sub(send.base);
            send.buf.rewind();
            send.offset = 0;
            send.preamble_left = send.preamble.as_ref().map_or(0, Bytes::len);
            send.fin_sent = false;
            send.max_data = 0;
            send.blocked_at = None;
            send.blocked_reported = None;
            let reset = send.cold().reset.is_some();
            if reset {
                // The reset goes again, after the data below its Reliable
                // Size.
                if let Some(r) = send.cold_mut().reset.as_mut() {
                    r.written = false;
                }
                send.state = SendState::ResetSent;
            } else if send.state != SendState::Ready {
                send.state = SendState::Send;
            }
            if self.peer_tp.is_some() {
                // The peer's limits are known already.
                self.after_establish(k);
            } else {
                self.schedule(k);
            }
            if reset {
                self.streams.queue_ctrl(k);
            }
        }
        let flow = self.streams.send_flow_mut();
        // The application bytes are unsent again.
        flow.buffered += rewound;
        flow.used = 0;
        flow.blocked_reported = None;
        match &self.peer_tp {
            // No floor: the data waits for the peer's parameters.
            None => {
                self.streams.peer_limits(0, [0, 0]);
                self.features = Features::default();
            }
            Some(_) => self.wake_capacity_waiters(),
        }
        // The bootstrap pipe starts again with the parameters.
        self.early_state().starts += 1;
        let rtt = self.initial_rtt(0);
        if let Some(i) = self.att_index(0) {
            let framing = self.atts.at(i).out().map(|o| o.framing());
            if let Some(framing) = framing {
                let o =
                    super::pipes::OutPipe::new(framing, super::pipes::OutState::Active, rtt, now)
                        .with_parameters_first();
                self.atts.at_mut(i).replace_out(o);
            }
        }
        self.stats.bytes_sent = 0;
    }

    /// How often the bootstrap pipe started writing again from its first
    /// record after its carrier rejected early data: a driver moves the
    /// carrier to its new stream before the first batch of a new start.
    pub fn bootstrap_start(&self) -> u32 {
        self.early.as_deref().map_or(0, |e| e.starts)
    }

    /// Whether the configuration allows carrier early data.
    pub fn carrier_early_data_allowed(&self) -> bool {
        self.config.early_data.carrier_early_data
    }

    /// Server side: data arriving now is carrier early data (`true`) until
    /// the carrier's handshake completes (`false`). Peer streams are
    /// replayable meanwhile ([`SessionCore::is_replayable`]).
    pub fn set_carrier_early_data(&mut self, active: bool) {
        if active || self.early.is_some() {
            self.early_state().carrier_in = active;
        }
    }

    /// Whether `key`'s opening frame arrived as carrier early data and the
    /// carrier's handshake has not completed: an attacker may have
    /// replayed it, so the application should not act on it in a way that
    /// must not happen twice. Once the handshake completed, the data can
    /// no longer be a replay.
    pub fn is_replayable(&self, key: super::StreamKey) -> bool {
        self.early.as_deref().is_some_and(|e| e.carrier_in)
            && self.streams.get(key).is_some_and(|s| !s.local)
    }

    /// The early state, allocated on first use.
    fn early_state(&mut self) -> &mut EarlyState {
        self.early.get_or_insert_with(Box::default)
    }

    /// Whether early data may be sent now: before the peer's parameters,
    /// with early data configured (a driver's establishing call returns at
    /// once then).
    pub fn early_data_open(&self) -> bool {
        self.early_open()
    }

    /// What became of the early data: not sent, pending, accepted or
    /// rejected. Accepted is reported only once the carrier settled its own
    /// early data as well.
    pub fn early_data_state(&self) -> EarlyDataState {
        let Some(e) = self.early.as_deref() else {
            return EarlyDataState::NotSent;
        };
        match e.outcome {
            EarlyDataState::Accepted if e.carrier == CarrierEarly::Pending => {
                EarlyDataState::Pending
            }
            o => o,
        }
    }

    /// Whether early data may be sent now: before the peer's parameters.
    pub(super) fn early_open(&self) -> bool {
        self.early.as_deref().is_some_and(|e| e.sending.is_some())
            && self.state == State::Establishing
    }

    /// The parameters the send side works with: the peer's, or before them
    /// the floor that early data assumes.
    pub(super) fn send_tp(&self) -> Option<&TpValues> {
        self.peer_tp
            .as_ref()
            .or_else(|| Some(&self.early.as_deref()?.sending.as_ref()?.assumed))
    }

    /// Writes the fence before the first early STREAM frame (SPEC.md
    /// Section 6.1.2, Sending rule 3); `false` when it does not fit.
    pub(super) fn write_fence(&mut self, w: &mut Records<'_>) -> bool {
        let Some(es) = self.early.as_deref_mut() else {
            return true;
        };
        let Some(e) = es.sending.as_mut() else {
            return true;
        };
        if e.sent {
            return true;
        }
        if !e.fence {
            e.sent = true;
            es.outcome = EarlyDataState::Pending;
            return true;
        }
        let entry = [PipeAckEntry {
            pipe_id: 0,
            lane: 0,
            position: 0,
            ack_delay: 0,
        }];
        if !w.try_frame(&Frame::PipeAck(PipeAck::new(&entry))) {
            return false;
        }
        e.sent = true;
        es.outcome = EarlyDataState::Pending;
        true
    }

    /// The peer's parameters arrived after early data: the outcome rules
    /// (SPEC.md Section 6.1.2, Outcome). `Ok(false)` when the session
    /// closed with "early data rejected"; an error for parameters below
    /// the floor.
    pub(super) fn early_outcome(
        &mut self,
        tp: &TransportParameters,
        now: std::time::Instant,
    ) -> Result<bool, Error> {
        let Some(e) = self.early.as_deref_mut().and_then(|e| e.sending.take()) else {
            return Ok(true);
        };
        if !e.sent {
            return Ok(true);
        }
        let acks = self.features.pipe_ack || self.features.multipath;
        let no_streams = !e.remembered && tp.initial_max_streams_bidi.unwrap_or(0) == 0;
        if (e.fence && !acks) || no_streams {
            // The peer stopped at the fence or at the first early STREAM
            // frame: it processed none of the early data.
            self.early_state().outcome = EarlyDataState::Rejected;
            self.set_error(SessionError::EarlyDataRejected);
            self.enter_closing(
                Some(CloseFrame::Transport {
                    code: TransportErrorCode::NO_ERROR.0,
                    frame_type: 0,
                    reason: Bytes::new(),
                }),
                now,
            );
            return Ok(false);
        }
        // Below the assumed set: a limit reduced, a stored zmux parameter
        // smaller or gone (RFC 9000 Section 7.4.1).
        let a = &e.set;
        let less =
            |peer: Option<u64>, assumed: Option<u64>| peer.unwrap_or(0) < assumed.unwrap_or(0);
        let below = less(tp.initial_max_data, a.initial_max_data)
            || less(tp.initial_max_streams_bidi, a.initial_max_streams_bidi)
            || less(tp.initial_max_streams_uni, a.initial_max_streams_uni)
            || less(
                tp.initial_max_stream_data_bidi_remote,
                a.initial_max_stream_data_bidi_remote,
            )
            || less(
                tp.initial_max_stream_data_bidi_local,
                a.initial_max_stream_data_bidi_local,
            )
            || less(
                tp.initial_max_stream_data_uni,
                a.initial_max_stream_data_uni,
            )
            || less(tp.zmux_preamble, a.zmux_preamble)
            || tp.max_record_size_or_default() < a.max_record_size_or_default()
            || (a.zmux_pipe_ack && !tp.zmux_pipe_ack)
            || (a.reset_stream_at && !tp.reset_stream_at);
        if below {
            self.early_state().outcome = EarlyDataState::Rejected;
            return Err(Error::transport_parameter(
                "parameters below those early data assumed",
            ));
        }
        self.early_state().outcome = EarlyDataState::Accepted;
        Ok(true)
    }
}
