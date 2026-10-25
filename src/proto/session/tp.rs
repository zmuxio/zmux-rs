//! The transport parameter values a session keeps: what it uses after the
//! handshake, of either endpoint's parameters, instead of the whole
//! [`TransportParameters`].
//!
//! The peer's are kept as [`TpValues`]; the local ones are those of the
//! shared configuration ([`TpValues::local`]), so a session keeps only what
//! is its own ([`LocalTp`]: its nonces, Lane Key and locator).

use super::Config;
use crate::proto::params::{
    DEFAULT_ACK_THRESHOLD, DEFAULT_MAX_ACK_DELAY_MS, MultipathParameter, RoleParameter,
    TransportParameters, ZMUX_MAX_RECORD_SIZE,
};

/// Saturated at `u32::MAX`: sizes and counts whose larger values change
/// nothing for this endpoint (a record, a preamble, an acknowledgement
/// threshold or a lane count beyond 4 Gi).
fn narrow(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// One endpoint's transport parameter values in use after the handshake,
/// absent ones resolved to their defaults (0: absent, where 0 is not a
/// valid value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TpValues {
    /// initial_max_stream_data_bidi_local.
    pub(super) window_bidi_local: u64,
    /// initial_max_stream_data_bidi_remote.
    pub(super) window_bidi_remote: u64,
    /// initial_max_stream_data_uni.
    pub(super) window_uni: u64,
    /// initial_max_streams_bidi.
    pub(super) streams_bidi: u64,
    /// max_idle_timeout in milliseconds (0: none).
    pub(super) max_idle_timeout: u64,
    /// The nonce of `zmux_role` auto.
    pub(super) role_nonce: Option<u64>,
    /// zmux_multipath (the local one as the session sends it: its locator
    /// and Secret Flags may change before the parameters are sent).
    pub(super) multipath: Option<MultipathParameter>,
    /// The Lane Key of zmux_max_lanes.
    pub(super) lane_key: Option<[u8; 16]>,
    max_record_size: u32,
    max_datagram_frame_size: u32,
    preamble: u32,
    ack_threshold: u32,
    max_lanes: u32,
    /// zmux_max_ack_delay in milliseconds (below 2^14).
    max_ack_delay: u16,
    /// reset_stream_at.
    pub(super) reset_stream_at: bool,
    /// zmux_pipe_ack.
    pub(super) pipe_ack: bool,
    /// None of the zmux parameters is present (SPEC.md Section 13.1).
    pub(super) plain_qmux: bool,
}

impl TpValues {
    pub(super) fn of(tp: &TransportParameters) -> Self {
        Self {
            window_bidi_local: tp.initial_max_stream_data_bidi_local.unwrap_or(0),
            window_bidi_remote: tp.initial_max_stream_data_bidi_remote.unwrap_or(0),
            window_uni: tp.initial_max_stream_data_uni.unwrap_or(0),
            streams_bidi: tp.initial_max_streams_bidi.unwrap_or(0),
            max_idle_timeout: tp.max_idle_timeout.unwrap_or(0),
            role_nonce: match tp.zmux_role {
                Some(RoleParameter::Auto { nonce }) => Some(nonce),
                _ => None,
            },
            multipath: tp.zmux_multipath,
            lane_key: tp.zmux_max_lanes.map(|l| l.lane_key),
            max_record_size: narrow(tp.max_record_size_or_default()),
            max_datagram_frame_size: narrow(tp.max_datagram_frame_size.unwrap_or(0)),
            preamble: narrow(tp.zmux_preamble.unwrap_or(0)),
            ack_threshold: narrow(tp.ack_threshold_or_default()),
            max_lanes: narrow(tp.max_lanes_or_default()),
            max_ack_delay: u16::try_from(tp.max_ack_delay_or_default()).unwrap_or(u16::MAX),
            reset_stream_at: tp.reset_stream_at,
            pipe_ack: tp.zmux_pipe_ack,
            plain_qmux: tp.is_plain_qmux(),
        }
    }

    /// The local values: those `config` gives every session
    /// ([`Config::transport_parameters`], whose test hook's parameters
    /// stand for all of them when set) with the session's own `own`.
    pub(super) fn local(config: &Config, own: &LocalTp) -> Self {
        if let Some(tp) = &config.hooks.transport_parameters {
            return Self::of(tp);
        }
        let window = config.initial_stream_receive_window;
        Self {
            window_bidi_local: window,
            window_bidi_remote: window,
            window_uni: window,
            streams_bidi: config.max_incoming_streams,
            max_idle_timeout: u64::try_from(config.max_idle_timeout.as_millis())
                .unwrap_or(u64::MAX),
            role_nonce: own.role_nonce,
            multipath: own.multipath,
            lane_key: Some(own.lane_key),
            max_record_size: narrow(ZMUX_MAX_RECORD_SIZE),
            max_datagram_frame_size: if config.enable_datagrams {
                narrow(ZMUX_MAX_RECORD_SIZE)
            } else {
                0
            },
            preamble: narrow(config.preamble_limit()),
            ack_threshold: narrow(DEFAULT_ACK_THRESHOLD),
            max_lanes: narrow(config.max_lanes.get()),
            max_ack_delay: u16::try_from(DEFAULT_MAX_ACK_DELAY_MS).unwrap_or(u16::MAX),
            reset_stream_at: true,
            pipe_ack: true,
            plain_qmux: false,
        }
    }

    /// max_record_size, or its default.
    pub(super) fn max_record_size(&self) -> u64 {
        u64::from(self.max_record_size)
    }

    /// max_datagram_frame_size (0: no datagrams).
    pub(super) fn max_datagram_frame_size(&self) -> u64 {
        u64::from(self.max_datagram_frame_size)
    }

    /// zmux_preamble (0 when absent).
    pub(super) fn preamble(&self) -> u64 {
        u64::from(self.preamble)
    }

    /// zmux_ack_threshold, or its default.
    pub(super) fn ack_threshold(&self) -> u64 {
        u64::from(self.ack_threshold)
    }

    /// zmux_max_ack_delay in milliseconds, or its default.
    pub(super) fn max_ack_delay(&self) -> u64 {
        u64::from(self.max_ack_delay)
    }

    /// Max Lanes L of zmux_max_lanes, 1 when absent.
    pub(super) fn max_lanes(&self) -> u64 {
        u64::from(self.max_lanes)
    }
}

/// What of the local transport parameters is the session's own: the rest
/// comes from the shared configuration ([`TpValues::local`]).
#[derive(Debug, Clone, Copy)]
pub(super) struct LocalTp {
    /// zmux_multipath as the session sends it (its locator and Secret
    /// Flags may change before the parameters are sent).
    pub(super) multipath: Option<MultipathParameter>,
    /// The nonce of `zmux_role` auto.
    pub(super) role_nonce: Option<u64>,
    /// The Lane Key of zmux_max_lanes.
    pub(super) lane_key: [u8; 16],
}

impl LocalTp {
    /// The session's own part of `tp`, the parameters it sends.
    pub(super) fn of(tp: &TransportParameters) -> Self {
        let v = TpValues::of(tp);
        Self {
            multipath: v.multipath,
            role_nonce: v.role_nonce,
            lane_key: v.lane_key.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values a session takes from the shared configuration are those
    /// of the parameters it sends.
    #[test]
    fn local_values_are_those_sent() {
        for (mp, datagrams, window) in [(false, false, 256 * 1024), (true, true, 1000)] {
            let mut c = Config::default();
            if mp {
                c.max_pipes = 4;
                c.pipe_auth = super::super::PipeAuth::psk([7; 32]);
            }
            c.enable_datagrams = datagrams;
            c.initial_stream_receive_window = window;
            let tp = c.transport_parameters(Some(5), [1; 16], [2; 16]);
            let own = LocalTp::of(&tp);
            assert_eq!(TpValues::local(&c, &own), TpValues::of(&tp));
        }
    }
}
