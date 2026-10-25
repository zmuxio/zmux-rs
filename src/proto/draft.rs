//! The values that depend on the QMux draft version (SPEC.md Section
//! 13.5): one set per draft, and the one this crate speaks
//! ([`CURRENT`]). Every QMux-specific codepoint, the first-record check,
//! the ALPN identifiers and their alias rule take their values from here,
//! so that moving to another draft is a change of this module alone.

/// The values of one QMux draft version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Draft {
    /// The draft number (`2` for draft-ietf-quic-qmux-02).
    pub number: u8,
    /// The QX_TRANSPORT_PARAMETERS frame type, which also starts every
    /// bootstrap pipe (the first-record check).
    pub transport_parameters: u64,
    /// The QX_PING request frame type.
    pub ping_request: u64,
    /// The QX_PING response frame type.
    pub ping_response: u64,
    /// The max_record_size transport parameter id.
    pub max_record_size: u64,
    /// The ALPN identifier without an application.
    pub alpn: &'static str,
    /// The identifier of an earlier draft with the same codepoints, which
    /// is accepted as an alias of [`Draft::alpn`] (SPEC.md Section 6.2),
    /// with its application part (`<alias>.<application>`) and its
    /// `<name>-NN` form for other names.
    pub alpn_alias: Option<&'static str>,
}

/// draft-ietf-quic-qmux-02, whose codepoints are draft-01's: `qmux-01` is
/// its alias.
pub const QMUX_02: Draft = Draft {
    number: 2,
    transport_parameters: 0x3f51_5330_0d0a_0d0a,
    ping_request: 0x348c_6752_9ef8_c7bd,
    ping_response: 0x348c_6752_9ef8_c7be,
    max_record_size: 0x0571_c594_29cd_0845,
    alpn: "qmux-02",
    alpn_alias: Some("qmux-01"),
};

/// The draft this crate speaks.
pub const CURRENT: Draft = QMUX_02;

impl Draft {
    /// The encoded QX_TRANSPORT_PARAMETERS type: the eight bytes that
    /// start a session (an eight-byte variable-length integer).
    pub const fn session_prefix(&self) -> [u8; 8] {
        (self.transport_parameters | 0xc000_0000_0000_0000).to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prefix_is_the_encoded_type() {
        assert_eq!(
            QMUX_02.session_prefix(),
            [0xff, 0x51, 0x53, 0x30, 0x0d, 0x0a, 0x0d, 0x0a]
        );
    }
}
