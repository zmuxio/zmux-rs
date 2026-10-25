//! Identification of a new carrier (SPEC.md Section 6.2, MULTIPATH.md
//! Section 5.5) and ALPN identifiers (SPEC.md Sections 6.2 and 13.3).
//!
//! Without TLS the first bytes identify the protocol: the first record of a
//! bootstrap pipe must have a Size from 9 to the receiver's own
//! `max_record_size` followed by the QX_TRANSPORT_PARAMETERS type
//! (`ff 51 53 30 0d 0a 0d 0a` in QMux-02). A listener that also accepts joins accepts the
//! PIPE_JOIN type `9a 24 de 36` after a Size from 26, and on a new stream of
//! a connection that already carries a pipe of the endpoint the PIPE_LANE
//! type `ba 05 a1 c9` after a Size from 22 (a lane, MULTIPATH.md Section
//! 5.8). The check runs byte by byte and rejects as soon as no valid first
//! record can begin with the bytes seen.

use super::draft::CURRENT;
use super::error::Error;

/// The encoded QX_TRANSPORT_PARAMETERS type that starts a session
/// ([`crate::proto::draft`]).
pub const SESSION_PREFIX: [u8; 8] = CURRENT.session_prefix();
/// The encoded PIPE_JOIN type that starts an in-band join.
pub const JOIN_PREFIX: [u8; 4] = [0x9a, 0x24, 0xde, 0x36];
/// The smallest Size of a first record that starts a session.
pub const MIN_SESSION_RECORD: u64 = 9;
/// The smallest Size of a first record that starts a join.
pub const MIN_JOIN_RECORD: u64 = 26;
/// The encoded PIPE_LANE type that starts a lane.
pub const LANE_PREFIX: [u8; 4] = [0xba, 0x05, 0xa1, 0xc9];
/// The smallest Size of a first record that starts a lane.
pub const MIN_LANE_RECORD: u64 = 22;

/// What a new carrier turned out to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirstRecord {
    /// A new session (QX_TRANSPORT_PARAMETERS first).
    Session,
    /// A pipe join (PIPE_JOIN first).
    Join,
    /// A lane of a pipe (PIPE_LANE first).
    Lane,
}

/// The state of the first-record check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Undecided; more bytes are needed.
    NeedMore,
    /// The prefix identifies a valid first record.
    Accept(FirstRecord),
    /// No valid first record starts with the bytes seen. `at` is the
    /// 1-based position of the byte that decided it.
    Reject {
        /// The deciding byte, counted from 1.
        at: u64,
    },
}

/// Incremental first-record check. It only looks at the bytes; the caller
/// still feeds them to the record parser once the carrier is accepted.
#[derive(Debug, Clone)]
pub struct Classifier {
    max_record_size: u64,
    sessions: bool,
    joins: bool,
    lanes: bool,
    seen: [u8; 16],
    have: usize,
    verdict: Verdict,
}

impl Classifier {
    /// A check for the given alternatives; `max_record_size` is the
    /// receiver's own limit.
    pub const fn new(max_record_size: u64, accept_sessions: bool, accept_joins: bool) -> Self {
        Self {
            max_record_size,
            sessions: accept_sessions,
            joins: accept_joins,
            lanes: false,
            seen: [0; 16],
            have: 0,
            verdict: Verdict::NeedMore,
        }
    }

    /// The check for a bootstrap pipe: only a new session is valid.
    pub const fn bootstrap(max_record_size: u64) -> Self {
        Self::new(max_record_size, true, false)
    }

    /// The check also accepts a lane: for a new stream of a connection
    /// that already carries a pipe of the endpoint (MULTIPATH.md Section
    /// 5.5).
    pub const fn with_lanes(mut self) -> Self {
        self.lanes = true;
        self
    }

    /// The current verdict.
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Feeds bytes; stops looking once the verdict is decided.
    pub fn push(&mut self, bytes: &[u8]) -> Verdict {
        for &b in bytes {
            if self.verdict != Verdict::NeedMore {
                break;
            }
            if let Some(slot) = self.seen.get_mut(self.have) {
                *slot = b;
                self.have += 1;
            }
            self.verdict = self.evaluate();
        }
        self.verdict
    }

    /// Checks the first message of a message-framed carrier: the message
    /// length stands for the Size (SPEC.md Section 3.4). `at` in a
    /// rejection counts the message bytes, 0 meaning the length itself.
    pub fn message(&mut self, message: &[u8]) -> Verdict {
        if self.verdict != Verdict::NeedMore || self.have != 0 {
            return self.verdict;
        }
        let mut size = [0u8; 8];
        let Ok(width) = super::varint::encode(message.len() as u64, &mut size) else {
            self.verdict = Verdict::Reject { at: 0 };
            return self.verdict;
        };
        self.push(&size[..width]);
        if let Verdict::Reject { .. } = self.verdict {
            self.verdict = Verdict::Reject { at: 0 };
            return self.verdict;
        }
        self.push(message);
        match self.verdict {
            Verdict::Reject { at } => {
                self.verdict = Verdict::Reject {
                    at: at - width as u64,
                };
            }
            // A complete message that is shorter than the prefix.
            Verdict::NeedMore => {
                self.verdict = Verdict::Reject {
                    at: message.len() as u64,
                }
            }
            Verdict::Accept(_) => {}
        }
        self.verdict
    }

    fn evaluate(&self) -> Verdict {
        let seen = &self.seen[..self.have];
        let Some((size, width)) = super::varint::decode(seen) else {
            return Verdict::NeedMore;
        };
        let rest = &seen[width..];
        let mut alive = false;
        let candidates = [
            (
                self.sessions,
                MIN_SESSION_RECORD,
                &SESSION_PREFIX[..],
                FirstRecord::Session,
            ),
            (
                self.joins,
                MIN_JOIN_RECORD,
                &JOIN_PREFIX[..],
                FirstRecord::Join,
            ),
            (
                self.lanes,
                MIN_LANE_RECORD,
                &LANE_PREFIX[..],
                FirstRecord::Lane,
            ),
        ];
        for (enabled, min, prefix, kind) in candidates {
            if !enabled || size < min || size > self.max_record_size {
                continue;
            }
            let n = rest.len().min(prefix.len());
            if rest[..n] != prefix[..n] {
                continue;
            }
            if rest.len() >= prefix.len() {
                return Verdict::Accept(kind);
            }
            alive = true;
        }
        if alive {
            Verdict::NeedMore
        } else {
            Verdict::Reject {
                at: self.have as u64,
            }
        }
    }

    /// The error a session closes with when the check fails: the endpoint
    /// sends its own parameters and then CONNECTION_CLOSE with it.
    pub const fn rejection_error() -> Error {
        Error::protocol_violation(0, "not a zmux or QMux peer")
    }
}

/// The default ALPN identifier (SPEC.md Section 6.2;
/// [`crate::proto::draft`]).
pub const DEFAULT_ALPN: &[u8] = CURRENT.alpn.as_bytes();

/// The draft's identifier and its alias, each with its `-NN` suffix:
/// `qmux-02`, `-02`, `qmux-01` and `-01` for QMux-02.
struct AliasRule {
    own: &'static [u8],
    own_suffix: &'static [u8],
    alias: &'static [u8],
    alias_suffix: &'static [u8],
}

fn alias_rule() -> Option<AliasRule> {
    let alias = CURRENT.alpn_alias?.as_bytes();
    let own = CURRENT.alpn.as_bytes();
    let suffix = |id: &'static [u8]| &id[id.iter().rposition(|&b| b == b'-').unwrap_or(0)..];
    Some(AliasRule {
        own,
        own_suffix: suffix(own),
        alias,
        alias_suffix: suffix(alias),
    })
}

/// The alias of a configured ALPN identifier (SPEC.md Section 6.2), for a
/// draft whose codepoints an earlier draft shares ([`crate::proto::draft::Draft::alpn_alias`]):
/// for QMux-02, `qmux-01` for `qmux-02`, `qmux-01.<application>` for
/// `qmux-02.<application>`, `<name>-01` for any other `<name>-02`, and no
/// alias otherwise. A client may offer the aliases after its configured
/// identifiers.
pub fn alpn_alias(configured: &[u8]) -> Option<Vec<u8>> {
    let AliasRule {
        own,
        own_suffix,
        alias,
        alias_suffix,
    } = alias_rule()?;
    if configured == own {
        return Some(alias.to_vec());
    }
    if let Some(app) = configured
        .strip_prefix(own)
        .and_then(|r| r.strip_prefix(b"."))
    {
        return Some([alias, b".", app].concat());
    }
    configured
        .strip_suffix(own_suffix)
        .map(|stem| [stem, alias_suffix].concat())
}

/// The ALPN identifiers to configure on a TLS client or server for
/// `applications` (SPEC.md Sections 6.2 and 13.3): `qmux-02` without
/// applications, `qmux-02.<application>` for each, followed by their
/// draft-01 aliases (`qmux-01`, `qmux-01.<application>`), which a server
/// accepts and a client may offer last.
///
/// ```
/// assert_eq!(zmux::alpn_protocols(&[]), [b"qmux-02".to_vec(), b"qmux-01".to_vec()]);
/// assert_eq!(
///     zmux::alpn_protocols(&["chat"]),
///     [b"qmux-02.chat".to_vec(), b"qmux-01.chat".to_vec()]
/// );
/// ```
pub fn alpn_protocols(applications: &[&str]) -> Vec<Vec<u8>> {
    let configured: Vec<Vec<u8>> = if applications.is_empty() {
        vec![DEFAULT_ALPN.to_vec()]
    } else {
        applications
            .iter()
            .map(|a| [DEFAULT_ALPN, b".", a.as_bytes()].concat())
            .collect()
    };
    let aliases: Vec<Vec<u8>> = configured.iter().filter_map(|c| alpn_alias(c)).collect();
    configured.into_iter().chain(aliases).collect()
}

/// Whether a protocol identifier offered by the peer matches a configured
/// one: the same identifier or its draft-01 alias ([`alpn_alias`]),
/// compared byte for byte.
pub fn alpn_matches(configured: &[u8], offered: &[u8]) -> bool {
    if configured == offered {
        return true;
    }
    let Some(AliasRule {
        own,
        own_suffix,
        alias,
        alias_suffix,
    }) = alias_rule()
    else {
        return false;
    };
    if configured == own {
        return offered == alias;
    }
    if let Some(app) = configured
        .strip_prefix(own)
        .and_then(|r| r.strip_prefix(b"."))
    {
        return offered
            .strip_prefix(alias)
            .and_then(|r| r.strip_prefix(b"."))
            == Some(app);
    }
    match (
        configured.strip_suffix(own_suffix),
        offered.strip_suffix(alias_suffix),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Server-side ALPN selection: the first identifier in the client's offer
/// that matches a configured one, in the client's order of preference.
pub fn select_alpn<'a, C, O>(configured: C, offered: O) -> Option<&'a [u8]>
where
    C: IntoIterator<Item = &'a [u8]> + Clone,
    O: IntoIterator<Item = &'a [u8]>,
{
    offered
        .into_iter()
        .find(|o| configured.clone().into_iter().any(|c| alpn_matches(c, o)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reject_at(bytes: &[u8]) -> Verdict {
        Classifier::bootstrap(65_535).push(bytes)
    }

    #[test]
    fn foreign_prefixes() {
        // WIRE_EXAMPLES.md Section 7.
        assert_eq!(
            reject_at(&[0x5a, 0x4d, 0x55, 0x58, 0x01]),
            Verdict::Reject { at: 3 }
        );
        assert_eq!(reject_at(b"GET / "), Verdict::Reject { at: 3 });
        assert_eq!(reject_at(b"PRI * "), Verdict::Reject { at: 3 });
        assert_eq!(reject_at(&[0x16, 0x03, 0x01]), Verdict::Reject { at: 2 });
        assert_eq!(reject_at(b"SSH-2."), Verdict::Reject { at: 3 });
        assert_eq!(reject_at(&[0x08]), Verdict::Reject { at: 1 });
    }

    #[test]
    fn accepts_sessions_and_joins() {
        let tp = [0x0d, 0xff, 0x51, 0x53, 0x30, 0x0d, 0x0a, 0x0d, 0x0a];
        let mut c = Classifier::bootstrap(65_535);
        for (i, b) in tp.iter().enumerate() {
            let v = c.push(&[*b]);
            if i + 1 < tp.len() {
                assert_eq!(v, Verdict::NeedMore);
            }
        }
        assert_eq!(c.verdict(), Verdict::Accept(FirstRecord::Session));
        let join = [0x26, 0x9a, 0x24, 0xde, 0x36];
        assert_eq!(
            Classifier::new(65_535, true, true).push(&join),
            Verdict::Accept(FirstRecord::Join)
        );
        assert_eq!(
            Classifier::bootstrap(65_535).push(&join),
            Verdict::Reject { at: 2 }
        );
        // A Size of 24 cannot start a join.
        assert_eq!(
            Classifier::new(65_535, false, true).push(&[0x18]),
            Verdict::Reject { at: 1 }
        );
    }

    #[test]
    fn first_message() {
        let tp = [0xff, 0x51, 0x53, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x00];
        assert_eq!(
            Classifier::bootstrap(65_535).message(&tp),
            Verdict::Accept(FirstRecord::Session)
        );
        assert_eq!(
            Classifier::bootstrap(65_535).message(&tp[..8]),
            Verdict::Reject { at: 0 }
        );
        let mut bad = tp;
        bad[3] = 0;
        assert_eq!(
            Classifier::bootstrap(65_535).message(&bad),
            Verdict::Reject { at: 4 }
        );
    }

    #[test]
    fn alpn() {
        assert!(alpn_matches(b"qmux-02", b"qmux-02"));
        assert!(alpn_matches(b"qmux-02", b"qmux-01"));
        assert!(alpn_matches(b"h3qx-02", b"h3qx-01"));
        assert!(!alpn_matches(b"qmux-02", b"qmux-03"));
        assert!(!alpn_matches(b"qmux-01", b"qmux-02"));
        assert!(alpn_matches(b"qmux-02.app", b"qmux-01.app"));
        assert!(!alpn_matches(b"qmux-02.app", b"qmux-01.ap"));
        assert!(!alpn_matches(b"qmux-021", b"qmux-011"));
        // Only the `qmux-02.` prefix carries an application part.
        assert!(!alpn_matches(b"foo-02.app", b"foo-01.app"));
        assert!(alpn_matches(b"qmux-02.x-02", b"qmux-01.x-02"));
        assert!(!alpn_matches(b"qmux-02.x-02", b"qmux-02.x-01"));
        assert_eq!(alpn_alias(b"myapp"), None);
        assert_eq!(alpn_alias(b"qmux-02.chat"), Some(b"qmux-01.chat".to_vec()));
        let configured: [&[u8]; 1] = [b"qmux-02"];
        let offered: [&[u8]; 2] = [b"h2", b"qmux-01"];
        assert_eq!(select_alpn(configured, offered), Some(&b"qmux-01"[..]));
    }
}
