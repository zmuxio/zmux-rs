//! Duplicate sessions (EXTENSIONS.md Section 11): two
//! endpoints that dialed each other at about the same time keep the same
//! one of their two sessions, each deciding alone from values both have,
//! and drain the other.

use std::cmp::Ordering;
use std::fmt;

use crate::driver::handle::SessionApi;
use crate::driver::handle::{Driver, Session};
use crate::proto::VarInt;
use crate::proto::session::State;

/// Which value decided (EXTENSIONS.md Section 11, Survivor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DuplicateRule {
    /// The application identities of the dialers.
    Identity,
    /// The dialers' Session Nonces of `zmux_multipath`.
    SessionNonce,
    /// The dialers' `zmux_role` nonces.
    RoleNonce,
}

/// Why the rule did not apply; nothing was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DuplicateError {
    /// A session is not established, or already closing.
    NotEstablished,
    /// Which endpoint dialed a session is not known
    /// ([`Session::set_dialer`](crate::Session#method.set_dialer)).
    DialerUnknown,
    /// The same endpoint dialed both sessions: not a race; the dialer
    /// alone decides which to keep, and its peer leaves both to it.
    SameDialer,
    /// No value decides: no identities, and neither multipath nor `auto`
    /// roles on both sessions. The application decides.
    Undecided,
    /// The deciding values are equal: the endpoint reached itself.
    SelfConnection,
}

impl fmt::Display for DuplicateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotEstablished => "a session is not established",
            Self::DialerUnknown => "the dialer of a session is not known",
            Self::SameDialer => "both sessions have the same dialer",
            Self::Undecided => "no value decides between the sessions",
            Self::SelfConnection => "the endpoint reached itself",
        })
    }
}

impl std::error::Error for DuplicateError {}

/// The rule over either driver's sessions: the survivor, the loser, the
/// rule that decided and whether the rejoin was started.
pub(crate) fn resolve<D: Driver>(
    s1: &Session<D>,
    s2: &Session<D>,
    local_identity: Option<&[u8]>,
    peer_identity: Option<&[u8]>,
    rejoin: Option<&D::Dial>,
) -> Result<(Session<D>, Session<D>, DuplicateRule, bool), DuplicateError> {
    for s in [s1, s2] {
        if !matches!(
            s.state(),
            State::Active | State::Draining | State::Suspended
        ) {
            return Err(DuplicateError::NotEstablished);
        }
    }
    let (Some(d1), Some(d2)) = (s1.is_dialer(), s2.is_dialer()) else {
        return Err(DuplicateError::DialerUnknown);
    };
    if d1 == d2 {
        return Err(DuplicateError::SameDialer);
    }
    // Each session's value of its dialer: this endpoint's when it dialed
    // the session, the peer's otherwise.
    let (order, rule) = if let (Some(l), Some(p)) = (local_identity, peer_identity) {
        let pick = |d: bool| if d { l } else { p };
        (pick(d1).cmp(pick(d2)), DuplicateRule::Identity)
    } else if let (Some(n1), Some(n2)) = (s1.session_nonces(), s2.session_nonces()) {
        let pick = |d: bool, (l, p): ([u8; 16], [u8; 16])| if d { l } else { p };
        (pick(d1, n1).cmp(&pick(d2, n2)), DuplicateRule::SessionNonce)
    } else if let (Some(n1), Some(n2)) = (s1.role_nonces(), s2.role_nonces()) {
        let pick = |d: bool, (l, p): (u64, u64)| if d { l } else { p };
        (pick(d1, n1).cmp(&pick(d2, n2)), DuplicateRule::RoleNonce)
    } else {
        return Err(DuplicateError::Undecided);
    };
    let (survivor, loser, loser_dialed) = match order {
        Ordering::Less => (s1, s2, d2),
        Ordering::Greater => (s2, s1, d1),
        Ordering::Equal => return Err(DuplicateError::SelfConnection),
    };
    loser.begin_shutdown(VarInt::ZERO, b"");
    let rejoin_started = loser_dialed
        && survivor.is_multipath()
        && survivor.join_wanted()
        && rejoin.is_some_and(|dial| D::start_rejoin(survivor.downgrade(), dial.clone()));
    Ok((survivor.clone(), loser.clone(), rule, rejoin_started))
}

/// A driver's `DuplicateOptions`, `Resolved` and `resolve_duplicate`: `$d` the
/// driver, `$session` its session type,
/// `$dial` its dial function type.
macro_rules! duplicate_api {
    ($d:ty, $session:ty, $dial:ty) => {
        /// The options of [`resolve_duplicate`]: the
        /// application's identities of the two endpoints, the same byte
        /// strings at both ends, and how to rejoin the losing route.
        #[derive(Clone, Default)]
        #[non_exhaustive]
        #[must_use]
        pub struct DuplicateOptions {
            /// This endpoint's identity.
            pub local_identity: Option<Vec<u8>>,
            /// The peer's identity.
            pub peer_identity: Option<Vec<u8>>,
            /// `rejoin`: dials the route of the losing session again, so
            /// that the survivor keeps it as a pipe (EXTENSIONS.md Section
            /// 11, Keeping the route). A hint: see
            /// [`Resolved::rejoin_started`].
            pub rejoin: Option<$dial>,
        }

        impl DuplicateOptions {
            /// Options with the identities of this endpoint and of its peer.
            pub fn with_identities(local: impl Into<Vec<u8>>, peer: impl Into<Vec<u8>>) -> Self {
                Self {
                    local_identity: Some(local.into()),
                    peer_identity: Some(peer.into()),
                    rejoin: None,
                }
            }

            /// With `rejoin`: the dial function of the losing route.
            pub fn with_rejoin(mut self, dial: impl Into<$dial>) -> Self {
                self.rejoin = Some(dial.into());
                self
            }
        }

        impl ::std::fmt::Debug for DuplicateOptions {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct("DuplicateOptions")
                    .field("local_identity", &self.local_identity)
                    .field("peer_identity", &self.peer_identity)
                    .field("rejoin", &self.rejoin.is_some())
                    .finish()
            }
        }

        /// The decision: the session kept, and the one being drained.
        #[derive(Debug)]
        #[non_exhaustive]
        pub struct Resolved {
            /// The session kept: open new streams here.
            pub survivor: $session,
            /// The session being drained: GOAWAY when it is in use, no new
            /// streams, and an application close with NO_ERROR once its
            /// streams have ended (its `close_reason` tells when).
            pub loser: $session,
            /// The value that decided.
            pub rule: $crate::helpers::DuplicateRule,
            /// The rejoin of `opts.rejoin` was started: this endpoint
            /// dialed the losing session, the survivor uses multipath, has
            /// fewer attachments than its `max_pipes`, and a pipe added now
            /// would join at once (the peer's cap and refusal backoff). The
            /// dial and the pipe's addition run in the background (a task,
            /// or a thread with the std driver); a failed dial or join is
            /// dropped and never undoes the resolution.
            pub rejoin_started: bool,
        }

        /// Applies the duplicate-session rule (EXTENSIONS.md Section 11) to two
        /// established sessions that the application has identified as connecting
        /// the same two endpoints, one dialed by each.
        ///
        /// The survivor is the session whose dialer has the smaller value, the
        /// first that both sessions have of: the application identities of
        /// `opts`, compared bytewise; the dialers' Session Nonces when both
        /// sessions use multipath; the dialers' role nonces when both negotiated
        /// the roles with `auto`. Both endpoints compute the same survivor from
        /// these values, so each acts alone; the rule works only when both apply
        /// it (towards a peer that does not, a plain QMux peer included, the
        /// application decides alone).
        ///
        /// The losing session stops opening streams at once and drains: two-phase
        /// GOAWAY when it is in use, so that streams the peer opened concurrently
        /// are processed or reported as retryable, then an application close with
        /// NO_ERROR once its streams have ended; without GOAWAY it closes once its
        /// streams have ended. Never waits. With `opts.rejoin`, the losing route
        /// is dialed again in the background and joined to the survivor when that
        /// applies ([`Resolved::rejoin_started`]).
        ///
        /// Fails, and changes nothing, when a session is not established, a
        /// dialer is unknown ([`Session::is_dialer`](crate::Session#method.is_dialer)), the same endpoint dialed
        /// both sessions, or no value decides.
        pub fn resolve_duplicate(
            s1: &$session,
            s2: &$session,
            opts: &DuplicateOptions,
        ) -> Result<Resolved, $crate::helpers::DuplicateError> {
            let (survivor, loser, rule, rejoin_started) = $crate::helpers::resolve::<$d>(
                s1,
                s2,
                opts.local_identity.as_deref(),
                opts.peer_identity.as_deref(),
                opts.rejoin.as_ref(),
            )?;
            Ok(Resolved {
                survivor,
                loser,
                rule,
                rejoin_started,
            })
        }
    };
}
pub(crate) use duplicate_api;
