//! A new pipe's first bytes at the accepting end: through its listener
//! until the session accepts the join. The shared step of the sans-IO
//! multipath harnesses (tests and benches).

#![allow(dead_code)]

use std::time::Instant;

use zmux::proto::listener::{CarrierId, Classified, ListenerCore, Opened};
use zmux::proto::record::Framing;
use zmux::proto::session::{JoinVerdict, PipeId, SessionCore};

/// What became of a pipe's bytes fed through the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Joined {
    /// The listener needs more bytes, or the session asked to wait.
    Pending,
    /// The session attached the pipe and took the bytes after the join.
    Attached(PipeId),
    /// The session refused the join; the listener is done with the
    /// carrier.
    Refused,
    /// The listener refused or closed the carrier (no join).
    Dropped,
}

/// [`feed_join`]'s outcome.
pub(crate) struct Fed {
    pub(crate) joined: Joined,
    /// A carrier the listener evicted to take this one.
    pub(crate) evicted: Option<CarrierId>,
}

/// Feeds `bytes` of the carrier tagged `tag` (byte-stream framed) to
/// `listener`, opening it into `carrier` first, and offers its join to
/// `session` once the listener classified it.
pub(crate) fn feed_join(
    listener: &mut ListenerCore,
    session: &mut SessionCore,
    carrier: &mut Option<CarrierId>,
    tag: u64,
    bytes: &[u8],
    now: Instant,
) -> Fed {
    const BS: Framing = Framing::ByteStream;
    let mut evicted = None;
    let c = match *carrier {
        Some(c) => c,
        None => match listener.open(tag, BS, now) {
            Opened::Accepted { id, evicted: e } => {
                evicted = e;
                *carrier = Some(id);
                id
            }
            Opened::Refused => {
                return Fed {
                    joined: Joined::Dropped,
                    evicted,
                };
            }
        },
    };
    let joined = match listener.data(c, bytes, now) {
        Classified::NeedMore => Joined::Pending,
        Classified::Join {
            frame,
            bytes,
            inband,
            ..
        } => match session.offer_join(&frame, &[], Some(BS), Some(BS), inband, now) {
            JoinVerdict::Accepted(p) => {
                listener.done(c);
                *carrier = None;
                session.receive(p, &bytes, now);
                Joined::Attached(p)
            }
            JoinVerdict::Wait => Joined::Pending,
            _ => {
                listener.done(c);
                *carrier = None;
                Joined::Refused
            }
        },
        _ => {
            listener.done(c);
            *carrier = None;
            Joined::Dropped
        }
    };
    Fed { joined, evicted }
}
