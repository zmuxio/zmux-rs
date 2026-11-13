//! A new pipe's first bytes at the accepting end: through its listener, Hello, Reply and
//! Confirm, until the session attaches the pipe. The shared step of the sans-IO multipath
//! harnesses (tests and benches).

#![allow(dead_code)]

use std::time::Instant;
use zmux::shaping::UnitPlan;

use zmux::proto::listener::{CarrierId, Classified, Entered, ListenerCore};
use zmux::proto::record::Framing;
use zmux::proto::seal::join::JoinHello;
use zmux::proto::session::{
    ClaimedHello, ConfirmedJoin, JoinStep, OpenedHello, PeerCarrier, PeerJoin, PipeId, SessionCore,
};

const BS: Framing = Framing::ByteStream;

/// What became of a pipe's bytes fed through the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Joined {
    /// The handshake goes on: more bytes are wanted, or the session holds the Hello.
    Pending,
    /// The session attached the pipe and took the bytes after the Confirm.
    Attached(PipeId),
    /// The session refused the join; the carrier closes.
    Refused,
    /// The listener refused or closed the carrier (no join).
    Dropped,
}

/// The accepting end's handshake of one carrier.
#[derive(Debug, Default)]
pub(crate) struct Accepting {
    pub(crate) carrier: Option<CarrierId>,
    /// A Hello the session holds, offered again.
    pub(crate) hello: Option<Vec<u8>>,
    join: Option<Box<PeerJoin>>,
    /// Bytes after the Hello.
    buf: Vec<u8>,
}

/// [`feed_join`]'s outcome.
pub(crate) struct Fed {
    pub(crate) joined: Joined,
    /// The Reply to write on the carrier, empty when there is none.
    pub(crate) reply: Vec<u8>,
}

/// Feeds `bytes` of the carrier tagged `tag` (byte-stream framed) to the accepting end:
/// the listener classifies the Hello, the session verifies it and writes the Reply, and
/// attaches the pipe once the Confirm arrived. Empty `bytes` offer a held Hello again.
pub(crate) fn feed_join(
    listener: &mut ListenerCore,
    session: &mut SessionCore,
    st: &mut Accepting,
    tag: u64,
    bytes: &[u8],
    now: Instant,
) -> Fed {
    let mut fed = Fed {
        joined: Joined::Pending,
        reply: Vec::new(),
    };
    if st.hello.is_none() && st.join.is_none() {
        let c = match st.carrier {
            Some(c) => c,
            None => match listener.enter(tag) {
                Entered::Taken { slot, .. } => {
                    let id = listener.open(Some(slot), BS, now);
                    st.carrier = Some(id);
                    id
                }
                Entered::SourceFull | Entered::Full => {
                    fed.joined = Joined::Dropped;
                    return fed;
                }
            },
        };
        match listener.data(c, bytes, now) {
            Classified::NeedMore => return fed,
            Classified::Join { hello, .. } => st.hello = Some(hello),
            _ => {
                st.close(listener);
                fed.joined = Joined::Dropped;
                return fed;
            }
        }
    } else {
        st.buf.extend_from_slice(bytes);
    }
    let carrier = PeerCarrier {
        inbound: Some(BS),
        outbound: Some(BS),
        looped: false,
        overhead: 0,
        received: 0,
    };
    if let Some(hello) = st.hello.take() {
        let parsed = JoinHello::parse(BS, &hello).expect("the listener parsed this Hello");
        match session.open_hello(&parsed, &[], now) {
            OpenedHello::Hold | OpenedHello::KeyWait => {
                st.hello = Some(hello);
                return fed;
            }
            OpenedHello::Verified(mut join) => {
                match session.claim_hello(&mut join, carrier, &UnitPlan::default(), now) {
                    ClaimedHello::Accept(reply) => {
                        fed.reply = reply;
                        st.join = Some(join);
                    }
                    ClaimedHello::Refuse(reply) => {
                        fed.reply = reply;
                        st.close(listener);
                        fed.joined = Joined::Refused;
                        return fed;
                    }
                    ClaimedHello::Close => {
                        st.close(listener);
                        fed.joined = Joined::Refused;
                        return fed;
                    }
                }
            }
            _ => {
                st.close(listener);
                fed.joined = Joined::Refused;
                return fed;
            }
        }
    }
    let Some(join) = st.join.as_mut() else {
        return fed;
    };
    match join.read_confirm(&st.buf) {
        Ok(None) => return fed,
        Ok(Some(n)) => {
            st.buf.drain(..n);
        }
        Err(_) => {
            st.close(listener);
            fed.joined = Joined::Refused;
            return fed;
        }
    }
    let join = st.join.take().expect("held above");
    fed.joined = match session.confirm_join(*join, carrier, now) {
        ConfirmedJoin::Attached { pipe, .. } => {
            let rest = std::mem::take(&mut st.buf);
            session.receive(pipe, &rest, now);
            Joined::Attached(pipe)
        }
        _ => Joined::Refused,
    };
    st.close(listener);
    fed
}

impl Accepting {
    fn close(&mut self, listener: &mut ListenerCore) {
        if let Some(c) = self.carrier.take() {
            listener.done(c);
        }
        self.join = None;
        self.hello = None;
    }
}

/// The joining end's handshake of one carrier.
/// A Proven join: its confirmation and the bytes read beyond it.
type Finished = (Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Joining {
    /// The Hello is not written yet.
    Hello,
    /// The Reply is awaited.
    Reply,
    /// Proven, or a carrier that needs no handshake: records flow.
    Records,
    /// The attachment failed or was declined.
    Gone,
}

/// Feeds `input` to the joining end: `Some((confirm, rest))` once the Reply is proven,
/// with what to write and the records that followed it. Leaves bytes it still wants in
/// `input`; `Err` when the attachment is gone.
pub(crate) fn feed_reply(
    session: &mut SessionCore,
    pipe: PipeId,
    input: &mut Vec<u8>,
    now: Instant,
) -> Result<Option<Finished>, ()> {
    loop {
        match session.verify_reply(pipe, input, now) {
            JoinStep::More { consumed, .. } => {
                input.drain(..consumed);
                if consumed == 0 {
                    return Ok(None);
                }
            }
            JoinStep::Verified { consumed, .. } => {
                input.drain(..consumed);
                let plan = UnitPlan::default();
                let confirm = session
                    .join_finish(pipe, &plan, now)
                    .map_err(|_| ())?
                    .confirm;
                return Ok(Some((confirm, std::mem::take(input))));
            }
            JoinStep::Declined | JoinStep::Failed => return Err(()),
        }
    }
}

/// The whole handshake of `joiner`'s added pipe with nothing lost on the way, at one
/// instant: the pipe is attached at both ends when it returns `Joined::Attached`.
pub(crate) fn join_at_once(
    listener: &mut ListenerCore,
    joiner: &mut SessionCore,
    acceptor: &mut SessionCore,
    pipe: PipeId,
    now: Instant,
) -> Joined {
    joiner
        .join_prepare(pipe, now)
        .expect("a joining pipe")
        .expect("not deferred");
    let hello = joiner
        .join_hello(pipe, (BS, 0), &UnitPlan::default(), now)
        .expect("a joining pipe");
    let mut st = Accepting::default();
    let fed = feed_join(listener, acceptor, &mut st, pipe.get(), &hello, now);
    if fed.joined != Joined::Pending {
        return fed.joined;
    }
    let mut input = fed.reply;
    let Ok(Some((confirm, _))) = feed_reply(joiner, pipe, &mut input, now) else {
        return Joined::Refused;
    };
    feed_join(listener, acceptor, &mut st, pipe.get(), &confirm, now).joined
}
