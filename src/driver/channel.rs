//! Datagram channels of pipe carriers: the interface a carrier adapter
//! implements ([`DatagramChannel`]), the router of the channel datagrams of
//! a connection shared by several pipes ([`ChannelDemux`]), and the task of
//! each pipe with a channel.
//!
//! The task owns the channel's sending side: it polls the core for the
//! datagrams that go on the channel ([`SessionCore::poll_channel`]) and
//! sends them outside the lock, so that they never wait behind a batch of
//! the pipe; a failed send counts as a datagram dropped on send. What the
//! channel receives for the pipe goes to the core from the adapter's
//! receive loop ([`ChannelReceiver`]). The task ends with the pipe, the
//! session, or a peer that did not negotiate the channel.
//!
//! [`SessionCore::poll_channel`]: crate::proto::session::SessionCore::poll_channel

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use bytes::Bytes;

use super::handle::{Shared, State};
use super::tokio::{Tokio, now};
use super::wait::{List, Wait};
use crate::proto::frame::channel;
use crate::proto::session::PipeId;

/// The datagram channel of a pipe's carrier, an optional capability of a
/// carrier ([`crate::PipeIo::with_datagram_channel`]): an unreliable
/// datagram service of the carrier besides the reliable stream that is the
/// pipe, such as the QUIC datagrams of the connection a QUIC stream belongs
/// to, the HTTP Datagrams of an HTTP/3 request stream, or the datagrams of
/// a WebTransport session. When both endpoints negotiate it, a session with
/// datagrams enabled sends a DATAGRAM frame that fits the channel on it
/// instead of in a record, so that a lost carrier packet loses that
/// datagram instead of delaying every later one; nothing changes for the
/// application.
///
/// A channel datagram is the varint [`DatagramChannel::channel_id`], when
/// the channel has one, then one DATAGRAM frame without its Length field
/// (the [`channel`] frame module).
pub trait DatagramChannel: Send + Sync + 'static {
    /// The varint each channel datagram of the pipe starts with, by which
    /// the peer's carrier routes it to the pipe: the Pipe Stream ID (the
    /// carrier stream ID of the pipe) on a channel that the streams of a
    /// connection share. An HTTP/3 carrier whose channel is the QUIC
    /// datagrams of its connection gives the request stream's Quarter
    /// Stream ID, which makes each channel datagram a whole HTTP Datagram.
    /// `None`: the channel is the pipe's own and its datagrams are the
    /// frame alone. It may change while the pipe is used (a stream
    /// replaced after rejected early data).
    fn channel_id(&self) -> Option<u64>;

    /// The largest channel datagram the channel takes now,
    /// [`DatagramChannel::channel_id`] included; 0 while it takes none
    /// (the carrier did not negotiate datagrams, or has not yet). Called
    /// outside the session's lock whenever the pipe's channel task wakes;
    /// it must not wait.
    fn max_datagram_size(&self) -> usize;

    /// Sends one channel datagram. It may wait while the carrier's own
    /// queue is full (the session's datagram queue drops its oldest
    /// datagrams meanwhile); an error drops the datagram.
    fn send(&self, datagram: Bytes) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;

    /// Starts handing the channel datagrams received for the pipe,
    /// [`DatagramChannel::channel_id`] removed, to `receiver`, until the
    /// registration returned is dropped.
    fn receive(&self, receiver: ChannelReceiver) -> ChannelRegistration;
}

type Deliver = dyn Fn(Bytes) + Send + Sync;

/// Where a carrier hands the channel datagrams it received for a pipe
/// ([`DatagramChannel::receive`]): the pipe's session. Cheap to clone.
#[derive(Clone)]
pub struct ChannelReceiver(Arc<Deliver>);

impl fmt::Debug for ChannelReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelReceiver(..)")
    }
}

impl ChannelReceiver {
    /// A receiver that calls `deliver` (for tests and wrappers).
    pub fn new(deliver: impl Fn(Bytes) + Send + Sync + 'static) -> Self {
        Self(Arc::new(deliver))
    }

    /// Delivers one received channel datagram, its
    /// [`DatagramChannel::channel_id`] removed: the DATAGRAM frame. It
    /// never waits: the session takes it from a bounded queue of the pipe,
    /// which drops (and counts) what does not fit.
    pub fn deliver(&self, frame: Bytes) {
        let handler = &self.0;
        handler(frame);
    }
}

/// A registration of [`DatagramChannel::receive`]: datagrams reach the
/// receiver until it is dropped.
#[must_use = "the receiver is unregistered when the registration is dropped"]
pub struct ChannelRegistration(Option<Box<dyn FnOnce() + Send>>);

impl fmt::Debug for ChannelRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelRegistration(..)")
    }
}

impl ChannelRegistration {
    /// A registration that runs `stop` when dropped.
    pub fn new(stop: impl FnOnce() + Send + 'static) -> Self {
        Self(Some(Box::new(stop)))
    }

    /// A registration with nothing to stop (a channel that receives
    /// nothing).
    pub fn none() -> Self {
        Self(None)
    }
}

impl Drop for ChannelRegistration {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            stop();
        }
    }
}

/// Routes the channel datagrams of one carrier connection shared by several
/// pipes, such as a QUIC connection or a WebTransport session, to those
/// pipes by the varint they start with ([`DatagramChannel::channel_id`]).
/// An adapter runs one receive loop per connection that passes every
/// datagram to [`ChannelDemux::deliver`], and its pipes'
/// [`DatagramChannel::receive`] register with [`ChannelDemux::register`].
/// The pipes may belong to several sessions. Cheap to clone.
#[derive(Clone, Default)]
pub struct ChannelDemux {
    inner: Arc<Demux>,
}

#[derive(Default)]
struct Demux {
    /// By channel ID: the registration's token and its receiver.
    routes: Mutex<HashMap<u64, (u64, ChannelReceiver)>>,
    tokens: AtomicU64,
    dropped: AtomicU64,
}

impl Demux {
    fn routes(&self) -> std::sync::MutexGuard<'_, HashMap<u64, (u64, ChannelReceiver)>> {
        self.routes.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for ChannelDemux {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelDemux")
            .field("routes", &self.inner.routes().len())
            .field("dropped", &self.dropped())
            .finish()
    }
}

impl ChannelDemux {
    /// An empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Hands the datagrams that start with `id` to `receiver` until the
    /// registration is dropped; a later registration of the same ID
    /// replaces it.
    pub fn register(&self, id: u64, receiver: ChannelReceiver) -> ChannelRegistration {
        let token = self.inner.tokens.fetch_add(1, Ordering::Relaxed);
        self.inner.routes().insert(id, (token, receiver));
        let inner = Arc::downgrade(&self.inner);
        ChannelRegistration::new(move || {
            if let Some(d) = inner.upgrade() {
                d.routes().retain(|_, (t, _)| *t != token);
            }
        })
    }

    /// Routes the datagrams that start with `from` to the receiver
    /// registered for it from now on by `to` (a pipe whose stream was
    /// replaced).
    pub fn rekey(&self, from: u64, to: u64) {
        let mut routes = self.inner.routes();
        if let Some(r) = routes.remove(&from) {
            routes.insert(to, r);
        }
    }

    /// Routes one channel datagram to the pipe it names, its ID removed;
    /// one that names no registered pipe (unknown, not yet attached, or
    /// closed) or whose ID is truncated is dropped and counted
    /// ([`ChannelDemux::dropped`]). Returns whether it was routed.
    /// The frame handed on is a slice of `datagram`, not a copy.
    pub fn deliver(&self, datagram: Bytes) -> bool {
        let route = channel::split(&datagram).and_then(|(id, frame)| {
            let at = datagram.len() - frame.len();
            let r = self.inner.routes().get(&id).map(|(_, r)| r.clone());
            r.map(|r| (r, at))
        });
        let route = route.map(|(r, at)| (r, datagram.slice(at..)));
        match route {
            Some((r, frame)) => {
                r.deliver(frame);
                true
            }
            None => {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// The datagrams [`ChannelDemux::deliver`] dropped because they named
    /// no registered pipe.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }
}

/// The receiving side of a pipe's datagram channel, registered with the
/// carrier before the session can announce the channel: a peer may send
/// on it as soon as it reads the parameters, and what reaches a carrier
/// before the registration names no pipe and is dropped.
pub(crate) struct Receiving {
    _registration: ChannelRegistration,
    _task: AbortOnDrop,
}

/// Registers the receiver of pipe `pipe`'s channel. Dropped (a pipe the
/// session refused), it unregisters.
pub(crate) fn attach(
    shared: &Arc<Shared<Tokio>>,
    pipe: PipeId,
    ch: &Arc<dyn DatagramChannel>,
) -> Receiving {
    // The carrier's receive loop, which may serve several sessions, never
    // waits for this session's lock: it queues, and a task of the pipe
    // hands the queue to the session.
    let inbox = Arc::new(Inbox::default());
    let task = tokio::spawn(receive(Arc::downgrade(shared), pipe, inbox.clone()));
    let task = AbortOnDrop(task.abort_handle());
    let registration = ch.receive(ChannelReceiver::new(move |frame| inbox.push(frame)));
    Receiving {
        _registration: registration,
        _task: task,
    }
}

/// Starts the task of the datagram channel of pipe `pipe` (a session with
/// datagrams enabled whose carrier has one), whose receiver `receiving`
/// registered.
pub(crate) fn start(
    shared: &Arc<Shared<Tokio>>,
    pipe: PipeId,
    ch: Arc<dyn DatagramChannel>,
    receiving: Receiving,
) {
    tokio::spawn(run(shared.clone(), pipe, ch, receiving));
}

/// The task of a pipe's datagram channel: sends what the core puts on the
/// channel, until the channel may no longer be used; what the channel
/// receives goes to the session while it runs. It ends on the session's
/// close, which wakes every wait.
async fn run(
    shared: Arc<Shared<Tokio>>,
    pipe: PipeId,
    ch: Arc<dyn DatagramChannel>,
    _receiving: Receiving,
) {
    let mut out = Vec::new();
    loop {
        // The carrier's maximum may grow with its path, or shrink.
        let (id, max) = (ch.channel_id(), ch.max_datagram_size());
        let generation = {
            let mut st = shared.lock();
            st.core.set_pipe_channel(pipe, id, max);
            let live = st.core.poll_channel(pipe, &mut out);
            let generation = st.core.channel_generation();
            st.after_command();
            if !live {
                return;
            }
            generation
        };
        if !out.is_empty() {
            let mut failed = 0;
            for b in out.drain(..) {
                if ch.send(b).await.is_err() {
                    failed += 1;
                }
            }
            if failed > 0 {
                let mut st = shared.lock();
                st.core.channel_send_failed(failed);
                st.after_command();
            }
            continue;
        }
        Wait::new(&shared.inner, List::Channel, |st: &mut State<Tokio>| {
            (st.core.channel_generation() != generation || !st.core.channel_live(pipe))
                .then_some(())
        })
        .await;
    }
}

/// The channel datagrams received for a pipe, waiting for its session.
#[derive(Default)]
struct Inbox {
    queue: Mutex<(VecDeque<Bytes>, u64)>,
    ready: tokio::sync::Notify,
}

/// The datagrams an inbox holds at most: beyond, the newest is dropped and
/// counted as a received datagram dropped.
const INBOX: usize = 256;

impl Inbox {
    fn push(&self, frame: Bytes) {
        {
            let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            if q.0.len() >= INBOX {
                q.1 += 1;
                return;
            }
            q.0.push_back(frame);
        }
        self.ready.notify_one();
    }

    /// Everything queued, and the count dropped since the last take.
    fn take(&self, into: &mut VecDeque<Bytes>) -> u64 {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::swap(into, &mut q.0);
        std::mem::take(&mut q.1)
    }
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Hands what the pipe's channel received to its session, a batch per
/// critical section.
async fn receive(shared: Weak<Shared<Tokio>>, pipe: PipeId, inbox: Arc<Inbox>) {
    let mut batch = VecDeque::new();
    loop {
        inbox.ready.notified().await;
        let dropped = inbox.take(&mut batch);
        let Some(s) = shared.upgrade() else {
            return;
        };
        s.receive_channel(pipe, &mut batch, dropped);
    }
}

impl Shared<Tokio> {
    /// Channel datagrams received for pipe `pipe`, and `dropped` more that
    /// did not fit its queue.
    fn receive_channel(&self, pipe: PipeId, batch: &mut VecDeque<Bytes>, dropped: u64) {
        let mut st = self.lock();
        let due = st.core.poll_timeout();
        let now = now();
        st.core.channel_dropped(dropped);
        for frame in batch.drain(..) {
            st.core.receive_channel_datagram(pipe, &frame, now);
        }
        let (mut st, _) = self.police_datagrams(st);
        // A datagram held for a stream not opened yet has a deadline the
        // task's timer must see.
        let earlier = match (due, st.core.poll_timeout()) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(d), Some(t)) => t < d,
        };
        if earlier {
            st.wake_task();
        }
        st.after_command();
    }
}
