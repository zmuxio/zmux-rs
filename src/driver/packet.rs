//! Packet streams (EXTENSIONS.md Section 12): packets over a bidirectional
//! stream, each sent as a datagram associated with the stream or as an
//! RFC 9297 DATAGRAM capsule in the stream's bytes. A helper over the
//! stream and datagram operations: the session keeps no state for it.

use std::fmt;
use std::future::poll_fn;
use std::pin::pin;
use std::task::{Context, Poll};

use bytes::Bytes;

use crate::helpers::capsule::{self, Decoded, Decoder, MAX_HEADER};
use crate::proto::session::Preamble;
use crate::proto::{ApplicationErrorCode, VarInt, varint};
use crate::{DatagramError, OpenError, RecvStream, SendStream, Session, StreamError};

/// The default bound of a packet's payload: 65535 bytes.
pub const DEFAULT_MAX_PACKET: usize = 65535;

/// How a [`PacketStream`] sends a packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendPolicy {
    /// As a datagram when the session's datagrams are in use and the
    /// packet fits the stream's largest datagram at that moment, else as a
    /// capsule. A datagram refused by a limiter is dropped, never sent as
    /// a capsule instead.
    #[default]
    PreferDatagram,
    /// Always as a capsule: in order and reliably.
    StreamOnly,
    /// Always as a datagram: a packet that does not fit fails.
    DatagramOnly,
}

/// How a [`PacketStream`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PacketOptions {
    /// How packets are sent (default [`SendPolicy::PreferDatagram`]).
    pub policy: SendPolicy,
    /// The largest payload sent or accepted, Context ID excluded (default
    /// [`DEFAULT_MAX_PACKET`]). A received DATAGRAM capsule with a larger
    /// payload, or a capsule of any type whose Length exceeds it by more
    /// than 8 (the largest Context ID), ends the stream with
    /// `ZMUX_PACKET_ERROR`.
    pub max_packet: usize,
}

impl Default for PacketOptions {
    fn default() -> Self {
        Self {
            policy: SendPolicy::PreferDatagram,
            max_packet: DEFAULT_MAX_PACKET,
        }
    }
}

impl PacketOptions {
    /// The defaults with `policy`.
    #[must_use]
    pub fn with_policy(policy: SendPolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }
}

/// A packet received: its Context ID and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Packet {
    /// The Context ID (0 unless the sender chose another).
    pub context: u64,
    /// The payload.
    pub payload: Bytes,
}

/// How a packet left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sent {
    /// As a datagram associated with the stream.
    Datagram,
    /// As a DATAGRAM capsule in the stream's bytes.
    Capsule,
    /// Not at all: a datagram limiter refused it.
    Dropped,
}

/// Why a packet operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketError {
    /// The payload is larger than `max`: the stream's packet bound, or for
    /// [`SendPolicy::DatagramOnly`] the stream's largest datagram now.
    TooLarge {
        /// The largest payload.
        max: usize,
    },
    /// The Context ID is not below 2^62.
    InvalidContext,
    /// [`SendPolicy::DatagramOnly`] without datagrams on the session.
    NotNegotiated,
    /// The peer's bytes were malformed (a capsule above the bound, or the
    /// stream ended inside one): the stream was reset and stopped with
    /// `ZMUX_PACKET_ERROR`.
    Malformed,
    /// The stream failed.
    Stream(StreamError),
    /// The stream's datagram could not be sent.
    Datagram(DatagramError),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max } => write!(f, "packet larger than {max} bytes"),
            Self::InvalidContext => f.write_str("context ID out of range"),
            Self::NotNegotiated => f.write_str("datagrams not in use on the session"),
            Self::Malformed => f.write_str("malformed packet stream"),
            Self::Stream(e) => write!(f, "stream: {e}"),
            Self::Datagram(e) => write!(f, "datagram: {e}"),
        }
    }
}

impl std::error::Error for PacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stream(e) => Some(e),
            Self::Datagram(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StreamError> for PacketError {
    fn from(e: StreamError) -> Self {
        Self::Stream(e)
    }
}

impl From<PacketError> for std::io::Error {
    fn from(e: PacketError) -> Self {
        match e {
            PacketError::Stream(s) => s.into(),
            PacketError::Datagram(d) => d.into(),
            PacketError::Malformed => Self::new(std::io::ErrorKind::InvalidData, e),
            PacketError::NotNegotiated => Self::new(std::io::ErrorKind::Unsupported, e),
            _ => Self::new(std::io::ErrorKind::InvalidInput, e),
        }
    }
}

/// The counters of a packet stream or of one of its halves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PacketStats {
    /// Packets sent as datagrams.
    pub sent_datagrams: u64,
    /// Packets sent as capsules.
    pub sent_capsules: u64,
    /// Packets not sent because they were too large for a datagram
    /// ([`SendPolicy::DatagramOnly`]).
    pub dropped_too_large: u64,
    /// Packets not sent because a datagram limiter refused them.
    pub dropped_limited: u64,
    /// Packets received as datagrams.
    pub received_datagrams: u64,
    /// Packets received as capsules.
    pub received_capsules: u64,
    /// Capsules of unknown types skipped.
    pub skipped_capsules: u64,
}

impl PacketStats {
    fn merge(self, o: Self) -> Self {
        Self {
            sent_datagrams: self.sent_datagrams + o.sent_datagrams,
            sent_capsules: self.sent_capsules + o.sent_capsules,
            dropped_too_large: self.dropped_too_large + o.dropped_too_large,
            dropped_limited: self.dropped_limited + o.dropped_limited,
            received_datagrams: self.received_datagrams + o.received_datagrams,
            received_capsules: self.received_capsules + o.received_capsules,
            skipped_capsules: self.skipped_capsules + o.skipped_capsules,
        }
    }
}

fn packet_error() -> VarInt {
    VarInt::from_u64(ApplicationErrorCode::ZMUX_PACKET_ERROR.0).unwrap_or(VarInt::ZERO)
}

/// A bidirectional stream that carries packets (EXTENSIONS.md Section 12):
/// each packet goes as a datagram associated with the stream or as a
/// DATAGRAM capsule in its bytes, as [`SendPolicy`] says. Packets are
/// never fragmented and not ordered relative to each other; those in
/// capsules arrive in order and reliably.
///
/// Both endpoints wrap the stream, the opener and the acceptor alike, once
/// their application agreed that it is a packet stream (for example by its
/// preamble). It has no byte access; [`split`](Self::split) gives a
/// sending and a receiving half for two tasks.
///
/// ```no_run
/// # async fn f(session: zmux::Session) -> Result<(), Box<dyn std::error::Error>> {
/// use zmux::helpers::{PacketOptions, PacketStream};
///
/// let (send, recv) = session.open_bi().await?;
/// let mut packets = PacketStream::new(send, recv);
/// packets.send(bytes::Bytes::from_static(b"ping")).await?;
/// if let Some(p) = packets.recv().await? {
///     println!("{} bytes", p.payload.len());
/// }
/// packets.close().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PacketStream {
    tx: PacketSender,
    rx: PacketReceiver,
}

impl PacketStream {
    /// Wraps a bidirectional stream with the default options.
    #[must_use]
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self::with_options(send, recv, PacketOptions::default())
    }

    /// Wraps a bidirectional stream.
    #[must_use]
    pub fn with_options(send: SendStream, recv: RecvStream, opts: PacketOptions) -> Self {
        Self {
            tx: PacketSender {
                send,
                policy: opts.policy,
                max: opts.max_packet,
                pending: [None, None],
                started: false,
                stats: PacketStats::default(),
            },
            rx: PacketReceiver {
                recv,
                decoder: Decoder::new(opts.max_packet),
                buf: Bytes::new(),
                datagram_first: true,
                datagrams_done: false,
                state: RecvState::Open,
                stats: PacketStats::default(),
            },
        }
    }

    /// Sends a packet with Context ID 0. See [`PacketSender::send`].
    ///
    /// # Errors
    ///
    /// As [`PacketSender::send_with_context`].
    pub async fn send(&mut self, payload: Bytes) -> Result<Sent, PacketError> {
        self.tx.send(payload).await
    }

    /// Sends a packet with Context ID `context`. See
    /// [`PacketSender::send_with_context`].
    ///
    /// # Errors
    ///
    /// As [`PacketSender::send_with_context`].
    pub async fn send_with_context(
        &mut self,
        context: u64,
        payload: Bytes,
    ) -> Result<Sent, PacketError> {
        self.tx.send_with_context(context, payload).await
    }

    /// The next packet. See [`PacketReceiver::recv`].
    ///
    /// # Errors
    ///
    /// As [`PacketReceiver::recv`].
    pub async fn recv(&mut self) -> Result<Option<Packet>, PacketError> {
        self.rx.recv().await
    }

    /// Ends the sending direction. See [`PacketSender::close`].
    ///
    /// # Errors
    ///
    /// As [`PacketSender::close`].
    pub async fn close(&mut self) -> Result<(), PacketError> {
        self.tx.close().await
    }

    /// Both directions' counters.
    pub fn stats(&self) -> PacketStats {
        self.tx.stats.merge(self.rx.stats)
    }

    /// The sending and the receiving half.
    pub fn split(self) -> (PacketSender, PacketReceiver) {
        (self.tx, self.rx)
    }
}

/// The sending half of a [`PacketStream`].
#[derive(Debug)]
pub struct PacketSender {
    send: SendStream,
    policy: SendPolicy,
    max: usize,
    /// What remains of a capsule whose write was cancelled: its header and
    /// payload, written before anything else.
    pending: [Option<Bytes>; 2],
    /// Some bytes of the pending capsule were written: it must be
    /// completed to keep the stream's bytes whole capsules. Otherwise a
    /// cancelled capsule is dropped, never sent.
    started: bool,
    stats: PacketStats,
}

impl PacketSender {
    /// Sends a packet with Context ID 0.
    ///
    /// # Errors
    ///
    /// As [`send_with_context`](Self::send_with_context).
    pub async fn send(&mut self, payload: Bytes) -> Result<Sent, PacketError> {
        self.send_with_context(0, payload).await
    }

    /// Sends a packet with Context ID `context`, as the policy says. A
    /// datagram never waits; a capsule waits for the stream's buffer.
    /// Cancel-safe: a cancelled send was not sent unless part of it was
    /// already written, in which case it is completed by the next send or
    /// [`close`](Self::close) (and then counted in `sent_capsules`), so
    /// the stream's bytes stay whole capsules. A caller retrying after a
    /// cancellation may therefore send a packet twice only if its first
    /// write had begun.
    ///
    /// # Errors
    ///
    /// [`PacketError::TooLarge`] above the packet bound (or, for
    /// [`SendPolicy::DatagramOnly`], above the largest datagram);
    /// [`PacketError::InvalidContext`]; [`PacketError::NotNegotiated`];
    /// the stream's or the datagram's error.
    pub async fn send_with_context(
        &mut self,
        context: u64,
        payload: Bytes,
    ) -> Result<Sent, PacketError> {
        if context > varint::MAX {
            return Err(PacketError::InvalidContext);
        }
        if payload.len() > self.max {
            return Err(PacketError::TooLarge { max: self.max });
        }
        let fits = self
            .send
            .max_datagram_size(context)
            .filter(|&m| payload.len() <= m);
        match self.policy {
            SendPolicy::StreamOnly => {}
            SendPolicy::PreferDatagram if fits.is_none() => {}
            SendPolicy::PreferDatagram => match self.datagram(context, payload.clone()) {
                Ok(sent) => return Ok(sent),
                // Lost the fit since it was asked: a capsule instead.
                Err(PacketError::TooLarge { .. } | PacketError::NotNegotiated) => {}
                Err(e) => return Err(e),
            },
            SendPolicy::DatagramOnly => {
                return match self.send.max_datagram_size(context) {
                    None => Err(PacketError::NotNegotiated),
                    Some(max) if payload.len() > max => {
                        self.stats.dropped_too_large += 1;
                        Err(PacketError::TooLarge { max })
                    }
                    Some(_) => {
                        let r = self.datagram(context, payload);
                        if matches!(r, Err(PacketError::TooLarge { .. })) {
                            self.stats.dropped_too_large += 1;
                        }
                        r
                    }
                };
            }
        }
        self.finish_pending().await?;
        let mut h = [0; MAX_HEADER];
        let n = capsule::datagram_header(context, payload.len(), &mut h);
        self.pending = [
            Some(Bytes::copy_from_slice(&h[..n])),
            (!payload.is_empty()).then_some(payload),
        ];
        self.started = false;
        self.flush().await?;
        self.stats.sent_capsules += 1;
        Ok(Sent::Capsule)
    }

    fn datagram(&mut self, context: u64, payload: Bytes) -> Result<Sent, PacketError> {
        match self.send.try_send_datagram(context, payload) {
            Ok(true) => {
                self.stats.sent_datagrams += 1;
                Ok(Sent::Datagram)
            }
            Ok(false) => {
                self.stats.dropped_limited += 1;
                Ok(Sent::Dropped)
            }
            Err(DatagramError::TooLarge { max }) => Err(PacketError::TooLarge { max }),
            Err(DatagramError::NotNegotiated) => Err(PacketError::NotNegotiated),
            Err(e) => Err(PacketError::Datagram(e)),
        }
    }

    /// Completes a capsule whose write was cancelled after it began, or
    /// drops one cancelled before any byte of it was written.
    async fn finish_pending(&mut self) -> Result<(), PacketError> {
        if self.pending[0].is_none() && self.pending[1].is_none() {
            return Ok(());
        }
        if !self.started {
            self.pending = [None, None];
            return Ok(());
        }
        self.flush().await?;
        self.stats.sent_capsules += 1;
        Ok(())
    }

    /// Writes what remains of a capsule.
    async fn flush(&mut self) -> Result<(), PacketError> {
        let (send, pending, started) = (&self.send, &mut self.pending, &mut self.started);
        poll_fn(|cx: &mut Context<'_>| {
            for slot in pending.iter_mut() {
                while let Some(part) = slot {
                    match send.poll_write_part(cx.waker(), part) {
                        Poll::Ready(Ok(n)) => {
                            *started |= n > 0;
                            if part.is_empty() {
                                *slot = None;
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
            Poll::Ready(Ok(()))
        })
        .await
    }

    /// Ends the sending direction cleanly once a capsule in progress was
    /// written: the peer's [`PacketReceiver::recv`] then returns `None`.
    ///
    /// # Errors
    ///
    /// The stream's error, while completing a pending capsule or finishing
    /// (a stream already finished or reset locally is not an error).
    pub async fn close(&mut self) -> Result<(), PacketError> {
        self.finish_pending().await?;
        match self.send.finish() {
            Ok(()) | Err(StreamError::ClosedLocally) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The counters of the sending direction.
    pub fn stats(&self) -> PacketStats {
        self.stats
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecvState {
    Open,
    /// The stream's bytes ended at a capsule boundary: the datagrams
    /// already queued for the stream are delivered before the end.
    Draining,
    Ended,
    Malformed,
}

/// The receiving half of a [`PacketStream`].
#[derive(Debug)]
pub struct PacketReceiver {
    recv: RecvStream,
    decoder: Decoder,
    /// Stream bytes read and not decoded yet.
    buf: Bytes,
    /// Which way is looked at first, alternating so that neither starves
    /// the other.
    datagram_first: bool,
    /// The stream can carry no more datagrams.
    datagrams_done: bool,
    state: RecvState,
    stats: PacketStats,
}

impl PacketReceiver {
    /// The next packet, whichever way it came; `None` once the peer closed
    /// its direction at a capsule boundary and the datagrams already
    /// queued for the stream were delivered. Datagrams arriving after that
    /// are dropped (EXTENSIONS.md Section 6.4). A payload is a slice of the
    /// received bytes where it arrived whole, without copying. Cancel-safe.
    ///
    /// # Errors
    ///
    /// [`PacketError::Malformed`] when the peer's bytes were malformed:
    /// the stream is then reset and stopped with `ZMUX_PACKET_ERROR`, and
    /// later calls fail the same way. The stream's error, for example its
    /// reset by the peer.
    pub async fn recv(&mut self) -> Result<Option<Packet>, PacketError> {
        match self.state {
            RecvState::Open | RecvState::Draining => {}
            RecvState::Ended => return Ok(None),
            RecvState::Malformed => return Err(PacketError::Malformed),
        }
        let Self {
            recv,
            decoder,
            buf,
            datagram_first,
            datagrams_done,
            state,
            stats,
        } = self;
        let recv: &RecvStream = recv;
        let mut datagram = pin!(recv.read_datagram());
        poll_fn(|cx| {
            if *state == RecvState::Draining {
                return Poll::Ready(Ok(drain(
                    datagram.as_mut(),
                    cx,
                    datagrams_done,
                    state,
                    stats,
                )));
            }
            *datagram_first = !*datagram_first;
            let mut tried = false;
            loop {
                if *datagram_first && !tried && !*datagrams_done {
                    tried = true;
                    match datagram.as_mut().poll(cx) {
                        Poll::Ready(Ok(d)) => {
                            stats.received_datagrams += 1;
                            return Poll::Ready(Ok(Some(Packet {
                                context: d.context,
                                payload: d.payload,
                            })));
                        }
                        Poll::Ready(Err(_)) => *datagrams_done = true,
                        Poll::Pending => {}
                    }
                }
                match decoder.decode(buf) {
                    Decoded::Packet { context, payload } => {
                        stats.received_capsules += 1;
                        return Poll::Ready(Ok(Some(Packet { context, payload })));
                    }
                    Decoded::Skipped => {
                        stats.skipped_capsules += 1;
                        continue;
                    }
                    Decoded::Malformed(_) => {
                        return Poll::Ready(Err(malformed(recv, state)));
                    }
                    Decoded::More => {}
                }
                match recv.poll_read_chunk(cx.waker(), decoder.want()) {
                    Poll::Ready(Ok(Some(chunk))) => {
                        *buf = chunk;
                        continue;
                    }
                    Poll::Ready(Ok(None)) if decoder.at_boundary() => {
                        *state = RecvState::Draining;
                        return Poll::Ready(Ok(drain(
                            datagram.as_mut(),
                            cx,
                            datagrams_done,
                            state,
                            stats,
                        )));
                    }
                    Poll::Ready(Ok(None)) => {
                        return Poll::Ready(Err(malformed(recv, state)));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {}
                }
                if !tried && !*datagrams_done {
                    match datagram.as_mut().poll(cx) {
                        Poll::Ready(Ok(d)) => {
                            stats.received_datagrams += 1;
                            return Poll::Ready(Ok(Some(Packet {
                                context: d.context,
                                payload: d.payload,
                            })));
                        }
                        Poll::Ready(Err(_)) => *datagrams_done = true,
                        Poll::Pending => {}
                    }
                }
                return Poll::Pending;
            }
        })
        .await
    }

    /// The counters of the receiving direction.
    pub fn stats(&self) -> PacketStats {
        self.stats
    }
}

/// A datagram already queued for the stream, without waiting; `None`, and
/// the end, once there is none.
fn drain<F>(
    next_datagram: std::pin::Pin<&mut F>,
    cx: &mut Context<'_>,
    datagrams_done: &mut bool,
    state: &mut RecvState,
    counts: &mut PacketStats,
) -> Option<Packet>
where
    F: Future<Output = Result<crate::StreamDatagram, StreamError>>,
{
    if !*datagrams_done {
        match next_datagram.poll(cx) {
            Poll::Ready(Ok(d)) => {
                counts.received_datagrams += 1;
                return Some(Packet {
                    context: d.context,
                    payload: d.payload,
                });
            }
            Poll::Ready(Err(_)) => *datagrams_done = true,
            Poll::Pending => {}
        }
    }
    *state = RecvState::Ended;
    None
}

fn malformed(recv: &RecvStream, state: &mut RecvState) -> PacketError {
    recv.fail_shared(packet_error());
    *state = RecvState::Malformed;
    PacketError::Malformed
}

impl Session {
    /// Opens a bidirectional stream with `preamble`, waiting for stream
    /// credit as [`Session::open_bi_with`](Session#method.open_bi_with) does, and wraps it as a
    /// [`PacketStream`].
    pub async fn open_packet_stream(
        &self,
        preamble: &Preamble,
        opts: PacketOptions,
    ) -> Result<PacketStream, OpenError> {
        let (send, recv) = self.open_bi_with(preamble).await?;
        Ok(PacketStream::with_options(send, recv, opts))
    }
}
