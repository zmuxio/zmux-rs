//! Datagrams on a carrier's datagram channel (EXTENSIONS.md Section 6.8).
//!
//! A pipe carrier may have an unreliable datagram service of its own: QUIC
//! datagrams of the connection a QUIC stream pipe belongs to, the HTTP
//! Datagrams of an HTTP/3 request stream, the datagrams of a WebTransport
//! session. The driver tells the core about it
//! ([`SessionCore::set_pipe_channel`]); when both endpoints negotiated
//! `zmux_carrier_datagrams`, the core decides per DATAGRAM frame whether it
//! goes on the channel of the pipe it would otherwise go to (it fits the
//! channel's current maximum, and the pipe is not shaped) or in a record,
//! and hands channel datagrams to the driver
//! ([`SessionCore::poll_channel`]), which sends them on a task of the pipe
//! so that they never wait behind a batch. Received ones are processed by
//! [`SessionCore::receive_channel_datagram`] with the rules of records,
//! without the accounting of records: no PIPE_ACK position, no no-effect
//! budget, no idle timer restart. The sizes, queues and limiters of
//! datagrams are unchanged.

use std::time::Instant;

use bytes::{BufMut, Bytes, BytesMut};

use super::pipes::{Channel, InState, OutPipe};
use super::{CoreEvent, PipeId, SessionCore, State};
use crate::proto::frame::{FrameType, channel};
use crate::proto::payload::Flow;

impl SessionCore {
    /// The carrier of `pipe` has a datagram channel: `id` is the Pipe Stream
    /// ID that starts the pipe's channel datagrams on a channel shared by
    /// the streams of a connection (`None` where the channel is the pipe's
    /// own), `max` the largest channel datagram it takes now, Pipe Stream ID
    /// included (0 while it takes none). The driver calls it again whenever
    /// it learns a new maximum, and owns the channel's I/O: it sends what
    /// [`SessionCore::poll_channel`] returns and passes what arrives to
    /// [`SessionCore::receive_channel_datagram`].
    ///
    /// Given for the bootstrap pipe before its first transmit, it makes a
    /// session with datagrams enabled send `zmux_carrier_datagrams` (a
    /// multipath session sends it anyway: a pipe it joins may have a
    /// channel).
    pub fn set_pipe_channel(&mut self, pipe: PipeId, id: Option<u64>, max: usize) {
        if pipe == PipeId(0) && self.config.enable_datagrams {
            self.local.carrier_datagrams = true;
        }
        let Some(o) = self.out_mut(pipe.0) else {
            return;
        };
        let new = Channel { id, max };
        if o.channel() == Some(new) {
            return;
        }
        o.set_channel(Some(new));
        // A larger maximum may take queued datagrams.
        self.channel_kick();
    }

    /// Changes whenever datagrams were queued that may go on a channel, or
    /// the channels' pipes changed: a driver's channel task that polled
    /// [`SessionCore::poll_channel`] waits for it to change (it is woken by
    /// [`CoreEvent::ChannelDatagrams`] and by the pipe events).
    pub fn channel_generation(&self) -> u64 {
        self.dgram().channel_gen
    }

    /// Whether the datagram channel of `pipe` may still be used: its
    /// outbound pipe is live, the session is not closed, and the peer did
    /// not establish the session without the channel. Once it is false, the
    /// driver ends the channel's task.
    pub fn channel_live(&self, pipe: PipeId) -> bool {
        self.state < State::Closing
            && !(self.is_established() && !self.features.carrier_datagrams)
            && self
                .out_ref(pipe.0)
                .is_some_and(|o| o.channel().is_some() && o.is_live())
    }

    /// Moves the queued datagrams that go on the datagram channel of `pipe`
    /// now to the end of `out`, each a whole channel datagram for the
    /// driver to send in order, outside the lock (EXTENSIONS.md Section
    /// 6.8). Returns [`SessionCore::channel_live`]. Datagrams returned
    /// count as sent; [`SessionCore::channel_send_failed`] counts those the
    /// carrier refused as dropped instead.
    pub fn poll_channel(&mut self, pipe: PipeId, out: &mut Vec<Bytes>) -> bool {
        let send_queue = self.config.datagram_send_queue;
        if !self.channel_live(pipe) {
            return false;
        }
        let Some(ch) = self.channel_for(pipe.0, false) else {
            return true;
        };
        let mut i = 0;
        loop {
            let Some((flow, data)) = self.dgram().send.get(i) else {
                return true;
            };
            let flow = *flow;
            let f = self.flow_of(flow);
            let n = f.map_or(0, |f| f.encoded_len()) + data.len();
            if self.datagram_pipe(flow).is_some() || channel::datagram_len(ch.id, n) > ch.max {
                i += 1;
                continue;
            }
            let was_full = self.dgram().send.len() >= send_queue;
            let Some((_, data)) = self.dgram_mut().send.remove(i) else {
                return true;
            };
            let mut b = BytesMut::with_capacity(channel::datagram_len(ch.id, n));
            let mut header = [0u8; 9 + 16];
            let mut h = channel::encode_header(ch.id, &mut header).unwrap_or(0);
            if let Some(f) = f {
                h += f.encode(&mut header[h..]).unwrap_or(0);
            }
            b.put_slice(&header[..h]);
            b.put_slice(&data);
            out.push(b.freeze());
            self.datagram_sent(f, data.len() as u64);
            self.stats.datagrams_sent_channel += 1;
            if was_full {
                self.events.push_back(CoreEvent::DatagramsUnblocked);
            }
        }
    }

    /// `n` channel datagrams of [`SessionCore::poll_channel`] were refused
    /// by the carrier: counted as dropped instead of sent (no fallback to
    /// a record: they were due when they were taken).
    pub fn channel_send_failed(&mut self, n: usize) {
        let n = n as u64;
        let s = &mut self.stats;
        s.datagrams_sent = s.datagrams_sent.saturating_sub(n);
        s.datagrams_sent_channel = s.datagrams_sent_channel.saturating_sub(n);
        s.datagrams_dropped_send += n;
    }

    /// `n` channel datagrams the driver dropped before handing them over
    /// (its queue was full): counted as received datagrams dropped.
    pub fn channel_dropped(&mut self, n: u64) {
        if n > 0 {
            self.count_dropped(n);
        }
    }

    /// A channel datagram received for `pipe`, its Pipe Stream ID removed
    /// (EXTENSIONS.md Section 6.8). Dropped and counted when the pipe is
    /// not an open inbound pipe of the session or the session did not
    /// negotiate the channel; otherwise anything but one DATAGRAM frame of
    /// type 0x30 closes the session with PROTOCOL_VIOLATION, and the frame
    /// is processed as one in a record on that pipe, without the
    /// accounting of a record (no PIPE_ACK position, no no-effect budget,
    /// no idle timer restart).
    pub fn receive_channel_datagram(&mut self, pipe: PipeId, frame: &[u8], now: Instant) {
        self.tick(now);
        if self.state >= State::Closing {
            return;
        }
        let open = self
            .att(pipe.0)
            .and_then(|a| a.inp())
            .is_some_and(|p| p.state() == InState::Open);
        if !open || !self.is_established() || !self.features.carrier_datagrams {
            self.count_dropped(1);
            return;
        }
        let gates = self.receive_gates();
        let d = match channel::decode_frame(frame, &gates) {
            Ok(d) => d,
            Err(e) => {
                self.protocol_error(e, now);
                return;
            }
        };
        // A subset of datagrams_received: those counted now (a held one
        // counts when it is delivered).
        let before = self.stats.datagrams_received;
        self.rx_channel = true;
        let r = self.on_datagram(d, FrameType::DATAGRAM.0);
        self.rx_channel = false;
        if let Err(e) = r {
            self.protocol_error(e, now);
            return;
        }
        self.stats.datagrams_received_channel += self.stats.datagrams_received - before;
    }

    /// The pipe whose datagram channel the datagrams that go with the
    /// control frames may take: the bootstrap pipe outside multipath, the
    /// first live pipe of the control order in a multipath session
    /// (MULTIPATH.md Section 11.1 rule S7). Unlike the control pipe it does
    /// not change while a carrier refuses bytes.
    fn channel_pipe(&self) -> Option<u64> {
        if self.mp.is_none() {
            return self.atts.iter().find(|a| a.out().is_some()).map(|a| a.id());
        }
        let views = self.views();
        views
            .control()
            .iter()
            .map(|&i| self.atts.at(i))
            .find(|a| a.out().is_some_and(OutPipe::is_live))
            .map(|a| a.id())
    }

    /// The datagram channel that datagrams for `pipe` may take now: the
    /// channel is negotiated and has room, `pipe` is the channel pipe, and
    /// its records are not shaped (`shaped`: the batch being built is).
    pub(super) fn channel_for(&self, pipe: u64, shaped: bool) -> Option<Channel> {
        if !self.features.carrier_datagrams || shaped || self.shape_shaped(pipe) {
            return None;
        }
        let ch = self.out_ref(pipe)?.channel().filter(|c| c.max > 0)?;
        (self.channel_pipe() == Some(pipe)).then_some(ch)
    }

    /// Whether a queued datagram goes on a datagram channel rather than in
    /// a record: it does not follow its stream's opening frame, and fits
    /// the channel of the channel pipe.
    pub(super) fn channel_takes(&self, flow: Option<(u64, u64)>, len: usize) -> bool {
        if !self.features.carrier_datagrams || self.datagram_pipe(flow).is_some() {
            return false;
        }
        let Some(ch) = self.channel_pipe().and_then(|p| self.channel_for(p, false)) else {
            return false;
        };
        let n = self.flow_of(flow).map_or(0, |f| f.encoded_len()) + len;
        channel::datagram_len(ch.id, n) <= ch.max
    }

    /// The flow prefix of a queued datagram, with datagram flows in use.
    pub(super) fn flow_of(&self, flow: Option<(u64, u64)>) -> Option<Flow> {
        match (self.features.datagram_flows, flow) {
            (false, _) => None,
            (true, None) => Some(Flow::Session),
            (true, Some((stream_id, context))) => Some(Flow::Stream { stream_id, context }),
        }
    }

    /// Datagrams may wait for a channel: the channel tasks look again.
    pub(super) fn channel_kick(&mut self) {
        if !self.atts.outs().any(|o| o.channel().is_some()) {
            return;
        }
        let d = self.dgram_mut();
        d.channel_gen = d.channel_gen.wrapping_add(1);
        if !self
            .events
            .iter()
            .any(|e| matches!(e, CoreEvent::ChannelDatagrams))
        {
            self.events.push_back(CoreEvent::ChannelDatagrams);
        }
    }
}
