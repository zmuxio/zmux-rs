//! Frames (SPEC.md Section 4): QUIC version 1 frames, the QMux-02 frames,
//! the QUIC extension frames RESET_STREAM_AT and DATAGRAM, and the zmux
//! extension and multipath frames.
//!
//! Decoding borrows from the input: payloads (STREAM data, DATAGRAM data,
//! reasons, locators, parameter blocks) are slices of it and nothing is
//! copied or allocated. Every frame type has an exact `encoded_len` and an
//! `encode` that writes into a caller-provided buffer.

mod entries;
mod ext;
mod pipe;
mod qmux;
mod quic;

use std::fmt;

pub use ext::{GoAwayFrame, Priority, PriorityUpdate};
pub use pipe::{
    JOIN_TOKEN_LEN, JoinDirection, LANE_KEY_LEN, MAX_JOIN_FRAME_LEN, MAX_LOCATOR_LEN, PipeAbandon,
    PipeAck, PipeAckEntry, PipeJoin, PipeLane, PipeStatus, PipeStatusValue,
};
pub use qmux::{QxPing, QxTransportParameters};
use quic::parse_stream_header;
pub use quic::{
    ConnectionClose, DataBlocked, Datagram, MAX_COUNT, MaxData, MaxStreamData, MaxStreams, Padding,
    ResetStream, ResetStreamAt, StopSending, Stream, StreamDataBlocked, StreamHeader,
    StreamsBlocked,
};

use super::codec::{Cursor, Short, Writer};
use super::draft;

// The QMux draft's frame types, for patterns.
const QX_TP: u64 = draft::CURRENT.transport_parameters;
const QX_PING_REQ: u64 = draft::CURRENT.ping_request;
const QX_PING_RESP: u64 = draft::CURRENT.ping_response;
use super::error::{EncodeError, Error};
use super::varint;

/// A frame type value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameType(pub u64);

impl FrameType {
    /// PADDING.
    pub const PADDING: Self = Self(0x00);
    /// PING (prohibited).
    pub const PING: Self = Self(0x01);
    /// RESET_STREAM.
    pub const RESET_STREAM: Self = Self(0x04);
    /// STOP_SENDING.
    pub const STOP_SENDING: Self = Self(0x05);
    /// STREAM without the OFF, LEN and FIN bits.
    pub const STREAM: Self = Self(0x08);
    /// MAX_DATA.
    pub const MAX_DATA: Self = Self(0x10);
    /// MAX_STREAM_DATA.
    pub const MAX_STREAM_DATA: Self = Self(0x11);
    /// MAX_STREAMS for bidirectional streams.
    pub const MAX_STREAMS_BIDI: Self = Self(0x12);
    /// MAX_STREAMS for unidirectional streams.
    pub const MAX_STREAMS_UNI: Self = Self(0x13);
    /// DATA_BLOCKED.
    pub const DATA_BLOCKED: Self = Self(0x14);
    /// STREAM_DATA_BLOCKED.
    pub const STREAM_DATA_BLOCKED: Self = Self(0x15);
    /// STREAMS_BLOCKED for bidirectional streams.
    pub const STREAMS_BLOCKED_BIDI: Self = Self(0x16);
    /// STREAMS_BLOCKED for unidirectional streams.
    pub const STREAMS_BLOCKED_UNI: Self = Self(0x17);
    /// CONNECTION_CLOSE with a transport error code.
    pub const CONNECTION_CLOSE: Self = Self(0x1c);
    /// CONNECTION_CLOSE with an application error code.
    pub const CONNECTION_CLOSE_APPLICATION: Self = Self(0x1d);
    /// RESET_STREAM_AT.
    pub const RESET_STREAM_AT: Self = Self(0x24);
    /// DATAGRAM without a Length field.
    pub const DATAGRAM: Self = Self(0x30);
    /// DATAGRAM with a Length field.
    pub const DATAGRAM_LEN: Self = Self(0x31);
    /// QX_TRANSPORT_PARAMETERS ([`crate::proto::draft`]).
    pub const QX_TRANSPORT_PARAMETERS: Self = Self(draft::CURRENT.transport_parameters);
    /// QX_PING request ([`crate::proto::draft`]).
    pub const QX_PING_REQUEST: Self = Self(draft::CURRENT.ping_request);
    /// QX_PING response ([`crate::proto::draft`]).
    pub const QX_PING_RESPONSE: Self = Self(draft::CURRENT.ping_response);
    /// GOAWAY.
    pub const GOAWAY: Self = Self(0x1911_f43e);
    /// PRIORITY_UPDATE.
    pub const PRIORITY_UPDATE: Self = Self(0x073d_08cf);
    /// PIPE_JOIN.
    pub const PIPE_JOIN: Self = Self(0x1a24_de36);
    /// PIPE_ACK.
    pub const PIPE_ACK: Self = Self(0x0b2b_3eeb);
    /// PIPE_LANE.
    pub const PIPE_LANE: Self = Self(0x3a05_a1c9);
    /// PIPE_PING.
    pub const PIPE_PING: Self = Self(0x269b_43e6);
    /// PIPE_ABANDON.
    pub const PIPE_ABANDON: Self = Self(0x23b3_5b74);
    /// PIPE_STATUS.
    pub const PIPE_STATUS: Self = Self(0x227b_2811);

    /// The registry name, if the type is in the registry (REGISTRY.md
    /// Section 2), prohibited QUIC types included.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x00 => "PADDING",
            0x01 => "PING",
            0x02 | 0x03 => "ACK",
            0x04 => "RESET_STREAM",
            0x05 => "STOP_SENDING",
            0x06 => "CRYPTO",
            0x07 => "NEW_TOKEN",
            0x08..=0x0f => "STREAM",
            0x10 => "MAX_DATA",
            0x11 => "MAX_STREAM_DATA",
            0x12 | 0x13 => "MAX_STREAMS",
            0x14 => "DATA_BLOCKED",
            0x15 => "STREAM_DATA_BLOCKED",
            0x16 | 0x17 => "STREAMS_BLOCKED",
            0x18 => "NEW_CONNECTION_ID",
            0x19 => "RETIRE_CONNECTION_ID",
            0x1a => "PATH_CHALLENGE",
            0x1b => "PATH_RESPONSE",
            0x1c | 0x1d => "CONNECTION_CLOSE",
            0x1e => "HANDSHAKE_DONE",
            0x24 => "RESET_STREAM_AT",
            0x30 | 0x31 => "DATAGRAM",
            QX_TP => "QX_TRANSPORT_PARAMETERS",
            QX_PING_REQ | QX_PING_RESP => "QX_PING",
            0x1911_f43e => "GOAWAY",
            0x073d_08cf => "PRIORITY_UPDATE",
            0x1a24_de36 => "PIPE_JOIN",
            0x0b2b_3eeb => "PIPE_ACK",
            0x3a05_a1c9 => "PIPE_LANE",
            0x269b_43e6 => "PIPE_PING",
            0x23b3_5b74 => "PIPE_ABANDON",
            0x227b_2811 => "PIPE_STATUS",
            _ => return None,
        })
    }

    /// Whether this is one of the STREAM types 0x08 to 0x0f.
    pub const fn is_stream(self) -> bool {
        self.0 >= 0x08 && self.0 <= 0x0f
    }
}

impl fmt::Debug for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name}({:#x})", self.0),
            None => write!(f, "FrameType({:#x})", self.0),
        }
    }
}

/// The type of a stream: the second least significant bit of its ID, and the
/// low bit of the MAX_STREAMS and STREAMS_BLOCKED types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Bidirectional.
    Bidi,
    /// Unidirectional.
    Uni,
}

impl Dir {
    const fn from_low_bit(frame_type: u64) -> Self {
        if frame_type & 1 == 0 {
            Self::Bidi
        } else {
            Self::Uni
        }
    }
}

/// What a receiver accepts beyond the frames that are always available
/// (SPEC.md Section 4.2). A frame whose gate is closed is an unknown frame:
/// FRAME_ENCODING_ERROR, or PROTOCOL_VIOLATION for DATAGRAM (RFC 9221
/// Section 3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Gates {
    /// The receiver announced `reset_stream_at`.
    pub reset_stream_at: bool,
    /// The receiver's `max_datagram_frame_size`: the largest DATAGRAM frame
    /// it accepts, 0 if none.
    pub max_datagram_frame_size: u64,
    /// GOAWAY is in use.
    pub goaway: bool,
    /// PRIORITY_UPDATE is in use.
    pub priority: bool,
    /// Multipath is in use (PIPE_* frames).
    pub multipath: bool,
    /// Pipe acknowledgement without multipath is in use (PIPE_ACK only,
    /// MULTIPATH.md Section 3.5).
    pub pipe_ack: bool,
    /// Lanes are available toward the receiver (PIPE_LANE, MULTIPATH.md
    /// Section 3.6).
    pub lanes: bool,
}

impl Gates {
    /// Nothing beyond the always-available frames.
    pub const NONE: Self = Self {
        reset_stream_at: false,
        max_datagram_frame_size: 0,
        goaway: false,
        priority: false,
        multipath: false,
        pipe_ack: false,
        lanes: false,
    };

    /// Every gate open, with no DATAGRAM size limit.
    pub const ALL: Self = Self {
        reset_stream_at: true,
        max_datagram_frame_size: u64::MAX,
        goaway: true,
        priority: true,
        multipath: true,
        pipe_ack: true,
        lanes: true,
    };
}

/// A decoded frame, borrowing its payload from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame<'a> {
    /// A run of PADDING frames.
    Padding(Padding),
    /// RESET_STREAM.
    ResetStream(ResetStream),
    /// STOP_SENDING.
    StopSending(StopSending),
    /// STREAM.
    Stream(Stream<'a>),
    /// MAX_DATA.
    MaxData(MaxData),
    /// MAX_STREAM_DATA.
    MaxStreamData(MaxStreamData),
    /// MAX_STREAMS.
    MaxStreams(MaxStreams),
    /// DATA_BLOCKED.
    DataBlocked(DataBlocked),
    /// STREAM_DATA_BLOCKED.
    StreamDataBlocked(StreamDataBlocked),
    /// STREAMS_BLOCKED.
    StreamsBlocked(StreamsBlocked),
    /// CONNECTION_CLOSE.
    ConnectionClose(ConnectionClose<'a>),
    /// RESET_STREAM_AT.
    ResetStreamAt(ResetStreamAt),
    /// DATAGRAM.
    Datagram(Datagram<'a>),
    /// QX_TRANSPORT_PARAMETERS.
    TransportParameters(QxTransportParameters<'a>),
    /// QX_PING.
    QxPing(QxPing),
    /// GOAWAY.
    GoAway(GoAwayFrame),
    /// PRIORITY_UPDATE.
    PriorityUpdate(PriorityUpdate),
    /// PIPE_JOIN.
    PipeJoin(PipeJoin<'a>),
    /// PIPE_ACK.
    PipeAck(PipeAck<'a>),
    /// PIPE_LANE.
    PipeLane(PipeLane),
    /// PIPE_PING.
    PipePing,
    /// PIPE_ABANDON.
    PipeAbandon(PipeAbandon),
    /// PIPE_STATUS.
    PipeStatus(PipeStatus),
}

/// Why a decode stopped.
enum Fail {
    /// The input ended inside the frame.
    Short,
    /// The frame is invalid.
    Invalid(Error),
}

impl From<Short> for Fail {
    fn from(_: Short) -> Self {
        Self::Short
    }
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}

const PIPE_PING_LEN: usize = varint::len(FrameType::PIPE_PING.0);

impl<'a> Frame<'a> {
    /// Decodes one frame from the start of `buf`, which must hold the rest
    /// of a record: a frame without a Length field (STREAM without the LEN
    /// bit, DATAGRAM type 0x30) extends to the end of `buf`.
    ///
    /// Returns the frame and the number of bytes it occupied. A frame that
    /// does not fit in `buf` is truncated (FRAME_ENCODING_ERROR).
    pub fn decode(buf: &'a [u8], gates: &Gates) -> Result<(Self, usize), Error> {
        match decode(buf, gates) {
            Ok(r) => Ok(r),
            Err(Fail::Short) => Err(truncated(buf)),
            Err(Fail::Invalid(e)) => Err(e),
        }
    }

    /// The frame type value this frame encodes with.
    pub fn frame_type(&self) -> FrameType {
        FrameType(match self {
            Self::Padding(_) => FrameType::PADDING.0,
            Self::ResetStream(_) => FrameType::RESET_STREAM.0,
            Self::StopSending(_) => FrameType::STOP_SENDING.0,
            Self::Stream(f) => f.header().frame_type(),
            Self::MaxData(_) => FrameType::MAX_DATA.0,
            Self::MaxStreamData(_) => FrameType::MAX_STREAM_DATA.0,
            Self::MaxStreams(f) => match f.dir {
                Dir::Bidi => FrameType::MAX_STREAMS_BIDI.0,
                Dir::Uni => FrameType::MAX_STREAMS_UNI.0,
            },
            Self::DataBlocked(_) => FrameType::DATA_BLOCKED.0,
            Self::StreamDataBlocked(_) => FrameType::STREAM_DATA_BLOCKED.0,
            Self::StreamsBlocked(f) => match f.dir {
                Dir::Bidi => FrameType::STREAMS_BLOCKED_BIDI.0,
                Dir::Uni => FrameType::STREAMS_BLOCKED_UNI.0,
            },
            Self::ConnectionClose(f) if f.application => FrameType::CONNECTION_CLOSE_APPLICATION.0,
            Self::ConnectionClose(_) => FrameType::CONNECTION_CLOSE.0,
            Self::ResetStreamAt(_) => FrameType::RESET_STREAM_AT.0,
            Self::Datagram(f) if f.explicit_len => FrameType::DATAGRAM_LEN.0,
            Self::Datagram(_) => FrameType::DATAGRAM.0,
            Self::TransportParameters(_) => FrameType::QX_TRANSPORT_PARAMETERS.0,
            Self::QxPing(f) if f.response => FrameType::QX_PING_RESPONSE.0,
            Self::QxPing(_) => FrameType::QX_PING_REQUEST.0,
            Self::GoAway(_) => FrameType::GOAWAY.0,
            Self::PriorityUpdate(_) => FrameType::PRIORITY_UPDATE.0,
            Self::PipeJoin(_) => FrameType::PIPE_JOIN.0,
            Self::PipeAck(_) => FrameType::PIPE_ACK.0,
            Self::PipeLane(_) => FrameType::PIPE_LANE.0,
            Self::PipePing => FrameType::PIPE_PING.0,
            Self::PipeAbandon(_) => FrameType::PIPE_ABANDON.0,
            Self::PipeStatus(_) => FrameType::PIPE_STATUS.0,
        })
    }

    /// Whether the frame is ack-eliciting (SPEC.md Section 1.4): anything
    /// but PADDING, PIPE_ACK and CONNECTION_CLOSE.
    pub const fn is_ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Self::Padding(_) | Self::PipeAck(_) | Self::ConnectionClose(_)
        )
    }

    /// Length of the encoding.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Padding(f) => f.encoded_len(),
            Self::ResetStream(f) => f.encoded_len(),
            Self::StopSending(f) => f.encoded_len(),
            Self::Stream(f) => f.encoded_len(),
            Self::MaxData(f) => f.encoded_len(),
            Self::MaxStreamData(f) => f.encoded_len(),
            Self::MaxStreams(f) => f.encoded_len(),
            Self::DataBlocked(f) => f.encoded_len(),
            Self::StreamDataBlocked(f) => f.encoded_len(),
            Self::StreamsBlocked(f) => f.encoded_len(),
            Self::ConnectionClose(f) => f.encoded_len(),
            Self::ResetStreamAt(f) => f.encoded_len(),
            Self::Datagram(f) => f.encoded_len(),
            Self::TransportParameters(f) => f.encoded_len(),
            Self::QxPing(f) => f.encoded_len(),
            Self::GoAway(f) => f.encoded_len(),
            Self::PriorityUpdate(f) => f.encoded_len(),
            Self::PipeJoin(f) => f.encoded_len(),
            Self::PipeAck(f) => f.encoded_len(),
            Self::PipeLane(f) => f.encoded_len(),
            Self::PipePing => PIPE_PING_LEN,
            Self::PipeAbandon(f) => f.encoded_len(),
            Self::PipeStatus(f) => f.encoded_len(),
        }
    }

    /// Writes the frame to the start of `buf` and returns its length, which
    /// equals [`Frame::encoded_len`]. On error the contents of `buf` are
    /// unspecified.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        self.write(&mut w)?;
        Ok(w.pos())
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::Padding(f) => f.write(w),
            Self::ResetStream(f) => f.write(w),
            Self::StopSending(f) => f.write(w),
            Self::Stream(f) => f.write(w),
            Self::MaxData(f) => f.write(w),
            Self::MaxStreamData(f) => f.write(w),
            Self::MaxStreams(f) => f.write(w),
            Self::DataBlocked(f) => f.write(w),
            Self::StreamDataBlocked(f) => f.write(w),
            Self::StreamsBlocked(f) => f.write(w),
            Self::ConnectionClose(f) => f.write(w),
            Self::ResetStreamAt(f) => f.write(w),
            Self::Datagram(f) => f.write(w),
            Self::TransportParameters(f) => f.write(w),
            Self::QxPing(f) => f.write(w),
            Self::GoAway(f) => f.write(w),
            Self::PriorityUpdate(f) => f.write(w),
            Self::PipeJoin(f) => f.write(w),
            Self::PipeAck(f) => f.write(w),
            Self::PipeLane(f) => f.write(w),
            Self::PipePing => w.varint(FrameType::PIPE_PING.0),
            Self::PipeAbandon(f) => f.write(w),
            Self::PipeStatus(f) => f.write(w),
        }
    }
}

macro_rules! encode_methods {
    ($($ty:ident$(<$lt:lifetime>)?),* $(,)?) => {
        $(
            impl$(<$lt>)? $ty$(<$lt>)? {
                /// Writes the frame to the start of `buf` and returns its
                /// length. On error the contents of `buf` are unspecified.
                pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
                    let mut w = Writer::new(buf);
                    self.write(&mut w)?;
                    Ok(w.pos())
                }
            }
        )*
    };
}

encode_methods!(
    Padding,
    ResetStream,
    StopSending,
    Stream<'a>,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    ConnectionClose<'a>,
    ResetStreamAt,
    Datagram<'a>,
    QxTransportParameters<'a>,
    QxPing,
    GoAwayFrame,
    PriorityUpdate,
    PipeJoin<'a>,
    PipeAck<'a>,
    PipeLane,
    PipeAbandon,
    PipeStatus,
);

/// The truncation error for a frame that starts at `buf`.
fn truncated(buf: &[u8]) -> Error {
    let ty = varint::decode(buf).map_or(0, |(t, _)| t);
    Error::frame_encoding(ty, "truncated frame")
}

/// Decodes one frame from `buf`, the rest of a record.
fn decode<'a>(buf: &'a [u8], gates: &Gates) -> Result<(Frame<'a>, usize), Fail> {
    let mut c = Cursor::new(buf);
    let (ty, width) = c.varint_with_width()?;
    if width != varint::len(ty) {
        return Err(Error::protocol_violation(ty, "frame type not minimally encoded").into());
    }
    let frame = match ty {
        0x00 => Frame::Padding(Padding {
            len: 1 + c.skip_run(0),
        }),
        0x04 => Frame::ResetStream(ResetStream::read(&mut c)?),
        0x05 => Frame::StopSending(StopSending::read(&mut c)?),
        0x08..=0x0f => {
            let (h, header_len) = parse_stream_header(buf, buf.len() as u64)?.ok_or(Fail::Short)?;
            c = Cursor::new(buf);
            c.advance(header_len)?;
            Frame::Stream(Stream {
                stream_id: h.stream_id,
                offset: h.offset,
                data: c.bytes(h.len)?,
                fin: h.fin,
                explicit_offset: h.explicit_offset,
                explicit_len: h.explicit_len,
            })
        }
        0x10 => Frame::MaxData(MaxData::read(&mut c)?),
        0x11 => Frame::MaxStreamData(MaxStreamData::read(&mut c)?),
        0x12 | 0x13 => Frame::MaxStreams(MaxStreams::read(&mut c, ty)?),
        0x14 => Frame::DataBlocked(DataBlocked::read(&mut c)?),
        0x15 => Frame::StreamDataBlocked(StreamDataBlocked::read(&mut c)?),
        0x16 | 0x17 => Frame::StreamsBlocked(StreamsBlocked::read(&mut c, ty)?),
        0x1c | 0x1d => Frame::ConnectionClose(ConnectionClose::read(&mut c, ty)?),
        0x24 => {
            gate(gates.reset_stream_at, ty, "RESET_STREAM_AT not announced")?;
            Frame::ResetStreamAt(ResetStreamAt::read(&mut c, ty)?)
        }
        0x30 | 0x31 => {
            if gates.max_datagram_frame_size == 0 {
                return Err(Error::protocol_violation(ty, "DATAGRAM not announced").into());
            }
            let data = if ty == FrameType::DATAGRAM_LEN.0 {
                let len = c.varint()?;
                c.bytes(len)?
            } else {
                c.rest()
            };
            if c.pos() as u64 > gates.max_datagram_frame_size {
                return Err(Error::protocol_violation(ty, "DATAGRAM larger than announced").into());
            }
            Frame::Datagram(Datagram {
                data,
                explicit_len: ty == FrameType::DATAGRAM_LEN.0,
            })
        }
        0x01..=0x03 | 0x06 | 0x07 | 0x18..=0x1b | 0x1e => {
            return Err(Error::frame_encoding(ty, "prohibited frame type").into());
        }
        QX_TP => Frame::TransportParameters(QxTransportParameters::read(&mut c)?),
        QX_PING_REQ | QX_PING_RESP => Frame::QxPing(QxPing::read(&mut c, ty)?),
        0x1911_f43e => {
            gate(gates.goaway, ty, "GOAWAY not in use")?;
            Frame::GoAway(GoAwayFrame::read(&mut c, ty)?)
        }
        0x073d_08cf => {
            gate(gates.priority, ty, "PRIORITY_UPDATE not in use")?;
            Frame::PriorityUpdate(PriorityUpdate::read(&mut c, ty)?)
        }
        0x1a24_de36 => {
            gate(gates.multipath, ty, "multipath not in use")?;
            Frame::PipeJoin(PipeJoin::read(&mut c, ty)?)
        }
        0x0b2b_3eeb => {
            gate(
                gates.multipath || gates.pipe_ack,
                ty,
                "pipe acknowledgement not in use",
            )?;
            Frame::PipeAck(PipeAck::read(&mut c, ty)?)
        }
        0x3a05_a1c9 => {
            gate(gates.lanes, ty, "lanes not available")?;
            Frame::PipeLane(PipeLane::read(&mut c)?)
        }
        0x269b_43e6 => {
            gate(gates.multipath, ty, "multipath not in use")?;
            Frame::PipePing
        }
        0x23b3_5b74 => {
            gate(gates.multipath, ty, "multipath not in use")?;
            Frame::PipeAbandon(PipeAbandon::read(&mut c)?)
        }
        0x227b_2811 => {
            gate(gates.multipath, ty, "multipath not in use")?;
            Frame::PipeStatus(PipeStatus::read(&mut c, ty)?)
        }
        _ => return Err(Error::frame_encoding(ty, "unknown frame type").into()),
    };
    Ok((frame, c.pos()))
}

#[inline]
fn gate(open: bool, ty: u64, reason: &'static str) -> Result<(), Error> {
    if open {
        Ok(())
    } else {
        Err(Error::frame_encoding(ty, reason))
    }
}

/// Iterator over the frames of a complete record body.
///
/// Yields `Err` once at the first invalid frame and then stops.
#[derive(Debug, Clone)]
pub struct Frames<'a> {
    rest: &'a [u8],
    gates: Gates,
}

impl<'a> Frames<'a> {
    /// Iterates over `body`, the Frames field of one record.
    pub const fn new(body: &'a [u8], gates: Gates) -> Self {
        Self { rest: body, gates }
    }

    /// Updates the gates for the frames that follow, for example after the
    /// transport parameters at the start of the record were processed.
    pub fn set_gates(&mut self, gates: Gates) {
        self.gates = gates;
    }

    /// The bytes not yet decoded.
    pub const fn remaining(&self) -> &'a [u8] {
        self.rest
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match Frame::decode(self.rest, &self.gates) {
            Ok((frame, n)) => {
                self.rest = self.rest.get(n..).unwrap_or_default();
                Some(Ok(frame))
            }
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}
