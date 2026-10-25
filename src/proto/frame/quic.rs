//! QUIC version 1 frames (RFC 9000 Section 19) and the QUIC extension frames
//! RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-11) and DATAGRAM
//! (RFC 9221) as zmux uses them (SPEC.md Section 4.3).

use super::{Dir, Fail, FrameType};
use crate::proto::codec::{Cursor, Writer};
use crate::proto::error::{EncodeError, Error};
use crate::proto::varint::{self, len as vlen};

/// The largest value of a stream count (MAX_STREAMS, STREAMS_BLOCKED, GOAWAY
/// watermarks) and of pipe ID limits: 2^60.
pub const MAX_COUNT: u64 = 1 << 60;

pub(super) const STREAM_OFF: u64 = 0x04;
pub(super) const STREAM_LEN: u64 = 0x02;
pub(super) const STREAM_FIN: u64 = 0x01;

/// PADDING (0x00). Each wire PADDING frame is one zero byte; the decoder
/// reports a run of them as one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padding {
    /// Number of PADDING frames (bytes) in the run.
    pub len: usize,
}

impl Padding {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        self.len
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.len == 0 {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.zeros(self.len)
    }
}

/// RESET_STREAM (0x04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStream {
    /// Stream ID.
    pub stream_id: u64,
    /// Application error code.
    pub error_code: u64,
    /// Final size of the stream.
    pub final_size: u64,
}

impl ResetStream {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        1 + vlen(self.stream_id) + vlen(self.error_code) + vlen(self.final_size)
    }

    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self {
            stream_id: c.varint()?,
            error_code: c.varint()?,
            final_size: c.varint()?,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::RESET_STREAM.0)?;
        w.varint(self.stream_id)?;
        w.varint(self.error_code)?;
        w.varint(self.final_size)
    }
}

/// STOP_SENDING (0x05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSending {
    /// Stream ID.
    pub stream_id: u64,
    /// Application error code.
    pub error_code: u64,
}

impl StopSending {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        1 + vlen(self.stream_id) + vlen(self.error_code)
    }

    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self {
            stream_id: c.varint()?,
            error_code: c.varint()?,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::STOP_SENDING.0)?;
        w.varint(self.stream_id)?;
        w.varint(self.error_code)
    }
}

/// The header of a STREAM frame (0x08 to 0x0f): everything but the data.
///
/// Senders write the header and then the data, either copied after it or
/// referenced separately in a gather write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader {
    /// Stream ID.
    pub stream_id: u64,
    /// Offset of the first data byte.
    pub offset: u64,
    /// Number of data bytes.
    pub len: u64,
    /// The FIN bit.
    pub fin: bool,
    /// Whether the Offset field is present. It is always present when
    /// `offset` is not 0; a frame at offset 0 may still carry it.
    pub explicit_offset: bool,
    /// Whether the Length field is present. Without it the data extends to
    /// the end of the record, so the frame must be the last one.
    pub explicit_len: bool,
}

impl StreamHeader {
    /// The frame type with the OFF, LEN and FIN bits.
    pub const fn frame_type(&self) -> u64 {
        let mut ty = FrameType::STREAM.0;
        if self.explicit_offset || self.offset != 0 {
            ty |= STREAM_OFF;
        }
        if self.explicit_len {
            ty |= STREAM_LEN;
        }
        if self.fin {
            ty |= STREAM_FIN;
        }
        ty
    }

    /// Length of the header encoding.
    pub const fn encoded_len(&self) -> usize {
        let ty = self.frame_type();
        let mut n = 1 + vlen(self.stream_id);
        if ty & STREAM_OFF != 0 {
            n += vlen(self.offset);
        }
        if self.explicit_len {
            n += vlen(self.len);
        }
        n
    }

    /// Writes the header.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        self.write(&mut w)?;
        Ok(w.pos())
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self
            .offset
            .checked_add(self.len)
            .is_none_or(|end| end > varint::MAX)
        {
            return Err(EncodeError::ValueOutOfRange);
        }
        let ty = self.frame_type();
        w.u8(ty as u8)?;
        w.varint(self.stream_id)?;
        if ty & STREAM_OFF != 0 {
            w.varint(self.offset)?;
        }
        if self.explicit_len {
            w.varint(self.len)?;
        }
        Ok(())
    }
}

/// Parses a STREAM frame header from `buf`, a prefix of the rest of a record
/// that is `record_rest` bytes long; the first byte is a STREAM type.
///
/// Returns `Ok(None)` when `buf` ends inside the header.
pub(super) fn parse_stream_header(
    buf: &[u8],
    record_rest: u64,
) -> Result<Option<(StreamHeader, usize)>, Error> {
    let mut c = Cursor::new(buf);
    let (Ok(ty), Ok(stream_id)) = (c.u8().map(u64::from), c.varint()) else {
        return Ok(None);
    };
    let explicit_offset = ty & STREAM_OFF != 0;
    let offset = if explicit_offset {
        match c.varint() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        }
    } else {
        0
    };
    let explicit_len = ty & STREAM_LEN != 0;
    let len = if explicit_len {
        let Ok(len) = c.varint() else {
            return Ok(None);
        };
        if len > record_rest.saturating_sub(c.pos() as u64) {
            return Err(Error::frame_encoding(ty, "STREAM data exceeds the record"));
        }
        len
    } else {
        record_rest.saturating_sub(c.pos() as u64)
    };
    if offset.checked_add(len).is_none_or(|end| end > varint::MAX) {
        return Err(Error::frame_encoding(
            ty,
            "STREAM offset plus length above 2^62-1",
        ));
    }
    let header = StreamHeader {
        stream_id,
        offset,
        len,
        fin: ty & STREAM_FIN != 0,
        explicit_offset,
        explicit_len,
    };
    Ok(Some((header, c.pos())))
}

/// STREAM (0x08 to 0x0f) with its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stream<'a> {
    /// Stream ID.
    pub stream_id: u64,
    /// Offset of the first data byte.
    pub offset: u64,
    /// The data.
    pub data: &'a [u8],
    /// The FIN bit.
    pub fin: bool,
    /// Whether the Offset field is present even though `offset` is 0.
    pub explicit_offset: bool,
    /// Whether the Length field is present.
    pub explicit_len: bool,
}

impl<'a> Stream<'a> {
    /// A STREAM frame with a Length field, and an Offset field when `offset`
    /// is not 0.
    pub const fn new(stream_id: u64, offset: u64, data: &'a [u8], fin: bool) -> Self {
        Self {
            stream_id,
            offset,
            data,
            fin,
            explicit_offset: false,
            explicit_len: true,
        }
    }

    /// The header of this frame.
    pub const fn header(&self) -> StreamHeader {
        StreamHeader {
            stream_id: self.stream_id,
            offset: self.offset,
            len: self.data.len() as u64,
            fin: self.fin,
            explicit_offset: self.explicit_offset,
            explicit_len: self.explicit_len,
        }
    }

    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        self.header().encoded_len() + self.data.len()
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        self.header().write(w)?;
        w.bytes(self.data)
    }
}

/// MAX_DATA (0x10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxData {
    /// Maximum Data: the session flow-control limit.
    pub maximum: u64,
}

/// MAX_STREAM_DATA (0x11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreamData {
    /// Stream ID.
    pub stream_id: u64,
    /// Maximum Stream Data.
    pub maximum: u64,
}

/// MAX_STREAMS (0x12 bidirectional, 0x13 unidirectional).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreams {
    /// Stream type.
    pub dir: Dir,
    /// Maximum Streams: a cumulative count, at most 2^60.
    pub maximum: u64,
}

/// DATA_BLOCKED (0x14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataBlocked {
    /// The session limit at which the sender is blocked.
    pub limit: u64,
}

/// STREAM_DATA_BLOCKED (0x15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDataBlocked {
    /// Stream ID.
    pub stream_id: u64,
    /// The stream limit at which the sender is blocked.
    pub limit: u64,
}

/// STREAMS_BLOCKED (0x16 bidirectional, 0x17 unidirectional).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamsBlocked {
    /// Stream type.
    pub dir: Dir,
    /// The stream-count limit at which the sender is blocked, at most 2^60.
    pub limit: u64,
}

macro_rules! single_value {
    ($ty:ident, $field:ident, $code:expr) => {
        impl $ty {
            /// Length of the encoding.
            pub const fn encoded_len(&self) -> usize {
                vlen($code) + vlen(self.$field)
            }

            pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
                w.varint($code)?;
                w.varint(self.$field)
            }
        }
    };
}

single_value!(MaxData, maximum, FrameType::MAX_DATA.0);
single_value!(DataBlocked, limit, FrameType::DATA_BLOCKED.0);

impl MaxData {
    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self {
            maximum: c.varint()?,
        })
    }
}

impl DataBlocked {
    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self { limit: c.varint()? })
    }
}

impl MaxStreamData {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        1 + vlen(self.stream_id) + vlen(self.maximum)
    }

    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self {
            stream_id: c.varint()?,
            maximum: c.varint()?,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::MAX_STREAM_DATA.0)?;
        w.varint(self.stream_id)?;
        w.varint(self.maximum)
    }
}

impl StreamDataBlocked {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        1 + vlen(self.stream_id) + vlen(self.limit)
    }

    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self {
            stream_id: c.varint()?,
            limit: c.varint()?,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::STREAM_DATA_BLOCKED.0)?;
        w.varint(self.stream_id)?;
        w.varint(self.limit)
    }
}

impl MaxStreams {
    const fn code(&self) -> u64 {
        match self.dir {
            Dir::Bidi => FrameType::MAX_STREAMS_BIDI.0,
            Dir::Uni => FrameType::MAX_STREAMS_UNI.0,
        }
    }

    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        1 + vlen(self.maximum)
    }

    pub(super) fn read(c: &mut Cursor<'_>, ty: u64) -> Result<Self, Fail> {
        let maximum = c.varint()?;
        if maximum > MAX_COUNT {
            return Err(Error::frame_encoding(ty, "MAX_STREAMS above 2^60").into());
        }
        Ok(Self {
            dir: Dir::from_low_bit(ty),
            maximum,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.maximum > MAX_COUNT {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.varint(self.code())?;
        w.varint(self.maximum)
    }
}

impl StreamsBlocked {
    const fn code(&self) -> u64 {
        match self.dir {
            Dir::Bidi => FrameType::STREAMS_BLOCKED_BIDI.0,
            Dir::Uni => FrameType::STREAMS_BLOCKED_UNI.0,
        }
    }

    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        1 + vlen(self.limit)
    }

    pub(super) fn read(c: &mut Cursor<'_>, ty: u64) -> Result<Self, Fail> {
        let limit = c.varint()?;
        if limit > MAX_COUNT {
            return Err(Error::frame_encoding(ty, "STREAMS_BLOCKED above 2^60").into());
        }
        Ok(Self {
            dir: Dir::from_low_bit(ty),
            limit,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.limit > MAX_COUNT {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.varint(self.code())?;
        w.varint(self.limit)
    }
}

/// CONNECTION_CLOSE (0x1c transport, 0x1d application).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionClose<'a> {
    /// Type 0x1d: the code is an application error code. Type 0x1c: a
    /// transport error code, and the frame carries `frame_type`.
    pub application: bool,
    /// Error code.
    pub error_code: u64,
    /// Frame Type of a transport close: the frame that caused the error, or
    /// 0. Not encoded for an application close.
    pub frame_type: u64,
    /// Reason Phrase (UTF-8 by convention; not validated).
    pub reason: &'a [u8],
}

impl<'a> ConnectionClose<'a> {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        let mut n = 1 + vlen(self.error_code) + vlen(self.reason.len() as u64) + self.reason.len();
        if !self.application {
            n += vlen(self.frame_type);
        }
        n
    }

    pub(super) fn read(c: &mut Cursor<'a>, ty: u64) -> Result<Self, Fail> {
        let application = ty == FrameType::CONNECTION_CLOSE_APPLICATION.0;
        let error_code = c.varint()?;
        let frame_type = if application { 0 } else { c.varint()? };
        let len = c.varint()?;
        let reason = c.bytes(len)?;
        Ok(Self {
            application,
            error_code,
            frame_type,
            reason,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.application {
            w.varint(FrameType::CONNECTION_CLOSE_APPLICATION.0)?;
            w.varint(self.error_code)?;
        } else {
            w.varint(FrameType::CONNECTION_CLOSE.0)?;
            w.varint(self.error_code)?;
            w.varint(self.frame_type)?;
        }
        w.varint(self.reason.len() as u64)?;
        w.bytes(self.reason)
    }
}

/// RESET_STREAM_AT (0x24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStreamAt {
    /// Stream ID.
    pub stream_id: u64,
    /// Application error code.
    pub error_code: u64,
    /// Final size of the stream.
    pub final_size: u64,
    /// Reliable Size: the data below it is still delivered. At most
    /// `final_size`.
    pub reliable_size: u64,
}

impl ResetStreamAt {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        1 + vlen(self.stream_id)
            + vlen(self.error_code)
            + vlen(self.final_size)
            + vlen(self.reliable_size)
    }

    pub(super) fn read(c: &mut Cursor<'_>, ty: u64) -> Result<Self, Fail> {
        let f = Self {
            stream_id: c.varint()?,
            error_code: c.varint()?,
            final_size: c.varint()?,
            reliable_size: c.varint()?,
        };
        if f.reliable_size > f.final_size {
            return Err(Error::frame_encoding(ty, "Reliable Size above Final Size").into());
        }
        Ok(f)
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.reliable_size > self.final_size {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.varint(FrameType::RESET_STREAM_AT.0)?;
        w.varint(self.stream_id)?;
        w.varint(self.error_code)?;
        w.varint(self.final_size)?;
        w.varint(self.reliable_size)
    }
}

/// DATAGRAM (0x30 without length, 0x31 with length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    /// Datagram Data. With datagram flows in use it starts with the flow
    /// prefix ([`crate::proto::payload::Flow`]).
    pub data: &'a [u8],
    /// Whether the Length field is present (type 0x31). Without it the data
    /// extends to the end of the record.
    pub explicit_len: bool,
}

impl<'a> Datagram<'a> {
    /// Splits the data into its flow and payload when datagram flows are in
    /// use (EXTENSIONS.md Section 6.3).
    pub fn flow(&self) -> Result<(crate::proto::payload::Flow, &'a [u8]), Error> {
        let ty = if self.explicit_len {
            FrameType::DATAGRAM_LEN.0
        } else {
            FrameType::DATAGRAM.0
        };
        crate::proto::payload::Flow::parse(self.data)
            .map_err(|e| Error::new(e.code(), ty, e.reason()))
    }

    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        let n = 1 + self.data.len();
        if self.explicit_len {
            n + vlen(self.data.len() as u64)
        } else {
            n
        }
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.explicit_len {
            w.varint(FrameType::DATAGRAM_LEN.0)?;
            w.varint(self.data.len() as u64)?;
        } else {
            w.varint(FrameType::DATAGRAM.0)?;
        }
        w.bytes(self.data)
    }
}
