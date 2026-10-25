//! zmux extension frames GOAWAY (EXTENSIONS.md Section 3) and
//! PRIORITY_UPDATE (EXTENSIONS.md Section 5).

use super::quic::MAX_COUNT;
use super::{Fail, FrameType};
use crate::proto::codec::{Cursor, Writer};
use crate::proto::error::{EncodeError, Error};
use crate::proto::varint::len as vlen;

/// GOAWAY (0x1911f43e).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoAwayFrame {
    /// Maximum Bidirectional Streams watermark (a count, at most 2^60).
    pub max_bidi: u64,
    /// Maximum Unidirectional Streams watermark (a count, at most 2^60).
    pub max_uni: u64,
    /// Application Protocol Error Code.
    pub error_code: u64,
}

impl GoAwayFrame {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        4 + vlen(self.max_bidi) + vlen(self.max_uni) + vlen(self.error_code)
    }

    pub(super) fn read(c: &mut Cursor<'_>, ty: u64) -> Result<Self, Fail> {
        let f = Self {
            max_bidi: c.varint()?,
            max_uni: c.varint()?,
            error_code: c.varint()?,
        };
        if f.max_bidi > MAX_COUNT || f.max_uni > MAX_COUNT {
            return Err(Error::frame_encoding(ty, "GOAWAY watermark above 2^60").into());
        }
        Ok(f)
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.max_bidi > MAX_COUNT || self.max_uni > MAX_COUNT {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.varint(FrameType::GOAWAY.0)?;
        w.varint(self.max_bidi)?;
        w.varint(self.max_uni)?;
        w.varint(self.error_code)
    }
}

/// An RFC 9218 priority: urgency 0 (most urgent) to 7 and the incremental
/// flag. On the wire it is one byte: urgency in the three most significant
/// bits, incremental in the next bit, then four bits that must be 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Priority {
    urgency: u8,
    incremental: bool,
}

impl Default for Priority {
    /// [`Priority::DEFAULT`].
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Priority {
    /// The RFC 9218 default: urgency 3, not incremental.
    pub const DEFAULT: Self = Self {
        urgency: 3,
        incremental: false,
    };

    /// Urgency 0, not incremental: control and signalling streams, which
    /// a multipath session also copies to a second pipe.
    pub const URGENT: Self = Self {
        urgency: 0,
        incremental: false,
    };

    /// Urgency 7, incremental: bulk transfers that should never hold
    /// anything else back.
    pub const BACKGROUND: Self = Self {
        urgency: 7,
        incremental: true,
    };

    /// Creates a priority; `None` if `urgency` is above 7.
    pub const fn new(urgency: u8, incremental: bool) -> Option<Self> {
        if urgency > 7 {
            None
        } else {
            Some(Self {
                urgency,
                incremental,
            })
        }
    }

    /// Urgency, 0 to 7.
    pub const fn urgency(self) -> u8 {
        self.urgency
    }

    /// Whether the stream is incremental.
    pub const fn incremental(self) -> bool {
        self.incremental
    }

    /// The wire byte.
    pub const fn to_byte(self) -> u8 {
        (self.urgency << 5) | if self.incremental { 0x10 } else { 0 }
    }

    /// Parses the wire byte; `None` if a reserved low bit is set.
    pub const fn from_byte(b: u8) -> Option<Self> {
        if b & 0x0f != 0 {
            None
        } else {
            Some(Self {
                urgency: b >> 5,
                incremental: b & 0x10 != 0,
            })
        }
    }
}

/// PRIORITY_UPDATE (0x073d08cf).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityUpdate {
    /// Stream ID.
    pub stream_id: u64,
    /// Sequence Number, per stream and sender, starting at 1.
    pub sequence: u64,
    /// The requested priority of the receiver's sending part.
    pub priority: Priority,
}

impl PriorityUpdate {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        4 + vlen(self.stream_id) + vlen(self.sequence) + 1
    }

    pub(super) fn read(c: &mut Cursor<'_>, ty: u64) -> Result<Self, Fail> {
        let stream_id = c.varint()?;
        let sequence = c.varint()?;
        let priority = Priority::from_byte(c.u8()?).ok_or(Error::frame_encoding(
            ty,
            "PRIORITY_UPDATE reserved bits set",
        ))?;
        Ok(Self {
            stream_id,
            sequence,
            priority,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::PRIORITY_UPDATE.0)?;
        w.varint(self.stream_id)?;
        w.varint(self.sequence)?;
        w.u8(self.priority.to_byte())
    }
}
