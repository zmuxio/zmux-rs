//! Multipath frames (MULTIPATH.md Sections 5.1, 6.2, 6.4, 8.1 and 9).

use super::entries::Entries;
use super::{Fail, FrameType};
use crate::proto::codec::{Cursor, Writer};
use crate::proto::error::{EncodeError, Error};
use crate::proto::varint::len as vlen;

/// The largest PIPE_JOIN frame, from Type to Join Token.
pub const MAX_JOIN_FRAME_LEN: usize = 64;
/// The largest Session Locator.
pub const MAX_LOCATOR_LEN: usize = 16;
/// The length of a Join Token.
pub const JOIN_TOKEN_LEN: usize = 16;

const FLAG_DIRECTION_MASK: u8 = 0x03;
const FLAG_CARRIER_BOUND: u8 = 0x04;
const FLAG_STANDBY: u8 = 0x08;
const FLAG_RESERVED_MASK: u8 = 0xf0;

/// Direction of an attachment, named from its joiner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JoinDirection {
    /// Joiner to acceptor.
    Up,
    /// Acceptor to joiner.
    Down,
    /// Both directions (a bidirectional carrier).
    Bidi,
}

impl JoinDirection {
    /// The value of the direction bits of the PIPE_JOIN Flags.
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Up => 0,
            Self::Down => 1,
            Self::Bidi => 2,
        }
    }

    /// Parses the direction bits; 3 is invalid.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Up),
            1 => Some(Self::Down),
            2 => Some(Self::Bidi),
            _ => None,
        }
    }
}

/// PIPE_JOIN (0x1a24de36).
///
/// The Join Token covers the frame bytes from Type through Priority as
/// received; see [`crate::proto::keys::verify_join`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeJoin<'a> {
    /// Session Locator of the acceptor, 1 to 16 bytes.
    pub locator: &'a [u8],
    /// Pipe ID of the new attachment.
    pub pipe_id: u64,
    /// Direction of the attachment.
    pub direction: JoinDirection,
    /// Whether the token covers the new carrier's TLS exporter.
    pub carrier_bound: bool,
    /// Fate Group of the attachment; 0 means independent.
    pub fate_group: u64,
    /// The joiner's initial request for the acceptor's outbound direction
    /// (MULTIPATH.md Section 9, sequence number 0): standby and priority.
    /// For direction up the joiner sends neither and the acceptor ignores
    /// both.
    pub standby: bool,
    /// See `standby`.
    pub priority: u64,
    /// Join Token.
    pub token: [u8; JOIN_TOKEN_LEN],
}

impl<'a> PipeJoin<'a> {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        vlen(FrameType::PIPE_JOIN.0)
            + 1
            + self.locator.len()
            + vlen(self.pipe_id)
            + 1
            + vlen(self.fate_group)
            + vlen(self.priority)
            + JOIN_TOKEN_LEN
    }

    /// Decodes a PIPE_JOIN frame that a listener received as the first frame
    /// of a carrier, or out of band. Returns the frame and its length; the
    /// token covers `buf[..len - 16]` exactly as received, so verify it with
    /// [`crate::proto::keys::verify_join`] on those bytes rather than on a
    /// re-encoding. Bytes after the frame are not examined: in band, other
    /// frames may follow in the record; out of band, the caller requires
    /// `len == buf.len()`.
    ///
    /// Any error closes only the carrier (MULTIPATH.md Section 5.4).
    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), Error> {
        let mut c = Cursor::new(buf);
        let ty = FrameType::PIPE_JOIN.0;
        let truncated = Error::frame_encoding(ty, "truncated PIPE_JOIN");
        match c.varint_with_width() {
            Ok((t, w)) if t == ty && w == vlen(ty) => {}
            Ok(_) => return Err(Error::frame_encoding(0, "not a PIPE_JOIN frame")),
            Err(_) => return Err(truncated),
        }
        match Self::read(&mut c, ty) {
            Ok(f) => Ok((f, c.pos())),
            Err(Fail::Short) => Err(truncated),
            Err(Fail::Invalid(e)) => Err(e),
        }
    }

    pub(super) fn read(c: &mut Cursor<'a>, ty: u64) -> Result<Self, Fail> {
        let start = c.pos() - vlen(ty);
        let locator_len = c.u8()?;
        if locator_len == 0 || usize::from(locator_len) > MAX_LOCATOR_LEN {
            return Err(Error::frame_encoding(ty, "PIPE_JOIN locator length out of range").into());
        }
        let locator = c.bytes(locator_len.into())?;
        let pipe_id = c.varint()?;
        let flags = c.u8()?;
        let direction = JoinDirection::from_bits(flags & FLAG_DIRECTION_MASK)
            .ok_or(Error::frame_encoding(ty, "PIPE_JOIN invalid direction"))?;
        if flags & FLAG_RESERVED_MASK != 0 {
            return Err(Error::frame_encoding(ty, "PIPE_JOIN reserved flag set").into());
        }
        let fate_group = c.varint()?;
        let priority = c.varint()?;
        let token = *c.array::<JOIN_TOKEN_LEN>()?;
        if c.pos() - start > MAX_JOIN_FRAME_LEN {
            return Err(Error::frame_encoding(ty, "PIPE_JOIN longer than 64 bytes").into());
        }
        Ok(Self {
            locator,
            pipe_id,
            direction,
            carrier_bound: flags & FLAG_CARRIER_BOUND != 0,
            fate_group,
            standby: flags & FLAG_STANDBY != 0,
            priority,
            token,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.locator.is_empty()
            || self.locator.len() > MAX_LOCATOR_LEN
            || self.encoded_len() > MAX_JOIN_FRAME_LEN
        {
            return Err(EncodeError::ValueOutOfRange);
        }
        let mut flags = self.direction.to_bits();
        if self.carrier_bound {
            flags |= FLAG_CARRIER_BOUND;
        }
        if self.standby {
            flags |= FLAG_STANDBY;
        }
        w.varint(FrameType::PIPE_JOIN.0)?;
        w.u8(self.locator.len() as u8)?;
        w.bytes(self.locator)?;
        w.varint(self.pipe_id)?;
        w.u8(flags)?;
        w.varint(self.fate_group)?;
        w.varint(self.priority)?;
        w.bytes(&self.token)
    }
}

/// An entry of PIPE_ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeAckEntry {
    /// A pipe inbound to the frame's sender.
    pub pipe_id: u64,
    /// A lane of that pipe (MULTIPATH.md Section 2.5); 0 for a pipe without
    /// lanes.
    pub lane: u64,
    /// The sender's receive position on that lane.
    pub position: u64,
    /// Microseconds between processing the record that brought the position
    /// to this value and sending the frame.
    pub ack_delay: u64,
}

impl PipeAckEntry {
    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self {
            pipe_id: c.varint()?,
            lane: c.varint()?,
            position: c.varint()?,
            ack_delay: c.varint()?,
        })
    }

    pub(super) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(self.pipe_id)?;
        w.varint(self.lane)?;
        w.varint(self.position)?;
        w.varint(self.ack_delay)
    }

    pub(super) fn encoded_len(&self) -> usize {
        vlen(self.pipe_id) + vlen(self.lane) + vlen(self.position) + vlen(self.ack_delay)
    }

    /// The (Pipe ID, Lane) key whose strict increase orders the entries
    /// of a frame (MULTIPATH.md Section 6.2).
    pub(super) const fn key(&self) -> (u64, u64) {
        (self.pipe_id, self.lane)
    }
}

/// The length of a Lane Key (MULTIPATH.md Section 3.6).
pub const LANE_KEY_LEN: usize = 16;

/// PIPE_LANE (0x3a05a1c9): the first frame of a lane (MULTIPATH.md Section
/// 5.8), whose first record holds nothing else but PADDING.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeLane {
    /// The receiver's Lane Key from its `zmux_max_lanes` parameter.
    pub lane_key: [u8; LANE_KEY_LEN],
    /// The attachment whose direction from the writer to the reader the
    /// lane carries.
    pub pipe_id: u64,
    /// The lane's number.
    pub lane: u64,
}

impl PipeLane {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        vlen(FrameType::PIPE_LANE.0) + LANE_KEY_LEN + vlen(self.pipe_id) + vlen(self.lane)
    }

    /// The smallest encoding: one-byte Pipe ID and Lane.
    pub const MIN_LEN: usize = vlen(FrameType::PIPE_LANE.0) + LANE_KEY_LEN + 2;

    /// Decodes the PIPE_LANE frame that begins the first record of a new
    /// stream (MULTIPATH.md Section 5.8), for routing it by its Lane Key.
    /// Returns the frame and its length; bytes after it are not examined.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        let mut c = Cursor::new(buf);
        let ty = FrameType::PIPE_LANE.0;
        let truncated = Error::frame_encoding(ty, "truncated PIPE_LANE");
        match c.varint_with_width() {
            Ok((t, w)) if t == ty && w == vlen(ty) => {}
            Ok(_) => return Err(Error::frame_encoding(0, "not a PIPE_LANE frame")),
            Err(_) => return Err(truncated),
        }
        match Self::read(&mut c) {
            Ok(f) => Ok((f, c.pos())),
            Err(Fail::Short) => Err(truncated),
            Err(Fail::Invalid(e)) => Err(e),
        }
    }

    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self {
            lane_key: *c.array::<LANE_KEY_LEN>()?,
            pipe_id: c.varint()?,
            lane: c.varint()?,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::PIPE_LANE.0)?;
        w.bytes(&self.lane_key)?;
        w.varint(self.pipe_id)?;
        w.varint(self.lane)
    }
}

/// PIPE_ACK (0x0b2b3eeb): a snapshot of the sender's receive positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeAck<'a> {
    entries: Entries<'a>,
}

impl<'a> PipeAck<'a> {
    /// A PIPE_ACK listing `entries`, which must be non-empty and in strictly
    /// increasing (Pipe ID, Lane) order.
    pub const fn new(entries: &'a [PipeAckEntry]) -> Self {
        Self {
            entries: Entries::List(entries),
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the frame has no entries (never true for a decoded frame).
    pub fn is_empty(&self) -> bool {
        self.entries.len() == 0
    }

    /// The entries in frame order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = PipeAckEntry> + Clone + use<'a> {
        self.entries.iter()
    }

    /// Length of the encoding.
    pub fn encoded_len(&self) -> usize {
        vlen(FrameType::PIPE_ACK.0) + self.entries.encoded_len()
    }

    pub(super) fn read(c: &mut Cursor<'a>, ty: u64) -> Result<Self, Fail> {
        let mut probe = *c;
        if probe.varint()? == 0 {
            return Err(Error::frame_encoding(ty, "PIPE_ACK without entries").into());
        }
        Ok(Self {
            entries: Entries::read(
                c,
                ty,
                "PIPE_ACK entries not in increasing (Pipe ID, Lane) order",
            )?,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.is_empty() {
            return Err(EncodeError::ValueOutOfRange);
        }
        w.varint(FrameType::PIPE_ACK.0)?;
        self.entries.write(w)
    }
}

/// PIPE_ABANDON (0x23b35b74).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeAbandon {
    /// Pipe ID of the attachment.
    pub pipe_id: u64,
    /// Transport error code: NO_ERROR for a graceful removal.
    pub error_code: u64,
}

impl PipeAbandon {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        vlen(FrameType::PIPE_ABANDON.0) + vlen(self.pipe_id) + vlen(self.error_code)
    }

    pub(super) fn read(c: &mut Cursor<'_>) -> Result<Self, Fail> {
        Ok(Self {
            pipe_id: c.varint()?,
            error_code: c.varint()?,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::PIPE_ABANDON.0)?;
        w.varint(self.pipe_id)?;
        w.varint(self.error_code)
    }
}

/// The Status field of PIPE_STATUS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PipeStatusValue {
    /// 0: use the pipe normally.
    #[default]
    Available,
    /// 1: use the pipe only on failover, when no non-standby pipe is
    /// usable.
    Standby,
}

/// PIPE_STATUS (0x227b2811): the sender's request for how the receiver
/// uses its outbound direction of an attachment (MULTIPATH.md Section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeStatus {
    /// The pipe inbound to the frame's sender.
    pub pipe_id: u64,
    /// Sequence Number, per pipe and sender, starting at 1.
    pub sequence: u64,
    /// Status.
    pub status: PipeStatusValue,
    /// Priority: the tier, lower preferred; every value is valid.
    pub priority: u64,
}

impl PipeStatus {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        vlen(FrameType::PIPE_STATUS.0)
            + vlen(self.pipe_id)
            + vlen(self.sequence)
            + 1
            + vlen(self.priority)
    }

    pub(super) fn read(c: &mut Cursor<'_>, ty: u64) -> Result<Self, Fail> {
        let pipe_id = c.varint()?;
        let sequence = c.varint()?;
        let status = match c.varint()? {
            0 => PipeStatusValue::Available,
            1 => PipeStatusValue::Standby,
            _ => return Err(Error::frame_encoding(ty, "PIPE_STATUS invalid status").into()),
        };
        let priority = c.varint()?;
        Ok(Self {
            pipe_id,
            sequence,
            status,
            priority,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::PIPE_STATUS.0)?;
        w.varint(self.pipe_id)?;
        w.varint(self.sequence)?;
        w.varint(match self.status {
            PipeStatusValue::Available => 0,
            PipeStatusValue::Standby => 1,
        })?;
        w.varint(self.priority)
    }
}
