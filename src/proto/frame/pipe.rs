//! Multipath frames.

use super::entries::Entries;
use super::{Fail, FrameType};
use crate::proto::codec::{Cursor, Writer};
use crate::proto::error::{EncodeError, Error};
use crate::proto::varint::len as vlen;

/// The largest Session Locator.
pub const MAX_LOCATOR_LEN: usize = 255;

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
    /// The value of Direction in a Hello's join pipe item.
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Up => 0,
            Self::Down => 1,
            Self::Bidi => 2,
        }
    }

    /// Parses Direction; 3 is invalid.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Up),
            1 => Some(Self::Down),
            2 => Some(Self::Bidi),
            _ => None,
        }
    }
}

/// An entry of PIPE_ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeAckEntry {
    /// A pipe inbound to the frame's sender.
    pub pipe_id: u64,
    /// A lane of that pipe; 0 for a pipe without lanes.
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
    /// of a frame.
    pub(super) const fn key(&self) -> (u64, u64) {
        (self.pipe_id, self.lane)
    }
}

/// The length of a Lane Key.
pub const LANE_KEY_LEN: usize = 16;

/// PIPE_LANE (0x3a05a1c9): the first frame of a lane, whose first record holds nothing else but
/// PADDING.
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
    /// stream, for routing it by its Lane Key. Returns the frame and its
    /// length; bytes after it are not examined.
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
/// uses its outbound direction of an attachment.
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

/// The Phase of SESSION_EPOCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EpochPhase {
    /// 0: the offering end's share.
    Offer,
    /// 1: the answering end's share.
    Answer,
}

impl EpochPhase {
    /// The wire value.
    pub const fn value(self) -> u8 {
        self as u8
    }
}

/// SESSION_EPOCH (0x024e93eb): one step of an epoch exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEpoch<'a> {
    /// Phase.
    pub phase: EpochPhase,
    /// The target epoch.
    pub epoch: u64,
    /// The share.
    pub share: &'a [u8],
    /// The sender's Locator for the target epoch, empty to keep its current one.
    pub locator: &'a [u8],
    /// The received bytes of the body, Phase through Locator; empty for a frame made
    /// locally.
    pub raw: &'a [u8],
}

impl<'a> SessionEpoch<'a> {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        vlen(FrameType::SESSION_EPOCH.0) + self.body_len()
    }

    /// Length of the body, Phase through Locator.
    pub const fn body_len(&self) -> usize {
        1 + vlen(self.epoch)
            + vlen(self.share.len() as u64)
            + self.share.len()
            + 1
            + self.locator.len()
    }

    pub(super) fn read(c: &mut Cursor<'a>, ty: u64) -> Result<Self, Fail> {
        let phase = match c.u8()? {
            0 => EpochPhase::Offer,
            1 => EpochPhase::Answer,
            _ => {
                return Err(Error::protocol_violation(ty, "SESSION_EPOCH undefined Phase").into());
            }
        };
        let epoch = c.varint()?;
        let n = c.varint()?;
        let share = c.bytes(n)?;
        let n = c.u8()?;
        let locator = c.bytes(u64::from(n))?;
        Ok(Self {
            phase,
            epoch,
            share,
            locator,
            raw: &[],
        })
    }

    /// Writes the body, Phase through Locator.
    pub(crate) fn write_body(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let len = u8::try_from(self.locator.len()).map_err(|_| EncodeError::ValueOutOfRange)?;
        w.u8(self.phase.value())?;
        w.varint(self.epoch)?;
        w.varint(self.share.len() as u64)?;
        w.bytes(self.share)?;
        w.u8(len)?;
        w.bytes(self.locator)
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::SESSION_EPOCH.0)?;
        self.write_body(w)
    }

    /// The body, Phase through Locator: what the epoch derivation takes. A received
    /// frame's are the bytes received.
    pub fn body(&self) -> Vec<u8> {
        if !self.raw.is_empty() {
            return self.raw.to_vec();
        }
        let mut out = vec![0; self.body_len()];
        let mut w = Writer::new(&mut out);
        let _ = self.write_body(&mut w);
        out
    }
}
