//! Bounded arrival feedback for one pipe and channel.

use super::{Fail, FrameType};
use crate::proto::codec::{Cursor, Writer};
use crate::proto::error::{EncodeError, Error};
use crate::proto::varint;

const TYPE: u64 = FrameType::DATAGRAM_ACK.0;
pub const MAX_DATAGRAM_ACK_SIZE: usize = 8192;
pub const MAX_DATAGRAM_ACK_RANGES: usize = 4090;

/// The carrier on which a reported datagram arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DatagramChannelKind {
    Record = 0,
    Native = 1,
}

/// A validated `DATAGRAM_ACK` frame. Ranges are inclusive and descend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramAck<'a> {
    pub pipe: u64,
    pub channel: DatagramChannelKind,
    pub delay_micros: u64,
    largest: u64,
    first_range: u64,
    count: usize,
    pairs: &'a [u8],
}

impl<'a> DatagramAck<'a> {
    /// Constructs a report from the largest sequence, its range length minus
    /// one, and any further varint (gap, range length minus one) pairs.
    pub fn new(
        pipe: u64,
        channel: DatagramChannelKind,
        delay_micros: u64,
        largest: u64,
        first_range: u64,
        pairs: &'a [u8],
    ) -> Result<Self, EncodeError> {
        let mut frame = Self {
            pipe,
            channel,
            delay_micros,
            largest,
            first_range,
            count: 0,
            pairs,
        };
        if [pipe, delay_micros, largest, first_range]
            .into_iter()
            .any(|v| v > varint::MAX)
            || pairs.len() > MAX_DATAGRAM_ACK_SIZE
        {
            return Err(EncodeError::ValueOutOfRange);
        }
        let mut prev = largest
            .checked_sub(first_range)
            .ok_or(EncodeError::ValueOutOfRange)?;
        let mut cursor = Cursor::new(pairs);
        while !cursor.is_empty() {
            prev = read_range(&mut cursor, prev)
                .map_err(|_| EncodeError::ValueOutOfRange)?
                .0;
            frame.count += 1;
        }
        if frame.count > MAX_DATAGRAM_ACK_RANGES || frame.encoded_len() > MAX_DATAGRAM_ACK_SIZE {
            return Err(EncodeError::ValueOutOfRange);
        }
        Ok(frame)
    }

    /// The reported ranges. Iteration takes time proportional to their count.
    pub fn ranges(self) -> impl Iterator<Item = (u64, u64)> + 'a {
        let first = self.largest - self.first_range;
        let mut previous = first;
        let mut cursor = Cursor::new(self.pairs);
        std::iter::once((first, self.largest)).chain(std::iter::from_fn(move || {
            let range = read_range(&mut cursor, previous).ok()?;
            previous = range.0;
            Some(range)
        }))
    }

    #[must_use]
    pub fn encoded_len(self) -> usize {
        varint::len(TYPE)
            + varint::len(self.pipe)
            + 1
            + varint::len(self.largest)
            + varint::len(self.delay_micros)
            + varint::len(self.count as u64)
            + varint::len(self.first_range)
            + self.pairs.len()
    }

    pub(super) fn read(c: &mut Cursor<'a>) -> Result<Self, Fail> {
        let pos = c.pos();
        let rest = c.remaining_bytes();
        let bytes = &rest[..rest.len().min(MAX_DATAGRAM_ACK_SIZE - pos)];
        let mut ack = Cursor::new(bytes);
        let pipe = ack.varint()?;
        let channel = match ack.u8()? {
            0 => DatagramChannelKind::Record,
            1 => DatagramChannelKind::Native,
            _ => return Err(Error::frame_encoding(TYPE, "invalid DATAGRAM_ACK channel").into()),
        };
        let largest = ack.varint()?;
        let delay_micros = ack.varint()?;
        let count = ack.varint()?;
        if count > MAX_DATAGRAM_ACK_RANGES as u64 || count * 2 > ack.remaining() as u64 {
            return Err(
                Error::frame_encoding(TYPE, "DATAGRAM_ACK ranges exceed frame bounds").into(),
            );
        }
        let first_range = ack.varint()?;
        let pairs_start = ack.pos();
        let mut prev = largest
            .checked_sub(first_range)
            .ok_or_else(|| Error::frame_encoding(TYPE, "DATAGRAM_ACK first range underflow"))?;
        for _ in 0..count {
            prev = read_range(&mut ack, prev)?.0;
        }
        c.advance(ack.pos())?;
        Ok(Self {
            pipe,
            channel,
            delay_micros,
            largest,
            first_range,
            count: crate::util::usize_sat(count),
            pairs: &bytes[pairs_start..ack.pos()],
        })
    }

    pub(super) fn write(self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(TYPE)?;
        w.varint(self.pipe)?;
        w.u8(self.channel as u8)?;
        w.varint(self.largest)?;
        w.varint(self.delay_micros)?;
        w.varint(self.count as u64)?;
        w.varint(self.first_range)?;
        w.bytes(self.pairs)
    }
}

fn read_range(c: &mut Cursor<'_>, previous: u64) -> Result<(u64, u64), Fail> {
    let gap = c.varint()?;
    let len = c.varint()?;
    let end = previous
        .checked_sub(gap + 2)
        .ok_or_else(|| Error::frame_encoding(TYPE, "DATAGRAM_ACK gap underflow"))?;
    let start = end
        .checked_sub(len)
        .ok_or_else(|| Error::frame_encoding(TYPE, "DATAGRAM_ACK range underflow"))?;
    Ok((start, end))
}
