//! The QMux-02 frames QX_TRANSPORT_PARAMETERS (Section 4.2) and QX_PING
//! (Section 4.3).

use super::{Fail, FrameType};
use crate::proto::codec::{Cursor, Writer};
use crate::proto::error::EncodeError;
use crate::proto::params::TransportParameters;
use crate::proto::varint::len as vlen;

/// QX_TRANSPORT_PARAMETERS (0x3f5153300d0a0d0a in QMux-02,
/// [`crate::proto::draft`]), carrying an encoded
/// transport-parameter block.
///
/// Decoding validates the block (SPEC.md Section 5.2); parse it with
/// [`TransportParameters::decode`] to read the values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QxTransportParameters<'a> {
    /// The Transport Parameters field, as a sequence of (ID, Length, Value).
    pub block: &'a [u8],
}

impl<'a> QxTransportParameters<'a> {
    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        8 + vlen(self.block.len() as u64) + self.block.len()
    }

    /// Parses the parameter block.
    pub fn parameters(&self) -> Result<TransportParameters, crate::proto::Error> {
        TransportParameters::decode(self.block)
    }

    pub(super) fn read(c: &mut Cursor<'a>) -> Result<Self, Fail> {
        let len = c.varint()?;
        let block = c.bytes(len)?;
        TransportParameters::validate_block(block).map_err(|e| {
            crate::proto::Error::new(e.code(), FrameType::QX_TRANSPORT_PARAMETERS.0, e.reason())
        })?;
        Ok(Self { block })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(FrameType::QX_TRANSPORT_PARAMETERS.0)?;
        w.varint(self.block.len() as u64)?;
        w.bytes(self.block)
    }
}

/// QX_PING (0x348c67529ef8c7bd request, 0x348c67529ef8c7be response in
/// QMux-02, [`crate::proto::draft`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QxPing {
    /// Whether this is a response.
    pub response: bool,
    /// Sequence Number.
    pub sequence: u64,
}

impl QxPing {
    const fn code(&self) -> u64 {
        if self.response {
            FrameType::QX_PING_RESPONSE.0
        } else {
            FrameType::QX_PING_REQUEST.0
        }
    }

    /// Length of the encoding.
    pub const fn encoded_len(&self) -> usize {
        8 + vlen(self.sequence)
    }

    pub(super) fn read(c: &mut Cursor<'_>, ty: u64) -> Result<Self, Fail> {
        Ok(Self {
            response: ty == FrameType::QX_PING_RESPONSE.0,
            sequence: c.varint()?,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(self.code())?;
        w.varint(self.sequence)
    }
}
