//! Formats carried inside frame payloads: the stream preamble
//! (EXTENSIONS.md Section 4) at the start of a stream's data, and the flow
//! prefix of DATAGRAM data (EXTENSIONS.md Section 6.3). Violations of either
//! are PROTOCOL_VIOLATION.

use super::codec::{Cursor, Writer};
use super::error::{EncodeError, Error};
use super::frame::Priority;
use super::varint::{self, len as vlen};

/// Preamble TLV types (REGISTRY.md Section 5).
pub mod tlv {
    /// OPEN_INFO: the opener's metadata for the peer application.
    pub const OPEN_INFO: u64 = 0x01;
    /// PRIORITY: the opener's initial priority request.
    pub const PRIORITY: u64 = 0x02;
    /// DEADLINE: reserved; never sent, ignored on receipt.
    pub const DEADLINE: u64 = 0x03;
    /// PIPE_CARRIER: empty; the stream carries a pipe pair of a nested
    /// session (EXTENSIONS.md Section 10).
    pub const PIPE_CARRIER: u64 = 0x05;
    /// The first type of the application range (EXTENSIONS.md Section 4.3).
    pub const APPLICATION_FIRST: u64 = 0x1000;
    /// The last type of the application range.
    pub const APPLICATION_LAST: u64 = 0x3fff;
}

/// Status of a registered preamble TLV type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlvStatus {
    /// In use.
    Active,
    /// Reserved: never sent, ignored on receipt.
    Reserved,
}

/// The registered preamble TLV types (GREASE types excluded).
pub const PREAMBLE_TLVS: &[(&str, u64, TlvStatus)] = &[
    ("OPEN_INFO", tlv::OPEN_INFO, TlvStatus::Active),
    ("PRIORITY", tlv::PRIORITY, TlvStatus::Active),
    ("DEADLINE", tlv::DEADLINE, TlvStatus::Reserved),
    ("PIPE_CARRIER", tlv::PIPE_CARRIER, TlvStatus::Active),
];

/// The GREASE TLV type 0x1f * `n` + 0x21, or `None` if it does not fit in a
/// varint.
pub const fn grease_tlv_type(n: u64) -> Option<u64> {
    match n.checked_mul(0x1f) {
        Some(v) if v <= varint::MAX - 0x21 => Some(v + 0x21),
        _ => None,
    }
}

/// Whether `ty` is a GREASE TLV type.
pub const fn is_grease_tlv_type(ty: u64) -> bool {
    ty >= 0x21 && (ty - 0x21).is_multiple_of(0x1f)
}

/// Whether `ty` is an application TLV type: 0x1000 to 0x3fff, GREASE values
/// excluded (EXTENSIONS.md Section 4.3). zmux never interprets these and
/// delivers them to the application in the order received.
pub const fn is_application_tlv_type(ty: u64) -> bool {
    ty >= tlv::APPLICATION_FIRST && ty <= tlv::APPLICATION_LAST && !is_grease_tlv_type(ty)
}

/// The application TLVs of a TLV list, in order: an iterator of
/// `(type, value)` over encoded TLVs that skips every other type. Built from
/// a parsed preamble ([`WirePreamble::app_tlvs`]) or from TLVs a sender encoded
/// with [`AppTlvs::encode_one`]; iteration stops at a truncated TLV.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppTlvs<'a> {
    rest: &'a [u8],
}

impl<'a> AppTlvs<'a> {
    /// A view over encoded TLVs (type, length, value, repeated).
    pub const fn new(encoded: &'a [u8]) -> Self {
        Self { rest: encoded }
    }

    /// The encoded TLVs not yet iterated, other types included.
    pub const fn encoded(&self) -> &'a [u8] {
        self.rest
    }

    /// Whether no application TLV is in the list.
    pub fn is_empty(&self) -> bool {
        let mut it = *self;
        it.next().is_none()
    }

    /// The encoded length of the application TLVs alone.
    pub fn encoded_len(&self) -> usize {
        (*self)
            .map(|(ty, v)| vlen(ty) + vlen(v.len() as u64) + v.len())
            .sum()
    }

    /// Encodes one TLV, appending it to `out`.
    pub fn encode_one(ty: u64, value: &[u8], out: &mut Vec<u8>) {
        let mut head = [0u8; 16];
        let mut w = Writer::new(&mut head);
        // Two varints of at most 8 bytes each always fit.
        let _ = w.varint(ty);
        let _ = w.varint(value.len() as u64);
        let n = w.pos();
        out.extend_from_slice(&head[..n]);
        out.extend_from_slice(value);
    }
}

impl<'a> Iterator for AppTlvs<'a> {
    type Item = (u64, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        while !self.rest.is_empty() {
            let mut c = Cursor::new(self.rest);
            let parsed = (|| {
                let ty = c.varint().ok()?;
                let len = c.varint().ok()?;
                let value = c.bytes(len).ok()?;
                Some((ty, value))
            })();
            let Some((ty, value)) = parsed else {
                self.rest = &[];
                return None;
            };
            self.rest = c.rest();
            if is_application_tlv_type(ty) {
                return Some((ty, value));
            }
        }
        None
    }
}

/// A GREASE TLV to put last in a preamble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GreaseTlv<'a> {
    /// A GREASE type, 0x1f * N + 0x21.
    pub ty: u64,
    /// 0 to 8 random bytes.
    pub value: &'a [u8],
}

/// The stream preamble: the known TLVs of a stream's opening metadata and
/// its application TLVs. Unknown, reserved and GREASE TLVs are skipped when
/// parsing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WirePreamble<'a> {
    /// OPEN_INFO.
    pub open_info: Option<&'a [u8]>,
    /// PRIORITY.
    pub priority: Option<Priority>,
    /// PIPE_CARRIER: the stream carries a pipe pair of a nested session.
    pub pipe_carrier: bool,
    /// The application TLVs, in order (encoded after PIPE_CARRIER).
    pub app_tlvs: AppTlvs<'a>,
}

impl<'a> WirePreamble<'a> {
    /// Parses the preamble from the data of the STREAM frame at offset 0
    /// (EXTENSIONS.md Section 4.4). `limit` is the receiver's Maximum
    /// Preamble Size. Returns the preamble and its size (Length field plus
    /// Length), where the application data starts.
    pub fn parse(frame_data: &'a [u8], limit: u64) -> Result<(Self, usize), Error> {
        let pv = |reason| Error::protocol_violation(0, reason);
        let (len, width) =
            varint::decode(frame_data).ok_or(pv("preamble Length not in the first frame"))?;
        let size = (width as u64).saturating_add(len);
        if size > limit {
            return Err(pv("preamble above the announced limit"));
        }
        let body = usize::try_from(size)
            .ok()
            .and_then(|end| frame_data.get(width..end))
            .ok_or(pv("preamble not contained in the first frame"))?;
        let mut out = Self::default();
        let mut c = Cursor::new(body);
        while !c.is_empty() {
            let truncated = |_| pv("truncated preamble TLV");
            let ty = c.varint().map_err(truncated)?;
            let len = c.varint().map_err(truncated)?;
            let value = c.bytes(len).map_err(truncated)?;
            match ty {
                tlv::OPEN_INFO => {
                    if out.open_info.replace(value).is_some() {
                        return Err(pv("OPEN_INFO repeated"));
                    }
                }
                tlv::PRIORITY => {
                    let p = match value {
                        [b] => Priority::from_byte(*b),
                        _ => None,
                    }
                    .ok_or(pv("invalid PRIORITY TLV"))?;
                    if out.priority.replace(p).is_some() {
                        return Err(pv("PRIORITY repeated"));
                    }
                }
                tlv::PIPE_CARRIER => {
                    if !value.is_empty() {
                        return Err(pv("invalid PIPE_CARRIER TLV"));
                    }
                    if std::mem::replace(&mut out.pipe_carrier, true) {
                        return Err(pv("PIPE_CARRIER repeated"));
                    }
                }
                _ => {}
            }
        }
        out.app_tlvs = AppTlvs::new(body);
        Ok((out, body.len() + width))
    }

    fn body_len(&self, grease: Option<GreaseTlv<'_>>) -> usize {
        let mut n = 0;
        if let Some(info) = self.open_info {
            n += vlen(tlv::OPEN_INFO) + vlen(info.len() as u64) + info.len();
        }
        if self.priority.is_some() {
            n += vlen(tlv::PRIORITY) + 1 + 1;
        }
        if self.pipe_carrier {
            n += vlen(tlv::PIPE_CARRIER) + 1;
        }
        n += self.app_tlvs.encoded_len();
        if let Some(g) = grease {
            n += vlen(g.ty) + vlen(g.value.len() as u64) + g.value.len();
        }
        n
    }

    /// Length of the encoding, Length field included.
    pub fn encoded_len(&self, grease: Option<GreaseTlv<'_>>) -> usize {
        let body = self.body_len(grease);
        vlen(body as u64) + body
    }

    /// Writes the preamble: OPEN_INFO, PRIORITY, PIPE_CARRIER, the
    /// application TLVs in order, then `grease`.
    pub fn encode(
        &self,
        grease: Option<GreaseTlv<'_>>,
        buf: &mut [u8],
    ) -> Result<usize, EncodeError> {
        if let Some(g) = grease
            && (!is_grease_tlv_type(g.ty) || g.value.len() > 8)
        {
            return Err(EncodeError::ValueOutOfRange);
        }
        let mut w = Writer::new(buf);
        w.varint(self.body_len(grease) as u64)?;
        if let Some(info) = self.open_info {
            w.varint(tlv::OPEN_INFO)?;
            w.varint(info.len() as u64)?;
            w.bytes(info)?;
        }
        if let Some(p) = self.priority {
            w.varint(tlv::PRIORITY)?;
            w.varint(1)?;
            w.u8(p.to_byte())?;
        }
        if self.pipe_carrier {
            w.varint(tlv::PIPE_CARRIER)?;
            w.varint(0)?;
        }
        for (ty, value) in self.app_tlvs {
            w.varint(ty)?;
            w.varint(value.len() as u64)?;
            w.bytes(value)?;
        }
        if let Some(g) = grease {
            w.varint(g.ty)?;
            w.varint(g.value.len() as u64)?;
            w.bytes(g.value)?;
        }
        Ok(w.pos())
    }
}

/// The association of a datagram (EXTENSIONS.md Section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flow {
    /// Flow 0: the session as a whole.
    Session,
    /// Flow n > 0: the bidirectional stream n - 1.
    Stream {
        /// The bidirectional stream ID.
        stream_id: u64,
        /// Context ID within the association.
        context: u64,
    },
}

impl Flow {
    /// Length of the prefix.
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Session => 1,
            Self::Stream { stream_id, context } => {
                vlen(stream_id.saturating_add(1)) + vlen(*context)
            }
        }
    }

    /// Writes the prefix.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        match *self {
            Self::Session => w.varint(0)?,
            Self::Stream { stream_id, context } => {
                if stream_id & 0x02 != 0 {
                    return Err(EncodeError::ValueOutOfRange);
                }
                w.varint(
                    stream_id
                        .checked_add(1)
                        .ok_or(EncodeError::ValueOutOfRange)?,
                )?;
                w.varint(context)?;
            }
        }
        Ok(w.pos())
    }

    /// Splits DATAGRAM data into its flow and payload. A truncated prefix,
    /// or a flow naming a unidirectional stream, is a PROTOCOL_VIOLATION
    /// (the error's frame type is 0; [`crate::proto::frame::Datagram::flow`]
    /// sets it).
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        let truncated = |_| Error::protocol_violation(0, "truncated datagram flow prefix");
        let mut c = Cursor::new(data);
        let flow = c.varint().map_err(truncated)?;
        if flow == 0 {
            return Ok((Self::Session, c.rest()));
        }
        let context = c.varint().map_err(truncated)?;
        let stream_id = flow - 1;
        if stream_id & 0x02 != 0 {
            return Err(Error::protocol_violation(
                0,
                "datagram flow names a unidirectional stream",
            ));
        }
        Ok((Self::Stream { stream_id, context }, c.rest()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_round_trip() {
        // WIRE_EXAMPLES.md Section 2.1: OPEN_INFO, PRIORITY urgency 1 and
        // an empty GREASE TLV of type 0x21, then "hello".
        let data = b"\x16\x01\x0fexample.com:443\x02\x01\x20\x21\x00hello";
        let (p, size) = WirePreamble::parse(data, 4096).unwrap();
        assert_eq!(p.open_info, Some(&b"example.com:443"[..]));
        assert_eq!(p.priority, Priority::new(1, false));
        assert_eq!(&data[size..], b"hello");
        let grease = GreaseTlv {
            ty: 0x21,
            value: &[],
        };
        let mut buf = [0u8; 64];
        let n = p.encode(Some(grease), &mut buf).unwrap();
        assert_eq!(n, p.encoded_len(Some(grease)));
        assert_eq!(&buf[..n], &data[..size]);
        assert!(WirePreamble::parse(data, 22).is_err());
        assert!(WirePreamble::parse(&data[..10], 4096).is_err());
        assert_eq!(WirePreamble::parse(&[0x00], 1).unwrap().1, 1);
    }

    /// EXTENSIONS.md Section 4.3: application TLVs in order, repeats
    /// included; GREASE values in the range and other types are not
    /// application TLVs; PIPE_CARRIER is empty and at most once.
    #[test]
    fn application_tlvs_and_pipe_carrier() {
        let mut tlvs = Vec::new();
        AppTlvs::encode_one(0x1000, b"a", &mut tlvs);
        AppTlvs::encode_one(0x3fff, b"", &mut tlvs);
        AppTlvs::encode_one(0x1000, b"b", &mut tlvs);
        let p = WirePreamble {
            pipe_carrier: true,
            app_tlvs: AppTlvs::new(&tlvs),
            ..WirePreamble::default()
        };
        let mut buf = [0u8; 64];
        let n = p.encode(None, &mut buf).unwrap();
        assert_eq!(n, p.encoded_len(None));
        let (q, size) = WirePreamble::parse(&buf[..n], 4096).unwrap();
        assert_eq!(size, n);
        assert!(q.pipe_carrier);
        let got: Vec<_> = q.app_tlvs.collect();
        assert_eq!(
            got,
            [(0x1000, &b"a"[..]), (0x3fff, &b""[..]), (0x1000, &b"b"[..])]
        );
        // 0x101d = 0x1f * 0x84 + 0x21 is GREASE; 0x0fff is outside.
        assert!(!is_application_tlv_type(0x101d));
        assert!(!is_application_tlv_type(0x0fff));
        assert!(!is_application_tlv_type(0x4000));
        assert!(WirePreamble::parse(b"\x03\x05\x01\x78", 4096).is_err());
        assert!(WirePreamble::parse(b"\x04\x05\x00\x05\x00", 4096).is_err());
    }

    #[test]
    fn flows() {
        let (f, rest) = Flow::parse(&[0x05, 0x00, b'u']).unwrap();
        assert_eq!(
            f,
            Flow::Stream {
                stream_id: 4,
                context: 0
            }
        );
        assert_eq!(rest, b"u");
        assert!(Flow::parse(&[0x03, 0x00]).is_err());
        assert!(Flow::parse(&[0x05]).is_err());
        assert_eq!(Flow::parse(&[0x00]).unwrap(), (Flow::Session, &[][..]));
    }
}
