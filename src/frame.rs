use crate::error::{Error, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource, Result};
use crate::payload::parse_priority_update_metadata;
use crate::protocol::EXT_PRIORITY_UPDATE;
use crate::tlv::validate_tlvs;
use crate::varint::{
    decode_varint_with_len, encode_varint_to_slice, parse_varint, read_exact_checked, PackedVarint,
};
use std::fmt;
use std::io;

pub const FRAME_FLAG_OPEN_METADATA: u8 = 0x20;
pub const FRAME_FLAG_FIN: u8 = 0x40;
const FRAME_FLAG_OPEN_METADATA_FIN: u8 = FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN;
pub(crate) const MAX_FRAME_HEADER_LEN: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    Data = 1,
    MaxData = 2,
    StopSending = 3,
    Ping = 4,
    Pong = 5,
    Blocked = 6,
    Reset = 7,
    Abort = 8,
    GoAway = 9,
    Close = 10,
    Ext = 11,
}

impl FrameType {
    #[inline]
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::Data,
            2 => Self::MaxData,
            3 => Self::StopSending,
            4 => Self::Ping,
            5 => Self::Pong,
            6 => Self::Blocked,
            7 => Self::Reset,
            8 => Self::Abort,
            9 => Self::GoAway,
            10 => Self::Close,
            11 => Self::Ext,
            _ => return Err(Error::protocol("invalid frame type")),
        })
    }

    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Data => "DATA",
            Self::MaxData => "MAX_DATA",
            Self::StopSending => "STOP_SENDING",
            Self::Ping => "PING",
            Self::Pong => "PONG",
            Self::Blocked => "BLOCKED",
            Self::Reset => "RESET",
            Self::Abort => "ABORT",
            Self::GoAway => "GOAWAY",
            Self::Close => "CLOSE",
            Self::Ext => "EXT",
        }
    }
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    #[inline]
    fn try_from(value: u8) -> Result<Self> {
        Self::from_u8(value)
    }
}

impl From<FrameType> for u8 {
    #[inline]
    fn from(value: FrameType) -> Self {
        value.as_u8()
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for FrameType {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_frame_payload: u64,
    pub max_control_payload_bytes: u64,
    pub max_extension_payload_bytes: u64,
}

impl Default for Limits {
    #[inline]
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Limits {
    pub const DEFAULT: Self = Self {
        max_frame_payload: 16_384,
        max_control_payload_bytes: 4096,
        max_extension_payload_bytes: 4096,
    };

    #[inline]
    pub fn normalized(self) -> Self {
        let defaults = Self::DEFAULT;
        Self {
            max_frame_payload: nonzero_or_default(
                self.max_frame_payload,
                defaults.max_frame_payload,
            ),
            max_control_payload_bytes: nonzero_or_default(
                self.max_control_payload_bytes,
                defaults.max_control_payload_bytes,
            ),
            max_extension_payload_bytes: nonzero_or_default(
                self.max_extension_payload_bytes,
                defaults.max_extension_payload_bytes,
            ),
        }
    }

    #[inline]
    pub fn inbound_payload_limit(self, frame_type: FrameType) -> u64 {
        match frame_type {
            FrameType::Data => self.max_frame_payload,
            FrameType::Ext => self.max_extension_payload_bytes,
            _ => self.max_control_payload_bytes,
        }
    }
}

#[inline]
fn nonzero_or_default(value: u64, default: u64) -> u64 {
    if value == 0 {
        default
    } else {
        value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameView<'a> {
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u64,
    pub payload: &'a [u8],
}

impl<'a> FrameView<'a> {
    pub fn code(&self) -> u8 {
        self.frame_type.as_u8() | self.flags
    }

    #[inline]
    pub fn try_to_owned(&self) -> Result<Frame> {
        let payload = if self.payload.is_empty() {
            Vec::new()
        } else {
            let mut payload = Vec::new();
            reserve_frame_payload(&mut payload, self.payload.len())?;
            payload.extend_from_slice(self.payload);
            payload
        };
        Ok(Frame {
            frame_type: self.frame_type,
            flags: self.flags,
            stream_id: self.stream_id,
            payload,
        })
    }

    pub fn parse(src: &'a [u8], limits: Limits) -> Result<(Self, usize)> {
        let limits = limits.normalized();
        let (frame_len, n_len) = parse_varint(src)?;
        if frame_len < 2 {
            return Err(Error::frame_size("frame too short"));
        }
        if src.len() < n_len + 1 {
            return Err(Error::frame_size("truncated frame"));
        }
        let code = src[n_len];
        let frame_type = FrameType::from_u8(code & 0x1f)?;
        let flags = code & 0xe0;
        let stream_start = n_len + 1;
        if src.len() < stream_start + 1 {
            return Err(Error::frame_size("truncated frame"));
        }
        let stream_len = 1usize << (src[stream_start] >> 6);
        let stream_len_u64 = stream_len as u64;
        if frame_len < 1 + stream_len_u64 {
            return Err(Error::frame_size("frame too short"));
        }
        let stream_end = stream_start + stream_len;
        if src.len() < stream_end {
            return Err(Error::frame_size("truncated frame"));
        }
        let stream_id = decode_varint_with_len(&src[stream_start..stream_end], stream_len)?;
        let payload_start = stream_end;
        let payload_len = frame_len - 1 - stream_len_u64;
        if payload_len > limits.inbound_payload_limit(frame_type) {
            return Err(Error::frame_size("payload exceeds configured limit"));
        }
        if frame_len > usize::MAX as u64 {
            return Err(Error::frame_size("payload exceeds configured limit"));
        }
        let frame_len = frame_len as usize;
        let total_len = n_len
            .checked_add(frame_len)
            .ok_or_else(|| Error::frame_size("payload exceeds configured limit"))?;
        if src.len() < total_len {
            return Err(Error::frame_size("truncated frame"));
        }
        let frame = Self {
            frame_type,
            flags,
            stream_id,
            payload: &src[payload_start..total_len],
        };
        frame.validate(limits, true)?;
        Ok((frame, total_len))
    }

    pub fn validate(&self, limits: Limits, inbound: bool) -> Result<()> {
        validate_frame_parts(
            self.frame_type,
            self.flags,
            self.stream_id,
            self.payload,
            limits,
            inbound,
        )
    }
}

impl Frame {
    #[inline]
    pub fn new(frame_type: FrameType, stream_id: u64, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            frame_type,
            flags: 0,
            stream_id,
            payload: payload.into(),
        }
    }

    #[inline]
    pub fn with_flags(
        frame_type: FrameType,
        flags: u8,
        stream_id: u64,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            frame_type,
            flags,
            stream_id,
            payload: payload.into(),
        }
    }

    #[inline]
    pub fn code(&self) -> u8 {
        self.frame_type.as_u8() | self.flags
    }

    pub fn as_view(&self) -> FrameView<'_> {
        FrameView {
            frame_type: self.frame_type,
            flags: self.flags,
            stream_id: self.stream_id,
            payload: &self.payload,
        }
    }

    pub fn marshal(&self) -> Result<Vec<u8>> {
        let mut header = [0u8; MAX_FRAME_HEADER_LEN];
        let header_len = self.encode_header(&mut header)?;
        let encoded_len = encoded_total_len(header_len, self.payload.len())?;
        let mut out = Vec::new();
        out.try_reserve_exact(encoded_len)
            .map_err(|_| Error::local("zmux: frame allocation failed"))?;
        out.extend_from_slice(&header[..header_len]);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    #[inline]
    pub fn encoded_len(&self) -> Result<usize> {
        let body_len = frame_body_len(self.stream_id, self.payload.len())?;
        let body_len_u64 = frame_body_len_u64(body_len)?;
        encoded_total_len(crate::varint::varint_len(body_len_u64)?, body_len)
    }

    #[inline]
    pub fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut header = [0u8; MAX_FRAME_HEADER_LEN];
        let header_len = self.encode_header(&mut header)?;
        out.try_reserve(encoded_total_len(header_len, self.payload.len())?)
            .map_err(|_| Error::local("zmux: frame allocation failed"))?;
        out.extend_from_slice(&header[..header_len]);
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    pub(crate) fn encode_header(&self, out: &mut [u8; MAX_FRAME_HEADER_LEN]) -> Result<usize> {
        self.encode_header_with_limits(Limits::DEFAULT, out)
    }

    pub(crate) fn encode_header_with_limits(
        &self,
        limits: Limits,
        out: &mut [u8; MAX_FRAME_HEADER_LEN],
    ) -> Result<usize> {
        self.validate(limits, false)?;
        let stream_id = PackedVarint::new(self.stream_id)?;
        self.encode_validated_header_with_packed_stream_id(stream_id, out)
    }

    pub(crate) fn encode_header_with_stream_id_cache(
        &self,
        limits: Limits,
        stream_id_cache: &mut Option<PackedVarint>,
        out: &mut [u8; MAX_FRAME_HEADER_LEN],
    ) -> Result<usize> {
        self.validate(limits, false)?;
        let stream_id = match *stream_id_cache {
            Some(cached) if cached.value() == self.stream_id => cached,
            _ => {
                let encoded = PackedVarint::new(self.stream_id)?;
                *stream_id_cache = Some(encoded);
                encoded
            }
        };
        self.encode_validated_header_with_packed_stream_id(stream_id, out)
    }

    fn encode_validated_header_with_packed_stream_id(
        &self,
        stream_id: PackedVarint,
        out: &mut [u8; MAX_FRAME_HEADER_LEN],
    ) -> Result<usize> {
        if stream_id.value() != self.stream_id {
            return Err(Error::local("zmux: cached stream_id mismatch"));
        }
        let stream_id_len = stream_id.len();
        let body_len = frame_body_len_for_stream_len(stream_id_len, self.payload.len())?;
        let body_len_u64 = frame_body_len_u64(body_len)?;
        let frame_len_len = crate::varint::varint_len(body_len_u64)?;
        let expected_header_len = frame_len_len + 1 + stream_id_len;
        let mut off = encode_varint_to_slice(out, body_len_u64)?;
        out[off] = self.code();
        off += 1;
        out[off..off + stream_id_len].copy_from_slice(stream_id.as_slice());
        off += stream_id_len;
        debug_assert_eq!(off, expected_header_len);
        Ok(off)
    }

    pub fn parse(src: &[u8], limits: Limits) -> Result<(Self, usize)> {
        let (frame, total_len) = FrameView::parse(src, limits)?;
        Ok((frame.try_to_owned()?, total_len))
    }

    pub fn validate(&self, limits: Limits, inbound: bool) -> Result<()> {
        validate_frame_parts(
            self.frame_type,
            self.flags,
            self.stream_id,
            &self.payload,
            limits,
            inbound,
        )
    }
}

fn frame_body_len(stream_id: u64, payload_len: usize) -> Result<usize> {
    frame_body_len_for_stream_len(crate::varint::varint_len(stream_id)?, payload_len)
}

fn frame_body_len_for_stream_len(stream_id_len: usize, payload_len: usize) -> Result<usize> {
    let len = 1usize
        .checked_add(stream_id_len)
        .ok_or_else(|| Error::frame_size("frame too large"))?;
    len.checked_add(payload_len)
        .ok_or_else(|| Error::frame_size("frame too large"))
}

fn frame_body_len_u64(body_len: usize) -> Result<u64> {
    if body_len > u64::MAX as usize {
        return Err(Error::frame_size("frame too large"));
    }
    let body_len = body_len as u64;
    if body_len > crate::varint::MAX_VARINT62 {
        return Err(Error::frame_size("frame too large"));
    }
    Ok(body_len)
}

fn encoded_total_len(header_len: usize, payload_len: usize) -> Result<usize> {
    header_len
        .checked_add(payload_len)
        .ok_or_else(|| Error::frame_size("frame too large"))
}

fn reserve_frame_payload(payload: &mut Vec<u8>, payload_len: usize) -> Result<()> {
    payload
        .try_reserve_exact(payload_len)
        .map_err(|_| Error::local("zmux: frame payload allocation failed"))
}

fn validate_frame_parts(
    frame_type: FrameType,
    flags: u8,
    stream_id: u64,
    payload: &[u8],
    limits: Limits,
    inbound: bool,
) -> Result<()> {
    validate_frame_envelope(frame_type, flags, stream_id, payload, limits, inbound)?;

    match frame_type {
        FrameType::Data => validate_data_payload(payload, flags),
        FrameType::MaxData | FrameType::Blocked => {
            validate_exact_one_varint_payload(frame_type, payload)
        }
        FrameType::Ping | FrameType::Pong => {
            if payload.len() < 8 {
                Err(Error::frame_size("ping/pong payload too short"))
            } else {
                Ok(())
            }
        }
        FrameType::StopSending | FrameType::Reset | FrameType::Abort | FrameType::Close => {
            validate_error_and_diag_payload(payload)
        }
        FrameType::GoAway => validate_go_away_payload(payload),
        FrameType::Ext => validate_ext_payload(stream_id, payload),
    }
}

fn validate_frame_envelope(
    frame_type: FrameType,
    flags: u8,
    stream_id: u64,
    payload: &[u8],
    limits: Limits,
    inbound: bool,
) -> Result<()> {
    validate_frame_flags(frame_type, flags)?;
    validate_frame_scope(frame_type, stream_id)?;
    if inbound && (payload.len() as u64) > limits.inbound_payload_limit(frame_type) {
        return Err(Error::frame_size("payload exceeds configured limit"));
    }
    Ok(())
}

pub fn read_frame<R: io::Read>(reader: &mut R, limits: Limits) -> Result<Frame> {
    read_frame_inner(reader, limits, false).map_err(frame_read_error)
}

pub fn parse_frame(src: &[u8], limits: Limits) -> Result<(Frame, usize)> {
    Frame::parse(src, limits)
}

pub(crate) fn read_session_frame<R: io::Read>(reader: &mut R, limits: Limits) -> Result<Frame> {
    read_frame_inner(reader, limits, true).map_err(frame_read_error)
}

fn read_frame_inner<R: io::Read>(
    reader: &mut R,
    limits: Limits,
    defer_data_metadata_validation: bool,
) -> Result<Frame> {
    let limits = limits.normalized();
    let frame_len = read_frame_length(reader)?;
    if frame_len < 2 {
        return Err(Error::frame_size("frame too short"));
    }
    let max_len = limits
        .max_frame_payload
        .max(limits.max_control_payload_bytes)
        .max(limits.max_extension_payload_bytes)
        .saturating_add(9);
    if frame_len > max_len {
        return Err(Error::frame_size("payload exceeds configured limit"));
    }
    let mut code_buf = [0u8; 1];
    read_frame_exact(reader, &mut code_buf, "truncated frame")?;
    let code = code_buf[0];
    let frame_type = FrameType::from_u8(code & 0x1f)?;
    let flags = code & 0xe0;

    let mut stream_buf = [0u8; 8];
    read_frame_exact(reader, &mut stream_buf[..1], "truncated frame")?;
    let stream_len = 1usize << (stream_buf[0] >> 6);
    let stream_len_u64 = stream_len as u64;
    if frame_len < 1 + stream_len_u64 {
        return Err(Error::frame_size("frame too short"));
    }
    if stream_len > 1 {
        read_frame_exact(reader, &mut stream_buf[1..stream_len], "truncated frame")?;
    }
    let stream_id = decode_varint_with_len(&stream_buf[..stream_len], stream_len)?;
    let payload_len = frame_len - 1 - stream_len_u64;
    if payload_len > limits.inbound_payload_limit(frame_type) {
        return Err(Error::frame_size("payload exceeds configured limit"));
    }
    if payload_len > usize::MAX as u64 {
        return Err(Error::frame_size("payload exceeds configured limit"));
    }
    let payload_len = payload_len as usize;
    let mut payload = Vec::new();
    reserve_frame_payload(&mut payload, payload_len)?;
    payload.resize(payload_len, 0);
    read_frame_exact(reader, &mut payload, "truncated frame")?;
    if defer_data_metadata_validation {
        validate_frame_envelope(frame_type, flags, stream_id, &payload, limits, true)?;
    } else {
        validate_frame_parts(frame_type, flags, stream_id, &payload, limits, true)?;
    }
    Ok(Frame {
        frame_type,
        flags,
        stream_id,
        payload,
    })
}

fn frame_read_error(err: Error) -> Error {
    with_session_read_context(err)
}

fn read_frame_length<R: io::Read>(reader: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    match read_first_frame_length_byte(reader)? {
        Some(first) => buf[0] = first,
        None => return Err(Error::io(io::Error::from(io::ErrorKind::UnexpectedEof))),
    }
    let len = 1usize << (buf[0] >> 6);
    if len > 1 {
        read_frame_exact(reader, &mut buf[1..len], "truncated varint62")?;
    }
    decode_varint_with_len(&buf[..len], len)
}

fn read_first_frame_length_byte<R: io::Read>(reader: &mut R) -> Result<Option<u8>> {
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(1) => return Ok(Some(byte[0])),
            Ok(_) => {
                return Err(Error::from(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reader reported invalid progress",
                )));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(Error::from(err)),
        }
    }
}

fn read_frame_exact<R: io::Read>(
    reader: &mut R,
    dst: &mut [u8],
    truncated_message: &'static str,
) -> Result<()> {
    read_exact_checked(reader, dst).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            Error::protocol(truncated_message)
        } else {
            Error::from(err)
        }
    })
}

fn with_session_read_context(mut err: Error) -> Error {
    if err.source() == ErrorSource::Unknown && err.source_io_error_kind().is_none() {
        err = err.with_source(ErrorSource::Remote);
    }
    err.with_scope(ErrorScope::Session)
        .with_operation(ErrorOperation::Read)
        .with_direction(ErrorDirection::Read)
}

fn validate_frame_flags(frame_type: FrameType, flags: u8) -> Result<()> {
    if frame_type != FrameType::Data {
        if flags == 0 {
            return Ok(());
        }
        return Err(Error::protocol("invalid flags for frame type"));
    }
    if matches!(
        flags,
        0 | FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN | FRAME_FLAG_OPEN_METADATA_FIN
    ) {
        Ok(())
    } else {
        Err(Error::protocol("invalid flags for frame type"))
    }
}

fn validate_frame_scope(frame_type: FrameType, stream_id: u64) -> Result<()> {
    let message = match (frame_type, stream_id == 0) {
        (FrameType::Data, true) => Some("DATA requires non-zero stream_id"),
        (FrameType::StopSending, true) => Some("STOP_SENDING requires non-zero stream_id"),
        (FrameType::Reset, true) => Some("RESET requires non-zero stream_id"),
        (FrameType::Abort, true) => Some("ABORT requires non-zero stream_id"),
        (FrameType::Ping, false) => Some("PING requires stream_id = 0"),
        (FrameType::Pong, false) => Some("PONG requires stream_id = 0"),
        (FrameType::GoAway, false) => Some("GOAWAY requires stream_id = 0"),
        (FrameType::Close, false) => Some("CLOSE requires stream_id = 0"),
        _ => None,
    };
    if let Some(message) = message {
        return Err(Error::protocol(message));
    }
    Ok(())
}

fn validate_data_payload(payload: &[u8], flags: u8) -> Result<()> {
    if flags & FRAME_FLAG_OPEN_METADATA == 0 {
        return Ok(());
    }
    let (metadata_len, n) = parse_varint(payload)
        .map_err(|err| frame_size_with_error("invalid OPEN_METADATA length", err))?;
    if metadata_len > (payload.len() - n) as u64 {
        return Err(Error::frame_size("OPEN_METADATA payload overrun"));
    }
    let metadata_len = metadata_len as usize;
    validate_tlvs(&payload[n..n + metadata_len])
        .map_err(|err| frame_size_with_error("invalid OPEN_METADATA payload", err))
}

fn validate_exact_one_varint_payload(frame_type: FrameType, payload: &[u8]) -> Result<()> {
    let (invalid_message, trailing_message) = match frame_type {
        FrameType::MaxData => (
            "invalid MAX_DATA payload",
            "MAX_DATA payload has trailing bytes",
        ),
        FrameType::Blocked => (
            "invalid BLOCKED payload",
            "BLOCKED payload has trailing bytes",
        ),
        _ => (
            "invalid varint payload",
            "varint payload has trailing bytes",
        ),
    };
    let (_, n) =
        parse_varint(payload).map_err(|err| frame_size_with_error(invalid_message, err))?;
    if n != payload.len() {
        return Err(Error::protocol(trailing_message));
    }
    Ok(())
}

fn validate_error_and_diag_payload(payload: &[u8]) -> Result<()> {
    let (_, n) =
        parse_varint(payload).map_err(|err| frame_size_with_error("invalid error_code", err))?;
    validate_tlvs(&payload[n..])
        .map_err(|err| frame_size_with_error("invalid diagnostic payload", err))
}

fn validate_go_away_payload(payload: &[u8]) -> Result<()> {
    let mut off = 0usize;
    for _ in 0..3 {
        let (_, n) = parse_varint(&payload[off..])
            .map_err(|err| frame_size_with_error("malformed GOAWAY payload", err))?;
        off += n;
    }
    validate_tlvs(&payload[off..])
        .map_err(|err| frame_size_with_error("malformed GOAWAY diagnostics", err))
}

fn validate_ext_payload(stream_id: u64, payload: &[u8]) -> Result<()> {
    let (ext_type, n) =
        parse_varint(payload).map_err(|err| frame_size_with_error("malformed EXT payload", err))?;
    if ext_type == EXT_PRIORITY_UPDATE {
        if stream_id == 0 {
            return Err(Error::protocol(
                "PRIORITY_UPDATE requires non-zero stream_id",
            ));
        }
        parse_priority_update_metadata(&payload[n..])
            .map_err(|err| frame_size_with_error("malformed PRIORITY_UPDATE payload", err))?;
    }
    Ok(())
}

fn frame_size_with_error(context: &str, err: Error) -> Error {
    Error::frame_size(format!("{context}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{
        encoded_total_len, frame_body_len_for_stream_len, frame_body_len_u64, Frame, FrameType,
        Limits, FRAME_FLAG_FIN,
    };
    use crate::error::ErrorCode;
    use crate::varint::MAX_VARINT62;

    #[test]
    fn frame_type_is_displayable_and_string_borrowable() {
        assert_eq!(FrameType::Data.as_str(), "DATA");
        assert_eq!(FrameType::MaxData.as_ref(), "MAX_DATA");
        assert_eq!(FrameType::StopSending.to_string(), "STOP_SENDING");
        assert_eq!(FrameType::Ext.as_u8(), 11);
    }

    #[test]
    fn frame_as_view_borrows_payload_without_copying() {
        let frame = Frame::with_flags(FrameType::Data, FRAME_FLAG_FIN, 7, vec![1, 2, 3]);
        let view = frame.as_view();

        assert_eq!(view.frame_type, FrameType::Data);
        assert_eq!(view.flags, FRAME_FLAG_FIN);
        assert_eq!(view.stream_id, 7);
        assert_eq!(view.payload, &[1, 2, 3]);
        assert_eq!(view.payload.as_ptr(), frame.payload.as_ptr());
    }

    #[test]
    fn limits_normalized_uses_defaults_only_for_zero_values() {
        let normalized = Limits {
            max_frame_payload: 0,
            max_control_payload_bytes: 128,
            max_extension_payload_bytes: 0,
        }
        .normalized();

        assert_eq!(
            normalized.max_frame_payload,
            Limits::default().max_frame_payload
        );
        assert_eq!(normalized.max_control_payload_bytes, 128);
        assert_eq!(
            normalized.max_extension_payload_bytes,
            Limits::default().max_extension_payload_bytes
        );
    }

    #[test]
    fn limits_normalized_preserves_explicit_non_zero_values() {
        let explicit = Limits {
            max_frame_payload: 128,
            max_control_payload_bytes: 256,
            max_extension_payload_bytes: 512,
        };

        assert_eq!(explicit.normalized(), explicit);

        let partial = Limits {
            max_frame_payload: 0,
            max_control_payload_bytes: 128,
            max_extension_payload_bytes: 0,
        };

        let normalized = partial.normalized();
        assert_eq!(
            normalized.max_frame_payload,
            Limits::default().max_frame_payload
        );
        assert_eq!(normalized.max_control_payload_bytes, 128);
        assert_eq!(
            normalized.max_extension_payload_bytes,
            Limits::default().max_extension_payload_bytes
        );
    }

    #[test]
    fn limits_inbound_payload_limit_uses_frame_kind_specific_field() {
        let limits = Limits {
            max_frame_payload: 10,
            max_control_payload_bytes: 20,
            max_extension_payload_bytes: 30,
        };

        assert_eq!(limits.inbound_payload_limit(FrameType::Data), 10);
        assert_eq!(limits.inbound_payload_limit(FrameType::Ext), 30);
        assert_eq!(limits.inbound_payload_limit(FrameType::Ping), 20);
        assert_eq!(limits.inbound_payload_limit(FrameType::Close), 20);
    }

    #[test]
    fn frame_length_accounting_uses_checked_wide_arithmetic() {
        if let Ok(payload_len) = usize::try_from(4_294_967_294u64) {
            let body_len = frame_body_len_for_stream_len(1, payload_len).unwrap();
            assert_eq!(u64::try_from(body_len).unwrap(), 4_294_967_296);
            assert_eq!(frame_body_len_u64(body_len).unwrap(), 4_294_967_296);
        }

        let err = frame_body_len_for_stream_len(8, usize::MAX).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::FrameSize));

        if let Ok(body_len) = usize::try_from(MAX_VARINT62 + 1) {
            let err = frame_body_len_u64(body_len).unwrap_err();
            assert_eq!(err.code(), Some(ErrorCode::FrameSize));
        }

        let err = encoded_total_len(usize::MAX, 1).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    }
}
