use crate::error::{Error, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource, Result};
use std::io;

pub const MAX_VARINT62: u64 = (1u64 << 62) - 1;
pub const MAX_VARINT_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PackedVarint {
    value: u64,
    bytes: [u8; MAX_VARINT_LEN],
    len: u8,
}

impl PackedVarint {
    #[inline]
    pub(crate) fn new(value: u64) -> Result<Self> {
        let mut bytes = [0u8; MAX_VARINT_LEN];
        let len = encode_varint_to_slice(&mut bytes, value)?;
        Ok(Self {
            value,
            bytes,
            len: len as u8,
        })
    }

    #[inline]
    pub(crate) fn value(self) -> u64 {
        self.value
    }

    #[inline]
    pub(crate) fn len(self) -> usize {
        self.len as usize
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }
}

#[inline]
pub fn varint_len(v: u64) -> Result<usize> {
    if v <= MAX_VARINT62 {
        Ok(canonical_varint_len(v))
    } else {
        Err(Error::protocol("varint62 value out of range"))
    }
}

#[inline]
pub fn append_varint(dst: &mut Vec<u8>, v: u64) -> Result<()> {
    let n = varint_len(v)?;
    dst.try_reserve(n)
        .map_err(|_| Error::local("zmux: varint allocation failed"))?;
    append_varint_reserved_with_len(dst, v, n);
    Ok(())
}

#[inline]
pub(crate) fn append_varint_reserved(dst: &mut Vec<u8>, v: u64) -> Result<()> {
    let n = varint_len(v)?;
    append_varint_reserved_with_len(dst, v, n);
    Ok(())
}

#[inline]
fn append_varint_reserved_with_len(dst: &mut Vec<u8>, v: u64, n: usize) {
    debug_assert!(dst.capacity().saturating_sub(dst.len()) >= n);
    match n {
        1 => dst.push(v as u8),
        2 => dst.extend_from_slice(&[((v >> 8) as u8 & 0x3f) | 0x40, v as u8]),
        4 => dst.extend_from_slice(&[
            ((v >> 24) as u8 & 0x3f) | 0x80,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]),
        8 => dst.extend_from_slice(&[
            ((v >> 56) as u8 & 0x3f) | 0xc0,
            (v >> 48) as u8,
            (v >> 40) as u8,
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]),
        _ => unreachable!(),
    }
}

#[inline]
pub fn encode_varint_to_slice(dst: &mut [u8], v: u64) -> Result<usize> {
    let n = varint_len(v)?;
    if dst.len() < n {
        return Err(Error::frame_size("varint destination too small"));
    }
    match n {
        1 => dst[0] = v as u8,
        2 => {
            dst[0] = ((v >> 8) as u8 & 0x3f) | 0x40;
            dst[1] = v as u8;
        }
        4 => {
            dst[0] = ((v >> 24) as u8 & 0x3f) | 0x80;
            dst[1] = (v >> 16) as u8;
            dst[2] = (v >> 8) as u8;
            dst[3] = v as u8;
        }
        8 => {
            dst[0] = ((v >> 56) as u8 & 0x3f) | 0xc0;
            dst[1] = (v >> 48) as u8;
            dst[2] = (v >> 40) as u8;
            dst[3] = (v >> 32) as u8;
            dst[4] = (v >> 24) as u8;
            dst[5] = (v >> 16) as u8;
            dst[6] = (v >> 8) as u8;
            dst[7] = v as u8;
        }
        _ => unreachable!(),
    }
    Ok(n)
}

#[inline]
pub fn parse_varint(src: &[u8]) -> Result<(u64, usize)> {
    if src.is_empty() {
        return Err(varint_wire_error("truncated varint62"));
    }
    let first = src[0];
    let n = encoded_len_from_first(first);
    if src.len() < n {
        return Err(varint_wire_error("truncated varint62"));
    }
    validate_decoded_varint(decode_varint_value(src, n), n)
}

#[inline]
pub(crate) fn decode_varint_with_len(src: &[u8], n: usize) -> Result<u64> {
    if !matches!(n, 1 | 2 | 4 | 8) || src.len() < n {
        return Err(varint_wire_error("truncated varint62"));
    }
    validate_decoded_varint(decode_varint_value(src, n), n).map(|(value, _)| value)
}

#[inline]
pub fn read_varint<R: io::Read>(reader: &mut R) -> Result<(u64, usize)> {
    let mut buf = [0u8; MAX_VARINT_LEN];
    buf[0] = read_first_varint_byte(reader)?;
    let n = encoded_len_from_first(buf[0]);
    if n > 1 {
        read_varint_tail_bytes(reader, &mut buf[1..n])?;
    }
    validate_decoded_varint(decode_varint_value(&buf, n), n)
}

#[inline]
pub fn encode_varint(v: u64) -> Result<Vec<u8>> {
    let mut buf = [0u8; MAX_VARINT_LEN];
    let n = encode_varint_to_slice(&mut buf, v)?;
    let mut out = Vec::new();
    out.try_reserve_exact(n)
        .map_err(|_| Error::local("zmux: varint allocation failed"))?;
    out.extend_from_slice(&buf[..n]);
    Ok(out)
}

pub(crate) fn read_exact_checked<R: io::Read>(
    reader: &mut R,
    mut dst: &mut [u8],
) -> io::Result<()> {
    while !dst.is_empty() {
        match reader.read(dst) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(n) if n <= dst.len() => {
                let (_, remaining) = dst.split_at_mut(n);
                dst = remaining;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reader reported invalid progress",
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[inline]
const fn encoded_len_from_first(first: u8) -> usize {
    1usize << (first >> 6)
}

#[inline]
const fn canonical_varint_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

#[inline]
fn decode_varint_value(src: &[u8], n: usize) -> u64 {
    debug_assert!(src.len() >= n);
    match n {
        1 => (src[0] & 0x3f) as u64,
        2 => u16::from_be_bytes([src[0] & 0x3f, src[1]]) as u64,
        4 => u32::from_be_bytes([src[0] & 0x3f, src[1], src[2], src[3]]) as u64,
        8 => u64::from_be_bytes([
            src[0] & 0x3f,
            src[1],
            src[2],
            src[3],
            src[4],
            src[5],
            src[6],
            src[7],
        ]),
        _ => unreachable!("varint62 prefix produces only 1, 2, 4, or 8 byte lengths"),
    }
}

#[inline]
fn validate_decoded_varint(value: u64, n: usize) -> Result<(u64, usize)> {
    if value > MAX_VARINT62 {
        return Err(varint_wire_error("varint62 value out of range"));
    }
    if canonical_varint_len(value) != n {
        return Err(varint_wire_error("non-canonical varint62"));
    }
    Ok((value, n))
}

#[inline]
fn read_first_varint_byte<R: io::Read>(reader: &mut R) -> Result<u8> {
    let mut byte = [0u8; 1];
    read_exact_checked(reader, &mut byte).map_err(map_varint_read_error)?;
    Ok(byte[0])
}

#[inline]
fn read_varint_tail_bytes<R: io::Read>(reader: &mut R, dst: &mut [u8]) -> Result<()> {
    read_exact_checked(reader, dst).map_err(map_varint_read_error)
}

#[inline]
fn map_varint_read_error(err: io::Error) -> Error {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        varint_wire_error("truncated varint62")
    } else {
        Error::from(err)
    }
}

#[inline]
fn varint_wire_error(message: &'static str) -> Error {
    Error::protocol(message)
        .with_scope(ErrorScope::Session)
        .with_operation(ErrorOperation::Read)
        .with_source(ErrorSource::Remote)
        .with_direction(ErrorDirection::Read)
}

#[cfg(test)]
mod tests {
    use super::{
        append_varint, encode_varint, encode_varint_to_slice, parse_varint, read_varint,
        varint_len, MAX_VARINT62,
    };
    use crate::error::{Error, ErrorCode, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource};
    use std::io;

    #[test]
    fn varint_len_and_round_trip_cover_encoding_boundaries() {
        let cases = [
            (0, 1, &[0x00][..]),
            (63, 1, &[0x3f][..]),
            (64, 2, &[0x40, 0x40][..]),
            (16_383, 2, &[0x7f, 0xff][..]),
            (16_384, 4, &[0x80, 0x00, 0x40, 0x00][..]),
            (1_073_741_823, 4, &[0xbf, 0xff, 0xff, 0xff][..]),
            (
                1_073_741_824,
                8,
                &[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00][..],
            ),
            (
                MAX_VARINT62,
                8,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            ),
        ];

        for (value, expected_len, expected_bytes) in cases {
            assert_eq!(varint_len(value).unwrap(), expected_len);
            let encoded = encode_varint(value).unwrap();
            assert_eq!(encoded, expected_bytes);
            assert_eq!(parse_varint(&encoded).unwrap(), (value, expected_len));
            let mut reader = io::Cursor::new(&encoded);
            assert_eq!(read_varint(&mut reader).unwrap(), (value, expected_len));

            let mut appended = Vec::new();
            append_varint(&mut appended, value).unwrap();
            assert_eq!(appended, expected_bytes);
        }
    }

    #[test]
    fn out_of_range_and_too_small_destination_do_not_write_partial_data() {
        let mut dst = vec![0xaa];
        let err = append_varint(&mut dst, MAX_VARINT62 + 1).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert!(err.is_protocol_message("varint62 value out of range"));
        assert_eq!(dst, [0xaa]);

        let wrapped: io::Error = err.clone().into();
        let preserved = wrapped
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<Error>())
            .expect("structured varint error should be preserved inside io::Error");
        assert_eq!(preserved.code(), Some(ErrorCode::Protocol));
        assert!(preserved.is_protocol_message("varint62 value out of range"));

        let mut short = [0u8; 1];
        let err = encode_varint_to_slice(&mut short, 64).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::FrameSize));
        assert!(err.to_string().contains("varint destination too small"));
    }

    #[test]
    fn parse_varint_rejects_truncated_and_non_canonical_encodings() {
        for raw in [&[][..], &[0x40][..], &[0x80, 0x00, 0x00][..]] {
            let err = parse_varint(raw).unwrap_err();
            assert_eq!(err.code(), Some(ErrorCode::Protocol));
            assert!(err.is_protocol_message("truncated varint62"));
            assert_varint_wire_error(&err);
        }

        for raw in [&[0x40, 0x01][..], &[0x80, 0x00, 0x00, 0x01][..]] {
            let err = parse_varint(raw).unwrap_err();
            assert_eq!(err.code(), Some(ErrorCode::Protocol));
            assert!(err.is_protocol_message("non-canonical varint62"));
            assert_varint_wire_error(&err);
        }
    }

    #[test]
    fn read_varint_maps_eof_to_structured_truncated_protocol_error() {
        let mut empty = io::Cursor::new(&[][..]);
        let err = read_varint(&mut empty).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert!(err.is_protocol_message("truncated varint62"));
        assert_varint_wire_error(&err);
        assert_eq!(err.source_io_error_kind(), None);

        for raw in [&[0x40][..], &[0x80, 0x00, 0x00][..]] {
            let mut cursor = io::Cursor::new(raw);
            let err = read_varint(&mut cursor).unwrap_err();
            assert_eq!(err.code(), Some(ErrorCode::Protocol));
            assert!(err.is_protocol_message("truncated varint62"));
            assert_varint_wire_error(&err);
            assert_eq!(err.source_io_error_kind(), None);
        }
    }

    #[test]
    fn read_varint_preserves_non_eof_io_errors() {
        struct FailingReader;

        impl io::Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::TimedOut))
            }
        }

        let mut reader = FailingReader;
        let err = read_varint(&mut reader).unwrap_err();
        assert_eq!(err.source_io_error_kind(), Some(io::ErrorKind::TimedOut));
    }

    fn assert_varint_wire_error(err: &Error) {
        assert_eq!(err.scope(), ErrorScope::Session);
        assert_eq!(err.operation(), ErrorOperation::Read);
        assert_eq!(err.source(), ErrorSource::Remote);
        assert_eq!(err.direction(), ErrorDirection::Read);
    }
}
