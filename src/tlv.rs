use crate::error::{Error, Result};
use crate::varint::{append_varint, parse_varint, varint_len};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub typ: u64,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(typ: u64, value: impl Into<Vec<u8>>) -> Result<Self> {
        validate_tlv_header(typ, 0)?;
        let value = value.into();
        validate_tlv_header(typ, value.len())?;
        Ok(Self { typ, value })
    }

    #[must_use]
    pub fn as_view(&self) -> TlvView<'_> {
        TlvView {
            typ: self.typ,
            value: &self.value,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        validate_tlv_header(self.typ, self.value.len())
    }

    pub fn encoded_len(&self) -> Result<usize> {
        tlv_encoded_len(self.typ, self.value.len())
    }

    pub fn append_to(&self, dst: &mut Vec<u8>) -> Result<()> {
        append_tlv(dst, self.typ, &self.value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvView<'a> {
    pub typ: u64,
    pub value: &'a [u8],
}

impl<'a> TlvView<'a> {
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.value.is_empty()
    }

    pub fn validate(self) -> Result<()> {
        validate_tlv_header(self.typ, self.value.len())
    }

    pub fn encoded_len(self) -> Result<usize> {
        tlv_encoded_len(self.typ, self.value.len())
    }

    pub fn append_to(self, dst: &mut Vec<u8>) -> Result<()> {
        append_tlv(dst, self.typ, self.value)
    }

    pub fn to_tlv(self) -> Result<Tlv> {
        validate_tlv_header(self.typ, self.value.len())?;
        Ok(Tlv {
            typ: self.typ,
            value: clone_tlv_value(self.value)?,
        })
    }
}

pub(crate) struct TlvViews<'a> {
    src: &'a [u8],
}

impl<'a> Iterator for TlvViews<'a> {
    type Item = Result<TlvView<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.src.is_empty() {
            return None;
        }

        let src = self.src;
        let (typ, n_typ) = match parse_tlv_varint(src) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.src = &[];
                return Some(Err(err));
            }
        };
        let src = &src[n_typ..];
        let (len, n_len) = match parse_tlv_varint(src) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.src = &[];
                return Some(Err(err));
            }
        };
        let src = &src[n_len..];
        let len = match usize::try_from(len) {
            Ok(len) => len,
            Err(_) => {
                self.src = &[];
                return Some(Err(Error::protocol(
                    "tlv value overruns containing payload",
                )));
            }
        };
        if src.len() < len {
            self.src = &[];
            return Some(Err(Error::protocol(
                "tlv value overruns containing payload",
            )));
        }

        let (value, rest) = src.split_at(len);
        self.src = rest;
        Some(Ok(TlvView { typ, value }))
    }
}

pub(crate) fn tlv_views(src: &[u8]) -> TlvViews<'_> {
    TlvViews { src }
}

#[inline]
pub fn append_tlv(dst: &mut Vec<u8>, typ: u64, value: &[u8]) -> Result<()> {
    let encoded_len = tlv_encoded_len(typ, value.len())?;
    dst.try_reserve(encoded_len)
        .map_err(|_| Error::local("zmux: tlv allocation failed"))?;

    append_varint(dst, typ)?;
    append_varint(
        dst,
        u64::try_from(value.len()).map_err(|_| Error::frame_size("tlv value too large"))?,
    )?;
    dst.extend_from_slice(value);
    Ok(())
}

#[inline]
pub fn visit_tlvs(src: &[u8], mut visit: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<()> {
    for tlv in tlv_views(src) {
        let tlv = tlv?;
        visit(tlv.typ, tlv.value)?;
    }
    Ok(())
}

pub fn parse_tlvs_view(src: &[u8]) -> Result<Vec<TlvView<'_>>> {
    let mut out = tlv_vec_with_capacity(tlv_parse_capacity_hint(src.len()))?;
    for tlv in tlv_views(src) {
        push_tlv(&mut out, tlv?)?;
    }
    Ok(out)
}

pub fn parse_tlvs(src: &[u8]) -> Result<Vec<Tlv>> {
    let mut out = tlv_vec_with_capacity(tlv_parse_capacity_hint(src.len()))?;
    visit_tlvs(src, |typ, value| {
        push_tlv(
            &mut out,
            Tlv {
                typ,
                value: clone_tlv_value(value)?,
            },
        )
    })?;
    Ok(out)
}

#[inline]
pub(crate) fn validate_tlvs(src: &[u8]) -> Result<()> {
    visit_tlvs(src, |_, _| Ok(()))
}

fn parse_tlv_varint(src: &[u8]) -> Result<(u64, usize)> {
    parse_varint(src).map_err(|err| {
        if err.is_protocol_message("truncated varint62") {
            Error::protocol("truncated tlv")
        } else {
            err
        }
    })
}

fn validate_tlv_header(typ: u64, value_len: usize) -> Result<()> {
    let _ = tlv_encoded_len(typ, value_len)?;
    Ok(())
}

fn tlv_encoded_len(typ: u64, value_len: usize) -> Result<usize> {
    let value_len_u64 =
        u64::try_from(value_len).map_err(|_| Error::frame_size("tlv value too large"))?;
    varint_len(typ)?
        .checked_add(varint_len(value_len_u64)?)
        .and_then(|len| len.checked_add(value_len))
        .ok_or_else(|| Error::frame_size("tlv value too large"))
}

fn tlv_parse_capacity_hint(src_len: usize) -> usize {
    const MAX_HINT: usize = 64;
    (src_len / 2).min(MAX_HINT)
}

fn tlv_vec_with_capacity<T>(capacity: usize) -> Result<Vec<T>> {
    let mut out = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| Error::local("zmux: tlv allocation failed"))?;
    Ok(out)
}

fn push_tlv<T>(out: &mut Vec<T>, tlv: T) -> Result<()> {
    if out.len() == out.capacity() {
        out.try_reserve(1)
            .map_err(|_| Error::local("zmux: tlv allocation failed"))?;
    }
    out.push(tlv);
    Ok(())
}

fn clone_tlv_value(value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(value.len())
        .map_err(|_| Error::local("zmux: tlv allocation failed"))?;
    out.extend_from_slice(value);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{append_tlv, parse_tlvs, parse_tlvs_view, validate_tlvs, visit_tlvs, Tlv, TlvView};
    use crate::error::ErrorCode;
    use crate::varint::MAX_VARINT62;

    #[test]
    fn append_tlv_validates_before_writing_and_round_trips_duplicates() {
        let mut dst = vec![0xaa];
        let err = append_tlv(&mut dst, MAX_VARINT62 + 1, b"x").unwrap_err();
        assert!(err.is_protocol_message("varint62 value out of range"));
        assert_eq!(dst, [0xaa]);

        append_tlv(&mut dst, 1, b"ssh").unwrap();
        append_tlv(&mut dst, 1, b"").unwrap();

        let tlvs = parse_tlvs(&dst[1..]).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].typ, 1);
        assert_eq!(tlvs[0].value, b"ssh");
        assert_eq!(tlvs[1].typ, 1);
        assert!(tlvs[1].value.is_empty());
        validate_tlvs(&dst[1..]).unwrap();
    }

    #[test]
    fn visit_tlvs_borrows_value_bytes() {
        let mut raw = Vec::new();
        append_tlv(&mut raw, 7, b"abcd").unwrap();

        let base = raw.as_ptr() as usize;
        let end = base + raw.len();
        let mut seen = false;
        visit_tlvs(&raw, |typ, value| {
            assert_eq!(typ, 7);
            assert_eq!(value, b"abcd");
            let ptr = value.as_ptr() as usize;
            assert!(ptr >= base && ptr + value.len() <= end);
            seen = true;
            Ok(())
        })
        .unwrap();
        assert!(seen);
    }

    #[test]
    fn parse_tlvs_view_borrows_value_bytes() {
        let mut raw = Vec::new();
        append_tlv(&mut raw, 7, b"abcd").unwrap();

        let views = parse_tlvs_view(&raw).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].typ, 7);
        assert_eq!(views[0].value, b"abcd");

        let base = raw.as_ptr() as usize;
        let end = base + raw.len();
        let ptr = views[0].value.as_ptr() as usize;
        assert!(ptr >= base && ptr + views[0].value.len() <= end);
    }

    #[test]
    fn tlv_owned_and_view_methods_share_wire_encoding() {
        let tlv = Tlv::new(9, b"hello".to_vec()).unwrap();
        assert!(!tlv.is_empty());
        assert_eq!(tlv.encoded_len().unwrap(), 7);

        let view = tlv.as_view();
        assert_eq!(
            view,
            TlvView {
                typ: 9,
                value: b"hello"
            }
        );
        assert!(!view.is_empty());
        assert_eq!(view.encoded_len().unwrap(), tlv.encoded_len().unwrap());
        view.validate().unwrap();

        let mut from_owned = Vec::new();
        tlv.append_to(&mut from_owned).unwrap();
        let mut from_view = Vec::new();
        view.append_to(&mut from_view).unwrap();
        assert_eq!(from_owned, from_view);

        let cloned = view.to_tlv().unwrap();
        assert_eq!(cloned, tlv);
        assert_ne!(cloned.value.as_ptr(), tlv.value.as_ptr());
    }

    #[test]
    fn tlv_methods_validate_type_before_writing() {
        let err = Tlv::new(MAX_VARINT62 + 1, b"x".to_vec()).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));

        let view = TlvView {
            typ: MAX_VARINT62 + 1,
            value: b"x",
        };
        assert!(view.validate().is_err());

        let mut dst = vec![0xaa];
        let before = dst.clone();
        let err = view.append_to(&mut dst).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert_eq!(dst, before);
    }

    #[test]
    fn parse_tlvs_keeps_non_canonical_varint_as_protocol_error() {
        let err = parse_tlvs(&[0x40, 0x01, 0x00]).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert!(err.is_protocol_message("non-canonical varint62"));
    }

    #[test]
    fn parse_tlvs_maps_truncated_headers_and_value_overruns_to_protocol() {
        for raw in [&[0x40][..], &[0x01, 0x40][..]] {
            let err = parse_tlvs(raw).unwrap_err();
            assert_eq!(err.code(), Some(ErrorCode::Protocol));
            assert!(err.to_string().contains("truncated tlv"));
        }

        let err = parse_tlvs(&[0x01, 0x02, 0xaa]).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert!(err
            .to_string()
            .contains("tlv value overruns containing payload"));
    }
}
