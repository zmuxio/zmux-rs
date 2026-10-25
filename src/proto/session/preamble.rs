//! The application's view of a stream preamble (EXTENSIONS.md Section 4):
//! one value given when a stream is opened and returned for a stream the
//! peer opened, so that a relay forwards it whole.

use std::fmt;

use bytes::{Bytes, BytesMut};

use crate::proto::frame::Dir;
use crate::proto::payload::{AppTlvs, is_application_tlv_type};
use crate::proto::varint;

use super::OpenError;

/// A stream's preamble: its open info, its application TLVs in order, and
/// whether it carries a pipe pair of a nested session (EXTENSIONS.md
/// Sections 4 and 10.2).
///
/// Given when the stream is opened ([`Session::open_bi_with`](crate::Session#method.open_bi_with),
/// [`Session::open_uni_with`](crate::Session#method.open_uni_with), [`Session::open_pipe_stream`](crate::Session#method.open_pipe_stream)), so that it
/// cannot come too late; for a stream the peer opened,
/// [`RecvStream::preamble`](crate::RecvStream#method.preamble) returns the same type, and a relay opens the
/// next hop's stream with it, adjusted as its conventions say. The stream's
/// requested priority is not part of it: [`RecvStream::set_peer_priority`](crate::RecvStream#method.set_peer_priority)
/// may be called at any time.
///
/// Values share the buffers they came in; cloning is cheap.
///
/// ```
/// use zmux::Preamble;
///
/// const DEST: u64 = 0x1000;
/// const HOPS: u64 = 0x1001;
/// let pre = Preamble::new()
///     .with_info("GET /video")
///     .with_tlv(DEST, b"10.0.0.7:443")
///     .with_tlv(HOPS, [8]);
/// // A relay forwards it with one hop less.
/// let mut next = pre.clone();
/// let hops = next.tlv(HOPS).map_or(0, |v| v[0]);
/// next.replace_tlv(HOPS, [hops - 1]);
/// assert_eq!(next.tlv(DEST).as_deref(), Some(&b"10.0.0.7:443"[..]));
/// assert_eq!(next.tlv(HOPS).as_deref(), Some(&[7][..]));
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Preamble {
    info: Option<Bytes>,
    /// The application TLVs, encoded (type, length, value) in order.
    tlvs: Bytes,
    pipe_carrier: bool,
    /// A TLV type that cannot be encoded was added (checked at opening).
    unencodable: bool,
}

impl Preamble {
    /// An empty preamble: no open info, no TLV, not a carrier.
    pub fn new() -> Self {
        Self::default()
    }

    /// With `info` as the open info (OPEN_INFO).
    #[must_use]
    pub fn with_info(mut self, info: impl Into<Bytes>) -> Self {
        self.info = Some(info.into());
        self
    }

    /// With an application TLV appended: `ty` from 0x1000 to 0x3fff, not
    /// a GREASE value (checked when the stream is opened,
    /// [`OpenError::InvalidArgument`]). Repeatable; sent in the order
    /// added.
    #[must_use]
    pub fn with_tlv(mut self, ty: u64, value: impl AsRef<[u8]>) -> Self {
        self.push_tlv(ty, value.as_ref());
        self
    }

    /// Marked as the carrier of a pipe pair of a nested session
    /// (PIPE_CARRIER, EXTENSIONS.md Section 10.2; bidirectional streams
    /// only). [`Session::open_pipe_stream`](crate::Session#method.open_pipe_stream) sets it itself.
    #[must_use]
    pub fn with_pipe_carrier(mut self) -> Self {
        self.pipe_carrier = true;
        self
    }

    /// The open info.
    pub fn info(&self) -> Option<&Bytes> {
        self.info.as_ref()
    }

    /// Sets or clears the open info.
    pub fn set_info(&mut self, info: Option<Bytes>) {
        self.info = info;
    }

    /// The application TLVs in order; the values share the preamble's
    /// buffer.
    pub fn tlvs(&self) -> impl Iterator<Item = (u64, Bytes)> + '_ {
        AppTlvs::new(&self.tlvs).map(|(ty, v)| (ty, self.tlvs.slice_ref(v)))
    }

    /// The value of the first TLV of type `ty`.
    pub fn tlv(&self, ty: u64) -> Option<Bytes> {
        self.tlvs().find(|(t, _)| *t == ty).map(|(_, v)| v)
    }

    /// Appends an application TLV (see [`Preamble::with_tlv`]).
    pub fn push_tlv(&mut self, ty: u64, value: &[u8]) {
        if ty > varint::MAX {
            self.unencodable = true;
            return;
        }
        let mut out = Vec::with_capacity(self.tlvs.len() + value.len() + 16);
        out.extend_from_slice(&self.tlvs);
        AppTlvs::encode_one(ty, value, &mut out);
        self.tlvs = Bytes::from(out);
    }

    /// Replaces the TLVs of type `ty` with one of value `value`, where the
    /// first of them was, or appends it.
    pub fn replace_tlv(&mut self, ty: u64, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        if ty > varint::MAX {
            self.unencodable = true;
            return;
        }
        let mut out = Vec::with_capacity(self.tlvs.len() + value.len() + 16);
        let mut done = false;
        for (t, v) in AppTlvs::new(&self.tlvs) {
            if t != ty {
                AppTlvs::encode_one(t, v, &mut out);
            } else if !done {
                AppTlvs::encode_one(ty, value, &mut out);
                done = true;
            }
        }
        if !done {
            AppTlvs::encode_one(ty, value, &mut out);
        }
        self.tlvs = Bytes::from(out);
    }

    /// Removes the TLVs of type `ty`.
    pub fn remove_tlv(&mut self, ty: u64) {
        let mut out = Vec::with_capacity(self.tlvs.len());
        for (t, v) in AppTlvs::new(&self.tlvs).filter(|(t, _)| *t != ty) {
            AppTlvs::encode_one(t, v, &mut out);
        }
        self.tlvs = Bytes::from(out);
    }

    /// Whether the stream carries a pipe pair of a nested session.
    pub fn is_pipe_carrier(&self) -> bool {
        self.pipe_carrier
    }

    /// Marks or unmarks the stream as a pipe carrier.
    pub fn set_pipe_carrier(&mut self, on: bool) {
        self.pipe_carrier = on;
    }

    /// Whether the preamble holds nothing to send.
    pub fn is_empty(&self) -> bool {
        self.info.is_none() && self.tlvs.is_empty() && !self.pipe_carrier && !self.unencodable
    }

    /// A preamble from a stream's stored parts: its open info, its encoded
    /// TLVs (only the application ones are kept) and the carrier flag.
    pub(crate) fn from_parts(info: Option<Bytes>, raw: Option<&Bytes>, carrier: bool) -> Self {
        let tlvs = match raw {
            None => Bytes::new(),
            // Only application TLVs: shared as they are.
            Some(raw) if AppTlvs::new(raw).encoded_len() == raw.len() => raw.clone(),
            Some(raw) => {
                let mut out = BytesMut::new();
                for (t, v) in AppTlvs::new(raw) {
                    let mut one = Vec::new();
                    AppTlvs::encode_one(t, v, &mut one);
                    out.extend_from_slice(&one);
                }
                out.freeze()
            }
        };
        Self {
            info,
            tlvs,
            pipe_carrier: carrier,
            unencodable: false,
        }
    }

    /// The parts a stream stores: open info, encoded TLVs, carrier flag.
    pub(crate) fn parts(&self) -> (Option<Bytes>, Option<Bytes>, bool) {
        let tlvs = (!self.tlvs.is_empty()).then(|| self.tlvs.clone());
        (self.info.clone(), tlvs, self.pipe_carrier)
    }

    /// Checks the preamble for a stream of type `dir`: every TLV whole and
    /// of an application type, PIPE_CARRIER only on a bidirectional
    /// stream.
    pub(crate) fn check(&self, dir: Dir) -> Result<(), OpenError> {
        if self.unencodable || (self.pipe_carrier && dir != Dir::Bidi) {
            return Err(OpenError::InvalidArgument);
        }
        let mut rest = &self.tlvs[..];
        while !rest.is_empty() {
            let (ty, w1) = varint::decode(rest).ok_or(OpenError::InvalidArgument)?;
            let (len, w2) = varint::decode(&rest[w1..]).ok_or(OpenError::InvalidArgument)?;
            let end = usize::try_from(len)
                .ok()
                .and_then(|l| (w1 + w2).checked_add(l))
                .filter(|&e| e <= rest.len())
                .ok_or(OpenError::InvalidArgument)?;
            if !is_application_tlv_type(ty) {
                return Err(OpenError::InvalidArgument);
            }
            rest = &rest[end..];
        }
        Ok(())
    }
}

impl fmt::Debug for Preamble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Preamble")
            .field("info", &self.info)
            .field("tlvs", &self.tlvs().collect::<Vec<_>>())
            .field("pipe_carrier", &self.pipe_carrier)
            .finish()
    }
}
