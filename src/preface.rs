use crate::error::{Error, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource, Result};
use crate::protocol::*;
use crate::settings::{parse_settings_tlv, Settings};
use crate::varint::{append_varint, parse_varint, read_exact_checked, read_varint, varint_len};
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preface {
    pub preface_version: u8,
    pub role: Role,
    pub tie_breaker_nonce: u64,
    pub min_proto: u64,
    pub max_proto: u64,
    pub capabilities: u64,
    pub settings: Settings,
}

impl Preface {
    #[inline]
    pub fn has_capability(&self, bit: u64) -> bool {
        has_capability(self.capabilities, bit)
    }

    #[inline]
    pub fn supports_open_metadata(&self) -> bool {
        capabilities_support_open_metadata(self.capabilities)
    }

    #[inline]
    pub fn supports_priority_update(&self) -> bool {
        capabilities_support_priority_update(self.capabilities)
    }

    #[inline]
    pub fn can_carry_open_info(&self) -> bool {
        capabilities_can_carry_open_info(self.capabilities)
    }

    #[inline]
    pub fn can_carry_priority_on_open(&self) -> bool {
        capabilities_can_carry_priority_on_open(self.capabilities)
    }

    #[inline]
    pub fn can_carry_group_on_open(&self) -> bool {
        capabilities_can_carry_group_on_open(self.capabilities)
    }

    #[inline]
    pub fn can_carry_priority_in_update(&self) -> bool {
        capabilities_can_carry_priority_in_update(self.capabilities)
    }

    #[inline]
    pub fn can_carry_group_in_update(&self) -> bool {
        capabilities_can_carry_group_in_update(self.capabilities)
    }

    #[inline]
    pub fn has_peer_visible_priority_semantics(&self) -> bool {
        capabilities_have_peer_visible_priority_semantics(self.capabilities)
    }

    #[inline]
    pub fn has_peer_visible_group_semantics(&self) -> bool {
        capabilities_have_peer_visible_group_semantics(self.capabilities)
    }

    pub fn marshal(&self) -> Result<Vec<u8>> {
        self.marshal_with_settings_padding(&[])
    }

    pub fn marshal_with_settings_padding(&self, padding: &[u8]) -> Result<Vec<u8>> {
        if self.preface_version != PREFACE_VERSION {
            return Err(Error::unsupported_version("unsupported preface version"));
        }
        if self.min_proto == 0 || self.max_proto == 0 {
            return Err(Error::protocol("protocol version bounds must be non-zero"));
        }
        if self.role == Role::Auto && self.tie_breaker_nonce == 0 {
            return Err(Error::protocol(
                "role=auto requires non-zero tie-breaker nonce",
            ));
        }

        let base_settings_len = self.settings.encoded_tlv_len()?;
        let padding_tlv_len = if padding.is_empty() {
            0
        } else {
            settings_padding_tlv_len(padding.len())?
        };
        let settings_bytes = checked_len_add(
            base_settings_len,
            padding_tlv_len,
            "settings_tlv exceeds 4096 bytes",
        )?;
        let settings_len = settings_len_u64(settings_bytes)?;
        if settings_len > MAX_PREFACE_SETTINGS_BYTES {
            return Err(Error::frame_size("settings_tlv exceeds 4096 bytes"));
        }

        let encoded_len = self.encoded_len(settings_len, settings_bytes)?;
        let mut out = Vec::new();
        out.try_reserve_exact(encoded_len)
            .map_err(|_| Error::local("zmux: preface allocation failed"))?;
        out.extend_from_slice(MAGIC);
        out.push(self.preface_version);
        out.push(self.role.as_u8());
        append_varint(&mut out, self.tie_breaker_nonce)?;
        append_varint(&mut out, self.min_proto)?;
        append_varint(&mut out, self.max_proto)?;
        append_varint(&mut out, self.capabilities)?;
        append_varint(&mut out, settings_len)?;
        self.settings.append_tlv_to(&mut out)?;
        if !padding.is_empty() {
            crate::tlv::append_tlv(&mut out, SETTING_PREFACE_PADDING, padding)?;
        }
        debug_assert_eq!(out.len(), encoded_len);
        Ok(out)
    }

    fn encoded_len(&self, settings_len: u64, settings_bytes: usize) -> Result<usize> {
        [
            self.tie_breaker_nonce,
            self.min_proto,
            self.max_proto,
            self.capabilities,
            settings_len,
        ]
        .into_iter()
        .try_fold(MAGIC.len() + 2 + settings_bytes, |len, value| {
            checked_len_add(len, varint_len(value)?, "preface too large")
        })
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        let (p, n) = parse_preface_prefix(data)?;
        if n != data.len() {
            return Err(Error::protocol("unexpected trailing bytes after preface"));
        }
        Ok(p)
    }
}

pub fn read_preface<R: io::Read>(reader: &mut R) -> Result<Preface> {
    read_preface_inner(reader).map_err(preface_read_error)
}

pub fn parse_preface(data: &[u8]) -> Result<Preface> {
    Preface::parse(data)
}

fn read_preface_inner<R: io::Read>(reader: &mut R) -> Result<Preface> {
    let mut fixed = [0u8; 6];
    read_exact_checked(reader, &mut fixed)?;
    if &fixed[..4] != MAGIC {
        return Err(Error::protocol("invalid magic"));
    }
    if fixed[4] != PREFACE_VERSION {
        return Err(Error::unsupported_version("unsupported preface version"));
    }
    let role = Role::from_u8(fixed[5])?;
    let (tie_breaker_nonce, _) = read_varint(reader)?;
    let (min_proto, _) = read_varint(reader)?;
    let (max_proto, _) = read_varint(reader)?;
    let (capabilities, _) = read_varint(reader)?;
    let (settings_len, _) = read_varint(reader)?;
    if settings_len > MAX_PREFACE_SETTINGS_BYTES {
        return Err(Error::frame_size("settings_tlv exceeds 4096 bytes"));
    }
    let settings_len = checked_settings_len(settings_len)?;
    let mut settings_buf = [0u8; MAX_PREFACE_SETTINGS_BYTES as usize];
    let settings = &mut settings_buf[..settings_len];
    read_exact_checked(reader, settings)?;
    Ok(Preface {
        preface_version: fixed[4],
        role,
        tie_breaker_nonce,
        min_proto,
        max_proto,
        capabilities,
        settings: parse_settings_tlv(settings)?,
    })
}

fn preface_read_error(err: Error) -> Error {
    let err = if err.source_io_error_kind() == Some(io::ErrorKind::UnexpectedEof) {
        Error::protocol("truncated preface")
    } else {
        err
    };
    with_session_read_context(err)
}

fn with_session_read_context(mut err: Error) -> Error {
    if err.source() == ErrorSource::Unknown && err.source_io_error_kind().is_none() {
        err = err.with_source(ErrorSource::Remote);
    }
    err.with_scope(ErrorScope::Session)
        .with_operation(ErrorOperation::Read)
        .with_direction(ErrorDirection::Read)
}

pub fn parse_preface_prefix(data: &[u8]) -> Result<(Preface, usize)> {
    if data.len() < 6 {
        return Err(Error::protocol("truncated preface"));
    }
    if &data[..4] != MAGIC {
        return Err(Error::protocol("invalid magic"));
    }
    if data[4] != PREFACE_VERSION {
        return Err(Error::unsupported_version("unsupported preface version"));
    }
    let role = Role::from_u8(data[5])?;
    let mut off = 6usize;
    let read = |off: &mut usize| -> Result<u64> {
        let (v, n) = parse_varint(&data[*off..])?;
        *off += n;
        Ok(v)
    };
    let tie_breaker_nonce = read(&mut off)?;
    let min_proto = read(&mut off)?;
    let max_proto = read(&mut off)?;
    let capabilities = read(&mut off)?;
    let settings_len = read(&mut off)?;
    if settings_len > MAX_PREFACE_SETTINGS_BYTES {
        return Err(Error::frame_size("settings_tlv exceeds 4096 bytes"));
    }
    let settings_len = checked_settings_len(settings_len)?;
    if data.len() - off < settings_len {
        return Err(Error::protocol("truncated preface settings"));
    }
    let settings_end = off + settings_len;
    let settings = parse_settings_tlv(&data[off..settings_end])?;
    off = settings_end;
    Ok((
        Preface {
            preface_version: PREFACE_VERSION,
            role,
            tie_breaker_nonce,
            min_proto,
            max_proto,
            capabilities,
            settings,
        },
        off,
    ))
}

fn settings_len_u64(len: usize) -> Result<u64> {
    u64::try_from(len).map_err(|_| Error::frame_size("settings_tlv exceeds 4096 bytes"))
}

fn checked_settings_len(len: u64) -> Result<usize> {
    usize::try_from(len).map_err(|_| Error::frame_size("settings_tlv exceeds 4096 bytes"))
}

fn settings_padding_tlv_len(padding_len: usize) -> Result<usize> {
    checked_len_add(
        checked_len_add(
            varint_len(SETTING_PREFACE_PADDING)?,
            varint_len(settings_len_u64(padding_len)?)?,
            "settings_tlv exceeds 4096 bytes",
        )?,
        padding_len,
        "settings_tlv exceeds 4096 bytes",
    )
}

fn checked_len_add(lhs: usize, rhs: usize, context: &'static str) -> Result<usize> {
    lhs.checked_add(rhs)
        .ok_or_else(|| Error::frame_size(context))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub proto: u64,
    pub capabilities: u64,
    pub local_role: Role,
    pub peer_role: Role,
    pub peer_settings: Settings,
}

impl Negotiated {
    #[inline]
    pub fn has_capability(&self, bit: u64) -> bool {
        has_capability(self.capabilities, bit)
    }

    #[inline]
    pub fn supports_open_metadata(&self) -> bool {
        capabilities_support_open_metadata(self.capabilities)
    }

    #[inline]
    pub fn supports_priority_update(&self) -> bool {
        capabilities_support_priority_update(self.capabilities)
    }

    #[inline]
    pub fn can_carry_open_info(&self) -> bool {
        capabilities_can_carry_open_info(self.capabilities)
    }

    #[inline]
    pub fn can_carry_priority_on_open(&self) -> bool {
        capabilities_can_carry_priority_on_open(self.capabilities)
    }

    #[inline]
    pub fn can_carry_group_on_open(&self) -> bool {
        capabilities_can_carry_group_on_open(self.capabilities)
    }

    #[inline]
    pub fn can_carry_priority_in_update(&self) -> bool {
        capabilities_can_carry_priority_in_update(self.capabilities)
    }

    #[inline]
    pub fn can_carry_group_in_update(&self) -> bool {
        capabilities_can_carry_group_in_update(self.capabilities)
    }

    #[inline]
    pub fn has_peer_visible_priority_semantics(&self) -> bool {
        capabilities_have_peer_visible_priority_semantics(self.capabilities)
    }

    #[inline]
    pub fn has_peer_visible_group_semantics(&self) -> bool {
        capabilities_have_peer_visible_group_semantics(self.capabilities)
    }
}

pub fn negotiate_prefaces(local: &Preface, peer: &Preface) -> Result<Negotiated> {
    if local.role == Role::Auto && local.tie_breaker_nonce == 0 {
        return Err(Error::protocol("local auto role requires non-zero nonce"));
    }
    if peer.role == Role::Auto && peer.tie_breaker_nonce == 0 {
        return Err(Error::protocol("peer auto role requires non-zero nonce"));
    }

    let proto = local.max_proto.min(peer.max_proto);
    if proto < local.min_proto.max(peer.min_proto) {
        return Err(Error::unsupported_version("no compatible protocol version"));
    }
    for settings in [local.settings, peer.settings] {
        if settings.max_frame_payload < 16_384
            || settings.max_control_payload_bytes < 4096
            || settings.max_extension_payload_bytes < 4096
        {
            return Err(Error::protocol("receive limits below compatibility floor"));
        }
    }

    let (local_role, peer_role) = resolve_roles(
        local.role,
        local.tie_breaker_nonce,
        peer.role,
        peer.tie_breaker_nonce,
    )?;

    Ok(Negotiated {
        proto,
        capabilities: local.capabilities & peer.capabilities,
        local_role,
        peer_role,
        peer_settings: peer.settings,
    })
}

pub fn resolve_roles(
    local_role: Role,
    local_nonce: u64,
    peer_role: Role,
    peer_nonce: u64,
) -> Result<(Role, Role)> {
    match (local_role, peer_role) {
        (Role::Initiator, Role::Responder) => Ok((Role::Initiator, Role::Responder)),
        (Role::Responder, Role::Initiator) => Ok((Role::Responder, Role::Initiator)),
        (Role::Initiator, Role::Auto) => Ok((Role::Initiator, Role::Responder)),
        (Role::Responder, Role::Auto) => Ok((Role::Responder, Role::Initiator)),
        (Role::Auto, Role::Initiator) => Ok((Role::Responder, Role::Initiator)),
        (Role::Auto, Role::Responder) => Ok((Role::Initiator, Role::Responder)),
        (Role::Initiator, Role::Initiator) => Err(Error::role_conflict(
            "both peers explicitly requested initiator",
        )),
        (Role::Responder, Role::Responder) => Err(Error::role_conflict(
            "both peers explicitly requested responder",
        )),
        (Role::Auto, Role::Auto) => {
            if local_nonce == peer_nonce {
                return Err(Error::role_conflict("equal auto-role nonces"));
            }
            if local_nonce > peer_nonce {
                Ok((Role::Initiator, Role::Responder))
            } else {
                Ok((Role::Responder, Role::Initiator))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preface_settings_padding_is_wire_only() {
        let preface = Preface {
            preface_version: PREFACE_VERSION,
            role: Role::Initiator,
            tie_breaker_nonce: 0,
            min_proto: PROTO_VERSION,
            max_proto: PROTO_VERSION,
            capabilities: 0,
            settings: Settings {
                ping_padding_key: 99,
                ..Settings::default()
            },
        };

        let base = preface.marshal().unwrap();
        let padded = preface
            .marshal_with_settings_padding(&[0xff, 0x00, 0x80, 0x01])
            .unwrap();

        assert!(padded.len() > base.len());
        assert_eq!(Preface::parse(&padded).unwrap(), preface);
    }

    #[test]
    fn preface_and_negotiated_expose_capability_helpers() {
        let caps =
            CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS | CAPABILITY_PRIORITY_UPDATE;
        let preface = Preface {
            preface_version: PREFACE_VERSION,
            role: Role::Initiator,
            tie_breaker_nonce: 0,
            min_proto: PROTO_VERSION,
            max_proto: PROTO_VERSION,
            capabilities: caps,
            settings: Settings::default(),
        };
        let negotiated = Negotiated {
            proto: PROTO_VERSION,
            capabilities: caps,
            local_role: Role::Initiator,
            peer_role: Role::Responder,
            peer_settings: Settings::default(),
        };

        assert!(preface.has_capability(CAPABILITY_OPEN_METADATA));
        assert!(preface.supports_open_metadata());
        assert!(preface.supports_priority_update());
        assert!(preface.can_carry_open_info());
        assert!(preface.can_carry_priority_on_open());
        assert!(!preface.can_carry_group_on_open());
        assert!(preface.can_carry_priority_in_update());
        assert!(!preface.can_carry_group_in_update());
        assert!(preface.has_peer_visible_priority_semantics());
        assert!(!preface.has_peer_visible_group_semantics());

        assert!(negotiated.has_capability(CAPABILITY_OPEN_METADATA));
        assert!(negotiated.supports_open_metadata());
        assert!(negotiated.supports_priority_update());
        assert!(negotiated.can_carry_open_info());
        assert!(negotiated.can_carry_priority_on_open());
        assert!(!negotiated.can_carry_group_on_open());
        assert!(negotiated.can_carry_priority_in_update());
        assert!(!negotiated.can_carry_group_in_update());
        assert!(negotiated.has_peer_visible_priority_semantics());
        assert!(!negotiated.has_peer_visible_group_semantics());
    }

    #[test]
    fn preface_padding_is_rejected_before_exceeding_settings_limit() {
        let preface = Preface {
            preface_version: PREFACE_VERSION,
            role: Role::Initiator,
            tie_breaker_nonce: 0,
            min_proto: PROTO_VERSION,
            max_proto: PROTO_VERSION,
            capabilities: 0,
            settings: Settings::default(),
        };
        let padding = vec![0; MAX_PREFACE_SETTINGS_BYTES as usize];

        let err = preface.marshal_with_settings_padding(&padding).unwrap_err();

        assert_eq!(err.code(), Some(crate::ErrorCode::FrameSize));
        assert!(err.to_string().contains("settings_tlv exceeds 4096 bytes"));
    }

    #[test]
    fn preface_marshal_rejects_zero_protocol_bounds() {
        let mut preface = Preface {
            preface_version: PREFACE_VERSION,
            role: Role::Initiator,
            tie_breaker_nonce: 0,
            min_proto: PROTO_VERSION,
            max_proto: PROTO_VERSION,
            capabilities: 0,
            settings: Settings::default(),
        };

        preface.min_proto = 0;
        let err = preface.marshal().unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err
            .to_string()
            .contains("protocol version bounds must be non-zero"));

        preface.min_proto = PROTO_VERSION;
        preface.max_proto = 0;
        let err = preface.marshal().unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err
            .to_string()
            .contains("protocol version bounds must be non-zero"));
    }
}
