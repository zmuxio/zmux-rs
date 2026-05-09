use crate::error::{Error, Result};
use crate::frame::Limits;
use crate::protocol::*;
#[cfg(test)]
use crate::varint::append_varint;
use crate::varint::{append_varint_reserved, parse_varint, varint_len, MAX_VARINT62};
use std::collections::HashSet;
use std::fmt;

const INLINE_UNKNOWN_SETTING_IDS: usize = 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u64)]
pub enum SchedulerHint {
    #[default]
    UnspecifiedOrBalanced = 0,
    Latency = 1,
    BalancedFair = 2,
    BulkThroughput = 3,
    GroupFair = 4,
}

impl SchedulerHint {
    #[must_use]
    pub const fn from_u64(v: u64) -> Self {
        match v {
            1 => Self::Latency,
            2 => Self::BalancedFair,
            3 => Self::BulkThroughput,
            4 => Self::GroupFair,
            _ => Self::UnspecifiedOrBalanced,
        }
    }

    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnspecifiedOrBalanced => "unspecified_or_balanced",
            Self::Latency => "latency",
            Self::BalancedFair => "balanced_fair",
            Self::BulkThroughput => "bulk_throughput",
            Self::GroupFair => "group_fair",
        }
    }
}

impl fmt::Display for SchedulerHint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for SchedulerHint {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<SchedulerHint> for u64 {
    #[inline]
    fn from(value: SchedulerHint) -> Self {
        value.as_u64()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub initial_max_stream_data_bidi_locally_opened: u64,
    pub initial_max_stream_data_bidi_peer_opened: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_data: u64,
    pub max_incoming_streams_bidi: u64,
    pub max_incoming_streams_uni: u64,
    pub max_frame_payload: u64,
    pub max_control_payload_bytes: u64,
    pub max_extension_payload_bytes: u64,
    pub scheduler_hints: SchedulerHint,
    pub ping_padding_key: u64,
}

impl Settings {
    pub const DEFAULT: Self = Self {
        initial_max_stream_data_bidi_locally_opened: 65_536,
        initial_max_stream_data_bidi_peer_opened: 65_536,
        initial_max_stream_data_uni: 65_536,
        initial_max_data: 262_144,
        max_incoming_streams_bidi: 256,
        max_incoming_streams_uni: 256,
        max_frame_payload: 16_384,
        max_control_payload_bytes: 4096,
        max_extension_payload_bytes: 4096,
        scheduler_hints: SchedulerHint::UnspecifiedOrBalanced,
        ping_padding_key: 0,
    };

    #[must_use]
    pub const fn limits(self) -> Limits {
        Limits {
            max_frame_payload: self.max_frame_payload,
            max_control_payload_bytes: self.max_control_payload_bytes,
            max_extension_payload_bytes: self.max_extension_payload_bytes,
        }
    }

    pub fn validate(self) -> Result<()> {
        for (name, value) in [
            (
                "initial_max_stream_data_bidi_locally_opened",
                self.initial_max_stream_data_bidi_locally_opened,
            ),
            (
                "initial_max_stream_data_bidi_peer_opened",
                self.initial_max_stream_data_bidi_peer_opened,
            ),
            (
                "initial_max_stream_data_uni",
                self.initial_max_stream_data_uni,
            ),
            ("initial_max_data", self.initial_max_data),
            ("max_incoming_streams_bidi", self.max_incoming_streams_bidi),
            ("max_incoming_streams_uni", self.max_incoming_streams_uni),
            ("max_frame_payload", self.max_frame_payload),
            ("max_control_payload_bytes", self.max_control_payload_bytes),
            (
                "max_extension_payload_bytes",
                self.max_extension_payload_bytes,
            ),
            ("ping_padding_key", self.ping_padding_key),
        ] {
            validate_setting_varint(name, value)?;
        }
        Ok(())
    }

    pub fn encoded_tlv_len(self) -> Result<usize> {
        self.validate()?;
        settings_tlv_len(self, Self::DEFAULT)
    }

    pub fn append_tlv_to(self, dst: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        let defaults = Self::DEFAULT;
        reserve_settings_bytes(dst, settings_tlv_len(self, defaults)?)?;
        append_settings_tlv_to(dst, self, defaults)
    }

    pub(crate) fn append_tlv_to_prevalidated(self, dst: &mut Vec<u8>) -> Result<()> {
        append_settings_tlv_to(dst, self, Self::DEFAULT)
    }
}

impl Default for Settings {
    #[inline]
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[must_use]
pub const fn default_settings() -> Settings {
    Settings::DEFAULT
}

pub fn marshal_settings_tlv(settings: Settings) -> Result<Vec<u8>> {
    settings.validate()?;
    let defaults = Settings::DEFAULT;
    let encoded_len = settings_tlv_len(settings, defaults)?;
    if encoded_len == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    reserve_settings_bytes(&mut out, encoded_len)?;
    append_settings_tlv_to(&mut out, settings, defaults)?;
    debug_assert_eq!(out.len(), encoded_len);
    Ok(out)
}

#[inline]
fn append_settings_tlv_to(dst: &mut Vec<u8>, settings: Settings, defaults: Settings) -> Result<()> {
    for (id, value, default) in settings_entries(settings, defaults) {
        if value != default {
            append_setting_varint(dst, id, value)?;
        }
    }
    Ok(())
}

#[inline]
fn settings_tlv_len(settings: Settings, defaults: Settings) -> Result<usize> {
    let mut len = 0usize;
    for (id, value, default) in settings_entries(settings, defaults) {
        if value == default {
            continue;
        }
        len = checked_len_add(
            len,
            setting_varint_tlv_len(id, value)?,
            "settings_tlv too large",
        )?;
    }
    Ok(len)
}

#[inline]
fn settings_entries(settings: Settings, defaults: Settings) -> [(u64, u64, u64); 11] {
    [
        (
            SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED,
            settings.initial_max_stream_data_bidi_locally_opened,
            defaults.initial_max_stream_data_bidi_locally_opened,
        ),
        (
            SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED,
            settings.initial_max_stream_data_bidi_peer_opened,
            defaults.initial_max_stream_data_bidi_peer_opened,
        ),
        (
            SETTING_INITIAL_MAX_STREAM_DATA_UNI,
            settings.initial_max_stream_data_uni,
            defaults.initial_max_stream_data_uni,
        ),
        (
            SETTING_INITIAL_MAX_DATA,
            settings.initial_max_data,
            defaults.initial_max_data,
        ),
        (
            SETTING_MAX_INCOMING_STREAMS_BIDI,
            settings.max_incoming_streams_bidi,
            defaults.max_incoming_streams_bidi,
        ),
        (
            SETTING_MAX_INCOMING_STREAMS_UNI,
            settings.max_incoming_streams_uni,
            defaults.max_incoming_streams_uni,
        ),
        (
            SETTING_MAX_FRAME_PAYLOAD,
            settings.max_frame_payload,
            defaults.max_frame_payload,
        ),
        (
            SETTING_MAX_CONTROL_PAYLOAD_BYTES,
            settings.max_control_payload_bytes,
            defaults.max_control_payload_bytes,
        ),
        (
            SETTING_MAX_EXTENSION_PAYLOAD_BYTES,
            settings.max_extension_payload_bytes,
            defaults.max_extension_payload_bytes,
        ),
        (
            SETTING_SCHEDULER_HINTS,
            settings.scheduler_hints.as_u64(),
            defaults.scheduler_hints.as_u64(),
        ),
        (
            SETTING_PING_PADDING_KEY,
            settings.ping_padding_key,
            defaults.ping_padding_key,
        ),
    ]
}

#[inline]
fn setting_varint_tlv_len(id: u64, value: u64) -> Result<usize> {
    let value_len = varint_len(value)?;
    checked_len_sum3(
        varint_len(id)?,
        varint_len(value_len as u64)?,
        value_len,
        "setting tlv too large",
    )
}

#[inline]
fn append_setting_varint(dst: &mut Vec<u8>, id: u64, value: u64) -> Result<()> {
    append_varint_reserved(dst, id)?;
    append_varint_reserved(dst, varint_len(value)? as u64)?;
    append_varint_reserved(dst, value)
}

pub fn parse_settings_tlv(mut src: &[u8]) -> Result<Settings> {
    let mut settings = Settings::DEFAULT;
    let mut seen_known = 0u16;
    let mut seen_unknown = UnknownSettingTracker::default();

    while !src.is_empty() {
        let (typ, n_typ) = parse_varint(src)?;
        src = &src[n_typ..];
        let (len, n_len) = parse_varint(src)?;
        src = &src[n_len..];
        if len > src.len() as u64 {
            return Err(Error::protocol("tlv value overruns containing payload"));
        }
        let len = len as usize;
        let value_bytes = &src[..len];
        src = &src[len..];

        if let Some(bit) = known_setting_seen_bit(typ) {
            if seen_known & bit != 0 {
                return Err(Error::protocol(format!("duplicate setting id {typ}")));
            }
            seen_known |= bit;
            if typ == SETTING_PREFACE_PADDING {
                continue;
            }
        } else {
            if !seen_unknown.insert(typ)? {
                return Err(Error::protocol(format!("duplicate setting id {typ}")));
            }
            continue;
        }

        let (value, n) = parse_varint(value_bytes)?;
        if n != value_bytes.len() {
            return Err(Error::protocol(format!("setting {typ} has trailing bytes")));
        }

        match typ {
            SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED => {
                settings.initial_max_stream_data_bidi_locally_opened = value;
            }
            SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED => {
                settings.initial_max_stream_data_bidi_peer_opened = value;
            }
            SETTING_INITIAL_MAX_STREAM_DATA_UNI => settings.initial_max_stream_data_uni = value,
            SETTING_INITIAL_MAX_DATA => settings.initial_max_data = value,
            SETTING_MAX_INCOMING_STREAMS_BIDI => settings.max_incoming_streams_bidi = value,
            SETTING_MAX_INCOMING_STREAMS_UNI => settings.max_incoming_streams_uni = value,
            SETTING_MAX_FRAME_PAYLOAD => settings.max_frame_payload = value,
            SETTING_MAX_CONTROL_PAYLOAD_BYTES => settings.max_control_payload_bytes = value,
            SETTING_MAX_EXTENSION_PAYLOAD_BYTES => settings.max_extension_payload_bytes = value,
            SETTING_SCHEDULER_HINTS => settings.scheduler_hints = SchedulerHint::from_u64(value),
            SETTING_PING_PADDING_KEY => settings.ping_padding_key = value,
            _ => {}
        }
    }

    Ok(settings)
}

#[derive(Default)]
struct UnknownSettingTracker {
    inline: [u64; INLINE_UNKNOWN_SETTING_IDS],
    len: usize,
    overflow: Option<HashSet<u64>>,
}

impl UnknownSettingTracker {
    #[inline]
    fn insert(&mut self, typ: u64) -> Result<bool> {
        if let Some(seen) = self.overflow.as_mut() {
            return Ok(seen.insert(typ));
        }
        if self.inline[..self.len].contains(&typ) {
            return Ok(false);
        }
        if self.len < self.inline.len() {
            self.inline[self.len] = typ;
            self.len += 1;
            return Ok(true);
        }

        let mut seen = HashSet::new();
        seen.try_reserve(self.len + 1)
            .map_err(|_| Error::local("zmux: settings duplicate tracker allocation failed"))?;
        for &known in &self.inline[..self.len] {
            seen.insert(known);
        }
        let inserted = seen.insert(typ);
        self.overflow = Some(seen);
        Ok(inserted)
    }
}

#[inline]
fn checked_len_add(lhs: usize, rhs: usize, context: &'static str) -> Result<usize> {
    lhs.checked_add(rhs)
        .ok_or_else(|| Error::frame_size(context))
}

#[inline]
fn checked_len_sum3(a: usize, b: usize, c: usize, context: &'static str) -> Result<usize> {
    checked_len_add(checked_len_add(a, b, context)?, c, context)
}

#[inline]
fn reserve_settings_bytes(dst: &mut Vec<u8>, additional: usize) -> Result<()> {
    dst.try_reserve_exact(additional)
        .map_err(|_| Error::local("zmux: settings allocation failed"))
}

#[inline]
fn validate_setting_varint(name: &'static str, value: u64) -> Result<()> {
    if value <= MAX_VARINT62 {
        Ok(())
    } else {
        Err(Error::protocol(format!(
            "settings {name} must be within varint62 range"
        )))
    }
}

#[inline]
fn known_setting_seen_bit(typ: u64) -> Option<u16> {
    let bit = match typ {
        SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED => 1 << 0,
        SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED => 1 << 1,
        SETTING_INITIAL_MAX_STREAM_DATA_UNI => 1 << 2,
        SETTING_INITIAL_MAX_DATA => 1 << 3,
        SETTING_MAX_INCOMING_STREAMS_BIDI => 1 << 4,
        SETTING_MAX_INCOMING_STREAMS_UNI => 1 << 5,
        SETTING_MAX_FRAME_PAYLOAD => 1 << 6,
        SETTING_MAX_CONTROL_PAYLOAD_BYTES => 1 << 7,
        SETTING_MAX_EXTENSION_PAYLOAD_BYTES => 1 << 8,
        SETTING_SCHEDULER_HINTS => 1 << 9,
        SETTING_PING_PADDING_KEY => 1 << 10,
        SETTING_PREFACE_PADDING => 1 << 11,
        _ => return None,
    };
    Some(bit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::append_tlv;
    use crate::varint::MAX_VARINT62;

    #[test]
    fn ping_padding_key_round_trips_and_preface_padding_is_ignored() {
        let settings = Settings {
            ping_padding_key: 123_456,
            ..Settings::default()
        };
        let mut encoded = marshal_settings_tlv(settings).unwrap();
        append_tlv(&mut encoded, SETTING_PREFACE_PADDING, &[0xff, 0x00, 0x7f]).unwrap();

        let parsed = parse_settings_tlv(&encoded).unwrap();

        assert_eq!(parsed.ping_padding_key, settings.ping_padding_key);
        assert_eq!(
            parsed.initial_max_data,
            Settings::default().initial_max_data
        );
    }

    #[test]
    fn settings_tlv_round_trips_selected_wire_fields() {
        let settings = Settings {
            initial_max_data: 12_345,
            max_frame_payload: 8_192,
            scheduler_hints: SchedulerHint::GroupFair,
            ..Settings::default()
        };
        let encoded = marshal_settings_tlv(settings).unwrap();

        let parsed = parse_settings_tlv(&encoded).unwrap();

        assert_eq!(parsed.initial_max_data, settings.initial_max_data);
        assert_eq!(parsed.max_frame_payload, settings.max_frame_payload);
        assert_eq!(parsed.scheduler_hints, settings.scheduler_hints);
    }

    #[test]
    fn settings_value_update_round_trips_ping_padding_key() {
        let settings = Settings {
            ping_padding_key: 123_456,
            ..Settings::default()
        };

        assert_eq!(settings.ping_padding_key, 123_456);
        assert_eq!(
            settings,
            Settings {
                ping_padding_key: settings.ping_padding_key,
                ..Settings::default()
            }
        );
    }

    #[test]
    fn settings_validate_rejects_payload_fields_above_varint62() {
        let frame_payload = Settings {
            max_frame_payload: MAX_VARINT62 + 1,
            ..Settings::default()
        };
        let err = frame_payload.validate().unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err
            .to_string()
            .contains("settings max_frame_payload must be within varint62 range"));

        let control_payload = Settings {
            max_control_payload_bytes: MAX_VARINT62 + 1,
            ..Settings::default()
        };
        let err = control_payload.validate().unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err
            .to_string()
            .contains("settings max_control_payload_bytes must be within varint62 range"));
    }

    #[test]
    fn padding_setting_id_matches_go_compatibility_value() {
        assert_eq!(SETTING_PING_PADDING_KEY, 11);
        assert_eq!(SETTING_PREFACE_PADDING, 12);
    }

    #[test]
    fn known_setting_seen_bit_recognizes_configured_range() {
        for id in [
            SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED,
            SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED,
            SETTING_INITIAL_MAX_STREAM_DATA_UNI,
            SETTING_INITIAL_MAX_DATA,
            SETTING_MAX_INCOMING_STREAMS_BIDI,
            SETTING_MAX_INCOMING_STREAMS_UNI,
            SETTING_MAX_FRAME_PAYLOAD,
            SETTING_MAX_CONTROL_PAYLOAD_BYTES,
            SETTING_MAX_EXTENSION_PAYLOAD_BYTES,
            SETTING_SCHEDULER_HINTS,
            SETTING_PING_PADDING_KEY,
            SETTING_PREFACE_PADDING,
        ] {
            assert!(
                known_setting_seen_bit(id).is_some_and(|bit| bit != 0),
                "missing seen bit for setting {id}"
            );
        }

        assert_eq!(known_setting_seen_bit(99), None);
    }

    #[test]
    fn settings_tlv_rejects_huge_value_length_without_truncation() {
        let mut encoded = Vec::new();
        append_varint(&mut encoded, SETTING_PREFACE_PADDING).unwrap();
        append_varint(&mut encoded, MAX_VARINT62).unwrap();

        let err = parse_settings_tlv(&encoded).unwrap_err();

        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
    }

    #[test]
    fn append_tlv_to_matches_marshal_and_preserves_dst_on_invalid_settings() {
        let settings = Settings {
            initial_max_data: 123_456,
            scheduler_hints: SchedulerHint::GroupFair,
            ping_padding_key: 0x0123_4567_89ab_cdef,
            ..Settings::default()
        };

        let marshaled = marshal_settings_tlv(settings).unwrap();
        let mut appended = vec![0xaa, 0xbb];
        settings.append_tlv_to(&mut appended).unwrap();

        assert_eq!(settings.encoded_tlv_len().unwrap(), marshaled.len());
        assert_eq!(&appended[..2], &[0xaa, 0xbb]);
        assert_eq!(&appended[2..], marshaled.as_slice());

        let invalid = Settings {
            ping_padding_key: MAX_VARINT62 + 1,
            ..Settings::default()
        };
        let mut dst = vec![1, 2, 3];
        let before = dst.clone();

        let err = invalid.append_tlv_to(&mut dst).unwrap_err();

        assert_eq!(dst, before);
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
    }

    #[test]
    fn settings_limits_view_matches_receive_limit_fields() {
        let settings = Settings {
            max_frame_payload: 32_768,
            max_control_payload_bytes: 8192,
            max_extension_payload_bytes: 16_384,
            ..Settings::default()
        };

        let limits = settings.limits();

        assert_eq!(limits.max_frame_payload, settings.max_frame_payload);
        assert_eq!(
            limits.max_control_payload_bytes,
            settings.max_control_payload_bytes
        );
        assert_eq!(
            limits.max_extension_payload_bytes,
            settings.max_extension_payload_bytes
        );
        assert_eq!(limits, settings.limits());
    }

    #[test]
    fn settings_tlv_duplicate_and_opaque_rules_match_preface_namespace() {
        let value = crate::varint::encode_varint(10).unwrap();
        let mut duplicate_known = Vec::new();
        append_tlv(&mut duplicate_known, SETTING_INITIAL_MAX_DATA, &value).unwrap();
        append_tlv(&mut duplicate_known, SETTING_INITIAL_MAX_DATA, &value).unwrap();

        let err = parse_settings_tlv(&duplicate_known).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err
            .to_string()
            .contains(&format!("duplicate setting id {SETTING_INITIAL_MAX_DATA}")));

        let mut duplicate_unknown = Vec::new();
        append_tlv(&mut duplicate_unknown, 99, &value).unwrap();
        append_tlv(&mut duplicate_unknown, 99, &value).unwrap();

        let err = parse_settings_tlv(&duplicate_unknown).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));

        let mut duplicate_padding = Vec::new();
        append_tlv(&mut duplicate_padding, SETTING_PREFACE_PADDING, &[1]).unwrap();
        append_tlv(&mut duplicate_padding, SETTING_PREFACE_PADDING, &[2]).unwrap();

        let err = parse_settings_tlv(&duplicate_padding).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err
            .to_string()
            .contains(&format!("duplicate setting id {SETTING_PREFACE_PADDING}")));

        let mut opaque = Vec::new();
        append_tlv(&mut opaque, 99, &[0xff, 0x00, 0x01]).unwrap();
        append_tlv(&mut opaque, SETTING_PREFACE_PADDING, &[0xff, 0x00, 0x01]).unwrap();

        assert_eq!(parse_settings_tlv(&opaque).unwrap(), Settings::default());
    }

    #[test]
    fn settings_tlv_unknown_duplicate_detection_spills_without_losing_seen_ids() {
        let mut many_unknown = Vec::new();
        for typ in 1000..1010 {
            append_tlv(&mut many_unknown, typ, &[0xff, 0x00]).unwrap();
        }
        assert_eq!(
            parse_settings_tlv(&many_unknown).unwrap(),
            Settings::default()
        );

        append_tlv(&mut many_unknown, 1002, &[0x01]).unwrap();
        let err = parse_settings_tlv(&many_unknown).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err.to_string().contains("duplicate setting id 1002"));
    }

    #[test]
    fn settings_tlv_bounds_known_varint_to_tlv_value() {
        let mut bounded_truncated = Vec::new();
        append_varint(&mut bounded_truncated, SETTING_INITIAL_MAX_DATA).unwrap();
        append_varint(&mut bounded_truncated, 1).unwrap();
        bounded_truncated.push(0x40);
        append_tlv(&mut bounded_truncated, 99, &[0x01]).unwrap();

        let err = parse_settings_tlv(&bounded_truncated).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err.to_string().contains("truncated varint62"));

        let mut trailing = Vec::new();
        append_tlv(&mut trailing, SETTING_INITIAL_MAX_DATA, &[0x01, 0x02]).unwrap();

        let err = parse_settings_tlv(&trailing).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));

        let mut empty = Vec::new();
        append_tlv(&mut empty, SETTING_INITIAL_MAX_DATA, &[]).unwrap();

        let err = parse_settings_tlv(&empty).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err.to_string().contains("truncated varint62"));

        let mut non_canonical = Vec::new();
        append_tlv(&mut non_canonical, SETTING_INITIAL_MAX_DATA, &[0x40, 0x01]).unwrap();

        let err = parse_settings_tlv(&non_canonical).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::Protocol));
        assert!(err.to_string().contains("non-canonical varint62"));
    }

    #[test]
    fn scheduler_hint_conversion_matches_registry() {
        assert_eq!(SchedulerHint::from_u64(1), SchedulerHint::Latency);
        assert_eq!(SchedulerHint::from_u64(4), SchedulerHint::GroupFair);
        assert_eq!(
            SchedulerHint::from_u64(99),
            SchedulerHint::UnspecifiedOrBalanced
        );
        assert_eq!(SchedulerHint::from_u64(2), SchedulerHint::BalancedFair);
        assert_eq!(SchedulerHint::BulkThroughput.as_u64(), 3);
    }

    #[test]
    fn scheduler_hint_string_surface_matches_registry_names() {
        assert_eq!(
            SchedulerHint::UnspecifiedOrBalanced.as_str(),
            "unspecified_or_balanced"
        );
        assert_eq!(SchedulerHint::Latency.as_ref(), "latency");
        assert_eq!(SchedulerHint::BalancedFair.to_string(), "balanced_fair");
        assert_eq!(SchedulerHint::BulkThroughput.as_str(), "bulk_throughput");
        assert_eq!(SchedulerHint::GroupFair.as_ref(), "group_fair");
    }
}
