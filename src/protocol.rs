use crate::error::{Error, Result};
use std::fmt;

pub const MAGIC: &[u8; 4] = b"ZMUX";
pub const PREFACE_VERSION: u8 = 1;
pub const PROTO_VERSION: u64 = 1;
pub const MAX_PREFACE_SETTINGS_BYTES: u64 = 4096;

pub const CAPABILITY_PRIORITY_HINTS: u64 = 1 << 0;
pub const CAPABILITY_STREAM_GROUPS: u64 = 1 << 1;
pub const CAPABILITY_MULTILINK_BASIC_RETIRED: u64 = 1 << 2;
pub const CAPABILITY_MULTILINK_BASIC: u64 = CAPABILITY_MULTILINK_BASIC_RETIRED;
pub const CAPABILITY_PRIORITY_UPDATE: u64 = 1 << 3;
pub const CAPABILITY_OPEN_METADATA: u64 = 1 << 4;

pub const EXT_PRIORITY_UPDATE: u64 = 1;
pub const EXT_ML_READY_RETIRED: u64 = 2;
pub const EXT_ML_ATTACH_RETIRED: u64 = 3;
pub const EXT_ML_ATTACH_ACK_RETIRED: u64 = 4;
pub const EXT_ML_DRAIN_REQ_RETIRED: u64 = 5;
pub const EXT_ML_DRAIN_ACK_RETIRED: u64 = 6;

pub const METADATA_STREAM_PRIORITY: u64 = 1;
pub const METADATA_STREAM_GROUP: u64 = 2;
pub const METADATA_OPEN_INFO: u64 = 3;

pub const DIAG_DEBUG_TEXT: u64 = 1;
pub const DIAG_RETRY_AFTER_MILLIS: u64 = 2;
pub const DIAG_OFFENDING_STREAM_ID: u64 = 3;
pub const DIAG_OFFENDING_FRAME_TYPE: u64 = 4;

pub const SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED: u64 = 1;
pub const SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED: u64 = 2;
pub const SETTING_INITIAL_MAX_STREAM_DATA_UNI: u64 = 3;
pub const SETTING_INITIAL_MAX_DATA: u64 = 4;
pub const SETTING_MAX_INCOMING_STREAMS_BIDI: u64 = 5;
pub const SETTING_MAX_INCOMING_STREAMS_UNI: u64 = 6;
pub const SETTING_MAX_FRAME_PAYLOAD: u64 = 7;
pub const SETTING_IDLE_TIMEOUT_MILLIS: u64 = 8;
pub const SETTING_KEEPALIVE_HINT_MILLIS: u64 = 9;
pub const SETTING_MAX_CONTROL_PAYLOAD_BYTES: u64 = 10;
pub const SETTING_MAX_EXTENSION_PAYLOAD_BYTES: u64 = 11;
pub const SETTING_SCHEDULER_HINTS: u64 = 12;
pub const SETTING_PING_PADDING_KEY: u64 = 13;
pub const SETTING_PREFACE_PADDING: u64 = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Role {
    Initiator = 0,
    Responder = 1,
    Auto = 2,
}

impl Role {
    #[inline]
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::Initiator,
            1 => Self::Responder,
            2 => Self::Auto,
            _ => return Err(Error::protocol("invalid role")),
        })
    }

    #[inline]
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
            Self::Auto => "auto",
        }
    }
}

impl TryFrom<u8> for Role {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Self::from_u8(value)
    }
}

impl From<Role> for u8 {
    fn from(value: Role) -> Self {
        value.as_u8()
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for Role {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[must_use]
#[inline]
pub fn has_capability(caps: u64, bit: u64) -> bool {
    caps & bit != 0
}

#[must_use]
#[inline]
pub fn capabilities_support_open_metadata(caps: u64) -> bool {
    has_capability(caps, CAPABILITY_OPEN_METADATA)
}

#[must_use]
#[inline]
pub fn capabilities_support_priority_update(caps: u64) -> bool {
    has_capability(caps, CAPABILITY_PRIORITY_UPDATE)
}

#[must_use]
#[inline]
pub fn capabilities_can_carry_open_info(caps: u64) -> bool {
    capabilities_support_open_metadata(caps)
}

#[must_use]
#[inline]
pub fn capabilities_can_carry_priority_on_open(caps: u64) -> bool {
    capabilities_support_open_metadata(caps) && has_capability(caps, CAPABILITY_PRIORITY_HINTS)
}

#[must_use]
#[inline]
pub fn capabilities_can_carry_group_on_open(caps: u64) -> bool {
    capabilities_support_open_metadata(caps) && has_capability(caps, CAPABILITY_STREAM_GROUPS)
}

#[must_use]
#[inline]
pub fn capabilities_can_carry_priority_update(caps: u64) -> bool {
    capabilities_support_priority_update(caps) && has_capability(caps, CAPABILITY_PRIORITY_HINTS)
}

#[must_use]
#[inline]
pub fn capabilities_can_carry_priority_in_update(caps: u64) -> bool {
    capabilities_can_carry_priority_update(caps)
}

#[must_use]
#[inline]
pub fn capabilities_can_carry_group_update(caps: u64) -> bool {
    capabilities_support_priority_update(caps) && has_capability(caps, CAPABILITY_STREAM_GROUPS)
}

#[must_use]
#[inline]
pub fn capabilities_can_carry_group_in_update(caps: u64) -> bool {
    capabilities_can_carry_group_update(caps)
}

#[must_use]
#[inline]
pub fn capabilities_have_peer_visible_priority_semantics(caps: u64) -> bool {
    capabilities_can_carry_priority_on_open(caps) || capabilities_can_carry_priority_update(caps)
}

#[must_use]
#[inline]
pub fn capabilities_have_peer_visible_group_semantics(caps: u64) -> bool {
    capabilities_can_carry_group_on_open(caps) || capabilities_can_carry_group_update(caps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_match_cross_language_contract() {
        assert_eq!(MAGIC, b"ZMUX");
        assert_eq!(PREFACE_VERSION, 1);
        assert_eq!(PROTO_VERSION, 1);
        assert_eq!(MAX_PREFACE_SETTINGS_BYTES, 4096);

        assert_eq!(CAPABILITY_PRIORITY_HINTS, 1);
        assert_eq!(CAPABILITY_STREAM_GROUPS, 1 << 1);
        assert_eq!(CAPABILITY_MULTILINK_BASIC_RETIRED, 1 << 2);
        assert_eq!(
            CAPABILITY_MULTILINK_BASIC,
            CAPABILITY_MULTILINK_BASIC_RETIRED
        );
        assert_eq!(CAPABILITY_PRIORITY_UPDATE, 1 << 3);
        assert_eq!(CAPABILITY_OPEN_METADATA, 1 << 4);

        assert_eq!(EXT_PRIORITY_UPDATE, 1);
        assert_eq!(EXT_ML_READY_RETIRED, 2);
        assert_eq!(EXT_ML_ATTACH_RETIRED, 3);
        assert_eq!(EXT_ML_ATTACH_ACK_RETIRED, 4);
        assert_eq!(EXT_ML_DRAIN_REQ_RETIRED, 5);
        assert_eq!(EXT_ML_DRAIN_ACK_RETIRED, 6);

        assert_eq!(SETTING_PING_PADDING_KEY, 13);
        assert_eq!(SETTING_PREFACE_PADDING, 63);
    }

    #[test]
    fn capability_helpers_require_carriage_and_semantics() {
        let priority_open = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS;
        let group_update = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_STREAM_GROUPS;

        assert!(capabilities_support_open_metadata(priority_open));
        assert!(!capabilities_support_priority_update(priority_open));
        assert!(capabilities_can_carry_priority_on_open(priority_open));
        assert!(!capabilities_can_carry_priority_update(priority_open));
        assert!(!capabilities_can_carry_priority_in_update(priority_open));
        assert!(capabilities_have_peer_visible_priority_semantics(
            priority_open
        ));

        assert!(capabilities_can_carry_group_update(group_update));
        assert!(capabilities_can_carry_group_in_update(group_update));
        assert!(!capabilities_can_carry_group_on_open(group_update));
        assert!(capabilities_have_peer_visible_group_semantics(group_update));
        assert!(!capabilities_have_peer_visible_priority_semantics(
            CAPABILITY_PRIORITY_HINTS
        ));
    }

    #[test]
    fn role_conversions_are_standard_rust_surface() {
        assert_eq!(Role::try_from(0).unwrap(), Role::Initiator);
        assert_eq!(u8::from(Role::Responder), 1);
        assert_eq!(Role::Auto.as_ref(), "auto");
        assert_eq!(Role::Initiator.to_string(), "initiator");
        assert!(Role::try_from(3).is_err());
    }
}
