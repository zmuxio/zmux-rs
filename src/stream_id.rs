use crate::error::{Error, Result};
use crate::protocol::Role;
use crate::settings::Settings;
use crate::varint::MAX_VARINT62;

#[inline]
#[must_use]
pub(crate) const fn first_local_stream_id(role: Role, bidi: bool) -> u64 {
    match (role, bidi) {
        (Role::Initiator, true) => 4,
        (Role::Initiator, false) => 2,
        (Role::Responder, true) => 1,
        (Role::Responder, false) => 3,
        (Role::Auto, _) => 0,
    }
}

#[inline]
#[must_use]
pub(crate) const fn first_peer_stream_id(local_role: Role, bidi: bool) -> u64 {
    match (local_role, bidi) {
        (Role::Initiator, true) => 1,
        (Role::Initiator, false) => 3,
        (Role::Responder, true) => 4,
        (Role::Responder, false) => 2,
        (Role::Auto, _) => 0,
    }
}

#[inline]
#[must_use]
pub(crate) const fn stream_is_bidi(stream_id: u64) -> bool {
    stream_id & 0x2 == 0
}

#[inline]
#[must_use]
pub(crate) const fn stream_opener(stream_id: u64) -> Role {
    if stream_id & 0x1 == 0 {
        Role::Initiator
    } else {
        Role::Responder
    }
}

#[inline]
#[must_use]
pub(crate) const fn stream_is_local(local_role: Role, stream_id: u64) -> bool {
    matches!(
        (local_role, stream_opener(stream_id)),
        (Role::Initiator, Role::Initiator) | (Role::Responder, Role::Responder)
    )
}

#[inline]
#[must_use]
pub(crate) fn projected_local_open_id(next_id: u64, queue_len: usize) -> u64 {
    if queue_len == 0 || next_id == 0 || next_id > MAX_VARINT62 {
        return next_id;
    }
    let remaining = (MAX_VARINT62 - next_id) / 4;
    let Ok(queue_len) = u64::try_from(queue_len) else {
        return MAX_VARINT62 + 1;
    };
    if queue_len > remaining {
        MAX_VARINT62 + 1
    } else {
        next_id + queue_len * 4
    }
}

#[inline]
pub(crate) fn validate_go_away_watermark_for_direction(stream_id: u64, bidi: bool) -> Result<()> {
    if stream_id == 0 {
        return Ok(());
    }
    if stream_id > MAX_VARINT62 {
        return Err(Error::protocol(format!(
            "stream {stream_id} exceeds varint62 range for GOAWAY watermark"
        )));
    }
    if stream_is_bidi(stream_id) != bidi {
        return Err(Error::protocol(format!(
            "stream {stream_id} has wrong direction for GOAWAY watermark"
        )));
    }
    Ok(())
}

#[inline]
pub(crate) fn validate_go_away_watermark_creator(owner: Role, stream_id: u64) -> Result<()> {
    if stream_id == 0 {
        return Ok(());
    }
    if !stream_is_local(owner, stream_id) {
        return Err(Error::protocol(format!(
            "stream {stream_id} is not creatable by role {owner}"
        )));
    }
    Ok(())
}

#[inline]
#[must_use]
pub(crate) fn initial_send_window(local_role: Role, peer: &Settings, stream_id: u64) -> u64 {
    let bidi = stream_is_bidi(stream_id);
    let local = stream_is_local(local_role, stream_id);
    if !bidi {
        if local {
            peer.initial_max_stream_data_uni
        } else {
            0
        }
    } else if local {
        peer.initial_max_stream_data_bidi_peer_opened
    } else {
        peer.initial_max_stream_data_bidi_locally_opened
    }
}

#[inline]
#[must_use]
pub(crate) fn initial_receive_window(local_role: Role, local: &Settings, stream_id: u64) -> u64 {
    let bidi = stream_is_bidi(stream_id);
    let opened_locally = stream_is_local(local_role, stream_id);
    if !bidi {
        if opened_locally {
            0
        } else {
            local.initial_max_stream_data_uni
        }
    } else if opened_locally {
        local.initial_max_stream_data_bidi_locally_opened
    } else {
        local.initial_max_stream_data_bidi_peer_opened
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_id_classification_matches_registry() {
        assert_eq!(first_local_stream_id(Role::Initiator, true), 4);
        assert_eq!(first_local_stream_id(Role::Initiator, false), 2);
        assert_eq!(first_local_stream_id(Role::Responder, true), 1);
        assert_eq!(first_local_stream_id(Role::Responder, false), 3);
        assert_eq!(first_peer_stream_id(Role::Initiator, true), 1);
        assert_eq!(first_peer_stream_id(Role::Initiator, false), 3);
        assert_eq!(first_peer_stream_id(Role::Responder, true), 4);
        assert_eq!(first_peer_stream_id(Role::Responder, false), 2);

        assert!(stream_is_bidi(4));
        assert!(!stream_is_bidi(2));
        assert_eq!(stream_opener(4), Role::Initiator);
        assert_eq!(stream_opener(1), Role::Responder);
        assert!(stream_is_local(Role::Initiator, 2));
        assert!(!stream_is_local(Role::Initiator, 3));
    }

    #[test]
    fn stream_id_projection_and_watermarks_do_not_wrap() {
        let next = first_local_stream_id(Role::Responder, true);
        let last = next + ((MAX_VARINT62 - next) / 4) * 4;

        assert_eq!(last & 0x3, next & 0x3);
        assert!(last <= MAX_VARINT62);
        assert_eq!(projected_local_open_id(9, 3), 21);
        assert_eq!(projected_local_open_id(next, 3), next + 12);
        assert_eq!(projected_local_open_id(last - 4, 1), last);
        assert_eq!(projected_local_open_id(last, 1), MAX_VARINT62 + 1);
        assert_eq!(projected_local_open_id(0, 1), 0);
        assert_eq!(
            projected_local_open_id(MAX_VARINT62 + 1, 1),
            MAX_VARINT62 + 1
        );
    }

    #[test]
    fn stream_id_validation_rejects_reserved_range_and_wrong_local_class() {
        assert!(validate_go_away_watermark_for_direction(MAX_VARINT62 + 1, true).is_err());
        assert!(validate_go_away_watermark_for_direction(2, true).is_err());
        assert!(validate_go_away_watermark_creator(Role::Responder, 4).is_err());
    }

    #[test]
    fn initial_windows_match_setting_direction_model() {
        let settings = Settings {
            initial_max_stream_data_bidi_locally_opened: 11,
            initial_max_stream_data_bidi_peer_opened: 22,
            initial_max_stream_data_uni: 33,
            ..Settings::default()
        };

        assert_eq!(initial_send_window(Role::Responder, &settings, 1), 22);
        assert_eq!(initial_send_window(Role::Responder, &settings, 4), 11);
        assert_eq!(initial_send_window(Role::Responder, &settings, 2), 0);
        assert_eq!(initial_send_window(Role::Responder, &settings, 3), 33);

        assert_eq!(initial_receive_window(Role::Responder, &settings, 1), 11);
        assert_eq!(initial_receive_window(Role::Responder, &settings, 4), 22);
        assert_eq!(initial_receive_window(Role::Responder, &settings, 2), 33);
        assert_eq!(initial_receive_window(Role::Responder, &settings, 3), 0);
    }
}
