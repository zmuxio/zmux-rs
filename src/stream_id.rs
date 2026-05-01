use crate::error::{Error, Result};
use crate::protocol::Role;
use crate::settings::Settings;
use crate::varint::MAX_VARINT62;

#[inline]
#[must_use]
pub fn first_local_stream_id(role: Role, bidi: bool) -> u64 {
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
pub fn first_peer_stream_id(local_role: Role, bidi: bool) -> u64 {
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
pub fn stream_is_bidi(stream_id: u64) -> bool {
    stream_id & 0x2 == 0
}

#[inline]
#[must_use]
pub fn stream_opener(stream_id: u64) -> Role {
    if stream_id & 0x1 == 0 {
        Role::Initiator
    } else {
        Role::Responder
    }
}

#[inline]
#[must_use]
pub fn stream_is_local(local_role: Role, stream_id: u64) -> bool {
    stream_opener(stream_id) == local_role
}

#[inline]
#[must_use]
pub fn local_open_refused_by_goaway(
    stream_id: u64,
    bidi: bool,
    peer_goaway_bidi: u64,
    peer_goaway_uni: u64,
) -> bool {
    if bidi {
        stream_id > peer_goaway_bidi
    } else {
        stream_id > peer_goaway_uni
    }
}

#[inline]
#[must_use]
pub fn peer_open_refused_by_goaway(
    stream_id: u64,
    local_goaway_bidi: u64,
    local_goaway_uni: u64,
) -> bool {
    if stream_is_bidi(stream_id) {
        stream_id > local_goaway_bidi
    } else {
        stream_id > local_goaway_uni
    }
}

#[inline]
#[must_use]
pub fn max_stream_id_for_class(next_id: u64) -> u64 {
    if next_id == 0 || next_id > MAX_VARINT62 {
        return 0;
    }
    next_id + ((MAX_VARINT62 - next_id) / 4) * 4
}

#[inline]
#[must_use]
pub fn projected_local_open_id(next_id: u64, queue_len: usize) -> u64 {
    if queue_len == 0 || next_id == 0 || next_id > MAX_VARINT62 {
        return next_id;
    }
    let remaining = (MAX_VARINT62 - next_id) / 4;
    let queue_len = u64::try_from(queue_len).unwrap_or(u64::MAX);
    if queue_len > remaining {
        MAX_VARINT62 + 1
    } else {
        next_id + queue_len * 4
    }
}

#[inline]
#[must_use]
pub fn expected_next_peer_stream_id(
    stream_id: u64,
    next_peer_bidi: u64,
    next_peer_uni: u64,
) -> u64 {
    if stream_is_bidi(stream_id) {
        next_peer_bidi
    } else {
        next_peer_uni
    }
}

#[inline]
#[must_use]
pub fn stream_kind_for_local(local_role: Role, stream_id: u64) -> (bool, bool) {
    let bidi = stream_is_bidi(stream_id);
    let local_opened = stream_is_local(local_role, stream_id);
    match (bidi, local_opened) {
        (true, _) => (true, true),
        (false, true) => (true, false),
        (false, false) => (false, true),
    }
}

#[inline]
pub fn validate_stream_id_for_role(_local_role: Role, stream_id: u64) -> Result<()> {
    if stream_id == 0 {
        return Err(Error::protocol("stream_id = 0 is session-scoped"));
    }
    if stream_id > MAX_VARINT62 {
        return Err(Error::protocol(format!(
            "stream_id {stream_id} exceeds varint62 range"
        )));
    }
    Ok(())
}

#[inline]
pub fn validate_local_open_id(local_role: Role, stream_id: u64, bidi: bool) -> Result<()> {
    validate_stream_id_for_role(local_role, stream_id)?;
    if !stream_is_local(local_role, stream_id) {
        return Err(Error::protocol(format!(
            "stream_id {stream_id} is not locally owned for role {local_role}"
        )));
    }
    if stream_is_bidi(stream_id) != bidi {
        let want = if bidi {
            "bidirectional"
        } else {
            "unidirectional"
        };
        return Err(Error::protocol(format!(
            "stream_id {stream_id} is not {want}"
        )));
    }
    Ok(())
}

#[inline]
pub(crate) fn validate_goaway_watermark_for_direction(stream_id: u64, bidi: bool) -> Result<()> {
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
pub(crate) fn validate_goaway_watermark_creator(owner: Role, stream_id: u64) -> Result<()> {
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
pub fn initial_send_window(local_role: Role, peer: &Settings, stream_id: u64) -> u64 {
    if !stream_is_bidi(stream_id) {
        if stream_is_local(local_role, stream_id) {
            peer.initial_max_stream_data_uni
        } else {
            0
        }
    } else if stream_is_local(local_role, stream_id) {
        peer.initial_max_stream_data_bidi_peer_opened
    } else {
        peer.initial_max_stream_data_bidi_locally_opened
    }
}

#[inline]
#[must_use]
pub fn initial_receive_window(local_role: Role, local: &Settings, stream_id: u64) -> u64 {
    if !stream_is_bidi(stream_id) {
        if stream_is_local(local_role, stream_id) {
            0
        } else {
            local.initial_max_stream_data_uni
        }
    } else if stream_is_local(local_role, stream_id) {
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
        assert_eq!(stream_kind_for_local(Role::Initiator, 4), (true, true));
        assert_eq!(stream_kind_for_local(Role::Initiator, 2), (true, false));
        assert_eq!(stream_kind_for_local(Role::Initiator, 3), (false, true));
    }

    #[test]
    fn stream_id_projection_and_watermarks_do_not_wrap() {
        let next = first_local_stream_id(Role::Responder, true);
        let last = max_stream_id_for_class(next);

        assert_eq!(last & 0x3, next & 0x3);
        assert!(last <= MAX_VARINT62);
        assert_eq!(max_stream_id_for_class(9), 9 + ((MAX_VARINT62 - 9) / 4) * 4);
        assert_eq!(projected_local_open_id(9, 3), 21);
        assert_eq!(projected_local_open_id(next, 3), next + 12);
        assert_eq!(projected_local_open_id(last - 4, 1), last);
        assert_eq!(projected_local_open_id(last, 1), MAX_VARINT62 + 1);
        assert_eq!(projected_local_open_id(0, 1), 0);
        assert_eq!(
            projected_local_open_id(MAX_VARINT62 + 1, 1),
            MAX_VARINT62 + 1
        );

        assert!(local_open_refused_by_goaway(12, true, 8, 99));
        assert!(!local_open_refused_by_goaway(8, true, 8, 99));
        assert!(local_open_refused_by_goaway(
            last,
            true,
            last - 4,
            MAX_VARINT62
        ));
        assert!(!local_open_refused_by_goaway(
            last - 4,
            true,
            last - 4,
            MAX_VARINT62
        ));
        assert!(peer_open_refused_by_goaway(13, 12, 99));
        assert!(peer_open_refused_by_goaway(last, last - 4, MAX_VARINT62));
        assert_eq!(expected_next_peer_stream_id(3, 1, 3), 3);
        assert_eq!(expected_next_peer_stream_id(4, 4, 3), 4);
    }

    #[test]
    fn stream_id_validation_rejects_reserved_range_and_wrong_local_class() {
        validate_local_open_id(Role::Initiator, 4, true).unwrap();
        validate_local_open_id(Role::Initiator, 2, false).unwrap();

        assert!(validate_stream_id_for_role(Role::Initiator, 0).is_err());
        assert!(validate_stream_id_for_role(Role::Initiator, MAX_VARINT62 + 1).is_err());
        assert!(validate_local_open_id(Role::Initiator, 1, true).is_err());
        assert!(validate_local_open_id(Role::Initiator, 2, true).is_err());
        assert!(validate_goaway_watermark_for_direction(MAX_VARINT62 + 1, true).is_err());
        assert!(validate_goaway_watermark_for_direction(2, true).is_err());
        assert!(validate_goaway_watermark_creator(Role::Responder, 4).is_err());
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
