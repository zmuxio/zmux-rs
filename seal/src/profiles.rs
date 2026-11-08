//! The choices of Profile of both ends, in one place.

use zmux_seal_proto::Profile;

/// A client's default list without AES hardware.
const CLIENT: [u64; 4] = [1, 4, 3, 5];
/// A client's default list with AES hardware.
const CLIENT_AES: [u64; 4] = [3, 5, 1, 4];
/// What a server accepts by default: no Profile without a pre-shared key.
pub(crate) const SERVER_DEFAULT: [u64; 2] = [1, 3];

pub(crate) fn client_default() -> &'static [u64] {
    if zmux::proto::seal::has_aes_hardware() {
        &CLIENT_AES
    } else {
        &CLIENT
    }
}

pub(crate) fn has_psk(profile: Profile) -> bool {
    profile.psk_len().is_some()
}
