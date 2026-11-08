//! The Establish Profile table.

use zmux::proto::seal::kex::{
    self, MLKEM768_CT_LEN, MLKEM768_EK_LEN, MLKEM768_RANDOM_LEN, MLKEM768_SEED_LEN, X25519_LEN,
};
use zmux::proto::seal::{Cipher, Error, Hash, SHA256, Secret, aes_256_gcm, chacha20_poly1305};

/// The handshake name a shaper is told for Establish.
pub const HANDSHAKE_ESTABLISH: &str = "establish";

type DhOp = fn(&[u8], &[u8]) -> Result<Secret, Error>;
type EncapsOp = fn(&[u8], &[u8]) -> Result<(Vec<u8>, Secret), Error>;

pub(crate) struct DhFn {
    pub(crate) public_len: usize,
    pub(crate) private_len: usize,
    pub(crate) generate: fn() -> Result<Secret, Error>,
    pub(crate) public: fn(&[u8]) -> Vec<u8>,
    /// Fails with `kex` on an all-zero output.
    pub(crate) dh: DhOp,
}

static X25519: DhFn = DhFn {
    public_len: X25519_LEN,
    private_len: X25519_LEN,
    generate: kex::x25519_generate,
    public: |private| kex::x25519_public(private).expect("length checked against the table"),
    dh: kex::x25519,
};

/// The KEM of a hybrid Profile (Noise HFS): the initiator sends an
/// encapsulation key, the responder a ciphertext, and both mix the shared
/// secret. A KEM is not contributory: the encapsulating end alone decides it.
pub(crate) struct KemFn {
    pub(crate) encap_key_len: usize,
    pub(crate) ciphertext_len: usize,
    /// The length of the key generation seed `(d, z)`.
    pub(crate) seed_len: usize,
    /// The length of the encapsulation randomness `m`.
    pub(crate) random_len: usize,
    /// The decapsulation key and the encapsulation key of a seed.
    pub(crate) generate: fn(&[u8]) -> (Secret, Vec<u8>),
    /// `(ciphertext, shared secret)` for a received key and randomness `m`;
    /// `kex` on an invalid key. The only check of a received key.
    pub(crate) encapsulate: EncapsOp,
    /// Has no failure of its own: a wrong ciphertext gives a pseudorandom
    /// secret (implicit rejection), and the AEAD that follows fails.
    pub(crate) decapsulate: fn(&[u8], &[u8]) -> Secret,
}

static MLKEM768: KemFn = KemFn {
    encap_key_len: MLKEM768_EK_LEN,
    ciphertext_len: MLKEM768_CT_LEN,
    seed_len: MLKEM768_SEED_LEN,
    random_len: MLKEM768_RANDOM_LEN,
    generate: |seed| kex::mlkem768_generate(seed).expect("length checked against the table"),
    encapsulate: kex::mlkem768_encapsulate,
    decapsulate: |dk, ct| kex::mlkem768_decapsulate(dk, ct).expect("length checked on reading"),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    Psk,
    E,
    S,
    Ee,
    Es,
    Se,
    /// Sends a fresh KEM encapsulation key.
    E1,
    /// Encapsulates to the peer's key and mixes the shared secret.
    Ekem1,
}

pub(crate) struct Shape {
    pub(crate) messages: &'static [&'static [Token]],
    /// Known payload types of each message, padding omitted.
    pub(crate) known: &'static [&'static [u64]],
}

use Token::{E, E1, Ee, Ekem1, Es, Psk, S, Se};

const KNOWN_PSK: &[&[u64]] = &[&[2], &[1, 2, 3, 8], &[1, 2, 3, 8]];
// The msg2 of XXhfs does not authenticate the client, so it takes no first bytes
// of a carrier.
const KNOWN_NO_PSK: &[&[u64]] = &[&[], &[1, 2, 8], &[1, 2, 3, 8]];

// The KEM ciphertext follows ee, so the responder's static key, its
// credentials and everything after them are under keys holding the KEM secret.
static XXHFS_PSK0: Shape = Shape {
    messages: &[&[Psk, E, E1], &[E, Ee, Ekem1, S, Es], &[S, Se]],
    known: KNOWN_PSK,
};
static XXHFS: Shape = Shape {
    messages: &[&[E, E1], &[E, Ee, Ekem1, S, Es], &[S, Se]],
    known: KNOWN_NO_PSK,
};

pub(crate) struct Params {
    pub(crate) value: u64,
    pub(crate) noise_name: &'static str,
    pub(crate) shape: &'static Shape,
    pub(crate) dh: &'static DhFn,
    pub(crate) kem: &'static KemFn,
    pub(crate) cipher: fn() -> &'static Cipher,
    pub(crate) hash: &'static Hash,
    pub(crate) psk_len: usize,
    pub(crate) has_handle: bool,
    pub(crate) pq_confidentiality: bool,
}

macro_rules! profile {
    ($value:literal, $name:literal, $shape:ident, $cipher:path, $handle:literal, $pq:literal) => {
        Params {
            value: $value,
            noise_name: $name,
            shape: &$shape,
            dh: &X25519,
            kem: &MLKEM768,
            cipher: $cipher,
            hash: &SHA256,
            psk_len: 32,
            has_handle: $handle,
            pq_confidentiality: $pq,
        }
    };
}

/// The Profile table: numbers, patterns and Levels are assigned here only.
static PROFILES: [Params; 4] = [
    profile!(
        1,
        "Noise_XXhfs+psk0_25519+MLKEM768_ChaChaPoly_SHA256",
        XXHFS_PSK0,
        chacha20_poly1305,
        true,
        true
    ),
    profile!(
        3,
        "Noise_XXhfs+psk0_25519+MLKEM768_AESGCM_SHA256",
        XXHFS_PSK0,
        aes_256_gcm,
        true,
        true
    ),
    profile!(
        4,
        "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256",
        XXHFS,
        chacha20_poly1305,
        false,
        true
    ),
    profile!(
        5,
        "Noise_XXhfs_25519+MLKEM768_AESGCM_SHA256",
        XXHFS,
        aes_256_gcm,
        false,
        true
    ),
];

/// One complete combination of handshake functions and pattern.
#[derive(Clone, Copy)]
pub struct Profile(pub(crate) &'static Params);

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.noise_name)
    }
}

impl PartialEq for Profile {
    fn eq(&self, other: &Self) -> bool {
        self.0.value == other.0.value
    }
}

impl Eq for Profile {}

impl Profile {
    /// The Profile with this value, if this implementation has it.
    pub fn from_value(value: u64) -> Option<Profile> {
        PROFILES.iter().find(|p| p.value == value).map(Profile)
    }

    /// Every Profile of this implementation.
    pub fn all() -> impl Iterator<Item = Profile> {
        PROFILES.iter().map(Profile)
    }

    /// The Profile value.
    pub fn value(self) -> u64 {
        self.0.value
    }

    /// The Noise protocol name.
    pub fn noise_name(self) -> &'static str {
        self.0.noise_name
    }

    /// Whether the Hello carries a Handle.
    pub fn has_handle(self) -> bool {
        self.0.has_handle
    }

    /// The PQ confidentiality column: whether the handshake's confidentiality and the
    /// keys it yields resist a passive quantum adversary.
    pub fn pq_confidentiality(self) -> bool {
        self.0.pq_confidentiality
    }

    /// The AEAD of the Profile.
    pub fn cipher(self) -> &'static Cipher {
        (self.0.cipher)()
    }

    /// The handshake name a shaper is told for this Profile's messages.
    pub fn handshake_name(self) -> &'static str {
        HANDSHAKE_ESTABLISH
    }

    /// The Noise length of message `index` (0 to 2) with an empty payload: the
    /// shortest valid form, which a shaper pads from.
    pub fn empty_message_len(self, index: usize) -> usize {
        let params = self.0;
        let tag = (params.cipher)().tag_len();
        let psk = self.psk_len().is_some();
        let mut keyed = false;
        let mut out = 0;
        for tokens in params.shape.messages.iter().take(index + 1) {
            let mut len = 0;
            for &token in *tokens {
                let (value, seal) = match token {
                    Psk | Ee | Es | Se => {
                        keyed = true;
                        continue;
                    }
                    E => {
                        len += params.dh.public_len;
                        keyed |= psk;
                        continue;
                    }
                    S => (params.dh.public_len, keyed),
                    E1 => (params.kem.encap_key_len, keyed),
                    Ekem1 => (params.kem.ciphertext_len, keyed),
                };
                len += value + if seal { tag } else { 0 };
            }
            out = len + if keyed { tag } else { 0 };
        }
        out
    }

    /// The length of the pre-shared key, or `None` without one.
    pub fn psk_len(self) -> Option<usize> {
        self.0.shape.messages[0]
            .contains(&Psk)
            .then_some(self.0.psk_len)
    }
}
