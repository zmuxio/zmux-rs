//! The AEADs and the hash named by the Suite and Profile tables.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, AeadInOut, KeyInit, Nonce, Payload, Tag};
use hmac::Mac;
use sha2::{Digest, Sha256};

use super::Error;
use crate::proto::keys::{hkdf_expand, hkdf_extract};

type SealFn = fn(&[u8], u64, &[u8], &[u8]) -> Vec<u8>;
type ExpandFn = fn(&[u8], &[u8], usize) -> Result<Vec<u8>, Error>;
type OpenFn = fn(&[u8], u64, &[u8], &[u8]) -> Result<Vec<u8>, Error>;
type KeyedFn = fn(&[u8]) -> Keyed;

/// The tag length of every AEAD of the tables.
pub(crate) const TAG_LEN: usize = 16;

/// An AEAD with its parameters.
#[derive(Debug)]
pub struct Cipher {
    key_len: usize,
    tag_len: usize,
    rekey_interval: u64,
    seal: SealFn,
    open: OpenFn,
    keyed: KeyedFn,
}

impl Cipher {
    /// The key length.
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The tag length.
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// Records per key.
    pub fn rekey_interval(&self) -> u64 {
        self.rekey_interval
    }

    /// The largest record plaintext.
    pub fn max_plaintext(&self) -> usize {
        u16::MAX as usize - self.tag_len
    }

    /// Encrypts with counter `n`.
    pub fn seal(&self, key: &[u8], n: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        (self.seal)(key, n, aad, plaintext)
    }

    /// Decrypts with counter `n`.
    pub fn open(
        &self,
        key: &[u8],
        n: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        (self.open)(key, n, aad, ciphertext)
    }

    /// The AEAD with `key` expanded, for the records of one key.
    pub(crate) fn keyed(&self, key: &[u8]) -> Keyed {
        (self.keyed)(key)
    }
}

/// An AEAD instance with its key expanded: built once per key, it seals and
/// opens records in place. Dropped, its key schedule is overwritten.
pub(crate) enum Keyed {
    /// Boxed: its key schedule is large, and it is built once per key.
    Aes(Box<Aes256Gcm>),
    #[cfg(feature = "seal-chacha")]
    ChaCha(chacha20poly1305::ChaCha20Poly1305),
}

impl Keyed {
    /// Encrypts `msg` in place with counter `n` and no AAD; the tag.
    pub(crate) fn seal_in_place(&self, n: u64, msg: &mut [u8]) -> [u8; TAG_LEN] {
        match self {
            Self::Aes(c) => seal_in_place_with(&**c, nonce_be(n), msg),
            #[cfg(feature = "seal-chacha")]
            Self::ChaCha(c) => seal_in_place_with(c, chacha::nonce_le(n), msg),
        }
    }

    /// Decrypts `msg` in place with counter `n` and no AAD against `tag`.
    /// On failure `msg` holds no plaintext the caller may use.
    pub(crate) fn open_in_place(
        &self,
        n: u64,
        msg: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        match self {
            Self::Aes(c) => open_in_place_with(&**c, nonce_be(n), msg, tag),
            #[cfg(feature = "seal-chacha")]
            Self::ChaCha(c) => open_in_place_with(c, chacha::nonce_le(n), msg, tag),
        }
    }
}

fn seal_in_place_with<C: AeadInOut>(cipher: &C, nonce: [u8; 12], msg: &mut [u8]) -> [u8; TAG_LEN]
where
    Nonce<C>: From<[u8; 12]>,
{
    let tag = cipher
        .encrypt_inout_detached(&Nonce::<C>::from(nonce), b"", msg.into())
        .expect("record limits are below the AEAD limit");
    let mut out = [0; TAG_LEN];
    out.copy_from_slice(&tag);
    out
}

fn open_in_place_with<C: AeadInOut>(
    cipher: &C,
    nonce: [u8; 12],
    msg: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Error>
where
    Nonce<C>: From<[u8; 12]>,
{
    let tag = Tag::<C>::try_from(&tag[..]).map_err(|_| Error::InvalidConfig)?;
    cipher
        .decrypt_inout_detached(&Nonce::<C>::from(nonce), b"", msg.into(), &tag)
        .map_err(|_| Error::Auth)
}

fn seal_with<C: Aead + KeyInit>(key: &[u8], nonce: [u8; 12], aad: &[u8], msg: &[u8]) -> Vec<u8>
where
    Nonce<C>: From<[u8; 12]>,
{
    let cipher = C::new_from_slice(key).expect("key length comes from the table");
    let nonce = Nonce::<C>::from(nonce);
    cipher
        .encrypt(&nonce, Payload { msg, aad })
        .expect("record limits are below the AEAD limit")
}

fn open_with<C: Aead + KeyInit>(
    key: &[u8],
    nonce: [u8; 12],
    aad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Error>
where
    Nonce<C>: From<[u8; 12]>,
{
    let cipher = C::new_from_slice(key).map_err(|_| Error::InvalidConfig)?;
    let nonce = Nonce::<C>::from(nonce);
    cipher
        .decrypt(&nonce, Payload { msg, aad })
        .map_err(|_| Error::Auth)
}

fn nonce_be(n: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&n.to_be_bytes());
    nonce
}

pub(super) static AES_256_GCM: Cipher = Cipher {
    key_len: 32,
    tag_len: 16,
    rekey_interval: 1 << 20,
    seal: |k, n, a, m| seal_with::<Aes256Gcm>(k, nonce_be(n), a, m),
    open: |k, n, a, m| open_with::<Aes256Gcm>(k, nonce_be(n), a, m),
    keyed: |k| {
        Keyed::Aes(Box::new(
            Aes256Gcm::new_from_slice(k).expect("key length comes from the table"),
        ))
    },
};

/// AES-256-GCM with a big-endian counter.
pub fn aes_256_gcm() -> &'static Cipher {
    &AES_256_GCM
}

#[cfg(feature = "seal-chacha")]
pub(super) mod chacha {
    use chacha20poly1305::ChaCha20Poly1305;

    use chacha20poly1305::aead::KeyInit;

    use super::{Cipher, Keyed, open_with, seal_with};

    pub(super) fn nonce_le(n: u64) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        nonce
    }

    pub(in crate::proto::seal) static CHACHA20_POLY1305: Cipher = Cipher {
        key_len: 32,
        tag_len: 16,
        rekey_interval: 1 << 20,
        seal: |k, n, a, m| seal_with::<ChaCha20Poly1305>(k, nonce_le(n), a, m),
        open: |k, n, a, m| open_with::<ChaCha20Poly1305>(k, nonce_le(n), a, m),
        keyed: |k| {
            Keyed::ChaCha(
                ChaCha20Poly1305::new_from_slice(k).expect("key length comes from the table"),
            )
        },
    };
}

/// ChaCha20-Poly1305 with a little-endian counter.
#[cfg(feature = "seal-chacha")]
pub fn chacha20_poly1305() -> &'static Cipher {
    &chacha::CHACHA20_POLY1305
}

/// A hash with the HMAC and HKDF built on it.
#[derive(Debug)]
pub struct Hash {
    out_len: usize,
    hash: fn(&[&[u8]]) -> Vec<u8>,
    hmac: fn(&[u8], &[&[u8]]) -> Vec<u8>,
    extract: fn(&[u8], &[u8]) -> Vec<u8>,
    expand: ExpandFn,
}

impl Hash {
    /// The output length.
    pub fn out_len(&self) -> usize {
        self.out_len
    }

    /// The hash of the concatenated parts.
    pub fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        (self.hash)(parts)
    }

    /// HMAC of the concatenated parts.
    pub fn hmac(&self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        (self.hmac)(key, parts)
    }

    /// HKDF-Extract.
    pub fn extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        (self.extract)(salt, ikm)
    }

    /// HKDF-Expand. A PRK shorter than the output is `invalid_config`, and so is
    /// more than 255 outputs.
    pub fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        (self.expand)(prk, info, len)
    }
}

fn sha256_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    if prk.len() < 32 || len > 255 * 32 {
        return Err(Error::InvalidConfig);
    }
    let mut out = vec![0; len];
    hkdf_expand(prk, info, &mut out);
    Ok(out)
}

/// SHA-256.
pub static SHA256: Hash = Hash {
    out_len: 32,
    hash: |parts| {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update(part);
        }
        hash.finalize().to_vec()
    },
    hmac: |key, parts| {
        let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(key)
            .expect("HMAC takes keys of any length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    },
    extract: |salt, ikm| hkdf_extract(salt, ikm).to_vec(),
    expand: sha256_expand,
};
