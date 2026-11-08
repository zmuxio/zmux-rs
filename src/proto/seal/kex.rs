//! The key exchange primitives of the secure carrier: X25519 and ML-KEM-768. Establish
//! (Noise DH and KEM tokens), the Groups of Join and the session epochs all use these
//! entry points, so the contributory check of X25519 and the encapsulation key check of
//! ML-KEM exist once.

use libcrux_ml_kem::mlkem768;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{Error, Secret, fill_random};

/// The length of an X25519 public and private key.
pub const X25519_LEN: usize = 32;
/// The length of an ML-KEM-768 encapsulation key.
pub const MLKEM768_EK_LEN: usize = mlkem768::MlKem768PublicKey::len();
/// The length of an ML-KEM-768 ciphertext.
pub const MLKEM768_CT_LEN: usize = mlkem768::MlKem768Ciphertext::len();
/// The length of the key generation seed `(d, z)`.
pub const MLKEM768_SEED_LEN: usize = libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;
/// The length of the encapsulation randomness `m`.
pub const MLKEM768_RANDOM_LEN: usize = libcrux_ml_kem::ENCAPS_SEED_SIZE;

/// Overwrites a stack copy of key material.
fn wipe<const N: usize>(mut bytes: [u8; N]) {
    bytes.fill(0);
    std::hint::black_box(&mut bytes);
}

fn x25519_private(private: &[u8]) -> Result<StaticSecret, Error> {
    let bytes: [u8; X25519_LEN] = private.try_into().map_err(|_| Error::InvalidConfig)?;
    Ok(StaticSecret::from(bytes))
}

/// A new X25519 private key from the operating system's random source. A failing source
/// is `random_failed`: the library's own generator would panic on it.
pub fn x25519_generate() -> Result<Secret, Error> {
    let mut private = vec![0; X25519_LEN];
    fill_random(&mut private)?;
    Ok(Secret::from(private))
}

/// The public key of an X25519 private key.
pub fn x25519_public(private: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(PublicKey::from(&x25519_private(private)?)
        .as_bytes()
        .to_vec())
}

/// X25519 of a private and a public key. An all-zero output, which every low-order and
/// all-zero public key gives, is `kex`, judged in constant time by the library.
pub fn x25519(private: &[u8], public: &[u8]) -> Result<Secret, Error> {
    let public: [u8; X25519_LEN] = public.try_into().map_err(|_| Error::Kex)?;
    let shared = x25519_private(private)?.diffie_hellman(&PublicKey::from(public));
    if !shared.was_contributory() {
        return Err(Error::Kex);
    }
    Ok(Secret::from(&shared.as_bytes()[..]))
}

/// ML-KEM-768's modulus q.
const MLKEM_Q: u16 = 3329;
/// The bytes of the 12-bit coefficients that open an ML-KEM-768 encapsulation key (k = 3).
const MLKEM768_T_LEN: usize = 384 * 3;

/// The encapsulation key check of FIPS 203 Section 7.2, done here rather than left to the
/// library: the length, and every 12-bit coefficient (ByteDecode12) below q. The key is
/// public, so the check need not take constant time. This is the only check of a received
/// encapsulation key.
pub fn mlkem768_check_ek(ek: &[u8]) -> Result<(), Error> {
    if ek.len() != MLKEM768_EK_LEN {
        return Err(Error::Kex);
    }
    for &[b0, b1, b2] in ek[..MLKEM768_T_LEN].as_chunks::<3>().0 {
        let (b0, b1, b2) = (u16::from(b0), u16::from(b1), u16::from(b2));
        if (b0 | (b1 & 0x0f) << 8) >= MLKEM_Q || (b1 >> 4 | b2 << 4) >= MLKEM_Q {
            return Err(Error::Kex);
        }
    }
    Ok(())
}

/// Fresh randomness of `len` bytes from the operating system.
pub fn kem_random(len: usize) -> Result<Secret, Error> {
    let mut out = vec![0; len];
    fill_random(&mut out)?;
    Ok(Secret::from(out))
}

/// The decapsulation key and the encapsulation key of a 64-byte seed `(d, z)`.
pub fn mlkem768_generate(seed: &[u8]) -> Result<(Secret, Vec<u8>), Error> {
    let seed: [u8; MLKEM768_SEED_LEN] = seed.try_into().map_err(|_| Error::InvalidConfig)?;
    let (dk, ek) = mlkem768::generate_key_pair(seed).into_parts();
    wipe(seed);
    let dk: [u8; mlkem768::MlKem768PrivateKey::len()] = dk.into();
    let out = Secret::from(&dk[..]);
    wipe(dk);
    Ok((out, ek.as_slice().to_vec()))
}

/// `(ciphertext, shared secret)` for a received key and the randomness `m`; `kex` on a key
/// that fails [`mlkem768_check_ek`].
pub fn mlkem768_encapsulate(ek: &[u8], m: &[u8]) -> Result<(Vec<u8>, Secret), Error> {
    mlkem768_check_ek(ek)?;
    let ek = mlkem768::MlKem768PublicKey::try_from(ek).map_err(|_| Error::Kex)?;
    let m: [u8; MLKEM768_RANDOM_LEN] = m.try_into().map_err(|_| Error::InvalidConfig)?;
    let (ct, ss) = mlkem768::encapsulate(&ek, m);
    wipe(m);
    let out = Secret::from(&ss[..]);
    wipe(ss);
    Ok((ct.as_slice().to_vec(), out))
}

/// The shared secret of a ciphertext. It has no failure of its own: a wrong ciphertext
/// gives an unrelated secret (implicit rejection), and the AEAD that follows fails. A
/// ciphertext of another length is `kex`; callers check the length on reading.
pub fn mlkem768_decapsulate(dk: &[u8], ct: &[u8]) -> Result<Secret, Error> {
    let dk: [u8; mlkem768::MlKem768PrivateKey::len()] =
        dk.try_into().map_err(|_| Error::InvalidConfig)?;
    let dk = mlkem768::MlKem768PrivateKey::from(dk);
    let ct = mlkem768::MlKem768Ciphertext::try_from(ct).map_err(|_| Error::Kex)?;
    let ss = mlkem768::decapsulate(&dk, &ct);
    wipe(<[u8; mlkem768::MlKem768PrivateKey::len()]>::from(dk));
    let out = Secret::from(&ss[..]);
    wipe(ss);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generated key passes; a coefficient at q in either half of a 3-byte group, or a
    /// wrong length, is `Kex`; the bytes after the coefficients (rho) are not judged.
    #[test]
    fn encapsulation_key_coefficients_below_q() {
        let (_, ek) = mlkem768_generate(&[7; MLKEM768_SEED_LEN]).unwrap();
        assert_eq!(mlkem768_check_ek(&ek), Ok(()));
        let mut low = ek.clone();
        low[0] = 0x01;
        low[1] = (low[1] & 0xf0) | 0x0d;
        assert_eq!(mlkem768_check_ek(&low), Err(Error::Kex));
        let mut high = ek.clone();
        high[1] |= 0xf0;
        high[2] = 0xff;
        assert_eq!(mlkem768_check_ek(&high), Err(Error::Kex));
        assert_eq!(mlkem768_check_ek(&ek[1..]), Err(Error::Kex));
        let mut rho = ek;
        let last = rho.len() - 1;
        rho[last] = 0xff;
        assert_eq!(mlkem768_check_ek(&rho), Ok(()));
    }

    #[test]
    fn x25519_low_order_is_kex() {
        let private = [9u8; 32];
        assert_eq!(x25519(&private, &[0; 32]), Err(Error::Kex));
        let peer = x25519_public(&[5u8; 32]).unwrap();
        assert!(x25519(&private, &peer).is_ok());
    }
}
