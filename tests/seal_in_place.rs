//! The in-place record operations against the allocating AEAD calls they
//! replace: the same records, the same counters and rekeys, the same
//! failures.

use zmux::proto::seal::*;

fn ciphers() -> Vec<&'static Cipher> {
    vec![aes_256_gcm(), chacha20_poly1305()]
}

const KEY: [u8; 32] = [0x5a; 32];

/// The record the allocating path makes at `(key, n)`.
fn reference(c: &Cipher, key: &[u8], n: u64, plain: &[u8]) -> Vec<u8> {
    c.seal(key, n, b"", plain)
}

#[test]
fn in_place_records_match_the_aead_calls() {
    for c in ciphers() {
        let lens = [
            0,
            1,
            15,
            16,
            17,
            1000,
            c.max_plaintext() - 1,
            c.max_plaintext(),
        ];
        // Across a rekey: the counters before and after the interval.
        for start in [0, c.rekey_interval() - 2] {
            let mut sealer = Sealer::at(c, &KEY, start);
            let mut opener = Opener::at(c, &KEY, start);
            let mut appender = Sealer::at(c, &KEY, start);
            // The reference: the allocating AEAD call with the counter and
            // the rekey of the specification, kept here.
            let mut key = KEY.to_vec();
            for (i, &len) in lens.iter().enumerate() {
                let n = start + i as u64;
                if n != 0 && n.is_multiple_of(c.rekey_interval()) {
                    key = c.seal(&key, u64::MAX, b"", &[0; 32])[..32].to_vec();
                }
                let plain: Vec<u8> = (0..len).map(|b| (b * 7 + i) as u8).collect();
                let want = reference(c, &key, n, &plain);
                assert_eq!(c.open(&key, n, b"", &want).unwrap(), plain);
                let mut record = plain.clone();
                record.resize(len + 16, 0);
                sealer.seal_in_place(&mut record).unwrap();
                assert_eq!(record, want, "seal_in_place at n {n}");
                let mut appended = vec![9];
                appender.seal_into(&plain, &mut appended).unwrap();
                assert_eq!(appended[1..], want[..]);
                assert_eq!(opener.open_in_place(&mut record).unwrap(), &plain[..]);
                assert_eq!(sealer.state(), (key.as_slice(), n + 1));
                assert_eq!(opener.state(), sealer.state());
            }
        }
    }
}

#[test]
fn in_place_failures_match() {
    for c in ciphers() {
        // Too large: refused without consuming a nonce.
        let mut s = Sealer::at(c, &KEY, 5);
        let mut big = vec![0; c.max_plaintext() + 1 + 16];
        assert_eq!(s.seal_in_place(&mut big), Err(Error::TooLarge));
        assert_eq!(s.seal_in_place(&mut [0; 15]), Err(Error::TooLarge));
        assert_eq!(s.state().1, 5);
        let mut out = vec![1, 2];
        assert_eq!(s.seal_into(&big[16..], &mut out), Err(Error::TooLarge));
        assert_eq!(out, [1, 2]);
        // A forged record, or one shorter than its tag, ends the direction
        // as the allocating open does.
        let mut record = s.seal(b"data").unwrap();
        record[0] ^= 1;
        for bad in [record.clone(), vec![0; 15]] {
            let mut o = Opener::at(c, &KEY, 5);
            let mut old = Opener::at(c, &KEY, 5);
            let mut b = bad.clone();
            assert_eq!(o.open_in_place(&mut b), Err(Error::Auth));
            assert_eq!(old.open(&bad), Err(Error::Auth));
            let mut good = Sealer::at(c, &KEY, 5).seal(b"x").unwrap();
            assert!(o.open_in_place(&mut good).is_err(), "the direction ended");
            assert_eq!(o.state(), old.state());
        }
    }
}
