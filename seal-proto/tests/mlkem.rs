//! ML-KEM-768 vectors of Wycheproof and C2SP CCTV, run through the entry points the
//! hybrid Profiles use: key generation from a seed, encapsulation behind the received
//! key's check, decapsulation with implicit rejection.
//!
//! `tests/data/mlkem768` holds a subset: of each kind of Wycheproof case a few, every
//! CCTV modulus case of the encapsulation file, every 13th key of CCTV `modulus`, and
//! the CCTV `unluckysample` and `strcmp` files whole. `ZMUX_MLKEM_VECTORS` names a
//! directory with the full files of the same names to run instead. Cases on the
//! lengths of a decapsulation key or ciphertext are left out: the handshake fixes
//! both before they reach the KEM.

use serde_json::Value;
use zmux::proto::seal::Error;
use zmux::proto::seal::kex;

fn generate(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = kex::mlkem768_generate(seed).unwrap();
    (dk.to_vec(), ek)
}

fn encapsulate(ek: &[u8], m: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (ct, ss) = kex::mlkem768_encapsulate(ek, m)?;
    Ok((ct, ss.to_vec()))
}

fn decapsulate(dk: &[u8], ct: &[u8]) -> Vec<u8> {
    kex::mlkem768_decapsulate(dk, ct).unwrap().to_vec()
}

fn dir() -> String {
    std::env::var("ZMUX_MLKEM_VECTORS")
        .unwrap_or_else(|_| format!("{}/tests/data/mlkem768", env!("CARGO_MANIFEST_DIR")))
}

fn read(name: &str) -> String {
    let path = format!("{}/{name}", dir());
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    v.get(key)
        .and_then(Value::as_str)
        .map(unhex)
        .unwrap_or_default()
}

/// Every test of a Wycheproof file, with its group's source for messages.
fn wycheproof(name: &str) -> Vec<(String, Value)> {
    let v: Value = serde_json::from_str(&read(name)).unwrap();
    let mut out = Vec::new();
    for g in v["testGroups"].as_array().unwrap() {
        assert_eq!(g["parameterSet"], "ML-KEM-768", "{name}");
        let source = g["source"]["name"].as_str().unwrap_or("").to_string();
        for t in g["tests"].as_array().unwrap() {
            out.push((format!("{name} {source} #{}", t["tcId"]), t.clone()));
        }
    }
    assert!(!out.is_empty(), "{name}: no tests");
    out
}

/// The `key = hex` lines of a CCTV file.
fn cctv(name: &str) -> Vec<(String, Vec<u8>)> {
    read(name)
        .lines()
        .filter_map(|l| l.split_once(" = "))
        .map(|(k, v)| (k.trim().to_string(), unhex(v.trim())))
        .collect()
}

fn field<'a>(f: &'a [(String, Vec<u8>)], key: &str) -> &'a [u8] {
    &f.iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("no {key}"))
        .1
}

#[test]
fn wycheproof_keygen_from_seed() {
    let all = wycheproof("mlkem_768_keygen_seed_test.json");
    for (name, t) in &all {
        let (dk, ek) = generate(&hx(t, "seed"));
        assert_eq!(ek, hx(t, "ek"), "{name}: ek");
        assert_eq!(dk, hx(t, "dk"), "{name}: dk");
    }
    println!("keygen: {} vectors", all.len());
}

#[test]
fn wycheproof_encapsulation_checks_the_key() {
    let all = wycheproof("mlkem_768_encaps_test.json");
    let mut refused = 0;
    for (name, t) in &all {
        let got = encapsulate(&hx(t, "ek"), &hx(t, "m"));
        if t["result"] == "valid" {
            let (ct, ss) = got.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(ct, hx(t, "c"), "{name}: c");
            assert_eq!(ss, hx(t, "K"), "{name}: K");
        } else {
            assert_eq!(got.unwrap_err().class(), "kex", "{name}");
            refused += 1;
        }
    }
    println!("encaps: {} vectors, {refused} refused", all.len());
}

#[test]
fn wycheproof_decapsulation() {
    let all = wycheproof("mlkem_768_test.json");
    let mut count = 0;
    for (name, t) in &all {
        let (seed, ct) = (hx(t, "seed"), hx(t, "c"));
        let invalid = t["result"] != "valid";
        // Lengths are the handshake's: any such case left in a full file is skipped.
        if invalid || ct.len() != 1088 || seed.len() != 64 {
            assert!(invalid, "{name}: a valid case of another length");
            continue;
        }
        let (dk, ek) = generate(&seed);
        if t.get("ek").is_some() {
            assert_eq!(ek, hx(t, "ek"), "{name}: ek");
        }
        assert_eq!(decapsulate(&dk, &ct), hx(t, "K"), "{name}: K");
        count += 1;
    }
    println!("decaps: {count} of {} vectors", all.len());
}

#[test]
fn cctv_modulus_keys_are_refused() {
    let text = read("modulus768.txt");
    let mut count = 0;
    for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let ek = unhex(line.trim());
        assert_eq!(ek.len(), 1184, "line {i}");
        let got = encapsulate(&ek, &[0; 32]);
        assert_eq!(got.unwrap_err().class(), "kex", "line {i}");
        count += 1;
    }
    println!("modulus: {count} keys");
}

/// A key whose matrix needs more than the usual SHAKE-128 output in SampleNTT. Its
/// `ek` and `dk` came from `(d, z)` by the draft of FIPS 203, whose `G(d)` has no
/// domain separator byte: the final standard derives another key from them, so key
/// generation is not checked here. Encapsulation to `ek` with `m` and decapsulation
/// with `dk` both expand the unlucky matrix.
#[test]
fn cctv_unlucky_sample() {
    let f = cctv("unlucky768.txt");
    let (ek, dk) = (field(&f, "ek"), field(&f, "dk"));
    // The draft's key is still a valid FIPS 203 key pair: dk embeds ek and z.
    assert_eq!(&dk[1152..2336], ek, "ek in dk");
    assert_eq!(&dk[2368..], field(&f, "z"), "z in dk");
    let (ct, ss) = encapsulate(ek, field(&f, "m")).unwrap();
    assert_eq!(ct, field(&f, "c"), "c");
    assert_eq!(ss, field(&f, "K"), "K");
    assert_eq!(decapsulate(dk, &ct), field(&f, "K"), "decaps");
}

/// Implicit rejection whose comparison would pass a `strcmp` stopping at a zero byte.
#[test]
fn cctv_strcmp() {
    let f = cctv("strcmp768.txt");
    assert_eq!(decapsulate(field(&f, "dk"), field(&f, "c")), field(&f, "K"));
}

/// CCTV `accumulated`: SHAKE-128 of the empty string gives, per iteration, a seed
/// `d || z`, a message `m` and a random ciphertext; SHAKE-128 over `ek`, `c`, `K` and
/// the implicit rejection of the random ciphertext, in that order for each
/// iteration, is the result. The decapsulation key is not part of it. The value
/// for 10 000 iterations is CCTV's, as Go's `crypto/mlkem` tests check it.
#[test]
fn cctv_accumulated() {
    const N: usize = 10_000;
    const WANT: &str = "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc";
    let per = 64 + 32 + 1088;
    let mut random = vec![0; N * per];
    libcrux_sha3::portable::shake128(&mut random, b"");
    let mut acc = Vec::with_capacity(N * (1184 + 1088 + 32 + 32));
    for chunk in random.chunks(per) {
        let (seed, rest) = chunk.split_at(64);
        let (m, bad) = rest.split_at(32);
        let (dk, ek) = generate(seed);
        let (ct, ss) = encapsulate(&ek, m).unwrap();
        assert_eq!(decapsulate(&dk, &ct), ss);
        let rejected = decapsulate(&dk, bad);
        for part in [&ek[..], &ct, &ss, &rejected] {
            acc.extend_from_slice(part);
        }
    }
    let mut out = [0; 32];
    libcrux_sha3::portable::shake128(&mut out, &acc);
    let got: String = out.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, WANT);
}
