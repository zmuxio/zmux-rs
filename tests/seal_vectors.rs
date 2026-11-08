//! Runs the vectors of the secure carrier specification that belong to the core:
//! Join, Suites, records, `Export`, dispatch, and their shared derivations.
//! `ZMUX_SEAL_VECTORS` overrides the sibling zmux-spec checkout.

use serde_json::Value;
use sha2::{Digest, Sha256};
use zmux::proto::seal::join::*;
use zmux::proto::seal::*;

fn load(name: &str) -> Value {
    let dir = std::env::var("ZMUX_SEAL_VECTORS").unwrap_or_else(|_| {
        format!(
            "{}/testdata/spec/secure-carrier/vectors",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let path = format!("{dir}/{name}.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
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

fn framing_of(v: &Value) -> Framing {
    match v["framing"].as_str().unwrap_or("stream") {
        "stream" => Framing::ByteStream,
        "message" => Framing::Records,
        f => panic!("{f}"),
    }
}

fn set(v: &Value, key: &str) -> Vec<u64> {
    v[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect()
}

/// An endpoint's `{suites, groups}`.
fn crypto(v: &Value, key: &str) -> SessionCrypto {
    SessionCrypto {
        suites: set(&v[key], "suites"),
        groups: set(&v[key], "groups"),
    }
}

/// `session_crypto` of a vector's `crypto_i` and `crypto_r`.
fn session_crypto_of(v: &Value) -> Vec<u8> {
    session_crypto(&crypto(v, "crypto_i"), &crypto(v, "crypto_r")).unwrap()
}

fn suite_of(v: &Value) -> &'static Suite {
    Suite::from_value(v["suite"].as_u64().unwrap()).unwrap()
}

fn config<'a>(
    v: &Value,
    framing: Framing,
    locator: &'a [u8],
    psk: &'a [u8],
    binding: &'a [u8],
) -> Result<JoinConfig<'a>, Error> {
    let mode =
        Mode::from_byte(v["mode"].as_u64().unwrap() as u8).map_err(|_| Error::InvalidConfig)?;
    Ok(JoinConfig {
        suite: suite_of(v),
        group: Group::from_value(v["group"].as_u64().unwrap_or(1)).ok_or(Error::InvalidConfig)?,
        mode,
        // The key phase is bit 7 of the ModeByte.
        phase: (v["mode_byte"].as_u64().unwrap_or(0) >> 7) as u8,
        framing,
        locator,
        psk,
        binding,
    })
}

fn joiner_hello(
    v: &Value,
    framing: Framing,
    payload: Vec<u8>,
) -> Result<(Vec<u8>, HelloSent), Error> {
    let (locator, psk, binding, random) = (
        hx(v, "locator"),
        hx(v, "join_psk"),
        hx(v, "binding"),
        hx(v, "random_i"),
    );
    let attempt = v["attempt"].as_u64().unwrap();
    Joiner::with_random(
        config(v, framing, &locator, &psk, &binding)?,
        attempt,
        &random,
    )?
    .with_kex(&hx(v, "x_i"), &hx(v, "kem_seed"))
    // Some vectors carry an unassigned item a receiver skips.
    .write_hello_with_unknown(&payload, Some(ShareOverride::InPayload))
}

fn acceptor_open(
    v: &Value,
    framing: Framing,
    wire: &[u8],
) -> Result<(Unconfirmed, Payload), Error> {
    let hello = JoinHello::parse(framing, wire)?;
    let (mut psk, binding) = (hx(v, "join_psk"), hx(v, "binding"));
    // A key phase the acceptor has no epoch for opens under another key.
    if let Some(phases) = v.get("accepted_phases").and_then(Value::as_array)
        && !phases
            .iter()
            .any(|p| p.as_u64() == Some(u64::from(hello.phase())))
    {
        psk = Sha256::digest(b"zmux-seal vectors acceptor key of no epoch").to_vec();
    }
    Acceptor::open(
        &hello,
        AcceptorKeys {
            psk: &psk,
            binding: &binding,
            groups: &usable_groups(v),
        },
    )
    .map(|(u, p)| (u.with_kex(&hx(v, "x_r"), &hx(v, "encaps_m")), p))
}

/// The usable Groups of a vector: the intersection of `crypto_i` and `crypto_r`.
fn usable_groups(v: &Value) -> Vec<u64> {
    if v.get("crypto_i").is_none() {
        return vec![1, 2];
    }
    SessionCrypto::usable(&crypto(v, "crypto_i").groups, &crypto(v, "crypto_r").groups)
}

fn check_schedule(v: &Value, s: &Schedule) {
    let name = v["name"].as_str().unwrap();
    let ss: Vec<String> =
        s.ss.iter()
            .map(|x| x.iter().map(|b| format!("{b:02x}")).collect())
            .collect();
    let want: Vec<String> = v["ss"]
        .as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
        .unwrap_or_default();
    assert_eq!(ss, want, "{name}: ss");
    let pairs: [(&str, &[u8]); 11] = [
        ("th", &s.th),
        ("th2", &s.th2),
        ("th3", &s.th3),
        ("k0", &s.k0),
        ("k1", &s.k1),
        ("hs", &s.hs),
        ("key_i2r", &s.key_i2r),
        ("key_r2i", &s.key_r2i),
        ("mac_key", &s.mac_key),
        ("exporter_secret", &s.exporter_secret),
        ("confirm_tag", &s.confirm_tag),
    ];
    for (key, got) in pairs {
        assert_eq!(got, hx(v, key), "{name}: {key}");
    }
}

fn check_export(v: &Value, f: &Finished) {
    let x = &v["export"];
    let label = x["label"].as_str().unwrap().as_bytes();
    let out = f
        .export(
            label,
            &hx(x, "context"),
            x["length"].as_u64().unwrap() as usize,
        )
        .unwrap();
    assert_eq!(out, hx(x, "output"), "{}: export", v["name"]);
}

fn run_join(v: &Value, framing: Framing) {
    let name = v["name"].as_str().unwrap();
    let suffix = if framing == Framing::ByteStream {
        "stream"
    } else {
        "message"
    };
    let (want_hello, want_reply, want_confirm) = (
        hx(v, &format!("hello_{suffix}")),
        hx(v, &format!("reply_{suffix}")),
        hx(v, &format!("confirm_{suffix}")),
    );

    // Joiner: every AEAD output is byte-compared.
    let (hello, sent) = joiner_hello(v, framing, hx(v, "hello_payload")).unwrap();
    assert_eq!(hello, want_hello, "{name}: hello");
    let (proven, used) = sent.read_reply(&want_reply).unwrap();
    assert_eq!(used, want_reply.len(), "{name}");
    assert_eq!(
        proven.payload().as_bytes(),
        hx(v, "reply_payload"),
        "{name}"
    );
    let (confirm, joined) = proven
        .write_confirm(v["confirm_padding"].as_u64().unwrap_or(0) as usize)
        .unwrap();
    assert_eq!(confirm, want_confirm, "{name}: confirm");
    check_schedule(v, &joined.schedule());
    check_export(v, &joined);

    // Acceptor.
    let (unconfirmed, payload) = acceptor_open(v, framing, &want_hello).unwrap();
    assert_eq!(payload.as_bytes(), hx(v, "hello_payload"), "{name}");
    let (reply, wait) = unconfirmed
        .write_reply_with_random(
            &hx(v, "reply_payload"),
            v["attempt_r"].as_u64().unwrap(),
            &hx(v, "random_r"),
            Some(ShareOverride::InPayload),
        )
        .unwrap();
    assert_eq!(reply, want_reply, "{name}: reply");
    let (accepted, used) = wait.read_confirm(&want_confirm).unwrap();
    assert_eq!(used, want_confirm.len(), "{name}");
    check_schedule(v, &accepted.schedule());
    check_export(v, &accepted);

    match (joined.into_records(), accepted.into_records()) {
        (Some((mut js, mut jo)), Some((mut acc, mut ao))) => {
            assert_eq!(ao.open(&js.seal(b"up").unwrap()).unwrap(), b"up", "{name}");
            assert_eq!(
                jo.open(&acc.seal(b"down").unwrap()).unwrap(),
                b"down",
                "{name}"
            );
        }
        (None, None) => assert_ne!(v["mode"], 0, "{name}"),
        _ => panic!("{name}: ends disagree about records"),
    }
}

#[test]
fn join() {
    let all = load("join");
    let all = all.as_array().unwrap();
    for v in all {
        let name = v["name"].as_str().unwrap();
        let suite = suite_of(v);
        let role = if v["role"] == "i" {
            JoinRole::Initiator
        } else {
            JoinRole::Responder
        };
        let psk =
            derive_join_psk(suite, &hx(v, "epoch_secret"), role, &session_crypto_of(v)).unwrap();
        assert_eq!(psk, hx(v, "join_psk"), "{name}: psk");
        let hello = hx(v, "hello_message");
        let head = 4 + hx(v, "locator").len();
        assert_eq!(hello[head..head + 32], hx(v, "r_i"), "{name}: r_i");
        assert_eq!(hx(v, "reply_message")[1..33], hx(v, "r_r"), "{name}: r_r");
        run_join(v, Framing::ByteStream);
        run_join(v, Framing::Records);
    }
    println!("join: {} vectors", all.len());
}

enum End {
    J0,
    J1(HelloSent),
    A0,
    A1(Unconfirmed),
    A2(AwaitConfirm),
    Done,
}

fn padded(step: &Value, payload: Vec<u8>) -> Vec<u8> {
    match step.get("padding").and_then(Value::as_u64) {
        Some(n) => [encode_payload(&[(0, &vec![0; n as usize])]), payload].concat(),
        None => payload,
    }
}

fn steps(v: &Value) -> Result<(), Error> {
    let framing = framing_of(v);
    let mut end = if v["side"] == "joiner" {
        End::J0
    } else {
        End::A0
    };
    for step in v["steps"].as_array().unwrap() {
        let wire = hx(step, "wire");
        end = match (step["op"].as_str().unwrap(), end) {
            ("write_hello", End::J0) => {
                End::J1(joiner_hello(v, framing, padded(step, hx(v, "hello_payload")))?.1)
            }
            ("hello", End::A0) => End::A1(acceptor_open(v, framing, &wire)?.0),
            ("write_reply", End::A1(u)) => End::A2(
                u.write_reply_with_random(
                    &padded(step, hx(v, "reply_payload")),
                    v["attempt_r"].as_u64().unwrap(),
                    &hx(v, "random_r"),
                    Some(ShareOverride::InPayload),
                )?
                .1,
            ),
            ("reply", End::J1(s)) => {
                s.read_reply(&wire)?;
                End::Done
            }
            ("confirm", End::A2(w)) => {
                w.read_confirm(&wire)?;
                End::Done
            }
            (op, _) => panic!("{}: op {op} in the wrong state", v["name"]),
        };
    }
    Ok(())
}

#[test]
fn join_negative() {
    let all = load("join_negative");
    let all = all.as_array().unwrap();
    let mut failures = Vec::new();
    for v in all {
        let want = v["error"].as_str().unwrap();
        let got = steps(v);
        let got = got.as_ref().map_err(|e| e.class());
        if got != Err(want) {
            failures.push(format!("{}: want {want}, got {got:?}", v["name"]));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {}:\n{}",
        failures.len(),
        all.len(),
        failures.join("\n")
    );
    println!("join_negative: {} vectors", all.len());
}

#[test]
fn receiver_join() {
    let all = load("receiver");
    let all = all["join"].as_array().unwrap();
    for v in all {
        steps(v).unwrap_or_else(|e| panic!("{}: {e}", v["name"]));
    }
    println!("receiver join: {} vectors", all.len());
}

#[test]
fn config_join() {
    let all = load("config");
    let mut count = 0;
    for v in all
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["kind"] == "join")
    {
        let (locator, psk, binding) = (hx(v, "handle"), hx(v, "psk"), hx(v, "binding"));
        let got = config(v, Framing::ByteStream, &locator, &psk, &binding).and_then(Joiner::new);
        assert_eq!(
            got.err().map(Error::class),
            v["error"].as_str(),
            "{}",
            v["name"]
        );
        count += 1;
    }
    println!("config join: {count} vectors");
}

#[test]
fn config_session_crypto() {
    let all = load("config");
    let mut count = 0;
    for v in all
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["kind"] == "session_crypto")
    {
        let got = session_crypto(&crypto(v, "crypto"), &SessionCrypto::local());
        assert_eq!(
            got.err().map(Error::class),
            v["error"].as_str(),
            "{}",
            v["name"]
        );
        count += 1;
    }
    println!("config session_crypto: {count} vectors");
}

#[test]
fn hello_core() {
    let all = load("hello");
    let mut count = 0;
    for v in all.as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let framing = framing_of(v);
        let mut input = hx(v, "header");
        input.resize(input.len() + v["fill"].as_u64().unwrap() as usize, 0x5a);
        let got = match v["kind"].as_str().unwrap() {
            "join" => JoinHello::parse(framing, &input).map(|h| h.consumed()),
            "reply" => parse_reply(Suite::from_value(1).unwrap(), framing, &input).map(|r| r.2),
            "frame" => cut_unit(framing, &input).map(|c| c.1),
            _ => continue,
        };
        match got {
            Ok(consumed) => assert_eq!(consumed as u64, v["consumed"].as_u64().unwrap(), "{name}"),
            Err(e) => {
                assert_eq!(e.class(), v["error"].as_str().unwrap(), "{name}");
                if let Error::Incomplete { need } = e {
                    assert_eq!(need as u64, v["need"].as_u64().unwrap(), "{name}");
                }
            }
        }
        count += 1;
    }
    println!("hello core: {count} vectors");
}

#[test]
fn record() {
    let all = load("record");
    let all = all.as_array().unwrap();
    for v in all {
        let name = format!(
            "{}/{}",
            v["cipher"].as_str().unwrap(),
            v["name"].as_str().unwrap()
        );
        let cipher = match v["cipher"].as_str().unwrap() {
            "ChaChaPoly" => chacha20_poly1305(),
            "AESGCM" => aes_256_gcm(),
            c => panic!("{c}"),
        };
        let key = hx(v, "key");
        let n = v["n"].as_u64().unwrap();
        let plain = if let Some(fill) = v.get("plaintext_fill") {
            Some(vec![
                fill["byte"].as_u64().unwrap() as u8;
                fill["length"].as_u64().unwrap() as usize
            ])
        } else {
            v.get("plaintext").map(|p| unhex(p.as_str().unwrap()))
        };
        let ciphertext = v.get("ciphertext").map(|c| unhex(c.as_str().unwrap()));
        if let Some(want) = v.get("error").and_then(Value::as_str) {
            if let Some(ct) = &ciphertext {
                let mut o = Opener::at(cipher, &key, n);
                assert_eq!(o.open(ct).unwrap_err().class(), want, "{name}");
                assert!(o.open(ct).is_err(), "{name}: failure must be permanent");
            } else {
                let mut s = Sealer::at(cipher, &key, n);
                assert_eq!(
                    s.seal(plain.as_ref().unwrap()).unwrap_err().class(),
                    want,
                    "{name}"
                );
                assert_eq!(s.state().1, n, "{name}: no nonce consumed");
            }
            continue;
        }
        let plain = plain.unwrap_or_default();
        let (key_after, n_after) = (hx(v, "key_after"), v["n_after"].as_u64().unwrap());
        let mut s = Sealer::at(cipher, &key, n);
        let out = s.seal(&plain).unwrap();
        match &ciphertext {
            Some(ct) => assert_eq!(&out, ct, "{name}: seal"),
            None => assert_eq!(
                Sha256::digest(&out).as_slice(),
                hx(v, "ciphertext_sha256"),
                "{name}: seal"
            ),
        }
        assert_eq!(s.state(), (&key_after[..], n_after), "{name}: seal state");
        let mut o = Opener::at(cipher, &key, n);
        assert_eq!(o.open(&out).unwrap(), plain, "{name}: open");
        assert_eq!(o.state(), (&key_after[..], n_after), "{name}: open state");
    }
    println!("record: {} vectors", all.len());
}

#[test]
fn exporter() {
    let all = load("exporter");
    let all = all.as_array().unwrap();
    for v in all {
        let name = v["name"].as_str().unwrap();
        let mut label = v["label"].as_str().unwrap().as_bytes().to_vec();
        if let Some(n) = v.get("label_fill").and_then(Value::as_u64) {
            label = vec![b'l'; n as usize];
        }
        let mut context = hx(v, "context");
        if let Some(n) = v.get("context_fill").and_then(Value::as_u64) {
            context = vec![0; n as usize];
        }
        let got = export(
            &SHA256,
            &hx(v, "exporter_secret"),
            &label,
            &context,
            v["length"].as_u64().unwrap() as usize,
        );
        if let Some(e) = v.get("error") {
            assert_eq!(got.unwrap_err().class(), e.as_str().unwrap(), "{name}");
        } else if v.get("output_sha256").is_some() {
            assert_eq!(
                Sha256::digest(got.unwrap()).as_slice(),
                hx(v, "output_sha256"),
                "{name}"
            );
        } else {
            assert_eq!(got.unwrap(), hx(v, "output"), "{name}");
        }
    }
    println!("exporter: {} vectors", all.len());
}

#[test]
fn derive_core() {
    let v = load("derive");
    let mut count = 0;
    for j in v["join_psk"].as_array().unwrap() {
        let name = j["name"].as_str().unwrap_or("join_psk");
        let sc = session_crypto_of(j);
        let suite = j["suite"].as_u64().unwrap();
        let len = j["hash_len"].as_u64().unwrap() as usize;
        for (role, key) in [
            (JoinRole::Initiator, "join_psk_i"),
            (JoinRole::Responder, "join_psk_r"),
        ] {
            let got = expand_join_psk(suite, &hx(j, "epoch_secret"), role, &sc, len).unwrap();
            assert_eq!(got, hx(j, key), "{name}: {key}");
        }
        count += 1;
    }
    for c in v["session_crypto"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let got = if c.get("crypto_i").is_some() {
            session_crypto(&crypto(c, "crypto_i"), &crypto(c, "crypto_r"))
        } else {
            SessionCrypto::parse(&hx(c, "value")).map(|p| p.encode())
        };
        match c.get("error") {
            Some(e) => assert_eq!(
                got.map_err(|_| "invalid_config").unwrap_err(),
                e.as_str().unwrap(),
                "{name}"
            ),
            None => assert_eq!(got.unwrap(), hx(c, "encoding"), "{name}"),
        }
        count += 1;
    }
    for c in v["combine"].as_array().into_iter().flatten() {
        let ss: Vec<Vec<u8>> = c["ss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| unhex(x.as_str().unwrap()))
            .collect();
        let out = combine(&SHA256, &hx(c, "salt"), &ss);
        assert_eq!(&*out, hx(c, "output"), "{}", c["name"]);
        count += 1;
    }
    for b in v["bound_exporter"].as_array().unwrap() {
        let half = |key| Some(hx(b, key)).filter(|h| !h.is_empty());
        let (up, down) = (half("up"), half("down"));
        let got = bound_exporter(up.as_deref(), down.as_deref());
        match b.get("error") {
            Some(e) => assert_eq!(
                got.unwrap_err().class(),
                e.as_str().unwrap(),
                "{}",
                b["name"]
            ),
            None => assert_eq!(got.unwrap(), hx(b, "output"), "{}", b["name"]),
        }
        count += 1;
    }
    // From an Establish's exporter secret through the session secret to the Join keys.
    for x in v["session"].as_array().unwrap() {
        let exported = export(
            &SHA256,
            &hx(x, "exporter_secret"),
            zmux::proto::keys::EXPORTER_SESSION_LABEL.as_bytes(),
            b"",
            32,
        )
        .unwrap();
        assert_eq!(exported, hx(x, "session_export"));
        let nonce = |key| <[u8; 16]>::try_from(hx(x, key)).unwrap();
        let secret = zmux::proto::keys::session_secret(
            &nonce("init_nonce"),
            &nonce("resp_nonce"),
            &exported,
            &[],
        );
        assert_eq!(secret.to_vec(), hx(x, "session_secret"));
        for j in x["join_psk"].as_array().unwrap() {
            let sc = session_crypto_of(j);
            for (role, key) in [
                (JoinRole::Initiator, "join_psk_i"),
                (JoinRole::Responder, "join_psk_r"),
            ] {
                let got = derive_join_psk(suite_of(j), &secret, role, &sc).unwrap();
                assert_eq!(got, hx(j, key));
            }
        }
        count += 1;
    }
    println!("derive core: {count} vectors");
}

#[test]
fn dispatch_vectors() {
    let all = load("dispatch");
    let all = all.as_array().unwrap();
    for v in all {
        let got = dispatch(framing_of(v), &hx(v, "bytes"));
        let (class, need) = match got {
            Dispatch::Establish => ("establish", None),
            Dispatch::Join => ("join", None),
            Dispatch::Reserved => ("reserved", None),
            Dispatch::Record => ("record", None),
            Dispatch::Other => ("other", None),
            Dispatch::Incomplete { need } => ("incomplete", Some(need as u64)),
        };
        assert_eq!(class, v["class"].as_str().unwrap(), "{v}");
        assert_eq!(need, v.get("need").and_then(Value::as_u64), "{v}");
    }
    println!("dispatch: {} vectors", all.len());
}
