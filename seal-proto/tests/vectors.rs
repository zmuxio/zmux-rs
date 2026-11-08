//! Runs the Establish vectors of the secure carrier specification; the core's
//! are in the root crate's `tests/seal_vectors.rs`.
//! `ZMUX_SEAL_VECTORS` overrides the sibling zmux-spec checkout.

use serde_json::Value;
use zmux_seal_proto::*;

fn load(name: &str) -> Value {
    let dir = std::env::var("ZMUX_SEAL_VECTORS").unwrap_or_else(|_| {
        format!(
            "{}/../testdata/spec/secure-carrier/vectors",
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

/// A missing field is empty: vectors omit what a case does not have.
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

fn mode_of(v: &Value) -> Result<Mode, Error> {
    Mode::from_byte(v["mode"].as_u64().unwrap() as u8).map_err(|_| Error::InvalidConfig)
}

fn profile_of(v: &Value) -> Profile {
    Profile::from_value(v["profile"].as_u64().unwrap()).unwrap()
}

fn initiator(v: &Value, framing: Framing) -> Result<Initiator, Error> {
    let (handle, psk, s, binding, e, kem) = (
        hx(v, "handle"),
        hx(v, "psk"),
        hx(v, "initiator_static"),
        hx(v, "binding"),
        hx(v, "initiator_ephemeral"),
        hx(v, "initiator_kem_seed"),
    );
    Initiator::with_ephemeral(
        InitiatorConfig {
            profile: profile_of(v),
            mode: mode_of(v)?,
            framing,
            handle: &handle,
            psk: &psk,
            static_secret: &s,
            binding: &binding,
            max_app_data: max_app_data(v),
        },
        &e,
        &kem,
    )
}

fn responder(v: &Value, framing: Framing, wire: &[u8]) -> Result<(ResponderReply, Payload), Error> {
    let hello = Hello::parse(framing, wire)?;
    let psk = if hello.profile().psk_len().is_some() {
        hx(v, "psk")
    } else {
        Vec::new()
    };
    let (s, binding, e, kem) = (
        hx(v, "responder_static"),
        hx(v, "binding"),
        hx(v, "responder_ephemeral"),
        hx(v, "responder_encaps_m"),
    );
    let keys = ResponderKeys {
        psk: &psk,
        static_secret: &s,
        binding: &binding,
        max_app_data: max_app_data(v),
    };
    Responder::read_hello_with_ephemeral(&hello, keys, &e, &kem)
}

/// The receivers' local bound of a vector; absent: the default.
fn max_app_data(v: &Value) -> usize {
    v["max_app_data"].as_u64().unwrap_or(0) as usize
}

fn cut(framing: Framing, wire: &[u8]) -> Result<&[u8], Error> {
    Ok(zmux::proto::seal::cut_unit(framing, wire)?.0)
}

fn check_step(name: &str, m: &Value, wire: &[u8], framing: Framing, t: (&[u8], &[u8])) {
    let key = if framing == Framing::ByteStream {
        "wire_stream"
    } else {
        "wire_message"
    };
    assert_eq!(wire, hx(m, key), "{name}: {key}");
    assert_eq!(t.0, hx(m, "h"), "{name}: h");
    assert_eq!(t.1, hx(m, "ck"), "{name}: ck");
}

fn check_complete(v: &Value, c: &Complete) {
    let name = v["name"].as_str().unwrap();
    assert_eq!(c.handshake_hash(), hx(v, "handshake_hash"), "{name}: hash");
    assert_eq!(c.transcript().1, hx(v, "chaining_key"), "{name}: ck");
    assert_eq!(c.split().0, hx(v, "split_c1"), "{name}: c1");
    assert_eq!(c.split().1, hx(v, "split_c2"), "{name}: c2");
    assert_eq!(
        c.exporter_secret(),
        hx(v, "exporter_secret"),
        "{name}: exporter secret"
    );
    let x = &v["exporter"];
    let label = x["label"].as_str().unwrap().as_bytes();
    let out = c
        .export(
            label,
            &hx(x, "context"),
            x["length"].as_u64().unwrap() as usize,
        )
        .unwrap();
    assert_eq!(out, hx(x, "output"), "{name}: export");
    assert_eq!(
        v["records_use_split"].as_bool().unwrap(),
        c.mode() == Mode::Sealed,
        "{name}"
    );
}

/// The signing key of a message with a proof.
fn signer(m: &Value) -> Option<SigningKey> {
    m.get("proof_seed")
        .map(|_| SigningKey::from_seed(KEYALG_MLDSA44, &hx(m, "proof_seed")).unwrap())
}

/// Checks M of a signing step and signs it as the vector's signer did.
fn sign(name: &str, m: &Value, k: &SigningKey, message: &[u8]) -> Vec<u8> {
    assert_eq!(message, hx(m, "proof_message"), "{name}: M");
    assert!(message.ends_with(&hx(m, "h_p")), "{name}: h_p");
    let sig = k.sign_deterministic(message).unwrap();
    let proof = Proof {
        key_alg: KEYALG_MLDSA44,
        key: k.public(),
        sig: &sig,
    };
    assert_eq!(proof.encode(), hx(m, "proof"), "{name}: proof");
    sig
}

/// The vector's credential and application data of a message, as read.
fn check_read(name: &str, m: &Value, p: &Payload) {
    let want = m
        .get("credential")
        .map(|c| (c["type"].as_u64().unwrap(), hx(c, "data")));
    let got = p.credential().map(|c| (c.kind, c.credential.to_vec()));
    assert_eq!(got, want, "{name}: credential");
    assert_eq!(
        p.app_data().filter(|d| !d.is_empty()).map(<[u8]>::to_vec),
        m.get("app_data").map(|_| hx(m, "app_data")),
        "{name}: app data"
    );
}

/// An end's verification of the peer, as a verifier and the core run it: a pin, or a
/// verdict naming a proof key or none.
fn check_verify(
    name: &str,
    x: Option<&Value>,
    peer_static: &[u8],
    check: impl Fn(Option<&KeyId>, bool) -> Result<bool, Error>,
) {
    let Some(x) = x else {
        return;
    };
    let mut proof_key = x.get("proof_key").map(|_| hx(x, "proof_key"));
    if x.get("pin_id").is_some() {
        assert_eq!(
            key_id(KEYALG_X25519, peer_static).to_vec(),
            hx(x, "pin_id"),
            "{name}: pin"
        );
        proof_key = x.get("pin_proof_id").map(|_| hx(x, "pin_proof_id"));
    }
    let key = proof_key.map(|k| KeyId::try_from(k).unwrap());
    let require = x["require_pq_auth"].as_bool().unwrap_or(false);
    let pq = check(key.as_ref(), require).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(pq, x["pq_authenticated"].as_bool().unwrap(), "{name}: pq");
}

fn run_handshake(v: &Value, framing: Framing) {
    let name = v["name"].as_str().unwrap();
    let msgs = v["messages"].as_array().unwrap();
    let p = |i: usize| hx(&msgs[i], "payload");
    let key = if framing == Framing::ByteStream {
        "wire_stream"
    } else {
        "wire_message"
    };

    let (hello, await_reply) = initiator(v, framing).unwrap().write_hello(&p(0)).unwrap();
    check_step(name, &msgs[0], &hello, framing, await_reply.transcript());
    let reply_wire = hx(&msgs[1], key);
    let verify = await_reply
        .read_reply(cut(framing, &reply_wire).unwrap())
        .unwrap();
    assert_eq!(
        verify.payload().as_bytes(),
        p(1),
        "{name}: i reads payload 2"
    );
    check_read(name, &msgs[1], verify.payload());
    check_step(name, &msgs[1], &reply_wire, framing, verify.transcript());
    check_verify(
        name,
        v.get("verify_server"),
        verify.peer_static(),
        |k, r| verify.check_proof(k, r),
    );
    let finish = verify.accept();
    let (finish, init_done) = match signer(&msgs[2]) {
        Some(k) => {
            let s = finish.write_finish_signed(&p(2)).unwrap();
            let sig = sign(name, &msgs[2], &k, s.message());
            s.finish(&sig).unwrap()
        }
        None => finish.write_finish(&p(2)).unwrap(),
    };
    check_step(name, &msgs[2], &finish, framing, init_done.transcript());
    check_complete(v, &init_done);

    let (reply, payload) = responder(v, framing, &hx(&msgs[0], key)).unwrap();
    assert_eq!(payload.as_bytes(), p(0), "{name}: r reads payload 1");
    check_read(name, &msgs[0], &payload);
    check_step(
        name,
        &msgs[0],
        &hx(&msgs[0], key),
        framing,
        reply.transcript(),
    );
    let (wire, await_finish) = match signer(&msgs[1]) {
        Some(k) => {
            let s = reply.write_reply_signed(&p(1)).unwrap();
            let sig = sign(name, &msgs[1], &k, s.message());
            s.finish(&sig).unwrap()
        }
        None => reply.write_reply(&p(1)).unwrap(),
    };
    assert_eq!(wire, reply_wire, "{name}: reply");
    check_step(name, &msgs[1], &wire, framing, await_finish.transcript());
    let finish = hx(&msgs[2], key);
    let (resp_done, payload) = await_finish
        .read_finish(cut(framing, &finish).unwrap())
        .unwrap();
    assert_eq!(payload.as_bytes(), p(2), "{name}: r reads payload 3");
    check_read(name, &msgs[2], &payload);
    assert_eq!(resp_done.peer_static().map(<[u8]>::len), Some(32), "{name}");
    check_verify(
        name,
        v.get("verify_client"),
        resp_done.peer_static().unwrap(),
        |k, r| resp_done.check_proof(k, r),
    );
    check_step(name, &msgs[2], &finish, framing, resp_done.transcript());
    check_complete(v, &resp_done);

    match (init_done.into_records(), resp_done.into_records()) {
        (Some((mut is, mut io)), Some((mut rs, mut ro))) => {
            assert_eq!(ro.open(&is.seal(b"up").unwrap()).unwrap(), b"up", "{name}");
            assert_eq!(
                io.open(&rs.seal(b"down").unwrap()).unwrap(),
                b"down",
                "{name}"
            );
        }
        (None, None) => {}
        _ => panic!("{name}: ends disagree about records"),
    }
}

#[test]
fn handshake() {
    run_handshakes(&load("handshake"));
}

fn run_handshakes(all: &Value) {
    let all = all.as_array().unwrap();
    for v in all {
        let name = v["name"].as_str().unwrap();
        let (profile, mode) = (profile_of(v), mode_of(v).unwrap());
        assert_eq!(
            profile.pq_confidentiality(),
            v["pq_confidential"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            profile.noise_name(),
            v["noise_name"].as_str().unwrap(),
            "{name}"
        );
        let got = prologue(profile, mode, &hx(v, "handle"), &hx(v, "binding"));
        assert_eq!(got, hx(v, "prologue"), "{name}: prologue");
        run_handshake(v, Framing::ByteStream);
        run_handshake(v, Framing::Records);
    }
    println!("handshake: {} vectors", all.len());
}

enum End {
    I0(Initiator),
    I1(AwaitReply),
    I2(Verify),
    I3(Finish),
    R0,
    R1(ResponderReply),
    R2(AwaitFinish),
    Done,
}

/// The payload of a write step: a padding item and application data of zero bytes, each
/// when the step asks for it.
fn written(step: &Value) -> Vec<u8> {
    let pad = step
        .get("padding")
        .and_then(Value::as_u64)
        .map(|n| vec![0; n as usize]);
    let data = step
        .get("app_data_len")
        .and_then(Value::as_u64)
        .map(|n| vec![0; n as usize]);
    let mut items: Vec<(u64, &[u8])> = Vec::new();
    if let Some(p) = &pad {
        items.push((0, p));
    }
    if let Some(d) = &data {
        items.push((2, d));
    }
    encode_payload(&items)
}

/// The verdict of a verify step: its proof key, none when absent.
fn verdict(step: &Value) -> (Option<KeyId>, bool) {
    let key = step
        .get("proof_key")
        .map(|_| KeyId::try_from(hx(step, "proof_key")).unwrap());
    (key, step["require_pq_auth"].as_bool().unwrap_or(false))
}

fn steps(v: &Value) -> Result<(), Error> {
    let framing = framing_of(v);
    let mut end = if v["side"] == "initiator" {
        End::I0(initiator(v, framing)?)
    } else {
        End::R0
    };
    for step in v["steps"].as_array().unwrap() {
        let wire = hx(step, "wire");
        end = match (step["op"].as_str().unwrap(), end) {
            ("hello", End::R0) => End::R1(responder(v, framing, &wire)?.0),
            ("write", End::I0(i)) => End::I1(i.write_hello(&written(step))?.1),
            ("write", End::R1(r)) => End::R2(r.write_reply(&written(step))?.1),
            ("read", End::I1(i)) => End::I2(i.read_reply(cut(framing, &wire)?)?),
            ("verify", End::I2(i)) => {
                let (key, require) = verdict(step);
                i.check_proof(key.as_ref(), require)?;
                End::I2(i)
            }
            ("write", End::I2(i)) => {
                i.accept().write_finish(&written(step))?;
                End::Done
            }
            ("write", End::I3(f)) => {
                f.write_finish(&written(step))?;
                End::Done
            }
            ("force_n", End::I2(i)) => {
                let mut f = i.accept();
                f.force_n();
                End::I3(f)
            }
            ("force_n", End::R2(mut r)) => {
                r.force_n();
                End::R2(r)
            }
            ("read", End::R2(r)) => {
                r.read_finish(cut(framing, &wire)?)?;
                End::Done
            }
            (op, _) => panic!("{}: op {op} in the wrong state", v["name"]),
        };
    }
    Ok(())
}

#[test]
fn negative() {
    run_negatives(&load("negative"));
}

fn run_negatives(all: &Value) {
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
    println!("negative: {} vectors", all.len());
}

#[test]
fn receiver_establish() {
    let all = load("receiver");
    let all = all["establish"].as_array().unwrap();
    for v in all {
        steps(v).unwrap_or_else(|e| panic!("{}: {e}", v["name"]));
    }
    println!("receiver establish: {} vectors", all.len());
}

/// An initiator of a config vector and its first message, with the type it puts there.
fn config_start(v: &Value) -> Result<(), Error> {
    let (handle, psk, s, binding) = (
        hx(v, "handle"),
        hx(v, "psk"),
        hx(v, "static"),
        hx(v, "binding"),
    );
    let i = Initiator::new(InitiatorConfig {
        profile: profile_of(v),
        mode: mode_of(v)?,
        framing: Framing::ByteStream,
        handle: &handle,
        psk: &psk,
        static_secret: &s,
        binding: &binding,
        max_app_data: 0,
    })?;
    let data = vec![0; v["app_data_len"].as_u64().unwrap_or(0) as usize];
    let value: Vec<u8> = match v["write_type"].as_u64() {
        Some(1) if v["cred_type_0"] == true => vec![0],
        Some(1) => vec![1],
        // A proof of KeyAlg 3, all its lengths empty.
        Some(8) => vec![3, 0],
        Some(_) => vec![0],
        None => Vec::new(),
    };
    let mut items: Vec<(u64, &[u8])> = Vec::new();
    if !data.is_empty() {
        items.push((2, &data));
    }
    if let Some(t) = v["write_type"].as_u64() {
        items.push((t, &value));
    }
    i.write_hello(&encode_payload(&items)).map(|_| ())
}

#[test]
fn config_establish() {
    let all = load("config");
    let mut count = 0;
    for v in all.as_array().unwrap().iter() {
        let got = match v["kind"].as_str().unwrap() {
            "establish" => config_start(v),
            // A pin that names no proof key.
            "pin" => check_pin_pq_auth(v["require_pq_auth"].as_bool().unwrap(), false),
            _ => continue,
        };
        assert_eq!(
            got.err().map(Error::class),
            v["error"].as_str(),
            "{}",
            v["name"]
        );
        count += 1;
    }
    println!("config establish: {count} vectors");
}

#[test]
fn hello_establish() {
    let all = load("hello");
    let mut count = 0;
    for v in all
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["kind"] == "establish")
    {
        let name = v["name"].as_str().unwrap();
        let mut input = hx(v, "header");
        input.resize(input.len() + v["fill"].as_u64().unwrap() as usize, 0x5a);
        match Hello::parse(framing_of(v), &input) {
            Ok(h) => assert_eq!(
                h.consumed() as u64,
                v["consumed"].as_u64().unwrap(),
                "{name}"
            ),
            Err(e) => {
                assert_eq!(e.class(), v["error"].as_str().unwrap(), "{name}");
                if let Error::Incomplete { need } = e {
                    assert_eq!(need as u64, v["need"].as_u64().unwrap(), "{name}");
                }
            }
        }
        count += 1;
    }
    println!("hello establish: {count} vectors");
}

#[test]
fn derive_establish() {
    let v = load("derive");
    let x = &v["exporter_secret"];
    let profile = Profile::from_value(1).unwrap();
    assert_eq!(
        exporter_secret(profile, &hx(x, "ck"), &hx(x, "h")).unwrap(),
        hx(x, "exporter_secret")
    );
    let mut count = 1;
    for h in v["handle_psk"].as_array().unwrap() {
        let got = derive_handle_psk(&hx(h, "secret"), &hx(h, "domain"), &hx(h, "salt"));
        match h.get("error") {
            Some(e) => assert_eq!(
                got.unwrap_err().class(),
                e.as_str().unwrap(),
                "{}",
                h["name"]
            ),
            None => {
                let got = got.unwrap();
                assert_eq!(got.handle, hx(h, "handle"), "{}", h["name"]);
                assert_eq!(got.psk, hx(h, "psk"), "{}", h["name"]);
            }
        }
        count += 1;
    }
    println!("derive establish: {count} vectors");
}
