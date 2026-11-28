//! Attacks on Join: a third party that terminates a carrier,
//! reads a Hello and answers whatever it likes; a downgrade of the Secret Flags; a replayed
//! Hello on another path.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test values are small and bounded; checked conversions would only add noise"
)]

#[path = "common/core_pair.rs"]
mod core_pair;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;
use zmux::adapter::CarrierExporter;
use zmux::proto::record::Framing;
use zmux::proto::seal::RecordMode;
use zmux::proto::seal::join::JoinHello;
use zmux::proto::session::{
    AllowRecordMode, ClaimedHello, Config, CoreEvent, OpenedHello, PeerCarrier, PipeId,
    SessionCore, State,
};
use zmux::shaping::UnitPlan;
use zmux::{
    Listener, ListenerConfig, OnReject, PipeAuth, PipeIo, PipeOptions, RejectAction, Session,
};

fn config() -> Config {
    let mut c =
        Config::multipath(PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end());
    c.allow_record_mode = Some(AllowRecordMode::new(|_, _, _| true));
    c
}

async fn sessions() -> (Session, Session, Listener) {
    let (a, b) = duplex(1 << 20);
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
            .await
    });
    let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
    let server = listener.accept().await.unwrap();
    client.established().await.unwrap();
    (client, server, listener)
}

fn framed(frame: &[u8]) -> Vec<u8> {
    let mut out = [frame.len() as u8].to_vec();
    assert!(frame.len() < 64);
    out.extend_from_slice(frame);
    out
}

/// A1 to A5: whatever a third party answers one Hello with, nothing of it reaches the
/// session and only the attachment can fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_third_party_reads_one_hello_and_nothing_else() {
    let mut fake_reply = vec![3u8];
    fake_reply.extend_from_slice(&[0; 32]);
    fake_reply.extend_from_slice(&[0, 16]);
    fake_reply.extend_from_slice(&[0; 16]);
    let answers: Vec<(&str, Option<Vec<u8>>)> = vec![
        ("A1 silent", None),
        // PIPE_ACK type with an entry for pipe 2 far beyond anything sent.
        (
            "A2 forged acknowledgement",
            Some(framed(&[0x80, 0, 0, 0x2a, 1, 2, 0, 0x80, 1, 0, 0, 0])),
        ),
        (
            "A3 forged stream data",
            Some(framed(&[0x0f, 0, 0, 6, b'F', b'O', b'R', b'G', b'E', b'D'])),
        ),
        (
            "A4 forged CONNECTION_CLOSE",
            Some(framed(&[0x1c, 0x0a, 0, 0])),
        ),
        ("A5 forged Reply", Some(fake_reply)),
        ("A5 beyond max_record_size", Some(vec![0x80, 1, 0, 0, 0xff])),
        (
            "A5 beyond any record",
            Some(vec![0xc0, 0, 1, 0, 0, 0, 0, 0]),
        ),
        ("A5 garbage", Some(vec![2, 0xff, 0xff])),
    ];
    for mode in [RecordMode::Sealed, RecordMode::Bound, RecordMode::Trusted] {
        for (name, answer) in &answers {
            let (client, server, _listener) = sessions().await;
            let (near, mut far) = duplex(1 << 20);
            let mut io = PipeIo::new(near);
            if mode == RecordMode::Bound {
                io = io.with_carrier_secure().with_exporter(|_, _, out| {
                    out.fill(9);
                    true
                });
            }
            let pipe = client
                .test_begin_join(io, PipeOptions::new().with_record_mode(mode))
                .unwrap();
            let mut hello = vec![0; 4096];
            let n = far.read(&mut hello).await.unwrap();
            assert_eq!(hello[0], 2, "{name}: a Hello first");
            if let Some(a) = answer {
                far.write_all(a).await.unwrap();
                far.flush().await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
            // Nothing more than the Hello reached the carrier, and nothing of it the session.
            let mut more = [0; 16];
            let extra = timeout(Duration::from_millis(10), far.read(&mut more)).await;
            assert!(
                !matches!(extra, Ok(Ok(m)) if m > 0),
                "{mode:?} {name}: bytes after {n} of Hello"
            );
            assert_ne!(
                pipe.stats().and_then(|s| s.outbound),
                Some(zmux::OutboundState::Active),
                "{mode:?} {name}: ACTIVE without a Reply"
            );
            // The session goes on over pipe 0.
            let (mut send, _r) = client.open_bi().await.unwrap();
            send.write_all(b"real").await.unwrap();
            send.flush().await.unwrap();
            let (_s, mut r) = timeout(Duration::from_secs(5), server.accept_bi())
                .await
                .unwrap()
                .unwrap();
            let mut b = [0; 4];
            r.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"real", "{mode:?} {name}");
            client.close().await;
        }
    }
}

/// A Bound join through a party that terminates the carrier: the two ends export different
/// values, and the Hello does not verify. Nothing is sent back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_join_through_a_relay_fails_at_the_acceptor() {
    let (client, server, listener) = sessions().await;
    let exporter = |v: u8| {
        move |_: &str, _: &[u8], out: &mut [u8]| {
            out.fill(v);
            true
        }
    };
    let (near, far) = duplex(1 << 16);
    let l = listener.clone();
    let far = PipeIo::new(far)
        .with_carrier_secure()
        .with_exporter(exporter(1));
    tokio::spawn(async move { l.handle_pipe(far, zmux::PipeHint::default()).await });
    let near = PipeIo::new(near)
        .with_carrier_secure()
        .with_exporter(exporter(2));
    let pipe = client
        .test_begin_join(near, PipeOptions::new().with_record_mode(RecordMode::Bound))
        .unwrap();
    assert!(
        timeout(Duration::from_secs(5), pipe.joined())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(server.stats().join_auth_failures, 1);
    let _ = CarrierExporter::new(|_, _, _| false);
}

/// A Bound join whose two ends see different exporters is closed at once by default, as
/// every refused join is, without a byte and long before the join timeout a stall would
/// last.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_join_with_another_binding_is_closed_at_once_by_default() {
    let (client, _server, listener) = sessions().await;
    let exporter = |v: u8| {
        move |_: &str, _: &[u8], out: &mut [u8]| {
            out.fill(v);
            true
        }
    };
    let (near, far) = duplex(1 << 16);
    let l = listener.clone();
    let far = PipeIo::new(far)
        .with_carrier_secure()
        .with_exporter(exporter(1));
    let start = tokio::time::Instant::now();
    let served = tokio::spawn(async move {
        let r = l.handle_pipe(far, zmux::PipeHint::default()).await;
        (r, start.elapsed())
    });
    let near = PipeIo::new(near)
        .with_carrier_secure()
        .with_exporter(exporter(2));
    let pipe = client
        .test_begin_join(near, PipeOptions::new().with_record_mode(RecordMode::Bound))
        .unwrap();
    let (r, took) = timeout(Duration::from_secs(5), served)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r, Err(zmux::HandleError::Rejected));
    assert!(took < Duration::from_secs(2), "{took:?}");
    assert!(
        timeout(Duration::from_secs(5), pipe.joined())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(listener.stats().rejected, 1);
}

/// A Sealed join passes through a relay that reads every byte: it needs no carrier
/// integrity, and the relay sees no plaintext of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_join_passes_a_relay_that_sees_no_plaintext() {
    let (client, server, listener) = sessions().await;
    let (near, mut relay_a) = duplex(1 << 16);
    let (mut relay_b, far) = duplex(1 << 16);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut up = [0u8; 8192];
        let mut down = [0u8; 8192];
        loop {
            tokio::select! {
                r = relay_a.read(&mut up) => {
                    let Ok(n @ 1..) = r else { return };
                    log.lock().unwrap().extend_from_slice(&up[..n]);
                    if relay_b.write_all(&up[..n]).await.is_err() { return }
                }
                r = relay_b.read(&mut down) => {
                    let Ok(n @ 1..) = r else { return };
                    if relay_a.write_all(&down[..n]).await.is_err() { return }
                }
            }
        }
    });
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
            .await
    });
    let pipe = client
        .test_begin_join(PipeIo::new(near), PipeOptions::new())
        .unwrap();
    timeout(Duration::from_secs(5), pipe.joined())
        .await
        .unwrap()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.pipes().len() < 2 {
        assert!(Instant::now() < deadline, "the acceptor attached it");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    client.pipe(PipeId::new(0)).unwrap().abort().unwrap();
    let (mut send, _r) = client.open_bi().await.unwrap();
    send.write_all(b"a secret that stays inside").await.unwrap();
    send.flush().await.unwrap();
    let (_s, mut r) = timeout(Duration::from_secs(5), server.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let mut b = [0; 26];
    r.read_exact(&mut b).await.unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.windows(8).any(|w| w == b"a secret"));
}

/// Carries a Sealed join from the joiner to the acceptor unit by unit; drops whole records
/// on `drop`, and on `fin` ends the carrier at a record boundary.
async fn unit_relay<R, W>(
    mut from: R,
    mut to: W,
    drop_units: Arc<AtomicBool>,
    fin: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut b = [0u8; 8192];
    let mut in_units = false;
    loop {
        if fin.load(SeqCst) {
            let _ = to.shutdown().await;
            let _ = tokio::io::copy(&mut from, &mut tokio::io::sink()).await;
            return;
        }
        match timeout(Duration::from_millis(5), from.read(&mut b)).await {
            Ok(Ok(0) | Err(_)) => return,
            Ok(Ok(n)) => buf.extend_from_slice(&b[..n]),
            Err(_) => {}
        }
        if !in_units && buf.len() >= 4 && buf.len() >= 4 + usize::from(buf[3]) + 32 {
            let head = 4 + usize::from(buf[3]) + 32;
            if to.write_all(&buf[..head]).await.is_err() {
                return;
            }
            buf.drain(..head);
            in_units = true;
        }
        while in_units && buf.len() >= 2 {
            let unit = 2 + usize::from(u16::from_be_bytes([buf[0], buf[1]]));
            if buf.len() < unit {
                break;
            }
            if drop_units.load(SeqCst) {
                dropped.fetch_add(unit, SeqCst);
            } else if to.write_all(&buf[..unit]).await.is_err() {
                return;
            }
            buf.drain(..unit);
        }
    }
}

/// A carrier that ends at a record boundary with no `PIPE_ABANDON` fails its pipe: the data it
/// lost is sent again and no stream sees an end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_end_at_a_record_boundary_is_a_failure() {
    let (client, server, listener) = sessions().await;
    let (near, relay_a) = duplex(1 << 20);
    let (relay_b, far) = duplex(1 << 20);
    let (a_read, mut a_write) = tokio::io::split(relay_a);
    let (mut b_read, b_write) = tokio::io::split(relay_b);
    let drop_units = Arc::new(AtomicBool::new(false));
    let fin = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    tokio::spawn(unit_relay(
        a_read,
        b_write,
        drop_units.clone(),
        fin.clone(),
        dropped.clone(),
    ));
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut b_read, &mut a_write).await;
    });
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
            .await
    });
    let pipe = client
        .test_begin_join(PipeIo::new(near), PipeOptions::new().with_probation(None))
        .unwrap();
    timeout(Duration::from_secs(5), pipe.joined())
        .await
        .unwrap()
        .unwrap();
    let id = pipe.id();
    // Stream data takes the relayed pipe, with no probation and the first on standby: what
    // is dropped is then data, not control frames while the first pipe is preferred.
    client
        .pipe(PipeId::new(0))
        .unwrap()
        .update(&zmux::PipeUpdate {
            send_standby: zmux::Change::Set(true),
            ..Default::default()
        })
        .unwrap();
    let until = async |what: &str, f: &dyn Fn() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !f() {
            assert!(Instant::now() < deadline, "{what}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    until("the acceptor's pipe", &|| server.pipes().len() >= 2).await;
    let (mut send, _r) = client.open_bi().await.unwrap();
    send.write_all(&[7]).await.unwrap();
    send.flush().await.unwrap();
    let (_s, mut recv) = timeout(Duration::from_secs(5), server.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let reader = tokio::spawn(async move { recv.read_to_end(1 << 30).await });
    drop_units.store(true, SeqCst);
    let chunk = vec![7u8; 4096];
    let mut total = 1;
    let deadline = Instant::now() + Duration::from_secs(30);
    while dropped.load(SeqCst) < 2048 {
        assert!(
            Instant::now() < deadline,
            "nothing went over the relayed pipe"
        );
        send.write_all(&chunk).await.unwrap();
        send.flush().await.unwrap();
        total += chunk.len();
    }
    fin.store(true, SeqCst);
    until("the end to fail the pipe", &|| {
        server
            .pipe_stats()
            .iter()
            .find(|p| p.pipe == id)
            .is_none_or(|p| p.outbound == Some(zmux::OutboundState::Failed))
    })
    .await;
    until("the lost data to be sent again", &|| {
        client.stats().bytes_reinjected > 0
    })
    .await;
    assert!(!reader.is_finished(), "the stream saw an end");
    send.write_all(&chunk).await.unwrap();
    total += chunk.len();
    send.finish().unwrap();
    let all = timeout(Duration::from_secs(30), reader)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(all.len(), total);
    assert!(all.iter().all(|&b| b == 7));
    assert_eq!(client.state(), server.state());
}

/// A Hello in Bound on a carrier with no Binding is refused as auth and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_hello_without_a_binding_is_refused_as_auth() {
    let (a, b) = duplex(1 << 20);
    let reason = Arc::new(std::sync::Mutex::new(String::new()));
    let seen = reason.clone();
    let mut lc = ListenerConfig::default();
    lc.on_reject = Some(OnReject::new(move |i| {
        *seen.lock().unwrap() = i.reason.to_string();
        RejectAction::Close
    }));
    let listener = Listener::new(config(), lc).expect("valid listener configuration");
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
            .await
    });
    let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
    let server = listener.accept().await.unwrap();
    client.established().await.unwrap();
    let (near, far) = duplex(1 << 16);
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
            .await
    });
    let near = PipeIo::new(near).with_carrier_secure().with_exporter(
        |_: &str, _: &[u8], out: &mut [u8]| {
            out.fill(1);
            true
        },
    );
    let e = client
        .test_begin_join(near, PipeOptions::new().with_record_mode(RecordMode::Bound))
        .unwrap();
    let joined = timeout(Duration::from_secs(10), e.joined()).await.unwrap();
    assert!(joined.is_err());
    assert_eq!(reason.lock().unwrap().as_str(), "auth");
    assert_eq!(server.stats().join_auth_failures, 1);
}

// ---- sans-IO: the Hello on the wire ------------------------------------------------------

/// A pair of cores established on pipe 0.
fn pair(a: Config, mut b: Config) -> core_pair::CorePair {
    b.test_hooks().locator = b"server".to_vec();
    core_pair::CorePair::new(a, b)
}

fn trusted_hello(core: &mut SessionCore, now: Instant) -> (PipeId, Vec<u8>) {
    let f = Some(Framing::ByteStream);
    let id = core
        .add_pipe(f, f, &PipeOptions::new(), RecordMode::Trusted, None, now)
        .unwrap();
    core.join_prepare(id, now).unwrap().unwrap();
    let mut unit = core
        .join_hello(id, (Framing::ByteStream, 0), &UnitPlan::default(), now)
        .unwrap();
    let len = unit.len();
    core.complete_join_write(&mut unit, len, false, now);
    (id, unit.to_vec())
}

fn carrier() -> PeerCarrier {
    let f = Some(Framing::ByteStream);
    PeerCarrier {
        setup: None,
        sources: zmux::CarrierHalfSources::default(),
        inbound: f,
        outbound: f,
        looped: false,
        overhead: 0,
        received: 0,
    }
}

fn open(core: &mut SessionCore, hello: &[u8], binding: &[u8], now: Instant) -> OpenedHello {
    let parsed = JoinHello::parse(Framing::ByteStream, hello).unwrap();
    core.open_hello(&parsed, binding, now)
}

/// A replayed Hello takes the Pipe ID but moves nothing: no pipe, no cap, no suspension. The
/// replayer can neither read the Reply nor make a confirmation, and the original then fails
/// as though lost.
#[test]
fn a_replay_on_another_path_moves_nothing() {
    let mut p = pair(config(), config());
    let now = p.now;
    let (_, hello) = trusted_hello(&mut p.a, now);
    let before = p.b.pipe_ids();
    let OpenedHello::Verified(mut replay) = open(&mut p.b, &hello, &[], now) else {
        panic!("the Hello verifies at ciphertext level");
    };
    assert!(matches!(
        p.b.claim_hello(&mut replay, &carrier(), &UnitPlan::default(), now),
        ClaimedHello::Accept { .. }
    ));
    assert_eq!(
        p.b.pipe_ids(),
        before,
        "an Unconfirmed carrier has no attachment"
    );
    // A guessed confirmation is refused, and no more can be done with this carrier.
    assert!(replay.read_confirm(&[0; 32]).is_err());
    assert_eq!(p.b.pipe_ids(), before);
    // The original, arriving second, closes at step 6.
    assert!(matches!(
        open(&mut p.b, &hello, &[], now),
        OpenedHello::Close
    ));
    assert_eq!(p.b.stats().join_replays, 1);
    assert_eq!(p.b.state(), State::Active);
}

/// A Hello bound to one carrier does not verify on another.
#[test]
fn a_bound_hello_does_not_verify_on_another_carrier() {
    let mut p = pair(config(), config());
    let now = p.now;
    let f = Some(Framing::ByteStream);
    let binding = [5; 32];
    let id =
        p.a.add_pipe(
            f,
            f,
            &PipeOptions::new(),
            RecordMode::Bound,
            Some(&binding),
            now,
        )
        .unwrap();
    p.a.join_prepare(id, now).unwrap().unwrap();
    let hello =
        p.a.join_hello(id, (Framing::ByteStream, 0), &UnitPlan::default(), now)
            .unwrap();
    assert!(matches!(
        open(&mut p.b, &hello, &[6; 32], now),
        OpenedHello::AuthFailed
    ));
    assert_eq!(p.b.stats().join_auth_failures, 1);
    assert!(
        matches!(
            p.b.poll_event(),
            Some(CoreEvent::JoinAuthFailed { reason: "auth" })
        ) || std::iter::from_fn(|| p.b.poll_event())
            .any(|e| matches!(e, CoreEvent::JoinAuthFailed { reason: "auth" }))
    );
    // The ID stays free: the right carrier still joins.
    assert!(matches!(
        open(&mut p.b, &hello, &binding, now),
        OpenedHello::Verified(_)
    ));
}

/// Secret Flags are never intersected: clearing one on the path closes the session rather
/// than taking that source out of the secret.
#[test]
fn a_cleared_secret_flag_is_no_downgrade() {
    use zmux::proto::keys::{SecretFlags, secret_flags, select_secret_source};
    let both = secret_flags::EXPORTER | secret_flags::PSK;
    assert_eq!(
        select_secret_source(both, secret_flags::EXPORTER),
        SecretFlags::Differ
    );
    assert_eq!(
        select_secret_source(both, secret_flags::PSK),
        SecretFlags::Differ
    );
    // Clearing all costs at most multipath.
    assert_eq!(select_secret_source(both, 0), SecretFlags::NoSource);
}

/// A Suite set changed on the path makes every join fail: both sets enter the keys.
#[test]
fn a_changed_suite_set_makes_joins_fail() {
    let mut narrow = config();
    narrow.session_crypto.suites = vec![1];
    let mut p = pair(config(), narrow);
    let now = p.now;
    // Both ends agree on what they saw: the join works.
    let (_, hello) = trusted_hello(&mut p.a, now);
    assert!(matches!(
        open(&mut p.b, &hello, &[], now),
        OpenedHello::Verified(_)
    ));
    // An end that believes another set derives other keys.
    let sc = |suites: &[u64]| zmux::proto::seal::SessionCrypto {
        suites: suites.to_vec(),
        groups: vec![1, 2],
    };
    let wide = zmux::proto::seal::session_crypto(&sc(&[1, 2]), &sc(&[1])).unwrap();
    let real = zmux::proto::seal::session_crypto(&sc(&[1]), &sc(&[1])).unwrap();
    let suite = zmux::proto::seal::Suite::from_value(1).unwrap();
    let k = |s: &[u8]| {
        zmux::proto::seal::derive_join_psk(
            suite,
            &[7; 32],
            zmux::proto::seal::JoinRole::Initiator,
            s,
        )
        .unwrap()
    };
    assert_ne!(k(&wide), k(&real));
}

/// A Hello naming a Suite outside the session's is an unauthenticated rejection, given the
/// listener's reject policy, and not a close past it.
#[test]
fn a_suite_outside_the_session_is_unknown_suite() {
    let mut narrow = config();
    narrow.session_crypto.suites = vec![1];
    let mut p = pair(config(), narrow);
    let now = p.now;
    let (_, mut hello) = trusted_hello(&mut p.a, now);
    assert_eq!(hello[1], 1, "the Suite follows the Hello type");
    hello[1] = 2;
    assert!(matches!(
        open(&mut p.b, &hello, &[], now),
        OpenedHello::UnknownSuite
    ));
}

// ---- plans of the messages ---------------------------------------------------------------

fn prepared(core: &mut SessionCore, mode: RecordMode, now: Instant) -> (PipeId, &'static str) {
    let f = Some(Framing::ByteStream);
    let id = core
        .add_pipe(f, f, &PipeOptions::new(), mode, None, now)
        .unwrap();
    (id, core.join_prepare(id, now).unwrap().unwrap())
}

/// Each message reaches its planned length on the wire, in Sealed and Trusted; a Reply keeps
/// within three times what was received in Sealed and not in Trusted.
#[test]
fn plans_reach_the_wire() {
    use zmux::proto::session::JoinStep;
    for mode in [RecordMode::Sealed, RecordMode::Trusted] {
        let mut p = pair(config(), config());
        let now = p.now;
        let (id, name) = prepared(&mut p.a, mode, now);
        assert_eq!(name, "hello", "another pipe is usable");
        let plan = UnitPlan::new(700, 0, 0);
        let bs = (Framing::ByteStream, 0);
        let mut hello = p.a.join_hello(id, bs, &plan, now).unwrap();
        let len = hello.len();
        p.a.complete_join_write(&mut hello, len, false, now);
        assert_eq!(hello.len(), 700);
        let OpenedHello::Verified(mut join) = open(&mut p.b, &hello, &[], now) else {
            panic!("not verified");
        };
        let mut c = carrier();
        c.received = hello.len();
        let reply_plan = UnitPlan::new(5000, 0, 0);
        let ClaimedHello::Accept { reply, .. } = p.b.claim_hello(&mut join, &c, &reply_plan, now)
        else {
            panic!("not accepted");
        };
        if mode == RecordMode::Trusted {
            assert_eq!(reply.len(), 5000);
        } else {
            assert!(
                reply.len() <= 2100 && reply.len() >= 2098,
                "{}",
                reply.len()
            );
        }
        let JoinStep::Verified { consumed, .. } = p.a.verify_reply(id, &reply, now) else {
            panic!("not verified");
        };
        assert_eq!(consumed, reply.len());
        let mut done = p.a.join_finish(id, &UnitPlan::new(300, 0, 0), now).unwrap();
        assert_eq!(done.confirm.len(), 300);
        assert_eq!(join.read_confirm(&done.confirm).unwrap(), Some(300));
        p.a.complete_join_write(&mut done.confirm, 300, false, now);
        assert!(p.a.shaping_stats().handshake_measured_bytes > 500);
        assert_eq!(p.a.shaping_stats().wire_spent, 0);
    }
}

/// A first batch stays within a Hello's planned length, and a closing session refuses the
/// message whose plan it waited for.
#[test]
fn a_closing_session_ends_a_prepared_join() {
    let mut p = pair(config(), config());
    let now = p.now;
    let (id, _) = prepared(&mut p.a, RecordMode::Trusted, now);
    p.a.abort(0u32.into(), b"", now);
    let r =
        p.a.join_hello(id, (Framing::ByteStream, 0), &UnitPlan::default(), now);
    assert!(r.is_err());
}

/// A first batch above what a Hello's ciphertext holds does not fail the join, and the Hello
/// stays within the handshake message floor of 8192 bytes.
#[test]
fn an_early_limit_beyond_the_ciphertext_keeps_the_join() {
    let mut a = config();
    a.join_early_hello = Some(1 << 20);
    a.resume_timeout = Some(Duration::from_secs(60));
    let mut b = config();
    b.resume_timeout = a.resume_timeout;
    let mut p = pair(a, b);
    let now = p.now;
    let k = p.a.open(zmux::proto::frame::Dir::Bidi).unwrap();
    assert!(p.a.write(k, &vec![7; 128 << 10]).unwrap() >= 66_000);
    p.a.write_failed(PipeId::new(0), std::io::ErrorKind::BrokenPipe, now);
    let (id, name) = prepared(&mut p.a, RecordMode::Sealed, now);
    assert_eq!(name, "hello_early");
    let plan = UnitPlan::default();
    let hello =
        p.a.join_hello(id, (Framing::ByteStream, 0), &plan, now)
            .unwrap();
    assert!((7_000..=8192).contains(&hello.len()), "{}", hello.len());
    assert!(matches!(
        open(&mut p.b, &hello, &[], now),
        OpenedHello::Verified(_)
    ));
}

/// With Group 2, the largest Locator and the default 8 KiB first batch, the Hello is at most
/// 8192 bytes as written, the batch cut to the room the key share leaves, and the join
/// verifies; a Reply stays within the floor too.
#[test]
fn a_hello_with_the_largest_locator_and_a_full_batch_fits_the_floor() {
    let mut client = config();
    client.resume_timeout = Some(Duration::from_secs(60));
    let mut server = config();
    server.resume_timeout = client.resume_timeout;
    server.test_hooks().locator = vec![b'L'; 255];
    let mut p = core_pair::CorePair::new(client, server);
    let now = p.now;
    let k = p.a.open(zmux::proto::frame::Dir::Bidi).unwrap();
    assert!(p.a.write(k, &vec![7; 128 << 10]).unwrap() >= 66_000);
    p.a.write_failed(PipeId::new(0), std::io::ErrorKind::BrokenPipe, now);
    let (id, name) = prepared(&mut p.a, RecordMode::Sealed, now);
    assert_eq!(name, "hello_early");
    let hello =
        p.a.join_hello(id, (Framing::ByteStream, 0), &UnitPlan::default(), now)
            .unwrap();
    assert!(
        (6_000..=8192).contains(&hello.len()),
        "{} bytes",
        hello.len()
    );
    let OpenedHello::Verified(mut join) = open(&mut p.b, &hello, &[], now) else {
        panic!("not verified");
    };
    let mut c = carrier();
    c.received = hello.len();
    let ClaimedHello::Accept { reply, .. } =
        p.b.claim_hello(&mut join, &c, &UnitPlan::new(60_000, 0, 0), now)
    else {
        panic!("not accepted");
    };
    // A plan of 60000 bytes is cut to the floor (and to three times the Hello received).
    assert!(reply.len() <= 8192, "{}", reply.len());
}

/// Every refused join stalls for the listener's join timeout from its refusal: a Hello that
/// does not parse, and one for a known Locator whose session sets a longer join timeout.
#[tokio::test(start_paused = true)]
async fn refused_joins_stall_for_the_listeners_join_timeout() {
    let reasons = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = reasons.clone();
    let mut lc = ListenerConfig::default();
    lc.on_reject = Some(OnReject::new(move |i| {
        seen.lock().unwrap().push(i.reason.to_string());
        RejectAction::Stall
    }));
    lc.session_config = Some(zmux::SessionConfigFn::new(|_| {
        let mut c = config();
        c.join_timeout = Duration::from_secs(60);
        Ok(Some(c))
    }));
    let mut base = config();
    base.join_timeout = Duration::from_secs(3);
    let listener = Listener::new(base, lc).expect("valid listener configuration");
    let (a, b) = duplex(1 << 20);
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
            .await
    });
    let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
    let _server = listener.accept().await.unwrap();
    client.established().await.unwrap();
    let stalled = |far: PipeIo| {
        let l = listener.clone();
        let start = tokio::time::Instant::now();
        let (hold, closed) = tokio::sync::oneshot::channel::<()>();
        let far = far.with_unsent(move || {
            let _ = &hold;
            None
        });
        let setup =
            tokio::spawn(async move { l.handle_pipe(far, zmux::PipeHint::default()).await });
        async move {
            assert!(setup.await.unwrap().is_err());
            assert_eq!(start.elapsed(), Duration::ZERO);
            assert!(closed.await.is_err());
            assert_eq!(start.elapsed(), Duration::from_secs(3));
        }
    };
    // A message that is a Join by its first byte but no Hello: its Suite is no shortest
    // varint.
    let (mut near, far) = duplex(1 << 16);
    let task = stalled(PipeIo::new(far).records());
    near.write_all(&[2, 0x40, 0x01]).await.unwrap();
    task.await;
    // A known Locator: Bound without a Binding at the acceptor.
    let (near, far) = duplex(1 << 16);
    let task = stalled(PipeIo::new(far));
    let near = PipeIo::new(near).with_carrier_secure().with_exporter(
        |_: &str, _: &[u8], out: &mut [u8]| {
            out.fill(1);
            true
        },
    );
    let _join = client
        .test_begin_join(near, PipeOptions::new().with_record_mode(RecordMode::Bound))
        .unwrap();
    task.await;
    assert_eq!(*reasons.lock().unwrap(), ["malformed", "auth"]);
}

/// A carrier from a source that holds its share is closed at once, before anything is
/// read and without the reject policy, and counted as refused.
#[tokio::test(start_paused = true)]
async fn a_carrier_over_its_source_limit_is_closed_at_once() {
    let reasons = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = reasons.clone();
    let mut lc = ListenerConfig::default();
    lc.limits.max_pending_per_source = 3;
    lc.handshake_timeout = Duration::from_millis(500);
    lc.limits.first_record_timeout = Duration::from_secs(60);
    lc.on_reject = Some(OnReject::new(move |i| {
        seen.lock().unwrap().push((i.profile, i.reason.to_string()));
        RejectAction::Stall
    }));
    let listener = Listener::new(config(), lc).expect("valid listener configuration");
    // Three silent carriers hold the source's slots; the fourth is over.
    let start = tokio::time::Instant::now();
    let mut held = Vec::new();
    for _ in 0..4 {
        let (near, far) = duplex(1 << 16);
        let l = listener.clone();
        held.push((
            near,
            tokio::spawn(async move {
                l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
                    .await
            }),
        ));
        tokio::task::yield_now().await;
    }
    let (mut near, task) = held.pop().unwrap();
    assert_eq!(task.await.unwrap(), Err(zmux::HandleError::Refused));
    assert_eq!(start.elapsed(), Duration::ZERO);
    // Nothing was sent on the refused carrier.
    let mut buf = [0u8; 1];
    assert_eq!(near.read(&mut buf).await.unwrap(), 0);
    assert!(reasons.lock().unwrap().is_empty());
    assert_eq!(listener.stats().refused, 1);
}

/// At the listener, a Hello whose Suite is outside its session's set goes to the reject
/// policy with the local reason `unknown_suite`, without opening the Hello.
#[tokio::test(start_paused = true)]
async fn the_listener_refuses_a_suite_outside_the_session_as_unknown_suite() {
    let reasons = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = reasons.clone();
    let mut lc = ListenerConfig::default();
    lc.on_reject = Some(OnReject::new(move |i| {
        seen.lock().unwrap().push(i.reason.to_string());
        RejectAction::Close
    }));
    let mut base = config();
    base.session_crypto.suites = vec![1];
    let listener = Listener::new(base, lc).expect("valid listener configuration");
    let (a, b) = duplex(1 << 20);
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
            .await
    });
    let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
    let _server = listener.accept().await.unwrap();
    client.established().await.unwrap();
    // The client's Hello, its Suite changed on the way.
    let (cnear, mut cfar) = duplex(1 << 16);
    let _join = client
        .test_begin_join(PipeIo::new(cnear).records(), PipeOptions::new())
        .unwrap();
    let mut hello = vec![0u8; 1 << 16];
    let n = cfar.read(&mut hello).await.unwrap();
    hello.truncate(n);
    assert_eq!(&hello[..2], [2, 1], "a Join of Suite 1");
    hello[1] = 2;
    let (mut lnear, lfar) = duplex(1 << 16);
    let l = listener.clone();
    let task = tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(lfar).records(), zmux::PipeHint::default())
            .await
    });
    lnear.write_all(&hello).await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert_eq!(*reasons.lock().unwrap(), ["unknown_suite"]);
}

/// Deliver the first ACK for bytes already sent on a locally installed join.
/// The timer need not have run when the packet is taken off the healthy pipe.
#[test]
// HS-22, HS-23
fn a_late_ack_cannot_attach_an_expired_installed_pipe() {
    use zmux::proto::frame::{Frame, PipeAck, PipeAckEntry};
    use zmux::proto::session::{ConfirmedJoin, JoinStep, PipeError, PipeFailure};

    for (on_time, timer_ran) in [(true, false), (false, false), (false, true)] {
        let mut cfg = config();
        cfg.join_timeout = Duration::from_secs(3);
        let mut p = pair(cfg.clone(), cfg.clone());
        let now = p.now;
        let (id, hello) = trusted_hello(&mut p.a, now);
        let OpenedHello::Verified(mut join) = open(&mut p.b, &hello, &[], now) else {
            panic!("authenticated Hello");
        };
        let plan = UnitPlan::default();
        let ClaimedHello::Accept { reply, .. } = p.b.claim_hello(&mut join, &carrier(), &plan, now)
        else {
            panic!("accepted Hello");
        };
        assert!(matches!(
            p.a.verify_reply(id, &reply, now),
            JoinStep::Verified { .. }
        ));
        let done = p.a.join_finish(id, &plan, now).unwrap();
        assert!(join.read_confirm(&done.confirm).unwrap().is_some());
        assert!(matches!(
            p.b.confirm_join(*join, &carrier(), now),
            ConfirmedJoin::Attached { .. }
        ));
        assert!(matches!(p.a.pipe_joined(id), Some(Ok(()))));
        assert!(p.a.pipe_attached(id).is_none());

        // The peer acknowledges the actual probation probe on the new pipe.
        p.a.poll_transmit(id, now, &mut p.out);
        let sent = p.out.len() as u64;
        assert!(sent > 0);
        p.a.pipe_written(id, sent, now);
        let entries = [PipeAckEntry {
            pipe_id: id.get(),
            lane: 0,
            position: sent,
            ack_delay: 0,
        }];
        let mut ack = [0u8; 64];
        let n = Frame::PipeAck(PipeAck::new(&entries))
            .encode(&mut ack)
            .unwrap();
        let ack = framed(&ack[..n]);
        let deadline = now + cfg.join_timeout;
        let arrival = if on_time {
            deadline.checked_sub(Duration::from_nanos(1)).unwrap()
        } else {
            deadline
        };
        if timer_ran {
            p.a.handle_timeout(arrival);
        }
        for _ in 0..2 {
            assert_eq!(
                p.a.receive_in_place(core_pair::P0, &ack, arrival),
                ack.len()
            );
        }
        let result = p.a.pipe_attached(id);
        if on_time {
            assert!(matches!(result, Some(Ok(()))), "{result:?}");
        } else {
            assert!(
                matches!(
                    result,
                    Some(Err(PipeError::Failed(PipeFailure::JoinTimedOut)))
                ),
                "{result:?}"
            );
        }
        let mut attached_events = 0;
        while let Some(event) = p.a.poll_event() {
            if matches!(event, CoreEvent::PipeAttached { pipe } if pipe == id) {
                attached_events += 1;
            }
        }
        assert_eq!(attached_events, usize::from(on_time));
        let listed = p.a.pipes().into_iter().find(|s| s.pipe == id);
        assert_eq!(listed.map(|s| s.peer_attached), on_time.then_some(true));
    }
}

#[test]
// HS-28
fn a_deferred_join_keeps_its_abort_after_immediate_retirement() {
    let mut cfg = config();
    cfg.session_policy.limits.steady_attachments = 2;
    let mut p = pair(cfg.clone(), cfg.clone());
    let f = Some(Framing::ByteStream);
    let id = (0..=cfg.session_policy.limits.steady_attachments
        + cfg.session_policy.limits.join_headroom)
        .find_map(|_| {
            let id =
                p.a.add_pipe(f, f, &PipeOptions::new(), RecordMode::Trusted, None, p.now)
                    .unwrap();
            p.a.join_deferred(id).then_some(id)
        })
        .expect("the cap held the new join");
    let snapshot = p.a.pipe_final(id).unwrap();
    p.a.remove_pipe(id, false, p.now).unwrap();
    assert!(!p.a.has_pipe(id));
    let error = snapshot.get().unwrap().closed.as_ref().unwrap_err();
    assert!(matches!(
        error,
        zmux::PipeError::Failed(zmux::PipeFailure::Aborted)
    ));
    assert!(error.is_gone());
    assert!(std::iter::from_fn(|| p.a.poll_event()).any(|e| matches!(
        e, CoreEvent::PipeRetired {pipe, join_failure: Some(zmux::PipeFailure::Aborted), failed: true} if pipe == id
    )));
}

#[test]
// HS-24a
fn a_carrier_error_uses_the_cores_advanced_join_clock() {
    use zmux::{PipeError, PipeFailure};

    for expired in [false, true] {
        let cfg = config();
        let mut p = pair(cfg.clone(), cfg.clone());
        let (id, _) = trusted_hello(&mut p.a, p.now);
        if expired {
            // Advance only the core. The I/O error still carries the older
            // driver timestamp and the timer handler has not run.
            p.a.set_pipe_unsent(core_pair::P0, 0, p.now + cfg.join_timeout);
        }
        let kind = std::io::ErrorKind::UnexpectedEof;
        p.a.join_carrier_failed(id, kind, p.now);
        let cause = if expired {
            PipeFailure::JoinTimedOut
        } else {
            PipeFailure::Carrier(kind)
        };
        assert!(
            matches!(p.a.pipe_joined(id), Some(Err(PipeError::Failed(actual))) if actual == cause),
            "{:?}",
            p.a.pipe_joined(id)
        );
    }
}
