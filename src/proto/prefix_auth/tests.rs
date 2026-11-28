use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::Deserialize;

use super::*;
use crate::adapter::Framing;
use crate::{AdmissionStage, CarrierExporter, ClockDomain};

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn array<const LEN: usize>(hex: &str) -> [u8; LEN] {
    bytes(hex).try_into().unwrap()
}

#[derive(Deserialize)]
struct Vectors {
    prefix: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    binding: String,
    id: String,
    nonce: String,
    outer: String,
    slot: u64,
    slot_seconds: u64,
    ticket_key: String,
    token: String,
    header: String,
}

impl Vector {
    fn ticket(&self, single_use: bool) -> PrefixTicket {
        PrefixTicket::new(
            array(&self.id),
            array(&self.ticket_key),
            1,
            0..=u64::MAX,
            single_use,
        )
    }

    fn presenter(&self) -> PrefixAuth {
        let generation = PrefixGeneration::new(array(&self.outer), 0..=u64::MAX);
        let schedule = Arc::new(PrefixSchedule::new(1, vec![generation]).unwrap());
        PrefixAuth::new(
            self.ticket(false),
            schedule,
            self.slot_seconds,
            PrefixBinding::AllowCleartext,
        )
        .unwrap()
    }
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str::<Vectors>(include_str!(
        "../../../testdata/spec/secure-carrier/vectors/first_message.json"
    ))
    .unwrap()
    .prefix
}

#[test]
fn first_message_byte_vectors() {
    for vector in vectors() {
        let token = vector
            .presenter()
            .token_at(vector.slot, array(&vector.nonce), &bytes(&vector.binding))
            .unwrap();
        assert_eq!(token, array(&vector.token), "{}", vector.name);
        assert_eq!(
            PrefixAuth::header_value(&token),
            vector.header,
            "{}",
            vector.name
        );
    }
}

#[derive(Deserialize)]
struct Scenarios {
    prefix: PrefixScenarios,
}

#[derive(Deserialize)]
struct PrefixScenarios {
    base_unix_seconds: u64,
    default_input: String,
    slot_seconds: u64,
    skew_slots: u32,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    form: String,
    #[serde(default)]
    accept_first_use_dos: bool,
    #[serde(default)]
    claim_capacity: usize,
    cutover_slot: Option<u64>,
    incoming_outer_from: Option<String>,
    #[serde(default)]
    single_use: bool,
    attempts: Vec<Attempt>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Attempt {
    input: Option<String>,
    expect: String,
    then: String,
    append_hex: String,
    expect_remaining_hex: String,
    take_bytes: Option<usize>,
    offset_seconds: i64,
    expire_at_offset_seconds: Option<i64>,
    early_data: bool,
    outer_transport: String,
    binding_hex: Option<String>,
    accept_first_use_dos: Option<bool>,
    count: Option<usize>,
    append_text: String,
    xor_byte: Option<usize>,
    xor_unused_bit: bool,
    concurrent_inputs: Vec<String>,
    expect_multiset: Vec<String>,
}

fn bound_info(binding: Vec<u8>) -> CarrierInfo {
    CarrierInfo::new().with_prefix_binding(CarrierExporter::new(move |label, context, out| {
        if label != PREFIX_AUTH_EXPORTER_LABEL || !context.is_empty() || binding.len() != out.len()
        {
            return false;
        }
        out.copy_from_slice(&binding);
        true
    }))
}

async fn run(
    store: Arc<dyn PrefixStore>,
    case: &Case,
    attempt: &Attempt,
    vector: &Vector,
    unix: u64,
) -> &'static str {
    let bound = !vector.binding.is_empty();
    let binding = if bound {
        PrefixBinding::Bound
    } else if attempt
        .accept_first_use_dos
        .unwrap_or(case.accept_first_use_dos)
    {
        PrefixBinding::AllowCleartext
    } else {
        PrefixBinding::Encrypted
    };
    let verifier = PrefixAuthVerifier::new(store, binding)
        .unwrap()
        .with_clock(move || Some(unix));
    let binding = bytes(attempt.binding_hex.as_deref().unwrap_or(&vector.binding));
    let mut info = match attempt.outer_transport.as_str() {
        "" | "tls13" | "quic" => bound_info(binding),
        "tls12" => CarrierInfo::new().with_encrypted(),
        "cleartext" => CarrierInfo::new(),
        other => panic!("unknown transport {other}"),
    };
    if attempt.early_data {
        info = info.with_early_data();
    }
    let mut prefix = bytes(&vector.token);
    prefix.extend(bytes(&attempt.append_hex));
    if let Some(i) = attempt.xor_byte {
        prefix[i] ^= 1;
    }
    if let Some(n) = attempt.take_bytes {
        prefix.truncate(n);
    }
    match case.form.as_str() {
        "header" => {
            prefix.clear();
            let mut value = vector.header.as_bytes().to_vec();
            value.extend_from_slice(attempt.append_text.as_bytes());
            if attempt.xor_unused_bit {
                let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let end = value.last_mut().unwrap();
                *end = alphabet[alphabet.iter().position(|b| b == end).unwrap() ^ 1];
            }
            let count = attempt.count.unwrap_or(1);
            info = info
                .with_stage(AdmissionStage::Head)
                .with_headers(move |each| {
                    for _ in 0..count {
                        each(PREFIX_AUTH_HEADER, &value);
                    }
                });
        }
        "message" => info = info.with_framing(Framing::Records),
        "" | "stream" => {}
        other => panic!("unknown form {other}"),
    }
    let time = PrefixDeadline::new(ClockDomain::default(), None);
    match verifier.redeem(&info, &prefix, time, Box::new(())).await {
        Some((skip, principal)) => {
            assert_eq!(prefix[skip..], bytes(&attempt.expect_remaining_hex));
            assert_eq!(principal, bound.then(|| array(&vector.id)));
            "accepted"
        }
        None => "refused",
    }
}

#[tokio::test]
async fn first_message_prefix_scenarios() {
    let scenarios: Scenarios = serde_json::from_str(include_str!(
        "../../../testdata/spec/secure-carrier/vectors/first_message_cases.json"
    ))
    .unwrap();
    let suite = scenarios.prefix;
    let vectors: HashMap<_, _> = vectors()
        .into_iter()
        .map(|vector| (vector.name.clone(), vector))
        .collect();
    let base = &vectors[&suite.default_input];
    let window = PrefixWindow::new(suite.slot_seconds, suite.skew_slots, 2).unwrap();
    for case in suite.cases {
        let outer = array(&base.outer);
        let generations = match case.cutover_slot {
            Some(cutover) => vec![
                PrefixGeneration::new(outer, 0..=cutover - 1),
                PrefixGeneration::new(
                    array(&vectors[case.incoming_outer_from.as_deref().unwrap_or("rotated")].outer),
                    cutover..=u64::MAX,
                ),
            ],
            None => vec![PrefixGeneration::new(outer, 0..=u64::MAX)],
        };
        let store =
            Arc::new(MemoryPrefixStore::new(window, generations, case.claim_capacity).unwrap());
        store.add_ticket(base.ticket(case.single_use)).unwrap();
        for attempt in &case.attempts {
            if let Some(offset) = attempt.expire_at_offset_seconds {
                store.expire(suite.base_unix_seconds.checked_add_signed(offset).unwrap());
                continue;
            }
            let unix = suite
                .base_unix_seconds
                .checked_add_signed(attempt.offset_seconds)
                .unwrap();
            if !attempt.concurrent_inputs.is_empty() {
                let [left, right] = attempt.concurrent_inputs.as_slice() else {
                    panic!("expected two callers")
                };
                let (left, right) = tokio::join!(
                    run(store.clone(), &case, attempt, &vectors[left], unix),
                    run(store.clone(), &case, attempt, &vectors[right], unix),
                );
                let mut actual = [left, right];
                actual.sort_unstable();
                let mut expected = attempt.expect_multiset.clone();
                expected.sort_unstable();
                assert_eq!(actual.as_slice(), expected, "{}", case.name);
                continue;
            }
            let vector = &vectors[attempt.input.as_deref().unwrap_or(&suite.default_input)];
            assert_eq!(
                run(store.clone(), &case, attempt, vector, unix).await,
                attempt.expect,
                "{} / {} at offset {}",
                case.name,
                vector.name,
                attempt.offset_seconds,
            );
            match attempt.then.as_str() {
                "revoke_ticket" => store.revoke_ticket(array(&base.id)),
                "" | "end_carrier" => {}
                other => panic!("unknown operation {other}"),
            }
        }
    }
}

#[test]
fn first_message_all_slot_trials_run_even_at_uint64_edges() {
    let generation = PrefixGeneration::new([1; 32], 0..=u64::MAX);
    for (current, expected_trials) in [
        (0, [0, 0, 1]),
        (7, [6, 7, 8]),
        (u64::MAX, [u64::MAX - 1, u64::MAX, 0]),
    ] {
        for matching in [Some(0), Some(1), Some(2), None] {
            let mut tried = Vec::new();
            let got = slot_trials(current, 1, &generation, |slot| {
                tried.push(slot);
                Some(tried.len() - 1) == matching
            });
            assert_eq!(tried, expected_trials);
            assert_eq!(
                got,
                matching.and_then(|i| current.checked_add_signed(i64::try_from(i).unwrap() - 1))
            );
        }
    }
    let mut count = 0;
    slot_trials(12, 0, &generation, |_| {
        count += 1;
        false
    });
    assert_eq!(count, 1);
    assert!(PrefixWindow::new(30, 3, 2).is_err());
}

#[test]
fn verifier_checks_skew_and_ticket_header_configuration() {
    let store = Arc::new(
        MemoryPrefixStore::new(
            PrefixWindow::new(30, 3, 3).unwrap(),
            vec![PrefixGeneration::new([1; 32], 0..=u64::MAX)],
            1,
        )
        .unwrap(),
    );
    assert!(PrefixAuthVerifier::new(store.clone(), PrefixBinding::Encrypted).is_err());
    let verifier =
        || PrefixAuthVerifier::with_max_skew(store.clone(), PrefixBinding::Encrypted, 3).unwrap();
    let presenter = PrefixAuth::new(
        PrefixTicket::new([2; 16], [3; 32], 1, 0..=u64::MAX, false),
        store.local_schedule().0,
        30,
        PrefixBinding::Encrypted,
    )
    .unwrap();
    for name in [
        "bad field",
        ":path",
        "Authorization",
        "Accept-Language",
        "SEC-WebSocket-Key",
        "zmux-PIPE-pair",
    ] {
        assert!(verifier().with_header(name).is_err(), "{name}");
        assert!(presenter.clone().with_header(name).is_err(), "{name}");
    }
    assert_eq!(
        verifier().with_header("").unwrap().header_name(),
        PREFIX_AUTH_HEADER
    );
    assert_eq!(
        presenter
            .with_header("X-Ticket")
            .unwrap()
            .prefix_ticket_header(),
        Some("X-Ticket")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_use_ticket_can_be_claimed_by_only_one_worker() {
    let id = [1; 16];
    let store = Arc::new(
        MemoryPrefixStore::new(
            PrefixWindow::new(30, 1, 2).unwrap(),
            vec![PrefixGeneration::new([2; 32], 0..=u64::MAX)],
            2,
        )
        .unwrap(),
    );
    store
        .add_ticket(PrefixTicket::new(id, [3; 32], 1, 0..=100, true))
        .unwrap();
    let ready = Arc::new(std::sync::Barrier::new(2));
    let handle = tokio::runtime::Handle::current();
    let claim = |nonce| {
        let (ready, store, handle) = (ready.clone(), store.clone(), handle.clone());
        tokio::task::spawn_blocking(move || {
            let attempt = PrefixDeadline::new(ClockDomain::default(), None);
            let claim = PrefixClaim {
                id,
                nonce: [nonce; 16],
                commit_id: [nonce; 16],
                version: 1,
                schedule: store.local_schedule().0.version(),
                generation: 0,
                issue_slot: 7,
                checked_slot: 7,
                local_slot: 7,
            };
            ready.wait();
            handle.block_on(store.claim(attempt, claim)).unwrap()
        })
    };
    let (a, b) = tokio::join!(claim(4), claim(5));
    assert_ne!(a.unwrap(), b.unwrap());
}

#[tokio::test(start_paused = true)]
async fn missing_first_carrier_stalls_with_or_without_a_fallback_target() {
    use crate::{Admission, Config, Fallback, Listener, ListenerConfig, PrefixRejection};
    let store = Arc::new(
        MemoryPrefixStore::new(
            PrefixWindow::new(30, 1, 2).unwrap(),
            vec![PrefixGeneration::new([2; 32], 0..=u64::MAX)],
            1,
        )
        .unwrap(),
    );
    let verifier = Arc::new(PrefixAuthVerifier::new(store, PrefixBinding::Encrypted).unwrap());
    for has_fallback in [false, true] {
        let limits = ListenerConfig {
            admission: Some(
                Admission::prefix_auth(verifier.clone(), PrefixRejection::Fallback)
                    .with_peek_timeout(Duration::from_secs(1))
                    .with_stall_interval(Duration::from_secs(2), Duration::from_secs(2)),
            ),
            fallback: has_fallback.then(|| {
                Fallback::new(|_| async {
                    panic!("no first carrier to hand off");
                })
            }),
            ..ListenerConfig::default()
        };
        let listener = Listener::new(Config::default(), limits).unwrap();
        let peer = "127.0.0.1:0".parse().unwrap();
        let mut entry = listener.adapter().enter(peer, None).unwrap();
        assert!(
            entry
                .admit_first(CarrierInfo::new(), std::future::pending())
                .await
                .is_none()
        );
        assert_eq!(listener.stats().admission.stalled, 1);
        drop(entry);

        let mut entry = listener.adapter().enter(peer, None).unwrap();
        assert!(
            entry
                .admit_first(CarrierInfo::new(), async {
                    Err(io::ErrorKind::ConnectionReset.into())
                })
                .await
                .is_none()
        );
        assert_eq!(listener.stats().admission.handshake_failed, 1);
        assert_eq!(listener.stats().admission.stalled, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn split_bootstrap_refuses_different_bound_ticket_principals() {
    use crate::adapter::Admit;
    use crate::{
        Admission, CarrierExporter, Config, HandleError, Listener, ListenerConfig, PipeHint,
        PipeIo, PrefixRejection,
    };

    let store = Arc::new(
        MemoryPrefixStore::new(
            PrefixWindow::new(30, 1, 2).unwrap(),
            vec![PrefixGeneration::new([2; 32], 0..=u64::MAX)],
            2,
        )
        .unwrap(),
    );
    let verifier = PrefixAuthVerifier::new(store.clone(), PrefixBinding::Bound)
        .unwrap()
        .with_clock(|| Some(30));
    let listener = Listener::new(
        Config::default(),
        ListenerConfig {
            admission: Some(Admission::prefix_auth(
                Arc::new(verifier),
                PrefixRejection::Close,
            )),
            ..ListenerConfig::default()
        },
    )
    .unwrap();
    let peer = "127.0.0.1:0".parse().unwrap();
    let mut hint = Vec::new();
    let binding = [8; 32];
    for id in [9, 10] {
        let ticket = PrefixTicket::new([id; 16], [3; 32], 1, 0..=100, false);
        store.add_ticket(ticket.clone()).unwrap();
        let presenter =
            PrefixAuth::new(ticket, store.local_schedule().0, 30, PrefixBinding::Bound).unwrap();
        let token = presenter.token_at(1, [id; 16], &binding).unwrap();
        let field = PrefixAuth::header_value(&token);
        let info = CarrierInfo::new()
            .with_prefix_binding(CarrierExporter::new(move |_, _, out| {
                out.copy_from_slice(&binding);
                true
            }))
            .with_headers(move |visit| visit(PREFIX_AUTH_HEADER, field.as_bytes()));
        let mut entry = listener.adapter().enter(peer, None).unwrap();
        assert!(matches!(
            entry
                .decide_request(info, None::<&mut tokio::io::Empty>)
                .await,
            Admit::Accept(_)
        ));
        let mut half = PipeHint::from_entry(entry);
        half.pair = Some(vec![7; crate::adapter::PAIRING_TOKEN_LEN]);
        hint.push(half);
    }
    let (up, _peer) = tokio::io::duplex(64);
    let (up, down) = tokio::join!(
        listener.handle_pipe(PipeIo::reader(up), hint.remove(0)),
        listener.handle_pipe(PipeIo::writer(tokio::io::sink()), hint.remove(0)),
    );
    assert!(matches!(up, Err(HandleError::Rejected)));
    assert!(matches!(down, Err(HandleError::Rejected)));
}

struct FaultStore {
    memory: MemoryPrefixStore,
    floors: AtomicUsize,
    lookups: AtomicUsize,
    claims: AtomicUsize,
    claim_started: tokio::sync::mpsc::UnboundedSender<(PrefixClaim, PrefixDeadline)>,
    resolved: tokio::sync::mpsc::UnboundedSender<(PrefixClaim, PrefixDeadline)>,
    pending_receipt: bool,
}

impl PrefixStore for FaultStore {
    fn window(&self) -> PrefixWindow {
        self.memory.window()
    }

    fn local_schedule(&self) -> (Arc<PrefixSchedule>, u64) {
        self.memory.local_schedule()
    }

    fn floor(&self, attempt: PrefixDeadline) -> PrefixStoreFuture<'_, u64> {
        self.floors.fetch_add(1, Ordering::Relaxed);
        self.memory.floor(attempt)
    }

    fn lookup(
        &self,
        attempt: PrefixDeadline,
        id: [u8; 16],
    ) -> PrefixStoreFuture<'_, Option<PrefixTicket>> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.memory.lookup(attempt, id)
    }

    fn claim(&self, attempt: PrefixDeadline, claim: PrefixClaim) -> PrefixStoreFuture<'_, bool> {
        Box::pin(async move {
            self.claims.fetch_add(1, Ordering::Relaxed);
            if !self.memory.claim(attempt.clone(), claim).await? {
                return Ok(false);
            }
            self.claim_started.send((claim, attempt)).unwrap();
            if self.pending_receipt {
                std::future::pending().await
            } else {
                Err(io::ErrorKind::ConnectionReset.into())
            }
        })
    }

    fn resolve(&self, attempt: PrefixDeadline, claim: PrefixClaim) -> PrefixStoreFuture<'_, bool> {
        Box::pin(async move {
            assert!(attempt.deadline().is_some());
            assert!(!attempt.ended());
            let accepted = self.memory.resolve(attempt.clone(), claim).await?;
            self.resolved.send((claim, attempt)).unwrap();
            Ok(accepted)
        })
    }
}

#[tokio::test]
async fn first_message_missing_receipt_is_resolved_with_the_original_commit_id() {
    let vector = vectors().remove(0);
    for pending_receipt in [false, true] {
        let generation = PrefixGeneration::new(array(&vector.outer), 0..=u64::MAX);
        let window = PrefixWindow::new(vector.slot_seconds, 1, 2).unwrap();
        let memory = MemoryPrefixStore::new(window, vec![generation], 1).unwrap();
        let ticket = vector.ticket(true);
        memory.add_ticket(ticket.clone()).unwrap();
        let (claim_started, mut started) = tokio::sync::mpsc::unbounded_channel();
        let (resolved, mut result) = tokio::sync::mpsc::unbounded_channel();
        let store = Arc::new(FaultStore {
            memory,
            floors: AtomicUsize::new(0),
            lookups: AtomicUsize::new(0),
            claims: AtomicUsize::new(0),
            claim_started,
            resolved,
            pending_receipt,
        });
        let unix = vector.slot * vector.slot_seconds;
        let verifier = Arc::new(
            PrefixAuthVerifier::new(store.clone(), PrefixBinding::Encrypted)
                .unwrap()
                .with_clock(move || Some(unix)),
        );
        let token = array::<PREFIX_TOKEN_LEN>(&vector.token);
        let info = CarrierInfo::new().with_encrypted();
        let clock = ClockDomain::default();
        let fresh = || {
            PrefixDeadline::new(
                clock.clone(),
                clock.now().checked_add(Duration::from_secs(60)),
            )
        };
        let mut bad = token;
        bad[32] ^= 1;
        assert!(
            verifier
                .redeem(&info, &bad, fresh(), Box::new(()))
                .await
                .is_none()
        );
        assert_eq!(store.floors.load(Ordering::Relaxed), 0);
        assert_eq!(store.lookups.load(Ordering::Relaxed), 0);
        bad = token;
        bad[48] ^= 1;
        assert!(
            verifier
                .redeem(&info, &bad, fresh(), Box::new(()))
                .await
                .is_none()
        );
        assert_eq!(store.floors.load(Ordering::Relaxed), 1);
        assert_eq!(store.lookups.load(Ordering::Relaxed), 1);
        assert_eq!(store.claims.load(Ordering::Relaxed), 0);

        let original = fresh();
        let work =
            tokio::spawn(
                async move { verifier.redeem(&info, &token, original, Box::new(())).await },
            );
        let (first, attempt) = started.recv().await.unwrap();
        if pending_receipt {
            work.abort();
            assert!(work.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(work.await.unwrap(), Some((PREFIX_TOKEN_LEN, None)));
        }
        let (resolved, receipt) = result.recv().await.unwrap();
        assert_eq!(first, resolved);
        assert!(attempt.ended());
        assert!(receipt.deadline() < attempt.deadline());
        assert_eq!(store.claims.load(Ordering::Relaxed), 1);
        assert!(
            store
                .memory
                .lookup(receipt, ticket.id)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn first_message_revocation_and_rotation_invalidate_an_inflight_claim() {
    let window = PrefixWindow::new(1, 1, 2).unwrap();
    let generation = PrefixGeneration::new([7; 32], 0..=u64::MAX);
    let store = MemoryPrefixStore::new(window, vec![generation.clone()], 2).unwrap();
    store.revoke_ticket([0; 16]);
    assert!(
        store
            .add_ticket(PrefixTicket::new([0; 16], [1; 32], 1, 0..=100, false))
            .is_err()
    );
    let ticket = PrefixTicket::new([2; 16], [3; 32], 1, 0..=100, false);
    store.add_ticket(ticket.clone()).unwrap();
    let attempt = PrefixDeadline::new(ClockDomain::default(), None);
    assert!(
        store
            .lookup(attempt.clone(), ticket.id)
            .await
            .unwrap()
            .is_some()
    );
    let mut claim = PrefixClaim {
        id: ticket.id,
        nonce: [4; 16],
        commit_id: [5; 16],
        version: 1,
        schedule: store.local_schedule().0.version(),
        generation: 0,
        issue_slot: 7,
        checked_slot: 7,
        local_slot: 7,
    };
    store.set_generations(vec![generation]).unwrap();
    assert!(!store.claim(attempt.clone(), claim).await.unwrap());
    claim.schedule = store.local_schedule().0.version();
    store.revoke_ticket(ticket.id);
    assert!(!store.claim(attempt.clone(), claim).await.unwrap());
    assert_eq!(store.floor(attempt).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn first_message_refusal_replays_input_even_when_the_authority_is_unavailable() {
    use crate::adapter::AdmitIo;
    use crate::{Admission, Config, Fallback, Listener, ListenerConfig, PipeIo, PrefixRejection};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Unavailable(MemoryPrefixStore);

    impl PrefixStore for Unavailable {
        fn window(&self) -> PrefixWindow {
            self.0.window()
        }

        fn local_schedule(&self) -> (Arc<PrefixSchedule>, u64) {
            self.0.local_schedule()
        }

        fn floor(&self, _: PrefixDeadline) -> PrefixStoreFuture<'_, u64> {
            Box::pin(async { Err(io::ErrorKind::NotConnected.into()) })
        }

        fn lookup(
            &self,
            _: PrefixDeadline,
            _: [u8; 16],
        ) -> PrefixStoreFuture<'_, Option<PrefixTicket>> {
            panic!("lookup after the floor failed")
        }

        fn claim(&self, _: PrefixDeadline, _: PrefixClaim) -> PrefixStoreFuture<'_, bool> {
            panic!("claim after the floor failed")
        }

        fn resolve(&self, _: PrefixDeadline, _: PrefixClaim) -> PrefixStoreFuture<'_, bool> {
            panic!("resolve without a claim")
        }
    }

    let vector = vectors().remove(0);
    let window = PrefixWindow::new(vector.slot_seconds, 1, 2).unwrap();
    let generation = PrefixGeneration::new(array(&vector.outer), 0..=u64::MAX);
    let store = Arc::new(Unavailable(
        MemoryPrefixStore::new(window, vec![generation], 1).unwrap(),
    ));
    let unix = vector.slot * vector.slot_seconds;
    let verifier = Arc::new(
        PrefixAuthVerifier::new(store, PrefixBinding::Encrypted)
            .unwrap()
            .with_clock(move || Some(unix)),
    );
    let (reported, mut reports) = tokio::sync::mpsc::unbounded_channel();
    let limits = ListenerConfig {
        admission: Some(
            Admission::prefix_auth(verifier, PrefixRejection::Fallback)
                .with_peek_timeout(Duration::from_secs(3)),
        ),
        fallback: Some(Fallback::new(move |takeover| {
            let reported = reported.clone();
            async move {
                reported.send(takeover.replayed().to_vec()).unwrap();
                let mut outer = takeover.into_stream().unwrap();
                outer.write_all(b"host").await.unwrap();
            }
        })),
        ..ListenerConfig::default()
    };
    let listener = Listener::new(Config::default(), limits).unwrap();
    let peer = "127.0.0.1:9".parse().unwrap();
    let token = bytes(&vector.token);
    let mut wrong = token.clone();
    wrong[0] ^= 1;
    for input in [token.as_slice(), wrong.as_slice(), &token[..63]] {
        let mut entry = listener.adapter().enter(peer, None).unwrap();
        let (mut client, server) = tokio::io::duplex(256);
        client.write_all(input).await.unwrap();
        let io = AdmitIo::stream(server, PipeIo::new);
        let mut output = Vec::new();
        let (accepted, read) = tokio::join!(
            entry.admit(CarrierInfo::new().with_encrypted(), io),
            client.read_to_end(&mut output),
        );
        assert!(accepted.is_none());
        read.unwrap();
        assert_eq!(output, b"host");
        assert_eq!(reports.recv().await.unwrap(), input);
    }
}
