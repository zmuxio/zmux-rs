//! Deterministic regressions for the Rust core and driver contracts.

#[path = "common/core_pair.rs"]
mod core_pair;
#[path = "common/mp_net.rs"]
mod mp_net;

use std::time::Duration;

use bytes::Bytes;
use core_pair::{CorePair, P0};
use zmux::proto::frame::{Datagram, DatagramPrefix};
use zmux::proto::payload::Flow;
use zmux::proto::record::Framing;
use zmux::proto::seal::join::JoinHello;
use zmux::proto::session::{ClaimedHello, OpenedHello, PeerCarrier, PeerJoin, SessionCore};
use zmux::shaping::UnitPlan;
use zmux::{Config, EpochPolicy, PipeAuth, PipeOptions, RecordMode};

const BS: Framing = Framing::ByteStream;

fn authorization_update(
    mut policy: zmux::SessionPolicy,
    authorize: zmux::AuthorizeJoin,
) -> zmux::SessionPolicy {
    policy.revision += 1;
    policy.auth_generation += 1;
    policy.authorize_join = Some(authorize);
    policy
}

fn config() -> Config {
    let mut config = Config::multipath(PipeAuth::exporter());
    config.epoch_policy = EpochPolicy::MANUAL;
    config
}

fn epoch_pair() -> CorePair {
    let mut pair = CorePair::attached(config(), config());
    for (core, locator) in [
        (&mut pair.a, b"initiator".as_slice()),
        (&mut pair.b, b"responder".as_slice()),
    ] {
        core.set_locator(locator).unwrap();
        core.set_secure_first_pipe(RecordMode::Bound);
        core.set_bootstrap_exporter_value(vec![42; 32]);
    }
    pair.pump();
    assert_eq!(pair.a.epoch(), Some(0));
    assert_eq!(pair.b.epoch(), Some(0));
    pair
}

fn hello(core: &mut SessionCore, now: std::time::Instant) -> Vec<u8> {
    let pipe = core
        .add_pipe(
            Some(BS),
            Some(BS),
            &PipeOptions::new(),
            RecordMode::Sealed,
            None,
            now,
        )
        .unwrap();
    core.join_prepare(pipe, now).unwrap().unwrap();
    let mut unit = core
        .join_hello(pipe, (BS, 0), &UnitPlan::default(), now)
        .unwrap();
    let len = unit.len();
    core.complete_join_write(&mut unit, len, false, now);
    unit.to_vec()
}

fn verified(core: &mut SessionCore, hello: &[u8], now: std::time::Instant) -> Box<PeerJoin> {
    let hello = JoinHello::parse(BS, hello).unwrap();
    let OpenedHello::Verified(join) = core.open_hello(&hello, &[], now) else {
        panic!("expected an authenticated Hello");
    };
    join
}

fn carrier(hello: &[u8]) -> PeerCarrier {
    PeerCarrier {
        setup: None,
        sources: zmux::CarrierHalfSources::default(),
        inbound: Some(BS),
        outbound: Some(BS),
        looped: false,
        overhead: 0,
        received: hello.len(),
    }
}

#[test]
fn next_batch_h_join_denial_leaves_epoch_and_id_untouched() {
    let mut pair = epoch_pair();
    pair.a.advance_epoch(pair.now).unwrap();
    pair.send(true);
    pair.send(false);
    assert_eq!(pair.a.epoch(), Some(1));
    assert_eq!(pair.b.epoch(), Some(0));

    let wire = hello(&mut pair.a, pair.now);
    let mut rejected = verified(&mut pair.b, &wire, pair.now);
    assert_eq!(rejected.epoch(), 1);
    assert_eq!(
        pair.b.epoch(),
        Some(0),
        "authentication cannot start retention"
    );
    assert!(rejected.read_confirm(&[]).is_err());
    assert_eq!(pair.b.pipe_ids(), [P0]);
    let mut next = pair.b.session_policy().clone();
    next.revision += 1;
    next.auth_generation += 1;
    pair.b.set_session_policy(next, pair.now).unwrap();
    assert!(matches!(
        pair.b.claim_hello(
            &mut rejected,
            &carrier(&wire),
            &UnitPlan::default(),
            pair.now
        ),
        ClaimedHello::AuthorizationChanged
    ));
    assert_eq!(pair.b.epoch(), Some(0));
    assert_eq!(pair.b.pending_peer_joins(), 0);

    // The same authenticated Hello can still be authorized. Its successful
    // key exchange starts retention at this commit, even before Confirm.
    let mut allowed = verified(&mut pair.b, &wire, pair.now);
    assert_eq!(rejected.pipe().id, allowed.pipe().id);
    assert!(matches!(
        pair.b.claim_hello(
            &mut allowed,
            &carrier(&wire),
            &UnitPlan::default(),
            pair.now
        ),
        ClaimedHello::Accept { .. }
    ));
    assert_eq!(pair.b.epoch(), Some(1));
    assert_eq!(pair.b.pipe_ids(), [P0]);
}

#[test]
fn authorization_changes_after_reply_keep_claimed_id_and_epoch() {
    use zmux::PipeId;
    use zmux::proto::session::{ConfirmedJoin, JoinStep};

    let mut pair = epoch_pair();
    pair.a.advance_epoch(pair.now).unwrap();
    pair.send(true);
    pair.send(false);
    assert_eq!(pair.a.epoch(), Some(1));
    assert_eq!(pair.b.epoch(), Some(0));

    let wire = hello(&mut pair.a, pair.now);
    let mut join = verified(&mut pair.b, &wire, pair.now);
    let id = PipeId::new(join.pipe().id);
    let carrier = carrier(&wire);
    let plan = UnitPlan::default();
    let ClaimedHello::Accept { reply, evicted } =
        pair.b.claim_hello(&mut join, &carrier, &plan, pair.now)
    else {
        panic!("expected a successful Reply");
    };
    assert_eq!(evicted, [] as [zmux::proto::listener::CarrierId; 0]);
    assert_eq!(pair.b.epoch(), Some(1));
    assert_eq!(pair.b.pending_peer_joins(), 1);
    assert!(matches!(
        pair.a.verify_reply(id, &reply, pair.now),
        JoinStep::Verified { .. }
    ));
    let confirm = pair.a.join_finish(id, &plan, pair.now).unwrap().confirm;
    assert!(join.read_confirm(&confirm).unwrap().is_some());

    let mut policy = pair.b.session_policy().clone();
    policy.revision += 1;
    policy.auth_generation += 1;
    pair.b.set_session_policy(policy, pair.now).unwrap();
    assert!(matches!(
        pair.b.confirm_join(*join, &carrier, pair.now),
        ConfirmedJoin::AuthorizationChanged
    ));
    assert_eq!(pair.b.pending_peer_joins(), 0);
    assert_eq!(pair.b.pipe_ids(), [P0]);
    assert_eq!(pair.b.epoch(), Some(1));

    let parsed = JoinHello::parse(BS, &wire).unwrap();
    assert!(matches!(
        pair.b.open_hello(&parsed, &[], pair.now),
        OpenedHello::Close
    ));
}

#[test]
fn strict_join_requires_a_registered_source_for_every_requested_half() {
    use std::sync::Arc;

    let mut pair = epoch_pair();
    let mut next = pair.b.session_policy().clone();
    next.revision += 1;
    next.join_source_routes = Some(Arc::new([Arc::from("registered")].into()));
    pair.b.set_session_policy(next, pair.now).unwrap();
    let wire = hello(&mut pair.a, pair.now);
    let mut carrier = carrier(&wire);
    let plan = UnitPlan::default();
    for receive_route in [None, Some("unknown")] {
        carrier.sources.send.route = Some(Arc::from("registered"));
        carrier.sources.receive.route = receive_route.map(Arc::from);
        let mut join = verified(&mut pair.b, &wire, pair.now);
        assert!(matches!(
            pair.b.claim_hello(&mut join, &carrier, &plan, pair.now),
            ClaimedHello::UnknownSource
        ));
        assert_eq!(pair.b.pending_peer_joins(), 0);
    }
    carrier.sources.receive.route = Some(Arc::from("registered"));
    let mut join = verified(&mut pair.b, &wire, pair.now);
    assert!(matches!(
        pair.b.claim_hello(&mut join, &carrier, &plan, pair.now),
        ClaimedHello::Accept { .. }
    ));
}

#[test]
fn next_batch_h_old_epoch_expires_during_authorization() {
    let mut pair = epoch_pair();
    let old_wire = hello(&mut pair.a, pair.now);
    let mut pending = verified(&mut pair.b, &old_wire, pair.now);

    pair.a.advance_epoch(pair.now).unwrap();
    pair.pump();
    // Another authorized join can start the responder's retention even
    // when the epoch answer has not yet been acknowledged.
    let new_wire = hello(&mut pair.a, pair.now);
    let mut new = verified(&mut pair.b, &new_wire, pair.now);
    assert!(matches!(
        pair.b.claim_hello(
            &mut new,
            &carrier(&new_wire),
            &UnitPlan::default(),
            pair.now
        ),
        ClaimedHello::Accept { .. }
    ));
    assert_eq!(pair.b.epoch(), Some(1));

    let expiry = pair.now + zmux::proto::session::EPOCH_RETENTION;
    assert!(matches!(
        pair.b.claim_hello(
            &mut pending,
            &carrier(&old_wire),
            &UnitPlan::default(),
            expiry
        ),
        ClaimedHello::Close
    ));
    assert_eq!(pair.b.pipe_ids(), [P0]);
}

#[test]
fn next_batch_e1_prefix_uses_the_actual_varint_width() {
    for (sequence, width) in [
        (0, 1),
        (63, 1),
        (64, 2),
        (16_383, 2),
        (16_384, 4),
        ((1 << 30) - 1, 4),
        (1 << 30, 8),
        ((1 << 62) - 1, 8),
    ] {
        let flow = Flow::Stream {
            stream_id: 64,
            context: 1 << 30,
        };
        let prefix = DatagramPrefix::Sequenced { sequence, flow };
        let mut data = [0; 28];
        let n = prefix.encode(&mut data).unwrap();
        assert_eq!(n, width + flow.encoded_len());
        data[n..n + 3].copy_from_slice(b"udp");
        let frame = Datagram {
            data: &data[..n + 3],
            explicit_len: false,
        };
        assert_eq!(frame.sequenced().unwrap(), (sequence, flow, &b"udp"[..]));
    }
}

fn datagram_record(sequence: u64, flow: Flow, payload: &[u8]) -> Vec<u8> {
    let mut prefix = [0; 24];
    let n = DatagramPrefix::Sequenced { sequence, flow }
        .encode(&mut prefix)
        .unwrap();
    let mut record = vec![u8::try_from(1 + n + payload.len()).unwrap(), 0x30];
    record.extend_from_slice(&prefix[..n]);
    record.extend_from_slice(payload);
    record
}

#[test]
fn next_batch_e1_duplicates_and_window_are_shared_by_records_and_native() {
    let mut config = config();
    config.datagram_config_mut().dedup_window = 64;
    config.enable_datagrams = true;
    let mut pair = CorePair::new(config.clone(), config);
    for to in [&mut pair.a, &mut pair.b] {
        assert!(to.features().same_family);
        for sequence in [0, 0, 64, 0, 63] {
            let datagram = datagram_record(sequence, Flow::Session, b"udp");
            assert_eq!(to.receive_in_place(P0, &datagram, pair.now), datagram.len());
            if sequence == 64 {
                to.receive_channel_datagram(P0, &datagram[1..], pair.now);
            }
        }
        for _ in 0..3 {
            assert_eq!(
                to.recv_datagram(pair.now).unwrap(),
                Some(Bytes::from_static(b"udp"))
            );
        }
        assert_eq!(to.recv_datagram(pair.now).unwrap(), None);
        assert_eq!(to.datagram_stats().duplicates_dropped, 2);
        assert_eq!(to.datagram_stats().stale_dropped, 1);
    }
}

#[tokio::test]
async fn next_batch_h_rust_driver_rechecks_revocation_and_reports_denial() {
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    tokio::time::timeout(Duration::from_secs(60), async {
        let config = Config::multipath(PipeAuth::psk([23; 32]).with_end_to_end());
        let listener =
            zmux::Listener::new(config.clone(), zmux::ListenerConfig::default()).unwrap();
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let acceptor = listener.clone();
        let bootstrap = tokio::spawn(async move {
            acceptor
                .handle_pipe(zmux::PipeIo::new(server_io), zmux::PipeHint::default())
                .await
        });
        let client = zmux::Session::connect(zmux::PipeIo::new(client_io), config)
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        bootstrap.await.unwrap().unwrap();
        client.established().await.unwrap();

        for revoked in [false, true] {
            let (entered, request) = oneshot::channel();
            let (complete, verdict) = oneshot::channel();
            let gate = Mutex::new(Some((entered, verdict)));
            server
                .set_session_policy(authorization_update(
                    server.session_policy(),
                    zmux::AuthorizeJoin::new_async(move |request| {
                        let (entered, verdict) = gate.lock().unwrap().take().unwrap();
                        entered.send(request).unwrap();
                        async move { verdict.await.unwrap() }
                    }),
                ))
                .unwrap();
            let (near, far) = tokio::io::duplex(1 << 16);
            let pipe = client
                .test_begin_join(zmux::PipeIo::new(near), PipeOptions::new())
                .unwrap();
            let acceptor = listener.clone();
            let mut send = zmux::CarrierHalfSource::new(zmux::CarrierKind::Streaming, None);
            send.route = Some("from-acceptor".into());
            let mut receive = zmux::CarrierHalfSource::new(zmux::CarrierKind::Split, None);
            receive.route = Some("to-acceptor".into());
            let sources = zmux::CarrierHalfSources { send, receive };
            let far = zmux::PipeIo::new(far).with_accounting_sources(sources.clone());
            let join =
                tokio::spawn(
                    async move { acceptor.handle_pipe(far, zmux::PipeHint::default()).await },
                );
            let request = request.await.unwrap();
            assert_eq!(request.pipe_id, pipe.id());
            assert_eq!(request.record_mode, RecordMode::Sealed);
            assert_eq!(request.session, server.id());
            assert_eq!(request.join_epoch, 0);
            assert_eq!(request.sources, sources);
            assert_eq!(request.first_batch, zmux::JoinFirstBatch::default());
            assert_eq!(
                request.auth_generation,
                server.session_policy().auth_generation
            );
            assert_eq!(server.pipes().len(), 1);
            let capacity = server.capacity();
            assert_eq!(capacity.authorizing_peer_joins, 1);
            assert_eq!(capacity.pending_peer_joins, 0);
            assert_eq!(capacity.local_carriers, 2);
            if revoked {
                server
                    .set_session_policy(authorization_update(
                        server.session_policy(),
                        zmux::AuthorizeJoin::new(|_| false),
                    ))
                    .unwrap();
            }
            complete.send(revoked).unwrap();
            assert!(join.await.unwrap().is_err());
            assert!(pipe.joined().await.is_err());
            assert_eq!(server.capacity().authorizing_peer_joins, 0);
            assert_eq!(server.epoch(), Some(0));
            assert_eq!(server.pipes().len(), 1);
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn next_batch_h_attempt_completes_once_at_confirmation_or_cancellation() {
    use std::sync::Mutex;
    use tokio::sync::oneshot;
    use zmux::{
        AttachmentSpec, AttemptReason, CarrierOpener, ChangeRequest, Directions, Listener,
        ListenerConfig, MemberSpec, PipeHint, PipeIo, Session,
    };

    fn secure(io: tokio::io::DuplexStream) -> PipeIo {
        PipeIo::new(io)
            .with_secure_first_pipe(RecordMode::Sealed)
            .with_exporter(|_, _, out| {
                out.fill(24);
                true
            })
    }

    tokio::time::timeout(Duration::from_hours(1), async {
        for cancel in [false, true] {
            let mut config = Config::multipath(PipeAuth::none().with_end_to_end());
            config.epoch_policy = EpochPolicy::MANUAL;
            let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();

            let (local, remote) = tokio::io::duplex(1 << 16);
            let acceptor = listener.clone();
            tokio::spawn(async move {
                acceptor
                    .handle_pipe(secure(remote), PipeHint::default())
                    .await
            });
            let client = Session::connect(secure(local), config).await.unwrap();
            let server = listener.accept().await.unwrap();
            client.advance_epoch().unwrap();
            loop {
                let snapshot = client.capacity();
                if client.epoch().unwrap() > 0 {
                    break;
                }
                client.capacity_changed(snapshot.observed).await;
            }

            let (entered, request) = oneshot::channel();
            let (allow, verdict) = oneshot::channel();
            let gate = Mutex::new(Some((entered, verdict)));
            server
                .set_session_policy(authorization_update(
                    server.session_policy(),
                    zmux::AuthorizeJoin::new_async(move |request| {
                        let next = gate.lock().unwrap().take();
                        async move {
                            if let Some((entered, verdict)) = next {
                                entered.send(request).unwrap();
                                verdict.await.unwrap_or(false)
                            } else {
                                false
                            }
                        }
                    }),
                ))
                .unwrap();
            let mut change = ChangeRequest::new(client.capacity(), Duration::from_secs(60));
            change.min_epoch = 1;
            change.add.push(MemberSpec {
                candidate: None,
                attachments: vec![AttachmentSpec::new(
                    Directions::BOTH,
                    PipeOptions::default(),
                )],
            });
            let change = client.begin_change(change).unwrap();
            let opener = CarrierOpener::new(move |_| {
                let acceptor = listener.clone();
                async move {
                    let (local, remote) = tokio::io::duplex(1 << 16);
                    tokio::spawn(async move {
                        acceptor
                            .handle_pipe(PipeIo::new(remote), PipeHint::default())
                            .await
                    });
                    Ok::<_, std::io::Error>(vec![PipeIo::new(local)])
                }
            });
            let attempt = change.start_member(0, opener).unwrap();
            let join = request.await.unwrap();
            assert_eq!(join.join_epoch, 1);
            assert!(attempt.snapshot().result.is_none());
            if cancel {
                attempt.cancel();
                let result = attempt.wait().await;
                assert_eq!(result.reason, AttemptReason::Cancelled);
                assert_eq!(result.pipes, [join.pipe_id]);
                drop(allow);
            } else {
                allow.send(true).unwrap();
                let result = attempt.wait().await;
                assert_eq!(result.reason, AttemptReason::Confirmed);
                assert_eq!(result.pipes, [join.pipe_id]);
                change.commit().unwrap();
            }
            assert_eq!(attempt.wait().await.id, attempt.snapshot().id);
        }
    })
    .await
    .unwrap();
}

#[test]
fn next_batch_e1_family_gate_rejects_legacy_evidence_and_retired_parameter() {
    use zmux::proto::params::{TransportParameters, id};
    use zmux::proto::varint;

    let params = TransportParameters {
        zmux_goaway: true,
        ..Default::default()
    };
    let mut block = [0; 32];
    let n = params.encode(None, &mut block).unwrap();
    assert!(TransportParameters::decode(&block[..n]).is_err());
    let n = varint::encode(id::RETIRED_ZMUX_DATAGRAM_FLOWS, &mut block).unwrap();
    block[n] = 0;
    assert!(TransportParameters::decode(&block[..=n]).is_err());
    assert!(TransportParameters::decode(&[]).unwrap().is_plain_qmux());

    let same = TransportParameters {
        zmux_datagram_family: true,
        ..params
    };
    let n = same.encode(None, &mut block).unwrap();
    assert_eq!(TransportParameters::decode(&block[..n]).unwrap(), same);
}

#[cfg(feature = "test-hooks")]
#[test]
fn next_batch_e1_expired_hold_releases_the_sequence() {
    use zmux::proto::frame::Dir;

    let mut config = Config::default();
    config.enable_datagrams = true;
    #[cfg(feature = "test-hooks")]
    {
        config.test_hooks().no_first_ping = true;
        config.test_hooks().rtt = Some(Duration::from_millis(20));
    }
    let mut pair = CorePair::attached(config.clone(), config);
    for core in [&mut pair.a, &mut pair.b] {
        core.set_pipe_channel(P0, None, 1200, 1200);
    }
    pair.pump();
    let held = datagram_record(
        18,
        Flow::Stream {
            stream_id: 0,
            context: 7,
        },
        b"held",
    );
    pair.b.receive_channel_datagram(P0, &held[1..], pair.now);
    pair.b.receive_channel_datagram(P0, &held[1..], pair.now);
    assert_eq!(pair.b.datagram_stats().duplicates_dropped, 1);

    // Advance well past the measured RTT. The peer stays within its idle
    // budget and only time on the injected clock moves.
    pair.now += Duration::from_secs(1);
    pair.b.handle_timeout(pair.now);
    let stream = pair.a.open(Dir::Bidi).unwrap();
    pair.a.write(stream, b"open").unwrap();
    pair.pump();
    let remote = pair.b.accept(Dir::Bidi).unwrap().unwrap();
    let late = datagram_record(
        18,
        Flow::Stream {
            stream_id: 0,
            context: 7,
        },
        b"retry",
    );
    pair.b.receive_channel_datagram(P0, &late[1..], pair.now);
    assert_eq!(
        pair.b.recv_stream_datagram(remote, pair.now).unwrap(),
        Some((7, Bytes::from_static(b"retry")))
    );
}

#[test]
fn next_batch_e2_equal_urgency_rotates_between_flow_heads() {
    use zmux::proto::frame::{Dir, Frame, Gates};
    use zmux::proto::record::{Event, RecordReader};

    let mut config = Config::default();
    config.enable_datagrams = true;
    let mut pair = CorePair::new(config.clone(), config);
    let a = pair.a.open(Dir::Bidi).unwrap();
    let b = pair.a.open(Dir::Bidi).unwrap();
    pair.a.write(a, b"open a").unwrap();
    pair.a.write(b, b"open b").unwrap();
    let bulk = pair.a.open(Dir::Bidi).unwrap();
    let short = pair.a.open(Dir::Bidi).unwrap();
    pair.a.write(bulk, b"open bulk").unwrap();
    pair.a.write(short, b"open short").unwrap();
    pair.pump();
    let bulk_id = pair.a.peek_stream_id(bulk).unwrap();
    let short_id = pair.a.peek_stream_id(short).unwrap();
    let backlog = vec![0; 32 * 1024];
    assert_eq!(pair.a.write(bulk, &backlog).unwrap(), backlog.len());
    pair.a.write(short, b"x").unwrap();
    for flow in [a, a, b, b] {
        pair.a
            .send_stream_datagram(flow, 0, Bytes::from_static(b"payload"), true, pair.now)
            .unwrap();
    }
    let mut observed = Vec::new();
    let mut reader = RecordReader::new(65_535);
    pair.send_with(true, |mut input| {
        while let Some(event) = reader.read(&mut input, &Gates::ALL).unwrap() {
            match event {
                Event::Frame(Frame::Datagram(frame)) => {
                    let Flow::Stream { stream_id, .. } = frame.sequenced().unwrap().1 else {
                        panic!("expected a stream datagram");
                    };
                    observed.push(stream_id);
                }
                Event::Frame(Frame::Stream(frame)) if observed.last() != Some(&frame.stream_id) => {
                    observed.push(frame.stream_id);
                }
                _ => {}
            }
        }
    });
    // Reliable directions and each Flow take turns in the same urgency.
    assert_eq!(&observed[..4], [bulk_id, short_id, 0, 4]);
    assert_eq!(
        observed
            .into_iter()
            .filter(|&id| id == 0 || id == 4)
            .collect::<Vec<_>>(),
        [0, 4, 0, 4],
    );
}

#[test]
fn next_batch_e2_priority_is_shared_by_reliable_and_datagram_data() {
    use zmux::proto::frame::{Dir, Frame, Gates, Priority};
    use zmux::proto::record::{Event, RecordReader};

    let mut config = Config::default();
    config.enable_datagrams = true;
    let mut pair = CorePair::new(config.clone(), config);
    let stream = pair.a.open(Dir::Bidi).unwrap();
    pair.a.write(stream, b"open").unwrap();
    pair.pump();
    for (urgency, datagram_first) in [(0, false), (7, true)] {
        pair.a
            .set_priority(stream, Priority::new(urgency, true).unwrap())
            .unwrap();
        // Queue the later winner last, so urgency must outrank arrival.
        let (send, datagram) = (
            |pair: &mut CorePair| {
                pair.a.write(stream, b"x").unwrap();
            },
            |pair: &mut CorePair| {
                pair.a
                    .send_datagram(Bytes::from_static(b"udp"), true, pair.now)
                    .unwrap();
            },
        );
        if datagram_first {
            send(&mut pair);
            datagram(&mut pair);
        } else {
            datagram(&mut pair);
            send(&mut pair);
        }
        let mut seen = Vec::new();
        let mut reader = RecordReader::new(65_535);
        pair.send_with(true, |mut input| {
            while let Some(event) = reader.read(&mut input, &Gates::ALL).unwrap() {
                match event {
                    Event::Frame(Frame::Datagram(_)) => seen.push(true),
                    Event::Frame(Frame::Stream(_)) => seen.push(false),
                    _ => {}
                }
            }
        });
        assert_eq!(seen, [datagram_first, !datagram_first]);
    }
}

#[test]
fn next_batch_e3_copies_keep_sequence_and_obey_budget_and_fate() {
    use std::num::{NonZeroU8, NonZeroU64};
    use zmux::{Change, DatagramCopyPolicy, DatagramSendOptions, PipeId};

    let mut cfg =
        Config::multipath(PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end());
    cfg.enable_datagrams = true;
    cfg.probation = None;
    cfg.epoch_policy = EpochPolicy::MANUAL;
    cfg.datagram_config_mut().replica_percent = 50;
    let mut net = mp_net::MpNet::<(), ()>::new(cfg.clone(), cfg, ());
    net.ends[mp_net::A].set_locator(b"a").unwrap();
    net.ends[mp_net::B].set_locator(b"b").unwrap();
    net.step(usize::MAX);
    let mut options = PipeOptions::new();
    options.send_priority = Change::Set(3);
    let alternate = net.add_pipe(&options).unwrap();
    net.strict_joins = true;
    for _ in 0..16 {
        net.step(usize::MAX);
    }
    assert!(net.links[&alternate].attached());

    let copy = DatagramSendOptions {
        copies: Some(DatagramCopyPolicy::Duplicate(NonZeroU8::new(2).unwrap())),
        independent_fate: Some(true),
        ..Default::default()
    };
    let main = PipeId::new(0);
    let alternate = PipeId::new(alternate);
    let send = |core: &mut SessionCore, now, payload: &'static [u8], options| {
        core.send_datagram_with(Bytes::from_static(payload), options, true, now)
            .unwrap();
    };

    // Unknown or shared fate gives no permission to duplicate.
    send(
        &mut net.ends[mp_net::A],
        net.now,
        b"baseline",
        DatagramSendOptions::default(),
    );
    send(&mut net.ends[mp_net::A], net.now, b"unknown!", copy);
    net.step(usize::MAX);
    let stats = net.ends[mp_net::A].datagram_stats();
    assert_eq!(stats.replica_degradation.fate, 1);
    assert_eq!(stats.drops, zmux::DatagramDrops::default());
    for (pipe, domain) in [(main, 1), (alternate, 2)] {
        net.ends[mp_net::A]
            .set_pipe_replica_domain(pipe, NonZeroU64::new(domain))
            .unwrap();
    }
    send(&mut net.ends[mp_net::A], net.now, b"copied16 bytes!!", copy);
    net.step(usize::MAX);
    let stats = net.ends[mp_net::A].datagram_stats();
    assert_eq!(stats.record.replica_bytes, 16);
    assert_eq!(stats.record.replicas, 1);
    assert_eq!(stats.record.replicas_accepted, 1);
    assert_eq!(net.ends[mp_net::B].datagram_stats().duplicates_dropped, 1);
    assert_eq!(
        net.ends[mp_net::B]
            .recv_datagram(net.now)
            .unwrap()
            .unwrap()
            .as_ref(),
        b"baseline"
    );
    assert_eq!(
        net.ends[mp_net::B]
            .recv_datagram(net.now)
            .unwrap()
            .unwrap()
            .as_ref(),
        b"unknown!"
    );
    assert_eq!(
        net.ends[mp_net::B]
            .recv_datagram(net.now)
            .unwrap()
            .unwrap()
            .as_ref(),
        b"copied16 bytes!!"
    );
    assert!(
        net.ends[mp_net::B]
            .recv_datagram(net.now)
            .unwrap()
            .is_none()
    );

    // The negotiated burst still permits a second small replica.
    send(&mut net.ends[mp_net::A], net.now, b"ordinary", copy);
    net.step(usize::MAX);
    let stats = net.ends[mp_net::A].datagram_stats();
    assert_eq!(stats.record.replicas, 2);
    assert_eq!(stats.replica_degradation.budget, 0);
}

#[test]
fn next_batch_e3_adaptive_needs_attributed_evidence_or_urgency_and_independence() {
    use std::num::NonZeroU64;
    use zmux::{
        DatagramChannelKind, DatagramCopyPolicy, DatagramLossSample, DatagramSendOptions, PipeId,
    };

    for rate in [0, 20] {
        let mut cfg = Config::multipath(
            PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end(),
        );
        cfg.enable_datagrams = true;
        cfg.probation = None;
        cfg.epoch_policy = EpochPolicy::MANUAL;
        cfg.datagram_config_mut().replica_percent = rate;
        cfg.datagram_config_mut().priority = zmux::Priority::new(0, true).unwrap();
        let mut net = mp_net::MpNet::<(), ()>::new(cfg.clone(), cfg, ());
        net.ends[mp_net::A].set_locator(b"a").unwrap();
        net.ends[mp_net::B].set_locator(b"b").unwrap();
        net.step(usize::MAX);
        let mut options = PipeOptions::new();
        options.send_priority = zmux::Change::Set(3);
        let alternate = net.add_pipe(&options).unwrap();
        net.strict_joins = true;
        for _ in 0..16 {
            net.step(usize::MAX);
        }
        assert!(net.links[&alternate].attached());
        let alternate = PipeId::new(alternate);
        let send = |net: &mut mp_net::MpNet<(), ()>, urgent| {
            net.ends[mp_net::A]
                .send_datagram_with(
                    Bytes::new(),
                    DatagramSendOptions {
                        copies: Some(DatagramCopyPolicy::Adaptive),
                        urgent,
                        independent_fate: Some(false),
                        ..Default::default()
                    },
                    true,
                    net.now,
                )
                .unwrap();
            net.step(usize::MAX);
            net.ends[mp_net::A].datagram_stats().record.replicas
        };
        assert_eq!(send(&mut net, Some(true)), 0);
        let core = &mut net.ends[mp_net::A];
        core.set_pipe_replica_domain(P0, NonZeroU64::new(1))
            .unwrap();
        core.set_pipe_replica_domain(alternate, NonZeroU64::new(2))
            .unwrap();
        assert_eq!(send(&mut net, None), 0);
        let expected = u64::from(rate != 0);
        assert_eq!(send(&mut net, Some(true)), expected);
        assert_eq!(send(&mut net, Some(false)), expected, "Urgent cannot latch");
        for (pipe, lost) in [(P0, 5), (alternate, 2)] {
            assert!(
                net.ends[mp_net::A]
                    .report_datagram_loss(
                        pipe,
                        DatagramChannelKind::Record,
                        DatagramLossSample {
                            observed_at: net.now,
                            source_generation: 1,
                            finalized: 100,
                            lost
                        },
                        net.now,
                    )
                    .unwrap()
            );
        }
        assert_eq!(send(&mut net, Some(false)), 2 * expected);
        assert_eq!(net.ends[mp_net::A].datagram_stats().record.replica_bytes, 0);
        assert_eq!(
            net.ends[mp_net::A]
                .datagram_stats()
                .replica_degradation
                .budget,
            if rate == 0 { 5 } else { 0 }
        );

        if rate != 0 {
            // datagram.md clears the latch when an evaluation has no usable alternative.
            // An unwritable native route excludes the only alternative without changing its identity.
            let originals = net.ends[mp_net::A].datagram_stats().record.originals;
            net.advance(1);
            net.ends[mp_net::A].set_pipe_channel(alternate, None, 1200, 0);
            assert_eq!(send(&mut net, Some(false)), 2);
            assert_eq!(
                net.ends[mp_net::A].datagram_stats().record.originals,
                originals + 1
            );
            net.ends[mp_net::A].set_pipe_channel(alternate, None, 0, 0);
            assert!(
                net.ends[mp_net::A]
                    .report_datagram_loss(
                        P0,
                        DatagramChannelKind::Record,
                        DatagramLossSample {
                            observed_at: net.now,
                            source_generation: 1,
                            finalized: 100,
                            lost: 3,
                        },
                        net.now,
                    )
                    .unwrap()
            );
            assert_eq!(
                send(&mut net, Some(false)),
                2,
                "recovery requires the entry threshold again"
            );
            assert_eq!(
                net.ends[mp_net::A].datagram_stats().record.originals,
                originals + 2
            );
        }
    }
}

#[test]
fn next_batch_e4_deadline_expires_without_writes_and_never_renews() {
    use zmux::{DatagramDeadline, DatagramSendOptions};

    let mut config = Config::default();
    config.enable_datagrams = true;
    let mut pair = CorePair::new(config.clone(), config);
    let start = pair.now;
    let ttl = Duration::from_millis(100);
    pair.a
        .send_datagram_with(
            Bytes::from_static(b"stale"),
            DatagramSendOptions {
                deadline: Some(DatagramDeadline::After(ttl)),
                ..Default::default()
            },
            true,
            start,
        )
        .unwrap();
    pair.a.handle_timeout(start + ttl);
    assert_eq!(pair.a.datagram_stats().drops.deadline, 1);

    pair.now = start + ttl;
    pair.a
        .send_datagram(Bytes::from_static(b"kept"), true, pair.now)
        .unwrap();
    pair.pump();
    assert_eq!(
        pair.b.recv_datagram(pair.now).unwrap(),
        Some(Bytes::from_static(b"kept"))
    );
    assert_eq!(pair.b.recv_datagram(pair.now).unwrap(), None);
}

#[test]
fn invalid_and_immediate_datagram_deadlines_leave_the_stream_unopened() {
    use zmux::proto::frame::Dir;
    use zmux::{DatagramDeadline, DatagramDrop, DatagramError, DatagramSendOptions};

    let mut config = Config::default();
    config.enable_datagrams = true;
    let mut pair = CorePair::new(config.clone(), config);
    let stream = pair.a.open(Dir::Bidi).unwrap();
    for (ttl, invalid) in [(Duration::MAX, true), (Duration::ZERO, false)] {
        let options = DatagramSendOptions {
            deadline: Some(DatagramDeadline::After(ttl)),
            ..DatagramSendOptions::default()
        };
        let result =
            pair.a
                .send_stream_datagram_with(stream, 0, Bytes::new(), options, true, pair.now);
        if invalid {
            assert!(matches!(result, Err(DatagramError::InvalidOptions(_))));
        } else {
            assert_eq!(result, Err(DatagramError::Dropped(DatagramDrop::Deadline)));
        }
        assert_eq!(pair.a.peek_stream_id(stream), None);
        assert_eq!(zmux::test_hooks::datagram_send_state(&pair.a), (0, 0));
    }
}

#[test]
fn native_path_can_carry_exactly_one_empty_payload() {
    use zmux::proto::frame::channel;
    use zmux::proto::session::NativeDatagramResult;
    use zmux::{DatagramCarrier, DatagramSendOptions};

    let mut config = Config::default();
    config.enable_datagrams = true;
    let mut pair = CorePair::attached(config.clone(), config);
    let route = channel::Prefix::Carrier(64);
    let prefix = DatagramPrefix::Sequenced {
        sequence: 0,
        flow: Flow::Session,
    };
    let boundary = channel::datagram_len(route.id(), prefix.encoded_len());
    for core in [&mut pair.a, &mut pair.b] {
        core.set_pipe_channel(P0, route, boundary - 1, boundary - 1);
    }
    pair.pump();
    assert_eq!(pair.a.datagram_path().native_payload, None);

    pair.a.set_pipe_channel(P0, route, boundary, boundary);
    let path = pair.a.datagram_path();
    assert_eq!(path.native_payload, Some(0));
    assert_eq!(path.native_room, Some(0));
    pair.a
        .send_datagram_with(
            Bytes::new(),
            DatagramSendOptions {
                carrier: Some(DatagramCarrier::RequireNative),
                ..DatagramSendOptions::default()
            },
            true,
            pair.now,
        )
        .unwrap();
    let mut native = Vec::new();
    assert!(pair.a.poll_channel(P0, &mut native, pair.now));
    let [packet] = <[_; 1]>::try_from(native).unwrap();
    assert_eq!(packet.bytes.len(), boundary);
    pair.b
        .receive_channel_datagram(P0, &packet.bytes[route.outer_bytes()..], pair.now);
    pair.a
        .channel_done(P0, packet.outcome, NativeDatagramResult::Accepted, pair.now);
    assert_eq!(pair.b.recv_datagram(pair.now).unwrap(), Some(Bytes::new()));
    assert_eq!(pair.a.datagram_stats().native.originals_accepted, 1);
    assert_eq!(pair.a.datagram_stats().record.originals_accepted, 0);
}

#[test]
fn next_batch_e5_reports_arrival_once_and_does_not_elicit_ack() {
    use zmux::proto::frame::{DatagramAck, DatagramChannelKind, Frame, Gates};

    let mut config = Config::default();
    config.enable_datagrams = true;
    let mut pair = CorePair::new(config.clone(), config);
    pair.a
        .send_datagram(Bytes::from_static(b"payload"), true, pair.now)
        .unwrap();
    let sent_at = pair.now;
    pair.a.poll_transmit(P0, sent_at, &mut pair.out);
    let len = pair.out.stream_len();
    pair.wire.clear();
    pair.out.copy_to_vec(&mut pair.wire);
    pair.a
        .transmit_progress(P0.into(), &mut pair.out, len, true, sent_at);
    pair.a.pipe_written(P0, len, sent_at);
    pair.now += Duration::from_millis(5);
    assert_eq!(
        pair.b.receive_in_place(P0, &pair.wire, pair.now),
        pair.wire.len()
    );
    let evidence = |pair: &CorePair| {
        pair.a
            .datagram_feedback(P0, DatagramChannelKind::Record)
            .unwrap()
    };
    let awaiting = evidence(&pair);
    assert_eq!(
        (awaiting.tracking, awaiting.awaiting, awaiting.arrived),
        (1, 1, 0)
    );
    assert_eq!(awaiting.sample_source, None);
    pair.pump();
    let quality = pair
        .a
        .datagram_feedback(P0, DatagramChannelKind::Record)
        .unwrap();
    assert_eq!(
        (quality.awaiting, quality.arrived, quality.samples),
        (0, 1, 1)
    );
    assert_eq!(quality.sampled_at, Some(pair.now));
    assert_eq!(quality.sample_age, Some(Duration::ZERO));
    assert_eq!(
        quality.sample_source,
        Some(zmux::DatagramEvidenceSource::DatagramAck)
    );

    let highest = (1 << 62) - 1;
    let ack = DatagramAck::new(0, DatagramChannelKind::Record, 0, highest, highest, &[]).unwrap();
    let frame = Frame::DatagramAck(ack);
    assert!(!frame.is_ack_eliciting());
    let mut bytes = vec![0; 1 + frame.encoded_len()];
    bytes[0] = u8::try_from(frame.encoded_len()).unwrap();
    frame.encode(&mut bytes[1..]).unwrap();
    assert!(Frame::decode(&bytes[1..], &Gates::NONE).is_err());
    pair.a.receive_in_place(P0, &bytes, pair.now);
    assert_eq!(
        pair.a.datagram_feedback(P0, DatagramChannelKind::Record),
        Some(quality)
    );
    pair.now = sent_at + Duration::from_secs(10);
    pair.a.handle_timeout(pair.now);
    let expired = evidence(&pair);
    assert_eq!(
        (
            expired.tracking,
            expired.awaiting,
            expired.arrived,
            expired.expired
        ),
        (1, 0, 0, 1)
    );
    pair.now += Duration::from_millis(5);
    pair.a.handle_timeout(pair.now);
    assert_eq!(evidence(&pair).samples, 0);
    assert_eq!(evidence(&pair).report_rtt, None);
}

#[cfg(all(unix, feature = "blocking"))]
#[test]
fn next_batch_h_blocking_driver_rejects_a_superseded_policy() {
    use std::os::unix::net::UnixStream;
    use std::sync::{Mutex, mpsc};
    use zmux::blocking;

    fn pipe(io: UnixStream) -> blocking::PipeIo {
        let closer = io.try_clone().unwrap();
        blocking::PipeIo::from_halves(io.try_clone().unwrap(), io).with_closer(move |how| {
            let _ = closer.shutdown(how);
        })
    }

    let config = Config::multipath(PipeAuth::psk([37; 32]).with_end_to_end());
    let listener =
        blocking::Listener::new(config.clone(), zmux::ListenerConfig::default(), None).unwrap();
    let (near, far) = UnixStream::pair().unwrap();
    let acceptor = listener.clone();
    let bootstrap =
        std::thread::spawn(move || acceptor.handle_pipe(pipe(far), blocking::PipeHint::default()));
    let client = blocking::Session::connect(pipe(near), config).unwrap();
    let server = listener.accept().unwrap();
    bootstrap.join().unwrap().unwrap();

    let (entered, request) = mpsc::channel();
    let (complete, verdict) = mpsc::channel();
    let gate = Mutex::new(verdict);
    server
        .set_session_policy(authorization_update(
            server.session_policy(),
            zmux::AuthorizeJoin::new(move |join| {
                entered.send(join).unwrap();
                gate.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(60))
                    .unwrap()
            }),
        ))
        .unwrap();

    let (near, far) = UnixStream::pair().unwrap();
    let joiner =
        std::thread::spawn(move || client.test_join(pipe(near), PipeOptions::new()).map(|_| ()));
    let acceptor = listener.clone();
    let accepting =
        std::thread::spawn(move || acceptor.handle_pipe(pipe(far), blocking::PipeHint::default()));
    assert_eq!(
        request
            .recv_timeout(Duration::from_secs(60))
            .unwrap()
            .record_mode,
        RecordMode::Sealed
    );
    server
        .set_session_policy(authorization_update(
            server.session_policy(),
            zmux::AuthorizeJoin::new(|_| false),
        ))
        .unwrap();
    complete.send(true).unwrap();
    assert!(accepting.join().unwrap().is_err());
    assert!(joiner.join().unwrap().is_err());
    assert_eq!(server.epoch(), Some(0));
    assert_eq!(server.pipes().len(), 1);
}

#[test]
fn next_batch_f_an_idle_writer_still_arms_the_datagram_deadline() {
    use zmux::{DatagramCarrier, DatagramDeadline, DatagramSendOptions};

    let mut config = Config::default();
    config.enable_datagrams = true;
    let mut pair = CorePair::attached(config.clone(), config);
    // The carrier temporarily has no native capacity.
    for core in [&mut pair.a, &mut pair.b] {
        core.set_pipe_channel(P0, None, 0, 0);
    }
    pair.pump();
    let deadline = pair.now + Duration::from_millis(1);
    pair.a
        .send_datagram_with(
            Bytes::from_static(b"wait for native"),
            DatagramSendOptions {
                deadline: Some(DatagramDeadline::At(deadline)),
                carrier: Some(DatagramCarrier::RequireNative),
                ..Default::default()
            },
            true,
            pair.now,
        )
        .unwrap();
    assert!(!pair.a.wants_write(P0));
    assert_eq!(pair.a.poll_timeout(), Some(deadline));
    pair.a.handle_timeout(deadline);
    assert_eq!(pair.a.datagram_stats().drops.deadline, 1);
    assert!(!pair.a.wants_write(P0));
}

#[test]
fn next_batch_f_retirement_waits_for_carrier_write_shutdown() {
    use zmux::proto::session::{DirectionState, OutboundState};
    use zmux::{PipeHalf, PipeId};

    let mut cfg =
        Config::multipath(PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end());
    cfg.probation = None;
    let mut net = mp_net::MpNet::<(), ()>::new(cfg.clone(), cfg, ());
    net.ends[mp_net::A].set_locator(b"a").unwrap();
    net.ends[mp_net::B].set_locator(b"b").unwrap();
    net.step(usize::MAX);
    let id = net.add_pipe(&PipeOptions::new()).unwrap();
    for _ in 0..16 {
        net.step(usize::MAX);
    }
    assert!(net.links[&id].attached());
    net.links.get_mut(&id).unwrap().flows[mp_net::A].hold_shutdown = true;
    let pipe = PipeId::new(id);
    let core = &mut net.ends[mp_net::A];
    assert!(matches!(
        core.drain_attachments(&[P0, pipe], net.now, |_| Ok(())),
        Err(zmux::PipeError::NoDirectionCoverage)
    ));
    assert!(!core.pipe_health(P0).unwrap().ending());
    assert!(!core.pipe_health(pipe).unwrap().ending());
    net.ends[mp_net::A]
        .remove_pipe(pipe, true, net.now)
        .unwrap();
    for _ in 0..16 {
        net.step(usize::MAX);
        net.advance(25);
    }
    assert_eq!(
        net.ends[mp_net::A].pipe_state(pipe, PipeHalf::Outbound),
        Some(DirectionState::Outbound(OutboundState::Closed)),
    );
    assert!(net.links[&id].flows[mp_net::A].shutdown_pending);
    assert!(!net.ends[mp_net::A].pipe_retired(pipe));
    assert!(net.ends[mp_net::A].pipe_closed(pipe).is_none());
    assert!(!net.links[&id].flows[mp_net::A].writer_closed);

    net.links.get_mut(&id).unwrap().flows[mp_net::A].hold_shutdown = false;
    net.step(usize::MAX);
    assert!(net.links[&id].flows[mp_net::A].fin);
    assert!(net.ends[mp_net::A].pipe_retired(pipe));
    assert!(matches!(
        net.ends[mp_net::B].pipe_closed(pipe),
        Some(Ok(()))
    ));
}

#[cfg(feature = "test-hooks")]
#[test]
fn bound_setup_waits_for_redundant_reliable_ack() {
    use mp_net::{A, B, MpNet};
    use zmux::proto::frame::channel;
    use zmux::test_hooks::core_reliable_setup_end;

    let mut config =
        Config::multipath(PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end());
    config.enable_datagrams = true;
    config.probation = None;
    config.epoch_policy = EpochPolicy::MANUAL;
    config.liveness.probe_interval = None;
    config.liveness.keep_alive_period = None;
    config.liveness.standby_probe = None;
    config.test_hooks().unpaced = true;
    let mut net = MpNet::<(), ()>::new(config.clone(), config, ());
    net.ends[A].set_locator(b"setup-a").unwrap();
    net.ends[B].set_locator(b"setup-b").unwrap();
    for core in &mut net.ends {
        core.set_pipe_channel(P0, channel::Prefix::None, 1200, 1200);
    }
    net.step(usize::MAX);
    let alternate = zmux::PipeId::new(net.add_pipe(&PipeOptions::new()).unwrap());
    let pipes = [P0, alternate];
    for _ in 0..16 {
        net.step(usize::MAX);
        net.advance(25);
    }
    let cut = core_reliable_setup_end(&net.ends[B], &pipes).expect("established setup drained");

    for core in &mut net.ends {
        let key = core.open(zmux::Dir::Bidi).unwrap();
        assert_eq!(core.write(key, b"setup").unwrap(), 5);
        core.flush(key).unwrap();
    }
    net.step(usize::MAX);
    net.advance(zmux::proto::params::DEFAULT_MAX_ACK_DELAY_MS);
    net.step(usize::MAX);

    let sent = |net: &MpNet<(), ()>, pipe| net.ends[B].pipe_info(pipe).unwrap().bytes_sent;
    let after_primary = [sent(&net, P0), sent(&net, alternate)];
    assert!(
        after_primary
            .iter()
            .zip(&cut)
            .any(|(&position, &old)| position > old)
    );
    assert_eq!(
        core_reliable_setup_end(&net.ends[B], &pipes),
        None,
        "the primary ACK alone cannot close setup while the backup ACK is due"
    );

    // Both primary ACKs were emitted before either crossed the carrier.
    // The next redundant snapshot therefore covers a trailing reliable
    // ACK-only record on the other endpoint, even with no native traffic.
    let acknowledged = |net: &MpNet<(), ()>| {
        pipes.map(|pipe| net.ends[A].pipe_info(pipe).unwrap().bytes_acked.unwrap())
    };
    let premature = acknowledged(&net);
    net.advance(50);
    net.step(usize::MAX);
    let including_copy = core_reliable_setup_end(&net.ends[B], &pipes).expect("backup ACK sent");
    assert!(
        including_copy
            .iter()
            .zip(&after_primary)
            .any(|(&position, &old)| position > old)
    );
    let settled = acknowledged(&net);
    assert!(
        settled
            .iter()
            .zip(&premature)
            .any(|(after, before)| after > before),
        "the late reliable ACK must change the prematurely sampled cut"
    );

    let reliable_rx = net.ends[B].pipe_info(P0).unwrap().bytes_received;
    let native = datagram_record(0, Flow::Session, b"native");
    net.ends[B].receive_channel_datagram(P0, &native[1..], net.now);
    assert_eq!(
        net.ends[B].recv_datagram(net.now).unwrap(),
        Some(Bytes::from_static(b"native")),
    );
    assert_eq!(
        net.ends[B].pipe_info(P0).unwrap().bytes_received,
        reliable_rx
    );
    assert_eq!(acknowledged(&net), settled);
}

#[test]
fn g4_a_native_replica_keeps_its_copy_queue_charge_until_completion() {
    use std::num::NonZeroU8;
    use zmux::proto::session::NativeDatagramResult;
    use zmux::{Change, DatagramCopyPolicy, DatagramSendOptions, PipeId};

    for (packet_limit, byte_limit) in [(1, 512), (64, 8)] {
        let mut cfg = Config::multipath(
            PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end(),
        );
        cfg.enable_datagrams = true;
        cfg.probation = None;
        cfg.epoch_policy = EpochPolicy::MANUAL;
        cfg.datagram_send_queue = packet_limit;
        cfg.datagram_config_mut().send_bytes = byte_limit;

        let mut net = mp_net::MpNet::<(), ()>::new(cfg.clone(), cfg, ());
        for (end, locator) in [(mp_net::A, b"a"), (mp_net::B, b"b")] {
            net.ends[end].set_locator(locator).unwrap();
        }
        net.step(usize::MAX);
        let mut options = PipeOptions::new();
        options.send_priority = Change::Set(3);
        let alternate = net.add_pipe(&options).unwrap();
        net.strict_joins = true;
        for _ in 0..16 {
            net.step(usize::MAX);
        }
        assert!(net.links[&alternate].attached());
        let alternate = PipeId::new(alternate);
        let core = &mut net.ends[mp_net::A];
        for pipe in [P0, alternate] {
            core.set_pipe_channel(pipe, None, 1200, 1200);
        }

        let mut originals = Vec::new();
        let mut replicas = Vec::new();
        let options = DatagramSendOptions {
            copies: Some(DatagramCopyPolicy::Duplicate(NonZeroU8::new(2).unwrap())),
            ..Default::default()
        };
        for attempt in 1..=3 {
            core.send_datagram_with(Bytes::from_static(b"four"), options, true, net.now)
                .unwrap();
            assert!(core.poll_channel(P0, &mut originals, net.now));
            assert_eq!(originals.len(), 1);
            let original = originals.pop().unwrap().outcome;
            core.channel_done(P0, original, NativeDatagramResult::Accepted, net.now);
            assert!(core.poll_channel(alternate, &mut replicas, net.now));
            assert_eq!(replicas.len(), 1);
            if attempt == 2 {
                assert_eq!(core.datagram_stats().native.replicas, 1);
                assert_eq!(core.datagram_stats().replica_degradation.budget, 1);
                let copy = replicas.pop().unwrap().outcome;
                core.channel_done(alternate, copy, NativeDatagramResult::Rejected, net.now);
            }
        }
        assert_eq!(core.datagram_stats().native.replicas, 2);
        let copy = replicas.pop().unwrap().outcome;
        core.channel_done(alternate, copy, NativeDatagramResult::Accepted, net.now);
    }
}
