use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

static DEFAULT_CONFIG_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn public_protocol_aliases_remain_pinned() {
    assert_eq!(zmux::MAGIC, b"ZMUX");
    assert_eq!(zmux::PREFACE_VERSION, 1);
    assert_eq!(zmux::PROTO_VERSION, 1);
    assert_eq!(zmux::MAX_PREFACE_SETTINGS_BYTES, 4096);
    assert_eq!(zmux::MAX_VARINT62, (1u64 << 62) - 1);

    assert_eq!(zmux::CAPABILITY_PRIORITY_HINTS, 1);
    assert_eq!(zmux::CAPABILITY_STREAM_GROUPS, 1 << 1);
    assert_eq!(zmux::CAPABILITY_MULTILINK_BASIC_RETIRED, 1 << 2);
    assert_eq!(
        zmux::CAPABILITY_MULTILINK_BASIC,
        zmux::CAPABILITY_MULTILINK_BASIC_RETIRED
    );
    assert_eq!(zmux::CAPABILITY_PRIORITY_UPDATE, 1 << 3);
    assert_eq!(zmux::CAPABILITY_OPEN_METADATA, 1 << 4);

    assert_eq!(u64::from(zmux::SchedulerHint::UnspecifiedOrBalanced), 0);
    assert_eq!(u64::from(zmux::SchedulerHint::Latency), 1);
    assert_eq!(u64::from(zmux::SchedulerHint::BalancedFair), 2);
    assert_eq!(u64::from(zmux::SchedulerHint::BulkThroughput), 3);
    assert_eq!(u64::from(zmux::SchedulerHint::GroupFair), 4);
    assert_eq!(
        zmux::SchedulerHint::from_u64(99),
        zmux::SchedulerHint::UnspecifiedOrBalanced
    );
    assert_eq!(
        zmux::SchedulerHint::from_code(4),
        zmux::SchedulerHint::GroupFair
    );
    assert_eq!(
        zmux::SchedulerHint::from_code(99),
        zmux::SchedulerHint::UnspecifiedOrBalanced
    );

    assert_eq!(zmux::SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED, 1);
    assert_eq!(zmux::SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED, 2);
    assert_eq!(zmux::SETTING_INITIAL_MAX_STREAM_DATA_UNI, 3);
    assert_eq!(zmux::SETTING_INITIAL_MAX_DATA, 4);
    assert_eq!(zmux::SETTING_MAX_INCOMING_STREAMS_BIDI, 5);
    assert_eq!(zmux::SETTING_MAX_INCOMING_STREAMS_UNI, 6);
    assert_eq!(zmux::SETTING_MAX_FRAME_PAYLOAD, 7);
    assert_eq!(zmux::SETTING_IDLE_TIMEOUT_MILLIS, 8);
    assert_eq!(zmux::SETTING_KEEPALIVE_HINT_MILLIS, 9);
    assert_eq!(zmux::SETTING_MAX_CONTROL_PAYLOAD_BYTES, 10);
    assert_eq!(zmux::SETTING_MAX_EXTENSION_PAYLOAD_BYTES, 11);
    assert_eq!(zmux::SETTING_SCHEDULER_HINTS, 12);
    assert_eq!(zmux::SETTING_PING_PADDING_KEY, 13);
    assert_eq!(zmux::SETTING_PREFACE_PADDING, 63);

    assert_eq!(zmux::EXT_PRIORITY_UPDATE, 1);
    assert_eq!(zmux::EXT_ML_READY_RETIRED, 2);
    assert_eq!(zmux::EXT_ML_ATTACH_RETIRED, 3);
    assert_eq!(zmux::EXT_ML_ATTACH_ACK_RETIRED, 4);
    assert_eq!(zmux::EXT_ML_DRAIN_REQ_RETIRED, 5);
    assert_eq!(zmux::EXT_ML_DRAIN_ACK_RETIRED, 6);

    assert_eq!(zmux::METADATA_STREAM_PRIORITY, 1);
    assert_eq!(zmux::METADATA_STREAM_GROUP, 2);
    assert_eq!(zmux::METADATA_OPEN_INFO, 3);

    assert_eq!(zmux::DIAG_DEBUG_TEXT, 1);
    assert_eq!(zmux::DIAG_RETRY_AFTER_MILLIS, 2);
    assert_eq!(zmux::DIAG_OFFENDING_STREAM_ID, 3);
    assert_eq!(zmux::DIAG_OFFENDING_FRAME_TYPE, 4);

    assert_eq!(zmux::ErrorCode::NoError.as_u64(), 0);
    assert_eq!(zmux::ErrorCode::Protocol.as_u64(), 1);
    assert_eq!(zmux::ErrorCode::FlowControl.as_u64(), 2);
    assert_eq!(zmux::ErrorCode::StreamLimit.as_u64(), 3);
    assert_eq!(zmux::ErrorCode::RefusedStream.as_u64(), 4);
    assert_eq!(zmux::ErrorCode::StreamState.as_u64(), 5);
    assert_eq!(zmux::ErrorCode::StreamClosed.as_u64(), 6);
    assert_eq!(zmux::ErrorCode::SessionClosing.as_u64(), 7);
    assert_eq!(zmux::ErrorCode::Cancelled.as_u64(), 8);
    assert_eq!(zmux::ErrorCode::IdleTimeout.as_u64(), 9);
    assert_eq!(zmux::ErrorCode::FrameSize.as_u64(), 10);
    assert_eq!(zmux::ErrorCode::UnsupportedVersion.as_u64(), 11);
    assert_eq!(zmux::ErrorCode::RoleConflict.as_u64(), 12);
    assert_eq!(zmux::ErrorCode::Internal.as_u64(), 13);
    assert_eq!(
        zmux::ErrorCode::from_code(13),
        Some(zmux::ErrorCode::Internal)
    );
    assert!(zmux::ErrorCode::from_code(99).is_none());

    assert_eq!(zmux::FrameType::from_u8(1).unwrap(), zmux::FrameType::Data);
    assert_eq!(zmux::FrameType::from_u8(11).unwrap(), zmux::FrameType::Ext);
    assert_eq!(
        zmux::FrameType::from_code(4).unwrap(),
        zmux::FrameType::Ping
    );
    assert_eq!(u8::from(zmux::FrameType::Close), 10);
    assert_eq!(zmux::FrameType::try_from(11).unwrap(), zmux::FrameType::Ext);
    assert!(zmux::FrameType::from_u8(12).is_err());
    assert_eq!(u8::from(zmux::Role::Responder), 1);
    assert_eq!(zmux::Role::try_from(2).unwrap(), zmux::Role::Auto);
}

#[test]
fn public_conformance_parse_error_is_nameable() {
    let err = "unknown".parse::<zmux::Claim>().unwrap_err();
    assert_eq!(err, zmux::ParseConformanceError::Claim);
    assert_eq!(err.to_string(), "unknown zmux conformance claim");
}

#[test]
fn public_config_builders_and_global_template_remain_ergonomic() {
    let _guard = DEFAULT_CONFIG_LOCK.lock().unwrap();
    zmux::reset_default_config();

    let builtin = zmux::Config::builtin_default();
    assert_eq!(builtin.role, zmux::Role::Auto);
    assert_eq!(builtin.min_proto, zmux::PROTO_VERSION);
    assert_eq!(builtin.max_proto, zmux::PROTO_VERSION);
    assert_eq!(builtin.settings, zmux::Settings::DEFAULT);
    assert!(!builtin.preface_padding);
    assert!(!builtin.ping_padding);

    zmux::configure_default_config(|cfg| {
        cfg.preface_padding = true;
        cfg.ping_padding = true;
        cfg.ping_padding_min_bytes = 33;
        cfg.ping_padding_max_bytes = 44;
        cfg.settings.max_control_payload_bytes = 8_192;
        cfg.settings.ping_padding_key = 123;
        cfg.tie_breaker_nonce = 456;
        cfg.min_proto = 0;
        cfg.max_proto = 0;
    });

    let configured = zmux::default_config();
    assert!(configured.preface_padding);
    assert!(configured.ping_padding);
    assert_eq!(configured.ping_padding_min_bytes, 33);
    assert_eq!(configured.ping_padding_max_bytes, 44);
    assert_eq!(configured.settings.max_control_payload_bytes, 8_192);
    assert_eq!(
        configured.settings.max_frame_payload,
        zmux::Settings::DEFAULT.max_frame_payload
    );
    assert_eq!(configured.settings.ping_padding_key, 0);
    assert_eq!(configured.tie_breaker_nonce, 0);
    assert_eq!(configured.min_proto, zmux::PROTO_VERSION);
    assert_eq!(configured.max_proto, zmux::PROTO_VERSION);

    let initiator = zmux::Config::initiator();
    assert_eq!(initiator.role, zmux::Role::Initiator);
    assert_eq!(
        zmux::Config::responder().with_role(zmux::Role::Auto).role,
        zmux::Role::Auto
    );
    let cfg = zmux::Config::default()
        .with_capabilities(zmux::CAPABILITY_OPEN_METADATA)
        .enable_capabilities(zmux::CAPABILITY_PRIORITY_HINTS)
        .with_settings(zmux::Settings {
            max_frame_payload: 32 * 1024,
            ..zmux::Settings::DEFAULT
        });
    assert_eq!(
        cfg.capabilities,
        zmux::CAPABILITY_OPEN_METADATA | zmux::CAPABILITY_PRIORITY_HINTS
    );
    assert_eq!(cfg.settings.max_frame_payload, 32 * 1024);

    let opts = zmux::OpenOptions::new()
        .try_with_initial_priority(zmux::MAX_VARINT62)
        .unwrap()
        .try_with_initial_group(9)
        .unwrap()
        .with_open_info_bytes(b"hello");
    assert_eq!(opts.initial_priority, Some(zmux::MAX_VARINT62));
    assert_eq!(opts.initial_group, Some(9));
    assert_eq!(opts.open_info, b"hello");
    assert_eq!(
        zmux::OpenOptions::open_info_bytes(b"borrowed").open_info,
        b"borrowed"
    );
    assert!(opts.validate().is_ok());
    assert!(zmux::OpenOptions::new()
        .try_with_initial_group(zmux::MAX_VARINT62 + 1)
        .is_err());

    zmux::Config::reset_default();
    assert!(!zmux::Config::default().ping_padding);
}

#[test]
fn public_codec_facade_round_trips_without_private_modules() -> zmux::Result<()> {
    assert_eq!(zmux::default_settings(), zmux::Settings::DEFAULT);

    let mut varint = Vec::new();
    zmux::append_varint(&mut varint, 16_384)?;
    assert_eq!(zmux::parse_varint(&varint)?, (16_384, 4));
    assert_eq!(
        zmux::encode_varint_to_slice(&mut [0; zmux::MAX_VARINT_LEN], 63)?,
        1
    );

    let mut tlv = Vec::new();
    zmux::append_tlv(&mut tlv, 99, b"value")?;
    let views = zmux::parse_tlvs_view(&tlv)?;
    assert_eq!(views[0].typ, 99);
    assert_eq!(views[0].value, b"value");
    assert_eq!(views[0].to_tlv()?.value, b"value");
    assert_eq!(
        zmux::parse_tlvs(&tlv)?[0],
        zmux::Tlv::new(99, b"value".to_vec())?
    );

    let frame = zmux::Frame::with_flags(
        zmux::FrameType::Data,
        zmux::FRAME_FLAG_FIN,
        4,
        b"abc".to_vec(),
    );
    let encoded = frame.marshal()?;
    assert_eq!(frame.encoded_len()?, encoded.len());
    let (view, view_len) = zmux::FrameView::parse(&encoded, zmux::Limits::default())?;
    assert_eq!(view.payload, b"abc");
    assert_eq!(view_len, encoded.len());
    let (parsed_frame, parsed_frame_len) = zmux::parse_frame(&encoded, zmux::Limits::default())?;
    assert_eq!(parsed_frame, frame);
    assert_eq!(parsed_frame_len, encoded.len());
    let (owned, owned_len) = zmux::read_frame(&mut encoded.as_slice(), zmux::Limits::default())
        .map(|frame| (frame, encoded.len()))?;
    assert_eq!(owned, frame);
    assert_eq!(owned_len, encoded.len());

    let metadata_prefix = zmux::build_open_metadata_prefix(
        zmux::CAPABILITY_OPEN_METADATA
            | zmux::CAPABILITY_PRIORITY_HINTS
            | zmux::CAPABILITY_STREAM_GROUPS,
        Some(7),
        Some(3),
        b"info",
        zmux::Settings::DEFAULT.max_frame_payload,
    )?;
    let data = zmux::parse_data_payload_view(&metadata_prefix, zmux::FRAME_FLAG_OPEN_METADATA)?;
    assert_eq!(data.metadata.priority, Some(7));
    assert_eq!(data.metadata.group, Some(3));
    assert_eq!(data.metadata.open_info(), b"info");
    assert!(data.metadata.has_open_info());
    assert!(data.app_data.is_empty());
    assert!(data.metadata_valid);

    let update = zmux::MetadataUpdate::new()
        .try_with_priority(11)?
        .try_with_group(12)?;
    let update_payload = zmux::build_priority_update_payload(
        zmux::CAPABILITY_PRIORITY_UPDATE
            | zmux::CAPABILITY_PRIORITY_HINTS
            | zmux::CAPABILITY_STREAM_GROUPS,
        update,
        zmux::Settings::DEFAULT.max_extension_payload_bytes,
    )?;
    let (metadata, valid) = zmux::parse_priority_update_payload(&update_payload)?;
    assert!(valid);
    assert_eq!(metadata.priority, Some(11));
    assert_eq!(metadata.group, Some(12));

    let close = zmux::build_code_payload(7, "closing", 64)?;
    assert_eq!(
        zmux::parse_error_payload(&close)?,
        (7, "closing".to_owned())
    );
    let goaway = zmux::build_goaway_payload(0, 0, 8, "drain")?;
    assert_eq!(zmux::parse_goaway_payload(&goaway)?.reason, "drain");

    let preface = test_preface(zmux::Role::Initiator);
    let preface_bytes = preface.marshal_with_settings_padding(b"pad")?;
    let (parsed, consumed) = zmux::parse_preface_prefix(&preface_bytes)?;
    assert_eq!(parsed, preface);
    assert_eq!(consumed, preface_bytes.len());
    assert_eq!(zmux::parse_preface(&preface_bytes)?, preface);
    let mut preface_with_trailing = preface_bytes.clone();
    preface_with_trailing.push(0);
    assert!(zmux::parse_preface(&preface_with_trailing).is_err());

    let peer = test_preface(zmux::Role::Responder);
    let negotiated = zmux::negotiate_prefaces(&preface, &peer)?;
    assert_eq!(negotiated.local_role, zmux::Role::Initiator);
    assert!(negotiated.supports_open_metadata());

    Ok(())
}

#[test]
fn public_trait_object_surface_accepts_external_implementations() -> zmux::Result<()> {
    let mut stream: zmux::BoxNativeStream = Box::new(DummyStream);
    assert_eq!(stream.stream_id(), 42);
    assert_eq!(stream.open_info(), b"api");
    assert!(stream.has_open_info());
    assert_eq!(stream.metadata().open_info, b"api");
    assert_eq!(
        stream.writev(&[IoSlice::new(b"a"), IoSlice::new(b"bc")])?,
        3
    );
    assert_eq!(
        stream.write_vectored_final_timeout(&[IoSlice::new(b"done")], Duration::from_millis(1))?,
        4
    );
    stream.set_deadline(Some(Instant::now()))?;
    stream.clear_deadline()?;
    stream.cancel_read(8)?;
    stream.cancel_write(8)?;
    stream.close_with_error(9, "abort")?;

    let mut buf = [0; 3];
    assert_eq!(Read::read(&mut stream, &mut buf)?, 3);
    assert_eq!(&buf, b"api");
    assert_eq!(Write::write(&mut stream, b"xy")?, 2);
    stream.flush()?;

    let send: zmux::BoxNativeSendStream = Box::new(DummyStream);
    assert_eq!(send.write_final(b"fin")?, 3);
    send.close_write()?;

    let recv: zmux::BoxNativeRecvStream = Box::new(DummyStream);
    assert_eq!(recv.read_timeout(&mut buf, Duration::from_millis(1))?, 3);
    recv.close_read()?;

    let session: zmux::BoxNativeSession = Box::new(DummySession);
    assert_eq!(session.state(), zmux::SessionState::Ready);
    assert_eq!(session.ping(b"echo")?, Duration::from_millis(1));
    assert!(session.wait_timeout(Duration::from_millis(1))?);
    assert!(!session.closed());
    assert_eq!(session.stats().state, zmux::SessionState::Ready);
    assert_eq!(session.open_and_send(b"hello")?.1, 5);
    assert_eq!(session.open_uni_and_send(b"hello")?.1, 5);
    assert!(session.peer_goaway_error().is_none());
    assert!(session.peer_close_error().is_none());
    assert_eq!(session.local_preface().role, zmux::Role::Initiator);
    assert_eq!(session.peer_preface().role, zmux::Role::Responder);
    assert_eq!(session.negotiated().proto, zmux::PROTO_VERSION);

    let arc_session = Arc::new(DummySession);
    assert_eq!(
        zmux::NativeSession::ping(&arc_session, b"echo")?,
        Duration::from_millis(1)
    );

    Ok(())
}

#[test]
fn public_async_surface_accepts_generic_and_erased_sessions() {
    fn assert_session<S: zmux::Session>() {}
    fn assert_stream<S: zmux::StreamApi>() {}
    fn assert_send_stream<S: zmux::SendStreamApi>() {}
    fn assert_recv_stream<S: zmux::RecvStreamApi>() {}

    assert_session::<zmux::Conn>();
    assert_session::<zmux::ClosedSession>();
    assert_stream::<zmux::Stream>();
    assert_send_stream::<zmux::SendStream>();
    assert_recv_stream::<zmux::RecvStream>();
    assert_session::<DummyAsyncSession>();
    assert_stream::<DummyAsyncStream>();

    let session: zmux::BoxSession = zmux::box_session(DummyAsyncSession);
    assert_eq!(session.state(), zmux::SessionState::Ready);
    assert_eq!(session.stats().state, zmux::SessionState::Ready);
    assert!(!session.closed());

    let wrapped = zmux::BoxedSession::new(DummyAsyncSession);
    assert_eq!(
        zmux::Session::stats(wrapped.inner()).state,
        zmux::SessionState::Ready
    );
    let _inner = wrapped.into_inner();
}

#[test]
fn async_session_timeout_defaults_share_one_budget() -> zmux::Result<()> {
    let original_timeout = Duration::from_secs(5);
    let write_timeouts = Arc::new(Mutex::new(Vec::new()));
    let write_attempts = Arc::new(AtomicUsize::new(0));
    let session = TimeoutBudgetAsyncSession {
        open_delay: Duration::from_millis(20),
        write_timeouts: Arc::clone(&write_timeouts),
        write_attempts: Arc::clone(&write_attempts),
    };

    block_on(zmux::Session::open_and_send_timeout(
        &session,
        b"bidi",
        original_timeout,
    ))?;
    block_on(zmux::Session::open_and_send_with_options_timeout(
        &session,
        zmux::OpenOptions::default(),
        b"bidi-opts",
        original_timeout,
    ))?;
    block_on(zmux::Session::open_uni_and_send_timeout(
        &session,
        b"uni",
        original_timeout,
    ))?;
    block_on(zmux::Session::open_uni_and_send_with_options_timeout(
        &session,
        zmux::OpenOptions::default(),
        b"uni-opts",
        original_timeout,
    ))?;

    let timeouts = write_timeouts.lock().unwrap();
    assert_eq!(timeouts.len(), 4);
    assert_eq!(write_attempts.load(Ordering::Relaxed), 4);
    assert!(timeouts.iter().all(|timeout| *timeout < original_timeout));

    Ok(())
}

#[test]
fn async_session_timeout_defaults_fail_when_open_consumes_budget() {
    let write_timeouts = Arc::new(Mutex::new(Vec::new()));
    let write_attempts = Arc::new(AtomicUsize::new(0));
    let session = TimeoutBudgetAsyncSession {
        open_delay: Duration::from_millis(20),
        write_timeouts: Arc::clone(&write_timeouts),
        write_attempts: Arc::clone(&write_attempts),
    };

    let err = match block_on(zmux::Session::open_and_send_timeout(
        &session,
        b"bidi",
        Duration::from_millis(1),
    )) {
        Ok(_) => panic!("open_and_send_timeout unexpectedly succeeded"),
        Err(err) => err,
    };
    assert!(err.is_timeout());
    assert_eq!(err.operation(), zmux::ErrorOperation::Write);
    assert_eq!(err.direction(), zmux::ErrorDirection::Write);
    assert_eq!(write_attempts.load(Ordering::Relaxed), 0);
    assert!(write_timeouts.lock().unwrap().is_empty());
}

#[test]
fn async_session_default_open_and_send_skips_empty_bidi_writes() -> zmux::Result<()> {
    let write_timeouts = Arc::new(Mutex::new(Vec::new()));
    let write_attempts = Arc::new(AtomicUsize::new(0));
    let session = TimeoutBudgetAsyncSession {
        open_delay: Duration::ZERO,
        write_timeouts: Arc::clone(&write_timeouts),
        write_attempts: Arc::clone(&write_attempts),
    };

    assert_eq!(block_on(zmux::Session::open_and_send(&session, b""))?.1, 0);
    assert_eq!(
        block_on(zmux::Session::open_and_send_with_options(
            &session,
            zmux::OpenOptions::default(),
            b"",
        ))?
        .1,
        0
    );
    assert_eq!(write_attempts.load(Ordering::Relaxed), 0);
    assert!(write_timeouts.lock().unwrap().is_empty());

    Ok(())
}

#[test]
fn closed_session_helpers_match_user_facing_session_contract() -> zmux::Result<()> {
    let session = zmux::closed_session();
    assert!(zmux::Session::closed(&session));
    assert_eq!(zmux::Session::state(&session), zmux::SessionState::Closed);
    assert_eq!(
        zmux::Session::stats(&session),
        zmux::SessionStats::empty(zmux::SessionState::Closed)
    );
    assert!(zmux::Session::local_addr(&session).is_none());
    assert!(zmux::Session::peer_addr(&session).is_none());
    assert!(block_on(zmux::Session::close(&session)).is_ok());
    assert!(block_on(zmux::Session::wait_timeout(
        &session,
        Duration::from_millis(1)
    ))?);
    assert!(block_on(zmux::Session::wait_close_error(&session))?.is_none());
    assert!(block_on(zmux::Session::wait_close_error_timeout(
        &session,
        Duration::from_millis(1)
    ))?
    .is_none());

    let err = match block_on(zmux::Session::open_stream(&session)) {
        Ok(_) => panic!("closed async session opened a stream"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.operation(), zmux::ErrorOperation::Open);
    assert_eq!(err.source(), zmux::ErrorSource::Local);

    let err = match block_on(zmux::Session::accept_stream_timeout(
        &session,
        Duration::from_millis(1),
    )) {
        Ok(_) => panic!("closed async session accepted a stream"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.operation(), zmux::ErrorOperation::Accept);

    let boxed = zmux::boxed_closed_session();
    assert!(zmux::Session::closed(&boxed));
    assert!(block_on(zmux::Session::wait(&boxed)).is_ok());

    let native = zmux::closed_native_session();
    assert!(zmux::NativeSession::closed(&native));
    assert_eq!(
        zmux::NativeSession::state(&native),
        zmux::SessionState::Closed
    );
    assert_eq!(
        zmux::NativeSession::stats(&native),
        zmux::SessionStats::empty(zmux::SessionState::Closed)
    );
    assert!(zmux::NativeSession::local_addr(&native).is_none());
    assert!(zmux::NativeSession::peer_addr(&native).is_none());
    zmux::NativeSession::close(&native)?;
    assert!(zmux::NativeSession::wait_timeout(
        &native,
        Duration::from_millis(1)
    )?);
    assert!(zmux::NativeSession::wait_close_error(&native)?.is_none());
    assert!(
        zmux::NativeSession::wait_close_error_timeout(&native, Duration::from_millis(1))?.is_none()
    );
    assert_eq!(
        zmux::NativeSession::local_preface(&native).preface_version,
        0
    );
    assert_eq!(zmux::NativeSession::negotiated(&native).proto, 0);

    let err = match zmux::NativeSession::open_stream(&native) {
        Ok(_) => panic!("closed native session opened a stream"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.operation(), zmux::ErrorOperation::Open);
    assert_eq!(err.source(), zmux::ErrorSource::Local);

    let err = zmux::NativeSession::goaway(&native, 0, 0).unwrap_err();
    assert!(err.is_session_closed());
    assert_eq!(err.operation(), zmux::ErrorOperation::Close);

    let boxed_native = zmux::boxed_closed_native_session();
    assert!(zmux::NativeSession::closed(&boxed_native));
    assert!(zmux::NativeSession::wait(&boxed_native).is_ok());

    Ok(())
}

#[test]
fn same_async_upper_layer_code_works_with_native_sessions() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();
    block_on(exercise_common_async_session(&client, &server))
}

#[test]
fn tcp_session_and_stream_addresses_follow_rust_connection_shape() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();
    assert_eq!(client.local_addr(), server.peer_addr());
    assert_eq!(client.peer_addr(), server.local_addr());
    assert_eq!(client.remote_addr(), client.peer_addr());

    let stream = client.open_stream()?;
    stream.write_final(b"addr")?;
    let accepted = server.accept_stream_timeout(Duration::from_secs(5))?;
    assert_eq!(stream.local_addr(), client.local_addr());
    assert_eq!(stream.peer_addr(), client.peer_addr());
    assert_eq!(accepted.local_addr(), server.local_addr());
    assert_eq!(accepted.peer_addr(), server.peer_addr());
    let mut buf = [0u8; 4];
    assert_eq!(accepted.read(&mut buf)?, 4);
    assert_eq!(&buf, b"addr");

    let _ = client.close();
    let _ = server.close();
    Ok(())
}

#[test]
fn duplex_transport_wrapper_carries_addresses_and_close_control() -> zmux::Result<()> {
    let close_count = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let client_close_count = Arc::clone(&close_count);
    let client = thread::spawn(move || {
        let socket = TcpStream::connect(addr).unwrap();
        let transport = tcp_duplex_transport(socket, Some(client_close_count));
        zmux::client_transport(transport, zmux::Config::default()).unwrap()
    });

    let (socket, _) = listener.accept()?;
    let server = thread::spawn(move || {
        let transport = tcp_duplex_transport(socket, None);
        zmux::server_transport(transport, zmux::Config::default()).unwrap()
    });

    let client = client.join().unwrap();
    let server = server.join().unwrap();
    assert_eq!(client.local_addr(), server.peer_addr());
    assert_eq!(client.peer_addr(), server.local_addr());

    let stream = client.open_stream()?;
    stream.write_final(b"transport")?;
    let accepted = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut buf = [0u8; 9];
    assert_eq!(accepted.read(&mut buf)?, buf.len());
    assert_eq!(&buf, b"transport");

    let _ = client.close_with_error(0x100, "done");
    let _ = server.close_with_error(0x100, "done");
    let _ = client.wait_timeout(Duration::from_secs(5));
    let _ = server.wait_timeout(Duration::from_secs(5));

    for _ in 0..50 {
        if close_count.load(Ordering::Relaxed) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_ne!(close_count.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn duplex_transport_is_a_rust_read_write_connection() -> io::Result<()> {
    let read_timeouts = Arc::new(AtomicUsize::new(0));
    let write_timeouts = Arc::new(AtomicUsize::new(0));
    let closes = Arc::new(AtomicUsize::new(0));
    let mut transport =
        zmux::DuplexTransport::new(io::Cursor::new(b"hello".to_vec()), Vec::<u8>::new())
            .with_control(RecordingTransportControl {
                read_timeouts: Arc::clone(&read_timeouts),
                write_timeouts: Arc::clone(&write_timeouts),
                closes: Arc::clone(&closes),
            });

    let mut buf = [0u8; 2];
    assert_eq!(Read::read(&mut transport, &mut buf)?, 2);
    assert_eq!(&buf, b"he");
    Write::write_all(&mut transport, b"out")?;
    Write::flush(&mut transport)?;
    assert_eq!(transport.reader().position(), 2);
    assert_eq!(transport.writer(), b"out");
    transport.writer_mut().extend_from_slice(b"!");

    transport.set_read_timeout(Some(Duration::from_millis(10)))?;
    transport.set_write_timeout(None)?;
    transport.close()?;

    assert_eq!(read_timeouts.load(Ordering::Relaxed), 1);
    assert_eq!(write_timeouts.load(Ordering::Relaxed), 1);
    assert_eq!(closes.load(Ordering::Relaxed), 1);
    let (_reader, writer) = transport.into_parts();
    assert_eq!(writer, b"out!");
    Ok(())
}

#[test]
fn public_join_helpers_build_full_stream_views_from_halves() -> zmux::Result<()> {
    let mut joined = zmux::join_native_streams(DummyStream, DummyStream)
        .with_info_side(zmux::DuplexInfoSide::Write);
    assert_eq!(joined.info_side(), zmux::DuplexInfoSide::Write);
    assert_eq!(joined.read_stream_id(), 42);
    assert_eq!(joined.write_stream_id(), 42);
    assert_eq!(zmux::NativeStreamInfo::stream_id(&joined), 42);
    assert!(zmux::NativeStreamInfo::bidirectional(&joined));
    assert_eq!(zmux::NativeStreamInfo::open_info(&joined), b"api");

    let mut buf = [0; 3];
    assert_eq!(Read::read(&mut joined, &mut buf)?, 3);
    assert_eq!(&buf, b"api");
    assert_eq!(Write::write(&mut joined, b"xy")?, 2);
    zmux::NativeStreamInfo::set_timeout(&joined, Some(Duration::from_secs(1)))?;
    zmux::NativeRecvStreamApi::set_read_timeout(&joined, None)?;
    zmux::NativeSendStreamApi::set_write_timeout(&joined, Some(Duration::from_secs(1)))?;
    assert_eq!(zmux::NativeSendStreamApi::write_final(&joined, b"fin")?, 3);
    zmux::NativeStreamInfo::close(&joined)?;

    let joined = zmux::join_streams(DummyAsyncStream, DummyAsyncStream);
    assert_eq!(joined.info_side(), zmux::DuplexInfoSide::Read);
    assert_eq!(joined.read_stream_id(), 42);
    assert_eq!(joined.write_stream_id(), 42);
    assert_eq!(zmux::StreamInfo::open_info(&joined), b"api");
    assert!(zmux::StreamInfo::bidirectional(&joined));

    let joined = joined.with_info_side(zmux::DuplexInfoSide::Write);
    assert_eq!(joined.info_side(), zmux::DuplexInfoSide::Write);
    assert_eq!(zmux::StreamInfo::stream_id(&joined), 42);
    zmux::StreamInfo::set_timeout(&joined, Some(Duration::from_secs(1)))?;
    zmux::RecvStreamApi::set_read_timeout(&joined, None)?;
    zmux::SendStreamApi::set_write_timeout(&joined, Some(Duration::from_secs(1)))?;

    let joined = zmux::join_streams(LabeledStream::new(77, b"joined"), DummyAsyncStream);
    let mut first = [0u8; 2];
    let mut second = [0u8; 4];
    let n = {
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        block_on(zmux::RecvStreamApi::read_vectored(&joined, &mut bufs))?
    };
    assert_eq!(n, 6);
    assert_eq!(&first, b"jo");
    assert_eq!(&second, b"ined");

    let joined = zmux::join_streams(LabeledStream::new(78, b"exact"), DummyAsyncStream);
    let mut exact = [0u8; 5];
    block_on(zmux::RecvStreamApi::read_exact(&joined, &mut exact))?;
    assert_eq!(&exact, b"exact");

    let joined = zmux::join_streams(LabeledStream::new(79, b"timer"), DummyAsyncStream);
    let mut exact = [0u8; 5];
    block_on(zmux::RecvStreamApi::read_exact_timeout(
        &joined,
        &mut exact,
        Duration::from_secs(1),
    ))?;
    assert_eq!(&exact, b"timer");

    Ok(())
}

#[test]
fn borrowed_native_streams_follow_std_io_connection_shape() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();
    let outbound = client.open_stream()?;
    let mut outbound_ref = &outbound;
    Write::write_all(&mut outbound_ref, b"borrowed-bidi")?;
    zmux::NativeSendStreamApi::close_write(&outbound_ref)?;

    let inbound = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut inbound_ref = &inbound;
    let mut bidi = [0u8; 13];
    assert_eq!(Read::read(&mut inbound_ref, &mut bidi)?, bidi.len());
    assert_eq!(&bidi, b"borrowed-bidi");

    let outbound = client.open_stream()?;
    let mut outbound_ref = &outbound;
    Write::write_all(&mut outbound_ref, b"vectored-bidi")?;
    zmux::NativeSendStreamApi::close_write(&outbound_ref)?;

    let inbound = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut inbound_ref = &inbound;
    let mut first = [0u8; 8];
    let mut second = [0u8; 5];
    let n = {
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        Read::read_vectored(&mut inbound_ref, &mut bufs)?
    };
    assert_eq!(n, 13);
    assert_eq!(&first, b"vectored");
    assert_eq!(&second, b"-bidi");

    let outbound = client.open_stream()?;
    let mut outbound_ref = &outbound;
    Write::write_all(&mut outbound_ref, b"exact-bidi")?;
    zmux::NativeSendStreamApi::close_write(&outbound_ref)?;

    let inbound = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut inbound_ref = &inbound;
    let mut exact = [0u8; 10];
    Read::read_exact(&mut inbound_ref, &mut exact)?;
    assert_eq!(&exact, b"exact-bidi");

    let outbound = client.open_stream()?;
    let mut outbound_ref = &outbound;
    Write::write_all(&mut outbound_ref, b"timed-read")?;
    zmux::NativeSendStreamApi::close_write(&outbound_ref)?;

    let inbound = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut exact = [0u8; 10];
    zmux::NativeRecvStreamApi::read_exact_timeout(&inbound, &mut exact, Duration::from_secs(5))?;
    assert_eq!(&exact, b"timed-read");

    let send = client.open_uni_stream()?;
    let mut send_ref = &send;
    Write::write_all(&mut send_ref, b"borrowed-uni")?;
    zmux::NativeSendStreamApi::close_write(&send_ref)?;

    let recv = server.accept_uni_stream_timeout(Duration::from_secs(5))?;
    let mut recv_ref = &recv;
    let mut uni = [0u8; 12];
    assert_eq!(Read::read(&mut recv_ref, &mut uni)?, uni.len());
    assert_eq!(&uni, b"borrowed-uni");

    let joined = zmux::join_native_streams(DummyStream, DummyStream);
    let mut joined_ref = &joined;
    let mut joined_buf = [0; 3];
    assert_eq!(Read::read(&mut joined_ref, &mut joined_buf)?, 3);
    assert_eq!(Write::write(&mut joined_ref, b"xy")?, 2);
    assert_eq!(zmux::NativeStreamInfo::stream_id(&joined_ref), 42);

    let joined = zmux::join_native_streams(LabeledStream::new(77, b"joined"), DummyStream);
    let mut joined_ref = &joined;
    let mut joined_first = [0u8; 2];
    let mut joined_second = [0u8; 4];
    let n = {
        let mut bufs = [
            IoSliceMut::new(&mut joined_first),
            IoSliceMut::new(&mut joined_second),
        ];
        Read::read_vectored(&mut joined_ref, &mut bufs)?
    };
    assert_eq!(n, 6);
    assert_eq!(&joined_first, b"jo");
    assert_eq!(&joined_second, b"ined");

    let _ = client.close();
    let _ = server.close();
    Ok(())
}

#[test]
fn joined_streams_reject_invalid_underlying_progress() -> zmux::Result<()> {
    let mut native =
        zmux::join_native_streams(InvalidProgressStream::read_progress(4), DummyStream);
    let mut buf = [0u8; 3];
    let err = Read::read(&mut native, &mut buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let mut native =
        zmux::join_native_streams(InvalidProgressStream::read_progress(4), DummyStream);
    let mut first = [0u8; 1];
    let mut second = [0u8; 2];
    let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
    let err = Read::read_vectored(&mut native, &mut bufs).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let err = zmux::NativeRecvStreamApi::read_timeout(&native, &mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let err =
        zmux::NativeRecvStreamApi::read_exact_timeout(&native, &mut buf, Duration::from_secs(1))
            .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let mut native =
        zmux::join_native_streams(DummyStream, InvalidProgressStream::write_progress(4));
    let err = Write::write(&mut native, b"abc").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let err = zmux::NativeSendStreamApi::write_timeout(&native, b"abc", Duration::from_secs(1))
        .unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let parts = [IoSlice::new(b"a"), IoSlice::new(b"bc")];
    let err = zmux::NativeSendStreamApi::writev(&native, &parts).unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let async_joined =
        zmux::join_streams(InvalidProgressStream::read_progress(4), DummyAsyncStream);
    let err = block_on(zmux::RecvStreamApi::read(&async_joined, &mut buf)).unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let err = block_on(zmux::RecvStreamApi::read_exact(&async_joined, &mut buf)).unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let err = block_on(zmux::RecvStreamApi::read_exact_timeout(
        &async_joined,
        &mut buf,
        Duration::from_secs(1),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let async_joined =
        zmux::join_streams(DummyAsyncStream, InvalidProgressStream::write_progress(4));
    let err = block_on(zmux::SendStreamApi::write(&async_joined, b"abc")).unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let err = block_on(zmux::SendStreamApi::write_vectored(&async_joined, &parts)).unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let err = block_on(zmux::SendStreamApi::write_final_timeout(
        &async_joined,
        b"abc",
        Duration::from_secs(1),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let invalid_reader = InvalidProgressStream::read_progress(8193);
    let mut out = Vec::new();
    let err = block_on(zmux::RecvStreamApi::read_to_end(&invalid_reader, &mut out)).unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let err = block_on(zmux::RecvStreamApi::read_to_end_limited(&invalid_reader, 3)).unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let mut one = [0u8; 1];
    let err = zmux::NativeRecvStreamApi::read_exact_timeout(
        &ZeroSizedCloseProbe,
        &mut one,
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(
        err.source_io_error_kind(),
        Some(io::ErrorKind::UnexpectedEof)
    );

    let err = block_on(zmux::RecvStreamApi::read_exact(
        &ZeroSizedCloseProbe,
        &mut one,
    ))
    .unwrap_err();
    assert_eq!(
        err.source_io_error_kind(),
        Some(io::ErrorKind::UnexpectedEof)
    );

    Ok(())
}

#[test]
fn async_session_open_and_send_rejects_invalid_stream_progress() {
    let session = InvalidProgressAsyncSession;
    let opts = zmux::OpenOptions::default();
    let timeout = Duration::from_secs(1);
    let parts = [IoSlice::new(b"ab"), IoSlice::new(b"c")];

    assert_invalid_write_progress(block_on(zmux::Session::open_and_send(&session, b"abc")));

    assert_invalid_write_progress(block_on(zmux::Session::open_and_send_timeout(
        &session, b"abc", timeout,
    )));

    assert_invalid_write_progress(block_on(zmux::Session::open_and_send_with_options(
        &session,
        opts.clone(),
        b"abc",
    )));

    assert_invalid_write_progress(block_on(zmux::Session::open_and_send_with_options_timeout(
        &session,
        opts.clone(),
        b"abc",
        timeout,
    )));

    assert_invalid_write_progress(block_on(zmux::Session::open_and_send_vectored(
        &session, &parts,
    )));

    assert_invalid_write_progress(block_on(zmux::Session::open_and_send_vectored_timeout(
        &session, &parts, timeout,
    )));

    assert_invalid_write_progress(block_on(
        zmux::Session::open_and_send_vectored_with_options(&session, opts.clone(), &parts),
    ));

    assert_invalid_write_progress(block_on(
        zmux::Session::open_and_send_vectored_with_options_timeout(
            &session,
            opts.clone(),
            &parts,
            timeout,
        ),
    ));

    assert_invalid_write_progress(block_on(zmux::Session::open_uni_and_send(&session, b"abc")));

    assert_invalid_write_progress(block_on(zmux::Session::open_uni_and_send_timeout(
        &session, b"abc", timeout,
    )));

    assert_invalid_write_progress(block_on(zmux::Session::open_uni_and_send_with_options(
        &session,
        opts.clone(),
        b"abc",
    )));

    assert_invalid_write_progress(block_on(
        zmux::Session::open_uni_and_send_with_options_timeout(&session, opts, b"abc", timeout),
    ));

    assert_invalid_write_progress(block_on(zmux::Session::open_uni_and_send_vectored(
        &session, &parts,
    )));

    assert_invalid_write_progress(block_on(zmux::Session::open_uni_and_send_vectored_timeout(
        &session, &parts, timeout,
    )));

    assert_invalid_write_progress(block_on(
        zmux::Session::open_uni_and_send_vectored_with_options(
            &session,
            zmux::OpenOptions::default(),
            &parts,
        ),
    ));

    assert_invalid_write_progress(block_on(
        zmux::Session::open_uni_and_send_vectored_with_options_timeout(
            &session,
            zmux::OpenOptions::default(),
            &parts,
            timeout,
        ),
    ));

    let boxed = zmux::BoxedSession::new(InvalidProgressAsyncSession);
    assert_invalid_write_progress(block_on(zmux::Session::open_and_send(&boxed, b"abc")));
    assert_invalid_write_progress(block_on(zmux::Session::open_and_send_vectored(
        &boxed, &parts,
    )));
}

#[test]
fn joined_stream_halves_can_be_paused_replaced_and_detached() -> zmux::Result<()> {
    let mut native =
        zmux::join_native_streams(LabeledStream::new(1, b"one"), LabeledStream::new(2, b"two"));
    let mut buf = [0u8; 8];
    let n = Read::read(&mut native, &mut buf)?;
    assert_eq!(&buf[..n], b"one");

    let mut paused_read = native.pause_read()?;
    assert_eq!(paused_read.current().unwrap().id, 1);
    assert!(native.recv().is_none());
    let previous = paused_read.replace(LabeledStream::new(3, b"new"));
    assert_eq!(previous.unwrap().id, 1);
    paused_read.resume()?;
    assert_eq!(native.read_stream_id(), 3);
    let n = Read::read(&mut native, &mut buf)?;
    assert_eq!(&buf[..n], b"new");

    let detached = native.detach_send()?.unwrap();
    assert_eq!(detached.id, 2);
    assert!(Write::write(&mut native, b"x").is_err());
    native.replace_send(LabeledStream::new(4, b"out"))?;
    assert_eq!(native.write_stream_id(), 4);
    assert_eq!(Write::write(&mut native, b"x")?, 1);

    let async_joined = zmux::join_streams(
        LabeledStream::new(10, b"alpha"),
        LabeledStream::new(20, b"beta"),
    );
    let mut paused_read = async_joined.pause_read()?;
    assert_eq!(paused_read.current().unwrap().id, 10);
    assert!(async_joined.recv().is_none());
    let previous = paused_read.replace(LabeledStream::new(30, b"gamma"));
    assert_eq!(previous.unwrap().id, 10);
    paused_read.resume()?;
    assert_eq!(async_joined.read_stream_id(), 30);

    let mut buf = [0u8; 8];
    let n = block_on(zmux::RecvStreamApi::read(&async_joined, &mut buf))?;
    assert_eq!(&buf[..n], b"gamma");

    let detached = async_joined.detach_send()?.unwrap();
    assert_eq!(detached.id, 20);
    assert!(block_on(zmux::SendStreamApi::write(&async_joined, b"x")).is_err());
    async_joined.replace_send(LabeledStream::new(40, b"delta"))?;
    assert_eq!(async_joined.write_stream_id(), 40);
    assert_eq!(
        block_on(zmux::SendStreamApi::write(&async_joined, b"x"))?,
        1
    );

    Ok(())
}

#[test]
fn joined_streams_can_start_empty_and_hot_plug_halves() -> zmux::Result<()> {
    let native_events = Arc::new(Mutex::new(Vec::new()));
    let read_deadline = Instant::now() + Duration::from_secs(30);
    let write_deadline = Instant::now() + Duration::from_secs(60);
    let mut native =
        zmux::join_optional_native_streams::<DeadlineProbeStream, DeadlineProbeStream>(None, None);
    assert_eq!(native.read_stream_id(), 0);
    assert_eq!(native.write_stream_id(), 0);
    assert!(Read::read(&mut native, &mut [0u8; 1]).is_err());
    assert!(Write::write(&mut native, b"x").is_err());
    zmux::NativeRecvStreamApi::set_read_deadline(&native, Some(read_deadline))?;
    zmux::NativeSendStreamApi::set_write_deadline(&native, Some(write_deadline))?;

    let mut paused_read = native.pause_read()?;
    assert!(paused_read.current().is_none());
    paused_read.replace(DeadlineProbeStream::new(1, Arc::clone(&native_events)));
    paused_read.resume()?;
    assert_eq!(native.read_stream_id(), 1);
    assert_deadline_event(
        &native_events,
        DeadlineEvent::new(1, DeadlineSide::Read, Some(read_deadline)),
    );

    let mut paused_write = native.pause_write()?;
    assert!(paused_write.current().is_none());
    paused_write.replace(DeadlineProbeStream::new(2, Arc::clone(&native_events)));
    paused_write.resume()?;
    assert_eq!(native.write_stream_id(), 2);
    assert_deadline_event(
        &native_events,
        DeadlineEvent::new(2, DeadlineSide::Write, Some(write_deadline)),
    );

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_joined =
        zmux::join_optional_streams::<DeadlineProbeStream, DeadlineProbeStream>(None, None);
    assert_eq!(async_joined.read_stream_id(), 0);
    assert_eq!(async_joined.write_stream_id(), 0);
    assert!(block_on(zmux::RecvStreamApi::read(&async_joined, &mut [0u8; 1])).is_err());
    assert!(block_on(zmux::SendStreamApi::write(&async_joined, b"x")).is_err());
    zmux::RecvStreamApi::set_read_deadline(&async_joined, Some(read_deadline))?;
    zmux::SendStreamApi::set_write_deadline(&async_joined, Some(write_deadline))?;

    let mut paused_read = async_joined.pause_read()?;
    assert!(paused_read.current().is_none());
    paused_read.replace(DeadlineProbeStream::new(10, Arc::clone(&async_events)));
    paused_read.resume()?;
    assert_eq!(async_joined.read_stream_id(), 10);
    assert_deadline_event(
        &async_events,
        DeadlineEvent::new(10, DeadlineSide::Read, Some(read_deadline)),
    );

    let mut paused_write = async_joined.pause_write()?;
    assert!(paused_write.current().is_none());
    paused_write.replace(DeadlineProbeStream::new(20, Arc::clone(&async_events)));
    paused_write.resume()?;
    assert_eq!(async_joined.write_stream_id(), 20);
    assert_deadline_event(
        &async_events,
        DeadlineEvent::new(20, DeadlineSide::Write, Some(write_deadline)),
    );

    Ok(())
}

#[test]
fn joined_stream_deadlines_follow_hot_swapped_halves() -> zmux::Result<()> {
    let native_events = Arc::new(Mutex::new(Vec::new()));
    let read_deadline = Instant::now() + Duration::from_secs(30);
    let write_deadline = Instant::now() + Duration::from_secs(60);
    let native = zmux::join_native_streams(
        DeadlineProbeStream::new(1, Arc::clone(&native_events)),
        DeadlineProbeStream::new(2, Arc::clone(&native_events)),
    );

    zmux::NativeRecvStreamApi::set_read_deadline(&native, Some(read_deadline))?;
    zmux::NativeSendStreamApi::set_write_deadline(&native, Some(write_deadline))?;
    assert_deadline_event(
        &native_events,
        DeadlineEvent::new(1, DeadlineSide::Read, Some(read_deadline)),
    );
    assert_deadline_event(
        &native_events,
        DeadlineEvent::new(2, DeadlineSide::Write, Some(write_deadline)),
    );

    native_events.lock().unwrap().clear();
    let mut paused_read = native.pause_read()?;
    paused_read.replace(DeadlineProbeStream::new(3, Arc::clone(&native_events)));
    paused_read.resume()?;
    assert_deadline_event(
        &native_events,
        DeadlineEvent::new(3, DeadlineSide::Read, Some(read_deadline)),
    );

    native_events.lock().unwrap().clear();
    native.replace_send(DeadlineProbeStream::new(4, Arc::clone(&native_events)))?;
    assert_deadline_event(
        &native_events,
        DeadlineEvent::new(4, DeadlineSide::Write, Some(write_deadline)),
    );

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_joined = zmux::join_streams(
        DeadlineProbeStream::new(10, Arc::clone(&async_events)),
        DeadlineProbeStream::new(20, Arc::clone(&async_events)),
    );
    zmux::RecvStreamApi::set_read_deadline(&async_joined, Some(read_deadline))?;
    zmux::SendStreamApi::set_write_deadline(&async_joined, Some(write_deadline))?;
    assert_deadline_event(
        &async_events,
        DeadlineEvent::new(10, DeadlineSide::Read, Some(read_deadline)),
    );
    assert_deadline_event(
        &async_events,
        DeadlineEvent::new(20, DeadlineSide::Write, Some(write_deadline)),
    );

    async_events.lock().unwrap().clear();
    let mut paused_write = async_joined.pause_write()?;
    paused_write.replace(DeadlineProbeStream::new(30, Arc::clone(&async_events)));
    paused_write.resume()?;
    assert_deadline_event(
        &async_events,
        DeadlineEvent::new(30, DeadlineSide::Write, Some(write_deadline)),
    );

    async_events.lock().unwrap().clear();
    async_joined.replace_recv(DeadlineProbeStream::new(40, Arc::clone(&async_events)))?;
    assert_deadline_event(
        &async_events,
        DeadlineEvent::new(40, DeadlineSide::Read, Some(read_deadline)),
    );

    Ok(())
}

#[test]
fn joined_stream_resume_replays_deadline_refresh_during_apply() -> zmux::Result<()> {
    let native_events = Arc::new(Mutex::new(Vec::new()));
    let native = zmux::join_native_streams(
        DeadlineProbeStream::new(1, Arc::clone(&native_events)),
        DeadlineProbeStream::new(2, Arc::clone(&native_events)),
    );
    let mut paused_read = native.pause_read()?;
    let replacement = DeadlineProbeStream::blocking_deadlines(3, Arc::clone(&native_events));
    let probe = replacement.clone();
    let _ = paused_read.replace(replacement);

    let first_deadline = Instant::now() + Duration::from_secs(30);
    let second_deadline = Instant::now() + Duration::from_secs(60);
    zmux::NativeRecvStreamApi::set_read_deadline(&native, Some(first_deadline))?;
    let resume = thread::spawn(move || paused_read.resume());

    assert!(
        probe.wait_first_deadline_started(),
        "native read resume did not begin replaying the staged deadline"
    );
    zmux::NativeRecvStreamApi::set_read_deadline(&native, Some(second_deadline))?;
    probe.release_deadline();
    resume.join().unwrap()?;

    assert_eq!(
        deadline_events_for(&native_events, 3, DeadlineSide::Read),
        vec![Some(first_deadline), Some(second_deadline)]
    );

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_joined = zmux::join_streams(
        DeadlineProbeStream::new(10, Arc::clone(&async_events)),
        DeadlineProbeStream::new(20, Arc::clone(&async_events)),
    );
    let mut paused_write = async_joined.pause_write()?;
    let replacement = DeadlineProbeStream::blocking_deadlines(30, Arc::clone(&async_events));
    let probe = replacement.clone();
    let _ = paused_write.replace(replacement);

    zmux::SendStreamApi::set_write_deadline(&async_joined, Some(first_deadline))?;
    let resume = thread::spawn(move || paused_write.resume());

    assert!(
        probe.wait_first_deadline_started(),
        "async write resume did not begin replaying the staged deadline"
    );
    zmux::SendStreamApi::set_write_deadline(&async_joined, Some(second_deadline))?;
    probe.release_deadline();
    resume.join().unwrap()?;

    assert_eq!(
        deadline_events_for(&async_events, 30, DeadlineSide::Write),
        vec![Some(first_deadline), Some(second_deadline)]
    );

    Ok(())
}

#[test]
fn joined_stream_set_deadline_replays_refresh_during_active_apply() -> zmux::Result<()> {
    let native_events = Arc::new(Mutex::new(Vec::new()));
    let native_read = DeadlineProbeStream::blocking_deadlines(101, Arc::clone(&native_events));
    let native_probe = native_read.clone();
    let native = Arc::new(zmux::join_native_streams(
        native_read,
        DeadlineProbeStream::new(102, Arc::clone(&native_events)),
    ));

    let first_deadline = Instant::now() + Duration::from_secs(30);
    let second_deadline = Instant::now() + Duration::from_secs(60);
    let first_native = Arc::clone(&native);
    let first_setter = thread::spawn(move || {
        zmux::NativeRecvStreamApi::set_read_deadline(&*first_native, Some(first_deadline))
    });

    assert!(
        native_probe.wait_first_deadline_started(),
        "native read deadline apply did not reach the underlying half"
    );
    zmux::NativeRecvStreamApi::set_read_deadline(&*native, Some(second_deadline))?;
    native_probe.release_deadline();
    first_setter.join().unwrap()?;

    assert_eq!(
        deadline_events_for(&native_events, 101, DeadlineSide::Read),
        vec![Some(first_deadline), Some(second_deadline)]
    );

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_read = DeadlineProbeStream::blocking_deadlines(201, Arc::clone(&async_events));
    let async_probe = async_read.clone();
    let async_joined = Arc::new(zmux::join_streams(
        async_read,
        DeadlineProbeStream::new(202, Arc::clone(&async_events)),
    ));
    let first_async = Arc::clone(&async_joined);
    let first_setter = thread::spawn(move || {
        zmux::RecvStreamApi::set_read_deadline(&*first_async, Some(first_deadline))
    });

    assert!(
        async_probe.wait_first_deadline_started(),
        "async read deadline apply did not reach the underlying half"
    );
    zmux::RecvStreamApi::set_read_deadline(&*async_joined, Some(second_deadline))?;
    async_probe.release_deadline();
    first_setter.join().unwrap()?;

    assert_eq!(
        deadline_events_for(&async_events, 201, DeadlineSide::Read),
        vec![Some(first_deadline), Some(second_deadline)]
    );

    Ok(())
}

#[test]
fn joined_stream_paused_operations_honor_stored_deadlines() -> zmux::Result<()> {
    let native = Arc::new(zmux::join_native_streams(
        LabeledStream::new(1, b"read"),
        LabeledStream::new(2, b"write"),
    ));
    let paused_read = native.pause_read()?;
    zmux::NativeRecvStreamApi::set_read_deadline(
        &*native,
        Some(Instant::now() + Duration::from_millis(50)),
    )?;
    let (done_tx, done_rx) = mpsc::channel();
    let reader = Arc::clone(&native);
    let read_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        let timed_out = match zmux::NativeRecvStreamApi::read_timeout(
            &*reader,
            &mut buf,
            Duration::from_secs(5),
        ) {
            Ok(_) => false,
            Err(err) => err.is_timeout(),
        };
        done_tx.send(timed_out).unwrap();
    });
    let timed_out = match done_rx.recv_timeout(Duration::from_secs(1)) {
        Ok(timed_out) => timed_out,
        Err(err) => {
            let _ = paused_read.resume();
            let _ = read_thread.join();
            panic!("native paused read did not honor stored deadline: {err}");
        }
    };
    assert!(timed_out);
    paused_read.resume()?;
    read_thread.join().unwrap();

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_joined = Arc::new(zmux::join_streams(
        DeadlineProbeStream::new(10, Arc::clone(&async_events)),
        DeadlineProbeStream::new(20, Arc::clone(&async_events)),
    ));
    let paused_write = async_joined.pause_write()?;
    zmux::SendStreamApi::set_write_deadline(
        &*async_joined,
        Some(Instant::now() + Duration::from_millis(50)),
    )?;
    let (done_tx, done_rx) = mpsc::channel();
    let writer = Arc::clone(&async_joined);
    let write_thread = thread::spawn(move || {
        let timed_out = match block_on(zmux::SendStreamApi::write_timeout(
            &*writer,
            b"x",
            Duration::from_secs(5),
        )) {
            Ok(_) => false,
            Err(err) => err.is_timeout(),
        };
        done_tx.send(timed_out).unwrap();
    });
    let timed_out = match done_rx.recv_timeout(Duration::from_secs(1)) {
        Ok(timed_out) => timed_out,
        Err(err) => {
            let _ = paused_write.resume();
            let _ = write_thread.join();
            panic!("async paused write did not honor stored deadline: {err}");
        }
    };
    assert!(timed_out);
    paused_write.resume()?;
    write_thread.join().unwrap();

    Ok(())
}

#[test]
fn joined_stream_replace_propagates_deadline_replay_failure() -> zmux::Result<()> {
    let native_events = Arc::new(Mutex::new(Vec::new()));
    let native = zmux::join_native_streams(
        DeadlineProbeStream::new(1, Arc::clone(&native_events)),
        DeadlineProbeStream::new(2, Arc::clone(&native_events)),
    );
    zmux::NativeRecvStreamApi::set_read_deadline(
        &native,
        Some(Instant::now() + Duration::from_secs(30)),
    )?;

    let err = match native.replace_recv(DeadlineProbeStream::failing_deadlines(
        3,
        Arc::clone(&native_events),
    )) {
        Ok(_) => panic!("replace_recv unexpectedly accepted a half that rejected deadline replay"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("deadline probe failure"));
    assert_eq!(native.read_stream_id(), 1);

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_joined = zmux::join_streams(
        DeadlineProbeStream::new(10, Arc::clone(&async_events)),
        DeadlineProbeStream::new(20, Arc::clone(&async_events)),
    );
    zmux::SendStreamApi::set_write_deadline(
        &async_joined,
        Some(Instant::now() + Duration::from_secs(30)),
    )?;

    let err = match async_joined.replace_send(DeadlineProbeStream::failing_deadlines(
        30,
        Arc::clone(&async_events),
    )) {
        Ok(_) => panic!("replace_send unexpectedly accepted a half that rejected deadline replay"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("deadline probe failure"));
    assert_eq!(async_joined.write_stream_id(), 20);

    Ok(())
}

#[test]
fn native_stream_clones_share_close_identity_for_join_dedup() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();

    let stream = client.open_stream()?;
    let stream_clone = stream.clone();
    assert_eq!(
        zmux::NativeStreamInfo::close_identity(&stream),
        zmux::NativeStreamInfo::close_identity(&stream_clone)
    );
    assert_eq!(
        zmux::StreamInfo::close_identity(&stream),
        zmux::StreamInfo::close_identity(&stream_clone)
    );

    let joined = zmux::join_native_streams(stream.clone(), stream_clone.clone());
    zmux::NativeStreamInfo::close(&joined)?;

    let send = client.open_uni_stream()?;
    let send_clone = send.clone();
    assert_eq!(
        zmux::NativeStreamInfo::close_identity(&send),
        zmux::NativeStreamInfo::close_identity(&send_clone)
    );
    assert_eq!(
        zmux::StreamInfo::close_identity(&send),
        zmux::StreamInfo::close_identity(&send_clone)
    );
    send.write_final(b"identity")?;

    let recv = server.accept_uni_stream_timeout(Duration::from_secs(5))?;
    let recv_clone = recv.clone();
    assert_eq!(
        zmux::NativeStreamInfo::close_identity(&recv),
        zmux::NativeStreamInfo::close_identity(&recv_clone)
    );
    assert_eq!(
        zmux::StreamInfo::close_identity(&recv),
        zmux::StreamInfo::close_identity(&recv_clone)
    );

    let async_joined = zmux::join_streams(recv.clone(), send_clone);
    block_on(zmux::StreamInfo::close(&async_joined))?;

    let _ = client.close();
    let _ = server.close();
    Ok(())
}

#[test]
fn joined_stream_close_closes_supplied_halves_as_full_streams() -> zmux::Result<()> {
    let native_events = Arc::new(Mutex::new(Vec::new()));
    let native = zmux::join_native_streams(
        DirectionalCloseProbe::new("native-read", Arc::clone(&native_events)),
        DirectionalCloseProbe::new("native-write", Arc::clone(&native_events)),
    );

    zmux::NativeStreamInfo::close(&native)?;
    assert_eq!(
        close_events(&native_events),
        vec!["native-write:close", "native-read:close"]
    );

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_joined = zmux::join_streams(
        DirectionalCloseProbe::new("async-read", Arc::clone(&async_events)),
        DirectionalCloseProbe::new("async-write", Arc::clone(&async_events)),
    );

    block_on(zmux::StreamInfo::close(&async_joined))?;
    assert_eq!(
        close_events(&async_events),
        vec!["async-write:close", "async-read:close"]
    );

    Ok(())
}

#[test]
fn joined_stream_close_deduplicates_shared_async_close_identity() -> zmux::Result<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::new(DirectionalCloseProbe::new("shared", Arc::clone(&events)));
    let joined = zmux::join_streams(Arc::clone(&shared), Arc::clone(&shared));

    block_on(zmux::StreamInfo::close(&joined))?;
    assert_eq!(close_events(&events), vec!["shared:close"]);

    events.lock().unwrap().clear();
    let shared = Arc::new(DirectionalCloseProbe::new("shared", Arc::clone(&events)));
    let joined = zmux::join_streams(Arc::clone(&shared), Arc::clone(&shared));

    block_on(zmux::StreamInfo::close_with_error(&joined, 7, "boom"))?;
    assert_eq!(close_events(&events), vec!["shared:close_with_error"]);

    Ok(())
}

#[test]
fn joined_stream_default_close_identity_does_not_dedupe_zero_sized_halves() -> zmux::Result<()> {
    ZERO_SIZED_NATIVE_CLOSES.store(0, Ordering::Relaxed);
    ZERO_SIZED_ASYNC_CLOSES.store(0, Ordering::Relaxed);

    assert!(zmux::NativeStreamInfo::close_identity(&ZeroSizedCloseProbe).is_null());
    assert!(zmux::StreamInfo::close_identity(&ZeroSizedCloseProbe).is_null());

    let native = zmux::join_native_streams(ZeroSizedCloseProbe, ZeroSizedCloseProbe);
    zmux::NativeStreamInfo::close(&native)?;
    assert_eq!(ZERO_SIZED_NATIVE_CLOSES.load(Ordering::Relaxed), 2);

    let async_joined = zmux::join_streams(ZeroSizedCloseProbe, ZeroSizedCloseProbe);
    block_on(zmux::StreamInfo::close(&async_joined))?;
    assert_eq!(ZERO_SIZED_ASYNC_CLOSES.load(Ordering::Relaxed), 2);

    Ok(())
}

#[test]
fn joined_stream_close_ignores_absent_halves_but_fully_closes_present_halves() -> zmux::Result<()> {
    let native_read_events = Arc::new(Mutex::new(Vec::new()));
    let native_read_only =
        zmux::join_optional_native_streams::<DirectionalCloseProbe, DirectionalCloseProbe>(
            Some(DirectionalCloseProbe::new(
                "native-read",
                Arc::clone(&native_read_events),
            )),
            None,
        );
    zmux::NativeSendStreamApi::close_write(&native_read_only)?;
    assert!(close_events(&native_read_events).is_empty());
    zmux::NativeStreamInfo::close(&native_read_only)?;
    assert_eq!(close_events(&native_read_events), vec!["native-read:close"]);

    let native_write_events = Arc::new(Mutex::new(Vec::new()));
    let native_write_only =
        zmux::join_optional_native_streams::<DirectionalCloseProbe, DirectionalCloseProbe>(
            None,
            Some(DirectionalCloseProbe::new(
                "native-write",
                Arc::clone(&native_write_events),
            )),
        );
    zmux::NativeRecvStreamApi::close_read(&native_write_only)?;
    assert!(close_events(&native_write_events).is_empty());
    zmux::NativeStreamInfo::close(&native_write_only)?;
    assert_eq!(
        close_events(&native_write_events),
        vec!["native-write:close"]
    );

    let async_read_events = Arc::new(Mutex::new(Vec::new()));
    let async_read_only = zmux::join_optional_streams::<DirectionalCloseProbe, DirectionalCloseProbe>(
        Some(DirectionalCloseProbe::new(
            "async-read",
            Arc::clone(&async_read_events),
        )),
        None,
    );
    block_on(zmux::SendStreamApi::close_write(&async_read_only))?;
    assert!(close_events(&async_read_events).is_empty());
    block_on(zmux::StreamInfo::close(&async_read_only))?;
    assert_eq!(close_events(&async_read_events), vec!["async-read:close"]);

    let async_write_events = Arc::new(Mutex::new(Vec::new()));
    let async_write_only =
        zmux::join_optional_streams::<DirectionalCloseProbe, DirectionalCloseProbe>(
            None,
            Some(DirectionalCloseProbe::new(
                "async-write",
                Arc::clone(&async_write_events),
            )),
        );
    block_on(zmux::RecvStreamApi::close_read(&async_write_only))?;
    assert!(close_events(&async_write_events).is_empty());
    block_on(zmux::StreamInfo::close(&async_write_only))?;
    assert_eq!(close_events(&async_write_events), vec!["async-write:close"]);

    Ok(())
}

#[test]
fn async_joined_direct_replace_does_not_steal_an_active_pause() -> zmux::Result<()> {
    let joined = zmux::join_streams(
        LabeledStream::new(1, b"read"),
        LabeledStream::new(2, b"write"),
    );
    let paused = joined.pause_read()?;
    let err = match joined.replace_recv(LabeledStream::new(3, b"replacement")) {
        Ok(_) => panic!("replace_recv unexpectedly replaced a paused half"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("joined stream half is paused"));
    paused.resume()?;
    assert_eq!(joined.read_stream_id(), 1);
    Ok(())
}

#[test]
fn async_joined_direct_replace_waits_for_active_io() -> zmux::Result<()> {
    let initial = BlockingAsyncStream::new(1);
    let control = initial.clone();
    let joined = Arc::new(zmux::join_streams(initial, LabeledStream::new(2, b"write")));

    let reader = Arc::clone(&joined);
    let read_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        block_on(zmux::RecvStreamApi::read(&*reader, &mut buf))
    });
    assert!(
        control.wait_read_started(),
        "async read did not enter the attached half"
    );

    let replacer = Arc::clone(&joined);
    let (done_tx, done_rx) = mpsc::channel();
    let replace_thread = thread::spawn(move || {
        let result = replacer
            .replace_recv(BlockingAsyncStream::new(3))
            .map(|previous| previous.map(|stream| stream.id()));
        done_tx.send(result).unwrap();
    });

    assert!(
        done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "replace_recv completed before the active read left the old half"
    );
    control.release_read();
    read_thread.join().unwrap()?;
    let previous = done_rx.recv_timeout(Duration::from_secs(1)).unwrap()?;
    replace_thread.join().unwrap();

    assert_eq!(previous, Some(1));
    assert_eq!(joined.read_stream_id(), 3);
    Ok(())
}

#[test]
fn async_joined_pause_waits_for_active_deadline_replay() -> zmux::Result<()> {
    let initial = BlockingAsyncStream::new(1);
    let control = initial.clone();
    let joined = Arc::new(zmux::join_streams(initial, LabeledStream::new(2, b"write")));

    let deadline_joined = Arc::clone(&joined);
    let deadline_thread = thread::spawn(move || {
        zmux::RecvStreamApi::set_read_deadline(
            &*deadline_joined,
            Some(Instant::now() + Duration::from_secs(30)),
        )
    });
    assert!(
        control.wait_deadline_started(),
        "async read deadline did not enter the attached half"
    );

    let pauser = Arc::clone(&joined);
    let (done_tx, done_rx) = mpsc::channel();
    let pause_thread = thread::spawn(move || {
        let result = pauser
            .pause_read_timeout(Duration::from_secs(1))
            .map(|paused| paused.current().map(|stream| stream.id()));
        done_tx.send(result).unwrap();
    });

    assert!(
        done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "pause_read completed before the active deadline replay finished"
    );
    control.release_deadline();
    deadline_thread.join().unwrap()?;
    let paused_id = done_rx.recv_timeout(Duration::from_secs(1)).unwrap()?;
    pause_thread.join().unwrap();

    assert_eq!(paused_id, Some(1));
    assert_eq!(control.deadline_calls(), 2);
    assert_eq!(joined.read_stream_id(), 1);
    Ok(())
}

#[test]
fn native_joined_half_pause_timeout_does_not_block_behind_active_io() -> zmux::Result<()> {
    let recv = BlockingNativeStream::new();
    let control = recv.clone();
    let joined = Arc::new(zmux::join_native_streams(recv, DummyStream));
    let reader = Arc::clone(&joined);
    let read_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        let _ = zmux::NativeRecvStreamApi::read_timeout(&*reader, &mut buf, Duration::from_secs(5));
    });

    control.wait_started();
    let err = match joined.pause_read_timeout(Duration::from_millis(50)) {
        Ok(_) => panic!("pause_read_timeout unexpectedly paused an active read"),
        Err(err) => err,
    };
    assert!(err.is_timeout());

    control.release();
    read_thread.join().unwrap();
    let paused = joined.pause_read_timeout(Duration::from_secs(1))?;
    paused.resume()?;
    Ok(())
}

#[test]
fn native_joined_active_half_replays_deadline_set_while_io_active() -> zmux::Result<()> {
    let recv = BlockingNativeStream::new();
    let control = recv.clone();
    let joined = Arc::new(zmux::join_native_streams(recv, DummyStream));
    let reader = Arc::clone(&joined);
    let read_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        zmux::NativeRecvStreamApi::read_timeout(&*reader, &mut buf, Duration::from_secs(5))
    });

    control.wait_started();
    let deadline = Instant::now() + Duration::from_secs(30);
    zmux::NativeRecvStreamApi::set_read_deadline(&*joined, Some(deadline))?;
    assert!(
        control.read_deadlines().is_empty(),
        "deadline should wait for the active native half to return"
    );

    control.release();
    read_thread.join().unwrap()?;
    assert_eq!(control.read_deadlines(), vec![Some(deadline)]);
    Ok(())
}

async fn exercise_common_async_session<S>(client: &S, server: &S) -> zmux::Result<()>
where
    S: zmux::Session + ?Sized,
{
    assert!(!zmux::Session::closed(client));
    assert!(!zmux::Session::closed(server));
    assert_eq!(
        zmux::Session::state(client),
        zmux::Session::stats(client).state
    );
    assert_eq!(
        zmux::Session::state(server),
        zmux::Session::stats(server).state
    );

    let outbound = zmux::Session::open_stream(client).await?;
    zmux::StreamInfo::set_deadline(&outbound, Some(Instant::now() + Duration::from_secs(5)))?;
    zmux::StreamInfo::clear_deadline(&outbound)?;
    zmux::SendStreamApi::write_final(&outbound, b"client-to-server").await?;
    let inbound = zmux::Session::accept_stream_timeout(server, Duration::from_secs(5)).await?;
    assert_eq!(
        zmux::RecvStreamApi::read_to_end_limited(&inbound, b"client-to-server".len()).await?,
        b"client-to-server"
    );

    zmux::SendStreamApi::write_final(&inbound, b"server-to-client").await?;
    assert_eq!(read_all_async(&outbound).await?, b"server-to-client");
    zmux::StreamInfo::close(&outbound).await?;
    zmux::StreamInfo::close(&inbound).await?;

    let (outbound, n) = zmux::Session::open_and_send(client, b"open-and-send").await?;
    assert_eq!(n, b"open-and-send".len());
    zmux::SendStreamApi::close_write(&outbound).await?;
    let inbound = zmux::Session::accept_stream_timeout(server, Duration::from_secs(5)).await?;
    assert_eq!(read_all_async(&inbound).await?, b"open-and-send");
    zmux::StreamInfo::close(&outbound).await?;
    zmux::StreamInfo::close(&inbound).await?;

    let parts = [IoSlice::new(b"open-"), IoSlice::new(b"vectored")];
    let (outbound, n) = zmux::Session::open_and_send_vectored(client, &parts).await?;
    assert_eq!(n, b"open-vectored".len());
    zmux::SendStreamApi::close_write(&outbound).await?;
    let inbound = zmux::Session::accept_stream_timeout(server, Duration::from_secs(5)).await?;
    assert_eq!(read_all_async(&inbound).await?, b"open-vectored");
    zmux::StreamInfo::close(&outbound).await?;
    zmux::StreamInfo::close(&inbound).await?;

    let (outbound, n) = zmux::Session::open_uni_and_send(server, b"server-uni").await?;
    assert_eq!(n, b"server-uni".len());
    let inbound = zmux::Session::accept_uni_stream_timeout(client, Duration::from_secs(5)).await?;
    assert_eq!(read_all_async(&inbound).await?, b"server-uni");
    zmux::StreamInfo::close(&outbound).await?;
    zmux::StreamInfo::close(&inbound).await?;
    drop(outbound);

    let parts = [IoSlice::new(b"server-"), IoSlice::new(b"uni-vectored")];
    let (outbound, n) = zmux::Session::open_uni_and_send_vectored(server, &parts).await?;
    assert_eq!(n, b"server-uni-vectored".len());
    let inbound = zmux::Session::accept_uni_stream_timeout(client, Duration::from_secs(5)).await?;
    assert_eq!(read_all_async(&inbound).await?, b"server-uni-vectored");
    zmux::StreamInfo::close(&outbound).await?;
    zmux::StreamInfo::close(&inbound).await?;

    zmux::Session::close(client).await?;
    zmux::Session::close(server).await?;
    assert!(zmux::Session::wait_timeout(client, Duration::from_secs(5)).await?);
    assert!(zmux::Session::wait_timeout(server, Duration::from_secs(5)).await?);
    assert!(zmux::Session::closed(client));
    assert!(zmux::Session::closed(server));
    Ok(())
}

async fn read_all_async<S>(stream: &S) -> zmux::Result<Vec<u8>>
where
    S: zmux::RecvStreamApi + ?Sized,
{
    let mut out = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let n =
            zmux::RecvStreamApi::read_timeout(stream, &mut buffer, Duration::from_secs(5)).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buffer[..n]);
    }
}

fn native_tcp_pair() -> (zmux::Conn, zmux::Conn) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = thread::spawn(move || {
        let socket = TcpStream::connect(addr).unwrap();
        zmux::client_tcp(socket, zmux::Config::default()).unwrap()
    });
    let (socket, _) = listener.accept().unwrap();
    let server = thread::spawn(move || zmux::server_tcp(socket, zmux::Config::default()).unwrap());
    (client.join().unwrap(), server.join().unwrap())
}

fn tcp_duplex_transport(
    socket: TcpStream,
    close_count: Option<Arc<AtomicUsize>>,
) -> zmux::DuplexTransport<TcpStream, TcpStream> {
    let local_addr = socket.local_addr().ok();
    let peer_addr = socket.peer_addr().ok();
    let reader = socket.try_clone().unwrap();
    let close_socket = socket.try_clone().unwrap();
    let transport =
        zmux::DuplexTransport::new(reader, socket).with_addresses(local_addr, peer_addr);
    match close_count {
        Some(close_count) => transport.with_close_fn(move || {
            close_count.fetch_add(1, Ordering::Relaxed);
            close_socket.shutdown(Shutdown::Both)
        }),
        None => transport,
    }
}

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::yield_now(),
        }
    }
}

fn assert_invalid_write_progress<T>(result: zmux::Result<T>) {
    let err = match result {
        Ok(_) => panic!("operation unexpectedly accepted invalid write progress"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("write reported invalid progress"));
}

struct RecordingTransportControl {
    read_timeouts: Arc<AtomicUsize>,
    write_timeouts: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}

impl zmux::DuplexTransportControl for RecordingTransportControl {
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeouts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeouts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        self.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

struct DummyStream;

impl zmux::NativeStreamInfo for DummyStream {
    fn stream_id(&self) -> u64 {
        42
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        3
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
        dst.extend_from_slice(b"api");
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata {
            open_info: b"api".to_vec(),
            ..zmux::StreamMetadata::default()
        }
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> zmux::Result<()> {
        Ok(())
    }
}

impl Read for DummyStream {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let data = b"api";
        let n = dst.len().min(data.len());
        dst[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
}

impl Write for DummyStream {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl zmux::NativeRecvStreamApi for DummyStream {
    fn read_closed(&self) -> bool {
        false
    }

    fn read_timeout(&self, dst: &mut [u8], _timeout: Duration) -> zmux::Result<usize> {
        let data = b"api";
        let n = dst.len().min(data.len());
        dst[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_read(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeSendStreamApi for DummyStream {
    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn writev(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final(&self, src: &[u8]) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_write(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamApi for DummyStream {}

#[derive(Clone, Copy)]
struct InvalidProgressStream {
    read_n: usize,
    write_n: usize,
}

impl InvalidProgressStream {
    fn read_progress(n: usize) -> Self {
        Self {
            read_n: n,
            write_n: 0,
        }
    }

    fn write_progress(n: usize) -> Self {
        Self {
            read_n: 0,
            write_n: n,
        }
    }
}

impl Read for InvalidProgressStream {
    fn read(&mut self, _dst: &mut [u8]) -> io::Result<usize> {
        Ok(self.read_n)
    }
}

impl Write for InvalidProgressStream {
    fn write(&mut self, _src: &[u8]) -> io::Result<usize> {
        Ok(self.write_n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamInfo for InvalidProgressStream {
    fn stream_id(&self) -> u64 {
        77
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeRecvStreamApi for InvalidProgressStream {
    fn read_closed(&self) -> bool {
        false
    }

    fn read_timeout(&self, _dst: &mut [u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(self.read_n)
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_read(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeSendStreamApi for InvalidProgressStream {
    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, _src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn writev(&self, _parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_vectored_timeout(
        &self,
        _parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_final(&self, _src: &[u8]) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_vectored_final(&self, _parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_final_timeout(&self, _src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_vectored_final_timeout(
        &self,
        _parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_write(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamApi for InvalidProgressStream {}

impl zmux::StreamInfo for InvalidProgressStream {
    fn stream_id(&self) -> u64 {
        77
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::RecvStreamApi for InvalidProgressStream {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.read_n) })
    }

    fn read_timeout<'a>(
        &'a self,
        _dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.read_n) })
    }

    fn read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::SendStreamApi for InvalidProgressStream {
    fn write<'a>(&'a self, _src: &'a [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.write_n) })
    }

    fn write_timeout<'a>(
        &'a self,
        _src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.write_n) })
    }

    fn write_final_timeout<'a>(
        &'a self,
        _src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.write_n) })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        _parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.write_n) })
    }

    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::StreamApi for InvalidProgressStream {}

#[derive(Clone)]
struct LabeledStream {
    id: u64,
    data: &'static [u8],
}

impl LabeledStream {
    fn new(id: u64, data: &'static [u8]) -> Self {
        Self { id, data }
    }
}

impl Read for LabeledStream {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let n = dst.len().min(self.data.len());
        dst[..n].copy_from_slice(&self.data[..n]);
        Ok(n)
    }

    fn read_vectored(&mut self, dsts: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let mut copied = 0;
        for dst in dsts {
            if copied == self.data.len() {
                break;
            }
            let n = dst.len().min(self.data.len() - copied);
            dst[..n].copy_from_slice(&self.data[copied..copied + n]);
            copied += n;
        }
        Ok(copied)
    }
}

impl Write for LabeledStream {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamInfo for LabeledStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        self.data.len()
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
        dst.extend_from_slice(self.data);
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata {
            open_info: self.data.to_vec(),
            ..zmux::StreamMetadata::default()
        }
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeRecvStreamApi for LabeledStream {
    fn read_closed(&self) -> bool {
        false
    }

    fn read_timeout(&self, dst: &mut [u8], _timeout: Duration) -> zmux::Result<usize> {
        let n = dst.len().min(self.data.len());
        dst[..n].copy_from_slice(&self.data[..n]);
        Ok(n)
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_read(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeSendStreamApi for LabeledStream {
    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn writev(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final(&self, src: &[u8]) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_write(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamApi for LabeledStream {}

#[derive(Clone)]
struct BlockingNativeStream {
    state: Arc<(Mutex<BlockingReadState>, Condvar)>,
}

struct BlockingReadState {
    started: bool,
    released: bool,
    read_deadlines: Vec<Option<Instant>>,
}

impl BlockingNativeStream {
    fn new() -> Self {
        Self {
            state: Arc::new((
                Mutex::new(BlockingReadState {
                    started: false,
                    released: false,
                    read_deadlines: Vec::new(),
                }),
                Condvar::new(),
            )),
        }
    }

    fn wait_started(&self) {
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().unwrap();
        while !state.started {
            state = cond.wait(state).unwrap();
        }
    }

    fn release(&self) {
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.released = true;
        cond.notify_all();
    }

    fn read_deadlines(&self) -> Vec<Option<Instant>> {
        let (lock, _) = &*self.state;
        lock.lock().unwrap().read_deadlines.clone()
    }

    fn wait_for_release(&self) {
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.started = true;
        cond.notify_all();
        while !state.released {
            state = cond.wait(state).unwrap();
        }
    }
}

impl Read for BlockingNativeStream {
    fn read(&mut self, _dst: &mut [u8]) -> io::Result<usize> {
        self.wait_for_release();
        Ok(0)
    }
}

impl zmux::NativeStreamInfo for BlockingNativeStream {
    fn stream_id(&self) -> u64 {
        99
    }

    fn opened_locally(&self) -> bool {
        false
    }

    fn bidirectional(&self) -> bool {
        false
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::Result<()> {
        self.release();
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> zmux::Result<()> {
        self.release();
        Ok(())
    }
}

impl zmux::NativeRecvStreamApi for BlockingNativeStream {
    fn read_closed(&self) -> bool {
        false
    }

    fn read_timeout(&self, _dst: &mut [u8], _timeout: Duration) -> zmux::Result<usize> {
        self.wait_for_release();
        Ok(0)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        let (lock, cond) = &*self.state;
        lock.lock().unwrap().read_deadlines.push(deadline);
        cond.notify_all();
        Ok(())
    }

    fn close_read(&self) -> zmux::Result<()> {
        self.release();
        Ok(())
    }

    fn cancel_read(&self, _code: u64) -> zmux::Result<()> {
        self.release();
        Ok(())
    }
}

#[derive(Clone)]
struct BlockingAsyncStream {
    id: u64,
    state: Arc<(Mutex<BlockingAsyncState>, Condvar)>,
}

struct BlockingAsyncState {
    read_started: bool,
    read_released: bool,
    deadline_started: bool,
    deadline_released: bool,
    deadline_calls: usize,
}

impl BlockingAsyncStream {
    fn new(id: u64) -> Self {
        Self {
            id,
            state: Arc::new((
                Mutex::new(BlockingAsyncState {
                    read_started: false,
                    read_released: false,
                    deadline_started: false,
                    deadline_released: false,
                    deadline_calls: 0,
                }),
                Condvar::new(),
            )),
        }
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn wait_read_started(&self) -> bool {
        self.wait_until(|state| state.read_started)
    }

    fn wait_deadline_started(&self) -> bool {
        self.wait_until(|state| state.deadline_started)
    }

    fn release_read(&self) {
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.read_released = true;
        cond.notify_all();
    }

    fn release_deadline(&self) {
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.deadline_released = true;
        cond.notify_all();
    }

    fn deadline_calls(&self) -> usize {
        let (lock, _) = &*self.state;
        lock.lock().unwrap().deadline_calls
    }

    fn wait_until(&self, ready: impl Fn(&BlockingAsyncState) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().unwrap();
        while !ready(&state) {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let (next, wait) = cond.wait_timeout(state, remaining).unwrap();
            state = next;
            if wait.timed_out() && !ready(&state) {
                return false;
            }
        }
        true
    }

    fn wait_for_read_release(&self) {
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.read_started = true;
        cond.notify_all();
        while !state.read_released {
            state = cond.wait(state).unwrap();
        }
    }

    fn block_first_deadline(&self) {
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.deadline_calls += 1;
        if state.deadline_calls != 1 {
            return;
        }
        state.deadline_started = true;
        cond.notify_all();
        while !state.deadline_released {
            state = cond.wait(state).unwrap();
        }
    }
}

impl zmux::StreamInfo for BlockingAsyncStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn opened_locally(&self) -> bool {
        false
    }

    fn bidirectional(&self) -> bool {
        false
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move {
            self.release_read();
            Ok(())
        })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async move {
            self.release_read();
            Ok(())
        })
    }
}

impl zmux::RecvStreamApi for BlockingAsyncStream {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.wait_for_read_release();
            Ok(0)
        })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn read_closed(&self) -> bool {
        false
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        self.block_first_deadline();
        Ok(())
    }

    fn close_read(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move {
            self.release_read();
            Ok(())
        })
    }

    fn cancel_read(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move {
            self.release_read();
            Ok(())
        })
    }
}

impl zmux::StreamInfo for LabeledStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        self.data.len()
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
        dst.extend_from_slice(self.data);
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata {
            open_info: self.data.to_vec(),
            ..zmux::StreamMetadata::default()
        }
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::RecvStreamApi for LabeledStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            let n = dst.len().min(self.data.len());
            dst[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        })
    }

    fn read_vectored<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            let mut copied = 0;
            for dst in dsts {
                if copied == self.data.len() {
                    break;
                }
                let n = dst.len().min(self.data.len() - copied);
                dst[..n].copy_from_slice(&self.data[copied..copied + n]);
                copied += n;
            }
            Ok(copied)
        })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn read_vectored_timeout<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.read_vectored(dsts)
    }

    fn read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::SendStreamApi for LabeledStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::StreamApi for LabeledStream {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadlineSide {
    Stream,
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeadlineEvent {
    id: u64,
    side: DeadlineSide,
    deadline: Option<Instant>,
}

impl DeadlineEvent {
    fn new(id: u64, side: DeadlineSide, deadline: Option<Instant>) -> Self {
        Self { id, side, deadline }
    }
}

#[derive(Clone)]
struct DeadlineProbeStream {
    id: u64,
    events: Arc<Mutex<Vec<DeadlineEvent>>>,
    blocker: Option<Arc<DeadlineProbeBlocker>>,
    fail_deadlines: bool,
}

struct DeadlineProbeBlocker {
    state: Mutex<DeadlineProbeBlockerState>,
    changed: Condvar,
}

struct DeadlineProbeBlockerState {
    calls: usize,
    first_started: bool,
    released: bool,
}

impl DeadlineProbeStream {
    fn new(id: u64, events: Arc<Mutex<Vec<DeadlineEvent>>>) -> Self {
        Self {
            id,
            events,
            blocker: None,
            fail_deadlines: false,
        }
    }

    fn blocking_deadlines(id: u64, events: Arc<Mutex<Vec<DeadlineEvent>>>) -> Self {
        Self {
            id,
            events,
            blocker: Some(Arc::new(DeadlineProbeBlocker::new())),
            fail_deadlines: false,
        }
    }

    fn failing_deadlines(id: u64, events: Arc<Mutex<Vec<DeadlineEvent>>>) -> Self {
        Self {
            id,
            events,
            blocker: None,
            fail_deadlines: true,
        }
    }

    fn record(&self, side: DeadlineSide, deadline: Option<Instant>) {
        self.events
            .lock()
            .unwrap()
            .push(DeadlineEvent::new(self.id, side, deadline));
        if let Some(blocker) = &self.blocker {
            blocker.block_first_call();
        }
    }

    fn record_deadline(&self, side: DeadlineSide, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record(side, deadline);
        if self.fail_deadlines {
            Err(zmux::Error::local("deadline probe failure"))
        } else {
            Ok(())
        }
    }

    fn wait_first_deadline_started(&self) -> bool {
        match &self.blocker {
            Some(blocker) => blocker.wait_first_started(),
            None => false,
        }
    }

    fn release_deadline(&self) {
        if let Some(blocker) = &self.blocker {
            blocker.release();
        }
    }
}

impl DeadlineProbeBlocker {
    fn new() -> Self {
        Self {
            state: Mutex::new(DeadlineProbeBlockerState {
                calls: 0,
                first_started: false,
                released: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn block_first_call(&self) {
        let mut state = self.state.lock().unwrap();
        state.calls += 1;
        if state.calls != 1 {
            return;
        }
        state.first_started = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn wait_first_started(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut state = self.state.lock().unwrap();
        while !state.first_started {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let (next, wait) = self.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if wait.timed_out() && !state.first_started {
                return false;
            }
        }
        true
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.released = true;
        self.changed.notify_all();
    }
}

fn assert_deadline_event(events: &Arc<Mutex<Vec<DeadlineEvent>>>, expected: DeadlineEvent) {
    let events = events.lock().unwrap();
    assert!(
        events.contains(&expected),
        "missing {expected:?} in {events:?}"
    );
}

fn deadline_events_for(
    events: &Arc<Mutex<Vec<DeadlineEvent>>>,
    id: u64,
    side: DeadlineSide,
) -> Vec<Option<Instant>> {
    events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.id == id && event.side == side)
        .map(|event| event.deadline)
        .collect()
}

impl Read for DeadlineProbeStream {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let data = b"deadline";
        let n = dst.len().min(data.len());
        dst[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
}

impl Write for DeadlineProbeStream {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamInfo for DeadlineProbeStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Stream, deadline)
    }

    fn close(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeRecvStreamApi for DeadlineProbeStream {
    fn read_closed(&self) -> bool {
        false
    }

    fn read_timeout(&self, dst: &mut [u8], _timeout: Duration) -> zmux::Result<usize> {
        let data = b"deadline";
        let n = dst.len().min(data.len());
        dst[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Read, deadline)
    }

    fn close_read(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_read(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeSendStreamApi for DeadlineProbeStream {
    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn writev(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final(&self, src: &[u8]) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Write, deadline)
    }

    fn close_write(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_write(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamApi for DeadlineProbeStream {}

impl zmux::StreamInfo for DeadlineProbeStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Stream, deadline)
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::RecvStreamApi for DeadlineProbeStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            let data = b"deadline";
            let n = dst.len().min(data.len());
            dst[..n].copy_from_slice(&data[..n]);
            Ok(n)
        })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn read_closed(&self) -> bool {
        false
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Read, deadline)
    }

    fn close_read(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::SendStreamApi for DeadlineProbeStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn write_closed(&self) -> bool {
        false
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Write, deadline)
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::StreamApi for DeadlineProbeStream {}

#[derive(Clone)]
struct DirectionalCloseProbe {
    label: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

impl DirectionalCloseProbe {
    fn new(label: &'static str, events: Arc<Mutex<Vec<String>>>) -> Self {
        Self { label, events }
    }

    fn record(&self, operation: &'static str) {
        self.events
            .lock()
            .unwrap()
            .push(format!("{}:{operation}", self.label));
    }
}

fn close_events(events: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    events.lock().unwrap().clone()
}

impl Read for DirectionalCloseProbe {
    fn read(&mut self, _dst: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for DirectionalCloseProbe {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamInfo for DirectionalCloseProbe {
    fn stream_id(&self) -> u64 {
        0
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::Result<()> {
        self.record("close");
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> zmux::Result<()> {
        self.record("close_with_error");
        Ok(())
    }
}

impl zmux::NativeRecvStreamApi for DirectionalCloseProbe {
    fn read_closed(&self) -> bool {
        false
    }

    fn read_timeout(&self, _dst: &mut [u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(0)
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::Result<()> {
        self.record("close_read");
        Ok(())
    }

    fn cancel_read(&self, _code: u64) -> zmux::Result<()> {
        self.record("cancel_read");
        Ok(())
    }
}

impl zmux::NativeSendStreamApi for DirectionalCloseProbe {
    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn writev(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final(&self, src: &[u8]) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> zmux::Result<()> {
        self.record("close_write");
        Ok(())
    }

    fn cancel_write(&self, _code: u64) -> zmux::Result<()> {
        self.record("cancel_write");
        Ok(())
    }
}

impl zmux::NativeStreamApi for DirectionalCloseProbe {}

impl zmux::StreamInfo for DirectionalCloseProbe {
    fn stream_id(&self) -> u64 {
        0
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        self.record("close");
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        self.record("close_with_error");
        Box::pin(async { Ok(()) })
    }
}

impl zmux::RecvStreamApi for DirectionalCloseProbe {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn read_closed(&self) -> bool {
        false
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        self.record("close_read");
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        self.record("cancel_read");
        Box::pin(async { Ok(()) })
    }
}

impl zmux::SendStreamApi for DirectionalCloseProbe {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn write_closed(&self) -> bool {
        false
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        self.record("close_write");
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        self.record("cancel_write");
        Box::pin(async { Ok(()) })
    }
}

impl zmux::StreamApi for DirectionalCloseProbe {}

static ZERO_SIZED_NATIVE_CLOSES: AtomicUsize = AtomicUsize::new(0);
static ZERO_SIZED_ASYNC_CLOSES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
struct ZeroSizedCloseProbe;

impl Read for ZeroSizedCloseProbe {
    fn read(&mut self, _dst: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for ZeroSizedCloseProbe {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamInfo for ZeroSizedCloseProbe {
    fn stream_id(&self) -> u64 {
        0
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::Result<()> {
        ZERO_SIZED_NATIVE_CLOSES.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> zmux::Result<()> {
        zmux::NativeStreamInfo::close(self)
    }
}

impl zmux::NativeRecvStreamApi for ZeroSizedCloseProbe {
    fn read_closed(&self) -> bool {
        false
    }

    fn read_timeout(&self, _dst: &mut [u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(0)
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_read(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeSendStreamApi for ZeroSizedCloseProbe {
    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn writev(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final(&self, src: &[u8]) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn write_final_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.writev(parts)
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn cancel_write(&self, _code: u64) -> zmux::Result<()> {
        Ok(())
    }
}

impl zmux::NativeStreamApi for ZeroSizedCloseProbe {}

impl zmux::StreamInfo for ZeroSizedCloseProbe {
    fn stream_id(&self) -> u64 {
        0
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        ZERO_SIZED_ASYNC_CLOSES.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        zmux::StreamInfo::close(self)
    }
}

impl zmux::RecvStreamApi for ZeroSizedCloseProbe {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn read_closed(&self) -> bool {
        false
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::SendStreamApi for ZeroSizedCloseProbe {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn write_closed(&self) -> bool {
        false
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::StreamApi for ZeroSizedCloseProbe {}

struct TimeoutBudgetAsyncSession {
    open_delay: Duration,
    write_timeouts: Arc<Mutex<Vec<Duration>>>,
    write_attempts: Arc<AtomicUsize>,
}

impl TimeoutBudgetAsyncSession {
    fn stream(&self) -> TimeoutBudgetAsyncStream {
        TimeoutBudgetAsyncStream {
            write_timeouts: Arc::clone(&self.write_timeouts),
            write_attempts: Arc::clone(&self.write_attempts),
        }
    }
}

impl zmux::Session for TimeoutBudgetAsyncSession {
    type Stream = TimeoutBudgetAsyncStream;
    type SendStream = TimeoutBudgetAsyncStream;
    type RecvStream = TimeoutBudgetAsyncStream;

    fn accept_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async move { Ok(self.stream()) })
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::RecvStream>> {
        Box::pin(async move { Ok(self.stream()) })
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::RecvStream>> {
        self.accept_uni_stream()
    }

    fn open_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async move { Ok(self.stream()) })
    }

    fn open_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        let open_delay = self.open_delay;
        let stream = self.stream();
        Box::pin(async move {
            thread::sleep(open_delay);
            Ok(stream)
        })
    }

    fn open_uni_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        Box::pin(async move { Ok(self.stream()) })
    }

    fn open_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        let open_delay = self.open_delay;
        let stream = self.stream();
        Box::pin(async move {
            thread::sleep(open_delay);
            Ok(stream)
        })
    }

    fn open_stream_with_options(
        &self,
        opts: zmux::OpenOptions,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        let stream = self.stream();
        Box::pin(async move {
            opts.validate()?;
            Ok(stream)
        })
    }

    fn open_stream_with_options_timeout(
        &self,
        opts: zmux::OpenOptions,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        let open_delay = self.open_delay;
        let stream = self.stream();
        Box::pin(async move {
            opts.validate()?;
            thread::sleep(open_delay);
            Ok(stream)
        })
    }

    fn open_uni_stream_with_options(
        &self,
        opts: zmux::OpenOptions,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        let stream = self.stream();
        Box::pin(async move {
            opts.validate()?;
            Ok(stream)
        })
    }

    fn open_uni_stream_with_options_timeout(
        &self,
        opts: zmux::OpenOptions,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        let open_delay = self.open_delay;
        let stream = self.stream();
        Box::pin(async move {
            opts.validate()?;
            thread::sleep(open_delay);
            Ok(stream)
        })
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::BoxFuture<'_, zmux::Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn closed(&self) -> bool {
        false
    }

    fn close_error(&self) -> Option<zmux::Error> {
        None
    }

    fn state(&self) -> zmux::SessionState {
        zmux::SessionState::Ready
    }

    fn stats(&self) -> zmux::SessionStats {
        empty_stats()
    }
}

struct TimeoutBudgetAsyncStream {
    write_timeouts: Arc<Mutex<Vec<Duration>>>,
    write_attempts: Arc<AtomicUsize>,
}

impl TimeoutBudgetAsyncStream {
    fn record_write_timeout(&self, timeout: Duration) {
        self.write_attempts.fetch_add(1, Ordering::Relaxed);
        self.write_timeouts.lock().unwrap().push(timeout);
    }
}

impl zmux::StreamInfo for TimeoutBudgetAsyncStream {
    fn stream_id(&self) -> u64 {
        7
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::RecvStreamApi for TimeoutBudgetAsyncStream {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::SendStreamApi for TimeoutBudgetAsyncStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.write_attempts.fetch_add(1, Ordering::Relaxed);
            Ok(src.len())
        })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.record_write_timeout(timeout);
            Ok(src.len())
        })
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.record_write_timeout(timeout);
            Ok(src.len())
        })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.record_write_timeout(timeout);
            Ok(parts.iter().map(|part| part.len()).sum())
        })
    }

    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::StreamApi for TimeoutBudgetAsyncStream {}

struct DummyAsyncStream;

impl zmux::StreamInfo for DummyAsyncStream {
    fn stream_id(&self) -> u64 {
        42
    }

    fn opened_locally(&self) -> bool {
        true
    }

    fn bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        3
    }

    fn copy_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.clear();
        dst.extend_from_slice(b"api");
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata {
            open_info: b"api".to_vec(),
            ..zmux::StreamMetadata::default()
        }
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::RecvStreamApi for DummyAsyncStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            let data = b"api";
            let n = dst.len().min(data.len());
            dst[..n].copy_from_slice(&data[..n]);
            Ok(n)
        })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::SendStreamApi for DummyAsyncStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::BoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::StreamApi for DummyAsyncStream {}

struct InvalidProgressAsyncSession;

impl InvalidProgressAsyncSession {
    fn stream() -> InvalidProgressStream {
        InvalidProgressStream::write_progress(4)
    }
}

impl zmux::Session for InvalidProgressAsyncSession {
    type Stream = InvalidProgressStream;
    type SendStream = InvalidProgressStream;
    type RecvStream = InvalidProgressStream;

    fn accept_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async { Err(zmux::Error::session_closed()) })
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::RecvStream>> {
        Box::pin(async { Err(zmux::Error::session_closed()) })
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::RecvStream>> {
        self.accept_uni_stream()
    }

    fn open_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async { Ok(InvalidProgressAsyncSession::stream()) })
    }

    fn open_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        self.open_stream()
    }

    fn open_uni_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        Box::pin(async { Ok(InvalidProgressAsyncSession::stream()) })
    }

    fn open_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        self.open_uni_stream()
    }

    fn open_stream_with_options(
        &self,
        _opts: zmux::OpenOptions,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        self.open_stream()
    }

    fn open_stream_with_options_timeout(
        &self,
        _opts: zmux::OpenOptions,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        self.open_stream()
    }

    fn open_uni_stream_with_options(
        &self,
        _opts: zmux::OpenOptions,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        self.open_uni_stream()
    }

    fn open_uni_stream_with_options_timeout(
        &self,
        _opts: zmux::OpenOptions,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        self.open_uni_stream()
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::BoxFuture<'_, zmux::Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn closed(&self) -> bool {
        false
    }

    fn close_error(&self) -> Option<zmux::Error> {
        None
    }

    fn state(&self) -> zmux::SessionState {
        zmux::SessionState::Ready
    }

    fn stats(&self) -> zmux::SessionStats {
        zmux::SessionStats::empty(zmux::SessionState::Ready)
    }
}

struct DummyAsyncSession;

impl zmux::Session for DummyAsyncSession {
    type Stream = DummyAsyncStream;
    type SendStream = DummyAsyncStream;
    type RecvStream = DummyAsyncStream;

    fn accept_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async { Ok(DummyAsyncStream) })
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::RecvStream>> {
        Box::pin(async { Ok(DummyAsyncStream) })
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::RecvStream>> {
        self.accept_uni_stream()
    }

    fn open_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async { Ok(DummyAsyncStream) })
    }

    fn open_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        self.open_stream()
    }

    fn open_uni_stream(&self) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        Box::pin(async { Ok(DummyAsyncStream) })
    }

    fn open_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        self.open_uni_stream()
    }

    fn open_stream_with_options(
        &self,
        opts: zmux::OpenOptions,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async move {
            opts.validate()?;
            Ok(DummyAsyncStream)
        })
    }

    fn open_stream_with_options_timeout(
        &self,
        opts: zmux::OpenOptions,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::Stream>> {
        self.open_stream_with_options(opts)
    }

    fn open_uni_stream_with_options(
        &self,
        opts: zmux::OpenOptions,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        Box::pin(async move {
            opts.validate()?;
            Ok(DummyAsyncStream)
        })
    }

    fn open_uni_stream_with_options_timeout(
        &self,
        opts: zmux::OpenOptions,
        _timeout: Duration,
    ) -> zmux::BoxFuture<'_, zmux::Result<Self::SendStream>> {
        self.open_uni_stream_with_options(opts)
    }

    fn close(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::BoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> zmux::BoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::BoxFuture<'_, zmux::Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn closed(&self) -> bool {
        false
    }

    fn close_error(&self) -> Option<zmux::Error> {
        None
    }

    fn state(&self) -> zmux::SessionState {
        zmux::SessionState::Ready
    }

    fn stats(&self) -> zmux::SessionStats {
        empty_stats()
    }
}

struct DummySession;

impl zmux::NativeSession for DummySession {
    fn accept_stream(&self) -> zmux::Result<zmux::BoxNativeStream> {
        Ok(Box::new(DummyStream))
    }

    fn accept_stream_timeout(&self, _timeout: Duration) -> zmux::Result<zmux::BoxNativeStream> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::Result<zmux::BoxNativeRecvStream> {
        Ok(Box::new(DummyStream))
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::Result<zmux::BoxNativeRecvStream> {
        self.accept_uni_stream()
    }

    fn open_stream(&self) -> zmux::Result<zmux::BoxNativeStream> {
        Ok(Box::new(DummyStream))
    }

    fn open_stream_timeout(&self, _timeout: Duration) -> zmux::Result<zmux::BoxNativeStream> {
        self.open_stream()
    }

    fn open_uni_stream(&self) -> zmux::Result<zmux::BoxNativeSendStream> {
        Ok(Box::new(DummyStream))
    }

    fn open_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::Result<zmux::BoxNativeSendStream> {
        self.open_uni_stream()
    }

    fn open_stream_with_options(
        &self,
        opts: zmux::OpenOptions,
    ) -> zmux::Result<zmux::BoxNativeStream> {
        opts.validate()?;
        self.open_stream()
    }

    fn open_stream_with_options_timeout(
        &self,
        opts: zmux::OpenOptions,
        _timeout: Duration,
    ) -> zmux::Result<zmux::BoxNativeStream> {
        self.open_stream_with_options(opts)
    }

    fn open_uni_stream_with_options(
        &self,
        opts: zmux::OpenOptions,
    ) -> zmux::Result<zmux::BoxNativeSendStream> {
        opts.validate()?;
        self.open_uni_stream()
    }

    fn open_uni_stream_with_options_timeout(
        &self,
        opts: zmux::OpenOptions,
        _timeout: Duration,
    ) -> zmux::Result<zmux::BoxNativeSendStream> {
        self.open_uni_stream_with_options(opts)
    }

    fn open_and_send(&self, data: &[u8]) -> zmux::Result<(zmux::BoxNativeStream, usize)> {
        Ok((Box::new(DummyStream), data.len()))
    }

    fn open_and_send_timeout(
        &self,
        data: &[u8],
        _timeout: Duration,
    ) -> zmux::Result<(zmux::BoxNativeStream, usize)> {
        self.open_and_send(data)
    }

    fn open_and_send_with_options(
        &self,
        opts: zmux::OpenOptions,
        data: &[u8],
    ) -> zmux::Result<(zmux::BoxNativeStream, usize)> {
        opts.validate()?;
        self.open_and_send(data)
    }

    fn open_and_send_with_options_timeout(
        &self,
        opts: zmux::OpenOptions,
        data: &[u8],
        _timeout: Duration,
    ) -> zmux::Result<(zmux::BoxNativeStream, usize)> {
        self.open_and_send_with_options(opts, data)
    }

    fn open_uni_and_send(&self, data: &[u8]) -> zmux::Result<(zmux::BoxNativeSendStream, usize)> {
        Ok((Box::new(DummyStream), data.len()))
    }

    fn open_uni_and_send_timeout(
        &self,
        data: &[u8],
        _timeout: Duration,
    ) -> zmux::Result<(zmux::BoxNativeSendStream, usize)> {
        self.open_uni_and_send(data)
    }

    fn open_uni_and_send_with_options(
        &self,
        opts: zmux::OpenOptions,
        data: &[u8],
    ) -> zmux::Result<(zmux::BoxNativeSendStream, usize)> {
        opts.validate()?;
        self.open_uni_and_send(data)
    }

    fn open_uni_and_send_with_options_timeout(
        &self,
        opts: zmux::OpenOptions,
        data: &[u8],
        _timeout: Duration,
    ) -> zmux::Result<(zmux::BoxNativeSendStream, usize)> {
        self.open_uni_and_send_with_options(opts, data)
    }

    fn ping(&self, _echo: &[u8]) -> zmux::Result<Duration> {
        Ok(Duration::from_millis(1))
    }

    fn ping_timeout(&self, echo: &[u8], _timeout: Duration) -> zmux::Result<Duration> {
        self.ping(echo)
    }

    fn goaway(&self, _last_accepted_bidi: u64, _last_accepted_uni: u64) -> zmux::Result<()> {
        Ok(())
    }

    fn goaway_with_error(
        &self,
        _last_accepted_bidi: u64,
        _last_accepted_uni: u64,
        _code: u64,
        _reason: &str,
    ) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> zmux::Result<()> {
        Ok(())
    }

    fn wait(&self) -> zmux::Result<()> {
        Ok(())
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::Result<bool> {
        Ok(true)
    }

    fn closed(&self) -> bool {
        false
    }

    fn close_error(&self) -> Option<zmux::Error> {
        None
    }

    fn state(&self) -> zmux::SessionState {
        zmux::SessionState::Ready
    }

    fn stats(&self) -> zmux::SessionStats {
        empty_stats()
    }

    fn peer_goaway_error(&self) -> Option<zmux::PeerGoAwayError> {
        None
    }

    fn peer_close_error(&self) -> Option<zmux::PeerCloseError> {
        None
    }

    fn local_preface(&self) -> zmux::Preface {
        test_preface(zmux::Role::Initiator)
    }

    fn peer_preface(&self) -> zmux::Preface {
        test_preface(zmux::Role::Responder)
    }

    fn negotiated(&self) -> zmux::Negotiated {
        zmux::Negotiated {
            proto: zmux::PROTO_VERSION,
            capabilities: common_capabilities(),
            local_role: zmux::Role::Initiator,
            peer_role: zmux::Role::Responder,
            peer_settings: zmux::Settings::DEFAULT,
        }
    }
}

fn test_preface(role: zmux::Role) -> zmux::Preface {
    zmux::Preface {
        preface_version: zmux::PREFACE_VERSION,
        role,
        tie_breaker_nonce: 0,
        min_proto: zmux::PROTO_VERSION,
        max_proto: zmux::PROTO_VERSION,
        capabilities: common_capabilities(),
        settings: zmux::Settings::DEFAULT,
    }
}

fn common_capabilities() -> u64 {
    zmux::CAPABILITY_OPEN_METADATA
        | zmux::CAPABILITY_PRIORITY_UPDATE
        | zmux::CAPABILITY_PRIORITY_HINTS
        | zmux::CAPABILITY_STREAM_GROUPS
}

fn empty_stats() -> zmux::SessionStats {
    zmux::SessionStats::empty(zmux::SessionState::Ready)
}
