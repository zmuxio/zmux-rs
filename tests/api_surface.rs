use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

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
        zmux::SchedulerHint::from_u64(4),
        zmux::SchedulerHint::GroupFair
    );
    assert_eq!(
        zmux::SchedulerHint::from_u64(99),
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
        zmux::ErrorCode::from_u64(13),
        Some(zmux::ErrorCode::Internal)
    );
    assert!(zmux::ErrorCode::from_u64(99).is_none());

    assert_eq!(zmux::FrameType::from_u8(1).unwrap(), zmux::FrameType::Data);
    assert_eq!(zmux::FrameType::from_u8(11).unwrap(), zmux::FrameType::Ext);
    assert_eq!(zmux::FrameType::from_u8(4).unwrap(), zmux::FrameType::Ping);
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
fn public_config_builders_remain_ergonomic() {
    let default = zmux::Config::default();
    assert_eq!(default.role, zmux::Role::Auto);
    assert_eq!(default.min_proto, zmux::PROTO_VERSION);
    assert_eq!(default.max_proto, zmux::PROTO_VERSION);
    assert_eq!(default.settings, zmux::Settings::DEFAULT);
    assert!(!default.preface_padding);
    assert!(!default.ping_padding);

    let initiator = zmux::Config::initiator();
    assert_eq!(initiator.role, zmux::Role::Initiator);
    assert_eq!(
        zmux::Config::responder().role(zmux::Role::Auto).role,
        zmux::Role::Auto
    );
    let cfg = zmux::Config::default()
        .capabilities(zmux::CAPABILITY_OPEN_METADATA)
        .enable_capabilities(zmux::CAPABILITY_PRIORITY_HINTS)
        .settings(zmux::Settings {
            max_frame_payload: 32 * 1024,
            ..zmux::Settings::DEFAULT
        });
    assert_eq!(
        cfg.capabilities,
        zmux::CAPABILITY_OPEN_METADATA | zmux::CAPABILITY_PRIORITY_HINTS
    );
    assert_eq!(cfg.settings.max_frame_payload, 32 * 1024);

    let opts = zmux::OpenOptions::new()
        .priority(zmux::MAX_VARINT62)
        .group(9)
        .open_info(b"hello");
    assert_eq!(opts.initial_priority(), Some(zmux::MAX_VARINT62));
    assert_eq!(opts.initial_group(), Some(9));
    assert_eq!(opts.open_info_bytes(), b"hello");
    assert_eq!(
        zmux::OpenOptions::new()
            .open_info(b"borrowed")
            .open_info_bytes(),
        b"borrowed"
    );
    let open_info_buf = vec![0, 1, 2, 3];
    assert_eq!(
        zmux::OpenOptions::new()
            .open_info(&open_info_buf)
            .open_info_bytes(),
        open_info_buf.as_slice()
    );
    assert_eq!(
        zmux::OpenOptions::new()
            .open_info(open_info_buf.as_slice())
            .open_info_bytes(),
        open_info_buf.as_slice()
    );
    assert_eq!(
        zmux::OpenOptions::new()
            .open_info(open_info_buf.clone())
            .open_info_bytes(),
        open_info_buf.as_slice()
    );
    assert!(opts.validate().is_ok());
    assert!(zmux::OpenOptions::new()
        .group(zmux::MAX_VARINT62 + 1)
        .validate()
        .is_err());

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
    assert_eq!(views[0].try_to_owned()?.value, b"value");
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

    let update = zmux::MetadataUpdate::new().priority(11).group(12);
    update.validate()?;
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
    let goaway = zmux::build_go_away_payload(0, 0, 8, "drain")?;
    assert_eq!(zmux::parse_go_away_payload(&goaway)?.reason, "drain");

    let preface = test_preface_role(zmux::Role::Initiator);
    let preface_bytes = preface.marshal_with_settings_padding(b"pad")?;
    let (parsed, consumed) = zmux::parse_preface_prefix(&preface_bytes)?;
    assert_eq!(parsed, preface);
    assert_eq!(consumed, preface_bytes.len());
    assert_eq!(zmux::parse_preface(&preface_bytes)?, preface);
    let mut preface_with_trailing = preface_bytes.clone();
    preface_with_trailing.push(0);
    assert!(zmux::parse_preface(&preface_with_trailing).is_err());

    let peer = test_preface_role(zmux::Role::Responder);
    let negotiated = zmux::negotiate_prefaces(&preface, &peer)?;
    assert_eq!(negotiated.local_role, zmux::Role::Initiator);
    assert!(negotiated.supports_open_metadata());

    Ok(())
}

#[test]
fn public_trait_object_surface_accepts_external_implementations() -> zmux::Result<()> {
    let mut stream: zmux::BoxDuplexStream = Box::new(DummyStream);
    assert_eq!(stream.stream_id(), 42);
    assert_eq!(stream.open_info(), b"api");
    assert!(stream.has_open_info());
    assert_eq!(stream.metadata().open_info, b"api");
    assert_eq!(
        zmux::SendStreamHandle::write_vectored(
            stream.as_ref(),
            &[IoSlice::new(b"a"), IoSlice::new(b"bc")]
        )?,
        3
    );
    assert_eq!(
        stream.write_vectored_final_timeout(&[IoSlice::new(b"done")], Duration::from_millis(1))?,
        4
    );
    stream.set_deadline(Some(Instant::now()))?;
    stream.set_deadline(None)?;
    stream.cancel_read(8)?;
    stream.cancel_write(8)?;
    stream.close_with_error(9, "abort")?;

    let mut buf = [0; 3];
    assert_eq!(Read::read(&mut stream, &mut buf)?, 3);
    assert_eq!(&buf, b"api");
    assert_eq!(Write::write(&mut stream, b"xy")?, 2);
    stream.flush()?;

    let send: zmux::BoxSendStream = Box::new(DummyStream);
    assert_eq!(send.write_final(zmux::WritePayload::from(&b"fin"[..]))?, 3);
    send.close_write()?;

    let recv: zmux::BoxRecvStream = Box::new(DummyStream);
    assert_eq!(recv.read_timeout(&mut buf, Duration::from_millis(1))?, 3);
    recv.close_read()?;

    let session: zmux::BoxSession = zmux::box_session(DummySession);
    assert_eq!(session.state(), zmux::SessionState::Ready);
    assert_eq!(session.ping(b"echo")?, Duration::from_millis(1));
    assert!(session.wait_timeout(Duration::from_millis(1))?);
    assert!(!session.is_closed());
    assert_eq!(session.stats().state, zmux::SessionState::Ready);
    assert_eq!(
        session
            .open_and_send(zmux::OpenSend::new(b"hello"))?
            .stream_id(),
        42
    );
    assert_eq!(
        session
            .open_uni_and_send(zmux::OpenSend::new(b"hello"))?
            .stream_id(),
        42
    );
    let parts = [IoSlice::new(b"he"), IoSlice::new(b"llo")];
    assert_eq!(
        session
            .open_and_send(zmux::OpenSend::vectored(&parts))?
            .stream_id(),
        42
    );
    assert_eq!(
        session
            .open_and_send(zmux::OpenSend::vectored(&parts).options(zmux::OpenOptions::new()))?
            .stream_id(),
        42
    );
    assert_eq!(
        session
            .open_uni_and_send(zmux::OpenSend::vectored(&parts))?
            .stream_id(),
        42
    );
    assert_eq!(
        session
            .open_uni_and_send(zmux::OpenSend::vectored(&parts).options(zmux::OpenOptions::new()))?
            .stream_id(),
        42
    );
    assert!(session.peer_go_away_error().is_none());
    assert!(session.peer_close_error().is_none());
    assert_eq!(session.local_preface().role, zmux::Role::Initiator);
    assert_eq!(session.peer_preface().role, zmux::Role::Responder);
    assert_eq!(session.negotiated().proto, zmux::PROTO_VERSION);

    let arc_session = Arc::new(DummySession);
    assert_eq!(
        zmux::Session::ping(&arc_session, b"echo")?,
        Duration::from_millis(1)
    );
    assert_eq!(
        zmux::Session::open_and_send(&arc_session, zmux::OpenSend::vectored(&parts))?.stream_id(),
        42
    );

    Ok(())
}

#[test]
fn public_async_surface_accepts_generic_and_erased_sessions() {
    fn assert_session<S: zmux::AsyncSession>() {}
    fn assert_stream<S: zmux::AsyncDuplexStreamHandle>() {}
    fn assert_send_stream<S: zmux::AsyncSendStreamHandle>() {}
    fn assert_recv_stream<S: zmux::AsyncRecvStreamHandle>() {}

    assert_session::<zmux::Conn>();
    assert_session::<zmux::ClosedAsyncSession>();
    assert_stream::<zmux::Stream>();
    assert_send_stream::<zmux::SendStream>();
    assert_recv_stream::<zmux::RecvStream>();
    assert_session::<DummyAsyncSession>();
    assert_stream::<DummyAsyncStream>();

    let session: zmux::BoxAsyncSession = zmux::box_async_session(DummyAsyncSession);
    assert_eq!(session.state(), zmux::SessionState::Ready);
    assert_eq!(session.stats().state, zmux::SessionState::Ready);
    assert!(!session.is_closed());

    let closed: zmux::BoxAsyncSession = zmux::box_async_session(zmux::closed_async_session());
    assert!(closed.is_closed());

    let stream = DummyAsyncStream;
    block_on(zmux::AsyncSendStreamHandle::write_all_timeout(
        &stream,
        zmux::WritePayload::from(&b"timeout-all"[..]),
        Duration::from_secs(1),
    ))
    .unwrap();
    block_on(zmux::AsyncSendStreamHandle::write_all(
        &stream,
        b"owned-all".to_vec().into(),
    ))
    .unwrap();
    assert_eq!(
        block_on(zmux::AsyncSendStreamHandle::write_final(
            &stream,
            b"owned-final".to_vec().into(),
        ))
        .unwrap(),
        b"owned-final".len()
    );

    let boxed_stream: zmux::BoxAsyncSendStream = Box::new(DummyAsyncStream);
    block_on(zmux::AsyncSendStreamHandle::write_all_timeout(
        &boxed_stream,
        b"boxed-owned-all".to_vec().into(),
        Duration::from_secs(1),
    ))
    .unwrap();
    assert_eq!(
        block_on(zmux::AsyncSendStreamHandle::write_final_timeout(
            &boxed_stream,
            b"boxed-owned-final".to_vec().into(),
            Duration::from_secs(1),
        ))
        .unwrap(),
        b"boxed-owned-final".len()
    );
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

    block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"bidi").timeout(original_timeout),
    ))?;
    block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"bidi-opts")
            .options(zmux::OpenOptions::default())
            .timeout(original_timeout),
    ))?;
    block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"uni").timeout(original_timeout),
    ))?;
    block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"uni-opts")
            .options(zmux::OpenOptions::default())
            .timeout(original_timeout),
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

    let err = match block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"bidi").timeout(Duration::from_millis(1)),
    )) {
        Ok(_) => panic!("open_send request unexpectedly succeeded"),
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

    block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b""),
    ))?;
    block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"").options(zmux::OpenOptions::default()),
    ))?;
    assert_eq!(write_attempts.load(Ordering::Relaxed), 0);
    assert!(write_timeouts.lock().unwrap().is_empty());

    Ok(())
}

#[test]
fn async_session_open_uni_and_send_uses_payload_write_path() -> zmux::Result<()> {
    let payload_calls = Arc::new(AtomicUsize::new(0));
    let session = PayloadRouteAsyncSession {
        payload_calls: Arc::clone(&payload_calls),
    };

    let _stream = block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"owned-default-final".to_vec()),
    ))?;

    assert_eq!(payload_calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn closed_session_helpers_match_user_facing_session_contract() -> zmux::Result<()> {
    let session = zmux::closed_async_session();
    assert!(zmux::AsyncSession::is_closed(&session));
    assert_eq!(
        zmux::AsyncSession::state(&session),
        zmux::SessionState::Closed
    );
    assert_eq!(
        zmux::AsyncSession::stats(&session),
        zmux::SessionStats::empty(zmux::SessionState::Closed)
    );
    assert!(zmux::AsyncSession::local_addr(&session).is_none());
    assert!(zmux::AsyncSession::peer_addr(&session).is_none());
    assert!(block_on(zmux::AsyncSession::close(&session)).is_ok());
    assert!(block_on(zmux::AsyncSession::wait_timeout(
        &session,
        Duration::from_millis(1)
    ))?);
    block_on(zmux::AsyncSession::wait(&session))?;
    assert!(zmux::AsyncSession::close_error(&session).is_none());

    let err = match block_on(zmux::AsyncSession::open_stream(&session)) {
        Ok(_) => panic!("closed async session opened a stream"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.operation(), zmux::ErrorOperation::Open);
    assert_eq!(err.source(), zmux::ErrorSource::Local);

    let err = match block_on(zmux::AsyncSession::accept_stream_timeout(
        &session,
        Duration::from_millis(1),
    )) {
        Ok(_) => panic!("closed async session accepted a stream"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.operation(), zmux::ErrorOperation::Accept);

    let boxed = zmux::box_async_session(zmux::closed_async_session());
    assert!(zmux::AsyncSession::is_closed(&boxed));
    assert!(block_on(zmux::AsyncSession::wait(&boxed)).is_ok());

    let native = zmux::closed_session();
    assert!(zmux::Session::is_closed(&native));
    assert_eq!(zmux::Session::state(&native), zmux::SessionState::Closed);
    assert_eq!(
        zmux::Session::stats(&native),
        zmux::SessionStats::empty(zmux::SessionState::Closed)
    );
    assert!(zmux::Session::local_addr(&native).is_none());
    assert!(zmux::Session::peer_addr(&native).is_none());
    zmux::Session::close(&native)?;
    assert!(zmux::Session::wait_timeout(
        &native,
        Duration::from_millis(1)
    )?);
    zmux::Session::wait(&native)?;
    assert!(zmux::Session::close_error(&native).is_none());
    assert_eq!(zmux::Session::local_preface(&native).preface_version, 0);
    assert_eq!(zmux::Session::negotiated(&native).proto, 0);

    let err = match zmux::Session::open_stream(&native) {
        Ok(_) => panic!("closed native session opened a stream"),
        Err(err) => err,
    };
    assert!(err.is_session_closed());
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.operation(), zmux::ErrorOperation::Open);
    assert_eq!(err.source(), zmux::ErrorSource::Local);

    let err = zmux::Session::go_away(&native, 0, 0).unwrap_err();
    assert!(err.is_session_closed());
    assert_eq!(err.operation(), zmux::ErrorOperation::Close);

    let boxed_native: zmux::BoxSession = zmux::box_session(zmux::closed_session());
    assert!(zmux::Session::is_closed(&boxed_native));
    assert!(zmux::Session::wait(&boxed_native).is_ok());

    Ok(())
}

#[test]
fn same_async_upper_layer_code_works_with_native_sessions() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();
    block_on(exercise_common_async_session(&client, &server))
}

#[test]
fn same_async_upper_layer_code_works_with_boxed_native_sessions() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();
    let client = zmux::box_async_session(client);
    let server = zmux::box_async_session(server);
    block_on(exercise_common_async_session(
        client.as_ref(),
        server.as_ref(),
    ))
}

#[test]
fn concrete_native_open_and_send_accepts_binary_slices_directly() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();
    let empty = zmux::OpenSend::new([]);
    assert_eq!(empty.payload().checked_len()?, 0);

    let payload_buf = vec![0x01, 0x02, b'p', b'a', b'y', b'l', b'o', b'a', b'd'];
    let _stream = client.open_and_send(&payload_buf)?;

    let accepted = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut buf = [0u8; 9];
    assert_eq!(accepted.read(&mut buf)?, 9);
    assert_eq!(buf.as_slice(), payload_buf.as_slice());

    let owned_payload = vec![0x03, 0x04, b'f', b'i', b'n'];
    let _send = client.open_uni_and_send(owned_payload.clone())?;
    let mut accepted = server.accept_uni_stream_timeout(Duration::from_secs(5))?;
    let mut buf = Vec::new();
    accepted.read_to_end(&mut buf)?;
    assert_eq!(buf, owned_payload);

    let _ = client.close();
    let _ = server.close();
    Ok(())
}

#[test]
fn tcp_session_and_stream_addresses_follow_rust_connection_shape() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();
    assert_eq!(client.local_addr(), server.peer_addr());
    assert_eq!(client.peer_addr(), server.local_addr());
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
        zmux::Conn::client(transport).unwrap()
    });

    let (socket, _) = listener.accept()?;
    let server = thread::spawn(move || {
        let transport = tcp_duplex_transport(socket, None);
        zmux::Conn::server(transport).unwrap()
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
    let local_addr: SocketAddr = "127.0.0.1:10000".parse().unwrap();
    let peer_addr: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let mut transport =
        zmux::DuplexTransport::new(io::Cursor::new(b"hello".to_vec()), Vec::<u8>::new())
            .with_local_addr(local_addr)
            .with_peer_addr(peer_addr)
            .with_control(Box::new(RecordingTransportControl {
                read_timeouts: Arc::clone(&read_timeouts),
                write_timeouts: Arc::clone(&write_timeouts),
                closes: Arc::clone(&closes),
            }));

    let mut buf = [0u8; 2];
    assert_eq!(Read::read(&mut transport, &mut buf)?, 2);
    assert_eq!(&buf, b"he");
    Write::write_all(&mut transport, b"out")?;
    Write::flush(&mut transport)?;
    assert_eq!(transport.reader().position(), 2);
    assert_eq!(transport.writer(), b"out");
    assert_eq!(transport.local_addr(), Some(local_addr));
    assert_eq!(transport.peer_addr(), Some(peer_addr));
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
fn duplex_io_wraps_cloneable_full_duplex_io_without_manual_split() -> io::Result<()> {
    let wrapped = zmux::duplex_io(io::Cursor::new(b"hello".to_vec()));
    let mut transport = zmux::DuplexConnection::into_transport(wrapped)
        .map_err(|err| io::Error::other(err.to_string()))?;

    let mut buf = [0u8; 5];
    Read::read_exact(&mut transport, &mut buf)?;
    assert_eq!(&buf, b"hello");

    Write::write_all(&mut transport, b"out")?;
    assert_eq!(transport.writer().get_ref(), b"outlo");

    let wrapped = zmux::DuplexIo::new(io::Cursor::new(b"inner".to_vec()));
    assert_eq!(wrapped.into_inner().into_inner(), b"inner");

    let transport = zmux::try_duplex_io(io::Cursor::new(b"try".to_vec()), |io| Ok(io.clone()))
        .map_err(|err| io::Error::other(err.to_string()))?;
    assert_eq!(transport.reader().get_ref(), b"try");
    Ok(())
}

#[test]
fn duplex_transport_close_hook_preserves_existing_timeout_control() -> io::Result<()> {
    let read_timeouts = Arc::new(AtomicUsize::new(0));
    let write_timeouts = Arc::new(AtomicUsize::new(0));
    let control_closes = Arc::new(AtomicUsize::new(0));
    let close_hook_calls = Arc::new(AtomicUsize::new(0));
    let close_hook_calls_for_transport = Arc::clone(&close_hook_calls);

    let transport = zmux::DuplexTransport::new(io::Cursor::new(Vec::<u8>::new()), Vec::<u8>::new())
        .with_control(Box::new(RecordingTransportControl {
            read_timeouts: Arc::clone(&read_timeouts),
            write_timeouts: Arc::clone(&write_timeouts),
            closes: Arc::clone(&control_closes),
        }))
        .with_close_fn(move || {
            close_hook_calls_for_transport.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

    transport.set_read_timeout(Some(Duration::from_millis(1)))?;
    transport.set_write_timeout(None)?;
    transport.close()?;

    assert_eq!(read_timeouts.load(Ordering::Relaxed), 1);
    assert_eq!(write_timeouts.load(Ordering::Relaxed), 1);
    assert_eq!(control_closes.load(Ordering::Relaxed), 0);
    assert_eq!(close_hook_calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn duplex_transport_control_can_be_timeout_only() -> io::Result<()> {
    let read_timeouts = Arc::new(AtomicUsize::new(0));
    let write_timeouts = Arc::new(AtomicUsize::new(0));
    let transport = zmux::DuplexTransport::new(io::Cursor::new(Vec::<u8>::new()), Vec::<u8>::new())
        .with_control(TimeoutOnlyTransportControl {
            read_timeouts: Arc::clone(&read_timeouts),
            write_timeouts: Arc::clone(&write_timeouts),
        });

    transport.set_read_timeout(Some(Duration::from_millis(1)))?;
    transport.set_write_timeout(None)?;
    transport.close()?;

    assert_eq!(read_timeouts.load(Ordering::Relaxed), 1);
    assert_eq!(write_timeouts.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn public_join_helpers_build_full_stream_views_from_halves() -> zmux::Result<()> {
    let mut joined =
        zmux::join_streams(DummyStream, DummyStream).with_info_side(zmux::DuplexInfoSide::Write);
    assert_eq!(joined.info_side(), zmux::DuplexInfoSide::Write);
    assert_eq!(joined.read_stream_id(), 42);
    assert_eq!(joined.write_stream_id(), 42);
    assert_eq!(zmux::StreamHandle::stream_id(&joined), 42);
    assert!(zmux::StreamHandle::is_bidirectional(&joined));
    assert_eq!(zmux::StreamHandle::open_info(&joined), b"api");

    let mut buf = [0; 3];
    assert_eq!(Read::read(&mut joined, &mut buf)?, 3);
    assert_eq!(&buf, b"api");
    assert_eq!(Write::write(&mut joined, b"xy")?, 2);
    zmux::StreamHandle::set_timeout(&joined, Some(Duration::from_secs(1)))?;
    zmux::RecvStreamHandle::set_read_timeout(&joined, None)?;
    zmux::SendStreamHandle::set_write_timeout(&joined, Some(Duration::from_secs(1)))?;
    assert_eq!(
        zmux::SendStreamHandle::write_final(&joined, zmux::WritePayload::from(&b"fin"[..]))?,
        3
    );
    zmux::StreamHandle::close(&joined)?;

    let joined = zmux::join_async_streams(DummyAsyncStream, DummyAsyncStream);
    assert_eq!(joined.info_side(), zmux::DuplexInfoSide::Read);
    assert_eq!(joined.read_stream_id(), 42);
    assert_eq!(joined.write_stream_id(), 42);
    assert_eq!(zmux::AsyncStreamHandle::open_info(&joined), b"api");
    assert!(zmux::AsyncStreamHandle::is_bidirectional(&joined));

    let joined = joined.with_info_side(zmux::DuplexInfoSide::Write);
    assert_eq!(joined.info_side(), zmux::DuplexInfoSide::Write);
    assert_eq!(zmux::AsyncStreamHandle::stream_id(&joined), 42);
    zmux::AsyncStreamHandle::set_timeout(&joined, Some(Duration::from_secs(1)))?;
    zmux::AsyncRecvStreamHandle::set_read_timeout(&joined, None)?;
    zmux::AsyncSendStreamHandle::set_write_timeout(&joined, Some(Duration::from_secs(1)))?;

    let joined = zmux::join_async_streams(LabeledStream::new(77, b"joined"), DummyAsyncStream);
    let mut first = [0u8; 2];
    let mut second = [0u8; 4];
    let n = {
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        block_on(zmux::AsyncRecvStreamHandle::read_vectored(
            &joined, &mut bufs,
        ))?
    };
    assert_eq!(n, 6);
    assert_eq!(&first, b"jo");
    assert_eq!(&second, b"ined");

    let joined = zmux::join_async_streams(LabeledStream::new(78, b"exact"), DummyAsyncStream);
    let mut exact = [0u8; 5];
    block_on(zmux::AsyncRecvStreamHandle::read_exact(&joined, &mut exact))?;
    assert_eq!(&exact, b"exact");

    let joined = zmux::join_async_streams(LabeledStream::new(79, b"timer"), DummyAsyncStream);
    let mut exact = [0u8; 5];
    block_on(zmux::AsyncRecvStreamHandle::read_exact_timeout(
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
    zmux::SendStreamHandle::close_write(&outbound_ref)?;

    let inbound = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut inbound_ref = &inbound;
    let mut bidi = [0u8; 13];
    assert_eq!(Read::read(&mut inbound_ref, &mut bidi)?, bidi.len());
    assert_eq!(&bidi, b"borrowed-bidi");

    let outbound = client.open_stream()?;
    let mut outbound_ref = &outbound;
    Write::write_all(&mut outbound_ref, b"vectored-bidi")?;
    zmux::SendStreamHandle::close_write(&outbound_ref)?;

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
    zmux::SendStreamHandle::close_write(&outbound_ref)?;

    let inbound = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut inbound_ref = &inbound;
    let mut exact = [0u8; 10];
    Read::read_exact(&mut inbound_ref, &mut exact)?;
    assert_eq!(&exact, b"exact-bidi");

    let outbound = client.open_stream()?;
    let mut outbound_ref = &outbound;
    Write::write_all(&mut outbound_ref, b"timed-read")?;
    zmux::SendStreamHandle::close_write(&outbound_ref)?;

    let inbound = server.accept_stream_timeout(Duration::from_secs(5))?;
    let mut exact = [0u8; 10];
    zmux::RecvStreamHandle::read_exact_timeout(&inbound, &mut exact, Duration::from_secs(5))?;
    assert_eq!(&exact, b"timed-read");

    let send = client.open_uni_stream()?;
    let mut send_ref = &send;
    Write::write_all(&mut send_ref, b"borrowed-uni")?;
    zmux::SendStreamHandle::close_write(&send_ref)?;

    let recv = server.accept_uni_stream_timeout(Duration::from_secs(5))?;
    let mut recv_ref = &recv;
    let mut uni = [0u8; 12];
    assert_eq!(Read::read(&mut recv_ref, &mut uni)?, uni.len());
    assert_eq!(&uni, b"borrowed-uni");

    let joined = zmux::join_streams(DummyStream, DummyStream);
    let mut joined_ref = &joined;
    let mut joined_buf = [0; 3];
    assert_eq!(Read::read(&mut joined_ref, &mut joined_buf)?, 3);
    assert_eq!(Write::write(&mut joined_ref, b"xy")?, 2);
    assert_eq!(zmux::StreamHandle::stream_id(&joined_ref), 42);

    let joined = zmux::join_streams(LabeledStream::new(77, b"joined"), DummyStream);
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
fn joined_stream_connection_requires_both_halves() {
    let missing_read =
        zmux::DuplexStream::<DummyStream, DummyStream>::from_parts(None, Some(DummyStream));
    let err = match zmux::Conn::client(missing_read) {
        Ok(_) => panic!("connection unexpectedly accepted a missing read half"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("missing a read half"));

    let missing_write =
        zmux::DuplexStream::<DummyStream, DummyStream>::from_parts(Some(DummyStream), None);
    let err = match zmux::Conn::client(missing_write) {
        Ok(_) => panic!("connection unexpectedly accepted a missing write half"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("missing a write half"));
}

#[test]
fn joined_stream_transport_close_does_not_wait_for_active_read() -> io::Result<()> {
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let joined = zmux::join_streams(
        BlockingReadHalf {
            entered: entered_tx,
            release: release_rx,
        },
        SinkWriteHalf,
    );
    let transport = zmux::DuplexConnection::into_transport(joined)
        .map_err(|err| io::Error::other(err.to_string()))?;
    let mut reader: zmux::DuplexStream<BlockingReadHalf, SinkWriteHalf> =
        transport.reader().clone();
    let reader_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        Read::read(&mut reader, &mut buf)
    });

    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("joined read did not become active");

    let (closed_tx, closed_rx) = mpsc::sync_channel(1);
    let close_thread = thread::spawn(move || {
        let _ = closed_tx.send(transport.close());
    });
    let close_result = match closed_rx.recv_timeout(Duration::from_millis(100)) {
        Ok(result) => result,
        Err(err) => {
            let _ = release_tx.send(());
            let _ = reader_thread.join();
            let _ = close_thread.join();
            panic!("joined transport close waited for the active read: {err}");
        }
    };
    close_result?;

    release_tx.send(()).unwrap();
    assert_eq!(reader_thread.join().unwrap()?, 0);
    close_thread.join().unwrap();
    Ok(())
}

#[test]
fn joined_native_stream_transport_close_closes_underlying_zmux_stream() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();
    let stream = client.open_stream()?;
    let close_probe = stream.clone();
    let joined = zmux::join_streams(stream.clone(), stream);
    let transport = zmux::DuplexConnection::into_transport(joined)?;

    transport.close()?;

    assert!(close_probe.is_read_closed());
    assert!(close_probe.is_write_closed());
    let _ = client.close();
    let _ = server.close();
    Ok(())
}

#[test]
fn native_session_vectored_open_and_send_works_through_trait() -> zmux::Result<()> {
    let (client, server) = native_tcp_pair();

    let bidi_parts = [IoSlice::new(b"trait-"), IoSlice::new(b"bidi")];
    let outbound = zmux::Session::open_and_send(&client, zmux::OpenSend::vectored(&bidi_parts))?;
    zmux::SendStreamHandle::close_write(&outbound)?;

    let mut inbound = zmux::Session::accept_stream_timeout(&server, Duration::from_secs(5))?;
    let mut buf = [0u8; 10];
    Read::read_exact(&mut inbound, &mut buf)?;
    assert_eq!(&buf, b"trait-bidi");
    zmux::StreamHandle::close(&outbound)?;
    zmux::StreamHandle::close(&inbound)?;

    let uni_parts = [IoSlice::new(b"trait-"), IoSlice::new(b"uni")];
    let outbound = zmux::Session::open_uni_and_send(&server, zmux::OpenSend::vectored(&uni_parts))?;

    let mut inbound = zmux::Session::accept_uni_stream_timeout(&client, Duration::from_secs(5))?;
    let mut buf = [0u8; 9];
    Read::read_exact(&mut inbound, &mut buf)?;
    assert_eq!(&buf, b"trait-uni");
    zmux::StreamHandle::close(&outbound)?;
    zmux::StreamHandle::close(&inbound)?;

    let _ = client.close();
    let _ = server.close();
    Ok(())
}

#[test]
fn joined_streams_reject_invalid_underlying_progress() -> zmux::Result<()> {
    let mut native = zmux::join_streams(InvalidProgressStream::read_progress(4), DummyStream);
    let mut buf = [0u8; 3];
    let err = Read::read(&mut native, &mut buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let mut native = zmux::join_streams(InvalidProgressStream::read_progress(4), DummyStream);
    let mut first = [0u8; 1];
    let mut second = [0u8; 2];
    let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
    let err = Read::read_vectored(&mut native, &mut bufs).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let err = zmux::RecvStreamHandle::read_timeout(&native, &mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let err = zmux::RecvStreamHandle::read_exact_timeout(&native, &mut buf, Duration::from_secs(1))
        .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let mut native = zmux::join_streams(DummyStream, InvalidProgressStream::write_progress(4));
    let err = Write::write(&mut native, b"abc").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let err =
        zmux::SendStreamHandle::write_timeout(&native, b"abc", Duration::from_secs(1)).unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let parts = [IoSlice::new(b"a"), IoSlice::new(b"bc")];
    let err = zmux::SendStreamHandle::write_vectored(&native, &parts).unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let async_joined =
        zmux::join_async_streams(InvalidProgressStream::read_progress(4), DummyAsyncStream);
    let err = block_on(zmux::AsyncRecvStreamHandle::read(&async_joined, &mut buf)).unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let err = block_on(zmux::AsyncRecvStreamHandle::read_exact(
        &async_joined,
        &mut buf,
    ))
    .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let err = block_on(zmux::AsyncRecvStreamHandle::read_exact_timeout(
        &async_joined,
        &mut buf,
        Duration::from_secs(1),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let async_joined =
        zmux::join_async_streams(DummyAsyncStream, InvalidProgressStream::write_progress(4));
    let err = block_on(zmux::AsyncSendStreamHandle::write(&async_joined, b"abc")).unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let err = block_on(zmux::AsyncSendStreamHandle::write_vectored(
        &async_joined,
        &parts,
    ))
    .unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let err = block_on(zmux::AsyncSendStreamHandle::write_final_timeout(
        &async_joined,
        zmux::WritePayload::from(&b"abc"[..]),
        Duration::from_secs(1),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("write reported invalid progress"));

    let invalid_reader = InvalidProgressStream::read_progress(8193);
    let mut out = Vec::new();
    let err = block_on(zmux::AsyncRecvStreamHandle::read_to_end(
        &invalid_reader,
        &mut out,
    ))
    .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let err = block_on(zmux::AsyncRecvStreamHandle::read_to_end_limited(
        &invalid_reader,
        3,
    ))
    .unwrap_err();
    assert!(err.to_string().contains("read reported invalid progress"));

    let mut one = [0u8; 1];
    let err = zmux::RecvStreamHandle::read_exact_timeout(
        &ZeroSizedCloseProbe,
        &mut one,
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(
        err.source_io_error_kind(),
        Some(io::ErrorKind::UnexpectedEof)
    );

    let err = block_on(zmux::AsyncRecvStreamHandle::read_exact(
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

    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"abc"),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"abc").timeout(timeout),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"abc").options(opts.clone()),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"abc")
            .options(opts.clone())
            .timeout(timeout),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::vectored(&parts),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::vectored(&parts).timeout(timeout),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::vectored(&parts).options(opts.clone()),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::vectored(&parts)
            .options(opts.clone())
            .timeout(timeout),
    )));

    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"abc"),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"abc").timeout(timeout),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"abc").options(opts.clone()),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"abc").options(opts).timeout(timeout),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::vectored(&parts),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::vectored(&parts).timeout(timeout),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::vectored(&parts).options(zmux::OpenOptions::default()),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::vectored(&parts)
            .options(zmux::OpenOptions::default())
            .timeout(timeout),
    )));

    let boxed = zmux::box_async_session(InvalidProgressAsyncSession);
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        boxed.as_ref(),
        zmux::OpenSend::new(b"abc"),
    )));
    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        boxed.as_ref(),
        zmux::OpenSend::vectored(&parts),
    )));
}

#[test]
fn session_default_open_and_send_closes_stream_after_write_failure() {
    let closes = Arc::new(AtomicUsize::new(0));
    let session = CleanupTrackingSession::new(Arc::clone(&closes));

    assert_invalid_write_progress(zmux::Session::open_and_send(
        &session,
        zmux::OpenSend::new(b"abc"),
    ));
    assert_eq!(closes.load(Ordering::SeqCst), 1);

    assert_invalid_write_progress(zmux::Session::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"abc"),
    ));
    assert_eq!(closes.load(Ordering::SeqCst), 2);
}

#[test]
fn async_session_default_open_and_send_closes_stream_after_write_failure() {
    let closes = Arc::new(AtomicUsize::new(0));
    let session = CleanupTrackingSession::new(Arc::clone(&closes));

    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_and_send(
        &session,
        zmux::OpenSend::new(b"abc"),
    )));
    assert_eq!(closes.load(Ordering::SeqCst), 1);

    assert_invalid_write_progress(block_on(zmux::AsyncSession::open_uni_and_send(
        &session,
        zmux::OpenSend::new(b"abc"),
    )));
    assert_eq!(closes.load(Ordering::SeqCst), 2);
}

#[test]
fn joined_stream_halves_can_be_paused_replaced_and_detached() -> zmux::Result<()> {
    let mut native =
        zmux::join_streams(LabeledStream::new(1, b"one"), LabeledStream::new(2, b"two"));
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

    let async_joined = zmux::join_async_streams(
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
    let n = block_on(zmux::AsyncRecvStreamHandle::read(&async_joined, &mut buf))?;
    assert_eq!(&buf[..n], b"gamma");

    let detached = async_joined.detach_send()?.unwrap();
    assert_eq!(detached.id, 20);
    assert!(block_on(zmux::AsyncSendStreamHandle::write(&async_joined, b"x")).is_err());
    async_joined.replace_send(LabeledStream::new(40, b"delta"))?;
    assert_eq!(async_joined.write_stream_id(), 40);
    assert_eq!(
        block_on(zmux::AsyncSendStreamHandle::write(&async_joined, b"x"))?,
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
        zmux::DuplexStream::<DeadlineProbeStream, DeadlineProbeStream>::from_parts(None, None);
    assert_eq!(native.read_stream_id(), 0);
    assert_eq!(native.write_stream_id(), 0);
    assert!(Read::read(&mut native, &mut [0u8; 1]).is_err());
    assert!(Write::write(&mut native, b"x").is_err());
    zmux::RecvStreamHandle::set_read_deadline(&native, Some(read_deadline))?;
    zmux::SendStreamHandle::set_write_deadline(&native, Some(write_deadline))?;

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
        zmux::AsyncDuplexStream::<DeadlineProbeStream, DeadlineProbeStream>::from_parts(None, None);
    assert_eq!(async_joined.read_stream_id(), 0);
    assert_eq!(async_joined.write_stream_id(), 0);
    assert!(block_on(zmux::AsyncRecvStreamHandle::read(
        &async_joined,
        &mut [0u8; 1]
    ))
    .is_err());
    assert!(block_on(zmux::AsyncSendStreamHandle::write(&async_joined, b"x")).is_err());
    zmux::AsyncRecvStreamHandle::set_read_deadline(&async_joined, Some(read_deadline))?;
    zmux::AsyncSendStreamHandle::set_write_deadline(&async_joined, Some(write_deadline))?;

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
    let native = zmux::join_streams(
        DeadlineProbeStream::new(1, Arc::clone(&native_events)),
        DeadlineProbeStream::new(2, Arc::clone(&native_events)),
    );

    zmux::RecvStreamHandle::set_read_deadline(&native, Some(read_deadline))?;
    zmux::SendStreamHandle::set_write_deadline(&native, Some(write_deadline))?;
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
    let async_joined = zmux::join_async_streams(
        DeadlineProbeStream::new(10, Arc::clone(&async_events)),
        DeadlineProbeStream::new(20, Arc::clone(&async_events)),
    );
    zmux::AsyncRecvStreamHandle::set_read_deadline(&async_joined, Some(read_deadline))?;
    zmux::AsyncSendStreamHandle::set_write_deadline(&async_joined, Some(write_deadline))?;
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
    let native = zmux::join_streams(
        DeadlineProbeStream::new(1, Arc::clone(&native_events)),
        DeadlineProbeStream::new(2, Arc::clone(&native_events)),
    );
    let mut paused_read = native.pause_read()?;
    let replacement = DeadlineProbeStream::blocking_deadlines(3, Arc::clone(&native_events));
    let probe = replacement.clone();
    let _ = paused_read.replace(replacement);

    let first_deadline = Instant::now() + Duration::from_secs(30);
    let second_deadline = Instant::now() + Duration::from_secs(60);
    zmux::RecvStreamHandle::set_read_deadline(&native, Some(first_deadline))?;
    let resume = thread::spawn(move || paused_read.resume());

    assert!(
        probe.wait_first_deadline_started(),
        "native read resume did not begin replaying the staged deadline"
    );
    zmux::RecvStreamHandle::set_read_deadline(&native, Some(second_deadline))?;
    probe.release_deadline();
    resume.join().unwrap()?;

    assert_eq!(
        deadline_events_for(&native_events, 3, DeadlineSide::Read),
        vec![Some(first_deadline), Some(second_deadline)]
    );

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_joined = zmux::join_async_streams(
        DeadlineProbeStream::new(10, Arc::clone(&async_events)),
        DeadlineProbeStream::new(20, Arc::clone(&async_events)),
    );
    let mut paused_write = async_joined.pause_write()?;
    let replacement = DeadlineProbeStream::blocking_deadlines(30, Arc::clone(&async_events));
    let probe = replacement.clone();
    let _ = paused_write.replace(replacement);

    zmux::AsyncSendStreamHandle::set_write_deadline(&async_joined, Some(first_deadline))?;
    let resume = thread::spawn(move || paused_write.resume());

    assert!(
        probe.wait_first_deadline_started(),
        "async write resume did not begin replaying the staged deadline"
    );
    zmux::AsyncSendStreamHandle::set_write_deadline(&async_joined, Some(second_deadline))?;
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
    let native = Arc::new(zmux::join_streams(
        native_read,
        DeadlineProbeStream::new(102, Arc::clone(&native_events)),
    ));

    let first_deadline = Instant::now() + Duration::from_secs(30);
    let second_deadline = Instant::now() + Duration::from_secs(60);
    let first_native = Arc::clone(&native);
    let first_setter = thread::spawn(move || {
        zmux::RecvStreamHandle::set_read_deadline(&*first_native, Some(first_deadline))
    });

    assert!(
        native_probe.wait_first_deadline_started(),
        "native read deadline apply did not reach the underlying half"
    );
    zmux::RecvStreamHandle::set_read_deadline(&*native, Some(second_deadline))?;
    native_probe.release_deadline();
    first_setter.join().unwrap()?;

    assert_eq!(
        deadline_events_for(&native_events, 101, DeadlineSide::Read),
        vec![Some(first_deadline), Some(second_deadline)]
    );

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_read = DeadlineProbeStream::blocking_deadlines(201, Arc::clone(&async_events));
    let async_probe = async_read.clone();
    let async_joined = Arc::new(zmux::join_async_streams(
        async_read,
        DeadlineProbeStream::new(202, Arc::clone(&async_events)),
    ));
    let first_async = Arc::clone(&async_joined);
    let first_setter = thread::spawn(move || {
        zmux::AsyncRecvStreamHandle::set_read_deadline(&*first_async, Some(first_deadline))
    });

    assert!(
        async_probe.wait_first_deadline_started(),
        "async read deadline apply did not reach the underlying half"
    );
    zmux::AsyncRecvStreamHandle::set_read_deadline(&*async_joined, Some(second_deadline))?;
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
    let native = Arc::new(zmux::join_streams(
        LabeledStream::new(1, b"read"),
        LabeledStream::new(2, b"write"),
    ));
    let paused_read = native.pause_read()?;
    zmux::RecvStreamHandle::set_read_deadline(
        &*native,
        Some(Instant::now() + Duration::from_millis(50)),
    )?;
    let (done_tx, done_rx) = mpsc::channel();
    let reader = Arc::clone(&native);
    let read_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        let timed_out = match zmux::RecvStreamHandle::read_timeout(
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
    let async_joined = Arc::new(zmux::join_async_streams(
        DeadlineProbeStream::new(10, Arc::clone(&async_events)),
        DeadlineProbeStream::new(20, Arc::clone(&async_events)),
    ));
    let paused_write = async_joined.pause_write()?;
    zmux::AsyncSendStreamHandle::set_write_deadline(
        &*async_joined,
        Some(Instant::now() + Duration::from_millis(50)),
    )?;
    let (done_tx, done_rx) = mpsc::channel();
    let writer = Arc::clone(&async_joined);
    let write_thread = thread::spawn(move || {
        let timed_out = match block_on(zmux::AsyncSendStreamHandle::write_timeout(
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
    let native = zmux::join_streams(
        DeadlineProbeStream::new(1, Arc::clone(&native_events)),
        DeadlineProbeStream::new(2, Arc::clone(&native_events)),
    );
    zmux::RecvStreamHandle::set_read_deadline(
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
    let async_joined = zmux::join_async_streams(
        DeadlineProbeStream::new(10, Arc::clone(&async_events)),
        DeadlineProbeStream::new(20, Arc::clone(&async_events)),
    );
    zmux::AsyncSendStreamHandle::set_write_deadline(
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
        zmux::StreamHandle::close_identity(&stream),
        zmux::StreamHandle::close_identity(&stream_clone)
    );
    assert_eq!(
        zmux::AsyncStreamHandle::close_identity(&stream),
        zmux::AsyncStreamHandle::close_identity(&stream_clone)
    );

    let joined = zmux::join_streams(stream.clone(), stream_clone.clone());
    zmux::StreamHandle::close(&joined)?;

    let send = client.open_uni_stream()?;
    let send_clone = send.clone();
    assert_eq!(
        zmux::StreamHandle::close_identity(&send),
        zmux::StreamHandle::close_identity(&send_clone)
    );
    assert_eq!(
        zmux::AsyncStreamHandle::close_identity(&send),
        zmux::AsyncStreamHandle::close_identity(&send_clone)
    );
    send.write_final(b"identity")?;

    let recv = server.accept_uni_stream_timeout(Duration::from_secs(5))?;
    let recv_clone = recv.clone();
    assert_eq!(
        zmux::StreamHandle::close_identity(&recv),
        zmux::StreamHandle::close_identity(&recv_clone)
    );
    assert_eq!(
        zmux::AsyncStreamHandle::close_identity(&recv),
        zmux::AsyncStreamHandle::close_identity(&recv_clone)
    );

    let async_joined = zmux::join_async_streams(recv.clone(), send_clone);
    block_on(zmux::AsyncStreamHandle::close(&async_joined))?;

    let _ = client.close();
    let _ = server.close();
    Ok(())
}

#[test]
fn joined_stream_close_closes_supplied_halves_as_full_streams() -> zmux::Result<()> {
    let native_events = Arc::new(Mutex::new(Vec::new()));
    let native = zmux::join_streams(
        DirectionalCloseProbe::new("native-read", Arc::clone(&native_events)),
        DirectionalCloseProbe::new("native-write", Arc::clone(&native_events)),
    );

    zmux::StreamHandle::close(&native)?;
    assert_eq!(
        close_events(&native_events),
        vec!["native-write:close", "native-read:close"]
    );

    let async_events = Arc::new(Mutex::new(Vec::new()));
    let async_joined = zmux::join_async_streams(
        DirectionalCloseProbe::new("async-read", Arc::clone(&async_events)),
        DirectionalCloseProbe::new("async-write", Arc::clone(&async_events)),
    );

    block_on(zmux::AsyncStreamHandle::close(&async_joined))?;
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
    let joined = zmux::join_async_streams(Arc::clone(&shared), Arc::clone(&shared));

    block_on(zmux::AsyncStreamHandle::close(&joined))?;
    assert_eq!(close_events(&events), vec!["shared:close"]);

    events.lock().unwrap().clear();
    let shared = Arc::new(DirectionalCloseProbe::new("shared", Arc::clone(&events)));
    let joined = zmux::join_async_streams(Arc::clone(&shared), Arc::clone(&shared));

    block_on(zmux::AsyncStreamHandle::close_with_error(
        &joined, 7, "boom",
    ))?;
    assert_eq!(close_events(&events), vec!["shared:close_with_error"]);

    Ok(())
}

#[test]
fn joined_stream_default_close_identity_does_not_dedupe_zero_sized_halves() -> zmux::Result<()> {
    ZERO_SIZED_NATIVE_CLOSES.store(0, Ordering::Relaxed);
    ZERO_SIZED_ASYNC_CLOSES.store(0, Ordering::Relaxed);

    assert!(zmux::StreamHandle::close_identity(&ZeroSizedCloseProbe).is_null());
    assert!(zmux::AsyncStreamHandle::close_identity(&ZeroSizedCloseProbe).is_null());

    let native = zmux::join_streams(ZeroSizedCloseProbe, ZeroSizedCloseProbe);
    zmux::StreamHandle::close(&native)?;
    assert_eq!(ZERO_SIZED_NATIVE_CLOSES.load(Ordering::Relaxed), 2);

    let async_joined = zmux::join_async_streams(ZeroSizedCloseProbe, ZeroSizedCloseProbe);
    block_on(zmux::AsyncStreamHandle::close(&async_joined))?;
    assert_eq!(ZERO_SIZED_ASYNC_CLOSES.load(Ordering::Relaxed), 2);

    Ok(())
}

#[test]
fn joined_stream_close_ignores_absent_halves_but_fully_closes_present_halves() -> zmux::Result<()> {
    let native_read_events = Arc::new(Mutex::new(Vec::new()));
    let native_read_only =
        zmux::DuplexStream::<DirectionalCloseProbe, DirectionalCloseProbe>::from_parts(
            Some(DirectionalCloseProbe::new(
                "native-read",
                Arc::clone(&native_read_events),
            )),
            None,
        );
    zmux::SendStreamHandle::close_write(&native_read_only)?;
    assert!(close_events(&native_read_events).is_empty());
    zmux::StreamHandle::close(&native_read_only)?;
    assert_eq!(close_events(&native_read_events), vec!["native-read:close"]);

    let native_write_events = Arc::new(Mutex::new(Vec::new()));
    let native_write_only =
        zmux::DuplexStream::<DirectionalCloseProbe, DirectionalCloseProbe>::from_parts(
            None,
            Some(DirectionalCloseProbe::new(
                "native-write",
                Arc::clone(&native_write_events),
            )),
        );
    zmux::RecvStreamHandle::close_read(&native_write_only)?;
    assert!(close_events(&native_write_events).is_empty());
    zmux::StreamHandle::close(&native_write_only)?;
    assert_eq!(
        close_events(&native_write_events),
        vec!["native-write:close"]
    );

    let async_read_events = Arc::new(Mutex::new(Vec::new()));
    let async_read_only =
        zmux::AsyncDuplexStream::<DirectionalCloseProbe, DirectionalCloseProbe>::from_parts(
            Some(DirectionalCloseProbe::new(
                "async-read",
                Arc::clone(&async_read_events),
            )),
            None,
        );
    block_on(zmux::AsyncSendStreamHandle::close_write(&async_read_only))?;
    assert!(close_events(&async_read_events).is_empty());
    block_on(zmux::AsyncStreamHandle::close(&async_read_only))?;
    assert_eq!(close_events(&async_read_events), vec!["async-read:close"]);

    let async_write_events = Arc::new(Mutex::new(Vec::new()));
    let async_write_only =
        zmux::AsyncDuplexStream::<DirectionalCloseProbe, DirectionalCloseProbe>::from_parts(
            None,
            Some(DirectionalCloseProbe::new(
                "async-write",
                Arc::clone(&async_write_events),
            )),
        );
    block_on(zmux::AsyncRecvStreamHandle::close_read(&async_write_only))?;
    assert!(close_events(&async_write_events).is_empty());
    block_on(zmux::AsyncStreamHandle::close(&async_write_only))?;
    assert_eq!(close_events(&async_write_events), vec!["async-write:close"]);

    Ok(())
}

#[test]
fn async_joined_direct_replace_does_not_steal_an_active_pause() -> zmux::Result<()> {
    let joined = zmux::join_async_streams(
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
    let joined = Arc::new(zmux::join_async_streams(
        initial,
        LabeledStream::new(2, b"write"),
    ));

    let reader = Arc::clone(&joined);
    let read_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        block_on(zmux::AsyncRecvStreamHandle::read(&*reader, &mut buf))
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
    let joined = Arc::new(zmux::join_async_streams(
        initial,
        LabeledStream::new(2, b"write"),
    ));

    let deadline_joined = Arc::clone(&joined);
    let deadline_thread = thread::spawn(move || {
        zmux::AsyncRecvStreamHandle::set_read_deadline(
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
    let joined = Arc::new(zmux::join_streams(recv, DummyStream));
    let reader = Arc::clone(&joined);
    let read_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        let _ = zmux::RecvStreamHandle::read_timeout(&*reader, &mut buf, Duration::from_secs(5));
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
    let joined = Arc::new(zmux::join_streams(recv, DummyStream));
    let reader = Arc::clone(&joined);
    let read_thread = thread::spawn(move || {
        let mut buf = [0u8; 1];
        zmux::RecvStreamHandle::read_timeout(&*reader, &mut buf, Duration::from_secs(5))
    });

    control.wait_started();
    let deadline = Instant::now() + Duration::from_secs(30);
    zmux::RecvStreamHandle::set_read_deadline(&*joined, Some(deadline))?;
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
    S: zmux::AsyncSession + ?Sized,
{
    assert!(!zmux::AsyncSession::is_closed(client));
    assert!(!zmux::AsyncSession::is_closed(server));
    assert_eq!(
        zmux::AsyncSession::state(client),
        zmux::AsyncSession::stats(client).state
    );
    assert_eq!(
        zmux::AsyncSession::state(server),
        zmux::AsyncSession::stats(server).state
    );

    let outbound = zmux::AsyncSession::open_stream(client).await?;
    zmux::AsyncStreamHandle::set_deadline(
        &outbound,
        Some(Instant::now() + Duration::from_secs(5)),
    )?;
    zmux::AsyncStreamHandle::set_deadline(&outbound, None)?;
    zmux::AsyncSendStreamHandle::write_final(
        &outbound,
        zmux::WritePayload::from(&b"client-to-server"[..]),
    )
    .await?;
    let inbound = zmux::AsyncSession::accept_stream_timeout(server, Duration::from_secs(5)).await?;
    assert_eq!(
        zmux::AsyncRecvStreamHandle::read_to_end_limited(&inbound, b"client-to-server".len())
            .await?,
        b"client-to-server"
    );

    zmux::AsyncSendStreamHandle::write_final(
        &inbound,
        zmux::WritePayload::from(&b"server-to-client"[..]),
    )
    .await?;
    assert_eq!(read_all_async(&outbound).await?, b"server-to-client");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    let outbound =
        zmux::AsyncSession::open_and_send(client, zmux::OpenSend::new(b"open-and-send")).await?;
    zmux::AsyncSendStreamHandle::close_write(&outbound).await?;
    let inbound = zmux::AsyncSession::accept_stream_timeout(server, Duration::from_secs(5)).await?;
    assert_eq!(read_all_async(&inbound).await?, b"open-and-send");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    let parts = [IoSlice::new(b"open-"), IoSlice::new(b"vectored")];
    let outbound =
        zmux::AsyncSession::open_and_send(client, zmux::OpenSend::vectored(&parts)).await?;
    zmux::AsyncSendStreamHandle::close_write(&outbound).await?;
    let inbound = zmux::AsyncSession::accept_stream_timeout(server, Duration::from_secs(5)).await?;
    assert_eq!(read_all_async(&inbound).await?, b"open-vectored");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    let outbound =
        zmux::AsyncSession::open_uni_and_send(server, zmux::OpenSend::new(b"server-uni")).await?;
    let inbound =
        zmux::AsyncSession::accept_uni_stream_timeout(client, Duration::from_secs(5)).await?;
    assert_eq!(read_all_async(&inbound).await?, b"server-uni");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;
    drop(outbound);

    let parts = [IoSlice::new(b"server-"), IoSlice::new(b"uni-vectored")];
    let outbound =
        zmux::AsyncSession::open_uni_and_send(server, zmux::OpenSend::vectored(&parts)).await?;
    let inbound =
        zmux::AsyncSession::accept_uni_stream_timeout(client, Duration::from_secs(5)).await?;
    assert_eq!(read_all_async(&inbound).await?, b"server-uni-vectored");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    zmux::AsyncSession::close(client).await?;
    zmux::AsyncSession::close(server).await?;
    assert!(zmux::AsyncSession::wait_timeout(client, Duration::from_secs(5)).await?);
    assert!(zmux::AsyncSession::wait_timeout(server, Duration::from_secs(5)).await?);
    assert!(zmux::AsyncSession::is_closed(client));
    assert!(zmux::AsyncSession::is_closed(server));
    Ok(())
}

async fn read_all_async<S>(stream: &S) -> zmux::Result<Vec<u8>>
where
    S: zmux::AsyncRecvStreamHandle + ?Sized,
{
    let mut out = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let n =
            zmux::AsyncRecvStreamHandle::read_timeout(stream, &mut buffer, Duration::from_secs(5))
                .await?;
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
        zmux::Conn::client(socket).unwrap()
    });
    let (socket, _) = listener.accept().unwrap();
    let server = thread::spawn(move || zmux::Conn::server(socket).unwrap());
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

struct TimeoutOnlyTransportControl {
    read_timeouts: Arc<AtomicUsize>,
    write_timeouts: Arc<AtomicUsize>,
}

impl zmux::DuplexTransportControl for TimeoutOnlyTransportControl {
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeouts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeouts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
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

struct BlockingReadHalf {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

impl Read for BlockingReadHalf {
    fn read(&mut self, _dst: &mut [u8]) -> io::Result<usize> {
        let _ = self.entered.send(());
        let _ = self.release.recv();
        Ok(0)
    }
}

struct SinkWriteHalf;

impl Write for SinkWriteHalf {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        Ok(src.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

struct DummyStream;

impl zmux::StreamHandle for DummyStream {
    fn stream_id(&self) -> u64 {
        42
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        3
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
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

impl zmux::RecvStreamHandle for DummyStream {
    fn is_read_closed(&self) -> bool {
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

impl zmux::SendStreamHandle for DummyStream {
    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final<'a>(&self, payload: zmux::WritePayload<'a>) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final_timeout<'a>(
        &self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
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

impl zmux::DuplexStreamHandle for DummyStream {}

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

impl zmux::StreamHandle for InvalidProgressStream {
    fn stream_id(&self) -> u64 {
        77
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

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

impl zmux::RecvStreamHandle for InvalidProgressStream {
    fn is_read_closed(&self) -> bool {
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

impl zmux::SendStreamHandle for InvalidProgressStream {
    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, _src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_vectored(&self, _parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_vectored_timeout(
        &self,
        _parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_final<'a>(&self, _payload: zmux::WritePayload<'a>) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_vectored_final(&self, _parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(self.write_n)
    }

    fn write_final_timeout<'a>(
        &self,
        _payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::Result<usize> {
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

impl zmux::DuplexStreamHandle for InvalidProgressStream {}

impl zmux::AsyncStreamHandle for InvalidProgressStream {
    fn stream_id(&self) -> u64 {
        77
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncRecvStreamHandle for InvalidProgressStream {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.read_n) })
    }

    fn read_timeout<'a>(
        &'a self,
        _dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.read_n) })
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for InvalidProgressStream {
    fn write<'a>(&'a self, _src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.write_n) })
    }

    fn write_timeout<'a>(
        &'a self,
        _src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.write_n) })
    }

    fn write_final_timeout<'a>(
        &'a self,
        _payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.write_n) })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        _parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(self.write_n) })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for InvalidProgressStream {}

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

impl zmux::StreamHandle for LabeledStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        self.data.len()
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
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

impl zmux::RecvStreamHandle for LabeledStream {
    fn is_read_closed(&self) -> bool {
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

impl zmux::SendStreamHandle for LabeledStream {
    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final<'a>(&self, payload: zmux::WritePayload<'a>) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final_timeout<'a>(
        &self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
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

impl zmux::DuplexStreamHandle for LabeledStream {}

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

impl zmux::StreamHandle for BlockingNativeStream {
    fn stream_id(&self) -> u64 {
        99
    }

    fn is_opened_locally(&self) -> bool {
        false
    }

    fn is_bidirectional(&self) -> bool {
        false
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

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

impl zmux::RecvStreamHandle for BlockingNativeStream {
    fn is_read_closed(&self) -> bool {
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

impl zmux::AsyncStreamHandle for BlockingAsyncStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn is_opened_locally(&self) -> bool {
        false
    }

    fn is_bidirectional(&self) -> bool {
        false
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move {
            self.release_read();
            Ok(())
        })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async move {
            self.release_read();
            Ok(())
        })
    }
}

impl zmux::AsyncRecvStreamHandle for BlockingAsyncStream {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.wait_for_read_release();
            Ok(0)
        })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        self.block_first_deadline();
        Ok(())
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move {
            self.release_read();
            Ok(())
        })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move {
            self.release_read();
            Ok(())
        })
    }
}

impl zmux::AsyncStreamHandle for LabeledStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        self.data.len()
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(self.data);
    }

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata {
            open_info: self.data.to_vec(),
            ..zmux::StreamMetadata::default()
        }
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncRecvStreamHandle for LabeledStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            let n = dst.len().min(self.data.len());
            dst[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        })
    }

    fn read_vectored<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
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
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn read_vectored_timeout<'a>(
        &'a self,
        dsts: &'a mut [IoSliceMut<'_>],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read_vectored(dsts)
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for LabeledStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { payload.checked_len() })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for LabeledStream {}

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

impl zmux::StreamHandle for DeadlineProbeStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

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

impl zmux::RecvStreamHandle for DeadlineProbeStream {
    fn is_read_closed(&self) -> bool {
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

impl zmux::SendStreamHandle for DeadlineProbeStream {
    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final<'a>(&self, payload: zmux::WritePayload<'a>) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final_timeout<'a>(
        &self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
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

impl zmux::DuplexStreamHandle for DeadlineProbeStream {}

impl zmux::AsyncStreamHandle for DeadlineProbeStream {
    fn stream_id(&self) -> u64 {
        self.id
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Stream, deadline)
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncRecvStreamHandle for DeadlineProbeStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
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
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Read, deadline)
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for DeadlineProbeStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { payload.checked_len() })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> zmux::Result<()> {
        self.record_deadline(DeadlineSide::Write, deadline)
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for DeadlineProbeStream {}

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

impl zmux::StreamHandle for DirectionalCloseProbe {
    fn stream_id(&self) -> u64 {
        0
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

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

impl zmux::RecvStreamHandle for DirectionalCloseProbe {
    fn is_read_closed(&self) -> bool {
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

impl zmux::SendStreamHandle for DirectionalCloseProbe {
    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final<'a>(&self, payload: zmux::WritePayload<'a>) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final_timeout<'a>(
        &self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
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

impl zmux::DuplexStreamHandle for DirectionalCloseProbe {}

impl zmux::AsyncStreamHandle for DirectionalCloseProbe {
    fn stream_id(&self) -> u64 {
        0
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        self.record("close");
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        self.record("close_with_error");
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncRecvStreamHandle for DirectionalCloseProbe {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        self.record("close_read");
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        self.record("cancel_read");
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for DirectionalCloseProbe {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { payload.checked_len() })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        self.record("close_write");
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        self.record("cancel_write");
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for DirectionalCloseProbe {}

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

impl zmux::StreamHandle for ZeroSizedCloseProbe {
    fn stream_id(&self) -> u64 {
        0
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

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
        zmux::StreamHandle::close(self)
    }
}

impl zmux::RecvStreamHandle for ZeroSizedCloseProbe {
    fn is_read_closed(&self) -> bool {
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

impl zmux::SendStreamHandle for ZeroSizedCloseProbe {
    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(src.len())
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(parts.iter().map(|part| part.len()).sum())
    }

    fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final<'a>(&self, payload: zmux::WritePayload<'a>) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        self.write_vectored(parts)
    }

    fn write_final_timeout<'a>(
        &self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        payload.checked_len()
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        self.write_vectored(parts)
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

impl zmux::DuplexStreamHandle for ZeroSizedCloseProbe {}

impl zmux::AsyncStreamHandle for ZeroSizedCloseProbe {
    fn stream_id(&self) -> u64 {
        0
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        ZERO_SIZED_ASYNC_CLOSES.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        zmux::AsyncStreamHandle::close(self)
    }
}

impl zmux::AsyncRecvStreamHandle for ZeroSizedCloseProbe {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn set_read_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for ZeroSizedCloseProbe {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { payload.checked_len() })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn set_write_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for ZeroSizedCloseProbe {}

macro_rules! impl_noop_async_session_controls {
    () => {
        fn ping<'a>(&'a self, _echo: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<Duration>> {
            Box::pin(async { Ok(Duration::ZERO) })
        }

        fn ping_timeout<'a>(
            &'a self,
            _echo: &'a [u8],
            _timeout: Duration,
        ) -> zmux::AsyncBoxFuture<'a, zmux::Result<Duration>> {
            Box::pin(async { Ok(Duration::ZERO) })
        }

        fn go_away(
            &self,
            _last_accepted_bidi: u64,
            _last_accepted_uni: u64,
        ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn go_away_with_error<'a>(
            &'a self,
            _last_accepted_bidi: u64,
            _last_accepted_uni: u64,
            _code: u64,
            _reason: &'a str,
        ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn peer_go_away_error(&self) -> Option<zmux::PeerGoAwayError> {
            None
        }

        fn peer_close_error(&self) -> Option<zmux::PeerCloseError> {
            None
        }

        fn local_preface(&self) -> zmux::Preface {
            test_preface()
        }

        fn peer_preface(&self) -> zmux::Preface {
            test_preface()
        }

        fn negotiated(&self) -> zmux::Negotiated {
            zmux::Negotiated {
                proto: 0,
                capabilities: 0,
                local_role: zmux::Role::Initiator,
                peer_role: zmux::Role::Initiator,
                peer_settings: zmux::default_settings(),
            }
        }
    };
}

fn test_preface() -> zmux::Preface {
    zmux::Preface {
        preface_version: 0,
        role: zmux::Role::Initiator,
        tie_breaker_nonce: 0,
        min_proto: 0,
        max_proto: 0,
        capabilities: 0,
        settings: zmux::default_settings(),
    }
}

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

impl zmux::AsyncSession for TimeoutBudgetAsyncSession {
    type Stream = TimeoutBudgetAsyncStream;
    type SendStream = TimeoutBudgetAsyncStream;
    type RecvStream = TimeoutBudgetAsyncStream;

    fn accept_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async move { Ok(self.stream()) })
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        Box::pin(async move { Ok(self.stream()) })
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        self.accept_uni_stream()
    }

    fn open_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        let (opts, timeout) = request.into_parts();
        let open_delay = self.open_delay;
        let stream = self.stream();
        Box::pin(async move {
            opts.validate()?;
            if timeout.is_some() {
                thread::sleep(open_delay);
            }
            Ok(stream)
        })
    }

    fn open_uni_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::SendStream>> {
        let (opts, timeout) = request.into_parts();
        let open_delay = self.open_delay;
        let stream = self.stream();
        Box::pin(async move {
            opts.validate()?;
            if timeout.is_some() {
                thread::sleep(open_delay);
            }
            Ok(stream)
        })
    }

    impl_noop_async_session_controls!();

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::AsyncBoxFuture<'_, zmux::Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn is_closed(&self) -> bool {
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

impl zmux::AsyncStreamHandle for TimeoutBudgetAsyncStream {
    fn stream_id(&self) -> u64 {
        7
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncRecvStreamHandle for TimeoutBudgetAsyncStream {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for TimeoutBudgetAsyncStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.write_attempts.fetch_add(1, Ordering::Relaxed);
            Ok(src.len())
        })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.record_write_timeout(timeout);
            Ok(src.len())
        })
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: zmux::WritePayload<'a>,
        timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.record_write_timeout(timeout);
            payload.checked_len()
        })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.record_write_timeout(timeout);
            Ok(parts.iter().map(|part| part.len()).sum())
        })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for TimeoutBudgetAsyncStream {}

#[derive(Clone)]
struct PayloadRouteAsyncSession {
    payload_calls: Arc<AtomicUsize>,
}

impl PayloadRouteAsyncSession {
    fn stream(&self) -> PayloadRouteAsyncStream {
        PayloadRouteAsyncStream {
            payload_calls: Arc::clone(&self.payload_calls),
        }
    }
}

impl zmux::AsyncSession for PayloadRouteAsyncSession {
    type Stream = PayloadRouteAsyncStream;
    type SendStream = PayloadRouteAsyncStream;
    type RecvStream = PayloadRouteAsyncStream;

    fn accept_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async move { Ok(self.stream()) })
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        Box::pin(async move { Ok(self.stream()) })
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        self.accept_uni_stream()
    }

    fn open_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        let stream = self.stream();
        Box::pin(async move {
            request.open_options().validate()?;
            Ok(stream)
        })
    }

    fn open_uni_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::SendStream>> {
        let stream = self.stream();
        Box::pin(async move {
            request.open_options().validate()?;
            Ok(stream)
        })
    }

    impl_noop_async_session_controls!();

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::AsyncBoxFuture<'_, zmux::Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn is_closed(&self) -> bool {
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

#[derive(Clone)]
struct PayloadRouteAsyncStream {
    payload_calls: Arc<AtomicUsize>,
}

impl zmux::AsyncStreamHandle for PayloadRouteAsyncStream {
    fn stream_id(&self) -> u64 {
        99
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncRecvStreamHandle for PayloadRouteAsyncStream {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn read_timeout<'a>(
        &'a self,
        dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for PayloadRouteAsyncStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final<'a>(
        &'a self,
        payload: zmux::WritePayload<'a>,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move {
            self.payload_calls.fetch_add(1, Ordering::Relaxed);
            payload.checked_len()
        })
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { payload.checked_len() })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for PayloadRouteAsyncStream {}

struct DummyAsyncStream;

impl zmux::AsyncStreamHandle for DummyAsyncStream {
    fn stream_id(&self) -> u64 {
        42
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        3
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
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

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncRecvStreamHandle for DummyAsyncStream {
    fn read<'a>(&'a self, dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
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
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.read(dst)
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for DummyAsyncStream {
    fn write<'a>(&'a self, src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(src.len()) })
    }

    fn write_timeout<'a>(
        &'a self,
        src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        self.write(src)
    }

    fn write_final_timeout<'a>(
        &'a self,
        payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { payload.checked_len() })
    }

    fn write_vectored_final_timeout<'a>(
        &'a self,
        parts: &'a [IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async move { Ok(parts.iter().map(|part| part.len()).sum()) })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for DummyAsyncStream {}

struct InvalidProgressAsyncSession;

impl InvalidProgressAsyncSession {
    fn stream() -> InvalidProgressStream {
        InvalidProgressStream::write_progress(4)
    }
}

impl zmux::AsyncSession for InvalidProgressAsyncSession {
    type Stream = InvalidProgressStream;
    type SendStream = InvalidProgressStream;
    type RecvStream = InvalidProgressStream;

    fn accept_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async { Err(zmux::Error::session_closed()) })
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        Box::pin(async { Err(zmux::Error::session_closed()) })
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        self.accept_uni_stream()
    }

    fn open_stream_with(
        &self,
        _request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async { Ok(InvalidProgressAsyncSession::stream()) })
    }

    fn open_uni_stream_with(
        &self,
        _request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::SendStream>> {
        Box::pin(async { Ok(InvalidProgressAsyncSession::stream()) })
    }

    impl_noop_async_session_controls!();

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::AsyncBoxFuture<'_, zmux::Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn is_closed(&self) -> bool {
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

#[derive(Clone)]
struct CleanupTrackingStream {
    closes: Arc<AtomicUsize>,
}

impl CleanupTrackingStream {
    const INVALID_PROGRESS: usize = 4;

    fn new(closes: Arc<AtomicUsize>) -> Self {
        Self { closes }
    }
}

impl Read for CleanupTrackingStream {
    fn read(&mut self, _dst: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for CleanupTrackingStream {
    fn write(&mut self, _src: &[u8]) -> io::Result<usize> {
        Ok(Self::INVALID_PROGRESS)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl zmux::StreamHandle for CleanupTrackingStream {
    fn stream_id(&self) -> u64 {
        88
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

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
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl zmux::RecvStreamHandle for CleanupTrackingStream {
    fn is_read_closed(&self) -> bool {
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

impl zmux::SendStreamHandle for CleanupTrackingStream {
    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(&self, update: zmux::MetadataUpdate) -> zmux::Result<()> {
        update.validate()
    }

    fn write_timeout(&self, _src: &[u8], _timeout: Duration) -> zmux::Result<usize> {
        Ok(Self::INVALID_PROGRESS)
    }

    fn write_vectored(&self, _parts: &[IoSlice<'_>]) -> zmux::Result<usize> {
        Ok(Self::INVALID_PROGRESS)
    }

    fn write_vectored_timeout(
        &self,
        _parts: &[IoSlice<'_>],
        _timeout: Duration,
    ) -> zmux::Result<usize> {
        Ok(Self::INVALID_PROGRESS)
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

impl zmux::DuplexStreamHandle for CleanupTrackingStream {}

impl zmux::AsyncStreamHandle for CleanupTrackingStream {
    fn stream_id(&self) -> u64 {
        88
    }

    fn is_opened_locally(&self) -> bool {
        true
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        0
    }

    fn append_open_info_to(&self, _dst: &mut Vec<u8>) {}

    fn metadata(&self) -> zmux::StreamMetadata {
        zmux::StreamMetadata::default()
    }

    fn set_deadline(&self, _deadline: Option<Instant>) -> zmux::Result<()> {
        Ok(())
    }

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async move {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

impl zmux::AsyncRecvStreamHandle for CleanupTrackingStream {
    fn read<'a>(&'a self, _dst: &'a mut [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn read_timeout<'a>(
        &'a self,
        _dst: &'a mut [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(0) })
    }

    fn is_read_closed(&self) -> bool {
        false
    }

    fn close_read(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_read(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncSendStreamHandle for CleanupTrackingStream {
    fn write<'a>(&'a self, _src: &'a [u8]) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(Self::INVALID_PROGRESS) })
    }

    fn write_timeout<'a>(
        &'a self,
        _src: &'a [u8],
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(Self::INVALID_PROGRESS) })
    }

    fn write_final_timeout<'a>(
        &'a self,
        _payload: zmux::WritePayload<'a>,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<usize>> {
        Box::pin(async { Ok(Self::INVALID_PROGRESS) })
    }

    fn is_write_closed(&self) -> bool {
        false
    }

    fn update_metadata(
        &self,
        update: zmux::MetadataUpdate,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async move { update.validate() })
    }

    fn close_write(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn cancel_write(&self, _code: u64) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl zmux::AsyncDuplexStreamHandle for CleanupTrackingStream {}

#[derive(Clone)]
struct CleanupTrackingSession {
    closes: Arc<AtomicUsize>,
}

impl CleanupTrackingSession {
    fn new(closes: Arc<AtomicUsize>) -> Self {
        Self { closes }
    }

    fn stream(&self) -> CleanupTrackingStream {
        CleanupTrackingStream::new(Arc::clone(&self.closes))
    }
}

impl zmux::Session for CleanupTrackingSession {
    fn accept_stream(&self) -> zmux::Result<zmux::BoxDuplexStream> {
        Err(zmux::Error::session_closed())
    }

    fn accept_stream_timeout(&self, _timeout: Duration) -> zmux::Result<zmux::BoxDuplexStream> {
        zmux::Session::accept_stream(self)
    }

    fn accept_uni_stream(&self) -> zmux::Result<zmux::BoxRecvStream> {
        Err(zmux::Error::session_closed())
    }

    fn accept_uni_stream_timeout(&self, _timeout: Duration) -> zmux::Result<zmux::BoxRecvStream> {
        zmux::Session::accept_uni_stream(self)
    }

    fn open_stream_with(&self, request: zmux::OpenRequest) -> zmux::Result<zmux::BoxDuplexStream> {
        request.open_options().validate()?;
        Ok(Box::new(self.stream()))
    }

    fn open_uni_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::Result<zmux::BoxSendStream> {
        request.open_options().validate()?;
        Ok(Box::new(self.stream()))
    }

    fn ping(&self, _echo: &[u8]) -> zmux::Result<Duration> {
        Err(zmux::Error::session_closed())
    }

    fn ping_timeout(&self, echo: &[u8], _timeout: Duration) -> zmux::Result<Duration> {
        zmux::Session::ping(self, echo)
    }

    fn go_away(&self, _last_accepted_bidi: u64, _last_accepted_uni: u64) -> zmux::Result<()> {
        Ok(())
    }

    fn go_away_with_error(
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

    fn is_closed(&self) -> bool {
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

    fn peer_go_away_error(&self) -> Option<zmux::PeerGoAwayError> {
        None
    }

    fn peer_close_error(&self) -> Option<zmux::PeerCloseError> {
        None
    }

    fn local_preface(&self) -> zmux::Preface {
        test_preface_role(zmux::Role::Initiator)
    }

    fn peer_preface(&self) -> zmux::Preface {
        test_preface_role(zmux::Role::Responder)
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

impl zmux::AsyncSession for CleanupTrackingSession {
    type Stream = CleanupTrackingStream;
    type SendStream = CleanupTrackingStream;
    type RecvStream = CleanupTrackingStream;

    fn accept_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async { Err(zmux::Error::session_closed()) })
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        zmux::AsyncSession::accept_stream(self)
    }

    fn accept_uni_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        Box::pin(async { Err(zmux::Error::session_closed()) })
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        zmux::AsyncSession::accept_uni_stream(self)
    }

    fn open_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        let stream = self.stream();
        Box::pin(async move {
            request.open_options().validate()?;
            Ok(stream)
        })
    }

    fn open_uni_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::SendStream>> {
        let stream = self.stream();
        Box::pin(async move {
            request.open_options().validate()?;
            Ok(stream)
        })
    }

    impl_noop_async_session_controls!();

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::AsyncBoxFuture<'_, zmux::Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn is_closed(&self) -> bool {
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

struct DummyAsyncSession;

impl zmux::AsyncSession for DummyAsyncSession {
    type Stream = DummyAsyncStream;
    type SendStream = DummyAsyncStream;
    type RecvStream = DummyAsyncStream;

    fn accept_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        Box::pin(async { Ok(DummyAsyncStream) })
    }

    fn accept_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        Box::pin(async { Ok(DummyAsyncStream) })
    }

    fn accept_uni_stream_timeout(
        &self,
        _timeout: Duration,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::RecvStream>> {
        self.accept_uni_stream()
    }

    fn open_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::Stream>> {
        let opts = request.open_options().clone();
        Box::pin(async move {
            opts.validate()?;
            Ok(DummyAsyncStream)
        })
    }

    fn open_uni_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::AsyncBoxFuture<'_, zmux::Result<Self::SendStream>> {
        let opts = request.open_options().clone();
        Box::pin(async move {
            opts.validate()?;
            Ok(DummyAsyncStream)
        })
    }

    impl_noop_async_session_controls!();

    fn close(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_with_error<'a>(
        &'a self,
        _code: u64,
        _reason: &'a str,
    ) -> zmux::AsyncBoxFuture<'a, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> zmux::AsyncBoxFuture<'_, zmux::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn wait_timeout(&self, _timeout: Duration) -> zmux::AsyncBoxFuture<'_, zmux::Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    fn is_closed(&self) -> bool {
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

impl zmux::Session for DummySession {
    fn accept_stream(&self) -> zmux::Result<zmux::BoxDuplexStream> {
        Ok(Box::new(DummyStream))
    }

    fn accept_stream_timeout(&self, _timeout: Duration) -> zmux::Result<zmux::BoxDuplexStream> {
        self.accept_stream()
    }

    fn accept_uni_stream(&self) -> zmux::Result<zmux::BoxRecvStream> {
        Ok(Box::new(DummyStream))
    }

    fn accept_uni_stream_timeout(&self, _timeout: Duration) -> zmux::Result<zmux::BoxRecvStream> {
        self.accept_uni_stream()
    }

    fn open_stream_with(&self, request: zmux::OpenRequest) -> zmux::Result<zmux::BoxDuplexStream> {
        request.open_options().validate()?;
        Ok(Box::new(DummyStream))
    }

    fn open_uni_stream_with(
        &self,
        request: zmux::OpenRequest,
    ) -> zmux::Result<zmux::BoxSendStream> {
        request.open_options().validate()?;
        Ok(Box::new(DummyStream))
    }

    fn open_and_send(&self, request: zmux::OpenSend<'_>) -> zmux::Result<zmux::BoxDuplexStream> {
        let opts = request.open_options();
        opts.validate()?;
        request.payload().checked_len()?;
        Ok(Box::new(DummyStream))
    }

    fn open_uni_and_send(&self, request: zmux::OpenSend<'_>) -> zmux::Result<zmux::BoxSendStream> {
        let opts = request.open_options();
        opts.validate()?;
        request.payload().checked_len()?;
        Ok(Box::new(DummyStream))
    }

    fn ping(&self, _echo: &[u8]) -> zmux::Result<Duration> {
        Ok(Duration::from_millis(1))
    }

    fn ping_timeout(&self, echo: &[u8], _timeout: Duration) -> zmux::Result<Duration> {
        self.ping(echo)
    }

    fn go_away(&self, _last_accepted_bidi: u64, _last_accepted_uni: u64) -> zmux::Result<()> {
        Ok(())
    }

    fn go_away_with_error(
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

    fn is_closed(&self) -> bool {
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

    fn peer_go_away_error(&self) -> Option<zmux::PeerGoAwayError> {
        None
    }

    fn peer_close_error(&self) -> Option<zmux::PeerCloseError> {
        None
    }

    fn local_preface(&self) -> zmux::Preface {
        test_preface_role(zmux::Role::Initiator)
    }

    fn peer_preface(&self) -> zmux::Preface {
        test_preface_role(zmux::Role::Responder)
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

fn test_preface_role(role: zmux::Role) -> zmux::Preface {
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
