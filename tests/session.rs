//! End-to-end tests of the drivers: two zmux sessions over in-memory and
//! TCP carriers.

use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zmux::{Config, OpenError, PipeIo, Session, SessionError, StreamError, VarInt};

async fn pair_with(client: Config, server: Config) -> (Session, Session) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn(Session::accept(PipeIo::new(b), server));
    let client = Session::connect(PipeIo::new(a), client)
        .await
        .expect("connect");
    let server = server.await.unwrap().expect("accept");
    (client, server)
}

async fn pair() -> (Session, Session) {
    pair_with(Config::default(), Config::default()).await
}

fn datagram_config() -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c
}

#[tokio::test]
async fn echo_over_memory() {
    let (client, server) = pair().await;
    let echo = tokio::spawn(async move {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        let data = recv.read_to_end(1 << 20).await.unwrap();
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
        send.stopped().await.unwrap();
        server
    });
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"hello zmux").await.unwrap();
    send.finish().unwrap();
    let reply = recv.read_to_end(1 << 20).await.unwrap();
    assert_eq!(reply, b"hello zmux");
    let _server = echo.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_transfer_with_flow_control() {
    let mut small = Config::default();
    small.initial_stream_receive_window = 16 * 1024;
    small.initial_connection_receive_window = 64 * 1024;
    small.max_stream_receive_window = zmux::Cap::Fixed(64 * 1024);
    small.max_connection_receive_window = zmux::Cap::Fixed(128 * 1024);
    let (client, server) = pair_with(small.clone(), small).await;
    const LEN: usize = 8 * 1024 * 1024;
    let reader = tokio::spawn(async move {
        let mut recv = server.accept_uni().await.unwrap();
        let mut total = 0usize;
        let mut sum = 0u64;
        let mut buf = vec![0u8; 50_000];
        while let Some(n) = recv.read(&mut buf).await.unwrap() {
            for (i, b) in buf[..n].iter().enumerate() {
                assert_eq!(*b, ((total + i) % 251) as u8);
            }
            sum += buf[..n].iter().map(|&b| u64::from(b)).sum::<u64>();
            total += n;
        }
        (total, sum, server)
    });
    let mut send = client.open_uni().await.unwrap();
    let data: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let expected: u64 = data.iter().map(|&b| u64::from(b)).sum();
    for chunk in data.chunks(100_000) {
        send.write_all(chunk).await.unwrap();
    }
    send.finish().unwrap();
    let (total, sum, _server) = reader.await.unwrap();
    assert_eq!(total, LEN);
    assert_eq!(sum, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_streams() {
    let (client, server) = pair().await;
    let srv = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..300 {
            let (mut send, mut recv) = server.accept_bi().await.unwrap();
            tasks.push(tokio::spawn(async move {
                let data = recv.read_to_end(1 << 20).await.unwrap();
                send.write_all(&data).await.unwrap();
                send.finish().unwrap();
                let _ = send.stopped().await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        server
    });
    let mut tasks = Vec::new();
    for i in 0..300u32 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let (mut send, mut recv) = client.open_bi().await.unwrap();
            let msg = format!("stream {i}").repeat(100);
            send.write_all(msg.as_bytes()).await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(1 << 20).await.unwrap(), msg.as_bytes());
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let _server = srv.await.unwrap();
}

#[tokio::test]
async fn reset_and_stop_reach_the_peer() {
    let (client, server) = pair().await;
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"x").await.unwrap();
    let (mut ssend, mut srecv) = server.accept_bi().await.unwrap();
    let mut b = [0u8; 1];
    srecv.read_exact(&mut b).await.unwrap();
    send.reset(VarInt::from_u32(7)).unwrap();
    // The preamble stays reliable on a local stream: the reset is a
    // RESET_STREAM_AT with no application bytes owed.
    assert_eq!(
        srecv.read(&mut b).await,
        Err(StreamError::Reset {
            code: VarInt::from_u32(7),
            reliable_size: 0,
        })
    );
    srecv.stop(VarInt::from_u32(9)).ok();
    ssend.write_all(b"y").await.unwrap();
    recv.stop(VarInt::from_u32(11)).unwrap();
    assert_eq!(ssend.stopped().await, Ok(Some(VarInt::from_u32(11))));
    let err = loop {
        match ssend.write(b"zzz").await {
            Ok(_) => tokio::task::yield_now().await,
            Err(e) => break e,
        }
    };
    assert_eq!(err, StreamError::Stopped(VarInt::from_u32(11)));
}

#[tokio::test]
async fn preamble_and_priority_reach_the_peer() {
    let (client, server) = pair().await;
    // Application TLVs in order, repeats included.
    let pre = zmux::Preamble::new()
        .with_info("route=/chat")
        .with_tlv(0x1000, b"dst")
        .with_tlv(0x1002, [7])
        .with_tlv(0x1000, b"dst2")
        .with_pipe_carrier();
    for ty in [0x0fff, 0x4000, 0x101d] {
        assert_eq!(
            client
                .open_bi_with(&pre.clone().with_tlv(ty, b""))
                .await
                .err(),
            Some(OpenError::InvalidArgument)
        );
    }
    // PIPE_CARRIER only on a bidirectional stream.
    assert_eq!(
        client.open_uni_with(&pre).await.err(),
        Some(OpenError::InvalidArgument)
    );
    // Beyond the peer's Maximum Preamble Size (4096 at most).
    assert_eq!(
        client
            .open_bi_with(&zmux::Preamble::new().with_info(vec![b'x'; 5000]))
            .await
            .err(),
        Some(OpenError::PreambleTooLarge)
    );
    let (mut send, _recv) = client.open_bi_with(&pre).await.unwrap();
    // Reading the identifier pins the stream; the preamble was given at
    // opening, so nothing can come too late.
    send.pin_id().unwrap();
    send.write_all(b"hi").await.unwrap();
    let (_s, mut r) = server.accept_bi().await.unwrap();
    let got = r.preamble();
    assert_eq!(got, pre);
    assert_eq!(got.info().map(|b| &b[..]), Some(&b"route=/chat"[..]));
    assert!(got.is_pipe_carrier());
    assert_eq!(
        got.tlvs().collect::<Vec<_>>(),
        [
            (0x1000, Bytes::from_static(b"dst")),
            (0x1002, Bytes::from_static(&[7])),
            (0x1000, Bytes::from_static(b"dst2")),
        ]
    );
    // A relay forwards the whole preamble, one TLV adjusted.
    let mut next = got.clone();
    next.replace_tlv(0x1002, [6]);
    let (mut fwd, _) = server.open_bi_with(&next).await.unwrap();
    fwd.write_all(b"x").await.unwrap();
    let (_s2, back) = client.accept_bi().await.unwrap();
    let back = back.preamble();
    assert_eq!(back.info(), got.info());
    assert_eq!(back.tlv(0x1002).as_deref(), Some(&[6][..]));
    assert_eq!(back.tlvs().count(), 3);
    let mut b = [0u8; 2];
    r.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"hi");
}

#[tokio::test]
async fn datagrams_both_ways() {
    let (client, server) = pair_with(datagram_config(), datagram_config()).await;
    // The datagram size limit: the peer's 65535-byte limits less the
    // frame type and Flow 0, beyond this endpoint's 16 KiB records.
    assert_eq!(client.max_datagram_size(), Some(65533));
    for len in [65533, 1500, 9000, 16380, 65533] {
        let packet = Bytes::from(vec![len as u8; len]);
        client.send_datagram(packet.clone()).unwrap();
        assert_eq!(server.read_datagram().await.unwrap(), packet);
    }
    client.send_datagram(Bytes::from_static(b"ping")).unwrap();
    assert_eq!(
        server.read_datagram().await.unwrap(),
        Bytes::from_static(b"ping")
    );
    server.send_datagram(Bytes::from_static(b"pong")).unwrap();
    assert_eq!(
        client.read_datagram().await.unwrap(),
        Bytes::from_static(b"pong")
    );
    // Stream datagrams.
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(b"open").await.unwrap();
    // The Flow counts at its largest until the stream has its ID, which
    // the driver gives it when it sends the stream's first frame: the peer
    // accepting the stream shows that it has one.
    let (_ssend, srecv) = server.accept_bi().await.unwrap();
    assert!(send.id().is_some());
    assert_eq!(send.max_datagram_size(5), Some(65532));
    send.send_datagram(5, Bytes::from_static(b"on-stream"))
        .unwrap();
    let d = srecv.read_datagram().await.unwrap();
    assert_eq!(
        (d.context, d.payload),
        (5, Bytes::from_static(b"on-stream"))
    );
}

#[tokio::test]
async fn close_code_reaches_the_peer() {
    let (client, server) = pair().await;
    client.abort(VarInt::from_u32(42), b"bye");
    let e = server.closing().await;
    assert_eq!(
        e,
        SessionError::ApplicationClosed {
            code: VarInt::from_u32(42),
            reason: Bytes::from_static(b"bye"),
            remote: true
        }
    );
    assert!(matches!(
        client.closing().await,
        SessionError::ApplicationClosed { remote: false, .. }
    ));
    assert!(matches!(
        server.accept_bi().await,
        Err(SessionError::ApplicationClosed { .. })
    ));
}

#[tokio::test]
async fn graceful_shutdown_waits_for_streams() {
    let (client, server) = pair().await;
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"req").await.unwrap();
    send.finish().unwrap();
    let srv = tokio::spawn(async move {
        let (mut s, mut r) = server.accept_bi().await.unwrap();
        let req = r.read_to_end(100).await.unwrap();
        let shutdown = {
            let server = server.clone();
            tokio::spawn(async move { server.shutdown(VarInt::from_u32(0), b"done").await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        s.write_all(&req).await.unwrap();
        s.finish().unwrap();
        drop((s, r));
        shutdown.await.unwrap()
    });
    assert_eq!(recv.read_to_end(100).await.unwrap(), b"req");
    drop((send, recv));
    srv.await.unwrap().expect("graceful shutdown");
    assert!(matches!(
        client.closing().await,
        SessionError::ApplicationClosed { remote: true, .. }
    ));
}

#[tokio::test]
async fn ping_measures_rtt() {
    let (client, _server) = pair().await;
    // In-memory pipes report no carrier RTT: the first record carried a
    // QX_PING request already; another one measures again, and concurrent
    // calls join the outstanding request.
    let (a, b) = tokio::join!(client.ping(), client.ping());
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(client.rtt().is_some());
    assert!(a <= Duration::from_secs(1) && b <= Duration::from_secs(1));
    client.close().await;
    assert!(client.ping().await.is_err());
}

#[tokio::test]
async fn async_read_write_traits() {
    let (client, server) = pair().await;
    let srv = tokio::spawn(async move {
        let (mut s, mut r) = server.accept_bi().await.unwrap();
        let mut buf = Vec::new();
        AsyncReadExt::read_to_end(&mut r, &mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
        s.shutdown().await.unwrap();
        server
    });
    let (mut s, mut r) = client.open_bi().await.unwrap();
    AsyncWriteExt::write_all(&mut s, b"through traits")
        .await
        .unwrap();
    AsyncWriteExt::shutdown(&mut s).await.unwrap();
    let mut buf = Vec::new();
    AsyncReadExt::read_to_end(&mut r, &mut buf).await.unwrap();
    assert_eq!(buf, b"through traits");
    let _server = srv.await.unwrap();
}

#[tokio::test]
async fn echo_over_tcp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let session = Session::accept(PipeIo::from_tcp(tcp), Config::default())
            .await
            .unwrap();
        let (mut s, mut r) = session.accept_bi().await.unwrap();
        let data = r.read_to_end(1 << 24).await.unwrap();
        s.write_all(&data).await.unwrap();
        s.finish().unwrap();
        s.stopped().await.unwrap();
        session
    });
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let client = Session::connect(PipeIo::from_tcp(tcp), Config::default())
        .await
        .unwrap();
    let (mut s, mut r) = client.open_bi().await.unwrap();
    let data: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
    s.write_chunk(Bytes::from(data.clone())).await.unwrap();
    s.finish().unwrap();
    assert_eq!(r.read_to_end(1 << 24).await.unwrap(), data);
    let _session = srv.await.unwrap();
}

#[test]
fn blocking_echo_over_tcp() {
    use std::io::{Read, Write};
    use zmux::blocking;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let session =
            blocking::Session::accept(blocking::PipeIo::from_tcp(tcp), Config::default()).unwrap();
        let (mut s, mut r) = session.accept_bi().unwrap();
        let mut data = Vec::new();
        Read::read_to_end(&mut r, &mut data).unwrap();
        Write::write_all(&mut s, &data).unwrap();
        s.finish().unwrap();
        s.stopped().unwrap();
        session
    });
    let tcp = std::net::TcpStream::connect(addr).unwrap();
    let client =
        blocking::Session::connect(blocking::PipeIo::from_tcp(tcp), Config::default()).unwrap();
    let (mut s, mut r) = client.open_bi().unwrap();
    let data: Vec<u8> = (0..2_000_000u32).map(|i| (i * 7) as u8).collect();
    Write::write_all(&mut s, &data).unwrap();
    s.finish().unwrap();
    let mut back = Vec::new();
    Read::read_to_end(&mut r, &mut back).unwrap();
    assert_eq!(back, data);
    let session = srv.join().unwrap();
    client.abort(VarInt::from_u32(3), b"");
    assert!(matches!(
        session.closing(),
        Ok(SessionError::ApplicationClosed { remote: true, .. })
    ));
}

#[test]
fn blocking_read_timeout() {
    use zmux::blocking;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        blocking::Session::accept(blocking::PipeIo::from_tcp(tcp), Config::default()).unwrap()
    });
    let tcp = std::net::TcpStream::connect(addr).unwrap();
    let client =
        blocking::Session::connect(blocking::PipeIo::from_tcp(tcp), Config::default()).unwrap();
    let server = srv.join().unwrap();
    let (mut s, _r) = client.open_bi().unwrap();
    s.write_all(b"x").unwrap();
    let (_ss, mut sr) = server.accept_bi().unwrap();
    let mut b = [0u8; 4];
    assert_eq!(sr.read(&mut b).unwrap(), Some(1));
    sr.set_read_timeout(Some(Duration::from_millis(50)));
    assert_eq!(sr.read(&mut b), Err(zmux::blocking::WaitError::TimedOut));
}

#[tokio::test]
async fn chunked_io_and_received_reset() {
    let (client, server) = pair().await;
    let (mut send, _recv) = client.open_bi().await.unwrap();
    let id = send.pin_id().unwrap();
    let mut chunks = [
        Bytes::from_static(b"one "),
        Bytes::new(),
        Bytes::from(vec![7u8; 100_000]),
    ];
    let w = send.write_chunks(&mut chunks).await.unwrap();
    assert!(w.bytes > 0);
    let (_ssend, mut srecv) = server.accept_bi().await.unwrap();
    assert_eq!(srecv.pin_id().unwrap(), id);
    let mut got = 0;
    let mut bufs = vec![Bytes::new(); 4];
    while got < w.bytes {
        let n = srecv.read_chunks(&mut bufs).await.unwrap().unwrap();
        got += bufs[..n].iter().map(Bytes::len).sum::<usize>();
    }
    send.reset(VarInt::from_u32(3)).unwrap();
    assert_eq!(srecv.received_reset().await, Ok(Some(VarInt::from_u32(3))));
    // A finished stream reports no reset.
    let (mut send2, _r2) = client.open_bi().await.unwrap();
    send2.write_all(b"done").await.unwrap();
    send2.finish().unwrap();
    let (_s, mut r) = server.accept_bi().await.unwrap();
    assert_eq!(r.read_to_end(10).await.unwrap(), b"done");
    assert_eq!(r.received_reset().await, Ok(None));
}

/// A configuration that offers multipath without
/// join credentials, or a session accepted without a listener (which
/// cannot accept joins) that offers it, is refused at once instead of
/// running silently on one pipe.
#[tokio::test]
async fn multipath_configuration_errors_are_reported() {
    let mut no_auth = Config::default();
    no_auth.max_pipes = 8;
    let (a, _b) = tokio::io::duplex(1024);
    assert!(matches!(
        Session::connect(PipeIo::new(a), no_auth).await,
        Err(zmux::ConnectError::InvalidConfig(_))
    ));
    let (_a, b) = tokio::io::duplex(1024);
    let psk = zmux::PipeAuth::psk(*b"a pre-shared key of 32 bytes....");
    assert!(matches!(
        Session::accept(PipeIo::new(b), Config::multipath(psk)).await,
        Err(zmux::ConnectError::InvalidConfig(_))
    ));
}

/// Secret Flags state a choice and never negotiate it: flags
/// that differ close the session with TRANSPORT_PARAMETER_ERROR. (A side without a source
/// is the trace multipath.negotiation.no_secret_source.)
#[tokio::test]
async fn secret_flags_that_differ_close_the_session() {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let psk = zmux::PipeAuth::psk(*b"a pre-shared key of 32 bytes....");
    let listener = zmux::Listener::new(
        Config::multipath(zmux::PipeAuth::exporter()),
        zmux::ListenerConfig::default(),
    )
    .expect("valid listener configuration");
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(
            PipeIo::new(b).with_exporter(|_, _, out| {
                out.fill(1);
                true
            }),
            Default::default(),
        )
        .await
    });
    let client = Session::connect(PipeIo::new(a), Config::multipath(psk)).await;
    if let Ok(client) = client {
        let e = tokio::time::timeout(Duration::from_secs(5), client.closing())
            .await
            .expect("closed");
        assert!(
            matches!(
                e,
                SessionError::TransportClosed { code, .. }
                    if code == zmux::proto::TransportErrorCode::TRANSPORT_PARAMETER_ERROR
            ),
            "{e:?}"
        );
    }
}

/// A graceful shutdown that is cancelled (here by a
/// timeout while a stream keeps it waiting) closes the session at once,
/// with its code and reason.
#[tokio::test]
async fn a_cancelled_shutdown_closes_at_once() {
    let (client, server) = pair().await;
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(b"open").await.unwrap();
    let r = tokio::time::timeout(
        Duration::from_millis(50),
        client.shutdown(VarInt::from_u32(7), b"bye"),
    )
    .await;
    assert!(r.is_err(), "the open stream holds the shutdown");
    let e = tokio::time::timeout(Duration::from_secs(5), server.closing())
        .await
        .expect("closed at once");
    assert!(
        matches!(e, SessionError::ApplicationClosed { code, remote: true, .. } if code == VarInt::from_u32(7)),
        "{e:?}"
    );
}

/// The tracer is
/// told the session's start, its events in order, and its end last.
#[tokio::test]
async fn the_tracer_sees_events_in_order_and_the_end_last() {
    #[derive(Default)]
    struct Log(std::sync::Mutex<Vec<String>>);
    impl zmux::Tracer for Log {
        fn established(&self) {
            self.0.lock().unwrap().push("established".into());
        }
        fn event(&self, event: &zmux::SessionEvent) {
            let name = match event {
                zmux::SessionEvent::GoAwayReceived(_) => "goaway",
                _ => "other",
            };
            self.0.lock().unwrap().push(name.into());
        }
        fn closed(&self, _: &SessionError) {
            self.0.lock().unwrap().push("closed".into());
        }
    }
    let log = std::sync::Arc::new(Log::default());
    let mut config = Config::default();
    config.tracer = Some(log.clone());
    let (client, server) = pair_with(config, Config::default()).await;
    server.shutdown(VarInt::ZERO, b"").await.unwrap();
    client.closing().await;
    let done = || log.0.lock().unwrap().last().map(String::as_str) == Some("closed");
    for _ in 0..500 {
        if done() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(*log.0.lock().unwrap(), ["established", "goaway", "closed"]);
}

/// With `protocols` on both ends, the session's
/// protocol is the accepting side's most preferred one that both list.
#[tokio::test]
async fn protocols_negotiate_the_accepting_sides_preference() {
    let mut client = Config::default();
    client.protocols = Some(vec!["b".into(), "a".into()]);
    let mut server = Config::default();
    server.protocols = Some(vec!["c".into(), "a".into(), "b".into()]);
    let (client, server) = pair_with(client, server).await;
    assert_eq!(client.protocol().as_deref(), Some("a"));
    assert_eq!(server.protocol().as_deref(), Some("a"));
    let (c, s) = pair().await;
    assert_eq!((c.protocol(), s.protocol()), (None, None));
}

#[tokio::test]
async fn a_shaper_pads_the_records_of_a_session() {
    use std::sync::Arc;
    use zmux::shaping::{Caps, Factory, RecordPlan, RecordView, Shaper};
    struct Pad;
    impl Shaper for Pad {
        fn capabilities(&self) -> Caps {
            Caps::PLAN
        }
        fn plan(&mut self, _: &RecordView, plan: &mut RecordPlan) {
            plan.pad_to = 1000;
        }
    }
    struct F;
    impl Factory for F {
        fn shaper(&self, _: &zmux::shaping::ShapedPipe) -> Option<Box<dyn Shaper>> {
            Some(Box::new(Pad))
        }
    }
    let (client, server) = pair().await;
    client.set_shaper(Some(Arc::new(F)), None);
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(b"0123456789").await.unwrap();
    send.finish().unwrap();
    let (_s, mut recv) = server.accept_bi().await.unwrap();
    assert_eq!(recv.read_to_end(100).await.unwrap(), b"0123456789");
    let st = client.shaping_stats();
    assert!(st.wire_spent >= 900, "{st:?}");
}

/// Delays the first record of each pipe it shapes, or every record.
fn first_delay(all: bool) -> std::sync::Arc<dyn zmux::shaping::Factory> {
    use zmux::shaping::{Caps, RecordPlan, RecordView, Shaper};
    struct D {
        all: bool,
        n: u64,
    }
    impl Shaper for D {
        fn capabilities(&self) -> Caps {
            Caps::PLAN
        }
        fn plan(&mut self, _: &RecordView, plan: &mut RecordPlan) {
            if self.n == 0 || self.all {
                plan.delay = Duration::from_millis(20);
            }
            self.n += 1;
        }
    }
    std::sync::Arc::new(move |_: &zmux::shaping::ShapedPipe| {
        Some(Box::new(D { all, n: 0 }) as Box<dyn Shaper>)
    })
}

fn first_delay_config(all: bool) -> Config {
    let mut c = Config::default();
    c.shaper = Some(first_delay(all));
    c
}

/// A shaping delay of the first record of the bootstrap pipe, from the
/// session's creation (`Config::shaper`), holds the transport parameters,
/// which still lead the pipe once it ends: both ends establish and echo.
#[tokio::test]
async fn a_delayed_first_record_keeps_the_parameters_first() {
    for all in [false, true] {
        let run = async {
            let (client, server) =
                pair_with(first_delay_config(all), first_delay_config(all)).await;
            let echo = tokio::spawn(async move {
                let (mut send, mut recv) = server.accept_bi().await.unwrap();
                let data = recv.read_to_end(1 << 20).await.unwrap();
                send.write_all(&data).await.unwrap();
                send.finish().unwrap();
                send.stopped().await.unwrap();
                server
            });
            let (mut send, mut recv) = client.open_bi().await.unwrap();
            send.write_all(b"hello").await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(1 << 20).await.unwrap(), b"hello");
            let _server = echo.await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(10), run)
            .await
            .unwrap_or_else(|_| panic!("all={all}: timed out"));
    }
}

/// [`a_delayed_first_record_keeps_the_parameters_first`] on the blocking
/// driver.
#[test]
fn blocking_a_delayed_first_record_keeps_the_parameters_first() {
    use std::io::{Read, Write};
    use zmux::blocking;
    for all in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let session =
                blocking::Session::accept(blocking::PipeIo::from_tcp(tcp), first_delay_config(all))
                    .unwrap();
            let (mut s, mut r) = session.accept_bi().unwrap();
            let mut data = Vec::new();
            Read::read_to_end(&mut r, &mut data).unwrap();
            Write::write_all(&mut s, &data).unwrap();
            s.finish().unwrap();
            s.stopped().unwrap();
            session
        });
        let tcp = std::net::TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let client =
            blocking::Session::connect(blocking::PipeIo::from_tcp(tcp), first_delay_config(all))
                .unwrap();
        let (mut s, mut r) = client.open_bi().unwrap();
        r.set_read_timeout(Some(Duration::from_secs(10)));
        Write::write_all(&mut s, b"hello").unwrap();
        s.finish().unwrap();
        let mut back = Vec::new();
        Read::read_to_end(&mut r, &mut back).unwrap();
        assert_eq!(back, b"hello", "all={all}");
        let _session = srv.join().unwrap();
        client.close();
    }
}

/// The session's application byte counts are those of
/// its meter, streams and datagrams together.
#[tokio::test]
async fn session_stats_report_the_meter() {
    let (client, server) = pair_with(datagram_config(), datagram_config()).await;
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(b"hello").await.unwrap();
    send.finish().unwrap();
    let (_s, mut r) = server.accept_bi().await.unwrap();
    assert_eq!(r.read_to_end(1 << 10).await.unwrap(), b"hello");
    client.send_datagram(Bytes::from_static(b"dgram")).unwrap();
    assert_eq!(server.read_datagram().await.unwrap(), &b"dgram"[..]);
    let (c, s) = (client.stats(), server.stats());
    assert_eq!((c.bytes_written, c.datagram_bytes_sent), (5, 5));
    assert_eq!((s.bytes_read, s.datagram_bytes_received), (5, 5));
    let m = server.meter().get();
    assert_eq!(
        (
            s.bytes_written,
            s.bytes_read,
            s.datagram_bytes_sent,
            s.datagram_bytes_received
        ),
        (
            m.bytes_written,
            m.bytes_read,
            m.datagram_bytes_sent,
            m.datagram_bytes_received
        )
    );
}

/// A handle that outlives its stream (the sending part
/// of a rejected stream) keeps reading the final statistics.
#[tokio::test]
async fn stream_stats_stay_after_release() {
    let (client, server) = pair().await;
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(b"abc").await.unwrap();
    send.finish().unwrap();
    let (keep, recv) = server.accept_bi().await.unwrap();
    while keep.stats().bytes_received < 3 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    recv.reject().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.stats().streams_active != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the session released the stream");
    let st = keep.stats();
    assert_eq!(st.bytes_received, 3);
    assert_eq!(st.bytes_read, 0);
}

/// The durations since an event are measured at the
/// time of the snapshot, not at the session's latest input.
#[tokio::test]
async fn pipe_stats_are_taken_at_the_current_time() {
    let (client, _server) = pair().await;
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(b"x").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
    let wait = Duration::from_millis(200);
    tokio::time::sleep(wait).await;
    let st = client.pipe_stats();
    let since = st[0].since_last_traffic.expect("a live pipe");
    assert!(since >= wait, "{since:?}");
    let one = client.pipes()[0].stats().unwrap();
    assert!(one.since_last_traffic.unwrap() >= wait);
}

/// An open that waits for stream credit is counted once in
/// `stream_credit_waits`, however long it waits; an open with credit is not.
#[tokio::test]
async fn opens_waiting_for_stream_credit_are_counted() {
    let mut server = Config::default();
    // No bidirectional credit: every bidirectional open waits.
    server.max_incoming_streams = 0;
    let (client, _srv) = pair_with(Config::default(), server).await;
    client.open_uni().await.unwrap();
    assert_eq!(client.stats().stream_credit_waits, 0);
    let waiting = {
        let c = client.clone();
        tokio::spawn(async move { c.open_bi().await.map(|_| ()) })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while client.stats().stream_credit_waits == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the waiting open was not counted");
    // Woken again (another command), it is not counted twice.
    client.open_uni().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(client.stats().stream_credit_waits, 1);
    waiting.abort();
}

/// The negotiation results that are reported by
/// their own calls: establishment, QMux version, TLS state, DATAGRAM and
/// RESET_STREAM_AT support per side, pipe acknowledgement and resume.
#[tokio::test]
async fn negotiation_results_are_reported() {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let tls = zmux::TlsState::new(Some(b"app".to_vec()), Some("example.test".into()));
    let reported = tls.clone();
    let server_io = PipeIo::new(b).with_terminated_tls(move || Some(reported.clone()));
    let server = tokio::spawn(Session::accept(server_io, datagram_config()));
    let client = Session::connect(PipeIo::new(a), Config::default())
        .await
        .expect("connect");
    let server = server.await.unwrap().expect("accept");
    server.established().await.unwrap();
    for s in [&client, &server] {
        assert!(s.is_established());
        assert_eq!(s.qmux_version(), "draft-02");
        assert_eq!(
            s.reset_stream_at_support(),
            zmux::Support {
                local: true,
                peer: true
            }
        );
        // Pipe acknowledgement is on by default; resume needs multipath.
        assert!(s.pipe_ack_in_use());
        assert!(!s.resume_in_use());
        assert!(!s.is_plain_qmux_peer());
    }
    assert_eq!(server.tls(), Some(tls));
    assert_eq!(client.tls(), None);
    assert_eq!(
        server.datagram_support(),
        zmux::Support {
            local: true,
            peer: false
        }
    );
    assert_eq!(
        client.datagram_support(),
        zmux::Support {
            local: false,
            peer: true
        }
    );
}

/// A session without multipath has no epoch.
#[tokio::test]
async fn a_single_pipe_session_has_no_epoch() {
    let (client, server) = pair().await;
    client.established().await.unwrap();
    assert_eq!(client.epoch(), None);
    assert_eq!(server.epoch(), None);
}
