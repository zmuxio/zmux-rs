//! The runtime settings of sessions and streams read back as in force: what
//! the configuration or a setter gave, with no copy kept beside the core.

use std::net::{TcpListener, TcpStream};

use zmux::sched::Scheduler;
use zmux::{CapacityFloor, Config, PipeIo, Priority, QualityBand, Session};

#[tokio::test]
async fn session_and_stream_settings_read_back() {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let mut c = Config::default();
    c.scheduler = Scheduler::SpreadEta;
    let (client, server) = tokio::join!(
        async { Session::connect(PipeIo::new(a), c).await.unwrap() },
        async {
            Session::accept(PipeIo::new(b), Config::default())
                .await
                .unwrap()
        }
    );
    assert!(matches!(client.scheduler(), Scheduler::SpreadEta));
    assert!(matches!(server.scheduler(), Scheduler::Affinity));
    client.set_scheduler(Scheduler::SpreadRoundRobin);
    assert!(matches!(client.scheduler(), Scheduler::SpreadRoundRobin));

    assert!(client.quality_band().is_none() && client.capacity_floor().is_none());
    let band = QualityBand {
        rtt: Some(std::time::Duration::from_millis(5)),
        ..QualityBand::default()
    };
    client.set_quality_band(Some(band)).unwrap();
    assert_eq!(client.quality_band(), Some(band));
    let floor = CapacityFloor::new(1000);
    client.set_capacity_floor(Some(floor)).unwrap();
    assert_eq!(client.capacity_floor(), Some(floor));
    client.set_quality_band(None).unwrap();
    client.set_capacity_floor(None).unwrap();
    assert!(client.quality_band().is_none() && client.capacity_floor().is_none());
    assert!(client.shaper().is_none());

    let (send, recv) = client.open_bi().await.unwrap();
    assert!(send.scheduler().is_none());
    assert_eq!(send.redundant(), None);
    // A new sending part has the local default, not the wire default.
    assert_eq!(send.priority(), Priority::LOCAL_DEFAULT);
    assert_eq!(Priority::LOCAL_DEFAULT, Priority::new(3, true).unwrap());
    assert_eq!(Priority::WIRE_DEFAULT, Priority::new(3, false).unwrap());
    let session_buffer = send.send_buffer();
    send.set_send_buffer(1 << 20).unwrap();
    send.set_scheduler(Some(Scheduler::SpreadRoundRobin))
        .unwrap();
    send.set_redundant(Some(true)).unwrap();
    assert_eq!(send.send_buffer(), 1 << 20);
    assert!(session_buffer != 1 << 20);
    assert!(matches!(
        send.scheduler(),
        Some(Scheduler::SpreadRoundRobin)
    ));
    assert_eq!(send.redundant(), Some(true));
    send.set_scheduler(None).unwrap();
    assert!(send.scheduler().is_none());

    assert_eq!(recv.peer_priority(), None);
    let (initial, _) = recv.receive_window();
    recv.set_receive_window(initial + 4096, initial + 8192)
        .unwrap();
    assert_eq!(recv.receive_window(), (initial + 4096, initial + 8192));
    // A cap of 0 is automatic; a nonzero cap below the initial window is an
    // invalid argument that changes nothing; a lower initial window only
    // changes what is read back.
    recv.set_receive_window(initial + 4096, 0).unwrap();
    assert_eq!(recv.receive_window(), (initial + 4096, 0));
    assert_eq!(
        recv.set_receive_window(initial + 8192, initial),
        Err(zmux::StreamError::InvalidArgument)
    );
    assert_eq!(recv.receive_window(), (initial + 4096, 0));
    recv.set_receive_window(initial, 0).unwrap();
    assert_eq!(recv.receive_window(), (initial, 0));
    recv.set_receive_window(initial + 4096, initial + 8192)
        .unwrap();
    // Before the stream's first frame the request rides its preamble.
    let want = Priority::new(1, true).unwrap();
    if recv.set_peer_priority(want).is_ok() {
        assert_eq!(recv.peer_priority(), Some(want));
    }
    drop(server);
}

#[test]
fn blocking_settings_read_back() {
    use zmux::blocking::PipeIo;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        zmux::blocking::Session::accept(PipeIo::from_tcp(c), Config::default()).unwrap()
    });
    let client = zmux::blocking::Session::connect(
        PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
        Config::default(),
    )
    .unwrap();
    let _server = server.join().unwrap();
    client.set_scheduler(Scheduler::SpreadEta);
    assert!(matches!(client.scheduler(), Scheduler::SpreadEta));
    let floor = CapacityFloor::new(500);
    client.set_capacity_floor(Some(floor)).unwrap();
    assert_eq!(client.capacity_floor(), Some(floor));
    let (send, recv) = client.open_bi().unwrap();
    send.set_send_buffer(1 << 20).unwrap();
    assert_eq!(send.send_buffer(), 1 << 20);
    send.set_redundant(Some(false)).unwrap();
    assert_eq!(send.redundant(), Some(false));
    assert!(send.scheduler().is_none());
    let (initial, _) = recv.receive_window();
    recv.set_receive_window(initial + 4096, initial + 8192)
        .unwrap();
    assert_eq!(recv.receive_window(), (initial + 4096, initial + 8192));
    assert_eq!(recv.peer_priority(), None);
}

/// A getter never fails and never waits: on a stream of a closed session it
/// returns the value the stream held last.
#[tokio::test]
async fn stream_getters_after_the_session_closed_return_the_last_value() {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (client, server) = tokio::join!(
        async {
            Session::connect(PipeIo::new(a), Config::default())
                .await
                .unwrap()
        },
        async {
            Session::accept(PipeIo::new(b), Config::default())
                .await
                .unwrap()
        }
    );
    let (send, recv) = client.open_bi().await.unwrap();
    let want = Priority::new(1, false).unwrap();
    send.set_priority(want).unwrap();
    send.set_send_buffer(1 << 20).unwrap();
    send.set_scheduler(Some(Scheduler::SpreadRoundRobin))
        .unwrap();
    send.set_redundant(Some(true)).unwrap();
    let (initial, _) = recv.receive_window();
    recv.set_receive_window(initial + 4096, initial + 8192)
        .unwrap();
    let asked = Priority::new(5, true).unwrap();
    let asked_ok = recv.set_peer_priority(asked).is_ok();
    let peer = recv.peer_priority();

    client.close().await;
    client.closed().await;
    drop(server);

    assert_eq!(send.priority(), want);
    assert_eq!(send.send_buffer(), 1 << 20);
    assert!(matches!(
        send.scheduler(),
        Some(Scheduler::SpreadRoundRobin)
    ));
    assert_eq!(send.redundant(), Some(true));
    assert_eq!(recv.receive_window(), (initial + 4096, initial + 8192));
    assert_eq!(recv.peer_priority(), peer);
    if asked_ok {
        assert_eq!(peer, Some(asked));
    }
}

#[test]
fn blocking_stream_getters_after_the_session_closed_return_the_last_value() {
    use zmux::blocking::PipeIo;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        zmux::blocking::Session::accept(PipeIo::from_tcp(c), Config::default()).unwrap()
    });
    let client = zmux::blocking::Session::connect(
        PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
        Config::default(),
    )
    .unwrap();
    let _server = server.join().unwrap();
    let (send, recv) = client.open_bi().unwrap();
    let want = Priority::new(0, false).unwrap();
    send.set_priority(want).unwrap();
    send.set_send_buffer(1 << 19).unwrap();
    let (initial, _) = recv.receive_window();
    recv.set_receive_window(initial + 1024, initial + 2048)
        .unwrap();
    client.close();
    let _ = client.closed();
    assert_eq!(send.priority(), want);
    assert_eq!(send.send_buffer(), 1 << 19);
    assert_eq!(recv.receive_window(), (initial + 1024, initial + 2048));
}

/// A `StreamHandle` reads the same settings as the parts, without holding a
/// part: while the parts exist, after they were dropped (the session
/// discarded the stream) and after the session closed.
#[tokio::test]
async fn stream_handle_getters_read_without_a_part() {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (client, server) = tokio::join!(
        async {
            Session::connect(PipeIo::new(a), Config::default())
                .await
                .unwrap()
        },
        async {
            Session::accept(PipeIo::new(b), Config::default())
                .await
                .unwrap()
        }
    );
    let (send, recv) = client.open_bi().await.unwrap();
    let handle = send.handle();
    let other = recv.handle();
    // The defaults, before anything is set.
    assert_eq!(handle.priority(), Priority::LOCAL_DEFAULT);
    assert!(handle.scheduler().is_none() && handle.redundant().is_none());
    assert_eq!(handle.peer_priority(), None);

    let want = Priority::new(1, false).unwrap();
    send.set_priority(want).unwrap();
    send.set_send_buffer(1 << 20).unwrap();
    send.set_scheduler(Some(Scheduler::SpreadRoundRobin))
        .unwrap();
    send.set_redundant(Some(true)).unwrap();
    let (initial, _) = recv.receive_window();
    recv.set_receive_window(initial + 4096, initial + 8192)
        .unwrap();
    let asked = recv
        .set_peer_priority(Priority::new(5, true).unwrap())
        .is_ok();
    let check = |h: &zmux::StreamHandle| {
        assert_eq!(h.priority(), want);
        assert_eq!(h.send_buffer(), 1 << 20);
        assert!(matches!(h.scheduler(), Some(Scheduler::SpreadRoundRobin)));
        assert_eq!(h.redundant(), Some(true));
        assert_eq!(h.receive_window(), (initial + 4096, initial + 8192));
    };
    check(&handle);
    check(&other);
    assert_eq!(handle.peer_priority(), recv.peer_priority());
    assert_eq!(asked, handle.peer_priority().is_some());
    let peer = handle.peer_priority();

    // The handle holds no part: the stream goes with the parts, and the
    // handle keeps what the stream held last.
    let mut send = send;
    send.reset(zmux::VarInt::from_u32(0)).unwrap();
    let mut recv = recv;
    recv.stop(zmux::VarInt::from_u32(0)).unwrap();
    drop((send, recv));
    check(&handle);
    assert_eq!(handle.peer_priority(), peer);
    client.close().await;
    client.closed().await;
    drop(server);
    check(&handle);
    check(&other.clone());
}
