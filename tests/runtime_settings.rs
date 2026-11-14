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
    assert!(send.scheduler().unwrap().is_none());
    assert_eq!(send.redundant().unwrap(), None);
    let session_buffer = send.send_buffer().unwrap();
    send.set_send_buffer(1 << 20).unwrap();
    send.set_scheduler(Some(Scheduler::SpreadRoundRobin))
        .unwrap();
    send.set_redundant(Some(true)).unwrap();
    assert_eq!(send.send_buffer().unwrap(), 1 << 20);
    assert!(session_buffer != 1 << 20);
    assert!(matches!(
        send.scheduler().unwrap(),
        Some(Scheduler::SpreadRoundRobin)
    ));
    assert_eq!(send.redundant().unwrap(), Some(true));
    send.set_scheduler(None).unwrap();
    assert!(send.scheduler().unwrap().is_none());

    assert_eq!(recv.peer_priority().unwrap(), None);
    let (initial, _) = recv.receive_window().unwrap();
    recv.set_receive_window(initial + 4096, initial + 8192)
        .unwrap();
    assert_eq!(
        recv.receive_window().unwrap(),
        (initial + 4096, initial + 8192)
    );
    // Before the stream's first frame the request rides its preamble.
    let want = Priority::new(1, true).unwrap();
    if recv.set_peer_priority(want).is_ok() {
        assert_eq!(recv.peer_priority().unwrap(), Some(want));
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
    assert_eq!(send.send_buffer().unwrap(), 1 << 20);
    send.set_redundant(Some(false)).unwrap();
    assert_eq!(send.redundant().unwrap(), Some(false));
    assert!(send.scheduler().unwrap().is_none());
    let (initial, _) = recv.receive_window().unwrap();
    recv.set_receive_window(initial + 4096, initial + 8192)
        .unwrap();
    assert_eq!(
        recv.receive_window().unwrap(),
        (initial + 4096, initial + 8192)
    );
    assert_eq!(recv.peer_priority().unwrap(), None);
}
