//! QUIC datagrams as the datagram channel of stream pipes (EXTENSIONS.md
//! Section 6.8): a session through a delaying, lossy UDP relay, where
//! datagrams on the channel arrive after the one-way delay while a lost
//! packet of the pipe is retransmitted and datagrams in records wait for
//! it; the fallback to records where the connection has no datagrams one
//! way; and several sessions on one connection, whose channel datagrams
//! the connection's receive loop routes by Pipe Stream ID.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;
use zmux::shaping::{Caps, Shaper};
use zmux::{Config, PipeId, Session};
use zmux_quinn::{Options, QuicCarrier};

/// Every test has a hard deadline.
const DEADLINE: Duration = Duration::from_secs(60);

struct Quic {
    server: quinn::Endpoint,
    client: quinn::Endpoint,
}

impl Quic {
    /// Endpoints with the carrier's transport configuration; `client_dgrams`
    /// false: the client's connections take no QUIC datagrams.
    fn new(client_dgrams: bool) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        tls.alpn_protocols = vec![b"zmux".to_vec()];
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        server_config.transport_config(Arc::new(Options::default().transport_config()));
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"zmux".to_vec()];
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut transport = Options::default().transport_config();
        if !client_dgrams {
            transport.datagram_receive_buffer_size(None);
        }
        let mut cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
        cc.transport_config(Arc::new(transport));
        client.set_default_client_config(cc);
        Self { server, client }
    }

    /// A connection to `addr` (the server's own, or a relay's): the
    /// client's end and the server's.
    async fn connect(&self, addr: SocketAddr) -> (quinn::Connection, quinn::Connection) {
        tokio::join!(
            async {
                self.client
                    .connect(addr, "localhost")
                    .unwrap()
                    .await
                    .unwrap()
            },
            async { self.server.accept().await.unwrap().await.unwrap() }
        )
    }
}

/// A UDP relay between a client and a server that delays every packet by
/// `delay` each way and, once armed, drops every `nth` packet from the
/// client to the server.
struct Relay {
    addr: SocketAddr,
    armed: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relay {
    async fn start(server: SocketAddr, delay: Duration, nth: u64) -> Self {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicU64::new(0));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>, SocketAddr)>();
        let out = sock.clone();
        // Constant delay: deadlines are in arrival order.
        let sender = async move {
            while let Some((at, data, to)) = rx.recv().await {
                tokio::time::sleep_until(at.into()).await;
                let _ = out.send_to(&data, to).await;
            }
        };
        let (a, d) = (armed.clone(), dropped.clone());
        let receiver = async move {
            let mut client = None;
            let mut buf = vec![0u8; 65536];
            let mut seen = 0u64;
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let to = if from == server {
                    match client {
                        Some(c) => c,
                        None => continue,
                    }
                } else {
                    client = Some(from);
                    if a.load(Ordering::Relaxed) {
                        seen += 1;
                        if seen.is_multiple_of(nth) {
                            d.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                    server
                };
                let _ = tx.send((Instant::now() + delay, buf[..n].to_vec(), to));
            }
        };
        let task = tokio::spawn(async move {
            tokio::join!(sender, receiver);
        });
        Self {
            addr,
            armed,
            dropped,
            task,
        }
    }
}

fn dgram_config() -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c
}

/// A session over one QUIC connection: the client's and the server's.
async fn sessions(cc: quinn::Connection, sc: quinn::Connection) -> (Session, Session, QuicCarrier) {
    let client = QuicCarrier::new(cc, Options::default());
    let server = QuicCarrier::new(sc, Options::default());
    let accept = {
        let server = server.clone();
        tokio::spawn(async move {
            Session::accept(server.accept_pipe().await.unwrap(), dgram_config())
                .await
                .unwrap()
        })
    };
    let cs = Session::connect(client.open_pipe().await.unwrap(), dgram_config())
        .await
        .unwrap();
    (cs, accept.await.unwrap(), server)
}

/// A shaper that changes nothing: its pipe's datagrams go in records.
struct Plain;

impl Shaper for Plain {
    fn capabilities(&self) -> Caps {
        Caps::NONE
    }
}

/// Sends `n` datagrams at a steady pace from `from` (one per 20 ms, well
/// within the congestion window of a lossy path) and returns the one-way
/// latency of each that `to` received.
async fn paced(from: &Session, to: &Session, n: usize) -> Vec<Duration> {
    let start = Instant::now();
    let reader = {
        let to = to.clone();
        tokio::spawn(async move {
            let mut lat = Vec::new();
            while let Ok(Ok(d)) =
                tokio::time::timeout(Duration::from_millis(1500), to.read_datagram()).await
            {
                let sent = u64::from_be_bytes(d[..8].try_into().unwrap());
                lat.push(start.elapsed() - Duration::from_micros(sent));
            }
            lat
        })
    };
    for _ in 0..n {
        let mut d = (start.elapsed().as_micros() as u64).to_be_bytes().to_vec();
        d.resize(200, 1);
        from.send_datagram(Bytes::from(d)).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    reader.await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_datagrams_are_not_held_behind_lost_packets() {
    tokio::time::timeout(DEADLINE, async {
        let quic = Quic::new(true);
        let delay = Duration::from_millis(30);
        let relay = Relay::start(quic.server.local_addr().unwrap(), delay, 10).await;
        let (cc, sc) = quic.connect(relay.addr).await;
        let (cs, ss, _server) = sessions(cc, sc).await;
        relay.armed.store(true, Ordering::Relaxed);

        // On the channel: none waits for a retransmission; some are lost.
        let lat = paced(&cs, &ss, 100).await;
        let max = lat.iter().max().copied().unwrap();
        let (c, s) = (cs.stats(), ss.stats());
        assert!(relay.dropped.load(Ordering::Relaxed) > 0);
        assert!(lat.len() < 100, "lost ones are lost: {}", lat.len());
        assert!(lat.len() > 50, "{}", lat.len());
        assert!(max < delay + Duration::from_millis(40), "max {max:?}");
        assert_eq!(c.datagrams_sent_channel, 100);
        assert_eq!(c.datagrams_sent, 100);
        assert_eq!(s.datagrams_received_channel, lat.len() as u64);

        // In records (the pipe is shaped): every one arrives, and those
        // after a lost packet wait for its retransmission.
        assert!(cs.set_pipe_shaper(PipeId::new(0), Some(Box::new(Plain))));
        let lat = paced(&cs, &ss, 100).await;
        let max = lat.iter().max().copied().unwrap();
        assert_eq!(lat.len(), 100, "reliable in records");
        assert!(max > 2 * delay + Duration::from_millis(20), "max {max:?}");
        assert_eq!(
            cs.stats().datagrams_sent_channel,
            100,
            "none more on the channel"
        );
        cs.close(zmux::VarInt::from_u32(0), b"");
    })
    .await
    .expect("deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_datagrams_disabled_locally_fall_back_to_records() {
    tokio::time::timeout(DEADLINE, async {
        let quic = Quic::new(false);
        let (cc, sc) = quic.connect(quic.server.local_addr().unwrap()).await;
        let (cs, ss, _server) = sessions(cc, sc).await;
        for i in 0..20u8 {
            cs.send_datagram(Bytes::from(vec![i; 100])).unwrap();
            ss.send_datagram(Bytes::from(vec![i; 100])).unwrap();
            let (a, b) = tokio::join!(
                tokio::time::timeout(Duration::from_secs(3), ss.read_datagram()),
                tokio::time::timeout(Duration::from_secs(3), cs.read_datagram())
            );
            let (a, b) = (a.unwrap(), b.unwrap());
            assert_eq!(a.unwrap()[0], i);
            assert_eq!(b.unwrap()[0], i);
        }
        let (c, s) = (cs.stats(), ss.stats());
        // The client's datagrams take the server's QUIC datagrams; the
        // client's connection takes none, so the server's go in records.
        // quinn sends no QUIC datagrams where its own configuration takes
        // none: both directions go in records.
        assert_eq!((c.datagrams_sent_channel, s.datagrams_sent_channel), (0, 0));
        assert_eq!(
            (s.datagrams_received_channel, c.datagrams_received_channel),
            (0, 0)
        );
        assert!(c.datagrams_dropped_send == 0 && s.datagrams_dropped_send == 0);
        assert_eq!((c.datagrams_received, s.datagrams_received), (20, 20));
        cs.close(zmux::VarInt::from_u32(0), b"");
    })
    .await
    .expect("deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_sharing_a_connection_get_their_own_channel_datagrams() {
    tokio::time::timeout(DEADLINE, async {
        let quic = Quic::new(true);
        let (cc, sc) = quic.connect(quic.server.local_addr().unwrap()).await;
        let client = QuicCarrier::new(cc, Options::default());
        let server = QuicCarrier::new(sc, Options::default());
        let mut pairs = Vec::new();
        for _ in 0..3 {
            let accept = {
                let server = server.clone();
                tokio::spawn(async move {
                    Session::accept(server.accept_pipe().await.unwrap(), dgram_config())
                        .await
                        .unwrap()
                })
            };
            let cs = Session::connect(client.open_pipe().await.unwrap(), dgram_config())
                .await
                .unwrap();
            pairs.push((cs, accept.await.unwrap()));
        }
        for round in 0..10u8 {
            for (i, (cs, ss)) in pairs.iter().enumerate() {
                cs.send_datagram(Bytes::from(vec![i as u8, round])).unwrap();
                ss.send_datagram(Bytes::from(vec![i as u8, round, 1]))
                    .unwrap();
            }
            for (i, (cs, ss)) in pairs.iter().enumerate() {
                let d = ss.read_datagram().await.unwrap();
                assert_eq!(&d[..], [i as u8, round]);
                let d = cs.read_datagram().await.unwrap();
                assert_eq!(&d[..], [i as u8, round, 1]);
            }
        }
        for (cs, ss) in &pairs {
            assert_eq!(cs.stats().datagrams_received_channel, 10);
            assert_eq!(ss.stats().datagrams_received_channel, 10);
        }
        assert_eq!(client.datagrams().dropped(), 0);
        assert_eq!(server.datagrams().dropped(), 0);
        // A closed session's pipe names no pipe any more: the peer's
        // datagrams for it are dropped and counted by the connection.
        let (cs, ss) = pairs.remove(0);
        cs.close(zmux::VarInt::from_u32(0), b"");
        let _ = ss.closed().await;
        let _ = cs.closed().await;
        let mut tries = 0;
        while server.datagrams().dropped() == 0 && tries < 100 {
            // A raw datagram that names the closed pipe (QUIC stream 0).
            let _ = client.connection().send_datagram(Bytes::from(
                zmux::proto::frame::channel::encode(Some(0), &[0]),
            ));
            tokio::time::sleep(Duration::from_millis(20)).await;
            tries += 1;
        }
        assert!(server.datagrams().dropped() > 0);
        let (cs, ss) = &pairs[0];
        cs.send_datagram(Bytes::from_static(b"still")).unwrap();
        assert_eq!(&ss.read_datagram().await.unwrap()[..], b"still");
    })
    .await
    .expect("deadline");
}
