//! WebTransport carriers over loopback: one-step `connect` and `serve`
//! with streams both ways and a close the peer sees, lanes on further
//! unidirectional streams without a listener (`accept_pipe`,
//! `handle_lane`) and through a listener in a multipath session, and a
//! lost session that is a failure of its pipes, never their clean end.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use web_transport_quinn::quinn;
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeFailure, Session, SessionError};
use zmux_webtransport::{Options, Url, WebTransportCarrier};

/// A WebTransport server and a client for it over loopback.
struct Wt {
    server: Option<web_transport_quinn::Server>,
    client: web_transport_quinn::Client,
    url: Url,
}

impl Wt {
    fn new(opts: &Options) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let alpn = vec![web_transport_quinn::ALPN.as_bytes().to_vec()];
        let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        tls.alpn_protocols = alpn.clone();
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        server_config.transport_config(Arc::new(opts.transport_config()));
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = alpn;
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        client_config.transport_config(Arc::new(opts.transport_config()));
        let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        Self {
            server: Some(web_transport_quinn::Server::new(endpoint)),
            client: web_transport_quinn::Client::new(client_ep, client_config),
            url: format!("https://{addr}/zmux").parse().unwrap(),
        }
    }

    /// A WebTransport session: the client's end and the server's.
    async fn pair(&mut self) -> (web_transport_quinn::Session, web_transport_quinn::Session) {
        let server = self.server.as_mut().unwrap();
        let (c, s) = tokio::join!(self.client.connect(self.url.clone()), async {
            server.accept().await.unwrap().ok().await
        });
        (c.unwrap(), s.unwrap())
    }
}

/// Sends `n` streams of `len` bytes each from `from` to `to` at once and
/// checks every byte.
async fn transfer(from: &Session, to: &Session, n: usize, len: usize) {
    let receiver = {
        let to = to.clone();
        tokio::spawn(async move {
            let mut readers = Vec::new();
            for _ in 0..n {
                let mut recv = to.accept_uni().await.unwrap();
                readers.push(tokio::spawn(async move {
                    recv.read_to_end(len + 1).await.unwrap()
                }));
            }
            for r in readers {
                let data = r.await.unwrap();
                assert_eq!(data.len(), len);
                assert!(data.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
            }
        })
    };
    let data = bytes::Bytes::from((0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    let mut writers = Vec::new();
    for _ in 0..n {
        let mut send = from.open_uni().await.unwrap();
        let data = data.clone();
        writers.push(tokio::spawn(async move {
            send.write_chunk(data).await.unwrap();
            send.finish().unwrap();
            send
        }));
    }
    for w in writers {
        drop(w.await.unwrap());
    }
    receiver.await.unwrap();
}

/// One step from a client to a session and from a server to its sessions:
/// streams go both ways and a close reaches the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_serve() {
    let opts = Options::default();
    let mut wt = Wt::new(&opts);
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let serving = tokio::spawn(zmux_webtransport::serve(
        listener.clone(),
        wt.server.take().unwrap(),
        opts.clone(),
    ));
    let client = zmux_webtransport::connect(&wt.client, wt.url.clone(), &opts, Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    transfer(&client, &server, 2, 256 << 10).await;
    transfer(&server, &client, 2, 256 << 10).await;
    client.close(0u32.into(), b"bye");
    let e = tokio::time::timeout(Duration::from_secs(10), server.closed())
        .await
        .expect("closed");
    assert!(
        matches!(e, SessionError::ApplicationClosed { remote: true, .. }),
        "{e:?}"
    );
    listener.close();
    serving.await.unwrap();
}

/// Without a listener: the peer's pipe comes from `accept_pipe`, and the
/// lanes, further unidirectional streams of the session, are routed to
/// their pipe by `handle_lane`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lanes_without_a_listener() {
    let opts = Options::default();
    let mut wt = Wt::new(&opts);
    let (cw, sw) = wt.pair().await;
    let client = WebTransportCarrier::new(cw, opts.clone());
    let server = WebTransportCarrier::new(sw, opts);
    let accept = {
        let server = server.clone();
        tokio::spawn(async move {
            Session::accept(server.accept_pipe().await.unwrap(), Config::default())
                .await
                .unwrap()
        })
    };
    let cs = Session::connect(client.open_pipe().await.unwrap(), Config::default())
        .await
        .unwrap();
    let ss = accept.await.unwrap();
    drop((client, server));
    transfer(&cs, &ss, 8, 1 << 20).await;
    assert!(cs.pipe_stats()[0].lanes_out > 1, "no lane was opened");
    assert!(ss.pipe_stats()[0].lanes_in > 1, "no lane was accepted");
    cs.close(0u32.into(), b"");
}

/// Through a listener, in a multipath session: the listener takes the
/// pipe and the lanes the client opens on the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lanes_through_a_listener() {
    let opts = Options::default();
    let mut wt = Wt::new(&opts);
    let config = Config::multipath(PipeAuth::psk(*b"zmux-webtransport-test-psk-01234"));
    let listener = Listener::new(config.clone(), ListenerConfig::default());
    let (cw, sw) = wt.pair().await;
    let _server = WebTransportCarrier::with_listener(sw, &listener, opts.clone());
    let client = WebTransportCarrier::new(cw, opts);
    let cs = Session::connect(client.open_pipe().await.unwrap(), config)
        .await
        .unwrap();
    let ss = listener.accept().await.unwrap();
    assert_eq!(cs.multipath(), zmux::Multipath::InUse);
    transfer(&cs, &ss, 8, 1 << 20).await;
    assert!(cs.pipe_stats()[0].lanes_out > 1, "no lane was opened");
    assert!(ss.pipe_stats()[0].lanes_in > 1, "no lane was accepted");
    cs.close(0u32.into(), b"");
}

/// A WebTransport session that ends under the zmux session is a failure of
/// its pipes, at both ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_session_is_a_failure_not_a_clean_end() {
    let opts = Options::default();
    let mut wt = Wt::new(&opts);
    let (cw, sw) = wt.pair().await;
    let client = WebTransportCarrier::new(cw, opts.clone());
    let server = WebTransportCarrier::new(sw, opts);
    let accept = {
        let server = server.clone();
        tokio::spawn(async move {
            Session::accept(server.accept_pipe().await.unwrap(), Config::default())
                .await
                .unwrap()
        })
    };
    let cs = Session::connect(client.open_pipe().await.unwrap(), Config::default())
        .await
        .unwrap();
    let ss = accept.await.unwrap();
    transfer(&cs, &ss, 2, 64 << 10).await;
    client.session().close(7, b"gone");
    for s in [&cs, &ss] {
        let e = tokio::time::timeout(Duration::from_secs(10), s.closed())
            .await
            .expect("ended");
        assert!(
            matches!(
                e,
                SessionError::PipesLost {
                    last: Some(PipeFailure::Carrier(_))
                }
            ),
            "{e:?}"
        );
    }
}
