//! WebTransport carriers over loopback: one-step `connect` and `serve`
//! with streams both ways and a close the peer sees, lanes on further
//! unidirectional streams without a listener (`accept_pipe`,
//! `handle_lane`) and through a listener in a multipath session, and a
//! lost session that is a failure of its pipes, never their clean end;
//! and a request forwarded from early data, answered 425.

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
    /// The client's endpoint and configuration, for connections made
    /// outside `client`.
    client_ep: quinn::Endpoint,
    client_config: quinn::ClientConfig,
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
            client: web_transport_quinn::Client::new(client_ep.clone(), client_config.clone()),
            url: format!("https://{addr}/zmux").parse().unwrap(),
            client_ep,
            client_config,
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
        (*wt.server.take().unwrap()).clone(),
        opts.clone(),
    ));
    let client = zmux_webtransport::connect(&wt.client, wt.url.clone(), &opts, Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert_kind([&client, &server], zmux::CarrierKind::WebTransport);
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

/// An admission decides on the session request before it is answered: a
/// request to the path it accepts carries a session; one to another path
/// goes to the fallback handler, unanswered before, which rejects it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_decides_on_the_session_request() {
    let admission = zmux::Admission::new(0, |info, prefix| {
        assert!(prefix.is_empty());
        let req = info
            .request
            .and_then(|r| r.downcast_ref::<web_transport_quinn::proto::ConnectRequest>())
            .expect("the request");
        assert!(info.has_exporter());
        match req.url.path() {
            "/zmux" => zmux::Verdict::accept(0),
            _ => zmux::Verdict::Fallback,
        }
    });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = zmux_webtransport::WebTransportFallback::new(move |req| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(req.url.path().to_owned());
            let _ = req
                .reject(web_transport_quinn::http::StatusCode::FORBIDDEN)
                .await;
        }
    });
    let opts = Options::default().with_fallback(fallback);
    let mut wt = Wt::new(&opts);
    let listener = Listener::new(Config::default(), admitted(Some(admission)));
    let serving = tokio::spawn(zmux_webtransport::serve(
        listener.clone(),
        (*wt.server.take().unwrap()).clone(),
        opts.clone(),
    ));
    let client = zmux_webtransport::connect(&wt.client, wt.url.clone(), &opts, Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    transfer(&client, &server, 1, 64 << 10).await;
    let mut other = wt.url.clone();
    other.set_path("/other");
    assert!(wt.client.connect(other).await.is_err());
    assert_eq!(rx.recv().await.unwrap(), "/other");
    client.close(0u32.into(), b"");
    listener.close();
    serving.await.unwrap();
}

/// A prefix authentication token bound to the QUIC connection travels in
/// the `Zmux-Prefix-Auth` field of the session request: `dial_over` gives
/// the credential the connection's exporter and is admitted; `dial`, whose
/// client makes the connection itself, has none for a bound credential,
/// and a request without the field is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_token_in_the_session_request() {
    let auth = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), true).unwrap();
    let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024));
    let opts = Options::default();
    let mut wt = Wt::new(&opts);
    let listener = Listener::new(
        Config::default(),
        admitted(Some(zmux::Admission::prefix_auth(verifier))),
    );
    let serving = tokio::spawn(zmux_webtransport::serve(
        listener.clone(),
        (*wt.server.take().unwrap()).clone(),
        opts.clone(),
    ));
    let limit = Duration::from_secs(10);
    let body = async {
        assert!(wt.client.connect(wt.url.clone()).await.is_err(), "no token");
        let client_opts = Options::default().with_credential(Arc::new(auth));
        let e = zmux_webtransport::dial(&wt.client, wt.url.clone(), &client_opts)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        let addr = (wt.url.host_str().unwrap(), wt.url.port().unwrap());
        let addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)
            .unwrap()
            .next()
            .unwrap();
        let conn = wt
            .client_ep
            .connect_with(wt.client_config.clone(), addr, "127.0.0.1")
            .unwrap()
            .await
            .unwrap();
        let pipe = zmux_webtransport::dial_over(conn, wt.url.clone(), &client_opts)
            .await
            .unwrap();
        let client = Session::connect(pipe, Config::default()).await.unwrap();
        let server = listener.accept().await.unwrap();
        transfer(&client, &server, 1, 64 << 10).await;
        client.close(0u32.into(), b"");
    };
    tokio::time::timeout(limit, body).await.unwrap();
    listener.close();
    serving.await.unwrap();
}

/// A session request that an intermediary forwarded from TLS early data
/// (`Early-Data: 1`) is answered 425 before any admission, with an
/// admission and without one, and gives the listener nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_forwarded_from_early_data_is_answered_425() {
    let decided = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = decided.clone();
    let admission = zmux::Admission::new(0, move |_, _| {
        counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        zmux::Verdict::accept(0)
    });
    for admission in [None, Some(admission)] {
        let opts = Options::default();
        let mut wt = Wt::new(&opts);
        let listener = Listener::new(Config::default(), admitted(admission));
        let serving = tokio::spawn(zmux_webtransport::serve(
            listener.clone(),
            (*wt.server.take().unwrap()).clone(),
            opts.clone(),
        ));
        let mut request = web_transport_quinn::proto::ConnectRequest::new(wt.url.clone());
        request.headers.insert(
            "early-data",
            web_transport_quinn::http::HeaderValue::from_static("1"),
        );
        let e = tokio::time::timeout(Duration::from_secs(10), wt.client.connect(request))
            .await
            .expect("answered")
            .expect_err("refused");
        assert!(e.to_string().contains("425"), "{e}");
        assert_eq!(listener.stats().sessions, 0);
        listener.close();
        serving.await.unwrap();
    }
    assert_eq!(decided.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// A session with datagrams enabled sends them as datagrams of the
/// WebTransport session (EXTENSIONS.md Section 6.8), both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_ride_webtransport_datagrams() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut config = Config::default();
        config.enable_datagrams = true;
        let opts = Options::default();
        let mut wt = Wt::new(&opts);
        let listener = Listener::new(config.clone(), ListenerConfig::default());
        let serving = tokio::spawn(zmux_webtransport::serve(
            listener.clone(),
            (*wt.server.take().unwrap()).clone(),
            opts.clone(),
        ));
        let client = zmux_webtransport::connect(&wt.client, wt.url.clone(), &opts, config)
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        for i in 0..20u8 {
            client
                .send_datagram(bytes::Bytes::from(vec![i; 300]))
                .unwrap();
            assert_eq!(server.read_datagram().await.unwrap()[..], [i; 300]);
            server
                .send_datagram(bytes::Bytes::from(vec![i; 30]))
                .unwrap();
            assert_eq!(client.read_datagram().await.unwrap()[..], [i; 30]);
        }
        let (c, s) = (client.stats(), server.stats());
        assert_eq!(
            (c.datagrams_sent_channel, s.datagrams_sent_channel),
            (20, 20)
        );
        assert_eq!(
            (c.datagrams_received_channel, s.datagrams_received_channel),
            (20, 20)
        );
        client.close(0u32.into(), b"bye");
        let _ = server.closed().await;
        listener.close();
        serving.await.unwrap();
    })
    .await
    .expect("deadline");
}

fn admitted(admission: Option<zmux::Admission>) -> ListenerConfig {
    let mut lc = ListenerConfig::default();
    lc.admission = admission;
    lc
}

/// Pipe 0 of each session is of carrier kind `kind`.
fn assert_kind(sessions: [&zmux::Session; 2], kind: zmux::CarrierKind) {
    for s in sessions {
        let p = s.pipe(zmux::PipeId::new(0)).unwrap();
        assert_eq!(p.stats().unwrap().carrier, Some(kind));
    }
}
