//! HTTP streaming peer for the Java HTTP interop test: `server|client|bad KIND ADDR`,
//! KIND `stream`, `split` (HTTP/1.1), `stream2`, `split2` (h2c).
//!
//! Prefix authentication key `right` (`bad` presents `wrong`), 30 s slots, skew 1.
//! `server` serves HTTP/1.1 and h2c on ADDR whatever KIND, prints `READY <address>` (the bound one; port 0 picks a free port), echoes one
//! stream per session (`SESSION <content>`) and answers other requests 418, printing
//! `FALLBACK <target>`. `client` prints `OK ping`; `bad` prints `REFUSED <error>`.
//!
//! KIND `tls1` and `tls2` are bidirectional carriers over TLS 1.3 (HTTP/1.1,
//! HTTP/2) with multipath and no admission: the server serves both and
//! WebSocket upgrades (HTTP/1.1 and HTTP/2 extended `CONNECT`) on a
//! self-signed certificate; the client skips verification, pings, joins a
//! second carrier (Bound, else Sealed: `MODE <mode>`), pings again and prints
//! `OK ping`. `behind` is that server in cleartext (HTTP/1.1 and h2c), for a
//! front that terminates TLS. The client's `wsh2` bootstraps as `tls2` and
//! joins a WebSocket over an HTTP/2 extended `CONNECT` on a TLS connection of
//! its own, in Bound. The server prints `MODE <mode>` for each joined pipe
//! after a stream.

use std::sync::Arc;
use std::time::Duration;
use zmux_web_peer::common;

use tokio::net::TcpListener;
use zmux::{Listener, Session};
use zmux_http::{Http2Connection, Options};
use zmux_rustls::TlsConnection;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mode, kind, addr) = (args[1].as_str(), args[2].as_str(), args[3].as_str());
    match (mode, kind) {
        ("server", "tls1" | "tls2" | "wsh2") => mp_server(addr, true).await,
        ("server", "behind") => mp_server(addr, false).await,
        ("client", "tls1" | "tls2" | "wsh2") => mp_client(kind, addr).await,
        ("server", _) => server(addr).await,
        ("client" | "bad", _) => {
            client(
                kind,
                addr,
                if mode == "client" { b"right" } else { b"wrong" },
            )
            .await;
        }
        (other, _) => panic!("unknown mode {other}"),
    }
}

async fn server(addr: &str) {
    let fallback = zmux_http::Fallback::new(|req: zmux_http::FallbackRequest, _| async move {
        let target = req.uri().path().to_string();
        println!("FALLBACK {target}");
        let mut resp = http::Response::new(zmux_http::PipeBody::full(format!("fallback {target}")));
        *resp.status_mut() = http::StatusCode::IM_A_TEAPOT;
        resp
    });
    let listener = common::listener(b"right", None);
    let tcp = TcpListener::bind(addr).await.expect("bind");
    let local = tcp.local_addr().expect("local address");
    tokio::spawn(zmux_http::serve(
        listener.clone(),
        tcp,
        Options::default().with_fallback(fallback),
    ));
    println!("READY {local}");
    common::serve_sessions(listener).await;
}

async fn client(kind: &str, addr: &str, key: &[u8]) {
    let options = Options::default().with_carrier_credential(Arc::new(common::auth(key)));
    let config = zmux::Config::default();
    let session = match kind {
        "stream" => zmux_http::connect_http1(addr, &options, config).await,
        "split" => zmux_http::connect_http1_split(addr, &options, config).await,
        "stream2" | "split2" => match Http2Connection::connect(addr, options).await {
            Ok(h2) if kind == "stream2" => h2.connect_session(config).await,
            Ok(h2) => h2.connect_split_session(config).await,
            Err(e) => {
                println!("REFUSED {e}");
                return;
            }
        },
        other => panic!("unknown kind {other}"),
    };
    let session = match session {
        Ok(s) => s,
        Err(e) => {
            println!("REFUSED {e}");
            return;
        }
    };
    match common::ping(&session).await {
        Ok(got) => println!("OK {got}"),
        Err(e) => println!("REFUSED {e}"),
    }
    session.close().await;
}

async fn mp_server(addr: &str, tls: bool) {
    let listener = Listener::new(mp_config(), zmux::ListenerConfig::default()).expect("listener");
    let endpoint = zmux_http::Endpoint::new(listener.clone(), Options::default())
        .with_websocket(zmux_websocket::Options::default());
    let tcp = TcpListener::bind(addr).await.expect("bind");
    let local = tcp.local_addr().expect("local address");
    if tls {
        let acceptor = tls_acceptor();
        tokio::spawn(async move {
            endpoint
                .serve_with(
                    || tcp.accept(),
                    move |conn, _| {
                        let accepted = acceptor.accept(conn);
                        async move { accepted.await.map(TlsConnection::new) }
                    },
                )
                .await;
        });
    } else {
        tokio::spawn(endpoint.serve(tcp));
    }
    println!("READY {local}");
    while let Some(session) = listener.accept().await {
        tokio::spawn(echo_all(session));
    }
}

fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let cert = zmux_testcert::self_signed(vec!["localhost".into(), "127.0.0.1".into()])
        .expect("certificate");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(vec![der], key)
    .expect("certificate");
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(server))
}

/// Accepts any server certificate: the peers' certificates are generated at start.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS 1.3 connection to `addr` offering `alpn`.
async fn tls_conn(addr: &str, alpn: &[u8]) -> TlsConnection {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    c.alpn_protocols = vec![alpn.to_vec()];
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let tls = tokio_rustls::TlsConnector::from(Arc::new(c))
        .connect(name, tcp)
        .await
        .expect("TLS handshake");
    TlsConnection::new(tls)
}

/// A WebSocket over an HTTP/2 extended `CONNECT` on a TLS connection of its own.
async fn ws_h2(addr: &str) -> std::io::Result<zmux::PipeIo> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;
    let conn = tls_conn(addr, b"h2").await;
    let binding = conn.binding();
    let (mut sender, driver) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(conn))
            .await
            .map_err(std::io::Error::other)?;
    tokio::spawn(driver);
    let mut req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://{addr}/zmux"))
        .header("sec-websocket-version", "13")
        .header(
            "sec-websocket-protocol",
            String::from_utf8_lossy(zmux::proto::ident::DEFAULT_ALPN).as_ref(),
        )
        .body(zmux_http::PipeBody::empty())
        .map_err(std::io::Error::other)?;
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    let resp = sender
        .send_request(req)
        .await
        .map_err(std::io::Error::other)?;
    if resp.status() != http::StatusCode::OK {
        return Err(std::io::Error::other(format!("status {}", resp.status())));
    }
    let protocol = resp
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let upgraded = hyper::upgrade::on(resp)
        .await
        .map_err(std::io::Error::other)?;
    let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
    Ok(binding.apply(zmux_websocket::pipe(ws, protocol)))
}

async fn mp_client(kind: &str, addr: &str) {
    let https = Options::default().with_https(true);
    let config = mp_config();
    let h2 = if kind == "tls1" {
        None
    } else {
        Some(
            Http2Connection::handshake(tls_conn(addr, b"h2").await, addr, https.clone())
                .await
                .expect("HTTP/2"),
        )
    };
    let dial = async || match &h2 {
        Some(h2) => h2.open_pipe().await,
        None => zmux_http::dial_http1_over(tls_conn(addr, b"http/1.1").await, addr, &https).await,
    };
    let session = Session::connect(dial().await.expect("dial"), config)
        .await
        .expect("session");
    println!("OK {}", common::ping(&session).await.expect("ping"));
    let modes: &[zmux::RecordMode] = if kind == "wsh2" {
        &[zmux::RecordMode::Bound]
    } else {
        &[zmux::RecordMode::Bound, zmux::RecordMode::Sealed]
    };
    let mut joined = false;
    for &mode in modes {
        let mut result = None;
        for _ in 0..100 {
            let io = if kind == "wsh2" {
                ws_h2(addr).await
            } else {
                dial().await
            };
            result = join(&session, io, mode).await;
            if result.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        match result.unwrap_or_else(|| Err("deferred".to_owned())) {
            Ok(m) => {
                println!("MODE {m}");
                joined = true;
                break;
            }
            Err(e) => println!("JOIN {} refused: {e}", mode_name(Some(mode))),
        }
    }
    if !joined {
        println!("ERROR no join");
        std::process::exit(1);
    }
    match common::ping(&session).await {
        Ok(got) => println!("OK {got}"),
        Err(e) => println!("ERROR {e}"),
    }
    session.close().await;
}

/// Joins `io` in `mode`; `None` when a refused join holds joins back.
async fn join(
    session: &Session,
    io: std::io::Result<zmux::PipeIo>,
    mode: zmux::RecordMode,
) -> Option<Result<String, String>> {
    let io = match io {
        Ok(io) => io,
        Err(e) => return Some(Err(e.to_string())),
    };
    let pipe = match session.begin_add_pipe(io, zmux::PipeOptions::new().with_record_mode(mode)) {
        Ok(pipe) => pipe,
        Err(zmux::PipeError::Deferred) => return None,
        Err(e) => return Some(Err(e.to_string())),
    };
    Some(
        match tokio::time::timeout(Duration::from_secs(10), pipe.joined()).await {
            Err(_) => Err("join timed out".to_owned()),
            Ok(Err(e)) => Err(e.to_string()),
            Ok(Ok(())) => Ok(mode_name(pipe.stats().and_then(|s| s.record_mode))),
        },
    )
}

/// The session configuration of the TLS peers: multipath with a pre-shared
/// join key of 32 bytes 7, joins in Bound only on a carrier that declares
/// the contract.
#[must_use]
pub fn mp_config() -> zmux::Config {
    let mut c = zmux::Config::multipath(zmux::PipeAuth::psk([7u8; 32]).with_end_to_end());
    c.max_pipes = 4;
    c.allow_record_mode = Some(zmux::AllowRecordMode::new(|c, mode, _| {
        mode == zmux::RecordMode::Sealed
            || mode == zmux::RecordMode::Bound && c.secure && c.has_exporter
    }));
    c
}

/// The record mode as the peers print it.
#[must_use]
pub fn mode_name(m: Option<zmux::RecordMode>) -> String {
    m.map_or_else(|| "none".to_owned(), |m| format!("{m:?}").to_lowercase())
}

/// Echoes every stream of `session`. After each it prints `SESSION
/// <content>` and `MODE <mode>` for each joined pipe.
pub async fn echo_all(session: Session) {
    while let Ok((mut send, mut recv)) = session.accept_bi().await {
        let Ok(data) = recv.read_to_end(1 << 20).await else {
            return;
        };
        if send.write_all(&data).await.is_ok() {
            let _ = send.finish();
        }
        println!("SESSION {}", String::from_utf8_lossy(&data));
        for s in session.pipe_stats() {
            if s.pipe != zmux::PipeId::new(0) {
                println!("MODE {}", mode_name(s.record_mode));
            }
        }
    }
}
