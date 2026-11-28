//! HTTP streaming peer for the Java HTTP interop test: `server|client|bad KIND ADDR`,
//! KIND `stream` (HTTP/1.1), `stream2` (h2c), `split` and `split2` (TLS).
//!
//! Prefix authentication key `right` (`bad` presents `wrong`), 30 s slots, skew 1.
//! `server` serves on ADDR and prints `READY <address>` (the bound one; port 0 picks a free port), echoes one
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
        ("server", _) => server(addr, kind.starts_with("split")).await,
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

async fn server(addr: &str, tls: bool) {
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
    let endpoint =
        zmux_http::Endpoint::new(listener.clone(), Options::default().with_fallback(fallback))
            .unwrap();
    serve_http(endpoint, tcp, tls);
    println!("READY {local}");
    common::serve_sessions(listener).await;
}

async fn client(kind: &str, addr: &str, key: &[u8]) {
    let options = Options::default().with_carrier_credential(Arc::new(common::auth(key)));
    let config = zmux::Config::default();
    let session = match kind {
        "stream" => zmux_http::connect_http1(addr, &options, config)
            .await
            .map_err(std::io::Error::from),
        "split" => {
            let address = addr.to_owned();
            let pipe = zmux_http::dial_http1_split_with(
                move || {
                    let address = address.clone();
                    async move { tls_conn(&address, b"http/1.1").await }
                },
                addr,
                &options.with_https(true),
            )
            .await;
            match pipe {
                Ok(pipe) => Session::connect(pipe, config)
                    .await
                    .map_err(std::io::Error::from),
                Err(e) => Err(e),
            }
        }
        "stream2" => match Http2Connection::connect(addr, options).await {
            Ok(h2) => h2
                .connect_session(config)
                .await
                .map_err(std::io::Error::from),
            Err(e) => Err(e),
        },
        "split2" => match tls_conn(addr, b"h2").await {
            Ok(tls) => {
                match Http2Connection::handshake(tls, addr, options.with_https(true)).await {
                    Ok(h2) => h2
                        .connect_split_session(config)
                        .await
                        .map_err(std::io::Error::from),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
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
        .unwrap()
        .with_websocket(zmux_websocket::Options::default());
    let tcp = TcpListener::bind(addr).await.expect("bind");
    let local = tcp.local_addr().expect("local address");
    serve_http(endpoint, tcp, tls);
    println!("READY {local}");
    while let Some(session) = listener.accept().await {
        tokio::spawn(echo_all(session));
    }
}

fn serve_http(endpoint: zmux_http::Endpoint, tcp: TcpListener, tls: bool) {
    if tls {
        let acceptor = common::tls_acceptor();
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
}

/// A TLS 1.3 connection to `addr` offering `alpn`.
async fn tls_conn(addr: &str, alpn: &[u8]) -> std::io::Result<TlsConnection> {
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let tls = common::tls_connector(alpn).connect(name, tcp).await?;
    Ok(TlsConnection::new(tls))
}

/// A WebSocket over an HTTP/2 extended `CONNECT` on a TLS connection of its own.
async fn ws_h2(addr: &str) -> std::io::Result<zmux::PipeIo> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;
    let conn = tls_conn(addr, b"h2").await?;
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
            Http2Connection::handshake(
                tls_conn(addr, b"h2").await.expect("TLS handshake"),
                addr,
                https.clone(),
            )
            .await
            .expect("HTTP/2"),
        )
    };
    let dial = async || match &h2 {
        Some(h2) => h2.open_pipe().await,
        None => zmux_http::dial_http1_over(tls_conn(addr, b"http/1.1").await?, addr, &https).await,
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
    use zmux::{
        AttachmentSpec, AttemptReason, CarrierOpener, ChangeError, ChangeRequest, Directions,
        MemberSpec,
    };

    let io = match io {
        Ok(io) => io,
        Err(e) => return Some(Err(e.to_string())),
    };

    let mut request = ChangeRequest::new(session.capacity(), Duration::from_secs(30));
    request.add.push(MemberSpec {
        candidate: None,
        attachments: vec![AttachmentSpec::new(
            Directions::BOTH,
            zmux::PipeOptions::default().with_record_mode(mode),
        )],
    });
    let change = match session.begin_change(request) {
        Ok(change) => change,
        Err(ChangeError::Capacity) => return None,
        Err(error) => return Some(Err(error.to_string())),
    };
    let attempt = match change.start_member(0, CarrierOpener::prepared(vec![io])) {
        Ok(attempt) => attempt,
        Err(ChangeError::Capacity) => return None,
        Err(error) => return Some(Err(error.to_string())),
    };
    let result = attempt.wait().await;
    if result.reason != AttemptReason::Confirmed {
        return Some(Err(result.error.map_or_else(
            || format!("join: {:?}", result.reason),
            |e| e.to_string(),
        )));
    }
    if let Err(error) = change.commit() {
        return Some(Err(error.to_string()));
    }
    let mode = result
        .pipes
        .first()
        .and_then(|&id| session.pipe(id))
        .and_then(|p| p.stats())
        .and_then(|s| s.record_mode);
    Some(Ok(mode_name(mode)))
}

/// The session configuration of the TLS peers: multipath with a pre-shared
/// join key of 32 bytes 7, joins in Bound only on a carrier that declares
/// the contract.
#[must_use]
pub fn mp_config() -> zmux::Config {
    let mut c = zmux::Config::multipath(zmux::PipeAuth::psk([7u8; 32]).with_end_to_end());
    c.session_policy.limits.steady_attachments = 4;
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
