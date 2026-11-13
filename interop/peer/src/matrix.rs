//! The `matrix-server` / `matrix-client` modes: one scenario of the secure
//! carrier's cross-implementation matrix per process (the contract is the
//! driver's, `zmux-spec/interop/seal-matrix/matrix.py`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use zmux::RecordMode;
use zmux::{Listener, ListenerConfig, PipeOptions, Session, SessionError, VarInt};

use super::{NoVerify, SEAL_NODE, provider, seal_keys, tls_server_config, x25519_dalek_public};

const CLIENT_KEY: [u8; 32] = [0x6b; 32];
const A_LEN: usize = 1 << 20;
const B_LEN: usize = 64 << 10;
const CLOSE_CODE: u32 = 85;
const CLOSE_REASON: &[u8] = b"matrix-close";

type Res<T = ()> = Result<T, String>;

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) % 256) as u8).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Res<[u8; 32]> {
    if s.len() != 64 {
        return Err(format!("bad key id {s}"));
    }
    let mut out = [0; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn profile_of(sc: &str) -> Res<u64> {
    Ok(match sc {
        "psk" | "join" | "epoch" | "close" | "close-idle" => 1,
        "xx" | "appdata" | "proof" => 4,
        other => return Err(format!("unknown scenario {other}")),
    })
}

fn session_config(sc: &str) -> zmux::Config {
    let mut c = super::seal_config();
    if sc == "join" || sc == "epoch" {
        c.max_pipes = 4;
        c.allow_record_mode = Some(zmux::proto::session::AllowRecordMode::new(|_, _, _| true));
    }
    c
}

/// Runs one side's scenario within 30 seconds and exits with its outcome.
/// The server's listen address from the environment variable `env` (for runs
/// across hosts), by default an ephemeral loopback port.
fn listen_addr(env: &str) -> String {
    std::env::var(env).unwrap_or_else(|_| "127.0.0.1:0".into())
}

pub async fn main(server: bool, args: &[String]) -> ! {
    let r = tokio::time::timeout(Duration::from_secs(30), async {
        if server {
            run_server(args).await
        } else {
            run_client(args).await
        }
    })
    .await
    .unwrap_or_else(|_| Err("timeout".into()));
    match r {
        Ok(()) => {
            println!("OK");
            std::process::exit(0)
        }
        Err(e) if e.starts_with("CLOSE lost") => {
            println!("{e}");
            std::process::exit(3)
        }
        Err(e) => {
            println!("FAIL {e}");
            std::process::exit(1)
        }
    }
}

/// Writes `data` and FIN on `send` while reading the echo on `recv`, and
/// checks it.
async fn write_and_check(
    mut send: zmux::SendStream,
    mut recv: zmux::RecvStream,
    data: Vec<u8>,
    what: &str,
) -> Res {
    let n = data.len();
    let writer = async move {
        send.write_all(&data)
            .await
            .map_err(|e| format!("{what} write: {e}"))?;
        send.finish().map_err(|e| format!("{what} finish: {e}"))?;
        Ok::<_, String>(())
    };
    let reader = async {
        recv.read_to_end(n + 1)
            .await
            .map_err(|e| format!("{what} read: {e}"))
    };
    let (w, got) = tokio::join!(writer, reader);
    w?;
    if got? != pattern(n) {
        return Err(format!("{what} echo differs"));
    }
    Ok(())
}

/// Echoes `recv` onto `send`, then FIN, and waits until the FIN went out.
async fn echo(mut send: zmux::SendStream, mut recv: zmux::RecvStream, what: &str) -> Res {
    let mut buf = vec![0u8; 64 << 10];
    while let Some(n) = recv
        .read(&mut buf)
        .await
        .map_err(|e| format!("{what} read: {e}"))?
    {
        send.write_all(&buf[..n])
            .await
            .map_err(|e| format!("{what} write: {e}"))?;
    }
    send.finish().map_err(|e| format!("{what} finish: {e}"))?;
    let _ = send.stopped().await;
    Ok(())
}

/// The server's part of the exchange: echo A, then send B and check it.
async fn server_exchange(s: &Session) -> Res {
    let (send, recv) = s.accept_bi().await.map_err(|e| format!("accept A: {e}"))?;
    echo(send, recv, "A").await?;
    let (send, recv) = s.open_bi().await.map_err(|e| format!("open B: {e}"))?;
    write_and_check(send, recv, pattern(B_LEN), "B").await
}

/// The client's part of the exchange: send A and check it, then echo B.
async fn client_exchange(s: &Session) -> Res {
    let (send, recv) = s.open_bi().await.map_err(|e| format!("open A: {e}"))?;
    write_and_check(send, recv, pattern(A_LEN), "A").await?;
    let (send, recv) = s.accept_bi().await.map_err(|e| format!("accept B: {e}"))?;
    echo(send, recv, "B").await
}

/// The epoch new joins use: the highest of the pipes' epochs and the
/// committed one seen.
fn epoch_of(s: &Session, committed: u64) -> u64 {
    s.pipe_stats()
        .iter()
        .filter_map(|p| p.epoch)
        .max()
        .unwrap_or(0)
        .max(committed)
}

/// Waits for the event EpochCommitted and returns its epoch.
async fn wait_commit(s: &Session) -> Res<u64> {
    while let Some(e) = s.next_event().await {
        if let zmux::SessionEvent::EpochCommitted { epoch } = e {
            return Ok(epoch);
        }
    }
    Err("session ended before EpochCommitted".into())
}

fn print_app_data(data: &[zmux_seal::AppData]) {
    for d in data {
        println!(
            "APPDATA {} {} fs={} auth={}",
            d.message,
            String::from_utf8_lossy(&d.data),
            d.forward_secret,
            d.authenticated
        );
    }
}

/// The Gate of the matrix: the interop Handle, and the client's Peer kept
/// as the admitted value.
struct MatrixGate;

impl zmux_seal::Gate for MatrixGate {
    fn resolve<'a>(
        &'a self,
        handle: &'a [u8],
        source: Option<std::net::SocketAddr>,
    ) -> zmux_seal::BoxFuture<'a, Result<Vec<u8>, zmux_seal::VerifyError>> {
        super::SealGate.resolve(handle, source)
    }
    fn credential<'a>(
        &'a self,
        _: &'a [u8],
        _: zmux_seal::Profile,
        _: &'a [u8],
        _: Option<std::net::SocketAddr>,
    ) -> zmux_seal::BoxFuture<'a, Result<Option<zmux_seal::Credential>, zmux_seal::VerifyError>>
    {
        Box::pin(async { Ok(None) })
    }
    fn commit<'a>(
        &'a self,
        admission: zmux_seal::Admission<'a>,
        _: Option<std::net::SocketAddr>,
    ) -> zmux_seal::BoxFuture<'a, Result<zmux::AdmittedValue, zmux_seal::VerifyError>> {
        let peer = admission.peer.clone();
        Box::pin(async move { Ok(Arc::new(peer) as zmux::AdmittedValue) })
    }
}

fn app_data(message: u8, data: &'static [u8]) -> zmux_seal::AppDataSource {
    Arc::new(move |r: &zmux_seal::AppDataRequest<'_>| {
        let out = if r.message == message {
            data.to_vec()
        } else {
            Vec::new()
        };
        Box::pin(async move { Ok(out) })
    })
}

async fn run_server(args: &[String]) -> Res {
    let sc = args.first().ok_or("scenario")?.as_str();
    profile_of(sc)?;
    let mut opts = zmux_seal::ServerOptions {
        accepted_profiles: vec![1, 3, 4, 5],
        ..Default::default()
    };
    if sc == "join" || sc == "epoch" {
        opts.allow_record_mode = Some(Arc::new(|_, _| true));
    }
    if sc == "appdata" {
        opts.app_data = Some(app_data(2, b"srv-msg2"));
        opts.client_verifier = Some(Arc::new(zmux_seal::PinVerifier::new(
            zmux_seal::static_key_id(&x25519_dalek_public(CLIENT_KEY)),
        )));
    }
    if sc == "proof" {
        let key = zmux_seal::SigningKey::generate(zmux_seal::KEYALG_MLDSA44)
            .map_err(|e| format!("proof key: {e}"))?;
        println!("PROOFKEY {}", hex(&key.key_id()));
        opts.signer = Some(Arc::new(zmux_seal::KeySigner(key)));
    }
    let server = zmux_seal::ServerConfig::new(Arc::new(MatrixGate), SEAL_NODE, opts)
        .map_err(|e| format!("server config: {e}"))?;
    let tcp = TcpListener::bind(listen_addr("ZMUX_MATRIX_LISTEN"))
        .await
        .map_err(|e| e.to_string())?;
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    let listener = Listener::new(session_config(sc), lc).map_err(|e| e.to_string())?;
    println!("LISTEN {}", tcp.local_addr().map_err(|e| e.to_string())?);
    if sc == "join" {
        let tls = TcpListener::bind(listen_addr("ZMUX_MATRIX_LISTENTLS"))
            .await
            .map_err(|e| e.to_string())?;
        println!("LISTENTLS {}", tls.local_addr().map_err(|e| e.to_string())?);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_config(&[])));
        let handler = listener.clone();
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = tls.accept().await {
                let (acceptor, listener) = (acceptor.clone(), handler.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = listener
                            .handle_pipe(
                                zmux_rustls::over_tcp(tls),
                                zmux::PipeHint::from_peer(peer),
                            )
                            .await;
                    }
                });
            }
        });
    }
    tokio::spawn(listener.clone().serve(tcp));
    let s = listener.accept().await.ok_or("listener ended")?;
    let committed = Arc::new(Mutex::new(0u64));
    if sc == "epoch" {
        let (s, c) = (s.clone(), committed.clone());
        tokio::spawn(async move {
            while let Some(e) = s.next_event().await {
                if let zmux::SessionEvent::EpochCommitted { epoch } = e {
                    *c.lock().unwrap() = epoch;
                }
            }
        });
    }
    if sc == "appdata" {
        let peer = s
            .admitted()
            .and_then(|v| v.downcast::<zmux_seal::Peer>().ok())
            .ok_or("no admitted Peer")?;
        print_app_data(&peer.app_data);
    }
    if sc == "close" {
        let (_send, mut recv) = s.accept_bi().await.map_err(|e| format!("accept: {e}"))?;
        let mut buf = vec![0u8; B_LEN];
        let mut got = 0;
        while got < B_LEN {
            match recv
                .read(&mut buf[got..])
                .await
                .map_err(|e| format!("read: {e}"))?
            {
                Some(n) => got += n,
                None => return Err("FIN before 64 KiB".into()),
            }
        }
        // Completes once CONNECTION_CLOSE has been handed to the carrier, so
        // the process may exit. An abort returns at once, and a close after
        // it too: the exit would then race the background write.
        s.close_with_error(VarInt::from_u32(CLOSE_CODE), CLOSE_REASON)
            .await;
        println!("CLOSING");
        return Ok(());
    }
    server_exchange(&s).await?;
    if sc == "close-idle" {
        // Completes once CONNECTION_CLOSE has been handed to the carrier, so
        // the process may exit. An abort returns at once, and a close after
        // it too: the exit would then race the background write.
        s.close_with_error(VarInt::from_u32(CLOSE_CODE), CLOSE_REASON)
            .await;
        println!("CLOSING");
        return Ok(());
    }
    let end = s.closing().await;
    if sc == "epoch" {
        println!("EPOCH {}", epoch_of(&s, *committed.lock().unwrap()));
    }
    match end {
        SessionError::ApplicationClosed {
            code, remote: true, ..
        } if code == VarInt::ZERO => Ok(()),
        other => Err(format!("session end: {other}")),
    }
}

async fn run_client(args: &[String]) -> Res {
    let sc = args.first().ok_or("scenario")?.as_str();
    let profile = profile_of(sc)?;
    let addr = args.get(1).ok_or("address")?.clone();
    let node = zmux_seal::static_key_id(&x25519_dalek_public(SEAL_NODE));
    let pin = if sc == "proof" {
        let id = unhex(args.get(2).ok_or("proof key id")?)?;
        zmux_seal::PinVerifier::with_proof_key(node, id)
    } else {
        zmux_seal::PinVerifier::new(node)
    };
    let mut cfg = zmux_seal::ClientConfig {
        verifier: Some(Arc::new(pin)),
        allowed_profiles: vec![profile],
        require_pq_auth: sc == "proof",
        ..Default::default()
    };
    if profile == 1 {
        let k = seal_keys();
        cfg.handle = k.handle;
        cfg.psk = k.psk;
    }
    if sc == "join" || sc == "epoch" {
        cfg.record_mode = RecordMode::Sealed;
    }
    if sc == "appdata" {
        cfg.static_secret = zmux_seal::StaticSecret::Given(CLIENT_KEY);
        cfg.app_data = Some(app_data(3, b"cli-msg3"));
    }
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (p, peer) = zmux_seal::establish(zmux::PipeIo::tcp(tcp), &cfg)
        .await
        .map_err(|e| format!("establish: {e}"))?;
    let s = Session::connect(p, session_config(sc))
        .await
        .map_err(|e| format!("session: {e}"))?;
    match sc {
        "appdata" => print_app_data(&peer.app_data),
        "proof" => {
            println!(
                "PQ confidential={} authenticated={}",
                peer.pq_confidential, peer.pq_authenticated
            );
            if !peer.pq_authenticated {
                return Err("not PQ authenticated".into());
            }
        }
        "join" => {
            let tls_addr = args.get(2).ok_or("tls address")?;
            let tls = rustls::ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| e.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth();
            let tcp = TcpStream::connect(tls_addr)
                .await
                .map_err(|e| format!("connect tls: {e}"))?;
            let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
            let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
                .connect(name, tcp)
                .await
                .map_err(|e| format!("tls: {e}"))?;
            let pipe = s
                .begin_add_pipe(
                    zmux_rustls::over_tcp(stream),
                    PipeOptions::default().with_record_mode(RecordMode::Bound),
                )
                .map_err(|e| format!("add pipe: {e}"))?;
            pipe.attached().await.map_err(|e| format!("attach: {e}"))?;
            println!("PIPES {}", s.pipes().len());
        }
        "epoch" => {
            s.advance_epoch()
                .map_err(|e| format!("advance epoch: {e}"))?;
            let committed = wait_commit(&s).await?;
            let tcp = TcpStream::connect(&addr)
                .await
                .map_err(|e| format!("connect join: {e}"))?;
            let pipe = s
                .begin_add_pipe(
                    zmux::PipeIo::tcp(tcp),
                    PipeOptions::default().with_record_mode(RecordMode::Sealed),
                )
                .map_err(|e| format!("add pipe: {e}"))?;
            pipe.attached().await.map_err(|e| format!("attach: {e}"))?;
            client_exchange(&s).await?;
            println!("EPOCH {}", epoch_of(&s, committed));
            return graceful_end(&s).await;
        }
        _ => {}
    }
    if sc == "close" {
        let (mut send, _recv) = s.open_bi().await.map_err(|e| format!("open: {e}"))?;
        let chunk = pattern(64 << 10);
        while send.write_all(&chunk).await.is_ok() {}
        return report_close(s.closing().await);
    }
    client_exchange(&s).await?;
    if sc == "close-idle" {
        return report_close(s.closing().await);
    }
    graceful_end(&s).await
}

/// Ends the session with code 0 once its streams have ended, so that the
/// echo of B is not dropped by an immediate close.
async fn graceful_end(s: &Session) -> Res {
    tokio::time::timeout(Duration::from_secs(10), s.shutdown(VarInt::ZERO, b""))
        .await
        .map_err(|_| "shutdown timed out".to_string())?
        .map_err(|e| format!("shutdown: {e}"))
}

fn report_close(end: SessionError) -> Res {
    match end {
        SessionError::ApplicationClosed {
            code,
            reason,
            remote: true,
        } if code == VarInt::from_u32(CLOSE_CODE) => {
            println!(
                "CLOSE code={code} reason={}",
                String::from_utf8_lossy(&reason)
            );
            Ok(())
        }
        other => Err(format!("CLOSE lost {other}")),
    }
}
