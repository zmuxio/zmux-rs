use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use zmux::OpenOptions;
use zmux_quinn::{wrap_session, QuinnStream};

const APPLICATION_PROTOCOL: &str = "zmux-rust-go-quic-interop";
const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DATA: u32 = 1 << 20;

fn positive_env_seconds(name: &str) -> Option<u64> {
    let value = env::var(name).ok()?;
    let parsed = value.trim().parse::<u64>().ok()?;
    (parsed > 0).then_some(parsed)
}

fn process_timeout() -> Duration {
    positive_env_seconds("ZMUX_INTEROP_TIMEOUT_SECONDS")
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_PROCESS_TIMEOUT)
}

fn interop_go_root() -> Option<PathBuf> {
    if env::var("ZMUX_INTEROP").ok().as_deref() != Some("1") {
        eprintln!("skipping Go QUIC interop smoke: set ZMUX_INTEROP=1 to run");
        return None;
    }
    let root = match env::var("ZMUX_GO_ROOT") {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => {
            eprintln!(
                "skipping Go QUIC interop smoke: set ZMUX_GO_ROOT to the Go implementation root"
            );
            return None;
        }
    };
    if !root.is_dir() {
        eprintln!(
            "skipping Go QUIC interop smoke: Go implementation root not found: {}",
            root.display()
        );
        return None;
    }
    let root = match root.canonicalize() {
        Ok(root) => root,
        Err(err) => {
            eprintln!(
                "skipping Go QUIC interop smoke: could not resolve Go implementation root {}: {err}",
                root.display()
            );
            return None;
        }
    };
    if Command::new("go")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| !status.success())
        .unwrap_or(true)
    {
        eprintln!("skipping Go QUIC interop smoke: go executable not found");
        return None;
    }
    Some(root)
}

fn temp_work_dir(prefix: &str) -> io::Result<PathBuf> {
    for attempt in 0..100u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("{prefix}-{}-{nanos}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique zmux QUIC interop temp directory",
    ))
}

struct TempWorkDir {
    path: PathBuf,
}

impl TempWorkDir {
    fn create(prefix: &str) -> io::Result<Self> {
        Ok(Self {
            path: temp_work_dir(prefix)?,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempWorkDir {
    fn drop(&mut self) {
        remove_dir_all_retry(&self.path);
    }
}

fn write_go_helper(work: &Path, go_root: &Path, main_go: &str) -> io::Result<()> {
    let go_root = go_root.canonicalize()?;
    let go_path = go_mod_string(&go_root.display().to_string().replace('\\', "/"));
    let adapter_path = go_mod_string(
        &go_root
            .join("adapter")
            .join("quicmux")
            .display()
            .to_string()
            .replace('\\', "/"),
    );
    fs::write(
        work.join("go.mod"),
        format!(
            "module zmux_rust_go_quic_interop_smoke\n\n\
             go 1.25\n\n\
             require (\n\
                 github.com/quic-go/quic-go v0.59.0\n\
                 github.com/zmuxio/zmux-go v0.0.0\n\
                 github.com/zmuxio/zmux-go/adapter/quicmux v0.0.0\n\
             )\n\n\
             replace github.com/zmuxio/zmux-go => {go_path}\n\
             replace github.com/zmuxio/zmux-go/adapter/quicmux => {adapter_path}\n"
        ),
    )?;
    fs::write(work.join("main.go"), main_go)?;
    Ok(())
}

fn go_mod_string(value: &str) -> String {
    format!("{value:?}")
}

fn helper_exe(work: &Path) -> PathBuf {
    work.join(if cfg!(windows) {
        "interop-helper.exe"
    } else {
        "interop-helper"
    })
}

fn build_go_helper(work: &Path) -> io::Result<PathBuf> {
    let exe = helper_exe(work);
    let child = Command::new("go")
        .arg("build")
        .arg("-mod=mod")
        .arg("-o")
        .arg(&exe)
        .arg(".")
        .current_dir(work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    assert_go_success(wait_for_child(
        ChildGuard { child: Some(child) },
        process_timeout(),
    )?);
    Ok(exe)
}

fn spawn_helper_with_piped_stdin(exe: &Path, args: &[&str]) -> io::Result<ChildGuard> {
    spawn_helper_with_stdin(exe, args, Stdio::piped())
}

fn spawn_helper_with_stdin(exe: &Path, args: &[&str], stdin: Stdio) -> io::Result<ChildGuard> {
    let child = Command::new(exe)
        .args(args)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok(ChildGuard { child: Some(child) })
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn send_start_signal(&mut self) -> io::Result<()> {
        let Some(child) = self.child.as_mut() else {
            return Err(io::Error::other("child already reaped"));
        };
        let Some(mut stdin) = child.stdin.take() else {
            return Err(io::Error::other("child stdin is not piped"));
        };
        stdin.write_all(&[1])?;
        stdin.flush()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn remove_dir_all_retry(path: &Path) {
    for attempt in 0..5 {
        match fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(_) if attempt < 4 => thread::sleep(Duration::from_millis(50 * (attempt + 1))),
            Err(_) => return,
        }
    }
}

struct ProcessOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

fn drain_pipe<R>(pipe: Option<R>) -> thread::JoinHandle<io::Result<String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            pipe.read_to_end(&mut bytes)?;
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })
}

fn wait_for_child(mut guard: ChildGuard, timeout: Duration) -> io::Result<ProcessOutput> {
    let mut child = guard.child.take().expect("child already taken");
    let stdout = drain_pipe(child.stdout.take());
    let stderr = drain_pipe(child.stderr.take());
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            let status = child.wait()?;
            break status;
        }
        thread::sleep(Duration::from_millis(20));
    };

    let stdout = stdout
        .join()
        .map_err(|_| io::Error::other("stdout drain thread panicked"))??;
    let stderr = stderr
        .join()
        .map_err(|_| io::Error::other("stderr drain thread panicked"))??;
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

fn assert_go_success(output: ProcessOutput) {
    assert!(
        !output.timed_out && output.status.success(),
        "go helper failed with status {:?}, timed_out={}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        output.timed_out,
        output.stdout,
        output.stderr
    );
}

async fn assert_go_child_success(child: ChildGuard) {
    let output = tokio::task::spawn_blocking(move || wait_for_child(child, process_timeout()))
        .await
        .expect("go helper wait task panicked")
        .expect("go helper wait failed");
    assert_go_success(output);
}

fn wait_for_ready_addr(path: &Path) -> io::Result<String> {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        match fs::read_to_string(path) {
            Ok(address) => {
                let address = address.trim();
                if !address.is_empty() {
                    return Ok(address.to_owned());
                }
            }
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Go QUIC helper did not publish its ready address",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn quinn_server_config() -> quinn::ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .unwrap();
    tls_config.alpn_protocols = vec![APPLICATION_PROTOCOL.as_bytes().to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config).unwrap()));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .receive_window(MAX_DATA.into())
        .stream_receive_window(MAX_DATA.into())
        .max_concurrent_bidi_streams(64_u8.into())
        .max_concurrent_uni_streams(64_u8.into());
    server_config
}

fn quinn_client_config() -> quinn::ClientConfig {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![APPLICATION_PROTOCOL.as_bytes().to_vec()];

    quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config).unwrap()))
}

async fn connect_to_go_server(address: &str) -> quinn::Connection {
    let server_addr: SocketAddr = address.parse().unwrap();
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    endpoint.set_default_client_config(quinn_client_config());
    let connecting = endpoint.connect(server_addr, "localhost").unwrap();
    tokio::time::timeout(CONNECT_TIMEOUT, connecting)
        .await
        .unwrap()
        .unwrap()
}

async fn accept_one_quinn_connection(endpoint: &quinn::Endpoint) -> quinn::Connection {
    let incoming = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.accept())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(CONNECT_TIMEOUT, incoming)
        .await
        .unwrap()
        .unwrap()
}

async fn read_all_stream(stream: &QuinnStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = [0u8; 256];
    loop {
        let result = tokio::time::timeout(STREAM_TIMEOUT, stream.read(&mut buffer))
            .await
            .unwrap();
        let n = match result {
            Ok(n) => n,
            Err(err) if !out.is_empty() && is_remote_graceful_session_close(&err) => return out,
            Err(err) => panic!("stream read failed: {err}"),
        };
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buffer[..n]);
    }
}

fn is_remote_graceful_session_close(err: &zmux::Error) -> bool {
    err.application_code() == Some(zmux::ErrorCode::NoError.as_u64())
        && err.source() == zmux::ErrorSource::Remote
        && err.termination_kind() == zmux::TerminationKind::SessionTermination
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
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
        cert: &CertificateDer<'_>,
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

fn go_quic_server_main() -> String {
    r#"package main

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "io"
    "math/big"
    "os"
    "time"

    "github.com/quic-go/quic-go"
    quicmux "github.com/zmuxio/zmux-go/adapter/quicmux"
)

func fatal(format string, args ...any) {
    fmt.Fprintf(os.Stdout, "ERR "+format+"\n", args...)
    os.Exit(1)
}

func serverTLS() *tls.Config {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        fatal("generate key: %v", err)
    }
    template := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{CommonName: "localhost"},
        NotBefore: time.Now().Add(-time.Hour),
        NotAfter: time.Now().Add(time.Hour),
        KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        DNSNames: []string{"localhost"},
    }
    der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
    if err != nil {
        fatal("create cert: %v", err)
    }
    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
    keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
    cert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        fatal("load key pair: %v", err)
    }
    return &tls.Config{
        Certificates: []tls.Certificate{cert},
        NextProtos: []string{"APPLICATION_PROTOCOL_PLACEHOLDER"},
    }
}

func main() {
    if len(os.Args) != 2 {
        fatal("usage: main <ready-file>")
    }
    listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS(), nil)
    if err != nil {
        fatal("listen: %v", err)
    }
    defer listener.Close()
    if err := os.WriteFile(os.Args[1], []byte(listener.Addr().String()), 0600); err != nil {
        fatal("ready file: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    conn, err := listener.Accept(ctx)
    if err != nil {
        fatal("accept conn: %v", err)
    }
    session := quicmux.WrapSession(conn)
    defer session.Close()

    stream, err := session.AcceptStream(ctx)
    if err != nil {
        fatal("accept stream: %v", err)
    }
    if got := string(stream.OpenInfo()); got != "rust-open" {
        fatal("open info = %q", got)
    }
    meta := stream.Metadata()
    if meta.Priority != 7 || meta.Group == nil || *meta.Group != 11 {
        fatal("metadata = priority:%d group:%v", meta.Priority, meta.Group)
    }
    payload, err := io.ReadAll(stream)
    if err != nil {
        fatal("read stream: %v", err)
    }
    if got := string(payload); got != "rust->go" {
        fatal("payload = %q", got)
    }
    if _, err := stream.WriteFinal([]byte("go:" + string(payload))); err != nil {
        fatal("write final: %v", err)
    }
    var gate [1]byte
    if _, err := os.Stdin.Read(gate[:]); err != nil {
        fatal("read close signal: %v", err)
    }
    if err := session.Close(); err != nil {
        fatal("close session: %v", err)
    }
    waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer waitCancel()
    if err := session.Wait(waitCtx); err != nil {
        fatal("wait: %v", err)
    }
}
"#
        .replace("APPLICATION_PROTOCOL_PLACEHOLDER", APPLICATION_PROTOCOL)
}

fn go_quic_client_main() -> String {
    r#"package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "os"
    "time"

    "github.com/quic-go/quic-go"
    zmux "github.com/zmuxio/zmux-go"
    quicmux "github.com/zmuxio/zmux-go/adapter/quicmux"
)

func fatal(format string, args ...any) {
    fmt.Fprintf(os.Stdout, "ERR "+format+"\n", args...)
    os.Exit(1)
}

func clientTLS() *tls.Config {
    return &tls.Config{
        InsecureSkipVerify: true,
        NextProtos: []string{"APPLICATION_PROTOCOL_PLACEHOLDER"},
    }
}

func main() {
    if len(os.Args) != 2 {
        fatal("usage: main <addr>")
    }
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    conn, err := quic.DialAddr(ctx, os.Args[1], clientTLS(), nil)
    if err != nil {
        fatal("dial: %v", err)
    }
    session := quicmux.WrapSession(conn)
    defer session.Close()

    var gate [1]byte
    if _, err := os.Stdin.Read(gate[:]); err != nil {
        fatal("read start signal: %v", err)
    }

    priority := uint64(7)
    group := uint64(11)
    stream, err := session.OpenStreamWithOptions(ctx, zmux.OpenOptions{
        InitialPriority: &priority,
        InitialGroup: &group,
        OpenInfo: []byte("go-open"),
    })
    if err != nil {
        fatal("open stream: %v", err)
    }
    if _, err := stream.WriteFinal([]byte("go->rust")); err != nil {
        fatal("write final: %v", err)
    }
    response, err := io.ReadAll(stream)
    if err != nil {
        fatal("read response: %v", err)
    }
    if got := string(response); got != "rust:go->rust" {
        fatal("response = %q", got)
    }
    if err := session.Close(); err != nil {
        fatal("close session: %v", err)
    }
    waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer waitCancel()
    if err := session.Wait(waitCtx); err != nil {
        fatal("wait: %v", err)
    }
}
"#
        .replace("APPLICATION_PROTOCOL_PLACEHOLDER", APPLICATION_PROTOCOL)
}

#[tokio::test]
async fn rust_quinn_client_talks_to_go_quic_server_with_open_metadata() {
    let Some(go_root) = interop_go_root() else {
        return;
    };
    let work = TempWorkDir::create("zmux-rust-go-quic-server-interop").unwrap();
    let main_go = go_quic_server_main();
    write_go_helper(work.path(), &go_root, &main_go).unwrap();
    let exe = build_go_helper(work.path()).unwrap();
    let ready_file = work.path().join("ready.addr");
    let mut child =
        spawn_helper_with_piped_stdin(&exe, &[ready_file.to_str().expect("non-utf8 temp path")])
            .unwrap();
    let address = wait_for_ready_addr(&ready_file).unwrap();

    let conn = connect_to_go_server(&address).await;
    let session = wrap_session(conn);
    let stream = session
        .open_stream_with_options(
            OpenOptions::new()
                .with_initial_priority(7)
                .with_initial_group(11)
                .with_open_info(b"rust-open".to_vec()),
        )
        .await
        .unwrap();
    stream.write_final(b"rust->go").await.unwrap();
    assert_eq!(read_all_stream(&stream).await, b"go:rust->go");
    child.send_start_signal().unwrap();
    assert_go_child_success(child).await;
    session.close();
    let _ = session.wait().await;
}

#[tokio::test]
async fn go_quic_client_talks_to_rust_quinn_server_with_open_metadata() {
    let Some(go_root) = interop_go_root() else {
        return;
    };
    let work = TempWorkDir::create("zmux-go-rust-quic-client-interop").unwrap();
    let main_go = go_quic_client_main();
    write_go_helper(work.path(), &go_root, &main_go).unwrap();
    let exe = build_go_helper(work.path()).unwrap();

    let endpoint = quinn::Endpoint::server(
        quinn_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
        .unwrap();
    let address = endpoint.local_addr().unwrap().to_string();
    let mut child = spawn_helper_with_piped_stdin(&exe, &[&address]).unwrap();

    let conn = accept_one_quinn_connection(&endpoint).await;
    let session = wrap_session(conn);
    child.send_start_signal().unwrap();

    let stream = session.accept_stream_timeout(STREAM_TIMEOUT).await.unwrap();
    assert_eq!(stream.open_info(), b"go-open");
    let metadata = stream.metadata();
    assert_eq!(metadata.priority, Some(7));
    assert_eq!(metadata.group, Some(11));
    assert_eq!(read_all_stream(&stream).await, b"go->rust");
    stream.write_final(b"rust:go->rust").await.unwrap();
    assert_go_child_success(child).await;
    session.close();
    let _ = session.wait().await;
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    endpoint.wait_idle().await;
}
