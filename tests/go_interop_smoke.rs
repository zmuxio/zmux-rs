use std::env;
use std::fs;
use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zmux::{
    Config, Conn, OpenOptions, CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS,
};

const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const READY_TIMEOUT: Duration = Duration::from_secs(5);

static GO_INTEROP_LOCK: Mutex<()> = Mutex::new(());

fn go_interop_guard() -> MutexGuard<'static, ()> {
    GO_INTEROP_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

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
        eprintln!("skipping Go interop smoke: set ZMUX_INTEROP=1 to run");
        return None;
    }
    let root = match env::var("ZMUX_GO_ROOT") {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => {
            eprintln!("skipping Go interop smoke: set ZMUX_GO_ROOT to the Go implementation root");
            return None;
        }
    };
    if !root.is_dir() {
        eprintln!(
            "skipping Go interop smoke: Go implementation root not found: {}",
            root.display()
        );
        return None;
    }
    let root = match root.canonicalize() {
        Ok(root) => root,
        Err(err) => {
            eprintln!(
                "skipping Go interop smoke: could not resolve Go implementation root {}: {err}",
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
        eprintln!("skipping Go interop smoke: go executable not found");
        return None;
    }
    Some(root)
}

fn interop_config() -> Config {
    Config {
        capabilities: CAPABILITY_OPEN_METADATA
            | CAPABILITY_PRIORITY_UPDATE
            | CAPABILITY_PRIORITY_HINTS
            | CAPABILITY_STREAM_GROUPS,
        preface_padding: true,
        preface_padding_min_bytes: 16,
        preface_padding_max_bytes: 16,
        ping_padding: true,
        ping_padding_min_bytes: 16,
        ping_padding_max_bytes: 16,
        ..Config::default()
    }
}

fn tcp_session_client(socket: TcpStream) -> Conn {
    Conn::client_with_config(socket, interop_config()).unwrap()
}

fn tcp_session_server(socket: TcpStream) -> Conn {
    Conn::server_with_config(socket, interop_config()).unwrap()
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
        "could not allocate unique zmux interop temp directory",
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

fn go_mod_version(go_root: &Path) -> io::Result<String> {
    let go_mod = fs::read_to_string(go_root.join("go.mod"))?;
    go_mod
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            matches!(parts.next(), Some("go"))
                .then(|| parts.next())
                .flatten()
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Go root go.mod missing go directive",
            )
        })
}

fn write_go_helper(work: &Path, go_root: &Path, main_go: &str) -> io::Result<()> {
    let go_version = go_mod_version(go_root)?;
    let go_root = go_root.canonicalize()?;
    let go_path = go_mod_string(&go_root.display().to_string().replace('\\', "/"));
    fs::write(
        work.join("go.mod"),
        format!(
            "module zmux_rust_go_interop_smoke\n\n\
             go {go_version}\n\n\
             require github.com/zmuxio/zmux-go v0.0.0\n\n\
             replace github.com/zmuxio/zmux-go => {go_path}\n"
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

fn spawn_helper(exe: &Path, args: &[&str]) -> io::Result<ChildGuard> {
    let child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok(ChildGuard { child: Some(child) })
}

struct ChildGuard {
    child: Option<Child>,
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

fn connect_with_retry(address: &str) -> io::Result<TcpStream> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match TcpStream::connect(address) {
            Ok(socket) => return Ok(socket),
            Err(err) if Instant::now() < deadline => {
                let last_err = err;
                thread::sleep(Duration::from_millis(20));
                if Instant::now() >= deadline {
                    return Err(last_err);
                }
            }
            Err(err) => return Err(err),
        }
    }
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
                "Go helper did not publish its ready address",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn accept_with_timeout(listener: TcpListener, timeout: Duration) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false)?;
                return Ok(socket);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for Go client connection",
                ));
            }
            Err(err) => return Err(err),
        }
    }
}

fn read_all_stream(mut stream: zmux::Stream) -> Vec<u8> {
    let mut out = Vec::new();
    stream.read_to_end(&mut out).unwrap();
    out
}

fn go_server_main() -> &'static str {
    r#"package main

import (
    "context"
    "fmt"
    "io"
    "net"
    "os"
    "time"

    zmux "github.com/zmuxio/zmux-go"
)

func fatal(format string, args ...any) {
    fmt.Fprintf(os.Stdout, "ERR "+format+"\n", args...)
    os.Exit(1)
}

func main() {
    if len(os.Args) != 3 {
        fatal("usage: main <addr> <ready-file>")
    }
    listener, err := net.Listen("tcp", os.Args[1])
    if err != nil {
        fatal("listen: %v", err)
    }
    defer listener.Close()
    if err := os.WriteFile(os.Args[2], []byte(listener.Addr().String()), 0600); err != nil {
        fatal("ready file: %v", err)
    }

    raw, err := listener.Accept()
    if err != nil {
        fatal("accept: %v", err)
    }
    caps := zmux.CapabilityOpenMetadata | zmux.CapabilityPriorityUpdate | zmux.CapabilityPriorityHints | zmux.CapabilityStreamGroups
    session, err := zmux.Server(raw, &zmux.Config{
        Capabilities: caps,
        PrefacePadding: true,
        PrefacePaddingMinBytes: 16,
        PrefacePaddingMaxBytes: 16,
        PingPadding: true,
        PingPaddingMinBytes: 16,
        PingPaddingMaxBytes: 16,
    })
    if err != nil {
        fatal("server: %v", err)
    }
    defer session.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if session.LocalPreface().Settings.PingPaddingKey == 0 {
        fatal("local ping padding key was not advertised")
    }
    if session.PeerPreface().Settings.PingPaddingKey == 0 {
        fatal("peer ping padding key was not advertised")
    }
    if _, err := session.Ping(ctx, []byte("go-ping-rust-client")); err != nil {
        fatal("ping rust client: %v", err)
    }
    stream, err := session.AcceptStream(ctx)
    if err != nil {
        fatal("accept stream: %v", err)
    }
    if got := string(stream.OpenInfo()); got != "rust-open" {
        fatal("open info = %q", got)
    }
    meta := stream.Metadata()
    if meta.Priority != 7 || meta.Group == nil || *meta.Group != 9 {
        fatal("metadata = priority:%d group:%v", meta.Priority, meta.Group)
    }
    payload, err := io.ReadAll(stream)
    if err != nil {
        fatal("read stream: %v", err)
    }
    if got := string(payload); got != "rust->go" {
        fatal("payload = %q", got)
    }
    if _, err := stream.WriteFinal([]byte("go:"+string(payload))); err != nil {
        fatal("write final: %v", err)
    }
    _ = stream.Close()
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
}

fn go_client_main() -> &'static str {
    r#"package main

import (
    "context"
    "fmt"
    "io"
    "net"
    "os"
    "time"

    zmux "github.com/zmuxio/zmux-go"
)

func fatal(format string, args ...any) {
    fmt.Fprintf(os.Stdout, "ERR "+format+"\n", args...)
    os.Exit(1)
}

func main() {
    if len(os.Args) != 2 {
        fatal("usage: main <addr>")
    }
    raw, err := net.Dial("tcp", os.Args[1])
    if err != nil {
        fatal("dial: %v", err)
    }
    caps := zmux.CapabilityOpenMetadata | zmux.CapabilityPriorityUpdate | zmux.CapabilityPriorityHints | zmux.CapabilityStreamGroups
    session, err := zmux.Client(raw, &zmux.Config{
        Capabilities: caps,
        PrefacePadding: true,
        PrefacePaddingMinBytes: 16,
        PrefacePaddingMaxBytes: 16,
        PingPadding: true,
        PingPaddingMinBytes: 16,
        PingPaddingMaxBytes: 16,
    })
    if err != nil {
        fatal("client: %v", err)
    }
    defer session.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if session.LocalPreface().Settings.PingPaddingKey == 0 {
        fatal("local ping padding key was not advertised")
    }
    if session.PeerPreface().Settings.PingPaddingKey == 0 {
        fatal("peer ping padding key was not advertised")
    }
    if _, err := session.Ping(ctx, []byte("go-ping-rust-server")); err != nil {
        fatal("ping rust server: %v", err)
    }
    priority := uint64(7)
    group := uint64(9)
    stream, err := session.OpenStreamWithOptions(ctx, zmux.OpenOptions{
        InitialPriority: &priority,
        InitialGroup:    &group,
        OpenInfo:        []byte("go-open"),
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
}

#[test]
fn rust_client_talks_to_go_server_with_open_metadata() {
    let Some(go_root) = interop_go_root() else {
        return;
    };
    let _guard = go_interop_guard();
    let work = TempWorkDir::create("zmux-rust-go-server-interop").unwrap();
    write_go_helper(work.path(), &go_root, go_server_main()).unwrap();
    let exe = build_go_helper(work.path()).unwrap();
    let ready_file = work.path().join("ready.addr");
    let child = spawn_helper(
        &exe,
        &[
            "127.0.0.1:0",
            ready_file.to_str().expect("non-utf8 temp path"),
        ],
    )
    .unwrap();
    let address = wait_for_ready_addr(&ready_file).unwrap();

    let socket = connect_with_retry(&address).unwrap();
    let session = tcp_session_client(socket);
    assert_ne!(session.local_preface().settings.ping_padding_key, 0);
    assert_ne!(session.peer_preface().settings.ping_padding_key, 0);
    session
        .ping_timeout(b"rust-ping-go-server", Duration::from_secs(5))
        .unwrap();
    let stream = session
        .open_stream_with(
            OpenOptions::new()
                .priority(7)
                .group(9)
                .open_info(b"rust-open"),
        )
        .unwrap();
    stream.write_final(b"rust->go").unwrap();
    assert_eq!(read_all_stream(stream), b"go:rust->go");
    session.close().unwrap();
    assert!(session.wait_timeout(Duration::from_secs(5)).unwrap());

    assert_go_success(wait_for_child(child, process_timeout()).unwrap());
}

#[test]
fn go_client_talks_to_rust_server_with_open_metadata() {
    let Some(go_root) = interop_go_root() else {
        return;
    };
    let _guard = go_interop_guard();
    let work = TempWorkDir::create("zmux-go-rust-server-interop").unwrap();
    write_go_helper(work.path(), &go_root, go_client_main()).unwrap();
    let exe = build_go_helper(work.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server_thread = thread::spawn(move || {
        let socket = accept_with_timeout(listener, ACCEPT_TIMEOUT).unwrap();
        let session = tcp_session_server(socket);
        assert_ne!(session.local_preface().settings.ping_padding_key, 0);
        assert_ne!(session.peer_preface().settings.ping_padding_key, 0);
        session
            .ping_timeout(b"rust-ping-go-client", Duration::from_secs(5))
            .unwrap();
        let stream = session
            .accept_stream_timeout(Duration::from_secs(5))
            .unwrap();
        assert_eq!(stream.open_info(), b"go-open");
        let metadata = stream.metadata();
        assert_eq!(metadata.priority, Some(7));
        assert_eq!(metadata.group, Some(9));
        assert_eq!(read_all_stream(stream.clone()), b"go->rust");
        stream.write_final(b"rust:go->rust").unwrap();
        assert!(session.wait_timeout(Duration::from_secs(5)).unwrap());
    });

    let child = spawn_helper(&exe, &[&address]).unwrap();
    let output = wait_for_child(child, process_timeout()).unwrap();
    let server_result = server_thread.join();
    assert_go_success(output);
    server_result.unwrap();
}
