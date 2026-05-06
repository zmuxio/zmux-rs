use std::env;
use std::fs;
use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zmux::{
    Config, Conn, OpenOptions, CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS,
};

const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const READY_TIMEOUT: Duration = Duration::from_secs(5);

fn process_timeout() -> Duration {
    env::var("ZMUX_INTEROP_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_PROCESS_TIMEOUT)
}

fn interop_java_root() -> Option<PathBuf> {
    if env::var("ZMUX_INTEROP").ok().as_deref() != Some("1") {
        eprintln!("skipping Java interop smoke: set ZMUX_INTEROP=1 to run");
        return None;
    }
    let root = match env::var("ZMUX_JAVA_ROOT") {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => {
            eprintln!(
                "skipping Java interop smoke: set ZMUX_JAVA_ROOT to the Java implementation root"
            );
            return None;
        }
    };
    if !root.is_dir() {
        eprintln!(
            "skipping Java interop smoke: Java implementation root not found: {}",
            root.display()
        );
        return None;
    }
    for tool in ["java", "javac", "mvn"] {
        if Command::new(tool)
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| !status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping Java interop smoke: {tool} executable not found");
            return None;
        }
    }
    root.canonicalize().ok()
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
    Conn::client_tcp_with_config(socket, interop_config()).unwrap()
}

fn tcp_session_server(socket: TcpStream) -> Conn {
    Conn::server_tcp_with_config(socket, interop_config()).unwrap()
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
        "could not allocate unique zmux Java interop temp directory",
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
        let _ = fs::remove_dir_all(&self.path);
    }
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
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ok(ProcessOutput {
        status,
        stdout: stdout
            .join()
            .map_err(|_| io::Error::other("stdout drain thread panicked"))??,
        stderr: stderr
            .join()
            .map_err(|_| io::Error::other("stderr drain thread panicked"))??,
        timed_out,
    })
}

fn assert_process_success(name: &str, output: ProcessOutput) {
    assert!(
        !output.timed_out && output.status.success(),
        "{name} failed with status {:?}, timed_out={}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        output.timed_out,
        output.stdout,
        output.stderr
    );
}

fn ensure_java_module_built(java_root: &Path) {
    let child = Command::new("mvn")
        .arg("-q")
        .arg("-pl")
        .arg("zmux")
        .arg("-am")
        .arg("-DskipTests")
        .arg("package")
        .current_dir(java_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert_process_success(
        "maven build",
        wait_for_child(ChildGuard { child: Some(child) }, process_timeout()).unwrap(),
    );
}

fn classpath(work: &Path, java_root: &Path) -> String {
    let sep = if cfg!(windows) { ";" } else { ":" };
    format!(
        "{}{sep}{}",
        work.display(),
        java_root
            .join("zmux")
            .join("target")
            .join("classes")
            .display()
    )
}

fn write_java_helper(work: &Path) -> io::Result<PathBuf> {
    let source = work.join("InteropHelper.java");
    fs::write(source, java_helper_source())?;
    Ok(work.to_path_buf())
}

fn build_java_helper(work: &Path, java_root: &Path) {
    let child = Command::new("javac")
        .arg("-cp")
        .arg(classpath(work, java_root))
        .arg("-d")
        .arg(work)
        .arg(work.join("InteropHelper.java"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert_process_success(
        "javac helper build",
        wait_for_child(ChildGuard { child: Some(child) }, process_timeout()).unwrap(),
    );
}

fn spawn_java_helper(work: &Path, java_root: &Path, args: &[&str]) -> io::Result<ChildGuard> {
    let child = Command::new("java")
        .arg("-cp")
        .arg(classpath(work, java_root))
        .arg("InteropHelper")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok(ChildGuard { child: Some(child) })
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
                "Java helper did not publish its ready address",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn connect_with_retry(address: &str) -> io::Result<TcpStream> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match TcpStream::connect(address) {
            Ok(socket) => return Ok(socket),
            Err(err) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
                if Instant::now() >= deadline {
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        }
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
                    "timed out waiting for Java client connection",
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

fn java_helper_source() -> &'static str {
    r#"import io.zmux.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;

public final class InteropHelper {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private static void fatal(String message) {
        System.out.println("ERR " + message);
        System.exit(1);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String string(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    private static ZmuxConfig config() {
        long caps = Protocol.CAPABILITY_OPEN_METADATA
                | Protocol.CAPABILITY_PRIORITY_UPDATE
                | Protocol.CAPABILITY_PRIORITY_HINTS
                | Protocol.CAPABILITY_STREAM_GROUPS;
        return ZmuxConfig.builder()
                .capabilities(caps)
                .prefacePadding(true)
                .prefacePaddingMinBytes(16)
                .prefacePaddingMaxBytes(16)
                .pingPadding(true)
                .pingPaddingMinBytes(16)
                .pingPaddingMaxBytes(16)
                .build();
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            fatal("missing mode");
        }
        if ("server".equals(args[0])) {
            runServer(args);
        } else if ("client".equals(args[0])) {
            runClient(args);
        } else {
            fatal("unknown mode " + args[0]);
        }
    }

    private static void runServer(String[] args) throws Exception {
        if (args.length != 2) {
            fatal("usage: server <ready-file>");
        }
        ServerSocket listener = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        Files.write(Paths.get(args[1]), bytes("127.0.0.1:" + listener.getLocalPort()));
        Socket raw = listener.accept();
        ZmuxNativeSession session = Zmux.server(raw, config());
        if (session.localPreface().settings().pingPaddingKey() == 0L
                || session.peerPreface().settings().pingPaddingKey() == 0L) {
            fatal("ping padding key missing");
        }
        session.ping(bytes("java-ping-rust-client"), TIMEOUT);
        ZmuxNativeStream stream = session.acceptStream(TIMEOUT);
        if (!"rust-open".equals(string(stream.openInfo()))) {
            fatal("open info = " + string(stream.openInfo()));
        }
        StreamMetadata metadata = stream.metadata();
        if (metadata.priority() != 7L || metadata.group() == null || metadata.group() != 9L) {
            fatal("metadata = " + metadata);
        }
        byte[] payload = stream.readAllBytes();
        if (!"rust->java".equals(string(payload))) {
            fatal("payload = " + string(payload));
        }
        stream.writeFinal(bytes("java:" + string(payload)));
        stream.close();
        session.close();
        session.awaitTerminationOrThrow(TIMEOUT);
        listener.close();
    }

    private static void runClient(String[] args) throws Exception {
        if (args.length != 2) {
            fatal("usage: client <addr>");
        }
        Socket raw = new Socket();
        String[] parts = args[1].split(":");
        raw.connect(new InetSocketAddress(parts[0], Integer.parseInt(parts[1])), 5000);
        ZmuxNativeSession session = Zmux.client(raw, config());
        if (session.localPreface().settings().pingPaddingKey() == 0L
                || session.peerPreface().settings().pingPaddingKey() == 0L) {
            fatal("ping padding key missing");
        }
        session.ping(bytes("java-ping-rust-server"), TIMEOUT);
        OpenOptions options = OpenOptions.builder()
                .priority(7)
                .group(9)
                .openInfo("java-open")
                .build();
        ZmuxNativeStream stream = session.openStream(options, TIMEOUT);
        stream.writeFinal(bytes("java->rust"));
        byte[] response = stream.readAllBytes();
        if (!"rust:java->rust".equals(string(response))) {
            fatal("response = " + string(response));
        }
        session.close();
        session.awaitTerminationOrThrow(TIMEOUT);
    }
}
"#
}

#[test]
fn rust_client_talks_to_java_server_with_open_metadata() {
    let Some(java_root) = interop_java_root() else {
        return;
    };
    ensure_java_module_built(&java_root);
    let work = TempWorkDir::create("zmux-rust-java-server-interop").unwrap();
    write_java_helper(work.path()).unwrap();
    build_java_helper(work.path(), &java_root);
    let ready_file = work.path().join("ready.addr");
    let child = spawn_java_helper(
        work.path(),
        &java_root,
        &["server", ready_file.to_str().expect("non-utf8 temp path")],
    )
    .unwrap();
    let address = wait_for_ready_addr(&ready_file).unwrap();

    let session = tcp_session_client(connect_with_retry(&address).unwrap());
    assert_ne!(session.local_preface().settings.ping_padding_key, 0);
    assert_ne!(session.peer_preface().settings.ping_padding_key, 0);
    session
        .ping_timeout(b"rust-ping-java-server", Duration::from_secs(5))
        .unwrap();
    let stream = session
        .open_stream_with(
            OpenOptions::new()
                .priority(7)
                .group(9)
                .with_open_info(b"rust-open"),
        )
        .unwrap();
    stream.write_final(b"rust->java").unwrap();
    assert_eq!(read_all_stream(stream), b"java:rust->java");
    session.close().unwrap();
    assert!(session.wait_timeout(Duration::from_secs(5)).unwrap());

    assert_process_success(
        "java helper",
        wait_for_child(child, process_timeout()).unwrap(),
    );
}

#[test]
fn java_client_talks_to_rust_server_with_open_metadata() {
    let Some(java_root) = interop_java_root() else {
        return;
    };
    ensure_java_module_built(&java_root);
    let work = TempWorkDir::create("zmux-java-rust-server-interop").unwrap();
    write_java_helper(work.path()).unwrap();
    build_java_helper(work.path(), &java_root);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server_thread = thread::spawn(move || {
        let session = tcp_session_server(accept_with_timeout(listener, ACCEPT_TIMEOUT).unwrap());
        assert_ne!(session.local_preface().settings.ping_padding_key, 0);
        assert_ne!(session.peer_preface().settings.ping_padding_key, 0);
        session
            .ping_timeout(b"rust-ping-java-client", Duration::from_secs(5))
            .unwrap();
        let stream = session
            .accept_stream_timeout(Duration::from_secs(5))
            .unwrap();
        assert_eq!(stream.open_info(), b"java-open");
        let metadata = stream.metadata();
        assert_eq!(metadata.priority, Some(7));
        assert_eq!(metadata.group, Some(9));
        assert_eq!(read_all_stream(stream.clone()), b"java->rust");
        stream.write_final(b"rust:java->rust").unwrap();
        assert!(session.wait_timeout(Duration::from_secs(5)).unwrap());
    });

    let child = spawn_java_helper(work.path(), &java_root, &["client", &address]).unwrap();
    let output = wait_for_child(child, process_timeout()).unwrap();
    let server_result = server_thread.join();
    assert_process_success("java helper", output);
    server_result.unwrap();
}
