//! Host code in the driver: called with no zmux lock held, a panic in it means no plan or a
//! refusal, and the checks around a join's last message and a Bound Hello.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[cfg(unix)]
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};
#[cfg(unix)]
use zmux::blocking as b;
use zmux::proto::listener::{OnReject, RejectAction};
use zmux::proto::seal::RecordMode;
use zmux::proto::session::{AllowRecordMode, AuthorizeJoin, RecordPolicy};
use zmux::shaping::{HandshakeShaper, UnitPlan};
use zmux::{
    Config, HandleError, Listener, ListenerConfig, PAIRING_TOKEN_LEN, PipeAuth, PipeHint, PipeIo,
    PipeOptions, Session, VarInt,
};

fn config() -> Config {
    Config::multipath(PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end())
}

async fn sessions(c: Config, server: Config) -> (Session, Session, Listener) {
    let l = Listener::new(server, ListenerConfig::default()).expect("valid listener configuration");
    let (a, far) = duplex(1 << 16);
    let l2 = l.clone();
    tokio::spawn(async move {
        let _ = l2.handle_pipe(PipeIo::new(far), PipeHint::default()).await;
    });
    let s = Session::connect(PipeIo::new(a), c).await.unwrap();
    let srv = l.accept().await.unwrap();
    (s, srv, l)
}

fn timed<F: Future>(f: F) -> tokio::time::Timeout<F> {
    tokio::time::timeout(Duration::from_secs(20), f)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn record_policy_runs_without_the_session_lock() {
    timed(async {
        let holder: Arc<OnceLock<Session>> = Arc::default();
        let (tx, rx) = mpsc::channel();
        let (h, tx) = (holder.clone(), Mutex::new(tx));
        let mut c = config();
        c.record_policy = Some(RecordPolicy::new(move |_| {
            // Another thread asks the session something while the policy waits for it.
            let h = h.clone();
            let (done, finished) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = h.get().unwrap().stats();
                let _ = done.send(());
            });
            let free = finished.recv_timeout(Duration::from_secs(5)).is_ok();
            tx.lock().unwrap().send(free).unwrap();
            RecordMode::Sealed
        }));
        let (s, _srv, _l) = sessions(c, config()).await;
        holder.set(s.clone()).ok();
        let (x, _y) = duplex(1 << 16);
        let _ = s.begin_add_pipe(PipeIo::new(x), PipeOptions::default());
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap());
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_record_policy_leaves_sealed() {
    timed(async {
        let mut c = config();
        c.record_policy = Some(RecordPolicy::new(|_| panic!("the policy")));
        let (s, _srv, _l) = sessions(c, config()).await;
        let (x, _y) = duplex(1 << 16);
        s.begin_add_pipe(PipeIo::new(x), PipeOptions::default())
            .unwrap();
    })
    .await
    .unwrap();
}

/// Joins through the listener and returns what `handle_pipe` said.
async fn join_through(s: &Session, l: &Listener) -> Result<(), HandleError> {
    let (x, y) = duplex(1 << 16);
    let _pipe = s
        .begin_add_pipe(PipeIo::new(x), PipeOptions::default())
        .unwrap();
    l.handle_pipe(PipeIo::new(y), PipeHint::default())
        .await
        .map(|_| ())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panicking_join_policies_refuse() {
    timed(async {
        for allow in [true, false] {
            let mut server = config();
            if allow {
                server.allow_record_mode = Some(AllowRecordMode::new(|_, _, _| panic!("a")));
            } else {
                server.authorize_join = Some(AuthorizeJoin::new(|_| panic!("b")));
            }
            let (s, _srv, l) = sessions(config(), server).await;
            while !s.join_ready() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(join_through(&s, &l).await, Err(HandleError::Rejected));
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_reject_policy_closes() {
    timed(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let mut limits = ListenerConfig::default();
        limits.on_reject = Some(OnReject(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            panic!("the policy");
        })));
        let (s, _srv, l) = sessions_with(limits).await;
        // A Hello in Bound on a carrier with nothing to check it with.
        let (near, far) = duplex(1 << 16);
        let _pipe = s.begin_add_pipe(bound_carrier(near), bound()).unwrap();
        assert_eq!(
            l.handle_pipe(PipeIo::new(far), PipeHint::default()).await,
            Err(HandleError::Rejected)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[test]
fn a_panicking_reject_policy_closes_on_the_std_driver() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let mut limits = ListenerConfig::default();
    limits.on_reject = Some(OnReject(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        panic!("the policy");
    })));
    limits.handshake_timeout = Duration::from_secs(5);
    let l = b::Listener::new(config(), limits, None).expect("valid listener configuration");
    // An unknown Locator: whichever join of no session.
    let (x, y) = std::os::unix::net::UnixStream::pair().unwrap();
    let (x2, y2) = (x.try_clone().unwrap(), y.try_clone().unwrap());
    let t = std::thread::spawn(move || {
        use std::io::Write;
        let mut x = x;
        let _ = x.write_all(&stray_join_hello());
        x
    });
    let r = l.handle_pipe(b::PipeIo::from_halves(y, y2), b::PipeHint::default());
    assert_eq!(r, Err(HandleError::Rejected));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop((x2, t.join().unwrap()));
}

/// A Hello from a client of another listener: the session it names is not here.
#[cfg(unix)]
fn stray_join_hello() -> Vec<u8> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (s, _srv, _l) = sessions(config(), config()).await;
        while !s.join_ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let (x, mut y) = duplex(1 << 16);
        let _pipe = s
            .begin_add_pipe(PipeIo::new(x), PipeOptions::default())
            .unwrap();
        let mut hello = vec![0; 4096];
        let n = y.read(&mut hello).await.unwrap();
        hello.truncate(n);
        hello
    })
}

async fn sessions_with(limits: ListenerConfig) -> (Session, Session, Listener) {
    let l = Listener::new(config(), limits).expect("valid listener configuration");
    let (a, far) = duplex(1 << 16);
    let l2 = l.clone();
    tokio::spawn(async move {
        let _ = l2.handle_pipe(PipeIo::new(far), PipeHint::default()).await;
    });
    let s = Session::connect(PipeIo::new(a), config()).await.unwrap();
    let srv = l.accept().await.unwrap();
    while !s.join_ready() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    (s, srv, l)
}

fn bound() -> PipeOptions {
    PipeOptions::new().with_record_mode(RecordMode::Bound)
}

fn bound_carrier(io: DuplexStream) -> PipeIo {
    PipeIo::new(io)
        .with_carrier_secure()
        .with_exporter(|_, _, out| {
            out.fill(9);
            true
        })
}

/// A listener that takes Bound, rejecting with the reason it is told.
fn bound_listener() -> (ListenerConfig, Config, Arc<Mutex<Vec<String>>>) {
    let reasons: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = reasons.clone();
    let mut limits = ListenerConfig::default();
    limits.on_reject = Some(OnReject(Arc::new(move |i| {
        seen.lock().unwrap().push(i.reason.to_string());
        RejectAction::Close
    })));
    let mut server = config();
    server.allow_record_mode = Some(AllowRecordMode::new(|_, _, _| true));
    (limits, server, reasons)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bound_without_a_binding_is_auth() {
    timed(async {
        let (limits, server, reasons) = bound_listener();
        let l = Listener::new(server, limits).expect("valid listener configuration");
        let (a, far) = duplex(1 << 16);
        let l2 = l.clone();
        tokio::spawn(async move {
            let _ = l2.handle_pipe(PipeIo::new(far), PipeHint::default()).await;
        });
        let s = Session::connect(PipeIo::new(a), config()).await.unwrap();
        let _srv = l.accept().await.unwrap();
        while !s.join_ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // An exporter without the declaration, a declaration without an exporter, neither.
        let carriers: [fn(DuplexStream) -> PipeIo; 3] = [
            |y| {
                PipeIo::new(y).with_exporter(|_, _, out| {
                    out.fill(9);
                    true
                })
            },
            |y| PipeIo::new(y).with_carrier_secure(),
            PipeIo::new,
        ];
        for acceptor in carriers {
            let (x, y) = duplex(1 << 16);
            let _pipe = s.begin_add_pipe(bound_carrier(x), bound()).unwrap();
            let r = l.handle_pipe(acceptor(y), PipeHint::default()).await;
            assert_eq!(r, Err(HandleError::Rejected));
        }
        assert_eq!(*reasons.lock().unwrap(), vec!["auth"; 3]);
    })
    .await
    .unwrap();
}

/// The Hello in Bound reaches a split acceptor whose halves have the contract and an
/// exporter each: refused, once the pair is complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bound_on_a_split_acceptor_is_auth() {
    timed(async {
        let (limits, server, reasons) = bound_listener();
        let l = Listener::new(server, limits).expect("valid listener configuration");
        let (a, far) = duplex(1 << 16);
        let l2 = l.clone();
        tokio::spawn(async move {
            let _ = l2.handle_pipe(PipeIo::new(far), PipeHint::default()).await;
        });
        let s = Session::connect(PipeIo::new(a), config()).await.unwrap();
        let _srv = l.accept().await.unwrap();
        while !s.join_ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let (x, y) = duplex(1 << 16);
        let (y_read, y_write) = tokio::io::split(y);
        let _pipe = s.begin_add_pipe(bound_carrier(x), bound()).unwrap();
        let pair = || {
            let mut h = PipeHint::default();
            h.pair = Some(vec![5; PAIRING_TOKEN_LEN]);
            h
        };
        let export = |_: &str, _: &[u8], out: &mut [u8]| {
            out.fill(9);
            true
        };
        let up = PipeIo::reader(y_read)
            .with_carrier_secure()
            .with_exporter(export);
        let down = PipeIo::writer(y_write)
            .with_carrier_secure()
            .with_exporter(export);
        let (l2, p1) = (l.clone(), pair());
        let second = tokio::spawn(async move { l2.handle_pipe(down, p1).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // The downlink came first: its handler takes the pair.
        l.handle_pipe(up, pair()).await.unwrap();
        assert_eq!(second.await.unwrap(), Err(HandleError::Rejected));
        assert_eq!(*reasons.lock().unwrap(), vec!["auth"]);
    })
    .await
    .unwrap();
}

/// Closes the session while the join's last message is written; tells what happens to the
/// carrier after that.
#[derive(Default)]
struct Watched {
    /// Writes so far; the second is the confirmation.
    writes: AtomicUsize,
    reads_after_last: AtomicUsize,
    dropped: AtomicBool,
}

struct LastWrite {
    io: DuplexStream,
    session: Arc<OnceLock<Session>>,
    watched: Arc<Watched>,
}

impl Drop for LastWrite {
    fn drop(&mut self) {
        self.watched.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for LastWrite {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.watched.writes.load(Ordering::SeqCst) >= 2 {
            self.watched.reads_after_last.fetch_add(1, Ordering::SeqCst);
        }
        Pin::new(&mut self.io).poll_read(cx, out)
    }
}

impl AsyncWrite for LastWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.watched.writes.fetch_add(1, Ordering::SeqCst) == 1 {
            self.session
                .get()
                .unwrap()
                .abort(VarInt::from_u32(1), b"during the last message");
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// A session that ends while the last message of a join is written takes no pipe task: the
/// carrier is neither read again nor kept, with the session's handle still held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_finished_on_an_ended_session_starts_no_pipe_task() {
    timed(async {
        let (s, _srv, l) = sessions_with(ListenerConfig::default()).await;
        let holder: Arc<OnceLock<Session>> = Arc::default();
        holder.set(s.clone()).ok();
        let watched = Arc::new(Watched::default());
        let (near, far) = duplex(1 << 16);
        let carrier = LastWrite {
            io: near,
            session: holder,
            watched: watched.clone(),
        };
        let l2 = l.clone();
        tokio::spawn(async move {
            let _ = l2.handle_pipe(PipeIo::new(far), PipeHint::default()).await;
        });
        let (r, w) = tokio::io::split(carrier);
        let _pipe = s
            .begin_add_pipe(PipeIo::from_halves(r, w), PipeOptions::default())
            .unwrap();
        while !watched.dropped.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(watched.writes.load(Ordering::SeqCst), 2);
        assert_eq!(watched.reads_after_last.load(Ordering::SeqCst), 0);
    })
    .await
    .unwrap();
}

/// The same on the std driver: no thread of the pipe touches the carrier afterwards.
#[cfg(unix)]
#[test]
fn a_join_finished_on_an_ended_session_starts_no_pipe_thread() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[derive(Default)]
    struct Seen {
        writes: AtomicUsize,
        reads_after_last: AtomicUsize,
    }
    struct R(UnixStream, Arc<Seen>);
    impl Read for R {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.1.writes.load(Ordering::SeqCst) >= 2 {
                self.1.reads_after_last.fetch_add(1, Ordering::SeqCst);
            }
            self.0.read(out)
        }
    }
    struct W(UnixStream, Arc<Seen>, Arc<OnceLock<b::Session>>);
    impl Write for W {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.1.writes.fetch_add(1, Ordering::SeqCst) == 1 {
                self.2.get().unwrap().abort(VarInt::from_u32(1), b"last");
            }
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    let c = Arc::new(config());
    let l = b::Listener::new(c.clone(), ListenerConfig::default(), None)
        .expect("valid listener configuration");
    let (x, y) = UnixStream::pair().unwrap();
    let (l2, y2) = (l.clone(), y.try_clone().unwrap());
    std::thread::spawn(move || {
        l2.handle_pipe(b::PipeIo::from_halves(y, y2), b::PipeHint::default())
    });
    let x2 = x.try_clone().unwrap();
    let s = b::Session::connect(b::PipeIo::from_halves(x, x2), c).unwrap();
    let srv = l.accept(Some(Duration::from_secs(5))).unwrap();
    while !s.join_ready() {
        std::thread::sleep(Duration::from_millis(5));
    }
    let holder: Arc<OnceLock<b::Session>> = Arc::default();
    holder.set(s.clone()).ok();
    let (p, q) = UnixStream::pair().unwrap();
    let (l3, q2) = (l.clone(), q.try_clone().unwrap());
    std::thread::spawn(move || {
        l3.handle_pipe(b::PipeIo::from_halves(q, q2), b::PipeHint::default())
    });
    let seen = Arc::new(Seen::default());
    let ended = Arc::new(AtomicUsize::new(0));
    let e = ended.clone();
    let carrier = b::PipeIo::from_halves(
        R(p.try_clone().unwrap(), seen.clone()),
        W(p, seen.clone(), holder),
    )
    .with_closer(move |how| {
        if how == std::net::Shutdown::Both {
            e.fetch_add(1, Ordering::SeqCst);
        }
    });
    let _pipe = s.begin_add_pipe(carrier, PipeOptions::default()).unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while seen.writes.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(seen.writes.load(Ordering::SeqCst), 2);
    assert_eq!(seen.reads_after_last.load(Ordering::SeqCst), 0);
    // The carrier no thread took was ended all the same, as the session's
    // end ends every carrier.
    assert!(ended.load(Ordering::SeqCst) >= 1);
    drop(srv);
}

/// Two one-way carriers join as one on the std driver: traffic runs, both closers run with
/// the attachment, and a half without the contract gives the pair none.
#[cfg(unix)]
#[test]
fn paired_join_on_the_std_driver() {
    use std::os::unix::net::UnixStream;
    let c = Arc::new(config());
    let l = b::Listener::new(c.clone(), ListenerConfig::default(), None)
        .expect("valid listener configuration");
    let (x, y) = UnixStream::pair().unwrap();
    let (l2, y2) = (l.clone(), y.try_clone().unwrap());
    std::thread::spawn(move || {
        l2.handle_pipe(b::PipeIo::from_halves(y, y2), b::PipeHint::default())
    });
    let x2 = x.try_clone().unwrap();
    let s = b::Session::connect(b::PipeIo::from_halves(x, x2), c).unwrap();
    let srv = l.accept(Some(Duration::from_secs(5))).unwrap();
    while !s.join_ready() {
        std::thread::sleep(Duration::from_millis(5));
    }
    let (up_near, up_far) = UnixStream::pair().unwrap();
    let (down_far, down_near) = UnixStream::pair().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let closer = |n: Arc<AtomicUsize>| {
        move |_| {
            n.fetch_add(1, Ordering::SeqCst);
        }
    };
    let (a, d) = (up_near.try_clone().unwrap(), down_near.try_clone().unwrap());
    let up = b::PipeIo::writer(up_near)
        .with_closer(move |h| {
            let _ = a.shutdown(h);
        })
        .with_closer(closer(closed.clone()));
    let down = b::PipeIo::reader(down_near)
        .with_closer(move |h| {
            let _ = d.shutdown(h);
        })
        .with_closer(closer(closed.clone()));
    let pair = b::PipeIo::paired_join(up, down);
    let pipe = s.begin_add_pipe(pair, PipeOptions::default()).unwrap();
    let (l3, f2) = (l.clone(), up_far.try_clone().unwrap());
    let df = down_far.try_clone().unwrap();
    std::thread::spawn(move || {
        let _keep = f2;
        l3.handle_pipe(b::PipeIo::from_halves(up_far, df), b::PipeHint::default())
    });
    pipe.session()
        .set_wait_timeout(Some(Duration::from_secs(10)));
    pipe.joined().unwrap();
    let echo = std::thread::spawn(move || {
        let (mut send, mut recv) = srv.accept_bi().unwrap();
        let mut got = [0; 5];
        recv.read_exact(&mut got).unwrap();
        // To the FIN: a receiver dropped before it stops the sender, whose
        // finish can come after.
        assert_eq!(recv.read(&mut [0; 1]).unwrap(), None);
        send.write_all(&got).unwrap();
        send.finish().unwrap();
        srv
    });
    let (mut send, mut recv) = s.open_bi().unwrap();
    send.write_all(b"hello").unwrap();
    send.finish().unwrap();
    let mut got = [0; 5];
    recv.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"hello");
    let srv = echo.join().unwrap();
    s.close();
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while closed.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(closed.load(Ordering::SeqCst) >= 2);
    drop((srv, down_far));
    // A pair of which a half has no contract declares none.
    let mut with_mode = PipeOptions::new();
    with_mode = with_mode.with_record_mode(RecordMode::Bound);
    let (g, _h) = UnixStream::pair().unwrap();
    let (i, _j) = UnixStream::pair().unwrap();
    let up = b::PipeIo::writer(g)
        .with_carrier_secure()
        .with_exporter(|_, _, o| {
            o.fill(1);
            true
        });
    let pair = b::PipeIo::paired_join(up, b::PipeIo::reader(i));
    assert!(s.begin_add_pipe(pair, with_mode).is_err());
}

/// An accept error other than the listener's close leaves `serve` running.
#[cfg(unix)]
#[test]
fn serve_goes_on_after_an_accept_error() {
    use std::os::fd::OwnedFd;
    let l = b::Listener::new(config(), ListenerConfig::default(), None)
        .expect("valid listener configuration");
    // A socket that does not listen: every accept fails with an error of the socket.
    let real = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let conn = std::net::TcpStream::connect(real.local_addr().unwrap()).unwrap();
    let tcp = std::net::TcpListener::from(OwnedFd::from(conn));
    let l2 = l.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = l2.serve(&tcp);
        let _ = tx.send(r.is_ok());
    });
    assert!(rx.recv_timeout(Duration::from_millis(400)).is_err());
    l.close();
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
}

#[test]
fn hook_lengths_saturate() {
    let huge = UnitPlan::new(usize::MAX, usize::MAX - 1, usize::MAX);
    assert_eq!(huge.pad_for(10), isize::MAX as usize);
    let small = UnitPlan::new(10, 8, 1);
    assert_eq!(small.pad_for(3), 17);
    // Through a join: the message's room bounds it.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        timed(async {
            let mut c = config();
            c.handshake_shaper = Some(HandshakeShaper::new(|_| {
                Some(UnitPlan::new(usize::MAX, 0, usize::MAX))
            }));
            let (s, _srv, l) = sessions(c, config()).await;
            while !s.join_ready() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let (x, y) = duplex(1 << 18);
            let pipe = s
                .begin_add_pipe(PipeIo::new(x), PipeOptions::default())
                .unwrap();
            let l2 = l.clone();
            tokio::spawn(async move {
                let _ = l2.handle_pipe(PipeIo::new(y), PipeHint::default()).await;
            });
            pipe.joined().await.unwrap();
        })
        .await
        .unwrap();
    });
}

fn poll<F: Future>(f: Pin<&mut F>) -> bool {
    let mut cx = Context::from_waker(Waker::noop());
    f.poll(&mut cx).is_ready()
}

/// The first half of a split bootstrap goes (its handler cancelled) with the second in its
/// slot: the second half ends and the token starts a new pairing.
#[tokio::test(flavor = "current_thread")]
async fn a_dropped_first_half_releases_the_second_and_the_token() {
    let mut limits = ListenerConfig::default();
    limits.handshake_timeout = Duration::from_secs(30);
    let l = Listener::new(config(), limits).expect("valid listener configuration");
    let hint = || {
        let mut h = PipeHint::default();
        h.pair = Some(vec![7; PAIRING_TOKEN_LEN]);
        h
    };
    let (r1, _w1) = duplex(1024);
    let (_r2, w2) = duplex(1024);
    let mut first = Box::pin(l.handle_pipe(PipeIo::reader(r1), hint()));
    assert!(!poll(first.as_mut()));
    let mut second = Box::pin(l.handle_pipe(PipeIo::writer(w2), hint()));
    for _ in 0..5 {
        assert!(!poll(second.as_mut()));
    }
    drop(first);
    tokio::time::timeout(Duration::from_secs(3), second)
        .await
        .expect("the second half ends")
        .unwrap();
    // Waits as a first half: not refused for a pairing nobody is in.
    let (r3, _w3) = duplex(1024);
    let mut third = Box::pin(l.handle_pipe(PipeIo::reader(r3), hint()));
    assert!(!poll(third.as_mut()));
}

/// The same with no second half yet: nothing of the token stays.
#[tokio::test(flavor = "current_thread")]
async fn a_lone_first_half_dropped_frees_the_token() {
    let l =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let hint = || {
        let mut h = PipeHint::default();
        h.pair = Some(vec![8; PAIRING_TOKEN_LEN]);
        h
    };
    for _ in 0..2 {
        let (r, _w) = duplex(1024);
        let mut first = Box::pin(l.handle_pipe(PipeIo::reader(r), hint()));
        assert!(!poll(first.as_mut()));
    }
    // The other direction now is a first half again, no pair with what went away.
    let (_r, w) = duplex(1024);
    let mut down = Box::pin(l.handle_pipe(PipeIo::writer(w), hint()));
    assert!(!poll(down.as_mut()));
}

/// A session configuration function that fails or panics closes the carrier, rejected,
/// and says so in the listener's log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_session_config_is_logged() {
    for panics in [false, true] {
        let logged = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = logged.clone();
        let mut limits = ListenerConfig::default();
        limits.logger = Some(zmux::Logger::new(move |_, m| {
            sink.lock().unwrap().push(m.to_string());
        }));
        limits.session_config = Some(zmux::proto::listener::SessionConfigFn::new(move |_| {
            if panics {
                panic!("the chooser");
            }
            Err("no configuration".to_string())
        }));
        let l = Listener::new(config(), limits).expect("valid listener configuration");
        let (a, far) = duplex(1 << 16);
        let client = tokio::spawn(Session::connect(PipeIo::new(a), config()));
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            l.handle_pipe(PipeIo::new(far), PipeHint::default()),
        )
        .await
        .expect("handled");
        assert!(matches!(r, Err(HandleError::Rejected)), "{r:?}");
        let logged = logged.lock().unwrap().clone();
        let want = if panics {
            "panicked"
        } else {
            "failed: no configuration"
        };
        assert!(
            logged
                .iter()
                .any(|m| m.contains("session_config") && m.contains(want)),
            "{logged:?}"
        );
        client.abort();
    }
}
