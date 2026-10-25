//! Lanes in the tokio driver (MULTIPATH.md Sections 2.5 and 5.8): the identity
//! of a carrier's connection, the opener of new
//! streams on it, and the routing of the streams the peer opens there to
//! the session and pipe they are lanes of.
//!
//! The routing table holds every session of the process that accepts
//! lanes, by its Lane Key; a stream is looked up by the key its PIPE_LANE
//! carries, compared in constant time, and then must be on the connection
//! of its pipe's lane 0. The table is a leaf lock, taken when a session
//! starts or ends and when a lane arrives, never on the I/O paths.

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use ::tokio::io::{AsyncReadExt, AsyncWrite};

use super::handle::Shared;
use super::listen::HandleError;
use super::stream_pipe::{StreamReader, StreamWriter};
use super::tokio::{PipeIo, Tokio, Writer};
use crate::proto::keys::lane_key_eq;
use crate::proto::listener::{Classified, LaneProbe};
use crate::proto::record::ZMUX_MAX_RECORD_SIZE;
use crate::proto::session::{LaneAccept, LaneId, PipeId};

/// The identity of a multi-stream carrier connection:
/// equal for two carriers exactly when they are streams of the same
/// connection. It is the stack's connection object, compared by identity,
/// never its addresses.
#[derive(Clone)]
pub struct CarrierConnId {
    ptr: usize,
    /// Keeps the object's allocation, so that no other connection takes
    /// its address while the identity is held.
    _keep: Weak<dyn Any + Send + Sync>,
}

impl CarrierConnId {
    /// The identity of the connection `conn` (the QUIC connection, the
    /// HTTP/2 connection, the session whose streams carry pipes).
    pub fn new<T: Any + Send + Sync>(conn: &Arc<T>) -> Self {
        let weak: Weak<dyn Any + Send + Sync> = Arc::downgrade(conn) as _;
        Self {
            ptr: Arc::as_ptr(conn).cast::<()>() as usize,
            _keep: weak,
        }
    }
}

impl PartialEq for CarrierConnId {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl Eq for CarrierConnId {}

impl Hash for CarrierConnId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ptr.hash(state);
    }
}

impl fmt::Debug for CarrierConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CarrierConnId({:#x})", self.ptr)
    }
}

/// What a connection carries for this process's sessions: the pipes with
/// their lane 0 on it, and the new streams on it that wait for their first
/// record outside the listener's limits (MULTIPATH.md Section 5.5, at most
/// one per pipe).
#[derive(Debug, Default)]
struct Carried {
    pipes: usize,
    waiting: usize,
    /// The lanes the nested pipes of this process opened as streams of
    /// the connection, an outer session (MULTIPATH.md Section 5.8).
    lanes: usize,
}

/// The connections that carry pipes of this process's sessions: a leaf
/// lock, taken when a pipe with a connection starts or ends and when a
/// listener meets a new stream or classifies it.
static CARRYING: std::sync::LazyLock<Mutex<std::collections::HashMap<CarrierConnId, Carried>>> =
    std::sync::LazyLock::new(Mutex::default);

fn carrying() -> std::sync::MutexGuard<'static, std::collections::HashMap<CarrierConnId, Carried>> {
    CARRYING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Leaves the table entry of `conn` once nothing is carried on it.
fn prune(t: &mut std::collections::HashMap<CarrierConnId, Carried>, conn: &CarrierConnId) {
    if t.get(conn)
        .is_some_and(|c| c.pipes == 0 && c.waiting == 0 && c.lanes == 0)
    {
        t.remove(conn);
    }
}

/// A pipe's claim that its connection carries lane 0 of an OPEN inbound
/// pipe of the endpoint (MULTIPATH.md Section 5.5): counted while the
/// session task finds the pipe open ([`ConnClaim::set_open`]) and the
/// claim lives.
pub(crate) struct ConnClaim {
    conn: CarrierConnId,
    open: bool,
}

impl ConnClaim {
    pub(crate) fn new(conn: CarrierConnId) -> Self {
        Self { conn, open: false }
    }

    pub(crate) fn conn(&self) -> &CarrierConnId {
        &self.conn
    }

    /// The pipe is OPEN, or no longer: counted, or no longer.
    pub(crate) fn set_open(&mut self, open: bool) {
        if open == self.open {
            return;
        }
        self.open = open;
        let mut t = carrying();
        let c = t.entry(self.conn.clone()).or_default();
        if open {
            c.pipes += 1;
        } else {
            c.pipes = c.pipes.saturating_sub(1);
            prune(&mut t, &self.conn);
        }
    }
}

impl Drop for ConnClaim {
    fn drop(&mut self) {
        self.set_open(false);
    }
}

/// A new stream on a connection that carries pipes of this process's
/// sessions, waiting for its first record outside the listener's limits
/// (MULTIPATH.md Section 5.5) until the ticket is dropped.
pub(crate) struct Exempt(CarrierConnId);

impl Exempt {
    /// A ticket for a new stream on `conn`, when it carries lane 0 of a
    /// pipe of ours and fewer of its new streams than such pipes wait for
    /// their first record: the lane the peer's writer may open per pipe
    /// (MULTIPATH.md Section 5.8). Otherwise the stream is a carrier like
    /// any other.
    pub(crate) fn new(conn: &CarrierConnId) -> Option<Self> {
        let mut t = carrying();
        let c = t.get_mut(conn)?;
        if c.waiting >= c.pipes {
            return None;
        }
        c.waiting += 1;
        Some(Self(conn.clone()))
    }
}

impl Drop for Exempt {
    fn drop(&mut self) {
        let mut t = carrying();
        if let Some(c) = t.get_mut(&self.0) {
            c.waiting = c.waiting.saturating_sub(1);
        }
        prune(&mut t, &self.0);
    }
}

/// The sending half of a lane, with what it keeps open alongside: the
/// unused receiving half of a bidirectional stream, which the peer ends at
/// once and which is no event of the pipe (MULTIPATH.md Section 2.5), and
/// for a lane that is a stream of an outer session, its count there.
pub(crate) struct LaneWriter {
    pub(crate) writer: Writer,
    pub(crate) keep: Option<StreamReader>,
    pub(crate) outer: Option<OuterLane>,
}

/// A lane that is a stream of an outer session, counted there while it
/// lives: the nested pipes of the process hold at most half of the outer
/// peer's initial_max_streams_bidi as lanes (MULTIPATH.md Section 5.8).
pub(crate) struct OuterLane(CarrierConnId);

impl OuterLane {
    /// A count on `conn` when fewer than `limit` lanes hold one.
    fn new(conn: &CarrierConnId, limit: u64) -> Option<Self> {
        let mut t = carrying();
        let c = t.entry(conn.clone()).or_default();
        if c.lanes as u64 >= limit {
            prune(&mut t, conn);
            return None;
        }
        c.lanes += 1;
        Some(Self(conn.clone()))
    }
}

impl Drop for OuterLane {
    fn drop(&mut self) {
        let mut t = carrying();
        if let Some(c) = t.get_mut(&self.0) {
            c.lanes = c.lanes.saturating_sub(1);
        }
        prune(&mut t, &self.0);
    }
}

/// A future that opens a lane's stream.
pub(crate) type OpenFuture = Pin<Box<dyn Future<Output = io::Result<LaneWriter>> + Send>>;

/// Opens new streams on a carrier's connection.
pub(crate) type LaneOpener = Arc<dyn Fn() -> OpenFuture + Send + Sync>;

/// An opener from an application's function returning a writer.
pub(crate) fn opener<F, Fut, W>(f: F) -> LaneOpener
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<W>> + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    Arc::new(move || {
        let fut = f();
        Box::pin(async move {
            let w = fut.await?;
            Ok(LaneWriter {
                writer: Writer::Io(Box::pin(w)),
                keep: None,
                outer: None,
            })
        })
    })
}

/// The opener of a stream carrier: a further stream of the outer session,
/// with PIPE_CARRIER and the application TLVs of the pipe's own stream
/// (which a relay routes it by), whose sending part carries the lane
/// (EXTENSIONS.md Section 10.2).
pub(crate) fn stream_opener(outer: Weak<Shared<Tokio>>, preamble: crate::Preamble) -> LaneOpener {
    Arc::new(move || {
        let (outer, preamble) = (outer.clone(), preamble.clone());
        Box::pin(async move {
            // Only while the application holds the outer session.
            let session = super::handle::WeakSession::from_weak(outer)
                .upgrade()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
            // The outer session's stream credit is the application's too:
            // a lane never waits for it, never overtakes an application's
            // open, and holds at most half the peer's initial bidirectional
            // streams with the other lanes on it; otherwise none is opened
            // this time (`WouldBlock`, no refusal).
            let not_now = || io::Error::from(io::ErrorKind::WouldBlock);
            let shared = session.shared();
            let limit = shared.lock().core.peer_initial_streams_bidi().unwrap_or(0) / 2;
            let claim = OuterLane::new(&CarrierConnId::new(shared), limit).ok_or_else(not_now)?;
            let (send, recv) = match session.try_open_bi_with(&session.carrier_preamble(&preamble))
            {
                Ok(s) => s,
                Err(crate::OpenError::Blocked) => return Err(not_now()),
                Err(_) => return Err(io::Error::from(io::ErrorKind::NotConnected)),
            };
            let io = super::tokio::pipe_stream(send, recv, &preamble);
            let mut w = io
                .into_lane_writer()
                .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
            w.outer = Some(claim);
            Ok(w)
        })
    })
}

/// A session of the routing table.
struct Entry {
    key: [u8; 16],
    session: Weak<Shared<Tokio>>,
}

static TABLE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

fn table() -> std::sync::MutexGuard<'static, Vec<Entry>> {
    TABLE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Adds a session that accepts lanes (its own Max Lanes above 1) under its
/// Lane Key; ended sessions leave the table here too.
pub(crate) fn register(session: &Arc<Shared<Tokio>>, key: [u8; 16]) {
    let mut t = table();
    t.retain(|e| e.session.strong_count() > 0);
    t.push(Entry {
        key,
        session: Arc::downgrade(session),
    });
}

/// The session with Lane Key `key` left: its entry goes (with those of
/// sessions that are gone).
pub(crate) fn unregister(key: &[u8; 16]) {
    table().retain(|e| e.key != *key && e.session.strong_count() > 0);
}

/// The Lane Keys in the routing table, for leak tests.
#[cfg(feature = "test-hooks")]
pub(crate) fn registered() -> Vec<[u8; 16]> {
    table().iter().map(|e| e.key).collect()
}

/// The session whose Lane Key is `key`, compared in constant time with
/// every entry (MULTIPATH.md Section 5.8).
fn lookup(key: &[u8; 16]) -> Option<Arc<Shared<Tokio>>> {
    let t = table();
    let mut found = None;
    for e in t.iter() {
        if lane_key_eq(&e.key, key) && found.is_none() {
            found = Some(e.session.clone());
        }
    }
    found?.upgrade()
}

/// How long a stream may take to bring its first record (MULTIPATH.md
/// Section 5.6, the first-record timeout).
const FIRST_RECORD: Duration = Duration::from_secs(2);

/// Hands a stream the peer opened on a lane-capable connection to the
/// session and pipe it is a lane of: by the Lane Key
/// its first record's PIPE_LANE carries, among the sessions of the
/// process, on an endpoint without a [`crate::Listener`] (whose
/// [`crate::Listener::handle_pipe`] routes such streams the same way). The
/// carrier must report its connection ([`PipeIo::with_carrier_conn`]; a
/// stream carrier does). A stream that names no pipe of a session with
/// its lane 0 on the same connection is aborted, and nothing else happens
/// (MULTIPATH.md Section 5.8).
pub async fn handle_lane(mut io: PipeIo) -> Result<(), HandleError> {
    let framing = io.framing;
    let mut probe = LaneProbe::new(ZMUX_MAX_RECORD_SIZE, framing);
    let first = async {
        let Some(reader) = io.reader.as_mut() else {
            return Classified::Reject;
        };
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => return Classified::Reject,
                Ok(n) => n,
            };
            let c = probe.data(&buf[..n]);
            if c != Classified::NeedMore {
                return c;
            }
        }
    };
    match ::tokio::time::timeout(FIRST_RECORD, first).await {
        Ok(Classified::Lane {
            lane_key,
            pipe,
            lane,
            bytes,
        }) => route(io, &lane_key, PipeId(pipe).lane(lane), bytes),
        Ok(_) => Err(HandleError::Rejected),
        Err(_) => Err(HandleError::TimedOut),
    }
}

/// Offers the stream `io`, whose first bytes `prefix` begin with a
/// PIPE_LANE carrying `key` for lane `at`, to the session with that key.
pub(crate) fn route(
    mut io: PipeIo,
    key: &[u8; 16],
    at: LaneId,
    prefix: Vec<u8>,
) -> Result<(), HandleError> {
    let (Some(conn), Some(session)) = (io.conn().cloned(), lookup(key)) else {
        // Dropping the stream aborts it.
        return Err(HandleError::Rejected);
    };
    io.prefix = prefix;
    match session.accept_lane(at, &conn, io) {
        LaneAccept::Accepted => Ok(()),
        _ => Err(HandleError::Rejected),
    }
}

impl PipeIo {
    /// The sending half of an opened lane stream: the carrier's writer,
    /// keeping a stream carrier's receiving part.
    pub(crate) fn into_lane_writer(mut self) -> Option<LaneWriter> {
        let writer = self.writer.take()?;
        let keep = match self.reader.take() {
            Some(super::tokio::Reader::Stream(r)) => Some(r),
            _ => None,
        };
        Some(LaneWriter {
            writer,
            keep,
            outer: None,
        })
    }
}

/// Ends the unused sending half of an accepted lane at once and
/// gracefully (MULTIPATH.md Section 2.5).
pub(crate) fn finish_reverse(writer: Option<Writer>) {
    match writer {
        Some(Writer::Stream(w)) => finish_stream(w),
        Some(mut w) => {
            if let Ok(rt) = ::tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = ::tokio::io::AsyncWriteExt::shutdown(&mut w).await;
                });
            }
        }
        None => {}
    }
}

fn finish_stream(mut w: StreamWriter) {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let _ = AsyncWrite::poll_shutdown(Pin::new(&mut w), &mut cx);
}
