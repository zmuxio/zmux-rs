//! TCP socket queries and options of the drivers' TCP carriers:
//!
//! - the carrier's minimum RTT with microsecond resolution, which feeds
//!   receive-window auto-tuning and the low-water mark: Linux `TCP_INFO`
//!   `tcpi_min_rtt` (never `tcpi_rtt`, which
//!   is smoothed and includes queueing), Windows `SIO_TCP_INFO` `MinRttUs`.
//!   Darwin reports only a smoothed RTT in milliseconds, which the spec
//!   forbids: none there, and the core measures the credit loop instead;
//! - the carrier's unsent bytes (Linux `tcpi_notsent_bytes`, from the same
//!   query), which the multipath write-stall rule uses (MULTIPATH.md
//!   Section 7.1);
//! - `TCP_NOTSENT_LOWAT` (Linux, Android, Apple platforms), set from the
//!   core's wanted value by a [`Probe`].
//!
//! This is the crate's only unsafe code: `getsockopt` into a buffer the
//! kernel may fill only up to the length passed, `setsockopt` of one
//! integer, and `WSAIoctl(SIO_TCP_INFO)` into a `TCP_INFO_v0`. The sans-IO
//! core stays free of unsafe code.
#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use crate::proto::session::{PipeId, SessionCore as Core};

/// What one query of a TCP socket reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TcpInfo {
    /// The kernel's minimum RTT, microsecond resolution.
    pub(crate) min_rtt: Option<Duration>,
    /// Bytes written to the socket and not yet sent.
    pub(crate) unsent: Option<u64>,
}

/// A duplicate of a TCP carrier's socket, kept open for queries and an
/// abort: one duplicate per carrier, shared by its clones.
#[derive(Debug, Clone)]
pub(crate) struct TcpSocket {
    socket: std::sync::Arc<std::net::TcpStream>,
}

impl TcpSocket {
    /// Duplicates the socket's descriptor (`None` when that fails).
    #[cfg(unix)]
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn new(socket: &impl std::os::fd::AsFd) -> Option<Self> {
        let fd = socket.as_fd().try_clone_to_owned().ok()?;
        Some(Self {
            socket: std::sync::Arc::new(fd.into()),
        })
    }

    /// Duplicates the socket handle (`None` when that fails).
    #[cfg(windows)]
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn new(socket: &impl std::os::windows::io::AsSocket) -> Option<Self> {
        let socket = socket.as_socket().try_clone_to_owned().ok()?;
        Some(Self {
            socket: std::sync::Arc::new(socket.into()),
        })
    }

    /// A socket shared with its carrier (no duplicate).
    #[cfg_attr(not(feature = "blocking"), allow(dead_code))]
    pub(crate) fn shared(socket: std::sync::Arc<std::net::TcpStream>) -> Self {
        Self { socket }
    }

    /// Shuts the socket down both ways: the carrier fails without the
    /// graceful end of a layer above it (no TLS close_notify), and a read
    /// or write blocked on it returns.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn shut_down(&self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }

    /// Queries the socket once (one system call where the platform reports
    /// anything).
    pub(crate) fn info(&self) -> TcpInfo {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            linux::info(self.socket.as_raw_fd())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            windows::info(self.socket.as_raw_socket())
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
        TcpInfo::default()
    }

    /// The socket's send buffer (`SO_SNDBUF`), where the low-water mark is
    /// supported.
    pub(crate) fn send_buffer(&self) -> Option<u64> {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        {
            use std::os::fd::AsRawFd;
            let mut buf = [0u8; 4];
            let len = getsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &mut buf,
            )?;
            field(&buf, len, 0).filter(|&v| v > 0).map(u64::from)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        None
    }

    /// Limits the unsent bytes the kernel queues for the socket: it is
    /// writable only below `bytes`. Whether it was set.
    pub(crate) fn set_notsent_lowat(&self, bytes: u64) -> bool {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        {
            use std::os::fd::AsRawFd;
            setsockopt(self.socket.as_raw_fd(), NOTSENT_LOWAT, bytes)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        {
            let _ = bytes;
            false
        }
    }
}

/// Cancels the I/O blocked on a socket in other threads (Windows: a
/// shutdown alone does not end a blocked `recv`).
#[cfg(windows)]
pub(crate) fn cancel_blocked(socket: &std::net::TcpStream) {
    use std::os::windows::io::AsRawSocket;
    windows::cancel_blocked(socket.as_raw_socket());
}

/// How often a [`Probe`] queries its socket and re-reads the core's wanted
/// low-water mark, at most.
pub(crate) const PROBE_INTERVAL: Duration = Duration::from_millis(20);

/// The periodic work on a TCP carrier, in three steps so that no system call
/// runs under the core lock: [`Probe::query`] reads the socket (no lock),
/// [`Probe::feed`] hands the result to the core and reads the low-water
/// mark it wants (under the lock), [`Probe::apply`] sets the socket option
/// (after the lock).
#[derive(Debug)]
pub(crate) struct Probe {
    socket: TcpSocket,
    /// When the next query is due.
    next: Instant,
    /// The low-water mark the socket has.
    lowat: u64,
    /// The socket's send buffer, read once: the low-water mark never
    /// exceeds it.
    send_buffer: Option<u64>,
    /// The last query, for [`Probe::feed`].
    info: Option<TcpInfo>,
    /// The core's wanted low-water mark, for [`Probe::apply`].
    want: Option<u64>,
}

impl Probe {
    /// A probe of a socket whose low-water mark is `lowat` now; the first
    /// query is due at once.
    pub(crate) fn new(socket: TcpSocket, lowat: u64, now: Instant) -> Self {
        let send_buffer = socket.send_buffer();
        Self {
            socket,
            next: now,
            lowat,
            send_buffer,
            info: None,
            want: None,
        }
    }

    /// When the next query is due.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn next_query(&self) -> Instant {
        self.next
    }

    /// Step 1, without any lock: queries the socket when due; whether it
    /// did.
    pub(crate) fn query(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now + PROBE_INTERVAL;
        self.info = Some(self.socket.info());
        true
    }

    /// Step 2, under the core lock: the carrier's minimum RTT and unsent
    /// bytes go to the core (per pipe in a multipath session), and the
    /// wanted low-water mark is read. Nothing when no query is pending.
    pub(crate) fn feed(&mut self, core: &mut Core, pipe: PipeId, now: Instant) {
        let Some(info) = self.info.take() else {
            return;
        };
        if core.is_multipath() {
            if let Some(rtt) = info.min_rtt {
                core.set_pipe_carrier_rtt(pipe, Some(rtt));
            }
            if let Some(unsent) = info.unsent {
                core.set_pipe_unsent(pipe, unsent, now);
            }
        } else if let Some(rtt) = info.min_rtt {
            core.set_carrier_rtt(Some(rtt));
        }
        self.want = Some(core.notsent_lowat(pipe));
    }

    /// Step 3, after the core lock: sets the low-water mark when the wanted
    /// value (capped by the send buffer) differs from the current one by more
    /// than 25 %.
    pub(crate) fn apply(&mut self) {
        let Some(want) = self.want.take() else {
            return;
        };
        let want = self.send_buffer.map_or(want, |b| want.min(b));
        if changed(self.lowat, want) && self.socket.set_notsent_lowat(want) {
            self.lowat = want;
        }
    }

    /// The low-water mark the socket has.
    #[cfg(test)]
    pub(crate) fn lowat(&self) -> u64 {
        self.lowat
    }
}

/// Whether `new` differs from `old` by more than 25 % of `old`.
fn changed(old: u64, new: u64) -> bool {
    u128::from(new.abs_diff(old)) * 4 > u128::from(old)
}

/// Reads a socket option into `buf`; the bytes the kernel wrote.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn getsockopt(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    buf: &mut [u8],
) -> Option<usize> {
    let mut len = libc::socklen_t::try_from(buf.len()).ok()?;
    // SAFETY: `buf` is valid for writes of `len` bytes, which bounds what
    // the kernel writes, and `len` is a valid socklen_t it updates to the
    // bytes written. `fd` is open (owned by the caller's `OwnedFd`).
    let r = unsafe { libc::getsockopt(fd, level, name, buf.as_mut_ptr().cast(), &raw mut len) };
    (r == 0).then_some(len as usize)
}

/// TCP_NOTSENT_LOWAT (`<netinet/tcp.h>`; 0x201 on Apple platforms).
#[cfg(any(target_os = "linux", target_os = "android"))]
const NOTSENT_LOWAT: libc::c_int = libc::TCP_NOTSENT_LOWAT;
#[cfg(target_vendor = "apple")]
const NOTSENT_LOWAT: libc::c_int = 0x201;

/// Sets an integer TCP socket option (saturated to `c_int`).
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn setsockopt(fd: std::os::fd::RawFd, name: libc::c_int, value: u64) -> bool {
    let value = libc::c_int::try_from(value).unwrap_or(libc::c_int::MAX);
    let Ok(len) = libc::socklen_t::try_from(size_of::<libc::c_int>()) else {
        return false;
    };
    // SAFETY: the option value is a valid c_int of `len` bytes that the
    // kernel only reads; `fd` is open (owned by the caller's `OwnedFd`).
    let r =
        unsafe { libc::setsockopt(fd, libc::IPPROTO_TCP, name, (&raw const value).cast(), len) };
    r == 0
}

/// A native-endian u32 at `off`, when the kernel wrote all of it.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn field(buf: &[u8], len: usize, off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4).filter(|_| len >= off + 4)?;
    Some(u32::from_ne_bytes(b.try_into().ok()?))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::time::Duration;

    use super::{TcpInfo, field, getsockopt};

    /// Offsets in `struct tcp_info` (stable kernel ABI, both since Linux
    /// 4.6): `tcpi_notsent_bytes` and `tcpi_min_rtt` (microseconds).
    pub(super) const NOTSENT_BYTES: usize = 144;
    pub(super) const MIN_RTT: usize = 148;

    pub(super) fn info(fd: std::os::fd::RawFd) -> TcpInfo {
        let mut buf = [0u8; MIN_RTT + 4];
        let Some(len) = getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, &mut buf) else {
            return TcpInfo::default();
        };
        // A kernel older than 4.6 writes less (a short read: no value).
        // Before its first sample the kernel reports ~0.
        let min_rtt = field(&buf, len, MIN_RTT)
            .filter(|&us| us > 0 && us != u32::MAX)
            .map(|us| Duration::from_micros(u64::from(us)));
        let unsent = field(&buf, len, NOTSENT_BYTES).map(u64::from);
        TcpInfo { min_rtt, unsent }
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::time::Duration;

    use super::TcpInfo;

    /// `SIO_TCP_INFO` = `_WSAIORW(IOC_VENDOR, 39)` (`<mstcpip.h>`).
    const SIO_TCP_INFO: u32 = 0xD800_0027;

    /// `TCP_INFO_v0` (`<mstcpip.h>`, Windows 10 1703 and later); version 0
    /// is requested, which every version since reports.
    #[repr(C)]
    #[derive(Default)]
    struct TcpInfoV0 {
        state: i32,
        mss: u32,
        connection_time_ms: u64,
        timestamps_enabled: u8,
        rtt_us: u32,
        min_rtt_us: u32,
        bytes_in_flight: u32,
        cwnd: u32,
        snd_wnd: u32,
        rcv_wnd: u32,
        rcv_buf: u32,
        bytes_out: u64,
        bytes_in: u64,
        bytes_reordered: u32,
        bytes_retrans: u32,
        fast_retrans: u32,
        dup_acks_in: u32,
        timeout_episodes: u32,
        syn_retrans: u8,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CancelIoEx(handle: *mut c_void, overlapped: *mut c_void) -> i32;
    }

    /// Cancels the I/O any thread has pending on `socket`, blocking calls
    /// included (their Winsock implementation waits for overlapped
    /// requests, which this cancels): they return with an error.
    pub(crate) fn cancel_blocked(socket: std::os::windows::io::RawSocket) {
        // SAFETY: `socket` is an open socket handle (the caller holds the
        // socket); a null OVERLAPPED cancels every request on the handle,
        // and the call touches no memory of ours.
        let _ = unsafe { CancelIoEx(socket as usize as *mut c_void, std::ptr::null_mut()) };
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(
            s: usize,
            code: u32,
            in_buf: *const c_void,
            in_len: u32,
            out_buf: *mut c_void,
            out_len: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
            completion: *mut c_void,
        ) -> i32;
    }

    pub(super) fn info(socket: std::os::windows::io::RawSocket) -> TcpInfo {
        let Ok(s) = usize::try_from(socket) else {
            return TcpInfo::default();
        };
        let version: u32 = 0;
        let mut out = TcpInfoV0::default();
        let mut returned: u32 = 0;
        let Ok(out_len) = u32::try_from(std::mem::size_of::<TcpInfoV0>()) else {
            return TcpInfo::default();
        };
        // SAFETY: the input is a valid u32 of 4 bytes that the call only
        // reads; the output is a valid, writable `TCP_INFO_v0` of `out_len`
        // bytes (every bit pattern is valid for its integer fields), which
        // bounds what the call writes; `returned` is a valid u32. No
        // overlapped I/O: both trailing pointers are null. `s` is an open
        // socket (owned by the caller's `OwnedSocket`).
        let r = unsafe {
            WSAIoctl(
                s,
                SIO_TCP_INFO,
                (&raw const version).cast(),
                4,
                (&raw mut out).cast(),
                out_len,
                &raw mut returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let min_rtt_end = std::mem::offset_of!(TcpInfoV0, min_rtt_us) + 4;
        if r != 0 || (returned as usize) < min_rtt_end {
            return TcpInfo::default();
        }
        let us = out.min_rtt_us;
        TcpInfo {
            min_rtt: (us > 0 && us != u32::MAX).then(|| Duration::from_micros(u64::from(us))),
            unsent: None,
        }
    }

    #[cfg(test)]
    #[test]
    fn layout_matches_the_sdk() {
        assert_eq!(std::mem::offset_of!(TcpInfoV0, rtt_us), 20);
        assert_eq!(std::mem::offset_of!(TcpInfoV0, min_rtt_us), 24);
        assert_eq!(std::mem::offset_of!(TcpInfoV0, bytes_out), 48);
        assert_eq!(std::mem::size_of::<TcpInfoV0>(), 88);
    }
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    /// A connected loopback pair that has exchanged some data, so that the
    /// kernel has an RTT sample.
    fn pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut a = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut b, _) = l.accept().unwrap();
        for _ in 0..8 {
            a.write_all(&[1; 1000]).unwrap();
            let mut buf = [0; 1000];
            b.read_exact(&mut buf).unwrap();
            b.write_all(&buf).unwrap();
            a.read_exact(&mut buf).unwrap();
        }
        (a, b)
    }

    #[test]
    fn queries_a_connected_socket() {
        let (a, _b) = pair();
        let s = TcpSocket::new(&a).expect("descriptor");
        let info = s.info();
        if cfg!(any(target_os = "linux", target_os = "android", windows)) {
            let rtt = info.min_rtt.expect("a minimum RTT after traffic");
            assert!(rtt < Duration::from_secs(1), "{rtt:?}");
        } else {
            // Darwin: only a smoothed millisecond RTT, which is not used.
            assert_eq!(info.min_rtt, None);
        }
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert_eq!(info.unsent, Some(0));
        } else {
            assert_eq!(info.unsent, None);
        }
    }

    #[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "musl")))]
    #[test]
    fn linux_offsets_match_libc() {
        assert_eq!(
            std::mem::offset_of!(libc::tcp_info, tcpi_min_rtt),
            linux::MIN_RTT
        );
        assert_eq!(
            std::mem::offset_of!(libc::tcp_info, tcpi_notsent_bytes),
            linux::NOTSENT_BYTES
        );
    }

    #[test]
    fn lowat_changes_only_beyond_a_quarter() {
        assert!(!changed(128 * 1024, 150 * 1024));
        assert!(changed(128 * 1024, 161 * 1024));
        assert!(changed(128 * 1024, 32 * 1024));
        assert!(!changed(32 * 1024, 40 * 1024));
        assert!(changed(0, 1));
    }

    #[test]
    fn probe_applies_capped_by_the_send_buffer() {
        let (a, _b) = pair();
        let s = TcpSocket::new(&a).expect("descriptor");
        let supported = s.set_notsent_lowat(128 * 1024);
        let now = Instant::now();
        let mut p = Probe::new(s, 128 * 1024, now);
        assert!(p.query(now));
        assert!(
            !p.query(now + Duration::from_millis(1)),
            "at most every 20 ms"
        );
        assert!(p.query(now + PROBE_INTERVAL));
        // A wanted value far above the send buffer is capped by it.
        p.want = Some(u64::MAX / 2);
        p.apply();
        if supported {
            let cap = p.send_buffer.expect("SO_SNDBUF");
            let want = if changed(128 * 1024, cap) {
                cap
            } else {
                128 * 1024
            };
            assert_eq!(p.lowat(), want);
        } else {
            assert_eq!(p.lowat(), 128 * 1024);
        }
    }
}
