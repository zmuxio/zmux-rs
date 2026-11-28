//! A pinned, per-thread `PERF_COUNT_HW_INSTRUCTIONS` event (`instructions:u`).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[repr(C)]
struct PerfEventAttrV0 {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

pub(super) struct Instructions(OwnedFd);

impl Instructions {
    pub(super) fn open() -> io::Result<Self> {
        const PERF_TYPE_HARDWARE: u32 = 0;
        const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
        const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1;
        const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 2;
        const DISABLED: u64 = 1;
        const PINNED: u64 = 1 << 2;
        const EXCLUDE_KERNEL: u64 = 1 << 5;
        const EXCLUDE_HV: u64 = 1 << 6;
        const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;
        let attr = PerfEventAttrV0 {
            kind: PERF_TYPE_HARDWARE,
            size: 64,
            config: PERF_COUNT_HW_INSTRUCTIONS,
            sample_period: 0,
            sample_type: 0,
            read_format: PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
            flags: DISABLED | PINNED | EXCLUDE_KERNEL | EXCLUDE_HV,
            wakeup_events: 0,
            bp_type: 0,
            config1: 0,
        };
        // SAFETY: the initialized version-0 perf_event_attr is valid for the
        // syscall. With pid=0 and cpu=-1 the event follows this thread.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &raw const attr,
                0,
                -1,
                -1,
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful perf_event_open gives this caller one new descriptor.
        Ok(Self(unsafe {
            OwnedFd::from_raw_fd(libc::c_int::try_from(fd).unwrap())
        }))
    }

    pub(super) fn start(&self) -> io::Result<()> {
        const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
        self.enable_or_disable(PERF_EVENT_IOC_ENABLE)
    }

    fn enable_or_disable(&self, request: libc::c_ulong) -> io::Result<()> {
        // SAFETY: both perf requests take no pointer, and the descriptor is live.
        (unsafe { libc::ioctl(self.0.as_raw_fd(), request, 0) } == 0)
            .then_some(())
            .ok_or_else(io::Error::last_os_error)
    }

    pub(super) fn stop(&self) -> io::Result<u64> {
        const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
        self.enable_or_disable(PERF_EVENT_IOC_DISABLE)?;
        let mut values = [0_u64; 3];
        // SAFETY: read may initialize the three u64s but may not exceed the buffer.
        let n = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                values.as_mut_ptr().cast(),
                size_of_val(&values),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let [count, enabled, running] = values;
        if n.unsigned_abs() != size_of_val(&values) || enabled == 0 || running != enabled {
            return Err(io::Error::other(
                "user instruction counter was not scheduled continuously",
            ));
        }
        Ok(count)
    }
}
