//! What Establish needs of a carrier, so that one implementation runs on both drivers. On
//! the std driver a call simply blocks in its first poll.

use std::future::Future;
use std::io;
use std::time::Duration;

use zmux::proto::seal::{Framing, RecordMode};
use zmux::{AdmittedValue, CarrierKind};

use crate::establish::read_frame;
use crate::exporter_of;

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "reply timeout passed")
}

pub(crate) trait Carrier: Sized + Send {
    fn framing(&self) -> Framing;
    fn kind(&self) -> Option<CarrierKind>;
    /// The carrier's own write overhead.
    fn overhead(&self) -> u16;
    fn read(&mut self, into: &mut Vec<u8>) -> impl Future<Output = io::Result<usize>> + Send;
    fn write(&mut self, unit: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
    /// The Binding: `None` without the Bound contract or an exporter on a half.
    fn binding(&self) -> Option<Vec<u8>>;
    fn early_data_possible(&self) -> bool;
    /// What a wait of the handshake ends with: the carrier's shutdown on the std driver.
    type Wait: Send + Sync;
    fn wait(&self) -> Self::Wait;
    /// Waits as a shaper said.
    fn sleep(wait: &Self::Wait, d: Duration) -> impl Future<Output = ()> + Send;
    /// Reads one unit, failing with `TimedOut` once `limit` passes. The std driver's reads
    /// block, so there the carrier is shut down at the limit, which needs a closer; without
    /// one the read is not bounded.
    fn read_unit_within(
        &mut self,
        framing: Framing,
        buf: &mut Vec<u8>,
        limit: Duration,
    ) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
    /// The carrier of a finished handshake; `rest` is what was read beyond it.
    fn finish(self, rest: Vec<u8>, complete: zmux_seal_proto::Complete, mode: RecordMode) -> Self;
    fn admitted(self, value: AdmittedValue) -> Self;
    /// With the padding bytes the handshake added.
    fn padded(self, bytes: u64) -> Self;
    /// The carrier with what was read of it first.
    fn replay(self, read: Vec<u8>) -> Self;
}

impl Carrier for zmux::PipeIo {
    fn framing(&self) -> Framing {
        self.handshake_framing()
    }
    fn kind(&self) -> Option<CarrierKind> {
        self.carrier()
    }
    fn overhead(&self) -> u16 {
        self.write_overhead()
    }
    async fn read(&mut self, into: &mut Vec<u8>) -> io::Result<usize> {
        self.read_handshake(into).await
    }
    async fn write(&mut self, unit: &[u8]) -> io::Result<()> {
        self.write_handshake(unit).await
    }
    fn binding(&self) -> Option<Vec<u8>> {
        self.bound_exporter()
    }
    fn early_data_possible(&self) -> bool {
        zmux::PipeIo::early_data_possible(self)
    }
    type Wait = ();
    fn wait(&self) {}
    async fn sleep((): &(), d: Duration) {
        tokio::time::sleep(d).await;
    }
    async fn read_unit_within(
        &mut self,
        framing: Framing,
        buf: &mut Vec<u8>,
        limit: Duration,
    ) -> io::Result<Vec<u8>> {
        tokio::time::timeout(limit, read_frame(self, framing, buf))
            .await
            .unwrap_or_else(|_| Err(timed_out()))
    }
    fn finish(self, rest: Vec<u8>, complete: zmux_seal_proto::Complete, mode: RecordMode) -> Self {
        let keep = complete.exporter_only();
        let p = self.with_prefix(rest);
        let p = match complete.into_records() {
            Some((sealer, opener)) => p.seal_records(sealer, opener),
            None => p,
        };
        p.with_secure_first_pipe(mode)
            .with_handshake_exporter(exporter_of(keep))
    }
    fn admitted(self, value: AdmittedValue) -> Self {
        self.with_admitted(value)
    }
    fn padded(self, bytes: u64) -> Self {
        self.with_handshake_padding(bytes)
    }
    fn replay(self, read: Vec<u8>) -> Self {
        self.with_prefix(read)
    }
}

#[cfg(feature = "blocking")]
impl Carrier for zmux::blocking::PipeIo {
    fn framing(&self) -> Framing {
        self.handshake_framing()
    }
    fn kind(&self) -> Option<CarrierKind> {
        self.carrier()
    }
    fn overhead(&self) -> u16 {
        self.write_overhead()
    }
    async fn read(&mut self, into: &mut Vec<u8>) -> io::Result<usize> {
        self.read_handshake(into)
    }
    async fn write(&mut self, unit: &[u8]) -> io::Result<()> {
        self.write_handshake(unit)
    }
    fn binding(&self) -> Option<Vec<u8>> {
        self.bound_exporter()
    }
    fn early_data_possible(&self) -> bool {
        false
    }
    type Wait = zmux::blocking::HandshakeWait;
    fn wait(&self) -> Self::Wait {
        self.handshake_wait()
    }
    async fn sleep(wait: &Self::Wait, d: Duration) {
        wait.sleep(d);
    }
    async fn read_unit_within(
        &mut self,
        framing: Framing,
        buf: &mut Vec<u8>,
        limit: Duration,
    ) -> io::Result<Vec<u8>> {
        // Disarmed when dropped, at the end of this read.
        let watchdog = self.watchdog(limit);
        let r = read_frame(self, framing, buf).await;
        if watchdog.is_some_and(|w| w.fired()) {
            return Err(timed_out());
        }
        r
    }
    fn finish(self, rest: Vec<u8>, complete: zmux_seal_proto::Complete, mode: RecordMode) -> Self {
        let keep = complete.exporter_only();
        let p = self.with_prefix(rest);
        let p = match complete.into_records() {
            Some((sealer, opener)) => p.seal_records(sealer, opener),
            None => p,
        };
        p.with_secure_first_pipe(mode)
            .with_exporter(exporter_of(keep))
    }
    fn admitted(self, value: AdmittedValue) -> Self {
        self.with_admitted(value)
    }
    fn padded(self, bytes: u64) -> Self {
        self.with_handshake_padding(bytes)
    }
    fn replay(self, read: Vec<u8>) -> Self {
        self.with_prefix(read)
    }
}
