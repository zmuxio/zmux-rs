//! Observe record accounting and attachment lifetime under injected I/O.

use std::sync::Arc;

use super::super::attachment::Attachment;
use super::{AccountingTicket, Ledger, PipeAccounting, PipeId};
use crate::proto::record::{Framing, RecordReader};
use crate::{AccountingPolicy, CarrierHalfSource, CarrierHalfSources, CarrierKind, PipeHalf};

/// Test-only access to an attachment's production record ledger and ticket.
pub struct AccountingProbe {
    ledger: Arc<Ledger>,
    owner: Option<Arc<Attachment>>,
    worker: Option<Box<dyn Send + Sync>>,
    ticket: AccountingTicket,
}

impl std::fmt::Debug for AccountingProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountingProbe")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

impl AccountingProbe {
    /// Starts a probe with the supplied record-accounting sources.
    ///
    /// # Panics
    /// Panics if a new attachment already owns an accounting ledger.
    #[must_use]
    pub fn new(id: PipeId, send: Option<&str>, receive: Option<&str>, held: bool) -> Self {
        let source = |name: Option<&str>| {
            let mut source = CarrierHalfSource::new(CarrierKind::Streaming, None);
            source.route = name.map(Arc::from);
            source
        };
        let ledger = Arc::new(Ledger::new(
            id,
            CarrierHalfSources {
                send: source(send),
                receive: source(receive),
            },
            send.is_some(),
            receive.is_some(),
            AccountingPolicy {
                enabled: true,
                ..AccountingPolicy::default()
            },
        ));
        let owner = Arc::new(Attachment::default());
        let worker = held.then(|| Box::new(owner.worker()) as Box<dyn Send + Sync>);
        let outcome = owner.outcome();
        outcome.accounting.set(ledger.clone()).unwrap();
        Self {
            ledger,
            ticket: AccountingTicket::from_outcome(outcome).unwrap(),
            owner: Some(owner),
            worker,
        }
    }

    /// Reports a complete encoded record at the provider boundary.
    pub fn record(&self, half: PipeHalf, lane: u64, bytes: u64) {
        match half {
            PipeHalf::Outbound => self.ledger.write_progress(lane, bytes, 1, 0),
            PipeHalf::Inbound => self
                .ledger
                .receive_complete(lane, bytes, Framing::ByteStream),
        }
    }

    /// Reports a partial write before its lane is settled.
    pub fn partial_write(&self, lane: u64, partial: u64) {
        self.ledger.write_progress(lane, 0, 0, partial);
    }

    /// Settles written records when the carrier releases its writer.
    pub fn finish_write(&self, lane: u64) {
        self.ledger.finish_write(lane);
    }

    /// Reports incomplete framing when the reader ends.
    pub fn finish_read(&self, lane: u64, reader: &RecordReader) {
        self.ledger
            .pending_read(lane, reader.pending_record_bytes());
        self.ledger.finish_read(lane);
    }

    /// Drops the protocol's attachment owner.
    pub fn retire(&mut self) {
        self.owner.take();
    }

    /// Drops the last held I/O worker.
    pub fn release_io(&mut self) {
        self.worker.take();
    }

    /// Returns the current live record totals.
    #[must_use]
    pub fn snapshot(&self) -> PipeAccounting {
        self.ledger.snapshot()
    }

    /// Checks whether the attachment and its workers have released the ticket.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.ticket.end.released.is_done()
    }

    /// Returns the real completion ticket.
    #[must_use]
    pub fn ticket(&self) -> &AccountingTicket {
        &self.ticket
    }
}
