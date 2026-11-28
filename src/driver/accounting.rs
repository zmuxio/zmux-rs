use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use super::attachment::PipeOutcome;
use crate::proto::session::accounting::Ledger;
use crate::{PipeAccounting, PipeId, SessionId};

/// Completion ticket for the record accounting of an attachment.
///
/// This ticket can outlive its session. The async wait is cancellation-safe,
/// and the final value remains available for repeated waits.
#[derive(Clone)]
pub struct AccountingTicket {
    end: Arc<PipeOutcome>,
    ledger: Arc<Ledger>,
}

impl fmt::Debug for AccountingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountingTicket")
            .field("pipe", &self.end.id.get())
            .finish_non_exhaustive()
    }
}

impl AccountingTicket {
    pub(super) fn from_outcome(end: &Arc<PipeOutcome>) -> Option<Self> {
        Some(Self {
            ledger: end.accounting.get()?.clone(),
            end: end.clone(),
        })
    }

    /// Waits for the last I/O worker on a blocking driver.
    ///
    /// # Errors
    ///
    /// Returns a timeout or an error when called on a blocking driver's own thread.
    #[cfg(feature = "blocking")]
    pub fn wait_blocking(
        &self,
        timeout: Option<std::time::Duration>,
    ) -> Result<PipeAccounting, super::blocking::WaitError> {
        super::blocking::wait_for(timeout, self.wait())
    }

    /// Waits for the last I/O worker and returns the final totals.
    pub async fn wait(&self) -> PipeAccounting {
        self.end.released.wait().await;
        self.ledger.final_snapshot()
    }
}

type TicketMap = BTreeMap<(SessionId, PipeId), AccountingTicket>;

/// Collects final accounting tickets at attachment handoff, including bootstrap.
///
/// Register the collection with [`crate::Config::with_accounting_tickets`].
/// It retains unclaimed tickets until taken, drained, or dropped. Drain it
/// regularly when a session or listener can accept many attachments.
#[derive(Clone, Debug, Default)]
pub struct AccountingTickets(Arc<Mutex<TicketMap>>);

impl AccountingTickets {
    /// Takes a published ticket by its local session and attachment IDs.
    pub fn take(&self, session: SessionId, pipe: PipeId) -> Option<AccountingTicket> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(session, pipe))
    }

    /// Takes every published ticket, including those for retired attachments.
    pub fn drain(&self) -> Vec<(SessionId, PipeId, AccountingTicket)> {
        let tickets = std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner));
        tickets
            .into_iter()
            .map(|((session, pipe), ticket)| (session, pipe, ticket))
            .collect()
    }

    pub(crate) fn sink(&self) -> AccountingTicketSink {
        AccountingTicketSink(Arc::downgrade(&self.0))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AccountingTicketSink(Weak<Mutex<TicketMap>>);

impl AccountingTicketSink {
    pub(super) fn publish(&self, session: SessionId, pipe: PipeId, end: &Arc<PipeOutcome>) {
        if let Some(tickets) = self.0.upgrade()
            && let Some(ticket) = AccountingTicket::from_outcome(end)
        {
            tickets
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert((session, pipe), ticket);
        }
    }
}

#[cfg(all(feature = "test-hooks", feature = "tokio"))]
pub(crate) mod probe;
