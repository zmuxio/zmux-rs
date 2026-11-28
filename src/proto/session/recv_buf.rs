//! Backing identity and external read leases.

use bytes::Bytes;

/// A read buffer of the driver that received data may reference: an
/// identifier that grows with every new buffer of the session, and the
/// bytes the buffer holds alive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Backing {
    /// Grows with every buffer the driver reads into.
    pub(crate) id: u64,
    /// The size of the buffer's allocation.
    pub(crate) size: usize,
}

impl Backing {
    pub(crate) fn new(size: usize) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            size,
        }
    }
}

/// An immutable range together with the allocation that holds it.
#[derive(Debug, Default)]
pub(crate) struct Segment {
    pub(crate) bytes: Bytes,
    pub(crate) backing: Backing,
}

#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub(super) use loans::ReadLoans;

#[cfg(any(test, all(any(feature = "tokio", feature = "blocking"), not(loom))))]
mod loans {
    use super::{Backing, Bytes};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, PoisonError};

    const LOAN_BYTES: usize = 8 * 1024 * 1024;
    const LOAN_SLOTS: usize = 32_768;

    #[derive(Debug, Default)]
    struct LoanState {
        bytes: usize,
        slots: usize,
        roots: HashMap<u64, usize>,
    }

    #[derive(Debug)]
    pub(in crate::proto::session) struct ReadLoans {
        state: Mutex<LoanState>,
        slots: usize,
    }

    impl Default for ReadLoans {
        fn default() -> Self {
            Self::with_slots(LOAN_SLOTS)
        }
    }

    impl ReadLoans {
        pub(crate) fn with_slots(slots: usize) -> Self {
            Self {
                state: Mutex::default(),
                slots,
            }
        }

        pub(in crate::proto::session) fn lend(
            self: &Arc<Self>,
            backing: Backing,
            bytes: impl FnOnce() -> Bytes,
        ) -> Option<Bytes> {
            let loan = self.acquire(backing)?;
            Some(loan.attach(bytes()))
        }

        pub(in crate::proto::session) fn acquire(
            self: &Arc<Self>,
            backing: Backing,
        ) -> Option<ReadLoan> {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.slots == self.slots {
                return None;
            }
            if let Some(count) = state.roots.get_mut(&backing.id) {
                *count += 1;
            } else {
                let charged = state.bytes.checked_add(backing.size)?;
                if charged > LOAN_BYTES {
                    return None;
                }
                state.roots.insert(backing.id, 1);
                state.bytes = charged;
            }
            state.slots += 1;
            Some(ReadLoan {
                loans: self.clone(),
                backing,
            })
        }
    }

    pub(in crate::proto::session) struct ReadLoan {
        loans: Arc<ReadLoans>,
        backing: Backing,
    }

    impl ReadLoan {
        pub(in crate::proto::session) fn attach(self, bytes: Bytes) -> Bytes {
            Bytes::from_owner(LoanedBytes { bytes, _loan: self })
        }
    }

    impl Drop for ReadLoan {
        fn drop(&mut self) {
            let mut state = self
                .loans
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let count = state.roots.get_mut(&self.backing.id).expect("live loan");
            *count -= 1;
            if *count == 0 {
                state.roots.remove(&self.backing.id);
                state.bytes -= self.backing.size;
            }
            state.slots -= 1;
        }
    }

    struct LoanedBytes {
        bytes: Bytes,
        _loan: ReadLoan,
    }

    impl AsRef<[u8]> for LoanedBytes {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn loans_charge_the_root_once_and_release_at_the_last_slice() {
            let loans = Arc::new(ReadLoans::with_slots(2));
            let full = Backing::new(LOAN_BYTES);
            let next = Backing::new(1);
            let first = loans.acquire(full).unwrap();
            let second = loans.acquire(full).unwrap();
            assert!(loans.acquire(full).is_none());
            drop(first);
            assert!(loans.acquire(next).is_none());
            drop(second);
            assert!(loans.acquire(next).is_some());
        }
    }
}
