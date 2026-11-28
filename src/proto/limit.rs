//! The limiter interface: one small interface through
//! which any external limiter, budget or meter acts on bytes that zmux
//! forwards itself, the datagrams of a session and
//! the relay helper, without zmux knowing what it implements.
//!
//! Rate limiting, byte budgets and quotas are not part of zmux: stream
//! I/O is the standard interface of the language, so a general limiter
//! wraps it, and flow control turns a reader it slows into backpressure on
//! the peer. Datagram calls are not stream I/O, so a session takes a
//! limiter for them ([`DatagramLimiter`]).

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::task::{Context, Poll};

/// An external limiter: reserve, then refund. A caller takes bytes
/// before it moves them and gives back what it did not use. The three
/// methods have the same names and meaning in every zmux language.
///
/// Contract (units are bytes):
///
/// - **Arguments.** `max` 0 takes nothing and returns 0 at once; `min` 0
///   is taken as 1 and `min` > `max` as `max`. `(n, n)` is an
///   all-or-nothing request, `(1, max)` one for as much as possible.
/// - **Grant.** A successful grant takes and returns `n` in the normalized
///   inclusive range `min..=max`. An atomic request `(n, n)` must be
///   granted in full. A request beyond the limiter's atomic capacity
///   must fail immediately.
///   A limiter should not grant much less than its quantum (about 20 ms of
///   traffic at its rate) when `max` allows.
/// - [`Limiter::poll_acquire`] waits until it can grant. A future dropped
///   while it waits took nothing. An error takes nothing and fails the
///   operation that asked.
/// - [`Limiter::try_acquire`] never blocks: it grants as above, or
///   returns 0 with nothing taken.
/// - [`Limiter::refund`] gives back bytes granted and not used:
///   best-effort, never blocks or panics, callable from any thread and
///   from cleanup; a refund beyond what is outstanding is clamped.
/// - Every method is safe under any number of concurrent callers, with no
///   fairness guarantee.
///
/// zmux calls every method outside session locks. Splice may retain a
/// bounded output while waiting. A limiter that panics, or grants outside
/// the normalized range (with 0 allowed from `try_acquire`), fails the
/// acquisition that asked ([`LimitError`]) or, in `try_acquire`, counts as
/// nothing taken; a panic in `refund` is ignored. The callers in zmux go
/// through [`Permit`], which applies these rules.
pub trait Limiter: Send + Sync {
    /// Maximum atomic grant, independent of the current balance.
    ///
    /// Return `None` if the maximum is unknown, or `Some(u64::MAX)` for
    /// unlimited capacity. Splice requires a declared maximum at installation.
    fn max_burst_bytes(&self) -> Option<u64> {
        None
    }

    /// Waits until the limiter can grant, then takes and returns the
    /// grant (see the trait's contract); `Err` takes nothing.
    fn poll_acquire(
        &self,
        cx: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<u64, LimitError>>;

    /// Takes and returns a grant now, or 0 with nothing taken.
    fn try_acquire(&self, min: u64, max: u64) -> u64;

    /// Gives back `n` bytes granted and not used.
    fn refund(&self, n: u64);
}

/// Why a [`Limiter`] did not grant: its own error ([`LimitError::new`],
/// the [`source`](StdError::source)), a panic, or a grant outside the
/// contract.
#[derive(Debug)]
pub struct LimitError(Cause);

#[derive(Debug)]
enum Cause {
    Limiter(Box<dyn StdError + Send + Sync>),
    Panicked,
    InvalidGrant { granted: u64, min: u64, max: u64 },
}

impl LimitError {
    /// The limiter's own error, for example a budget exhausted.
    pub fn new(error: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self(Cause::Limiter(error.into()))
    }

    /// Whether the limiter panicked.
    #[must_use]
    pub const fn is_panic(&self) -> bool {
        matches!(self.0, Cause::Panicked)
    }

    /// Whether the limiter granted outside the contract.
    #[must_use]
    pub const fn is_invalid_grant(&self) -> bool {
        matches!(self.0, Cause::InvalidGrant { .. })
    }
}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Cause::Limiter(e) => write!(f, "limiter refused: {e}"),
            Cause::Panicked => f.write_str("limiter panicked"),
            Cause::InvalidGrant { granted, min, max } => {
                write!(f, "limiter granted {granted} bytes, outside {min}..={max}")
            }
        }
    }
}

impl StdError for LimitError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.0 {
            Cause::Limiter(e) => Some(&**e),
            _ => None,
        }
    }
}

/// Bytes granted by a limiter: what is not [`Permit::consume`]d is
/// refunded when it is dropped.
#[must_use = "a permit dropped unused refunds its bytes"]
pub struct Permit<'a> {
    limiter: &'a dyn Limiter,
    left: u64,
}

impl<'a> Permit<'a> {
    /// Waits for a grant of `min..=max` bytes from `limiter`, as a permit
    /// that refunds what it holds unused when dropped. `max` 0 is an
    /// empty permit at once. Cancel-safe: a future dropped unfinished took
    /// nothing. Any limiter coerces: `Permit::acquire(&my_limiter, 1, n)`,
    /// or `&*arc` for an `Arc<dyn Limiter>`.
    ///
    /// # Errors
    ///
    /// The limiter's error, its panic or a grant outside the contract
    /// ([`LimitError`]); nothing stays taken.
    pub fn acquire(
        limiter: &'a dyn Limiter,
        min: u64,
        max: u64,
    ) -> impl Future<Output = Result<Self, LimitError>> + 'a {
        std::future::poll_fn(move |cx| Self::poll_acquire(limiter, cx, min, max))
    }

    /// One poll of [`Permit::acquire`], with the
    /// arguments brought into the contract and the grant checked.
    pub(crate) fn poll_acquire(
        limiter: &'a dyn Limiter,
        cx: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<Self, LimitError>> {
        if max == 0 {
            return Poll::Ready(Ok(Permit { limiter, left: 0 }));
        }
        let min = min.clamp(1, max);
        let got = match catch_unwind(AssertUnwindSafe(|| limiter.poll_acquire(cx, min, max))) {
            Err(_) => return Poll::Ready(Err(LimitError(Cause::Panicked))),
            Ok(Poll::Pending) => return Poll::Pending,
            Ok(Poll::Ready(Err(e))) => return Poll::Ready(Err(e)),
            Ok(Poll::Ready(Ok(n))) => n,
        };
        if !(min..=max).contains(&got) {
            refund(Some(limiter), got);
            return Poll::Ready(Err(LimitError(Cause::InvalidGrant {
                granted: got,
                min,
                max,
            })));
        }
        Poll::Ready(Ok(Permit { limiter, left: got }))
    }

    /// A grant of `min..=max` bytes now ([`Limiter::try_acquire`]); `None`
    /// when it is 0, the limiter panicked or violated the range (refunded
    /// at once), or `max` is 0 (no call).
    pub fn try_acquire(limiter: &'a dyn Limiter, min: u64, max: u64) -> Option<Self> {
        if max == 0 {
            return None;
        }
        let min = min.clamp(1, max);
        let got = catch_unwind(AssertUnwindSafe(|| limiter.try_acquire(min, max))).unwrap_or(0);
        if !(min..=max).contains(&got) {
            refund(Some(limiter), got);
            return None;
        }
        (got > 0).then_some(Permit { limiter, left: got })
    }

    /// The bytes it holds unused.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.left
    }

    /// Whether it holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.left == 0
    }

    /// Uses `n` of its bytes (at most what it holds): they stay taken.
    pub fn consume(&mut self, n: u64) {
        self.left -= n.min(self.left);
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn prepaid_remaining(&mut self) -> &mut u64 {
        &mut self.left
    }

    /// Uses every byte it holds; returns how many: the grant of an atomic
    /// unit, refunded with [`refund`] if the unit does not go on.
    pub(crate) fn take_all(mut self) -> u64 {
        std::mem::take(&mut self.left)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        refund(Some(self.limiter), self.left);
    }
}

impl fmt::Debug for Permit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Permit").field("left", &self.left).finish()
    }
}

/// Polices one datagram of `len` payload bytes: `try_acquire(len, len)`.
/// The exact grant when the datagram passes, to [`refund`] if it is then
/// not queued. Returns `None` when the datagram is to be dropped.
/// An empty datagram passes without a call (grant 0).
pub fn police(limiter: &dyn Limiter, len: u64) -> Option<u64> {
    if len == 0 {
        return Some(0);
    }
    Permit::try_acquire(limiter, len, len).map(Permit::take_all)
}

/// Refunds `n` bytes to `limiter` (a panic is ignored; nothing for 0).
pub fn refund<L: Limiter + ?Sized>(limiter: Option<&L>, n: u64) {
    if let Some(l) = limiter
        && n > 0
    {
        let _ = catch_unwind(AssertUnwindSafe(|| l.refund(n)));
    }
}

/// The datagram limiters of a session, one per direction (the hook
/// `datagram_limiter`). Datagram limiting polices and never
/// shapes: a datagram passes when the direction's limiter grants its whole
/// payload without waiting (`try_acquire(n, n)`), and is otherwise dropped
/// and counted (`datagrams_dropped_limit`): on send before it is queued, on
/// receive before it is queued for the application, always outside the
/// session's lock (see [`Limiter`]). A grant whose datagram is then not
/// queued is refunded. Without a limiter (the default) nothing is called;
/// with one, each datagram costs one call (two when it is not queued) and
/// no allocation.
#[derive(Clone, Default)]
pub struct DatagramLimiter {
    /// Limits the datagrams this endpoint sends, session and stream
    /// datagrams together.
    pub send: Option<Arc<dyn Limiter>>,
    /// Limits the datagrams received from the peer.
    pub receive: Option<Arc<dyn Limiter>>,
}

impl fmt::Debug for DatagramLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramLimiter")
            .field("send", &self.send.is_some())
            .field("receive", &self.receive.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A budget that never refills: grants `min..=max` of what is left, or
    /// waits (pending) / returns 0 when less than `min` is left.
    struct Budget(AtomicU64);

    impl Limiter for Budget {
        fn poll_acquire(
            &self,
            _: &mut Context<'_>,
            min: u64,
            max: u64,
        ) -> Poll<Result<u64, LimitError>> {
            match self.try_acquire(min, max) {
                0 => Poll::Pending,
                n => Poll::Ready(Ok(n)),
            }
        }
        fn try_acquire(&self, min: u64, max: u64) -> u64 {
            let mut left = self.0.load(Ordering::SeqCst);
            loop {
                if left < min {
                    return 0;
                }
                let n = left.min(max);
                match self
                    .0
                    .compare_exchange(left, left - n, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => return n,
                    Err(now) => left = now,
                }
            }
        }
        fn refund(&self, n: u64) {
            self.0.fetch_add(n, Ordering::SeqCst);
        }
    }

    /// Answers with a fixed grant (or panics), recording each call's
    /// arguments and refunds.
    struct Fixed {
        grant: Option<u64>,
        calls: Mutex<Vec<(u64, u64)>>,
        refunded: AtomicU64,
    }

    fn fixed(grant: Option<u64>) -> Fixed {
        Fixed {
            grant,
            calls: Mutex::default(),
            refunded: AtomicU64::new(0),
        }
    }

    impl Limiter for Fixed {
        fn poll_acquire(
            &self,
            _: &mut Context<'_>,
            min: u64,
            max: u64,
        ) -> Poll<Result<u64, LimitError>> {
            Poll::Ready(Ok(self.try_acquire(min, max)))
        }
        fn try_acquire(&self, min: u64, max: u64) -> u64 {
            self.calls.lock().unwrap().push((min, max));
            self.grant.expect("limiter")
        }
        fn refund(&self, n: u64) {
            self.refunded.fetch_add(n, Ordering::SeqCst);
        }
    }

    fn poll(l: &dyn Limiter, min: u64, max: u64) -> Result<Permit<'_>, LimitError> {
        let cx = &mut Context::from_waker(std::task::Waker::noop());
        match std::pin::pin!(Permit::acquire(l, min, max)).poll(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => panic!("pending"),
        }
    }

    #[test]
    fn arguments_are_brought_into_the_contract() {
        let f = fixed(Some(8));
        assert!(poll(&f, 5, 0).unwrap().is_empty());
        assert!(Permit::try_acquire(&f, 5, 0).is_none());
        assert!(f.calls.lock().unwrap().is_empty(), "max 0 makes no call");
        for (min, max) in [(0, 8), (9, 8), (3, 8)] {
            assert_eq!(poll(&f, min, max).unwrap().len(), 8);
        }
        assert_eq!(Permit::try_acquire(&f, 0, 8).unwrap().len(), 8);
        assert_eq!(*f.calls.lock().unwrap(), [(1, 8), (8, 8), (3, 8), (1, 8)]);
    }

    #[test]
    fn invalid_grants_and_panics_take_nothing() {
        // Above max: refunded whole; an error from acquire, None from try.
        let over = fixed(Some(9));
        let e = poll(&over, 1, 8).unwrap_err();
        assert!(e.is_invalid_grant() && e.source().is_none());
        assert!(Permit::try_acquire(&over, 1, 8).is_none());
        assert_eq!(over.refunded.load(Ordering::SeqCst), 18);
        let short = fixed(Some(7));
        assert!(poll(&short, 8, 8).unwrap_err().is_invalid_grant());
        assert_eq!(police(&short, 8), None);
        assert_eq!(short.refunded.load(Ordering::SeqCst), 14);
        // 0 from acquire breaks the contract; from try it is a refusal.
        let zero = fixed(Some(0));
        assert!(poll(&zero, 1, 8).unwrap_err().is_invalid_grant());
        assert!(Permit::try_acquire(&zero, 1, 8).is_none());
        assert_eq!(zero.refunded.load(Ordering::SeqCst), 0);
        let panics = fixed(None);
        assert!(poll(&panics, 1, 8).unwrap_err().is_panic());
        assert!(Permit::try_acquire(&panics, 1, 8).is_none());
        assert_eq!(police(&panics, 4), None);
    }

    #[test]
    fn the_limiters_own_error_is_the_source() {
        struct Fails;
        impl Limiter for Fails {
            fn poll_acquire(
                &self,
                _: &mut Context<'_>,
                _: u64,
                _: u64,
            ) -> Poll<Result<u64, LimitError>> {
                Poll::Ready(Err(LimitError::new("quota gone")))
            }
            fn try_acquire(&self, _: u64, _: u64) -> u64 {
                0
            }
            fn refund(&self, _: u64) {
                panic!("refund")
            }
        }
        let e = poll(&Fails, 1, 1).unwrap_err();
        assert_eq!(e.source().unwrap().to_string(), "quota gone");
        refund(Some(&Fails as &dyn Limiter), 1);
    }

    #[test]
    fn a_permit_refunds_what_it_did_not_use() {
        let b = Budget(AtomicU64::new(100));
        let mut p = Permit::try_acquire(&b, 1, 60).unwrap();
        assert_eq!((p.len(), b.0.load(Ordering::SeqCst)), (60, 40));
        p.consume(25);
        drop(p);
        assert_eq!(b.0.load(Ordering::SeqCst), 75);
    }

    #[test]
    fn a_datagram_passes_only_with_a_grant_of_its_whole_payload() {
        let b = Budget(AtomicU64::new(1500));
        assert_eq!(police(&b, 1000), Some(1000));
        assert_eq!(police(&b, 1000), None, "500 left: never cut");
        assert_eq!(b.0.load(Ordering::SeqCst), 500, "nothing taken");
        assert_eq!(police(&b, 0), Some(0));
        refund(Some(&b as &dyn Limiter), 1000);
        assert_eq!(b.0.load(Ordering::SeqCst), 1500);
    }

    /// Many callers of one limiter never take more than it has: what was
    /// consumed plus what is left is the budget.
    #[test]
    fn a_shared_limiter_never_over_grants() {
        let b = Arc::new(Budget(AtomicU64::new(10_000)));
        let used = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let (b, used) = (b.clone(), used.clone());
                std::thread::spawn(move || {
                    let l: &dyn Limiter = &*b;
                    for k in 0..2_000u64 {
                        let want = 1 + (k + i) % 37;
                        let Some(mut p) = Permit::try_acquire(l, 1, want) else {
                            continue;
                        };
                        assert!(p.len() <= want);
                        let n = p.len().min(1 + k % 5);
                        p.consume(n);
                        used.fetch_add(n, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let used = used.load(Ordering::SeqCst);
        assert!(used <= 10_000);
        assert_eq!(used + b.0.load(Ordering::SeqCst), 10_000);
    }
}
