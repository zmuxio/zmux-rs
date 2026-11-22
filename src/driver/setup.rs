//! Ownership of a listener admission. A `Slot` is a lookup key in `ListenerCore`.
//! Only Reservation owns the right to return it. Neither Reservation nor Setup is Clone.
use std::sync::{Arc, Weak};

use super::attachment::Attachment;
use crate::proto::listener::{CarrierId, Slot};

/// A native listener critical section. Like the session lock, this marks the
/// lock scope until the underlying guard has been released.
pub(super) struct ListenerLock<'a, T> {
    guard: std::sync::MutexGuard<'a, T>,
    #[cfg(debug_assertions)]
    _scope: crate::lock_scope::Token,
}

impl<'a, T> From<std::sync::MutexGuard<'a, T>> for ListenerLock<'a, T> {
    fn from(guard: std::sync::MutexGuard<'a, T>) -> Self {
        Self {
            guard,
            #[cfg(debug_assertions)]
            _scope: crate::lock_scope::Token::new(),
        }
    }
}

impl<T> std::ops::Deref for ListenerLock<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> std::ops::DerefMut for ListenerLock<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

#[cfg(feature = "blocking")]
impl<'a, T> ListenerLock<'a, T> {
    pub(super) fn into_wait(self) -> std::sync::MutexGuard<'a, T> {
        self.guard
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum CommitError {
    ListenerClosed,
    Evicted,
    Withdrawn,
    Refused,
}

impl From<CommitError> for crate::HandleError {
    fn from(_: CommitError) -> Self {
        Self::Refused
    }
}

pub(super) trait SlotTable: Send + Sync + 'static {
    fn release(&self, slot: Slot);
    /// Holds the listener lock through the final withdrawal check and deregistration.
    fn commit(
        &self,
        id: Option<CarrierId>,
        slot: Option<Slot>,
        remove: bool,
        willing: impl FnOnce() -> bool,
    ) -> Result<(), CommitError>;
}

// Endpoints without a listener cannot construct a reservation.
#[cfg(feature = "tokio")]
impl SlotTable for std::convert::Infallible {
    fn release(&self, _: Slot) {
        match *self {}
    }

    fn commit(
        &self,
        _: Option<CarrierId>,
        _: Option<Slot>,
        _: bool,
        _: impl FnOnce() -> bool,
    ) -> Result<(), CommitError> {
        match *self {}
    }
}

struct Reservation<T: SlotTable> {
    listener: Weak<T>,
    id: Slot,
}

impl<T: SlotTable> Drop for Reservation<T> {
    fn drop(&mut self) {
        if let Some(listener) = self.listener.upgrade() {
            listener.release(self.id);
        }
    }
}

/// Reservation for one bootstrap eligible for publication. Its place passes to
/// the accept queue on publication, or returns on any setup exit.
pub(super) struct QueuePlace<F: Fn()>(Option<F>);

impl<F: Fn()> QueuePlace<F> {
    pub(super) fn new(release: F, admitted: bool) -> Self {
        Self(admitted.then_some(release))
    }

    pub(super) fn queued(&mut self) {
        self.0.take();
    }
}

impl<F: Fn()> Drop for QueuePlace<F> {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            release();
        }
    }
}

/// The terminal disposition specifies who owns the admission's resources.
#[derive(Clone, Copy)]
enum Fate {
    Publish,
    Session,
    #[cfg(feature = "tokio")]
    Returned,
    Transfer(Transfer),
    #[cfg(feature = "tokio")]
    Exempt,
    Refused,
    Stalled,
    Cancelled,
    Stopped,
    HostFailed,
}

/// Dispositions that move an uninstalled carrier out of setup.
#[derive(Clone, Copy)]
pub(super) enum Transfer {
    Reply,
    #[cfg(feature = "tokio")]
    Fallback,
}

/// A setup is linear. The carrier may change representation (raw pipe, transformed
/// pipe, establishing session) without cloning its reservation or its authority.
pub(super) struct Setup<O, C> {
    carrier: C,
    owner: O,
}

pub(super) trait Owner {
    type Table: SlotTable;
    fn authority(&mut self) -> &mut Authority<Self::Table>;
}

impl<O: Owner> Owner for &mut O {
    type Table = O::Table;
    fn authority(&mut self) -> &mut Authority<Self::Table> {
        (**self).authority()
    }
}

/// The listener's cleanup worker owns this carrier and reservation together.
pub(super) struct Stall<C> {
    carrier: C,
    id: Slot,
    _group: Arc<Attachment>,
}

impl<C> Stall<C> {
    #[cfg(feature = "tokio")]
    pub(super) fn slot(&self) -> Slot {
        self.id
    }

    #[cfg(feature = "tokio")]
    pub(super) fn carrier_mut(&mut self) -> &mut C {
        &mut self.carrier
    }

    #[cfg(feature = "blocking")]
    pub(super) fn wait(self, wait: impl FnOnce(Slot)) {
        wait(self.id);
        drop(self.carrier);
    }
}

enum Phase<T: SlotTable> {
    Pending {
        slot: Option<Reservation<T>>,
        group: Option<Arc<Attachment>>,
    },
    Publishing {
        slot: Option<Reservation<T>>,
        group: Option<Arc<Attachment>>,
    },
    Stalled {
        id: Slot,
        _group: Arc<Attachment>,
    },
    Transferred,
}

/// Each caller competes exactly once with the setup that receives its carrier.
#[derive(Debug, Default)]
pub(super) struct Handoff(std::sync::atomic::AtomicU8);

impl Handoff {
    const OPEN: u8 = 0;
    const WITHDRAWN: u8 = 1;
    const COMMITTED: u8 = 2;

    #[cfg(feature = "tokio")]
    pub(super) fn withdraw(&self) -> bool {
        self.choose(Self::WITHDRAWN).is_ok()
    }

    fn choose(&self, outcome: u8) -> Result<u8, u8> {
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        self.0
            .compare_exchange(Self::OPEN, outcome, AcqRel, Acquire)
    }

    pub(super) fn commit(&self) -> bool {
        matches!(self.choose(Self::COMMITTED), Ok(_) | Err(Self::COMMITTED))
    }

    fn willing(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire) != Self::WITHDRAWN
    }
}

pub(super) struct Authority<T: SlotTable> {
    state: Phase<T>,
    table: Option<Weak<T>>,
    registration: Option<CarrierId>,
    // Foreign runtimes may request cancellation before they can drop the future.
    withdrawal: Option<Arc<Handoff>>,
    partner: Option<Arc<Handoff>>,
}

impl<T: SlotTable> Authority<T> {
    fn retain(slot: Option<Reservation<T>>, group: Option<Arc<Attachment>>) {
        if let (Some(group), Some(slot)) = (group, slot) {
            group.hold(slot);
        }
    }

    fn arbitrate(&self, remove: bool, check: fn(&Handoff) -> bool) -> Result<(), CommitError> {
        let willing = || {
            // Settle both receipts. A withdrawn half still allows its partner to commit.
            let first = self.withdrawal.as_deref().is_none_or(check);
            let second = self.partner.as_deref().is_some_and(check);
            first || second
        };
        if let Some(table) = &self.table {
            table.upgrade().ok_or(CommitError::ListenerClosed)?.commit(
                self.registration,
                self.slot(),
                remove,
                willing,
            )
        } else {
            willing().then_some(()).ok_or(CommitError::Withdrawn)
        }
    }

    pub(super) fn checkpoint(&self) -> Result<(), CommitError> {
        self.arbitrate(false, Handoff::willing)
    }

    fn transition(&mut self, event: Fate) -> Result<(), CommitError> {
        if matches!(self.state, Phase::Pending { .. })
            && matches!(event, Fate::Publish | Fate::Transfer(_) | Fate::Stalled)
        {
            self.arbitrate(!matches!(event, Fate::Stalled), Handoff::commit)?;
        }
        match std::mem::replace(&mut self.state, Phase::Transferred) {
            Phase::Publishing { slot, group } => match event {
                Fate::Session => Ok(()),
                Fate::Refused | Fate::Cancelled => {
                    Self::retain(slot, group);
                    Ok(())
                }
                #[cfg(feature = "tokio")]
                Fate::Returned | Fate::Exempt => {
                    self.state = Phase::Publishing { slot, group };
                    Err(CommitError::Refused)
                }
                Fate::Publish
                | Fate::Transfer(_)
                | Fate::Stalled
                | Fate::Stopped
                | Fate::HostFailed => {
                    self.state = Phase::Publishing { slot, group };
                    Err(CommitError::Refused)
                }
            },
            Phase::Pending { slot, group } => match event {
                Fate::Publish => {
                    self.state = Phase::Publishing { slot, group };
                    Ok(())
                }
                Fate::Session => {
                    self.state = Phase::Pending { slot, group };
                    Err(CommitError::Refused)
                }
                #[cfg(feature = "tokio")]
                Fate::Returned | Fate::Transfer(Transfer::Fallback) => Ok(()),
                #[cfg(feature = "tokio")]
                Fate::Exempt => {
                    self.state = Phase::Pending { slot: None, group };
                    drop(slot);
                    Ok(())
                }
                Fate::Stalled => {
                    let slot = slot.ok_or(CommitError::Refused)?;
                    let id = slot.id;
                    let group = group.unwrap_or_default();
                    group.hold(slot);
                    self.state = Phase::Stalled { id, _group: group };
                    Ok(())
                }
                Fate::Transfer(Transfer::Reply)
                | Fate::Refused
                | Fate::Cancelled
                | Fate::Stopped
                | Fate::HostFailed => {
                    Self::retain(slot, group);
                    Ok(())
                }
            },
            settled @ (Phase::Transferred | Phase::Stalled { .. }) => {
                self.state = settled;
                Err(CommitError::Refused)
            }
        }
    }
}

impl<T: SlotTable> Owner for Authority<T> {
    type Table = T;
    fn authority(&mut self) -> &mut Self {
        self
    }
}

#[cfg(feature = "tokio")]
impl Authority<std::convert::Infallible> {
    pub(super) fn direct() -> Self {
        Self::new()
    }
}

impl<T: SlotTable> Authority<T> {
    fn new() -> Self {
        Self {
            state: Phase::Pending {
                slot: None,
                group: None,
            },
            withdrawal: None,
            partner: None,
            table: None,
            registration: None,
        }
    }

    pub(super) fn listener(table: &Arc<T>) -> Self {
        let mut authority = Self::new();
        authority.table = Some(Arc::downgrade(table));
        authority
    }

    pub(super) fn register(&mut self, id: CarrierId) {
        self.registration = Some(id);
    }

    #[cfg(feature = "tokio")]
    pub(super) fn withdrawal(&mut self) -> Arc<Handoff> {
        self.withdrawal.get_or_insert_default().clone()
    }

    #[cfg(feature = "tokio")]
    pub(super) fn observe_withdrawal(&mut self, gate: Arc<Handoff>) {
        self.withdrawal = Some(gate);
    }

    pub(super) fn stalled<C>(&mut self, carrier: C) -> Option<Stall<C>> {
        if !matches!(self.state, Phase::Stalled { .. }) {
            return None;
        }
        let Phase::Stalled { id, _group: group } =
            std::mem::replace(&mut self.state, Phase::Transferred)
        else {
            unreachable!()
        };
        Some(Stall {
            carrier,
            id,
            _group: group,
        })
    }

    /// The table issues a slot only after this owner can accept it. The ID
    /// enters its drop guard before returning to either driver.
    pub(super) fn reserve<R>(
        &mut self,
        listener: &Arc<T>,
        acquire: impl FnOnce() -> Result<(Slot, R), crate::HandleError>,
    ) -> Result<R, crate::HandleError> {
        let Phase::Pending { slot, .. } = &mut self.state else {
            return Err(crate::HandleError::Refused);
        };
        if slot.is_some() {
            return Err(crate::HandleError::Refused);
        }
        let (id, result) = acquire()?;
        *slot = Some(Reservation {
            listener: Arc::downgrade(listener),
            id,
        });
        Ok(result)
    }

    pub(super) fn slot(&self) -> Option<Slot> {
        match &self.state {
            Phase::Pending { slot, .. } => slot.as_ref().map(|r| r.id),
            Phase::Stalled { id, .. } => Some(*id),
            Phase::Publishing { .. } | Phase::Transferred => None,
        }
    }

    #[cfg(feature = "tokio")]
    pub(super) fn stalling(&self) -> bool {
        matches!(self.state, Phase::Stalled { .. })
    }

    #[cfg(feature = "tokio")]
    pub(super) fn admission_worker(&mut self) -> Box<dyn Send + Sync> {
        let Phase::Pending { group, .. } = &mut self.state else {
            unreachable!("decisions precede handoff")
        };
        Box::new(group.get_or_insert_default().worker())
    }

    pub(super) fn bind(&mut self, attachment: &Arc<Attachment>) {
        if let Phase::Pending { group, .. } = &mut self.state {
            #[cfg(feature = "tokio")]
            attachment.adopt(group.as_ref());
            *group = Some(attachment.clone());
        }
    }

    pub(super) fn stop(&mut self) -> Result<(), crate::HandleError> {
        self.transition(Fate::Stopped).map_err(Into::into)
    }

    pub(super) fn host_failed(&mut self) -> Result<(), crate::HandleError> {
        self.transition(Fate::HostFailed).map_err(Into::into)
    }

    pub(super) fn stall(&mut self) -> Result<(), crate::HandleError> {
        self.transition(Fate::Stalled).map_err(Into::into)
    }

    #[cfg(feature = "tokio")]
    pub(super) fn exempt(&mut self) -> Result<(), crate::HandleError> {
        self.transition(Fate::Exempt).map_err(Into::into)
    }

    #[cfg(feature = "tokio")]
    pub(super) fn give_back(&mut self) -> Result<(), crate::HandleError> {
        self.transition(Fate::Returned).map_err(Into::into)
    }
}

#[cfg(feature = "tokio")]
impl<C> Setup<Authority<std::convert::Infallible>, C> {
    /// A process-wide lane probe has no reservation. Its resolved target
    /// supplies the listener participating in the installation commit.
    pub(super) fn at_listener<T: SlotTable>(self, table: &Arc<T>) -> Setup<Authority<T>, C> {
        Setup::new(Authority::listener(table), self.carrier)
    }
}

impl<O: Owner, C> Setup<O, C> {
    pub(super) fn new(owner: O, carrier: C) -> Self {
        Self { carrier, owner }
    }

    pub(super) fn parts(&mut self) -> (&mut O, &mut C) {
        (&mut self.owner, &mut self.carrier)
    }

    #[cfg(feature = "blocking")]
    pub(super) fn map<D>(self, f: impl FnOnce(C) -> D) -> Setup<O, D> {
        Setup::new(self.owner, f(self.carrier))
    }

    #[cfg(feature = "tokio")]
    pub(super) fn register<P: Owner<Table = O::Table>>(
        self,
        f: impl FnOnce(O) -> P,
    ) -> Setup<P, C> {
        Setup::new(f(self.owner), self.carrier)
    }

    /// A transform can move the carrier, while its original authority stays
    /// in this frame through the host call, errors and cancellation.
    #[cfg(feature = "tokio")]
    pub(super) async fn prepare<D>(
        mut self,
        f: impl AsyncFnOnce(&mut O, C) -> Result<D, crate::HandleError>,
    ) -> Result<Setup<O, D>, crate::HandleError> {
        let carrier = f(&mut self.owner, self.carrier).await?;
        Ok(Setup::new(self.owner, carrier))
    }

    #[cfg(feature = "blocking")]
    pub(super) fn prepare_blocking<D>(
        mut self,
        f: impl FnOnce(&mut O, C) -> Result<D, crate::HandleError>,
    ) -> Result<Setup<O, D>, crate::HandleError> {
        let carrier = f(&mut self.owner, self.carrier)?;
        Ok(Setup::new(self.owner, carrier))
    }

    #[cfg(feature = "tokio")]
    pub(super) fn pair(
        mut self,
        mut second: Self,
        combine: impl FnOnce(C, C) -> C,
        group: &Arc<Attachment>,
    ) -> Result<Self, crate::HandleError> {
        self.owner.authority().partner = second.owner.authority().withdrawal.take();
        second.owner.authority().give_back()?;
        self.owner.authority().bind(group);
        Ok(Self::new(self.owner, combine(self.carrier, second.carrier)))
    }

    /// Synchronous publication cannot be cancelled partway. The driver's closure
    /// validates the listener/session state and moves the payload under its lock.
    /// Release the reservation after leaving that critical section.
    pub(super) fn publish(
        self,
        publish: impl FnOnce(C) -> Result<(), crate::HandleError>,
    ) -> Result<(), crate::HandleError> {
        self.publication()?.finish(publish)
    }

    pub(super) fn publication(mut self) -> Result<Publication<O, C>, CommitError> {
        self.owner.authority().transition(Fate::Publish)?;
        Ok(Publication(self))
    }

    pub(super) fn claim(mut self, to: Transfer) -> Result<C, CommitError> {
        self.owner.authority().transition(Fate::Transfer(to))?;
        Ok(self.carrier)
    }
}

pub(super) struct Publication<O, C>(Setup<O, C>);

impl<O: Owner, C> Publication<O, C> {
    pub(super) fn finish(
        self,
        publish: impl FnOnce(C) -> Result<(), crate::HandleError>,
    ) -> Result<(), crate::HandleError> {
        let Setup { mut owner, carrier } = self.0;
        let outcome = publish(carrier);
        owner.authority().transition(if outcome.is_ok() {
            Fate::Session
        } else {
            Fate::Refused
        })?;
        outcome
    }
}

#[cfg(feature = "tokio")]
impl<O: Owner, C> Setup<O, Option<C>> {
    pub(super) fn transpose(self) -> Option<Setup<O, C>> {
        self.carrier.map(|carrier| Setup::new(self.owner, carrier))
    }
}

impl<T: SlotTable> Drop for Authority<T> {
    fn drop(&mut self) {
        let _ = self.transition(Fate::Cancelled);
    }
}

/// Observe cancellation before polling the next pre-handoff setup step. A
/// synchronous publication that completes in that poll wins irrevocably.
pub(crate) async fn while_open<T>(stop: impl Future, work: impl Future<Output = T>) -> Option<T> {
    let mut stop = std::pin::pin!(stop);
    let mut work = std::pin::pin!(work);
    std::future::poll_fn(|cx| {
        if stop.as_mut().poll(cx).is_ready() {
            std::task::Poll::Ready(None)
        } else {
            work.as_mut().poll(cx).map(Some)
        }
    })
    .await
}

/// Setup and its watchdog share one interrupt target across carrier transforms.
#[cfg(feature = "blocking")]
pub(super) struct Interrupt(std::sync::Mutex<Option<Arc<super::blocking::Closer>>>);

#[cfg(feature = "blocking")]
impl Interrupt {
    pub(super) fn new(target: Arc<super::blocking::Closer>) -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(Some(target))))
    }

    pub(super) fn closer(self: &Arc<Self>) -> Arc<super::blocking::Closer> {
        let owner = self.clone();
        Arc::new(Box::new(move |_| {
            let current = owner
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(close) = current {
                close(std::net::Shutdown::Both);
            }
        }))
    }

    pub(super) fn replace(
        &self,
        next: Arc<super::blocking::Closer>,
    ) -> Result<(), crate::HandleError> {
        let mut current = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.is_none() {
            drop(current);
            next(std::net::Shutdown::Both);
            return Err(crate::HandleError::Refused);
        }
        let old = current.replace(next);
        drop(current);
        drop(old);
        Ok(())
    }
}

/// The listener owns establishment and the queue. Only accept transfers a
/// session to the application, changing the close code used at shutdown.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionOwner {
    Establishing,
    Queued,
    Accepted,
}

type SessionMap<S> =
    std::sync::Mutex<std::collections::HashMap<crate::SessionId, (Weak<S>, SessionOwner)>>;

/// Owned by the session's accounting link until its driver ends, including
/// startup rollback. Removal never has to lock a listener or a session.
pub(super) struct SessionRegistration<S> {
    registry: Weak<SessionMap<S>>,
    id: crate::SessionId,
}

impl<S> Drop for SessionRegistration<S> {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.id);
        }
    }
}

pub(super) struct Sessions<D: super::handle::Driver>(Arc<SessionMap<super::handle::Shared<D>>>);

impl<D: super::handle::Driver> Default for Sessions<D> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<D: super::handle::Driver> Sessions<D> {
    pub(super) fn start(
        &self,
        session: &Arc<super::handle::Shared<D>>,
    ) -> SessionRegistration<super::handle::Shared<D>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                session.id,
                (Arc::downgrade(session), SessionOwner::Establishing),
            );
        SessionRegistration {
            registry: Arc::downgrade(&self.0),
            id: session.id,
        }
    }

    fn mark(&self, id: crate::SessionId, owner: SessionOwner) -> bool {
        let mut table = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = table.get_mut(&id) {
            entry.1 = owner;
            true
        } else {
            false
        }
    }

    pub(super) fn queue(&self, id: crate::SessionId) -> Result<(), crate::HandleError> {
        self.mark(id, SessionOwner::Queued)
            .then_some(())
            .ok_or(crate::HandleError::Rejected)
    }

    pub(super) fn accept(&self, id: crate::SessionId) {
        // A session already queued may have ended before the application took it.
        self.mark(id, SessionOwner::Accepted);
    }

    fn snapshot(&self, owner: SessionOwner) -> Vec<Weak<super::handle::Shared<D>>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|v| v.1 == owner)
            .map(|v| v.0.clone())
            .collect()
    }

    pub(super) fn establishing(&self) -> Vec<Arc<super::handle::Shared<D>>> {
        self.snapshot(SessionOwner::Establishing)
            .into_iter()
            .filter_map(|s| s.upgrade())
            .collect()
    }

    pub(super) fn accepted(&self) -> Vec<super::handle::Session<D>> {
        // Upgrading an application handle takes its session lock, after snapshot unlocks.
        self.snapshot(SessionOwner::Accepted)
            .into_iter()
            .filter_map(|s| super::handle::WeakSession::from_weak(s).upgrade())
            .collect()
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

    #[derive(Default)]
    struct Table {
        stopped: AtomicBool,
        releases: AtomicUsize,
    }

    impl SlotTable for Table {
        fn release(&self, _: Slot) {
            self.releases.fetch_add(1, SeqCst);
        }
        fn commit(
            &self,
            _: Option<CarrierId>,
            _: Option<Slot>,
            _: bool,
            willing: impl FnOnce() -> bool,
        ) -> Result<(), CommitError> {
            if self.stopped.load(SeqCst) {
                return Err(CommitError::ListenerClosed);
            }
            willing().then_some(()).ok_or(CommitError::Withdrawn)
        }
    }

    #[test]
    // HS-04, HS-43
    fn every_handoff_checks_stop_and_both_withdrawals_at_commit() {
        for fate in [
            Fate::Publish,
            Fate::Transfer(Transfer::Reply),
            Fate::Transfer(Transfer::Fallback),
            Fate::Stalled,
        ] {
            for (stop, left, right) in [
                (true, false, false),
                (false, true, true),
                (false, true, false),
                (false, false, true),
                (false, false, false),
            ] {
                let table = Arc::<Table>::default();
                let group = Arc::<Attachment>::default();
                let make = |id| {
                    let mut owner = Authority::listener(&table);
                    owner.reserve(&table, || Ok((Slot(id), ()))).unwrap();
                    let gate = owner.withdrawal();
                    (Setup::new(owner, ()), gate)
                };
                let (first, a) = make(1);
                let (second, b) = make(2);
                let mut combined = first.pair(second, |(), ()| (), &group).unwrap();
                assert_eq!(table.releases.load(SeqCst), 1);
                if left {
                    assert!(a.withdraw());
                }
                if right {
                    assert!(b.withdraw());
                }
                table.stopped.store(stop, SeqCst);
                let claimed = combined.owner.transition(fate);
                assert_eq!(claimed.is_ok(), !(stop || left && right));
                if claimed.is_ok() {
                    assert!(!a.withdraw() && !b.withdraw());
                    // A stop after commit cannot recall a handed-off resource.
                    table.stopped.store(true, SeqCst);
                    assert!(combined.owner.transition(fate).is_err());
                    if matches!(fate, Fate::Publish) {
                        combined.owner.transition(Fate::Refused).unwrap();
                    }
                }
                drop(combined);
                drop(group);
                assert_eq!(table.releases.load(SeqCst), 2);
            }
        }
        assert!(Authority::<Table>::new().stall().is_err());
    }
}
