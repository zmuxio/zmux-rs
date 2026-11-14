//! The TLS connection beneath an HTTP connection, when this process
//! terminates it: a [`TlsConnection`] given as the connection.

use std::any::Any;
use std::sync::{Arc, Mutex, PoisonError};

use zmux::PipeIo;
use zmux_rustls::{TlsBinding, TlsConnection};

/// The binding of `io` when it is a [`TlsConnection`].
pub(crate) fn binding_of<IO: 'static>(io: &IO) -> Option<TlsBinding> {
    (io as &dyn Any)
        .downcast_ref::<TlsConnection>()
        .map(TlsConnection::binding)
}

/// The binding of the connection a client's bidirectional request goes out
/// on; a redirect followed over a new connection replaces it with that
/// connection's.
#[derive(Clone)]
pub(crate) struct BindingSlot(Arc<Mutex<Option<TlsBinding>>>);

impl BindingSlot {
    pub(crate) fn new(binding: Option<TlsBinding>) -> Self {
        Self(Arc::new(Mutex::new(binding)))
    }

    fn get(&self) -> Option<TlsBinding> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set(&self, binding: Option<TlsBinding>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = binding;
    }

    /// `io` declared as the connection now in the slot is: secure when it
    /// is bound, with the exporter and the TLS state of whichever
    /// connection then carries the request.
    pub(crate) fn apply(&self, io: PipeIo) -> PipeIo {
        let Some(first) = self.get() else {
            return io;
        };
        if first.terminated_tls().is_none() {
            return io;
        }
        // The TLS state (ALPN, SNI) of whichever connection carries the
        // request now: a redirect's replaces the first one's.
        let tls = self.clone();
        let io = io.with_terminated_tls(move || tls.get().and_then(|b| b.terminated_tls()));
        if !first.is_bound() {
            return io;
        }
        let slot = self.clone();
        io.with_carrier_secure()
            .with_exporter(move |label, context, out| {
                slot.get().is_some_and(|b| b.export(label, context, out))
            })
    }
}
