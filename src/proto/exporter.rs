//! The keying material exporter of a carrier: the one source of the
//! exporter of the innermost end-to-end handshake. It is read when a
//! value is needed, never when the carrier is made: the handshake may
//! complete later (early data).

use std::fmt;
use std::sync::Arc;

use super::keys::{EXPORTER_JOIN_LABEL, EXPORTER_SESSION_LABEL};

/// Labels starting with this key zmux's own joins:
/// [`CarrierExporter::export_for_host`] refuses them.
pub const RESERVED_EXPORTER_PREFIX: &str = "EXPORTER-zmux-";

/// The carrier exporter's label of an Establish's Binding.
const EXPORTER_SEAL_BOUND_LABEL: &str = "EXPORTER-zmux-seal-bound";

/// The length of the exporter values zmux reads.
const VALUE_LEN: usize = 32;

/// Fills `out` with keying material for a label and a context (RFC 5705,
/// RFC 8446 Section 7.5); `false` while the handshake is incomplete, or if
/// the carrier cannot export.
pub type ExportFn = dyn Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync;

/// What a TLS (or QUIC) handshake this process ran negotiated. It answers
/// only whether TLS ends in this process, as an entrance's test; it is no
/// proof of an end-to-end handshake (it holds as well when an intermediary
/// reaches this process over TLS of its own): exporters come from
/// [`CarrierExporter`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsState {
    /// The application protocol negotiated.
    pub alpn: Option<Vec<u8>>,
    /// The server name of the handshake.
    pub server_name: Option<String>,
}

impl TlsState {
    /// The state of a handshake with these results.
    pub fn new(alpn: Option<Vec<u8>>, server_name: Option<String>) -> Self {
        Self { alpn, server_name }
    }
}

/// Why a session's exporter gave the host no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportError {
    /// The bootstrap carrier has no exporter.
    NoExporter,
    /// The label starts with [`RESERVED_EXPORTER_PREFIX`].
    ReservedLabel,
    /// The carrier gave no value: its handshake is incomplete, or its
    /// connection is gone.
    Unavailable,
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoExporter => "the carrier has no exporter",
            Self::ReservedLabel => "the exporter label is reserved",
            Self::Unavailable => "the carrier gave no exporter value",
        })
    }
}

impl std::error::Error for ExportError {}

/// A carrier's exporter; for a split bootstrap, those of its two halves
/// ([`Self::split`]).
#[derive(Clone)]
pub struct CarrierExporter {
    first: Arc<ExportFn>,
    second: Option<Arc<ExportFn>>,
}

impl fmt::Debug for CarrierExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CarrierExporter")
            .field("split", &self.second.is_some())
            .finish()
    }
}

impl CarrierExporter {
    /// The exporter of one connection.
    pub fn new(export: impl Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync + 'static) -> Self {
        Self {
            first: Arc::new(export),
            second: None,
        }
    }

    /// The exporter of a split bootstrap with an exporter on both halves.
    /// Halves of one connection give that connection's value; two
    /// connections give the uplink's followed by the downlink's, twice the
    /// length. (A split bootstrap with an exporter on one half uses that
    /// half's exporter alone.)
    #[must_use]
    pub fn split(up: &Self, down: &Self) -> Self {
        Self {
            first: up.first.clone(),
            second: Some(down.first.clone()),
        }
    }

    /// `length` bytes for `label` and `context`, twice that for a split
    /// exporter on two connections; `None` while the handshake is
    /// incomplete or once the connection is gone.
    pub fn export(&self, label: &str, context: &[u8], length: usize) -> Option<Vec<u8>> {
        let mut out = vec![0; length];
        if !(self.first)(label, context, &mut out) {
            return None;
        }
        if let Some(second) = &self.second {
            let mut other = vec![0; length];
            if !second(label, context, &mut other) {
                return None;
            }
            if other != out {
                out.extend_from_slice(&other);
            }
        }
        Some(out)
    }

    /// What the host's own label gives from a session's exporter, if it
    /// has one: labels of zmux are refused.
    pub fn export_for_host(
        exporter: Option<&Self>,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, ExportError> {
        if label.starts_with(RESERVED_EXPORTER_PREFIX) {
            return Err(ExportError::ReservedLabel);
        }
        exporter
            .ok_or(ExportError::NoExporter)?
            .export(label, context, length)
            .ok_or(ExportError::Unavailable)
    }

    /// The value of `EXPORTER-zmux-session`: the session secret's input,
    /// which a sans-IO host passes to
    /// [`SessionCore::set_bootstrap_exporter_value`](super::session::SessionCore::set_bootstrap_exporter_value).
    pub fn session_value(&self) -> Option<Vec<u8>> {
        self.export(EXPORTER_SESSION_LABEL, b"", VALUE_LEN)
    }

    /// The Binding of an Establish. `split` is a carrier of two halves,
    /// which needs the exporter of each.
    pub fn seal_binding(&self, split: bool) -> Option<Vec<u8>> {
        let read = |f: &Arc<ExportFn>| {
            let mut out = vec![0; VALUE_LEN];
            f(EXPORTER_SEAL_BOUND_LABEL, b"", &mut out).then_some(out)
        };
        let up = read(&self.first)?;
        let down = match (&self.second, split) {
            (Some(second), _) => read(second)?,
            (None, true) => return None,
            (None, false) => up.clone(),
        };
        super::seal::bound_exporter(Some(&up), Some(&down)).ok()
    }

    /// The value of `EXPORTER-zmux-join`: the Binding of a Bound Join, made on one connection.
    pub fn pipe_binding(&self) -> Option<Vec<u8>> {
        let mut out = vec![0; VALUE_LEN];
        (self.first)(EXPORTER_JOIN_LABEL, b"", &mut out).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(b: u8) -> CarrierExporter {
        CarrierExporter::new(move |_, _, out| {
            out.fill(b);
            true
        })
    }

    #[test]
    fn a_split_exporter_concatenates_only_two_connections() {
        let same = CarrierExporter::split(&fixed(1), &fixed(1));
        assert_eq!(same.session_value(), Some(vec![1; 32]));
        let two = CarrierExporter::split(&fixed(1), &fixed(2));
        let mut want = vec![1; 32];
        want.extend_from_slice(&[2; 32]);
        assert_eq!(two.session_value(), Some(want));
        // The Binding: one value, or the two by role; a half without one is no Binding.
        assert_eq!(same.seal_binding(true), Some(vec![1; 32]));
        let binding = two.seal_binding(true).unwrap();
        assert_eq!(binding.len(), 32);
        assert_ne!(binding, vec![1; 32]);
        assert_ne!(
            binding,
            CarrierExporter::split(&fixed(2), &fixed(1))
                .seal_binding(true)
                .unwrap()
        );
        assert_eq!(fixed(1).seal_binding(true), None);
        assert_eq!(fixed(1).seal_binding(false), Some(vec![1; 32]));
        let none = CarrierExporter::new(|_, _, _| false);
        assert_eq!(
            CarrierExporter::split(&fixed(1), &none).session_value(),
            None
        );
    }
}
