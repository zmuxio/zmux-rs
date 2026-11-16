//! The keying material exporter of a carrier: the one source of the
//! exporter of the innermost end-to-end handshake. It is read when a
//! value is needed, never when the carrier is made: the handshake may
//! complete later (early data).

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::seal::{Secret, ct_eq};

use super::keys::{
    EXPORTER_JOIN_LABEL, EXPORTER_SEAL_BOUND_LABEL, EXPORTER_SESSION_LABEL,
    PREFIX_AUTH_EXPORTER_LABEL,
};

/// Labels starting with this key zmux's own joins:
/// [`CarrierExporter::export_for_host`] refuses them.
pub const RESERVED_EXPORTER_PREFIX: &str = "EXPORTER-zmux-";

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
    #[must_use]
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

/// What an asynchronous exporter ([`CarrierExporter::new_async`]) is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportRequest {
    /// The label.
    pub label: String,
    /// The context.
    pub context: Vec<u8>,
    /// The length of the value.
    pub length: usize,
}

/// The future of an asynchronous exporter.
pub type ExportFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send>>;

/// The callable behind an asynchronous exporter.
pub type AsyncExportFn = dyn Fn(ExportRequest) -> ExportFuture + Send + Sync;

/// The labels zmux reads, each with an empty context and [`VALUE_LEN`] bytes.
const ZMUX_LABELS: [&str; 4] = [
    EXPORTER_SESSION_LABEL,
    EXPORTER_JOIN_LABEL,
    EXPORTER_SEAL_BOUND_LABEL,
    PREFIX_AUTH_EXPORTER_LABEL,
];

/// One connection's exporter.
#[derive(Clone)]
enum Source {
    /// Answers in the call, from any thread.
    Now(Arc<ExportFn>),
    /// Answers later; the values zmux reads are fetched once
    /// ([`CarrierExporter::resolve`]) and answered from then on.
    Later {
        export: Arc<AsyncExportFn>,
        values: Arc<std::sync::Mutex<[Option<Secret>; ZMUX_LABELS.len()]>>,
    },
}

impl Source {
    fn fill(&self, label: &str, context: &[u8], out: &mut [u8]) -> bool {
        match self {
            Self::Now(f) => f(label, context, out),
            Self::Later { values, .. } => {
                if !context.is_empty() || out.len() != VALUE_LEN {
                    return false;
                }
                let Some(i) = ZMUX_LABELS.iter().position(|l| *l == label) else {
                    return false;
                };
                let values = values
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                values[i].as_deref().is_some_and(|v| {
                    out.copy_from_slice(v);
                    true
                })
            }
        }
    }

    async fn ask(&self, label: &str, context: &[u8], length: usize) -> Option<Vec<u8>> {
        match self {
            Self::Now(f) => {
                let mut out = vec![0; length];
                f(label, context, &mut out).then_some(out)
            }
            Self::Later { export, .. } => {
                let request = ExportRequest {
                    label: label.to_owned(),
                    context: context.to_vec(),
                    length,
                };
                let later = crate::proto::Decision::catch(|| {
                    crate::proto::Decision::Later(export(request))
                })?;
                let v = later.settle().await?.ok()?;
                (v.len() == length).then_some(v)
            }
        }
    }

    async fn resolve(&self) {
        let Self::Later { values, .. } = self else {
            return;
        };
        for (i, label) in ZMUX_LABELS.iter().enumerate() {
            let known = values
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[i]
                .is_some();
            if !known && let Some(v) = self.ask(label, b"", VALUE_LEN).await {
                values
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)[i] = Some(Secret::from(v));
            }
        }
    }
}

/// A carrier's exporter; for a split bootstrap, those of its two halves
/// ([`Self::split`]). Cheap to clone and callable from any thread.
#[derive(Clone)]
pub struct CarrierExporter {
    first: Source,
    second: Option<Source>,
}

impl fmt::Debug for CarrierExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CarrierExporter")
            .field("split", &self.second.is_some())
            .field("later", &matches!(self.first, Source::Later { .. }))
            .finish_non_exhaustive()
    }
}

impl CarrierExporter {
    /// The exporter of one connection, answering in the call.
    pub fn new(export: impl Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync + 'static) -> Self {
        Self {
            first: Source::Now(Arc::new(export)),
            second: None,
        }
    }

    /// The exporter of one connection whose values come later (from
    /// another thread, a language binding): `export` returns the value's
    /// future, an error while the handshake is incomplete or once the
    /// connection is gone. The values zmux itself reads are fetched once,
    /// outside every lock, by [`Self::resolve`], which the drivers await
    /// before a carrier's session, join or Establish needs them; until then
    /// the synchronous reads give nothing. Other labels are read with
    /// [`Self::export_async`].
    pub fn new_async<F>(export: impl Fn(ExportRequest) -> F + Send + Sync + 'static) -> Self
    where
        F: Future<Output = std::io::Result<Vec<u8>>> + Send + 'static,
    {
        Self {
            first: Source::Later {
                export: Arc::new(move |r| Box::pin(export(r))),
                values: Arc::default(),
            },
            second: None,
        }
    }

    /// An exporter holding the values zmux reads (its joins, an
    /// Establish's Binding, prefix authentication), read now from `export`,
    /// and no other: for metadata of a connection borrowed only for the
    /// call (an admission's [`CarrierInfo`](crate::CarrierInfo) of a TLS
    /// stream it does not own). Other labels give nothing.
    pub fn snapshot(export: impl Fn(&str, &[u8], &mut [u8]) -> bool) -> Self {
        let mut values: [Option<Secret>; ZMUX_LABELS.len()] = Default::default();
        for (v, label) in values.iter_mut().zip(ZMUX_LABELS) {
            let mut out = Secret::from(vec![0; VALUE_LEN]);
            *v = export(label, b"", out.as_mut_slice()).then_some(out);
        }
        Self {
            first: Source::Later {
                export: Arc::new(|_| {
                    Box::pin(std::future::ready(Err(
                        std::io::ErrorKind::Unsupported.into()
                    )))
                }),
                values: Arc::new(std::sync::Mutex::new(values)),
            },
            second: None,
        }
    }

    /// Fetches the values zmux reads from an exporter whose values come
    /// later; nothing for one that answers in the call. Cancel-safe: the
    /// values fetched stay.
    pub fn resolve(&self) -> impl Future<Output = ()> + Send + 'static {
        let this = self.clone();
        async move {
            this.first.resolve().await;
            if let Some(s) = &this.second {
                s.resolve().await;
            }
        }
    }

    /// Whether the values zmux reads are answered without waiting.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        let done = |s: &Source| match s {
            Source::Now(_) => true,
            Source::Later { values, .. } => values
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .all(Option::is_some),
        };
        done(&self.first) && self.second.as_ref().is_none_or(done)
    }

    /// [`Self::export`] for any label, waiting for an exporter whose
    /// values come later.
    pub fn export_async(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send + 'static {
        let this = self.clone();
        let (label, context) = (label.to_owned(), context.to_vec());
        async move {
            let mut out = this.first.ask(&label, &context, length).await?;
            if let Some(second) = &this.second {
                let other = Secret::from(second.ask(&label, &context, length).await?);
                if !ct_eq(&other, &out) {
                    out.extend_from_slice(&other);
                }
            }
            Some(out)
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
    #[must_use]
    pub fn export(&self, label: &str, context: &[u8], length: usize) -> Option<Vec<u8>> {
        let mut out = vec![0; length];
        if !self.first.fill(label, context, &mut out) {
            return None;
        }
        if let Some(second) = &self.second {
            // Keying material dropped here is cleared.
            let mut other = Secret::from(vec![0; length]);
            if !second.fill(label, context, other.as_mut_slice()) {
                return None;
            }
            if !ct_eq(&other, &out) {
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
    #[must_use]
    pub fn session_value(&self) -> Option<Vec<u8>> {
        self.export(EXPORTER_SESSION_LABEL, b"", VALUE_LEN)
    }

    /// The Binding of an Establish. `split` is a carrier of two halves,
    /// which needs the exporter of each.
    #[must_use]
    pub fn seal_binding(&self, split: bool) -> Option<Vec<u8>> {
        let read = |f: &Source| {
            let mut out = super::seal::Secret::from(vec![0; VALUE_LEN]);
            f.fill(EXPORTER_SEAL_BOUND_LABEL, b"", out.as_mut_slice())
                .then_some(out)
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
    #[must_use]
    pub fn pipe_binding(&self) -> Option<Vec<u8>> {
        let mut out = vec![0; VALUE_LEN];
        self.first
            .fill(EXPORTER_JOIN_LABEL, b"", &mut out)
            .then_some(out)
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
