//! What the WebSocket and the HTTP peer share: the session script.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use zmux::{
    Listener, MemoryPrefixStore, PrefixAuth, PrefixAuthVerifier, PrefixBinding, PrefixGeneration,
    PrefixRejection, PrefixStore, PrefixTicket, PrefixWindow, Session,
};

fn fixture(key: &[u8]) -> (PrefixTicket, PrefixGeneration) {
    let digest = |label: &[u8]| -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(label);
        hash.update(key);
        hash.finalize().into()
    };
    let id = *digest(b"interop ticket id ").first_chunk().unwrap();
    let ticket = PrefixTicket::new(id, digest(b"interop ticket key "), 0, 0..=u64::MAX, false);
    let generation = PrefixGeneration::new(digest(b"interop outer key "), 0..=u64::MAX);
    (ticket, generation)
}

/// The scripted client's reusable unbound ticket.
///
/// # Panics
///
/// If the fixture schedule or slot length is invalid.
#[must_use]
pub fn auth(key: &[u8]) -> PrefixAuth {
    let (ticket, generation) = fixture(key);
    let schedule = Arc::new(zmux::PrefixSchedule::new(1, vec![generation]).unwrap());
    PrefixAuth::new(ticket, schedule, 30, PrefixBinding::AllowCleartext).unwrap()
}

/// A listener that admits the scripted client's test ticket.
///
/// # Panics
///
/// If the fixture's ticket configuration is invalid.
#[must_use]
pub fn listener(key: &[u8], fallback: Option<zmux::Fallback>) -> Listener {
    let (ticket, generation) = fixture(key);
    let window = PrefixWindow::new(30, 1, 2).unwrap();
    let store = Arc::new(MemoryPrefixStore::new(window, vec![generation], 0).unwrap());
    store.add_ticket(ticket).unwrap();
    debug_assert_eq!(store.window(), window);
    let verifier = Arc::new(PrefixAuthVerifier::new(store, PrefixBinding::AllowCleartext).unwrap());
    let mut limits = zmux::ListenerConfig::default();
    limits.admission = Some(zmux::Admission::prefix_auth(
        verifier,
        PrefixRejection::Fallback,
    ));
    limits.fallback = fallback;
    Listener::new(zmux::Config::default(), limits).expect("valid listener configuration")
}

/// Echoes one stream of `session`, printing `SESSION <content>`.
pub async fn echo_one(session: Session) {
    let Ok((mut send, mut recv)) = session.accept_bi().await else {
        return;
    };
    let Ok(data) = recv.read_to_end(1 << 20).await else {
        return;
    };
    println!("SESSION {}", String::from_utf8_lossy(&data));
    if send.write_all(&data).await.is_ok() {
        let _ = send.finish();
    }
    // The client closes after reading the echo.
    let _ = tokio::time::timeout(Duration::from_secs(10), session.closed()).await;
}

/// Serves every session of `listener` until the process is killed.
pub async fn serve_sessions(listener: Listener) {
    while let Some(session) = listener.accept().await {
        tokio::spawn(echo_one(session));
    }
}

/// Sends `ping` on a stream of `session` and reads the echo.
///
/// # Errors
///
/// The failed step's error, as text.
pub async fn ping(session: &Session) -> Result<String, String> {
    let (mut send, mut recv) = session.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(b"ping").await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let got = recv.read_to_end(1 << 16).await.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&got).into_owned())
}

/// Makes the scripted server's TLS 1.3 acceptor with a temporary certificate.
///
/// # Panics
///
/// If the certificate or TLS configuration cannot be generated.
#[must_use]
pub fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let cert = zmux_testcert::self_signed(vec!["localhost".into(), "127.0.0.1".into()])
        .expect("certificate");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(vec![der], key)
    .expect("certificate");
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(server))
}

// Accepts any server certificate: the peers' certificates are generated at start.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Makes the scripted client connector for the peers' ephemeral certificates.
///
/// # Panics
///
/// If TLS 1.3 cannot be configured.
#[must_use]
pub fn tls_connector(alpn: &[u8]) -> tokio_rustls::TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    c.alpn_protocols = vec![alpn.to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(c))
}
