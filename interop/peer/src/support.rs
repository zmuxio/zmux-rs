//! Shared transport and session settings for the interoperability peers.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{Config, PipeAuth, Session};

pub(crate) fn config(multipath: bool) -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c.max_incoming_uni_streams = zmux::UniCredit::Limit(16);
    if multipath {
        c.session_policy.limits.steady_attachments = 4;
        c.pipe_auth = PipeAuth::psk(b"zmux interop pre-shared key 0123".to_vec()).with_end_to_end();
        c.allow_record_mode = Some(zmux::proto::session::AllowRecordMode::new(|_, _, _| true));
    }
    c
}

pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A self-signed certificate for `localhost`, offering `alpn`.
pub(crate) fn tls_server_config(alpn: &[&[u8]]) -> rustls::ServerConfig {
    let cert = zmux_testcert::self_signed(vec!["localhost".into()]).expect("cert");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls")
        .with_no_client_auth()
        .with_single_cert(vec![der], PrivateKeyDer::Pkcs8(key))
        .expect("tls");
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tls
}

/// TLS 1.3 to a self-signed peer, unverified, offering `alpn`.
pub(crate) fn tls_client_config(alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tls
}

/// Accepts the server's certificate unverified: a self-signed one of a
/// local test.
#[derive(Debug)]
pub(crate) struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut out, x| {
            let _ = write!(out, "{x:02x}");
            out
        })
}

pub(crate) async fn join_carrier(
    session: &Session,
    carrier: zmux::PipeIo,
    mode: zmux::RecordMode,
) -> Result<(), String> {
    use zmux::{
        AttachmentSpec, AttemptReason, CarrierOpener, ChangeRequest, Directions, MemberSpec,
        PipeOptions,
    };
    let mut request = ChangeRequest::new(session.capacity(), Duration::from_secs(30));
    request.add.push(MemberSpec {
        candidate: None,
        attachments: vec![AttachmentSpec::new(
            Directions::BOTH,
            PipeOptions::default().with_record_mode(mode),
        )],
    });
    let change = session
        .begin_change(request)
        .map_err(|error| error.to_string())?;
    let attempt = change
        .start_member(0, CarrierOpener::prepared(vec![carrier]))
        .map_err(|error| error.to_string())?;
    let result = attempt.wait().await;
    if result.reason != AttemptReason::Confirmed {
        return Err(format!(
            "join ended: {:?}: {:?}",
            result.reason, result.error
        ));
    }
    change.commit().map_err(|error| error.to_string())?;
    Ok(())
}
