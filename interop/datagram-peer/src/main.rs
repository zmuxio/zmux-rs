//! A zmux peer over QUIC for the interoperability tests of the datagram
//! channel, with the other implementations (Go, Java).
//!
//! ```text
//! zmux-datagram-peer server <cert.pem> <key.pem>   listen, print `LISTEN <addr>`,
//!                                                  echo every session datagram and stream
//! zmux-datagram-peer client <addr> <n>             dial, send n datagrams (100 bytes,
//!                                                  the index first), expect each echoed
//! ```
//!
//! ALPN `qmux-02`; the client skips certificate verification (test peers).
//! Both modes print `STATS sent=<n> sentch=<n> recv=<n> recvch=<n>` (session
//! datagrams sent and received, and those that used the QUIC datagram
//! channel) when the session ends: a peer that supports the channel has
//! `sentch` and `recvch` above zero. A 60-second deadline ends the process.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use zmux::{Config, Listener, ListenerConfig, Session};
use zmux_quinn::Options;

const ALPN: &[u8] = b"qmux-02";

fn cfg() -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c
}

fn stats(s: &Session) {
    let s = s.stats();
    println!(
        "STATS sent={} sentch={} recv={} recvch={}",
        s.datagrams_sent,
        s.datagrams_sent_channel,
        s.datagrams_received,
        s.datagrams_received_channel
    );
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[tokio::main]
async fn main() {
    tokio::time::timeout(Duration::from_secs(60), run())
        .await
        .expect("deadline");
}

async fn run() {
    let args: Vec<String> = std::env::args().collect();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // aws-lc parses PKCS#8 EC keys without the embedded public key, as Java writes them.
    let server_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let opts = Options::default();
    match args[1].as_str() {
        "server" => {
            let certs: Vec<_> = CertificateDer::pem_file_iter(&args[2])
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let key = PrivateKeyDer::from_pem_file(&args[3]).unwrap();
            let mut tls = rustls::ServerConfig::builder_with_provider(server_provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            tls.alpn_protocols = vec![ALPN.to_vec()];
            let sc = zmux_quinn::server_config(tls, &opts).unwrap();
            let ep = quinn::Endpoint::server(sc, "127.0.0.1:0".parse().unwrap()).unwrap();
            println!("LISTEN {}", ep.local_addr().unwrap());
            let listener = Listener::new(cfg(), ListenerConfig::default())
                .expect("valid listener configuration");
            tokio::spawn(zmux_quinn::serve(listener.clone(), ep, opts, None));
            let s = listener.accept().await.expect("a session");
            {
                let s = s.clone();
                tokio::spawn(async move {
                    while let Ok((mut tx, mut rx)) = s.accept_bi().await {
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 16384];
                            while let Ok(Some(n)) = rx.read(&mut buf).await {
                                if tx.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                            let _ = tx.finish();
                        });
                    }
                });
            }
            while let Ok(d) = s.read_datagram().await {
                let _ = s.send_datagram(d);
            }
            stats(&s);
        }
        "client" => {
            let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
                .with_no_client_auth();
            tls.alpn_protocols = vec![ALPN.to_vec()];
            let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            ep.set_default_client_config(zmux_quinn::client_config(tls, &opts).unwrap());
            let addr: SocketAddr = args[2].parse().unwrap();
            let n: u32 = args[3].parse().unwrap();
            let s = zmux_quinn::connect(&ep, addr, "localhost", &opts, cfg())
                .await
                .unwrap();
            for i in 0..n {
                let mut d = i.to_be_bytes().to_vec();
                d.resize(100, 0);
                s.send_datagram(Bytes::from(d.clone())).unwrap();
                let e = tokio::time::timeout(Duration::from_secs(5), s.read_datagram())
                    .await
                    .expect("echo timeout")
                    .unwrap();
                assert_eq!(&e[..], &d[..], "echo {i}");
            }
            stats(&s);
            let _ = tokio::time::timeout(Duration::from_secs(2), s.close()).await;
            drop(s);
            ep.wait_idle().await;
        }
        m => panic!("mode {m}"),
    }
}
