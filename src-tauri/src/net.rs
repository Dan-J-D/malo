//! HTTP/WS clients that trust exactly one server certificate (TOFU pin) or the Web PKI.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn normalize(fp: &str) -> String {
    let hex: String = fp
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    hex.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Debug)]
struct Verifier {
    /// None: record only (probe). Some: require this fingerprint.
    pin: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity.as_ref());
        *self.seen.lock().unwrap() = Some(fp.clone());
        match &self.pin {
            Some(pin) if *pin != fp => Err(rustls::Error::General(format!(
                "server certificate changed (expected {pin}, got {fp}) — refusing to connect"
            ))),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn builder() -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
}

/// Pinned (`Some(fp)`) or Web PKI (`None`) TLS configuration.
pub fn tls_config(pin: Option<&str>) -> Arc<ClientConfig> {
    match pin {
        Some(fp) => Arc::new(
            builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Verifier {
                    pin: Some(normalize(fp)),
                    seen: Default::default(),
                }))
                .with_no_client_auth(),
        ),
        None => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        }
    }
}

/// Accepts any certificate but records its fingerprint (first contact, shown to the user to confirm).
pub fn probe_config() -> (Arc<ClientConfig>, Arc<Mutex<Option<String>>>) {
    let seen = Arc::new(Mutex::new(None));
    let cfg = builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier {
            pin: None,
            seen: seen.clone(),
        }))
        .with_no_client_auth();
    (Arc::new(cfg), seen)
}

pub fn http_client(tls: Arc<ClientConfig>) -> reqwest::Client {
    reqwest::Client::builder()
        .use_preconfigured_tls((*tls).clone())
        .timeout(std::time::Duration::from_secs(300))
        .connect_timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}
