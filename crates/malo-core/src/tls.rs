//! rustls client configurations.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Standard verification against the Mozilla root store.
pub fn webpki_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Accepts any certificate. Only for explicitly flagged test servers.
pub fn insecure_config() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Verifier { pin: None }))
            .with_no_client_auth(),
    )
}

/// Accepts exactly the certificate whose SHA-256 fingerprint matches `pin` (TOFU pinning).
pub fn pinned_config(pin: &str) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Verifier {
                pin: Some(normalize_fingerprint(pin)),
            }))
            .with_no_client_auth(),
    )
}

/// `AB:CD:…` upper-case hex SHA-256 of a DER certificate.
pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn normalize_fingerprint(s: &str) -> String {
    let hex: String = s
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
    pin: Option<String>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match &self.pin {
            None => Ok(ServerCertVerified::assertion()),
            Some(pin) if *pin == fingerprint(end_entity.as_ref()) => {
                Ok(ServerCertVerified::assertion())
            }
            Some(_) => Err(rustls::Error::General(
                "certificate fingerprint does not match the pinned one".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fingerprint_normalization() {
        assert_eq!(super::normalize_fingerprint("ab:cd ef"), "AB:CD:EF");
        assert_eq!(super::normalize_fingerprint("ABCDEF"), "AB:CD:EF");
    }
}
