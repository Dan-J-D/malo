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

/// Accepts the server whose certificate, or the authority that issued it, has the SHA-256
/// fingerprint `pin` (TOFU pinning; see [`check_pin`]).
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

/// Whether a server's certificate matches a pin: the certificate itself (self-signed or
/// user-provided), or an authority in the chain the server sent that issued it (Malo's own
/// authority, which renews the server certificate without changing the pin). Names aren't
/// checked: the pin is the server's identity.
pub fn check_pin(
    pin: &str,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> Result<(), rustls::Error> {
    if fingerprint(end_entity.as_ref()) == pin {
        return Ok(());
    }
    let Some(ca) = intermediates
        .iter()
        .find(|c| fingerprint(c.as_ref()) == pin)
    else {
        return Err(rustls::Error::General(
            "certificate fingerprint does not match the pinned one".into(),
        ));
    };
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone().into_owned())?;
    let others: Vec<CertificateDer<'_>> =
        intermediates.iter().filter(|c| *c != ca).cloned().collect();
    let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
    rustls::client::verify_server_cert_signed_by_trust_anchor(
        &parsed,
        &roots,
        &others,
        now,
        provider().signature_verification_algorithms.all,
    )
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
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(pin) = &self.pin {
            check_pin(pin, end_entity, intermediates, now)?;
        }
        Ok(ServerCertVerified::assertion())
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
