//! Self-signed certificate on first boot (or user-provided PEM files).

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::ServerConfig;

pub struct Tls {
    pub config: Arc<rustls::ServerConfig>,
    pub fingerprint: String,
}

fn load_pem(
    cert: &Path,
    key: &Path,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = rustls_pemfile_certs(
        &std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?,
    )?;
    let key_pem = std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
    use rustls::pki_types::pem::PemObject;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).context("parse private key")?;
    Ok((certs, key))
}

fn rustls_pemfile_certs(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .context("parse certificate")?;
    anyhow::ensure!(!certs.is_empty(), "no certificate in PEM");
    Ok(certs)
}

pub fn load_or_create(cfg: &ServerConfig) -> anyhow::Result<Tls> {
    let (cert_path, key_path) = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            let dir = cfg.data_dir.join("tls");
            std::fs::create_dir_all(&dir)?;
            let (c, k) = (dir.join("cert.pem"), dir.join("key.pem"));
            if !c.exists() || !k.exists() {
                let mut names = vec!["localhost".to_string(), "malo".to_string()];
                if let Ok(h) = std::env::var("MALO_TLS_HOSTNAMES") {
                    names.extend(
                        h.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    );
                }
                let mut params = rcgen::CertificateParams::new(names)?;
                params
                    .subject_alt_names
                    .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, "Malo backup server");
                params.not_after = rcgen::date_time_ymd(2099, 1, 1);
                let key = rcgen::KeyPair::generate()?;
                let cert = params.self_signed(&key)?;
                std::fs::write(&c, cert.pem())?;
                crate::keyring::write_atomic(&k, key.serialize_pem().as_bytes())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600))?;
                }
                tracing::info!(
                    "generated a self-signed TLS certificate in {}",
                    dir.display()
                );
            }
            (c, k)
        }
    };
    let (certs, key) = load_pem(&cert_path, &key_path)?;
    let fingerprint = malo_core::tls::fingerprint(certs[0].as_ref());
    let mut config = rustls::ServerConfig::builder_with_provider(malo_core::tls::provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Tls {
        config: Arc::new(config),
        fingerprint,
    })
}
