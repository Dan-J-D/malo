//! TLS for the API and the mail services: user-provided PEM files, or certificates from Malo's own
//! certificate authority.
//!
//! The authority is created once, in `<data>/tls`, and is what devices install to trust this
//! server (phones for mail apps; the Malo app pins it). It may only vouch for this server's names
//! (name constraints), so a device that trusts it can't be fooled about any other site. The
//! server certificate it issues follows Apple's rules for trusted certificates (at most 397 days,
//! server-auth usage, every name as a SAN) and is renewed while the server runs. Names come from
//! `MALO_TLS_HOSTNAMES`; a name the authority doesn't cover gets a new authority, to be installed
//! again.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints, SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};

use crate::config::ServerConfig;

/// Lifetime of a server certificate (Apple accepts at most 398 days for some uses, 825 for all).
const CERT_DAYS: i64 = 397;
/// A certificate is renewed when it has less than this left.
const RENEW_BEFORE_DAYS: i64 = 30;
const RENEW_CHECK: Duration = Duration::from_secs(6 * 3600);
/// Always in the certificate: how the Malo app reaches a bundled or local server.
const BASE_NAMES: [&str; 4] = ["localhost", "malo", "127.0.0.1", "::1"];

pub struct Tls {
    pub config: Arc<rustls::ServerConfig>,
    /// What clients pin: the authority's fingerprint, or the certificate's for user-provided files.
    pub fingerprint: String,
    /// Malo's own authority (DER) and the names its certificate covers; None with user files.
    pub ca: Option<CaInfo>,
}

#[derive(Debug, Clone)]
pub struct CaInfo {
    pub der: Vec<u8>,
    pub names: Vec<String>,
}

/// Hands out the current certificate, so a renewal applies to new connections right away.
#[derive(Debug)]
struct Resolver(RwLock<Arc<CertifiedKey>>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().unwrap().clone())
    }
}

/// What was issued, next to the files.
#[derive(Serialize, Deserialize, Default)]
struct Issued {
    /// Shown in the authority's name, to tell several Malo servers apart on a phone.
    ca_id: String,
    /// The names the authority may vouch for.
    ca_names: Vec<String>,
    /// The names of the current certificate and when it expires (unix seconds).
    names: Vec<String>,
    not_after: i64,
}

struct Paths {
    ca: PathBuf,
    ca_key: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    issued: PathBuf,
}

impl Paths {
    fn new(dir: &Path) -> Paths {
        Paths {
            ca: dir.join("ca.pem"),
            ca_key: dir.join("ca-key.pem"),
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
            issued: dir.join("issued.json"),
        }
    }
}

pub fn load_or_create(cfg: &ServerConfig) -> anyhow::Result<Tls> {
    if let (Some(c), Some(k)) = (&cfg.tls_cert, &cfg.tls_key) {
        let key = certified(&std::fs::read(c)?, &std::fs::read(k)?)
            .with_context(|| format!("TLS files {} and {}", c.display(), k.display()))?;
        let fingerprint = malo_core::tls::fingerprint(key.cert[0].as_ref());
        return Ok(Tls {
            config: server_config(Arc::new(Resolver(RwLock::new(key))))?,
            fingerprint,
            ca: None,
        });
    }
    let dir = cfg.data_dir.join("tls");
    std::fs::create_dir_all(&dir)?;
    let paths = Paths::new(&dir);
    let names = wanted_names();
    let (issued, ca_pem) = ensure(&paths, &names)?;
    let key = certified(&std::fs::read(&paths.cert)?, &std::fs::read(&paths.key)?)?;
    let ca_der = CertificateDer::from_pem_slice(ca_pem.as_bytes())
        .context("parse the authority's certificate")?
        .to_vec();
    let fingerprint = malo_core::tls::fingerprint(&ca_der);
    let resolver = Arc::new(Resolver(RwLock::new(key)));
    tracing::info!(
        "TLS: Malo's certificate authority (SHA-256 {fingerprint}) issues the certificate for {}, valid until {}",
        issued.names.join(", "),
        date(issued.not_after),
    );
    if std::env::var("MALO_TLS_HOSTNAMES").is_err() {
        tracing::info!(
            "TLS: set MALO_TLS_HOSTNAMES to the names or addresses mail apps and browsers use for this server, or they'll refuse its certificate"
        );
    }
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(renew(paths, names, Arc::downgrade(&resolver)));
    }
    Ok(Tls {
        config: server_config(resolver)?,
        fingerprint,
        ca: Some(CaInfo {
            der: ca_der,
            names: issued.names,
        }),
    })
}

fn server_config(resolver: Arc<Resolver>) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let mut config = rustls::ServerConfig::builder_with_provider(malo_core::tls::provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn certified(chain_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Arc<CertifiedKey>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<_, _>>()
        .context("parse certificate")?;
    anyhow::ensure!(!certs.is_empty(), "no certificate in PEM");
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("parse private key")?;
    let signing = malo_core::tls::provider()
        .key_provider
        .load_private_key(key)
        .context("load private key")?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

/// The certificate's names: the fixed ones and `MALO_TLS_HOSTNAMES` (lower case, no repeats).
fn wanted_names() -> Vec<String> {
    let extra = std::env::var("MALO_TLS_HOSTNAMES").unwrap_or_default();
    let mut names: Vec<String> = vec![];
    for n in BASE_NAMES
        .iter()
        .map(|s| s.to_string())
        .chain(extra.split(',').map(|s| s.trim().to_lowercase()))
    {
        if !n.is_empty() && !names.contains(&n) {
            names.push(n);
        }
    }
    names
}

/// Makes sure there's an authority covering `names` and a current certificate for exactly
/// `names`; returns what was issued and the authority's PEM.
fn ensure(p: &Paths, names: &[String]) -> anyhow::Result<(Issued, String)> {
    let mut issued: Issued = std::fs::read(&p.issued)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let have_ca = p.ca.exists() && p.ca_key.exists() && !issued.ca_id.is_empty();
    let covered = names.iter().all(|n| issued.ca_names.contains(n));
    if !have_ca || !covered {
        if have_ca {
            tracing::warn!(
                "TLS: the certificate authority doesn't cover {}; created a new one. Install it again on devices that trust this server",
                names
                    .iter()
                    .filter(|n| !issued.ca_names.contains(n))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        } else if p.cert.exists() {
            tracing::warn!(
                "TLS: replaced the self-signed certificate with one from Malo's own certificate authority; the Malo app asks once to confirm the new fingerprint"
            );
        }
        let id: [u8; 4] = rand::random();
        issued = Issued {
            ca_id: id.iter().map(|b| format!("{b:02x}")).collect(),
            ca_names: names.to_vec(),
            ..Issued::default()
        };
        let key = KeyPair::generate()?;
        let ca = ca_params(&issued)?.self_signed(&key)?;
        std::fs::write(&p.ca, ca.pem())?;
        write_key(&p.ca_key, &key.serialize_pem())?;
        tracing::info!(
            "TLS: created Malo's certificate authority in {}",
            p.ca.display()
        );
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let due = issued.not_after - now < RENEW_BEFORE_DAYS * 86_400;
    if !p.cert.exists() || !p.key.exists() || issued.names != names || due {
        issue(p, &mut issued, names)?;
    }
    Ok((issued, std::fs::read_to_string(&p.ca)?))
}

fn ca_params(issued: &Issued) -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(
        DnType::CommonName,
        format!("Malo certificate authority {}", issued.ca_id),
    );
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Malo");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: issued.ca_names.iter().map(|n| subtree(n)).collect(),
        excluded_subtrees: vec![],
    });
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    Ok(params)
}

fn subtree(name: &str) -> GeneralSubtree {
    match name.parse::<IpAddr>() {
        Ok(ip @ IpAddr::V4(_)) => GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(ip, 32)),
        Ok(ip @ IpAddr::V6(_)) => GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(ip, 128)),
        Err(_) => GeneralSubtree::DnsName(name.to_string()),
    }
}

/// Issues a certificate for `names` from the authority on disk and records it.
fn issue(p: &Paths, issued: &mut Issued, names: &[String]) -> anyhow::Result<()> {
    let ca_key = KeyPair::from_pem(&std::fs::read_to_string(&p.ca_key)?)
        .context("load the authority's key")?;
    // Signing needs the authority's name and key, which these parameters reproduce.
    let ca = ca_params(issued)?.self_signed(&ca_key)?;
    let mut params = CertificateParams::new(names.to_vec())?;
    let shown = names
        .iter()
        .rev()
        .find(|n| !BASE_NAMES.contains(&n.as_str()))
        .map(String::as_str)
        .unwrap_or("Malo backup server");
    params.distinguished_name.push(DnType::CommonName, shown);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let mut serial: [u8; 16] = rand::random();
    serial[0] &= 0x7f;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(CERT_DAYS - 1);
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &ca, &ca_key)?;
    // The chain: the certificate, then the authority (clients that pin it find it there).
    let chain = format!("{}{}", cert.pem(), std::fs::read_to_string(&p.ca)?);
    write_key(&p.key, &key.serialize_pem())?;
    std::fs::write(&p.cert, chain)?;
    issued.names = names.to_vec();
    issued.not_after = (now + time::Duration::days(CERT_DAYS - 1)).unix_timestamp();
    crate::keyring::write_atomic(&p.issued, &serde_json::to_vec_pretty(issued)?)?;
    tracing::info!(
        "TLS: issued a certificate for {}, valid until {}",
        names.join(", "),
        date(issued.not_after)
    );
    Ok(())
}

fn write_key(path: &Path, pem: &str) -> anyhow::Result<()> {
    crate::keyring::write_atomic(path, pem.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn date(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|d| d.date().to_string())
        .unwrap_or_default()
}

/// Renews the certificate before it expires, for as long as the server uses it.
async fn renew(p: Paths, names: Vec<String>, resolver: std::sync::Weak<Resolver>) {
    loop {
        tokio::time::sleep(RENEW_CHECK).await;
        let Some(resolver) = resolver.upgrade() else {
            return;
        };
        let renewed = tokio::task::spawn_blocking({
            let names = names.clone();
            let p = Paths {
                ca: p.ca.clone(),
                ca_key: p.ca_key.clone(),
                cert: p.cert.clone(),
                key: p.key.clone(),
                issued: p.issued.clone(),
            };
            move || -> anyhow::Result<Arc<CertifiedKey>> {
                ensure(&p, &names)?;
                certified(&std::fs::read(&p.cert)?, &std::fs::read(&p.key)?)
            }
        })
        .await;
        match renewed {
            Ok(Ok(key)) => {
                let mut current = resolver.0.write().unwrap();
                if current.cert[0] != key.cert[0] {
                    *current = key;
                }
            }
            Ok(Err(e)) => tracing::warn!("TLS: renewing the certificate: {e:#}"),
            Err(e) => tracing::warn!("TLS: renewing the certificate: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{ServerName, UnixTime};

    fn issued_in(dir: &Path, names: &[&str]) -> (Issued, String) {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        ensure(&Paths::new(dir), &names).unwrap()
    }

    fn chain(dir: &Path) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_file_iter(dir.join("cert.pem"))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn authority_issues_renewable_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let (issued, ca_pem) = issued_in(dir.path(), &["localhost", "10.0.0.1"]);
        let ca = CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap();
        let pin = malo_core::tls::fingerprint(&ca);
        let certs = chain(dir.path());
        assert_eq!(certs.len(), 2, "certificate, then the authority");
        assert_eq!(certs[1], ca);
        let now = UnixTime::now();
        // The pinned authority vouches for the certificate, and a browser-style check accepts
        // it for its names (and only those).
        malo_core::tls::check_pin(&pin, &certs[0], &certs[1..], now).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let parsed = rustls::server::ParsedCertificate::try_from(&certs[0]).unwrap();
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &roots,
            &[],
            now,
            malo_core::tls::provider()
                .signature_verification_algorithms
                .all,
        )
        .unwrap();
        for ok in ["10.0.0.1", "localhost"] {
            let name = ServerName::try_from(ok).unwrap();
            rustls::client::verify_server_name(&parsed, &name).unwrap();
        }
        let other = ServerName::try_from("example.com").unwrap();
        assert!(rustls::client::verify_server_name(&parsed, &other).is_err());
        let days = (issued.not_after - time::OffsetDateTime::now_utc().unix_timestamp()) / 86_400;
        assert!((CERT_DAYS - 3..CERT_DAYS).contains(&days), "{days}");

        // Nothing changes on the next start; a new certificate when it's due, same authority.
        let first = certs[0].clone();
        issued_in(dir.path(), &["localhost", "10.0.0.1"]);
        assert_eq!(chain(dir.path())[0], first);
        let mut due: Issued =
            serde_json::from_slice(&std::fs::read(dir.path().join("issued.json")).unwrap())
                .unwrap();
        due.not_after = time::OffsetDateTime::now_utc().unix_timestamp() + 86_400;
        std::fs::write(
            dir.path().join("issued.json"),
            serde_json::to_vec(&due).unwrap(),
        )
        .unwrap();
        let (_, same_ca) = issued_in(dir.path(), &["localhost", "10.0.0.1"]);
        assert_eq!(same_ca, ca_pem);
        let renewed = chain(dir.path());
        assert_ne!(renewed[0], first);
        malo_core::tls::check_pin(&pin, &renewed[0], &renewed[1..], now).unwrap();

        // A name the authority doesn't cover needs a new authority.
        let (_, new_ca) = issued_in(dir.path(), &["localhost", "10.0.0.1", "mail.example.org"]);
        assert_ne!(new_ca, ca_pem);
        let moved = chain(dir.path());
        assert!(malo_core::tls::check_pin(&pin, &moved[0], &moved[1..], now).is_err());
    }

    #[test]
    fn authority_is_limited_to_its_names() {
        // A certificate for another name, signed by the authority's key, isn't accepted by
        // clients that trust the authority.
        let dir = tempfile::tempdir().unwrap();
        let (issued, ca_pem) = issued_in(dir.path(), &["localhost"]);
        let ca_key =
            KeyPair::from_pem(&std::fs::read_to_string(dir.path().join("ca-key.pem")).unwrap())
                .unwrap();
        let ca = ca_params(&issued).unwrap().self_signed(&ca_key).unwrap();
        let mut params = CertificateParams::new(vec!["bank.example.com".to_string()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let forged = params.signed_by(&key, &ca, &ca_key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
            .unwrap();
        let der = CertificateDer::from(forged.der().to_vec());
        let parsed = rustls::server::ParsedCertificate::try_from(&der).unwrap();
        assert!(rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &roots,
            &[],
            UnixTime::now(),
            malo_core::tls::provider()
                .signature_verification_algorithms
                .all,
        )
        .is_err());
    }
}
