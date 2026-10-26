//! Server configuration from environment variables and an optional TOML file.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// `MALO_LISTEN`, default `0.0.0.0:8443`.
    pub listen: SocketAddr,
    /// `MALO_DATA_DIR`, default `/data`.
    pub data_dir: PathBuf,
    /// `MALO_TLS_CERT` / `MALO_TLS_KEY`: PEM files. When unset, a self-signed certificate is generated on first boot.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// `MALO_TLS=off` serves plain HTTP (only behind a TLS-terminating reverse proxy or on loopback).
    pub tls: bool,
    /// Upper bound for every user's auto-lock (`MALO_MAX_AUTO_LOCK_HOURS`, default 24).
    pub max_auto_lock_hours: u32,
    /// Absolute paths fs destinations may use besides the user's own directory (`MALO_ALLOWED_FS_MOUNTS`, colon separated).
    pub allowed_fs_mounts: Vec<PathBuf>,
    /// Global concurrent job limit (`MALO_WORKERS`).
    pub workers: usize,
    /// Set by the desktop app: every request must carry `x-malo-sidecar: <secret>`.
    pub sidecar_secret: Option<String>,
    /// Session idle timeout in minutes.
    pub session_idle_minutes: i64,
    /// Development/test only: auto-lock after this many seconds instead of hours (`MALO_AUTO_LOCK_SECONDS`).
    pub auto_lock_seconds: Option<i64>,
    /// `MALO_TRUST_PROXY_HEADERS=1`: take the client address from `X-Real-IP` / `X-Forwarded-For`
    /// (set by the reverse proxy) for rate limits. Only behind a proxy that sets these headers:
    /// otherwise clients could pick their own address.
    pub trust_proxy_headers: bool,
    /// `MALO_IMAP_LISTEN`: address of the IMAP service (implicit TLS) that serves the backed-up
    /// mail to mail apps. Off when unset.
    pub imap_listen: Option<SocketAddr>,
    /// `MALO_SMTP_LISTEN`: address of the SMTP submission service (implicit TLS) that sends mail
    /// through each account's own SMTP server. Off when unset.
    pub smtp_listen: Option<SocketAddr>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: "0.0.0.0:8443".parse().unwrap(),
            data_dir: PathBuf::from("/data"),
            tls_cert: None,
            tls_key: None,
            tls: true,
            max_auto_lock_hours: 24,
            allowed_fs_mounts: vec![],
            workers: 4,
            sidecar_secret: None,
            session_idle_minutes: 12 * 60,
            auto_lock_seconds: None,
            trust_proxy_headers: false,
            imap_listen: None,
            smtp_listen: None,
        }
    }
}

impl ServerConfig {
    pub fn load() -> anyhow::Result<ServerConfig> {
        let mut cfg = match std::env::var("MALO_CONFIG") {
            Ok(path) => toml::from_str(&std::fs::read_to_string(&path)?)?,
            Err(_) => ServerConfig::default(),
        };
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if let Some(v) = env("MALO_LISTEN") {
            cfg.listen = v.parse()?;
        }
        if let Some(v) = env("MALO_DATA_DIR") {
            cfg.data_dir = v.into();
        }
        if let Some(v) = env("MALO_TLS_CERT") {
            cfg.tls_cert = Some(v.into());
        }
        if let Some(v) = env("MALO_TLS_KEY") {
            cfg.tls_key = Some(v.into());
        }
        if let Some(v) = env("MALO_TLS") {
            cfg.tls = !matches!(v.as_str(), "off" | "0" | "false");
        }
        if let Some(v) = env("MALO_MAX_AUTO_LOCK_HOURS") {
            cfg.max_auto_lock_hours = v.parse()?;
        }
        if let Some(v) = env("MALO_ALLOWED_FS_MOUNTS") {
            cfg.allowed_fs_mounts = v
                .split(':')
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect();
        }
        if let Some(v) = env("MALO_WORKERS") {
            cfg.workers = v.parse()?;
        }
        if let Some(v) = env("MALO_AUTO_LOCK_SECONDS") {
            cfg.auto_lock_seconds = Some(v.parse()?);
        }
        if let Some(v) = env("MALO_TRUST_PROXY_HEADERS") {
            cfg.trust_proxy_headers = matches!(v.as_str(), "1" | "true" | "on" | "yes");
        }
        let off = |v: &str| matches!(v, "off" | "0" | "false" | "no");
        if let Some(v) = env("MALO_IMAP_LISTEN") {
            cfg.imap_listen = if off(&v) { None } else { Some(v.parse()?) };
        }
        if let Some(v) = env("MALO_SMTP_LISTEN") {
            cfg.smtp_listen = if off(&v) { None } else { Some(v.parse()?) };
        }
        if let Some(v) = env("MALO_SIDECAR_SECRET") {
            cfg.sidecar_secret = Some(v);
        }
        // Remove the secret from the environment so child processes can't read it.
        std::env::remove_var("MALO_SIDECAR_SECRET");
        cfg.max_auto_lock_hours = cfg.max_auto_lock_hours.clamp(1, 24 * 30);
        cfg.workers = cfg.workers.max(1);
        Ok(cfg)
    }
}
