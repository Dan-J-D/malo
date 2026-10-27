//! IMAP and SMTP services for mail apps (Apple Mail, Thunderbird…): read an account's backed-up
//! mail, including mail already purged from its server, and send through the account's own SMTP
//! server.
//!
//! Each account gets its own login with a server-generated password, so the Malo password (which
//! unlocks every key) never goes into a mail app. Mail is readable only while its owner is
//! unlocked: the keys stay in RAM only for as long as the auto-lock allows, and a mail login
//! doesn't change that.

pub mod imap;
pub use malo_core::mime;
pub mod smtp;
mod starttls;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::keyring::UnlockedUser;
use crate::state::{AppState, SharedState};

/// What the API tells the app about the mail services.
#[derive(Debug, Clone, Default)]
pub struct MailInfo {
    pub imap_port: Option<u16>,
    pub smtp_port: Option<u16>,
    pub fingerprint: Option<String>,
}

/// Simultaneous IMAP and SMTP connections across all users.
const MAX_CONNECTIONS: usize = 512;
/// Simultaneous connections from one address (one /64 for IPv6).
const MAX_PER_IP: usize = 16;
/// A connection must have logged in this long after it opened, however busy it keeps itself.
pub(crate) const LOGIN_DEADLINE: Duration = Duration::from_secs(120);
/// Commands (lines, for SMTP) a connection may send before it logs in.
pub(crate) const PREAUTH_COMMANDS: u32 = 32;
pub const DEFAULT_PASSWORD_LENGTH: u32 = 24;

/// A random password of letters and digits (≈5.95 bits per character).
pub fn generate_password(len: u32) -> String {
    let mut rng = rand::rngs::OsRng;
    (0..len.clamp(16, 128))
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect()
}

/// Mail login names: lower-case letters, digits and `. _ - + @`, 3–64 characters.
pub fn normalize_username(name: &str) -> Result<String, String> {
    let n = name.trim().to_lowercase();
    if !(3..=64).contains(&n.len()) {
        return Err("the username must be 3–64 characters long".into());
    }
    if !n.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err("the username must start with a letter or digit".into());
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@'))
    {
        return Err("the username may only contain letters, digits and . _ - + @".into());
    }
    Ok(n)
}

pub fn hash_password(password: &str) -> String {
    // Generated passwords carry ~143 bits of entropy: a fast hash is enough.
    malo_core::crypto::sha256_hex(format!("malo-mail-login:{password}").as_bytes())
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// A signed-in mail session.
#[derive(Clone)]
pub struct MailUser {
    pub user_id: String,
    pub account_id: String,
    pub username: String,
    password_hash: String,
    /// Cancelled when the user is locked.
    pub sealed: CancellationToken,
}

#[derive(Debug)]
pub enum LoginError {
    Invalid,
    /// Right password, but the user's keys are locked.
    Locked,
    Throttled(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Gone {
    Locked,
    Revoked,
}

impl Gone {
    pub fn message(&self) -> &'static str {
        match self {
            Gone::Locked => "Malo is locked: log in to the Malo app to unlock your mail",
            Gone::Revoked => "this mail login was changed or removed in Malo",
        }
    }
}

impl MailUser {
    /// The unlocked user while this login is valid. Callers use it for one step and drop it, so
    /// a session never keeps keys in memory after a lock.
    pub fn unlocked(&self, state: &AppState) -> Result<Arc<UnlockedUser>, Gone> {
        let row = state.db.mail_login(&self.username).ok().flatten();
        let valid = row.is_some_and(|r| {
            r.user_id == self.user_id
                && r.account_id == self.account_id
                && same(&r.password_hash, &self.password_hash)
        });
        if !valid {
            return Err(Gone::Revoked);
        }
        if self.sealed.is_cancelled() {
            return Err(Gone::Locked);
        }
        let user = state.keyring.get(&self.user_id).ok_or(Gone::Locked)?;
        if user.config().account(&self.account_id).is_none() {
            return Err(Gone::Revoked);
        }
        Ok(user)
    }
}

/// Checks a mail login. Failures back off like app logins, in a table of their own.
pub async fn authenticate(
    state: &SharedState,
    username: &str,
    password: &str,
    ip: IpAddr,
) -> Result<MailUser, LoginError> {
    let key = username.to_lowercase();
    if let Some(wait) = state.mail_failures.check(&key, ip) {
        return Err(LoginError::Throttled(crate::auth::try_again(wait)));
    }
    let hash = hash_password(password);
    let row = state.db.mail_login(username).ok().flatten();
    let user_row = row
        .as_ref()
        .and_then(|r| state.db.user(&r.user_id).ok().flatten());
    let ok = match (&row, &user_row) {
        (Some(r), Some(u)) => same(&r.password_hash, &hash) && !u.disabled,
        _ => false,
    };
    if !ok {
        state.mail_failures.record(&key, ip);
        // Slow down guessing a little on every miss, before the backoff starts.
        tokio::time::sleep(Duration::from_millis(500)).await;
        return Err(LoginError::Invalid);
    }
    state.mail_failures.clear(&key, ip);
    let row = row.unwrap();
    let Some(user) = state.keyring.get(&row.user_id) else {
        return Err(LoginError::Locked);
    };
    if user.config().account(&row.account_id).is_none() {
        return Err(LoginError::Invalid);
    }
    let _ = state.db.touch_mail_login(&row.username);
    Ok(MailUser {
        user_id: row.user_id,
        account_id: row.account_id,
        username: row.username,
        password_hash: row.password_hash,
        sealed: user.cancel.clone(),
    })
}

pub use malo_core::lines::read_line;

pub struct Listeners {
    imap: Option<std::net::TcpListener>,
    smtp: Option<std::net::TcpListener>,
}

impl Listeners {
    /// Binds the configured mail ports (before the server state exists, so it can report them).
    pub fn bind(cfg: &crate::config::ServerConfig) -> anyhow::Result<Listeners> {
        let bind = |a: Option<SocketAddr>| -> anyhow::Result<Option<std::net::TcpListener>> {
            a.map(|a| {
                let l = std::net::TcpListener::bind(a)
                    .map_err(|e| anyhow::anyhow!("cannot listen on {a}: {e}"))?;
                l.set_nonblocking(true)?;
                Ok(l)
            })
            .transpose()
        };
        Ok(Listeners {
            imap: bind(cfg.imap_listen)?,
            smtp: bind(cfg.smtp_listen)?,
        })
    }

    pub fn any(&self) -> bool {
        self.imap.is_some() || self.smtp.is_some()
    }

    pub fn addrs(&self) -> (Option<SocketAddr>, Option<SocketAddr>) {
        let a = |l: &Option<std::net::TcpListener>| l.as_ref().and_then(|l| l.local_addr().ok());
        (a(&self.imap), a(&self.smtp))
    }

    /// Starts accepting connections (implicit TLS) until shutdown.
    pub fn spawn(self, state: SharedState, tls: Arc<rustls::ServerConfig>) -> anyhow::Result<()> {
        let mut config = (*tls).clone();
        config.alpn_protocols = vec![];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let per_ip = Arc::new(PerIp::default());
        if let Some(l) = self.imap {
            serve(
                TcpListener::from_std(l)?,
                state.clone(),
                acceptor.clone(),
                (slots.clone(), per_ip.clone()),
                Service::Imap,
            );
        }
        if let Some(l) = self.smtp {
            serve(
                TcpListener::from_std(l)?,
                state,
                acceptor,
                (slots, per_ip),
                Service::Smtp,
            );
        }
        Ok(())
    }
}

/// Open connections per client address.
#[derive(Default)]
struct PerIp(std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>);

/// One connection counted in [`PerIp`] until dropped.
struct IpSlot(Arc<PerIp>, IpAddr);

impl PerIp {
    fn take(self: &Arc<Self>, ip: IpAddr) -> Option<IpSlot> {
        let ip = crate::limits::client_key(ip);
        let mut map = self.0.lock().unwrap();
        let n = map.entry(ip).or_default();
        if *n >= MAX_PER_IP {
            return None;
        }
        *n += 1;
        Some(IpSlot(self.clone(), ip))
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut map = self.0 .0.lock().unwrap();
        if let Some(n) = map.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.1);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Service {
    Imap,
    Smtp,
}

fn serve(
    listener: TcpListener,
    state: SharedState,
    acceptor: TlsAcceptor,
    (slots, per_ip): (Arc<Semaphore>, Arc<PerIp>),
    service: Service,
) {
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                a = listener.accept() => a,
                _ = state.shutdown.cancelled() => return,
            };
            let (tcp, peer) = match accepted {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!("mail accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let name = match service {
                Service::Imap => "IMAP",
                Service::Smtp => "SMTP",
            };
            if imap::tracing_on() {
                tracing::info!("mail: {name} connection from {peer}");
            }
            let Some(ip_slot) = per_ip.take(peer.ip()) else {
                tracing::debug!(
                    "mail: refused a {name} connection from {peer}: {MAX_PER_IP} already open"
                );
                drop(tcp);
                continue;
            };
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                tracing::warn!(
                    "mail: refused a {name} connection from {peer}: all {MAX_CONNECTIONS} connections are in use"
                );
                drop(tcp);
                continue;
            };
            let (state, acceptor) = (state.clone(), acceptor.clone());
            tokio::spawn(async move {
                let _permit = (permit, ip_slot);
                // The login deadline counts from here: the plain-text STARTTLS part and the TLS
                // handshake use it up too.
                let opened = std::time::Instant::now();
                let mut tcp = tcp;
                tcp.set_nodelay(true).ok();
                let greet = match starttls::opening(&tcp).await {
                    Ok(Some(starttls::Opening::Tls)) => true,
                    Ok(Some(starttls::Opening::Plain)) => {
                        if imap::tracing_on() {
                            tracing::info!("mail: {peer} connected without TLS; offering STARTTLS");
                        }
                        let outcome = match service {
                            Service::Imap => starttls::imap(&mut tcp, opened).await,
                            Service::Smtp => starttls::smtp(&mut tcp, opened).await,
                        };
                        match outcome {
                            Ok(starttls::Outcome::StartTls) => {
                                if imap::tracing_on() {
                                    tracing::info!("mail: {peer} started TLS with STARTTLS");
                                }
                                // The session continues without a second greeting.
                                false
                            }
                            Ok(starttls::Outcome::TriedPlainLogin) => {
                                tracing::warn!(
                                    "mail: an app at {peer} tried to log in to {name} without TLS and was refused; turn on SSL/TLS (or STARTTLS) in its account settings"
                                );
                                return;
                            }
                            Ok(starttls::Outcome::Closed) => return,
                            Err(e) => {
                                tracing::debug!("mail: plain-text {name} from {peer}: {e:#}");
                                return;
                            }
                        }
                    }
                    _ => return,
                };
                let stream =
                    match tokio::time::timeout(Duration::from_secs(30), acceptor.accept(tcp)).await
                    {
                        Ok(Ok(s)) => s,
                        failed => {
                            let why = match failed {
                                Ok(Err(e)) => format!("{e}"),
                                _ => "timed out".into(),
                            };
                            if imap::tracing_on() {
                                tracing::info!("mail TLS handshake with {peer} failed: {why}");
                            } else {
                                tracing::debug!("mail TLS handshake with {peer} failed: {why}");
                            }
                            return;
                        }
                    };
                let res = match service {
                    Service::Imap => imap::session(state, stream, peer.ip(), greet, opened).await,
                    Service::Smtp => smtp::session(state, stream, peer.ip(), greet, opened).await,
                };
                if let Err(e) = res {
                    if imap::tracing_on() {
                        tracing::info!("mail session from {peer} ended: {e:#}");
                    } else {
                        tracing::debug!("mail session from {peer}: {e:#}");
                    }
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_per_ip() {
        let per_ip = Arc::new(PerIp::default());
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let same_64: IpAddr = "2001:db8::2".parse().unwrap();
        let held: Vec<IpSlot> = (0..MAX_PER_IP).map(|_| per_ip.take(ip).unwrap()).collect();
        assert!(per_ip.take(same_64).is_none());
        assert!(per_ip.take("2001:db8:0:1::1".parse().unwrap()).is_some());
        drop(held);
        assert!(per_ip.take(ip).is_some());
        assert_eq!(per_ip.0.lock().unwrap().len(), 0, "slots are given back");
    }

    #[test]
    fn passwords_and_usernames() {
        let p = generate_password(24);
        assert_eq!(p.len(), 24);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(p, generate_password(24));
        assert_eq!(generate_password(4).len(), 16);
        assert_eq!(normalize_username(" Test-Email ").unwrap(), "test-email");
        for bad in ["ab", "-x1", "a b c", "ünï", &"x".repeat(65)] {
            assert!(normalize_username(bad).is_err(), "{bad}");
        }
    }
}
