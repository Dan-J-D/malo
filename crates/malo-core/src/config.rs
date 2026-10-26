//! The per-user configuration, stored encrypted with the config key.

use std::collections::BTreeMap;

use malo_api::{
    AccountAuth, AccountInput, AccountView, DeepCheckMode, DestinationInput, DestinationView,
    PurgePolicy, SmtpSettings, TlsMode, UserSettings, REDACTED,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Key};

#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    #[serde(default)]
    pub accept_invalid_certs: bool,
    pub username: String,
    pub auth: AccountAuth,
    pub backup_interval_minutes: u32,
    pub idle: bool,
    pub enabled: bool,
    /// Upstream SMTP server for mail sent through Malo (same username and credentials).
    #[serde(default)]
    pub smtp: Option<SmtpSettings>,
    #[serde(default)]
    pub imported: bool,
    #[serde(default)]
    pub policy: PurgePolicy,
    /// Bumped on every change (optimistic concurrency between devices).
    #[serde(default)]
    pub revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Destination {
    pub id: String,
    pub name: String,
    pub scheme: String,
    pub options: BTreeMap<String, String>,
    pub root: String,
    pub encrypt: bool,
    pub required_for_purge: bool,
    pub deep_check: DeepCheckMode,
    #[serde(default)]
    pub revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// Hex archive key (exportable as recovery kit).
    pub archive_key: String,
    #[serde(default)]
    pub recovery_kit_exported: bool,
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub destinations: Vec<Destination>,
    #[serde(default)]
    pub settings: UserSettings,
}

impl Drop for UserConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.archive_key.zeroize();
    }
}

impl UserConfig {
    pub fn new(archive_key: &Key) -> Self {
        UserConfig {
            archive_key: hex::encode(archive_key.as_ref()),
            recovery_kit_exported: false,
            accounts: vec![],
            destinations: vec![],
            settings: UserSettings::default(),
        }
    }

    pub fn archive_key(&self) -> anyhow::Result<Key> {
        let bytes = Zeroizing::new(hex::decode(&self.archive_key)?);
        anyhow::ensure!(bytes.len() == 32, "archive key must be 32 bytes");
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&bytes);
        Ok(k)
    }

    pub fn account(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn account_mut(&mut self, id: &str) -> Option<&mut Account> {
        self.accounts.iter_mut().find(|a| a.id == id)
    }

    pub fn destination(&self, id: &str) -> Option<&Destination> {
        self.destinations.iter().find(|d| d.id == id)
    }

    pub fn seal(&self, key: &Key, user_id: &str) -> anyhow::Result<Vec<u8>> {
        let json = Zeroizing::new(serde_json::to_vec(self)?);
        Ok(crypto::seal_blob(key, aad(user_id).as_bytes(), &json))
    }

    pub fn open(key: &Key, user_id: &str, blob: &[u8]) -> anyhow::Result<Self> {
        let json = crypto::open_blob(key, aad(user_id).as_bytes(), blob)?;
        Ok(serde_json::from_slice(&json)?)
    }
}

fn aad(user_id: &str) -> String {
    format!("malo/v1/config/{user_id}")
}

pub const SETTINGS_BACKUP_FORMAT: &str = "malo-settings-v1";

/// The copy of a user's settings kept on every destination, encrypted with the archive key. With
/// the recovery kit and the credentials of one destination, the accounts and destinations (and
/// their credentials) come back on a new server, under their old ids.
#[derive(Serialize, Deserialize)]
pub struct SettingsBackup {
    pub format: String,
    pub saved_at: chrono::DateTime<chrono::Utc>,
    pub accounts: Vec<Account>,
    pub destinations: Vec<Destination>,
    pub settings: UserSettings,
}

impl UserConfig {
    /// The settings copy as JSON, and a hash of its content that ignores the time it was made
    /// (to skip rewriting an unchanged copy).
    pub fn settings_backup(&self) -> anyhow::Result<(Zeroizing<Vec<u8>>, String)> {
        let mut b = SettingsBackup {
            format: SETTINGS_BACKUP_FORMAT.into(),
            saved_at: chrono::DateTime::UNIX_EPOCH,
            accounts: self.accounts.clone(),
            destinations: self.destinations.clone(),
            settings: self.settings.clone(),
        };
        let hash = crypto::sha256_hex(&Zeroizing::new(serde_json::to_vec(&b)?));
        b.saved_at = chrono::Utc::now();
        Ok((Zeroizing::new(serde_json::to_vec(&b)?), hash))
    }
}

impl SettingsBackup {
    pub fn parse(json: &[u8]) -> anyhow::Result<SettingsBackup> {
        let b: SettingsBackup = serde_json::from_slice(json)?;
        anyhow::ensure!(
            b.format == SETTINGS_BACKUP_FORMAT,
            "unsupported settings copy {}",
            b.format
        );
        Ok(b)
    }
}

const SECRET_OPTION_HINTS: &[&str] = &[
    "secret",
    "password",
    "credential",
    "account_key",
    "sas_token",
    "token",
    "application_key",
    "private_key",
];

pub fn is_secret_option(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_OPTION_HINTS.iter().any(|h| k.contains(h))
}

/// Optimistic concurrency: an edit based on an older revision is refused.
pub fn check_revision(client: Option<u64>, stored: u64) -> anyhow::Result<()> {
    match client {
        Some(r) if r != stored => Err(StaleRevision { client: r, stored }.into()),
        _ => Ok(()),
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "changed on another device (revision {stored}, you edited {client}) — reload and try again"
)]
pub struct StaleRevision {
    pub client: u64,
    pub stored: u64,
}

/// Names users type (accounts, destinations): visible text only, at most 100 characters.
pub fn validate_name(what: &str, name: &str) -> anyhow::Result<()> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "{what} is required");
    anyhow::ensure!(
        name.chars().count() <= 100,
        "{what} is too long (max. 100 characters)"
    );
    if let Some(c) = name.chars().find(|c| crate::layout::is_invisible(*c)) {
        anyhow::bail!(
            "{what} contains a hidden or control character (U+{:04X})",
            c as u32
        );
    }
    Ok(())
}

fn is_host_name(h: &str) -> bool {
    h.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

fn keep(new: String, old: Option<&String>) -> String {
    match (new.as_str(), old) {
        (REDACTED, Some(o)) => o.clone(),
        _ => new,
    }
}

impl Account {
    pub fn from_input(
        id: String,
        input: AccountInput,
        previous: Option<&Account>,
    ) -> anyhow::Result<Account> {
        let smtp = input
            .smtp
            .map(|s| SmtpSettings {
                host: s.host.trim().to_string(),
                ..s
            })
            .filter(|s| !s.host.is_empty());
        // A saved secret only fills in a redacted field while it goes to the same servers (IMAP
        // and SMTP), user and kind of connection; otherwise anyone with a session could send it
        // to their own server.
        let same_server = previous.is_some_and(|p| {
            p.host == input.host.trim()
                && p.port == input.port
                && p.username == input.username
                && p.tls == input.tls
                && (p.accept_invalid_certs || !input.accept_invalid_certs)
                && (smtp.is_none() || p.smtp == smtp)
        });
        let saved = previous.filter(|_| same_server).map(|p| &p.auth);
        let auth = match (input.auth, saved) {
            (AccountAuth::Password { password }, prev) => {
                let old = match prev {
                    Some(AccountAuth::Password { password }) => Some(password),
                    _ => None,
                };
                AccountAuth::Password {
                    password: keep(password, old),
                }
            }
            (
                AccountAuth::OAuth2 {
                    provider,
                    auth_url,
                    token_url,
                    client_id,
                    client_secret,
                    scopes,
                    refresh_token,
                },
                prev,
            ) => {
                // The token and secret also stay with the provider they were issued by.
                let (old_secret, old_refresh) = match prev {
                    Some(AccountAuth::OAuth2 {
                        provider: p,
                        auth_url: a,
                        token_url: t,
                        client_id: c,
                        client_secret,
                        refresh_token,
                        ..
                    }) if (*p, a, t, c) == (provider, &auth_url, &token_url, &client_id) => {
                        (client_secret.as_ref(), Some(refresh_token))
                    }
                    _ => (None, None),
                };
                AccountAuth::OAuth2 {
                    provider,
                    auth_url,
                    token_url,
                    client_id,
                    client_secret: client_secret.map(|s| keep(s, old_secret)),
                    scopes,
                    refresh_token: keep(refresh_token, old_refresh),
                }
            }
        };
        let (AccountAuth::Password { password: secret }
        | AccountAuth::OAuth2 {
            refresh_token: secret,
            ..
        }) = &auth;
        anyhow::ensure!(!secret.is_empty(), "credentials are required");
        let redacted_secret =
            matches!(&auth, AccountAuth::OAuth2 { client_secret: Some(s), .. } if s == REDACTED);
        anyhow::ensure!(
            secret != REDACTED && !redacted_secret,
            "enter the password again (or sign in again): the server or sign-in settings changed, so the saved one isn't reused"
        );
        validate_name("name", &input.name)?;
        anyhow::ensure!(!input.host.trim().is_empty(), "host is required");
        anyhow::ensure!(
            is_host_name(input.host.trim()),
            "host must be an ASCII host name or IP address (use the xn-- form for international domains)"
        );
        anyhow::ensure!(input.port != 0, "port is required");
        if let Some(s) = &smtp {
            anyhow::ensure!(
                is_host_name(&s.host),
                "SMTP host must be an ASCII host name or IP address (use the xn-- form for international domains)"
            );
            anyhow::ensure!(s.port != 0, "SMTP port is required");
        }
        Ok(Account {
            id,
            name: input.name.trim().to_string(),
            host: input.host.trim().to_string(),
            port: input.port,
            tls: input.tls,
            accept_invalid_certs: input.accept_invalid_certs,
            username: input.username,
            auth,
            backup_interval_minutes: input.backup_interval_minutes.max(1),
            idle: input.idle,
            enabled: input.enabled,
            smtp,
            imported: previous.map(|p| p.imported).unwrap_or(false),
            policy: previous.map(|p| p.policy.clone()).unwrap_or_default(),
            revision: previous.map(|p| p.revision + 1).unwrap_or(1),
        })
    }

    pub fn redacted_auth(&self) -> AccountAuth {
        match &self.auth {
            AccountAuth::Password { .. } => AccountAuth::Password {
                password: REDACTED.into(),
            },
            AccountAuth::OAuth2 {
                provider,
                auth_url,
                token_url,
                client_id,
                client_secret,
                scopes,
                ..
            } => AccountAuth::OAuth2 {
                provider: *provider,
                auth_url: auth_url.clone(),
                token_url: token_url.clone(),
                client_id: client_id.clone(),
                client_secret: client_secret.as_ref().map(|_| REDACTED.to_string()),
                scopes: scopes.clone(),
                refresh_token: REDACTED.into(),
            },
        }
    }

    /// View without secrets; runtime fields are filled in by the caller.
    pub fn view(&self) -> AccountView {
        AccountView {
            revision: self.revision,
            id: self.id.clone(),
            name: self.name.clone(),
            host: self.host.clone(),
            port: self.port,
            tls: self.tls,
            accept_invalid_certs: self.accept_invalid_certs,
            username: self.username.clone(),
            auth: self.redacted_auth(),
            backup_interval_minutes: self.backup_interval_minutes,
            idle: self.idle,
            enabled: self.enabled,
            smtp: self.smtp.clone(),
            imported: self.imported,
            policy: self.policy.clone(),
            last_backup: None,
            last_backup_ok: None,
            next_backup: None,
            next_purge: None,
            purge_blocked: None,
            message_count: 0,
            stored_bytes: 0,
        }
    }
}

impl Destination {
    pub fn from_input(
        id: String,
        input: DestinationInput,
        previous: Option<&Destination>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!input.name.trim().is_empty(), "name is required");
        anyhow::ensure!(
            input
                .scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && !input.scheme.is_empty(),
            "invalid scheme"
        );
        if let DeepCheckMode::Rotating { slices } = input.deep_check {
            anyhow::ensure!(slices >= 1, "rotating deep check needs at least one slice");
        }
        // Saved secrets are only reused for the same storage (scheme and every other option).
        let public = |o: &BTreeMap<String, String>| {
            o.iter()
                .filter(|(k, _)| !is_secret_option(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        let same_storage = previous.is_some_and(|p| {
            p.scheme == input.scheme && public(&p.options) == public(&input.options)
        });
        let options: BTreeMap<String, String> = input
            .options
            .into_iter()
            .map(|(k, v)| {
                let old = previous
                    .filter(|_| same_storage)
                    .and_then(|p| p.options.get(&k));
                (k, keep(v, old))
            })
            .collect();
        if let Some((k, _)) = options.iter().find(|(_, v)| v.as_str() == REDACTED) {
            anyhow::bail!(
                "enter '{k}' again: the storage settings changed, so the saved secret isn't reused"
            );
        }
        let dest = Destination {
            id,
            name: input.name.trim().to_string(),
            scheme: input.scheme,
            options,
            root: input.root.trim_matches('/').to_string(),
            encrypt: input.encrypt,
            required_for_purge: input.required_for_purge,
            deep_check: input.deep_check,
            revision: previous.map(|p| p.revision + 1).unwrap_or(1),
        };
        crate::store::validate_destination(&dest)?;
        Ok(dest)
    }

    pub fn view(&self) -> DestinationView {
        DestinationView {
            revision: self.revision,
            id: self.id.clone(),
            name: self.name.clone(),
            scheme: self.scheme.clone(),
            options: self
                .options
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        if is_secret_option(k) {
                            REDACTED.to_string()
                        } else {
                            v.clone()
                        },
                    )
                })
                .collect(),
            root: self.root.clone(),
            encrypt: self.encrypt,
            required_for_purge: self.required_for_purge,
            deep_check: self.deep_check.clone(),
            object_count: 0,
            stored_bytes: 0,
            health: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(password: &str) -> AccountInput {
        AccountInput {
            revision: None,
            name: "Work".into(),
            host: "imap.example.com".into(),
            port: 993,
            tls: TlsMode::Implicit,
            accept_invalid_certs: false,
            username: "me".into(),
            auth: AccountAuth::Password {
                password: password.into(),
            },
            backup_interval_minutes: 30,
            idle: false,
            enabled: true,
            smtp: None,
        }
    }

    #[test]
    fn redacted_secret_is_kept() {
        let a = Account::from_input("a".into(), input("s3cret"), None).unwrap();
        assert!(
            matches!(a.view().auth, AccountAuth::Password { ref password } if password == REDACTED)
        );
        let b = Account::from_input("a".into(), input(REDACTED), Some(&a)).unwrap();
        assert!(matches!(b.auth, AccountAuth::Password { ref password } if password == "s3cret"));
        assert!(Account::from_input("a".into(), input(REDACTED), None).is_err());
    }

    #[test]
    fn redacted_secret_never_follows_a_new_smtp_server() {
        let mut i = input("s3cret");
        i.smtp = Some(SmtpSettings {
            host: "smtp.example.com".into(),
            port: 465,
            tls: TlsMode::Implicit,
        });
        let a = Account::from_input("a".into(), i.clone(), None).unwrap();
        let mut same = i.clone();
        same.auth = AccountAuth::Password {
            password: REDACTED.into(),
        };
        assert!(Account::from_input("a".into(), same.clone(), Some(&a)).is_ok());
        let mut moved = same;
        moved.smtp.as_mut().unwrap().host = "smtp.attacker.example".into();
        assert!(Account::from_input("a".into(), moved, Some(&a)).is_err());
    }

    #[test]
    fn names_reject_hidden_characters() {
        assert!(validate_name("name", "Work 日本 😀").is_ok());
        for bad in [
            "",
            "   ",
            "Work\u{202E}",
            "\u{200B}",
            "a\u{0}b",
            &"x".repeat(101),
        ] {
            assert!(validate_name("name", bad).is_err(), "{bad:?}");
        }
        let mut i = input("pw");
        i.host = "imap.exa\u{200B}mple.com".into();
        assert!(Account::from_input("a".into(), i, None).is_err());
    }

    #[test]
    fn config_seal_bound_to_user() {
        let k = crypto::random_key();
        let cfg = UserConfig::new(&crypto::random_key());
        let blob = cfg.seal(&k, "u1").unwrap();
        assert!(UserConfig::open(&k, "u2", &blob).is_err());
        let back = UserConfig::open(&k, "u1", &blob).unwrap();
        assert_eq!(back.archive_key, cfg.archive_key);
    }

    #[test]
    fn destination_secret_options_redacted() {
        let mut opts = BTreeMap::new();
        opts.insert("bucket".into(), "b".into());
        opts.insert("secret_access_key".into(), "xyz".into());
        let d = Destination::from_input(
            "d".into(),
            DestinationInput {
                revision: None,
                name: "S3".into(),
                scheme: "s3".into(),
                options: opts,
                root: "/malo/".into(),
                encrypt: true,
                required_for_purge: true,
                deep_check: DeepCheckMode::Full,
            },
            None,
        )
        .unwrap();
        assert_eq!(d.root, "malo");
        let v = d.view();
        assert_eq!(v.options["secret_access_key"], REDACTED);
        assert_eq!(v.options["bucket"], "b");
    }
}
