//! Per-user key ring in server RAM. Login unlocks; keys are wiped on auto-lock, "Lock now" or restart.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Duration, Utc};
use malo_core::config::UserConfig;
use malo_core::crypto::{self, KdfParams, Key, UserKeys, Vault};
use malo_core::index::Index;
use malo_core::oauth::TokenCache;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

/// Secret key material, boxed so its address is stable and can be mlocked.
pub struct Secrets {
    pub archive_key: Key,
    pub config_key: Key,
    pub spool_key: Key,
}

impl Drop for Secrets {
    fn drop(&mut self) {
        let ptr = self as *mut Secrets as *mut u8;
        unsafe {
            memsec::munlock(ptr, std::mem::size_of::<Secrets>());
        }
    }
}

fn lock_memory(s: &mut Secrets) {
    let ptr = s as *mut Secrets as *mut u8;
    // Best effort: failure (RLIMIT_MEMLOCK) is not fatal.
    unsafe {
        memsec::mlock(ptr, std::mem::size_of::<Secrets>());
    }
}

pub struct UnlockedUser {
    pub user_id: String,
    pub username: String,
    pub secrets: Box<Secrets>,
    pub config: RwLock<Arc<UserConfig>>,
    pub index: Arc<Index>,
    pub tokens: Arc<TokenCache>,
    pub unlocked_at: DateTime<Utc>,
    pub expires_at: Mutex<DateTime<Utc>>,
    /// Cancelled on lock: running jobs stop at the next message boundary.
    pub cancel: CancellationToken,
    pub dir: PathBuf,
    /// Serializes config writes.
    pub config_write: tokio::sync::Mutex<()>,
    /// Scheduled jobs skipped while the user was locked (shown once after login).
    pub skipped_while_locked: std::sync::atomic::AtomicU32,
}

impl UnlockedUser {
    pub fn config(&self) -> Arc<UserConfig> {
        self.config.read().unwrap().clone()
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        *self.expires_at.lock().unwrap()
    }

    /// Applies `f` to a copy of the config, seals it and writes it atomically.
    pub async fn update_config<R>(
        &self,
        f: impl FnOnce(&mut UserConfig) -> anyhow::Result<R>,
    ) -> anyhow::Result<R> {
        let _guard = self.config_write.lock().await;
        let mut cfg = (*self.config()).clone();
        let r = f(&mut cfg)?;
        let blob = cfg.seal(&self.secrets.config_key, &self.user_id)?;
        write_atomic(&self.dir.join("config.bin"), &blob)?;
        *self.config.write().unwrap() = Arc::new(cfg);
        Ok(r)
    }
}

pub fn write_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    if let Some(f) = malo_core::faults::pick(malo_core::faults::Site::ConfigWrite, "") {
        // A crash or full disk mid-write: half a temp file, never renamed over the real one.
        let _ = std::fs::write(&tmp, &data[..data.len() / 2]);
        return Err(malo_core::faults::io_error(f).into());
    }
    {
        use std::io::Write;
        // Owner-only from the first byte (keys, vaults, sealed configs): never readable
        // under a loose umask, even for a moment. A stale temp file may carry other modes.
        let _ = std::fs::remove_file(&tmp);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Default)]
pub struct KeyRing {
    users: Mutex<HashMap<String, Arc<UnlockedUser>>>,
}

pub struct UserPaths {
    pub dir: PathBuf,
}

impl UserPaths {
    /// User ids are server-generated UUIDs; anything else (`..`, `/`, …) never becomes a path.
    pub fn try_new(data_dir: &Path, user_id: &str) -> anyhow::Result<Self> {
        let id = uuid::Uuid::parse_str(user_id).map_err(|_| anyhow::anyhow!("invalid user id"))?;
        Ok(UserPaths {
            dir: data_dir.join("users").join(id.hyphenated().to_string()),
        })
    }

    /// Like [`Self::try_new`]; an invalid id maps to a directory that is never created.
    pub fn new(data_dir: &Path, user_id: &str) -> Self {
        Self::try_new(data_dir, user_id).unwrap_or_else(|_| {
            tracing::error!("refusing a non-UUID user id as a path component");
            UserPaths {
                dir: data_dir.join("users").join(".invalid-user-id"),
            }
        })
    }
    pub fn vault(&self) -> PathBuf {
        self.dir.join("vault.bin")
    }
    /// The MDK wrapped with a key derived from the archive key: the recovery kit can set a new password.
    pub fn recovery(&self) -> PathBuf {
        self.dir.join("recovery.bin")
    }
    pub fn config(&self) -> PathBuf {
        self.dir.join("config.bin")
    }
    pub fn index(&self) -> PathBuf {
        self.dir.join("index.db")
    }
    pub fn spool(&self) -> PathBuf {
        self.dir.join("spool")
    }
    pub fn local(&self) -> PathBuf {
        self.dir.join("local")
    }
}

fn recovery_aad(user_id: &str) -> String {
    format!("malo/v1/recovery-slot/{user_id}")
}

/// Writes the recovery slot: the MDK sealed with a key derived from the archive key. Whoever holds
/// the recovery kit can already read every backup; with the slot they can also set a new password
/// and keep the user, their accounts and destinations, instead of starting over.
pub fn write_recovery_slot(
    paths: &UserPaths,
    user_id: &str,
    mdk: &Key,
    archive_key: &Key,
) -> anyhow::Result<()> {
    let wrap = crypto::derive(archive_key.as_ref(), None, "malo/v1/recovery-slot");
    let blob = crypto::seal_blob(&wrap, recovery_aad(user_id).as_bytes(), mdk.as_ref());
    write_atomic(&paths.recovery(), &blob)
}

#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    #[error("this user has no recovery slot yet")]
    NoSlot,
    #[error("the recovery kit doesn't belong to this user")]
    WrongKit,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Sets a new password with the archive key from the recovery kit (Argon2id; call from a blocking
/// thread). The MDK stays the same, so config, index and backups are untouched.
pub fn reset_password_with_kit(
    data_dir: &Path,
    user_id: &str,
    archive_key: &Key,
    new_password: &str,
) -> Result<(), RecoverError> {
    let paths = UserPaths::try_new(data_dir, user_id)?;
    let blob = match std::fs::read(paths.recovery()) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(RecoverError::NoSlot),
        Err(e) => return Err(anyhow::Error::from(e).into()),
    };
    let wrap = crypto::derive(archive_key.as_ref(), None, "malo/v1/recovery-slot");
    let raw = crypto::open_blob(&wrap, recovery_aad(user_id).as_bytes(), &blob)
        .map_err(|_| RecoverError::WrongKit)?;
    if raw.len() != 32 {
        return Err(anyhow::anyhow!("damaged recovery slot").into());
    }
    let mut mdk = zeroize::Zeroizing::new([0u8; 32]);
    mdk.copy_from_slice(&raw);
    let vault = Vault::seal(user_id, new_password, &mdk, KdfParams::from_env())
        .map_err(anyhow::Error::from)?;
    write_atomic(&paths.vault(), &vault.to_bytes())?;
    Ok(())
}

/// Creates the vault, config and index of a new user.
pub fn provision_user(
    data_dir: &Path,
    user_id: &str,
    password: &str,
    archive_key: Option<Key>,
) -> anyhow::Result<()> {
    let paths = UserPaths::try_new(data_dir, user_id)?;
    std::fs::create_dir_all(&paths.dir)?;
    std::fs::create_dir_all(paths.local())?;
    let mdk = crypto::random_key();
    let vault = Vault::seal(user_id, password, &mdk, KdfParams::from_env())?;
    let keys = UserKeys::derive(&mdk);
    let imported = archive_key.is_some();
    let archive = archive_key.unwrap_or_else(crypto::random_key);
    let mut cfg = UserConfig::new(&archive);
    // A user created from a recovery kit already holds it.
    cfg.recovery_kit_exported = imported;
    write_atomic(&paths.config(), &cfg.seal(&keys.config, user_id)?)?;
    Index::open(&paths.index(), &keys.sqlcipher)?;
    write_recovery_slot(&paths, user_id, &mdk, &archive)?;
    write_atomic(&paths.vault(), &vault.to_bytes())?;
    Ok(())
}

/// Opens the vault with the password (Argon2id; call from a blocking thread).
pub fn open_vault(data_dir: &Path, user_id: &str, password: &str) -> anyhow::Result<Key> {
    let paths = UserPaths::new(data_dir, user_id);
    let vault = Vault::from_bytes(&std::fs::read(paths.vault())?)?;
    Ok(vault.open(user_id, password)?)
}

pub fn change_password(data_dir: &Path, user_id: &str, old: &str, new: &str) -> anyhow::Result<()> {
    let paths = UserPaths::new(data_dir, user_id);
    let vault = Vault::from_bytes(&std::fs::read(paths.vault())?)?;
    let new_vault = vault.rewrap(user_id, old, new, KdfParams::from_env())?;
    write_atomic(&paths.vault(), &new_vault.to_bytes())
}

impl KeyRing {
    pub fn get(&self, user_id: &str) -> Option<Arc<UnlockedUser>> {
        let users = self.users.lock().unwrap();
        let u = users.get(user_id)?;
        (u.expires_at() > Utc::now()).then(|| u.clone())
    }

    pub fn unlocked_ids(&self) -> Vec<String> {
        self.users.lock().unwrap().keys().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.users.lock().unwrap().len()
    }

    /// Builds the unlocked state from the MDK. If the user is already unlocked, the existing state is
    /// kept (same keys, running jobs untouched, one config in memory) and only the auto-lock period
    /// restarts, since the user just proved their password again.
    #[allow(clippy::too_many_arguments)]
    pub fn unlock(
        &self,
        data_dir: &Path,
        user_id: &str,
        username: &str,
        mut mdk: Key,
        lock_hours: u32,
        lock_override: Option<Duration>,
        on_rotate: malo_core::oauth::RotateFn,
    ) -> anyhow::Result<Arc<UnlockedUser>> {
        if let Some(existing) = self.get(user_id) {
            mdk.zeroize();
            let hours = lock_hours.min(existing.config().settings.auto_lock_hours.max(1));
            *existing.expires_at.lock().unwrap() =
                Utc::now() + lock_override.unwrap_or_else(|| Duration::hours(hours as i64));
            return Ok(existing);
        }
        let paths = UserPaths::new(data_dir, user_id);
        let keys = UserKeys::derive(&mdk);
        let config = UserConfig::open(&keys.config, user_id, &std::fs::read(paths.config())?);
        // Users created before recovery slots existed get theirs at their next login.
        if let Ok(cfg) = &config {
            if !paths.recovery().exists() {
                if let Err(e) = cfg
                    .archive_key()
                    .and_then(|a| write_recovery_slot(&paths, user_id, &mdk, &a))
                {
                    tracing::warn!(user = %user_id, "writing the recovery slot failed: {e:#}");
                }
            }
        }
        mdk.zeroize();
        let config = config?;
        let index = Arc::new(Index::open(&paths.index(), &keys.sqlcipher)?);
        let accounts: Vec<String> = config.accounts.iter().map(|a| a.id.clone()).collect();
        let destinations: Vec<String> = config.destinations.iter().map(|d| d.id.clone()).collect();
        match index.prune_deleted(&accounts, &destinations) {
            Ok(0) => {}
            Ok(n) => {
                tracing::info!(user = %user_id, "removed index data of {n} deleted account(s)/destination(s)")
            }
            Err(e) => {
                tracing::warn!(user = %user_id, "index cleanup of deleted items failed: {e:#}")
            }
        }
        let mut secrets = Box::new(Secrets {
            archive_key: config.archive_key()?,
            config_key: keys.config.clone(),
            spool_key: keys.spool.clone(),
        });
        lock_memory(&mut secrets);
        let lock_hours = lock_hours.min(config.settings.auto_lock_hours.max(1));
        let now = Utc::now();
        let user = Arc::new(UnlockedUser {
            user_id: user_id.to_string(),
            username: username.to_string(),
            secrets,
            config: RwLock::new(Arc::new(config)),
            index,
            tokens: Arc::new(TokenCache::new(on_rotate)),
            unlocked_at: now,
            expires_at: Mutex::new(
                now + lock_override.unwrap_or_else(|| Duration::hours(lock_hours as i64)),
            ),
            cancel: CancellationToken::new(),
            dir: paths.dir,
            config_write: tokio::sync::Mutex::new(()),
            skipped_while_locked: Default::default(),
        });
        if let Some(old) = self
            .users
            .lock()
            .unwrap()
            .insert(user_id.to_string(), user.clone())
        {
            // Only reachable for an entry that had expired but wasn't swept yet: seal it properly.
            old.cancel.cancel();
        }
        Ok(user)
    }

    /// Wipes the user's keys. Returns true if they were unlocked.
    pub fn lock(&self, user_id: &str) -> bool {
        let removed = self.users.lock().unwrap().remove(user_id);
        match removed {
            Some(u) => {
                u.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// Users whose mandatory auto-lock has passed.
    pub fn expired(&self) -> Vec<String> {
        let now = Utc::now();
        self.users
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, u)| u.expires_at() <= now)
            .map(|(k, _)| k.clone())
            .collect()
    }
}
