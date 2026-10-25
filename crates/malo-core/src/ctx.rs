//! Execution context handed to jobs by the server.

use std::path::PathBuf;
use std::sync::Arc;

use malo_api::{JobProgress, SyncEvent};
use tokio_util::sync::CancellationToken;

use crate::config::{Account, UserConfig};
use crate::crypto::{self, Key};
use crate::index::Index;
use crate::oauth::TokenSource;
use crate::store::{FsPolicy, Store};

pub trait EventSink: Send + Sync {
    fn emit(&self, event: SyncEvent);
}

/// Discards events (tests, CLI).
pub struct NullSink;
impl EventSink for NullSink {
    fn emit(&self, _: SyncEvent) {}
}

pub struct JobCtx {
    pub job_id: String,
    pub user_id: String,
    pub config: Arc<UserConfig>,
    pub archive_key: Key,
    pub index: Arc<Index>,
    pub spool_dir: PathBuf,
    pub spool_key: Key,
    pub fs: FsPolicy,
    pub tokens: Arc<dyn TokenSource>,
    pub events: Arc<dyn EventSink>,
    pub cancel: CancellationToken,
    /// Cancelled when the user is locked or deleted (as opposed to a plain job cancel): the job
    /// then stops without writing anything else.
    pub sealed: CancellationToken,
    /// Started by the user ("Back up now"): retries everything, ignoring backoff.
    pub manual: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("cancelled")]
pub struct Cancelled;

impl JobCtx {
    pub fn check_cancel(&self) -> anyhow::Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Cancelled.into());
        }
        Ok(())
    }

    pub fn progress(&self, done: u64, total: u64, message: impl Into<String>) {
        self.events.emit(SyncEvent::JobProgress {
            job_id: self.job_id.clone(),
            progress: JobProgress {
                done,
                total,
                message: message.into(),
            },
        });
    }

    pub fn account(&self, id: &str) -> anyhow::Result<&Account> {
        self.config
            .account(id)
            .ok_or_else(|| anyhow::anyhow!("unknown account {id}"))
    }

    pub fn stores(&self) -> anyhow::Result<Vec<Store>> {
        self.config
            .destinations
            .iter()
            .map(|d| Store::open(d, &self.archive_key, &self.fs))
            .collect()
    }

    pub fn store(&self, id: &str) -> anyhow::Result<Store> {
        let d = self
            .config
            .destination(id)
            .ok_or_else(|| anyhow::anyhow!("unknown destination {id}"))?;
        Store::open(d, &self.archive_key, &self.fs)
    }

    pub fn destination_ids(&self) -> Vec<String> {
        self.config
            .destinations
            .iter()
            .map(|d| d.id.clone())
            .collect()
    }

    fn spool_path(&self, message: i64) -> PathBuf {
        self.spool_dir.join(format!("{message}.spool"))
    }

    /// Writes a downloaded message to the encrypted spool.
    pub fn spool_put(&self, message: i64, raw: &[u8]) -> anyhow::Result<()> {
        if let Some(f) = crate::faults::pick(crate::faults::Site::Spool, &self.user_id) {
            return Err(crate::faults::io_error(f).into());
        }
        self.ensure_dir(&self.spool_dir)?;
        let blob = crypto::seal_blob(&self.spool_key, format!("spool:{message}").as_bytes(), raw);
        let tmp = self.spool_dir.join(format!("{message}.tmp"));
        std::fs::write(&tmp, blob)?;
        std::fs::rename(tmp, self.spool_path(message))?;
        Ok(())
    }

    pub fn spool_get(&self, message: i64) -> Option<Vec<u8>> {
        let blob = std::fs::read(self.spool_path(message)).ok()?;
        crypto::open_blob(
            &self.spool_key,
            format!("spool:{message}").as_bytes(),
            &blob,
        )
        .ok()
        .map(|z| z.to_vec())
    }

    pub fn spool_remove(&self, message: i64) {
        let _ = std::fs::remove_file(self.spool_path(message));
    }

    /// Creates one directory level, never its parents: a deleted user's folder is never resurrected.
    fn ensure_dir(&self, dir: &std::path::Path) -> anyhow::Result<()> {
        match std::fs::create_dir(dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(anyhow::anyhow!(
                "cannot create {}: {e} (was the user deleted?)",
                dir.display()
            )),
        }
    }

    fn cache_dir(&self) -> PathBuf {
        self.spool_dir.join("cache")
    }

    /// Encrypted viewer cache (spool key), so repeated views don't re-download from a destination.
    pub fn cache_get(&self, message: i64) -> Option<Vec<u8>> {
        let path = self.cache_dir().join(format!("{message}.bin"));
        let blob = std::fs::read(&path).ok()?;
        let raw = crypto::open_blob(
            &self.spool_key,
            format!("cache:{message}").as_bytes(),
            &blob,
        )
        .ok()?;
        // Touch for LRU eviction.
        let _ = std::fs::File::options()
            .append(true)
            .open(&path)
            .and_then(|f| f.set_modified(std::time::SystemTime::now()));
        Some(raw.to_vec())
    }

    /// Stores a message in the viewer cache, evicting the least recently used entries above `max_bytes`.
    pub fn cache_put(&self, message: i64, raw: &[u8], max_bytes: u64) -> anyhow::Result<()> {
        if let Some(f) = crate::faults::pick(crate::faults::Site::Cache, &self.user_id) {
            return Err(crate::faults::io_error(f).into());
        }
        let dir = self.cache_dir();
        self.ensure_dir(&self.spool_dir)?;
        self.ensure_dir(&dir)?;
        let blob = crypto::seal_blob(&self.spool_key, format!("cache:{message}").as_bytes(), raw);
        let tmp = dir.join(format!("{message}.tmp"));
        std::fs::write(&tmp, blob)?;
        std::fs::rename(&tmp, dir.join(format!("{message}.bin")))?;
        let mut entries: Vec<(std::time::SystemTime, u64, PathBuf)> = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let m = e.metadata().ok()?;
                Some((m.modified().ok()?, m.len(), e.path()))
            })
            .collect();
        let mut total: u64 = entries.iter().map(|e| e.1).sum();
        entries.sort_by_key(|e| e.0);
        for (_, len, path) in entries {
            if total <= max_bytes {
                break;
            }
            let _ = std::fs::remove_file(path);
            total = total.saturating_sub(len);
        }
        Ok(())
    }
}

pub fn is_cancelled(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Cancelled>().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(dir: &std::path::Path) -> JobCtx {
        let archive = crypto::random_key();
        JobCtx {
            job_id: "t".into(),
            user_id: "u".into(),
            config: Arc::new(UserConfig::new(&archive)),
            archive_key: archive,
            index: Arc::new(Index::open_in_memory().unwrap()),
            spool_dir: dir.to_path_buf(),
            spool_key: crypto::random_key(),
            fs: FsPolicy {
                user_root: dir.to_path_buf(),
                allowed_mounts: vec![],
                user_id: "u".into(),
            },
            tokens: Arc::new(crate::oauth::TokenCache::new(Box::new(|_, _| {}))),
            events: Arc::new(NullSink),
            cancel: CancellationToken::new(),
            sealed: CancellationToken::new(),
            manual: false,
        }
    }

    #[test]
    fn spool_and_cache_are_encrypted_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path());
        let secret = b"Subject: very secret\r\n\r\nbody".to_vec();
        c.spool_put(1, &secret).unwrap();
        c.cache_put(1, &secret, 1 << 20).unwrap();
        for entry in walk(dir.path()) {
            let bytes = std::fs::read(&entry).unwrap();
            assert!(
                !bytes.windows(6).any(|w| w == b"secret"),
                "plaintext on disk in {entry:?}"
            );
        }
        assert_eq!(c.spool_get(1).unwrap(), secret);
        assert_eq!(c.cache_get(1).unwrap(), secret);
        // Eviction keeps the cache under its cap.
        for i in 2..20 {
            c.cache_put(i, &vec![7u8; 10_000], 50_000).unwrap();
        }
        let total: u64 = walk(&dir.path().join("cache"))
            .iter()
            .map(|p| std::fs::metadata(p).unwrap().len())
            .sum();
        assert!(total <= 50_000, "{total}");
        assert!(c.cache_get(19).is_some());
    }

    fn walk(p: &std::path::Path) -> Vec<PathBuf> {
        let mut out = vec![];
        for e in std::fs::read_dir(p).unwrap().flatten() {
            if e.path().is_dir() {
                out.extend(walk(&e.path()));
            } else {
                out.push(e.path());
            }
        }
        out
    }
}
