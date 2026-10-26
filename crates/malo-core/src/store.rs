//! Destinations: OpenDAL operators, object layout, encrypted write + read-back verification, manifests.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;

use anyhow::{anyhow, bail, Context};
use futures::TryStreamExt;
use malo_api::DestinationTest;
use opendal::{ErrorKind, Operator, Scheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Account, Destination};
use crate::crypto::{self, Key, StreamDecryptor};
use crate::faults;
use crate::layout::{self, NameKey};

/// Where `fs` destinations may write.
#[derive(Debug, Clone)]
pub struct FsPolicy {
    /// `<data>/users/<id>/local`: relative fs roots resolve here.
    pub user_root: PathBuf,
    /// Admin allow-listed absolute mount points (each user gets `<mount>/<user-id>/`).
    pub allowed_mounts: Vec<PathBuf>,
    /// Owner of the destinations; names the per-user subfolder inside shared mounts that were
    /// first used before `owner_dir` existed.
    pub user_id: String,
    /// Keyed folder name of the owner (`NameKey::owner_dir`): the subfolder inside a shared mount
    /// when there's no older `<mount>/<user-id>/` folder.
    pub owner_dir: Option<String>,
}

pub struct Store {
    pub dest: Destination,
    op: Operator,
    names: NameKey,
    archive_key: Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verify {
    Ok,
    Missing,
    Corrupt(String),
}

/// One line of a mailbox manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestEntry {
    pub account_id: String,
    pub mailbox: String,
    pub mailbox_display: String,
    pub delimiter: Option<String>,
    pub special_use: Option<String>,
    pub uidvalidity: u32,
    pub uid: u32,
    pub sha256: String,
    pub size: u64,
    pub flags: Vec<String>,
    pub labels: Vec<String>,
    pub internaldate: Option<chrono::DateTime<chrono::Utc>>,
    pub gm_msgid: Option<String>,
    pub message_id: Option<String>,
    pub object_path: String,
    pub envelope: malo_api::Envelope,
}

/// Result of [`Store::scan`].
pub struct Scan {
    /// With the account directory each was found in (an account renamed on a plain destination
    /// has one directory per name).
    pub markers: Vec<(String, AccountMarker)>,
    pub entries: Vec<(String, ManifestEntry)>,
    /// Markers, manifests or manifest lines that couldn't be decrypted or parsed.
    pub unreadable: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMarker {
    pub account_id: String,
    pub name: String,
    pub host: String,
    pub username: String,
    /// Manifest generation of this account on this destination: raised by every complete manifest
    /// write and written last, so a higher number always means newer manifests (0: unknown/legacy).
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub written_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug)]
pub enum MarkerRead {
    Absent,
    /// Present but undecodable: nothing can be said about the manifests next to it.
    Damaged,
    Found(AccountMarker),
}

fn has_parent_refs(p: &Path) -> bool {
    p.components().any(|c| matches!(c, Component::ParentDir))
}

/// Creates `rel` below `base` one directory at a time, re-checking after every step that the real
/// (symlink-resolved) path is still inside `base`. Nothing is ever created outside it.
fn create_within(base: &Path, rel: &Path) -> anyhow::Result<PathBuf> {
    let real_base = base
        .canonicalize()
        .with_context(|| format!("{} does not exist", base.display()))?;
    let mut cur = real_base.clone();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => {
                let next = cur.join(c);
                match std::fs::create_dir(&next) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => {
                        return Err(e).with_context(|| format!("cannot create {}", next.display()))
                    }
                }
                let real = next.canonicalize()?;
                if !real.starts_with(&real_base) || !real.is_dir() {
                    bail!("fs root escapes its allowed directory");
                }
                cur = real;
            }
            Component::CurDir => {}
            _ => bail!("fs root must be a plain path without '..'"),
        }
    }
    Ok(cur)
}

/// Resolves the effective fs root. Relative roots live in the user's own directory; absolute roots
/// must be inside an admin-allowed mount and are placed in a per-user subfolder of it
/// (`<mount>/<user-id>/<rest>`), so users sharing a mount can never touch each other's files.
pub fn confine_fs_root(requested: Option<&str>, policy: &FsPolicy) -> anyhow::Result<PathBuf> {
    let req = requested.unwrap_or("").trim();
    if req.contains('\0') {
        bail!("fs root contains a NUL byte");
    }
    let p = Path::new(req);
    if has_parent_refs(p) {
        bail!("fs root must not contain '..'");
    }
    if p.is_absolute() {
        for m in &policy.allowed_mounts {
            if !m.is_absolute() || has_parent_refs(m) {
                continue;
            }
            if let Ok(rest) = p.strip_prefix(m) {
                // First the user's own subfolder (checked against the mount), then everything below
                // it is checked against that subfolder, so symlinks can't reach other users' folders.
                // A folder named after the user id predates keyed names and is kept, unless the
                // keyed folder is already in use: a user-id folder appearing later must not move
                // the backups somewhere else.
                let sub = match &policy.owner_dir {
                    Some(o) if m.join(o).exists() || !m.join(&policy.user_id).exists() => {
                        o.as_str()
                    }
                    _ => policy.user_id.as_str(),
                };
                let mut comps = Path::new(sub).components();
                if !matches!(
                    (comps.next(), comps.next()),
                    (Some(Component::Normal(_)), None)
                ) {
                    bail!("invalid owner folder for a shared mount");
                }
                let own = create_within(m, Path::new(sub))?;
                return create_within(&own, rest);
            }
        }
        bail!(
            "fs path {} is outside the allowed mounts; ask an admin to allow it",
            p.display()
        );
    }
    // The user's own folder must already exist (it's created with the user): never recreate it.
    if let Some(parent) = policy.user_root.parent() {
        if !parent.exists() {
            bail!("user data folder {} no longer exists", parent.display());
        }
    }
    match std::fs::create_dir(&policy.user_root) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(e).with_context(|| format!("cannot create {}", policy.user_root.display()))
        }
    }
    create_within(&policy.user_root, p)
}

const MAX_PREFIX_BYTES: usize = 512;

/// Rejects destination settings that could reach outside their storage area: `..` in the prefix or
/// any `*root` option, and options that make the server read one of its own files
/// (`credential_path`, `config_file`, …).
pub fn validate_destination(dest: &Destination) -> anyhow::Result<()> {
    layout::check_rel_path(&dest.root).context("destination prefix")?;
    // Object keys are limited (S3: 1024 bytes, file names: 255 bytes per component) and Malo's
    // own paths below the prefix need room: a longer prefix could never hold a backup.
    if dest.root.len() > MAX_PREFIX_BYTES {
        bail!("destination prefix is too long (max. {MAX_PREFIX_BYTES} bytes)");
    }
    if dest.root.split('/').any(|seg| seg.len() > 255) {
        bail!("a folder name in the destination prefix is too long (max. 255 bytes)");
    }
    for (k, v) in &dest.options {
        let key = k.to_ascii_lowercase();
        if key.ends_with("_path") || key.ends_with("_file") || key == "path" || key == "file" {
            bail!("option '{k}' would read a file on the server; paste its content instead (e.g. 'credential')");
        }
        if key.ends_with("root") && !dest.scheme.eq_ignore_ascii_case("fs") {
            layout::check_rel_path(v.trim_start_matches('/'))
                .with_context(|| format!("option '{k}'"))?;
        }
    }
    Ok(())
}

impl Store {
    pub fn open(dest: &Destination, archive_key: &Key, fs: &FsPolicy) -> anyhow::Result<Store> {
        let scheme = Scheme::from_str(&dest.scheme)
            .map_err(|e| anyhow!("unknown scheme {}: {e}", dest.scheme))?;
        validate_destination(dest)?;
        let mut opts: HashMap<String, String> = dest.options.clone().into_iter().collect();
        // Never pick up the server's own config files or environment (~/.aws/config, gcloud ADC…):
        // a destination only uses the credentials its owner entered.
        if matches!(scheme, Scheme::S3 | Scheme::Gcs) {
            opts.insert("disable_config_load".into(), "true".into());
        }
        if scheme == Scheme::Fs {
            let root = confine_fs_root(opts.get("root").map(String::as_str), fs)?;
            opts.insert("root".into(), root.to_string_lossy().into_owned());
        }
        // Own HTTP client per operator: OpenDAL's global client is bound to the first tokio runtime that used it.
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()
            .context("http client")?;
        let op = Operator::via_iter(scheme, opts)
            .with_context(|| format!("cannot configure {}", dest.scheme))?
            .layer(opendal::layers::HttpClientLayer::new(
                opendal::raw::HttpClient::with(http),
            ))
            .layer(
                opendal::layers::RetryLayer::new()
                    .with_max_times(4)
                    .with_jitter(),
            );
        Ok(Store {
            dest: dest.clone(),
            op,
            names: NameKey::new(archive_key),
            archive_key: archive_key.clone(),
        })
    }

    fn settings_path(&self) -> String {
        self.portable(self.names.settings_backup(&self.dest.root))
    }

    /// Writes the encrypted settings copy. Always encrypted with the archive key, also on a plain
    /// destination: it holds the credentials of every account and destination.
    pub async fn write_settings_backup(&self, json: &[u8]) -> anyhow::Result<()> {
        let path = self.settings_path();
        let path = self.checked(&path)?;
        self.write_obj(path, crypto::encrypt_object(&self.archive_key, json))
            .await
    }

    /// The settings copy, or `None` when the destination has none.
    pub async fn read_settings_backup(
        &self,
    ) -> anyhow::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        let path = self.settings_path();
        let path = self.checked(&path)?;
        match self.op.stat(path).await {
            Ok(_) => {}
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("stat {path}")),
        }
        let raw = self.read_obj(path).await?;
        let json = crypto::decrypt_object(&self.archive_key, &raw)
            .map_err(|_| anyhow!("the settings copy on {} can't be decrypted", self.dest.name))?;
        Ok(Some(zeroize::Zeroizing::new(json)))
    }

    /// For tests: wrap an existing operator.
    pub fn from_operator(dest: &Destination, op: Operator, archive_key: &Key) -> Store {
        Store {
            dest: dest.clone(),
            op,
            names: NameKey::new(archive_key),
            archive_key: archive_key.clone(),
        }
    }

    pub fn operator(&self) -> &Operator {
        &self.op
    }

    /// All uploads go through here (fault injection in test builds).
    async fn write_obj(&self, path: &str, mut data: Vec<u8>) -> anyhow::Result<()> {
        use faults::Fault;
        match faults::pick(faults::Site::StoreWrite, &self.dest.id) {
            None => {}
            Some(f @ (Fault::Error | Fault::NoSpace)) => {
                return Err(faults::io_error(f)).with_context(|| format!("write {path}"))
            }
            Some(Fault::Truncate) => data.truncate(data.len() / 2),
            Some(Fault::FlipBit) => {
                if !data.is_empty() {
                    let i = data.len() / 2;
                    data[i] ^= 0x10;
                }
            }
            Some(Fault::LostWrite) => return Ok(()),
            Some(Fault::WriteThenError) => {
                self.op.write(path, data).await?;
                return Err(faults::io_error(Fault::Error))
                    .with_context(|| format!("write {path}"));
            }
            Some(Fault::Slow) => tokio::time::sleep(std::time::Duration::from_millis(300)).await,
        }
        self.op
            .write(path, data)
            .await
            .with_context(|| format!("write {path}"))?;
        Ok(())
    }

    /// All whole-object downloads go through here (fault injection in test builds).
    async fn read_obj(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let buf = self
            .op
            .read(path)
            .await
            .with_context(|| format!("read {path}"))?
            .to_vec();
        match faults::pick(faults::Site::StoreRead, &self.dest.id) {
            Some(faults::Fault::Slow) => {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                Ok(buf)
            }
            Some(f) => faults::corrupt_read(f, buf).with_context(|| format!("read {path}")),
            None => Ok(buf),
        }
    }

    /// stat / list / delete faults (test builds).
    fn meta_fault(&self, what: &str) -> anyhow::Result<()> {
        match faults::pick(faults::Site::StoreMeta, &self.dest.id) {
            Some(faults::Fault::Slow) | None => Ok(()),
            Some(f) => Err(faults::io_error(f)).with_context(|| what.to_string()),
        }
    }

    /// Every path handed to the backend is checked: no `..`, `.`, backslashes or drive letters.
    fn checked<'a>(&self, path: &'a str) -> anyhow::Result<&'a str> {
        layout::check_rel_path(path)?;
        Ok(path)
    }

    pub fn account_dir(&self, account: &Account) -> String {
        if self.dest.encrypt {
            self.names.account_dir(&account.id)
        } else {
            layout::plain_account_dir(&account.id, &account.name)
        }
    }

    pub fn account_root(&self, account: &Account) -> String {
        self.portable(layout::join(&[&self.dest.root, &self.account_dir(account)]))
    }

    /// The destination root as stored on the backend.
    pub fn root_prefix(&self) -> String {
        self.portable(self.dest.root.clone())
    }

    fn portable(&self, path: String) -> String {
        if self.dest.scheme.eq_ignore_ascii_case("gcs") {
            layout::ascii_path(&path)
        } else {
            path
        }
    }

    /// Object path of one message. Encrypted objects are content-addressed (deduplicated).
    pub fn object_path(
        &self,
        account: &Account,
        mailbox_path: &str,
        uidvalidity: u32,
        uid: u32,
        sha256: &str,
    ) -> String {
        let dir = self.account_dir(account);
        self.portable(if self.dest.encrypt {
            self.names.object_path(&self.dest.root, &dir, sha256)
        } else {
            layout::plain_object_path(&self.dest.root, &dir, mailbox_path, uidvalidity, uid)
        })
    }

    pub fn manifest_path(&self, account: &Account, mailbox: &str, mailbox_path: &str) -> String {
        let dir = self.account_dir(account);
        self.portable(if self.dest.encrypt {
            self.names.manifest_path(&self.dest.root, &dir, mailbox)
        } else {
            layout::plain_manifest_path(&self.dest.root, &dir, mailbox_path)
        })
    }

    fn encode(&self, plaintext: &[u8]) -> Vec<u8> {
        if self.dest.encrypt {
            crypto::encrypt_object(&self.archive_key, plaintext)
        } else {
            plaintext.to_vec()
        }
    }

    /// Writes an object (skipping identical existing encrypted objects) and reads it back to verify.
    /// Returns the stored size.
    pub async fn put_verified(
        &self,
        path: &str,
        plaintext: &[u8],
        sha256: &str,
    ) -> anyhow::Result<u64> {
        let path = self.checked(path)?;
        if self.dest.encrypt {
            if let Verify::Ok = self
                .verify(path, true, sha256, plaintext.len() as u64, true)
                .await?
            {
                return Ok(crypto::encrypted_len(plaintext.len() as u64));
            }
        }
        let data = self.encode(plaintext);
        let len = data.len() as u64;
        self.write_obj(path, data).await?;
        match self
            .verify(
                path,
                self.dest.encrypt,
                sha256,
                plaintext.len() as u64,
                true,
            )
            .await?
        {
            Verify::Ok => Ok(len),
            Verify::Missing => bail!("object {path} missing right after write"),
            Verify::Corrupt(e) => bail!("read-back of {path} failed: {e}"),
        }
    }

    /// Reads and decodes an object.
    pub async fn get(&self, path: &str, encrypted: bool) -> anyhow::Result<Vec<u8>> {
        let path = self.checked(path)?;
        let buf = self.read_obj(path).await?;
        if encrypted {
            Ok(crypto::decrypt_object(&self.archive_key, &buf)?)
        } else {
            Ok(buf)
        }
    }

    /// Stat (quick) or download + decrypt + hash (deep).
    pub async fn verify(
        &self,
        path: &str,
        encrypted: bool,
        sha256: &str,
        size: u64,
        deep: bool,
    ) -> anyhow::Result<Verify> {
        let path = self.checked(path)?;
        let expected_len = if encrypted {
            crypto::encrypted_len(size)
        } else {
            size
        };
        self.meta_fault(&format!("stat {path}"))?;
        let meta = match self.op.stat(path).await {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Verify::Missing),
            Err(e) => return Err(e.into()),
        };
        if meta.content_length() != expected_len {
            return Ok(Verify::Corrupt(format!(
                "size {} ≠ expected {expected_len}",
                meta.content_length()
            )));
        }
        if !deep {
            return Ok(Verify::Ok);
        }
        let reader = match self.op.reader(path).await {
            Ok(r) => r,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Verify::Missing),
            Err(e) => return Err(e.into()),
        };
        let mut stream = reader.into_bytes_stream(..).await?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut dec = encrypted.then(|| StreamDecryptor::new(&self.archive_key));
        let mut read_fault = faults::pick(faults::Site::StoreRead, &self.dest.id);
        if let Some(f @ (faults::Fault::Error | faults::Fault::NoSpace)) = read_fault {
            return Err(faults::io_error(f)).with_context(|| format!("read {path}"));
        }
        while let Some(chunk) = stream.try_next().await? {
            let chunk = match read_fault.take() {
                Some(faults::Fault::FlipBit) => {
                    let mut c = chunk.to_vec();
                    if let Some(b) = c.get_mut(0) {
                        *b ^= 0x10;
                    }
                    bytes::Bytes::from(c)
                }
                // The connection drops after the first chunk.
                Some(faults::Fault::Truncate) => {
                    return Err(faults::io_error(faults::Fault::Error))
                        .with_context(|| format!("read {path}: connection reset"))
                }
                _ => chunk,
            };
            match dec.as_mut() {
                Some(d) => match d.update(&chunk) {
                    Ok(pt) => {
                        total += pt.len() as u64;
                        hasher.update(&pt);
                    }
                    Err(e) => return Ok(Verify::Corrupt(e.to_string())),
                },
                None => {
                    total += chunk.len() as u64;
                    hasher.update(&chunk);
                }
            }
        }
        if let Some(d) = dec {
            match d.finish() {
                Ok(pt) => {
                    total += pt.len() as u64;
                    hasher.update(&pt);
                }
                Err(e) => return Ok(Verify::Corrupt(e.to_string())),
            }
        }
        let got = hex::encode(hasher.finalize());
        if total != size || got != sha256 {
            return Ok(Verify::Corrupt(format!(
                "sha256 mismatch ({} bytes)",
                total
            )));
        }
        Ok(Verify::Ok)
    }

    pub async fn delete(&self, path: &str) -> anyhow::Result<()> {
        let path = self.checked(path)?;
        self.meta_fault(&format!("delete {path}"))?;
        self.op.delete(path).await?;
        Ok(())
    }

    /// All files under `prefix` with their sizes.
    pub async fn list_files(&self, prefix: &str) -> anyhow::Result<HashMap<String, u64>> {
        let prefix = self.checked(prefix)?;
        let dir = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        let mut out = HashMap::new();
        self.meta_fault(&format!("list {dir}"))?;
        let mut lister = match self.op.lister_with(&dir).recursive(true).await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = lister.try_next().await? {
            if entry.metadata().is_file() {
                out.insert(
                    entry.path().trim_start_matches('/').to_string(),
                    entry.metadata().content_length(),
                );
            }
        }
        // Some services don't return sizes when listing; fill them in by stat.
        for (path, size) in out.iter_mut() {
            if *size == 0 {
                if let Ok(m) = self.op.stat(path).await {
                    *size = m.content_length();
                }
            }
        }
        Ok(out)
    }

    fn marker_path(&self, account: &Account) -> String {
        let name = if self.dest.encrypt {
            "account.json.enc"
        } else {
            "account.json"
        };
        layout::join(&[&self.account_root(account), name])
    }

    pub async fn write_account_marker(
        &self,
        account: &Account,
        generation: u64,
    ) -> anyhow::Result<()> {
        let marker = AccountMarker {
            account_id: account.id.clone(),
            name: account.name.clone(),
            host: account.host.clone(),
            username: account.username.clone(),
            generation,
            written_at: Some(chrono::Utc::now()),
        };
        let json = serde_json::to_vec_pretty(&marker)?;
        self.write_obj(&self.marker_path(account), self.encode(&json))
            .await
    }

    /// The account's marker on this destination. Storage errors are returned.
    pub async fn read_account_marker(&self, account: &Account) -> anyhow::Result<MarkerRead> {
        let path = self.marker_path(account);
        let path = self.checked(&path)?;
        self.meta_fault(&format!("stat {path}"))?;
        match self.op.stat(path).await {
            Ok(_) => {}
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => return Ok(MarkerRead::Absent),
            Err(e) => return Err(e).with_context(|| format!("stat {path}")),
        }
        let raw = self.read_obj(path).await?;
        let body = if self.dest.encrypt {
            match crypto::decrypt_object(&self.archive_key, &raw) {
                Ok(b) => b,
                Err(_) => return Ok(MarkerRead::Damaged),
            }
        } else {
            raw
        };
        Ok(serde_json::from_slice(&body).map_or(MarkerRead::Damaged, MarkerRead::Found))
    }

    /// Rewrites one mailbox manifest. Write is followed by a read-back check.
    pub async fn write_manifest(
        &self,
        path: &str,
        entries: &[ManifestEntry],
    ) -> anyhow::Result<()> {
        let path = self.checked(path)?;
        let mut body = Vec::new();
        for e in entries {
            serde_json::to_writer(&mut body, e)?;
            body.push(b'\n');
        }
        let sha = crypto::sha256_hex(&body);
        let data = self.encode(&body);
        self.write_obj(path, data)
            .await
            .with_context(|| format!("write manifest {path}"))?;
        match self
            .verify(path, self.dest.encrypt, &sha, body.len() as u64, true)
            .await?
        {
            Verify::Ok => Ok(()),
            other => bail!("manifest {path} failed read-back: {other:?}"),
        }
    }

    pub async fn read_manifest(&self, path: &str) -> anyhow::Result<Vec<ManifestEntry>> {
        let path = self.checked(path)?;
        let body = self.get(path, self.dest.encrypt).await?;
        body.split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).map_err(Into::into))
            .collect()
    }

    /// Every account marker and manifest entry found on this destination (index rebuild).
    /// Reads every account marker and manifest it can. Files it can't decrypt or parse — another
    /// user's backups sharing the same storage, or foreign files — are skipped and counted, so one
    /// user's data can never break another user's rebuild. Storage errors still fail the scan.
    pub async fn scan(&self) -> anyhow::Result<Scan> {
        self.scan_in(&self.root_prefix()).await
    }

    /// [`Store::scan`] limited to one directory (one account's).
    pub async fn scan_in(&self, prefix: &str) -> anyhow::Result<Scan> {
        let files = self.list_files(prefix).await?;
        let mut markers = Vec::new();
        let mut entries = Vec::new();
        let (marker_name, manifest_suffix) = if self.dest.encrypt {
            ("account.json.enc", ".jsonl.enc")
        } else {
            ("account.json", ".jsonl")
        };
        let mut unreadable = 0;
        for path in files.keys() {
            let is_marker = path.ends_with(&format!("/{marker_name}"));
            let is_manifest = path.contains("/manifest/") && path.ends_with(manifest_suffix);
            if !is_marker && !is_manifest {
                continue;
            }
            let dir = if is_marker {
                path.rsplit_once('/').map(|(d, _)| d)
            } else {
                path.rsplit_once("/manifest/").map(|(d, _)| d)
            }
            .unwrap_or_default()
            .to_string();
            let raw = self.read_obj(self.checked(path)?).await?;
            let body = if self.dest.encrypt {
                match crypto::decrypt_object(&self.archive_key, &raw) {
                    Ok(b) => b,
                    Err(_) => {
                        unreadable += 1;
                        continue;
                    }
                }
            } else {
                raw
            };
            if is_marker {
                match serde_json::from_slice(&body) {
                    Ok(m) => markers.push((dir, m)),
                    Err(_) => unreadable += 1,
                }
            } else {
                for line in body.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    match serde_json::from_slice(line) {
                        Ok(e) => entries.push((dir.clone(), e)),
                        Err(_) => unreadable += 1,
                    }
                }
            }
        }
        if unreadable > 0 {
            tracing::info!(dest = %self.dest.name, "scan skipped {unreadable} file(s)/line(s) it can't read (other users' data?)");
        }
        Ok(Scan {
            markers,
            entries,
            unreadable,
        })
    }

    /// Writes, reads back and deletes a probe object.
    pub async fn test(&self) -> DestinationTest {
        let path = self.portable(layout::join(&[
            &self.dest.root,
            &format!(".malo-probe-{}", uuid::Uuid::new_v4()),
        ]));
        let data = crypto::random_bytes::<64>().to_vec();
        let t0 = Instant::now();
        if let Err(e) = self.op.write(&path, data.clone()).await {
            return DestinationTest {
                ok: false,
                error: Some(format!("write failed: {e}")),
                write_ms: 0,
                read_ms: 0,
            };
        }
        let write_ms = t0.elapsed().as_millis() as u64;
        let t1 = Instant::now();
        let read = self.op.read(&path).await.map(|b| b.to_vec());
        let read_ms = t1.elapsed().as_millis() as u64;
        let del = self.op.delete(&path).await;
        let error = match (read, del) {
            (Ok(b), _) if b != data => Some("read-back returned different bytes".to_string()),
            (Err(e), _) => Some(format!("read failed: {e}")),
            (_, Err(e)) => Some(format!("delete failed: {e}")),
            _ => None,
        };
        DestinationTest {
            ok: error.is_none(),
            error,
            write_ms,
            read_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use malo_api::{DeepCheckMode, TlsMode};
    use opendal::services::Memory;

    pub fn dest(encrypt: bool) -> Destination {
        Destination {
            revision: 1,
            id: "d1".into(),
            name: "mem".into(),
            scheme: "memory".into(),
            options: Default::default(),
            root: "backup".into(),
            encrypt,
            required_for_purge: true,
            deep_check: DeepCheckMode::Full,
        }
    }

    fn account() -> Account {
        Account {
            revision: 1,
            id: "0123456789abcdef".into(),
            name: "Work".into(),
            host: "h".into(),
            port: 993,
            tls: TlsMode::Implicit,
            accept_invalid_certs: false,
            username: "u".into(),
            auth: malo_api::AccountAuth::Password {
                password: "p".into(),
            },
            backup_interval_minutes: 30,
            idle: false,
            enabled: true,
            imported: false,
            policy: Default::default(),
        }
    }

    #[tokio::test]
    async fn write_verify_detect_corruption() {
        for encrypt in [false, true] {
            let k = crypto::random_key();
            let store = Store::from_operator(
                &dest(encrypt),
                Operator::new(Memory::default()).unwrap().finish(),
                &k,
            );
            let msg = b"From: a@b\r\nSubject: hi\r\n\r\nbody".repeat(5000);
            let sha = crypto::sha256_hex(&msg);
            let path = store.object_path(&account(), "INBOX", 1, 2, &sha);
            if encrypt {
                assert!(!path.contains("INBOX") && path.ends_with(".enc"));
            } else {
                assert_eq!(
                    path,
                    "backup/Work_01234567/mailboxes/INBOX/1-83ecb521/2.eml"
                );
            }
            store.put_verified(&path, &msg, &sha).await.unwrap();
            assert_eq!(store.get(&path, encrypt).await.unwrap(), msg);
            assert_eq!(
                store
                    .verify(&path, encrypt, &sha, msg.len() as u64, true)
                    .await
                    .unwrap(),
                Verify::Ok
            );
            // Flip one byte → deep check says corrupt, quick says ok (same size).
            let mut raw = store.operator().read(&path).await.unwrap().to_vec();
            raw[100] ^= 1;
            store.operator().write(&path, raw).await.unwrap();
            assert!(matches!(
                store
                    .verify(&path, encrypt, &sha, msg.len() as u64, true)
                    .await
                    .unwrap(),
                Verify::Corrupt(_)
            ));
            assert_eq!(
                store
                    .verify(&path, encrypt, &sha, msg.len() as u64, false)
                    .await
                    .unwrap(),
                Verify::Ok
            );
            store.delete(&path).await.unwrap();
            assert_eq!(
                store
                    .verify(&path, encrypt, &sha, msg.len() as u64, false)
                    .await
                    .unwrap(),
                Verify::Missing
            );
            let files = store.list_files("backup").await.unwrap();
            assert!(files.is_empty());
        }
    }

    #[tokio::test]
    async fn manifests_round_trip() {
        let k = crypto::random_key();
        let store = Store::from_operator(
            &dest(true),
            Operator::new(Memory::default()).unwrap().finish(),
            &k,
        );
        let a = account();
        assert!(matches!(
            store.read_account_marker(&a).await.unwrap(),
            MarkerRead::Absent
        ));
        store.write_account_marker(&a, 7).await.unwrap();
        let MarkerRead::Found(back) = store.read_account_marker(&a).await.unwrap() else {
            panic!("marker not found");
        };
        assert_eq!(
            (back.account_id.as_str(), back.generation),
            (a.id.as_str(), 7)
        );
        let e = ManifestEntry {
            account_id: a.id.clone(),
            mailbox: "INBOX".into(),
            mailbox_display: "INBOX".into(),
            delimiter: Some("/".into()),
            special_use: None,
            uidvalidity: 1,
            uid: 2,
            sha256: "ab".into(),
            size: 3,
            flags: vec![],
            labels: vec![],
            internaldate: None,
            gm_msgid: None,
            message_id: None,
            object_path: "x".into(),
            envelope: crate::index::empty_envelope(),
        };
        let path = store.manifest_path(&a, "INBOX", "INBOX");
        store
            .write_manifest(&path, std::slice::from_ref(&e))
            .await
            .unwrap();
        let scan = store.scan().await.unwrap();
        let (markers, entries) = (scan.markers, scan.entries);
        assert_eq!(scan.unreadable, 0);
        // Another key's data in the same place is skipped, not fatal.
        let other =
            Store::from_operator(&dest(true), store.operator().clone(), &crypto::random_key());
        let foreign = other.scan().await.unwrap();
        assert!(foreign.markers.is_empty() && foreign.entries.is_empty());
        assert_eq!(foreign.unreadable, 2);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].1.name, "Work");
        assert_eq!(markers[0].0, store.account_root(&a));
        assert_eq!(entries, vec![(store.account_root(&a), e)]);
        let mpath = store.marker_path(&a);
        store.operator().write(&mpath, vec![1u8; 40]).await.unwrap();
        assert!(matches!(
            store.read_account_marker(&a).await.unwrap(),
            MarkerRead::Damaged
        ));
    }

    #[test]
    fn fs_confinement() {
        let dir = tempfile::tempdir().unwrap();
        let user_root = dir.path().join("users/u1/local");
        let mount = dir.path().join("mnt");
        std::fs::create_dir_all(&mount).unwrap();
        // User folders exist from registration on; confinement never creates them.
        std::fs::create_dir_all(dir.path().join("users/u1")).unwrap();
        std::fs::create_dir_all(dir.path().join("users/u2")).unwrap();
        assert!(
            confine_fs_root(
                Some("x"),
                &FsPolicy {
                    user_root: dir.path().join("users/gone/local"),
                    allowed_mounts: vec![],
                    user_id: "gone".into(),
                    owner_dir: None,
                }
            )
            .is_err(),
            "a deleted user's folder must not be recreated"
        );
        assert!(!dir.path().join("users/gone").exists());
        let policy = |user: &str| FsPolicy {
            user_root: dir.path().join(format!("users/{user}/local")),
            allowed_mounts: vec![mount.clone()],
            user_id: user.into(),
            owner_dir: None,
        };
        let p1 = policy("u1");
        let r = confine_fs_root(Some("backups/a"), &p1).unwrap();
        assert!(r.starts_with(user_root.canonicalize().unwrap()));
        for bad in [
            "..",
            "../../etc",
            "backups/../../..",
            "./../x",
            "/etc",
            "/",
            "x\0y",
        ] {
            assert!(confine_fs_root(Some(bad), &p1).is_err(), "{bad:?} accepted");
        }
        let escape = format!("{}/../outside", mount.display());
        assert!(confine_fs_root(Some(&escape), &p1).is_err());
        assert!(!dir.path().join("outside").exists());

        // Shared mounts: every user lands in their own subfolder, even for the same requested path.
        let shared = mount.join("family/backups");
        let a = confine_fs_root(Some(shared.to_str().unwrap()), &p1).unwrap();
        let b = confine_fs_root(Some(shared.to_str().unwrap()), &policy("u2")).unwrap();
        let real_mount = mount.canonicalize().unwrap();
        assert_eq!(a, real_mount.join("u1/family/backups"));
        assert_eq!(b, real_mount.join("u2/family/backups"));

        // With a keyed owner folder, a new user holding the same archive key (restored from the
        // recovery kit) finds the same files; an existing `<mount>/<user-id>/` folder is kept.
        let keyed = |user: &str| FsPolicy {
            owner_dir: Some("k0ffee".into()),
            ..policy(user)
        };
        assert_eq!(
            confine_fs_root(Some(shared.to_str().unwrap()), &keyed("u1")).unwrap(),
            a
        );
        assert_eq!(
            confine_fs_root(Some(shared.to_str().unwrap()), &keyed("u3")).unwrap(),
            real_mount.join("k0ffee/family/backups")
        );
        assert_eq!(
            confine_fs_root(Some(shared.to_str().unwrap()), &keyed("u4")).unwrap(),
            real_mount.join("k0ffee/family/backups")
        );
        // A user-id folder showing up later doesn't move a keyed user's backups.
        std::fs::create_dir_all(mount.join("u3")).unwrap();
        assert_eq!(
            confine_fs_root(Some(shared.to_str().unwrap()), &keyed("u3")).unwrap(),
            real_mount.join("k0ffee/family/backups")
        );

        #[cfg(unix)]
        {
            // Symlinks can't lead out, and nothing gets created on the far side.
            let outside = dir.path().join("victim");
            std::fs::create_dir_all(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, user_root.join("escape")).unwrap();
            assert!(confine_fs_root(Some("escape/new"), &p1).is_err());
            assert!(
                !outside.join("new").exists(),
                "created a directory outside the user root"
            );
            // Another user's subfolder in a shared mount can't be reached via a symlink either.
            std::os::unix::fs::symlink(real_mount.join("u2"), real_mount.join("u1/peek")).unwrap();
            let peek = mount.join("peek/family");
            assert!(confine_fs_root(Some(peek.to_str().unwrap()), &p1).is_err());
        }
    }

    #[test]
    fn destination_validation() {
        let mut d = dest(false);
        for root in ["..", "a/../..", "./x", "C:/x", "a\\b"] {
            d.root = root.into();
            assert!(
                validate_destination(&d).is_err(),
                "prefix {root:?} accepted"
            );
        }
        d.root = "malo/backups".into();
        assert!(validate_destination(&d).is_ok());
        for key in ["credential_path", "config_file", "CREDENTIAL_PATH", "path"] {
            let mut d = dest(false);
            d.options.insert(key.into(), "/etc/passwd".into());
            assert!(validate_destination(&d).is_err(), "option {key} accepted");
        }
        let mut d = dest(false);
        d.scheme = "s3".into();
        d.options.insert("root".into(), "/a/../../b".into());
        assert!(validate_destination(&d).is_err());
    }

    #[tokio::test]
    async fn store_rejects_traversal_paths() {
        let k = crypto::random_key();
        let store = Store::from_operator(
            &dest(false),
            Operator::new(Memory::default()).unwrap().finish(),
            &k,
        );
        for bad in ["../x", "a/../../b", "./a"] {
            assert!(store.get(bad, false).await.is_err());
            assert!(store
                .put_verified(bad, b"x", &crypto::sha256_hex(b"x"))
                .await
                .is_err());
            assert!(store.delete(bad).await.is_err());
            assert!(store.list_files(bad).await.is_err());
        }
    }
}
