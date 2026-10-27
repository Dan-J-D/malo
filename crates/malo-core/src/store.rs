//! Destinations: OpenDAL operators, object layout, encrypted write + read-back verification, manifests.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context};
use futures::TryStreamExt;
use malo_api::DestinationTest;
use opendal::{ErrorKind, Operator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Account, Destination};
use crate::crypto::{self, Key, StreamDecryptor};
use crate::faults;
use crate::layout::{self, NameKey};
use crate::objectlock::Locker;
use crate::ratelimit::{self, Limiter};

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
    /// Speed limits of this destination (shared with every job using it).
    up: Arc<Limiter>,
    down: Arc<Limiter>,
    /// Sets Object Lock retention on message objects (S3 and B2 with Object Lock set).
    locker: Option<Arc<Locker>>,
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
    /// Size of the object on this destination. Absent in manifests from before compression,
    /// whose objects all have the size [`crypto::encrypted_len`] (or the plain size) gives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_size: Option<u64>,
    /// Collections the message is in, by name (one list per message, repeated in each of its
    /// entries).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collections: Vec<String>,
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

/// Size of an object stored without compression: what manifests and replicas from before
/// compression imply.
pub fn expected_stored_len(encrypted: bool, size: u64) -> u64 {
    if encrypted {
        crypto::encrypted_len(size)
    } else {
        size
    }
}

/// The object was written compressed (by its name: see [`NameKey::compressed_object_path`]).
pub fn is_compressed_path(path: &str) -> bool {
    path.ends_with(".z.enc")
}

/// The OpenDAL services a destination can use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Scheme {
    S3,
    Gcs,
    Azblob,
    Webdav,
    B2,
    Fs,
}

impl Scheme {
    fn parse(s: &str) -> anyhow::Result<Scheme> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "s3" => Scheme::S3,
            "gcs" => Scheme::Gcs,
            "azblob" => Scheme::Azblob,
            "webdav" => Scheme::Webdav,
            "b2" => Scheme::B2,
            "fs" => Scheme::Fs,
            _ => bail!("{s} can't be used as a destination"),
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Scheme::S3 => "s3",
            Scheme::Gcs => "gcs",
            Scheme::Azblob => "azblob",
            Scheme::Webdav => "webdav",
            Scheme::B2 => "b2",
            Scheme::Fs => "fs",
        }
    }
}

/// The OpenDAL options a destination may set, per service (with the aliases OpenDAL accepts).
/// Everything else is refused: options that make the server use its own identity (an instance
/// role, a VM service account, `role_arn`), read its own files, or that a future OpenDAL adds.
fn allowed_options(scheme: Scheme) -> &'static [&'static str] {
    match scheme {
        Scheme::S3 => &[
            "root",
            "bucket",
            "aws_bucket",
            "aws_bucket_name",
            "bucket_name",
            "endpoint",
            "aws_endpoint",
            "aws_endpoint_url",
            "endpoint_url",
            "region",
            "aws_region",
            "access_key_id",
            "aws_access_key_id",
            "secret_access_key",
            "aws_secret_access_key",
            "session_token",
            "aws_session_token",
            "aws_token",
            "token",
            "allow_anonymous",
            "skip_signature",
            "server_side_encryption",
            "aws_server_side_encryption",
            "server_side_encryption_aws_kms_key_id",
            "aws_sse_kms_key_id",
            "server_side_encryption_customer_algorithm",
            "server_side_encryption_customer_key",
            "aws_sse_customer_key_base64",
            "server_side_encryption_customer_key_md5",
            "default_storage_class",
            "enable_virtual_host_style",
            "aws_virtual_hosted_style_request",
            "virtual_hosted_style_request",
            "batch_max_operations",
            "delete_max_size",
            "disable_stat_with_override",
            "checksum_algorithm",
            "aws_checksum_algorithm",
            "disable_write_with_if_match",
            "enable_write_with_append",
            "disable_list_objects_v2",
            "enable_request_payer",
            "aws_request_payer",
            "request_payer",
            "enable_versioning",
            // Forced on anyway.
            "disable_config_load",
            "disable_ec2_metadata",
        ],
        Scheme::Gcs => &[
            "root",
            "bucket",
            "google_bucket",
            "google_bucket_name",
            "bucket_name",
            "endpoint",
            "scope",
            "credential",
            "google_service_account_key",
            "service_account_key",
            "token",
            "predefined_acl",
            "default_storage_class",
            "allow_anonymous",
            "google_skip_signature",
            "skip_signature",
            // Forced on anyway.
            "disable_config_load",
            "disable_vm_metadata",
        ],
        Scheme::Azblob => &[
            "root",
            "container",
            "azure_container_name",
            "container_name",
            "endpoint",
            "azure_storage_endpoint",
            "azure_endpoint",
            "account_name",
            "azure_storage_account_name",
            "account_key",
            "azure_storage_account_key",
            "azure_storage_access_key",
            "azure_storage_master_key",
            "access_key",
            "master_key",
            "sas_token",
            "azure_storage_sas_key",
            "azure_storage_sas_token",
            "sas_key",
            "encryption_key",
            "encryption_key_sha256",
            "encryption_algorithm",
            "batch_max_operations",
        ],
        Scheme::Webdav => &[
            "root",
            "endpoint",
            "username",
            "password",
            "token",
            "disable_copy",
        ],
        Scheme::B2 => &[
            "root",
            "bucket",
            "bucket_id",
            "application_key_id",
            "application_key",
        ],
        Scheme::Fs => &["root"],
    }
}

/// Azure falls back to credentials from the server's environment and to the VM's managed
/// identity when a destination has none of its own: it must bring a SAS token or a shared key.
fn check_azure_credentials(dest: &Destination) -> anyhow::Result<()> {
    let has = |keys: &[&str]| has_option(dest, keys);
    let sas = has(&[
        "sas_token",
        "azure_storage_sas_key",
        "azure_storage_sas_token",
        "sas_key",
    ]);
    let key = has(&[
        "account_key",
        "azure_storage_account_key",
        "azure_storage_access_key",
        "azure_storage_master_key",
        "access_key",
        "master_key",
    ]);
    let name = has(&["account_name", "azure_storage_account_name"]);
    if sas || (key && name) {
        Ok(())
    } else {
        bail!("an Azure destination needs a SAS token, or an account name and account key")
    }
}

fn has_option(dest: &Destination, keys: &[&str]) -> bool {
    dest.options
        .iter()
        .any(|(k, v)| keys.contains(&k.to_ascii_lowercase().as_str()) && !v.trim().is_empty())
}

/// Without keys of its own, S3 goes down the AWS credential chain, and parts of it (web identity,
/// ECS task role, SSO and credential processes) can't be switched off: they would sign with the
/// server's identity. So a destination brings its keys, or is explicitly anonymous.
fn check_s3_credentials(dest: &Destination) -> anyhow::Result<()> {
    let id = has_option(dest, &["access_key_id", "aws_access_key_id"]);
    let secret = has_option(dest, &["secret_access_key", "aws_secret_access_key"]);
    let anonymous = dest.options.iter().any(|(k, v)| {
        matches!(
            k.to_ascii_lowercase().as_str(),
            "allow_anonymous" | "skip_signature"
        ) && v.trim().eq_ignore_ascii_case("true")
    });
    if (id && secret) || anonymous {
        Ok(())
    } else {
        bail!("an S3 destination needs an access key ID and secret access key (or allow_anonymous for a public bucket)")
    }
}

/// Fields of a Google service account key file. Anything else means another kind of credential.
const GCS_SERVICE_ACCOUNT_FIELDS: &[&str] = &[
    "type",
    "project_id",
    "private_key_id",
    "private_key",
    "client_email",
    "client_id",
    "auth_uri",
    "token_uri",
    "auth_provider_x509_cert_url",
    "client_x509_cert_url",
    "universe_domain",
];

/// GCS accepts every kind of Google credential file, and some of them make the server act on its
/// own behalf: an `external_account` reads a file or URL of the attacker's choosing (with
/// `${VAR}`s from the server's environment) and posts it to a token URL they pick. Only service
/// account keys, which sign with their own key against Google's fixed token endpoint, are allowed.
fn check_gcs_credentials(dest: &Destination) -> anyhow::Result<()> {
    use base64::Engine;
    for (k, v) in &dest.options {
        let key = k.to_ascii_lowercase();
        if !matches!(
            key.as_str(),
            "credential" | "google_service_account_key" | "service_account_key"
        ) {
            continue;
        }
        let json = base64::engine::general_purpose::STANDARD
            .decode(v.trim())
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
        let Some(serde_json::Value::Object(fields)) = json else {
            bail!("option '{k}' must be a base64-encoded service account key (JSON)");
        };
        if fields.get("type").and_then(|t| t.as_str()) != Some("service_account") {
            bail!("option '{k}' must be a service account key (\"type\": \"service_account\")");
        }
        if let Some(f) = fields
            .keys()
            .find(|f| !GCS_SERVICE_ACCOUNT_FIELDS.contains(&f.as_str()))
        {
            bail!("option '{k}' has a field a service account key doesn't have: '{f}'");
        }
    }
    Ok(())
}

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
    let scheme = Scheme::parse(&dest.scheme)?;
    let allowed = allowed_options(scheme);
    match scheme {
        Scheme::Azblob => check_azure_credentials(dest)?,
        Scheme::S3 => check_s3_credentials(dest)?,
        Scheme::Gcs => check_gcs_credentials(dest)?,
        _ => {}
    }
    for (k, v) in &dest.options {
        let key = k.to_ascii_lowercase();
        if key.ends_with("_path") || key.ends_with("_file") || key == "path" || key == "file" {
            bail!("option '{k}' would read a file on the server; paste its content instead (e.g. 'credential')");
        }
        if !allowed.contains(&key.as_str()) {
            bail!(
                "option '{k}' isn't supported for {} destinations",
                dest.scheme
            );
        }
        if key.ends_with("root") && !dest.scheme.eq_ignore_ascii_case("fs") {
            layout::check_rel_path(v.trim_start_matches('/'))
                .with_context(|| format!("option '{k}'"))?;
        }
    }
    Ok(())
}

/// A destination's options as the operator gets them. Never pick up the server's own config
/// files, environment (~/.aws/config, gcloud ADC…) or the identity of the machine it runs on (EC2
/// instance role, GCE service account): a destination only uses the credentials its owner entered.
fn forced_options(
    scheme: Scheme,
    options: impl IntoIterator<Item = (String, String)>,
) -> HashMap<String, String> {
    let mut opts: HashMap<String, String> = options
        .into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect();
    match scheme {
        Scheme::S3 => {
            opts.insert("disable_config_load".into(), "true".into());
            opts.insert("disable_ec2_metadata".into(), "true".into());
        }
        Scheme::Gcs => {
            opts.insert("disable_config_load".into(), "true".into());
            opts.insert("disable_vm_metadata".into(), "true".into());
        }
        _ => {}
    }
    opts
}

/// An operator for a non-`fs` destination, without a `Store` around it (tests use it to reach
/// objects behind Malo's back).
#[doc(hidden)]
pub fn raw_operator(scheme: &str, options: &BTreeMap<String, String>) -> anyhow::Result<Operator> {
    let s = Scheme::parse(scheme)?;
    anyhow::ensure!(s != Scheme::Fs, "not for fs destinations");
    let dest = Destination {
        id: String::new(),
        name: String::new(),
        scheme: scheme.into(),
        options: options.clone(),
        root: String::new(),
        encrypt: false,
        required_for_purge: false,
        deep_check: malo_api::DeepCheckMode::Off,
        revision: 0,
        recovery_secrets: false,
        missing_secrets: vec![],
        features: Default::default(),
    };
    validate_destination(&dest)?;
    operator(s, forced_options(s, dest.options.clone()))
}

fn operator(scheme: Scheme, opts: HashMap<String, String>) -> anyhow::Result<Operator> {
    // Checked on every open, not only when saved: the block may have been turned on since.
    for (k, v) in &opts {
        if k.contains("endpoint") && !v.trim().is_empty() {
            crate::netguard::check_url_literal(&format!("option '{k}'"), v)?;
        }
    }
    // Own HTTP client per operator: OpenDAL's global client is bound to the first tokio runtime
    // that used it. It doesn't follow redirects and checks the addresses it connects to.
    let http = crate::netguard::storage_http_client()
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .context("http client")?;
    opendal::init_default_registry();
    let op = Operator::via_iter(scheme.as_str(), opts)?;
    let ctx = op
        .context()
        .with_http_transport(opendal::HttpTransporter::new(
            opendal_http_transport_reqwest::ReqwestTransport::new(http),
        ));
    Ok(op.with_context(ctx).layer(
        opendal::layers::RetryLayer::new()
            .with_max_times(4)
            .with_jitter(),
    ))
}

impl Store {
    pub fn open(dest: &Destination, archive_key: &Key, fs: &FsPolicy) -> anyhow::Result<Store> {
        if !dest.complete() {
            bail!(
                "\"{}\" was restored without its credentials ({}): enter them again under Destinations",
                dest.name,
                dest.missing_secrets.join(", ")
            );
        }
        let scheme = Scheme::parse(&dest.scheme)?;
        validate_destination(dest)?;
        Locker::for_destination(dest)?;
        let mut opts = forced_options(scheme, dest.options.clone());
        if scheme == Scheme::Fs {
            let root = confine_fs_root(opts.get("root").map(String::as_str), fs)?;
            opts.insert("root".into(), root.to_string_lossy().into_owned());
        }
        let op =
            operator(scheme, opts).with_context(|| format!("cannot configure {}", dest.scheme))?;
        Ok(Store::from_operator(dest, op, archive_key))
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
        let (up, down) = ratelimit::destination(
            &dest.id,
            dest.features.upload_kib_per_sec,
            dest.features.download_kib_per_sec,
        );
        let locker = match Locker::for_destination(dest) {
            Ok(l) => l.map(Arc::new),
            Err(e) => {
                tracing::warn!(dest = %dest.name, "Object Lock can't be used: {e:#}");
                None
            }
        };
        Store {
            dest: dest.clone(),
            op,
            names: NameKey::new(archive_key),
            archive_key: archive_key.clone(),
            up,
            down,
            locker,
        }
    }

    /// The Object Lock of this destination, when it has one.
    pub fn locker(&self) -> Option<&Locker> {
        self.locker.as_deref()
    }

    async fn throttle_up(&self, bytes: u64) {
        self.up.take(bytes).await;
        ratelimit::global_upload().take(bytes).await;
    }

    async fn throttle_down(&self, bytes: u64) {
        self.down.take(bytes).await;
        ratelimit::global_download().take(bytes).await;
    }

    pub fn operator(&self) -> &Operator {
        &self.op
    }

    /// All uploads go through here (fault injection in test builds).
    async fn write_obj(&self, path: &str, mut data: Vec<u8>) -> anyhow::Result<()> {
        use faults::Fault;
        self.throttle_up(data.len() as u64).await;
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
        self.throttle_down(buf.len() as u64).await;
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

    /// Object path of one message. Encrypted objects are content-addressed (deduplicated);
    /// compressed ones have a name of their own.
    pub fn object_path(
        &self,
        account: &Account,
        mailbox_path: &str,
        uidvalidity: u32,
        uid: u32,
        sha256: &str,
    ) -> String {
        let dir = self.account_dir(account);
        self.portable(if self.dest.compresses() {
            self.names
                .compressed_object_path(&self.dest.root, &dir, sha256)
        } else if self.dest.encrypt {
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

    /// Manifests, markers and other small files: encrypted on encrypted destinations, never
    /// compressed (they are rewritten in place and must stay readable by older versions).
    fn encode(&self, plaintext: &[u8]) -> Vec<u8> {
        if self.dest.encrypt {
            crypto::encrypt_object(&self.archive_key, plaintext)
        } else {
            plaintext.to_vec()
        }
    }

    /// A message object: compressed first where the destination compresses.
    fn encode_message(&self, plaintext: &[u8]) -> Vec<u8> {
        if self.dest.compresses() {
            crypto::encrypt_object_compressed(&self.archive_key, plaintext)
        } else {
            self.encode(plaintext)
        }
    }

    /// Writes a message object (skipping identical existing encrypted objects) and reads it back
    /// to verify. Returns the stored size.
    pub async fn put_verified(
        &self,
        path: &str,
        plaintext: &[u8],
        sha256: &str,
    ) -> anyhow::Result<u64> {
        let path = self.checked(path)?;
        let size = plaintext.len() as u64;
        if self.dest.encrypt {
            if let (Verify::Ok, Some(stored)) = self
                .verify_sized(path, true, sha256, size, None, true)
                .await?
            {
                return Ok(stored);
            }
        }
        let data = self.encode_message(plaintext);
        let len = data.len() as u64;
        self.write_obj(path, data).await?;
        match self
            .verify(path, self.dest.encrypt, sha256, size, Some(len), true)
            .await?
        {
            Verify::Ok => {
                // A copy that isn't locked doesn't count as stored on a destination meant to be
                // immutable; integrity checks extend the lock later.
                if let Some(l) = &self.locker {
                    l.lock(path, l.until_from_now()).await?;
                }
                Ok(len)
            }
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

    /// Stat (quick) or download + decrypt + hash (deep). `stored` is the object's size on the
    /// destination when known (the index records it); without it, the size an uncompressed object
    /// has is expected, except in a deep check, where the hash decides.
    pub async fn verify(
        &self,
        path: &str,
        encrypted: bool,
        sha256: &str,
        size: u64,
        stored: Option<u64>,
        deep: bool,
    ) -> anyhow::Result<Verify> {
        Ok(self
            .verify_sized(path, encrypted, sha256, size, stored, deep)
            .await?
            .0)
    }

    /// [`Store::verify`], also returning the object's size on the destination.
    async fn verify_sized(
        &self,
        path: &str,
        encrypted: bool,
        sha256: &str,
        size: u64,
        stored: Option<u64>,
        deep: bool,
    ) -> anyhow::Result<(Verify, Option<u64>)> {
        let path = self.checked(path)?;
        let expected_len = stored
            .filter(|s| *s > 0)
            .or_else(|| (!deep).then(|| expected_stored_len(encrypted, size)));
        self.meta_fault(&format!("stat {path}"))?;
        let meta = match self.op.stat(path).await {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok((Verify::Missing, None)),
            Err(e) => return Err(e.into()),
        };
        let len = Some(meta.content_length());
        if let Some(expected_len) = expected_len {
            if meta.content_length() != expected_len {
                return Ok((
                    Verify::Corrupt(format!(
                        "size {} ≠ expected {expected_len}",
                        meta.content_length()
                    )),
                    len,
                ));
            }
        }
        if !deep {
            return Ok((Verify::Ok, len));
        }
        let reader = match self.op.reader(path).await {
            Ok(r) => r,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok((Verify::Missing, None)),
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
            self.throttle_down(chunk.len() as u64).await;
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
                    Err(e) => return Ok((Verify::Corrupt(e.to_string()), len)),
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
                Err(e) => return Ok((Verify::Corrupt(e.to_string()), len)),
            }
        }
        let got = hex::encode(hasher.finalize());
        if total != size || got != sha256 {
            return Ok((
                Verify::Corrupt(format!("sha256 mismatch ({} bytes)", total)),
                len,
            ));
        }
        Ok((Verify::Ok, len))
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
            .verify(path, self.dest.encrypt, &sha, body.len() as u64, None, true)
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

    /// Whether the destination answers, by listing its folder (writes nothing). A folder that
    /// doesn't exist yet counts as reachable.
    pub async fn reachable(&self) -> anyhow::Result<()> {
        let root = self.checked(&self.dest.root)?;
        let dir = if root.is_empty() {
            String::new()
        } else {
            format!("{}/", root.trim_end_matches('/'))
        };
        self.meta_fault(&format!("list {dir}"))?;
        match self.op.lister_with(&dir).await {
            Ok(mut l) => {
                l.try_next().await?;
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
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
                lock: None,
            };
        }
        let write_ms = t0.elapsed().as_millis() as u64;
        let lock = match &self.locker {
            None => None,
            Some(l) => match self.test_lock(l, &path).await {
                Ok(s) => Some(s),
                Err(e) => {
                    let _ = self.op.delete(&path).await;
                    return DestinationTest {
                        ok: false,
                        error: Some(format!("Object Lock: {e:#}")),
                        write_ms,
                        read_ms: 0,
                        lock: None,
                    };
                }
            },
        };
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
            lock,
        }
    }

    /// Checks the bucket's lock settings, and that a probe object can be locked (for a minute,
    /// so the probe goes away soon; on a versioned bucket its deletion leaves a delete marker).
    async fn test_lock(&self, l: &Locker, probe: &str) -> anyhow::Result<String> {
        let bucket = l.check_bucket().await?;
        l.lock(probe, chrono::Utc::now() + chrono::Duration::seconds(60))
            .await?;
        let r = l
            .retention(probe)
            .await?
            .ok_or_else(|| anyhow!("the probe object shows no retention after locking it"))?;
        Ok(format!("{bucket}; a test object was locked ({})", r.mode))
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
            recovery_secrets: false,
            missing_secrets: vec![],
            features: Default::default(),
        }
    }

    pub fn account() -> Account {
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
            smtp: None,
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
                Operator::new(Memory::default()).unwrap(),
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
            let stored = store.put_verified(&path, &msg, &sha).await.unwrap();
            if encrypt {
                // Compressed: far smaller than the message, and named as such.
                assert!(stored < msg.len() as u64 / 10, "{stored}");
                assert!(is_compressed_path(&path));
            } else {
                assert_eq!(stored, msg.len() as u64);
            }
            // Writing the same message again finds the stored copy and reports its real size.
            assert_eq!(store.put_verified(&path, &msg, &sha).await.unwrap(), stored);
            assert_eq!(store.get(&path, encrypt).await.unwrap(), msg);
            assert_eq!(
                store
                    .verify(&path, encrypt, &sha, msg.len() as u64, None, true)
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
                    .verify(&path, encrypt, &sha, msg.len() as u64, None, true)
                    .await
                    .unwrap(),
                Verify::Corrupt(_)
            ));
            assert_eq!(
                store
                    .verify(&path, encrypt, &sha, msg.len() as u64, Some(stored), false)
                    .await
                    .unwrap(),
                Verify::Ok
            );
            // Without the recorded size, a quick check of a compressed object expects the
            // uncompressed size and can't confirm it.
            if encrypt {
                assert!(matches!(
                    store
                        .verify(&path, encrypt, &sha, msg.len() as u64, None, false)
                        .await
                        .unwrap(),
                    Verify::Corrupt(_)
                ));
            }
            store.delete(&path).await.unwrap();
            assert_eq!(
                store
                    .verify(&path, encrypt, &sha, msg.len() as u64, None, false)
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
        let store =
            Store::from_operator(&dest(true), Operator::new(Memory::default()).unwrap(), &k);
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
            stored_size: None,
            collections: vec![],
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

    fn s3_dest() -> Destination {
        Destination {
            scheme: "s3".into(),
            options: [("access_key_id", "a"), ("secret_access_key", "s")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..dest(false)
        }
    }

    /// Credential files that make the server read its own files or fetch URLs are refused.
    #[test]
    fn gcs_accepts_only_service_account_keys() {
        use base64::Engine;
        let gcs = |key: &str, json: &str| Destination {
            scheme: "gcs".into(),
            options: [
                ("bucket".to_string(), "b".to_string()),
                (
                    key.to_string(),
                    base64::engine::general_purpose::STANDARD.encode(json),
                ),
            ]
            .into_iter()
            .collect(),
            ..dest(false)
        };
        let sa = r#"{"type":"service_account","project_id":"p","private_key":"k","client_email":"a@p.iam.gserviceaccount.com","token_uri":"https://oauth2.googleapis.com/token"}"#;
        assert!(validate_destination(&gcs("credential", sa)).is_ok());
        for json in [
            r#"{"type":"external_account","audience":"${MALO_SIDECAR_SECRET}","subject_token_type":"x","token_url":"https://evil.example/t","credential_source":{"file":"/data/tls/key.pem"}}"#,
            r#"{"type":"impersonated_service_account","service_account_impersonation_url":"https://evil.example","source_credentials":{}}"#,
            r#"{"type":"authorized_user","client_id":"a","client_secret":"b","refresh_token":"c"}"#,
            r#"{"type":"service_account","private_key":"k","client_email":"a","credential_source":{"file":"/etc/passwd"}}"#,
            r#"["service_account"]"#,
            "not json",
        ] {
            for key in [
                "credential",
                "Service_Account_Key",
                "google_service_account_key",
            ] {
                assert!(
                    validate_destination(&gcs(key, json)).is_err(),
                    "{key}={json} accepted"
                );
            }
        }
        let mut d = gcs("credential", sa);
        d.options.insert("credential".into(), "%%%".into());
        assert!(validate_destination(&d).is_err());
    }

    #[test]
    fn destination_validation() {
        let mut d = s3_dest();
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
            let mut d = s3_dest();
            d.options.insert(key.into(), "/etc/passwd".into());
            assert!(validate_destination(&d).is_err(), "option {key} accepted");
        }
        let mut d = s3_dest();
        d.options.insert("root".into(), "/a/../../b".into());
        assert!(validate_destination(&d).is_err());
    }

    #[test]
    fn destination_options_are_allowlisted() {
        let with = |scheme: &str, opts: &[(&str, &str)]| Destination {
            scheme: scheme.into(),
            options: opts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..dest(false)
        };
        let ok = [
            with(
                "s3",
                &[
                    ("bucket", "b"),
                    ("endpoint", "https://s3.example.com"),
                    ("Region", "x"),
                    ("access_key_id", "a"),
                    ("secret_access_key", "s"),
                ],
            ),
            with("s3", &[("bucket", "public"), ("allow_anonymous", "true")]),
            with(
                "s3",
                &[("aws_access_key_id", "a"), ("aws_secret_access_key", "s")],
            ),
            with("gcs", &[("bucket", "b"), ("credential", "eyJ0eXBlIjoic2VydmljZV9hY2NvdW50IiwicHJpdmF0ZV9rZXkiOiJrIiwiY2xpZW50X2VtYWlsIjoiYUBiIn0=")]),
            with("azblob", &[("container", "c"), ("sas_token", "sv=1")]),
            with("azblob", &[("account_name", "n"), ("account_key", "a2V5")]),
            with(
                "webdav",
                &[("endpoint", "https://dav.example.com"), ("password", "p")],
            ),
            with("b2", &[("bucket", "b"), ("application_key", "k")]),
            with("fs", &[("root", "/backups")]),
        ];
        for d in ok {
            assert!(
                validate_destination(&d).is_ok(),
                "{} {:?}",
                d.scheme,
                d.options
            );
        }
        let refused = [
            // The server's own identity.
            with("s3", &[("role_arn", "arn:aws:iam::1:role/x")]),
            // No keys: the AWS chain would find the server's (web identity, ECS, SSO).
            with(
                "s3",
                &[("bucket", "b"), ("endpoint", "https://s3.example.com")],
            ),
            with("s3", &[("access_key_id", "a")]),
            with("s3", &[("bucket", "b"), ("allow_anonymous", "false")]),
            with("s3", &[("external_id", "x")]),
            with("s3", &[("role_session_name", "x")]),
            with("gcs", &[("service_account", "default")]),
            with(
                "gcs",
                &[("google_application_credentials", "/etc/key.json")],
            ),
            with("azblob", &[("container", "c")]),
            with("azblob", &[("account_key", "a2V5")]),
            // Unknown options, a server path for fs, unusable services.
            with("s3", &[("something_new", "x")]),
            with("fs", &[("atomic_write_dir", "/tmp")]),
            with("memory", &[]),
            with("ftp", &[]),
        ];
        for d in refused {
            assert!(
                validate_destination(&d).is_err(),
                "{} {:?}",
                d.scheme,
                d.options
            );
        }
    }

    #[test]
    fn store_open_forces_own_credentials_only() {
        let k = crypto::random_key();
        let fs = FsPolicy {
            user_root: std::env::temp_dir(),
            allowed_mounts: vec![],
            user_id: "u".into(),
            owner_dir: None,
        };
        let d = Destination {
            options: [
                ("bucket".to_string(), "b".to_string()),
                ("region".to_string(), "us-east-1".to_string()),
                ("disable_ec2_metadata".to_string(), "false".to_string()),
                ("disable_config_load".to_string(), "false".to_string()),
                ("access_key_id".to_string(), "a".to_string()),
                ("secret_access_key".to_string(), "s".to_string()),
            ]
            .into_iter()
            .collect(),
            ..s3_dest()
        };
        let store = Store::open(&d, &k, &fs).unwrap();
        let info = format!("{:?}", store.operator().info());
        assert!(info.contains("s3"), "{info}");
        // The forced settings are what the operator was built with, whatever the destination says.
        let opts = forced_options(Scheme::S3, d.options.clone());
        assert_eq!(opts["disable_ec2_metadata"], "true");
        assert_eq!(opts["disable_config_load"], "true");
        let gcs = forced_options(Scheme::Gcs, Vec::new());
        assert_eq!(gcs["disable_vm_metadata"], "true");
        assert_eq!(gcs["disable_config_load"], "true");
        assert!(
            Store::open(&dest(false), &k, &fs).is_err(),
            "memory is refused"
        );
    }

    #[tokio::test]
    async fn store_rejects_traversal_paths() {
        let k = crypto::random_key();
        let store =
            Store::from_operator(&dest(false), Operator::new(Memory::default()).unwrap(), &k);
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
