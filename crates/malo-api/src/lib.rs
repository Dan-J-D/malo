//! Request, response and event types shared by `malo-server`, `malo-core` and the GUI.
//!
//! TypeScript bindings are generated into `src/lib/api/types.ts` by `cargo test -p malo-api`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub type Timestamp = DateTime<Utc>;

/// Placeholder sent instead of secret values. Sending it back on update keeps the stored value.
pub const REDACTED: &str = "********";

// ───────────────────────────── auth / users ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct LoginResponse {
    pub token: String,
    pub me: Me,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct Me {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub unlocked: bool,
    pub unlocked_at: Option<Timestamp>,
    pub expires_at: Option<Timestamp>,
    /// User-chosen auto-lock in hours (always ≤ the server maximum).
    pub auto_lock_hours: u32,
    pub server_max_auto_lock_hours: u32,
    /// True until the user has downloaded the recovery kit once.
    pub recovery_kit_pending: bool,
    /// Jobs that came due while the user was locked and were skipped.
    pub skipped_while_locked: u32,
}

/// Sets a new password with the recovery kit when the old one is forgotten. The user, their
/// accounts, destinations and settings stay as they are.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct RecoverRequest {
    pub username: String,
    pub recovery_kit: RecoveryKitFile,
    /// Passphrase of an encrypted kit.
    #[serde(default)]
    #[ts(optional)]
    pub kit_passphrase: Option<String>,
    pub new_password: String,
}

/// Asks for the recovery kit: the account password again, and the passphrase that will encrypt
/// the kit file (the kit is for when the password is forgotten, so it can't be the password).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct RecoveryKitRequest {
    pub password: String,
    pub passphrase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

/// Deletes the caller's own account. Second confirmation step: `confirm` must be exactly
/// `delete <username>` and the password must unlock the vault.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct DeleteAccountRequest {
    pub password: String,
    pub confirm: String,
}

/// First-boot admin creation with the one-time token printed in the server log.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct SetupRequest {
    pub setup_token: String,
    pub username: String,
    pub password: String,
}

/// Self-registration or invite redemption.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub invite_code: Option<String>,
    /// Optional recovery kit of a previous user: its archive key is adopted so old encrypted backups stay readable.
    pub recovery_kit: Option<RecoveryKitFile>,
    /// Passphrase of an encrypted kit.
    #[serde(default)]
    #[ts(optional)]
    pub kit_passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ServerStatus {
    pub version: String,
    pub needs_setup: bool,
    pub self_registration: bool,
    /// SHA-256 fingerprint (hex, colon separated) of the TLS certificate the server serves.
    pub cert_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct Health {
    pub status: String,
    pub sealed_users: u32,
    pub unlocked_users: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct UserSettings {
    pub auto_lock_hours: u32,
    pub quick_check_hours: u32,
    pub deep_check_hours: u32,
    pub auto_repair: bool,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            auto_lock_hours: 24,
            quick_check_hours: 24,
            deep_check_hours: 24 * 7,
            auto_repair: false,
        }
    }
}

/// The archive key of a user: enough to decrypt every encrypted backup they ever wrote.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct RecoveryKit {
    pub format: String,
    pub user_id: String,
    pub username: String,
    pub created_at: Timestamp,
    /// Hex-encoded 256-bit archive key.
    pub archive_key: String,
    /// Short check value derived from the key, so a mistyped or damaged kit is refused instead of
    /// silently creating a user who can read nothing. Absent in kits saved by older versions.
    #[serde(default)]
    #[ts(optional)]
    pub check: Option<String>,
}

pub const SEALED_KIT_FORMAT: &str = "malo-recovery-kit-v2";

/// A recovery kit file encrypted with a passphrase (Argon2id + AES-256-GCM). Only the format and
/// the key derivation settings are readable; the username and key are inside `data`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct SealedRecoveryKit {
    pub format: String,
    pub kdf: KitKdf,
    /// Hex.
    pub salt: String,
    /// Base64 of nonce, ciphertext and tag; the plaintext is a [`RecoveryKit`] as JSON.
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct KitKdf {
    pub algorithm: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// A kit file as read from disk: encrypted (current) or plain (saved by older versions).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum RecoveryKitFile {
    Sealed(SealedRecoveryKit),
    Plain(RecoveryKit),
}
// ───────────────────────────── accounts ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// TLS from the first byte (port 993).
    Implicit,
    /// Plain connection upgraded with STARTTLS (port 143). Refused if STARTTLS fails.
    Starttls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProvider {
    Google,
    Microsoft,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccountAuth {
    Password {
        password: String,
    },
    #[serde(rename = "oauth2")]
    OAuth2 {
        provider: OAuthProvider,
        auth_url: String,
        token_url: String,
        client_id: String,
        client_secret: Option<String>,
        scopes: Vec<String>,
        refresh_token: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct AccountInput {
    /// Revision the client edited (from the view). A stale one is rejected with 409 so a device
    /// can't silently overwrite a change made elsewhere. Omit to overwrite unconditionally.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub revision: Option<u64>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    /// Accept self-signed/invalid server certificates (test servers only).
    #[serde(default)]
    pub accept_invalid_certs: bool,
    pub username: String,
    /// Secret fields equal to [`REDACTED`] keep their stored value.
    pub auth: AccountAuth,
    pub backup_interval_minutes: u32,
    pub idle: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct AccountView {
    /// Increases with every change; send it back when saving.
    #[ts(type = "number")]
    pub revision: u64,
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub accept_invalid_certs: bool,
    pub username: String,
    /// Same shape as the input, with secrets replaced by [`REDACTED`].
    pub auth: AccountAuth,
    pub backup_interval_minutes: u32,
    pub idle: bool,
    pub enabled: bool,
    pub imported: bool,
    pub policy: PurgePolicy,
    pub last_backup: Option<Timestamp>,
    pub last_backup_ok: Option<bool>,
    pub next_backup: Option<Timestamp>,
    pub next_purge: Option<Timestamp>,
    pub purge_blocked: Option<String>,
    #[ts(type = "number")]
    pub message_count: u64,
    #[ts(type = "number")]
    pub stored_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ConnectionTest {
    pub ok: bool,
    pub error: Option<String>,
    pub capabilities: Vec<String>,
    pub warnings: Vec<String>,
    pub mailboxes: Vec<String>,
    pub gmail: bool,
    pub uidplus: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct AccountPreset {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub oauth: Option<OAuthPreset>,
    pub app_password_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct OAuthPreset {
    pub provider: OAuthProvider,
    pub auth_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub guide_url: String,
}

// ───────────────────────────── destinations ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DeepCheckMode {
    /// Re-hash every object on every deep check.
    Full,
    /// Re-hash 1/`slices` of the objects per deep check.
    Rotating { slices: u32 },
    /// Never download for checking (egress-sensitive destinations).
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct DestinationInput {
    /// Revision the client edited (from the view). A stale one is rejected with 409 so a device
    /// can't silently overwrite a change made elsewhere. Omit to overwrite unconditionally.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub revision: Option<u64>,
    pub name: String,
    /// OpenDAL scheme: fs, s3, gcs, azblob, webdav, b2, …
    pub scheme: String,
    /// OpenDAL options. Values equal to [`REDACTED`] keep their stored value on update.
    pub options: BTreeMap<String, String>,
    /// Prefix inside the service root.
    pub root: String,
    pub encrypt: bool,
    pub required_for_purge: bool,
    pub deep_check: DeepCheckMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct DestinationView {
    /// Increases with every change; send it back when saving.
    #[ts(type = "number")]
    pub revision: u64,
    pub id: String,
    pub name: String,
    pub scheme: String,
    pub options: BTreeMap<String, String>,
    pub root: String,
    pub encrypt: bool,
    pub required_for_purge: bool,
    pub deep_check: DeepCheckMode,
    #[ts(type = "number")]
    pub object_count: u64,
    #[ts(type = "number")]
    pub stored_bytes: u64,
    pub health: Option<DestinationHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct DestinationTest {
    pub ok: bool,
    pub error: Option<String>,
    #[ts(type = "number")]
    pub write_ms: u64,
    #[ts(type = "number")]
    pub read_ms: u64,
}

// ───────────────────────────── purge ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct PurgePolicy {
    /// Messages older than this many days are eligible. 0 = all verified messages.
    pub older_than_days: u32,
    /// Destination ids that must hold a verified replica. At least one.
    pub required_destinations: Vec<String>,
    pub exclude_mailboxes: Vec<String>,
    pub exclude_flagged: bool,
    /// Scheduled purge interval; 0 disables scheduled purges (manual only).
    pub schedule_hours: u32,
    pub armed: bool,
    pub armed_at: Option<Timestamp>,
}

impl Default for PurgePolicy {
    fn default() -> Self {
        Self {
            older_than_days: 365,
            required_destinations: vec![],
            exclude_mailboxes: vec![],
            exclude_flagged: true,
            schedule_hours: 24,
            armed: false,
            armed_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct PurgePreview {
    pub account_id: String,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub total_bytes: u64,
    pub mailboxes: Vec<PurgeMailboxCount>,
    /// Why purging is currently impossible (missing UIDPLUS, failing check, no required destination …).
    pub blocked_reason: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct PurgeMailboxCount {
    pub mailbox: String,
    #[ts(type = "number")]
    pub count: u64,
    #[ts(type = "number")]
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ArmRequest {
    /// Must equal the account name exactly.
    pub confirm_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct PurgeSummary {
    pub account_id: String,
    #[ts(type = "number")]
    pub deleted: u64,
    #[ts(type = "number")]
    pub bytes: u64,
    #[ts(type = "number")]
    pub skipped: u64,
    pub errors: Vec<String>,
}

// ───────────────────────────── jobs ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum CheckScope {
    All,
    Account { account_id: String },
    Destination { destination_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JobKind {
    Backup {
        account_id: String,
    },
    Check {
        scope: CheckScope,
        deep: bool,
    },
    PurgeDryRun {
        account_id: String,
    },
    Purge {
        account_id: String,
    },
    Repair {
        scope: CheckScope,
    },
    RebuildIndex {
        destination_id: String,
    },
    /// From every destination: all mail, with each account's newest manifests first.
    RebuildIndexAll,
}

impl JobKind {
    /// Account whose mutex this job needs, if any.
    pub fn account_id(&self) -> Option<&str> {
        match self {
            JobKind::Backup { account_id } | JobKind::Purge { account_id } => Some(account_id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Done,
    Failed,
    Cancelled,
    SkippedLocked,
}

impl JobState {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Running => "running",
            JobState::Done => "done",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
            JobState::SkippedLocked => "skipped_locked",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "queued" => JobState::Queued,
            "running" => JobState::Running,
            "done" => JobState::Done,
            "cancelled" => JobState::Cancelled,
            "skipped_locked" => JobState::SkippedLocked,
            _ => JobState::Failed,
        }
    }
    pub fn is_finished(&self) -> bool {
        !matches!(self, JobState::Queued | JobState::Running)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum JobTrigger {
    Manual,
    Scheduled,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct JobProgress {
    #[ts(type = "number")]
    pub done: u64,
    #[ts(type = "number")]
    pub total: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct JobInfo {
    pub id: String,
    pub kind: JobKind,
    pub state: JobState,
    pub trigger: JobTrigger,
    pub created_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    pub progress: JobProgress,
    pub error: Option<String>,
    /// Job-specific result (backup stats, purge summary, check report id …).
    #[ts(type = "any")]
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct CreateJobRequest {
    pub kind: JobKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ScheduledJob {
    pub key: String,
    pub kind: JobKind,
    pub next_run: Timestamp,
}

// ───────────────────────────── messages ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum MessageState {
    Discovered,
    Downloading,
    Stored,
    Verified,
    Error,
}

impl MessageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageState::Discovered => "discovered",
            MessageState::Downloading => "downloading",
            MessageState::Stored => "stored",
            MessageState::Verified => "verified",
            MessageState::Error => "error",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "discovered" => MessageState::Discovered,
            "downloading" => MessageState::Downloading,
            "stored" => MessageState::Stored,
            "verified" => MessageState::Verified,
            _ => MessageState::Error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct Envelope {
    pub from: String,
    pub from_name: Option<String>,
    pub to: Vec<String>,
    pub subject: String,
    pub date: Option<Timestamp>,
    pub message_id: Option<String>,
    pub attachment_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MessageSummary {
    #[ts(type = "number")]
    pub id: i64,
    pub account_id: String,
    pub mailboxes: Vec<String>,
    pub labels: Vec<String>,
    pub envelope: Envelope,
    #[ts(type = "number")]
    pub size: u64,
    pub internal_date: Option<Timestamp>,
    pub state: MessageState,
    pub stored: u32,
    pub destinations: u32,
    pub error: Option<String>,
    pub reviewed: bool,
    pub first_seen_at: Timestamp,
    pub flags: Vec<String>,
    pub deleted_on_server: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MessageList {
    #[ts(type = "number")]
    pub total: u64,
    pub messages: Vec<MessageSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MailboxInfo {
    pub account_id: String,
    pub name: String,
    pub display_name: String,
    pub special_use: Option<String>,
    pub uidvalidity: u32,
    #[ts(type = "number")]
    pub message_count: u64,
    #[ts(type = "number")]
    pub new_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ReviewedRequest {
    #[ts(type = "Array<number>")]
    pub ids: Vec<i64>,
    /// Mark everything (optionally of one account) as reviewed.
    #[serde(default)]
    pub all: bool,
    pub account_id: Option<String>,
    /// False marks the messages unread again. Only applies to `ids`, never to `all`.
    #[serde(default = "yes")]
    pub reviewed: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MessageView {
    #[ts(type = "number")]
    pub id: i64,
    pub headers: Vec<(String, String)>,
    pub from: String,
    pub from_name: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub date: Option<Timestamp>,
    pub text: String,
    /// Sanitized HTML, present only when requested with `html=true`.
    pub html: Option<String>,
    pub has_html: bool,
    /// Number of remote resources replaced by placeholders.
    pub remote_blocked: u32,
    pub remote_allowed: bool,
    pub authentication_results: Vec<String>,
    pub warnings: Vec<String>,
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct AttachmentInfo {
    pub index: u32,
    pub filename: String,
    pub declared_type: String,
    pub sniffed_type: Option<String>,
    #[ts(type = "number")]
    pub size: u64,
    pub warnings: Vec<String>,
}

// ───────────────────────────── integrity ─────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct DestinationHealth {
    pub destination_id: String,
    pub name: String,
    #[ts(type = "number")]
    pub healthy: u64,
    #[ts(type = "number")]
    pub missing: u64,
    #[ts(type = "number")]
    pub corrupt: u64,
    #[ts(type = "number")]
    pub orphaned: u64,
    #[ts(type = "number")]
    pub pending: u64,
    #[ts(type = "number")]
    pub checked_deep: u64,
    pub error: Option<String>,
    pub ok: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct AccountBacklog {
    pub account_id: String,
    pub name: String,
    #[ts(type = "number")]
    pub on_server: u64,
    #[ts(type = "number")]
    pub backlog: u64,
    #[ts(type = "number")]
    pub vanished: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct CheckReport {
    #[ts(type = "number")]
    pub id: i64,
    pub created_at: Timestamp,
    pub deep: bool,
    pub scope: CheckScope,
    pub destinations: Vec<DestinationHealth>,
    pub accounts: Vec<AccountBacklog>,
    #[ts(type = "number")]
    pub repaired: u64,
    pub ok: bool,
}

// ───────────────────────────── audit ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct AuditEntry {
    #[ts(type = "number")]
    pub id: i64,
    pub at: Timestamp,
    pub kind: String,
    pub account_id: Option<String>,
    #[ts(type = "any")]
    pub detail: serde_json::Value,
}

// ───────────────────────────── admin ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub disabled: bool,
    pub created_at: Timestamp,
    pub max_accounts: Option<u32>,
    pub unlocked: bool,
}

/// Every field is optional: only the fields sent are changed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct UpdateUserRequest {
    #[serde(default)]
    #[ts(optional)]
    pub disabled: Option<bool>,
    #[serde(default)]
    #[ts(optional)]
    pub role: Option<Role>,
    /// Sets the user's own account limit.
    #[serde(default)]
    #[ts(optional)]
    pub max_accounts: Option<u32>,
    /// True drops the user's own limit: they follow the server default again.
    #[serde(default)]
    #[ts(optional)]
    pub max_accounts_default: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct CreateInviteRequest {
    pub username: Option<String>,
    pub role: Role,
    pub valid_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct Invite {
    pub code: String,
    pub username: Option<String>,
    pub role: Role,
    pub expires_at: Timestamp,
}

/// An invite as listed for administrators. The code itself is never stored; `id` is its hash.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct InviteInfo {
    pub id: String,
    pub username: Option<String>,
    pub role: Role,
    pub expires_at: Timestamp,
    pub used: bool,
}

/// One administrative action, kept in the server database.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct AdminAuditEntry {
    #[ts(type = "number")]
    pub id: i64,
    pub at: Timestamp,
    /// Who did it: an administrator's username, or the user themselves (`self`).
    pub actor: String,
    pub action: String,
    /// The user or invite acted on, when there is one.
    pub target: Option<String>,
    #[ts(type = "any")]
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct AdminSettings {
    pub max_auto_lock_hours: u32,
    pub allowed_fs_mounts: Vec<String>,
    pub self_registration: bool,
    pub default_max_accounts: u32,
    pub max_jobs_per_user: u32,
    /// Refuse mail servers and storage endpoints on loopback, private and link-local addresses,
    /// so users can't make the server probe its own network. Off by default: a self-hosted mail
    /// server or MinIO on the LAN is common.
    #[serde(default)]
    pub block_private_networks: bool,
}

impl Default for AdminSettings {
    fn default() -> Self {
        Self {
            max_auto_lock_hours: 24,
            allowed_fs_mounts: vec![],
            self_registration: false,
            default_max_accounts: 20,
            max_jobs_per_user: 2,
            block_private_networks: false,
        }
    }
}

// ───────────────────────────── events ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncEvent {
    JobQueued {
        job: JobInfo,
    },
    JobStarted {
        job: JobInfo,
    },
    JobProgress {
        job_id: String,
        progress: JobProgress,
    },
    JobFinished {
        job: JobInfo,
    },
    NewMessageDiscovered {
        message: MessageSummary,
    },
    MessageStateChanged {
        #[ts(type = "number")]
        id: i64,
        account_id: String,
        state: MessageState,
        stored: u32,
        destinations: u32,
        error: Option<String>,
    },
    CheckProgress {
        job_id: String,
        destination_id: String,
        #[ts(type = "number")]
        done: u64,
        #[ts(type = "number")]
        total: u64,
    },
    CheckFinished {
        report: CheckReport,
    },
    PurgeSummary {
        summary: PurgeSummary,
    },
    AccountsChanged,
    Locked {
        reason: String,
    },
    Notice {
        level: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct EventBatch {
    pub events: Vec<SyncEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ApiError {
    pub error: String,
    pub code: String,
}

/// Writes every type declaration into a single TypeScript module.
pub fn typescript_bindings() -> String {
    macro_rules! decls {
        ($($t:ty),* $(,)?) => {{
            let mut out = String::from(
                "// Generated by `cargo test -p malo-api` from crates/malo-api/src/lib.rs. Do not edit.\n\n",
            );
            $( out.push_str("export "); out.push_str(&<$t as TS>::decl()); out.push_str("\n\n"); )*
            out
        }};
    }
    let mut out = decls!(
        Role,
        LoginRequest,
        LoginResponse,
        Me,
        ChangePasswordRequest,
        DeleteAccountRequest,
        SetupRequest,
        RegisterRequest,
        RecoverRequest,
        RecoveryKitRequest,
        ServerStatus,
        Health,
        UserSettings,
        RecoveryKit,
        SealedRecoveryKit,
        KitKdf,
        RecoveryKitFile,
        TlsMode,
        OAuthProvider,
        AccountAuth,
        AccountInput,
        AccountView,
        ConnectionTest,
        AccountPreset,
        OAuthPreset,
        DeepCheckMode,
        DestinationInput,
        DestinationView,
        DestinationTest,
        PurgePolicy,
        PurgePreview,
        PurgeMailboxCount,
        ArmRequest,
        PurgeSummary,
        CheckScope,
        JobKind,
        JobState,
        JobTrigger,
        JobProgress,
        JobInfo,
        CreateJobRequest,
        ScheduledJob,
        MessageState,
        Envelope,
        MessageSummary,
        MessageList,
        MailboxInfo,
        ReviewedRequest,
        MessageView,
        AttachmentInfo,
        DestinationHealth,
        AccountBacklog,
        CheckReport,
        AuditEntry,
        UserInfo,
        UpdateUserRequest,
        CreateInviteRequest,
        InviteInfo,
        AdminAuditEntry,
        Invite,
        AdminSettings,
        SyncEvent,
        EventBatch,
        ApiError,
    );
    out.push_str(&format!("export const REDACTED = {REDACTED:?};\n"));
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn export_typescript_bindings() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src/lib/api/types.ts");
        let content = super::typescript_bindings();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current != content {
            std::fs::write(&path, content).unwrap();
        }
    }
}
