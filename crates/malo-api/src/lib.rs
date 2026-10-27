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
    /// Code from the authenticator app (or a recovery code) when two-step login is on. Without
    /// it, such a login fails with the code `totp_required` and changes nothing.
    #[serde(default)]
    #[ts(optional)]
    pub totp: Option<String>,
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
    /// The saved kit doesn't hold the destinations as they are now (added or changed since, or
    /// with new credentials where the kit keeps them), so a new kit should be saved.
    /// Older servers don't send it.
    #[serde(default)]
    pub recovery_kit_outdated: bool,
    /// Jobs that came due while the user was locked and were skipped.
    pub skipped_while_locked: u32,
    /// Logging in also asks for a code from an authenticator app. Older servers don't send it.
    #[serde(default)]
    pub totp_enabled: bool,
    /// Recovery codes left for two-step login.
    #[serde(default)]
    pub totp_recovery_codes_left: u32,
}

// ───────────────────────────── two-step login (TOTP) ─────────────────────────────

/// Starts turning on two-step login: asks for the password again.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct TotpSetupRequest {
    pub password: String,
}

/// A new authenticator secret, not in use until confirmed with a code from it.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct TotpSetup {
    /// Base32, for typing into the app by hand.
    pub secret: String,
    /// `otpauth://totp/…`
    pub uri: String,
    /// The URI as a QR code (SVG markup).
    pub qr_svg: String,
}

/// Confirms [`TotpSetup`] with a code from the app, or (with the password) turns two-step login
/// off or replaces the recovery codes.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct TotpCodeRequest {
    pub code: String,
    #[serde(default)]
    #[ts(optional)]
    pub password: Option<String>,
}

/// One-time codes for when the authenticator app is lost. Shown once; Malo keeps only hashes.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct TotpRecoveryCodes {
    pub codes: Vec<String>,
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

/// Checks the caller's password without changing anything, e.g. before an app stores it.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

/// First-boot admin creation with the one-time token printed in the server log.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct SetupRequest {
    pub setup_token: String,
    pub username: String,
    pub password: String,
    /// Optional recovery kit: the administrator is restored from it, like a registration with a
    /// kit (a replacement for a lost server).
    #[serde(default)]
    #[ts(optional)]
    pub recovery_kit: Option<RecoveryKitFile>,
    #[serde(default)]
    #[ts(optional)]
    pub kit_passphrase: Option<String>,
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
pub struct RegisterResponse {
    /// Destinations set up from the recovery kit. When there are any, the first login restores
    /// accounts, settings and mail from them.
    pub restored_destinations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ServerStatus {
    pub version: String,
    pub needs_setup: bool,
    pub self_registration: bool,
    /// SHA-256 fingerprint (hex, colon separated) of the TLS certificate the server serves.
    pub cert_fingerprint: Option<String>,
}

/// `GET /healthz` (anyone: just the status) and `GET /admin/health` (with the user counts).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct Health {
    pub status: String,
    #[serde(default)]
    #[ts(optional = nullable)]
    pub sealed_users: Option<u32>,
    #[serde(default)]
    #[ts(optional = nullable)]
    pub unlocked_users: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct UserSettings {
    pub auto_lock_hours: u32,
    pub quick_check_hours: u32,
    pub deep_check_hours: u32,
    pub auto_repair: bool,
    /// The settings copy on each destination also holds mail passwords and sign-in tokens, so a
    /// restore brings accounts back ready to run. Off: restored accounts ask to sign in again.
    #[serde(default)]
    pub copy_mail_credentials: bool,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            auto_lock_hours: 24,
            quick_check_hours: 24,
            deep_check_hours: 24 * 7,
            auto_repair: false,
            copy_mail_credentials: false,
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
    /// The user's destinations when the kit was saved, their credentials only where the user
    /// asked for that ([`DestinationInput::recovery_secrets`]). Registering with
    /// the kit sets them up again and the first login rebuilds everything from them, so nothing
    /// has to be typed in. Only ever inside a sealed kit; absent in kits from older versions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[ts(skip)]
    pub destinations: Vec<serde_json::Value>,
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
    /// Outgoing server for mail sent through Malo's SMTP submission service. It signs in with
    /// the same username and credentials as the IMAP server. None: sending is not set up.
    #[serde(default)]
    #[ts(optional)]
    pub smtp: Option<SmtpSettings>,
}

/// The upstream SMTP server of an account (submission, always over TLS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    /// Implicit TLS (port 465) or STARTTLS (port 587).
    pub tls: TlsMode,
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
    pub smtp: Option<SmtpSettings>,
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
    pub smtp: Option<SmtpSettings>,
}

// ───────────────────────────── mail access (IMAP / SMTP) ─────────────────────────────

/// How mail apps reach this server, and the logins of the user's accounts.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MailAccessInfo {
    /// Port of the IMAP service (TLS or STARTTLS); None when the server doesn't run it.
    pub imap_port: Option<u16>,
    /// Port of the SMTP submission service (TLS or STARTTLS); None when the server doesn't run it.
    pub smtp_port: Option<u16>,
    /// SHA-256 fingerprint of the certificate both services present, or of Malo's certificate
    /// authority that issues it.
    pub fingerprint: Option<String>,
    /// Malo issues its own certificates: devices install its authority (`/tls/malo-ca.*`).
    pub authority: bool,
    /// The names and addresses the certificate covers; mail apps must use one of them.
    pub certificate_names: Vec<String>,
    pub logins: Vec<MailLoginView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MailLoginView {
    pub account_id: String,
    pub username: String,
    pub created_at: Timestamp,
    pub last_used: Option<Timestamp>,
}

/// Creates the IMAP/SMTP login of an account, or replaces it (new username and/or a new
/// password). The password is always generated by the server.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MailLoginRequest {
    pub username: String,
    /// Length of the generated password (16–128, default 24).
    #[serde(default)]
    #[ts(optional)]
    pub password_length: Option<u32>,
}

/// The folders mail apps can see of one account, and which of them they do.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MailViewInfo {
    /// A Gmail account: it has labels and inbox categories.
    pub gmail: bool,
    pub inbox_all_mail: bool,
    pub split_categories: bool,
    pub folders: Vec<MailFolderInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MailFolderInfo {
    /// Raw (modified UTF-7) name, as mail apps see it.
    pub name: String,
    pub display_name: String,
    /// `\Sent`, `\Drafts`, `\Junk`, `\Trash`, `\All`…
    pub special_use: Option<String>,
    pub kind: MailFolderKind,
    pub shown: bool,
    #[ts(type = "number")]
    pub messages: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum MailFolderKind {
    /// A mailbox of the account's server.
    Mailbox,
    /// A Gmail label.
    Label,
    /// Gmail's INBOX holding only the Primary category.
    Primary,
    /// Gmail's INBOX holding all of All Mail.
    AllMail,
    /// A Gmail inbox category (Social, Promotions, Updates, Forums).
    Category,
    /// A saved search shown as a folder (`Smart/…`).
    Smart,
    /// A collection shown as a folder (`Collections/…`).
    Collection,
}

/// Which folders mail apps see. Messages a mail app moved keep their place either way.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MailViewSettings {
    /// Gmail: INBOX shows every message of All Mail, archived ones too.
    pub inbox_all_mail: bool,
    /// Gmail: INBOX shows Primary only; Social, Promotions, Updates and Forums get folders.
    pub split_categories: bool,
    /// Raw names of the folders to leave out (INBOX is always shown).
    pub hidden: Vec<String>,
}

/// Returned once: the server keeps only a hash of the password.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MailLoginCreated {
    pub login: MailLoginView,
    pub password: String,
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

/// S3 Object Lock / B2 File Lock retention mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum LockMode {
    /// Users with a special permission can still shorten or remove the lock.
    Governance,
    /// Nobody can delete or shorten it until it expires, not even the account's root user.
    Compliance,
}

/// Every message object written to the destination is locked against deletion and overwriting
/// for `days`. Integrity checks extend the lock of objects still in the backup, so it rolls
/// forward and old mail stays protected. Needs a bucket created with Object Lock (S3) or File
/// Lock (B2) enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ObjectLock {
    pub mode: LockMode,
    pub days: u32,
}

/// Longest lock Malo sets (ten years).
pub const MAX_LOCK_DAYS: u32 = 3650;

/// How Malo uses a destination, apart from where it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct DestinationFeatures {
    /// Compress messages with zstd before encrypting them (encrypted destinations only; plain
    /// destinations keep browsable `.eml` files).
    #[serde(default = "yes")]
    pub compress: bool,
    /// S3 and B2 only.
    #[serde(default)]
    #[ts(optional)]
    pub object_lock: Option<ObjectLock>,
    /// Limit on writes to this destination, in KiB/s (0: none).
    #[serde(default)]
    pub upload_kib_per_sec: u32,
    /// Limit on reads from this destination, in KiB/s (0: none).
    #[serde(default)]
    pub download_kib_per_sec: u32,
    /// Storage price per GB and month, for the cost estimate.
    #[serde(default)]
    #[ts(optional)]
    pub price_per_gb_month: Option<f64>,
}

impl Default for DestinationFeatures {
    fn default() -> Self {
        Self {
            compress: true,
            object_lock: None,
            upload_kib_per_sec: 0,
            download_kib_per_sec: 0,
            price_per_gb_month: None,
        }
    }
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
    /// Keep this destination's credentials in the recovery kit and the settings copies. Off, a
    /// restore brings the destination back without them and asks for them again.
    #[serde(default)]
    pub recovery_secrets: bool,
    #[serde(default)]
    pub features: DestinationFeatures,
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
    /// Older servers send neither of these.
    #[serde(default)]
    #[ts(optional)]
    pub recovery_secrets: Option<bool>,
    /// Credentials it came back without from a recovery kit or settings copy: until they are
    /// entered again, nothing is written to or read from it.
    #[serde(default)]
    #[ts(optional)]
    pub missing_secrets: Option<Vec<String>>,
    #[ts(type = "number")]
    pub object_count: u64,
    #[ts(type = "number")]
    pub stored_bytes: u64,
    pub health: Option<DestinationHealth>,
    #[serde(default)]
    pub features: DestinationFeatures,
    /// Objects still stored without compression (a *Compress stored mail* job shrinks them).
    #[serde(default)]
    #[ts(type = "number")]
    pub uncompressed_objects: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct DestinationTest {
    pub ok: bool,
    pub error: Option<String>,
    #[ts(type = "number")]
    pub write_ms: u64,
    #[ts(type = "number")]
    pub read_ms: u64,
    /// With Object Lock set: what the bucket and a locked probe object showed.
    #[serde(default)]
    #[ts(optional)]
    pub lock: Option<String>,
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

/// Most messages one delete job takes; the app splits larger selections.
pub const MAX_DELETE_BATCH: usize = 1000;

/// Where selected messages are deleted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum DeleteScope {
    /// From the mail server only; the backup stays. Like a purge: each message must be verified
    /// on the purge policy's required destinations (or every destination when none are set).
    Server,
    /// From the backup (index, manifests and stored objects on every destination), and first from
    /// the mail server where it's still there, so the next backup doesn't bring it back.
    Everywhere,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct DeleteSummary {
    pub account_id: String,
    #[ts(type = "number")]
    pub deleted_from_server: u64,
    #[ts(type = "number")]
    pub deleted_from_backup: u64,
    #[ts(type = "number")]
    pub skipped: u64,
    pub errors: Vec<String>,
}

/// Marks messages as spam, or as not spam (`spam: false`). Malo records it at once; messages
/// still on their mail server are also moved there, into its Junk folder (or back to the inbox),
/// by a job per account.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct SpamRequest {
    #[ts(type = "Array<number>")]
    pub ids: Vec<i64>,
    pub spam: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct SpamResponse {
    /// Messages marked in Malo.
    #[ts(type = "number")]
    pub marked: u64,
    /// The jobs moving messages on their mail servers (none when every message was already
    /// gone from its server).
    pub jobs: Vec<JobInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct SpamSummary {
    pub account_id: String,
    pub spam: bool,
    /// Moved on the mail server.
    #[ts(type = "number")]
    pub moved: u64,
    /// Already where they belong, or no longer on the server.
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
    /// Indexes mail backed up before it could be indexed for full-text search.
    SearchIndex,
    /// Deletes messages the user selected (at most [`MAX_DELETE_BATCH`]).
    DeleteMessages {
        account_id: String,
        #[ts(type = "Array<number>")]
        message_ids: Vec<i64>,
        scope: DeleteScope,
    },
    /// Moves messages the user marked as spam into the mail server's Junk folder, or ones marked
    /// as not spam back to the inbox (at most [`MAX_DELETE_BATCH`]).
    MoveSpam {
        account_id: String,
        #[ts(type = "Array<number>")]
        message_ids: Vec<i64>,
        spam: bool,
    },
    /// Uploads backed-up messages to a mail account (`IMAP APPEND`).
    RestoreToImap {
        target_account_id: String,
        selection: RestoreSelection,
        target: RestoreTarget,
    },
    /// Rewrites objects stored before compression (or on a destination that just turned it on)
    /// compressed. All destinations without one.
    CompressStored {
        #[serde(default)]
        #[ts(optional)]
        destination_id: Option<String>,
    },
}

/// Which backed-up messages a restore uploads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum RestoreSelection {
    Messages {
        #[ts(type = "Array<number>")]
        ids: Vec<i64>,
    },
    /// Everything a search finds (the same syntax as the search box).
    Search {
        query: String,
        #[serde(default)]
        #[ts(optional)]
        account_id: Option<String>,
    },
    /// Every message of an account, optionally of one mailbox.
    Account {
        account_id: String,
        #[serde(default)]
        #[ts(optional)]
        mailbox: Option<String>,
    },
}

/// Where restored messages go on the target account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "to", rename_all = "snake_case")]
pub enum RestoreTarget {
    /// The mailboxes they were backed up from (created when missing; Gmail labels become labels).
    Original,
    /// One folder for all of them, created when missing.
    Folder { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct RestoreRequest {
    pub target_account_id: String,
    pub selection: RestoreSelection,
    pub target: RestoreTarget,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct RestoreSummary {
    pub target_account_id: String,
    #[ts(type = "number")]
    pub restored: u64,
    /// Already in the target mailbox (same Message-ID).
    #[ts(type = "number")]
    pub skipped: u64,
    #[ts(type = "number")]
    pub failed: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct CompressSummary {
    #[ts(type = "number")]
    pub objects: u64,
    #[ts(type = "number")]
    pub bytes_before: u64,
    #[ts(type = "number")]
    pub bytes_after: u64,
    #[ts(type = "number")]
    pub failed: u64,
    pub errors: Vec<String>,
}

// ───────────────────────────── storage usage ─────────────────────────────

/// What one account takes up on one destination.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct UsageCell {
    pub account_id: String,
    pub destination_id: String,
    #[ts(type = "number")]
    pub messages: u64,
    /// Size of the messages themselves.
    #[ts(type = "number")]
    pub message_bytes: u64,
    /// What the objects take up on the destination (after compression and encryption;
    /// duplicates stored once).
    #[ts(type = "number")]
    pub stored_bytes: u64,
}

/// Stored bytes of one destination at the end of a day.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct UsagePoint {
    /// `YYYY-MM-DD`
    pub date: String,
    pub destination_id: String,
    #[ts(type = "number")]
    pub stored_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
pub struct UsageReport {
    pub cells: Vec<UsageCell>,
    /// Daily totals per destination, oldest first, from the first backup on.
    pub history: Vec<UsagePoint>,
}

// ───────────────────────────── saved searches ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct SavedSearch {
    pub id: String,
    pub name: String,
    /// Search box syntax.
    pub query: String,
    /// Limited to one account; all accounts without.
    #[serde(default)]
    #[ts(optional)]
    pub account_id: Option<String>,
    /// Also a folder in mail apps (under `Smart/`), with the messages of the mail login's account.
    #[serde(default)]
    pub mail_folder: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct SavedSearchInput {
    pub name: String,
    pub query: String,
    #[serde(default)]
    #[ts(optional)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub mail_folder: bool,
}

// ───────────────────────────── collections ─────────────────────────────

/// Messages grouped by hand. Kept in Malo only (never on the mail server), in the backup's
/// manifests too, so a rebuild brings them back. Searchable as `tag:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct Collection {
    pub id: String,
    pub name: String,
    /// Also a folder in mail apps (under `Collections/`), with the messages of the mail login's
    /// account. Copying mail into it adds it; deleting it there takes it out again.
    pub mail_folder: bool,
    #[ts(type = "number")]
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct CollectionInput {
    pub name: String,
    #[serde(default)]
    pub mail_folder: bool,
}

/// Adds messages to a collection, or takes them out.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct CollectionMembersRequest {
    #[ts(type = "Array<number>")]
    pub ids: Vec<i64>,
    #[serde(default = "yes")]
    pub add: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct CollectionMembersResult {
    /// Messages that were added (or taken out); the others already were.
    #[ts(type = "number")]
    pub changed: u64,
    pub collection: Collection,
}

// ───────────────────────────── alerts ─────────────────────────────

/// Where alerts go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AlertChannel {
    /// A JSON `POST` with `title`, `message`, `severity` and `event` (see the README).
    Webhook { url: String },
    /// An ntfy topic, on ntfy.sh or a server of your own.
    Ntfy {
        /// Defaults to `https://ntfy.sh`.
        server: String,
        topic: String,
        /// An access token for protected topics ([`REDACTED`] in views).
        #[serde(default)]
        #[ts(optional)]
        token: Option<String>,
    },
    /// The notify endpoint of an Apprise API server, e.g. `http://apprise:8000/notify/malo`,
    /// which passes the alert on to whatever services it is set up for.
    Apprise { url: String },
    /// An email sent through the outgoing (SMTP) server of one of your accounts. Only while
    /// you're logged in: the account's credentials are sealed while you're locked.
    Email { account_id: String, to: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct AlertSettings {
    #[serde(default)]
    pub channels: Vec<AlertChannel>,
    /// Alert when an account's backup failed this many times in a row (0: never).
    #[serde(default = "default_backup_failures")]
    pub backup_failures: u32,
    /// An integrity check found missing or damaged copies, or couldn't run.
    #[serde(default = "yes")]
    pub check_problems: bool,
    /// Signing in to a mail account with OAuth stopped working (the refresh token was refused).
    #[serde(default = "yes")]
    pub oauth_failures: bool,
    /// A destination can't be reached.
    #[serde(default = "yes")]
    pub destination_unreachable: bool,
    /// Scheduled jobs are being skipped because you're locked. Sent through webhooks, ntfy and
    /// Apprise only, whose addresses the server then keeps readable while you're locked.
    #[serde(default = "yes")]
    pub skipped_locked: bool,
    /// Also say when a problem alerted about is over.
    #[serde(default = "yes")]
    pub recoveries: bool,
}

fn default_backup_failures() -> u32 {
    3
}

impl Default for AlertSettings {
    fn default() -> Self {
        Self {
            channels: vec![],
            backup_failures: default_backup_failures(),
            check_problems: true,
            oauth_failures: true,
            destination_unreachable: true,
            skipped_locked: true,
            recoveries: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum AlertEvent {
    BackupFailing,
    CheckProblems,
    OauthFailing,
    DestinationUnreachable,
    SkippedLocked,
    Recovered,
    Test,
}

/// What happened when an alert was sent to one channel.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct AlertDelivery {
    /// The channel, e.g. "ntfy alerts" or "email to me@example.com".
    pub channel: String,
    pub ok: bool,
    pub error: Option<String>,
}

// ───────────────────────────── export ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// mboxrd: one file per folder (zipped when there are several).
    Mbox,
    /// A zipped Maildir++ tree per account, with flags in the file names.
    Maildir,
    /// A zip of `.eml` files in their folders.
    Zip,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ExportRequest {
    pub selection: RestoreSelection,
    pub format: ExportFormat,
}

/// A prepared export: download it once from `/export/{token}` within a few minutes.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct ExportTicket {
    pub token: String,
    pub filename: String,
    #[ts(type = "number")]
    pub messages: u64,
}

impl JobKind {
    /// Account whose mutex this job needs, if any.
    pub fn account_id(&self) -> Option<&str> {
        match self {
            JobKind::Backup { account_id }
            | JobKind::Purge { account_id }
            | JobKind::DeleteMessages { account_id, .. }
            | JobKind::MoveSpam { account_id, .. } => Some(account_id),
            JobKind::RestoreToImap {
                target_account_id, ..
            } => Some(target_account_id),
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
    /// With a full-text search: the best-matching text, matches between U+0002 and U+0003.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub snippet: Option<String>,
    /// Gmail category other than Primary (`social`, `promotions`, `updates`, `forums`).
    pub category: Option<String>,
    /// Messages in its conversation, itself included.
    #[serde(default)]
    pub thread_size: u32,
    /// In a conversation: the start of the text, without quoted replies.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub preview: Option<String>,
    /// Spam: marked so in Malo, or in the mail server's Junk folder and not marked otherwise.
    #[serde(default)]
    pub spam: bool,
    /// Names of the collections it is in.
    #[serde(default)]
    pub collections: Vec<String>,
}

/// A value for a search operator (`from:`, `to:`, `file:`), most used first.
#[derive(Debug, Clone, Serialize, Deserialize, TS, PartialEq, Eq)]
pub struct SearchSuggestion {
    pub value: String,
    /// The sender's display name, for `from:`.
    pub name: Option<String>,
    #[ts(type = "number")]
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct MessageList {
    #[ts(type = "number")]
    pub total: u64,
    pub messages: Vec<MessageSummary>,
    /// With a search: messages not indexed for full-text search yet (matched by sender,
    /// recipients and subject only).
    #[serde(default)]
    #[ts(type = "number")]
    pub unindexed: u64,
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
    /// Where replies go, when the sender asks for another address (Reply-To).
    #[serde(default)]
    pub reply_to: Vec<String>,
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

/// A message written in Malo, sent through the account's SMTP server.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct SendRequest {
    /// Sender address; the account's username when it is an address.
    #[serde(default)]
    #[ts(optional)]
    pub from: Option<String>,
    /// `Name <addr>` or `addr`.
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    /// The message this answers (In-Reply-To, References).
    #[serde(default)]
    #[ts(optional, type = "number")]
    pub in_reply_to: Option<i64>,
    /// A message whose attachments go along (forwarding).
    #[serde(default)]
    #[ts(optional, type = "number")]
    pub attachments_of: Option<i64>,
    /// The draft this was written in: deleted once the message is sent.
    #[serde(default)]
    #[ts(optional, type = "number")]
    pub draft_id: Option<i64>,
}

/// A message being written, kept (encrypted, in Malo only) until it is sent or discarded.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct DraftView {
    #[ts(type = "number")]
    pub id: i64,
    pub account_id: String,
    pub message: SendRequest,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct DraftInput {
    /// The draft to update; a new one without it.
    #[serde(default)]
    #[ts(optional, type = "number")]
    pub id: Option<i64>,
    pub account_id: String,
    pub message: SendRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct SendResult {
    pub message_id: String,
    /// The sent copy was saved in this mailbox on the account's server (not for Gmail, which
    /// files sent mail itself).
    pub saved_to: Option<String>,
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
    /// Server-wide limit on writes to storage, in KiB/s, shared by every user (0: none).
    #[serde(default)]
    pub upload_kib_per_sec: u32,
    /// Server-wide limit on downloads from mail servers and storage, in KiB/s (0: none).
    #[serde(default)]
    pub download_kib_per_sec: u32,
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
            upload_kib_per_sec: 0,
            download_kib_per_sec: 0,
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
    /// Messages the user deleted from the backup: they're gone from the index.
    MessagesDeleted {
        account_id: String,
        #[ts(type = "Array<number>")]
        ids: Vec<i64>,
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
        TotpSetupRequest,
        TotpSetup,
        TotpCodeRequest,
        TotpRecoveryCodes,
        ChangePasswordRequest,
        DeleteAccountRequest,
        SetupRequest,
        RegisterRequest,
        RegisterResponse,
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
        SmtpSettings,
        MailAccessInfo,
        MailLoginView,
        MailLoginRequest,
        MailLoginCreated,
        MailViewInfo,
        MailFolderInfo,
        MailFolderKind,
        MailViewSettings,
        DeepCheckMode,
        LockMode,
        ObjectLock,
        DestinationFeatures,
        DestinationInput,
        DestinationView,
        DestinationTest,
        PurgePolicy,
        PurgePreview,
        PurgeMailboxCount,
        ArmRequest,
        PurgeSummary,
        DeleteScope,
        DeleteSummary,
        SpamRequest,
        SpamResponse,
        SpamSummary,
        CheckScope,
        JobKind,
        RestoreSelection,
        RestoreTarget,
        RestoreRequest,
        RestoreSummary,
        CompressSummary,
        UsageCell,
        UsagePoint,
        UsageReport,
        SavedSearch,
        SavedSearchInput,
        Collection,
        CollectionInput,
        CollectionMembersRequest,
        CollectionMembersResult,
        AlertChannel,
        AlertSettings,
        AlertEvent,
        AlertDelivery,
        ExportFormat,
        ExportRequest,
        ExportTicket,
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
        SearchSuggestion,
        SendRequest,
        SendResult,
        DraftView,
        DraftInput,
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
    out.push_str(&format!("export const MAX_LOCK_DAYS = {MAX_LOCK_DAYS};\n"));
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
