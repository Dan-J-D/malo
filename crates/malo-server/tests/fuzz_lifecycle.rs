//! Stateful, model-based fuzzing of client interference and client lifecycle.
//!
//! A seeded generator produces sequences of operations by several users at once — register, login,
//! logout, lock, auto-lock, password change, self-deletion, admin disable/delete, server restart,
//! accounts and destinations (also on shared storage), backups/checks/repairs/rebuilds/purges that
//! overlap with all of the above, and outside-world faults (mail added/deleted by other clients,
//! mailboxes recreated, IMAP connections kicked, storage objects deleted/corrupted, storage outages).
//! After every step a set of invariants is checked against a model of what should be true.
//! A failure is shrunk to a minimal sequence (delta debugging) and saved for replay.
//!
//! ```sh
//! docker compose --profile test up -d && docker compose --profile test up rustfs-init
//! MALO_IT=1 cargo test -p malo-server --test fuzz_lifecycle -- --nocapture
//! # knobs: MALO_FUZZ_RUNS=20 MALO_FUZZ_STEPS=60 MALO_FUZZ_SEED=1234 MALO_FUZZ_SHRINK=25
//! # replay: MALO_FUZZ_REPLAY=target/fuzz-lifecycle/failure-<seed>.json
//! ```

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use malo_api::*;
use malo_core::faults;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use reqwest::Method;
use serde::{Deserialize, Serialize};

const USERS: usize = 4;
const MAILBOXES: usize = 3;
const AUTO_LOCK_SECS: i64 = 40;
const S3_BUCKET: &str = "malo-b";

// ───────────────────────────── operations ─────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum DestKind {
    /// Admin-allowed mount; every user asks for the same path.
    SharedMount,
    /// Same S3 bucket and prefix for every user.
    SharedS3,
    /// A path that tries to leave the allowed area: refused, or confined so that nothing ever
    /// lands outside it (see `TRAVERSAL_ROOTS`).
    Traversal,
    /// A symlink inside the user's own mount folder that points outside it.
    Symlink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Op {
    Register {
        u: usize,
    },
    Login {
        u: usize,
    },
    Logout {
        u: usize,
    },
    Lock {
        u: usize,
    },
    ChangePassword {
        u: usize,
    },
    DeleteSelf {
        u: usize,
    },
    AdminSetDisabled {
        u: usize,
        disabled: bool,
    },
    AdminDelete {
        u: usize,
    },
    Restart,
    /// The user's index is lost (disk failure): the server restarts without it.
    LoseIndex {
        u: usize,
    },
    Sleep {
        ms: u64,
    },
    AddDestination {
        u: usize,
        kind: DestKind,
        #[serde(default)]
        name: Option<String>,
        /// Shared mount: hostile sub-folder · S3: hostile prefix · traversal: template index.
        #[serde(default)]
        root: Option<String>,
        #[serde(default)]
        encrypt: Option<bool>,
        #[serde(default)]
        deep: Option<u8>,
    },
    RemoveDestination {
        u: usize,
        slot: usize,
    },
    AddAccount {
        u: usize,
        mailbox: usize,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        opts: Option<AccOpts>,
    },
    RenameAccount {
        u: usize,
        slot: usize,
        #[serde(default)]
        name: Option<String>,
    },
    RemoveAccount {
        u: usize,
        slot: usize,
    },
    Backup {
        u: usize,
        slot: usize,
        wait: bool,
    },
    Check {
        u: usize,
        deep: bool,
        wait: bool,
    },
    Repair {
        u: usize,
        wait: bool,
    },
    Rebuild {
        u: usize,
        slot: usize,
        wait: bool,
        /// From every destination instead of one.
        #[serde(default)]
        all: bool,
    },
    ArmPurge {
        u: usize,
        slot: usize,
        #[serde(default)]
        policy: Option<PolicyShape>,
    },
    Purge {
        u: usize,
        slot: usize,
        wait: bool,
    },
    CancelLatest {
        u: usize,
    },
    ImapAppend {
        m: usize,
        to_box: bool,
        /// Another (hostile-named, possibly nested) folder instead of INBOX/Box.
        #[serde(default)]
        folder: Option<String>,
        #[serde(default)]
        shape: Option<MsgShape>,
    },
    /// Another mail client creates, renames or deletes a folder.
    ImapFolder {
        m: usize,
        action: FolderAction,
    },
    ImapDelete {
        m: usize,
    },
    ImapRecreateBox {
        m: usize,
    },
    ImapKick {
        m: usize,
    },
    DeleteSharedObject {
        pick: u32,
    },
    CorruptSharedObject {
        pick: u32,
    },
    StorageOutage {
        ms: u64,
    },
    Probe {
        u: usize,
        v: usize,
    },
    /// Several operations at the same time.
    Burst {
        ops: Vec<Op>,
    },
    /// Second device of the same user.
    LoginB {
        u: usize,
    },
    LogoutB {
        u: usize,
    },
    /// Device B saves an account form loaded before device A changed it.
    StaleEdit {
        u: usize,
        slot: usize,
    },
    /// Storage / local-disk fault rule (seeded, self-expiring after `count` injections).
    Faults {
        site: faults::Site,
        fault: faults::Fault,
        per_mille: u32,
        target: FaultTarget,
        count: u32,
    },
    ClearFaults,
    /// Network fault between Malo and S3 (toxiproxy) for `ms`.
    Net {
        kind: NetKind,
        ms: u64,
    },
    /// A user's local-folder destination becomes read-only (real EACCES) for `ms`.
    ReadOnlyPrimary {
        u: usize,
        ms: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum FaultTarget {
    AnyDestination,
    Primary { u: usize },
    Shared { u: usize },
    Local,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum NetKind {
    Reset,
    Timeout,
    Latency,
    CutUpload,
}

// ───────────────────────────── hostile inputs ─────────────────────────────

/// Pieces of names from hell: Unicode normalization pairs and case twins, invisible and bidi
/// characters, look-alikes, emoji sequences, path syntax (also look-alike and encoded), IMAP
/// modified-UTF-7 syntax, shell/glob characters and reserved device names.
const NAME_PIECES: &[&str] = &[
    "inbox",
    "INBOX",
    "Archive",
    "café",
    "cafe\u{301}",
    "CAFÉ",
    "Straße",
    "STRASSE",
    "ǅ",
    "ﬁle",
    "Ä",
    "A\u{308}",
    "\u{301}",
    "\u{200B}",
    "\u{200D}",
    "\u{202E}",
    "\u{2066}",
    "\u{FEFF}",
    "\u{00AD}",
    "\u{180E}",
    "📧",
    "👨\u{200D}👩\u{200D}👧",
    "🏳\u{FE0F}\u{200D}🌈",
    "收件箱",
    "بريد",
    "רשימה",
    "Почта",
    "раypal",
    "аpple",
    "..",
    ".",
    "/",
    "\\",
    "%2e%2e",
    "%2F",
    "．．",
    "‥",
    "⁄",
    "∕",
    "~",
    "~1",
    "&",
    "&-",
    "&AOk-",
    "+",
    ":",
    "*",
    "%",
    "?",
    "\"",
    "<",
    ">",
    "|",
    " ",
    "\t",
    "\n",
    "\0",
    "CON",
    "NUL",
    "COM1",
    ".git",
    "-rf",
    "$HOME",
    "${x}",
    "'",
    "`",
    "#",
    ";",
];

fn hostile_name(rng: &mut StdRng) -> String {
    let mut s = String::new();
    for _ in 0..rng.gen_range(1..5) {
        s.push_str(NAME_PIECES[rng.gen_range(0..NAME_PIECES.len())]);
    }
    if rng.gen_bool(0.08) {
        s = s.repeat(rng.gen_range(10..40)); // far beyond any file-name limit
    }
    s
}

/// A name that is hostile most of the time and plain otherwise.
fn maybe_hostile(rng: &mut StdRng) -> Option<String> {
    rng.gen_bool(0.7).then(|| hostile_name(rng))
}

/// Traversal attempts for local-folder destinations. `{canary}` is a folder next to the data
/// directory and the mount; nothing may ever appear in it. `{mount}` is the allowed mount.
const TRAVERSAL_ROOTS: &[&str] = &[
    "../../../../tmp",
    "../outside",
    "a/../../outside",
    "./../outside",
    "{canary}",
    "{canary}/x",
    "{mount}/../outside",
    "{mount}/a/../../outside",
    "..%2f..%2foutside",
    "．．/．．/outside",
    "‥/‥/outside",
    "..\\..\\outside",
    "..\u{2215}..\u{2215}outside",
    "{mount}/\u{0}/../outside",
    "~/../outside",
    "//{canary}",
];

/// What a fuzzed message looks like (the bytes are built from this and its token).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MsgShape {
    /// 0 plain · 1 RFC 2047 + quoted-printable · 2 hostile attachment names + HTML ·
    /// 3 malformed MIME · 4 large · 5 headers only · 6 Latin-1 8-bit
    kind: u8,
    /// Large bodies only.
    size: u32,
    flags: Vec<String>,
    /// IMAP internal date.
    date: String,
    /// Shares one Message-ID with every other such message (identity must not rely on it).
    dup_id: bool,
    name: String,
}

fn gen_shape(rng: &mut StdRng) -> MsgShape {
    const FLAGS: &[&str] = &[
        "\\Seen",
        "\\Flagged",
        "\\Answered",
        "\\Draft",
        "$Junk",
        "fuzzkw",
    ];
    const MONTHS: &[&str] = &[
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    MsgShape {
        kind: rng.gen_range(0..7),
        size: rng.gen_range(1_000_000..3_000_000),
        flags: FLAGS
            .iter()
            .filter(|_| rng.gen_bool(0.25))
            .map(|f| f.to_string())
            .collect(),
        date: format!(
            "{:02}-{}-{} {:02}:{:02}:{:02} {}",
            rng.gen_range(1..29),
            MONTHS[rng.gen_range(0..12)],
            rng.gen_range(1999..2036),
            rng.gen_range(0..24),
            rng.gen_range(0..60),
            rng.gen_range(0..60),
            ["+0000", "-1200", "+1400", "+0530"][rng.gen_range(0..4)],
        ),
        dup_id: rng.gen_bool(0.15),
        name: hostile_name(rng),
    }
}

/// Header-safe version of a hostile string (no line breaks or NUL inside a header line).
fn header_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if matches!(c, '\r' | '\n' | '\0') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Builds a message whose subject starts with `"{token} subject"` (the model keys on it).
fn build_message(token: &str, shape: &MsgShape) -> Vec<u8> {
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let name = header_safe(&shape.name);
    let msg_id = if shape.dup_id {
        "<duplicate@fuzz.example>".to_string()
    } else {
        format!("<{}@fuzz.example>", uuid::Uuid::new_v4())
    };
    let head = |subject: &str, extra: &str| {
        format!(
            "From: \"{name}\" <sender@example.com>\r\nTo: rcpt@example.com\r\nSubject: {subject}\r\n\
Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: {msg_id}\r\nMIME-Version: 1.0\r\n{extra}"
        )
    };
    let mut m: Vec<u8> = match shape.kind {
        1 => {
            let subject = format!("{token} subject =?UTF-8?B?{}?=", b64(name.as_bytes()));
            let body: String = name
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() {
                        (b as char).to_string()
                    } else {
                        format!("={b:02X}")
                    }
                })
                .collect();
            format!(
                "{}Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{body}\r\n",
                head(&subject, "")
            )
            .into_bytes()
        }
        2 => {
            let encoded: String = name
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            let mut s = head(
                &format!("{token} subject {name}"),
                "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n",
            );
            s.push_str("--B\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p onclick=\"x()\">hi</p><script>alert(1)</script><a href=\"javascript:alert(1)\">x</a>\r\n");
            for fname in [
                format!("../../{name}.exe"),
                format!("\u{202E}{name}gpj.exe"),
                name.clone(),
            ] {
                s.push_str(&format!(
                    "--B\r\nContent-Type: application/octet-stream; name=\"{fname}\"\r\nContent-Disposition: attachment; filename=\"{fname}\"; filename*=UTF-8''{encoded}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
                    b64(fname.as_bytes())
                ));
            }
            s.push_str("--B--\r\n");
            s.into_bytes()
        }
        3 => format!(
            "{}Content-Type: multipart/mixed; boundary=\"never-closed\"\r\n\r\n--never-closed\r\nContent-Type: text/plain; charset=x-unknown-{}\r\nContent-Transfer-Encoding: base64\r\n\r\n!!not*base64$$\r\n",
            head(&format!("{token} subject {name}"), ""),
            name.len()
        )
        .into_bytes(),
        4 => {
            let mut s = head(
                &format!("{token} subject large"),
                "Content-Type: text/plain; charset=utf-8\r\n\r\n",
            )
            .into_bytes();
            let line = format!("{} {name}\r\n", "x".repeat(70));
            while s.len() < shape.size as usize {
                s.extend_from_slice(line.as_bytes());
            }
            s
        }
        5 => format!("Subject: {token} subject\r\n\r\n").into_bytes(),
        6 => {
            let mut s = head(
                &format!("{token} subject latin1"),
                "Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
            )
            .into_bytes();
            s.extend_from_slice(b"caf\xe9 na\xefve \xa9 \xff\xfe\r\n");
            s
        }
        _ => {
            let mut s = head(
                &format!("{token} subject {name}"),
                "Content-Type: text/plain; charset=utf-8\r\n\r\n",
            );
            s.push_str(&format!("Body {name}\r\n"));
            s.into_bytes()
        }
    };
    if !m.ends_with(b"\r\n") {
        m.extend_from_slice(b"\r\n");
    }
    m
}

/// Account settings beyond the name.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccOpts {
    starttls: bool,
    idle: bool,
}

/// A randomized retention policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyShape {
    older_than_days: u32,
    exclude_flagged: bool,
    /// Excludes one of the server's folders (picked when the policy is set).
    exclude_pick: Option<u32>,
    only_primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum FolderAction {
    Create { name: String },
    Rename { pick: u32, to: String },
    Delete { pick: u32 },
}

fn gen_op(rng: &mut StdRng, depth: u32) -> Op {
    let u = rng.gen_range(0..USERS);
    let slot = rng.gen_range(0..3);
    let wait = rng.gen_bool(0.4);
    match rng.gen_range(0..100) {
        0..=5 => Op::Register { u },
        6..=13 => Op::Login { u },
        14..=15 => Op::Logout { u },
        16..=18 => Op::Lock { u },
        19 => Op::ChangePassword { u },
        20 => Op::DeleteSelf { u },
        21 => Op::AdminSetDisabled {
            u,
            disabled: rng.gen_bool(0.5),
        },
        22 => Op::AdminDelete { u },
        23 => Op::Restart,
        26 => Op::LoseIndex { u },
        24..=25 => Op::Sleep {
            ms: rng.gen_range(50..1500),
        },
        27..=30 => {
            let kind = match rng.gen_range(0..7) {
                0 | 1 => DestKind::SharedMount,
                2 | 3 => DestKind::SharedS3,
                4 | 5 => DestKind::Traversal,
                _ => DestKind::Symlink,
            };
            let root = match kind {
                DestKind::Traversal => Some(rng.gen_range(0..TRAVERSAL_ROOTS.len()).to_string()),
                _ if rng.gen_bool(0.3) => Some(hostile_name(rng)),
                _ => None,
            };
            Op::AddDestination {
                u,
                kind,
                name: maybe_hostile(rng),
                root,
                encrypt: Some(rng.gen_bool(0.5)),
                deep: Some(rng.gen_range(0..3)),
            }
        }
        31 => Op::RemoveDestination { u, slot },
        32..=37 => Op::AddAccount {
            u,
            mailbox: rng.gen_range(0..MAILBOXES),
            name: maybe_hostile(rng),
            opts: rng.gen_bool(0.5).then(|| AccOpts {
                starttls: rng.gen_bool(0.5),
                idle: rng.gen_bool(0.4),
            }),
        },
        38..=39 => Op::RenameAccount {
            u,
            slot,
            name: maybe_hostile(rng),
        },
        40 => Op::RemoveAccount { u, slot },
        41..=48 => Op::Backup { u, slot, wait },
        49..=50 => Op::ImapFolder {
            m: rng.gen_range(0..MAILBOXES),
            action: match rng.gen_range(0..4) {
                0 | 1 => FolderAction::Create {
                    name: hostile_name(rng),
                },
                2 => FolderAction::Rename {
                    pick: rng.gen(),
                    to: hostile_name(rng),
                },
                _ => FolderAction::Delete { pick: rng.gen() },
            },
        },
        51..=53 => Op::Check {
            u,
            deep: rng.gen_bool(0.5),
            wait,
        },
        54..=55 => Op::Repair { u, wait },
        56..=57 => Op::Rebuild {
            u,
            slot,
            wait,
            all: rng.gen_bool(0.5),
        },
        58..=60 => Op::ArmPurge {
            u,
            slot,
            policy: rng.gen_bool(0.6).then(|| PolicyShape {
                older_than_days: rng.gen_range(0..4) * rng.gen_range(0..4000),
                exclude_flagged: rng.gen_bool(0.5),
                exclude_pick: rng.gen_bool(0.3).then(|| rng.gen()),
                only_primary: rng.gen_bool(0.3),
            }),
        },
        61..=64 => Op::Purge { u, slot, wait },
        65 => Op::CancelLatest { u },
        66..=72 => Op::ImapAppend {
            m: rng.gen_range(0..MAILBOXES),
            to_box: rng.gen_bool(0.3),
            folder: rng.gen_bool(0.25).then(|| hostile_name(rng)),
            shape: rng.gen_bool(0.7).then(|| gen_shape(rng)),
        },
        73..=74 => Op::ImapDelete {
            m: rng.gen_range(0..MAILBOXES),
        },
        75 => Op::ImapRecreateBox {
            m: rng.gen_range(0..MAILBOXES),
        },
        76..=77 => Op::ImapKick {
            m: rng.gen_range(0..MAILBOXES),
        },
        78 => Op::DeleteSharedObject { pick: rng.gen() },
        79 => Op::CorruptSharedObject { pick: rng.gen() },
        80 => Op::StorageOutage {
            ms: rng.gen_range(300..2500),
        },
        81..=84 => Op::Probe {
            u,
            v: rng.gen_range(0..USERS),
        },
        85..=86 => Op::LoginB { u },
        87 => Op::LogoutB { u },
        88 => Op::StaleEdit { u, slot },
        89..=95 => {
            use faults::{Fault, Site};
            let site = [
                Site::StoreWrite,
                Site::StoreWrite,
                Site::StoreRead,
                Site::StoreMeta,
                Site::Spool,
                Site::Cache,
                Site::ConfigWrite,
                Site::Index,
            ][rng.gen_range(0..8)];
            let fault = match site {
                Site::StoreWrite => [
                    Fault::Error,
                    Fault::NoSpace,
                    Fault::Truncate,
                    Fault::FlipBit,
                    Fault::LostWrite,
                    Fault::WriteThenError,
                    Fault::Slow,
                ][rng.gen_range(0..7)],
                Site::StoreRead => [Fault::Error, Fault::Truncate, Fault::FlipBit, Fault::Slow]
                    [rng.gen_range(0..4)],
                _ => [Fault::Error, Fault::NoSpace][rng.gen_range(0..2)],
            };
            let target = match site {
                Site::StoreWrite | Site::StoreRead | Site::StoreMeta => match rng.gen_range(0..3) {
                    0 => FaultTarget::AnyDestination,
                    1 => FaultTarget::Primary { u },
                    _ => FaultTarget::Shared { u },
                },
                _ => FaultTarget::Local,
            };
            Op::Faults {
                site,
                fault,
                per_mille: rng.gen_range(100..900),
                target,
                count: rng.gen_range(1..12),
            }
        }
        96 => Op::ClearFaults,
        97 => Op::Net {
            kind: [
                NetKind::Reset,
                NetKind::Timeout,
                NetKind::Latency,
                NetKind::CutUpload,
            ][rng.gen_range(0..4)],
            ms: rng.gen_range(300..3000),
        },
        98 => Op::ReadOnlyPrimary {
            u,
            ms: rng.gen_range(300..3000),
        },
        _ if depth == 0 => Op::Burst {
            ops: (0..rng.gen_range(2..5)).map(|_| gen_op(rng, 1)).collect(),
        },
        _ => Op::Backup {
            u,
            slot,
            wait: false,
        },
    }
}

fn gen_sequence(seed: u64, steps: usize) -> Vec<Op> {
    let mut rng = StdRng::seed_from_u64(seed);
    // A realistic start: a few users with accounts, so later operations have something to hit.
    let mut ops = vec![
        Op::Register { u: 0 },
        Op::Register { u: 1 },
        Op::AddAccount {
            u: 0,
            mailbox: 0,
            name: None,
            opts: None,
        },
        Op::AddAccount {
            u: 1,
            mailbox: 0,
            name: None,
            opts: None,
        },
        Op::ImapAppend {
            m: 0,
            to_box: false,
            folder: None,
            shape: None,
        },
    ];
    ops.extend((0..steps).map(|_| gen_op(&mut rng, 0)));
    ops
}

// ───────────────────────────── model ─────────────────────────────

#[derive(Default, Clone)]
struct AccModel {
    id: String,
    /// As the server stored it (it may normalize what was sent).
    name: String,
    mailbox: usize,
    starttls: bool,
    idle: bool,
}

#[derive(Default, Clone)]
struct DestModel {
    id: String,
    primary: bool,
}

/// Local disk faults (index, config, spool, cache) are active or fired within the last seconds.
fn local_faults_recent() -> bool {
    use faults::Site;
    [Site::Index, Site::ConfigWrite, Site::Spool, Site::Cache]
        .into_iter()
        .any(|site| faults::active(site) || faults::injected_recently(site, Duration::from_secs(5)))
}

#[derive(Default)]
struct UserModel {
    name: String,
    password: String,
    id: Option<String>,
    disabled: bool,
    deleted: bool,
    session: Option<(Api, Instant)>,
    /// Tokens that must never work again.
    stale: Vec<Api>,
    accounts: Vec<AccModel>,
    /// Every account id the user ever had (events/jobs may mention removed ones).
    ever_accounts: HashSet<String>,
    ever_destinations: HashSet<String>,
    destinations: Vec<DestModel>,
    jobs: Vec<String>,
    /// Mailbox slots this user ever backed up (for the never-lose-mail check).
    ever_mailboxes: HashSet<usize>,
    events: Option<Arc<Mutex<Vec<SyncEvent>>>>,
    /// Second device: its own session and event stream.
    device_b: Option<(Api, Instant)>,
    events_b: Option<Arc<Mutex<Vec<SyncEvent>>>>,
    /// When the keys stopped being valid (lock, delete, disable, restart).
    sealed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Mail whose only verified copy sat on a destination the user removed: the objects stay on
    /// that storage (re-add + rebuild brings them back), but Malo no longer tracks them.
    released: HashSet<String>,
    /// The index (with its audit log of purges) was lost at least once.
    lost_index: bool,
    /// Name of the user's folder in the shared mount, derived from their archive key (known
    /// once they were unlocked).
    owner_dir: Option<String>,
}

#[derive(Clone)]
struct Truth {
    raw: Vec<u8>,
    externally_deleted: bool,
}

struct MailModel {
    imap_user: String,
    /// token → original bytes
    messages: BTreeMap<String, Truth>,
}

struct World {
    dir: tempfile::TempDir,
    /// Purges seen in the users' audit logs so far (an audit log goes with a lost index).
    purge_log: HashMap<String, Vec<usize>>,
    /// Indexes deleted by `LoseIndex` (and the backups since then had to cope).
    indexes_lost: u32,
    mount: PathBuf,
    s3_prefix: String,
    server: Option<malo_server::Running>,
    api: Api,
    admin: Option<Api>,
    users: Vec<UserModel>,
    mail: Vec<MailModel>,
    /// user id → files (path, len, mtime) of a deleted user, which must never change again.
    deleted_snapshots: HashMap<String, Vec<(PathBuf, u64, std::time::SystemTime)>>,
    trace: Vec<String>,
    outage_until: Option<Instant>,
    /// Last time the outside world was deliberately broken (storage outage, IMAP kick, faults).
    last_fault: Option<Instant>,
    /// The fuzzer deleted or corrupted objects on shared storage behind Malo's back.
    shared_damage: bool,
    msg_counter: u64,
    /// Until when 500s are acceptable (local-disk faults: index, config, spool, cache).
    disk_faults_until: Option<Instant>,
    /// Local-folder destinations currently made read-only.
    read_only: Vec<PathBuf>,
    /// Next to the data directory and the mount: every traversal attempt aims here, and nothing
    /// may ever appear in it.
    canary: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Violation {
    kind: String,
    detail: String,
    step: usize,
}

type Check = Result<(), Violation>;

fn violation(kind: &str, detail: impl Into<String>) -> Violation {
    Violation {
        kind: kind.into(),
        detail: detail.into(),
        step: 0,
    }
}

// ───────────────────────────── helpers ─────────────────────────────

async fn start(dir: &Path, mount: &Path) -> malo_server::Running {
    let mount = mount.to_path_buf();
    start_server(dir, move |c| {
        c.allowed_fs_mounts = vec![mount];
        c.auto_lock_seconds = Some(AUTO_LOCK_SECS);
        c.workers = 3;
    })
    .await
}

/// `docker compose` against the repository's compose file (works whatever the project is called).
fn compose(args: &[&str]) {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker-compose.yml");
    let _ = std::process::Command::new("docker")
        .args(["compose", "-f", file.to_str().unwrap(), "--profile", "test"])
        .args(args)
        .output();
}

/// Tokens of the messages in one folder.
async fn folder_tokens(c: &mut malo_core::imap::ImapConn, folder: &str) -> Vec<String> {
    let mut out = vec![];
    if c.select(folder).await.is_ok() {
        for uid in c.all_uids().await.unwrap_or_default() {
            if let Ok(Some((raw, _))) = c.fetch_raw(uid).await {
                out.push(token_of(&raw));
            }
        }
    }
    out
}

/// The model's key of a message: the first word of its subject.
fn token_of(raw: &[u8]) -> String {
    malo_core::viewer::envelope_of(raw)
        .subject
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

fn walk(p: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
        let path = e.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn snapshot(p: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let mut files = vec![];
    walk(p, &mut files);
    let mut v: Vec<_> = files
        .into_iter()
        .filter_map(|f| {
            let m = std::fs::metadata(&f).ok()?;
            Some((f, m.len(), m.modified().ok()?))
        })
        .collect();
    v.sort();
    v
}

const TOXI_API: &str = "http://127.0.0.1:8474";

/// Parallel fuzz processes (`MALO_FUZZ_SHARD=0..16`) each get their own S3 proxy.
fn shard() -> u16 {
    env_u64("MALO_FUZZ_SHARD", 0).min(15) as u16
}

fn toxi_name() -> String {
    match shard() {
        0 => "rustfs".into(),
        n => format!("rustfs{n}"),
    }
}

fn toxi_s3() -> String {
    format!("http://127.0.0.1:{}", 19001 + shard())
}

/// Makes sure this shard's S3 proxy exists and carries no faults.
async fn toxi_reset() {
    let http = reqwest::Client::new();
    let name = toxi_name();
    let _ = http
        .post(format!("{TOXI_API}/proxies"))
        .json(&serde_json::json!({"name": name, "listen": format!("0.0.0.0:{}", 19001 + shard()), "upstream": "rustfs:9000"}))
        .send()
        .await;
    let _ = http
        .delete(format!("{TOXI_API}/proxies/{name}/toxics/fuzz"))
        .send()
        .await;
    let _ = http
        .post(format!("{TOXI_API}/proxies/{name}"))
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await;
}

/// Breaks the Malo ↔ S3 connection for `ms`.
async fn toxic(kind: NetKind, ms: u64) {
    let (ty, stream, attrs) = match kind {
        NetKind::Reset => (
            "reset_peer",
            "downstream",
            serde_json::json!({"timeout": 0}),
        ),
        NetKind::Timeout => (
            "timeout",
            "downstream",
            serde_json::json!({"timeout": 1500}),
        ),
        NetKind::Latency => (
            "latency",
            "downstream",
            serde_json::json!({"latency": 1200, "jitter": 600}),
        ),
        // Uploads die after 20 kB: half-written objects.
        NetKind::CutUpload => (
            "limit_data",
            "upstream",
            serde_json::json!({"bytes": 20000}),
        ),
    };
    let http = reqwest::Client::new();
    let _ = http
        .post(format!("{TOXI_API}/proxies/{}/toxics", toxi_name()))
        .json(&serde_json::json!({"name": "fuzz", "type": ty, "stream": stream, "toxicity": 1.0, "attributes": attrs}))
        .send()
        .await;
    tokio::time::sleep(Duration::from_millis(ms)).await;
    let _ = http
        .delete(format!("{TOXI_API}/proxies/{}/toxics/fuzz", toxi_name()))
        .send()
        .await;
}

fn set_read_only(dir: &Path, ro: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut dirs = vec![dir.to_path_buf()];
        let mut i = 0;
        while i < dirs.len() {
            let d = dirs[i].clone();
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                if e.path().is_dir() {
                    dirs.push(e.path());
                }
            }
            i += 1;
        }
        for d in dirs {
            let _ = std::fs::set_permissions(
                &d,
                std::fs::Permissions::from_mode(if ro { 0o555 } else { 0o755 }),
            );
        }
    }
}

/// Statuses that are a server bug no matter what (502 is the documented "no readable copy").
fn is_server_error(status: u16) -> bool {
    status >= 500 && status != 502
}

impl World {
    fn state(&self) -> &malo_server::state::SharedState {
        &self.server.as_ref().unwrap().state
    }

    /// A call that must never produce a 5xx. Returns the status (0 = transport error) and body.
    async fn call<B: Serialize>(
        &mut self,
        api: &Api,
        m: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<(u16, serde_json::Value), Violation> {
        match api
            .call::<B, serde_json::Value>(m.clone(), path, body)
            .await
        {
            Ok(v) => Ok((200, v)),
            Err((500, text)) if self.disk_faults_tolerated() => {
                Ok((500, serde_json::Value::String(text)))
            }
            Err((status, text)) if is_server_error(status) => Err(violation(
                "server_error",
                format!("{m} {path} → {status}: {text}"),
            )),
            Err((status, text)) => Ok((status, serde_json::Value::String(text))),
        }
    }

    /// A failing disk legitimately turns requests into 500s — but never into a crash.
    fn disk_faults_tolerated(&mut self) -> bool {
        if local_faults_recent() {
            self.disk_faults_until = Some(Instant::now() + Duration::from_secs(3));
        }
        self.disk_faults_until.is_some_and(|t| Instant::now() < t)
    }

    async fn admin(&mut self) -> Api {
        if let Some(a) = &self.admin {
            if a.status_of(Method::GET, "/me").await == 200 {
                return a.clone();
            }
        }
        let a = self.api.login("admin", "admin-password-1").await;
        self.admin = Some(a.clone());
        a
    }

    fn session(&self, u: usize) -> Option<Api> {
        self.users[u].session.as_ref().map(|(a, _)| a.clone())
    }

    /// Users come back: an action by a logged-out (but existing, enabled) user logs in first.
    async fn ensure_session(&mut self, u: usize) -> Result<Option<Api>, Violation> {
        let um = &self.users[u];
        if um.session.is_none() && um.id.is_some() && !um.deleted && !um.disabled {
            self.login(u).await?;
        }
        Ok(self.session(u))
    }

    /// Remembers the user's shared-mount folder while their keys are in memory: after a deletion
    /// it can't be derived any more.
    fn note_owner_dir(&mut self, u: usize) {
        if self.users[u].owner_dir.is_some() {
            return;
        }
        let Some(id) = self.users[u].id.clone() else {
            return;
        };
        if let Some(k) = self.state().keyring.get(&id) {
            self.users[u].owner_dir =
                Some(malo_core::layout::NameKey::new(&k.secrets.archive_key).owner_dir());
        }
    }

    /// Marks a user's session(s) as dead and records when their keys were sealed.
    fn seal(&mut self, u: usize) {
        if let Some((api, _)) = self.users[u].session.take() {
            self.users[u].stale.push(api);
        }
        if let Some((api, _)) = self.users[u].device_b.take() {
            self.users[u].stale.push(api);
        }
        self.users[u].events = None;
        self.users[u].events_b = None;
        self.users[u].sealed_at.get_or_insert_with(chrono::Utc::now);
    }

    /// One device's session reached its auto-lock time. The keys stay as long as another device's
    /// (later) login keeps them; only when no device is left is the user sealed.
    fn expire_device(&mut self, u: usize, device_b: bool) {
        let um = &mut self.users[u];
        let gone = if device_b {
            um.device_b.take()
        } else {
            um.session.take()
        };
        if let Some((api, _)) = gone {
            um.stale.push(api);
        }
        if device_b {
            um.events_b = None;
        } else {
            um.events = None;
        }
        if um.session.is_none() && um.device_b.is_none() {
            um.sealed_at.get_or_insert_with(chrono::Utc::now);
        }
    }

    async fn subscribe(&mut self, u: usize) {
        if let Some(api) = self.session(u) {
            // The WebSocket may be refused while the server restarts; that's fine.
            let events = tokio::time::timeout(Duration::from_secs(5), api.events())
                .await
                .ok();
            self.users[u].events = events;
        }
    }

    /// Input for an existing account with a new name, keeping how it connects.
    fn account_input(&self, acc: &AccModel, name: &str) -> AccountInput {
        let mut input = imap_input(
            name,
            &self.mail[acc.mailbox].imap_user,
            if acc.starttls { 10143 } else { IMAP_PORT },
        );
        if acc.starttls {
            input.tls = TlsMode::Starttls;
        }
        input.idle = acc.idle;
        input.auth = AccountAuth::Password {
            password: REDACTED.into(),
        };
        input
    }

    /// Every folder of a mail server except INBOX (raw, modified-UTF-7 names).
    async fn server_folders(&self, m: usize) -> Vec<String> {
        let mut c = imap_conn(&self.mail[m].imap_user, IMAP_PORT).await;
        let mut v: Vec<String> = c
            .list_mailboxes()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|b| b.name)
            .filter(|n| !n.eq_ignore_ascii_case("INBOX"))
            .collect();
        c.logout().await;
        v.sort();
        v
    }

    async fn new_message(
        &mut self,
        m: usize,
        to_box: bool,
        folder: Option<&str>,
        shape: Option<&MsgShape>,
    ) -> anyhow::Result<()> {
        self.msg_counter += 1;
        let token = format!(
            "fz{}x{}",
            self.dir
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .replace('.', ""),
            self.msg_counter
        );
        let raw = match shape {
            Some(shape) => build_message(&token, shape),
            None => mail(
                &format!("{token} subject"),
                if self.msg_counter.is_multiple_of(4) {
                    30_000
                } else {
                    0
                },
            ),
        };
        let mut c = imap_conn(&self.mail[m].imap_user, IMAP_PORT).await;
        let target = match folder {
            Some(f) => malo_core::layout::encode_utf7(f),
            None if to_box => "Box".to_string(),
            None => "INBOX".to_string(),
        };
        if target != "INBOX" {
            let _ = c.session.create(&target).await;
        }
        let flags = shape
            .filter(|s| !s.flags.is_empty())
            .map(|s| format!("({})", s.flags.join(" ")));
        let date = shape.map_or("01-Jan-2020 10:00:00 +0000".to_string(), |s| s.date.clone());
        // A folder name the server refuses is no message (another client simply could not do it).
        let stored = c
            .session
            .append(
                &target,
                flags.as_deref(),
                Some(&format!("\"{date}\"")),
                &raw,
            )
            .await
            .is_ok();
        c.logout().await;
        if !stored {
            return Ok(());
        }
        self.mail[m].messages.insert(
            token,
            Truth {
                raw,
                externally_deleted: false,
            },
        );
        Ok(())
    }

    /// Waits until a user has no queued/running job (lifecycle: nothing keeps running after a lock).
    async fn wait_jobs_quiet(&self, user_id: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let busy = self.state().jobs.running_for(user_id) > 0
                || self
                    .state()
                    .db
                    .active_jobs(user_id)
                    .map(|j| !j.is_empty())
                    .unwrap_or(false);
            if !busy {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn job(&mut self, u: usize, kind: JobKind, wait: bool) -> Check {
        let Some(api) = self.ensure_session(u).await? else {
            return Ok(());
        };
        let (status, v) = self
            .call(
                &api,
                Method::POST,
                "/jobs",
                Some(&CreateJobRequest { kind }),
            )
            .await?;
        if status != 200 {
            return Ok(());
        }
        let job: JobInfo =
            serde_json::from_value(v).map_err(|e| violation("bad_response", e.to_string()))?;
        self.users[u].jobs.push(job.id.clone());
        if wait {
            let injected_before = faults::injected();
            let started = Instant::now();
            let deadline = Instant::now() + Duration::from_secs(90);
            loop {
                let (st, v) = self
                    .call(&api, Method::GET, &format!("/jobs/{}", job.id), None::<&()>)
                    .await?;
                if st != 200 {
                    break; // session ended (auto-lock): fine
                }
                let j: JobInfo = serde_json::from_value(v).unwrap();
                if j.state.is_finished() {
                    // Maintenance jobs must not fail because of someone else's data. Faults the
                    // fuzzer injected, locks and cancels explain a failure; anything else doesn't.
                    let maintenance = matches!(
                        j.kind,
                        JobKind::Check { .. }
                            | JobKind::Repair { .. }
                            | JobKind::RebuildIndex { .. }
                            | JobKind::PurgeDryRun { .. }
                    );
                    let explained = faults::injected() != injected_before
                        || self.disk_faults_tolerated()
                        || self
                            .last_fault
                            .is_some_and(|t| t >= started - Duration::from_secs(5))
                        || j.error.as_deref().is_some_and(|e| {
                            e.contains("locked") || e.contains("cancel") || e.contains("unknown")
                        });
                    if maintenance && j.state == JobState::Failed && !explained {
                        return Err(violation(
                            "job_failed",
                            format!("{:?} failed: {}", j.kind, j.error.unwrap_or_default()),
                        ));
                    }
                    break;
                }
                if Instant::now() > deadline {
                    return Err(violation(
                        "job_hang",
                        format!("job {} ({:?}) still {:?} after 90 s", j.id, j.kind, j.state),
                    ));
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
        Ok(())
    }

    /// Submits a job, waits for it and returns how it ended. A session that auto-locks meanwhile
    /// cancels the job: log in again and resubmit it.
    async fn job_info(&mut self, u: usize, kind: JobKind) -> Result<Option<JobInfo>, Violation> {
        for _ in 0..3 {
            match self.job_info_once(u, kind.clone()).await? {
                Some(Ok(j)) => return Ok(Some(j)),
                // The server rejected the session: it auto-locked.
                Some(Err(true)) => self.expire_device(u, false),
                // Locked through another device or the server; this session still works.
                Some(Err(false)) => {}
                None => return Ok(None),
            }
        }
        Ok(None)
    }

    /// One attempt: `Some(Err(session_ended))` when a lock cancelled the job before it finished.
    async fn job_info_once(
        &mut self,
        u: usize,
        kind: JobKind,
    ) -> Result<Option<Result<JobInfo, bool>>, Violation> {
        let Some(api) = self.ensure_session(u).await? else {
            return Ok(None);
        };
        let (st, v) = self
            .call(
                &api,
                Method::POST,
                "/jobs",
                Some(&CreateJobRequest { kind }),
            )
            .await?;
        if st == 401 || st == 423 {
            return Ok(Some(Err(true)));
        }
        if st != 200 {
            return Ok(None);
        }
        let job: JobInfo = serde_json::from_value(v).unwrap();
        self.users[u].jobs.push(job.id.clone());
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut last = None;
        loop {
            let (st, v) = self
                .call(&api, Method::GET, &format!("/jobs/{}", job.id), None::<&()>)
                .await?;
            if st == 200 {
                let j: JobInfo = serde_json::from_value(v).unwrap();
                if j.state == JobState::Cancelled
                    && j.error
                        .as_deref()
                        .is_some_and(|e| e.contains("user was locked"))
                {
                    return Ok(Some(Err(false)));
                }
                if j.state.is_finished() {
                    return Ok(Some(Ok(j)));
                }
                last = Some(j);
            } else if st == 401 || st == 423 {
                return Ok(Some(Err(true)));
            }
            if Instant::now() > deadline {
                let (_, all) = self
                    .call(&api, Method::GET, "/jobs?limit=50", None::<&()>)
                    .await?;
                let others: Vec<String> = serde_json::from_value::<Vec<JobInfo>>(all)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|o| !o.state.is_finished())
                    .map(|o| format!("{} {:?} {:?} {:?}", o.id, o.kind, o.state, o.progress))
                    .collect();
                self.trace.push(format!(
                    "  diag: hung job {:?}; unfinished jobs {others:?}; jobs active server-wide {}; free IMAP slots {:?}",
                    last.map(|j| (j.kind, j.state, j.progress, j.started_at)),
                    self.state().jobs.active(),
                    ["localhost", "127.0.0.1"].map(malo_core::imap::host_slots_free),
                ));
                return Err(violation(
                    "job_hang",
                    format!("job {} never finished", job.id),
                ));
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    /// After all faults are gone, Malo must heal on its own: every message of every live account
    /// verified on every destination, and a deep check of everything clean.
    /// Which tokens each surviving user's audit log says Malo purged from the server.
    async fn purged_by(&mut self) -> Result<HashMap<String, Vec<usize>>, Violation> {
        let mut purged_by: HashMap<String, Vec<usize>> = HashMap::new();
        for u in 0..USERS {
            let Some(api) = self.session(u) else { continue };
            let (_, v) = self
                .call(&api, Method::GET, "/audit?limit=2000", None::<&()>)
                .await?;
            for e in serde_json::from_value::<Vec<AuditEntry>>(v).unwrap_or_default() {
                // "purge_pending" is written before the server deletion, "purged" after it.
                if e.kind == "purged" || e.kind == "purge_pending" {
                    if let Some(subject) = e.detail.get("subject").and_then(|s| s.as_str()) {
                        let token = subject.split_whitespace().next().unwrap_or("").to_string();
                        purged_by.entry(token).or_default().push(u);
                    }
                }
            }
        }
        for (token, users) in purged_by {
            let known = self.purge_log.entry(token).or_default();
            for u in users {
                if !known.contains(&u) {
                    known.push(u);
                }
            }
        }
        Ok(self.purge_log.clone())
    }

    /// Tokens of messages whose only verified copy (among the user's destinations) is on `dest`.
    fn only_copies_on(&mut self, u: usize, dest: &str) -> HashSet<String> {
        let uid = self.users[u].id.clone().unwrap_or_default();
        let Some(k) = self.state().keyring.get(&uid) else {
            return HashSet::new();
        };
        let mut out = HashSet::new();
        for r in k.index.replicas_in(dest).unwrap_or_default() {
            if r.status != malo_core::index::ReplicaStatus::Verified {
                continue;
            }
            let elsewhere = k
                .index
                .replicas_of(r.message)
                .unwrap_or_default()
                .iter()
                .any(|o| {
                    o.destination != dest && o.status == malo_core::index::ReplicaStatus::Verified
                });
            if elsewhere {
                continue;
            }
            if let Ok(Some(m)) = k.index.message(r.message) {
                let token = m.envelope.subject.split_whitespace().next().unwrap_or("");
                out.insert(token.to_string());
            }
        }
        out
    }

    /// True when every damaged replica on `dest` belongs to mail nothing can bring back: the
    /// fuzzer damaged shared storage, no verified copy of the content is left anywhere, and the
    /// message is gone from the IMAP server. Malo must report such damage, not hide it.
    fn unrecoverable_damage_only(&mut self, u: usize, dest: &str) -> bool {
        if !self.shared_damage {
            return false;
        }
        let uid = self.users[u].id.clone().unwrap_or_default();
        let Some(k) = self.state().keyring.get(&uid) else {
            return false;
        };
        let damaged: Vec<_> = k
            .index
            .replicas_in(dest)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| {
                matches!(
                    r.status,
                    malo_core::index::ReplicaStatus::Missing
                        | malo_core::index::ReplicaStatus::Corrupt
                )
            })
            .collect();
        let imported: HashSet<String> = k
            .config()
            .accounts
            .iter()
            .filter(|a| a.imported)
            .map(|a| a.id.clone())
            .collect();
        let lost = damaged.iter().all(|r| {
            // Imported archives have no server: their mail is "gone" from IMAP by definition
            // (live accounts were backed up just before; a copy there would have been found).
            let in_import = k
                .index
                .message(r.message)
                .ok()
                .flatten()
                .is_some_and(|m| imported.contains(&m.account));
            let gone_from_server = in_import
                || k.index
                    .memberships(r.message)
                    .unwrap_or_default()
                    .iter()
                    .all(|m| m.deleted_on_server);
            let mut copies = vec![r.message];
            if let Some(sha) = &r.sha256 {
                copies.extend(k.index.messages_with_sha(sha).unwrap_or_default());
            }
            let verified_somewhere = copies.iter().any(|id| {
                k.index
                    .replicas_of(*id)
                    .unwrap_or_default()
                    .iter()
                    .any(|x| x.status == malo_core::index::ReplicaStatus::Verified)
            });
            gone_from_server && !verified_somewhere
        });
        if lost && !damaged.is_empty() {
            self.trace.push(format!(
                "  note: {} replica(s) on {dest} unrecoverable (only copy damaged by the fuzzer, mail deleted on the server)",
                damaged.len()
            ));
        }
        lost && !damaged.is_empty()
    }

    async fn converge(&mut self, u: usize) -> Check {
        for acc in self.users[u].accounts.clone() {
            // One retry, as an operator would; a backup that keeps failing without faults is a bug.
            let mut last = None;
            for _ in 0..2 {
                last = self
                    .job_info(
                        u,
                        JobKind::Backup {
                            account_id: acc.id.clone(),
                        },
                    )
                    .await?;
                let clean = last.as_ref().is_some_and(|j| {
                    j.state == JobState::Done
                        && j.result
                            .as_ref()
                            .and_then(|r| r.get("errors"))
                            .and_then(|e| e.as_array())
                            .is_none_or(|e| e.is_empty())
                });
                if clean {
                    break;
                }
            }
            if let Some(j) = &last {
                self.trace.push(format!(
                    "  converge backup {}: {:?} {:?} {}",
                    acc.name,
                    j.state,
                    j.error,
                    j.result.as_ref().map(|r| r.to_string()).unwrap_or_default()
                ));
                // Correct refusal when the user really has nowhere to back up to.
                let no_destinations = self.users[u].destinations.is_empty()
                    && j.error.as_deref() == Some("no destinations configured");
                if j.state != JobState::Done && !no_destinations {
                    return Err(violation(
                        "not_converged",
                        format!(
                            "user {u}: backup of {} keeps failing without faults: {:?}",
                            acc.name, j.error
                        ),
                    ));
                }
            }
        }
        // No false "verified": with faults gone and before any repair, every replica Malo marked
        // verified on the primary destination (never damaged at rest by the fuzzer) is intact.
        let primary = self.users[u]
            .destinations
            .iter()
            .find(|d| d.primary)
            .map(|d| d.id.clone());
        if let Some(primary) = primary {
            let scope = CheckScope::Destination {
                destination_id: primary.clone(),
            };
            if let Some(j) = self
                .job_info(u, JobKind::Check { scope, deep: true })
                .await?
            {
                if let Some(r) = j
                    .result
                    .and_then(|r| serde_json::from_value::<CheckReport>(r).ok())
                {
                    if let Some(h) = r.destinations.iter().find(|h| h.destination_id == primary) {
                        if h.missing + h.corrupt > 0 {
                            return Err(violation(
                                "false_verified",
                                format!("user {u}: {} missing and {} corrupt objects on the primary destination were recorded as verified", h.missing, h.corrupt),
                            ));
                        }
                    }
                }
            }
        }
        // Rotating deep checks re-hash a different slice each time, so damage can surface one
        // check later: repair and check up to three rounds, as an operator would.
        for _ in 0..2 {
            self.job_info(
                u,
                JobKind::Repair {
                    scope: CheckScope::All,
                },
            )
            .await?;
            let healthy = self
                .job_info(
                    u,
                    JobKind::Check {
                        scope: CheckScope::All,
                        deep: true,
                    },
                )
                .await?
                .and_then(|j| j.result)
                .and_then(|r| serde_json::from_value::<CheckReport>(r).ok())
                .is_some_and(|r| r.destinations.iter().all(|d| d.ok));
            if healthy {
                break;
            }
        }
        let repair = self
            .job_info(
                u,
                JobKind::Repair {
                    scope: CheckScope::All,
                },
            )
            .await?;
        self.trace.push(format!(
            "  converge repair: {:?} {:?} {}",
            repair.as_ref().map(|j| j.state),
            repair.as_ref().and_then(|j| j.error.clone()),
            repair
                .as_ref()
                .and_then(|j| j.result.as_ref())
                .map(|r| r.to_string())
                .unwrap_or_default()
        ));
        if let Some(j) = self
            .job_info(
                u,
                JobKind::Check {
                    scope: CheckScope::All,
                    deep: true,
                },
            )
            .await?
        {
            let report: Option<CheckReport> = j.result.and_then(|r| serde_json::from_value(r).ok());
            if let Some(r) = report {
                if let Some(d) = r
                    .destinations
                    .iter()
                    .find(|d| !d.ok && !self.unrecoverable_damage_only(u, &d.destination_id))
                {
                    self.trace
                        .push(format!("  diag: check after repair: {:?}", r.destinations));
                    let uid = self.users[u].id.clone().unwrap_or_default();
                    if let Some(k) = self.state().keyring.get(&uid) {
                        for rep in k.index.replicas_in(&d.destination_id).unwrap_or_default() {
                            if rep.status == malo_core::index::ReplicaStatus::Verified {
                                continue;
                            }
                            let msg = k.index.message(rep.message).ok().flatten();
                            self.trace.push(format!(
                                "  diag: damaged msg {} account {:?} sha {:?} path {} status {:?}; all replicas {:?}",
                                rep.message,
                                msg.as_ref().map(|m| m.account.clone()),
                                rep.sha256,
                                rep.object_path,
                                rep.status,
                                k.index
                                    .replicas_of(rep.message)
                                    .unwrap_or_default()
                                    .iter()
                                    .map(|x| (x.destination.clone(), format!("{:?}", x.status), x.object_path.clone()))
                                    .collect::<Vec<_>>()
                            ));
                        }
                        self.trace.push(format!(
                            "  diag: accounts {:?}; destinations {:?}",
                            k.config()
                                .accounts
                                .iter()
                                .map(|a| (a.id.clone(), a.name.clone(), a.enabled, a.imported))
                                .collect::<Vec<_>>(),
                            k.config()
                                .destinations
                                .iter()
                                .map(|d| (d.id.clone(), d.name.clone()))
                                .collect::<Vec<_>>()
                        ));
                    }
                    return Err(violation(
                        "not_converged",
                        format!("user {u}: destination {} still unhealthy after repair: {} missing, {} corrupt, error {:?}", d.name, d.missing, d.corrupt, d.error),
                    ));
                }
            } else if j.state != JobState::Done {
                return Err(violation(
                    "not_converged",
                    format!("user {u}: final deep check {:?}: {:?}", j.state, j.error),
                ));
            }
        }
        let Some(api) = self.session(u) else {
            return Ok(());
        };
        let purged = self.purged_by().await?;
        for acc in self.users[u].accounts.clone() {
            let (st, v) = self
                .call(
                    &api,
                    Method::GET,
                    &format!("/messages?account={}&limit=1000", acc.id),
                    None::<&()>,
                )
                .await?;
            if st != 200 {
                continue;
            }
            let list: MessageList = serde_json::from_value(v).unwrap();
            self.trace.push(format!(
                "  converge user {u} account {}: {} messages",
                acc.name, list.total
            ));
            for m in list.messages {
                // Never stored anywhere, then deleted by another client: nothing could save it.
                let token = m
                    .envelope
                    .subject
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let deleted_elsewhere = m.deleted_on_server
                    && m.stored == 0
                    && self.mail[acc.mailbox]
                        .messages
                        .get(&token)
                        .is_some_and(|t| t.externally_deleted);
                // Purged from the server by another account on the same mailbox (that one holds
                // the verified copies; the mail-loss check proves it can give them back), or by a
                // user deleted since: this account never got to store it.
                let purged_elsewhere = m.deleted_on_server
                    && m.stored == 0
                    && (purged.contains_key(&token)
                        || self.users.iter().any(|x| {
                            (x.deleted || x.lost_index) && x.ever_mailboxes.contains(&acc.mailbox)
                        }));
                let gone_before_download =
                    m.error.as_deref().is_some_and(|e| e.contains("vanished"))
                        || deleted_elsewhere
                        || purged_elsewhere;
                if m.state != MessageState::Verified && !gone_before_download {
                    let uid = self.users[u].id.clone().unwrap_or_default();
                    let row = self
                        .state()
                        .keyring
                        .get(&uid)
                        .and_then(|k| k.index.message(m.id).ok().flatten());
                    let last_backup = self
                        .state()
                        .db
                        .jobs(&uid, 50)
                        .unwrap_or_default()
                        .into_iter()
                        .find(|j| matches!(&j.kind, JobKind::Backup { account_id } if *account_id == acc.id));
                    if let Some(k) = self.state().keyring.get(&uid) {
                        for ms in k.index.memberships(m.id).unwrap_or_default() {
                            let mb = k.index.mailbox(ms.mailbox).ok().flatten();
                            self.trace.push(format!(
                                "  diag: membership mailbox={} uid={} deleted={} | {:?}",
                                ms.mailbox,
                                ms.uid,
                                ms.deleted_on_server,
                                mb.map(|b| (b.name, b.uidvalidity, b.current, b.highest_uid))
                            ));
                        }
                        let row = k.index.message(m.id).ok().flatten();
                        self.trace.push(format!(
                            "  diag: sha={:?} replicas={:?}",
                            row.and_then(|r| r.sha256),
                            k.index
                                .replicas_of(m.id)
                                .unwrap_or_default()
                                .iter()
                                .map(|r| (r.destination.clone(), format!("{:?}", r.status)))
                                .collect::<Vec<_>>()
                        ));
                    }
                    self.trace.push(format!(
                        "  diag: row attempts={:?} state={:?}; last backup {:?} {:?} {:?}",
                        row.as_ref().map(|r| r.attempts),
                        row.as_ref().map(|r| r.state),
                        last_backup.as_ref().map(|j| j.state),
                        last_backup.as_ref().and_then(|j| j.error.clone()),
                        last_backup.as_ref().and_then(|j| j.result.clone()),
                    ));
                    return Err(violation(
                        "not_converged",
                        format!(
                            "user {u}: message {} ({}) stuck as {:?} ({}/{} copies): {:?}",
                            m.id, m.envelope.subject, m.state, m.stored, m.destinations, m.error
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn primary_and_others(&self, u: usize) -> Vec<String> {
        self.users[u]
            .destinations
            .iter()
            .map(|d| d.id.clone())
            .collect()
    }

    async fn restart(&mut self) -> Check {
        self.restart_losing_index(None).await
    }

    /// Restart; with a user id, that user's index is deleted while the server is down.
    async fn restart_losing_index(&mut self, lose: Option<&str>) -> Check {
        let old = self.server.take().unwrap();
        old.shutdown(Duration::from_secs(30)).await;
        for u in 0..USERS {
            self.seal(u);
        }
        if let Some(id) = lose {
            let dir = self.dir.path().join("users").join(id);
            for f in ["index.db", "index.db-wal", "index.db-shm"] {
                let _ = std::fs::remove_file(dir.join(f));
            }
            self.trace.push(format!("  index of {id} deleted"));
            self.indexes_lost += 1;
        }
        // The admin's session ended with the restart as well.
        self.admin = None;
        let server = start(self.dir.path(), &self.mount).await;
        self.api = Api::new(&server);
        // Every pinned client keeps working against the same certificate.
        self.server = Some(server);
        if self.state().keyring.count() != 0 {
            return Err(violation(
                "restart_unsealed",
                "users unlocked right after a restart",
            ));
        }
        Ok(())
    }
}

// ───────────────────────────── executor ─────────────────────────────

impl World {
    async fn exec(&mut self, op: &Op) -> Check {
        match op {
            Op::Burst { ops } => {
                // Run concurrently: each op gets its own world view of the API, so execute the
                // HTTP-level part in parallel and fold model updates in afterwards.
                let mut futures = Vec::new();
                for o in ops {
                    if matches!(o, Op::Restart | Op::LoseIndex { .. } | Op::Burst { .. }) {
                        continue;
                    }
                    futures.push(self.plan_concurrent(o.clone()));
                }
                let plans: Vec<_> = futures::future::join_all(futures).await;
                for p in plans {
                    p?;
                }
                Ok(())
            }
            // Boxed: the step future is large, and debug builds keep unboxed futures on the stack.
            other => Box::pin(self.exec_one(other)).await,
        }
    }

    /// Fire-and-forget form of an op for bursts: issues the request(s) without touching the model
    /// except for job ids, so overlapping requests really overlap.
    fn plan_concurrent(&self, op: Op) -> futures::future::BoxFuture<'static, Check> {
        let sessions: Vec<Option<Api>> = (0..USERS).map(|u| self.session(u)).collect();
        let accounts: Vec<Vec<String>> = self
            .users
            .iter()
            .map(|u| u.accounts.iter().map(|a| a.id.clone()).collect())
            .collect();
        Box::pin(async move {
            let req = |api: Api, m: Method, path: String, body: Option<serde_json::Value>| async move {
                match api
                    .call::<serde_json::Value, serde_json::Value>(m.clone(), &path, body.as_ref())
                    .await
                {
                    // A failing local disk legitimately turns requests into 500s.
                    Err((500, _)) if local_faults_recent() => Ok(()),
                    Err((s, t)) if is_server_error(s) => {
                        Err(violation("server_error", format!("{m} {path} → {s}: {t}")))
                    }
                    _ => Ok(()),
                }
            };
            match op {
                Op::Backup { u, slot, .. } => {
                    if let (Some(api), Some(acc)) = (
                        sessions[u].clone(),
                        accounts[u].get(slot % accounts[u].len().max(1)).cloned(),
                    ) {
                        req(
                            api,
                            Method::POST,
                            "/jobs".into(),
                            Some(
                                serde_json::json!({"kind": {"type": "backup", "account_id": acc}}),
                            ),
                        )
                        .await?;
                    }
                }
                Op::Check { u, deep, .. } => {
                    if let Some(api) = sessions[u].clone() {
                        req(api, Method::POST, "/jobs".into(), Some(serde_json::json!({"kind": {"type": "check", "scope": {"scope": "all"}, "deep": deep}}))).await?;
                    }
                }
                Op::Probe { u, .. } | Op::Login { u } | Op::RenameAccount { u, .. } => {
                    if let Some(api) = sessions[u].clone() {
                        req(api.clone(), Method::GET, "/accounts".into(), None).await?;
                        req(api, Method::GET, "/messages?limit=50".into(), None).await?;
                    }
                }
                Op::Lock { u } | Op::Logout { u } => {
                    // Lock races with everything else in the burst; the model learns about it on
                    // the next check through 401s, so only issue a harmless read here.
                    if let Some(api) = sessions[u].clone() {
                        req(api, Method::GET, "/me".into(), None).await?;
                    }
                }
                _ => {}
            }
            Ok(())
        })
    }

    async fn login(&mut self, u: usize) -> Check {
        let um = &self.users[u];
        if um.id.is_none() || um.deleted {
            return Ok(());
        }
        let anon = Api {
            token: None,
            ..self.api.clone()
        };
        let req = LoginRequest {
            username: um.name.clone(),
            password: um.password.clone(),
        };
        let disabled = um.disabled;
        match anon
            .call::<_, LoginResponse>(Method::POST, "/auth/login", Some(&req))
            .await
        {
            Ok(r) => {
                if disabled {
                    return Err(violation("disabled_login", "a disabled user could log in"));
                }
                let api = Api {
                    token: Some(r.token),
                    ..self.api.clone()
                };
                if let Some((old, _)) = self.users[u].session.replace((api, Instant::now())) {
                    // Re-login keeps older sessions valid, so the old one isn't stale.
                    drop(old);
                }
                self.users[u].sealed_at = None;
                self.note_owner_dir(u);
                self.subscribe(u).await;
            }
            Err((s, t)) if is_server_error(s) => {
                return Err(violation("server_error", format!("login → {s}: {t}")))
            }
            Err((s, t)) => {
                if !disabled && s != 429 {
                    return Err(violation(
                        "login_refused",
                        format!("correct password refused: {s} {t}"),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn exec_one(&mut self, op: &Op) -> Check {
        match *op {
            Op::Register { u } => {
                if self.users[u].id.is_some() || self.users[u].deleted {
                    return Ok(());
                }
                let admin = self.admin().await;
                let name = self.users[u].name.clone();
                let invite: Invite = admin
                    .post(
                        "/admin/invites",
                        &CreateInviteRequest {
                            username: Some(name.clone()),
                            role: Role::User,
                            valid_hours: 1,
                        },
                    )
                    .await;
                let anon = Api {
                    token: None,
                    ..self.api.clone()
                };
                let pw = self.users[u].password.clone();
                let (st, _) = self
                    .call(
                        &anon,
                        Method::POST,
                        "/auth/register",
                        Some(&RegisterRequest {
                            username: name,
                            password: pw,
                            invite_code: Some(invite.code),
                            recovery_kit: None,
                            kit_passphrase: None,
                        }),
                    )
                    .await?;
                if st != 200 {
                    if st == 500 && self.disk_faults_tolerated() {
                        // A failing disk may refuse a registration — but must leave nothing behind.
                        let name = self.users[u].name.clone();
                        if self.state().db.user_by_name(&name).ok().flatten().is_some() {
                            return Err(violation(
                                "half_registered",
                                "registration failed but the user exists",
                            ));
                        }
                        let known: HashSet<String> = self
                            .state()
                            .db
                            .users()
                            .unwrap_or_default()
                            .into_iter()
                            .map(|u| u.id)
                            .collect();
                        for e in std::fs::read_dir(self.dir.path().join("users"))
                            .into_iter()
                            .flatten()
                            .flatten()
                        {
                            let n = e.file_name().to_string_lossy().to_string();
                            if !known.contains(&n) {
                                return Err(violation(
                                    "half_registered",
                                    format!("failed registration left folder users/{n}"),
                                ));
                            }
                        }
                        return Ok(());
                    }
                    return Err(violation("register_failed", format!("status {st}")));
                }
                let name = self.users[u].name.clone();
                self.users[u].id = self
                    .state()
                    .db
                    .user_by_name(&name)
                    .ok()
                    .flatten()
                    .map(|r| r.id);
                self.login(u).await?;
                // Every user has an own, never-faulted primary destination (safety baseline).
                if let Some(api) = self.session(u) {
                    let (st, v) = self
                        .call(
                            &api,
                            Method::POST,
                            "/destinations",
                            Some(&fs_dest("primary", "primary")),
                        )
                        .await?;
                    if st == 200 {
                        let d: DestinationView = serde_json::from_value(v).unwrap();
                        self.users[u].ever_destinations.insert(d.id.clone());
                        self.users[u].destinations.push(DestModel {
                            id: d.id,
                            primary: true,
                        });
                    }
                }
            }
            Op::Login { u } => self.login(u).await?,
            Op::Logout { u } => {
                if let Some(api) = self.session(u) {
                    self.call(&api, Method::POST, "/auth/logout", None::<&()>)
                        .await?;
                    let (a, _) = self.users[u].session.take().unwrap();
                    self.users[u].stale.push(a);
                    self.users[u].events = None;
                    // Logging out on one device leaves the other one alone.
                    if let Some((b, t)) = self.users[u].device_b.clone() {
                        let st = b.status_of(Method::GET, "/me").await;
                        if st != 200 && (t.elapsed().as_secs() as i64) + 2 < AUTO_LOCK_SECS {
                            return Err(violation(
                                "logout_hit_other_device",
                                format!("device B got {st} after device A logged out"),
                            ));
                        }
                    }
                }
            }
            Op::Lock { u } => {
                if let Some(api) = self.session(u) {
                    self.call(&api, Method::POST, "/auth/lock", None::<&()>)
                        .await?;
                    let other = self.users[u]
                        .events_b
                        .clone()
                        .filter(|_| self.users[u].device_b.is_some());
                    self.seal(u);
                    // The other device is told it was locked.
                    if let Some(ev) = other {
                        let seen = wait_until(
                            move || {
                                let ev = ev.clone();
                                Box::pin(async move {
                                    ev.lock()
                                        .unwrap()
                                        .iter()
                                        .any(|e| matches!(e, SyncEvent::Locked { .. }))
                                })
                            },
                            5,
                        )
                        .await;
                        if !seen {
                            return Err(violation(
                                "lock_not_announced",
                                "device B never received the Locked notice",
                            ));
                        }
                    }
                    let id = self.users[u].id.clone().unwrap();
                    if self.state().keyring.get(&id).is_some() {
                        return Err(violation(
                            "lock_kept_keys",
                            "keys still in memory after Lock now",
                        ));
                    }
                    if !self.wait_jobs_quiet(&id, 30).await {
                        return Err(violation(
                            "jobs_after_lock",
                            "jobs still running 30 s after Lock now",
                        ));
                    }
                }
            }
            Op::ChangePassword { u } => {
                if let Some(api) = self.session(u) {
                    let new = format!("{}-{}", self.users[u].name, rand::random::<u16>());
                    let body = ChangePasswordRequest {
                        old_password: self.users[u].password.clone(),
                        new_password: new.clone(),
                    };
                    let (st, _) = self
                        .call(&api, Method::POST, "/auth/password", Some(&body))
                        .await?;
                    if st == 200 {
                        self.users[u].password = new;
                        // Other devices must log in again with the new password; this one stays.
                        if let Some((b, _)) = self.users[u].device_b.take() {
                            self.users[u].stale.push(b);
                            self.users[u].events_b = None;
                        }
                        if api.status_of(Method::GET, "/me").await != 200 {
                            return Err(violation(
                                "password_change_logged_out_self",
                                "the device that changed the password lost its session",
                            ));
                        }
                    }
                }
            }
            Op::DeleteSelf { u } => {
                if let Some(api) = self.session(u) {
                    let name = self.users[u].name.clone();
                    let body = DeleteAccountRequest {
                        password: self.users[u].password.clone(),
                        confirm: format!("delete {name}"),
                    };
                    let (st, _) = self
                        .call(&api, Method::POST, "/me/delete", Some(&body))
                        .await?;
                    if st == 200 {
                        self.mark_deleted(u).await?;
                    }
                }
            }
            Op::AdminSetDisabled { u, disabled } => {
                let Some(id) = self.users[u].id.clone().filter(|_| !self.users[u].deleted) else {
                    return Ok(());
                };
                let admin = self.admin().await;
                let body = UpdateUserRequest {
                    disabled: Some(disabled),
                    role: None,
                    max_accounts: None,
                    max_accounts_default: None,
                };
                let (st, _) = self
                    .call(
                        &admin,
                        Method::PUT,
                        &format!("/admin/users/{id}"),
                        Some(&body),
                    )
                    .await?;
                if st == 200 {
                    self.users[u].disabled = disabled;
                    if disabled {
                        self.seal(u);
                        if self.state().keyring.get(&id).is_some() {
                            return Err(violation(
                                "disable_kept_keys",
                                "keys still in memory after disabling",
                            ));
                        }
                        if !self.wait_jobs_quiet(&id, 30).await {
                            return Err(violation(
                                "jobs_after_disable",
                                "jobs still running 30 s after disabling",
                            ));
                        }
                    }
                }
            }
            Op::AdminDelete { u } => {
                let Some(id) = self.users[u].id.clone().filter(|_| !self.users[u].deleted) else {
                    return Ok(());
                };
                let admin = self.admin().await;
                let (st, _) = self
                    .call(
                        &admin,
                        Method::DELETE,
                        &format!("/admin/users/{id}"),
                        None::<&()>,
                    )
                    .await?;
                if st == 200 {
                    self.mark_deleted(u).await?;
                }
            }
            Op::Restart => self.restart().await?,
            Op::LoseIndex { u } => {
                let id = self.users[u].id.clone().filter(|_| !self.users[u].deleted);
                if id.is_some() {
                    // Remember the purges its audit log holds (when it can still be read).
                    let _ = self.ensure_session(u).await?;
                    self.purged_by().await?;
                    self.users[u].lost_index = true;
                }
                self.restart_losing_index(id.as_deref()).await?
            }
            Op::Sleep { ms } => tokio::time::sleep(Duration::from_millis(ms)).await,
            Op::AddDestination {
                u,
                kind,
                ref name,
                ref root,
                encrypt,
                deep,
            } => {
                let Some(api) = self.ensure_session(u).await? else {
                    return Ok(());
                };
                let fill = |t: &str, w: &World| {
                    t.replace("{canary}", w.canary.to_str().unwrap())
                        .replace("{mount}", w.mount.to_str().unwrap())
                };
                let mut input = match kind {
                    DestKind::SharedMount => {
                        let mut p = self.mount.join("common");
                        if let Some(sub) = root {
                            p = p.join(sub);
                        }
                        fs_dest("shared-mount", &p.to_string_lossy())
                    }
                    DestKind::SharedS3 => {
                        let prefix = match root {
                            Some(sub) => format!("{}/{sub}", self.s3_prefix),
                            None => self.s3_prefix.clone(),
                        };
                        let mut d = s3_dest("shared-s3", S3_BUCKET, &prefix, true);
                        d.options.insert("endpoint".into(), toxi_s3());
                        d
                    }
                    DestKind::Traversal => {
                        let i = root
                            .as_deref()
                            .and_then(|r| r.parse::<usize>().ok())
                            .unwrap_or(0)
                            % TRAVERSAL_ROOTS.len();
                        let t = fill(TRAVERSAL_ROOTS[i], self);
                        let mut d = fs_dest("evil", &t);
                        // Every other attempt goes through the in-service prefix instead.
                        if i % 2 == 1 {
                            d = fs_dest("evil", self.mount.join("common").to_str().unwrap());
                            d.root = t;
                        }
                        d
                    }
                    DestKind::Symlink => {
                        // The user's own mount folder holds a link to the outside.
                        self.note_owner_dir(u);
                        let Some(own) = self.users[u].owner_dir.clone() else {
                            return Ok(());
                        };
                        let own = self.mount.join(own);
                        let _ = std::fs::create_dir_all(&own);
                        let link = own.join(format!("link{}", self.msg_counter));
                        #[cfg(unix)]
                        let _ = std::os::unix::fs::symlink(&self.canary, &link);
                        let mut d = fs_dest(
                            "linked",
                            self.mount
                                .join(link.file_name().unwrap())
                                .join("x")
                                .to_str()
                                .unwrap(),
                        );
                        if root.is_some() {
                            d = fs_dest("linked", self.mount.join("common").to_str().unwrap());
                            d.root =
                                format!("../{}/x", link.file_name().unwrap().to_string_lossy());
                        }
                        d
                    }
                };
                if let Some(n) = name {
                    input.name = n.clone();
                }
                if kind != DestKind::SharedS3 {
                    input.encrypt = encrypt.unwrap_or(false);
                }
                input.deep_check = match deep.unwrap_or(0) {
                    1 => DeepCheckMode::Rotating { slices: 3 },
                    2 => DeepCheckMode::Off,
                    _ => DeepCheckMode::Full,
                };
                let (st, v) = self
                    .call(&api, Method::POST, "/destinations", Some(&input))
                    .await?;
                let dotdot = |p: &str| p.split(['/', '\\']).any(|c| c == "..");
                match st {
                    200 => {
                        // A real ".." path component must never be accepted.
                        let opt_root = input.options.get("root").cloned().unwrap_or_default();
                        if matches!(kind, DestKind::Traversal)
                            && (dotdot(&opt_root) || dotdot(&input.root))
                        {
                            return Err(violation("traversal_accepted", format!("{input:?}")));
                        }
                        let d: DestinationView = serde_json::from_value(v).unwrap();
                        self.users[u].ever_destinations.insert(d.id.clone());
                        self.users[u].destinations.push(DestModel {
                            id: d.id,
                            primary: false,
                        });
                    }
                    s if s >= 500 && !self.disk_faults_tolerated() => {
                        return Err(violation(
                            "name_crash",
                            format!("POST /destinations {input:?} → {s}"),
                        ));
                    }
                    _ => {}
                }
            }
            Op::RemoveDestination { u, slot } => {
                let Some(api) = self.ensure_session(u).await? else {
                    return Ok(());
                };
                let removable: Vec<usize> = (0..self.users[u].destinations.len())
                    .filter(|i| !self.users[u].destinations[*i].primary)
                    .collect();
                if removable.is_empty() {
                    return Ok(());
                }
                let i = removable[slot % removable.len()];
                let id = self.users[u].destinations[i].id.clone();
                let only_here = self.only_copies_on(u, &id);
                let (st, _) = self
                    .call(
                        &api,
                        Method::DELETE,
                        &format!("/destinations/{id}"),
                        None::<&()>,
                    )
                    .await?;
                if st == 200 {
                    self.users[u].destinations.remove(i);
                    self.users[u].released.extend(only_here);
                }
            }
            Op::AddAccount {
                u,
                mailbox,
                ref name,
                ref opts,
            } => {
                let Some(api) = self.ensure_session(u).await? else {
                    return Ok(());
                };
                let name = name.clone().unwrap_or_else(|| {
                    format!("acc{u}-{mailbox}-{}", self.users[u].accounts.len())
                });
                let (starttls, idle) = opts
                    .as_ref()
                    .map_or((false, false), |o| (o.starttls, o.idle));
                let mut input = imap_input(
                    &name,
                    &self.mail[mailbox].imap_user,
                    if starttls { 10143 } else { IMAP_PORT },
                );
                if starttls {
                    input.tls = TlsMode::Starttls;
                }
                input.idle = idle;
                let (st, v) = self
                    .call(&api, Method::POST, "/accounts", Some(&input))
                    .await?;
                if st == 200 {
                    let a: AccountView = serde_json::from_value(v).unwrap();
                    self.users[u].ever_accounts.insert(a.id.clone());
                    self.users[u].ever_mailboxes.insert(mailbox);
                    self.users[u].accounts.push(AccModel {
                        id: a.id,
                        name: a.name,
                        mailbox,
                        starttls,
                        idle,
                    });
                } else if st >= 500 {
                    // A name the server cannot handle must be refused (4xx), never crash it.
                    if !self.disk_faults_tolerated() {
                        return Err(violation(
                            "name_crash",
                            format!("POST /accounts with name {name:?} → {st}"),
                        ));
                    }
                }
            }
            Op::RenameAccount { u, slot, ref name } => {
                let Some(api) = self.ensure_session(u).await? else {
                    return Ok(());
                };
                if self.users[u].accounts.is_empty() {
                    return Ok(());
                }
                let i = slot % self.users[u].accounts.len();
                let acc = self.users[u].accounts[i].clone();
                let new_name = name.clone().unwrap_or_else(|| {
                    format!(
                        "{}-r{}",
                        acc.name.split("-r").next().unwrap(),
                        rand::random::<u16>()
                    )
                });
                let input = self.account_input(&acc, &new_name);
                let (st, v) = self
                    .call(
                        &api,
                        Method::PUT,
                        &format!("/accounts/{}", acc.id),
                        Some(&input),
                    )
                    .await?;
                if st == 200 {
                    let a: AccountView = serde_json::from_value(v).unwrap();
                    self.users[u].accounts[i].name = a.name;
                } else if st >= 500 && !self.disk_faults_tolerated() {
                    return Err(violation(
                        "name_crash",
                        format!("PUT /accounts with name {new_name:?} → {st}"),
                    ));
                }
            }
            Op::RemoveAccount { u, slot } => {
                let Some(api) = self.ensure_session(u).await? else {
                    return Ok(());
                };
                if self.users[u].accounts.is_empty() {
                    return Ok(());
                }
                let i = slot % self.users[u].accounts.len();
                let id = self.users[u].accounts[i].id.clone();
                let (st, _) = self
                    .call(
                        &api,
                        Method::DELETE,
                        &format!("/accounts/{id}"),
                        None::<&()>,
                    )
                    .await?;
                if st == 200 {
                    self.users[u].accounts.remove(i);
                }
            }
            Op::Backup { u, slot, wait } => {
                if let Some(acc) = self.users[u]
                    .accounts
                    .get(slot % self.users[u].accounts.len().max(1))
                    .cloned()
                {
                    self.job(u, JobKind::Backup { account_id: acc.id }, wait)
                        .await?;
                }
            }
            Op::Check { u, deep, wait } => {
                self.job(
                    u,
                    JobKind::Check {
                        scope: CheckScope::All,
                        deep,
                    },
                    wait,
                )
                .await?
            }
            Op::Repair { u, wait } => {
                self.job(
                    u,
                    JobKind::Repair {
                        scope: CheckScope::All,
                    },
                    wait,
                )
                .await?
            }
            Op::Rebuild {
                u,
                slot: _,
                wait,
                all: true,
            } => {
                self.job(u, JobKind::RebuildIndexAll, wait).await?;
            }
            Op::Rebuild { u, slot, wait, .. } => {
                if let Some(d) = self.users[u]
                    .destinations
                    .get(slot % self.users[u].destinations.len().max(1))
                    .cloned()
                {
                    self.job(
                        u,
                        JobKind::RebuildIndex {
                            destination_id: d.id,
                        },
                        wait,
                    )
                    .await?;
                }
            }
            Op::ArmPurge {
                u,
                slot,
                ref policy,
            } => {
                let Some(api) = self.ensure_session(u).await? else {
                    return Ok(());
                };
                let Some(acc) = self.users[u]
                    .accounts
                    .get(slot % self.users[u].accounts.len().max(1))
                    .cloned()
                else {
                    return Ok(());
                };
                let shape = policy.clone().unwrap_or(PolicyShape {
                    older_than_days: 0,
                    exclude_flagged: false,
                    exclude_pick: None,
                    only_primary: false,
                });
                let mut required = self.primary_and_others(u);
                if shape.only_primary {
                    required.truncate(1);
                }
                let mut exclude = vec![];
                if let Some(pick) = shape.exclude_pick {
                    let folders = self.server_folders(acc.mailbox).await;
                    if !folders.is_empty() {
                        exclude.push(folders[pick as usize % folders.len()].clone());
                    }
                }
                let policy = PurgePolicy {
                    older_than_days: shape.older_than_days,
                    required_destinations: required,
                    exclude_mailboxes: exclude,
                    exclude_flagged: shape.exclude_flagged,
                    schedule_hours: 0,
                    armed: false,
                    armed_at: None,
                };
                let (st, _) = self
                    .call(
                        &api,
                        Method::PUT,
                        &format!("/accounts/{}/policy", acc.id),
                        Some(&policy),
                    )
                    .await?;
                if st != 200 {
                    return Ok(());
                }
                self.job(
                    u,
                    JobKind::PurgeDryRun {
                        account_id: acc.id.clone(),
                    },
                    true,
                )
                .await?;
                let Some(api) = self.ensure_session(u).await? else {
                    return Ok(());
                };
                self.call(
                    &api,
                    Method::POST,
                    &format!("/accounts/{}/policy/arm", acc.id),
                    Some(&ArmRequest {
                        confirm_name: acc.name.clone(),
                    }),
                )
                .await?;
            }
            Op::Purge { u, slot, wait } => {
                if let Some(acc) = self.users[u]
                    .accounts
                    .get(slot % self.users[u].accounts.len().max(1))
                    .cloned()
                {
                    // A purge of an unarmed account arms it first (policy, dry run, typed name).
                    let armed = match self.ensure_session(u).await? {
                        Some(api) => {
                            let path = format!("/accounts/{}", acc.id);
                            let (st, v) = self.call(&api, Method::GET, &path, None::<&()>).await?;
                            st == 200
                                && v.pointer("/policy/armed").and_then(|a| a.as_bool())
                                    == Some(true)
                        }
                        None => false,
                    };
                    if !armed {
                        Box::pin(self.exec_one(&Op::ArmPurge {
                            u,
                            slot,
                            policy: None,
                        }))
                        .await?;
                    }
                    self.job(u, JobKind::Purge { account_id: acc.id }, wait)
                        .await?;
                }
            }
            Op::CancelLatest { u } => {
                if let (Some(api), Some(id)) = (self.session(u), self.users[u].jobs.last().cloned())
                {
                    self.call(&api, Method::DELETE, &format!("/jobs/{id}"), None::<&()>)
                        .await?;
                }
            }
            Op::ImapAppend {
                m,
                to_box,
                ref folder,
                ref shape,
            } => {
                self.new_message(m, to_box, folder.as_deref(), shape.as_ref())
                    .await
                    .map_err(|e| violation("harness", e.to_string()))?;
            }
            Op::ImapFolder { m, ref action } => {
                // Another mail client changes folders. Its connection is not Malo's: if the IMAP
                // server stops answering it, drop that client and go on.
                let user = self.mail[m].imap_user.clone();
                let folders = match action {
                    FolderAction::Create { .. } => vec![],
                    _ => tokio::time::timeout(Duration::from_secs(30), self.server_folders(m))
                        .await
                        .unwrap_or_default(),
                };
                let action = action.clone();
                let work = async move {
                    let mut c = imap_conn(&user, IMAP_PORT).await;
                    let mut deleted = vec![];
                    match &action {
                        FolderAction::Create { name } => {
                            let _ = c.session.create(malo_core::layout::encode_utf7(name)).await;
                        }
                        FolderAction::Rename { pick, to } => {
                            if !folders.is_empty() {
                                let from = &folders[*pick as usize % folders.len()];
                                let _ = c
                                    .session
                                    .rename(from, malo_core::layout::encode_utf7(to))
                                    .await;
                            }
                        }
                        FolderAction::Delete { pick } => {
                            if !folders.is_empty() {
                                let name = folders[*pick as usize % folders.len()].clone();
                                // Its messages are deleted by another client: record them first.
                                let tokens = folder_tokens(&mut c, &name).await;
                                c.session.select("INBOX").await.ok();
                                if c.session.delete(&name).await.is_ok() {
                                    deleted = tokens;
                                }
                            }
                        }
                    }
                    c.logout().await;
                    deleted
                };
                match tokio::time::timeout(Duration::from_secs(30), work).await {
                    Ok(deleted) => {
                        for t in deleted {
                            if let Some(t) = self.mail[m].messages.get_mut(&t) {
                                t.externally_deleted = true;
                            }
                        }
                    }
                    Err(_) => self.trace.push(
                        "  note: the IMAP server did not answer another client's folder change"
                            .into(),
                    ),
                }
            }
            Op::ImapDelete { m } => {
                // Another mail client deletes the newest message it can find.
                let mut c = imap_conn(&self.mail[m].imap_user, IMAP_PORT).await;
                c.select("INBOX").await.ok();
                if let Some(uid) = c.all_uids().await.ok().and_then(|u| u.last().copied()) {
                    if let Ok(Some((raw, _))) = c.fetch_raw(uid).await {
                        let subject = malo_core::viewer::envelope_of(&raw).subject;
                        let token = subject.split_whitespace().next().unwrap_or("").to_string();
                        if c.delete_uids(&[uid]).await.is_ok() {
                            if let Some(t) = self.mail[m].messages.get_mut(&token) {
                                t.externally_deleted = true;
                            }
                        }
                    }
                }
                c.logout().await;
            }
            Op::ImapRecreateBox { m } => {
                let mut c = imap_conn(&self.mail[m].imap_user, IMAP_PORT).await;
                if c.select("Box").await.is_ok() {
                    for uid in c.all_uids().await.unwrap_or_default() {
                        if let Ok(Some((raw, _))) = c.fetch_raw(uid).await {
                            let token = malo_core::viewer::envelope_of(&raw)
                                .subject
                                .split_whitespace()
                                .next()
                                .unwrap_or("")
                                .to_string();
                            if let Some(t) = self.mail[m].messages.get_mut(&token) {
                                t.externally_deleted = true;
                            }
                        }
                    }
                    c.session.select("INBOX").await.ok();
                    let _ = c.session.delete("Box").await;
                }
                let _ = c.session.create("Box").await;
                c.logout().await;
            }
            Op::ImapKick { m } => {
                compose(&[
                    "exec",
                    "-T",
                    "dovecot",
                    "doveadm",
                    "kick",
                    &self.mail[m].imap_user,
                ]);
                self.last_fault = Some(Instant::now());
            }
            Op::DeleteSharedObject { pick } => {
                if let Some(path) = self.pick_shared_object(pick).await {
                    let _ = s3_operator(S3_BUCKET).delete(&path).await;
                    self.shared_damage = true;
                    self.last_fault = Some(Instant::now());
                    self.trace.push(format!("  deleted {path}"));
                }
            }
            Op::CorruptSharedObject { pick } => {
                if let Some(path) = self.pick_shared_object(pick).await {
                    let op = s3_operator(S3_BUCKET);
                    if let Ok(buf) = op.read(&path).await {
                        let mut raw = buf.to_vec();
                        if let Some(b) = raw.get_mut(60) {
                            *b ^= 0x5A;
                        }
                        let _ = op.write(&path, raw).await;
                        self.shared_damage = true;
                        self.last_fault = Some(Instant::now());
                        self.trace.push(format!("  corrupted {path}"));
                    }
                }
            }
            Op::StorageOutage { ms } => {
                compose(&["pause", "rustfs"]);
                self.last_fault = Some(Instant::now());
                self.outage_until = Some(Instant::now() + Duration::from_millis(ms));
                tokio::time::sleep(Duration::from_millis(ms)).await;
                compose(&["unpause", "rustfs"]);
                self.outage_until = None;
            }
            Op::Probe { u, v } => self.probe(u, v).await?,
            Op::LoginB { u } => {
                let um = &self.users[u];
                if um.id.is_none() || um.deleted || um.disabled {
                    return Ok(());
                }
                let anon = Api {
                    token: None,
                    ..self.api.clone()
                };
                let req = LoginRequest {
                    username: um.name.clone(),
                    password: um.password.clone(),
                };
                match anon
                    .call::<_, LoginResponse>(Method::POST, "/auth/login", Some(&req))
                    .await
                {
                    Ok(r) => {
                        let api = Api {
                            token: Some(r.token),
                            ..self.api.clone()
                        };
                        self.users[u].events_b =
                            tokio::time::timeout(Duration::from_secs(5), api.events())
                                .await
                                .ok();
                        if let Some((old, _)) =
                            self.users[u].device_b.replace((api, Instant::now()))
                        {
                            drop(old);
                        }
                        self.users[u].sealed_at = None;
                        // A second login doesn't disturb the first device.
                        if let Some((a, t)) = self.users[u].session.clone() {
                            if a.status_of(Method::GET, "/me").await != 200
                                && (t.elapsed().as_secs() as i64) + 2 < AUTO_LOCK_SECS
                            {
                                return Err(violation(
                                    "second_login_broke_first",
                                    "device A lost its session when device B logged in",
                                ));
                            }
                        }
                    }
                    Err((500, _)) if self.disk_faults_tolerated() => {}
                    Err((s, t)) if is_server_error(s) => {
                        return Err(violation("server_error", format!("login B → {s}: {t}")))
                    }
                    Err((s, t)) if s != 429 => {
                        return Err(violation(
                            "login_refused",
                            format!("device B, correct password refused: {s} {t}"),
                        ))
                    }
                    Err(_) => {}
                }
            }
            Op::LogoutB { u } => {
                if let Some((b, _)) = self.users[u].device_b.take() {
                    self.call(&b, Method::POST, "/auth/logout", None::<&()>)
                        .await?;
                    self.users[u].stale.push(b);
                    self.users[u].events_b = None;
                    if let Some((a, t)) = self.users[u].session.clone() {
                        let st = a.status_of(Method::GET, "/me").await;
                        if st != 200 && (t.elapsed().as_secs() as i64) + 2 < AUTO_LOCK_SECS {
                            return Err(violation(
                                "logout_hit_other_device",
                                format!("device A got {st} after device B logged out"),
                            ));
                        }
                    }
                }
            }
            Op::StaleEdit { u, slot } => {
                let Some(a_api) = self.ensure_session(u).await? else {
                    return Ok(());
                };
                if self.users[u].device_b.is_none() {
                    Box::pin(self.exec_one(&Op::LoginB { u })).await?;
                }
                let Some((b_api, _)) = self.users[u].device_b.clone() else {
                    return Ok(());
                };
                if self.users[u].accounts.is_empty() {
                    return Ok(());
                }
                let i = slot % self.users[u].accounts.len();
                let acc = self.users[u].accounts[i].clone();
                // Device B loads the form …
                let (st, v) = self
                    .call(
                        &b_api,
                        Method::GET,
                        &format!("/accounts/{}", acc.id),
                        None::<&()>,
                    )
                    .await?;
                if st != 200 {
                    return Ok(());
                }
                let seen: AccountView = serde_json::from_value(v).unwrap();
                // … device A saves a change meanwhile …
                let a_name = format!(
                    "{}-a{}",
                    acc.name.split("-a").next().unwrap(),
                    rand::random::<u16>()
                );
                let mut input = self.account_input(&acc, &a_name);
                input.revision = Some(seen.revision);
                let (st, v) = self
                    .call(
                        &a_api,
                        Method::PUT,
                        &format!("/accounts/{}", acc.id),
                        Some(&input),
                    )
                    .await?;
                if st != 200 {
                    return Ok(());
                }
                let a: AccountView = serde_json::from_value(v).unwrap();
                self.users[u].accounts[i].name = a.name;
                // … then device B saves its stale form: must be refused, never overwrite A's change.
                let mut stale = self.account_input(&acc, &format!("{}-b", acc.name));
                stale.revision = Some(seen.revision);
                let (st, body) = self
                    .call(
                        &b_api,
                        Method::PUT,
                        &format!("/accounts/{}", acc.id),
                        Some(&stale),
                    )
                    .await?;
                match st {
                    409 => {}
                    200 => {
                        return Err(violation(
                            "stale_overwrite",
                            "device B overwrote device A's newer change",
                        ))
                    }
                    other => {
                        return Err(violation(
                            "stale_edit_status",
                            format!("expected 409 for a stale save, got {other}: {body}"),
                        ))
                    }
                }
            }
            Op::Faults {
                site,
                fault,
                per_mille,
                target,
                count,
            } => {
                let scope = match target {
                    FaultTarget::AnyDestination | FaultTarget::Local => None,
                    FaultTarget::Primary { u } | FaultTarget::Shared { u } => {
                        let primary = matches!(target, FaultTarget::Primary { .. });
                        match self.users[u]
                            .destinations
                            .iter()
                            .find(|d| d.primary == primary)
                        {
                            Some(d) => Some(d.id.clone()),
                            None => return Ok(()), // no such destination: no fault
                        }
                    }
                };
                let scope = match site {
                    faults::Site::Spool | faults::Site::Cache => None,
                    _ => scope,
                };
                faults::add(faults::Rule {
                    site,
                    fault,
                    per_mille,
                    scope,
                    remaining: Some(count),
                });
                self.last_fault = Some(Instant::now());
            }
            Op::ClearFaults => faults::clear(),
            Op::Net { kind, ms } => {
                toxic(kind, ms).await;
                self.last_fault = Some(Instant::now());
            }
            Op::ReadOnlyPrimary { u, ms } => {
                let Some(id) = self.users[u].id.clone().filter(|_| !self.users[u].deleted) else {
                    return Ok(());
                };
                let dir = self
                    .dir
                    .path()
                    .join("users")
                    .join(&id)
                    .join("local")
                    .join("primary");
                if dir.exists() {
                    set_read_only(&dir, true);
                    self.read_only.push(dir.clone());
                    self.last_fault = Some(Instant::now());
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    set_read_only(&dir, false);
                    self.read_only.retain(|d| d != &dir);
                }
            }
            Op::Burst { .. } => unreachable!(),
        }
        Ok(())
    }
}

// ───────────────────────────── more operations ─────────────────────────────

impl World {
    async fn pick_shared_object(&self, pick: u32) -> Option<String> {
        use futures::TryStreamExt;
        let op = s3_operator(S3_BUCKET);
        let mut files = Vec::new();
        let mut l = op
            .lister_with(&format!("{}/", self.s3_prefix))
            .recursive(true)
            .await
            .ok()?;
        while let Ok(Some(e)) = l.try_next().await {
            if e.path().contains("/objects/") {
                files.push(e.path().to_string());
            }
        }
        files.sort();
        (!files.is_empty()).then(|| files[pick as usize % files.len()].clone())
    }

    /// After a self- or admin-deletion: everything of the user is gone and stays gone.
    async fn mark_deleted(&mut self, u: usize) -> Check {
        self.seal(u);
        self.users[u].deleted = true;
        let id = self.users[u].id.clone().unwrap();
        if self.state().keyring.get(&id).is_some() {
            return Err(violation(
                "delete_kept_keys",
                "keys still in memory after deletion",
            ));
        }
        if !self.wait_jobs_quiet(&id, 30).await {
            return Err(violation(
                "jobs_after_delete",
                "jobs still running 30 s after deletion",
            ));
        }
        let dir = self.dir.path().join("users").join(&id);
        if dir.exists() {
            return Err(violation(
                "delete_left_data",
                format!("{} still exists", dir.display()),
            ));
        }
        // Shared-mount backups of a deleted user may stay, but must never change again.
        if let Some(own) = self.users[u].owner_dir.clone() {
            let snap = snapshot(&self.mount.join(&own));
            self.deleted_snapshots.insert(own, snap);
        }
        Ok(())
    }

    /// User `u` pokes at everything of user `v` it might know: ids in paths and query strings.
    async fn probe(&mut self, u: usize, v: usize) -> Check {
        if u == v {
            return Ok(());
        }
        let Some(api) = self.ensure_session(u).await? else {
            return Ok(());
        };
        let mut paths = Vec::new();
        for id in self.users[v].ever_accounts.clone() {
            paths.push((Method::GET, format!("/accounts/{id}")));
            paths.push((Method::POST, format!("/accounts/{id}/test")));
            paths.push((Method::PUT, format!("/accounts/{id}/policy")));
            paths.push((Method::POST, format!("/accounts/{id}/policy/arm")));
            paths.push((Method::DELETE, format!("/accounts/{id}")));
            paths.push((Method::GET, format!("/mailboxes?account={id}")));
            paths.push((Method::GET, format!("/messages?account={id}")));
            paths.push((Method::GET, format!("/audit?account={id}")));
        }
        for id in self.users[v].ever_destinations.clone() {
            paths.push((Method::POST, format!("/destinations/{id}/test")));
            paths.push((Method::DELETE, format!("/destinations/{id}")));
        }
        for id in self.users[v].jobs.clone() {
            paths.push((Method::GET, format!("/jobs/{id}")));
            paths.push((Method::DELETE, format!("/jobs/{id}")));
        }
        for (m, path) in paths {
            let body = if m == Method::PUT {
                Some(serde_json::to_value(PurgePolicy::default()).unwrap())
            } else if m == Method::POST {
                Some(serde_json::json!({"confirm_name": "x"}))
            } else {
                None
            };
            let (st, v) = self.call(&api, m.clone(), &path, body.as_ref()).await?;
            let leaked = match st {
                200 => match &v {
                    serde_json::Value::Array(a) => !a.is_empty(),
                    serde_json::Value::Object(o) => {
                        o.get("total").and_then(|t| t.as_u64()) != Some(0)
                    }
                    _ => true,
                },
                _ => false,
            };
            if leaked {
                return Err(violation(
                    "isolation_probe",
                    format!("{m} {path} by another user → {st}: {v}"),
                ));
            }
        }
        // Jobs on another user's account must be refused too.
        for id in self.users[v].ever_accounts.clone() {
            let body = CreateJobRequest {
                kind: JobKind::Backup {
                    account_id: id.clone(),
                },
            };
            let (st, _) = self.call(&api, Method::POST, "/jobs", Some(&body)).await?;
            if st == 200 {
                return Err(violation(
                    "isolation_probe",
                    format!("user {u} started a backup of user {v}'s account {id}"),
                ));
            }
        }
        Ok(())
    }
}

// ───────────────────────────── invariants ─────────────────────────────

impl World {
    async fn check(&mut self) -> Check {
        // Health.
        let server = self.server.as_ref().unwrap();
        if server.task.is_finished() {
            return Err(violation("server_died", "the HTTP server task ended"));
        }
        let health = self.api.status_of(Method::GET, "/healthz").await;
        if health != 200 {
            return Err(violation("unhealthy", format!("/healthz → {health}")));
        }

        // Dead tokens stay dead.
        for u in 0..USERS {
            for api in self.users[u].stale.clone() {
                let st = api.status_of(Method::GET, "/me").await;
                if st == 200 {
                    return Err(violation(
                        "stale_token_works",
                        format!("user {u}: a logged-out/locked/deleted session still works"),
                    ));
                }
            }
        }

        // Sealed users have no keys and nothing running.
        for u in 0..USERS {
            let Some(id) = self.users[u].id.clone() else {
                continue;
            };
            let sealed = self.users[u].session.is_none() && self.users[u].device_b.is_none();
            if sealed && !self.users[u].deleted {
                if let Some(at) = self.users[u].sealed_at {
                    // Another live session of the same user may exist only if we never sealed.
                    if self.state().keyring.get(&id).is_some()
                        && chrono::Utc::now() - at > chrono::Duration::seconds(2)
                    {
                        return Err(violation(
                            "sealed_has_keys",
                            format!("user {u} is locked but keys are in memory"),
                        ));
                    }
                    let started_after = self
                        .state()
                        .db
                        .jobs(&id, 500)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|j| {
                            j.started_at
                                .is_some_and(|s| s > at + chrono::Duration::seconds(1))
                        })
                        .filter(|j| !matches!(j.state, JobState::SkippedLocked))
                        .count();
                    if started_after > 0 {
                        return Err(violation(
                            "job_after_seal",
                            format!("user {u}: {started_after} job(s) started while locked"),
                        ));
                    }
                }
            }
            if self.users[u].deleted {
                let dir = self.dir.path().join("users").join(&id);
                if dir.exists() {
                    return Err(violation(
                        "zombie_user_dir",
                        format!("deleted user {u}'s folder came back: {}", dir.display()),
                    ));
                }
                if self.state().db.user(&id).ok().flatten().is_some() {
                    return Err(violation(
                        "zombie_user_row",
                        format!("deleted user {u} is back in the user table"),
                    ));
                }
            }
        }

        // Device B sessions stay valid until a lock, a password change elsewhere or auto-lock.
        for u in 0..USERS {
            let Some((b, t)) = self.users[u].device_b.clone() else {
                continue;
            };
            let st = b.status_of(Method::GET, "/me").await;
            if st != 200 {
                let age = t.elapsed().as_secs() as i64;
                // Each session ends at its own auto-lock time.
                if (st == 401 || st == 423) && age + 2 >= AUTO_LOCK_SECS {
                    self.expire_device(u, true);
                    continue;
                }
                if st == 500 && self.disk_faults_tolerated() {
                    continue;
                }
                return Err(violation(
                    "session_lost",
                    format!("user {u}'s device B session ended early ({st}) after {age} s"),
                ));
            }
        }

        // Valid sessions: everything they see is theirs, and the config is what they last saved.
        for u in 0..USERS {
            let Some(api) = self.session(u) else { continue };
            let (st, v) = self
                .call(&api, Method::GET, "/accounts", None::<&()>)
                .await?;
            if st != 200 {
                let age = self.users[u]
                    .session
                    .as_ref()
                    .map(|(_, t)| t.elapsed().as_secs() as i64)
                    .unwrap_or(0);
                if (st == 401 || st == 423) && age + 2 >= AUTO_LOCK_SECS {
                    self.expire_device(u, false); // auto-lock of this session
                    continue;
                }
                if st == 401 || st == 423 {
                    return Err(violation(
                        "session_lost",
                        format!("user {u}'s session ended early ({st}) after {age} s"),
                    ));
                }
                continue;
            }
            let accounts: Vec<AccountView> = serde_json::from_value(v).unwrap();
            let mine: HashSet<&String> = self.users[u].ever_accounts.iter().collect();
            for a in &accounts {
                if !mine.contains(&a.id) && !a.imported {
                    return Err(violation(
                        "isolation_list",
                        format!("user {u} sees account {} ({})", a.id, a.name),
                    ));
                }
            }
            for m in &self.users[u].accounts {
                match accounts.iter().find(|a| a.id == m.id) {
                    None => {
                        return Err(violation(
                            "lost_account",
                            format!("user {u}'s account {} vanished", m.name),
                        ))
                    }
                    Some(a) if a.name != m.name => {
                        return Err(violation(
                            "lost_update",
                            format!(
                                "user {u}: account renamed to {:?} but server says {:?}",
                                m.name, a.name
                            ),
                        ))
                    }
                    _ => {}
                }
            }
            let imported: HashSet<String> = accounts
                .iter()
                .filter(|a| a.imported)
                .map(|a| a.id.clone())
                .collect();
            let (_, v) = self
                .call(&api, Method::GET, "/destinations", None::<&()>)
                .await?;
            if let Ok(dests) = serde_json::from_value::<Vec<DestinationView>>(v) {
                for d in dests {
                    if !self.users[u].ever_destinations.contains(&d.id) {
                        return Err(violation(
                            "isolation_list",
                            format!("user {u} sees destination {}", d.id),
                        ));
                    }
                }
            }
            let (_, v) = self
                .call(&api, Method::GET, "/messages?limit=1000", None::<&()>)
                .await?;
            if let Ok(list) = serde_json::from_value::<MessageList>(v) {
                for msg in list.messages {
                    if !self.users[u].ever_accounts.contains(&msg.account_id)
                        && !imported.contains(&msg.account_id)
                    {
                        let owners: Vec<usize> = (0..USERS)
                            .filter(|o| self.users[*o].ever_accounts.contains(&msg.account_id))
                            .collect();
                        let (_, audit) = self
                            .call(&api, Method::GET, "/audit?limit=50", None::<&()>)
                            .await?;
                        self.trace.push(format!(
                            "  diag: owners {owners:?}; message {}; accounts {:?}; dests {:?}; audit {}",
                            serde_json::to_string(&msg).unwrap_or_default(),
                            accounts.iter().map(|a| (&a.id, &a.name, a.imported)).collect::<Vec<_>>(),
                            self.users[u].destinations.iter().map(|d| &d.id).collect::<Vec<_>>(),
                            audit
                        ));
                        return Err(violation(
                            "isolation_messages",
                            format!(
                                "user {u} sees message {} of account {}",
                                msg.id, msg.account_id
                            ),
                        ));
                    }
                }
            }
            let (_, v) = self
                .call(&api, Method::GET, "/jobs?limit=1000", None::<&()>)
                .await?;
            if let Ok(jobs) = serde_json::from_value::<Vec<JobInfo>>(v) {
                for j in jobs {
                    let ok = match &j.kind {
                        JobKind::Backup { account_id }
                        | JobKind::Purge { account_id }
                        | JobKind::PurgeDryRun { account_id } => {
                            self.users[u].ever_accounts.contains(account_id)
                                || imported.contains(account_id)
                        }
                        JobKind::RebuildIndex { destination_id } => {
                            self.users[u].ever_destinations.contains(destination_id)
                        }
                        _ => true,
                    };
                    if !ok {
                        return Err(violation(
                            "isolation_jobs",
                            format!("user {u} sees job {:?}", j.kind),
                        ));
                    }
                }
            }
            // Live events only concern this user.
            let streams: Vec<_> = [self.users[u].events.clone(), self.users[u].events_b.clone()]
                .into_iter()
                .flatten()
                .collect();
            for events in streams {
                let events = events.lock().unwrap().clone();
                for e in events {
                    let account = match &e {
                        SyncEvent::NewMessageDiscovered { message } => {
                            Some(message.account_id.clone())
                        }
                        SyncEvent::MessageStateChanged { account_id, .. } => {
                            Some(account_id.clone())
                        }
                        SyncEvent::JobQueued { job }
                        | SyncEvent::JobStarted { job }
                        | SyncEvent::JobFinished { job } => {
                            job.kind.account_id().map(str::to_string)
                        }
                        SyncEvent::PurgeSummary { summary } => Some(summary.account_id.clone()),
                        _ => None,
                    };
                    if let Some(a) = account {
                        if !self.users[u].ever_accounts.contains(&a) && !imported.contains(&a) {
                            return Err(violation(
                                "isolation_events",
                                format!("user {u} received an event about account {a}: {e:?}"),
                            ));
                        }
                    }
                }
            }
        }

        // Independent oracle for "verified": every replica the index marks verified on a user's
        // primary local folder is read straight from disk by the fuzzer and must hash correctly.
        for u in 0..USERS {
            let (Some(id), false) = (self.users[u].id.clone(), self.users[u].deleted) else {
                continue;
            };
            let Some(primary) = self.users[u]
                .destinations
                .iter()
                .find(|d| d.primary)
                .map(|d| d.id.clone())
            else {
                continue;
            };
            let Some(user) = self.state().keyring.get(&id) else {
                continue;
            };
            let Ok(replicas) = user.index.replicas_in(&primary) else {
                continue;
            }; // index faults
            let root = self
                .dir
                .path()
                .join("users")
                .join(&id)
                .join("local")
                .join("primary");
            for r in replicas
                .into_iter()
                .filter(|r| r.status == malo_core::index::ReplicaStatus::Verified)
            {
                let Some(sha) = r.sha256.as_deref() else {
                    continue;
                };
                let on_disk = std::fs::read(root.join(&r.object_path)).ok();
                let good = on_disk
                    .as_deref()
                    .is_some_and(|b| malo_core::crypto::sha256_hex(b) == sha);
                if !good {
                    return Err(violation(
                        "false_verified",
                        format!(
                            "user {u}: {} is recorded as verified but is {} on disk",
                            r.object_path,
                            if on_disk.is_none() {
                                "missing"
                            } else {
                                "wrong"
                            }
                        ),
                    ));
                }
            }
        }

        // Nothing ever lands outside the allowed area (every traversal attempt aims at the canary).
        let mut escaped = vec![];
        walk(&self.canary, &mut escaped);
        if let Some(f) = escaped.first() {
            return Err(violation(
                "escaped_root",
                format!(
                    "{} file(s) written outside the allowed area, e.g. {}",
                    escaped.len(),
                    f.display()
                ),
            ));
        }

        // No two different messages share a storage path (a name mapping that collides would
        // make one backup overwrite another).
        for u in 0..USERS {
            let Some(id) = self.users[u].id.clone() else {
                continue;
            };
            let Some(k) = self.state().keyring.get(&id) else {
                continue;
            };
            for d in k.config().destinations.iter() {
                let mut by_path: HashMap<String, HashSet<String>> = HashMap::new();
                for r in k.index.replicas_in(&d.id).unwrap_or_default() {
                    if r.status == malo_core::index::ReplicaStatus::Verified {
                        if let Some(sha) = r.sha256 {
                            by_path.entry(r.object_path).or_default().insert(sha);
                        }
                    }
                }
                if let Some((path, shas)) = by_path.iter().find(|(_, s)| s.len() > 1) {
                    return Err(violation(
                        "path_collision",
                        format!(
                            "user {u}: {} different messages stored at {path}",
                            shas.len()
                        ),
                    ));
                }
            }
        }

        // Files: user folders only for users that exist; shared mount split per user, nothing else.
        for u in 0..USERS {
            self.note_owner_dir(u);
        }
        let owners: HashSet<String> = self
            .users
            .iter()
            .filter_map(|u| u.owner_dir.clone())
            .collect();
        // A user never unlocked so far has no folder to account for yet, but if one shows up it
        // may be theirs.
        let all_known = self
            .users
            .iter()
            .all(|u| u.id.is_none() || u.owner_dir.is_some());
        for e in std::fs::read_dir(self.mount.as_path())
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = e.file_name().to_string_lossy().to_string();
            if all_known && !owners.contains(&name) {
                return Err(violation(
                    "shared_mount_layout",
                    format!("unexpected entry {name} at the top of the shared mount"),
                ));
            }
        }
        for (own, snap) in &self.deleted_snapshots {
            if &snapshot(&self.mount.join(own)) != snap {
                return Err(violation(
                    "zombie_writes",
                    format!("files in {own} of a deleted user changed after the deletion"),
                ));
            }
        }
        Ok(())
    }

    /// End of a run: let everything settle, log every surviving user in, let Malo repair and
    /// rebuild, then require that no mail was lost.
    async fn final_check(&mut self) -> Check {
        // The world heals: no more injected faults, network faults or read-only folders.
        faults::clear();
        toxi_reset().await;
        for d in std::mem::take(&mut self.read_only) {
            set_read_only(&d, false);
        }
        self.disk_faults_until = None;
        for u in 0..USERS {
            if let Some(id) = self.users[u].id.clone() {
                if !self.users[u].deleted && !self.wait_jobs_quiet(&id, 120).await {
                    return Err(violation(
                        "job_hang",
                        format!("user {u}'s jobs never finished"),
                    ));
                }
            }
        }
        // Restart: everything is reloaded from disk, proving config, vaults and indexes survived
        // the injected write failures.
        self.restart().await?;
        let admin = self.admin().await;
        for u in 0..USERS {
            if self.users[u].deleted || self.users[u].id.is_none() {
                continue;
            }
            if self.users[u].disabled {
                let id = self.users[u].id.clone().unwrap();
                let body = UpdateUserRequest {
                    disabled: Some(false),
                    role: None,
                    max_accounts: None,
                    max_accounts_default: None,
                };
                self.call(
                    &admin,
                    Method::PUT,
                    &format!("/admin/users/{id}"),
                    Some(&body),
                )
                .await?;
                self.users[u].disabled = false;
            }
            self.login(u).await?;
            // Malo's own recovery tools come first: rebuild from every destination (restores index
            // rows of removed accounts and of a lost index) and repair damaged copies.
            let rebuilt = self.job_info(u, JobKind::RebuildIndexAll).await?;
            self.trace.push(format!(
                "  final rebuild user {u}: {:?} {:?} {}",
                rebuilt.as_ref().map(|j| j.state),
                rebuilt.as_ref().and_then(|j| j.error.clone()),
                rebuilt
                    .as_ref()
                    .and_then(|j| j.result.as_ref())
                    .map(|r| r.to_string().chars().take(1500).collect::<String>())
                    .unwrap_or_default()
            ));
            self.job(
                u,
                JobKind::Repair {
                    scope: CheckScope::All,
                },
                true,
            )
            .await?;
        }
        for u in 0..USERS {
            if !self.users[u].deleted && self.users[u].id.is_some() {
                self.converge(u).await?;
            }
        }
        self.check().await?;
        self.never_lose_mail().await
    }

    /// Every message ever put on a mail server is still there, was deleted by another client, or
    /// is readable — byte for byte — from the backup of a surviving user who purged it.
    async fn never_lose_mail(&mut self) -> Check {
        let mut backed_up = 0u64;
        for u in 0..USERS {
            if let Some(api) = self.session(u) {
                let (_, v) = self
                    .call(
                        &api,
                        Method::GET,
                        "/messages?state=verified&limit=1",
                        None::<&()>,
                    )
                    .await?;
                backed_up += v.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
            }
        }
        self.trace.push(format!(
            "final: {backed_up} verified backups across surviving users"
        ));
        let purged_by = self.purged_by().await?;
        for m in 0..MAILBOXES {
            let on_server: HashSet<String> = {
                let mut c = imap_conn(&self.mail[m].imap_user, IMAP_PORT).await;
                let mut set = HashSet::new();
                for mb in c
                    .list_mailboxes()
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|b| b.selectable)
                {
                    if c.select(&mb.name).await.is_ok() {
                        for uid in c.all_uids().await.unwrap_or_default() {
                            if let Ok(Some((raw, _))) = c.fetch_raw(uid).await {
                                let token = malo_core::viewer::envelope_of(&raw)
                                    .subject
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                                set.insert(token);
                            }
                        }
                    }
                }
                c.logout().await;
                set
            };
            for (token, truth) in self.mail[m].messages.clone() {
                if on_server.contains(&token) || truth.externally_deleted {
                    continue;
                }
                let holders = purged_by.get(&token).cloned().unwrap_or_default();
                if !holders.is_empty()
                    && holders
                        .iter()
                        .all(|u| self.users[*u].released.contains(&token))
                {
                    self.trace.push(format!(
                        "  note: purged {token} lives only on a destination its user removed"
                    ));
                    continue;
                }
                // A purge whose audit record went with a lost index: one of the users who lost
                // theirs and backed up this mailbox must still give the mail back.
                let holders = if holders.is_empty() {
                    let candidates: Vec<usize> = (0..USERS)
                        .filter(|u| {
                            let x = &self.users[*u];
                            x.lost_index && !x.deleted && x.ever_mailboxes.contains(&m)
                        })
                        .collect();
                    if candidates
                        .iter()
                        .any(|u| self.users[*u].released.contains(&token))
                    {
                        continue;
                    }
                    let mut found = candidates.is_empty();
                    for u in &candidates {
                        let Some(api) = self.session(*u) else {
                            found = true;
                            break;
                        };
                        let (_, v) = self
                            .call(
                                &api,
                                Method::GET,
                                &format!("/messages?q={token}%20subject&limit=1000"),
                                None::<&()>,
                            )
                            .await?;
                        let list: MessageList = serde_json::from_value(v).unwrap_or(MessageList {
                            total: 0,
                            messages: vec![],
                            unindexed: 0,
                        });
                        for msg in list.messages {
                            if raw_bytes(&api, msg.id).await.as_deref()
                                == Some(truth.raw.as_slice())
                            {
                                found = true;
                                break;
                            }
                        }
                        if found {
                            break;
                        }
                    }
                    if !found {
                        return Err(violation(
                            "mail_lost",
                            format!("{token} vanished from mailbox {m}, and none of users {candidates:?} (who lost their index) can give it back"),
                        ));
                    }
                    if !candidates.is_empty() {
                        continue;
                    }
                    holders
                } else {
                    holders
                };
                if holders.is_empty() {
                    let excused = self
                        .users
                        .iter()
                        .any(|u| u.deleted && u.ever_mailboxes.contains(&m));
                    if !excused {
                        return Err(violation(
                            "mail_lost",
                            format!("{token} vanished from mailbox {m} without any purge record"),
                        ));
                    }
                    continue;
                }
                for u in holders {
                    let Some(api) = self.session(u) else { continue };
                    let (_, v) = self
                        .call(
                            &api,
                            Method::GET,
                            &format!("/messages?q={token}%20subject&limit=1000"),
                            None::<&()>,
                        )
                        .await?;
                    let list: MessageList = serde_json::from_value(v).unwrap_or(MessageList {
                        total: 0,
                        messages: vec![],
                        unindexed: 0,
                    });
                    let mut found = false;
                    let mut seen = vec![];
                    for msg in list.messages {
                        let bytes = raw_bytes(&api, msg.id).await;
                        if bytes.as_deref() == Some(truth.raw.as_slice()) {
                            found = true;
                            break;
                        }
                        seen.push(format!(
                            "#{} {:?} raw={:?}",
                            msg.id,
                            serde_json::to_string(&msg).unwrap_or_default(),
                            bytes.map(|b| b.len())
                        ));
                    }
                    if !found {
                        self.trace.push(format!(
                            "  diag: {} search hits for {token} (truth {} bytes): {}",
                            list.total,
                            truth.raw.len(),
                            seen.join("; ")
                        ));
                        let (audit_status, audit) = self
                            .call(&api, Method::GET, "/audit?limit=2000", None::<&()>)
                            .await?;
                        self.trace.push(format!(
                            "  diag: audit {audit_status}, {} entries",
                            audit.as_array().map_or(0, |a| a.len())
                        ));
                        // Where is it still listed? Every manifest on every destination of the user.
                        let uid = self.users[u].id.clone().unwrap_or_default();
                        if let Some(k) = self.state().keyring.get(&uid) {
                            let ctx = malo_server::jobs::job_ctx(
                                self.state(),
                                &k,
                                "diag",
                                tokio_util::sync::CancellationToken::new(),
                            );
                            for store in ctx.stores().unwrap_or_default() {
                                match store.scan().await {
                                    Ok(scan) => {
                                        let markers: Vec<_> = scan
                                            .markers
                                            .iter()
                                            .map(|(d, m)| {
                                                (d.clone(), m.account_id.clone(), m.generation)
                                            })
                                            .collect();
                                        let hits: Vec<_> = scan
                                            .entries
                                            .iter()
                                            .filter(|(_, e)| e.envelope.subject.starts_with(&token))
                                            .map(|(d, e)| {
                                                (
                                                    d.clone(),
                                                    e.mailbox.clone(),
                                                    e.uid,
                                                    e.object_path.clone(),
                                                )
                                            })
                                            .collect();
                                        self.trace.push(format!(
                                            "  diag: destination {} markers {markers:?}; manifest lines for {token}: {hits:?}",
                                            store.dest.name
                                        ));
                                    }
                                    Err(e) => self.trace.push(format!(
                                        "  diag: destination {} unreadable: {e:#}",
                                        store.dest.name
                                    )),
                                }
                            }
                        }
                        for e in
                            serde_json::from_value::<Vec<AuditEntry>>(audit).unwrap_or_default()
                        {
                            let hit = e.detail.to_string().contains(&token);
                            if hit && e.kind == "purged" {
                                let uid = self.users[u].id.clone().unwrap_or_default();
                                let id = e
                                    .detail
                                    .get("message")
                                    .and_then(|m| m.as_i64())
                                    .unwrap_or(-1);
                                if let Some(k) = self.state().keyring.get(&uid) {
                                    let row = k.index.message(id).ok().flatten();
                                    self.trace.push(format!(
                                        "  diag: purged row {id}: {:?}; memberships {:?}; replicas {:?}",
                                        row.map(|r| (r.account, r.state, r.sha256, r.envelope.subject)),
                                        k.index.memberships(id).unwrap_or_default().iter().map(|m| (m.mailbox, m.uid, m.deleted_on_server)).collect::<Vec<_>>(),
                                        k.index.replicas_of(id).unwrap_or_default().iter().map(|r| (r.destination.clone(), format!("{:?}", r.status))).collect::<Vec<_>>()
                                    ));
                                }
                            }
                            if hit
                                || e.kind.starts_with("account")
                                || e.kind.starts_with("destination")
                                || e.kind.contains("rebuil")
                            {
                                self.trace.push(format!(
                                    "  diag: audit {} {:?} {:?} {}",
                                    e.at, e.kind, e.account_id, e.detail
                                ));
                            }
                        }
                        self.trace.push(format!(
                            "  diag: current accounts {:?}",
                            self.users[u]
                                .accounts
                                .iter()
                                .map(|a| (a.id.clone(), a.name.clone()))
                                .collect::<Vec<_>>()
                        ));
                        return Err(violation(
                            "mail_lost",
                            format!(
                                "user {u} purged {token} from mailbox {m} but can't give it back"
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

async fn raw_bytes(api: &Api, id: i64) -> Option<Vec<u8>> {
    let tls = (*malo_core::tls::pinned_config(&api.fingerprint)).clone();
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .ok()?;
    let r = http
        .get(format!("{}/messages/{id}/raw", api.base))
        .bearer_auth(api.token.as_ref()?)
        .send()
        .await
        .ok()?;
    if !r.status().is_success() {
        return None;
    }
    Some(r.bytes().await.ok()?.to_vec())
}

// ───────────────────────────── runner, shrinking, replay ─────────────────────────────

#[derive(Serialize, Deserialize)]
struct Failure {
    seed: u64,
    violation: Violation,
    ops: Vec<Op>,
    trace: Vec<String>,
}

/// Fault injection is process-wide: runs never overlap.
static RUN_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn run(seed: u64, ops: &[Op], verbose: bool) -> (Option<Violation>, Vec<String>) {
    Box::pin(run_inner(seed, ops, verbose)).await
}

async fn run_inner(seed: u64, ops: &[Op], verbose: bool) -> (Option<Violation>, Vec<String>) {
    let _guard = RUN_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    faults::reset(seed);
    toxi_reset().await;
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("nas");
    std::fs::create_dir_all(&mount).unwrap();
    let server = start(dir.path(), &mount).await;
    let api = bootstrap(&server).await;
    let tag = format!(
        "{seed:x}{}",
        &uuid::Uuid::new_v4().simple().to_string()[..6]
    );
    let canary = dir.path().join("outside");
    std::fs::create_dir_all(&canary).unwrap();
    let mut world = World {
        mount,
        canary,
        s3_prefix: format!("fuzz-{tag}"),
        api: Api {
            token: None,
            ..api.clone()
        },
        admin: Some(api),
        server: Some(server),
        users: (0..USERS)
            .map(|i| UserModel {
                name: format!("fz{tag}u{i}"),
                password: format!("fz{tag}u{i}-password"),
                ..Default::default()
            })
            .collect(),
        mail: (0..MAILBOXES)
            .map(|i| MailModel {
                imap_user: format!("fz{tag}m{i}"),
                messages: BTreeMap::new(),
            })
            .collect(),
        deleted_snapshots: HashMap::new(),
        trace: vec![],
        outage_until: None,
        last_fault: None,
        shared_damage: false,
        msg_counter: 0,
        disk_faults_until: None,
        read_only: vec![],
        indexes_lost: 0,
        purge_log: HashMap::new(),
        dir,
    };
    let mut result = None;
    for (i, op) in ops.iter().enumerate() {
        world.trace.push(format!("{i:3}: {op:?}"));
        if verbose {
            eprintln!("[fuzz {seed}] {i:3}: {op:?}");
        }
        let step = tokio::time::timeout(Duration::from_secs(240), async {
            Box::pin(world.exec(op))
                .await
                .and(Box::pin(world.check()).await)
        })
        .await;
        let outcome = match step {
            Ok(r) => r,
            Err(_) => Err(violation(
                "step_timeout",
                format!(
                    "a step took longer than 240 s (deadlock?); jobs active {}, free IMAP slots {:?}",
                    world.state().jobs.active(),
                    malo_core::imap::host_slots_free("localhost"),
                ),
            )),
        };
        if let Err(mut v) = outcome {
            v.step = i;
            result = Some(v);
            break;
        }
        // Keep the user ids in the model up to date (registered users).
        for u in 0..USERS {
            if world.users[u].id.is_none() && !world.users[u].deleted {
                if let Ok(Some(row)) = world.state().db.user_by_name(&world.users[u].name.clone()) {
                    world.users[u].id = Some(row.id);
                }
            }
        }
    }
    if result.is_none() {
        world.trace.push("final check".into());
        if let Err(mut v) = tokio::time::timeout(Duration::from_secs(600), world.final_check())
            .await
            .unwrap_or_else(|_| {
                Err(violation(
                    "step_timeout",
                    "final check took longer than 600 s",
                ))
            })
        {
            v.step = ops.len();
            result = Some(v);
        }
    }
    compose(&["unpause", "rustfs"]);
    faults::clear();
    toxi_reset().await;
    for d in std::mem::take(&mut world.read_only) {
        set_read_only(&d, false);
    }
    let mut purged = 0;
    let mut jobs = 0;
    if let Some(server) = world.server.as_ref() {
        for u in &world.users {
            if let Some(id) = &u.id {
                let all = server.state.db.jobs(id, 10_000).unwrap_or_default();
                jobs += all.len();
                purged += all
                    .iter()
                    .filter(|j| matches!(j.kind, JobKind::Purge { .. }))
                    .filter_map(|j| j.result.as_ref()?.get("deleted")?.as_u64())
                    .sum::<u64>();
            }
        }
    }
    world.trace.push(format!(
        "summary: {} users registered ({} deleted), {} accounts, {} messages created, {} purged by Malo, {} jobs, {} I/O faults injected, {} indexes lost",
        world.users.iter().filter(|u| u.id.is_some()).count(),
        world.users.iter().filter(|u| u.deleted).count(),
        world.users.iter().map(|u| u.ever_accounts.len()).sum::<usize>(),
        world.mail.iter().map(|m| m.messages.len()).sum::<usize>(),
        purged,
        jobs,
        faults::injected(),
        world.indexes_lost,
    ));
    if let Some(server) = world.server.take() {
        server.shutdown(Duration::from_secs(20)).await;
    }
    (result, world.trace)
}

/// Delta debugging: drop chunks of operations while the same kind of violation still happens.
async fn shrink(
    seed: u64,
    mut ops: Vec<Op>,
    kind: &str,
    budget: usize,
) -> (Vec<Op>, Violation, Vec<String>) {
    let (mut best_v, mut best_trace) = run(seed, &ops, false).await;
    let mut attempts = 1;
    let mut chunk = (ops.len() / 2).max(1);
    while chunk >= 1 && attempts < budget {
        let mut i = 0;
        let mut progressed = false;
        while i < ops.len() && attempts < budget {
            let mut candidate = ops.clone();
            let end = (i + chunk).min(candidate.len());
            candidate.drain(i..end);
            attempts += 1;
            let (v, trace) = run(seed, &candidate, false).await;
            if v.as_ref().is_some_and(|v| v.kind == kind) {
                eprintln!("[fuzz {seed}] shrunk to {} ops", candidate.len());
                ops = candidate;
                best_v = v;
                best_trace = trace;
                progressed = true;
            } else {
                i += chunk;
            }
        }
        if !progressed {
            if chunk == 1 {
                break;
            }
            chunk /= 2;
        }
    }
    let v = best_v
        .unwrap_or_else(|| violation(kind, "did not reproduce while shrinking (timing-dependent)"));
    (ops, v, best_trace)
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fuzz_client_lifecycle_and_interference() {
    if !enabled() {
        return;
    }
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/fuzz-lifecycle");
    std::fs::create_dir_all(&out_dir).unwrap();
    if let Ok(file) = std::env::var("MALO_FUZZ_REPLAY") {
        let f: Failure = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let (v, trace) = run(f.seed, &f.ops, true).await;
        if let Some(v) = v {
            panic!("replay of {file} fails: {v:?}\n{}", trace.join("\n"));
        }
        eprintln!("replay of {file} passes now");
        return;
    }
    let runs = env_u64("MALO_FUZZ_RUNS", 3);
    let steps = env_u64("MALO_FUZZ_STEPS", 40) as usize;
    let first = env_u64("MALO_FUZZ_SEED", rand::random::<u32>() as u64);
    let budget = env_u64("MALO_FUZZ_SHRINK", 25) as usize;
    // MALO_FUZZ_KEEP_GOING=1: record each failure and continue with the next seed.
    let keep_going = env_u64("MALO_FUZZ_KEEP_GOING", 0) == 1;
    let mut failures = vec![];
    for seed in first..first + runs {
        let ops = gen_sequence(seed, steps);
        eprintln!("[fuzz] seed {seed}: {} operations", ops.len());
        let started = Instant::now();
        let (v, trace) = run(seed, &ops, false).await;
        let Some(v) = v else {
            let tail: Vec<_> = trace.iter().rev().take(2).rev().cloned().collect();
            eprintln!(
                "[fuzz] seed {seed}: ok ({:.0} s) — {}",
                started.elapsed().as_secs_f64(),
                tail.join(" | ")
            );
            continue;
        };
        eprintln!(
            "[fuzz] seed {seed}: VIOLATION {} at step {}: {}\n{}",
            v.kind,
            v.step,
            v.detail,
            trace.join("\n")
        );
        let failing: Vec<Op> = ops[..(v.step + 1).min(ops.len())].to_vec();
        let (small, v2, trace2) = shrink(seed, failing, &v.kind, budget).await;
        let file = out_dir.join(format!("failure-{seed}.json"));
        let f = Failure {
            seed,
            violation: v2.clone(),
            ops: small.clone(),
            trace: trace2.clone(),
        };
        std::fs::write(&file, serde_json::to_vec_pretty(&f).unwrap()).unwrap();
        if keep_going {
            eprintln!(
                "[fuzz] seed {seed}: FAILED {} — minimal sequence ({} ops) saved to {}",
                v2.kind,
                small.len(),
                file.display()
            );
            failures.push(format!("seed {seed}: {} — {}", v2.kind, v2.detail));
            continue;
        }
        panic!(
            "fuzz seed {seed}: {} — {}\nminimal sequence ({} ops), saved to {}:\n{}",
            v2.kind,
            v2.detail,
            small.len(),
            file.display(),
            trace2.join("\n")
        );
    }
    assert!(
        failures.is_empty(),
        "{} failing seed(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Fixed seeds that once found bugs; they run in CI on every change.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fuzz_regressions() {
    if !enabled() {
        return;
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fuzz-regressions");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in files
        .into_iter()
        .filter(|f| f.extension().is_some_and(|e| e == "json"))
    {
        let f: Failure = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let (v, trace) = run(f.seed, &f.ops, false).await;
        assert!(
            v.is_none(),
            "regression {} fails again: {v:?}\n{}",
            file.display(),
            trace.join("\n")
        );
    }
}

/// Seed 1000145, made deterministic: with the index failing, a rename either fails and changes
/// nothing, or succeeds — it must never report failure after committing (the account view read
/// purge status from the index after the commit).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_edit_under_index_faults_changes_nothing() {
    if !enabled() {
        return;
    }
    let _guard = RUN_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    faults::reset(1);
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("nas");
    std::fs::create_dir_all(&mount).unwrap();
    let server = start(dir.path(), &mount).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("idxfault")).await;
    let dest: DestinationView = api
        .post(
            "/destinations",
            &fs_dest("nas", mount.join("common").to_str().unwrap()),
        )
        .await;
    let acc: AccountView = api
        .post("/accounts", &imap_input("before", &uniq("idxm"), IMAP_PORT))
        .await;
    let policy = PurgePolicy {
        older_than_days: 0,
        required_destinations: vec![dest.id.clone()],
        exclude_mailboxes: vec![],
        exclude_flagged: false,
        schedule_hours: 0,
        armed: false,
        armed_at: None,
    };
    let acc: AccountView = api
        .put(&format!("/accounts/{}/policy", acc.id), &policy)
        .await;

    // Every index statement fails from now on.
    faults::add(faults::Rule {
        site: faults::Site::Index,
        fault: faults::Fault::NoSpace,
        per_mille: 1000,
        scope: None,
        remaining: None,
    });
    let mut input = imap_input("after", &acc.username, IMAP_PORT);
    input.revision = Some(acc.revision);
    let res: Result<AccountView, _> = api
        .call(Method::PUT, &format!("/accounts/{}", acc.id), Some(&input))
        .await;
    faults::clear();

    let now: Vec<AccountView> = api.get("/accounts").await;
    let name = &now.iter().find(|a| a.id == acc.id).unwrap().name;
    match res {
        Ok(v) => {
            assert_eq!(v.name, "after");
            assert_eq!(name, "after");
            // The unreadable purge status shows as blocked, never as clear.
            assert!(v.purge_blocked.is_some(), "{v:?}");
        }
        Err(e) => assert_eq!(name, "before", "rename reported {e:?} but was applied"),
    }
    server.shutdown(Duration::from_secs(5)).await;
}

/// Seed 1000168, made deterministic: an account deletion whose config write fails must keep the
/// account whole — including the records of mail already purged from the server, which no backup
/// can bring back. (The index rows used to be deleted before the config commit.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_account_delete_keeps_purged_mail_records() {
    if !enabled() {
        return;
    }
    let _guard = RUN_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    faults::reset(1);
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("nas");
    std::fs::create_dir_all(&mount).unwrap();
    let server = start(dir.path(), &mount).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("delfault")).await;
    let acc: AccountView = api
        .post("/accounts", &imap_input("acc", &uniq("delm"), IMAP_PORT))
        .await;
    // A message Malo backed up and then purged from the server: only the index knows it.
    let me: Me = api.get("/me").await;
    let user = server.state.keyring.get(&me.id).unwrap();
    let env = malo_core::index::empty_envelope();
    let msg = user
        .index
        .insert_message(&malo_core::index::NewMessage {
            account: &acc.id,
            run: None,
            size: 1,
            internaldate: None,
            message_id_hdr: None,
            gm_msgid: None,
            envelope: &env,
            state: MessageState::Verified,
            sha256: Some(&"0".repeat(64)),
        })
        .unwrap();

    faults::add(faults::Rule {
        site: faults::Site::ConfigWrite,
        fault: faults::Fault::NoSpace,
        per_mille: 1000,
        scope: None,
        remaining: None,
    });
    let res: Result<(), _> = api
        .call(
            Method::DELETE,
            &format!("/accounts/{}", acc.id),
            None::<&()>,
        )
        .await;
    faults::clear();
    assert!(res.is_err(), "config write was failing: {res:?}");
    let accounts: Vec<AccountView> = api.get("/accounts").await;
    assert!(accounts.iter().any(|a| a.id == acc.id));
    assert!(
        user.index.message(msg).unwrap().is_some(),
        "failed delete erased the record of purged mail"
    );

    // A successful delete whose index cleanup fails: the leftovers go at the next unlock.
    faults::add(faults::Rule {
        site: faults::Site::Index,
        fault: faults::Fault::Error,
        per_mille: 1000,
        scope: None,
        remaining: None,
    });
    let res: Result<(), _> = api
        .call(
            Method::DELETE,
            &format!("/accounts/{}", acc.id),
            None::<&()>,
        )
        .await;
    faults::clear();
    assert!(res.is_ok(), "{res:?}");
    assert!(user.index.message(msg).unwrap().is_some());
    drop(user);
    server.state.keyring.lock(&me.id);
    let api = api
        .login(&me.username, &format!("{}-password", me.username))
        .await;
    let _: Me = api.get("/me").await;
    let user = server.state.keyring.get(&me.id).unwrap();
    assert!(user.index.message(msg).unwrap().is_none());
    server.shutdown(Duration::from_secs(5)).await;
}

/// Seed 1000356, made deterministic: a purge must never delete mail from the server without a
/// record of it. With every audit write failing, the purge has to stop before deleting anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purge_never_deletes_without_a_record() {
    if !enabled() {
        return;
    }
    let _guard = RUN_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    faults::reset(1);
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("nas");
    std::fs::create_dir_all(&mount).unwrap();
    let server = start(dir.path(), &mount).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("purgerec")).await;
    let dest: DestinationView = api
        .post(
            "/destinations",
            &fs_dest("nas", mount.join("common").to_str().unwrap()),
        )
        .await;
    let imap_user = uniq("purgem");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    append(&mut c, "INBOX", None, None, &mail("purge-record", 0)).await;
    let acc: AccountView = api
        .post("/accounts", &imap_input("acc", &imap_user, IMAP_PORT))
        .await;
    let backup = api
        .run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
        .await;
    assert_eq!(backup.state, JobState::Done, "{backup:?}");
    let policy = PurgePolicy {
        older_than_days: 0,
        required_destinations: vec![dest.id.clone()],
        exclude_mailboxes: vec![],
        exclude_flagged: false,
        schedule_hours: 0,
        armed: false,
        armed_at: None,
    };
    let _: AccountView = api
        .put(&format!("/accounts/{}/policy", acc.id), &policy)
        .await;
    api.run_job(JobKind::PurgeDryRun {
        account_id: acc.id.clone(),
    })
    .await;
    let _: AccountView = api
        .post(
            &format!("/accounts/{}/policy/arm", acc.id),
            &ArmRequest {
                confirm_name: "acc".into(),
            },
        )
        .await;

    faults::add(faults::Rule {
        site: faults::Site::Index,
        fault: faults::Fault::NoSpace,
        per_mille: 1000,
        scope: Some("audit".into()),
        remaining: None,
    });
    api.run_job(JobKind::Purge {
        account_id: acc.id.clone(),
    })
    .await;
    faults::clear();

    c.select("INBOX").await.unwrap();
    assert_eq!(
        c.all_uids().await.unwrap().len(),
        1,
        "purge deleted mail although its record could not be written"
    );
    c.logout().await;

    // With the index healthy again, the purge goes through and leaves its record.
    let purge = api
        .run_job(JobKind::Purge {
            account_id: acc.id.clone(),
        })
        .await;
    assert_eq!(purge.state, JobState::Done, "{purge:?}");
    let audit: Vec<AuditEntry> = api.get("/audit?limit=100").await;
    assert!(audit.iter().any(|e| e.kind == "purged"));
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    c.select("INBOX").await.unwrap();
    assert!(c.all_uids().await.unwrap().is_empty());
    c.logout().await;
    server.shutdown(Duration::from_secs(5)).await;
}

/// Regression 15 under a different fault sequence: purged mail must stay recoverable by a rebuild
/// even when the destination's manifests lagged behind its objects (purge refreshes them first).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purged_mail_survives_account_removal_via_rebuild() {
    if !enabled() {
        return;
    }
    let _guard = RUN_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    faults::reset(1);
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("nas");
    std::fs::create_dir_all(&mount).unwrap();
    let server = start(dir.path(), &mount).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("purgereb")).await;
    let root = mount.join("common");
    let dest: DestinationView = api
        .post("/destinations", &fs_dest("nas", root.to_str().unwrap()))
        .await;
    let imap_user = uniq("purgerebm");
    let raw = mail("purge-rebuild", 0);
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    append(&mut c, "INBOX", None, None, &raw).await;
    c.logout().await;
    let acc: AccountView = api
        .post("/accounts", &imap_input("acc", &imap_user, IMAP_PORT))
        .await;
    let backup = api
        .run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
        .await;
    assert_eq!(backup.state, JobState::Done, "{backup:?}");

    let policy = PurgePolicy {
        older_than_days: 0,
        required_destinations: vec![dest.id.clone()],
        exclude_mailboxes: vec![],
        exclude_flagged: false,
        schedule_hours: 0,
        armed: false,
        armed_at: None,
    };
    let _: AccountView = api
        .put(&format!("/accounts/{}/policy", acc.id), &policy)
        .await;
    api.run_job(JobKind::PurgeDryRun {
        account_id: acc.id.clone(),
    })
    .await;
    let _: AccountView = api
        .post(
            &format!("/accounts/{}/policy/arm", acc.id),
            &ArmRequest {
                confirm_name: "acc".into(),
            },
        )
        .await;
    // The manifests lag behind (here: lost) while the objects are intact.
    fn manifests(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                manifests(&p, out);
            } else if p.to_string_lossy().contains(".jsonl") {
                out.push(p);
            }
        }
    }
    let mut files = vec![];
    manifests(&mount, &mut files);
    assert!(!files.is_empty());
    for f in &files {
        std::fs::remove_file(f).unwrap();
    }

    let purge = api
        .run_job(JobKind::Purge {
            account_id: acc.id.clone(),
        })
        .await;
    assert_eq!(purge.state, JobState::Done, "{purge:?}");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    c.select("INBOX").await.unwrap();
    assert!(c.all_uids().await.unwrap().is_empty(), "purge removed it");
    c.logout().await;

    // The account is removed; a rebuild from the destination must bring the purged mail back.
    let _: () = api
        .call(
            Method::DELETE,
            &format!("/accounts/{}", acc.id),
            None::<&()>,
        )
        .await
        .unwrap();
    let rebuild = api
        .run_job(JobKind::RebuildIndex {
            destination_id: dest.id.clone(),
        })
        .await;
    assert_eq!(rebuild.state, JobState::Done, "{rebuild:?}");
    let list: MessageList = api.get("/messages?q=purge-rebuild&limit=10").await;
    assert_eq!(
        list.total, 1,
        "purged mail not recoverable after account removal"
    );
    assert_eq!(
        api.bytes(&format!("/messages/{}/raw", list.messages[0].id))
            .await,
        raw
    );
    server.shutdown(Duration::from_secs(5)).await;
}
