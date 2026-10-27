//! Per-user index in SQLCipher (`users/<id>/index.db`).

use std::path::Path;
use std::sync::{Mutex, MutexGuard, TryLockError};

use chrono::{DateTime, Utc};
use malo_api::{AuditEntry, CheckReport, Envelope, MailboxInfo, MessageState, MessageSummary};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::crypto::Key;

/// Locks a SQLite connection shared by async tasks. Uncontended, it's a plain lock. When another
/// task holds it (a backup busy in the index), the wait happens with this runtime worker handed
/// off: otherwise every request queued on the lock pins a worker, and once all are pinned the
/// server can't even finish TLS handshakes.
pub fn lock_db<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.try_lock() {
        Ok(g) => g,
        Err(TryLockError::Poisoned(e)) => e.into_inner(),
        Err(TryLockError::WouldBlock) => {
            let wait = || m.lock().unwrap_or_else(|e| e.into_inner());
            let multi_thread = tokio::runtime::Handle::try_current()
                .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
            if multi_thread {
                tokio::task::block_in_place(wait)
            } else {
                wait()
            }
        }
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL,
    name TEXT NOT NULL,
    display TEXT NOT NULL,
    path TEXT NOT NULL,
    delimiter TEXT,
    special_use TEXT,
    uidvalidity INTEGER NOT NULL,
    highest_uid INTEGER NOT NULL DEFAULT 0,
    highestmodseq INTEGER,
    current INTEGER NOT NULL DEFAULT 1,
    last_seen_review TEXT,
    UNIQUE(account, name, uidvalidity)
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL,
    state TEXT NOT NULL,
    first_seen_run INTEGER,
    first_seen_at TEXT NOT NULL,
    reviewed INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT,
    size INTEGER NOT NULL DEFAULT 0,
    internaldate TEXT,
    message_id_hdr TEXT,
    gm_msgid TEXT,
    envelope TEXT NOT NULL,
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT
);
CREATE INDEX IF NOT EXISTS messages_account ON messages(account, state);
CREATE INDEX IF NOT EXISTS messages_date ON messages(internaldate);
CREATE UNIQUE INDEX IF NOT EXISTS messages_gm ON messages(account, gm_msgid) WHERE gm_msgid IS NOT NULL;
CREATE INDEX IF NOT EXISTS messages_sha ON messages(sha256);
CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY,
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    mailbox INTEGER NOT NULL REFERENCES mailboxes(id),
    uid INTEGER NOT NULL,
    flags TEXT NOT NULL DEFAULT '',
    gm_labels TEXT NOT NULL DEFAULT '',
    deleted_on_server_at TEXT,
    purged INTEGER NOT NULL DEFAULT 0,
    UNIQUE(mailbox, uid)
);
CREATE INDEX IF NOT EXISTS memberships_message ON memberships(message);
CREATE TABLE IF NOT EXISTS replicas (
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,
    object_path TEXT NOT NULL,
    encrypted INTEGER NOT NULL,
    stored_size INTEGER NOT NULL DEFAULT 0,
    written_at TEXT,
    verified_at TEXT,
    last_check_at TEXT,
    last_deep_at TEXT,
    status TEXT NOT NULL,
    PRIMARY KEY(message, destination)
);
CREATE INDEX IF NOT EXISTS replicas_dest ON replicas(destination, object_path);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    job_id TEXT,
    kind TEXT NOT NULL,
    account TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    stats TEXT
);
CREATE TABLE IF NOT EXISTS check_reports (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    deep INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS destination_status (
    destination TEXT PRIMARY KEY,
    failing INTEGER NOT NULL,
    reason TEXT,
    updated_at TEXT NOT NULL,
    deep_slice INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    account TEXT,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS imap_mailboxes (
    account TEXT NOT NULL,
    name TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uidnext INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(account, name)
);
CREATE TABLE IF NOT EXISTS imap_uids (
    account TEXT NOT NULL,
    mailbox TEXT NOT NULL,
    uid INTEGER NOT NULL,
    membership INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
    flags TEXT,
    hidden INTEGER NOT NULL DEFAULT 0,
    moved INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(account, mailbox, uid),
    UNIQUE(account, mailbox, membership)
);
CREATE INDEX IF NOT EXISTS imap_uids_membership ON imap_uids(membership);
CREATE TABLE IF NOT EXISTS imap_meta (
    sha256 TEXT PRIMARY KEY,
    header BLOB NOT NULL,
    envelope BLOB NOT NULL,
    bodystructure BLOB NOT NULL,
    body BLOB NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(
    subject, sender, recipients, attachments, body,
    tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS search_forget AFTER DELETE ON messages BEGIN
    DELETE FROM search WHERE rowid = old.id;
END;
CREATE TABLE IF NOT EXISTS drafts (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL,
    message TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tombstones (
    account TEXT NOT NULL,
    mailbox TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    deleted_at TEXT NOT NULL,
    PRIMARY KEY(account, mailbox, uidvalidity, uid, sha256)
);
"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaStatus {
    Pending,
    Written,
    Verified,
    Missing,
    Corrupt,
}

impl ReplicaStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReplicaStatus::Pending => "pending",
            ReplicaStatus::Written => "written",
            ReplicaStatus::Verified => "verified",
            ReplicaStatus::Missing => "missing",
            ReplicaStatus::Corrupt => "corrupt",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "written" => Self::Written,
            "verified" => Self::Verified,
            "missing" => Self::Missing,
            "corrupt" => Self::Corrupt,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MailboxRow {
    pub id: i64,
    pub account: String,
    pub name: String,
    pub display: String,
    pub path: String,
    pub delimiter: Option<String>,
    pub special_use: Option<String>,
    pub uidvalidity: u32,
    pub highest_uid: u32,
    pub highestmodseq: Option<u64>,
    pub current: bool,
}

#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: i64,
    pub account: String,
    pub state: MessageState,
    pub sha256: Option<String>,
    pub size: u64,
    pub internaldate: Option<DateTime<Utc>>,
    pub message_id_hdr: Option<String>,
    pub gm_msgid: Option<String>,
    pub envelope: Envelope,
    pub error: Option<String>,
    pub reviewed: bool,
    pub first_seen_at: DateTime<Utc>,
    pub attempts: u32,
    pub last_attempt_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct MembershipRow {
    pub id: i64,
    pub message: i64,
    pub mailbox: i64,
    pub uid: u32,
    pub flags: Vec<String>,
    pub gm_labels: Vec<String>,
    pub deleted_on_server: bool,
}

#[derive(Debug, Clone)]
pub struct ReplicaRow {
    pub message: i64,
    pub destination: String,
    pub object_path: String,
    pub encrypted: bool,
    pub stored_size: u64,
    pub status: ReplicaStatus,
    pub verified_at: Option<DateTime<Utc>>,
    pub sha256: Option<String>,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MessageQuery {
    pub account: Option<String>,
    pub mailbox: Option<i64>,
    pub new_only: bool,
    pub text: Option<String>,
    pub states: Vec<MessageState>,
    pub limit: u32,
    pub offset: u32,
    /// Only messages up to this id: a scrolling client pins its first page's newest id, so mail
    /// arriving meanwhile doesn't shift the offsets of the pages it loads later.
    pub max_id: Option<i64>,
    pub sort: MessageSort,
    /// Search column for words of `text` without one (see [`crate::search::COLUMNS`]).
    pub field: Option<String>,
    /// Gmail category (see [`crate::search::CATEGORIES`]); `primary` is mail in none of the others.
    pub category: Option<String>,
    /// Spam and Trash, apart from the rest of the mail (None: no such filter).
    pub folder: Option<MailFolder>,
}

/// Where a message belongs in the mail list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailFolder {
    /// Everything but spam and trash.
    Mail,
    Spam,
    Trash,
}

impl MailFolder {
    pub fn parse(s: &str) -> Option<MailFolder> {
        match s {
            "mail" => Some(MailFolder::Mail),
            "spam" => Some(MailFolder::Spam),
            "trash" => Some(MailFolder::Trash),
            _ => None,
        }
    }
}

/// Order of a message list. Ties (and messages without a date) fall back to discovery order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MessageSort {
    /// Most recently received first (the server's INTERNALDATE).
    #[default]
    Newest,
    Oldest,
    /// Sender name (or address) A–Z, case- and accent-insensitive.
    Sender,
    Largest,
    /// Best full-text match first (only with a search; otherwise newest first).
    Relevance,
}

impl MessageSort {
    pub fn parse(s: &str) -> MessageSort {
        match s {
            "oldest" => MessageSort::Oldest,
            "sender" => MessageSort::Sender,
            "largest" => MessageSort::Largest,
            "relevance" => MessageSort::Relevance,
            _ => MessageSort::Newest,
        }
    }

    fn order_by(self) -> &'static str {
        match self {
            MessageSort::Newest | MessageSort::Relevance => "g.internaldate IS NULL, g.internaldate DESC, g.id DESC",
            MessageSort::Oldest => "g.internaldate IS NULL, g.internaldate ASC, g.id ASC",
            MessageSort::Sender => {
                "malo_fold(coalesce(json_extract(g.envelope, '$.from_name'), json_extract(g.envelope, '$.from'), '')) ASC, g.id DESC"
            }
            MessageSort::Largest => "g.size DESC, g.id DESC",
        }
    }
}

pub struct NewMessage<'a> {
    pub account: &'a str,
    pub run: Option<i64>,
    pub size: u64,
    pub internaldate: Option<DateTime<Utc>>,
    pub message_id_hdr: Option<&'a str>,
    pub gm_msgid: Option<&'a str>,
    pub envelope: &'a Envelope,
    pub state: MessageState,
    pub sha256: Option<&'a str>,
}

pub struct Index {
    conn: Mutex<Connection>,
}

fn ts(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.with_timezone(&Utc))
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

/// Gmail labels used to be stored still escaped (`\\Inbox`), so INBOX, Sent, Drafts and
/// Starred were empty for mail apps. Repaired once.
fn unescape_stored_labels(conn: &Connection) -> anyhow::Result<()> {
    const DONE: &str = "labels_unescaped";
    if conn
        .query_row("SELECT 1 FROM kv WHERE k=?1", [DONE], |_| Ok(()))
        .optional()?
        .is_some()
    {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    let rows: Vec<(i64, String)> = tx
        .prepare("SELECT id, gm_labels FROM memberships WHERE instr(gm_labels, '\\')>0")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    {
        let mut update = tx.prepare("UPDATE memberships SET gm_labels=?2 WHERE id=?1")?;
        for (id, labels) in rows {
            let fixed: Vec<String> = split_list(labels.clone())
                .iter()
                .map(|l| crate::imap::unescape_quoted(l))
                .collect();
            let fixed = join_list(&fixed);
            if fixed != labels {
                update.execute(params![id, fixed])?;
            }
        }
    }
    tx.execute("INSERT INTO kv(k,v) VALUES(?1,'1')", [DONE])?;
    tx.commit()?;
    Ok(())
}

pub fn split_list(s: String) -> Vec<String> {
    if s.is_empty() {
        vec![]
    } else {
        s.split('\u{1f}').map(str::to_string).collect()
    }
}

pub fn join_list(v: &[String]) -> String {
    v.join("\u{1f}")
}

impl Index {
    /// Opens (or creates) an encrypted index. A wrong key fails here.
    pub fn open(path: &Path, key: &Key) -> anyhow::Result<Index> {
        let conn = Connection::open(path)?;
        Self::init(conn, Some(key))
    }

    pub fn open_in_memory() -> anyhow::Result<Index> {
        Self::init(Connection::open_in_memory()?, None)
    }

    fn init(conn: Connection, key: Option<&Key>) -> anyhow::Result<Index> {
        if let Some(key) = key {
            conn.execute_batch(&format!(
                "PRAGMA key = \"x'{}'\";",
                hex::encode(key.as_ref())
            ))?;
        }
        conn.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;",
        )?;
        conn.execute_batch(SCHEMA)?;
        // Older indexes: add columns introduced later (ignored when already present).
        let _ = conn.execute_batch("ALTER TABLE messages ADD COLUMN last_attempt_at TEXT");
        // Gmail category (social, promotions, updates, forums); NULL is Primary or not Gmail.
        let _ = conn.execute_batch("ALTER TABLE messages ADD COLUMN category TEXT");
        let _ =
            conn.execute_batch("ALTER TABLE imap_uids ADD COLUMN moved INTEGER NOT NULL DEFAULT 0");
        // The content hash whose text is in `search` (see crate::search).
        let _ = conn.execute_batch("ALTER TABLE messages ADD COLUMN indexed_sha TEXT");
        // Conversation key, set with the search text. Messages indexed before it existed are
        // indexed again (the search-index job) to get one.
        if conn
            .execute_batch("ALTER TABLE messages ADD COLUMN thread TEXT")
            .is_ok()
        {
            conn.execute_batch("UPDATE messages SET indexed_sha=NULL")?;
        }
        // Spam as marked in Malo: 1 spam, 0 not spam, NULL as the mail server files it (Junk).
        let _ = conn.execute_batch("ALTER TABLE messages ADD COLUMN spam INTEGER");
        // Until when the object is known to be locked (Object Lock), extended by checks.
        let _ = conn.execute_batch("ALTER TABLE replicas ADD COLUMN locked_until TEXT");
        unescape_stored_labels(&conn)?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS messages_thread ON messages(account, thread) WHERE thread IS NOT NULL",
        )?;
        conn.create_scalar_function(
            "malo_fold",
            1,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| Ok(fold(&ctx.get::<String>(0)?)),
        )?;
        conn.create_scalar_function(
            "malo_contains",
            2,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                Ok(crate::search::contains(
                    &fold(&ctx.get::<String>(0)?),
                    &ctx.get::<String>(1)?,
                ))
            },
        )?;
        Ok(Index {
            conn: Mutex::new(conn),
        })
    }

    pub fn with<R>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<R>) -> anyhow::Result<R> {
        if let Some(fault) = crate::faults::pick(crate::faults::Site::Index, "") {
            anyhow::bail!("index: {}", crate::faults::io_error(fault));
        }
        let conn = lock_db(&self.conn);
        Ok(f(&conn)?)
    }

    // ───── kv ─────

    pub fn kv_get(&self, k: &str) -> anyhow::Result<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT v FROM kv WHERE k=?1", [k], |r| r.get(0))
                .optional()
        })
    }

    pub fn kv_delete(&self, k: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM kv WHERE k=?1", [k]))?;
        Ok(())
    }

    /// Atomically raises a counter to at least `at_least` and then by `step`; returns the result.
    pub fn kv_bump(&self, k: &str, at_least: u64, step: u64) -> anyhow::Result<u64> {
        self.with(|c| {
            let cur: Option<String> = c
                .query_row("SELECT v FROM kv WHERE k=?1", [k], |r| r.get(0))
                .optional()?;
            let cur = cur.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            let next = cur.max(at_least) + step;
            c.execute(
                "INSERT INTO kv(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=?2",
                params![k, next.to_string()],
            )?;
            Ok(next)
        })
    }

    pub fn kv_set(&self, k: &str, v: &str) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO kv(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=?2",
                [k, v],
            )
        })?;
        Ok(())
    }

    // ───── mailboxes ─────

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_mailbox(
        &self,
        account: &str,
        name: &str,
        display: &str,
        path: &str,
        delimiter: Option<&str>,
        special_use: Option<&str>,
        uidvalidity: u32,
    ) -> anyhow::Result<MailboxRow> {
        self.with(|c| {
            // A changed UIDVALIDITY creates a new row; old rows (and their records) are kept but not current.
            // Their UIDs are void on the server, so messages there are gone from it: unstored ones
            // then get stored from the spool or another replica instead of waiting forever.
            c.execute(
                "UPDATE memberships SET deleted_on_server_at=?4
                 WHERE deleted_on_server_at IS NULL AND mailbox IN
                   (SELECT id FROM mailboxes WHERE account=?1 AND name=?2 AND uidvalidity<>?3)",
                params![account, name, uidvalidity, now()],
            )?;
            c.execute(
                "UPDATE mailboxes SET current=0 WHERE account=?1 AND name=?2 AND uidvalidity<>?3",
                params![account, name, uidvalidity],
            )?;
            c.execute(
                "INSERT INTO mailboxes(account,name,display,path,delimiter,special_use,uidvalidity,current)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,1)
                 ON CONFLICT(account,name,uidvalidity) DO UPDATE SET display=?3, path=?4, delimiter=?5, special_use=?6, current=1",
                params![account, name, display, path, delimiter, special_use, uidvalidity],
            )?;
            c.query_row(
                &format!("{MAILBOX_SELECT} WHERE account=?1 AND name=?2 AND uidvalidity=?3"),
                params![account, name, uidvalidity],
                mailbox_row,
            )
        })
    }

    pub fn mark_mailboxes_not_current(&self, account: &str, keep: &[String]) -> anyhow::Result<()> {
        self.with(|c| {
            let mut stmt =
                c.prepare("SELECT id, name FROM mailboxes WHERE account=?1 AND current=1")?;
            let rows: Vec<(i64, String)> = stmt
                .query_map([account], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            for (id, name) in rows {
                if !keep.contains(&name) {
                    c.execute("UPDATE mailboxes SET current=0 WHERE id=?1", [id])?;
                }
            }
            Ok(())
        })
    }

    pub fn mailbox(&self, id: i64) -> anyhow::Result<Option<MailboxRow>> {
        self.with(|c| {
            c.query_row(&format!("{MAILBOX_SELECT} WHERE id=?1"), [id], mailbox_row)
                .optional()
        })
    }

    pub fn mailboxes(
        &self,
        account: Option<&str>,
        current_only: bool,
    ) -> anyhow::Result<Vec<MailboxRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "{MAILBOX_SELECT} WHERE (?1 IS NULL OR account=?1) AND (?2=0 OR current=1) ORDER BY account, name"
            ))?;
            let rows = stmt.query_map(params![account, current_only as i32], mailbox_row)?.collect();
            rows
        })
    }

    pub fn set_mailbox_sync(
        &self,
        id: i64,
        highest_uid: u32,
        modseq: Option<u64>,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE mailboxes SET highest_uid=MAX(highest_uid, ?2), highestmodseq=?3 WHERE id=?1",
                params![id, highest_uid, modseq.map(|m| m as i64)],
            )
        })?;
        Ok(())
    }

    pub fn mailbox_infos(&self, account: Option<&str>) -> anyhow::Result<Vec<MailboxInfo>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT mb.account, mb.name, mb.display, mb.special_use, mb.uidvalidity,
                    (SELECT COUNT(*) FROM memberships m WHERE m.mailbox=mb.id),
                    (SELECT COUNT(*) FROM memberships m JOIN messages g ON g.id=m.message WHERE m.mailbox=mb.id AND g.reviewed=0)
                 FROM mailboxes mb WHERE (?1 IS NULL OR mb.account=?1) AND mb.current=1 ORDER BY mb.account, mb.display",
            )?;
            let rows = stmt.query_map(params![account], |r| {
                Ok(MailboxInfo {
                    account_id: r.get(0)?,
                    name: r.get(1)?,
                    display_name: r.get(2)?,
                    special_use: r.get(3)?,
                    uidvalidity: r.get(4)?,
                    message_count: r.get::<_, i64>(5)? as u64,
                    new_count: r.get::<_, i64>(6)? as u64,
                })
            })?
            .collect();
            rows
        })
    }

    // ───── messages ─────

    pub fn find_by_gm_msgid(&self, account: &str, gm: &str) -> anyhow::Result<Option<i64>> {
        self.with(|c| find_by_gm_msgid_on(c, account, gm))
    }

    pub fn find_membership(&self, mailbox: i64, uid: u32) -> anyhow::Result<Option<MembershipRow>> {
        self.with(|c| find_membership_on(c, mailbox, uid))
    }

    pub fn insert_message(&self, m: &NewMessage) -> anyhow::Result<i64> {
        self.with(|c| insert_message_on(c, m))
    }

    pub fn add_membership(
        &self,
        message: i64,
        mailbox: i64,
        uid: u32,
        flags: &[String],
        labels: &[String],
    ) -> anyhow::Result<()> {
        self.with(|c| add_membership_on(c, message, mailbox, uid, flags, labels))
    }

    /// Records a batch of messages found in one mailbox, in a single transaction: one commit
    /// instead of several per message, which on a first sync of a large mailbox is the
    /// difference between minutes of WAL writes and seconds. A Gmail message already known
    /// through another mailbox only gains the membership. Returns the newly added messages.
    pub fn record_discovered(
        &self,
        account: &str,
        mailbox: i64,
        run: i64,
        found: &[crate::imap::Discovered],
        destinations: u32,
    ) -> anyhow::Result<Vec<MessageSummary>> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let mut added = Vec::new();
            for d in found {
                if find_membership_on(&tx, mailbox, d.uid)?.is_some() {
                    continue;
                }
                let gm = d.gm_msgid.map(|g| g.to_string());
                let existing = match gm.as_deref() {
                    Some(g) => find_by_gm_msgid_on(&tx, account, g)?,
                    None => None,
                };
                if let Some(existing) = existing {
                    add_membership_on(&tx, existing, mailbox, d.uid, &d.flags, &d.gm_labels)?;
                    update_labels_on(&tx, existing, &d.gm_labels)?;
                    continue;
                }
                let id = insert_message_on(
                    &tx,
                    &NewMessage {
                        account,
                        run: Some(run),
                        size: d.size as u64,
                        internaldate: d.internaldate,
                        message_id_hdr: d.envelope.message_id.as_deref(),
                        gm_msgid: gm.as_deref(),
                        envelope: &d.envelope,
                        state: MessageState::Discovered,
                        sha256: None,
                    },
                )?;
                add_membership_on(&tx, id, mailbox, d.uid, &d.flags, &d.gm_labels)?;
                let one = MessageQuery {
                    limit: 1,
                    ..Default::default()
                };
                added.extend(query_messages_on(&tx, &one, Some(id), destinations)?.1);
            }
            tx.commit()?;
            Ok(added)
        })
    }

    pub fn update_flags(
        &self,
        mailbox: i64,
        uid: u32,
        flags: &[String],
        labels: Option<&[String]>,
    ) -> anyhow::Result<()> {
        self.with(|c| match labels {
            Some(l) => c.execute(
                "UPDATE memberships SET flags=?3, gm_labels=?4 WHERE mailbox=?1 AND uid=?2",
                params![mailbox, uid, join_list(flags), join_list(l)],
            ),
            None => c.execute(
                "UPDATE memberships SET flags=?3 WHERE mailbox=?1 AND uid=?2",
                params![mailbox, uid, join_list(flags)],
            ),
        })?;
        Ok(())
    }

    /// Stores the Gmail categories of a mailbox's messages from UID `from_uid` on: the ones in
    /// `found`, and Primary (none) for the rest. Returns how many changed.
    pub fn set_categories(
        &self,
        mailbox: i64,
        from_uid: u32,
        found: &std::collections::HashMap<u32, &str>,
    ) -> anyhow::Result<u64> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let rows: Vec<(u32, i64, Option<String>)> = {
                let mut stmt = tx.prepare(
                    "SELECT m.uid, g.id, g.category FROM memberships m JOIN messages g ON g.id=m.message
                     WHERE m.mailbox=?1 AND m.uid>=?2 AND m.deleted_on_server_at IS NULL",
                )?;
                let rows = stmt
                    .query_map(params![mailbox, from_uid], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })?
                    .collect::<Result<_, _>>()?;
                rows
            };
            let mut changed = 0;
            {
                let mut update = tx.prepare("UPDATE messages SET category=?2 WHERE id=?1")?;
                for (uid, id, current) in rows {
                    let want = found.get(&uid).copied();
                    if want != current.as_deref() {
                        update.execute(params![id, want])?;
                        changed += 1;
                    }
                }
            }
            tx.commit()?;
            Ok(changed)
        })
    }

    pub fn update_labels_for_message(&self, message: i64, labels: &[String]) -> anyhow::Result<()> {
        self.with(|c| update_labels_on(c, message, labels))
    }

    /// UIDs of a mailbox that are still believed to exist on the server.
    pub fn live_uids(&self, mailbox: i64) -> anyhow::Result<Vec<u32>> {
        self.with(|c| {
            let mut stmt =
                c.prepare("SELECT uid FROM memberships WHERE mailbox=?1 AND deleted_on_server_at IS NULL ORDER BY uid")?;
            let rows = stmt.query_map([mailbox], |r| r.get(0))?.collect();
            rows
        })
    }

    pub fn mark_deleted_on_server(
        &self,
        mailbox: i64,
        uids: &[u32],
        purged: bool,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare(
                    "UPDATE memberships SET deleted_on_server_at=?3, purged=MAX(purged, ?4) WHERE mailbox=?1 AND uid=?2 AND deleted_on_server_at IS NULL",
                )?;
                let at = now();
                for uid in uids {
                    stmt.execute(params![mailbox, uid, at, purged as i32])?;
                }
            }
            tx.commit()
        })
    }

    pub fn set_state(
        &self,
        id: i64,
        state: MessageState,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE messages SET state=?2, error=?3,
                    attempts=attempts + (CASE WHEN ?3 IS NULL THEN 0 ELSE 1 END),
                    last_attempt_at=CASE WHEN ?3 IS NULL THEN last_attempt_at ELSE ?4 END
                 WHERE id=?1",
                params![id, state.as_str(), error, now()],
            )
        })?;
        Ok(())
    }

    pub fn set_content(
        &self,
        id: i64,
        sha256: &str,
        size: u64,
        envelope: Option<&Envelope>,
    ) -> anyhow::Result<()> {
        self.with(|c| match envelope {
            Some(e) => c.execute(
                "UPDATE messages SET sha256=?2, size=?3, envelope=?4 WHERE id=?1",
                params![id, sha256, size as i64, serde_json::to_string(e).unwrap()],
            ),
            None => c.execute(
                "UPDATE messages SET sha256=?2, size=?3 WHERE id=?1",
                params![id, sha256, size as i64],
            ),
        })?;
        Ok(())
    }

    pub fn message(&self, id: i64) -> anyhow::Result<Option<MessageRow>> {
        self.with(|c| {
            c.query_row(&format!("{MESSAGE_SELECT} WHERE id=?1"), [id], message_row)
                .optional()
        })
    }

    /// Messages of an account that still need work (resumable leftovers first).
    ///
    /// Messages that failed repeatedly are never given up on: after 5 failures they are retried
    /// with exponential backoff (30 min, doubling, at most daily), so a long storage outage heals
    /// by itself. `retry_all` (a manual "Back up now") ignores the backoff.
    pub fn pending_messages(
        &self,
        account: &str,
        retry_all: bool,
    ) -> anyhow::Result<Vec<MessageRow>> {
        let rows: Vec<MessageRow> = self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "{MESSAGE_SELECT} WHERE account=?1 AND state IN ('discovered','downloading','stored','error')
                 ORDER BY CASE state WHEN 'downloading' THEN 0 WHEN 'stored' THEN 1 WHEN 'discovered' THEN 2 ELSE 3 END, id"
            ))?;
            let rows = stmt.query_map([account], message_row)?.collect();
            rows
        })?;
        let now = Utc::now();
        Ok(rows
            .into_iter()
            .filter(|m| {
                retry_all
                    || m.attempts < 5
                    || m.last_attempt_at
                        .is_none_or(|t| now - t >= retry_backoff(m.attempts))
            })
            .collect())
    }

    pub fn memberships(&self, message: i64) -> anyhow::Result<Vec<MembershipRow>> {
        self.with(|c| {
            let mut stmt =
                c.prepare(&format!("{MEMBERSHIP_SELECT} WHERE message=?1 ORDER BY id"))?;
            let rows = stmt.query_map([message], membership_row)?.collect();
            rows
        })
    }

    /// Removes messages the user deleted from the backup: their rows, memberships and replicas.
    /// Each membership leaves a tombstone, so manifests on a destination that couldn't be
    /// rewritten yet don't bring the message back in a rebuild. Returns the stored objects that
    /// no remaining replica uses (encrypted objects are shared by identical messages), as
    /// (destination, object path).
    pub fn forget_messages(&self, ids: &[i64]) -> anyhow::Result<Vec<(String, String)>> {
        let now = Utc::now().to_rfc3339();
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let mut objects: Vec<(String, String)> = Vec::new();
            for id in ids {
                let sha: Option<Option<String>> = tx
                    .query_row("SELECT sha256 FROM messages WHERE id=?1", [id], |r| r.get(0))
                    .optional()?;
                let Some(sha) = sha else { continue };
                tx.execute(
                    "INSERT OR IGNORE INTO tombstones(account, mailbox, uidvalidity, uid, sha256, deleted_at)
                     SELECT g.account, mb.name, mb.uidvalidity, m.uid, ?2, ?3
                     FROM memberships m JOIN mailboxes mb ON mb.id=m.mailbox JOIN messages g ON g.id=m.message
                     WHERE m.message=?1",
                    params![id, sha.unwrap_or_default(), now],
                )?;
                {
                    let mut stmt =
                        tx.prepare("SELECT destination, object_path FROM replicas WHERE message=?1")?;
                    let rows = stmt.query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?;
                    for row in rows {
                        objects.push(row?);
                    }
                }
                tx.execute("DELETE FROM memberships WHERE message=?1", [id])?;
                tx.execute("DELETE FROM replicas WHERE message=?1", [id])?;
                tx.execute("DELETE FROM messages WHERE id=?1", [id])?;
            }
            tx.execute(IMAP_META_CLEANUP, [])?;
            objects.sort();
            objects.dedup();
            let mut unused = Vec::new();
            for (dest, path) in objects {
                let used: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM replicas WHERE destination=?1 AND object_path=?2)",
                    params![dest, path],
                    |r| r.get(0),
                )?;
                if !used {
                    unused.push((dest, path));
                }
            }
            tx.commit()?;
            Ok(unused)
        })
    }

    /// Whether a manifest line describes a message the user deleted from the backup.
    pub fn is_tombstoned(
        &self,
        account: &str,
        mailbox: &str,
        uidvalidity: u32,
        uid: u32,
        sha256: &str,
    ) -> anyhow::Result<bool> {
        self.with(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM tombstones WHERE account=?1 AND mailbox=?2 AND uidvalidity=?3 AND uid=?4 AND sha256=?5)",
                params![account, mailbox, uidvalidity, uid, sha256],
                |r| r.get(0),
            )
        })
    }

    /// Whether any replica on `destination` still uses `object_path`.
    pub fn object_in_use(&self, destination: &str, object_path: &str) -> anyhow::Result<bool> {
        self.with(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM replicas WHERE destination=?1 AND object_path=?2)",
                params![destination, object_path],
                |r| r.get(0),
            )
        })
    }

    pub fn messages_with_sha(&self, sha256: &str) -> anyhow::Result<Vec<i64>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT id FROM messages WHERE sha256=?1")?;
            let rows = stmt.query_map([sha256], |r| r.get(0))?.collect();
            rows
        })
    }

    /// The start of a message's indexed text, quoted lines and reply headers left out.
    fn preview(&self, id: i64) -> anyhow::Result<Option<String>> {
        let body: Option<String> = self.with(|c| {
            c.query_row("SELECT body FROM search WHERE rowid=?1", [id], |r| r.get(0))
                .optional()
        })?;
        Ok(body.and_then(|b| preview_text(&b)))
    }

    /// The messages of `id`'s conversation (itself when it has none), oldest first, each copy of
    /// a message (same Message-ID in several folders) once.
    pub fn thread(&self, id: i64, destinations: u32) -> anyhow::Result<Vec<MessageSummary>> {
        let ids: Vec<(i64, Option<String>)> = self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT t.id, t.message_id_hdr FROM messages g JOIN messages t
                   ON t.account=g.account AND (t.id=g.id OR (g.thread IS NOT NULL AND t.thread=g.thread))
                 WHERE g.id=?1
                 ORDER BY t.internaldate IS NULL, t.internaldate, t.id LIMIT 200",
            )?;
            let rows = stmt
                .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect();
            rows
        })?;
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for (tid, mid) in ids {
            // The opened message is always the copy shown.
            if let Some(m) = mid.filter(|_| tid != id) {
                if !seen.insert(m) {
                    continue;
                }
            }
            if let Some(mut s) = self.summary(tid, destinations)? {
                s.preview = self.preview(tid)?;
                out.push(s);
            }
        }
        // A copy seen before the opened one is dropped in favour of it.
        if let Some(own) = out
            .iter()
            .find(|s| s.id == id)
            .and_then(|s| s.envelope.message_id.clone())
        {
            out.retain(|s| s.id == id || s.envelope.message_id.as_deref() != Some(own.as_str()));
        }
        Ok(out)
    }

    pub fn summary(&self, id: i64, destinations: u32) -> anyhow::Result<Option<MessageSummary>> {
        Ok(self
            .query_messages(
                &MessageQuery {
                    limit: 1,
                    ..Default::default()
                },
                Some(id),
                destinations,
            )?
            .1
            .pop())
    }

    pub fn list_messages(
        &self,
        q: &MessageQuery,
        destinations: u32,
    ) -> anyhow::Result<(u64, Vec<MessageSummary>)> {
        self.query_messages(q, None, destinations)
    }

    /// Ids of every message a search finds (search box syntax), newest first, at most `cap`.
    pub fn matching_ids(
        &self,
        account: Option<&str>,
        text: &str,
        cap: usize,
    ) -> anyhow::Result<Vec<i64>> {
        let mut q = MessageQuery {
            account: account.map(str::to_string),
            text: Some(text.to_string()).filter(|t| !t.trim().is_empty()),
            limit: 1000,
            ..Default::default()
        };
        let mut out = Vec::new();
        loop {
            let (_, page) = self.list_messages(&q, 0)?;
            let n = page.len();
            out.extend(page.into_iter().map(|m| m.id));
            if n < 1000 || out.len() >= cap {
                break;
            }
            // Pinned to the first page, so mail arriving meanwhile doesn't shift the pages.
            if q.max_id.is_none() {
                q.max_id = out.iter().copied().max();
            }
            q.offset += 1000;
        }
        out.truncate(cap);
        Ok(out)
    }

    /// Ids of an account's messages, optionally only those in mailboxes of one name.
    pub fn account_message_ids(
        &self,
        account: &str,
        mailbox: Option<&str>,
    ) -> anyhow::Result<Vec<i64>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT g.id FROM messages g WHERE g.account=?1 AND (?2 IS NULL OR EXISTS(
                    SELECT 1 FROM memberships m JOIN mailboxes mb ON mb.id=m.mailbox
                    WHERE m.message=g.id AND mb.name=?2)) ORDER BY g.id",
            )?;
            let rows = stmt
                .query_map(params![account, mailbox], |r| r.get(0))?
                .collect();
            rows
        })
    }

    fn query_messages(
        &self,
        q: &MessageQuery,
        id: Option<i64>,
        destinations: u32,
    ) -> anyhow::Result<(u64, Vec<MessageSummary>)> {
        self.with(|c| query_messages_on(c, q, id, destinations))
    }

    pub fn mark_reviewed(
        &self,
        ids: &[i64],
        all_of_account: Option<Option<&str>>,
    ) -> anyhow::Result<u64> {
        self.with(|c| {
            if let Some(account) = all_of_account {
                return Ok(c.execute(
                    "UPDATE messages SET reviewed=1 WHERE reviewed=0 AND (?1 IS NULL OR account=?1)",
                    params![account],
                )? as u64);
            }
            let tx = c.unchecked_transaction()?;
            let mut n = 0;
            for id in ids {
                n += tx.execute("UPDATE messages SET reviewed=1 WHERE id=?1", [id])?;
            }
            tx.commit()?;
            Ok(n as u64)
        })
    }

    /// Marks the given messages reviewed, or new again when `reviewed` is false.
    pub fn set_reviewed(&self, ids: &[i64], reviewed: bool) -> anyhow::Result<u64> {
        if reviewed {
            return self.mark_reviewed(ids, None);
        }
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let mut n = 0;
            for id in ids {
                n += tx.execute("UPDATE messages SET reviewed=0 WHERE id=?1", [id])?;
            }
            tx.commit()?;
            Ok(n as u64)
        })
    }

    /// Marks messages as spam (or not spam); None goes back to how the mail server files them.
    pub fn set_spam(&self, ids: &[i64], spam: Option<bool>) -> anyhow::Result<u64> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let mut n = 0;
            for id in ids {
                n += tx.execute("UPDATE messages SET spam=?2 WHERE id=?1", params![id, spam])?;
            }
            tx.commit()?;
            Ok(n as u64)
        })
    }

    pub fn account_stats(&self, account: &str) -> anyhow::Result<(u64, u64)> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*), COALESCE(SUM(size),0) FROM messages WHERE account=?1 AND state='verified'",
                [account],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
            )
        })
    }

    pub fn delete_account(&self, account: &str) -> anyhow::Result<()> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            tx.execute("DELETE FROM memberships WHERE message IN (SELECT id FROM messages WHERE account=?1)", [account])?;
            tx.execute("DELETE FROM replicas WHERE message IN (SELECT id FROM messages WHERE account=?1)", [account])?;
            tx.execute("DELETE FROM messages WHERE account=?1", [account])?;
            tx.execute("DELETE FROM mailboxes WHERE account=?1", [account])?;
            tx.execute("DELETE FROM imap_mailboxes WHERE account=?1", [account])?;
            tx.execute("DELETE FROM drafts WHERE account=?1", [account])?;
            tx.execute(IMAP_META_CLEANUP, [])?;
            tx.commit()
        })
    }

    /// Drops the rows of accounts and destinations no longer in the config (left behind when the
    /// index cleanup of a deletion failed after its config commit). Returns how many went.
    pub fn prune_deleted(
        &self,
        accounts: &[String],
        destinations: &[String],
    ) -> anyhow::Result<usize> {
        let dests: Vec<String> = self.with(|c| {
            let mut stmt = c.prepare("SELECT DISTINCT destination FROM replicas")?;
            let rows = stmt.query_map([], |r| r.get(0))?.collect();
            rows
        })?;
        let mut pruned = 0;
        for d in dests.iter().filter(|d| !destinations.contains(d)) {
            self.delete_replicas_for_destination(d)?;
            pruned += 1;
        }
        Ok(pruned + self.prune_accounts(accounts)?)
    }

    fn prune_accounts(&self, keep: &[String]) -> anyhow::Result<usize> {
        let ids: Vec<String> = self.with(|c| {
            let mut stmt =
                c.prepare("SELECT account FROM messages UNION SELECT account FROM mailboxes")?;
            let rows = stmt.query_map([], |r| r.get(0))?.collect();
            rows
        })?;
        let mut pruned = 0;
        for id in ids.iter().filter(|id| !keep.contains(id)) {
            self.delete_account(id)?;
            pruned += 1;
        }
        Ok(pruned)
    }

    // ───── replicas ─────

    pub fn upsert_replica(
        &self,
        message: i64,
        destination: &str,
        object_path: &str,
        encrypted: bool,
        stored_size: u64,
        status: ReplicaStatus,
    ) -> anyhow::Result<()> {
        let n = now();
        let verified = (status == ReplicaStatus::Verified).then(|| n.clone());
        self.with(|c| {
            c.execute(
                "INSERT INTO replicas(message,destination,object_path,encrypted,stored_size,written_at,verified_at,last_check_at,status)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?6,?8)
                 ON CONFLICT(message,destination) DO UPDATE SET object_path=?3, encrypted=?4, stored_size=?5, written_at=?6,
                    verified_at=COALESCE(?7, verified_at), last_check_at=?6, status=?8",
                params![message, destination, object_path, encrypted, stored_size as i64, n, verified, status.as_str()],
            )
        })?;
        Ok(())
    }

    pub fn set_replica_status(
        &self,
        message: i64,
        destination: &str,
        status: ReplicaStatus,
        deep: bool,
    ) -> anyhow::Result<()> {
        let n = now();
        self.with(|c| {
            c.execute(
                "UPDATE replicas SET status=?3, last_check_at=?4,
                    verified_at=CASE WHEN ?3='verified' THEN ?4 ELSE verified_at END,
                    last_deep_at=CASE WHEN ?5 THEN ?4 ELSE last_deep_at END
                 WHERE message=?1 AND destination=?2",
                params![message, destination, status.as_str(), n, deep],
            )
        })?;
        Ok(())
    }

    pub fn replicas_of(&self, message: i64) -> anyhow::Result<Vec<ReplicaRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!("{REPLICA_SELECT} WHERE r.message=?1"))?;
            let rows = stmt.query_map([message], replica_row)?.collect();
            rows
        })
    }

    /// The replicas stored in one object of a destination.
    pub fn replicas_at(
        &self,
        destination: &str,
        object_path: &str,
    ) -> anyhow::Result<Vec<ReplicaRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "{REPLICA_SELECT} WHERE r.destination=?1 AND r.object_path=?2 ORDER BY r.message"
            ))?;
            let rows = stmt
                .query_map([destination, object_path], replica_row)?
                .collect();
            rows
        })
    }

    pub fn replicas_in(&self, destination: &str) -> anyhow::Result<Vec<ReplicaRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "{REPLICA_SELECT} WHERE r.destination=?1 ORDER BY r.message"
            ))?;
            let rows = stmt.query_map([destination], replica_row)?.collect();
            rows
        })
    }

    pub fn replica_stats(&self, destination: &str) -> anyhow::Result<(u64, u64)> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(DISTINCT object_path), COALESCE(SUM(stored_size),0) FROM replicas WHERE destination=?1 AND status='verified'",
                [destination],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
            )
        })
    }

    /// Moves every replica stored at `old_path` on a destination to `new_path` (a recompressed
    /// copy of the same content). Returns the messages moved.
    pub fn move_replica_object(
        &self,
        destination: &str,
        old_path: &str,
        new_path: &str,
        stored_size: u64,
    ) -> anyhow::Result<u64> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE replicas SET object_path=?3, stored_size=?4, locked_until=NULL
                 WHERE destination=?1 AND object_path=?2",
                params![destination, old_path, new_path, stored_size as i64],
            )
        })?;
        Ok(n as u64)
    }

    /// Verified objects on an encrypted destination that were stored without compression.
    pub fn uncompressed_objects(&self, destination: &str) -> anyhow::Result<Vec<String>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT DISTINCT object_path FROM replicas WHERE destination=?1 AND encrypted=1
                   AND status='verified' AND object_path NOT LIKE '%.z.enc' ORDER BY object_path",
            )?;
            let rows = stmt.query_map([destination], |r| r.get(0))?.collect();
            rows
        })
    }

    pub fn uncompressed_count(&self, destination: &str) -> anyhow::Result<u64> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(DISTINCT object_path) FROM replicas WHERE destination=?1 AND encrypted=1
                   AND status='verified' AND object_path NOT LIKE '%.z.enc'",
                [destination],
                |r| r.get::<_, i64>(0),
            )
        })
        .map(|n| n as u64)
    }

    /// Verified objects whose lock isn't known to hold until `until`.
    pub fn lock_due(&self, destination: &str, until: DateTime<Utc>) -> anyhow::Result<Vec<String>> {
        let until = until.to_rfc3339();
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT object_path FROM replicas WHERE destination=?1 AND status='verified'
                 GROUP BY object_path HAVING MIN(COALESCE(locked_until,'')) < ?2 ORDER BY object_path",
            )?;
            let rows = stmt.query_map(params![destination, until], |r| r.get(0))?.collect();
            rows
        })
    }

    pub fn set_locked_until(
        &self,
        destination: &str,
        object_path: &str,
        until: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE replicas SET locked_until=?3 WHERE destination=?1 AND object_path=?2",
                params![destination, object_path, until.to_rfc3339()],
            )
        })?;
        Ok(())
    }

    /// What each account takes up on each destination (verified replicas). Objects shared by
    /// several messages of an account count once.
    pub fn usage(&self) -> anyhow::Result<Vec<malo_api::UsageCell>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT account, destination, COUNT(*), SUM(size), SUM(stored) FROM (
                    SELECT g.account AS account, r.destination AS destination, r.object_path,
                           MAX(g.size) AS size, MAX(r.stored_size) AS stored
                    FROM replicas r JOIN messages g ON g.id=r.message
                    WHERE r.status='verified'
                    GROUP BY g.account, r.destination, r.object_path)
                 GROUP BY account, destination ORDER BY account, destination",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(malo_api::UsageCell {
                        account_id: r.get(0)?,
                        destination_id: r.get(1)?,
                        messages: r.get::<_, i64>(2)? as u64,
                        message_bytes: r.get::<_, i64>(3)? as u64,
                        stored_bytes: r.get::<_, i64>(4)? as u64,
                    })
                })?
                .collect();
            rows
        })
    }

    /// Bytes stored per destination and day, from when each object was written (verified
    /// replicas that are still there). Running totals, oldest first.
    pub fn usage_history(&self) -> anyhow::Result<Vec<malo_api::UsagePoint>> {
        let daily: Vec<(String, String, i64)> = self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT day, destination, SUM(stored) FROM (
                    SELECT r.destination AS destination, r.object_path,
                           MIN(substr(COALESCE(r.written_at, r.verified_at, ''), 1, 10)) AS day,
                           MAX(r.stored_size) AS stored
                    FROM replicas r JOIN messages g ON g.id=r.message
                    WHERE r.status='verified'
                    GROUP BY g.account, r.destination, r.object_path)
                 WHERE day <> '' GROUP BY day, destination ORDER BY day",
            )?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect();
            rows
        })?;
        let mut totals: std::collections::BTreeMap<String, u64> = Default::default();
        Ok(daily
            .into_iter()
            .map(|(date, destination_id, bytes)| {
                let t = totals.entry(destination_id.clone()).or_default();
                *t += bytes.max(0) as u64;
                malo_api::UsagePoint {
                    date,
                    destination_id,
                    stored_bytes: *t,
                }
            })
            .collect())
    }

    pub fn delete_replicas_for_destination(&self, destination: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM replicas WHERE destination=?1", [destination]))?;
        Ok(())
    }

    /// Re-evaluates a message's state from its replicas: verified when every destination is verified.
    ///
    /// Read and write happen under one lock: jobs refresh the same message concurrently (a backup
    /// verifying the last copy while a check works from an older read), and a split read/write
    /// could store a stale "stored" over a newer "verified" that nothing would correct.
    pub fn refresh_message_state(
        &self,
        message: i64,
        destinations: &[String],
    ) -> anyhow::Result<(MessageState, u32)> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!("{REPLICA_SELECT} WHERE r.message=?1"))?;
            let reps: Vec<ReplicaRow> = stmt
                .query_map([message], replica_row)?
                .collect::<rusqlite::Result<_>>()?;
            let verified = destinations
                .iter()
                .filter(|d| {
                    reps.iter()
                        .any(|r| &r.destination == *d && r.status == ReplicaStatus::Verified)
                })
                .count() as u32;
            let current = c
                .query_row("SELECT state FROM messages WHERE id=?1", [message], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .map(|s| MessageState::parse(&s))
                .unwrap_or(MessageState::Error);
            let state = if !destinations.is_empty() && verified as usize == destinations.len() {
                MessageState::Verified
            } else if verified > 0 || current == MessageState::Verified {
                MessageState::Stored
            } else {
                current
            };
            if state != current {
                c.execute(
                    "UPDATE messages SET state=?2, error=NULL, attempts=CASE WHEN ?2='verified' THEN 0 ELSE attempts END WHERE id=?1",
                    params![message, state.as_str()],
                )?;
            }
            Ok((state, verified))
        })
    }

    // ───── destination status (blocks purge) ─────

    pub fn set_destination_status(
        &self,
        destination: &str,
        failing: bool,
        reason: Option<&str>,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO destination_status(destination,failing,reason,updated_at) VALUES(?1,?2,?3,?4)
                 ON CONFLICT(destination) DO UPDATE SET failing=?2, reason=?3, updated_at=?4",
                params![destination, failing, reason, now()],
            )
        })?;
        Ok(())
    }

    pub fn destination_failing(&self, destination: &str) -> anyhow::Result<Option<String>> {
        self.with(|c| {
            c.query_row(
                "SELECT reason FROM destination_status WHERE destination=?1 AND failing=1",
                [destination],
                |r| {
                    Ok(r.get::<_, Option<String>>(0)?
                        .unwrap_or_else(|| "integrity check failed".into()))
                },
            )
            .optional()
        })
    }

    pub fn next_deep_slice(&self, destination: &str, slices: u32) -> anyhow::Result<u32> {
        self.with(|c| {
            let cur: Option<i64> = c
                .query_row("SELECT deep_slice FROM destination_status WHERE destination=?1", [destination], |r| r.get(0))
                .optional()?;
            let cur = cur.unwrap_or(0) as u32 % slices.max(1);
            c.execute(
                "INSERT INTO destination_status(destination,failing,updated_at,deep_slice) VALUES(?1,0,?2,?3)
                 ON CONFLICT(destination) DO UPDATE SET deep_slice=?3",
                params![destination, now(), (cur + 1) % slices.max(1)],
            )?;
            Ok(cur)
        })
    }

    // ───── runs / reports / audit ─────

    pub fn start_run(
        &self,
        job_id: &str,
        kind: &str,
        account: Option<&str>,
    ) -> anyhow::Result<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO runs(job_id,kind,account,started_at,status) VALUES(?1,?2,?3,?4,'running')",
                params![job_id, kind, account, now()],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    pub fn finish_run(
        &self,
        run: i64,
        status: &str,
        stats: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE runs SET finished_at=?2, status=?3, stats=?4 WHERE id=?1",
                params![run, now(), status, stats.to_string()],
            )
        })?;
        Ok(())
    }

    pub fn last_run(
        &self,
        kind: &str,
        account: &str,
    ) -> anyhow::Result<Option<(DateTime<Utc>, bool)>> {
        self.with(|c| {
            c.query_row(
                "SELECT finished_at, status FROM runs WHERE kind=?1 AND account=?2 AND finished_at IS NOT NULL ORDER BY id DESC LIMIT 1",
                [kind, account],
                |r| Ok((ts(r.get(0)?).unwrap_or_default(), r.get::<_, String>(1)? == "ok")),
            )
            .optional()
        })
    }

    pub fn save_report(&self, report: &CheckReport) -> anyhow::Result<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO check_reports(created_at,deep,ok,report) VALUES(?1,?2,?3,?4)",
                params![
                    report.created_at.to_rfc3339(),
                    report.deep,
                    report.ok,
                    serde_json::to_string(report).unwrap()
                ],
            )?;
            let id = c.last_insert_rowid();
            let mut r = report.clone();
            r.id = id;
            c.execute(
                "UPDATE check_reports SET report=?2 WHERE id=?1",
                params![id, serde_json::to_string(&r).unwrap()],
            )?;
            Ok(id)
        })
    }

    pub fn reports(&self, limit: u32) -> anyhow::Result<Vec<CheckReport>> {
        self.with(|c| {
            let mut stmt =
                c.prepare("SELECT report FROM check_reports ORDER BY id DESC LIMIT ?1")?;
            let rows: Vec<String> = stmt
                .query_map([limit], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            Ok(rows
                .into_iter()
                .filter_map(|s| serde_json::from_str(&s).ok())
                .collect())
        })
    }

    pub fn audit(
        &self,
        kind: &str,
        account: Option<&str>,
        detail: &serde_json::Value,
    ) -> anyhow::Result<()> {
        // Test builds can fail audit writes alone (fault scope "audit").
        if let Some(fault) = crate::faults::pick(crate::faults::Site::Index, "audit") {
            anyhow::bail!("index: {}", crate::faults::io_error(fault));
        }
        self.with(|c| {
            c.execute(
                "INSERT INTO audit_log(at,kind,account,detail) VALUES(?1,?2,?3,?4)",
                params![now(), kind, account, detail.to_string()],
            )
        })?;
        Ok(())
    }

    pub fn audit_entries(
        &self,
        account: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<AuditEntry>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, at, kind, account, detail FROM audit_log WHERE (?1 IS NULL OR account=?1) ORDER BY id DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![account, limit], |r| {
                Ok(AuditEntry {
                    id: r.get(0)?,
                    at: ts(r.get(1)?).unwrap_or_default(),
                    kind: r.get(2)?,
                    account_id: r.get(3)?,
                    detail: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
                })
            })?
            .collect();
            rows
        })
    }
}

/// Search folding: Unicode NFC + lowercase, invisible characters removed, so `über` finds `Über`
/// (also when stored decomposed) and `PayPal` finds `Pay<zero-width>Pal`.
pub fn fold(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    s.nfc()
        .filter(|c| !crate::layout::is_invisible(*c))
        .flat_map(char::to_lowercase)
        .collect()
}

/// The text of a message's envelope that searches fall back to before it's indexed.
const ENVELOPE_TEXT: &str = "coalesce(json_extract(g.envelope, '$.subject'), '') || ' ' ||
    coalesce(json_extract(g.envelope, '$.from_name'), '') || ' ' ||
    coalesce(json_extract(g.envelope, '$.from'), '') || ' ' ||
    coalesce(json_extract(g.envelope, '$.to'), '')";

/// Wait before retrying a message that failed `attempts` times (≥ 5): 30 min, doubling, max 24 h.
pub fn retry_backoff(attempts: u32) -> chrono::Duration {
    let exp = attempts.saturating_sub(5).min(6);
    chrono::Duration::minutes((30i64 << exp).min(24 * 60))
}

pub fn empty_envelope() -> Envelope {
    Envelope {
        from: String::new(),
        from_name: None,
        to: vec![],
        subject: String::new(),
        date: None,
        message_id: None,
        attachment_count: 0,
    }
}

/// Drops cached IMAP header data of content no message has any more.
const IMAP_META_CLEANUP: &str =
    "DELETE FROM imap_meta WHERE sha256 NOT IN (SELECT sha256 FROM messages WHERE sha256 IS NOT NULL)";

const MAILBOX_SELECT: &str = "SELECT id, account, name, display, path, delimiter, special_use, uidvalidity, highest_uid, highestmodseq, current FROM mailboxes";

fn mailbox_row(r: &rusqlite::Row) -> rusqlite::Result<MailboxRow> {
    Ok(MailboxRow {
        id: r.get(0)?,
        account: r.get(1)?,
        name: r.get(2)?,
        display: r.get(3)?,
        path: r.get(4)?,
        delimiter: r.get(5)?,
        special_use: r.get(6)?,
        uidvalidity: r.get(7)?,
        highest_uid: r.get(8)?,
        highestmodseq: r.get::<_, Option<i64>>(9)?.map(|m| m as u64),
        current: r.get::<_, i32>(10)? != 0,
    })
}

const MESSAGE_SELECT: &str = "SELECT id, account, state, sha256, size, internaldate, message_id_hdr, gm_msgid, envelope, error, reviewed, first_seen_at, attempts, last_attempt_at FROM messages";

fn message_row(r: &rusqlite::Row) -> rusqlite::Result<MessageRow> {
    Ok(MessageRow {
        id: r.get(0)?,
        account: r.get(1)?,
        state: MessageState::parse(&r.get::<_, String>(2)?),
        sha256: r.get(3)?,
        size: r.get::<_, i64>(4)? as u64,
        internaldate: ts(r.get(5)?),
        message_id_hdr: r.get(6)?,
        gm_msgid: r.get(7)?,
        envelope: serde_json::from_str(&r.get::<_, String>(8)?)
            .unwrap_or_else(|_| empty_envelope()),
        error: r.get(9)?,
        reviewed: r.get::<_, i32>(10)? != 0,
        first_seen_at: ts(r.get(11)?).unwrap_or_default(),
        attempts: r.get(12)?,
        last_attempt_at: ts(r.get(13)?),
    })
}

// Single-statement queries shared by the `Index` methods and the batched ones (which run them
// inside a transaction they already hold the lock for).

fn find_membership_on(
    c: &Connection,
    mailbox: i64,
    uid: u32,
) -> rusqlite::Result<Option<MembershipRow>> {
    c.query_row(
        &format!("{MEMBERSHIP_SELECT} WHERE mailbox=?1 AND uid=?2"),
        params![mailbox, uid],
        membership_row,
    )
    .optional()
}

fn find_by_gm_msgid_on(c: &Connection, account: &str, gm: &str) -> rusqlite::Result<Option<i64>> {
    c.query_row(
        "SELECT id FROM messages WHERE account=?1 AND gm_msgid=?2",
        [account, gm],
        |r| r.get(0),
    )
    .optional()
}

fn insert_message_on(c: &Connection, m: &NewMessage) -> rusqlite::Result<i64> {
    c.execute(
        "INSERT INTO messages(account,state,first_seen_run,first_seen_at,size,internaldate,message_id_hdr,gm_msgid,envelope,sha256)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            m.account,
            m.state.as_str(),
            m.run,
            now(),
            m.size as i64,
            m.internaldate.map(|d| d.to_rfc3339()),
            m.message_id_hdr,
            m.gm_msgid,
            serde_json::to_string(m.envelope).unwrap(),
            m.sha256,
        ],
    )?;
    Ok(c.last_insert_rowid())
}

fn add_membership_on(
    c: &Connection,
    message: i64,
    mailbox: i64,
    uid: u32,
    flags: &[String],
    labels: &[String],
) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO memberships(message,mailbox,uid,flags,gm_labels) VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(mailbox,uid) DO UPDATE SET flags=?4, gm_labels=?5, deleted_on_server_at=NULL",
        params![message, mailbox, uid, join_list(flags), join_list(labels)],
    )?;
    Ok(())
}

fn update_labels_on(c: &Connection, message: i64, labels: &[String]) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE memberships SET gm_labels=?2 WHERE message=?1",
        params![message, join_list(labels)],
    )?;
    Ok(())
}

fn query_messages_on(
    c: &Connection,
    q: &MessageQuery,
    id: Option<i64>,
    destinations: u32,
) -> rusqlite::Result<(u64, Vec<MessageSummary>)> {
    let states: Option<String> = if q.states.is_empty() {
        None
    } else {
        Some(
            q.states
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
    };
    // Indexed messages are searched by their full text, the others by envelope (see crate::search).
    let search = crate::search::parse(q.text.as_deref().unwrap_or(""), q.field.as_deref());
    let fts = search.fts.clone();
    // A single message is a rowid lookup: written as `?6 IS NULL OR g.id=?6` SQLite can't use
    // the key and scans the table, which made discovering n messages cost n² row reads.
    let by_id = if id.is_some() {
        "g.id=?6"
    } else {
        "?6 IS NULL"
    };
    // Junk and Trash: ids of every account's mailboxes with that role, comma-separated.
    let (junk, trash) = role_mailbox_lists(c)?;
    // Never NULL (`g.spam=1 OR …` is NULL when unmarked), or `NOT` would drop the message too.
    let is_spam = format!(
        "(CASE WHEN g.spam IS NULL THEN {} ELSE g.spam=1 END)",
        filed_in("?21")
    );
    let is_trash = format!("(NOT {is_spam} AND {})", filed_in("?22"));
    let folder = q.folder.map(|f| match f {
        MailFolder::Mail => "mail",
        MailFolder::Spam => "spam",
        MailFolder::Trash => "trash",
    });
    let filter = format!(
        "WHERE {by_id}
          AND (?1 IS NULL OR g.account=?1)
          AND (?2 IS NULL OR EXISTS(SELECT 1 FROM memberships m WHERE m.message=g.id AND m.mailbox=?2))
          AND (?3=0 OR g.reviewed=0)
          AND (?10 IS NULL
            OR g.id IN (SELECT rowid FROM search WHERE search MATCH ?10)
            OR (?4 IS NOT NULL AND (g.sha256 IS NULL OR g.indexed_sha IS NOT g.sha256)
                AND malo_contains({ENVELOPE_TEXT}, ?4)))
          AND (?11 IS NULL OR malo_contains({ENVELOPE_TEXT}, ?11))
          AND (?12 IS NULL OR g.internaldate >= ?12)
          AND (?13 IS NULL OR g.internaldate < ?13)
          AND (?14 IS NULL OR (coalesce(json_extract(g.envelope, '$.attachment_count'), 0) > 0) = ?14)
          AND (?15 IS NULL OR coalesce((SELECT COUNT(*)=SUM(m.deleted_on_server_at IS NOT NULL) FROM memberships m WHERE m.message=g.id), 0) = ?15)
          AND (?16 IS NULL OR g.reviewed = 1 - ?16)
          AND (?17 IS NULL OR coalesce(g.category, 'primary') = ?17)
          AND (?18 IS NULL OR (coalesce(g.category, 'primary') = ?18) = ?19)
          AND (?5 IS NULL OR instr(',' || ?5 || ',', ',' || g.state || ',') > 0)
          AND (?7 IS NULL OR g.id<=?7)
          AND (?20 IS NULL OR (?20='spam' AND {is_spam}) OR (?20='trash' AND {is_trash})
            OR (?20='mail' AND NOT {is_spam} AND NOT {is_trash}))"
    );
    {
        let limit = if q.limit == 0 { 100 } else { q.limit.min(1000) };
        let p = params![
            q.account,
            q.mailbox,
            q.new_only as i32,
            search.envelope,
            states,
            id,
            q.max_id,
            limit,
            q.offset,
            fts,
            search.literal,
            search.after,
            search.before,
            search.has_attachment,
            search.purged,
            search.unread,
            q.category
                .as_deref()
                .filter(|c| crate::search::CATEGORIES.contains(c)),
            search.category.as_ref().map(|c| c.0.as_str()),
            search.category.as_ref().map(|c| c.1),
            folder,
            junk,
            trash
        ];
        // The total only matters for paging a list; counting is a full scan.
        let total: i64 = match id {
            Some(_) => 0,
            None => c.query_row(
                &format!("SELECT COUNT(*) FROM messages g {filter}"),
                p,
                |r| r.get(0),
            )?,
        };
        let sql = format!(
            "SELECT g.id, g.account, g.envelope, g.size, g.internaldate, g.state, g.error, g.reviewed, g.first_seen_at,
                (SELECT COUNT(*) FROM replicas r WHERE r.message=g.id AND r.status='verified'),
                (SELECT group_concat(mb.display, char(31)) FROM memberships m JOIN mailboxes mb ON mb.id=m.mailbox WHERE m.message=g.id),
                (SELECT m.gm_labels FROM memberships m WHERE m.message=g.id LIMIT 1),
                (SELECT m.flags FROM memberships m WHERE m.message=g.id LIMIT 1),
                (SELECT COUNT(*)=SUM(m.deleted_on_server_at IS NOT NULL) FROM memberships m WHERE m.message=g.id),
                {snippet},
                g.category,
                CASE WHEN g.thread IS NULL THEN 1 ELSE
                  (SELECT COUNT(DISTINCT coalesce(t.message_id_hdr, t.id)) FROM messages t WHERE t.account=g.account AND t.thread=g.thread) END,
                {is_spam}
             FROM messages g {filter} ORDER BY {order} LIMIT ?8 OFFSET ?9",
            // Matches are marked with STX/ETX (U+0002, U+0003) for the app to highlight.
            snippet = if fts.is_some() {
                "(SELECT snippet(search, -1, char(2), char(3), '…', 12) FROM search WHERE search MATCH ?10 AND rowid=g.id)"
            } else {
                "NULL"
            },
            order = match (q.sort, &fts) {
                // bm25 is lower for better matches; subject and sender count most.
                (MessageSort::Relevance, Some(_)) => {
                    "(SELECT bm25(search, 10.0, 5.0, 3.0, 4.0, 1.0) FROM search WHERE search MATCH ?10 AND rowid=g.id) IS NULL,
                     (SELECT bm25(search, 10.0, 5.0, 3.0, 4.0, 1.0) FROM search WHERE search MATCH ?10 AND rowid=g.id),
                     g.internaldate IS NULL, g.internaldate DESC, g.id DESC"
                }
                (sort, _) => sort.order_by(),
            }
        );
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt
            .query_map(p, |r| {
                Ok(MessageSummary {
                    id: r.get(0)?,
                    account_id: r.get(1)?,
                    envelope: serde_json::from_str(&r.get::<_, String>(2)?)
                        .unwrap_or_else(|_| empty_envelope()),
                    size: r.get::<_, i64>(3)? as u64,
                    internal_date: ts(r.get(4)?),
                    state: MessageState::parse(&r.get::<_, String>(5)?),
                    error: r.get(6)?,
                    reviewed: r.get::<_, i32>(7)? != 0,
                    first_seen_at: ts(r.get(8)?).unwrap_or_default(),
                    stored: r.get::<_, i64>(9)? as u32,
                    destinations,
                    mailboxes: split_list(r.get::<_, Option<String>>(10)?.unwrap_or_default()),
                    labels: split_list(r.get::<_, Option<String>>(11)?.unwrap_or_default()),
                    flags: split_list(r.get::<_, Option<String>>(12)?.unwrap_or_default()),
                    deleted_on_server: r.get::<_, Option<bool>>(13)?.unwrap_or(false),
                    snippet: r.get(14)?,
                    category: r.get(15)?,
                    thread_size: r.get::<_, i64>(16)? as u32,
                    preview: None,
                    spam: r.get::<_, bool>(17)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok((total as u64, rows))
    }
}

/// SQL: the message `g` is filed only in the mailboxes listed in parameter `set` (comma-separated
/// ids). Only memberships still on the server count, unless it is on the server nowhere any more:
/// then where it last was.
fn filed_in(set: &str) -> String {
    let considered = "(m.deleted_on_server_at IS NULL OR NOT EXISTS(SELECT 1 FROM memberships l WHERE l.message=g.id AND l.deleted_on_server_at IS NULL))";
    let inside = format!("instr(',' || {set} || ',', ',' || m.mailbox || ',') > 0");
    format!(
        "(EXISTS(SELECT 1 FROM memberships m WHERE m.message=g.id AND {considered} AND {inside})
          AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.message=g.id AND {considered} AND NOT {inside}))"
    )
}

/// Every account's Junk and Trash mailbox ids, each list comma-separated (see
/// [`crate::mailview::role_mailboxes`]).
fn role_mailbox_lists(c: &Connection) -> rusqlite::Result<(String, String)> {
    let mut stmt = c.prepare(
        "SELECT id, account, name, delimiter, special_use FROM mailboxes ORDER BY account, id",
    )?;
    let rows: Vec<(String, crate::mailview::MailboxRole)> = stmt
        .query_map([], |r| {
            Ok((r.get(1)?, (r.get(0)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        })?
        .collect::<Result<_, _>>()?;
    let mut by_account: std::collections::BTreeMap<&str, Vec<crate::mailview::MailboxRole>> =
        Default::default();
    for (account, mb) in &rows {
        by_account.entry(account).or_default().push(mb.clone());
    }
    let join = |role: &str| {
        by_account
            .values()
            .flat_map(|mbs| crate::mailview::role_mailboxes(mbs, role))
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    Ok((join("\\Junk"), join("\\Trash")))
}

/// About two lines of text: quoted replies (`>`) and the "On … wrote:" line before them are
/// skipped, whitespace collapsed.
fn preview_text(body: &str) -> Option<String> {
    const MAX: usize = 200;
    let lines: Vec<&str> = body.lines().map(str::trim).collect();
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() || line.starts_with('>') {
            continue;
        }
        let quotes_next = lines[i + 1..]
            .iter()
            .find(|l| !l.is_empty())
            .is_some_and(|l| l.starts_with('>'));
        if quotes_next && line.ends_with(':') {
            continue;
        }
        for word in line.split_whitespace() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(word);
        }
        if out.chars().count() >= MAX {
            break;
        }
    }
    if out.chars().count() > MAX {
        out = out
            .chars()
            .take(MAX)
            .collect::<String>()
            .trim_end()
            .to_string();
        out.push('…');
    }
    (!out.is_empty()).then_some(out)
}

const MEMBERSHIP_SELECT: &str =
    "SELECT id, message, mailbox, uid, flags, gm_labels, deleted_on_server_at IS NOT NULL FROM memberships";

fn membership_row(r: &rusqlite::Row) -> rusqlite::Result<MembershipRow> {
    Ok(MembershipRow {
        id: r.get(0)?,
        message: r.get(1)?,
        mailbox: r.get(2)?,
        uid: r.get(3)?,
        flags: split_list(r.get(4)?),
        gm_labels: split_list(r.get(5)?),
        deleted_on_server: r.get(6)?,
    })
}

const REPLICA_SELECT: &str = "SELECT r.message, r.destination, r.object_path, r.encrypted, r.stored_size, r.status, r.verified_at, g.sha256, g.size
     FROM replicas r JOIN messages g ON g.id=r.message";

fn replica_row(r: &rusqlite::Row) -> rusqlite::Result<ReplicaRow> {
    Ok(ReplicaRow {
        message: r.get(0)?,
        destination: r.get(1)?,
        object_path: r.get(2)?,
        encrypted: r.get(3)?,
        stored_size: r.get::<_, i64>(4)? as u64,
        status: ReplicaStatus::parse(&r.get::<_, String>(5)?),
        verified_at: ts(r.get(6)?),
        sha256: r.get(7)?,
        size: r.get::<_, i64>(8)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_key;

    #[test]
    fn preview_skips_quotes() {
        let body = "Sounds good,\n\nsee you   then.\n\nOn Mon, Ann wrote:\n> earlier\n> text\n";
        assert_eq!(
            preview_text(body).as_deref(),
            Some("Sounds good, see you then.")
        );
        assert_eq!(preview_text("> only quoted\n"), None);
        let long = "word ".repeat(100);
        let p = preview_text(&long).unwrap();
        assert!(p.ends_with('…') && p.chars().count() <= 201);
    }

    #[test]
    fn sqlcipher_key_required() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.db");
        let k = random_key();
        {
            let idx = Index::open(&path, &k).unwrap();
            idx.kv_set("a", "b").unwrap();
        }
        assert!(Index::open(&path, &random_key()).is_err());
        let idx = Index::open(&path, &k).unwrap();
        assert_eq!(idx.kv_get("a").unwrap().as_deref(), Some("b"));
        // Plaintext marker must not appear on disk.
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(15).any(|w| w == b"SQLite format 3"));
    }

    #[test]
    fn failing_messages_are_retried_with_backoff_not_dropped() {
        let idx = Index::open_in_memory().unwrap();
        let env = empty_envelope();
        let id = idx
            .insert_message(&NewMessage {
                account: "a",
                run: None,
                size: 1,
                internaldate: None,
                message_id_hdr: None,
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Discovered,
                sha256: None,
            })
            .unwrap();
        for _ in 0..7 {
            idx.set_state(id, MessageState::Error, Some("storage down"))
                .unwrap();
        }
        // Just failed for the 7th time: waits for its backoff on scheduled runs …
        assert!(idx.pending_messages("a", false).unwrap().is_empty());
        // … a manual backup retries it anyway …
        assert_eq!(idx.pending_messages("a", true).unwrap().len(), 1);
        // … and once the backoff has passed, scheduled runs retry it too.
        idx.with(|c| {
            c.execute(
                "UPDATE messages SET last_attempt_at='2000-01-01T00:00:00Z'",
                [],
            )
        })
        .unwrap();
        assert_eq!(idx.pending_messages("a", false).unwrap().len(), 1);
        assert_eq!(retry_backoff(5), chrono::Duration::minutes(30));
        assert_eq!(retry_backoff(50), chrono::Duration::hours(24));
    }

    #[test]
    fn forgotten_messages_leave_tombstones_and_shared_objects() {
        let idx = Index::open_in_memory().unwrap();
        let env = empty_envelope();
        let inbox = idx
            .upsert_mailbox("a", "INBOX", "INBOX", "INBOX", None, None, 7)
            .unwrap();
        let sha = "ab".repeat(32);
        let add = |uid: u32| {
            let id = idx
                .insert_message(&NewMessage {
                    account: "a",
                    run: None,
                    size: 1,
                    internaldate: None,
                    message_id_hdr: None,
                    gm_msgid: None,
                    envelope: &env,
                    state: MessageState::Verified,
                    sha256: Some(&sha),
                })
                .unwrap();
            idx.add_membership(id, inbox.id, uid, &[], &[]).unwrap();
            // Identical content: both messages use the same encrypted object.
            idx.upsert_replica(id, "d1", "o/shared.enc", true, 1, ReplicaStatus::Verified)
                .unwrap();
            id
        };
        let (one, two) = (add(1), add(2));
        // The object stays while the other message uses it …
        assert!(idx.forget_messages(&[one]).unwrap().is_empty());
        assert!(idx.message(one).unwrap().is_none());
        assert!(idx.memberships(one).unwrap().is_empty());
        assert!(idx.is_tombstoned("a", "INBOX", 7, 1, &sha).unwrap());
        // … not for another UID, UIDVALIDITY or content.
        assert!(!idx.is_tombstoned("a", "INBOX", 7, 2, &sha).unwrap());
        assert!(!idx.is_tombstoned("a", "INBOX", 8, 1, &sha).unwrap());
        assert!(!idx
            .is_tombstoned("a", "INBOX", 7, 1, &"cd".repeat(32))
            .unwrap());
        // … and goes with the last one.
        assert_eq!(
            idx.forget_messages(&[two, 999]).unwrap(),
            vec![("d1".to_string(), "o/shared.enc".to_string())]
        );
        assert!(!idx.object_in_use("d1", "o/shared.enc").unwrap());
    }

    #[test]
    fn prune_deleted_keeps_configured_accounts_and_destinations() {
        let idx = Index::open_in_memory().unwrap();
        let env = empty_envelope();
        let msg = |account: &str| {
            idx.insert_message(&NewMessage {
                account,
                run: None,
                size: 1,
                internaldate: None,
                message_id_hdr: None,
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Verified,
                sha256: Some(&"0".repeat(64)),
            })
            .unwrap()
        };
        let (kept, gone) = (msg("kept"), msg("gone"));
        for d in ["d-kept", "d-gone"] {
            idx.upsert_replica(kept, d, "p", false, 1, ReplicaStatus::Verified)
                .unwrap();
        }
        let n = idx
            .prune_deleted(&["kept".into()], &["d-kept".into()])
            .unwrap();
        assert_eq!(n, 2);
        assert!(idx.message(kept).unwrap().is_some());
        assert!(idx.message(gone).unwrap().is_none());
        let reps = idx.replicas_of(kept).unwrap();
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].destination, "d-kept");
        // Nothing left to prune.
        assert_eq!(
            idx.prune_deleted(&["kept".into()], &["d-kept".into()])
                .unwrap(),
            0
        );
    }

    #[test]
    fn new_uidvalidity_voids_old_uids() {
        let idx = Index::open_in_memory().unwrap();
        let env = empty_envelope();
        let old = idx
            .upsert_mailbox("a", "Box", "Box", "Box", Some("/"), None, 1)
            .unwrap();
        let id = idx
            .insert_message(&NewMessage {
                account: "a",
                run: None,
                size: 1,
                internaldate: None,
                message_id_hdr: None,
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Error,
                sha256: Some(&"0".repeat(64)),
            })
            .unwrap();
        idx.add_membership(id, old.id, 1, &[], &[]).unwrap();
        // The mailbox is recreated on the server: UID 1 of the old row no longer exists there,
        // so the unstored message must take the offline path (spool / other replicas).
        let new = idx
            .upsert_mailbox("a", "Box", "Box", "Box", Some("/"), None, 2)
            .unwrap();
        assert_ne!(old.id, new.id);
        assert!(idx
            .memberships(id)
            .unwrap()
            .iter()
            .all(|m| m.deleted_on_server));
        assert!(idx.live_uids(old.id).unwrap().is_empty());
    }

    #[test]
    fn unicode_search() {
        let idx = Index::open_in_memory().unwrap();
        let mb = idx
            .upsert_mailbox("acc", "INBOX", "INBOX", "INBOX", Some("/"), None, 1)
            .unwrap();
        for (i, subject) in [
            "Über uns",
            "Cafe\u{301} au lait",
            "Pay\u{200B}Pal receipt",
            "100% off",
            "plain",
        ]
        .iter()
        .enumerate()
        {
            let mut env = empty_envelope();
            env.subject = subject.to_string();
            let id = idx
                .insert_message(&NewMessage {
                    account: "acc",
                    run: None,
                    size: 1,
                    internaldate: None,
                    message_id_hdr: None,
                    gm_msgid: None,
                    envelope: &env,
                    state: MessageState::Verified,
                    sha256: None,
                })
                .unwrap();
            idx.add_membership(id, mb.id, i as u32 + 1, &[], &[])
                .unwrap();
        }
        let hits = |q: &str| {
            idx.list_messages(
                &MessageQuery {
                    text: Some(q.into()),
                    ..Default::default()
                },
                1,
            )
            .unwrap()
            .0
        };
        assert_eq!(hits("über"), 1);
        assert_eq!(hits("ÜBER"), 1);
        assert_eq!(
            hits("caf\u{e9}"),
            1,
            "composed query finds decomposed subject"
        );
        assert_eq!(
            hits("paypal"),
            1,
            "zero-width characters don't hide matches"
        );
        assert_eq!(hits("100%"), 1);
        assert_eq!(hits("%"), 1, "% is literal, not a wildcard");
        assert_eq!(hits("_"), 0);
        assert_eq!(hits("😀\u{202E}"), 0);
    }

    #[test]
    fn escaped_gmail_labels_are_repaired_once() {
        let idx = Index::open_in_memory().unwrap();
        let all = idx
            .upsert_mailbox(
                "acc",
                "[Gmail]/All Mail",
                "All Mail",
                "All",
                Some("/"),
                Some("\\All"),
                1,
            )
            .unwrap();
        let d = crate::imap::Discovered {
            uid: 1,
            flags: vec![],
            internaldate: None,
            size: 1,
            envelope: empty_envelope(),
            gm_msgid: Some(1),
            gm_labels: vec![],
        };
        idx.record_discovered("acc", all.id, 1, &[d], 1).unwrap();
        let stored = "\\\\Inbox\u{1f}\\\\Important\u{1f}Say \\\"hi\\\"\u{1f}Work";
        let labels = || {
            idx.with(|c| {
                c.query_row("SELECT gm_labels FROM memberships", [], |r| {
                    r.get::<_, String>(0)
                })
            })
            .unwrap()
        };
        idx.with(|c| {
            c.execute("UPDATE memberships SET gm_labels=?1", [stored])?;
            c.execute("DELETE FROM kv WHERE k='labels_unescaped'", [])
        })
        .unwrap();
        idx.with(|c| unescape_stored_labels(c).map_err(|_| rusqlite::Error::InvalidQuery))
            .unwrap();
        assert_eq!(
            labels(),
            "\\Inbox\u{1f}\\Important\u{1f}Say \"hi\"\u{1f}Work"
        );
        // Only once: labels stored correctly since then are left alone.
        idx.with(|c| c.execute("UPDATE memberships SET gm_labels=?1", [stored]))
            .unwrap();
        idx.with(|c| unescape_stored_labels(c).map_err(|_| rusqlite::Error::InvalidQuery))
            .unwrap();
        assert_eq!(labels(), stored);
    }

    #[test]
    fn batched_discovery_and_pinned_paging() {
        let idx = Index::open_in_memory().unwrap();
        let all = idx
            .upsert_mailbox(
                "acc",
                "[Gmail]/All Mail",
                "All Mail",
                "All",
                Some("/"),
                Some("\\All"),
                1,
            )
            .unwrap();
        let trash = idx
            .upsert_mailbox(
                "acc",
                "[Gmail]/Trash",
                "Trash",
                "Trash",
                Some("/"),
                Some("\\Trash"),
                1,
            )
            .unwrap();
        let found = |uids: std::ops::Range<u32>| -> Vec<crate::imap::Discovered> {
            uids.map(|uid| crate::imap::Discovered {
                uid,
                flags: vec![],
                // Higher UIDs here are older and larger, so every sort order differs from id order.
                internaldate: DateTime::from_timestamp(1_700_000_000 - uid as i64 * 60, 0),
                size: uid,
                envelope: Envelope {
                    from_name: Some(format!("{}", (b'a' + (uid % 26) as u8) as char)),
                    ..empty_envelope()
                },
                gm_msgid: Some(1000 + uid as u64),
                gm_labels: vec![],
            })
            .collect()
        };
        let added = idx
            .record_discovered("acc", all.id, 1, &found(1..251), 2)
            .unwrap();
        assert_eq!(added.len(), 250);
        assert_eq!(added[0].destinations, 2);
        // Seen again: nothing new. The same Gmail message in another mailbox: membership only.
        assert!(idx
            .record_discovered("acc", all.id, 2, &found(1..251), 2)
            .unwrap()
            .is_empty());
        assert!(idx
            .record_discovered("acc", trash.id, 2, &found(1..6), 2)
            .unwrap()
            .is_empty());
        assert_eq!(idx.live_uids(trash.id).unwrap().len(), 5);

        let page = |offset: u32, max_id: Option<i64>| {
            let q = MessageQuery {
                limit: 100,
                offset,
                max_id,
                ..Default::default()
            };
            idx.list_messages(&q, 2).unwrap()
        };
        let (total, first) = page(0, None);
        assert_eq!(total, 250);
        let pin = Some(first[0].id);
        let before: Vec<i64> = page(100, pin).1.iter().map(|m| m.id).collect();
        // Mail found after the first page doesn't shift the pinned pages.
        idx.record_discovered("acc", all.id, 3, &found(251..261), 2)
            .unwrap();
        let after: Vec<i64> = page(100, pin).1.iter().map(|m| m.id).collect();
        assert_eq!(before, after);
        assert_eq!(page(0, None).0, 260);

        let top = |sort: MessageSort| {
            let q = MessageQuery {
                limit: 1,
                sort,
                ..Default::default()
            };
            let m = idx.list_messages(&q, 2).unwrap().1.remove(0);
            (m.size, m.envelope.from_name.unwrap())
        };
        assert_eq!(top(MessageSort::Newest).0, 1);
        assert_eq!(top(MessageSort::Oldest).0, 260);
        assert_eq!(top(MessageSort::Largest).0, 260);
        assert_eq!(top(MessageSort::Sender).1, "a");
    }

    /// Spam and Trash are apart from the rest: by the server's folder (marked or only named so),
    /// unless marked otherwise in Malo; a purged message stays where it last was.
    #[test]
    fn spam_and_trash_folders() {
        let idx = Index::open_in_memory().unwrap();
        let mb = |acc: &str, name: &str, special: Option<&str>| {
            idx.upsert_mailbox(acc, name, name, name, Some("/"), special, 1)
                .unwrap()
        };
        let inbox = mb("a", "INBOX", None);
        let junk = mb("a", "[Gmail]/Spam", Some("\\Junk"));
        let trash = mb("a", "Trash", Some("\\Trash"));
        // Account b's server marks nothing: its folder named "Junk" is the one.
        let b_inbox = mb("b", "INBOX", None);
        let b_junk = mb("b", "Junk", None);
        let env = empty_envelope();
        let mut uid = 0;
        let mut msg = |acc: &str, mailbox: i64| {
            uid += 1;
            let id = idx
                .insert_message(&NewMessage {
                    account: acc,
                    run: None,
                    size: 10,
                    internaldate: None,
                    message_id_hdr: None,
                    gm_msgid: None,
                    envelope: &env,
                    state: MessageState::Verified,
                    sha256: None,
                })
                .unwrap();
            idx.add_membership(id, mailbox, uid, &[], &[]).unwrap();
            (id, uid)
        };
        let (ham, _) = msg("a", inbox.id);
        let (spam, _) = msg("a", junk.id);
        let (binned, _) = msg("a", trash.id);
        let (b_ham, _) = msg("b", b_inbox.id);
        let (b_spam, _) = msg("b", b_junk.id);
        // Purged from Junk: still spam.
        let (gone, gone_uid) = msg("a", junk.id);
        idx.mark_deleted_on_server(junk.id, &[gone_uid], true)
            .unwrap();
        // Moved from the inbox to Junk: the inbox copy is gone, the Junk one counts.
        let (moved, moved_uid) = msg("a", inbox.id);
        idx.mark_deleted_on_server(inbox.id, &[moved_uid], false)
            .unwrap();
        idx.add_membership(moved, junk.id, 99, &[], &[]).unwrap();

        let ids = |folder: MailFolder| {
            let mut v: Vec<i64> = idx
                .list_messages(
                    &MessageQuery {
                        folder: Some(folder),
                        ..Default::default()
                    },
                    1,
                )
                .unwrap()
                .1
                .into_iter()
                .map(|m| m.id)
                .collect();
            v.sort();
            v
        };
        assert_eq!(ids(MailFolder::Mail), vec![ham, b_ham]);
        assert_eq!(ids(MailFolder::Spam), vec![spam, b_spam, gone, moved]);
        assert_eq!(ids(MailFolder::Trash), vec![binned]);

        // Marked in Malo: that wins over the folder, both ways.
        idx.set_spam(&[ham], Some(true)).unwrap();
        idx.set_spam(&[spam], Some(false)).unwrap();
        assert_eq!(ids(MailFolder::Mail), vec![spam, b_ham]);
        assert_eq!(ids(MailFolder::Spam), vec![ham, b_spam, gone, moved]);
        let summary = idx.summary(ham, 1).unwrap().unwrap();
        assert!(summary.spam);
        assert!(!idx.summary(spam, 1).unwrap().unwrap().spam);
        // Without a folder, everything.
        assert_eq!(idx.list_messages(&MessageQuery::default(), 1).unwrap().0, 7);
    }

    #[test]
    fn messages_and_replicas() {
        let idx = Index::open_in_memory().unwrap();
        let mb = idx
            .upsert_mailbox("acc", "INBOX", "INBOX", "INBOX", Some("/"), None, 5)
            .unwrap();
        let env = empty_envelope();
        let id = idx
            .insert_message(&NewMessage {
                account: "acc",
                run: None,
                size: 10,
                internaldate: None,
                message_id_hdr: None,
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Discovered,
                sha256: None,
            })
            .unwrap();
        idx.add_membership(id, mb.id, 7, &["\\Seen".into()], &[])
            .unwrap();
        assert_eq!(idx.find_membership(mb.id, 7).unwrap().unwrap().message, id);
        let (total, list) = idx
            .list_messages(
                &MessageQuery {
                    new_only: true,
                    ..Default::default()
                },
                2,
            )
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(list[0].mailboxes, vec!["INBOX"]);
        assert_eq!(list[0].flags, vec!["\\Seen"]);
        let dests = vec!["d1".to_string(), "d2".to_string()];
        idx.upsert_replica(id, "d1", "p", true, 100, ReplicaStatus::Verified)
            .unwrap();
        assert_eq!(
            idx.refresh_message_state(id, &dests).unwrap(),
            (MessageState::Stored, 1)
        );
        idx.upsert_replica(id, "d2", "p", true, 100, ReplicaStatus::Verified)
            .unwrap();
        assert_eq!(
            idx.refresh_message_state(id, &dests).unwrap(),
            (MessageState::Verified, 2)
        );
        idx.mark_reviewed(&[id], None).unwrap();
        let new_only = MessageQuery {
            new_only: true,
            ..Default::default()
        };
        let (total, _) = idx.list_messages(&new_only, 2).unwrap();
        assert_eq!(total, 0);
        idx.set_reviewed(&[id], false).unwrap();
        assert_eq!(idx.list_messages(&new_only, 2).unwrap().0, 1);
        idx.set_reviewed(&[id], true).unwrap();
        assert_eq!(idx.list_messages(&new_only, 2).unwrap().0, 0);
        // New UIDVALIDITY → new current mailbox row, old one kept.
        let mb2 = idx
            .upsert_mailbox("acc", "INBOX", "INBOX", "INBOX", Some("/"), None, 6)
            .unwrap();
        assert_ne!(mb2.id, mb.id);
        assert!(!idx.mailbox(mb.id).unwrap().unwrap().current);
        assert_eq!(idx.mailboxes(Some("acc"), true).unwrap().len(), 1);
    }
}
