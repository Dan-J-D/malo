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
}

impl MessageSort {
    pub fn parse(s: &str) -> MessageSort {
        match s {
            "oldest" => MessageSort::Oldest,
            "sender" => MessageSort::Sender,
            "largest" => MessageSort::Largest,
            _ => MessageSort::Newest,
        }
    }

    fn order_by(self) -> &'static str {
        match self {
            MessageSort::Newest => "g.internaldate IS NULL, g.internaldate DESC, g.id DESC",
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

fn split_list(s: String) -> Vec<String> {
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
        conn.create_scalar_function(
            "malo_fold",
            1,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| Ok(fold(&ctx.get::<String>(0)?)),
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

    pub fn messages_with_sha(&self, sha256: &str) -> anyhow::Result<Vec<i64>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT id FROM messages WHERE sha256=?1")?;
            let rows = stmt.query_map([sha256], |r| r.get(0))?.collect();
            rows
        })
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

/// `%` and `_` in a search are literal characters, not wildcards.
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

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
    let text = q
        .text
        .as_ref()
        .filter(|t| !t.trim().is_empty())
        .map(|t| format!("%{}%", like_escape(&fold(t.trim()))));
    // A single message is a rowid lookup: written as `?6 IS NULL OR g.id=?6` SQLite can't use
    // the key and scans the table, which made discovering n messages cost n² row reads.
    let by_id = if id.is_some() {
        "g.id=?6"
    } else {
        "?6 IS NULL"
    };
    let filter = format!(
        "WHERE {by_id}
          AND (?1 IS NULL OR g.account=?1)
          AND (?2 IS NULL OR EXISTS(SELECT 1 FROM memberships m WHERE m.message=g.id AND m.mailbox=?2))
          AND (?3=0 OR g.reviewed=0)
          AND (?4 IS NULL OR malo_fold(
                coalesce(json_extract(g.envelope, '$.subject'), '') || ' ' ||
                coalesce(json_extract(g.envelope, '$.from_name'), '') || ' ' ||
                coalesce(json_extract(g.envelope, '$.from'), '') || ' ' ||
                coalesce(json_extract(g.envelope, '$.to'), '')) LIKE ?4 ESCAPE '\\')
          AND (?5 IS NULL OR instr(',' || ?5 || ',', ',' || g.state || ',') > 0)
          AND (?7 IS NULL OR g.id<=?7)"
    );
    {
        let p = params![q.account, q.mailbox, q.new_only as i32, text, states, id, q.max_id];
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
                (SELECT COUNT(*)=SUM(m.deleted_on_server_at IS NOT NULL) FROM memberships m WHERE m.message=g.id)
             FROM messages g {filter} ORDER BY {order} LIMIT ?8 OFFSET ?9",
            order = q.sort.order_by()
        );
        let limit = if q.limit == 0 { 100 } else { q.limit.min(1000) };
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt
            .query_map(
                params![
                    q.account,
                    q.mailbox,
                    q.new_only as i32,
                    text,
                    states,
                    id,
                    q.max_id,
                    limit,
                    q.offset
                ],
                |r| {
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
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok((total as u64, rows))
    }
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
    fn batched_discovery_and_pinned_paging() {
        let idx = Index::open_in_memory().unwrap();
        let all = idx
            .upsert_mailbox("acc", "[Gmail]/All Mail", "All Mail", "All", Some("/"), Some("\\All"), 1)
            .unwrap();
        let trash = idx
            .upsert_mailbox("acc", "[Gmail]/Trash", "Trash", "Trash", Some("/"), Some("\\Trash"), 1)
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
        let added = idx.record_discovered("acc", all.id, 1, &found(1..251), 2).unwrap();
        assert_eq!(added.len(), 250);
        assert_eq!(added[0].destinations, 2);
        // Seen again: nothing new. The same Gmail message in another mailbox: membership only.
        assert!(idx.record_discovered("acc", all.id, 2, &found(1..251), 2).unwrap().is_empty());
        assert!(idx.record_discovered("acc", trash.id, 2, &found(1..6), 2).unwrap().is_empty());
        assert_eq!(idx.live_uids(trash.id).unwrap().len(), 5);

        let page = |offset: u32, max_id: Option<i64>| {
            let q = MessageQuery { limit: 100, offset, max_id, ..Default::default() };
            idx.list_messages(&q, 2).unwrap()
        };
        let (total, first) = page(0, None);
        assert_eq!(total, 250);
        let pin = Some(first[0].id);
        let before: Vec<i64> = page(100, pin).1.iter().map(|m| m.id).collect();
        // Mail found after the first page doesn't shift the pinned pages.
        idx.record_discovered("acc", all.id, 3, &found(251..261), 2).unwrap();
        let after: Vec<i64> = page(100, pin).1.iter().map(|m| m.id).collect();
        assert_eq!(before, after);
        assert_eq!(page(0, None).0, 260);

        let top = |sort: MessageSort| {
            let q = MessageQuery { limit: 1, sort, ..Default::default() };
            let m = idx.list_messages(&q, 2).unwrap().1.remove(0);
            (m.size, m.envelope.from_name.unwrap())
        };
        assert_eq!(top(MessageSort::Newest).0, 1);
        assert_eq!(top(MessageSort::Oldest).0, 260);
        assert_eq!(top(MessageSort::Largest).0, 260);
        assert_eq!(top(MessageSort::Sender).1, "a");
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
        let (total, _) = idx
            .list_messages(
                &MessageQuery {
                    new_only: true,
                    ..Default::default()
                },
                2,
            )
            .unwrap();
        assert_eq!(total, 0);
        // New UIDVALIDITY → new current mailbox row, old one kept.
        let mb2 = idx
            .upsert_mailbox("acc", "INBOX", "INBOX", "INBOX", Some("/"), None, 6)
            .unwrap();
        assert_ne!(mb2.id, mb.id);
        assert!(!idx.mailbox(mb.id).unwrap().unwrap().current);
        assert_eq!(idx.mailboxes(Some("acc"), true).unwrap().len(), 1);
    }
}
