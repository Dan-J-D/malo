//! `server.db`: plain SQLite without secrets — users, sessions, invites, job metadata, schedules, settings.

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use malo_api::{
    AdminAuditEntry, AdminSettings, InviteInfo, JobInfo, JobKind, JobProgress, JobState,
    JobTrigger, Role, ScheduledJob, UserInfo,
};
use rusqlite::{params, Connection, OptionalExtension};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    max_accounts INTEGER,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
    code_hash TEXT PRIMARY KEY,
    username TEXT,
    role TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    trigger TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    progress TEXT NOT NULL DEFAULT '{"done":0,"total":0,"message":""}',
    error TEXT,
    result TEXT
);
CREATE INDEX IF NOT EXISTS jobs_user ON jobs(user_id, created_at);
CREATE TABLE IF NOT EXISTS schedules (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    kind TEXT NOT NULL,
    interval_secs INTEGER NOT NULL,
    next_run TEXT NOT NULL,
    PRIMARY KEY(user_id, key)
);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mail_logins (
    username TEXT PRIMARY KEY COLLATE NOCASE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used TEXT,
    UNIQUE(user_id, account_id)
);
CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT NOT NULL DEFAULT '{}'
);
"#;

pub struct Db {
    conn: Mutex<Connection>,
}

fn ts(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.with_timezone(&Utc))
}

fn role_str(r: Role) -> &'static str {
    match r {
        Role::Admin => "admin",
        Role::User => "user",
    }
}

fn parse_role(s: &str) -> Role {
    if s == "admin" {
        Role::Admin
    } else {
        Role::User
    }
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub disabled: bool,
    pub created_at: DateTime<Utc>,
    pub max_accounts: Option<u32>,
    pub last_login: Option<DateTime<Utc>>,
}

impl UserRow {
    pub fn info(&self, unlocked: bool) -> UserInfo {
        UserInfo {
            id: self.id.clone(),
            username: self.username.clone(),
            role: self.role,
            disabled: self.disabled,
            created_at: self.created_at,
            max_accounts: self.max_accounts,
            unlocked,
        }
    }
}

fn user_row(r: &rusqlite::Row) -> rusqlite::Result<UserRow> {
    Ok(UserRow {
        id: r.get(0)?,
        username: r.get(1)?,
        role: parse_role(&r.get::<_, String>(2)?),
        disabled: r.get::<_, i32>(3)? != 0,
        created_at: ts(r.get(4)?).unwrap_or_default(),
        max_accounts: r.get(5)?,
        last_login: ts(r.get(6)?),
    })
}

const USER_SELECT: &str =
    "SELECT id, username, role, disabled, created_at, max_accounts, last_login FROM users";

fn job_row(r: &rusqlite::Row) -> rusqlite::Result<(String, JobInfo)> {
    let kind: String = r.get(2)?;
    let progress: String = r.get(8)?;
    let result: Option<String> = r.get(10)?;
    Ok((
        r.get(1)?,
        JobInfo {
            id: r.get(0)?,
            kind: serde_json::from_str(&kind).unwrap_or(JobKind::Check {
                scope: malo_api::CheckScope::All,
                deep: false,
            }),
            state: JobState::parse(&r.get::<_, String>(3)?),
            trigger: if r.get::<_, String>(4)? == "scheduled" {
                JobTrigger::Scheduled
            } else {
                JobTrigger::Manual
            },
            created_at: ts(r.get(5)?).unwrap_or_default(),
            started_at: ts(r.get(6)?),
            finished_at: ts(r.get(7)?),
            progress: serde_json::from_str(&progress).unwrap_or_default(),
            error: r.get(9)?,
            result: result.and_then(|s| serde_json::from_str(&s).ok()),
        },
    ))
}

const JOB_SELECT: &str =
    "SELECT id, user_id, kind, state, trigger, created_at, started_at, finished_at, progress, error, result FROM jobs";

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Db> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;",
        )?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn with<R>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<R>) -> anyhow::Result<R> {
        let c = malo_core::index::lock_db(&self.conn);
        Ok(f(&c)?)
    }

    // ───── settings ─────

    pub fn setting(&self, k: &str) -> anyhow::Result<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT v FROM settings WHERE k=?1", [k], |r| r.get(0))
                .optional()
        })
    }

    pub fn set_setting(&self, k: &str, v: &str) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO settings(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=?2",
                [k, v],
            )
        })?;
        Ok(())
    }

    pub fn delete_setting(&self, k: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM settings WHERE k=?1", [k]))?;
        Ok(())
    }

    /// Deletes the setting only if it still has the value `v`. True when this call removed it, so
    /// of two concurrent callers exactly one wins.
    pub fn take_setting(&self, k: &str, v: &str) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM settings WHERE k=?1 AND v=?2", [k, v]))? == 1)
    }

    // ───── admin audit ─────

    pub fn admin_audit(
        &self,
        actor: &str,
        action: &str,
        target: Option<&str>,
        detail: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO admin_audit(at, actor, action, target, detail) VALUES(?1,?2,?3,?4,?5)",
                params![
                    Utc::now().to_rfc3339(),
                    actor,
                    action,
                    target,
                    detail.to_string()
                ],
            )
        })?;
        Ok(())
    }

    pub fn admin_audit_list(&self, limit: u32) -> anyhow::Result<Vec<AdminAuditEntry>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, at, actor, action, target, detail FROM admin_audit ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt
                .query_map([limit], |r| {
                    Ok(AdminAuditEntry {
                        id: r.get(0)?,
                        at: ts(Some(r.get(1)?)).unwrap_or_else(Utc::now),
                        actor: r.get(2)?,
                        action: r.get(3)?,
                        target: r.get(4)?,
                        detail: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                    })
                })?
                .collect();
            rows
        })
    }

    pub fn admin_settings(&self) -> anyhow::Result<AdminSettings> {
        Ok(self
            .setting("admin")?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default())
    }

    pub fn set_admin_settings(&self, s: &AdminSettings) -> anyhow::Result<()> {
        self.set_setting("admin", &serde_json::to_string(s)?)
    }

    // ───── users ─────

    pub fn active_admin_count(&self) -> anyhow::Result<u64> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)
        })
    }

    pub fn user_count(&self) -> anyhow::Result<u64> {
        self.with(|c| {
            c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
                .map(|n| n as u64)
        })
    }

    pub fn create_user(
        &self,
        id: &str,
        username: &str,
        role: Role,
        max_accounts: Option<u32>,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO users(id, username, role, created_at, max_accounts) VALUES(?1,?2,?3,?4,?5)",
                params![id, username, role_str(role), Utc::now().to_rfc3339(), max_accounts],
            )
        })?;
        Ok(())
    }

    pub fn user(&self, id: &str) -> anyhow::Result<Option<UserRow>> {
        self.with(|c| {
            c.query_row(&format!("{USER_SELECT} WHERE id=?1"), [id], user_row)
                .optional()
        })
    }

    pub fn user_by_name(&self, username: &str) -> anyhow::Result<Option<UserRow>> {
        self.with(|c| {
            c.query_row(
                &format!("{USER_SELECT} WHERE username=?1"),
                [username],
                user_row,
            )
            .optional()
        })
    }

    pub fn users(&self) -> anyhow::Result<Vec<UserRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!("{USER_SELECT} ORDER BY username"))?;
            let rows = stmt.query_map([], user_row)?.collect();
            rows
        })
    }

    /// False (and nothing changed) if the change would leave no active administrator.
    pub fn update_user(
        &self,
        id: &str,
        disabled: Option<bool>,
        role: Option<Role>,
        max_accounts: Option<Option<u32>>,
    ) -> anyhow::Result<bool> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let c = &tx;
            if let Some(d) = disabled {
                c.execute("UPDATE users SET disabled=?2 WHERE id=?1", params![id, d])?;
            }
            if let Some(r) = role {
                c.execute(
                    "UPDATE users SET role=?2 WHERE id=?1",
                    params![id, role_str(r)],
                )?;
            }
            if let Some(m) = max_accounts {
                c.execute(
                    "UPDATE users SET max_accounts=?2 WHERE id=?1",
                    params![id, m],
                )?;
            }
            // Never leave the server without an active administrator (two demotions at once).
            let admins: i64 = c.query_row(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0",
                [],
                |r| r.get(0),
            )?;
            if admins == 0 {
                return Ok(false); // dropping the transaction rolls it back
            }
            tx.commit()?;
            Ok(true)
        })
    }

    pub fn touch_login(&self, id: &str) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE users SET last_login=?2 WHERE id=?1",
                params![id, Utc::now().to_rfc3339()],
            )
        })?;
        Ok(())
    }

    /// Deletes the user unless that would leave no active administrator, in one statement so
    /// two administrators deleting themselves at once can't both succeed. False if refused.
    pub fn delete_user_keeping_an_admin(&self, id: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            c.execute(
                "DELETE FROM users WHERE id=?1 AND (role!='admin' OR disabled=1 OR
                   (SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0) > 1)",
                [id],
            )
        })?;
        Ok(n == 1)
    }

    // ───── sessions ─────

    pub fn create_session(
        &self,
        token_hash: &str,
        user_id: &str,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.with(|c| {
            c.execute(
                "INSERT INTO sessions(token_hash,user_id,created_at,last_seen,expires_at) VALUES(?1,?2,?3,?3,?4)",
                params![token_hash, user_id, now, expires_at.to_rfc3339()],
            )
        })?;
        Ok(())
    }

    /// Returns the user id if the session exists, isn't expired and hasn't been idle too long.
    pub fn check_session(
        &self,
        token_hash: &str,
        idle: chrono::Duration,
    ) -> anyhow::Result<Option<String>> {
        self.session(token_hash, idle, true)
    }

    /// Like [`Db::check_session`], but doesn't count as activity: an open event stream alone
    /// mustn't keep an idle session alive.
    pub fn session_still_valid(
        &self,
        token_hash: &str,
        idle: chrono::Duration,
    ) -> anyhow::Result<Option<String>> {
        self.session(token_hash, idle, false)
    }

    fn session(
        &self,
        token_hash: &str,
        idle: chrono::Duration,
        touch: bool,
    ) -> anyhow::Result<Option<String>> {
        let now = Utc::now();
        self.with(|c| {
            let row: Option<(String, String, String)> = c
                .query_row(
                    "SELECT user_id, last_seen, expires_at FROM sessions WHERE token_hash=?1",
                    [token_hash],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((user, last_seen, expires)) = row else {
                return Ok(None);
            };
            let expired = ts(Some(expires)).is_none_or(|e| e <= now);
            let idle_out = ts(Some(last_seen)).is_none_or(|l| now - l > idle);
            if expired || idle_out {
                c.execute("DELETE FROM sessions WHERE token_hash=?1", [token_hash])?;
                return Ok(None);
            }
            if touch {
                c.execute(
                    "UPDATE sessions SET last_seen=?2 WHERE token_hash=?1",
                    params![token_hash, now.to_rfc3339()],
                )?;
            }
            Ok(Some(user))
        })
    }

    pub fn delete_session(&self, token_hash: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM sessions WHERE token_hash=?1", [token_hash]))?;
        Ok(())
    }

    pub fn delete_user_sessions(&self, user_id: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM sessions WHERE user_id=?1", [user_id]))?;
        Ok(())
    }

    pub fn delete_all_sessions(&self) -> anyhow::Result<()> {
        self.with(|c| c.execute("DELETE FROM sessions", []))?;
        Ok(())
    }

    // ───── invites ─────

    pub fn create_invite(
        &self,
        code_hash: &str,
        username: Option<&str>,
        role: Role,
        expires: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO invites(code_hash,username,role,expires_at) VALUES(?1,?2,?3,?4)",
                params![code_hash, username, role_str(role), expires.to_rfc3339()],
            )
        })?;
        Ok(())
    }

    /// The role of an unused, unexpired invite valid for `username`.
    pub fn invite_role(&self, code_hash: &str, username: &str) -> anyhow::Result<Option<Role>> {
        self.with(|c| valid_invite(c, code_hash, username))
    }

    /// Consumes an invite. Returns its role if valid for `username`.
    pub fn redeem_invite(&self, code_hash: &str, username: &str) -> anyhow::Result<Option<Role>> {
        self.with(|c| {
            let Some(role) = valid_invite(c, code_hash, username)? else {
                return Ok(None);
            };
            // Only one of two concurrent registrations with the same code gets it.
            if c.execute(
                "UPDATE invites SET used=1 WHERE code_hash=?1 AND used=0",
                [code_hash],
            )? != 1
            {
                return Ok(None);
            }
            Ok(Some(role))
        })
    }

    /// Gives back an invite whose registration failed after redeeming it (e.g. the name was taken).
    pub fn release_invite(&self, code_hash: &str) -> anyhow::Result<()> {
        self.with(|c| c.execute("UPDATE invites SET used=0 WHERE code_hash=?1", [code_hash]))?;
        Ok(())
    }

    pub fn invites(&self) -> anyhow::Result<Vec<InviteInfo>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT code_hash, username, role, expires_at, used FROM invites ORDER BY expires_at DESC",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(InviteInfo {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        role: parse_role(&r.get::<_, String>(2)?),
                        expires_at: ts(Some(r.get(3)?)).unwrap_or_else(Utc::now),
                        used: r.get::<_, i32>(4)? != 0,
                    })
                })?
                .collect();
            rows
        })
    }

    /// Revokes an invite. True when it existed.
    pub fn delete_invite(&self, code_hash: &str) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM invites WHERE code_hash=?1", [code_hash]))? == 1)
    }

    /// Drops invites that expired more than a month ago.
    pub fn prune_invites(&self) -> anyhow::Result<()> {
        let cutoff = (Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        self.with(|c| c.execute("DELETE FROM invites WHERE expires_at < ?1", [cutoff]))?;
        Ok(())
    }

    // ───── jobs ─────

    pub fn insert_job(&self, user_id: &str, job: &JobInfo) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO jobs(id,user_id,kind,state,trigger,created_at,started_at,finished_at,error) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    job.id,
                    user_id,
                    serde_json::to_string(&job.kind).unwrap(),
                    job.state.as_str(),
                    if job.trigger == JobTrigger::Scheduled { "scheduled" } else { "manual" },
                    job.created_at.to_rfc3339(),
                    job.started_at.map(|t| t.to_rfc3339()),
                    job.finished_at.map(|t| t.to_rfc3339()),
                    job.error,
                ],
            )
        })?;
        Ok(())
    }

    pub fn update_job(&self, job: &JobInfo) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE jobs SET state=?2, started_at=?3, finished_at=?4, progress=?5, error=?6, result=?7 WHERE id=?1",
                params![
                    job.id,
                    job.state.as_str(),
                    job.started_at.map(|t| t.to_rfc3339()),
                    job.finished_at.map(|t| t.to_rfc3339()),
                    serde_json::to_string(&job.progress).unwrap(),
                    job.error,
                    job.result.as_ref().map(|r| r.to_string()),
                ],
            )
        })?;
        Ok(())
    }

    pub fn update_progress(&self, id: &str, p: &JobProgress) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE jobs SET progress=?2 WHERE id=?1",
                params![id, serde_json::to_string(p).unwrap()],
            )
        })?;
        Ok(())
    }

    pub fn job(&self, id: &str) -> anyhow::Result<Option<(String, JobInfo)>> {
        self.with(|c| {
            c.query_row(&format!("{JOB_SELECT} WHERE id=?1"), [id], job_row)
                .optional()
        })
    }

    pub fn jobs(&self, user_id: &str, limit: u32) -> anyhow::Result<Vec<JobInfo>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "{JOB_SELECT} WHERE user_id=?1 ORDER BY created_at DESC LIMIT ?2"
            ))?;
            let rows = stmt
                .query_map(params![user_id, limit], job_row)?
                .map(|r| r.map(|(_, j)| j))
                .collect();
            rows
        })
    }

    pub fn active_jobs(&self, user_id: &str) -> anyhow::Result<Vec<JobInfo>> {
        self.with(|c| {
            let mut stmt =
                c.prepare(&format!("{JOB_SELECT} WHERE user_id=?1 AND state IN ('queued','running') ORDER BY created_at"))?;
            let rows = stmt.query_map(params![user_id], job_row)?.map(|r| r.map(|(_, j)| j)).collect();
            rows
        })
    }

    /// Jobs left queued/running by a previous process are marked failed at startup.
    pub fn fail_stale_jobs(&self) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE jobs SET state='failed', error='server restarted', finished_at=?1 WHERE state IN ('queued','running')",
                [Utc::now().to_rfc3339()],
            )
        })?;
        Ok(())
    }

    pub fn skipped_since(
        &self,
        user_id: &str,
        since: Option<DateTime<Utc>>,
    ) -> anyhow::Result<u32> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM jobs WHERE user_id=?1 AND state='skipped_locked' AND (?2 IS NULL OR created_at > ?2)",
                params![user_id, since.map(|s| s.to_rfc3339())],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u32)
        })
    }

    pub fn prune_jobs(&self, keep_days: i64) -> anyhow::Result<()> {
        let cutoff = (Utc::now() - chrono::Duration::days(keep_days)).to_rfc3339();
        self.with(|c| {
            c.execute(
                "DELETE FROM jobs WHERE created_at < ?1 AND state NOT IN ('queued','running')",
                [cutoff],
            )
        })?;
        Ok(())
    }

    // ───── schedules ─────

    pub fn schedules(
        &self,
        user_id: Option<&str>,
    ) -> anyhow::Result<Vec<(String, ScheduledJob, i64)>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT user_id, key, kind, next_run, interval_secs FROM schedules WHERE (?1 IS NULL OR user_id=?1) ORDER BY next_run",
            )?;
            let rows = stmt
                .query_map(params![user_id], |r| {
                    let kind: String = r.get(2)?;
                    Ok((
                        r.get::<_, String>(0)?,
                        ScheduledJob {
                            key: r.get(1)?,
                            kind: serde_json::from_str(&kind).unwrap_or(JobKind::Check { scope: malo_api::CheckScope::All, deep: false }),
                            next_run: ts(r.get(3)?).unwrap_or_default(),
                        },
                        r.get::<_, i64>(4)?,
                    ))
                })?
                .collect();
            rows
        })
    }

    pub fn upsert_schedule(
        &self,
        user_id: &str,
        key: &str,
        kind: &JobKind,
        interval_secs: i64,
        first_run: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO schedules(user_id,key,kind,interval_secs,next_run) VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(user_id,key) DO UPDATE SET kind=?3,
                    next_run=CASE WHEN interval_secs<>?4 THEN ?5 ELSE next_run END, interval_secs=?4",
                params![user_id, key, serde_json::to_string(kind).unwrap(), interval_secs, first_run.to_rfc3339()],
            )
        })?;
        Ok(())
    }

    pub fn set_next_run(
        &self,
        user_id: &str,
        key: &str,
        next: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE schedules SET next_run=?3 WHERE user_id=?1 AND key=?2",
                params![user_id, key, next.to_rfc3339()],
            )
        })?;
        Ok(())
    }

    pub fn retain_schedules(&self, user_id: &str, keep: &[String]) -> anyhow::Result<()> {
        let existing: Vec<String> = self.with(|c| {
            let mut stmt = c.prepare("SELECT key FROM schedules WHERE user_id=?1")?;
            let rows = stmt.query_map([user_id], |r| r.get(0))?.collect();
            rows
        })?;
        for k in existing.into_iter().filter(|k| !keep.contains(k)) {
            self.with(|c| {
                c.execute(
                    "DELETE FROM schedules WHERE user_id=?1 AND key=?2",
                    params![user_id, k],
                )
            })?;
        }
        Ok(())
    }

    // ───── IMAP/SMTP logins ─────

    pub fn mail_login(&self, username: &str) -> anyhow::Result<Option<MailLoginRow>> {
        self.with(|c| {
            c.query_row(
                &format!("{MAIL_LOGIN_SELECT} WHERE username=?1"),
                [username],
                mail_login_row,
            )
            .optional()
        })
    }

    pub fn mail_logins(&self, user_id: &str) -> anyhow::Result<Vec<MailLoginRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "{MAIL_LOGIN_SELECT} WHERE user_id=?1 ORDER BY username"
            ))?;
            let rows = stmt.query_map([user_id], mail_login_row)?.collect();
            rows
        })
    }

    /// Sets the login of an account, replacing its previous one. False if another account
    /// (of any user) already uses the username.
    pub fn set_mail_login(
        &self,
        user_id: &str,
        account_id: &str,
        username: &str,
        password_hash: &str,
    ) -> anyhow::Result<bool> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let owner: Option<(String, String)> = tx
                .query_row(
                    "SELECT user_id, account_id FROM mail_logins WHERE username=?1",
                    [username],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if owner.is_some_and(|(u, a)| u != user_id || a != account_id) {
                return Ok(false);
            }
            tx.execute(
                "DELETE FROM mail_logins WHERE user_id=?1 AND account_id=?2",
                params![user_id, account_id],
            )?;
            tx.execute(
                "INSERT INTO mail_logins(username, user_id, account_id, password_hash, created_at) VALUES(?1,?2,?3,?4,?5)",
                params![username, user_id, account_id, password_hash, Utc::now().to_rfc3339()],
            )?;
            tx.commit()?;
            Ok(true)
        })
    }

    pub fn delete_mail_login(&self, user_id: &str, account_id: &str) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            c.execute(
                "DELETE FROM mail_logins WHERE user_id=?1 AND account_id=?2",
                params![user_id, account_id],
            )
        })?;
        Ok(n > 0)
    }

    pub fn touch_mail_login(&self, username: &str) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE mail_logins SET last_used=?2 WHERE username=?1",
                params![username, Utc::now().to_rfc3339()],
            )
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MailLoginRow {
    pub username: String,
    pub user_id: String,
    pub account_id: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

impl MailLoginRow {
    pub fn view(&self) -> malo_api::MailLoginView {
        malo_api::MailLoginView {
            account_id: self.account_id.clone(),
            username: self.username.clone(),
            created_at: self.created_at,
            last_used: self.last_used,
        }
    }
}

const MAIL_LOGIN_SELECT: &str =
    "SELECT username, user_id, account_id, password_hash, created_at, last_used FROM mail_logins";

fn mail_login_row(r: &rusqlite::Row) -> rusqlite::Result<MailLoginRow> {
    Ok(MailLoginRow {
        username: r.get(0)?,
        user_id: r.get(1)?,
        account_id: r.get(2)?,
        password_hash: r.get(3)?,
        created_at: ts(r.get(4)?).unwrap_or_default(),
        last_used: ts(r.get(5)?),
    })
}

fn valid_invite(
    c: &rusqlite::Connection,
    code_hash: &str,
    username: &str,
) -> rusqlite::Result<Option<Role>> {
    let row: Option<(Option<String>, String, String, i32)> = c
        .query_row(
            "SELECT username, role, expires_at, used FROM invites WHERE code_hash=?1",
            [code_hash],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((name, role, exp, used)) = row else {
        return Ok(None);
    };
    if used != 0 || ts(Some(exp)).is_none_or(|e| e < Utc::now()) {
        return Ok(None);
    }
    if name.is_some_and(|n| !n.eq_ignore_ascii_case(username)) {
        return Ok(None);
    }
    Ok(Some(parse_role(&role)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_active_administrator_always_remains() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("server.db")).unwrap();
        db.create_user("a", "alice", Role::Admin, None).unwrap();
        db.create_user("b", "bob", Role::Admin, None).unwrap();
        db.create_user("u", "user", Role::User, None).unwrap();
        assert!(db.delete_user_keeping_an_admin("u").unwrap());
        assert!(db.delete_user_keeping_an_admin("a").unwrap());
        assert!(!db.delete_user_keeping_an_admin("b").unwrap());
        assert!(!db.update_user("b", Some(true), None, None).unwrap());
        assert!(!db.update_user("b", None, Some(Role::User), None).unwrap());
        assert_eq!(db.active_admin_count().unwrap(), 1);
        assert!(db.update_user("b", None, None, Some(Some(3))).unwrap());
    }
}
