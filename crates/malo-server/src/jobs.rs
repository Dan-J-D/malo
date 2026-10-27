//! Job queue: global worker pool, per-user fairness, per-account mutex, cancellation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use malo_api::{CheckScope, JobInfo, JobKind, JobProgress, JobState, JobTrigger, SyncEvent};
use malo_core::ctx::{is_cancelled, EventSink, JobCtx};
use malo_core::store::FsPolicy;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::keyring::{UnlockedUser, UserPaths};
use crate::state::SharedState;

type AccountLock = Arc<tokio::sync::Mutex<()>>;

/// A queued or running job, as far as cancelling it is concerned.
struct Active {
    user: String,
    account: Option<String>,
    cancel: CancellationToken,
}

pub struct JobManager {
    workers: Arc<Semaphore>,
    user_slots: Mutex<HashMap<String, Arc<Semaphore>>>,
    account_locks: Mutex<HashMap<(String, String), AccountLock>>,
    /// job id → queued and running jobs.
    running: Mutex<HashMap<String, Active>>,
}

impl JobManager {
    pub fn new(workers: usize) -> Self {
        JobManager {
            workers: Arc::new(Semaphore::new(workers)),
            user_slots: Mutex::new(HashMap::new()),
            account_locks: Mutex::new(HashMap::new()),
            running: Mutex::new(HashMap::new()),
        }
    }

    fn user_slot(&self, user: &str, per_user: usize) -> Arc<Semaphore> {
        self.user_slots
            .lock()
            .unwrap()
            .entry(user.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(per_user.max(1))))
            .clone()
    }

    fn account_lock(&self, user: &str, account: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.account_locks
            .lock()
            .unwrap()
            .entry((user.to_string(), account.to_string()))
            .or_default()
            .clone()
    }

    /// Number of jobs that are queued or running.
    pub fn active(&self) -> usize {
        self.running.lock().unwrap().len()
    }

    /// Queued or running jobs of one user.
    pub fn running_for(&self, user_id: &str) -> usize {
        self.running
            .lock()
            .unwrap()
            .values()
            .filter(|j| j.user == user_id)
            .count()
    }

    /// Waits until a (locked) user has no queued or running job. Returns false on timeout.
    pub async fn wait_user_idle(&self, user_id: &str, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while self.running_for(user_id) > 0 {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        true
    }

    pub fn cancel(&self, job_id: &str) -> bool {
        match self.running.lock().unwrap().get(job_id).map(|j| &j.cancel) {
            Some(t) => {
                t.cancel();
                true
            }
            None => false,
        }
    }

    /// Stops one account's queued and running jobs and waits for them to end, then holds the
    /// account until the guard drops: no backup or purge of it runs meanwhile (account deletion).
    pub async fn quiesce_account(
        &self,
        user_id: &str,
        account_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        for j in self.running.lock().unwrap().values() {
            if j.user == user_id && j.account.as_deref() == Some(account_id) {
                j.cancel.cancel();
            }
        }
        self.account_lock(user_id, account_id).lock_owned().await
    }
}

pub fn fs_policy(state: &SharedState, user: &UnlockedUser) -> FsPolicy {
    let mut mounts = state.cfg.allowed_fs_mounts.clone();
    if let Ok(s) = state.db.admin_settings() {
        mounts.extend(s.allowed_fs_mounts.iter().map(PathBuf::from));
    }
    FsPolicy {
        user_root: UserPaths::new(&state.cfg.data_dir, &user.user_id).local(),
        allowed_mounts: mounts,
        user_id: user.user_id.clone(),
        owner_dir: Some(malo_core::layout::NameKey::new(&user.secrets.archive_key).owner_dir()),
    }
}

/// Persists progress (throttled) and forwards every event to the user's stream.
struct JobSink {
    inner: Arc<dyn EventSink>,
    db: Arc<crate::db::Db>,
    job_id: String,
    last: Mutex<Instant>,
}

impl EventSink for JobSink {
    fn emit(&self, event: SyncEvent) {
        if let SyncEvent::JobProgress { job_id, progress } = &event {
            if *job_id == self.job_id {
                let mut last = self.last.lock().unwrap();
                if last.elapsed() > Duration::from_secs(1) {
                    *last = Instant::now();
                    let _ = self.db.update_progress(job_id, progress);
                }
            }
        }
        self.inner.emit(event);
    }
}

pub fn job_ctx(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    job_id: &str,
    cancel: CancellationToken,
) -> JobCtx {
    let paths = UserPaths::new(&state.cfg.data_dir, &user.user_id);
    JobCtx {
        job_id: job_id.to_string(),
        user_id: user.user_id.clone(),
        config: usable_config(user),
        archive_key: user.secrets.archive_key.clone(),
        index: user.index.clone(),
        spool_dir: paths.spool(),
        spool_key: user.secrets.spool_key.clone(),
        fs: fs_policy(state, user),
        tokens: user.tokens.clone(),
        sealed: user.cancel.clone(),
        manual: false,
        events: Arc::new(JobSink {
            inner: state.events.sink(&user.user_id),
            db: state.db.clone(),
            job_id: job_id.to_string(),
            last: Mutex::new(Instant::now()),
        }),
        cancel,
    }
}

/// The config jobs work with: destinations still waiting for their credentials (restored without
/// them) are left out, so backups and checks carry on with the others and a purge that requires
/// one of them stays blocked.
fn usable_config(user: &UnlockedUser) -> Arc<malo_core::config::UserConfig> {
    let cfg = user.config();
    if cfg.destinations.iter().all(|d| d.complete()) {
        return cfg;
    }
    let mut usable = (*cfg).clone();
    usable.destinations.retain(|d| d.complete());
    Arc::new(usable)
}

/// A user restored from a kit rebuilds from its destinations at the first chance: when they log
/// in, or when a destination that came back without its credentials gets them.
pub fn start_restore_if_ready(state: &SharedState, user: &UnlockedUser) {
    let cfg = user.config();
    if !cfg.restore_pending || !cfg.destinations.iter().any(|d| d.complete()) {
        return;
    }
    if let Err(e) = submit(
        state,
        &user.user_id,
        JobKind::RebuildIndexAll,
        JobTrigger::Manual,
    ) {
        tracing::warn!(user = %user.username, "could not start the restore: {e:#}");
    }
}

fn new_job(kind: JobKind, trigger: JobTrigger, state: JobState) -> JobInfo {
    JobInfo {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        state,
        trigger,
        created_at: Utc::now(),
        started_at: None,
        finished_at: None,
        progress: JobProgress::default(),
        error: None,
        result: None,
    }
}

/// Records a job that came due while the user was locked.
pub fn record_skipped(
    state: &SharedState,
    user_id: &str,
    kind: JobKind,
) -> anyhow::Result<JobInfo> {
    let mut job = new_job(kind, JobTrigger::Scheduled, JobState::SkippedLocked);
    job.finished_at = Some(Utc::now());
    job.error = Some("user was locked".into());
    state.db.insert_job(user_id, &job)?;
    Ok(job)
}

/// Queues a job. Identical queued/running jobs are reused instead of duplicated.
pub fn submit(
    state: &SharedState,
    user_id: &str,
    kind: JobKind,
    trigger: JobTrigger,
) -> anyhow::Result<JobInfo> {
    if state.shutdown.is_cancelled() {
        anyhow::bail!("server is shutting down");
    }
    let Some(user) = state.keyring.get(user_id) else {
        return record_skipped(state, user_id, kind);
    };
    if let Some(existing) = state
        .db
        .active_jobs(user_id)?
        .into_iter()
        .find(|j| j.kind == kind)
    {
        return Ok(existing);
    }
    let job = new_job(kind, trigger, JobState::Queued);
    state.db.insert_job(user_id, &job)?;
    state
        .events
        .emit(user_id, SyncEvent::JobQueued { job: job.clone() });
    let cancel = user.cancel.child_token();
    state.jobs.running.lock().unwrap().insert(
        job.id.clone(),
        Active {
            user: user_id.to_string(),
            account: job.kind.account_id().map(str::to_string),
            cancel: cancel.clone(),
        },
    );
    let st = state.clone();
    let job2 = job.clone();
    tokio::spawn(async move {
        let id = job2.id.clone();
        let user_id = user.user_id.clone();
        run_job(&st, user, job2, cancel).await;
        st.jobs.running.lock().unwrap().remove(&id);
        let _ = user_id;
    });
    Ok(job)
}

async fn run_job(
    state: &SharedState,
    user: Arc<UnlockedUser>,
    mut job: JobInfo,
    cancel: CancellationToken,
) {
    let per_user = state
        .db
        .admin_settings()
        .map(|s| s.max_jobs_per_user)
        .unwrap_or(2) as usize;
    let slot = state.jobs.user_slot(&user.user_id, per_user);
    let lock = job
        .kind
        .account_id()
        .map(|a| state.jobs.account_lock(&user.user_id, a));
    let acquire = async {
        let s = slot.acquire_owned().await.expect("open");
        let w = state
            .jobs
            .workers
            .clone()
            .acquire_owned()
            .await
            .expect("open");
        // Per-account mutex: a purge waits for a running backup (and vice versa).
        let a = match &lock {
            Some(l) => Some(l.clone().lock_owned().await),
            None => None,
        };
        (s, w, a)
    };
    let guards = tokio::select! {
        g = acquire => Some(g),
        _ = cancel.cancelled() => None,
    };
    let finish = |job: &mut JobInfo, st: JobState, err: Option<String>| {
        job.state = st;
        job.error = err;
        job.finished_at = Some(Utc::now());
        let _ = state.db.update_job(job);
        state
            .events
            .emit(&user.user_id, SyncEvent::JobFinished { job: job.clone() });
    };
    let Some(_guards) = guards else {
        let reason = if user.cancel.is_cancelled() {
            "user was locked"
        } else {
            "cancelled"
        };
        finish(&mut job, JobState::Cancelled, Some(reason.into()));
        return;
    };
    if state
        .keyring
        .get(&user.user_id)
        .is_none_or(|u| !Arc::ptr_eq(&u, &user))
    {
        finish(
            &mut job,
            JobState::SkippedLocked,
            Some("user was locked".into()),
        );
        return;
    }
    job.state = JobState::Running;
    job.started_at = Some(Utc::now());
    let _ = state.db.update_job(&job);
    state
        .events
        .emit(&user.user_id, SyncEvent::JobStarted { job: job.clone() });

    let mut ctx = job_ctx(state, &user, &job.id, cancel.clone());
    // "Back up now" retries every pending message right away; scheduled runs respect backoff.
    ctx.manual = job.trigger == JobTrigger::Manual;
    let result = execute(state, &user, &ctx, &job.kind).await;
    if let Ok(Some((_, j))) = state.db.job(&job.id) {
        job.progress = j.progress;
    }
    match result {
        Ok(value) => {
            job.result = Some(value);
            finish(&mut job, JobState::Done, None);
            index_for_search_after(state, &user, &job.kind);
        }
        Err(e) if is_cancelled(&e) || cancel.is_cancelled() => {
            let reason = if user.cancel.is_cancelled() {
                "stopped: user was locked"
            } else {
                "cancelled"
            };
            finish(&mut job, JobState::Cancelled, Some(reason.into()));
        }
        Err(e) => {
            tracing::warn!(job = %job.id, "job failed: {e:#}");
            finish(&mut job, JobState::Failed, Some(format!("{e:#}")));
        }
    }
}

async fn execute(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    ctx: &JobCtx,
    kind: &JobKind,
) -> anyhow::Result<serde_json::Value> {
    use malo_core::{purge, rebuild, sync, verify};
    // Addresses are checked again when the job runs: a name may resolve differently by now.
    let refused = |e: crate::error::ApiErr| anyhow::anyhow!(e.message);
    if let JobKind::Backup { account_id }
    | JobKind::Purge { account_id }
    | JobKind::PurgeDryRun { account_id }
    | JobKind::DeleteMessages { account_id, .. } = kind
    {
        crate::net::check_account(state, ctx.account(account_id)?)
            .await
            .map_err(refused)?;
    }
    for d in &ctx.config.destinations {
        crate::net::check_destination(state, d)
            .await
            .map_err(refused)?;
    }
    Ok(match kind {
        JobKind::Backup { account_id } => {
            let account = ctx.account(account_id)?;
            anyhow::ensure!(
                !account.imported,
                "imported accounts have no server to back up"
            );
            let r = serde_json::to_value(sync::run_backup(ctx, account_id).await?)?;
            save_settings_copies(ctx, &user.config()).await;
            r
        }
        JobKind::Check { scope, deep } => {
            let repair = ctx.config.settings.auto_repair;
            let r = serde_json::to_value(verify::run_check(ctx, scope, *deep, repair).await?)?;
            save_settings_copies(ctx, &user.config()).await;
            r
        }
        JobKind::Repair { scope } => {
            serde_json::to_value(verify::run_check(ctx, scope, true, true).await?)?
        }
        JobKind::PurgeDryRun { account_id } => {
            let preview = purge::preview(ctx, account_id).await?;
            let account = ctx.account(account_id)?;
            user.index.kv_set(
                &format!("dryrun:{account_id}"),
                &policy_fingerprint(&account.policy),
            )?;
            serde_json::to_value(preview)?
        }
        JobKind::Purge { account_id } => {
            serde_json::to_value(purge::run_purge(ctx, account_id).await?)?
        }
        JobKind::SearchIndex => serde_json::to_value(malo_core::search::run_index(ctx).await?)?,
        JobKind::DeleteMessages {
            account_id,
            message_ids,
            scope,
        } => serde_json::to_value(
            purge::delete_selected(ctx, account_id, message_ids, *scope).await?,
        )?,
        JobKind::RebuildIndex { .. } | JobKind::RebuildIndexAll => {
            let from = match kind {
                JobKind::RebuildIndex { destination_id } => vec![destination_id.clone()],
                _ => ctx.destination_ids(),
            };
            // The first rebuild of a user restored from a kit also takes the settings over.
            let first_restore = user.config().restore_pending;
            if first_restore {
                user.update_config(|c| {
                    c.restore_pending = false;
                    Ok(())
                })
                .await?;
            }
            let (restored_accounts, restored_destinations) =
                restore_settings(state, user, ctx, &from, first_restore).await?;
            // Destinations that came back with the settings are scanned too, in a second pass.
            if restored_destinations > 0 && matches!(kind, JobKind::RebuildIndex { .. }) {
                submit(
                    state,
                    &user.user_id,
                    JobKind::RebuildIndexAll,
                    JobTrigger::Manual,
                )?;
            }
            let stats = match kind {
                JobKind::RebuildIndex { destination_id } => {
                    rebuild::rebuild_index(ctx, destination_id).await?
                }
                _ => rebuild::rebuild_all(ctx).await?,
            };
            if !stats.unknown_accounts.is_empty() {
                let markers = stats.unknown_accounts.clone();
                user.update_config(|cfg| {
                    for m in markers {
                        if cfg.account(&m.account_id).is_none() {
                            cfg.accounts.push(malo_core::config::Account {
                                revision: 1,
                                id: m.account_id.clone(),
                                name: format!("{} (imported)", m.name),
                                host: m.host.clone(),
                                port: 993,
                                tls: malo_api::TlsMode::Implicit,
                                accept_invalid_certs: false,
                                username: m.username.clone(),
                                auth: malo_api::AccountAuth::Password {
                                    password: "-".into(),
                                },
                                backup_interval_minutes: 60,
                                idle: false,
                                enabled: false,
                                smtp: None,
                                imported: true,
                                policy: Default::default(),
                            });
                        }
                    }
                    Ok(())
                })
                .await?;
                state.events.emit(&user.user_id, SyncEvent::AccountsChanged);
            }
            let mut v = serde_json::to_value(&stats)?;
            v["restored_accounts"] = restored_accounts.into();
            v["restored_destinations"] = restored_destinations.into();
            v
        }
    })
}

/// Queues the search-index job when a job left mail that isn't indexed for full-text search: mail
/// backed up before search existed, mail a backup only found already stored, or a rebuilt index.
fn index_for_search_after(state: &SharedState, user: &UnlockedUser, kind: &JobKind) {
    if !matches!(
        kind,
        JobKind::Backup { .. } | JobKind::RebuildIndex { .. } | JobKind::RebuildIndexAll
    ) {
        return;
    }
    index_if_pending(state, user);
}

/// Queues the search-index job when messages lack searchable text or the header data mail apps
/// fetch. Also called when a mail app logs in, so its first sync doesn't download every message.
pub(crate) fn index_if_pending(state: &SharedState, user: &UnlockedUser) {
    // Messages the last run couldn't read (no destination reachable) don't queue it again by
    // themselves; new ones do, and that run retries them too.
    let unavailable = user
        .index
        .kv_get(malo_core::search::UNAVAILABLE_KEY)
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0u64);
    if user.index.search_pending_count(None).unwrap_or(0) > unavailable {
        if let Err(e) = submit(
            state,
            &user.user_id,
            JobKind::SearchIndex,
            JobTrigger::Scheduled,
        ) {
            tracing::warn!("queueing the search index: {e:#}");
        }
    }
}

/// Keeps the encrypted settings copy on every destination current (best effort, after backups
/// and checks). A copy is only rewritten when the settings changed since it was written. It is
/// made from the whole config, destinations waiting for credentials included, and written to the
/// destinations the job can use.
async fn save_settings_copies(ctx: &JobCtx, full: &malo_core::config::UserConfig) {
    let (json, hash) = match full.settings_backup() {
        Ok(x) => x,
        Err(e) => return tracing::warn!("settings copy: {e:#}"),
    };
    for d in &ctx.config.destinations {
        let key = format!("settings_copy:{}", d.id);
        if ctx.index.kv_get(&key).ok().flatten().as_deref() == Some(hash.as_str()) {
            continue;
        }
        let written = async { ctx.store(&d.id)?.write_settings_backup(&json).await }.await;
        match written {
            Ok(()) => {
                let _ = ctx.index.kv_set(&key, &hash);
            }
            Err(e) => {
                tracing::warn!(destination = %d.name, "writing the settings copy failed: {e:#}")
            }
        }
    }
}

/// Same storage: scheme, prefix and every non-secret option match.
fn same_storage(a: &malo_core::config::Destination, b: &malo_core::config::Destination) -> bool {
    let public = |d: &malo_core::config::Destination| {
        d.options
            .iter()
            .filter(|(k, _)| !malo_core::config::is_secret_option(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>()
    };
    a.scheme == b.scheme && a.root == b.root && public(a) == public(b)
}

/// Brings back accounts and destinations from the newest settings copy on the given destinations:
/// with the recovery kit and one destination re-added by hand, everything else returns with its
/// old id (so backups continue in the same folders) and its credentials. Accounts found only as
/// "imported" are replaced by the full account. Purges always come back disarmed.
async fn restore_settings(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    ctx: &JobCtx,
    from: &[String],
    adopt_settings: bool,
) -> anyhow::Result<(u64, u64)> {
    use malo_core::config::SettingsBackup;
    let mut newest: Option<SettingsBackup> = None;
    for id in from {
        let read = async { ctx.store(id)?.read_settings_backup().await }.await;
        match read.and_then(|j| j.map(|j| SettingsBackup::parse(&j)).transpose()) {
            Ok(Some(b)) if newest.as_ref().is_none_or(|n| b.saved_at > n.saved_at) => {
                newest = Some(b)
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(destination = %id, "reading the settings copy failed: {e:#}"),
        }
    }
    let Some(mut backup) = newest else {
        return Ok((0, 0));
    };
    let saved_at = backup.saved_at;
    let removed = |id: &str| {
        user.index
            .kv_get(&format!("removed:{id}"))
            .ok()
            .flatten()
            .is_some()
    };
    backup.accounts.retain(|a| !removed(&a.id));
    backup.destinations.retain(|d| !removed(&d.id));
    let max_lock = crate::auth::max_lock_hours(state);
    let (accounts, destinations) = user
        .update_config(move |cfg| {
            let (mut na, mut nd) = (0u64, 0u64);
            if adopt_settings {
                let mut s = backup.settings.clone();
                s.auto_lock_hours = s.auto_lock_hours.clamp(1, max_lock);
                cfg.settings = s;
            }
            for d in backup.destinations {
                if cfg.destination(&d.id).is_some()
                    || cfg.destinations.iter().any(|x| same_storage(x, &d))
                {
                    continue;
                }
                cfg.destinations.push(d);
                nd += 1;
            }
            for mut a in backup.accounts {
                a.policy.armed = false;
                a.policy.armed_at = None;
                match cfg.account_mut(&a.id) {
                    Some(cur) if cur.imported => {
                        a.revision = cur.revision + 1;
                        *cur = a;
                        na += 1;
                    }
                    Some(_) => {}
                    None => {
                        cfg.accounts.push(a);
                        na += 1;
                    }
                }
            }
            Ok((na, nd))
        })
        .await?;
    if adopt_settings {
        // Check intervals may have changed.
        crate::scheduler::sync_schedules(state, user)?;
    }
    if accounts + destinations > 0 {
        crate::scheduler::sync_schedules(state, user)?;
        state.events.emit(&user.user_id, SyncEvent::AccountsChanged);
        let _ = user.index.audit(
            "settings_restored",
            None,
            &serde_json::json!({"accounts": accounts, "destinations": destinations, "saved_at": saved_at}),
        );
    }
    Ok((accounts, destinations))
}

/// Identifies a policy version; arming requires a dry run of exactly this version.
pub fn policy_fingerprint(p: &malo_api::PurgePolicy) -> String {
    let mut p = p.clone();
    p.armed = false;
    p.armed_at = None;
    malo_core::crypto::sha256_hex(serde_json::to_string(&p).unwrap().as_bytes())
}

/// Default scope used by scheduled checks.
pub fn all_scope() -> CheckScope {
    CheckScope::All
}
