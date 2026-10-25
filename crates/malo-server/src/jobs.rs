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

pub fn fs_policy(state: &SharedState, user_id: &str) -> FsPolicy {
    let mut mounts = state.cfg.allowed_fs_mounts.clone();
    if let Ok(s) = state.db.admin_settings() {
        mounts.extend(s.allowed_fs_mounts.iter().map(PathBuf::from));
    }
    FsPolicy {
        user_root: UserPaths::new(&state.cfg.data_dir, user_id).local(),
        allowed_mounts: mounts,
        user_id: user_id.to_string(),
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
        config: user.config(),
        archive_key: user.secrets.archive_key.clone(),
        index: user.index.clone(),
        spool_dir: paths.spool(),
        spool_key: user.secrets.spool_key.clone(),
        fs: fs_policy(state, &user.user_id),
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
    Ok(match kind {
        JobKind::Backup { account_id } => {
            let account = ctx.account(account_id)?;
            anyhow::ensure!(
                !account.imported,
                "imported accounts have no server to back up"
            );
            serde_json::to_value(sync::run_backup(ctx, account_id).await?)?
        }
        JobKind::Check { scope, deep } => {
            let repair = ctx.config.settings.auto_repair;
            serde_json::to_value(verify::run_check(ctx, scope, *deep, repair).await?)?
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
        JobKind::RebuildIndex { .. } | JobKind::RebuildIndexAll => {
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
            serde_json::to_value(&stats)?
        }
    })
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
