//! Scheduled backups, integrity checks and purges; mandatory auto-lock; IMAP IDLE triggers.

use std::time::Duration;

use chrono::Utc;
use malo_api::{CheckScope, JobKind, JobTrigger, SyncEvent};
use tokio_util::sync::CancellationToken;

use crate::jobs;
use crate::keyring::UnlockedUser;
use crate::state::SharedState;

/// Rebuilds the schedule rows of a user from their config (called on unlock and config changes).
pub fn sync_schedules(state: &SharedState, user: &UnlockedUser) -> anyhow::Result<()> {
    let cfg = user.config();
    let now = Utc::now();
    let mut keep = Vec::new();
    for a in cfg.accounts.iter().filter(|a| a.enabled && !a.imported) {
        let key = format!("backup:{}", a.id);
        let secs = a.backup_interval_minutes.max(1) as i64 * 60;
        state.db.upsert_schedule(
            &user.user_id,
            &key,
            &JobKind::Backup {
                account_id: a.id.clone(),
            },
            secs,
            now,
        )?;
        keep.push(key);
        if a.policy.armed && a.policy.schedule_hours > 0 {
            let key = format!("purge:{}", a.id);
            let secs = a.policy.schedule_hours as i64 * 3600;
            state.db.upsert_schedule(
                &user.user_id,
                &key,
                &JobKind::Purge {
                    account_id: a.id.clone(),
                },
                secs,
                now + chrono::Duration::seconds(secs),
            )?;
            keep.push(key);
        }
    }
    if !cfg.destinations.is_empty() {
        for (key, hours, deep) in [
            ("check:quick", cfg.settings.quick_check_hours, false),
            ("check:deep", cfg.settings.deep_check_hours, true),
        ] {
            if hours > 0 {
                let secs = hours as i64 * 3600;
                state.db.upsert_schedule(
                    &user.user_id,
                    key,
                    &JobKind::Check {
                        scope: CheckScope::All,
                        deep,
                    },
                    secs,
                    now + chrono::Duration::seconds(secs),
                )?;
                keep.push(key.to_string());
            }
        }
    }
    state.db.retain_schedules(&user.user_id, &keep)?;
    Ok(())
}

/// Wipes a user's keys, ends their sessions and tells their GUI.
pub fn lock_user(state: &SharedState, user_id: &str, reason: &str) {
    let was = state.keyring.lock(user_id);
    let _ = state.db.delete_user_sessions(user_id);
    state.idle_watchers.lock().unwrap().retain(|(u, _), t| {
        if u == user_id {
            t.cancel();
            false
        } else {
            true
        }
    });
    if was {
        tracing::info!(user = user_id, "locked: {reason}");
        state.events.emit(
            user_id,
            SyncEvent::Locked {
                reason: reason.to_string(),
            },
        );
    }
}

pub async fn tick(state: &SharedState) {
    for user_id in state.keyring.expired() {
        lock_user(state, &user_id, "auto-lock period ended");
    }
    let now = Utc::now();
    let rows = match state.db.schedules(None) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("reading schedules: {e:#}");
            return;
        }
    };
    for (user_id, sched, interval) in rows {
        if sched.next_run > now {
            continue;
        }
        let next = now + chrono::Duration::seconds(interval.max(60));
        if let Err(e) = state.db.set_next_run(&user_id, &sched.key, next) {
            tracing::error!("updating schedule: {e:#}");
            continue;
        }
        if state
            .db
            .user(&user_id)
            .ok()
            .flatten()
            .is_none_or(|u| u.disabled)
        {
            continue;
        }
        let res = if state.keyring.get(&user_id).is_some() {
            jobs::submit(state, &user_id, sched.kind, JobTrigger::Scheduled).map(|_| ())
        } else {
            jobs::record_skipped(state, &user_id, sched.kind).map(|_| ())
        };
        if let Err(e) = res {
            tracing::error!(user = user_id, "scheduling {} failed: {e:#}", sched.key);
        }
    }
    reconcile_idle(state);
    let _ = state.db.prune_jobs(90);
}

pub fn spawn(state: SharedState) {
    let ms: u64 = std::env::var("MALO_SCHEDULER_TICK_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_millis(ms));
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = iv.tick() => tick(&state).await,
                _ = state.shutdown.cancelled() => return,
            }
        }
    });
}

/// Keeps one IDLE watcher on INBOX per unlocked user and IDLE-enabled account.
fn reconcile_idle(state: &SharedState) {
    let mut wanted = Vec::new();
    for uid in state.keyring.unlocked_ids() {
        if let Some(u) = state.keyring.get(&uid) {
            for a in u
                .config()
                .accounts
                .iter()
                .filter(|a| a.enabled && a.idle && !a.imported)
            {
                wanted.push((uid.clone(), a.id.clone()));
            }
        }
    }
    let mut watchers = state.idle_watchers.lock().unwrap();
    watchers.retain(|k, t| {
        let keep = wanted.contains(k) && !t.is_cancelled();
        if !keep {
            t.cancel();
        }
        keep
    });
    for key in wanted {
        if watchers.contains_key(&key) {
            continue;
        }
        let Some(user) = state.keyring.get(&key.0) else {
            continue;
        };
        let token = user.cancel.child_token();
        watchers.insert(key.clone(), token.clone());
        tokio::spawn(idle_loop(state.clone(), key.0, key.1, token));
    }
}

async fn idle_loop(
    state: SharedState,
    user_id: String,
    account_id: String,
    stop: CancellationToken,
) {
    let mut backoff = Duration::from_secs(30);
    while !stop.is_cancelled() {
        let Some(user) = state.keyring.get(&user_id) else {
            return;
        };
        let Some(account) = user.config().account(&account_id).cloned() else {
            return;
        };
        let tokens = user.tokens.clone();
        drop(user);
        let attempt = async {
            let mut conn = malo_core::imap::connect_unmetered(&account, tokens.as_ref()).await?;
            anyhow::ensure!(conn.caps.idle(), "server has no IDLE");
            conn.select("INBOX").await?;
            conn.idle_wait(Duration::from_secs(25 * 60)).await
        };
        let res = tokio::select! {
            r = attempt => r,
            _ = stop.cancelled() => return,
        };
        match res {
            Ok(true) => {
                backoff = Duration::from_secs(30);
                let _ = jobs::submit(
                    &state,
                    &user_id,
                    JobKind::Backup {
                        account_id: account_id.clone(),
                    },
                    JobTrigger::Scheduled,
                );
                // Let the burst settle before watching again.
                tokio::select! { _ = tokio::time::sleep(Duration::from_secs(5)) => {}, _ = stop.cancelled() => return }
            }
            Ok(false) => backoff = Duration::from_secs(30),
            Err(e) => {
                tracing::debug!(account = %account_id, "IDLE watcher: {e:#}");
                tokio::select! { _ = tokio::time::sleep(backoff) => {}, _ = stop.cancelled() => return }
                backoff = (backoff * 2).min(Duration::from_secs(30 * 60));
            }
        }
    }
}
