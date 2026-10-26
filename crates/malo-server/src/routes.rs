//! REST handlers. Every handler is scoped to the session's user; admin routes never touch user data.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use chrono::Utc;
use malo_api::*;
use malo_core::config::{Account, Destination};
use malo_core::ctx::JobCtx;
use malo_core::index::{MessageQuery, MessageSort, ReplicaStatus};
use malo_core::oauth::TokenSource;
use malo_core::store::Store;
use malo_core::{crypto, imap, oauth, viewer};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::auth::{self, Admin, AuthUser, Unlocked};
use crate::error::{ApiErr, ApiResult};
use crate::jobs::{self, policy_fingerprint};
use crate::keyring::UnlockedUser;
use crate::scheduler;
use crate::state::SharedState;

/// Edit failures: a stale revision (another device changed it) is a 409, anything else a 400.
fn edit_error(e: anyhow::Error) -> ApiErr {
    if e.downcast_ref::<malo_core::config::StaleRevision>()
        .is_some()
    {
        ApiErr::conflict(format!("{e:#}"))
    } else {
        ApiErr::bad_request(format!("{e:#}"))
    }
}

#[derive(Deserialize)]
pub struct RevisionQuery {
    pub revision: Option<u64>,
}

/// Bookkeeping after a change is committed must not turn the response into an error: the change
/// happened. Failures are logged instead (e.g. audit rows on a full disk).
fn best_effort<T>(r: anyhow::Result<T>, what: &str) {
    if let Err(e) = r {
        tracing::warn!("{what} failed after the change was saved: {e:#}");
    }
}

fn ctx_for(state: &SharedState, user: &Arc<UnlockedUser>) -> JobCtx {
    jobs::job_ctx(state, user, "api", CancellationToken::new())
}

// ───────────────────────────── public ─────────────────────────────

pub async fn status(State(state): State<SharedState>) -> ApiResult<Json<ServerStatus>> {
    Ok(Json(ServerStatus {
        version: env!("CARGO_PKG_VERSION").into(),
        needs_setup: state.db.user_count()? == 0,
        self_registration: state.db.admin_settings()?.self_registration,
        cert_fingerprint: state.cert_fingerprint.clone(),
    }))
}

/// For load balancers and the Docker health check: says nothing about the users.
pub async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        sealed_users: None,
        unlocked_users: None,
    })
}

/// [`healthz`] with how many users are unlocked, for administrators.
pub async fn admin_health(
    State(state): State<SharedState>,
    _admin: Admin,
) -> ApiResult<Json<Health>> {
    let total = state.db.user_count()? as u32;
    let unlocked = state.keyring.count() as u32;
    Ok(Json(Health {
        status: "ok".into(),
        sealed_users: Some(total.saturating_sub(unlocked)),
        unlocked_users: Some(unlocked),
    }))
}

pub async fn presets() -> Json<Vec<AccountPreset>> {
    Json(oauth::presets())
}

// ───────────────────────────── settings ─────────────────────────────

pub async fn get_settings(u: Unlocked) -> Json<UserSettings> {
    Json(u.user.config().settings.clone())
}

pub async fn put_settings(
    State(state): State<SharedState>,
    u: Unlocked,
    Json(mut s): Json<UserSettings>,
) -> ApiResult<Json<UserSettings>> {
    let max = auth::max_lock_hours(&state);
    s.auto_lock_hours = s.auto_lock_hours.clamp(1, max);
    let s2 = s.clone();
    u.user
        .update_config(move |cfg| {
            cfg.settings = s2;
            Ok(())
        })
        .await?;
    // A shorter auto-lock applies immediately; it can never be extended without logging in again.
    {
        let mut exp = u.user.expires_at.lock().unwrap();
        let new = u.user.unlocked_at + chrono::Duration::hours(s.auto_lock_hours as i64);
        if new < *exp {
            *exp = new;
        }
    }
    scheduler::sync_schedules(&state, &u.user)?;
    Ok(Json(s))
}

// ───────────────────────────── accounts ─────────────────────────────

fn account_view(
    state: &SharedState,
    user: &UnlockedUser,
    a: &Account,
) -> anyhow::Result<AccountView> {
    let mut v = a.view();
    // Statistics are best effort: an unreadable index must not hide the account itself.
    let (count, bytes) = user.index.account_stats(&a.id).unwrap_or_default();
    v.message_count = count;
    v.stored_bytes = bytes;
    if let Some((at, ok)) = user.index.last_run("backup", &a.id).ok().flatten() {
        v.last_backup = Some(at);
        v.last_backup_ok = Some(ok);
    }
    for (_, s, _) in state.db.schedules(Some(&user.user_id))? {
        if s.key == format!("backup:{}", a.id) {
            v.next_backup = Some(s.next_run);
        }
        if s.key == format!("purge:{}", a.id) {
            v.next_purge = Some(s.next_run);
        }
    }
    let mut failing = std::collections::HashMap::new();
    for d in &a.policy.required_destinations {
        // Best effort like the statistics (the change is already committed when this runs);
        // an unreadable status shows as blocked — purge itself re-checks and fails closed.
        match user.index.destination_failing(d) {
            Ok(Some(r)) => {
                failing.insert(d.clone(), r);
            }
            Ok(None) => {}
            Err(_) => {
                failing.insert(d.clone(), "status unavailable".into());
            }
        }
    }
    let dests: Vec<String> = user
        .config()
        .destinations
        .iter()
        .map(|d| d.id.clone())
        .collect();
    v.purge_blocked = malo_core::purge::blocked_reason(&a.policy, &failing, &dests);
    Ok(v)
}

pub async fn list_accounts(
    State(state): State<SharedState>,
    u: Unlocked,
) -> ApiResult<Json<Vec<AccountView>>> {
    let cfg = u.user.config();
    Ok(Json(
        cfg.accounts
            .iter()
            .map(|a| account_view(&state, &u.user, a))
            .collect::<anyhow::Result<_>>()?,
    ))
}

pub async fn get_account(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<Json<AccountView>> {
    let cfg = u.user.config();
    let a = cfg
        .account(&id)
        .ok_or_else(|| ApiErr::not_found("account"))?;
    Ok(Json(account_view(&state, &u.user, a)?))
}

pub async fn create_account(
    State(state): State<SharedState>,
    u: Unlocked,
    Json(input): Json<AccountInput>,
) -> ApiResult<(StatusCode, Json<AccountView>)> {
    let limit = u
        .auth
        .user
        .max_accounts
        .unwrap_or(state.db.admin_settings()?.default_max_accounts);
    let id = uuid::Uuid::new_v4().to_string();
    let account = Account::from_input(id.clone(), input, None)
        .map_err(|e| ApiErr::bad_request(format!("{e:#}")))?;
    crate::net::check_account(&state, &account).await?;
    let acc2 = account.clone();
    // Counted under the config lock, so two requests at once can't both pass the limit.
    let added = u
        .user
        .update_config(move |cfg| {
            if cfg.accounts.len() as u32 >= limit {
                return Ok(false);
            }
            cfg.accounts.push(acc2);
            Ok(true)
        })
        .await?;
    if !added {
        return Err(ApiErr::forbidden(format!(
            "account limit of {limit} reached"
        )));
    }
    scheduler::sync_schedules(&state, &u.user)?;
    state
        .events
        .emit(&u.user.user_id, SyncEvent::AccountsChanged);
    Ok((
        StatusCode::CREATED,
        Json(account_view(&state, &u.user, &account)?),
    ))
}

pub async fn update_account(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
    Json(input): Json<AccountInput>,
) -> ApiResult<Json<AccountView>> {
    if let Some(prev) = u.user.config().account(&id) {
        let mut probe = prev.clone();
        probe.host = input.host.trim().to_string();
        probe.port = input.port;
        probe.smtp = input.smtp.clone();
        crate::net::check_account(&state, &probe).await?;
    }
    let updated = u
        .user
        .update_config(move |cfg| {
            let prev = cfg
                .account(&id)
                .ok_or_else(|| anyhow::anyhow!("unknown account"))?
                .clone();
            malo_core::config::check_revision(input.revision, prev.revision)?;
            let mut next = Account::from_input(id.clone(), input, Some(&prev))?;
            // Changing where we connect invalidates the purge arming.
            if next.host != prev.host || next.username != prev.username {
                next.policy.armed = false;
                next.policy.armed_at = None;
            }
            // An imported account (found on a destination, without credentials) becomes a normal
            // one once it has sign-in details again, and keeps its id, folder and history.
            next.imported = prev.imported && next.auth == prev.auth;
            *cfg.account_mut(&id).unwrap() = next.clone();
            Ok(next)
        })
        .await
        .map_err(edit_error)?;
    u.user.tokens.invalidate(&updated.id);
    scheduler::sync_schedules(&state, &u.user)?;
    state
        .events
        .emit(&u.user.user_id, SyncEvent::AccountsChanged);
    Ok(Json(account_view(&state, &u.user, &updated)?))
}

pub async fn delete_account(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if u.user.config().account(&id).is_none() {
        return Err(ApiErr::not_found("account"));
    }
    // Backups stay on the destinations; only the local index rows go — after the config commit:
    // a failed commit must leave the account whole, including the records of mail already purged
    // from the server (a backup cannot bring those back). Rows a failed cleanup leaves behind are
    // pruned at the next unlock.
    // A backup still running would rewrite this account's manifests from the emptied index and
    // erase the destinations' record of mail already purged from the server: stop it first.
    let _quiet = state.jobs.quiesce_account(&u.user.user_id, &id).await;
    let id2 = id.clone();
    u.user
        .update_config(move |cfg| {
            cfg.accounts.retain(|a| a.id != id2);
            Ok(())
        })
        .await?;
    best_effort(u.user.index.delete_account(&id), "index cleanup");
    best_effort(
        state.db.delete_mail_login(&u.user.user_id, &id),
        "mail login removal",
    );
    // A settings copy written before the removal must not bring the account back in a rebuild.
    best_effort(
        u.user.index.kv_set(&format!("removed:{id}"), "1"),
        "removal record",
    );
    best_effort(
        u.user
            .index
            .audit("account_deleted", Some(&id), &serde_json::json!({})),
        "audit",
    );
    scheduler::sync_schedules(&state, &u.user)?;
    state
        .events
        .emit(&u.user.user_id, SyncEvent::AccountsChanged);
    Ok(StatusCode::NO_CONTENT)
}

async fn test_account(user: &UnlockedUser, account: &Account) -> ConnectionTest {
    let mut t = ConnectionTest {
        ok: false,
        error: None,
        capabilities: vec![],
        warnings: vec![],
        mailboxes: vec![],
        gmail: false,
        uidplus: false,
    };
    let res = async {
        let mut conn = imap::connect(account, user.tokens.as_ref()).await?;
        t.capabilities = conn.caps.list();
        t.gmail = conn.caps.gmail();
        t.uidplus = conn.caps.uidplus();
        let list = conn.list_mailboxes().await?;
        t.mailboxes = list
            .iter()
            .filter(|m| m.selectable)
            .map(|m| malo_core::layout::decode_utf7(&m.name))
            .collect();
        conn.logout().await;
        anyhow::Ok(())
    }
    .await;
    match res {
        Ok(()) => {
            t.ok = true;
            if !t.uidplus {
                t.warnings
                    .push("Server lacks UIDPLUS: purging is disabled for this account.".into());
            }
            if !t.capabilities.iter().any(|c| c == "IDLE") {
                t.warnings
                    .push("Server lacks IDLE: near-real-time backups are unavailable.".into());
            }
            if account.accept_invalid_certs {
                t.warnings
                    .push("Certificate verification is disabled for this account.".into());
            }
        }
        Err(e) => t.error = Some(format!("{e:#}")),
    }
    t
}

pub async fn test_saved_account(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<Json<ConnectionTest>> {
    let cfg = u.user.config();
    let a = cfg
        .account(&id)
        .ok_or_else(|| ApiErr::not_found("account"))?;
    crate::net::check_account(&state, a).await?;
    Ok(Json(test_account(&u.user, a).await))
}

#[derive(Deserialize)]
pub struct TestQuery {
    /// Existing account whose secrets fill redacted fields.
    pub id: Option<String>,
}

pub async fn test_new_account(
    State(state): State<SharedState>,
    u: Unlocked,
    Query(q): Query<TestQuery>,
    Json(input): Json<AccountInput>,
) -> ApiResult<Json<ConnectionTest>> {
    let cfg = u.user.config();
    let prev = q.id.as_deref().and_then(|id| cfg.account(id));
    let id = format!("test-{}", uuid::Uuid::new_v4());
    let account = Account::from_input(id.clone(), input, prev)
        .map_err(|e| ApiErr::bad_request(format!("{e:#}")))?;
    crate::net::check_account(&state, &account).await?;
    let res = test_account(&u.user, &account).await;
    u.user.tokens.invalidate(&id);
    Ok(Json(res))
}

pub async fn put_policy(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
    Query(rev): Query<RevisionQuery>,
    Json(mut policy): Json<PurgePolicy>,
) -> ApiResult<Json<AccountView>> {
    let cfg = u.user.config();
    for d in &policy.required_destinations {
        if cfg.destination(d).is_none() {
            return Err(ApiErr::bad_request(format!("unknown destination {d}")));
        }
    }
    policy.required_destinations.sort();
    policy.required_destinations.dedup();
    // Any policy change disarms.
    policy.armed = false;
    policy.armed_at = None;
    let p2 = policy.clone();
    let acc = u
        .user
        .update_config(move |cfg| {
            let a = cfg
                .account_mut(&id)
                .ok_or_else(|| anyhow::anyhow!("unknown account"))?;
            malo_core::config::check_revision(rev.revision, a.revision)?;
            a.policy = p2;
            a.revision += 1;
            Ok(a.clone())
        })
        .await
        .map_err(|e| {
            if e.to_string().contains("unknown account") {
                ApiErr::not_found(e.to_string())
            } else {
                edit_error(e)
            }
        })?;
    best_effort(
        u.user.index.audit(
            "policy_changed",
            Some(&acc.id),
            &serde_json::to_value(&policy).unwrap(),
        ),
        "audit",
    );
    scheduler::sync_schedules(&state, &u.user)?;
    Ok(Json(account_view(&state, &u.user, &acc)?))
}

pub async fn arm_policy(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
    Json(req): Json<ArmRequest>,
) -> ApiResult<Json<AccountView>> {
    let cfg = u.user.config();
    let a = cfg
        .account(&id)
        .ok_or_else(|| ApiErr::not_found("account"))?;
    if req.confirm_name != a.name {
        return Err(ApiErr::bad_request(
            "type the account name exactly to confirm",
        ));
    }
    if a.policy.required_destinations.is_empty() {
        return Err(ApiErr::bad_request(
            "select at least one required destination",
        ));
    }
    if u.user.index.kv_get(&format!("dryrun:{id}"))? != Some(policy_fingerprint(&a.policy)) {
        return Err(ApiErr::conflict(
            "run a dry run of the current policy first",
        ));
    }
    let acc = u
        .user
        .update_config(move |cfg| {
            let a = cfg.account_mut(&id).unwrap();
            a.policy.armed = true;
            a.policy.armed_at = Some(Utc::now());
            a.revision += 1;
            Ok(a.clone())
        })
        .await?;
    best_effort(
        u.user.index.audit(
            "policy_armed",
            Some(&acc.id),
            &serde_json::to_value(&acc.policy).unwrap(),
        ),
        "audit",
    );
    scheduler::sync_schedules(&state, &u.user)?;
    Ok(Json(account_view(&state, &u.user, &acc)?))
}

pub async fn disarm_policy(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<Json<AccountView>> {
    let acc = u
        .user
        .update_config(move |cfg| {
            let a = cfg
                .account_mut(&id)
                .ok_or_else(|| anyhow::anyhow!("unknown account"))?;
            a.policy.armed = false;
            a.policy.armed_at = None;
            a.revision += 1;
            Ok(a.clone())
        })
        .await
        .map_err(|e| ApiErr::not_found(e.to_string()))?;
    best_effort(
        u.user
            .index
            .audit("policy_disarmed", Some(&acc.id), &serde_json::json!({})),
        "audit",
    );
    scheduler::sync_schedules(&state, &u.user)?;
    Ok(Json(account_view(&state, &u.user, &acc)?))
}

// ───────────────────────────── destinations ─────────────────────────────

fn destination_view(user: &UnlockedUser, d: &Destination) -> anyhow::Result<DestinationView> {
    let mut v = d.view();
    let (count, bytes) = user.index.replica_stats(&d.id).unwrap_or_default();
    v.object_count = count;
    v.stored_bytes = bytes;
    v.health = user
        .index
        .reports(1)
        .unwrap_or_default()
        .into_iter()
        .next()
        .and_then(|r| {
            r.destinations
                .into_iter()
                .find(|h| h.destination_id == d.id)
        });
    Ok(v)
}

pub async fn list_destinations(u: Unlocked) -> ApiResult<Json<Vec<DestinationView>>> {
    let cfg = u.user.config();
    Ok(Json(
        cfg.destinations
            .iter()
            .map(|d| destination_view(&u.user, d))
            .collect::<anyhow::Result<_>>()?,
    ))
}

pub async fn create_destination(
    State(state): State<SharedState>,
    u: Unlocked,
    Json(input): Json<DestinationInput>,
) -> ApiResult<(StatusCode, Json<DestinationView>)> {
    let id = uuid::Uuid::new_v4().to_string();
    let d = Destination::from_input(id, input, None)
        .map_err(|e| ApiErr::bad_request(format!("{e:#}")))?;
    crate::net::check_destination(&state, &d).await?;
    // Validate configuration (including fs confinement) before saving.
    Store::open(
        &d,
        &u.user.secrets.archive_key,
        &jobs::fs_policy(&state, &u.user),
    )
    .map_err(|e| ApiErr::bad_request(format!("{e:#}")))?;
    // Existing verified messages need a replica on the new destination. Done before the config
    // commit: if it fails, nothing changed (marking messages "stored" without a new destination is
    // harmless — the next backup marks them verified again).
    u.user.index.with(|c| {
        c.execute(
            "UPDATE messages SET state='stored' WHERE state='verified'",
            [],
        )
    })?;
    let d2 = d.clone();
    u.user
        .update_config(move |cfg| {
            cfg.destinations.push(d2);
            Ok(())
        })
        .await?;
    scheduler::sync_schedules(&state, &u.user)?;
    Ok((StatusCode::CREATED, Json(destination_view(&u.user, &d)?)))
}

pub async fn update_destination(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
    Json(input): Json<DestinationInput>,
) -> ApiResult<Json<DestinationView>> {
    let cfg = u.user.config();
    let prev = cfg
        .destination(&id)
        .ok_or_else(|| ApiErr::not_found("destination"))?
        .clone();
    malo_core::config::check_revision(input.revision, prev.revision).map_err(edit_error)?;
    let next = Destination::from_input(id.clone(), input, Some(&prev))
        .map_err(|e| ApiErr::bad_request(format!("{e:#}")))?;
    if next.encrypt != prev.encrypt || next.scheme != prev.scheme || next.root != prev.root {
        return Err(ApiErr::bad_request("scheme, root and encryption can't change on an existing destination; add a new one instead"));
    }
    crate::net::check_destination(&state, &next).await?;
    Store::open(
        &next,
        &u.user.secrets.archive_key,
        &jobs::fs_policy(&state, &u.user),
    )
    .map_err(|e| ApiErr::bad_request(format!("{e:#}")))?;
    let n2 = next.clone();
    let based_on = prev.revision;
    u.user
        .update_config(move |cfg| {
            let cur = cfg
                .destinations
                .iter_mut()
                .find(|d| d.id == id)
                .ok_or_else(|| anyhow::anyhow!("unknown destination"))?;
            // Re-checked under the config lock: another device may have saved in between.
            malo_core::config::check_revision(Some(based_on), cur.revision)?;
            *cur = n2;
            Ok(())
        })
        .await
        .map_err(edit_error)?;
    Ok(Json(destination_view(&u.user, &next)?))
}

pub async fn delete_destination(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if u.user.config().destination(&id).is_none() {
        return Err(ApiErr::not_found("destination"));
    }
    // Replica rows go after the config commit: a failed commit must not make Malo forget copies
    // of mail already purged from the server. Leftovers are pruned at the next unlock.
    let id2 = id.clone();
    u.user
        .update_config(move |cfg| {
            cfg.destinations.retain(|d| d.id != id2);
            for a in cfg.accounts.iter_mut() {
                if a.policy.required_destinations.contains(&id2) {
                    a.policy.required_destinations.retain(|d| d != &id2);
                    a.policy.armed = false;
                    a.policy.armed_at = None;
                }
            }
            Ok(())
        })
        .await?;
    best_effort(
        u.user.index.delete_replicas_for_destination(&id),
        "index cleanup",
    );
    best_effort(
        u.user.index.kv_set(&format!("removed:{id}"), "1"),
        "removal record",
    );
    best_effort(
        u.user.index.audit(
            "destination_removed",
            None,
            &serde_json::json!({"destination": id}),
        ),
        "audit",
    );
    scheduler::sync_schedules(&state, &u.user)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn test_saved_destination(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<Json<DestinationTest>> {
    let cfg = u.user.config();
    let d = cfg
        .destination(&id)
        .ok_or_else(|| ApiErr::not_found("destination"))?;
    crate::net::check_destination(&state, d).await?;
    Ok(Json(test_destination(&state, &u.user, d).await))
}

pub async fn test_new_destination(
    State(state): State<SharedState>,
    u: Unlocked,
    Query(q): Query<TestQuery>,
    Json(input): Json<DestinationInput>,
) -> ApiResult<Json<DestinationTest>> {
    let cfg = u.user.config();
    let prev = q.id.as_deref().and_then(|id| cfg.destination(id));
    let d = Destination::from_input("test".into(), input, prev)
        .map_err(|e| ApiErr::bad_request(format!("{e:#}")))?;
    crate::net::check_destination(&state, &d).await?;
    Ok(Json(test_destination(&state, &u.user, &d).await))
}

async fn test_destination(
    state: &SharedState,
    user: &UnlockedUser,
    d: &Destination,
) -> DestinationTest {
    match Store::open(d, &user.secrets.archive_key, &jobs::fs_policy(state, user)) {
        Ok(store) => store.test().await,
        Err(e) => DestinationTest {
            ok: false,
            error: Some(format!("{e:#}")),
            write_ms: 0,
            read_ms: 0,
        },
    }
}

// ───────────────────────────── jobs ─────────────────────────────

pub async fn create_job(
    State(state): State<SharedState>,
    u: Unlocked,
    Json(req): Json<CreateJobRequest>,
) -> ApiResult<(StatusCode, Json<JobInfo>)> {
    let cfg = u.user.config();
    match &req.kind {
        JobKind::Backup { account_id }
        | JobKind::PurgeDryRun { account_id }
        | JobKind::Purge { account_id } => {
            cfg.account(account_id)
                .ok_or_else(|| ApiErr::not_found("account"))?;
        }
        JobKind::RebuildIndex { destination_id } => {
            cfg.destination(destination_id)
                .ok_or_else(|| ApiErr::not_found("destination"))?;
        }
        JobKind::Check { scope, .. } | JobKind::Repair { scope } => match scope {
            CheckScope::Account { account_id } => {
                cfg.account(account_id)
                    .ok_or_else(|| ApiErr::not_found("account"))?;
            }
            CheckScope::Destination { destination_id } => {
                cfg.destination(destination_id)
                    .ok_or_else(|| ApiErr::not_found("destination"))?;
            }
            CheckScope::All => {}
        },
        JobKind::RebuildIndexAll | JobKind::SearchIndex => {}
        JobKind::DeleteMessages {
            account_id,
            message_ids,
            ..
        } => {
            cfg.account(account_id)
                .ok_or_else(|| ApiErr::not_found("account"))?;
            if message_ids.is_empty() || message_ids.len() > malo_api::MAX_DELETE_BATCH {
                return Err(ApiErr::bad_request(format!(
                    "select between 1 and {} messages per delete",
                    malo_api::MAX_DELETE_BATCH
                )));
            }
        }
    }
    if let JobKind::Purge { account_id } = &req.kind {
        if !cfg.account(account_id).is_some_and(|a| a.policy.armed) {
            return Err(ApiErr::conflict("arm the purge policy first"));
        }
    }
    let job = jobs::submit(&state, &u.user.user_id, req.kind, JobTrigger::Manual)?;
    Ok((StatusCode::ACCEPTED, Json(job)))
}

#[derive(Deserialize)]
pub struct LimitQuery {
    pub limit: Option<u32>,
    pub account: Option<String>,
}

pub async fn list_jobs(
    State(state): State<SharedState>,
    auth: AuthUser,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<Vec<JobInfo>>> {
    Ok(Json(
        state
            .db
            .jobs(&auth.user.id, q.limit.unwrap_or(100).min(1000))?,
    ))
}

pub async fn get_job(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<JobInfo>> {
    match state.db.job(&id)? {
        Some((owner, job)) if owner == auth.user.id => Ok(Json(job)),
        _ => Err(ApiErr::not_found("job")),
    }
}

pub async fn cancel_job(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    match state.db.job(&id)? {
        Some((owner, job)) if owner == auth.user.id => {
            if job.state.is_finished() || !state.jobs.cancel(&id) {
                return Err(ApiErr::conflict("job is not running"));
            }
            Ok(StatusCode::ACCEPTED)
        }
        _ => Err(ApiErr::not_found("job")),
    }
}

pub async fn list_schedules(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> ApiResult<Json<Vec<ScheduledJob>>> {
    Ok(Json(
        state
            .db
            .schedules(Some(&auth.user.id))?
            .into_iter()
            .map(|(_, s, _)| s)
            .collect(),
    ))
}

// ───────────────────────────── messages ─────────────────────────────

#[derive(Deserialize)]
pub struct MessagesQuery {
    pub account: Option<String>,
    pub mailbox: Option<String>,
    pub uidvalidity: Option<u32>,
    #[serde(default)]
    pub new: bool,
    pub q: Option<String>,
    pub state: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub max_id: Option<i64>,
    /// newest (default), oldest, sender, largest, relevance (with `q`)
    pub sort: Option<String>,
    /// Search column for words of `q` without one: subject, sender, recipients, body, attachments.
    pub field: Option<String>,
    /// Gmail category: primary, social, promotions, updates, forums.
    pub category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SuggestQuery {
    /// from, to or file
    pub field: String,
    #[serde(default)]
    pub prefix: String,
    pub account: Option<String>,
}

/// Values for a search operator, as the user types it.
pub async fn search_suggest(
    u: Unlocked,
    Query(q): Query<SuggestQuery>,
) -> ApiResult<Json<Vec<malo_api::SearchSuggestion>>> {
    Ok(Json(u.user.index.search_suggest(
        &q.field,
        &q.prefix,
        q.account.as_deref(),
        8,
    )?))
}

pub async fn list_mailboxes(
    u: Unlocked,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<Vec<MailboxInfo>>> {
    Ok(Json(u.user.index.mailbox_infos(q.account.as_deref())?))
}

pub async fn list_messages(
    u: Unlocked,
    Query(q): Query<MessagesQuery>,
) -> ApiResult<Json<MessageList>> {
    let mailbox = match (&q.account, &q.mailbox) {
        (Some(a), Some(m)) => u
            .user
            .index
            .mailboxes(Some(a), false)?
            .into_iter()
            .filter(|mb| &mb.name == m && q.uidvalidity.is_none_or(|v| v == mb.uidvalidity))
            .max_by_key(|mb| mb.current)
            .map(|mb| mb.id)
            .or(Some(-1)),
        _ => None,
    };
    let states = q
        .state
        .as_deref()
        .map(|s| s.split(',').map(MessageState::parse).collect())
        .unwrap_or_default();
    let dests = u.user.config().destinations.len() as u32;
    let unindexed = match q.q.as_deref().map(str::trim) {
        Some(t) if !t.is_empty() => u.user.index.search_pending_count(q.account.as_deref())?,
        _ => 0,
    };
    let (total, messages) = u.user.index.list_messages(
        &MessageQuery {
            account: q.account,
            mailbox,
            new_only: q.new,
            text: q.q,
            states,
            limit: q.limit.unwrap_or(100).min(1000),
            offset: q.offset.unwrap_or(0),
            max_id: q.max_id,
            sort: q
                .sort
                .as_deref()
                .map(MessageSort::parse)
                .unwrap_or_default(),
            field: q.field,
            category: q.category,
        },
        dests,
    )?;
    Ok(Json(MessageList {
        total,
        messages,
        unindexed,
    }))
}

pub async fn mark_reviewed(u: Unlocked, Json(req): Json<ReviewedRequest>) -> ApiResult<Json<u64>> {
    let n = if req.all {
        u.user
            .index
            .mark_reviewed(&[], Some(req.account_id.as_deref()))?
    } else {
        u.user.index.set_reviewed(&req.ids, req.reviewed)?
    };
    Ok(Json(n))
}

pub async fn get_message(u: Unlocked, Path(id): Path<i64>) -> ApiResult<Json<MessageSummary>> {
    let dests = u.user.config().destinations.len() as u32;
    Ok(Json(
        u.user
            .index
            .summary(id, dests)?
            .ok_or_else(|| ApiErr::not_found("message"))?,
    ))
}

/// The conversation of a message, oldest first.
pub async fn message_thread(
    u: Unlocked,
    Path(id): Path<i64>,
) -> ApiResult<Json<Vec<MessageSummary>>> {
    let dests = u.user.config().destinations.len() as u32;
    let thread = u.user.index.thread(id, dests)?;
    if thread.is_empty() {
        return Err(ApiErr::not_found("message"));
    }
    Ok(Json(thread))
}

/// Sends a message written in Malo through the account's SMTP server, and saves the sent copy
/// in the account's Sent mailbox (Gmail files it by itself).
pub async fn send_message(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(account_id): Path<String>,
    Json(req): Json<SendRequest>,
) -> ApiResult<Json<SendResult>> {
    use malo_core::compose::{self, Attachment, Draft};
    let account = u
        .user
        .config()
        .account(&account_id)
        .cloned()
        .ok_or_else(|| ApiErr::not_found("account"))?;
    let smtp = account.smtp.clone().ok_or_else(|| {
        ApiErr::bad_request(format!(
            "Sending isn't set up for {}: add its outgoing (SMTP) server under Accounts",
            account.name
        ))
    })?;
    crate::net::check_smtp(&state, &smtp).await?;
    let from = req.from.clone().unwrap_or_else(|| account.username.clone());
    let list = |v: &[String]| -> ApiResult<Vec<compose::Mailbox>> {
        v.iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| compose::parse_mailbox(s).map_err(|e| ApiErr::bad_request(format!("{e:#}"))))
            .collect()
    };
    let in_reply_to = match req.in_reply_to {
        Some(id) => Some(load_raw(&state, &u.user, id).await?),
        None => None,
    };
    let attachments = match req.attachments_of {
        Some(id) => {
            let raw = load_raw(&state, &u.user, id).await?;
            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Attachment>> {
                let n = viewer::render(id, &raw, false, false)?.attachments.len() as u32;
                (0..n)
                    .map(|i| {
                        let (filename, content_type, data) = viewer::attachment(&raw, i)?;
                        Ok(Attachment {
                            filename,
                            content_type,
                            data,
                        })
                    })
                    .collect()
            })
            .await
            .map_err(|e| anyhow::anyhow!(e))??
        }
        None => vec![],
    };
    let draft = Draft {
        from: compose::parse_mailbox(&from).map_err(|_| {
            ApiErr::bad_request(format!(
                "“{from}” isn't an email address: enter the address to send from"
            ))
        })?,
        to: list(&req.to)?,
        cc: list(&req.cc)?,
        bcc: list(&req.bcc)?,
        subject: req.subject.clone(),
        body: req.body.clone(),
        in_reply_to,
        attachments,
    };
    let built = compose::build(&draft).map_err(|e| ApiErr::bad_request(format!("{e:#}")))?;
    let msg = malo_core::smtp::Message {
        from: &draft.from.address,
        to: &built.recipients,
        data: &built.data,
    };
    let tokens = u.user.tokens.clone();
    match malo_core::smtp::send(&account, &smtp, tokens.as_ref(), &msg).await {
        Ok(()) => {}
        Err(malo_core::smtp::SendError::Rejected(r)) => {
            return Err(ApiErr::bad_request(format!(
                "{} refused the message: {} {}",
                smtp.host, r.code, r.text
            )))
        }
        Err(malo_core::smtp::SendError::Failed(e)) => {
            return Err(ApiErr::bad_request(format!(
                "Couldn't send through {}: {e:#}",
                smtp.host
            )))
        }
    }
    tracing::info!(account = %account.id, recipients = built.recipients.len(), "sent a message written in Malo");
    // Gmail (it has an All Mail mailbox) keeps sent mail by itself; other servers get a copy in
    // their Sent mailbox, like a mail app would save it.
    let boxes = u.user.index.mailboxes(Some(&account.id), true)?;
    let gmail = boxes
        .iter()
        .any(|b| b.special_use.as_deref() == Some("\\All"));
    let sent = boxes
        .iter()
        .find(|b| b.special_use.as_deref() == Some("\\Sent"))
        .map(|b| b.name.clone());
    let mut saved_to = None;
    if let (false, Some(sent)) = (gmail, sent) {
        let res = async {
            let mut conn = imap::connect(&account, tokens.as_ref()).await?;
            conn.session
                .append(&sent, Some("(\\Seen)"), None, &built.data)
                .await?;
            conn.logout().await;
            anyhow::Ok(())
        }
        .await;
        match res {
            Ok(()) => saved_to = Some(malo_core::layout::decode_utf7(&sent)),
            Err(e) => tracing::warn!(account = %account.id, "saving the sent copy: {e:#}"),
        }
    }
    if let Some(d) = req.draft_id {
        u.user.index.delete_draft(d)?;
    }
    let _ = jobs::submit(
        &state,
        &u.user.user_id,
        JobKind::Backup {
            account_id: account.id.clone(),
        },
        JobTrigger::Scheduled,
    );
    Ok(Json(SendResult {
        message_id: built.message_id,
        saved_to,
    }))
}

pub async fn list_drafts(u: Unlocked) -> ApiResult<Json<Vec<DraftView>>> {
    Ok(Json(u.user.index.drafts()?))
}

pub async fn save_draft(u: Unlocked, Json(d): Json<DraftInput>) -> ApiResult<Json<DraftView>> {
    if u.user.config().account(&d.account_id).is_none() {
        return Err(ApiErr::not_found("account"));
    }
    u.user
        .index
        .save_draft(d.id, &d.account_id, &d.message)?
        .map(Json)
        .ok_or_else(|| ApiErr::not_found("draft"))
}

pub async fn delete_draft(u: Unlocked, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    if u.user.index.delete_draft(id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiErr::not_found("draft"))
    }
}

const VIEWER_CACHE_BYTES: u64 = 256 * 1024 * 1024;

/// Loads the raw message: encrypted spool and viewer cache first, then any verified replica (hash-checked).
pub(crate) async fn load_raw(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    id: i64,
) -> ApiResult<Vec<u8>> {
    let msg = user
        .index
        .message(id)?
        .ok_or_else(|| ApiErr::not_found("message"))?;
    let ctx = ctx_for(state, user);
    let sha = msg
        .sha256
        .clone()
        .ok_or_else(|| ApiErr::conflict("message has not been downloaded yet"))?;
    for cached in [ctx.spool_get(id), ctx.cache_get(id)].into_iter().flatten() {
        if crypto::sha256_hex(&cached) == sha {
            return Ok(cached);
        }
    }
    let mut replicas = user.index.replicas_of(id)?;
    // Prefer local filesystem destinations.
    let cfg = user.config();
    replicas.sort_by_key(|r| {
        cfg.destination(&r.destination)
            .map(|d| d.scheme != "fs")
            .unwrap_or(true)
    });
    let mut last_err = None;
    for r in replicas
        .into_iter()
        .filter(|r| r.status == ReplicaStatus::Verified)
    {
        let store = match ctx.store(&r.destination) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        match store.get(&r.object_path, r.encrypted).await {
            Ok(raw) if crypto::sha256_hex(&raw) == sha => {
                if let Err(e) = ctx.cache_put(id, &raw, VIEWER_CACHE_BYTES) {
                    tracing::debug!("viewer cache: {e:#}");
                }
                return Ok(raw);
            }
            Ok(_) => {
                last_err = Some(anyhow::anyhow!(
                    "replica on {} failed its hash check",
                    store.dest.name
                ))
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(ApiErr::new(
        StatusCode::BAD_GATEWAY,
        "unavailable",
        format!(
            "no readable copy: {}",
            last_err
                .map(|e| format!("{e:#}"))
                .unwrap_or_else(|| "no verified replica".into())
        ),
    ))
}

#[derive(Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub html: bool,
    #[serde(default)]
    pub remote: bool,
}

pub async fn view_message(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<i64>,
    Query(q): Query<ViewQuery>,
) -> ApiResult<Json<MessageView>> {
    let raw = load_raw(&state, &u.user, id).await?;
    let view = tokio::task::spawn_blocking(move || viewer::render(id, &raw, q.html, q.remote))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    Ok(Json(view))
}

fn download(bytes: Vec<u8>, filename: &str, content_type: &str) -> Response {
    let safe: String = filename
        .chars()
        .map(|c| {
            if c.is_control() || c == '"' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect();
    let ascii: String = safe
        .chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect();
    let encoded: String = safe
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"),
        )
        .header("x-content-type-options", "nosniff")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "sandbox; default-src 'none'",
        )
        .body(Body::from(bytes))
        .unwrap()
}

pub async fn raw_message(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<i64>,
) -> ApiResult<Response> {
    let raw = load_raw(&state, &u.user, id).await?;
    Ok(download(
        raw,
        &format!("message-{id}.eml"),
        "message/rfc822",
    ))
}

pub async fn attachment(
    State(state): State<SharedState>,
    u: Unlocked,
    Path((id, n)): Path<(i64, u32)>,
) -> ApiResult<Response> {
    let raw = load_raw(&state, &u.user, id).await?;
    let (name, _declared, bytes) =
        viewer::attachment(&raw, n).map_err(|e| ApiErr::not_found(e.to_string()))?;
    // Always an opaque download: never rendered inline.
    Ok(download(bytes, &name, "application/octet-stream"))
}

// ───────────────────────────── mail access (IMAP / SMTP) ─────────────────────────────

pub async fn mail_access(
    State(state): State<SharedState>,
    u: Unlocked,
) -> ApiResult<Json<MailAccessInfo>> {
    let cfg = u.user.config();
    let logins = state
        .db
        .mail_logins(&u.user.user_id)?
        .into_iter()
        .filter(|l| cfg.account(&l.account_id).is_some())
        .map(|l| l.view())
        .collect();
    Ok(Json(MailAccessInfo {
        imap_port: state.mail.imap_port,
        smtp_port: state.mail.smtp_port,
        fingerprint: state.mail.fingerprint.clone(),
        authority: state.tls_ca.is_some(),
        certificate_names: state
            .tls_ca
            .as_ref()
            .map(|c| c.names.clone())
            .unwrap_or_default(),
        logins,
    }))
}

/// Malo's certificate authority, for devices to install (public, like any certificate):
/// `malo-ca.mobileconfig` (an iPhone/iPad/Mac profile), `malo-ca.crt` (DER, Android and
/// Windows) or `malo-ca.pem`.
pub async fn authority(
    State(state): State<SharedState>,
    Path(file): Path<String>,
) -> ApiResult<Response> {
    let Some(ca) = &state.tls_ca else {
        return Err(ApiErr::not_found("certificate authority"));
    };
    let b64 = |der: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
    let (content_type, body) = match file.as_str() {
        "malo-ca.crt" => ("application/x-x509-ca-cert", ca.der.clone()),
        "malo-ca.pem" => {
            let lines: Vec<String> = b64(&ca.der)
                .as_bytes()
                .chunks(64)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect();
            let pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            );
            ("application/x-pem-file", pem.into_bytes())
        }
        "malo-ca.mobileconfig" => (
            "application/x-apple-aspen-config",
            mobileconfig(&ca.der, &b64(&ca.der)).into_bytes(),
        ),
        _ => return Err(ApiErr::not_found("file")),
    };
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{file}\""),
        )
        .body(Body::from(body))
        .unwrap())
}

/// A configuration profile that installs the authority as a root certificate. Its identifiers
/// come from the certificate, so installing it again replaces the profile instead of adding one.
fn mobileconfig(der: &[u8], b64: &str) -> String {
    let fp = crypto::sha256_hex(der);
    let uuid = |salt: &str| {
        let h = crypto::sha256_hex(format!("{salt}{fp}").as_bytes());
        format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
        .to_uppercase()
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key><string>malo-ca.crt</string>
      <key>PayloadContent</key><data>{b64}</data>
      <key>PayloadDescription</key><string>Lets this device trust your Malo server (mail apps and the Malo app). It can only vouch for that server's names.</string>
      <key>PayloadDisplayName</key><string>Malo certificate authority</string>
      <key>PayloadIdentifier</key><string>app.malo.ca.{fp_short}</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>{inner}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>Malo server certificate</string>
  <key>PayloadIdentifier</key><string>app.malo.profile.{fp_short}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{outer}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#,
        fp_short = &fp[..16],
        inner = uuid("payload"),
        outer = uuid("profile"),
    )
}

/// Creates or replaces the mail login of an account. The password is generated here and shown
/// once; only its hash is kept.
pub async fn put_mail_login(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
    Json(req): Json<MailLoginRequest>,
) -> ApiResult<Json<MailLoginCreated>> {
    if u.user.config().account(&id).is_none() {
        return Err(ApiErr::not_found("account"));
    }
    let username = crate::mail::normalize_username(&req.username).map_err(ApiErr::bad_request)?;
    let password = crate::mail::generate_password(
        req.password_length
            .unwrap_or(crate::mail::DEFAULT_PASSWORD_LENGTH),
    );
    let hash = crate::mail::hash_password(&password);
    if !state
        .db
        .set_mail_login(&u.user.user_id, &id, &username, &hash)?
    {
        return Err(ApiErr::conflict(format!(
            "the username '{username}' is already taken"
        )));
    }
    best_effort(
        u.user.index.audit(
            "mail_login_set",
            Some(&id),
            &serde_json::json!({ "username": username }),
        ),
        "audit",
    );
    let login = state
        .db
        .mail_login(&username)?
        .ok_or_else(|| anyhow::anyhow!("mail login vanished"))?;
    Ok(Json(MailLoginCreated {
        login: login.view(),
        password,
    }))
}

pub async fn delete_mail_login(
    State(state): State<SharedState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.db.delete_mail_login(&u.user.user_id, &id)? {
        return Err(ApiErr::not_found("mail login"));
    }
    best_effort(
        u.user
            .index
            .audit("mail_login_removed", Some(&id), &serde_json::json!({})),
        "audit",
    );
    Ok(StatusCode::NO_CONTENT)
}

fn mail_view_info(user: &UnlockedUser, account: &str) -> anyhow::Result<MailViewInfo> {
    use malo_core::mailview::FolderSource;
    let settings = user.index.imap_settings(account)?;
    let folders = user.index.imap_all_folders(account, &settings)?;
    let gmail = folders
        .iter()
        .any(|f| f.special_use.as_deref() == Some("\\All") && f.source == FolderSource::Mailbox);
    let mut out = Vec::new();
    for f in folders {
        let inbox = f.name.eq_ignore_ascii_case("INBOX");
        out.push(MailFolderInfo {
            display_name: malo_core::layout::decode_utf7(&f.name),
            messages: user.index.imap_view(account, &f)?.messages.len() as u64,
            special_use: f.special_use.clone(),
            kind: match f.source {
                FolderSource::Mailbox => MailFolderKind::Mailbox,
                FolderSource::Label(_) => MailFolderKind::Label,
                FolderSource::Primary => MailFolderKind::Primary,
                FolderSource::AllMail => MailFolderKind::AllMail,
                FolderSource::Category(_) => MailFolderKind::Category,
            },
            shown: inbox || !settings.hidden.contains(&f.name),
            name: f.name,
        });
    }
    Ok(MailViewInfo {
        gmail,
        inbox_all_mail: settings.inbox_all_mail,
        split_categories: settings.split_categories,
        folders: out,
    })
}

pub async fn get_mail_view(u: Unlocked, Path(id): Path<String>) -> ApiResult<Json<MailViewInfo>> {
    if u.user.config().account(&id).is_none() {
        return Err(ApiErr::not_found("account"));
    }
    Ok(Json(mail_view_info(&u.user, &id)?))
}

/// Chooses the folders mail apps see; they pick up the change at their next sync.
pub async fn put_mail_view(
    u: Unlocked,
    Path(id): Path<String>,
    Json(req): Json<MailViewSettings>,
) -> ApiResult<Json<MailViewInfo>> {
    if u.user.config().account(&id).is_none() {
        return Err(ApiErr::not_found("account"));
    }
    let mut hidden: Vec<String> = req
        .hidden
        .into_iter()
        .filter(|n| !n.eq_ignore_ascii_case("INBOX"))
        .collect();
    hidden.sort();
    hidden.dedup();
    u.user.index.set_imap_settings(
        &id,
        &malo_core::mailview::ViewSettings {
            inbox_all_mail: req.inbox_all_mail,
            split_categories: req.split_categories,
            hidden,
        },
    )?;
    Ok(Json(mail_view_info(&u.user, &id)?))
}

/// Shows every backed-up message to mail apps again (undoes their deletions and flag changes).
pub async fn reset_mail_view(u: Unlocked, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if u.user.config().account(&id).is_none() {
        return Err(ApiErr::not_found("account"));
    }
    u.user.index.imap_reset(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

// ───────────────────────────── integrity / audit ─────────────────────────────

pub async fn latest_check(u: Unlocked) -> ApiResult<Json<Option<CheckReport>>> {
    Ok(Json(u.user.index.reports(1)?.into_iter().next()))
}

pub async fn list_checks(
    u: Unlocked,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<Vec<CheckReport>>> {
    Ok(Json(u.user.index.reports(q.limit.unwrap_or(20).min(200))?))
}

pub async fn audit(u: Unlocked, Query(q): Query<LimitQuery>) -> ApiResult<Json<Vec<AuditEntry>>> {
    Ok(Json(u.user.index.audit_entries(
        q.account.as_deref(),
        q.limit.unwrap_or(200).min(2000),
    )?))
}

// ───────────────────────────── admin ─────────────────────────────

pub async fn admin_users(
    State(state): State<SharedState>,
    _a: Admin,
) -> ApiResult<Json<Vec<UserInfo>>> {
    Ok(Json(
        state
            .db
            .users()?
            .iter()
            .map(|u| u.info(state.keyring.get(&u.id).is_some()))
            .collect(),
    ))
}

pub async fn admin_update_user(
    State(state): State<SharedState>,
    Admin(me): Admin,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<Json<UserInfo>> {
    if id == me.user.id && (req.disabled == Some(true) || req.role == Some(Role::User)) {
        return Err(ApiErr::bad_request("you can't disable or demote yourself"));
    }
    let before = state
        .db
        .user(&id)?
        .ok_or_else(|| ApiErr::not_found("user"))?;
    let max_accounts = match (req.max_accounts_default, req.max_accounts) {
        (Some(true), _) => Some(None),
        (_, Some(n)) => Some(Some(n)),
        _ => None,
    };
    if !state
        .db
        .update_user(&id, req.disabled, req.role, max_accounts)?
    {
        return Err(ApiErr::conflict("that would leave no active administrator"));
    }
    if req.disabled == Some(true) {
        scheduler::lock_user(&state, &id, "disabled by an administrator");
    }
    let u = state.db.user(&id)?.unwrap();
    auth::admin_audit(
        &state,
        &me.user.username,
        "user_updated",
        Some(&before.username),
        serde_json::json!({
            "disabled": req.disabled, "role": req.role, "max_accounts": max_accounts,
        }),
    );
    Ok(Json(u.info(state.keyring.get(&id).is_some())))
}

#[derive(Deserialize)]
pub struct DeleteUserQuery {
    /// Also delete backups in the user's local folder destinations (they can't be restored).
    #[serde(default)]
    pub delete_local_backups: bool,
}

pub async fn admin_delete_user(
    State(state): State<SharedState>,
    Admin(me): Admin,
    Path(id): Path<String>,
    Query(q): Query<DeleteUserQuery>,
) -> ApiResult<StatusCode> {
    if id == me.user.id {
        return Err(ApiErr::bad_request("you can't delete yourself"));
    }
    let target = state
        .db
        .user(&id)?
        .ok_or_else(|| ApiErr::not_found("user"))?;
    // Local folder backups live in the user's data folder and go with it. They may be the only
    // copy of mail already purged from the server, so this needs its own confirmation.
    let local = crate::keyring::UserPaths::try_new(&state.cfg.data_dir, &id)?.local();
    let has_local = std::fs::read_dir(&local).is_ok_and(|mut d| d.next().is_some());
    if has_local && !q.delete_local_backups {
        return Err(ApiErr::new(
            StatusCode::CONFLICT,
            "local_backups",
            format!(
                "{} has backups in a local folder on this server; deleting the user deletes them too. A forgotten password can be reset with the recovery kit instead.",
                target.username
            ),
        ));
    }
    scheduler::lock_user(&state, &id, "deleted");
    if !state
        .jobs
        .wait_user_idle(&id, std::time::Duration::from_secs(60))
        .await
    {
        tracing::warn!(user = %id, "jobs still running 60 s after the deletion request");
    }
    if !state.db.delete_user_keeping_an_admin(&id)? {
        return Err(ApiErr::conflict("that would leave no active administrator"));
    }
    let dir = crate::keyring::UserPaths::try_new(&state.cfg.data_dir, &id)?.dir;
    if dir.starts_with(state.cfg.data_dir.join("users")) {
        let _ = std::fs::remove_dir_all(dir);
    }
    auth::admin_audit(
        &state,
        &me.user.username,
        "user_deleted",
        Some(&target.username),
        serde_json::json!({
            "local_backups_deleted": has_local,
        }),
    );
    Ok(StatusCode::NO_CONTENT)
}

pub async fn admin_invites(
    State(state): State<SharedState>,
    _a: Admin,
) -> ApiResult<Json<Vec<InviteInfo>>> {
    Ok(Json(state.db.invites()?))
}

pub async fn admin_revoke_invite(
    State(state): State<SharedState>,
    Admin(me): Admin,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.db.delete_invite(&id)? {
        return Err(ApiErr::not_found("invite"));
    }
    auth::admin_audit(
        &state,
        &me.user.username,
        "invite_revoked",
        Some(&id[..12.min(id.len())]),
        serde_json::json!({}),
    );
    Ok(StatusCode::NO_CONTENT)
}

pub async fn admin_audit_log(
    State(state): State<SharedState>,
    _a: Admin,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<Vec<AdminAuditEntry>>> {
    Ok(Json(
        state
            .db
            .admin_audit_list(q.limit.unwrap_or(200).min(1000))?,
    ))
}

pub async fn admin_create_invite(
    State(state): State<SharedState>,
    Admin(me): Admin,
    Json(req): Json<CreateInviteRequest>,
) -> ApiResult<Json<Invite>> {
    let code = auth::random_token()[..24].to_string();
    let expires = Utc::now() + chrono::Duration::hours(req.valid_hours.clamp(1, 24 * 30) as i64);
    let hash = auth::hash_token(&code);
    state
        .db
        .create_invite(&hash, req.username.as_deref(), req.role, expires)?;
    auth::admin_audit(
        &state,
        &me.user.username,
        "invite_created",
        Some(&hash[..12]),
        serde_json::json!({
            "username": req.username, "role": req.role, "expires_at": expires,
        }),
    );
    Ok(Json(Invite {
        code,
        username: req.username,
        role: req.role,
        expires_at: expires,
    }))
}

pub async fn admin_get_settings(
    State(state): State<SharedState>,
    _a: Admin,
) -> ApiResult<Json<AdminSettings>> {
    Ok(Json(state.db.admin_settings()?))
}

pub async fn admin_put_settings(
    State(state): State<SharedState>,
    Admin(me): Admin,
    Json(mut s): Json<AdminSettings>,
) -> ApiResult<Json<AdminSettings>> {
    s.max_auto_lock_hours = s
        .max_auto_lock_hours
        .clamp(1, state.cfg.max_auto_lock_hours);
    s.max_jobs_per_user = s.max_jobs_per_user.clamp(1, 16);
    for m in &s.allowed_fs_mounts {
        let p = std::path::Path::new(m);
        if !p.is_absolute()
            || p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ApiErr::bad_request(format!(
                "mount {m} must be an absolute path without '..'"
            )));
        }
    }
    state.db.set_admin_settings(&s)?;
    crate::net::sync_setting(&state);
    auth::admin_audit(
        &state,
        &me.user.username,
        "settings_changed",
        None,
        serde_json::to_value(&s).unwrap_or_default(),
    );
    Ok(Json(s))
}
