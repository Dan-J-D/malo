//! Login = unlock, sessions, registration, bootstrap and the auth extractors.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use malo_api::{
    ChangePasswordRequest, DeleteAccountRequest, LoginRequest, LoginResponse, Me, RegisterRequest,
    Role, SetupRequest,
};
use malo_core::crypto;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::db::UserRow;
use crate::error::{ApiErr, ApiResult};
use crate::keyring::{self, UnlockedUser};
use crate::scheduler;
use crate::state::{AppState, SharedState};

pub fn hash_token(token: &str) -> String {
    crypto::sha256_hex(token.as_bytes())
}

pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// An authenticated session.
pub struct AuthUser {
    pub user: UserRow,
    pub token_hash: String,
}

impl FromRequestParts<SharedState> for AuthUser {
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| ApiErr::unauthorized("missing session token"))?;
        let token_hash = hash_token(header.trim());
        let idle = chrono::Duration::minutes(state.cfg.session_idle_minutes);
        let user_id = state
            .db
            .check_session(&token_hash, idle)?
            .ok_or_else(|| ApiErr::unauthorized("session expired"))?;
        let user = state
            .db
            .user(&user_id)?
            .ok_or_else(|| ApiErr::unauthorized("unknown user"))?;
        if user.disabled {
            return Err(ApiErr::forbidden("account disabled"));
        }
        Ok(AuthUser { user, token_hash })
    }
}

/// An authenticated session whose keys are unlocked.
pub struct Unlocked {
    pub auth: AuthUser,
    pub user: Arc<UnlockedUser>,
}

impl FromRequestParts<SharedState> for Unlocked {
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let auth = AuthUser::from_request_parts(parts, state).await?;
        let user = state
            .keyring
            .get(&auth.user.id)
            .ok_or_else(ApiErr::locked)?;
        Ok(Unlocked { auth, user })
    }
}

pub struct Admin(pub AuthUser);

impl FromRequestParts<SharedState> for Admin {
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let auth = AuthUser::from_request_parts(parts, state).await?;
        if auth.user.role != Role::Admin {
            return Err(ApiErr::forbidden("admin only"));
        }
        Ok(Admin(auth))
    }
}

pub fn me(state: &AppState, user: &UserRow) -> Me {
    let unlocked = state.keyring.get(&user.id);
    let settings_hours = unlocked
        .as_ref()
        .map(|u| u.config().settings.auto_lock_hours)
        .unwrap_or(24);
    let max = max_lock_hours(state);
    Me {
        id: user.id.clone(),
        username: user.username.clone(),
        role: user.role,
        unlocked: unlocked.is_some(),
        unlocked_at: unlocked.as_ref().map(|u| u.unlocked_at),
        expires_at: unlocked.as_ref().map(|u| u.expires_at()),
        auto_lock_hours: settings_hours.min(max),
        server_max_auto_lock_hours: max,
        recovery_kit_pending: unlocked
            .as_ref()
            .is_some_and(|u| !u.config().recovery_kit_exported),
        skipped_while_locked: unlocked
            .as_ref()
            .map(|u| u.skipped_while_locked.load(Ordering::Relaxed))
            .unwrap_or(0),
    }
}

pub fn max_lock_hours(state: &AppState) -> u32 {
    let admin = state
        .db
        .admin_settings()
        .map(|s| s.max_auto_lock_hours)
        .unwrap_or(24);
    state.cfg.max_auto_lock_hours.min(admin.max(1))
}

fn failure_delay(n: u32) -> Duration {
    if n < 5 {
        Duration::ZERO
    } else {
        Duration::from_secs((30u64 << (n - 5).min(5)).min(15 * 60))
    }
}

fn check_failures(state: &AppState, key: &str) -> ApiResult<()> {
    let map = state.login_failures.lock().unwrap();
    if let Some((n, at)) = map.get(key) {
        let wait = failure_delay(*n);
        if at.elapsed() < wait {
            return Err(ApiErr::too_many(format!(
                "too many failed attempts; try again in {}s",
                (wait - at.elapsed()).as_secs() + 1
            )));
        }
    }
    Ok(())
}

fn record_failure(state: &AppState, key: &str) {
    let mut map = state.login_failures.lock().unwrap();
    let e = map.entry(key.to_string()).or_insert((0, Instant::now()));
    e.0 += 1;
    e.1 = Instant::now();
}

async fn run_kdf<T: Send + 'static>(
    state: &AppState,
    f: impl FnOnce() -> T + Send + 'static,
) -> ApiResult<T> {
    let _permit = state
        .kdf_slots
        .acquire()
        .await
        .map_err(|_| ApiErr::too_many("busy"))?;
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiErr::from(anyhow::anyhow!(e)))
}

/// Persists rotated OAuth refresh tokens into the user's config.
fn rotation_handler(state: Weak<AppState>, user_id: String) -> malo_core::oauth::RotateFn {
    Box::new(move |account_id: &str, new_token: String| {
        let (Some(state), account_id, user_id) =
            (state.upgrade(), account_id.to_string(), user_id.clone())
        else {
            return;
        };
        tokio::spawn(async move {
            let Some(user) = state.keyring.get(&user_id) else {
                return;
            };
            let res = user
                .update_config(|cfg| {
                    if let Some(a) = cfg.account_mut(&account_id) {
                        if let malo_api::AccountAuth::OAuth2 { refresh_token, .. } = &mut a.auth {
                            *refresh_token = new_token;
                        }
                    }
                    Ok(())
                })
                .await;
            if let Err(e) = res {
                tracing::warn!("storing rotated refresh token failed: {e:#}");
            }
        });
    })
}

pub async fn login(
    State(state): State<SharedState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let key = req.username.to_lowercase();
    check_failures(&state, &key)?;
    let user = state.db.user_by_name(&req.username)?;
    let password = Zeroizing::new(req.password);
    let Some(user) = user.filter(|u| !u.disabled) else {
        // Spend comparable time so unknown names aren't distinguishable.
        let pw = password.clone();
        run_kdf(&state, move || {
            let _ = crypto::Vault::seal(
                "x",
                &pw,
                &crypto::random_key(),
                crypto::KdfParams::from_env(),
            );
        })
        .await?;
        record_failure(&state, &key);
        return Err(ApiErr::unauthorized("invalid username or password"));
    };
    let data_dir = state.cfg.data_dir.clone();
    let uid = user.id.clone();
    let pw = password.clone();
    let mdk = run_kdf(&state, move || keyring::open_vault(&data_dir, &uid, &pw)).await?;
    let mdk = match mdk {
        Ok(k) => k,
        Err(_) => {
            record_failure(&state, &key);
            return Err(ApiErr::unauthorized("invalid username or password"));
        }
    };
    state.login_failures.lock().unwrap().remove(&key);
    let unlocked = state.keyring.unlock(
        &state.cfg.data_dir,
        &user.id,
        &user.username,
        mdk,
        max_lock_hours(&state),
        state.cfg.auto_lock_seconds.map(chrono::Duration::seconds),
        rotation_handler(Arc::downgrade(&state), user.id.clone()),
    )?;
    let skipped = state.db.skipped_since(&user.id, user.last_login)?;
    unlocked
        .skipped_while_locked
        .store(skipped, Ordering::Relaxed);
    state.db.touch_login(&user.id)?;
    scheduler::sync_schedules(&state, &unlocked)?;
    let token = random_token();
    state
        .db
        .create_session(&hash_token(&token), &user.id, unlocked.expires_at())?;
    tracing::info!(user = %user.username, "unlocked");
    Ok(Json(LoginResponse {
        token,
        me: me(&state, &user),
    }))
}

pub async fn logout(State(state): State<SharedState>, auth: AuthUser) -> ApiResult<StatusCode> {
    state.db.delete_session(&auth.token_hash)?;
    Ok(StatusCode::NO_CONTENT)
}

/// "Lock now": wipes keys and ends every session of the user.
pub async fn lock(State(state): State<SharedState>, auth: AuthUser) -> ApiResult<StatusCode> {
    scheduler::lock_user(&state, &auth.user.id, "locked by user");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_me(State(state): State<SharedState>, auth: AuthUser) -> ApiResult<Json<Me>> {
    Ok(Json(me(&state, &auth.user)))
}

fn validate_credentials(username: &str, password: &str) -> ApiResult<()> {
    let ok_name = (2..=64).contains(&username.len())
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    let ok_name = ok_name && !username.starts_with('.') && !username.contains("..");
    if !ok_name {
        return Err(ApiErr::bad_request(
            "username: 2–64 characters of letters, digits, . _ - @ (not starting with '.' and without '..')",
        ));
    }
    if password.chars().count() < 10 {
        return Err(ApiErr::bad_request(
            "password must have at least 10 characters",
        ));
    }
    Ok(())
}

/// The exact text a user must type to delete their own account.
pub fn delete_confirmation(username: &str) -> String {
    format!("delete {username}")
}

/// Self-service account deletion. The GUI asks twice (warning, then typed confirmation + password);
/// the server re-checks both. Wipes the user's keys, config, index, spool and local fs backups.
/// Remote destinations are not touched.
pub async fn delete_self(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<DeleteAccountRequest>,
) -> ApiResult<StatusCode> {
    let user = &auth.user;
    if req.confirm != delete_confirmation(&user.username) {
        return Err(ApiErr::bad_request(format!(
            "type \"{}\" exactly to confirm",
            delete_confirmation(&user.username)
        )));
    }
    if user.role == Role::Admin && state.db.active_admin_count()? <= 1 {
        return Err(ApiErr::conflict(
            "you are the last administrator; make someone else an administrator first",
        ));
    }
    let key = user.username.to_lowercase();
    check_failures(&state, &key)?;
    let data_dir = state.cfg.data_dir.clone();
    let uid = user.id.clone();
    let pw = Zeroizing::new(req.password);
    let ok = run_kdf(&state, move || {
        keyring::open_vault(&data_dir, &uid, &pw).is_ok()
    })
    .await?;
    if !ok {
        record_failure(&state, &key);
        return Err(ApiErr::unauthorized("password is wrong"));
    }
    scheduler::lock_user(&state, &user.id, "account deleted");
    // Jobs stop at the next message; only delete once nothing can write to the folder any more.
    if !state
        .jobs
        .wait_user_idle(&user.id, std::time::Duration::from_secs(60))
        .await
    {
        tracing::warn!(user = %user.username, "jobs still running 60 s after the deletion request");
    }
    state.db.delete_user(&user.id)?;
    let dir = keyring::UserPaths::try_new(&state.cfg.data_dir, &user.id)?.dir;
    if dir.starts_with(state.cfg.data_dir.join("users")) {
        std::fs::remove_dir_all(&dir).or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(anyhow::Error::from(e))
            }
        })?;
    }
    tracing::info!(user = %user.username, "account deleted by its owner");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    validate_credentials(&auth.user.username, &req.new_password)?;
    let data_dir = state.cfg.data_dir.clone();
    let uid = auth.user.id.clone();
    let (old, new) = (
        Zeroizing::new(req.old_password),
        Zeroizing::new(req.new_password),
    );
    run_kdf(&state, move || {
        keyring::change_password(&data_dir, &uid, &old, &new)
    })
    .await?
    .map_err(|_| ApiErr::unauthorized("current password is wrong"))?;
    // Other sessions must log in again with the new password.
    state.db.delete_user_sessions(&auth.user.id)?;
    let token = auth.token_hash.clone();
    let expires = state
        .keyring
        .get(&auth.user.id)
        .map(|u| u.expires_at())
        .unwrap_or_else(Utc::now);
    state.db.create_session(&token, &auth.user.id, expires)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn provision(
    state: &SharedState,
    username: &str,
    password: String,
    role: Role,
    archive_key: Option<crypto::Key>,
) -> ApiResult<String> {
    if state.db.user_by_name(username)?.is_some() {
        return Err(ApiErr::conflict("username taken"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let data_dir = state.cfg.data_dir.clone();
    let id2 = id.clone();
    let pw = Zeroizing::new(password);
    let dir = keyring::UserPaths::try_new(&state.cfg.data_dir, &id)?.dir;
    let created = run_kdf(state, move || {
        keyring::provision_user(&data_dir, &id2, &pw, archive_key)
    })
    .await?
    .map_err(ApiErr::from)
    .and_then(|()| {
        let max = state.db.admin_settings()?.default_max_accounts;
        state.db.create_user(&id, username, role, Some(max))?;
        Ok(())
    });
    if let Err(e) = created {
        // A half-created user (full disk, I/O error) leaves nothing behind.
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
    }
    Ok(id)
}

pub async fn setup(
    State(state): State<SharedState>,
    Json(req): Json<SetupRequest>,
) -> ApiResult<StatusCode> {
    if state.db.user_count()? > 0 {
        return Err(ApiErr::conflict("already set up"));
    }
    let expected = state
        .db
        .setting("setup_token_hash")?
        .ok_or_else(|| ApiErr::forbidden("no setup token"))?;
    if hash_token(req.setup_token.trim()) != expected {
        return Err(ApiErr::forbidden("invalid setup token"));
    }
    validate_credentials(&req.username, &req.password)?;
    provision(&state, &req.username, req.password, Role::Admin, None).await?;
    state.db.delete_setting("setup_token_hash")?;
    tracing::info!("first admin {} created", req.username);
    Ok(StatusCode::CREATED)
}

pub async fn register(
    State(state): State<SharedState>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<StatusCode> {
    validate_credentials(&req.username, &req.password)?;
    let role = match &req.invite_code {
        Some(code) => state
            .db
            .redeem_invite(&hash_token(code.trim()), &req.username)?
            .ok_or_else(|| ApiErr::forbidden("invalid or expired invite"))?,
        None if state.db.admin_settings()?.self_registration => Role::User,
        None => return Err(ApiErr::forbidden("registration requires an invite")),
    };
    let archive = match &req.recovery_kit {
        Some(kit) => {
            let bytes = Zeroizing::new(
                hex::decode(kit.archive_key.trim())
                    .map_err(|_| ApiErr::bad_request("bad recovery kit"))?,
            );
            if bytes.len() != 32 {
                return Err(ApiErr::bad_request("bad recovery kit"));
            }
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&bytes);
            Some(k)
        }
        None => None,
    };
    provision(&state, &req.username, req.password, role, archive).await?;
    Ok(StatusCode::CREATED)
}

#[cfg(test)]
mod tests {
    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(super::failure_delay(4).as_secs(), 0);
        assert_eq!(super::failure_delay(5).as_secs(), 30);
        assert_eq!(super::failure_delay(6).as_secs(), 60);
        assert_eq!(super::failure_delay(50).as_secs(), 900);
    }
}
