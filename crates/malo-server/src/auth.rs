//! Login = unlock, sessions, registration, bootstrap and the auth extractors.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use malo_api::{
    ChangePasswordRequest, DeleteAccountRequest, LoginRequest, LoginResponse, Me, RecoverRequest,
    RecoveryKitRequest, RegisterRequest, Role, SealedRecoveryKit, SetupRequest,
};
use malo_core::crypto;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::db::UserRow;
use crate::error::{ApiErr, ApiResult};
use crate::keyring::{self, RecoverError, UnlockedUser};
use crate::kit;
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

/// The client's address: the TCP peer, or (with `MALO_TRUST_PROXY_HEADERS`) the address the
/// reverse proxy reports. Rate limits and failed-login backoff are counted per client.
pub struct ClientIp(pub IpAddr);

pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
        if let Some(ip) = header("x-real-ip").and_then(|v| v.trim().parse().ok()) {
            return ip;
        }
        // The right-most entry is the one the proxy itself added; earlier ones are client-supplied.
        if let Some(ip) = header("x-forwarded-for")
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

impl FromRequestParts<SharedState> for ClientIp {
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        Ok(ClientIp(client_ip(
            &parts.headers,
            peer,
            state.cfg.trust_proxy_headers,
        )))
    }
}

/// Key for the request rate limit (`tower_governor`), the same client address as [`ClientIp`].
#[derive(Clone)]
pub struct ClientIpKey {
    pub trust_proxy: bool,
}

impl tower_governor::key_extractor::KeyExtractor for ClientIpKey {
    type Key = IpAddr;

    fn extract<T>(
        &self,
        req: &axum::http::Request<T>,
    ) -> Result<IpAddr, tower_governor::GovernorError> {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        if peer.is_none() && !self.trust_proxy {
            return Err(tower_governor::GovernorError::UnableToExtractKey);
        }
        Ok(client_ip(req.headers(), peer, self.trust_proxy))
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

/// Backoff for one client guessing one user's password: steep after five misses.
fn failure_delay(n: u32) -> Duration {
    if n < 5 {
        Duration::ZERO
    } else {
        Duration::from_secs((30u64 << (n - 5).min(5)).min(15 * 60))
    }
}

/// Backoff for one user across all clients: it slows guessing spread over many addresses, but is
/// short enough that nobody can keep a user locked out by failing on purpose.
fn user_failure_delay(n: u32) -> Duration {
    if n < 20 {
        Duration::ZERO
    } else {
        Duration::from_secs((5u64 << ((n - 20) / 5).min(4)).min(60))
    }
}

/// How long to wait after `n` failures.
type Backoff = fn(u32) -> Duration;

/// Failures count per name and client, and per name alone.
fn failure_keys(name: &str, ip: IpAddr) -> [(String, Backoff); 2] {
    let name = name.to_lowercase();
    [
        (format!("{name}|{ip}"), failure_delay),
        (name, user_failure_delay),
    ]
}

pub(crate) fn check_failures(state: &AppState, name: &str, ip: IpAddr) -> ApiResult<()> {
    let map = state.login_failures.lock().unwrap();
    for (key, delay) in failure_keys(name, ip) {
        if let Some((n, at)) = map.get(&key) {
            let wait = delay(*n);
            if at.elapsed() < wait {
                return Err(ApiErr::too_many(format!(
                    "too many failed attempts; try again in {}s",
                    (wait - at.elapsed()).as_secs() + 1
                )));
            }
        }
    }
    Ok(())
}

/// Most entries are for names that don't exist; old ones are dropped so the map stays small.
const FAILURES_KEPT: usize = 10_000;

pub(crate) fn record_failure(state: &AppState, name: &str, ip: IpAddr) {
    let mut map = state.login_failures.lock().unwrap();
    if map.len() >= FAILURES_KEPT {
        map.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(3600));
        if map.len() >= FAILURES_KEPT {
            map.clear();
        }
    }
    for (key, _) in failure_keys(name, ip) {
        let e = map.entry(key).or_insert((0, Instant::now()));
        e.0 += 1;
        e.1 = Instant::now();
    }
}

pub(crate) fn clear_failures(state: &AppState, name: &str, ip: IpAddr) {
    let mut map = state.login_failures.lock().unwrap();
    for (key, _) in failure_keys(name, ip) {
        map.remove(&key);
    }
}

/// Records an administrative action; failures are logged, never returned.
pub fn admin_audit(
    state: &AppState,
    actor: &str,
    action: &str,
    target: Option<&str>,
    detail: serde_json::Value,
) {
    if let Err(e) = state.db.admin_audit(actor, action, target, &detail) {
        tracing::warn!("admin audit: {e:#}");
    }
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
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let key = req.username.to_lowercase();
    check_failures(&state, &key, ip)?;
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
        record_failure(&state, &key, ip);
        return Err(ApiErr::unauthorized("invalid username or password"));
    };
    let data_dir = state.cfg.data_dir.clone();
    let uid = user.id.clone();
    let pw = password.clone();
    let mdk = run_kdf(&state, move || keyring::open_vault(&data_dir, &uid, &pw)).await?;
    let mdk = match mdk {
        Ok(k) => k,
        Err(_) => {
            record_failure(&state, &key, ip);
            return Err(ApiErr::unauthorized("invalid username or password"));
        }
    };
    clear_failures(&state, &key, ip);
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
    ClientIp(ip): ClientIp,
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
    check_failures(&state, &key, ip)?;
    let data_dir = state.cfg.data_dir.clone();
    let uid = user.id.clone();
    let pw = Zeroizing::new(req.password);
    let ok = run_kdf(&state, move || {
        keyring::open_vault(&data_dir, &uid, &pw).is_ok()
    })
    .await?;
    if !ok {
        record_failure(&state, &key, ip);
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
    admin_audit(
        &state,
        "self",
        "user_deleted_by_owner",
        Some(&user.username),
        serde_json::json!({}),
    );
    tracing::info!(user = %user.username, "account deleted by its owner");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<SharedState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    validate_credentials(&auth.user.username, &req.new_password)?;
    let name = auth.user.username.clone();
    check_failures(&state, &name, ip)?;
    let data_dir = state.cfg.data_dir.clone();
    let uid = auth.user.id.clone();
    let (old, new) = (
        Zeroizing::new(req.old_password),
        Zeroizing::new(req.new_password),
    );
    let changed = run_kdf(&state, move || {
        keyring::change_password(&data_dir, &uid, &old, &new)
    })
    .await?;
    if changed.is_err() {
        record_failure(&state, &name, ip);
        return Err(ApiErr::unauthorized("current password is wrong"));
    }
    clear_failures(&state, &name, ip);
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
    // No own account limit: the user follows the server default, also when it changes later.
    .and_then(|()| Ok(state.db.create_user(&id, username, role, None)?));
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
    // Claimed before the slow key derivation: of two setups with the token, only one goes on.
    if !state.db.take_setting("setup_token_hash", &expected)? {
        return Err(ApiErr::conflict("already set up"));
    }
    if let Err(e) = provision(&state, &req.username, req.password, Role::Admin, None).await {
        state.db.set_setting("setup_token_hash", &expected)?;
        return Err(e);
    }
    admin_audit(
        &state,
        &req.username,
        "setup",
        Some(&req.username),
        serde_json::json!({}),
    );
    tracing::info!("first admin {} created", req.username);
    Ok(StatusCode::CREATED)
}

pub async fn register(
    State(state): State<SharedState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<StatusCode> {
    validate_credentials(&req.username, &req.password)?;
    if state.db.user_by_name(&req.username)?.is_some() {
        return Err(ApiErr::conflict("username taken"));
    }
    // The kit is opened before the invite is used, so a wrong passphrase doesn't use it up.
    let archive = match req.recovery_kit.clone() {
        Some(file) => {
            check_failures(&state, "recovery kit", ip)?;
            let pass = req.kit_passphrase.clone().map(Zeroizing::new);
            let opened = run_kdf(&state, move || {
                kit::open(&file, pass.as_deref().map(String::as_str))
            })
            .await?;
            match opened {
                Ok(k) => Some(k),
                Err(e) => {
                    record_failure(&state, "recovery kit", ip);
                    return Err(e);
                }
            }
        }
        None => None,
    };
    let invite = req.invite_code.as_deref().map(|c| hash_token(c.trim()));
    let role = match &invite {
        Some(hash) => state
            .db
            .redeem_invite(hash, &req.username)?
            .ok_or_else(|| ApiErr::forbidden("invalid or expired invite"))?,
        None if state.db.admin_settings()?.self_registration => Role::User,
        None => return Err(ApiErr::forbidden("registration requires an invite")),
    };
    if let Err(e) = provision(&state, &req.username, req.password, role, archive).await {
        if let Some(hash) = &invite {
            state.db.release_invite(hash)?;
        }
        return Err(e);
    }
    admin_audit(
        &state,
        "self",
        "registered",
        Some(&req.username),
        serde_json::json!({
            "role": role, "invite": invite.as_deref().map(|h| &h[..12]),
        }),
    );
    Ok(StatusCode::CREATED)
}

/// Forgotten password: the recovery kit sets a new one. The user keeps their id, accounts,
/// destinations, index and local backups; every session ends and the keys are locked.
pub async fn recover(
    State(state): State<SharedState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RecoverRequest>,
) -> ApiResult<StatusCode> {
    validate_credentials(&req.username, &req.new_password)?;
    let name = req.username.to_lowercase();
    check_failures(&state, &name, ip)?;
    let wrong = || ApiErr::unauthorized("unknown user, or the recovery kit isn't theirs");
    let user = state
        .db
        .user_by_name(&req.username)?
        .filter(|u| !u.disabled);
    let data_dir = state.cfg.data_dir.clone();
    let uid = user.as_ref().map(|u| u.id.clone());
    let (file, pass) = (req.recovery_kit, req.kit_passphrase.map(Zeroizing::new));
    let pw = Zeroizing::new(req.new_password);
    let res = run_kdf(&state, move || -> ApiResult<()> {
        let key = kit::open(&file, pass.as_deref().map(String::as_str))?;
        let Some(uid) = uid else { return Err(wrong()) };
        keyring::reset_password_with_kit(&data_dir, &uid, &key, &pw).map_err(|e| match e {
            RecoverError::WrongKit => wrong(),
            RecoverError::NoSlot => ApiErr::conflict(
                "this user hasn't logged in since recovery by kit became available, so the kit can't reset their password; register a new user with the kit instead",
            ),
            RecoverError::Other(e) => ApiErr::from(e),
        })
    })
    .await?;
    if let Err(e) = res {
        record_failure(&state, &name, ip);
        return Err(e);
    }
    clear_failures(&state, &name, ip);
    let user = user.expect("checked in the reset");
    scheduler::lock_user(&state, &user.id, "password reset with the recovery kit");
    admin_audit(
        &state,
        "self",
        "password_reset_with_kit",
        Some(&user.username),
        serde_json::json!({}),
    );
    tracing::info!(user = %user.username, "password reset with the recovery kit");
    Ok(StatusCode::NO_CONTENT)
}

/// Hands out the recovery kit, sealed with the passphrase the user picked. The password is asked
/// again: an unattended unlocked session alone isn't enough to take the archive key away.
pub async fn recovery_kit(
    State(state): State<SharedState>,
    ClientIp(ip): ClientIp,
    u: Unlocked,
    Json(req): Json<RecoveryKitRequest>,
) -> ApiResult<Json<SealedRecoveryKit>> {
    kit::check_passphrase(&req.passphrase)?;
    if req.passphrase == req.password {
        return Err(ApiErr::bad_request(
            "pick a kit passphrase that differs from your password: the kit is for when the password is forgotten",
        ));
    }
    let name = u.auth.user.username.clone();
    check_failures(&state, &name, ip)?;
    let data_dir = state.cfg.data_dir.clone();
    let user = u.user.clone();
    let (pw, pass) = (Zeroizing::new(req.password), Zeroizing::new(req.passphrase));
    let sealed = run_kdf(&state, move || -> ApiResult<Option<SealedRecoveryKit>> {
        if keyring::open_vault(&data_dir, &user.user_id, &pw).is_err() {
            return Ok(None);
        }
        let archive = user.config().archive_key()?;
        Ok(Some(kit::seal(
            &user.user_id,
            &user.username,
            &archive,
            &pass,
        )?))
    })
    .await??;
    let Some(sealed) = sealed else {
        record_failure(&state, &name, ip);
        return Err(ApiErr::unauthorized("password is wrong"));
    };
    clear_failures(&state, &name, ip);
    if let Err(e) = u
        .user
        .index
        .audit("recovery_kit_created", None, &serde_json::json!({}))
    {
        tracing::warn!("audit: {e:#}");
    }
    Ok(Json(sealed))
}

/// The app confirms the kit file was written; only then the reminder to save it goes away.
pub async fn recovery_kit_saved(u: Unlocked) -> ApiResult<StatusCode> {
    u.user
        .update_config(|c| {
            c.recovery_kit_exported = true;
            Ok(())
        })
        .await?;
    if let Err(e) = u
        .user
        .index
        .audit("recovery_kit_exported", None, &serde_json::json!({}))
    {
        tracing::warn!("audit: {e:#}");
    }
    Ok(StatusCode::NO_CONTENT)
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
