//! Two-step login: a time-based one-time code (RFC 6238: HMAC-SHA1, 30 s steps, 6 digits) from an
//! authenticator app after the password, or one of ten single-use recovery codes.
//!
//! The secret is kept in `server.db` sealed with a key derived from the user's config key, so it
//! is only readable with the password (or while the user is unlocked); administrators and a copy
//! of `server.db` see nothing usable. Recovery codes are stored as keyed hashes under the same key.
//! A code is accepted once: the step it was for is recorded, and earlier steps are refused.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use hmac::{Hmac, Mac};
use malo_api::{TotpCodeRequest, TotpRecoveryCodes, TotpSetup, TotpSetupRequest};
use malo_core::crypto::{self, Key};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::auth::{ClientIp, Unlocked};
use crate::error::{ApiErr, ApiResult};
use crate::state::SharedState;

const STEP_SECS: i64 = 30;
const DIGITS: u32 = 6;
/// Codes from one step before and after are accepted too (clock drift).
const WINDOW: i64 = 1;
const RECOVERY_CODES: usize = 10;

/// The key the secret and recovery codes are sealed with.
pub fn totp_key(config_key: &Key) -> Key {
    crypto::derive(config_key.as_ref(), None, "malo/v1/totp")
}

fn aad(user_id: &str) -> Vec<u8> {
    format!("malo totp {user_id}").into_bytes()
}

/// RFC 4226 HOTP value of `counter`.
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

fn step_at(unix: i64) -> i64 {
    unix.div_euclid(STEP_SECS)
}

/// The step `code` is valid for around `now`, if any, later than `after`.
pub fn check_code(secret: &[u8], code: &str, now: i64, after: i64) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let step = step_at(now);
    (step - WINDOW..=step + WINDOW)
        .filter(|s| *s > after && *s >= 0)
        .find(|s| hotp(secret, *s as u64) == want)
}

/// Recovery codes: `xxxxx-xxxxx` of 31 letters and digits without look-alikes (about 50 bits).
fn new_recovery_codes() -> Vec<String> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    (0..RECOVERY_CODES)
        .map(|_| {
            let b: [u8; 10] = crypto::random_bytes();
            let s: String = b
                .iter()
                .map(|x| ALPHABET[*x as usize % ALPHABET.len()] as char)
                .collect();
            format!("{}-{}", &s[..5], &s[5..])
        })
        .collect()
}

fn normalize_recovery(code: &str) -> String {
    code.trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

fn recovery_hash(key: &Key, code: &str) -> String {
    crypto::hmac_hex(key.as_ref(), normalize_recovery(code).as_bytes())
}

/// Two-step login state of a user, as stored.
pub struct TotpRow {
    pub secret: Vec<u8>,
    pub recovery: Vec<String>,
    pub last_step: i64,
    pub enabled: bool,
}

/// What a login with this code does.
pub enum Verdict {
    /// Accepted: the step (or recovery code) is used up.
    Ok,
    Wrong,
}

/// Checks a login code (authenticator or recovery code) and uses it up.
pub fn verify_login(
    state: &SharedState,
    user_id: &str,
    config_key: &Key,
    code: &str,
) -> anyhow::Result<Verdict> {
    let Some(row) = state.db.totp(user_id)? else {
        return Ok(Verdict::Ok);
    };
    if !row.enabled {
        return Ok(Verdict::Ok);
    }
    let key = totp_key(config_key);
    let secret = crypto::open_blob(&key, &aad(user_id), &row.secret)?;
    let now = chrono::Utc::now().timestamp();
    if let Some(step) = check_code(&secret, code, now, row.last_step) {
        // Compare-and-set: two logins with the same code can't both win.
        return Ok(if state.db.totp_use_step(user_id, row.last_step, step)? {
            Verdict::Ok
        } else {
            Verdict::Wrong
        });
    }
    let h = recovery_hash(&key, code);
    if normalize_recovery(code).len() == 10 && row.recovery.contains(&h) {
        return Ok(if state.db.totp_use_recovery(user_id, &h)? {
            Verdict::Ok
        } else {
            Verdict::Wrong
        });
    }
    Ok(Verdict::Wrong)
}

fn qr_svg(uri: &str) -> anyhow::Result<String> {
    let code = qrcode::QrCode::new(uri.as_bytes())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build())
}

fn wrong_code() -> ApiErr {
    ApiErr::new(
        StatusCode::FORBIDDEN,
        "totp_wrong",
        "the code is wrong or was already used",
    )
}

/// `POST /auth/totp/setup`: a new secret, not used for logins until confirmed.
pub async fn setup(
    State(state): State<SharedState>,
    ClientIp(ip): ClientIp,
    u: Unlocked,
    Json(req): Json<TotpSetupRequest>,
) -> ApiResult<Json<TotpSetup>> {
    crate::auth::check_password(&state, &u.auth, ip, Zeroizing::new(req.password)).await?;
    if state.db.totp(&u.user.user_id)?.is_some_and(|r| r.enabled) {
        return Err(ApiErr::conflict(
            "two-step login is already on; turn it off first to use another app",
        ));
    }
    let secret: [u8; 20] = crypto::random_bytes();
    let b32 = data_encoding::BASE32_NOPAD.encode(&secret);
    let key = totp_key(&u.user.secrets.config_key);
    state.db.set_totp_pending(
        &u.user.user_id,
        &crypto::seal_blob(&key, &aad(&u.user.user_id), &secret),
    )?;
    let issuer = "Malo";
    let label = format!("{issuer}:{}", u.auth.user.username);
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let uri = format!(
        "otpauth://totp/{}?secret={b32}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(&label).replace('+', "%20"),
        enc(issuer)
    );
    Ok(Json(TotpSetup {
        qr_svg: qr_svg(&uri)?,
        secret: b32,
        uri,
    }))
}

/// `POST /auth/totp/enable`: confirms the pending secret with a code and turns two-step login on.
pub async fn enable(
    State(state): State<SharedState>,
    u: Unlocked,
    Json(req): Json<TotpCodeRequest>,
) -> ApiResult<Json<TotpRecoveryCodes>> {
    let user_id = &u.user.user_id;
    let row = state
        .db
        .totp(user_id)?
        .filter(|r| !r.enabled)
        .ok_or_else(|| ApiErr::conflict("start the setup again"))?;
    let key = totp_key(&u.user.secrets.config_key);
    let secret = crypto::open_blob(&key, &aad(user_id), &row.secret)
        .map_err(|_| ApiErr::conflict("start the setup again"))?;
    let now = chrono::Utc::now().timestamp();
    let step = check_code(&secret, &req.code, now, 0).ok_or_else(wrong_code)?;
    let codes = new_recovery_codes();
    let hashes: Vec<String> = codes.iter().map(|c| recovery_hash(&key, c)).collect();
    state.db.enable_totp(user_id, step, &hashes)?;
    crate::auth::admin_audit(
        &state,
        &u.auth.user.username,
        "totp_enabled",
        Some(&u.auth.user.username),
        serde_json::json!({}),
    );
    Ok(Json(TotpRecoveryCodes { codes }))
}

/// Checks the password and a current code (or recovery code) of a user with two-step login.
async fn confirm(
    state: &SharedState,
    u: &Unlocked,
    ip: std::net::IpAddr,
    req: TotpCodeRequest,
) -> ApiResult<()> {
    let password = req
        .password
        .ok_or_else(|| ApiErr::bad_request("enter your password"))?;
    crate::auth::check_password(state, &u.auth, ip, Zeroizing::new(password)).await?;
    match verify_login(
        state,
        &u.user.user_id,
        &u.user.secrets.config_key,
        &req.code,
    )? {
        Verdict::Ok => Ok(()),
        Verdict::Wrong => {
            crate::auth::record_failure(state, &u.auth.user.username.to_lowercase(), ip);
            Err(wrong_code())
        }
    }
}

/// `POST /auth/totp/disable` (password and a code).
pub async fn disable(
    State(state): State<SharedState>,
    ClientIp(ip): ClientIp,
    u: Unlocked,
    Json(req): Json<TotpCodeRequest>,
) -> ApiResult<StatusCode> {
    if !state.db.totp(&u.user.user_id)?.is_some_and(|r| r.enabled) {
        state.db.delete_totp(&u.user.user_id)?;
        return Ok(StatusCode::NO_CONTENT);
    }
    confirm(&state, &u, ip, req).await?;
    state.db.delete_totp(&u.user.user_id)?;
    crate::auth::admin_audit(
        &state,
        &u.auth.user.username,
        "totp_disabled",
        Some(&u.auth.user.username),
        serde_json::json!({}),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /auth/totp/recovery-codes` (password and a code): ten new codes; the old ones stop working.
pub async fn new_recovery(
    State(state): State<SharedState>,
    ClientIp(ip): ClientIp,
    u: Unlocked,
    Json(req): Json<TotpCodeRequest>,
) -> ApiResult<Json<TotpRecoveryCodes>> {
    if !state.db.totp(&u.user.user_id)?.is_some_and(|r| r.enabled) {
        return Err(ApiErr::conflict("two-step login is off"));
    }
    confirm(&state, &u, ip, req).await?;
    let key = totp_key(&u.user.secrets.config_key);
    let codes = new_recovery_codes();
    let hashes: Vec<String> = codes.iter().map(|c| recovery_hash(&key, c)).collect();
    state.db.set_totp_recovery(&u.user.user_id, &hashes)?;
    Ok(Json(TotpRecoveryCodes { codes }))
}

/// For [`crate::auth::me`]: on, and recovery codes left.
pub fn status(state: &crate::state::AppState, user_id: &str) -> (bool, u32) {
    match state.db.totp(user_id) {
        Ok(Some(r)) if r.enabled => (true, r.recovery.len() as u32),
        _ => (false, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1 (8 digits there; the last 6 here).
    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        for (t, code) in [
            (59i64, 94287082u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
        ] {
            assert_eq!(hotp(secret, step_at(t) as u64), code % 1_000_000, "t={t}");
        }
    }

    #[test]
    fn window_and_replay() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000i64;
        let step = step_at(now);
        let code = format!("{:06}", hotp(secret, step as u64));
        assert_eq!(check_code(secret, &code, now, 0), Some(step));
        assert_eq!(
            check_code(secret, &format!("{} {}", &code[..3], &code[3..]), now, 0),
            Some(step)
        );
        // Accepted from the next step, not after two.
        assert_eq!(check_code(secret, &code, now + STEP_SECS, 0), Some(step));
        assert_eq!(check_code(secret, &code, now + 2 * STEP_SECS, 0), None);
        // A used step can't be used again.
        assert_eq!(check_code(secret, &code, now, step), None);
        for bad in ["", "12345", "1234567", "abcdef"] {
            assert_eq!(check_code(secret, bad, now, 0), None);
        }
    }

    #[test]
    fn recovery_codes_shape() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        for c in &codes {
            assert_eq!(c.len(), 11);
            assert_eq!(normalize_recovery(&c.to_uppercase()).len(), 10);
        }
        let key = crypto::random_key();
        assert_eq!(
            recovery_hash(&key, &codes[0]),
            recovery_hash(
                &key,
                &format!(" {} ", codes[0].to_uppercase().replace('-', ""))
            )
        );
    }
}
