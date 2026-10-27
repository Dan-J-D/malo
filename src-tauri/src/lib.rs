//! Malo desktop app. The Rust side owns the HTTP/WS client and the session token; the Svelte UI only
//! calls the commands below. The token never reaches JavaScript.

mod held;
mod net;
mod oauth;
mod profile;
mod sidecar;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use futures::StreamExt;
use malo_api::{
    EventBatch, LoginRequest, LoginResponse, Me, RecoveryKitFile, RecoveryKitRequest,
    SealedRecoveryKit, ServerStatus, SyncEvent, SEALED_KIT_FORMAT,
};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// reqwest's own message ("error sending request for url …") hides why; the cause chain has it
/// (timed out, connection refused, certificate mismatch…).
fn net_err(e: reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        msg = format!("{msg}: {s}");
        src = s.source();
    }
    msg
}

#[derive(Clone)]
struct Conn {
    base: String,
    fingerprint: Option<String>,
    http: reqwest::Client,
    sidecar_secret: Option<String>,
    token: Option<String>,
}

#[derive(Default)]
pub struct AppState {
    conn: Mutex<Option<Conn>>,
    events: Mutex<Option<tokio::task::AbortHandle>>,
    sidecar: Mutex<Option<sidecar::Sidecar>>,
    tray_mode: AtomicBool,
    held: held::Held,
    /// The profile file unlocked for this session, with its key. Dropped (and wiped) on lock,
    /// log out and disconnect.
    profile: Mutex<Option<OpenProfile>>,
    /// Who logged in on the current connection, for saving it as a profile.
    username: Mutex<Option<String>>,
}

struct OpenProfile {
    path: PathBuf,
    data: profile::Data,
    sealer: profile::Sealer,
}

/// App preferences. Which server to use isn't one of them: that is in profile files, and only
/// their paths are remembered here (KeePassXC-style), unless the user turns that off.
#[derive(Serialize, Deserialize, Clone)]
pub struct Prefs {
    #[serde(default)]
    pub tray_mode: bool,
    /// Profile files opened recently, the latest first.
    #[serde(default)]
    pub recent_profiles: Vec<String>,
    #[serde(default = "yes")]
    pub remember_recent: bool,
    /// Left by versions before profiles: the server connected to last and its pin. Only read, so
    /// connecting there again still warns about a changed certificate; never written again, and
    /// removed once a profile holds that server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

fn yes() -> bool {
    true
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            tray_mode: false,
            recent_profiles: Vec::new(),
            remember_recent: true,
            url: None,
            fingerprint: None,
        }
    }
}

/// Most profile paths kept in the recent list.
const RECENT_KEPT: usize = 8;

fn prefs_path(app: &AppHandle) -> CmdResult<PathBuf> {
    let dir = app.path().app_config_dir().map_err(err)?;
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir.join("preferences.json"))
}

fn load_prefs(app: &AppHandle) -> Prefs {
    prefs_path(app)
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_prefs(app: &AppHandle, p: &Prefs) -> CmdResult<()> {
    std::fs::write(prefs_path(app)?, serde_json::to_vec_pretty(p).map_err(err)?).map_err(err)
}

fn conn(state: &AppState) -> CmdResult<Conn> {
    state
        .conn
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "not connected to a server".to_string())
}

fn request(c: &Conn, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
    let mut r = c.http.request(method, format!("{}{}", c.base, path));
    if let Some(t) = &c.token {
        r = r.bearer_auth(t);
    }
    if let Some(s) = &c.sidecar_secret {
        r = r.header("x-malo-sidecar", s);
    }
    r
}

/// API error forwarded to the UI as `"<status>|<code>|<message>"`.
async fn check(resp: reqwest::Response) -> CmdResult<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let (code, msg) = match serde_json::from_str::<malo_api::ApiError>(&body) {
        Ok(e) => (e.code, e.error),
        Err(_) => ("error".into(), body),
    };
    // Never hand the UI an empty message (e.g. a 404 from a server that lacks the route).
    let msg = if msg.trim().is_empty() {
        format!(
            "the server answered HTTP {status}{}",
            reqwest::StatusCode::from_u16(status)
                .ok()
                .and_then(|s| s.canonical_reason())
                .map(|r| format!(" ({r})"))
                .unwrap_or_default()
        )
    } else {
        msg
    };
    Err(format!("{status}|{code}|{msg}"))
}

fn normalize_url(url: &str) -> CmdResult<String> {
    let u = url::Url::parse(url.trim()).map_err(|e| format!("invalid URL: {e}"))?;
    if u.scheme() != "https" {
        return Err("the server URL must start with https://".into());
    }
    Ok(u.as_str().trim_end_matches('/').to_string())
}

// ───────────────────────────── connection ─────────────────────────────

#[derive(Serialize)]
pub struct Probe {
    url: String,
    fingerprint: Option<String>,
    /// The certificate is valid under the Web PKI (no pin needed).
    publicly_trusted: bool,
    status: ServerStatus,
}

#[tauri::command]
async fn probe_server(url: String) -> CmdResult<Probe> {
    let url = normalize_url(&url)?;
    // A publicly trusted certificate needs no pin.
    let pki = net::http_client(net::tls_config(None));
    if let Ok(r) = pki.get(format!("{url}/status")).send().await {
        if let Ok(status) = check(r).await.map_err(err)?.json::<ServerStatus>().await {
            return Ok(Probe {
                url,
                fingerprint: None,
                publicly_trusted: true,
                status,
            });
        }
    }
    let (cfg, seen) = net::probe_config();
    let r = net::http_client(cfg)
        .get(format!("{url}/status"))
        .send()
        .await
        .map_err(|e| format!("cannot reach server: {e}"))?;
    let status: ServerStatus = check(r).await?.json().await.map_err(err)?;
    // Pin the authority the server names as its own (Malo's, so renewals keep the pin) when it
    // sent it; otherwise the certificate itself. Never an authority the server doesn't name:
    // that could be a public one that vouches for anyone.
    let chain = seen.lock().unwrap().clone().unwrap_or_default();
    let fp = match &status.cert_fingerprint {
        Some(own) if chain.iter().skip(1).any(|c| c == &net::normalize(own)) => {
            Some(net::normalize(own))
        }
        _ => chain.first().cloned(),
    };
    Ok(Probe {
        url,
        fingerprint: fp,
        publicly_trusted: false,
        status,
    })
}

/// The error for a server whose certificate isn't the pinned one any more: `409|cert_changed|`
/// and the details as JSON (`url`, `old`, `new`; null stands for a publicly trusted certificate).
fn cert_changed(url: &str, old: Option<&str>, new: Option<&str>) -> String {
    let details = serde_json::json!({ "url": url, "old": old, "new": new });
    format!("409|cert_changed|{details}")
}

/// Connects to a remote server, pinning the confirmed fingerprint (or none for public certificates).
/// The pin of the server connected to before is only replaced with `replace_pin`: a changed
/// certificate is what an interception looks like, so the app asks first.
#[tauri::command]
async fn connect_remote(
    app: AppHandle,
    state: State<'_, AppState>,
    url: String,
    fingerprint: Option<String>,
    replace_pin: Option<bool>,
) -> CmdResult<ServerStatus> {
    remote(&app, &state, url, fingerprint, replace_pin.unwrap_or(false)).await
}

async fn remote(
    app: &AppHandle,
    state: &AppState,
    url: String,
    fingerprint: Option<String>,
    replace_pin: bool,
) -> CmdResult<ServerStatus> {
    let url = normalize_url(&url)?;
    let fingerprint = fingerprint.map(|f| net::normalize(&f));
    let pinned = pinned_for(app, state, &url);
    if let Some(old) = &pinned {
        if fingerprint != *old && !replace_pin {
            return Err(cert_changed(&url, old.as_deref(), fingerprint.as_deref()));
        }
    }
    let http = net::http_client(net::tls_config(fingerprint.as_deref()));
    let sent = match http.get(format!("{url}/status")).send().await {
        Ok(r) => r,
        Err(e) => {
            // With a pin, tell a changed certificate apart from a server that's just unreachable.
            if let Some(pin) = &fingerprint {
                if let Ok(p) = probe_server(url.clone()).await {
                    if p.fingerprint.as_ref() != Some(pin) {
                        return Err(cert_changed(&url, Some(pin), p.fingerprint.as_deref()));
                    }
                }
            }
            return Err(net_err(e));
        }
    };
    let status: ServerStatus = check(sent).await?.json().await.map_err(err)?;
    stop_events(state);
    *state.conn.lock().unwrap() = Some(Conn {
        base: url.clone(),
        fingerprint: fingerprint.clone(),
        http,
        sidecar_secret: None,
        token: None,
    });
    *state.username.lock().unwrap() = None;
    // A certificate the user deliberately trusted in place of the old one becomes the pin.
    let mut open = state.profile.lock().unwrap();
    if let Some(p) = open.as_mut() {
        if let profile::Server::Remote {
            url: purl,
            fingerprint: pfp,
        } = &mut p.data.server
        {
            if *purl == url && *pfp != fingerprint {
                *pfp = fingerprint;
                save_open(p)?;
            }
        }
    }
    Ok(status)
}

/// What is pinned for `url`, if anything: the open profile's certificate, `Some(None)` when the
/// profile expects a publicly trusted one (a switch to a private certificate is a change too), or
/// the pin older versions kept.
fn pinned_for(app: &AppHandle, state: &AppState, url: &str) -> Option<Option<String>> {
    if let Some(p) = state.profile.lock().unwrap().as_ref() {
        if let profile::Server::Remote {
            url: purl,
            fingerprint,
        } = &p.data.server
        {
            if purl == url {
                return Some(fingerprint.as_deref().map(net::normalize));
            }
        }
    }
    let prefs = load_prefs(app);
    prefs
        .fingerprint
        .filter(|_| prefs.url.as_deref() == Some(url))
        .map(|f| Some(net::normalize(&f)))
}

#[derive(Serialize)]
pub struct LocalInfo {
    url: String,
    fingerprint: Option<String>,
    status: ServerStatus,
    setup_token: Option<String>,
}

/// Starts (or reuses) the bundled server on 127.0.0.1 with a per-launch secret.
#[tauri::command]
async fn start_local(app: AppHandle, state: State<'_, AppState>) -> CmdResult<LocalInfo> {
    local(&app, &state).await
}

async fn local(app: &AppHandle, state: &AppState) -> CmdResult<LocalInfo> {
    let existing = state
        .sidecar
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.info.clone());
    let info = match existing {
        Some(i) => i,
        None => {
            let data = local_data_dir(app)?;
            let sc = sidecar::spawn(app, &data).await.map_err(err)?;
            let info = sc.info.clone();
            *state.sidecar.lock().unwrap() = Some(sc);
            info
        }
    };
    let http = net::http_client(net::tls_config(info.fingerprint.as_deref()));
    let c = Conn {
        base: info.url.clone(),
        fingerprint: info.fingerprint.clone(),
        http,
        sidecar_secret: Some(info.secret.clone()),
        token: None,
    };
    let status: ServerStatus = check(
        request(&c, reqwest::Method::GET, "/status")
            .send()
            .await
            .map_err(err)?,
    )
    .await?
    .json()
    .await
    .map_err(err)?;
    stop_events(state);
    *state.conn.lock().unwrap() = Some(c);
    *state.username.lock().unwrap() = None;
    Ok(LocalInfo {
        url: info.url,
        fingerprint: info.fingerprint,
        status,
        setup_token: info.setup_token.clone(),
    })
}

#[tauri::command]
fn get_prefs(app: AppHandle) -> Prefs {
    load_prefs(&app)
}

#[tauri::command]
fn set_tray_mode(app: AppHandle, state: State<'_, AppState>, enabled: bool) -> CmdResult<()> {
    state.tray_mode.store(enabled, Ordering::Relaxed);
    let mut p = load_prefs(&app);
    p.tray_mode = enabled;
    save_prefs(&app, &p)
}

#[tauri::command]
fn disconnect(state: State<'_, AppState>) {
    stop_events(&state);
    state.held.clear();
    *state.conn.lock().unwrap() = None;
    *state.username.lock().unwrap() = None;
    *state.profile.lock().unwrap() = None;
}

// ───────────────────────────── profiles ─────────────────────────────

/// What the UI may know about a profile: never its password, or the pinned fingerprint.
#[derive(Serialize)]
pub struct ProfileInfo {
    path: String,
    /// The file name without its extension.
    name: String,
    local: bool,
    url: Option<String>,
    username: Option<String>,
    /// The Malo password is kept in the profile (unlocking it logs in).
    has_password: bool,
}

fn profile_name(path: &std::path::Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "profile".into())
}

fn info_of(p: &OpenProfile) -> ProfileInfo {
    let (local, url) = match &p.data.server {
        profile::Server::Local => (true, None),
        profile::Server::Remote { url, .. } => (false, Some(url.clone())),
    };
    ProfileInfo {
        path: p.path.display().to_string(),
        name: profile_name(&p.path),
        local,
        url,
        username: p.data.username.clone(),
        has_password: p.data.password.is_some(),
    }
}

/// Writes the open profile: to a new file next to it first, then renamed over it, so a crash
/// halfway never leaves a damaged profile behind.
fn save_open(p: &OpenProfile) -> CmdResult<()> {
    use rand::RngCore;
    let bytes = p.sealer.seal(&p.data).map_err(err)?;
    let dir = p.path.parent().ok_or("no folder to save the profile in")?;
    let mut rnd = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let tmp = dir.join(format!(".malo-profile-{}.tmp", hex::encode(rnd)));
    let written = write_private(&tmp, &bytes).and_then(|()| std::fs::rename(&tmp, &p.path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.map_err(|e| format!("could not save the profile {}: {e}", p.path.display()))
}

/// Puts `path` first in the recent list, unless the user turned the list off.
fn remember(app: &AppHandle, path: &std::path::Path) -> CmdResult<()> {
    let mut prefs = load_prefs(app);
    if !prefs.remember_recent {
        return Ok(());
    }
    let path = path.display().to_string();
    prefs.recent_profiles.retain(|p| *p != path);
    prefs.recent_profiles.insert(0, path);
    prefs.recent_profiles.truncate(RECENT_KEPT);
    save_prefs(app, &prefs)
}

#[derive(Serialize)]
pub struct RecentProfile {
    path: String,
    name: String,
    exists: bool,
}

#[derive(Serialize)]
pub struct Profiles {
    recent: Vec<RecentProfile>,
    remember_recent: bool,
    open: Option<ProfileInfo>,
}

#[tauri::command]
fn profiles(app: AppHandle, state: State<'_, AppState>) -> Profiles {
    let prefs = load_prefs(&app);
    Profiles {
        recent: prefs
            .recent_profiles
            .iter()
            .map(|p| {
                let path = PathBuf::from(p);
                RecentProfile {
                    name: profile_name(&path),
                    exists: path.is_file(),
                    path: p.clone(),
                }
            })
            .collect(),
        remember_recent: prefs.remember_recent,
        open: state.profile.lock().unwrap().as_ref().map(info_of),
    }
}

/// Takes a profile off the recent list (the file stays).
#[tauri::command]
fn forget_profile(app: AppHandle, path: String) -> CmdResult<()> {
    let mut prefs = load_prefs(&app);
    prefs.recent_profiles.retain(|p| *p != path);
    save_prefs(&app, &prefs)
}

/// Turning the recent list off also empties it: then the app keeps no trace of any server.
#[tauri::command]
fn set_remember_recent(app: AppHandle, enabled: bool) -> CmdResult<()> {
    let mut prefs = load_prefs(&app);
    prefs.remember_recent = enabled;
    if !enabled {
        prefs.recent_profiles.clear();
    }
    save_prefs(&app, &prefs)
}

/// Native "Open" dialog for a profile file (`MALO_AUTOPICK_PROFILE` in headless tests).
#[tauri::command]
fn pick_profile(app: AppHandle) -> Option<String> {
    if let Some(p) = test_hook("MALO_AUTOPICK_PROFILE") {
        return Some(p.display().to_string());
    }
    let mut dialog = app
        .dialog()
        .file()
        .add_filter("Malo profile", &[profile::EXTENSION]);
    if let Some(dir) = dialog_dir(&app) {
        dialog = dialog.set_directory(dir);
    }
    dialog
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

#[derive(Serialize)]
pub struct Unlocked {
    profile: ProfileInfo,
    url: String,
    local: bool,
    status: ServerStatus,
    setup_token: Option<String>,
    /// Logged in with the password kept in the profile.
    me: Option<Me>,
    /// Why logging in with the kept password failed (it was probably changed since).
    login_error: Option<String>,
}

/// The message of a `"<status>|<code>|<message>"` error.
fn message_of(e: &str) -> String {
    let mut parts = e.splitn(3, '|');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(s), Some(_), Some(m)) if s.parse::<u16>().is_ok() => m.to_string(),
        _ => e.to_string(),
    }
}

/// Opens a profile with its password, connects to its server and, when it keeps the Malo
/// password, logs in. A changed certificate leaves the profile open, so trusting the new one can
/// update its pin; any other failure closes it again.
#[tauri::command]
async fn unlock_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> CmdResult<Unlocked> {
    let path = PathBuf::from(path);
    let meta =
        std::fs::metadata(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // A profile is a few hundred bytes; anything big is not one.
    if meta.len() > 64 * 1024 {
        return Err(profile::Error::NotAProfile.to_string());
    }
    let bytes = std::fs::read(&path).map_err(err)?;
    let (data, sealer) = tokio::task::spawn_blocking(move || profile::open(&bytes, &password))
        .await
        .map_err(err)?
        .map_err(err)?;
    remember(&app, &path)?;
    // Leave whatever was connected before.
    stop_events(&state);
    state.held.clear();
    *state.conn.lock().unwrap() = None;
    *state.username.lock().unwrap() = None;
    let server = data.server.clone();
    let creds = data.username.clone().zip(data.password.clone());
    let p = OpenProfile { path, data, sealer };
    let info = info_of(&p);
    *state.profile.lock().unwrap() = Some(p);
    let connected = match server {
        profile::Server::Local => local(&app, &state)
            .await
            .map(|i| (i.url, true, i.status, i.setup_token)),
        profile::Server::Remote { url, fingerprint } => {
            remote(&app, &state, url.clone(), fingerprint, false)
                .await
                .map(|s| (url, false, s, None))
        }
    };
    let (url, local, status, setup_token) = match connected {
        Ok(c) => c,
        Err(e) => {
            if !e.starts_with("409|cert_changed|") {
                *state.profile.lock().unwrap() = None;
            }
            return Err(e);
        }
    };
    let (mut me, mut login_error) = (None, None);
    if let (Some((user, pw)), false) = (creds, status.needs_setup) {
        match login_as(&state, &user, &pw).await {
            Ok(m) => me = Some(m),
            Err(e) => login_error = Some(message_of(&e)),
        }
    }
    Ok(Unlocked {
        profile: info,
        url,
        local,
        status,
        setup_token,
        me,
        login_error,
    })
}

#[tauri::command]
fn close_profile(state: State<'_, AppState>) {
    *state.profile.lock().unwrap() = None;
}

/// Saves the current connection as a new profile file the user picks, encrypted with `password`.
/// `login_password` is the Malo password to keep in it, if wanted. The new profile is then open.
#[tauri::command]
async fn save_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
    login_password: Option<String>,
) -> CmdResult<Option<ProfileInfo>> {
    if password.chars().count() < 8 {
        return Err("use a profile password of at least 8 characters".into());
    }
    let c = conn(&state)?;
    let server = match c.sidecar_secret {
        Some(_) => profile::Server::Local,
        None => profile::Server::Remote {
            url: c.base.clone(),
            fingerprint: c.fingerprint.clone(),
        },
    };
    let username = state.username.lock().unwrap().clone();
    if login_password.is_some() && username.is_none() {
        return Err("log in first, so the profile knows whose password it keeps".into());
    }
    let host = match &server {
        profile::Server::Local => "this-computer".to_string(),
        profile::Server::Remote { url, .. } => url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| "server".into()),
    };
    let suggested = match &username {
        Some(u) => format!("{u} on {host}.{}", profile::EXTENSION),
        None => format!("{host}.{}", profile::EXTENSION),
    };
    if let Some(pw) = &login_password {
        verify_login(&state, pw).await?;
    }
    let Some(mut target) = save_target(&app, &suggested) else {
        return Ok(None);
    };
    if target.extension().is_none() {
        target.set_extension(profile::EXTENSION);
    }
    let sealer = tokio::task::spawn_blocking(move || profile::Sealer::new(&password))
        .await
        .map_err(err)?
        .map_err(err)?;
    let p = OpenProfile {
        path: target,
        data: profile::Data {
            server: server.clone(),
            username,
            password: login_password.map(zeroize::Zeroizing::new),
        },
        sealer,
    };
    save_open(&p)?;
    remember(&app, &p.path)?;
    // The pin older versions kept for this server now lives in the profile.
    let mut prefs = load_prefs(&app);
    if let profile::Server::Remote { url, .. } = &server {
        if prefs.url.as_deref() == Some(url) {
            prefs.url = None;
            prefs.fingerprint = None;
            save_prefs(&app, &prefs)?;
        }
    }
    let info = info_of(&p);
    *state.profile.lock().unwrap() = Some(p);
    Ok(Some(info))
}

/// Keeps the Malo password in the open profile (with the username logged in now), or forgets it.
#[tauri::command]
async fn set_profile_login(
    state: State<'_, AppState>,
    password: Option<String>,
) -> CmdResult<ProfileInfo> {
    if let Some(pw) = &password {
        verify_login(&state, pw).await?;
    }
    let username = state.username.lock().unwrap().clone();
    let mut open = state.profile.lock().unwrap();
    let p = open.as_mut().ok_or("no profile is open")?;
    if password.is_some() {
        p.data.username = Some(username.ok_or("log in first")?);
    }
    p.data.password = password.map(zeroize::Zeroizing::new);
    save_open(p)?;
    Ok(info_of(p))
}

#[tauri::command]
async fn change_profile_password(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    if password.chars().count() < 8 {
        return Err("use a profile password of at least 8 characters".into());
    }
    if state.profile.lock().unwrap().is_none() {
        return Err("no profile is open".into());
    }
    let sealer = tokio::task::spawn_blocking(move || profile::Sealer::new(&password))
        .await
        .map_err(err)?
        .map_err(err)?;
    let mut open = state.profile.lock().unwrap();
    let p = open.as_mut().ok_or("no profile is open")?;
    p.sealer = sealer;
    save_open(p)
}

// ───────────────────────────── local server data ─────────────────────────────

/// Data directory of the bundled server. Always derived here, never taken from the UI.
fn local_data_dir(app: &AppHandle) -> CmdResult<PathBuf> {
    Ok(app.path().app_data_dir().map_err(err)?.join("server"))
}

fn dir_size(path: &std::path::Path) -> (u64, u64) {
    let mut bytes = 0;
    let mut files = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return (0, 0);
    };
    for e in entries.flatten() {
        let Ok(meta) = e.metadata() else { continue };
        if meta.is_dir() {
            let (b, f) = dir_size(&e.path());
            bytes += b;
            files += f;
        } else {
            bytes += meta.len();
            files += 1;
        }
    }
    (bytes, files)
}

#[derive(Serialize)]
pub struct LocalDataInfo {
    path: String,
    exists: bool,
    bytes: u64,
    files: u64,
    users: u64,
    running: bool,
}

#[tauri::command]
fn local_data_info(app: AppHandle, state: State<'_, AppState>) -> CmdResult<LocalDataInfo> {
    let dir = local_data_dir(&app)?;
    let (bytes, files) = dir_size(&dir);
    let users = std::fs::read_dir(dir.join("users"))
        .map(|r| r.flatten().filter(|e| e.path().is_dir()).count() as u64)
        .unwrap_or(0);
    Ok(LocalDataInfo {
        path: dir.display().to_string(),
        exists: dir.exists(),
        bytes,
        files,
        users,
        running: state.sidecar.lock().unwrap().is_some(),
    })
}

/// Opens the local server's data folder in the system file manager.
#[tauri::command]
fn reveal_local_data(app: AppHandle) -> CmdResult<()> {
    let dir = local_data_dir(&app)?;
    std::fs::create_dir_all(&dir).map_err(err)?;
    app.opener()
        .open_path(dir.display().to_string(), None::<&str>)
        .map_err(err)
}

/// Stops the bundled server and deletes all of its data: every local user, their keys, indexes,
/// spool and "fs" destination backups. `confirm` must be exactly "DELETE".
#[tauri::command]
async fn reset_local_data(
    app: AppHandle,
    state: State<'_, AppState>,
    confirm: String,
    reset_preferences: bool,
) -> CmdResult<()> {
    if confirm != "DELETE" {
        return Err("type DELETE to confirm".into());
    }
    let dir = local_data_dir(&app)?;
    let sidecar = state.sidecar.lock().unwrap().take();
    let was_local = sidecar.is_some()
        || state
            .conn
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|c| c.sidecar_secret.is_some());
    if let Some(sc) = sidecar {
        sc.stop();
    }
    if was_local {
        stop_events(&state);
        *state.conn.lock().unwrap() = None;
    }
    // The process may need a moment to release its files (Windows keeps them locked).
    let mut last = None;
    for _ in 0..20 {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                last = None;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                last = None;
                break;
            }
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if let Some(e) = last {
        return Err(format!("could not delete {}: {e}", dir.display()));
    }
    if was_local {
        *state.profile.lock().unwrap() = None;
    }
    if reset_preferences {
        let _ = std::fs::remove_file(prefs_path(&app)?);
    }
    tracing::info!("local server data reset: {}", dir.display());
    Ok(())
}

// ───────────────────────────── session ─────────────────────────────

#[tauri::command]
async fn login(state: State<'_, AppState>, username: String, password: String) -> CmdResult<Me> {
    let me = login_as(&state, &username, &password).await?;
    // A profile without a username learns it; one made for someone else stays as it is.
    let mut open = state.profile.lock().unwrap();
    if let Some(p) = open.as_mut().filter(|p| p.data.username.is_none()) {
        p.data.username = Some(username);
        if let Err(e) = save_open(p) {
            tracing::warn!("could not update the profile: {e}");
        }
    }
    Ok(me)
}

/// Checks with the server that `password` is the logged-in user's, before a profile keeps it: a
/// typo would otherwise only show up at the next unlock. Servers without the check are trusted.
async fn verify_login(state: &AppState, password: &str) -> CmdResult<()> {
    let c = conn(state)?;
    if c.token.is_none() {
        return Err("log in first, so the profile knows whose password it keeps".into());
    }
    let resp = request(&c, reqwest::Method::POST, "/auth/verify-password")
        .json(&malo_api::VerifyPasswordRequest {
            password: password.to_string(),
        })
        .send()
        .await
        .map_err(err)?;
    match resp.status().as_u16() {
        404 => Ok(()),
        403 => Err("403|wrong_password|That isn't your Malo password. Nothing was saved.".into()),
        _ => check(resp).await.map(drop),
    }
}

async fn login_as(state: &AppState, username: &str, password: &str) -> CmdResult<Me> {
    let mut c = conn(state)?;
    c.token = None;
    let resp = request(&c, reqwest::Method::POST, "/auth/login")
        .json(&LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        })
        .send()
        .await
        .map_err(err)?;
    let r: LoginResponse = check(resp).await?.json().await.map_err(err)?;
    if let Some(cur) = state.conn.lock().unwrap().as_mut() {
        cur.token = Some(r.token);
    }
    *state.username.lock().unwrap() = Some(r.me.username.clone());
    Ok(r.me)
}

#[tauri::command]
async fn logout(state: State<'_, AppState>, lock: bool) -> CmdResult<()> {
    let c = conn(&state)?;
    let path = if lock { "/auth/lock" } else { "/auth/logout" };
    let _ = request(&c, reqwest::Method::POST, path).send().await;
    stop_events(&state);
    state.held.clear();
    if let Some(cur) = state.conn.lock().unwrap().as_mut() {
        cur.token = None;
    }
    // Like a password manager: locking or logging out closes the profile, whose password is
    // needed again to get back in.
    *state.profile.lock().unwrap() = None;
    Ok(())
}

/// Server-relative API path without traversal (`..`, `.`, encoded dots, backslashes).
fn valid_api_path(path: &str) -> bool {
    let route = path.split(['?', '#']).next().unwrap_or("");
    let lower = route.to_ascii_lowercase();
    path.starts_with('/')
        && !path.contains("://")
        && !path.starts_with("/auth/login")
        // The archive key leaves the server only through `save_recovery_kit`, straight to a file.
        && lower.trim_end_matches('/') != "/recovery-kit"
        && !route.contains('\\')
        && !lower.contains("%2e")
        && !lower.contains("%2f")
        && !lower.contains("%5c")
        && route.split('/').all(|seg| seg != ".." && seg != ".")
}

/// Generic authenticated API call. Paths are server-relative; auth endpoints that create tokens go through `login`.
#[tauri::command]
async fn api(
    state: State<'_, AppState>,
    method: String,
    path: String,
    body: Option<serde_json::Value>,
) -> CmdResult<serde_json::Value> {
    if !valid_api_path(&path) {
        return Err("400|bad_request|invalid path".into());
    }
    let c = conn(&state)?;
    let m = reqwest::Method::from_bytes(method.to_uppercase().as_bytes()).map_err(err)?;
    let mut r = request(&c, m, &path);
    if let Some(mut b) = body {
        state.held.release(&mut b);
        r = r.json(&b);
    }
    let resp = check(r.send().await.map_err(net_err)?).await?;
    let text = resp.text().await.map_err(err)?;
    if text.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(&text).map_err(err)
}

fn stop_events(state: &AppState) {
    if let Some(h) = state.events.lock().unwrap().take() {
        h.abort();
    }
}

/// Streams `EventBatch`es from `WS /events` into a Tauri channel, reconnecting until locked/logged out.
#[tauri::command]
async fn subscribe_events(
    state: State<'_, AppState>,
    on_event: Channel<EventBatch>,
) -> CmdResult<()> {
    stop_events(&state);
    let c = conn(&state)?;
    let token = c.token.clone().ok_or("not logged in")?;
    let ws_url = c.base.replacen("https://", "wss://", 1) + "/events";
    let handle = tokio::spawn(async move {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut backoff = Duration::from_secs(1);
        loop {
            let Ok(mut req) = ws_url.as_str().into_client_request() else {
                return;
            };
            req.headers_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            if let Some(s) = &c.sidecar_secret {
                req.headers_mut()
                    .insert("x-malo-sidecar", s.parse().unwrap());
            }
            let connector =
                tokio_tungstenite::Connector::Rustls(net::tls_config(c.fingerprint.as_deref()));
            match tokio_tungstenite::connect_async_tls_with_config(
                req,
                None,
                false,
                Some(connector),
            )
            .await
            {
                Ok((mut ws, _)) => {
                    backoff = Duration::from_secs(1);
                    while let Some(Ok(msg)) = ws.next().await {
                        if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
                            if let Ok(batch) = serde_json::from_str::<EventBatch>(&t) {
                                let locked = batch
                                    .events
                                    .iter()
                                    .any(|e| matches!(e, SyncEvent::Locked { .. }));
                                if on_event.send(batch).is_err() || locked {
                                    return;
                                }
                            }
                        }
                    }
                }
                Err(tokio_tungstenite::tungstenite::Error::Http(r)) if r.status() == 401 => {
                    let _ = on_event.send(EventBatch {
                        events: vec![SyncEvent::Locked {
                            reason: "session ended".into(),
                        }],
                    });
                    return;
                }
                Err(_) => {}
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    });
    *state.events.lock().unwrap() = Some(handle.abort_handle());
    Ok(())
}

// ───────────────────────────── files ─────────────────────────────

/// Zero-width, bidi-override and other invisible characters (same set as malo-core's layout).
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202F}'
        | '\u{205F}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{FFF0}'..='\u{FFFB}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}')
        || c.is_control()
}

/// Turns an untrusted name (e.g. an attachment's filename) into a plain file name: no directories,
/// no `..`, no leading dots, no characters that are special on any OS.
fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| !is_invisible(*c))
        .map(|c| if ":*?\"<>|".contains(c) { '_' } else { c })
        .collect();
    let cleaned = cleaned
        .trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' '])
        .to_string();
    if cleaned.is_empty() {
        "download".into()
    } else {
        cleaned.chars().take(200).collect()
    }
}

/// Where file dialogs open: Documents (home if there is none). Without a directory they start in
/// the process's working directory, which under `tauri dev` is src-tauri/: a file saved there
/// restarts the app.
fn dialog_dir(app: &AppHandle) -> Option<PathBuf> {
    let paths = app.path();
    paths.document_dir().or_else(|_| paths.home_dir()).ok()
}

/// A setting for the headless end-to-end tests (`MALO_AUTOSAVE_DIR`, `MALO_AUTOPICK_FILE`):
/// only debug builds read it, so a release can't be told to skip its file dialogs.
fn test_hook(name: &str) -> Option<PathBuf> {
    if cfg!(debug_assertions) {
        std::env::var_os(name).map(PathBuf::from)
    } else {
        None
    }
}

/// Native "Save as…" dialog. `MALO_AUTOSAVE_DIR` skips it (see [`test_hook`]).
fn save_target(app: &AppHandle, suggested: &str) -> Option<PathBuf> {
    let suggested = safe_file_name(suggested);
    if let Some(dir) = test_hook("MALO_AUTOSAVE_DIR") {
        return Some(dir.join(&suggested));
    }
    let mut dialog = app.dialog().file().set_file_name(&suggested);
    if let Some(dir) = dialog_dir(app) {
        dialog = dialog.set_directory(dir);
    }
    dialog.blocking_save_file().and_then(|p| p.into_path().ok())
}

async fn download_to(
    app: &AppHandle,
    state: &AppState,
    path: &str,
    suggested: &str,
) -> CmdResult<Option<String>> {
    let Some(target) = save_target(app, suggested) else {
        return Ok(None);
    };
    // The dialog already asked whether to replace an existing file.
    let tmp = fetch_to_temp(state, path, &target).await?;
    let placed = std::fs::rename(&tmp, &target);
    if placed.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    placed.map_err(err)?;
    mark_downloaded(&target);
    Ok(Some(target.display().to_string()))
}

/// Marks a saved file as downloaded from the internet (Windows' "mark of the web"), so Office
/// opens it in Protected View, blocks its macros, and SmartScreen checks it before it runs. Mail
/// came from the internet whatever server Malo copied it from. Best effort: a file system without
/// alternate data streams (FAT, network shares) can't hold the mark.
fn mark_downloaded(path: &std::path::Path) {
    #[cfg(windows)]
    {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        let _ = std::fs::write(stream, "[ZoneTransfer]\r\nZoneId=3\r\n");
    }
    #[cfg(not(windows))]
    let _ = path;
}

/// Streams a server response into a new hidden file next to `target`, with a random name: it
/// can't be an existing file, or a link someone placed to make the download land elsewhere.
async fn fetch_to_temp(
    state: &AppState,
    path: &str,
    target: &std::path::Path,
) -> CmdResult<PathBuf> {
    use rand::RngCore;
    use tokio::io::AsyncWriteExt;
    let c = conn(state)?;
    let resp = check(
        request(&c, reqwest::Method::GET, path)
            .send()
            .await
            .map_err(err)?,
    )
    .await?;
    let dir = target.parent().ok_or("no folder to save into")?;
    let mut rnd = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let tmp = dir.join(format!(".malo-{}.part", hex::encode(rnd)));
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .await
        .map_err(err)?;
    let written = async {
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            f.write_all(&chunk.map_err(err)?).await.map_err(err)?;
        }
        f.flush().await.map_err(err)
    }
    .await;
    if let Err(e) = written {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    Ok(tmp)
}

/// Copies a finished download to `target` if nothing has that name (checked and claimed in one
/// step, so nothing existing is ever overwritten or followed).
fn place_new(tmp: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    std::io::copy(&mut std::fs::File::open(tmp)?, &mut out)?;
    out.sync_all()
}

/// "Save as…" for an attachment. Never opened automatically.
#[tauri::command]
async fn save_attachment(
    app: AppHandle,
    state: State<'_, AppState>,
    message_id: i64,
    index: u32,
    filename: String,
) -> CmdResult<Option<String>> {
    let name = safe_file_name(&filename);
    download_to(
        &app,
        &state,
        &format!("/messages/{message_id}/attachments/{index}"),
        &name,
    )
    .await
}

#[tauri::command]
async fn save_raw(
    app: AppHandle,
    state: State<'_, AppState>,
    message_id: i64,
) -> CmdResult<Option<String>> {
    download_to(
        &app,
        &state,
        &format!("/messages/{message_id}/raw"),
        &format!("message-{message_id}.eml"),
    )
    .await
}

/// Saves several messages as `.eml` files into a folder the user picks (`MALO_AUTOSAVE_DIR` in
/// headless tests). Existing files are never overwritten. Returns the folder and how many were
/// saved; a failure stops there and reports how far it got.
#[tauri::command]
async fn save_raw_many(
    app: AppHandle,
    state: State<'_, AppState>,
    message_ids: Vec<i64>,
) -> CmdResult<Option<(String, u32)>> {
    let dir = match test_hook("MALO_AUTOSAVE_DIR") {
        Some(d) => d,
        None => {
            let mut dialog = app.dialog().file();
            if let Some(d) = dialog_dir(&app) {
                dialog = dialog.set_directory(d);
            }
            match dialog
                .blocking_pick_folder()
                .and_then(|p| p.into_path().ok())
            {
                Some(d) => d,
                None => return Ok(None),
            }
        }
    };
    let mut saved = 0u32;
    for id in message_ids {
        let first = dir.join(format!("message-{id}.eml"));
        let saved_one = async {
            let tmp = fetch_to_temp(&state, &format!("/messages/{id}/raw"), &first).await?;
            let mut n = 0u32;
            let placed = loop {
                let target = match n {
                    0 => first.clone(),
                    n => dir.join(format!("message-{id}-{n}.eml")),
                };
                match place_new(&tmp, &target) {
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 10_000 => n += 1,
                    res => break res.map(|()| mark_downloaded(&target)),
                }
            };
            let _ = std::fs::remove_file(&tmp);
            placed.map_err(err)
        }
        .await;
        if let Err(e) = saved_one {
            return Err(format!("saved {saved} message(s), then: {e}"));
        }
        saved += 1;
    }
    Ok(Some((dir.display().to_string(), saved)))
}

/// Raw RFC 822 source as text (lossy UTF-8), shown in a <pre>, never rendered.
#[tauri::command]
async fn raw_source(state: State<'_, AppState>, message_id: i64) -> CmdResult<String> {
    let c = conn(&state)?;
    let resp = check(
        request(
            &c,
            reqwest::Method::GET,
            &format!("/messages/{message_id}/raw"),
        )
        .send()
        .await
        .map_err(err)?,
    )
    .await?;
    let bytes = resp.bytes().await.map_err(err)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Writes a file only its owner can read: the kit is encrypted, but its passphrase is all that
/// stands between the file and every backup.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(0o600);
        // An existing file keeps its mode on open; tighten it first.
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Asks the server for the kit (the password again, and the passphrase that encrypts the file),
/// saves it, and only then tells the server it was saved. Cancelling or a failed write leaves the
/// reminder to save it in place.
#[tauri::command]
async fn save_recovery_kit(
    app: AppHandle,
    state: State<'_, AppState>,
    username: String,
    password: String,
    passphrase: String,
) -> CmdResult<Option<String>> {
    let c = conn(&state)?;
    let kit: SealedRecoveryKit = check(
        request(&c, reqwest::Method::POST, "/recovery-kit")
            .json(&RecoveryKitRequest {
                password,
                passphrase,
            })
            .send()
            .await
            .map_err(err)?,
    )
    .await?
    .json()
    .await
    .map_err(err)?;
    let Some(target) = save_target(&app, &format!("malo-recovery-kit-{username}.json")) else {
        return Ok(None);
    };
    write_private(&target, &serde_json::to_vec_pretty(&kit).map_err(err)?).map_err(err)?;
    check(
        request(&c, reqwest::Method::POST, "/recovery-kit/saved")
            .send()
            .await
            .map_err(err)?,
    )
    .await?;
    Ok(Some(target.display().to_string()))
}

#[tauri::command]
async fn pick_recovery_kit(
    app: AppHandle,
    state: State<'_, AppState>,
) -> CmdResult<Option<RecoveryKitFile>> {
    // `MALO_AUTOPICK_FILE` skips the dialog (see `test_hook`).
    let picked = match test_hook("MALO_AUTOPICK_FILE") {
        Some(p) => Some(p),
        None => {
            let mut dialog = app.dialog().file().add_filter("Recovery kit", &["json"]);
            if let Some(dir) = dialog_dir(&app) {
                dialog = dialog.set_directory(dir);
            }
            dialog.blocking_pick_file().and_then(|p| p.into_path().ok())
        }
    };
    let Some(path) = picked else {
        return Ok(None);
    };
    let mut kit: RecoveryKitFile = serde_json::from_slice(&std::fs::read(path).map_err(err)?)
        .map_err(|_| "not a Malo recovery kit".to_string())?;
    // A plain kit holds the archive key in the clear: the UI only gets a placeholder for it.
    if let RecoveryKitFile::Plain(k) = &mut kit {
        k.archive_key = state.held.hold(std::mem::take(&mut k.archive_key));
    }
    let format = match &kit {
        RecoveryKitFile::Sealed(k) => k.format.as_str(),
        RecoveryKitFile::Plain(k) => k.format.as_str(),
    };
    if format != SEALED_KIT_FORMAT && format != "malo-recovery-kit-v1" {
        return Err("unsupported recovery kit format".into());
    }
    Ok(Some(kit))
}

/// Opens a link in the system browser after the UI showed the real target and the user confirmed.
#[tauri::command]
fn open_external(app: AppHandle, url: String) -> CmdResult<()> {
    let u = url::Url::parse(&url).map_err(err)?;
    if !matches!(u.scheme(), "http" | "https" | "mailto") {
        return Err("only http, https and mailto links can be opened".into());
    }
    let u = if u.scheme() == "mailto" {
        safe_mailto(u)
    } else {
        u
    };
    app.opener().open_url(u.as_str(), None::<&str>).map_err(err)
}

/// A mailto link with only the fields a message link needs. Some mail apps (Evolution, KMail,
/// older Thunderbird) also take `attach=` and similar, which would attach a file of the user's
/// to a reply addressed to whoever wrote the link.
fn safe_mailto(mut u: url::Url) -> url::Url {
    const KEEP: &[&str] = &["to", "cc", "bcc", "subject", "body", "in-reply-to"];
    let kept: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, _)| KEEP.contains(&k.to_ascii_lowercase().as_str()))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    u.set_query(None);
    if !kept.is_empty() {
        // Spaces as %20: mail apps don't read the `+` of form encoding as a space.
        let q = kept
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        u.set_query(Some(&q));
    }
    u
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

#[tauri::command]
async fn oauth_authorize(
    app: AppHandle,
    state: State<'_, AppState>,
    req: oauth::OAuthRequest,
) -> CmdResult<oauth::OAuthResult> {
    let token = oauth::authorize(&app, req)
        .await
        .map_err(|e| format!("{e:#}"))?;
    // The UI saves the account with a placeholder; the token goes to the server from here.
    Ok(oauth::OAuthResult {
        refresh_token: state.held.hold(token),
    })
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .setup(|app| {
            let prefs = load_prefs(app.handle());
            // Rewritten once, so what older versions kept (the last mode and username) is gone.
            if prefs_path(app.handle()).is_ok_and(|p| p.exists()) {
                let _ = save_prefs(app.handle(), &prefs);
            }
            app.state::<AppState>()
                .tray_mode
                .store(prefs.tray_mode, Ordering::Relaxed);
            build_tray(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<AppState>();
                // Tray mode: keep the bundled server running in the background.
                if state.tray_mode.load(Ordering::Relaxed)
                    && state.sidecar.lock().unwrap().is_some()
                {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            probe_server,
            connect_remote,
            start_local,
            get_prefs,
            set_tray_mode,
            profiles,
            pick_profile,
            unlock_profile,
            close_profile,
            forget_profile,
            set_remember_recent,
            save_profile,
            set_profile_login,
            change_profile_password,
            disconnect,
            login,
            logout,
            api,
            subscribe_events,
            save_attachment,
            save_raw,
            save_raw_many,
            raw_source,
            save_recovery_kit,
            pick_recovery_kit,
            open_external,
            oauth_authorize,
            local_data_info,
            reveal_local_data,
            reset_local_data,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Malo")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(sc) = app.state::<AppState>().sidecar.lock().unwrap().take() {
                    sc.stop();
                }
            }
        });
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;
    let show = MenuItem::with_id(app, "show", "Show Malo", true, None::<&str>)?;
    let quit = MenuItem::with_id(
        app,
        "quit",
        "Quit (stops the local server)",
        true,
        None::<&str>,
    )?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    let mut tray = TrayIconBuilder::with_id("malo")
        .menu(&menu)
        .tooltip("Malo backup");
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.on_menu_event(|app, e| match e.id.as_ref() {
        "show" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }
        "quit" => app.exit(0),
        _ => {}
    })
    .build(app)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saving_never_overwrites_or_follows_links() {
        let dir = std::env::temp_dir().join(format!("malo-place-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tmp = dir.join(".malo-x.part");
        std::fs::write(&tmp, b"new").unwrap();
        let existing = dir.join("message-1.eml");
        std::fs::write(&existing, b"old").unwrap();
        let e = place_new(&tmp, &existing).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&existing).unwrap(), b"old");
        #[cfg(unix)]
        {
            let victim = dir.join("victim");
            std::os::unix::fs::symlink(&victim, dir.join("message-2.eml")).unwrap();
            assert!(place_new(&tmp, &dir.join("message-2.eml")).is_err());
            assert!(!victim.exists(), "a link isn't followed");
        }
        place_new(&tmp, &dir.join("message-3.eml")).unwrap();
        assert_eq!(std::fs::read(dir.join("message-3.eml")).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mailto_links_cannot_attach_files() {
        let clean = |s: &str| safe_mailto(url::Url::parse(s).unwrap()).to_string();
        assert_eq!(
            clean("mailto:a@b.example?subject=Hi%20there&attach=/home/me/.ssh/id_rsa&body=x"),
            "mailto:a@b.example?subject=Hi%20there&body=x"
        );
        for bad in [
            "mailto:a@b?ATTACH=~/.gnupg",
            "mailto:a@b?attachment=file:///etc/passwd",
            "mailto:a@b?x-attach=/x",
        ] {
            assert_eq!(clean(bad), "mailto:a@b", "{bad}");
        }
        assert_eq!(clean("mailto:a@b"), "mailto:a@b");
    }

    #[test]
    fn file_names_cannot_escape() {
        assert_eq!(safe_file_name("../../.bashrc"), "bashrc");
        assert_eq!(safe_file_name(".."), "download");
        assert_eq!(safe_file_name("..\\..\\evil.exe"), "evil.exe");
        assert_eq!(safe_file_name("/etc/passwd"), "passwd");
        assert_eq!(safe_file_name("C:\\Windows\\x.dll"), "x.dll");
        assert_eq!(safe_file_name("a:b?.txt"), "a_b_.txt");
        assert_eq!(safe_file_name("invoice.pdf"), "invoice.pdf");
        // RLO would make "invoice\u{202E}fdp.exe" look like "invoiceexe.pdf" in a file manager.
        assert_eq!(safe_file_name("invoice\u{202E}fdp.exe"), "invoicefdp.exe");
        assert_eq!(safe_file_name("\u{200B}..\u{200B}"), "download");
        assert_eq!(
            safe_file_name("Bericht für Müller 😀.pdf"),
            "Bericht für Müller 😀.pdf"
        );
        assert_eq!(safe_file_name("   "), "download");
    }

    #[test]
    fn api_paths_cannot_traverse() {
        assert!(valid_api_path("/messages/1/view?html=true"));
        assert!(valid_api_path("/messages?q=..%2Fx")); // query strings are data, not paths
        for bad in [
            "/messages/../admin/users",
            "/./me",
            "/messages/%2e%2e/admin",
            "/a%2Fb",
            "/x\\y",
            "messages",
            "https://evil/x",
            "/auth/login",
            "/recovery-kit",
            "/Recovery-Kit/",
        ] {
            assert!(!valid_api_path(bad), "{bad}");
        }
    }
}
