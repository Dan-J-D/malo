//! malo-server: HTTPS API, auth + key ring, scheduler and job queue on top of `malo-core`.

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod jobs;
pub mod keyring;
pub mod kit;
pub mod net;
pub mod routes;
pub mod scheduler;
pub mod state;
pub mod tlsgen;
pub mod ws;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;

use crate::config::ServerConfig;
use crate::db::Db;
use crate::jobs::JobManager;
use crate::keyring::KeyRing;
use crate::state::{AppState, EventHub, SharedState};

/// Makes the process harder to inspect: no core dumps, not ptrace-able by other users.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    #[cfg(unix)]
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
    }
}

async fn sidecar_guard(State(state): State<SharedState>, req: Request, next: Next) -> Response {
    if let Some(secret) = &state.cfg.sidecar_secret {
        let given = req
            .headers()
            .get("x-malo-sidecar")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let ok = given.len() == secret.len()
            && given
                .bytes()
                .zip(secret.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        if !ok && req.uri().path() != "/healthz" {
            return (StatusCode::FORBIDDEN, "missing sidecar secret").into_response();
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    h.insert("cache-control", "no-store".parse().unwrap());
    h.insert("referrer-policy", "no-referrer".parse().unwrap());
    resp
}

pub fn router(state: SharedState) -> Router {
    use routes::*;
    let burst: u32 = std::env::var("MALO_LOGIN_BURST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let governor = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(2)
            .burst_size(burst)
            .key_extractor(auth::ClientIpKey {
                trust_proxy: state.cfg.trust_proxy_headers,
            })
            .finish()
            .expect("governor config"),
    );
    let limited = Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/register", post(auth::register))
        .route("/auth/recover", post(auth::recover))
        .route("/recovery-kit", post(auth::recovery_kit))
        .route("/setup", post(auth::setup))
        .layer(GovernorLayer { config: governor });
    Router::new()
        .merge(limited)
        .route("/status", get(status))
        .route("/healthz", get(healthz))
        .route("/presets", get(presets))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/lock", post(auth::lock))
        .route("/auth/password", post(auth::change_password))
        .route("/me/delete", post(auth::delete_self))
        .route("/me", get(auth::get_me))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/recovery-kit/saved", post(auth::recovery_kit_saved))
        .route("/accounts", get(list_accounts).post(create_account))
        .route("/accounts/test", post(test_new_account))
        .route(
            "/accounts/{id}",
            get(get_account).put(update_account).delete(delete_account),
        )
        .route("/accounts/{id}/test", post(test_saved_account))
        .route("/accounts/{id}/policy", put(put_policy))
        .route("/accounts/{id}/policy/arm", post(arm_policy))
        .route("/accounts/{id}/policy/disarm", post(disarm_policy))
        .route(
            "/destinations",
            get(list_destinations).post(create_destination),
        )
        .route("/destinations/test", post(test_new_destination))
        .route(
            "/destinations/{id}",
            put(update_destination).delete(delete_destination),
        )
        .route("/destinations/{id}/test", post(test_saved_destination))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/{id}", get(get_job).delete(cancel_job))
        .route("/schedules", get(list_schedules))
        .route("/mailboxes", get(list_mailboxes))
        .route("/messages", get(list_messages))
        .route("/messages/reviewed", post(mark_reviewed))
        .route("/messages/{id}", get(get_message))
        .route("/messages/{id}/view", get(view_message))
        .route("/messages/{id}/raw", get(raw_message))
        .route("/messages/{id}/attachments/{n}", get(attachment))
        .route("/checks", get(list_checks))
        .route("/checks/latest", get(latest_check))
        .route("/audit", get(audit))
        .route("/admin/users", get(admin_users))
        .route(
            "/admin/users/{id}",
            put(admin_update_user).delete(admin_delete_user),
        )
        .route(
            "/admin/invites",
            get(admin_invites).post(admin_create_invite),
        )
        .route(
            "/admin/invites/{id}",
            axum::routing::delete(admin_revoke_invite),
        )
        .route("/admin/audit", get(admin_audit_log))
        .route(
            "/admin/settings",
            get(admin_get_settings).put(admin_put_settings),
        )
        .route("/events", get(ws::events))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), sidecar_guard))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

pub struct Running {
    pub addr: SocketAddr,
    pub fingerprint: Option<String>,
    pub setup_token: Option<String>,
    pub state: SharedState,
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Running {
    /// Graceful stop: no new jobs, scheduler stopped, every user locked (running jobs stop at the
    /// next message), then waits up to `grace` for jobs to finish and closes the listener.
    pub async fn shutdown(self, grace: std::time::Duration) {
        self.state.shutdown.cancel();
        for uid in self.state.keyring.unlocked_ids() {
            scheduler::lock_user(&self.state, &uid, "server shutting down");
        }
        let deadline = tokio::time::Instant::now() + grace;
        while self.state.jobs.active() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        if self.state.jobs.active() > 0 {
            tracing::warn!(
                "{} job(s) still running at shutdown",
                self.state.jobs.active()
            );
        }
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Opens the data dir, prepares TLS and starts serving in the background.
pub async fn start(cfg: ServerConfig) -> anyhow::Result<Running> {
    std::fs::create_dir_all(cfg.data_dir.join("users"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cfg.data_dir, std::fs::Permissions::from_mode(0o700));
    }
    let db = Arc::new(Db::open(&cfg.data_dir.join("server.db"))?);
    // A restart seals every user: no sessions survive, jobs left running are failed.
    db.delete_all_sessions()?;
    db.fail_stale_jobs()?;
    let setup_token = if db.user_count()? == 0 {
        let t = auth::random_token()[..32].to_string();
        db.set_setting("setup_token_hash", &auth::hash_token(&t))?;
        Some(t)
    } else {
        None
    };
    let tls = if cfg.tls {
        Some(tlsgen::load_or_create(&cfg)?)
    } else {
        None
    };
    let state: SharedState = Arc::new(AppState {
        db,
        keyring: KeyRing::default(),
        events: Arc::new(EventHub::default()),
        jobs: JobManager::new(cfg.workers),
        kdf_slots: tokio::sync::Semaphore::new(2),
        login_failures: Mutex::new(HashMap::new()),
        cert_fingerprint: tls.as_ref().map(|t| t.fingerprint.clone()),
        idle_watchers: Mutex::new(HashMap::new()),
        shutdown: tokio_util::sync::CancellationToken::new(),
        cfg: cfg.clone(),
    });
    scheduler::spawn(state.clone());
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let listener = std::net::TcpListener::bind(cfg.listen)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let task = match &tls {
        Some(t) => {
            let rc = axum_server::tls_rustls::RustlsConfig::from_config(t.config.clone());
            let server = axum_server::from_tcp_rustls(listener, rc);
            tokio::spawn(async move { server.serve(app).await.map_err(Into::into) })
        }
        None => {
            let l = tokio::net::TcpListener::from_std(listener)?;
            tokio::spawn(async move { axum::serve(l, app).await.map_err(Into::into) })
        }
    };
    Ok(Running {
        addr,
        fingerprint: tls.map(|t| t.fingerprint),
        setup_token,
        state,
        task,
    })
}
