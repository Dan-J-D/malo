//! Harness for integration tests against `docker compose --profile test up -d`.
//! Tests are skipped unless `MALO_IT=1`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use futures::future::BoxFuture;
use futures::StreamExt;
use malo_api::*;
use malo_core::config::Account;
use malo_core::imap::{self, ImapConn};
use malo_core::oauth::TokenSource;
use malo_server::config::ServerConfig;
use malo_server::Running;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub const IMAP_PORT: u16 = 10993;
pub const IMAP_NO_UIDPLUS_PORT: u16 = 11993;
pub const S3_ENDPOINT: &str = "http://127.0.0.1:19000";
pub const GCS_ENDPOINT: &str = "http://127.0.0.1:14443";
pub const GCS_BUCKET: &str = "malo-gcs";

pub fn enabled() -> bool {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("MALO_INSECURE_FAST_KDF", "1");
        std::env::set_var("MALO_SCHEDULER_TICK_MS", "500");
        std::env::set_var("MALO_LOGIN_BURST", "1000");
        let _ = tracing_subscriber::fmt()
            .with_env_filter("warn,malo=info")
            .with_test_writer()
            .try_init();
    });
    let on = std::env::var("MALO_IT").as_deref() == Ok("1");
    if !on {
        eprintln!("skipping: set MALO_IT=1 and start `docker compose --profile test up -d`");
    }
    on
}

pub fn uniq(prefix: &str) -> String {
    format!(
        "{prefix}{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

pub async fn start_server(
    data: &std::path::Path,
    tweak: impl FnOnce(&mut ServerConfig),
) -> Running {
    let mut cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.to_path_buf(),
        workers: 4,
        ..Default::default()
    };
    tweak(&mut cfg);
    malo_server::start(cfg).await.expect("server starts")
}

#[derive(Clone)]
pub struct Api {
    pub base: String,
    pub ws: String,
    pub http: reqwest::Client,
    pub token: Option<String>,
    pub fingerprint: String,
}

impl Api {
    pub fn new(r: &Running) -> Api {
        let fp = r.fingerprint.clone().expect("tls on");
        let tls = (*malo_core::tls::pinned_config(&fp)).clone();
        Api {
            base: format!("https://127.0.0.1:{}", r.addr.port()),
            ws: format!("wss://127.0.0.1:{}/events", r.addr.port()),
            http: reqwest::Client::builder()
                .use_preconfigured_tls(tls)
                .timeout(Duration::from_secs(120))
                .build()
                .unwrap(),
            token: None,
            fingerprint: fp,
        }
    }

    fn req(&self, m: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let r = self.http.request(m, format!("{}{}", self.base, path));
        match &self.token {
            Some(t) => r.bearer_auth(t),
            None => r,
        }
    }

    pub async fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        m: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, (u16, String)> {
        let mut r = self.req(m, path);
        if let Some(b) = body {
            r = r.json(b);
        }
        let resp = r.send().await.map_err(|e| (0, e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status >= 400 {
            return Err((status, text));
        }
        let text = if text.is_empty() {
            "null".to_string()
        } else {
            text
        };
        serde_json::from_str(&text).map_err(|e| (status, format!("{e}: {text}")))
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> T {
        self.call::<(), T>(reqwest::Method::GET, path, None)
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e:?}"))
    }
    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, b: &B) -> T {
        self.call(reqwest::Method::POST, path, Some(b))
            .await
            .unwrap_or_else(|e| panic!("POST {path}: {e:?}"))
    }
    pub async fn put<B: Serialize, T: DeserializeOwned>(&self, path: &str, b: &B) -> T {
        self.call(reqwest::Method::PUT, path, Some(b))
            .await
            .unwrap_or_else(|e| panic!("PUT {path}: {e:?}"))
    }
    pub async fn status_of(&self, m: reqwest::Method, path: &str) -> u16 {
        self.req(m, path)
            .send()
            .await
            .map(|r| r.status().as_u16())
            .unwrap_or(0)
    }
    pub async fn bytes(&self, path: &str) -> Vec<u8> {
        let r = self.req(reqwest::Method::GET, path).send().await.unwrap();
        assert!(r.status().is_success(), "GET {path}: {}", r.status());
        r.bytes().await.unwrap().to_vec()
    }

    pub async fn login(&self, username: &str, password: &str) -> Api {
        let r: LoginResponse = self
            .post(
                "/auth/login",
                &LoginRequest {
                    username: username.into(),
                    password: password.into(),
                },
            )
            .await;
        Api {
            token: Some(r.token),
            ..self.clone()
        }
    }

    pub async fn run_job(&self, kind: JobKind) -> JobInfo {
        let job: JobInfo = self.post("/jobs", &CreateJobRequest { kind }).await;
        self.wait_job(&job.id).await
    }

    pub async fn wait_job(&self, id: &str) -> JobInfo {
        for _ in 0..600 {
            let j: JobInfo = self.get(&format!("/jobs/{id}")).await;
            if j.state.is_finished() {
                return j;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("job {id} did not finish");
    }

    /// Collects every event of this session in the background.
    pub async fn events(&self) -> Arc<Mutex<Vec<SyncEvent>>> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = self.ws.as_str().into_client_request().unwrap();
        req.headers_mut().insert(
            "authorization",
            format!("Bearer {}", self.token.as_ref().unwrap())
                .parse()
                .unwrap(),
        );
        let tls = malo_core::tls::pinned_config(&self.fingerprint);
        let (mut socket, _) = tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(tls)),
        )
        .await
        .expect("ws connect");
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = out.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = socket.next().await {
                if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
                    if let Ok(b) = serde_json::from_str::<EventBatch>(&t) {
                        sink.lock().unwrap().extend(b.events);
                    }
                }
            }
        });
        out
    }
}

/// Creates the first admin and returns an admin session.
pub async fn bootstrap(r: &Running) -> Api {
    let api = Api::new(r);
    let token = r.setup_token.clone().expect("fresh server");
    let _: serde_json::Value = api
        .post(
            "/setup",
            &SetupRequest {
                setup_token: token,
                username: "admin".into(),
                password: "admin-password-1".into(),
            },
        )
        .await;
    api.login("admin", "admin-password-1").await
}

/// Registers a user through an admin invite and logs in.
pub async fn new_user(admin: &Api, name: &str) -> Api {
    let invite: Invite = admin
        .post(
            "/admin/invites",
            &CreateInviteRequest {
                username: Some(name.into()),
                role: Role::User,
                valid_hours: 1,
            },
        )
        .await;
    let anon = Api {
        token: None,
        ..admin.clone()
    };
    let _: serde_json::Value = anon
        .post(
            "/auth/register",
            &RegisterRequest {
                username: name.into(),
                password: format!("{name}-password"),
                invite_code: Some(invite.code),
                recovery_kit: None,
                kit_passphrase: None,
            },
        )
        .await;
    anon.login(name, &format!("{name}-password")).await
}

pub fn imap_input(name: &str, imap_user: &str, port: u16) -> AccountInput {
    AccountInput {
        revision: None,
        name: name.into(),
        host: "localhost".into(),
        port,
        tls: TlsMode::Implicit,
        accept_invalid_certs: true,
        username: imap_user.into(),
        auth: AccountAuth::Password {
            password: "pass".into(),
        },
        backup_interval_minutes: 60,
        idle: false,
        enabled: true,
        smtp: None,
    }
}

pub struct NoTokens;
impl TokenSource for NoTokens {
    fn access_token<'a>(&'a self, _: &'a Account) -> BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async { anyhow::bail!("no oauth in tests") })
    }
    fn invalidate(&self, _: &str) {}
}

pub async fn imap_conn(imap_user: &str, port: u16) -> ImapConn {
    let a = Account::from_input("seed".into(), imap_input("seed", imap_user, port), None).unwrap();
    // Another mail client: it must not take Malo's own per-host connection slots.
    imap::connect_unmetered(&a, &NoTokens)
        .await
        .expect("imap connect")
}

/// A test message; `attachment` bytes are base64-encoded into a second part.
pub fn mail(subject: &str, attachment: usize) -> Vec<u8> {
    use base64::Engine;
    let id = uuid::Uuid::new_v4();
    let mut m = format!(
        "From: Sender <sender@example.com>\r\nTo: rcpt@example.com\r\nSubject: {subject}\r\n\
Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <{id}@example.com>\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n--XX\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody of {subject} ünïcödé\r\n"
    );
    if attachment > 0 {
        let data: Vec<u8> = (0..attachment).map(|i| (i * 7 % 256) as u8).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        m.push_str("--XX\r\nContent-Type: application/octet-stream; name=\"data.bin\"\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n");
        for chunk in b64.as_bytes().chunks(76) {
            m.push_str(std::str::from_utf8(chunk).unwrap());
            m.push_str("\r\n");
        }
    }
    m.push_str("--XX--\r\n");
    m.into_bytes()
}

pub async fn append(
    conn: &mut ImapConn,
    mailbox: &str,
    flags: Option<&str>,
    date: Option<&str>,
    content: &[u8],
) {
    let date = date.map(|d| format!("\"{d}\""));
    conn.session
        .append(mailbox, flags, date.as_deref(), content)
        .await
        .expect("append");
}

pub async fn create_mailbox(conn: &mut ImapConn, name: &str) {
    conn.session.create(name).await.expect("create mailbox");
}

pub fn s3_dest(name: &str, bucket: &str, root: &str, encrypt: bool) -> DestinationInput {
    let opts: BTreeMap<String, String> = [
        ("bucket", bucket),
        ("endpoint", S3_ENDPOINT),
        ("region", "us-east-1"),
        ("access_key_id", "malo-test"),
        ("secret_access_key", "malo-test-secret"),
        ("disable_config_load", "true"),
        ("disable_ec2_metadata", "true"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    DestinationInput {
        revision: None,
        name: name.into(),
        scheme: "s3".into(),
        options: opts,
        root: root.into(),
        encrypt,
        required_for_purge: true,
        deep_check: DeepCheckMode::Full,
    }
}

pub async fn ensure_gcs_bucket() {
    let _ = reqwest::Client::new()
        .post(format!("{GCS_ENDPOINT}/storage/v1/b"))
        .json(&serde_json::json!({"name": GCS_BUCKET}))
        .send()
        .await;
}

pub fn gcs_dest(name: &str, root: &str, encrypt: bool) -> DestinationInput {
    let opts: BTreeMap<String, String> = [
        ("bucket", GCS_BUCKET),
        ("endpoint", GCS_ENDPOINT),
        ("allow_anonymous", "true"),
        ("disable_vm_metadata", "true"),
        ("disable_config_load", "true"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    DestinationInput {
        revision: None,
        name: name.into(),
        scheme: "gcs".into(),
        options: opts,
        root: root.into(),
        encrypt,
        required_for_purge: true,
        deep_check: DeepCheckMode::Full,
    }
}

pub fn fs_dest(name: &str, root: &str) -> DestinationInput {
    DestinationInput {
        revision: None,
        name: name.into(),
        scheme: "fs".into(),
        options: BTreeMap::from([("root".to_string(), root.to_string())]),
        root: String::new(),
        encrypt: false,
        required_for_purge: true,
        deep_check: DeepCheckMode::Full,
    }
}

/// Direct OpenDAL access to the S3 test bucket (to delete or corrupt objects behind Malo's back).
pub fn s3_operator(bucket: &str) -> opendal::Operator {
    let opts = s3_dest("x", bucket, "", false)
        .options
        .into_iter()
        .collect::<Vec<_>>();
    opendal::Operator::via_iter(opendal::Scheme::S3, opts).unwrap()
}

pub async fn wait_until(mut f: impl FnMut() -> BoxFuture<'static, bool>, secs: u64) -> bool {
    for _ in 0..secs * 5 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

pub const OAUTH_ISSUER: &str = "http://localhost:18080/default";
pub const IMAP_OAUTH_PORT: u16 = 12993;

/// Runs the authorization-code + PKCE flow against the mock provider (its login form takes any
/// username, which becomes the token's `sub`) and returns a refresh token.
pub async fn oauth_refresh_token(username: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let verifier = format!(
        "v-{}-{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let redirect = "http://127.0.0.1:5555/callback";
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let authorize = format!(
        "{OAUTH_ISSUER}/authorize?response_type=code&client_id=malo-test&redirect_uri={redirect}\
&scope=openid%20offline_access&state=s&code_challenge={challenge}&code_challenge_method=S256"
    );
    let resp = http
        .post(&authorize)
        .form(&[("username", username)])
        .send()
        .await
        .expect("authorize");
    let location = resp
        .headers()
        .get("location")
        .expect("redirect with code")
        .to_str()
        .unwrap()
        .to_string();
    let code = url_param(&location, "code").expect("code");
    let tok: serde_json::Value = http
        .post(format!("{OAUTH_ISSUER}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect),
            ("client_id", "malo-test"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    tok["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string()
}

fn url_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(str::to_string))
}

pub fn oauth_input(name: &str, imap_user: &str, refresh_token: &str) -> AccountInput {
    AccountInput {
        revision: None,
        name: name.into(),
        host: "localhost".into(),
        port: IMAP_OAUTH_PORT,
        tls: TlsMode::Implicit,
        accept_invalid_certs: true,
        username: imap_user.into(),
        auth: AccountAuth::OAuth2 {
            provider: OAuthProvider::Custom,
            auth_url: format!("{OAUTH_ISSUER}/authorize"),
            token_url: format!("{OAUTH_ISSUER}/token"),
            client_id: "malo-test".into(),
            client_secret: None,
            scopes: vec!["openid".into(), "offline_access".into()],
            refresh_token: refresh_token.into(),
        },
        backup_interval_minutes: 60,
        idle: false,
        enabled: true,
        smtp: None,
    }
}

/// IMAP session on the OAuth-only Dovecot, authenticated through the real refresh + XOAUTH2 path.
pub async fn oauth_imap_conn(imap_user: &str, refresh_token: &str) -> ImapConn {
    let a = Account::from_input(
        "seed".into(),
        oauth_input("seed", imap_user, refresh_token),
        None,
    )
    .unwrap();
    let tokens = malo_core::oauth::TokenCache::new(Box::new(|_, _| {}));
    imap::connect(&a, &tokens)
        .await
        .expect("oauth imap connect")
}
