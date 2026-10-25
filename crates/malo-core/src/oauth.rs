//! OAuth2: provider presets and server-side access-token refresh (the interactive flow runs in the GUI).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use malo_api::{AccountAuth, AccountPreset, OAuthPreset, OAuthProvider, TlsMode};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RefreshToken, Scope, TokenResponse, TokenUrl};

use crate::config::Account;

pub fn google() -> OAuthPreset {
    OAuthPreset {
        provider: OAuthProvider::Google,
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
        token_url: "https://oauth2.googleapis.com/token".into(),
        scopes: vec!["https://mail.google.com/".into()],
        guide_url: "https://developers.google.com/identity/protocols/oauth2/native-app".into(),
    }
}

pub fn microsoft() -> OAuthPreset {
    OAuthPreset {
        provider: OAuthProvider::Microsoft,
        auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
        token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
        scopes: vec![
            "https://outlook.office.com/IMAP.AccessAsUser.All".into(),
            "offline_access".into(),
        ],
        guide_url: "https://learn.microsoft.com/entra/identity-platform/quickstart-register-app"
            .into(),
    }
}

pub fn presets() -> Vec<AccountPreset> {
    let p = |id: &str, name: &str, host: &str, oauth: Option<OAuthPreset>, hint: Option<&str>| {
        AccountPreset {
            id: id.into(),
            name: name.into(),
            host: host.into(),
            port: 993,
            tls: TlsMode::Implicit,
            oauth,
            app_password_hint: hint.map(Into::into),
        }
    };
    vec![
        p("gmail", "Gmail / Google Workspace", "imap.gmail.com", Some(google()),
          Some("Create an app password at https://myaccount.google.com/apppasswords (requires 2-Step Verification).")),
        p("outlook", "Outlook.com / Microsoft 365", "outlook.office365.com", Some(microsoft()),
          Some("Microsoft disabled basic auth for most tenants; use OAuth2.")),
        p("yahoo", "Yahoo Mail", "imap.mail.yahoo.com", None,
          Some("Generate an app password in Yahoo Account Security.")),
        p("icloud", "iCloud Mail", "imap.mail.me.com", None,
          Some("Generate an app-specific password at https://account.apple.com.")),
        p("fastmail", "Fastmail", "imap.fastmail.com", None,
          Some("Create an app password under Settings → Privacy & Security.")),
        p("gmx", "GMX", "imap.gmx.net", None, None),
        p("zoho", "Zoho Mail", "imap.zoho.com", None, Some("Use an application-specific password.")),
        p("aol", "AOL Mail", "imap.aol.com", None, Some("Generate an app password in account security.")),
        p("custom", "Other IMAP server", "", None, None),
    ]
}

/// Supplies IMAP access tokens for OAuth2 accounts.
pub trait TokenSource: Send + Sync {
    fn access_token<'a>(&'a self, account: &'a Account) -> BoxFuture<'a, anyhow::Result<String>>;
    /// Drops a cached token after the server rejected it.
    fn invalidate(&self, account_id: &str);
}

/// Called with `(account_id, new_refresh_token)`.
pub type RotateFn = Box<dyn Fn(&str, String) + Send + Sync>;

/// Refreshes tokens on demand and caches them until shortly before expiry.
/// `on_rotate` is called when the provider returns a new refresh token (Microsoft rotates them).
pub struct TokenCache {
    cache: Mutex<HashMap<String, (String, Instant)>>,
    on_rotate: RotateFn,
    http: reqwest::Client,
}

impl TokenCache {
    pub fn new(on_rotate: RotateFn) -> Self {
        TokenCache {
            cache: Mutex::new(HashMap::new()),
            on_rotate,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
                .expect("http client"),
        }
    }

    async fn refresh(&self, account: &Account) -> anyhow::Result<String> {
        let AccountAuth::OAuth2 {
            auth_url,
            token_url,
            client_id,
            client_secret,
            scopes,
            refresh_token,
            ..
        } = &account.auth
        else {
            anyhow::bail!("account does not use OAuth2");
        };
        let mut client = BasicClient::new(ClientId::new(client_id.clone()))
            .set_auth_uri(AuthUrl::new(auth_url.clone())?)
            .set_token_uri(TokenUrl::new(token_url.clone())?);
        if let Some(secret) = client_secret.as_ref().filter(|s| !s.is_empty()) {
            client = client.set_client_secret(ClientSecret::new(secret.clone()));
        }
        let rt = RefreshToken::new(refresh_token.clone());
        let mut req = client.exchange_refresh_token(&rt);
        for s in scopes {
            req = req.add_scope(Scope::new(s.clone()));
        }
        let token = req
            .request_async(&self.http)
            .await
            .map_err(|e| anyhow::anyhow!("token refresh failed: {e}"))?;
        if let Some(new_rt) = token.refresh_token() {
            if new_rt.secret() != refresh_token {
                (self.on_rotate)(&account.id, new_rt.secret().clone());
            }
        }
        let ttl = token.expires_in().unwrap_or(Duration::from_secs(3600));
        let access = token.access_token().secret().clone();
        self.cache.lock().unwrap().insert(
            account.id.clone(),
            (
                access.clone(),
                Instant::now() + ttl.saturating_sub(Duration::from_secs(120)),
            ),
        );
        Ok(access)
    }
}

impl TokenSource for TokenCache {
    fn access_token<'a>(&'a self, account: &'a Account) -> BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async move {
            if let Some((tok, exp)) = self.cache.lock().unwrap().get(&account.id) {
                if Instant::now() < *exp {
                    return Ok(tok.clone());
                }
            }
            self.refresh(account).await
        })
    }

    fn invalidate(&self, account_id: &str) {
        self.cache.lock().unwrap().remove(account_id);
    }
}

/// SASL XOAUTH2 initial response.
pub fn xoauth2_string(user: &str, access_token: &str) -> String {
    format!("user={user}\x01auth=Bearer {access_token}\x01\x01")
}
