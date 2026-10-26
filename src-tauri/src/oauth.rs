//! OAuth2 authorization-code flow with PKCE on a 127.0.0.1 loopback listener, using the system browser.
//! The resulting refresh token is sent to the server, which refreshes access tokens itself.

use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_opener::OpenerExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Deserialize)]
pub struct OAuthRequest {
    pub provider: malo_api::OAuthProvider,
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    /// Pre-fills the account picker.
    pub login_hint: Option<String>,
}

#[derive(Serialize)]
pub struct OAuthResult {
    /// A placeholder for the token (see `held`).
    pub refresh_token: String,
}

const PAGE: &str = "<!doctype html><meta charset=utf-8><title>Malo</title><body style=\"font-family:sans-serif;padding:3em\"><h2>Malo is authorized.</h2><p>You can close this tab and return to Malo.</p>";

/// A provider URL (which can come from the server's presets): https, or http to this machine for
/// local test providers. Never another scheme, which the system would hand to whatever program
/// claims it.
fn provider_url(what: &str, url: &str) -> anyhow::Result<url::Url> {
    let u = url::Url::parse(url).with_context(|| format!("the {what} isn't a valid URL"))?;
    let loopback = match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match u.scheme() {
        "https" => Ok(u),
        "http" if loopback => Ok(u),
        _ => bail!("the {what} must be an https address"),
    }
}

fn query_param(target: &str, key: &str) -> Option<String> {
    let url = url::Url::parse(&format!("http://localhost{target}")).ok()?;
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// Signs in through the browser; returns the refresh token.
pub async fn authorize(app: &AppHandle, req: OAuthRequest) -> anyhow::Result<String> {
    provider_url("authorization URL", &req.auth_url)?;
    provider_url("token URL", &req.token_url)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let mut client = BasicClient::new(ClientId::new(req.client_id.clone()))
        .set_auth_uri(AuthUrl::new(req.auth_url.clone())?)
        .set_token_uri(TokenUrl::new(req.token_url.clone())?)
        .set_redirect_uri(RedirectUrl::new(redirect)?);
    if let Some(s) = req.client_secret.as_ref().filter(|s| !s.is_empty()) {
        client = client.set_client_secret(ClientSecret::new(s.clone()));
    }
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut auth = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(challenge);
    for s in &req.scopes {
        auth = auth.add_scope(Scope::new(s.clone()));
    }
    if req.provider == malo_api::OAuthProvider::Google {
        // Needed for Google to issue a refresh token.
        auth = auth
            .add_extra_param("access_type", "offline")
            .add_extra_param("prompt", "consent");
    }
    if let Some(h) = &req.login_hint {
        auth = auth.add_extra_param("login_hint", h.clone());
    }
    let (url, csrf) = auth.url();
    let url = provider_url("authorization URL", url.as_str())?;
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .context("cannot open the browser")?;

    let code = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            let (mut sock, _) = listener.accept().await?;
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await?;
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            if !target.starts_with("/callback") {
                let _ = sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
                continue;
            }
            // Any page in the browser can call this address: only the callback of this sign-in
            // (its state) is answered as such, others are ignored and the sign-in goes on.
            if query_param(&target, "state").as_deref() != Some(csrf.secret().as_str()) {
                let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                continue;
            }
            let body = PAGE;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = sock.write_all(resp.as_bytes()).await;
            if let Some(e) = query_param(&target, "error") {
                bail!("authorization denied: {e} {}", query_param(&target, "error_description").unwrap_or_default());
            }
            return query_param(&target, "code").ok_or_else(|| anyhow!("no authorization code in callback"));
        }
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for the browser sign-in"))??;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(verifier)
        .request_async(&http)
        .await
        .map_err(|e| anyhow!("token exchange failed: {e}"))?;
    let refresh = token.refresh_token().ok_or_else(|| {
        anyhow!("the provider did not return a refresh token (offline access not granted)")
    })?;
    Ok(refresh.secret().clone())
}

#[cfg(test)]
mod tests {
    use super::provider_url;

    #[test]
    fn provider_urls() {
        for ok in [
            "https://accounts.google.com/o/oauth2/v2/auth",
            "http://localhost:18080/default/authorize",
            "http://127.0.0.1:9/x",
            "http://[::1]/x",
        ] {
            assert!(provider_url("URL", ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://example.com/authorize",
            "file:///etc/passwd",
            "smb://evil.example/share",
            "ms-settings:privacy",
            "javascript:alert(1)",
            "not a url",
        ] {
            assert!(provider_url("URL", bad).is_err(), "{bad}");
        }
    }
}
