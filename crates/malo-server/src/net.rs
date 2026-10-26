//! With the admin setting `block_private_networks`, mail servers and storage endpoints must be on
//! public addresses: users can't make the server connect to (and report on) its own network.

use malo_api::SmtpSettings;
use malo_core::config::{Account, Destination};

use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

pub use malo_core::netguard::is_private;

/// The admin setting, also passed on to every connection made (see `malo_core::netguard`).
fn blocking(state: &AppState) -> bool {
    let on = state
        .db
        .admin_settings()
        .map(|s| s.block_private_networks)
        .unwrap_or(false);
    malo_core::netguard::set_block_private(on);
    on
}

/// Applies the admin setting at startup and after it changes.
pub fn sync_setting(state: &AppState) {
    blocking(state);
}

/// Every address `host` resolves to must be public. Checked again when connecting; this check
/// gives a clear answer when the settings are saved.
async fn check_host(host: &str, port: u16) -> ApiResult<()> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ApiErr::bad_request(format!("can't resolve {host}: {e}")))?;
    for a in addrs {
        if is_private(a.ip()) {
            return Err(ApiErr::forbidden(format!(
                "{host} is on a private network address ({}); this server only allows public addresses",
                a.ip()
            )));
        }
    }
    Ok(())
}

/// The host of a URL option, checked like a server name.
async fn check_url(what: &str, value: &str) -> ApiResult<()> {
    let with_scheme = if value.contains("://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    let url = url::Url::parse(&with_scheme)
        .map_err(|_| ApiErr::bad_request(format!("{what} isn't a valid URL")))?;
    let host = url
        .host_str()
        .ok_or_else(|| ApiErr::bad_request(format!("{what} has no host")))?;
    check_host(host, url.port_or_known_default().unwrap_or(443)).await
}

pub async fn check_account(state: &AppState, a: &Account) -> ApiResult<()> {
    if !blocking(state) {
        return Ok(());
    }
    check_host(&a.host, a.port).await?;
    if let malo_api::AccountAuth::OAuth2 { token_url, .. } = &a.auth {
        check_url("the token URL", token_url).await?;
    }
    match &a.smtp {
        Some(s) => check_host(&s.host, s.port).await,
        None => Ok(()),
    }
}

/// The outgoing server of an account, checked again before each message is relayed.
pub async fn check_smtp(state: &AppState, s: &SmtpSettings) -> ApiResult<()> {
    if !blocking(state) {
        return Ok(());
    }
    check_host(&s.host, s.port).await
}

/// Endpoint-like options of a destination (`endpoint`, `*_endpoint`, URLs).
pub async fn check_destination(state: &AppState, d: &Destination) -> ApiResult<()> {
    if !blocking(state) || d.scheme.eq_ignore_ascii_case("fs") {
        return Ok(());
    }
    for (k, v) in &d.options {
        let v = v.trim();
        if !k.to_ascii_lowercase().contains("endpoint") || v.is_empty() {
            continue;
        }
        check_url(&format!("option '{k}'"), v).await?;
    }
    Ok(())
}
