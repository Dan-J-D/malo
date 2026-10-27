//! Alerts: a backup tool that fails silently is worse than none. When backups of an account
//! keep failing, a check finds damaged or missing copies, an OAuth sign-in stops working, a
//! destination can't be reached, or scheduled jobs are skipped because the user is locked, Malo
//! tells them through a webhook, ntfy, an Apprise API server, or an email sent through one of
//! their accounts' SMTP servers.
//!
//! Alert settings live in the encrypted user config. While a user is locked the server can't read
//! it, so for the "skipped while locked" alert it keeps the webhook, ntfy and Apprise channels in
//! `server.db` (`alert_mirror`) when that alert is on. Email needs the account's credentials,
//! which stay sealed: it's only used while the user is logged in.
//!
//! Each problem is alerted once (bookkeeping in `alert_state`), and once more when it's over.

use std::sync::Arc;
use std::time::Duration;

use malo_api::{
    AlertChannel, AlertDelivery, AlertEvent, AlertSettings, CheckReport, JobInfo, JobKind,
    JobState, REDACTED,
};

use crate::keyring::UnlockedUser;
use crate::state::SharedState;

const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct Alert {
    pub event: AlertEvent,
    pub title: String,
    pub message: String,
}

impl Alert {
    fn new(event: AlertEvent, title: impl Into<String>, message: impl Into<String>) -> Self {
        Alert {
            event,
            title: title.into(),
            message: message.into(),
        }
    }

    fn severity(&self) -> &'static str {
        match self.event {
            AlertEvent::Recovered => "ok",
            AlertEvent::Test => "info",
            AlertEvent::SkippedLocked => "warning",
            _ => "error",
        }
    }
}

/// How a channel is named in results and the audit log (no secrets).
pub fn channel_label(c: &AlertChannel) -> String {
    let host = |u: &str| {
        url::Url::parse(u)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| "?".into())
    };
    match c {
        AlertChannel::Webhook { url } => format!("webhook to {}", host(url)),
        AlertChannel::Ntfy { server, topic, .. } => format!("ntfy {}/{topic}", host(server)),
        AlertChannel::Apprise { url } => format!("Apprise at {}", host(url)),
        AlertChannel::Email { to, .. } => format!("email to {to}"),
    }
}

fn check_http_url(what: &str, u: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(u.trim()).map_err(|_| anyhow::anyhow!("{what} isn't a valid URL"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "{what} must be an http:// or https:// address"
    );
    anyhow::ensure!(
        url.username().is_empty() || url.scheme() == "https",
        "{what}: send a user name and password over https only"
    );
    malo_core::netguard::check_url_literal(what, url.as_str())?;
    Ok(url)
}

/// Checks and tidies settings before they're saved. `prev` supplies secrets sent back as
/// [`REDACTED`].
pub fn validate(
    cfg: &malo_core::config::UserConfig,
    mut s: AlertSettings,
    prev: &AlertSettings,
) -> anyhow::Result<AlertSettings> {
    anyhow::ensure!(s.channels.len() <= 10, "at most 10 alert channels");
    s.backup_failures = s.backup_failures.min(100);
    for c in &mut s.channels {
        match c {
            AlertChannel::Webhook { url } | AlertChannel::Apprise { url } => {
                *url = check_http_url("the alert address", url)?.to_string();
            }
            AlertChannel::Ntfy {
                server,
                topic,
                token,
            } => {
                if server.trim().is_empty() {
                    *server = "https://ntfy.sh".into();
                }
                *server = check_http_url("the ntfy server", server)?
                    .as_str()
                    .trim_end_matches('/')
                    .to_string();
                *topic = topic.trim().to_string();
                anyhow::ensure!(
                    !topic.is_empty()
                        && topic.len() <= 64
                        && topic
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                    "ntfy topics are 1–64 letters, digits, - and _"
                );
                if token.as_deref() == Some(REDACTED) {
                    *token = prev.channels.iter().find_map(|p| match p {
                        AlertChannel::Ntfy {
                            server: s2,
                            topic: t2,
                            token,
                        } if s2 == server && t2 == topic => token.clone(),
                        _ => None,
                    });
                }
                if token.as_deref().is_some_and(|t| t.trim().is_empty()) {
                    *token = None;
                }
            }
            AlertChannel::Email { account_id, to } => {
                let a = cfg
                    .account(account_id)
                    .ok_or_else(|| anyhow::anyhow!("the account to send alerts with is gone"))?;
                anyhow::ensure!(
                    a.smtp.is_some(),
                    "{} has no outgoing (SMTP) server: add one under Accounts first",
                    a.name
                );
                *to = to.trim().to_string();
                anyhow::ensure!(
                    malo_core::compose::valid_address(to),
                    "“{to}” isn't an email address"
                );
            }
        }
    }
    Ok(s)
}

/// The settings as the app shows them: tokens replaced by [`REDACTED`].
pub fn view(s: &AlertSettings) -> AlertSettings {
    let mut s = s.clone();
    for c in &mut s.channels {
        if let AlertChannel::Ntfy { token: Some(t), .. } = c {
            *t = REDACTED.into();
        }
    }
    s
}

/// Keeps the channels the server may use while the user is locked: the ones that need no mail
/// credentials, and only while the "skipped while locked" alert is on.
pub fn sync_mirror(state: &SharedState, user_id: &str, s: &AlertSettings) {
    let push: Vec<&AlertChannel> = s
        .channels
        .iter()
        .filter(|c| !matches!(c, AlertChannel::Email { .. }))
        .collect();
    let json = (s.skipped_locked && !push.is_empty())
        .then(|| serde_json::to_string(&push).ok())
        .flatten();
    if let Err(e) = state.db.set_alert_mirror(user_id, json.as_deref()) {
        tracing::warn!(user = user_id, "saving the alert channels: {e:#}");
    }
}

fn http() -> anyhow::Result<reqwest::Client> {
    Ok(malo_core::netguard::http_client()
        .timeout(TIMEOUT)
        .build()?)
}

async fn post_json(url: &str, token: Option<&str>, body: serde_json::Value) -> anyhow::Result<()> {
    check_http_url("the alert address", url)?;
    let mut req = http()?.post(url).json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let text: String = text.chars().take(200).collect();
        anyhow::bail!("{status} {}", text.trim());
    }
    Ok(())
}

async fn send_email(
    state: &SharedState,
    user: &UnlockedUser,
    account_id: &str,
    to: &str,
    alert: &Alert,
) -> anyhow::Result<()> {
    use malo_core::compose::{self, Draft};
    let account = user
        .config()
        .account(account_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the account to send with is gone"))?;
    let smtp = account
        .smtp
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{} has no outgoing (SMTP) server", account.name))?;
    crate::net::check_smtp(state, &smtp)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    let from = compose::parse_mailbox(&account.username).map_err(|_| {
        anyhow::anyhow!(
            "{}'s user name isn't an email address to send from",
            account.name
        )
    })?;
    let draft = Draft {
        from: compose::Mailbox {
            name: Some("Malo".into()),
            address: from.address,
        },
        to: vec![compose::parse_mailbox(to)?],
        cc: vec![],
        bcc: vec![],
        subject: format!("Malo: {}", alert.title),
        body: format!(
            "{}\n\n— Malo backup, for {}\n",
            alert.message, user.username
        ),
        in_reply_to: None,
        attachments: vec![],
    };
    let built = compose::build(&draft)?;
    let msg = malo_core::smtp::Message {
        from: &draft.from.address,
        to: &built.recipients,
        data: &built.data,
    };
    tokio::time::timeout(
        Duration::from_secs(120),
        malo_core::smtp::send(&account, &smtp, user.tokens.as_ref(), &msg),
    )
    .await
    .map_err(|_| anyhow::anyhow!("the SMTP server took too long"))?
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Sends one alert to every channel; email only with `user` (logged in).
pub async fn deliver(
    state: &SharedState,
    username: &str,
    user: Option<&UnlockedUser>,
    channels: &[AlertChannel],
    alert: &Alert,
) -> Vec<AlertDelivery> {
    let mut out = Vec::new();
    for c in channels {
        let res: anyhow::Result<()> = match c {
            AlertChannel::Webhook { url } => {
                post_json(
                    url,
                    None,
                    serde_json::json!({
                        "source": "malo",
                        "event": alert.event,
                        "severity": alert.severity(),
                        "title": alert.title,
                        "message": alert.message,
                        "user": username,
                        "at": chrono::Utc::now(),
                    }),
                )
                .await
            }
            AlertChannel::Ntfy {
                server,
                topic,
                token,
            } => {
                let (priority, tags) = match alert.severity() {
                    "error" => (4, vec!["rotating_light"]),
                    "warning" => (4, vec!["warning"]),
                    "ok" => (3, vec!["white_check_mark"]),
                    _ => (3, vec!["information_source"]),
                };
                post_json(
                    server,
                    token.as_deref(),
                    serde_json::json!({
                        "topic": topic,
                        "title": alert.title,
                        "message": alert.message,
                        "priority": priority,
                        "tags": tags,
                    }),
                )
                .await
            }
            AlertChannel::Apprise { url } => {
                let kind = match alert.severity() {
                    "error" => "failure",
                    "warning" => "warning",
                    "ok" => "success",
                    _ => "info",
                };
                post_json(
                    url,
                    None,
                    serde_json::json!({"title": alert.title, "body": alert.message, "type": kind}),
                )
                .await
            }
            AlertChannel::Email { account_id, to } => match user {
                Some(u) => send_email(state, u, account_id, to, alert).await,
                None => Err(anyhow::anyhow!("not sent: email needs you to be logged in")),
            },
        };
        if let Err(e) = &res {
            tracing::warn!(user = username, channel = %channel_label(c), "alert not delivered: {e:#}");
        }
        out.push(AlertDelivery {
            channel: channel_label(c),
            ok: res.is_ok(),
            error: res.err().map(|e| format!("{e:#}")),
        });
    }
    out
}

/// Sends an alert of a logged-in user in the background and notes it in their audit log.
fn send(state: &SharedState, user: &Arc<UnlockedUser>, account: Option<&str>, alert: Alert) {
    let channels = user.config().alerts.channels.clone();
    if channels.is_empty() {
        return;
    }
    let (state, user, account) = (state.clone(), user.clone(), account.map(str::to_string));
    tokio::spawn(async move {
        let results = deliver(&state, &user.username, Some(&user), &channels, &alert).await;
        let _ = user.index.audit(
            "alert_sent",
            account.as_deref(),
            &serde_json::json!({
                "event": alert.event,
                "title": alert.title,
                "delivered": results.iter().filter(|r| r.ok).count(),
                "failed": results.iter().filter(|r| !r.ok).map(|r| format!("{}: {}", r.channel, r.error.as_deref().unwrap_or(""))).collect::<Vec<_>>(),
            }),
        );
    });
}

fn first_line(s: &str) -> String {
    let line = s.lines().next().unwrap_or("").trim();
    if line.chars().count() > 300 {
        format!("{}…", line.chars().take(300).collect::<String>())
    } else {
        line.to_string()
    }
}

/// Looks at a finished job and alerts about what went wrong (or right again).
pub fn after_job(state: &SharedState, user: &Arc<UnlockedUser>, job: &JobInfo) {
    let (state, user, job) = (state.clone(), user.clone(), job.clone());
    tokio::spawn(async move {
        if let Err(e) = after_job_inner(&state, &user, &job).await {
            tracing::warn!(user = %user.username, "alert bookkeeping: {e:#}");
        }
    });
}

async fn after_job_inner(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    job: &JobInfo,
) -> anyhow::Result<()> {
    let s = user.config().alerts.clone();
    let uid = &user.user_id;
    let db = &state.db;
    match (&job.kind, job.state) {
        (JobKind::Backup { account_id }, JobState::Failed) => {
            let name = account_name(user, account_id);
            let error = job.error.clone().unwrap_or_default();
            let n = db.alert_count(uid, &format!("backup:{account_id}"))?;
            if s.backup_failures > 0 && n == s.backup_failures as i64 {
                send(
                    state,
                    user,
                    Some(account_id),
                    Alert::new(
                        AlertEvent::BackupFailing,
                        format!("Backups of {name} are failing"),
                        format!(
                            "The last {n} backups of {name} failed. Latest error: {}",
                            first_line(&error)
                        ),
                    ),
                );
            }
            if error.contains(malo_core::oauth::REFRESH_FAILED)
                && db.alert_flag(uid, &format!("oauth:{account_id}"))?
                && s.oauth_failures
            {
                send(
                    state,
                    user,
                    Some(account_id),
                    Alert::new(
                        AlertEvent::OauthFailing,
                        format!("Malo can't sign in to {name}"),
                        format!(
                            "The mail provider refused to renew Malo's access to {name}, so it can't be backed up. Sign in again under Accounts → {name}. Error: {}",
                            first_line(&error)
                        ),
                    ),
                );
            }
            probe_destinations(state, user, &s).await?;
        }
        (JobKind::Backup { account_id }, JobState::Done) => {
            let failures = db.alert_clear(uid, &format!("backup:{account_id}"))?;
            let oauth = db.alert_clear(uid, &format!("oauth:{account_id}"))? > 0;
            let alerted = (s.backup_failures > 0 && failures >= s.backup_failures as i64)
                || (oauth && s.oauth_failures);
            if alerted && s.recoveries {
                let name = account_name(user, account_id);
                send(
                    state,
                    user,
                    Some(account_id),
                    Alert::new(
                        AlertEvent::Recovered,
                        format!("Backups of {name} work again"),
                        format!(
                            "The backup of {name} just succeeded, after {failures} that failed."
                        ),
                    ),
                );
            }
            let had_errors = job
                .result
                .as_ref()
                .and_then(|r| r.get("errors"))
                .and_then(|e| e.as_array())
                .is_some_and(|e| !e.is_empty());
            if had_errors || !db.alert_keys(uid, "dest:")?.is_empty() {
                probe_destinations(state, user, &s).await?;
            }
        }
        (JobKind::Check { .. } | JobKind::Repair { .. }, JobState::Done) => {
            if let Some(report) = job
                .result
                .clone()
                .and_then(|r| serde_json::from_value::<CheckReport>(r).ok())
            {
                after_check(state, user, &s, &report)?;
            }
        }
        (JobKind::Check { .. } | JobKind::Repair { .. }, JobState::Failed) => {
            if s.check_problems && db.alert_flag(uid, "check:failed")? {
                send(
                    state,
                    user,
                    None,
                    Alert::new(
                        AlertEvent::CheckProblems,
                        "The integrity check couldn't run",
                        format!(
                            "Malo couldn't check your backups: {}",
                            first_line(job.error.as_deref().unwrap_or(""))
                        ),
                    ),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn account_name(user: &UnlockedUser, id: &str) -> String {
    user.config()
        .account(id)
        .map(|a| a.name.clone())
        .unwrap_or_else(|| "an account".into())
}

fn destination_name(user: &UnlockedUser, id: &str) -> String {
    user.config()
        .destination(id)
        .map(|d| d.name.clone())
        .unwrap_or_else(|| "a destination".into())
}

fn after_check(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    s: &AlertSettings,
    report: &CheckReport,
) -> anyhow::Result<()> {
    let (db, uid) = (&state.db, &user.user_id);
    db.alert_clear(uid, "check:failed")?;
    for d in &report.destinations {
        // Unreachable: the same alert as after a backup.
        if let Some(e) = &d.error {
            destination_down(state, user, s, &d.destination_id, e)?;
            continue;
        }
        destination_up(state, user, s, &d.destination_id)?;
        let key = format!("check:{}", d.destination_id);
        let problems = (d.missing + d.corrupt) as i64;
        let before = db.alert_state(uid, &key)?;
        if problems == 0 {
            if db.alert_clear(uid, &key)? > 0 && s.check_problems && s.recoveries {
                send(
                    state,
                    user,
                    None,
                    Alert::new(
                        AlertEvent::Recovered,
                        format!("{} checks out again", d.name),
                        format!("The last check found every message intact on {}.", d.name),
                    ),
                );
            }
            continue;
        }
        // Alerted again only when the count changes, not at every check.
        if problems != before {
            db.with(|c| {
                c.execute(
                    "INSERT INTO alert_state(user_id,key,value) VALUES(?1,?2,?3)
                     ON CONFLICT(user_id,key) DO UPDATE SET value=?3",
                    rusqlite::params![uid, key, problems],
                )
            })?;
            if s.check_problems {
                let repaired = if report.repaired > 0 {
                    format!(" {} were repaired from other copies.", report.repaired)
                } else {
                    " Turn on automatic repair, or run Repair on the Health page.".into()
                };
                send(
                    state,
                    user,
                    None,
                    Alert::new(
                        AlertEvent::CheckProblems,
                        format!("Damaged or missing copies on {}", d.name),
                        format!(
                            "The {} check of {} found {} missing and {} damaged {}.{repaired}",
                            if report.deep { "deep" } else { "quick" },
                            d.name,
                            d.missing,
                            d.corrupt,
                            if problems == 1 { "copy" } else { "copies" },
                        ),
                    ),
                );
            }
        }
    }
    Ok(())
}

fn destination_down(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    s: &AlertSettings,
    id: &str,
    error: &str,
) -> anyhow::Result<()> {
    if state.db.alert_flag(&user.user_id, &format!("dest:{id}"))? && s.destination_unreachable {
        let name = destination_name(user, id);
        send(
            state,
            user,
            None,
            Alert::new(
                AlertEvent::DestinationUnreachable,
                format!("Can't reach {name}"),
                format!(
                    "Malo can't reach the destination {name}, so new mail isn't stored there. Error: {}",
                    first_line(error)
                ),
            ),
        );
    }
    Ok(())
}

fn destination_up(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    s: &AlertSettings,
    id: &str,
) -> anyhow::Result<()> {
    if state.db.alert_clear(&user.user_id, &format!("dest:{id}"))? > 0
        && s.destination_unreachable
        && s.recoveries
    {
        let name = destination_name(user, id);
        send(
            state,
            user,
            None,
            Alert::new(
                AlertEvent::Recovered,
                format!("{name} is reachable again"),
                format!("Malo can reach {name} again; mail waiting for it is stored at the next backup."),
            ),
        );
    }
    Ok(())
}

/// Tries every destination (listing its folder) and alerts about the ones that don't answer.
async fn probe_destinations(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    s: &AlertSettings,
) -> anyhow::Result<()> {
    let ctx = crate::routes::ctx_for(state, user);
    for d in ctx.config.destinations.clone() {
        let res = async {
            crate::net::check_destination(state, &d)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            let store = ctx.store(&d.id)?;
            tokio::time::timeout(Duration::from_secs(30), store.reachable())
                .await
                .map_err(|_| anyhow::anyhow!("no answer within 30 seconds"))?
        }
        .await;
        match res {
            Ok(()) => destination_up(state, user, s, &d.id)?,
            Err(e) => destination_down(state, user, s, &d.id, &format!("{e:#}"))?,
        }
    }
    Ok(())
}

/// A scheduled job came due while the user was locked. Alerted once per locked period, through
/// the channels kept for that ([`sync_mirror`]).
pub fn skipped_while_locked(state: &SharedState, user_id: &str) {
    let Ok(Some(json)) = state.db.alert_mirror(user_id) else {
        return;
    };
    match state.db.alert_flag(user_id, "locked") {
        Ok(true) => {}
        _ => return,
    }
    let Ok(channels) = serde_json::from_str::<Vec<AlertChannel>>(&json) else {
        return;
    };
    let username = state
        .db
        .user(user_id)
        .ok()
        .flatten()
        .map(|u| u.username)
        .unwrap_or_default();
    let state = state.clone();
    tokio::spawn(async move {
        let alert = Alert::new(
            AlertEvent::SkippedLocked,
            "Backups are paused: Malo is locked",
            format!(
                "Malo locked {username}'s keys (auto-lock, \"Lock now\" or a server restart), so scheduled backups and checks are skipped. Log in to Malo to resume them."
            ),
        );
        deliver(&state, &username, None, &channels, &alert).await;
    });
}

/// After logging in: the next locked period alerts again, and the kept channels are refreshed.
pub fn on_unlock(state: &SharedState, user: &UnlockedUser) {
    let _ = state.db.alert_clear(&user.user_id, "locked");
    sync_mirror(state, &user.user_id, &user.config().alerts);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_labels_hide_secrets() {
        let c = AlertChannel::Webhook {
            url: "https://hooks.example.com/services/T000/SECRET".into(),
        };
        assert_eq!(channel_label(&c), "webhook to hooks.example.com");
        let c = AlertChannel::Ntfy {
            server: "https://ntfy.sh".into(),
            topic: "malo".into(),
            token: Some("tk_secret".into()),
        };
        assert_eq!(channel_label(&c), "ntfy ntfy.sh/malo");
    }

    #[test]
    fn urls() {
        assert!(check_http_url("x", "https://example.com/hook").is_ok());
        assert!(check_http_url("x", "http://apprise:8000/notify/malo").is_ok());
        for bad in [
            "ftp://example.com",
            "example.com",
            "http://user:pw@example.com/",
            "",
        ] {
            assert!(check_http_url("x", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tokens_are_redacted_and_kept() {
        let cfg = malo_core::config::UserConfig::new(&malo_core::crypto::random_key());
        let prev = AlertSettings {
            channels: vec![AlertChannel::Ntfy {
                server: "https://ntfy.sh".into(),
                topic: "malo".into(),
                token: Some("tk_secret".into()),
            }],
            ..Default::default()
        };
        let shown = view(&prev);
        assert!(!serde_json::to_string(&shown).unwrap().contains("tk_secret"));
        let saved = validate(&cfg, shown, &prev).unwrap();
        assert_eq!(saved, prev);
        let bad = AlertSettings {
            channels: vec![AlertChannel::Ntfy {
                server: String::new(),
                topic: "a b".into(),
                token: None,
            }],
            ..Default::default()
        };
        assert!(validate(&cfg, bad, &prev).is_err());
    }
}
