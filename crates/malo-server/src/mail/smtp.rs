//! SMTP submission service: a mail app signs in with an account's mail login, and every message is
//! relayed byte for byte through that account's own SMTP server, signed in with the account's
//! credentials. Malo never delivers mail itself.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use malo_api::{JobKind, JobTrigger};
use malo_core::smtp::{self as client, SendError};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use super::{authenticate, read_line, LoginError, MailUser};
use crate::state::SharedState;

pub const MAX_MESSAGE: usize = 50 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 200;
const IDLE: Duration = Duration::from_secs(5 * 60);

struct Session<S> {
    io: BufReader<S>,
    /// Whether to send the greeting (not after STARTTLS).
    greet: bool,
    state: SharedState,
    ip: IpAddr,
    user: Option<MailUser>,
    from: Option<String>,
    to: Vec<String>,
    failed_auth: u32,
}

/// Strips CR/LF so an upstream error text can't inject reply lines.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .chars()
        .take(400)
        .collect()
}

/// The address of `MAIL FROM:<a>` / `RCPT TO:<a>` (parameters after it are ignored).
fn path_arg(arg: &str, prefix: &str) -> Option<String> {
    let rest = arg.get(..prefix.len())?;
    if !rest.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = arg[prefix.len()..].trim_start();
    let inner = rest.strip_prefix('<')?;
    let end = inner.find('>')?;
    let addr = inner[..end].trim();
    let ok = addr.len() <= 320
        && addr
            .chars()
            .all(|c| !c.is_control() && c != ' ' && c != '<');
    ok.then(|| addr.to_string())
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    async fn reply(&mut self, text: &str) -> std::io::Result<()> {
        let w = self.io.get_mut();
        w.write_all(text.as_bytes()).await?;
        w.write_all(b"\r\n").await?;
        w.flush().await
    }

    async fn line(&mut self) -> anyhow::Result<Option<String>> {
        let line = match tokio::time::timeout(IDLE, read_line(&mut self.io, 4096)).await {
            Ok(r) => r?,
            Err(_) => {
                let _ = self.reply("421 4.4.2 Idle too long, closing").await;
                return Ok(None);
            }
        };
        Ok(line.map(|l| {
            String::from_utf8_lossy(&l)
                .trim_end_matches(['\r', '\n'])
                .to_string()
        }))
    }

    async fn auth(&mut self, args: &str) -> anyhow::Result<()> {
        if self.user.is_some() {
            return Ok(self.reply("503 5.5.1 Already authenticated").await?);
        }
        let mut words = args.split_whitespace();
        let mech = words.next().unwrap_or("").to_ascii_uppercase();
        let initial = words.next().map(str::to_string);
        let b64 = base64::engine::general_purpose::STANDARD;
        let decode = |s: &str| {
            b64.decode(s.trim())
                .ok()
                .map(|v| String::from_utf8_lossy(&v).to_string())
        };
        let (username, password) = match mech.as_str() {
            "PLAIN" => {
                let resp = match initial {
                    Some(r) if r != "=" => r,
                    _ => {
                        self.reply("334 ").await?;
                        self.line().await?.unwrap_or_default()
                    }
                };
                if resp == "*" {
                    return Ok(self.reply("501 5.7.0 Authentication cancelled").await?);
                }
                let Some(s) = decode(&resp) else {
                    return Ok(self.reply("501 5.5.2 Invalid base64").await?);
                };
                let mut parts = s.splitn(3, '\0');
                let (_authz, user, pass) = (parts.next(), parts.next(), parts.next());
                match (user, pass) {
                    (Some(u), Some(p)) => (u.to_string(), p.to_string()),
                    _ => return Ok(self.reply("501 5.5.2 Malformed PLAIN response").await?),
                }
            }
            "LOGIN" => {
                let user = match initial {
                    Some(r) => r,
                    None => {
                        self.reply("334 VXNlcm5hbWU6").await?;
                        self.line().await?.unwrap_or_default()
                    }
                };
                self.reply("334 UGFzc3dvcmQ6").await?;
                let pass = self.line().await?.unwrap_or_default();
                match (decode(&user), decode(&pass)) {
                    (Some(u), Some(p)) => (u, p),
                    _ => return Ok(self.reply("501 5.5.2 Invalid base64").await?),
                }
            }
            _ => {
                return Ok(self
                    .reply("504 5.5.4 Unrecognized authentication type")
                    .await?)
            }
        };
        match authenticate(&self.state, &username, &password, self.ip).await {
            Ok(u) => {
                self.user = Some(u);
                self.reply("235 2.7.0 Authentication successful").await?;
            }
            Err(LoginError::Locked) => {
                self.reply(&format!("454 4.7.0 {}", super::Gone::Locked.message()))
                    .await?
            }
            Err(LoginError::Throttled(m)) => {
                self.reply(&format!("454 4.7.0 {}", one_line(&m))).await?
            }
            Err(LoginError::Invalid) => {
                self.failed_auth += 1;
                self.reply("535 5.7.8 Authentication credentials invalid")
                    .await?;
                if self.failed_auth >= 3 {
                    anyhow::bail!("too many failed logins");
                }
            }
        }
        Ok(())
    }

    /// Reads the message after DATA (dot-unstuffed). None if it was too large.
    async fn data(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let mut msg = Vec::new();
        let mut too_large = false;
        loop {
            let line = tokio::time::timeout(IDLE, read_line(&mut self.io, 1 << 20))
                .await
                .map_err(|_| anyhow::anyhow!("timeout in DATA"))??
                .ok_or_else(|| anyhow::anyhow!("connection closed in DATA"))?;
            let bare = line.strip_suffix(b"\n").unwrap_or(&line);
            let bare = bare.strip_suffix(b"\r").unwrap_or(bare);
            if bare == b"." {
                break;
            }
            let content = bare.strip_prefix(b".").unwrap_or(bare);
            if msg.len() + content.len() + 2 > MAX_MESSAGE {
                too_large = true;
            }
            if !too_large {
                msg.extend_from_slice(content);
                msg.extend_from_slice(b"\r\n");
            }
        }
        Ok((!too_large).then_some(msg))
    }

    async fn relay(&mut self, data: Vec<u8>) -> anyhow::Result<String> {
        let mail_user = self.user.clone().expect("authenticated");
        let user = match mail_user.unlocked(&self.state) {
            Ok(u) => u,
            Err(g) => return Ok(format!("451 4.7.0 {}", g.message())),
        };
        let Some(account) = user.config().account(&mail_user.account_id).cloned() else {
            return Ok("554 5.7.0 The account no longer exists".into());
        };
        let tokens = user.tokens.clone();
        drop(user);
        let Some(smtp) = account.smtp.clone() else {
            return Ok(format!(
                "554 5.3.5 Sending isn't set up for {}: add its outgoing (SMTP) server in Malo under Accounts",
                account.name
            ));
        };
        if let Err(e) = crate::net::check_smtp(&self.state, &smtp).await {
            return Ok(format!("554 5.7.0 {}", one_line(&e.message)));
        }
        let from = self.from.clone().unwrap_or_default();
        let msg = client::Message {
            from: &from,
            to: &self.to,
            data: &data,
        };
        Ok(
            match client::send(&account, &smtp, tokens.as_ref(), &msg).await {
                Ok(()) => {
                    tracing::info!(account = %account.id, recipients = self.to.len(), "relayed a message");
                    // Back up the account soon, so the sent copy (if its server keeps one) shows up.
                    let _ = crate::jobs::submit(
                        &self.state,
                        &mail_user.user_id,
                        JobKind::Backup {
                            account_id: account.id.clone(),
                        },
                        JobTrigger::Scheduled,
                    );
                    format!("250 2.0.0 Sent through {}", smtp.host)
                }
                Err(SendError::Rejected(r)) => {
                    let code = if (400..500).contains(&r.code) {
                        451
                    } else {
                        554
                    };
                    format!(
                        "{code} {} said: {} {}",
                        smtp.host,
                        r.code,
                        one_line(&r.text)
                    )
                }
                Err(SendError::Failed(e)) => {
                    format!(
                        "451 4.4.0 Couldn't send through {}: {}",
                        smtp.host,
                        one_line(&format!("{e:#}"))
                    )
                }
            },
        )
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        // Not again after STARTTLS: the client goes on with its next command.
        if self.greet {
            self.reply("220 malo ESMTP Malo mail submission").await?;
        }
        while let Some(line) = self.line().await? {
            let (verb, args) = match line.split_once(' ') {
                Some((v, a)) => (v.to_ascii_uppercase(), a.trim().to_string()),
                None => (line.to_ascii_uppercase(), String::new()),
            };
            match verb.as_str() {
                "EHLO" => {
                    self.from = None;
                    self.to.clear();
                    self.reply(&format!(
                        "250-malo\r\n250-SIZE {MAX_MESSAGE}\r\n250-8BITMIME\r\n250 AUTH PLAIN LOGIN"
                    ))
                    .await?
                }
                "HELO" => self.reply("250 malo").await?,
                "AUTH" => self.auth(&args).await?,
                "MAIL" => {
                    if self.user.is_none() {
                        self.reply("530 5.7.0 Authentication required").await?;
                    } else if self.from.is_some() {
                        self.reply("503 5.5.1 Sender already given").await?;
                    } else if let Some(addr) = path_arg(&args, "FROM:") {
                        let size = args
                            .split_whitespace()
                            .find_map(|p| {
                                p.to_ascii_uppercase()
                                    .strip_prefix("SIZE=")
                                    .map(str::to_string)
                            })
                            .and_then(|s| s.parse::<usize>().ok());
                        if size.is_some_and(|s| s > MAX_MESSAGE) {
                            self.reply("552 5.3.4 Message too large").await?;
                        } else {
                            self.from = Some(addr);
                            self.reply("250 2.1.0 OK").await?;
                        }
                    } else {
                        self.reply("501 5.5.4 Syntax: MAIL FROM:<address>").await?;
                    }
                }
                "RCPT" => {
                    if self.from.is_none() {
                        self.reply("503 5.5.1 Need MAIL first").await?;
                    } else if self.to.len() >= MAX_RECIPIENTS {
                        self.reply("452 4.5.3 Too many recipients").await?;
                    } else {
                        match path_arg(&args, "TO:").filter(|a| !a.is_empty()) {
                            Some(a) => {
                                self.to.push(a);
                                self.reply("250 2.1.5 OK").await?;
                            }
                            None => self.reply("501 5.5.4 Syntax: RCPT TO:<address>").await?,
                        }
                    }
                }
                "DATA" => {
                    if self.to.is_empty() {
                        self.reply("503 5.5.1 Need RCPT first").await?;
                        continue;
                    }
                    self.reply("354 End data with <CR><LF>.<CR><LF>").await?;
                    let reply = match self.data().await? {
                        Some(data) => self.relay(data).await?,
                        None => "552 5.3.4 Message too large".to_string(),
                    };
                    self.from = None;
                    self.to.clear();
                    self.reply(&reply).await?;
                }
                "RSET" => {
                    self.from = None;
                    self.to.clear();
                    self.reply("250 2.0.0 OK").await?;
                }
                "NOOP" => self.reply("250 2.0.0 OK").await?,
                "VRFY" => self.reply("252 2.5.0 Cannot verify").await?,
                "QUIT" => {
                    self.reply("221 2.0.0 Bye").await?;
                    return Ok(());
                }
                "STARTTLS" => self.reply("503 5.5.1 Already using TLS").await?,
                _ => self.reply("502 5.5.2 Command not recognized").await?,
            }
        }
        Ok(())
    }
}

pub async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    state: SharedState,
    stream: S,
    ip: IpAddr,
    greet: bool,
) -> anyhow::Result<()> {
    Session {
        io: BufReader::new(stream),
        state,
        ip,
        greet,
        user: None,
        from: None,
        to: vec![],
        failed_auth: 0,
    }
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(
            path_arg("FROM:<a@b.c> SIZE=10", "FROM:").as_deref(),
            Some("a@b.c")
        );
        assert_eq!(path_arg("from: <a@b.c>", "FROM:").as_deref(), Some("a@b.c"));
        assert_eq!(path_arg("FROM:<>", "FROM:").as_deref(), Some(""));
        assert_eq!(path_arg("TO:a@b.c", "TO:"), None);
        assert_eq!(path_arg("TO:<a b@c>", "TO:"), None);
        assert_eq!(one_line("a\r\n250 x"), "a  250 x");
    }
}
