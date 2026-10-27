//! SMTP client for mail sent through Malo: implicit TLS or STARTTLS (never plaintext), password
//! (PLAIN/LOGIN) or XOAUTH2 sign-in with the account's IMAP credentials, and a byte-exact relay of
//! the message the mail app submitted.

use std::time::Duration;

use anyhow::{anyhow, Context};
use base64::Engine;
use malo_api::{AccountAuth, SmtpSettings, TlsMode};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::Account;
use crate::oauth::{xoauth2_string, TokenSource};
use crate::tls;

const TIMEOUT: Duration = Duration::from_secs(60);
/// The server may take a while to accept a large message after the final dot.
const DATA_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Longest reply line accepted (RFC 5321 allows 512 bytes).
const MAX_LINE: usize = 8 * 1024;

/// A reply of the upstream server.
#[derive(Debug, Clone)]
pub struct Reply {
    pub code: u16,
    pub text: String,
}

impl Reply {
    fn positive(&self) -> bool {
        (200..400).contains(&self.code)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// The upstream server refused (a 4xx or 5xx reply): relayed to the mail app as is.
    #[error("{} {}", .0.code, .0.text)]
    Rejected(Reply),
    /// Connection, TLS or protocol trouble: a temporary failure for the mail app.
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
}

pub struct Message<'a> {
    pub from: &'a str,
    pub to: &'a [String],
    /// The message with CRLF line endings, not dot-stuffed.
    pub data: &'a [u8],
}

struct Conn<S> {
    io: BufReader<S>,
    ehlo: Vec<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    async fn reply(&mut self, timeout: Duration) -> anyhow::Result<Reply> {
        let mut text = Vec::new();
        loop {
            let line =
                tokio::time::timeout(timeout, crate::lines::read_line(&mut self.io, MAX_LINE))
                    .await
                    .map_err(|_| anyhow!("the SMTP server stopped responding"))??
                    .ok_or_else(|| anyhow!("the SMTP server closed the connection"))?;
            // The code is read from the bytes: a reply with a multi-byte character among the first
            // ones would put a string slice off a character boundary.
            let code: u16 = line
                .get(..3)
                .filter(|c| c.iter().all(u8::is_ascii_digit))
                .and_then(|c| std::str::from_utf8(c).ok()?.parse().ok())
                .ok_or_else(|| {
                    anyhow!(
                        "malformed SMTP reply: {}",
                        String::from_utf8_lossy(&line).trim()
                    )
                })?;
            let more = line.get(3) == Some(&b'-');
            text.push(
                String::from_utf8_lossy(line.get(4..).unwrap_or_default())
                    .trim_end()
                    .to_string(),
            );
            if !more {
                return Ok(Reply {
                    code,
                    text: text.join(" "),
                });
            }
            anyhow::ensure!(text.len() < 1000, "SMTP reply too long");
        }
    }

    async fn send_line(&mut self, line: &str) -> anyhow::Result<()> {
        let w = self.io.get_mut();
        w.write_all(line.as_bytes()).await?;
        w.write_all(b"\r\n").await?;
        w.flush().await?;
        Ok(())
    }

    async fn cmd(&mut self, line: &str) -> anyhow::Result<Reply> {
        self.send_line(line).await?;
        self.reply(TIMEOUT).await
    }

    /// Sends a command whose reply must be positive.
    async fn expect(&mut self, line: &str) -> Result<Reply, SendError> {
        let r = self.cmd(line).await?;
        if r.positive() {
            Ok(r)
        } else {
            Err(SendError::Rejected(r))
        }
    }

    async fn hello(&mut self) -> Result<(), SendError> {
        let r = self.expect("EHLO malo").await?;
        // Every word of the reply: enough for the few keywords and AUTH mechanisms we look for.
        self.ehlo = r.text.split(' ').map(|s| s.to_ascii_uppercase()).collect();
        Ok(())
    }

    fn has(&self, kw: &str) -> bool {
        self.ehlo.iter().any(|w| w == kw)
    }

    async fn login(
        &mut self,
        account: &Account,
        tokens: &dyn TokenSource,
    ) -> Result<(), SendError> {
        let b64 = |s: &[u8]| base64::engine::general_purpose::STANDARD.encode(s);
        match &account.auth {
            AccountAuth::Password { password } => {
                if self.has("PLAIN") || !self.has("LOGIN") {
                    let ir = b64(format!("\0{}\0{}", account.username, password).as_bytes());
                    self.expect(&format!("AUTH PLAIN {ir}")).await?;
                } else {
                    let r = self.cmd("AUTH LOGIN").await?;
                    if r.code != 334 {
                        return Err(SendError::Rejected(r));
                    }
                    let r = self.cmd(&b64(account.username.as_bytes())).await?;
                    if r.code != 334 {
                        return Err(SendError::Rejected(r));
                    }
                    self.expect(&b64(password.as_bytes())).await?;
                }
            }
            AccountAuth::OAuth2 { .. } => {
                let token = tokens.access_token(account).await?;
                let ir = b64(xoauth2_string(&account.username, &token).as_bytes());
                let mut r = self.cmd(&format!("AUTH XOAUTH2 {ir}")).await?;
                if r.code == 334 {
                    // An error challenge (JSON); an empty response completes the exchange.
                    r = self.cmd("").await?;
                }
                if !r.positive() {
                    tokens.invalidate(&account.id);
                    return Err(SendError::Rejected(r));
                }
            }
        }
        Ok(())
    }

    /// Sends `msg`, whose data is `stuffed` (see [`dot_stuff`]).
    async fn transfer(&mut self, msg: &Message<'_>, stuffed: &[u8]) -> Result<(), SendError> {
        let mut mail = format!("MAIL FROM:<{}>", msg.from);
        if self.has("SIZE") {
            mail.push_str(&format!(" SIZE={}", msg.data.len()));
        }
        if self.has("8BITMIME") && msg.data.iter().any(|b| *b >= 0x80) {
            mail.push_str(" BODY=8BITMIME");
        }
        self.expect(&mail).await?;
        for rcpt in msg.to {
            if let Err(e) = self.expect(&format!("RCPT TO:<{rcpt}>")).await {
                // All or nothing: the mail app is told the message went to nobody.
                let _ = self.cmd("RSET").await;
                return Err(match e {
                    SendError::Rejected(r) => SendError::Rejected(Reply {
                        code: r.code,
                        text: format!("<{rcpt}>: {}", r.text),
                    }),
                    other => other,
                });
            }
        }
        let r = self.cmd("DATA").await?;
        if r.code != 354 {
            return Err(SendError::Rejected(r));
        }
        let w = self.io.get_mut();
        w.write_all(stuffed).await.map_err(anyhow::Error::from)?;
        w.flush().await.map_err(anyhow::Error::from)?;
        let r = self.reply(DATA_TIMEOUT).await?;
        if !r.positive() {
            return Err(SendError::Rejected(r));
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), self.cmd("QUIT")).await;
        Ok(())
    }
}

/// Dot-stuffs the message for DATA and adds the final dot. Lines must end in CRLF: a bare CR or
/// LF is refused rather than turned into a line break, which would let text that was one header
/// line (a Message-ID copied from received mail, say) become two.
pub fn dot_stuff(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 50 + 5);
    let mut line_start = true;
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\r' if data.get(i + 1) == Some(&b'\n') => {
                out.extend_from_slice(b"\r\n");
                line_start = true;
                i += 1;
            }
            b'\r' | b'\n' => anyhow::bail!("the message has a line break that isn't CRLF"),
            b => {
                if line_start && b == b'.' {
                    out.push(b'.');
                }
                out.push(b);
                line_start = false;
            }
        }
        i += 1;
    }
    if !line_start {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    Ok(out)
}

async fn tls_wrap(
    account: &Account,
    host: &str,
    tcp: TcpStream,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = if account.accept_invalid_certs {
        tls::insecure_config()
    } else {
        tls::webpki_config()
    };
    let name = ServerName::try_from(host.to_string()).context("invalid SMTP host name")?;
    tokio::time::timeout(TIMEOUT, TlsConnector::from(config).connect(name, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake with the SMTP server timed out"))?
        .context("TLS handshake with the SMTP server failed")
}

/// Sends one message through the account's SMTP server.
pub async fn send(
    account: &Account,
    smtp: &SmtpSettings,
    tokens: &dyn TokenSource,
    msg: &Message<'_>,
) -> Result<(), SendError> {
    let stuffed = dot_stuff(msg.data)?;
    let tcp = tokio::time::timeout(TIMEOUT, crate::netguard::connect_tcp(&smtp.host, smtp.port))
        .await
        .map_err(|_| anyhow!("connection to {}:{} timed out", smtp.host, smtp.port))?
        .with_context(|| format!("cannot connect to {}:{}", smtp.host, smtp.port))?;
    tcp.set_nodelay(true).ok();
    let stream = match smtp.tls {
        TlsMode::Implicit => tls_wrap(account, &smtp.host, tcp).await?,
        TlsMode::Starttls => {
            let mut plain = Conn {
                io: BufReader::new(tcp),
                ehlo: vec![],
            };
            let greeting = plain.reply(TIMEOUT).await?;
            if greeting.code != 220 {
                return Err(SendError::Rejected(greeting));
            }
            plain.hello().await?;
            if !plain.has("STARTTLS") {
                return Err(anyhow!(
                    "the SMTP server doesn't offer STARTTLS; plaintext connections are not allowed"
                )
                .into());
            }
            plain.expect("STARTTLS").await?;
            if !plain.io.buffer().is_empty() {
                return Err(
                    anyhow!("unexpected data after STARTTLS (possible injection attack)").into(),
                );
            }
            tls_wrap(account, &smtp.host, plain.io.into_inner()).await?
        }
    };
    let mut conn = Conn {
        io: BufReader::new(stream),
        ehlo: vec![],
    };
    if smtp.tls == TlsMode::Implicit {
        let greeting = conn.reply(TIMEOUT).await?;
        if greeting.code != 220 {
            return Err(SendError::Rejected(greeting));
        }
    }
    conn.hello().await?;
    conn.login(account, tokens).await?;
    conn.transfer(msg, &stuffed).await
}

#[cfg(test)]
mod tests {
    use super::{dot_stuff, Conn};
    use std::time::Duration;

    async fn reply_to(server: &'static [u8]) -> anyhow::Result<u16> {
        let (mut ours, theirs) = tokio::io::duplex(4096);
        tokio::io::AsyncWriteExt::write_all(&mut ours, server).await?;
        drop(ours);
        let mut c = Conn {
            io: tokio::io::BufReader::new(theirs),
            ehlo: vec![],
        };
        Ok(c.reply(Duration::from_secs(5)).await?.code)
    }

    /// A server (or anyone before STARTTLS) sending bytes that aren't a reply code gets an error,
    /// not a panic.
    #[tokio::test]
    async fn malformed_replies_are_errors() {
        assert_eq!(reply_to(b"250-a\r\n250 ok\r\n").await.unwrap(), 250);
        for bad in [
            &b"25\xc3\xa9 x\r\n"[..],
            b"1\xff\r\n",
            b"\xe2\x82\xac\r\n",
            b"25\r\n",
            b"+25 x\r\n",
        ] {
            assert!(reply_to(bad).await.is_err(), "{bad:?}");
        }
    }

    #[test]
    fn dot_stuffing() {
        let ok = |d: &[u8]| dot_stuff(d).unwrap();
        assert_eq!(ok(b"a\r\n.b\r\n"), b"a\r\n..b\r\n.\r\n");
        assert_eq!(ok(b".\r\nx"), b"..\r\nx\r\n.\r\n");
        assert_eq!(ok(b""), b".\r\n");
        assert_eq!(ok(b"a.b\r\n"), b"a.b\r\n.\r\n");
        for bad in [
            &b".\nx"[..],
            b"a\rb\r\n",
            b"In-Reply-To: <x\rBcc: y>\r\n",
            b"a\r",
        ] {
            assert!(dot_stuff(bad).is_err(), "{bad:?}");
        }
    }
}
