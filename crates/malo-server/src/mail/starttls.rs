//! Both ports use implicit TLS, but mail apps set to STARTTLS (or "SSL off") connect in plain
//! text and wait for a greeting, while Malo waits for their TLS hello: each would wait for the
//! other until the connection timed out. Such an app gets a plain-text greeting that offers
//! STARTTLS and nothing else, so passwords and mail still only travel encrypted.

use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::read_line;

/// How long a client gets to start TLS before it's taken for one waiting for a greeting.
const SPEAKS_FIRST: Duration = Duration::from_millis(1500);
/// Plain-text commands before STARTTLS: enough for any app, not for keeping a connection busy.
const MAX_COMMANDS: usize = 20;
const LINE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_LINE: usize = 1024;

/// How a client opened the connection.
pub enum Opening {
    /// It sent a TLS hello.
    Tls,
    /// It's waiting for a greeting (or sent plain text).
    Plain,
}

/// None when the client closed the connection without a word.
pub async fn opening(tcp: &TcpStream) -> std::io::Result<Option<Opening>> {
    let mut first = [0u8; 1];
    match tokio::time::timeout(SPEAKS_FIRST, tcp.peek(&mut first)).await {
        Ok(Ok(0)) => Ok(None),
        // 0x16: a TLS handshake record.
        Ok(Ok(_)) if first[0] == 0x16 => Ok(Some(Opening::Tls)),
        Ok(Ok(_)) | Err(_) => Ok(Some(Opening::Plain)),
        Ok(Err(e)) => Err(e),
    }
}

/// What came of the plain-text part.
pub enum Outcome {
    /// The client asked for STARTTLS and was told to begin: TLS starts now.
    StartTls,
    /// It left, or never asked.
    Closed,
    /// It tried to log in without TLS (refused).
    TriedPlainLogin,
}

/// IMAP before STARTTLS: CAPABILITY, ID, NOOP, LOGOUT and STARTTLS; logins are refused.
pub async fn imap(tcp: &mut TcpStream) -> anyhow::Result<Outcome> {
    const CAPS: &str = "IMAP4rev1 STARTTLS LOGINDISABLED";
    let mut io = BufReader::new(tcp);
    let mut tried_login = false;
    io.get_mut()
        .write_all(
            format!("* OK [CAPABILITY {CAPS}] Malo IMAP ready; start TLS to log in\r\n").as_bytes(),
        )
        .await?;
    for _ in 0..MAX_COMMANDS {
        let Some(line) = next_line(&mut io).await? else {
            break;
        };
        let line = String::from_utf8_lossy(&line);
        let mut words = line.split_whitespace();
        let (Some(tag), cmd) = (
            words.next(),
            words.next().unwrap_or("").to_ascii_uppercase(),
        ) else {
            continue;
        };
        let reply = match cmd.as_str() {
            "CAPABILITY" => format!("* CAPABILITY {CAPS}\r\n{tag} OK CAPABILITY completed\r\n"),
            "ID" => format!("* ID (\"name\" \"Malo\")\r\n{tag} OK ID completed\r\n"),
            "NOOP" => format!("{tag} OK NOOP completed\r\n"),
            "LOGOUT" => {
                io.get_mut()
                    .write_all(
                        format!("* BYE Logging out\r\n{tag} OK LOGOUT completed\r\n").as_bytes(),
                    )
                    .await?;
                break;
            }
            "STARTTLS" => {
                io.get_mut()
                    .write_all(format!("{tag} OK Begin TLS negotiation now\r\n").as_bytes())
                    .await?;
                // The client waits for this reply before its TLS hello, so nothing may be buffered.
                if !io.buffer().is_empty() {
                    anyhow::bail!("data sent before the TLS handshake");
                }
                return Ok(Outcome::StartTls);
            }
            "LOGIN" | "AUTHENTICATE" => {
                tried_login = true;
                format!(
                    "{tag} NO [PRIVACYREQUIRED] Logging in needs TLS: turn on SSL/TLS (or STARTTLS) for this account\r\n"
                )
            }
            _ => format!("{tag} BAD Start TLS first (STARTTLS)\r\n"),
        };
        io.get_mut().write_all(reply.as_bytes()).await?;
    }
    Ok(if tried_login {
        Outcome::TriedPlainLogin
    } else {
        Outcome::Closed
    })
}

/// SMTP before STARTTLS: EHLO (offering STARTTLS), HELO, NOOP, RSET, QUIT and STARTTLS.
pub async fn smtp(tcp: &mut TcpStream) -> anyhow::Result<Outcome> {
    let mut io = BufReader::new(tcp);
    let mut tried_login = false;
    io.get_mut()
        .write_all(b"220 malo ESMTP Malo mail submission\r\n")
        .await?;
    for _ in 0..MAX_COMMANDS {
        let Some(line) = next_line(&mut io).await? else {
            break;
        };
        let line = String::from_utf8_lossy(&line);
        let verb = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let reply: &[u8] = match verb.as_str() {
            "EHLO" => b"250-malo\r\n250 STARTTLS\r\n",
            "HELO" => b"250 malo\r\n",
            "NOOP" | "RSET" => b"250 2.0.0 OK\r\n",
            "QUIT" => {
                io.get_mut().write_all(b"221 2.0.0 Bye\r\n").await?;
                break;
            }
            "STARTTLS" => {
                io.get_mut()
                    .write_all(b"220 2.0.0 Ready to start TLS\r\n")
                    .await?;
                if !io.buffer().is_empty() {
                    anyhow::bail!("data sent before the TLS handshake");
                }
                return Ok(Outcome::StartTls);
            }
            "AUTH" => {
                tried_login = true;
                b"530 5.7.0 Logging in needs TLS: turn on SSL/TLS (or STARTTLS) for this account\r\n"
            }
            _ => b"530 5.7.0 Must issue a STARTTLS command first\r\n",
        };
        io.get_mut().write_all(reply).await?;
    }
    Ok(if tried_login {
        Outcome::TriedPlainLogin
    } else {
        Outcome::Closed
    })
}

async fn next_line(io: &mut BufReader<&mut TcpStream>) -> anyhow::Result<Option<Vec<u8>>> {
    match tokio::time::timeout(LINE_TIMEOUT, read_line(io, MAX_LINE)).await {
        Ok(l) => Ok(l?),
        Err(_) => Ok(None),
    }
}
