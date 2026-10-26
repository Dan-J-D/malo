//! IMAP client: TLS/STARTTLS connect, password and XOAUTH2 login, listing, discovery and download.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use async_imap::types::{Fetch, Flag, NameAttribute};
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use imap_proto::types::BodyStructure;
use malo_api::{AccountAuth, Envelope, TlsMode};
use once_cell::sync::Lazy;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;

use crate::config::Account;
use crate::oauth::{xoauth2_string, TokenSource};
use crate::tls;

pub type Stream = tokio_rustls::client::TlsStream<TcpStream>;
pub type Session = async_imap::Session<Stream>;

/// Gmail's inbox categories besides Primary, as `category:` search terms.
pub const GMAIL_CATEGORIES: [&str; 4] = ["social", "promotions", "updates", "forums"];

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Simultaneous connections per IMAP host across all users (Gmail allows ~15 per account).
const PER_HOST_CONNECTIONS: usize = 8;

static HOST_LIMITS: Lazy<Mutex<HashMap<String, Arc<Semaphore>>>> = Lazy::new(Default::default);

async fn host_permit(host: &str) -> OwnedSemaphorePermit {
    let sem = HOST_LIMITS
        .lock()
        .unwrap()
        .entry(host.to_ascii_lowercase())
        .or_insert_with(|| Arc::new(Semaphore::new(PER_HOST_CONNECTIONS)))
        .clone();
    sem.acquire_owned().await.expect("semaphore never closed")
}

#[derive(Debug, Clone, Default)]
pub struct Caps(HashSet<String>);

impl Caps {
    pub fn has(&self, c: &str) -> bool {
        self.0.contains(&c.to_ascii_uppercase())
    }
    pub fn uidplus(&self) -> bool {
        self.has("UIDPLUS")
    }
    pub fn gmail(&self) -> bool {
        self.has("X-GM-EXT-1")
    }
    pub fn condstore(&self) -> bool {
        self.has("CONDSTORE") || self.has("QRESYNC")
    }
    pub fn idle(&self) -> bool {
        self.has("IDLE")
    }
    pub fn mv(&self) -> bool {
        self.has("MOVE")
    }
    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = self.0.iter().cloned().collect();
        v.sort();
        v
    }
}

pub struct ImapConn {
    pub session: Session,
    pub caps: Caps,
    _permit: Option<OwnedSemaphorePermit>,
}

struct XOAuth2(Option<String>);

impl async_imap::Authenticator for XOAuth2 {
    type Response = String;
    fn process(&mut self, _challenge: &[u8]) -> String {
        // First continuation: send the token. On failure the server sends an error JSON; reply empty.
        self.0.take().unwrap_or_default()
    }
}

/// Longest line accepted from a server before TLS.
const MAX_PLAIN_LINE: usize = 8 * 1024;

async fn read_line(r: &mut BufReader<TcpStream>) -> anyhow::Result<String> {
    let line = tokio::time::timeout(CONNECT_TIMEOUT, crate::lines::read_line(r, MAX_PLAIN_LINE))
        .await??
        .ok_or_else(|| anyhow!("connection closed by server"))?;
    Ok(String::from_utf8_lossy(&line).into_owned())
}

async fn starttls(tcp: TcpStream) -> anyhow::Result<TcpStream> {
    let mut r = BufReader::new(tcp);
    let greeting = read_line(&mut r).await?;
    if !greeting.starts_with("* OK") {
        bail!("unexpected greeting: {}", greeting.trim());
    }
    r.get_mut().write_all(b"m0 STARTTLS\r\n").await?;
    loop {
        let line = read_line(&mut r).await?;
        if line.starts_with("m0 ") {
            if line.starts_with("m0 OK") {
                break;
            }
            bail!(
                "STARTTLS refused ({}); plaintext connections are not allowed",
                line.trim()
            );
        }
    }
    if !r.buffer().is_empty() {
        bail!("unexpected data after STARTTLS (possible injection attack)");
    }
    Ok(r.into_inner())
}

/// Free connection slots for a host (diagnostics); None if Malo never connected to it.
pub fn host_slots_free(host: &str) -> Option<usize> {
    HOST_LIMITS
        .lock()
        .unwrap()
        .get(&host.to_ascii_lowercase())
        .map(|s| s.available_permits())
}

/// Connects, upgrades to TLS and authenticates. Plaintext is never allowed.
pub async fn connect(account: &Account, tokens: &dyn TokenSource) -> anyhow::Result<ImapConn> {
    let permit = host_permit(&account.host).await;
    open(account, tokens, Some(permit)).await
}

/// A connection that doesn't count against the host's limit, for IDLE watchers: one long-lived
/// connection per account that does no backup work. Otherwise enough watched accounts on one
/// host (e.g. several Gmail accounts) would hold every slot and starve all backups and checks.
pub async fn connect_unmetered(
    account: &Account,
    tokens: &dyn TokenSource,
) -> anyhow::Result<ImapConn> {
    open(account, tokens, None).await
}

async fn open(
    account: &Account,
    tokens: &dyn TokenSource,
    permit: Option<OwnedSemaphorePermit>,
) -> anyhow::Result<ImapConn> {
    let tcp = tokio::time::timeout(
        CONNECT_TIMEOUT,
        crate::netguard::connect_tcp(&account.host, account.port),
    )
    .await
    .map_err(|_| anyhow!("connection to {}:{} timed out", account.host, account.port))?
    .with_context(|| format!("cannot connect to {}:{}", account.host, account.port))?;
    tcp.set_nodelay(true).ok();
    let tcp = match account.tls {
        TlsMode::Implicit => tcp,
        TlsMode::Starttls => starttls(tcp).await?,
    };
    let config = if account.accept_invalid_certs {
        tls::insecure_config()
    } else {
        tls::webpki_config()
    };
    let name = ServerName::try_from(account.host.clone()).context("invalid host name")?;
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(config).connect(name, tcp),
    )
    .await
    .map_err(|_| anyhow!("TLS handshake timed out"))?
    .context("TLS handshake failed")?;
    let mut client = async_imap::Client::new(stream);
    if account.tls == TlsMode::Implicit {
        let greeting = client
            .read_response()
            .await?
            .ok_or_else(|| anyhow!("no greeting from server"))?;
        if let imap_proto::Response::Data {
            status: imap_proto::Status::Bye,
            ..
        } = greeting.parsed()
        {
            bail!("server said BYE");
        }
    }
    let mut session = match &account.auth {
        AccountAuth::Password { password } => client
            .login(&account.username, password)
            .await
            .map_err(|(e, _)| anyhow!("login failed: {e}"))?,
        AccountAuth::OAuth2 { .. } => {
            let token = tokens.access_token(account).await?;
            match client
                .authenticate(
                    "XOAUTH2",
                    XOAuth2(Some(xoauth2_string(&account.username, &token))),
                )
                .await
            {
                Ok(s) => s,
                Err((e, _)) => {
                    tokens.invalidate(&account.id);
                    bail!("XOAUTH2 authentication failed: {e}");
                }
            }
        }
    };
    let caps = session.capabilities().await?;
    let set = caps
        .iter()
        .map(|c| match c {
            async_imap::types::Capability::Imap4rev1 => "IMAP4REV1".to_string(),
            async_imap::types::Capability::Auth(a) => format!("AUTH={}", a.to_ascii_uppercase()),
            async_imap::types::Capability::Atom(a) => a.to_ascii_uppercase(),
        })
        .collect();
    Ok(ImapConn {
        session,
        caps: Caps(set),
        _permit: permit,
    })
}

impl ImapConn {
    pub async fn logout(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.session.logout()).await;
    }

    pub async fn list_mailboxes(&mut self) -> anyhow::Result<Vec<MailboxListing>> {
        let names: Vec<_> = self
            .session
            .list(Some(""), Some("*"))
            .await?
            .try_collect()
            .await?;
        let mut out: Vec<MailboxListing> = names
            .iter()
            .map(|n| {
                let mut selectable = true;
                let mut special_use = None;
                for a in n.attributes() {
                    match a {
                        NameAttribute::NoSelect => selectable = false,
                        NameAttribute::Extension(e) if e.eq_ignore_ascii_case("\\NonExistent") => {
                            selectable = false
                        }
                        NameAttribute::All => special_use = Some("\\All".to_string()),
                        NameAttribute::Archive => special_use = Some("\\Archive".to_string()),
                        NameAttribute::Drafts => special_use = Some("\\Drafts".to_string()),
                        NameAttribute::Flagged => special_use = Some("\\Flagged".to_string()),
                        NameAttribute::Junk => special_use = Some("\\Junk".to_string()),
                        NameAttribute::Sent => special_use = Some("\\Sent".to_string()),
                        NameAttribute::Trash => special_use = Some("\\Trash".to_string()),
                        NameAttribute::Extension(e) if e.eq_ignore_ascii_case("\\Important") => {
                            special_use = Some("\\Important".to_string())
                        }
                        _ => {}
                    }
                }
                MailboxListing {
                    name: unescape_quoted(n.name()),
                    delimiter: n.delimiter().map(unescape_quoted),
                    special_use,
                    selectable,
                }
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub async fn select(&mut self, name: &str) -> anyhow::Result<SelectInfo> {
        let mb = if self.caps.condstore() {
            self.session.select_condstore(name).await?
        } else {
            self.session.select(name).await?
        };
        Ok(SelectInfo {
            uidvalidity: mb
                .uid_validity
                .ok_or_else(|| anyhow!("server did not report UIDVALIDITY for {name}"))?,
            uidnext: mb.uid_next,
            exists: mb.exists,
            highest_modseq: mb.highest_modseq,
        })
    }

    /// UIDs strictly greater than `after`.
    pub async fn uids_after(&mut self, after: u32) -> anyhow::Result<Vec<u32>> {
        let set = self
            .session
            .uid_search(format!("UID {}:*", after.saturating_add(1)))
            .await?;
        let mut v: Vec<u32> = set.into_iter().filter(|u| *u > after).collect();
        v.sort_unstable();
        Ok(v)
    }

    pub async fn all_uids(&mut self) -> anyhow::Result<Vec<u32>> {
        let mut v: Vec<u32> = self.session.uid_search("ALL").await?.into_iter().collect();
        v.sort_unstable();
        Ok(v)
    }

    /// Discovery pass: metadata only, never the body.
    pub async fn discover(&mut self, uids: &[u32]) -> anyhow::Result<Vec<Discovered>> {
        let mut out = Vec::with_capacity(uids.len());
        let gm = self.caps.gmail();
        let query = if gm {
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE X-GM-MSGID X-GM-LABELS)"
        } else {
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE)"
        };
        for chunk in uids.chunks(200) {
            let fetches: Vec<Fetch> = self
                .session
                .uid_fetch(uid_set(chunk), query)
                .await?
                .try_collect()
                .await?;
            for f in fetches.iter() {
                if let Some(d) = Discovered::from_fetch(f) {
                    out.push(d);
                }
            }
        }
        out.sort_by_key(|d| d.uid);
        Ok(out)
    }

    /// Flag (and label) changes since `modseq` (CONDSTORE).
    pub async fn changed_since(
        &mut self,
        modseq: u64,
    ) -> anyhow::Result<Vec<(u32, Vec<String>, Option<Vec<String>>)>> {
        let query = if self.caps.gmail() {
            format!("(UID FLAGS X-GM-LABELS) (CHANGEDSINCE {modseq})")
        } else {
            format!("(UID FLAGS) (CHANGEDSINCE {modseq})")
        };
        let fetches: Vec<Fetch> = self
            .session
            .uid_fetch("1:*", query)
            .await?
            .try_collect()
            .await?;
        Ok(fetches
            .iter()
            .filter_map(|f| {
                let labels = f.gmail_labels().map(|l| gmail_labels(l));
                Some((f.uid?, flags_of(f), labels))
            })
            .collect())
    }

    /// Gmail categories of the selected mailbox's messages from UID `from_uid` on (Primary
    /// messages are in none of them).
    pub async fn gmail_categories(
        &mut self,
        from_uid: u32,
    ) -> anyhow::Result<HashMap<u32, &'static str>> {
        let mut out = HashMap::new();
        for c in GMAIL_CATEGORIES {
            let uids = self
                .session
                .uid_search(format!(
                    "UID {}:* X-GM-RAW \"category:{c}\"",
                    from_uid.max(1)
                ))
                .await?;
            for u in uids.into_iter().filter(|u| *u >= from_uid) {
                out.insert(u, c);
            }
        }
        Ok(out)
    }

    /// Current flags of specific UIDs.
    pub async fn flags(
        &mut self,
        uids: &[u32],
    ) -> anyhow::Result<HashMap<u32, (Vec<String>, u32, Option<u64>)>> {
        let mut out = HashMap::new();
        let q = if self.caps.gmail() {
            "(UID FLAGS RFC822.SIZE X-GM-MSGID)"
        } else {
            "(UID FLAGS RFC822.SIZE)"
        };
        for chunk in uids.chunks(500) {
            let fetches: Vec<Fetch> = self
                .session
                .uid_fetch(uid_set(chunk), q)
                .await?
                .try_collect()
                .await?;
            for f in &fetches {
                if let Some(uid) = f.uid {
                    out.insert(
                        uid,
                        (flags_of(f), f.size.unwrap_or(0), f.gmail_msg_id().copied()),
                    );
                }
            }
        }
        Ok(out)
    }

    /// What purge compares before deleting: flags, size, received date, Message-ID, Gmail id.
    pub async fn identities(&mut self, uids: &[u32]) -> anyhow::Result<HashMap<u32, Identity>> {
        let mut out = HashMap::new();
        let q = if self.caps.gmail() {
            "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE X-GM-MSGID)"
        } else {
            "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE)"
        };
        for chunk in uids.chunks(200) {
            let fetches: Vec<Fetch> = self
                .session
                .uid_fetch(uid_set(chunk), q)
                .await?
                .try_collect()
                .await?;
            for f in &fetches {
                let Some(uid) = f.uid else { continue };
                out.insert(
                    uid,
                    Identity {
                        flags: flags_of(f),
                        size: f.size.unwrap_or(0),
                        gm_msgid: f.gmail_msg_id().copied(),
                        message_id: f
                            .envelope()
                            .and_then(|e| e.message_id.as_ref())
                            .map(|m| String::from_utf8_lossy(m).trim().to_string()),
                        internaldate: f.internal_date().map(|d| d.with_timezone(&Utc)),
                    },
                );
            }
        }
        Ok(out)
    }

    /// Download pass: `BODY.PEEK[]` never sets `\Seen`.
    pub async fn fetch_raw(&mut self, uid: u32) -> anyhow::Result<Option<(Vec<u8>, Option<u32>)>> {
        let fetches: Vec<Fetch> = self
            .session
            .uid_fetch(uid.to_string(), "(UID RFC822.SIZE BODY.PEEK[])")
            .await?
            .try_collect()
            .await?;
        Ok(fetches
            .iter()
            .find(|f| f.uid == Some(uid))
            .and_then(|f| f.body().map(|b| (b.to_vec(), f.size))))
    }

    /// `UID STORE +FLAGS.SILENT (\Deleted)` then `UID EXPUNGE <set>`. Returns the expunged UIDs.
    pub async fn delete_uids(&mut self, uids: &[u32]) -> anyhow::Result<Vec<u32>> {
        if !self.caps.uidplus() {
            bail!("server lacks UIDPLUS; refusing to expunge");
        }
        let mut expunged = Vec::new();
        for chunk in uids.chunks(200) {
            let set = uid_set(chunk);
            let _: Vec<Fetch> = self
                .session
                .uid_store(&set, "+FLAGS.SILENT (\\Deleted)")
                .await?
                .try_collect()
                .await?;
            let gone: Vec<u32> = self.session.uid_expunge(&set).await?.try_collect().await?;
            expunged.extend(gone);
        }
        Ok(expunged)
    }

    pub async fn uid_move(&mut self, uids: &[u32], target: &str) -> anyhow::Result<()> {
        for chunk in uids.chunks(200) {
            self.session.uid_mv(uid_set(chunk), target).await?;
        }
        Ok(())
    }

    pub async fn uids_by_gm_msgid(&mut self, ids: &[u64]) -> anyhow::Result<HashMap<u64, u32>> {
        let mut out = HashMap::new();
        for id in ids {
            let found = self.session.uid_search(format!("X-GM-MSGID {id}")).await?;
            if let Some(uid) = found.into_iter().max() {
                out.insert(*id, uid);
            }
        }
        Ok(out)
    }

    pub async fn noop(&mut self) -> anyhow::Result<()> {
        self.session.noop().await?;
        Ok(())
    }

    /// Waits (IMAP IDLE) until the selected mailbox changes or `timeout` elapses. Consumes the connection.
    pub async fn idle_wait(self, timeout: Duration) -> anyhow::Result<bool> {
        let ImapConn { session, .. } = self;
        let mut handle = session.idle();
        handle.init().await?;
        let (fut, _stop) = handle.wait_with_timeout(timeout);
        let changed = matches!(
            fut.await?,
            async_imap::extensions::idle::IdleResponse::NewData(_)
        );
        let mut s = handle.done().await?;
        let _ = s.logout().await;
        Ok(changed)
    }
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub flags: Vec<String>,
    pub size: u32,
    pub gm_msgid: Option<u64>,
    pub message_id: Option<String>,
    pub internaldate: Option<DateTime<Utc>>,
}

/// The parser hands quoted strings over still escaped (`\"`, `\\`). Mailbox names are 7-bit
/// (modified UTF-7), so servers send them quoted; a name with `"` or `\` could otherwise never be
/// selected again — its mail would silently never be backed up.
pub fn unescape_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(n @ ('\\' | '"')) => out.push(n),
                Some(n) => {
                    out.push(c);
                    out.push(n);
                }
                None => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct MailboxListing {
    pub name: String,
    pub delimiter: Option<String>,
    pub special_use: Option<String>,
    pub selectable: bool,
}

#[derive(Debug, Clone)]
pub struct SelectInfo {
    pub uidvalidity: u32,
    pub uidnext: Option<u32>,
    pub exists: u32,
    pub highest_modseq: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Discovered {
    pub uid: u32,
    pub flags: Vec<String>,
    pub internaldate: Option<DateTime<Utc>>,
    pub size: u32,
    pub envelope: Envelope,
    pub gm_msgid: Option<u64>,
    pub gm_labels: Vec<String>,
}

pub fn flag_str(f: &Flag) -> String {
    match f {
        Flag::Seen => "\\Seen".into(),
        Flag::Answered => "\\Answered".into(),
        Flag::Flagged => "\\Flagged".into(),
        Flag::Deleted => "\\Deleted".into(),
        Flag::Draft => "\\Draft".into(),
        Flag::Recent => "\\Recent".into(),
        Flag::MayCreate => "\\*".into(),
        Flag::Custom(c) => c.to_string(),
    }
}

fn flags_of(f: &Fetch) -> Vec<String> {
    f.flags()
        .filter(|f| !matches!(f, Flag::Recent))
        .map(|f| flag_str(&f))
        .collect()
}

/// Gmail sends system labels quoted (`"\\Inbox"`), which [unescape_quoted] undoes (atoms
/// hold neither escape, so it leaves them alone).
fn gmail_labels(labels: &[std::borrow::Cow<'_, str>]) -> Vec<String> {
    labels.iter().map(|l| unescape_quoted(l)).collect()
}

impl Discovered {
    fn from_fetch(f: &Fetch) -> Option<Discovered> {
        let uid = f.uid?;
        let mut env = f
            .envelope()
            .map(convert_envelope)
            .unwrap_or_else(crate::index::empty_envelope);
        env.attachment_count = f.bodystructure().map(count_attachments).unwrap_or(0);
        Some(Discovered {
            uid,
            flags: flags_of(f),
            internaldate: f.internal_date().map(|d| d.with_timezone(&Utc)),
            size: f.size.unwrap_or(0),
            envelope: env,
            gm_msgid: f.gmail_msg_id().copied(),
            gm_labels: f
                .gmail_labels()
                .map(|l| gmail_labels(l))
                .unwrap_or_default(),
        })
    }
}

/// Decodes an RFC 2047 encoded unstructured header value.
pub fn decode_words(raw: &[u8]) -> String {
    let mut hdr = b"Subject: ".to_vec();
    hdr.extend(raw.iter().filter(|b| **b != b'\r' && **b != b'\n'));
    hdr.extend_from_slice(b"\r\n\r\n");
    mail_parser::MessageParser::default()
        .parse_headers(&hdr[..])
        .and_then(|m| m.subject().map(str::to_string))
        .unwrap_or_else(|| String::from_utf8_lossy(raw).into_owned())
}

fn parse_date(raw: &[u8]) -> Option<DateTime<Utc>> {
    let mut hdr = b"Date: ".to_vec();
    hdr.extend_from_slice(raw);
    hdr.extend_from_slice(b"\r\n\r\n");
    let msg = mail_parser::MessageParser::default().parse_headers(&hdr[..])?;
    DateTime::from_timestamp(msg.date()?.to_timestamp(), 0)
}

fn addr(a: &imap_proto::types::Address) -> String {
    let m = a
        .mailbox
        .as_ref()
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_default();
    match &a.host {
        Some(h) => format!("{m}@{}", String::from_utf8_lossy(h)),
        None => m,
    }
}

fn convert_envelope(e: &imap_proto::types::Envelope) -> Envelope {
    let from = e.from.as_ref().and_then(|v| v.first());
    Envelope {
        from: from.map(addr).unwrap_or_default(),
        from_name: from
            .and_then(|a| a.name.as_ref())
            .map(|n| decode_words(n))
            .filter(|n| !n.is_empty()),
        to: e
            .to
            .as_ref()
            .map(|v| v.iter().map(addr).collect())
            .unwrap_or_default(),
        subject: e
            .subject
            .as_ref()
            .map(|s| decode_words(s))
            .unwrap_or_default(),
        date: e.date.as_ref().and_then(|d| parse_date(d)),
        message_id: e
            .message_id
            .as_ref()
            .map(|m| String::from_utf8_lossy(m).trim().to_string()),
        attachment_count: 0,
    }
}

pub fn count_attachments(bs: &BodyStructure) -> u32 {
    let (common, children): (_, Vec<&BodyStructure>) = match bs {
        BodyStructure::Basic { common, .. } | BodyStructure::Text { common, .. } => {
            (common, vec![])
        }
        BodyStructure::Message { common, .. } => (common, vec![]),
        BodyStructure::Multipart { bodies, .. } => {
            return bodies.iter().map(count_attachments).sum()
        }
    };
    let _ = children;
    let disp_attachment = common
        .disposition
        .as_ref()
        .map(|d| d.ty.eq_ignore_ascii_case("attachment"))
        .unwrap_or(false);
    let has_name = common
        .ty
        .params
        .as_ref()
        .map(|p| p.iter().any(|(k, _)| k.eq_ignore_ascii_case("name")))
        .unwrap_or(false)
        || common
            .disposition
            .as_ref()
            .and_then(|d| d.params.as_ref())
            .map(|p| p.iter().any(|(k, _)| k.eq_ignore_ascii_case("filename")))
            .unwrap_or(false);
    let is_text_body = common.ty.ty.eq_ignore_ascii_case("text") && !disp_attachment && !has_name;
    u32::from(
        !is_text_body
            && (disp_attachment || has_name || matches!(bs, BodyStructure::Message { .. })),
    )
}

/// Compact UID set: `1:5,7,9:10`.
pub fn uid_set(uids: &[u32]) -> String {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            i += 1;
            end = sorted[i];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
        i += 1;
    }
    parts.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmail_labels_are_unescaped() {
        // Gmail: X-GM-LABELS ("\\Inbox" "\\Important" Work "Say \"hi\"")
        assert_eq!(unescape_quoted(r"\\Inbox"), r"\Inbox");
        assert_eq!(unescape_quoted(r#"Say \"hi\""#), r#"Say "hi""#);
        assert_eq!(
            unescape_quoted(r"\Inbox"),
            r"\Inbox",
            "atoms are left alone"
        );
        assert_eq!(unescape_quoted(r"a\b"), r"a\b");
    }

    #[test]
    fn uid_sets() {
        assert_eq!(uid_set(&[5, 1, 2, 3, 9, 7, 10]), "1:3,5,7,9:10");
        assert_eq!(uid_set(&[4]), "4");
        assert_eq!(uid_set(&[]), "");
    }

    #[test]
    fn mailbox_names_are_unescaped() {
        assert_eq!(unescape_quoted(r#"a\"b"#), r#"a"b"#);
        assert_eq!(unescape_quoted(r"a\\b"), r"a\b");
        assert_eq!(unescape_quoted(r#".git&-AOk-\""#), r#".git&-AOk-""#);
        assert_eq!(unescape_quoted("plain/&AOk-"), "plain/&AOk-");
        assert_eq!(unescape_quoted(r"trailing\"), r"trailing\");
    }

    #[test]
    fn decodes_encoded_words() {
        assert_eq!(decode_words(b"=?UTF-8?B?SGVsbG8gV8O2cmxk?="), "Hello Wörld");
        assert_eq!(decode_words(b"plain subject"), "plain subject");
    }
}
