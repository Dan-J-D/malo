//! Messages written in Malo (new mail, replies and forwards), built as MIME for sending through
//! the account's SMTP server (see [`crate::smtp`]).

use anyhow::{bail, Context};
use base64::Engine;
use chrono::Utc;
use mail_parser::MessageParser;
use rand::Rng;

/// A recipient or sender: `Name <addr@host>` or a bare address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub name: Option<String>,
    pub address: String,
}

/// A plausible address: one `@`, no spaces, brackets, quotes or control characters.
pub fn valid_address(a: &str) -> bool {
    let Some((local, domain)) = a.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && a.len() <= 254
        && !a.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '<' | '>' | '"' | ',' | ';' | '(' | ')')
        })
}

/// Parses `Name <addr>`, `"Name" <addr>` or `addr`.
pub fn parse_mailbox(s: &str) -> anyhow::Result<Mailbox> {
    let s = s.trim();
    if s.chars().any(|c| c.is_control()) {
        bail!("“{s}” contains control characters");
    }
    let (name, address) = match (s.rfind('<'), s.ends_with('>')) {
        (Some(i), true) => {
            let name = s[..i].trim().trim_matches('"').trim();
            (
                (!name.is_empty()).then(|| name.to_string()),
                s[i + 1..s.len() - 1].trim().to_string(),
            )
        }
        _ => (None, s.to_string()),
    };
    if !valid_address(&address) {
        bail!("“{s}” isn't an email address");
    }
    Ok(Mailbox { name, address })
}

/// RFC 2047 encoded words (UTF-8, base64) for header text that isn't plain ASCII.
fn encode_words(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return s.to_string();
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in s.chars() {
        // 45 bytes encode to 60 characters: each word stays within the 75-character limit.
        if chunk.len() + c.len_utf8() > 45 {
            words.push(format!("=?UTF-8?B?{}?=", b64.encode(&chunk)));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", b64.encode(&chunk)));
    }
    words.join("\r\n ")
}

fn mailbox_header(m: &Mailbox) -> String {
    match &m.name {
        Some(n) if n.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ') => {
            format!("{n} <{}>", m.address)
        }
        Some(n) if n.is_ascii() => {
            format!("\"{}\" <{}>", n.replace(['"', '\\'], ""), m.address)
        }
        Some(n) => format!("{} <{}>", encode_words(n), m.address),
        None => m.address.clone(),
    }
}

fn list_header(name: &str, list: &[Mailbox]) -> Option<String> {
    (!list.is_empty()).then(|| {
        format!(
            "{name}: {}\r\n",
            list.iter()
                .map(mailbox_header)
                .collect::<Vec<_>>()
                .join(",\r\n ")
        )
    })
}

fn base64_lines(data: &[u8]) -> String {
    let enc = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(enc.len() + enc.len() / 76 * 2 + 2);
    for line in enc.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push_str("\r\n");
    }
    out
}

/// `filename="…"`, with RFC 2231 `filename*=` for names that aren't plain ASCII.
fn file_param(key: &str, name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '"' | '\\' | '/'))
        .collect();
    if clean.is_ascii() {
        format!("{key}=\"{clean}\"")
    } else {
        let pct: String = clean
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        format!("{key}*=UTF-8''{pct}")
    }
}

pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

pub struct Draft {
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub subject: String,
    pub body: String,
    /// The message replied to (raw), for In-Reply-To and References.
    pub in_reply_to: Option<Vec<u8>>,
    pub attachments: Vec<Attachment>,
}

pub struct Built {
    pub data: Vec<u8>,
    /// Every recipient (to, cc and bcc), each once.
    pub recipients: Vec<String>,
    pub message_id: String,
}

fn random_hex(n: usize) -> String {
    let mut rng = rand::rngs::OsRng;
    (0..n)
        .map(|_| format!("{:x}", rng.gen_range(0..16u8)))
        .collect()
}

/// Wraps a header at spaces so lines stay under 78 characters where possible.
fn fold(line: &str) -> String {
    let mut out = String::new();
    let mut len = 0;
    for (i, word) in line.split(' ').enumerate() {
        if i > 0 {
            if len + 1 + word.len() > 76 {
                out.push_str("\r\n ");
                len = 1;
            } else {
                out.push(' ');
                len += 1;
            }
        }
        out.push_str(word);
        len += word.len();
    }
    out
}

/// A Message-ID from received mail that can go into our headers as is: printable ASCII without
/// spaces or angle brackets. Anything else (a CR, say) is left out of the reply.
fn valid_message_id(id: &str) -> bool {
    (1..=250).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'<' && b != b'>')
}

/// Builds the message: headers, a UTF-8 text body, and attachments (multipart/mixed).
pub fn build(d: &Draft) -> anyhow::Result<Built> {
    if d.to.is_empty() && d.cc.is_empty() && d.bcc.is_empty() {
        bail!("add at least one recipient");
    }
    if d.subject.chars().any(|c| c == '\r' || c == '\n') {
        bail!("the subject can't contain line breaks");
    }
    let domain = d
        .from
        .address
        .rsplit_once('@')
        .map(|(_, h)| h.to_string())
        .context("the sender isn't an email address")?;
    let message_id = format!("{}@{domain}", random_hex(32));
    let mut h = String::new();
    h.push_str(&format!("Date: {}\r\n", Utc::now().to_rfc2822()));
    h.push_str(&format!("From: {}\r\n", mailbox_header(&d.from)));
    if let Some(l) = list_header("To", &d.to) {
        h.push_str(&l);
    }
    if let Some(l) = list_header("Cc", &d.cc) {
        h.push_str(&l);
    }
    h.push_str(&format!("Subject: {}\r\n", encode_words(&d.subject)));
    h.push_str(&format!("Message-ID: <{message_id}>\r\n"));
    if let Some(raw) = &d.in_reply_to {
        if let Some(orig) = MessageParser::default().parse(raw.as_slice()) {
            if let Some(id) = orig.message_id().filter(|id| valid_message_id(id)) {
                let mut refs: Vec<String> = orig
                    .references()
                    .as_text_list()
                    .map(|l| {
                        l.iter()
                            .filter(|r| valid_message_id(r))
                            .map(|r| format!("<{r}>"))
                            .collect()
                    })
                    .unwrap_or_default();
                refs.push(format!("<{id}>"));
                h.push_str(&format!("In-Reply-To: <{id}>\r\n"));
                h.push_str(&format!(
                    "{}\r\n",
                    fold(&format!("References: {}", refs.join(" ")))
                ));
            }
        }
    }
    h.push_str("MIME-Version: 1.0\r\n");
    h.push_str("User-Agent: Malo\r\n");

    let body = d.body.replace("\r\n", "\n").replace('\n', "\r\n");
    let text_part = format!(
        "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        base64_lines(body.as_bytes())
    );
    let mut out = h;
    if d.attachments.is_empty() {
        out.push_str(&text_part);
    } else {
        let boundary = format!("malo-{}", random_hex(24));
        out.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\nThis is a multi-part message in MIME format.\r\n"
        ));
        out.push_str(&format!("--{boundary}\r\n{text_part}"));
        for a in &d.attachments {
            let ct: String = a
                .content_type
                .chars()
                .filter(|c| c.is_ascii_graphic() && !matches!(c, '"' | ';'))
                .collect();
            let ct = if ct.contains('/') {
                ct
            } else {
                "application/octet-stream".into()
            };
            out.push_str(&format!(
                "--{boundary}\r\nContent-Type: {ct}; {}\r\nContent-Disposition: attachment; {}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
                file_param("name", &a.filename),
                file_param("filename", &a.filename),
                base64_lines(&a.data)
            ));
        }
        out.push_str(&format!("--{boundary}--\r\n"));
    }
    let mut recipients: Vec<String> = Vec::new();
    for m in d.to.iter().chain(&d.cc).chain(&d.bcc) {
        if !recipients
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&m.address))
        {
            recipients.push(m.address.clone());
        }
    }
    Ok(Built {
        data: out.into_bytes(),
        recipients,
        message_id,
    })
}

impl crate::index::Index {
    /// Drafts, most recently changed first.
    pub fn drafts(&self) -> anyhow::Result<Vec<malo_api::DraftView>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, account, message, updated_at FROM drafts ORDER BY updated_at DESC, id DESC",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows
                .into_iter()
                .filter_map(|(id, account_id, message, at)| {
                    Some(malo_api::DraftView {
                        id,
                        account_id,
                        message: serde_json::from_str(&message).ok()?,
                        updated_at: chrono::DateTime::parse_from_rfc3339(&at)
                            .ok()?
                            .with_timezone(&Utc),
                    })
                })
                .collect())
        })
    }

    /// Saves a draft: a new one without `id`, else that one (None when it is gone).
    pub fn save_draft(
        &self,
        id: Option<i64>,
        account: &str,
        message: &malo_api::SendRequest,
    ) -> anyhow::Result<Option<malo_api::DraftView>> {
        let json = serde_json::to_string(message)?;
        let now = Utc::now();
        let id = self.with(|c| match id {
            Some(id) => Ok(c
                .execute(
                    "UPDATE drafts SET account=?2, message=?3, updated_at=?4 WHERE id=?1",
                    rusqlite::params![id, account, json, now.to_rfc3339()],
                )?
                .eq(&1)
                .then_some(id)),
            None => {
                c.execute(
                    "INSERT INTO drafts(account, message, updated_at) VALUES(?1,?2,?3)",
                    rusqlite::params![account, json, now.to_rfc3339()],
                )?;
                Ok(Some(c.last_insert_rowid()))
            }
        })?;
        Ok(id.map(|id| malo_api::DraftView {
            id,
            account_id: account.to_string(),
            message: message.clone(),
            updated_at: now,
        }))
    }

    pub fn delete_draft(&self, id: i64) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM drafts WHERE id=?1", [id]))? == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mb(s: &str) -> Mailbox {
        parse_mailbox(s).unwrap()
    }

    #[test]
    fn addresses() {
        assert_eq!(
            mb("Alice Example <alice@example.com>"),
            Mailbox {
                name: Some("Alice Example".into()),
                address: "alice@example.com".into()
            }
        );
        assert_eq!(mb("\"Bob\" <bob@x.org>").name.as_deref(), Some("Bob"));
        assert_eq!(mb(" carol@x.org ").address, "carol@x.org");
        for bad in [
            "nobody",
            "a b@x.org",
            "x@localhost",
            "x@y.org\r\nBcc: z@q.org",
            "<>",
            "a@.org",
        ] {
            assert!(parse_mailbox(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn builds_a_reply_with_an_attachment() {
        let original = b"Message-ID: <orig@example.com>\r\nReferences: <root@example.com>\r\nSubject: Hi\r\n\r\nhello\r\n";
        let built = build(&Draft {
            from: mb("Me <me@example.org>"),
            to: vec![mb("Zoë Ünïcode <zoe@example.com>")],
            cc: vec![mb("bob@example.com")],
            bcc: vec![mb("ZOE@example.com"), mb("hidden@example.net")],
            subject: "Re: Grüße".into(),
            body: "Thanks!\n\n> hello\n".into(),
            in_reply_to: Some(original.to_vec()),
            attachments: vec![Attachment {
                filename: "rapport é.pdf".into(),
                content_type: "application/pdf".into(),
                data: b"%PDF-1".to_vec(),
            }],
        })
        .unwrap();
        assert_eq!(
            built.recipients,
            ["zoe@example.com", "bob@example.com", "hidden@example.net"]
        );
        let text = String::from_utf8(built.data.clone()).unwrap();
        assert!(
            !text.contains("hidden@example.net"),
            "bcc stays out of the headers"
        );
        assert!(text.contains("In-Reply-To: <orig@example.com>"));
        assert!(text.contains("References: <root@example.com> <orig@example.com>"));
        assert!(
            !text.contains('\n') || text.split('\n').all(|l| l.is_empty() || l.ends_with('\r'))
        );
        // Read back, it is the message that was written.
        let m = MessageParser::default().parse(&built.data).unwrap();
        assert_eq!(m.subject(), Some("Re: Grüße"));
        assert_eq!(m.to().unwrap().first().unwrap().name(), Some("Zoë Ünïcode"));
        assert_eq!(m.body_text(0).unwrap(), "Thanks!\r\n\r\n> hello\r\n");
        let a = m.attachments().next().unwrap();
        use mail_parser::MimeHeaders;
        assert_eq!(a.attachment_name(), Some("rapport é.pdf"));
        assert_eq!(a.contents(), b"%PDF-1");
        assert_eq!(m.message_id(), Some(built.message_id.as_str()));
        assert!(built.message_id.ends_with("@example.org"));
    }

    #[test]
    fn hostile_message_ids_are_left_out() {
        let reply = |original: &[u8]| {
            let built = build(&Draft {
                from: mb("me@example.org"),
                to: vec![mb("a@example.com")],
                cc: vec![],
                bcc: vec![],
                subject: "Re: x".into(),
                body: "ok".into(),
                in_reply_to: Some(original.to_vec()),
                attachments: vec![],
            })
            .unwrap();
            // Every line break is CRLF, so the message can be sent.
            crate::smtp::dot_stuff(&built.data).unwrap();
            String::from_utf8(built.data).unwrap()
        };
        let text = reply(b"Message-ID: <a\rBcc: victim@example.net>\r\nSubject: x\r\n\r\nhi\r\n");
        assert!(
            !text.contains("In-Reply-To") && !text.contains("victim"),
            "{text}"
        );
        let text = reply(
            b"Message-ID: <ok@example.com>\r\nReferences: <bad\rX-Evil: 1> <root@example.com>\r\n\r\nhi\r\n",
        );
        assert!(text.contains("In-Reply-To: <ok@example.com>"));
        assert!(
            text.contains("References: <root@example.com> <ok@example.com>"),
            "{text}"
        );
        assert!(!text.contains("X-Evil"));
        assert!(!valid_message_id("a b@c") && !valid_message_id("a>b") && !valid_message_id(""));
        assert!(valid_message_id("CAF=x+y@mail.gmail.com"));
    }

    #[test]
    fn drafts_are_kept_until_deleted() {
        let idx = crate::index::Index::open_in_memory().unwrap();
        let msg = |subject: &str| malo_api::SendRequest {
            from: None,
            to: vec!["a@b.org".into()],
            cc: vec![],
            bcc: vec![],
            subject: subject.into(),
            body: "…".into(),
            in_reply_to: None,
            attachments_of: None,
            draft_id: None,
        };
        let d = idx.save_draft(None, "acc", &msg("one")).unwrap().unwrap();
        let again = idx
            .save_draft(Some(d.id), "acc", &msg("two"))
            .unwrap()
            .unwrap();
        assert_eq!(again.id, d.id);
        let all = idx.drafts().unwrap();
        assert_eq!((all.len(), all[0].message.subject.as_str()), (1, "two"));
        assert!(idx.delete_draft(d.id).unwrap());
        assert!(idx
            .save_draft(Some(d.id), "acc", &msg("x"))
            .unwrap()
            .is_none());
        idx.save_draft(None, "acc", &msg("y")).unwrap();
        idx.delete_account("acc").unwrap();
        assert!(idx.drafts().unwrap().is_empty());
    }

    #[test]
    fn refuses_bad_input() {
        let d = |subject: &str, to: Vec<Mailbox>| Draft {
            from: mb("me@example.org"),
            to,
            cc: vec![],
            bcc: vec![],
            subject: subject.into(),
            body: String::new(),
            in_reply_to: None,
            attachments: vec![],
        };
        assert!(build(&d("x", vec![])).is_err());
        assert!(build(&d("x\r\nBcc: evil@x.org", vec![mb("a@b.org")])).is_err());
        assert!(build(&d("plain", vec![mb("a@b.org")])).is_ok());
    }
}
