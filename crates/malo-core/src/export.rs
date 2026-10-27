//! Exporting backed-up mail as files other programs read: mbox (mboxrd), Maildir++ or a zip of
//! `.eml` files, sorted into one folder tree per account.
//!
//! The export is produced while it downloads: messages are read one at a time (from the spool or
//! a verified replica, hash-checked) and the archive is written into a channel, so nothing is kept
//! on the server's disk. A message that can't be read is left out and listed in
//! `export-errors.txt`; a single mbox file has no room for that list, so its download stops with
//! an error instead.

use std::collections::{BTreeSet, HashMap};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use malo_api::{ExportFormat, RestoreSelection};
use tokio::sync::mpsc;

use crate::ctx::JobCtx;
use crate::index::{MailboxRow, MembershipRow};
use crate::zipstream::ZipWriter;

/// Output collected before it is handed to the channel.
const CHUNK: usize = 256 * 1024;

/// One message of an export, where it goes and how it's marked.
#[derive(Debug, Clone)]
pub struct Item {
    pub id: i64,
    /// Top folder: the account's name.
    pub account: String,
    /// Folder path below it, e.g. `["INBOX"]` or `["Projects", "2024"]`.
    pub folder: Vec<String>,
    pub flags: Vec<String>,
    pub date: DateTime<Utc>,
    pub subject: String,
    pub from: String,
}

#[derive(Debug, Default, Clone)]
pub struct Plan {
    pub items: Vec<Item>,
    /// Messages left out before reading anything (not backed up yet).
    pub skipped: Vec<String>,
}

impl Plan {
    fn single_folder(&self) -> bool {
        self.items
            .windows(2)
            .all(|w| w[0].account == w[1].account && w[0].folder == w[1].folder)
    }

    /// The file the export downloads as.
    pub fn filename(&self, format: ExportFormat) -> String {
        if format == ExportFormat::Mbox && self.single_folder() {
            if let Some(first) = self.items.first() {
                let name = first.folder.last().map(String::as_str).unwrap_or("mail");
                return format!("{}.mbox", friendly(name, 80));
            }
        }
        let kind = match format {
            ExportFormat::Mbox => "mbox",
            ExportFormat::Maildir => "maildir",
            ExportFormat::Zip => "eml",
        };
        format!("malo-export-{kind}-{}.zip", Utc::now().format("%Y-%m-%d"))
    }

    pub fn content_type(&self, format: ExportFormat) -> &'static str {
        if self.filename(format).ends_with(".mbox") {
            "application/mbox"
        } else {
            "application/zip"
        }
    }
}

/// A file or folder name that unpacks anywhere: no separators or characters Windows refuses,
/// nothing hidden, no `.`/`..`, at most `max` characters.
pub fn friendly(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                || crate::layout::is_invisible(c)
            {
                '_'
            } else {
                c
            }
        })
        .take(max)
        .collect();
    out = out.trim_matches(|c: char| c == ' ' || c == '.').to_string();
    if out.is_empty() {
        return "_".into();
    }
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3",
    ];
    let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        out.insert(0, '_');
    }
    out
}

/// The folder a message is exported into: the mailbox it was backed up from. Gmail's All Mail
/// is split up by label (Inbox, Sent, Drafts, then the first label of its own).
fn folder_of(mailbox: Option<&MailboxRow>, membership: Option<&MembershipRow>) -> Vec<String> {
    let Some(mb) = mailbox else {
        return vec!["Unfiled".into()];
    };
    let split = |name: &str, delim: Option<&str>| -> Vec<String> {
        match delim.filter(|d| !d.is_empty()) {
            Some(d) => name.split(d).map(str::to_string).collect(),
            None => vec![name.to_string()],
        }
    };
    if mb.special_use.as_deref() == Some("\\All") {
        let labels = membership.map(|m| m.gm_labels.as_slice()).unwrap_or(&[]);
        let has = |l: &str| labels.iter().any(|x| x.eq_ignore_ascii_case(l));
        for (label, folder) in [
            ("\\Inbox", "INBOX"),
            ("\\Sent", "Sent"),
            ("\\Draft", "Drafts"),
        ] {
            if has(label) {
                return vec![folder.into()];
            }
        }
        if let Some(l) = labels
            .iter()
            .find(|l| !l.starts_with('\\') && !l.is_empty())
        {
            return split(l, Some("/"));
        }
    }
    if mb.name.eq_ignore_ascii_case("INBOX") {
        return vec!["INBOX".into()];
    }
    split(&mb.display, mb.delimiter.as_deref())
}

/// What a selection exports, sorted by account, folder and date.
pub fn plan(ctx: &JobCtx, selection: &RestoreSelection) -> anyhow::Result<Plan> {
    let ids = crate::restore::resolve(ctx, selection)?;
    let only_mailbox = match selection {
        RestoreSelection::Account { mailbox, .. } => mailbox.as_deref(),
        _ => None,
    };
    // Two accounts of the same name get their ids added, so their folders stay apart.
    let mut names: HashMap<String, String> = HashMap::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for a in &ctx.config.accounts {
        *seen
            .entry(friendly(&a.name, 80).to_lowercase())
            .or_default() += 1;
    }
    for a in &ctx.config.accounts {
        let base = friendly(&a.name, 80);
        let name = if seen[&base.to_lowercase()] > 1 {
            format!("{base} ({})", &a.id[..a.id.len().min(8)])
        } else {
            base
        };
        names.insert(a.id.clone(), name);
    }
    let mut mailboxes: HashMap<i64, Option<MailboxRow>> = HashMap::new();
    let mut plan = Plan::default();
    for id in ids {
        let Some(msg) = ctx.index.message(id)? else {
            continue;
        };
        let date = msg
            .internaldate
            .or(msg.envelope.date)
            .unwrap_or(msg.first_seen_at);
        if msg.sha256.is_none() {
            plan.skipped.push(format!(
                "{} ({}): not backed up yet",
                msg.envelope.subject,
                date.format("%Y-%m-%d")
            ));
            continue;
        }
        let memberships = ctx.index.memberships(id)?;
        let mut pick: Option<(&MembershipRow, Option<MailboxRow>)> = None;
        for m in &memberships {
            let row = mailboxes
                .entry(m.mailbox)
                .or_insert_with(|| ctx.index.mailbox(m.mailbox).ok().flatten())
                .clone();
            let wanted = only_mailbox.is_none_or(|w| row.as_ref().is_some_and(|r| r.name == w));
            if wanted {
                pick = Some((m, row));
                break;
            }
        }
        let (membership, mailbox) = match pick {
            Some((m, row)) => (Some(m), row),
            None => (memberships.first(), None),
        };
        plan.items.push(Item {
            id,
            account: names
                .get(&msg.account)
                .cloned()
                .unwrap_or_else(|| friendly(&msg.account, 40)),
            folder: folder_of(mailbox.as_ref(), membership)
                .iter()
                .map(|c| friendly(c, 80))
                .collect(),
            flags: membership.map(|m| m.flags.clone()).unwrap_or_default(),
            date,
            subject: msg.envelope.subject.clone(),
            from: msg.envelope.from.clone(),
        });
    }
    plan.items.sort_by(|a, b| {
        (&a.account, &a.folder, a.date, a.id).cmp(&(&b.account, &b.folder, b.date, b.id))
    });
    Ok(plan)
}

fn has_flag(flags: &[String], f: &str) -> bool {
    flags.iter().any(|x| x.eq_ignore_ascii_case(f))
}

/// One message in mboxrd form: a `From ` line, `Status`/`X-Status` for its flags (unless it has
/// them already), LF line ends, `From ` lines quoted with one more `>`, and a blank line after.
pub fn mbox_entry(item: &Item, raw: &[u8]) -> Vec<u8> {
    let sender = if !item.from.is_empty()
        && item.from.contains('@')
        && !item
            .from
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        item.from.as_str()
    } else {
        "MAILER-DAEMON"
    };
    let mut out = Vec::with_capacity(raw.len() + 128);
    out.extend_from_slice(
        format!(
            "From {sender} {}\n",
            item.date.format("%a %b %e %H:%M:%S %Y")
        )
        .as_bytes(),
    );
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
        .unwrap_or(raw.len());
    let has_status = raw[..header_end].split(|&b| b == b'\n').any(|l| {
        l.len() >= 7 && l[..7].eq_ignore_ascii_case(b"status:")
            || l.len() >= 9 && l[..9].eq_ignore_ascii_case(b"x-status:")
    });
    if !has_status {
        let seen = has_flag(&item.flags, "\\Seen");
        out.extend_from_slice(if seen {
            b"Status: RO\n"
        } else {
            b"Status: O\n"
        });
        let x: String = [
            ("\\Answered", 'A'),
            ("\\Flagged", 'F'),
            ("\\Draft", 'T'),
            ("\\Deleted", 'D'),
        ]
        .iter()
        .filter(|(f, _)| has_flag(&item.flags, f))
        .map(|(_, c)| *c)
        .collect();
        if !x.is_empty() {
            out.extend_from_slice(format!("X-Status: {x}\n").as_bytes());
        }
    }
    let mut lines = raw.split(|&b| b == b'\n').peekable();
    while let Some(line) = lines.next() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if lines.peek().is_none() && line.is_empty() {
            break;
        }
        let quoted = line.iter().position(|&b| b != b'>').unwrap_or(line.len());
        if line[quoted..].starts_with(b"From ") {
            out.push(b'>');
        }
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}

/// Maildir file name: unique, with the size and the flags (`:2,` then D F R S T).
pub fn maildir_name(item: &Item, size: usize) -> String {
    let flags: String = [
        ("\\Draft", 'D'),
        ("\\Flagged", 'F'),
        ("\\Answered", 'R'),
        ("\\Seen", 'S'),
        ("\\Deleted", 'T'),
    ]
    .iter()
    .filter(|(f, _)| has_flag(&item.flags, f))
    .map(|(_, c)| *c)
    .collect();
    format!(
        "{}.M{}P0.malo,S={size}:2,{flags}",
        item.date.timestamp().max(0),
        item.id
    )
}

/// The Maildir++ folder of an item below its account: the root for INBOX, `.A.B` for `A/B`.
fn maildir_folder(item: &Item) -> String {
    if item.folder.len() == 1 && item.folder[0].eq_ignore_ascii_case("INBOX") {
        return String::new();
    }
    let parts: Vec<String> = item.folder.iter().map(|c| c.replace('.', "_")).collect();
    format!(".{}/", parts.join("."))
}

fn eml_name(item: &Item) -> String {
    let subject = if item.subject.trim().is_empty() {
        "(no subject)"
    } else {
        item.subject.trim()
    };
    format!(
        "{} {} [{}].eml",
        item.date.format("%Y-%m-%d %H%M"),
        friendly(subject, 60),
        item.id
    )
}

pub struct Sink {
    tx: mpsc::Sender<std::io::Result<Bytes>>,
}

impl Sink {
    pub fn new(tx: mpsc::Sender<std::io::Result<Bytes>>) -> Self {
        Sink { tx }
    }

    async fn send(&self, b: Vec<u8>) -> anyhow::Result<()> {
        if b.is_empty() {
            return Ok(());
        }
        self.tx
            .send(Ok(Bytes::from(b)))
            .await
            .map_err(|_| anyhow::anyhow!("the download was stopped"))
    }

    async fn fail(&self, e: &anyhow::Error) {
        let _ = self
            .tx
            .send(Err(std::io::Error::other(format!("{e:#}"))))
            .await;
    }
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ExportStats {
    pub exported: u64,
    pub failed: u64,
    pub bytes: u64,
}

/// Writes the export into `sink`. Errors end the download with an error.
pub async fn write(
    ctx: &JobCtx,
    plan: &Plan,
    format: ExportFormat,
    sink: Sink,
) -> anyhow::Result<ExportStats> {
    let res = write_inner(ctx, plan, format, &sink).await;
    if let Err(e) = &res {
        sink.fail(e).await;
    }
    let (stats, errors) = res?;
    ctx.index.audit(
        "exported",
        None,
        &serde_json::json!({
            "format": format,
            "messages": stats.exported,
            "failed": stats.failed + plan.skipped.len() as u64,
            "errors": errors.iter().take(20).collect::<Vec<_>>(),
        }),
    )?;
    Ok(stats)
}

async fn write_inner(
    ctx: &JobCtx,
    plan: &Plan,
    format: ExportFormat,
    sink: &Sink,
) -> anyhow::Result<(ExportStats, Vec<String>)> {
    let stores = ctx.stores()?;
    let mut stats = ExportStats::default();
    let mut errors: Vec<String> = plan.skipped.clone();
    let plain_mbox = plan.filename(format).ends_with(".mbox");
    let mut zip = ZipWriter::new();
    let mut made: BTreeSet<String> = BTreeSet::new();
    // The mbox file being written: (account, folder).
    let mut open_mbox: Option<(String, Vec<String>)> = None;
    let mut buffered: Vec<u8> = Vec::new();
    let now = Utc::now();

    for item in &plan.items {
        ctx.check_cancel()?;
        let msg = ctx.index.message(item.id)?;
        let raw = match &msg {
            Some(m) => crate::restore::read_message(ctx, &stores, m).await,
            None => None,
        };
        let Some(raw) = raw else {
            let e = format!(
                "{} ({}): no readable copy in the spool or on any destination",
                item.subject,
                item.date.format("%Y-%m-%d")
            );
            if plain_mbox {
                anyhow::bail!("export stopped: {e}");
            }
            stats.failed += 1;
            errors.push(e);
            continue;
        };
        stats.exported += 1;
        stats.bytes += raw.len() as u64;
        match format {
            ExportFormat::Mbox if plain_mbox => {
                buffered.extend(mbox_entry(item, &raw));
                if buffered.len() >= CHUNK {
                    sink.send(std::mem::take(&mut buffered)).await?;
                }
                continue;
            }
            ExportFormat::Mbox => {
                let key = (item.account.clone(), item.folder.clone());
                if open_mbox.as_ref() != Some(&key) {
                    if open_mbox.is_some() {
                        zip.finish_file();
                    }
                    let mut path = item.account.clone();
                    for (i, c) in item.folder.iter().enumerate() {
                        path.push('/');
                        path.push_str(c);
                        if i + 1 == item.folder.len() {
                            path.push_str(".mbox");
                        }
                    }
                    zip.start_file(&path, now);
                    open_mbox = Some(key);
                }
                zip.write(&mbox_entry(item, &raw));
            }
            ExportFormat::Maildir => {
                let root = format!("{}/", item.account);
                let folder = format!("{root}{}", maildir_folder(item));
                for dir in [&root, &folder] {
                    if made.insert(dir.clone()) {
                        for sub in ["cur", "new", "tmp"] {
                            zip.add_dir(&format!("{dir}{sub}/"), now);
                        }
                        if dir != &root {
                            zip.add_file(&format!("{dir}maildirfolder"), now, b"");
                        }
                    }
                }
                let name = format!("{folder}cur/{}", maildir_name(item, raw.len()));
                zip.add_file(&name, item.date, &raw);
            }
            ExportFormat::Zip => {
                let name = format!(
                    "{}/{}/{}",
                    item.account,
                    item.folder.join("/"),
                    eml_name(item)
                );
                zip.add_file(&name, item.date, &raw);
            }
        }
        if zip.pending() >= CHUNK {
            sink.send(zip.take()).await?;
        }
    }
    if plain_mbox {
        sink.send(buffered).await?;
        return Ok((stats, errors));
    }
    if open_mbox.is_some() {
        zip.finish_file();
    }
    if !errors.is_empty() {
        let mut text = format!("{} message(s) could not be exported:\n\n", errors.len());
        for e in &errors {
            text.push_str(e);
            text.push('\n');
        }
        zip.add_file("export-errors.txt", now, text.as_bytes());
    }
    sink.send(zip.finish()).await?;
    Ok((stats, errors))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(flags: &[&str]) -> Item {
        Item {
            id: 42,
            account: "Work".into(),
            folder: vec!["INBOX".into()],
            flags: flags.iter().map(|f| f.to_string()).collect(),
            date: DateTime::parse_from_rfc3339("2024-03-05T06:07:08Z")
                .unwrap()
                .with_timezone(&Utc),
            subject: "Hi".into(),
            from: "a@example.com".into(),
        }
    }

    #[test]
    fn mboxrd_entries() {
        let raw = b"From: a@example.com\r\nSubject: Hi\r\n\r\nFrom here\r\n>From there\r\nok\r\n";
        let out = String::from_utf8(mbox_entry(&item(&["\\Seen", "\\Flagged"]), raw)).unwrap();
        assert_eq!(
            out,
            "From a@example.com Tue Mar  5 06:07:08 2024\nStatus: RO\nX-Status: F\n\
             From: a@example.com\nSubject: Hi\n\n>From here\n>>From there\nok\n\n"
        );
        // A message that has Status headers keeps its own; no final newline gets one.
        let raw = b"Status: O\nSubject: x\n\nbody";
        let mut it = item(&[]);
        it.from = "not an address".into();
        let out = String::from_utf8(mbox_entry(&it, raw)).unwrap();
        assert_eq!(
            out,
            "From MAILER-DAEMON Tue Mar  5 06:07:08 2024\nStatus: O\nSubject: x\n\nbody\n\n"
        );
    }

    #[test]
    fn maildir_names_and_folders() {
        assert_eq!(
            maildir_name(&item(&["\\Seen", "\\Answered", "\\Draft"]), 10),
            "1709618828.M42P0.malo,S=10:2,DRS"
        );
        assert_eq!(maildir_folder(&item(&[])), "");
        let mut it = item(&[]);
        it.folder = vec!["Projects".into(), "v1.2".into()];
        assert_eq!(maildir_folder(&it), ".Projects.v1_2/");
    }

    #[test]
    fn friendly_names() {
        assert_eq!(friendly("a/b:c?", 80), "a_b_c_");
        assert_eq!(friendly("..", 80), "_");
        assert_eq!(friendly(" x. ", 80), "x");
        assert_eq!(friendly("con.txt", 80), "_con.txt");
        assert_eq!(friendly("a\u{202E}b", 80), "a_b");
        assert_eq!(friendly("abcdef", 3), "abc");
        assert_eq!(eml_name(&item(&[])), "2024-03-05 0607 Hi [42].eml");
    }

    #[test]
    fn gmail_all_mail_follows_labels() {
        let mb = MailboxRow {
            id: 1,
            account: "a".into(),
            name: "[Gmail]/All Mail".into(),
            display: "[Gmail]/All Mail".into(),
            path: String::new(),
            delimiter: Some("/".into()),
            special_use: Some("\\All".into()),
            uidvalidity: 1,
            highest_uid: 1,
            highestmodseq: None,
            current: true,
        };
        let m = |labels: &[&str]| MembershipRow {
            id: 1,
            message: 1,
            mailbox: 1,
            uid: 1,
            flags: vec![],
            gm_labels: labels.iter().map(|l| l.to_string()).collect(),
            deleted_on_server: false,
        };
        assert_eq!(folder_of(Some(&mb), Some(&m(&["\\Inbox"]))), ["INBOX"]);
        assert_eq!(
            folder_of(Some(&mb), Some(&m(&["Work/2024"]))),
            ["Work", "2024"]
        );
        assert_eq!(folder_of(Some(&mb), Some(&m(&[]))), ["[Gmail]", "All Mail"]);
        assert_eq!(folder_of(None, None), ["Unfiled"]);
    }
}
