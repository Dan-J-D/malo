//! Full-text search over backed-up mail: an FTS5 table (`search`) inside the encrypted index, so
//! the searchable text is as protected as the rest of the index and goes away with its message.
//!
//! New mail is indexed while a backup has it in memory; mail backed up earlier is indexed by the
//! search-index job, from the spool, the viewer cache or a destination. Until a message is indexed,
//! searches match its sender, recipients and subject only.

use std::collections::HashSet;

use futures::StreamExt;
use mail_parser::{MessageParser, MimeHeaders};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::crypto;
use crate::ctx::JobCtx;
use crate::index::{fold, Index};
use crate::mailview::ImapMeta;

/// Body text indexed per message; the rest of a very long message isn't searchable.
pub const MAX_BODY_CHARS: usize = 200_000;
/// Messages loaded at once by the search-index job.
const CONCURRENCY: usize = 8;
/// kv: how many messages the last search-index job couldn't read.
pub const UNAVAILABLE_KEY: &str = "search_unavailable";

/// Messages whose content isn't indexed: no searchable text, or no header data for mail apps.
const PENDING: &str = "indexed_sha IS NOT sha256
    OR NOT EXISTS(SELECT 1 FROM imap_meta i WHERE i.sha256=messages.sha256)";

/// The searchable text of one message. It keeps its case (the tokenizer ignores case and
/// accents) so snippets read naturally, but not characters that hide words (see [`clean`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SearchDoc {
    pub subject: String,
    pub sender: String,
    pub recipients: String,
    pub attachments: String,
    pub body: String,
    /// The conversation it belongs to: the first Message-ID of References, else In-Reply-To,
    /// else its own Message-ID (lower case, without angle brackets).
    pub thread: Option<String>,
    /// What mail apps fetch without the message: header, ENVELOPE and BODYSTRUCTURE.
    pub imap: Option<ImapMeta>,
}

/// Text of a raw message: headers people search by, attachment names and the readable body
/// (HTML-only mail as text). Unparseable mail gives an empty document.
pub fn extract(raw: &[u8]) -> SearchDoc {
    let imap = Some(ImapMeta::of(raw));
    let Some(msg) = MessageParser::default().parse(raw) else {
        return SearchDoc {
            imap,
            ..SearchDoc::default()
        };
    };
    let addresses = |list: &[Option<&mail_parser::Address>]| {
        let mut out = String::new();
        for a in list.iter().flatten().flat_map(|a| a.iter()) {
            for part in [a.name(), a.address()].into_iter().flatten() {
                out.push_str(part);
                out.push(' ');
            }
        }
        out
    };
    let mut body = String::new();
    let mut i = 0;
    while let Some(text) = msg.body_text(i) {
        if body.len() >= MAX_BODY_CHARS {
            break;
        }
        body.push_str(&text);
        body.push('\n');
        i += 1;
    }
    if let Some((cut, _)) = body.char_indices().nth(MAX_BODY_CHARS) {
        body.truncate(cut);
    }
    let attachments: Vec<&str> = msg
        .attachments()
        .filter_map(|p| p.attachment_name())
        .collect();
    let first = |v: &mail_parser::HeaderValue| {
        v.as_text_list()
            .and_then(|l| l.first().map(|s| s.to_string()))
    };
    let thread = first(msg.references())
        .or_else(|| first(msg.in_reply_to()))
        .or_else(|| msg.message_id().map(str::to_string))
        .map(|id| {
            id.trim_matches(|c: char| c == '<' || c == '>' || c.is_whitespace())
                .to_lowercase()
        })
        .filter(|id| !id.is_empty());
    SearchDoc {
        thread,
        subject: clean(msg.subject().unwrap_or("")),
        sender: clean(&addresses(&[msg.from(), msg.sender(), msg.reply_to()])),
        recipients: clean(&addresses(&[msg.to(), msg.cc(), msg.bcc()])),
        // One name per line, so suggestions can tell them apart.
        attachments: clean(&attachments.join("\n")),
        body: clean(&body),
        imap,
    }
}

/// NFC with invisible characters removed, so `Pay<zero-width>Pal` is indexed as `PayPal`.
fn clean(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    s.nfc()
        .filter(|c| !crate::layout::is_invisible(*c))
        .collect()
}

/// An FTS5 string literal.
fn literal(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn has_words(s: &str) -> bool {
    s.chars().any(char::is_alphanumeric)
}

/// A substring search (IMAP `BODY`/`TEXT`) as an FTS5 phrase whose last word may be a prefix.
/// None when it has no words to look for.
pub fn phrase(s: &str) -> Option<String> {
    let s = fold(s.trim());
    has_words(&s).then(|| format!("{}*", literal(&s)))
}

/// Columns of the `search` table a term can be limited to.
pub const COLUMNS: [&str; 5] = ["subject", "sender", "recipients", "attachments", "body"];

fn column_of(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "from" | "sender" => "sender",
        "to" | "cc" | "bcc" | "recipients" => "recipients",
        "subject" => "subject",
        "body" => "body",
        "file" | "attachment" | "filename" | "attachments" => "attachments",
        _ => return None,
    })
}

/// A date or the start of a month or year: `2024-03-01`, `2024-03`, `2024`. Compared as text
/// with the stored RFC 3339 dates, which start the same way.
fn date_prefix(s: &str) -> Option<String> {
    let shape = |n: usize| {
        s.len() == n
            && s.char_indices().all(|(i, c)| {
                if i == 4 || i == 7 {
                    c == '-'
                } else {
                    c.is_ascii_digit()
                }
            })
    };
    (shape(4) || shape(7) || shape(10)).then(|| s.to_string())
}

/// A search typed in the app (see [`parse`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Search {
    /// FTS5 query for indexed messages; None when no term has words.
    pub fts: Option<String>,
    /// [`contains_spec`] for messages not indexed yet, checked against their envelope; None when
    /// a term can only be answered by the index (`body:`, `file:`).
    pub envelope: Option<String>,
    /// [`contains_spec`] of terms without words (`%`, `&`), which the index can't look up:
    /// checked against every message's envelope.
    pub literal: Option<String>,
    /// Received on or after this date (prefix of an RFC 3339 date).
    pub after: Option<String>,
    /// Received before this date.
    pub before: Option<String>,
    pub has_attachment: Option<bool>,
    /// Deleted on the mail server (only the backup has it).
    pub purged: Option<bool>,
    pub unread: Option<bool>,
    /// Gmail category (`primary`, `social`, `promotions`, `updates`, `forums`), and whether the
    /// message must be in it (false: `-category:`).
    pub category: Option<(String, bool)>,
    /// Collections (`tag:name`), and whether the message must be in it (false: `-tag:`).
    pub tags: Vec<(String, bool)>,
}

/// Gmail's inbox categories, Primary first.
pub const CATEGORIES: [&str; 5] = ["primary", "social", "promotions", "updates", "forums"];

impl Search {
    /// Whether a term with words must match (through the index or the envelope).
    pub fn has_text(&self) -> bool {
        self.fts.is_some()
    }
}

/// Encodes term groups for the `malo_contains` SQL function: every group needs one of its
/// alternatives (U+001F between them) in the text; a group starting with U+001D needs none.
/// Groups are separated by U+001E.
fn contains_spec(groups: &[Vec<String>], not: &[String]) -> Option<String> {
    let mut parts: Vec<String> = groups.iter().map(|g| g.join("\u{1f}")).collect();
    parts.extend(not.iter().map(|n| format!("\u{1d}{n}")));
    (!parts.is_empty()).then(|| parts.join("\u{1e}"))
}

/// Evaluates a [`contains_spec`] against folded text.
pub fn contains(hay: &str, spec: &str) -> bool {
    spec.split('\u{1e}')
        .all(|group| match group.strip_prefix('\u{1d}') {
            Some(n) => !hay.contains(n),
            None => group.split('\u{1f}').any(|alt| hay.contains(alt)),
        })
}

/// One term of a search: its text, the column it's limited to, and how it was written.
struct Term {
    text: String,
    column: Option<&'static str>,
    quoted: bool,
    negate: bool,
    /// `name:` that isn't a column (`has:`, `is:`, `before:`, …).
    operator: Option<String>,
}

fn terms(input: &str) -> Vec<Term> {
    let mut out = vec![];
    let mut chars = input.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        if chars.peek().is_none() {
            break;
        }
        let negate = chars.next_if_eq(&'-').is_some();
        let mut word = String::new();
        let mut column = None;
        let mut operator = None;
        let mut quoted = false;
        loop {
            match chars.peek() {
                None => break,
                Some(c) if c.is_whitespace() => break,
                Some('"') if word.is_empty() => {
                    chars.next();
                    quoted = true;
                    for c in chars.by_ref() {
                        if c == '"' {
                            break;
                        }
                        word.push(c);
                    }
                    break;
                }
                Some(':') if column.is_none() && operator.is_none() && !word.is_empty() => {
                    chars.next();
                    let name = word.to_ascii_lowercase();
                    if let Some(c) = column_of(&name) {
                        column = Some(c);
                    } else if matches!(
                        name.as_str(),
                        "has" | "is" | "before" | "after" | "category" | "tag" | "collection"
                    ) {
                        operator = Some(if name == "collection" {
                            "tag".into()
                        } else {
                            name
                        });
                    } else {
                        word.push(':');
                        continue;
                    }
                    word.clear();
                }
                Some(&c) => {
                    chars.next();
                    word.push(c);
                }
            }
        }
        out.push(Term {
            text: word,
            column,
            quoted,
            negate,
            operator,
        });
    }
    out
}

/// Parses a search typed in the app:
///
/// - words match words starting with them (`inv` finds `invoice`), all of them must match;
/// - `"exact phrase"`;
/// - `from:`, `to:` (also cc), `subject:`, `body:` and `file:` (attachment names) limit a word or
///   phrase to that part; `column` does that for words without one;
/// - `OR` between two words or phrases, `-word` leaves out messages with it;
/// - `after:2024-03-01` and `before:2024` (received; a day, month or year), `has:attachment`,
///   `is:purged` (deleted on the mail server), `is:unread`, `is:read`, `category:social` (Gmail:
///   primary, social, promotions, updates, forums), `tag:name` or `tag:"two words"` (in that
///   collection); `-` negates them too.
pub fn parse(input: &str, column: Option<&str>) -> Search {
    let column = column.and_then(|c| COLUMNS.iter().copied().find(|x| *x == c));
    let mut s = Search::default();
    let mut groups: Vec<Vec<(String, bool)>> = Vec::new();
    let mut not: Vec<String> = Vec::new();
    let (mut env_groups, mut env_not, mut env_ok): (Vec<Vec<String>>, Vec<String>, bool) =
        (Vec::new(), Vec::new(), true);
    let (mut lit_groups, mut lit_not): (Vec<Vec<String>>, Vec<String>) = (vec![], vec![]);
    let mut or_next = false;
    for t in terms(input) {
        if let Some(op) = &t.operator {
            let value = t.text.to_ascii_lowercase();
            let flag = Some(!t.negate);
            match (op.as_str(), value.as_str()) {
                ("has", "attachment" | "attachments") => s.has_attachment = flag,
                ("is", "purged" | "deleted") => s.purged = flag,
                ("is", "unread" | "new") => s.unread = flag,
                ("is", "read") => s.unread = Some(t.negate),
                ("category", c) if CATEGORIES.contains(&c) => {
                    s.category = Some((c.to_string(), !t.negate))
                }
                ("after", d) if !t.negate => s.after = date_prefix(d).or(s.after),
                ("before", d) if !t.negate => s.before = date_prefix(d).or(s.before),
                ("tag", _) if !t.text.trim().is_empty() => {
                    s.tags.push((t.text.trim().to_string(), !t.negate))
                }
                _ => {}
            }
            or_next = false;
            continue;
        }
        if !t.quoted && !t.negate && t.column.is_none() && t.text == "OR" {
            or_next = !groups.is_empty() || !lit_groups.is_empty();
            continue;
        }
        let folded = fold(&t.text);
        if folded.is_empty() {
            continue;
        }
        let col = t.column.or(column);
        // Envelope fallback: sender, recipients and subject are in it, body and files aren't.
        let in_envelope = !matches!(col, Some("body" | "attachments"));
        if !has_words(&folded) {
            if t.negate {
                lit_not.push(folded);
            } else if or_next && !lit_groups.is_empty() {
                lit_groups.last_mut().expect("checked").push(folded);
            } else {
                lit_groups.push(vec![folded]);
            }
            or_next = false;
            continue;
        }
        let mut term = literal(&folded);
        if !t.quoted {
            term.push('*');
        }
        if let Some(c) = col {
            term = format!("{c} : {term}");
        }
        if t.negate {
            not.push(term);
            if in_envelope {
                env_not.push(folded);
            }
        } else if or_next && !groups.is_empty() {
            groups
                .last_mut()
                .expect("checked")
                .push((term, in_envelope));
            if let Some(g) = env_groups.last_mut() {
                g.push(folded);
            }
        } else {
            groups.push(vec![(term, in_envelope)]);
            env_groups.push(vec![folded]);
        }
        or_next = false;
    }
    if !groups.is_empty() {
        let mut q = groups
            .iter()
            .map(|g| match g.len() {
                1 => g[0].0.clone(),
                _ => format!(
                    "({})",
                    g.iter()
                        .map(|x| x.0.as_str())
                        .collect::<Vec<_>>()
                        .join(" OR ")
                ),
            })
            .collect::<Vec<_>>()
            .join(" AND ");
        for n in not {
            q = format!("({q}) NOT {n}");
        }
        s.fts = Some(q);
        // A group the envelope can't answer for every alternative can't be checked there.
        env_ok = groups.iter().all(|g| g.iter().all(|x| x.1));
    }
    if env_ok {
        s.envelope = contains_spec(&env_groups, &env_not);
    }
    s.literal = contains_spec(&lit_groups, &lit_not);
    s
}

/// The FTS5 query of a search (see [`parse`]); None when no term has words.
pub fn query(input: &str) -> Option<String> {
    parse(input, None).fts
}

impl Index {
    /// Stores the searchable text of message `id`, unless its content changed meanwhile (or it
    /// was deleted). Returns whether it was stored.
    pub fn search_put(&self, id: i64, sha256: &str, doc: &SearchDoc) -> anyhow::Result<bool> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let current: Option<Option<String>> = tx
                .query_row("SELECT sha256 FROM messages WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .optional()?;
            if current.flatten().as_deref() != Some(sha256) {
                return Ok(false);
            }
            tx.execute("DELETE FROM search WHERE rowid=?1", [id])?;
            tx.execute(
                "INSERT INTO search(rowid, subject, sender, recipients, attachments, body)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    id,
                    doc.subject,
                    doc.sender,
                    doc.recipients,
                    doc.attachments,
                    doc.body
                ],
            )?;
            tx.execute(
                "UPDATE messages SET indexed_sha=?2, thread=?3 WHERE id=?1",
                params![id, sha256, doc.thread],
            )?;
            if let Some(m) = &doc.imap {
                tx.execute(
                    "INSERT OR REPLACE INTO imap_meta(sha256, header, envelope, bodystructure, body)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![sha256, m.header, m.envelope, m.bodystructure, m.body],
                )?;
            }
            tx.commit()?;
            Ok(true)
        })
    }

    /// Whether message `id` is indexed with content `sha256`.
    pub fn search_indexed(&self, id: i64, sha256: &str) -> anyhow::Result<bool> {
        self.with(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id=?1 AND indexed_sha=?2)
                   AND EXISTS(SELECT 1 FROM imap_meta WHERE sha256=?2)",
                params![id, sha256],
                |r| r.get(0),
            )
        })
    }

    /// Indexes a raw message (already hash-checked as `sha256`).
    pub fn search_index_raw(&self, id: i64, sha256: &str, raw: &[u8]) -> anyhow::Result<bool> {
        self.search_put(id, sha256, &extract(raw))
    }

    /// Messages with content that isn't indexed yet, newest first, below id `before`.
    pub fn search_pending(
        &self,
        account: Option<&str>,
        before: i64,
        limit: u32,
    ) -> anyhow::Result<Vec<(i64, String)>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT id, sha256 FROM messages
                 WHERE id<?2 AND (?1 IS NULL OR account=?1) AND sha256 IS NOT NULL
                   AND ({PENDING})
                 ORDER BY id DESC LIMIT ?3"
            ))?;
            let rows = stmt
                .query_map(params![account, before, limit], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect();
            rows
        })
    }

    /// How many messages with content aren't indexed yet.
    pub fn search_pending_count(&self, account: Option<&str>) -> anyhow::Result<u64> {
        self.with(|c| {
            c.query_row(
                &format!(
                    "SELECT COUNT(*) FROM messages WHERE (?1 IS NULL OR account=?1)
                       AND sha256 IS NOT NULL AND ({PENDING})"
                ),
                params![account],
                |r| r.get::<_, i64>(0),
            )
        })
        .map(|n| n as u64)
    }

    /// Ids of the messages matching an FTS5 query (see [`query`] and [`phrase`]), optionally
    /// limited to one column.
    pub fn search_ids(&self, expr: &str, column: Option<&str>) -> anyhow::Result<HashSet<i64>> {
        let expr = match column {
            Some(c) => format!("{c} : ({expr})"),
            None => expr.to_string(),
        };
        self.with(|c| {
            let mut stmt = c.prepare("SELECT rowid FROM search WHERE search MATCH ?1")?;
            let rows = stmt.query_map([&expr], |r| r.get(0))?.collect();
            rows
        })
    }

    /// Values for a search operator (`from`, `to` or `file`) containing `prefix`, most used
    /// first; with an empty prefix, the most used ones.
    pub fn search_suggest(
        &self,
        field: &str,
        prefix: &str,
        account: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<malo_api::SearchSuggestion>> {
        let spec: String = fold(prefix.trim())
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        let row = |r: &rusqlite::Row| {
            Ok(malo_api::SearchSuggestion {
                value: r.get(0)?,
                name: r.get(1)?,
                count: r.get::<_, i64>(2)? as u64,
            })
        };
        match field {
            "from" => self.with(|c| {
                let mut stmt = c.prepare(
                    "SELECT json_extract(envelope, '$.from'), max(json_extract(envelope, '$.from_name')), COUNT(*)
                     FROM messages
                     WHERE (?1 IS NULL OR account=?1) AND coalesce(json_extract(envelope, '$.from'), '')<>''
                       AND (?2='' OR malo_contains(coalesce(json_extract(envelope, '$.from_name'), '') || ' ' || json_extract(envelope, '$.from'), ?2))
                     GROUP BY lower(json_extract(envelope, '$.from')) ORDER BY 3 DESC, 1 LIMIT ?3",
                )?;
                let rows = stmt.query_map(params![account, spec, limit], row)?.collect();
                rows
            }),
            "to" => self.with(|c| {
                let mut stmt = c.prepare(
                    "SELECT j.value, NULL, COUNT(*) FROM messages g, json_each(g.envelope, '$.to') j
                     WHERE (?1 IS NULL OR g.account=?1) AND j.type='text' AND j.value<>''
                       AND (?2='' OR malo_contains(j.value, ?2))
                     GROUP BY lower(j.value) ORDER BY 3 DESC, 1 LIMIT ?3",
                )?;
                let rows = stmt.query_map(params![account, spec, limit], row)?.collect();
                rows
            }),
            "file" => {
                // Attachment names are only in the full-text index, one per line.
                let names: Vec<String> = self.with(|c| match phrase(prefix) {
                    Some(p) => {
                        let mut stmt = c.prepare(
                            "SELECT search.attachments FROM search JOIN messages g ON g.id=search.rowid
                             WHERE search MATCH ?1 AND (?2 IS NULL OR g.account=?2) LIMIT 1000",
                        )?;
                        let rows = stmt
                            .query_map(params![format!("attachments : {p}"), account], |r| r.get(0))?
                            .collect();
                        rows
                    }
                    None => {
                        let mut stmt = c.prepare(
                            "SELECT search.attachments FROM search JOIN messages g ON g.id=search.rowid
                             WHERE search.attachments<>'' AND (?1 IS NULL OR g.account=?1)
                             ORDER BY search.rowid DESC LIMIT 1000",
                        )?;
                        let rows = stmt.query_map(params![account], |r| r.get(0))?.collect();
                        rows
                    }
                })?;
                let mut counts: std::collections::HashMap<String, (String, u64)> =
                    std::collections::HashMap::new();
                for name in names.iter().flat_map(|n| n.lines()) {
                    let name = name.trim();
                    let key = fold(name);
                    if name.is_empty() || !key.contains(&spec) {
                        continue;
                    }
                    counts.entry(key).or_insert_with(|| (name.to_string(), 0)).1 += 1;
                }
                let mut v: Vec<_> = counts
                    .into_values()
                    .map(|(value, count)| malo_api::SearchSuggestion {
                        value,
                        name: None,
                        count,
                    })
                    .collect();
                v.sort_by(|a, b| b.count.cmp(&a.count).then(a.value.cmp(&b.value)));
                v.truncate(limit as usize);
                Ok(v)
            }
            _ => Ok(vec![]),
        }
    }

    /// Ids of an account's messages that have content but aren't indexed (yet).
    pub fn search_unindexed(&self, account: &str) -> anyhow::Result<HashSet<i64>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM messages WHERE account=?1 AND sha256 IS NOT NULL
                   AND indexed_sha IS NOT sha256",
            )?;
            let rows = stmt.query_map([account], |r| r.get(0))?.collect();
            rows
        })
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SearchIndexStats {
    pub indexed: u64,
    /// Messages whose content couldn't be read from the spool or any destination.
    pub unavailable: u64,
}

/// The search-index job: indexes the mail of every account that was backed up before it could be
/// indexed (or restored by an index rebuild), newest first.
pub async fn run_index(ctx: &JobCtx) -> anyhow::Result<SearchIndexStats> {
    let stores = ctx.stores()?;
    let total = ctx.index.search_pending_count(None)?;
    let mut stats = SearchIndexStats::default();
    let mut before = i64::MAX;
    ctx.progress(0, total, "indexing mail for search");
    loop {
        ctx.check_cancel()?;
        let batch = ctx.index.search_pending(None, before, 200)?;
        let Some(last) = batch.last() else { break };
        before = last.0;
        let mut loaded = futures::stream::iter(batch)
            .map(|(id, sha)| {
                let stores = &stores;
                async move {
                    let raw = load(ctx, id, &sha, stores).await;
                    (id, sha, raw)
                }
            })
            .buffer_unordered(CONCURRENCY);
        while let Some((id, sha, raw)) = loaded.next().await {
            ctx.check_cancel()?;
            let Some(raw) = raw else {
                stats.unavailable += 1;
                continue;
            };
            let doc = tokio::task::spawn_blocking(move || extract(&raw)).await?;
            if ctx.index.search_put(id, &sha, &doc)? {
                stats.indexed += 1;
            }
            let done = stats.indexed + stats.unavailable;
            if done % 50 == 0 {
                ctx.progress(
                    done,
                    total,
                    format!("indexing mail for search: {done} of {total}"),
                );
            }
        }
    }
    ctx.index
        .kv_set(UNAVAILABLE_KEY, &stats.unavailable.to_string())?;
    Ok(stats)
}

/// A message's content from Malo's own encrypted spool or viewer cache, else from a destination.
async fn load(
    ctx: &JobCtx,
    id: i64,
    sha256: &str,
    stores: &[crate::store::Store],
) -> Option<Vec<u8>> {
    let local = [ctx.spool_get(id), ctx.cache_get(id)]
        .into_iter()
        .flatten()
        .find(|raw| crypto::sha256_hex(raw) == sha256);
    if local.is_some() {
        return local;
    }
    let msg = ctx.index.message(id).ok().flatten()?;
    crate::sync::copy_from_replica(ctx, &msg, stores).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{empty_envelope, NewMessage};
    use malo_api::MessageState;

    const RAW: &[u8] = b"From: Alice Example <alice@example.com>\r\n\
To: Bob <bob@example.org>\r\n\
Subject: Quarterly Invoice\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Please pay the <b>caf\xc3\xa9</b> bill by Friday. Order #A-1234.</p>\r\n\
--b\r\n\
Content-Type: application/pdf; name=\"receipt-march.pdf\"\r\n\
Content-Disposition: attachment; filename=\"receipt-march.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERg==\r\n\
--b--\r\n";

    #[test]
    fn extracts_text() {
        let d = extract(RAW);
        assert_eq!(d.subject, "Quarterly Invoice");
        assert!(d.sender.contains("Alice Example") && d.sender.contains("alice@example.com"));
        assert!(d.recipients.contains("bob@example.org"));
        assert!(d.attachments.contains("receipt-march.pdf"));
        assert!(d.body.contains("café bill by Friday"), "{}", d.body);
        assert_eq!(extract(b"").subject, "");
        assert!(
            extract(b"").imap.is_some(),
            "mail apps can still list unparseable mail"
        );
        assert_eq!(d.thread, None, "no Message-ID, no References");
        let reply = extract(
            b"Message-ID: <c@x>\r\nIn-Reply-To: <B@x>\r\nReferences: <A@x> <B@x>\r\n\r\nhi\r\n",
        );
        assert_eq!(reply.thread.as_deref(), Some("a@x"));
        assert_eq!(
            extract(b"Message-ID: <Root@x>\r\n\r\nhi\r\n")
                .thread
                .as_deref(),
            Some("root@x")
        );
    }

    #[test]
    fn translates_queries() {
        assert_eq!(query("inv").as_deref(), Some("\"inv\"*"));
        assert_eq!(
            query("from:alice \"pay the\"").as_deref(),
            Some("sender : \"alice\"* AND \"pay the\"")
        );
        assert_eq!(
            query("invoice OR receipt -spam").as_deref(),
            Some("((\"invoice\"* OR \"receipt\"*)) NOT \"spam\"*")
        );
        assert_eq!(query("Über").as_deref(), Some("\"über\"*"));
        assert_eq!(query("a\"b").as_deref(), Some("\"a\"\"b\"*"));
        assert_eq!(query("weird:x").as_deref(), Some("\"weird:x\"*"));
        assert_eq!(query("  % & ").as_deref(), None);
        assert_eq!(query("-spam").as_deref(), None);
        assert_eq!(query("OR x").as_deref(), Some("\"x\"*"));
        assert_eq!(phrase(" Pay The ").as_deref(), Some("\"pay the\"*"));
        assert_eq!(phrase("%").as_deref(), None);
    }

    #[test]
    fn parses_operators() {
        let s = parse(
            "from:bob has:attachment after:2024-03 before:2025 is:purged -is:unread",
            None,
        );
        assert_eq!(s.fts.as_deref(), Some("sender : \"bob\"*"));
        assert_eq!(s.envelope.as_deref(), Some("bob"));
        assert_eq!(
            (s.has_attachment, s.purged, s.unread),
            (Some(true), Some(true), Some(false))
        );
        assert_eq!(
            (s.after.as_deref(), s.before.as_deref()),
            (Some("2024-03"), Some("2025"))
        );
        assert_eq!(parse("after:yesterday before:2024-1-1", None).after, None);
        assert_eq!(parse("before:2024-1-1", None).before, None);
        assert_eq!(parse("-has:attachment", None).has_attachment, Some(false));
        assert_eq!(parse("is:read", None).unread, Some(false));
        assert_eq!(parse("has:attachment", None).fts, None);
        // Only the index can answer body: and file:.
        assert_eq!(parse("body:x", None).envelope, None);
        assert_eq!(parse("x OR file:y", None).envelope, None);
        assert_eq!(
            parse("hello", Some("subject")).fts.as_deref(),
            Some("subject : \"hello\"*")
        );
        assert_eq!(
            parse("hello", Some("nonsense")).fts.as_deref(),
            Some("\"hello\"*")
        );
        let spec = parse("hel OR zzz -wor", None).envelope.unwrap();
        assert!(contains("help", &spec));
        assert!(!contains("hello world", &spec));
        assert!(!contains("nothing", &spec));
        let lit = parse("100% & ", None);
        assert_eq!(lit.literal.as_deref(), Some("&"));
    }

    #[test]
    fn filters_and_suggestions() {
        use crate::index::MessageQuery;
        let idx = Index::open_in_memory().unwrap();
        let mb = idx
            .upsert_mailbox("a", "INBOX", "INBOX", "INBOX", Some("/"), None, 1)
            .unwrap();
        let date = |s: &str| {
            Some(
                chrono::DateTime::parse_from_rfc3339(s)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            )
        };
        let mut ids = vec![];
        for (uid, from, name, files, when) in [
            (1, "alice@example.com", "Alice", 1, "2024-02-10T10:00:00Z"),
            (2, "alice@example.com", "Alice", 0, "2024-07-01T10:00:00Z"),
            (3, "albert@example.org", "Albert", 0, "2025-01-05T10:00:00Z"),
        ] {
            let mut env = empty_envelope();
            env.from = from.into();
            env.from_name = Some(name.into());
            env.to = vec!["me@example.net".into()];
            env.attachment_count = files;
            let id = idx
                .insert_message(&NewMessage {
                    account: "a",
                    run: None,
                    size: 1,
                    internaldate: date(when),
                    message_id_hdr: None,
                    gm_msgid: None,
                    envelope: &env,
                    state: MessageState::Verified,
                    sha256: None,
                })
                .unwrap();
            idx.add_membership(id, mb.id, uid, &[], &[]).unwrap();
            ids.push(id);
        }
        idx.mark_deleted_on_server(mb.id, &[3], true).unwrap();
        idx.set_reviewed(&[ids[0]], true).unwrap();
        let hits = |q: &str| {
            let mut v: Vec<i64> = idx
                .list_messages(
                    &MessageQuery {
                        text: Some(q.into()),
                        ..Default::default()
                    },
                    1,
                )
                .unwrap()
                .1
                .into_iter()
                .map(|m| m.id)
                .collect();
            v.sort();
            v
        };
        assert_eq!(hits("from:alice"), vec![ids[0], ids[1]]);
        assert_eq!(hits("has:attachment"), vec![ids[0]]);
        assert_eq!(hits("-has:attachment"), vec![ids[1], ids[2]]);
        assert_eq!(hits("after:2024-06 before:2025"), vec![ids[1]]);
        assert_eq!(hits("after:2024-07-01"), vec![ids[1], ids[2]]);
        assert_eq!(hits("is:purged"), vec![ids[2]]);
        assert_eq!(hits("is:unread from:al"), vec![ids[1], ids[2]]);
        assert_eq!(hits("alice -has:attachment"), vec![ids[1]]);
        idx.with(|c| {
            c.execute(
                "UPDATE messages SET category='social' WHERE id=?1",
                [ids[1]],
            )
        })
        .unwrap();
        assert_eq!(hits("category:social"), vec![ids[1]]);
        assert_eq!(hits("-category:social"), vec![ids[0], ids[2]]);
        assert_eq!(hits("category:primary"), vec![ids[0], ids[2]]);
        let in_category = |c: &str| {
            idx.list_messages(
                &MessageQuery {
                    category: Some(c.into()),
                    ..Default::default()
                },
                1,
            )
            .unwrap()
            .1
        };
        let social = in_category("social");
        assert_eq!(
            (social.len(), social[0].category.as_deref()),
            (1, Some("social"))
        );
        assert_eq!(in_category("primary").len(), 2);
        assert_eq!(
            in_category("bogus").len(),
            3,
            "an unknown category doesn't filter"
        );
        assert!(
            hits("body:alice").is_empty(),
            "not indexed: no body to search"
        );

        let taxes = idx.create_collection("Taxes 2025", true).unwrap().unwrap();
        let keep = idx.create_collection("keep", false).unwrap().unwrap();
        assert_eq!(
            idx.create_collection("KEEP", false).unwrap(),
            Err(crate::collections::CollectionError::NameTaken)
        );
        let (n, accounts) = idx
            .collection_members(&taxes.id, &[ids[0], ids[2], ids[0], 9999], true)
            .unwrap()
            .unwrap();
        assert_eq!((n, accounts), (2, vec!["a".to_string()]));
        idx.collection_members(&keep.id, &[ids[2]], true).unwrap();
        assert_eq!(hits("tag:\"taxes 2025\""), vec![ids[0], ids[2]]);
        assert_eq!(hits("collection:Keep"), vec![ids[2]]);
        assert_eq!(hits("tag:\"Taxes 2025\" -tag:keep"), vec![ids[0]]);
        assert_eq!(hits("tag:keep tag:\"Taxes 2025\""), vec![ids[2]]);
        assert_eq!(hits("-tag:keep"), vec![ids[0], ids[1]]);
        assert!(hits("tag:nothing").is_empty());
        assert_eq!(
            idx.collections_of(ids[2]).unwrap(),
            vec!["keep".to_string(), "Taxes 2025".to_string()]
        );
        let shown = idx
            .list_messages(
                &MessageQuery {
                    text: Some("tag:keep".into()),
                    ..Default::default()
                },
                1,
            )
            .unwrap()
            .1;
        assert_eq!(shown[0].collections.len(), 2);
        idx.collection_members(&taxes.id, &[ids[0]], false).unwrap();
        assert_eq!(hits("tag:\"taxes 2025\""), vec![ids[2]]);
        let (renamed, _) = idx
            .update_collection(&keep.id, "Kept", false)
            .unwrap()
            .unwrap();
        assert_eq!((renamed.name.as_str(), renamed.count), ("Kept", 1));
        assert!(hits("tag:keep").is_empty());
        assert_eq!(
            idx.delete_collection(&keep.id).unwrap(),
            Some(vec!["a".to_string()])
        );
        assert!(hits("tag:kept").is_empty());
        assert_eq!(hits("alice"), vec![ids[0], ids[1]], "messages stay");
        assert_eq!(
            idx.restore_collections(ids[1], &["New one".into(), "bad/name".into()])
                .unwrap(),
            1
        );
        assert_eq!(hits("tag:\"new one\""), vec![ids[1]]);

        let from = idx.search_suggest("from", "AL", Some("a"), 8).unwrap();
        assert_eq!(from[0].value, "alice@example.com");
        assert_eq!((from[0].name.as_deref(), from[0].count), (Some("Alice"), 2));
        assert_eq!(from[1].value, "albert@example.org");
        assert_eq!(
            idx.search_suggest("from", "bert", None, 8).unwrap().len(),
            1
        );
        assert!(idx
            .search_suggest("from", "x", Some("other"), 8)
            .unwrap()
            .is_empty());
        let to = idx.search_suggest("to", "", None, 8).unwrap();
        assert_eq!((to[0].value.as_str(), to[0].count), ("me@example.net", 3));
    }

    #[test]
    fn index_and_search() {
        let idx = Index::open_in_memory().unwrap();
        let env = empty_envelope();
        let id = idx
            .insert_message(&NewMessage {
                account: "a",
                run: None,
                size: RAW.len() as u64,
                internaldate: None,
                message_id_hdr: None,
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Verified,
                sha256: Some("s1"),
            })
            .unwrap();
        assert_eq!(idx.search_pending_count(Some("a")).unwrap(), 1);
        // A stale hash (the content changed meanwhile) isn't stored.
        assert!(!idx.search_index_raw(id, "other", RAW).unwrap());
        assert!(idx.search_index_raw(id, "s1", RAW).unwrap());
        assert_eq!(idx.search_pending_count(None).unwrap(), 0);
        // Mail apps' header data is stored with it; without it the message is pending again.
        let meta = idx.imap_meta("s1").unwrap().expect("IMAP header data");
        assert!(meta.envelope.starts_with(b"("));
        idx.with(|c| c.execute("DELETE FROM imap_meta", []))
            .unwrap();
        assert_eq!(idx.search_pending_count(None).unwrap(), 1);
        assert!(!idx.search_indexed(id, "s1").unwrap());
        assert!(idx.search_index_raw(id, "s1", RAW).unwrap());
        assert_eq!(idx.search_pending_count(None).unwrap(), 0);
        let hits = |q: &str| idx.search_ids(&query(q).unwrap(), None).unwrap();
        for q in [
            "invoice",
            "INV",
            "cafe",
            "café",
            "a-1234",
            "from:alice",
            "file:receipt",
            "\"pay the\"",
            "to:bob friday",
        ] {
            assert!(hits(q).contains(&id), "{q}");
        }
        for q in [
            "to:alice",
            "\"pay friday\"",
            "invoice -friday",
            "subject:friday",
        ] {
            assert!(hits(q).is_empty(), "{q}");
        }
        assert!(idx
            .search_ids(&phrase("bill by").unwrap(), Some("body"))
            .unwrap()
            .contains(&id));
        let files = idx.search_suggest("file", "rec", None, 8).unwrap();
        assert_eq!(files[0].value, "receipt-march.pdf");
        assert_eq!(idx.search_suggest("file", "", None, 8).unwrap().len(), 1);
        assert!(idx
            .search_suggest("file", "zzz", None, 8)
            .unwrap()
            .is_empty());
        // Its conversation: itself, plus a reply that references it.
        assert_eq!(idx.thread(id, 1).unwrap().len(), 1);
        let reply = idx
            .insert_message(&NewMessage {
                account: "a",
                run: None,
                size: 1,
                internaldate: None,
                message_id_hdr: Some("<r@x>"),
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Verified,
                sha256: Some("s2"),
            })
            .unwrap();
        let mut doc = extract(b"Message-ID: <r@x>\r\nIn-Reply-To: <t@x>\r\n\r\nok\r\n");
        assert_eq!(doc.thread.as_deref(), Some("t@x"));
        idx.search_put(
            id,
            "s1",
            &SearchDoc {
                thread: Some("t@x".into()),
                ..extract(RAW)
            },
        )
        .unwrap();
        doc.body = "ok".into();
        idx.search_put(reply, "s2", &doc).unwrap();
        let t = idx.thread(reply, 1).unwrap();
        assert_eq!(t.iter().map(|m| m.id).collect::<Vec<_>>(), vec![id, reply]);
        assert!(t.iter().all(|m| m.thread_size == 2));
        // Deleting the message deletes its text.
        idx.forget_messages(&[id, reply]).unwrap();
        assert!(hits("invoice").is_empty());
        let n: i64 = idx
            .with(|c| c.query_row("SELECT COUNT(*) FROM search", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(n, 0);
    }
}
