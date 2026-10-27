//! IMAP service: one account's backed-up mail per login, served from the index and the backups
//! (encrypted spool and viewer cache first, then verified replicas, each hash-checked).
//!
//! The archive is never changed from here. Flags and expunges only change the account's IMAP view
//! (see `malo_core::mailview`); moving to Trash hides a message from its folder. APPEND goes to
//! the account's own server (and comes back with the next backup); drafts aren't kept.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, NaiveDate, Utc};
use futures::StreamExt;
use malo_api::{JobKind, JobTrigger};
use malo_core::mailview::{Folder, FolderSource, ImapMeta, ViewMessage};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use super::mime::{self, istr, Kind, Part};
use super::{
    authenticate, read_line, Gone, LoginError, MailUser, LOGIN_DEADLINE, PREAUTH_COMMANDS,
};
use crate::keyring::UnlockedUser;
use crate::state::SharedState;

const CAPABILITIES: &str =
    "IMAP4rev1 LITERAL+ SASL-IR AUTH=PLAIN ID IDLE NAMESPACE MOVE SPECIAL-USE UNSELECT CHILDREN";
const MAX_LINE: usize = 64 * 1024;
/// How many messages a command reads at once (they may come from a remote destination).
const LOAD_CONCURRENCY: usize = 8;
/// Commands slower than this are logged even without tracing.
const SLOW: Duration = Duration::from_secs(10);
/// With tracing, how many responses of one command are logged (the tagged result always is).
const TRACE_RESPONSES: u32 = 5;

/// `MALO_MAIL_TRACE=1` logs each IMAP command (without passwords), the first lines Malo answers
/// with, how each command ended and how long it took: to see where a mail app gets stuck.
pub(crate) fn tracing_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("MALO_MAIL_TRACE").is_ok_and(|v| !v.is_empty() && v != "0" && v != "false")
    })
}

/// A command as the trace shows it: literals as their size, passwords left out.
fn describe(segs: &[Seg]) -> String {
    let first = match segs.first() {
        Some(Seg::Text(t)) => String::from_utf8_lossy(t).into_owned(),
        _ => String::new(),
    };
    let mut words = first.split_whitespace();
    let (tag, cmd) = (words.next().unwrap_or("*"), words.next().unwrap_or(""));
    let s = if cmd.eq_ignore_ascii_case("LOGIN") || cmd.eq_ignore_ascii_case("AUTHENTICATE") {
        format!("{tag} {} [credentials hidden]", cmd.to_ascii_uppercase())
    } else {
        segs.iter()
            .map(|s| match s {
                Seg::Text(t) => String::from_utf8_lossy(t).trim_end().to_string(),
                Seg::Literal(l) => format!("[{} bytes]", l.len()),
            })
            .collect::<Vec<_>>()
            .join("")
    };
    shorten(&s, 300)
}

fn shorten(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}
const MAX_LITERAL: usize = super::smtp::MAX_MESSAGE;
/// RFC 3501: at least 30 minutes for an authenticated client.
const AUTOLOGOUT: Duration = Duration::from_secs(31 * 60);
const PREAUTH_TIMEOUT: Duration = Duration::from_secs(60);
/// The size of a whole command before login; only LOGIN and AUTHENTICATE may carry literals.
const PREAUTH_MAX: usize = 8 * 1024;
/// Lines and literals of one command.
const MAX_SEGMENTS: usize = 64;
/// Parentheses nested in a command, and NOT/OR nested in a search.
const MAX_DEPTH: usize = 32;
/// LIST patterns (reference included).
const MAX_PATTERN: usize = 1024;
/// Patterns in one LIST (RFC 5258 allows a list of them); each is matched against every folder.
const MAX_PATTERNS: usize = 32;
/// Flags in one STORE or APPEND.
const MAX_FLAGS: usize = 64;
const IDLE_POLL: Duration = Duration::from_secs(20);

// ───────────────────────────── parsing ─────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Atom(String),
    Str(Vec<u8>),
    List(Vec<Tok>),
}

impl Tok {
    fn atom(&self) -> Option<&str> {
        match self {
            Tok::Atom(a) => Some(a),
            _ => None,
        }
    }

    /// An astring: atom, quoted string or literal.
    fn string(&self) -> Option<String> {
        match self {
            Tok::Atom(a) => Some(a.clone()),
            Tok::Str(s) => Some(String::from_utf8_lossy(s).into_owned()),
            Tok::List(_) => None,
        }
    }

    fn list(&self) -> Option<&[Tok]> {
        match self {
            Tok::List(l) => Some(l),
            _ => None,
        }
    }
}

enum Seg {
    Text(Vec<u8>),
    Literal(Vec<u8>),
}

/// Tokenizes a command; literals arrive as their own segments. None for a malformed command or
/// one nested deeper than [`MAX_DEPTH`].
fn tokenize(segs: Vec<Seg>) -> Option<Vec<Tok>> {
    let mut stack: Vec<Vec<Tok>> = vec![vec![]];
    for seg in segs {
        let text = match seg {
            Seg::Literal(l) => {
                stack.last_mut()?.push(Tok::Str(l));
                continue;
            }
            Seg::Text(t) => t,
        };
        let mut i = 0;
        while i < text.len() {
            match text[i] {
                b' ' | b'\r' | b'\n' => i += 1,
                b'(' => {
                    if stack.len() > MAX_DEPTH {
                        return None;
                    }
                    stack.push(vec![]);
                    i += 1;
                }
                b')' => {
                    let l = stack.pop()?;
                    stack.last_mut()?.push(Tok::List(l));
                    i += 1;
                }
                b'"' => {
                    let mut s = Vec::new();
                    i += 1;
                    loop {
                        match *text.get(i)? {
                            b'\\' => {
                                s.push(*text.get(i + 1)?);
                                i += 2;
                            }
                            b'"' => {
                                i += 1;
                                break;
                            }
                            c => {
                                s.push(c);
                                i += 1;
                            }
                        }
                    }
                    stack.last_mut()?.push(Tok::Str(s));
                }
                _ => {
                    let start = i;
                    let mut depth = 0;
                    while i < text.len() {
                        match text[i] {
                            b'[' => depth += 1,
                            b']' if depth > 0 => depth -= 1,
                            b' ' | b'(' | b')' | b'\r' | b'\n' if depth == 0 => break,
                            _ => {}
                        }
                        i += 1;
                    }
                    let atom = String::from_utf8_lossy(&text[start..i]).into_owned();
                    stack.last_mut()?.push(Tok::Atom(atom));
                }
            }
        }
    }
    (stack.len() == 1).then(|| stack.pop().unwrap())
}

/// `{123}` or `{123+}` at the end of a line: (size, synchronizing).
fn literal_marker(line: &[u8]) -> Option<(usize, bool)> {
    let line = line.strip_suffix(b"\n")?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let line = line.strip_suffix(b"}")?;
    let open = line.iter().rposition(|b| *b == b'{')?;
    let inner = &line[open + 1..];
    let (digits, sync) = match inner.strip_suffix(b"+") {
        Some(d) => (d, false),
        None => (inner, true),
    };
    let n = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((n, sync))
}

/// More ranges than any app sends (a 64 KB atom holds about 32,000); a set sent as a literal could
/// otherwise hold millions.
const MAX_SET_RANGES: usize = 50_000;

/// Sequence sets: `1:5,7,9:*`. `*` is `max`. Sorted, with overlapping and adjacent ranges merged,
/// so [`in_set`] is a binary search.
fn parse_set(s: &str, max: u32) -> Option<Vec<(u32, u32)>> {
    let mut ranges = s
        .split(',')
        .enumerate()
        .map(|(i, r)| {
            if i >= MAX_SET_RANGES {
                return None;
            }
            let num = |x: &str| -> Option<u32> {
                if x == "*" {
                    Some(max)
                } else {
                    x.parse().ok().filter(|n| *n > 0)
                }
            };
            let (a, b) = match r.split_once(':') {
                Some((a, b)) => (num(a)?, num(b)?),
                None => {
                    let n = num(r)?;
                    (n, n)
                }
            };
            Some((a.min(b), a.max(b)))
        })
        .collect::<Option<Vec<_>>>()?;
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (a, b) in ranges {
        match merged.last_mut() {
            Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    Some(merged)
}

/// `set` as [`parse_set`] returns it: sorted and merged.
fn in_set(set: &[(u32, u32)], n: u32) -> bool {
    let i = set.partition_point(|(_, b)| *b < n);
    set.get(i).is_some_and(|(a, _)| *a <= n)
}

#[derive(Debug, Clone, PartialEq)]
enum Spec {
    All,
    Header,
    Fields(Vec<String>, bool),
    Text,
    Mime,
}

#[derive(Debug, Clone, PartialEq)]
struct Section {
    peek: bool,
    path: Vec<u32>,
    spec: Spec,
    partial: Option<(usize, usize)>,
}

impl Section {
    fn label(&self) -> String {
        let mut s: Vec<String> = self.path.iter().map(|n| n.to_string()).collect();
        match &self.spec {
            Spec::All => {}
            Spec::Header => s.push("HEADER".into()),
            Spec::Text => s.push("TEXT".into()),
            Spec::Mime => s.push("MIME".into()),
            Spec::Fields(f, not) => s.push(format!(
                "HEADER.FIELDS{} ({})",
                if *not { ".NOT" } else { "" },
                f.join(" ")
            )),
        }
        let mut label = format!("BODY[{}]", s.join("."));
        if let Some((start, _)) = self.partial {
            label.push_str(&format!("<{start}>"));
        }
        label
    }

    /// Whether only the top-level header is needed (no download when its data is cached).
    fn header_only(&self) -> bool {
        self.path.is_empty() && matches!(self.spec, Spec::Header | Spec::Fields(..))
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Att {
    Uid,
    Flags,
    InternalDate,
    Size,
    Envelope,
    BodyStructure,
    Body,
    Section(Section),
    Rfc822,
    Rfc822Header,
    Rfc822Text,
}

fn parse_section(a: &str) -> Option<Section> {
    let upper = a.to_ascii_uppercase();
    let (name, rest) = upper.split_once('[')?;
    let peek = match name {
        "BODY" => false,
        "BODY.PEEK" => true,
        _ => return None,
    };
    let close = rest.rfind(']')?;
    let (inner, after) = (&rest[..close], &rest[close + 1..]);
    // Field names keep the client's spelling inside the list; the rest is case-insensitive.
    let orig_inner = &a[name.len() + 1..name.len() + 1 + close];
    let mut path = Vec::new();
    let mut spec_start = 0;
    for part in inner.split('.') {
        match part.parse::<u32>() {
            Ok(n) if n > 0 => {
                path.push(n);
                spec_start += part.len() + 1;
            }
            _ => break,
        }
    }
    let spec_start = spec_start.min(inner.len());
    let spec_text = &inner[spec_start..];
    let spec = if spec_text.is_empty() {
        Spec::All
    } else if spec_text == "HEADER" {
        Spec::Header
    } else if spec_text == "TEXT" {
        Spec::Text
    } else if spec_text == "MIME" {
        if path.is_empty() {
            return None;
        }
        Spec::Mime
    } else if let Some(list) = spec_text
        .strip_prefix("HEADER.FIELDS.NOT")
        .map(|l| (l, true))
        .or_else(|| spec_text.strip_prefix("HEADER.FIELDS").map(|l| (l, false)))
    {
        let (_, not) = list;
        let orig = orig_inner.get(spec_start..)?;
        let open = orig.find('(')?;
        let close = orig.rfind(')')?;
        let names = orig
            .get(open + 1..close)?
            .split_whitespace()
            .map(|n| n.trim_matches('"').to_ascii_uppercase())
            .collect();
        Spec::Fields(names, not)
    } else {
        return None;
    };
    let partial = match after.strip_prefix('<').and_then(|p| p.strip_suffix('>')) {
        Some(p) => {
            let (s, l) = p.split_once('.')?;
            Some((s.parse().ok()?, l.parse().ok()?))
        }
        None if after.is_empty() => None,
        None => return None,
    };
    Some(Section {
        peek,
        path,
        spec,
        partial,
    })
}

fn parse_att(t: &Tok) -> Option<Vec<Att>> {
    let a = t.atom()?;
    let up = a.to_ascii_uppercase();
    Some(match up.as_str() {
        "ALL" => vec![Att::Flags, Att::InternalDate, Att::Size, Att::Envelope],
        "FAST" => vec![Att::Flags, Att::InternalDate, Att::Size],
        "FULL" => vec![
            Att::Flags,
            Att::InternalDate,
            Att::Size,
            Att::Envelope,
            Att::Body,
        ],
        "UID" => vec![Att::Uid],
        "FLAGS" => vec![Att::Flags],
        "INTERNALDATE" => vec![Att::InternalDate],
        "RFC822.SIZE" => vec![Att::Size],
        "ENVELOPE" => vec![Att::Envelope],
        "BODYSTRUCTURE" => vec![Att::BodyStructure],
        "BODY" => vec![Att::Body],
        "RFC822" => vec![Att::Rfc822],
        "RFC822.HEADER" => vec![Att::Rfc822Header],
        "RFC822.TEXT" => vec![Att::Rfc822Text],
        // CONDSTORE isn't offered; ignore what some clients ask anyway.
        "MODSEQ" | "X-GM-MSGID" | "X-GM-THRID" | "X-GM-LABELS" => vec![],
        _ => vec![Att::Section(parse_section(a)?)],
    })
}

fn parse_atts(t: &Tok) -> Option<Vec<Att>> {
    match t {
        Tok::List(l) => {
            let mut out = vec![];
            for x in l {
                out.extend(parse_att(x)?);
            }
            Some(out)
        }
        t => parse_att(t),
    }
}

#[derive(Debug, Clone)]
enum Key {
    All,
    Seq(Vec<(u32, u32)>),
    Uid(Vec<(u32, u32)>),
    Flag(String, bool),
    Larger(u64),
    Smaller(u64),
    Before(NaiveDate),
    On(NaiveDate),
    Since(NaiveDate),
    SentBefore(NaiveDate),
    SentOn(NaiveDate),
    SentSince(NaiveDate),
    Header(String, String),
    Body(String),
    Text(String),
    Not(Box<Key>),
    Or(Box<Key>, Box<Key>),
    And(Vec<Key>),
    None,
}

fn search_date(t: Option<&Tok>) -> Option<NaiveDate> {
    let s = t?.string()?;
    NaiveDate::parse_from_str(s.trim_matches('"'), "%d-%b-%Y").ok()
}

/// One search key from the front of `toks`. Lists, NOT and OR nest at most [`MAX_DEPTH`] deep, which
/// also bounds the recursion of everything that walks a [`Key`].
fn parse_key(
    toks: &mut std::iter::Peekable<std::slice::Iter<Tok>>,
    max_seq: u32,
    max_uid: u32,
    depth: usize,
) -> Option<Key> {
    if depth > MAX_DEPTH {
        return None;
    }
    let t = toks.next()?;
    if let Tok::List(l) = t {
        let mut it = l.iter().peekable();
        let mut keys = vec![];
        while it.peek().is_some() {
            keys.push(parse_key(&mut it, max_seq, max_uid, depth + 1)?);
        }
        return Some(Key::And(keys));
    }
    let word = t.string()?;
    let up = word.to_ascii_uppercase();
    let mut arg = || toks.next().and_then(|t| t.string());
    let flag = |f: &str, has: bool| Some(Key::Flag(f.into(), has));
    match up.as_str() {
        "ALL" => Some(Key::All),
        "ANSWERED" => flag("\\Answered", true),
        "UNANSWERED" => flag("\\Answered", false),
        "DELETED" => flag("\\Deleted", true),
        "UNDELETED" => flag("\\Deleted", false),
        "DRAFT" => flag("\\Draft", true),
        "UNDRAFT" => flag("\\Draft", false),
        "FLAGGED" => flag("\\Flagged", true),
        "UNFLAGGED" => flag("\\Flagged", false),
        "SEEN" | "OLD" => flag("\\Seen", true),
        "UNSEEN" => flag("\\Seen", false),
        "RECENT" | "NEW" => Some(Key::None),
        "KEYWORD" => Some(Key::Flag(arg()?, true)),
        "UNKEYWORD" => Some(Key::Flag(arg()?, false)),
        "LARGER" => Some(Key::Larger(arg()?.parse().ok()?)),
        "SMALLER" => Some(Key::Smaller(arg()?.parse().ok()?)),
        "BEFORE" => Some(Key::Before(search_date(toks.next())?)),
        "ON" => Some(Key::On(search_date(toks.next())?)),
        "SINCE" => Some(Key::Since(search_date(toks.next())?)),
        "SENTBEFORE" => Some(Key::SentBefore(search_date(toks.next())?)),
        "SENTON" => Some(Key::SentOn(search_date(toks.next())?)),
        "SENTSINCE" => Some(Key::SentSince(search_date(toks.next())?)),
        "FROM" | "TO" | "CC" | "BCC" | "SUBJECT" => Some(Key::Header(up.clone(), arg()?)),
        "HEADER" => {
            let name = arg()?;
            Some(Key::Header(name.to_ascii_uppercase(), arg()?))
        }
        "BODY" => Some(Key::Body(arg()?)),
        "TEXT" => Some(Key::Text(arg()?)),
        "UID" => Some(Key::Uid(parse_set(&arg()?, max_uid)?)),
        "NOT" => Some(Key::Not(Box::new(parse_key(
            toks,
            max_seq,
            max_uid,
            depth + 1,
        )?))),
        "OR" => {
            let a = parse_key(toks, max_seq, max_uid, depth + 1)?;
            let b = parse_key(toks, max_seq, max_uid, depth + 1)?;
            Some(Key::Or(Box::new(a), Box::new(b)))
        }
        _ => Some(Key::Seq(parse_set(&word, max_seq)?)),
    }
}

impl Key {
    fn needs_header(&self) -> bool {
        match self {
            Key::Header(..) | Key::SentBefore(_) | Key::SentOn(_) | Key::SentSince(_) => true,
            Key::Not(k) => k.needs_header(),
            Key::Or(a, b) => a.needs_header() || b.needs_header(),
            Key::And(v) => v.iter().any(Key::needs_header),
            _ => false,
        }
    }

    /// The `BODY` (true) and `TEXT` (false) strings searched for.
    fn text_keys<'a>(&'a self, out: &mut Vec<(bool, &'a str)>) {
        match self {
            Key::Body(s) => out.push((true, s)),
            Key::Text(s) => out.push((false, s)),
            Key::Not(k) => k.text_keys(out),
            Key::Or(a, b) => {
                a.text_keys(out);
                b.text_keys(out);
            }
            Key::And(v) => v.iter().for_each(|k| k.text_keys(out)),
            _ => {}
        }
    }
}

fn contains_ci(hay: &[u8], needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let hay = String::from_utf8_lossy(hay).to_lowercase();
    hay.contains(&needle.to_lowercase())
}

/// Messages matching each `BODY`/`TEXT` string in the full-text index; None for a string the
/// index can't look up (no words in it).
type FullText = HashMap<(bool, String), Option<HashSet<i64>>>;

struct SearchItem<'a> {
    seq: u32,
    msg: &'a ViewMessage,
    header: Option<&'a [u8]>,
    raw: Option<&'a [u8]>,
    /// The message is in the full-text index: `full_text` answers BODY and TEXT for it.
    indexed: bool,
    full_text: &'a FullText,
}

/// A `BODY`/`TEXT` match: the full-text index (words, accents and HTML markup ignored) for an
/// indexed message, else a substring of the raw message.
fn text_match(it: &SearchItem, body: bool, s: &str) -> bool {
    if it.indexed {
        if let Some(Some(hits)) = it.full_text.get(&(body, s.to_string())) {
            return hits.contains(&it.msg.message);
        }
    }
    it.raw.is_some_and(|r| {
        let hay = if body { mime::split(r).1 } else { r };
        contains_ci(hay, s)
    })
}

fn sent_date(header: Option<&[u8]>) -> Option<NaiveDate> {
    let f = mime::fields(header?);
    let v = String::from_utf8_lossy(mime::field(&f, "date")?).to_string();
    // Drop a trailing comment such as "(UTC)".
    let v = v.split('(').next().unwrap_or("").trim().to_string();
    DateTime::parse_from_rfc2822(&v)
        .ok()
        .map(|d| d.date_naive())
}

fn matches(k: &Key, it: &SearchItem) -> bool {
    let day = it.msg.internaldate.map(|d| d.date_naive());
    match k {
        Key::All => true,
        Key::None => false,
        Key::Seq(s) => in_set(s, it.seq),
        Key::Uid(s) => in_set(s, it.msg.uid),
        Key::Flag(f, has) => it.msg.flags.iter().any(|x| x.eq_ignore_ascii_case(f)) == *has,
        Key::Larger(n) => it.msg.size > *n,
        Key::Smaller(n) => it.msg.size < *n,
        Key::Before(d) => day.is_some_and(|x| x < *d),
        Key::On(d) => day == Some(*d),
        Key::Since(d) => day.is_some_and(|x| x >= *d),
        Key::SentBefore(d) => sent_date(it.header).or(day).is_some_and(|x| x < *d),
        Key::SentOn(d) => sent_date(it.header).or(day) == Some(*d),
        Key::SentSince(d) => sent_date(it.header).or(day).is_some_and(|x| x >= *d),
        Key::Header(name, value) => {
            let Some(h) = it.header else { return false };
            mime::fields(h)
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .any(|(_, v)| {
                    contains_ci(v, value)
                        || contains_ci(malo_core::imap::decode_words(v).as_bytes(), value)
                })
        }
        Key::Body(s) => text_match(it, true, s),
        Key::Text(s) => text_match(it, false, s),
        Key::Not(k) => !matches(k, it),
        Key::Or(a, b) => matches(a, it) || matches(b, it),
        Key::And(v) => v.iter().all(|k| matches(k, it)),
    }
}

/// `LIST` patterns: `*` matches anything, `%` anything but the delimiter. Matched row by row
/// (pattern length × name length), so no pattern can make it backtrack.
fn wildcard(pattern: &[u8], name: &[u8], delim: Option<u8>) -> bool {
    // row[j]: the pattern so far matches the first j bytes of the name.
    let mut row = vec![false; name.len() + 1];
    row[0] = true;
    let mut next = vec![false; name.len() + 1];
    for &p in pattern {
        match p {
            b'*' | b'%' => {
                next[0] = row[0];
                for j in 1..=name.len() {
                    let extend = next[j - 1] && (p == b'*' || Some(name[j - 1]) != delim);
                    next[j] = row[j] || extend;
                }
            }
            c => {
                next[0] = false;
                for j in 1..=name.len() {
                    next[j] = row[j - 1] && name[j - 1] == c;
                }
            }
        }
        std::mem::swap(&mut row, &mut next);
    }
    row[name.len()]
}

fn is_inbox(name: &str) -> bool {
    name.eq_ignore_ascii_case("INBOX")
}

fn imap_date(d: Option<DateTime<Utc>>) -> String {
    d.unwrap_or(DateTime::UNIX_EPOCH)
        .format("%d-%b-%Y %H:%M:%S +0000")
        .to_string()
}

/// A flag as RFC 3501 has it: `\Seen` and other system flags, or a keyword atom. Anything else
/// (spaces, CR/LF, quotes, parentheses) would break the responses that list flags, or the
/// command that APPEND sends upstream.
fn valid_flag(f: &str) -> bool {
    let atom = f.strip_prefix('\\').unwrap_or(f);
    !atom.is_empty()
        && f.len() <= 64
        && atom
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"(){%*\"\\]".contains(&b))
}

/// The flags of a STORE or APPEND, without `\Recent`; None if one isn't a valid flag or there
/// are too many.
fn given_flags<'a>(toks: impl IntoIterator<Item = &'a Tok>) -> Option<Vec<String>> {
    let mut out = vec![];
    for t in toks {
        let f = t.string()?;
        if !valid_flag(&f) || out.len() >= MAX_FLAGS {
            return None;
        }
        if !f.eq_ignore_ascii_case("\\Recent") {
            out.push(f);
        }
    }
    Some(out)
}

/// An APPEND date-time: `"dd-Mon-yyyy hh:mm:ss +zzzz"` (the day may be space-padded).
fn append_date(s: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(s).ok()?;
    // Two characters for the day; some clients leave out the padding of a single digit.
    let padded = match s.len() {
        26 => true,
        25 => !s.starts_with(' '),
        _ => false,
    };
    if !padded {
        return None;
    }
    DateTime::parse_from_str(s.trim_start(), "%d-%b-%Y %H:%M:%S %z").ok()?;
    Some(s.to_string())
}

fn flag_list(flags: &[String]) -> String {
    let v: Vec<&str> = flags
        .iter()
        .map(String::as_str)
        .filter(|f| !f.eq_ignore_ascii_case("\\Recent"))
        .collect();
    format!("({})", v.join(" "))
}

/// The bytes of a section of a message.
fn section_bytes(raw: &[u8], s: &Section) -> Vec<u8> {
    let root = mime::parse(raw);
    let node: &Part = if s.path.is_empty() {
        &root
    } else {
        match mime::resolve(&root, &s.path) {
            Some(n) => n,
            None => return vec![],
        }
    };
    // HEADER/TEXT of a part address its encapsulated message.
    let message = |n: &'_ Part<'_>| -> Option<(Vec<u8>, Vec<u8>)> {
        if s.path.is_empty() {
            return Some((n.header.to_vec(), n.body.to_vec()));
        }
        match &n.kind {
            Kind::Message(inner) => Some((inner.header.to_vec(), inner.body.to_vec())),
            _ => None,
        }
    };
    match &s.spec {
        Spec::All if s.path.is_empty() => raw.to_vec(),
        Spec::All => node.body.to_vec(),
        Spec::Mime => node.header.to_vec(),
        Spec::Header => message(node).map(|m| m.0).unwrap_or_default(),
        Spec::Text => message(node).map(|m| m.1).unwrap_or_default(),
        Spec::Fields(names, not) => message(node)
            .map(|m| mime::header_fields(&m.0, names, *not))
            .unwrap_or_default(),
    }
}

fn partial(bytes: Vec<u8>, p: Option<(usize, usize)>) -> Vec<u8> {
    match p {
        Some((start, len)) => bytes
            .get(start.min(bytes.len())..start.saturating_add(len).min(bytes.len()))
            .unwrap_or_default()
            .to_vec(),
        None => bytes,
    }
}

// ───────────────────────────── session ─────────────────────────────

struct Selected {
    folder: Folder,
    readonly: bool,
    uidvalidity: u32,
    uidnext: u32,
    msgs: Vec<ViewMessage>,
}

struct Session<S> {
    io: BufReader<S>,
    /// Whether to send the greeting (not after STARTTLS).
    greet: bool,
    state: SharedState,
    ip: IpAddr,
    user: Option<MailUser>,
    sel: Option<Selected>,
    failed_logins: u32,
    /// When the connection opened, and commands read before login.
    opened: std::time::Instant,
    commands: u32,
    /// Connection number in the trace (see [`tracing_on`]).
    trace: Option<u64>,
    /// The command being answered, and what has been sent for it.
    current: Option<String>,
    responses: u32,
    sent: usize,
}

/// What a command handler wants next.
enum Flow {
    Continue,
    Close,
}

type CmdResult = anyhow::Result<Flow>;

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.responses += 1;
        self.sent += data.len();
        if let Some(n) = self.trace {
            self.trace_sent(n, data);
        }
        let w = self.io.get_mut();
        w.write_all(data).await?;
        w.flush().await
    }

    /// Logs what was sent: each line, or just the first of a response carrying message data.
    fn trace_sent(&self, n: u64, data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        let has_literal = text.contains("}\r\n");
        let lines: Vec<&str> = text.trim_end_matches("\r\n").split("\r\n").collect();
        let shown = if has_literal { &lines[..1] } else { &lines[..] };
        for (i, l) in shown.iter().enumerate() {
            let tagged = self
                .current
                .as_deref()
                .is_some_and(|t| l.strip_prefix(t).is_some_and(|r| r.starts_with(' ')));
            if !tagged && self.responses > TRACE_RESPONSES {
                continue;
            }
            let more = if has_literal && i == 0 && data.len() > l.len() + 2 {
                format!(" (+{} bytes)", data.len() - l.len() - 2)
            } else {
                String::new()
            };
            tracing::info!("IMAP #{n} S: {}{more}", shorten(l, 300));
        }
    }

    async fn line(&mut self, s: &str) -> std::io::Result<()> {
        self.send(format!("{s}\r\n").as_bytes()).await
    }

    /// Reads one command with its literals. Ok(None) at end of stream or timeout, or for a command
    /// that can't be skipped.
    async fn read_command(&mut self) -> anyhow::Result<Option<Vec<Seg>>> {
        let authed = self.user.is_some();
        if !authed {
            if self.commands >= PREAUTH_COMMANDS {
                self.line("* BYE Too many commands without logging in")
                    .await?;
                return Ok(None);
            }
            self.commands += 1;
        }
        // Worked out again for every line and literal: before login, NOOPs and a command trickled
        // out one literal at a time don't keep a connection that never logs in open.
        let opened = self.opened;
        let timeout = || {
            if authed {
                AUTOLOGOUT
            } else {
                PREAUTH_TIMEOUT.min(LOGIN_DEADLINE.saturating_sub(opened.elapsed()))
            }
        };
        let (max_line, max_total) = if authed {
            (MAX_LINE, MAX_LITERAL)
        } else {
            (PREAUTH_MAX, PREAUTH_MAX)
        };
        let mut segs = vec![];
        let mut total = 0usize;
        loop {
            let wait = timeout();
            let line = match tokio::time::timeout(wait, read_line(&mut self.io, max_line)).await {
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                    self.line("* BYE Command line too long").await?;
                    return Ok(None);
                }
                Ok(l) => l?,
                Err(_) => {
                    if let Some(n) = self.trace {
                        tracing::info!("IMAP #{n}: no command for {wait:?}, logging out");
                    }
                    let _ = self.line("* BYE Autologout; idle for too long").await;
                    return Ok(None);
                }
            };
            let Some(line) = line else {
                if let Some(n) = self.trace {
                    tracing::info!("IMAP #{n}: the app closed the connection");
                }
                return Ok(None);
            };
            total = total.saturating_add(line.len());
            if segs.len() + 2 > MAX_SEGMENTS || total > max_total {
                // The rest of the command can't be told apart from the next one.
                self.line("* BYE Command too long").await?;
                return Ok(None);
            }
            match literal_marker(&line) {
                Some((n, sync)) => {
                    let mut text = line;
                    let open = text.iter().rposition(|b| *b == b'{').unwrap();
                    text.truncate(open);
                    let refused = if !authed && !literal_allowed(&segs, &text) {
                        Some("BAD Log in first")
                    } else if total.checked_add(n).is_none_or(|t| t > max_total) {
                        Some("NO [TOOBIG] Message too large")
                    } else {
                        None
                    };
                    if let Some(why) = refused {
                        let tag = String::from_utf8_lossy(&segs_tag(&segs, &text)).to_string();
                        if sync {
                            self.line(&format!("{tag} {why}")).await?;
                            return Ok(Some(vec![]));
                        }
                        self.line("* BYE Literal too large").await?;
                        return Ok(None);
                    }
                    total += n;
                    segs.push(Seg::Text(text));
                    if sync {
                        self.line("+ Ready for literal data").await?;
                    }
                    // Memory grows with the data that actually arrives, not with the size announced.
                    let mut lit = Vec::with_capacity(n.min(64 * 1024));
                    let mut src = (&mut self.io).take(n as u64);
                    tokio::time::timeout(timeout(), src.read_to_end(&mut lit))
                        .await
                        .map_err(|_| anyhow::anyhow!("timeout reading a literal"))??;
                    if lit.len() < n {
                        return Ok(None);
                    }
                    segs.push(Seg::Literal(lit));
                }
                None => {
                    segs.push(Seg::Text(line));
                    return Ok(Some(segs));
                }
            }
        }
    }

    /// The unlocked user for one step; a session that lost it says BYE.
    async fn unlocked(&mut self) -> anyhow::Result<Result<Arc<UnlockedUser>, ()>> {
        let Some(u) = &self.user else {
            return Ok(Err(()));
        };
        match u.unlocked(&self.state) {
            Ok(user) => Ok(Ok(user)),
            Err(g) => {
                self.line(&format!("* BYE {}", g.message())).await?;
                Ok(Err(()))
            }
        }
    }

    fn account_id(&self) -> String {
        self.user
            .as_ref()
            .map(|u| u.account_id.clone())
            .unwrap_or_default()
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        // Not again after STARTTLS: the client goes on with its next command.
        if self.greet {
            self.line(&format!("* OK [CAPABILITY {CAPABILITIES}] Malo IMAP ready"))
                .await?;
        }
        while let Some(segs) = self.read_command().await? {
            if segs.is_empty() {
                continue;
            }
            let traced = self.trace.map(|n| (n, describe(&segs)));
            let Some(toks) = tokenize(segs) else {
                self.line("* BAD Malformed command").await?;
                continue;
            };
            let Some(tag) = toks.first().and_then(Tok::atom).map(str::to_string) else {
                self.line("* BAD Missing tag").await?;
                continue;
            };
            let Some(cmd) = toks.get(1).and_then(Tok::atom).map(str::to_ascii_uppercase) else {
                self.line(&format!("{tag} BAD Missing command")).await?;
                continue;
            };
            let args = &toks[2..];
            if let Some((n, text)) = traced {
                tracing::info!("IMAP #{n} C: {text}");
            }
            self.current = Some(tag.clone());
            (self.responses, self.sent) = (0, 0);
            let started = std::time::Instant::now();
            let result = self.dispatch(&tag, &cmd, args).await;
            let took = started.elapsed();
            if (took > SLOW && cmd != "IDLE") || self.trace.is_some() {
                let what = if cmd == "UID" {
                    let sub = args.first().and_then(Tok::atom).unwrap_or_default();
                    format!("UID {}", sub.to_ascii_uppercase())
                } else {
                    cmd.clone()
                };
                tracing::info!(
                    "IMAP{} {what} took {:.1}s: {} responses, {} bytes",
                    self.trace.map(|n| format!(" #{n}")).unwrap_or_default(),
                    took.as_secs_f64(),
                    self.responses,
                    self.sent,
                );
            }
            self.current = None;
            let flow = match result {
                Ok(f) => f,
                Err(e) => {
                    if self.trace.is_some() {
                        tracing::info!("IMAP {cmd} failed: {e:#}");
                    } else {
                        tracing::debug!("IMAP {cmd} failed: {e:#}");
                    }
                    let msg = format!("{e:#}").replace(['\r', '\n'], " ");
                    self.line(&format!("{tag} NO {msg}")).await?;
                    Flow::Continue
                }
            };
            if let Flow::Close = flow {
                break;
            }
        }
        Ok(())
    }

    async fn dispatch(&mut self, tag: &str, cmd: &str, args: &[Tok]) -> CmdResult {
        match cmd {
            "CAPABILITY" => {
                self.line(&format!("* CAPABILITY {CAPABILITIES}")).await?;
                self.line(&format!("{tag} OK CAPABILITY completed")).await?;
                return Ok(Flow::Continue);
            }
            "NOOP" if self.user.is_none() => {
                self.line(&format!("{tag} OK NOOP completed")).await?;
                return Ok(Flow::Continue);
            }
            "LOGOUT" => {
                self.line("* BYE Logging out").await?;
                self.line(&format!("{tag} OK LOGOUT completed")).await?;
                return Ok(Flow::Close);
            }
            "ID" => {
                self.line("* ID (\"name\" \"Malo\")").await?;
                self.line(&format!("{tag} OK ID completed")).await?;
                return Ok(Flow::Continue);
            }
            "STARTTLS" => {
                self.line(&format!("{tag} BAD Already using TLS")).await?;
                return Ok(Flow::Continue);
            }
            "LOGIN" | "AUTHENTICATE" if self.user.is_some() => {
                self.line(&format!("{tag} BAD Already authenticated"))
                    .await?;
                return Ok(Flow::Continue);
            }
            "LOGIN" => {
                let (Some(u), Some(p)) = (
                    args.first().and_then(Tok::string),
                    args.get(1).and_then(Tok::string),
                ) else {
                    self.line(&format!("{tag} BAD LOGIN needs a username and password"))
                        .await?;
                    return Ok(Flow::Continue);
                };
                return self.login(tag, &u, &p).await;
            }
            "AUTHENTICATE" => return self.authenticate_plain(tag, args).await,
            _ => {}
        }
        if self.user.is_none() {
            self.line(&format!("{tag} BAD Log in first")).await?;
            return Ok(Flow::Continue);
        }
        let Ok(user) = self.unlocked().await? else {
            return Ok(Flow::Close);
        };
        match cmd {
            "NAMESPACE" => {
                self.line("* NAMESPACE ((\"\" \"/\")) NIL NIL").await?;
                self.ok(tag, "NAMESPACE").await
            }
            "ENABLE" => {
                self.line("* ENABLED").await?;
                self.ok(tag, "ENABLE").await
            }
            "LIST" | "LSUB" | "XLIST" => self.list(tag, cmd, args, &user).await,
            "STATUS" => self.status(tag, args, &user).await,
            "SELECT" | "EXAMINE" => self.select(tag, args, cmd == "EXAMINE", &user).await,
            "CREATE" | "DELETE" | "RENAME" => {
                self.line(&format!(
                    "{tag} NO [CANNOT] Malo serves a read-only backup; folders can't be changed here"
                ))
                .await?;
                Ok(Flow::Continue)
            }
            "SUBSCRIBE" | "UNSUBSCRIBE" => self.ok(tag, cmd).await,
            "APPEND" => {
                drop(user);
                self.append(tag, args).await
            }
            "NOOP" | "CHECK" => {
                self.refresh(&user).await?;
                self.ok(tag, cmd).await
            }
            "IDLE" => {
                drop(user);
                self.idle(tag).await
            }
            _ if self.sel.is_none() => {
                self.line(&format!("{tag} BAD No mailbox selected")).await?;
                Ok(Flow::Continue)
            }
            "CLOSE" => {
                self.expunge(&user, None, true).await?;
                self.sel = None;
                self.ok(tag, "CLOSE").await
            }
            "UNSELECT" => {
                self.sel = None;
                self.ok(tag, "UNSELECT").await
            }
            "EXPUNGE" => {
                if self.sel.as_ref().is_some_and(|s| s.readonly) {
                    return self.readonly(tag).await;
                }
                self.expunge(&user, None, false).await?;
                self.ok(tag, "EXPUNGE").await
            }
            "FETCH" => self.fetch(tag, args, false, &user).await,
            "STORE" => self.store(tag, args, false, &user).await,
            "SEARCH" => self.search(tag, args, false, &user).await,
            "COPY" | "MOVE" => self.copy(tag, args, false, cmd == "MOVE", &user).await,
            "UID" => {
                let sub = args
                    .first()
                    .and_then(Tok::atom)
                    .map(str::to_ascii_uppercase)
                    .unwrap_or_default();
                let rest = args.get(1..).unwrap_or_default();
                match sub.as_str() {
                    "FETCH" => self.fetch(tag, rest, true, &user).await,
                    "STORE" => self.store(tag, rest, true, &user).await,
                    "SEARCH" => self.search(tag, rest, true, &user).await,
                    "COPY" | "MOVE" => self.copy(tag, rest, true, sub == "MOVE", &user).await,
                    "EXPUNGE" => {
                        if self.sel.as_ref().is_some_and(|s| s.readonly) {
                            return self.readonly(tag).await;
                        }
                        let max = self.max_uid();
                        let Some(set) = rest
                            .first()
                            .and_then(Tok::atom)
                            .and_then(|s| parse_set(s, max))
                        else {
                            return self.bad(tag, "UID EXPUNGE needs a UID set").await;
                        };
                        self.expunge(&user, Some(&set), false).await?;
                        self.ok(tag, "UID EXPUNGE").await
                    }
                    _ => self.bad(tag, "Unknown UID command").await,
                }
            }
            _ => self.bad(tag, "Unknown command").await,
        }
    }

    async fn ok(&mut self, tag: &str, what: &str) -> CmdResult {
        self.line(&format!("{tag} OK {what} completed")).await?;
        Ok(Flow::Continue)
    }

    async fn bad(&mut self, tag: &str, msg: &str) -> CmdResult {
        self.line(&format!("{tag} BAD {msg}")).await?;
        Ok(Flow::Continue)
    }

    async fn readonly(&mut self, tag: &str) -> CmdResult {
        self.line(&format!("{tag} NO Mailbox is read-only (EXAMINE)"))
            .await?;
        Ok(Flow::Continue)
    }

    async fn login(&mut self, tag: &str, username: &str, password: &str) -> CmdResult {
        match authenticate(&self.state, username, password, self.ip).await {
            Ok(u) => {
                tracing::info!(login = %u.username, "IMAP login");
                if let Ok(user) = u.unlocked(&self.state) {
                    crate::jobs::index_if_pending(&self.state, &user);
                }
                self.user = Some(u);
                self.line(&format!("{tag} OK [CAPABILITY {CAPABILITIES}] Logged in"))
                    .await?;
                Ok(Flow::Continue)
            }
            Err(LoginError::Locked) => {
                self.line(&format!(
                    "{tag} NO [UNAVAILABLE] {}",
                    Gone::Locked.message()
                ))
                .await?;
                Ok(Flow::Continue)
            }
            Err(LoginError::Throttled(m)) => {
                self.line(&format!("{tag} NO [UNAVAILABLE] {m}")).await?;
                Ok(Flow::Continue)
            }
            Err(LoginError::Invalid) => {
                self.failed_logins += 1;
                self.line(&format!(
                    "{tag} NO [AUTHENTICATIONFAILED] Invalid credentials"
                ))
                .await?;
                Ok(if self.failed_logins >= 3 {
                    Flow::Close
                } else {
                    Flow::Continue
                })
            }
        }
    }

    async fn authenticate_plain(&mut self, tag: &str, args: &[Tok]) -> CmdResult {
        let mech = args.first().and_then(Tok::atom).unwrap_or("");
        if !mech.eq_ignore_ascii_case("PLAIN") {
            self.line(&format!("{tag} NO [CANNOT] Unsupported mechanism"))
                .await?;
            return Ok(Flow::Continue);
        }
        let response = match args.get(1).and_then(Tok::string) {
            Some(r) if r != "=" => r,
            _ => {
                self.line("+ ").await?;
                let line =
                    tokio::time::timeout(PREAUTH_TIMEOUT, read_line(&mut self.io, PREAUTH_MAX))
                        .await
                        .map_err(|_| anyhow::anyhow!("timeout"))??
                        .unwrap_or_default();
                String::from_utf8_lossy(&line).trim().to_string()
            }
        };
        if response == "*" {
            return self.bad(tag, "Authentication cancelled").await;
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(response.trim())
            .ok()
            .map(|v| String::from_utf8_lossy(&v).into_owned());
        let Some(decoded) = decoded else {
            return self.bad(tag, "Invalid base64").await;
        };
        let mut parts = decoded.splitn(3, '\0');
        let (_authz, user, pass) = (parts.next(), parts.next(), parts.next());
        match (user, pass) {
            (Some(u), Some(p)) => {
                let (u, p) = (u.to_string(), p.to_string());
                self.login(tag, &u, &p).await
            }
            _ => self.bad(tag, "Malformed PLAIN response").await,
        }
    }

    fn folders(&self, user: &UnlockedUser) -> anyhow::Result<Vec<Folder>> {
        user.index.imap_folders(&self.account_id())
    }

    fn find_folder(&self, user: &UnlockedUser, name: &str) -> anyhow::Result<Option<Folder>> {
        Ok(self
            .folders(user)?
            .into_iter()
            .find(|f| f.name == name || (is_inbox(name) && is_inbox(&f.name))))
    }

    async fn list(&mut self, tag: &str, cmd: &str, args: &[Tok], user: &UnlockedUser) -> CmdResult {
        // LIST-EXTENDED selection options are accepted and ignored.
        let args: Vec<&Tok> = args
            .iter()
            .skip(usize::from(matches!(args.first(), Some(Tok::List(_)))))
            .collect();
        let (Some(reference), Some(pattern)) = (args.first(), args.get(1)) else {
            return self.bad(tag, "LIST needs a reference and a pattern").await;
        };
        let reference = reference.string().unwrap_or_default();
        let patterns: Vec<String> = match pattern {
            Tok::List(l) => l.iter().filter_map(Tok::string).collect(),
            t => t.string().into_iter().collect(),
        };
        if patterns.len() > MAX_PATTERNS {
            return self.bad(tag, "LIST has too many patterns").await;
        }
        if patterns
            .iter()
            .any(|p| reference.len() + p.len() > MAX_PATTERN)
        {
            return self.bad(tag, "LIST pattern too long").await;
        }
        let folders = self.folders(user)?;
        let default_delim = folders
            .iter()
            .find_map(|f| f.delimiter.clone())
            .unwrap_or_else(|| "/".into());
        let name = if cmd == "LSUB" { "LSUB" } else { "LIST" };
        if patterns.iter().all(|p| p.is_empty()) {
            let mut out = format!("* {name} (\\Noselect) ").into_bytes();
            istr(&mut out, default_delim.as_bytes());
            out.extend_from_slice(b" \"\"\r\n");
            self.send(&out).await?;
            return self.ok(tag, name).await;
        }
        // Every folder plus the parents its name implies.
        let mut entries: Vec<(String, Option<String>, Option<String>, bool)> = folders
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    f.delimiter.clone(),
                    f.special_use.clone(),
                    true,
                )
            })
            .collect();
        for f in &folders {
            if let Some(d) = f.delimiter.as_deref().filter(|d| !d.is_empty()) {
                let mut prefix = String::new();
                let parts: Vec<&str> = f.name.split(d).collect();
                for p in &parts[..parts.len().saturating_sub(1)] {
                    if !prefix.is_empty() {
                        prefix.push_str(d);
                    }
                    prefix.push_str(p);
                    if !entries.iter().any(|e| e.0 == prefix) {
                        entries.push((prefix.clone(), Some(d.to_string()), None, false));
                    }
                }
            }
        }
        entries.sort();
        let mut out = Vec::new();
        for (fname, delim, special, selectable) in &entries {
            let d = delim.as_deref().and_then(|d| d.bytes().next());
            let hit = patterns.iter().any(|p| {
                let full = format!("{reference}{p}");
                wildcard(full.as_bytes(), fname.as_bytes(), d)
                    || (is_inbox(fname)
                        && wildcard(full.to_ascii_uppercase().as_bytes(), b"INBOX", d))
            });
            if !hit {
                continue;
            }
            let has_children = delim.as_deref().is_some_and(|d| {
                let prefix = format!("{fname}{d}");
                entries.iter().any(|e| e.0.starts_with(&prefix))
            });
            let mut attrs = vec![if has_children {
                "\\HasChildren"
            } else {
                "\\HasNoChildren"
            }];
            if !selectable {
                attrs.push("\\Noselect");
            }
            if let Some(s) = special.as_deref().filter(|_| cmd != "LSUB") {
                attrs.push(s);
            }
            out.extend_from_slice(format!("* {name} ({}) ", attrs.join(" ")).as_bytes());
            match delim {
                Some(d) => istr(&mut out, d.as_bytes()),
                None => out.extend_from_slice(b"NIL"),
            }
            out.push(b' ');
            istr(&mut out, fname.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        self.send(&out).await?;
        self.ok(tag, name).await
    }

    async fn status(&mut self, tag: &str, args: &[Tok], user: &UnlockedUser) -> CmdResult {
        let (Some(name), Some(items)) = (
            args.first().and_then(Tok::string),
            args.get(1).and_then(Tok::list),
        ) else {
            return self.bad(tag, "STATUS needs a mailbox and items").await;
        };
        let Some(folder) = self.find_folder(user, &name)? else {
            self.line(&format!("{tag} NO [NONEXISTENT] No such mailbox"))
                .await?;
            return Ok(Flow::Continue);
        };
        let view = user.index.imap_view(&self.account_id(), &folder)?;
        let mut parts = vec![];
        for item in items.iter().filter_map(Tok::atom) {
            let item = item.to_ascii_uppercase();
            let v = match item.as_str() {
                "MESSAGES" => view.messages.len() as u64,
                "RECENT" => 0,
                "UIDNEXT" => view.uidnext as u64,
                "UIDVALIDITY" => view.uidvalidity as u64,
                "UNSEEN" => view
                    .messages
                    .iter()
                    .filter(|m| !m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")))
                    .count() as u64,
                _ => continue,
            };
            parts.push(format!("{item} {v}"));
        }
        let mut out = b"* STATUS ".to_vec();
        istr(&mut out, folder.name.as_bytes());
        out.extend_from_slice(format!(" ({})\r\n", parts.join(" ")).as_bytes());
        self.send(&out).await?;
        self.ok(tag, "STATUS").await
    }

    async fn select(
        &mut self,
        tag: &str,
        args: &[Tok],
        readonly: bool,
        user: &UnlockedUser,
    ) -> CmdResult {
        self.sel = None;
        let Some(name) = args.first().and_then(Tok::string) else {
            return self.bad(tag, "SELECT needs a mailbox").await;
        };
        let Some(folder) = self.find_folder(user, &name)? else {
            self.line(&format!("{tag} NO [NONEXISTENT] No such mailbox"))
                .await?;
            return Ok(Flow::Continue);
        };
        let view = user.index.imap_view(&self.account_id(), &folder)?;
        let unseen = view
            .messages
            .iter()
            .position(|m| !m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")));
        // Keywords in use (tags such as $label1 or a server's categories) are announced too:
        // mail apps only show keywords listed here.
        let keywords: BTreeSet<&str> = view
            .messages
            .iter()
            .flat_map(|m| &m.flags)
            .map(String::as_str)
            .filter(|f| !f.starts_with('\\'))
            .collect();
        let mut flags = String::from("\\Answered \\Flagged \\Deleted \\Seen \\Draft");
        for k in &keywords {
            flags.push(' ');
            flags.push_str(k);
        }
        let mut out = String::new();
        out.push_str(&format!("* FLAGS ({flags})\r\n"));
        if readonly {
            out.push_str("* OK [PERMANENTFLAGS ()] Read-only\r\n");
        } else {
            out.push_str(&format!("* OK [PERMANENTFLAGS ({flags} \\*)] Flags are kept in Malo, not on the mail server\r\n"));
        }
        out.push_str(&format!(
            "* {} EXISTS\r\n* 0 RECENT\r\n",
            view.messages.len()
        ));
        if let Some(i) = unseen {
            out.push_str(&format!("* OK [UNSEEN {}] First unseen\r\n", i + 1));
        }
        out.push_str(&format!(
            "* OK [UIDVALIDITY {}] UIDs valid\r\n",
            view.uidvalidity
        ));
        out.push_str(&format!(
            "* OK [UIDNEXT {}] Predicted next UID\r\n",
            view.uidnext
        ));
        out.push_str(&format!(
            "{tag} OK [{}] {} completed\r\n",
            if readonly { "READ-ONLY" } else { "READ-WRITE" },
            if readonly { "EXAMINE" } else { "SELECT" }
        ));
        self.sel = Some(Selected {
            folder,
            readonly,
            uidvalidity: view.uidvalidity,
            uidnext: view.uidnext,
            msgs: view.messages,
        });
        self.send(out.as_bytes()).await?;
        Ok(Flow::Continue)
    }

    fn max_uid(&self) -> u32 {
        self.sel
            .as_ref()
            .and_then(|s| s.msgs.last().map(|m| m.uid))
            .unwrap_or(0)
    }

    /// Indices into the selected messages addressed by a sequence or UID set.
    fn targets(&self, set: &str, uid: bool) -> Option<Vec<usize>> {
        let sel = self.sel.as_ref()?;
        let max = if uid {
            self.max_uid()
        } else {
            sel.msgs.len() as u32
        };
        let ranges = parse_set(set, max)?;
        Some(
            sel.msgs
                .iter()
                .enumerate()
                .filter(|(i, m)| in_set(&ranges, if uid { m.uid } else { *i as u32 + 1 }))
                .map(|(i, _)| i)
                .collect(),
        )
    }

    /// Tells the client what changed in the selected folder since it last looked.
    async fn refresh(&mut self, user: &UnlockedUser) -> anyhow::Result<()> {
        let account = self.account_id();
        let Some(sel) = self.sel.as_mut() else {
            return Ok(());
        };
        let view = user.index.imap_view(&account, &sel.folder)?;
        if view.uidvalidity != sel.uidvalidity {
            self.sel = None;
            self.line("* BYE The mail view of this account was reset; reconnect to load it again")
                .await?;
            anyhow::bail!("view reset");
        }
        let mut out = String::new();
        let now: HashMap<u32, &ViewMessage> = view.messages.iter().map(|m| (m.uid, m)).collect();
        let mut i = sel.msgs.len();
        while i > 0 {
            i -= 1;
            if !now.contains_key(&sel.msgs[i].uid) {
                out.push_str(&format!("* {} EXPUNGE\r\n", i + 1));
                sel.msgs.remove(i);
            }
        }
        for (i, m) in sel.msgs.iter_mut().enumerate() {
            if let Some(n) = now.get(&m.uid) {
                if n.flags != m.flags {
                    m.flags = n.flags.clone();
                    out.push_str(&format!(
                        "* {} FETCH (UID {} FLAGS {})\r\n",
                        i + 1,
                        m.uid,
                        flag_list(&m.flags)
                    ));
                }
            }
        }
        let last = sel.msgs.last().map(|m| m.uid).unwrap_or(0);
        let before = sel.msgs.len();
        sel.msgs
            .extend(view.messages.iter().filter(|m| m.uid > last).cloned());
        if sel.msgs.len() != before {
            out.push_str(&format!("* {} EXISTS\r\n", sel.msgs.len()));
        }
        sel.uidnext = view.uidnext;
        if !out.is_empty() {
            self.send(out.as_bytes()).await?;
        }
        Ok(())
    }

    async fn fetch(
        &mut self,
        tag: &str,
        args: &[Tok],
        uid: bool,
        user: &Arc<UnlockedUser>,
    ) -> CmdResult {
        let (Some(set), Some(atts)) = (args.first().and_then(Tok::atom), args.get(1)) else {
            return self.bad(tag, "FETCH needs a set and items").await;
        };
        let Some(mut atts) = parse_atts(atts) else {
            return self.bad(tag, "Invalid FETCH items").await;
        };
        let Some(targets) = self.targets(set, uid) else {
            return self.bad(tag, "Invalid sequence set").await;
        };
        if uid && !atts.contains(&Att::Uid) {
            atts.insert(0, Att::Uid);
        }
        let readonly = self.sel.as_ref().is_some_and(|s| s.readonly);
        let marks_seen = !readonly
            && atts.iter().any(|a| {
                matches!(a, Att::Rfc822 | Att::Rfc822Text)
                    || matches!(a, Att::Section(s) if !s.peek)
            });
        let needs_raw = atts.iter().any(|a| {
            matches!(a, Att::Rfc822 | Att::Rfc822Text)
                || matches!(a, Att::Section(s) if !s.header_only())
        });
        let needs_meta = atts.iter().any(|a| {
            matches!(
                a,
                Att::Envelope | Att::BodyStructure | Att::Body | Att::Rfc822Header
            ) || matches!(a, Att::Section(s) if s.header_only())
        });
        let account = self.account_id();
        let mut failed = None;
        let mut seen_changes = vec![];
        let msgs: Vec<(usize, ViewMessage)> = targets
            .into_iter()
            .filter_map(|idx| {
                let m = self.sel.as_ref()?.msgs.get(idx)?.clone();
                Some((idx, m))
            })
            .collect();
        // Several messages load at once; responses still go out in order, as each is ready.
        // (The futures are built up front, not in a stream's closure: that keeps the session
        // future Send.)
        let state = self.state.clone();
        let jobs: Vec<_> = msgs
            .into_iter()
            .map(|(idx, m)| {
                let (state, user) = (state.clone(), user.clone());
                async move {
                    let loaded = load(&state, &user, &m, needs_raw, needs_meta).await;
                    (idx, m, loaded)
                }
            })
            .collect();
        let mut queue = futures::stream::iter(jobs).buffered(LOAD_CONCURRENCY);
        while let Some((idx, m, loaded)) = queue.next().await {
            let (meta, raw_bytes) = match loaded {
                Ok(v) => v,
                Err(e) => {
                    failed = Some(e);
                    continue;
                }
            };
            let mut flags = m.flags.clone();
            let mut add_flags = false;
            if marks_seen && !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")) {
                flags.push("\\Seen".into());
                seen_changes.push((m.uid, flags.clone()));
                if let Some(s) = self.sel.as_mut() {
                    s.msgs[idx].flags = flags.clone();
                }
                add_flags = !atts.contains(&Att::Flags);
            }
            let mut out = format!("* {} FETCH (", idx + 1).into_bytes();
            let mut first = true;
            let mut sep = |out: &mut Vec<u8>| {
                if !std::mem::take(&mut first) {
                    out.push(b' ');
                }
            };
            for a in atts.iter() {
                sep(&mut out);
                match a {
                    Att::Uid => out.extend_from_slice(format!("UID {}", m.uid).as_bytes()),
                    Att::Flags => {
                        out.extend_from_slice(format!("FLAGS {}", flag_list(&flags)).as_bytes())
                    }
                    Att::InternalDate => out.extend_from_slice(
                        format!("INTERNALDATE \"{}\"", imap_date(m.internaldate)).as_bytes(),
                    ),
                    Att::Size => {
                        let size = raw_bytes.as_ref().map(|r| r.len() as u64).unwrap_or(m.size);
                        out.extend_from_slice(format!("RFC822.SIZE {size}").as_bytes())
                    }
                    Att::Envelope => {
                        out.extend_from_slice(b"ENVELOPE ");
                        out.extend_from_slice(&meta.as_ref().unwrap().envelope);
                    }
                    Att::BodyStructure => {
                        out.extend_from_slice(b"BODYSTRUCTURE ");
                        out.extend_from_slice(&meta.as_ref().unwrap().bodystructure);
                    }
                    Att::Body => {
                        out.extend_from_slice(b"BODY ");
                        out.extend_from_slice(&meta.as_ref().unwrap().body);
                    }
                    Att::Rfc822 => {
                        out.extend_from_slice(b"RFC822 ");
                        literal(&mut out, raw_bytes.as_deref().unwrap_or_default());
                    }
                    Att::Rfc822Text => {
                        out.extend_from_slice(b"RFC822.TEXT ");
                        literal(
                            &mut out,
                            mime::split(raw_bytes.as_deref().unwrap_or_default()).1,
                        );
                    }
                    Att::Rfc822Header => {
                        out.extend_from_slice(b"RFC822.HEADER ");
                        literal(&mut out, &meta.as_ref().unwrap().header);
                    }
                    Att::Section(s) => {
                        let bytes = if s.header_only() {
                            let header = &meta.as_ref().unwrap().header;
                            match &s.spec {
                                Spec::Fields(names, not) => {
                                    mime::header_fields(header, names, *not)
                                }
                                _ => header.clone(),
                            }
                        } else {
                            section_bytes(raw_bytes.as_deref().unwrap_or_default(), s)
                        };
                        out.extend_from_slice(s.label().as_bytes());
                        out.push(b' ');
                        literal(&mut out, &partial(bytes, s.partial));
                    }
                }
            }
            if add_flags {
                sep(&mut out);
                out.extend_from_slice(format!("FLAGS {}", flag_list(&flags)).as_bytes());
            }
            out.extend_from_slice(b")\r\n");
            self.send(&out).await?;
        }
        if !seen_changes.is_empty() {
            let folder = self
                .sel
                .as_ref()
                .map(|s| s.folder.name.clone())
                .unwrap_or_default();
            user.index
                .imap_set_flags(&account, &folder, &seen_changes)?;
        }
        match failed {
            Some(e) => {
                let msg = format!("{e:#}").replace(['\r', '\n'], " ");
                let msg = if msg.starts_with('[') {
                    msg
                } else {
                    format!("[UNAVAILABLE] {msg}")
                };
                self.line(&format!("{tag} NO {msg}")).await?;
                Ok(Flow::Continue)
            }
            None => self.ok(tag, if uid { "UID FETCH" } else { "FETCH" }).await,
        }
    }

    async fn store(
        &mut self,
        tag: &str,
        args: &[Tok],
        uid: bool,
        user: &UnlockedUser,
    ) -> CmdResult {
        if self.sel.as_ref().is_some_and(|s| s.readonly) {
            return self.readonly(tag).await;
        }
        let (Some(set), Some(item)) = (
            args.first().and_then(Tok::atom),
            args.get(1).and_then(Tok::atom),
        ) else {
            return self.bad(tag, "STORE needs a set, an item and flags").await;
        };
        let item = item.to_ascii_uppercase();
        let silent = item.ends_with(".SILENT");
        let mode = match item.trim_end_matches(".SILENT") {
            "FLAGS" => 0,
            "+FLAGS" => 1,
            "-FLAGS" => -1,
            _ => return self.bad(tag, "Unknown STORE item").await,
        };
        let given = match args.get(2) {
            Some(Tok::List(l)) => given_flags(l),
            _ => given_flags(&args[2..]),
        };
        let Some(given) = given else {
            return self.bad(tag, "Invalid flags").await;
        };
        let Some(targets) = self.targets(set, uid) else {
            return self.bad(tag, "Invalid sequence set").await;
        };
        let account = self.account_id();
        let sel = self.sel.as_mut().unwrap();
        let mut changes = vec![];
        let mut out = String::new();
        for idx in targets {
            let m = &mut sel.msgs[idx];
            let has = |flags: &[String], f: &str| flags.iter().any(|x| x.eq_ignore_ascii_case(f));
            let mut flags = match mode {
                0 => vec![],
                _ => m.flags.clone(),
            };
            match mode {
                -1 => flags.retain(|f| !has(&given, f)),
                _ => {
                    for f in &given {
                        if !has(&flags, f) {
                            flags.push(f.clone());
                        }
                    }
                }
            }
            if flags != m.flags {
                m.flags = flags.clone();
                changes.push((m.uid, flags));
            }
            if !silent {
                out.push_str(&format!("* {} FETCH (", idx + 1));
                if uid {
                    out.push_str(&format!("UID {} ", m.uid));
                }
                out.push_str(&format!("FLAGS {})\r\n", flag_list(&m.flags)));
            }
        }
        let folder = sel.folder.name.clone();
        if !changes.is_empty() {
            user.index.imap_set_flags(&account, &folder, &changes)?;
        }
        self.send(out.as_bytes()).await?;
        self.ok(tag, if uid { "UID STORE" } else { "STORE" }).await
    }

    async fn search(
        &mut self,
        tag: &str,
        args: &[Tok],
        uid: bool,
        user: &Arc<UnlockedUser>,
    ) -> CmdResult {
        let mut args = args;
        // RETURN (ESEARCH) isn't offered; CHARSET is accepted (matching is UTF-8 anyway).
        if args
            .first()
            .and_then(Tok::atom)
            .is_some_and(|a| a.eq_ignore_ascii_case("CHARSET"))
        {
            args = args.get(2..).unwrap_or_default();
        }
        let sel_len = self.sel.as_ref().map(|s| s.msgs.len()).unwrap_or(0) as u32;
        let max_uid = self.max_uid();
        let mut it = args.iter().peekable();
        let mut keys = vec![];
        while it.peek().is_some() {
            match parse_key(&mut it, sel_len, max_uid, 0) {
                Some(k) => keys.push(k),
                None => return self.bad(tag, "Invalid search criteria").await,
            }
        }
        let key = Key::And(keys);
        let need_header = key.needs_header();
        let mut texts = vec![];
        key.text_keys(&mut texts);
        let mut full_text = FullText::new();
        let mut unindexed = HashSet::new();
        if !texts.is_empty() {
            unindexed = user.index.search_unindexed(&self.account_id())?;
            for (body, s) in texts {
                let hits = match malo_core::search::phrase(s) {
                    Some(expr) => Some(user.index.search_ids(&expr, body.then_some("body"))?),
                    None => None,
                };
                full_text.insert((body, s.to_string()), hits);
            }
        }
        // Raw messages are read only where the index can't answer.
        let raw_for_all = full_text.values().any(Option::is_none);
        let msgs = self
            .sel
            .as_ref()
            .map(|s| s.msgs.clone())
            .unwrap_or_default();
        let mut hits = vec![];
        let state = self.state.clone();
        let check_text = !full_text.is_empty();
        let jobs: Vec<_> = msgs
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let indexed = !unindexed.contains(&m.message);
                let need_raw = check_text && (raw_for_all || !indexed);
                let (state, user, m) = (state.clone(), user.clone(), m.clone());
                async move {
                    let (meta, raw) = if need_raw || need_header {
                        load(&state, &user, &m, need_raw, need_header)
                            .await
                            .unwrap_or_default()
                    } else {
                        (None, None)
                    };
                    (i, m, indexed, meta.map(|x| x.header), raw)
                }
            })
            .collect();
        let mut queue = futures::stream::iter(jobs).buffered(LOAD_CONCURRENCY);
        while let Some((i, m, indexed, header, raw_bytes)) = queue.next().await {
            let item = SearchItem {
                seq: i as u32 + 1,
                msg: &m,
                header: header.as_deref(),
                raw: raw_bytes.as_deref(),
                indexed,
                full_text: &full_text,
            };
            if matches(&key, &item) {
                hits.push(if uid { m.uid } else { i as u32 + 1 });
            }
        }
        let mut out = String::from("* SEARCH");
        for h in hits {
            out.push_str(&format!(" {h}"));
        }
        out.push_str("\r\n");
        self.send(out.as_bytes()).await?;
        self.ok(tag, if uid { "UID SEARCH" } else { "SEARCH" })
            .await
    }

    /// Hides messages marked \Deleted (within `uids`, for UID EXPUNGE) from the folder.
    async fn expunge(
        &mut self,
        user: &UnlockedUser,
        uids: Option<&[(u32, u32)]>,
        silent: bool,
    ) -> anyhow::Result<()> {
        let account = self.account_id();
        let Some(sel) = self.sel.as_mut() else {
            return Ok(());
        };
        if sel.readonly {
            return Ok(());
        }
        let gone: Vec<usize> = sel
            .msgs
            .iter()
            .enumerate()
            .filter(|(_, m)| m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted")))
            .filter(|(_, m)| uids.is_none_or(|s| in_set(s, m.uid)))
            .map(|(i, _)| i)
            .collect();
        self.hide(user, &account, &gone, silent).await
    }

    async fn hide(
        &mut self,
        user: &UnlockedUser,
        account: &str,
        indices: &[usize],
        silent: bool,
    ) -> anyhow::Result<()> {
        let Some(sel) = self.sel.as_mut() else {
            return Ok(());
        };
        let uids: Vec<u32> = indices.iter().map(|i| sel.msgs[*i].uid).collect();
        if uids.is_empty() {
            return Ok(());
        }
        user.index.imap_hide(account, &sel.folder.name, &uids)?;
        let mut out = String::new();
        for i in indices.iter().rev() {
            out.push_str(&format!("* {} EXPUNGE\r\n", i + 1));
            sel.msgs.remove(*i);
        }
        if !silent {
            self.send(out.as_bytes()).await?;
        }
        Ok(())
    }

    /// COPY/MOVE re-file messages in this view: into Spam, a Gmail category, Trash or any other
    /// folder. The backup and the account's server never change.
    async fn copy(
        &mut self,
        tag: &str,
        args: &[Tok],
        uid: bool,
        mv: bool,
        user: &UnlockedUser,
    ) -> CmdResult {
        let (Some(set), Some(target)) = (
            args.first().and_then(Tok::atom),
            args.get(1).and_then(Tok::string),
        ) else {
            return self.bad(tag, "COPY needs a set and a mailbox").await;
        };
        let Some(folder) = self.find_folder(user, &target)? else {
            self.line(&format!("{tag} NO [TRYCREATE] No such mailbox"))
                .await?;
            return Ok(Flow::Continue);
        };
        let Some(targets) = self.targets(set, uid) else {
            return self.bad(tag, "Invalid sequence set").await;
        };
        let what = if mv { "MOVE" } else { "COPY" };
        if mv && self.sel.as_ref().is_some_and(|s| s.readonly) {
            return self.readonly(tag).await;
        }
        let account = self.account_id();
        let Some(sel) = self.sel.as_mut() else {
            return Ok(Flow::Continue);
        };
        if sel.folder.name == folder.name || targets.is_empty() {
            return self.ok(tag, what).await;
        }
        let uids: Vec<u32> = targets.iter().map(|i| sel.msgs[*i].uid).collect();
        user.index
            .imap_place(&account, &sel.folder.name, &uids, &folder.name, !mv)?;
        if mv {
            let mut out = String::new();
            for i in targets.iter().rev() {
                out.push_str(&format!("* {} EXPUNGE\r\n", i + 1));
                sel.msgs.remove(*i);
            }
            self.send(out.as_bytes()).await?;
        }
        self.ok(tag, what).await
    }

    /// APPEND goes to the account's own server; the message shows up here after the next backup.
    async fn append(&mut self, tag: &str, args: &[Tok]) -> CmdResult {
        let Some(name) = args.first().and_then(Tok::string) else {
            return self.bad(tag, "APPEND needs a mailbox").await;
        };
        // mailbox [(flags)] [date-time] message
        let mut flags = None;
        let mut strings = vec![];
        for t in &args[1..] {
            match t {
                Tok::List(l) if flags.is_none() && strings.is_empty() => {
                    let Some(f) = given_flags(l) else {
                        return self.bad(tag, "Invalid flags").await;
                    };
                    flags = Some(format!("({})", f.join(" ")));
                }
                Tok::Str(s) => strings.push(s),
                _ => return self.bad(tag, "Invalid APPEND arguments").await,
            }
        }
        let (date, content) = match strings[..] {
            [c] => (None, c.clone()),
            [d, c] => match append_date(d) {
                Some(d) => (Some(d), c.clone()),
                None => return self.bad(tag, "Invalid APPEND date").await,
            },
            _ => return self.bad(tag, "APPEND needs a message").await,
        };
        let Ok(user) = self.unlocked().await? else {
            return Ok(Flow::Close);
        };
        let Some(folder) = self.find_folder(&user, &name)? else {
            self.line(&format!("{tag} NO [TRYCREATE] No such mailbox"))
                .await?;
            return Ok(Flow::Continue);
        };
        let mail_user = self.user.clone().unwrap();
        let account = user.config().account(&mail_user.account_id).cloned();
        let tokens = user.tokens.clone();
        drop(user);
        let Some(account) = account else {
            return Ok(Flow::Close);
        };
        let draft = folder.special_use.as_deref() == Some("\\Drafts");
        let gmail_sent = matches!(&folder.source, FolderSource::Label(l) if l == "\\Sent");
        if draft || gmail_sent {
            // Drafts stay in the mail app; Gmail files sent mail by itself.
            self.line(&format!(
                "{tag} OK {}",
                if draft {
                    "Drafts aren't kept on the backup server"
                } else {
                    "Gmail already keeps sent mail"
                }
            ))
            .await?;
            return Ok(Flow::Continue);
        }
        let upstream = match &folder.source {
            FolderSource::Label(l) if l == "\\Inbox" => "INBOX".to_string(),
            FolderSource::Primary | FolderSource::AllMail | FolderSource::Category(_) => {
                "INBOX".to_string()
            }
            FolderSource::Label(l) => l.clone(),
            FolderSource::Mailbox => folder.name.clone(),
        };
        let date = date.map(|d| format!("\"{d}\""));
        if let Err(e) = crate::net::check_account(&self.state, &account).await {
            self.line(&format!(
                "{tag} NO {}",
                e.message.replace(['\r', '\n'], " ")
            ))
            .await?;
            return Ok(Flow::Continue);
        }
        let res = async {
            let mut conn = malo_core::imap::connect(&account, tokens.as_ref()).await?;
            conn.session
                .append(&upstream, flags.as_deref(), date.as_deref(), &content)
                .await?;
            conn.logout().await;
            anyhow::Ok(())
        }
        .await;
        match res {
            Ok(()) => {
                let _ = crate::jobs::submit(
                    &self.state,
                    &mail_user.user_id,
                    JobKind::Backup {
                        account_id: account.id.clone(),
                    },
                    JobTrigger::Scheduled,
                );
                self.line(&format!(
                    "{tag} OK APPEND completed: saved on {}, it shows up here after the next backup",
                    account.host
                ))
                .await?;
            }
            Err(e) => {
                let msg = format!("{e:#}").replace(['\r', '\n'], " ");
                self.line(&format!(
                    "{tag} NO Couldn't save on {}: {msg}",
                    account.host
                ))
                .await?;
            }
        }
        Ok(Flow::Continue)
    }

    async fn idle(&mut self, tag: &str) -> CmdResult {
        self.line("+ idling").await?;
        let sealed = self.user.as_ref().unwrap().sealed.clone();
        let started = tokio::time::Instant::now();
        loop {
            tokio::select! {
                // Only waiting for input happens in here: fill_buf loses nothing when the poll
                // timer wins, while a half-read line would.
                ready = async { self.io.fill_buf().await.map(|b| b.is_empty()) } => {
                    if ready? {
                        return Ok(Flow::Close);
                    }
                    let Some(line) = read_line(&mut self.io, MAX_LINE).await? else {
                        return Ok(Flow::Close);
                    };
                    if String::from_utf8_lossy(&line).trim().eq_ignore_ascii_case("DONE") {
                        return self.ok(tag, "IDLE").await;
                    }
                    return self.bad(tag, "Expected DONE").await;
                }
                _ = tokio::time::sleep(IDLE_POLL) => {
                    if started.elapsed() > AUTOLOGOUT {
                        self.line("* BYE Autologout; idle for too long").await?;
                        return Ok(Flow::Close);
                    }
                    let Ok(user) = self.unlocked().await? else { return Ok(Flow::Close) };
                    if self.refresh(&user).await.is_err() {
                        return Ok(Flow::Close);
                    }
                }
                _ = sealed.cancelled() => {
                    self.line(&format!("* BYE {}", Gone::Locked.message())).await?;
                    return Ok(Flow::Close);
                }
            }
        }
    }
}

fn literal(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(format!("{{{}}}\r\n", bytes.len()).as_bytes());
    out.extend_from_slice(bytes);
}

/// The tag of a command being read (for an error before it is complete).
/// What a command needs of a message: its raw bytes, its header data, or both. Header data is
/// normally stored when the message is indexed, so header-only fetches don't download anything;
/// otherwise it's computed from the raw message and kept.
async fn load(
    state: &SharedState,
    user: &Arc<UnlockedUser>,
    m: &ViewMessage,
    need_raw: bool,
    need_meta: bool,
) -> anyhow::Result<(Option<ImapMeta>, Option<Vec<u8>>)> {
    let mut meta = if need_meta {
        user.index.imap_meta(&m.sha256)?
    } else {
        None
    };
    let raw = if need_raw || (need_meta && meta.is_none()) {
        Some(
            crate::routes::load_raw(state, user, m.message)
                .await
                .map_err(|e| anyhow::anyhow!("[UNAVAILABLE] {}", e.message))?,
        )
    } else {
        None
    };
    if let (true, None, Some(bytes)) = (need_meta, &meta, &raw) {
        let computed = ImapMeta::of(bytes);
        if let Err(e) = user.index.put_imap_meta(&m.sha256, &computed) {
            tracing::debug!("caching IMAP header data: {e:#}");
        }
        meta = Some(computed);
    }
    Ok((meta, raw.filter(|_| need_raw)))
}

/// Before login, only LOGIN and AUTHENTICATE may send literals (a password with odd characters).
fn literal_allowed(segs: &[Seg], line: &[u8]) -> bool {
    let first = match segs.first() {
        Some(Seg::Text(t)) => t.as_slice(),
        _ => line,
    };
    let cmd = first.split(|b| *b == b' ').nth(1).unwrap_or_default();
    cmd.eq_ignore_ascii_case(b"LOGIN") || cmd.eq_ignore_ascii_case(b"AUTHENTICATE")
}

fn segs_tag(segs: &[Seg], line: &[u8]) -> Vec<u8> {
    let first = match segs.first() {
        Some(Seg::Text(t)) => t.as_slice(),
        _ => line,
    };
    first.split(|b| *b == b' ').next().unwrap_or(b"*").to_vec()
}

pub async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    state: SharedState,
    stream: S,
    ip: IpAddr,
    greet: bool,
    opened: std::time::Instant,
) -> anyhow::Result<()> {
    Session {
        io: BufReader::new(stream),
        state,
        ip,
        greet,
        user: None,
        sel: None,
        failed_logins: 0,
        opened,
        commands: 0,
        trace: tracing_on().then(|| {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("IMAP #{n}: connection from {ip}");
            n
        }),
        current: None,
        responses: 0,
        sent: 0,
    }
    .run()
    .await
}

/// Fuzzing entry point (`fuzz/fuzz_targets/imap_server_command.rs`): the command parsers on
/// whatever a mail app sends. 0xFF bytes split the input into text and literal segments.
#[doc(hidden)]
pub fn fuzz_command(data: &[u8]) {
    let segs: Vec<Seg> = data
        .split(|b| *b == 0xff)
        .take(MAX_SEGMENTS)
        .enumerate()
        .map(|(i, s)| match i % 2 {
            0 => Seg::Text(s.to_vec()),
            _ => Seg::Literal(s.to_vec()),
        })
        .collect();
    let _ = describe(&segs);
    let _ = literal_marker(data);
    let _ = literal_allowed(&segs, data);
    let _ = segs_tag(&segs, data);
    let Some(toks) = tokenize(segs) else { return };
    for (i, t) in toks.iter().enumerate().take(16) {
        let _ = parse_key(&mut toks[i..].iter().peekable(), 100, 1000, 0);
        let _ = parse_atts(t);
        let _ = given_flags(toks[i..].iter());
        if let Some(a) = t.atom() {
            let _ = parse_set(a, 1000);
            let _ = parse_section(a);
        }
        if let Some(s) = t.string() {
            let _ = append_date(s.as_bytes());
        }
    }
    if let [p, n, ..] = toks.as_slice() {
        if let (Some(p), Some(n)) = (p.string(), n.string()) {
            if p.len() <= MAX_PATTERN {
                let _ = wildcard(p.as_bytes(), n.as_bytes(), Some(b'/'));
                let _ = wildcard(p.as_bytes(), n.as_bytes(), None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        tokenize(vec![Seg::Text(s.as_bytes().to_vec())]).unwrap()
    }

    #[test]
    fn tokenizer() {
        let t = toks("a1 UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (DATE FROM)]<0.100>)\r\n");
        assert_eq!(t[3], Tok::Atom("1:*".into()));
        let atts = parse_atts(&t[4]).unwrap();
        assert_eq!(atts[0], Att::Flags);
        let Att::Section(s) = &atts[1] else { panic!() };
        assert!(s.peek);
        assert_eq!(
            s.spec,
            Spec::Fields(vec!["DATE".into(), "FROM".into()], false)
        );
        assert_eq!(s.partial, Some((0, 100)));
        assert_eq!(s.label(), "BODY[HEADER.FIELDS (DATE FROM)]<0>");
        let t = toks("a LOGIN \"us\\\"er\" pass\r\n");
        assert_eq!(t[2], Tok::Str(b"us\"er".to_vec()));
        let segs = vec![
            Seg::Text(b"a APPEND INBOX (\\Seen) ".to_vec()),
            Seg::Literal(b"Subject: x\r\n\r\nhi".to_vec()),
            Seg::Text(b"\r\n".to_vec()),
        ];
        let t = tokenize(segs).unwrap();
        assert_eq!(t[4], Tok::Str(b"Subject: x\r\n\r\nhi".to_vec()));
        assert_eq!(literal_marker(b"a APPEND x {12}\r\n"), Some((12, true)));
        assert_eq!(literal_marker(b"a APPEND x {12+}\r\n"), Some((12, false)));
        assert_eq!(literal_marker(b"a NOOP\r\n"), None);
    }

    #[test]
    fn sections() {
        let s = parse_section("BODY[1.2.MIME]").unwrap();
        assert_eq!((s.path.clone(), s.spec.clone()), (vec![1, 2], Spec::Mime));
        assert_eq!(parse_section("BODY[]").unwrap().spec, Spec::All);
        assert_eq!(parse_section("body.peek[text]").unwrap().spec, Spec::Text);
        assert!(parse_section("BODY[MIME]").is_none());
        let raw = b"Subject: a\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\none\r\n--b--\r\n";
        assert_eq!(
            section_bytes(raw, &parse_section("BODY[1]").unwrap()),
            b"one"
        );
        assert_eq!(
            section_bytes(raw, &parse_section("BODY[1.MIME]").unwrap()),
            b"Content-Type: text/plain\r\n\r\n"
        );
        assert_eq!(
            section_bytes(
                raw,
                &parse_section("BODY[HEADER.FIELDS (subject)]").unwrap()
            ),
            b"Subject: a\r\n\r\n"
        );
        assert_eq!(partial(b"abcdef".to_vec(), Some((2, 3))), b"cde");
        assert_eq!(partial(b"abc".to_vec(), Some((5, 3))), b"");
    }

    #[test]
    fn sets_and_wildcards() {
        assert_eq!(
            parse_set("1:3,7,9:*", 12),
            Some(vec![(1, 3), (7, 7), (9, 12)])
        );
        assert_eq!(parse_set("5:2", 9), Some(vec![(2, 5)]));
        assert_eq!(parse_set("0", 9), None);
        assert_eq!(
            parse_set("9,1:3,4,2,20:22", 30),
            Some(vec![(1, 4), (9, 9), (20, 22)])
        );
        let set = parse_set("9,1:3,20:22", 30).unwrap();
        for (n, inside) in [
            (0, false),
            (1, true),
            (3, true),
            (4, false),
            (9, true),
            (21, true),
            (23, false),
        ] {
            assert_eq!(in_set(&set, n), inside, "{n}");
        }
        let many = vec!["1"; MAX_SET_RANGES + 1].join(",");
        assert_eq!(parse_set(&many, 9), None);
        assert_eq!(parse_set(&many[2..], 9), Some(vec![(1, 1)]));
        assert!(wildcard(b"*", b"[Gmail]/All Mail", Some(b'/')));
        assert!(wildcard(b"%", b"INBOX", Some(b'/')));
        assert!(!wildcard(b"%", b"[Gmail]/All Mail", Some(b'/')));
        assert!(wildcard(b"[Gmail]/%", b"[Gmail]/All Mail", Some(b'/')));
        assert!(wildcard(b"*Mail", b"[Gmail]/All Mail", Some(b'/')));
        assert!(wildcard(b"%/%", b"[Gmail]/All Mail", Some(b'/')));
        assert!(!wildcard(b"%Mail", b"[Gmail]/All Mail", Some(b'/')));
        assert!(wildcard(b"", b"", Some(b'/')));
        assert!(!wildcard(b"", b"x", Some(b'/')));
        assert!(wildcard(b"%", b"a/b", None));
        // Exponential for a backtracking matcher.
        let pattern = "*a".repeat(500) + "b";
        let started = std::time::Instant::now();
        assert!(!wildcard(
            pattern.as_bytes(),
            "a".repeat(1000).as_bytes(),
            None
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn hostile_commands() {
        let deep = format!(
            "a SEARCH {}ALL{}\r\n",
            "(".repeat(100_000),
            ")".repeat(100_000)
        );
        assert!(tokenize(vec![Seg::Text(deep.into_bytes())]).is_none());
        let ok = format!(
            "a SEARCH {}ALL{}\r\n",
            "(".repeat(MAX_DEPTH),
            ")".repeat(MAX_DEPTH)
        );
        assert!(tokenize(vec![Seg::Text(ok.into_bytes())]).is_some());

        let nots = toks(&format!("{}ALL", "NOT ".repeat(10_000)));
        assert!(parse_key(&mut nots.iter().peekable(), 1, 1, 0).is_none());
        let nots = toks(&format!("{}ALL", "NOT ".repeat(MAX_DEPTH)));
        assert!(parse_key(&mut nots.iter().peekable(), 1, 1, 0).is_some());

        assert!(parse_section("BODY[HEADER.FIELDS)(]").is_none());
    }

    #[test]
    fn flags_and_dates() {
        for f in ["\\Seen", "$Forwarded", "Junk", "\\Answered"] {
            assert!(valid_flag(f), "{f}");
        }
        for f in [
            "",
            "\\",
            "a b",
            "x\r\nA1 DELETE INBOX",
            "(x",
            "\"q\"",
            "a]",
            "a*",
            "é",
            &"x".repeat(65),
        ] {
            assert!(!valid_flag(f), "{f}");
        }
        let list = |v: &[&str]| -> Vec<Tok> {
            v.iter().map(|s| Tok::Str(s.as_bytes().to_vec())).collect()
        };
        assert_eq!(
            given_flags(&list(&["\\Seen", "\\Recent"])),
            Some(vec!["\\Seen".into()])
        );
        assert_eq!(given_flags(&list(&["ok", "bad\r\n"])), None);
        assert_eq!(given_flags(&list(&["a"; MAX_FLAGS + 1])), None);
        assert!(append_date(b"17-Jul-1996 02:44:25 -0700").is_some());
        assert!(append_date(b" 7-Jul-1996 02:44:25 -0700").is_some());
        assert!(append_date(b"7-Jul-1996 02:44:25 -0700").is_some());
        assert!(append_date(b"17-Jul-1996 02:44:25 -0700\r\nA1 X").is_none());
        assert!(append_date(b"yesterday").is_none());
    }

    #[test]
    fn search_keys() {
        let t = toks("OR SEEN (FROM \"bob\" SINCE 1-Feb-2024) NOT 2:3");
        let mut it = t.iter().peekable();
        let k = parse_key(&mut it, 10, 50, 0).unwrap();
        assert!(matches!(k, Key::Or(..)));
        assert!(k.needs_header());
        let k2 = parse_key(&mut it, 10, 50, 0).unwrap();
        let m = ViewMessage {
            uid: 4,
            message: 1,
            flags: vec![],
            size: 10,
            internaldate: None,
            sha256: String::new(),
        };
        let item = SearchItem {
            seq: 2,
            msg: &m,
            header: Some(b"From: Bob <b@x>\r\n\r\n"),
            raw: None,
            indexed: false,
            full_text: &FullText::new(),
        };
        assert!(!matches(&k2, &item));
        assert!(!matches(&k, &item), "no date, so SINCE fails");
    }
}
