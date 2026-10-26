//! MIME structure for the IMAP service: part numbering, section contents, ENVELOPE and
//! BODYSTRUCTURE, all computed from the raw message without decoding or changing a byte.

const MAX_DEPTH: usize = 24;

pub enum Kind<'a> {
    Leaf,
    Multipart(Vec<Part<'a>>),
    /// message/rfc822 (or global): the encapsulated message.
    Message(Box<Part<'a>>),
}

pub struct Part<'a> {
    /// Header block including the blank line that ends it.
    pub header: &'a [u8],
    pub body: &'a [u8],
    /// Lower-case type and subtype.
    pub ctype: (String, String),
    pub params: Vec<(String, String)>,
    pub kind: Kind<'a>,
}

/// Splits a message into header (with its terminating blank line) and body.
pub fn split(raw: &[u8]) -> (&[u8], &[u8]) {
    if raw.starts_with(b"\r\n") {
        return (&raw[..2], &raw[2..]);
    }
    if raw.starts_with(b"\n") {
        return (&raw[..1], &raw[1..]);
    }
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\n' {
            if raw[i + 1..].starts_with(b"\r\n") {
                return (&raw[..i + 3], &raw[i + 3..]);
            }
            if raw[i + 1..].starts_with(b"\n") {
                return (&raw[..i + 2], &raw[i + 2..]);
            }
        }
        i += 1;
    }
    (raw, &[])
}

/// Header fields as (name, unfolded raw value).
pub fn fields(header: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for line in header.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            if let Some(last) = out.last_mut() {
                last.1.extend_from_slice(line);
            }
            continue;
        }
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
            let value = trim(&line[colon + 1..]).to_vec();
            out.push((name, value));
        }
    }
    out
}

fn trim(v: &[u8]) -> &[u8] {
    let start = v
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    &v[start..end]
}

pub fn field<'f>(fields: &'f [(String, Vec<u8>)], name: &str) -> Option<&'f [u8]> {
    fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// `type/subtype; a=b; c="d"`: lower-case type, subtype and parameter names, unquoted values.
type Params = Vec<(String, String)>;

fn content_type(v: &[u8]) -> Option<((String, String), Params)> {
    let s = String::from_utf8_lossy(v);
    let mut items = split_params(&s).into_iter();
    let t = items.next()?;
    let (ty, sub) = t.split_once('/')?;
    let (ty, sub) = (
        ty.trim().to_ascii_lowercase(),
        sub.trim().to_ascii_lowercase(),
    );
    if ty.is_empty() || sub.is_empty() {
        return None;
    }
    Some(((ty, sub), params_of(items)))
}

/// Splits at `;` outside quoted strings.
fn split_params(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                cur.push(c);
                escaped = true
            }
            '"' => {
                quoted = !quoted;
                cur.push(c)
            }
            ';' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn params_of(items: impl Iterator<Item = String>) -> Vec<(String, String)> {
    items
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            let k = k.trim().to_ascii_lowercase();
            (!k.is_empty()).then(|| (k, unquote(v.trim())))
        })
        .collect()
}

fn unquote(v: &str) -> String {
    match v.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(inner) => {
            let mut out = String::new();
            let mut esc = false;
            for c in inner.chars() {
                if esc {
                    out.push(c);
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else {
                    out.push(c);
                }
            }
            out
        }
        None => v.to_string(),
    }
}

pub fn parse(raw: &[u8]) -> Part<'_> {
    parse_part(raw, false, 0)
}

fn parse_part(raw: &[u8], digest: bool, depth: usize) -> Part<'_> {
    let (header, body) = split(raw);
    let f = fields(header);
    let default = if digest {
        ("message".to_string(), "rfc822".to_string())
    } else {
        ("text".to_string(), "plain".to_string())
    };
    let (ctype, params) = field(&f, "content-type")
        .and_then(content_type)
        .unwrap_or((default, vec![]));
    let mut part = Part {
        header,
        body,
        ctype,
        params,
        kind: Kind::Leaf,
    };
    if depth >= MAX_DEPTH {
        return part;
    }
    if part.ctype.0 == "multipart" {
        let boundary = part
            .params
            .iter()
            .find(|(k, _)| k == "boundary")
            .map(|(_, v)| v.clone());
        if let Some(b) = boundary.filter(|b| !b.is_empty()) {
            let digest = part.ctype.1 == "digest";
            let children = split_multipart(body, b.as_bytes())
                .into_iter()
                .map(|c| parse_part(c, digest, depth + 1))
                .collect();
            part.kind = Kind::Multipart(children);
        } else {
            part.kind = Kind::Multipart(vec![]);
        }
    } else if part.ctype.0 == "message" && matches!(part.ctype.1.as_str(), "rfc822" | "global") {
        part.kind = Kind::Message(Box::new(parse_part(body, false, depth + 1)));
    }
    part
}

/// The body parts between `--boundary` lines (without the line break before each delimiter).
fn split_multipart<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = vec![];
    let mut start: Option<usize> = None;
    let mut line_start = 0;
    while line_start <= body.len() {
        let end = body[line_start..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(body.len(), |p| line_start + p);
        let line = &body[line_start..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(rest) = line
            .strip_prefix(b"--")
            .and_then(|l| l.strip_prefix(boundary))
        {
            let closing = rest.starts_with(b"--");
            if closing || trim(rest).is_empty() {
                if let Some(s) = start {
                    // The CRLF before the delimiter belongs to the delimiter.
                    let mut e = line_start;
                    if e > s && body[e - 1] == b'\n' {
                        e -= 1;
                        if e > s && body[e - 1] == b'\r' {
                            e -= 1;
                        }
                    }
                    parts.push(&body[s..e.max(s)]);
                }
                if closing {
                    return parts;
                }
                start = Some((end + 1).min(body.len()));
            }
        }
        if end >= body.len() {
            break;
        }
        line_start = end + 1;
    }
    // No closing delimiter: the last part runs to the end.
    if let Some(s) = start {
        parts.push(&body[s..]);
    }
    parts
}

/// The node a part number path points to (`1.2.3`), as IMAP numbers them.
pub fn resolve<'p, 'a>(root: &'p Part<'a>, path: &[u32]) -> Option<&'p Part<'a>> {
    let mut cur = root;
    for (i, n) in path.iter().enumerate() {
        let n = *n as usize;
        // A message/rfc822 part (not the root) is numbered by its encapsulated message.
        let container = match (&cur.kind, i) {
            (Kind::Message(inner), i) if i > 0 => inner.as_ref(),
            _ => cur,
        };
        cur = match &container.kind {
            Kind::Multipart(children) => children.get(n.checked_sub(1)?)?,
            _ if n == 1 && (i == 0 || !std::ptr::eq(container, cur)) => container,
            _ => return None,
        };
    }
    Some(cur)
}

// ───────────────────────────── IMAP syntax ─────────────────────────────

/// A string as an IMAP quoted string, or a literal when it can't be one.
pub fn istr(out: &mut Vec<u8>, s: &[u8]) {
    let plain = s.len() < 1024 && s.iter().all(|b| *b >= 0x20 && *b < 0x7f || *b == b'\t');
    if plain {
        out.push(b'"');
        for b in s {
            if *b == b'"' || *b == b'\\' {
                out.push(b'\\');
            }
            out.push(*b);
        }
        out.push(b'"');
    } else {
        out.extend_from_slice(format!("{{{}}}\r\n", s.len()).as_bytes());
        out.extend_from_slice(s);
    }
}

pub fn nstr(out: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        Some(s) => istr(out, s),
        None => out.extend_from_slice(b"NIL"),
    }
}

fn upper(out: &mut Vec<u8>, s: &str) {
    istr(out, s.to_ascii_uppercase().as_bytes());
}

fn params_list(out: &mut Vec<u8>, params: &[(String, String)]) {
    if params.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        upper(out, k);
        out.push(b' ');
        istr(out, v.as_bytes());
    }
    out.push(b')');
}

fn lines(body: &[u8]) -> usize {
    let n = body.iter().filter(|b| **b == b'\n').count();
    if body.last().is_some_and(|b| *b != b'\n') {
        n + 1
    } else {
        n
    }
}

/// `(type params)` of Content-Disposition, or NIL.
fn disposition(out: &mut Vec<u8>, f: &[(String, Vec<u8>)]) {
    let Some(v) = field(f, "content-disposition") else {
        out.extend_from_slice(b"NIL");
        return;
    };
    let s = String::from_utf8_lossy(v);
    let mut items = split_params(&s).into_iter();
    let ty = items.next().unwrap_or_default();
    let ty = ty.trim();
    if ty.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    upper(out, ty);
    out.push(b' ');
    params_list(out, &params_of(items));
    out.push(b')');
}

fn opt_field(out: &mut Vec<u8>, f: &[(String, Vec<u8>)], name: &str) {
    nstr(out, field(f, name));
}

/// BODYSTRUCTURE (`extended`) or BODY of a part.
pub fn body_structure(out: &mut Vec<u8>, p: &Part, extended: bool) {
    let f = fields(p.header);
    out.push(b'(');
    match &p.kind {
        Kind::Multipart(children) if !children.is_empty() => {
            for c in children {
                body_structure(out, c, extended);
            }
            out.push(b' ');
            upper(out, &p.ctype.1);
            if extended {
                out.push(b' ');
                params_list(out, &p.params);
                out.push(b' ');
                disposition(out, &f);
                out.push(b' ');
                opt_field(out, &f, "content-language");
                out.push(b' ');
                opt_field(out, &f, "content-location");
            }
        }
        kind => {
            // An empty multipart is shown as an empty text part.
            let (ty, sub, params) = if matches!(kind, Kind::Multipart(_)) {
                ("text".to_string(), "plain".to_string(), vec![])
            } else {
                (p.ctype.0.clone(), p.ctype.1.clone(), p.params.clone())
            };
            upper(out, &ty);
            out.push(b' ');
            upper(out, &sub);
            out.push(b' ');
            if ty == "text" && !params.iter().any(|(k, _)| k == "charset") {
                let mut with = vec![("charset".to_string(), "us-ascii".to_string())];
                with.extend(params);
                params_list(out, &with);
            } else {
                params_list(out, &params);
            }
            out.push(b' ');
            opt_field(out, &f, "content-id");
            out.push(b' ');
            opt_field(out, &f, "content-description");
            out.push(b' ');
            let enc = field(&f, "content-transfer-encoding")
                .map(|e| String::from_utf8_lossy(e).trim().to_string())
                .filter(|e| !e.is_empty())
                .unwrap_or_else(|| "7bit".into());
            upper(out, &enc);
            out.extend_from_slice(format!(" {}", p.body.len()).as_bytes());
            if let Kind::Message(inner) = kind {
                out.push(b' ');
                envelope(out, &fields(inner.header));
                out.push(b' ');
                body_structure(out, inner, extended);
                out.extend_from_slice(format!(" {}", lines(p.body)).as_bytes());
            } else if ty == "text" {
                out.extend_from_slice(format!(" {}", lines(p.body)).as_bytes());
            }
            if extended {
                out.push(b' ');
                opt_field(out, &f, "content-md5");
                out.push(b' ');
                disposition(out, &f);
                out.push(b' ');
                opt_field(out, &f, "content-language");
                out.push(b' ');
                opt_field(out, &f, "content-location");
            }
        }
    }
    out.push(b')');
}

/// ENVELOPE from the header fields.
pub fn envelope(out: &mut Vec<u8>, f: &[(String, Vec<u8>)]) {
    out.push(b'(');
    opt_field(out, f, "date");
    out.push(b' ');
    opt_field(out, f, "subject");
    let from = field(f, "from");
    for (name, fallback) in [
        ("from", None),
        ("sender", from),
        ("reply-to", from),
        ("to", None),
        ("cc", None),
        ("bcc", None),
    ] {
        out.push(b' ');
        addresses(out, field(f, name).or(fallback));
    }
    out.push(b' ');
    opt_field(out, f, "in-reply-to");
    out.push(b' ');
    opt_field(out, f, "message-id");
    out.push(b')');
}

#[derive(Debug, PartialEq)]
enum Addr {
    Mailbox {
        name: Option<String>,
        mailbox: String,
        host: String,
    },
    GroupStart(String),
    GroupEnd,
}

fn addresses(out: &mut Vec<u8>, v: Option<&[u8]>) {
    let list = v.map(parse_addresses).unwrap_or_default();
    if list.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for a in list {
        out.push(b'(');
        match a {
            Addr::Mailbox {
                name,
                mailbox,
                host,
            } => {
                nstr(out, name.as_deref().map(str::as_bytes));
                out.extend_from_slice(b" NIL ");
                istr(out, mailbox.as_bytes());
                out.push(b' ');
                istr(out, host.as_bytes());
            }
            Addr::GroupStart(name) => {
                out.extend_from_slice(b"NIL NIL ");
                istr(out, name.as_bytes());
                out.extend_from_slice(b" NIL");
            }
            Addr::GroupEnd => out.extend_from_slice(b"NIL NIL NIL NIL"),
        }
        out.push(b')');
    }
    out.push(b')');
}

/// A lenient RFC 5322 address-list parser; encoded words stay encoded (IMAP sends them raw).
fn parse_addresses(v: &[u8]) -> Vec<Addr> {
    let s = String::from_utf8_lossy(v);
    let mut out = vec![];
    let mut item = String::new();
    let mut in_group = false;
    let (mut quoted, mut escaped, mut comment, mut angle) = (false, false, 0u32, false);
    let flush = |item: &mut String, out: &mut Vec<Addr>| {
        if let Some(a) = parse_mailbox(item) {
            out.push(a);
        }
        item.clear();
    };
    for c in s.chars() {
        if escaped {
            item.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted || comment > 0 => {
                item.push(c);
                escaped = true;
            }
            '"' if comment == 0 => {
                quoted = !quoted;
                item.push(c);
            }
            '(' if !quoted => {
                comment += 1;
                item.push(c);
            }
            ')' if !quoted && comment > 0 => {
                comment -= 1;
                item.push(c);
            }
            '<' if !quoted && comment == 0 => {
                angle = true;
                item.push(c);
            }
            '>' if !quoted && comment == 0 => {
                angle = false;
                item.push(c);
            }
            ':' if !quoted && comment == 0 && !angle && !in_group => {
                out.push(Addr::GroupStart(unquote(strip_comments(&item).trim())));
                item.clear();
                in_group = true;
            }
            ';' if !quoted && comment == 0 && !angle && in_group => {
                flush(&mut item, &mut out);
                out.push(Addr::GroupEnd);
                in_group = false;
            }
            ',' if !quoted && comment == 0 && !angle => flush(&mut item, &mut out),
            _ => item.push(c),
        }
    }
    flush(&mut item, &mut out);
    if in_group {
        out.push(Addr::GroupEnd);
    }
    out
}

fn strip_comments(s: &str) -> String {
    let mut out = String::new();
    let (mut depth, mut quoted, mut escaped) = (0u32, false, false);
    for c in s.chars() {
        if escaped {
            if depth == 0 {
                out.push(c);
            }
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted || depth > 0 => {
                escaped = true;
                if depth == 0 {
                    out.push(c);
                }
            }
            '"' if depth == 0 => {
                quoted = !quoted;
                out.push(c);
            }
            '(' if !quoted => depth += 1,
            ')' if !quoted && depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

fn parse_mailbox(item: &str) -> Option<Addr> {
    let clean = strip_comments(item);
    let clean = clean.trim();
    if clean.is_empty() {
        return None;
    }
    let (name, spec) = match (clean.find('<'), clean.rfind('>')) {
        (Some(l), Some(r)) if l < r => {
            let name = unquote(clean[..l].trim());
            let spec = &clean[l + 1..r];
            // Obsolete source route: <@a,@b:user@host>
            let spec = match spec.rfind(':') {
                Some(i) if spec.starts_with('@') => &spec[i + 1..],
                _ => spec,
            };
            ((!name.is_empty()).then_some(name), spec.trim().to_string())
        }
        _ => (None, clean.to_string()),
    };
    let spec = spec.replace(char::is_whitespace, "");
    let (mailbox, host) = match spec.rfind('@') {
        Some(i) => (spec[..i].to_string(), spec[i + 1..].to_string()),
        None => (spec.clone(), String::new()),
    };
    if mailbox.is_empty() && host.is_empty() {
        return None;
    }
    Some(Addr::Mailbox {
        name,
        mailbox: unquote(&mailbox),
        host,
    })
}

/// The header with only (or, with `not`, without) the named fields, plus the blank line.
pub fn header_fields(header: &[u8], names: &[String], not: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut keep = false;
    for line in header.split_inclusive(|b| *b == b'\n') {
        let bare = line.strip_suffix(b"\n").unwrap_or(line);
        let bare = bare.strip_suffix(b"\r").unwrap_or(bare);
        if bare.is_empty() {
            continue;
        }
        if bare[0] != b' ' && bare[0] != b'\t' {
            let name = bare
                .iter()
                .position(|b| *b == b':')
                .map(|c| String::from_utf8_lossy(&bare[..c]).trim().to_string())
                .unwrap_or_default();
            keep = names.iter().any(|n| n.eq_ignore_ascii_case(&name)) != not;
        }
        if keep {
            out.extend_from_slice(bare);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"From: \"Doe, Jane\" <jane@example.com>\r\nTo: a@b.c, Team: x@y.z, (c) w@v.u;\r\nSubject: =?UTF-8?B?w6k=?=\r\nContent-Type: multipart/mixed; boundary=\"XX\"\r\n\r\npreamble\r\n--XX\r\nContent-Type: text/plain\r\n\r\nhello\r\n--XX\r\nContent-Type: message/rfc822\r\n\r\nSubject: inner\r\nContent-Type: multipart/alternative; boundary=YY\r\n\r\n--YY\r\n\r\ninner text\r\n--YY\r\nContent-Type: text/html\r\n\r\n<p>x</p>\r\n--YY--\r\n\r\n--XX--\r\nepilogue\r\n";

    #[test]
    fn parts_and_sections() {
        let root = parse(MSG);
        let Kind::Multipart(children) = &root.kind else {
            panic!("multipart")
        };
        assert_eq!(children.len(), 2);
        assert_eq!(resolve(&root, &[1]).unwrap().body, b"hello");
        let inner = resolve(&root, &[2]).unwrap();
        assert!(matches!(inner.kind, Kind::Message(_)));
        assert_eq!(resolve(&root, &[2, 1]).unwrap().body, b"inner text");
        assert_eq!(resolve(&root, &[2, 2]).unwrap().body, b"<p>x</p>");
        assert!(resolve(&root, &[3]).is_none());
        // A single-part message: part 1 is its body.
        let single = parse(b"Subject: x\r\n\r\nbody\r\n");
        assert_eq!(resolve(&single, &[1]).unwrap().body, b"body\r\n");
        assert!(resolve(&single, &[2]).is_none());
        assert!(resolve(&single, &[1, 1]).is_none());
    }

    #[test]
    fn structure_and_envelope() {
        let root = parse(MSG);
        let mut bs = vec![];
        body_structure(&mut bs, &root, true);
        let bs = String::from_utf8(bs).unwrap();
        assert!(
            bs.starts_with("((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 5 1"),
            "{bs}"
        );
        assert!(bs.contains("\"MESSAGE\" \"RFC822\""), "{bs}");
        assert!(bs.contains("\"ALTERNATIVE\""), "{bs}");
        assert!(bs.contains(" \"MIXED\" (\"BOUNDARY\" \"XX\")"), "{bs}");
        let mut env = vec![];
        envelope(&mut env, &fields(root.header));
        let env = String::from_utf8(env).unwrap();
        assert!(
            env.contains("((\"Doe, Jane\" NIL \"jane\" \"example.com\"))"),
            "{env}"
        );
        assert!(env.contains("((NIL NIL \"a\" \"b.c\")(NIL NIL \"Team\" NIL)(NIL NIL \"x\" \"y.z\")(NIL NIL \"w\" \"v.u\")(NIL NIL NIL NIL))"), "{env}");
        assert!(env.contains("\"=?UTF-8?B?w6k=?=\""), "{env}");
    }

    #[test]
    fn header_field_selection() {
        let h = b"Subject: a\r\n b\r\nFrom: x\r\nTo: y\r\n\r\n";
        assert_eq!(
            header_fields(h, &["subject".into(), "TO".into()], false),
            b"Subject: a\r\n b\r\nTo: y\r\n\r\n"
        );
        assert_eq!(
            header_fields(h, &["subject".into()], true),
            b"From: x\r\nTo: y\r\n\r\n"
        );
    }

    #[test]
    fn strings() {
        let mut o = vec![];
        istr(&mut o, b"a\"b");
        assert_eq!(o, b"\"a\\\"b\"");
        let mut o = vec![];
        istr(&mut o, "é".as_bytes());
        assert_eq!(o, b"{2}\r\n\xc3\xa9");
    }
}
