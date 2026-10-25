//! Safe viewer: parse with mail-parser, plain text by default, sanitized HTML on request.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use base64::Engine;
use mail_parser::{MessageParser, MimeHeaders, PartType};
use malo_api::{AttachmentInfo, MessageView};

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "com", "bat", "cmd", "scr", "pif", "msi", "msp", "dll", "cpl", "js", "jse", "vbs",
    "vbe", "wsf", "wsh", "ps1", "psm1", "jar", "hta", "lnk", "reg", "app", "apk", "dmg", "pkg",
    "iso", "img", "vhd", "sh", "command", "docm", "xlsm", "pptm", "dotm", "xlam", "one",
    "appimage", "deb", "rpm", "run",
];

const SAFE_INLINE_IMAGE_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
];

const STYLE_PROPERTIES: &[&str] = &[
    "color",
    "background-color",
    "font",
    "font-family",
    "font-size",
    "font-style",
    "font-weight",
    "text-align",
    "text-decoration",
    "text-transform",
    "line-height",
    "letter-spacing",
    "white-space",
    "vertical-align",
    "margin",
    "margin-top",
    "margin-bottom",
    "margin-left",
    "margin-right",
    "padding",
    "padding-top",
    "padding-bottom",
    "padding-left",
    "padding-right",
    "border",
    "border-top",
    "border-bottom",
    "border-left",
    "border-right",
    "border-color",
    "border-width",
    "border-style",
    "border-collapse",
    "border-radius",
    "width",
    "max-width",
    "min-width",
    "height",
    "max-height",
    "display",
    "list-style-type",
    "direction",
];

pub struct SanitizedHtml {
    pub html: String,
    pub remote_blocked: u32,
}

fn style_is_safe(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    !(l.contains('\\')
        || l.contains("url(")
        || l.contains("expression")
        || l.contains("@import")
        || l.contains("javascript:"))
}

/// Sanitizes HTML with ammonia. Scripts, handlers, forms, frames, objects, meta refresh and
/// `javascript:` are removed; remote resources become placeholders unless `allow_remote`;
/// `cid:` references are inlined from `inline_parts` as `data:` URIs.
pub fn sanitize_html(
    html: &str,
    inline_parts: &HashMap<String, String>,
    allow_remote: bool,
) -> SanitizedHtml {
    let blocked = Arc::new(AtomicU32::new(0));
    let counter = blocked.clone();
    let parts = inline_parts.clone();
    let mut b = ammonia::Builder::default();
    b.url_schemes(HashSet::from(["http", "https", "mailto", "cid", "data"]))
        .link_rel(Some("noopener noreferrer nofollow"))
        .strip_comments(true)
        .add_generic_attributes(["style"])
        .add_tag_attributes("td", ["width", "height", "valign", "bgcolor"])
        .add_tag_attributes(
            "table",
            ["width", "cellpadding", "cellspacing", "border", "bgcolor"],
        )
        .add_tag_attributes("font", ["color", "size", "face"])
        .add_tags(["font", "center"])
        .rm_tags([
            "form", "input", "button", "select", "textarea", "iframe", "frame", "frameset",
            "object", "embed", "applet", "base", "meta", "link", "svg", "math", "audio", "video",
            "source", "track", "picture",
        ])
        .filter_style_properties(STYLE_PROPERTIES.iter().copied().collect())
        .attribute_filter(move |element, attribute, value| -> Option<Cow<str>> {
            let v = value.trim();
            let lower = v.to_ascii_lowercase();
            match (element, attribute) {
                ("img", "src") => {
                    if let Some(cid) = lower.strip_prefix("cid:") {
                        let key = cid.trim_matches(|c| c == '<' || c == '>').to_string();
                        return parts.get(&key).map(|d| Cow::Owned(d.clone()));
                    }
                    if lower.starts_with("data:") {
                        return SAFE_INLINE_IMAGE_TYPES
                            .iter()
                            .any(|t| lower.starts_with(&format!("data:{t};")))
                            .then(|| Cow::Owned(v.to_string()));
                    }
                    if lower.starts_with("http://")
                        || lower.starts_with("https://")
                        || lower.starts_with("//")
                    {
                        if allow_remote && lower.starts_with("https://") {
                            return Some(Cow::Owned(v.to_string()));
                        }
                        counter.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    None
                }
                ("a", "href") => {
                    if lower.starts_with("http://")
                        || lower.starts_with("https://")
                        || lower.starts_with("mailto:")
                    {
                        Some(Cow::Owned(v.to_string()))
                    } else {
                        None
                    }
                }
                (_, "style") => style_is_safe(v).then(|| Cow::Owned(v.to_string())),
                (_, "background") | (_, "srcset") | (_, "poster") => {
                    counter.fetch_add(1, Ordering::Relaxed);
                    None
                }
                (_, "cite") => None,
                _ => {
                    if lower.starts_with("data:") || lower.starts_with("cid:") {
                        None
                    } else {
                        Some(Cow::Owned(v.to_string()))
                    }
                }
            }
        });
    let html = b.clean(html).to_string();
    SanitizedHtml {
        html,
        remote_blocked: blocked.load(Ordering::Relaxed),
    }
}

fn address_list(a: Option<&mail_parser::Address>) -> Vec<String> {
    a.map(|a| {
        a.iter()
            .map(|x| match (x.name(), x.address()) {
                (Some(n), Some(e)) => format!("{n} <{e}>"),
                (None, Some(e)) => e.to_string(),
                (Some(n), None) => n.to_string(),
                _ => String::new(),
            })
            .filter(|s| !s.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

static EMAIL_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(r"(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}").unwrap()
});
static DOMAIN_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(
        r"(?i)\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|co|de|uk|fr|bank|gov|edu|info|biz|app)\b",
    )
    .unwrap()
});

/// Warns when the display name contains an address or domain that differs from the real sender.
pub fn display_name_warning(name: Option<&str>, address: &str) -> Option<String> {
    let name = name?;
    let addr = address.to_ascii_lowercase();
    let domain = addr.rsplit('@').next().unwrap_or("");
    if let Some(m) = EMAIL_RE.find(name) {
        if m.as_str().to_ascii_lowercase() != addr {
            return Some(format!(
                "Display name shows \"{}\" but the message was sent from {address}",
                m.as_str()
            ));
        }
    } else if let Some(m) = DOMAIN_RE.find(name) {
        let shown = m.as_str().to_ascii_lowercase();
        if !domain.ends_with(&shown) {
            return Some(format!(
                "Display name mentions {shown} but the sender domain is {domain}"
            ));
        }
    }
    None
}

fn extension(name: &str) -> Option<String> {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
}

/// Hidden or direction-changing characters (zero-width, RLO …), excluding ordinary whitespace.
pub fn hidden_characters(s: &str) -> Vec<String> {
    let mut found: Vec<String> = s
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r') && crate::layout::is_invisible(*c))
        .map(|c| format!("U+{:04X}", c as u32))
        .collect();
    found.dedup();
    found
}

/// Sender domains that use punycode or non-ASCII letters can imitate well-known domains.
pub fn lookalike_domain_warning(address: &str) -> Option<String> {
    let domain = address.rsplit('@').next()?.to_ascii_lowercase();
    if domain.split('.').any(|l| l.starts_with("xn--")) || !domain.is_ascii() {
        return Some(format!(
            "Sender domain {domain} uses non-ASCII characters that can imitate other domains"
        ));
    }
    None
}

pub fn attachment_warnings(filename: &str, declared: &str, sniffed: Option<&str>) -> Vec<String> {
    let mut w = Vec::new();
    let hidden = hidden_characters(filename);
    if !hidden.is_empty() {
        w.push(format!(
            "File name contains hidden or text-direction characters ({}): the name you see may not be the real one",
            hidden.join(", ")
        ));
    }
    if let Some(ext) = extension(filename) {
        if EXECUTABLE_EXTENSIONS.contains(&ext.as_str()) {
            w.push(format!("Executable or macro-capable file type (.{ext})"));
        }
    }
    // Double extensions like invoice.pdf.exe
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() > 2
        && extension(filename).is_some_and(|e| EXECUTABLE_EXTENSIONS.contains(&e.as_str()))
    {
        w.push("Double file extension".into());
    }
    if let Some(s) = sniffed {
        let declared_base = declared
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !declared_base.is_empty()
            && declared_base != "application/octet-stream"
            && declared_base != s
        {
            w.push(format!(
                "Declared as {declared_base} but content looks like {s}"
            ));
        }
        if matches!(
            s,
            "application/x-executable"
                | "application/vnd.microsoft.portable-executable"
                | "application/x-mach-binary"
                | "application/x-msdownload"
                | "application/x-elf"
                | "application/x-sh"
        ) {
            w.push("Content is an executable program".into());
        }
    }
    w
}

fn content_type_of(part: &mail_parser::MessagePart) -> String {
    part.content_type()
        .map(|c| match c.subtype() {
            Some(s) => format!("{}/{}", c.ctype(), s),
            None => c.ctype().to_string(),
        })
        .unwrap_or_else(|| "application/octet-stream".into())
        .to_ascii_lowercase()
}

pub fn render(
    id: i64,
    raw: &[u8],
    want_html: bool,
    allow_remote: bool,
) -> anyhow::Result<MessageView> {
    let msg = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| anyhow::anyhow!("cannot parse message"))?;
    let from = msg.from().and_then(|a| a.first());
    let from_addr = from.and_then(|a| a.address()).unwrap_or("").to_string();
    let from_name = from.and_then(|a| a.name()).map(str::to_string);
    let mut warnings = Vec::new();
    if let Some(w) = display_name_warning(from_name.as_deref(), &from_addr) {
        warnings.push(w);
    }
    if let Some(w) = lookalike_domain_warning(&from_addr) {
        warnings.push(w);
    }
    for (what, value) in [
        ("sender name", from_name.as_deref().unwrap_or("")),
        ("subject", msg.subject().unwrap_or("")),
    ] {
        let hidden = hidden_characters(value);
        if !hidden.is_empty() {
            warnings.push(format!(
                "The {what} contains hidden or text-direction characters ({})",
                hidden.join(", ")
            ));
        }
    }
    if let (Some(rp), false) = (msg.return_address(), from_addr.is_empty()) {
        let rd = rp.rsplit('@').next().unwrap_or("").to_ascii_lowercase();
        let fd = from_addr
            .rsplit('@')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if !rd.is_empty() && !fd.is_empty() && !rd.ends_with(&fd) && !fd.ends_with(&rd) {
            warnings.push(format!(
                "Return-Path domain {rd} differs from From domain {fd}"
            ));
        }
    }
    let headers: Vec<(String, String)> = msg
        .headers_raw()
        .map(|(k, v)| {
            (
                k.to_string(),
                v.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    let authentication_results: Vec<String> = headers
        .iter()
        .filter(|(k, _)| {
            k.eq_ignore_ascii_case("Authentication-Results")
                || k.eq_ignore_ascii_case("ARC-Authentication-Results")
        })
        .map(|(_, v)| v.clone())
        .collect();
    if !authentication_results.is_empty()
        && authentication_results.iter().any(|r| {
            let l = r.to_ascii_lowercase();
            l.contains("dmarc=fail") || l.contains("spf=fail") || l.contains("dkim=fail")
        })
    {
        warnings.push("Sender authentication failed (SPF/DKIM/DMARC)".into());
    }

    let has_html = msg.html_bodies().any(|p| p.is_content_type("text", "html"));
    let text = msg.body_text(0).map(|t| t.into_owned()).unwrap_or_default();

    // Inline images referenced by Content-ID.
    let mut inline_parts = HashMap::new();
    for part in msg.parts.iter() {
        if let (Some(cid), PartType::InlineBinary(data) | PartType::Binary(data)) =
            (part.content_id(), &part.body)
        {
            let ct = content_type_of(part);
            if SAFE_INLINE_IMAGE_TYPES.contains(&ct.as_str()) {
                let b64 = base64::engine::general_purpose::STANDARD.encode(data);
                inline_parts.insert(
                    cid.trim_matches(|c| c == '<' || c == '>')
                        .to_ascii_lowercase(),
                    format!("data:{ct};base64,{b64}"),
                );
            }
        }
    }
    let (html, remote_blocked) = if want_html && has_html {
        let raw_html = msg.body_html(0).map(|h| h.into_owned()).unwrap_or_default();
        let s = sanitize_html(&raw_html, &inline_parts, allow_remote);
        (Some(s.html), s.remote_blocked)
    } else {
        (None, 0)
    };

    let attachments = msg
        .attachments()
        .enumerate()
        .map(|(i, part)| {
            let filename = part
                .attachment_name()
                .map(str::to_string)
                .unwrap_or_else(|| format!("attachment-{}", i + 1));
            let declared = content_type_of(part);
            let contents = part.contents();
            let sniffed = infer::get(contents).map(|t| t.mime_type().to_string());
            let warnings = attachment_warnings(&filename, &declared, sniffed.as_deref());
            AttachmentInfo {
                index: i as u32,
                filename,
                declared_type: declared,
                sniffed_type: sniffed,
                size: contents.len() as u64,
                warnings,
            }
        })
        .collect();

    Ok(MessageView {
        id,
        headers,
        from: from_addr,
        from_name,
        to: address_list(msg.to()),
        cc: address_list(msg.cc()),
        subject: msg.subject().unwrap_or("").to_string(),
        date: msg
            .date()
            .and_then(|d| chrono::DateTime::from_timestamp(d.to_timestamp(), 0)),
        text,
        html,
        has_html,
        remote_blocked,
        remote_allowed: allow_remote,
        authentication_results,
        warnings,
        attachments,
    })
}

/// Returns `(filename, declared content type, bytes)` of attachment `n`.
pub fn attachment(raw: &[u8], n: u32) -> anyhow::Result<(String, String, Vec<u8>)> {
    let msg = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| anyhow::anyhow!("cannot parse message"))?;
    let part = msg
        .attachments()
        .nth(n as usize)
        .ok_or_else(|| anyhow::anyhow!("no attachment {n}"))?;
    let filename = part
        .attachment_name()
        .map(str::to_string)
        .unwrap_or_else(|| format!("attachment-{}", n + 1));
    Ok((filename, content_type_of(part), part.contents().to_vec()))
}

/// Envelope summary from a full message (used when rebuilding from raw).
pub fn envelope_of(raw: &[u8]) -> malo_api::Envelope {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return crate::index::empty_envelope();
    };
    let from = msg.from().and_then(|a| a.first());
    malo_api::Envelope {
        from: from.and_then(|a| a.address()).unwrap_or("").to_string(),
        from_name: from.and_then(|a| a.name()).map(str::to_string),
        to: msg
            .to()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.address().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        subject: msg.subject().unwrap_or("").to_string(),
        date: msg
            .date()
            .and_then(|d| chrono::DateTime::from_timestamp(d.to_timestamp(), 0)),
        message_id: msg.message_id().map(|m| format!("<{m}>")),
        attachment_count: msg.attachment_count() as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(html: &str) -> SanitizedHtml {
        sanitize_html(html, &HashMap::new(), false)
    }

    #[test]
    fn sanitizer_corpus() {
        let corpus = [
            "<script>alert(1)</script><p>hi</p>",
            "<img src=x onerror=alert(1)>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<a href=\"JaVaScRiPt:alert(1)\">x</a>",
            "<a href=\" javascript:alert(1)\">x</a>",
            "<meta http-equiv=\"refresh\" content=\"0;url=https://evil\">",
            "<iframe src=\"https://evil\"></iframe>",
            "<object data=\"x\"></object><embed src=\"x\">",
            "<form action=\"https://evil\"><input name=p></form>",
            "<svg onload=alert(1)><script>alert(1)</script></svg>",
            "<svg><a xlink:href=\"javascript:alert(1)\">x</a></svg>",
            "<div style=\"background:url(https://evil/track.gif)\">x</div>",
            "<div style=\"background-image: u\\72l(https://evil)\">x</div>",
            "<div style=\"width: expression(alert(1))\">x</div>",
            "<style>@import url(https://evil/x.css); body{background:url(https://evil)}</style>",
            "<body onload=alert(1)>",
            "<link rel=stylesheet href=https://evil/x.css>",
            "<base href=\"https://evil/\">",
            "<table background=\"https://evil/bg.png\"><tr><td>x</td></tr></table>",
            "<img srcset=\"https://evil/a.png 1x\">",
            "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>",
            "<img src=\"data:image/svg+xml,<svg onload=alert(1)>\">",
            "<p onclick=\"alert(1)\" onmouseover=\"x()\">p</p>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        ];
        for input in corpus {
            let out = clean(input).html.to_ascii_lowercase();
            for bad in [
                "<script",
                "onerror",
                "onload",
                "onclick",
                "onmouseover",
                "javascript:",
                "<iframe",
                "<object",
                "<embed",
                "<form",
                "<input",
                "<meta",
                "<svg",
                "<link",
                "<base",
                "url(",
                "expression",
                "@import",
                "https://evil",
                "data:text",
                "svg+xml",
            ] {
                assert!(!out.contains(bad), "{input:?} → {out:?} contains {bad}");
            }
        }
    }

    #[test]
    fn remote_images_blocked_unless_allowed() {
        let html =
            "<p>x</p><img src=\"https://tracker.example/p.gif\"><img src=\"http://x/y.png\">";
        let s = clean(html);
        assert_eq!(s.remote_blocked, 2);
        assert!(!s.html.contains("tracker"));
        let allowed = sanitize_html(html, &HashMap::new(), true);
        assert!(allowed.html.contains("https://tracker.example/p.gif"));
        assert!(
            !allowed.html.contains("http://x/y.png"),
            "plain http stays blocked"
        );
    }

    #[test]
    fn cid_inlined_and_links_kept() {
        let parts = HashMap::from([(
            "logo@x".to_string(),
            "data:image/png;base64,AAAA".to_string(),
        )]);
        let s = sanitize_html(
            "<img src=\"cid:logo@x\"><a href=\"https://ok.example\">ok</a>",
            &parts,
            false,
        );
        assert!(s.html.contains("data:image/png;base64,AAAA"));
        assert!(s.html.contains("href=\"https://ok.example\""));
        assert!(s.html.contains("noopener"));
    }

    #[test]
    fn unicode_tricks_are_flagged() {
        let w = attachment_warnings("invoice\u{202E}fdp.exe", "application/pdf", None);
        assert!(w.iter().any(|x| x.contains("U+202E")), "{w:?}");
        assert!(
            w.iter().any(|x| x.contains("Executable")),
            "real extension is .exe: {w:?}"
        );
        assert!(lookalike_domain_warning("ceo@xn--pypal-4ve.com").is_some());
        assert!(lookalike_domain_warning("ceo@pаypal.com").is_some()); // Cyrillic а
        assert!(lookalike_domain_warning("ceo@paypal.com").is_none());
        let raw = "From: \"Pay\u{200B}Pal\" <x@xn--pypal-4ve.com>\r\nSubject: Re\u{202E}gnp.exe\r\n\r\nbody".as_bytes();
        let v = render(1, raw, false, false).unwrap();
        assert!(
            v.warnings.iter().any(|x| x.contains("sender name")),
            "{:?}",
            v.warnings
        );
        assert!(
            v.warnings.iter().any(|x| x.contains("subject")),
            "{:?}",
            v.warnings
        );
        assert!(
            v.warnings.iter().any(|x| x.contains("imitate")),
            "{:?}",
            v.warnings
        );
    }

    #[test]
    fn unicode_url_tricks_are_not_links() {
        for href in [
            "jav\u{200B}ascript:alert(1)",
            "ｊａｖａｓｃｒｉｐｔ:alert(1)",
            "java\u{0}script:alert(1)",
            "\u{202E}:tpircsavaj",
        ] {
            let out =
                sanitize_html(&format!("<a href=\"{href}\">x</a>"), &HashMap::new(), false).html;
            assert!(!out.contains("href"), "{href:?} → {out}");
        }
    }

    /// Arbitrary bytes and hostile Unicode in headers, bodies and filenames never crash the viewer.
    #[test]
    fn random_messages_never_panic() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let nasty = [
            "\u{202E}",
            "\u{200B}",
            "\u{FEFF}",
            "\u{0}",
            "=?UTF-8?B?",
            "?=",
            "😀",
            "é",
            "\r\n",
            "\"",
            "<",
            ">",
            "&#0;",
            "%",
            "\\",
            "日本",
        ];
        for i in 0..2000 {
            let mut pick = |n: usize| -> String {
                (0..n)
                    .map(|_| nasty[rng.gen_range(0..nasty.len())])
                    .collect()
            };
            let raw = if i % 3 == 0 {
                (0..rng.gen_range(0..2000))
                    .map(|_| rand::random::<u8>())
                    .collect::<Vec<u8>>()
            } else {
                format!(
                    "From: \"{}\" <a{}@b.c>\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n--{}\r\nContent-Type: text/html\r\n\r\n<p title=\"{}\">{}</p><img src=\"cid:{}\">\r\n--{}\r\nContent-Disposition: attachment; filename=\"{}\"\r\n\r\n{}\r\n",
                    pick(5), pick(2), pick(8), "B", "B", pick(4), pick(30), pick(3), "B", pick(6), pick(20)
                )
                .into_bytes()
            };
            let _ = render(1, &raw, true, i % 2 == 0);
            let _ = attachment(&raw, 0);
            let _ = envelope_of(&raw);
            let _ = crate::imap::decode_words(&raw[..raw.len().min(200)]);
            let _ = sanitize_html(&String::from_utf8_lossy(&raw), &HashMap::new(), true);
        }
    }

    #[test]
    fn render_message() {
        let raw = b"From: \"PayPal Support paypal.com\" <evil@phish.example>\r\n\
To: me@example.com\r\nSubject: =?UTF-8?B?SGVsbG8gV8O2cmxk?=\r\n\
Authentication-Results: mx.example; spf=fail smtp.mailfrom=phish.example\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: multipart/alternative; boundary=\"c\"\r\n\r\n\
--c\r\nContent-Type: text/plain\r\n\r\nplain body\r\n\
--c\r\nContent-Type: text/html\r\n\r\n<p>html <script>x()</script><img src=\"https://t.example/x\"></p>\r\n--c--\r\n\
--b\r\nContent-Type: application/pdf; name=\"invoice.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA==\r\n--b--\r\n";
        let v = render(1, raw, false, false).unwrap();
        assert_eq!(v.subject, "Hello Wörld");
        assert!(v.text.contains("plain body"));
        assert!(v.html.is_none());
        assert!(v.has_html);
        assert!(
            v.warnings.iter().any(|w| w.contains("paypal.com")),
            "{:?}",
            v.warnings
        );
        assert!(v
            .warnings
            .iter()
            .any(|w| w.contains("authentication failed")));
        assert_eq!(v.attachments.len(), 1);
        let a = &v.attachments[0];
        assert!(
            a.warnings.iter().any(|w| w.contains("Executable")),
            "{:?}",
            a.warnings
        );
        assert!(
            a.warnings
                .iter()
                .any(|w| w.contains("Declared as application/pdf")),
            "{:?}",
            a.warnings
        );
        let v = render(1, raw, true, false).unwrap();
        let html = v.html.unwrap();
        assert!(!html.contains("script") && !html.contains("t.example"));
        assert_eq!(v.remote_blocked, 1);
        let (name, _, bytes) = attachment(raw, 0).unwrap();
        assert_eq!(name, "invoice.pdf.exe");
        assert_eq!(&bytes[..2], b"MZ");
    }
}
