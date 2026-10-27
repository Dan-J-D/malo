//! On-store object layout and mailbox name encoding.
//!
//! Plain:     `<root>/<account>/mailboxes/<Mailbox/Sub>/<uidvalidity>/<uid>.eml` + `manifest/<mailbox>.jsonl`
//! Encrypted: `<root>/<hmac(account)>/objects/<xx>/<hmac(sha256)>.enc` + `manifest/<hmac(mailbox)>.jsonl.enc`

use base64::Engine;

use crate::crypto::{self, Key};

/// Decodes an IMAP modified UTF-7 mailbox name (RFC 3501 §5.1.3). Invalid sequences are kept verbatim.
pub fn decode_utf7(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let Some(end) = after.find('-') else {
            out.push_str(&rest[pos..]);
            return out;
        };
        let chunk = &after[..end];
        if chunk.is_empty() {
            out.push('&');
        } else {
            match decode_utf7_chunk(chunk) {
                Some(s) => out.push_str(&s),
                None => out.push_str(&rest[pos..pos + 1 + end + 1]),
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn decode_utf7_chunk(chunk: &str) -> Option<String> {
    let b64 = chunk.replace(',', "/");
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(b64.as_bytes())
        .ok()?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Encodes a UTF-8 mailbox name as IMAP modified UTF-7.
pub fn encode_utf7(name: &str) -> String {
    let mut out = String::new();
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(bytes)
            .replace('/', ",");
        out.push('&');
        out.push_str(&b64);
        out.push('-');
        pending.clear();
    };
    for c in name.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// Makes one path component safe for every OpenDAL backend and common filesystems.
/// Unsafe characters are percent-encoded so the mapping stays reversible and collision-free.
/// Characters that render as nothing or reorder text: zero-width, bidi controls, BOM, invisible
/// fillers, tag characters, line/paragraph separators. Encoded so names can't hide or spoof text.
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202F}'
        | '\u{205F}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{FFF0}'..='\u{FFFB}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}')
        || c.is_control()
}

/// Longest encoded component kept as is; longer ones are shortened with a hash (filesystems allow 255 bytes).
const MAX_COMPONENT_BYTES: usize = 120;

fn short_hash(s: &str) -> String {
    crate::crypto::sha256_hex(s.as_bytes())[..8].to_string()
}

/// Makes one path component safe for every OpenDAL backend and common filesystems.
/// Unsafe and invisible characters are percent-encoded so the mapping stays collision-free, and
/// overlong names are shortened with a hash of the original.
pub fn safe_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        let unsafe_char = matches!(
            c,
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '%' | '#' | '~'
        ) || is_invisible(c)
            || (i == 0 && c == '.')
            || (i == 0 && c == ' ');
        if unsafe_char {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    if out.ends_with(' ') || out.ends_with('.') {
        let last = out.pop().unwrap();
        out.push_str(&format!("%{:02X}", last as u8));
    }
    if out.is_empty() {
        return "%00".into();
    }
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3",
    ];
    let upper = out.to_ascii_uppercase();
    let stem = upper.split('.').next().unwrap_or("");
    if RESERVED.contains(&stem) {
        out.insert_str(0, "%5F");
    }
    if out.len() > MAX_COMPONENT_BYTES {
        let mut cut = MAX_COMPONENT_BYTES - 10;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        // Never leave a dangling half escape like "%E".
        while let Some(i) = out.rfind('%') {
            if out.len() - i < 3 {
                out.truncate(i);
            } else {
                break;
            }
        }
        out.push('~');
        out.push_str(&short_hash(s));
    }
    out
}

/// Path of a mailbox: decoded from UTF-7, split on the hierarchy delimiter, each component made safe.
pub fn mailbox_path(raw_name: &str, delimiter: Option<&str>) -> String {
    let decoded = decode_utf7(raw_name);
    match delimiter.filter(|d| !d.is_empty()) {
        Some(d) => decoded
            .split(d)
            .map(safe_component)
            .collect::<Vec<_>>()
            .join("/"),
        None => safe_component(&decoded),
    }
}

/// Reversible ASCII-only form of a path (`~XX` escapes), for backends that mangle other characters
/// (OpenDAL's GCS service double-encodes object names on upload).
pub fn ascii_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("~{b:02X}"));
        }
    }
    out
}

/// Rejects storage paths that could leave their root or that object stores refuse: `..` or `.`
/// segments, backslashes, control characters and drive letters (`C:`). Every path handed to a
/// backend goes through this. (`%2E%2E` is fine: it is a literal name — Malo's own escaping of a
/// mailbox called `..` — and no backend decodes it.)
pub fn check_rel_path(path: &str) -> anyhow::Result<()> {
    // Control characters (newline, DEL, C1…) are refused by object stores and break listings.
    if path.contains('\\') || path.chars().any(char::is_control) {
        anyhow::bail!("path {path:?} contains a forbidden character");
    }
    for seg in path.split('/') {
        if seg == ".." || seg == "." {
            anyhow::bail!("path {path:?} must not contain '.' or '..' segments");
        }
        if seg.len() >= 2 && seg.as_bytes()[1] == b':' && seg.as_bytes()[0].is_ascii_alphabetic() {
            anyhow::bail!("path {path:?} must not contain a drive letter");
        }
    }
    Ok(())
}

pub fn join(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|p| p.trim_matches('/'))
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// Directory name of an account in the plain layout.
pub fn plain_account_dir(account_id: &str, account_name: &str) -> String {
    let short: String = account_id.chars().take(8).collect();
    safe_component(&format!("{account_name}_{short}"))
}

pub fn plain_object_path(
    root: &str,
    account_dir: &str,
    mailbox: &str,
    uidvalidity: u32,
    uid: u32,
) -> String {
    // The tag of the exact mailbox path keeps mailboxes that only differ in case or Unicode
    // normalization (`Work` / `work`, NFC / NFD) apart on case- or normalization-insensitive
    // filesystems (macOS, Windows), where they would otherwise share files.
    join(&[
        root,
        account_dir,
        "mailboxes",
        mailbox,
        &format!("{uidvalidity}-{}", short_hash(mailbox)),
        &format!("{uid}.eml"),
    ])
}

pub fn plain_manifest_path(root: &str, account_dir: &str, mailbox_path: &str) -> String {
    join(&[
        root,
        account_dir,
        "manifest",
        &format!("{mailbox_path}-{}.jsonl", short_hash(mailbox_path)),
    ])
}

/// Keyed names for the encrypted layout, derived from the archive key so a recovery kit can rebuild them.
pub struct NameKey(Key);

impl NameKey {
    pub fn new(archive_key: &Key) -> Self {
        NameKey(crypto::derive(archive_key.as_ref(), None, "malo/v1/names"))
    }
    pub fn account_dir(&self, account_id: &str) -> String {
        self.mac(&format!("account:{account_id}"))[..32].to_string()
    }
    pub fn object_path(&self, root: &str, account_dir: &str, sha256: &str) -> String {
        let h = self.mac(&format!("object:{sha256}"));
        join(&[root, account_dir, "objects", &h[..2], &format!("{h}.enc")])
    }
    /// Where a destination that compresses keeps the message: next to the uncompressed name, so
    /// recompressing an object writes a new one and never overwrites the only copy.
    pub fn compressed_object_path(&self, root: &str, account_dir: &str, sha256: &str) -> String {
        let h = self.mac(&format!("object:{sha256}"));
        join(&[root, account_dir, "objects", &h[..2], &format!("{h}.z.enc")])
    }
    pub fn manifest_path(&self, root: &str, account_dir: &str, mailbox: &str) -> String {
        let h = self.mac(&format!("mailbox:{mailbox}"));
        join(&[
            root,
            account_dir,
            "manifest",
            &format!("{}.jsonl.enc", &h[..32]),
        ])
    }
    /// The owner's folder inside a shared fs mount. It follows the archive key, not the user id,
    /// so a user restored with the recovery kit finds the same folder.
    pub fn owner_dir(&self) -> String {
        self.mac("owner")[..32].to_string()
    }
    /// The encrypted copy of the user's settings at the destination root (see `SettingsBackup`).
    pub fn settings_backup(&self, root: &str) -> String {
        join(&[
            root,
            &format!("malo-settings-{}.enc", &self.mac("settings")[..24]),
        ])
    }
    fn mac(&self, s: &str) -> String {
        crypto::hmac_hex(self.0.as_ref(), s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf7_round_trip() {
        assert_eq!(decode_utf7("INBOX"), "INBOX");
        assert_eq!(decode_utf7("Entw&APw-rfe"), "Entwürfe");
        assert_eq!(decode_utf7("&ZeVnLIqe-"), "日本語");
        assert_eq!(decode_utf7("Tom &- Jerry"), "Tom & Jerry");
        assert_eq!(decode_utf7("&2D3eAA-"), "😀");
        for s in [
            "Entwürfe",
            "日本語/子",
            "Tom & Jerry",
            "😀 smile",
            "plain",
            "a&b&c",
            "Ünïcödé",
        ] {
            assert_eq!(decode_utf7(&encode_utf7(s)), s, "{s}");
        }
        assert_eq!(encode_utf7("Entwürfe"), "Entw&APw-rfe");
        // Broken input is preserved.
        assert_eq!(decode_utf7("bad&@@@-x"), "bad&@@@-x");
        assert_eq!(decode_utf7("open&abc"), "open&abc");
    }

    #[test]
    fn safe_components() {
        assert_eq!(safe_component("INBOX"), "INBOX");
        assert_eq!(safe_component("a/b"), "a%2Fb");
        assert_eq!(safe_component(".."), "%2E%2E");
        assert_eq!(safe_component(".hidden"), "%2Ehidden");
        assert_eq!(safe_component("x:y*z?"), "x%3Ay%2Az%3F");
        assert_eq!(safe_component("100%"), "100%25");
        assert_eq!(safe_component("tab\there"), "tab%09here");
        assert_eq!(safe_component("trail."), "trail%2E");
        assert_eq!(safe_component(""), "%00");
        assert_eq!(safe_component("CON"), "%5FCON");
        assert_eq!(safe_component("Entwürfe"), "Entwürfe");
        // Distinct names never collide.
        assert_ne!(safe_component("a%2Fb"), safe_component("a/b"));
    }

    #[test]
    fn mailbox_paths() {
        assert_eq!(mailbox_path("INBOX/Sub/Deep", Some("/")), "INBOX/Sub/Deep");
        assert_eq!(mailbox_path("INBOX.Sub", Some(".")), "INBOX/Sub");
        assert_eq!(mailbox_path("INBOX.a/b", Some(".")), "INBOX/a%2Fb");
        assert_eq!(
            mailbox_path("[Gmail]/All Mail", Some("/")),
            "[Gmail]/All Mail"
        );
        assert_eq!(
            mailbox_path("Entw&APw-rfe/..", Some("/")),
            "Entwürfe/%2E%2E"
        );
        assert_eq!(mailbox_path("a/b", None), "a%2Fb");
        assert_eq!(
            plain_object_path("backup/", "Work_abcd1234", "INBOX/Sub", 7, 42),
            "backup/Work_abcd1234/mailboxes/INBOX/Sub/7-3a916558/42.eml"
        );
        assert_eq!(
            plain_object_path("", "a", "INBOX", 1, 2),
            format!("a/mailboxes/INBOX/1-{}/2.eml", short_hash("INBOX"))
        );
    }

    #[test]
    fn traversal_rejected() {
        for bad in [
            "..", "../x", "a/../b", "a/..", "./a", "a/./b", "a\\..\\b", "C:/x", "a/c:/x", "x\0y",
            "a\n|b", "a\rb", "a\tb", "a\u{7f}b", "a\u{85}b",
        ] {
            assert!(check_rel_path(bad).is_err(), "{bad:?} accepted");
        }
        for ok in [
            "",
            "a",
            "a/b/c.eml",
            "root/acc_1234/mailboxes/%2E%2Ehidden/1/2.eml",
            "a..b/c",
            "...",
            "x/.hidden.enc",
            "a/b/",
        ] {
            assert!(check_rel_path(ok).is_ok(), "{ok:?} rejected");
        }
        // Everything Malo generates from hostile mailbox and account names stays safe.
        for name in ["..", "../../etc", "a/../../b", "%2e%2e", ".", "C:\\x"] {
            let p = plain_object_path(
                "root",
                &plain_account_dir("0123456789", name),
                &mailbox_path(name, Some("/")),
                1,
                2,
            );
            assert!(check_rel_path(&p).is_ok(), "{name:?} → {p:?}");
        }
    }

    #[test]
    fn invisible_and_bidi_characters_are_encoded() {
        // "invoice<RLO>fdp.exe" would display as "invoiceexe.pdf".
        let c = safe_component("invoice\u{202E}fdp.exe");
        assert_eq!(c, "invoice%E2%80%AEfdp.exe");
        assert_eq!(safe_component("Work\u{200B}"), "Work%E2%80%8B");
        assert_eq!(safe_component("\u{FEFF}Inbox"), "%EF%BB%BFInbox");
        assert_ne!(safe_component("Work"), safe_component("Work\u{200B}"));
        // Visible Unicode stays readable, including emoji and look-alike dots (they are plain names).
        assert_eq!(safe_component("Entwürfe 日本 😀"), "Entwürfe 日本 😀");
        assert_eq!(safe_component("\u{FF0E}\u{FF0E}"), "\u{FF0E}\u{FF0E}");
        assert!(check_rel_path(&safe_component("\u{FF0E}\u{FF0E}")).is_ok());
    }

    #[test]
    fn long_names_are_shortened_uniquely() {
        let a = "😀".repeat(200);
        let b = format!("{}x", "😀".repeat(200));
        let (ca, cb) = (safe_component(&a), safe_component(&b));
        assert!(
            ca.len() <= MAX_COMPONENT_BYTES && cb.len() <= MAX_COMPONENT_BYTES,
            "{} {}",
            ca.len(),
            cb.len()
        );
        assert_ne!(ca, cb);
        let enc = safe_component(&"\u{200B}".repeat(100));
        assert!(enc.len() <= MAX_COMPONENT_BYTES);
        let before_tag = enc.rsplit_once('~').unwrap().0;
        assert!(
            !before_tag.ends_with('%')
                && before_tag
                    .rfind('%')
                    .is_none_or(|i| before_tag.len() - i >= 3),
            "{enc}"
        );
    }

    #[test]
    fn case_and_normalization_variants_never_share_files() {
        let paths: Vec<String> = ["Work", "work", "WORK", "Caf\u{e9}", "Cafe\u{301}"]
            .iter()
            .map(|m| plain_object_path("r", "a", &mailbox_path(m, Some("/")), 7, 1).to_lowercase())
            .collect();
        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(unique.len(), paths.len(), "{paths:?}");
    }

    /// Random Unicode (incl. surrogate-range UTF-7, invisible and bidi characters) never panics and
    /// never produces a path that escapes.
    #[test]
    fn random_unicode_never_panics_or_escapes() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let pool: Vec<char> =
            "./\\:%&-+,~ aZ0é日😀\u{202E}\u{200B}\u{FEFF}\u{0}\u{7F}\u{FF0E}\u{2024}"
                .chars()
                .collect();
        for _ in 0..20_000 {
            let len = rng.gen_range(0..40);
            let s: String = (0..len)
                .map(|_| {
                    if rng.gen_bool(0.8) {
                        pool[rng.gen_range(0..pool.len())]
                    } else {
                        char::from_u32(rng.gen_range(0..0x10FFFF)).unwrap_or('x')
                    }
                })
                .collect();
            let decoded = decode_utf7(&s);
            let _ = encode_utf7(&decoded);
            for delim in [Some("/"), Some("."), None] {
                let mp = mailbox_path(&s, delim);
                let p = plain_object_path("root", &plain_account_dir(&s, &s), &mp, 1, 2);
                assert!(check_rel_path(&p).is_ok(), "{s:?} → {p:?}");
                assert!(p.split('/').all(|c| c.len() <= MAX_COMPONENT_BYTES), "{p}");
            }
        }
    }

    #[test]
    fn ascii_paths() {
        assert_eq!(
            ascii_path("a b/Entwürfe/x~y%.eml"),
            "a~20b/Entw~C3~BCrfe/x~7Ey~25.eml"
        );
        assert_eq!(ascii_path("plain/path-1_2.eml"), "plain/path-1_2.eml");
    }

    #[test]
    fn encrypted_names_hide_metadata() {
        let k = crypto::random_key();
        let n = NameKey::new(&k);
        let dir = n.account_dir("acc-1");
        assert_eq!(dir.len(), 32);
        let p = n.object_path("root", &dir, "deadbeef");
        assert!(p.starts_with(&format!("root/{dir}/objects/")));
        assert!(!p.contains("deadbeef"));
        assert_eq!(p, n.object_path("root", &dir, "deadbeef"));
        assert_ne!(
            n.account_dir("acc-1"),
            NameKey::new(&crypto::random_key()).account_dir("acc-1")
        );
        assert!(!n.manifest_path("", &dir, "INBOX").contains("INBOX"));
    }
}
