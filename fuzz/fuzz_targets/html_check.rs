//! Minimal tag/attribute tokenizer for asserting that sanitized HTML is inert. Text content is
//! ignored (a "javascript:" in prose is harmless); tag names and attribute values are what count.

pub struct Tag {
    pub name: String,
    pub attrs: Vec<(String, String)>,
}

pub fn tags(html: &str) -> Vec<Tag> {
    let c: Vec<char> = html.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] != '<' {
            i += 1;
            continue;
        }
        i += 1;
        if i < c.len() && c[i] == '/' {
            i += 1;
        }
        let name: String = c[i..].iter().take_while(|ch| ch.is_ascii_alphanumeric() || **ch == '-').collect();
        i += name.chars().count();
        let mut attrs = Vec::new();
        loop {
            while i < c.len() && (c[i].is_whitespace() || c[i] == '/') {
                i += 1;
            }
            if i >= c.len() || c[i] == '>' {
                i += 1;
                break;
            }
            let start = i;
            while i < c.len() && !c[i].is_whitespace() && !matches!(c[i], '=' | '>' | '/') {
                i += 1;
            }
            let attr: String = c[start..i].iter().collect();
            let mut value = String::new();
            while i < c.len() && c[i].is_whitespace() {
                i += 1;
            }
            if i < c.len() && c[i] == '=' {
                i += 1;
                while i < c.len() && c[i].is_whitespace() {
                    i += 1;
                }
                if i < c.len() && (c[i] == '"' || c[i] == '\'') {
                    let q = c[i];
                    i += 1;
                    let s = i;
                    while i < c.len() && c[i] != q {
                        i += 1;
                    }
                    value = c[s..i.min(c.len())].iter().collect();
                    i += 1;
                } else {
                    let s = i;
                    while i < c.len() && !c[i].is_whitespace() && c[i] != '>' {
                        i += 1;
                    }
                    value = c[s..i].iter().collect();
                }
            }
            if attr.is_empty() {
                i += 1;
                continue;
            }
            attrs.push((attr.to_ascii_lowercase(), value));
        }
        out.push(Tag { name: name.to_ascii_lowercase(), attrs });
    }
    out
}

fn decode(v: &str) -> String {
    // Entities and whitespace/control characters that browsers ignore inside URLs.
    v.replace("&colon;", ":").replace("&#58;", ":").replace("&#x3a;", ":").replace("&tab;", "").replace("&newline;", "")
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Panics with a description if the sanitized HTML could run code or load remote content.
pub fn assert_inert(html: &str, allow_remote: bool) {
    const BAD_TAGS: &[&str] = &["script", "iframe", "frame", "frameset", "object", "embed", "applet", "form", "input", "button",
        "base", "meta", "link", "svg", "math", "style", "audio", "video", "source", "picture"];
    for t in tags(html) {
        assert!(!BAD_TAGS.contains(&t.name.as_str()), "<{}> survived: {html}", t.name);
        for (name, value) in &t.attrs {
            assert!(!name.starts_with("on"), "event handler {name} survived: {html}");
            let v = decode(value);
            if matches!(name.as_str(), "href" | "src" | "action" | "formaction" | "xlink:href" | "background" | "poster" | "srcset" | "cite") {
                for scheme in ["javascript:", "vbscript:", "data:text", "data:image/svg"] {
                    assert!(!v.starts_with(scheme), "{name}={value} survived: {html}");
                }
                if !allow_remote && name != "href" {
                    assert!(!v.starts_with("http") && !v.starts_with("//"), "remote {name}={value} survived: {html}");
                }
            }
            if name == "style" {
                assert!(!v.contains("url(") && !v.contains("expression(") && !v.contains("@import"), "style={value} survived: {html}");
            }
        }
    }
}
