//! `GET /`: a page for installing Malo's certificate authority on a device, opened in that
//! device's browser. The section for the visitor's platform (from the User-Agent) comes first and
//! is open; the downloads are the `/tls/malo-ca.*` files. No scripts, nothing loaded from elsewhere.

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Response};

use crate::state::SharedState;

#[derive(Clone, Copy, PartialEq)]
enum Platform {
    Iphone,
    Mac,
    Android,
    Windows,
    Linux,
}

const ORDER: [Platform; 5] = [
    Platform::Iphone,
    Platform::Mac,
    Platform::Android,
    Platform::Windows,
    Platform::Linux,
];

fn detect(user_agent: &str) -> Option<Platform> {
    let ua = user_agent.to_ascii_lowercase();
    // Order matters: Android user agents say Linux, iPhones say "like Mac OS X".
    if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod") {
        Some(Platform::Iphone)
    } else if ua.contains("android") {
        Some(Platform::Android)
    } else if ua.contains("windows") {
        Some(Platform::Windows)
    } else if ua.contains("macintosh") || ua.contains("mac os x") {
        Some(Platform::Mac)
    } else if ua.contains("linux") || ua.contains("x11") {
        Some(Platform::Linux)
    } else {
        None
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The fingerprint in four lines of eight bytes, easier to compare by eye.
fn fingerprint_lines(fp: &str) -> String {
    fp.split(':')
        .collect::<Vec<_>>()
        .chunks(8)
        .map(|c| c.join(":"))
        .collect::<Vec<_>>()
        .join("<br>")
}

/// Title, download (link and label) and steps of one platform.
fn section(p: Platform) -> (&'static str, &'static str, &'static str, &'static str) {
    match p {
        Platform::Iphone => (
            "iPhone and iPad",
            "tls/malo-ca.mobileconfig",
            "Download the profile",
            "<ol>\
             <li>Open this page in <strong>Safari</strong> and tap the button; allow the download.</li>\
             <li>Open <em>Settings</em> → <em>Profile Downloaded</em> → <em>Install</em>, and enter your passcode.</li>\
             <li>Then <em>Settings</em> → <em>General</em> → <em>About</em> → <em>Certificate Trust Settings</em>, and turn on <em>Malo certificate authority</em>. Without this step the device still won't trust the server.</li>\
             </ol>",
        ),
        Platform::Mac => (
            "Mac",
            "tls/malo-ca.mobileconfig",
            "Download the profile",
            "<ol>\
             <li>Open <em>System Settings</em> → <em>General</em> → <em>Device Management</em> (on older macOS: <em>Profiles</em>), double-click <em>Malo server certificate</em> and choose <em>Install</em>.</li>\
             <li>Mail and Safari trust the server from now on.</li>\
             </ol>\
             <p class=\"aside\">Using an iPad with a desktop browser? Follow the iPhone steps.</p>",
        ),
        Platform::Android => (
            "Android",
            "tls/malo-ca.crt",
            "Download the certificate",
            "<ol>\
             <li>Open <em>Settings</em> → <em>Security &amp; privacy</em> → <em>More security settings</em> → <em>Encryption &amp; credentials</em> → <em>Install a certificate</em> → <em>CA certificate</em> (names differ a little between phones; search Settings for “certificate”).</li>\
             <li>Choose <em>Install anyway</em> and pick the downloaded <code>malo-ca.crt</code>.</li>\
             </ol>\
             <p class=\"aside\">Some apps, like Gmail and Outlook, ignore certificates you install. Thunderbird, K-9 Mail and FairEmail use them.</p>",
        ),
        Platform::Windows => (
            "Windows",
            "tls/malo-ca.crt",
            "Download the certificate",
            "<ol>\
             <li>Open the downloaded certificate and choose <em>Install Certificate…</em>.</li>\
             <li>Pick <em>Current User</em>, then <em>Place all certificates in the following store</em> → <em>Browse…</em> → <em>Trusted Root Certification Authorities</em>.</li>\
             <li>Finish and confirm the security warning. Outlook, Edge and Chrome trust the server from now on.</li>\
             </ol>\
             <p class=\"aside\">Thunderbird keeps its own list: <em>Settings</em> → <em>Privacy &amp; Security</em> → <em>Manage Certificates</em> → <em>Authorities</em> → <em>Import</em>, and tick “Trust this CA to identify websites”.</p>",
        ),
        Platform::Linux => (
            "Linux",
            "tls/malo-ca.pem",
            "Download the certificate",
            "<ol>\
             <li>Debian, Ubuntu:<code class=\"cmd\">sudo cp malo-ca.pem /usr/local/share/ca-certificates/malo-ca.crt\nsudo update-ca-certificates</code></li>\
             <li>Fedora, Arch:<code class=\"cmd\">sudo trust anchor --store malo-ca.pem</code></li>\
             </ol>\
             <p class=\"aside\">Thunderbird and Firefox keep their own list: <em>Settings</em> → <em>Privacy &amp; Security</em> → <em>Manage Certificates</em> → <em>Authorities</em> → <em>Import</em>.</p>",
        ),
    }
}

pub async fn page(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let html = render(state.tls_ca.as_ref(), detect(ua));
    (
        [(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
        )],
        Html(html),
    )
        .into_response()
}

fn render(ca: Option<&crate::tlsgen::CaInfo>, here: Option<Platform>) -> String {
    let body = match ca {
        None => "<h1>Nothing to install</h1>\
                 <p class=\"lede\">This Malo server uses a certificate from its administrator, not one Malo issues itself, so devices don't need anything from here.</p>"
            .to_string(),
        Some(ca) => {
            let fp = malo_core::tls::fingerprint(&ca.der);
            // The names people use; localhost and the like only matter on the server itself.
            let shown: Vec<String> = ca
                .names
                .iter()
                .filter(|n| !["localhost", "malo", "127.0.0.1", "::1"].contains(&n.as_str()))
                .map(|n| format!("<code>{}</code>", esc(n)))
                .collect();
            let names = match shown.len() {
                0 => "this computer".to_string(),
                _ => format!("at {}", shown.join(", ")),
            };
            let mut platforms: Vec<Platform> = here.into_iter().collect();
            platforms.extend(ORDER.iter().filter(|p| Some(**p) != here));
            let sections: String = platforms
                .iter()
                .map(|p| {
                    let (title, href, label, steps) = section(*p);
                    let open = if Some(*p) == here { " open" } else { "" };
                    let tag = if Some(*p) == here {
                        "<span class=\"tag\">This device</span>"
                    } else {
                        ""
                    };
                    format!(
                        "<details{open}><summary><span>{title}</span>{tag}</summary>\
                         <div class=\"inner\"><a class=\"button\" href=\"{href}\" download>{label}</a>{steps}</div></details>"
                    )
                })
                .collect();
            format!(
                "<h1>Trust this Malo server</h1>\
                 <p class=\"lede\">Install Malo's certificate once on each device that reads backed-up mail. Mail apps and browsers then connect without warnings. The certificate can only vouch for this server, {names}, and nothing else.</p>\
                 <div class=\"platforms\">{sections}</div>\
                 <section class=\"check\"><h2>Before you trust it</h2>\
                 <p>When installing, the device shows the certificate's SHA-256 fingerprint. It must match the one in the Malo app (<em>Accounts</em> → <em>Mail app</em>) and in the server log:</p>\
                 <p class=\"fp\">{fp}</p>\
                 <p>Install it once: the server renews its own certificate every year without needing anything new on your devices.</p></section>",
                fp = fingerprint_lines(&fp),
            )
        }
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Trust this Malo server</title>
<style>
:root {{
  --frame: #f2f2f3; --panel: #ffffff; --raised: #f4f4f5; --text: #18181b; --muted: #71717a;
  --line: #e4e4e7; --accent: #2563eb; --accent-2: #2563eb;
  color-scheme: light dark;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --frame: #141414; --panel: #1a1a1a; --raised: #232323; --text: #ededed; --muted: #8f8f8f;
    --line: #262626; --accent: #2f6fed; --accent-2: #5b8ff9; }}
}}
* {{ box-sizing: border-box; }}
html {{ font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--text); background: var(--frame); -webkit-text-size-adjust: 100%; }}
body {{ margin: 0; padding: 48px 16px 64px; }}
main {{ max-width: 620px; margin: 0 auto; }}
.mark {{ display: inline-grid; place-items: center; width: 40px; height: 40px; border-radius: 12px; background: var(--accent); color: #fff; font-weight: 700; font-size: 20px; margin-bottom: 20px; }}
h1 {{ font-size: 1.75rem; line-height: 1.2; letter-spacing: -0.02em; margin: 0 0 10px; font-weight: 650; }}
h2 {{ font-size: 1rem; margin: 0 0 6px; }}
.lede {{ color: var(--muted); margin: 0 0 28px; }}
code {{ font: 0.85em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--raised); padding: 1px 5px; border-radius: 5px; overflow-wrap: anywhere; }}
code.cmd {{ display: block; white-space: pre; overflow-x: auto; overflow-wrap: normal; margin: 6px 0 4px; padding: 10px 12px; border-radius: 8px; line-height: 1.6; }}
.platforms {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }}
details + details {{ border-top: 1px solid var(--line); }}
summary {{ list-style: none; cursor: pointer; display: flex; align-items: center; gap: 10px; padding: 16px 18px; font-weight: 600; }}
summary::-webkit-details-marker {{ display: none; }}
summary::after {{ content: ""; margin-left: auto; width: 8px; height: 8px; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: rotate(45deg); transition: transform 200ms cubic-bezier(0.22, 1, 0.36, 1); }}
details[open] > summary::after {{ transform: rotate(225deg); }}
summary:hover {{ background: var(--raised); }}
summary:focus-visible {{ outline: 2px solid var(--accent-2); outline-offset: -2px; }}
.tag {{ font-size: 0.75rem; font-weight: 600; color: var(--accent-2); background: color-mix(in srgb, var(--accent) 14%, transparent); padding: 2px 8px; border-radius: 999px; }}
.inner {{ padding: 2px 18px 18px; }}
.button {{ display: inline-block; background: var(--accent); color: #fff; text-decoration: none; font-weight: 600; padding: 11px 18px; border-radius: 10px; transition: transform 300ms cubic-bezier(0.34, 1.56, 0.64, 1), background-color 150ms; }}
.button:hover {{ background: color-mix(in srgb, var(--accent) 85%, white); }}
.button:active {{ transform: scale(0.97); transition-duration: 80ms; }}
.button:focus-visible {{ outline: 2px solid var(--accent-2); outline-offset: 2px; }}
ol {{ margin: 16px 0 0; padding-left: 22px; }}
li {{ margin: 6px 0; }}
li::marker {{ color: var(--muted); }}
.aside {{ color: var(--muted); font-size: 0.9rem; margin: 12px 0 0; }}
.check {{ margin-top: 32px; color: var(--muted); font-size: 0.95rem; }}
.check h2 {{ color: var(--text); }}
.fp {{ font: 0.85rem/1.7 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--text); background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; word-break: break-all; }}
@media (prefers-reduced-motion: reduce) {{ * {{ transition: none !important; }} }}
</style>
</head>
<body><main><div class="mark" aria-hidden="true">M</div>{body}</main></body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platforms_from_user_agents() {
        let cases = [
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15",
                Some(Platform::Iphone),
            ),
            (
                "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 Chrome/130",
                Some(Platform::Android),
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                Some(Platform::Windows),
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15",
                Some(Platform::Mac),
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
                Some(Platform::Linux),
            ),
            ("curl/8.5.0", None),
        ];
        for (ua, want) in cases {
            assert!(detect(ua) == want, "{ua}");
        }
    }

    #[test]
    fn page_puts_this_device_first() {
        let ca = crate::tlsgen::CaInfo {
            der: vec![1, 2, 3],
            names: vec!["localhost".into(), "10.0.0.1".into(), "<b>".into()],
        };
        let html = render(Some(&ca), Some(Platform::Android));
        let android = html.find("<span>Android</span>").unwrap();
        assert!(android < html.find("<span>iPhone and iPad</span>").unwrap());
        assert!(html.contains("<details open><summary><span>Android</span>"));
        assert_eq!(html.matches("<details open>").count(), 1);
        assert!(html.contains("href=\"tls/malo-ca.crt\""));
        assert!(html.contains("&lt;b&gt;") && !html.contains("<code><b>"));
        assert!(render(None, None).contains("Nothing to install"));
    }
}
