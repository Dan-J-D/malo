//! Alerts (webhook, ntfy, Apprise, email) and exports (mbox, Maildir, zip), end to end against a
//! fake HTTP receiver and a fake SMTP server. Needs no Docker: failures come from closed ports,
//! and exported messages are put into the index and spool directly.
//!
//! ```sh
//! cargo test -p malo-server --test alerts_export
//! ```

mod common;

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use malo_api::*;
use malo_core::crypto::sha256_hex;
use malo_core::index::NewMessage;
use reqwest::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn setup_env() {
    std::env::set_var("MALO_INSECURE_FAST_KDF", "1");
    std::env::set_var("MALO_LOGIN_BURST", "1000");
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,malo=info")
        .with_test_writer()
        .try_init();
}

/// Requests a fake HTTP server received: (path, JSON body, authorization header).
type Seen = Arc<Mutex<Vec<(String, serde_json::Value, Option<String>)>>>;

/// Answers every POST with 200, except `/token` (an OAuth token endpoint refusing the refresh
/// token) and `/broken` (a 500).
async fn fake_http() -> (u16, Seen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Default::default();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = tcp.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_string();
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse().ok())?
                            })
                            .unwrap_or(0);
                        while buf.len() < i + 4 + len {
                            let n = tcp.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        break (head, buf[i + 4..].to_vec());
                    }
                };
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                let auth = head.lines().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("authorization")
                        .then(|| v.trim().to_string())
                });
                let json = serde_json::from_slice(&body).unwrap_or_else(|_| {
                    serde_json::Value::String(String::from_utf8_lossy(&body).into())
                });
                let (status, reply) = match path.as_str() {
                    "/token" => ("400 Bad Request", r#"{"error":"invalid_grant"}"#),
                    "/broken" => ("500 Internal Server Error", "nope"),
                    _ => ("200 OK", "{}"),
                };
                log.lock().unwrap().push((path, json, auth));
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = tcp.write_all(resp.as_bytes()).await;
            });
        }
    });
    (port, seen)
}

/// An IMAP server that greets and refuses everything: enough to get to the OAuth sign-in.
async fn fake_imap() -> u16 {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(malo_core::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = tls.write_all(b"* OK fake IMAP ready\r\n").await;
                let mut buf = [0u8; 1024];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    let tag = String::from_utf8_lossy(&buf[..n])
                        .split_whitespace()
                        .next()
                        .unwrap_or("*")
                        .to_string();
                    let _ = tls
                        .write_all(format!("{tag} NO go away\r\n").as_bytes())
                        .await;
                }
            });
        }
    });
    port
}

fn received(seen: &Seen, path: &str) -> Vec<serde_json::Value> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(p, _, _)| p == path)
        .map(|(_, j, _)| j.clone())
        .collect()
}

fn events(seen: &Seen, path: &str) -> Vec<String> {
    received(seen, path)
        .iter()
        .map(|j| j["event"].as_str().unwrap_or("").to_string())
        .collect()
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    // Up to a minute: a destination is retried a few times before it counts as unreachable.
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alerts() {
    setup_env();
    let (http_port, seen) = fake_http().await;
    let (smtp_port, smtp) = fake_smtp().await;
    let base = format!("http://127.0.0.1:{http_port}");
    let dir = tempfile::tempdir().unwrap();
    let r = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&r).await;
    let me: Me = admin.get("/me").await;

    // A mail server nobody answers on, and a destination that can't be reached.
    // Not scheduled: only the backups the test runs count.
    let mut input = imap_input("Work", "me@example.com", 1);
    input.enabled = false;
    input.smtp = Some(SmtpSettings {
        host: "localhost".into(),
        port: smtp_port,
        tls: TlsMode::Implicit,
    });
    let work: AccountView = admin.post("/accounts", &input).await;
    let mut dest = s3_dest("Offsite", "malo", "alerts", true);
    dest.options
        .insert("endpoint".into(), "http://127.0.0.1:1".into());
    let offsite: DestinationView = admin.post("/destinations", &dest).await;

    let settings = AlertSettings {
        channels: vec![
            AlertChannel::Webhook {
                url: format!("{base}/hook"),
            },
            AlertChannel::Ntfy {
                server: format!("{base}/ntfy"),
                topic: "malo-test".into(),
                token: Some("tk_secret".into()),
            },
            AlertChannel::Apprise {
                url: format!("{base}/notify/malo"),
            },
            AlertChannel::Email {
                account_id: work.id.clone(),
                to: "me@example.com".into(),
            },
        ],
        backup_failures: 2,
        ..Default::default()
    };

    // Bad settings are refused.
    let mut bad = settings.clone();
    bad.channels.push(AlertChannel::Webhook {
        url: "ftp://example.com/x".into(),
    });
    let refused: Result<AlertSettings, _> = admin.call(Method::PUT, "/alerts", Some(&bad)).await;
    assert_eq!(refused.unwrap_err().0, 400);

    // A test reaches every channel before anything is saved.
    let results: Vec<AlertDelivery> = admin.post("/alerts/test", &settings).await;
    assert!(results.iter().all(|r| r.ok), "{results:?}");
    assert_eq!(events(&seen, "/hook"), ["test"]);
    let ntfy = &received(&seen, "/ntfy")[0];
    assert_eq!(ntfy["topic"], "malo-test");
    assert_eq!(ntfy["title"], "Test alert from Malo");
    let ntfy_auth = seen
        .lock()
        .unwrap()
        .iter()
        .find(|s| s.0 == "/ntfy")
        .unwrap()
        .2
        .clone();
    assert_eq!(ntfy_auth.as_deref(), Some("Bearer tk_secret"));
    assert_eq!(received(&seen, "/notify/malo")[0]["type"], "info");
    {
        let up = smtp.lock().unwrap();
        assert_eq!(up.envelopes.len(), 1);
        let text = String::from_utf8_lossy(&up.messages[0]);
        assert!(
            text.contains("Subject: Malo: Test alert from Malo"),
            "{text}"
        );
        assert!(up.envelopes[0]
            .1
            .iter()
            .any(|t| t.contains("me@example.com")));
    }
    // A channel that fails says so.
    let one = AlertSettings {
        channels: vec![AlertChannel::Webhook {
            url: format!("{base}/broken"),
        }],
        ..Default::default()
    };
    let results: Vec<AlertDelivery> = admin.post("/alerts/test", &one).await;
    assert!(!results[0].ok && results[0].error.as_deref().unwrap().contains("500"));

    // Saved: the token is shown redacted, and kept when sent back that way.
    let shown: AlertSettings = admin.put("/alerts", &settings).await;
    let AlertChannel::Ntfy { token, .. } = &shown.channels[1] else {
        panic!()
    };
    assert_eq!(token.as_deref(), Some(REDACTED));
    let again: AlertSettings = admin.put("/alerts", &shown).await;
    assert_eq!(again, shown);
    let stored = r.state.keyring.get(&me.id).unwrap().config().alerts.clone();
    assert_eq!(stored, settings);
    seen.lock().unwrap().clear();

    // The first failed backup: no alert about the account yet, one about the destination.
    let job = admin
        .run_job(JobKind::Backup {
            account_id: work.id.clone(),
        })
        .await;
    assert_eq!(job.state, JobState::Failed);
    eventually("the destination alert", || {
        events(&seen, "/hook") == ["destination_unreachable"]
    })
    .await;
    let hook = &received(&seen, "/hook")[0];
    assert_eq!(hook["title"], "Can't reach Offsite");
    assert_eq!(hook["severity"], "error");
    assert_eq!(hook["user"], "admin");
    // The second in a row alerts about the account; the destination isn't alerted twice.
    admin
        .run_job(JobKind::Backup {
            account_id: work.id.clone(),
        })
        .await;
    eventually("the backup alert", || {
        events(&seen, "/hook") == ["destination_unreachable", "backup_failing"]
    })
    .await;
    let hook = &received(&seen, "/hook")[1];
    assert_eq!(hook["title"], "Backups of Work are failing");
    assert!(hook["message"]
        .as_str()
        .unwrap()
        .contains("The last 2 backups"));
    eventually("emails", || smtp.lock().unwrap().messages.len() == 3).await;
    // A third failure stays quiet.
    admin
        .run_job(JobKind::Backup {
            account_id: work.id.clone(),
        })
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(events(&seen, "/hook").len(), 2);

    // An OAuth account whose provider refuses the refresh token.
    let mut oauth = imap_input("Gmail", "me@gmail.example", fake_imap().await);
    oauth.enabled = false;
    oauth.auth = AccountAuth::OAuth2 {
        provider: OAuthProvider::Custom,
        auth_url: format!("{base}/authorize"),
        token_url: format!("{base}/token"),
        client_id: "malo".into(),
        client_secret: None,
        scopes: vec!["mail".into()],
        refresh_token: "revoked".into(),
    };
    let gmail: AccountView = admin.post("/accounts", &oauth).await;
    let job = admin
        .run_job(JobKind::Backup {
            account_id: gmail.id.clone(),
        })
        .await;
    assert!(
        job.error
            .as_deref()
            .unwrap()
            .contains("token refresh failed"),
        "{:?}",
        job.error
    );
    eventually("the sign-in alert", || {
        events(&seen, "/hook").last().map(String::as_str) == Some("oauth_failing")
    })
    .await;
    assert_eq!(
        received(&seen, "/hook").last().unwrap()["title"],
        "Malo can't sign in to Gmail"
    );

    // Check results: alerted when the count of damaged copies changes, and when it's over.
    let user = r.state.keyring.get(&me.id).unwrap();
    let check = |corrupt: u64| {
        let report = CheckReport {
            id: 1,
            created_at: chrono::Utc::now(),
            deep: true,
            scope: CheckScope::All,
            destinations: vec![DestinationHealth {
                destination_id: offsite.id.clone(),
                name: "Offsite".into(),
                corrupt,
                ok: corrupt == 0,
                ..Default::default()
            }],
            accounts: vec![],
            repaired: 0,
            ok: corrupt == 0,
        };
        JobInfo {
            id: "x".into(),
            kind: JobKind::Check {
                scope: CheckScope::All,
                deep: true,
            },
            state: JobState::Done,
            trigger: JobTrigger::Scheduled,
            created_at: chrono::Utc::now(),
            started_at: None,
            finished_at: None,
            progress: Default::default(),
            error: None,
            result: Some(serde_json::to_value(report).unwrap()),
        }
    };
    seen.lock().unwrap().clear();
    malo_server::alerts::after_job(&r.state, &user, &check(2));
    // The check also reached the destination: that problem is over.
    let sorted = |seen: &Seen| {
        let mut e = events(seen, "/hook");
        e.sort();
        e
    };
    eventually("the check alert and the destination recovery", || {
        sorted(&seen) == ["check_problems", "recovered"]
    })
    .await;
    let hooks = received(&seen, "/hook");
    let problem = hooks
        .iter()
        .find(|h| h["event"] == "check_problems")
        .unwrap();
    assert!(problem["message"]
        .as_str()
        .unwrap()
        .contains("0 missing and 2 damaged copies"));
    let back = hooks.iter().find(|h| h["event"] == "recovered").unwrap();
    assert_eq!(back["title"], "Offsite is reachable again");
    malo_server::alerts::after_job(&r.state, &user, &check(2));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(events(&seen, "/hook").len(), 2, "same count: no new alert");
    malo_server::alerts::after_job(&r.state, &user, &check(0));
    eventually("the check recovery", || events(&seen, "/hook").len() == 3).await;
    assert_eq!(
        received(&seen, "/hook")[2]["title"],
        "Offsite checks out again"
    );
    drop(user);

    // Locked: scheduled jobs are skipped, alerted once through the kept channels (not email).
    let mails_before = smtp.lock().unwrap().messages.len();
    seen.lock().unwrap().clear();
    assert_eq!(admin.status_of(Method::POST, "/auth/lock").await, 204);
    assert!(r.state.keyring.get(&me.id).is_none());
    for _ in 0..3 {
        malo_server::jobs::record_skipped(
            &r.state,
            &me.id,
            JobKind::Backup {
                account_id: work.id.clone(),
            },
        )
        .unwrap();
    }
    eventually("the locked alert", || {
        events(&seen, "/hook") == ["skipped_locked"]
            && received(&seen, "/ntfy").len() == 1
            && received(&seen, "/notify/malo").len() == 1
    })
    .await;
    assert_eq!(received(&seen, "/notify/malo")[0]["type"], "warning");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(events(&seen, "/hook").len(), 1, "once per locked period");
    assert_eq!(smtp.lock().unwrap().messages.len(), mails_before);

    // Logging in starts a new period; turning the alert off forgets the kept channels.
    let admin = admin.login("admin", "admin-password-1").await;
    let mut off = settings.clone();
    off.skipped_locked = false;
    let _: AlertSettings = admin.put("/alerts", &off).await;
    assert!(r.state.db.alert_mirror(&me.id).unwrap().is_none());
    let mut on = off.clone();
    on.skipped_locked = true;
    let _: AlertSettings = admin.put("/alerts", &on).await;
    let kept = r.state.db.alert_mirror(&me.id).unwrap().unwrap();
    assert!(kept.contains("malo-test") && !kept.contains("email"));
}

const PLAIN: &[u8] =
    b"From: Ann <ann@example.com>\r\nSubject: Hello\r\n\r\nFrom the start\r\nbye\r\n";
const SECOND: &[u8] = b"From: Bob <bob@example.com>\r\nSubject: Report 2024\r\n\r\nnumbers\r\n";
const NESTED: &[u8] = b"From: Cy <cy@example.com>\r\nSubject: Plan\r\n\r\nsteps\r\n";

fn unzip(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).expect("a zip");
    (0..z.len())
        .map(|i| {
            let mut f = z.by_index(i).unwrap();
            let mut data = vec![];
            f.read_to_end(&mut data).unwrap();
            (f.name().to_string(), data)
        })
        .collect()
}

async fn export(
    api: &Api,
    selection: RestoreSelection,
    format: ExportFormat,
) -> (ExportTicket, Vec<u8>) {
    let ticket: ExportTicket = api
        .post("/export", &ExportRequest { selection, format })
        .await;
    let body = api.bytes(&format!("/export/{}", ticket.token)).await;
    (ticket, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exports() {
    setup_env();
    let dir = tempfile::tempdir().unwrap();
    let r = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&r).await;
    let mut input = imap_input("Work", "me@example.com", 1);
    input.enabled = false;
    let acc: AccountView = admin.post("/accounts", &input).await;
    let me: Me = admin.get("/me").await;

    // INBOX: two messages; Projects/2024: one, and one whose copies are all gone.
    let mut ids = vec![];
    {
        let user = r.state.keyring.get(&me.id).unwrap();
        let ctx = malo_server::jobs::job_ctx(&r.state, &user, "t", Default::default());
        let inbox = user
            .index
            .upsert_mailbox(&acc.id, "INBOX", "INBOX", "INBOX", Some("/"), None, 7)
            .unwrap();
        let projects = user
            .index
            .upsert_mailbox(
                &acc.id,
                "Projects/2024",
                "Projects/2024",
                "Projects/2024",
                Some("/"),
                None,
                7,
            )
            .unwrap();
        let date = chrono::DateTime::parse_from_rfc3339("2024-03-05T06:07:08Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let lost: &[u8] = b"Subject: Lost\r\n\r\ngone\r\n";
        for (uid, raw, mailbox, flags, subject, spooled) in [
            (
                1u32,
                PLAIN,
                inbox.id,
                vec!["\\Seen".to_string(), "\\Flagged".into()],
                "Hello",
                true,
            ),
            (2, SECOND, inbox.id, vec![], "Report 2024", true),
            (
                3,
                NESTED,
                projects.id,
                vec!["\\Answered".to_string()],
                "Plan",
                true,
            ),
            (4, lost, projects.id, vec![], "Lost", false),
        ] {
            let sha = sha256_hex(raw);
            let mut env = malo_core::index::empty_envelope();
            env.subject = subject.into();
            env.from = "ann@example.com".into();
            let id = user
                .index
                .insert_message(&NewMessage {
                    account: &acc.id,
                    run: None,
                    size: raw.len() as u64,
                    internaldate: Some(date + chrono::Duration::minutes(uid as i64)),
                    message_id_hdr: None,
                    gm_msgid: None,
                    envelope: &env,
                    state: MessageState::Stored,
                    sha256: Some(&sha),
                })
                .unwrap();
            user.index
                .add_membership(id, mailbox, uid, &flags, &[])
                .unwrap();
            if spooled {
                ctx.spool_put(id, raw).unwrap();
            }
            ids.push(id);
        }
    }
    let account = |mailbox: Option<&str>| RestoreSelection::Account {
        account_id: acc.id.clone(),
        mailbox: mailbox.map(str::to_string),
    };

    // A zip of .eml files, in their folders; the unreadable one is listed.
    let (ticket, body) = export(&admin, account(None), ExportFormat::Zip).await;
    assert_eq!(ticket.messages, 4);
    assert!(ticket.filename.starts_with("malo-export-eml-") && ticket.filename.ends_with(".zip"));
    let files = unzip(&body);
    let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(
        names,
        [
            format!("Work/INBOX/2024-03-05 0608 Hello [{}].eml", ids[0]).as_str(),
            &format!("Work/INBOX/2024-03-05 0609 Report 2024 [{}].eml", ids[1]),
            &format!("Work/Projects/2024/2024-03-05 0610 Plan [{}].eml", ids[2]),
            "export-errors.txt",
        ]
    );
    assert_eq!(files[0].1, PLAIN);
    assert_eq!(files[2].1, NESTED);
    let errors = String::from_utf8(files[3].1.clone()).unwrap();
    assert!(
        errors.contains("Lost (2024-03-05): no readable copy"),
        "{errors}"
    );
    // A ticket works once.
    assert_eq!(
        admin
            .status_of(Method::GET, &format!("/export/{}", ticket.token))
            .await,
        404
    );

    // Maildir++: INBOX at the root, other folders as .A.B, flags in the names.
    let (_, body) = export(
        &admin,
        RestoreSelection::Messages {
            ids: ids[..3].to_vec(),
        },
        ExportFormat::Maildir,
    )
    .await;
    let files = unzip(&body);
    let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
    let t0 = 1_709_618_828i64;
    assert_eq!(
        names,
        [
            "Work/cur/",
            "Work/new/",
            "Work/tmp/",
            &format!(
                "Work/cur/{}.M{}P0.malo,S={}:2,FS",
                t0 + 60,
                ids[0],
                PLAIN.len()
            ),
            &format!(
                "Work/cur/{}.M{}P0.malo,S={}:2,",
                t0 + 120,
                ids[1],
                SECOND.len()
            ),
            "Work/.Projects.2024/cur/",
            "Work/.Projects.2024/new/",
            "Work/.Projects.2024/tmp/",
            "Work/.Projects.2024/maildirfolder",
            &format!(
                "Work/.Projects.2024/cur/{}.M{}P0.malo,S={}:2,R",
                t0 + 180,
                ids[2],
                NESTED.len()
            ),
        ]
    );
    assert_eq!(files[3].1, PLAIN);

    // One folder as mbox: a single mboxrd file.
    let (ticket, body) = export(&admin, account(Some("INBOX")), ExportFormat::Mbox).await;
    assert_eq!(ticket.filename, "INBOX.mbox");
    let text = String::from_utf8(body).unwrap();
    assert_eq!(
        text,
        "From ann@example.com Tue Mar  5 06:08:08 2024\nStatus: RO\nX-Status: F\n\
         From: Ann <ann@example.com>\nSubject: Hello\n\n>From the start\nbye\n\n\
         From ann@example.com Tue Mar  5 06:09:08 2024\nStatus: O\n\
         From: Bob <bob@example.com>\nSubject: Report 2024\n\nnumbers\n\n"
    );

    // Several folders as mbox: a zip with one file per folder.
    let (ticket, body) = export(
        &admin,
        RestoreSelection::Search {
            query: String::new(),
            account_id: None,
        },
        ExportFormat::Mbox,
    )
    .await;
    assert!(ticket.filename.ends_with(".zip"));
    let files = unzip(&body);
    let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(
        names,
        [
            "Work/INBOX.mbox",
            "Work/Projects/2024.mbox",
            "export-errors.txt"
        ]
    );
    assert!(String::from_utf8_lossy(&files[1].1).contains("Subject: Plan\n\nsteps\n"));

    // A single mbox file can't list what it left out: the download fails instead.
    let ticket: ExportTicket = admin
        .post(
            "/export",
            &ExportRequest {
                selection: RestoreSelection::Messages { ids: vec![ids[3]] },
                format: ExportFormat::Mbox,
            },
        )
        .await;
    let resp = admin
        .req(Method::GET, &format!("/export/{}", ticket.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.bytes().await.is_err(), "the stream ends with an error");

    // Nothing backed up: refused before any download.
    let none: Result<ExportTicket, _> = admin
        .call(
            Method::POST,
            "/export",
            Some(&ExportRequest {
                selection: RestoreSelection::Messages { ids: vec![9999] },
                format: ExportFormat::Zip,
            }),
        )
        .await;
    assert_eq!(none.unwrap_err().0, 400);

    // Someone else's ticket is no use.
    let other = new_user(&admin, &uniq("other")).await;
    let ticket: ExportTicket = admin
        .post(
            "/export",
            &ExportRequest {
                selection: account(None),
                format: ExportFormat::Zip,
            },
        )
        .await;
    assert_eq!(
        other
            .status_of(Method::GET, &format!("/export/{}", ticket.token))
            .await,
        404
    );
}
