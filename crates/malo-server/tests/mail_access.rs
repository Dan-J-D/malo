//! IMAP and SMTP services for mail apps, end to end with a real IMAP client and a fake upstream
//! SMTP server. Needs no Docker: messages are put into the index and spool directly.

mod common;

use std::sync::{Arc, Mutex};

use async_imap::imap_proto;
use base64::Engine;
use futures::TryStreamExt;
use malo_api::*;
use malo_core::crypto::sha256_hex;
use malo_core::index::NewMessage;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use common::*;

fn setup_env() {
    std::env::set_var("MALO_INSECURE_FAST_KDF", "1");
    std::env::set_var("MALO_LOGIN_BURST", "1000");
}

#[derive(Default)]
struct Upstream {
    auth: Vec<String>,
    envelopes: Vec<(String, Vec<String>)>,
    messages: Vec<Vec<u8>>,
}

/// A TLS SMTP server that accepts AUTH PLAIN and refuses recipients at `reject.example`.
async fn fake_smtp() -> (u16, Arc<Mutex<Upstream>>) {
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Upstream::default()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, log) = (acceptor.clone(), log.clone());
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut io = BufReader::new(tls);
                let mut from = String::new();
                let mut to = vec![];
                io.get_mut().write_all(b"220 fake ESMTP\r\n").await.unwrap();
                loop {
                    let mut line = String::new();
                    if io.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let up = line.to_ascii_uppercase();
                    let reply: &[u8] = if up.starts_with("EHLO") {
                        b"250-fake\r\n250-SIZE 1000000\r\n250 AUTH PLAIN LOGIN\r\n"
                    } else if up.starts_with("AUTH PLAIN") {
                        let b = base64::engine::general_purpose::STANDARD
                            .decode(line[11..].trim())
                            .unwrap();
                        log.lock().unwrap().auth.push(String::from_utf8(b).unwrap());
                        b"235 ok\r\n"
                    } else if up.starts_with("MAIL FROM:") {
                        from = line[10..].trim().to_string();
                        b"250 ok\r\n"
                    } else if up.starts_with("RCPT TO:") {
                        if up.contains("REJECT.EXAMPLE") {
                            b"550 5.1.1 no such user\r\n"
                        } else {
                            to.push(line[8..].trim().to_string());
                            b"250 ok\r\n"
                        }
                    } else if up.starts_with("DATA") {
                        io.get_mut().write_all(b"354 go\r\n").await.unwrap();
                        let mut data = vec![];
                        loop {
                            let mut l = vec![];
                            io.read_until(b'\n', &mut l).await.unwrap();
                            if l == b".\r\n" {
                                break;
                            }
                            data.extend_from_slice(&l);
                        }
                        let mut log = log.lock().unwrap();
                        log.messages.push(data);
                        log.envelopes.push((from.clone(), std::mem::take(&mut to)));
                        b"250 queued\r\n"
                    } else if up.starts_with("QUIT") {
                        let _ = io.get_mut().write_all(b"221 bye\r\n").await;
                        return;
                    } else {
                        b"250 ok\r\n"
                    };
                    io.get_mut().write_all(reply).await.unwrap();
                }
            });
        }
    });
    (port, seen)
}

async fn tls(addr: std::net::SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    tokio_rustls::TlsConnector::from(malo_core::tls::insecure_config())
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

type Imap = async_imap::Session<tokio_rustls::client::TlsStream<TcpStream>>;

async fn imap_login(addr: std::net::SocketAddr, user: &str, pass: &str) -> Result<Imap, String> {
    let mut client = async_imap::Client::new(tls(addr).await);
    client.read_response().await.unwrap().unwrap();
    client
        .login(user, pass)
        .await
        .map_err(|(e, _)| e.to_string())
}

/// Talks SMTP line by line; returns the last reply line of each step.
async fn smtp_dialog(addr: std::net::SocketAddr, steps: &[&str]) -> Vec<String> {
    let mut io = BufReader::new(tls(addr).await);
    let mut replies = vec![read_reply(&mut io).await];
    for s in steps {
        io.get_mut().write_all(s.as_bytes()).await.unwrap();
        io.get_mut().write_all(b"\r\n").await.unwrap();
        replies.push(read_reply(&mut io).await);
    }
    replies
}

async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(io: &mut R) -> String {
    loop {
        let mut l = String::new();
        io.read_line(&mut l).await.unwrap();
        if l.as_bytes().get(3) != Some(&b'-') {
            return l.trim_end().to_string();
        }
    }
}

const FIRST: &[u8] = b"From: Alice <alice@example.com>\r\nTo: me@example.com\r\nSubject: first\r\nMessage-ID: <1@example.com>\r\nDate: Tue, 1 Oct 2024 10:00:00 +0000\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n--b\r\nContent-Type: application/pdf; name=a.pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n--b--\r\n";
const PURGED: &[u8] = b"From: Bob <bob@example.com>\r\nTo: me@example.com\r\nSubject: second, purged long ago\r\nMessage-ID: <2@example.com>\r\nDate: Wed, 2 Oct 2024 10:00:00 +0000\r\n\r\nold news\r\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mail_apps_read_backups_and_send() {
    setup_env();
    let (smtp_port, upstream) = fake_smtp().await;
    let dir = tempfile::tempdir().unwrap();
    let r = start_server(dir.path(), |c| {
        c.imap_listen = Some("127.0.0.1:0".parse().unwrap());
        c.smtp_listen = Some("127.0.0.1:0".parse().unwrap());
    })
    .await;
    let (imap, smtp) = (r.imap_addr.unwrap(), r.smtp_addr.unwrap());
    let admin = bootstrap(&r).await;
    let mut input = imap_input("Work", "me@example.com", 1);
    input.enabled = false;
    input.smtp = Some(SmtpSettings {
        host: "localhost".into(),
        port: smtp_port,
        tls: TlsMode::Implicit,
    });
    let acc: AccountView = admin.post("/accounts", &input).await;

    // Two backed-up messages, one of them long gone from the mail server.
    let me: Me = admin.get("/me").await;
    let mut ids = vec![];
    {
        let user = r.state.keyring.get(&me.id).unwrap();
        let ctx = malo_server::jobs::job_ctx(&r.state, &user, "t", Default::default());
        let inbox = user
            .index
            .upsert_mailbox(&acc.id, "INBOX", "INBOX", "INBOX", Some("/"), None, 7)
            .unwrap();
        user.index
            .upsert_mailbox(
                &acc.id,
                "Trash",
                "Trash",
                "Trash",
                Some("/"),
                Some("\\Trash"),
                7,
            )
            .unwrap();
        for (uid, raw) in [(1u32, FIRST), (2, PURGED)] {
            let sha = sha256_hex(raw);
            let env = malo_core::index::empty_envelope();
            let id = user
                .index
                .insert_message(&NewMessage {
                    account: &acc.id,
                    run: None,
                    size: raw.len() as u64,
                    internaldate: Some(chrono::Utc::now()),
                    message_id_hdr: None,
                    gm_msgid: None,
                    envelope: &env,
                    state: MessageState::Stored,
                    sha256: Some(&sha),
                })
                .unwrap();
            user.index
                .add_membership(id, inbox.id, uid, &[], &[])
                .unwrap();
            ctx.spool_put(id, raw).unwrap();
            ids.push(id);
            // The first is indexed for full-text search, the other waits for the search-index job.
            if uid == 1 {
                assert!(user.index.search_index_raw(id, &sha, raw).unwrap());
            }
        }
        user.index
            .mark_deleted_on_server(inbox.id, &[2], true)
            .unwrap();
    }

    let info: MailAccessInfo = admin.get("/mail-access").await;
    assert_eq!(info.imap_port, Some(imap.port()));
    assert!(info.logins.is_empty());
    let login: MailLoginCreated = admin
        .put(
            &format!("/accounts/{}/mail-login", acc.id),
            &MailLoginRequest {
                username: "Test-Email".into(),
                password_length: None,
            },
        )
        .await;
    assert_eq!(login.login.username, "test-email");
    assert_eq!(login.password.len(), 24);
    let info: MailAccessInfo = admin.get("/mail-access").await;
    assert_eq!(info.logins.len(), 1);

    // Usernames are unique across users.
    let bob = new_user(&admin, "bob").await;
    let bob_acc: AccountView = bob.post("/accounts", &imap_input("B", "b", 1)).await;
    let taken = bob
        .call::<_, serde_json::Value>(
            reqwest::Method::PUT,
            &format!("/accounts/{}/mail-login", bob_acc.id),
            Some(&MailLoginRequest {
                username: "test-email".into(),
                password_length: Some(40),
            }),
        )
        .await;
    assert_eq!(taken.unwrap_err().0, 409);

    // Searching in the app: full text with a highlighted snippet where indexed.
    let found: MessageList = admin.get("/messages?q=hello").await;
    assert_eq!(found.total, 1);
    assert_eq!(found.unindexed, 1);
    let snippet = found.messages[0].snippet.as_deref().unwrap();
    assert!(snippet.contains("\u{2}hello\u{3}"), "{snippet}");
    let found: MessageList = admin.get("/messages?q=news").await;
    assert_eq!(
        found.total, 0,
        "not indexed yet, and its envelope has no 'news'"
    );
    let job = admin.run_job(JobKind::SearchIndex).await;
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    assert_eq!(job.result.unwrap()["indexed"], 1);
    let found: MessageList = admin.get("/messages?q=news&sort=relevance").await;
    assert_eq!((found.total, found.unindexed), (1, 0));
    // (A mail app logging in also starts this job when mail is waiting for it.)

    assert!(imap_login(imap, "test-email", "wrong").await.is_err());
    // The Malo password is not a mail password.
    assert!(imap_login(imap, "test-email", "admin-password-1")
        .await
        .is_err());

    let mut s = imap_login(imap, "test-email", &login.password)
        .await
        .unwrap();
    let names: Vec<String> = s
        .list(Some(""), Some("*"))
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap()
        .iter()
        .map(|n| n.name().to_string())
        .collect();
    assert_eq!(names, vec!["INBOX", "Trash"]);
    let mb = s.select("INBOX").await.unwrap();
    assert_eq!(mb.exists, 2, "the purged message is there too");
    let fetches: Vec<_> = s
        .uid_fetch(
            "1:*",
            "(UID FLAGS RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[])",
        )
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(fetches.len(), 2);
    assert_eq!(fetches[0].body().unwrap(), FIRST);
    assert_eq!(fetches[1].body().unwrap(), PURGED);
    assert_eq!(fetches[0].size, Some(FIRST.len() as u32));
    let env = fetches[0].envelope().unwrap();
    assert_eq!(env.subject.as_deref(), Some(&b"first"[..]));
    let from = &env.from.as_ref().unwrap()[0];
    assert_eq!(from.host.as_deref(), Some(&b"example.com"[..]));
    assert!(matches!(
        fetches[0].bodystructure(),
        Some(imap_proto::types::BodyStructure::Multipart { .. })
    ));
    assert!(
        fetches[0].flags().next().is_none(),
        "PEEK leaves \\Seen unset"
    );

    // Header-only fetches use the cached header data; parts are addressable.
    let part: Vec<_> = s
        .uid_fetch("1", "(BODY[1] BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(
        part[0].section(&imap_proto::types::SectionPath::Part(vec![1], None)),
        Some(&b"hello"[..])
    );
    assert!(
        part[0].flags().any(|f| f == async_imap::types::Flag::Seen),
        "BODY[] marks it seen"
    );

    let hits = s.uid_search("SUBJECT \"purged\"").await.unwrap();
    assert_eq!(hits.into_iter().collect::<Vec<_>>(), vec![2]);
    let unseen = s.uid_search("UNSEEN").await.unwrap();
    assert_eq!(unseen.into_iter().collect::<Vec<_>>(), vec![2]);
    // BODY and TEXT: the full-text index for indexed mail, the raw message for the rest.
    for (query, want) in [
        ("BODY \"hello\"", vec![1]),
        ("BODY \"old ne\"", vec![2]),
        ("TEXT \"alice\"", vec![1]),
        ("TEXT \"a.pdf\"", vec![1]),
        ("BODY \"alice\"", vec![]),
        ("NOT BODY \"hello\"", vec![2]),
    ] {
        let mut hits: Vec<u32> = s.uid_search(query).await.unwrap().into_iter().collect();
        hits.sort();
        assert_eq!(hits, want, "{query}");
    }

    // "Search in" limits words without an operator to one part of the message.
    let found: MessageList = admin.get("/messages?q=hello&field=body").await;
    assert_eq!(found.total, 1);
    let found: MessageList = admin.get("/messages?q=hello&field=subject").await;
    assert_eq!(found.total, 0);
    let files: Vec<SearchSuggestion> = admin.get("/search/suggest?field=file&prefix=a").await;
    assert_eq!(files[0].value, "a.pdf");
    let senders: Vec<SearchSuggestion> = admin.get("/search/suggest?field=from").await;
    assert!(
        senders.is_empty(),
        "these test messages have no envelope sender"
    );

    let _: Vec<_> = s
        .uid_store("2", "+FLAGS (\\Flagged)")
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    // Moving files it in Trash in this view; the backup keeps it where it was.
    s.uid_mv("1", "Trash").await.unwrap();
    assert_eq!(s.select("INBOX").await.unwrap().exists, 1);
    let flagged = s.uid_search("FLAGGED").await.unwrap();
    assert_eq!(flagged.into_iter().collect::<Vec<_>>(), vec![2]);
    assert!(s.copy("2", "Nowhere").await.is_err(), "no such folder");
    let trash = s.select("Trash").await.unwrap();
    assert_eq!(trash.exists, 1);
    let moved: Vec<_> = s
        .fetch("1", "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(moved[0].header().unwrap()).contains("first"));

    // Folders can be left out of mail apps.
    let view: MailViewInfo = admin
        .put(
            &format!("/accounts/{}/mail-view", acc.id),
            &MailViewSettings {
                split_categories: true,
                hidden: vec!["Trash".into(), "INBOX".into()],
            },
        )
        .await;
    assert!(!view.gmail);
    let shown: Vec<(&str, bool, u64)> = view
        .folders
        .iter()
        .map(|f| (f.name.as_str(), f.shown, f.messages))
        .collect();
    assert_eq!(shown, vec![("INBOX", true, 1), ("Trash", false, 1)]);
    let names: Vec<String> = s
        .list(Some(""), Some("*"))
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap()
        .iter()
        .map(|n| n.name().to_string())
        .collect();
    assert_eq!(names, vec!["INBOX"]);
    let _: MailViewInfo = admin
        .put(
            &format!("/accounts/{}/mail-view", acc.id),
            &MailViewSettings {
                split_categories: true,
                hidden: vec![],
            },
        )
        .await;
    s.logout().await.unwrap();
    let resp = admin
        .status_of(
            reqwest::Method::POST,
            &format!("/accounts/{}/mail-view/reset", acc.id),
        )
        .await;
    assert_eq!(resp, 204);
    let mut s = imap_login(imap, "test-email", &login.password)
        .await
        .unwrap();
    assert_eq!(
        s.select("INBOX").await.unwrap().exists,
        2,
        "reset shows it again"
    );
    let mut idle = s.idle();
    idle.init().await.unwrap();
    let mut s = idle.done().await.unwrap();
    s.noop().await.unwrap();
    s.logout().await.unwrap();

    // Sending goes through the account's own SMTP server, with the account's credentials.
    let plain = base64::engine::general_purpose::STANDARD
        .encode(format!("\0test-email\0{}", login.password));
    let replies = smtp_dialog(
        smtp,
        &[
            "EHLO mac",
            &format!("AUTH PLAIN {plain}"),
            "MAIL FROM:<me@example.com>",
            "RCPT TO:<alice@example.com>",
            "DATA",
            "From: me@example.com\r\nTo: alice@example.com\r\nSubject: Re: first\r\n\r\n..leading dot\r\nbye\r\n.",
            "MAIL FROM:<me@example.com>",
            "RCPT TO:<x@reject.example>",
            "DATA",
            "Subject: nope\r\n\r\nx\r\n.",
            "QUIT",
        ],
    )
    .await;
    assert!(replies[2].starts_with("235"), "{replies:?}");
    assert!(replies[6].starts_with("250 2.0.0 Sent"), "{replies:?}");
    assert!(replies[10].starts_with("554"), "{replies:?}");
    assert!(replies[10].contains("no such user"), "{replies:?}");
    {
        let up = upstream.lock().unwrap();
        assert_eq!(up.auth[0], "\0me@example.com\0pass");
        assert!(up.envelopes[0].0.starts_with("<me@example.com>"));
        assert_eq!(up.envelopes[0].1, vec!["<alice@example.com>".to_string()]);
        assert_eq!(
            up.messages[0],
            b"From: me@example.com\r\nTo: alice@example.com\r\nSubject: Re: first\r\n\r\n..leading dot\r\nbye\r\n"
        );
        assert_eq!(up.messages.len(), 1);
    }
    let unauth = smtp_dialog(smtp, &["EHLO mac", "MAIL FROM:<me@example.com>"]).await;
    assert!(unauth[2].starts_with("530"), "{unauth:?}");

    // Writing in Malo: a reply that takes the original's attachments along, through the account's
    // SMTP server. Bcc recipients get it without showing up in the headers.
    let draft: DraftView = admin
        .put(
            "/drafts",
            &DraftInput {
                id: None,
                account_id: acc.id.clone(),
                message: SendRequest {
                    from: None,
                    to: vec!["alice@example.com".into()],
                    cc: vec![],
                    bcc: vec![],
                    subject: "Re: first".into(),
                    body: "Thanks".into(),
                    in_reply_to: Some(ids[0]),
                    attachments_of: None,
                    draft_id: None,
                },
            },
        )
        .await;
    let drafts: Vec<DraftView> = admin.get("/drafts").await;
    assert_eq!(drafts.len(), 1);
    let sent: SendResult = admin
        .post(
            &format!("/accounts/{}/send", acc.id),
            &SendRequest {
                from: Some("Me <me@example.com>".into()),
                to: vec!["Alice <alice@example.com>".into()],
                cc: vec![],
                bcc: vec!["hidden@example.net".into()],
                subject: "Re: first".into(),
                body: "Thanks!".into(),
                in_reply_to: Some(ids[0]),
                attachments_of: Some(ids[0]),
                draft_id: Some(draft.id),
            },
        )
        .await;
    let drafts: Vec<DraftView> = admin.get("/drafts").await;
    assert!(drafts.is_empty(), "sending deletes its draft");
    assert!(sent.message_id.ends_with("@example.com"));
    assert_eq!(sent.saved_to, None, "this account has no Sent mailbox");
    {
        let up = upstream.lock().unwrap();
        assert_eq!(
            up.envelopes[1].1,
            vec![
                "<alice@example.com>".to_string(),
                "<hidden@example.net>".to_string()
            ]
        );
        let text = String::from_utf8_lossy(&up.messages[1]).to_string();
        assert!(text.contains("In-Reply-To: <1@example.com>"), "{text}");
        assert!(text.contains("filename=\"a.pdf\""), "{text}");
        assert!(!text.contains("hidden@example.net"), "{text}");
    }
    let thread: Vec<MessageSummary> = admin.get(&format!("/messages/{}/thread", ids[0])).await;
    assert_eq!(thread.len(), 1);

    // A locked user's mail is unreadable until they log in again.
    assert_eq!(
        admin.status_of(reqwest::Method::POST, "/auth/lock").await,
        204
    );
    let err = imap_login(imap, "test-email", &login.password)
        .await
        .unwrap_err();
    assert!(err.contains("locked"), "{err}");
    let admin = Api::new(&r).login("admin", "admin-password-1").await;
    assert!(imap_login(imap, "test-email", &login.password)
        .await
        .is_ok());

    // A new password replaces the old one; removing the login ends it.
    let again: MailLoginCreated = admin
        .put(
            &format!("/accounts/{}/mail-login", acc.id),
            &MailLoginRequest {
                username: "test-email".into(),
                password_length: Some(32),
            },
        )
        .await;
    assert_eq!(again.password.len(), 32);
    assert!(imap_login(imap, "test-email", &login.password)
        .await
        .is_err());
    let mut s = imap_login(imap, "test-email", &again.password)
        .await
        .unwrap();
    s.select("INBOX").await.unwrap();
    assert_eq!(
        admin
            .status_of(
                reqwest::Method::DELETE,
                &format!("/accounts/{}/mail-login", acc.id)
            )
            .await,
        204
    );
    assert!(
        s.noop().await.is_err(),
        "a removed login ends open sessions"
    );
    r.shutdown(std::time::Duration::from_secs(5)).await;
}
