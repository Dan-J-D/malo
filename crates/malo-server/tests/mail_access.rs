//! IMAP and SMTP services for mail apps, end to end with a real IMAP client and a fake upstream
//! SMTP server. Needs no Docker: messages are put into the index and spool directly.

mod common;

use async_imap::imap_proto;
use base64::Engine;
use futures::TryStreamExt;
use malo_api::*;
use malo_core::crypto::sha256_hex;
use malo_core::index::NewMessage;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use common::*;

fn setup_env() {
    std::env::set_var("MALO_INSECURE_FAST_KDF", "1");
    std::env::set_var("MALO_LOGIN_BURST", "1000");
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

/// Upgrades a plain-text connection after STARTTLS was accepted.
async fn upgrade(io: BufReader<TcpStream>) -> tokio_rustls::client::TlsStream<TcpStream> {
    assert!(io.buffer().is_empty());
    tokio_rustls::TlsConnector::from(malo_core::tls::insecure_config())
        .connect(ServerName::try_from("localhost").unwrap(), io.into_inner())
        .await
        .unwrap()
}

async fn send_line<W: AsyncWriteExt + Unpin>(w: &mut W, line: &str) {
    w.write_all(format!("{line}\r\n").as_bytes()).await.unwrap();
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
    // Malo's certificate authority: what the services present chains to it, and devices can
    // download it to install.
    assert!(info.authority);
    assert!(info.certificate_names.contains(&"localhost".to_string()));
    let ca = admin.bytes("/tls/malo-ca.crt").await;
    assert_eq!(
        Some(malo_core::tls::fingerprint(&ca)),
        info.fingerprint,
        "the services' pin is the authority"
    );
    let profile = String::from_utf8(admin.bytes("/tls/malo-ca.mobileconfig").await).unwrap();
    assert!(profile.contains("com.apple.security.root"));
    assert!(profile.contains(&base64::engine::general_purpose::STANDARD.encode(&ca)));
    let pem = String::from_utf8(admin.bytes("/tls/malo-ca.pem").await).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    let chain = tls(imap)
        .await
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()
        .to_vec();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].as_ref(), &ca[..]);
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

    // Apps set to STARTTLS (or "SSL off") connect in plain text and wait for a greeting: they
    // can't log in until they start TLS, and then the session goes on without a second greeting.
    {
        let mut io = BufReader::new(TcpStream::connect(imap).await.unwrap());
        let greeting = read_reply(&mut io).await;
        assert!(
            greeting.contains("STARTTLS") && greeting.contains("LOGINDISABLED"),
            "{greeting}"
        );
        send_line(
            io.get_mut(),
            &format!("a LOGIN test-email {}", login.password),
        )
        .await;
        let refused = read_reply(&mut io).await;
        assert!(refused.starts_with("a NO [PRIVACYREQUIRED]"), "{refused}");
        send_line(io.get_mut(), "b STARTTLS").await;
        assert!(read_reply(&mut io).await.starts_with("b OK"));
        let mut s = async_imap::Client::new(upgrade(io).await)
            .login("test-email", &login.password)
            .await
            .map_err(|(e, _)| e)
            .unwrap();
        assert_eq!(s.select("INBOX").await.unwrap().exists, 2);
        s.logout().await.unwrap();
    }

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
                inbox_all_mail: true,
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
                inbox_all_mail: true,
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

    // Saved searches shown in mail apps are read-only folders of their matches.
    let hidden: SavedSearch = admin
        .post(
            "/saved-searches",
            &SavedSearchInput {
                name: "Not in apps".into(),
                query: "hello".into(),
                account_id: None,
                mail_folder: false,
            },
        )
        .await;
    let smart: SavedSearch = admin
        .post(
            "/saved-searches",
            &SavedSearchInput {
                name: "Hello mail".into(),
                query: "hello".into(),
                account_id: Some(acc.id.clone()),
                mail_folder: true,
            },
        )
        .await;
    let dup = admin
        .call::<_, serde_json::Value>(
            reqwest::Method::POST,
            "/saved-searches",
            Some(&SavedSearchInput {
                name: "hello MAIL".into(),
                query: "x".into(),
                account_id: None,
                mail_folder: false,
            }),
        )
        .await;
    assert_eq!(dup.unwrap_err().0, 400, "names are unique");
    let all: Vec<SavedSearch> = admin.get("/saved-searches").await;
    assert_eq!(all.len(), 2);
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
    assert!(names.contains(&"Smart/Hello mail".to_string()), "{names:?}");
    assert!(
        !names.iter().any(|n| n.contains("Not in apps")),
        "{names:?}"
    );
    let found = s.select("Smart/Hello mail").await.unwrap();
    assert_eq!(found.exists, 1);
    let hit: Vec<_> = s
        .fetch("1", "BODY.PEEK[]")
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(hit[0].body().unwrap(), FIRST);
    assert!(
        s.append("Smart/Hello mail", None, None, b"Subject: x\r\n\r\ny\r\n")
            .await
            .is_err(),
        "smart folders take no new mail"
    );
    for id in [&hidden.id, &smart.id] {
        let gone = admin
            .status_of(reqwest::Method::DELETE, &format!("/saved-searches/{id}"))
            .await;
        assert_eq!(gone, 204);
    }
    s.select("INBOX").await.unwrap();
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
    // SMTP with STARTTLS: offered in EHLO, required before AUTH.
    {
        let mut io = BufReader::new(TcpStream::connect(smtp).await.unwrap());
        assert!(read_reply(&mut io).await.starts_with("220"));
        send_line(io.get_mut(), "EHLO mac").await;
        assert_eq!(read_reply(&mut io).await, "250 STARTTLS");
        send_line(io.get_mut(), &format!("AUTH PLAIN {plain}")).await;
        assert!(read_reply(&mut io).await.starts_with("530"));
        send_line(io.get_mut(), "STARTTLS").await;
        assert!(read_reply(&mut io).await.starts_with("220"));
        let mut io = BufReader::new(upgrade(io).await);
        send_line(io.get_mut(), "EHLO mac").await;
        assert!(read_reply(&mut io).await.starts_with("250"));
        send_line(io.get_mut(), &format!("AUTH PLAIN {plain}")).await;
        let authed = read_reply(&mut io).await;
        assert!(authed.starts_with("235"), "{authed}");
    }

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

/// A raw IMAP connection, for commands no real client would send.
struct Raw(BufReader<tokio_rustls::client::TlsStream<TcpStream>>);

impl Raw {
    async fn open(addr: std::net::SocketAddr) -> Raw {
        let mut io = BufReader::new(tls(addr).await);
        let mut greeting = String::new();
        io.read_line(&mut greeting).await.unwrap();
        assert!(greeting.starts_with("* OK"), "{greeting}");
        Raw(io)
    }

    async fn send(&mut self, data: &[u8]) {
        let _ = self.0.get_mut().write_all(data).await;
        let _ = self.0.get_mut().flush().await;
    }

    /// Sends `tag text` and reads up to its tagged reply, a BYE or the end of the stream; returns
    /// the last line ("" for a closed connection).
    async fn cmd(&mut self, tag: &str, text: &str) -> String {
        self.send(format!("{tag} {text}\r\n").as_bytes()).await;
        self.reply(tag).await
    }

    async fn log_in(&mut self, pass: &str) {
        let r = self.cmd("l", &format!("LOGIN hostile {pass}")).await;
        assert!(r.starts_with("l OK"), "{r}");
    }

    async fn reply(&mut self, tag: &str) -> String {
        let read = async {
            loop {
                let mut l = String::new();
                if self.0.read_line(&mut l).await.unwrap_or(0) == 0 {
                    return String::new();
                }
                let l = l.trim_end().to_string();
                if l.starts_with(&format!("{tag} "))
                    || l.starts_with("* BYE")
                    || l.starts_with("* BAD")
                    || l.starts_with("+")
                {
                    return l;
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), read)
            .await
            .unwrap_or_else(|_| panic!("no answer to {tag} in time"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_imap_clients() {
    setup_env();
    let dir = tempfile::tempdir().unwrap();
    let r = start_server(dir.path(), |c| {
        c.imap_listen = Some("127.0.0.1:0".parse().unwrap());
    })
    .await;
    let imap = r.imap_addr.unwrap();
    let admin = bootstrap(&r).await;
    let mut input = imap_input("Work", "me@example.com", 1);
    input.enabled = false;
    let acc: AccountView = admin.post("/accounts", &input).await;
    let me: Me = admin.get("/me").await;
    {
        let user = r.state.keyring.get(&me.id).unwrap();
        let ctx = malo_server::jobs::job_ctx(&r.state, &user, "t", Default::default());
        let inbox = user
            .index
            .upsert_mailbox(&acc.id, "INBOX", "INBOX", "INBOX", Some("/"), None, 7)
            .unwrap();
        let sha = sha256_hex(FIRST);
        let env = malo_core::index::empty_envelope();
        let id = user
            .index
            .insert_message(&NewMessage {
                account: &acc.id,
                run: None,
                size: FIRST.len() as u64,
                internaldate: Some(chrono::Utc::now()),
                message_id_hdr: None,
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Stored,
                sha256: Some(&sha),
            })
            .unwrap();
        user.index
            .add_membership(id, inbox.id, 1, &[], &[])
            .unwrap();
        ctx.spool_put(id, FIRST).unwrap();
    }
    let login: MailLoginCreated = admin
        .put(
            &format!("/accounts/{}/mail-login", acc.id),
            &MailLoginRequest {
                username: "hostile".into(),
                password_length: None,
            },
        )
        .await;
    let pass = login.password.clone();

    // Before login: nesting deeper than the parser allows is refused, not recursed into.
    let mut c = Raw::open(imap).await;
    let deep = format!("NOOP {}", "(".repeat(4000));
    assert_eq!(c.cmd("a", &deep).await, "* BAD Malformed command");
    // A line over the pre-login limit ends the connection.
    let long = format!("NOOP {}", "x".repeat(10_000));
    assert!(c.cmd("b", &long).await.starts_with("* BYE"));
    // Only LOGIN and AUTHENTICATE may send literals before login.
    let mut c = Raw::open(imap).await;
    assert_eq!(c.cmd("c", "ID {5}").await, "c BAD Log in first");
    assert!(c
        .cmd("d", "LOGIN {100000}")
        .await
        .starts_with("d NO [TOOBIG]"));
    // A connection can't keep itself open with NOOPs.
    let mut c = Raw::open(imap).await;
    let mut last = String::new();
    for i in 0..40 {
        last = c.cmd(&format!("n{i}"), "NOOP").await;
        if last.starts_with("* BYE") {
            break;
        }
    }
    assert!(last.starts_with("* BYE"), "{last}");

    // The server is still up and serving.
    let mut c = Raw::open(imap).await;
    c.log_in(&pass).await;
    assert!(c.cmd("s", "SELECT INBOX").await.starts_with("s OK"));

    // After login: still no deep nesting, in commands or in searches.
    let deep = format!("SEARCH {}ALL{}", "(".repeat(100), ")".repeat(100));
    assert_eq!(c.cmd("a", &deep).await, "* BAD Malformed command");
    let nots = format!("SEARCH {}ALL", "NOT ".repeat(5000));
    assert_eq!(c.cmd("b", &nots).await, "b BAD Invalid search criteria");
    assert!(c.cmd("b2", "SEARCH NOT NOT ALL").await.starts_with("b2 OK"));

    // A pattern that makes a backtracking matcher take forever; and one too long.
    let started = std::time::Instant::now();
    let pattern = format!("\"{}\"", "*a".repeat(400) + "b");
    assert!(c
        .cmd("c", &format!("LIST \"\" {pattern}"))
        .await
        .starts_with("c OK"));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let pattern = format!("\"{}\"", "*".repeat(2000));
    assert_eq!(
        c.cmd("d", &format!("LIST \"\" {pattern}")).await,
        "d BAD LIST pattern too long"
    );

    // A malformed section is an error, not a crash of the connection.
    let r1 = c.cmd("e", "FETCH 1 BODY[HEADER.FIELDS)(]").await;
    assert!(r1.starts_with("e BAD"), "{r1}");
    assert!(c.cmd("f", "NOOP").await.starts_with("f OK"));

    // Flags with CR/LF (or other characters flags can't have) are refused.
    c.send(b"g STORE 1 +FLAGS ({12+}\r\nx\r\nA1 LOGOUT)\r\n")
        .await;
    assert_eq!(c.reply("g").await, "g BAD Invalid flags");
    assert_eq!(
        c.cmd("h", "STORE 1 +FLAGS (a\"b)").await,
        "h BAD Invalid flags"
    );
    assert!(c
        .cmd("i", "STORE 1 +FLAGS ($Ok \\Seen)")
        .await
        .starts_with("i OK"));
    c.send(b"j APPEND INBOX ({12+}\r\nx\r\nA1 LOGOUT) {2+}\r\nhi\r\n")
        .await;
    assert_eq!(c.reply("j").await, "j BAD Invalid flags");
    c.send(b"k APPEND INBOX \"1-Jan-2024\r\nA1 X\" {2+}\r\nhi\r\n")
        .await;
    let r2 = c.reply("k").await;
    assert!(r2.contains("BAD"), "{r2}");

    // Too many lines in one command.
    let mut many = String::from("m SEARCH");
    for _ in 0..70 {
        many.push_str(" TEXT {1+}\r\nx");
    }
    many.push_str("\r\n");
    c.send(many.as_bytes()).await;
    assert!(c.reply("m").await.starts_with("* BYE"));

    // And the server is still there.
    let mut c = Raw::open(imap).await;
    c.log_in(&pass).await;
    r.shutdown(std::time::Duration::from_secs(5)).await;
}

/// Collections: grouped in the app, searched with `tag:`, and filed from mail apps through their
/// `Collections/` folders.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collections() {
    setup_env();
    let dir = tempfile::tempdir().unwrap();
    let r = start_server(dir.path(), |c| {
        c.imap_listen = Some("127.0.0.1:0".parse().unwrap());
    })
    .await;
    let imap = r.imap_addr.unwrap();
    let admin = bootstrap(&r).await;
    let mut input = imap_input("Work", "me@example.com", 1);
    input.enabled = false;
    let acc: AccountView = admin.post("/accounts", &input).await;
    let me: Me = admin.get("/me").await;
    let mut ids = vec![];
    {
        let user = r.state.keyring.get(&me.id).unwrap();
        let ctx = malo_server::jobs::job_ctx(&r.state, &user, "t", Default::default());
        let inbox = user
            .index
            .upsert_mailbox(&acc.id, "INBOX", "INBOX", "INBOX", Some("/"), None, 7)
            .unwrap();
        for uid in 1..=3u32 {
            let raw = format!(
                "From: a@example.com\r\nSubject: number {uid}\r\nMessage-ID: <{uid}@x>\r\n\r\nbody {uid}\r\n"
            );
            let id = user
                .index
                .insert_message(&NewMessage {
                    account: &acc.id,
                    run: None,
                    size: raw.len() as u64,
                    internaldate: Some(chrono::Utc::now()),
                    message_id_hdr: None,
                    gm_msgid: None,
                    envelope: &malo_core::index::empty_envelope(),
                    state: MessageState::Stored,
                    sha256: Some(&sha256_hex(raw.as_bytes())),
                })
                .unwrap();
            user.index
                .add_membership(id, inbox.id, uid, &[], &[])
                .unwrap();
            ctx.spool_put(id, raw.as_bytes()).unwrap();
            ids.push(id);
        }
    }

    let receipts: Collection = admin
        .post(
            "/collections",
            &CollectionInput {
                name: " Receipts ".into(),
                mail_folder: true,
            },
        )
        .await;
    assert_eq!((receipts.name.as_str(), receipts.count), ("Receipts", 0));
    let dup = admin
        .call::<_, Collection>(
            reqwest::Method::POST,
            "/collections",
            Some(&CollectionInput {
                name: "receipts".into(),
                mail_folder: false,
            }),
        )
        .await;
    assert_eq!(dup.unwrap_err().0, 409);
    let bad = admin
        .call::<_, Collection>(
            reqwest::Method::POST,
            "/collections",
            Some(&CollectionInput {
                name: "a/b".into(),
                mail_folder: false,
            }),
        )
        .await;
    assert_eq!(bad.unwrap_err().0, 400);
    let members = format!("/collections/{}/messages", receipts.id);
    let res: CollectionMembersResult = admin
        .post(
            &members,
            &CollectionMembersRequest {
                ids: vec![ids[0], ids[0]],
                add: true,
            },
        )
        .await;
    assert_eq!((res.changed, res.collection.count), (1, 1));
    let found: MessageList = admin.get("/messages?q=tag%3AReceipts").await;
    assert_eq!(found.total, 1);
    assert_eq!(found.messages[0].collections, vec!["Receipts".to_string()]);

    let login: MailLoginCreated = admin
        .put(
            &format!("/accounts/{}/mail-login", acc.id),
            &MailLoginRequest {
                username: "collector".into(),
                password_length: None,
            },
        )
        .await;
    let mut s = imap_login(imap, "collector", &login.password)
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
    assert_eq!(names, vec!["Collections", "Collections/Receipts", "INBOX"]);
    assert_eq!(s.select("Collections/Receipts").await.unwrap().exists, 1);

    // Copying into the folder adds to the collection; moving takes it out of INBOX's view too.
    assert_eq!(s.select("INBOX").await.unwrap().exists, 3);
    s.uid_copy("2", "Collections/Receipts").await.unwrap();
    s.uid_mv("3", "Collections/Receipts").await.unwrap();
    let list: Vec<Collection> = admin.get("/collections").await;
    assert_eq!(list[0].count, 3);
    assert_eq!(s.select("INBOX").await.unwrap().exists, 2);
    assert!(s
        .append(
            "Collections/Receipts",
            None,
            None,
            b"Subject: x\r\n\r\ny\r\n"
        )
        .await
        .is_err());

    // Deleting there takes it out of the collection, never out of the backup.
    assert_eq!(s.select("Collections/Receipts").await.unwrap().exists, 3);
    let _: Vec<_> = s
        .uid_store("1", "+FLAGS (\\Deleted)")
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    let _: Vec<_> = s.expunge().await.unwrap().try_collect().await.unwrap();
    let list: Vec<Collection> = admin.get("/collections").await;
    assert_eq!(list[0].count, 2);
    let all: MessageList = admin.get("/messages").await;
    assert_eq!(all.total, 3);
    // Added again from the app, it shows again (under a new UID).
    let _: CollectionMembersResult = admin
        .post(
            &members,
            &CollectionMembersRequest {
                ids: vec![ids[0]],
                add: true,
            },
        )
        .await;
    assert_eq!(s.select("Collections/Receipts").await.unwrap().exists, 3);

    // Renamed, the folder follows; deleted, it's gone and the messages stay.
    let renamed: Collection = admin
        .put(
            &format!("/collections/{}", receipts.id),
            &CollectionInput {
                name: "Bills".into(),
                mail_folder: true,
            },
        )
        .await;
    assert_eq!(renamed.count, 3);
    assert_eq!(s.select("Collections/Bills").await.unwrap().exists, 3);
    assert!(s.select("Collections/Receipts").await.is_err());
    assert_eq!(
        admin
            .status_of(
                reqwest::Method::DELETE,
                &format!("/collections/{}", receipts.id)
            )
            .await,
        204
    );
    assert!(s.select("Collections/Bills").await.is_err());
    let all: MessageList = admin.get("/messages").await;
    assert_eq!(all.total, 3);
    s.logout().await.unwrap();
    r.shutdown(std::time::Duration::from_secs(5)).await;
}
