//! End-to-end tests of two-step login, restoring to IMAP, compression, storage usage and Object
//! Lock, against the services of `docker compose --profile test up -d`.
//!
//! ```sh
//! MALO_IT=1 cargo test -p malo-server --test features
//! ```

mod common;

use std::collections::HashMap;

use common::*;
use malo_api::*;
use reqwest::Method;

fn job_result<T: serde::de::DeserializeOwned>(j: &JobInfo) -> T {
    assert_eq!(j.state, JobState::Done, "job failed: {:?}", j.error);
    serde_json::from_value(j.result.clone().expect("result")).expect("result shape")
}

fn code_at(secret_b32: &str, step: i64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.as_bytes())
        .unwrap();
    format!("{:06}", malo_server::totp::hotp(&secret, step as u64))
}

fn step_now() -> i64 {
    chrono::Utc::now().timestamp() / 30
}

async fn try_login(
    anon: &Api,
    user: &str,
    password: &str,
    totp: Option<String>,
) -> Result<LoginResponse, (u16, String)> {
    anon.call(
        Method::POST,
        "/auth/login",
        Some(&LoginRequest {
            username: user.into(),
            password: password.into(),
            totp,
        }),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_step_login() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let name = uniq("totp");
    let password = format!("{name}-password");
    let api = new_user(&admin, &name).await;
    let anon = Api {
        token: None,
        ..api.clone()
    };

    let wrong_pw = api
        .call::<_, TotpSetup>(
            Method::POST,
            "/auth/totp/setup",
            Some(&TotpSetupRequest {
                password: "nope".into(),
            }),
        )
        .await;
    assert!(wrong_pw.is_err(), "setup needs the password");
    let setup: TotpSetup = api
        .post(
            "/auth/totp/setup",
            &TotpSetupRequest {
                password: password.clone(),
            },
        )
        .await;
    assert!(
        setup.uri.starts_with("otpauth://totp/Malo%3A"),
        "{}",
        setup.uri
    );
    assert!(setup.qr_svg.contains("<svg"));
    // Not in force until confirmed.
    try_login(&anon, &name, &password, None).await.unwrap();
    let bad = api
        .call::<_, TotpRecoveryCodes>(
            Method::POST,
            "/auth/totp/enable",
            Some(&TotpCodeRequest {
                code: "000000".into(),
                password: None,
            }),
        )
        .await;
    assert!(bad.is_err());
    let step = step_now();
    let codes: TotpRecoveryCodes = api
        .post(
            "/auth/totp/enable",
            &TotpCodeRequest {
                code: code_at(&setup.secret, step),
                password: None,
            },
        )
        .await;
    assert_eq!(codes.codes.len(), 10);
    let me: Me = api.get("/me").await;
    assert!(me.totp_enabled);
    assert_eq!(me.totp_recovery_codes_left, 10);

    let (status, body) = try_login(&anon, &name, &password, None).await.unwrap_err();
    assert_eq!(status, 401);
    assert!(body.contains("totp_required"), "{body}");
    let (status, body) = try_login(&anon, &name, &password, Some("123456".into()))
        .await
        .unwrap_err();
    assert_eq!(status, 401);
    assert!(body.contains("totp_wrong"), "{body}");
    // A wrong password with a code says nothing about the code.
    let (_, body) = try_login(
        &anon,
        &name,
        "wrong",
        Some(code_at(&setup.secret, step + 1)),
    )
    .await
    .unwrap_err();
    assert!(!body.contains("totp"), "{body}");
    // The code used to turn it on is used up; the next one works once.
    assert!(
        try_login(&anon, &name, &password, Some(code_at(&setup.secret, step)))
            .await
            .is_err()
    );
    let next = code_at(&setup.secret, step + 1);
    try_login(&anon, &name, &password, Some(next.clone()))
        .await
        .unwrap();
    assert!(
        try_login(&anon, &name, &password, Some(next))
            .await
            .is_err(),
        "a code can't be replayed"
    );
    // Recovery codes work once each, typed in any case and with or without the dash.
    let recovery = codes.codes[0].to_uppercase().replace('-', "");
    try_login(&anon, &name, &password, Some(recovery.clone()))
        .await
        .unwrap();
    assert!(try_login(&anon, &name, &password, Some(recovery))
        .await
        .is_err());
    let me: Me = api.get("/me").await;
    assert_eq!(me.totp_recovery_codes_left, 9);

    // Turning it off takes the password and a code.
    let no_pw = api
        .call::<_, serde_json::Value>(
            Method::POST,
            "/auth/totp/disable",
            Some(&TotpCodeRequest {
                code: codes.codes[1].clone(),
                password: None,
            }),
        )
        .await;
    assert!(no_pw.is_err());
    let _: serde_json::Value = api
        .post(
            "/auth/totp/disable",
            &TotpCodeRequest {
                code: codes.codes[1].clone(),
                password: Some(password.clone()),
            },
        )
        .await;
    try_login(&anon, &name, &password, None).await.unwrap();
    let me: Me = api.get("/me").await;
    assert!(!me.totp_enabled);
    server.shutdown(std::time::Duration::from_secs(5)).await;
}

/// Messages on an IMAP server, by subject: (mailbox, flags, raw).
async fn mailbox_contents(imap_user: &str) -> HashMap<String, (String, Vec<String>, Vec<u8>)> {
    let mut c = imap_conn(imap_user, IMAP_PORT).await;
    let list = c.list_mailboxes().await.unwrap();
    let mut out = HashMap::new();
    for mb in list.iter().filter(|m| m.selectable) {
        c.select(&mb.name).await.unwrap();
        let uids = c.all_uids().await.unwrap();
        let flags = c.flags(&uids).await.unwrap();
        for uid in uids {
            let (raw, _) = c.fetch_raw(uid).await.unwrap().unwrap();
            let subject = malo_core::viewer::envelope_of(&raw).subject;
            let mut f = flags[&uid].0.clone();
            f.sort();
            out.insert(subject, (mb.name.clone(), f, raw));
        }
    }
    c.logout().await;
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restore_to_imap() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("restorer")).await;
    let _: DestinationView = api.post("/destinations", &fs_dest("local", "b")).await;

    let source = uniq("restsrc");
    let mut c = imap_conn(&source, IMAP_PORT).await;
    create_mailbox(&mut c, "Work").await;
    append(
        &mut c,
        "INBOX",
        Some("(\\Seen)"),
        None,
        &mail("restore one", 0),
    )
    .await;
    append(
        &mut c,
        "INBOX",
        Some("(\\Flagged \\Seen)"),
        Some("05-Mar-2024 08:30:00 +0000"),
        &mail("restore two", 20_000),
    )
    .await;
    append(&mut c, "Work", None, None, &mail("restore work", 0)).await;
    c.logout().await;
    let src: AccountView = api
        .post("/accounts", &imap_input("source", &source, IMAP_PORT))
        .await;
    let _: serde_json::Value = job_result(
        &api.run_job(JobKind::Backup {
            account_id: src.id.clone(),
        })
        .await,
    );
    let before = mailbox_contents(&source).await;
    assert_eq!(before.len(), 3);

    // A new, empty mailbox at another provider.
    let target = uniq("resttgt");
    imap_conn(&target, IMAP_PORT).await.logout().await;
    let mut input = imap_input("target", &target, IMAP_PORT);
    input.enabled = false;
    let tgt: AccountView = api.post("/accounts", &input).await;

    let restore = |selection: RestoreSelection, to: RestoreTarget| {
        let api = api.clone();
        let tgt = tgt.id.clone();
        async move {
            let job: JobInfo = api
                .post(
                    "/restore",
                    &RestoreRequest {
                        target_account_id: tgt,
                        selection,
                        target: to,
                    },
                )
                .await;
            job_result::<RestoreSummary>(&api.wait_job(&job.id).await)
        }
    };
    let whole = RestoreSelection::Account {
        account_id: src.id.clone(),
        mailbox: None,
    };
    let s = restore(whole.clone(), RestoreTarget::Original).await;
    assert_eq!((s.restored, s.skipped, s.failed), (3, 0, 0), "{s:?}");
    let after = mailbox_contents(&target).await;
    assert_eq!(after.len(), 3);
    for (subject, (mailbox, flags, raw)) in &before {
        let (m, f, r) = &after[subject];
        assert_eq!(m, mailbox, "{subject}");
        assert_eq!(f, flags, "{subject}");
        assert_eq!(r, raw, "{subject} byte-identical");
    }
    // Running it again adds nothing.
    let s = restore(whole, RestoreTarget::Original).await;
    assert_eq!((s.restored, s.skipped, s.failed), (0, 3, 0), "{s:?}");

    // A search, into a folder of its own.
    let s = restore(
        RestoreSelection::Search {
            query: "\"restore work\"".into(),
            account_id: Some(src.id.clone()),
        },
        RestoreTarget::Folder {
            name: "Restored".into(),
        },
    )
    .await;
    assert_eq!((s.restored, s.failed), (1, 0), "{s:?}");
    let mut c = imap_conn(&target, IMAP_PORT).await;
    assert_eq!(c.select("Restored").await.unwrap().exists, 1);
    c.logout().await;

    // Bad requests are refused before a job starts.
    for (selection, to) in [
        (
            RestoreSelection::Messages { ids: vec![] },
            RestoreTarget::Original,
        ),
        (
            RestoreSelection::Messages { ids: vec![1] },
            RestoreTarget::Folder {
                name: "bad*name".into(),
            },
        ),
    ] {
        let r = api
            .call::<_, JobInfo>(
                Method::POST,
                "/restore",
                Some(&RestoreRequest {
                    target_account_id: tgt.id.clone(),
                    selection,
                    target: to,
                }),
            )
            .await;
        assert_eq!(r.unwrap_err().0, 400);
    }
    server.shutdown(std::time::Duration::from_secs(5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compression_recompression_and_usage() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("squeeze")).await;
    let root = uniq("squeeze");

    // A destination set up before compression existed.
    let mut input = s3_dest("rustfs", "malo-a", &root, true);
    input.features.compress = false;
    input.features.price_per_gb_month = Some(0.006);
    let dest: DestinationView = api.post("/destinations", &input).await;

    let imap_user = uniq("squeezem");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    // Text compresses well; the attachment is base64 of a repeating pattern.
    append(&mut c, "INBOX", None, None, &mail("text only", 0)).await;
    append(
        &mut c,
        "INBOX",
        None,
        None,
        &mail("with attachment", 200_000),
    )
    .await;
    c.logout().await;
    let acc: AccountView = api
        .post("/accounts", &imap_input("acc", &imap_user, IMAP_PORT))
        .await;
    let backup = || {
        api.run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
    };
    let _: serde_json::Value = job_result(&backup().await);
    let views: Vec<DestinationView> = api.get("/destinations").await;
    // Only counted where compression is on: that's when they can be compressed.
    assert_eq!(views[0].uncompressed_objects, 0);
    let usage: UsageReport = api.get("/usage").await;
    let cell = &usage.cells[0];
    assert_eq!(
        (cell.account_id.as_str(), cell.messages),
        (acc.id.as_str(), 2)
    );
    assert!(cell.stored_bytes >= cell.message_bytes, "{cell:?}");
    let uncompressed = cell.stored_bytes;

    // Turned on: new mail is stored compressed, and the old can be compressed too.
    input.revision = Some(dest.revision);
    input.features.compress = true;
    let view: DestinationView = api.put(&format!("/destinations/{}", dest.id), &input).await;
    assert_eq!(view.uncompressed_objects, 2);
    let s: CompressSummary = job_result(
        &api.run_job(JobKind::CompressStored {
            destination_id: Some(dest.id.clone()),
        })
        .await,
    );
    assert_eq!((s.objects, s.failed), (2, 0), "{s:?}");
    assert!(s.bytes_after * 2 < s.bytes_before, "{s:?}");
    let views: Vec<DestinationView> = api.get("/destinations").await;
    assert_eq!(views[0].uncompressed_objects, 0);
    let usage: UsageReport = api.get("/usage").await;
    let cell = &usage.cells[0];
    assert_eq!(cell.messages, 2);
    assert_eq!(
        cell.stored_bytes,
        uncompressed - s.bytes_before + s.bytes_after
    );
    assert!(cell.stored_bytes < cell.message_bytes, "{cell:?}");
    assert!(!usage.history.is_empty());
    assert_eq!(
        usage.history.last().unwrap().stored_bytes,
        cell.stored_bytes
    );

    // Only compressed objects are left in the bucket, and every one reads back.
    let op = s3_operator("malo-a");
    let objects: Vec<String> = op
        .list_with(&format!("{root}/"))
        .recursive(true)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.path().to_string())
        .filter(|p| p.contains("/objects/"))
        .collect();
    assert_eq!(objects.len(), 2, "{objects:?}");
    assert!(objects.iter().all(|p| p.ends_with(".z.enc")), "{objects:?}");
    let report: CheckReport = job_result(
        &api.run_job(JobKind::Check {
            scope: CheckScope::All,
            deep: true,
        })
        .await,
    );
    assert!(report.destinations.iter().all(|d| d.ok), "{report:?}");

    // New mail goes in compressed.
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    append(
        &mut c,
        "INBOX",
        None,
        None,
        &mail("after compression", 50_000),
    )
    .await;
    c.logout().await;
    let _: serde_json::Value = job_result(&backup().await);
    let views: Vec<DestinationView> = api.get("/destinations").await;
    assert_eq!(views[0].uncompressed_objects, 0);
    let usage: UsageReport = api.get("/usage").await;
    assert_eq!(usage.cells[0].messages, 3);
    server.shutdown(std::time::Duration::from_secs(5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn object_lock_on_s3() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("locker")).await;

    // Refused where the bucket has no Object Lock.
    let mut plain = s3_dest("plain", "malo-a", &uniq("lockless"), true);
    plain.features.object_lock = Some(ObjectLock {
        mode: LockMode::Governance,
        days: 1,
    });
    let t: DestinationTest = api.post("/destinations/test", &plain).await;
    assert!(!t.ok, "{t:?}");
    // Out of range.
    let mut input = s3_dest("locked", "malo-lock", &uniq("locked"), true);
    input.features.object_lock = Some(ObjectLock {
        mode: LockMode::Governance,
        days: MAX_LOCK_DAYS + 1,
    });
    assert_eq!(
        api.call::<_, DestinationView>(Method::POST, "/destinations", Some(&input))
            .await
            .unwrap_err()
            .0,
        400
    );
    input.features.object_lock = Some(ObjectLock {
        mode: LockMode::Governance,
        days: 1,
    });
    let t: DestinationTest = api.post("/destinations/test", &input).await;
    assert!(t.ok, "{t:?}");
    assert!(t.lock.is_some(), "{t:?}");
    let dest: DestinationView = api.post("/destinations", &input).await;

    let imap_user = uniq("lockm");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    append(&mut c, "INBOX", None, None, &mail("locked mail", 0)).await;
    c.logout().await;
    let acc: AccountView = api
        .post("/accounts", &imap_input("acc", &imap_user, IMAP_PORT))
        .await;
    let stats: serde_json::Value = job_result(
        &api.run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
        .await,
    );
    assert_eq!(stats["errors"], serde_json::json!([]), "{stats}");

    // The stored object carries a retention date about a day out.
    let me: Me = api.get("/me").await;
    let user = server.state.keyring.get(&me.id).unwrap();
    let cfg = user.config();
    let core_dest = cfg.destinations.iter().find(|d| d.id == dest.id).unwrap();
    let locker = malo_core::objectlock::Locker::for_destination(core_dest)
        .unwrap()
        .expect("locking destination");
    let list: MessageList = api.get("/messages?q=locked&limit=5").await;
    let replicas = user.index.replicas_of(list.messages[0].id).unwrap();
    let retention = locker
        .retention(&replicas[0].object_path)
        .await
        .unwrap()
        .expect("retention set");
    assert_eq!(retention.mode, "governance");
    let left = retention.until.expect("retain-until date") - chrono::Utc::now();
    assert!(
        left > chrono::Duration::hours(23) && left <= chrono::Duration::hours(24),
        "{retention:?}"
    );
    server.shutdown(std::time::Duration::from_secs(5)).await;
}
