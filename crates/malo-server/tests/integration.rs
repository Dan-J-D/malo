//! End-to-end tests: real Dovecot, RustFS (S3), fake-gcs-server and fs destinations.
//!
//! ```sh
//! docker compose --profile test up -d
//! MALO_IT=1 cargo test -p malo-server --test integration
//! ```

mod common;

use base64::Engine as _;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use common::*;
use malo_api::*;
use malo_core::index::ReplicaStatus;
use reqwest::Method;

fn job_result<T: serde::de::DeserializeOwned>(j: &JobInfo) -> T {
    assert_eq!(j.state, JobState::Done, "job failed: {:?}", j.error);
    serde_json::from_value(j.result.clone().expect("result")).expect("result shape")
}

async fn add_destinations(api: &Api, prefix: &str) -> Vec<DestinationView> {
    ensure_gcs_bucket().await;
    let mut out = Vec::new();
    for input in [
        s3_dest("rustfs", "malo-a", &format!("{prefix}/s3"), true),
        gcs_dest("gcs", &format!("{prefix}/gcs"), false),
        fs_dest("local", "backups"),
    ] {
        let t: DestinationTest = api.post("/destinations/test", &input).await;
        assert!(
            t.ok,
            "destination {} test failed: {:?}",
            input.name, t.error
        );
        out.push(api.post("/destinations", &input).await);
    }
    out
}

async fn seed_standard(imap_user: &str) -> usize {
    let mut c = imap_conn(imap_user, IMAP_PORT).await;
    create_mailbox(&mut c, "Projects").await;
    create_mailbox(&mut c, "Projects/2024/Q1").await;
    let unicode = malo_core::layout::encode_utf7("Entwürfe/Ünïcödé 日本");
    create_mailbox(&mut c, &unicode).await;
    append(&mut c, "INBOX", None, None, &mail("hello", 0)).await;
    append(
        &mut c,
        "INBOX",
        Some("(\\Seen)"),
        None,
        &mail("big attachment", 3 * 1024 * 1024),
    )
    .await;
    append(
        &mut c,
        "INBOX",
        Some("(\\Deleted)"),
        None,
        &mail("decoy deleted", 0),
    )
    .await;
    append(
        &mut c,
        "Projects/2024/Q1",
        None,
        None,
        &mail("nested", 10_000),
    )
    .await;
    append(&mut c, &unicode, None, None, &mail("unicode mailbox", 0)).await;
    c.logout().await;
    5
}

/// Raw bytes of every message on the IMAP server, keyed by subject.
async fn server_messages(imap_user: &str, port: u16) -> HashMap<String, Vec<u8>> {
    let mut c = imap_conn(imap_user, port).await;
    let list = c.list_mailboxes().await.unwrap();
    let mut out = HashMap::new();
    for mb in list.iter().filter(|m| m.selectable) {
        c.select(&mb.name).await.unwrap();
        for uid in c.all_uids().await.unwrap() {
            let (raw, _) = c.fetch_raw(uid).await.unwrap().unwrap();
            let subject = malo_core::viewer::envelope_of(&raw).subject;
            out.insert(subject, raw);
        }
    }
    c.logout().await;
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_two_users_byte_identical_and_isolated() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let alice = new_user(&admin, &uniq("alice")).await;
    let bob = new_user(&admin, &uniq("bob")).await;
    let events = alice.events().await;

    let mut accounts: Vec<(Api, AccountView, String)> = Vec::new();
    for (api, who) in [(&alice, "a"), (&bob, "b")] {
        add_destinations(api, &uniq(who)).await;
        for n in 0..2 {
            let imap_user = uniq(&format!("{who}{n}-"));
            seed_standard(&imap_user).await;
            let input = imap_input(&format!("{who} account {n}"), &imap_user, IMAP_PORT);
            let test: ConnectionTest = api.post("/accounts/test", &input).await;
            assert!(test.ok && test.uidplus, "{test:?}");
            let acc: AccountView = api.post("/accounts", &input).await;
            accounts.push((api.clone(), acc, imap_user));
        }
    }

    // Backups of all four accounts run concurrently.
    let mut jobs = Vec::new();
    for (api, acc, _) in &accounts {
        let j: JobInfo = api
            .post(
                "/jobs",
                &CreateJobRequest {
                    kind: JobKind::Backup {
                        account_id: acc.id.clone(),
                    },
                },
            )
            .await;
        jobs.push((api.clone(), j.id));
    }
    for (api, id) in &jobs {
        let j = api.wait_job(id).await;
        let stats: serde_json::Value = job_result(&j);
        assert_eq!(stats["errors"].as_array().unwrap().len(), 0, "{stats}");
        assert_eq!(stats["discovered"], 5);
    }

    // Every message is byte-identical on every destination and via the API.
    for (api, acc, imap_user) in &accounts {
        let on_server = server_messages(imap_user, IMAP_PORT).await;
        let list: MessageList = api
            .get(&format!("/messages?account={}&limit=1000", acc.id))
            .await;
        assert_eq!(list.total as usize, on_server.len());
        let user_id: Me = api.get("/me").await;
        let unlocked = server.state.keyring.get(&user_id.id).unwrap();
        let ctx = malo_server::jobs::job_ctx(&server.state, &unlocked, "t", Default::default());
        for m in &list.messages {
            assert_eq!(m.state, MessageState::Verified);
            assert_eq!(m.stored, 3);
            let expected = &on_server[&m.envelope.subject];
            assert_eq!(
                &api.bytes(&format!("/messages/{}/raw", m.id)).await,
                expected,
                "{}",
                m.envelope.subject
            );
            let reps = unlocked.index.replicas_of(m.id).unwrap();
            assert_eq!(reps.len(), 3);
            for r in reps {
                let store = ctx.store(&r.destination).unwrap();
                assert_eq!(
                    &store.get(&r.object_path, r.encrypted).await.unwrap(),
                    expected
                );
                if r.encrypted {
                    assert!(!r.object_path.contains("INBOX") && !r.object_path.contains(&acc.name));
                } else {
                    assert!(r.object_path.contains("/mailboxes/"));
                }
            }
        }
        // Unicode and nested mailbox names survive.
        let boxes: Vec<MailboxInfo> = api.get(&format!("/mailboxes?account={}", acc.id)).await;
        let names: HashSet<String> = boxes.iter().map(|b| b.display_name.clone()).collect();
        assert!(names.contains("Entwürfe/Ünïcödé 日本"), "{names:?}");
        assert!(names.contains("Projects/2024/Q1"));
        // Viewer works and stays safe by default.
        let big = list
            .messages
            .iter()
            .find(|m| m.envelope.subject == "big attachment")
            .unwrap();
        let view: MessageView = api.get(&format!("/messages/{}/view", big.id)).await;
        assert!(view.html.is_none());
        assert_eq!(view.attachments.len(), 1);
        let att = api
            .bytes(&format!("/messages/{}/attachments/0", big.id))
            .await;
        assert_eq!(att.len(), 3 * 1024 * 1024);
    }
    // The decoy \Deleted message is still on the server (Malo never expunges during backup).
    let first_user = &accounts[0].2;
    assert!(server_messages(first_user, IMAP_PORT)
        .await
        .contains_key("decoy deleted"));

    // Isolation: bob can't see or touch alice's data.
    let (_, alice_acc, _) = &accounts[0];
    let bob_accounts: Vec<AccountView> = bob.get("/accounts").await;
    assert_eq!(bob_accounts.len(), 2);
    assert!(bob_accounts.iter().all(|a| a.name.starts_with('b')));
    assert_eq!(
        bob.status_of(Method::GET, &format!("/accounts/{}", alice_acc.id))
            .await,
        404
    );
    assert_eq!(
        bob.status_of(Method::POST, &format!("/accounts/{}/test", alice_acc.id))
            .await,
        404
    );
    assert_eq!(
        bob.status_of(Method::DELETE, &format!("/accounts/{}", alice_acc.id))
            .await,
        404
    );
    assert_eq!(
        bob.status_of(Method::GET, &format!("/jobs/{}", jobs[0].1))
            .await,
        404
    );
    assert_eq!(
        bob.status_of(Method::DELETE, &format!("/jobs/{}", jobs[0].1))
            .await,
        404
    );
    let r = bob
        .call::<_, JobInfo>(
            Method::POST,
            "/jobs",
            Some(&CreateJobRequest {
                kind: JobKind::Backup {
                    account_id: alice_acc.id.clone(),
                },
            }),
        )
        .await;
    assert_eq!(r.unwrap_err().0, 404);
    let leak: MessageList = bob
        .get(&format!("/messages?account={}", alice_acc.id))
        .await;
    assert_eq!(leak.total, 0);
    let bob_jobs: Vec<JobInfo> = bob.get("/jobs").await;
    assert!(bob_jobs.iter().all(|j| j
        .kind
        .account_id()
        .is_none_or(|a| bob_accounts.iter().any(|b| b.id == a))));
    // Admins manage users but can't read their mail.
    assert_eq!(
        admin
            .status_of(Method::GET, &format!("/accounts/{}", alice_acc.id))
            .await,
        404
    );

    // Events: NewMessageDiscovered once per message, always before any state change of it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    {
        let ev = events.lock().unwrap();
        let mut discovered: HashMap<i64, usize> = HashMap::new();
        let mut first_state: HashMap<i64, usize> = HashMap::new();
        for (i, e) in ev.iter().enumerate() {
            match e {
                SyncEvent::NewMessageDiscovered { message } => {
                    *discovered.entry(message.id).or_default() += 1
                }
                SyncEvent::MessageStateChanged { id, .. } => {
                    first_state.entry(*id).or_insert(i);
                }
                _ => {}
            }
        }
        assert_eq!(discovered.len(), 10, "alice has 2 × 5 messages");
        assert!(discovered.values().all(|n| *n == 1));
        for (i, e) in ev.iter().enumerate() {
            if let SyncEvent::NewMessageDiscovered { message } = e {
                assert!(
                    first_state.get(&message.id).is_none_or(|s| *s > i),
                    "state change before discovery"
                );
            }
        }
        // Bob's events never reach alice.
        assert!(!ev.iter().any(|e| matches!(e, SyncEvent::JobStarted { job } if job.kind.account_id().is_some_and(|a| bob_accounts.iter().any(|b| b.id == a)))));
    }

    // A re-run is a no-op.
    let (api, acc, imap_user) = &accounts[0];
    let again = api
        .run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
        .await;
    let stats: serde_json::Value = job_result(&again);
    assert_eq!(
        (stats["discovered"].as_u64(), stats["downloaded"].as_u64()),
        (Some(0), Some(0)),
        "{stats}"
    );

    // Mail injected during a run is picked up by the next pass at the latest.
    let j: JobInfo = api
        .post(
            "/jobs",
            &CreateJobRequest {
                kind: JobKind::Backup {
                    account_id: acc.id.clone(),
                },
            },
        )
        .await;
    let mut c = imap_conn(imap_user, IMAP_PORT).await;
    append(&mut c, "INBOX", None, None, &mail("injected during run", 0)).await;
    c.logout().await;
    api.wait_job(&j.id).await;
    let next = api
        .run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
        .await;
    job_result::<serde_json::Value>(&next);
    let list: MessageList = api
        .get(&format!("/messages?account={}&q=injected", acc.id))
        .await;
    assert_eq!(list.total, 1);
    assert_eq!(list.messages[0].state, MessageState::Verified);
    let new_only: MessageList = api
        .get(&format!("/messages?account={}&new=true", acc.id))
        .await;
    assert_eq!(new_only.total, 6);
    let _: u64 = api
        .post(
            "/messages/reviewed",
            &ReviewedRequest {
                ids: vec![],
                all: true,
                account_id: Some(acc.id.clone()),
                reviewed: true,
            },
        )
        .await;
    let new_only: MessageList = api
        .get(&format!("/messages?account={}&new=true", acc.id))
        .await;
    assert_eq!(new_only.total, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_lock_stops_jobs_and_restart_seals() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |c| c.auto_lock_seconds = Some(8)).await;
    let admin = bootstrap(&server).await;
    let name = uniq("carol");
    // Invite first: the admin's own session also auto-locks after 8 s.
    let invite: Invite = admin
        .post(
            "/admin/invites",
            &CreateInviteRequest {
                username: Some(name.clone()),
                role: Role::User,
                valid_hours: 1,
            },
        )
        .await;
    let imap_user = uniq("lock-");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    for i in 0..BULK {
        append(
            &mut c,
            "INBOX",
            None,
            None,
            &mail(&format!("bulk {i}"), 400_000),
        )
        .await;
    }
    c.logout().await;
    // The 8-second auto-lock starts at login.
    let anon = Api {
        token: None,
        ..admin.clone()
    };
    let _: serde_json::Value = anon
        .post(
            "/auth/register",
            &RegisterRequest {
                username: name.clone(),
                password: format!("{name}-password"),
                invite_code: Some(invite.code),
                recovery_kit: None,
                kit_passphrase: None,
            },
        )
        .await;
    let carol = anon.login(&name, &format!("{name}-password")).await;
    let _: DestinationView = carol.post("/destinations", &fs_dest("local", "b")).await;
    let acc: AccountView = carol
        .post("/accounts", &imap_input("bulk", &imap_user, IMAP_PORT))
        .await;
    let me: Me = carol.get("/me").await;
    assert!(me.unlocked && me.expires_at.is_some());
    let events = carol.events().await;

    // The schedule starts a backup immediately; it must be cut off by the auto-lock.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut job_id = None;
    while job_id.is_none() && std::time::Instant::now() < deadline {
        let jobs: Vec<JobInfo> = carol.get("/jobs").await;
        job_id = jobs
            .into_iter()
            .find(|j| j.state == JobState::Running)
            .map(|j| j.id);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let job_id = job_id.expect("scheduled backup started");
    let st = server.state.clone();
    let uid = me.id.clone();
    assert!(
        wait_until(
            move || {
                let st = st.clone();
                let uid = uid.clone();
                Box::pin(async move { st.keyring.get(&uid).is_none() })
            },
            30
        )
        .await
    );
    assert_eq!(
        carol.status_of(Method::GET, "/me").await,
        401,
        "session ends with the lock"
    );
    let job = admin_view_job(&server, &job_id).await;
    assert_eq!(job.state, JobState::Cancelled, "{job:?}");
    assert!(job.error.unwrap_or_default().contains("locked"));
    // Events arrive in 100 ms batches: wait for the Locked notice instead of racing it.
    let ev = events.clone();
    let locked_seen = wait_until(
        move || {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock()
                    .unwrap()
                    .iter()
                    .any(|e| matches!(e, SyncEvent::Locked { .. }))
            })
        },
        10,
    )
    .await;
    assert!(locked_seen, "no Locked event");

    // A scheduled job coming due while locked is recorded as skipped.
    server
        .state
        .db
        .set_next_run(&me.id, &format!("backup:{}", acc.id), chrono::Utc::now())
        .unwrap();
    let db = server.state.db.clone();
    let uid = me.id.clone();
    assert!(
        wait_until(
            move || {
                let db = db.clone();
                let uid = uid.clone();
                Box::pin(async move { db.skipped_since(&uid, None).unwrap() > 0 })
            },
            10
        )
        .await
    );

    // After login: skipped count is shown and the backup resumes to completion.
    let anon = Api {
        token: None,
        ..carol.clone()
    };
    let carol = anon.login(&name, &format!("{name}-password")).await;
    let me: Me = carol.get("/me").await;
    assert!(me.skipped_while_locked >= 1);
    let partial: MessageList = carol
        .get(&format!("/messages?account={}&state=verified", acc.id))
        .await;
    assert!(partial.total < BULK, "the first run was interrupted");
    // Keep the keys long enough for the rest of the test.
    let later = chrono::Utc::now() + chrono::Duration::hours(1);
    *server
        .state
        .keyring
        .get(&me.id)
        .unwrap()
        .expires_at
        .lock()
        .unwrap() = later;
    server
        .state
        .db
        .with(|c| c.execute("UPDATE sessions SET expires_at=?1", [later.to_rfc3339()]))
        .unwrap();
    let done = carol
        .run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
        .await;
    job_result::<serde_json::Value>(&done);
    let all: MessageList = carol
        .get(&format!("/messages?account={}&state=verified", acc.id))
        .await;
    assert_eq!(all.total, BULK);

    // Restart: every user is sealed, old sessions are gone, data is intact.
    server.task.abort();
    drop(server);
    let server2 = start_server(dir.path(), |_| {}).await;
    let api2 = Api::new(&server2);
    // Anyone sees that the server is up, only administrators how many users are unlocked.
    let health: Health = api2.get("/healthz").await;
    assert_eq!((health.status.as_str(), health.sealed_users), ("ok", None));
    assert_eq!(api2.status_of(Method::GET, "/admin/health").await, 401);
    let admin2 = api2.login("admin", "admin-password-1").await;
    let health: Health = admin2.get("/admin/health").await;
    assert_eq!(
        health.unlocked_users,
        Some(1),
        "the admin who just logged in"
    );
    assert!(health.sealed_users.unwrap() >= 1, "carol");
    let old = Api {
        token: carol.token.clone(),
        ..api2.clone()
    };
    assert_eq!(old.status_of(Method::GET, "/me").await, 401);
    let carol2 = api2.login(&name, &format!("{name}-password")).await;
    let all: MessageList = carol2
        .get(&format!("/messages?account={}&state=verified", acc.id))
        .await;
    assert_eq!(all.total, BULK);
    // Wrong password is rejected; password change keeps data readable.
    assert!(api2
        .call::<_, LoginResponse>(
            Method::POST,
            "/auth/login",
            Some(&LoginRequest {
                username: name.clone(),
                password: "nope-nope-nope".into(),
                totp: None,
            })
        )
        .await
        .is_err());
    let _: serde_json::Value = carol2
        .post(
            "/auth/password",
            &ChangePasswordRequest {
                old_password: format!("{name}-password"),
                new_password: "a-brand-new-password".into(),
            },
        )
        .await;
    let _: serde_json::Value = carol2.post("/auth/lock", &()).await;
    let carol3 = api2.login(&name, "a-brand-new-password").await;
    let v: MessageView = carol3
        .get(&format!("/messages/{}/view", all.messages[0].id))
        .await;
    assert!(v.subject.starts_with("bulk"));
}

const BULK: u64 = 200;

async fn admin_view_job(server: &malo_server::Running, id: &str) -> JobInfo {
    for _ in 0..100 {
        if let Some((_, j)) = server.state.db.job(id).unwrap() {
            if j.state.is_finished() {
                return j;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("job {id} never finished");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integrity_detects_repairs_and_blocks_purge() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let dave = new_user(&admin, &uniq("dave")).await;
    let prefix = uniq("int");
    let s3: DestinationView = dave
        .post("/destinations", &s3_dest("rustfs", "malo-b", &prefix, true))
        .await;
    let fs: DestinationView = dave.post("/destinations", &fs_dest("local", "b")).await;
    let imap_user = uniq("int-");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    for i in 0..6 {
        append(
            &mut c,
            "INBOX",
            None,
            Some("01-Jan-2020 10:00:00 +0000"),
            &mail(&format!("old {i}"), 5000),
        )
        .await;
    }
    c.logout().await;
    let acc: AccountView = dave
        .post("/accounts", &imap_input("int", &imap_user, IMAP_PORT))
        .await;
    job_result::<serde_json::Value>(
        &dave
            .run_job(JobKind::Backup {
                account_id: acc.id.clone(),
            })
            .await,
    );

    let clean: CheckReport = job_result(
        &dave
            .run_job(JobKind::Check {
                scope: CheckScope::All,
                deep: true,
            })
            .await,
    );
    assert!(clean.ok, "{clean:?}");
    assert_eq!(clean.accounts[0].backlog, 0);

    // Policy that would purge everything, requiring both destinations.
    let policy = PurgePolicy {
        older_than_days: 30,
        required_destinations: vec![s3.id.clone(), fs.id.clone()],
        exclude_mailboxes: vec![],
        exclude_flagged: true,
        schedule_hours: 0,
        armed: false,
        armed_at: None,
    };
    let _: AccountView = dave
        .put(&format!("/accounts/{}/policy", acc.id), &policy)
        .await;

    // Delete one object and corrupt another behind Malo's back.
    let me: Me = dave.get("/me").await;
    let user = server.state.keyring.get(&me.id).unwrap();
    let reps = user.index.replicas_in(&s3.id).unwrap();
    let op = s3_operator("malo-b");
    op.delete(&reps[0].object_path).await.unwrap();
    let mut raw = op.read(&reps[1].object_path).await.unwrap().to_vec();
    raw[200] ^= 0xFF;
    op.write(&reps[1].object_path, raw).await.unwrap();

    let quick: CheckReport = job_result(
        &dave
            .run_job(JobKind::Check {
                scope: CheckScope::All,
                deep: false,
            })
            .await,
    );
    let h = quick
        .destinations
        .iter()
        .find(|d| d.destination_id == s3.id)
        .unwrap();
    assert_eq!(
        (h.missing, h.corrupt, h.ok),
        (1, 0, false),
        "quick check sees the missing object only: {h:?}"
    );
    let deep: CheckReport = job_result(
        &dave
            .run_job(JobKind::Check {
                scope: CheckScope::Destination {
                    destination_id: s3.id.clone(),
                },
                deep: true,
            })
            .await,
    );
    let h = &deep.destinations[0];
    assert_eq!((h.missing, h.corrupt), (1, 1), "{h:?}");
    // A later quick check (or a deep slice that skips it) must not forget the known corruption.
    let quick: CheckReport = job_result(
        &dave
            .run_job(JobKind::Check {
                scope: CheckScope::All,
                deep: false,
            })
            .await,
    );
    let h = quick
        .destinations
        .iter()
        .find(|d| d.destination_id == s3.id)
        .unwrap();
    assert_eq!((h.missing, h.corrupt), (1, 1), "{h:?}");

    // Purge is blocked while the required destination is failing.
    let preview: PurgePreview = job_result(
        &dave
            .run_job(JobKind::PurgeDryRun {
                account_id: acc.id.clone(),
            })
            .await,
    );
    assert!(
        preview
            .blocked_reason
            .as_deref()
            .unwrap_or("")
            .contains("integrity"),
        "{preview:?}"
    );

    // Repair restores both from the fs copy.
    let repaired: CheckReport = job_result(
        &dave
            .run_job(JobKind::Repair {
                scope: CheckScope::All,
            })
            .await,
    );
    assert_eq!(repaired.repaired, 2, "{repaired:?}");
    assert!(repaired.ok);
    let after: CheckReport = job_result(
        &dave
            .run_job(JobKind::Check {
                scope: CheckScope::All,
                deep: true,
            })
            .await,
    );
    assert!(after.ok, "{after:?}");
    for r in user.index.replicas_in(&s3.id).unwrap() {
        assert_eq!(r.status, ReplicaStatus::Verified);
    }
    let preview: PurgePreview = job_result(
        &dave
            .run_job(JobKind::PurgeDryRun {
                account_id: acc.id.clone(),
            })
            .await,
    );
    assert_eq!(preview.blocked_reason, None, "{preview:?}");
    assert_eq!(preview.total_count, 6);

    // Orphans are reported but don't fail the destination.
    op.write(
        &format!(
            "{}/objects/zz/orphan.enc",
            reps[0].object_path.split("/objects/").next().unwrap()
        ),
        vec![1u8; 10],
    )
    .await
    .unwrap();
    let orphan: CheckReport = job_result(
        &dave
            .run_job(JobKind::Check {
                scope: CheckScope::All,
                deep: false,
            })
            .await,
    );
    let h = orphan
        .destinations
        .iter()
        .find(|d| d.destination_id == s3.id)
        .unwrap();
    assert_eq!(h.orphaned, 1);
    assert!(h.ok);
    let latest: Option<CheckReport> = dave.get("/checks/latest").await;
    assert_eq!(latest.unwrap().id, orphan.id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purge_rules_and_refusals() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let erin = new_user(&admin, &uniq("erin")).await;
    let prefix = uniq("purge");
    let s3: DestinationView = erin
        .post("/destinations", &s3_dest("rustfs", "malo-a", &prefix, true))
        .await;
    let fs: DestinationView = erin.post("/destinations", &fs_dest("local", "p")).await;
    let old = Some("01-Jan-2020 10:00:00 +0000");

    let imap_user = uniq("purge-");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    create_mailbox(&mut c, "Keep").await;
    for i in 0..3 {
        append(
            &mut c,
            "INBOX",
            None,
            old,
            &mail(&format!("eligible {i}"), 1000),
        )
        .await;
    }
    append(
        &mut c,
        "INBOX",
        Some("(\\Flagged)"),
        old,
        &mail("old flagged", 0),
    )
    .await;
    append(&mut c, "INBOX", None, None, &mail("too new", 0)).await;
    append(
        &mut c,
        "INBOX",
        Some("(\\Deleted)"),
        None,
        &mail("new decoy deleted", 0),
    )
    .await;
    append(&mut c, "Keep", None, old, &mail("old but kept", 0)).await;
    c.logout().await;
    let acc: AccountView = erin
        .post("/accounts", &imap_input("purge", &imap_user, IMAP_PORT))
        .await;
    job_result::<serde_json::Value>(
        &erin
            .run_job(JobKind::Backup {
                account_id: acc.id.clone(),
            })
            .await,
    );

    let policy = PurgePolicy {
        older_than_days: 30,
        required_destinations: vec![s3.id.clone(), fs.id.clone()],
        exclude_mailboxes: vec!["Keep".into()],
        exclude_flagged: true,
        schedule_hours: 24,
        armed: false,
        armed_at: None,
    };
    let _: AccountView = erin
        .put(&format!("/accounts/{}/policy", acc.id), &policy)
        .await;
    let scheds: Vec<ScheduledJob> = erin.get("/schedules").await;
    assert!(
        !scheds.iter().any(|s| s.key.starts_with("purge:")),
        "not scheduled before arming"
    );
    // Can't purge or arm without a dry run of this exact policy.
    let e = erin
        .call::<_, JobInfo>(
            Method::POST,
            "/jobs",
            Some(&CreateJobRequest {
                kind: JobKind::Purge {
                    account_id: acc.id.clone(),
                },
            }),
        )
        .await;
    assert_eq!(e.unwrap_err().0, 409);
    let arm = |name: &str| ArmRequest {
        confirm_name: name.into(),
    };
    let e = erin
        .call::<_, AccountView>(
            Method::POST,
            &format!("/accounts/{}/policy/arm", acc.id),
            Some(&arm("purge")),
        )
        .await;
    assert_eq!(e.unwrap_err().0, 409);
    let preview: PurgePreview = job_result(
        &erin
            .run_job(JobKind::PurgeDryRun {
                account_id: acc.id.clone(),
            })
            .await,
    );
    assert_eq!(preview.total_count, 3, "{preview:?}");
    assert_eq!(preview.blocked_reason, None);
    let e = erin
        .call::<_, AccountView>(
            Method::POST,
            &format!("/accounts/{}/policy/arm", acc.id),
            Some(&arm("wrong")),
        )
        .await;
    assert_eq!(e.unwrap_err().0, 400);
    let armed: AccountView = erin
        .post(&format!("/accounts/{}/policy/arm", acc.id), &arm("purge"))
        .await;
    assert!(armed.policy.armed);
    let scheds: Vec<ScheduledJob> = erin.get("/schedules").await;
    assert!(
        scheds.iter().any(|s| s.key == format!("purge:{}", acc.id)),
        "scheduled once armed"
    );

    // The armed policy runs from the scheduler (forced due now) — no manual trigger.
    let me: Me = erin.get("/me").await;
    server
        .state
        .db
        .set_next_run(&me.id, &format!("purge:{}", acc.id), chrono::Utc::now())
        .unwrap();
    let purge_job = {
        let mut found = None;
        for _ in 0..100 {
            let jobs: Vec<JobInfo> = erin.get("/jobs").await;
            found = jobs.into_iter().find(|j| {
                matches!(&j.kind, JobKind::Purge { account_id } if *account_id == acc.id)
                    && j.trigger == JobTrigger::Scheduled
            });
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        found.expect("scheduled purge started")
    };
    let summary: PurgeSummary = job_result(&erin.wait_job(&purge_job.id).await);
    assert_eq!(summary.deleted, 3, "{summary:?}");
    let left = server_messages(&imap_user, IMAP_PORT).await;
    let mut subjects: Vec<_> = left.keys().cloned().collect();
    subjects.sort();
    assert_eq!(
        subjects,
        vec![
            "new decoy deleted",
            "old but kept",
            "old flagged",
            "too new"
        ]
    );
    let audit: Vec<AuditEntry> = erin.get(&format!("/audit?account={}", acc.id)).await;
    assert_eq!(audit.iter().filter(|a| a.kind == "purged").count(), 3);
    // Purged mail stays readable from the backup.
    let gone: MessageList = erin
        .get(&format!("/messages?account={}&q=eligible", acc.id))
        .await;
    assert!(gone.messages.iter().all(|m| m.deleted_on_server));
    let v: MessageView = erin
        .get(&format!("/messages/{}/view", gone.messages[0].id))
        .await;
    assert!(v.subject.starts_with("eligible"));
    // Any policy change disarms.
    let changed: AccountView = erin
        .put(
            &format!("/accounts/{}/policy", acc.id),
            &PurgePolicy {
                older_than_days: 60,
                ..policy.clone()
            },
        )
        .await;
    assert!(!changed.policy.armed);

    // Missing replica → pre-purge re-verify aborts before touching the server.
    let imap2 = uniq("purge2-");
    let mut c = imap_conn(&imap2, IMAP_PORT).await;
    for i in 0..2 {
        append(&mut c, "INBOX", None, old, &mail(&format!("victim {i}"), 0)).await;
    }
    c.logout().await;
    let acc2: AccountView = erin
        .post("/accounts", &imap_input("purge2", &imap2, IMAP_PORT))
        .await;
    job_result::<serde_json::Value>(
        &erin
            .run_job(JobKind::Backup {
                account_id: acc2.id.clone(),
            })
            .await,
    );
    let p2 = PurgePolicy {
        exclude_mailboxes: vec![],
        ..policy.clone()
    };
    let _: AccountView = erin
        .put(&format!("/accounts/{}/policy", acc2.id), &p2)
        .await;
    job_result::<PurgePreview>(
        &erin
            .run_job(JobKind::PurgeDryRun {
                account_id: acc2.id.clone(),
            })
            .await,
    );
    let _: AccountView = erin
        .post(&format!("/accounts/{}/policy/arm", acc2.id), &arm("purge2"))
        .await;
    let me: Me = erin.get("/me").await;
    let user = server.state.keyring.get(&me.id).unwrap();
    let list: MessageList = erin.get(&format!("/messages?account={}", acc2.id)).await;
    let rep = user
        .index
        .replicas_of(list.messages[0].id)
        .unwrap()
        .into_iter()
        .find(|r| r.destination == s3.id)
        .unwrap();
    s3_operator("malo-a")
        .delete(&rep.object_path)
        .await
        .unwrap();
    let failed = erin
        .run_job(JobKind::Purge {
            account_id: acc2.id.clone(),
        })
        .await;
    assert_eq!(failed.state, JobState::Failed);
    assert!(failed.error.unwrap_or_default().contains("re-verification"));
    assert_eq!(
        server_messages(&imap2, IMAP_PORT).await.len(),
        2,
        "nothing deleted"
    );
    // The failed re-verification blocks purges until a repair fixes the destination.
    let blocked: PurgePreview = job_result(
        &erin
            .run_job(JobKind::PurgeDryRun {
                account_id: acc2.id.clone(),
            })
            .await,
    );
    assert!(blocked.blocked_reason.is_some());
    let fixed: CheckReport = job_result(
        &erin
            .run_job(JobKind::Repair {
                scope: CheckScope::All,
            })
            .await,
    );
    assert!(fixed.ok && fixed.repaired == 1, "{fixed:?}");

    // UIDVALIDITY change: the recreated mailbox is never purged from stale records.
    let imap3 = uniq("purge3-");
    let mut c = imap_conn(&imap3, IMAP_PORT).await;
    create_mailbox(&mut c, "Folder").await;
    append(&mut c, "Folder", None, old, &mail("in folder", 0)).await;
    c.logout().await;
    let acc3: AccountView = erin
        .post("/accounts", &imap_input("purge3", &imap3, IMAP_PORT))
        .await;
    job_result::<serde_json::Value>(
        &erin
            .run_job(JobKind::Backup {
                account_id: acc3.id.clone(),
            })
            .await,
    );
    let _: AccountView = erin
        .put(&format!("/accounts/{}/policy", acc3.id), &p2)
        .await;
    let pv: PurgePreview = job_result(
        &erin
            .run_job(JobKind::PurgeDryRun {
                account_id: acc3.id.clone(),
            })
            .await,
    );
    assert_eq!(pv.total_count, 1);
    let _: AccountView = erin
        .post(&format!("/accounts/{}/policy/arm", acc3.id), &arm("purge3"))
        .await;
    let mut c = imap_conn(&imap3, IMAP_PORT).await;
    c.session.delete("Folder").await.unwrap();
    create_mailbox(&mut c, "Folder").await;
    append(&mut c, "Folder", None, old, &mail("in folder", 0)).await;
    c.logout().await;
    let s: PurgeSummary = job_result(
        &erin
            .run_job(JobKind::Purge {
                account_id: acc3.id.clone(),
            })
            .await,
    );
    assert_eq!(s.deleted, 0, "{s:?}");
    // Dovecot may hand the recreated mailbox the same UIDVALIDITY (same second); then the identity
    // check (Message-ID, received date, content) is what stops the purge.
    assert!(
        s.errors
            .iter()
            .any(|e| e.contains("UIDVALIDITY") || e.contains("identity changed")),
        "{s:?}"
    );
    assert_eq!(server_messages(&imap3, IMAP_PORT).await.len(), 1);

    // No UIDPLUS → purge refused.
    let imap4 = uniq("nouid-");
    let mut c = imap_conn(&imap4, IMAP_NO_UIDPLUS_PORT).await;
    append(&mut c, "INBOX", None, old, &mail("cannot purge", 0)).await;
    c.logout().await;
    let acc4: AccountView = erin
        .post(
            "/accounts",
            &imap_input("nouid", &imap4, IMAP_NO_UIDPLUS_PORT),
        )
        .await;
    let t: ConnectionTest = erin.post(&format!("/accounts/{}/test", acc4.id), &()).await;
    assert!(!t.uidplus && t.warnings.iter().any(|w| w.contains("UIDPLUS")));
    job_result::<serde_json::Value>(
        &erin
            .run_job(JobKind::Backup {
                account_id: acc4.id.clone(),
            })
            .await,
    );
    let _: AccountView = erin
        .put(&format!("/accounts/{}/policy", acc4.id), &p2)
        .await;
    let pv: PurgePreview = job_result(
        &erin
            .run_job(JobKind::PurgeDryRun {
                account_id: acc4.id.clone(),
            })
            .await,
    );
    assert!(
        pv.blocked_reason
            .as_deref()
            .unwrap_or("")
            .contains("UIDPLUS"),
        "{pv:?}"
    );
    let _: AccountView = erin
        .post(&format!("/accounts/{}/policy/arm", acc4.id), &arm("nouid"))
        .await;
    let refused = erin
        .run_job(JobKind::Purge {
            account_id: acc4.id.clone(),
        })
        .await;
    assert_eq!(refused.state, JobState::Failed);
    assert!(refused.error.unwrap_or_default().contains("UIDPLUS"));
    assert_eq!(server_messages(&imap4, IMAP_NO_UIDPLUS_PORT).await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rebuild_index_and_recovery_kit() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let name = uniq("fran");
    let fran = new_user(&admin, &name).await;
    let fran_password = format!("{name}-password");
    let prefix = uniq("kit");
    let s3_input = s3_dest("rustfs", "malo-b", &prefix, true);
    let _: DestinationView = fran.post("/destinations", &s3_input).await;
    // Settings travel in the settings copy too, and a restore from the kit takes them over.
    let _: UserSettings = fran
        .put(
            "/settings",
            &UserSettings {
                quick_check_hours: 7,
                ..Default::default()
            },
        )
        .await;
    let imap_user = uniq("kit-");
    seed_standard(&imap_user).await;
    let acc: AccountView = fran
        .post("/accounts", &imap_input("kit", &imap_user, IMAP_PORT))
        .await;
    job_result::<serde_json::Value>(
        &fran
            .run_job(JobKind::Backup {
                account_id: acc.id.clone(),
            })
            .await,
    );
    let me: Me = fran.get("/me").await;
    assert!(me.recovery_kit_pending);
    // The app checks a password before keeping it in a profile; a wrong one is not a lost session.
    let ok = fran
        .call::<_, serde_json::Value>(
            Method::POST,
            "/auth/verify-password",
            Some(&serde_json::json!({ "password": fran_password })),
        )
        .await;
    assert!(ok.is_ok(), "{ok:?}");
    let wrong = fran
        .call::<_, serde_json::Value>(
            Method::POST,
            "/auth/verify-password",
            Some(&serde_json::json!({ "password": "not it" })),
        )
        .await;
    assert_eq!(wrong.unwrap_err().0, 403);
    let kit: SealedRecoveryKit = fran
        .post(
            "/recovery-kit",
            &RecoveryKitRequest {
                password: fran_password.clone(),
                passphrase: "kit passphrase for fran".into(),
            },
        )
        .await;
    assert_eq!(kit.format, malo_api::SEALED_KIT_FORMAT);
    // Fetching the kit alone doesn't count as saved; the app confirms after writing the file.
    let me: Me = fran.get("/me").await;
    assert!(me.recovery_kit_pending);
    let _: serde_json::Value = fran
        .post("/recovery-kit/saved", &serde_json::json!({}))
        .await;
    let me: Me = fran.get("/me").await;
    assert!(!me.recovery_kit_pending);
    assert!(
        !me.recovery_kit_outdated,
        "the kit holds the destinations as they are"
    );
    // The kit file doesn't contain the key, the username, the user id or the destination's
    // credentials in the clear.
    let file = serde_json::to_string(&kit).unwrap();
    assert!(!file.contains(&name) && !file.contains(&me.id), "{file}");
    assert!(
        !file.contains("rustfs") && !file.contains(&prefix),
        "{file}"
    );

    // A forgotten password: the kit resets it in place, keeping accounts and backups.
    let anon = Api {
        token: None,
        ..admin.clone()
    };
    let recover = |passphrase: &str, new_password: &str| RecoverRequest {
        username: name.clone(),
        recovery_kit: RecoveryKitFile::Sealed(kit.clone()),
        kit_passphrase: Some(passphrase.into()),
        new_password: new_password.into(),
    };
    let wrong = anon
        .call::<_, serde_json::Value>(
            Method::POST,
            "/auth/recover",
            Some(&recover("not the passphrase", "fran-new-password-1")),
        )
        .await;
    assert_eq!(wrong.unwrap_err().0, 401);
    // Someone else's kit can't reset fran's password.
    let other = new_user(&admin, &uniq("other")).await;
    let other_kit: SealedRecoveryKit = other
        .post(
            "/recovery-kit",
            &RecoveryKitRequest {
                password: format!("{}-password", other_name(&other).await),
                passphrase: "kit passphrase for other".into(),
            },
        )
        .await;
    let foreign = anon
        .call::<_, serde_json::Value>(
            Method::POST,
            "/auth/recover",
            Some(&RecoverRequest {
                recovery_kit: RecoveryKitFile::Sealed(other_kit),
                kit_passphrase: Some("kit passphrase for other".into()),
                ..recover("", "fran-new-password-1")
            }),
        )
        .await;
    assert_eq!(foreign.unwrap_err().0, 401);
    let _: serde_json::Value = anon
        .post(
            "/auth/recover",
            &recover("kit passphrase for fran", "fran-new-password-1"),
        )
        .await;
    // Every session was logged out, the old password is gone, and the data is unchanged.
    assert_eq!(fran.status_of(Method::GET, "/me").await, 401);
    let old = anon
        .call::<_, LoginResponse>(
            Method::POST,
            "/auth/login",
            Some(&LoginRequest {
                username: name.clone(),
                password: fran_password.clone(),
                totp: None,
            }),
        )
        .await;
    assert!(old.is_err());
    let fran = anon.login(&name, "fran-new-password-1").await;
    let accounts: Vec<AccountView> = fran.get("/accounts").await;
    assert_eq!(accounts.len(), 1);
    let list: MessageList = fran.get("/messages?limit=100").await;
    assert_eq!(list.total, 5);

    // Restore: a brand-new user created from the kit gets its destinations back. Their
    // credentials weren't kept in the kit (the default), so the restore starts once the storage
    // secret is entered again; then everything else comes back from the destination.
    let invite: Invite = admin
        .post(
            "/admin/invites",
            &CreateInviteRequest {
                username: None,
                role: Role::User,
                valid_hours: 1,
            },
        )
        .await;
    let heir = uniq("heir");
    let reg: RegisterResponse = anon
        .post(
            "/auth/register",
            &RegisterRequest {
                username: heir.clone(),
                password: "heir-password-1".into(),
                invite_code: Some(invite.code),
                recovery_kit: Some(RecoveryKitFile::Sealed(kit)),
                kit_passphrase: Some("kit passphrase for fran".into()),
            },
        )
        .await;
    assert_eq!(reg.restored_destinations, 1);
    let heir_api = anon.login(&heir, "heir-password-1").await;
    let dests: Vec<DestinationView> = heir_api.get("/destinations").await;
    assert_eq!(
        dests[0].missing_secrets.as_deref(),
        Some(&["secret_access_key".to_string()][..])
    );
    assert!(!dests[0].options.contains_key("secret_access_key"));
    let jobs: Vec<JobInfo> = heir_api.get("/jobs").await;
    assert!(
        !jobs
            .iter()
            .any(|j| matches!(j.kind, JobKind::RebuildIndexAll)),
        "nothing to restore from until the destination has its credentials"
    );
    let _: DestinationView = heir_api
        .put(&format!("/destinations/{}", dests[0].id), &s3_input)
        .await;
    let api = heir_api.clone();
    let restored = wait_until(
        move || {
            let api = api.clone();
            Box::pin(async move {
                let jobs: Vec<JobInfo> = api.get("/jobs").await;
                jobs.iter().any(|j| {
                    matches!(j.kind, JobKind::RebuildIndexAll)
                        && j.state != JobState::Queued
                        && j.state != JobState::Running
                })
            })
        },
        120,
    )
    .await;
    assert!(
        restored,
        "entering the credentials didn't start the restore"
    );
    let jobs: Vec<JobInfo> = heir_api.get("/jobs").await;
    let rebuild = jobs
        .iter()
        .find(|j| matches!(j.kind, JobKind::RebuildIndexAll))
        .unwrap();
    job_result::<serde_json::Value>(rebuild);
    let settings: UserSettings = heir_api.get("/settings").await;
    assert_eq!(settings.quick_check_hours, 7, "settings come back too");
    let me: Me = heir_api.get("/me").await;
    assert!(!me.recovery_kit_pending && !me.recovery_kit_outdated);
    // Logging in again doesn't restore twice.
    let again = anon.login(&heir, "heir-password-1").await;
    let jobs: Vec<JobInfo> = again.get("/jobs").await;
    assert_eq!(
        jobs.iter()
            .filter(|j| matches!(j.kind, JobKind::RebuildIndexAll))
            .count(),
        1
    );
    // The encrypted settings copy on the destination brings the account back with its settings
    // but, by default, without its password: it asks to sign in again (purge disarmed). The
    // destination isn't added twice.
    let accounts: Vec<AccountView> = heir_api.get("/accounts").await;
    assert_eq!(accounts.len(), 1);
    assert!(accounts[0].imported);
    assert_eq!(accounts[0].name, "kit");
    assert_eq!(accounts[0].host, acc.host);
    assert!(!accounts[0].policy.armed);
    let resumed: AccountView = heir_api
        .put(
            &format!("/accounts/{}", accounts[0].id),
            &imap_input("kit", &imap_user, IMAP_PORT),
        )
        .await;
    assert!(!resumed.imported, "signing in again resumes the account");
    let dests: Vec<DestinationView> = heir_api.get("/destinations").await;
    assert_eq!(dests.len(), 1);
    assert_eq!(dests[0].missing_secrets.as_deref(), Some(&[][..]));
    let list: MessageList = heir_api.get("/messages?limit=100").await;
    let subjects: Vec<_> = list
        .messages
        .iter()
        .map(|m| (m.envelope.subject.clone(), m.mailboxes.clone()))
        .collect();
    assert_eq!(list.total, 5, "{subjects:?}");
    let original = server_messages(&imap_user, IMAP_PORT).await;
    for m in &list.messages {
        assert_eq!(
            &heir_api.bytes(&format!("/messages/{}/raw", m.id)).await,
            &original[&m.envelope.subject]
        );
    }
    let boxes: Vec<MailboxInfo> = heir_api.get("/mailboxes").await;
    assert!(boxes
        .iter()
        .any(|b| b.display_name == "Entwürfe/Ünïcödé 日本"));
    // Invite codes are single-use.
    let users: Vec<UserInfo> = admin.get("/admin/users").await;
    assert!(users.iter().any(|u| u.username == heir));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn starttls_and_idle_trigger() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let gail = new_user(&admin, &uniq("gail")).await;
    let _: DestinationView = gail.post("/destinations", &fs_dest("local", "s")).await;

    // STARTTLS on port 143: upgraded before LOGIN, backup works.
    let imap_user = uniq("stls-");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    append(&mut c, "INBOX", None, None, &mail("over starttls", 0)).await;
    c.logout().await;
    let mut input = imap_input("starttls", &imap_user, 10143);
    input.tls = TlsMode::Starttls;
    input.idle = true;
    let t: ConnectionTest = gail.post("/accounts/test", &input).await;
    assert!(t.ok, "{t:?}");
    let acc: AccountView = gail.post("/accounts", &input).await;
    let first = gail
        .run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
        .await;
    job_result::<serde_json::Value>(&first);

    // IDLE: a new message triggers a backup without any manual job or schedule tick.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    append(&mut c, "INBOX", None, None, &mail("pushed by idle", 0)).await;
    c.logout().await;
    let api = gail.clone();
    let id = acc.id.clone();
    let arrived = wait_until(
        move || {
            let api = api.clone();
            let id = id.clone();
            Box::pin(async move {
                let l: MessageList = api
                    .get(&format!("/messages?account={id}&q=pushed&state=verified"))
                    .await;
                l.total == 1
            })
        },
        30,
    )
    .await;
    assert!(arrived, "IDLE did not trigger a backup");
    // The triggered job finishes shortly after the message is verified (manifests are written last).
    let api = gail.clone();
    let finished = wait_until(
        move || {
            let api = api.clone();
            Box::pin(async move {
                let jobs: Vec<JobInfo> = api.get("/jobs").await;
                jobs.iter()
                    .any(|j| j.trigger == JobTrigger::Scheduled && j.state == JobState::Done)
            })
        },
        30,
    )
    .await;
    assert!(finished, "the IDLE-triggered backup job never finished");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth2_xoauth2_backup_against_local_provider() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let hana = new_user(&admin, &uniq("hana")).await;
    let _: DestinationView = hana.post("/destinations", &fs_dest("local", "o")).await;

    // The mailbox owner signs in at the provider; Malo only ever gets the refresh token.
    let imap_user = uniq("oauth-");
    let refresh = oauth_refresh_token(&imap_user).await;
    let mut c = oauth_imap_conn(&imap_user, &refresh).await;
    append(&mut c, "INBOX", None, None, &mail("oauth one", 0)).await;
    append(&mut c, "INBOX", None, None, &mail("oauth two", 20_000)).await;
    c.logout().await;

    // Password login is impossible on this server; the token path is the only way in.
    let pw = hana
        .post::<_, ConnectionTest>(
            "/accounts/test",
            &imap_input("pw", &imap_user, IMAP_OAUTH_PORT),
        )
        .await;
    assert!(!pw.ok);

    let input = oauth_input("oauth mail", &imap_user, &refresh);
    let t: ConnectionTest = hana.post("/accounts/test", &input).await;
    assert!(t.ok, "{t:?}");
    let acc: AccountView = hana.post("/accounts", &input).await;
    // Secrets never come back from the API.
    match &acc.auth {
        AccountAuth::OAuth2 {
            refresh_token,
            client_secret,
            ..
        } => {
            assert_eq!(refresh_token, REDACTED);
            assert!(client_secret.is_none());
        }
        other => panic!("unexpected auth {other:?}"),
    }
    let stats: serde_json::Value = job_result(
        &hana
            .run_job(JobKind::Backup {
                account_id: acc.id.clone(),
            })
            .await,
    );
    assert_eq!(stats["discovered"], 2, "{stats}");
    let list: MessageList = hana
        .get(&format!("/messages?account={}&state=verified", acc.id))
        .await;
    assert_eq!(list.total, 2);

    // Editing the account with the redacted placeholder keeps the stored refresh token.
    let mut edited = input.clone();
    edited.name = "oauth mail (renamed)".into();
    if let AccountAuth::OAuth2 { refresh_token, .. } = &mut edited.auth {
        *refresh_token = REDACTED.into();
    }
    let _: AccountView = hana.put(&format!("/accounts/{}", acc.id), &edited).await;
    let again: serde_json::Value = job_result(
        &hana
            .run_job(JobKind::Backup {
                account_id: acc.id.clone(),
            })
            .await,
    );
    assert_eq!(again["errors"].as_array().unwrap().len(), 0, "{again}");

    // An unknown refresh token fails: real providers reject it at refresh time (invalid_grant); the
    // lenient mock issues a token for another subject, which the IMAP server then refuses.
    let bad = oauth_input("bad", &imap_user, "not-a-real-refresh-token");
    let t: ConnectionTest = hana.post("/accounts/test", &bad).await;
    assert!(!t.ok);
    let err = t.error.unwrap_or_default();
    assert!(
        err.contains("token refresh failed") || err.contains("XOAUTH2"),
        "{err}"
    );
    // A valid token for a different mailbox is refused by the IMAP server.
    let other = oauth_refresh_token(&uniq("oauth-other-")).await;
    let t: ConnectionTest = hana
        .post("/accounts/test", &oauth_input("x", &imap_user, &other))
        .await;
    assert!(!t.ok && t.error.unwrap_or_default().contains("XOAUTH2"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_own_account_requires_phrase_and_password() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let name = uniq("ivan");
    let ivan = new_user(&admin, &name).await;
    let _: DestinationView = ivan.post("/destinations", &fs_dest("local", "d")).await;
    let me: Me = ivan.get("/me").await;
    let user_dir = dir.path().join("users").join(&me.id);
    assert!(user_dir.join("vault.bin").exists());

    let req = |password: &str, confirm: &str| DeleteAccountRequest {
        password: password.into(),
        confirm: confirm.into(),
    };
    let wrong_phrase = ivan
        .call::<_, serde_json::Value>(
            Method::POST,
            "/me/delete",
            Some(&req(&format!("{name}-password"), "delete me")),
        )
        .await;
    assert_eq!(wrong_phrase.unwrap_err().0, 400);
    let wrong_password = ivan
        .call::<_, serde_json::Value>(
            Method::POST,
            "/me/delete",
            Some(&req("not-my-password", &format!("delete {name}"))),
        )
        .await;
    assert_eq!(wrong_password.unwrap_err().0, 401);
    assert!(user_dir.exists(), "nothing deleted after failed attempts");

    // The last administrator can't delete themselves.
    let last_admin = admin
        .call::<_, serde_json::Value>(
            Method::POST,
            "/me/delete",
            Some(&req("admin-password-1", "delete admin")),
        )
        .await;
    assert_eq!(last_admin.unwrap_err().0, 409);

    let _: serde_json::Value = ivan
        .post(
            "/me/delete",
            &req(&format!("{name}-password"), &format!("delete {name}")),
        )
        .await;
    assert!(!user_dir.exists(), "keys, index and local backups are gone");
    assert_eq!(ivan.status_of(Method::GET, "/me").await, 401);
    let anon = Api {
        token: None,
        ..admin.clone()
    };
    assert!(anon
        .call::<_, LoginResponse>(
            Method::POST,
            "/auth/login",
            Some(&LoginRequest {
                username: name.clone(),
                password: format!("{name}-password"),
                totp: None,
            }),
        )
        .await
        .is_err());
    let users: Vec<UserInfo> = admin.get("/admin/users").await;
    assert!(!users.iter().any(|u| u.username == name));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_traversal_is_rejected_everywhere() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("nas");
    std::fs::create_dir_all(&mount).unwrap();
    let server = start_server(dir.path(), |c| c.allowed_fs_mounts = vec![mount.clone()]).await;
    let admin = bootstrap(&server).await;
    let kim = new_user(&admin, &uniq("kim")).await;
    let lee = new_user(&admin, &uniq("lee")).await;

    let status = |r: Result<DestinationView, (u16, String)>| r.map(|_| 0).unwrap_or_else(|e| e.0);
    // `..` in the fs folder, in the prefix, absolute paths outside the allowed mounts, server-file options.
    let mut cases = vec![];
    for folder in [
        "../x",
        "a/../../..",
        "..",
        "/etc",
        &format!("{}/../escape", mount.display()),
    ] {
        cases.push(fs_dest("bad", folder));
    }
    let mut prefixed = fs_dest("bad", "ok");
    prefixed.root = "../../..".into();
    cases.push(prefixed);
    let mut s3 = s3_dest("bad", "malo-a", "a/../..", true);
    cases.push(s3.clone());
    // Object stores refuse control characters: such a prefix could never hold a backup.
    cases.push(s3_dest("bad", "malo-a", "x/\n|STRASSE", true));
    // Keys under such a prefix would exceed the object store's key length.
    cases.push(s3_dest("bad", "malo-a", &"Straße👨‍👩‍👧".repeat(40), true));
    s3.root = "fine".into();
    s3.options.insert("root".into(), "/x/../../y".into());
    cases.push(s3);
    let mut gcs = gcs_dest("bad", "fine", true);
    gcs.options
        .insert("credential_path".into(), "/etc/shadow".into());
    cases.push(gcs);
    // An "external account" credential would read a server file and post it to its token URL.
    let mut gcs = gcs_dest("bad", "fine", true);
    gcs.options.remove("allow_anonymous");
    gcs.options.insert(
        "credential".into(),
        base64::engine::general_purpose::STANDARD.encode(
            r#"{"type":"external_account","audience":"a","subject_token_type":"x","token_url":"http://127.0.0.1:9/t","credential_source":{"file":"/etc/passwd","format":{"type":"text"}}}"#,
        ),
    );
    cases.push(gcs);
    for c in &cases {
        let created = status(kim.call(Method::POST, "/destinations", Some(c)).await);
        assert_eq!(created, 400, "accepted {c:?}");
        match kim
            .call::<_, DestinationTest>(Method::POST, "/destinations/test", Some(c))
            .await
        {
            Err((400, msg)) => assert!(
                msg.contains("..")
                    || msg.contains("allowed")
                    || msg.contains("file on the server")
                    || msg.contains("forbidden character")
                    || msg.contains("too long")
                    || msg.contains("service account key"),
                "{msg}"
            ),
            Ok(t) => assert!(!t.ok, "test endpoint used {c:?}"),
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert!(!dir.path().join("escape").exists());

    // Usernames can't smuggle dots either.
    let invite: Invite = admin
        .post(
            "/admin/invites",
            &CreateInviteRequest {
                username: None,
                role: Role::User,
                valid_hours: 1,
            },
        )
        .await;
    let anon = Api {
        token: None,
        ..admin.clone()
    };
    for name in ["..", ".hidden", "a..b"] {
        let r = anon
            .call::<_, serde_json::Value>(
                Method::POST,
                "/auth/register",
                Some(&RegisterRequest {
                    username: name.into(),
                    password: "long-enough-password".into(),
                    invite_code: Some(invite.code.clone()),
                    recovery_kit: None,
                    kit_passphrase: None,
                }),
            )
            .await;
        assert_eq!(r.unwrap_err().0, 400, "{name}");
    }

    // A shared mount gives each user their own subfolder, even when both ask for the same path.
    let same = mount.join("family");
    let shared = fs_dest("nas", same.to_str().unwrap());
    let _: DestinationView = kim.post("/destinations", &shared).await;
    let _: DestinationView = lee.post("/destinations", &shared).await;
    for (api, who) in [(&kim, "k"), (&lee, "l")] {
        let imap_user = uniq(&format!("trav-{who}-"));
        let mut c = imap_conn(&imap_user, IMAP_PORT).await;
        append(
            &mut c,
            "INBOX",
            None,
            None,
            &mail(&format!("mail of {who}"), 0),
        )
        .await;
        c.logout().await;
        let acc: AccountView = api
            .post("/accounts", &imap_input("same name", &imap_user, IMAP_PORT))
            .await;
        job_result::<serde_json::Value>(
            &api.run_job(JobKind::Backup {
                account_id: acc.id.clone(),
            })
            .await,
        );
    }
    let kim_me: Me = kim.get("/me").await;
    let lee_me: Me = lee.get("/me").await;
    let files = |user: &str| -> Vec<std::path::PathBuf> {
        fn walk(p: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
                if e.path().is_dir() {
                    walk(&e.path(), out)
                } else {
                    out.push(e.path())
                }
            }
        }
        let mut v = vec![];
        walk(&mount.join(user), &mut v);
        v
    };
    // Each user gets their own folder in the shared mount, named by a key only they hold, so the
    // mount shows neither user ids nor how many folders belong to whom.
    let owners: Vec<String> = std::fs::read_dir(&mount)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(owners.len(), 2, "{owners:?}");
    for id in [&kim_me.id, &lee_me.id] {
        assert!(!owners.contains(id), "{owners:?}");
    }
    for owner in &owners {
        let f = files(owner);
        assert!(
            f.iter().any(|p| p.extension().is_some_and(|e| e == "eml")),
            "{f:?}"
        );
    }
    assert!(
        !mount.join("family").exists(),
        "nothing written to the shared path itself"
    );
}

/// Found by the lifecycle fuzzer: the IMAP parser returned quoted folder names still escaped, so a
/// folder with `"` or `\` in its name could never be selected and its mail was never backed up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_folder_names_are_backed_up() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("folders")).await;
    let _: DestinationView = api
        .post("/destinations", &fs_dest("local", "backups"))
        .await;
    let imap_user = uniq("foldersm");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    let names = [
        "quote\"inside",
        "back\\slash",
        "both\\\"mixed",
        "amp&-ersand",
        ".git‥&AOk-．．\"",
        "cafe\u{301} vs café",
        "\u{202E}gpj.exe",
    ];
    let mut stored = 0;
    for (i, n) in names.iter().enumerate() {
        let enc = malo_core::layout::encode_utf7(n);
        if c.session.create(&enc).await.is_ok() {
            append(
                &mut c,
                &enc,
                None,
                None,
                &mail(&format!("hostile folder {i}"), 0),
            )
            .await;
            stored += 1;
        }
    }
    c.logout().await;
    assert!(stored >= 5, "the test server refused most names");
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
    let list: MessageList = api
        .get("/messages?q=hostile%20folder&state=verified&limit=50")
        .await;
    assert_eq!(list.total as usize, stored, "{stats}");
    server.shutdown(std::time::Duration::from_secs(5)).await;
}

/// A folder renamed away on the server is never scanned again, so its already-downloaded
/// messages must still reach destinations added later.
#[tokio::test]
async fn messages_of_a_renamed_folder_reach_new_destinations() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("renamed")).await;
    let _: DestinationView = api.post("/destinations", &fs_dest("one", "one")).await;
    let imap_user = uniq("renamedm");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    c.session.create("Old").await.unwrap();
    append(&mut c, "Old", None, None, &mail("renamed folder mail", 0)).await;
    let acc: AccountView = api
        .post("/accounts", &imap_input("acc", &imap_user, IMAP_PORT))
        .await;
    let backup = || {
        api.run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
    };
    let _: serde_json::Value = job_result(&backup().await);
    c.session.rename("Old", "New").await.unwrap();
    c.logout().await;
    let _: DestinationView = api.post("/destinations", &fs_dest("two", "two")).await;
    // The first request may join an automatic backup that started before the rename.
    let _: serde_json::Value = job_result(&backup().await);
    let stats: serde_json::Value = job_result(&backup().await);
    assert_eq!(stats["errors"], serde_json::json!([]), "{stats}");
    let all: MessageList = api.get("/messages?q=renamed%20folder&limit=50").await;
    let verified: MessageList = api
        .get("/messages?q=renamed%20folder&state=verified&limit=50")
        .await;
    assert!(all.total >= 1);
    assert_eq!(
        verified.total,
        all.total,
        "{stats} {:?}",
        all.messages
            .iter()
            .map(|m| (m.state, m.stored, m.destinations, &m.mailboxes, &m.error))
            .collect::<Vec<_>>()
    );
    server.shutdown(std::time::Duration::from_secs(5)).await;
}

/// IDLE watchers hold one connection each for minutes; they must not use up the per-host
/// connection limit that backups and checks wait for.
#[tokio::test]
async fn idle_watchers_do_not_starve_backups() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let api = new_user(&admin, &uniq("idlers")).await;
    let _: DestinationView = api.post("/destinations", &fs_dest("local", "b")).await;
    // More watched accounts on one host than the host allows simultaneous connections.
    for i in 0..10 {
        let mut input = imap_input(&format!("watched {i}"), &uniq("idlem"), IMAP_PORT);
        input.idle = true;
        let _: AccountView = api.post("/accounts", &input).await;
    }
    let imap_user = uniq("idlework");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    append(&mut c, "INBOX", None, None, &mail("work while watched", 0)).await;
    c.logout().await;
    let acc: AccountView = api
        .post("/accounts", &imap_input("work", &imap_user, IMAP_PORT))
        .await;
    // Let every watcher connect and enter IDLE.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let job: JobInfo = api
        .post(
            "/jobs",
            &CreateJobRequest {
                kind: JobKind::Backup {
                    account_id: acc.id.clone(),
                },
            },
        )
        .await;
    let done = tokio::time::timeout(std::time::Duration::from_secs(60), api.wait_job(&job.id))
        .await
        .expect("backup starved by IDLE watchers");
    let stats: serde_json::Value = job_result(&done);
    assert_eq!(stats["errors"], serde_json::json!([]), "{stats}");
    server.shutdown(std::time::Duration::from_secs(5)).await;
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    if to.exists() {
        std::fs::remove_dir_all(to).unwrap();
    }
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

/// Stops the server, deletes the user's index (a lost or corrupted disk), starts it again.
async fn lose_index(
    server: malo_server::Running,
    data: &std::path::Path,
    user_id: &str,
) -> malo_server::Running {
    server.shutdown(Duration::from_secs(10)).await;
    for f in ["index.db", "index.db-wal", "index.db-shm"] {
        let _ = std::fs::remove_file(data.join("users").join(user_id).join(f));
    }
    start_server(data, |_| {}).await
}

async fn subjects_and_flags(api: &Api) -> HashMap<String, Vec<String>> {
    let list: MessageList = api.get("/messages?limit=100").await;
    list.messages
        .into_iter()
        .map(|m| (m.envelope.subject, m.flags))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_index_recovers_all_mail_with_newest_flags() {
    if !enabled() {
        return;
    }
    use futures::StreamExt;
    let dir = tempfile::tempdir().unwrap();
    let mut server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let name = uniq("gail");
    let password = format!("{name}-password");
    let gail = new_user(&admin, &name).await;
    let me: Me = gail.get("/me").await;
    let s3_prefix = uniq("gen");
    let _: DestinationView = gail
        .post(
            "/destinations",
            &s3_dest("rustfs", "malo-b", &s3_prefix, true),
        )
        .await;
    let _: DestinationView = gail.post("/destinations", &fs_dest("local", "b")).await;
    let fs_root = dir.path().join("users").join(&me.id).join("local/b");
    let imap_user = uniq("gen-");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    for i in 0..4 {
        append(&mut c, "INBOX", None, None, &mail(&format!("gen {i}"), 100)).await;
    }
    let acc: AccountView = gail
        .post("/accounts", &imap_input("gen", &imap_user, IMAP_PORT))
        .await;
    let backup = |api: Api, id: String| async move {
        job_result::<serde_json::Value>(&api.run_job(JobKind::Backup { account_id: id }).await)
    };
    backup(gail.clone(), acc.id.clone()).await;
    // An old copy of the local destination, from before the changes below.
    let old_fs = dir.path().join("old-fs");
    copy_tree(&fs_root, &old_fs);

    // "gen 0" is flagged and "gen 3" deleted by another client; the backups record both.
    c.select("INBOX").await.unwrap();
    let _: Vec<_> = c
        .session
        .uid_store("1", "+FLAGS (\\Flagged)")
        .await
        .unwrap()
        .collect()
        .await;
    c.delete_uids(&[4]).await.unwrap();
    c.logout().await;
    backup(gail.clone(), acc.id.clone()).await;
    let before = subjects_and_flags(&gail).await;
    assert_eq!(before.len(), 4, "{before:?}");
    assert!(
        before["gen 0"].iter().any(|f| f == "\\Flagged"),
        "{before:?}"
    );

    // 1. Index lost, local destination restored from its old copy: a rebuild from all
    //    destinations brings back every message, with the flags of the newest manifests.
    copy_tree(&old_fs, &fs_root);
    server = lose_index(server, dir.path(), &me.id).await;
    let gail = Api::new(&server).login(&name, &password).await;
    let job = gail.run_job(JobKind::RebuildIndexAll).await;
    let stats: serde_json::Value = job_result(&job);
    let gens: Vec<u64> = stats["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["generation"].as_u64().unwrap())
        .collect();
    assert_eq!(gens.len(), 2, "{stats}");
    assert_ne!(
        gens[0], gens[1],
        "the stale copy must have an older generation: {stats}"
    );
    let after = subjects_and_flags(&gail).await;
    assert_eq!(after.len(), 4, "{after:?}");
    assert!(after["gen 0"].iter().any(|f| f == "\\Flagged"), "{after:?}");

    // 2. Index lost again, and a backup runs before anyone rebuilds: it must not replace the
    //    manifests with what is left on the server ("gen 3" is gone from there).
    copy_tree(&old_fs, &fs_root);
    server = lose_index(server, dir.path(), &me.id).await;
    let gail = Api::new(&server).login(&name, &password).await;
    let stats = backup(gail.clone(), acc.id.clone()).await;
    assert_eq!(stats["errors"], serde_json::json!([]), "{stats}");
    let after = subjects_and_flags(&gail).await;
    assert_eq!(
        after.len(),
        4,
        "the backup absorbed the manifests first: {after:?}"
    );
    server = lose_index(server, dir.path(), &me.id).await;
    let gail = Api::new(&server).login(&name, &password).await;
    job_result::<serde_json::Value>(&gail.run_job(JobKind::RebuildIndexAll).await);
    let after = subjects_and_flags(&gail).await;
    assert_eq!(after.len(), 4, "no manifest lost a message: {after:?}");
    assert!(after["gen 0"].iter().any(|f| f == "\\Flagged"), "{after:?}");

    // 3. Markers gone (an interrupted write), manifests still there, index lost, then a backup:
    //    a destination this index never wrote to is imported first, marker or not.
    let op = s3_operator("malo-b");
    let mut lister = op
        .lister_with(&format!("{s3_prefix}/"))
        .recursive(true)
        .await
        .unwrap();
    while let Some(e) = futures::TryStreamExt::try_next(&mut lister).await.unwrap() {
        if e.path().ends_with("/account.json.enc") {
            op.delete(e.path()).await.unwrap();
        }
    }
    fn remove_markers(dir: &std::path::Path) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                remove_markers(&p);
            } else if p.file_name().is_some_and(|n| n == "account.json") {
                std::fs::remove_file(p).unwrap();
            }
        }
    }
    remove_markers(&fs_root);
    server = lose_index(server, dir.path(), &me.id).await;
    let gail = Api::new(&server).login(&name, &password).await;
    let stats = backup(gail.clone(), acc.id.clone()).await;
    assert_eq!(stats["errors"], serde_json::json!([]), "{stats}");
    server = lose_index(server, dir.path(), &me.id).await;
    let gail = Api::new(&server).login(&name, &password).await;
    job_result::<serde_json::Value>(&gail.run_job(JobKind::RebuildIndexAll).await);
    let after = subjects_and_flags(&gail).await;
    assert_eq!(after.len(), 4, "markers lost, mail kept: {after:?}");
    server.shutdown(Duration::from_secs(5)).await;
}

async fn other_name(api: &Api) -> String {
    let me: Me = api.get("/me").await;
    me.username
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_invites_limits_and_deletion() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let anon = Api {
        token: None,
        ..admin.clone()
    };
    // The setup token works once.
    let again = anon
        .call::<_, serde_json::Value>(
            Method::POST,
            "/setup",
            Some(&SetupRequest {
                setup_token: server.setup_token.clone().unwrap(),
                username: "second-admin".into(),
                password: "second-password-1".into(),
                recovery_kit: None,
                kit_passphrase: None,
            }),
        )
        .await;
    assert!(again.is_err());

    // Invites are listed without their codes and can be revoked before use.
    let invite: Invite = admin
        .post(
            "/admin/invites",
            &CreateInviteRequest {
                username: Some("nobody".into()),
                role: Role::User,
                valid_hours: 1,
            },
        )
        .await;
    let list: Vec<InviteInfo> = admin.get("/admin/invites").await;
    let open = list
        .iter()
        .find(|i| i.username.as_deref() == Some("nobody"))
        .expect("listed");
    assert!(!open.used);
    assert!(!serde_json::to_string(&list).unwrap().contains(&invite.code));
    assert_eq!(
        admin
            .status_of(Method::DELETE, &format!("/admin/invites/{}", open.id))
            .await,
        204
    );
    let revoked = anon
        .call::<_, serde_json::Value>(
            Method::POST,
            "/auth/register",
            Some(&RegisterRequest {
                username: "nobody".into(),
                password: "nobody-password".into(),
                invite_code: Some(invite.code.clone()),
                recovery_kit: None,
                kit_passphrase: None,
            }),
        )
        .await;
    assert!(revoked.is_err(), "a revoked invite can't be redeemed");

    // Partial updates change only what is sent; an explicit default clears the limit.
    let name = uniq("jo");
    let jo = new_user(&admin, &name).await;
    let me: Me = jo.get("/me").await;
    let user = |users: Vec<UserInfo>| users.into_iter().find(|u| u.id == me.id).unwrap();
    let _: serde_json::Value = admin
        .put(
            &format!("/admin/users/{}", me.id),
            &UpdateUserRequest {
                max_accounts: Some(0),
                ..Default::default()
            },
        )
        .await;
    let u = user(admin.get("/admin/users").await);
    assert_eq!(
        (u.max_accounts, u.disabled, u.role),
        (Some(0), false, Role::User)
    );
    let over = jo
        .call::<_, AccountView>(
            Method::POST,
            "/accounts",
            Some(&imap_input("x", &uniq("jom"), IMAP_PORT)),
        )
        .await;
    assert!(over.is_err(), "account limit enforced");
    let _: serde_json::Value = admin
        .put(
            &format!("/admin/users/{}", me.id),
            &UpdateUserRequest {
                max_accounts_default: Some(true),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(user(admin.get("/admin/users").await).max_accounts, None);

    // Deleting a user whose local folder holds backups needs a second, explicit confirmation.
    let _: DestinationView = jo.post("/destinations", &fs_dest("local", "d")).await;
    let imap_user = uniq("jom");
    seed_standard(&imap_user).await;
    let acc: AccountView = jo
        .post("/accounts", &imap_input("jo", &imap_user, IMAP_PORT))
        .await;
    job_result::<serde_json::Value>(
        &jo.run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
        .await,
    );
    let refused = admin
        .call::<_, serde_json::Value>(
            Method::DELETE,
            &format!("/admin/users/{}", me.id),
            None::<&()>,
        )
        .await;
    let (status, body) = refused.unwrap_err();
    assert_eq!(status, 409);
    assert!(body.contains("local_backups"), "{body}");
    assert!(dir.path().join("users").join(&me.id).exists());
    assert_eq!(
        admin
            .status_of(
                Method::DELETE,
                &format!("/admin/users/{}?delete_local_backups=true", me.id)
            )
            .await,
        204
    );
    assert!(!dir.path().join("users").join(&me.id).exists());

    // Everything above is in the admin log.
    let log: Vec<AdminAuditEntry> = admin.get("/admin/audit").await;
    let actions: Vec<&str> = log.iter().map(|e| e.action.as_str()).collect();
    for a in [
        "setup",
        "invite_created",
        "invite_revoked",
        "user_updated",
        "user_deleted",
    ] {
        assert!(actions.contains(&a), "{a} missing from {actions:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_selected_messages() {
    if !enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let kai = new_user(&admin, &uniq("kai")).await;
    let me: Me = kai.get("/me").await;
    let plain: DestinationView = kai.post("/destinations", &fs_dest("plain", "p")).await;
    let sealed: DestinationView = kai
        .post(
            "/destinations",
            &DestinationInput {
                encrypt: true,
                ..fs_dest("sealed", "s")
            },
        )
        .await;
    let imap_user = uniq("del-");
    let mut c = imap_conn(&imap_user, IMAP_PORT).await;
    for subject in ["keep", "server only", "everywhere", "backup only"] {
        append(&mut c, "INBOX", None, None, &mail(subject, 0)).await;
    }
    c.logout().await;
    let acc: AccountView = kai
        .post("/accounts", &imap_input("del", &imap_user, IMAP_PORT))
        .await;
    let backup = || {
        kai.run_job(JobKind::Backup {
            account_id: acc.id.clone(),
        })
    };
    job_result::<serde_json::Value>(&backup().await);
    let local = dir.path().join("users").join(&me.id).join("local");
    let files = |ext: &str| {
        fn walk(p: &std::path::Path, ext: &str, n: &mut usize) {
            for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
                if e.path().is_dir() {
                    walk(&e.path(), ext, n);
                } else if e.path().to_string_lossy().ends_with(ext) {
                    *n += 1;
                }
            }
        }
        let mut n = 0;
        walk(&local, ext, &mut n);
        n
    };
    let (eml, enc) = (files(".eml"), files(".enc"));
    let list: MessageList = kai.get("/messages?limit=100").await;
    let id = |subject: &str| {
        list.messages
            .iter()
            .find(|m| m.envelope.subject == subject)
            .unwrap()
            .id
    };
    let delete = |ids: Vec<i64>, scope: DeleteScope| {
        kai.run_job(JobKind::DeleteMessages {
            account_id: acc.id.clone(),
            message_ids: ids,
            scope,
        })
    };

    // From the server: the backup stays.
    let s: DeleteSummary = job_result(
        &delete(
            vec![id("server only"), id("backup only")],
            DeleteScope::Server,
        )
        .await,
    );
    assert_eq!(
        (s.deleted_from_server, s.deleted_from_backup),
        (2, 0),
        "{s:?}"
    );
    let on_server = server_messages(&imap_user, IMAP_PORT).await;
    assert_eq!(on_server.len(), 2);
    let list2: MessageList = kai.get("/messages?limit=100").await;
    assert_eq!(list2.total, 4);
    assert!(list2
        .messages
        .iter()
        .any(|m| m.envelope.subject == "server only" && m.deleted_on_server));

    // From the backup: one already gone from the server, one deleted there first.
    let s: DeleteSummary = job_result(
        &delete(
            vec![id("everywhere"), id("backup only")],
            DeleteScope::Everywhere,
        )
        .await,
    );
    assert_eq!(
        (s.deleted_from_server, s.deleted_from_backup),
        (1, 2),
        "{s:?}"
    );
    assert!(s.errors.is_empty(), "{s:?}");
    let on_server = server_messages(&imap_user, IMAP_PORT).await;
    assert_eq!(
        on_server.keys().collect::<HashSet<_>>(),
        HashSet::from([&"keep".to_string()])
    );
    let list3: MessageList = kai.get("/messages?limit=100").await;
    let left: HashSet<_> = list3
        .messages
        .iter()
        .map(|m| m.envelope.subject.clone())
        .collect();
    assert_eq!(left, HashSet::from(["keep".into(), "server only".into()]));
    // The stored copies are gone from both destinations.
    assert_eq!((files(".eml"), files(".enc")), (eml - 2, enc - 2));

    // Neither the next backup nor a rebuild from the rewritten manifests brings them back.
    job_result::<serde_json::Value>(&backup().await);
    for d in [&plain, &sealed] {
        job_result::<serde_json::Value>(
            &kai.run_job(JobKind::RebuildIndex {
                destination_id: d.id.clone(),
            })
            .await,
        );
    }
    let list4: MessageList = kai.get("/messages?limit=100").await;
    assert_eq!(list4.total, 2);

    // A check finds the destinations consistent.
    let report: CheckReport = job_result(
        &kai.run_job(JobKind::Check {
            scope: CheckScope::All,
            deep: true,
        })
        .await,
    );
    assert!(report.ok, "{report:?}");

    // Too many messages in one job are refused.
    let big = kai
        .call::<_, JobInfo>(
            Method::POST,
            "/jobs",
            Some(&CreateJobRequest {
                kind: JobKind::DeleteMessages {
                    account_id: acc.id.clone(),
                    message_ids: (0..=MAX_DELETE_BATCH as i64).collect(),
                    scope: DeleteScope::Everywhere,
                },
            }),
        )
        .await;
    assert_eq!(big.unwrap_err().0, 400);
}

/// A kit file whose key derivation costs as much as a real one (256 MiB).
fn costly_kit(kdf: malo_core::crypto::KdfParams) -> RecoveryKitFile {
    RecoveryKitFile::Sealed(SealedRecoveryKit {
        format: SEALED_KIT_FORMAT.into(),
        kdf: KitKdf {
            algorithm: "argon2id".into(),
            m_kib: kdf.m_kib,
            t: kdf.t,
            p: kdf.p,
        },
        salt: "00".repeat(16),
        data: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    })
}

/// Needs no Docker. Registration checks who may register before it derives any key from an
/// uploaded kit, and kits can't ask for more work than Malo's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_checks_before_key_derivation() {
    enabled();
    let dir = tempfile::tempdir().unwrap();
    let server = start_server(dir.path(), |_| {}).await;
    let admin = bootstrap(&server).await;
    let anon = Api {
        token: None,
        ..admin.clone()
    };
    let register = |invite: Option<String>, kit: RecoveryKitFile| RegisterRequest {
        username: uniq("kit"),
        password: "kit-user-password".into(),
        invite_code: invite,
        recovery_kit: Some(kit),
        kit_passphrase: Some("some kit passphrase".into()),
    };
    let default = malo_core::crypto::KdfParams::DEFAULT;
    for invite in [None, Some("not-an-invite".to_string())] {
        let started = std::time::Instant::now();
        let res = anon
            .call::<_, serde_json::Value>(
                Method::POST,
                "/auth/register",
                Some(&register(invite, costly_kit(default))),
            )
            .await;
        assert_eq!(res.unwrap_err().0, 403);
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "refused without deriving the kit's key"
        );
    }
    // Taken names aren't told to clients that may not register.
    let res = anon
        .call::<_, serde_json::Value>(
            Method::POST,
            "/auth/register",
            Some(&RegisterRequest {
                username: other_name(&admin).await,
                ..register(None, costly_kit(default))
            }),
        )
        .await;
    assert_eq!(res.unwrap_err().0, 403);

    let invite: Invite = admin
        .post(
            "/admin/invites",
            &CreateInviteRequest {
                username: None,
                role: Role::User,
                valid_hours: 1,
            },
        )
        .await;
    for over in [
        malo_core::crypto::KdfParams {
            m_kib: 1024 * 1024,
            ..default
        },
        malo_core::crypto::KdfParams { t: 10, ..default },
        malo_core::crypto::KdfParams { p: 4, ..default },
    ] {
        let started = std::time::Instant::now();
        let res = anon
            .call::<_, serde_json::Value>(
                Method::POST,
                "/auth/register",
                Some(&register(Some(invite.code.clone()), costly_kit(over))),
            )
            .await;
        assert_eq!(res.unwrap_err().0, 400);
        assert!(started.elapsed() < Duration::from_millis(1500));
    }
    // The invite wasn't used up by the failed attempts.
    let invites: Vec<InviteInfo> = admin.get("/admin/invites").await;
    assert!(invites.iter().all(|i| !i.used));
}
