//! Retention purge: permanent deletion from the IMAP server of messages verified in every required destination.

use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, bail, Context};
use chrono::{DateTime, Duration, Utc};
use malo_api::{
    DeleteScope, DeleteSummary, PurgeMailboxCount, PurgePolicy, PurgePreview, PurgeSummary,
    SyncEvent,
};

use crate::config::Account;
use crate::ctx::JobCtx;
use crate::imap::{self, ImapConn};
use crate::index::{MailboxRow, MembershipRow, MessageRow, ReplicaRow, ReplicaStatus};
use crate::store::{Store, Verify};
use crate::sync;

/// Everything the selection rule needs about one message.
#[derive(Debug, Clone)]
pub struct CandidateInput {
    pub message: MessageRow,
    pub memberships: Vec<(MembershipRow, MailboxRow)>,
    pub replicas: Vec<ReplicaRow>,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub message: MessageRow,
    /// Memberships still on the server and not excluded.
    pub memberships: Vec<(MembershipRow, MailboxRow)>,
}

/// Why purging is impossible right now, independent of individual messages.
pub fn blocked_reason(
    policy: &PurgePolicy,
    failing: &HashMap<String, String>,
    known_destinations: &[String],
) -> Option<String> {
    if policy.required_destinations.is_empty() {
        return Some("no required destination selected".into());
    }
    for d in &policy.required_destinations {
        if !known_destinations.contains(d) {
            return Some(format!("required destination {d} no longer exists"));
        }
        if let Some(reason) = failing.get(d) {
            return Some(format!(
                "integrity check failing on a required destination: {reason}"
            ));
        }
    }
    None
}

/// Retention rule: older than N days (0 = all), verified in every required destination,
/// not in an excluded mailbox, not flagged (if excluded), still on the server.
pub fn select_candidates(
    now: DateTime<Utc>,
    policy: &PurgePolicy,
    inputs: Vec<CandidateInput>,
) -> Vec<Candidate> {
    let cutoff = now - Duration::days(policy.older_than_days as i64);
    inputs
        .into_iter()
        .filter_map(|c| {
            if policy.required_destinations.is_empty() {
                return None;
            }
            let date = c.message.internaldate.or(c.message.envelope.date)?;
            if policy.older_than_days > 0 && date >= cutoff {
                return None;
            }
            let sha = c.message.sha256.as_ref()?;
            let all_verified = policy.required_destinations.iter().all(|d| {
                c.replicas.iter().any(|r| {
                    &r.destination == d
                        && r.status == ReplicaStatus::Verified
                        && r.sha256.as_ref() == Some(sha)
                })
            });
            if !all_verified {
                return None;
            }
            let live: Vec<_> = c
                .memberships
                .iter()
                .filter(|(m, mb)| !m.deleted_on_server && mb.current)
                .cloned()
                .collect();
            if live.is_empty() {
                return None;
            }
            // A message in any excluded mailbox (or flagged anywhere) is kept entirely.
            if live.iter().any(|(_, mb)| {
                policy
                    .exclude_mailboxes
                    .iter()
                    .any(|x| x == &mb.name || x == &mb.display)
            }) {
                return None;
            }
            if policy.exclude_flagged
                && live
                    .iter()
                    .any(|(m, _)| m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged")))
            {
                return None;
            }
            Some(Candidate {
                message: c.message,
                memberships: live,
            })
        })
        .collect()
}

fn gather(ctx: &JobCtx, account: &Account) -> anyhow::Result<Vec<CandidateInput>> {
    let mut boxes: HashMap<i64, MailboxRow> = HashMap::new();
    for mb in ctx.index.mailboxes(Some(&account.id), false)? {
        boxes.insert(mb.id, mb);
    }
    let ids: Vec<i64> = ctx.index.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id FROM messages WHERE account=?1 AND state IN ('verified','stored')",
        )?;
        let rows = stmt.query_map([&account.id], |r| r.get(0))?.collect();
        rows
    })?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(message) = ctx.index.message(id)? else {
            continue;
        };
        let memberships = ctx
            .index
            .memberships(id)?
            .into_iter()
            .filter_map(|m| boxes.get(&m.mailbox).cloned().map(|mb| (m, mb)))
            .collect();
        out.push(CandidateInput {
            message,
            memberships,
            replicas: ctx.index.replicas_of(id)?,
        });
    }
    Ok(out)
}

fn failing_destinations(
    ctx: &JobCtx,
    policy: &PurgePolicy,
) -> anyhow::Result<HashMap<String, String>> {
    let mut m = HashMap::new();
    for d in &policy.required_destinations {
        if let Some(r) = ctx.index.destination_failing(d)? {
            m.insert(d.clone(), r);
        }
    }
    Ok(m)
}

pub fn candidates(
    ctx: &JobCtx,
    account: &Account,
) -> anyhow::Result<(Vec<Candidate>, Option<String>)> {
    let failing = failing_destinations(ctx, &account.policy)?;
    let blocked = blocked_reason(&account.policy, &failing, &ctx.destination_ids());
    let list = select_candidates(Utc::now(), &account.policy, gather(ctx, account)?);
    Ok((list, blocked))
}

/// Dry run: counts and sizes per mailbox. Connects to check UIDPLUS.
pub async fn preview(ctx: &JobCtx, account_id: &str) -> anyhow::Result<PurgePreview> {
    let account = ctx.account(account_id)?.clone();
    let (list, mut blocked) = candidates(ctx, &account)?;
    let mut warnings = Vec::new();
    if account.policy.required_destinations.len() < 2 {
        warnings.push(
            "Only one required destination: a single storage failure could lose purged mail."
                .into(),
        );
    }
    match imap::connect(&account, ctx.tokens.as_ref()).await {
        Ok(conn) => {
            if !conn.caps.uidplus() {
                blocked.get_or_insert_with(|| {
                    "server lacks UIDPLUS (safe UID EXPUNGE impossible)".into()
                });
            }
            conn.logout().await;
        }
        Err(e) => warnings.push(format!(
            "could not connect to verify server capabilities: {e:#}"
        )),
    }
    let mut per: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for c in &list {
        for (_, mb) in &c.memberships {
            let e = per.entry(mb.display.clone()).or_default();
            e.0 += 1;
            e.1 += c.message.size;
        }
    }
    Ok(PurgePreview {
        account_id: account.id.clone(),
        total_count: list.len() as u64,
        total_bytes: list.iter().map(|c| c.message.size).sum(),
        mailboxes: per
            .into_iter()
            .map(|(mailbox, (count, bytes))| PurgeMailboxCount {
                mailbox,
                count,
                bytes,
            })
            .collect(),
        blocked_reason: blocked,
        warnings,
    })
}

/// Executes a purge for an armed policy.
pub async fn run_purge(ctx: &JobCtx, account_id: &str) -> anyhow::Result<PurgeSummary> {
    let account = ctx.account(account_id)?.clone();
    if !account.policy.armed {
        bail!("purge policy is not armed");
    }
    let (list, blocked) = candidates(ctx, &account)?;
    if let Some(b) = blocked {
        bail!("purge blocked: {b}");
    }
    let rules = Rules {
        required: account.policy.required_destinations.clone(),
        exclude_flagged: account.policy.exclude_flagged,
        audit: "purge_run",
    };
    let summary = delete_on_server(ctx, &account, list, &rules).await?;
    ctx.events.emit(SyncEvent::PurgeSummary {
        summary: summary.clone(),
    });
    Ok(summary)
}

/// How [`delete_on_server`] treats its candidates.
struct Rules {
    /// Destinations every candidate is re-verified on (and whose manifests are rewritten) before
    /// anything is deleted. Empty when the backup is deleted too.
    required: Vec<String>,
    /// Keep messages flagged on the server.
    exclude_flagged: bool,
    /// Audit log entry for the run.
    audit: &'static str,
}

/// Deletes candidates from the IMAP server: re-verifies their backups on the required
/// destinations, writes the manifests there, then deletes each UID only after re-confirming it is
/// still exactly the backed-up message. An error after the server was touched still returns the
/// partial summary in the audit log.
async fn delete_on_server(
    ctx: &JobCtx,
    account: &Account,
    list: Vec<Candidate>,
    rules: &Rules,
) -> anyhow::Result<PurgeSummary> {
    let mut summary = PurgeSummary {
        account_id: account.id.clone(),
        deleted: 0,
        bytes: 0,
        skipped: 0,
        errors: vec![],
    };
    if list.is_empty() {
        return Ok(summary);
    }

    // Pre-purge re-verify (stat + hash) in every required destination.
    let stores: HashMap<String, Store> = rules
        .required
        .iter()
        .map(|d| ctx.store(d).map(|s| (d.clone(), s)))
        .collect::<anyhow::Result<_>>()?;
    let mut confirmed: Vec<Candidate> = Vec::new();
    for (i, c) in list.into_iter().enumerate() {
        ctx.check_cancel()?;
        ctx.progress(i as u64, 0, "re-verifying backups");
        let sha = c.message.sha256.clone().unwrap_or_default();
        let mut ok = true;
        for (dest, store) in &stores {
            let rep = ctx
                .index
                .replicas_of(c.message.id)?
                .into_iter()
                .find(|r| &r.destination == dest);
            let Some(rep) = rep else {
                ok = false;
                break;
            };
            match store
                .verify(
                    &rep.object_path,
                    rep.encrypted,
                    &sha,
                    c.message.size,
                    (rep.stored_size > 0).then_some(rep.stored_size),
                    true,
                )
                .await
            {
                Ok(Verify::Ok) => {}
                Ok(v) => {
                    let st = if v == Verify::Missing {
                        ReplicaStatus::Missing
                    } else {
                        ReplicaStatus::Corrupt
                    };
                    ctx.index.set_replica_status(c.message.id, dest, st, true)?;
                    ctx.index.set_destination_status(
                        dest,
                        true,
                        Some("pre-purge verification failed"),
                    )?;
                    summary.errors.push(format!(
                        "message {}: replica on {} failed re-verification",
                        c.message.id, store.dest.name
                    ));
                    ok = false;
                    break;
                }
                Err(e) => {
                    summary
                        .errors
                        .push(format!("message {}: {e:#}", c.message.id));
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            confirmed.push(c);
        } else {
            summary.skipped += 1;
        }
    }
    if !summary.errors.is_empty() {
        // Something in a required destination is wrong: stop before touching the server.
        ctx.index.audit(
            "purge_aborted",
            Some(&account.id),
            &serde_json::json!({"errors": summary.errors}),
        )?;
        bail!(
            "purge aborted: {} replica(s) failed re-verification",
            summary.skipped
        );
    }

    // The manifests on every required destination must list what is about to leave the server:
    // they are what a rebuild (after a lost index or a removed account) recovers mail from.
    if !confirmed.is_empty() {
        let mut mailboxes: Vec<i64> = confirmed
            .iter()
            .flat_map(|c| c.memberships.iter().map(|(_, mb)| mb.id))
            .collect();
        mailboxes.sort_unstable();
        mailboxes.dedup();
        for store in stores.values() {
            ctx.check_cancel()?;
            sync::write_manifests(ctx, account, store, &mailboxes)
                .await
                .with_context(|| {
                    format!(
                        "purge aborted: manifest on {} could not be written",
                        store.dest.name
                    )
                })?;
        }
    }

    if confirmed.is_empty() {
        return Ok(summary);
    }
    let mut conn = imap::connect(account, ctx.tokens.as_ref()).await?;
    if !conn.caps.uidplus() {
        conn.logout().await;
        bail!("server lacks UIDPLUS; refusing to delete");
    }
    let flagged = rules.exclude_flagged;
    let result = if conn.caps.gmail() {
        purge_gmail(ctx, account, &mut conn, &confirmed, flagged, &mut summary).await
    } else {
        purge_generic(ctx, account, &mut conn, &confirmed, flagged, &mut summary).await
    };
    conn.logout().await;
    ctx.index.audit(
        rules.audit,
        Some(&account.id),
        &serde_json::json!({"deleted": summary.deleted, "bytes": summary.bytes, "skipped": summary.skipped, "errors": summary.errors}),
    )?;
    result.map(|_| summary)
}

/// Deletes messages the user selected, from the mail server (`DeleteScope::Server`) or from the
/// backup too (`DeleteScope::Everywhere`).
///
/// Server: like a purge without the age, mailbox and flag rules, since the user picked each
/// message: every one must be verified on the policy's required destinations (or on every
/// destination when none are set), and is re-verified there first.
///
/// Everywhere: messages still on the server are deleted there first (identity-checked, but
/// without the backup checks, since the backup goes as well); a message that stays on the server
/// is kept, or the next backup would bring it back. Then the messages leave the index (with
/// tombstones), the manifests on every destination are rewritten without them, and their stored
/// objects are deleted. A destination that can't be reached keeps its manifest marked dirty and
/// its objects queued, both finished by a later manifest write there.
pub async fn delete_selected(
    ctx: &JobCtx,
    account_id: &str,
    ids: &[i64],
    scope: DeleteScope,
) -> anyhow::Result<DeleteSummary> {
    let account = ctx.account(account_id)?.clone();
    if account.imported && scope == DeleteScope::Server {
        bail!("this imported account has no mail server to delete from");
    }
    let mut summary = DeleteSummary {
        account_id: account.id.clone(),
        ..Default::default()
    };
    let mut inputs = Vec::new();
    for id in ids {
        match ctx.index.message(*id)? {
            Some(message) if message.account == account.id => {
                let memberships = ctx
                    .index
                    .memberships(*id)?
                    .into_iter()
                    .filter_map(|m| Some((m.clone(), ctx.index.mailbox(m.mailbox).ok()??)))
                    .collect();
                inputs.push(CandidateInput {
                    replicas: ctx.index.replicas_of(*id)?,
                    message,
                    memberships,
                });
            }
            // Gone meanwhile, or another account's: nothing to do.
            _ => summary.skipped += 1,
        }
    }
    let live = |c: &CandidateInput| {
        c.memberships
            .iter()
            .any(|(m, mb)| !m.deleted_on_server && mb.current)
    };

    // 1. The mail server.
    let on_server: Vec<&CandidateInput> = inputs.iter().filter(|c| live(c)).collect();
    if !on_server.is_empty() && !account.imported {
        let rules = match scope {
            DeleteScope::Server => {
                let mut policy = account.policy.clone();
                if policy.required_destinations.is_empty() {
                    policy.required_destinations = ctx.destination_ids();
                }
                let failing = failing_destinations(ctx, &policy)?;
                if let Some(b) = blocked_reason(&policy, &failing, &ctx.destination_ids()) {
                    bail!("can't delete from the server: {b}");
                }
                Rules {
                    required: policy.required_destinations,
                    exclude_flagged: false,
                    audit: "deleted_on_server",
                }
            }
            DeleteScope::Everywhere => Rules {
                required: vec![],
                exclude_flagged: false,
                audit: "deleted_on_server",
            },
        };
        let backed_up = |c: &CandidateInput| {
            let Some(sha) = c.message.sha256.as_ref() else {
                return false;
            };
            rules.required.iter().all(|d| {
                c.replicas.iter().any(|r| {
                    &r.destination == d
                        && r.status == ReplicaStatus::Verified
                        && r.sha256.as_ref() == Some(sha)
                })
            })
        };
        let mut list = Vec::new();
        for c in on_server {
            if backed_up(c) {
                list.push(Candidate {
                    message: c.message.clone(),
                    memberships: c
                        .memberships
                        .iter()
                        .filter(|(m, mb)| !m.deleted_on_server && mb.current)
                        .cloned()
                        .collect(),
                });
            } else {
                summary.skipped += 1;
                summary.errors.push(format!(
                    "{}: not yet verified on every required destination; kept on the server",
                    subject_of(&c.message)
                ));
            }
        }
        let r = delete_on_server(ctx, &account, list, &rules).await?;
        summary.deleted_from_server = r.deleted;
        summary.skipped += r.skipped;
        summary.errors.extend(r.errors);
    }
    if scope == DeleteScope::Server {
        return Ok(summary);
    }

    // 2. The backup: only what is no longer on the server. What stayed there was counted as
    // skipped above.
    let mut gone = Vec::new();
    for c in &inputs {
        let still = ctx.index.memberships(c.message.id)?.into_iter().any(|m| {
            !m.deleted_on_server
                && c.memberships
                    .iter()
                    .any(|(_, mb)| mb.id == m.mailbox && mb.current)
        });
        if !still || account.imported {
            gone.push(c);
        }
    }
    if gone.is_empty() {
        return Ok(summary);
    }
    let mut mailboxes: Vec<i64> = gone
        .iter()
        .flat_map(|c| c.memberships.iter().map(|(_, mb)| mb.id))
        .collect();
    mailboxes.sort_unstable();
    mailboxes.dedup();
    let ids: Vec<i64> = gone.iter().map(|c| c.message.id).collect();
    for c in &gone {
        ctx.index.audit(
            "deleted_from_backup",
            Some(&account.id),
            &serde_json::json!({"message": c.message.id, "sha256": c.message.sha256, "size": c.message.size}),
        )?;
    }
    let unused = ctx.index.forget_messages(&ids)?;
    for id in &ids {
        ctx.spool_remove(*id);
    }
    summary.deleted_from_backup = ids.len() as u64;
    ctx.events.emit(SyncEvent::MessagesDeleted {
        account_id: account.id.clone(),
        ids: ids.clone(),
    });
    for dest in ctx.destination_ids() {
        let objects: Vec<String> = unused
            .iter()
            .filter(|(d, _)| *d == dest)
            .map(|(_, p)| p.clone())
            .collect();
        sync::queue_object_deletes(ctx, &dest, &objects)?;
        let result = async {
            let store = ctx.store(&dest)?;
            sync::write_manifests(ctx, &account, &store, &mailboxes).await?;
            sync::flush_object_deletes(ctx, &store).await
        }
        .await;
        if let Err(e) = result {
            let name = ctx
                .config
                .destination(&dest)
                .map_or(dest.clone(), |d| d.name.clone());
            summary.errors.push(format!(
                "{name}: {e:#} (cleaned up at the next successful backup there)"
            ));
        }
    }
    Ok(summary)
}

fn subject_of(m: &MessageRow) -> String {
    let s = m.envelope.subject.trim();
    if s.is_empty() {
        format!("message {}", m.id)
    } else {
        format!("“{s}”")
    }
}

/// Groups candidate memberships per mailbox.
type MailboxGroups<'a> = BTreeMap<i64, (MailboxRow, Vec<(u32, &'a MessageRow)>)>;

fn by_mailbox(list: &[Candidate]) -> MailboxGroups<'_> {
    let mut m: MailboxGroups = BTreeMap::new();
    for c in list {
        for (ms, mb) in &c.memberships {
            m.entry(mb.id)
                .or_insert_with(|| (mb.clone(), vec![]))
                .1
                .push((ms.uid, &c.message));
        }
    }
    m
}

/// Writes the purge record before anything is deleted: if this fails nothing is deleted, and if
/// recording the outcome fails afterwards, the history still shows what Malo removed.
fn record_pending(
    ctx: &JobCtx,
    account: &Account,
    mb: &MailboxRow,
    items: &[(u32, &MessageRow)],
) -> anyhow::Result<()> {
    for (uid, msg) in items {
        ctx.index.audit(
            "purge_pending",
            Some(&account.id),
            &serde_json::json!({
                "message": msg.id, "mailbox": mb.display, "uid": uid, "uidvalidity": mb.uidvalidity,
                "sha256": msg.sha256, "size": msg.size, "subject": msg.envelope.subject, "from": msg.envelope.from,
            }),
        )?;
    }
    Ok(())
}

fn record_deleted(
    ctx: &JobCtx,
    account: &Account,
    mb: &MailboxRow,
    deleted: &[(u32, &MessageRow)],
) -> anyhow::Result<()> {
    let uids: Vec<u32> = deleted.iter().map(|(u, _)| *u).collect();
    ctx.index.mark_deleted_on_server(mb.id, &uids, true)?;
    for (uid, msg) in deleted {
        ctx.index.audit(
            "purged",
            Some(&account.id),
            &serde_json::json!({
                "message": msg.id, "mailbox": mb.display, "uid": uid, "uidvalidity": mb.uidvalidity,
                "sha256": msg.sha256, "size": msg.size, "subject": msg.envelope.subject, "from": msg.envelope.from,
            }),
        )?;
    }
    Ok(())
}

/// Re-confirms identity (size, flags, Gmail id) of UIDs in the selected mailbox.
/// Re-confirms that each UID is still exactly the backed-up message before it is deleted: size,
/// Gmail id, received date and Message-ID must match. Without a Message-ID, the message is
/// downloaded and its SHA-256 compared with the backup. Servers can reuse UIDVALIDITY (Dovecot
/// does for a mailbox recreated within the same second), so UIDs alone are never trusted.
pub(crate) async fn confirm_identity<'a>(
    conn: &mut ImapConn,
    exclude_flagged: bool,
    items: &[(u32, &'a MessageRow)],
    summary: &mut PurgeSummary,
) -> anyhow::Result<Vec<(u32, &'a MessageRow)>> {
    let uids: Vec<u32> = items.iter().map(|(u, _)| *u).collect();
    let current = conn.identities(&uids).await?;
    let mut ok = Vec::new();
    for (uid, msg) in items {
        let Some(id) = current.get(uid) else {
            summary.skipped += 1;
            continue;
        };
        let same_size = id.size as u64 == msg.size;
        let same_gm = match (&msg.gm_msgid, id.gm_msgid) {
            (Some(a), Some(b)) => *a == b.to_string(),
            (None, _) => true,
            (Some(_), None) => false,
        };
        let same_date = match (msg.internaldate, id.internaldate) {
            (Some(a), Some(b)) => a.timestamp() == b.timestamp(),
            (None, _) => true,
            (Some(_), None) => false,
        };
        let same_message_id = match (&msg.message_id_hdr, &id.message_id) {
            (Some(a), Some(b)) => a == b,
            (Some(_), None) => false,
            (None, _) => true,
        };
        let mut same = same_size && same_gm && same_date && same_message_id;
        if same && msg.message_id_hdr.as_deref().is_none_or(str::is_empty) {
            // Nothing distinctive in the headers: compare the full content.
            same = match conn.fetch_raw(*uid).await? {
                Some((raw, _)) => {
                    msg.sha256.as_deref() == Some(crate::crypto::sha256_hex(&raw).as_str())
                }
                None => false,
            };
        }
        let flagged =
            exclude_flagged && id.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged"));
        if same && !flagged {
            ok.push((*uid, *msg));
        } else {
            summary.skipped += 1;
            if !same {
                summary.errors.push(format!("uid {uid}: not the backed-up message any more (identity changed on the server); skipped"));
            }
        }
    }
    Ok(ok)
}

async fn purge_generic(
    ctx: &JobCtx,
    account: &Account,
    conn: &mut ImapConn,
    list: &[Candidate],
    exclude_flagged: bool,
    summary: &mut PurgeSummary,
) -> anyhow::Result<()> {
    for (_, (mb, items)) in by_mailbox(list) {
        ctx.check_cancel()?;
        let sel = conn.select(&mb.name).await?;
        if sel.uidvalidity != mb.uidvalidity {
            summary.errors.push(format!(
                "{}: UIDVALIDITY changed; mailbox skipped",
                mb.display
            ));
            summary.skipped += items.len() as u64;
            continue;
        }
        let ok = confirm_identity(conn, exclude_flagged, &items, summary).await?;
        if ok.is_empty() {
            continue;
        }
        let uids: Vec<u32> = ok.iter().map(|(u, _)| *u).collect();
        record_pending(ctx, account, &mb, &ok)?;
        let expunged = conn.delete_uids(&uids).await?;
        let done: Vec<(u32, &MessageRow)> = ok
            .into_iter()
            .filter(|(u, _)| expunged.contains(u))
            .collect();
        // UID EXPUNGE responses carry sequence numbers on some servers; fall back to re-checking.
        let done = if done.len() < uids.len() {
            let still = conn.flags(&uids).await?;
            uids.iter()
                .filter(|u| !still.contains_key(u))
                .filter_map(|u| items.iter().find(|(x, _)| x == u).copied())
                .collect()
        } else {
            done
        };
        summary.deleted += done.len() as u64;
        summary.bytes += done.iter().map(|(_, m)| m.size).sum::<u64>();
        record_deleted(ctx, account, &mb, &done)?;
    }
    Ok(())
}

/// Gmail: deleting from a label only removes the label. Move from `\All` to `\Trash`, re-identify by
/// X-GM-MSGID, then `\Deleted` + `UID EXPUNGE` inside Trash, which deletes permanently.
async fn purge_gmail(
    ctx: &JobCtx,
    account: &Account,
    conn: &mut ImapConn,
    list: &[Candidate],
    exclude_flagged: bool,
    summary: &mut PurgeSummary,
) -> anyhow::Result<()> {
    let listing = conn.list_mailboxes().await?;
    let trash = listing
        .iter()
        .find(|m| m.special_use.as_deref() == Some("\\Trash"))
        .map(|m| m.name.clone())
        .ok_or_else(|| anyhow!("Gmail Trash mailbox not found"))?;
    let groups = by_mailbox(list);
    let mut to_expunge_in_trash: Vec<&MessageRow> = Vec::new();
    for (mb, items) in groups.values() {
        ctx.check_cancel()?;
        let sel = conn.select(&mb.name).await?;
        if sel.uidvalidity != mb.uidvalidity {
            summary.errors.push(format!(
                "{}: UIDVALIDITY changed; mailbox skipped",
                mb.display
            ));
            summary.skipped += items.len() as u64;
            continue;
        }
        let ok = confirm_identity(conn, exclude_flagged, items, summary).await?;
        if ok.is_empty() {
            continue;
        }
        record_pending(ctx, account, mb, &ok)?;
        if mb.name == trash {
            to_expunge_in_trash.extend(ok.iter().map(|(_, m)| *m));
        } else {
            let uids: Vec<u32> = ok.iter().map(|(u, _)| *u).collect();
            conn.uid_move(&uids, &trash).await?;
            record_deleted(ctx, account, mb, &ok)?;
            to_expunge_in_trash.extend(ok.iter().map(|(_, m)| *m));
        }
    }
    to_expunge_in_trash.sort_by_key(|m| m.id);
    to_expunge_in_trash.dedup_by_key(|m| m.id);
    if to_expunge_in_trash.is_empty() {
        return Ok(());
    }
    conn.select(&trash).await?;
    let ids: Vec<u64> = to_expunge_in_trash
        .iter()
        .filter_map(|m| m.gm_msgid.as_ref()?.parse().ok())
        .collect();
    let found = conn.uids_by_gm_msgid(&ids).await?;
    let uids: Vec<u32> = found.values().copied().collect();
    if !uids.is_empty() {
        conn.delete_uids(&uids).await?;
    }
    let remaining = conn.uids_by_gm_msgid(&ids).await?;
    let trash_row = groups
        .values()
        .find(|(mb, _)| mb.name == trash)
        .map(|(mb, _)| mb.clone());
    for m in to_expunge_in_trash {
        let gm: Option<u64> = m.gm_msgid.as_ref().and_then(|g| g.parse().ok());
        if gm.is_some_and(|g| remaining.contains_key(&g)) {
            summary
                .errors
                .push(format!("message {} still in Trash after expunge", m.id));
            continue;
        }
        summary.deleted += 1;
        summary.bytes += m.size;
        if let Some(tr) = &trash_row {
            if let Some((uid, _)) = groups[&tr.id].1.iter().find(|(_, x)| x.id == m.id) {
                record_deleted(ctx, account, tr, &[(*uid, m)])?;
            }
        }
        // Mark every membership gone: the message no longer exists in any label.
        for ms in ctx.index.memberships(m.id)? {
            ctx.index
                .mark_deleted_on_server(ms.mailbox, &[ms.uid], true)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::empty_envelope;
    use malo_api::MessageState;

    fn msg(id: i64, days_old: i64, sha: Option<&str>) -> MessageRow {
        MessageRow {
            id,
            account: "a".into(),
            state: MessageState::Verified,
            sha256: sha.map(Into::into),
            size: 100,
            internaldate: Some(Utc::now() - Duration::days(days_old)),
            message_id_hdr: None,
            gm_msgid: None,
            envelope: empty_envelope(),
            error: None,
            reviewed: false,
            first_seen_at: Utc::now(),
            attempts: 0,
            last_attempt_at: None,
        }
    }

    fn mb(id: i64, name: &str, current: bool) -> MailboxRow {
        MailboxRow {
            id,
            account: "a".into(),
            name: name.into(),
            display: name.into(),
            path: name.into(),
            delimiter: None,
            special_use: None,
            uidvalidity: 1,
            highest_uid: 0,
            highestmodseq: None,
            current,
        }
    }

    fn ms(message: i64, mailbox: i64, flags: &[&str], deleted: bool) -> MembershipRow {
        MembershipRow {
            id: message * 10 + mailbox,
            message,
            mailbox,
            uid: message as u32,
            flags: flags.iter().map(|s| s.to_string()).collect(),
            gm_labels: vec![],
            deleted_on_server: deleted,
        }
    }

    fn rep(message: i64, dest: &str, status: ReplicaStatus, sha: &str) -> ReplicaRow {
        ReplicaRow {
            message,
            destination: dest.into(),
            object_path: "p".into(),
            encrypted: true,
            stored_size: 1,
            status,
            verified_at: None,
            sha256: Some(sha.into()),
            size: 100,
        }
    }

    fn input(
        m: MessageRow,
        mss: Vec<(MembershipRow, MailboxRow)>,
        reps: Vec<ReplicaRow>,
    ) -> CandidateInput {
        CandidateInput {
            message: m,
            memberships: mss,
            replicas: reps,
        }
    }

    #[test]
    fn retention_selection() {
        let policy = PurgePolicy {
            older_than_days: 30,
            required_destinations: vec!["d1".into(), "d2".into()],
            exclude_mailboxes: vec!["Keep".into()],
            exclude_flagged: true,
            schedule_hours: 24,
            armed: true,
            armed_at: None,
        };
        let ok_reps = |id| {
            vec![
                rep(id, "d1", ReplicaStatus::Verified, "s"),
                rep(id, "d2", ReplicaStatus::Verified, "s"),
            ]
        };
        let inbox = mb(1, "INBOX", true);
        let keep = mb(2, "Keep", true);
        let stale = mb(3, "Old", false);
        let inputs = vec![
            input(
                msg(1, 60, Some("s")),
                vec![(ms(1, 1, &[], false), inbox.clone())],
                ok_reps(1),
            ), // eligible
            input(
                msg(2, 10, Some("s")),
                vec![(ms(2, 1, &[], false), inbox.clone())],
                ok_reps(2),
            ), // too new
            input(
                msg(3, 60, Some("s")),
                vec![(ms(3, 1, &[], false), inbox.clone())],
                vec![rep(3, "d1", ReplicaStatus::Verified, "s")],
            ), // missing d2
            input(
                msg(4, 60, Some("s")),
                vec![(ms(4, 1, &[], false), inbox.clone())],
                vec![
                    rep(4, "d1", ReplicaStatus::Verified, "s"),
                    rep(4, "d2", ReplicaStatus::Corrupt, "s"),
                ],
            ), // corrupt
            input(
                msg(5, 60, Some("s")),
                vec![(ms(5, 2, &[], false), keep.clone())],
                ok_reps(5),
            ), // excluded mailbox
            input(
                msg(6, 60, Some("s")),
                vec![(ms(6, 1, &["\\Flagged"], false), inbox.clone())],
                ok_reps(6),
            ), // flagged
            input(
                msg(7, 60, Some("s")),
                vec![(ms(7, 1, &[], true), inbox.clone())],
                ok_reps(7),
            ), // already gone
            input(
                msg(8, 60, Some("s")),
                vec![(ms(8, 3, &[], false), stale.clone())],
                ok_reps(8),
            ), // old uidvalidity
            input(
                msg(9, 60, None),
                vec![(ms(9, 1, &[], false), inbox.clone())],
                ok_reps(9),
            ), // never hashed
            input(
                msg(10, 60, Some("other")),
                vec![(ms(10, 1, &[], false), inbox.clone())],
                ok_reps(10),
            ), // hash mismatch
        ];
        let picked: Vec<i64> = select_candidates(Utc::now(), &policy, inputs.clone())
            .iter()
            .map(|c| c.message.id)
            .collect();
        assert_eq!(picked, vec![1]);

        // N = 0 → age doesn't matter.
        let all = PurgePolicy {
            older_than_days: 0,
            ..policy.clone()
        };
        let picked: Vec<i64> = select_candidates(Utc::now(), &all, inputs.clone())
            .iter()
            .map(|c| c.message.id)
            .collect();
        assert_eq!(picked, vec![1, 2]);

        // Flagged allowed when not excluded.
        let flagged_ok = PurgePolicy {
            exclude_flagged: false,
            ..policy.clone()
        };
        let picked: Vec<i64> = select_candidates(Utc::now(), &flagged_ok, inputs.clone())
            .iter()
            .map(|c| c.message.id)
            .collect();
        assert_eq!(picked, vec![1, 6]);

        // No required destination → nothing.
        let none = PurgePolicy {
            required_destinations: vec![],
            ..policy.clone()
        };
        assert!(select_candidates(Utc::now(), &none, inputs).is_empty());
    }

    #[test]
    fn blocked_reasons() {
        let mut policy = PurgePolicy::default();
        assert!(blocked_reason(&policy, &HashMap::new(), &[]).is_some());
        policy.required_destinations = vec!["d1".into()];
        assert!(blocked_reason(&policy, &HashMap::new(), &["d1".into()]).is_none());
        assert!(blocked_reason(&policy, &HashMap::new(), &["d2".into()]).is_some());
        let failing = HashMap::from([("d1".to_string(), "2 missing".to_string())]);
        assert!(blocked_reason(&policy, &failing, &["d1".into()])
            .unwrap()
            .contains("2 missing"));
    }
}
