//! Backup job: LIST/STATUS → discovery → download → write to every destination → read-back verify → manifests.

use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, bail};
use malo_api::{MessageState, SyncEvent};
use serde::Serialize;

use crate::config::Account;
use crate::crypto;
use crate::ctx::{is_cancelled, JobCtx};
use crate::imap::{self, ImapConn, MailboxListing};
use crate::index::{MailboxRow, MessageRow, NewMessage, ReplicaStatus};
use crate::layout;
use crate::store::{ManifestEntry, MarkerRead, Store};

#[derive(Debug, Default, Clone, Serialize)]
pub struct BackupStats {
    pub mailboxes: u64,
    pub discovered: u64,
    pub downloaded: u64,
    pub verified: u64,
    pub bytes: u64,
    pub errors: Vec<String>,
}

/// Which mailboxes to back up. Gmail exposes every message in `\All`, plus `\Junk` and `\Trash`.
pub fn backup_targets(list: &[MailboxListing], gmail: bool) -> Vec<MailboxListing> {
    let selectable = list.iter().filter(|m| m.selectable);
    if gmail {
        let picked: Vec<_> = selectable
            .clone()
            .filter(|m| {
                matches!(
                    m.special_use.as_deref(),
                    Some("\\All") | Some("\\Junk") | Some("\\Trash")
                )
            })
            .cloned()
            .collect();
        if picked
            .iter()
            .any(|m| m.special_use.as_deref() == Some("\\All"))
        {
            return picked;
        }
    }
    selectable.cloned().collect()
}

pub async fn run_backup(ctx: &JobCtx, account_id: &str) -> anyhow::Result<BackupStats> {
    let account = ctx.account(account_id)?.clone();
    let stores = ctx.stores()?;
    if stores.is_empty() {
        bail!("no destinations configured");
    }
    let run = ctx
        .index
        .start_run(&ctx.job_id, "backup", Some(account_id))?;
    let mut stats = BackupStats::default();
    let result = backup_inner(ctx, &account, &stores, run, &mut stats).await;
    let status = match &result {
        Ok(()) if stats.errors.is_empty() => "ok",
        Ok(()) => "partial",
        Err(e) if is_cancelled(e) => "cancelled",
        Err(_) => "failed",
    };
    ctx.index
        .finish_run(run, status, &serde_json::to_value(&stats)?)?;
    result.map(|_| stats)
}

async fn backup_inner(
    ctx: &JobCtx,
    account: &Account,
    stores: &[Store],
    run: i64,
    stats: &mut BackupStats,
) -> anyhow::Result<()> {
    ctx.progress(0, 0, "connecting");
    let mut conn = imap::connect(account, ctx.tokens.as_ref()).await?;
    let listing = conn.list_mailboxes().await?;
    let gmail = conn.caps.gmail();
    let targets = backup_targets(&listing, gmail);
    ctx.index.mark_mailboxes_not_current(
        &account.id,
        &targets.iter().map(|m| m.name.clone()).collect::<Vec<_>>(),
    )?;
    let dest_ids: Vec<String> = stores.iter().map(|s| s.dest.id.clone()).collect();
    let mut touched: Vec<i64> = Vec::new();
    let mut failure: Option<anyhow::Error> = None;

    for (i, target) in targets.iter().enumerate() {
        if let Err(e) = ctx.check_cancel() {
            failure = Some(e);
            break;
        }
        ctx.progress(
            i as u64,
            targets.len() as u64,
            format!("scanning {}", layout::decode_utf7(&target.name)),
        );
        match backup_mailbox(
            ctx, account, &mut conn, target, stores, &dest_ids, run, stats,
        )
        .await
        {
            Ok(mb) => {
                touched.push(mb);
                stats.mailboxes += 1;
            }
            Err(e) if is_cancelled(&e) => {
                failure = Some(e);
                break;
            }
            Err(e) => {
                let msg = format!("{}: {e:#}", layout::decode_utf7(&target.name));
                tracing::warn!(account = %account.id, "mailbox failed: {msg}");
                stats.errors.push(msg);
                // A broken connection would fail every following mailbox; reconnect once. The dead
                // connection goes first: holding its host slot while waiting for a new one could
                // deadlock jobs that all reconnect at once.
                if conn.noop().await.is_err() {
                    drop(conn);
                    conn = imap::connect(account, ctx.tokens.as_ref()).await?;
                }
            }
        }
    }
    conn.logout().await;

    // Messages no longer on the server (purged or deleted) still need copies on new destinations.
    if failure.is_none() {
        for msg in ctx.index.pending_messages(&account.id, ctx.manual)? {
            if ctx.check_cancel().is_err() {
                break;
            }
            // A folder gone from LIST (renamed or deleted elsewhere) is never scanned again.
            let mut live = false;
            for m in ctx.index.memberships(msg.id)? {
                if !m.deleted_on_server && ctx.index.mailbox(m.mailbox)?.is_some_and(|b| b.current)
                {
                    live = true;
                    break;
                }
            }
            if live || msg.sha256.is_none() {
                continue;
            }
            match replicate_offline(ctx, account, &msg, stores, &dest_ids).await {
                Ok(true) => stats.verified += 1,
                Ok(false) => {}
                Err(e) => stats.errors.push(format!("message {}: {e:#}", msg.id)),
            }
        }
    }

    // Manifests are rewritten even after a job cancel so they reflect every verified message —
    // but not once the user is locked or deleted: then nothing more may be written.
    let stores: &[Store] = if ctx.sealed.is_cancelled() {
        &[]
    } else {
        stores
    };
    for store in stores {
        if let Err(e) = write_manifests(ctx, account, store, &touched).await {
            stats
                .errors
                .push(format!("manifest on {}: {e:#}", store.dest.name));
        }
    }
    ctx.events.emit(SyncEvent::AccountsChanged);
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn backup_mailbox(
    ctx: &JobCtx,
    account: &Account,
    conn: &mut ImapConn,
    target: &MailboxListing,
    stores: &[Store],
    dest_ids: &[String],
    run: i64,
    stats: &mut BackupStats,
) -> anyhow::Result<i64> {
    let sel = conn.select(&target.name).await?;
    let display = layout::decode_utf7(&target.name);
    let path = layout::mailbox_path(&target.name, target.delimiter.as_deref());
    let mb = ctx.index.upsert_mailbox(
        &account.id,
        &target.name,
        &display,
        &path,
        target.delimiter.as_deref(),
        target.special_use.as_deref(),
        sel.uidvalidity,
    )?;

    // 1. Find new UIDs: full diff on the first run, `UID n+1:*` afterwards.
    let known = ctx.index.live_uids(mb.id)?;
    let candidates = if mb.highest_uid == 0 || known.is_empty() {
        conn.all_uids().await?
    } else {
        conn.uids_after(mb.highest_uid).await?
    };
    let known_set: std::collections::HashSet<u32> = known.into_iter().collect();
    let new_uids: Vec<u32> = candidates
        .into_iter()
        .filter(|u| !known_set.contains(u))
        .collect();

    // 2. Discovery pass: insert + announce before downloading.
    if !new_uids.is_empty() {
        for d in conn.discover(&new_uids).await? {
            if ctx.index.find_membership(mb.id, d.uid)?.is_some() {
                continue;
            }
            let gm = d.gm_msgid.map(|g| g.to_string());
            if let Some(existing) = gm
                .as_deref()
                .map(|g| ctx.index.find_by_gm_msgid(&account.id, g))
                .transpose()?
                .flatten()
            {
                // Same Gmail message seen through another mailbox: add the membership only.
                ctx.index
                    .add_membership(existing, mb.id, d.uid, &d.flags, &d.gm_labels)?;
                ctx.index
                    .update_labels_for_message(existing, &d.gm_labels)?;
                continue;
            }
            let id = ctx.index.insert_message(&NewMessage {
                account: &account.id,
                run: Some(run),
                size: d.size as u64,
                internaldate: d.internaldate,
                message_id_hdr: d.envelope.message_id.as_deref(),
                gm_msgid: gm.as_deref(),
                envelope: &d.envelope,
                state: MessageState::Discovered,
                sha256: None,
            })?;
            ctx.index
                .add_membership(id, mb.id, d.uid, &d.flags, &d.gm_labels)?;
            stats.discovered += 1;
            if let Some(summary) = ctx.index.summary(id, dest_ids.len() as u32)? {
                ctx.events
                    .emit(SyncEvent::NewMessageDiscovered { message: summary });
            }
        }
    }

    // Flag changes via CONDSTORE.
    if let (Some(old), Some(new)) = (mb.highestmodseq, sel.highest_modseq) {
        if new > old {
            for (uid, flags, labels) in conn.changed_since(old).await.unwrap_or_default() {
                ctx.index
                    .update_flags(mb.id, uid, &flags, labels.as_deref())?;
            }
        }
    }

    // 3+4. Download pass, leftovers first (pending_messages orders them).
    let pending = ctx.index.pending_messages(&account.id, ctx.manual)?;
    let mut work: Vec<(MessageRow, u32)> = Vec::new();
    for m in pending {
        if let Some(ms) = ctx
            .index
            .memberships(m.id)?
            .into_iter()
            .find(|ms| ms.mailbox == mb.id && !ms.deleted_on_server)
        {
            work.push((m, ms.uid));
        }
    }
    let total = work.len() as u64;
    for (i, (msg, uid)) in work.into_iter().enumerate() {
        ctx.check_cancel()?;
        ctx.progress(i as u64, total, format!("{display}: {} of {total}", i + 1));
        match store_message(ctx, account, conn, &mb, &msg, uid, stores, dest_ids).await {
            Ok(Some(bytes)) => {
                stats.downloaded += 1;
                stats.bytes += bytes;
            }
            Ok(None) => {}
            Err(e) => {
                let err = format!("{e:#}");
                ctx.index
                    .set_state(msg.id, MessageState::Error, Some(&err))?;
                emit_state(
                    ctx,
                    msg.id,
                    &account.id,
                    MessageState::Error,
                    0,
                    dest_ids.len() as u32,
                    Some(err.clone()),
                );
                stats.errors.push(format!("{display} uid {uid}: {err}"));
            }
        }
        if ctx.index.message(msg.id)?.map(|m| m.state) == Some(MessageState::Verified) {
            stats.verified += 1;
        }
    }

    // 5. highest_uid only advances past verified messages.
    let mut highest = mb.highest_uid;
    let mut uids: Vec<(u32, MessageState)> = Vec::new();
    for uid in ctx.index.live_uids(mb.id)? {
        if let Some(ms) = ctx.index.find_membership(mb.id, uid)? {
            let st = ctx
                .index
                .message(ms.message)?
                .map(|m| m.state)
                .unwrap_or(MessageState::Error);
            uids.push((uid, st));
        }
    }
    uids.sort_by_key(|(u, _)| *u);
    for (uid, st) in uids {
        if st != MessageState::Verified {
            break;
        }
        highest = highest.max(uid);
    }
    ctx.index
        .set_mailbox_sync(mb.id, highest, sel.highest_modseq)?;
    Ok(mb.id)
}

fn emit_state(
    ctx: &JobCtx,
    id: i64,
    account: &str,
    state: MessageState,
    stored: u32,
    destinations: u32,
    error: Option<String>,
) {
    ctx.events.emit(SyncEvent::MessageStateChanged {
        id,
        account_id: account.to_string(),
        state,
        stored,
        destinations,
        error,
    });
}

/// Downloads one message (or reuses the spool) and writes + verifies it on every destination
/// that doesn't hold a verified replica yet. Returns downloaded bytes.
#[allow(clippy::too_many_arguments)]
async fn store_message(
    ctx: &JobCtx,
    account: &Account,
    conn: &mut ImapConn,
    mb: &MailboxRow,
    msg: &MessageRow,
    uid: u32,
    stores: &[Store],
    dest_ids: &[String],
) -> anyhow::Result<Option<u64>> {
    let n = dest_ids.len() as u32;
    let replicas = ctx.index.replicas_of(msg.id)?;
    let missing: Vec<&Store> = stores
        .iter()
        .filter(|s| {
            !replicas
                .iter()
                .any(|r| r.destination == s.dest.id && r.status == ReplicaStatus::Verified)
        })
        .collect();
    if missing.is_empty() {
        let (state, stored) = ctx.index.refresh_message_state(msg.id, dest_ids)?;
        emit_state(ctx, msg.id, &account.id, state, stored, n, None);
        ctx.spool_remove(msg.id);
        return Ok(None);
    }

    let mut downloaded = None;
    let cached = match ctx
        .spool_get(msg.id)
        .filter(|raw| msg.sha256.as_deref() == Some(&crypto::sha256_hex(raw)))
    {
        Some(raw) => Some(raw),
        None => copy_from_replica(ctx, msg, stores).await,
    };
    let raw = match cached {
        Some(raw) => raw,
        None => {
            ctx.index
                .set_state(msg.id, MessageState::Downloading, None)?;
            emit_state(
                ctx,
                msg.id,
                &account.id,
                MessageState::Downloading,
                0,
                n,
                None,
            );
            let (raw, size) = conn
                .fetch_raw(uid)
                .await?
                .ok_or_else(|| anyhow!("message vanished from the server"))?;
            let expected = size.map(u64::from).unwrap_or(msg.size);
            if raw.len() as u64 != expected {
                bail!(
                    "downloaded {} bytes but the server reported RFC822.SIZE {expected}",
                    raw.len()
                );
            }
            let sha = crypto::sha256_hex(&raw);
            if let Some(old) = &msg.sha256 {
                if *old != sha {
                    tracing::warn!(message = msg.id, "content hash changed since last download");
                }
            }
            ctx.index
                .set_content(msg.id, &sha, raw.len() as u64, None)?;
            // The spool only speeds up resuming; a full or failing local disk must not stop the upload.
            if let Err(e) = ctx.spool_put(msg.id, &raw) {
                tracing::warn!(
                    message = msg.id,
                    "spool write failed, continuing from memory: {e:#}"
                );
            }
            downloaded = Some(raw.len() as u64);
            raw
        }
    };
    let sha = crypto::sha256_hex(&raw);
    let mut errors = Vec::new();
    for store in missing {
        let path = store.object_path(account, &mb.path, mb.uidvalidity, uid, &sha);
        match store.put_verified(&path, &raw, &sha).await {
            Ok(stored_size) => {
                ctx.index.upsert_replica(
                    msg.id,
                    &store.dest.id,
                    &path,
                    store.dest.encrypt,
                    stored_size,
                    ReplicaStatus::Verified,
                )?;
                let (state, stored) = ctx.index.refresh_message_state(msg.id, dest_ids)?;
                emit_state(ctx, msg.id, &account.id, state, stored, n, None);
            }
            Err(e) => {
                ctx.index.upsert_replica(
                    msg.id,
                    &store.dest.id,
                    &path,
                    store.dest.encrypt,
                    0,
                    ReplicaStatus::Pending,
                )?;
                errors.push(format!("{}: {e:#}", store.dest.name));
            }
        }
    }
    let (state, _) = ctx.index.refresh_message_state(msg.id, dest_ids)?;
    if state == MessageState::Verified {
        ctx.spool_remove(msg.id);
    }
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(downloaded)
}

/// Reads a verified copy of `msg` from another destination (hash-checked).
async fn copy_from_replica(ctx: &JobCtx, msg: &MessageRow, stores: &[Store]) -> Option<Vec<u8>> {
    let sha = msg.sha256.as_deref()?;
    for rep in ctx.index.replicas_of(msg.id).ok()? {
        if rep.status != ReplicaStatus::Verified {
            continue;
        }
        let Some(store) = stores.iter().find(|s| s.dest.id == rep.destination) else {
            continue;
        };
        if let Ok(raw) = store.get(&rep.object_path, rep.encrypted).await {
            if crypto::sha256_hex(&raw) == sha {
                return Some(raw);
            }
        }
    }
    None
}

/// Copies a message that is gone from the server to the destinations still missing it.
async fn replicate_offline(
    ctx: &JobCtx,
    account: &Account,
    msg: &MessageRow,
    stores: &[Store],
    dest_ids: &[String],
) -> anyhow::Result<bool> {
    // Malo's own encrypted download spool first: a message deleted from the server after Malo
    // downloaded it is still stored, even when no destination holds a copy yet.
    let spooled = ctx
        .spool_get(msg.id)
        .filter(|raw| msg.sha256.as_deref() == Some(crypto::sha256_hex(raw).as_str()));
    let raw = match spooled {
        Some(raw) => Some(raw),
        None => copy_from_replica(ctx, msg, stores).await,
    };
    let Some(raw) = raw else {
        return Ok(false);
    };
    let sha = crypto::sha256_hex(&raw);
    let ms = ctx.index.memberships(msg.id)?;
    let Some(first) = ms.first() else {
        return Ok(false);
    };
    let Some(mb) = ctx.index.mailbox(first.mailbox)? else {
        return Ok(false);
    };
    let replicas = ctx.index.replicas_of(msg.id)?;
    for store in stores {
        if replicas
            .iter()
            .any(|r| r.destination == store.dest.id && r.status == ReplicaStatus::Verified)
        {
            continue;
        }
        let path = store.object_path(account, &mb.path, mb.uidvalidity, first.uid, &sha);
        let size = store.put_verified(&path, &raw, &sha).await?;
        ctx.index.upsert_replica(
            msg.id,
            &store.dest.id,
            &path,
            store.dest.encrypt,
            size,
            ReplicaStatus::Verified,
        )?;
    }
    let (state, stored) = ctx.index.refresh_message_state(msg.id, dest_ids)?;
    emit_state(
        ctx,
        msg.id,
        &account.id,
        state,
        stored,
        dest_ids.len() as u32,
        None,
    );
    if state == MessageState::Verified {
        ctx.spool_remove(msg.id);
    }
    Ok(state == MessageState::Verified)
}

fn dest_generation_key(account_id: &str, destination_id: &str) -> String {
    format!("manifest_gen:{account_id}:{destination_id}")
}

/// Records, after a rebuild, that the index holds the account's manifests on a destination up to
/// `generation`: from now on they may be rewritten from the index.
pub fn absorbed_manifests(
    ctx: &JobCtx,
    account_id: &str,
    destination_id: &str,
    generation: u64,
) -> anyhow::Result<()> {
    // The account-wide counter stays above every generation seen, so newer is always higher.
    ctx.index
        .kv_bump(&format!("manifest_gen:{account_id}"), generation, 0)?;
    ctx.index
        .kv_bump(&dest_generation_key(account_id, destination_id), generation, 0)?;
    Ok(())
}

/// Rewrites the manifests of the given mailboxes on one destination from the index.
///
/// Manifests are what a rebuild recovers mail from, so they are only ever replaced by an index
/// that holds everything in them. The account's manifests on a destination this index never wrote
/// to, or whose generation is ahead of what the index knows of it (index lost, restored from an
/// old copy, rebuilt from another destination, destination re-added), are imported first. After a failed or partial write, a
/// new destination, or a destination that went back in time, every manifest of the account is
/// rewritten; the new generation is written last.
pub async fn write_manifests(
    ctx: &JobCtx,
    account: &Account,
    store: &Store,
    mailboxes: &[i64],
) -> anyhow::Result<()> {
    let dest_key = dest_generation_key(&account.id, &store.dest.id);
    let dirty_key = format!("manifest_dirty:{}:{}", account.id, store.dest.id);
    let mut known = ctx
        .index
        .kv_get(&dest_key)?
        .and_then(|v| v.parse::<u64>().ok());
    let mut theirs = match store.read_account_marker(account).await? {
        MarkerRead::Absent => None,
        // Unreadable: nothing is known about the manifests next to it.
        MarkerRead::Damaged => Some(u64::MAX),
        MarkerRead::Found(m) => Some(m.generation),
    };
    // An index that never wrote here (or lost track) imports whatever is there first, marker or
    // not: a marker can be missing or behind its manifests after an interrupted write.
    let ahead = known.is_none() || theirs.is_some_and(|g| g > known.unwrap_or(0));
    if ahead {
        let g = crate::rebuild::absorb_account(ctx, store, account).await?;
        tracing::info!(dest = %store.dest.name, account = %account.id, "imported manifests of generation {g} before rewriting them");
        known = Some(g);
        theirs = Some(g);
    }
    let full = ahead
        || ctx.index.kv_get(&dirty_key)?.is_some()
        || known.is_none()
        || theirs.is_none_or(|g| Some(g) < known);
    let all: Vec<i64>;
    let mailboxes = if full {
        all = ctx
            .index
            .mailboxes(Some(&account.id), false)?
            .into_iter()
            .map(|m| m.id)
            .collect();
        &all[..]
    } else {
        mailboxes
    };
    ctx.index.kv_set(&dirty_key, "1")?;
    if theirs.is_none() {
        // The account's name and server for a rebuild, even if the manifests below fail.
        store.write_account_marker(account, 0).await?;
    }
    let mut by_mailbox: BTreeMap<i64, Vec<ManifestEntry>> = BTreeMap::new();
    let mut boxes: HashMap<i64, MailboxRow> = HashMap::new();
    for id in mailboxes {
        if let Some(mb) = ctx.index.mailbox(*id)? {
            boxes.insert(*id, mb);
            by_mailbox.insert(*id, vec![]);
        }
    }
    for rep in ctx.index.replicas_in(&store.dest.id)? {
        if rep.status != ReplicaStatus::Verified {
            continue;
        }
        let Some(msg) = ctx.index.message(rep.message)? else {
            continue;
        };
        if msg.account != account.id {
            continue;
        }
        for ms in ctx.index.memberships(msg.id)? {
            let (Some(entries), Some(mb)) =
                (by_mailbox.get_mut(&ms.mailbox), boxes.get(&ms.mailbox))
            else {
                continue;
            };
            entries.push(ManifestEntry {
                account_id: account.id.clone(),
                mailbox: mb.name.clone(),
                mailbox_display: mb.display.clone(),
                delimiter: mb.delimiter.clone(),
                special_use: mb.special_use.clone(),
                uidvalidity: mb.uidvalidity,
                uid: ms.uid,
                sha256: msg.sha256.clone().unwrap_or_default(),
                size: msg.size,
                flags: ms.flags.clone(),
                labels: ms.gm_labels.clone(),
                internaldate: msg.internaldate,
                gm_msgid: msg.gm_msgid.clone(),
                message_id: msg.message_id_hdr.clone(),
                object_path: rep.object_path.clone(),
                envelope: msg.envelope.clone(),
            });
        }
    }
    for (id, mut entries) in by_mailbox {
        let mb = &boxes[&id];
        entries.sort_by_key(|e| e.uid);
        let key = format!("{}#{}", mb.name, mb.uidvalidity);
        let path = store.manifest_path(account, &key, &format!("{}.{}", mb.path, mb.uidvalidity));
        store.write_manifest(&path, &entries).await?;
    }
    let generation = ctx.index.kv_bump(
        &format!("manifest_gen:{}", account.id),
        theirs.unwrap_or(0),
        1,
    )?;
    // Recorded before the marker: if the marker write fails, the next write sees the destination
    // behind (a full rewrite), never ahead.
    ctx.index.kv_bump(&dest_key, generation, 0)?;
    store.write_account_marker(account, generation).await?;
    ctx.index.kv_delete(&dirty_key)?;
    Ok(())
}

/// Result of comparing the server with the index for one account.
#[derive(Debug, Default, Clone)]
pub struct ImapDiff {
    pub on_server: u64,
    pub backlog: u64,
    pub vanished: u64,
}

/// Full UID diff of every backed-up mailbox (integrity checks). Messages missing on the server
/// are recorded as deleted outside Malo, not treated as errors.
pub async fn imap_diff(ctx: &JobCtx, account: &Account) -> anyhow::Result<ImapDiff> {
    let mut conn = imap::connect(account, ctx.tokens.as_ref()).await?;
    let listing = conn.list_mailboxes().await?;
    let targets = backup_targets(&listing, conn.caps.gmail());
    let mut diff = ImapDiff::default();
    for t in targets {
        ctx.check_cancel()?;
        let sel = conn.select(&t.name).await?;
        let server: std::collections::HashSet<u32> = conn.all_uids().await?.into_iter().collect();
        diff.on_server += server.len() as u64;
        let mb = ctx
            .index
            .mailboxes(Some(&account.id), true)?
            .into_iter()
            .find(|m| m.name == t.name && m.uidvalidity == sel.uidvalidity);
        let Some(mb) = mb else {
            diff.backlog += server.len() as u64;
            continue;
        };
        let live = ctx.index.live_uids(mb.id)?;
        let live_set: std::collections::HashSet<u32> = live.iter().copied().collect();
        let gone: Vec<u32> = live.into_iter().filter(|u| !server.contains(u)).collect();
        diff.vanished += gone.len() as u64;
        if !gone.is_empty() {
            ctx.index.mark_deleted_on_server(mb.id, &gone, false)?;
            ctx.index.audit(
                "vanished_on_server",
                Some(&account.id),
                &serde_json::json!({"mailbox": mb.display, "uids": gone}),
            )?;
        }
        for uid in &server {
            if !live_set.contains(uid) {
                diff.backlog += 1;
            } else if let Some(ms) = ctx.index.find_membership(mb.id, *uid)? {
                if ctx.index.message(ms.message)?.map(|m| m.state) != Some(MessageState::Verified) {
                    diff.backlog += 1;
                }
            }
        }
    }
    conn.logout().await;
    Ok(diff)
}
