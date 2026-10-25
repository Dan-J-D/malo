//! Integrity checks (quick: list + compare; deep: download + decrypt + hash) and repair.

use std::collections::{HashMap, HashSet};

use malo_api::{
    AccountBacklog, CheckReport, CheckScope, DeepCheckMode, DestinationHealth, MessageState,
    SyncEvent,
};

use crate::config::Account;
use crate::crypto;
use crate::ctx::JobCtx;
use crate::imap;
use crate::index::{ReplicaRow, ReplicaStatus};
use crate::store::{Store, Verify};
use crate::sync;

fn is_object_path(p: &str) -> bool {
    !(p.contains("/manifest/")
        || p.ends_with("/account.json")
        || p.ends_with("/account.json.enc")
        || p.rsplit('/')
            .next()
            .is_some_and(|n| n.starts_with(".malo-probe")))
}

/// Whether this replica is re-hashed in this deep run.
fn in_deep_slice(mode: &DeepCheckMode, message: i64, slice: u32) -> bool {
    match mode {
        DeepCheckMode::Full => true,
        DeepCheckMode::Off => false,
        DeepCheckMode::Rotating { slices } => {
            (message.rem_euclid((*slices).max(1) as i64)) as u32 == slice
        }
    }
}

pub async fn run_check(
    ctx: &JobCtx,
    scope: &CheckScope,
    deep: bool,
    repair: bool,
) -> anyhow::Result<CheckReport> {
    let account_filter: Option<&str> = match scope {
        CheckScope::Account { account_id } => Some(account_id),
        _ => None,
    };
    let stores: Vec<Store> = match scope {
        CheckScope::Destination { destination_id } => vec![ctx.store(destination_id)?],
        _ => ctx.stores()?,
    };
    let dest_ids = ctx.destination_ids();
    let mut report = CheckReport {
        id: 0,
        created_at: chrono::Utc::now(),
        deep,
        scope: scope.clone(),
        destinations: vec![],
        accounts: vec![],
        repaired: 0,
        ok: true,
    };
    let mut damaged: Vec<(String, ReplicaRow)> = Vec::new();

    for (i, store) in stores.iter().enumerate() {
        ctx.check_cancel()?;
        ctx.progress(
            i as u64,
            stores.len() as u64,
            format!("checking {}", store.dest.name),
        );
        let (health, bad) = check_destination(ctx, store, account_filter, deep).await?;
        damaged.extend(bad.into_iter().map(|r| (store.dest.id.clone(), r)));
        report.destinations.push(health);
    }

    // Server ↔ index comparison.
    if !matches!(scope, CheckScope::Destination { .. }) {
        for account in ctx
            .config
            .accounts
            .iter()
            .filter(|a| a.enabled && !a.imported)
        {
            if account_filter.is_some_and(|f| f != account.id) {
                continue;
            }
            ctx.check_cancel()?;
            let mut b = AccountBacklog {
                account_id: account.id.clone(),
                name: account.name.clone(),
                ..Default::default()
            };
            match sync::imap_diff(ctx, account).await {
                Ok(d) => {
                    b.on_server = d.on_server;
                    b.backlog = d.backlog;
                    b.vanished = d.vanished;
                }
                Err(e) => b.error = Some(format!("{e:#}")),
            }
            report.accounts.push(b);
        }
    }

    if repair && !damaged.is_empty() {
        report.repaired = repair_replicas(ctx, &damaged).await?;
        // Re-evaluate the destinations that had damage.
        for h in report.destinations.iter_mut() {
            let (missing_fixed, corrupt_fixed) = count_fixed(ctx, &damaged, &h.destination_id)?;
            h.missing = h.missing.saturating_sub(missing_fixed);
            h.corrupt = h.corrupt.saturating_sub(corrupt_fixed);
            h.healthy += missing_fixed + corrupt_fixed;
            h.ok = h.error.is_none() && h.missing == 0 && h.corrupt == 0;
        }
    }

    for h in &report.destinations {
        let reason = (!h.ok).then(|| match &h.error {
            Some(e) => format!("check failed: {e}"),
            None => format!("{} missing, {} corrupt", h.missing, h.corrupt),
        });
        ctx.index
            .set_destination_status(&h.destination_id, !h.ok, reason.as_deref())?;
    }
    for (_, r) in &damaged {
        ctx.index.refresh_message_state(r.message, &dest_ids)?;
    }
    report.ok = report.destinations.iter().all(|d| d.ok);
    report.id = ctx.index.save_report(&report)?;
    ctx.events.emit(SyncEvent::CheckFinished {
        report: report.clone(),
    });
    Ok(report)
}

fn count_fixed(
    ctx: &JobCtx,
    damaged: &[(String, ReplicaRow)],
    dest: &str,
) -> anyhow::Result<(u64, u64)> {
    let mut missing = 0;
    let mut corrupt = 0;
    for (d, r) in damaged.iter().filter(|(d, _)| d == dest) {
        let now = ctx
            .index
            .replicas_of(r.message)?
            .into_iter()
            .find(|x| &x.destination == d);
        if now.map(|x| x.status) == Some(ReplicaStatus::Verified) {
            match r.status {
                ReplicaStatus::Missing => missing += 1,
                _ => corrupt += 1,
            }
        }
    }
    Ok((missing, corrupt))
}

async fn check_destination(
    ctx: &JobCtx,
    store: &Store,
    account_filter: Option<&str>,
    deep: bool,
) -> anyhow::Result<(DestinationHealth, Vec<ReplicaRow>)> {
    let mut h = DestinationHealth {
        destination_id: store.dest.id.clone(),
        name: store.dest.name.clone(),
        ..Default::default()
    };
    let mut damaged = Vec::new();
    let files = match store.list_files(&store.root_prefix()).await {
        Ok(f) => f,
        Err(e) => {
            h.error = Some(format!("{e:#}"));
            return Ok((h, damaged));
        }
    };
    let accounts: HashMap<String, &Account> = ctx
        .config
        .accounts
        .iter()
        .map(|a| (a.id.clone(), a))
        .collect();
    let slice = match &store.dest.deep_check {
        DeepCheckMode::Rotating { slices } if deep => {
            ctx.index.next_deep_slice(&store.dest.id, *slices)?
        }
        _ => 0,
    };
    let all = ctx.index.replicas_in(&store.dest.id)?;
    let mut referenced: HashSet<String> = HashSet::new();
    let mut checked_paths: HashMap<String, Verify> = HashMap::new();
    let mut account_of: HashMap<i64, String> = HashMap::new();
    for r in &all {
        referenced.insert(r.object_path.clone());
    }
    let mine: Vec<&ReplicaRow> = all
        .iter()
        .filter(|r| match account_filter {
            None => true,
            Some(a) => {
                let acc = account_of.entry(r.message).or_insert_with(|| {
                    ctx.index
                        .message(r.message)
                        .ok()
                        .flatten()
                        .map(|m| m.account)
                        .unwrap_or_default()
                });
                acc == a
            }
        })
        .collect();
    let total = mine.len() as u64;
    for (i, r) in mine.into_iter().enumerate() {
        if i % 200 == 0 {
            ctx.check_cancel()?;
            ctx.events.emit(SyncEvent::CheckProgress {
                job_id: ctx.job_id.clone(),
                destination_id: store.dest.id.clone(),
                done: i as u64,
                total,
            });
        }
        if matches!(r.status, ReplicaStatus::Pending | ReplicaStatus::Written) {
            h.pending += 1;
            continue;
        }
        let Some(sha) = r.sha256.as_deref() else {
            h.pending += 1;
            continue;
        };
        let expected = if r.encrypted {
            crypto::encrypted_len(r.size)
        } else {
            r.size
        };
        // A replica already found corrupt is always re-hashed: a size match must not clear it
        // just because this check's deep slice (or a quick check) skips it.
        let deep_done = (deep && in_deep_slice(&store.dest.deep_check, r.message, slice))
            || r.status == ReplicaStatus::Corrupt;
        let outcome = match files.get(&r.object_path) {
            None => Verify::Missing,
            Some(sz) if *sz != expected => Verify::Corrupt(format!("size {sz} ≠ {expected}")),
            Some(_) if deep_done => {
                if let Some(v) = checked_paths.get(&r.object_path) {
                    v.clone()
                } else {
                    let v = match store
                        .verify(&r.object_path, r.encrypted, sha, r.size, true)
                        .await
                    {
                        Ok(v) => v,
                        // A read error says nothing about the object: don't mark it corrupt, don't
                        // abort the whole check — report the destination as not confirmed.
                        Err(e) => {
                            h.error.get_or_insert_with(|| format!("{e:#}"));
                            continue;
                        }
                    };
                    h.checked_deep += 1;
                    checked_paths.insert(r.object_path.clone(), v.clone());
                    v
                }
            }
            Some(_) => Verify::Ok,
        };
        match outcome {
            Verify::Ok => {
                h.healthy += 1;
                ctx.index.set_replica_status(
                    r.message,
                    &store.dest.id,
                    ReplicaStatus::Verified,
                    deep_done,
                )?;
            }
            Verify::Missing => {
                h.missing += 1;
                ctx.index.set_replica_status(
                    r.message,
                    &store.dest.id,
                    ReplicaStatus::Missing,
                    deep_done,
                )?;
                let mut r = r.clone();
                r.status = ReplicaStatus::Missing;
                damaged.push(r);
            }
            Verify::Corrupt(why) => {
                tracing::warn!(dest = %store.dest.name, path = %r.object_path, "corrupt object: {why}");
                h.corrupt += 1;
                ctx.index.set_replica_status(
                    r.message,
                    &store.dest.id,
                    ReplicaStatus::Corrupt,
                    deep_done,
                )?;
                let mut r = r.clone();
                r.status = ReplicaStatus::Corrupt;
                damaged.push(r);
            }
        }
    }
    // Orphans: objects inside our account directories that no replica references.
    let prefixes: Vec<String> = accounts
        .values()
        .filter(|a| account_filter.is_none_or(|f| f == a.id))
        .map(|a| format!("{}/", store.account_root(a)))
        .collect();
    h.orphaned = files
        .keys()
        .filter(|p| {
            is_object_path(p)
                && !referenced.contains(*p)
                && prefixes.iter().any(|pre| p.starts_with(pre))
        })
        .count() as u64;
    h.ok = h.error.is_none() && h.missing == 0 && h.corrupt == 0;
    Ok((h, damaged))
}

/// Re-copies damaged replicas from a healthy destination, or re-fetches from IMAP.
pub async fn repair_replicas(
    ctx: &JobCtx,
    damaged: &[(String, ReplicaRow)],
) -> anyhow::Result<u64> {
    let stores: HashMap<String, Store> = ctx
        .stores()?
        .into_iter()
        .map(|s| (s.dest.id.clone(), s))
        .collect();
    let mut repaired = 0;
    let mut accounts_touched: HashSet<String> = HashSet::new();
    let mut imap_needed: Vec<(String, ReplicaRow)> = Vec::new();
    for (dest_id, r) in damaged {
        ctx.check_cancel()?;
        let Some(target) = stores.get(dest_id) else {
            continue;
        };
        let Some(sha) = r.sha256.as_deref() else {
            continue;
        };
        let mut fixed = false;
        // Sources: this message's other replicas, then any verified copy of the same content kept
        // for another message (e.g. an imported archive whose only copy was damaged, while the
        // live account still holds the mail). The hash is re-checked after every read.
        let mut sources = ctx.index.replicas_of(r.message)?;
        for other in ctx.index.messages_with_sha(sha)? {
            if other != r.message {
                sources.extend(ctx.index.replicas_of(other)?);
            }
        }
        for src in sources {
            if (src.message == r.message && src.destination == *dest_id)
                || src.status != ReplicaStatus::Verified
            {
                continue;
            }
            let Some(source) = stores.get(&src.destination) else {
                continue;
            };
            let Ok(raw) = source.get(&src.object_path, src.encrypted).await else {
                continue;
            };
            if crypto::sha256_hex(&raw) != sha {
                ctx.index.set_replica_status(
                    src.message,
                    &src.destination,
                    ReplicaStatus::Corrupt,
                    true,
                )?;
                continue;
            }
            if write_repair(ctx, target, r, &raw).await? {
                fixed = true;
                break;
            }
        }
        if fixed {
            repaired += 1;
            if let Some(m) = ctx.index.message(r.message)? {
                accounts_touched.insert(m.account);
            }
        } else {
            imap_needed.push((dest_id.clone(), r.clone()));
        }
    }
    // IMAP fallback, grouped per account.
    let mut by_account: HashMap<String, Vec<(String, ReplicaRow)>> = HashMap::new();
    for (d, r) in imap_needed {
        if let Some(m) = ctx.index.message(r.message)? {
            by_account.entry(m.account).or_default().push((d, r));
        }
    }
    for (account_id, items) in by_account {
        let Some(account) = ctx.config.account(&account_id).filter(|a| !a.imported) else {
            continue;
        };
        let Ok(mut conn) = imap::connect(account, ctx.tokens.as_ref()).await else {
            continue;
        };
        for (dest_id, r) in items {
            ctx.check_cancel()?;
            let Some(target) = stores.get(&dest_id) else {
                continue;
            };
            for ms in ctx
                .index
                .memberships(r.message)?
                .into_iter()
                .filter(|m| !m.deleted_on_server)
            {
                let Some(mb) = ctx.index.mailbox(ms.mailbox)?.filter(|m| m.current) else {
                    continue;
                };
                let Ok(sel) = conn.select(&mb.name).await else {
                    continue;
                };
                if sel.uidvalidity != mb.uidvalidity {
                    continue;
                }
                let Ok(Some((raw, _))) = conn.fetch_raw(ms.uid).await else {
                    continue;
                };
                if Some(crypto::sha256_hex(&raw).as_str()) != r.sha256.as_deref() {
                    continue;
                }
                if write_repair(ctx, target, &r, &raw).await? {
                    repaired += 1;
                    accounts_touched.insert(account_id.clone());
                    break;
                }
            }
        }
        conn.logout().await;
    }
    // Manifests may reference repaired objects; rewrite them (not after the user was locked).
    for account_id in accounts_touched
        .into_iter()
        .filter(|_| !ctx.sealed.is_cancelled())
    {
        let Some(account) = ctx.config.account(&account_id) else {
            continue;
        };
        let mbs: Vec<i64> = ctx
            .index
            .mailboxes(Some(&account_id), false)?
            .into_iter()
            .map(|m| m.id)
            .collect();
        for store in stores.values() {
            if let Err(e) = sync::write_manifests(ctx, account, store, &mbs).await {
                tracing::warn!("manifest rewrite on {} failed: {e:#}", store.dest.name);
            }
        }
    }
    let dest_ids = ctx.destination_ids();
    for (_, r) in damaged {
        let (state, stored) = ctx.index.refresh_message_state(r.message, &dest_ids)?;
        if let Some(m) = ctx.index.message(r.message)? {
            ctx.events.emit(SyncEvent::MessageStateChanged {
                id: r.message,
                account_id: m.account,
                state,
                stored,
                destinations: dest_ids.len() as u32,
                error: (state != MessageState::Verified).then(|| "replica damaged".to_string()),
            });
        }
    }
    Ok(repaired)
}

async fn write_repair(
    ctx: &JobCtx,
    target: &Store,
    r: &ReplicaRow,
    raw: &[u8],
) -> anyhow::Result<bool> {
    let sha = crypto::sha256_hex(raw);
    match target.put_verified(&r.object_path, raw, &sha).await {
        Ok(size) => {
            ctx.index.upsert_replica(
                r.message,
                &target.dest.id,
                &r.object_path,
                target.dest.encrypt,
                size,
                ReplicaStatus::Verified,
            )?;
            ctx.index.audit(
                "replica_repaired",
                None,
                &serde_json::json!({"message": r.message, "destination": target.dest.id, "path": r.object_path}),
            )?;
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("repair write to {} failed: {e:#}", target.dest.name);
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotating_slices_cover_everything() {
        let mode = DeepCheckMode::Rotating { slices: 7 };
        for m in 0..100i64 {
            assert_eq!((0..7).filter(|s| in_deep_slice(&mode, m, *s)).count(), 1);
        }
        assert!(!in_deep_slice(&DeepCheckMode::Off, 1, 0));
        assert!(is_object_path("r/a/objects/ab/x.enc"));
        assert!(!is_object_path("r/a/manifest/INBOX.jsonl"));
        assert!(!is_object_path("r/a/account.json"));
    }
}
