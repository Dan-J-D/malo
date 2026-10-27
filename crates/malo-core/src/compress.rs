//! Recompressing mail stored before compression: each uncompressed object on an encrypted
//! destination that compresses is read, checked against its hash, written again compressed under
//! its compressed name, and verified. Only then do the replicas point at the new object, the
//! manifests are rewritten, and the old object is deleted. The old copy is never overwritten, so
//! a failure at any point leaves the message stored.

use std::collections::BTreeMap;

use malo_api::CompressSummary;

use crate::crypto;
use crate::ctx::JobCtx;
use crate::store::Store;
use crate::sync;

pub async fn compress_stored(
    ctx: &JobCtx,
    destination_id: Option<&str>,
) -> anyhow::Result<CompressSummary> {
    let stores: Vec<Store> = match destination_id {
        Some(id) => vec![ctx.store(id)?],
        None => ctx.stores()?,
    };
    let mut summary = CompressSummary::default();
    // (destination, path) pairs to do, with the destinations that compress.
    let mut work: Vec<(usize, String)> = Vec::new();
    for (i, store) in stores.iter().enumerate() {
        if !store.dest.compresses() {
            continue;
        }
        work.extend(
            ctx.index
                .uncompressed_objects(&store.dest.id)?
                .into_iter()
                .map(|p| (i, p)),
        );
    }
    let total = work.len() as u64;
    // Old objects per destination and account: deleted once that account's manifests there
    // name the new ones.
    let mut moved: BTreeMap<usize, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for (n, (i, path)) in work.into_iter().enumerate() {
        if n % 20 == 0 {
            ctx.check_cancel()?;
            ctx.progress(n as u64, total, "compressing stored mail");
        }
        let store = &stores[i];
        match recompress(ctx, store, &path).await {
            Ok(Some((before, after, account))) => {
                summary.objects += 1;
                summary.bytes_before += before;
                summary.bytes_after += after;
                moved
                    .entry(i)
                    .or_default()
                    .entry(account)
                    .or_default()
                    .push(path);
            }
            Ok(None) => {}
            Err(e) => {
                summary.failed += 1;
                if summary.errors.len() < 20 {
                    summary.errors.push(format!("{}: {e:#}", store.dest.name));
                }
            }
        }
    }
    // A job stopped before this point leaves the old objects as orphans (wasted space, never a
    // manifest naming a deleted object); the dirty mark gets the manifests rewritten anyway.
    for (i, accounts) in moved {
        let store = &stores[i];
        for (account_id, old) in accounts {
            let Ok(account) = ctx.account(&account_id) else {
                continue;
            };
            let done = async {
                sync::write_manifests(ctx, account, store, &[]).await?;
                sync::queue_object_deletes(ctx, &store.dest.id, &old)?;
                sync::flush_object_deletes(ctx, store).await
            };
            if let Err(e) = done.await {
                summary
                    .errors
                    .push(format!("{}: {}: {e:#}", store.dest.name, account.name));
            }
        }
    }
    ctx.progress(total, total, "done");
    Ok(summary)
}

/// Recompresses one object. Returns its old and new size and its account; `None` when there's
/// nothing to do any more.
async fn recompress(
    ctx: &JobCtx,
    store: &Store,
    old_path: &str,
) -> anyhow::Result<Option<(u64, u64, String)>> {
    let replicas = ctx.index.replicas_at(&store.dest.id, old_path)?;
    let Some(first) = replicas.first() else {
        return Ok(None);
    };
    let sha = first
        .sha256
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{old_path}: no content hash"))?;
    let Some(msg) = ctx.index.message(first.message)? else {
        return Ok(None);
    };
    let account = ctx.account(&msg.account)?;
    let raw = store.get(old_path, true).await?;
    anyhow::ensure!(
        crypto::sha256_hex(&raw) == sha,
        "{old_path} doesn't match its hash; an integrity check will repair it"
    );
    // Compressed names depend on the account and content only.
    let new_path = store.object_path(account, "", 0, 0, &sha);
    anyhow::ensure!(new_path != old_path, "{old_path} has no compressed name");
    let after = store.put_verified(&new_path, &raw, &sha).await?;
    let before = replicas.iter().map(|r| r.stored_size).max().unwrap_or(0);
    // From here the manifests on the destination name an object that is about to go: the next
    // manifest write (this job's, or any other) rewrites all of them before deleting it.
    sync::mark_manifests_dirty(ctx, &account.id, &store.dest.id)?;
    ctx.index
        .move_replica_object(&store.dest.id, old_path, &new_path, after)?;
    Ok(Some((before, after, msg.account)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use malo_api::MessageState;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::config::{Destination, UserConfig};
    use crate::ctx::NullSink;
    use crate::index::{Index, NewMessage, ReplicaStatus};
    use crate::store::{is_compressed_path, FsPolicy};

    #[tokio::test]
    async fn stored_mail_is_recompressed_and_the_old_copy_removed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("u")).unwrap();
        let archive = crypto::random_key();
        let account = crate::store::tests::account();
        let mut dest = Destination {
            id: "d1".into(),
            scheme: "fs".into(),
            options: [("root".to_string(), "b".to_string())].into(),
            root: "malo".into(),
            ..crate::store::tests::dest(true)
        };
        dest.features.compress = false;
        let fs = FsPolicy {
            user_root: dir.path().join("u/local"),
            allowed_mounts: vec![],
            user_id: "u".into(),
            owner_dir: None,
        };
        let index = Arc::new(Index::open_in_memory().unwrap());
        let ctx_with = |dest: &Destination| {
            let mut cfg = UserConfig::new(&archive);
            cfg.accounts.push(account.clone());
            cfg.destinations.push(dest.clone());
            JobCtx {
                job_id: "t".into(),
                user_id: "u".into(),
                config: Arc::new(cfg),
                archive_key: archive.clone(),
                index: index.clone(),
                spool_dir: dir.path().join("spool"),
                spool_key: crypto::random_key(),
                fs: fs.clone(),
                tokens: Arc::new(crate::oauth::TokenCache::new(Box::new(|_, _| {}))),
                events: Arc::new(NullSink),
                cancel: CancellationToken::new(),
                sealed: CancellationToken::new(),
                manual: false,
            }
        };
        // A message stored before compression.
        let raw = b"Subject: report\r\n\r\n"
            .iter()
            .copied()
            .chain(b"The numbers for this quarter look fine. ".repeat(2000))
            .collect::<Vec<u8>>();
        let sha = crypto::sha256_hex(&raw);
        let old_ctx = ctx_with(&dest);
        let store = old_ctx.store("d1").unwrap();
        let old_path = store.object_path(&account, "INBOX", 1, 1, &sha);
        assert!(!is_compressed_path(&old_path));
        let before = store.put_verified(&old_path, &raw, &sha).await.unwrap();
        let mb = index
            .upsert_mailbox(&account.id, "INBOX", "INBOX", "INBOX", Some("/"), None, 1)
            .unwrap();
        let env = crate::index::empty_envelope();
        let id = index
            .insert_message(&NewMessage {
                account: &account.id,
                run: None,
                size: raw.len() as u64,
                internaldate: None,
                message_id_hdr: None,
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Verified,
                sha256: Some(&sha),
            })
            .unwrap();
        index.add_membership(id, mb.id, 1, &[], &[]).unwrap();
        index
            .upsert_replica(id, "d1", &old_path, true, before, ReplicaStatus::Verified)
            .unwrap();
        // Nothing to do while the destination doesn't compress.
        let s = compress_stored(&old_ctx, None).await.unwrap();
        assert_eq!(s.objects, 0);

        dest.features.compress = true;
        let ctx = ctx_with(&dest);
        assert_eq!(index.uncompressed_count("d1").unwrap(), 1);
        let s = compress_stored(&ctx, Some("d1")).await.unwrap();
        assert_eq!((s.objects, s.failed), (1, 0), "{:?}", s.errors);
        assert!(s.bytes_after * 10 < s.bytes_before, "{s:?}");
        assert_eq!(index.uncompressed_count("d1").unwrap(), 0);
        let rep = &index.replicas_of(id).unwrap()[0];
        assert!(is_compressed_path(&rep.object_path));
        assert_eq!(rep.stored_size, s.bytes_after);
        let store = ctx.store("d1").unwrap();
        assert_eq!(store.get(&rep.object_path, true).await.unwrap(), raw);
        // The old object is gone, and the manifest names the new one with its size.
        let files = store.list_files(&store.root_prefix()).await.unwrap();
        assert!(!files.contains_key(&old_path), "{files:?}");
        let scan = store.scan().await.unwrap();
        let entry = scan.entries.iter().find(|(_, e)| e.sha256 == sha).unwrap();
        assert_eq!(entry.1.object_path, rep.object_path);
        assert_eq!(entry.1.stored_size, Some(rep.stored_size));
        // A quick check accepts it by its recorded size.
        let report = crate::verify::run_check(&ctx, &malo_api::CheckScope::All, false, false)
            .await
            .unwrap();
        assert!(report.destinations[0].ok, "{report:?}");
        assert_eq!(report.destinations[0].healthy, 1);
    }
}
