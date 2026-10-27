//! "Spam" and "Not spam" on the mail server: messages marked spam in Malo move into the server's
//! Junk folder, ones marked not spam move from Junk back to the inbox, so the server (and its
//! spam filter) learns the same. The backup is never touched; only the index learns where the
//! message is now, so it doesn't look deleted or come back as a second copy.

use std::collections::BTreeMap;

use anyhow::anyhow;
use malo_api::{PurgeSummary, SpamSummary};

use crate::ctx::JobCtx;
use crate::imap::{self, ImapConn, MailboxListing};
use crate::index::{MailboxRow, MessageRow};
use crate::layout;

/// Moves the messages that are still on the account's server. Messages already where they
/// belong, or gone from the server, are skipped: Malo marked them already.
pub async fn move_on_server(
    ctx: &JobCtx,
    account_id: &str,
    ids: &[i64],
    spam: bool,
) -> anyhow::Result<SpamSummary> {
    let account = ctx.account(account_id)?.clone();
    let mut summary = SpamSummary {
        account_id: account.id.clone(),
        spam,
        ..Default::default()
    };
    if account.imported {
        return Ok(summary);
    }
    let mut conn = imap::connect(&account, ctx.tokens.as_ref()).await?;
    let result = run(ctx, &account.id, &mut conn, ids, spam, &mut summary).await;
    conn.logout().await;
    result?;
    Ok(summary)
}

async fn run(
    ctx: &JobCtx,
    account: &str,
    conn: &mut ImapConn,
    ids: &[i64],
    spam: bool,
    summary: &mut SpamSummary,
) -> anyhow::Result<()> {
    let listing = conn.list_mailboxes().await?;
    let gmail = conn.caps.gmail();
    let junk = junk_folder(&listing).ok_or_else(|| {
        anyhow!("the mail server has no Junk or Spam folder; the messages are marked as spam in Malo only")
    })?;
    let inbox = listing
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case("INBOX"))
        .cloned()
        .ok_or_else(|| anyhow!("the mail server has no INBOX"))?;
    let target = if spam { &junk } else { &inbox };
    // Where Malo keeps track of the message afterwards: Gmail's inbox is a label of All Mail,
    // which is what Malo backs up.
    let track = if gmail && !spam {
        listing
            .iter()
            .find(|m| m.special_use.as_deref() == Some("\\All"))
            .cloned()
            .ok_or_else(|| anyhow!("Gmail All Mail folder not found"))?
    } else {
        target.clone()
    };

    // Each message's copies on the server that have to move: into Junk from anywhere else, or
    // out of Junk into the inbox.
    let mut groups: BTreeMap<i64, (MailboxRow, Vec<(u32, MessageRow)>)> = BTreeMap::new();
    for id in ids {
        let Some(msg) = ctx.index.message(*id)? else {
            summary.skipped += 1;
            continue;
        };
        if msg.account != account {
            summary.skipped += 1;
            continue;
        }
        let mut any = false;
        for m in ctx.index.memberships(*id)? {
            if m.deleted_on_server {
                continue;
            }
            let Some(mb) = ctx.index.mailbox(m.mailbox)?.filter(|b| b.current) else {
                continue;
            };
            if (mb.name == junk.name) == spam {
                continue;
            }
            any = true;
            groups
                .entry(mb.id)
                .or_insert_with(|| (mb.clone(), vec![]))
                .1
                .push((m.uid, msg.clone()));
        }
        if !any {
            summary.skipped += 1;
        }
    }

    let mut moved: Vec<(MessageRow, Vec<String>)> = Vec::new();
    for (mb, items) in groups.values() {
        ctx.check_cancel()?;
        let sel = conn.select(&mb.name).await?;
        if sel.uidvalidity != mb.uidvalidity {
            summary.errors.push(format!(
                "{}: the folder was recreated on the server; its messages were not moved",
                mb.display
            ));
            summary.skipped += items.len() as u64;
            continue;
        }
        // Only UIDs that are still exactly the message Malo has (see purge).
        let refs: Vec<(u32, &MessageRow)> = items.iter().map(|(u, m)| (*u, m)).collect();
        let mut check = PurgeSummary {
            account_id: account.to_string(),
            deleted: 0,
            bytes: 0,
            skipped: 0,
            errors: vec![],
        };
        let ok = crate::purge::confirm_identity(conn, false, &refs, &mut check).await?;
        summary.skipped += check.skipped;
        summary.errors.extend(check.errors);
        if ok.is_empty() {
            continue;
        }
        let uids: Vec<u32> = ok.iter().map(|(u, _)| *u).collect();
        conn.move_or_copy(&uids, &target.name).await?;
        ctx.index.mark_deleted_on_server(mb.id, &uids, false)?;
        for (uid, msg) in &ok {
            ctx.index.audit(
                if spam {
                    "moved_to_spam"
                } else {
                    "moved_from_spam"
                },
                Some(account),
                &serde_json::json!({
                    "message": msg.id, "from_mailbox": mb.display, "uid": uid,
                    "to_mailbox": layout::decode_utf7(&target.name),
                    "subject": msg.envelope.subject, "from": msg.envelope.from,
                }),
            )?;
            let flags = ctx
                .index
                .find_membership(mb.id, *uid)?
                .map(|m| m.flags)
                .unwrap_or_default();
            moved.push(((*msg).clone(), flags));
        }
        summary.moved += ok.len() as u64;
    }
    if moved.is_empty() {
        return Ok(());
    }

    // Where the messages are now, so the index has them there rather than as purged.
    if let Err(e) = relocate(ctx, account, conn, &track, &moved).await {
        tracing::warn!(account, "finding moved messages: {e:#}");
    }
    ctx.events.emit(malo_api::SyncEvent::AccountsChanged);
    Ok(())
}

/// The server's Junk folder: the one it marks `\Junk`, or one named like it.
fn junk_folder(listing: &[MailboxListing]) -> Option<MailboxListing> {
    let rows: Vec<crate::mailview::MailboxRole> = listing
        .iter()
        .enumerate()
        .filter(|(_, m)| m.selectable)
        .map(|(i, m)| {
            (
                i as i64,
                m.name.clone(),
                m.delimiter.clone(),
                m.special_use.clone(),
            )
        })
        .collect();
    let i = *crate::mailview::role_mailboxes(&rows, "\\Junk").first()?;
    listing.get(i as usize).cloned()
}

/// Records each moved message's new UID in `track` (found by Gmail id or Message-ID). One that
/// can't be found is picked up by the next backup.
async fn relocate(
    ctx: &JobCtx,
    account: &str,
    conn: &mut ImapConn,
    track: &MailboxListing,
    moved: &[(MessageRow, Vec<String>)],
) -> anyhow::Result<()> {
    let sel = conn.select(&track.name).await?;
    let mb = ctx.index.upsert_mailbox(
        account,
        &track.name,
        &layout::decode_utf7(&track.name),
        &layout::mailbox_path(&track.name, track.delimiter.as_deref()),
        track.delimiter.as_deref(),
        track.special_use.as_deref(),
        sel.uidvalidity,
    )?;
    for (msg, flags) in moved {
        let candidates = match (&msg.gm_msgid, &msg.message_id_hdr) {
            (Some(gm), _) => match gm.parse::<u64>() {
                Ok(g) => conn
                    .uids_by_gm_msgid(&[g])
                    .await?
                    .values()
                    .copied()
                    .collect(),
                Err(_) => vec![],
            },
            (None, Some(id)) => conn.uids_by_message_id(id).await?.unwrap_or_default(),
            (None, None) => vec![],
        };
        // The newest UID Malo doesn't know yet: a copy that was there before has an older one.
        let mut fresh = None;
        for uid in candidates.into_iter().rev() {
            if ctx.index.find_membership(mb.id, uid)?.is_none() {
                fresh = Some(uid);
                break;
            }
        }
        if let Some(uid) = fresh {
            ctx.index.add_membership(msg.id, mb.id, uid, flags, &[])?;
        }
    }
    Ok(())
}
