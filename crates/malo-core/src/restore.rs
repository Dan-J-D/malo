//! Restoring backed-up mail to a mail account with `IMAP APPEND`: after a mailbox was lost or
//! wiped, to move mail to a new provider, or to bring back mail that was purged.
//!
//! Each message is read from the spool or a verified replica (hash-checked), and uploaded with its
//! flags and received date. Messages already in the target mailbox (same Message-ID) are skipped,
//! so a restore can be run again after an interruption.

use std::collections::HashMap;

use anyhow::Context;
use malo_api::{RestoreSelection, RestoreSummary, RestoreTarget};

use crate::config::Account;
use crate::ctx::JobCtx;
use crate::imap::{self, MailboxListing};
use crate::index::{MailboxRow, MembershipRow, MessageRow};
use crate::store::Store;
use crate::sync;

/// Most messages one restore takes.
pub const MAX_RESTORE: usize = 200_000;

/// The ids a selection stands for.
pub fn resolve(ctx: &JobCtx, selection: &RestoreSelection) -> anyhow::Result<Vec<i64>> {
    let mut ids = match selection {
        RestoreSelection::Messages { ids } => ids.clone(),
        RestoreSelection::Search { query, account_id } => {
            ctx.index
                .matching_ids(account_id.as_deref(), query, MAX_RESTORE + 1)?
        }
        RestoreSelection::Account {
            account_id,
            mailbox,
        } => ctx
            .index
            .account_message_ids(account_id, mailbox.as_deref())?,
    };
    ids.sort_unstable();
    ids.dedup();
    anyhow::ensure!(
        ids.len() <= MAX_RESTORE,
        "a restore takes at most {MAX_RESTORE} messages; restore fewer at a time"
    );
    Ok(ids)
}

pub async fn run_restore(
    ctx: &JobCtx,
    target_account_id: &str,
    selection: &RestoreSelection,
    target: &RestoreTarget,
) -> anyhow::Result<RestoreSummary> {
    let account = ctx.account(target_account_id)?.clone();
    check_target(&account)?;
    if let RestoreTarget::Folder { name } = target {
        check_folder_name(name)?;
    }
    let ids = resolve(ctx, selection)?;
    let stores = ctx.stores()?;
    let mut summary = RestoreSummary {
        target_account_id: account.id.clone(),
        ..Default::default()
    };
    let total = ids.len() as u64;
    ctx.progress(0, total, format!("restoring to {}", account.name));
    let mut conn = imap::connect(&account, ctx.tokens.as_ref()).await?;
    let mut listing = conn.list_mailboxes().await?;
    let mut selected: Option<String> = None;
    let mut mailbox_rows: HashMap<i64, Option<MailboxRow>> = HashMap::new();
    for (n, id) in ids.iter().enumerate() {
        if n % 10 == 0 {
            ctx.check_cancel()?;
            ctx.progress(n as u64, total, format!("restoring to {}", account.name));
        }
        let Some(msg) = ctx.index.message(*id)? else {
            summary.failed += 1;
            push_error(
                &mut summary,
                format!("message {id} is no longer in the backup"),
            );
            continue;
        };
        let memberships = ctx.index.memberships(msg.id)?;
        let mut source: Option<MailboxRow> = None;
        if let Some(first) = memberships.first() {
            source = mailbox_rows
                .entry(first.mailbox)
                .or_insert_with(|| ctx.index.mailbox(first.mailbox).ok().flatten())
                .clone();
        }
        let mailbox = match target {
            RestoreTarget::Folder { name } => name.clone(),
            RestoreTarget::Original => {
                original_mailbox(source.as_ref(), memberships.first(), &listing)
            }
        };
        let one = restore_one(
            ctx,
            &mut conn,
            &mut listing,
            &mut selected,
            &stores,
            &msg,
            memberships.first(),
            &mailbox,
        )
        .await;
        match one {
            Ok(true) => summary.restored += 1,
            Ok(false) => summary.skipped += 1,
            Err(e) => {
                summary.failed += 1;
                push_error(&mut summary, format!("{}: {e:#}", msg.envelope.subject));
                // The connection may be broken: start over with a new one.
                if e.downcast_ref::<std::io::Error>().is_some() || conn.noop().await.is_err() {
                    conn = imap::connect(&account, ctx.tokens.as_ref()).await?;
                    listing = conn.list_mailboxes().await?;
                    selected = None;
                }
            }
        }
    }
    conn.logout().await;
    ctx.progress(total, total, "done");
    ctx.index.audit(
        "restored_to_imap",
        Some(&account.id),
        &serde_json::json!({
            "restored": summary.restored,
            "skipped": summary.skipped,
            "failed": summary.failed,
        }),
    )?;
    Ok(summary)
}

fn push_error(summary: &mut RestoreSummary, e: String) {
    if summary.errors.len() < 50 {
        summary.errors.push(e);
    }
}

/// A folder name the user typed: something a mail server can take.
pub fn check_folder_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!name.trim().is_empty(), "enter a folder to restore into");
    anyhow::ensure!(name.len() <= 200, "the folder name is too long");
    anyhow::ensure!(
        !name.chars().any(|c| c.is_control() || c == '*' || c == '%'),
        "the folder name can't contain control characters, * or %"
    );
    Ok(())
}

/// The mailbox of the target server a message goes back to: the one with the same role (Sent,
/// Drafts, Junk, Trash, Archive), the same name, or for Gmail's All Mail the label it had.
fn original_mailbox(
    source: Option<&MailboxRow>,
    membership: Option<&MembershipRow>,
    target: &[MailboxListing],
) -> String {
    let by_role = |role: &str| {
        target
            .iter()
            .find(|m| m.special_use.as_deref() == Some(role) && m.selectable)
            .map(|m| m.name.clone())
    };
    let Some(src) = source else {
        return "INBOX".into();
    };
    if src.special_use.as_deref() == Some("\\All") {
        let labels = membership.map(|m| m.gm_labels.as_slice()).unwrap_or(&[]);
        let has = |l: &str| labels.iter().any(|x| x.eq_ignore_ascii_case(l));
        if has("\\Inbox") {
            return "INBOX".into();
        }
        for (label, role) in [("\\Sent", "\\Sent"), ("\\Draft", "\\Drafts")] {
            if has(label) {
                if let Some(m) = by_role(role) {
                    return m;
                }
            }
        }
        if let Some(l) = labels
            .iter()
            .find(|l| !l.starts_with('\\') && !l.is_empty())
        {
            return l.clone();
        }
        return by_role("\\Archive")
            .or_else(|| by_role("\\All"))
            .unwrap_or_else(|| "Archive".into());
    }
    if let Some(role) = src.special_use.as_deref() {
        if let Some(m) = by_role(role) {
            return m;
        }
    }
    if src.name.eq_ignore_ascii_case("INBOX") {
        return "INBOX".into();
    }
    src.name.clone()
}

/// Uploads one message unless the mailbox already has it. True when uploaded.
#[allow(clippy::too_many_arguments)]
async fn restore_one(
    ctx: &JobCtx,
    conn: &mut imap::ImapConn,
    listing: &mut Vec<MailboxListing>,
    selected: &mut Option<String>,
    stores: &[Store],
    msg: &MessageRow,
    membership: Option<&MembershipRow>,
    mailbox: &str,
) -> anyhow::Result<bool> {
    if !listing.iter().any(|m| m.name == mailbox) && !mailbox.eq_ignore_ascii_case("INBOX") {
        conn.create_if_missing(mailbox, listing).await?;
        *listing = conn.list_mailboxes().await?;
    }
    if selected.as_deref() != Some(mailbox) {
        conn.select(mailbox)
            .await
            .with_context(|| format!("cannot open {mailbox}"))?;
        *selected = Some(mailbox.to_string());
    }
    if let Some(mid) = msg.message_id_hdr.as_deref() {
        if let Some(uids) = conn.uids_by_message_id(mid).await? {
            if !uids.is_empty() {
                return Ok(false);
            }
        }
    }
    let raw = read_message(ctx, stores, msg)
        .await
        .ok_or_else(|| anyhow::anyhow!("no readable copy in the spool or on any destination"))?;
    let flags = membership.map(|m| m.flags.clone()).unwrap_or_default();
    conn.append(mailbox, &flags, msg.internaldate, &raw).await?;
    Ok(true)
}

/// The message's content, from the spool or a verified replica, matching its hash.
pub(crate) async fn read_message(
    ctx: &JobCtx,
    stores: &[Store],
    msg: &MessageRow,
) -> Option<Vec<u8>> {
    let sha = msg.sha256.as_deref()?;
    if let Some(raw) = ctx.spool_get(msg.id) {
        if crate::crypto::sha256_hex(&raw) == sha {
            return Some(raw);
        }
    }
    sync::copy_from_replica(ctx, msg, stores).await
}

/// The account a restore goes to must be usable now.
pub fn check_target(account: &Account) -> anyhow::Result<()> {
    anyhow::ensure!(
        !account.imported,
        "\"{}\" has no mail server to restore to: sign it in again under Accounts",
        account.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(name: &str, role: Option<&str>) -> MailboxListing {
        MailboxListing {
            name: name.into(),
            delimiter: Some("/".into()),
            special_use: role.map(str::to_string),
            selectable: true,
        }
    }

    fn mailbox(name: &str, role: Option<&str>) -> MailboxRow {
        MailboxRow {
            id: 1,
            account: "a".into(),
            name: name.into(),
            display: name.into(),
            path: name.into(),
            delimiter: Some("/".into()),
            special_use: role.map(str::to_string),
            uidvalidity: 1,
            highest_uid: 0,
            highestmodseq: None,
            current: true,
        }
    }

    fn member(labels: &[&str]) -> MembershipRow {
        MembershipRow {
            id: 1,
            message: 1,
            mailbox: 1,
            uid: 1,
            flags: vec![],
            gm_labels: labels.iter().map(|l| l.to_string()).collect(),
            deleted_on_server: false,
        }
    }

    #[test]
    fn original_mailboxes_follow_roles_and_labels() {
        let target = [
            listing("INBOX", None),
            listing("Sent Items", Some("\\Sent")),
            listing("Archive", Some("\\Archive")),
        ];
        let gmail_all = mailbox("[Gmail]/All Mail", Some("\\All"));
        let m = |l: &[&str]| original_mailbox(Some(&gmail_all), Some(&member(l)), &target);
        assert_eq!(m(&["\\Inbox", "Work"]), "INBOX");
        assert_eq!(m(&["\\Sent"]), "Sent Items");
        assert_eq!(m(&["\\Important", "Work/Projects"]), "Work/Projects");
        assert_eq!(m(&[]), "Archive");
        let sent = mailbox("[Gmail]/Sent Mail", Some("\\Sent"));
        assert_eq!(original_mailbox(Some(&sent), None, &target), "Sent Items");
        let drafts = mailbox("Drafts", Some("\\Drafts"));
        assert_eq!(original_mailbox(Some(&drafts), None, &target), "Drafts");
        assert_eq!(
            original_mailbox(Some(&mailbox("inbox", None)), None, &target),
            "INBOX"
        );
        assert_eq!(original_mailbox(None, None, &target), "INBOX");
    }

    #[test]
    fn folder_names() {
        assert!(check_folder_name("Restored/2026").is_ok());
        for bad in ["", "  ", "a\r\nb", "x*", "%"] {
            assert!(check_folder_name(bad).is_err(), "{bad:?}");
        }
    }
}
