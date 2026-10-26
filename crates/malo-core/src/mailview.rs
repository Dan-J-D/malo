//! The IMAP view of a backed-up account, served to mail apps by malo-server: folders, stable IMAP
//! UIDs, flags changed in the mail app and cached header data. Nothing here touches the backups:
//! flags, expunges and moves from a mail app only change this view.

use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, ToSql};
use serde::{Deserialize, Serialize};

use crate::imap::GMAIL_CATEGORIES;
use crate::index::{join_list, split_list, Index};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderSource {
    /// A mailbox of the account (every UIDVALIDITY it ever had, so mail purged long ago is there too).
    Mailbox,
    /// A Gmail label: the messages of All Mail that carry it.
    Label(String),
    /// Gmail's inbox without the messages of its other categories.
    Primary,
    /// The inbox messages of one Gmail category (`social`, `promotions`, `updates`, `forums`).
    Category(String),
}

#[derive(Debug, Clone)]
pub struct Folder {
    /// Raw (modified UTF-7) name, as the account's server had it.
    pub name: String,
    pub delimiter: Option<String>,
    pub special_use: Option<String>,
    pub source: FolderSource,
}

/// What mail apps see of an account, chosen in the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewSettings {
    /// Gmail: INBOX holds Primary only, the other categories get folders of their own.
    #[serde(default = "yes")]
    pub split_categories: bool,
    /// Raw names of folders mail apps don't see (INBOX is always shown).
    #[serde(default)]
    pub hidden: Vec<String>,
}

fn yes() -> bool {
    true
}

impl Default for ViewSettings {
    fn default() -> Self {
        ViewSettings {
            split_categories: true,
            hidden: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ViewMessage {
    pub uid: u32,
    pub message: i64,
    pub flags: Vec<String>,
    pub size: u64,
    pub internaldate: Option<DateTime<Utc>>,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct FolderView {
    pub uidvalidity: u32,
    pub uidnext: u32,
    /// Ascending by UID.
    pub messages: Vec<ViewMessage>,
}

/// Parsed header data of a message, so header-only fetches don't download it again.
#[derive(Debug, Clone)]
pub struct ImapMeta {
    pub header: Vec<u8>,
    /// ENVELOPE, BODYSTRUCTURE and BODY in IMAP syntax (bytes: literals may hold 8-bit text).
    pub envelope: Vec<u8>,
    pub bodystructure: Vec<u8>,
    pub body: Vec<u8>,
}

/// Messages become visible once their content is stored somewhere.
const VISIBLE: &str = "g.state IN ('stored','verified') AND g.sha256 IS NOT NULL";

/// The folder a Gmail label is shown as; None for system labels without one.
fn label_folder(label: &str) -> Option<(String, Option<&'static str>)> {
    Some(match label {
        "\\Inbox" => ("INBOX".into(), None),
        "\\Sent" => ("[Gmail]/Sent Mail".into(), Some("\\Sent")),
        "\\Draft" => ("[Gmail]/Drafts".into(), Some("\\Drafts")),
        "\\Starred" => ("[Gmail]/Starred".into(), Some("\\Flagged")),
        "\\Important" => ("[Gmail]/Important".into(), Some("\\Important")),
        l if l.starts_with('\\') || l.is_empty() => return None,
        l => (l.to_string(), None),
    })
}

/// The folder of a Gmail category.
pub fn category_folder(category: &str) -> String {
    let mut name = category.to_string();
    if let Some(first) = name.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    format!("Categories/{name}")
}

const IN_LABEL: &str =
    "mb.special_use='\\All' AND instr(char(31)||m.gm_labels||char(31), char(31)||?3||char(31))>0";

/// Which memberships belong in a folder: an SQL condition over `m`, `mb` and `g` (with `?1` the
/// account and `?2` the folder name) and its further parameters from `?3` on.
fn belongs(source: &FolderSource) -> (String, Vec<String>) {
    match source {
        FolderSource::Mailbox => ("mb.name=?2".into(), vec![]),
        FolderSource::Label(l) => (IN_LABEL.into(), vec![l.clone()]),
        FolderSource::Primary => (
            format!("{IN_LABEL} AND g.category IS NULL"),
            vec!["\\Inbox".into()],
        ),
        FolderSource::Category(c) => (
            format!("{IN_LABEL} AND g.category=?4"),
            vec!["\\Inbox".into(), c.clone()],
        ),
    }
}

fn ensure_mailbox(c: &Connection, account: &str, name: &str) -> rusqlite::Result<(u32, u32)> {
    let existing: Option<(u32, u32)> = c
        .query_row(
            "SELECT uidvalidity, uidnext FROM imap_mailboxes WHERE account=?1 AND name=?2",
            params![account, name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match existing {
        Some(v) => Ok(v),
        None => {
            let v = rand::random::<u32>() % 0x7fff_fffe + 1;
            c.execute(
                "INSERT INTO imap_mailboxes(account, name, uidvalidity, uidnext) VALUES(?1,?2,?3,1)",
                params![account, name, v],
            )?;
            Ok((v, 1))
        }
    }
}

impl Index {
    pub fn imap_settings(&self, account: &str) -> anyhow::Result<ViewSettings> {
        Ok(self
            .kv_get(&format!("imap_view:{account}"))?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default())
    }

    pub fn set_imap_settings(&self, account: &str, s: &ViewSettings) -> anyhow::Result<()> {
        self.kv_set(&format!("imap_view:{account}"), &serde_json::to_string(s)?)
    }

    /// The folders mail apps see, as the account's settings choose them.
    pub fn imap_folders(&self, account: &str) -> anyhow::Result<Vec<Folder>> {
        let settings = self.imap_settings(account)?;
        Ok(self
            .imap_all_folders(account, &settings)?
            .into_iter()
            .filter(|f| f.name.eq_ignore_ascii_case("INBOX") || !settings.hidden.contains(&f.name))
            .collect())
    }

    /// Every folder of an account, shown or not: its mailboxes (current or not) and, for Gmail,
    /// its labels and categories. There is always an INBOX.
    pub fn imap_all_folders(
        &self,
        account: &str,
        settings: &ViewSettings,
    ) -> anyhow::Result<Vec<Folder>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT name, delimiter, special_use FROM mailboxes WHERE account=?1 ORDER BY name, current DESC",
            )?;
            let rows = stmt.query_map([account], |r| {
                Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
            })?;
            let mut out: Vec<Folder> = Vec::new();
            let mut all_delimiter = None;
            for row in rows {
                let (name, delimiter, special_use): (String, Option<String>, Option<String>) =
                    row?;
                if out.last().is_some_and(|f| f.name == name) {
                    continue;
                }
                if special_use.as_deref() == Some("\\All") {
                    all_delimiter = Some(delimiter.clone());
                }
                out.push(Folder {
                    name,
                    delimiter,
                    special_use,
                    source: FolderSource::Mailbox,
                });
            }
            if let Some(delimiter) = all_delimiter {
                let mut stmt = c.prepare(
                    "SELECT DISTINCT m.gm_labels FROM memberships m JOIN mailboxes mb ON mb.id=m.mailbox
                     WHERE mb.account=?1 AND mb.special_use='\\All' AND m.gm_labels<>''",
                )?;
                let mut labels = BTreeSet::new();
                for l in stmt.query_map([account], |r| r.get::<_, String>(0))? {
                    labels.extend(split_list(l?));
                }
                if settings.split_categories {
                    labels.insert("\\Inbox".into());
                }
                for label in labels {
                    let Some((name, special_use)) = label_folder(&label) else {
                        continue;
                    };
                    if out.iter().any(|f| f.name.eq_ignore_ascii_case(&name)) {
                        continue;
                    }
                    let source = if label == "\\Inbox" && settings.split_categories {
                        FolderSource::Primary
                    } else {
                        FolderSource::Label(label)
                    };
                    out.push(Folder {
                        name,
                        delimiter: delimiter.clone(),
                        special_use: special_use.map(Into::into),
                        source,
                    });
                }
                if settings.split_categories {
                    for c in GMAIL_CATEGORIES {
                        out.push(Folder {
                            name: category_folder(c),
                            delimiter: Some("/".into()),
                            special_use: None,
                            source: FolderSource::Category(c.into()),
                        });
                    }
                }
            }
            if !out.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")) {
                out.push(Folder {
                    name: "INBOX".into(),
                    delimiter: Some("/".into()),
                    special_use: None,
                    source: FolderSource::Mailbox,
                });
            }
            out.sort_by(|a, b| {
                let inbox = |f: &Folder| !f.name.eq_ignore_ascii_case("INBOX");
                (inbox(a), &a.name).cmp(&(inbox(b), &b.name))
            });
            Ok(out)
        })
    }

    /// The messages of a folder. Messages stored since the last call get the next UIDs (each
    /// message at most once per folder, also when it was found again under a new UIDVALIDITY).
    /// A message that left a label or category leaves its folder too, unless a mail app moved
    /// it there.
    pub fn imap_view(&self, account: &str, folder: &Folder) -> anyhow::Result<FolderView> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let (uidvalidity, mut uidnext) = ensure_mailbox(&tx, account, &folder.name)?;
            let (cond, extra) = belongs(&folder.source);
            let mut args: Vec<&dyn ToSql> = vec![&account, &folder.name];
            args.extend(extra.iter().map(|e| e as &dyn ToSql));
            if folder.source != FolderSource::Mailbox {
                tx.execute(
                    &format!(
                        "DELETE FROM imap_uids WHERE account=?1 AND mailbox=?2 AND moved=0 AND membership NOT IN
                           (SELECT m.id FROM memberships m JOIN mailboxes mb ON mb.id=m.mailbox
                            JOIN messages g ON g.id=m.message WHERE mb.account=?1 AND {cond})"
                    ),
                    args.as_slice(),
                )?;
            }
            let mut seen_msg = HashSet::new();
            let mut seen_sha = HashSet::new();
            {
                let mut stmt = tx.prepare(
                    "SELECT g.id, g.sha256 FROM imap_uids i JOIN memberships m ON m.id=i.membership
                     JOIN messages g ON g.id=m.message WHERE i.account=?1 AND i.mailbox=?2",
                )?;
                let rows = stmt.query_map(params![account, folder.name], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
                })?;
                for row in rows {
                    let (id, sha) = row?;
                    seen_msg.insert(id);
                    seen_sha.extend(sha);
                }
            }
            let candidates: Vec<(i64, i64, String)> = {
                let mut stmt = tx.prepare(&format!(
                    "SELECT m.id, g.id, g.sha256 FROM memberships m JOIN mailboxes mb ON mb.id=m.mailbox
                     JOIN messages g ON g.id=m.message
                     WHERE mb.account=?1 AND {cond} AND {VISIBLE}
                       AND NOT EXISTS (SELECT 1 FROM imap_uids i WHERE i.account=?1 AND i.mailbox=?2 AND i.membership=m.id)
                     ORDER BY g.internaldate IS NULL, g.internaldate, m.id"
                ))?;
                let rows = stmt
                    .query_map(args.as_slice(), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<_, _>>()?;
                rows
            };
            let first_new = uidnext;
            {
                let mut insert = tx.prepare(
                    "INSERT INTO imap_uids(account, mailbox, uid, membership) VALUES(?1,?2,?3,?4)",
                )?;
                for (membership, message, sha) in candidates {
                    if !seen_msg.insert(message) || !seen_sha.insert(sha) {
                        continue;
                    }
                    insert.execute(params![account, folder.name, uidnext, membership])?;
                    uidnext += 1;
                }
            }
            if uidnext != first_new {
                tx.execute(
                    "UPDATE imap_mailboxes SET uidnext=?3 WHERE account=?1 AND name=?2",
                    params![account, folder.name, uidnext],
                )?;
            }
            let messages = {
                let mut stmt = tx.prepare(
                    "SELECT i.uid, g.id, coalesce(i.flags, m.flags), g.size, g.internaldate, g.sha256
                     FROM imap_uids i JOIN memberships m ON m.id=i.membership JOIN messages g ON g.id=m.message
                     WHERE i.account=?1 AND i.mailbox=?2 AND i.hidden=0 AND g.sha256 IS NOT NULL
                     ORDER BY i.uid",
                )?;
                let rows = stmt
                    .query_map(params![account, folder.name], |r| {
                        Ok(ViewMessage {
                            uid: r.get(0)?,
                            message: r.get(1)?,
                            flags: split_list(r.get(2)?),
                            size: r.get::<_, i64>(3)? as u64,
                            internaldate: r
                                .get::<_, Option<String>>(4)?
                                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                                .map(|d| d.with_timezone(&Utc)),
                            sha256: r.get(5)?,
                        })
                    })?
                    .collect::<Result<_, _>>()?;
                rows
            };
            tx.commit()?;
            Ok(FolderView {
                uidvalidity,
                uidnext,
                messages,
            })
        })
    }

    /// A mail app moved (or copied) messages to another folder: they get new UIDs there, keep
    /// their flags, and leave the source folder unless `copy`. Returns the new UIDs.
    pub fn imap_place(
        &self,
        account: &str,
        from: &str,
        uids: &[u32],
        to: &str,
        copy: bool,
    ) -> anyhow::Result<Vec<u32>> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let (_, mut uidnext) = ensure_mailbox(&tx, account, to)?;
            let mut placed = vec![];
            for uid in uids {
                let row: Option<(i64, i64, Option<String>)> = tx
                    .query_row(
                        "SELECT i.membership, m.message, coalesce(i.flags, m.flags) FROM imap_uids i
                         JOIN memberships m ON m.id=i.membership
                         WHERE i.account=?1 AND i.mailbox=?2 AND i.uid=?3",
                        params![account, from, uid],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let Some((membership, message, flags)) = row else {
                    continue;
                };
                // Whatever the target showed of this message before goes: it reappears under a
                // new UID, which mail apps notice.
                tx.execute(
                    "DELETE FROM imap_uids WHERE account=?1 AND mailbox=?2
                       AND membership IN (SELECT id FROM memberships WHERE message=?3)",
                    params![account, to, message],
                )?;
                tx.execute(
                    "INSERT INTO imap_uids(account, mailbox, uid, membership, flags, moved) VALUES(?1,?2,?3,?4,?5,1)",
                    params![account, to, uidnext, membership, flags],
                )?;
                placed.push(uidnext);
                uidnext += 1;
                if !copy {
                    tx.execute(
                        "UPDATE imap_uids SET hidden=1 WHERE account=?1 AND mailbox=?2 AND uid=?3",
                        params![account, from, uid],
                    )?;
                }
            }
            tx.execute(
                "UPDATE imap_mailboxes SET uidnext=?3 WHERE account=?1 AND name=?2",
                params![account, to, uidnext],
            )?;
            tx.commit()?;
            Ok(placed)
        })
    }

    /// Stores the flags a mail app set (they replace the server's flags in this view).
    pub fn imap_set_flags(
        &self,
        account: &str,
        folder: &str,
        changes: &[(u32, Vec<String>)],
    ) -> anyhow::Result<()> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare(
                    "UPDATE imap_uids SET flags=?4 WHERE account=?1 AND mailbox=?2 AND uid=?3",
                )?;
                for (uid, flags) in changes {
                    stmt.execute(params![account, folder, uid, join_list(flags)])?;
                }
            }
            tx.commit()
        })
    }

    /// Expunged in a mail app: hidden from this folder of the view, never deleted from the backup.
    pub fn imap_hide(&self, account: &str, folder: &str, uids: &[u32]) -> anyhow::Result<()> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare(
                    "UPDATE imap_uids SET hidden=1 WHERE account=?1 AND mailbox=?2 AND uid=?3",
                )?;
                for uid in uids {
                    stmt.execute(params![account, folder, uid])?;
                }
            }
            tx.commit()
        })
    }

    /// Forgets the view of an account (hidden messages and changed flags). Folders get a new
    /// UIDVALIDITY, so mail apps download the folder lists again.
    pub fn imap_reset(&self, account: &str) -> anyhow::Result<()> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            tx.execute("DELETE FROM imap_uids WHERE account=?1", [account])?;
            tx.execute("DELETE FROM imap_mailboxes WHERE account=?1", [account])?;
            tx.commit()
        })
    }

    pub fn imap_meta(&self, sha256: &str) -> anyhow::Result<Option<ImapMeta>> {
        self.with(|c| {
            c.query_row(
                "SELECT header, envelope, bodystructure, body FROM imap_meta WHERE sha256=?1",
                [sha256],
                |r| {
                    Ok(ImapMeta {
                        header: r.get(0)?,
                        envelope: r.get(1)?,
                        bodystructure: r.get(2)?,
                        body: r.get(3)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn put_imap_meta(&self, sha256: &str, m: &ImapMeta) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR REPLACE INTO imap_meta(sha256, header, envelope, bodystructure, body) VALUES(?1,?2,?3,?4,?5)",
                params![sha256, m.header, m.envelope, m.bodystructure, m.body],
            )
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::NewMessage;
    use malo_api::MessageState;

    fn add(ix: &Index, mailbox: i64, uid: u32, sha: &str, labels: &[&str]) -> i64 {
        let env = crate::index::empty_envelope();
        let id = ix
            .insert_message(&NewMessage {
                account: "a",
                run: None,
                size: 10,
                internaldate: None,
                message_id_hdr: None,
                gm_msgid: None,
                envelope: &env,
                state: MessageState::Verified,
                sha256: Some(sha),
            })
            .unwrap();
        let labels: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
        ix.add_membership(id, mailbox, uid, &["\\Seen".into()], &labels)
            .unwrap();
        id
    }

    #[test]
    fn uids_are_stable_and_ascending() {
        let ix = Index::open_in_memory().unwrap();
        let old = ix
            .upsert_mailbox("a", "Work", "Work", "Work", Some("/"), None, 1)
            .unwrap();
        let m0 = add(&ix, old.id, 5, "s1", &[]);
        // The server changed UIDVALIDITY: the same message is found again, plus a new one.
        let new = ix
            .upsert_mailbox("a", "Work", "Work", "Work", Some("/"), None, 2)
            .unwrap();
        let m1 = add(&ix, new.id, 1, "s1", &[]);
        let folders = ix.imap_folders("a").unwrap();
        let work = folders.iter().find(|f| f.name == "Work").unwrap();
        assert!(folders.iter().any(|f| f.name == "INBOX"));
        let v = ix.imap_view("a", work).unwrap();
        assert_eq!(v.messages.len(), 1, "a message found twice shows once");
        add(&ix, new.id, 2, "s2", &[]);
        let v2 = ix.imap_view("a", work).unwrap();
        assert_eq!(v2.uidvalidity, v.uidvalidity);
        assert_eq!(
            v2.messages.iter().map(|m| m.uid).collect::<Vec<_>>(),
            vec![1, 2]
        );
        ix.imap_set_flags("a", "Work", &[(1, vec!["\\Flagged".into()])])
            .unwrap();
        ix.imap_hide("a", "Work", &[2]).unwrap();
        let v3 = ix.imap_view("a", work).unwrap();
        assert_eq!(v3.messages.len(), 1);
        assert_eq!(v3.messages[0].flags, vec!["\\Flagged".to_string()]);
        // Deleting a message from the backup removes it from the view.
        ix.forget_messages(&[m0, m1]).unwrap();
        assert!(ix.imap_view("a", work).unwrap().messages.is_empty());
        ix.imap_reset("a").unwrap();
        let v4 = ix.imap_view("a", work).unwrap();
        assert_eq!(v4.messages.len(), 1, "reset shows hidden mail again");
        assert_eq!(v4.messages[0].uid, 1);
    }

    #[test]
    fn gmail_labels_and_categories_become_folders() {
        let ix = Index::open_in_memory().unwrap();
        let all = ix
            .upsert_mailbox(
                "a",
                "[Gmail]/All Mail",
                "All Mail",
                "x",
                Some("/"),
                Some("\\All"),
                1,
            )
            .unwrap();
        ix.upsert_mailbox(
            "a",
            "[Gmail]/Spam",
            "Spam",
            "y",
            Some("/"),
            Some("\\Junk"),
            1,
        )
        .unwrap();
        let primary = add(&ix, all.id, 1, "s1", &["\\Inbox", "Work"]);
        add(&ix, all.id, 2, "s2", &["\\Sent"]);
        add(&ix, all.id, 3, "s3", &["\\Inbox"]);
        let mut found = std::collections::HashMap::new();
        found.insert(3u32, "social");
        assert_eq!(ix.set_categories(all.id, 1, &found).unwrap(), 1);

        let folders = ix.imap_folders("a").unwrap();
        let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "INBOX",
                "Categories/Forums",
                "Categories/Promotions",
                "Categories/Social",
                "Categories/Updates",
                "Work",
                "[Gmail]/All Mail",
                "[Gmail]/Sent Mail",
                "[Gmail]/Spam"
            ]
        );
        let get = |name: &str| folders.iter().find(|f| f.name == name).unwrap().clone();
        let count = |name: &str| ix.imap_view("a", &get(name)).unwrap().messages.len();
        assert_eq!(count("INBOX"), 1, "only Primary");
        assert_eq!(count("Categories/Social"), 1);
        assert_eq!(count("[Gmail]/Sent Mail"), 1);
        assert_eq!(get("[Gmail]/Spam").special_use.as_deref(), Some("\\Junk"));

        // Gmail moved it to Primary: it leaves Social and joins INBOX under a new UID.
        ix.set_categories(all.id, 1, &Default::default()).unwrap();
        assert_eq!(count("Categories/Social"), 0);
        let inbox = ix.imap_view("a", &get("INBOX")).unwrap();
        assert_eq!(
            inbox.messages.iter().map(|m| m.uid).collect::<Vec<_>>(),
            vec![1, 2]
        );

        // Filed into Social in a mail app: it stays there, whatever Gmail says.
        let placed = ix
            .imap_place("a", "INBOX", &[1], "Categories/Social", false)
            .unwrap();
        assert_eq!(placed.len(), 1);
        assert_eq!(count("INBOX"), 1);
        let social = ix.imap_view("a", &get("Categories/Social")).unwrap();
        assert_eq!(social.messages[0].message, primary);
        assert_eq!(count("Categories/Social"), 1);

        // One view: no categories, Spam hidden.
        ix.set_imap_settings(
            "a",
            &ViewSettings {
                split_categories: false,
                hidden: vec!["[Gmail]/Spam".into(), "INBOX".into()],
            },
        )
        .unwrap();
        let folders = ix.imap_folders("a").unwrap();
        let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["INBOX", "Work", "[Gmail]/All Mail", "[Gmail]/Sent Mail"],
            "INBOX can't be hidden"
        );
        // Both inbox messages, except the one the mail app moved out of INBOX.
        let inbox = ix.imap_view("a", &folders[0]).unwrap();
        assert_eq!(inbox.messages.len(), 1);
        assert_ne!(inbox.messages[0].message, primary);
    }
}
