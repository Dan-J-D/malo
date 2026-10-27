//! Collections: messages grouped by hand, across accounts and folders. They live in the index
//! only (the mail servers never see them), are listed in the backup manifests so a rebuild brings
//! them back, and can be shown to mail apps as folders under `Collections/`.

use std::collections::BTreeSet;

use malo_api::Collection;
use rusqlite::{params, Connection, OptionalExtension};

use crate::index::{split_list, Index};

/// Most collections a user can have.
pub const MAX_COLLECTIONS: usize = 500;

/// Checks and tidies a collection name: 1–80 characters, without `/`, `"` or invisible ones (it
/// becomes a folder name and is written in searches as `tag:"name"`).
pub fn clean_name(name: &str) -> Result<String, &'static str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err("name: 1–80 characters");
    }
    if name
        .chars()
        .any(|c| crate::layout::is_invisible(c) || c.is_control() || c == '/' || c == '"')
    {
        return Err("the name can't contain /, \" or invisible characters");
    }
    Ok(name.to_string())
}

/// The (modified UTF-7) folder a collection shows as in mail apps.
pub fn folder_name(name: &str) -> String {
    format!("Collections/{}", crate::layout::encode_utf7(name))
}

const SELECT: &str = "SELECT c.id, c.name, c.mail_folder,
    (SELECT COUNT(*) FROM collection_members cm WHERE cm.collection=c.id) FROM collections c";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Collection> {
    Ok(Collection {
        id: r.get(0)?,
        name: r.get(1)?,
        mail_folder: r.get(2)?,
        count: r.get::<_, i64>(3)? as u64,
    })
}

fn get(c: &Connection, id: &str) -> rusqlite::Result<Option<Collection>> {
    c.query_row(&format!("{SELECT} WHERE c.id=?1"), [id], row)
        .optional()
}

/// Accounts with messages in a collection.
fn accounts_of(c: &Connection, id: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = c.prepare(
        "SELECT DISTINCT g.account FROM collection_members cm JOIN messages g ON g.id=cm.message
         WHERE cm.collection=?1",
    )?;
    let rows = stmt.query_map([id], |r| r.get(0))?;
    rows.collect()
}

/// Forgets what mail apps were shown of a collection's folder: it is gone or has a new name.
fn forget_folder(c: &Connection, name: &str) -> rusqlite::Result<()> {
    c.execute(
        "DELETE FROM imap_uids WHERE mailbox=?1",
        [folder_name(name)],
    )?;
    Ok(())
}

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..16].to_string()
}

#[derive(Debug, PartialEq, Eq)]
pub enum CollectionError {
    Invalid(&'static str),
    NameTaken,
    TooMany,
    NotFound,
}

impl std::fmt::Display for CollectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CollectionError::Invalid(e) => e,
            CollectionError::NameTaken => "a collection with this name exists",
            CollectionError::TooMany => "at most 500 collections",
            CollectionError::NotFound => "collection not found",
        })
    }
}

impl Index {
    /// Every collection, by name.
    pub fn collections(&self) -> anyhow::Result<Vec<Collection>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!("{SELECT} ORDER BY c.name COLLATE NOCASE"))?;
            let rows = stmt.query_map([], row)?;
            rows.collect()
        })
    }

    pub fn collection(&self, id: &str) -> anyhow::Result<Option<Collection>> {
        self.with(|c| get(c, id))
    }

    pub fn create_collection(
        &self,
        name: &str,
        mail_folder: bool,
    ) -> anyhow::Result<Result<Collection, CollectionError>> {
        let name = match clean_name(name) {
            Ok(n) => n,
            Err(e) => return Ok(Err(CollectionError::Invalid(e))),
        };
        self.with(|c| {
            let n: i64 = c.query_row("SELECT COUNT(*) FROM collections", [], |r| r.get(0))?;
            if n as usize >= MAX_COLLECTIONS {
                return Ok(Err(CollectionError::TooMany));
            }
            let id = new_id();
            let added = c.execute(
                "INSERT OR IGNORE INTO collections(id, name, mail_folder, created_at)
                 VALUES(?1,?2,?3,?4)",
                params![id, name, mail_folder, chrono::Utc::now().to_rfc3339()],
            )?;
            if added == 0 {
                return Ok(Err(CollectionError::NameTaken));
            }
            Ok(get(c, &id)?.ok_or(CollectionError::NotFound))
        })
    }

    /// Renames a collection or shows/hides it in mail apps. Returns it with the accounts whose
    /// manifests list it under its old name.
    pub fn update_collection(
        &self,
        id: &str,
        name: &str,
        mail_folder: bool,
    ) -> anyhow::Result<Result<(Collection, Vec<String>), CollectionError>> {
        let name = match clean_name(name) {
            Ok(n) => n,
            Err(e) => return Ok(Err(CollectionError::Invalid(e))),
        };
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let Some(old) = get(&tx, id)? else {
                return Ok(Err(CollectionError::NotFound));
            };
            let taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM collections WHERE name=?1 COLLATE NOCASE AND id<>?2)",
                params![name, id],
                |r| r.get(0),
            )?;
            if taken {
                return Ok(Err(CollectionError::NameTaken));
            }
            tx.execute(
                "UPDATE collections SET name=?2, mail_folder=?3 WHERE id=?1",
                params![id, name, mail_folder],
            )?;
            let accounts = if old.name != name {
                forget_folder(&tx, &old.name)?;
                accounts_of(&tx, id)?
            } else {
                vec![]
            };
            let new = get(&tx, id)?.ok_or(CollectionError::NotFound);
            tx.commit()?;
            Ok(new.map(|n| (n, accounts)))
        })
    }

    /// Deletes a collection (never its messages). Returns the accounts that had messages in it,
    /// or None if there was no such collection.
    pub fn delete_collection(&self, id: &str) -> anyhow::Result<Option<Vec<String>>> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let Some(old) = get(&tx, id)? else {
                return Ok(None);
            };
            let accounts = accounts_of(&tx, id)?;
            tx.execute("DELETE FROM collections WHERE id=?1", [id])?;
            forget_folder(&tx, &old.name)?;
            tx.commit()?;
            Ok(Some(accounts))
        })
    }

    /// Adds messages to a collection (`add`) or takes them out. Unknown ids are skipped. Returns
    /// how many changed and the accounts of those messages.
    pub fn collection_members(
        &self,
        id: &str,
        messages: &[i64],
        add: bool,
    ) -> anyhow::Result<Option<(u64, Vec<String>)>> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let Some(col) = get(&tx, id)? else {
                return Ok(None);
            };
            let folder = folder_name(&col.name);
            let now = chrono::Utc::now().to_rfc3339();
            let mut changed = 0;
            let mut accounts = BTreeSet::new();
            for m in messages {
                let account: Option<String> = tx
                    .query_row("SELECT account FROM messages WHERE id=?1", [m], |r| {
                        r.get(0)
                    })
                    .optional()?;
                let Some(account) = account else { continue };
                let n = if add {
                    tx.execute(
                        "INSERT OR IGNORE INTO collection_members(collection, message, added_at)
                         VALUES(?1,?2,?3)",
                        params![id, m, now],
                    )?
                } else {
                    tx.execute(
                        "DELETE FROM collection_members WHERE collection=?1 AND message=?2",
                        params![id, m],
                    )?
                };
                if n > 0 {
                    changed += 1;
                    accounts.insert(account);
                    // The message's place in the folder starts over: out of it now, or back in
                    // it under a new UID (also after it was deleted there before).
                    tx.execute(
                        "DELETE FROM imap_uids WHERE mailbox=?1
                           AND membership IN (SELECT id FROM memberships WHERE message=?2)",
                        params![folder, m],
                    )?;
                }
            }
            tx.commit()?;
            Ok(Some((changed, accounts.into_iter().collect())))
        })
    }

    /// The messages of an account in a collection.
    pub fn collection_message_ids(&self, id: &str, account: &str) -> anyhow::Result<Vec<i64>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT cm.message FROM collection_members cm JOIN messages g ON g.id=cm.message
                 WHERE cm.collection=?1 AND g.account=?2",
            )?;
            let rows = stmt.query_map(params![id, account], |r| r.get(0))?;
            rows.collect()
        })
    }

    /// Names of the collections a message is in, for the manifests.
    pub fn collections_of(&self, message: i64) -> anyhow::Result<Vec<String>> {
        self.with(|c| {
            let names: Option<String> = c.query_row(
                "SELECT group_concat(name, char(31)) FROM
                   (SELECT co.name FROM collection_members cm JOIN collections co ON co.id=cm.collection
                    WHERE cm.message=?1 ORDER BY co.name)",
                [message],
                |r| r.get(0),
            )?;
            Ok(split_list(names.unwrap_or_default()))
        })
    }

    /// Puts a message in the named collections, creating those that don't exist (rebuild).
    /// Invalid names are skipped. Returns how many it was added to.
    pub fn restore_collections(&self, message: i64, names: &[String]) -> anyhow::Result<u64> {
        let mut added = 0;
        for name in names {
            let Ok(name) = clean_name(name) else { continue };
            let id = self.with(|c| {
                let found: Option<String> = c
                    .query_row(
                        "SELECT id FROM collections WHERE name=?1 COLLATE NOCASE",
                        [&name],
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok(found)
            })?;
            let id = match id {
                Some(id) => id,
                None => match self.create_collection(&name, false)? {
                    Ok(col) => col.id,
                    Err(_) => continue,
                },
            };
            if let Some((n, _)) = self.collection_members(&id, &[message], true)? {
                added += n;
            }
        }
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(clean_name("  Taxes 2025 "), Ok("Taxes 2025".into()));
        assert!(clean_name("").is_err());
        assert!(clean_name("a/b").is_err());
        assert!(clean_name("say \"hi\"").is_err());
        assert!(clean_name("zero\u{200b}width").is_err());
        assert!(clean_name(&"x".repeat(81)).is_err());
        assert_eq!(folder_name("Reçus"), "Collections/Re&AOc-us");
    }
}
