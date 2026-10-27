# Security model

[← Back to the README](../README.md)

```
password ──Argon2id(user salt, m=256 MiB, t=3, p=1)──► KEK (never stored)
                                                        │ AES-256-GCM wrap (header + user id as AAD)
random 256-bit MDK ◄────────────────────────────────────┘  users/<id>/vault.bin
  └ HKDF-SHA256 ─► config key    → AES-256-GCM(user config: accounts, credentials, tokens, destinations, policies)
                ─► sqlcipher key → users/<id>/index.db
                ─► spool key     → encrypted download spool
  archive key (random, inside the config, exportable as the recovery kit)
                ─► HKDF per object → AES-256-GCM, 64 KiB segments (STREAM: counter + last-segment flag)
                                     (version 2: the segments hold a zstd frame of the message)
```

**Logging in unlocks your keys.** Malo stores no separate password hash: a failed GCM tag means the password was wrong. Changing your password only re-wraps the master data key; your config, index and backups are not re-encrypted.

**Auto-lock is mandatory.** When it expires (24 hours by default, which you can shorten but not disable), and also on "Lock now" or a server restart:

- the server wipes your keys from memory and ends your sessions;
- running jobs stop at the next message boundary;
- scheduled jobs that come due are recorded as *skipped (locked)*, and the app shows how many on your next login.

**Two-step login (optional).** *Settings → Two-step login* adds a 6-digit code from an authenticator app (TOTP, RFC 6238: SHA-1, 30-second steps) after the password. The secret is sealed with a key derived from your config key, so the server can't check codes, or even read the secret, while you're locked; logging in opens the vault first, then asks for the code. Each code works once (a code can't be replayed within its window), and wrong codes count toward the login backoff. Ten recovery codes, stored only as keyed hashes, each replace a code once. Turning it off or getting new recovery codes takes your password and a code. A password reset with the recovery kit turns it off, since the kit already proves who you are. The desktop app asks for the code after the password, also when a profile keeps your password.

**There is no admin backdoor.** If you forget your password, your data is lost unless you kept the **recovery kit**. The app makes you save it on your first login, and you can save a new one anytime in *Settings*. It asks for your password again, and you choose a separate **kit passphrase**.

- **The kit file is encrypted.** It holds your user id, username and archive key, sealed with AES-256-GCM under an Argon2id key from the kit passphrase. Without the passphrase its content reveals nothing, not even whose it is. Only the suggested file name contains your username, and you can rename it. The app writes it readable only by you, and it counts as saved only after the file was written. Kits from older versions (`malo-recovery-kit-v1`) are plain JSON and still accepted; replace them with a new kit and delete the old file.
- **Forgot your password, same server:** on the login screen, choose *Forgot password?*. Enter your username, pick the kit, type its passphrase and a new password. The server keeps a recovery slot (`users/<id>/recovery.bin`): your master data key, sealed with a key derived from the archive key. Unsealing it proves the kit is yours, and the vault is re-wrapped under the new password. Accounts, destinations, index and backups stay as they are, and every session is logged out. Users created before this feature get their slot on their next login.
- **Lost the server, or deleted the user.** The kit also holds your destinations: where they are and how they're set up, but **not their credentials** unless you turn on *Keep its credentials in the recovery kit and the settings copies* for a destination. On the new server's login screen choose *Restore from kit* (or, on a brand-new server, *Restore from recovery kit…* when creating the administrator). Pick the kit, type its passphrase and a new username and password. The destinations are set up again. Ones whose credentials were kept are used right away. The others show *needs credentials* and are left alone until you enter them (*Destinations → Enter credentials*). As soon as one destination is usable, Malo rebuilds from it: all mail comes back, and so do your accounts, the other destinations and your settings, from the encrypted settings copy every backup and check leaves on each destination (`malo-settings-<hmac>.enc`, sealed with the archive key). Restored accounts ask you to sign in again (they show as *imported* until you do), because the settings copy leaves out mail passwords and sign-in tokens unless you turn on *Settings → Keep mail passwords and sign-ins in the settings copies*. Purging comes back disarmed. Accounts and destinations you removed on purpose stay removed. Restored destinations are checked like any other when they're used (confined folders, allowed options, private networks). When you add or change a destination (or the credentials of one whose credentials the kit keeps), the app reminds you to save a new kit. Kits from older versions hold only the key: register with the kit, add one old destination with the same settings, and run *Rebuild index*. Drafts, Malo's read/unread marks, mail-app logins, job history and the audit log are not restored.
- **Why credentials stay out by default.** With them in, the kit and its passphrase (or the archive key and one destination) would be enough to reach every storage and every mailbox. Without them, someone who gets hold of the kit still needs your storage and mail passwords, which belong in your password manager. Turn them on if a one-step restore matters more to you than that separation. Either way, protect at least one destination against deletion (Object Lock on S3 or B2, see the [user guide](user-guide.md), or snapshots of the NAS share), so a stolen storage key can't wipe your backups.
- **Key changes:** changing your password doesn't change the kit. The archive key is never rotated, so an old kit and its passphrase keep working. Treat any kit as valid for as long as its backups exist.
- **Old vault copies:** a password change re-seals `vault.bin` under the new password, but a copy of the old `vault.bin` (a disk snapshot or a backup of the data dir) still opens with the old password. If you changed it because it leaked, treat earlier copies of the data dir as protected only by the old one.

**On encrypted destinations, names reveal nothing.** Objects are stored at `<root>/<hmac(account)>/objects/<xx>/<hmac(sha256)>.enc` (`.z.enc` when compressed) and manifests at `manifest/<hmac(mailbox)>.jsonl.enc`. No mailbox names or subjects appear. Plain destinations keep a browsable layout instead: `<root>/<Account>_<id>/mailboxes/<Mailbox/Sub>/<uidvalidity>/<uid>.eml`.

**No path can leave its area.**
- Every storage path passes one check before it reaches a storage backend: no `..` or `.` segments, backslashes, NUL or drive letters. This applies to destination prefixes, `*root` options and object paths read back from manifests during an index rebuild.
- `fs` destinations are created one directory at a time inside the user's own folder, checking symlinks at every step.
- Inside admin-allowed mounts each user gets their own folder, `<mount>/<hmac(archive key, "owner")>/`, so users who pick the same path never share files. The mount shows neither user ids nor which folders belong together. A folder from older versions (`<mount>/<user-id>/`) keeps being used.
- Options that would make the server read one of its own files (`credential_path`, `*_file`) are refused, and S3 and GCS never load the server's own config files.
- Server data paths only accept UUID user ids, and usernames can't start with `.` or contain `..`.
- In the desktop app, file names from emails are reduced to a plain name before saving, and the app's API bridge rejects traversal in server paths.

**Unicode is handled, not trusted.**
- Names work in any script, and with emoji.
- Hidden characters (zero-width, bidi overrides such as U+202E, BOM, tag characters) are percent-encoded in storage paths. They're rejected in account and destination names, and shown as visible `⟨U+202E⟩` markers in the UI. They're stripped from file names when saving. The viewer warns when a sender name, subject or attachment name contains them, and when the sender's domain uses punycode or non-ASCII letters.
- Overlong names are shortened with a hash so they always fit on disk.
- Plain-layout mailbox folders carry a short tag of the exact name, so `Work` and `work`, or composed and decomposed `é`, never share files on case- or normalization-insensitive filesystems.
- Passwords are normalized to NFC before key derivation, so composed and decomposed input unlock the same vault.
- Search ignores case and accents in all scripts, and ignores invisible characters, so `paypal` finds `Pay<zero-width>Pal`. The full-text index is an FTS5 table inside the encrypted index: searchable text is never written to disk in the clear, and it's deleted together with its message.
- Before a purge deletes a message, its Message-ID, received date and size must still match the backup; messages without a Message-ID are compared by content hash. UIDs are never trusted alone, because some servers reuse UIDVALIDITY.

**The desktop app's web view is locked down.**

- The session token stays in the Rust side of the app.
- The web view has only `core:default` capabilities and a strict CSP: no fs plugin, no shell permissions and no direct network access from JavaScript.
- Message HTML is sanitized on the server with ammonia, links are taken out of it, and it is rendered in an `<iframe sandbox="allow-same-origin">` (no scripts, forms, popups or navigation) with an inner CSP of `default-src 'none'`. Same-origin only lets the app measure the message, so the frame grows to its full height instead of scrolling inside a box.
- Questions such as opening a link or saving a risky attachment use the app's own dialog, showing the link's real target and any warning, with *Cancel* focused.
- Remote images are blocked until you allow them for one message. Links are shown with their real target and open only after you confirm.
- Attachments are never opened, only saved with *Save as…*. The app warns you about executables and about files whose content doesn't match their declared type.
