# Malo

Malo backs up email. It runs as an always-on server that copies every message byte-for-byte from any IMAP account to one or more storage destinations, checks those copies on a schedule, and can then permanently delete old mail from the mail server once every required destination holds a verified copy.

- **Many people, many accounts.** Each user unlocks only their own keys and sees only their own data. Administrators manage users but cannot read anyone's mail.
- **Any storage.** Destinations are [Apache OpenDAL](https://opendal.apache.org) services: a local folder or Docker volume, S3 and S3-compatible stores (RustFS, MinIO, R2, Wasabi…), Google Cloud Storage, Azure Blob, WebDAV, Backblaze B2 and more. Encryption is switched on or off per destination and is on by default.
- **Verified, not assumed.** Every write is read back and hashed. Quick checks compare listings with the index, and deep checks re-download and re-hash the objects. Repair copies a healthy replica back, or fetches the message from IMAP again.
- **Safe deletion.** Purging is opt-in and per account. You preview the result with a dry run, arm it by typing the account name, and it is disarmed automatically whenever the policy changes. Messages are re-verified just before deletion, and only `UID EXPUNGE` is used, never a bare `EXPUNGE`.
- **Desktop app** (Tauri v2 + Astro + Svelte 5). It connects to a remote server, pinning its certificate on first use, or runs the bundled server locally. A live **Newly found** list shows mail the moment it is discovered, and a sandboxed viewer that is safe by default lets you read your backups.

```
┌──────────── Tauri GUI (desktop) ─────────────┐        ┌──────────── malo-server (Docker / sidecar) ────────────┐
│ Svelte UI (Astro static, client:only)        │        │ axum HTTPS API + WebSocket events                      │
│   │ invoke()/Channel                         │  TLS   │ auth/sessions ─ per-user KeyRing (RAM, auto-lock)      │
│ Rust client: reqwest + tungstenite,          │◄──────►│ scheduler + job queue (per-account locks)              │
│ pinned cert, session token kept out of JS    │        │ malo-core: imap · sync · store(OpenDAL) · verify ·     │
│ OAuth loopback flow · sidecar launcher       │        │            purge · viewer(parse+sanitize) · crypto     │
└──────────────────────────────────────────────┘        │ data dir: server.db + users/<id>/{vault.bin,index.db}  │
                                                        └─────────────────────────────────────────────────────────┘
```

| Path | What it holds |
|---|---|
| `crates/malo-core` | Pure library: crypto and vault, IMAP, SQLCipher index, OpenDAL store and layouts, backup, integrity checks, purge, viewer, index rebuild |
| `crates/malo-api` | Shared request, response and event types. `cargo test -p malo-api` regenerates `src/lib/api/types.ts` |
| `crates/malo-server` | The server binary: axum, auth, key ring, scheduler and jobs, plus integration tests |
| `src-tauri` | Desktop app: API and WebSocket client, OAuth PKCE flow, sidecar launcher, tray |
| `src/` | Astro and Svelte 5 UI |
| `docker/`, `docker-compose.yml` | Production image, plus a test stack: Dovecot, RustFS and fake-gcs-server |
| `e2e/` | Headless WebDriver test of the real desktop app |

## Running the server (Docker)

```sh
docker compose up -d malo
docker compose logs malo | grep -E "setup token|certificate SHA-256"
```

On first start the server does two things:

- It creates its own **certificate authority** in `/data/tls` and logs its **SHA-256 fingerprint**. The desktop app shows this fingerprint when you first connect. Compare the two before you trust the server; the app then pins it. The authority issues the server's certificate: valid for 397 days, for the names in `MALO_TLS_HOSTNAMES`, and renewed automatically while the server runs, without changing the pin. It may only vouch for those names (name constraints), so a phone that trusts it can't be fooled about other sites. Servers that used the earlier self-signed certificate switch over on first start, and the desktop app asks once to confirm the new fingerprint.
- It logs a one-time **setup token**. Use it in the app to create the first administrator. After that, administrators invite users, or turn on self-registration.

### Configuration

The server is configured with environment variables. They can also go in a TOML file named by `MALO_CONFIG`, using the same names in lowercase without the `MALO_` prefix.

| Variable | Default | Meaning |
|---|---|---|
| `MALO_LISTEN` | `0.0.0.0:8443` | Address the server listens on |
| `MALO_DATA_DIR` | `/data` | Where `server.db`, the per-user vaults, indexes and spool, and fs destinations live |
| `MALO_TLS_CERT`, `MALO_TLS_KEY` | – | PEM files to use your own certificate instead of Malo's authority |
| `MALO_TLS_HOSTNAMES` | – | Names and addresses mail apps and browsers use for this server (e.g. `10.0.0.1,backup.lan`), comma-separated; the certificate covers them and `localhost`. A name the authority doesn't cover yet creates a new authority, to be installed again |
| `MALO_TLS=off` | on | Serve plain HTTP. Only do this behind a TLS-terminating reverse proxy |
| `MALO_MAX_AUTO_LOCK_HOURS` | `24` | Upper limit on any user's auto-lock |
| `MALO_ALLOWED_FS_MOUNTS` | – | Absolute paths, colon-separated, that `fs` destinations may use besides the user's own directory |
| `MALO_WORKERS` | `4` | Number of jobs that can run at once across all users |
| `MALO_IMAP_LISTEN` | off | Address of the IMAP service for mail apps, e.g. `0.0.0.0:1993` (implicit TLS). See [Mail apps](#mail-apps-imap-and-smtp) |
| `MALO_SMTP_LISTEN` | off | Address of the SMTP submission service for mail apps, e.g. `0.0.0.0:1465` (implicit TLS) |
| `MALO_MAIL_TRACE` | off | `1` logs every IMAP command (passwords hidden), Malo's replies and how long each took, to find where a mail app gets stuck. Commands slower than 10 s are logged anyway |
| `MALO_TRUSTED_PROXIES` | none | Addresses or CIDR ranges of your reverse proxies, comma separated (`127.0.0.1, 10.0.0.0/8`). Only requests from these take the client address (for rate limits and login backoff) from `MALO_PROXY_HEADER`; everyone else is counted by their own address, whatever headers they send |
| `MALO_PROXY_HEADER` | `x-forwarded-for` | The header your proxy sets: `x-forwarded-for` (the right-most address that isn't a trusted proxy counts) or a single-address header such as `x-real-ip` |
| `MALO_TRUST_PROXY_HEADERS` | off | Deprecated: trusts proxies on loopback and private networks. Set `MALO_TRUSTED_PROXIES` instead |

Administrators set the remaining options in the app (*Admin*): self-registration, the default and per-user account limits, the maximum auto-lock, extra `fs` mounts, and **Block private networks**. That last one refuses mail servers, storage endpoints and OAuth token URLs on loopback, private, link-local and other reserved addresses (also in their IPv6 forms such as NAT64 and 6to4). It is checked when an account or destination is saved or tested, and again on every connection, at the address actually connected to, so a name that later resolves somewhere else (DNS rebinding) gets nowhere; storage requests don't follow redirects. **It's off by default** because a LAN mail server or MinIO is a common setup: **turn it on for any server that users you don't fully trust share**, or they can make it connect to hosts on its own network, cloud metadata services included. Independently of the setting, a destination only ever uses the credentials entered for it: never the server's environment, config files or cloud identity (EC2 instance role, GCE service account, Azure managed identity), and only the options its storage service needs are accepted. The *Admin* page also lists open invites (which can be revoked) and a log of administrative actions: user changes and deletions, invites, settings, password resets with a kit, and settings restored by a rebuild.

Behind a reverse proxy with a public certificate, the app detects that the certificate is publicly trusted and doesn't pin it.

### Hardening

The server keeps unlocked keys in RAM, so it takes these steps:

- It disables core dumps (`RLIMIT_CORE=0`) and ptrace attachment (`PR_SET_DUMPABLE=0`).
- It `mlock`s its key material.
- It runs as a non-root user in a read-only, distroless container.

**Run the container without swap** (`mem_swappiness: 0` is set in the compose file). On a dedicated host, consider disabling swap or using encrypted swap. The image has a `HEALTHCHECK` (`malo-server --healthcheck`), and `/healthz` reports only how many users are sealed and how many are unlocked.

## Security model

```
password ──Argon2id(user salt, m=256 MiB, t=3, p=1)──► KEK (never stored)
                                                        │ AES-256-GCM wrap (header + user id as AAD)
random 256-bit MDK ◄────────────────────────────────────┘  users/<id>/vault.bin
  └ HKDF-SHA256 ─► config key    → AES-256-GCM(user config: accounts, credentials, tokens, destinations, policies)
                ─► sqlcipher key → users/<id>/index.db
                ─► spool key     → encrypted download spool
  archive key (random, inside the config, exportable as the recovery kit)
                ─► HKDF per object → AES-256-GCM, 64 KiB segments (STREAM: counter + last-segment flag)
```

**Logging in unlocks your keys.** Malo stores no separate password hash: a failed GCM tag means the password was wrong. Changing your password only re-wraps the master data key; your config, index and backups are not re-encrypted.

**Auto-lock is mandatory.** When it expires (24 hours by default, which you can shorten but not disable), and also on "Lock now" or a server restart:

- the server wipes your keys from memory and ends your sessions;
- running jobs stop at the next message boundary;
- scheduled jobs that come due are recorded as *skipped (locked)*, and the app shows how many on your next login.

**There is no admin backdoor.** If you forget your password, your data is lost unless you kept the **recovery kit**. The app makes you save it on your first login, and you can save a new one anytime in *Settings*. It asks for your password again, and you choose a separate **kit passphrase**.

- **The kit file is encrypted.** It holds your user id, username and archive key, sealed with AES-256-GCM under an Argon2id key from the kit passphrase. Without the passphrase its content reveals nothing, not even whose it is. Only the suggested file name contains your username, and you can rename it. The app writes it readable only by you, and it counts as saved only after the file was written. Kits from older versions (`malo-recovery-kit-v1`) are plain JSON and still accepted; replace them with a new kit and delete the old file.
- **Forgot your password, same server:** on the login screen, choose *Forgot password?*. Enter your username, pick the kit, type its passphrase and a new password. The server keeps a recovery slot (`users/<id>/recovery.bin`): your master data key, sealed with a key derived from the archive key. Unsealing it proves the kit is yours, and the vault is re-wrapped under the new password. Accounts, destinations, index and backups stay as they are, and every session is logged out. Users created before this feature get their slot on their next login.
- **Lost the server, or deleted the user:** create a new account (on any Malo server), import the kit on the registration screen, add one of your old destinations with the same settings, and run *Rebuild index*. The rebuild imports all mail. It also restores your accounts and destinations from the encrypted settings copy that every backup and check leaves on each destination (`malo-settings-<hmac>.enc`, sealed with the archive key). Accounts come back with their sign-in details but with purging disarmed. Accounts and destinations you removed on purpose stay removed. Accounts found only in manifests show as *imported* until you enter their sign-in details.
- **Key changes:** changing your password doesn't change the kit. The archive key is never rotated, so an old kit and its passphrase keep working. Treat any kit as valid for as long as its backups exist.

**On encrypted destinations, names reveal nothing.** Objects are stored at `<root>/<hmac(account)>/objects/<xx>/<hmac(sha256)>.enc` and manifests at `manifest/<hmac(mailbox)>.jsonl.enc`. No mailbox names or subjects appear. Plain destinations keep a browsable layout instead: `<root>/<Account>_<id>/mailboxes/<Mailbox/Sub>/<uidvalidity>/<uid>.eml`.

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
- Message HTML is sanitized on the server with ammonia, then rendered in an `<iframe sandbox="">` with an inner CSP of `default-src 'none'`.
- Remote images are blocked until you allow them for one message. Links are shown with their real target and open only after you confirm.
- Attachments are never opened, only saved with *Save as…*. The app warns you about executables and about files whose content doesn't match their declared type.

## Using it

1. **Destinations.** Add at least one: a local folder, S3, GCS, Azure, WebDAV or B2. Use *Test* to write, read back and delete a probe object. Two destinations on different systems are recommended before you turn on purging.
2. **Accounts.** Pick a preset (Gmail, Outlook/Microsoft 365, Yahoo, iCloud, Fastmail…) or *Other IMAP server*. Sign in with an app password, or with OAuth2 using **your own client ID**; the wizard includes instructions for Google Cloud and Azure. The OAuth sign-in runs in your browser through a loopback PKCE flow. Only the refresh token goes to the server, which refreshes access tokens itself.
3. **Backups.** They run every 30 minutes by default. With **IDLE** enabled, new mail in INBOX starts a backup immediately. Gmail is backed up from *All Mail*, *Spam* and *Trash*, with duplicates removed by `X-GM-MSGID` and labels preserved. Downloads use `BODY.PEEK[]`, so Malo never changes `\Seen`.
4. **Integrity.** A quick check runs daily and a deep check weekly, and you can also start one with *Verify now*. Destinations whose egress is expensive can be set to re-hash a rotating slice per run instead of everything. *Verify & repair* fixes missing or corrupt replicas.
5. **Purge.** Set the retention rule: older than N days (0 means everything), the required destinations, mailboxes to exclude, and whether to skip flagged mail. Run a dry run, then arm the purge by typing the account name. Each run re-verifies every candidate in every required destination, re-selects the mailbox, checks that UIDVALIDITY hasn't changed and that size and Gmail id still match, and only then deletes with `UID STORE +FLAGS.SILENT (\Deleted)` followed by `UID EXPUNGE <set>`. Servers without UIDPLUS are refused. On Gmail, messages are moved to Trash and expunged there, which deletes them permanently. Every deletion is written to the audit log.

   Exchange and Microsoft 365 may keep deleted items in *Recoverable Items* for some time; Malo can't control that.
6. **Searching.** The search box in *Mail* searches the full text of messages: subject, sender, recipients, attachment names and the body, with HTML mail read as text. Words match their beginnings (`inv` finds `invoice`). Operators:
   - `from:`, `to:`, `subject:`, `body:` and `file:` (attachment name);
   - `after:2024-03-01` and `before:2025` (the received date: a day, month or year);
   - `has:attachment`, `is:unread`, `is:read`, `is:purged` (deleted on the mail server);
   - `category:social` (or `primary`, `promotions`, `updates`, `forums`) for Gmail mail;
   - `"exact phrase"`, `word OR word`, and `-` in front of a word or operator to leave it out.

   As you type, the search box offers operators, and for `from:`, `to:` and `file:` it suggests the senders, recipients and attachment names in your mail, most used first. Finished operators become chips: click one to change it, or press Backspace to remove the last. The **?** button lists every operator, and the filter button shows *Search in* (one part of the message for plain words), a date range, *Has attachment* and *Deleted on server*. *Best match* sorts by relevance, and each result shows the matching text.

   Mail is indexed when a backup downloads it. Mail backed up before search existed, or restored by an index rebuild, is indexed by the *Index mail for search* job. That job runs on its own after a backup or rebuild, reading from the spool or a destination. Until a message is indexed, only its sender, recipients and subject are searched, and the list says how many messages that applies to. Mail apps' `SEARCH BODY`/`TEXT` use the same index.
7. **Reading.** Messages open as conversations: every message of the thread, oldest first, with the opened one and the newest expanded. The header shows the date range, the Gmail category, the people involved and every attachment in the conversation. Rows in the list show `[n]` when a message is part of a conversation. For Gmail accounts, tabs above the list filter by category (Primary, Social, Updates, Promotions, Forums), and other rows show their category's icon.
8. **Writing.** *Compose* (`c`) writes a new message; *Reply* (`r`), *Reply all* (`a`) and *Forward* (`f`) open a composer under the message, quoting it. A forward can include the original attachments. Mail is sent through the account's own SMTP server (add it under *Accounts*), and on servers other than Gmail a copy is saved in *Sent*. What you write is saved as a draft as you type, encrypted in Malo's index only (not on the mail server). *Drafts* (`Shift+D`) lists them; closing the composer keeps the draft, *Discard* deletes it, sending removes it. `Ctrl+Enter` sends.
9. **Selecting mail.** In *Mail*, tick the box left of a message's avatar, Ctrl/⌘-click a row, Shift-click for a range, press `x` for the open message, or Ctrl+A for the whole view (up to 10,000). The selection bar and right-click menu then act on all of them:
   - mark them read or unread, or save them as `.eml` files into a folder;
   - **Delete from mail server** (`Delete` or `#`): a purge of just these messages, without the age, mailbox and flag rules. Each message must be verified on the purge's required destinations (every destination when none are set). It's re-verified there and identity-checked on the server, like a purge. The backup stays.
   - **Delete from backup** (`Shift+Delete`): removes the messages from Malo's index, rewrites the manifests on every destination without them, and deletes their stored copies. A message still on the mail server is deleted there first, or the next backup would bring it back; if that fails, it stays in the backup too. A destination that can't be reached is cleaned up at its next successful backup, and tombstones in the index keep a rebuild from restoring the messages meanwhile. This can't be undone.

   Both deletions ask for two confirmations and run as jobs (at most 1,000 messages each, one per account), listed in *Activity* and the audit log.

## Mail apps (IMAP and SMTP)

With `MALO_IMAP_LISTEN` and `MALO_SMTP_LISTEN` set, Apple Mail, Thunderbird or any IMAP app can read an account's **backed-up** mail, including mail long purged from its server, and reply, reply all and forward through the account's own outgoing server.

- **One login per account, never your Malo password.** In *Accounts → Mail app*, pick a username (unique on the server, e.g. `work-mail`). Malo generates the password (24 random letters and digits by default, up to 128) and shows it once; it keeps only a hash. *New password* replaces it and signs out apps using the old one; *Remove login* ends access. The mail login can only read that one account's backups and send through that account: it can't unlock your vault, see other accounts or change settings.
- **Readable while you're unlocked.** The backups are encrypted with keys that exist only while you're logged in to Malo, so mail apps get `Malo is locked` after the auto-lock until you log in again. Failed mail logins share the app login's backoff.
- **Folders** are the account's mailboxes, every UIDVALIDITY they ever had included, so nothing purged is missing: Sent, Drafts, Spam/Junk, Trash, Archive and the rest, marked with their roles so mail apps file them in the right place. On Gmail, labels appear as folders (Sent Mail, Drafts, Starred, Important, your labels) next to *All Mail*, *Spam* and *Trash*. Messages show up once their content is stored. UIDs are Malo's own and stay stable.
- **Gmail categories.** Each backup records which category (Primary, Social, Promotions, Updates, Forums) Gmail put new mail in, and every message is checked again every 6 hours. By default INBOX shows Primary only and the others get folders under *Categories/*; turn that off to have everything in INBOX. A message Gmail re-categorizes moves folders on its own.
- **Choosing folders.** *Accounts → Mail app → Folders* lists every folder with its role and message count; untick any (except INBOX) to keep it out of mail apps, e.g. *All Mail* so Gmail mail doesn't show twice.
- **Fast listing.** Mail apps download headers and structure for every message first. Malo stores that data when it indexes a message for search, so listing a folder never downloads the messages from a destination. Mail backed up before this existed is indexed by the *Index mail for search* job, which starts when a mail app signs in. Until it finishes, those messages are read from the destinations (eight at a time), so a large mailbox lists slowly the first time.
- **The archive is read-only.** Flags (read, flagged…), deleting, and moving or copying between folders (*Move to Junk*, into a category, to Trash…) only change what mail apps see; the backups and the mail server stay untouched. Gmail doesn't let other apps set categories, so filing a message into a category stays in Malo. *Show every message again* undoes all of it. Creating, renaming and deleting folders are refused.
- **Sending.** Add the account's outgoing server (*Edit account → Outgoing mail*; presets fill it in). Each message is relayed unchanged, signed in with the account's IMAP credentials (password or OAuth2; Microsoft also needs the `SMTP.Send` scope), and the recipient list is all-or-nothing: if the server refuses one recipient, nothing is sent and the app gets the server's answer. *Block private networks* applies to SMTP servers too. Saving to *Sent* in the app stores the copy on the account's server, so the next backup picks it up (Gmail keeps sent mail by itself). Drafts aren't kept on the backup server: turn off *Store draft messages on the server* in Apple Mail.
- **Setup in Apple Mail:** *Other Mail Account…*, account type IMAP, this server as incoming and outgoing server, the mail login for both, the two ports with *Use TLS/SSL*. Both services present the server's certificate. Install Malo's certificate authority on the device first: open the server's address (e.g. `https://10.0.0.1:9443/`) in the device's browser: the page offers the download and the steps for iPhone, iPad, Mac, Android, Windows and Linux, with this device's first. On iPhone, also turn it on under Settings → General → About → *Certificate Trust Settings*. Use one of the names in `MALO_TLS_HOSTNAMES` as the server name. Apps set to *STARTTLS* (or with SSL off) work on the same ports: Malo greets them in plain text, offers only STARTTLS, and refuses logins until TLS is on. If an app gets nowhere, set `MALO_MAIL_TRACE=1` and watch the log.

## Desktop app

```sh
npm install
node scripts/build-sidecar.mjs --debug   # puts malo-server in src-tauri/binaries/ for the local mode
npm run tauri dev
```

- **Release bundles:** run `node scripts/build-sidecar.mjs && npx tauri build`. This produces AppImage, deb or rpm on Linux, dmg or app on macOS, and msi or NSIS on Windows, with the server bundled as a sidecar.
- **Local mode:** the bundled server starts on `127.0.0.1` on a random port, with a secret generated for each launch. Its data lives in the app's data folder.
- **Tray mode** (Settings) keeps backups running in the background after you close the window.
- **Cleaning up the local server.** The Connect screen and *Settings → Local server → Data* show where the local server's data lives and how much there is, with *Open folder* and *Reset local server…*. The login screen also offers the reset, for when you've forgotten the local password. Resetting stops the bundled server and deletes all local users, keys, indexes and local-folder backups. It does not touch IMAP servers or remote destinations. For development, `npm run reset-local` does the same while the app is closed (`-- --dry-run` to only list, `-- --prefs` to also forget app preferences, `-- --yes` to skip the prompt).
- **Deleting your account** (*Settings → Delete my account…*) removes your user from the server you're connected to: your keys, config, index, job history and local-folder backups. Backups on remote destinations stay, readable only with your recovery kit.

Both destructive actions take two steps. First you confirm you understand. Then you type an exact phrase: `DELETE` for the reset, or `delete <your username>` plus your password for account deletion. The server checks the phrase and the password again (`POST /me/delete`) and refuses to delete the last administrator.

## Development and tests

```sh
cargo test --workspace                     # unit tests (crypto, layouts, index, retention, sanitizer, …)
cargo test -p malo-api                     # regenerates src/lib/api/types.ts

docker compose --profile test up -d        # Dovecot (+ no-UIDPLUS and OAuth-only twins), mock OAuth2 provider, RustFS, fake-gcs-server
docker compose --profile test up rustfs-init
MALO_IT=1 cargo test -p malo-server --test integration

# Headless GUI test of the real Tauri binary (Xvfb + WebKitWebDriver in Docker):
cargo install tauri-driver --locked
node scripts/build-sidecar.mjs --debug && npx tauri build --debug --no-bundle
docker compose build malo
e2e/run.sh                                 # screenshots land in e2e/out/
```

The integration suite covers:

- two users, each with two accounts, backing up to RustFS (encrypted), GCS (plain) and fs, including nested and unicode mailboxes, a 3 MiB attachment and a decoy `\Deleted` message;
- every copy byte-identical to the original;
- user isolation;
- *NewMessageDiscovered* sent once per message, before its download;
- mail added during a run, and a re-run that does nothing;
- auto-lock stopping a running job, skipped-while-locked jobs, resuming after login, and a restart sealing every user;
- quick and deep checks detecting deleted and corrupted objects, repair, and purge blocked until repair;
- purge eligibility, decoys left alone, UIDVALIDITY change, missing replica, no UIDPLUS, and purges that only run on schedule once armed;
- STARTTLS, IDLE-triggered backups, the encrypted recovery kit (password reset with it, refusal of a wrong passphrase or someone else's kit), kit import, and an index rebuild that restores accounts and destinations from the settings copy;
- OAuth2 against a local provider: an authorization-code + PKCE flow yields a refresh token, the server refreshes it into access tokens and logs in with `AUTHENTICATE XOAUTH2` to a Dovecot that accepts nothing else, then backs up. It also checks that secrets are redacted, kept when you edit, and refused for the wrong mailbox.

The GUI test drives the app through:

- local-server setup and saving the encrypted recovery kit (checking the file is encrypted and private);
- adding a destination, a password account, and an OAuth2 account through the browser sign-in;
- watching the live "Newly found" list;
- the sandboxed viewer: phishing warning, de-fanged links, blocked tracker and attachment warnings;
- *Lock now*, resetting the password with the recovery kit (a wrong kit passphrase is refused), and unlocking again;
- remote mode against the Docker image, including the TOFU fingerprint check.

### Fuzzing

There are two kinds of fuzzing.

**Lifecycle and interference fuzzer** (`crates/malo-server/tests/fuzz_lifecycle.rs`). This is a stateful, model-based fuzzer for the whole server.

- **What it does:** seeded random sequences of operations by four users at once:
  - register, log in and out, Lock now, auto-lock, password change, delete account, admin disable or delete, server restart;
  - accounts and destinations, including two users on the same shared folder or the same S3 prefix;
  - backups, checks, repairs, rebuilds and purges overlapping all of the above, plus bursts of concurrent requests;
  - outside-world faults: other mail clients adding and deleting mail, mailboxes recreated, IMAP connections kicked, stored objects deleted or corrupted, storage outages;
  - I/O faults from a seeded injector that exists only in test builds (cargo feature `fault-injection`, off in release). It covers storage reads and writes, stat, list and delete, the spool, the viewer cache, config and vault writes, and the index. Faults: I/O errors, full disk, half-written or half-read objects, flipped bytes, writes that report success but store nothing, writes that land and then fail, and slow I/O;
  - network faults between Malo and S3 through toxiproxy (resets, timeouts, latency, connections cut mid-upload), and a local folder made read-only (a real EACCES);
  - a second device per user: parallel logins, logout on one device, and stale saves from a form loaded before another device's change;
  - hostile names for accounts, renames, destinations and IMAP folders. These include Unicode normalization pairs and case twins, invisible and bidi characters, look-alikes, emoji sequences, path syntax (`..`, `/`, `\`, `%2e%2e`, full-width dots), IMAP UTF-7 syntax, quotes, NUL and names far beyond file-name limits;
  - IMAP folders created, nested, renamed and deleted by other mail clients;
  - messages with RFC 2047 headers, 8-bit and Latin-1 bodies, malformed MIME, hostile attachment names, headers-only mail, bodies of several MB, duplicate Message-IDs, random flags and dates;
  - path-traversal destinations (relative, absolute, in the prefix field, encoded, look-alike) and symlinks inside a user's mount folder that point outside it;
  - randomized settings: STARTTLS or TLS, IDLE, encryption, deep-check mode, purge age, excluded folders, flagged mail and required destinations.
- **What it checks after every step:**
  - **Isolation:** lists, events, jobs and cross-user ID probes.
  - **Lifecycle:** dead sessions stay dead; locked, disabled or deleted users hold no keys and run nothing; a deleted user's files never come back; a restart seals everyone.
  - **Health and progress:** no 5xx responses (except 500s while the local disk is failing), no hangs, maintenance jobs never fail because of other users' data.
  - **Devices:** logging out on one device leaves the other alone; Lock now and a password change end the other device's session, and Lock is announced to it; a stale save is refused with 409 and never overwrites.
  - **Failed requests:** a request that fails changes nothing (no half-created users, destinations or accounts).
  - **No false "verified":** every replica the index calls verified on a user's local folder is read back from disk by the fuzzer itself and must hash correctly.
  - **Nothing escapes:** every traversal attempt aims at a canary folder next to the data directory and the mount, which must stay empty; the mount holds only per-user folders.
  - **No collisions:** two different messages never share a storage path. A name mapping that collided would make one backup overwrite another.
  - **Names never crash the server:** a name it cannot handle is refused with 4xx.
- **Final data-loss check:** every message ever put on a mail server is still there, was deleted by another client, or is readable byte for byte from the backup of a surviving user who purged it. This runs after Malo's own rebuild and repair.
- **Convergence:** once every fault is gone, the server restarts and reloads everything from disk, proving the config, vaults and indexes survived. Malo then has to heal on its own: every message verified on every destination, and a clean deep check.
- **Failures** are shrunk to a minimal sequence and saved for replay. Fixed bugs live on as cases in `crates/malo-server/tests/fuzz-regressions/`, which run in CI.

```sh
MALO_IT=1 cargo test -p malo-server --test fuzz_lifecycle -- --nocapture
#   MALO_FUZZ_RUNS=40 MALO_FUZZ_STEPS=120 MALO_FUZZ_SEED=5000 MALO_FUZZ_SHRINK=30
#   MALO_FUZZ_REPLAY=$PWD/target/fuzz-lifecycle/failure-<seed>.json
```

**Parser fuzzing** (`fuzz/`, cargo-fuzz, nightly toolchain) covers everything that parses untrusted bytes:
- encrypted objects (round trip, tampering and truncation detected);
- vault files and config blobs;
- manifests read back from storage;
- emails through the viewer;
- the HTML sanitizer (the output is checked to be inert);
- raw IMAP server responses;
- names and paths (UTF-7 round trip, no path can escape);
- API inputs.

```sh
cd fuzz && cargo +nightly fuzz run html_sanitizer -- -max_total_time=300
```

CI runs the regression cases and a short random lifecycle run on every change, and a long lifecycle run plus every parser target nightly.

Notes:

- The test stack uses **RustFS** as its S3-compatible store.
- OpenDAL 0.54's GCS service double-encodes object names on upload. On GCS, Malo therefore stores paths in a reversible ASCII-only form (`~XX` escapes).
- The OAuth test rig is for testing only. It uses `mock-oauth2-server`, an OAuth-only Dovecot that checks tokens through the provider's `userinfo` endpoint, and, in the headless GUI test, a stand-in `xdg-open` that fills in the mock's login form. None of it ships in the app or the server image.
- The Gmail-specific code paths (labels, `X-GM-MSGID`, and purging through Trash) and the Google and Microsoft OAuth endpoints have not been run against the real services in this repository's tests. Check them with your own accounts before you rely on purging.
