# Development and tests

[← Back to the README](../README.md)

## Architecture

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

```sh
cargo test --workspace                     # unit tests (crypto, layouts, index, retention, sanitizer, …)
cargo test -p malo-api                     # regenerates src/lib/api/types.ts

docker compose --profile test up -d        # Dovecot (+ no-UIDPLUS and OAuth-only twins), mock OAuth2 provider, RustFS, fake-gcs-server
docker compose --profile test up rustfs-init   # buckets malo-a, malo-b and malo-lock (Object Lock)
MALO_IT=1 cargo test -p malo-server --test integration
MALO_IT=1 cargo test -p malo-server --test features      # two-step login, restore, compression, Object Lock
cargo test -p malo-server --test mail_access             # IMAP/SMTP services for mail apps (no Docker)
cargo test -p malo-server --test alerts_export           # alerts to fake webhook/ntfy/Apprise/SMTP servers, exports (no Docker)

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
- STARTTLS, IDLE-triggered backups, the encrypted recovery kit (password reset with it, refusal of a wrong passphrase or someone else's kit), kit import, a restore from the kit that waits for the destination's credentials and brings accounts back asking to sign in again, the password check used before a profile keeps a password, and an index rebuild that restores accounts and destinations from the settings copy;
- two-step login: codes used once, replay refused, recovery codes, turning it off;
- restoring to an empty Dovecot account into the original folders (byte-identical, flags kept), a second run that skips everything, and a search restored into one folder;
- compression turned on for an existing RustFS destination: the stored mail recompressed, the old objects gone, deep checks passing, and the usage report matching;
- Object Lock on a RustFS bucket created with it: refused on a bucket without it, and stored mail carrying a governance retention date;
- OAuth2 against a local provider: an authorization-code + PKCE flow yields a refresh token, the server refreshes it into access tokens and logs in with `AUTHENTICATE XOAUTH2` to a Dovecot that accepts nothing else, then backs up. It also checks that secrets are redacted, kept when you edit, and refused for the wrong mailbox.

The GUI test drives the app through:

- local-server setup and saving the encrypted recovery kit (checking the file is encrypted and private);
- adding a destination, a password account, and an OAuth2 account through the browser sign-in;
- watching the live "Newly found" list;
- the sandboxed viewer: phishing warning, de-fanged links, blocked tracker, a frame sized to the message, and attachment warnings in the app's own dialog;
- *Lock now*, resetting the password with the recovery kit (a wrong kit passphrase is refused), and unlocking again;
- remote mode against the Docker image, including the TOFU fingerprint check.

## Fuzzing

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
  - randomized settings: STARTTLS or TLS, IDLE, encryption, deep-check mode, purge age, excluded folders, flagged mail and required destinations;
  - recovery: saving recovery kits, turning *keep its credentials in the kit* on and off per destination and mail passwords in the settings copies, deleted users coming back as new users restored from their kit (taking over their shared-mount folder), entering the storage credentials the kit left out, and signing restored accounts in again;
  - the password check an app runs before keeping a password, and opening conversations with text previews.
- **What it checks after every step:**
  - **Isolation:** lists, events, jobs and cross-user ID probes.
  - **Lifecycle:** dead sessions stay dead; locked, disabled or deleted users hold no keys and run nothing; a deleted user's files never come back; a restart seals everyone.
  - **Health and progress:** no 5xx responses (except 500s while the local disk is failing), no hangs, maintenance jobs never fail because of other users' data.
  - **Recovery:** a kit file shows nothing in the clear and stops being asked for once saved; changing what a destination keeps in the kit marks the kit outdated; a restore keeps every destination of the kit, brings storage secrets back only where they were kept, and brings accounts back ready to run only if mail passwords were copied; entering the missing credentials makes the destination usable; a deleted user replaced by a restore stays deleted; a wrong password in the password check is refused with 403 and never ends the session; a conversation contains the message it was opened from, and previews stay short.
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
