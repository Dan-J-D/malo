# Desktop app

[← Back to the README](../README.md)

```sh
npm install
node scripts/build-sidecar.mjs --debug   # puts malo-server in src-tauri/binaries/ for the local mode
npm run tauri dev
```

- **Release bundles:** run `node scripts/build-sidecar.mjs && npx tauri build`. This produces AppImage, deb or rpm on Linux, dmg or app on macOS, and msi or NSIS on Windows, with the server bundled as a sidecar.
- **Profiles.** The app doesn't remember servers. A connection is kept in a *profile*: a `.malo` file you save wherever you like, encrypted with its own password (Argon2id, AES-256-GCM). It holds the server (local, or a URL with its pinned certificate), your username and, if you choose, your Malo password, so unlocking the profile logs you in. Like a KeePassXC database, the app only lists the paths of profiles you opened recently; *Settings → Server and profile* turns that list off. Locking or logging out closes the profile, and its password is needed again. A changed certificate is caught when the profile is unlocked, and trusting the new one updates the profile's pin. After logging in without a profile, Malo offers to save one (*Settings → Save as profile…* any time). A Malo password kept in a profile is checked with the server first, so a typo can't be saved. Connecting without a profile still works: you then compare the fingerprint on every first connection. Pins kept by older versions are still checked until a profile holds that server.
- **Local mode:** the bundled server starts on `127.0.0.1` on a random port, with a secret generated for each launch. Its data lives in the app's data folder.
- **Tray mode** (Settings) keeps backups running in the background after you close the window.
- **Cleaning up the local server.** The Connect screen and *Settings → Local server → Data* show where the local server's data lives and how much there is, with *Open folder* and *Reset local server…*. The login screen also offers the reset, for when you've forgotten the local password. Resetting stops the bundled server and deletes all local users, keys, indexes and local-folder backups. It does not touch IMAP servers or remote destinations. For development, `npm run reset-local` does the same while the app is closed (`-- --dry-run` to only list, `-- --prefs` to also forget app preferences, `-- --yes` to skip the prompt).
- **Deleting your account** (*Settings → Delete my account…*) removes your user from the server you're connected to: your keys, config, index, job history and local-folder backups. Backups on remote destinations stay, readable only with your recovery kit.

Both destructive actions take two steps. First you confirm you understand. Then you type an exact phrase: `DELETE` for the reset, or `delete <your username>` plus your password for account deletion. The server checks the phrase and the password again (`POST /me/delete`) and refuses to delete the last administrator.
