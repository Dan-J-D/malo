<script lang="ts">
  import { onMount } from 'svelte';
  import { api, app } from '../api/client';
  import type * as T from '../api/types';
  import { session, attempt, notify, refreshMe, leaveServer, toLogin, errorText } from '../state.svelte';
  import LocalData from '../components/LocalData.svelte';
  import DangerConfirm from '../components/DangerConfirm.svelte';
  import Modal from '../components/Modal.svelte';
  import KitExport from '../components/KitExport.svelte';
  import ProfileSave from '../components/ProfileSave.svelte';
  import Icon from '../components/Icon.svelte';
  import { commands } from '../commands.svelte';

  let settings: T.UserSettings | null = $state(null);
  let oldPw = $state('');
  let newPw = $state('');
  let newPw2 = $state('');
  let tray = $state(false);
  let rememberRecent = $state(true);

  onMount(async () => {
    settings = (await attempt(() => api.get<T.UserSettings>('/settings'))) ?? null;
    const prefs = await app.prefs().catch(() => null);
    tray = prefs?.tray_mode ?? false;
    rememberRecent = prefs?.remember_recent ?? true;
  });

  async function saveSettings() {
    if (!settings) return;
    const r = await attempt(() => api.put<T.UserSettings>('/settings', settings), 'Settings saved');
    if (r) {
      settings = r;
      await refreshMe();
    }
  }

  async function changePassword(e: SubmitEvent) {
    e.preventDefault();
    if (newPw !== newPw2) return notify('Passwords do not match', 'error');
    const r = await attempt(() => api.post('/auth/password', { old_password: oldPw, new_password: newPw }), 'Password changed. Your data was not re-encrypted; only the key wrapping changed.');
    if (r === undefined) return;
    // A profile that keeps the password keeps the new one.
    if (session.profile?.has_password) {
      const p = await attempt(() => app.setProfileLogin(newPw), 'The profile keeps the new password');
      if (p) session.profile = p;
    }
    oldPw = newPw = newPw2 = '';
  }

  let exporting = $state(false);
  function exportKit() {
    exporting = true;
  }

  const switchServer = leaveServer;

  // ── Profile ──
  let profileDialog: 'save' | 'keep' | 'password' | null = $state(null);
  let pw = $state('');
  let pw2 = $state('');
  let profileBusy = $state(false);

  function closeProfileDialog() {
    profileDialog = null;
    pw = pw2 = '';
    keepError = '';
  }

  let keepError = $state('');
  async function keepPassword(e: SubmitEvent) {
    e.preventDefault();
    profileBusy = true;
    keepError = '';
    try {
      // The server checks it first: a typo kept here would only show at the next unlock.
      session.profile = await app.setProfileLogin(pw);
      notify('Unlocking the profile now logs you in', 'success');
      closeProfileDialog();
    } catch (err) {
      keepError = errorText(err);
    } finally {
      profileBusy = false;
    }
  }

  async function forgetPassword() {
    const p = await attempt(() => app.setProfileLogin(null), 'The profile no longer keeps your password');
    if (p) session.profile = p;
  }

  async function changeProfilePassword(e: SubmitEvent) {
    e.preventDefault();
    if (pw.length < 8) return notify('Use a profile password of at least 8 characters', 'error');
    if (pw !== pw2) return notify('Passwords do not match', 'error');
    profileBusy = true;
    const r = await attempt(() => app.changeProfilePassword(pw), 'Profile password changed');
    profileBusy = false;
    if (r !== undefined) closeProfileDialog();
  }

  async function setRemember() {
    await attempt(() => app.setRememberRecent(rememberRecent), rememberRecent ? 'Profiles you open are listed at start' : 'Malo no longer lists profiles you opened');
  }

  let deleting = $state(false);

  commands(() => [
    { id: 'settings-save', group: 'Settings', label: 'Save settings', keys: 'mod+s', anywhere: true, disabled: !settings || deleting, run: saveSettings },
    { id: 'settings-kit', group: 'Settings', label: 'Save recovery kit…', run: exportKit },
    { id: 'settings-switch', group: 'Settings', label: 'Switch server', run: switchServer },
  ]);

  async function deleteAccount(password: string) {
    const name = session.me!.username;
    await api.post('/me/delete', { password, confirm: `delete ${name}` });
    deleting = false;
    await app.logout(false).catch(() => undefined);
    toLogin(`The account "${name}" was deleted from this server.`);
    notify('Your account was deleted', 'success');
  }

  async function setTray() {
    await attempt(() => app.setTrayMode(tray), tray ? 'Malo keeps running in the tray when the window is closed' : 'Closing the window stops the local server');
  }
</script>

<h1>Settings</h1>

{#if settings}
  <div class="panel">
    <h2>Security</h2>
    <label>Auto-lock after (hours, max {session.me?.server_max_auto_lock_hours})
      <input type="number" min="1" max={session.me?.server_max_auto_lock_hours} bind:value={settings.auto_lock_hours} />
    </label>
    <p class="muted small">When the period ends the server wipes your keys from memory, stops running jobs at the next message and pauses schedules until you log in again. It can't be disabled; a shorter value applies immediately.</p>
    <label class="check"><input type="checkbox" class="switch" bind:checked={settings.copy_mail_credentials} /> Keep mail passwords and sign-ins in the settings copies on your destinations</label>
    <p class="muted small">Every destination holds an encrypted copy of your accounts and settings, so a restore from your recovery kit brings them back. {settings.copy_mail_credentials
      ? 'With this on, restored accounts resume backing up straight away; anyone with your kit, its passphrase and access to a destination could also read your mailboxes.'
      : 'Without them, restored accounts come back with every setting but ask you to sign in again before they back up.'}
      Whether a destination's own credentials are kept is set per destination.</p>
    <h2>Integrity checks</h2>
    <div class="cards">
      <label>Quick check every (hours, 0 = off) <input type="number" min="0" bind:value={settings.quick_check_hours} /></label>
      <label>Deep check every (hours, 0 = off) <input type="number" min="0" bind:value={settings.deep_check_hours} /></label>
    </div>
    <label class="check"><input type="checkbox" class="switch" bind:checked={settings.auto_repair} /> Repair damaged copies automatically during scheduled checks</label>
    <div class="mt-4"><button class="primary" onclick={saveSettings}>Save</button></div>
  </div>
{/if}

<div class="panel">
  <h2>Change password</h2>
  <form onsubmit={changePassword}>
    <div class="cards">
      <label>Current password <input type="password" bind:value={oldPw} required autocomplete="current-password" /></label>
      <label>New password <input type="password" bind:value={newPw} required minlength="10" autocomplete="new-password" /></label>
      <label>Repeat new password <input type="password" bind:value={newPw2} required autocomplete="new-password" /></label>
    </div>
    <button class="mt-1" type="submit">Change password</button>
  </form>
</div>

<div class="panel">
  <h2>Recovery kit</h2>
  <p class="muted">The recovery kit holds your archive key and your destinations with their credentials, encrypted with a passphrase you choose. With the kit and its passphrase you can reset a forgotten password on this server, or restore everything on a new server in one step: <em>Restore from kit</em> on the login screen sets the destinations up again and brings back your accounts, settings and mail. Kits saved by older versions are not encrypted or hold only the key: save a new one and delete the old file.</p>
  {#if session.me?.recovery_kit_outdated}
    <p class="callout">Your destinations changed since you saved the kit (added, edited or new credentials). Save a new kit so a restore needs nothing typed in.</p>
  {/if}
  <button onclick={exportKit}>Save recovery kit…</button>
</div>

{#if session.local}
  <div class="panel">
    <h2>Local server</h2>
    <label class="check"><input type="checkbox" class="switch" bind:checked={tray} onchange={setTray} /> Keep backing up in the system tray when the window is closed</label>
    <h3 class="mt-5">Data</h3>
    <LocalData />
  </div>
{/if}

<div class="panel">
  <h2>Server and profile</h2>
  <p class="small">{session.local ? 'Bundled local server' : session.url} · version {session.status?.version}</p>
  {#if session.profile}
    {@const p = session.profile}
    <div class="my-3 flex items-center gap-3 rounded-lg border border-line bg-raised px-3 py-2.5">
      <span class="grid size-9 flex-none place-items-center rounded-lg bg-accent/15 text-accent-2"><Icon name="key" size={17} /></span>
      <span class="min-w-0 flex-1">
        <span class="block truncate font-medium">Opened from {p.name}</span>
        <span class="mono block truncate text-muted" title={p.path}>{p.path}</span>
      </span>
      <span class="pill {p.has_password ? 'info' : 'muted'}" title={p.has_password ? 'Unlocking the profile logs in' : 'You log in after unlocking the profile'}>{p.has_password ? 'keeps your password' : 'username only'}</span>
    </div>
    <div class="row">
      {#if p.has_password}
        <button onclick={forgetPassword}>Forget the kept password</button>
      {:else}
        <button onclick={() => (profileDialog = 'keep')}>Keep my password in it…</button>
      {/if}
      <button onclick={() => (profileDialog = 'password')}>Change profile password…</button>
      <span class="grow"></span>
      <button onclick={switchServer}>Close profile</button>
    </div>
  {:else}
    <p class="muted">This connection isn't saved. Save it as a profile file to come back with one password; Malo itself doesn't remember servers.</p>
    <div class="row">
      <button class="primary" onclick={() => (profileDialog = 'save')}>Save as profile…</button>
      <span class="grow"></span>
      <button onclick={switchServer}>Switch server</button>
    </div>
  {/if}
  <label class="check mt-4"><input type="checkbox" class="switch" bind:checked={rememberRecent} onchange={setRemember} /> List the profiles I open at start (only their file paths are kept on this computer)</label>
</div>

<div class="panel border-bad/45!">
  <h2>Delete my account</h2>
  <p class="muted">Removes your user from {session.local ? 'the local server' : 'this server'}: your keys, accounts, destinations, index, job history and backups in local folder destinations. Backups on other destinations stay where they are, readable only with your recovery kit.</p>
  <button class="danger" onclick={() => (deleting = true)}>Delete my account…</button>
</div>

{#if deleting && session.me}
  <DangerConfirm
    title="Delete your account"
    phrase={`delete ${session.me.username}`}
    action="Delete my account"
    needsPassword
    onconfirm={deleteAccount}
    onclose={() => (deleting = false)}
  >
    <p>This permanently deletes <strong>{session.me.username}</strong> from {session.local ? 'the local server' : session.url}:</p>
    <ul class="small">
      <li>your encryption keys — the server can never decrypt your data again</li>
      <li>all email accounts, OAuth tokens, destinations and purge policies</li>
      <li>the message index, job history and audit log</li>
      <li>backups stored in <strong>local folder destinations</strong> on the server</li>
    </ul>
    <p class="small">Mail on your IMAP servers is not touched. Encrypted backups on S3, GCS, NAS and other destinations are <strong>not deleted</strong>; only your recovery kit can read them afterwards.</p>
    <button onclick={exportKit}>Save recovery kit first…</button>
  </DangerConfirm>
{/if}

{#if exporting && session.me}
  <Modal title="Save recovery kit" onclose={() => (exporting = false)}>
    <KitExport username={session.me.username} onsaved={() => ((exporting = false), void refreshMe())} />
  </Modal>
{/if}

{#if profileDialog === 'save'}
  <Modal title="Save as profile" onclose={closeProfileDialog}>
    <ProfileSave onsaved={closeProfileDialog} />
  </Modal>
{:else if profileDialog === 'keep'}
  <Modal title="Keep your password in the profile" onclose={closeProfileDialog}>
    <form onsubmit={keepPassword}>
      <p class="muted small">Unlocking the profile then logs you in. Anyone with the file and its password can unlock your backups, so its password should be as strong as this one.</p>
      <label>Your Malo password <input type="password" bind:value={pw} required autocomplete="current-password" /></label>
      {#if keepError}<p class="callout bad">{keepError}</p>{/if}
      <button class="primary mt-1" type="submit" disabled={profileBusy || !pw}>{profileBusy ? 'Checking…' : 'Keep it'}</button>
    </form>
  </Modal>
{:else if profileDialog === 'password'}
  <Modal title="Change profile password" onclose={closeProfileDialog}>
    <form onsubmit={changeProfilePassword}>
      <div class="cards">
        <label>New profile password <input type="password" bind:value={pw} required minlength="8" autocomplete="new-password" /></label>
        <label>Repeat <input type="password" bind:value={pw2} required autocomplete="new-password" /></label>
      </div>
      <button class="primary mt-1" type="submit" disabled={profileBusy}>{profileBusy ? 'Encrypting…' : 'Change password'}</button>
    </form>
  </Modal>
{/if}
