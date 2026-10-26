<script lang="ts">
  import { onMount } from 'svelte';
  import { api, app } from '../api/client';
  import type * as T from '../api/types';
  import { session, attempt, notify, refreshMe, errorText } from '../state.svelte';
  import LocalData from '../components/LocalData.svelte';
  import DangerConfirm from '../components/DangerConfirm.svelte';
  import Modal from '../components/Modal.svelte';
  import KitExport from '../components/KitExport.svelte';
  import { commands } from '../commands.svelte';

  let settings: T.UserSettings | null = $state(null);
  let oldPw = $state('');
  let newPw = $state('');
  let newPw2 = $state('');
  let tray = $state(false);

  onMount(async () => {
    settings = (await attempt(() => api.get<T.UserSettings>('/settings'))) ?? null;
    tray = (await app.prefs().catch(() => null))?.tray_mode ?? false;
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
    if (r !== undefined) oldPw = newPw = newPw2 = '';
  }

  let exporting = $state(false);
  function exportKit() {
    exporting = true;
  }

  async function switchServer() {
    await app.logout(false).catch(() => undefined);
    try {
      await app.disconnect();
    } catch (e) {
      notify(errorText(e), 'error');
    }
    session.me = null;
    session.phase = 'connect';
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
    session.me = null;
    session.lockedReason = `The account "${name}" was deleted from this server.`;
    session.phase = 'login';
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
  <p class="muted">The recovery kit holds your archive key, encrypted with a passphrase you choose. With the kit and its passphrase you can reset a forgotten password on this server, or read all your encrypted backups from a new account. Kits saved by older versions are not encrypted: save a new one and delete the old file.</p>
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
  <h2>Server</h2>
  <p class="small">{session.local ? 'Bundled local server' : session.url} · version {session.status?.version}</p>
  <button onclick={switchServer}>Switch server</button>
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
    <KitExport username={session.me.username} onsaved={() => (exporting = false)} />
  </Modal>
{/if}
