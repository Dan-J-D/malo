<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError } from '../api/client';
  import type * as T from '../api/types';
  import { session, attempt, notify, errorText } from '../state.svelte';
  import { when } from '../format';
  import { commands } from '../commands.svelte';
  import { contextMenu, copy, type Entry } from '../menu.svelte';

  let users: T.UserInfo[] = $state([]);
  let settings: T.AdminSettings | null = $state(null);
  let invite: T.Invite | null = $state(null);
  let inviteUser = $state('');
  let inviteRole: T.Role = $state('user');
  let inviteHours = $state(72);
  let mounts = $state('');
  let invites: T.InviteInfo[] = $state([]);
  let audit: T.AdminAuditEntry[] = $state([]);

  async function load() {
    if (session.me?.role !== 'admin') return;
    users = (await attempt(() => api.get<T.UserInfo[]>('/admin/users'))) ?? [];
    settings = (await attempt(() => api.get<T.AdminSettings>('/admin/settings'))) ?? null;
    mounts = settings?.allowed_fs_mounts.join('\n') ?? '';
    invites = (await attempt(() => api.get<T.InviteInfo[]>('/admin/invites'))) ?? [];
    audit = (await attempt(() => api.get<T.AdminAuditEntry[]>('/admin/audit?limit=100'))) ?? [];
  }
  onMount(load);

  // Only the fields in `patch` are sent; the rest stay as they are.
  async function update(u: T.UserInfo, patch: T.UpdateUserRequest) {
    await attempt(() => api.put(`/admin/users/${u.id}`, patch), 'User updated');
    load();
  }

  function setMaxAccounts(u: T.UserInfo, value: string) {
    const v = value.trim();
    if (v === '') return update(u, { max_accounts_default: true });
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0) return notify('Enter a whole number, or leave empty for the default', 'error');
    return update(u, { max_accounts: n });
  }

  async function remove(u: T.UserInfo) {
    if (!confirm(`Delete ${u.username} and all of their server-side data (keys, index, config)? Backups on remote destinations stay, readable only with their recovery kit. A forgotten password can be reset with the recovery kit instead.`)) return;
    try {
      await api.del(`/admin/users/${u.id}`);
    } catch (e) {
      if (!(e instanceof ApiError && e.code === 'local_backups')) return notify(errorText(e), 'error');
      // Their local folder backups would go too, and may be the only copy of mail already purged upstream.
      if (!confirm(`${e.message}\n\nDelete ${u.username} AND their local folder backups?`)) return;
      if ((await attempt(() => api.del(`/admin/users/${u.id}?delete_local_backups=true`))) === undefined) return;
    }
    notify('User deleted', 'success');
    load();
  }

  async function revokeInvite(i: T.InviteInfo) {
    if ((await attempt(() => api.del(`/admin/invites/${i.id}`), 'Invite revoked')) === undefined) return;
    // The code shown after creating may be the one just revoked (only its hash is listed).
    invite = null;
    load();
  }

  function userMenu(u: T.UserInfo): Entry[] {
    const self = u.id === session.me?.id;
    return [
      !self && { label: u.disabled ? 'Enable' : 'Disable', icon: u.disabled ? 'check' : 'ban', run: () => update(u, { disabled: !u.disabled }) },
      !self && { label: u.role === 'admin' ? 'Make regular user' : 'Make administrator', icon: 'key', run: () => update(u, { role: u.role === 'admin' ? 'user' : 'admin' }) },
      { label: 'Copy username', icon: 'copy', run: () => copy(u.username, 'Username copied') },
      '-',
      !self && { label: 'Delete user…', icon: 'x', danger: true, run: () => remove(u) },
    ];
  }

  commands(() => [
    { id: 'admin-invite', group: 'Admin', label: 'Create invite code', run: createInvite },
    { id: 'admin-save', group: 'Admin', label: 'Save server settings', keys: 'mod+s', anywhere: true, disabled: !settings, run: saveSettings },
    { id: 'admin-copy-invite', group: 'Admin', label: 'Copy invite code', disabled: !invite, run: () => invite && copy(invite.code, 'Invite code copied') },
  ]);

  async function createInvite() {
    invite = (await attempt(() => api.post<T.Invite>('/admin/invites', { username: inviteUser || null, role: inviteRole, valid_hours: inviteHours }))) ?? null;
    if (invite) load();
  }

  function auditText(e: T.AdminAuditEntry): string {
    return e.detail && typeof e.detail === 'object' && Object.keys(e.detail).length ? JSON.stringify(e.detail) : '';
  }

  async function saveSettings() {
    if (!settings) return;
    settings.allowed_fs_mounts = mounts.split('\n').map((s) => s.trim()).filter(Boolean);
    const r = await attempt(() => api.put<T.AdminSettings>('/admin/settings', settings), 'Server settings saved');
    if (r) {
      settings = r;
      load();
    }
  }
</script>

<h1>Administration</h1>
<p class="muted">Administrators manage users and limits. They cannot read anyone's mail or decrypt their backups.</p>

<div class="panel">
  <h2>Users</h2>
  <table>
    <thead><tr><th>User</th><th>Role</th><th>Created</th><th>Status</th><th>Max accounts</th><th></th></tr></thead>
    <tbody>
      {#each users as u (u.id)}
        <tr tabindex="0" {@attach contextMenu(() => userMenu(u))}>
          <td>{u.username}</td>
          <td>
            <select value={u.role} disabled={u.id === session.me?.id} onchange={(e) => update(u, { role: (e.target as HTMLSelectElement).value as T.Role })}>
              <option value="user">user</option><option value="admin">admin</option>
            </select>
          </td>
          <td class="small">{when(u.created_at)}</td>
          <td>{#if u.disabled}<span class="pill bad">disabled</span>{:else if u.unlocked}<span class="pill ok">unlocked</span>{:else}<span class="pill muted">sealed</span>{/if}</td>
          <td><input type="number" min="0" style="width: 6rem" value={u.max_accounts ?? ''} placeholder={settings ? String(settings.default_max_accounts) : ''} title="Empty: follows the server default" onchange={(e) => setMaxAccounts(u, (e.target as HTMLInputElement).value)} /></td>
          <td class="right">
            {#if u.id !== session.me?.id}
              <button onclick={() => update(u, { disabled: !u.disabled })}>{u.disabled ? 'Enable' : 'Disable'}</button>
              <button onclick={() => remove(u)}>Delete</button>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<div class="panel">
  <h2>Invite a user</h2>
  <div class="cards">
    <label>Username (optional) <input bind:value={inviteUser} /></label>
    <label>Role <select bind:value={inviteRole}><option value="user">user</option><option value="admin">admin</option></select></label>
    <label>Valid for (hours) <input type="number" min="1" bind:value={inviteHours} /></label>
  </div>
  <button onclick={createInvite}>Create invite code</button>
  {#if invite}<p class="callout ok">Invite code (single use, until {when(invite.expires_at)}): <span class="mono">{invite.code}</span> <button class="link" onclick={() => copy(invite!.code, 'Invite code copied')}>Copy</button><br /><span class="small muted">The code is shown only now; the server keeps just a hash of it.</span></p>{/if}
  {#if invites.length}
    <h3 class="mt-5">Open and recent invites</h3>
    <table>
      <thead><tr><th>For</th><th>Role</th><th>Expires</th><th>Status</th><th></th></tr></thead>
      <tbody>
        {#each invites as i (i.id)}
          {@const expired = new Date(i.expires_at) < new Date()}
          <tr tabindex="0" {@attach contextMenu(() => [!i.used && !expired && { label: 'Revoke invite', icon: 'x', danger: true, run: () => revokeInvite(i) }])}>
            <td>{i.username ?? 'anyone'}</td>
            <td>{i.role}</td>
            <td class="small">{when(i.expires_at)}</td>
            <td>{#if i.used}<span class="pill muted">used</span>{:else if expired}<span class="pill muted">expired</span>{:else}<span class="pill ok">open</span>{/if}</td>
            <td class="right">{#if !i.used && !expired}<button onclick={() => revokeInvite(i)}>Revoke</button>{/if}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if settings}
  <div class="panel">
    <h2>Server settings</h2>
    <div class="cards">
      <label>Maximum auto-lock (hours) <input type="number" min="1" bind:value={settings.max_auto_lock_hours} /></label>
      <label>Default max accounts per user <input type="number" min="1" bind:value={settings.default_max_accounts} /></label>
      <label>Concurrent jobs per user <input type="number" min="1" max="16" bind:value={settings.max_jobs_per_user} /></label>
    </div>
    <label class="check"><input type="checkbox" bind:checked={settings.self_registration} /> Allow self-registration without an invite</label>
    <label class="check"><input type="checkbox" bind:checked={settings.block_private_networks} /> Block mail servers and storage on private networks (loopback, LAN, link-local)</label>
    <p class="muted small">Turn this on when users you don't fully trust share the server: otherwise their accounts and destinations can make the server connect to hosts on its own network. Leave it off if users back up a mail server or MinIO on the LAN.</p>
    <label>Extra folders users may use for "fs" destinations (absolute paths, one per line)
      <textarea rows="3" bind:value={mounts} placeholder="/mnt/nas"></textarea>
    </label>
    <button class="primary" onclick={saveSettings}>Save</button>
  </div>
{/if}

<div class="panel">
  <h2>Admin log</h2>
  {#if audit.length === 0}<p class="muted">No administrative actions yet.</p>{:else}
    <table>
      <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
      <tbody>
        {#each audit as e (e.id)}
          <tr><td class="small">{when(e.at)}</td><td>{e.actor}</td><td>{e.action.replaceAll('_', ' ')}</td><td>{e.target ?? '—'}</td><td class="small muted mono">{auditText(e)}</td></tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
