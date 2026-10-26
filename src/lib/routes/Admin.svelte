<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { session, attempt } from '../state.svelte';
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

  async function load() {
    if (session.me?.role !== 'admin') return;
    users = (await attempt(() => api.get<T.UserInfo[]>('/admin/users'))) ?? [];
    settings = (await attempt(() => api.get<T.AdminSettings>('/admin/settings'))) ?? null;
    mounts = settings?.allowed_fs_mounts.join('\n') ?? '';
  }
  onMount(load);

  async function update(u: T.UserInfo, patch: Partial<T.UpdateUserRequest>) {
    await attempt(() => api.put(`/admin/users/${u.id}`, { disabled: null, role: null, max_accounts: null, ...patch }), 'User updated');
    load();
  }

  async function remove(u: T.UserInfo) {
    if (!confirm(`Delete ${u.username} and all of their server-side data (index, config, local fs backups)? Remote destinations are untouched.`)) return;
    await attempt(() => api.del(`/admin/users/${u.id}`), 'User deleted');
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
  }

  async function saveSettings() {
    if (!settings) return;
    settings.allowed_fs_mounts = mounts.split('\n').map((s) => s.trim()).filter(Boolean);
    const r = await attempt(() => api.put<T.AdminSettings>('/admin/settings', settings), 'Server settings saved');
    if (r) settings = r;
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
          <td><input type="number" min="0" style="width: 6rem" value={u.max_accounts ?? ''} onchange={(e) => update(u, { max_accounts: Number((e.target as HTMLInputElement).value) })} /></td>
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
  {#if invite}<p class="callout ok">Invite code (single use, until {when(invite.expires_at)}): <span class="mono">{invite.code}</span> <button class="link" onclick={() => copy(invite!.code, 'Invite code copied')}>Copy</button></p>{/if}
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
    <label>Extra folders users may use for "fs" destinations (absolute paths, one per line)
      <textarea rows="3" bind:value={mounts} placeholder="/mnt/nas"></textarea>
    </label>
    <button class="primary" onclick={saveSettings}>Save</button>
  </div>
{/if}
