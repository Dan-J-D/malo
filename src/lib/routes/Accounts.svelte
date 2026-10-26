<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { api, app, ApiError } from '../api/client';
  import type * as T from '../api/types';
  import { live, route, go, attempt, refreshAccounts, errorText, notify } from '../state.svelte';
  import { ago, bytes } from '../format';
  import { commands } from '../commands.svelte';
  import { contextMenu } from '../menu.svelte';
  import { accountMenu, removeAccount } from '../actions';
  import MailAccess from '../components/MailAccess.svelte';

  let presets: T.AccountPreset[] = $state([]);
  onMount(async () => {
    presets = (await attempt(() => api.get<T.AccountPreset[]>('/presets'))) ?? [];
  });

  // Wizard: preset → auth → test → policy hint
  const editingId = $derived(route.path.startsWith('/accounts/edit/') ? route.path.split('/')[3] : null);
  const mailFor = $derived(route.path.startsWith('/accounts/mail/') ? live.accounts.find((a) => a.id === route.path.split('/')[3]) ?? null : null);
  const wizard = $derived(route.path === '/accounts/new' || !!editingId);
  let step = $state(1);
  let preset: T.AccountPreset | null = $state(null);
  let authKind: 'password' | 'oauth2' = $state('password');
  let form: T.AccountInput = $state(blank());
  let oauth = $state({ provider: 'custom' as T.OAuthProvider, auth_url: '', token_url: '', client_id: '', client_secret: '', scopes: '', refresh_token: '' });
  let password = $state('');
  // Outgoing server for mail sent from mail apps through Malo (same sign-in as IMAP).
  let sending = $state(false);
  let smtp: T.SmtpSettings = $state({ host: '', port: 465, tls: 'implicit' });
  let test: T.ConnectionTest | null = $state(null);
  let busy = $state(false);
  let error = $state('');

  // Only the fields that decide how Malo signs in need a passing connection test before saving;
  // a new name, schedule or IDLE setting saves as is. Editing a sign-in field after a test
  // asks for a new one, so a stale test never vouches for different settings.
  const signInKey = $derived(JSON.stringify([form.host, form.port, form.tls, form.username, form.accept_invalid_certs, authKind,
    authKind === 'password' ? password : [oauth.provider, oauth.auth_url, oauth.token_url, oauth.client_id, oauth.client_secret, oauth.scopes, oauth.refresh_token]]));
  let loadedKey = $state<string | null>(null);
  let testedKey = $state<string | null>(null);
  const editing = $derived(editingId ? live.accounts.find((x) => x.id === editingId) ?? null : null);
  // An imported account has no working sign-in yet, so its saved settings vouch for nothing.
  const verified = $derived(signInKey === testedKey || (!!editing && !editing.imported && signInKey === loadedKey));
  // The server reuses a saved secret only for the same server and login: moving it elsewhere
  // must not hand the old password to a new host.
  const secretMoved = $derived(!!editing && !editing.imported && movedFrom(editing) && keptSecret(editing));
  function movedFrom(a: T.AccountView): boolean {
    if (form.host.trim() !== a.host || form.port !== a.port || form.username.trim() !== a.username || form.tls !== a.tls) return true;
    if (form.accept_invalid_certs && !a.accept_invalid_certs) return true;
    if (sending && (!a.smtp || smtp.host.trim() !== a.smtp.host || smtp.port !== a.smtp.port || smtp.tls !== a.smtp.tls)) return true;
    const o = a.auth;
    return o.kind === 'oauth2' && authKind === 'oauth2'
      && (oauth.provider !== o.provider || oauth.auth_url !== o.auth_url || oauth.token_url !== o.token_url || oauth.client_id !== o.client_id);
  }
  function keptSecret(a: T.AccountView): boolean {
    const o = a.auth;
    if (o.kind === 'password') return authKind === 'password' && password === o.password;
    return authKind === 'oauth2' && oauth.refresh_token === o.refresh_token;
  }
  let loadedFor = $state<string | null>(null);

  function blank(): T.AccountInput {
    return { revision: null, name: '', host: '', port: 993, tls: 'implicit', accept_invalid_certs: false, username: '', auth: { kind: 'password', password: '' }, backup_interval_minutes: 30, idle: true, enabled: true };
  }

  $effect(() => {
    if (editingId && loadedFor !== editingId) {
      const a = live.accounts.find((x) => x.id === editingId);
      if (a) {
        loadedFor = editingId;
        form = { revision: a.revision, name: a.name, host: a.host, port: a.port, tls: a.tls, accept_invalid_certs: a.accept_invalid_certs, username: a.username, auth: a.auth, backup_interval_minutes: a.backup_interval_minutes, idle: a.idle, enabled: a.enabled };
        sending = !!a.smtp;
        smtp = a.smtp ? { ...a.smtp } : { host: '', port: 465, tls: 'implicit' };
        authKind = a.auth.kind;
        if (a.auth.kind === 'password') password = a.auth.password;
        else oauth = { provider: a.auth.provider, auth_url: a.auth.auth_url, token_url: a.auth.token_url, client_id: a.auth.client_id, client_secret: a.auth.client_secret ?? '', scopes: a.auth.scopes.join(' '), refresh_token: a.auth.refresh_token };
        step = 2;
        // The saved settings already work; changing only the name or schedule needs no test.
        loadedKey = untrack(() => signInKey);
      }
    }
  });

  function pick(p: T.AccountPreset) {
    preset = p;
    form = { ...blank(), name: p.id === 'custom' ? '' : p.name, host: p.host, port: p.port, tls: p.tls };
    if (p.oauth) {
      oauth = { ...oauth, provider: p.oauth.provider, auth_url: p.oauth.auth_url, token_url: p.oauth.token_url, scopes: p.oauth.scopes.join(' ') };
    }
    authKind = p.id === 'outlook' ? 'oauth2' : 'password';
    sending = !!p.smtp;
    smtp = p.smtp ? { ...p.smtp } : { host: '', port: 465, tls: 'implicit' };
    step = 2;
  }

  function input(): T.AccountInput {
    const auth: T.AccountAuth = authKind === 'password'
      ? { kind: 'password', password }
      : { kind: 'oauth2', provider: oauth.provider, auth_url: oauth.auth_url, token_url: oauth.token_url, client_id: oauth.client_id, client_secret: oauth.client_secret || null, scopes: oauth.scopes.split(/\s+/).filter(Boolean), refresh_token: oauth.refresh_token };
    return { ...form, auth, smtp: sending && smtp.host.trim() ? { ...smtp, host: smtp.host.trim() } : undefined };
  }

  async function signIn() {
    error = '';
    busy = true;
    try {
      const r = await app.oauthAuthorize({
        provider: oauth.provider, auth_url: oauth.auth_url, token_url: oauth.token_url, client_id: oauth.client_id,
        client_secret: oauth.client_secret || null, scopes: oauth.scopes.split(/\s+/).filter(Boolean), login_hint: form.username || null,
      });
      oauth.refresh_token = r.refresh_token;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function runTest() {
    busy = true;
    error = '';
    test = null;
    try {
      const key = signInKey;
      test = await api.post<T.ConnectionTest>(`/accounts/test${editingId ? `?id=${editingId}` : ''}`, input());
      if (test.ok) testedKey = key;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function save() {
    busy = true;
    try {
      await (editingId ? api.put(`/accounts/${editingId}`, input()) : api.post<T.AccountView>('/accounts', input()));
      notify('Account saved', 'success');
      await refreshAccounts();
      close();
    } catch (e) {
      notify(errorText(e), 'error');
      // Edited on another device meanwhile: reload so the form shows the current values.
      if (e instanceof ApiError && e.status === 409) {
        await refreshAccounts();
        loadedFor = null;
      }
    } finally {
      busy = false;
    }
  }

  function close() {
    step = 1;
    preset = null;
    form = blank();
    password = '';
    sending = false;
    smtp = { host: '', port: 465, tls: 'implicit' };
    test = null;
    loadedFor = loadedKey = testedKey = null;
    go('/accounts');
  }

  commands(() => wizard
    ? [
        { id: 'account-cancel', group: 'Account', label: 'Cancel', keys: 'escape', run: close },
        { id: 'account-test', group: 'Account', label: 'Test connection', keys: 'mod+t', anywhere: true, disabled: busy || step === 1, run: runTest },
        { id: 'account-save', group: 'Account', label: verified ? (editingId ? 'Save changes' : 'Add account') : 'Test connection', keys: 'mod+enter, mod+s', anywhere: true,
          disabled: busy || step === 1 || (verified && !form.name.trim()), run: () => (verified ? save() : runTest()) },
        ...presets.map((p) => ({ id: `preset-${p.id}`, group: 'Provider', label: p.name, disabled: step !== 1, run: () => pick(p) })),
      ]
    : [
        { id: 'account-new', group: 'Accounts', label: 'Add account', keys: 'n', run: () => go('/accounts/new') },
        ...live.accounts.map((a) => ({ id: `edit-${a.id}`, group: 'Accounts', label: `Edit ${a.name}`, run: () => go(`/accounts/edit/${a.id}`) })),
        ...live.accounts.map((a) => ({ id: `mail-${a.id}`, group: 'Accounts', label: `Mail app access for ${a.name}`, run: () => go(`/accounts/mail/${a.id}`) })),
      ]);
</script>

{#if mailFor}
  <MailAccess account={mailFor} onclose={() => go('/accounts')} />
{/if}

{#if !wizard}
  <div class="row"><h1 class="grow">Accounts</h1><button class="primary" onclick={() => go('/accounts/new')}>Add account</button></div>
  <div class="panel">
    <table>
      <thead><tr><th>Name</th><th>Server</th><th>Auth</th><th>Schedule</th><th>Last backup</th><th>Stored</th><th></th></tr></thead>
      <tbody>
        {#each live.accounts as a}
          <tr tabindex="0" class="clickable" {@attach contextMenu(() => accountMenu(a))}
            ondblclick={() => go(`/accounts/edit/${a.id}`)} onkeydown={(e) => e.key === 'Enter' && e.target === e.currentTarget && go(`/accounts/edit/${a.id}`)}>
            <td><strong>{a.name}</strong>{#if a.imported} <span class="pill muted">imported</span>{/if}</td>
            <td class="small">{a.username}<br /><span class="muted">{a.host}:{a.port} · {a.tls}</span></td>
            <td>{a.auth.kind === 'oauth2' ? `OAuth2 (${a.auth.provider})` : 'Password'}</td>
            <td class="small">every {a.backup_interval_minutes} min{a.idle ? ' + IDLE' : ''}{a.enabled ? '' : ' (paused)'}</td>
            <td class="small">{ago(a.last_backup)}</td>
            <td class="small">{Number(a.message_count).toLocaleString()} · {bytes(a.stored_bytes)}</td>
            <td class="right">
              <button onclick={() => go(`/accounts/edit/${a.id}`)}>{a.imported ? 'Set up sign-in' : 'Edit'}</button>
              <button onclick={() => go(`/accounts/mail/${a.id}`)} title="Read and send this account's mail in Apple Mail or another IMAP app">Mail app</button>
              <button onclick={() => removeAccount(a)}>Remove</button>
            </td>
          </tr>
        {:else}
          <tr><td colspan="7" class="muted">No accounts yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
{:else}
  <div class="row"><h1 class="grow">{editingId ? 'Edit account' : 'Add account'}</h1><button onclick={close}>Cancel</button></div>
  {#if editing?.imported}<p class="callout">This account was found on a destination without working sign-in details. Enter them and test the connection to resume backups: it keeps its id, folders and backed-up mail.</p>{/if}
  <p class="muted small">Step {step === 1 ? 1 : verified ? 3 : 2} of 3: {step === 1 ? 'provider' : verified ? 'save' : 'sign-in'}</p>

  {#if step === 1}
    <div class="cards">
      {#each presets as p}
        <button class="panel flex-col items-start! gap-1 text-left" onclick={() => pick(p)}>
          <strong>{p.name}</strong>
          <span class="muted small">{p.host || 'Enter server details'}</span>
          {#if p.oauth}<span class="pill info">OAuth2</span>{/if}
        </button>
      {/each}
    </div>
  {:else}
    <div class="panel">
      <div class="cards">
        <label>Name <input bind:value={form.name} placeholder="Work mail" /></label>
        <label>Email / username <input bind:value={form.username} autocomplete="off" /></label>
        <label>IMAP host <input bind:value={form.host} /></label>
        <label>Port <input type="number" bind:value={form.port} /></label>
        <label>Security
          <select bind:value={form.tls}><option value="implicit">TLS (port 993)</option><option value="starttls">STARTTLS (port 143)</option></select>
        </label>
        <label>Backup every (minutes) <input type="number" min="1" bind:value={form.backup_interval_minutes} /></label>
      </div>
      <label class="check"><input type="checkbox" bind:checked={form.idle} /> Watch INBOX with IMAP IDLE for near-real-time backups</label>
      <label class="check"><input type="checkbox" bind:checked={form.enabled} /> Scheduled backups enabled</label>
      <label class="check"><input type="checkbox" bind:checked={form.accept_invalid_certs} /> Accept invalid server certificates <span class="muted">(test servers only — unsafe)</span></label>

      <h3>Outgoing mail</h3>
      <label class="check"><input type="checkbox" bind:checked={sending} /> Send mail from mail apps through this account's SMTP server <span class="muted">(signs in like IMAP)</span></label>
      {#if sending}
        <div class="cards">
          <label>SMTP host <input bind:value={smtp.host} placeholder="smtp.example.com" /></label>
          <label>Port <input type="number" bind:value={smtp.port} /></label>
          <label>Security
            <select bind:value={smtp.tls} onchange={() => (smtp.port = smtp.tls === 'implicit' ? 465 : 587)}><option value="implicit">TLS (port 465)</option><option value="starttls">STARTTLS (port 587)</option></select>
          </label>
        </div>
        {#if authKind === 'oauth2' && oauth.provider === 'microsoft'}<p class="muted small">Microsoft needs the <code>https://outlook.office.com/SMTP.Send</code> scope as well: add it to the scopes and sign in again.</p>{/if}
      {/if}

      <h3>Authentication</h3>
      <div class="row">
        <label class="check"><input type="radio" bind:group={authKind} value="password" /> Password / app password</label>
        <label class="check"><input type="radio" bind:group={authKind} value="oauth2" /> OAuth2 (your own client ID)</label>
      </div>
      {#if authKind === 'password'}
        {#if preset?.app_password_hint}<p class="callout small">{preset.app_password_hint}</p>{/if}
        <label>Password <input type="password" bind:value={password} autocomplete="new-password" /></label>
      {:else}
        <details class="small" open={!oauth.client_id}>
          <summary>How to create your own OAuth client</summary>
          {#if oauth.provider === 'google'}
            <ol>
              <li>In Google Cloud Console create a project and enable the Gmail API.</li>
              <li>Configure the OAuth consent screen (External, add yourself as a test user) with scope <code>https://mail.google.com/</code>.</li>
              <li>Create an OAuth client ID of type <strong>Desktop app</strong>. Copy the client ID and secret here.</li>
            </ol>
          {:else if oauth.provider === 'microsoft'}
            <ol>
              <li>In the Azure portal → App registrations → New registration. Account type: personal + work accounts.</li>
              <li>Add the platform <strong>Mobile and desktop applications</strong> with redirect URI <code>http://localhost</code>.</li>
              <li>API permissions: Office 365 Exchange Online / <code>IMAP.AccessAsUser.All</code> and <code>offline_access</code>. Copy the Application (client) ID here; no secret needed.</li>
            </ol>
          {:else}
            <p>Register a native/desktop client with a loopback redirect (<code>http://127.0.0.1</code>) and PKCE.</p>
          {/if}
        </details>
        <div class="cards">
          <label>Client ID <input bind:value={oauth.client_id} /></label>
          <label>Client secret <input bind:value={oauth.client_secret} placeholder="optional for public clients" /></label>
          {#if oauth.provider === 'custom'}
            <label>Authorization URL <input bind:value={oauth.auth_url} /></label>
            <label>Token URL <input bind:value={oauth.token_url} /></label>
          {/if}
          <label>Scopes <input bind:value={oauth.scopes} /></label>
        </div>
        <div class="row">
          <button onclick={signIn} disabled={busy || !oauth.client_id}>Sign in with browser…</button>
          {#if oauth.refresh_token}<span class="pill ok">authorized</span>{/if}
        </div>
      {/if}
      {#if secretMoved}<p class="callout small">The server, login or provider changed: enter the {authKind === 'password' ? 'password' : 'sign-in'} again. Saved secrets are only reused for the same server and login.</p>{/if}
      {#if error}<p class="callout bad">{error}</p>{/if}
      {#if test}
        <div class="callout" class:ok={test.ok} class:bad={!test.ok}>
          {#if test.ok}
            Connected. {test.mailboxes.length} mailboxes{test.gmail ? ' (Gmail: All Mail, Spam and Trash are backed up, labels preserved)' : ''}.
            {#each test.warnings as w}<div><strong>⚠ {w}</strong></div>{/each}
          {:else}Connection failed: {test.error}{/if}
        </div>
      {/if}
      <div class="row" style="margin-top: 1rem">
        <button onclick={runTest} disabled={busy}>Test connection</button>
        <button class="primary" disabled={busy || !verified || !form.name.trim()} onclick={save}>{editingId ? 'Save changes' : 'Add account'}</button>
        {#if !verified}<span class="muted small">{editing?.imported ? 'Test the connection to resume backups.' : editingId ? 'Sign-in settings changed: test the connection to save.' : 'Test the connection to continue.'}</span>{/if}
      </div>
      {#if verified && !editingId}<p class="muted small">After adding: set up a retention rule on the Purge page if you want Malo to delete old mail from the server.</p>{/if}
    </div>
  {/if}
{/if}

