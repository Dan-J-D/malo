<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError } from '../api/client';
  import type * as T from '../api/types';
  import { session, errorText, notify } from '../state.svelte';
  import { copy } from '../menu.svelte';
  import { ago } from '../format';
  import Modal from './Modal.svelte';

  // The IMAP/SMTP login of one account: a username the user picks and a password the server
  // generates, shown once. It is separate from the Malo password, so a mail app never holds
  // the password that unlocks every key.
  let { account, onclose }: { account: T.AccountView; onclose: () => void } = $props();

  let info = $state<T.MailAccessInfo | null>(null);
  let created = $state<T.MailLoginCreated | null>(null);
  let username = $state('');
  let length = $state(24);
  let busy = $state(false);
  let error = $state('');
  let editing = $state(false);
  let view = $state<T.MailViewInfo | null>(null);

  const ROLES: Record<string, string> = {
    '\\Sent': 'Sent', '\\Drafts': 'Drafts', '\\Junk': 'Spam', '\\Trash': 'Trash', '\\All': 'All mail',
    '\\Archive': 'Archive', '\\Flagged': 'Starred', '\\Important': 'Important',
  };
  function role(f: T.MailFolderInfo): string {
    if (f.kind === 'primary') return 'Primary';
    if (f.kind === 'category') return 'Category';
    return (f.special_use && ROLES[f.special_use]) || (f.kind === 'label' ? 'Label' : '');
  }

  const login = $derived(info?.logins.find((l) => l.account_id === account.id) ?? null);
  const host = $derived.by(() => {
    try {
      return new URL(session.url).hostname;
    } catch {
      return '';
    }
  });
  const enabled = $derived(!!info && (info.imap_port !== null || info.smtp_port !== null));

  onMount(load);

  async function load() {
    try {
      info = await api.get<T.MailAccessInfo>('/mail-access');
      const l = info.logins.find((x) => x.account_id === account.id);
      username = l?.username ?? suggest(account.name);
      view = await api.get<T.MailViewInfo>(`/accounts/${account.id}/mail-view`);
    } catch (e) {
      error = errorText(e);
    }
  }

  function suggest(name: string): string {
    const s = name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    return s.length >= 3 ? s : `mail-${s || 'account'}`;
  }

  async function save() {
    busy = true;
    error = '';
    try {
      created = await api.put<T.MailLoginCreated>(`/accounts/${account.id}/mail-login`, { username, password_length: length } satisfies T.MailLoginRequest);
      editing = false;
      await load();
    } catch (e) {
      error = e instanceof ApiError && e.status === 409 ? `“${username}” is taken: pick another username.` : errorText(e);
    } finally {
      busy = false;
    }
  }

  async function remove() {
    if (!confirm(`Remove the mail login “${login?.username}”? Mail apps using it are signed out.`)) return;
    busy = true;
    try {
      await api.del(`/accounts/${account.id}/mail-login`);
      created = null;
      notify('Mail login removed', 'success');
      await load();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function saveView(split: boolean, hidden: string[]) {
    try {
      view = await api.put<T.MailViewInfo>(`/accounts/${account.id}/mail-view`, { split_categories: split, hidden } satisfies T.MailViewSettings);
    } catch (e) {
      error = errorText(e);
    }
  }

  function toggle(f: T.MailFolderInfo, shown: boolean) {
    if (!view) return;
    const hidden = view.folders.filter((x) => (x.name === f.name ? !shown : !x.shown)).map((x) => x.name);
    saveView(view.split_categories, hidden);
  }

  async function resetView() {
    if (!confirm('Show every backed-up message in mail apps again? Messages deleted or moved to other folders in a mail app go back where they were, flags set there are cleared, and mail apps download the folders again.')) return;
    try {
      await api.post(`/accounts/${account.id}/mail-view/reset`);
      notify('Mail apps will show every message again', 'success');
    } catch (e) {
      error = errorText(e);
    }
  }
</script>

<Modal title={`Mail app access · ${account.name}`} {onclose}>
  {#if !info && !error}
    <p class="muted">Loading…</p>
  {:else if info && !enabled}
    <p>This server doesn't run its IMAP and SMTP services. The administrator turns them on with
      <code>MALO_IMAP_LISTEN</code> and <code>MALO_SMTP_LISTEN</code> (for example <code>0.0.0.0:1993</code> and <code>0.0.0.0:1465</code>) and publishes those ports.</p>
  {:else if info}
    <p class="small">Read this account's backed-up mail in Apple Mail or any IMAP app, including mail already purged from the server, and reply or forward through the account's own outgoing server. The mail app gets its own login: never your Malo password.</p>

    {#if created}
      <div class="callout ok">
        <p><strong>Copy the password now.</strong> Malo keeps only a hash of it and can't show it again; you can always make a new one.</p>
        <div class="row"><span class="grow">Username <code>{created.login.username}</code></span><button onclick={() => copy(created!.login.username, 'Username copied')}>Copy</button></div>
        <div class="row"><span class="grow">Password <code class="mono">{created.password}</code></span><button onclick={() => copy(created!.password, 'Password copied')}>Copy</button></div>
      </div>
    {/if}

    {#if login && !editing}
      <div class="row">
        <span class="grow">Login <code>{login.username}</code> <span class="muted small">· created {ago(login.created_at)} · {login.last_used ? `last used ${ago(login.last_used)}` : 'never used'}</span></span>
      </div>
      <div class="row">
        <button disabled={busy} onclick={save}>New password</button>
        <button disabled={busy} onclick={() => (editing = true)}>Change username…</button>
        <button disabled={busy} onclick={remove}>Remove login</button>
      </div>
    {:else}
      <div class="cards">
        <label>Username <input bind:value={username} autocomplete="off" spellcheck="false" placeholder="work-mail" /></label>
        <label>Password length
          <select bind:value={length}><option value={20}>20</option><option value={24}>24</option><option value={32}>32</option><option value={48}>48</option><option value={64}>64</option></select>
        </label>
      </div>
      <p class="muted small">Letters, digits and <code>. _ - + @</code>; unique on this server. The password is random letters and digits.</p>
      <div class="row">
        <button class="primary" disabled={busy || username.trim().length < 3} onclick={save}>{login ? 'Save username and make a new password' : 'Create login'}</button>
        {#if editing}<button onclick={() => (editing = false)}>Cancel</button>{/if}
      </div>
    {/if}
    {#if error}<p class="callout bad">{error}</p>{/if}

    {#if login}
      <h3>Settings for the mail app</h3>
      <table class="small">
        <tbody>
          {#if info.imap_port !== null}<tr><td>Incoming (IMAP)</td><td><code>{host || 'this server'}</code> port <code>{info.imap_port}</code>, SSL/TLS on</td></tr>{/if}
          {#if info.smtp_port !== null}<tr><td>Outgoing (SMTP)</td><td><code>{host || 'this server'}</code> port <code>{info.smtp_port}</code>, SSL/TLS on</td></tr>{/if}
          <tr><td>Username / password</td><td>the mail login above, for both</td></tr>
          {#if info.fingerprint}<tr><td>Certificate SHA-256</td><td class="mono" style="word-break: break-all">{info.fingerprint}</td></tr>{/if}
        </tbody>
      </table>
      {#if view}
        <h3>Folders</h3>
        <p class="muted small">Choose what the mail app shows. Moving a message in the mail app (to Spam, a category, Trash or any folder) files it there in Malo's view; the backup and the mail server stay as they are.</p>
        {#if view.gmail}
          <label class="check"><input type="checkbox" checked={view.split_categories} onchange={(e) => view && saveView((e.target as HTMLInputElement).checked, view.folders.filter((x) => !x.shown).map((x) => x.name))} />
            Separate Gmail categories: INBOX shows Primary; Social, Promotions, Updates and Forums get folders of their own</label>
        {/if}
        <table class="small">
          <thead><tr><th>Show</th><th>Folder</th><th></th><th class="right">Messages</th></tr></thead>
          <tbody>
            {#each view.folders as f (f.name)}
              <tr>
                <td><input type="checkbox" checked={f.shown} disabled={f.name.toUpperCase() === 'INBOX'} onchange={(e) => toggle(f, (e.target as HTMLInputElement).checked)} aria-label={`Show ${f.display_name}`} /></td>
                <td>{f.display_name}</td>
                <td>{#if role(f)}<span class="pill muted">{role(f)}</span>{/if}</td>
                <td class="right tabular-nums">{Number(f.messages).toLocaleString()}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if view.gmail && view.split_categories}<p class="muted small">Categories come from Gmail with each backup (all of them every 6 hours). Gmail doesn't let other apps change a message's category, so filing one into a category in the mail app only changes it here.</p>{/if}
      {/if}

      {#if !account.smtp}<p class="callout small">Sending isn't set up for this account yet: add its outgoing (SMTP) server under <em>Edit account</em>.</p>{/if}
      <details class="small">
        <summary>Apple Mail step by step</summary>
        <ol>
          <li>Mail → Settings → Accounts → <strong>+</strong> → <em>Other Mail Account…</em>. Enter a name, the account's email address and the mail login's password.</li>
          <li>When Mail can't find the server, enter the username above, account type <strong>IMAP</strong>, and <code>{host || 'this server'}</code> as incoming and outgoing server.</li>
          <li>In the account's <em>Server Settings</em>, turn off <em>Automatically manage connection settings</em>, set the ports above and keep <em>Use TLS/SSL</em> on.</li>
          <li>If Mail warns that it can't verify the server's identity, compare the certificate's SHA-256 fingerprint with the one shown here before trusting it.</li>
          <li>Under <em>Mailbox Behaviors</em>, turn off <em>Store draft messages on the server</em>: drafts aren't kept on the backup server.</li>
        </ol>
        <p>Mail is readable while you're unlocked in Malo. After the auto-lock, mail apps show a sign-in error until you log in to Malo again.</p>
        <p>The backup itself never changes from a mail app. Flags, deleting and moving between folders only change what mail apps see here; <button class="link" onclick={resetView}>show every message again</button>.</p>
      </details>
    {/if}
  {:else}
    <p class="callout bad">{error}</p>
  {/if}
</Modal>
