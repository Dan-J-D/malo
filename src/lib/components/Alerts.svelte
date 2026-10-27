<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, notify, errorText } from '../state.svelte';
  import Select from './Select.svelte';

  // Where Malo reports trouble: failing backups, damaged copies, broken sign-ins, unreachable
  // destinations and jobs skipped while locked. Each problem is sent once, and once more when
  // it's over.
  let s = $state<T.AlertSettings | null>(null);
  let busy = $state(false);
  let error = $state('');
  let results = $state<T.AlertDelivery[] | null>(null);

  const senders = $derived(live.accounts.filter((a) => a.smtp && !a.imported));
  const KINDS: { value: T.AlertChannel['kind']; label: string }[] = [
    { value: 'ntfy', label: 'ntfy' },
    { value: 'webhook', label: 'Webhook' },
    { value: 'apprise', label: 'Apprise' },
    { value: 'email', label: 'Email' },
  ];

  onMount(async () => {
    try {
      s = await api.get<T.AlertSettings>('/alerts');
    } catch (e) {
      error = errorText(e);
    }
  });

  function blank(kind: T.AlertChannel['kind']): T.AlertChannel {
    switch (kind) {
      case 'ntfy': return { kind, server: 'https://ntfy.sh', topic: '' };
      case 'webhook': return { kind, url: '' };
      case 'apprise': return { kind, url: '' };
      case 'email': return { kind, account_id: senders[0]?.id ?? '', to: senders[0]?.username ?? '' };
    }
  }

  function add(kind: T.AlertChannel['kind']) {
    if (!s) return;
    s.channels.push(blank(kind));
    results = null;
  }

  function setKind(i: number, kind: T.AlertChannel['kind']) {
    if (s && s.channels[i].kind !== kind) s.channels[i] = blank(kind);
  }

  async function run(fn: () => Promise<void>) {
    busy = true;
    error = '';
    try {
      await fn();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  const save = (e: SubmitEvent) => (e.preventDefault(), run(async () => {
    s = await api.put<T.AlertSettings>('/alerts', s);
    notify('Alert settings saved', 'success');
  }));

  const test = () => run(async () => {
    results = await api.post<T.AlertDelivery[]>('/alerts/test', s);
  });

  const hasPush = $derived(s?.channels.some((c) => c.kind !== 'email') ?? false);
  const hasEmail = $derived(s?.channels.some((c) => c.kind === 'email') ?? false);
</script>

<div class="panel">
  <h2>Alerts</h2>
  <p class="muted small mt-0">A backup that fails without anyone noticing is the worst kind. Malo can tell you on your phone or by email when something needs you, and again when it's fixed.</p>
  {#if s}
    <form onsubmit={save}>
      <h3>Send to</h3>
      {#if !s.channels.length}<p class="muted small">No channels yet: problems only show in the app.</p>{/if}
      {#each s.channels as c, i (i)}
        <div class="channel">
          <div class="kind"><Select value={c.kind} label="Channel type" options={KINDS} onchange={(k) => setKind(i, k)} /></div>
          {#if c.kind === 'ntfy'}
            <label>Server <input bind:value={c.server} placeholder="https://ntfy.sh" spellcheck="false" /></label>
            <label>Topic <input bind:value={c.topic} required maxlength="64" pattern="[A-Za-z0-9_\-]+" placeholder="malo-a8f3…" spellcheck="false" /></label>
            <label>Access token (optional) <input type="password" bind:value={c.token} autocomplete="off" placeholder="tk_…" /></label>
          {:else if c.kind === 'webhook'}
            <label class="wide">URL <input type="url" bind:value={c.url} required placeholder="https://example.com/hooks/malo" spellcheck="false" /></label>
          {:else if c.kind === 'apprise'}
            <label class="wide">Apprise API notify URL <input type="url" bind:value={c.url} required placeholder="http://apprise:8000/notify/malo" spellcheck="false" /></label>
          {:else}
            <label>Send with
              <Select bind:value={c.account_id} label="Account to send with" options={senders.map((a) => ({ value: a.id, label: a.name, hint: a.username }))} />
            </label>
            <label>To <input type="email" bind:value={c.to} required /></label>
          {/if}
          <button type="button" class="remove" title="Remove channel" aria-label="Remove channel" onclick={() => s?.channels.splice(i, 1)}>Remove</button>
        </div>
      {/each}
      <div class="row">
        <span class="muted small">Add:</span>
        {#each KINDS as k (k.value)}
          <button type="button" disabled={s.channels.length >= 10 || (k.value === 'email' && !senders.length)} title={k.value === 'email' && !senders.length ? 'Needs an account with an outgoing (SMTP) server' : undefined} onclick={() => add(k.value)}>{k.label}</button>
        {/each}
      </div>
      <p class="muted small">ntfy topics are public unless protected: pick one nobody would guess. Webhooks get a JSON <span class="mono">POST</span> with <span class="mono">event</span>, <span class="mono">severity</span>, <span class="mono">title</span> and <span class="mono">message</span>. Apprise passes alerts on to the services an Apprise API server is set up for (Telegram, Slack, Matrix, Signal…).</p>

      <h3>When</h3>
      <label class="inline">Backups of an account failed
        <input type="number" min="0" max="100" bind:value={s.backup_failures} style="width: 5rem" />
        times in a row <span class="muted small">(0: never)</span></label>
      <label class="check"><input type="checkbox" class="switch" bind:checked={s.oauth_failures} /> Signing in to a mail account with OAuth stopped working</label>
      <label class="check"><input type="checkbox" class="switch" bind:checked={s.destination_unreachable} /> A destination can't be reached</label>
      <label class="check"><input type="checkbox" class="switch" bind:checked={s.check_problems} /> An integrity check finds missing or damaged copies, or can't run</label>
      <label class="check"><input type="checkbox" class="switch" bind:checked={s.skipped_locked} /> Scheduled jobs are skipped because Malo is locked</label>
      {#if s.skipped_locked && hasPush}
        <p class="callout small" role="note"><strong>Stored unencrypted on the server.</strong> While you're locked the server can't read your settings, so for this alert it keeps the ntfy, webhook and Apprise addresses above, and the ntfy token, readable in <span class="mono">server.db</span>. Anyone with access to the server's data could use them to send you notifications. Turn this alert off to keep them encrypted with the rest of your settings.</p>
      {/if}
      {#if s.skipped_locked && hasEmail}
        <p class="muted small">Email can't send this one: the account's password stays sealed while you're locked.</p>
      {/if}
      <label class="check"><input type="checkbox" class="switch" bind:checked={s.recoveries} /> Also tell me when a problem is over</label>

      {#if results}
        <ul class="results">
          {#each results as r (r.channel)}
            <li>{#if r.ok}<span class="pill ok">sent</span>{:else}<span class="pill bad">failed</span>{/if} {r.channel}{#if r.error} <span class="muted small">{r.error}</span>{/if}</li>
          {/each}
        </ul>
      {/if}
      {#if error}<p class="callout bad">{error}</p>{/if}
      <div class="row mt-3">
        <button type="button" disabled={busy || !s.channels.length} onclick={test}>Send a test</button>
        <button class="primary" type="submit" disabled={busy}>Save</button>
      </div>
    </form>
  {:else if error}
    <p class="callout bad">{error}</p>
  {/if}
</div>

<style>
  .channel {
    display: grid;
    grid-template-columns: 9rem repeat(auto-fit, minmax(12rem, 1fr)) auto;
    gap: 0.5rem 0.75rem;
    align-items: end;
    padding: 0.75rem 0;
    border-bottom: 1px solid var(--line);
  }
  .channel label { margin: 0; }
  .channel .wide { grid-column: span 2; }
  .kind { align-self: end; }
  .inline { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .results { list-style: none; padding: 0; margin: 0.75rem 0 0; display: grid; gap: 0.35rem; }
  @media (max-width: 640px) {
    .channel { grid-template-columns: 1fr; }
    .channel .wide { grid-column: auto; }
  }
</style>
