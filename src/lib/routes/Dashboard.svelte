<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, session, attempt, accountName, destName, go } from '../state.svelte';
  import { ago, bytes, until, when, jobLabel } from '../format';
  import HealthMatrix from '../components/HealthMatrix.svelte';
  import { commands } from '../commands.svelte';
  import { contextMenu } from '../menu.svelte';
  import { accountMenu, backup as backupAccount, verifyAll } from '../actions';

  let schedules: T.ScheduledJob[] = $state([]);
  onMount(async () => {
    schedules = (await attempt(() => api.get<T.ScheduledJob[]>('/schedules'))) ?? [];
  });

  const totalMessages = $derived(live.accounts.reduce((n, a) => n + Number(a.message_count), 0));
  const totalBytes = $derived(live.accounts.reduce((n, a) => n + Number(a.stored_bytes), 0));
  const running = $derived(live.jobs.filter((j) => j.state === 'running' || j.state === 'queued'));

  const verify = verifyAll;
  commands(() => [
    { id: 'verify-quick', group: 'Overview', label: 'Quick verify everything', keys: 'v', run: () => verify(false) },
    { id: 'verify-deep', group: 'Overview', label: 'Deep verify everything', keys: 'shift+v', run: () => verify(true) },
  ]);
</script>

<h1>Overview</h1>

<div class="cards">
  <div class="panel"><div class="muted small">Backed-up messages</div><div class="stat">{totalMessages.toLocaleString()}</div><div class="muted small">{bytes(totalBytes)}</div></div>
  <div class="panel"><div class="muted small">Accounts · destinations</div><div class="stat">{live.accounts.length} · {live.destinations.length}</div></div>
  <div class="panel"><div class="muted small">Running jobs</div><div class="stat">{running.length}</div><a href="#/activity" class="small">Activity →</a></div>
  <div class="panel"><div class="muted small">Keys unlocked until</div><div class="stat small">{when(session.me?.expires_at)}</div><div class="muted small">in {until(session.me?.expires_at)} — then backups pause</div></div>
</div>

{#if live.destinations.length === 0 || live.accounts.length === 0}
  <div class="callout">
    Get started: {#if live.destinations.length === 0}<a href="#/destinations">add a destination</a> where backups go{/if}
    {#if live.destinations.length === 0 && live.accounts.length === 0}, then {/if}
    {#if live.accounts.length === 0}<a href="#/accounts/new">add an email account</a>{/if}.
  </div>
{/if}

<h2>Accounts</h2>
<div class="cards">
  {#each live.accounts as a}
    <!-- Focusable so Shift+F10 or the Menu key opens its actions. -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div class="panel" tabindex="0" role="group" aria-label={a.name} {@attach contextMenu(() => accountMenu(a))}>
      <div class="row"><strong class="grow">{a.name}</strong>
        {#if a.imported}<span class="pill muted">imported</span>
        {:else if !a.enabled}<span class="pill muted">paused</span>
        {:else if a.last_backup_ok === false}<span class="pill warn">last run had errors</span>
        {:else if a.last_backup}<span class="pill ok">ok</span>{/if}
      </div>
      <div class="muted small">{a.username} @ {a.host}</div>
      <div class="small" style="margin-top: 0.5rem">
        <div>Last backup: {ago(a.last_backup)}</div>
        <div>Next backup: {a.next_backup ? when(a.next_backup) : '—'}</div>
        <div>{Number(a.message_count).toLocaleString()} messages · {bytes(a.stored_bytes)}</div>
        <div>Purge: {#if a.policy.armed}<span class="pill warn">armed · {a.policy.older_than_days} d</span>{:else}<span class="muted">off</span>{/if}
          {#if a.policy.armed && a.purge_blocked}<span class="pill bad" title={a.purge_blocked}>blocked</span>{/if}</div>
      </div>
      {#if !a.imported}
        <div class="row" style="margin-top: 0.75rem"><button onclick={() => backupAccount(a)}>Back up now</button><button onclick={() => go(`/browse?account=${a.id}`)}>Browse</button></div>
      {/if}
    </div>
  {/each}
</div>

<h2>Backup health</h2>
<div class="panel">
  <HealthMatrix report={live.latestReport} />
  <div class="row" style="margin-top: 0.75rem"><button onclick={() => verify(false)}>Quick verify now</button><button onclick={() => verify(true)}>Deep verify now</button></div>
</div>

<h2>Next scheduled jobs</h2>
<div class="panel">
  {#if schedules.length === 0}<p class="muted">Nothing scheduled.</p>{:else}
    <table>
      <tbody>
        {#each schedules.slice(0, 10) as s}
          <tr><td>{jobLabel(s.kind, accountName, destName)}</td><td class="right muted">{when(s.next_run)}</td></tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
