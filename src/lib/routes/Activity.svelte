<script lang="ts">
  import { api } from '../api/client';
  import { live, attempt, accountName, destName, go, refreshJobs } from '../state.svelte';
  import { bytes, when, ago, jobLabel, reveal } from '../format';
  import StatusPill from '../components/StatusPill.svelte';

  const active = $derived(live.jobs.filter((j) => j.state === 'running' || j.state === 'queued'));
  const history = $derived(live.jobs.filter((j) => j.state !== 'running' && j.state !== 'queued').slice(0, 50));

  function cancel(id: string) {
    attempt(() => api.del(`/jobs/${id}`), 'Cancelling…');
  }
  const stateClass: Record<string, string> = { done: 'ok', failed: 'bad', cancelled: 'warn', skipped_locked: 'muted', running: 'info', queued: 'muted' };
</script>

<div class="row"><h1 class="grow">Activity</h1><button onclick={() => attempt(refreshJobs)}>Refresh</button></div>

<h2>Running</h2>
<div class="panel">
  {#each active as j (j.id)}
    <div class="border-b border-line py-2 last:border-b-0">
      <div class="row">
        <strong class="grow">{jobLabel(j.kind, accountName, destName)}</strong>
        <span class="pill {stateClass[j.state]}">{j.state}</span>
        <span class="muted small">{j.trigger}</span>
        <button onclick={() => cancel(j.id)}>Cancel</button>
      </div>
      <div class="small muted">{j.progress.message}</div>
      {#if j.progress.total > 0}<progress value={Number(j.progress.done)} max={Number(j.progress.total)}></progress>{/if}
    </div>
  {:else}
    <p class="muted">Nothing running.</p>
  {/each}
</div>

<div class="row"><h2 class="grow">Newly found</h2>
  <span class="muted small">Messages Malo has not seen before, as they are discovered — before they are downloaded.</span>
  {#if live.newlyFound.length}<button onclick={() => (live.newlyFound = [])}>Clear list</button>{/if}
</div>
<div class="panel">
  <table>
    <thead><tr><th>From</th><th>Subject</th><th>Date</th><th>Mailbox / labels</th><th class="right">Size</th><th>📎</th><th>Status</th></tr></thead>
    <tbody>
      {#each live.newlyFound as m (m.id)}
        {@const ready = m.state === 'stored' || m.state === 'verified'}
        <tr class:clickable={ready} onclick={() => ready && go(`/browse/${m.id}`)} title={ready ? 'Open in the safe viewer' : 'Not downloaded yet'}>
          <td>{reveal(m.envelope.from_name ?? m.envelope.from)}<div class="muted small">{m.envelope.from_name ? reveal(m.envelope.from) : ''}</div></td>
          <td>{reveal(m.envelope.subject) || '(no subject)'}</td>
          <td class="small">{when(m.envelope.date ?? m.internal_date)}</td>
          <td class="small">{reveal([...m.mailboxes, ...m.labels].join(', '))}<div class="muted">{accountName(m.account_id)}</div></td>
          <td class="right small">{bytes(m.size)}</td>
          <td>{m.envelope.attachment_count || ''}</td>
          <td><StatusPill state={m.state} stored={m.stored} destinations={m.destinations} error={m.error} /></td>
        </tr>
      {:else}
        <tr><td colspan="7" class="muted">New mail shows up here live while a backup runs.</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<h2>History</h2>
<div class="panel">
  <table>
    <thead><tr><th>Job</th><th>State</th><th>Trigger</th><th>Started</th><th>Finished</th><th>Details</th></tr></thead>
    <tbody>
      {#each history as j (j.id)}
        <tr>
          <td>{jobLabel(j.kind, accountName, destName)}</td>
          <td><span class="pill {stateClass[j.state]}">{j.state.replace('_', ' ')}</span></td>
          <td class="small">{j.trigger}</td>
          <td class="small">{when(j.started_at ?? j.created_at)}</td>
          <td class="small">{ago(j.finished_at)}</td>
          <td class="small">
            {#if j.error}<span class="text-bad">{j.error}</span>
            {:else if j.kind.type === 'backup' && j.result}
              {j.result.discovered} new · {j.result.downloaded} downloaded · {bytes(j.result.bytes)}{#if j.result.errors?.length} · <span class="text-bad">{j.result.errors.length} errors</span>{/if}
            {:else if j.kind.type === 'purge' && j.result}{j.result.deleted} deleted · {bytes(j.result.bytes)}
            {:else if (j.kind.type === 'check' || j.kind.type === 'repair') && j.result}{j.result.ok ? 'in sync' : 'problems found'}{j.result.repaired ? ` · ${j.result.repaired} repaired` : ''}
            {:else if j.kind.type === 'purge_dry_run' && j.result}{j.result.total_count} would be deleted
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

