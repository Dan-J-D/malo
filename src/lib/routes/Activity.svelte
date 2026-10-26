<script lang="ts">
  import { api } from '../api/client';
  import { live, attempt, accountName, destName, go, refreshJobs, clearFound, FOUND_KEEP } from '../state.svelte';
  import { bytes, when, ago, jobLabel, reveal, shortDate } from '../format';
  import StatusPill from '../components/StatusPill.svelte';
  import Icon from '../components/Icon.svelte';

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

<div class="row mt-8 mb-3 items-baseline">
  <h2 class="m-0">Newly found</h2>
  {#if live.foundCount}
    <span class="text-[0.85rem] text-muted tabular-nums">{live.foundCount.toLocaleString()} this session{live.foundCount > live.newlyFound.length ? ` · latest ${live.newlyFound.length}` : ''}</span>
  {/if}
  <span class="grow"></span>
  {#if live.foundCount > FOUND_KEEP}<a href="#/browse?new=1" class="text-[0.9rem]">See all in Mail</a>{/if}
  {#if live.newlyFound.length}<button onclick={clearFound}>Clear list</button>{/if}
</div>
<!-- The newest messages only: a first backup discovers the whole mailbox, and Mail's New view pages through all of it. -->
<div class="panel max-h-[26rem] overflow-y-auto p-1.5!">
  {#each live.newlyFound as m (m.id)}
    {@const ready = m.state === 'stored' || m.state === 'verified'}
    {@const sender = reveal(m.envelope.from_name ?? m.envelope.from) || '(unknown sender)'}
    <button class="grid w-full grid-cols-[minmax(0,13rem)_minmax(0,1fr)_auto_auto] items-center gap-x-4 rounded-lg bg-transparent px-3 py-2 text-left {ready ? 'hover:bg-hover' : 'cursor-default hover:bg-transparent!'}"
      onclick={() => ready && go(`/browse/${m.id}`)} title={ready ? 'Open in the safe viewer' : 'Not downloaded yet'}>
      <span class="min-w-0 leading-tight">
        <span class="untrusted block truncate">{sender}</span>
        <span class="block truncate text-[0.8rem] text-muted">{accountName(m.account_id)}</span>
      </span>
      <span class="flex min-w-0 items-center gap-1.5">
        <span class="subject truncate">{reveal(m.envelope.subject) || '(no subject)'}</span>
        {#if m.envelope.attachment_count}<span class="flex-none text-faint" title="{m.envelope.attachment_count} attachment(s)"><Icon name="paperclip" size={13} /></span>{/if}
      </span>
      <span class="text-right text-[0.8rem] whitespace-nowrap text-muted tabular-nums" title={when(m.envelope.date ?? m.internal_date)}>{shortDate(m.envelope.date ?? m.internal_date)} · {bytes(m.size)}</span>
      <StatusPill state={m.state} stored={m.stored} destinations={m.destinations} error={m.error} />
    </button>
  {:else}
    <p class="m-0 px-3 py-2 text-muted">New mail shows up here live while a backup runs.</p>
  {/each}
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

