<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, attempt } from '../state.svelte';
  import { when } from '../format';
  import HealthMatrix from '../components/HealthMatrix.svelte';
  import { commands } from '../commands.svelte';
  import { contextMenu } from '../menu.svelte';

  let reports: T.CheckReport[] = $state([]);
  let selected: T.CheckReport | null = $state(null);
  let scope = $state('all');

  async function load() {
    reports = (await attempt(() => api.get<T.CheckReport[]>('/checks?limit=30'))) ?? [];
  }
  onMount(load);
  $effect(() => {
    void live.latestReport;
    load();
  });

  function scopeValue(): T.CheckScope {
    if (scope.startsWith('a:')) return { scope: 'account', account_id: scope.slice(2) };
    if (scope.startsWith('d:')) return { scope: 'destination', destination_id: scope.slice(2) };
    return { scope: 'all' };
  }
  const check = (deep: boolean) => attempt(() => api.post('/jobs', { kind: { type: 'check', scope: scopeValue(), deep } }), 'Check queued');
  const repair = () => attempt(() => api.post('/jobs', { kind: { type: 'repair', scope: scopeValue() } }), 'Repair queued');
  const shown = $derived(selected ?? live.latestReport ?? reports[0] ?? null);

  // Moves the shown report through the history.
  function stepReport(d: number) {
    const i = reports.findIndex((r) => r.id === shown?.id);
    const r = reports[Math.min(reports.length - 1, Math.max(0, i + d))];
    if (r) selected = r;
  }

  commands(() => [
    { id: 'check-quick', group: 'Integrity', label: 'Quick verify now', keys: 'v', run: () => check(false) },
    { id: 'check-deep', group: 'Integrity', label: 'Deep verify now', keys: 'shift+v', run: () => check(true) },
    { id: 'check-repair', group: 'Integrity', label: 'Verify & repair', run: repair },
    { id: 'report-next', group: 'Integrity', label: 'Older report', keys: 'j, arrowdown', run: () => stepReport(1) },
    { id: 'report-prev', group: 'Integrity', label: 'Newer report', keys: 'k, arrowup', run: () => stepReport(-1) },
    { id: 'scope-all', group: 'Integrity scope', label: 'Scope: everything', disabled: scope === 'all', run: () => (scope = 'all') },
    ...live.accounts.map((a) => ({ id: `scope-a-${a.id}`, group: 'Integrity scope', label: `Scope: account ${a.name}`, disabled: scope === 'a:' + a.id, run: () => (scope = 'a:' + a.id) })),
    ...live.destinations.map((d) => ({ id: `scope-d-${d.id}`, group: 'Integrity scope', label: `Scope: destination ${d.name}`, disabled: scope === 'd:' + d.id, run: () => (scope = 'd:' + d.id) })),
  ]);
</script>

<h1>Integrity</h1>
<p class="muted">Quick checks list every destination and compare it with the index (missing, wrong size, orphaned objects) and compare the mail server with the index. Deep checks download, decrypt and re-hash objects. A failing required destination blocks purges until repaired.</p>

<div class="panel row">
  <label>Scope
    <select bind:value={scope}>
      <option value="all">Everything</option>
      {#each live.accounts as a}<option value={'a:' + a.id}>Account · {a.name}</option>{/each}
      {#each live.destinations as d}<option value={'d:' + d.id}>Destination · {d.name}</option>{/each}
    </select>
  </label>
  <button onclick={() => check(false)}>Quick verify now</button>
  <button onclick={() => check(true)}>Deep verify now</button>
  <button class="primary" onclick={repair}>Verify &amp; repair</button>
</div>

<div class="panel"><HealthMatrix report={shown} /></div>

<h2>Report history</h2>
<div class="panel">
  <table>
    <thead><tr><th>When</th><th>Kind</th><th>Scope</th><th>Result</th><th>Repaired</th></tr></thead>
    <tbody>
      {#each reports as r (r.id)}
        <tr class="clickable" tabindex="0" aria-selected={shown?.id === r.id} onclick={() => (selected = r)} onkeydown={(e) => e.key === 'Enter' && (selected = r)}
          {@attach contextMenu(() => [{ label: 'Show this report', icon: 'file', run: () => (selected = r) }])}>
          <td>{when(r.created_at)}</td>
          <td>{r.deep ? 'deep' : 'quick'}</td>
          <td class="small">{r.scope.scope}</td>
          <td>{#if r.ok}<span class="pill ok">in sync</span>{:else}<span class="pill bad">problems</span>{/if}</td>
          <td>{r.repaired}</td>
        </tr>
      {:else}
        <tr><td colspan="5" class="muted">No reports yet.</td></tr>
      {/each}
    </tbody>
  </table>
</div>
