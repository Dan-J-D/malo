<script lang="ts">
  import type { CheckReport } from '../api/types';
  import { when } from '../format';
  let { report }: { report: CheckReport | null } = $props();
</script>

{#if !report}
  <p class="muted">No integrity check has run yet.</p>
{:else}
  <p class="small muted">
    {report.deep ? 'Deep' : 'Quick'} check · {when(report.created_at)} ·
    {#if report.ok}<span class="pill ok">all in sync</span>{:else}<span class="pill bad">problems found</span>{/if}
    {#if report.repaired > 0}<span class="pill info">{report.repaired} repaired</span>{/if}
  </p>
  <table>
    <thead><tr><th>Destination</th><th>Healthy</th><th>Missing</th><th>Corrupt</th><th>Orphaned</th><th>Pending</th><th>Re-hashed</th><th></th></tr></thead>
    <tbody>
      {#each report.destinations as d}
        <tr>
          <td>{d.name}</td>
          <td>{d.healthy}</td>
          <td class={d.missing > 0 ? 'font-bold text-bad' : ''}>{d.missing}</td>
          <td class={d.corrupt > 0 ? 'font-bold text-bad' : ''}>{d.corrupt}</td>
          <td class={d.orphaned > 0 ? 'font-bold text-warn' : ''}>{d.orphaned}</td>
          <td>{d.pending}</td>
          <td>{d.checked_deep}</td>
          <td>
            {#if d.error}<span class="pill bad" title={d.error}>unreachable</span>
            {:else if d.ok}<span class="pill ok">healthy</span>
            {:else}<span class="pill bad">blocks purge</span>{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if report.accounts.length}
    <h3>Mail servers</h3>
    <table>
      <thead><tr><th>Account</th><th>On server</th><th>Not yet backed up</th><th>Deleted outside Malo</th><th></th></tr></thead>
      <tbody>
        {#each report.accounts as a}
          <tr>
            <td>{a.name}</td><td>{a.on_server}</td><td>{a.backlog}</td><td>{a.vanished}</td>
            <td>{#if a.error}<span class="pill warn" title={a.error}>unreachable</span>{/if}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/if}

