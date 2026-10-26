<script lang="ts">
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, accountName, notify } from '../state.svelte';
  import DangerConfirm from './DangerConfirm.svelte';

  // Confirms and starts deleting selected messages: one job per account and batch of
  // BATCH (the server's MAX_DELETE_BATCH). The jobs report back through their results.
  const BATCH = 1000;

  let {
    messages,
    scope,
    onstarted,
    onclose,
  }: { messages: T.MessageSummary[]; scope: T.DeleteScope; onstarted: (jobs: string[]) => void; onclose: () => void } = $props();

  const n = $derived(messages.length);
  const plural = (k: number, word: string) => `${k.toLocaleString()} ${word}${k === 1 ? '' : 's'}`;
  const imported = (m: T.MessageSummary) => live.accounts.find((a) => a.id === m.account_id)?.imported ?? false;
  const onServer = $derived(messages.filter((m) => !m.deleted_on_server && !imported(m)));
  const unverified = $derived(onServer.filter((m) => m.state !== 'verified'));
  const offServer = $derived(n - onServer.length);
  const accounts = $derived([...new Set(messages.map((m) => m.account_id))]);
  const target = $derived(scope === 'server' ? 'from mail server' : 'from backup');

  async function start() {
    const jobs: string[] = [];
    for (const account_id of accounts) {
      const ids = messages.filter((m) => m.account_id === account_id).map((m) => m.id);
      for (let i = 0; i < ids.length; i += BATCH) {
        const job = await api.post<T.JobInfo>('/jobs', {
          kind: { type: 'delete_messages', account_id, message_ids: ids.slice(i, i + BATCH), scope },
        } satisfies T.CreateJobRequest);
        jobs.push(job.id);
      }
    }
    notify(`Deleting ${plural(n, 'message')} ${target}…`, 'info');
    onstarted(jobs);
  }
</script>

<DangerConfirm
  title={scope === 'server' ? 'Delete from the mail server' : 'Delete from the backup'}
  phrase={`delete ${n}`}
  action={`Delete ${plural(n, 'message')}`}
  onconfirm={start}
  {onclose}
>
  {#if scope === 'server'}
    <p>Deletes <strong>{plural(onServer.length, 'message')}</strong> from {accounts.length === 1 ? accountName(accounts[0]) : plural(accounts.length, 'account')} on the mail server. The backups stay: you can still read, search and save them here.</p>
    <ul class="small">
      <li>Each message is deleted only if its backup is verified on the purge's required destinations (every destination when none are set), and is checked again first.</li>
      <li>On the server, a message is deleted only while it is still exactly the backed-up one.</li>
      {#if unverified.length}<li><strong>{plural(unverified.length, 'message')}</strong> {unverified.length === 1 ? "isn't" : "aren't"} verified everywhere yet and will probably be kept.</li>{/if}
      {#if offServer}<li>{plural(offServer, 'message')} {offServer === 1 ? 'is' : 'are'} already gone from the server (or from an imported account) and {offServer === 1 ? 'is' : 'are'} left as {offServer === 1 ? 'it is' : 'they are'}.</li>{/if}
    </ul>
  {:else}
    <p>Permanently deletes <strong>{plural(n, 'message')}</strong> from the backup: from Malo's index and from every destination. <strong>They can't be restored afterwards.</strong></p>
    <ul class="small">
      {#if onServer.length}<li><strong>{plural(onServer.length, 'message')}</strong> {onServer.length === 1 ? 'is' : 'are'} still on the mail server and {onServer.length === 1 ? 'is' : 'are'} deleted there first, or the next backup would bring {onServer.length === 1 ? 'it' : 'them'} back. One that can't be deleted there stays in the backup too.</li>{/if}
      {#if offServer}<li>{plural(offServer, 'message')} {offServer === 1 ? 'exists' : 'exist'} only in the backup.</li>{/if}
      <li>A destination that can't be reached right now is cleaned up at its next successful backup.</li>
    </ul>
  {/if}
</DangerConfirm>
