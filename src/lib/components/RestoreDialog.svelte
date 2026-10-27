<script lang="ts">
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, notify, errorText, go, accountName } from '../state.svelte';
  import Modal from './Modal.svelte';
  import Select from './Select.svelte';

  // Uploads backed-up mail to a mail account with IMAP: the one it came from after a mailbox was
  // lost, or another one when moving provider. Messages already there (same Message-ID) are
  // skipped, so running it again is safe.
  let {
    selection,
    what,
    from = '',
    onclose,
  }: {
    selection: T.RestoreSelection;
    /** What is restored, e.g. "3 messages" or "everything in Work". */
    what: string;
    /** The account the mail came from: preselected as the target. */
    from?: string;
    onclose: () => void;
  } = $props();

  const targets = $derived(live.accounts.filter((a) => !a.imported));
  let target = $state('');
  let into = $state<'original' | 'folder'>('original');
  let folder = $state(`Restored ${new Date().toISOString().slice(0, 10)}`);
  let busy = $state(false);
  let error = $state('');

  $effect.pre(() => {
    if (!target) target = targets.find((a) => a.id === from)?.id ?? targets[0]?.id ?? '';
  });

  async function start(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await api.post<T.JobInfo>('/restore', {
        target_account_id: target,
        selection,
        target: into === 'original' ? { to: 'original' } : { to: 'folder', name: folder.trim() },
      } satisfies T.RestoreRequest);
      notify(`Restoring ${what} to ${accountName(target)}`, 'success');
      onclose();
      go('/activity');
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Restore to a mail account" onclose={onclose}>
  <form onsubmit={start}>
    <p class="mt-0">Uploads {what} from the backup to a mail account, with flags and received dates. Messages already in the target folder are skipped.</p>
    {#if !targets.length}
      <p class="callout">No account to restore to: add one under Accounts first. Accounts brought back from a recovery kit need signing in again.</p>
    {:else}
      <label>Mail account
        <Select bind:value={target} options={targets.map((a) => ({ value: a.id, label: a.name, hint: a.username }))} />
      </label>
      {#if target && target !== from && from}
        <p class="muted small">Moving to another account: folders are matched by their role (Sent, Drafts, Junk…) or by name, and created where missing.</p>
      {/if}
      <fieldset class="m-0 border-0 p-0">
        <label class="check"><input type="radio" name="into" value="original" bind:group={into} /> Into the folders they were in</label>
        <label class="check"><input type="radio" name="into" value="folder" bind:group={into} /> All into one folder</label>
      </fieldset>
      {#if into === 'folder'}
        <label>Folder (created if missing) <input bind:value={folder} required maxlength="200" /></label>
      {/if}
    {/if}
    {#if error}<p class="callout bad">{error}</p>{/if}
    <div class="row mt-3">
      <span class="grow"></span>
      <button type="button" onclick={onclose}>Cancel</button>
      <button class="primary" type="submit" disabled={busy || !target || (into === 'folder' && !folder.trim())}>{busy ? 'Starting…' : 'Restore'}</button>
    </div>
  </form>
</Modal>
