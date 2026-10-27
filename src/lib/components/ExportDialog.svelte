<script lang="ts">
  import { api, app } from '../api/client';
  import type * as T from '../api/types';
  import { notify, errorText } from '../state.svelte';
  import Modal from './Modal.svelte';

  // Saves backed-up mail as files other mail programs read. The server reads each message from
  // the backup while the file downloads; nothing is left on the server.
  let {
    selection,
    what,
    onclose,
  }: {
    selection: T.RestoreSelection;
    /** What is exported, e.g. "3 messages" or "everything in Work". */
    what: string;
    onclose: () => void;
  } = $props();

  const FORMATS: { value: T.ExportFormat; label: string; hint: string }[] = [
    { value: 'mbox', label: 'mbox', hint: 'One file per folder, for Thunderbird, Apple Mail and mutt. Several folders come as a zip of .mbox files.' },
    { value: 'maildir', label: 'Maildir', hint: 'A zipped Maildir++ folder per account, with read and flagged marks in the file names: for Dovecot, mutt or another server.' },
    { value: 'zip', label: 'Zip of .eml files', hint: 'One file per message, in its folders. Opens anywhere, one message at a time.' },
  ];

  let format = $state<T.ExportFormat>('mbox');
  let busy = $state(false);
  let error = $state('');

  async function start(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      const ticket = await api.post<T.ExportTicket>('/export', { selection, format } satisfies T.ExportRequest);
      const path = await app.saveExport(ticket.token, ticket.filename);
      if (path) {
        notify(`Exported ${ticket.messages.toLocaleString()} message${ticket.messages === 1 ? '' : 's'} to ${path}`, 'success');
        onclose();
      }
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Export mail" onclose={() => !busy && onclose()}>
  <form onsubmit={start}>
    <p class="mt-0">Saves {what} from the backup as files, with their folders, received dates and read marks.</p>
    <fieldset class="m-0 border-0 p-0">
      {#each FORMATS as f (f.value)}
        <label class="check items-start">
          <input type="radio" name="format" value={f.value} bind:group={format} disabled={busy} />
          <span><strong>{f.label}</strong><br /><span class="muted small">{f.hint}</span></span>
        </label>
      {/each}
    </fieldset>
    <p class="muted small">Messages that can't be read from any destination are left out and listed in <span class="mono">export-errors.txt</span> inside the zip.</p>
    {#if error}<p class="callout bad">{error}</p>{/if}
    <div class="row mt-3">
      <span class="grow"></span>
      <button type="button" onclick={onclose} disabled={busy}>Cancel</button>
      <button class="primary" type="submit" disabled={busy}>{busy ? 'Exporting…' : 'Export…'}</button>
    </div>
  </form>
</Modal>
