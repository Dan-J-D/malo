<script lang="ts">
  import { untrack } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { notify, errorText, refreshCollections } from '../state.svelte';
  import Modal from './Modal.svelte';

  // Renames a collection, or shows it to mail apps as a folder.
  let { collection, onclose }: { collection: T.Collection; onclose: (saved?: T.Collection) => void } = $props();

  let name = $state(untrack(() => collection.name));
  let mailFolder = $state(untrack(() => collection.mail_folder));
  let busy = $state(false);
  let error = $state('');

  async function save(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      const c = await api.put<T.Collection>(`/collections/${collection.id}`, { name: name.trim(), mail_folder: mailFolder });
      await refreshCollections();
      notify('Collection saved', 'success');
      onclose(c);
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title={`Edit “${collection.name}”`} onclose={() => onclose()}>
  <form onsubmit={save}>
    <label>Name <input bind:value={name} required maxlength="80" /></label>
    <label class="check"><input type="checkbox" class="switch" bind:checked={mailFolder} /> Show in mail apps as a folder</label>
    <p class="muted small mt-0">Mail apps connected to Malo see it as <span class="mono">Collections/{name.trim() || '…'}</span>, with the messages of the account they're signed in to. Copying or moving mail into it adds it to the collection; deleting it there only takes it out again.</p>
    {#if error}<p class="callout bad">{error}</p>{/if}
    <div class="row mt-3">
      <span class="grow"></span>
      <button type="button" onclick={() => onclose()}>Cancel</button>
      <button class="primary" type="submit" disabled={busy || !name.trim()}>Save</button>
    </div>
  </form>
</Modal>
