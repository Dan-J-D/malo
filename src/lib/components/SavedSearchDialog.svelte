<script lang="ts">
  import { untrack } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, notify, errorText, refreshSavedSearches } from '../state.svelte';
  import Modal from './Modal.svelte';
  import Select from './Select.svelte';

  // Creates or edits a saved search. Shown in mail apps, it becomes a read-only folder under
  // "Smart" in Malo's IMAP service.
  let {
    search = null,
    query = '',
    account = '',
    onclose,
  }: {
    search?: T.SavedSearch | null;
    query?: string;
    account?: string;
    onclose: (saved?: T.SavedSearch) => void;
  } = $props();

  // The form starts from the props once; the dialog is created anew for each search.
  const init = untrack(() => ({
    name: search?.name ?? '',
    q: search?.query ?? query,
    scope: search ? (search.account_id ?? '') : account,
    mailFolder: search?.mail_folder ?? false,
  }));
  let name = $state(init.name);
  let q = $state(init.q);
  let scopeId = $state(init.scope);
  let mailFolder = $state(init.mailFolder);
  let busy = $state(false);
  let error = $state('');

  async function save(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    const input: T.SavedSearchInput = { name: name.trim(), query: q.trim(), account_id: scopeId || undefined, mail_folder: mailFolder };
    try {
      const s = search
        ? await api.put<T.SavedSearch>(`/saved-searches/${search.id}`, input)
        : await api.post<T.SavedSearch>('/saved-searches', input);
      await refreshSavedSearches();
      notify(search ? 'Saved search updated' : `Saved “${s.name}”`, 'success');
      onclose(s);
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title={search ? `Edit “${search.name}”` : 'Save search'} onclose={() => onclose()}>
  <form onsubmit={save}>
    <label>Name <input bind:value={name} required maxlength="80" placeholder="Invoices, From the bank…" /></label>
    <label>Search <input class="mono" bind:value={q} required maxlength="2000" spellcheck="false" /></label>
    <label>In
      <Select bind:value={scopeId} options={[{ value: '', label: 'Every account' }, ...live.accounts.map((a) => ({ value: a.id, label: a.name, hint: a.username }))]} />
    </label>
    <label class="check"><input type="checkbox" class="switch" bind:checked={mailFolder} /> Show in mail apps as a folder</label>
    <p class="muted small mt-0">Mail apps connected to Malo see it as <span class="mono">Smart/{name.trim() || '…'}</span>, holding the newest 10,000 matches. It's read-only: moving mail into it does nothing.</p>
    {#if error}<p class="callout bad">{error}</p>{/if}
    <div class="row mt-3">
      <span class="grow"></span>
      <button type="button" onclick={() => onclose()}>Cancel</button>
      <button class="primary" type="submit" disabled={busy || !name.trim() || !q.trim()}>Save</button>
    </div>
  </form>
</Modal>
