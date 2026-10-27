<script lang="ts">
  import { untrack } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, notify, errorText, refreshCollections } from '../state.svelte';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';

  // Puts messages in collections or takes them out; each box applies at once. A message can be
  // in any number of collections, and stays where it is in its mailboxes.
  let {
    messages,
    onchange,
    onclose,
  }: {
    messages: T.MessageSummary[];
    /** After messages went into (`add`) or out of the named collection. */
    onchange: (ids: number[], name: string, add: boolean) => void;
    onclose: () => void;
  } = $props();

  const ids = untrack(() => messages.map((m) => m.id));
  const key = (name: string) => name.toLowerCase();
  // How many of the messages each collection holds, by name; kept as boxes change.
  let held = $state<Record<string, number>>(untrack(() => {
    const c: Record<string, number> = {};
    for (const m of messages) for (const n of m.collections) c[key(n)] = (c[key(n)] ?? 0) + 1;
    return c;
  }));
  let name = $state('');
  let busy = $state(false);
  let error = $state('');

  async function apply(c: T.Collection, add: boolean) {
    busy = true;
    error = '';
    try {
      const r = await api.post<T.CollectionMembersResult>(`/collections/${c.id}/messages`, { ids, add });
      held[key(c.name)] = add ? ids.length : 0;
      onchange(ids, r.collection.name, add);
      await refreshCollections();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function create(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      const c = await api.post<T.Collection>('/collections', { name: name.trim(), mail_folder: false });
      await apply(c, true);
      if (!error) {
        notify(`Added to “${c.name}”`, 'success');
        name = '';
      }
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }

  const what = $derived(ids.length === 1 ? 'this message' : `these ${ids.length.toLocaleString()} messages`);
</script>

<Modal title="Collections" {onclose}>
  <p class="muted small mt-0">Group {what} by hand. Collections are kept by Malo (never on your mail server), go into the backups, and can be searched with <span class="mono">tag:name</span>.</p>
  {#if live.collections.length}
    <ul class="m-0 flex max-h-[45vh] list-none flex-col gap-px overflow-auto p-0">
      {#each live.collections as c (c.id)}
        {@const n = held[key(c.name)] ?? 0}
        <li>
          <label class="check m-0 flex items-center gap-2.5 rounded-lg px-2 py-1.5 hover:bg-hover/60">
            <input type="checkbox" checked={n === ids.length} disabled={busy}
              {@attach (el) => { el.indeterminate = n > 0 && n < ids.length; }}
              onchange={() => apply(c, n < ids.length)} />
            <span class="text-faint"><Icon name="folder" size={14} /></span>
            <span class="min-w-0 flex-1 truncate">{c.name}</span>
            <span class="text-[0.8rem] text-faint tabular-nums">{Number(c.count).toLocaleString()}</span>
          </label>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="muted small">No collections yet.</p>
  {/if}
  <form class="row mt-3" onsubmit={create}>
    <input class="grow" bind:value={name} maxlength="80" placeholder="New collection: Taxes 2025, Trip to Lisbon…" aria-label="New collection name" />
    <button class="primary" type="submit" disabled={busy || !name.trim()}><Icon name="plus" size={14} /> Create and add</button>
  </form>
  {#if error}<p class="callout bad">{error}</p>{/if}
  <div class="row mt-3">
    <span class="grow"></span>
    <button type="button" onclick={onclose}>Done</button>
  </div>
</Modal>
