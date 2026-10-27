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

  async function create(): Promise<boolean> {
    busy = true;
    error = '';
    try {
      const c = await api.post<T.Collection>('/collections', { name: name.trim(), mail_folder: false });
      await apply(c, true);
      if (error) return false;
      notify(`Added to “${c.name}”`, 'success');
      name = '';
      return true;
    } catch (err) {
      error = errorText(err);
      return false;
    } finally {
      busy = false;
    }
  }

  // Typing filters the list; ↑/↓ pick a collection (or "Create"), Enter applies it and closes.
  const typed = $derived(name.trim());
  const shown = $derived(live.collections.filter((c) => key(c.name).includes(key(typed))));
  const exact = $derived(shown.findIndex((c) => key(c.name) === key(typed)));
  const canCreate = $derived(!!typed && exact < 0);
  /** Choices for the keyboard: the collections shown, then "Create" (index `shown.length`). */
  const choices = $derived(shown.length + (canCreate ? 1 : 0));
  let active = $state(0);
  $effect(() => {
    void typed;
    active = untrack(() => Math.max(exact, 0));
  });
  const activeId = (i: number) => `collection-choice-${i}`;

  function key_(e: KeyboardEvent) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (choices) active = (active + (e.key === 'ArrowDown' ? 1 : -1) + choices) % choices;
      document.getElementById(activeId(active))?.scrollIntoView({ block: 'nearest' });
    }
  }

  async function choose(e: SubmitEvent) {
    e.preventDefault();
    if (busy || !choices) return;
    const c = shown[active];
    if (c) {
      const n = held[key(c.name)] ?? 0;
      await apply(c, n < ids.length);
      if (!error) onclose();
    } else if (canCreate && (await create())) {
      onclose();
    }
  }

  const what = $derived(ids.length === 1 ? 'this message' : `these ${ids.length.toLocaleString()} messages`);
</script>

<Modal title="Collections" {onclose}>
  <p class="muted small mt-0">Group {what} by hand. Collections are kept by Malo (never on your mail server), go into the backups, and can be searched with <span class="mono">tag:name</span>.</p>
  <form onsubmit={choose}>
    <input class="w-full" bind:value={name} maxlength="80" onkeydown={key_}
      placeholder={live.collections.length ? 'Find or create a collection…' : 'New collection: Taxes 2025, Trip to Lisbon…'}
      aria-label="Find or create a collection" role="combobox" aria-expanded="true" aria-controls="collection-choices"
      aria-activedescendant={choices ? activeId(active) : undefined} autocomplete="off" spellcheck="false"
      {@attach (el) => { el.focus(); }} />
  </form>
  <ul id="collection-choices" class="m-0 mt-2 flex max-h-[45vh] list-none flex-col gap-px overflow-auto p-0" role="listbox" aria-label="Collections">
    {#each shown as c, i (c.id)}
      {@const n = held[key(c.name)] ?? 0}
      <li id={activeId(i)} role="option" aria-selected={i === active}>
        <label class="check m-0 flex items-center gap-2.5 rounded-lg px-2 py-1.5 {i === active ? 'bg-hover' : 'hover:bg-hover/60'}">
          <input type="checkbox" tabindex="-1" checked={n === ids.length} disabled={busy}
            {@attach (el) => { el.indeterminate = n > 0 && n < ids.length; }}
            onchange={() => apply(c, n < ids.length)} />
          <span class="text-faint"><Icon name="folder" size={14} /></span>
          <span class="min-w-0 flex-1 truncate">{c.name}</span>
          <span class="text-[0.8rem] text-faint tabular-nums">{Number(c.count).toLocaleString()}</span>
        </label>
      </li>
    {/each}
    {#if canCreate}
      <li id={activeId(shown.length)} role="option" aria-selected={active === shown.length}>
        <button type="button" class="flex w-full items-center gap-2.5 rounded-lg bg-transparent px-2 py-1.5 text-left {active === shown.length ? 'bg-hover!' : 'hover:bg-hover/60'}"
          disabled={busy} onclick={async () => { if (await create()) onclose(); }}>
          <Icon name="plus" size={14} /> <span class="min-w-0 flex-1 truncate">Create “{typed}” and add</span>
        </button>
      </li>
    {/if}
  </ul>
  {#if !live.collections.length && !typed}<p class="muted small">No collections yet: type a name to create one.</p>{/if}
  {#if error}<p class="callout bad">{error}</p>{/if}
  <div class="row mt-3">
    <span class="muted small">↑↓ to pick, Enter to apply</span>
    <span class="grow"></span>
    <button type="button" onclick={onclose}>Done</button>
  </div>
</Modal>
