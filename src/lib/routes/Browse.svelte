<script lang="ts">
  import { api, qs } from '../api/client';
  import type * as T from '../api/types';
  import { live, route, scope, go, attempt, accountName } from '../state.svelte';
  import { reveal, shortDate } from '../format';
  import Viewer from '../components/Viewer.svelte';
  import Avatar from '../components/Avatar.svelte';
  import Icon from '../components/Icon.svelte';
  import { fade } from 'svelte/transition';
  import { ms } from '../motion';

  const params = $derived(new URLSearchParams(route.path.split('?')[1] ?? ''));
  const openId = $derived.by(() => {
    const m = /^\/browse\/(\d+)/.exec(route.path);
    return m ? Number(m[1]) : null;
  });

  // The account comes from the sidebar switcher, so it survives leaving and re-entering Mail.
  const account = $derived(scope.account);
  let mailbox = $state('');
  let newOnly = $state(false);
  let q = $state('');
  let page = $state(0);
  const pageSize = 100;
  let list: T.MessageList = $state({ total: 0, messages: [] });
  let loading = $state(false);
  let boxes: T.MailboxInfo[] = $state([]);
  let searchEl: HTMLInputElement | undefined = $state();

  $effect(() => {
    const a = params.get('account');
    if (a) scope.account = a;
  });

  // A different account starts on its whole mailbox list, first page.
  $effect.pre(() => {
    void account;
    mailbox = '';
    page = 0;
  });

  $effect(() => {
    void account;
    attempt(() => api.get<T.MailboxInfo[]>(`/mailboxes${qs({ account })}`)).then((b) => (boxes = b ?? []));
  });

  async function load() {
    loading = true;
    const r = await attempt(() =>
      api.get<T.MessageList>(`/messages${qs({ account, mailbox: account ? mailbox : '', new: newOnly, q, limit: pageSize, offset: page * pageSize })}`),
    );
    loading = false;
    if (r) list = r;
  }

  $effect(() => {
    void account; void mailbox; void newOnly; void page;
    load();
  });

  let searchTimer: ReturnType<typeof setTimeout>;
  function onSearch() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { page = 0; load(); }, 300);
  }

  function open(m: T.MessageSummary) {
    m.reviewed = true;
    go(`/browse/${m.id}`);
  }

  async function markAll() {
    await attempt(() => api.post('/messages/reviewed', { ids: [], all: true, account_id: account || null }), 'Marked as reviewed');
    live.newlyFound.forEach((m) => { if (!account || m.account_id === account) m.reviewed = true; });
    load();
  }

  const newTotal = $derived(boxes.reduce((n, b) => n + Number(b.new_count), 0));
  const title = $derived(account && mailbox ? reveal(boxes.find((b) => b.name === mailbox)?.display_name.split('/').pop() ?? mailbox) : account ? accountName(account) : 'All mail');
  const index = $derived(openId === null ? -1 : list.messages.findIndex((m) => m.id === openId));

  function step(d: number) {
    const m = list.messages[index + d];
    if (m) open(m);
  }

  function keys(e: KeyboardEvent) {
    const t = e.target as HTMLElement;
    if (t.closest('input, select, textarea')) {
      if (e.key === 'Escape') t.blur();
      return;
    }
    if (e.key === '/' || (e.key === 'k' && (e.metaKey || e.ctrlKey))) { e.preventDefault(); searchEl?.focus(); }
    else if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); index < 0 ? list.messages[0] && open(list.messages[0]) : step(1); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); step(-1); }
    else if (e.key === 'Escape' && openId !== null) go('/browse');
  }

  // Keep the selected row in view when moving with the keyboard.
  $effect(() => {
    if (openId !== null) document.getElementById(`msg-${openId}`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  });

  const stateIcon: Record<string, [string, string, string]> = {
    verified: ['check', 'text-ok', 'Verified on every destination'],
    stored: ['database', 'text-info', 'Stored, waiting for verification'],
    downloading: ['download', 'text-info', 'Downloading'],
    error: ['alert', 'text-bad', 'Error — will retry'],
  };
</script>

<svelte:window onkeydown={keys} />

<div class="grid h-full grid-cols-[minmax(320px,420px)_minmax(0,1fr)] gap-2">
  <!-- Message list -->
  <section class="flex min-h-0 flex-col overflow-hidden rounded-xl border border-line bg-panel">
    <header class="flex items-center gap-2 border-b border-line px-4 py-3">
      <Icon name="inbox" />
      <h1 class="m-0 flex-1 truncate text-base font-semibold">{title}</h1>
      <button class="bg-transparent px-2 py-1 text-muted hover:text-fg" onclick={markAll} title="Mark everything in this view as reviewed">
        <Icon name="checks" size={15} /> Mark all reviewed
      </button>
    </header>

    <div class="flex flex-col gap-2.5 px-3 pt-3 pb-2">
      <label class="relative m-0 block">
        <span class="sr-only">Search sender or subject</span>
        <span class="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-faint"><Icon name="search" size={15} /></span>
        <input bind:this={searchEl} class="w-full border-transparent bg-raised py-2 pr-12 pl-9" placeholder="Search" bind:value={q} oninput={onSearch} />
        <kbd class="absolute top-1/2 right-2 -translate-y-1/2 rounded-md bg-hover px-1.5 font-sans text-xs text-muted">/</kbd>
      </label>

      <div class="flex gap-1.5">
        <button class="flex-1 justify-center py-1.5 {newOnly ? 'bg-raised text-muted' : 'bg-accent! text-white'}" onclick={() => { newOnly = false; page = 0; }}>
          All
        </button>
        <button class="flex-1 justify-center py-1.5 {newOnly ? 'bg-accent! text-white' : 'bg-raised text-muted'}" onclick={() => { newOnly = true; page = 0; }}
          title="Messages that arrived since you last reviewed">
          New <span class="tabular-nums opacity-75">{newTotal}</span>
        </button>
      </div>

      {#if account}
        <div class="flex gap-1.5">
          <select class="min-w-0 flex-1 border-transparent py-1.5 text-[0.9rem]" aria-label="Mailbox" bind:value={mailbox} onchange={() => (page = 0)}>
            <option value="">All mailboxes</option>
            {#each boxes as b}
              <option value={b.name}>{'  '.repeat(b.display_name.split('/').length - 1)}{reveal(b.display_name.split('/').pop())} ({Number(b.new_count) > 0 ? `${b.new_count} new · ` : ''}{b.message_count})</option>
            {/each}
          </select>
        </div>
      {/if}
    </div>

    <div class="flex items-baseline justify-between px-4 pt-2 pb-1 text-[0.85rem] text-muted">
      <span>{newOnly ? 'New since last visit' : 'Messages'} <span class="text-faint tabular-nums">[{list.total.toLocaleString()}]</span></span>
    </div>

    <ul class="m-0 min-h-0 flex-1 list-none overflow-y-auto px-2 pb-2 transition-opacity duration-200 {loading ? 'opacity-50' : ''}" role="listbox" aria-label="Messages">
      {#each list.messages as m (m.id)}
        {@const sender = reveal(m.envelope.from_name ?? m.envelope.from) || '(unknown sender)'}
        {@const st = stateIcon[m.state]}
        <li id="msg-{m.id}" role="option" aria-selected={openId === m.id}>
          <button class="flex w-full items-start gap-3 rounded-lg px-2.5 py-2.5 text-left active:scale-[0.99] {openId === m.id ? 'bg-raised!' : 'bg-transparent'}" onclick={() => open(m)}>
            <span class="relative mt-0.5">
              <Avatar name={sender} seed={m.envelope.from} size={34} />
              {#if !m.reviewed}<span class="absolute -right-0.5 -bottom-0.5 size-2.5 rounded-full bg-accent-2 ring-2 ring-panel" title="New"></span>{/if}
            </span>
            <span class="flex min-w-0 flex-1 flex-col gap-0.5">
              <span class="flex items-baseline gap-2">
                <span class="untrusted flex-1 truncate {m.reviewed ? 'text-fg/80' : 'font-semibold text-fg'}">{sender}</span>
                <span class="flex-none text-[0.8rem] text-muted tabular-nums">{shortDate(m.envelope.date ?? m.internal_date)}</span>
              </span>
              <span class="flex items-center gap-2">
                <span class="subject flex-1 truncate text-muted">{reveal(m.envelope.subject) || '(no subject)'}</span>
                <span class="flex flex-none items-center gap-1.5">
                  {#if m.envelope.attachment_count}<span class="text-faint" title="{m.envelope.attachment_count} attachment(s)"><Icon name="paperclip" size={13} /></span>{/if}
                  {#if m.deleted_on_server}<span class="text-faint" title="Deleted on the mail server; only the backup remains"><Icon name="trash" size={13} /></span>{/if}
                  {#if st}<span class={st[1]} title={m.state === 'stored' ? `Stored on ${m.stored}/${m.destinations} destinations` : (m.error ?? st[2])}><Icon name={st[0]} size={13} /></span>{/if}
                </span>
              </span>
              {#if !account || m.labels.length}
                <span class="untrusted truncate text-[0.8rem] text-faint">{!account ? accountName(m.account_id) : ''}{!account && m.labels.length ? ' · ' : ''}{reveal(m.labels.join(', '))}</span>
              {/if}
            </span>
          </button>
        </li>
      {:else}
        <li class="px-3 py-10 text-center text-muted">{q ? 'No messages match this search.' : newOnly ? 'Nothing new since your last visit.' : 'No messages backed up here yet.'}</li>
      {/each}
    </ul>

    {#if list.total > pageSize}
      <footer class="flex items-center gap-2 border-t border-line px-3 py-2 text-[0.85rem]">
        <button class="bg-transparent px-2 py-1" disabled={page === 0} onclick={() => page--}>Previous</button>
        <span class="flex-1 text-center text-muted">Page {page + 1} of {Math.ceil(list.total / pageSize)}</span>
        <button class="bg-transparent px-2 py-1" disabled={(page + 1) * pageSize >= list.total} onclick={() => page++}>Next</button>
      </footer>
    {/if}
  </section>

  <!-- Reader -->
  <section class="flex min-h-0 flex-col overflow-hidden rounded-xl border border-line bg-panel">
    {#if openId !== null}
      <Viewer id={openId}>
        {#snippet toolbar()}
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={() => go('/browse')} aria-label="Close message" title="Close (Esc)"><Icon name="x" /></button>
          <span class="mx-1 h-4 w-px bg-line"></span>
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" disabled={index <= 0} onclick={() => step(-1)} aria-label="Previous message" title="Previous (k)"><span class="rotate-180"><Icon name="chevron" size={16} /></span></button>
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" disabled={index < 0 || index >= list.messages.length - 1} onclick={() => step(1)} aria-label="Next message" title="Next (j)"><Icon name="chevron" size={16} /></button>
        {/snippet}
      </Viewer>
    {:else}
      <div class="grid flex-1 place-items-center p-8 text-center" in:fade={{ duration: ms(200) }}>
        <div class="flex max-w-xs flex-col items-center gap-3 text-muted">
          <span class="grid size-12 place-items-center rounded-full bg-raised text-faint"><Icon name="inbox" size={22} /></span>
          <p class="m-0 text-fg">Select a message to read it</p>
          <p class="m-0 text-[0.85rem]">Messages open in a sandboxed viewer: plain text first, no remote content, links only after you confirm. Use <kbd class="rounded bg-raised px-1">j</kbd> and <kbd class="rounded bg-raised px-1">k</kbd> to move through the list.</p>
        </div>
      </div>
    {/if}
  </section>
</div>
