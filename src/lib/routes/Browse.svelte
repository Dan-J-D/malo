<script lang="ts">
  import { untrack } from 'svelte';
  import { SvelteMap } from 'svelte/reactivity';
  import { api, app, qs } from '../api/client';
  import type * as T from '../api/types';
  import { live, route, scope, go, attempt, accountName, setReviewed, notify } from '../state.svelte';
  import { commands, type Command } from '../commands.svelte';
  import { contextMenu, menuUnder, copy, type Entry } from '../menu.svelte';
  import { reveal, shortDate, highlights } from '../format';
  import { panes, savePanes, LIST_MIN, LIST_MAX, LIST_DEFAULT } from '../layout.svelte';
  import Viewer from '../components/Viewer.svelte';
  import Avatar from '../components/Avatar.svelte';
  import Icon from '../components/Icon.svelte';
  import Resizer from '../components/Resizer.svelte';
  import SearchBox from '../components/SearchBox.svelte';
  import DeleteMessages from '../components/DeleteMessages.svelte';
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
  /** Search column for words without an operator ("Search in"). */
  let field = $state('');
  const sorts = [['newest', 'Newest'], ['oldest', 'Oldest'], ['sender', 'Sender A–Z'], ['largest', 'Largest'], ['relevance', 'Best match']];
  let sort = $state(readSort());
  function readSort() {
    try {
      const v = localStorage.getItem('malo.sort');
      return sorts.some(([k]) => k === v) ? v! : 'newest';
    } catch {
      return 'newest';
    }
  }
  function setSort(v: string) {
    sort = v;
    try { localStorage.setItem('malo.sort', v); } catch { /* not remembered */ }
  }
  let boxes: T.MailboxInfo[] = $state([]);
  let searchBox: SearchBox | undefined = $state();
  let selBar: HTMLElement | undefined = $state();

  $effect(() => {
    const a = params.get('account');
    if (a) scope.account = a;
    if (params.get('new')) newOnly = true;
  });

  // A different account starts on its whole mailbox list.
  $effect.pre(() => {
    void account;
    mailbox = '';
  });

  // Also reloaded after marking mail, for the per-mailbox counts of new messages.
  function loadBoxes() {
    const a = account;
    attempt(() => api.get<T.MailboxInfo[]>(`/mailboxes${qs({ account: a })}`)).then((b) => { if (a === account) boxes = b ?? []; });
  }
  $effect(() => {
    void account;
    untrack(loadBoxes);
  });

  // ── Virtual list ──
  // Every row has the same height, so which rows are on screen follows from the scroll offset
  // alone: only those (plus an overscan margin) are rendered, inside a spacer as tall as the
  // whole list. Rows arrive in pages as they come into view. The first page pins the newest id
  // (`max_id`), so mail found by a running backup can't shift the offsets of later pages.
  const ROW = 76;
  const PAGE = 100;
  const OVERSCAN = 10;

  let total = $state(0);
  /** With a search: messages only searched by sender, recipients and subject (not indexed yet). */
  let unindexed = $state(0);
  let pages: Record<number, T.MessageSummary[]> = $state.raw({});
  let maxId: number | null = null;
  let gen = $state(0);
  const inflight = new Set<number>();
  let loading = $state(false);
  let baseFound = $state(0);
  let scroller: HTMLElement | undefined = $state();
  let scrollTop = $state(0);
  let viewH = $state(0);

  const first = $derived(Math.max(0, Math.floor(scrollTop / ROW) - OVERSCAN));
  const last = $derived(Math.min(total, Math.ceil((scrollTop + viewH) / ROW) + OVERSCAN));
  const visible = $derived(Array.from({ length: Math.max(0, last - first) }, (_, k) => first + k));
  const at = (i: number) => pages[Math.floor(i / PAGE)]?.[i % PAGE];

  const query = (p: number) =>
    `/messages${qs({ account, mailbox: account ? mailbox : '', new: newOnly, q, field: q.trim() ? field : '', sort, limit: PAGE, offset: p * PAGE, max_id: maxId })}`;

  async function fetchPage(p: number) {
    if (pages[p] || inflight.has(p)) return;
    const g = gen;
    inflight.add(p);
    const r = await attempt(() => api.get<T.MessageList>(query(p)));
    if (g !== gen) return;
    inflight.delete(p);
    if (r) pages = { ...pages, [p]: r.messages };
  }

  /** Starts the list over (filters changed, or the user asked for new mail). */
  async function reset() {
    const g = ++gen;
    clearSelection();
    inflight.clear();
    stopWaiting();
    maxId = null;
    loading = true;
    const r = await attempt(() => api.get<T.MessageList>(query(0)));
    if (g !== gen) return;
    loading = false;
    if (!r) return;
    maxId = r.messages[0]?.id ?? null;
    total = r.total;
    unindexed = q.trim() ? r.unindexed : 0;
    pages = { 0: r.messages };
    baseFound = live.foundCount;
    if (scroller) scroller.scrollTop = 0;
    scrollTop = 0;
  }

  $effect(() => {
    void account; void mailbox; void newOnly; void sort;
    untrack(reset);
  });

  // Pages for the rows on screen. A page is fetched once it has stayed in view for a moment,
  // so flinging the scrollbar across thousands of rows doesn't fetch every page on the way,
  // while slow continuous scrolling still loads as it goes.
  const waiting = new Map<number, ReturnType<typeof setTimeout>>();
  function stopWaiting() {
    waiting.forEach((t) => clearTimeout(t));
    waiting.clear();
  }
  $effect(() => {
    if (loading || total === 0) return;
    const from = Math.floor(first / PAGE);
    const to = Math.floor(Math.max(first, last - 1) / PAGE);
    untrack(() => {
      for (const [p, t] of waiting) {
        if (p < from || p > to) {
          clearTimeout(t);
          waiting.delete(p);
        }
      }
      for (let p = from; p <= to; p++) {
        if (pages[p] || inflight.has(p) || waiting.has(p)) continue;
        waiting.set(p, setTimeout(() => { waiting.delete(p); fetchPage(p); }, 90));
      }
    });
  });
  $effect(() => stopWaiting);

  async function indexNow() {
    if (await attempt(() => api.post('/jobs', { kind: { type: 'search_index' } }))) notify('Indexing mail for search', 'success');
  }

  let searchTimer: ReturnType<typeof setTimeout>;
  /** Typing waits for a pause; chips, filters and Enter search right away. */
  function onSearch(now: boolean) {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(reset, now ? 0 : 300);
  }

  // ── Selection ──
  // Ctrl/⌘-click or the checkbox toggles a message, Shift-click selects the range from the last
  // toggled one, x toggles the open message. Rows in a selection act together.
  const selected = new SvelteMap<number, T.MessageSummary>();
  let anchor = -1;
  let selectingAll = $state(false);
  let deleteScope: T.DeleteScope | null = $state(null);
  let pendingJobs: string[] = $state([]);
  /** Most messages "Select all" takes at once. */
  const SELECT_MAX = 10000;

  function clearSelection() {
    selected.clear();
    anchor = -1;
  }

  function toggle(m: T.MessageSummary, i: number) {
    if (selected.has(m.id)) selected.delete(m.id);
    else selected.set(m.id, m);
    anchor = i;
  }

  /** Selects rows anchor..i (both included), fetching pages that aren't loaded yet. */
  async function selectRange(i: number) {
    const from = Math.min(anchor < 0 ? i : anchor, i);
    const to = Math.max(anchor < 0 ? i : anchor, i);
    for (let p = Math.floor(from / PAGE); p <= Math.floor(to / PAGE); p++) await fetchPage(p);
    for (let k = from; k <= to; k++) {
      const m = at(k);
      if (m) selected.set(m.id, m);
    }
    anchor = i;
  }

  /** Every message in the current view (up to SELECT_MAX), fetched in large pages. */
  async function selectAll() {
    const g = gen;
    selectingAll = true;
    try {
      const want = Math.min(total, SELECT_MAX);
      for (let offset = 0; offset < want; offset += 1000) {
        const r = await attempt(() => api.get<T.MessageList>(
          `/messages${qs({ account, mailbox: account ? mailbox : '', new: newOnly, q, sort, limit: Math.min(1000, want - offset), offset, max_id: maxId })}`,
        ));
        if (!r || g !== gen) return;
        for (const m of r.messages) selected.set(m.id, m);
      }
      if (total > SELECT_MAX) notify(`Selected the first ${SELECT_MAX.toLocaleString()} of ${total.toLocaleString()} messages`, 'warning');
    } finally {
      selectingAll = false;
    }
  }

  function rowClick(e: MouseEvent, m: T.MessageSummary, i: number) {
    if (e.shiftKey) return void selectRange(i);
    if (e.ctrlKey || e.metaKey) return toggle(m, i);
    open(m, i);
  }

  const chosen = () => [...selected.values()];

  async function markSelected(reviewed: boolean) {
    const ids = [...selected.keys()];
    if (!(await setReviewed(ids, reviewed))) return;
    const set = new Set(ids);
    touch((x) => { if (set.has(x.id)) x.reviewed = reviewed; });
    loadBoxes();
    notify(`Marked ${ids.length.toLocaleString()} as ${reviewed ? 'read' : 'unread'}`, 'success');
  }

  async function saveSelected() {
    const r = await attempt(() => app.saveRawMany([...selected.keys()]));
    if (r) notify(`Saved ${r[1].toLocaleString()} message${r[1] === 1 ? '' : 's'} to ${r[0]}`, 'success');
  }

  // The list reloads when delete jobs finish (server-side deletes change the trash icons) and
  // when messages leave the backup, also from another device.
  $effect(() => {
    if (!pendingJobs.length) return;
    const done = pendingJobs.every((id) => {
      const j = live.jobs.find((x) => x.id === id);
      return j && j.state !== 'queued' && j.state !== 'running';
    });
    if (done) untrack(() => {
      pendingJobs = [];
      reset();
      loadBoxes();
    });
  });
  $effect(() => {
    const gone = live.deleted;
    if (!gone.length) return;
    untrack(() => {
      if (openId !== null && gone.includes(openId)) go('/browse');
      reset();
      loadBoxes();
    });
  });

  /** Actions on the whole selection, for the bar, its context menu and shortcuts. */
  function selectionMenu(): Entry[] {
    const n = selected.size;
    return [
      { label: 'Mark as read', icon: 'check', keys: 'shift+i', run: () => markSelected(true) },
      { label: 'Mark as unread', icon: 'mail', keys: 'shift+u', run: () => markSelected(false) },
      { label: `Save ${n === 1 ? '.eml' : `${n.toLocaleString()} .eml files`}…`, icon: 'download', run: saveSelected },
      '-',
      { label: 'Delete from mail server…', icon: 'trash', keys: 'delete', danger: true, run: () => (deleteScope = 'server') },
      { label: 'Delete from backup…', icon: 'trash', keys: 'shift+delete', danger: true, run: () => (deleteScope = 'everywhere') },
      '-',
      { label: 'Select all in this view', icon: 'checks', keys: 'mod+a', disabled: selected.size >= Math.min(total, SELECT_MAX), run: selectAll },
      { label: 'Clear selection', icon: 'x', keys: 'escape', run: clearSelection },
    ];
  }

  /** Applies `f` to copies of the rows and republishes the pages. The page map isn't deeply
   *  reactive, and a row only redraws when it is a new object. */
  function touch(f: (m: T.MessageSummary) => void) {
    pages = Object.fromEntries(Object.entries(pages).map(([p, rows]) => [p, rows.map((m) => {
      const c = { ...m };
      f(c);
      return c.reviewed === m.reviewed ? m : c;
    })]));
  }

  // Index of the open message in the whole list, when it's loaded.
  let sel = $state(-1);
  const index = $derived.by(() => {
    if (openId === null) return -1;
    if (sel >= 0 && at(sel)?.id === openId) return sel;
    for (const [p, rows] of Object.entries(pages)) {
      const i = rows.findIndex((m) => m.id === openId);
      if (i >= 0) return Number(p) * PAGE + i;
    }
    return -1;
  });

  function open(m: T.MessageSummary, i: number) {
    sel = i;
    if (!m.reviewed) touch((x) => { if (x.id === m.id) x.reviewed = true; });
    go(`/browse/${m.id}`);
  }

  async function markAll() {
    await attempt(() => api.post('/messages/reviewed', { ids: [], all: true, account_id: account || null }), 'Marked as read');
    live.newlyFound.forEach((m) => { if (!account || m.account_id === account) m.reviewed = true; });
    if (newOnly) reset();
    else touch((m) => (m.reviewed = true));
    loadBoxes();
  }

  async function mark(m: T.MessageSummary, reviewed: boolean) {
    if (!(await setReviewed([m.id], reviewed))) return;
    touch((x) => { if (x.id === m.id) x.reviewed = reviewed; });
    loadBoxes();
  }

  function fromSender(m: T.MessageSummary) {
    searchBox?.set(`from:${m.envelope.from}`);
  }

  function cycleSort() {
    const i = sorts.findIndex(([k]) => k === sort);
    setSort(sorts[(i + 1) % sorts.length][0]);
  }

  /** Scrolls just enough to show row `i` (it may not be rendered yet, so no scrollIntoView). */
  function showRow(i: number) {
    if (!scroller) return;
    const top = i * ROW;
    if (top < scroller.scrollTop) scroller.scrollTop = top;
    else if (top + ROW > scroller.scrollTop + viewH) scroller.scrollTop = top + ROW - viewH;
  }

  function step(d: number) {
    return openAt(index < 0 ? (d > 0 ? 0 : -1) : index + d);
  }

  async function openAt(i: number) {
    if (i < 0 || i >= total) return;
    if (!at(i)) await fetchPage(Math.floor(i / PAGE));
    const m = at(i);
    if (m) {
      open(m, i);
      showRow(i);
    }
  }

  /** Everything that can be done with one message, for its context menu and the "." shortcut. */
  function messageMenu(m: T.MessageSummary, i: number): Entry[] {
    if (selected.size > 1 && selected.has(m.id)) return selectionMenu();
    const subject = reveal(m.envelope.subject);
    return [
      { label: selected.has(m.id) ? 'Deselect' : 'Select', icon: 'check', keys: 'x', run: () => toggle(m, i) },
      openId !== m.id && { label: 'Open', icon: 'mail-open', run: () => open(m, i) },
      m.reviewed
        ? { label: 'Mark as unread', icon: 'mail', keys: 'shift+u', run: () => mark(m, false) }
        : { label: 'Mark as read', icon: 'check', keys: 'shift+i', run: () => mark(m, true) },
      '-',
      { label: 'Search mail from this sender', icon: 'search', run: () => fromSender(m) },
      !account && { label: `Show only ${accountName(m.account_id)}`, icon: 'at', run: () => (scope.account = m.account_id) },
      '-',
      { label: 'Copy sender address', icon: 'copy', run: () => copy(m.envelope.from, 'Address copied') },
      subject && { label: 'Copy subject', icon: 'copy', run: () => copy(subject, 'Subject copied') },
      { label: 'Save .eml…', icon: 'download', run: () => attempt(() => app.saveRaw(m.id)) },
      '-',
      { label: 'Delete from mail server…', icon: 'trash', danger: true, disabled: m.deleted_on_server, run: () => deleteOne(m, 'server') },
      { label: 'Delete from backup…', icon: 'trash', danger: true, run: () => deleteOne(m, 'everywhere') },
    ];
  }

  function deleteOne(m: T.MessageSummary, scope: T.DeleteScope) {
    clearSelection();
    selected.set(m.id, m);
    deleteScope = scope;
  }

  // Right-click on the list itself, around the rows.
  const listMenu = (): Entry[] => [
    { label: 'Select all in this view', icon: 'checks', keys: 'mod+a', disabled: total === 0, run: selectAll },
    { label: newOnly ? 'Show all messages' : 'Show only new messages', icon: 'mail', keys: 'n', run: () => (newOnly = !newOnly) },
    { label: 'Mark all read', icon: 'checks', keys: 'shift+a', run: markAll },
    { label: 'Reload list', icon: 'refresh', keys: 'r', run: reset },
    '-',
    ...sorts.map(([k, label]): Entry => ({ label: `Sort: ${label}`, icon: k === sort ? 'check' : undefined, run: () => setSort(k) })),
  ];

  const current = $derived(index >= 0 ? at(index) : undefined);
  const rowAt = (i: number) => scroller?.querySelector(`[aria-posinset="${i + 1}"]`);

  commands(() => {
    const m = current;
    const n = selected.size;
    const sel = n > 0;
    return [
      { id: 'select', group: 'Selection', label: m && selected.has(m.id) ? 'Deselect message' : 'Select message', keys: 'x', disabled: !m, run: () => m && toggle(m, index) },
      { id: 'select-all', group: 'Selection', label: 'Select all in this view', keys: 'mod+a', disabled: total === 0 || selectingAll, run: selectAll },
      { id: 'select-clear', group: 'Selection', label: 'Clear selection', keys: 'escape', disabled: !sel, run: clearSelection },
      { id: 'select-read', group: 'Selection', label: `Mark ${n} selected as read`, keys: 'shift+i', disabled: !sel, run: () => markSelected(true) },
      { id: 'select-unread', group: 'Selection', label: `Mark ${n} selected as unread`, keys: 'shift+u', disabled: !sel, run: () => markSelected(false) },
      { id: 'select-save', group: 'Selection', label: `Save ${n} selected as .eml files…`, disabled: !sel, run: saveSelected },
      { id: 'select-del-server', group: 'Selection', label: sel ? `Delete ${n} selected from mail server…` : 'Delete from mail server…', keys: 'delete, #',
        disabled: !sel && !m, run: () => (sel ? (deleteScope = 'server') : m && deleteOne(m, 'server')) },
      { id: 'select-del-backup', group: 'Selection', label: sel ? `Delete ${n} selected from backup…` : 'Delete from backup…', keys: 'shift+delete',
        disabled: !sel && !m, run: () => (sel ? (deleteScope = 'everywhere') : m && deleteOne(m, 'everywhere')) },
      { id: 'next', group: 'Mail', label: 'Next message', keys: 'j, arrowdown', run: () => step(1) },
      { id: 'prev', group: 'Mail', label: 'Previous message', keys: 'k, arrowup', run: () => step(-1) },
      { id: 'first', group: 'Mail', label: 'First message', keys: 'home', run: () => openAt(0) },
      { id: 'last', group: 'Mail', label: 'Last message', keys: 'end', run: () => openAt(total - 1) },
      { id: 'close', group: 'Mail', label: 'Close message', keys: 'escape', disabled: openId === null || sel, run: () => go('/browse') },
      { id: 'search', group: 'Mail', label: 'Search', keys: '/', run: () => searchBox?.focus() },
      { id: 'search-f', group: 'Mail', label: 'Search', keys: 'mod+f', anywhere: true, hidden: true, run: () => searchBox?.focus() },
      { id: 'actions', group: 'Mail', label: sel ? 'Selection actions…' : 'Message actions…', keys: '.', disabled: !m && !sel,
        run: () => (sel ? menuUnder(selBar ?? scroller, selectionMenu()) : m && menuUnder(rowAt(index) ?? scroller, messageMenu(m, index))) },
      { id: 'mark-unread', group: 'Mail', label: 'Mark as unread', keys: 'shift+u', disabled: sel || !m?.reviewed, run: () => m && mark(m, false) },
      { id: 'mark-read', group: 'Mail', label: 'Mark as read', keys: 'shift+i', disabled: sel || !m || m.reviewed, run: () => m && mark(m, true) },
      { id: 'mark-all', group: 'Mail', label: 'Mark all in this view read', keys: 'shift+a', run: markAll },
      { id: 'from-sender', group: 'Mail', label: 'Search mail from this sender', disabled: !m, run: () => m && fromSender(m) },
      { id: 'copy-sender', group: 'Mail', label: 'Copy sender address', disabled: !m, run: () => m && copy(m.envelope.from, 'Address copied') },
      { id: 'new-only', group: 'Mail', label: newOnly ? 'Show all messages' : 'Show only new messages', keys: 'n', run: () => (newOnly = !newOnly) },
      { id: 'reload', group: 'Mail', label: 'Reload list', keys: 'r', run: reset },
      { id: 'sort', group: 'Mail', label: 'Next sort order', keys: 's', run: cycleSort },
      ...sorts.map(([k, label]): Command => ({ id: `sort-${k}`, group: 'Mail', label: `Sort by ${label}`, disabled: k === sort, run: () => setSort(k) })),
      ...(account ? [{ id: 'box-all', group: 'Mailboxes', label: 'All mailboxes', disabled: mailbox === '', run: () => (mailbox = '') }] : []),
      ...(account ? boxes : []).map((b): Command => ({
        id: `box-${b.name}`, group: 'Mailboxes', label: reveal(b.display_name), disabled: mailbox === b.name, run: () => (mailbox = b.name),
      })),
    ];
  });

  const newTotal = $derived(boxes.reduce((n, b) => n + Number(b.new_count), 0));
  const title = $derived(account && mailbox ? reveal(boxes.find((b) => b.name === mailbox)?.display_name.split('/').pop() ?? mailbox) : account ? accountName(account) : 'All mail');
  // Mail a running backup found since the list was loaded (any account; a refresh sorts it out).
  const fresh = $derived(live.foundCount - baseFound);

  const stateIcon: Record<string, [string, string, string]> = {
    verified: ['check', 'text-ok', 'Verified on every destination'],
    stored: ['database', 'text-info', 'Stored, waiting for verification'],
    downloading: ['download', 'text-info', 'Downloading'],
    error: ['alert', 'text-bad', 'Error — will retry'],
  };
</script>

<div class="grid h-full gap-2" style="grid-template-columns: min({panes.list}px, 60%) minmax(0, 1fr)">
  <!-- Message list -->
  <div class="relative min-h-0 min-w-0">
  <section class="flex h-full min-h-0 flex-col overflow-hidden rounded-xl border border-line bg-panel">
    {#if selected.size}
      <!-- Same height as the title header, and swapped without a transition: the rows below must not move. -->
      <header bind:this={selBar} class="flex h-13 flex-none items-center gap-1 border-b border-line bg-accent/8 px-3" {@attach contextMenu(selectionMenu)}
        aria-label="Selection">
        <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={clearSelection} aria-label="Clear selection" title="Clear selection (Esc)"><Icon name="x" /></button>
        <span class="mr-auto truncate pl-1 font-semibold tabular-nums">{selected.size.toLocaleString()} selected</span>
        {#if selected.size < Math.min(total, SELECT_MAX)}
          <button class="link flex-none px-2 text-[0.85rem]" disabled={selectingAll} onclick={selectAll}>{selectingAll ? 'Selecting…' : `Select all ${Math.min(total, SELECT_MAX).toLocaleString()}`}</button>
        {/if}
        <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={() => markSelected(true)} title="Mark as read (Shift+I)" aria-label="Mark as read"><Icon name="check" /></button>
        <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={() => markSelected(false)} title="Mark as unread (Shift+U)" aria-label="Mark as unread"><Icon name="mail" /></button>
        <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={saveSelected} title="Save as .eml files…" aria-label="Save as .eml files"><Icon name="download" /></button>
        <button class="bg-transparent p-1.5 text-muted hover:text-bad" onclick={(e) => menuUnder(e.currentTarget, [
          { label: 'Delete from mail server…', icon: 'trash', keys: 'delete', danger: true, run: () => (deleteScope = 'server') },
          { label: 'Delete from backup…', icon: 'trash', keys: 'shift+delete', danger: true, run: () => (deleteScope = 'everywhere') },
        ])} title="Delete…" aria-label="Delete"><Icon name="trash" /></button>
      </header>
    {:else}
      <header class="flex h-13 flex-none items-center gap-2 border-b border-line px-4">
        <Icon name="inbox" />
        <h1 class="m-0 flex-1 truncate text-base font-semibold">{title}</h1>
        <button class="bg-transparent px-2 py-1 text-muted hover:text-fg" onclick={markAll} title="Mark everything in this view as read (Shift+A)">
          <Icon name="checks" size={15} /> Mark all read
        </button>
      </header>
    {/if}

    <div class="flex flex-col gap-2.5 px-3 pt-3 pb-2">
      <SearchBox bind:this={searchBox} bind:value={q} bind:field {account} onchange={onSearch} />

      <div class="flex gap-1.5">
        <button class="flex-1 justify-center py-1.5 {newOnly ? 'bg-raised text-muted' : 'bg-accent! text-white'}" onclick={() => (newOnly = false)}>
          All
        </button>
        <button class="flex-1 justify-center py-1.5 {newOnly ? 'bg-accent! text-white' : 'bg-raised text-muted'}" onclick={() => (newOnly = true)}
          title="Messages you haven't read yet">
          New <span class="tabular-nums opacity-75">{newTotal}</span>
        </button>
      </div>

      {#if account}
        <div class="flex gap-1.5">
          <select class="min-w-0 flex-1 border-transparent py-1.5 text-[0.9rem]" aria-label="Mailbox" bind:value={mailbox}>
            <option value="">All mailboxes</option>
            {#each boxes as b}
              <option value={b.name}>{'  '.repeat(b.display_name.split('/').length - 1)}{reveal(b.display_name.split('/').pop())} ({Number(b.new_count) > 0 ? `${b.new_count} new · ` : ''}{b.message_count})</option>
            {/each}
          </select>
        </div>
      {/if}
    </div>

    <div class="flex items-center justify-between gap-2 px-4 pt-2 pb-1 text-[0.85rem] text-muted">
      <span class="flex-1 truncate">{newOnly ? 'New since last visit' : 'Messages'} <span class="text-faint tabular-nums">[{total.toLocaleString()}]</span></span>
      {#if fresh > 0}
        <button class="rounded-full bg-accent/15 px-2.5 py-0.5 text-[0.8rem] text-accent-2 hover:bg-accent/25!" onclick={reset} transition:fade={{ duration: ms(150) }}>
          <Icon name="refresh" size={12} /> {fresh.toLocaleString()} new · show
        </button>
      {/if}
      <label class="m-0 flex-row items-center gap-1 font-normal">
        <span class="sr-only">Sort by</span>
        <Icon name="filter" size={13} />
        <select class="cursor-pointer border-transparent bg-transparent py-0.5 pr-1 pl-0.5 text-[0.85rem] text-muted hover:text-fg"
          value={sort} onchange={(e) => setSort(e.currentTarget.value)} title="Sort by">
          {#each sorts as [k, label]}<option value={k}>{label}</option>{/each}
        </select>
      </label>
    </div>
    {#if unindexed > 0}
      <p class="m-0 px-4 pb-1 text-[0.8rem] text-faint">{unindexed.toLocaleString()} message{unindexed === 1 ? '' : 's'} aren't indexed for full-text search yet, so only their sender, recipients and subject are searched. <button class="link text-[0.8rem]" onclick={indexNow}>Index now</button></p>
    {/if}

    <div bind:this={scroller} bind:clientHeight={viewH} onscroll={() => (scrollTop = scroller?.scrollTop ?? 0)}
      class="min-h-0 flex-1 overflow-y-auto px-2 pb-2 [scroll-behavior:auto] transition-opacity duration-200 {loading ? 'opacity-50' : ''}"
      role="listbox" aria-label="Messages" tabindex="-1" {@attach contextMenu(listMenu)}>
      {#if total === 0}
        <p class="m-0 px-3 py-10 text-center text-muted">{loading ? 'Loading…' : q ? 'No messages match this search.' : newOnly ? 'Nothing new since your last visit.' : 'No messages backed up here yet.'}</p>
      {:else}
        <ul class="relative m-0 list-none p-0" style="height: {total * ROW}px">
          {#each visible as i (i)}
            {@const m = at(i)}
            <li class="group absolute inset-x-0" style="top: {i * ROW}px; height: {ROW}px" role="option" aria-selected={!!m && (openId === m.id || selected.has(m.id))} aria-setsize={total} aria-posinset={i + 1}>
              {#if m}
                {@render row(m, i)}
                <!-- Over the avatar: shown on hover, and on every row while something is selected. -->
                <label class="absolute top-2.5 left-2.5 z-10 m-0 grid size-[34px] cursor-pointer place-items-center rounded-full bg-raised transition-opacity {selected.size ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 focus-within:opacity-100'}"
                  title="Select (x, or Ctrl/Shift-click the row)">
                  <input type="checkbox" class="m-0 size-4 cursor-pointer accent-[var(--color-accent)]" checked={selected.has(m.id)}
                    onclick={(e) => { e.preventDefault(); if (e.shiftKey) void selectRange(i); else toggle(m, i); }} aria-label="Select message" />
                </label>
              {:else}
                <div class="flex h-full items-start gap-3 px-2.5 py-2.5" aria-label="Loading">
                  <span class="mt-0.5 size-[34px] flex-none rounded-full bg-raised"></span>
                  <span class="flex flex-1 flex-col gap-2 pt-1">
                    <span class="h-3 w-2/5 rounded bg-raised"></span>
                    <span class="h-3 w-4/5 rounded bg-raised/70"></span>
                  </span>
                </div>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </section>
  <Resizer label="Resize message list" width={Math.min(panes.list, LIST_MAX)} min={LIST_MIN} max={LIST_MAX} set={(w) => (panes.list = Math.min(LIST_MAX, Math.max(LIST_MIN, w)))}
    reset={() => (panes.list = LIST_DEFAULT)} done={savePanes} />
  </div>

  <!-- Reader -->
  <section class="flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-line bg-panel">
    {#if openId !== null}
      <Viewer id={openId}>
        {#snippet toolbar()}
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={() => go('/browse')} aria-label="Close message" title="Close (Esc)"><Icon name="x" /></button>
          <span class="mx-1 h-4 w-px bg-line"></span>
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" disabled={index <= 0} onclick={() => step(-1)} aria-label="Previous message" title="Previous (k)"><span class="rotate-180"><Icon name="chevron" size={16} /></span></button>
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" disabled={index < 0 || index >= total - 1} onclick={() => step(1)} aria-label="Next message" title="Next (j)"><Icon name="chevron" size={16} /></button>
        {/snippet}
      </Viewer>
    {:else}
      <div class="grid flex-1 place-items-center p-8 text-center" in:fade={{ duration: ms(200) }}>
        <div class="flex max-w-xs flex-col items-center gap-3 text-muted">
          <span class="grid size-12 place-items-center rounded-full bg-raised text-faint"><Icon name="inbox" size={22} /></span>
          <p class="m-0 text-fg">Select a message to read it</p>
          <p class="m-0 text-[0.85rem]">Messages open in a sandboxed viewer: plain text first, no remote content, links only after you confirm. Use <kbd class="rounded bg-raised px-1">j</kbd> and <kbd class="rounded bg-raised px-1">k</kbd> to move through the list, right-click a message for its actions, and press <kbd class="rounded bg-raised px-1">?</kbd> for every shortcut.</p>
        </div>
      </div>
    {/if}
  </section>
</div>

{#snippet row(m: T.MessageSummary, i: number)}
  {@const sender = reveal(m.envelope.from_name ?? m.envelope.from) || '(unknown sender)'}
  {@const st = stateIcon[m.state]}
  {@const meta = [!account ? accountName(m.account_id) : '', reveal(m.labels.join(', '))].filter(Boolean).join(' · ')}
  <button class="flex h-full w-full items-start gap-3 overflow-hidden rounded-lg px-2.5 py-2.5 text-left active:scale-[0.99] {selected.has(m.id) ? 'bg-accent/12!' : openId === m.id ? 'bg-raised!' : 'bg-transparent'}" onclick={(e) => rowClick(e, m, i)}
    {@attach contextMenu(() => messageMenu(m, i))}>
    <span class="relative mt-0.5">
      <Avatar name={sender} seed={m.envelope.from} size={34} />
      {#if !m.reviewed}<span class="absolute -right-0.5 -bottom-0.5 size-2.5 rounded-full bg-accent-2 ring-2 ring-panel" title="Unread"></span>{/if}
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
      {#if m.snippet}
        <span class="untrusted truncate text-[0.8rem] text-faint">{#each highlights(m.snippet) as p, k (k)}{#if p.hit}<mark class="rounded-sm bg-accent/25 px-0.5 text-fg">{p.text}</mark>{:else}{p.text}{/if}{/each}</span>
      {:else}
        <span class="untrusted truncate text-[0.8rem] text-faint">{meta}</span>
      {/if}
    </span>
  </button>
{/snippet}

{#if deleteScope}
  <DeleteMessages messages={chosen()} scope={deleteScope} onclose={() => (deleteScope = null)}
    onstarted={(jobs) => { pendingJobs = [...pendingJobs, ...jobs]; deleteScope = null; clearSelection(); }} />
{/if}
