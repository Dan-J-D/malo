<script lang="ts">
  import { tick, untrack } from 'svelte';
  import { SvelteMap } from 'svelte/reactivity';
  import { api, app, qs } from '../api/client';
  import type * as T from '../api/types';
  import { live, route, scope, go, attempt, accountName, setReviewed, markSpam, notify, refreshCollections } from '../state.svelte';
  import { commands, type Command } from '../commands.svelte';
  import { contextMenu, menuUnder, copy, type Entry } from '../menu.svelte';
  import { reveal, shortDate, highlights, when, CATEGORIES, isGmail, type Category } from '../format';
  import { panes, savePanes, screen, LIST_MIN, LIST_MAX, LIST_DEFAULT } from '../layout.svelte';
  import Viewer from '../components/Viewer.svelte';
  import Composer, { type ComposeInit } from '../components/Composer.svelte';
  import Avatar from '../components/Avatar.svelte';
  import Icon from '../components/Icon.svelte';
  import Resizer from '../components/Resizer.svelte';
  import SearchBox from '../components/SearchBox.svelte';
  import Select from '../components/Select.svelte';
  import Segmented from '../components/Segmented.svelte';
  import DeleteMessages from '../components/DeleteMessages.svelte';
  import RestoreDialog from '../components/RestoreDialog.svelte';
  import ExportDialog from '../components/ExportDialog.svelte';
  import SavedSearchDialog from '../components/SavedSearchDialog.svelte';
  import CollectionsDialog from '../components/CollectionsDialog.svelte';
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
  /** Spam and Trash are kept out of the list unless asked for (a mailbox shows all it has). */
  let folder = $state<'mail' | 'spam' | 'trash'>('mail');
  const folderParam = $derived(account && mailbox ? '' : folder);
  let spamTotal = $state(0);
  let q = $state('');
  /** Search column for words without an operator ("Search in"). */
  let field = $state('');
  /** Gmail category tab ('' is every category). */
  let category: Category | '' = $state('');
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

  // A saved search from the sidebar: its words in the search box, its account in view.
  const savedId = $derived(params.get('search'));
  const saved = $derived(live.savedSearches.find((s) => s.id === savedId) ?? null);
  $effect(() => {
    const s = saved;
    if (!s) return;
    untrack(() => {
      scope.account = s.account_id ?? '';
      field = '';
      q = s.query;
      folder = 'mail';
      showDrafts = false;
      newOnly = false;
      onSearch(true);
    });
  });

  // A collection from the sidebar: searched by its name, in every account.
  const collectionId = $derived(params.get('collection'));
  const viewing = $derived(live.collections.find((c) => c.id === collectionId) ?? null);
  const collectionQuery = $derived(viewing ? `tag:"${viewing.name}"` : '');
  $effect(() => {
    const cq = collectionQuery;
    if (!cq) return;
    untrack(() => {
      scope.account = '';
      field = '';
      q = cq;
      folder = 'mail';
      showDrafts = false;
      newOnly = false;
      onSearch(true);
    });
  });

  // ── Collections: messages grouped by hand ──
  let collecting = $state<T.MessageSummary[] | null>(null);
  /** After messages went into or out of a collection: rows show it, a list filtered by
   *  collections is loaded again. */
  function collectionsChanged(ids: number[], name: string, add: boolean) {
    if (/(^|\s)-?(tag|collection):/i.test(q)) return reset();
    const set = new Set(ids);
    const lower = name.toLowerCase();
    touch((x) => {
      if (!set.has(x.id)) return;
      const rest = x.collections.filter((n) => n.toLowerCase() !== lower);
      x.collections = add ? [...rest, name].sort((a, b) => a.localeCompare(b)) : rest;
    });
    for (const id of ids) {
      const m = selected.get(id);
      if (m) selected.set(id, { ...m, collections: add ? [...m.collections.filter((n) => n.toLowerCase() !== lower), name] : m.collections.filter((n) => n.toLowerCase() !== lower) });
    }
  }
  async function removeFrom(c: T.Collection, list: T.MessageSummary[]) {
    const ids = list.map((m) => m.id);
    if (!(await attempt(() => api.post(`/collections/${c.id}/messages`, { ids, add: false }), `Removed from “${c.name}”`))) return;
    collectionsChanged(ids, c.name, false);
    await refreshCollections().catch(() => undefined);
  }

  // ── Restoring to a mail account, and saving searches ──
  let restoring = $state<{ selection: T.RestoreSelection; what: string; from: string } | null>(null);
  let savingSearch = $state(false);
  let exporting = $state<{ selection: T.RestoreSelection; what: string } | null>(null);
  const exportMessages = (list: T.MessageSummary[]) => (exporting = { selection: { by: 'messages', ids: list.map((m) => m.id) }, what: plural(list.length, 'message') });
  const plural = (n: number, one: string) => `${n.toLocaleString()} ${one}${n === 1 ? '' : 's'}`;
  function restoreMessages(list: T.MessageSummary[]) {
    const from = list.every((m) => m.account_id === list[0]?.account_id) ? (list[0]?.account_id ?? '') : '';
    restoring = { selection: { by: 'messages', ids: list.map((m) => m.id) }, what: plural(list.length, 'message'), from };
  }
  /** Everything the list shows: a search, a mailbox or a whole account. */
  const restoreView = $derived.by((): { selection: T.RestoreSelection; what: string; from: string } | null => {
    if (q.trim()) return { selection: { by: 'search', query: q.trim(), account_id: account || undefined }, what: `the ${plural(total, 'message')} this search finds`, from: account };
    if (account) return { selection: { by: 'account', account_id: account, mailbox: mailbox || undefined }, what: mailbox ? `everything in ${reveal(mailbox)}` : `all mail of ${accountName(account)}`, from: account };
    return null;
  });

  // A different account starts on its whole mailbox list.
  $effect.pre(() => {
    void account;
    mailbox = '';
  });

  // Gmail sorts mail into categories; the tabs show when the account in view (or, with every
  // account in view, any of them) is a Gmail account.
  const tabs = $derived(account ? isGmail(live.accounts.find((a) => a.id === account)) : live.accounts.some(isGmail));
  const categoryParam = $derived(tabs ? category : '');

  // ── Writing ──
  // A new message, or a draft being continued, takes the place of the reader.
  let composing: ComposeInit | null = $state(null);
  let showDrafts = $state(false);
  let drafts: T.DraftView[] = $state([]);

  function loadDrafts() {
    api.get<T.DraftView[]>('/drafts').then((d) => (drafts = d)).catch(() => undefined);
  }
  $effect(() => untrack(loadDrafts));
  const draftsInView = $derived(account ? drafts.filter((d) => d.account_id === account) : drafts);

  function compose() {
    const from = (account && live.accounts.find((a) => a.id === account && !a.imported)) || live.accounts.find((a) => a.smtp && !a.imported) || live.accounts.find((a) => !a.imported);
    if (!from) return notify('Add an account to write mail from', 'info');
    composing = { account_id: from.id, title: 'New message', message: { to: [], cc: [], bcc: [], subject: '', body: '' } };
  }

  function openDraft(d: T.DraftView) {
    composing = {
      account_id: d.account_id,
      draft_id: d.id,
      title: d.message.in_reply_to != null ? 'Reply' : 'Draft',
      message: d.message,
    };
  }

  function closeComposer() {
    composing = null;
    loadDrafts();
  }

  // Opening a message puts the reader back.
  $effect(() => {
    void openId;
    untrack(() => (composing = null));
  });

  // Also reloaded after marking mail, for the per-mailbox counts of new messages.
  function loadBoxes() {
    const a = account;
    attempt(() => api.get<T.MailboxInfo[]>(`/mailboxes${qs({ account: a })}`)).then((b) => { if (a === account) boxes = b ?? []; });
    attempt(() => api.get<T.MessageList>(`/messages${qs({ account: a, folder: 'spam', limit: 1 })}`)).then((r) => { if (a === account && r) spamTotal = r.total; });
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
    `/messages${qs({ account, mailbox: account ? mailbox : '', folder: folderParam, new: newOnly, q, field: q.trim() ? field : '', category: categoryParam, sort, limit: PAGE, offset: p * PAGE, max_id: maxId })}`;

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
    void account; void mailbox; void folderParam; void newOnly; void sort; void categoryParam;
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

  function isSelected(i: number): boolean {
    const m = i >= 0 ? at(i) : undefined;
    return !!m && selected.has(m.id);
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
          `/messages${qs({ account, mailbox: account ? mailbox : '', folder: folderParam, new: newOnly, q, sort, limit: Math.min(1000, want - offset), offset, max_id: maxId })}`,
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
    // On a phone, while choosing messages, a tap adds or removes one.
    if (screen.phone && selected.size) return toggle(m, i);
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

  /** Spam or not: the rows leave this view (or join it), so the list reloads. */
  async function spam(ids: number[], spam: boolean) {
    const jobs = await markSpam(ids, spam);
    if (!jobs) return;
    pendingJobs = [...pendingJobs, ...jobs];
    if (openId !== null && ids.includes(openId) && (folder === 'spam') !== spam) go('/browse');
    reset();
    loadBoxes();
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
      { label: 'Export as mbox, Maildir or zip…', icon: 'download', run: () => exportMessages(chosen()) },
      { label: 'Restore to a mail account…', icon: 'upload', run: () => restoreMessages(chosen()) },
      '-',
      { label: 'Add to collection…', icon: 'folder', keys: 'l', run: () => (collecting = chosen()) },
      viewing && { label: `Remove from “${viewing.name}”`, icon: 'x', run: () => viewing && removeFrom(viewing, chosen()) },
      '-',
      folder === 'spam'
        ? { label: 'Not spam', icon: 'inbox', keys: '!', run: () => spam([...selected.keys()], false) }
        : { label: 'Mark as spam', icon: 'ban', keys: '!', run: () => spam([...selected.keys()], true) },
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
      return c.reviewed === m.reviewed && c.collections === m.collections ? m : c;
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
    if (!m) return;
    // Focus follows the open message when it was on a row (e.g. one clicked before j/k), so the
    // focus ring doesn't stay behind on another row.
    const followFocus = !!scroller?.contains(document.activeElement) && document.activeElement !== scroller;
    open(m, i);
    showRow(i);
    if (followFocus) {
      await tick();
      rowAt(i)?.querySelector<HTMLElement>(':scope > button:first-child')?.focus({ preventScroll: true });
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
      { label: 'Export as mbox, Maildir or zip…', icon: 'download', run: () => exportMessages([m]) },
      { label: 'Restore to a mail account…', icon: 'upload', run: () => restoreMessages([m]) },
      '-',
      { label: 'Add to collection…', icon: 'folder', keys: 'l', run: () => (collecting = [m]) },
      ...live.collections
        .filter((c) => m.collections.some((n) => n.toLowerCase() === c.name.toLowerCase()))
        .map((c): Entry => ({ label: `Remove from “${c.name}”`, icon: 'x', run: () => removeFrom(c, [m]) })),
      '-',
      m.spam
        ? { label: 'Not spam', icon: 'inbox', keys: '!', run: () => spam([m.id], false) }
        : { label: 'Mark as spam', icon: 'ban', keys: '!', run: () => spam([m.id], true) },
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
    { label: 'Reload list', icon: 'refresh', keys: 'shift+r', run: reset },
    q.trim() && { label: 'Save this search…', icon: 'bookmark', run: () => (savingSearch = true) },
    restoreView && total > 0 && { label: 'Export all in this view…', icon: 'download', run: () => restoreView && (exporting = { selection: restoreView.selection, what: restoreView.what }) },
    restoreView && total > 0 && { label: 'Restore all in this view…', icon: 'upload', run: () => (restoring = restoreView) },
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
      { id: 'collect', group: sel ? 'Selection' : 'Mail', label: sel ? `Add ${n} selected to a collection…` : 'Add to collection…', keys: 'l',
        disabled: !sel && !m, run: () => (collecting = sel ? chosen() : m ? [m] : null) },
      { id: 'select-save', group: 'Selection', label: `Save ${n} selected as .eml files…`, disabled: !sel, run: saveSelected },
      sel
        ? { id: 'spam', group: 'Selection', label: folder === 'spam' ? `Mark ${n} selected as not spam` : `Mark ${n} selected as spam`, keys: '!', run: () => spam([...selected.keys()], folder !== 'spam') }
        : { id: 'spam', group: 'Mail', label: m?.spam ? 'Not spam' : 'Mark as spam', keys: '!', disabled: !m, run: () => m && spam([m.id], !m.spam) },
      { id: 'folder-spam', group: 'Mail', label: folder === 'spam' ? 'Leave Spam' : 'Show spam', keys: 'g s', disabled: !!(account && mailbox), run: () => openFolder(folder === 'spam' ? 'mail' : 'spam') },
      { id: 'folder-trash', group: 'Mail', label: folder === 'trash' ? 'Leave Trash' : 'Show trash', keys: 'g t', disabled: !!(account && mailbox), run: () => openFolder(folder === 'trash' ? 'mail' : 'trash') },
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
      { id: 'compose', group: 'Mail', label: 'Write a message', keys: 'c', run: compose },
      { id: 'drafts', group: 'Mail', label: showDrafts ? 'Show messages' : 'Show drafts', keys: 'shift+d', run: () => { showDrafts = !showDrafts; loadDrafts(); } },
      ...(tabs ? (['', ...Object.keys(CATEGORIES)] as (Category | '')[]).map((c): Command => ({
        id: `category-${c || 'all'}`, group: 'Categories', label: c ? CATEGORIES[c].label : 'Every category', disabled: category === c, run: () => (category = c),
      })) : []),
      { id: 'search-f', group: 'Mail', label: 'Search', keys: 'mod+f', anywhere: true, hidden: true, run: () => searchBox?.focus() },
      { id: 'actions', group: 'Mail', label: sel ? 'Selection actions…' : 'Message actions…', keys: '.', disabled: !m && !sel,
        run: () => (sel ? menuUnder(selBar ?? scroller, selectionMenu()) : m && menuUnder(rowAt(index) ?? scroller, messageMenu(m, index))) },
      { id: 'mark-unread', group: 'Mail', label: 'Mark as unread', keys: 'shift+u', disabled: sel || !m?.reviewed, run: () => m && mark(m, false) },
      { id: 'mark-read', group: 'Mail', label: 'Mark as read', keys: 'shift+i', disabled: sel || !m || m.reviewed, run: () => m && mark(m, true) },
      { id: 'mark-all', group: 'Mail', label: 'Mark all in this view read', keys: 'shift+a', run: markAll },
      { id: 'from-sender', group: 'Mail', label: 'Search mail from this sender', disabled: !m, run: () => m && fromSender(m) },
      { id: 'copy-sender', group: 'Mail', label: 'Copy sender address', disabled: !m, run: () => m && copy(m.envelope.from, 'Address copied') },
      { id: 'new-only', group: 'Mail', label: newOnly ? 'Show all messages' : 'Show only new messages', keys: 'n', run: () => (newOnly = !newOnly) },
      { id: 'reload', group: 'Mail', label: 'Reload list', keys: 'shift+r', run: reset },
      { id: 'sort', group: 'Mail', label: 'Next sort order', keys: 's', run: cycleSort },
      ...sorts.map(([k, label]): Command => ({ id: `sort-${k}`, group: 'Mail', label: `Sort by ${label}`, disabled: k === sort, run: () => setSort(k) })),
      ...(account ? [{ id: 'box-all', group: 'Mailboxes', label: 'All mailboxes', disabled: mailbox === '', run: () => (mailbox = '') }] : []),
      ...(account ? boxes : []).map((b): Command => ({
        id: `box-${b.name}`, group: 'Mailboxes', label: reveal(b.display_name), disabled: mailbox === b.name, run: () => (mailbox = b.name),
      })),
    ];
  });

  function openFolder(f: typeof folder) {
    folder = f;
    if (f !== 'mail') { showDrafts = false; newOnly = false; }
    if (openId !== null) go('/browse');
  }

  $effect(() => {
    screen.writing = composing !== null;
    return () => (screen.writing = false);
  });

  // A mailbox shows everything in it, spam or not.
  $effect(() => {
    if (account && mailbox) untrack(() => (folder = 'mail'));
  });
  /** Showing Spam or Trash rather than the mail itself. */
  const inFolder = $derived(folder !== 'mail' && !(account && mailbox));

  const newTotal = $derived(boxes.reduce((n, b) => n + Number(b.new_count), 0));
  const inCollection = $derived(!!viewing && q.trim() === collectionQuery);
  const title = $derived(inCollection && viewing ? viewing.name : account && mailbox ? reveal(boxes.find((b) => b.name === mailbox)?.display_name.split('/').pop() ?? mailbox) : folder === 'spam' ? 'Spam' : folder === 'trash' ? 'Trash' : account ? accountName(account) : 'All mail');
  // Mail a running backup found since the list was loaded (any account; a refresh sorts it out).
  const fresh = $derived(live.foundCount - baseFound);

  const stateIcon: Record<string, [string, string, string]> = {
    verified: ['check', 'text-ok', 'Verified on every destination'],
    stored: ['database', 'text-info', 'Stored, waiting for verification'],
    downloading: ['download', 'text-info', 'Downloading'],
    error: ['alert', 'text-bad', 'Error — will retry'],
  };
</script>

<!-- On a phone, one pane at a time: the list, or the message (or draft) open in the reader. -->
<div class="grid h-full {screen.phone ? '' : 'gap-2'}" style="grid-template-columns: {screen.phone ? 'minmax(0, 1fr)' : `min(${panes.list}px, 60%) minmax(0, 1fr)`}">
  <!-- Message list -->
  <div class="relative min-h-0 min-w-0 {screen.phone && (openId !== null || composing) ? 'hidden' : ''}">
  <section class="flex h-full min-h-0 flex-col overflow-hidden bg-panel {screen.phone ? '' : 'rounded-xl border border-line'}">
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
        <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={() => (collecting = chosen())} title="Add to collection… (l)" aria-label="Add to collection"><Icon name="folder" /></button>
        <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={saveSelected} title="Save as .eml files…" aria-label="Save as .eml files"><Icon name="download" /></button>
        {#if folder === 'spam'}
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={() => spam([...selected.keys()], false)} title="Not spam (!)" aria-label="Not spam"><Icon name="inbox" /></button>
        {:else}
          <button class="bg-transparent p-1.5 text-muted hover:text-warn" onclick={() => spam([...selected.keys()], true)} title="Mark as spam (!)" aria-label="Mark as spam"><Icon name="ban" /></button>
        {/if}
        <button class="bg-transparent p-1.5 text-muted hover:text-bad" onclick={(e) => menuUnder(e.currentTarget, [
          { label: 'Delete from mail server…', icon: 'trash', keys: 'delete', danger: true, run: () => (deleteScope = 'server') },
          { label: 'Delete from backup…', icon: 'trash', keys: 'shift+delete', danger: true, run: () => (deleteScope = 'everywhere') },
        ])} title="Delete…" aria-label="Delete"><Icon name="trash" /></button>
      </header>
    {:else}
      <header class="flex h-13 flex-none items-center gap-2 border-b border-line px-4">
        <Icon name={inFolder ? (folder === 'spam' ? 'ban' : 'trash') : inCollection ? 'folder' : 'inbox'} />
        <h1 class="m-0 flex-1 truncate text-base font-semibold">{title}</h1>
        <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={markAll} title="Mark everything in this view as read (Shift+A)" aria-label="Mark all read">
          <Icon name="checks" size={15} />
        </button>
        <button class="primary px-2.5 py-1 text-[0.9rem]" onclick={compose} title="Write a message (c)">
          <Icon name="pencil" size={14} /> Compose
        </button>
      </header>
    {/if}

    <div class="flex flex-col gap-2.5 px-3 pt-3 pb-2">
      <div class="flex items-center gap-1.5">
        <div class="min-w-0 flex-1"><SearchBox bind:this={searchBox} bind:value={q} bind:field {account} onchange={onSearch} /></div>
        {#if q.trim() && !(saved && saved.query === q.trim())}
          <button class="flex-none bg-transparent p-1.5 text-muted hover:text-fg" onclick={() => (savingSearch = true)} title="Save this search" aria-label="Save this search"><Icon name="bookmark" size={15} /></button>
        {/if}
      </div>

      {#if inFolder}
        <!-- In place of the view switch, the same height: where this is, and the way back. -->
        <div class="flex min-h-9 items-center gap-2.5 rounded-lg py-1.5 pr-1.5 pl-3 text-[0.85rem] {folder === 'spam' ? 'bg-warn/12 text-fg' : 'bg-raised text-fg'}" in:fade={{ duration: ms(150) }}>
          <span class="flex-none {folder === 'spam' ? 'text-warn' : 'text-muted'}"><Icon name={folder === 'spam' ? 'ban' : 'trash'} size={14} /></span>
          <span class="min-w-0 flex-1 leading-snug text-muted">
            {#if folder === 'spam'}
              Junk your mail server filed, and mail you marked. <span class="text-fg">Not spam</span> returns it to the inbox.
            {:else}
              In your mail server's Trash. The backup stays until you delete it.
            {/if}
          </span>
          <button class="flex-none px-2 py-1 text-[0.85rem]" onclick={() => openFolder('mail')} title="Back to your mail">
            <Icon name="arrow-left" size={13} /> {account ? accountName(account) : 'All mail'}
          </button>
        </div>
      {:else}
      <Segmented label="Show" value={showDrafts ? 'drafts' : newOnly ? 'new' : 'all'}
        onchange={(v) => { showDrafts = v === 'drafts'; newOnly = v === 'new'; if (showDrafts) loadDrafts(); }}
        options={[
          { value: 'all', label: 'All' },
          { value: 'new', label: 'New', count: newTotal, title: "Messages you haven't read yet" },
          { value: 'drafts', label: 'Drafts', count: draftsInView.length || undefined, title: 'Messages you started writing (Shift+D)' },
        ]} />
      {/if}

      {#if tabs && !showDrafts}
        <!-- Gmail categories: the chosen one is named, the others are icons with a tooltip. -->
        <Segmented label="Gmail categories" compact bind:value={category} options={[
          { value: '', label: 'All', icon: 'layers', title: 'Every category', bg: 'bg-panel', tone: 'text-fg' },
          ...(Object.keys(CATEGORIES) as Category[]).map((c) => ({ value: c, label: CATEGORIES[c].label, icon: CATEGORIES[c].icon, bg: CATEGORIES[c].bg, tone: CATEGORIES[c].tone })),
        ]} />
      {/if}

      {#if account}
        <div class="flex gap-1.5">
          <Select class="min-w-0 flex-1 text-[0.9rem]" label="Mailbox" bind:value={mailbox} options={[
            { value: '', label: 'All mailboxes' },
            ...boxes.map((b) => ({
              value: b.name,
              label: reveal(b.display_name.split('/').pop()),
              depth: b.display_name.split('/').length - 1,
              hint: `${Number(b.new_count) > 0 ? `${Number(b.new_count).toLocaleString()} new · ` : ''}${Number(b.message_count).toLocaleString()}`,
            })),
          ]} />
        </div>
      {/if}
    </div>

    {#if showDrafts}
    <div class="min-h-0 flex-1 overflow-y-auto px-2 pt-1 pb-2">
      {#if draftsInView.length === 0}
        <div class="flex flex-col items-center gap-3 px-3 py-10 text-center text-muted">
          <p class="m-0">No drafts. What you start writing is kept here until you send it.</p>
          <button class="primary" onclick={compose}><Icon name="pencil" size={14} /> Write a message</button>
        </div>
      {:else}
        <ul class="m-0 flex list-none flex-col p-0">
          {#each draftsInView as d (d.id)}
            {@const to = d.message.to.join(', ')}
            <li class="mt-0">
              <button class="flex w-full items-start gap-3 rounded-lg py-2.5 pr-2.5 pl-3 text-left {composing?.draft_id === d.id ? 'bg-raised!' : 'bg-transparent'}" onclick={() => openDraft(d)}
                {@attach contextMenu(() => [
                  { label: 'Continue writing', icon: 'pencil', run: () => openDraft(d) },
                  { label: 'Delete draft', icon: 'trash', danger: true, run: async () => { await attempt(() => api.del(`/drafts/${d.id}`)); if (composing?.draft_id === d.id) composing = null; loadDrafts(); } },
                ])}>
                <span class="mt-0.5 grid size-[34px] flex-none place-items-center rounded-full bg-raised text-muted"><Icon name={d.message.in_reply_to != null ? 'reply' : 'draft'} size={15} /></span>
                <span class="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span class="flex items-baseline gap-2">
                    <span class="untrusted flex-1 truncate {to ? 'text-fg' : 'text-faint'}">{to ? `To ${to}` : 'No recipients yet'}</span>
                    <span class="flex-none text-[0.8rem] text-muted tabular-nums" title={when(d.updated_at)}>{shortDate(d.updated_at)}</span>
                  </span>
                  <span class="subject truncate text-muted">{d.message.subject || '(no subject)'}</span>
                  <span class="untrusted truncate text-[0.8rem] text-faint">{d.message.body.trim().split('\n')[0] || (!account ? accountName(d.account_id) : '')}</span>
                </span>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
    {:else}
    <div class="flex items-center justify-between gap-2 px-4 pt-2 pb-1 text-[0.85rem] text-muted">
      <span class="flex-1 truncate">{inFolder ? (folder === 'spam' ? 'Spam' : 'Trash') : newOnly ? 'New since last visit' : 'Messages'} <span class="text-faint tabular-nums">[{total.toLocaleString()}]</span></span>
      {#if fresh > 0}
        <button class="rounded-full bg-accent/15 px-2.5 py-0.5 text-[0.8rem] text-accent-2 hover:bg-accent/25!" onclick={reset} transition:fade={{ duration: ms(150) }}>
          <Icon name="refresh" size={12} /> {fresh.toLocaleString()} new · show
        </button>
      {/if}
      {#if !inFolder && !(account && mailbox)}
        <!-- Set aside from the list, one click away. -->
        <span class="flex flex-none items-center">
          <button class="gap-1 bg-transparent px-1.5 py-0.5 text-[0.85rem] text-muted hover:text-fg" onclick={() => openFolder('spam')} title="Show spam (g s)">
            <Icon name="ban" size={13} /> Spam{#if spamTotal}<span class="text-faint tabular-nums">{spamTotal.toLocaleString()}</span>{/if}
          </button>
          <button class="bg-transparent p-1 text-muted hover:text-fg" onclick={() => openFolder('trash')} title="Show trash (g t)" aria-label="Show trash"><Icon name="trash" size={13} /></button>
        </span>
      {/if}
      <Select variant="ghost" class="text-[0.85rem]" label="Sort by" title="Sort by" value={sort} onchange={setSort}
        options={sorts.map(([k, label]) => ({ value: k, label }))} />
    </div>
    {#if unindexed > 0}
      <p class="m-0 px-4 pb-1 text-[0.8rem] text-faint">{unindexed.toLocaleString()} message{unindexed === 1 ? '' : 's'} aren't indexed for full-text search yet, so only their sender, recipients and subject are searched. <button class="link text-[0.8rem]" onclick={indexNow}>Index now</button></p>
    {/if}

    <div bind:this={scroller} bind:clientHeight={viewH} onscroll={() => (scrollTop = scroller?.scrollTop ?? 0)}
      class="min-h-0 flex-1 overflow-y-auto px-2 pb-2 [scroll-behavior:auto] transition-opacity duration-200 {loading ? 'opacity-50' : ''}"
      role="listbox" aria-label="Messages" tabindex="-1" {@attach contextMenu(listMenu)}>
      {#if total === 0}
        <p class="m-0 px-3 py-10 text-center text-muted">{loading ? 'Loading…' : q ? 'No messages match this search.' : inFolder ? (folder === 'spam' ? 'No spam. Messages you mark as spam, or your mail server files as junk, show up here.' : 'Trash is empty.') : newOnly ? 'Nothing new since your last visit.' : 'No messages backed up here yet.'}</p>
      {:else}
        <ul class="relative m-0 list-none p-0" style="height: {total * ROW}px">
          {#each visible as i (i)}
            {@const m = at(i)}
            <li class="group absolute inset-x-0 mt-0" style="top: {i * ROW}px; height: {ROW}px" role="option" aria-selected={!!m && (openId === m.id || selected.has(m.id))} aria-setsize={total} aria-posinset={i + 1}>
              {#if m}
                {@render row(m, i)}
                <!-- Its own column left of the avatar, the full height of the row: shown on hover, and
                     on every row while something is selected. -->
                {@const on = selected.has(m.id)}
                {#if screen.phone}
                  <!-- No hover on a touch screen: the avatar is the checkbox, and turns into a tick. -->
                  <button class="absolute top-0 left-0 z-10 flex h-full w-[3.4rem] items-start justify-center rounded-l-lg bg-transparent! p-0 pt-[0.7rem] pl-1 active:scale-100!"
                    role="checkbox" aria-checked={on} aria-label="Select message" onclick={() => toggle(m, i)}>
                    {#if on}<span class="grid size-[34px] animate-[check-pop_300ms_var(--ease-spring)] place-items-center rounded-full bg-accent text-white"><Icon name="check" size={16} /></span>{/if}
                  </button>
                {:else}
                <button class="absolute inset-y-0 left-0 z-10 flex w-11 items-start justify-center rounded-l-lg bg-transparent p-0 pt-5 hover:bg-transparent! active:scale-100! {on || selected.size ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100'}"
                  role="checkbox" aria-checked={on} aria-label="Select message" title="Select (x, or Ctrl/Shift-click the row)"
                  onclick={(e) => { if (e.shiftKey) void selectRange(i); else toggle(m, i); }}>
                  <span class="grid size-[18px] place-items-center rounded-[6px] border-[1.5px] transition-colors {on ? 'border-accent bg-accent text-white' : 'border-fg/30 hover:border-accent-2'}">
                    {#if on}<span class="grid animate-[check-pop_300ms_var(--ease-spring)]"><Icon name="check" size={12} /></span>{/if}
                  </span>
                </button>
                {/if}
              {:else}
                <div class="flex h-full items-start gap-3 py-2.5 pr-2.5 {screen.phone ? 'pl-3' : 'pl-11'}" aria-label="Loading">
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
    {/if}
  </section>
  {#if !screen.phone}
  <Resizer label="Resize message list" width={Math.min(panes.list, LIST_MAX)} min={LIST_MIN} max={LIST_MAX} set={(w) => (panes.list = Math.min(LIST_MAX, Math.max(LIST_MIN, w)))}
    reset={() => (panes.list = LIST_DEFAULT)} done={savePanes} />
  {/if}
  </div>

  <!-- Reader -->
  <section class="flex min-h-0 min-w-0 flex-col overflow-hidden bg-panel {screen.phone ? (openId !== null || composing ? '' : 'hidden') : 'rounded-xl border border-line'}">
    {#if composing}
      {#key composing}
        <Composer init={composing} onclose={closeComposer} onsent={closeComposer} />
      {/key}
    {:else if openId !== null}
      <Viewer id={openId} ondelete={deleteOne} onspam={(m, s) => spam([m.id], s)}>
        {#snippet toolbar()}
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={() => go('/browse')} aria-label={screen.phone ? 'Back to the list' : 'Close message'} title={screen.phone ? 'Back' : 'Close (Esc)'}><Icon name={screen.phone ? 'arrow-left' : 'x'} /></button>
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
  {@const sender = reveal(m.envelope.from_name || m.envelope.from) || '(unknown sender)'}
  {@const st = stateIcon[m.state]}
  {@const savedOk = m.state === 'verified' || m.state === 'stored'}
  {@const savedText = m.state === 'stored' ? `Backed up on ${m.stored} of ${m.destinations} destinations, waiting for verification` : m.state === 'error' ? `Not backed up: ${m.error ?? 'error'} (will retry)` : m.state === 'verified' ? 'Backed up and verified on every destination' : m.state === 'downloading' ? 'Not backed up yet: downloading' : 'Not backed up yet'}
  {@const serverText = m.deleted_on_server ? 'Not on the mail server any more: only the backup has it' : `On the mail server (${accountName(m.account_id)})`}
  {@const cat = tabs && !categoryParam && m.category && m.category in CATEGORIES ? CATEGORIES[m.category as Category] : null}
  {@const meta = [!account ? accountName(m.account_id) : '', reveal(m.labels.join(', '))].filter(Boolean).join(' · ')}
  <!-- Neighbouring selected rows join into one block. -->
  {@const on = selected.has(m.id)}
  {@const joinUp = on && isSelected(i - 1)}
  {@const joinDown = on && isSelected(i + 1)}
  <button class="flex h-full w-full items-start gap-3 overflow-hidden rounded-lg py-2.5 pr-2.5 {screen.phone ? 'pl-3' : 'pl-11'} text-left active:scale-[0.99] {joinUp ? 'rounded-t-none' : ''} {joinDown ? 'rounded-b-none' : ''} {on ? 'bg-accent/12! hover:bg-accent/18!' : openId === m.id ? 'bg-raised! hover:bg-hover!' : 'bg-transparent hover:bg-hover/50!'} {openId === m.id ? 'shadow-[inset_3px_0_0_var(--accent-2)]' : ''}" onclick={(e) => rowClick(e, m, i)}
    {@attach contextMenu(() => messageMenu(m, i))}>
    <span class="relative mt-0.5">
      <Avatar name={sender} seed={m.envelope.from} size={34} />
      {#if !m.reviewed}<span class="absolute -right-0.5 -bottom-0.5 size-2.5 rounded-full bg-accent-2 ring-2 ring-panel" title="Unread"></span>{/if}
    </span>
    <span class="flex min-w-0 flex-1 flex-col gap-0.5">
      <span class="flex items-baseline gap-2">
        <span class="flex min-w-0 flex-1 items-baseline gap-1.5">
          <span class="untrusted truncate {m.reviewed ? 'text-fg/80' : 'font-semibold text-fg'}">{sender}</span>
          {#if m.thread_size > 1}<span class="flex-none text-[0.8rem] text-faint tabular-nums" title="{m.thread_size} messages in this conversation">[{m.thread_size}]</span>{/if}
        </span>
        <span class="flex-none text-[0.8rem] text-muted tabular-nums">{shortDate(m.envelope.date ?? m.internal_date)}</span>
      </span>
      <span class="flex items-center gap-2">
        <span class="subject flex-1 truncate text-muted">{reveal(m.envelope.subject) || '(no subject)'}</span>
        <span class="flex flex-none items-center gap-1.5">
          {#if cat}<span class={cat.tone} title={cat.label}><Icon name={cat.icon} size={13} /></span>{/if}
          {#if m.envelope.attachment_count}<span class="text-faint" title="{m.envelope.attachment_count} attachment(s)"><Icon name="paperclip" size={13} /></span>{/if}
          {#if m.collections.length}<span class="text-faint" title="In {m.collections.join(', ')}" role="img" aria-label="In collections: {m.collections.join(', ')}"><Icon name="folder" size={13} /></span>{/if}
          {#if m.spam && folder !== 'spam'}<span class="text-warn" title="Spam"><Icon name="ban" size={13} /></span>{/if}
          <!-- Two marks side by side, like sent/delivered ticks: the first for the backup, the
               second for the account's mail server. A cross where it isn't (yet). -->
          <span class="flex" title={`${savedText}\n${serverText}`} role="img" aria-label="{savedText}. {serverText}.">
            <svg width="20" height="13" viewBox="0 0 30 20" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <g class={st?.[1] ?? 'text-faint'}>
                {#if savedOk}<path d="M2 10.5l5 5L18 4" />{:else}<path d="M4 5l10 10M14 5 4 15" />{/if}
              </g>
              <g class={m.deleted_on_server ? 'text-faint' : 'text-ok'}>
                {#if !m.deleted_on_server}<path d="M12.5 13l2.5 2.5L26 4" />{:else}<path d="M17 5l10 10M27 5 17 15" />{/if}
              </g>
            </svg>
          </span>
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
{#if exporting}
  <ExportDialog {...exporting} onclose={() => (exporting = null)} />
{/if}
{#if restoring}
  <RestoreDialog {...restoring} onclose={() => (restoring = null)} />
{/if}
{#if collecting}
  <CollectionsDialog messages={collecting} onchange={collectionsChanged} onclose={() => (collecting = null)} />
{/if}
{#if savingSearch}
  <SavedSearchDialog query={q.trim()} {account} onclose={(s) => { savingSearch = false; if (s) go(`/browse?search=${s.id}`); }} />
{/if}
