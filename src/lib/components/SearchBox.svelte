<script lang="ts" module>
  /** One operator of a search (`from:alice`, `-has:attachment`, `-word`), shown as a chip. */
  export interface Chip {
    field: string;
    value: string;
    negate: boolean;
    /** Shown instead of the value (a sender's name). */
    label?: string;
  }

  const COLUMNS = ['from', 'to', 'cc', 'bcc', 'subject', 'body', 'file', 'attachment', 'filename'];
  const FLAGS: Record<string, string[]> = { has: ['attachment'], is: ['unread', 'read', 'purged'] };
  const DATES = ['before', 'after'];
  const DATE = /^\d{4}(-\d{2}(-\d{2})?)?$/;

  interface Tok {
    raw: string;
    field: string;
    value: string;
    negate: boolean;
    quoted: boolean;
    closed: boolean;
  }

  /** Splits a search the way the server does (see malo-core search::parse). */
  function tokens(s: string): Tok[] {
    const out: Tok[] = [];
    let i = 0;
    while (i < s.length) {
      while (i < s.length && /\s/.test(s[i])) i++;
      if (i >= s.length) break;
      const start = i;
      const negate = s[i] === '-';
      if (negate) i++;
      let field = '';
      const m = /^([a-zA-Z]+):/.exec(s.slice(i));
      if (m && (COLUMNS.includes(m[1].toLowerCase()) || m[1].toLowerCase() in FLAGS || DATES.includes(m[1].toLowerCase()))) {
        field = m[1].toLowerCase();
        i += m[0].length;
      }
      let value: string;
      let quoted = false;
      let closed = true;
      if (s[i] === '"') {
        quoted = true;
        const j = s.indexOf('"', i + 1);
        closed = j >= 0;
        value = s.slice(i + 1, closed ? j : s.length);
        i = closed ? j + 1 : s.length;
      } else {
        const k = s.slice(i).search(/\s/);
        const end = k < 0 ? s.length : i + k;
        value = s.slice(i, end);
        i = end;
      }
      out.push({ raw: s.slice(start, i), field, value, negate, quoted, closed });
    }
    return out;
  }

  function chipOf(t: Tok): Chip | null {
    if (!t.closed || !t.value) return null;
    const v = t.value.toLowerCase();
    if (t.field in FLAGS) return FLAGS[t.field].includes(v) ? { field: t.field, value: v, negate: t.negate } : null;
    if (DATES.includes(t.field)) return !t.negate && DATE.test(t.value) ? { field: t.field, value: t.value, negate: false } : null;
    if (t.field) return { field: t.field, value: t.value, negate: t.negate };
    return t.negate ? { field: '', value: t.value, negate: true } : null;
  }

  export function serialize(c: Chip): string {
    const v = c.value.replace(/"/g, '');
    return `${c.negate ? '-' : ''}${c.field ? `${c.field}:` : ''}${/\s/.test(v) || !v ? `"${v}"` : v}`;
  }

  /**
   * Moves the finished operators of `text` into chips. The last word stays while it may still be
   * typed (no trailing space) unless `all`. A search with OR stays text: its words belong together.
   */
  export function extract(text: string, all: boolean): { chips: Chip[]; text: string } {
    const toks = tokens(text);
    if (toks.some((t) => !t.field && !t.quoted && !t.negate && t.value === 'OR')) return { chips: [], text };
    const trailing = /\s$/.test(text);
    const chips: Chip[] = [];
    const rest: string[] = [];
    toks.forEach((t, i) => {
      const typing = i === toks.length - 1 && !trailing && !all;
      const c = typing ? null : chipOf(t);
      if (c) chips.push(c);
      else rest.push(t.raw);
    });
    return { chips, text: rest.join(' ') + (trailing && rest.length ? ' ' : '') };
  }
</script>

<script lang="ts">
  import Select from './Select.svelte';
  import { untrack } from 'svelte';
  import { api, qs } from '../api/client';
  import type * as T from '../api/types';
  import Icon from './Icon.svelte';

  let {
    value = $bindable(''),
    field = $bindable(''),
    account = null,
    onchange,
  }: { value?: string; field?: string; account?: string | null; onchange: (immediate: boolean) => void } = $props();

  // The search the page starts with (kept in the URL or restored), split into chips and words.
  const initial = extract(untrack(() => value), true);
  let chips: Chip[] = $state(initial.chips);
  let text = $state(initial.text);
  let input: HTMLInputElement | undefined = $state();
  let focused = $state(false);
  let caretAtEnd = $state(true);
  let active = $state(-1);
  let closed = $state(false);
  let helpOpen = $state(false);
  let filtersOpen = $state(false);
  let remote: { field: string; prefix: string; items: T.SearchSuggestion[] } | null = $state(null);
  const listId = `search-suggest-${Math.random().toString(36).slice(2)}`;

  function compose(): string {
    return [...chips.map(serialize), text.trim()].filter(Boolean).join(' ');
  }

  /** Replaces the whole search (e.g. "Search mail from this sender"). */
  export function set(q: string) {
    const r = extract(q, true);
    chips = r.chips;
    text = r.text;
    publish(true);
  }

  export function focus() {
    input?.focus();
  }

  function publish(immediate: boolean) {
    const q = compose();
    if (q === value) return;
    value = q;
    onchange(immediate);
  }

  function setChips(next: Chip[]) {
    chips = next;
    publish(true);
  }

  /** Whether chip `n` takes the place of `old`: one date of each kind, one of read/unread. */
  function replaces(n: Chip, old: Chip): boolean {
    if (n.field !== old.field) return false;
    if (DATES.includes(n.field)) return true;
    if (n.field === 'is' && ['read', 'unread'].includes(n.value) && ['read', 'unread'].includes(old.value)) return true;
    return n.field in FLAGS && n.value === old.value;
  }

  function add(list: Chip[], n: Chip): Chip[] {
    return [...list.filter((c) => !replaces(n, c)), n];
  }

  function absorb(all: boolean) {
    const r = extract(text, all);
    if (r.chips.length) {
      chips = r.chips.reduce(add, chips);
      text = r.text;
    }
  }

  function oninput() {
    closed = false;
    active = -1;
    absorb(false);
    trackCaret();
    publish(false);
  }

  function trackCaret() {
    caretAtEnd = !input || input.selectionStart === text.length;
  }

  // ── Suggestions ──

  interface Item {
    key: string;
    label: string;
    hint?: string;
    /** Replaces the word being typed (keeps typing, e.g. `from:`). */
    insert?: string;
    /** Becomes a chip. */
    chip?: Chip;
  }

  const OPS: { op: string; hint: string; chip?: Chip }[] = [
    { op: 'from:', hint: 'Sender name or address' },
    { op: 'to:', hint: 'Recipient, also cc' },
    { op: 'subject:', hint: 'Words in the subject' },
    { op: 'body:', hint: 'Words in the message text' },
    { op: 'file:', hint: 'Attachment name' },
    { op: 'after:', hint: 'Received on or after a date' },
    { op: 'before:', hint: 'Received before a date' },
    { op: 'has:attachment', hint: 'With attachments', chip: { field: 'has', value: 'attachment', negate: false } },
    { op: 'is:unread', hint: 'Not read yet', chip: { field: 'is', value: 'unread', negate: false } },
    { op: 'is:read', hint: 'Already read', chip: { field: 'is', value: 'read', negate: false } },
    { op: 'is:purged', hint: 'Deleted on the mail server, only in the backup', chip: { field: 'is', value: 'purged', negate: false } },
  ];

  /** The word at the end of the input, while the caret is there. */
  const current = $derived.by(() => {
    if (!caretAtEnd || /\s$/.test(text) || !text) return null;
    const toks = tokens(text);
    const t = toks[toks.length - 1];
    return t && !t.closed ? null : t ?? null;
  });

  function ymd(d: Date): string {
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }
  function daysAgo(n: number): string {
    return ymd(new Date(Date.now() - n * 864e5));
  }

  const items: Item[] = $derived.by(() => {
    const t = current;
    if (!t) return [];
    const neg = t.negate;
    if (!t.field) {
      if (t.quoted) return [];
      const w = t.value.toLowerCase();
      if (!w) return [];
      return OPS.filter((o) => o.op.startsWith(w) && o.op !== w).map((o) => ({
        key: o.op,
        label: `${neg ? '-' : ''}${o.op}`,
        hint: o.hint,
        ...(o.chip ? { chip: { ...o.chip, negate: neg } } : { insert: `${neg ? '-' : ''}${o.op}` }),
      }));
    }
    if (DATES.includes(t.field)) {
      const presets: [string, string][] = [['Today', daysAgo(0)], ['A week ago', daysAgo(7)], ['A month ago', daysAgo(30)], ['A year ago', daysAgo(365)], ['Start of this year', `${new Date().getFullYear()}`]];
      return presets
        .filter(([, d]) => d.startsWith(t.value))
        .map(([label, d]) => ({ key: d + label, label: d, hint: label, chip: { field: t.field, value: d, negate: false } }));
    }
    if (t.field in FLAGS) {
      return FLAGS[t.field]
        .filter((v) => v.startsWith(t.value.toLowerCase()))
        .map((v) => ({ key: v, label: `${neg ? '-' : ''}${t.field}:${v}`, hint: OPS.find((o) => o.op === `${t.field}:${v}`)?.hint, chip: { field: t.field, value: v, negate: neg } }));
    }
    const kind = t.field === 'from' ? 'from' : ['to', 'cc', 'bcc'].includes(t.field) ? 'to' : ['file', 'attachment', 'filename'].includes(t.field) ? 'file' : null;
    if (!kind || !remote || remote.field !== kind || remote.prefix !== t.value) return [];
    return remote.items.map((s) => ({
      key: s.value,
      label: s.value,
      hint: [s.name, `${s.count.toLocaleString()} message${s.count === 1 ? '' : 's'}`].filter(Boolean).join(' · '),
      chip: { field: t.field, value: s.value, negate: neg, label: s.name ?? undefined },
    }));
  });

  // Values for from:, to: and file: come from the server, a moment after typing stops.
  let suggestTimer: ReturnType<typeof setTimeout>;
  $effect(() => {
    const t = current;
    const kind = !t ? null : t.field === 'from' ? 'from' : ['to', 'cc', 'bcc'].includes(t.field) ? 'to' : ['file', 'attachment', 'filename'].includes(t.field) ? 'file' : null;
    clearTimeout(suggestTimer);
    if (!t || !kind || !focused) return;
    const prefix = t.value;
    const acc = account;
    suggestTimer = setTimeout(async () => {
      try {
        const got = await api.get<T.SearchSuggestion[]>(`/search/suggest${qs({ field: kind, prefix, account: acc })}`);
        if (current?.value === prefix) remote = { field: kind, prefix, items: got };
      } catch {
        // Suggestions are a convenience: typing works without them.
      }
    }, 120);
  });

  const open = $derived(focused && !closed && items.length > 0);

  function pick(it: Item) {
    const toks = tokens(text);
    const before = toks.slice(0, -1).map((t) => t.raw).join(' ');
    if (it.insert) {
      text = (before ? `${before} ` : '') + it.insert;
      active = -1;
      queueMicrotask(() => input?.setSelectionRange(text.length, text.length));
    } else if (it.chip) {
      text = before ? `${before} ` : '';
      chips = add(chips, it.chip);
      active = -1;
    }
    input?.focus();
    publish(true);
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.isComposing) return;
    if (open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      const n = items.length;
      active = e.key === 'ArrowDown' ? (active + 1) % n : (active - 1 + n) % n;
    } else if (open && (e.key === 'Enter' || e.key === 'Tab') && (active >= 0 || e.key === 'Tab')) {
      e.preventDefault();
      pick(items[Math.max(active, 0)]);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      absorb(true);
      closed = true;
      publish(true);
    } else if (e.key === 'Escape' && open) {
      e.preventDefault();
      closed = true;
    } else if (e.key === 'Escape' && helpOpen) {
      e.preventDefault();
      helpOpen = false;
    } else if (e.key === 'Backspace' && input?.selectionStart === 0 && input.selectionEnd === 0 && chips.length) {
      e.preventDefault();
      setChips(chips.slice(0, -1));
    }
  }

  /** Puts a chip back into the text to change it. */
  function edit(i: number) {
    const c = chips[i];
    chips = chips.filter((_, k) => k !== i);
    text = `${text.trim() ? `${text.trim()} ` : ''}${serialize(c)}`;
    closed = false;
    input?.focus();
    queueMicrotask(() => {
      input?.setSelectionRange(text.length, text.length);
      trackCaret();
    });
    publish(true);
  }

  function chipText(c: Chip): [string, string] {
    if (c.field === 'has') return ['', c.negate ? 'No attachment' : 'Has attachment'];
    if (c.field === 'is') return ['', { unread: 'Unread', read: 'Read', purged: 'Deleted on server' }[c.value] ?? c.value];
    const names: Record<string, string> = { from: 'From', to: 'To', cc: 'Cc', bcc: 'Bcc', subject: 'Subject', body: 'Body', file: 'File', attachment: 'File', filename: 'File', before: 'Before', after: 'After' };
    return [c.field ? names[c.field] ?? c.field : '', c.label ?? c.value];
  }

  // ── Filter row: another view of the chips ──
  const chipValue = (f: string) => chips.find((c) => c.field === f && !c.negate)?.value ?? '';
  const hasChip = (f: string, v: string) => chips.some((c) => c.field === f && c.value === v && !c.negate);
  /** `before:` is exclusive, the "Until" field inclusive. */
  function shift(d: string, days: number): string {
    if (d.length !== 10) return '';
    const [y, m, dd] = d.split('-').map(Number);
    return ymd(new Date(y, m - 1, dd + days));
  }
  function setDate(f: string, v: string) {
    const rest = chips.filter((c) => c.field !== f);
    setChips(v ? [...rest, { field: f, value: v, negate: false }] : rest);
  }
  function setFlag(f: string, v: string, on: boolean) {
    const rest = chips.filter((c) => !(c.field === f && c.value === v));
    setChips(on ? [...rest, { field: f, value: v, negate: false }] : rest);
  }
  const filtering = $derived(filtersOpen || !!field || chips.some((c) => DATES.includes(c.field) || (c.field in FLAGS && !c.negate)));

  function insertOp(op: string) {
    const o = OPS.find((x) => x.op === op);
    helpOpen = false;
    if (o?.chip) {
      setChips(add(chips, o.chip));
    } else {
      text = `${text.trim() ? `${text.trim()} ` : ''}${op}`;
      closed = false;
    }
    input?.focus();
    queueMicrotask(() => {
      input?.setSelectionRange(text.length, text.length);
      trackCaret();
    });
  }

  function clearAll() {
    chips = [];
    text = '';
    field = '';
    input?.focus();
    publish(true);
  }

  const HELP: [string, string][] = [
    ['from:', 'Sender name or address: from:alice'],
    ['to:', 'Recipient, also cc: to:bob@example.com'],
    ['subject:', 'Words in the subject: subject:invoice'],
    ['body:', 'Words in the text: body:"order number"'],
    ['file:', 'Attachment name: file:pdf'],
    ['after:', 'Received on or after: after:2024-03-01, after:2024-03, after:2024'],
    ['before:', 'Received before: before:2025'],
    ['has:attachment', 'Messages with attachments'],
    ['is:unread', 'Not read yet (is:read for the others)'],
    ['is:purged', 'Deleted on the mail server, only in the backup'],
  ];
</script>

<div class="relative">
  <div
    class="flex min-h-[2.4rem] w-full cursor-text flex-wrap items-center gap-1 rounded-lg bg-raised py-1 pr-16 pl-9 {focused ? 'ring-2 ring-accent/50' : ''}"
    role="presentation"
    onmousedown={(e) => { if (e.target === e.currentTarget) { e.preventDefault(); input?.focus(); } }}>
    <span class="pointer-events-none absolute top-[1.2rem] left-3 -translate-y-1/2 text-faint"><Icon name="search" size={15} /></span>
    {#each chips as c, i (i + serialize(c))}
      {@const [name, val] = chipText(c)}
      <span class="flex max-w-full items-center gap-1 rounded-md bg-accent/15 py-0.5 pr-0.5 pl-2 text-[0.8rem] text-fg">
        <button class="untrusted min-w-0 truncate bg-transparent p-0 text-left text-[0.8rem] hover:bg-transparent! {c.negate ? 'line-through decoration-bad/70' : ''}"
          title="{c.negate ? 'Leaves out: ' : ''}{serialize(c)} (click to change)" onclick={() => edit(i)}>
          {#if name}<span class="text-muted">{name}</span> {/if}{val}
        </button>
        <button class="rounded bg-transparent p-0.5 text-muted hover:text-fg" aria-label="Remove {serialize(c)}" onclick={() => setChips(chips.filter((_, k) => k !== i))}><Icon name="x" size={12} /></button>
      </span>
    {/each}
    <input
      bind:this={input}
      bind:value={text}
      class="min-w-[6rem] flex-1 border-0 bg-transparent px-1 py-1 shadow-none outline-none focus:ring-0"
      placeholder={chips.length ? '' : 'Search'}
      role="combobox"
      aria-label="Search mail"
      aria-expanded={open}
      aria-controls={listId}
      aria-autocomplete="list"
      aria-activedescendant={open && active >= 0 ? `${listId}-${active}` : undefined}
      autocomplete="off"
      spellcheck="false"
      {oninput}
      {onkeydown}
      onkeyup={trackCaret}
      onclick={trackCaret}
      onfocus={() => { focused = true; closed = false; trackCaret(); }}
      onblur={() => { focused = false; absorb(true); publish(true); }} />
    <span class="absolute top-[1.2rem] right-1.5 flex -translate-y-1/2 items-center gap-0.5">
      {#if chips.length || text}
        <button class="rounded bg-transparent p-1 text-faint hover:text-fg" onclick={clearAll} aria-label="Clear search" title="Clear search"><Icon name="x" size={14} /></button>
      {/if}
      <button class="rounded bg-transparent p-1 {filtering ? 'text-accent-2' : 'text-faint'} hover:text-fg" onclick={() => (filtersOpen = !filtersOpen)} aria-label="Search filters" aria-pressed={filtersOpen} title="Filters"><Icon name="filter" size={14} /></button>
      <button class="rounded bg-transparent p-1 {helpOpen ? 'text-fg' : 'text-faint'} hover:text-fg" onclick={() => (helpOpen = !helpOpen)} aria-label="Search help" aria-expanded={helpOpen} title="Search operators"><Icon name="help" size={14} /></button>
    </span>
  </div>

  {#if open}
    <ul id={listId} role="listbox" aria-label="Suggestions"
      class="absolute inset-x-0 top-full z-50 m-0 mt-1 list-none rounded-xl border border-line bg-panel p-1 text-[0.85rem] shadow-2xl shadow-black/30">
      {#each items as it, i (it.key)}
        <li id="{listId}-{i}" role="option" aria-selected={i === active}>
          <button class="flex w-full items-baseline gap-2 rounded-lg px-2 py-1.5 text-left {i === active ? 'bg-hover!' : 'bg-transparent'}"
            onmousedown={(e) => e.preventDefault()} onclick={() => pick(it)} onmousemove={() => (active = i)}>
            <span class="untrusted min-w-0 flex-1 truncate font-medium">{it.label}</span>
            {#if it.hint}<span class="untrusted max-w-[55%] flex-none truncate text-[0.8rem] text-faint">{it.hint}</span>{/if}
          </button>
        </li>
      {/each}
    </ul>
  {/if}

  {#if helpOpen}
    <div class="absolute inset-x-0 top-full z-50 mt-1 rounded-xl border border-line bg-panel p-2 text-[0.85rem] shadow-2xl shadow-black/30" role="dialog" aria-label="Search operators">
      <p class="m-0 px-1.5 pb-1.5 text-faint">Words match their beginnings and every word must match. Click an operator to add it.</p>
      {#each HELP as [op, hint]}
        <button class="flex w-full items-baseline gap-2 rounded-lg bg-transparent px-1.5 py-1 text-left" onmousedown={(e) => e.preventDefault()} onclick={() => insertOp(op)}>
          <code class="flex-none text-accent-2">{op}</code><span class="min-w-0 flex-1 text-muted">{hint}</span>
        </button>
      {/each}
      <p class="m-0 px-1.5 pt-1.5 text-faint"><code>"exact phrase"</code> · <code>-word</code> leaves out · <code>word OR word</code></p>
    </div>
  {/if}

  {#if filtering}
    <div class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[0.8rem] text-muted">
      <span class="flex items-center gap-1">Search in
        <Select variant="ghost" class="text-[0.8rem]" label="Search in" bind:value={field} onchange={() => onchange(true)} options={[
          { value: '', label: 'Anywhere' },
          { value: 'subject', label: 'Subject' },
          { value: 'sender', label: 'Sender' },
          { value: 'recipients', label: 'Recipients' },
          { value: 'body', label: 'Message text' },
          { value: 'attachments', label: 'Attachment names' },
        ]} />
      </span>
      <label class="m-0 flex flex-row items-center gap-1 font-normal">From
        <input type="date" class="py-0.5 text-[0.8rem]" value={chipValue('after').length === 10 ? chipValue('after') : ''} onchange={(e) => setDate('after', e.currentTarget.value)} />
      </label>
      <label class="m-0 flex flex-row items-center gap-1 font-normal">Until
        <input type="date" class="py-0.5 text-[0.8rem]" value={shift(chipValue('before'), -1)} onchange={(e) => setDate('before', shift(e.currentTarget.value, 1))} />
      </label>
      <label class="m-0 flex flex-row items-center gap-1 font-normal"><input type="checkbox" checked={hasChip('has', 'attachment')} onchange={(e) => setFlag('has', 'attachment', e.currentTarget.checked)} /> Has attachment</label>
      <label class="m-0 flex flex-row items-center gap-1 font-normal"><input type="checkbox" checked={hasChip('is', 'purged')} onchange={(e) => setFlag('is', 'purged', e.currentTarget.checked)} /> Deleted on server</label>
    </div>
  {/if}
</div>
