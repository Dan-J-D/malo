<script lang="ts">
  import { api, qs } from '../api/client';
  import type * as T from '../api/types';
  import { personName, addressOf } from '../format';
  import Icon from './Icon.svelte';

  // Addresses as chips. Typing suggests people you've exchanged mail with; comma, Enter or Tab
  // (or leaving the field) turn what was typed into a chip.
  let {
    value = $bindable([]),
    label,
    account = null,
    autofocus = false,
  }: { value?: string[]; label: string; account?: string | null; autofocus?: boolean } = $props();

  let text = $state('');
  let input: HTMLInputElement | undefined = $state();
  let focused = $state(false);
  let items: T.SearchSuggestion[] = $state([]);
  let active = $state(0);
  const listId = `rcpt-${Math.random().toString(36).slice(2)}`;
  const looksValid = (s: string) => /^[^\s@<>",;]+@[^\s@<>",;]+\.[^\s@<>",;]+$/.test(addressOf(s));

  $effect(() => {
    if (autofocus) input?.focus();
  });

  function commit(raw = text) {
    const parts = raw.split(/[,;]+/).map((s) => s.trim()).filter(Boolean);
    const known = new Set(value.map(addressOf));
    const add = parts.filter((p) => !known.has(addressOf(p)));
    if (add.length) value = [...value, ...add];
    text = '';
    items = [];
  }

  let timer: ReturnType<typeof setTimeout>;
  function oninput() {
    if (/[,;]/.test(text)) return commit();
    clearTimeout(timer);
    const prefix = text.trim();
    if (prefix.length < 2) {
      items = [];
      return;
    }
    timer = setTimeout(async () => {
      try {
        const [from, to] = await Promise.all([
          api.get<T.SearchSuggestion[]>(`/search/suggest${qs({ field: 'from', prefix, account })}`),
          api.get<T.SearchSuggestion[]>(`/search/suggest${qs({ field: 'to', prefix, account })}`),
        ]);
        if (text.trim() !== prefix) return;
        const seen = new Set(value.map(addressOf));
        const merged = new Map<string, T.SearchSuggestion>();
        for (const s of [...from, ...to]) {
          const k = s.value.toLowerCase();
          if (seen.has(k)) continue;
          const had = merged.get(k);
          merged.set(k, had ? { ...had, name: had.name ?? s.name, count: had.count + s.count } : s);
        }
        items = [...merged.values()].sort((a, b) => b.count - a.count).slice(0, 6);
        active = 0;
      } catch {
        items = [];
      }
    }, 120);
  }

  function pick(s: T.SearchSuggestion) {
    commit(s.name ? `${s.name.replace(/[<>",;]/g, '')} <${s.value}>` : s.value);
    input?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.isComposing) return;
    const open = focused && items.length > 0;
    if (open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      active = (active + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length;
    } else if (open && (e.key === 'Enter' || e.key === 'Tab')) {
      e.preventDefault();
      pick(items[active]);
    } else if ((e.key === 'Enter' || e.key === 'Tab') && text.trim()) {
      e.preventDefault();
      commit();
    } else if (e.key === 'Escape' && open) {
      e.preventDefault();
      e.stopPropagation();
      items = [];
    } else if (e.key === 'Backspace' && !text && value.length) {
      e.preventDefault();
      value = value.slice(0, -1);
    }
  }
</script>

<div class="relative flex min-w-0 flex-1 items-start gap-2">
  <span class="w-14 flex-none pt-1 text-[0.85rem] text-muted">{label}</span>
  <div class="flex min-w-0 flex-1 flex-wrap items-center gap-1" role="presentation"
    onmousedown={(e) => { if (e.target === e.currentTarget) { e.preventDefault(); input?.focus(); } }}>
    {#each value as r, i (r)}
      {@const ok = looksValid(r)}
      <span class="flex max-w-full items-center gap-1 rounded-md py-0.5 pr-0.5 pl-2 text-[0.85rem] {ok ? 'bg-raised' : 'bg-bad/15 text-bad'}"
        title={ok ? addressOf(r) : `“${r}” doesn't look like an email address`}>
        <span class="untrusted truncate">{personName(r)}</span>
        <button type="button" class="rounded bg-transparent p-0.5 text-muted hover:text-fg" aria-label="Remove {r}" onclick={() => (value = value.filter((_, k) => k !== i))}><Icon name="x" size={11} /></button>
      </span>
    {/each}
    <input bind:this={input} bind:value={text} {oninput} {onkeydown}
      onfocus={() => (focused = true)} onblur={() => { focused = false; if (text.trim()) commit(); }}
      class="min-w-[8rem] flex-1 border-0 bg-transparent px-0 py-1 shadow-none outline-none focus-visible:outline-none" aria-label={label}
      role="combobox" aria-expanded={focused && items.length > 0} aria-controls={listId} autocomplete="off" spellcheck="false" />
  </div>
  {#if focused && items.length}
    <ul id={listId} role="listbox" class="absolute top-full left-12 z-50 m-0 mt-1 w-[min(24rem,90%)] list-none rounded-xl border border-line bg-panel p-1 text-[0.85rem] shadow-2xl shadow-black/30">
      {#each items as s, i (s.value)}
        <li role="option" aria-selected={i === active}>
          <button type="button" class="flex w-full items-baseline gap-2 rounded-lg px-2 py-1.5 text-left {i === active ? 'bg-hover!' : 'bg-transparent'}"
            onmousedown={(e) => e.preventDefault()} onclick={() => pick(s)} onmousemove={() => (active = i)}>
            <span class="untrusted min-w-0 flex-1 truncate">{s.name ?? s.value}</span>
            {#if s.name}<span class="untrusted max-w-[55%] truncate text-faint">{s.value}</span>{/if}
          </button>
        </li>
      {/each}
    </ul>
  {/if}
</div>
