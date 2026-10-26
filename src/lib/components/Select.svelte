<script lang="ts" module>
  export interface Option<T> {
    value: T;
    label: string;
    /** Extra text on the right of the list (counts). */
    hint?: string;
    disabled?: boolean;
    /** Nesting level, for mailbox trees. */
    depth?: number;
  }
</script>

<script lang="ts" generics="V extends string | number">
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';

  // A dropdown in the app's theme. Native <select> popups are drawn by the OS toolkit (GTK in the
  // Linux app) and ignore the theme; this one isn't. Keyboard: arrows, Home/End, Enter/Space,
  // Escape, and typing the start of an option.

  let {
    value = $bindable(),
    options,
    onchange,
    disabled = false,
    label: ariaLabel,
    title,
    variant = 'field',
    class: cls = '',
  }: {
    value: V;
    options: Option<V>[];
    onchange?: (v: V) => void;
    disabled?: boolean;
    /** Accessible name when no <label> wraps it. */
    label?: string;
    title?: string;
    /** `field` looks like an input; `ghost` is plain text with a chevron (toolbars). */
    variant?: 'field' | 'ghost';
    class?: string;
  } = $props();

  let open = $state(false);
  let active = $state(-1);
  let trigger: HTMLButtonElement | undefined = $state();
  let list: HTMLUListElement | undefined = $state();
  let pos = $state({ left: 0, top: 0, width: 0, maxHeight: 320, up: false });
  const id = `select-${Math.random().toString(36).slice(2)}`;

  const current = $derived(options.find((o) => o.value === value));

  function place() {
    if (!trigger) return;
    const r = trigger.getBoundingClientRect();
    const below = window.innerHeight - r.bottom - 8;
    const above = r.top - 8;
    const up = below < 200 && above > below;
    pos = {
      left: Math.min(r.left, window.innerWidth - Math.max(r.width, 180) - 8),
      top: up ? r.top - 4 : r.bottom + 4,
      width: r.width,
      maxHeight: Math.min(360, up ? above : below),
      up,
    };
  }

  async function show() {
    if (disabled) return;
    place();
    open = true;
    active = Math.max(0, options.findIndex((o) => o.value === value));
    await tick();
    scrollToActive();
  }

  function close(refocus = true) {
    open = false;
    if (refocus) trigger?.focus();
  }

  function choose(i: number) {
    const o = options[i];
    if (!o || o.disabled) return;
    close();
    if (o.value !== value) {
      value = o.value;
      onchange?.(o.value);
    }
  }

  function scrollToActive() {
    list?.querySelector(`#${id}-${active}`)?.scrollIntoView({ block: 'nearest' });
  }

  function move(from: number, step: number) {
    const n = options.length;
    for (let k = 1; k <= n; k++) {
      const i = (((from + step * k) % n) + n) % n;
      if (!options[i].disabled) return i;
    }
    return from;
  }

  let typed = '';
  let typedTimer: ReturnType<typeof setTimeout>;

  function onkeydown(e: KeyboardEvent) {
    if (disabled || e.isComposing) return;
    const handled = () => {
      e.preventDefault();
      e.stopPropagation();
    };
    if (!open) {
      if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) {
        handled();
        void show();
      }
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      handled();
      active = move(active, e.key === 'ArrowDown' ? 1 : -1);
    } else if (e.key === 'Home' || e.key === 'End') {
      handled();
      active = e.key === 'Home' ? move(-1, 1) : move(options.length, -1);
    } else if (e.key === 'Enter' || e.key === ' ') {
      handled();
      choose(active);
      return;
    } else if (e.key === 'Escape') {
      handled();
      close();
      return;
    } else if (e.key === 'Tab') {
      close(false);
      return;
    } else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
      handled();
      clearTimeout(typedTimer);
      typed += e.key.toLowerCase();
      typedTimer = setTimeout(() => (typed = ''), 700);
      const i = options.findIndex((o) => !o.disabled && o.label.trim().toLowerCase().startsWith(typed));
      if (i >= 0) active = i;
    } else {
      return;
    }
    void tick().then(scrollToActive);
  }

  // Clicks elsewhere, scrolling the page behind it and resizing close the list.
  $effect(() => {
    if (!open) return;
    const away = (e: Event) => {
      const t = e.target as Node;
      if (!list?.contains(t) && !trigger?.contains(t)) close(false);
    };
    const scrolled = (e: Event) => {
      if (!list?.contains(e.target as Node)) close(false);
    };
    const resized = () => close(false);
    document.addEventListener('pointerdown', away, true);
    document.addEventListener('scroll', scrolled, true);
    window.addEventListener('resize', resized);
    return () => {
      document.removeEventListener('pointerdown', away, true);
      document.removeEventListener('scroll', scrolled, true);
      window.removeEventListener('resize', resized);
    };
  });

  /** Renders the list on <body>, above dialogs and outside panes that clip their content. */
  function portal(node: HTMLElement) {
    document.body.appendChild(node);
    return () => node.remove();
  }
</script>

<button
  bind:this={trigger}
  type="button"
  class="select-trigger {variant} {cls}"
  {disabled}
  {title}
  role="combobox"
  aria-label={ariaLabel}
  aria-haspopup="listbox"
  aria-expanded={open}
  aria-controls={id}
  aria-activedescendant={open && active >= 0 ? `${id}-${active}` : undefined}
  onclick={() => (open ? close() : show())}
  {onkeydown}>
  <span class="untrusted min-w-0 flex-1 truncate text-left">{current?.label ?? ''}</span>
  <span class="flex-none text-faint transition-transform duration-300 ease-[var(--ease-spring)] {open ? 'rotate-180' : ''}"><Icon name="chevron" size={14} /></span>
</button>

{#if open}
  <ul
    bind:this={list}
    {@attach portal}
    {id}
    role="listbox"
    aria-label={ariaLabel ?? current?.label}
    class="select-list {pos.up ? 'pop-up' : 'pop-down'} fixed z-[210] m-0 list-none overflow-y-auto rounded-xl border border-line bg-panel p-1 text-[0.9rem] shadow-2xl shadow-black/30"
    style="left: {pos.left}px; {pos.up ? `bottom: ${window.innerHeight - pos.top}px` : `top: ${pos.top}px`}; min-width: {Math.max(pos.width, 160)}px; max-width: min(28rem, calc(100vw - 16px)); max-height: {pos.maxHeight}px">
    {#each options as o, i (i)}
      <!-- Keys go to the combobox button, which keeps focus (aria-activedescendant). -->
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <li id="{id}-{i}" role="option" aria-selected={o.value === value} aria-disabled={o.disabled}
        class="flex cursor-pointer items-center gap-2 rounded-lg py-1.5 pr-2.5 {i === active ? 'bg-hover' : ''} {o.disabled ? 'cursor-not-allowed opacity-45' : ''}"
        style="padding-left: {0.5 + (o.depth ?? 0) * 0.9}rem"
        onpointermove={() => { if (!o.disabled) active = i; }}
        onclick={() => choose(i)}>
        <span class="w-4 flex-none text-accent-2">{#if o.value === value}<Icon name="check" size={14} />{/if}</span>
        <span class="untrusted min-w-0 flex-1 truncate">{o.label}</span>
        {#if o.hint}<span class="flex-none pl-3 text-[0.8rem] text-faint tabular-nums">{o.hint}</span>{/if}
      </li>
    {/each}
  </ul>
{/if}
