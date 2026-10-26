<script lang="ts" module>
  export interface Segment<T> {
    value: T;
    label: string;
    icon?: string;
    /** Shown after the label (a count). */
    count?: number | string;
    title?: string;
    /** Classes for the highlight behind the chosen segment and for its text (e.g. a category's colours). */
    bg?: string;
    tone?: string;
  }
</script>

<script lang="ts" generics="V extends string | number | boolean">
  import { untrack } from 'svelte';
  import Icon from './Icon.svelte';

  // Mutually exclusive choices in one track; the highlight slides to the chosen one. `compact`
  // shows only icons for the others and gives the chosen one room for its label. Arrow keys move
  // the choice, like radio buttons.
  let {
    value = $bindable(),
    options,
    onchange,
    label,
    compact = false,
    class: cls = '',
  }: {
    value: V;
    options: Segment<V>[];
    onchange?: (v: V) => void;
    label: string;
    compact?: boolean;
    class?: string;
  } = $props();

  let buttons: HTMLButtonElement[] = $state([]);
  let pill = $state({ x: 0, w: 0 });
  /** No sliding until the highlight has been placed once (it would slide in from the left edge). */
  let placed = $state(false);

  const index = $derived(options.findIndex((o) => o.value === value));
  const chosen = $derived(options[index]);

  function place() {
    const b = buttons[index];
    if (!b) return;
    pill = { x: b.offsetLeft, w: b.offsetWidth };
    if (!placed) requestAnimationFrame(() => (placed = true));
  }

  // Follows the chosen segment, also while widths animate (compact mode) or the pane resizes.
  $effect(() => {
    void index;
    void options.length;
    untrack(place);
    const ro = new ResizeObserver(place);
    for (const b of buttons) if (b) ro.observe(b);
    return () => ro.disconnect();
  });

  function pick(i: number) {
    const o = options[i];
    if (!o || o.value === value) return;
    value = o.value;
    onchange?.(o.value);
  }

  function onkeydown(e: KeyboardEvent) {
    const step = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const i = (index + step + options.length) % options.length;
    pick(i);
    buttons[i]?.focus();
  }
</script>

<div class="relative flex gap-0.5 rounded-[10px] bg-raised p-0.5 {cls}" role="radiogroup" aria-label={label} tabindex="-1" {onkeydown}>
  <span aria-hidden="true"
    class="pointer-events-none absolute top-0.5 bottom-0.5 left-0 rounded-lg shadow-sm shadow-black/20 {chosen?.bg ?? 'bg-accent'} {placed ? 'transition-[translate,width,background-color] duration-[380ms] ease-[var(--ease-out)]' : ''} {index < 0 ? 'opacity-0' : ''}"
    style="translate: {pill.x}px 0; width: {pill.w}px"></span>
  {#each options as o, i (o.value)}
    {@const on = i === index}
    <button bind:this={buttons[i]} type="button" role="radio" aria-checked={on} tabindex={on || (index < 0 && i === 0) ? 0 : -1}
      aria-label={compact ? o.label : undefined} title={o.title ?? (compact ? o.label : undefined)}
      class="relative min-w-0 justify-center gap-1.5 rounded-lg bg-transparent! px-2 py-1 text-[0.9rem] active:scale-[0.97]
        transition-[color,flex-grow,transform] duration-[380ms] ease-[var(--ease-out)]
        {compact ? `basis-0 ${on ? 'grow-[2.6]' : 'grow'}` : 'flex-1'}
        {on ? (o.tone ?? 'text-white') : 'text-muted hover:text-fg'}"
      onclick={() => pick(i)}>
      {#if o.icon}<Icon name={o.icon} size={14} />{/if}
      {#if !compact || on}
        <span class="truncate {compact ? 'animate-[label-in_260ms_var(--ease-out)]' : ''}">{o.label}</span>
      {/if}
      {#if o.count !== undefined && (!compact || on)}<span class="tabular-nums opacity-75">{o.count}</span>{/if}
    </button>
  {/each}
</div>

