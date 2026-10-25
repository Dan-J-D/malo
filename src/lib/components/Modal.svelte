<script lang="ts">
  import type { Snippet } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import Icon from './Icon.svelte';
  let { title, onclose, children, wide = false }: { title: string; onclose: () => void; children: Snippet; wide?: boolean } = $props();
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

<div transition:fade={{ duration: ms(150) }} class="fixed inset-0 z-50 grid place-items-center bg-black/55" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div transition:scale={{ start: 0.96, duration: ms(200), easing: ease }} class="max-h-[90vh] overflow-auto rounded-xl border border-line bg-panel px-6 pt-4 pb-6 shadow-2xl {wide ? 'w-[min(1000px,96vw)]' : 'w-[min(640px,94vw)]'}"
    role="dialog" aria-modal="true" aria-label={title}>
    <header class="mb-2 flex items-center gap-2">
      <h2 class="my-2 flex-1">{title}</h2>
      <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={onclose} aria-label="Close"><Icon name="x" /></button>
    </header>
    {@render children()}
  </div>
</div>
