<script lang="ts">
  import { tick } from 'svelte';
  import { fly } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import { menu, closeMenu, type MenuItem } from '../menu.svelte';
  import { caps } from '../commands.svelte';
  import Icon from './Icon.svelte';

  let el: HTMLElement | undefined = $state();
  let pos = $state({ left: 0, top: 0 });

  // Kept inside the window: flipped left or up when it would run off an edge.
  $effect(() => {
    if (!menu.open) return;
    void menu.items;
    pos = { left: menu.x, top: menu.y };
    tick().then(() => {
      if (!el) return;
      const r = el.getBoundingClientRect();
      pos = {
        left: menu.x + r.width > innerWidth - 8 ? Math.max(8, menu.x - r.width) : menu.x,
        top: menu.y + r.height > innerHeight - 8 ? Math.max(8, innerHeight - 8 - r.height) : menu.y,
      };
      (menu.keyboard ? buttons()[0] : el)?.focus({ preventScroll: true });
    });
  });

  const buttons = () => [...(el?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? [])];

  function run(item: MenuItem) {
    closeMenu(true);
    item.run();
  }

  function key(e: KeyboardEvent) {
    if (!menu.open) return;
    const list = buttons();
    const i = list.indexOf(document.activeElement as HTMLButtonElement);
    const focus = (n: number) => list[(n + list.length) % list.length]?.focus();
    if (e.key === 'Escape') closeMenu(true);
    else if (e.key === 'ArrowDown') focus(i + 1);
    else if (e.key === 'ArrowUp') focus(i < 0 ? -1 : i - 1);
    else if (e.key === 'Home') focus(0);
    else if (e.key === 'End') focus(-1);
    else if (e.key === 'Tab') closeMenu(true);
    else if (e.key.length === 1 && /\S/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
      // Typing a letter moves to the next item starting with it.
      const ch = e.key.toLowerCase();
      const from = list.slice(i + 1).concat(list.slice(0, i + 1));
      from.find((b) => b.dataset.label?.toLowerCase().startsWith(ch))?.focus();
    } else return;
    e.preventDefault();
    e.stopPropagation();
  }

  function outside(e: Event) {
    if (menu.open && !el?.contains(e.target as Node)) closeMenu();
  }
</script>

<svelte:window onkeydowncapture={key} onpointerdowncapture={outside} onwheelcapture={outside} onresize={() => closeMenu()} onblur={() => closeMenu()} />

{#if menu.open}
  <div bind:this={el} role="menu" tabindex="-1" aria-label="Actions" transition:fly={{ y: -4, duration: ms(120), easing: ease }}
    class="fixed z-[200] flex outline-none min-w-[13rem] max-w-[22rem] flex-col rounded-xl border border-line bg-panel p-1 text-[0.9rem] shadow-2xl shadow-black/30"
    style="left: {pos.left}px; top: {pos.top}px" oncontextmenu={(e) => e.preventDefault()}>
    {#each menu.items as item}
      {#if item === '-'}
        <div class="mx-1.5 my-1 h-px bg-line" role="separator"></div>
      {:else}
        <button role="menuitem" data-label={item.label} disabled={item.disabled} onclick={() => run(item)}
          onpointerenter={(e) => e.currentTarget.focus({ preventScroll: true })} onpointerleave={() => el?.focus({ preventScroll: true })}
          class="flex w-full items-center gap-2.5 rounded-lg bg-transparent px-2 py-1.5 text-left hover:bg-transparent! focus:bg-hover! focus-visible:outline-none active:scale-100! {item.danger ? 'text-bad' : ''}">
          <span class="w-4 flex-none {item.danger ? '' : 'text-muted'}">{#if item.icon}<Icon name={item.icon} size={15} />{/if}</span>
          <span class="min-w-0 flex-1 truncate">{item.label}</span>
          {#if item.keys}<span class="flex-none pl-4 text-[0.8rem] text-faint">{caps(item.keys).join(' ')}</span>{/if}
        </button>
      {/if}
    {/each}
  </div>
{/if}
