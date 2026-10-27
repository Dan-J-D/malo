<script lang="ts">
  import { fade, scale } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import { dialog } from '../confirm.svelte';
  import Icon from './Icon.svelte';

  // Hosts the question `ask()` puts up. Escape or a click outside answers no; the cancel button
  // has focus, so a stray Enter doesn't confirm something risky.
  const d = $derived(dialog.current);
  let cancel: HTMLButtonElement | undefined = $state();
  let returnFocus: HTMLElement | null = null;

  $effect(() => {
    if (!d) return;
    returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancel?.focus();
    return () => returnFocus?.focus();
  });

  function key(e: KeyboardEvent) {
    if (!d || e.key !== 'Escape') return;
    e.preventDefault();
    e.stopPropagation();
    d.resolve(false);
  }
</script>

<svelte:window onkeydowncapture={key} />

{#if d}
  <div transition:fade={{ duration: ms(120) }} class="fixed inset-0 z-[60] grid place-items-center bg-black/55" role="presentation" onclick={(e) => e.target === e.currentTarget && d.resolve(false)}>
    <div transition:scale={{ start: 0.96, duration: ms(180), easing: ease }} class="max-h-[90vh] w-[min(520px,94vw)] overflow-auto rounded-xl border border-line bg-panel px-6 pt-5 pb-5 shadow-2xl"
      role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-body">
      <h2 id="confirm-title" class="mt-0 mb-3 flex items-start gap-2">
        {#if d.danger}<span class="mt-0.5 text-bad"><Icon name="alert" size={18} /></span>{/if}
        <span class="untrusted min-w-0 break-words">{d.title}</span>
      </h2>
      <div id="confirm-body">
        {#if d.body}<p class="untrusted my-2 break-words {d.mono ? 'mono rounded-lg bg-raised px-3 py-2 text-[0.85rem]' : ''}">{d.body}</p>{/if}
        {#if d.list?.length}
          <ul class="my-2 pl-5">{#each d.list as item}<li>{item}</li>{/each}</ul>
        {/if}
        {#if d.detail}<p class="my-2 text-[0.9rem] text-muted">{d.detail}</p>{/if}
        {#if d.warning}
          <div class="my-3 flex items-start gap-2 rounded-lg border border-bad/40 bg-bad/8 px-3 py-2 text-[0.9rem]">
            <span class="mt-0.5 text-bad"><Icon name="alert" size={15} /></span><span>{d.warning}</span>
          </div>
        {/if}
      </div>
      <div class="row mt-5 justify-end">
        <button bind:this={cancel} type="button" onclick={() => d.resolve(false)}>{d.cancel ?? 'Cancel'}</button>
        <button type="button" class={d.danger ? 'danger' : 'primary'} onclick={() => d.resolve(true)}>{d.confirm ?? 'Continue'}</button>
      </div>
    </div>
  </div>
{/if}
