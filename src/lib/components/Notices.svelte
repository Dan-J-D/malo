<script lang="ts">
  import { live } from '../state.svelte';
  import { fly, fade } from 'svelte/transition';
  import { flip } from 'svelte/animate';
  import { ms, ease } from '../motion';
  import Icon from './Icon.svelte';

  const look: Record<string, [string, string]> = {
    success: ['check', 'text-ok'],
    warning: ['alert', 'text-warn'],
    error: ['alert', 'text-bad'],
    info: ['activity', 'text-info'],
  };
</script>

<div class="pointer-events-none fixed right-4 bottom-4 z-[100] flex max-w-[420px] flex-col gap-2" aria-live="polite">
  {#each live.notices as n (n.id)}
    {@const [icon, tone] = look[n.level] ?? look.info}
    <div in:fly={{ x: 28, duration: ms(260), easing: ease }} out:fade={{ duration: ms(160) }} animate:flip={{ duration: ms(220) }}
      class="flex items-start gap-2.5 rounded-xl border border-line bg-raised px-3.5 py-2.5 shadow-lg shadow-black/20">
      <span class="mt-0.5 {tone}"><Icon name={icon} size={15} /></span><span>{n.message}</span>
    </div>
  {/each}
</div>
