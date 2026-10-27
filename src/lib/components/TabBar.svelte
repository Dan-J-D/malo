<script lang="ts">
  import { live, route } from '../state.svelte';
  import { screen } from '../layout.svelte';
  import Icon from './Icon.svelte';

  // On a phone, in place of the sidebar: the three places used most, and the whole sidebar
  // behind "More".
  const tabs = [
    ['/browse', 'Mail', 'inbox'],
    ['/dashboard', 'Overview', 'gauge'],
    ['/activity', 'Activity', 'activity'],
  ];
  const unseen = $derived(live.newlyFound.filter((m) => !m.reviewed).length);
  const running = $derived(live.jobs.filter((j) => j.state === 'running' || j.state === 'queued').length);
  const elsewhere = $derived(!tabs.some(([href]) => route.path.startsWith(href)));
</script>

<nav class="grid flex-none grid-cols-4 border-t border-line bg-panel pb-[env(safe-area-inset-bottom)] dark:bg-frame" aria-label="Sections">
  {#each tabs as [href, label, icon]}
    {@const active = route.path.startsWith(href)}
    <a href={'#' + href} aria-current={active ? 'page' : undefined}
      class="relative flex flex-col items-center gap-0.5 pt-2 pb-1.5 text-[0.7rem] no-underline! {active ? 'font-medium text-fg' : 'text-muted'}">
      <span class="relative grid h-7 w-12 place-items-center rounded-full transition-colors {active ? 'bg-accent/14 text-accent-2' : ''}">
        <Icon name={icon} size={19} />
        {#if href === '/browse' && unseen > 0}
          <span class="absolute -top-0.5 right-0.5 min-w-4 rounded-full bg-accent px-1 text-center text-[0.65rem] leading-4 font-semibold text-white tabular-nums">{unseen > 99 ? '99+' : unseen}</span>
        {:else if href === '/activity' && running > 0}
          <span class="absolute top-0 right-2 size-2 animate-pulse rounded-full bg-accent-2" title="{running} job(s) running or queued"></span>
        {/if}
      </span>
      {label}
    </a>
  {/each}
  <button class="flex flex-col items-center gap-0.5 rounded-none bg-transparent! pt-2 pb-1.5 text-[0.7rem] {elsewhere ? 'font-medium text-fg' : 'text-muted'}"
    onclick={() => (screen.drawer = true)} aria-haspopup="dialog" aria-expanded={screen.drawer}>
    <span class="grid h-7 w-12 place-items-center rounded-full {elsewhere ? 'bg-accent/14 text-accent-2' : ''}"><Icon name="more" size={19} /></span>
    More
  </button>
</nav>
