<script lang="ts">
  import { onMount } from 'svelte';
  import { fade, fly } from 'svelte/transition';
  import { ms, ease } from './motion';
  import { session, route, toStart } from './state.svelte';
  import Notices from './components/Notices.svelte';
  import ContextMenu from './components/ContextMenu.svelte';
  import ConfirmDialog from './components/ConfirmDialog.svelte';
  import Commands from './components/Commands.svelte';
  import Nav from './components/Nav.svelte';
  import TabBar from './components/TabBar.svelte';
  import Resizer from './components/Resizer.svelte';
  import { panes, savePanes, navWidth, screen, NAV_DEFAULT, NAV_RAIL, NAV_MAX } from './layout.svelte';
  import Unlock from './routes/Unlock.svelte';
  import Connect from './routes/Connect.svelte';
  import Login from './routes/Login.svelte';
  import Dashboard from './routes/Dashboard.svelte';
  import Accounts from './routes/Accounts.svelte';
  import Destinations from './routes/Destinations.svelte';
  import Storage from './routes/Storage.svelte';
  import Activity from './routes/Activity.svelte';
  import Integrity from './routes/Integrity.svelte';
  import Purge from './routes/Purge.svelte';
  import Browse from './routes/Browse.svelte';
  import Settings from './routes/Settings.svelte';
  import Admin from './routes/Admin.svelte';

  // Nothing connects on its own: the app keeps no server, only the profile files opened recently
  // (KeePassXC-style). The first screen asks for one of them, or for a server.
  onMount(toStart);

  // The page, without its sub-path or query (`/browse?account=…` is still Mail).
  const top = $derived('/' + (route.path.split(/[/?]/)[1] ?? ''));
  // On a phone, reading a message takes the whole screen; the tab bar comes back with the list.
  const reading = $derived(/^\/browse\/\d/.test(route.path));
  // The drawer closes once something in it was chosen.
  $effect(() => {
    void route.path;
    screen.drawer = false;
  });
</script>

<Notices />
<ContextMenu />
<ConfirmDialog />

{#if session.phase === 'boot'}
  <div class="grid h-dvh place-items-center text-muted">Starting…</div>
{:else if session.phase === 'unlock'}
  <Unlock />
{:else if session.phase === 'connect'}
  <Connect />
{:else if session.phase === 'login'}
  <Login />
{:else}
  <Commands />
  {#if screen.phone}
    <div class="flex h-dvh flex-col bg-frame">
      <main class={top === '/browse'
        ? 'min-h-0 flex-1 overflow-hidden pt-[env(safe-area-inset-top)]'
        : 'min-h-0 flex-1 overflow-auto bg-panel px-4 pt-[calc(env(safe-area-inset-top)+1.25rem)]'}>
        {@render page()}
        {#if top !== '/browse'}<div class="h-10" aria-hidden="true"></div>{/if}
      </main>
      {#if !reading && !screen.writing}<TabBar />{/if}
    </div>
    {#if screen.drawer}
      <div class="fixed inset-0 z-40 bg-black/40" role="presentation" onclick={() => (screen.drawer = false)} transition:fade={{ duration: ms(160) }}></div>
      <div class="fixed inset-y-0 left-0 z-40 w-[min(20rem,86vw)] bg-frame pt-[env(safe-area-inset-top)] pb-[env(safe-area-inset-bottom)] shadow-2xl shadow-black/30"
        role="dialog" aria-modal="true" aria-label="Menu" transition:fly={{ x: -320, duration: ms(240), easing: ease }}>
        <Nav drawer />
      </div>
    {/if}
  {:else}
  <div class="grid h-dvh bg-frame" style="grid-template-columns: {panes.nav}px minmax(0, 1fr)">
    <div class="relative min-w-0">
      <Nav />
      <Resizer label="Resize sidebar" width={panes.nav} min={NAV_RAIL} max={NAV_MAX} set={(w) => (panes.nav = navWidth(w))}
        reset={() => (panes.nav = NAV_DEFAULT)} done={savePanes} />
    </div>
    <main class={top === '/browse'
      ? 'min-w-0 overflow-hidden py-2 pr-2'
      : 'm-2 ml-0 min-w-0 overflow-auto rounded-xl border border-line bg-panel px-9 pt-7'}>
      {@render page()}
      <!-- A spacer, not padding: scroll containers don't always keep bottom padding. -->
      {#if top !== '/browse'}<div class="h-14" aria-hidden="true"></div>{/if}
    </main>
  </div>
  {/if}
{/if}

<svelte:window onkeydown={(e) => e.key === 'Escape' && screen.drawer && (screen.drawer = false)} />

{#snippet page()}
  {#key top}
  <div class="h-full" in:fade={{ duration: ms(160) }}>
  {#if top === '/accounts'}
    <Accounts />
  {:else if top === '/destinations'}
    <Destinations />
  {:else if top === '/storage'}
    <Storage />
  {:else if top === '/activity'}
    <Activity />
  {:else if top === '/integrity'}
    <Integrity />
  {:else if top === '/purge'}
    <Purge />
  {:else if top === '/browse'}
    <Browse />
  {:else if top === '/settings'}
    <Settings />
  {:else if top === '/admin' && session.me?.role === 'admin'}
    <Admin />
  {:else}
    <Dashboard />
  {/if}
  </div>
  {/key}
{/snippet}

