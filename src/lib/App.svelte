<script lang="ts">
  import { onMount } from 'svelte';
  import { fade } from 'svelte/transition';
  import { ms } from './motion';
  import { app, certChange } from './api/client';
  import { session, route } from './state.svelte';
  import Notices from './components/Notices.svelte';
  import ContextMenu from './components/ContextMenu.svelte';
  import Commands from './components/Commands.svelte';
  import Nav from './components/Nav.svelte';
  import Resizer from './components/Resizer.svelte';
  import { panes, savePanes, navWidth, NAV_DEFAULT, NAV_RAIL, NAV_MAX } from './layout.svelte';
  import Connect from './routes/Connect.svelte';
  import Login from './routes/Login.svelte';
  import Dashboard from './routes/Dashboard.svelte';
  import Accounts from './routes/Accounts.svelte';
  import Destinations from './routes/Destinations.svelte';
  import Activity from './routes/Activity.svelte';
  import Integrity from './routes/Integrity.svelte';
  import Purge from './routes/Purge.svelte';
  import Browse from './routes/Browse.svelte';
  import Settings from './routes/Settings.svelte';
  import Admin from './routes/Admin.svelte';

  // Reconnect to the last server automatically; a pinned remote is re-verified by fingerprint.
  onMount(async () => {
    try {
      const prefs = await app.prefs();
      if (prefs.mode === 'local') {
        const info = await app.startLocal();
        session.local = true;
        session.url = info.url;
        session.status = info.status;
        session.setupToken = info.setup_token;
        session.phase = 'login';
        return;
      }
      if (prefs.mode === 'remote' && prefs.url) {
        session.status = await app.connectRemote(prefs.url, prefs.fingerprint);
        session.url = prefs.url;
        session.phase = 'login';
        return;
      }
    } catch (e) {
      // Fall through to the connect screen, which warns about a changed certificate.
      session.certChanged = certChange(e);
    }
    session.phase = 'connect';
  });

  // The page, without its sub-path or query (`/browse?account=…` is still Mail).
  const top = $derived('/' + (route.path.split(/[/?]/)[1] ?? ''));
</script>

<Notices />
<ContextMenu />

{#if session.phase === 'boot'}
  <div class="grid h-screen place-items-center text-muted">Starting…</div>
{:else if session.phase === 'connect'}
  <Connect />
{:else if session.phase === 'login'}
  <Login />
{:else}
  <Commands />
  <div class="grid h-screen bg-frame" style="grid-template-columns: {panes.nav}px minmax(0, 1fr)">
    <div class="relative min-w-0">
      <Nav />
      <Resizer label="Resize sidebar" width={panes.nav} min={NAV_RAIL} max={NAV_MAX} set={(w) => (panes.nav = navWidth(w))}
        reset={() => (panes.nav = NAV_DEFAULT)} done={savePanes} />
    </div>
    <main class={top === '/browse'
      ? 'min-w-0 overflow-hidden py-2 pr-2'
      : 'm-2 ml-0 min-w-0 overflow-auto rounded-xl border border-line bg-panel px-9 py-7'}>
      {#key top}
      <div class="h-full" in:fade={{ duration: ms(160) }}>
      {#if top === '/accounts'}
        <Accounts />
      {:else if top === '/destinations'}
        <Destinations />
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
    </main>
  </div>
{/if}

