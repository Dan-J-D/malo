<script lang="ts">
  import { app, type Probe } from '../api/client';
  import { session, errorText } from '../state.svelte';
  import LocalData from '../components/LocalData.svelte';
  import Icon from '../components/Icon.svelte';

  let url = $state('https://');
  let probe: Probe | null = $state(null);
  let busy = $state(false);
  let error = $state('');

  async function local() {
    busy = true;
    error = '';
    try {
      const info = await app.startLocal();
      session.local = true;
      session.url = info.url;
      session.status = info.status;
      session.setupToken = info.setup_token;
      session.phase = 'login';
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function check() {
    busy = true;
    error = '';
    probe = null;
    try {
      probe = await app.probe(url);
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function trust() {
    if (!probe) return;
    busy = true;
    try {
      session.status = await app.connectRemote(probe.url, probe.publicly_trusted ? null : probe.fingerprint);
      session.local = false;
      session.url = probe.url;
      session.phase = 'login';
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  const mismatch = $derived.by(() => {
    const p = probe as Probe | null;
    return !!p && !p.publicly_trusted && !!p.status.cert_fingerprint && p.status.cert_fingerprint !== p.fingerprint;
  });
</script>

<div class="mx-auto my-16 max-w-[980px] px-4">
  <div class="mb-6 flex items-center gap-2.5"><span class="grid size-8 place-items-center rounded-lg bg-accent text-white"><Icon name="inbox" size={17} /></span><span class="text-lg font-semibold">Malo</span></div>
  <h1>Connect to a Malo server</h1>
  <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
    <section class="panel mb-0! bg-panel! px-6! py-5!">
      <h2 class="mt-0 flex items-center gap-2"><Icon name="server" /> On this computer</h2>
      <p class="muted">Runs the bundled backup server locally, bound to 127.0.0.1. Backups run while Malo is open (or in the tray if you enable tray mode).</p>
      <button class="primary" disabled={busy} onclick={local}>Use local server</button>
      <div style="margin-top: 1rem"><LocalData /></div>
    </section>
    <section class="panel mb-0! bg-panel! px-6! py-5!">
      <h2 class="mt-0 flex items-center gap-2"><Icon name="shield" /> Remote server</h2>
      <p class="muted">A Malo server running in Docker on your NAS or a VPS.</p>
      <label>Server URL <input bind:value={url} placeholder="https://backup.example.com:8443" /></label>
      <button disabled={busy || url.length < 10} onclick={check}>Check server</button>
      {#if probe}
        <div class="callout" class:ok={probe.publicly_trusted}>
          {#if probe.publicly_trusted}
            <p>The certificate is publicly trusted.</p>
          {:else}
            <p><strong>First connection.</strong> Compare this certificate fingerprint with the one in the server log before trusting it. Malo will refuse to connect if it ever changes.</p>
            <p class="mono">{probe.fingerprint}</p>
            {#if mismatch}
              <p class="callout bad">The server reports a different certificate ({probe.status.cert_fingerprint}). Something between you and the server may be intercepting the connection — or it runs behind a TLS proxy.</p>
            {/if}
          {/if}
          <p class="small muted">Server version {probe.status.version}{probe.status.needs_setup ? ' · not set up yet' : ''}</p>
          <button class="primary" disabled={busy} onclick={trust}>{probe.publicly_trusted ? 'Connect' : 'Trust and connect'}</button>
        </div>
      {/if}
    </section>
  </div>
  {#if error}<p class="callout bad">{error}</p>{/if}
</div>

