<script lang="ts">
  import { onMount } from 'svelte';
  import { app, certChange, type Probe } from '../api/client';
  import { session, errorText, toStart } from '../state.svelte';
  import LocalData from '../components/LocalData.svelte';
  import Icon from '../components/Icon.svelte';

  let url = $state('https://');
  let probe: Probe | null = $state(null);
  let busy = $state(false);
  let error = $state('');
  /** Ticked after comparing the new fingerprint with the server log. */
  let verified = $state(false);
  let hasProfiles = $state(false);

  onMount(async () => {
    const [prefs, profiles] = await Promise.all([app.prefs().catch(() => null), app.profiles().catch(() => null)]);
    // The server an older version remembered, until a profile holds it.
    if (prefs?.url) url = prefs.url;
    hasProfiles = !!profiles?.recent.length;
  });

  /** Connecting by hand leaves any profile. */
  async function leaveProfile() {
    if (!session.profile) return;
    session.profile = null;
    await app.closeProfile().catch(() => undefined);
  }

  async function local() {
    busy = true;
    error = '';
    try {
      await leaveProfile();
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
      const p = await app.probe(url);
      // A server trusted before that now shows another certificate isn't a first connection.
      const prefs = await app.prefs();
      const now = p.publicly_trusted ? null : p.fingerprint;
      if (prefs.url === p.url && prefs.fingerprint && prefs.fingerprint.toUpperCase() !== now?.toUpperCase()) {
        session.certChanged = { url: p.url, old: prefs.fingerprint, new: now };
        return;
      }
      probe = p;
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
      await leaveProfile();
      session.status = await app.connectRemote(probe.url, probe.publicly_trusted ? null : probe.fingerprint);
      session.local = false;
      session.url = probe.url;
      session.phase = 'login';
    } catch (e) {
      session.certChanged = certChange(e);
      if (session.certChanged) probe = null;
      else error = errorText(e);
    } finally {
      busy = false;
    }
  }

  /** Keeps the old pin: nothing connects to the server until its certificate matches again. */
  async function keepOld() {
    session.certChanged = null;
    verified = false;
    if (session.profile) {
      await leaveProfile();
      await toStart();
    }
  }

  /** Deliberately trusts the new certificate in place of the old one. */
  async function forgetOld() {
    const c = session.certChanged;
    if (!c || !verified) return;
    busy = true;
    error = '';
    try {
      // With a profile open, the new certificate becomes its pin.
      session.status = await app.connectRemote(c.url, c.new, true);
      session.certChanged = null;
      session.local = false;
      session.url = c.url;
      session.phase = 'login';
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
      verified = false;
    }
  }

  const mismatch = $derived.by(() => {
    const p = probe as Probe | null;
    return !!p && !p.publicly_trusted && !!p.status.cert_fingerprint && p.status.cert_fingerprint !== p.fingerprint;
  });
</script>

<div class="mx-auto my-16 max-w-[980px] px-4">
  <div class="mb-6 flex items-center gap-2.5"><span class="grid size-8 place-items-center rounded-lg bg-accent text-white"><Icon name="inbox" size={17} /></span><span class="text-lg font-semibold">Malo</span></div>
  {#if session.certChanged}
  {@const c = session.certChanged}
  <h1>The server's certificate changed</h1>
  <section class="panel bg-panel! px-6! py-5!" role="alert">
    <p class="callout bad"><strong>Malo didn't connect to {c.url}.</strong> It presents a different certificate than the one you trusted. If you didn't replace the server's certificate yourself, something between you and the server may be intercepting the connection: don't log in.</p>
    <p class="mb-1">Trusted certificate</p>
    <p class="mono">{c.old ?? 'A publicly trusted certificate (no fingerprint pinned)'}</p>
    <p class="mb-1">Certificate presented now</p>
    <p class="mono">{c.new ?? 'A publicly trusted certificate (no fingerprint pinned)'}</p>
    <button class="primary" disabled={busy} onclick={keepOld}>Keep the trusted certificate</button>
    <details class="mt-6">
      <summary>I replaced the certificate on the server</summary>
      <p class="muted">Compare the new fingerprint with the one in the server log (<span class="mono">docker logs</span>) before you trust it. The old certificate is forgotten{session.profile ? `, and the profile ${session.profile.name} pins the new one` : ''}.</p>
      <label class="check"><input type="checkbox" bind:checked={verified} /> The new fingerprint matches the server log</label>
      <button class="danger" disabled={busy || !verified} onclick={forgetOld}>Forget the old certificate and connect</button>
    </details>
  </section>
  {:else}
  <div class="flex items-baseline gap-3">
    <h1 class="flex-1">Connect to a Malo server</h1>
    {#if hasProfiles}<button class="link" onclick={() => (session.phase = 'unlock')}><Icon name="key" size={14} /> Use a saved profile</button>{/if}
  </div>
  <p class="muted -mt-2 mb-4">After you log in you can save this connection as a profile file, so next time you only need its password.{#if !hasProfiles} Have one already? <button class="link" onclick={() => (session.phase = 'unlock')}>Use a profile file</button>{/if}</p>
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
  {/if}
  {#if error}<p class="callout bad">{error}</p>{/if}
</div>

