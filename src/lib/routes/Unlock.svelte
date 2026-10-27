<script lang="ts">
  import { onMount } from 'svelte';
  import { app, certChange, type RecentProfile } from '../api/client';
  import { session, errorText, fromProfile } from '../state.svelte';
  import Icon from '../components/Icon.svelte';

  // Opens a connection profile: an encrypted file the user keeps (like a KeePassXC database) that
  // says which server to use, the certificate pinned for it and who logs in. The app remembers
  // only the paths of recent profiles; the last one used is preselected.
  let recent: RecentProfile[] = $state([]);
  let chosen = $state('');
  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  let input: HTMLInputElement | undefined = $state();
  /** Nothing is shown until the list is in, so the screen doesn't change under the user. */
  let loaded = $state(false);

  const current = $derived(recent.find((r) => r.path === chosen) ?? null);

  async function load() {
    recent = (await app.profiles().catch(() => null))?.recent ?? [];
    if (!recent.some((r) => r.path === chosen)) chosen = recent.find((r) => r.exists)?.path ?? recent[0]?.path ?? '';
  }

  onMount(async () => {
    await load();
    loaded = true;
  });

  $effect(() => {
    if (loaded && current?.exists) input?.focus();
  });

  function choose(path: string) {
    chosen = path;
    password = '';
    error = '';
    input?.focus();
  }

  async function openFile() {
    error = '';
    const path = await app.pickProfile().catch((e) => ((error = errorText(e)), null));
    if (!path) return;
    if (!recent.some((r) => r.path === path)) {
      const name = path.split(/[\\/]/).pop()?.replace(/\.malo$/i, '') ?? path;
      recent = [{ path, name, exists: true }, ...recent];
    }
    choose(path);
  }

  async function forget(path: string) {
    await app.forgetProfile(path).catch(() => undefined);
    if (chosen === path) chosen = '';
    await load();
    if (!recent.length) session.phase = 'connect';
  }

  async function unlock(e: SubmitEvent) {
    e.preventDefault();
    if (!chosen) return;
    busy = true;
    error = '';
    try {
      const u = await app.unlockProfile(chosen, password);
      password = '';
      await fromProfile(u);
    } catch (err) {
      const c = certChange(err);
      if (c) {
        // The profile stays open on the Rust side, so trusting the new certificate updates its pin.
        password = '';
        session.profile = (await app.profiles().catch(() => null))?.open ?? null;
        session.certChanged = c;
        session.phase = 'connect';
      } else {
        error = errorText(err);
        input?.select();
      }
    } finally {
      busy = false;
    }
  }

  function withoutProfile() {
    session.lockedReason = null;
    session.phase = 'connect';
  }
</script>

<div class="mx-auto my-20 max-w-[560px] px-4">
  <div class="mb-6 flex items-center gap-2.5"><span class="grid size-8 place-items-center rounded-lg bg-accent text-white"><Icon name="inbox" size={17} /></span><span class="text-lg font-semibold">Malo</span></div>
  <section class="panel bg-panel! px-7! py-6! shadow-xl shadow-black/10">
    <h1>Open a profile</h1>
    {#if session.lockedReason}<p class="callout">{session.lockedReason} Enter the profile password to continue.</p>{/if}

    {#if !loaded}
      <div class="h-40"></div>
    {:else if current}
      <form onsubmit={unlock}>
        <div class="my-3 flex items-center gap-3 rounded-lg border border-line bg-raised px-3 py-2.5">
          <span class="grid size-9 flex-none place-items-center rounded-lg bg-accent/15 text-accent-2"><Icon name="key" size={17} /></span>
          <span class="min-w-0 flex-1">
            <span class="block truncate font-medium">{current.name}</span>
            <span class="mono block truncate text-muted" title={current.path}>{current.path}</span>
          </span>
        </div>
        {#if !current.exists}
          <p class="callout bad">This file isn't there any more. It may be on a drive that isn't connected, or it was moved.</p>
        {/if}
        <label>Profile password
          <input bind:this={input} type="password" bind:value={password} required autocomplete="current-password" disabled={!current.exists} />
        </label>
        {#if error}<p class="callout bad">{error}</p>{/if}
        <div class="row mt-4">
          <button class="primary" type="submit" disabled={busy || !current.exists || !password}>{busy ? 'Unlocking… (key derivation takes a moment)' : 'Unlock'}</button>
        </div>
      </form>
    {:else}
      <p class="muted">A profile is a file that holds which server to connect to, its trusted certificate and your username, encrypted with a password. Malo itself remembers no server.</p>
    {/if}

    {#if recent.length > 1 || (recent.length && !current)}
      <h3 class="mt-6 mb-2 text-[0.9rem] font-medium text-muted">Recent profiles</h3>
      <ul class="m-0 flex list-none flex-col gap-0.5 p-0">
        {#each recent as r (r.path)}
          <li class="mt-0 flex items-center gap-1">
            <button type="button" class="flex min-w-0 flex-1 items-center gap-2.5 px-2.5 py-1.5 text-left {r.path === chosen ? 'bg-raised!' : 'bg-transparent'}" onclick={() => choose(r.path)}>
              <span class={r.exists ? 'text-muted' : 'text-faint'}><Icon name="key" size={14} /></span>
              <span class="min-w-0 flex-1 truncate {r.exists ? '' : 'text-faint line-through'}" title={r.path}>{r.name}</span>
              {#if !r.exists}<span class="pill muted">missing</span>{/if}
            </button>
            <button type="button" class="bg-transparent p-1.5 text-faint hover:text-fg" onclick={() => forget(r.path)} aria-label="Remove {r.name} from this list" title="Remove from this list (the file stays)"><Icon name="x" size={14} /></button>
          </li>
        {/each}
      </ul>
    {/if}

    <div class="row mt-6 border-t border-line pt-4">
      <button type="button" onclick={openFile}><Icon name="file" size={14} /> Open profile file…</button>
      <span class="grow"></span>
      <button type="button" class="link" onclick={withoutProfile}>Connect without a profile</button>
    </div>
  </section>
</div>
