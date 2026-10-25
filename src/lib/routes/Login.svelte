<script lang="ts">
  import { onMount } from 'svelte';
  import { api, app } from '../api/client';
  import type * as T from '../api/types';
  import { session, enterApp, errorText, notify } from '../state.svelte';
  import LocalData from '../components/LocalData.svelte';
  import Icon from '../components/Icon.svelte';

  type Mode = 'login' | 'setup' | 'register';
  let mode: Mode = $state(session.status?.needs_setup ? 'setup' : 'login');
  let username = $state('');
  let password = $state('');
  let password2 = $state('');
  let setupToken = $state(session.setupToken ?? '');
  let invite = $state('');
  let kit: T.RecoveryKit | null = $state(null);
  let busy = $state(false);
  let error = $state('');
  let pendingMe: T.Me | null = $state(null);
  let kitSaved = $state(false);

  onMount(async () => {
    const prefs = await app.prefs().catch(() => null);
    if (prefs?.last_username) username = prefs.last_username;
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (mode !== 'login' && password !== password2) {
      error = 'Passwords do not match';
      return;
    }
    busy = true;
    try {
      if (mode === 'setup') {
        await api.post('/setup', { setup_token: setupToken, username, password } satisfies T.SetupRequest);
        session.status = { ...session.status!, needs_setup: false };
        notify('Administrator created', 'success');
      } else if (mode === 'register') {
        await api.post('/auth/register', {
          username,
          password,
          invite_code: invite || null,
          recovery_kit: kit,
        } satisfies T.RegisterRequest);
        notify('Account created', 'success');
      }
      const me = await app.login(username, password);
      password = password2 = '';
      if (me.recovery_kit_pending) {
        pendingMe = me;
      } else {
        await enterApp(me);
      }
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function saveKit() {
    try {
      const path = await app.saveRecoveryKit();
      if (path) {
        kitSaved = true;
        notify(`Recovery kit saved to ${path}`, 'success');
      }
    } catch (e) {
      error = errorText(e);
    }
  }

  async function chooseKit() {
    try {
      kit = await app.pickRecoveryKit();
    } catch (e) {
      error = errorText(e);
    }
  }

  async function disconnect() {
    await app.disconnect();
    session.phase = 'connect';
  }
</script>

<div class="mx-auto my-20 max-w-[520px] px-4">
  <div class="mb-6 flex items-center gap-2.5"><span class="grid size-8 place-items-center rounded-lg bg-accent text-white"><Icon name="inbox" size={17} /></span><span class="text-lg font-semibold">Malo</span></div>
  {#if pendingMe}
    <section class="panel bg-panel! px-7! py-6! shadow-xl shadow-black/10">
      <h1>Save your recovery kit</h1>
      <p>Your backups are encrypted with a key that only your password unlocks. <strong>Nobody — not even the server administrator — can recover your data if you forget your password.</strong></p>
      <p>The recovery kit contains your archive key. With it, a new account can read every encrypted backup you made. Store it offline (password manager, USB stick, printed) and keep it secret.</p>
      <div class="row">
        <button class="primary" onclick={saveKit}>Save recovery kit…</button>
        <button disabled={!kitSaved} onclick={() => enterApp(pendingMe!)}>I stored it safely — continue</button>
      </div>
    </section>
  {:else}
    <section class="panel bg-panel! px-7! py-6! shadow-xl shadow-black/10">
      <h1>{mode === 'setup' ? 'Create the administrator' : mode === 'register' ? 'Create an account' : 'Log in to unlock'}</h1>
      <p class="muted small">{session.local ? 'Local server' : session.url}</p>
      {#if session.lockedReason}<p class="callout">{session.lockedReason} Log in to resume backups.</p>{/if}
      {#if mode === 'login'}
        <p class="muted">Logging in unlocks your keys on the server. Scheduled backups only run while you are unlocked; the server locks you automatically after your auto-lock period.</p>
      {/if}
      <form onsubmit={submit}>
        {#if mode === 'setup'}
          <label>Setup token <input bind:value={setupToken} required placeholder="printed in the server log on first start" /></label>
        {/if}
        <label>Username <input bind:value={username} required autocomplete="username" /></label>
        <label>Password <input type="password" bind:value={password} required autocomplete={mode === 'login' ? 'current-password' : 'new-password'} minlength={mode === 'login' ? 1 : 10} /></label>
        {#if mode !== 'login'}
          <label>Repeat password <input type="password" bind:value={password2} required autocomplete="new-password" /></label>
        {/if}
        {#if mode === 'register'}
          <label>Invite code <input bind:value={invite} placeholder={session.status?.self_registration ? 'optional' : 'required'} /></label>
          <div class="row small">
            <button type="button" onclick={chooseKit}>Import recovery kit…</button>
            <span class="muted">{kit ? `Kit of ${kit.username} will be adopted` : 'Optional: read the encrypted backups of a previous account'}</span>
          </div>
        {/if}
        {#if error}<p class="callout bad">{error}</p>{/if}
        <div class="row" style="margin-top: 1rem">
          <button class="primary" type="submit" disabled={busy}>{busy ? 'Working… (key derivation takes a moment)' : mode === 'login' ? 'Unlock' : 'Create'}</button>
          <span class="grow"></span>
          {#if mode === 'login'}
            <button type="button" class="link" onclick={() => (mode = 'register')}>Create account</button>
          {:else if mode === 'register'}
            <button type="button" class="link" onclick={() => (mode = 'login')}>Back to login</button>
          {/if}
          <button type="button" class="link" onclick={disconnect}>Change server</button>
        </div>
      </form>
      {#if session.local && mode === 'login'}<LocalData compact />{/if}
    </section>
  {/if}
</div>

