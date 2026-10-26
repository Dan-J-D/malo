<script lang="ts">
  import { onMount } from 'svelte';
  import { api, app } from '../api/client';
  import type * as T from '../api/types';
  import { session, enterApp, errorText, notify } from '../state.svelte';
  import LocalData from '../components/LocalData.svelte';
  import Icon from '../components/Icon.svelte';
  import KitExport from '../components/KitExport.svelte';

  type Mode = 'login' | 'setup' | 'register' | 'recover';
  let mode: Mode = $state(session.status?.needs_setup ? 'setup' : 'login');
  let username = $state('');
  let password = $state('');
  let password2 = $state('');
  let setupToken = $state(session.setupToken ?? '');
  let invite = $state('');
  let kit: T.RecoveryKitFile | null = $state(null);
  let kitPassphrase = $state('');
  let busy = $state(false);
  let error = $state('');
  let pendingMe: T.Me | null = $state(null);
  // Kept only until the kit is saved: the server asks for the password again before it hands out the key.
  let pendingPassword: string | null = $state(null);
  let kitSaved = $state(false);

  const sealed = $derived(kit !== null && 'data' in kit);
  // Plain (v1) kits carry the username in the clear; encrypted ones don't.
  const kitLabel = $derived(!kit ? '' : sealed ? 'Encrypted kit' : `Kit of ${(kit as T.RecoveryKit).username}`);

  function setMode(m: Mode) {
    mode = m;
    error = '';
    kit = null;
    kitPassphrase = '';
  }

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
    if (mode === 'recover' && !kit) {
      error = 'Choose your recovery kit file';
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
          kit_passphrase: sealed ? kitPassphrase : undefined,
        } satisfies T.RegisterRequest);
        notify('Account created', 'success');
      } else if (mode === 'recover') {
        await api.post('/auth/recover', {
          username,
          recovery_kit: kit!,
          kit_passphrase: sealed ? kitPassphrase : undefined,
          new_password: password,
        } satisfies T.RecoverRequest);
        notify('Password reset. Your backups and settings are unchanged.', 'success');
      }
      const me = await app.login(username, password);
      kit = null;
      kitPassphrase = '';
      if (me.recovery_kit_pending) {
        pendingPassword = password;
        pendingMe = me;
      } else {
        await enterApp(me);
      }
      password = password2 = '';
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function finishKit() {
    pendingPassword = null;
    enterApp(pendingMe!);
  }

  async function chooseKit() {
    try {
      // Cancelling the dialog keeps the kit chosen before.
      kit = (await app.pickRecoveryKit()) ?? kit;
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
      <p>The recovery kit contains your archive key, encrypted with a passphrase you choose. With the kit and its passphrase you can reset a forgotten password here, or read your backups from a new account or another server. Store the file offline (password manager, USB stick) and keep the passphrase somewhere else.</p>
      <KitExport username={pendingMe.username} password={pendingPassword} onsaved={() => (kitSaved = true)} />
      <div class="row mt-3">
        <button disabled={!kitSaved} onclick={finishKit}>I stored it safely — continue</button>
      </div>
    </section>
  {:else}
    <section class="panel bg-panel! px-7! py-6! shadow-xl shadow-black/10">
      <h1>{mode === 'setup' ? 'Create the administrator' : mode === 'register' ? 'Create an account' : mode === 'recover' ? 'Reset password with recovery kit' : 'Log in to unlock'}</h1>
      <p class="muted small">{session.local ? 'Local server' : session.url}</p>
      {#if session.lockedReason && mode === 'login'}<p class="callout">{session.lockedReason} Log in to resume backups.</p>{/if}
      {#if mode === 'login'}
        <p class="muted">Logging in unlocks your keys on the server. Scheduled backups only run while you are unlocked; the server locks you automatically after your auto-lock period.</p>
      {:else if mode === 'recover'}
        <p class="muted">Your recovery kit proves you own this account. Choose a new password: your accounts, destinations and backups stay as they are, and every other session is logged out.</p>
      {/if}
      <form onsubmit={submit}>
        {#if mode === 'setup'}
          <label>Setup token <input bind:value={setupToken} required placeholder="printed in the server log on first start" /></label>
        {/if}
        <label>Username <input bind:value={username} required autocomplete="username" /></label>
        {#if mode === 'recover'}
          <div class="row small">
            <button type="button" onclick={chooseKit}>Choose recovery kit…</button>
            <span class="muted">{kit ? kitLabel : 'The malo-recovery-kit-….json file you saved'}</span>
          </div>
          {#if sealed}<label>Kit passphrase <input type="password" bind:value={kitPassphrase} required autocomplete="off" /></label>{/if}
        {/if}
        <label>{mode === 'recover' ? 'New password' : 'Password'} <input type="password" bind:value={password} required autocomplete={mode === 'login' ? 'current-password' : 'new-password'} minlength={mode === 'login' ? 1 : 10} /></label>
        {#if mode !== 'login'}
          <label>Repeat password <input type="password" bind:value={password2} required autocomplete="new-password" /></label>
        {/if}
        {#if mode === 'register'}
          <label>Invite code <input bind:value={invite} placeholder={session.status?.self_registration ? 'optional' : 'required'} /></label>
          <div class="row small">
            <button type="button" onclick={chooseKit}>Import recovery kit…</button>
            <span class="muted">{kit ? `${kitLabel} will be adopted` : 'Optional: read the encrypted backups of a previous account'}</span>
            {#if kit}<button type="button" class="link" onclick={() => ((kit = null), (kitPassphrase = ''))}>Remove</button>{/if}
          </div>
          {#if sealed}<label>Kit passphrase <input type="password" bind:value={kitPassphrase} required autocomplete="off" /></label>{/if}
        {/if}
        {#if error}<p class="callout bad">{error}</p>{/if}
        <div class="row" style="margin-top: 1rem">
          <button class="primary" type="submit" disabled={busy}>{busy ? 'Working… (key derivation takes a moment)' : mode === 'login' ? 'Unlock' : mode === 'recover' ? 'Reset password' : 'Create'}</button>
          <span class="grow"></span>
          {#if mode === 'login'}
            <button type="button" class="link" onclick={() => setMode('recover')}>Forgot password?</button>
            <button type="button" class="link" onclick={() => setMode('register')}>Create account</button>
          {:else if mode === 'register' || mode === 'recover'}
            <button type="button" class="link" onclick={() => setMode('login')}>Back to login</button>
          {/if}
          <button type="button" class="link" onclick={disconnect}>Change server</button>
        </div>
      </form>
      {#if session.local && mode === 'login'}<LocalData compact />{/if}
    </section>
  {/if}
</div>

