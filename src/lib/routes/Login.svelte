<script lang="ts">
  import { api, app, ApiError } from '../api/client';
  import type * as T from '../api/types';
  import { session, live, enterApp, errorText, notify, leaveServer, go } from '../state.svelte';
  import LocalData from '../components/LocalData.svelte';
  import Icon from '../components/Icon.svelte';
  import KitExport from '../components/KitExport.svelte';
  import ProfileSave from '../components/ProfileSave.svelte';

  /** `restore`: a new user from a recovery kit, set up again from the destinations it holds. */
  type Mode = 'login' | 'setup' | 'register' | 'recover' | 'restore';
  let mode: Mode = $state(session.status?.needs_setup ? 'setup' : 'login');
  let username = $state(session.profile?.username ?? session.lastUsername ?? '');
  let password = $state('');
  let password2 = $state('');
  let setupToken = $state(session.setupToken ?? '');
  let invite = $state('');
  let kit: T.RecoveryKitFile | null = $state(null);
  let kitPassphrase = $state('');
  let busy = $state(false);
  let error = $state('');
  /** Two-step login: the server asked for a code from the authenticator app. */
  let needCode = $state(session.profileTotp);
  /** Only the code is missing: the password kept in the profile was accepted. */
  const profileCode = $derived(session.profileTotp && mode === 'login');
  let code = $state('');
  let codeInput: HTMLInputElement | undefined = $state();
  // Logged in from a profile that kept the password, with the kit still to save: the kit form
  // asks for the password itself.
  let pendingMe: T.Me | null = $state(session.kitPending);
  session.kitPending = null;
  // Kept only until the kit (and the profile) are saved: the server asks for the password again
  // before it hands out the key.
  let pendingPassword: string | null = $state(null);
  let kitSaved = $state(false);
  /** Destinations the kit brought back: the first login is rebuilding from them. */
  let restored = $state(0);
  /** Offer to save this connection as a profile once logged in, until the user declines once. */
  let wantProfile = $state(!session.profile && offerProfile());
  let profileStep = $state(false);

  function offerProfile(): boolean {
    try { return localStorage.getItem('malo.offerProfile') !== '0'; } catch { return true; }
  }
  function setOfferProfile(on: boolean) {
    wantProfile = on;
    try { localStorage.setItem('malo.offerProfile', on ? '1' : '0'); } catch { /* not remembered */ }
  }

  const sealed = $derived(kit !== null && 'data' in kit);
  // Plain (v1) kits carry the username in the clear; encrypted ones don't.
  const kitLabel = $derived(!kit ? '' : sealed ? 'Encrypted kit' : `Kit of ${(kit as T.RecoveryKit).username}`);

  function setMode(m: Mode) {
    mode = m;
    error = '';
    kit = null;
    kitPassphrase = '';
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (mode !== 'login' && password !== password2) {
      error = 'Passwords do not match';
      return;
    }
    if ((mode === 'recover' || mode === 'restore') && !kit) {
      error = 'Choose your recovery kit file';
      return;
    }
    busy = true;
    try {
      if (mode === 'setup') {
        const r = await api.post<T.RegisterResponse>('/setup', {
          setup_token: setupToken,
          username,
          password,
          recovery_kit: kit ?? undefined,
          kit_passphrase: sealed ? kitPassphrase : undefined,
        } satisfies T.SetupRequest);
        restored = r?.restored_destinations ?? 0;
        session.status = { ...session.status!, needs_setup: false };
        notify('Administrator created', 'success');
      } else if (mode === 'register' || mode === 'restore') {
        const r = await api.post<T.RegisterResponse>('/auth/register', {
          username,
          password,
          invite_code: invite || null,
          recovery_kit: kit,
          kit_passphrase: sealed ? kitPassphrase : undefined,
        } satisfies T.RegisterRequest);
        restored = r?.restored_destinations ?? 0;
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
      const me = profileCode
        ? await app.loginProfile(code)
        : await app.login(username, password, mode === 'login' && needCode ? code : null);
      code = '';
      kit = null;
      kitPassphrase = '';
      pendingMe = me;
      pendingPassword = password;
      if (!me.recovery_kit_pending) next();
      password = password2 = '';
    } catch (e) {
      if (e instanceof ApiError && e.code === 'totp_required') {
        // The password was right; ask for the code and keep what was typed.
        needCode = true;
        setTimeout(() => codeInput?.focus());
      } else {
        error = errorText(e);
        if (e instanceof ApiError && e.code === 'totp_wrong') {
          code = '';
          setTimeout(() => codeInput?.focus());
        }
      }
    } finally {
      busy = false;
    }
  }

  /** After the kit: the profile, if wanted, then the app. */
  function next() {
    if (wantProfile && !session.profile && !profileStep) {
      profileStep = true;
      return;
    }
    pendingPassword = null;
    const n = restored;
    enterApp(pendingMe!).then(() => {
      if (!n) return;
      const waiting = live.destinations.filter((d) => d.missing_secrets?.length).length;
      if (waiting === n) {
        // The kit kept no credentials: the restore starts once one destination has them.
        go('/destinations');
        notify(`Your kit brought back ${n} destination${n === 1 ? '' : 's'} without credentials. Enter them for one, and accounts, settings and mail come back from it.`, 'warning');
        return;
      }
      // Activity shows the rebuild bringing accounts, settings and mail back.
      go('/activity');
      notify(`Restoring from ${n - waiting} destination${n - waiting === 1 ? '' : 's'} saved in your kit: accounts, settings and mail come back as the rebuild runs.${waiting ? ` ${waiting} more wait for their credentials under Destinations.` : ''}`, 'success');
    });
  }

  function finishKit() {
    kitSaved = false;
    next();
  }

  async function chooseKit() {
    try {
      // Cancelling the dialog keeps the kit chosen before.
      kit = (await app.pickRecoveryKit()) ?? kit;
    } catch (e) {
      error = errorText(e);
    }
  }

  const disconnect = leaveServer;
</script>

<div class="mx-auto my-20 max-w-[520px] px-4">
  <div class="mb-6 flex items-center gap-2.5"><span class="grid size-8 place-items-center rounded-lg bg-accent text-white"><Icon name="inbox" size={17} /></span><span class="text-lg font-semibold">Malo</span></div>
  {#if pendingMe && profileStep}
    <section class="panel bg-panel! px-7! py-6! shadow-xl shadow-black/10">
      <h1>Save this connection as a profile</h1>
      <ProfileSave password={pendingPassword} onsaved={next} />
      <div class="row mt-3">
        <button class="link" onclick={() => (setOfferProfile(false), next())}>Not now</button>
      </div>
    </section>
  {:else if pendingMe && pendingMe.recovery_kit_pending}
    <section class="panel bg-panel! px-7! py-6! shadow-xl shadow-black/10">
      <h1>Save your recovery kit</h1>
      <p>Your backups are encrypted with a key that only your password unlocks. <strong>Nobody — not even the server administrator — can recover your data if you forget your password.</strong></p>
      <p>The recovery kit contains your archive key and your destinations, encrypted with a passphrase you choose. With the kit and its passphrase you can reset a forgotten password here, or restore everything on a new server in one step. Store the file offline (password manager, USB stick) and keep the passphrase somewhere else. Malo reminds you to save a new kit when your destinations change.</p>
      <KitExport username={pendingMe.username} password={pendingPassword} onsaved={() => (kitSaved = true)} />
      <div class="row mt-3">
        <button disabled={!kitSaved} onclick={finishKit}>I stored it safely — continue</button>
      </div>
    </section>
  {:else}
    <section class="panel bg-panel! px-7! py-6! shadow-xl shadow-black/10">
      <h1>{mode === 'setup' ? 'Create the administrator' : mode === 'register' ? 'Create an account' : mode === 'recover' ? 'Reset password with recovery kit' : mode === 'restore' ? 'Restore from a recovery kit' : 'Log in to unlock'}</h1>
      <p class="muted small">{#if session.profile}<Icon name="key" size={12} /> {session.profile.name} · {/if}{session.local ? 'Local server' : session.url}</p>
      {#if session.lockedReason && mode === 'login'}<p class="callout">{session.lockedReason} Log in to resume backups.</p>{/if}
      {#if mode === 'login'}
        <p class="muted">Logging in unlocks your keys on the server. Scheduled backups only run while you are unlocked; the server locks you automatically after your auto-lock period.</p>
      {:else if mode === 'recover'}
        <p class="muted">Your recovery kit proves you own this account. Choose a new password: your accounts, destinations and backups stay as they are, and every other session is logged out.</p>
      {:else if mode === 'restore'}
        <p class="muted">For when your old server or account is gone. You get a new account here, and the destinations saved in the kit are set up again. When you log in, Malo reads them and brings back your accounts, settings and mail. Kits saved before this existed hold only the key: then add one old destination and run <em>Rebuild index</em>.</p>
      {/if}
      <form onsubmit={submit}>
        {#if mode === 'setup'}
          <label>Setup token <input bind:value={setupToken} required placeholder="printed in the server log on first start" /></label>
        {/if}
        {#if profileCode}
          <p class="muted">The password kept in <strong>{session.profile?.name}</strong> was accepted.</p>
        {:else}
        <label>Username <input bind:value={username} required autocomplete="username" /></label>
        {/if}
        {#if mode === 'recover' || mode === 'restore'}
          <div class="row small">
            <button type="button" onclick={chooseKit}>Choose recovery kit…</button>
            <span class="muted">{kit ? kitLabel : 'The malo-recovery-kit-….json file you saved'}</span>
          </div>
          {#if sealed}<label>Kit passphrase <input type="password" bind:value={kitPassphrase} required autocomplete="off" /></label>{/if}
        {/if}
        {#if !profileCode}
        <label>{mode === 'recover' ? 'New password' : 'Password'} <input type="password" bind:value={password} required autocomplete={mode === 'login' ? 'current-password' : 'new-password'} minlength={mode === 'login' ? 1 : 10} /></label>
        {/if}
        {#if mode === 'login' && needCode}
          <label>Code from your authenticator app
            <input bind:this={codeInput} bind:value={code} required autocomplete="one-time-code" inputmode="text" spellcheck="false" placeholder="123456" maxlength="16" />
          </label>
          <p class="muted small">Lost the app? Enter one of your recovery codes instead (each works once).</p>
        {/if}
        {#if mode !== 'login'}
          <label>Repeat password <input type="password" bind:value={password2} required autocomplete="new-password" /></label>
        {/if}
        {#if mode === 'setup'}
          <div class="row small">
            <button type="button" onclick={chooseKit}>Restore from recovery kit…</button>
            <span class="muted">{kit ? `${kitLabel}: its destinations, accounts and mail come back` : 'Replacing a lost server? Optional'}</span>
            {#if kit}<button type="button" class="link" onclick={() => ((kit = null), (kitPassphrase = ''))}>Remove</button>{/if}
          </div>
          {#if sealed}<label>Kit passphrase <input type="password" bind:value={kitPassphrase} required autocomplete="off" /></label>{/if}
        {/if}
        {#if mode === 'restore'}
          <label>Invite code <input bind:value={invite} placeholder={session.status?.self_registration ? 'optional' : 'required'} /></label>
        {/if}
        {#if mode === 'register'}
          <label>Invite code <input bind:value={invite} placeholder={session.status?.self_registration ? 'optional' : 'required'} /></label>
          <div class="row small">
            <button type="button" onclick={chooseKit}>Import recovery kit…</button>
            <span class="muted">{kit ? `${kitLabel} will be adopted` : 'Optional: bring back a previous account’s destinations, settings and mail'}</span>
            {#if kit}<button type="button" class="link" onclick={() => ((kit = null), (kitPassphrase = ''))}>Remove</button>{/if}
          </div>
          {#if sealed}<label>Kit passphrase <input type="password" bind:value={kitPassphrase} required autocomplete="off" /></label>{/if}
        {/if}
        {#if !session.profile}
          <label class="check small"><input type="checkbox" checked={wantProfile} onchange={(e) => setOfferProfile(e.currentTarget.checked)} /> Then save this connection as a profile file</label>
        {/if}
        {#if error}<p class="callout bad">{error}</p>{/if}
        <div class="row" style="margin-top: 1rem">
          <button class="primary" type="submit" disabled={busy}>{busy ? 'Working… (key derivation takes a moment)' : mode === 'login' ? 'Unlock' : mode === 'recover' ? 'Reset password' : mode === 'restore' ? 'Restore' : 'Create'}</button>
          <span class="grow"></span>
          {#if mode === 'login'}
            <button type="button" class="link" onclick={() => setMode('recover')}>Forgot password?</button>
            <button type="button" class="link" onclick={() => setMode('register')}>Create account</button>
            <button type="button" class="link" onclick={() => setMode('restore')}>Restore from kit</button>
          {:else if mode === 'register' || mode === 'recover' || mode === 'restore'}
            <button type="button" class="link" onclick={() => setMode('login')}>Back to login</button>
          {/if}
          <button type="button" class="link" onclick={disconnect}>{session.profile ? 'Close profile' : 'Change server'}</button>
        </div>
      </form>
      {#if session.local && mode === 'login'}<LocalData compact />{/if}
    </section>
  {/if}
</div>

