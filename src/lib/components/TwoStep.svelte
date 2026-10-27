<script lang="ts">
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { session, notify, refreshMe, errorText } from '../state.svelte';
  import { copy } from '../menu.svelte';
  import Modal from './Modal.svelte';

  // Two-step login (TOTP): after the password, a code from an authenticator app or one of ten
  // recovery codes. Turning it on, off, or getting new recovery codes takes the password.
  type Step = 'password' | 'scan' | 'codes' | 'disable' | 'renew';
  let step: Step | null = $state(null);
  let password = $state('');
  let code = $state('');
  let setup = $state<T.TotpSetup | null>(null);
  let codes: string[] = $state([]);
  let busy = $state(false);
  let error = $state('');

  const on = $derived(session.me?.totp_enabled ?? false);
  const left = $derived(session.me?.totp_recovery_codes_left ?? 0);
  const qr = $derived(setup ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(setup.qr_svg)}` : '');

  function open(s: Step) {
    step = s;
    password = code = '';
    error = '';
    setup = null;
    codes = [];
  }

  function close() {
    step = null;
    password = code = '';
    setup = null;
    codes = [];
  }

  async function run(fn: () => Promise<void>) {
    busy = true;
    error = '';
    try {
      await fn();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  const start = (e: SubmitEvent) => (e.preventDefault(), run(async () => {
    setup = await api.post<T.TotpSetup>('/auth/totp/setup', { password } satisfies T.TotpSetupRequest);
    password = '';
    step = 'scan';
  }));

  const confirm = (e: SubmitEvent) => (e.preventDefault(), run(async () => {
    const r = await api.post<T.TotpRecoveryCodes>('/auth/totp/enable', { code: code.trim() } satisfies T.TotpCodeRequest);
    codes = r.codes;
    setup = null;
    step = 'codes';
    await refreshMe();
  }));

  const disable = (e: SubmitEvent) => (e.preventDefault(), run(async () => {
    await api.post('/auth/totp/disable', { code: code.trim(), password } satisfies T.TotpCodeRequest);
    close();
    await refreshMe();
    notify('Two-step login is off', 'success');
  }));

  const renew = (e: SubmitEvent) => (e.preventDefault(), run(async () => {
    const r = await api.post<T.TotpRecoveryCodes>('/auth/totp/recovery-codes', { code: code.trim(), password } satisfies T.TotpCodeRequest);
    codes = r.codes;
    step = 'codes';
    await refreshMe();
  }));
</script>

<div class="panel">
  <h2>Two-step login</h2>
  {#if on}
    <p><span class="pill ok">on</span> Logging in asks for a code from your authenticator app after the password.</p>
    {#if left <= 3}
      <p class="callout">{left === 0 ? 'No recovery codes left.' : `Only ${left} recovery code${left === 1 ? '' : 's'} left.`} Get new ones so a lost phone doesn't lock you out.</p>
    {:else}
      <p class="muted small">{left} recovery codes left.</p>
    {/if}
    <div class="row">
      <button onclick={() => open('renew')}>New recovery codes…</button>
      <button onclick={() => open('disable')}>Turn off…</button>
    </div>
  {:else}
    <p class="muted">After your password, logging in also asks for a 6-digit code from an authenticator app (1Password, Aegis, Google Authenticator…), so a leaked password alone doesn't unlock your backups. A recovery-kit password reset turns it off.</p>
    <button onclick={() => open('password')}>Set up…</button>
  {/if}
</div>

{#if step}
  <Modal title={step === 'disable' ? 'Turn off two-step login' : step === 'renew' ? 'New recovery codes' : step === 'codes' ? 'Your recovery codes' : 'Set up two-step login'} onclose={close}>
    {#if step === 'password'}
      <form onsubmit={start}>
        <label>Your Malo password <input type="password" bind:value={password} required autocomplete="current-password" /></label>
        {#if error}<p class="callout bad">{error}</p>{/if}
        <button class="primary mt-1" type="submit" disabled={busy || !password}>Continue</button>
      </form>
    {:else if step === 'scan' && setup}
      <form onsubmit={confirm}>
        <p class="muted small">Scan this with your authenticator app, or type the key into it by hand.</p>
        <div class="my-3 flex flex-wrap items-center gap-4">
          <img src={qr} alt="QR code for your authenticator app" class="size-48 rounded-lg bg-white p-1" />
          <div class="min-w-0 flex-1">
            <div class="small muted">Key</div>
            <div class="mono break-all">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</div>
            <button type="button" class="link small" onclick={() => copy(setup!.secret, 'Key copied')}>Copy key</button>
          </div>
        </div>
        <label>Code the app shows now
          <input bind:value={code} required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" placeholder="123456" />
        </label>
        {#if error}<p class="callout bad">{error}</p>{/if}
        <button class="primary mt-1" type="submit" disabled={busy || code.trim().length < 6}>Turn on</button>
      </form>
    {:else if step === 'codes'}
      <p>Each of these logs you in once in place of a code, if you lose your authenticator app. Store them with your recovery kit, apart from your phone. They aren't shown again.</p>
      <ul class="mono my-3 grid list-none grid-cols-2 gap-x-6 gap-y-1 p-0">
        {#each codes as c}<li class="m-0">{c}</li>{/each}
      </ul>
      <div class="row">
        <button onclick={() => copy(codes.join('\n'), 'Recovery codes copied')}>Copy</button>
        <span class="grow"></span>
        <button class="primary" onclick={close}>I stored them</button>
      </div>
    {:else}
      <form onsubmit={step === 'disable' ? disable : renew}>
        <label>Your Malo password <input type="password" bind:value={password} required autocomplete="current-password" /></label>
        <label>Code from your app, or a recovery code
          <input bind:value={code} required autocomplete="one-time-code" spellcheck="false" maxlength="16" />
        </label>
        {#if step === 'renew'}<p class="muted small">Your current recovery codes stop working.</p>{/if}
        {#if error}<p class="callout bad">{error}</p>{/if}
        <button class="mt-1 {step === 'disable' ? 'danger' : 'primary'}" type="submit" disabled={busy || !password || !code}>{step === 'disable' ? 'Turn off' : 'Get new codes'}</button>
      </form>
    {/if}
  </Modal>
{/if}
