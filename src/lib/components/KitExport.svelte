<script lang="ts">
  import { app } from '../api/client';
  import { errorText, notify } from '../state.svelte';

  // Saves an encrypted recovery kit. The server re-checks the password before handing out the
  // archive key; the passphrase encrypts the file so a copied kit alone is useless.
  let {
    username,
    password: knownPassword = null,
    onsaved,
  }: { username: string; password?: string | null; onsaved?: (path: string) => void } = $props();

  let password = $state('');
  let passphrase = $state('');
  let passphrase2 = $state('');
  let busy = $state(false);
  let error = $state('');

  async function save(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (passphrase.length < 12) return (error = 'Use a kit passphrase of at least 12 characters');
    if (passphrase !== passphrase2) return (error = 'Passphrases do not match');
    const pw = knownPassword ?? password;
    if (passphrase === pw) return (error = 'Use a passphrase different from your password');
    busy = true;
    try {
      const path = await app.saveRecoveryKit(username, pw, passphrase);
      if (path) {
        notify(`Recovery kit saved to ${path}`, 'success');
        password = passphrase = passphrase2 = '';
        onsaved?.(path);
      }
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<form onsubmit={save}>
  {#if knownPassword === null}
    <label>Your password <input type="password" bind:value={password} required autocomplete="current-password" /></label>
  {/if}
  <label>Kit passphrase <input type="password" bind:value={passphrase} required minlength="12" autocomplete="new-password" /></label>
  <label>Repeat kit passphrase <input type="password" bind:value={passphrase2} required autocomplete="new-password" /></label>
  <p class="muted small">The kit file is encrypted with this passphrase. Write it down apart from the file. It is not your password, and changing your password doesn't change it. Without it the kit can't be opened.</p>
  {#if error}<p class="callout bad">{error}</p>{/if}
  <div class="row mt-1">
    <button class="primary" type="submit" disabled={busy}>{busy ? 'Encrypting…' : 'Save recovery kit…'}</button>
  </div>
</form>
