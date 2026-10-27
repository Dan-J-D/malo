<script lang="ts">
  import { app, type ProfileInfo } from '../api/client';
  import { session, errorText, notify } from '../state.svelte';

  // Saves the current connection as an encrypted profile file: server, pinned certificate,
  // username and, if wanted, the Malo password. Next time, its password is all it takes.
  let {
    password: knownPassword = null,
    onsaved,
  }: { password?: string | null; onsaved?: (p: ProfileInfo) => void } = $props();

  let profilePw = $state('');
  let profilePw2 = $state('');
  let keepLogin = $state(true);
  let loginPw = $state('');
  let busy = $state(false);
  let error = $state('');

  async function save(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (profilePw.length < 8) return (error = 'Use a profile password of at least 8 characters');
    if (profilePw !== profilePw2) return (error = 'Passwords do not match');
    busy = true;
    try {
      const p = await app.saveProfile(profilePw, keepLogin ? (knownPassword ?? loginPw) : null);
      if (p) {
        session.profile = p;
        profilePw = profilePw2 = loginPw = '';
        notify(`Profile saved to ${p.path}`, 'success');
        onsaved?.(p);
      }
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<form onsubmit={save}>
  <p class="muted small">The profile file holds {session.local ? 'the local server' : session.url}, its trusted certificate and your username, encrypted with the password below. Keep it wherever you like, a USB stick or a synced folder. Malo remembers only where it is, and you can turn that off.</p>
  <div class="cards">
    <label>Profile password <input type="password" bind:value={profilePw} required minlength="8" autocomplete="new-password" /></label>
    <label>Repeat profile password <input type="password" bind:value={profilePw2} required autocomplete="new-password" /></label>
  </div>
  <label class="check"><input type="checkbox" class="switch" bind:checked={keepLogin} /> Keep my Malo password in the profile: unlocking it logs me in</label>
  {#if keepLogin}
    {#if knownPassword === null}
      <label>Your Malo password <input type="password" bind:value={loginPw} required autocomplete="current-password" /></label>
    {/if}
    <p class="muted small">Anyone with the file and its password can then unlock your backups, so pick a profile password as strong as your Malo password. Locking Malo closes the profile again.</p>
  {/if}
  {#if error}<p class="callout bad">{error}</p>{/if}
  <div class="row mt-1">
    <button class="primary" type="submit" disabled={busy}>{busy ? (keepLogin ? 'Checking the password and encrypting…' : 'Encrypting…') : 'Save profile…'}</button>
  </div>
</form>
