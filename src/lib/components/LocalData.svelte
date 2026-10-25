<script lang="ts">
  import { onMount } from 'svelte';
  import { app, type LocalDataInfo } from '../api/client';
  import { session, errorText, notify } from '../state.svelte';
  import { bytes } from '../format';
  import DangerConfirm from './DangerConfirm.svelte';

  /** `compact`: one line with a link (login screen); otherwise a full panel. */
  let { compact = false }: { compact?: boolean } = $props();

  let info: LocalDataInfo | null = $state(null);
  let open = $state(false);
  let resetPrefs = $state(false);

  async function load() {
    info = await app.localDataInfo().catch(() => null);
  }
  onMount(load);

  async function reveal() {
    try {
      await app.revealLocalData();
    } catch (e) {
      notify(errorText(e), 'error');
    }
  }

  async function reset() {
    await app.resetLocalData('DELETE', resetPrefs);
    open = false;
    notify('Local server data deleted', 'success');
    // Whatever screen we were on belonged to the deleted server.
    if (session.local) {
      session.local = false;
      session.me = null;
      session.status = null;
      session.setupToken = null;
      session.phase = 'connect';
    }
    await load();
  }
</script>

{#if info?.exists}
  {#if compact}
    <p class="small muted">
      Forgot the password of this local server? <button class="link" onclick={() => (open = true)}>Reset local server…</button>
    </p>
  {:else}
    <div class="small">
      <div class="row">
        <span class="grow">
          <strong>{bytes(info.bytes)}</strong> in {info.files.toLocaleString()} files · {info.users} user{info.users === 1 ? '' : 's'}
          {#if info.running}<span class="pill ok">running</span>{/if}
        </span>
        <button onclick={reveal}>Open folder</button>
        <button class="danger" onclick={() => (open = true)}>Reset local server…</button>
      </div>
      <div class="mono muted">{info.path}</div>
    </div>
  {/if}
{:else if !compact && info}
  <p class="small muted">No local server data yet ({info.path}).</p>
{/if}

{#if open && info}
  <DangerConfirm title="Reset the local server" phrase="DELETE" action="Delete local server data" onconfirm={reset} onclose={() => (open = false)}>
    <p>This stops the bundled server and permanently deletes <strong>{bytes(info.bytes)}</strong> in</p>
    <p class="mono small">{info.path}</p>
    <ul class="small">
      <li>all {info.users} local user{info.users === 1 ? '' : 's'}, their keys, settings, accounts and OAuth tokens</li>
      <li>the message index and job history</li>
      <li>backups in <strong>local folder destinations</strong> (they live inside this folder)</li>
    </ul>
    <p class="small">Mail on your IMAP servers and backups on other destinations (S3, GCS, NAS mounts…) are not touched. With your recovery kit, a new local account can read those encrypted backups again (<em>Rebuild index</em>).</p>
    <label class="check"><input type="checkbox" bind:checked={resetPrefs} /> Also forget app preferences (last server, tray mode)</label>
  </DangerConfirm>
{/if}
